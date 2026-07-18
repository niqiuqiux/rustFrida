//! Frida-compatible synchronous File API.

use crate::context::JSContext;
use crate::ffi;
use crate::jsapi::callback_util::throw_internal_error;
use crate::jsapi::util::add_cfunction_to_object;
use crate::value::JSValue;
use std::ffi::CString;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicU32, Ordering};

static FILE_CLASS_ID: AtomicU32 = AtomicU32::new(0);
const FILE_CLASS_NAME: &[u8] = b"File\0";
const DEFAULT_READ_CHUNK_SIZE: usize = 8192;

struct FridaFile {
    fp: *mut libc::FILE,
}

impl FridaFile {
    fn is_closed(&self) -> bool {
        self.fp.is_null()
    }
}

unsafe extern "C" fn file_finalizer(_rt: *mut ffi::JSRuntime, val: ffi::JSValue) {
    let class_id = FILE_CLASS_ID.load(Ordering::Relaxed);
    if class_id == 0 {
        return;
    }

    let opaque = ffi::JS_GetOpaque(val, class_id);
    if opaque.is_null() {
        return;
    }

    let mut state = Box::from_raw(opaque as *mut FridaFile);
    if !state.fp.is_null() {
        libc::fclose(state.fp);
        state.fp = std::ptr::null_mut();
    }
}

fn get_or_init_file_class_id(ctx: *mut ffi::JSContext) -> u32 {
    let mut class_id = FILE_CLASS_ID.load(Ordering::Relaxed);
    if class_id == 0 {
        let mut new_id = 0;
        new_id = unsafe { ffi::JS_NewClassID(&mut new_id) };
        match FILE_CLASS_ID.compare_exchange(0, new_id, Ordering::SeqCst, Ordering::Relaxed) {
            Ok(_) => class_id = new_id,
            Err(existing) => class_id = existing,
        }
    }

    unsafe {
        let rt = ffi::JS_GetRuntime(ctx);
        let class_def = ffi::JSClassDef {
            class_name: FILE_CLASS_NAME.as_ptr() as *const _,
            finalizer: Some(file_finalizer),
            gc_mark: None,
            call: None,
            exotic: std::ptr::null_mut(),
        };
        let _ = ffi::JS_NewClass(rt, class_id, &class_def);
    }

    class_id
}

unsafe fn get_file_state(ctx: *mut ffi::JSContext, this: ffi::JSValue) -> Result<*mut FridaFile, ffi::JSValue> {
    let class_id = FILE_CLASS_ID.load(Ordering::Relaxed);
    if class_id == 0 {
        return Err(ffi::JS_ThrowTypeError(ctx, b"Not a File\0".as_ptr() as *const _));
    }

    let opaque = ffi::JS_GetOpaque(this, class_id);
    if opaque.is_null() {
        return Err(ffi::JS_ThrowTypeError(ctx, b"Not a File\0".as_ptr() as *const _));
    }

    let state = opaque as *mut FridaFile;
    let state_ref = &*state;
    if state_ref.is_closed() {
        return Err(ffi::JS_ThrowTypeError(ctx, b"File is closed\0".as_ptr() as *const _));
    }
    Ok(state)
}

unsafe fn required_string_arg(
    ctx: *mut ffi::JSContext,
    argc: i32,
    argv: *mut ffi::JSValue,
    index: usize,
    message: &[u8],
) -> Result<String, ffi::JSValue> {
    if argc <= index as i32 {
        return Err(ffi::JS_ThrowTypeError(ctx, message.as_ptr() as *const _));
    }
    JSValue(*argv.add(index))
        .to_string(ctx)
        .ok_or_else(|| ffi::JS_ThrowTypeError(ctx, message.as_ptr() as *const _))
}

fn cstring_arg(ctx: *mut ffi::JSContext, s: &str, what: &str) -> Result<CString, ffi::JSValue> {
    CString::new(s).map_err(|_| unsafe {
        ffi::JS_ThrowTypeError(
            ctx,
            format!("{} must not contain NUL bytes\0", what).as_ptr() as *const _,
        )
    })
}

fn io_error(ctx: *mut ffi::JSContext, action: &str, detail: impl AsRef<str>) -> ffi::JSValue {
    unsafe { throw_internal_error(ctx, format!("File.{} failed: {}", action, detail.as_ref())) }
}

fn errno_error(ctx: *mut ffi::JSContext, action: &str) -> ffi::JSValue {
    io_error(ctx, action, std::io::Error::last_os_error().to_string())
}

unsafe fn extract_bytes(ctx: *mut ffi::JSContext, val: JSValue) -> Result<Vec<u8>, ffi::JSValue> {
    let mut size: usize = 0;
    let buf_ptr = ffi::JS_GetArrayBuffer(ctx, &mut size, val.raw());
    if !buf_ptr.is_null() {
        return Ok(std::slice::from_raw_parts(buf_ptr, size).to_vec());
    }
    crate::jsapi::callback_util::discard_pending_exception(ctx);

    let mut byte_offset: usize = 0;
    let mut byte_length: usize = 0;
    let mut bpe: usize = 0;
    let typed_ab = ffi::JS_GetTypedArrayBuffer(ctx, val.raw(), &mut byte_offset, &mut byte_length, &mut bpe);
    if ffi::qjs_is_exception(typed_ab) != 0 {
        let exc = ffi::JS_GetException(ctx);
        ffi::qjs_free_value(ctx, exc);
    } else {
        let typed_ab_val = JSValue(typed_ab);
        let mut result = None;
        if byte_length == 0 {
            result = Some(Vec::new());
        } else {
            let mut ab_size: usize = 0;
            let ab_ptr = ffi::JS_GetArrayBuffer(ctx, &mut ab_size, typed_ab);
            if !ab_ptr.is_null() && byte_offset + byte_length <= ab_size {
                result = Some(std::slice::from_raw_parts(ab_ptr.add(byte_offset), byte_length).to_vec());
            }
        }
        typed_ab_val.free(ctx);
        if let Some(bytes) = result {
            return Ok(bytes);
        }
    }

    if ffi::JS_IsArray(ctx, val.raw()) != 0 {
        let length_atom = ffi::JS_NewAtom(ctx, b"length\0".as_ptr() as *const _);
        let len_val_raw = ffi::qjs_get_property(ctx, val.raw(), length_atom);
        ffi::JS_FreeAtom(ctx, length_atom);
        let len_val = JSValue(len_val_raw);
        let len_i = len_val.to_i64(ctx).unwrap_or(0);
        len_val.free(ctx);
        if len_i < 0 {
            return Err(ffi::JS_ThrowRangeError(
                ctx,
                b"byte array length must be non-negative\0".as_ptr() as *const _,
            ));
        }
        let len = len_i as usize;
        let mut out = Vec::with_capacity(len);
        for i in 0..len {
            let elem_raw = ffi::JS_GetPropertyUint32(ctx, val.raw(), i as u32);
            let elem = JSValue(elem_raw);
            let byte = match elem.to_i64(ctx) {
                Some(v) if (0..=255).contains(&v) => v as u8,
                _ => {
                    elem.free(ctx);
                    return Err(ffi::JS_ThrowTypeError(
                        ctx,
                        b"byte array elements must be integers in the range 0..255\0".as_ptr() as *const _,
                    ));
                }
            };
            elem.free(ctx);
            out.push(byte);
        }
        return Ok(out);
    }

    Err(ffi::JS_ThrowTypeError(
        ctx,
        b"data must be an ArrayBuffer, TypedArray, or Array<number>\0".as_ptr() as *const _,
    ))
}

unsafe fn parse_size_arg(
    ctx: *mut ffi::JSContext,
    argc: i32,
    argv: *mut ffi::JSValue,
    index: usize,
) -> Result<Option<usize>, ffi::JSValue> {
    if argc <= index as i32 {
        return Ok(None);
    }
    let arg = JSValue(*argv.add(index));
    if arg.is_undefined() || arg.is_null() {
        return Ok(None);
    }
    let raw = match arg.to_i64(ctx) {
        Some(v) => v,
        None => {
            return Err(ffi::JS_ThrowTypeError(
                ctx,
                b"size must be a number\0".as_ptr() as *const _,
            ));
        }
    };
    if raw < 0 {
        return Err(ffi::JS_ThrowRangeError(
            ctx,
            b"size must be non-negative\0".as_ptr() as *const _,
        ));
    }
    Ok(Some(raw as usize))
}

unsafe fn read_from_file(
    ctx: *mut ffi::JSContext,
    state: &mut FridaFile,
    size: Option<usize>,
) -> Result<Vec<u8>, ffi::JSValue> {
    let mut out = Vec::new();

    if let Some(size) = size {
        out.resize(size, 0);
        let n = if size == 0 {
            0
        } else {
            libc::fread(out.as_mut_ptr() as *mut libc::c_void, 1, size, state.fp)
        };
        out.truncate(n);
        if n < size && libc::ferror(state.fp) != 0 {
            return Err(errno_error(ctx, "read"));
        }
        return Ok(out);
    }

    let mut buf = vec![0u8; DEFAULT_READ_CHUNK_SIZE];
    loop {
        let n = libc::fread(buf.as_mut_ptr() as *mut libc::c_void, 1, buf.len(), state.fp);
        if n > 0 {
            out.extend_from_slice(&buf[..n]);
        }
        if n < buf.len() {
            if libc::ferror(state.fp) != 0 {
                return Err(errno_error(ctx, "read"));
            }
            break;
        }
    }

    Ok(out)
}

unsafe fn seek_back(
    ctx: *mut ffi::JSContext,
    state: &mut FridaFile,
    count: usize,
    action: &str,
) -> Result<(), ffi::JSValue> {
    if count == 0 {
        return Ok(());
    }
    if libc::fseek(state.fp, -(count as libc::c_long), libc::SEEK_CUR) != 0 {
        return Err(errno_error(ctx, action));
    }
    Ok(())
}

unsafe extern "C" fn file_read_all_bytes(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let path = match required_string_arg(ctx, argc, argv, 0, b"File.readAllBytes(path) requires a path\0") {
        Ok(v) => v,
        Err(e) => return e,
    };

    match std::fs::read(&path) {
        Ok(bytes) => ffi::JS_NewArrayBufferCopy(ctx, bytes.as_ptr(), bytes.len()),
        Err(e) => io_error(ctx, "readAllBytes", e.to_string()),
    }
}

unsafe extern "C" fn file_read_all_text(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let path = match required_string_arg(ctx, argc, argv, 0, b"File.readAllText(path) requires a path\0") {
        Ok(v) => v,
        Err(e) => return e,
    };

    let mut file = match std::fs::File::open(&path) {
        Ok(file) => file,
        Err(e) => return io_error(ctx, "readAllText", e.to_string()),
    };
    let mut text = String::new();
    match file.read_to_string(&mut text) {
        Ok(_) => JSValue::string(ctx, &text).raw(),
        Err(e) => io_error(ctx, "readAllText", e.to_string()),
    }
}

unsafe extern "C" fn file_write_all_bytes(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let path = match required_string_arg(ctx, argc, argv, 0, b"File.writeAllBytes(path, data) requires a path\0") {
        Ok(v) => v,
        Err(e) => return e,
    };
    if argc < 2 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"File.writeAllBytes(path, data) requires data\0".as_ptr() as *const _,
        );
    }
    let bytes = match extract_bytes(ctx, JSValue(*argv.add(1))) {
        Ok(bytes) => bytes,
        Err(e) => return e,
    };

    match std::fs::write(&path, bytes) {
        Ok(()) => JSValue::undefined().raw(),
        Err(e) => io_error(ctx, "writeAllBytes", e.to_string()),
    }
}

unsafe extern "C" fn file_write_all_text(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let path = match required_string_arg(ctx, argc, argv, 0, b"File.writeAllText(path, text) requires a path\0") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let text = match required_string_arg(ctx, argc, argv, 1, b"File.writeAllText(path, text) requires text\0") {
        Ok(v) => v,
        Err(e) => return e,
    };

    match std::fs::File::create(&path).and_then(|mut file| file.write_all(text.as_bytes())) {
        Ok(()) => JSValue::undefined().raw(),
        Err(e) => io_error(ctx, "writeAllText", e.to_string()),
    }
}

unsafe extern "C" fn file_constructor(
    ctx: *mut ffi::JSContext,
    _new_target: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let path = match required_string_arg(ctx, argc, argv, 0, b"new File(filePath, mode) requires filePath\0") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let mode = match required_string_arg(ctx, argc, argv, 1, b"new File(filePath, mode) requires mode\0") {
        Ok(v) => v,
        Err(e) => return e,
    };

    let c_path = match cstring_arg(ctx, &path, "filePath") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let c_mode = match cstring_arg(ctx, &mode, "mode") {
        Ok(v) => v,
        Err(e) => return e,
    };

    let fp = libc::fopen(c_path.as_ptr(), c_mode.as_ptr());
    if fp.is_null() {
        return errno_error(ctx, "open");
    }

    let class_id = get_or_init_file_class_id(ctx);
    let obj = ffi::JS_NewObjectClass(ctx, class_id as i32);
    if ffi::qjs_is_exception(obj) != 0 {
        libc::fclose(fp);
        return obj;
    }

    let state = Box::into_raw(Box::new(FridaFile { fp }));
    ffi::JS_SetOpaque(obj, state as *mut _);
    obj
}

unsafe extern "C" fn file_tell(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let state = match get_file_state(ctx, this) {
        Ok(state) => &mut *state,
        Err(e) => return e,
    };
    let pos = libc::ftell(state.fp);
    if pos < 0 {
        return errno_error(ctx, "tell");
    }
    JSValue(ffi::qjs_new_int64(ctx, pos as i64)).raw()
}

unsafe extern "C" fn file_seek(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let state = match get_file_state(ctx, this) {
        Ok(state) => &mut *state,
        Err(e) => return e,
    };
    if argc < 1 {
        return ffi::JS_ThrowTypeError(ctx, b"seek(offset[, whence]) requires offset\0".as_ptr() as *const _);
    }
    let offset = match JSValue(*argv).to_i64(ctx) {
        Some(v) => v,
        None => return ffi::JS_ThrowTypeError(ctx, b"offset must be a number\0".as_ptr() as *const _),
    };
    let whence = if argc >= 2 {
        match JSValue(*argv.add(1)).to_i64(ctx) {
            Some(v) => v as i32,
            None => return ffi::JS_ThrowTypeError(ctx, b"whence must be a number\0".as_ptr() as *const _),
        }
    } else {
        libc::SEEK_SET
    };

    let result = libc::fseek(state.fp, offset as libc::c_long, whence);
    if result != 0 {
        return errno_error(ctx, "seek");
    }
    JSValue(ffi::qjs_new_int64(ctx, result as i64)).raw()
}

unsafe extern "C" fn file_read_bytes(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let state = match get_file_state(ctx, this) {
        Ok(state) => &mut *state,
        Err(e) => return e,
    };
    let size = match parse_size_arg(ctx, argc, argv, 0) {
        Ok(v) => v,
        Err(e) => return e,
    };
    match read_from_file(ctx, state, size) {
        Ok(bytes) => ffi::JS_NewArrayBufferCopy(ctx, bytes.as_ptr(), bytes.len()),
        Err(e) => e,
    }
}

unsafe extern "C" fn file_read_text(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let state = match get_file_state(ctx, this) {
        Ok(state) => &mut *state,
        Err(e) => return e,
    };
    let size = match parse_size_arg(ctx, argc, argv, 0) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let bytes = match read_from_file(ctx, state, size) {
        Ok(bytes) => bytes,
        Err(e) => return e,
    };
    match String::from_utf8(bytes) {
        Ok(text) => JSValue::string(ctx, &text).raw(),
        Err(e) => {
            let count = e.as_bytes().len();
            if let Err(seek_error) = seek_back(ctx, state, count, "readText") {
                return seek_error;
            }
            io_error(ctx, "readText", e.to_string())
        }
    }
}

unsafe extern "C" fn file_read_line(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let state = match get_file_state(ctx, this) {
        Ok(state) => &mut *state,
        Err(e) => return e,
    };

    let mut line = Vec::new();
    loop {
        let mut byte = 0u8;
        let n = libc::fread(&mut byte as *mut u8 as *mut libc::c_void, 1, 1, state.fp);
        if n == 1 {
            line.push(byte);
            if byte == b'\n' {
                break;
            }
            continue;
        }
        if libc::ferror(state.fp) != 0 {
            return errno_error(ctx, "readLine");
        }
        break;
    }

    match String::from_utf8(line) {
        Ok(text) => JSValue::string(ctx, &text).raw(),
        Err(e) => {
            let count = e.as_bytes().len();
            if let Err(seek_error) = seek_back(ctx, state, count, "readLine") {
                return seek_error;
            }
            io_error(ctx, "readLine", e.to_string())
        }
    }
}

unsafe extern "C" fn file_write(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let state = match get_file_state(ctx, this) {
        Ok(state) => &mut *state,
        Err(e) => return e,
    };
    if argc < 1 {
        return ffi::JS_ThrowTypeError(ctx, b"write(data) requires data\0".as_ptr() as *const _);
    }

    let arg = JSValue(*argv);
    let bytes = if arg.is_string() {
        match arg.to_string(ctx) {
            Some(s) => s.into_bytes(),
            None => return ffi::JS_ThrowTypeError(ctx, b"data string is invalid\0".as_ptr() as *const _),
        }
    } else {
        match extract_bytes(ctx, arg) {
            Ok(bytes) => bytes,
            Err(e) => return e,
        }
    };

    if !bytes.is_empty() {
        let n = libc::fwrite(bytes.as_ptr() as *const libc::c_void, 1, bytes.len(), state.fp);
        if n != bytes.len() {
            return errno_error(ctx, "write");
        }
    }

    JSValue::undefined().raw()
}

unsafe extern "C" fn file_flush(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let state = match get_file_state(ctx, this) {
        Ok(state) => &mut *state,
        Err(e) => return e,
    };
    if libc::fflush(state.fp) != 0 {
        return errno_error(ctx, "flush");
    }
    JSValue::undefined().raw()
}

unsafe extern "C" fn file_close(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let class_id = FILE_CLASS_ID.load(Ordering::Relaxed);
    if class_id == 0 {
        return ffi::JS_ThrowTypeError(ctx, b"Not a File\0".as_ptr() as *const _);
    }
    let opaque = ffi::JS_GetOpaque(this, class_id);
    if opaque.is_null() {
        return ffi::JS_ThrowTypeError(ctx, b"Not a File\0".as_ptr() as *const _);
    }
    let state = &mut *(opaque as *mut FridaFile);
    if state.fp.is_null() {
        return JSValue::undefined().raw();
    }
    let fp = state.fp;
    state.fp = std::ptr::null_mut();
    if libc::fclose(fp) != 0 {
        return errno_error(ctx, "close");
    }
    JSValue::undefined().raw()
}

unsafe fn add_int_property(ctx: *mut ffi::JSContext, obj: ffi::JSValue, name: &str, value: i32) {
    let cname = CString::new(name).unwrap();
    ffi::JS_DefinePropertyValueStr(
        ctx,
        obj,
        cname.as_ptr(),
        JSValue::int(value).raw(),
        (ffi::JS_PROP_C_W_E) as i32,
    );
}

/// Register the global Frida-compatible File constructor.
pub fn register_file_api(ctx: &JSContext) {
    let global = ctx.global_object();

    unsafe {
        let ctx_ptr = ctx.as_ptr();
        let class_id = get_or_init_file_class_id(ctx_ptr);

        let proto = ffi::JS_NewObject(ctx_ptr);
        add_cfunction_to_object(ctx_ptr, proto, "tell", file_tell, 0);
        add_cfunction_to_object(ctx_ptr, proto, "seek", file_seek, 2);
        add_cfunction_to_object(ctx_ptr, proto, "readBytes", file_read_bytes, 1);
        add_cfunction_to_object(ctx_ptr, proto, "readText", file_read_text, 1);
        add_cfunction_to_object(ctx_ptr, proto, "readLine", file_read_line, 0);
        add_cfunction_to_object(ctx_ptr, proto, "write", file_write, 1);
        add_cfunction_to_object(ctx_ptr, proto, "flush", file_flush, 0);
        add_cfunction_to_object(ctx_ptr, proto, "close", file_close, 0);

        let ctor_name = CString::new("File").unwrap();
        let ctor = ffi::JS_NewCFunction2(
            ctx_ptr,
            Some(file_constructor),
            ctor_name.as_ptr(),
            2,
            ffi::JSCFunctionEnum_JS_CFUNC_constructor,
            0,
        );
        add_cfunction_to_object(ctx_ptr, ctor, "readAllBytes", file_read_all_bytes, 1);
        add_cfunction_to_object(ctx_ptr, ctor, "readAllText", file_read_all_text, 1);
        add_cfunction_to_object(ctx_ptr, ctor, "writeAllBytes", file_write_all_bytes, 2);
        add_cfunction_to_object(ctx_ptr, ctor, "writeAllText", file_write_all_text, 2);
        add_int_property(ctx_ptr, ctor, "SEEK_SET", libc::SEEK_SET);
        add_int_property(ctx_ptr, ctor, "SEEK_CUR", libc::SEEK_CUR);
        add_int_property(ctx_ptr, ctor, "SEEK_END", libc::SEEK_END);

        ffi::JS_SetConstructor(ctx_ptr, ctor, proto);
        ffi::JS_SetClassProto(ctx_ptr, class_id, proto);

        global.set_property(ctx_ptr, "File", JSValue(ctor));
    }

    global.free(ctx.as_ptr());
}
