//! Frida-compatible NativePointer and legacy Memory read operations.

use super::helpers::get_addr_this_or_arg;
use super::safe_access::{read_exact, read_value, MemoryAccessError};
use crate::ffi;
use crate::jsapi::ptr::create_native_pointer;
use crate::value::JSValue;

const MAX_READ_SIZE: usize = 1024 * 1024 * 1024;
const MAX_STRING_SIZE: usize = 16 * 1024 * 1024;

unsafe fn throw_access_error(ctx: *mut ffi::JSContext, operation: &str, error: MemoryAccessError) -> ffi::JSValue {
    let message = format!("{}: {}\0", operation, error);
    ffi::JS_ThrowRangeError(
        ctx,
        b"%s\0".as_ptr() as *const _,
        message.as_ptr() as *const libc::c_char,
    )
}

unsafe fn throw_message(ctx: *mut ffi::JSContext, message: String) -> ffi::JSValue {
    let message = format!("{}\0", message);
    ffi::JS_ThrowRangeError(
        ctx,
        b"%s\0".as_ptr() as *const _,
        message.as_ptr() as *const libc::c_char,
    )
}

macro_rules! define_memory_read {
    ($name:ident, $js_name:literal, $rust_type:ty, ($ctx_id:ident, $val_id:ident) => $convert:expr) => {
        pub(super) unsafe extern "C" fn $name(
            $ctx_id: *mut ffi::JSContext,
            this: ffi::JSValue,
            argc: i32,
            argv: *mut ffi::JSValue,
        ) -> ffi::JSValue {
            let (addr, _, _) = match get_addr_this_or_arg($ctx_id, this, argc, argv) {
                Some(value) => value,
                None => {
                    return ffi::JS_ThrowTypeError(
                        $ctx_id,
                        concat!($js_name, "() requires a pointer\0").as_ptr() as *const _,
                    )
                }
            };
            let $val_id = match read_value::<$rust_type>(addr) {
                Ok(value) => value,
                Err(error) => return throw_access_error($ctx_id, $js_name, error),
            };
            $convert
        }
    };
}

define_memory_read!(memory_read_s8, "readS8", i8, (_ctx, value) => JSValue::int(value as i32).raw());
define_memory_read!(memory_read_u8, "readU8", u8, (_ctx, value) => JSValue::int(value as i32).raw());
define_memory_read!(memory_read_s16, "readS16", i16, (_ctx, value) => JSValue::int(value as i32).raw());
define_memory_read!(memory_read_u16, "readU16", u16, (_ctx, value) => JSValue::int(value as i32).raw());
define_memory_read!(memory_read_s32, "readS32", i32, (_ctx, value) => JSValue::int(value).raw());
define_memory_read!(memory_read_u32, "readU32", u32, (ctx, value) => ffi::qjs_new_uint32(ctx, value));
define_memory_read!(memory_read_s64, "readS64", i64, (ctx, value) => ffi::JS_NewBigInt64(ctx, value));
define_memory_read!(memory_read_u64, "readU64", u64, (ctx, value) => ffi::JS_NewBigUint64(ctx, value));
define_memory_read!(memory_read_float, "readFloat", f32, (ctx, value) => ffi::qjs_new_float64(ctx, value as f64));
define_memory_read!(memory_read_double, "readDouble", f64, (ctx, value) => ffi::qjs_new_float64(ctx, value));
define_memory_read!(memory_read_pointer, "readPointer", u64, (ctx, value) => create_native_pointer(ctx, value).raw());

unsafe fn parse_optional_length(
    ctx: *mut ffi::JSContext,
    argv: *mut ffi::JSValue,
    argc: i32,
    operation: &str,
) -> Result<Option<usize>, ffi::JSValue> {
    if argc == 0 {
        return Ok(None);
    }
    let raw = match JSValue(*argv).to_i64(ctx) {
        Some(value) => value,
        None => {
            let message = format!("{}: length must be an integer\0", operation);
            return Err(ffi::JS_ThrowTypeError(
                ctx,
                b"%s\0".as_ptr() as *const _,
                message.as_ptr() as *const libc::c_char,
            ));
        }
    };
    if raw < 0 {
        return Ok(None);
    }
    let length = raw as usize;
    if length > MAX_STRING_SIZE {
        return Err(throw_message(
            ctx,
            format!("{}: length exceeds maximum ({})", operation, MAX_STRING_SIZE),
        ));
    }
    Ok(Some(length))
}

fn read_nul_terminated(address: u64, unit_size: usize) -> Result<Vec<u8>, MemoryAccessError> {
    let mut result = Vec::new();
    while result.len() < MAX_STRING_SIZE {
        let cursor = address.checked_add(result.len() as u64).ok_or(MemoryAccessError {
            operation: super::safe_access::MemoryOperation::Read,
            address,
            size: result.len(),
            errno: libc::EOVERFLOW,
        })?;
        let page_remaining = 0x1000usize - (cursor as usize & 0xfff);
        let remaining = MAX_STRING_SIZE - result.len();
        let mut chunk_size = page_remaining.min(remaining).min(0x1000);
        if unit_size == 2 {
            chunk_size &= !1;
            if chunk_size == 0 {
                chunk_size = 2;
            }
        }
        let mut chunk = vec![0u8; chunk_size];
        read_exact(cursor, &mut chunk)?;

        let terminator = if unit_size == 1 {
            chunk.iter().position(|byte| *byte == 0)
        } else {
            chunk
                .chunks_exact(2)
                .position(|pair| pair[0] == 0 && pair[1] == 0)
                .map(|index| index * 2)
        };
        if let Some(index) = terminator {
            result.extend_from_slice(&chunk[..index]);
            return Ok(result);
        }
        result.extend_from_slice(&chunk);
    }

    Err(MemoryAccessError {
        operation: super::safe_access::MemoryOperation::Read,
        address: address.saturating_add(result.len() as u64),
        size: 1,
        errno: libc::EOVERFLOW,
    })
}

unsafe fn read_string_bytes(
    ctx: *mut ffi::JSContext,
    address: u64,
    length: Option<usize>,
    unit_size: usize,
    operation: &str,
) -> Result<Vec<u8>, ffi::JSValue> {
    let byte_length = match length {
        Some(length) => match length.checked_mul(unit_size) {
            Some(value) => value,
            None => return Err(throw_message(ctx, format!("{}: length overflow", operation))),
        },
        None => {
            return read_nul_terminated(address, unit_size).map_err(|error| throw_access_error(ctx, operation, error))
        }
    };
    let mut bytes = vec![0u8; byte_length];
    read_exact(address, &mut bytes).map_err(|error| throw_access_error(ctx, operation, error))?;
    Ok(bytes)
}

unsafe fn read_utf8_like(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
    strict: bool,
    operation: &str,
) -> ffi::JSValue {
    let (address, remaining_argv, remaining_argc) = match get_addr_this_or_arg(ctx, this, argc, argv) {
        Some(value) => value,
        None => return ffi::JS_ThrowTypeError(ctx, b"read string requires a pointer\0".as_ptr() as *const _),
    };
    if address == 0 {
        return JSValue::null().raw();
    }
    let length = match parse_optional_length(ctx, remaining_argv, remaining_argc, operation) {
        Ok(value) => value,
        Err(error) => return error,
    };
    let bytes = match read_string_bytes(ctx, address, length, 1, operation) {
        Ok(value) => value,
        Err(error) => return error,
    };
    if strict {
        match std::str::from_utf8(&bytes) {
            Ok(value) => JSValue::string(ctx, value).raw(),
            Err(error) => throw_message(
                ctx,
                format!("{}: invalid UTF-8 at byte {}", operation, error.valid_up_to()),
            ),
        }
    } else {
        JSValue::string(ctx, &String::from_utf8_lossy(&bytes)).raw()
    }
}

pub(super) unsafe extern "C" fn memory_read_cstring(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    read_utf8_like(ctx, this, argc, argv, false, "readCString")
}

pub(super) unsafe extern "C" fn memory_read_utf8_string(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    read_utf8_like(ctx, this, argc, argv, true, "readUtf8String")
}

pub(super) unsafe extern "C" fn memory_read_utf16_string(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let (address, remaining_argv, remaining_argc) = match get_addr_this_or_arg(ctx, this, argc, argv) {
        Some(value) => value,
        None => return ffi::JS_ThrowTypeError(ctx, b"readUtf16String() requires a pointer\0".as_ptr() as *const _),
    };
    if address == 0 {
        return JSValue::null().raw();
    }
    let length = match parse_optional_length(ctx, remaining_argv, remaining_argc, "readUtf16String") {
        Ok(value) => value,
        Err(error) => return error,
    };
    let bytes = match read_string_bytes(ctx, address, length, 2, "readUtf16String") {
        Ok(value) => value,
        Err(error) => return error,
    };
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_ne_bytes([pair[0], pair[1]]))
        .collect();
    match String::from_utf16(&units) {
        Ok(value) => JSValue::string(ctx, &value).raw(),
        Err(_) => throw_message(ctx, "readUtf16String: invalid UTF-16".to_string()),
    }
}

pub(super) unsafe extern "C" fn memory_read_ansi_string(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    ffi::JS_ThrowTypeError(ctx, b"ANSI API is only applicable on Windows\0".as_ptr() as *const _)
}

pub(super) unsafe extern "C" fn memory_read_byte_array(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let (address, remaining_argv, remaining_argc) = match get_addr_this_or_arg(ctx, this, argc, argv) {
        Some(value) => value,
        None => return ffi::JS_ThrowTypeError(ctx, b"readByteArray() requires a pointer\0".as_ptr() as *const _),
    };
    if remaining_argc < 1 {
        return ffi::JS_ThrowTypeError(ctx, b"readByteArray() requires length argument\0".as_ptr() as *const _);
    }
    let raw_length = match JSValue(*remaining_argv).to_i64(ctx) {
        Some(value) => value,
        None => return ffi::JS_ThrowTypeError(ctx, b"readByteArray: length must be an integer\0".as_ptr() as *const _),
    };
    if raw_length < 0 || raw_length as u64 > MAX_READ_SIZE as u64 {
        return throw_message(
            ctx,
            format!("readByteArray: length must be between 0 and {}", MAX_READ_SIZE),
        );
    }
    let length = raw_length as usize;
    let mut bytes = Vec::new();
    if bytes.try_reserve_exact(length).is_err() {
        return ffi::JS_ThrowInternalError(ctx, b"readByteArray: allocation failed\0".as_ptr() as *const _);
    }
    bytes.resize(length, 0);
    if let Err(error) = read_exact(address, &mut bytes) {
        return throw_access_error(ctx, "readByteArray", error);
    }
    ffi::JS_NewArrayBufferCopy(ctx, bytes.as_ptr(), bytes.len())
}
