use crate::ffi;
use crate::jsapi::callback_util::{extract_pointer_address, throw_internal_error};
use crate::jsapi::ptr::create_native_pointer;
use crate::jsapi::util::add_cfunction_to_object;
use crate::value::JSValue;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};
use std::ptr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;

#[repr(C)]
struct TCCState {
    _private: [u8; 0],
}

type TccErrorFunc = unsafe extern "C" fn(*mut c_void, *const c_char);
type TccCppLoadFunc = unsafe extern "C" fn(*mut c_void, *const c_char, *mut c_int) -> *const c_char;
type TccResolveFunc = unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void;
type TccSymbolFunc = unsafe extern "C" fn(*mut c_void, *const c_char, *const c_void);

extern "C" {
    fn tcc_new() -> *mut TCCState;
    fn tcc_delete(s: *mut TCCState);
    fn tcc_set_error_func(s: *mut TCCState, opaque: *mut c_void, func: Option<TccErrorFunc>);
    fn tcc_set_cpp_load_func(s: *mut TCCState, opaque: *mut c_void, func: Option<TccCppLoadFunc>);
    fn tcc_set_linker_resolve_func(s: *mut TCCState, opaque: *mut c_void, func: Option<TccResolveFunc>);
    fn tcc_set_options(s: *mut TCCState, options: *const c_char);
    fn tcc_set_output_type(s: *mut TCCState, output_type: c_int) -> c_int;
    fn tcc_compile_string(s: *mut TCCState, source: *const c_char) -> c_int;
    fn tcc_add_symbol(s: *mut TCCState, name: *const c_char, val: *const c_void) -> c_int;
    fn tcc_relocate(s: *mut TCCState, ptr: *mut c_void) -> c_int;
    fn tcc_get_symbol(s: *mut TCCState, name: *const c_char) -> *mut c_void;
    fn tcc_list_symbols(s: *mut TCCState, ctx: *mut c_void, cb: Option<TccSymbolFunc>);
}

const TCC_OUTPUT_MEMORY: c_int = 1;
const PR_SET_VMA: libc::c_int = 0x53564d41;
const PR_SET_VMA_ANON_NAME: libc::c_int = 0;

static CMODULE_CLASS_ID: AtomicU32 = AtomicU32::new(0);
const CMODULE_CLASS_NAME: &[u8] = b"CModule\0";
static CMODULE_CODE_VMA_NAME: &[u8] = b"wwb_cmodule_code\0";
static CMODULE_CODE_RANGES: Mutex<Vec<(u64, u64)>> = Mutex::new(Vec::new());

struct CModuleData {
    state: *mut TCCState,
    code: *mut c_void,
    map_size: usize,
}

struct CompileContext {
    errors: String,
    imports: HashMap<String, u64>,
}

pub(crate) fn is_cmodule_code_address(addr: u64) -> bool {
    CMODULE_CODE_RANGES
        .lock()
        .map(|ranges| ranges.iter().any(|(start, end)| addr >= *start && addr < *end))
        .unwrap_or(false)
}

fn register_cmodule_code_range(code: *mut c_void, map_size: usize) {
    if code.is_null() || map_size == 0 {
        return;
    }
    let start = code as u64;
    let Some(end) = start.checked_add(map_size as u64) else {
        return;
    };
    if let Ok(mut ranges) = CMODULE_CODE_RANGES.lock() {
        ranges.push((start, end));
    }
}

fn unregister_cmodule_code_range(code: *mut c_void, map_size: usize) {
    if code.is_null() || map_size == 0 {
        return;
    }
    let start = code as u64;
    let end = start.saturating_add(map_size as u64);
    if let Ok(mut ranges) = CMODULE_CODE_RANGES.lock() {
        ranges.retain(|(range_start, range_end)| *range_start != start || *range_end != end);
    }
}

unsafe fn mark_cmodule_code_vma(code: *mut c_void, code_size: usize) {
    if code.is_null() || code_size == 0 {
        return;
    }

    let _ = libc::syscall(
        libc::SYS_prctl as libc::c_long,
        PR_SET_VMA as libc::c_long,
        PR_SET_VMA_ANON_NAME as libc::c_ulong,
        code as libc::c_ulong,
        code_size as libc::c_ulong,
        CMODULE_CODE_VMA_NAME.as_ptr() as libc::c_ulong,
    );
}

unsafe extern "C" fn cmodule_finalizer(_rt: *mut ffi::JSRuntime, val: ffi::JSValue) {
    let class_id = CMODULE_CLASS_ID.load(Ordering::Relaxed);
    if class_id == 0 {
        return;
    }
    let opaque = ffi::JS_GetOpaque(val, class_id);
    if opaque.is_null() {
        return;
    }
    let mut data = Box::from_raw(opaque as *mut CModuleData);
    dispose_cmodule_data(&mut data);
}

unsafe fn dispose_cmodule_data(data: &mut CModuleData) {
    if !data.state.is_null() {
        tcc_delete(data.state);
        data.state = ptr::null_mut();
    }
    if !data.code.is_null() && data.map_size != 0 {
        unregister_cmodule_code_range(data.code, data.map_size);
        let _ = raw_munmap(data.code, data.map_size);
        data.code = ptr::null_mut();
        data.map_size = 0;
    }
}

fn page_align_len(len: usize) -> Option<usize> {
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let page = if page > 0 { page as usize } else { 4096 };
    len.checked_add(page - 1).map(|v| v & !(page - 1))
}

unsafe fn raw_mmap(len: usize, prot: i32, flags: i32) -> *mut c_void {
    let ret = libc::syscall(
        libc::SYS_mmap as libc::c_long,
        ptr::null_mut::<c_void>(),
        len,
        prot,
        flags,
        -1i32,
        0usize,
    );
    if ret == -1 {
        libc::MAP_FAILED
    } else {
        ret as *mut c_void
    }
}

unsafe fn raw_munmap(addr: *mut c_void, len: usize) -> i32 {
    libc::syscall(libc::SYS_munmap as libc::c_long, addr, len) as i32
}

unsafe fn raw_mprotect(addr: *mut c_void, len: usize, prot: i32) -> i32 {
    libc::syscall(libc::SYS_mprotect as libc::c_long, addr, len, prot) as i32
}

fn get_or_init_class_id(ctx: *mut ffi::JSContext) -> u32 {
    let mut class_id = CMODULE_CLASS_ID.load(Ordering::Relaxed);
    if class_id == 0 {
        let mut new_id: u32 = 0;
        new_id = unsafe { ffi::JS_NewClassID(&mut new_id) };
        match CMODULE_CLASS_ID.compare_exchange(0, new_id, Ordering::SeqCst, Ordering::Relaxed) {
            Ok(_) => class_id = new_id,
            Err(existing) => class_id = existing,
        }
    }

    unsafe {
        let rt = ffi::JS_GetRuntime(ctx);
        let class_def = ffi::JSClassDef {
            class_name: CMODULE_CLASS_NAME.as_ptr() as *const _,
            finalizer: Some(cmodule_finalizer),
            gc_mark: None,
            call: None,
            exotic: ptr::null_mut(),
        };
        let _ = ffi::JS_NewClass(rt, class_id, &class_def);
    }

    class_id
}

const STDINT_H: &[u8] = br#"
#ifndef _RF_STDINT_H
#define _RF_STDINT_H
typedef signed char int8_t;
typedef unsigned char uint8_t;
typedef signed short int16_t;
typedef unsigned short uint16_t;
typedef signed int int32_t;
typedef unsigned int uint32_t;
typedef signed long int64_t;
typedef unsigned long uint64_t;
typedef signed long intptr_t;
typedef unsigned long uintptr_t;
#endif
"#;

const STDDEF_H: &[u8] = br#"
#ifndef _RF_STDDEF_H
#define _RF_STDDEF_H
typedef unsigned long size_t;
typedef signed long ssize_t;
typedef signed long ptrdiff_t;
#ifndef NULL
#define NULL ((void *)0)
#endif
#endif
"#;

const STDBOOL_H: &[u8] = br#"
#ifndef _RF_STDBOOL_H
#define _RF_STDBOOL_H
#define bool _Bool
#define true 1
#define false 0
#endif
"#;

const STRING_H: &[u8] = br#"
#ifndef _RF_STRING_H
#define _RF_STRING_H
#include <stddef.h>
void *memcpy(void *dst, const void *src, size_t n);
void *memmove(void *dst, const void *src, size_t n);
void *memset(void *dst, int c, size_t n);
int memcmp(const void *a, const void *b, size_t n);
size_t strlen(const char *s);
#endif
"#;

const RFHOOK_H: &[u8] = br#"
#ifndef _RF_HOOK_H
#define _RF_HOOK_H
#include <stdint.h>
#include <stddef.h>
typedef struct {
    uint64_t x[31];
    uint64_t sp;
    uint64_t pc;
    uint64_t nzcv;
    void *trampoline;
    uint64_t d[8];
    uint64_t intercept_leave;
} HookContext;
uint64_t hook_invoke_trampoline(HookContext *ctx, void *trampoline);

typedef HookContext RfHookContext;
typedef void (*RfHookCallback)(HookContext *ctx, void *user_data);

static inline uint64_t rf_arg(HookContext *ctx, unsigned index) {
    return index < 31u ? ctx->x[index] : 0;
}

static inline void *rf_arg_ptr(HookContext *ctx, unsigned index) {
    return (void *)(uintptr_t)rf_arg(ctx, index);
}

static inline void rf_set_arg(HookContext *ctx, unsigned index, uint64_t value) {
    if (index < 31u) ctx->x[index] = value;
}

static inline void rf_set_arg_ptr(HookContext *ctx, unsigned index, const void *value) {
    rf_set_arg(ctx, index, (uint64_t)(uintptr_t)value);
}

static inline uint64_t rf_ret(HookContext *ctx) {
    return ctx->x[0];
}

static inline void rf_set_ret(HookContext *ctx, uint64_t value) {
    ctx->x[0] = value;
}

static inline void rf_set_ret_ptr(HookContext *ctx, const void *value) {
    ctx->x[0] = (uint64_t)(uintptr_t)value;
}

static inline uint64_t rf_farg_bits(HookContext *ctx, unsigned index) {
    return index < 8u ? ctx->d[index] : 0;
}

static inline void rf_set_farg_bits(HookContext *ctx, unsigned index, uint64_t bits) {
    if (index < 8u) ctx->d[index] = bits;
}

static inline void rf_set_intercept_leave(HookContext *ctx, int enabled) {
    ctx->intercept_leave = enabled ? 1u : 0u;
}

static inline int rf_has_orig(HookContext *ctx) {
    return ctx->trampoline != 0;
}

static inline uint64_t rf_call_orig(HookContext *ctx) {
    uint64_t result = hook_invoke_trampoline(ctx, ctx->trampoline);
    ctx->x[0] = result;
    return result;
}

static inline uint64_t rf_call_orig_with(HookContext *ctx,
                                         uint64_t x0, uint64_t x1,
                                         uint64_t x2, uint64_t x3) {
    ctx->x[0] = x0;
    ctx->x[1] = x1;
    ctx->x[2] = x2;
    ctx->x[3] = x3;
    return rf_call_orig(ctx);
}
#endif
"#;

const PRELUDE: &str = r#"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <rfhook.h>
"#;

unsafe fn header_bytes(path: *const c_char) -> Option<&'static [u8]> {
    if path.is_null() {
        return None;
    }
    let raw_name = CStr::from_ptr(path).to_string_lossy();
    let name = raw_name.strip_prefix("/rf/").unwrap_or(raw_name.as_ref());
    match name {
        "stdint.h" => Some(STDINT_H),
        "stddef.h" => Some(STDDEF_H),
        "stdbool.h" => Some(STDBOOL_H),
        "string.h" => Some(STRING_H),
        "rfhook.h" => Some(RFHOOK_H),
        _ => None,
    }
}

unsafe extern "C" fn cpp_load(_opaque: *mut c_void, path: *const c_char, len: *mut c_int) -> *const c_char {
    match header_bytes(path) {
        Some(bytes) => {
            if !len.is_null() {
                *len = bytes.len() as c_int;
            }
            bytes.as_ptr() as *const c_char
        }
        None => ptr::null(),
    }
}

unsafe extern "C" fn append_error(opaque: *mut c_void, msg: *const c_char) {
    if opaque.is_null() || msg.is_null() {
        return;
    }
    let ctx = &mut *(opaque as *mut CompileContext);
    if !ctx.errors.is_empty() {
        ctx.errors.push('\n');
    }
    ctx.errors.push_str(&CStr::from_ptr(msg).to_string_lossy());
}

unsafe extern "C" fn resolve_symbol(opaque: *mut c_void, name: *const c_char) -> *mut c_void {
    if name.is_null() {
        return ptr::null_mut();
    }
    let symbol = CStr::from_ptr(name).to_string_lossy();
    if !opaque.is_null() {
        let ctx = &mut *(opaque as *mut CompileContext);
        if let Some(addr) = ctx.imports.get(symbol.as_ref()) {
            return *addr as *mut c_void;
        }
    }

    let addr = crate::jsapi::module::find_export_in_loaded_modules(symbol.as_ref());
    if !addr.is_null() {
        return addr;
    }
    ptr::null_mut()
}

unsafe fn add_builtin_symbols(state: *mut TCCState) {
    let name = CString::new("hook_invoke_trampoline").unwrap();
    let addr = crate::ffi::hook::hook_invoke_trampoline as *const () as *const c_void;
    let _ = tcc_add_symbol(state, name.as_ptr(), addr);
}

unsafe fn collect_imports(
    ctx: *mut ffi::JSContext,
    obj: JSValue,
    imports: &mut HashMap<String, u64>,
) -> Result<(), ffi::JSValue> {
    if obj.is_undefined() || obj.is_null() {
        return Ok(());
    }
    if !obj.is_object() || ffi::JS_IsArray(ctx, obj.raw()) != 0 {
        return Err(ffi::JS_ThrowTypeError(
            ctx,
            b"CModule symbols must be an object\0".as_ptr() as *const _,
        ));
    }

    let mut props: *mut ffi::JSPropertyEnum = ptr::null_mut();
    let mut len: u32 = 0;
    let flags = ffi::JS_GPN_STRING_MASK as i32 | ffi::JS_GPN_ENUM_ONLY as i32;
    if ffi::JS_GetOwnPropertyNames(ctx, &mut props, &mut len, obj.raw(), flags) != 0 {
        return Err(ffi::JS_ThrowInternalError(
            ctx,
            b"CModule failed to enumerate symbols\0".as_ptr() as *const _,
        ));
    }

    for i in 0..len {
        let prop = *props.add(i as usize);
        let c_name = ffi::JS_AtomToCStringLen(ctx, ptr::null_mut(), prop.atom);
        if c_name.is_null() {
            continue;
        }
        let name = CStr::from_ptr(c_name).to_string_lossy().into_owned();
        ffi::qjs_free_cstring(ctx, c_name);

        let val = ffi::qjs_get_property(ctx, obj.raw(), prop.atom);
        let addr = match extract_pointer_address(ctx, JSValue(val), "CModule symbol") {
            Ok(v) => v,
            Err(e) => {
                ffi::qjs_free_value(ctx, val);
                ffi::JS_FreePropertyEnum(ctx, props, len);
                return Err(e);
            }
        };
        ffi::qjs_free_value(ctx, val);
        imports.insert(name, addr);
    }

    ffi::JS_FreePropertyEnum(ctx, props, len);
    Ok(())
}

unsafe extern "C" fn collect_symbol(ctx: *mut c_void, name: *const c_char, val: *const c_void) {
    if ctx.is_null() || name.is_null() || val.is_null() {
        return;
    }
    let symbols = &mut *(ctx as *mut Vec<(String, u64)>);
    let name = CStr::from_ptr(name).to_string_lossy();
    if name.is_empty() || name.starts_with('.') || name.starts_with('$') {
        return;
    }
    symbols.push((name.into_owned(), val as u64));
}

unsafe extern "C" fn cmodule_find_symbol(
    ctx: *mut ffi::JSContext,
    this_val: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(ctx, b"findSymbolByName(name) requires name\0".as_ptr() as *const _);
    }
    let class_id = CMODULE_CLASS_ID.load(Ordering::Relaxed);
    let data = ffi::JS_GetOpaque(this_val, class_id) as *mut CModuleData;
    if data.is_null() {
        return ffi::JS_ThrowTypeError(ctx, b"Not a CModule\0".as_ptr() as *const _);
    }
    if (*data).code.is_null() {
        return throw_internal_error(ctx, "CModule has already been disposed");
    }
    if (*data).state.is_null() {
        return throw_internal_error(ctx, "CModule metadata has already been dropped");
    }
    let name = match JSValue(*argv).to_string(ctx) {
        Some(v) => v,
        None => return ffi::JS_ThrowTypeError(ctx, b"symbol name must be a string\0".as_ptr() as *const _),
    };
    let cname = match CString::new(name) {
        Ok(value) => value,
        Err(_) => {
            return ffi::JS_ThrowTypeError(ctx, b"symbol name must not contain a NUL byte\0".as_ptr() as *const _)
        }
    };
    let addr = tcc_get_symbol((*data).state, cname.as_ptr());
    if addr.is_null() {
        JSValue::null().raw()
    } else {
        create_native_pointer(ctx, addr as u64).raw()
    }
}

unsafe extern "C" fn cmodule_drop_metadata(
    ctx: *mut ffi::JSContext,
    this_val: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let class_id = CMODULE_CLASS_ID.load(Ordering::Relaxed);
    let data = ffi::JS_GetOpaque(this_val, class_id) as *mut CModuleData;
    if data.is_null() {
        return ffi::JS_ThrowTypeError(ctx, b"Not a CModule\0".as_ptr() as *const _);
    }
    if !(*data).state.is_null() {
        tcc_delete((*data).state);
        (*data).state = ptr::null_mut();
    }
    JSValue::undefined().raw()
}

unsafe extern "C" fn cmodule_dispose(
    ctx: *mut ffi::JSContext,
    this_val: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let class_id = CMODULE_CLASS_ID.load(Ordering::Relaxed);
    let data = ffi::JS_GetOpaque(this_val, class_id) as *mut CModuleData;
    if data.is_null() {
        return ffi::JS_ThrowTypeError(ctx, b"Not a CModule\0".as_ptr() as *const _);
    }
    dispose_cmodule_data(&mut *data);
    JSValue::undefined().raw()
}

unsafe extern "C" fn cmodule_get_builtins(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let result = ffi::JS_NewObject(ctx);
    if ffi::qjs_is_exception(result) != 0 {
        return result;
    }
    let headers = ffi::JS_NewObject(ctx);
    if ffi::qjs_is_exception(headers) != 0 {
        ffi::qjs_free_value(ctx, result);
        return headers;
    }
    for (name, contents) in [
        ("stdint.h", STDINT_H),
        ("stddef.h", STDDEF_H),
        ("stdbool.h", STDBOOL_H),
        ("string.h", STRING_H),
        ("rfhook.h", RFHOOK_H),
    ] {
        JSValue(headers).set_property(
            ctx,
            name,
            JSValue::string(ctx, std::str::from_utf8(contents).unwrap_or_default()),
        );
    }

    let defines = ffi::JS_NewObject(ctx);
    if ffi::qjs_is_exception(defines) != 0 {
        ffi::qjs_free_value(ctx, headers);
        ffi::qjs_free_value(ctx, result);
        return defines;
    }
    for (name, value) in [
        ("__ANDROID__", "1"),
        ("__LP64__", "1"),
        ("__aarch64__", "1"),
        ("TCC_TARGET_ARM64", "1"),
    ] {
        JSValue(defines).set_property(ctx, name, JSValue::string(ctx, value));
    }
    JSValue(result).set_property(ctx, "defines", JSValue(defines));
    JSValue(result).set_property(ctx, "headers", JSValue(headers));
    result
}

unsafe extern "C" fn js_cmodule(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(ctx, b"CModule(source, symbols?) requires source\0".as_ptr() as *const _);
    }

    let source = match JSValue(*argv).to_string(ctx) {
        Some(s) => s,
        None => return ffi::JS_ThrowTypeError(ctx, b"CModule source must be a string\0".as_ptr() as *const _),
    };

    let mut compile_ctx = CompileContext {
        errors: String::new(),
        imports: HashMap::new(),
    };
    if argc >= 2 {
        if let Err(e) = collect_imports(ctx, JSValue(*argv.add(1)), &mut compile_ctx.imports) {
            return e;
        }
    }

    let state = tcc_new();
    if state.is_null() {
        return throw_internal_error(ctx, "CModule: tcc_new failed");
    }

    tcc_set_error_func(state, &mut compile_ctx as *mut _ as *mut c_void, Some(append_error));
    tcc_set_cpp_load_func(state, ptr::null_mut(), Some(cpp_load));
    tcc_set_linker_resolve_func(state, &mut compile_ctx as *mut _ as *mut c_void, Some(resolve_symbol));

    let options = CString::new("-Wall -Werror -isystem /rf -nostdinc -nostdlib").unwrap();
    tcc_set_options(state, options.as_ptr());
    tcc_set_output_type(state, TCC_OUTPUT_MEMORY);
    add_builtin_symbols(state);
    for (name, addr) in &compile_ctx.imports {
        if let Ok(cname) = CString::new(name.as_str()) {
            let _ = tcc_add_symbol(state, cname.as_ptr(), *addr as *const c_void);
        }
    }

    let combined = match CString::new(format!(
        "#line 1 \"rf_cmodule.c\"\n{}\n#line 1 \"module.c\"\n{}",
        PRELUDE, source
    )) {
        Ok(v) => v,
        Err(_) => {
            tcc_delete(state);
            return ffi::JS_ThrowTypeError(ctx, b"CModule source contains NUL byte\0".as_ptr() as *const _);
        }
    };
    if tcc_compile_string(state, combined.as_ptr()) == -1 || !compile_ctx.errors.is_empty() {
        let err = if compile_ctx.errors.is_empty() {
            "unknown compiler error".to_string()
        } else {
            compile_ctx.errors
        };
        tcc_delete(state);
        return throw_internal_error(ctx, format!("CModule compilation failed: {}", err));
    }

    let size = tcc_relocate(state, ptr::null_mut());
    if size <= 0 {
        let err = if compile_ctx.errors.is_empty() {
            "relocation size query failed".to_string()
        } else {
            compile_ctx.errors
        };
        tcc_delete(state);
        return throw_internal_error(ctx, format!("CModule link failed: {}", err));
    }

    let code_size = size as usize;
    let Some(map_size) = page_align_len(code_size) else {
        tcc_delete(state);
        return throw_internal_error(ctx, "CModule mmap size overflow");
    };
    let code = raw_mmap(
        map_size,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
    );
    if code == libc::MAP_FAILED {
        tcc_delete(state);
        return throw_internal_error(ctx, "CModule mmap(RW) failed");
    }
    mark_cmodule_code_vma(code, map_size);

    compile_ctx.errors.clear();
    tcc_set_error_func(state, &mut compile_ctx as *mut _ as *mut c_void, Some(append_error));
    if tcc_relocate(state, code) == -1 || !compile_ctx.errors.is_empty() {
        let err = if compile_ctx.errors.is_empty() {
            "relocation failed".to_string()
        } else {
            compile_ctx.errors
        };
        let _ = raw_munmap(code, map_size);
        tcc_delete(state);
        return throw_internal_error(ctx, format!("CModule link failed: {}", err));
    }
    ffi::qjs_clear_cache(code as *mut c_void, (code as usize + code_size) as *mut c_void);
    if raw_mprotect(code, map_size, libc::PROT_READ | libc::PROT_EXEC) != 0 {
        let error = std::io::Error::last_os_error();
        let _ = raw_munmap(code, map_size);
        tcc_delete(state);
        return throw_internal_error(ctx, format!("CModule mprotect(RX) failed: {error}"));
    }
    register_cmodule_code_range(code, map_size);

    let class_id = get_or_init_class_id(ctx);
    let obj = ffi::JS_NewObjectClass(ctx, class_id as i32);
    if ffi::qjs_is_exception(obj) != 0 {
        unregister_cmodule_code_range(code, map_size);
        let _ = raw_munmap(code, map_size);
        tcc_delete(state);
        return obj;
    }

    let data = Box::into_raw(Box::new(CModuleData { state, code, map_size }));
    ffi::JS_SetOpaque(obj, data as *mut c_void);

    let mut symbols: Vec<(String, u64)> = Vec::new();
    tcc_list_symbols(state, &mut symbols as *mut _ as *mut c_void, Some(collect_symbol));
    symbols.sort_by(|a, b| a.0.cmp(&b.0));
    symbols.dedup_by(|a, b| a.0 == b.0);
    for (name, addr) in symbols {
        if name.contains('\0') {
            continue;
        }
        let resolved_addr = CString::new(name.as_str())
            .ok()
            .map(|cname| tcc_get_symbol(state, cname.as_ptr()) as u64)
            .filter(|addr| *addr != 0)
            .unwrap_or(addr);
        let ptr_val = create_native_pointer(ctx, resolved_addr);
        JSValue(obj).set_property(ctx, &name, ptr_val);
    }

    JSValue(obj).set_property(ctx, "base", create_native_pointer(ctx, code as u64));
    JSValue(obj).set_property(ctx, "size", JSValue::int(code_size.min(i32::MAX as usize) as i32));
    add_cfunction_to_object(ctx, obj, "findSymbolByName", cmodule_find_symbol, 1);
    add_cfunction_to_object(ctx, obj, "dropMetadata", cmodule_drop_metadata, 0);
    obj
}

pub(crate) fn register_cmodule_api(ctx: *mut ffi::JSContext, global: ffi::JSValue) {
    let class_id = get_or_init_class_id(ctx);
    unsafe {
        let prototype = ffi::JS_NewObject(ctx);
        add_cfunction_to_object(ctx, prototype, "dispose", cmodule_dispose, 0);
        ffi::JS_SetClassProto(ctx, class_id, prototype);

        let cname = CString::new("CModule").unwrap();
        let ctor = ffi::JS_NewCFunction2(
            ctx,
            Some(js_cmodule),
            cname.as_ptr(),
            2,
            ffi::JSCFunctionEnum_JS_CFUNC_constructor_or_func,
            0,
        );
        let prototype = ffi::JS_GetClassProto(ctx, class_id);
        ffi::JS_SetConstructor(ctx, ctor, prototype);
        ffi::qjs_free_value(ctx, prototype);
        let builtins_getter = ffi::JS_NewCFunction2(
            ctx,
            Some(cmodule_get_builtins),
            b"builtins\0".as_ptr() as *const _,
            0,
            ffi::JSCFunctionEnum_JS_CFUNC_getter,
            0,
        );
        let atom = ffi::JS_NewAtom(ctx, b"builtins\0".as_ptr() as *const _);
        let _ = ffi::JS_DefinePropertyGetSet(
            ctx,
            ctor,
            atom,
            builtins_getter,
            JSValue::undefined().raw(),
            (ffi::JS_PROP_CONFIGURABLE | ffi::JS_PROP_ENUMERABLE) as i32,
        );
        ffi::JS_FreeAtom(ctx, atom);
        let atom = ffi::JS_NewAtom(ctx, cname.as_ptr());
        ffi::qjs_set_property(ctx, global, atom, ctor);
        ffi::JS_FreeAtom(ctx, atom);
    }
}
