//! Memory write operations

use super::helpers::{get_addr_from_arg, get_addr_this_or_arg};
use super::safe_access::{write_exact, write_value, MemoryAccessError};
use super::writest::extract_bytes;
use crate::ffi;
use crate::jsapi::ptr::get_native_pointer_addr;
use crate::value::JSValue;
use std::collections::HashSet;
use std::sync::Mutex;

/// 追踪 writeBytes(bytes, 1) 装过的 stealth1 patch 地址, 供 cleanup 批量
/// wxshadow_release. 这些 patch 不走 hook_engine, 不在 g_engine.hooks 链表上,
/// hook_engine_cleanup 看不到它们.
static WXSHADOW_PATCH_ADDRS: Mutex<Option<HashSet<u64>>> = Mutex::new(None);

fn track_wxshadow_addr(addr: u64) {
    let mut guard = WXSHADOW_PATCH_ADDRS.lock().unwrap_or_else(|e| e.into_inner());
    guard.get_or_insert_with(HashSet::new).insert(addr);
}

pub(crate) fn untrack_wxshadow_addr(addr: u64) {
    let mut guard = WXSHADOW_PATCH_ADDRS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(set) = guard.as_mut() {
        set.remove(&addr);
    }
}

/// 清理所有 writeBytes(bytes, 1) 装过的 stealth1 patch. cleanup 时在
/// hook_engine_cleanup 之后调用, 通过 kernel_hook 恢复原字节, 防止 --pid
/// 场景下 agent dlclose 后 patch 残留.
pub fn cleanup_wxshadow_patches() {
    let addrs = {
        let mut guard = WXSHADOW_PATCH_ADDRS.lock().unwrap_or_else(|e| e.into_inner());
        guard.take().unwrap_or_default()
    };
    for addr in addrs {
        unsafe {
            ffi::hook::wxshadow_release(addr as *mut std::ffi::c_void);
        }
    }
}

unsafe fn throw_write_error(ctx: *mut ffi::JSContext, operation: &str, error: MemoryAccessError) -> ffi::JSValue {
    let message = format!(
        "{}: {}; target must be writable (use Memory.protect first if appropriate)\0",
        operation, error
    );
    ffi::JS_ThrowRangeError(
        ctx,
        b"%s\0".as_ptr() as *const _,
        message.as_ptr() as *const libc::c_char,
    )
}

unsafe fn parse_u64(ctx: *mut ffi::JSContext, value: JSValue) -> Option<u64> {
    let mut result = 0u64;
    if ffi::qjs_value_to_u64(ctx, &mut result, value.raw()) == 0 {
        Some(result)
    } else {
        None
    }
}

unsafe fn parse_f64(ctx: *mut ffi::JSContext, value: JSValue) -> Option<f64> {
    let mut result = 0f64;
    if ffi::qjs_to_float64(ctx, &mut result, value.raw()) == 0 {
        Some(result)
    } else {
        None
    }
}

unsafe fn write_success(ctx: *mut ffi::JSContext, this: ffi::JSValue) -> ffi::JSValue {
    if get_native_pointer_addr(ctx, JSValue(this)).is_some() {
        ffi::qjs_dup_value(ctx, this)
    } else {
        JSValue::undefined().raw()
    }
}

/// Generate both `Memory.writeXxx(ptr, value)` and `ptr.writeXxx(value)`.
macro_rules! define_memory_write {
    ($name:ident, $js_name:literal, $rust_type:ty,
     ($ctx_id:ident, $value_id:ident) => $extract:expr) => {
        pub(super) unsafe extern "C" fn $name(
            $ctx_id: *mut ffi::JSContext,
            this: ffi::JSValue,
            argc: i32,
            argv: *mut ffi::JSValue,
        ) -> ffi::JSValue {
            let (addr, rem_argv, rem_argc) = match get_addr_this_or_arg($ctx_id, this, argc, argv) {
                Some(v) => v,
                None => {
                    return ffi::JS_ThrowTypeError(
                        $ctx_id,
                        concat!($js_name, "() requires a pointer\0").as_ptr() as *const _,
                    )
                }
            };
            if rem_argc < 1 {
                return ffi::JS_ThrowTypeError(
                    $ctx_id,
                    concat!($js_name, "() requires value argument\0").as_ptr() as *const _,
                );
            }
            let $value_id = JSValue(*rem_argv);
            let value: $rust_type = match $extract {
                Some(value) => value,
                None => {
                    return ffi::JS_ThrowTypeError(
                        $ctx_id,
                        concat!($js_name, "(): value has incompatible type\0").as_ptr() as *const _,
                    )
                }
            };
            if let Err(error) = write_value(addr, &value) {
                return throw_write_error($ctx_id, $js_name, error);
            }
            write_success($ctx_id, this)
        }
    };
}

define_memory_write!(memory_write_s8, "writeS8", i8,
    (ctx, value) => value.to_i64(ctx).map(|value| value as i8));
define_memory_write!(memory_write_u8, "writeU8", u8,
    (ctx, value) => parse_u64(ctx, value).map(|value| value as u8));
define_memory_write!(memory_write_s16, "writeS16", i16,
    (ctx, value) => value.to_i64(ctx).map(|value| value as i16));
define_memory_write!(memory_write_u16, "writeU16", u16,
    (ctx, value) => parse_u64(ctx, value).map(|value| value as u16));
define_memory_write!(memory_write_s32, "writeS32", i32,
    (ctx, value) => value.to_i64(ctx).map(|value| value as i32));
define_memory_write!(memory_write_u32, "writeU32", u32,
    (ctx, value) => parse_u64(ctx, value).map(|value| value as u32));
define_memory_write!(memory_write_s64, "writeS64", i64,
    (ctx, value) => value.to_i64(ctx));
define_memory_write!(memory_write_u64, "writeU64", u64,
    (ctx, value) => parse_u64(ctx, value));
define_memory_write!(memory_write_float, "writeFloat", f32,
    (ctx, value) => parse_f64(ctx, value).map(|value| value as f32));
define_memory_write!(memory_write_double, "writeDouble", f64,
    (ctx, value) => parse_f64(ctx, value));

/// Memory.writePointer(ptr, value) / ptr.writePointer(value)
pub(super) unsafe extern "C" fn memory_write_pointer(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let (addr, rem_argv, rem_argc) = match get_addr_this_or_arg(ctx, this, argc, argv) {
        Some(v) => v,
        None => return ffi::JS_ThrowTypeError(ctx, b"writePointer() requires a pointer\0".as_ptr() as *const _),
    };
    if rem_argc < 1 {
        return ffi::JS_ThrowTypeError(ctx, b"writePointer() requires value argument\0".as_ptr() as *const _);
    }
    let value = match get_addr_from_arg(ctx, JSValue(*rem_argv)) {
        Some(value) => value,
        None => {
            return ffi::JS_ThrowTypeError(
                ctx,
                b"writePointer() value must be a NativePointer or integer\0".as_ptr() as *const _,
            )
        }
    };
    if let Err(error) = write_value(addr, &value) {
        return throw_write_error(ctx, "writePointer", error);
    }
    write_success(ctx, this)
}

unsafe fn write_string_bytes(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
    utf16: bool,
) -> ffi::JSValue {
    let operation = if utf16 { "writeUtf16String" } else { "writeUtf8String" };
    let (address, remaining_argv, remaining_argc) = match get_addr_this_or_arg(ctx, this, argc, argv) {
        Some(value) => value,
        None => return ffi::JS_ThrowTypeError(ctx, b"write string requires a pointer\0".as_ptr() as *const _),
    };
    if remaining_argc < 1 {
        return ffi::JS_ThrowTypeError(ctx, b"write string requires a string value\0".as_ptr() as *const _);
    }
    let string = match JSValue(*remaining_argv).to_string(ctx) {
        Some(value) => value,
        None => return ffi::JS_ThrowTypeError(ctx, b"write string value must be a string\0".as_ptr() as *const _),
    };
    let bytes = if utf16 {
        let mut bytes = Vec::with_capacity((string.encode_utf16().count() + 1) * 2);
        for unit in string.encode_utf16().chain(std::iter::once(0)) {
            bytes.extend_from_slice(&unit.to_ne_bytes());
        }
        bytes
    } else {
        let mut bytes = string.into_bytes();
        bytes.push(0);
        bytes
    };
    if let Err(error) = write_exact(address, &bytes) {
        return throw_write_error(ctx, operation, error);
    }
    write_success(ctx, this)
}

pub(super) unsafe extern "C" fn memory_write_utf8_string(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    write_string_bytes(ctx, this, argc, argv, false)
}

pub(super) unsafe extern "C" fn memory_write_utf16_string(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    write_string_bytes(ctx, this, argc, argv, true)
}

pub(super) unsafe extern "C" fn memory_write_ansi_string(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    ffi::JS_ThrowTypeError(ctx, b"ANSI API is only applicable on Windows\0".as_ptr() as *const _)
}

/// `Memory.writeBytes(ptr, bytes, stealth?)` / `ptr.writeBytes(bytes, stealth?)`
///
/// Multi-byte write with an optional stealth flag:
///   - `stealth=0` or omitted: safe write to an already-writable mapping
///   - `stealth=1`: wxshadow_module prctl write with local restore tracking
///
/// For the "1 instruction → N instruction" replacement semantics (PC-rel
/// aware, atomic B→slot in recomp page), use `writest()` (stealth-2) instead.
pub(super) unsafe extern "C" fn memory_write_bytes(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let (addr, rem_argv, rem_argc) = match get_addr_this_or_arg(ctx, this, argc, argv) {
        Some(v) => v,
        None => {
            return ffi::JS_ThrowTypeError(ctx, b"writeBytes() requires a pointer\0".as_ptr() as *const _);
        }
    };
    if rem_argc < 1 {
        return ffi::JS_ThrowTypeError(ctx, b"writeBytes() requires bytes argument\0".as_ptr() as *const _);
    }

    let bytes = match extract_bytes(ctx, JSValue(*rem_argv)) {
        Ok(b) => b,
        Err(e) => return e,
    };
    if bytes.is_empty() {
        return write_success(ctx, this);
    }

    let stealth = if rem_argc >= 2 {
        JSValue(*rem_argv.add(1)).to_i64(ctx).unwrap_or(0)
    } else {
        0
    };

    match stealth {
        0 => {
            let len = bytes.len();
            if let Err(error) = write_exact(addr, &bytes) {
                return throw_write_error(ctx, "writeBytes", error);
            }
            ffi::hook::hook_flush_cache(addr as *mut _, len);
            write_success(ctx, this)
        }
        1 => {
            // wxshadow backend writes through prctl. Keep the
            // historical split order so hook jump installation remains safe
            // when bytes cross a 4KB boundary.
            let len = bytes.len();
            let page_off = (addr & 0xFFF) as usize;
            if page_off + len > 0x2000 {
                let msg = format!(
                    "writeBytes(stealth=1): bytes len={} 跨 >2 页 (page_off=0x{:x})，kernel_hook backend 不支持\0",
                    len, page_off
                );
                return ffi::JS_ThrowInternalError(ctx, b"%s\0".as_ptr() as *const _, msg.as_ptr());
            }
            if page_off + len > 0x1000 {
                let first_len = 0x1000 - page_off;
                let second_len = len - first_len;
                let second_addr = addr + first_len as u64;
                let rc2 = ffi::hook::wxshadow_patch(
                    second_addr as *mut std::ffi::c_void,
                    bytes.as_ptr().add(first_len) as *const std::ffi::c_void,
                    second_len,
                );
                if rc2 != 0 {
                    let msg = format!("writeBytes(stealth=1): kernel_hook second-page write rc={}\0", rc2);
                    return ffi::JS_ThrowInternalError(ctx, b"%s\0".as_ptr() as *const _, msg.as_ptr());
                }
                let rc1 = ffi::hook::wxshadow_patch(
                    addr as *mut std::ffi::c_void,
                    bytes.as_ptr() as *const std::ffi::c_void,
                    first_len,
                );
                if rc1 != 0 {
                    ffi::hook::wxshadow_release(second_addr as *mut std::ffi::c_void);
                    let msg = format!(
                        "writeBytes(stealth=1): kernel_hook first-page rc={}, second 已回滚\0",
                        rc1
                    );
                    return ffi::JS_ThrowInternalError(ctx, b"%s\0".as_ptr() as *const _, msg.as_ptr());
                }
                ffi::hook::hook_flush_cache(addr as *mut _, len);
                track_wxshadow_addr(addr);
                track_wxshadow_addr(second_addr);
            } else {
                let rc = ffi::hook::wxshadow_patch(
                    addr as *mut std::ffi::c_void,
                    bytes.as_ptr() as *const std::ffi::c_void,
                    len,
                );
                if rc != 0 {
                    let msg = format!("writeBytes(stealth=1): kernel_hook write rc={}\0", rc);
                    return ffi::JS_ThrowInternalError(ctx, b"%s\0".as_ptr() as *const _, msg.as_ptr());
                }
                ffi::hook::hook_flush_cache(addr as *mut _, len);
                track_wxshadow_addr(addr);
            }
            write_success(ctx, this)
        }
        other => {
            let msg = format!(
                "writeBytes: unsupported stealth mode {} (expected 0 or 1; use writest for mode 2)\0",
                other
            );
            ffi::JS_ThrowInternalError(ctx, b"%s\0".as_ptr() as *const _, msg.as_ptr())
        }
    }
}

pub(super) unsafe extern "C" fn memory_write_volatile(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let result = memory_write_bytes(ctx, this, argc, argv);
    if ffi::qjs_is_exception(result) != 0 {
        return result;
    }
    ffi::qjs_free_value(ctx, result);
    JSValue::undefined().raw()
}
