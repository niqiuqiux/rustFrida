//! `Memory.patchCode(address, size, apply)` — Frida-compatible code patching.
//!
//! The callback runs with the target pages temporarily writable and the
//! instruction cache flushed afterwards. Protection is restored even when the
//! callback throws, so a failed patch cannot leave the pages writable.
//!
//! This is the portable entry point. It briefly makes executable pages
//! writable, which a thread executing them at that moment can observe; the
//! project's `writeBytes(bytes, 1)` (wxshadow) and `writest()` (recomp slot)
//! paths exist for cases where that window is unacceptable.

use super::alloc::{format_protection, query_page_size};
use crate::ffi;
use crate::jsapi::callback_util::{extract_pointer_address, handle_js_exception, throw_internal_error};
use crate::jsapi::ptr::create_native_pointer;
use crate::jsapi::util::{canonicalize_user_address, query_page_protection};
use crate::value::JSValue;

/// Page range covering `[address, address + size)`.
fn page_range(address: u64, size: usize) -> Option<(usize, usize)> {
    let page_size = query_page_size();
    let address = canonicalize_user_address(address) as usize;
    let end = address.checked_add(size)?;
    let start = address & !(page_size - 1);
    let aligned_end = end.checked_add(page_size - 1)? & !(page_size - 1);
    Some((start, aligned_end.checked_sub(start)?))
}

/// Make the range writable, preferring to keep EXEC so a thread running this
/// code does not fault mid-patch. Falls back to plain RW when the kernel or
/// SELinux refuses a writable+executable mapping.
unsafe fn make_writable(start: usize, length: usize, original: i32) -> Result<i32, String> {
    let preferred = original | libc::PROT_READ | libc::PROT_WRITE;
    if libc::mprotect(start as *mut libc::c_void, length, preferred) == 0 {
        return Ok(preferred);
    }
    let fallback = libc::PROT_READ | libc::PROT_WRITE;
    if libc::mprotect(start as *mut libc::c_void, length, fallback) == 0 {
        return Ok(fallback);
    }
    Err(format!(
        "unable to make 0x{start:x}+{length} writable: {}",
        std::io::Error::last_os_error()
    ))
}

pub(super) unsafe extern "C" fn memory_patch_code(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 3 {
        return throw_internal_error(ctx, "Memory.patchCode() requires (address, size, apply)");
    }
    let address = match extract_pointer_address(ctx, JSValue(*argv), "Memory.patchCode") {
        Ok(value) => value,
        Err(error) => return error,
    };
    let size = match JSValue(*argv.add(1)).to_i64(ctx) {
        Some(value) if value > 0 && value <= 0x7fff_ffff => value as usize,
        _ => return throw_internal_error(ctx, "Memory.patchCode() invalid size"),
    };
    let apply = JSValue(*argv.add(2));
    if !apply.is_function(ctx) {
        return throw_internal_error(ctx, "Memory.patchCode() apply must be a function");
    }

    let Some((start, length)) = page_range(address, size) else {
        return throw_internal_error(ctx, "Memory.patchCode() address range overflow");
    };
    let Some(original) = query_page_protection(address) else {
        return throw_internal_error(ctx, "Memory.patchCode() address is not mapped");
    };

    // Nothing has been modified yet, so a failure here leaves the target intact.
    let granted = match make_writable(start, length, original) {
        Ok(value) => value,
        Err(error) => return throw_internal_error(ctx, error),
    };

    let target = create_native_pointer(ctx, address);
    let argument = target.raw();
    let global = ffi::JS_GetGlobalObject(ctx);
    let result = ffi::JS_Call(ctx, apply.raw(), global, 1, &argument as *const _ as *mut _);
    let had_exception = handle_js_exception(ctx, result, "Memory.patchCode");
    ffi::qjs_free_value(ctx, result);
    target.free(ctx);
    ffi::qjs_free_value(ctx, global);

    // Restore before reporting anything: leaving the pages writable would be a
    // worse outcome than the patch itself failing.
    let restored = libc::mprotect(start as *mut libc::c_void, length, original) == 0;
    ffi::hook::hook_flush_cache(canonicalize_user_address(address) as *mut _, size);

    if had_exception {
        // The exception raised by `apply` is already pending.
        return ffi::qjs_exception();
    }
    if !restored {
        return throw_internal_error(
            ctx,
            format!(
                "Memory.patchCode() could not restore protection \"{}\" at 0x{start:x} (left \"{}\")",
                format_protection(original),
                format_protection(granted)
            ),
        );
    }
    JSValue::undefined().raw()
}
