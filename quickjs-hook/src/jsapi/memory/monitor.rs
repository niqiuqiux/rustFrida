//! `MemoryAccessMonitor` — page-granular access notifications.
//!
//! The monitor itself lives in the Gum backend because it needs the fault
//! handler; this file owns the JavaScript surface and the callback root, and
//! guarantees the callback stops firing before its runtime goes away.

use crate::ffi;
use crate::jsapi::callback_util::{
    acquire_js_engine_for_callback, extract_pointer_address, handle_js_exception, throw_internal_error,
};
use crate::jsapi::ptr::create_native_pointer;
use crate::value::JSValue;
use std::sync::Mutex;

/// One monitored access, mirroring upstream `MemoryAccessDetails`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct MemoryAccessInfo {
    pub thread_id: u64,
    /// 0 invalid, 1 read, 2 write, 3 execute.
    pub operation: u32,
    pub from: u64,
    pub address: u64,
    pub range_index: u32,
    pub page_index: u32,
    pub pages_completed: u32,
    pub pages_total: u32,
}

#[derive(Clone, Copy)]
pub struct MemoryMonitorBackend {
    /// Install the monitor over `ranges` and report accesses to `context`.
    pub enable: fn(&[(u64, u64)], usize) -> Result<(), String>,
    pub disable: fn() -> Result<(), String>,
}

/// The JavaScript `onAccess` callback, kept alive for as long as the monitor is
/// installed. The value is only ever touched while holding the engine guard for
/// `context`, which is what makes moving it across threads sound.
#[derive(Clone, Copy)]
struct CallbackRoot {
    context: usize,
    value: ffi::JSValue,
}

unsafe impl Send for CallbackRoot {}

static MONITOR_BACKEND: Mutex<Option<MemoryMonitorBackend>> = Mutex::new(None);
static ON_ACCESS: Mutex<Option<CallbackRoot>> = Mutex::new(None);

pub fn install_memory_monitor_backend(backend: MemoryMonitorBackend) {
    *MONITOR_BACKEND.lock().unwrap_or_else(|error| error.into_inner()) = Some(backend);
}

fn backend() -> Option<MemoryMonitorBackend> {
    *MONITOR_BACKEND.lock().unwrap_or_else(|error| error.into_inner())
}

/// Tear the monitor down and drop the callback root.
///
/// Called from the cleanup path: a monitor left enabled would keep faulting
/// into a destroyed runtime.
pub fn cut_memory_monitor() {
    if let Some(backend) = backend() {
        let _ = (backend.disable)();
    }
    let callback = ON_ACCESS.lock().unwrap_or_else(|error| error.into_inner()).take();
    if let Some(root) = callback {
        let ctx = root.context as *mut ffi::JSContext;
        unsafe {
            if let Some(_guard) = acquire_js_engine_for_callback(ctx, "MemoryAccessMonitor teardown", 0) {
                ffi::qjs_free_value(ctx, root.value);
            }
        }
    }
}

fn operation_name(operation: u32) -> &'static str {
    match operation {
        1 => "read",
        2 => "write",
        3 => "execute",
        _ => "invalid",
    }
}

/// Called by the backend from the faulting thread.
pub fn dispatch_memory_access(info: MemoryAccessInfo) {
    let callback = {
        let guard = ON_ACCESS.lock().unwrap_or_else(|error| error.into_inner());
        *guard
    };
    let Some(root) = callback else {
        return;
    };
    let ctx = root.context as *mut ffi::JSContext;
    let callback = root.value;

    unsafe {
        let Some(_guard) = acquire_js_engine_for_callback(ctx, "MemoryAccessMonitor onAccess", info.thread_id) else {
            return;
        };
        // A script aborted mid-flight (execution timeout, thrown error) can
        // leave the monitor installed while its callback is gone. Faults keep
        // arriving until the cleanup path runs, so re-check before calling.
        if !JSValue(callback).is_function(ctx) {
            return;
        }
        let details = ffi::JS_NewObject(ctx);
        let operation = operation_name(info.operation);
        ffi::JS_SetPropertyStr(
            ctx,
            details,
            c"operation".as_ptr(),
            ffi::JS_NewStringLen(ctx, operation.as_ptr() as *const _, operation.len()),
        );
        ffi::JS_SetPropertyStr(
            ctx,
            details,
            c"from".as_ptr(),
            create_native_pointer(ctx, info.from).raw(),
        );
        ffi::JS_SetPropertyStr(
            ctx,
            details,
            c"address".as_ptr(),
            create_native_pointer(ctx, info.address).raw(),
        );
        ffi::JS_SetPropertyStr(
            ctx,
            details,
            c"rangeIndex".as_ptr(),
            ffi::qjs_new_int64(ctx, info.range_index as i64),
        );
        ffi::JS_SetPropertyStr(
            ctx,
            details,
            c"pageIndex".as_ptr(),
            ffi::qjs_new_int64(ctx, info.page_index as i64),
        );
        ffi::JS_SetPropertyStr(
            ctx,
            details,
            c"pagesCompleted".as_ptr(),
            ffi::qjs_new_int64(ctx, info.pages_completed as i64),
        );
        ffi::JS_SetPropertyStr(
            ctx,
            details,
            c"pagesTotal".as_ptr(),
            ffi::qjs_new_int64(ctx, info.pages_total as i64),
        );
        ffi::JS_SetPropertyStr(
            ctx,
            details,
            c"threadId".as_ptr(),
            ffi::qjs_new_int64(ctx, info.thread_id as i64),
        );

        let global = ffi::JS_GetGlobalObject(ctx);
        let result = ffi::JS_Call(ctx, callback, global, 1, &details as *const _ as *mut _);
        handle_js_exception(ctx, result, "MemoryAccessMonitor onAccess");
        ffi::qjs_free_value(ctx, result);
        ffi::qjs_free_value(ctx, details);
        ffi::qjs_free_value(ctx, global);
    }
}

unsafe fn parse_monitor_ranges(ctx: *mut ffi::JSContext, value: JSValue) -> Result<Vec<(u64, u64)>, ffi::JSValue> {
    let length = JSValue(ffi::JS_GetPropertyStr(ctx, value.raw(), c"length".as_ptr()));
    let count = length.to_u64(ctx);
    length.free(ctx);
    let Some(count) = count else {
        return Err(throw_internal_error(
            ctx,
            "MemoryAccessMonitor.enable() ranges must be an array of {base, size}",
        ));
    };

    let mut ranges = Vec::with_capacity(count as usize);
    for index in 0..count {
        let entry = JSValue(ffi::JS_GetPropertyUint32(ctx, value.raw(), index as u32));
        let base_value = JSValue(ffi::JS_GetPropertyStr(ctx, entry.raw(), c"base".as_ptr()));
        let base = extract_pointer_address(ctx, base_value, "MemoryAccessMonitor.enable() range base");
        base_value.free(ctx);
        let size_value = JSValue(ffi::JS_GetPropertyStr(ctx, entry.raw(), c"size".as_ptr()));
        let size = size_value.to_i64(ctx);
        size_value.free(ctx);
        entry.free(ctx);

        let base = base?;
        let Some(size) = size.filter(|size| *size > 0) else {
            return Err(throw_internal_error(
                ctx,
                "MemoryAccessMonitor.enable() invalid range size",
            ));
        };
        ranges.push((base, size as u64));
    }
    if ranges.is_empty() {
        return Err(throw_internal_error(
            ctx,
            "MemoryAccessMonitor.enable() expected one or more ranges",
        ));
    }
    Ok(ranges)
}

unsafe extern "C" fn js_monitor_enable(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let Some(backend) = backend() else {
        return throw_internal_error(
            ctx,
            "MemoryAccessMonitor requires the Gum backend, which this build does not have",
        );
    };
    if argc < 2 {
        return throw_internal_error(ctx, "MemoryAccessMonitor.enable() requires (ranges, callbacks)");
    }
    let ranges = match parse_monitor_ranges(ctx, JSValue(*argv)) {
        Ok(value) => value,
        Err(error) => return error,
    };

    let callbacks = JSValue(*argv.add(1));
    let on_access = JSValue(ffi::JS_GetPropertyStr(ctx, callbacks.raw(), c"onAccess".as_ptr()));
    if !on_access.is_function(ctx) {
        on_access.free(ctx);
        return throw_internal_error(
            ctx,
            "MemoryAccessMonitor.enable() callbacks.onAccess must be a function",
        );
    }

    // Replace any previous monitor first so a failed enable cannot leave two
    // callbacks registered.
    cut_memory_monitor();
    *ON_ACCESS.lock().unwrap_or_else(|error| error.into_inner()) = Some(CallbackRoot {
        context: ctx as usize,
        value: on_access.raw(),
    });

    if let Err(error) = (backend.enable)(&ranges, ctx as usize) {
        cut_memory_monitor();
        return throw_internal_error(ctx, format!("MemoryAccessMonitor.enable(): {error}"));
    }
    JSValue::undefined().raw()
}

unsafe extern "C" fn js_monitor_disable(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if backend().is_none() {
        return throw_internal_error(
            ctx,
            "MemoryAccessMonitor requires the Gum backend, which this build does not have",
        );
    }
    cut_memory_monitor();
    JSValue::undefined().raw()
}

pub(super) fn register_memory_monitor(ctx: &crate::context::JSContext) {
    use crate::jsapi::util::add_cfunction_to_object;

    let global = ctx.global_object();
    let monitor = ctx.new_object();
    unsafe {
        add_cfunction_to_object(ctx.as_ptr(), monitor.raw(), "enable", js_monitor_enable, 2);
        add_cfunction_to_object(ctx.as_ptr(), monitor.raw(), "disable", js_monitor_disable, 0);
        global.set_property(ctx.as_ptr(), "MemoryAccessMonitor", monitor);
    }
    global.free(ctx.as_ptr());
}
