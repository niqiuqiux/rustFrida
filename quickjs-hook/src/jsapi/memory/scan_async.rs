//! `Memory.scan(address, size, pattern, callbacks)` — background pattern scan.
//!
//! The scan runs on its own thread and re-enters JavaScript for each callback
//! through the same engine guard the other native callbacks use, so it obeys
//! the runtime's owner rules instead of opening a second uncontrolled entry.
//!
//! Upstream wraps this in a Promise from `runtime/core.js`. That wrapper needs a
//! job queue to settle, which arrives with the message loop in Goal 07, so the
//! callback form is the one exposed here.

use super::scan::{parse_pattern_argument, scan_range_chunked, MatchPattern};
use crate::ffi;
use crate::jsapi::callback_util::{
    acquire_js_engine_for_callback, extract_pointer_address, handle_js_exception, throw_internal_error,
};
use crate::jsapi::ptr::create_native_pointer;
use crate::value::JSValue;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Condvar, Mutex};

/// One in-flight scan. The JS callbacks are held as duplicated values so the
/// scanning thread keeps them alive without touching the GC from off-thread.
struct ScanJob {
    id: u64,
    context: usize,
    cancelled: AtomicBool,
}

static SCAN_JOBS: Mutex<Vec<std::sync::Arc<ScanJob>>> = Mutex::new(Vec::new());
static NEXT_SCAN_ID: AtomicU64 = AtomicU64::new(1);
static IN_FLIGHT_SCANS: Mutex<usize> = Mutex::new(0);
static IN_FLIGHT_SCANS_CV: Condvar = Condvar::new();

struct InFlightScanGuard;

impl InFlightScanGuard {
    fn enter() -> Self {
        let mut count = IN_FLIGHT_SCANS.lock().unwrap_or_else(|error| error.into_inner());
        *count += 1;
        Self
    }
}

impl Drop for InFlightScanGuard {
    fn drop(&mut self) {
        let mut count = IN_FLIGHT_SCANS.lock().unwrap_or_else(|error| error.into_inner());
        *count = count.saturating_sub(1);
        if *count == 0 {
            IN_FLIGHT_SCANS_CV.notify_all();
        }
    }
}

/// Stop every scan belonging to this runtime and stop new callbacks entering it.
///
/// Called from the cleanup path before the QuickJS runtime is destroyed; the
/// scan threads observe the flag between chunks, so a long scan cannot outlive
/// the context it would call back into.
pub fn cut_memory_scans() {
    let jobs = SCAN_JOBS.lock().unwrap_or_else(|error| error.into_inner());
    for job in jobs.iter() {
        job.cancelled.store(true, Ordering::SeqCst);
    }
}

/// Wait for scan callbacks to finish after [`cut_memory_scans`].
pub fn wait_for_memory_scans(timeout: std::time::Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    let mut count = IN_FLIGHT_SCANS.lock().unwrap_or_else(|error| error.into_inner());
    while *count != 0 {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return false;
        }
        let (guard, result) = IN_FLIGHT_SCANS_CV
            .wait_timeout(count, remaining)
            .unwrap_or_else(|error| error.into_inner());
        count = guard;
        if result.timed_out() && *count != 0 {
            return false;
        }
    }
    true
}

fn unregister_job(id: u64) {
    let mut jobs = SCAN_JOBS.lock().unwrap_or_else(|error| error.into_inner());
    jobs.retain(|job| job.id != id);
}

/// Duplicated JS callbacks. `usize` rather than `JSValue` so the struct can
/// cross into the scanning thread; they are only ever touched while holding the
/// engine guard for `context`.
struct ScanCallbacks {
    on_match: Option<ffi::JSValue>,
    on_error: Option<ffi::JSValue>,
    on_complete: Option<ffi::JSValue>,
}

// The values are owned by the job and only dereferenced under the engine guard.
unsafe impl Send for ScanCallbacks {}

unsafe fn dup_callback(ctx: *mut ffi::JSContext, object: JSValue, name: &std::ffi::CStr) -> Option<ffi::JSValue> {
    let value = JSValue(ffi::JS_GetPropertyStr(ctx, object.raw(), name.as_ptr()));
    if value.is_function(ctx) {
        Some(value.raw())
    } else {
        value.free(ctx);
        None
    }
}

unsafe fn call_scan_callback(ctx: *mut ffi::JSContext, callback: ffi::JSValue, arguments: &[ffi::JSValue]) {
    let global = ffi::JS_GetGlobalObject(ctx);
    let result = ffi::JS_Call(
        ctx,
        callback,
        global,
        arguments.len() as i32,
        arguments.as_ptr() as *mut _,
    );
    handle_js_exception(ctx, result, "Memory.scan");
    ffi::qjs_free_value(ctx, result);
    ffi::qjs_free_value(ctx, global);
}

fn run_scan(job: std::sync::Arc<ScanJob>, address: u64, size: usize, pattern: MatchPattern, callbacks: ScanCallbacks) {
    let _in_flight = InFlightScanGuard::enter();
    let ctx = job.context as *mut ffi::JSContext;

    let mut error: Option<String> = None;
    let mut cancelled = false;

    scan_range_chunked(address, size, &pattern, |match_address| {
        if job.cancelled.load(Ordering::SeqCst) {
            cancelled = true;
            return false;
        }
        let Some(on_match) = callbacks.on_match else {
            return true;
        };
        unsafe {
            let Some(_guard) = acquire_js_engine_for_callback(ctx, "Memory.scan onMatch", job.id) else {
                cancelled = true;
                return false;
            };
            if job.cancelled.load(Ordering::SeqCst) {
                cancelled = true;
                return false;
            }
            let arguments = [
                create_native_pointer(ctx, match_address).raw(),
                ffi::qjs_new_int64(ctx, pattern.len() as i64),
            ];
            call_scan_callback(ctx, on_match, &arguments);
            for argument in arguments {
                ffi::qjs_free_value(ctx, argument);
            }
        }
        true
    })
    .unwrap_or_else(|reason| error = Some(reason));

    if !cancelled && !job.cancelled.load(Ordering::SeqCst) {
        unsafe {
            if let Some(_guard) = acquire_js_engine_for_callback(ctx, "Memory.scan completion", job.id) {
                if !job.cancelled.load(Ordering::SeqCst) {
                    if let (Some(reason), Some(on_error)) = (error.as_ref(), callbacks.on_error) {
                        let message = ffi::JS_NewStringLen(ctx, reason.as_ptr() as *const _, reason.len());
                        call_scan_callback(ctx, on_error, &[message]);
                        ffi::qjs_free_value(ctx, message);
                    }
                    if let Some(on_complete) = callbacks.on_complete {
                        call_scan_callback(ctx, on_complete, &[]);
                    }
                }
            }
        }
    }

    // Release the callbacks under the guard so the GC sees a consistent state.
    unsafe {
        if let Some(_guard) = acquire_js_engine_for_callback(ctx, "Memory.scan teardown", job.id) {
            for callback in [callbacks.on_match, callbacks.on_error, callbacks.on_complete]
                .into_iter()
                .flatten()
            {
                ffi::qjs_free_value(ctx, callback);
            }
        }
    }
    unregister_job(job.id);
}

pub(super) unsafe extern "C" fn memory_scan(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 4 {
        return throw_internal_error(ctx, "Memory.scan() requires (address, size, pattern, callbacks)");
    }
    let address = match extract_pointer_address(ctx, JSValue(*argv), "Memory.scan") {
        Ok(value) => value,
        Err(error) => return error,
    };
    let size = match JSValue(*argv.add(1)).to_i64(ctx) {
        Some(value) if value >= 0 && value <= 0x7fff_ffff => value as usize,
        _ => return throw_internal_error(ctx, "Memory.scan() invalid size"),
    };
    let pattern = match parse_pattern_argument(ctx, JSValue(*argv.add(2)), "Memory.scan") {
        Ok(value) => value,
        Err(error) => return error,
    };
    let callbacks_value = JSValue(*argv.add(3));
    if ffi::qjs_is_object(callbacks_value.raw()) == 0 {
        return throw_internal_error(ctx, "Memory.scan() callbacks must be an object");
    }
    let callbacks = ScanCallbacks {
        on_match: dup_callback(ctx, callbacks_value, c"onMatch"),
        on_error: dup_callback(ctx, callbacks_value, c"onError"),
        on_complete: dup_callback(ctx, callbacks_value, c"onComplete"),
    };

    let job = std::sync::Arc::new(ScanJob {
        id: NEXT_SCAN_ID.fetch_add(1, Ordering::Relaxed),
        context: ctx as usize,
        cancelled: AtomicBool::new(false),
    });
    SCAN_JOBS
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .push(std::sync::Arc::clone(&job));

    let spawned = std::thread::Builder::new()
        .name("rf-memory-scan".to_string())
        .spawn(move || run_scan(job, address, size, pattern, callbacks));
    if let Err(error) = spawned {
        return throw_internal_error(ctx, format!("Memory.scan() could not start scan thread: {error}"));
    }
    JSValue::undefined().raw()
}
