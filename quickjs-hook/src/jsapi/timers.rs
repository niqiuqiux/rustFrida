//! Timers and the job pump: `setTimeout`, `setInterval`, `Script.nextTick`.
//!
//! A script's top-level run ends long before its timers do, so a background
//! thread owns the schedule and enters JavaScript through the same engine guard
//! the other native callbacks use. That thread also drains the QuickJS job
//! queue, which is what lets promises settle after the top-level run returns.
//!
//! The thread is started lazily by the first timer and stopped by the cleanup
//! path, so a script that never schedules anything keeps the previous
//! thread-free teardown behaviour.

use crate::ffi;
use crate::jsapi::callback_util::{acquire_js_engine_for_callback, handle_js_exception, throw_internal_error};
use crate::value::JSValue;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

/// How long the pump sleeps when nothing is scheduled but jobs may still arrive.
const IDLE_POLL: Duration = Duration::from_millis(20);
const JOIN_POLL: Duration = Duration::from_millis(5);

#[derive(Clone, Copy, PartialEq, Eq)]
enum TimerKind {
    Once,
    Repeating,
    /// Runs before any timeout, in registration order.
    NextTick,
}

struct Timer {
    id: u64,
    context: usize,
    callback: ffi::JSValue,
    due: Instant,
    interval: Duration,
    kind: TimerKind,
}

// The callback is only touched while holding the engine guard for `context`.
unsafe impl Send for Timer {}

struct TimerState {
    timers: Vec<Timer>,
    /// Set while a callback is running so `clearTimeout` from inside it is seen.
    running: Option<u64>,
    cancelled_running: bool,
}

static TIMERS: Mutex<TimerState> = Mutex::new(TimerState {
    timers: Vec::new(),
    running: None,
    cancelled_running: false,
});
static TIMERS_CV: Condvar = Condvar::new();
static NEXT_TIMER_ID: AtomicU64 = AtomicU64::new(1);
static PUMP_RUNNING: AtomicBool = AtomicBool::new(false);
static PUMP_STOP: AtomicBool = AtomicBool::new(true);
static PUMP_IN_CALLBACK: AtomicBool = AtomicBool::new(false);
/// Handle of the pump thread, so teardown can join it.
///
/// A flag alone is not enough: the agent is unmapped right after teardown
/// returns, and a thread that had merely set its "done" flag would still
/// have code to run in memory that is no longer there.
static PUMP_HANDLE: Mutex<Option<std::thread::JoinHandle<()>>> = Mutex::new(None);
/// Timers dropped by teardown, waiting for a safe point to release their
/// callbacks. The runtime asserts on outstanding references when it is freed,
/// so these must be released — just not while the pump might still be using
/// the engine.
static RETIRED_TIMERS: Mutex<Vec<Timer>> = Mutex::new(Vec::new());

fn lock_timers() -> std::sync::MutexGuard<'static, TimerState> {
    TIMERS.lock().unwrap_or_else(|error| error.into_inner())
}

/// Drop every timer and stop the pump.
///
/// Called from the cleanup path before the runtime is torn down: a timer that
/// fired afterwards would enter a destroyed context.
pub fn cut_timers() {
    PUMP_STOP.store(true, Ordering::SeqCst);
    let retired = {
        let mut state = lock_timers();
        state.cancelled_running = true;
        std::mem::take(&mut state.timers)
    };
    // Hand the callbacks to the release queue rather than freeing them here:
    // the pump may be mid-callback with the engine held, and this runs on the
    // thread that owns it.
    RETIRED_TIMERS
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .extend(retired);
    TIMERS_CV.notify_all();
}

/// Release the callbacks of timers dropped by [`cut_timers`].
///
/// Runs once the pump is known to be out of JavaScript, on the thread that owns
/// the engine, so the reference drops are seen by the runtime before it is
/// freed.
fn release_retired_timers() {
    let retired = std::mem::take(&mut *RETIRED_TIMERS.lock().unwrap_or_else(|error| error.into_inner()));
    for timer in retired {
        let ctx = timer.context as *mut ffi::JSContext;
        unsafe {
            if let Some(_guard) = acquire_js_engine_for_callback(ctx, "timer teardown", timer.id) {
                ffi::qjs_free_value(ctx, timer.callback);
            }
        }
    }
}

/// Wait until no timer callback is inside JavaScript.
///
/// This is what a script reload needs: the pump may keep running, it just must
/// not be in the runtime that is about to be replaced. Joining here would
/// deadlock, because the caller holds the engine the pump is waiting for.
pub fn wait_for_timer_callbacks(timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while PUMP_IN_CALLBACK.load(Ordering::SeqCst) {
        if Instant::now() >= deadline {
            return false;
        }
        TIMERS_CV.notify_all();
        std::thread::sleep(JOIN_POLL);
    }
    release_retired_timers();
    true
}

/// Wait for the pump thread to exit and join it.
///
/// Only for agent teardown: the code the thread runs is unmapped right after,
/// so a thread that had merely set its "done" flag is not good enough.
pub fn wait_for_timers(timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while PUMP_RUNNING.load(Ordering::SeqCst) || PUMP_IN_CALLBACK.load(Ordering::SeqCst) {
        if Instant::now() >= deadline {
            return false;
        }
        TIMERS_CV.notify_all();
        std::thread::sleep(JOIN_POLL);
    }
    let handle = PUMP_HANDLE.lock().unwrap_or_else(|error| error.into_inner()).take();
    if let Some(handle) = handle {
        let _ = handle.join();
    }
    release_retired_timers();
    true
}

/// Number of scheduled timers, for diagnostics and tests.
pub fn scheduled_timer_count() -> usize {
    lock_timers().timers.len()
}

fn next_due(state: &TimerState) -> Option<Instant> {
    state
        .timers
        .iter()
        .map(|timer| {
            if timer.kind == TimerKind::NextTick {
                None
            } else {
                Some(timer.due)
            }
        })
        .map(|due| due.unwrap_or_else(Instant::now))
        .min()
}

/// Take the timer that should run now, if any.
fn take_due_timer(state: &mut TimerState, now: Instant) -> Option<Timer> {
    // nextTick entries always win, in registration order.
    if let Some(index) = state.timers.iter().position(|timer| timer.kind == TimerKind::NextTick) {
        return Some(state.timers.remove(index));
    }
    let index = state
        .timers
        .iter()
        .enumerate()
        .filter(|(_, timer)| timer.due <= now)
        .min_by_key(|(_, timer)| timer.due)
        .map(|(index, _)| index)?;
    Some(state.timers.remove(index))
}

/// Run one timer and decide its fate, all under a single engine guard.
///
/// Acquiring the engine twice — once to call, once to release the callback —
/// would let another thread run JavaScript in between and collect the very
/// value being released.
///
/// Returns the timer when it should be rescheduled, and `None` once its
/// callback has been released.
unsafe fn run_and_retire(timer: Timer) -> Option<Timer> {
    let ctx = timer.context as *mut ffi::JSContext;
    let Some(_guard) = acquire_js_engine_for_callback(ctx, "timer", timer.id) else {
        // Without the engine the callback cannot be released safely either;
        // hand the timer back so the next round retries.
        return Some(timer);
    };

    if JSValue(timer.callback).is_function(ctx) {
        let global = ffi::JS_GetGlobalObject(ctx);
        // Pass a real (unused) slot rather than null: some QuickJS builtins
        // reachable from here read argv[0] regardless of argc.
        let arguments = [JSValue::undefined().raw()];
        let result = ffi::JS_Call(ctx, timer.callback, global, 0, arguments.as_ptr() as *mut _);
        handle_js_exception(ctx, result, "timer");
        ffi::qjs_free_value(ctx, result);
        ffi::qjs_free_value(ctx, global);
        drain_jobs(ctx);
    }

    let mut state = lock_timers();
    state.running = None;
    let cancelled = state.cancelled_running || PUMP_STOP.load(Ordering::SeqCst);
    state.cancelled_running = false;
    drop(state);

    if timer.kind == TimerKind::Repeating && !cancelled {
        return Some(Timer {
            due: Instant::now() + timer.interval,
            ..timer
        });
    }
    ffi::qjs_free_value(ctx, timer.callback);
    None
}

/// Run queued promise reactions. Without this a promise settled from a timer or
/// a native callback would never reach its `then`.
unsafe fn drain_jobs(ctx: *mut ffi::JSContext) {
    let runtime = ffi::JS_GetRuntime(ctx);
    let mut pending: *mut ffi::JSContext = std::ptr::null_mut();
    let mut budget = 1024;
    while budget > 0 && ffi::JS_ExecutePendingJob(runtime, &mut pending) > 0 {
        budget -= 1;
    }
}

fn pump_loop() {
    while !PUMP_STOP.load(Ordering::SeqCst) {
        let due = {
            let state = lock_timers();
            if state.timers.is_empty() {
                None
            } else {
                next_due(&state)
            }
        };

        let now = Instant::now();
        match due {
            Some(due) if due > now => {
                let wait = (due - now).min(IDLE_POLL);
                let state = lock_timers();
                let _ = TIMERS_CV.wait_timeout(state, wait);
                continue;
            }
            None => {
                let state = lock_timers();
                let _ = TIMERS_CV.wait_timeout(state, IDLE_POLL);
                continue;
            }
            Some(_) => {}
        }

        let timer = {
            let mut state = lock_timers();
            let Some(timer) = take_due_timer(&mut state, Instant::now()) else {
                continue;
            };
            state.running = Some(timer.id);
            state.cancelled_running = false;
            timer
        };

        // Teardown may have started between taking the timer and here. Do not
        // reach for the engine in that window: the thread running teardown holds
        // it, so this would block until it times out.
        if PUMP_STOP.load(Ordering::SeqCst) {
            RETIRED_TIMERS
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .push(timer);
            break;
        }

        PUMP_IN_CALLBACK.store(true, Ordering::SeqCst);
        let rescheduled = unsafe { run_and_retire(timer) };
        PUMP_IN_CALLBACK.store(false, Ordering::SeqCst);

        if let Some(timer) = rescheduled {
            if PUMP_STOP.load(Ordering::SeqCst) {
                RETIRED_TIMERS
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .push(timer);
                break;
            }
            lock_timers().timers.push(timer);
        }
    }
}

fn ensure_pump() -> Result<(), String> {
    if PUMP_RUNNING.load(Ordering::SeqCst) {
        PUMP_STOP.store(false, Ordering::SeqCst);
        return Ok(());
    }
    PUMP_STOP.store(false, Ordering::SeqCst);
    PUMP_RUNNING.store(true, Ordering::SeqCst);
    let spawned = std::thread::Builder::new().name("rf-js-timers".to_string()).spawn(|| {
        // A panic here would otherwise reach the agent's panic hook, which
        // aborts. Report it and let the pump stop; the session stays usable.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(pump_loop));
        if let Err(payload) = result {
            let reason = payload
                .downcast_ref::<&str>()
                .map(|text| (*text).to_string())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "unknown panic".to_string());
            crate::jsapi::console::output_message(&format!("[timers] pump thread panicked: {reason}"));
        }
        PUMP_IN_CALLBACK.store(false, Ordering::SeqCst);
        // Last statement: teardown watches this before joining.
        PUMP_RUNNING.store(false, Ordering::SeqCst);
    });
    match spawned {
        Ok(handle) => {
            *PUMP_HANDLE.lock().unwrap_or_else(|error| error.into_inner()) = Some(handle);
            Ok(())
        }
        Err(error) => {
            PUMP_RUNNING.store(false, Ordering::SeqCst);
            Err(format!("could not start the timer thread: {error}"))
        }
    }
}

unsafe fn schedule(ctx: *mut ffi::JSContext, argc: i32, argv: *mut ffi::JSValue, kind: TimerKind) -> ffi::JSValue {
    if argc < 1 {
        return throw_internal_error(ctx, "a timer requires a callback");
    }
    let callback = JSValue(*argv);
    if !callback.is_function(ctx) {
        return throw_internal_error(ctx, "a timer callback must be a function");
    }
    let delay = if kind == TimerKind::NextTick {
        0
    } else {
        match argc >= 2 {
            true => JSValue(*argv.add(1)).to_i64(ctx).unwrap_or(0).max(0),
            false => 0,
        }
    };
    // Repeating timers must make progress even when asked for zero delay.
    let interval = Duration::from_millis(if kind == TimerKind::Repeating {
        (delay as u64).max(1)
    } else {
        delay as u64
    });

    if let Err(error) = ensure_pump() {
        return throw_internal_error(ctx, error);
    }

    let id = NEXT_TIMER_ID.fetch_add(1, Ordering::Relaxed);
    let timer = Timer {
        id,
        context: ctx as usize,
        callback: ffi::qjs_dup_value(ctx, callback.raw()),
        due: Instant::now() + interval,
        interval,
        kind,
    };
    lock_timers().timers.push(timer);
    TIMERS_CV.notify_all();
    ffi::qjs_new_int64(ctx, id as i64)
}

unsafe extern "C" fn js_set_timeout(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    schedule(ctx, argc, argv, TimerKind::Once)
}

unsafe extern "C" fn js_set_interval(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    schedule(ctx, argc, argv, TimerKind::Repeating)
}

unsafe extern "C" fn js_next_tick(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let result = schedule(ctx, argc, argv, TimerKind::NextTick);
    if JSValue(result).is_exception() {
        return result;
    }
    ffi::qjs_free_value(ctx, result);
    JSValue::undefined().raw()
}

unsafe extern "C" fn js_clear_timer(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return JSValue::undefined().raw();
    }
    let Some(id) = JSValue(*argv).to_u64(ctx) else {
        return JSValue::undefined().raw();
    };

    let removed = {
        let mut state = lock_timers();
        if state.running == Some(id) {
            // Clearing the timer that is currently running: stop it from being
            // rescheduled rather than trying to remove it from the list.
            state.cancelled_running = true;
        }
        state
            .timers
            .iter()
            .position(|timer| timer.id == id)
            .map(|index| state.timers.remove(index))
    };
    if let Some(timer) = removed {
        ffi::qjs_free_value(ctx, timer.callback);
    }
    JSValue::undefined().raw()
}

/// Run any promise reactions queued by native callbacks, without waiting for
/// the pump. Used by the facade after re-entering JavaScript.
pub fn drain_pending_jobs(ctx: *mut ffi::JSContext) {
    unsafe { drain_jobs(ctx) };
}

pub fn register_timer_api(ctx: &crate::context::JSContext) {
    use crate::jsapi::util::add_cfunction_to_object;

    let global = ctx.global_object();
    unsafe {
        let raw = global.raw();
        add_cfunction_to_object(ctx.as_ptr(), raw, "__rf_set_timeout", js_set_timeout, 2);
        add_cfunction_to_object(ctx.as_ptr(), raw, "__rf_set_interval", js_set_interval, 2);
        add_cfunction_to_object(ctx.as_ptr(), raw, "__rf_clear_timer", js_clear_timer, 1);
        add_cfunction_to_object(ctx.as_ptr(), raw, "__rf_next_tick", js_next_tick, 1);
    }
    global.free(ctx.as_ptr());
}
