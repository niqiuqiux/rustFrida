//! Frida-compatible Stalker facade backed by an agent-provided tracing engine.

use crate::context::JSContext;
use crate::ffi;
use crate::jsapi::callback_util::{
    acquire_js_engine_for_callback, extract_pointer_address, handle_js_exception, hot_atoms, set_js_u64_property,
    throw_internal_error,
};
use crate::jsapi::ptr::create_native_pointer;
use crate::jsapi::stalker_writer;
use crate::jsapi::util::add_cfunction_to_object;
use crate::runtime::SuspendedRuntime;
use crate::value::JSValue;
use std::ffi::c_void;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Condvar, Mutex};

#[derive(Clone, Debug)]
pub struct StalkerEventBatch {
    pub thread_id: u64,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, Default)]
pub struct StalkerDrainResult {
    pub pending: bool,
    pub batches: Vec<StalkerEventBatch>,
}

#[derive(Clone, Copy, Debug)]
pub struct StalkerFollowConfig {
    pub thread_id: u64,
    pub event_mask: u32,
    pub queue_capacity: u32,
    pub queue_drain_interval: u32,
    pub transform: bool,
    pub context: usize,
    pub native_event_callback: u64,
    pub native_event_data: u64,
    pub defer_current_thread: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct StalkerCallProbeConfig {
    pub id: u32,
    pub target_address: u64,
    pub context: usize,
    pub native_callback: u64,
    pub native_data: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct StalkerInstruction {
    pub id: u32,
    pub address: u64,
    pub size: u32,
    pub bytes_len: u32,
    pub bytes: [u8; 24],
    pub mnemonic: [u8; 32],
    pub op_str: [u8; 160],
}

impl Default for StalkerInstruction {
    fn default() -> Self {
        Self {
            id: 0,
            address: 0,
            size: 0,
            bytes_len: 0,
            bytes: [0; 24],
            mnemonic: [0; 32],
            op_str: [0; 160],
        }
    }
}

pub type StalkerTransformNext = unsafe extern "C" fn(usize, *mut StalkerInstruction) -> i32;
pub type StalkerTransformKeep = unsafe extern "C" fn(usize);
pub type StalkerTransformGetMemoryAccess = unsafe extern "C" fn(usize) -> u32;
pub type StalkerTransformPutCallout = unsafe extern "C" fn(usize, usize, u32, u64, u64) -> i32;
pub type StalkerTransformPutChainingReturn = unsafe extern "C" fn(usize);

/// Dispatch one ARM64 writer or relocator opcode. Arguments are flattened into a
/// `u64` slice encoded per `stalker_writer`'s spec strings; the result lands in
/// `out`. Returns 1 on success, 0 when Gum reported failure, and -1 when the
/// opcode or its encoding is invalid.
pub type StalkerWriterInvoke = unsafe extern "C" fn(usize, u32, *const u64, u32, *mut u64) -> i32;
/// Construct an ARM64 writer that is owned by a JavaScript `Arm64Writer`
/// object. `pc_specified` is zero or one; a separate flag preserves the
/// upstream distinction between an omitted `pc` and `pc: 0`.
pub type StalkerStandaloneWriterCreate = unsafe extern "C" fn(u64, u64, u32) -> usize;
/// Drop the owner reference returned by [`StalkerStandaloneWriterCreate`].
/// Any live `Arm64Relocator` keeps its own Gum reference to the writer.
pub type StalkerStandaloneWriterDestroy = unsafe extern "C" fn(usize);
/// Flush then reset a standalone writer, optionally overriding its logical PC.
pub type StalkerStandaloneWriterReset = unsafe extern "C" fn(usize, u64, u64, u32) -> i32;
/// Create a relocator reading `input_code` and writing through the transform's
/// output writer. Returns 0 on failure.
pub type StalkerRelocatorCreate = unsafe extern "C" fn(usize, u64) -> usize;
pub type StalkerRelocatorDestroy = unsafe extern "C" fn(usize);

#[derive(Clone, Copy)]
pub struct StalkerTransformAccess {
    pub opaque: usize,
    pub next: StalkerTransformNext,
    pub keep: StalkerTransformKeep,
    pub get_memory_access: StalkerTransformGetMemoryAccess,
    pub put_callout: StalkerTransformPutCallout,
    pub put_chaining_return: StalkerTransformPutChainingReturn,
    /// `GumArm64Writer` of the current `GumStalkerOutput`.
    pub writer: usize,
    pub writer_invoke: StalkerWriterInvoke,
    pub relocator_create: StalkerRelocatorCreate,
    pub relocator_destroy: StalkerRelocatorDestroy,
    pub relocator_invoke: StalkerWriterInvoke,
}

/// Register, condition and index-mode names resolved by the backend so the
/// JavaScript facade never hardcodes Capstone or Gum enum values.
#[derive(Clone, Debug, Default)]
pub struct StalkerWriterEnums {
    pub registers: Vec<(String, u32)>,
    pub conditions: Vec<(String, u32)>,
    pub index_modes: Vec<(String, u32)>,
}

/// Per-thread queue state reported by `Stalker.statistics()`.
#[derive(Clone, Copy, Debug, Default)]
pub struct StalkerTraceStatistics {
    pub thread_id: u64,
    pub queue_capacity: u64,
    pub queued_events: u64,
    pub dropped_events: u64,
}

/// Runtime counters for the Stalker backend. This is a rustFrida extension: it
/// makes the otherwise silent queue-full path and the retirement queues
/// observable from a script.
#[derive(Clone, Debug, Default)]
pub struct StalkerStatistics {
    pub dropped_events: u64,
    pub active_traces: u64,
    pub pending_traces: u64,
    pub retired_traces: u64,
    pub active_call_probes: u64,
    pub retired_call_probes: u64,
    pub call_probe_anchors: u64,
    pub traces: Vec<StalkerTraceStatistics>,
}

pub type StalkerProbeGetArgument = unsafe extern "C" fn(usize, u32) -> u64;
pub type StalkerProbeSetArgument = unsafe extern "C" fn(usize, u32, u64);
pub type StalkerCalloutGetRegister = unsafe extern "C" fn(usize, u32) -> u64;
pub type StalkerCalloutSetRegister = unsafe extern "C" fn(usize, u32, u64);
pub type StalkerCalloutGetVector = unsafe extern "C" fn(usize, u32, *mut u8) -> i32;
pub type StalkerCalloutSetVector = unsafe extern "C" fn(usize, u32, *const u8) -> i32;

#[derive(Clone, Copy)]
pub struct StalkerCalloutAccess {
    pub opaque: usize,
    pub get_register: StalkerCalloutGetRegister,
    pub set_register: StalkerCalloutSetRegister,
    pub get_vector: StalkerCalloutGetVector,
    pub set_vector: StalkerCalloutSetVector,
}

#[derive(Clone, Copy)]
pub struct StalkerBackend {
    pub is_supported: fn() -> bool,
    pub follow: fn(StalkerFollowConfig) -> Result<(), String>,
    pub drain_due: fn() -> Result<Vec<StalkerEventBatch>, String>,
    pub unfollow: fn(u64) -> Result<Vec<StalkerEventBatch>, String>,
    pub flush: fn() -> Result<Vec<StalkerEventBatch>, String>,
    pub garbage_collect: fn() -> Result<StalkerDrainResult, String>,
    pub exclude: fn(u64, u64) -> Result<(), String>,
    pub invalidate: fn(Option<u64>, u64) -> Result<(), String>,
    pub add_call_probe: fn(StalkerCallProbeConfig) -> Result<(), String>,
    pub remove_call_probe: fn(u32) -> Result<(), String>,
    pub get_trust_threshold: fn() -> Result<i32, String>,
    pub set_trust_threshold: fn(i32) -> Result<(), String>,
    pub process_pending: fn() -> Result<(), String>,
    pub activate_current: fn(u64) -> Result<bool, String>,
    pub deactivate_current: fn() -> Result<(), String>,
    pub shutdown: fn() -> Result<bool, String>,
    pub writer_enums: fn() -> StalkerWriterEnums,
    pub standalone_writer_create: StalkerStandaloneWriterCreate,
    pub standalone_writer_destroy: StalkerStandaloneWriterDestroy,
    pub standalone_writer_reset: StalkerStandaloneWriterReset,
    pub standalone_writer_invoke: StalkerWriterInvoke,
    pub standalone_relocator_create: StalkerRelocatorCreate,
    pub standalone_relocator_destroy: StalkerRelocatorDestroy,
    pub standalone_relocator_invoke: StalkerWriterInvoke,
    pub statistics: fn() -> Result<StalkerStatistics, String>,
}

static STALKER_BACKEND: Mutex<Option<StalkerBackend>> = Mutex::new(None);
static ARM64_WRITER_CLASS_ID: AtomicU32 = AtomicU32::new(0);
static ARM64_RELOCATOR_CLASS_ID: AtomicU32 = AtomicU32::new(0);
const ARM64_WRITER_CLASS_NAME: &[u8] = b"Arm64Writer\0";
const ARM64_RELOCATOR_CLASS_NAME: &[u8] = b"Arm64Relocator\0";
static CALL_PROBE_ARGUMENT_STACK: Mutex<Vec<CallProbeArgumentAccess>> = Mutex::new(Vec::new());
static IN_FLIGHT_CALL_PROBES: Mutex<usize> = Mutex::new(0);
static IN_FLIGHT_CALL_PROBES_CV: Condvar = Condvar::new();
static STALKER_TRANSFORM_STACK: Mutex<Vec<StalkerTransformFrame>> = Mutex::new(Vec::new());
static NEXT_STALKER_TRANSFORM_TOKEN: AtomicU64 = AtomicU64::new(1);
static IN_FLIGHT_STALKER_TRANSFORMS: Mutex<usize> = Mutex::new(0);
static IN_FLIGHT_STALKER_TRANSFORMS_CV: Condvar = Condvar::new();
static STALKER_CALLOUT_STACK: Mutex<Vec<StalkerCalloutFrame>> = Mutex::new(Vec::new());
static IN_FLIGHT_STALKER_CALLOUTS: Mutex<usize> = Mutex::new(0);
static IN_FLIGHT_STALKER_CALLOUTS_CV: Condvar = Condvar::new();
static RETIRED_STALKER_CALLOUTS: Mutex<Vec<(usize, u32)>> = Mutex::new(Vec::new());

struct StalkerTransformFrame {
    owner_thread: u64,
    token: u64,
    access: StalkerTransformAccess,
    has_current_instruction: bool,
    instruction: Option<StalkerInstruction>,
    /// Relocators created during this callback, keyed by the handle handed to
    /// JavaScript. They are destroyed when the callback returns so a script
    /// cannot reach a Gum object whose writer has already been retired.
    relocators: Vec<(u64, usize)>,
    next_relocator_handle: u64,
}

struct StalkerTransformGuard {
    owner_thread: u64,
    token: u64,
}

struct StalkerCalloutFrame {
    owner_thread: u64,
    id: u32,
    access: StalkerCalloutAccess,
}

struct StalkerCalloutGuard {
    owner_thread: u64,
    id: u32,
}

impl StalkerCalloutGuard {
    fn push(id: u32, access: StalkerCalloutAccess) -> Self {
        let owner_thread = crate::current_thread_id_u64();
        STALKER_CALLOUT_STACK
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push(StalkerCalloutFrame {
                owner_thread,
                id,
                access,
            });
        Self { owner_thread, id }
    }
}

impl Drop for StalkerCalloutGuard {
    fn drop(&mut self) {
        let mut stack = STALKER_CALLOUT_STACK.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(index) = stack
            .iter()
            .rposition(|frame| frame.owner_thread == self.owner_thread && frame.id == self.id)
        {
            stack.remove(index);
        }
    }
}

struct InFlightStalkerCalloutGuard;

impl InFlightStalkerCalloutGuard {
    fn enter() -> Self {
        let mut count = IN_FLIGHT_STALKER_CALLOUTS
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        *count += 1;
        Self
    }
}

impl Drop for InFlightStalkerCalloutGuard {
    fn drop(&mut self) {
        let mut count = IN_FLIGHT_STALKER_CALLOUTS
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        *count = count.saturating_sub(1);
        if *count == 0 {
            IN_FLIGHT_STALKER_CALLOUTS_CV.notify_all();
        }
    }
}

impl StalkerTransformGuard {
    fn push(token: u64, access: StalkerTransformAccess) -> Self {
        let owner_thread = crate::current_thread_id_u64();
        STALKER_TRANSFORM_STACK
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push(StalkerTransformFrame {
                owner_thread,
                token,
                access,
                has_current_instruction: false,
                instruction: None,
                relocators: Vec::new(),
                next_relocator_handle: 1,
            });
        Self { owner_thread, token }
    }
}

impl Drop for StalkerTransformGuard {
    fn drop(&mut self) {
        let mut stack = STALKER_TRANSFORM_STACK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let Some(index) = stack
            .iter()
            .rposition(|frame| frame.owner_thread == self.owner_thread && frame.token == self.token)
        else {
            return;
        };
        let frame = stack.remove(index);
        // Release the Gum objects before dropping the lock: the writer they
        // reference stops being valid as soon as the transform callback returns.
        drop(stack);
        for (_, relocator) in frame.relocators {
            unsafe { (frame.access.relocator_destroy)(relocator) };
        }
    }
}

struct InFlightStalkerTransformGuard;

impl InFlightStalkerTransformGuard {
    fn enter() -> Self {
        let mut count = IN_FLIGHT_STALKER_TRANSFORMS
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        *count += 1;
        Self
    }
}

impl Drop for InFlightStalkerTransformGuard {
    fn drop(&mut self) {
        let mut count = IN_FLIGHT_STALKER_TRANSFORMS
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        *count = count.saturating_sub(1);
        if *count == 0 {
            IN_FLIGHT_STALKER_TRANSFORMS_CV.notify_all();
        }
    }
}

#[derive(Clone, Copy)]
struct CallProbeArgumentAccess {
    opaque: usize,
    get_argument: StalkerProbeGetArgument,
    set_argument: StalkerProbeSetArgument,
}

struct CallProbeArgumentGuard;

impl CallProbeArgumentGuard {
    fn push(access: CallProbeArgumentAccess) -> Self {
        CALL_PROBE_ARGUMENT_STACK
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push(access);
        Self
    }
}

impl Drop for CallProbeArgumentGuard {
    fn drop(&mut self) {
        CALL_PROBE_ARGUMENT_STACK
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .pop();
    }
}

struct InFlightCallProbeGuard;

impl InFlightCallProbeGuard {
    fn enter() -> Self {
        let mut count = IN_FLIGHT_CALL_PROBES.lock().unwrap_or_else(|error| error.into_inner());
        *count += 1;
        Self
    }
}

impl Drop for InFlightCallProbeGuard {
    fn drop(&mut self) {
        let mut count = IN_FLIGHT_CALL_PROBES.lock().unwrap_or_else(|error| error.into_inner());
        *count = count.saturating_sub(1);
        if *count == 0 {
            IN_FLIGHT_CALL_PROBES_CV.notify_all();
        }
    }
}

fn current_argument_access() -> Option<CallProbeArgumentAccess> {
    CALL_PROBE_ARGUMENT_STACK
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .last()
        .copied()
}

fn current_callout_access() -> Option<StalkerCalloutAccess> {
    let owner_thread = crate::current_thread_id_u64();
    STALKER_CALLOUT_STACK
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .iter()
        .rev()
        .find(|frame| frame.owner_thread == owner_thread)
        .map(|frame| frame.access)
}

pub fn retire_stalker_callout(context: usize, id: u32) {
    RETIRED_STALKER_CALLOUTS
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .push((context, id));
}

pub fn clear_retired_stalker_callouts() {
    RETIRED_STALKER_CALLOUTS
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clear();
}

fn take_retired_stalker_callouts(context: usize) -> Vec<u32> {
    let mut retired = RETIRED_STALKER_CALLOUTS
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let mut ids = Vec::new();
    retired.retain(|(entry_context, id)| {
        if *entry_context == context {
            ids.push(*id);
            false
        } else {
            true
        }
    });
    ids
}

pub fn wait_for_stalker_call_probe_callbacks(timeout: std::time::Duration) -> bool {
    let started = std::time::Instant::now();
    let mut count = IN_FLIGHT_CALL_PROBES.lock().unwrap_or_else(|error| error.into_inner());
    while *count != 0 {
        let Some(remaining) = timeout.checked_sub(started.elapsed()) else {
            return false;
        };
        let (guard, result) = IN_FLIGHT_CALL_PROBES_CV
            .wait_timeout(count, remaining)
            .unwrap_or_else(|error| error.into_inner());
        count = guard;
        if result.timed_out() && *count != 0 {
            return false;
        }
    }
    true
}

pub fn wait_for_stalker_transform_callbacks(timeout: std::time::Duration) -> bool {
    let started = std::time::Instant::now();
    let mut count = IN_FLIGHT_STALKER_TRANSFORMS
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    while *count != 0 {
        let Some(remaining) = timeout.checked_sub(started.elapsed()) else {
            return false;
        };
        let (guard, result) = IN_FLIGHT_STALKER_TRANSFORMS_CV
            .wait_timeout(count, remaining)
            .unwrap_or_else(|error| error.into_inner());
        count = guard;
        if result.timed_out() && *count != 0 {
            return false;
        }
    }
    true
}

pub fn wait_for_stalker_callout_callbacks(timeout: std::time::Duration) -> bool {
    let started = std::time::Instant::now();
    let mut count = IN_FLIGHT_STALKER_CALLOUTS
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    while *count != 0 {
        let Some(remaining) = timeout.checked_sub(started.elapsed()) else {
            return false;
        };
        let (guard, result) = IN_FLIGHT_STALKER_CALLOUTS_CV
            .wait_timeout(count, remaining)
            .unwrap_or_else(|error| error.into_inner());
        count = guard;
        if result.timed_out() && *count != 0 {
            return false;
        }
    }
    true
}

fn with_stalker_transform_frame_mut<R>(
    token: u64,
    operation: impl FnOnce(&mut StalkerTransformFrame) -> R,
) -> Option<R> {
    let owner_thread = crate::current_thread_id_u64();
    let mut stack = STALKER_TRANSFORM_STACK
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let frame = stack
        .iter_mut()
        .rev()
        .find(|frame| frame.owner_thread == owner_thread && frame.token == token)?;
    Some(operation(frame))
}

unsafe fn keep_all_stalker_instructions(access: StalkerTransformAccess) {
    let mut instruction = StalkerInstruction::default();
    while (access.next)(access.opaque, &mut instruction) != 0 {
        (access.keep)(access.opaque);
    }
}

unsafe fn keep_remaining_stalker_instructions(token: u64) {
    let _ = with_stalker_transform_frame_mut(token, |frame| {
        if frame.has_current_instruction {
            (frame.access.keep)(frame.access.opaque);
            frame.has_current_instruction = false;
        }

        let mut instruction = StalkerInstruction::default();
        while (frame.access.next)(frame.access.opaque, &mut instruction) != 0 {
            (frame.access.keep)(frame.access.opaque);
        }
    });
}

pub fn dispatch_stalker_transform(context: usize, thread_id: u64, access: StalkerTransformAccess) -> bool {
    let _in_flight = InFlightStalkerTransformGuard::enter();
    let ctx = context as *mut ffi::JSContext;
    if ctx.is_null() {
        unsafe { keep_all_stalker_instructions(access) };
        return false;
    }

    unsafe {
        let Some(_js_guard) = acquire_js_engine_for_callback(ctx, "stalker transform", thread_id) else {
            keep_all_stalker_instructions(access);
            return false;
        };

        let mut token = NEXT_STALKER_TRANSFORM_TOKEN.fetch_add(1, Ordering::Relaxed);
        if token == 0 || token > i64::MAX as u64 {
            NEXT_STALKER_TRANSFORM_TOKEN.store(2, Ordering::Relaxed);
            token = 1;
        }
        let _transform_guard = StalkerTransformGuard::push(token, access);

        let global = ffi::JS_GetGlobalObject(ctx);
        let dispatch = JSValue(ffi::qjs_get_property(
            ctx,
            global,
            hot_atoms().stalker_dispatch_transform,
        ));
        if !dispatch.is_function(ctx) {
            keep_remaining_stalker_instructions(token);
            dispatch.free(ctx);
            ffi::qjs_free_value(ctx, global);
            return false;
        }

        let arguments = [
            ffi::qjs_new_int64(ctx, thread_id as i64),
            ffi::qjs_new_int64(ctx, token as i64),
        ];
        let result = ffi::JS_Call(
            ctx,
            dispatch.raw(),
            global,
            arguments.len() as i32,
            arguments.as_ptr() as *mut _,
        );
        let had_exception = handle_js_exception(ctx, result, "stalker transform");
        if had_exception {
            keep_remaining_stalker_instructions(token);
        }

        ffi::qjs_free_value(ctx, result);
        for argument in arguments {
            ffi::qjs_free_value(ctx, argument);
        }
        dispatch.free(ctx);
        ffi::qjs_free_value(ctx, global);
        !had_exception
    }
}

pub fn dispatch_stalker_callout(context: usize, id: u32, access: StalkerCalloutAccess) {
    let _in_flight = InFlightStalkerCalloutGuard::enter();
    let ctx = context as *mut ffi::JSContext;
    if ctx.is_null() {
        return;
    }

    unsafe {
        let Some(_js_guard) = acquire_js_engine_for_callback(ctx, "stalker callout", id as u64) else {
            return;
        };
        let _callout_guard = StalkerCalloutGuard::push(id, access);

        let global = ffi::JS_GetGlobalObject(ctx);
        let dispatch = JSValue(ffi::qjs_get_property(ctx, global, hot_atoms().stalker_dispatch_callout));
        if !dispatch.is_function(ctx) {
            dispatch.free(ctx);
            ffi::qjs_free_value(ctx, global);
            return;
        }

        let argument = ffi::qjs_new_int64(ctx, id as i64);
        let result = ffi::JS_Call(ctx, dispatch.raw(), global, 1, &argument as *const _ as *mut _);
        handle_js_exception(ctx, result, "stalker callout");
        ffi::qjs_free_value(ctx, result);
        ffi::qjs_free_value(ctx, argument);
        dispatch.free(ctx);
        ffi::qjs_free_value(ctx, global);
    }
}

pub fn dispatch_stalker_call_probe(
    context: usize,
    id: u32,
    opaque: usize,
    get_argument: StalkerProbeGetArgument,
    set_argument: StalkerProbeSetArgument,
) {
    let _in_flight = InFlightCallProbeGuard::enter();
    let ctx = context as *mut ffi::JSContext;
    if ctx.is_null() {
        return;
    }

    unsafe {
        let Some(_js_guard) = acquire_js_engine_for_callback(ctx, "stalker call probe", id as u64) else {
            return;
        };
        let _argument_guard = CallProbeArgumentGuard::push(CallProbeArgumentAccess {
            opaque,
            get_argument,
            set_argument,
        });

        let global = ffi::JS_GetGlobalObject(ctx);
        let dispatch = JSValue(global).get_property(ctx, "__rf_stalker_dispatch_call_probe");
        if !dispatch.is_function(ctx) {
            dispatch.free(ctx);
            ffi::qjs_free_value(ctx, global);
            return;
        }

        let argument = ffi::qjs_new_int64(ctx, id as i64);
        let result = ffi::JS_Call(ctx, dispatch.raw(), global, 1, &argument as *const _ as *mut _);
        handle_js_exception(ctx, result, "stalker call probe");
        ffi::qjs_free_value(ctx, result);
        ffi::qjs_free_value(ctx, argument);
        dispatch.free(ctx);
        ffi::qjs_free_value(ctx, global);
    }
}

pub fn install_stalker_backend(backend: StalkerBackend) -> Result<(), String> {
    let mut guard = STALKER_BACKEND
        .lock()
        .map_err(|_| "Stalker backend lock poisoned".to_string())?;
    if guard.is_none() {
        *guard = Some(backend);
    }
    Ok(())
}

pub fn shutdown_stalker_backend() -> bool {
    let backend = STALKER_BACKEND.lock().ok().and_then(|guard| *guard);
    match backend {
        Some(backend) => (backend.shutdown)().unwrap_or(false),
        None => true,
    }
}

fn backend() -> Option<StalkerBackend> {
    STALKER_BACKEND.lock().ok().and_then(|guard| *guard)
}

pub(crate) fn process_pending_stalker() -> Result<(), String> {
    match backend() {
        Some(backend) => (backend.process_pending)(),
        None => Ok(()),
    }
}

struct NativeCallStalkerScope {
    runtime: Option<SuspendedRuntime>,
    activated: bool,
}

impl NativeCallStalkerScope {
    unsafe fn enter(ctx: *mut ffi::JSContext, target: u64, cooperative: bool) -> Result<Self, String> {
        let runtime = if cooperative {
            Some(SuspendedRuntime::suspend_cooperatively(ctx))
        } else {
            None
        };
        process_pending_stalker()?;
        let activated = match backend() {
            Some(backend) => (backend.activate_current)(target)?,
            None => false,
        };
        Ok(Self { runtime, activated })
    }

    unsafe fn finish(mut self) -> Result<(), String> {
        let result = if self.activated {
            match backend() {
                Some(backend) => (backend.deactivate_current)(),
                None => Ok(()),
            }
        } else {
            Ok(())
        };
        self.activated = false;
        if let Some(runtime) = self.runtime.as_mut() {
            runtime.resume();
        }
        result
    }
}

impl Drop for NativeCallStalkerScope {
    fn drop(&mut self) {
        if self.activated {
            if let Some(backend) = backend() {
                let _ = (backend.deactivate_current)();
            }
            self.activated = false;
        }
    }
}

pub(crate) unsafe fn with_stalker_native_call<R>(
    ctx: *mut ffi::JSContext,
    target: u64,
    operation: impl FnOnce() -> R,
) -> Result<R, String> {
    let scope = NativeCallStalkerScope::enter(ctx, target, true)?;
    let result = operation();
    scope.finish()?;
    Ok(result)
}

pub(crate) unsafe fn with_native_call_context<R>(
    ctx: *mut ffi::JSContext,
    target: u64,
    cooperative: bool,
    activate_stalker: bool,
    operation: impl FnOnce() -> R,
) -> Result<R, String> {
    if activate_stalker {
        let scope = NativeCallStalkerScope::enter(ctx, target, cooperative)?;
        let result = operation();
        scope.finish()?;
        return Ok(result);
    }
    if cooperative {
        let mut runtime = SuspendedRuntime::suspend_cooperatively(ctx);
        let result = operation();
        runtime.resume();
        Ok(result)
    } else {
        Ok(operation())
    }
}

unsafe fn backend_or_throw(ctx: *mut ffi::JSContext) -> Result<StalkerBackend, ffi::JSValue> {
    let Some(backend) = backend() else {
        return Err(throw_internal_error(ctx, "Stalker backend is not available"));
    };
    if !(backend.is_supported)() {
        return Err(throw_internal_error(ctx, "Stalker is not supported on this platform"));
    }
    Ok(backend)
}

unsafe fn required_u64(
    ctx: *mut ffi::JSContext,
    argc: i32,
    argv: *mut ffi::JSValue,
    index: usize,
    name: &str,
) -> Result<u64, ffi::JSValue> {
    if argc <= index as i32 {
        return Err(throw_internal_error(ctx, &format!("{name} is required")));
    }
    JSValue(*argv.add(index))
        .to_u64(ctx)
        .ok_or_else(|| throw_internal_error(ctx, &format!("{name} must be an integer")))
}

unsafe fn batches_to_js(ctx: *mut ffi::JSContext, batches: Vec<StalkerEventBatch>) -> ffi::JSValue {
    let result = ffi::JS_NewArray(ctx);
    let mut index = 0u32;

    for batch in batches.into_iter().filter(|batch| !batch.data.is_empty()) {
        let item = ffi::JS_NewObject(ctx);
        let item_value = JSValue(item);
        item_value.set_property(
            ctx,
            "threadId",
            JSValue(ffi::qjs_new_int64(ctx, batch.thread_id as i64)),
        );
        let data = ffi::JS_NewArrayBufferCopy(ctx, batch.data.as_ptr(), batch.data.len());
        item_value.set_property(ctx, "data", JSValue(data));
        if ffi::JS_SetPropertyUint32(ctx, result, index, item) < 0 {
            ffi::qjs_free_value(ctx, result);
            return ffi::qjs_exception();
        }
        index += 1;
    }

    result
}

unsafe extern "C" fn js_stalker_is_supported(
    _ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    JSValue::bool(backend().is_some_and(|value| (value.is_supported)())).raw()
}

unsafe extern "C" fn js_stalker_follow(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let backend = match backend_or_throw(ctx) {
        Ok(value) => value,
        Err(error) => return error,
    };
    let thread_id = match required_u64(ctx, argc, argv, 0, "threadId") {
        Ok(value) => value,
        Err(error) => return error,
    };
    let event_mask = match required_u64(ctx, argc, argv, 1, "eventMask") {
        Ok(value) if value <= 0x1f => value as u32,
        Ok(_) => return throw_internal_error(ctx, "eventMask is out of range"),
        Err(error) => return error,
    };
    let queue_capacity = match required_u64(ctx, argc, argv, 2, "queueCapacity") {
        Ok(value) if value <= u32::MAX as u64 => value as u32,
        Ok(_) => return throw_internal_error(ctx, "queueCapacity is out of range"),
        Err(error) => return error,
    };
    let queue_drain_interval = match required_u64(ctx, argc, argv, 3, "queueDrainInterval") {
        Ok(value) if value <= u32::MAX as u64 => value as u32,
        Ok(_) => return throw_internal_error(ctx, "queueDrainInterval is out of range"),
        Err(error) => return error,
    };
    let transform = match required_u64(ctx, argc, argv, 4, "transform") {
        Ok(0) => false,
        Ok(1) => true,
        Ok(_) => return throw_internal_error(ctx, "transform must be 0 or 1"),
        Err(error) => return error,
    };
    let native_event_callback = if argc >= 6 {
        match extract_pointer_address(ctx, JSValue(*argv.add(5)), "Stalker.follow onEvent") {
            Ok(value) => value,
            Err(error) => return error,
        }
    } else {
        0
    };
    let native_event_data = if argc >= 7 {
        match extract_pointer_address(ctx, JSValue(*argv.add(6)), "Stalker.follow data") {
            Ok(value) => value,
            Err(error) => return error,
        }
    } else {
        0
    };

    let config = StalkerFollowConfig {
        thread_id,
        event_mask,
        queue_capacity,
        queue_drain_interval,
        transform,
        context: transform.then_some(ctx as usize).unwrap_or(0),
        native_event_callback,
        native_event_data,
        defer_current_thread: true,
    };
    match (backend.follow)(config) {
        Ok(()) => JSValue::undefined().raw(),
        Err(error) => throw_internal_error(ctx, &error),
    }
}

unsafe extern "C" fn js_stalker_unfollow(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let backend = match backend_or_throw(ctx) {
        Ok(value) => value,
        Err(error) => return error,
    };
    let thread_id = match required_u64(ctx, argc, argv, 0, "threadId") {
        Ok(value) => value,
        Err(error) => return error,
    };
    let mut suspended = SuspendedRuntime::suspend(ctx);
    let result = (backend.unfollow)(thread_id);
    suspended.resume();
    match result {
        Ok(batches) => batches_to_js(ctx, batches),
        Err(error) => throw_internal_error(ctx, &error),
    }
}

unsafe extern "C" fn js_stalker_drain_due(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let backend = match backend_or_throw(ctx) {
        Ok(value) => value,
        Err(error) => return error,
    };
    match (backend.drain_due)() {
        Ok(batches) => batches_to_js(ctx, batches),
        Err(error) => throw_internal_error(ctx, &error),
    }
}

unsafe extern "C" fn js_stalker_flush(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let backend = match backend_or_throw(ctx) {
        Ok(value) => value,
        Err(error) => return error,
    };
    match (backend.flush)() {
        Ok(batches) => batches_to_js(ctx, batches),
        Err(error) => throw_internal_error(ctx, &error),
    }
}

unsafe extern "C" fn js_stalker_garbage_collect(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let backend = match backend_or_throw(ctx) {
        Ok(value) => value,
        Err(error) => return error,
    };
    match (backend.garbage_collect)() {
        Ok(result) => {
            let value = ffi::JS_NewObject(ctx);
            let object = JSValue(value);
            object.set_property(ctx, "pending", JSValue::bool(result.pending));
            object.set_property(ctx, "batches", JSValue(batches_to_js(ctx, result.batches)));
            value
        }
        Err(error) => throw_internal_error(ctx, &error),
    }
}

unsafe extern "C" fn js_stalker_exclude(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let backend = match backend_or_throw(ctx) {
        Ok(value) => value,
        Err(error) => return error,
    };
    if argc < 2 {
        return throw_internal_error(ctx, "Stalker.exclude requires base and size");
    }
    let base = match extract_pointer_address(ctx, JSValue(*argv), "Stalker.exclude base") {
        Ok(value) => value,
        Err(error) => return error,
    };
    let size = match required_u64(ctx, argc, argv, 1, "size") {
        Ok(value) => value,
        Err(error) => return error,
    };
    match (backend.exclude)(base, size) {
        Ok(()) => JSValue::undefined().raw(),
        Err(error) => throw_internal_error(ctx, &error),
    }
}

unsafe extern "C" fn js_stalker_invalidate(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let backend = match backend_or_throw(ctx) {
        Ok(value) => value,
        Err(error) => return error,
    };
    if argc < 1 {
        return throw_internal_error(ctx, "Stalker.invalidate requires an address");
    }

    let (thread_id, address_index) = if argc >= 2 {
        let thread_id = match required_u64(ctx, argc, argv, 0, "threadId") {
            Ok(value) => value,
            Err(error) => return error,
        };
        (Some(thread_id), 1usize)
    } else {
        (None, 0usize)
    };
    let address = match extract_pointer_address(ctx, JSValue(*argv.add(address_index)), "Stalker.invalidate address") {
        Ok(value) => value,
        Err(error) => return error,
    };
    match (backend.invalidate)(thread_id, address) {
        Ok(()) => JSValue::undefined().raw(),
        Err(error) => throw_internal_error(ctx, &error),
    }
}

unsafe extern "C" fn js_stalker_add_call_probe(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let backend = match backend_or_throw(ctx) {
        Ok(value) => value,
        Err(error) => return error,
    };
    let id = match required_u64(ctx, argc, argv, 0, "probeId") {
        Ok(value) if value != 0 && value <= u32::MAX as u64 => value as u32,
        Ok(_) => return throw_internal_error(ctx, "probeId is out of range"),
        Err(error) => return error,
    };
    if argc < 2 {
        return throw_internal_error(ctx, "Stalker.addCallProbe requires a target address");
    }
    let target_address = match extract_pointer_address(ctx, JSValue(*argv.add(1)), "Stalker.addCallProbe target") {
        Ok(value) => value,
        Err(error) => return error,
    };
    let native_callback = if argc >= 3 {
        match extract_pointer_address(ctx, JSValue(*argv.add(2)), "Stalker.addCallProbe callback") {
            Ok(value) => value,
            Err(error) => return error,
        }
    } else {
        0
    };
    let native_data = if argc >= 4 {
        match extract_pointer_address(ctx, JSValue(*argv.add(3)), "Stalker.addCallProbe data") {
            Ok(value) => value,
            Err(error) => return error,
        }
    } else {
        0
    };
    let config = StalkerCallProbeConfig {
        id,
        target_address,
        context: (native_callback == 0).then_some(ctx as usize).unwrap_or(0),
        native_callback,
        native_data,
    };
    match (backend.add_call_probe)(config) {
        Ok(()) => ffi::qjs_new_int64(ctx, id as i64),
        Err(error) => throw_internal_error(ctx, &error),
    }
}

unsafe extern "C" fn js_stalker_remove_call_probe(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let backend = match backend_or_throw(ctx) {
        Ok(value) => value,
        Err(error) => return error,
    };
    let id = match required_u64(ctx, argc, argv, 0, "probeId") {
        Ok(value) if value <= u32::MAX as u64 => value as u32,
        Ok(_) => return throw_internal_error(ctx, "probeId is out of range"),
        Err(error) => return error,
    };
    match (backend.remove_call_probe)(id) {
        Ok(()) => JSValue::undefined().raw(),
        Err(error) => throw_internal_error(ctx, &error),
    }
}

unsafe extern "C" fn js_stalker_get_probe_argument(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let index = match required_u64(ctx, argc, argv, 0, "argument index") {
        Ok(value) if value <= u32::MAX as u64 => value as u32,
        Ok(_) => return throw_internal_error(ctx, "argument index is out of range"),
        Err(error) => return error,
    };
    let Some(access) = current_argument_access() else {
        return throw_internal_error(ctx, "invalid operation outside a Stalker call probe");
    };
    create_native_pointer(ctx, (access.get_argument)(access.opaque, index)).raw()
}

unsafe extern "C" fn js_stalker_set_probe_argument(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let index = match required_u64(ctx, argc, argv, 0, "argument index") {
        Ok(value) if value <= u32::MAX as u64 => value as u32,
        Ok(_) => return throw_internal_error(ctx, "argument index is out of range"),
        Err(error) => return error,
    };
    if argc < 2 {
        return throw_internal_error(ctx, "argument value is required");
    }
    let value = match extract_pointer_address(ctx, JSValue(*argv.add(1)), "Stalker call probe argument") {
        Ok(value) => value,
        Err(error) => return error,
    };
    let Some(access) = current_argument_access() else {
        return throw_internal_error(ctx, "invalid operation outside a Stalker call probe");
    };
    (access.set_argument)(access.opaque, index, value);
    JSValue::undefined().raw()
}

fn stalker_instruction_text_len(bytes: &[u8]) -> usize {
    bytes.iter().position(|byte| *byte == 0).unwrap_or(bytes.len())
}

unsafe fn js_array_length(ctx: *mut ffi::JSContext, value: JSValue) -> Option<u64> {
    let length = JSValue(ffi::JS_GetPropertyStr(ctx, value.raw(), c"length".as_ptr()));
    let count = length.to_u64(ctx);
    length.free(ctx);
    count
}

/// Flatten the JavaScript arguments of a writer/relocator call into the `u64`
/// encoding the backend expects. `byte_storage` keeps buffers alive for the
/// duration of the dispatch.
unsafe fn encode_writer_arguments(
    ctx: *mut ffi::JSContext,
    method: &stalker_writer::StalkerWriterMethod,
    argc: i32,
    argv: *mut ffi::JSValue,
    first_argument: usize,
    byte_storage: &mut Vec<Vec<u8>>,
) -> Result<Vec<u64>, ffi::JSValue> {
    let expected = method.arg_spec.chars().count();
    let available = (argc as usize).saturating_sub(first_argument);
    if available < expected {
        return Err(throw_internal_error(
            ctx,
            format!("{}() expects {expected} argument(s)", method.name),
        ));
    }

    let mut encoded = Vec::with_capacity(expected);
    for (offset, spec) in method.arg_spec.chars().enumerate() {
        let value = JSValue(*argv.add(first_argument + offset));
        match spec {
            'a' => encoded.push(extract_pointer_address(ctx, value, method.name)?),
            'r' | 'c' | 'm' | 'u' | 'l' => {
                let Some(raw) = value.to_u64(ctx) else {
                    return Err(throw_internal_error(
                        ctx,
                        format!("{}() argument {offset} must be an integer", method.name),
                    ));
                };
                encoded.push(raw);
            }
            's' => {
                let Some(raw) = value.to_i64(ctx) else {
                    return Err(throw_internal_error(
                        ctx,
                        format!("{}() argument {offset} must be an integer", method.name),
                    ));
                };
                encoded.push(raw as u64);
            }
            'b' => {
                let bytes = crate::jsapi::memory::writest::extract_bytes(ctx, value)?;
                byte_storage.push(bytes);
                let bytes = byte_storage.last().expect("just pushed");
                encoded.push(bytes.as_ptr() as u64);
                encoded.push(bytes.len() as u64);
            }
            'A' => {
                // Pre-flattened by the facade as [count, kind0, value0, ...].
                let Some(count) = js_array_length(ctx, value) else {
                    return Err(throw_internal_error(
                        ctx,
                        format!("{}() argument {offset} must be an array", method.name),
                    ));
                };
                for index in 0..count {
                    let element = JSValue(ffi::JS_GetPropertyUint32(ctx, value.raw(), index as u32));
                    let raw = element.to_u64(ctx);
                    element.free(ctx);
                    let Some(raw) = raw else {
                        return Err(throw_internal_error(
                            ctx,
                            format!("{}() received a malformed argument list", method.name),
                        ));
                    };
                    encoded.push(raw);
                }
            }
            other => {
                return Err(throw_internal_error(
                    ctx,
                    format!("{}() uses unsupported argument spec '{other}'", method.name),
                ));
            }
        }
    }

    if stalker_writer::validate_arg_encoding(method.arg_spec, &encoded).is_none() {
        return Err(throw_internal_error(
            ctx,
            format!("{}() received a malformed argument list", method.name),
        ));
    }
    Ok(encoded)
}

unsafe fn writer_result_to_js(
    ctx: *mut ffi::JSContext,
    method: &stalker_writer::StalkerWriterMethod,
    status: i32,
    out: u64,
) -> ffi::JSValue {
    if status < 0 {
        return throw_internal_error(ctx, format!("{}() was rejected by the ARM64 writer", method.name));
    }
    match method.result {
        stalker_writer::StalkerWriterResult::Void => JSValue::undefined().raw(),
        stalker_writer::StalkerWriterResult::Bool => JSValue::bool(status != 0).raw(),
        stalker_writer::StalkerWriterResult::Unsigned => ffi::qjs_new_int64(ctx, out as i64),
        stalker_writer::StalkerWriterResult::Pointer => create_native_pointer(ctx, out).raw(),
    }
}

/// Native state of an independently owned `Arm64Writer` object. The function
/// pointers are copied from the backend at construction time so QuickJS
/// finalizers can release the Gum object without depending on JavaScript state.
struct StandaloneArm64Writer {
    handle: usize,
    destroy: StalkerStandaloneWriterDestroy,
    reset: StalkerStandaloneWriterReset,
    invoke: StalkerWriterInvoke,
}

/// Native state of an independently owned `Arm64Relocator` object. Gum's
/// relocator takes its own reference to the output writer, so this does not
/// need to keep a QuickJS reference to the writer object alive.
struct StandaloneArm64Relocator {
    handle: usize,
    destroy: StalkerRelocatorDestroy,
    invoke: StalkerWriterInvoke,
}

unsafe fn dispose_standalone_writer(data: &mut StandaloneArm64Writer) {
    if data.handle != 0 {
        (data.destroy)(data.handle);
        data.handle = 0;
    }
}

unsafe fn dispose_standalone_relocator(data: &mut StandaloneArm64Relocator) {
    if data.handle != 0 {
        (data.destroy)(data.handle);
        data.handle = 0;
    }
}

unsafe extern "C" fn standalone_writer_finalizer(_runtime: *mut ffi::JSRuntime, value: ffi::JSValue) {
    let class_id = ARM64_WRITER_CLASS_ID.load(Ordering::Relaxed);
    if class_id == 0 {
        return;
    }
    let opaque = ffi::JS_GetOpaque(value, class_id);
    if !opaque.is_null() {
        let mut data = Box::from_raw(opaque as *mut StandaloneArm64Writer);
        dispose_standalone_writer(&mut data);
    }
}

unsafe extern "C" fn standalone_relocator_finalizer(_runtime: *mut ffi::JSRuntime, value: ffi::JSValue) {
    let class_id = ARM64_RELOCATOR_CLASS_ID.load(Ordering::Relaxed);
    if class_id == 0 {
        return;
    }
    let opaque = ffi::JS_GetOpaque(value, class_id);
    if !opaque.is_null() {
        let mut data = Box::from_raw(opaque as *mut StandaloneArm64Relocator);
        dispose_standalone_relocator(&mut data);
    }
}

fn get_or_init_standalone_writer_class_id(ctx: *mut ffi::JSContext) -> u32 {
    let mut class_id = ARM64_WRITER_CLASS_ID.load(Ordering::Relaxed);
    if class_id == 0 {
        let mut allocated = 0u32;
        allocated = unsafe { ffi::JS_NewClassID(&mut allocated) };
        match ARM64_WRITER_CLASS_ID.compare_exchange(0, allocated, Ordering::SeqCst, Ordering::Relaxed) {
            Ok(_) => class_id = allocated,
            Err(existing) => class_id = existing,
        }
    }
    unsafe {
        let definition = ffi::JSClassDef {
            class_name: ARM64_WRITER_CLASS_NAME.as_ptr() as *const _,
            finalizer: Some(standalone_writer_finalizer),
            gc_mark: None,
            call: None,
            exotic: std::ptr::null_mut(),
        };
        let _ = ffi::JS_NewClass(ffi::JS_GetRuntime(ctx), class_id, &definition);
    }
    class_id
}

fn get_or_init_standalone_relocator_class_id(ctx: *mut ffi::JSContext) -> u32 {
    let mut class_id = ARM64_RELOCATOR_CLASS_ID.load(Ordering::Relaxed);
    if class_id == 0 {
        let mut allocated = 0u32;
        allocated = unsafe { ffi::JS_NewClassID(&mut allocated) };
        match ARM64_RELOCATOR_CLASS_ID.compare_exchange(0, allocated, Ordering::SeqCst, Ordering::Relaxed) {
            Ok(_) => class_id = allocated,
            Err(existing) => class_id = existing,
        }
    }
    unsafe {
        let definition = ffi::JSClassDef {
            class_name: ARM64_RELOCATOR_CLASS_NAME.as_ptr() as *const _,
            finalizer: Some(standalone_relocator_finalizer),
            gc_mark: None,
            call: None,
            exotic: std::ptr::null_mut(),
        };
        let _ = ffi::JS_NewClass(ffi::JS_GetRuntime(ctx), class_id, &definition);
    }
    class_id
}

unsafe fn unwrap_standalone_writer(
    ctx: *mut ffi::JSContext,
    value: ffi::JSValue,
) -> Result<&'static mut StandaloneArm64Writer, ffi::JSValue> {
    let class_id = get_or_init_standalone_writer_class_id(ctx);
    let opaque = ffi::JS_GetOpaque(value, class_id);
    if opaque.is_null() {
        return Err(ffi::JS_ThrowTypeError(
            ctx,
            b"expected an Arm64Writer\0".as_ptr() as *const _,
        ));
    }
    Ok(&mut *(opaque as *mut StandaloneArm64Writer))
}

unsafe fn unwrap_standalone_relocator(
    ctx: *mut ffi::JSContext,
    value: ffi::JSValue,
) -> Result<&'static mut StandaloneArm64Relocator, ffi::JSValue> {
    let class_id = get_or_init_standalone_relocator_class_id(ctx);
    let opaque = ffi::JS_GetOpaque(value, class_id);
    if opaque.is_null() {
        return Err(ffi::JS_ThrowTypeError(
            ctx,
            b"expected an Arm64Relocator\0".as_ptr() as *const _,
        ));
    }
    Ok(&mut *(opaque as *mut StandaloneArm64Relocator))
}

unsafe fn require_live_standalone_writer(
    ctx: *mut ffi::JSContext,
    value: ffi::JSValue,
) -> Result<&'static mut StandaloneArm64Writer, ffi::JSValue> {
    let data = unwrap_standalone_writer(ctx, value)?;
    if data.handle == 0 {
        return Err(throw_internal_error(ctx, "Arm64Writer has already been disposed"));
    }
    Ok(data)
}

unsafe fn require_live_standalone_relocator(
    ctx: *mut ffi::JSContext,
    value: ffi::JSValue,
) -> Result<&'static mut StandaloneArm64Relocator, ffi::JSValue> {
    let data = unwrap_standalone_relocator(ctx, value)?;
    if data.handle == 0 {
        return Err(throw_internal_error(ctx, "Arm64Relocator has already been disposed"));
    }
    Ok(data)
}

unsafe fn optional_writer_pc(
    ctx: *mut ffi::JSContext,
    argc: i32,
    argv: *mut ffi::JSValue,
    index: usize,
) -> Result<(u64, u32), ffi::JSValue> {
    if argc <= index as i32 {
        return Ok((0, 0));
    }
    let pc = extract_pointer_address(ctx, JSValue(*argv.add(index)), "Arm64Writer pc")?;
    Ok((pc, 1))
}

unsafe extern "C" fn js_standalone_writer_create(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let backend = match backend_or_throw(ctx) {
        Ok(value) => value,
        Err(error) => return error,
    };
    if argc < 1 {
        return throw_internal_error(ctx, "Arm64Writer code address is required");
    }
    let address = match extract_pointer_address(ctx, JSValue(*argv), "Arm64Writer code address") {
        Ok(value) if value != 0 => value,
        Ok(_) => return throw_internal_error(ctx, "Arm64Writer code address must not be NULL"),
        Err(error) => return error,
    };
    let (pc, pc_specified) = match optional_writer_pc(ctx, argc, argv, 1) {
        Ok(value) => value,
        Err(error) => return error,
    };
    let handle = (backend.standalone_writer_create)(address, pc, pc_specified);
    if handle == 0 {
        return throw_internal_error(ctx, "failed to create Arm64Writer");
    }

    let object = ffi::JS_NewObjectClass(ctx, get_or_init_standalone_writer_class_id(ctx) as i32);
    if ffi::qjs_is_exception(object) != 0 {
        (backend.standalone_writer_destroy)(handle);
        return object;
    }
    let data = Box::new(StandaloneArm64Writer {
        handle,
        destroy: backend.standalone_writer_destroy,
        reset: backend.standalone_writer_reset,
        invoke: backend.standalone_writer_invoke,
    });
    ffi::JS_SetOpaque(object, Box::into_raw(data) as *mut c_void);
    object
}

unsafe extern "C" fn js_standalone_writer_destroy(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(ctx, b"Arm64Writer.dispose requires a receiver\0".as_ptr() as *const _);
    }
    let data = match unwrap_standalone_writer(ctx, *argv) {
        Ok(value) => value,
        Err(error) => return error,
    };
    dispose_standalone_writer(data);
    JSValue::undefined().raw()
}

unsafe extern "C" fn js_standalone_writer_reset(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return throw_internal_error(ctx, "Arm64Writer.reset requires a code address");
    }
    let data = match require_live_standalone_writer(ctx, *argv) {
        Ok(value) => value,
        Err(error) => return error,
    };
    let address = match extract_pointer_address(ctx, JSValue(*argv.add(1)), "Arm64Writer.reset code address") {
        Ok(value) if value != 0 => value,
        Ok(_) => return throw_internal_error(ctx, "Arm64Writer.reset code address must not be NULL"),
        Err(error) => return error,
    };
    let (pc, pc_specified) = match optional_writer_pc(ctx, argc, argv, 2) {
        Ok(value) => value,
        Err(error) => return error,
    };
    if (data.reset)(data.handle, address, pc, pc_specified) < 0 {
        return throw_internal_error(ctx, "Arm64Writer.reset() was rejected by the ARM64 writer");
    }
    JSValue::undefined().raw()
}

unsafe extern "C" fn js_standalone_writer_invoke(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return throw_internal_error(ctx, "Arm64Writer opcode is required");
    }
    let data = match require_live_standalone_writer(ctx, *argv) {
        Ok(value) => value,
        Err(error) => return error,
    };
    let opcode = match required_u64(ctx, argc, argv, 1, "ARM64 writer opcode") {
        Ok(value) if value <= u32::MAX as u64 => value as u32,
        Ok(_) => return throw_internal_error(ctx, "ARM64 writer opcode is out of range"),
        Err(error) => return error,
    };
    let Some(method) = stalker_writer::lookup_writer_method(opcode) else {
        return throw_internal_error(ctx, "unknown ARM64 writer opcode");
    };
    if opcode == stalker_writer::OP_RESET {
        return throw_internal_error(ctx, "Arm64Writer.reset must be called through its public method");
    }

    let mut byte_storage = Vec::new();
    let encoded = match encode_writer_arguments(ctx, method, argc, argv, 2, &mut byte_storage) {
        Ok(value) => value,
        Err(error) => return error,
    };
    let mut out = 0u64;
    let status = (data.invoke)(data.handle, opcode, encoded.as_ptr(), encoded.len() as u32, &mut out);
    writer_result_to_js(ctx, method, status, out)
}

unsafe extern "C" fn js_standalone_relocator_create(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let backend = match backend_or_throw(ctx) {
        Ok(value) => value,
        Err(error) => return error,
    };
    if argc < 2 {
        return throw_internal_error(ctx, "Arm64Relocator requires an input code address and output writer");
    }
    let input = match extract_pointer_address(ctx, JSValue(*argv), "Arm64Relocator input code") {
        Ok(value) if value != 0 => value,
        Ok(_) => return throw_internal_error(ctx, "Arm64Relocator input code must not be NULL"),
        Err(error) => return error,
    };
    let writer = match require_live_standalone_writer(ctx, *argv.add(1)) {
        Ok(value) => value,
        Err(error) => return error,
    };
    let handle = (backend.standalone_relocator_create)(writer.handle, input);
    if handle == 0 {
        return throw_internal_error(ctx, "failed to create Arm64Relocator");
    }
    let object = ffi::JS_NewObjectClass(ctx, get_or_init_standalone_relocator_class_id(ctx) as i32);
    if ffi::qjs_is_exception(object) != 0 {
        (backend.standalone_relocator_destroy)(handle);
        return object;
    }
    let data = Box::new(StandaloneArm64Relocator {
        handle,
        destroy: backend.standalone_relocator_destroy,
        invoke: backend.standalone_relocator_invoke,
    });
    ffi::JS_SetOpaque(object, Box::into_raw(data) as *mut c_void);
    object
}

unsafe extern "C" fn js_standalone_relocator_destroy(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Arm64Relocator.dispose requires a receiver\0".as_ptr() as *const _,
        );
    }
    let data = match unwrap_standalone_relocator(ctx, *argv) {
        Ok(value) => value,
        Err(error) => return error,
    };
    dispose_standalone_relocator(data);
    JSValue::undefined().raw()
}

unsafe extern "C" fn js_standalone_relocator_reset(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 3 {
        return throw_internal_error(ctx, "Arm64Relocator.reset requires input code and output writer");
    }
    let relocator = match require_live_standalone_relocator(ctx, *argv) {
        Ok(value) => value,
        Err(error) => return error,
    };
    let input = match extract_pointer_address(ctx, JSValue(*argv.add(1)), "Arm64Relocator.reset input code") {
        Ok(value) if value != 0 => value,
        Ok(_) => return throw_internal_error(ctx, "Arm64Relocator.reset input code must not be NULL"),
        Err(error) => return error,
    };
    let writer = match require_live_standalone_writer(ctx, *argv.add(2)) {
        Ok(value) => value,
        Err(error) => return error,
    };
    let args = [input, writer.handle as u64];
    let mut out = 0u64;
    let status = (relocator.invoke)(
        relocator.handle,
        stalker_writer::RELOC_OP_RESET,
        args.as_ptr(),
        args.len() as u32,
        &mut out,
    );
    if status < 0 {
        return throw_internal_error(ctx, "Arm64Relocator.reset() was rejected by the ARM64 relocator");
    }
    JSValue::undefined().raw()
}

unsafe extern "C" fn js_standalone_relocator_invoke(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return throw_internal_error(ctx, "Arm64Relocator opcode is required");
    }
    let data = match require_live_standalone_relocator(ctx, *argv) {
        Ok(value) => value,
        Err(error) => return error,
    };
    let opcode = match required_u64(ctx, argc, argv, 1, "Arm64Relocator opcode") {
        Ok(value) if value <= u32::MAX as u64 => value as u32,
        Ok(_) => return throw_internal_error(ctx, "Arm64Relocator opcode is out of range"),
        Err(error) => return error,
    };
    let Some(method) = stalker_writer::lookup_relocator_method(opcode) else {
        return throw_internal_error(ctx, "unknown Arm64Relocator opcode");
    };
    if opcode == stalker_writer::RELOC_OP_RESET {
        return throw_internal_error(ctx, "Arm64Relocator.reset must be called through its public method");
    }
    let mut byte_storage = Vec::new();
    let encoded = match encode_writer_arguments(ctx, method, argc, argv, 2, &mut byte_storage) {
        Ok(value) => value,
        Err(error) => return error,
    };
    let mut out = 0u64;
    let status = (data.invoke)(data.handle, opcode, encoded.as_ptr(), encoded.len() as u32, &mut out);
    writer_result_to_js(ctx, method, status, out)
}

unsafe extern "C" fn js_stalker_writer_invoke(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let token = match required_stalker_transform_token(ctx, argc, argv) {
        Ok(value) => value,
        Err(error) => return error,
    };
    let opcode = match required_u64(ctx, argc, argv, 1, "ARM64 writer opcode") {
        Ok(value) if value <= u32::MAX as u64 => value as u32,
        Ok(_) => return throw_internal_error(ctx, "ARM64 writer opcode is out of range"),
        Err(error) => return error,
    };
    let Some(method) = stalker_writer::lookup_writer_method(opcode) else {
        return throw_internal_error(ctx, "unknown ARM64 writer opcode");
    };

    let mut byte_storage = Vec::new();
    let encoded = match encode_writer_arguments(ctx, method, argc, argv, 2, &mut byte_storage) {
        Ok(value) => value,
        Err(error) => return error,
    };

    let mut out = 0u64;
    let Some(status) = with_stalker_transform_frame_mut(token, |frame| {
        (frame.access.writer_invoke)(
            frame.access.writer,
            opcode,
            encoded.as_ptr(),
            encoded.len() as u32,
            &mut out,
        )
    }) else {
        return throw_internal_error(ctx, "invalid operation outside a Stalker transform callback");
    };

    writer_result_to_js(ctx, method, status, out)
}

unsafe extern "C" fn js_stalker_relocator_create(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let token = match required_stalker_transform_token(ctx, argc, argv) {
        Ok(value) => value,
        Err(error) => return error,
    };
    if argc < 2 {
        return throw_internal_error(ctx, "Arm64Relocator input code is required");
    }
    let input_code = match extract_pointer_address(ctx, JSValue(*argv.add(1)), "Arm64Relocator") {
        Ok(value) => value,
        Err(error) => return error,
    };
    if input_code == 0 {
        return throw_internal_error(ctx, "Arm64Relocator input code must not be NULL");
    }

    let Some(handle) = with_stalker_transform_frame_mut(token, |frame| {
        let relocator = (frame.access.relocator_create)(frame.access.writer, input_code);
        if relocator == 0 {
            return 0;
        }
        let handle = frame.next_relocator_handle;
        frame.next_relocator_handle = handle.saturating_add(1);
        frame.relocators.push((handle, relocator));
        handle
    }) else {
        return throw_internal_error(ctx, "invalid operation outside a Stalker transform callback");
    };
    if handle == 0 {
        return throw_internal_error(ctx, "failed to create Arm64Relocator");
    }
    ffi::qjs_new_int64(ctx, handle as i64)
}

unsafe extern "C" fn js_stalker_relocator_destroy(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let token = match required_stalker_transform_token(ctx, argc, argv) {
        Ok(value) => value,
        Err(error) => return error,
    };
    let handle = match required_u64(ctx, argc, argv, 1, "Arm64Relocator handle") {
        Ok(value) => value,
        Err(error) => return error,
    };

    // Dropping a relocator whose frame is already gone is a no-op: the transform
    // guard destroyed it when the callback returned.
    let _ = with_stalker_transform_frame_mut(token, |frame| {
        if let Some(index) = frame.relocators.iter().position(|(id, _)| *id == handle) {
            let (_, relocator) = frame.relocators.remove(index);
            (frame.access.relocator_destroy)(relocator);
        }
    });
    JSValue::undefined().raw()
}

unsafe extern "C" fn js_stalker_relocator_reset(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let token = match required_stalker_transform_token(ctx, argc, argv) {
        Ok(value) => value,
        Err(error) => return error,
    };
    let handle = match required_u64(ctx, argc, argv, 1, "Arm64Relocator handle") {
        Ok(value) => value,
        Err(error) => return error,
    };
    if argc < 3 {
        return throw_internal_error(ctx, "Arm64Relocator reset input code is required");
    }
    let input = match extract_pointer_address(ctx, JSValue(*argv.add(2)), "Arm64Relocator reset input code") {
        Ok(value) if value != 0 => value,
        Ok(_) => return throw_internal_error(ctx, "Arm64Relocator reset input code must not be NULL"),
        Err(error) => return error,
    };

    let Some(status) = with_stalker_transform_frame_mut(token, |frame| {
        let Some((_, relocator)) = frame.relocators.iter().copied().find(|(id, _)| *id == handle) else {
            return None;
        };
        let args = [input, frame.access.writer as u64];
        Some((frame.access.relocator_invoke)(
            relocator,
            stalker_writer::RELOC_OP_RESET,
            args.as_ptr(),
            args.len() as u32,
            std::ptr::null_mut(),
        ))
    }) else {
        return throw_internal_error(ctx, "invalid operation outside a Stalker transform callback");
    };
    match status {
        Some(status) if status >= 0 => JSValue::undefined().raw(),
        Some(_) => throw_internal_error(ctx, "Arm64Relocator.reset() was rejected by the ARM64 relocator"),
        None => throw_internal_error(ctx, "Arm64Relocator has already been disposed"),
    }
}

unsafe extern "C" fn js_stalker_relocator_invoke(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let token = match required_stalker_transform_token(ctx, argc, argv) {
        Ok(value) => value,
        Err(error) => return error,
    };
    let handle = match required_u64(ctx, argc, argv, 1, "Arm64Relocator handle") {
        Ok(value) => value,
        Err(error) => return error,
    };
    let opcode = match required_u64(ctx, argc, argv, 2, "Arm64Relocator opcode") {
        Ok(value) if value <= u32::MAX as u64 => value as u32,
        Ok(_) => return throw_internal_error(ctx, "Arm64Relocator opcode is out of range"),
        Err(error) => return error,
    };
    let Some(method) = stalker_writer::lookup_relocator_method(opcode) else {
        return throw_internal_error(ctx, "unknown Arm64Relocator opcode");
    };

    let mut byte_storage = Vec::new();
    let encoded = match encode_writer_arguments(ctx, method, argc, argv, 3, &mut byte_storage) {
        Ok(value) => value,
        Err(error) => return error,
    };

    let mut out = 0u64;
    let Some(status) = with_stalker_transform_frame_mut(token, |frame| {
        let Some((_, relocator)) = frame.relocators.iter().copied().find(|(id, _)| *id == handle) else {
            return None;
        };
        Some((frame.access.relocator_invoke)(
            relocator,
            opcode,
            encoded.as_ptr(),
            encoded.len() as u32,
            &mut out,
        ))
    }) else {
        return throw_internal_error(ctx, "invalid operation outside a Stalker transform callback");
    };
    let Some(status) = status else {
        return throw_internal_error(ctx, "Arm64Relocator has already been disposed");
    };

    writer_result_to_js(ctx, method, status, out)
}

unsafe fn set_js_string_property(ctx: *mut ffi::JSContext, object: ffi::JSValue, name: &str, value: &str) {
    let key = std::ffi::CString::new(name).unwrap_or_default();
    let text = ffi::JS_NewStringLen(ctx, value.as_ptr() as *const _, value.len());
    ffi::JS_SetPropertyStr(ctx, object, key.as_ptr(), text);
}

unsafe fn set_js_object_property(ctx: *mut ffi::JSContext, object: ffi::JSValue, name: &str, value: ffi::JSValue) {
    let key = std::ffi::CString::new(name).unwrap_or_default();
    ffi::JS_SetPropertyStr(ctx, object, key.as_ptr(), value);
}

unsafe fn method_table_to_js(
    ctx: *mut ffi::JSContext,
    methods: &[stalker_writer::StalkerWriterMethod],
) -> ffi::JSValue {
    let array = ffi::JS_NewArray(ctx);
    for (index, method) in methods.iter().enumerate() {
        let entry = ffi::JS_NewObject(ctx);
        set_js_string_property(ctx, entry, "name", method.name);
        set_js_u64_property(ctx, entry, "opcode", method.opcode as u64);
        set_js_string_property(ctx, entry, "argSpec", method.arg_spec);
        set_js_string_property(ctx, entry, "result", method.result.as_str());
        set_js_string_property(ctx, entry, "kind", method.kind.as_str());
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, entry);
    }
    array
}

unsafe fn enum_table_to_js(ctx: *mut ffi::JSContext, entries: &[(String, u32)]) -> ffi::JSValue {
    let object = ffi::JS_NewObject(ctx);
    for (name, value) in entries {
        set_js_u64_property(ctx, object, name, *value as u64);
    }
    object
}

unsafe extern "C" fn js_stalker_statistics(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let Some(backend) = backend() else {
        return throw_internal_error(ctx, "Stalker backend is not installed");
    };
    let statistics = match (backend.statistics)() {
        Ok(value) => value,
        Err(error) => return throw_internal_error(ctx, error),
    };

    let result = ffi::JS_NewObject(ctx);
    set_js_u64_property(ctx, result, "droppedEvents", statistics.dropped_events);
    set_js_u64_property(ctx, result, "activeTraces", statistics.active_traces);
    set_js_u64_property(ctx, result, "pendingTraces", statistics.pending_traces);
    set_js_u64_property(ctx, result, "retiredTraces", statistics.retired_traces);
    set_js_u64_property(ctx, result, "activeCallProbes", statistics.active_call_probes);
    set_js_u64_property(ctx, result, "retiredCallProbes", statistics.retired_call_probes);
    set_js_u64_property(ctx, result, "callProbeAnchors", statistics.call_probe_anchors);

    let traces = ffi::JS_NewArray(ctx);
    for (index, trace) in statistics.traces.iter().enumerate() {
        let entry = ffi::JS_NewObject(ctx);
        set_js_u64_property(ctx, entry, "threadId", trace.thread_id);
        set_js_u64_property(ctx, entry, "queueCapacity", trace.queue_capacity);
        set_js_u64_property(ctx, entry, "queuedEvents", trace.queued_events);
        set_js_u64_property(ctx, entry, "droppedEvents", trace.dropped_events);
        ffi::JS_SetPropertyUint32(ctx, traces, index as u32, entry);
    }
    set_js_object_property(ctx, result, "traces", traces);

    let retired_callouts = take_retired_stalker_callouts(ctx as usize);
    set_js_u64_property(ctx, result, "retiredCallouts", retired_callouts.len() as u64);
    // The retirement queue is consumed here, so hand the ids back to the facade
    // instead of dropping them: the bootstrap uses them to release JS roots.
    let callouts = ffi::JS_NewArray(ctx);
    for (index, id) in retired_callouts.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, callouts, index as u32, ffi::qjs_new_int64(ctx, *id as i64));
    }
    set_js_object_property(ctx, result, "retiredCalloutIds", callouts);
    result
}

unsafe extern "C" fn js_stalker_writer_spec(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let enums = backend().map(|backend| (backend.writer_enums)()).unwrap_or_default();
    let result = ffi::JS_NewObject(ctx);
    set_js_object_property(
        ctx,
        result,
        "methods",
        method_table_to_js(ctx, stalker_writer::STALKER_WRITER_METHODS),
    );
    set_js_object_property(
        ctx,
        result,
        "relocatorMethods",
        method_table_to_js(ctx, stalker_writer::STALKER_RELOCATOR_METHODS),
    );
    set_js_object_property(ctx, result, "registers", enum_table_to_js(ctx, &enums.registers));
    set_js_object_property(ctx, result, "conditions", enum_table_to_js(ctx, &enums.conditions));
    set_js_object_property(ctx, result, "indexModes", enum_table_to_js(ctx, &enums.index_modes));
    result
}

unsafe fn required_stalker_transform_token(
    ctx: *mut ffi::JSContext,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> Result<u64, ffi::JSValue> {
    required_u64(ctx, argc, argv, 0, "Stalker iterator token")
}

unsafe extern "C" fn js_stalker_transform_next(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let token = match required_stalker_transform_token(ctx, argc, argv) {
        Ok(value) => value,
        Err(error) => return error,
    };
    let mut instruction = StalkerInstruction::default();
    let Some(found) = with_stalker_transform_frame_mut(token, |frame| {
        let found = (frame.access.next)(frame.access.opaque, &mut instruction) != 0;
        frame.has_current_instruction = found;
        if found {
            frame.instruction = Some(instruction);
        }
        found
    }) else {
        return throw_internal_error(ctx, "invalid operation outside a Stalker transform callback");
    };

    JSValue::bool(found).raw()
}

unsafe extern "C" fn js_stalker_transform_get_instruction_field(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let token = match required_stalker_transform_token(ctx, argc, argv) {
        Ok(value) => value,
        Err(error) => return error,
    };
    let field = match required_u64(ctx, argc, argv, 1, "Stalker instruction field") {
        Ok(value) => value,
        Err(error) => return error,
    };
    let Some(instruction) = with_stalker_transform_frame_mut(token, |frame| frame.instruction) else {
        return throw_internal_error(ctx, "invalid operation outside a Stalker transform callback");
    };
    let Some(instruction) = instruction else {
        return throw_internal_error(ctx, "Stalker iterator next() has not produced an instruction");
    };

    match field {
        0 => ffi::qjs_new_int64(ctx, instruction.id as i64),
        1 => create_native_pointer(ctx, instruction.address).raw(),
        2 => create_native_pointer(ctx, instruction.address.saturating_add(instruction.size as u64)).raw(),
        3 => ffi::qjs_new_int64(ctx, instruction.size as i64),
        4 => ffi::JS_NewStringLen(
            ctx,
            instruction.mnemonic.as_ptr() as *const _,
            stalker_instruction_text_len(&instruction.mnemonic),
        ),
        5 => ffi::JS_NewStringLen(
            ctx,
            instruction.op_str.as_ptr() as *const _,
            stalker_instruction_text_len(&instruction.op_str),
        ),
        6 => {
            let bytes_len = (instruction.bytes_len as usize).min(instruction.bytes.len());
            ffi::JS_NewArrayBufferCopy(ctx, instruction.bytes.as_ptr(), bytes_len)
        }
        _ => throw_internal_error(ctx, "unknown Stalker instruction field"),
    }
}

unsafe extern "C" fn js_stalker_transform_keep_all(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let token = match required_stalker_transform_token(ctx, argc, argv) {
        Ok(value) => value,
        Err(error) => return error,
    };
    if with_stalker_transform_frame_mut(token, |_| ()).is_none() {
        return throw_internal_error(ctx, "invalid operation outside a Stalker transform callback");
    }
    keep_remaining_stalker_instructions(token);
    JSValue::undefined().raw()
}

unsafe extern "C" fn js_stalker_transform_keep(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let token = match required_stalker_transform_token(ctx, argc, argv) {
        Ok(value) => value,
        Err(error) => return error,
    };
    let Some(kept) = with_stalker_transform_frame_mut(token, |frame| {
        if !frame.has_current_instruction {
            return false;
        }
        (frame.access.keep)(frame.access.opaque);
        frame.has_current_instruction = false;
        true
    }) else {
        return throw_internal_error(ctx, "invalid operation outside a Stalker transform callback");
    };
    if !kept {
        return throw_internal_error(ctx, "Stalker iterator keep() requires a current instruction");
    }
    JSValue::undefined().raw()
}

unsafe extern "C" fn js_stalker_transform_get_memory_access(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let token = match required_stalker_transform_token(ctx, argc, argv) {
        Ok(value) => value,
        Err(error) => return error,
    };
    let Some(value) =
        with_stalker_transform_frame_mut(token, |frame| (frame.access.get_memory_access)(frame.access.opaque))
    else {
        return throw_internal_error(ctx, "invalid operation outside a Stalker transform callback");
    };
    ffi::qjs_new_int64(ctx, value as i64)
}

unsafe extern "C" fn js_stalker_transform_put_callout(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let token = match required_stalker_transform_token(ctx, argc, argv) {
        Ok(value) => value,
        Err(error) => return error,
    };
    let id = match required_u64(ctx, argc, argv, 1, "Stalker callout id") {
        Ok(value) if value != 0 && value <= u32::MAX as u64 => value as u32,
        Ok(_) => return throw_internal_error(ctx, "Stalker callout id is out of range"),
        Err(error) => return error,
    };
    let native_callback = if argc >= 3 {
        match extract_pointer_address(ctx, JSValue(*argv.add(2)), "Stalker callout callback") {
            Ok(value) => value,
            Err(error) => return error,
        }
    } else {
        0
    };
    let native_data = if argc >= 4 {
        match extract_pointer_address(ctx, JSValue(*argv.add(3)), "Stalker callout data") {
            Ok(value) => value,
            Err(error) => return error,
        }
    } else {
        0
    };
    let Some(added) = with_stalker_transform_frame_mut(token, |frame| {
        (frame.access.put_callout)(frame.access.opaque, ctx as usize, id, native_callback, native_data) != 0
    }) else {
        return throw_internal_error(ctx, "invalid operation outside a Stalker transform callback");
    };
    if !added {
        return throw_internal_error(ctx, "failed to insert Stalker callout");
    }
    JSValue::undefined().raw()
}

unsafe extern "C" fn js_stalker_transform_put_chaining_return(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let token = match required_stalker_transform_token(ctx, argc, argv) {
        Ok(value) => value,
        Err(error) => return error,
    };
    let Some(()) =
        with_stalker_transform_frame_mut(token, |frame| (frame.access.put_chaining_return)(frame.access.opaque))
    else {
        return throw_internal_error(ctx, "invalid operation outside a Stalker transform callback");
    };
    JSValue::undefined().raw()
}

unsafe extern "C" fn js_stalker_callout_get_register(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let field = match required_u64(ctx, argc, argv, 0, "CpuContext register") {
        Ok(value) if value <= u32::MAX as u64 => value as u32,
        Ok(_) => return throw_internal_error(ctx, "CpuContext register is out of range"),
        Err(error) => return error,
    };
    let Some(access) = current_callout_access() else {
        return throw_internal_error(ctx, "invalid operation outside a Stalker callout callback");
    };

    if (64..96).contains(&field) {
        let mut value = [0u8; 16];
        if (access.get_vector)(access.opaque, field - 64, value.as_mut_ptr()) == 0 {
            return throw_internal_error(ctx, "failed to read Stalker vector register");
        }
        return ffi::JS_NewArrayBufferCopy(ctx, value.as_ptr(), value.len());
    }
    if field > 33 {
        return throw_internal_error(ctx, "unknown CpuContext register");
    }

    let value = (access.get_register)(access.opaque, field);
    if field == 33 {
        ffi::qjs_new_uint32(ctx, value as u32)
    } else {
        create_native_pointer(ctx, value).raw()
    }
}

unsafe extern "C" fn js_stalker_callout_set_register(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let field = match required_u64(ctx, argc, argv, 0, "CpuContext register") {
        Ok(value) if value <= u32::MAX as u64 => value as u32,
        Ok(_) => return throw_internal_error(ctx, "CpuContext register is out of range"),
        Err(error) => return error,
    };
    if argc < 2 {
        return throw_internal_error(ctx, "CpuContext register value is required");
    }
    let Some(access) = current_callout_access() else {
        return throw_internal_error(ctx, "invalid operation outside a Stalker callout callback");
    };

    if (64..96).contains(&field) {
        let value = match crate::jsapi::memory::extract_bytes(ctx, JSValue(*argv.add(1))) {
            Ok(value) => value,
            Err(error) => return error,
        };
        if value.len() != 16 {
            return throw_internal_error(ctx, "incorrect vector size");
        }
        if (access.set_vector)(access.opaque, field - 64, value.as_ptr()) == 0 {
            return throw_internal_error(ctx, "failed to write Stalker vector register");
        }
        return JSValue::undefined().raw();
    }
    if field > 33 {
        return throw_internal_error(ctx, "unknown CpuContext register");
    }

    let value = match extract_pointer_address(ctx, JSValue(*argv.add(1)), "CpuContext register") {
        Ok(value) => value,
        Err(error) => return error,
    };
    (access.set_register)(access.opaque, field, value);
    JSValue::undefined().raw()
}

unsafe extern "C" fn js_stalker_take_retired_callouts(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let result = ffi::JS_NewArray(ctx);
    for (index, id) in take_retired_stalker_callouts(ctx as usize).into_iter().enumerate() {
        let value = ffi::qjs_new_uint32(ctx, id);
        if ffi::JS_SetPropertyUint32(ctx, result, index as u32, value) < 0 {
            ffi::qjs_free_value(ctx, result);
            return ffi::qjs_exception();
        }
    }
    result
}

unsafe extern "C" fn js_stalker_get_trust_threshold(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let backend = match backend_or_throw(ctx) {
        Ok(value) => value,
        Err(error) => return error,
    };
    match (backend.get_trust_threshold)() {
        Ok(value) => JSValue::int(value).raw(),
        Err(error) => throw_internal_error(ctx, &error),
    }
}

unsafe extern "C" fn js_stalker_set_trust_threshold(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let backend = match backend_or_throw(ctx) {
        Ok(value) => value,
        Err(error) => return error,
    };
    if argc < 1 {
        return throw_internal_error(ctx, "trustThreshold is required");
    }
    let Some(value) = JSValue(*argv).to_i64(ctx) else {
        return throw_internal_error(ctx, "trustThreshold must be an integer");
    };
    let Ok(value) = i32::try_from(value) else {
        return throw_internal_error(ctx, "trustThreshold is out of range");
    };
    match (backend.set_trust_threshold)(value) {
        Ok(()) => JSValue::undefined().raw(),
        Err(error) => throw_internal_error(ctx, &error),
    }
}

pub fn register_stalker_api(ctx: &JSContext) {
    let global = ctx.global_object();
    unsafe {
        let raw = global.raw();
        add_cfunction_to_object(
            ctx.as_ptr(),
            raw,
            "__rf_stalker_is_supported",
            js_stalker_is_supported,
            0,
        );
        add_cfunction_to_object(ctx.as_ptr(), raw, "__rf_stalker_follow", js_stalker_follow, 7);
        add_cfunction_to_object(ctx.as_ptr(), raw, "__rf_stalker_drain_due", js_stalker_drain_due, 0);
        add_cfunction_to_object(ctx.as_ptr(), raw, "__rf_stalker_unfollow", js_stalker_unfollow, 1);
        add_cfunction_to_object(ctx.as_ptr(), raw, "__rf_stalker_flush", js_stalker_flush, 0);
        add_cfunction_to_object(
            ctx.as_ptr(),
            raw,
            "__rf_stalker_garbage_collect",
            js_stalker_garbage_collect,
            0,
        );
        add_cfunction_to_object(ctx.as_ptr(), raw, "__rf_stalker_exclude", js_stalker_exclude, 2);
        add_cfunction_to_object(ctx.as_ptr(), raw, "__rf_stalker_invalidate", js_stalker_invalidate, 2);
        add_cfunction_to_object(
            ctx.as_ptr(),
            raw,
            "__rf_stalker_add_call_probe",
            js_stalker_add_call_probe,
            4,
        );
        add_cfunction_to_object(
            ctx.as_ptr(),
            raw,
            "__rf_stalker_remove_call_probe",
            js_stalker_remove_call_probe,
            1,
        );
        add_cfunction_to_object(
            ctx.as_ptr(),
            raw,
            "__rf_stalker_get_probe_argument",
            js_stalker_get_probe_argument,
            1,
        );
        add_cfunction_to_object(
            ctx.as_ptr(),
            raw,
            "__rf_stalker_set_probe_argument",
            js_stalker_set_probe_argument,
            2,
        );
        add_cfunction_to_object(
            ctx.as_ptr(),
            raw,
            "__rf_stalker_transform_next",
            js_stalker_transform_next,
            1,
        );
        add_cfunction_to_object(
            ctx.as_ptr(),
            raw,
            "__rf_stalker_transform_keep",
            js_stalker_transform_keep,
            1,
        );
        add_cfunction_to_object(
            ctx.as_ptr(),
            raw,
            "__rf_stalker_transform_keep_all",
            js_stalker_transform_keep_all,
            1,
        );
        add_cfunction_to_object(
            ctx.as_ptr(),
            raw,
            "__rf_stalker_transform_get_instruction_field",
            js_stalker_transform_get_instruction_field,
            2,
        );
        add_cfunction_to_object(
            ctx.as_ptr(),
            raw,
            "__rf_stalker_transform_get_memory_access",
            js_stalker_transform_get_memory_access,
            1,
        );
        add_cfunction_to_object(
            ctx.as_ptr(),
            raw,
            "__rf_stalker_transform_put_callout",
            js_stalker_transform_put_callout,
            4,
        );
        add_cfunction_to_object(
            ctx.as_ptr(),
            raw,
            "__rf_stalker_transform_put_chaining_return",
            js_stalker_transform_put_chaining_return,
            1,
        );
        add_cfunction_to_object(
            ctx.as_ptr(),
            raw,
            "__rf_stalker_callout_get_register",
            js_stalker_callout_get_register,
            1,
        );
        add_cfunction_to_object(
            ctx.as_ptr(),
            raw,
            "__rf_stalker_callout_set_register",
            js_stalker_callout_set_register,
            2,
        );
        add_cfunction_to_object(ctx.as_ptr(), raw, "__rf_stalker_statistics", js_stalker_statistics, 0);
        add_cfunction_to_object(ctx.as_ptr(), raw, "__rf_stalker_writer_spec", js_stalker_writer_spec, 0);
        add_cfunction_to_object(
            ctx.as_ptr(),
            raw,
            "__rf_arm64_writer_create",
            js_standalone_writer_create,
            2,
        );
        add_cfunction_to_object(
            ctx.as_ptr(),
            raw,
            "__rf_arm64_writer_destroy",
            js_standalone_writer_destroy,
            1,
        );
        add_cfunction_to_object(
            ctx.as_ptr(),
            raw,
            "__rf_arm64_writer_reset",
            js_standalone_writer_reset,
            3,
        );
        add_cfunction_to_object(
            ctx.as_ptr(),
            raw,
            "__rf_arm64_writer_invoke",
            js_standalone_writer_invoke,
            2,
        );
        add_cfunction_to_object(
            ctx.as_ptr(),
            raw,
            "__rf_arm64_relocator_create",
            js_standalone_relocator_create,
            2,
        );
        add_cfunction_to_object(
            ctx.as_ptr(),
            raw,
            "__rf_arm64_relocator_destroy",
            js_standalone_relocator_destroy,
            1,
        );
        add_cfunction_to_object(
            ctx.as_ptr(),
            raw,
            "__rf_arm64_relocator_reset",
            js_standalone_relocator_reset,
            3,
        );
        add_cfunction_to_object(
            ctx.as_ptr(),
            raw,
            "__rf_arm64_relocator_invoke",
            js_standalone_relocator_invoke,
            2,
        );
        add_cfunction_to_object(
            ctx.as_ptr(),
            raw,
            "__rf_stalker_writer_invoke",
            js_stalker_writer_invoke,
            2,
        );
        add_cfunction_to_object(
            ctx.as_ptr(),
            raw,
            "__rf_stalker_relocator_create",
            js_stalker_relocator_create,
            2,
        );
        add_cfunction_to_object(
            ctx.as_ptr(),
            raw,
            "__rf_stalker_relocator_destroy",
            js_stalker_relocator_destroy,
            2,
        );
        add_cfunction_to_object(
            ctx.as_ptr(),
            raw,
            "__rf_stalker_relocator_reset",
            js_stalker_relocator_reset,
            3,
        );
        add_cfunction_to_object(
            ctx.as_ptr(),
            raw,
            "__rf_stalker_relocator_invoke",
            js_stalker_relocator_invoke,
            3,
        );
        add_cfunction_to_object(
            ctx.as_ptr(),
            raw,
            "__rf_stalker_take_retired_callouts",
            js_stalker_take_retired_callouts,
            0,
        );
        add_cfunction_to_object(
            ctx.as_ptr(),
            raw,
            "__rf_stalker_get_trust_threshold",
            js_stalker_get_trust_threshold,
            0,
        );
        add_cfunction_to_object(
            ctx.as_ptr(),
            raw,
            "__rf_stalker_set_trust_threshold",
            js_stalker_set_trust_threshold,
            1,
        );
    }
    global.free(ctx.as_ptr());

    STALKER_TRANSFORM_STACK
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .reserve(8);

    match ctx.eval(include_str!("stalker_boot.js"), "<stalker_boot>") {
        Ok(value) => value.free(ctx.as_ptr()),
        Err(error) => crate::jsapi::console::output_message(&format!("[stalker] bootstrap failed: {error}")),
    }
}

#[cfg(test)]
mod tests {
    use crate::JSEngine;

    #[test]
    fn parses_native_stalker_event_buffers() {
        let engine = JSEngine::new().expect("engine");
        let value = engine
            .eval(
                r#"
                (() => {
                    const data = new ArrayBuffer(64);
                    const view = new DataView(data);
                    view.setUint32(0, 1, true);
                    view.setUint32(8, 0x1234, true);
                    view.setUint32(16, 0x5678, true);
                    view.setInt32(24, 3, true);
                    view.setUint32(32, 8, true);
                    view.setUint32(40, 0x9000, true);
                    view.setUint32(48, 0x9010, true);
                    const rows = Stalker.parse(data, { annotate: true, stringify: true });
                    return rows.length === 2 &&
                        rows[0].join(',') === 'call,0x1234,0x5678,3' &&
                        rows[1].join(',') === 'block,0x9000,0x9010';
                })()
                "#,
            )
            .expect("eval");
        assert_eq!(value.to_bool(), Some(true));
        value.free(engine.context().as_ptr());
    }
}
