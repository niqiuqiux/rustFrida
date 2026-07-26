//! Frida Gum Stalker backend and legacy CLI bridge.

#![cfg(feature = "frida-gum")]

use crate::communication::{log_msg, write_stream};
use crate::stalker_writer;
use frida_gum::interceptor::Interceptor;
use frida_gum::stalker::{
    Event, EventMask, EventSink, NativeCallProbeCallback, NativeEventSinkCallback, Stalker, StalkerIterator,
    StalkerMemoryAccess, Transformer,
};
use frida_gum::{Gum, MemoryRange, ModuleRegistryObserver, NativePointer};
use std::collections::{HashMap, HashSet};
use std::ffi::c_void;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use quickjs_hook::{
    StalkerBackend, StalkerCallProbeConfig, StalkerCalloutAccess, StalkerDrainResult, StalkerEventBatch,
    StalkerFollowConfig, StalkerInstruction, StalkerStatistics, StalkerTraceStatistics, StalkerTransformAccess,
};

const EVENT_RECORD_SIZE: usize = 32;
const VALID_EVENT_MASK: u32 = 0x1f;
const DEFAULT_QUEUE_CAPACITY: u32 = 16_384;
const DEFAULT_QUEUE_DRAIN_INTERVAL: u32 = 250;
const SHUTDOWN_GC_TIMEOUT: Duration = Duration::from_millis(500);
const DRAIN_WORKER_STOP_TIMEOUT: Duration = Duration::from_millis(1_500);
const DRAIN_WORKER_POLL_SLICE: Duration = Duration::from_millis(100);
const DRAIN_WORKER_IDLE_POLL: Duration = Duration::from_millis(25);

fn current_thread_id() -> u64 {
    unsafe { libc::syscall(libc::SYS_gettid) as u64 }
}

struct EventQueue {
    current: Vec<u8>,
    byte_limit: usize,
    /// Events discarded because the queue was full. The queue deliberately does
    /// not grow: a Stalker thread that outruns the drain worker must lose events
    /// rather than the agent's heap. The counter is monotonic so a script can
    /// tell a full queue apart from an idle one after a drain.
    dropped: u64,
}

impl EventQueue {
    fn with_capacity(capacity: usize) -> Self {
        let byte_limit = capacity.saturating_mul(EVENT_RECORD_SIZE);
        Self {
            current: Vec::with_capacity(byte_limit),
            byte_limit,
            dropped: 0,
        }
    }

    fn push(&mut self, event: &Event) {
        if self.byte_limit.saturating_sub(self.current.len()) >= EVENT_RECORD_SIZE {
            encode_event(event, &mut self.current);
        } else {
            self.dropped = self.dropped.saturating_add(1);
        }
    }

    fn drain(&mut self, thread_id: u64, replacement: Vec<u8>) -> Vec<quickjs_hook::StalkerEventBatch> {
        let data = std::mem::replace(&mut self.current, replacement);
        if data.is_empty() {
            Vec::new()
        } else {
            vec![quickjs_hook::StalkerEventBatch { thread_id, data }]
        }
    }
}

fn encode_event(event: &Event, output: &mut Vec<u8>) {
    let (kind, first, second, depth) = match event {
        Event::Call {
            location,
            target,
            depth,
        } => (EventMask::Call.bits(), location.0 as u64, target.0 as u64, *depth),
        Event::Ret {
            location,
            target,
            depth,
        } => (EventMask::Ret.bits(), location.0 as u64, target.0 as u64, *depth),
        Event::Exec { location } => (EventMask::Exec.bits(), location.0 as u64, 0, 0),
        Event::Block { start, end } => (EventMask::Block.bits(), start.0 as u64, end.0 as u64, 0),
        Event::Compile { start, end } => (EventMask::Compile.bits(), start.0 as u64, end.0 as u64, 0),
    };

    output.extend_from_slice(&kind.to_le_bytes());
    output.extend_from_slice(&0u32.to_le_bytes());
    output.extend_from_slice(&first.to_le_bytes());
    output.extend_from_slice(&second.to_le_bytes());
    output.extend_from_slice(&depth.to_le_bytes());
    output.extend_from_slice(&0u32.to_le_bytes());
}

struct TraceBuffer {
    thread_id: u64,
    event_mask: EventMask,
    capacity: usize,
    drain_interval: Option<Duration>,
    next_drain: Mutex<Option<Instant>>,
    queue: Mutex<EventQueue>,
}

impl TraceBuffer {
    fn new(config: StalkerFollowConfig) -> Self {
        Self::new_at(config, Instant::now())
    }

    fn new_at(config: StalkerFollowConfig, now: Instant) -> Self {
        let drain_interval =
            (config.queue_drain_interval != 0).then(|| Duration::from_millis(config.queue_drain_interval as u64));
        Self {
            thread_id: config.thread_id,
            event_mask: EventMask::from_bits(config.event_mask),
            capacity: config.queue_capacity as usize,
            drain_interval,
            next_drain: Mutex::new(drain_interval.map(|interval| now + interval)),
            queue: Mutex::new(EventQueue::with_capacity(config.queue_capacity as usize)),
        }
    }

    fn drain(&self) -> Vec<StalkerEventBatch> {
        let replacement = Vec::with_capacity(self.capacity.saturating_mul(EVENT_RECORD_SIZE));
        self.queue
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .drain(self.thread_id, replacement)
    }

    fn time_until_drain(&self, now: Instant) -> Option<Duration> {
        self.next_drain
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .map(|deadline| deadline.saturating_duration_since(now))
    }

    /// Snapshot of this trace's queue state for `Stalker.statistics()`.
    fn statistics(&self) -> StalkerTraceStatistics {
        let queue = self.queue.lock().unwrap_or_else(|error| error.into_inner());
        StalkerTraceStatistics {
            thread_id: self.thread_id,
            queue_capacity: self.capacity as u64,
            queued_events: (queue.current.len() / EVENT_RECORD_SIZE) as u64,
            dropped_events: queue.dropped,
        }
    }

    fn drain_if_due(&self, now: Instant) -> Vec<StalkerEventBatch> {
        let Some(interval) = self.drain_interval else {
            return Vec::new();
        };
        let mut next_drain = self.next_drain.lock().unwrap_or_else(|error| error.into_inner());
        if next_drain.is_none_or(|deadline| deadline > now) {
            return Vec::new();
        }
        *next_drain = Some(now + interval);
        drop(next_drain);
        self.drain()
    }
}

struct TraceSink {
    buffer: Arc<TraceBuffer>,
}

impl EventSink for TraceSink {
    fn query_mask(&mut self) -> EventMask {
        self.buffer.event_mask
    }

    fn start(&mut self) {}

    fn process(&mut self, event: &Event) {
        self.buffer
            .queue
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push(event);
    }

    fn flush(&mut self) {}

    fn stop(&mut self) {}
}

struct StalkerRuntime {
    stalker: Stalker,
    active: HashMap<u64, Arc<TraceBuffer>>,
    execution_active: HashSet<u64>,
    native_call_depth: HashMap<u64, usize>,
    pending: HashMap<u64, StalkerFollowConfig>,
    retired: Vec<Arc<TraceBuffer>>,
    call_probes: HashMap<u32, ActiveCallProbe>,
    call_probe_anchors: HashMap<u64, CallProbeAnchor>,
    retired_call_probes: Vec<Arc<CallProbeState>>,
}

struct ActiveCallProbe {
    gum_id: u32,
    target_address: u64,
    state: Option<Arc<CallProbeState>>,
}

/// Identity of the mapping that owned a probe target when its anchor was
/// installed. After an unload the same address can be handed to a different
/// module, and reusing the old anchor would leave Gum holding state for code
/// that is no longer mapped.
#[derive(Clone, Debug, Eq, PartialEq)]
struct AnchorModuleIdentity {
    base: u64,
    path: String,
}

struct CallProbeAnchor {
    gum_id: u32,
    module: Option<AnchorModuleIdentity>,
}

struct CallProbeState {
    id: u32,
    context: usize,
}

struct CalloutRetirement {
    context: usize,
    id: u32,
}

impl Drop for CalloutRetirement {
    fn drop(&mut self) {
        quickjs_hook::retire_stalker_callout(self.context, self.id);
    }
}

// Regular Gum operations are serialized through STALKER_RUNTIME. Shutdown takes
// the runtime out of the slot first: gum_stalker_stop() may wait for followed
// threads whose call-probe callbacks re-enter the JS Stalker API.
unsafe impl Send for StalkerRuntime {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StalkerLifecycle {
    Ready,
    ShuttingDown,
    Retained,
    Stopped,
}

struct StalkerRuntimeSlot {
    lifecycle: StalkerLifecycle,
    runtime: Option<StalkerRuntime>,
}

impl Default for StalkerRuntimeSlot {
    fn default() -> Self {
        Self {
            lifecycle: StalkerLifecycle::Ready,
            runtime: None,
        }
    }
}

enum ShutdownStart {
    Started(Option<StalkerRuntime>),
    AlreadyStopped,
}

impl StalkerRuntimeSlot {
    fn require_ready(&self) -> Result<(), String> {
        match self.lifecycle {
            StalkerLifecycle::Ready => Ok(()),
            StalkerLifecycle::ShuttingDown => Err("Stalker is shutting down".to_string()),
            StalkerLifecycle::Retained => Err("Stalker shutdown is incomplete".to_string()),
            StalkerLifecycle::Stopped => Err("Stalker backend is stopped".to_string()),
        }
    }

    fn begin_shutdown(&mut self) -> Result<ShutdownStart, String> {
        match self.lifecycle {
            StalkerLifecycle::Ready | StalkerLifecycle::Retained => {
                self.lifecycle = StalkerLifecycle::ShuttingDown;
                Ok(ShutdownStart::Started(self.runtime.take()))
            }
            StalkerLifecycle::ShuttingDown => Err("Stalker shutdown is already in progress".to_string()),
            StalkerLifecycle::Stopped => Ok(ShutdownStart::AlreadyStopped),
        }
    }

    fn retain_after_failed_shutdown(&mut self, runtime: Option<StalkerRuntime>) {
        debug_assert_eq!(self.lifecycle, StalkerLifecycle::ShuttingDown);
        debug_assert!(self.runtime.is_none());
        self.runtime = runtime;
        self.lifecycle = StalkerLifecycle::Retained;
    }

    fn finish_shutdown(&mut self) {
        debug_assert_eq!(self.lifecycle, StalkerLifecycle::ShuttingDown);
        debug_assert!(self.runtime.is_none());
        self.lifecycle = StalkerLifecycle::Stopped;
    }

    fn activate(&mut self) -> Result<(), String> {
        match self.lifecycle {
            StalkerLifecycle::Ready => Ok(()),
            StalkerLifecycle::Stopped => {
                debug_assert!(self.runtime.is_none());
                self.lifecycle = StalkerLifecycle::Ready;
                Ok(())
            }
            StalkerLifecycle::ShuttingDown => Err("Stalker shutdown is still in progress".to_string()),
            StalkerLifecycle::Retained => Err("previous Stalker shutdown did not complete".to_string()),
        }
    }
}

static STALKER_RUNTIME: OnceLock<Mutex<StalkerRuntimeSlot>> = OnceLock::new();
// A transient Gum handle tears down embedded GLib when dropped. Keep one alive
// across independent JS property calls and release it only during agent cleanup.
static GUM_RUNTIME: OnceLock<Mutex<Option<Gum>>> = OnceLock::new();
static MODULE_REGISTRY_OBSERVER: OnceLock<Mutex<Option<ModuleRegistryObserver>>> = OnceLock::new();
static DRAIN_WORKER_STOP: AtomicBool = AtomicBool::new(true);
static DRAIN_WORKER_RUNNING: AtomicBool = AtomicBool::new(false);
static DRAIN_WORKER_TID: AtomicI32 = AtomicI32::new(0);

fn runtime_slot() -> &'static Mutex<StalkerRuntimeSlot> {
    STALKER_RUNTIME.get_or_init(|| Mutex::new(StalkerRuntimeSlot::default()))
}

fn gum_slot() -> &'static Mutex<Option<Gum>> {
    GUM_RUNTIME.get_or_init(|| Mutex::new(None))
}

fn module_observer_slot() -> &'static Mutex<Option<ModuleRegistryObserver>> {
    MODULE_REGISTRY_OBSERVER.get_or_init(|| Mutex::new(None))
}

fn retain_gum() -> Result<Gum, String> {
    let mut slot = gum_slot().lock().map_err(|_| "Gum runtime lock poisoned".to_string())?;
    Ok(slot.get_or_insert_with(Gum::obtain).clone())
}

/// Drop the agent's handle on Gum without letting the singleton deinitialise.
///
/// Dropping the last `Gum` runs `gum_deinit_embedded()`, and that reliably
/// crashes this agent: while tearing itself down Gum touches a `GUM_TYPE_*`
/// macro, which re-enters `gobject_perform_init` (gtype.c) after the GObject
/// type system has already been torn down. It then takes a rwlock through a
/// pointer that has lost its load base — `0x47c00` on every run — and faults on
/// the `wwb-loader` thread just as shutdown finishes.
///
/// Leaking is safe here and only leaks memory the agent is about to lose
/// anyway: the earlier cleanup phases have already unfollowed Stalker, reverted
/// the Interceptor and disconnected the module-registry observer, so no Gum
/// callback can point into the agent by the time this runs. Gum's own
/// destructor list lives in its heap rather than in `atexit`, so nothing tries
/// to run it after the agent is unmapped.
fn release_gum() -> Result<(), String> {
    let mut slot = gum_slot().lock().map_err(|_| "Gum runtime lock poisoned".to_string())?;
    if let Some(gum) = slot.take() {
        std::mem::forget(gum);
    }
    Ok(())
}

fn install_module_unload_observer() -> Result<(), String> {
    let mut slot = module_observer_slot()
        .lock()
        .map_err(|_| "module observer lock poisoned".to_string())?;
    if slot.is_some() {
        return Ok(());
    }
    let gum = retain_gum()?;
    let observer = ModuleRegistryObserver::on_removed(&gum, |range| {
        let base = range.base_address().0 as u64;
        let size = range.size();
        log_msg(format!("[stalker] module removed base=0x{base:x} size=0x{size:x}\n"));
        let retired_hfollow_target = retire_hfollow_in_range(base, size);
        if let Err(error) = retire_stalker_state_in_range(base, size, retired_hfollow_target) {
            log_msg(format!("[stalker] failed to retire module tracing state: {error}\n"));
        }
        quickjs_hook::discard_native_hooks_in_range(base, size);
    })
    .ok_or_else(|| "failed to observe Gum module removals".to_string())?;
    *slot = Some(observer);
    Ok(())
}

fn release_module_unload_observer() -> Result<(), String> {
    let mut slot = module_observer_slot()
        .lock()
        .map_err(|_| "module observer lock poisoned".to_string())?;
    *slot = None;
    Ok(())
}

fn lock_runtime() -> Result<MutexGuard<'static, StalkerRuntimeSlot>, String> {
    runtime_slot()
        .lock()
        .map_err(|_| "Stalker runtime lock poisoned".to_string())
}

fn ensure_runtime(slot: &mut StalkerRuntimeSlot) -> Result<&mut StalkerRuntime, String> {
    slot.require_ready()?;
    if slot.runtime.is_none() {
        let gum = retain_gum()?;
        if !Stalker::is_supported(&gum) {
            return Err("Stalker is not supported on this platform".to_string());
        }
        slot.runtime = Some(StalkerRuntime {
            stalker: Stalker::new(&gum),
            active: HashMap::new(),
            execution_active: HashSet::new(),
            native_call_depth: HashMap::new(),
            pending: HashMap::new(),
            retired: Vec::new(),
            call_probes: HashMap::new(),
            call_probe_anchors: HashMap::new(),
            retired_call_probes: Vec::new(),
        });
    }
    slot.runtime
        .as_mut()
        .ok_or_else(|| "Stalker runtime initialization failed".to_string())
}

fn retain_failed_runtime(runtime: &mut Option<StalkerRuntime>) -> Result<(), String> {
    let retained = runtime.take();
    match lock_runtime() {
        Ok(mut slot) => {
            slot.retain_after_failed_shutdown(retained);
            Ok(())
        }
        Err(error) => {
            // Dropping a partially stopped Stalker may free translated code still
            // referenced by a target thread. At this point the agent will remain
            // resident, so intentionally retain the runtime for process lifetime.
            if let Some(runtime) = retained {
                std::mem::forget(runtime);
            }
            Err(error)
        }
    }
}

fn drain_runtime(runtime: &StalkerRuntime) -> Vec<StalkerEventBatch> {
    let mut batches = Vec::new();
    for buffer in runtime.active.values().chain(runtime.retired.iter()) {
        batches.extend(buffer.drain());
    }
    batches
}

fn drain_due_runtime(runtime: &StalkerRuntime, now: Instant) -> Vec<StalkerEventBatch> {
    let mut batches = Vec::new();
    for buffer in runtime.active.values() {
        batches.extend(buffer.drain_if_due(now));
    }
    batches
}

fn next_periodic_drain_delay(now: Instant) -> Duration {
    let Ok(slot) = runtime_slot().try_lock() else {
        return Duration::from_millis(1);
    };
    if slot.lifecycle != StalkerLifecycle::Ready {
        return DRAIN_WORKER_IDLE_POLL;
    }
    let Some(runtime) = slot.runtime.as_ref() else {
        return DRAIN_WORKER_IDLE_POLL;
    };
    runtime
        .active
        .values()
        .filter_map(|buffer| buffer.time_until_drain(now))
        .min()
        .unwrap_or(DRAIN_WORKER_IDLE_POLL)
        .min(DRAIN_WORKER_POLL_SLICE)
}

fn sleep_duration(duration: Duration) {
    let millis = duration.as_millis().max(1).min(i64::MAX as u128) as i64;
    crate::raw_thread::sleep_ms(millis);
}

fn drain_worker_loop() {
    let _raw_clone_js = quickjs_hook::mark_raw_clone_js_thread();
    let mut error_reported = false;
    while !DRAIN_WORKER_STOP.load(Ordering::Acquire) {
        let delay = next_periodic_drain_delay(Instant::now());
        if !delay.is_zero() {
            sleep_duration(delay);
            continue;
        }

        match quickjs_hook::try_dispatch_due_stalker_events() {
            Ok(true) => error_reported = false,
            Ok(false) => crate::raw_thread::sleep_ms(1),
            Err(error) => {
                if !error_reported {
                    log_msg(format!("[stalker] periodic event delivery failed: {error}"));
                    error_reported = true;
                }
                crate::raw_thread::sleep_ms(1);
            }
        }
    }
    DRAIN_WORKER_RUNNING.store(false, Ordering::Release);
}

fn task_exists(tid: i32) -> bool {
    tid > 0 && std::path::Path::new(&format!("/proc/self/task/{tid}")).exists()
}

fn start_drain_worker() -> Result<(), String> {
    let current_tid = DRAIN_WORKER_TID.load(Ordering::Acquire);
    if DRAIN_WORKER_RUNNING.load(Ordering::Acquire) && task_exists(current_tid) {
        return Ok(());
    }

    DRAIN_WORKER_STOP.store(false, Ordering::Release);
    DRAIN_WORKER_RUNNING.store(true, Ordering::Release);
    match crate::raw_thread::spawn_detached(b"wwb-stalker-drain\0", drain_worker_loop) {
        Ok(tid) => {
            DRAIN_WORKER_TID.store(tid, Ordering::Release);
            Ok(())
        }
        Err(error) => {
            DRAIN_WORKER_STOP.store(true, Ordering::Release);
            DRAIN_WORKER_RUNNING.store(false, Ordering::Release);
            Err(format!("failed to start Stalker drain worker: {error}"))
        }
    }
}

fn stop_drain_worker(timeout: Duration) -> bool {
    DRAIN_WORKER_STOP.store(true, Ordering::Release);
    let tid = DRAIN_WORKER_TID.load(Ordering::Acquire);
    if tid <= 0 {
        DRAIN_WORKER_RUNNING.store(false, Ordering::Release);
        return true;
    }

    let started = Instant::now();
    while task_exists(tid) {
        if started.elapsed() >= timeout {
            return false;
        }
        crate::raw_thread::sleep_ms(5);
    }
    DRAIN_WORKER_TID.store(0, Ordering::Release);
    DRAIN_WORKER_RUNNING.store(false, Ordering::Release);
    true
}

fn backend_is_supported() -> bool {
    match retain_gum() {
        Ok(gum) => Stalker::is_supported(&gum),
        Err(error) => {
            log_msg(format!("[stalker] failed to retain Gum runtime: {error}"));
            false
        }
    }
}

unsafe extern "C" fn transform_iterator_next(opaque: usize, output: *mut StalkerInstruction) -> i32 {
    if opaque == 0 || output.is_null() {
        return 0;
    }
    let iterator = &mut *(opaque as *mut StalkerIterator<'static>);
    let Some(instruction) = iterator.next() else {
        return 0;
    };
    let raw = &instruction.instr().insn;
    let mut snapshot = StalkerInstruction {
        id: raw.id,
        address: raw.address,
        size: raw.size as u32,
        bytes_len: (raw.size as usize).min(raw.bytes.len()) as u32,
        ..StalkerInstruction::default()
    };
    snapshot.bytes.copy_from_slice(&raw.bytes);
    for (destination, source) in snapshot.mnemonic.iter_mut().zip(raw.mnemonic.iter()) {
        *destination = *source as u8;
    }
    for (destination, source) in snapshot.op_str.iter_mut().zip(raw.op_str.iter()) {
        *destination = *source as u8;
    }
    output.write(snapshot);
    1
}

unsafe extern "C" fn transform_iterator_keep(opaque: usize) {
    if opaque != 0 {
        (&*(opaque as *const StalkerIterator<'static>)).keep_instr();
    }
}

unsafe extern "C" fn transform_iterator_get_memory_access(opaque: usize) -> u32 {
    if opaque == 0 {
        return 0;
    }
    match (&*(opaque as *const StalkerIterator<'static>)).memory_access() {
        StalkerMemoryAccess::Open => 0,
        StalkerMemoryAccess::Exclusive => 1,
    }
}

unsafe extern "C" fn callout_get_register(opaque: usize, field: u32) -> u64 {
    if opaque == 0 {
        return 0;
    }
    let context = &*(opaque as *const frida_gum::CpuContext<'_>);
    match field {
        0..=28 => context.reg(field as usize),
        29 => context.fp(),
        30 => context.lr(),
        31 => context.sp(),
        32 => context.pc(),
        33 => context.nzcv(),
        _ => 0,
    }
}

unsafe extern "C" fn callout_set_register(opaque: usize, field: u32, value: u64) {
    if opaque == 0 {
        return;
    }
    let context = &mut *(opaque as *mut frida_gum::CpuContext<'_>);
    match field {
        0..=28 => context.set_reg(field as usize, value),
        29 => context.set_fp(value),
        30 => context.set_lr(value),
        31 => context.set_sp(value),
        32 => context.set_pc(value),
        33 => context.set_nzcv(value),
        _ => {}
    }
}

unsafe extern "C" fn callout_get_vector(opaque: usize, index: u32, output: *mut u8) -> i32 {
    if opaque == 0 || index >= 32 || output.is_null() {
        return 0;
    }
    let context = &*(opaque as *const frida_gum::CpuContext<'_>);
    let value = context.vector_reg(index as usize);
    std::ptr::copy_nonoverlapping(value.as_ptr(), output, value.len());
    1
}

unsafe extern "C" fn callout_set_vector(opaque: usize, index: u32, input: *const u8) -> i32 {
    if opaque == 0 || index >= 32 || input.is_null() {
        return 0;
    }
    let context = &mut *(opaque as *mut frida_gum::CpuContext<'_>);
    let mut value = [0u8; 16];
    std::ptr::copy_nonoverlapping(input, value.as_mut_ptr(), value.len());
    context.set_vector_reg(index as usize, value);
    1
}

type NativeStalkerCallout = unsafe extern "C" fn(*mut c_void, *mut c_void);

unsafe extern "C" fn transform_iterator_put_callout(
    opaque: usize,
    context: usize,
    id: u32,
    native_callback: u64,
    native_data: u64,
) -> i32 {
    if opaque == 0 || context == 0 || id == 0 {
        return 0;
    }
    let iterator = &*(opaque as *const StalkerIterator<'static>);
    let retirement = CalloutRetirement { context, id };

    if native_callback != 0 {
        let callback: NativeStalkerCallout = std::mem::transmute(native_callback as usize);
        let data = native_data as usize as *mut c_void;
        iterator.put_callout(move |cpu_context| {
            let _retirement = &retirement;
            callback(cpu_context.cpu_context.cast::<c_void>(), data);
        });
    } else {
        iterator.put_callout(move |mut cpu_context| {
            let _retirement = &retirement;
            let access = StalkerCalloutAccess {
                opaque: &mut cpu_context as *mut frida_gum::CpuContext<'_> as usize,
                get_register: callout_get_register,
                set_register: callout_set_register,
                get_vector: callout_get_vector,
                set_vector: callout_set_vector,
            };
            quickjs_hook::dispatch_stalker_callout(context, id, access);
        });
    }
    1
}

unsafe extern "C" fn transform_iterator_put_chaining_return(opaque: usize) {
    if opaque != 0 {
        (&*(opaque as *const StalkerIterator<'static>)).put_chaining_return();
    }
}

fn validate_follow_config(config: StalkerFollowConfig) -> Result<(), String> {
    if config.thread_id == 0 {
        return Err("threadId must be non-zero".to_string());
    }
    if config.event_mask & !VALID_EVENT_MASK != 0 {
        return Err(format!("invalid Stalker event mask: 0x{:x}", config.event_mask));
    }
    if config.transform && config.context == 0 {
        return Err("Stalker transform requires a JavaScript context".to_string());
    }
    Ok(())
}

fn start_follow(runtime: &mut StalkerRuntime, config: StalkerFollowConfig) -> Result<(), String> {
    if runtime.active.contains_key(&config.thread_id) {
        return Err(format!("thread {} is already being followed", config.thread_id));
    }

    let has_native_event_callback = config.native_event_callback != 0;
    let buffer_config = if has_native_event_callback {
        StalkerFollowConfig {
            queue_capacity: 0,
            queue_drain_interval: 0,
            ..config
        }
    } else {
        config
    };
    let buffer = Arc::new(TraceBuffer::new(buffer_config));
    let sink = TraceSink {
        buffer: Arc::clone(&buffer),
    };
    let gum = config.transform.then(retain_gum).transpose()?;
    let transformer = gum.as_ref().map(|gum| {
        let context = config.context;
        let thread_id = config.thread_id;
        Transformer::from_callback(gum, move |mut iterator, output| {
            // The output writer belongs to Gum and is only valid for the
            // duration of this callback, so the facade retires everything that
            // references it before returning.
            let writer = output.writer();
            let access = StalkerTransformAccess {
                opaque: &mut iterator as *mut StalkerIterator<'_> as usize,
                next: transform_iterator_next,
                keep: transform_iterator_keep,
                get_memory_access: transform_iterator_get_memory_access,
                put_callout: transform_iterator_put_callout,
                put_chaining_return: transform_iterator_put_chaining_return,
                writer: writer.raw_writer() as usize,
                writer_invoke: stalker_writer::writer_invoke,
                relocator_create: stalker_writer::relocator_create,
                relocator_destroy: stalker_writer::relocator_destroy,
                relocator_invoke: stalker_writer::relocator_invoke,
            };
            quickjs_hook::dispatch_stalker_transform(context, thread_id, access);
        })
    });
    if has_native_event_callback {
        let callback: NativeEventSinkCallback = unsafe { std::mem::transmute(config.native_event_callback as usize) };
        let data = config.native_event_data as usize as *mut c_void;
        if config.thread_id == current_thread_id() {
            unsafe {
                runtime.stalker.follow_me_with_native_sink(
                    transformer.as_ref(),
                    EventMask::from_bits(config.event_mask),
                    callback,
                    data,
                );
            }
        } else {
            unsafe {
                runtime.stalker.follow_with_native_sink(
                    config.thread_id as usize,
                    transformer.as_ref(),
                    EventMask::from_bits(config.event_mask),
                    callback,
                    data,
                );
            }
        }
    } else if config.thread_id == current_thread_id() {
        runtime.stalker.follow_me_with_owned_sink(transformer.as_ref(), sink);
    } else {
        runtime
            .stalker
            .follow_with_owned_sink(config.thread_id as usize, transformer.as_ref(), sink);
    }
    runtime.active.insert(config.thread_id, buffer);
    runtime.execution_active.insert(config.thread_id);

    if config.queue_drain_interval != 0 && !has_native_event_callback {
        if let Err(error) = start_drain_worker() {
            let buffer = runtime
                .active
                .remove(&config.thread_id)
                .expect("newly followed thread must remain active");
            runtime.execution_active.remove(&config.thread_id);
            if config.thread_id == current_thread_id() {
                runtime.stalker.unfollow_me();
            } else {
                runtime.stalker.unfollow(config.thread_id as usize);
            }
            runtime.stalker.flush();
            runtime.retired.push(buffer);
            return Err(error);
        }
    }
    Ok(())
}

fn backend_follow(config: StalkerFollowConfig) -> Result<(), String> {
    validate_follow_config(config)?;
    let mut slot = lock_runtime()?;
    let runtime = ensure_runtime(&mut slot)?;
    if runtime.active.contains_key(&config.thread_id) || runtime.pending.contains_key(&config.thread_id) {
        return Err(format!("thread {} is already being followed", config.thread_id));
    }

    if config.defer_current_thread && config.thread_id == current_thread_id() {
        runtime.pending.insert(config.thread_id, config);
        Ok(())
    } else {
        start_follow(runtime, config)
    }
}

fn backend_process_pending() -> Result<(), String> {
    let thread_id = current_thread_id();
    let mut slot = lock_runtime()?;
    slot.require_ready()?;
    let Some(runtime) = slot.runtime.as_mut() else {
        return Ok(());
    };
    let Some(config) = runtime.pending.remove(&thread_id) else {
        return Ok(());
    };
    start_follow(runtime, config)
}

fn backend_activate_current(address: u64) -> Result<bool, String> {
    let thread_id = current_thread_id();
    let mut slot = lock_runtime()?;
    slot.require_ready()?;
    let Some(runtime) = slot.runtime.as_mut() else {
        return Ok(false);
    };
    if !runtime.active.contains_key(&thread_id) {
        return Ok(false);
    }
    if !runtime.stalker.is_following_me() {
        return Err(format!("thread {thread_id} has no active Stalker execution context"));
    }
    let depth = runtime.native_call_depth.get(&thread_id).copied().unwrap_or(0);
    if depth == 0 && !runtime.execution_active.contains(&thread_id) {
        runtime.stalker.activate(NativePointer(address as *mut c_void));
        runtime.execution_active.insert(thread_id);
    } else if depth != 0 && !runtime.execution_active.contains(&thread_id) {
        return Err(format!(
            "thread {thread_id} has an inactive Stalker execution context at native call depth {depth}"
        ));
    }
    let next_depth = depth
        .checked_add(1)
        .ok_or_else(|| format!("thread {thread_id} Stalker native call depth overflow"))?;
    runtime.native_call_depth.insert(thread_id, next_depth);
    Ok(true)
}

fn backend_deactivate_current() -> Result<(), String> {
    let thread_id = current_thread_id();
    let mut slot = lock_runtime()?;
    slot.require_ready()?;
    let Some(runtime) = slot.runtime.as_mut() else {
        return Ok(());
    };
    let Some(depth) = runtime.native_call_depth.get(&thread_id).copied() else {
        return Ok(());
    };
    if depth > 1 {
        runtime.native_call_depth.insert(thread_id, depth - 1);
        return Ok(());
    }
    runtime.native_call_depth.remove(&thread_id);
    if runtime.active.contains_key(&thread_id)
        && runtime.execution_active.contains(&thread_id)
        && runtime.stalker.is_following_me()
    {
        runtime.stalker.deactivate();
        runtime.execution_active.remove(&thread_id);
    }
    Ok(())
}

fn backend_drain_due() -> Result<Vec<StalkerEventBatch>, String> {
    let slot = lock_runtime()?;
    slot.require_ready()?;
    let Some(runtime) = slot.runtime.as_ref() else {
        return Ok(Vec::new());
    };
    Ok(drain_due_runtime(runtime, Instant::now()))
}

fn backend_unfollow(thread_id: u64) -> Result<Vec<StalkerEventBatch>, String> {
    let mut slot = lock_runtime()?;
    slot.require_ready()?;
    let Some(runtime) = slot.runtime.as_mut() else {
        return Ok(Vec::new());
    };
    if runtime.pending.remove(&thread_id).is_some() {
        return Ok(Vec::new());
    }
    let Some(buffer) = runtime.active.remove(&thread_id) else {
        return Ok(Vec::new());
    };
    runtime.execution_active.remove(&thread_id);
    runtime.native_call_depth.remove(&thread_id);

    if thread_id == current_thread_id() {
        runtime.stalker.unfollow_me();
    } else {
        runtime.stalker.unfollow(thread_id as usize);
    }
    runtime.stalker.flush();
    runtime.retired.push(buffer);
    // Unfollowing the last thread is the safe point where anchors left over from
    // removed probes can finally go.
    prune_unused_call_probe_anchors(runtime);
    Ok(drain_runtime(runtime))
}

fn backend_flush() -> Result<Vec<StalkerEventBatch>, String> {
    let mut slot = lock_runtime()?;
    slot.require_ready()?;
    let Some(runtime) = slot.runtime.as_mut() else {
        return Ok(Vec::new());
    };
    runtime.stalker.flush();
    Ok(drain_runtime(runtime))
}

fn backend_garbage_collect() -> Result<StalkerDrainResult, String> {
    let mut slot = lock_runtime()?;
    slot.require_ready()?;
    let Some(runtime) = slot.runtime.as_mut() else {
        return Ok(StalkerDrainResult::default());
    };
    let pending = runtime.stalker.garbage_collect();
    let batches = drain_runtime(runtime);
    if !pending {
        runtime.retired.clear();
    }
    Ok(StalkerDrainResult { pending, batches })
}

fn backend_exclude(base: u64, size: u64) -> Result<(), String> {
    let size = usize::try_from(size).map_err(|_| "Stalker exclusion size is out of range".to_string())?;
    let mut slot = lock_runtime()?;
    let runtime = ensure_runtime(&mut slot)?;
    runtime
        .stalker
        .exclude(&MemoryRange::new(NativePointer(base as *mut c_void), size));
    Ok(())
}

fn backend_invalidate(thread_id: Option<u64>, address: u64) -> Result<(), String> {
    let mut slot = lock_runtime()?;
    let runtime = ensure_runtime(&mut slot)?;
    let current_execution_was_active = current_execution_is_active(runtime);
    let address = NativePointer(address as *mut c_void);
    match thread_id {
        Some(thread_id) => runtime.stalker.invalidate_for_thread(thread_id as usize, address),
        None => runtime.stalker.invalidate(address),
    }
    restore_current_execution_state(runtime, current_execution_was_active);
    Ok(())
}

fn current_execution_is_active(runtime: &StalkerRuntime) -> bool {
    runtime.execution_active.contains(&current_thread_id())
}

fn restore_current_execution_state(runtime: &mut StalkerRuntime, was_active: bool) {
    let thread_id = current_thread_id();
    if !was_active && runtime.active.contains_key(&thread_id) && runtime.stalker.is_following_me() {
        runtime.stalker.deactivate();
        runtime.execution_active.remove(&thread_id);
    }
}

fn address_is_in_range(address: u64, base: u64, size: usize) -> bool {
    address.wrapping_sub(base) < size as u64
}

fn retire_stalker_state_in_range(base: u64, size: usize, retired_hfollow_target: Option<u64>) -> Result<usize, String> {
    let mut slot = lock_runtime()?;
    let Some(runtime) = slot.runtime.as_mut() else {
        return Ok(0);
    };
    let anchors = runtime
        .call_probe_anchors
        .iter()
        .filter_map(|(&address, anchor)| address_is_in_range(address, base, size).then_some((address, anchor.gum_id)))
        .collect::<Vec<_>>();
    if anchors.is_empty() && retired_hfollow_target.is_none() {
        return Ok(0);
    }

    let current_execution_was_active = current_execution_is_active(runtime);
    for (address, gum_id) in &anchors {
        runtime.call_probe_anchors.remove(address);
        runtime.stalker.remove_call_probe(*gum_id);
    }
    if let Some(address) = retired_hfollow_target {
        let address = NativePointer(address as *mut c_void);
        for thread_id in runtime.active.keys().copied().collect::<Vec<_>>() {
            runtime.stalker.invalidate_for_thread(thread_id as usize, address);
        }
    }
    restore_current_execution_state(runtime, current_execution_was_active);
    Ok(anchors.len())
}

unsafe extern "C" fn call_probe_anchor_callback(_details: *mut c_void, _data: *mut c_void) {}

/// Which mapping currently owns `address`, or `None` for anonymous, JIT or
/// hidden mappings that Gum cannot attribute to a module.
fn module_identity_at(address: u64) -> Option<AnchorModuleIdentity> {
    let gum = retain_gum().ok()?;
    let process = frida_gum::Process::obtain(&gum);
    let module = process.find_module_by_address(address as usize)?;
    Some(AnchorModuleIdentity {
        base: module.range().base_address().0 as u64,
        path: module.path(),
    })
}

fn ensure_call_probe_anchor(runtime: &mut StalkerRuntime, target_address: u64) {
    let identity = module_identity_at(target_address);
    if let Some(existing) = runtime.call_probe_anchors.get(&target_address) {
        // An unattributed address cannot prove reuse either way, so keep the
        // anchor: dropping it would reintroduce the trailing-BRK problem below.
        if existing.module.is_none() || identity.is_none() || existing.module == identity {
            return;
        }
        log_msg(format!(
            "[stalker] call probe anchor at 0x{target_address:x} was reused by another module; rebuilding\n"
        ));
        let stale = runtime
            .call_probe_anchors
            .remove(&target_address)
            .expect("anchor was just looked up");
        runtime.stalker.remove_call_probe(stale.gum_id);
    }

    // Frida 17.15.5 on ARM64 may execute the trailing BRK of a block when the
    // last probe is removed while a call/ret sink is active. Keep the Gum code
    // shape stable; user probes are still removed normally and stop firing.
    let callback: NativeCallProbeCallback = unsafe { std::mem::transmute(call_probe_anchor_callback as *const ()) };
    let gum_id = unsafe {
        runtime
            .stalker
            .add_call_probe_native(NativePointer(target_address as *mut c_void), callback, null_mut())
    };
    runtime.call_probe_anchors.insert(
        target_address,
        CallProbeAnchor {
            gum_id,
            module: identity,
        },
    );
}

/// Drop anchors that no user probe needs any more.
///
/// Removing the last probe of a block while a thread is being followed can make
/// that thread execute the block's trailing BRK, so this only runs once no
/// thread is followed: at that point no compiled block can be re-entered before
/// Stalker rebuilds it.
fn prune_unused_call_probe_anchors(runtime: &mut StalkerRuntime) -> usize {
    if !runtime.active.is_empty() || !runtime.pending.is_empty() || runtime.stalker.is_following_me() {
        return 0;
    }
    let unused = runtime
        .call_probe_anchors
        .iter()
        .filter(|(address, _)| {
            !runtime
                .call_probes
                .values()
                .any(|probe| probe.target_address == **address)
        })
        .map(|(address, anchor)| (*address, anchor.gum_id))
        .collect::<Vec<_>>();
    for (address, gum_id) in &unused {
        runtime.call_probe_anchors.remove(address);
        runtime.stalker.remove_call_probe(*gum_id);
    }
    unused.len()
}

unsafe extern "C" fn call_probe_get_argument(opaque: usize, index: u32) -> u64 {
    let context = &*(opaque as *const frida_gum::CpuContext<'_>);
    context.arg(index) as u64
}

unsafe extern "C" fn call_probe_set_argument(opaque: usize, index: u32, value: u64) {
    let context = &mut *(opaque as *mut frida_gum::CpuContext<'_>);
    context.set_arg(index, value as usize);
}

fn backend_add_call_probe(config: StalkerCallProbeConfig) -> Result<(), String> {
    let mut slot = lock_runtime()?;
    let runtime = ensure_runtime(&mut slot)?;
    if runtime.call_probes.contains_key(&config.id) {
        return Err(format!("call probe {} already exists", config.id));
    }

    ensure_call_probe_anchor(runtime, config.target_address);
    let current_execution_was_active = current_execution_is_active(runtime);
    let (gum_id, state) = if config.native_callback != 0 {
        let callback: NativeCallProbeCallback = unsafe { std::mem::transmute(config.native_callback as usize) };
        let gum_id = unsafe {
            runtime.stalker.add_call_probe_native(
                NativePointer(config.target_address as *mut c_void),
                callback,
                config.native_data as usize as *mut c_void,
            )
        };
        (gum_id, None)
    } else {
        if config.context == 0 {
            return Err("JavaScript call probe requires a JavaScript context".to_string());
        }
        let state = Arc::new(CallProbeState {
            id: config.id,
            context: config.context,
        });
        let callback_state = Arc::clone(&state);
        let gum_id = runtime.stalker.add_call_probe(
            NativePointer(config.target_address as *mut c_void),
            move |mut details| {
                let mut cpu_context = details.cpu_context();
                quickjs_hook::dispatch_stalker_call_probe(
                    callback_state.context,
                    callback_state.id,
                    &mut cpu_context as *mut _ as usize,
                    call_probe_get_argument,
                    call_probe_set_argument,
                );
            },
        );
        (gum_id, Some(state))
    };
    restore_current_execution_state(runtime, current_execution_was_active);
    runtime.call_probes.insert(
        config.id,
        ActiveCallProbe {
            gum_id,
            target_address: config.target_address,
            state,
        },
    );
    Ok(())
}

fn backend_remove_call_probe(id: u32) -> Result<(), String> {
    let mut slot = lock_runtime()?;
    slot.require_ready()?;
    let Some(runtime) = slot.runtime.as_mut() else {
        return Ok(());
    };
    if let Some(probe) = runtime.call_probes.remove(&id) {
        let current_execution_was_active = current_execution_is_active(runtime);
        runtime.stalker.remove_call_probe(probe.gum_id);
        prune_unused_call_probe_anchors(runtime);
        restore_current_execution_state(runtime, current_execution_was_active);
        if let Some(state) = probe.state {
            runtime.retired_call_probes.push(state);
        }
    }
    Ok(())
}

/// Snapshot the backend's counters. Retired traces keep contributing their drop
/// counts so a `%reload` or unfollow cannot make dropped events disappear.
fn backend_statistics() -> Result<StalkerStatistics, String> {
    let slot = lock_runtime()?;
    let Some(runtime) = slot.runtime.as_ref() else {
        return Ok(StalkerStatistics::default());
    };

    let mut traces: Vec<StalkerTraceStatistics> = runtime.active.values().map(|buffer| buffer.statistics()).collect();
    traces.sort_by_key(|trace| trace.thread_id);
    let retired_dropped: u64 = runtime
        .retired
        .iter()
        .map(|buffer| buffer.statistics().dropped_events)
        .sum();

    Ok(StalkerStatistics {
        dropped_events: traces
            .iter()
            .map(|trace| trace.dropped_events)
            .sum::<u64>()
            .saturating_add(retired_dropped),
        active_traces: runtime.active.len() as u64,
        pending_traces: runtime.pending.len() as u64,
        retired_traces: runtime.retired.len() as u64,
        active_call_probes: runtime.call_probes.len() as u64,
        retired_call_probes: runtime.retired_call_probes.len() as u64,
        call_probe_anchors: runtime.call_probe_anchors.len() as u64,
        traces,
    })
}

fn backend_get_trust_threshold() -> Result<i32, String> {
    let mut slot = lock_runtime()?;
    Ok(ensure_runtime(&mut slot)?.stalker.get_trust_threshold())
}

fn backend_set_trust_threshold(value: i32) -> Result<(), String> {
    let mut slot = lock_runtime()?;
    ensure_runtime(&mut slot)?.stalker.set_trust_threshold(value);
    Ok(())
}

fn backend_shutdown() -> Result<bool, String> {
    let mut runtime = {
        let mut slot = lock_runtime()?;
        match slot.begin_shutdown()? {
            ShutdownStart::Started(runtime) => runtime,
            ShutdownStart::AlreadyStopped => return Ok(shutdown_hfollow()),
        }
    };

    if !stop_drain_worker(DRAIN_WORKER_STOP_TIMEOUT) {
        retain_failed_runtime(&mut runtime)?;
        log_msg("[stalker] periodic drain worker did not stop; keeping agent resident\n".to_string());
        return Ok(false);
    }

    let Some(active_runtime) = runtime.as_mut() else {
        let stopped = shutdown_hfollow();
        quickjs_hook::clear_retired_stalker_callouts();
        lock_runtime()?.finish_shutdown();
        return Ok(stopped);
    };

    active_runtime.stalker.stop();
    active_runtime.stalker.flush();
    active_runtime
        .retired
        .extend(active_runtime.active.drain().map(|(_, buffer)| buffer));
    let call_probe_states = active_runtime
        .call_probes
        .values()
        .filter_map(|probe| probe.state.as_ref().map(Arc::clone))
        .chain(active_runtime.retired_call_probes.iter().cloned())
        .collect::<Vec<_>>();

    let probe_wait_started = Instant::now();
    while call_probe_states.iter().any(|state| Arc::strong_count(state) > 2) {
        if probe_wait_started.elapsed() >= DRAIN_WORKER_STOP_TIMEOUT {
            retain_failed_runtime(&mut runtime)?;
            log_msg("[stalker] call probe lifetimes did not stop; keeping agent resident\n".to_string());
            return Ok(false);
        }
        crate::raw_thread::sleep_ms(1);
    }
    if !quickjs_hook::wait_for_stalker_call_probe_callbacks(DRAIN_WORKER_STOP_TIMEOUT) {
        retain_failed_runtime(&mut runtime)?;
        log_msg("[stalker] call probe callbacks did not stop; keeping agent resident\n".to_string());
        return Ok(false);
    }
    if !quickjs_hook::wait_for_stalker_transform_callbacks(DRAIN_WORKER_STOP_TIMEOUT) {
        retain_failed_runtime(&mut runtime)?;
        log_msg("[stalker] transform callbacks did not stop; keeping agent resident\n".to_string());
        return Ok(false);
    }
    if !quickjs_hook::wait_for_stalker_callout_callbacks(DRAIN_WORKER_STOP_TIMEOUT) {
        retain_failed_runtime(&mut runtime)?;
        log_msg("[stalker] callout callbacks did not stop; keeping agent resident\n".to_string());
        return Ok(false);
    }

    active_runtime.call_probes.clear();
    active_runtime.retired_call_probes.clear();

    let started = Instant::now();
    loop {
        let pending = active_runtime.stalker.garbage_collect();
        if !pending {
            active_runtime.retired.clear();
            break;
        }
        if started.elapsed() >= SHUTDOWN_GC_TIMEOUT {
            retain_failed_runtime(&mut runtime)?;
            log_msg("[stalker] garbage collection timed out; keeping agent resident\n".to_string());
            return Ok(false);
        }
        crate::raw_thread::sleep_ms(10);
    }

    drop(runtime);
    quickjs_hook::clear_retired_stalker_callouts();
    let stopped = shutdown_hfollow();
    lock_runtime()?.finish_shutdown();
    Ok(stopped)
}

pub fn install_quickjs_backend() -> Result<(), String> {
    lock_runtime()?.activate()?;
    install_module_unload_observer()?;
    quickjs_hook::install_stalker_backend(StalkerBackend {
        is_supported: backend_is_supported,
        follow: backend_follow,
        drain_due: backend_drain_due,
        unfollow: backend_unfollow,
        flush: backend_flush,
        garbage_collect: backend_garbage_collect,
        exclude: backend_exclude,
        invalidate: backend_invalidate,
        add_call_probe: backend_add_call_probe,
        remove_call_probe: backend_remove_call_probe,
        get_trust_threshold: backend_get_trust_threshold,
        set_trust_threshold: backend_set_trust_threshold,
        process_pending: backend_process_pending,
        activate_current: backend_activate_current,
        deactivate_current: backend_deactivate_current,
        shutdown: backend_shutdown,
        writer_enums: stalker_writer::writer_enums,
        statistics: backend_statistics,
    })
}

pub fn shutdown() -> bool {
    backend_shutdown().unwrap_or(false)
}

/// Drop callbacks tied to the current QuickJS runtime while keeping embedded
/// Gum/GLib initialized. Embedded GLib startup callbacks are process-global and
/// cannot be initialized a second time during an in-process script reload.
pub fn pause_module_unload_observer_for_reload() -> Result<(), String> {
    release_module_unload_observer()
}

pub fn shutdown_module_observer() -> Result<(), String> {
    release_module_unload_observer()?;
    release_gum()
}

pub fn follow(tid: usize) {
    let thread_id = if tid == 0 { current_thread_id() } else { tid as u64 };
    let config = StalkerFollowConfig {
        thread_id,
        event_mask: EventMask::Exec.bits(),
        queue_capacity: DEFAULT_QUEUE_CAPACITY,
        queue_drain_interval: DEFAULT_QUEUE_DRAIN_INTERVAL,
        transform: false,
        context: 0,
        native_event_callback: 0,
        native_event_data: 0,
        defer_current_thread: false,
    };
    match backend_follow(config) {
        Ok(()) => write_stream(format!("Stalker following thread {}", thread_id).as_bytes()),
        Err(error) => write_stream(format!("Stalker follow failed: {}", error).as_bytes()),
    }
}

pub fn unfollow(tid: usize) {
    let thread_id = if tid == 0 { current_thread_id() } else { tid as u64 };
    match backend_unfollow(thread_id) {
        Ok(batches) => {
            let events = batches
                .iter()
                .map(|batch| batch.data.len() / EVENT_RECORD_SIZE)
                .sum::<usize>();
            let _ = backend_garbage_collect();
            write_stream(format!("Stalker stopped thread {} ({} events)", thread_id, events).as_bytes());
        }
        Err(error) => write_stream(format!("Stalker stop failed: {}", error).as_bytes()),
    }
}

struct HfollowRuntime {
    interceptor: Interceptor,
    target: usize,
}

unsafe impl Send for HfollowRuntime {}

static HFOLLOW_RUNTIME: OnceLock<Mutex<Option<HfollowRuntime>>> = OnceLock::new();
static HFOLLOW_ORIGINAL: AtomicUsize = AtomicUsize::new(0);

pub extern "C" fn replacecb(arg1: usize) -> usize {
    let original = HFOLLOW_ORIGINAL.load(Ordering::Acquire);
    if original == 0 {
        return 0;
    }
    let original_fn: extern "C" fn(usize) -> usize = unsafe { std::mem::transmute(original) };
    original_fn(arg1)
}

pub extern "C" fn replacecc() {
    let _ = shutdown_hfollow();
}

fn shutdown_hfollow() -> bool {
    let state = HFOLLOW_RUNTIME.get_or_init(|| Mutex::new(None));
    let mut state = state.lock().unwrap_or_else(|error| error.into_inner());
    if let Some(mut runtime) = state.take() {
        if crate::linker::is_address_mapped(runtime.target) {
            runtime.interceptor.revert(NativePointer(runtime.target as *mut c_void));
        } else {
            let range = MemoryRange::new(NativePointer(runtime.target as *mut c_void), 1);
            frida_gum::discard_interceptor_hooks_in_range(&range);
        }
    }
    HFOLLOW_ORIGINAL.store(0, Ordering::Release);
    true
}

fn retire_hfollow_in_range(base: u64, size: usize) -> Option<u64> {
    let state = HFOLLOW_RUNTIME.get_or_init(|| Mutex::new(None));
    let mut state = state.lock().unwrap_or_else(|error| error.into_inner());
    let target = state.as_ref().map(|runtime| runtime.target)?;
    if !address_is_in_range(target as u64, base, size) {
        return None;
    }

    // Gum discards the native interceptor context before emitting
    // module-removed. Do not call revert: it resolves and decodes the target
    // before looking up the context, which would read unmapped code.
    drop(state.take().expect("hfollow runtime disappeared under lock"));
    HFOLLOW_ORIGINAL.store(0, Ordering::Release);
    Some(target as u64)
}

pub fn hfollow(_module: &str, addr: usize) {
    let state = HFOLLOW_RUNTIME.get_or_init(|| Mutex::new(None));
    let mut state = state.lock().unwrap_or_else(|error| error.into_inner());
    if let Some(mut old) = state.take() {
        if crate::linker::is_address_mapped(old.target) {
            old.interceptor.revert(NativePointer(old.target as *mut c_void));
        } else {
            let range = MemoryRange::new(NativePointer(old.target as *mut c_void), 1);
            frida_gum::discard_interceptor_hooks_in_range(&range);
        }
    }

    let gum = match retain_gum() {
        Ok(gum) => gum,
        Err(error) => {
            log_msg(format!("Frida Gum initialization failed: {error}"));
            return;
        }
    };
    let mut interceptor = Interceptor::obtain(&gum);
    match interceptor.replace(
        NativePointer(addr as *mut c_void),
        NativePointer(replacecb as *mut c_void),
        NativePointer(null_mut()),
    ) {
        Ok(original) => {
            HFOLLOW_ORIGINAL.store(original.0 as usize, Ordering::Release);
            *state = Some(HfollowRuntime {
                interceptor,
                target: addr,
            });
            log_msg(format!("Frida Interceptor replacement installed at 0x{addr:x}"));
        }
        Err(error) => log_msg(format!("Frida Interceptor replacement failed: {error:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_range_membership_handles_bounds_and_overflow() {
        assert!(address_is_in_range(0x1000, 0x1000, 0x100));
        assert!(address_is_in_range(0x10ff, 0x1000, 0x100));
        assert!(!address_is_in_range(0x1100, 0x1000, 0x100));
        assert!(!address_is_in_range(0x0fff, 0x1000, 0x100));
        assert!(address_is_in_range(u64::MAX, u64::MAX - 1, 2));
        assert!(!address_is_in_range(0, u64::MAX - 1, 2));
    }

    fn follow_config(thread_id: u64, queue_drain_interval: u32) -> StalkerFollowConfig {
        StalkerFollowConfig {
            thread_id,
            event_mask: EventMask::Exec.bits(),
            queue_capacity: 2,
            queue_drain_interval,
            transform: false,
            context: 0,
            native_event_callback: 0,
            native_event_data: 0,
            defer_current_thread: false,
        }
    }

    #[test]
    fn event_queue_stays_bounded_and_reuses_preallocated_storage() {
        let mut queue = EventQueue::with_capacity(2);
        let allocated_capacity = queue.current.capacity();
        let event = Event::Exec {
            location: NativePointer(0x1234usize as *mut c_void),
        };

        queue.push(&event);
        queue.push(&event);
        queue.push(&event);

        assert_eq!(queue.current.len(), 2 * EVENT_RECORD_SIZE);
        assert_eq!(queue.current.capacity(), allocated_capacity);

        let replacement = Vec::with_capacity(queue.byte_limit);
        let replacement_capacity = replacement.capacity();
        let batches = queue.drain(7, replacement);

        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].thread_id, 7);
        assert_eq!(batches[0].data.len(), 2 * EVENT_RECORD_SIZE);
        assert!(queue.current.is_empty());
        assert_eq!(queue.current.capacity(), replacement_capacity);

        let mut disabled_queue = EventQueue::with_capacity(0);
        disabled_queue.push(&event);
        assert!(disabled_queue.current.is_empty());
        assert_eq!(disabled_queue.current.capacity(), 0);
    }

    #[test]
    fn periodic_drain_respects_deadline_and_rearms() {
        let started = Instant::now();
        let buffer = TraceBuffer::new_at(follow_config(7, 50), started);
        let event = Event::Exec {
            location: NativePointer(0x1234usize as *mut c_void),
        };
        buffer
            .queue
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push(&event);

        assert_eq!(buffer.time_until_drain(started), Some(Duration::from_millis(50)));
        assert!(buffer.drain_if_due(started + Duration::from_millis(49)).is_empty());
        assert_eq!(buffer.drain_if_due(started + Duration::from_millis(50)).len(), 1);
        assert_eq!(
            buffer.time_until_drain(started + Duration::from_millis(50)),
            Some(Duration::from_millis(50))
        );
    }

    #[test]
    fn zero_drain_interval_disables_periodic_delivery() {
        let started = Instant::now();
        let buffer = TraceBuffer::new_at(follow_config(7, 0), started);
        assert_eq!(buffer.time_until_drain(started), None);
        assert!(buffer.drain_if_due(started + Duration::from_secs(1)).is_empty());
    }

    #[test]
    fn lifecycle_blocks_reentrant_api_while_shutdown_is_in_progress() {
        let mut slot = StalkerRuntimeSlot::default();
        assert!(slot.require_ready().is_ok());
        assert!(matches!(slot.begin_shutdown(), Ok(ShutdownStart::Started(None))));
        assert_eq!(slot.lifecycle, StalkerLifecycle::ShuttingDown);
        assert_eq!(slot.require_ready().unwrap_err(), "Stalker is shutting down");
        assert_eq!(slot.activate().unwrap_err(), "Stalker shutdown is still in progress");

        slot.finish_shutdown();
        assert_eq!(slot.lifecycle, StalkerLifecycle::Stopped);
        assert!(matches!(slot.begin_shutdown(), Ok(ShutdownStart::AlreadyStopped)));

        slot.activate().unwrap();
        assert_eq!(slot.lifecycle, StalkerLifecycle::Ready);
        assert!(slot.require_ready().is_ok());
    }

    #[test]
    fn failed_shutdown_retains_state_until_a_retry_completes() {
        let mut slot = StalkerRuntimeSlot::default();
        assert!(matches!(slot.begin_shutdown(), Ok(ShutdownStart::Started(None))));
        slot.retain_after_failed_shutdown(None);
        assert_eq!(slot.lifecycle, StalkerLifecycle::Retained);
        assert_eq!(slot.require_ready().unwrap_err(), "Stalker shutdown is incomplete");
        assert_eq!(
            slot.activate().unwrap_err(),
            "previous Stalker shutdown did not complete"
        );

        assert!(matches!(slot.begin_shutdown(), Ok(ShutdownStart::Started(None))));
        slot.finish_shutdown();
        assert_eq!(slot.lifecycle, StalkerLifecycle::Stopped);
    }
}
