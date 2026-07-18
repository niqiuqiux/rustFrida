/*
 * Copyright © 2020-2021 Keegan Saunders
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! Code tracing engine.
//!
//! More details about the Frida Stalker can be found on the [Stalker page](https://frida.re/docs/stalker/)
//! of the Frida documentation.
//!
//! The Rust interface to the Stalker provides a best-effort "safe" interface,
//! but naturally runtime code modification takes great caution and
//! these bindings cannot prevent all types of misbehaviour resulting in misuse
//! of the Stalker interface.
//!
//! # Examples
//! To trace the current thread with the Stalker, create a new [`Stalker`] and [`Transformer`] and call
//! [`Stalker::follow_me()`]:
//! ```
//! # use frida_gum::Gum;
//! # use frida_gum::stalker::{Stalker, Transformer};
//! #[cfg(feature = "event-sink")]
//! use frida_gum::stalker::NoneEventSink;
//! let gum = unsafe { Gum::obtain() };
//! let mut stalker = Stalker::new(&gum);
//!
//! let transformer = Transformer::from_callback(&gum, |basic_block, _output| {
//!     for instr in basic_block {
//!         instr.keep();
//!     }
//! });
//!
//! #[cfg(feature = "event-sink")]
//! stalker.follow_me::<NoneEventSink>(&transformer, None);
//!
//! #[cfg(not(feature = "event-sink"))]
//! stalker.follow_me(&transformer);
//!
//! stalker.unfollow_me();
//! ```

use {
    crate::{CpuContext, Gum, MemoryRange, NativePointer},
    core::{ffi::c_void, marker::PhantomData},
    frida_gum_sys as gum_sys,
};

#[cfg(not(feature = "std"))]
use alloc::boxed::Box;

#[cfg(feature = "std")]
use std::boxed::Box;

#[cfg(feature = "event-sink")]
mod event_sink;
#[cfg(feature = "event-sink")]
pub use event_sink::*;

mod transformer;
pub use transformer::*;

#[cfg(feature = "event-sink")]
#[cfg_attr(docsrs, doc(cfg(feature = "event-sink")))]
pub struct NoneEventSink;

#[cfg(feature = "event-sink")]
#[cfg_attr(docsrs, doc(cfg(feature = "event-sink")))]
impl EventSink for NoneEventSink {
    fn query_mask(&mut self) -> EventMask {
        unreachable!()
    }

    fn start(&mut self) {
        unreachable!()
    }

    fn process(&mut self, _event: &Event) {
        unreachable!()
    }

    fn flush(&mut self) {
        unreachable!()
    }

    fn stop(&mut self) {
        unreachable!()
    }
}

#[cfg(feature = "stalker-observer")]
mod observer;
#[cfg(feature = "stalker-observer")]
pub use observer::*;

/// Code tracing engine interface.
pub struct Stalker {
    stalker: *mut frida_gum_sys::GumStalker,
    _gum: Gum,
}

/// Details for a call observed by a Stalker call probe.
pub struct CallProbeDetails<'a> {
    details: *mut gum_sys::GumCallDetails,
    phantom: PhantomData<&'a mut gum_sys::GumCallDetails>,
}

/// Native callback invoked by a Stalker call probe.
///
/// `GumCallDetails` and the user-data pointer follow the same ABI as
/// `gum_stalker_add_call_probe()`.
pub type NativeCallProbeCallback = unsafe extern "C" fn(*mut gum_sys::GumCallDetails, *mut c_void);

impl CallProbeDetails<'_> {
    fn from_raw(details: *mut gum_sys::GumCallDetails) -> Self {
        Self {
            details,
            phantom: PhantomData,
        }
    }

    /// Address of the function being called.
    pub fn target_address(&self) -> NativePointer {
        NativePointer(unsafe { (*self.details).target_address })
    }

    /// Address where the called function will return.
    pub fn return_address(&self) -> NativePointer {
        NativePointer(unsafe { (*self.details).return_address })
    }

    /// Stack pointer at the call site.
    pub fn stack_data(&self) -> NativePointer {
        NativePointer(unsafe { (*self.details).stack_data })
    }

    /// Mutable processor state backing the call's arguments.
    pub fn cpu_context(&mut self) -> CpuContext<'_> {
        unsafe { CpuContext::from_raw((*self.details).cpu_context) }
    }
}

unsafe extern "C" fn call_probe_callback<F>(details: *mut gum_sys::GumCallDetails, user_data: *mut c_void)
where
    F: Fn(CallProbeDetails<'_>) + Send + Sync + 'static,
{
    if details.is_null() || user_data.is_null() {
        return;
    }
    let callback = &*(user_data as *const F);
    callback(CallProbeDetails::from_raw(details));
}

unsafe extern "C" fn call_probe_destroy<F>(user_data: *mut c_void)
where
    F: Fn(CallProbeDetails<'_>) + Send + Sync + 'static,
{
    if !user_data.is_null() {
        drop(Box::from_raw(user_data as *mut F));
    }
}

impl Stalker {
    /// Checks if the Stalker is supported on the current platform.
    pub fn is_supported(_gum: &Gum) -> bool {
        unsafe { frida_gum_sys::gum_stalker_is_supported() != 0 }
    }

    /// Create a new Stalker.
    ///
    /// This call has the overhead of checking if the Stalker is
    /// available on the current platform, as creating a Stalker on an
    /// unsupported platform results in unwanted behaviour.
    pub fn new(gum: &Gum) -> Stalker {
        assert!(Self::is_supported(gum));

        Stalker {
            stalker: unsafe { frida_gum_sys::gum_stalker_new() },
            _gum: gum.clone(),
        }
    }

    /// Create a new Stalker object from existing raw stalker pointer.
    pub fn from_raw(gum: &Gum, raw_stalker: *mut frida_gum_sys::GumStalker) -> Stalker {
        Stalker {
            stalker: raw_stalker,
            _gum: gum.clone(),
        }
    }

    /// Create a new Stalker with parameters
    ///
    /// This call has the overhead of checking if the Stalker is
    /// available on the current platform, as creating a Stalker on an
    /// unsupported platform results in unwanted behaviour.
    #[cfg(all(target_arch = "aarch64", feature = "stalker-params"))]
    pub fn new_with_params(gum: &Gum, ic_entries: u32) -> Stalker {
        assert!(Self::is_supported(gum));

        Stalker {
            stalker: unsafe { frida_gum_sys::gum_stalker_new_with_params(ic_entries) },
            _gum: gum.clone(),
        }
    }

    /// Create a new Stalker with parameters
    ///
    /// This call has the overhead of checking if the Stalker is
    /// available on the current platform, as creating a Stalker on an
    /// unsupported platform results in unwanted behaviour.
    #[cfg(all(target_arch = "x86_64", feature = "stalker-params"))]
    pub fn new_with_params(gum: &Gum, ic_entries: u32, adjacent_blocks: u32) -> Stalker {
        assert!(Self::is_supported(gum));

        Stalker {
            stalker: unsafe { frida_gum_sys::gum_stalker_new_with_params(ic_entries, adjacent_blocks) },
            _gum: gum.clone(),
        }
    }

    /// Get the underlying frida stalker object
    pub fn raw_stalker(&self) -> *mut frida_gum_sys::GumStalker {
        self.stalker
    }

    /// Exclude a range of address from the Stalker engine.
    ///
    /// This exclusion will prevent the Stalker from tracing into the memory range,
    /// reducing instrumentation overhead as well as potential noise from the [`EventSink`].
    pub fn exclude(&mut self, range: &MemoryRange) {
        unsafe { gum_sys::gum_stalker_exclude(self.stalker, &range.memory_range as *const _) };
    }

    /// Set how many times a piece of code needs to be executed before it is assumed it can be
    /// trusted to not mutate.
    ///
    /// Specify -1 for no trust (slow), 0 to trust code from the get-go,
    /// and N to trust code after it has been executed N times. Defaults to 1.
    pub fn set_trust_threshold(&mut self, threshold: i32) {
        unsafe { gum_sys::gum_stalker_set_trust_threshold(self.stalker, threshold) };
    }

    /// Get the Stalker trust treshold, see [`Stalker::set_trust_threshold()`] for more details.
    pub fn get_trust_threshold(&self) -> i32 {
        unsafe { gum_sys::gum_stalker_get_trust_threshold(self.stalker) }
    }

    /// Flush all buffered events.
    pub fn flush(&mut self) {
        unsafe { gum_sys::gum_stalker_flush(self.stalker) }
    }

    pub fn stop(&mut self) {
        unsafe { gum_sys::gum_stalker_stop(self.stalker) }
    }

    /// Free accumulated memory at a safe point after [`Stalker::unfollow_me()`].
    ///
    /// This is needed to avoid race-conditions where the thread just unfollowed is executing its last instructions.
    pub fn garbage_collect(&mut self) -> bool {
        unsafe { gum_sys::gum_stalker_garbage_collect(self.stalker) != 0 }
    }

    /// Begin the Stalker on the specific thread.
    ///
    /// A [`Transformer`] must be specified, and will be updated with all events.
    ///
    /// If reusing an existing [`Transformer`], make sure to call [`Stalker::garbage_collect()`]
    /// periodically.
    #[cfg(feature = "event-sink")]
    #[cfg_attr(docsrs, doc(cfg(feature = "event-sink")))]
    pub fn follow<S: EventSink>(&mut self, thread_id: usize, transformer: &Transformer, event_sink: Option<&mut S>) {
        use frida_gum_sys::GumThreadId;

        let sink = if let Some(sink) = event_sink {
            event_sink_transform(sink)
        } else {
            core::ptr::null_mut()
        };

        unsafe { gum_sys::gum_stalker_follow(self.stalker, thread_id as GumThreadId, transformer.transformer, sink) };
    }

    /// Begin tracing a thread with a sink whose lifetime is owned by Gum.
    ///
    /// This is the safe choice for long-lived tracing: the sink is destroyed only
    /// after Gum releases its final reference during unfollow/stop.
    #[cfg(feature = "event-sink")]
    pub fn follow_with_owned_sink<S: EventSink + 'static>(
        &mut self,
        thread_id: usize,
        transformer: Option<&Transformer>,
        event_sink: S,
    ) {
        use frida_gum_sys::GumThreadId;

        let sink = event_sink_transform_owned(event_sink);
        let transformer = transformer.map_or(core::ptr::null_mut(), |value| value.transformer);
        unsafe {
            gum_sys::gum_stalker_follow(self.stalker, thread_id as GumThreadId, transformer, sink);
            gum_sys::g_object_unref(sink as *mut c_void);
        }
    }

    /// Begin tracing a thread and deliver each event directly to a native
    /// callback instead of buffering it for a Rust/JavaScript consumer.
    ///
    /// # Safety
    ///
    /// `callback` and `data` must remain valid until the thread is unfollowed
    /// and Gum has finished releasing the event sink.
    #[cfg(feature = "event-sink")]
    pub unsafe fn follow_with_native_sink(
        &mut self,
        thread_id: usize,
        transformer: Option<&Transformer>,
        event_mask: EventMask,
        callback: NativeEventSinkCallback,
        data: *mut c_void,
    ) {
        use frida_gum_sys::GumThreadId;

        let sink = gum_sys::gum_event_sink_make_from_callback(event_mask.bits(), Some(callback), data, None);
        let transformer = transformer.map_or(core::ptr::null_mut(), |value| value.transformer);
        gum_sys::gum_stalker_follow(self.stalker, thread_id as GumThreadId, transformer, sink);
        gum_sys::g_object_unref(sink as *mut c_void);
    }

    /// Begin the Stalker on the current thread.
    ///
    /// A [`Transformer`] must be specified, and will be updated with all events.
    ///
    /// If reusing an existing [`Transformer`], make sure to call [`Stalker::garbage_collect()`]
    /// periodically.
    #[cfg(feature = "event-sink")]
    #[cfg_attr(docsrs, doc(cfg(feature = "event-sink")))]
    pub fn follow_me<S: EventSink>(&mut self, transformer: &Transformer, event_sink: Option<&mut S>) {
        let sink = if let Some(sink) = event_sink {
            event_sink_transform(sink)
        } else {
            core::ptr::null_mut()
        };

        unsafe { gum_sys::gum_stalker_follow_me(self.stalker, transformer.transformer, sink) };
    }

    /// Begin tracing the current thread with a sink whose lifetime is owned by Gum.
    #[cfg(feature = "event-sink")]
    pub fn follow_me_with_owned_sink<S: EventSink + 'static>(
        &mut self,
        transformer: Option<&Transformer>,
        event_sink: S,
    ) {
        let sink = event_sink_transform_owned(event_sink);
        let transformer = transformer.map_or(core::ptr::null_mut(), |value| value.transformer);
        unsafe {
            gum_sys::gum_stalker_follow_me(self.stalker, transformer, sink);
            gum_sys::g_object_unref(sink as *mut c_void);
        }
    }

    /// Begin tracing the current thread with synchronous native event
    /// delivery. See [`Stalker::follow_with_native_sink`] for safety rules.
    #[cfg(feature = "event-sink")]
    pub unsafe fn follow_me_with_native_sink(
        &mut self,
        transformer: Option<&Transformer>,
        event_mask: EventMask,
        callback: NativeEventSinkCallback,
        data: *mut c_void,
    ) {
        let sink = gum_sys::gum_event_sink_make_from_callback(event_mask.bits(), Some(callback), data, None);
        let transformer = transformer.map_or(core::ptr::null_mut(), |value| value.transformer);
        gum_sys::gum_stalker_follow_me(self.stalker, transformer, sink);
        gum_sys::g_object_unref(sink as *mut c_void);
    }

    /// Begin the Stalker on the current thread.
    ///
    /// A [`Transformer`] must be specified, and will be updated with all events.
    ///
    /// If reusing an existing [`Transformer`], make sure to call [`Stalker::garbage_collect()`]
    /// periodically.
    #[cfg(not(feature = "event-sink"))]
    #[cfg_attr(docsrs, doc(cfg(not(feature = "event-sink"))))]
    pub fn follow_me(&mut self, transformer: &Transformer) {
        unsafe { gum_sys::gum_stalker_follow_me(self.stalker, transformer.transformer, core::ptr::null_mut()) };
    }

    /// Stop stalking the specific thread.
    pub fn unfollow(&mut self, thread_id: usize) {
        use frida_gum_sys::GumThreadId;

        unsafe { gum_sys::gum_stalker_unfollow(self.stalker, thread_id as GumThreadId) };
    }

    /// Stop stalking the current thread.
    pub fn unfollow_me(&mut self) {
        unsafe { gum_sys::gum_stalker_unfollow_me(self.stalker) };
    }

    /// Check if the Stalker is running on the current thread.
    pub fn is_following_me(&mut self) -> bool {
        unsafe { gum_sys::gum_stalker_is_following_me(self.stalker) != 0 }
    }

    /// Re-activate the Stalker at the specified start point.
    pub fn activate(&mut self, start: NativePointer) {
        unsafe { gum_sys::gum_stalker_activate(self.stalker, start.0) }
    }

    /// Pause the Stalker.
    pub fn deactivate(&mut self) {
        unsafe { gum_sys::gum_stalker_deactivate(self.stalker) }
    }

    /// Invalidate a translated block for every followed thread.
    pub fn invalidate(&mut self, address: NativePointer) {
        unsafe { gum_sys::gum_stalker_invalidate(self.stalker, address.0) }
    }

    /// Invalidate a translated block for one followed thread.
    pub fn invalidate_for_thread(&mut self, thread_id: usize, address: NativePointer) {
        unsafe { gum_sys::gum_stalker_invalidate_for_thread(self.stalker, thread_id as _, address.0) }
    }

    /// Register a callback invoked whenever a followed thread calls `target`.
    pub fn add_call_probe<F>(&mut self, target: NativePointer, callback: F) -> u32
    where
        F: Fn(CallProbeDetails<'_>) + Send + Sync + 'static,
    {
        let user_data = Box::into_raw(Box::new(callback)) as *mut c_void;
        unsafe {
            gum_sys::gum_stalker_add_call_probe(
                self.stalker,
                target.0,
                Some(call_probe_callback::<F>),
                user_data,
                Some(call_probe_destroy::<F>),
            )
        }
    }

    /// Register a call probe whose callback is native code.
    ///
    /// # Safety
    ///
    /// `callback` and `data` must remain valid until the probe is removed and
    /// Gum has finished releasing translated blocks that reference it.
    pub unsafe fn add_call_probe_native(
        &mut self,
        target: NativePointer,
        callback: NativeCallProbeCallback,
        data: *mut c_void,
    ) -> u32 {
        gum_sys::gum_stalker_add_call_probe(self.stalker, target.0, Some(callback), data, None)
    }

    /// Remove a call probe previously returned by [`Stalker::add_call_probe`].
    pub fn remove_call_probe(&mut self, id: u32) {
        unsafe { gum_sys::gum_stalker_remove_call_probe(self.stalker, id) }
    }

    /// Enable (experimental) unwind hooking
    pub fn enable_unwind_hooking(&mut self) {
        unsafe { gum_sys::gum_stalker_activate_experimental_unwind_support() }
    }

    #[cfg(feature = "stalker-observer")]
    #[cfg_attr(docsrs, doc(cfg(feature = "stalker-observer")))]
    pub fn set_observer<O: StalkerObserver>(&mut self, observer: &mut O) {
        let obs = stalker_observer_transform(observer);
        unsafe {
            gum_sys::gum_stalker_set_observer(self.stalker, obs);
        }
    }
}

impl Drop for Stalker {
    fn drop(&mut self) {
        unsafe { gum_sys::g_object_unref(self.stalker as *mut c_void) };
    }
}

impl core::fmt::Debug for Stalker {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Stalker")
            .field("stalker", &self.stalker)
            .finish_non_exhaustive()
    }
}
