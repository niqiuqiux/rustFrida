/*
 * Copyright © 2020-2021 Keegan Saunders
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#![cfg_attr(any(target_arch = "x86_64", target_arch = "x86"), allow(clippy::unnecessary_cast))]

use {
    crate::NativePointer,
    core::{ffi::c_void, ops::BitOr},
    frida_gum_sys as gum_sys,
    gum_sys::_GumEvent as GumEvent,
};

#[cfg(not(feature = "std"))]
use alloc::boxed::Box;

/// Native Stalker event callback used by Frida's `onEvent` fast path.
///
/// The callback runs synchronously on the followed thread. Both the event and
/// CPU context pointers are borrowed from Gum and are only valid for the
/// duration of the callback.
pub type NativeEventSinkCallback =
    unsafe extern "C" fn(*const gum_sys::GumEvent, *mut gum_sys::GumCpuContext, *mut c_void);

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[repr(transparent)]
#[cfg_attr(docsrs, doc(cfg(feature = "event-sink")))]
pub struct EventMask(u32);

#[allow(non_upper_case_globals)]
impl EventMask {
    pub const None: Self = Self(gum_sys::_GumEventType_GUM_NOTHING as u32);
    pub const Call: Self = Self(gum_sys::_GumEventType_GUM_CALL as u32);
    pub const Ret: Self = Self(gum_sys::_GumEventType_GUM_RET as u32);
    pub const Exec: Self = Self(gum_sys::_GumEventType_GUM_EXEC as u32);
    pub const Block: Self = Self(gum_sys::_GumEventType_GUM_BLOCK as u32);
    pub const Compile: Self = Self(gum_sys::_GumEventType_GUM_COMPILE as u32);

    pub const fn from_bits(bits: u32) -> Self {
        Self(bits & 0x1f)
    }

    pub const fn bits(self) -> u32 {
        self.0
    }
}

impl BitOr for EventMask {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self::from_bits(self.bits() | rhs.bits())
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "event-sink")))]
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum Event {
    Call {
        location: NativePointer,
        target: NativePointer,
        depth: i32,
    },
    Ret {
        location: NativePointer,
        target: NativePointer,
        depth: i32,
    },
    Exec {
        location: NativePointer,
    },
    Block {
        start: NativePointer,
        end: NativePointer,
    },
    Compile {
        start: NativePointer,
        end: NativePointer,
    },
}

#[cfg_attr(docsrs, doc(cfg(feature = "event-sink")))]
impl From<GumEvent> for Event {
    fn from(event: GumEvent) -> Event {
        match unsafe { event.type_ } {
            value if value == EventMask::Call.bits() => {
                let call = unsafe { event.call };
                Event::Call {
                    location: NativePointer(call.location),
                    target: NativePointer(call.target),
                    depth: call.depth,
                }
            }
            value if value == EventMask::Ret.bits() => {
                let ret = unsafe { event.ret };
                Event::Ret {
                    location: NativePointer(ret.location),
                    target: NativePointer(ret.target),
                    depth: ret.depth,
                }
            }
            value if value == EventMask::Exec.bits() => {
                let exec = unsafe { event.exec };
                Event::Exec {
                    location: NativePointer(exec.location),
                }
            }
            value if value == EventMask::Block.bits() => {
                let block = unsafe { event.block };
                Event::Block {
                    start: NativePointer(block.start),
                    end: NativePointer(block.end),
                }
            }
            value if value == EventMask::Compile.bits() => {
                let compile = unsafe { event.compile };
                Event::Compile {
                    start: NativePointer(compile.start),
                    end: NativePointer(compile.end),
                }
            }
            _ => unreachable!(),
        }
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "event-sink")))]
pub trait EventSink {
    fn query_mask(&mut self) -> EventMask;
    fn start(&mut self);
    fn process(&mut self, event: &Event);
    fn flush(&mut self);
    fn stop(&mut self);
}

unsafe extern "C" fn call_start<S: EventSink>(user_data: *mut c_void) {
    let event_sink: &mut S = &mut *(user_data as *mut S);
    event_sink.start();
}

unsafe extern "C" fn call_process<S: EventSink>(user_data: *mut c_void, event: *const frida_gum_sys::GumEvent) {
    let event_sink: &mut S = &mut *(user_data as *mut S);
    event_sink.process(&(*event).into());
}

unsafe extern "C" fn call_flush<S: EventSink>(user_data: *mut c_void) {
    let event_sink: &mut S = &mut *(user_data as *mut S);
    event_sink.flush();
}

unsafe extern "C" fn call_stop<S: EventSink>(user_data: *mut c_void) {
    let event_sink: &mut S = &mut *(user_data as *mut S);
    event_sink.stop();
}

unsafe extern "C" fn call_query_mask<S: EventSink>(user_data: *mut c_void) -> frida_gum_sys::GumEventType {
    let event_sink: &mut S = &mut *(user_data as *mut S);
    event_sink.query_mask().bits()
}

unsafe extern "C" fn call_destroy<S: EventSink>(user_data: *mut c_void) {
    let _ = Box::from_raw(user_data as *mut S);
}

pub(crate) fn event_sink_transform<S: EventSink>(event_sink: &mut S) -> *mut frida_gum_sys::GumEventSink {
    let rust = frida_gum_sys::RustEventSinkVTable {
        user_data: event_sink as *mut _ as *mut c_void,
        query_mask: Some(call_query_mask::<S>),
        start: Some(call_start::<S>),
        process: Some(call_process::<S>),
        flush: Some(call_flush::<S>),
        stop: Some(call_stop::<S>),
        destroy: None,
    };

    unsafe { frida_gum_sys::gum_rust_event_sink_new(rust) }
}

pub(crate) fn event_sink_transform_owned<S: EventSink + 'static>(event_sink: S) -> *mut frida_gum_sys::GumEventSink {
    let user_data = Box::into_raw(Box::new(event_sink)) as *mut c_void;
    let rust = frida_gum_sys::RustEventSinkVTable {
        user_data,
        query_mask: Some(call_query_mask::<S>),
        start: Some(call_start::<S>),
        process: Some(call_process::<S>),
        flush: Some(call_flush::<S>),
        stop: Some(call_stop::<S>),
        destroy: Some(call_destroy::<S>),
    };

    unsafe { frida_gum_sys::gum_rust_event_sink_new(rust) }
}
