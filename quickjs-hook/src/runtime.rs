//! JSRuntime wrapper

use crate::context::JSContext;
use crate::ffi;
use std::mem::MaybeUninit;
use std::ptr::NonNull;

/// Wrapper around QuickJS JSRuntime
pub struct JSRuntime {
    ptr: NonNull<ffi::JSRuntime>,
}

impl JSRuntime {
    /// Create a new JSRuntime
    pub fn new() -> Option<Self> {
        let ptr = unsafe { ffi::JS_NewRuntime() };
        NonNull::new(ptr).map(|ptr| {
            unsafe {
                ffi::JS_SetMemoryLimit(ptr.as_ptr(), 64 * 1024 * 1024);
                ffi::JS_SetInterruptHandler(
                    ptr.as_ptr(),
                    Some(crate::jsapi::callback_util::art_interrupt_handler),
                    std::ptr::null_mut(),
                );
            }
            JSRuntime { ptr }
        })
    }

    /// Create a new JSContext in this runtime
    pub fn new_context(&self) -> Option<JSContext> {
        JSContext::new(self)
    }

    /// Get the raw pointer
    pub fn as_ptr(&self) -> *mut ffi::JSRuntime {
        self.ptr.as_ptr()
    }

    /// Set memory limit in bytes
    pub fn set_memory_limit(&self, limit: usize) {
        unsafe {
            ffi::JS_SetMemoryLimit(self.ptr.as_ptr(), limit);
        }
    }

    /// Run garbage collection
    pub fn run_gc(&self) {
        unsafe {
            ffi::JS_RunGC(self.ptr.as_ptr());
        }
    }

    /// Set max stack size
    pub fn set_max_stack_size(&self, stack_size: usize) {
        unsafe {
            ffi::JS_SetMaxStackSize(self.ptr.as_ptr(), stack_size);
        }
    }
}

impl Drop for JSRuntime {
    fn drop(&mut self) {
        unsafe {
            ffi::JS_FreeRuntime(self.ptr.as_ptr());
        }
    }
}

// Safety: JSRuntime is protected by Mutex in the global JS_ENGINE, ensuring single-threaded access
unsafe impl Send for JSRuntime {}
unsafe impl Sync for JSRuntime {}

impl Default for JSRuntime {
    fn default() -> Self {
        Self::new().expect("Failed to create JSRuntime")
    }
}

#[repr(align(16))]
struct AlignedThreadState(MaybeUninit<ffi::JSRuntimeThreadState>);

/// Temporarily detaches the current native stack from a QuickJS runtime.
///
/// Frida uses this boundary before calling native code that may synchronously
/// re-enter JavaScript through Stalker or Interceptor callbacks.
pub(crate) struct SuspendedRuntime {
    runtime: *mut ffi::JSRuntime,
    state: AlignedThreadState,
    suspended: bool,
    cooperative: Option<crate::CooperativeJsCallbackGuard>,
}

impl SuspendedRuntime {
    /// `ctx` must belong to the runtime currently owned by this thread.
    pub(crate) unsafe fn suspend(ctx: *mut ffi::JSContext) -> Self {
        let runtime = ffi::JS_GetRuntime(ctx);
        let mut state = AlignedThreadState(MaybeUninit::uninit());
        ffi::JS_Suspend(runtime, state.0.as_mut_ptr());
        Self {
            runtime,
            state,
            suspended: true,
            cooperative: None,
        }
    }

    pub(crate) unsafe fn suspend_cooperatively(ctx: *mut ffi::JSContext) -> Self {
        let mut runtime = Self::suspend(ctx);
        runtime.cooperative = Some(crate::CooperativeJsCallbackGuard::begin());
        runtime
    }

    pub(crate) unsafe fn resume(&mut self) {
        if self.suspended {
            self.cooperative.take();
            ffi::JS_Resume(self.runtime, self.state.0.as_ptr());
            self.suspended = false;
        }
    }
}

impl Drop for SuspendedRuntime {
    fn drop(&mut self) {
        unsafe {
            self.resume();
        }
    }
}
