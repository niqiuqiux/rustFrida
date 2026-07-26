//! Gum-backed `MemoryAccessMonitor`.
//!
//! The frida-gum crate wrapper keeps its callback state on the stack, so this
//! goes straight to the sys API and owns the range array and the monitor for as
//! long as it is installed.

use frida_gum_sys as gum_sys;
use quickjs_hook::{dispatch_memory_access, MemoryAccessInfo, MemoryMonitorBackend};
use std::ffi::c_void;
use std::sync::Mutex;

struct MonitorState {
    monitor: *mut gum_sys::GumMemoryAccessMonitor,
    /// Gum's fault handler, held only while a monitor is installed.
    ///
    /// Obtaining it makes Gum claim SIGSEGV, which the agent otherwise
    /// deliberately leaves to ART's signal chain (see `crash_handler`). Doing it
    /// here rather than at startup keeps that claim scoped to scripts that
    /// actually ask for a monitor.
    exceptor: *mut c_void,
    /// Kept alive for the monitor's lifetime: Gum is handed a borrowed array.
    _ranges: Vec<gum_sys::GumMemoryRange>,
}

// The pointer is only used while holding MONITOR.
unsafe impl Send for MonitorState {}

static MONITOR: Mutex<Option<MonitorState>> = Mutex::new(None);

unsafe extern "C" fn on_access(
    _monitor: *mut gum_sys::GumMemoryAccessMonitor,
    details: *const gum_sys::GumMemoryAccessDetails,
    _user_data: *mut c_void,
) {
    if details.is_null() {
        return;
    }
    let details = &*details;
    dispatch_memory_access(MemoryAccessInfo {
        thread_id: details.thread_id,
        operation: details.operation,
        from: details.from as u64,
        address: details.address as u64,
        range_index: details.range_index,
        page_index: details.page_index,
        pages_completed: details.pages_completed,
        pages_total: details.pages_total,
    });
}

fn disable() -> Result<(), String> {
    let mut slot = MONITOR.lock().map_err(|_| "memory monitor lock poisoned".to_string())?;
    let Some(state) = slot.take() else {
        return Ok(());
    };
    unsafe {
        gum_sys::gum_memory_access_monitor_disable(state.monitor);
        gum_sys::g_object_unref(state.monitor as *mut c_void);
        // Releasing the last reference restores the previous SIGSEGV handler.
        if !state.exceptor.is_null() {
            gum_sys::g_object_unref(state.exceptor);
        }
    }
    Ok(())
}

fn enable(ranges: &[(u64, u64)], _context: usize) -> Result<(), String> {
    disable()?;

    let ranges: Vec<gum_sys::GumMemoryRange> = ranges
        .iter()
        .map(|(base, size)| gum_sys::GumMemoryRange {
            base_address: *base,
            size: *size as gum_sys::gsize,
        })
        .collect();

    let mut slot = MONITOR.lock().map_err(|_| "memory monitor lock poisoned".to_string())?;
    // The monitor reports accesses by removing page permissions and catching the
    // resulting faults, so Gum's exceptor has to be installed first.
    let exceptor = unsafe { gum_sys::gum_exceptor_obtain() };
    if exceptor.is_null() {
        return Err("Gum exceptor is unavailable, so faults cannot be caught".to_string());
    }
    let monitor = unsafe {
        gum_sys::gum_memory_access_monitor_new(
            ranges.as_ptr(),
            ranges.len() as u32,
            (gum_sys::_GumPageProtection_GUM_PAGE_READ
                | gum_sys::_GumPageProtection_GUM_PAGE_WRITE
                | gum_sys::_GumPageProtection_GUM_PAGE_EXECUTE) as gum_sys::GumPageProtection,
            gum_sys::true_ as i32,
            Some(on_access),
            std::ptr::null_mut(),
            None,
        )
    };
    if monitor.is_null() {
        unsafe { gum_sys::g_object_unref(exceptor as *mut c_void) };
        return Err("Gum refused to create the monitor".to_string());
    }

    let mut error: *mut gum_sys::GError = std::ptr::null_mut();
    let enabled = unsafe { gum_sys::gum_memory_access_monitor_enable(monitor, &mut error) };
    if enabled == 0 {
        let message = unsafe {
            if error.is_null() {
                "unknown error".to_string()
            } else {
                let text = std::ffi::CStr::from_ptr((*error).message)
                    .to_string_lossy()
                    .into_owned();
                gum_sys::_frida_g_error_free(error);
                text
            }
        };
        unsafe {
            gum_sys::g_object_unref(monitor as *mut c_void);
            gum_sys::g_object_unref(exceptor as *mut c_void);
        }
        return Err(message);
    }

    *slot = Some(MonitorState {
        monitor,
        exceptor: exceptor as *mut c_void,
        _ranges: ranges,
    });
    Ok(())
}

pub fn install_quickjs_backend() {
    quickjs_hook::install_memory_monitor_backend(MemoryMonitorBackend { enable, disable });
}
