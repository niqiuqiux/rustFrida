/*
 * Copyright (C) 2026 rustFrida contributors
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

use {
    crate::{Gum, MemoryRange},
    core::{ffi::c_void, mem},
    frida_gum_sys as gum_sys,
};

#[cfg(not(feature = "std"))]
use alloc::boxed::Box;

#[cfg(feature = "std")]
use std::boxed::Box;

/// Subscription to Gum's process-wide module removal notifications.
pub struct ModuleRegistryObserver {
    registry: *mut gum_sys::GumModuleRegistry,
    handler_id: gum_sys::gulong,
    _gum: Gum,
}

unsafe impl Send for ModuleRegistryObserver {}

impl ModuleRegistryObserver {
    /// Observe modules immediately before Gum reports that their mappings have
    /// been removed from the process module registry.
    pub fn on_removed<F>(gum: &Gum, callback: F) -> Option<Self>
    where
        F: Fn(MemoryRange) + Send + Sync + 'static,
    {
        let callback = Box::into_raw(Box::new(callback));
        let registry = unsafe { gum_sys::gum_module_registry_obtain() };
        if registry.is_null() {
            unsafe { drop(Box::from_raw(callback)) };
            return None;
        }

        let handler = unsafe {
            mem::transmute::<
                unsafe extern "C" fn(*mut gum_sys::GumModuleRegistry, *mut gum_sys::GumModule, *mut c_void),
                unsafe extern "C" fn(),
            >(module_removed::<F>)
        };
        let handler_id = unsafe {
            gum_sys::_frida_g_signal_connect_data(
                registry.cast(),
                c"module-removed".as_ptr(),
                Some(handler),
                callback.cast(),
                Some(destroy_callback::<F>),
                0,
            )
        };
        if handler_id == 0 {
            unsafe { drop(Box::from_raw(callback)) };
            return None;
        }

        Some(Self {
            registry,
            handler_id,
            _gum: gum.clone(),
        })
    }
}

impl Drop for ModuleRegistryObserver {
    fn drop(&mut self) {
        if self.handler_id != 0 && !self.registry.is_null() {
            unsafe {
                gum_sys::_frida_g_signal_handler_disconnect(self.registry.cast(), self.handler_id);
            }
            self.handler_id = 0;
        }
    }
}

unsafe extern "C" fn module_removed<F>(
    _registry: *mut gum_sys::GumModuleRegistry,
    module: *mut gum_sys::GumModule,
    user_data: *mut c_void,
) where
    F: Fn(MemoryRange) + Send + Sync + 'static,
{
    if module.is_null() || user_data.is_null() {
        return;
    }
    let range = gum_sys::gum_module_get_range(module);
    if range.is_null() {
        return;
    }
    let callback = &*(user_data as *const F);
    callback(MemoryRange::from_raw(range));
}

unsafe extern "C" fn destroy_callback<F>(user_data: *mut c_void, _closure: *mut gum_sys::GClosure)
where
    F: Fn(MemoryRange) + Send + Sync + 'static,
{
    if !user_data.is_null() {
        drop(Box::from_raw(user_data as *mut F));
    }
}
