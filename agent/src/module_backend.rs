//! Gum-backed services for the Frida-compatible Module object model.

use frida_gum::Gum;
use frida_gum_sys as gum_sys;
use quickjs_hook::{
    ModuleBackend, ModuleDependencyDetails, ModuleDetails, ModuleIdentity, ModuleObserverEvent, ModuleSectionDetails,
    ProcessObserverBackend, ProcessThreadDetails, ThreadObserverEvent,
};
use std::ffi::{c_void, CStr, CString};
use std::mem;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

const OBSERVER_WORKER_POLL_MS: i64 = 10;
const OBSERVER_WORKER_STOP_TIMEOUT: Duration = Duration::from_millis(1_500);

fn c_string(value: &str, label: &str) -> Result<CString, String> {
    CString::new(value).map_err(|_| format!("{label} contains a NUL byte"))
}

unsafe fn optional_string(value: *const gum_sys::gchar) -> Option<String> {
    (!value.is_null()).then(|| CStr::from_ptr(value).to_string_lossy().into_owned())
}

unsafe fn module_details(module: *mut gum_sys::GumModule) -> Option<ModuleDetails> {
    if module.is_null() {
        return None;
    }
    let name = optional_string(gum_sys::gum_module_get_name(module))?;
    let path = optional_string(gum_sys::gum_module_get_path(module))?;
    let range = gum_sys::gum_module_get_range(module);
    if range.is_null() {
        return None;
    }
    Some(ModuleDetails {
        name,
        version: optional_string(gum_sys::gum_module_get_version(module)),
        path,
        base: (*range).base_address,
        size: (*range).size as u64,
    })
}

unsafe extern "C" fn collect_module(
    module: *mut gum_sys::GumModule,
    user_data: gum_sys::gpointer,
) -> gum_sys::gboolean {
    if let Some(details) = module_details(module) {
        (&mut *(user_data as *mut Vec<ModuleDetails>)).push(details);
    }
    1
}

fn enumerate_modules() -> Vec<ModuleDetails> {
    let mut modules: Vec<ModuleDetails> = Vec::new();
    unsafe {
        gum_sys::gum_process_enumerate_modules(Some(collect_module), &mut modules as *mut Vec<ModuleDetails> as *mut _);
    }
    modules.sort_by_key(|module| module.base);
    modules
}

fn find_global_export_by_name(symbol: &str) -> Result<Option<u64>, String> {
    let symbol = c_string(symbol, "symbol name")?;
    let address = unsafe { gum_sys::gum_module_find_global_export_by_name(symbol.as_ptr()) };
    Ok((address != 0).then_some(address))
}

struct OwnedModule(*mut gum_sys::GumModule);

impl Drop for OwnedModule {
    fn drop(&mut self) {
        unsafe {
            gum_sys::g_object_unref(self.0.cast());
        }
    }
}

fn find_module(identity: &ModuleIdentity) -> Result<OwnedModule, String> {
    let path = c_string(&identity.path, "module path")?;
    let name = c_string(&identity.name, "module name")?;
    let mut module = unsafe { gum_sys::gum_process_find_module_by_name(path.as_ptr()) };
    if module.is_null() {
        module = unsafe { gum_sys::gum_process_find_module_by_name(name.as_ptr()) };
    }
    if module.is_null() {
        module = unsafe { gum_sys::gum_process_find_module_by_address(identity.base) };
    }
    if module.is_null() {
        return Err("module is no longer present in Gum's registry".to_string());
    }

    let owned = OwnedModule(module);
    let actual = unsafe { module_details(owned.0) }.ok_or_else(|| "unable to inspect Gum module".to_string())?;
    if actual.base != identity.base || actual.path != identity.path {
        return Err("Gum module identity does not match the requested instance".to_string());
    }
    Ok(owned)
}

fn ensure_initialized(identity: &ModuleIdentity) -> Result<(), String> {
    let module = find_module(identity)?;
    unsafe {
        gum_sys::gum_module_ensure_initialized(module.0);
    }
    Ok(())
}

unsafe extern "C" fn collect_section(
    details: *const gum_sys::GumSectionDetails,
    user_data: gum_sys::gpointer,
) -> gum_sys::gboolean {
    if details.is_null() {
        return 1;
    }
    let details = &*details;
    let Some(id) = optional_string(details.id) else {
        return 1;
    };
    let Some(name) = optional_string(details.name) else {
        return 1;
    };
    (&mut *(user_data as *mut Vec<ModuleSectionDetails>)).push(ModuleSectionDetails {
        id,
        name,
        address: details.address,
        size: details.size as u64,
    });
    1
}

fn enumerate_sections(identity: &ModuleIdentity) -> Result<Vec<ModuleSectionDetails>, String> {
    let module = find_module(identity)?;
    let mut sections = Vec::new();
    unsafe {
        gum_sys::gum_module_enumerate_sections(
            module.0,
            Some(collect_section),
            &mut sections as *mut Vec<ModuleSectionDetails> as *mut _,
        );
    }
    Ok(sections)
}

fn dependency_kind(kind: gum_sys::GumDependencyType) -> &'static str {
    match kind {
        gum_sys::GumDependencyType_GUM_DEPENDENCY_WEAK => "weak",
        gum_sys::GumDependencyType_GUM_DEPENDENCY_REEXPORT => "reexport",
        gum_sys::GumDependencyType_GUM_DEPENDENCY_UPWARD => "upward",
        _ => "regular",
    }
}

unsafe extern "C" fn collect_dependency(
    details: *const gum_sys::GumDependencyDetails,
    user_data: gum_sys::gpointer,
) -> gum_sys::gboolean {
    if details.is_null() {
        return 1;
    }
    let details = &*details;
    let Some(name) = optional_string(details.name) else {
        return 1;
    };
    (&mut *(user_data as *mut Vec<ModuleDependencyDetails>)).push(ModuleDependencyDetails {
        name,
        kind: dependency_kind(details.type_).to_string(),
    });
    1
}

fn enumerate_dependencies(identity: &ModuleIdentity) -> Result<Vec<ModuleDependencyDetails>, String> {
    let module = find_module(identity)?;
    let mut dependencies = Vec::new();
    unsafe {
        gum_sys::gum_module_enumerate_dependencies(
            module.0,
            Some(collect_dependency),
            &mut dependencies as *mut Vec<ModuleDependencyDetails> as *mut _,
        );
    }
    Ok(dependencies)
}

fn find_symbol_by_name(identity: &ModuleIdentity, symbol: &str) -> Result<Option<u64>, String> {
    let module = find_module(identity)?;
    let symbol = c_string(symbol, "symbol name")?;
    let address = unsafe { gum_sys::gum_module_find_symbol_by_name(module.0, symbol.as_ptr()) };
    Ok((address != 0).then_some(address))
}

struct ModuleObserverSubscription {
    registry: usize,
    added_handler: gum_sys::gulong,
    removed_handler: gum_sys::gulong,
    _gum: Gum,
}

unsafe impl Send for ModuleObserverSubscription {}

impl Drop for ModuleObserverSubscription {
    fn drop(&mut self) {
        let registry = self.registry as *mut gum_sys::GumModuleRegistry;
        if registry.is_null() {
            return;
        }
        if self.added_handler != 0 {
            unsafe {
                gum_sys::_frida_g_signal_handler_disconnect(registry.cast(), self.added_handler);
            }
            self.added_handler = 0;
        }
        if self.removed_handler != 0 {
            unsafe {
                gum_sys::_frida_g_signal_handler_disconnect(registry.cast(), self.removed_handler);
            }
            self.removed_handler = 0;
        }
    }
}

struct ThreadObserverSubscription {
    registry: usize,
    added_handler: gum_sys::gulong,
    removed_handler: gum_sys::gulong,
    renamed_handler: gum_sys::gulong,
    _gum: Gum,
}

unsafe impl Send for ThreadObserverSubscription {}

impl Drop for ThreadObserverSubscription {
    fn drop(&mut self) {
        let registry = self.registry as *mut gum_sys::GumThreadRegistry;
        if registry.is_null() {
            return;
        }
        for handler in [
            &mut self.added_handler,
            &mut self.removed_handler,
            &mut self.renamed_handler,
        ] {
            if *handler != 0 {
                unsafe {
                    gum_sys::_frida_g_signal_handler_disconnect(registry.cast(), *handler);
                }
                *handler = 0;
            }
        }
    }
}

static MODULE_OBSERVER: OnceLock<Mutex<Option<ModuleObserverSubscription>>> = OnceLock::new();
static THREAD_OBSERVER: OnceLock<Mutex<Option<ThreadObserverSubscription>>> = OnceLock::new();
static OBSERVER_WORKER_STOP: AtomicBool = AtomicBool::new(true);
static OBSERVER_WORKER_RUNNING: AtomicBool = AtomicBool::new(false);
static OBSERVER_WORKER_TID: AtomicI32 = AtomicI32::new(0);
static OBSERVER_CALLBACKS_IN_FLIGHT: AtomicUsize = AtomicUsize::new(0);

struct ObserverCallbackGuard;

impl ObserverCallbackGuard {
    fn enter() -> Self {
        OBSERVER_CALLBACKS_IN_FLIGHT.fetch_add(1, Ordering::AcqRel);
        Self
    }
}

impl Drop for ObserverCallbackGuard {
    fn drop(&mut self) {
        OBSERVER_CALLBACKS_IN_FLIGHT.fetch_sub(1, Ordering::AcqRel);
    }
}

fn module_observer_slot() -> &'static Mutex<Option<ModuleObserverSubscription>> {
    MODULE_OBSERVER.get_or_init(|| Mutex::new(None))
}

fn thread_observer_slot() -> &'static Mutex<Option<ThreadObserverSubscription>> {
    THREAD_OBSERVER.get_or_init(|| Mutex::new(None))
}

fn observer_worker_loop() {
    let _raw_clone_js = quickjs_hook::mark_raw_clone_js_thread();
    let mut error_reported = false;
    while !OBSERVER_WORKER_STOP.load(Ordering::Acquire) {
        match quickjs_hook::try_dispatch_process_observer_events() {
            Ok(true) => error_reported = false,
            Ok(false) => crate::raw_thread::sleep_ms(OBSERVER_WORKER_POLL_MS),
            Err(error) => {
                if !error_reported {
                    crate::communication::log_msg(format!("[process observer] dispatch failed: {error}\n"));
                    error_reported = true;
                }
                crate::raw_thread::sleep_ms(OBSERVER_WORKER_POLL_MS);
            }
        }
    }
    OBSERVER_WORKER_TID.store(0, Ordering::Release);
    OBSERVER_WORKER_RUNNING.store(false, Ordering::Release);
}

fn task_exists(tid: i32) -> bool {
    tid > 0 && std::path::Path::new(&format!("/proc/self/task/{tid}")).exists()
}

fn start_observer_worker() -> Result<(), String> {
    let tid = OBSERVER_WORKER_TID.load(Ordering::Acquire);
    if OBSERVER_WORKER_RUNNING.load(Ordering::Acquire) && task_exists(tid) {
        OBSERVER_WORKER_STOP.store(false, Ordering::Release);
        return Ok(());
    }
    OBSERVER_WORKER_STOP.store(false, Ordering::Release);
    OBSERVER_WORKER_RUNNING.store(true, Ordering::Release);
    match crate::raw_thread::spawn_detached(b"wwb-process-observer\0", observer_worker_loop) {
        Ok(tid) => {
            OBSERVER_WORKER_TID.store(tid, Ordering::Release);
            Ok(())
        }
        Err(error) => {
            OBSERVER_WORKER_STOP.store(true, Ordering::Release);
            OBSERVER_WORKER_RUNNING.store(false, Ordering::Release);
            Err(format!("failed to start process observer worker: {error}"))
        }
    }
}

fn stop_observer_worker() -> Result<(), String> {
    OBSERVER_WORKER_STOP.store(true, Ordering::Release);
    let tid = OBSERVER_WORKER_TID.load(Ordering::Acquire);
    if tid <= 0 || tid == unsafe { libc::syscall(libc::SYS_gettid) as i32 } {
        return Ok(());
    }
    let started = Instant::now();
    while OBSERVER_WORKER_RUNNING.load(Ordering::Acquire) && task_exists(tid) {
        if started.elapsed() >= OBSERVER_WORKER_STOP_TIMEOUT {
            return Err("process observer worker did not stop".to_string());
        }
        crate::raw_thread::sleep_ms(5);
    }
    OBSERVER_WORKER_TID.store(0, Ordering::Release);
    OBSERVER_WORKER_RUNNING.store(false, Ordering::Release);
    Ok(())
}

fn stop_observer_worker_if_idle() -> Result<(), String> {
    let modules_active = module_observer_slot()
        .lock()
        .map_err(|_| "module observer lock poisoned".to_string())?
        .is_some();
    let threads_active = thread_observer_slot()
        .lock()
        .map_err(|_| "thread observer lock poisoned".to_string())?
        .is_some();
    if modules_active || threads_active {
        Ok(())
    } else {
        stop_observer_worker()
    }
}

fn wait_observer_callbacks() -> Result<(), String> {
    let started = Instant::now();
    while OBSERVER_CALLBACKS_IN_FLIGHT.load(Ordering::Acquire) != 0 {
        if started.elapsed() >= OBSERVER_WORKER_STOP_TIMEOUT {
            return Err("process observer native callbacks did not drain".to_string());
        }
        crate::raw_thread::sleep_ms(1);
    }
    Ok(())
}

fn thread_state_name(state: gum_sys::GumThreadState) -> String {
    match state {
        gum_sys::GumThreadState_GUM_THREAD_RUNNING => "running",
        gum_sys::GumThreadState_GUM_THREAD_STOPPED => "stopped",
        gum_sys::GumThreadState_GUM_THREAD_WAITING => "waiting",
        gum_sys::GumThreadState_GUM_THREAD_UNINTERRUPTIBLE => "uninterruptible",
        gum_sys::GumThreadState_GUM_THREAD_HALTED => "halted",
        _ => "unknown",
    }
    .to_string()
}

unsafe fn thread_details(details: *const gum_sys::GumThreadDetails) -> Option<ProcessThreadDetails> {
    if details.is_null() {
        return None;
    }
    let details = &*details;
    Some(ProcessThreadDetails {
        id: details.id as u64,
        name: optional_string(details.name),
        state: thread_state_name(details.state),
    })
}

unsafe extern "C" fn collect_thread(
    details: *const gum_sys::GumThreadDetails,
    user_data: gum_sys::gpointer,
) -> gum_sys::gboolean {
    if let Some(details) = thread_details(details) {
        (&mut *(user_data as *mut Vec<ProcessThreadDetails>)).push(details);
    }
    1
}

unsafe extern "C" fn module_added(
    _registry: *mut gum_sys::GumModuleRegistry,
    module: *mut gum_sys::GumModule,
    _user_data: *mut c_void,
) {
    let _guard = ObserverCallbackGuard::enter();
    if let Some(details) = module_details(module) {
        quickjs_hook::queue_module_observer_event(ModuleObserverEvent::Added(details));
    }
}

unsafe extern "C" fn module_removed(
    _registry: *mut gum_sys::GumModuleRegistry,
    module: *mut gum_sys::GumModule,
    _user_data: *mut c_void,
) {
    let _guard = ObserverCallbackGuard::enter();
    if let Some(details) = module_details(module) {
        quickjs_hook::queue_module_observer_event(ModuleObserverEvent::Removed(details));
    }
}

unsafe extern "C" fn thread_added(
    _registry: *mut gum_sys::GumThreadRegistry,
    details: *const gum_sys::GumThreadDetails,
    _user_data: *mut c_void,
) {
    let _guard = ObserverCallbackGuard::enter();
    if let Some(details) = thread_details(details) {
        quickjs_hook::queue_thread_observer_event(ThreadObserverEvent::Added(details));
    }
}

unsafe extern "C" fn thread_removed(
    _registry: *mut gum_sys::GumThreadRegistry,
    details: *const gum_sys::GumThreadDetails,
    _user_data: *mut c_void,
) {
    let _guard = ObserverCallbackGuard::enter();
    if let Some(details) = thread_details(details) {
        quickjs_hook::queue_thread_observer_event(ThreadObserverEvent::Removed(details));
    }
}

unsafe extern "C" fn thread_renamed(
    _registry: *mut gum_sys::GumThreadRegistry,
    details: *const gum_sys::GumThreadDetails,
    previous_name: *const gum_sys::gchar,
    _user_data: *mut c_void,
) {
    let _guard = ObserverCallbackGuard::enter();
    if let Some(details) = thread_details(details) {
        quickjs_hook::queue_thread_observer_event(ThreadObserverEvent::Renamed {
            thread: details,
            previous_name: optional_string(previous_name),
        });
    }
}

unsafe fn signal_handler<T>(handler: T) -> gum_sys::GCallback
where
    T: Copy,
{
    Some(mem::transmute_copy(&handler))
}

fn attach_module_observer() -> Result<Vec<ModuleDetails>, String> {
    let mut slot = module_observer_slot()
        .lock()
        .map_err(|_| "module observer lock poisoned".to_string())?;
    if slot.is_some() {
        return Ok(enumerate_modules());
    }
    let gum = Gum::obtain();
    let registry = unsafe { gum_sys::gum_module_registry_obtain() };
    if registry.is_null() {
        return Err("Gum module registry is unavailable".to_string());
    }
    let mut modules: Vec<ModuleDetails> = Vec::new();
    unsafe {
        gum_sys::gum_module_registry_lock(registry);
        let added_handler = gum_sys::_frida_g_signal_connect_data(
            registry.cast(),
            c"module-added".as_ptr(),
            signal_handler(module_added as unsafe extern "C" fn(_, _, _)),
            std::ptr::null_mut(),
            None,
            0,
        );
        let removed_handler = gum_sys::_frida_g_signal_connect_data(
            registry.cast(),
            c"module-removed".as_ptr(),
            signal_handler(module_removed as unsafe extern "C" fn(_, _, _)),
            std::ptr::null_mut(),
            None,
            0,
        );
        if added_handler != 0 && removed_handler != 0 {
            gum_sys::gum_module_registry_enumerate_modules(
                registry,
                Some(collect_module),
                &mut modules as *mut Vec<ModuleDetails> as *mut _,
            );
        }
        gum_sys::gum_module_registry_unlock(registry);
        if added_handler == 0 || removed_handler == 0 {
            if added_handler != 0 {
                gum_sys::_frida_g_signal_handler_disconnect(registry.cast(), added_handler);
            }
            if removed_handler != 0 {
                gum_sys::_frida_g_signal_handler_disconnect(registry.cast(), removed_handler);
            }
            return Err("failed to subscribe to Gum module registry".to_string());
        }
        *slot = Some(ModuleObserverSubscription {
            registry: registry as usize,
            added_handler,
            removed_handler,
            _gum: gum,
        });
    }
    modules.sort_by_key(|module| module.base);
    Ok(modules)
}

fn detach_module_observer() -> Result<(), String> {
    let mut slot = module_observer_slot()
        .lock()
        .map_err(|_| "module observer lock poisoned".to_string())?;
    *slot = None;
    drop(slot);
    wait_observer_callbacks()?;
    stop_observer_worker_if_idle()
}

fn attach_thread_observer() -> Result<Vec<ProcessThreadDetails>, String> {
    let mut slot = thread_observer_slot()
        .lock()
        .map_err(|_| "thread observer lock poisoned".to_string())?;
    if slot.is_some() {
        let mut threads: Vec<ProcessThreadDetails> = Vec::new();
        unsafe {
            gum_sys::gum_process_enumerate_threads(
                Some(collect_thread),
                &mut threads as *mut Vec<ProcessThreadDetails> as *mut _,
                gum_sys::GumThreadFlags_GUM_THREAD_FLAGS_ALL,
            );
        }
        threads.sort_by_key(|thread| thread.id);
        return Ok(threads);
    }
    let gum = Gum::obtain();
    let registry = unsafe { gum_sys::gum_thread_registry_obtain() };
    if registry.is_null() {
        return Err("Gum thread registry is unavailable".to_string());
    }
    let mut threads: Vec<ProcessThreadDetails> = Vec::new();
    unsafe {
        gum_sys::gum_thread_registry_lock(registry);
        let added_handler = gum_sys::_frida_g_signal_connect_data(
            registry.cast(),
            c"thread-added".as_ptr(),
            signal_handler(thread_added as unsafe extern "C" fn(_, _, _)),
            std::ptr::null_mut(),
            None,
            0,
        );
        let removed_handler = gum_sys::_frida_g_signal_connect_data(
            registry.cast(),
            c"thread-removed".as_ptr(),
            signal_handler(thread_removed as unsafe extern "C" fn(_, _, _)),
            std::ptr::null_mut(),
            None,
            0,
        );
        let renamed_handler = gum_sys::_frida_g_signal_connect_data(
            registry.cast(),
            c"thread-renamed".as_ptr(),
            signal_handler(thread_renamed as unsafe extern "C" fn(_, _, _, _)),
            std::ptr::null_mut(),
            None,
            0,
        );
        if added_handler != 0 && removed_handler != 0 && renamed_handler != 0 {
            gum_sys::gum_thread_registry_enumerate_threads(
                registry,
                Some(collect_thread),
                &mut threads as *mut Vec<ProcessThreadDetails> as *mut _,
            );
        }
        gum_sys::gum_thread_registry_unlock(registry);
        if added_handler == 0 || removed_handler == 0 || renamed_handler == 0 {
            for handler in [added_handler, removed_handler, renamed_handler] {
                if handler != 0 {
                    gum_sys::_frida_g_signal_handler_disconnect(registry.cast(), handler);
                }
            }
            return Err("failed to subscribe to Gum thread registry".to_string());
        }
        *slot = Some(ThreadObserverSubscription {
            registry: registry as usize,
            added_handler,
            removed_handler,
            renamed_handler,
            _gum: gum,
        });
    }
    threads.sort_by_key(|thread| thread.id);
    Ok(threads)
}

fn detach_thread_observer() -> Result<(), String> {
    let mut slot = thread_observer_slot()
        .lock()
        .map_err(|_| "thread observer lock poisoned".to_string())?;
    *slot = None;
    drop(slot);
    wait_observer_callbacks()?;
    stop_observer_worker_if_idle()
}

pub fn install_quickjs_backend() {
    quickjs_hook::install_module_backend(ModuleBackend {
        enumerate_modules,
        find_global_export_by_name,
        ensure_initialized,
        enumerate_sections,
        enumerate_dependencies,
        find_symbol_by_name,
    });
    quickjs_hook::install_process_observer_backend(ProcessObserverBackend {
        attach_module_observer,
        detach_module_observer,
        attach_thread_observer,
        detach_thread_observer,
        start_dispatcher: start_observer_worker,
    });
}
