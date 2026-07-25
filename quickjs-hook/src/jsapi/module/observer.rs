const PROCESS_OBSERVER_QUEUE_CAPACITY: usize = 4096;
const PROCESS_OBSERVER_RECONCILE_INTERVAL: std::time::Duration = std::time::Duration::from_millis(50);

#[derive(Clone)]
enum QueuedProcessObserverEvent {
    Module(ModuleObserverEvent),
    Thread(ThreadObserverEvent),
}

struct ModuleObserver {
    on_added: Option<[u8; 16]>,
    on_removed: Option<[u8; 16]>,
    known: HashMap<(String, u64), ModuleDetails>,
}

struct ThreadObserver {
    on_added: Option<[u8; 16]>,
    on_removed: Option<[u8; 16]>,
    on_renamed: Option<[u8; 16]>,
    known: HashMap<u64, ProcessThreadDetails>,
}

struct ProcessObserverState {
    next_id: u32,
    module_accepting: bool,
    thread_accepting: bool,
    module_observers: HashMap<u32, ModuleObserver>,
    thread_observers: HashMap<u32, ThreadObserver>,
    events: std::collections::VecDeque<QueuedProcessObserverEvent>,
    reconciling: bool,
    last_reconcile: Option<std::time::Instant>,
}

impl Default for ProcessObserverState {
    fn default() -> Self {
        Self {
            next_id: 1,
            module_accepting: false,
            thread_accepting: false,
            module_observers: HashMap::new(),
            thread_observers: HashMap::new(),
            events: std::collections::VecDeque::new(),
            reconciling: false,
            last_reconcile: None,
        }
    }
}

static PROCESS_OBSERVERS: std::sync::OnceLock<std::sync::Mutex<ProcessObserverState>> = std::sync::OnceLock::new();

fn lock_process_observers() -> std::sync::MutexGuard<'static, ProcessObserverState> {
    PROCESS_OBSERVERS
        .get_or_init(|| std::sync::Mutex::new(ProcessObserverState::default()))
        .lock()
        .unwrap_or_else(|error| error.into_inner())
}

fn module_observer_key(details: &ModuleDetails) -> (String, u64) {
    (normalized_module_path(&details.path).to_string(), details.base)
}

fn merge_module_snapshots(modules: Vec<ModuleDetails>) -> Vec<ModuleDetails> {
    let current = current_module_details();
    let current_identities = current
        .iter()
        .map(module_observer_key)
        .collect::<HashSet<_>>();
    let mut by_identity = modules
        .into_iter()
        .filter(|module| current_identities.contains(&module_observer_key(module)))
        .map(|module| (module_observer_key(&module), module))
        .collect::<HashMap<_, _>>();
    for module in current {
        by_identity.entry(module_observer_key(&module)).or_insert(module);
    }
    let mut modules = by_identity.into_values().collect::<Vec<_>>();
    modules.sort_by_key(|module| module.base);
    modules
}

pub fn queue_module_observer_event(event: ModuleObserverEvent) {
    let mut state = lock_process_observers();
    if !state.module_accepting {
        return;
    }
    if state.events.len() == PROCESS_OBSERVER_QUEUE_CAPACITY {
        state.events.pop_front();
    }
    state.events.push_back(QueuedProcessObserverEvent::Module(event));
}

pub fn queue_thread_observer_event(event: ThreadObserverEvent) {
    let mut state = lock_process_observers();
    if !state.thread_accepting {
        return;
    }
    if state.events.len() == PROCESS_OBSERVER_QUEUE_CAPACITY {
        state.events.pop_front();
    }
    state.events.push_back(QueuedProcessObserverEvent::Thread(event));
}

unsafe fn callback_from_bytes(bytes: &[u8; 16]) -> ffi::JSValue {
    std::ptr::read(bytes.as_ptr() as *const ffi::JSValue)
}

unsafe fn free_callback(ctx: *mut ffi::JSContext, callback: Option<[u8; 16]>) {
    if let Some(callback) = callback {
        ffi::qjs_free_value(ctx, callback_from_bytes(&callback));
    }
}

unsafe fn duplicate_callback(ctx: *mut ffi::JSContext, callback: &[u8; 16]) -> ffi::JSValue {
    ffi::qjs_dup_value(ctx, callback_from_bytes(callback))
}

unsafe fn invoke_observer_callback(
    ctx: *mut ffi::JSContext,
    callback: ffi::JSValue,
    args: &mut [ffi::JSValue],
    context: &str,
) {
    let result = ffi::JS_Call(
        ctx,
        callback,
        JSValue::undefined().raw(),
        args.len() as i32,
        args.as_mut_ptr(),
    );
    crate::jsapi::callback_util::handle_js_exception(ctx, result, context);
    ffi::qjs_free_value(ctx, result);
    ffi::qjs_free_value(ctx, callback);
    for arg in args {
        ffi::qjs_free_value(ctx, *arg);
    }
}

unsafe fn module_details_to_instance(ctx: *mut ffi::JSContext, details: &ModuleDetails) -> ffi::JSValue {
    let info = ModuleInfo {
        name: details.name.clone(),
        version: details.version.clone(),
        base: details.base,
        size: details.size,
        path: details.path.clone(),
    };
    let raw = module_info_to_js(ctx, &info);
    let global = ffi::JS_GetGlobalObject(ctx);
    let wrap = ffi::JS_GetPropertyStr(ctx, global, c"__rf_module_wrap".as_ptr());
    if ffi::JS_IsFunction(ctx, wrap) == 0 {
        ffi::qjs_free_value(ctx, wrap);
        ffi::qjs_free_value(ctx, global);
        return raw;
    }
    let mut args = [raw];
    let wrapped = ffi::JS_Call(ctx, wrap, global, 1, args.as_mut_ptr());
    ffi::qjs_free_value(ctx, raw);
    ffi::qjs_free_value(ctx, wrap);
    ffi::qjs_free_value(ctx, global);
    if ffi::qjs_is_exception(wrapped) != 0 {
        crate::jsapi::callback_util::handle_js_exception(ctx, wrapped, "module observer wrapping");
        ffi::qjs_free_value(ctx, wrapped);
        module_info_to_js(ctx, &info)
    } else {
        wrapped
    }
}

unsafe fn thread_details_to_js(ctx: *mut ffi::JSContext, details: &ProcessThreadDetails) -> ffi::JSValue {
    let object = ffi::JS_NewObject(ctx);
    let value = JSValue(object);
    value.set_property(ctx, "id", js_u64_value(ctx, details.id));
    if let Some(name) = details.name.as_deref() {
        value.set_property(ctx, "name", JSValue::string(ctx, name));
    }
    value.set_property(ctx, "state", JSValue::string(ctx, &details.state));
    object
}

unsafe fn optional_callback(
    ctx: *mut ffi::JSContext,
    callbacks: JSValue,
    name: &str,
) -> Result<Option<[u8; 16]>, ffi::JSValue> {
    let value = callbacks.get_property(ctx, name);
    let result = if value.is_undefined() || value.is_null() {
        Ok(None)
    } else if value.is_function(ctx) {
        Ok(Some(crate::jsapi::callback_util::dup_callback_to_bytes(
            ctx,
            value.raw(),
        )))
    } else {
        let message = std::ffi::CString::new(format!("{name} must be a function")).unwrap();
        Err(ffi::JS_ThrowTypeError(ctx, message.as_ptr()))
    };
    value.free(ctx);
    result
}

fn allocate_observer_id(state: &mut ProcessObserverState) -> u32 {
    loop {
        let id = state.next_id;
        state.next_id = state.next_id.wrapping_add(1).max(1);
        if !state.module_observers.contains_key(&id) && !state.thread_observers.contains_key(&id) {
            return id;
        }
    }
}

unsafe fn invoke_initial_module_callbacks(ctx: *mut ffi::JSContext, observer_id: u32, modules: &[ModuleDetails]) {
    for module in modules {
        let callback = {
            let state = lock_process_observers();
            state
                .module_observers
                .get(&observer_id)
                .and_then(|observer| observer.on_added.as_ref())
                .map(|callback| duplicate_callback(ctx, callback))
        };
        if let Some(callback) = callback {
            let mut args = [module_details_to_instance(ctx, module)];
            invoke_observer_callback(ctx, callback, &mut args, "module observer onAdded");
        }
    }
}

unsafe fn invoke_initial_thread_callbacks(
    ctx: *mut ffi::JSContext,
    observer_id: u32,
    threads: &[ProcessThreadDetails],
) {
    for thread in threads {
        let callback = {
            let state = lock_process_observers();
            state
                .thread_observers
                .get(&observer_id)
                .and_then(|observer| observer.on_added.as_ref())
                .map(|callback| duplicate_callback(ctx, callback))
        };
        if let Some(callback) = callback {
            let mut args = [thread_details_to_js(ctx, thread)];
            invoke_observer_callback(ctx, callback, &mut args, "thread observer onAdded");
        }
    }
}

unsafe extern "C" fn js_process_attach_module_observer(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 || !JSValue(*argv).is_object() {
        return ffi::JS_ThrowTypeError(ctx, c"callbacks must be an object".as_ptr());
    }
    let callbacks = JSValue(*argv);
    let on_added = match optional_callback(ctx, callbacks, "onAdded") {
        Ok(callback) => callback,
        Err(error) => return error,
    };
    let on_removed = match optional_callback(ctx, callbacks, "onRemoved") {
        Ok(callback) => callback,
        Err(error) => {
            free_callback(ctx, on_added);
            return error;
        }
    };
    if on_added.is_none() && on_removed.is_none() {
        return ffi::JS_ThrowTypeError(ctx, c"at least one callback must be provided".as_ptr());
    }
    let Some(backend) = process_observer_backend() else {
        free_callback(ctx, on_added);
        free_callback(ctx, on_removed);
        return crate::jsapi::callback_util::throw_internal_error(ctx, "process observer backend is not available");
    };
    let first = lock_process_observers().module_observers.is_empty();
    let modules = if first {
        lock_process_observers().module_accepting = true;
        match (backend.attach_module_observer)() {
            Ok(modules) => merge_module_snapshots(modules),
            Err(error) => {
                let mut state = lock_process_observers();
                state.module_accepting = false;
                state
                    .events
                    .retain(|event| !matches!(event, QueuedProcessObserverEvent::Module(_)));
                drop(state);
                free_callback(ctx, on_added);
                free_callback(ctx, on_removed);
                return crate::jsapi::callback_util::throw_internal_error(ctx, error);
            }
        }
    } else {
        current_module_details()
    };
    let known = modules
        .iter()
        .cloned()
        .map(|module| (module_observer_key(&module), module))
        .collect();
    let observer_id = {
        let mut state = lock_process_observers();
        let observer_id = allocate_observer_id(&mut state);
        state.module_observers.insert(
            observer_id,
            ModuleObserver {
                on_added,
                on_removed,
                known,
            },
        );
        observer_id
    };
    if let Err(error) = (backend.start_dispatcher)() {
        let _ = detach_module_observer(ctx, observer_id);
        return crate::jsapi::callback_util::throw_internal_error(ctx, error);
    }
    invoke_initial_module_callbacks(ctx, observer_id, &modules);
    drain_process_observer_events(ctx);
    js_u64_value(ctx, observer_id as u64).raw()
}

unsafe extern "C" fn js_process_attach_thread_observer(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 || !JSValue(*argv).is_object() {
        return ffi::JS_ThrowTypeError(ctx, c"callbacks must be an object".as_ptr());
    }
    let callbacks = JSValue(*argv);
    let on_added = match optional_callback(ctx, callbacks, "onAdded") {
        Ok(callback) => callback,
        Err(error) => return error,
    };
    let on_removed = match optional_callback(ctx, callbacks, "onRemoved") {
        Ok(callback) => callback,
        Err(error) => {
            free_callback(ctx, on_added);
            return error;
        }
    };
    let on_renamed = match optional_callback(ctx, callbacks, "onRenamed") {
        Ok(callback) => callback,
        Err(error) => {
            free_callback(ctx, on_added);
            free_callback(ctx, on_removed);
            return error;
        }
    };
    if on_added.is_none() && on_removed.is_none() && on_renamed.is_none() {
        return ffi::JS_ThrowTypeError(ctx, c"at least one callback must be provided".as_ptr());
    }
    let Some(backend) = process_observer_backend() else {
        free_callback(ctx, on_added);
        free_callback(ctx, on_removed);
        free_callback(ctx, on_renamed);
        return crate::jsapi::callback_util::throw_internal_error(ctx, "process observer backend is not available");
    };
    let first = lock_process_observers().thread_observers.is_empty();
    let threads = if first {
        lock_process_observers().thread_accepting = true;
        match (backend.attach_thread_observer)() {
            Ok(threads) => threads,
            Err(error) => {
                let mut state = lock_process_observers();
                state.thread_accepting = false;
                state
                    .events
                    .retain(|event| !matches!(event, QueuedProcessObserverEvent::Thread(_)));
                drop(state);
                free_callback(ctx, on_added);
                free_callback(ctx, on_removed);
                free_callback(ctx, on_renamed);
                return crate::jsapi::callback_util::throw_internal_error(ctx, error);
            }
        }
    } else {
        current_thread_details()
    };
    let known = threads.iter().cloned().map(|thread| (thread.id, thread)).collect();
    let observer_id = {
        let mut state = lock_process_observers();
        let observer_id = allocate_observer_id(&mut state);
        state.thread_observers.insert(
            observer_id,
            ThreadObserver {
                on_added,
                on_removed,
                on_renamed,
                known,
            },
        );
        observer_id
    };
    if let Err(error) = (backend.start_dispatcher)() {
        let _ = detach_thread_observer(ctx, observer_id);
        return crate::jsapi::callback_util::throw_internal_error(ctx, error);
    }
    invoke_initial_thread_callbacks(ctx, observer_id, &threads);
    drain_process_observer_events(ctx);
    js_u64_value(ctx, observer_id as u64).raw()
}

unsafe fn detach_module_observer(ctx: *mut ffi::JSContext, observer_id: u32) -> Result<(), String> {
    let (observer, last) = {
        let mut state = lock_process_observers();
        let observer = state.module_observers.remove(&observer_id);
        let last = observer.is_some() && state.module_observers.is_empty();
        (observer, last)
    };
    let Some(observer) = observer else {
        return Ok(());
    };
    let detach_result = if last {
        let result = process_observer_backend()
            .map(|backend| (backend.detach_module_observer)())
            .unwrap_or(Ok(()));
        let mut state = lock_process_observers();
        state.module_accepting = false;
        state
            .events
            .retain(|event| !matches!(event, QueuedProcessObserverEvent::Module(_)));
        result
    } else {
        Ok(())
    };
    free_callback(ctx, observer.on_added);
    free_callback(ctx, observer.on_removed);
    detach_result
}

unsafe fn detach_thread_observer(ctx: *mut ffi::JSContext, observer_id: u32) -> Result<(), String> {
    let (observer, last) = {
        let mut state = lock_process_observers();
        let observer = state.thread_observers.remove(&observer_id);
        let last = observer.is_some() && state.thread_observers.is_empty();
        (observer, last)
    };
    let Some(observer) = observer else {
        return Ok(());
    };
    let detach_result = if last {
        let result = process_observer_backend()
            .map(|backend| (backend.detach_thread_observer)())
            .unwrap_or(Ok(()));
        let mut state = lock_process_observers();
        state.thread_accepting = false;
        state
            .events
            .retain(|event| !matches!(event, QueuedProcessObserverEvent::Thread(_)));
        result
    } else {
        Ok(())
    };
    free_callback(ctx, observer.on_added);
    free_callback(ctx, observer.on_removed);
    free_callback(ctx, observer.on_renamed);
    detach_result
}

unsafe extern "C" fn js_process_detach_module_observer(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let observer_id = if argc > 0 {
        JSValue(*argv).to_i64(ctx).unwrap_or(0) as u32
    } else {
        0
    };
    match detach_module_observer(ctx, observer_id) {
        Ok(()) => JSValue::undefined().raw(),
        Err(error) => crate::jsapi::callback_util::throw_internal_error(ctx, error),
    }
}

unsafe extern "C" fn js_process_detach_thread_observer(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let observer_id = if argc > 0 {
        JSValue(*argv).to_i64(ctx).unwrap_or(0) as u32
    } else {
        0
    };
    match detach_thread_observer(ctx, observer_id) {
        Ok(()) => JSValue::undefined().raw(),
        Err(error) => crate::jsapi::callback_util::throw_internal_error(ctx, error),
    }
}

unsafe extern "C" fn js_process_dispatch_observer_events(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    drain_process_observer_events(ctx);
    JSValue::undefined().raw()
}

unsafe fn dispatch_module_event(ctx: *mut ffi::JSContext, event: ModuleObserverEvent) {
    let (details, added) = match event {
        ModuleObserverEvent::Added(details) => (details, true),
        ModuleObserverEvent::Removed(details) => (details, false),
    };
    let key = module_observer_key(&details);
    let callbacks = {
        let mut state = lock_process_observers();
        let mut callbacks = Vec::new();
        for observer in state.module_observers.values_mut() {
            let callback = if added {
                if observer.known.contains_key(&key) {
                    None
                } else {
                    observer.known.insert(key.clone(), details.clone());
                    observer.on_added.as_ref()
                }
            } else if observer.known.remove(&key).is_some() {
                observer.on_removed.as_ref()
            } else {
                None
            };
            if let Some(callback) = callback {
                callbacks.push(duplicate_callback(ctx, callback));
            }
        }
        callbacks
    };
    for callback in callbacks {
        let mut args = [module_details_to_instance(ctx, &details)];
        invoke_observer_callback(
            ctx,
            callback,
            &mut args,
            if added {
                "module observer onAdded"
            } else {
                "module observer onRemoved"
            },
        );
    }
}

unsafe fn dispatch_thread_event(ctx: *mut ffi::JSContext, event: ThreadObserverEvent) {
    let (thread, kind, previous_name) = match event {
        ThreadObserverEvent::Added(thread) => (thread, 0, None),
        ThreadObserverEvent::Removed(thread) => (thread, 1, None),
        ThreadObserverEvent::Renamed {
            thread,
            previous_name,
        } => (thread, 2, previous_name),
    };
    let callbacks = {
        let mut state = lock_process_observers();
        let mut callbacks = Vec::new();
        for observer in state.thread_observers.values_mut() {
            let callback = match kind {
                0 => {
                    if observer.known.contains_key(&thread.id) {
                        None
                    } else {
                        observer.known.insert(thread.id, thread.clone());
                        observer.on_added.as_ref()
                    }
                }
                1 => {
                    if observer.known.remove(&thread.id).is_some() {
                        observer.on_removed.as_ref()
                    } else {
                        None
                    }
                }
                _ => match observer.known.get_mut(&thread.id) {
                    Some(known) if known.name != thread.name => {
                        *known = thread.clone();
                        observer.on_renamed.as_ref()
                    }
                    Some(known) => {
                        *known = thread.clone();
                        None
                    }
                    None => {
                        observer.known.insert(thread.id, thread.clone());
                        None
                    }
                },
            };
            if let Some(callback) = callback {
                callbacks.push(duplicate_callback(ctx, callback));
            }
        }
        callbacks
    };
    for callback in callbacks {
        let mut args = vec![thread_details_to_js(ctx, &thread)];
        let context = match kind {
            0 => "thread observer onAdded",
            1 => "thread observer onRemoved",
            _ => {
                args.push(
                    previous_name
                        .as_deref()
                        .map(|name| JSValue::string(ctx, name).raw())
                        .unwrap_or_else(|| JSValue::null().raw()),
                );
                "thread observer onRenamed"
            }
        };
        invoke_observer_callback(ctx, callback, &mut args, context);
    }
}

unsafe fn reconcile_process_observers(ctx: *mut ffi::JSContext) {
    let (reconcile_modules, reconcile_threads) = {
        let mut state = lock_process_observers();
        if state.reconciling
            || (state.module_observers.is_empty() && state.thread_observers.is_empty())
            || state
                .last_reconcile
                .is_some_and(|last| last.elapsed() < PROCESS_OBSERVER_RECONCILE_INTERVAL)
        {
            return;
        }
        state.reconciling = true;
        state.last_reconcile = Some(std::time::Instant::now());
        (!state.module_observers.is_empty(), !state.thread_observers.is_empty())
    };

    let modules = reconcile_modules.then(current_module_details);
    let threads = reconcile_threads.then(current_thread_details);
    let mut events = Vec::new();
    {
        let mut state = lock_process_observers();
        if let Some(modules) = modules {
            let current = modules
                .into_iter()
                .map(|module| (module_observer_key(&module), module))
                .collect::<HashMap<_, _>>();
            let known = state
                .module_observers
                .values()
                .flat_map(|observer| observer.known.iter())
                .map(|(key, module)| (key.clone(), module.clone()))
                .collect::<HashMap<_, _>>();

            for (key, module) in &known {
                if !current.contains_key(key) {
                    events.push(QueuedProcessObserverEvent::Module(ModuleObserverEvent::Removed(
                        module.clone(),
                    )));
                }
            }
            for (key, module) in current {
                if state
                    .module_observers
                    .values()
                    .any(|observer| !observer.known.contains_key(&key))
                {
                    events.push(QueuedProcessObserverEvent::Module(ModuleObserverEvent::Added(module)));
                }
            }
        }

        if let Some(threads) = threads {
            let current = threads
                .into_iter()
                .map(|thread| (thread.id, thread))
                .collect::<HashMap<_, _>>();
            let known = state
                .thread_observers
                .values()
                .flat_map(|observer| observer.known.iter())
                .map(|(&id, thread)| (id, thread.clone()))
                .collect::<HashMap<_, _>>();

            for (&id, thread) in &known {
                if !current.contains_key(&id) {
                    events.push(QueuedProcessObserverEvent::Thread(ThreadObserverEvent::Removed(
                        thread.clone(),
                    )));
                }
            }
            for (id, thread) in current {
                if state
                    .thread_observers
                    .values()
                    .any(|observer| !observer.known.contains_key(&id))
                {
                    events.push(QueuedProcessObserverEvent::Thread(ThreadObserverEvent::Added(thread)));
                    continue;
                }
                if let Some(previous_name) = state
                    .thread_observers
                    .values()
                    .filter_map(|observer| observer.known.get(&id))
                    .find(|known| known.name != thread.name)
                    .map(|known| known.name.clone())
                {
                    events.push(QueuedProcessObserverEvent::Thread(ThreadObserverEvent::Renamed {
                        thread,
                        previous_name,
                    }));
                }
            }
        }
        state.reconciling = false;
    }

    for event in events {
        match event {
            QueuedProcessObserverEvent::Module(event) => dispatch_module_event(ctx, event),
            QueuedProcessObserverEvent::Thread(event) => dispatch_thread_event(ctx, event),
        }
    }
}

pub(crate) unsafe fn drain_process_observer_events(ctx: *mut ffi::JSContext) {
    for _ in 0..PROCESS_OBSERVER_QUEUE_CAPACITY {
        let event = lock_process_observers().events.pop_front();
        match event {
            Some(QueuedProcessObserverEvent::Module(event)) => dispatch_module_event(ctx, event),
            Some(QueuedProcessObserverEvent::Thread(event)) => dispatch_thread_event(ctx, event),
            None => break,
        }
    }
    reconcile_process_observers(ctx);
}

pub(crate) fn process_observer_events_pending() -> bool {
    let state = lock_process_observers();
    if !state.events.is_empty() {
        return true;
    }
    if state.module_observers.is_empty() && state.thread_observers.is_empty() {
        return false;
    }
    state
        .last_reconcile
        .map_or(true, |last| last.elapsed() >= PROCESS_OBSERVER_RECONCILE_INTERVAL)
}

pub fn cut_process_observers() -> Result<(), String> {
    let (modules_active, threads_active) = {
        let mut state = lock_process_observers();
        state.module_accepting = false;
        state.thread_accepting = false;
        state.events.clear();
        state.reconciling = false;
        state.last_reconcile = None;
        (!state.module_observers.is_empty(), !state.thread_observers.is_empty())
    };
    if let Some(backend) = process_observer_backend() {
        if modules_active {
            (backend.detach_module_observer)()?;
        }
        if threads_active {
            (backend.detach_thread_observer)()?;
        }
    }
    Ok(())
}

pub unsafe fn free_process_observers(ctx: *mut ffi::JSContext) {
    let (modules, threads) = {
        let mut state = lock_process_observers();
        state.module_accepting = false;
        state.thread_accepting = false;
        state.events.clear();
        state.reconciling = false;
        state.last_reconcile = None;
        (
            std::mem::take(&mut state.module_observers),
            std::mem::take(&mut state.thread_observers),
        )
    };
    for observer in modules.into_values() {
        free_callback(ctx, observer.on_added);
        free_callback(ctx, observer.on_removed);
    }
    for observer in threads.into_values() {
        free_callback(ctx, observer.on_added);
        free_callback(ctx, observer.on_removed);
        free_callback(ctx, observer.on_renamed);
    }
}

fn current_module_details() -> Vec<ModuleDetails> {
    enumerate_process_modules()
        .into_iter()
        .map(|module| ModuleDetails {
            name: module.name,
            version: module.version,
            path: module.path,
            base: module.base,
            size: module.size,
        })
        .collect()
}

fn current_thread_details() -> Vec<ProcessThreadDetails> {
    process_threads()
        .into_iter()
        .map(|(id, name, state)| ProcessThreadDetails {
            id: id as u64,
            name,
            state,
        })
        .collect()
}
