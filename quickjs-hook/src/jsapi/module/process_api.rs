// ============================================================================
// JS API: Process namespace
// ============================================================================

#[derive(Clone, Debug)]
struct ProcessRangeRecord {
    base: u64,
    size: u64,
    protection: String,
    path: Option<String>,
}

unsafe fn js_u64_value(ctx: *mut ffi::JSContext, value: u64) -> JSValue {
    if value <= i64::MAX as u64 {
        JSValue(ffi::qjs_new_int64(ctx, value as i64))
    } else {
        JSValue::float(value as f64)
    }
}

fn process_arch_name() -> &'static str {
    #[cfg(target_arch = "aarch64")]
    {
        "arm64"
    }
    #[cfg(target_arch = "arm")]
    {
        "arm"
    }
    #[cfg(target_arch = "x86_64")]
    {
        "x64"
    }
    #[cfg(target_arch = "x86")]
    {
        "ia32"
    }
    #[cfg(not(any(
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "x86_64",
        target_arch = "x86"
    )))]
    {
        std::env::consts::ARCH
    }
}

fn process_page_size() -> i64 {
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size > 0 {
        page_size as i64
    } else {
        4096
    }
}

fn process_current_thread_id() -> i64 {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    unsafe {
        libc::syscall(libc::SYS_gettid) as i64
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        0
    }
}

fn process_find_module_by_name(name: &str) -> Option<ModuleInfo> {
    enumerate_process_modules()
        .into_iter()
        .find(|m| matches_module_lookup_name(&m.path, name) || m.name == name)
}

fn process_main_module() -> Option<ModuleInfo> {
    let modules = enumerate_process_modules();
    if modules.is_empty() {
        return None;
    }

    if let Ok(exe_path) = std::fs::read_link("/proc/self/exe") {
        let exe = exe_path.to_string_lossy();
        if let Some(module) = modules.iter().find(|m| m.path == exe) {
            return Some(module.clone());
        }
        if let Some(name) = exe.rsplit('/').next() {
            if let Some(module) = modules.iter().find(|m| m.name == name) {
                return Some(module.clone());
            }
        }
    }

    modules.into_iter().min_by_key(|m| m.base)
}

fn is_debugger_attached() -> bool {
    let status = match std::fs::read_to_string("/proc/self/status") {
        Ok(s) => s,
        Err(_) => return false,
    };
    status.lines().any(|line| {
        let Some(rest) = line.strip_prefix("TracerPid:") else {
            return false;
        };
        rest.trim().parse::<u32>().unwrap_or(0) != 0
    })
}

fn process_thread_state(tid: i32) -> String {
    let path = format!("/proc/self/task/{}/status", tid);
    let status = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => return "unknown".to_string(),
    };
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("State:") {
            return match rest.trim().as_bytes().first().copied() {
                Some(b'R') => "running",
                Some(b'T') | Some(b't') => "stopped",
                Some(b'S') | Some(b'I') => "waiting",
                Some(b'D') => "uninterruptible",
                Some(b'Z') | Some(b'X') | Some(b'x') | Some(b'K') | Some(b'W') | Some(b'P') => {
                    "halted"
                }
                _ => "unknown",
            }
            .to_string();
        }
    }
    "unknown".to_string()
}

fn process_thread_name(tid: i32) -> Option<String> {
    let path = format!("/proc/self/task/{}/comm", tid);
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim_end_matches('\n').to_string())
        .filter(|s| !s.is_empty())
}

fn process_threads() -> Vec<(i32, Option<String>, String)> {
    let entries = match std::fs::read_dir("/proc/self/task") {
        Ok(entries) => entries,
        Err(_) => return Vec::new(),
    };

    let mut threads = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Ok(tid) = name.parse::<i32>() else {
            continue;
        };
        threads.push((tid, process_thread_name(tid), process_thread_state(tid)));
    }
    threads.sort_by_key(|(tid, _, _)| *tid);
    threads
}

unsafe fn process_thread_to_js(
    ctx: *mut ffi::JSContext,
    tid: i32,
    name: Option<&str>,
    state: &str,
) -> ffi::JSValue {
    let obj = ffi::JS_NewObject(ctx);
    let obj_val = JSValue(obj);
    obj_val.set_property(ctx, "id", JSValue::int(tid));
    if let Some(name) = name {
        obj_val.set_property(ctx, "name", JSValue::string(ctx, name));
    }
    obj_val.set_property(ctx, "state", JSValue::string(ctx, state));
    obj
}

unsafe fn process_range_to_js(ctx: *mut ffi::JSContext, rec: &ProcessRangeRecord) -> ffi::JSValue {
    let obj = ffi::JS_NewObject(ctx);
    let obj_val = JSValue(obj);
    obj_val.set_property(ctx, "base", create_native_pointer(ctx, rec.base));
    obj_val.set_property(ctx, "size", js_u64_value(ctx, rec.size));
    obj_val.set_property(ctx, "protection", JSValue::string(ctx, &rec.protection));

    if let Some(path) = rec.path.as_ref() {
        let file = ffi::JS_NewObject(ctx);
        let file_val = JSValue(file);
        file_val.set_property(ctx, "path", JSValue::string(ctx, path));
        obj_val.set_property(ctx, "file", file_val);
    }

    obj
}

fn normalize_map_protection(perms: &str) -> Option<String> {
    let prot3_end = perms.len().min(3);
    let prot3 = &perms[..prot3_end];
    (prot3.len() == 3).then(|| prot3.to_string())
}

fn collect_process_ranges(prot_filter: Option<&str>, coalesce: bool) -> Vec<ProcessRangeRecord> {
    let maps = match crate::jsapi::util::read_proc_self_maps() {
        Some(s) => s,
        None => return Vec::new(),
    };

    let mut out: Vec<ProcessRangeRecord> = Vec::new();
    for entry in crate::jsapi::util::proc_maps_entries(&maps) {
        let Some(protection) = normalize_map_protection(entry.perms) else {
            continue;
        };
        if let Some(filter) = prot_filter {
            if !protection_matches(&protection, filter) {
                continue;
            }
        }

        let path = entry.path.map(str::to_string);
        let rec = ProcessRangeRecord {
            base: entry.start,
            size: entry.end.saturating_sub(entry.start),
            protection,
            path,
        };

        if coalesce {
            if let Some(last) = out.last_mut() {
                let same_attrs = last.base + last.size == rec.base
                    && last.protection == rec.protection
                    && last.path == rec.path;
                if same_attrs {
                    last.size += rec.size;
                    continue;
                }
            }
        }

        out.push(rec);
    }

    out
}

fn find_process_range_by_address(addr: u64) -> Option<ProcessRangeRecord> {
    let maps = crate::jsapi::util::read_proc_self_maps()?;
    for entry in crate::jsapi::util::proc_maps_entries(&maps) {
        if !entry.contains(addr) {
            continue;
        }
        let protection = normalize_map_protection(entry.perms)?;
        return Some(ProcessRangeRecord {
            base: entry.start,
            size: entry.end.saturating_sub(entry.start),
            protection,
            path: entry.path.map(str::to_string),
        });
    }
    None
}

fn process_current_dir() -> String {
    std::env::current_dir()
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| "/".to_string())
}

fn process_home_dir() -> String {
    std::env::var("HOME").unwrap_or_else(|_| "/".to_string())
}

fn process_tmp_dir() -> String {
    std::env::var("TMPDIR").unwrap_or_else(|_| "/data/local/tmp".to_string())
}

unsafe fn parse_process_range_options(
    ctx: *mut ffi::JSContext,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> Result<(Option<String>, bool), ffi::JSValue> {
    if argc < 1 {
        return Ok((None, false));
    }

    let arg = JSValue(*argv);
    if arg.is_null() || arg.is_undefined() {
        return Ok((None, false));
    }
    if arg.is_string() {
        return Ok((arg.to_string(ctx), false));
    }
    if !arg.is_object() {
        return Err(ffi::JS_ThrowTypeError(
            ctx,
            b"Process.enumerateRanges(protection | { protection, coalesce }) expected a string or object\0"
                .as_ptr() as *const _,
        ));
    }

    let protection_val = arg.get_property(ctx, "protection");
    let protection = if protection_val.is_null() || protection_val.is_undefined() {
        None
    } else {
        let parsed = protection_val.to_string(ctx);
        if parsed.is_none() {
            protection_val.free(ctx);
            return Err(ffi::JS_ThrowTypeError(
                ctx,
                b"Process.enumerateRanges: protection must be a string\0".as_ptr() as *const _,
            ));
        }
        parsed
    };
    protection_val.free(ctx);

    let coalesce_val = arg.get_property(ctx, "coalesce");
    let coalesce = coalesce_val.to_bool().unwrap_or(false);
    coalesce_val.free(ctx);

    Ok((protection, coalesce))
}

unsafe extern "C" fn js_process_enumerate_modules(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let modules = enumerate_process_modules();
    let arr = ffi::JS_NewArray(ctx);
    for (i, module) in modules.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, arr, i as u32, module_info_to_js(ctx, module));
    }
    arr
}

unsafe extern "C" fn js_process_find_module_by_name(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Process.findModuleByName(name) requires 1 argument\0".as_ptr() as *const _,
        );
    }
    let name = match require_string_arg(ctx, JSValue(*argv), "name") {
        Ok(s) => s,
        Err(exc) => return exc,
    };

    match process_find_module_by_name(&name) {
        Some(module) => module_info_to_js(ctx, &module),
        None => JSValue::null().raw(),
    }
}

unsafe extern "C" fn js_process_get_module_by_name(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let module = js_process_find_module_by_name(ctx, this, argc, argv);
    if !JSValue(module).is_null() {
        return module;
    }
    crate::jsapi::callback_util::throw_internal_error(ctx, "Process.getModuleByName: module not found")
}

unsafe extern "C" fn js_process_find_module_by_address(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Process.findModuleByAddress(address) requires 1 argument\0".as_ptr() as *const _,
        );
    }
    let addr = match crate::jsapi::callback_util::extract_pointer_address(
        ctx,
        JSValue(*argv),
        "Process.findModuleByAddress",
    ) {
        Ok(a) => a,
        Err(e) => return e,
    };

    match find_process_module_by_address(addr) {
        Some(module) => module_info_to_js(ctx, &module),
        None => JSValue::null().raw(),
    }
}

unsafe extern "C" fn js_process_get_module_by_address(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let module = js_process_find_module_by_address(ctx, this, argc, argv);
    if !JSValue(module).is_null() {
        return module;
    }
    crate::jsapi::callback_util::throw_internal_error(
        ctx,
        "Process.getModuleByAddress: module not found",
    )
}

unsafe extern "C" fn js_process_enumerate_ranges(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let (protection, coalesce) = match parse_process_range_options(ctx, argc, argv) {
        Ok(opts) => opts,
        Err(exc) => return exc,
    };

    let ranges = collect_process_ranges(protection.as_deref(), coalesce);
    let arr = ffi::JS_NewArray(ctx);
    for (i, rec) in ranges.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, arr, i as u32, process_range_to_js(ctx, rec));
    }
    arr
}

unsafe extern "C" fn js_process_find_range_by_address(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Process.findRangeByAddress(address) requires 1 argument\0".as_ptr() as *const _,
        );
    }
    let addr = match crate::jsapi::callback_util::extract_pointer_address(
        ctx,
        JSValue(*argv),
        "Process.findRangeByAddress",
    ) {
        Ok(a) => a,
        Err(e) => return e,
    };

    match find_process_range_by_address(addr) {
        Some(range) => process_range_to_js(ctx, &range),
        None => JSValue::null().raw(),
    }
}

unsafe extern "C" fn js_process_get_range_by_address(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let range = js_process_find_range_by_address(ctx, this, argc, argv);
    if !JSValue(range).is_null() {
        return range;
    }
    crate::jsapi::callback_util::throw_internal_error(
        ctx,
        "Process.getRangeByAddress: range not found",
    )
}

unsafe extern "C" fn js_process_enumerate_malloc_ranges(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    ffi::JS_NewArray(ctx)
}

unsafe extern "C" fn js_process_get_current_dir(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    JSValue::string(ctx, &process_current_dir()).raw()
}

unsafe extern "C" fn js_process_get_home_dir(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    JSValue::string(ctx, &process_home_dir()).raw()
}

unsafe extern "C" fn js_process_get_tmp_dir(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    JSValue::string(ctx, &process_tmp_dir()).raw()
}

unsafe extern "C" fn js_process_get_current_thread_id(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    JSValue(ffi::qjs_new_int64(ctx, process_current_thread_id())).raw()
}

unsafe extern "C" fn js_process_is_debugger_attached(
    _ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    JSValue::bool(is_debugger_attached()).raw()
}

unsafe extern "C" fn js_process_enumerate_threads(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let threads = process_threads();
    let arr = ffi::JS_NewArray(ctx);
    for (i, (tid, name, state)) in threads.iter().enumerate() {
        ffi::JS_SetPropertyUint32(
            ctx,
            arr,
            i as u32,
            process_thread_to_js(ctx, *tid, name.as_deref(), state),
        );
    }
    arr
}

pub fn register_process_api(ctx: &JSContext) {
    let global = ctx.global_object();

    unsafe {
        let ctx_ptr = ctx.as_ptr();
        let process_obj = ffi::JS_NewObject(ctx_ptr);
        let process_val = JSValue(process_obj);

        process_val.set_property(ctx_ptr, "id", JSValue::int(libc::getpid()));
        process_val.set_property(ctx_ptr, "arch", JSValue::string(ctx_ptr, process_arch_name()));
        process_val.set_property(ctx_ptr, "platform", JSValue::string(ctx_ptr, "linux"));
        process_val.set_property(
            ctx_ptr,
            "pointerSize",
            JSValue::int(std::mem::size_of::<usize>() as i32),
        );
        process_val.set_property(ctx_ptr, "pageSize", JSValue::int(process_page_size() as i32));
        process_val.set_property(ctx_ptr, "codeSigningPolicy", JSValue::string(ctx_ptr, "optional"));
        if let Some(main_module) = process_main_module() {
            process_val.set_property(ctx_ptr, "mainModule", JSValue(module_info_to_js(ctx_ptr, &main_module)));
        } else {
            process_val.set_property(ctx_ptr, "mainModule", JSValue::null());
        }

        add_cfunction_to_object(
            ctx_ptr,
            process_obj,
            "enumerateModules",
            js_process_enumerate_modules,
            0,
        );
        add_cfunction_to_object(
            ctx_ptr,
            process_obj,
            "findModuleByName",
            js_process_find_module_by_name,
            1,
        );
        add_cfunction_to_object(
            ctx_ptr,
            process_obj,
            "getModuleByName",
            js_process_get_module_by_name,
            1,
        );
        add_cfunction_to_object(
            ctx_ptr,
            process_obj,
            "findModuleByAddress",
            js_process_find_module_by_address,
            1,
        );
        add_cfunction_to_object(
            ctx_ptr,
            process_obj,
            "getModuleByAddress",
            js_process_get_module_by_address,
            1,
        );
        add_cfunction_to_object(
            ctx_ptr,
            process_obj,
            "enumerateRanges",
            js_process_enumerate_ranges,
            1,
        );
        add_cfunction_to_object(
            ctx_ptr,
            process_obj,
            "findRangeByAddress",
            js_process_find_range_by_address,
            1,
        );
        add_cfunction_to_object(
            ctx_ptr,
            process_obj,
            "getRangeByAddress",
            js_process_get_range_by_address,
            1,
        );
        add_cfunction_to_object(
            ctx_ptr,
            process_obj,
            "enumerateMallocRanges",
            js_process_enumerate_malloc_ranges,
            0,
        );
        add_cfunction_to_object(
            ctx_ptr,
            process_obj,
            "getCurrentDir",
            js_process_get_current_dir,
            0,
        );
        add_cfunction_to_object(
            ctx_ptr,
            process_obj,
            "getHomeDir",
            js_process_get_home_dir,
            0,
        );
        add_cfunction_to_object(
            ctx_ptr,
            process_obj,
            "getTmpDir",
            js_process_get_tmp_dir,
            0,
        );
        add_cfunction_to_object(
            ctx_ptr,
            process_obj,
            "getCurrentThreadId",
            js_process_get_current_thread_id,
            0,
        );
        add_cfunction_to_object(
            ctx_ptr,
            process_obj,
            "isDebuggerAttached",
            js_process_is_debugger_attached,
            0,
        );
        add_cfunction_to_object(
            ctx_ptr,
            process_obj,
            "enumerateThreads",
            js_process_enumerate_threads,
            0,
        );
        add_cfunction_to_object(
            ctx_ptr,
            process_obj,
            "__attachModuleObserver",
            js_process_attach_module_observer,
            1,
        );
        add_cfunction_to_object(
            ctx_ptr,
            process_obj,
            "__detachModuleObserver",
            js_process_detach_module_observer,
            1,
        );
        add_cfunction_to_object(
            ctx_ptr,
            process_obj,
            "__attachThreadObserver",
            js_process_attach_thread_observer,
            1,
        );
        add_cfunction_to_object(
            ctx_ptr,
            process_obj,
            "__detachThreadObserver",
            js_process_detach_thread_observer,
            1,
        );
        add_cfunction_to_object(
            ctx_ptr,
            process_obj,
            "__dispatchObserverEvents",
            js_process_dispatch_observer_events,
            0,
        );

        global.set_property(ctx_ptr, "Process", process_val);
    }

    global.free(ctx.as_ptr());
}
