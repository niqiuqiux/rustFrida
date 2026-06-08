// ============================================================================
// Module handle + symbol resolution
// ============================================================================

#[repr(C)]
struct AndroidDlextinfo {
    flags: u64,
    reserved_addr: u64,
    reserved_size: u64,
    relro_fd: i32,
    library_fd: i32,
    library_fd_offset: u64,
    library_namespace: u64,
}

/// Get a dlopen handle to libart.so via unrestricted linker API (Frida-style).
unsafe fn get_libart_handle() -> *mut std::ffi::c_void {
    LIBART_HANDLE
        .get_or_init(|| {
            let api = UNRESTRICTED_LINKER_API.get_or_init(|| init_unrestricted_linker_api());
            if let Some(api) = api {
                let &(libart_base, _) = LIBART_RANGE.get_or_init(probe_libart_range);
                if libart_base == 0 {
                    output_message("[linker api] libart.so base not found in /proc/self/maps");
                    return SyncPtr(std::ptr::null_mut());
                }

                let caller_addr = libart_base as *const std::ffi::c_void;

                let paths_to_try: Vec<String> = {
                    let mut paths = Vec::new();
                    if let Some(Some(path)) = LIBART_PATH.get() {
                        paths.push(path.clone());
                    }
                    paths.push("libart.so".to_string());
                    paths
                };

                for path in &paths_to_try {
                    let c_path = CString::new(path.as_str()).unwrap();
                    let handle = (api.dlopen)(
                        c_path.as_ptr() as *const i8,
                        libc::RTLD_NOW | libc::RTLD_NOLOAD,
                        caller_addr,
                    );
                    if !handle.is_null() {
                        output_message(&format!(
                            "[linker api] dlopen({}, NOLOAD, caller={:#x}) = {:?}",
                            path, libart_base, handle
                        ));
                        return SyncPtr(handle);
                    }

                    let err = libc::dlerror();
                    if !err.is_null() {
                        let err_msg = std::ffi::CStr::from_ptr(err).to_string_lossy();
                        output_message(&format!(
                            "[linker api] dlopen({}, NOLOAD) failed: {}",
                            path, err_msg
                        ));
                    }
                }

                output_message("[linker api] all dlopen attempts failed");
            }
            SyncPtr(std::ptr::null_mut())
        })
        .0
}

/// Get a dlopen handle to an arbitrary module via unrestricted linker API.
///
/// This is kept only for APIs that still need to load a new shared object
/// (Module.load/QBDI/JVMTI). Symbol lookup paths below intentionally avoid it.
unsafe fn module_dlopen(module_name: &str) -> *mut std::ffi::c_void {
    let c_name = CString::new(module_name).unwrap();

    // 直接走 unrestricted path（跳过 standard dlopen fast path）
    let api = UNRESTRICTED_LINKER_API.get_or_init(|| init_unrestricted_linker_api());
    if let Some(api) = api {
        let base = find_module_base(module_name);
        if base != 0 {
            let caller_addr = base as *const std::ffi::c_void;
            let handle = (api.dlopen)(
                c_name.as_ptr() as *const i8,
                libc::RTLD_NOW | libc::RTLD_NOLOAD,
                caller_addr,
            );
            if !handle.is_null() {
                return handle;
            }
        }

        // Try with trusted_caller as fallback
        let handle = (api.dlopen)(
            c_name.as_ptr() as *const i8,
            libc::RTLD_NOW | libc::RTLD_NOLOAD,
            api.trusted_caller,
        );
        if !handle.is_null() {
            return handle;
        }
    }

    std::ptr::null_mut()
}

/// Resolve a symbol from an arbitrary loaded module by parsing ELF metadata.
/// This bypasses the system linker entirely: no dlopen, dlsym, dladdr, or
/// __loader_* entrypoints are called on the lookup path.
pub(crate) unsafe fn module_dlsym(module_name: &str, symbol: &str) -> *mut std::ffi::c_void {
    if let Some((path, base)) = find_module_path_and_base(module_name) {
        let syms = elf_module_find_symbols(&path, base, &[symbol]);
        if let Some(&addr) = syms.get(symbol) {
            return addr as *mut std::ffi::c_void;
        }
    }

    std::ptr::null_mut()
}

fn should_scan_module_for_global_export(module: &ModuleInfo) -> bool {
    global_export_scan_priority(module).is_some()
}

fn is_probable_shared_object_path(path: &str) -> bool {
    path.ends_with(".so") || path.contains(".so!")
}

fn is_app_module_path(path: &str) -> bool {
    path.starts_with("/data/app/")
        || path.starts_with("/mnt/expand/")
        || path.starts_with("/data/user/")
        || path.starts_with("/data/data/")
}

fn global_export_scan_priority(module: &ModuleInfo) -> Option<u8> {
    let path = module.path.as_str();
    if path.starts_with("/memfd:") {
        return (path.starts_with("/memfd:wwb_") && is_probable_shared_object_path(path)).then_some(0);
    }
    if !is_probable_shared_object_path(path) {
        return None;
    }
    if is_app_module_path(path) {
        Some(0)
    } else {
        Some(1)
    }
}

/// Resolve a symbol across all loaded modules by parsing each module's ELF.
/// This is our RTLD_DEFAULT replacement for JS Module.findExportByName(null,...)
/// and CModule unresolved imports.
pub(crate) unsafe fn find_export_in_loaded_modules(symbol: &str) -> *mut std::ffi::c_void {
    let modules = enumerate_modules_from_maps();
    let mut candidates = modules
        .iter()
        .filter_map(|module| global_export_scan_priority(module).map(|priority| (priority, module)))
        .collect::<Vec<_>>();
    candidates.sort_by_key(|(priority, module)| (*priority, module.base));

    let mut seen = HashSet::new();
    for (_, module) in candidates {
        if !should_scan_module_for_global_export(module) {
            continue;
        }
        if !seen.insert(module.path.clone()) {
            continue;
        }
        let syms = elf_module_find_symbols(&module.path, module.base, &[symbol]);
        if let Some(&addr) = syms.get(symbol) {
            return addr as *mut std::ffi::c_void;
        }
    }
    std::ptr::null_mut()
}

/// Resolve a symbol by name substring from one loaded module's .symtab/.dynsym.
///
/// This is intended for Android framework native methods where the C++ mangled
/// signature drifts, but the stable JNI function stem remains in the symbol
/// name on debuggable/system builds.
pub(crate) unsafe fn module_find_symbol_contains(module_name: &str, needle: &str) -> Option<(String, u64)> {
    if needle.is_empty() {
        return None;
    }
    let (path, base) = find_module_path_and_base(module_name)?;
    let symbols = elf_module_enumerate_symbols(&path, base);
    let mut fallback: Option<(String, u64)> = None;
    for symbol in symbols {
        if symbol.address == 0 || !symbol.is_defined || symbol.kind != "function" {
            continue;
        }
        if !symbol.name.contains(needle) {
            continue;
        }
        if symbol.name.contains(needle) && !symbol.name.contains("CheckJNI") {
            return Some((symbol.name, symbol.address));
        }
        if fallback.is_none() {
            fallback = Some((symbol.name, symbol.address));
        }
    }
    fallback
}

/// Resolve a JNI registered native method by scanning the module's relocated
/// `JNINativeMethod { name, signature, fnPtr }` tables in memory.
///
/// This is intentionally independent from .symtab/.dynsym: Android framework
/// JNI method functions are often local symbols, and production system images
/// may strip their names while keeping the registration table relocated.
pub(crate) unsafe fn module_find_jni_native_method(module_name: &str, name: &str, sig: &str) -> Option<u64> {
    if name.is_empty() || sig.is_empty() {
        return None;
    }

    let ranges = module_memory_ranges(module_name);
    if ranges.is_empty() {
        return None;
    }
    let readable: Vec<MemoryRange> = ranges.iter().copied().filter(|r| r.readable).collect();
    let executable: Vec<MemoryRange> = ranges.iter().copied().filter(|r| r.executable).collect();
    if readable.is_empty() || executable.is_empty() {
        return None;
    }

    for range in &readable {
        let mut addr = align_up(range.start, 8);
        let end = range.end.saturating_sub(24);
        while addr <= end {
            let name_ptr = std::ptr::read_unaligned(addr as *const u64);
            let sig_ptr = std::ptr::read_unaligned((addr + 8) as *const u64);
            let fn_ptr = std::ptr::read_unaligned((addr + 16) as *const u64) & 0x0000_FFFF_FFFF_FFFF;
            if contains_addr(&executable, fn_ptr, 4)
                && cstr_equals_in_ranges(&readable, name_ptr, name)
                && cstr_equals_in_ranges(&readable, sig_ptr, sig)
            {
                return Some(fn_ptr);
            }
            addr += 8;
        }
    }
    None
}

#[derive(Clone, Copy)]
struct MemoryRange {
    start: u64,
    end: u64,
    readable: bool,
    executable: bool,
}

fn module_memory_ranges(module_name: &str) -> Vec<MemoryRange> {
    let maps = match crate::jsapi::util::read_proc_self_maps() {
        Some(s) => s,
        None => return Vec::new(),
    };
    crate::jsapi::util::proc_maps_entries(&maps)
        .filter_map(|entry| {
            let path = entry.path?;
            if !matches_module_lookup_name(path, module_name) {
                return None;
            }
            let prot = entry.prot_flags();
            Some(MemoryRange {
                start: entry.start,
                end: entry.end,
                readable: prot & libc::PROT_READ != 0,
                executable: prot & libc::PROT_EXEC != 0,
            })
        })
        .collect()
}

fn align_up(value: u64, align: u64) -> u64 {
    (value + align - 1) & !(align - 1)
}

fn contains_addr(ranges: &[MemoryRange], addr: u64, len: u64) -> bool {
    if addr == 0 {
        return false;
    }
    let Some(end) = addr.checked_add(len) else {
        return false;
    };
    ranges.iter().any(|range| addr >= range.start && end <= range.end)
}

unsafe fn cstr_equals_in_ranges(ranges: &[MemoryRange], ptr: u64, expected: &str) -> bool {
    let bytes = expected.as_bytes();
    let total_len = bytes.len() as u64 + 1;
    if !contains_addr(ranges, ptr, total_len) {
        return false;
    }
    let actual = std::slice::from_raw_parts(ptr as *const u8, bytes.len());
    actual == bytes && std::ptr::read(ptr.wrapping_add(bytes.len() as u64) as *const u8) == 0
}

fn dlerror_message() -> Option<String> {
    let err = unsafe { libc::dlerror() };
    if err.is_null() {
        None
    } else {
        Some(unsafe { std::ffi::CStr::from_ptr(err).to_string_lossy().into_owned() })
    }
}

fn is_app_private_path(path: &str) -> bool {
    path.starts_with("/data/user/") || path.starts_with("/data/data/")
}

fn select_app_namespace_caller() -> Option<(u64, String)> {
    enumerate_modules_from_maps()
        .into_iter()
        .filter(|module| {
            let path = module.path.as_str();
            path.ends_with(".so")
                && (path.starts_with("/data/app/")
                    || path.starts_with("/mnt/expand/")
                    || path.starts_with("/data/user/")
                    || path.starts_with("/data/data/"))
        })
        .max_by_key(|module| {
            let path = module.path.as_str();
            let app_lib = path.starts_with("/data/app/") && path.contains("/lib/");
            let private_lib = path.starts_with("/data/user/") || path.starts_with("/data/data/");
            (app_lib as u8, private_lib as u8, module.base)
        })
        .map(|module| (module.base, module.path))
}

/// Load a shared object from disk.
///
/// For app-private files prefer the normal linker path first, then retry with a
/// caller address from an already-loaded app module so Android chooses the app
/// namespace. The unrestricted linker caller is kept as a final fallback for
/// non-app paths that still need the historical Module.load behavior.
pub(crate) unsafe fn module_dlopen_load(
    path: &str,
    flags: i32,
) -> *mut std::ffi::c_void {
    let c_path = match CString::new(path) {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(),
    };

    let _ = libc::dlerror();
    crate::jsapi::console::output_message(&format!(
        "[module] dlopen_load: trying libc dlopen path={} flags=0x{:x}",
        path, flags
    ));
    let handle = libc::dlopen(c_path.as_ptr(), flags);
    crate::jsapi::console::output_message(&format!(
        "[module] dlopen_load: libc dlopen returned {:?}",
        handle
    ));
    if !handle.is_null() {
        return handle;
    }
    if let Some(err) = dlerror_message() {
        crate::jsapi::console::output_message(&format!(
            "[module] dlopen_load: libc dlopen failed: {}",
            err
        ));
    }

    let api = UNRESTRICTED_LINKER_API.get_or_init(|| init_unrestricted_linker_api());
    if let Some(api) = api {
        if let Some((caller, caller_path)) = select_app_namespace_caller() {
            crate::jsapi::console::output_message(&format!(
                "[module] dlopen_load: retry app caller={:#x} ({})",
                caller, caller_path
            ));
            let handle = (api.dlopen)(
                c_path.as_ptr() as *const i8,
                flags,
                caller as *const std::ffi::c_void,
            );
            crate::jsapi::console::output_message(&format!(
                "[module] dlopen_load: app caller returned {:?}",
                handle
            ));
            if !handle.is_null() {
                return handle;
            }
            if let Some(err) = dlerror_message() {
                crate::jsapi::console::output_message(&format!(
                    "[module] dlopen_load: app caller failed: {}",
                    err
                ));
            }
        }

        if is_app_private_path(path) {
            crate::jsapi::console::output_message(
                "[module] dlopen_load: skip linker trusted_caller fallback for app-private path",
            );
            return std::ptr::null_mut();
        }

        crate::jsapi::console::output_message(&format!(
            "[module] dlopen_load: path={} flags=0x{:x} caller={:?}",
            path, flags, api.trusted_caller
        ));
        let handle = (api.dlopen)(
            c_path.as_ptr() as *const i8,
            flags,
            api.trusted_caller,
        );
        crate::jsapi::console::output_message(&format!(
            "[module] dlopen_load: returned {:?}",
            handle
        ));
        return handle;
    }
    std::ptr::null_mut()
}

/// Load a shared object from disk through a tagged memfd.
///
/// This keeps the default `Module.load(path)` behavior unchanged, while allowing
/// callers to opt into a `/memfd:wwb_*` maps marker when requested.
pub(crate) unsafe fn module_dlopen_load_memfd(
    path: &str,
    flags: i32,
    memfd_name: &str,
) -> Result<*mut std::ffi::c_void, String> {
    let blob = std::fs::read(path).map_err(|e| format!("read '{}' failed: {}", path, e))?;
    let c_name = CString::new(memfd_name).map_err(|_| "memfd name contains NUL byte".to_string())?;
    let fd = libc::syscall(libc::SYS_memfd_create as libc::c_long, c_name.as_ptr(), 0) as i32;
    if fd < 0 {
        return Err(format!("memfd_create('{}') failed: {}", memfd_name, std::io::Error::last_os_error()));
    }

    let mut written = 0usize;
    while written < blob.len() {
        let n = libc::write(
            fd,
            blob[written..].as_ptr() as *const std::ffi::c_void,
            blob.len() - written,
        );
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            libc::close(fd);
            return Err(format!("write '{}' to memfd '{}' failed: {}", path, memfd_name, err));
        }
        if n == 0 {
            libc::close(fd);
            return Err(format!("write '{}' to memfd '{}' made no progress", path, memfd_name));
        }
        written += n as usize;
    }

    let handle = memfd_dlopen_with_flags(memfd_name, fd, flags);
    libc::close(fd);
    Ok(handle)
}

/// Load a shared object as if the call came from libart's linker namespace.
/// ART plugins such as libopenjdkjvmti.so live in the ART APEX namespace and
/// may reject the generic linker trusted-caller used for ordinary app modules.
pub(crate) unsafe fn module_dlopen_load_from_libart_namespace(
    path: &str,
    flags: i32,
) -> *mut std::ffi::c_void {
    let c_path = match CString::new(path) {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(),
    };
    let api = UNRESTRICTED_LINKER_API.get_or_init(|| init_unrestricted_linker_api());
    if let Some(api) = api {
        let &(libart_base, _) = LIBART_RANGE.get_or_init(probe_libart_range);
        if libart_base != 0 {
            return (api.dlopen)(
                c_path.as_ptr() as *const i8,
                flags,
                libart_base as *const std::ffi::c_void,
            );
        }
    }
    std::ptr::null_mut()
}

/// Load a shared object from an existing memfd using the linker's trusted-caller API.
pub(crate) unsafe fn memfd_dlopen(name: &str, fd: i32) -> *mut std::ffi::c_void {
    memfd_dlopen_with_flags(name, fd, libc::RTLD_NOW)
}

/// Load a shared object from an existing memfd using caller-provided dlopen flags.
pub(crate) unsafe fn memfd_dlopen_with_flags(name: &str, fd: i32, flags: i32) -> *mut std::ffi::c_void {
    let c_name = match CString::new(name) {
        Ok(value) => value,
        Err(_) => return std::ptr::null_mut(),
    };

    let api = UNRESTRICTED_LINKER_API.get_or_init(|| init_unrestricted_linker_api());
    if let Some(api) = api {
        if let Some(android_dlopen_ext) = api.android_dlopen_ext {
            let extinfo = AndroidDlextinfo {
                flags: 0x10,
                reserved_addr: 0,
                reserved_size: 0,
                relro_fd: 0,
                library_fd: fd,
                library_fd_offset: 0,
                library_namespace: 0,
            };
            crate::jsapi::console::output_message(&format!(
                "[module] memfd_dlopen: name={} fd={} flags=0x{:x} caller={:?}",
                name, fd, flags, api.trusted_caller
            ));
            let handle = android_dlopen_ext(
                c_name.as_ptr() as *const i8,
                flags,
                &extinfo as *const _ as *const std::ffi::c_void,
                api.trusted_caller,
            );
            crate::jsapi::console::output_message(&format!(
                "[module] memfd_dlopen: android_dlopen_ext returned {:?}",
                handle
            ));
            return handle;
        }
    }

    std::ptr::null_mut()
}

/// Resolve a symbol from libart.so by parsing ELF metadata.
pub(crate) unsafe fn libart_dlsym(name: &str) -> *mut std::ffi::c_void {
    let &(libart_base, _) = LIBART_RANGE.get_or_init(probe_libart_range);
    if libart_base == 0 {
        return std::ptr::null_mut();
    }

    let path = match LIBART_PATH.get() {
        Some(Some(path)) => path.clone(),
        _ => match find_module_path_and_base("libart.so") {
            Some((path, _)) => path,
            None => return std::ptr::null_mut(),
        },
    };

    let syms = elf_module_find_symbols(&path, libart_base, &[name]);
    if let Some(&addr) = syms.get(name) {
        return addr as *mut std::ffi::c_void;
    }

    std::ptr::null_mut()
}

/// Resolve a libart symbol by name substring from .symtab/.dynsym.
///
/// This is used for ART internals whose mangled signatures drift across Android
/// releases while the stable semantic name remains present.
pub(crate) unsafe fn libart_find_symbol_contains(needle: &str) -> Option<(String, u64)> {
    let &(libart_base, _) = LIBART_RANGE.get_or_init(probe_libart_range);
    if libart_base == 0 || needle.is_empty() {
        return None;
    }

    let path = match LIBART_PATH.get() {
        Some(Some(path)) => path.clone(),
        _ => match find_module_path_and_base("libart.so") {
            Some((path, _)) => path,
            None => return None,
        },
    };

    let symbols = elf_module_enumerate_symbols(&path, libart_base);
    let mut fallback: Option<(String, u64)> = None;
    for symbol in symbols {
        if symbol.address == 0 || !symbol.is_defined || symbol.kind != "function" {
            continue;
        }
        if !symbol.name.contains(needle) {
            continue;
        }
        if symbol.name.contains("CodeInfo") {
            return Some((symbol.name, symbol.address));
        }
        if fallback.is_none() {
            fallback = Some((symbol.name, symbol.address));
        }
    }
    fallback
}

/// 在多个候选符号中查找第一个可用的（通过 libart_dlsym）
pub(crate) unsafe fn dlsym_first_match(candidates: &[&str]) -> u64 {
    for &sym_name in candidates {
        let addr = libart_dlsym(sym_name);
        if !addr.is_null() {
            return addr as u64;
        }
    }
    0
}

/// Check if an address falls within libart.so.
pub(crate) fn is_in_libart(addr: u64) -> bool {
    if addr == 0 {
        return false;
    }
    let &(start, end) = LIBART_RANGE.get_or_init(probe_libart_range);
    if start != 0 || end != 0 {
        return addr >= start && addr < end;
    }

    find_module_by_address(addr)
        .map(|module| module.name == "libart.so" || module.path.ends_with("/libart.so"))
        .unwrap_or(false)
}

// ============================================================================
// soinfo traversal (Frida-style)
// ============================================================================

/// Walk the linker's soinfo linked list under dl_mutex.
/// Returns Vec<(base_addr, path)> for all loaded modules.
///
/// Reference: gum_enumerate_soinfo() at gumandroid.c:994
///
/// soinfo layout (API 26+):
///   soinfo starts with a ListEntry (prev, next) = 16 bytes
///   body = soinfo + 16 (API 26+) or soinfo + 12 (API 23-25)
///   body->next at body + 0x28 (40 bytes)
///   body->base at body + 0x80 (128 bytes, after phdr/phnum/entry/base)
#[allow(dead_code)]
unsafe fn enumerate_soinfo() -> Vec<(u64, String)> {
    let api = match UNRESTRICTED_LINKER_API.get_or_init(|| init_unrestricted_linker_api()) {
        Some(api) => api,
        None => return Vec::new(),
    };

    // Get soinfo list head
    let head: *mut std::ffi::c_void = if let Some(get_head) = api.solist_get_head {
        get_head()
    } else if !api.solist.is_null() {
        *api.solist
    } else {
        return Vec::new();
    };

    if head.is_null() {
        return Vec::new();
    }

    let soinfo_get_path = match api.soinfo_get_path {
        Some(f) => f,
        None => return Vec::new(),
    };

    let mut result = Vec::new();

    let mut current = head;
    let mut count = 0u32;
    while !current.is_null() && count < 4096 {
        count += 1;

        // Get path via soinfo::get_realpath()
        let path_ptr = soinfo_get_path(current);
        let path = if !path_ptr.is_null() {
            std::ffi::CStr::from_ptr(path_ptr)
                .to_string_lossy()
                .to_string()
        } else {
            String::new()
        };

        // soinfo body: skip ListEntry header (16 bytes on API 26+)
        // body->base is at a known offset — but varies by Android version.
        // For the JS API we use /proc/self/maps instead (more reliable).
        // Here we just collect paths for namespace-aware dlopen.
        let base = find_module_base_for_path(&path);
        if base != 0 || !path.is_empty() {
            result.push((base, path));
        }

        // next soinfo: soinfo is a linked list via ListEntry at offset 0
        // ListEntry { next: *mut soinfo, prev: *mut soinfo }
        // next is at offset 0
        let next = *(current as *const *mut std::ffi::c_void);
        current = next;
    }

    result
}

/// Find base address for a given full path from /proc/self/maps.
fn find_module_base_for_path(path: &str) -> u64 {
    if path.is_empty() {
        return 0;
    }
    let maps = match super::util::read_proc_self_maps() {
        Some(s) => s,
        None => return 0,
    };
    let base = crate::jsapi::util::proc_maps_entries(&maps)
        .find_map(|entry| (entry.path == Some(path)).then_some(entry.start))
        .unwrap_or(0);
    base
}
