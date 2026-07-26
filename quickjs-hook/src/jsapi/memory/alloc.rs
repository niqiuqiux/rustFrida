//! Memory allocation helpers (Frida-compatible).
//!
//! Memory.alloc(size) / Memory.allocUtf8String(str) — 分配堆内存并返回 NativePointer。
//! 分配的内存由 QuickJS 的 finalizer 在 GC 时自动 free，用法与 Frida 完全一致:
//!
//!   var path = Memory.allocUtf8String('/tmp/foo');
//!   var fd = open(path, 0);
//!   // path 被 GC 时 free，无需手动管理
//!
//! 实现细节:
//!   - 为每块分配建一个带 finalizer 的 NativePointer class 实例
//!   - 与现有 ptr() 创建的 NativePointer 共享同一个 class (地址 getter 相同)
//!   - 额外用 JS_SetOpaque 存 owned 堆指针，finalizer 时 libc::free

use crate::ffi;
use crate::jsapi::callback_util::throw_internal_error;
use crate::jsapi::ptr::{create_owned_native_pointer, create_owned_pages_native_pointer};
use crate::jsapi::util::canonicalize_user_address;
use crate::value::JSValue;

/// Android ships 4K, 16K and 64K page devices, so nothing here may assume 4096.
pub(crate) fn query_page_size() -> usize {
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if size > 0 {
        size as usize
    } else {
        4096
    }
}

/// Parse a Frida protection string such as `"rw-"` or `"rwx"` into mmap flags.
pub(crate) fn parse_protection(text: &str) -> Option<i32> {
    let bytes = text.as_bytes();
    if bytes.len() != 3 {
        return None;
    }
    let mut protection = 0;
    match bytes[0] {
        b'r' => protection |= libc::PROT_READ,
        b'-' => {}
        _ => return None,
    }
    match bytes[1] {
        b'w' => protection |= libc::PROT_WRITE,
        b'-' => {}
        _ => return None,
    }
    match bytes[2] {
        b'x' => protection |= libc::PROT_EXEC,
        b'-' => {}
        _ => return None,
    }
    Some(protection)
}

pub(crate) fn format_protection(protection: i32) -> String {
    let mut text = String::with_capacity(3);
    text.push(if protection & libc::PROT_READ != 0 { 'r' } else { '-' });
    text.push(if protection & libc::PROT_WRITE != 0 { 'w' } else { '-' });
    text.push(if protection & libc::PROT_EXEC != 0 { 'x' } else { '-' });
    text
}

/// Not exported by the Android libc bindings. Kernels older than 4.17 ignore the
/// flag and treat the address as a plain hint, which the caller already handles
/// by re-checking the result against the requested window.
const MAP_FIXED_NOREPLACE: i32 = 0x10_0000;

unsafe fn map_pages(size: usize, protection: i32) -> Option<u64> {
    let mapped = libc::mmap(
        std::ptr::null_mut(),
        size,
        protection,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    );
    (mapped != libc::MAP_FAILED).then(|| mapped as u64)
}

/// Try to map `size` bytes within `max_distance` of `near`.
///
/// Candidate addresses come from the gaps between existing mappings, and each
/// attempt is placed with MAP_FIXED_NOREPLACE so a racing mapping is reported
/// rather than silently clobbered. Kernels without that flag fall back to a
/// hint, which the caller re-checks against the requested window.
unsafe fn map_pages_near(size: usize, protection: i32, near: u64, max_distance: u64) -> Option<u64> {
    let page_size = query_page_size();
    let near = canonicalize_user_address(near);
    let window_start = near.saturating_sub(max_distance) & !(page_size as u64 - 1);
    let window_end = near.saturating_add(max_distance);
    if window_end <= window_start {
        return None;
    }

    let maps = crate::jsapi::util::read_proc_self_maps()?;
    let mut occupied: Vec<(u64, u64)> = crate::jsapi::util::proc_maps_entries(&maps)
        .map(|entry| (entry.start, entry.end))
        .collect();
    occupied.sort_unstable();

    // Walk the gaps between mappings, preferring candidates closest to `near`.
    let mut candidates: Vec<u64> = Vec::new();
    let mut cursor = window_start;
    for (start, end) in &occupied {
        if *end <= cursor {
            continue;
        }
        if *start > cursor {
            let gap_end = (*start).min(window_end);
            let mut candidate = cursor;
            while candidate.saturating_add(size as u64) <= gap_end {
                candidates.push(candidate);
                candidate = candidate.saturating_add(page_size as u64);
                if candidates.len() > 4096 {
                    break;
                }
            }
        }
        cursor = cursor.max(*end);
        if cursor >= window_end {
            break;
        }
    }
    while cursor.saturating_add(size as u64) <= window_end && candidates.len() <= 4096 {
        candidates.push(cursor);
        cursor = cursor.saturating_add(page_size as u64);
    }

    candidates.sort_by_key(|candidate| candidate.abs_diff(near));

    for candidate in candidates {
        if candidate == 0 {
            continue;
        }
        let mapped = libc::mmap(
            candidate as *mut libc::c_void,
            size,
            protection,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
            -1,
            0,
        );
        if mapped == libc::MAP_FAILED {
            continue;
        }
        let address = mapped as u64;
        if address >= window_start && address.saturating_add(size as u64) <= window_end {
            return Some(address);
        }
        libc::munmap(mapped, size);
    }
    None
}

struct AllocOptions {
    protection: i32,
    near: Option<u64>,
    max_distance: u64,
}

unsafe fn parse_alloc_options(ctx: *mut ffi::JSContext, value: JSValue) -> Result<AllocOptions, ffi::JSValue> {
    use crate::jsapi::callback_util::extract_pointer_address;

    let mut options = AllocOptions {
        protection: libc::PROT_READ | libc::PROT_WRITE,
        near: None,
        max_distance: 0,
    };
    if value.is_undefined() || value.is_null() {
        return Ok(options);
    }
    if ffi::qjs_is_object(value.raw()) == 0 {
        return Err(throw_internal_error(ctx, "Memory.alloc() options must be an object"));
    }

    let protection = JSValue(ffi::JS_GetPropertyStr(ctx, value.raw(), c"protection".as_ptr()));
    if !protection.is_undefined() && !protection.is_null() {
        let text = protection.to_string(ctx);
        protection.free(ctx);
        let Some(parsed) = text.as_deref().and_then(parse_protection) else {
            return Err(throw_internal_error(
                ctx,
                "Memory.alloc() protection must be a string like \"rwx\"",
            ));
        };
        options.protection = parsed;
    } else {
        protection.free(ctx);
    }

    let near = JSValue(ffi::JS_GetPropertyStr(ctx, value.raw(), c"near".as_ptr()));
    let has_near = !near.is_undefined() && !near.is_null();
    if has_near {
        let address = extract_pointer_address(ctx, near, "Memory.alloc() near");
        near.free(ctx);
        options.near = Some(address?);
    } else {
        near.free(ctx);
    }

    let max_distance = JSValue(ffi::JS_GetPropertyStr(ctx, value.raw(), c"maxDistance".as_ptr()));
    if !max_distance.is_undefined() && !max_distance.is_null() {
        let parsed = max_distance.to_u64(ctx);
        max_distance.free(ctx);
        let Some(parsed) = parsed else {
            return Err(throw_internal_error(
                ctx,
                "Memory.alloc() maxDistance must be an integer",
            ));
        };
        options.max_distance = parsed;
    } else {
        max_distance.free(ctx);
    }

    if options.near.is_some() && options.max_distance == 0 {
        return Err(throw_internal_error(
            ctx,
            "Memory.alloc() maxDistance is required when near is given",
        ));
    }
    Ok(options)
}

/// `Memory.alloc(size[, options])` — allocate memory owned by the returned
/// NativePointer.
///
/// Matches upstream: sub-page sizes come from the heap and are read/write, so
/// asking for executable memory or placement near an address requires a
/// page-multiple size. Whole-page requests are mapped with the requested
/// protection and unmapped when the last derived pointer is collected.
pub(super) unsafe extern "C" fn memory_alloc(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(ctx, b"Memory.alloc() requires 1 argument: size\0".as_ptr() as *const _);
    }
    let size = match JSValue(*argv).to_i64(ctx) {
        Some(value) if value > 0 && value <= 0x7fff_ffff => value as usize,
        _ => return throw_internal_error(ctx, "Memory.alloc() invalid size"),
    };
    let options = match parse_alloc_options(
        ctx,
        if argc >= 2 {
            JSValue(*argv.add(1))
        } else {
            JSValue::undefined()
        },
    ) {
        Ok(value) => value,
        Err(error) => return error,
    };

    let page_size = query_page_size();
    let page_aligned = size % page_size == 0;

    if let Some(near) = options.near {
        if !page_aligned {
            return throw_internal_error(ctx, "Memory.alloc() size must be a multiple of page size");
        }
        let Some(address) = map_pages_near(size, options.protection, near, options.max_distance) else {
            return throw_internal_error(ctx, "Memory.alloc() unable to allocate free page(s) near address");
        };
        return create_owned_pages_native_pointer(ctx, address, size).raw();
    }

    if !page_aligned {
        if options.protection & libc::PROT_EXEC != 0 {
            return throw_internal_error(ctx, "Memory.alloc() size must be a multiple of page size");
        }
        let memory = libc::calloc(1, size);
        if memory.is_null() {
            return throw_internal_error(ctx, "Memory.alloc() out of memory");
        }
        return create_owned_native_pointer(ctx, memory as u64).raw();
    }

    let Some(address) = map_pages(size, options.protection) else {
        return throw_internal_error(ctx, "Memory.alloc() out of memory");
    };
    create_owned_pages_native_pointer(ctx, address, size).raw()
}

/// Memory.flushCodeCache(addr, size) - 刷新 instruction cache
///
/// 用于自修改代码场景：写入新指令后必须调用此函数，否则 CPU 可能执行
/// 陈旧的缓存行导致未定义行为。
///
/// ARM64 需要: DC CVAU + DSB ISH + IC IVAU + DSB ISH + ISB
/// 直接调 __builtin___clear_cache 让 libclang_rt 实现这个序列。
/// `Memory.protect(addr, size, protection)` — 页级 mprotect.
/// protection: "rwx" 风格 3 字符, '-' = 空缺位. 例 "r-x" "rw-" "---".
/// addr 自动 round-down 到页首; size 自动 round-up 到页尾.
/// 返回 true = 成功; 失败抛 RangeError 带 errno 信息.
///
/// 只挂在 Memory 命名空间, 不挂 NativePointer prototype — protect 是页级
/// 语义, 挂在单个指针上容易误导 (改的不是这个指针本身, 是所在页整页).
pub(super) unsafe extern "C" fn memory_protect(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    use crate::jsapi::callback_util::extract_pointer_address;

    if argc < 3 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Memory.protect(addr, size, protection) requires 3 arguments\0".as_ptr() as *const _,
        );
    }
    let addr = match extract_pointer_address(ctx, JSValue(*argv), "Memory.protect") {
        Ok(a) => a,
        Err(e) => return e,
    };
    let size = match JSValue(*argv.add(1)).to_i64(ctx) {
        Some(n) if (0..=0x7fff_ffff).contains(&n) => n as usize,
        _ => {
            return ffi::JS_ThrowTypeError(ctx, b"Memory.protect: invalid size\0".as_ptr() as *const _);
        }
    };
    let prot_str = match JSValue(*argv.add(2)).to_string(ctx) {
        Some(s) => s,
        None => {
            return ffi::JS_ThrowTypeError(
                ctx,
                b"Memory.protect: protection must be string (e.g. \"rwx\")\0".as_ptr() as *const _,
            );
        }
    };

    let b = prot_str.as_bytes();
    if b.len() != 3 || !matches!(b[0], b'r' | b'-') || !matches!(b[1], b'w' | b'-') || !matches!(b[2], b'x' | b'-') {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Memory.protect: protection must be 3-char string like \"rwx\"\0".as_ptr() as *const _,
        );
    }
    let mut prot: i32 = 0;
    if b[0] == b'r' {
        prot |= libc::PROT_READ;
    }
    if b[1] == b'w' {
        prot |= libc::PROT_WRITE;
    }
    if b[2] == b'x' {
        prot |= libc::PROT_EXEC;
    }

    if size == 0 {
        return JSValue::bool(true).raw();
    }

    // Android devices may use 4K, 16K, or 64K pages.
    let page_size = libc::sysconf(libc::_SC_PAGESIZE);
    if page_size <= 0 {
        return ffi::JS_ThrowInternalError(ctx, b"Memory.protect: unable to query page size\0".as_ptr() as *const _);
    }
    let page_size = page_size as usize;
    let addr = canonicalize_user_address(addr);
    let range_end = match (addr as usize).checked_add(size) {
        Some(value) => value,
        None => return ffi::JS_ThrowRangeError(ctx, b"Memory.protect: address range overflow\0".as_ptr() as *const _),
    };
    let page_start = (addr as usize) & !(page_size - 1);
    let page_end = match range_end.checked_add(page_size - 1) {
        Some(value) => value & !(page_size - 1),
        None => return ffi::JS_ThrowRangeError(ctx, b"Memory.protect: address range overflow\0".as_ptr() as *const _),
    };
    let page_len = page_end - page_start;

    if libc::mprotect(page_start as *mut libc::c_void, page_len, prot) != 0 {
        let err = std::io::Error::last_os_error();
        let msg = format!("Memory.protect({:#x}, {}, \"{}\"): {}\0", addr, size, prot_str, err);
        return ffi::JS_ThrowRangeError(ctx, msg.as_ptr() as *const _);
    }
    JSValue::bool(true).raw()
}

pub(super) unsafe extern "C" fn memory_flush_code_cache(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    use crate::jsapi::callback_util::extract_pointer_address;
    if argc < 2 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Memory.flushCodeCache() requires (addr, size)\0".as_ptr() as *const _,
        );
    }
    let addr = match extract_pointer_address(ctx, JSValue(*argv), "Memory.flushCodeCache") {
        Ok(a) => a,
        Err(e) => return e,
    };
    let size = match JSValue(*argv.add(1)).to_i64(ctx) {
        Some(n) if n > 0 => n as usize,
        _ => {
            return ffi::JS_ThrowTypeError(
                ctx,
                b"Memory.flushCodeCache() size must be positive\0".as_ptr() as *const _,
            );
        }
    };

    extern "C" {
        fn __clear_cache(start: *mut std::ffi::c_void, end: *mut std::ffi::c_void);
    }
    let addr = canonicalize_user_address(addr);
    let start = addr as *mut std::ffi::c_void;
    let end = (addr as usize + size) as *mut std::ffi::c_void;
    __clear_cache(start, end);
    JSValue::undefined().raw()
}

/// Memory.allocUtf8String(str) - 分配并拷贝 UTF-8 字符串 (null-terminated)
pub(super) unsafe extern "C" fn memory_alloc_utf8_string(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Memory.allocUtf8String() requires 1 argument: str\0".as_ptr() as *const _,
        );
    }
    let s = match JSValue(*argv).to_string(ctx) {
        Some(s) => s,
        None => {
            return ffi::JS_ThrowTypeError(
                ctx,
                b"Memory.allocUtf8String() argument must be a string\0".as_ptr() as *const _,
            );
        }
    };

    let bytes = s.as_bytes();
    let total = bytes.len() + 1; // + null terminator
    let mem = libc::malloc(total);
    if mem.is_null() {
        return ffi::JS_ThrowInternalError(ctx, b"Memory.allocUtf8String() out of memory\0".as_ptr() as *const _);
    }
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), mem as *mut u8, bytes.len());
    *(mem as *mut u8).add(bytes.len()) = 0;
    let addr = mem as u64;
    create_owned_native_pointer(ctx, addr).raw()
}

/// Memory.allocUtf16String(str) - allocate a native-endian UTF-16 string.
pub(super) unsafe extern "C" fn memory_alloc_utf16_string(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Memory.allocUtf16String() requires 1 argument: str\0".as_ptr() as *const _,
        );
    }
    let string = match JSValue(*argv).to_string(ctx) {
        Some(value) => value,
        None => {
            return ffi::JS_ThrowTypeError(
                ctx,
                b"Memory.allocUtf16String() argument must be a string\0".as_ptr() as *const _,
            )
        }
    };
    let units: Vec<u16> = string.encode_utf16().chain(std::iter::once(0)).collect();
    let byte_length = units.len() * std::mem::size_of::<u16>();
    let memory = libc::malloc(byte_length);
    if memory.is_null() {
        return ffi::JS_ThrowInternalError(ctx, b"Memory.allocUtf16String() out of memory\0".as_ptr() as *const _);
    }
    std::ptr::copy_nonoverlapping(units.as_ptr(), memory as *mut u16, units.len());
    create_owned_native_pointer(ctx, memory as u64).raw()
}

pub(super) unsafe extern "C" fn memory_alloc_ansi_string(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    ffi::JS_ThrowTypeError(ctx, b"ANSI API is only applicable on Windows\0".as_ptr() as *const _)
}
