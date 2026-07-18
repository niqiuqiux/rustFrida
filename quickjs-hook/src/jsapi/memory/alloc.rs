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
use crate::jsapi::ptr::create_owned_native_pointer;
use crate::jsapi::util::canonicalize_user_address;
use crate::value::JSValue;

/// Memory.alloc(size) - 分配 size 字节，返回 NativePointer
pub(super) unsafe extern "C" fn memory_alloc(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(ctx, b"Memory.alloc() requires 1 argument: size\0".as_ptr() as *const _);
    }
    let size_arg = JSValue(*argv);
    let size = match size_arg.to_i64(ctx) {
        Some(s) if s > 0 => s as usize,
        _ => {
            return ffi::JS_ThrowTypeError(
                ctx,
                b"Memory.alloc() size must be a positive integer\0".as_ptr() as *const _,
            );
        }
    };
    if size > 256 * 1024 * 1024 {
        return ffi::JS_ThrowRangeError(ctx, b"Memory.alloc() size too large (max 256MB)\0".as_ptr() as *const _);
    }

    let mem = libc::calloc(1, size);
    if mem.is_null() {
        return ffi::JS_ThrowInternalError(ctx, b"Memory.alloc() out of memory\0".as_ptr() as *const _);
    }
    let addr = mem as u64;
    create_owned_native_pointer(ctx, addr).raw()
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
