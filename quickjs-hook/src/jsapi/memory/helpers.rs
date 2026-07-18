//! Memory helper functions

use crate::ffi;
use crate::jsapi::ptr::get_native_pointer_addr;
use crate::value::JSValue;

/// Helper to get address from argument
pub(super) unsafe fn get_addr_from_arg(ctx: *mut ffi::JSContext, val: JSValue) -> Option<u64> {
    get_native_pointer_addr(ctx, val).or_else(|| val.to_u64(ctx))
}

/// 从 NativePointer this 或 argv[0] 取地址，返回 (addr, remaining_argv, remaining_argc)。
/// 适配两种调用风格:
///   - `Memory.readU32(addr)` → this 不是 NativePointer, addr = argv[0]
///   - `ptr(addr).readU32()` → this 是 NativePointer, addr = this
pub(super) unsafe fn get_addr_this_or_arg(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> Option<(u64, *mut ffi::JSValue, i32)> {
    // 先尝试从 this 取（NativePointer 方法风格）
    if let Some(addr) = get_native_pointer_addr(ctx, JSValue(this)) {
        return Some((addr, argv, argc));
    }
    // Fallback: Memory.readXxx(addr, ...) 风格，argv[0] 是地址
    if argc < 1 {
        return None;
    }
    let addr = get_addr_from_arg(ctx, JSValue(*argv))?;
    Some((addr, argv.add(1), argc - 1))
}
