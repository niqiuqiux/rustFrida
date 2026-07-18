//! js_hook, js_unhook, js_call_native implementations

use crate::ffi;
use crate::ffi::hook as hook_ffi;
use crate::jsapi::callback_util::{
    dup_callback_to_bytes, ensure_function_arg, extract_pointer_address, get_js_u64_property,
    js_i64_to_js_number_or_bigint, js_value_to_u64_or_zero, set_js_cfunction_property, set_js_u64_property,
    throw_internal_error,
};
use crate::jsapi::ptr::create_native_pointer;
use crate::jsapi::stalker::with_stalker_native_call;
use crate::jsapi::util::is_addr_accessible;
use crate::value::JSValue;

use super::callback::{
    attach_on_enter_wrapper, attach_on_leave_wrapper, hook_callback_wrapper, native_attach_on_enter_wrapper,
    native_attach_on_leave_wrapper, NativeAttachCallbacks,
};
use super::cmodule::is_cmodule_code_address;
use super::registry::{
    self, hook_error_message, init_registry, HookData, HookKind, InterceptorListenerData, StealthMode, HOOK_OK,
    HOOK_REGISTRY,
};
use crate::jsapi::callback_util::with_registry_mut;

unsafe fn finalize_recomp_hook_slot(
    hook_addr: u64,
    orig_addr: u64,
    trampoline: *mut std::ffi::c_void,
) -> Result<(), String> {
    if trampoline.is_null() {
        return Err("recomp hook trampoline is null".to_string());
    }
    if let Err(e) = crate::recomp::fixup_slot_trampoline(trampoline as *mut u8, orig_addr as usize) {
        let _ = crate::recomp::try_revert_slot_patch(orig_addr as usize);
        return Err(format!("recomp fixup trampoline: {}", e));
    }
    let ret = hook_ffi::hook_mark_recomp_hook(hook_addr as *mut std::ffi::c_void);
    if ret != HOOK_OK {
        let _ = crate::recomp::try_revert_slot_patch(orig_addr as usize);
        return Err(format!("recomp mark hook: {}", hook_error_str(ret)));
    }
    if let Err(e) = crate::recomp::commit_slot_patch(orig_addr as usize) {
        let _ = crate::recomp::try_revert_slot_patch(orig_addr as usize);
        return Err(format!("recomp commit slot: {}", e));
    }
    Ok(())
}

/// hook(ptr, callback, mode?) - Install a hook at the given address
///
/// mode: Hook.NORMAL (0, default), Hook.WXSHADOW (1) / true, Hook.RECOMP (2)
pub(crate) unsafe extern "C" fn js_hook(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return ffi::JS_ThrowTypeError(ctx, b"hook() requires at least 2 arguments\0".as_ptr() as *const _);
    }

    let ptr_arg = JSValue(*argv);
    let callback_arg = JSValue(*argv.add(1));

    // 解析 stealth 模式：0=Normal, 1/true=WxShadow, 2=Recomp
    let mode = if argc >= 3 {
        let mode_arg = JSValue(*argv.add(2));
        match mode_arg.to_i64(ctx) {
            Some(v) => StealthMode::from_js_arg(v),
            // bool true → WxShadow（向后兼容）
            None if mode_arg.to_bool() == Some(true) => StealthMode::WxShadow,
            None => StealthMode::Normal,
        }
    } else {
        StealthMode::Normal
    };

    install_hook(ctx, ptr_arg, callback_arg, mode)
}

/// recompHook(ptr, callback) - 便捷函数，等价于 hook(ptr, callback, Hook.RECOMP)
pub(crate) unsafe extern "C" fn js_recomp_hook(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return ffi::JS_ThrowTypeError(ctx, b"recompHook() requires 2 arguments\0".as_ptr() as *const _);
    }

    let ptr_arg = JSValue(*argv);
    let callback_arg = JSValue(*argv.add(1));

    install_hook(ctx, ptr_arg, callback_arg, StealthMode::Recomp)
}

/// 统一 hook 安装逻辑
unsafe fn install_hook(
    ctx: *mut ffi::JSContext,
    ptr_arg: JSValue,
    callback_arg: JSValue,
    mode: StealthMode,
) -> ffi::JSValue {
    let addr = match extract_pointer_address(ctx, ptr_arg, "hook") {
        Ok(a) => a,
        Err(e) => return e,
    };

    if let Err(err) = ensure_function_arg(ctx, callback_arg, b"hook() second argument must be a function\0") {
        return err;
    }

    init_registry();

    // 方案 (b): 同一 addr 重复 hook 自动替换老 hook。
    // 先拆掉旧 hook（恢复 recomp 页字节 + 回收 slot + 释放老 callback），
    // 等 in-flight native callback 退出，再装新 hook。避免 HashMap.insert
    // 覆盖 HookData 后 slot 泄漏 + orig_insn 被当成"B→老 slot"污染 callOriginal。
    if let Some(old_data) = with_registry_mut(&HOOK_REGISTRY, |registry| registry.remove(&addr)).flatten() {
        super::remove_single_hook(addr, &old_data);
        // 短 wait 给当前在 thunk 内的 callback 退出；超时就放弃 free（old callback
        // 泄漏一次，callback_wrapper 自带 "not a function" 校验不会崩）。
        if old_data.kind == HookKind::Interceptor
            || super::callback::wait_for_in_flight_native_hook_callbacks(std::time::Duration::from_millis(20))
        {
            super::free_hook_callback(addr, &old_data);
        }
    }

    // Recomp 模式：先重编译页，再分配跳板 slot
    // alloc_trampoline_slot 在 recomp 代码页写 B→slot，返回 slot 地址。
    // hook engine 以 stealth=0 在 slot 上写 full jump→thunk，无需碰原始 SO。
    let (hook_addr, recomp_addr) = match mode {
        StealthMode::Recomp => {
            // 确保页已重编译
            if let Err(e) = crate::recomp::ensure_and_translate(addr as usize) {
                return throw_internal_error(ctx, &format!("hook(recomp): {}", e));
            }
            // 分配跳板 slot（recomp 跳板区，B range 内保证）
            match crate::recomp::alloc_trampoline_slot(addr as usize) {
                Ok(slot) => (slot as u64, slot as u64),
                Err(e) => return throw_internal_error(ctx, &format!("hook(recomp slot): {}", e)),
            }
        }
        _ => (addr, 0),
    };

    let callback_bytes = dup_callback_to_bytes(ctx, callback_arg.raw());

    let stealth_flag = match mode {
        StealthMode::WxShadow => 1,
        _ => 0,
    };

    let trampoline = hook_ffi::hook_replace(
        hook_addr as *mut std::ffi::c_void,
        Some(hook_callback_wrapper),
        addr as *mut std::ffi::c_void, // user_data = 原始地址（registry key）
        stealth_flag,
    );

    if trampoline.is_null() {
        let callback: ffi::JSValue = std::ptr::read(callback_bytes.as_ptr() as *const ffi::JSValue);
        ffi::qjs_free_value(ctx, callback);
        return throw_internal_error(ctx, "hook_replace failed: could not install hook");
    }

    // Recomp: fixup trampoline + commit B 指令
    if mode == StealthMode::Recomp {
        if let Err(e) = finalize_recomp_hook_slot(hook_addr, addr, trampoline) {
            let callback: ffi::JSValue = std::ptr::read(callback_bytes.as_ptr() as *const ffi::JSValue);
            ffi::qjs_free_value(ctx, callback);
            hook_ffi::hook_remove(hook_addr as *mut std::ffi::c_void);
            return throw_internal_error(ctx, &format!("hook(recomp): {}", e));
        }
    }

    with_registry_mut(&HOOK_REGISTRY, |registry| {
        registry.insert(
            addr,
            HookData {
                ctx: ctx as usize,
                callback_bytes,
                on_leave_bytes: [0u8; 16],
                has_on_enter: true,
                has_on_leave: false,
                trampoline: trampoline as u64,
                kind: HookKind::Replace,
                mode,
                recomp_addr,
                native_attach_data: 0,
            },
        );
    });

    JSValue::bool(true).raw()
}

/// unhook(ptr) - Remove a hook at the given address
pub(crate) unsafe extern "C" fn js_unhook(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(ctx, b"unhook() requires 1 argument\0".as_ptr() as *const _);
    }

    let ptr_arg = JSValue(*argv);

    let addr = match extract_pointer_address(ctx, ptr_arg, "unhook") {
        Ok(a) => a,
        Err(e) => return e,
    };

    let registry_data = with_registry_mut(&HOOK_REGISTRY, |registry| registry.remove(&addr)).flatten();

    if let Some(data) = registry_data {
        super::remove_single_hook(addr, &data);
        super::free_hook_callback(addr, &data);
        return JSValue::bool(true).raw();
    }

    // registry 中不存在, 可能是:
    //  1) writest 留下的 slot (无 HookData) — try_revert_slot_patch 恢复 recomp 页字节
    //  2) writeBytes(bytes, 1) 留下的 stealth1 patch — wxshadow_release 通过 kernel_hook 恢复
    //  3) 普通 stealth=0 hook 未登记但 hook engine 已 attach — hook_remove 恢复
    // 三路都静默尝试; 全不命中才报错.
    let slot_cleared = crate::recomp::try_revert_slot_patch(addr as usize);
    let wxshadow_released = ffi::hook::wxshadow_release(addr as *mut std::ffi::c_void) == 0;
    if wxshadow_released {
        crate::jsapi::memory::untrack_wxshadow_addr(addr);
    }
    let hook_removed = hook_ffi::hook_remove(addr as *mut std::ffi::c_void) == HOOK_OK;

    if !slot_cleared && !wxshadow_released && !hook_removed {
        return ffi::JS_ThrowInternalError(
            ctx,
            b"unhook: no hook/writest/wxshadow patch registered at address\0".as_ptr() as *const _,
        );
    }

    JSValue::bool(true).raw()
}

/// callNative(ptr, arg0?, arg1?, ..., arg5?) - Call a native function at addr with 0-6 args.
/// Arguments are passed in x0-x5 (ARM64 calling convention). Unspecified args default to 0.
/// Return value: Number when result fits exactly in f64 (≤ 2^53), BigUint64 otherwise.
pub(crate) unsafe extern "C" fn js_call_native(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(ctx, b"callNative() requires at least 1 argument\0".as_ptr() as *const _);
    }

    let ptr_arg = JSValue(*argv);

    let addr = match extract_pointer_address(ctx, ptr_arg, "callNative") {
        Ok(a) => a,
        Err(e) => return e,
    };

    if addr < 0x10000 {
        return ffi::JS_ThrowRangeError(ctx, b"callNative() address is not mapped\0".as_ptr() as *const _);
    }

    if !is_addr_accessible(addr, 4) {
        return ffi::JS_ThrowRangeError(ctx, b"callNative() address is not mapped\0".as_ptr() as *const _);
    }

    if !is_cmodule_code_address(addr) {
        if !crate::jsapi::module::is_address_in_loaded_module(addr) {
            return ffi::JS_ThrowRangeError(
                ctx,
                b"callNative() address is not in an executable segment\0".as_ptr() as *const _,
            );
        }
    }

    let mut args = [0u64; 6];
    for i in 0..6usize {
        if (i + 1) < argc as usize {
            let arg = JSValue(*argv.add(i + 1));
            args[i] = js_value_to_u64_or_zero(ctx, arg);
        }
    }

    let func: unsafe extern "C" fn(u64, u64, u64, u64, u64, u64) -> i64 = std::mem::transmute(addr as usize);
    let result =
        match with_stalker_native_call(ctx, addr, || func(args[0], args[1], args[2], args[3], args[4], args[5])) {
            Ok(result) => result,
            Err(error) => return throw_internal_error(ctx, &format!("callNative: {error}")),
        };

    js_i64_to_js_number_or_bigint(ctx, result)
}

/// hookNative(target, callbackPtr, userData?, mode?)
///
/// Installs a native HookCallback directly on the hot path:
///   void callback(HookContext *ctx, void *user_data)
///
/// The callback may modify ctx->x[0] as the return value, or call
/// hook_invoke_trampoline(ctx, ctx->trampoline) from C to invoke the original.
pub(crate) unsafe extern "C" fn js_hook_native(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"hookNative(target, callbackPtr, userData?, mode?) requires target and callback\0".as_ptr() as *const _,
        );
    }

    let target = match extract_pointer_address(ctx, JSValue(*argv), "hookNative target") {
        Ok(a) => a,
        Err(e) => return e,
    };
    let callback_addr = match extract_pointer_address(ctx, JSValue(*argv.add(1)), "hookNative callback") {
        Ok(a) => a,
        Err(e) => return e,
    };
    if callback_addr < 0x10000 || !is_addr_accessible(callback_addr, 4) {
        return ffi::JS_ThrowRangeError(ctx, b"hookNative callback address is not mapped\0".as_ptr() as *const _);
    }

    let user_data = if argc >= 3 {
        js_value_to_u64_or_zero(ctx, JSValue(*argv.add(2)))
    } else {
        0
    };
    let mode = if argc >= 4 {
        parse_stealth_mode(ctx, JSValue(*argv.add(3)))
    } else {
        StealthMode::Normal
    };

    init_registry();

    if let Some(old_data) = with_registry_mut(&HOOK_REGISTRY, |registry| registry.remove(&target)).flatten() {
        super::remove_single_hook(target, &old_data);
        if old_data.kind == HookKind::Interceptor
            || super::callback::wait_for_in_flight_native_hook_callbacks(std::time::Duration::from_millis(20))
        {
            super::free_hook_callback(target, &old_data);
        }
    }

    let (hook_addr, recomp_addr) = match mode {
        StealthMode::Recomp => {
            if let Err(e) = crate::recomp::ensure_and_translate(target as usize) {
                return throw_internal_error(ctx, &format!("hookNative(recomp): {}", e));
            }
            match crate::recomp::alloc_trampoline_slot(target as usize) {
                Ok(slot) => (slot as u64, slot as u64),
                Err(e) => return throw_internal_error(ctx, &format!("hookNative(recomp slot): {}", e)),
            }
        }
        _ => (target, 0),
    };

    let stealth_flag = match mode {
        StealthMode::WxShadow => 1,
        _ => 0,
    };
    let callback_fn: unsafe extern "C" fn(*mut hook_ffi::HookContext, *mut std::ffi::c_void) =
        std::mem::transmute(callback_addr as usize);

    let trampoline = hook_ffi::hook_replace(
        hook_addr as *mut std::ffi::c_void,
        Some(callback_fn),
        user_data as *mut std::ffi::c_void,
        stealth_flag,
    );
    if trampoline.is_null() {
        return throw_internal_error(ctx, "hookNative: hook_replace failed");
    }

    if mode == StealthMode::Recomp {
        if let Err(e) = finalize_recomp_hook_slot(hook_addr, target, trampoline) {
            hook_ffi::hook_remove(hook_addr as *mut std::ffi::c_void);
            return throw_internal_error(ctx, &format!("hookNative(recomp): {}", e));
        }
    }

    with_registry_mut(&HOOK_REGISTRY, |registry| {
        registry.insert(
            target,
            HookData {
                ctx: ctx as usize,
                callback_bytes: [0u8; 16],
                on_leave_bytes: [0u8; 16],
                has_on_enter: false,
                has_on_leave: false,
                trampoline: trampoline as u64,
                kind: HookKind::Replace,
                mode,
                recomp_addr,
                native_attach_data: 0,
            },
        );
    });

    create_native_pointer(ctx, trampoline as u64).raw()
}

/// attachNative(target, onEnterPtr, userData?, mode?)
/// attachNative(target, { onEnter?, onLeave?, data?, mode? })
///
/// Installs a native onEnter callback with hook_attach(). The hook engine calls
/// the original function automatically after onEnter returns. If no native
/// onLeave is installed, the hook engine tail-jumps to the original function.
pub(crate) unsafe extern "C" fn js_attach_native(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"attachNative(target, callbackPtr|options, userData?, mode?) requires target and callback\0".as_ptr()
                as *const _,
        );
    }

    let target = match extract_pointer_address(ctx, JSValue(*argv), "attachNative target") {
        Ok(a) => a,
        Err(e) => return e,
    };
    type NativeHookCallback = unsafe extern "C" fn(*mut hook_ffi::HookContext, *mut std::ffi::c_void);

    let callback_arg = JSValue(*argv.add(1));
    let on_enter_prop = callback_arg.get_property(ctx, "onEnter");
    let on_leave_prop = callback_arg.get_property(ctx, "onLeave");
    let is_options = callback_arg.is_object() && (!on_enter_prop.is_undefined() || !on_leave_prop.is_undefined());

    let (on_enter_addr, on_leave_addr, user_data, mode) = if is_options {
        let data_prop = callback_arg.get_property(ctx, "data");
        let mode_prop = callback_arg.get_property(ctx, "mode");
        let parsed = (|| -> Result<(u64, u64, u64, StealthMode), ffi::JSValue> {
            let on_enter = if on_enter_prop.is_undefined() || on_enter_prop.is_null() {
                0
            } else {
                extract_pointer_address(ctx, on_enter_prop, "attachNative onEnter")?
            };
            let on_leave = if on_leave_prop.is_undefined() || on_leave_prop.is_null() {
                0
            } else {
                extract_pointer_address(ctx, on_leave_prop, "attachNative onLeave")?
            };
            if on_enter == 0 && on_leave == 0 {
                return Err(ffi::JS_ThrowTypeError(
                    ctx,
                    b"attachNative options must provide onEnter or onLeave\0".as_ptr() as *const _,
                ));
            }
            let data = if data_prop.is_undefined() || data_prop.is_null() {
                0
            } else {
                js_value_to_u64_or_zero(ctx, data_prop)
            };
            let parsed_mode = if mode_prop.is_undefined() || mode_prop.is_null() {
                StealthMode::Normal
            } else {
                parse_stealth_mode(ctx, mode_prop)
            };
            Ok((on_enter, on_leave, data, parsed_mode))
        })();
        data_prop.free(ctx);
        mode_prop.free(ctx);
        match parsed {
            Ok(v) => v,
            Err(e) => {
                on_enter_prop.free(ctx);
                on_leave_prop.free(ctx);
                return e;
            }
        }
    } else {
        let on_enter = match extract_pointer_address(ctx, callback_arg, "attachNative callback") {
            Ok(a) => a,
            Err(e) => {
                on_enter_prop.free(ctx);
                on_leave_prop.free(ctx);
                return e;
            }
        };
        let data = if argc >= 3 {
            js_value_to_u64_or_zero(ctx, JSValue(*argv.add(2)))
        } else {
            0
        };
        let parsed_mode = if argc >= 4 {
            parse_stealth_mode(ctx, JSValue(*argv.add(3)))
        } else {
            StealthMode::Normal
        };
        (on_enter, 0, data, parsed_mode)
    };
    on_enter_prop.free(ctx);
    on_leave_prop.free(ctx);

    if on_enter_addr != 0 && (on_enter_addr < 0x10000 || !is_addr_accessible(on_enter_addr, 4)) {
        return ffi::JS_ThrowRangeError(
            ctx,
            b"attachNative onEnter address is not mapped\0".as_ptr() as *const _,
        );
    }
    if on_leave_addr != 0 && (on_leave_addr < 0x10000 || !is_addr_accessible(on_leave_addr, 4)) {
        return ffi::JS_ThrowRangeError(
            ctx,
            b"attachNative onLeave address is not mapped\0".as_ptr() as *const _,
        );
    }

    init_registry();
    if let Some(old_data) = with_registry_mut(&HOOK_REGISTRY, |registry| registry.remove(&target)).flatten() {
        super::remove_single_hook(target, &old_data);
        if old_data.kind == HookKind::Interceptor
            || super::callback::wait_for_in_flight_native_hook_callbacks(std::time::Duration::from_millis(20))
        {
            super::free_hook_callback(target, &old_data);
        }
    }

    let (hook_addr, recomp_addr) = match mode {
        StealthMode::Recomp => {
            if let Err(e) = crate::recomp::ensure_and_translate(target as usize) {
                return throw_internal_error(ctx, &format!("attachNative(recomp): {}", e));
            }
            match crate::recomp::alloc_trampoline_slot(target as usize) {
                Ok(slot) => (slot as u64, slot as u64),
                Err(e) => return throw_internal_error(ctx, &format!("attachNative(recomp slot): {}", e)),
            }
        }
        _ => (target, 0),
    };
    let stealth_flag = match mode {
        StealthMode::WxShadow => 1,
        _ => 0,
    };
    let user_on_enter_fn: Option<NativeHookCallback> = if on_enter_addr == 0 {
        None
    } else {
        Some(std::mem::transmute(on_enter_addr as usize))
    };
    let user_on_leave_fn: Option<NativeHookCallback> = if on_leave_addr == 0 {
        None
    } else {
        Some(std::mem::transmute(on_leave_addr as usize))
    };
    let native_attach_data = Box::into_raw(Box::new(NativeAttachCallbacks {
        on_enter: user_on_enter_fn,
        on_leave: user_on_leave_fn,
        user_data: user_data as *mut std::ffi::c_void,
    })) as usize;
    let on_enter_fn: Option<NativeHookCallback> = if user_on_enter_fn.is_some() {
        Some(native_attach_on_enter_wrapper)
    } else {
        None
    };
    let on_leave_fn: Option<NativeHookCallback> = if user_on_leave_fn.is_some() {
        Some(native_attach_on_leave_wrapper)
    } else {
        None
    };
    let result = hook_ffi::hook_attach(
        hook_addr as *mut std::ffi::c_void,
        on_enter_fn,
        on_leave_fn,
        native_attach_data as *mut std::ffi::c_void,
        stealth_flag,
    );
    if result != HOOK_OK {
        super::callback::free_native_attach_callbacks(native_attach_data);
        return throw_internal_error(ctx, &format!("attachNative: {}", hook_error_str(result)));
    }
    if mode == StealthMode::Recomp {
        let trampoline = hook_ffi::hook_get_trampoline(hook_addr as *mut std::ffi::c_void);
        if let Err(e) = finalize_recomp_hook_slot(hook_addr, target, trampoline) {
            super::callback::free_native_attach_callbacks(native_attach_data);
            hook_ffi::hook_remove(hook_addr as *mut std::ffi::c_void);
            return throw_internal_error(ctx, &format!("attachNative(recomp): {}", e));
        }
    }

    with_registry_mut(&HOOK_REGISTRY, |registry| {
        registry.insert(
            target,
            HookData {
                ctx: ctx as usize,
                callback_bytes: [0u8; 16],
                on_leave_bytes: [0u8; 16],
                has_on_enter: false,
                has_on_leave: false,
                trampoline: 0,
                kind: HookKind::Attach,
                mode,
                recomp_addr,
                native_attach_data,
            },
        );
    });

    JSValue::bool(true).raw()
}

// ─────────────────────────── NativeFunction API ──────────────────────────────
//
// Frida-compatible native 函数调用器。通过 ARM64 AAPCS64 register-passing
// 约定调用任意签名的 native 函数，支持最多 8 个整数参数 (x0-x7) + 8 个浮点
// 参数 (d0-d7)，以及 void/bool/int*/long/size_t/pointer/float/double 返回值。
//
// 使用方式（与 Frida 完全一致）:
//   var open = new NativeFunction(
//       Module.findExportByName('libc.so', 'open'),
//       'int',
//       ['pointer', 'int']
//   );
//   var fd = open(Memory.allocUtf8String('/tmp/foo'), 2);
//
// 实现：NativeFunction 在 JS 侧通过 boot script 定义（native_boot.js），
// 它创建一个闭包保存 addr/retType/argTypes，每次调用时把参数分拆到 GPR/FPR
// 数组，然后调 __nativeCall(addr, retTypeKind, gprBytes, fprBytes) native 函数。
// native 函数通过 native_call_shim (asm) 把寄存器装好并跳转到目标。

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NativeRetKind {
    Void = 0,
    Int = 1,     // 整数类型 (bool/char/int/long/size_t/pointer)，从 x0 读
    Double = 2,  // double / float64，从 d0 读
    Float32 = 3, // float (32-bit)，从 s0 读（必须用独立的 extern -> f32 签名）
}

enum NativeCallResult {
    Void,
    Int(u64),
    Double(f64),
    Float32(f32),
}

impl NativeRetKind {
    fn from_i32(v: i32) -> Option<Self> {
        match v {
            0 => Some(Self::Void),
            1 => Some(Self::Int),
            2 => Some(Self::Double),
            3 => Some(Self::Float32),
            _ => None,
        }
    }
}

extern "C" {
    /// ARM64 AAPCS64 shim：
    ///   - gpr[0..8] 载入 x0-x7
    ///   - fpr[0..8] 载入 d0-d7
    ///   - stk[0..stk_count] 拷贝到栈上 (每槽 8 字节，caller 分配/释放)
    ///   - 跳转到 fn_ptr
    ///
    /// 三个 extern 签名指向同一个 asm symbol，用不同的 Rust 返回类型告诉
    /// 编译器从哪个物理寄存器读返回值:
    ///   -> u64 → x0 (integer/pointer)
    ///   -> f64 → d0 (double)
    ///   -> f32 → s0 (float 32-bit，低 32 bits of v0)
    fn native_call_shim(
        fn_ptr: *const std::ffi::c_void,
        gpr: *const u64,
        fpr: *const f64,
        stk: *const u64,
        stk_count: usize,
    ) -> u64;
    #[link_name = "native_call_shim"]
    fn native_call_shim_f64(
        fn_ptr: *const std::ffi::c_void,
        gpr: *const u64,
        fpr: *const f64,
        stk: *const u64,
        stk_count: usize,
    ) -> f64;
    #[link_name = "native_call_shim"]
    fn native_call_shim_f32(
        fn_ptr: *const std::ffi::c_void,
        gpr: *const u64,
        fpr: *const f64,
        stk: *const u64,
        stk_count: usize,
    ) -> f32;
}

/// __nativeCall(addr, retKind, gpr[], fpr[], fprFloatMask, stk[])
///
/// - addr: NativePointer / number
/// - retKind: 0=void, 1=int, 2=double, 3=float32
/// - gpr[]: length-8 JS Array (BigInt/Number/Pointer) — x0-x7 寄存器参数
/// - fpr[]: length-8 JS Array (Number)                — d0-d7 寄存器参数
/// - fprFloatMask: int32 bit mask，bit i=1 表示 fpr[i] 是 float32 而非 float64
/// - stk[]: 变长 JS Array (BigInt)，溢出参数的**原始 u64 位图**
///          按声明顺序排列，JS 侧已经把 int/float/double 转好 bit pattern
///          每槽 8 字节，float32 在低 32 bits、高 32 bits = 0
///
/// 无参上限。stk 为空时走无栈溢出快路径。
pub(crate) unsafe extern "C" fn js_native_call(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 6 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"__nativeCall() requires 6 arguments: addr, retKind, gpr[], fpr[], fprFloatMask, stk[]\0".as_ptr()
                as *const _,
        );
    }
    let addr_arg = JSValue(*argv);
    let kind_arg = JSValue(*argv.add(1));
    let gpr_arg = JSValue(*argv.add(2));
    let fpr_arg = JSValue(*argv.add(3));
    let mask_arg = JSValue(*argv.add(4));
    let stk_arg = JSValue(*argv.add(5));

    let addr = match extract_pointer_address(ctx, addr_arg, "__nativeCall") {
        Ok(a) => a,
        Err(e) => return e,
    };
    if addr < 0x10000 || !is_addr_accessible(addr, 4) {
        return ffi::JS_ThrowRangeError(ctx, b"__nativeCall() address is not mapped\0".as_ptr() as *const _);
    }
    // 检查页是否可执行 (PROT_EXEC): 通过 /proc/self/maps 查 prot 位。
    // 不依赖 dladdr 因为 Memory.alloc 分配的 RWX 页不在任何 loaded SO 里。
    if !is_cmodule_code_address(addr) {
        use crate::jsapi::util::{proc_maps_entries, read_proc_self_maps};
        let maps = read_proc_self_maps();
        let mut is_exec = false;
        if let Some(ref m) = maps {
            for entry in proc_maps_entries(m) {
                if entry.contains(addr) {
                    is_exec = (entry.prot_flags() & libc::PROT_EXEC) != 0;
                    break;
                }
            }
        }
        if !is_exec {
            return ffi::JS_ThrowRangeError(
                ctx,
                b"__nativeCall() address is not in an executable page\0".as_ptr() as *const _,
            );
        }
    }

    let kind_num = kind_arg.to_i64(ctx).unwrap_or(-1);
    let kind = match NativeRetKind::from_i32(kind_num as i32) {
        Some(k) => k,
        None => {
            return ffi::JS_ThrowTypeError(ctx, b"__nativeCall() retKind must be 0..3\0".as_ptr() as *const _);
        }
    };

    let fpr_float_mask = mask_arg.to_i64(ctx).unwrap_or(0) as u32;

    // 从 JS Array 读 8 个 u64 → gpr 寄存器组
    let mut gpr = [0u64; 8];
    for i in 0..8u32 {
        let elem = ffi::JS_GetPropertyUint32(ctx, gpr_arg.raw(), i);
        let v = JSValue(elem);
        gpr[i as usize] = js_value_to_u64_or_zero(ctx, v);
        ffi::qjs_free_value(ctx, elem);
    }

    // 从 JS Array 读 8 个 number → fpr 寄存器组
    // 对标记为 float32 的槽做 f32 截断：低 32 bits 存 f32 位图，高 32 bits 为 0
    let mut fpr = [0.0f64; 8];
    for i in 0..8u32 {
        let elem = ffi::JS_GetPropertyUint32(ctx, fpr_arg.raw(), i);
        let v = JSValue(elem);
        let val = v.to_float().unwrap_or(0.0);
        ffi::qjs_free_value(ctx, elem);
        fpr[i as usize] = if (fpr_float_mask >> i) & 1 == 1 {
            let f32_bits = (val as f32).to_bits() as u64;
            f64::from_bits(f32_bits)
        } else {
            val
        };
    }

    // 读取 stk[] 长度 + 每个槽的 u64 值（JS 侧已转成 BigInt）
    // 上限：256 个溢出参数（2KB 栈空间），足够任何合理调用
    const MAX_STK: usize = 256;
    let stk_len = {
        let len_val = stk_arg.get_property(ctx, "length");
        let n = len_val.to_i64(ctx).unwrap_or(0);
        len_val.free(ctx);
        n.max(0) as usize
    };
    if stk_len > MAX_STK {
        return ffi::JS_ThrowRangeError(
            ctx,
            b"__nativeCall() too many stack args (> 256)\0".as_ptr() as *const _,
        );
    }
    let mut stk = [0u64; MAX_STK];
    for i in 0..stk_len {
        let elem = ffi::JS_GetPropertyUint32(ctx, stk_arg.raw(), i as u32);
        let v = JSValue(elem);
        stk[i] = js_value_to_u64_or_zero(ctx, v);
        ffi::qjs_free_value(ctx, elem);
    }

    let fn_ptr = addr as *const std::ffi::c_void;
    let stk_ptr = stk.as_ptr();

    let result = match with_stalker_native_call(ctx, addr, || match kind {
        NativeRetKind::Void => {
            native_call_shim(fn_ptr, gpr.as_ptr(), fpr.as_ptr(), stk_ptr, stk_len);
            NativeCallResult::Void
        }
        NativeRetKind::Int => {
            NativeCallResult::Int(native_call_shim(fn_ptr, gpr.as_ptr(), fpr.as_ptr(), stk_ptr, stk_len))
        }
        NativeRetKind::Double => NativeCallResult::Double(native_call_shim_f64(
            fn_ptr,
            gpr.as_ptr(),
            fpr.as_ptr(),
            stk_ptr,
            stk_len,
        )),
        NativeRetKind::Float32 => NativeCallResult::Float32(native_call_shim_f32(
            fn_ptr,
            gpr.as_ptr(),
            fpr.as_ptr(),
            stk_ptr,
            stk_len,
        )),
    }) {
        Ok(result) => result,
        Err(error) => return throw_internal_error(ctx, &format!("NativeFunction: {error}")),
    };

    match result {
        NativeCallResult::Void => JSValue::undefined().raw(),
        NativeCallResult::Int(value) => js_i64_to_js_number_or_bigint(ctx, value as i64),
        NativeCallResult::Double(value) => ffi::qjs_new_float64(ctx, value),
        NativeCallResult::Float32(value) => ffi::qjs_new_float64(ctx, value as f64),
    }
}

/// diagAllocNear(addr) - 诊断 hook_alloc_near 对指定地址的有效性
pub(crate) unsafe extern "C" fn js_diag_alloc_near(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"diagAllocNear() requires 1 argument (address)\0".as_ptr() as *const _,
        );
    }

    let ptr_arg = JSValue(*argv);
    let addr = match extract_pointer_address(ctx, ptr_arg, "diagAllocNear") {
        Ok(a) => a,
        Err(e) => return e,
    };

    hook_ffi::hook_diag_alloc_near(addr as *mut std::ffi::c_void);
    JSValue::undefined().raw()
}

// ═════════════════════════════ Interceptor (Frida) ════════════════════════════

fn parse_stealth_mode(ctx: *mut ffi::JSContext, v: JSValue) -> StealthMode {
    match v.to_i64(ctx) {
        Some(n) => StealthMode::from_js_arg(n),
        None if v.to_bool() == Some(true) => StealthMode::WxShadow,
        None => StealthMode::Normal,
    }
}

fn hook_error_str(code: i32) -> String {
    let bytes = hook_error_message(code);
    std::ffi::CStr::from_bytes_with_nul(bytes)
        .map(|c| c.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "hook engine error".to_string())
}

fn is_executable_hook_target(addr: u64) -> bool {
    if addr < 0x10000 || !is_addr_accessible(addr, 4) {
        return false;
    }

    crate::jsapi::util::query_page_protection(addr).is_some_and(|protection| protection & libc::PROT_EXEC != 0)
}

unsafe fn create_interceptor_listener_object(ctx: *mut ffi::JSContext, target: u64, listener_id: u64) -> ffi::JSValue {
    let listener = ffi::JS_NewObject(ctx);
    set_js_u64_property(ctx, listener, "__addr", target);
    set_js_u64_property(ctx, listener, "__listenerId", listener_id);
    set_js_cfunction_property(ctx, listener, "detach", js_listener_detach, 0);
    listener
}

/// Interceptor.attach(target, callbacks, mode?)
/// callbacks: `{ onEnter?(args) { ... }, onLeave?(retval) { ... } }`
///   - `this` 在 onEnter/onLeave 之间共享，用户可挂自定义字段跨阶段传状态
///   - args 是 NativePointer 代理，args[0..7] = x0..x7，支持写回
///   - retval.replace(v) 改返回值，retval.toInt32() 等
/// 返回 listener `{ detach(): 分离此 hook }`
pub(crate) unsafe extern "C" fn js_interceptor_attach(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Interceptor.attach requires target and callbacks\0".as_ptr() as *const _,
        );
    }

    let ptr_arg = JSValue(*argv);
    let callbacks_arg = JSValue(*argv.add(1));
    let mode = if argc >= 3 {
        parse_stealth_mode(ctx, JSValue(*argv.add(2)))
    } else {
        StealthMode::Normal
    };

    let addr = match extract_pointer_address(ctx, ptr_arg, "Interceptor.attach") {
        Ok(a) => a,
        Err(e) => return e,
    };

    if !is_executable_hook_target(addr) {
        // Gum's module-removal notification is asynchronous. Retire an exact
        // stale registry entry now so an immediate reload can reuse the same
        // virtual address without colliding with the old hook-engine entry.
        super::discard_native_hooks_in_range(addr, 1);
        return ffi::JS_ThrowRangeError(
            ctx,
            b"Interceptor.attach: target address is not executable\0".as_ptr() as *const _,
        );
    }

    if !callbacks_arg.is_object() {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Interceptor.attach callbacks must be an object { onEnter?, onLeave? }\0".as_ptr() as *const _,
        );
    }

    let on_enter_val = callbacks_arg.get_property(ctx, "onEnter");
    let on_leave_val = callbacks_arg.get_property(ctx, "onLeave");
    let has_on_enter = on_enter_val.is_function(ctx);
    let has_on_leave = on_leave_val.is_function(ctx);

    if !has_on_enter && !has_on_leave {
        on_enter_val.free(ctx);
        on_leave_val.free(ctx);
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Interceptor.attach: callbacks must provide onEnter or onLeave\0".as_ptr() as *const _,
        );
    }

    init_registry();

    let existing = with_registry_mut(&HOOK_REGISTRY, |registry| registry.get(&addr).copied()).flatten();
    if let Some(existing) = existing {
        if existing.kind != HookKind::Interceptor {
            on_enter_val.free(ctx);
            on_leave_val.free(ctx);
            return throw_internal_error(
                ctx,
                "Interceptor.attach: target is already owned by an incompatible hook",
            );
        }

        let listener_id = registry::add_interceptor_listener(InterceptorListenerData {
            id: 0,
            target: addr,
            ctx: ctx as usize,
            on_enter_bytes: if has_on_enter {
                dup_callback_to_bytes(ctx, on_enter_val.raw())
            } else {
                [0; 16]
            },
            on_leave_bytes: if has_on_leave {
                dup_callback_to_bytes(ctx, on_leave_val.raw())
            } else {
                [0; 16]
            },
            has_on_enter,
            has_on_leave,
        });
        on_enter_val.free(ctx);
        on_leave_val.free(ctx);
        return create_interceptor_listener_object(ctx, addr, listener_id);
    }

    // Recomp 模式：先重编译页 + 分配 slot
    let (hook_addr, recomp_addr) = match mode {
        StealthMode::Recomp => {
            if let Err(e) = crate::recomp::ensure_and_translate(addr as usize) {
                on_enter_val.free(ctx);
                on_leave_val.free(ctx);
                return throw_internal_error(ctx, &format!("Interceptor.attach(recomp): {}", e));
            }
            match crate::recomp::alloc_trampoline_slot(addr as usize) {
                Ok(slot) => (slot as u64, slot as u64),
                Err(e) => {
                    on_enter_val.free(ctx);
                    on_leave_val.free(ctx);
                    return throw_internal_error(ctx, &format!("Interceptor.attach(recomp slot): {}", e));
                }
            }
        }
        _ => (addr, 0),
    };

    let listener_data = InterceptorListenerData {
        id: 0,
        target: addr,
        ctx: ctx as usize,
        on_enter_bytes: if has_on_enter {
            dup_callback_to_bytes(ctx, on_enter_val.raw())
        } else {
            [0; 16]
        },
        on_leave_bytes: if has_on_leave {
            dup_callback_to_bytes(ctx, on_leave_val.raw())
        } else {
            [0; 16]
        },
        has_on_enter,
        has_on_leave,
    };
    on_enter_val.free(ctx);
    on_leave_val.free(ctx);

    let listener_id = registry::add_interceptor_listener(listener_data);
    let hook_data = HookData {
        ctx: ctx as usize,
        callback_bytes: [0; 16],
        on_leave_bytes: [0; 16],
        has_on_enter: false,
        has_on_leave: false,
        trampoline: 0,
        kind: HookKind::Interceptor,
        mode,
        recomp_addr,
        native_attach_data: 0,
    };
    with_registry_mut(&HOOK_REGISTRY, |registry| {
        registry.insert(addr, hook_data);
    });

    let stealth_flag = match mode {
        StealthMode::WxShadow => 1,
        _ => 0,
    };

    let result = hook_ffi::hook_attach(
        hook_addr as *mut std::ffi::c_void,
        Some(attach_on_enter_wrapper),
        Some(attach_on_leave_wrapper),
        addr as *mut std::ffi::c_void,
        stealth_flag,
    );

    if result != HOOK_OK {
        with_registry_mut(&HOOK_REGISTRY, |registry| {
            registry.remove(&addr);
        });
        let (removed, _) = registry::remove_interceptor_listener(addr, listener_id);
        if let Some(listener) = removed {
            super::free_interceptor_listener_callback(&listener);
        }
        if mode == StealthMode::Recomp {
            let _ = crate::recomp::try_revert_slot_patch(addr as usize);
        }
        return throw_internal_error(ctx, &format!("hook_attach: {}", hook_error_str(result)));
    }

    // Recomp: 需要修正 slot trampoline（hook_attach 已生成 thunk 并 patch 了 slot 的 4 字节）
    if mode == StealthMode::Recomp {
        let trampoline = hook_ffi::hook_get_trampoline(hook_addr as *mut std::ffi::c_void);
        if let Err(e) = finalize_recomp_hook_slot(hook_addr, addr, trampoline) {
            with_registry_mut(&HOOK_REGISTRY, |registry| {
                registry.remove(&addr);
            });
            let (removed, _) = registry::remove_interceptor_listener(addr, listener_id);
            if let Some(listener) = removed {
                super::free_interceptor_listener_callback(&listener);
            }
            super::remove_single_hook(addr, &hook_data);
            return throw_internal_error(ctx, &format!("hook_attach(recomp): {}", e));
        }
    }

    create_interceptor_listener_object(ctx, addr, listener_id)
}

/// Interceptor.replace(target, replacement, mode?) — 等价现有 hook()（replace 模式）
pub(crate) unsafe extern "C" fn js_interceptor_replace(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Interceptor.replace requires target and replacement\0".as_ptr() as *const _,
        );
    }
    let ptr_arg = JSValue(*argv);
    let replacement_arg = JSValue(*argv.add(1));
    let mode = if argc >= 3 {
        parse_stealth_mode(ctx, JSValue(*argv.add(2)))
    } else {
        StealthMode::Normal
    };
    let result = install_hook(ctx, ptr_arg, replacement_arg, mode);
    if ffi::qjs_is_exception(result) != 0 {
        return result;
    }
    ffi::qjs_free_value(ctx, result);
    JSValue::undefined().raw()
}

/// Interceptor.revert(target) — 还原 replace 安装的替换；不存在时静默返回。
pub(crate) unsafe extern "C" fn js_interceptor_revert(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(ctx, b"Interceptor.revert requires target\0".as_ptr() as *const _);
    }
    let target = match extract_pointer_address(ctx, JSValue(*argv), "Interceptor.revert") {
        Ok(target) => target,
        Err(error) => return error,
    };
    let data = with_registry_mut(&HOOK_REGISTRY, |registry| {
        if registry.get(&target).is_some_and(|data| data.kind == HookKind::Replace) {
            registry.remove(&target)
        } else {
            None
        }
    })
    .flatten();
    if let Some(data) = data {
        super::remove_single_hook(target, &data);
        super::free_hook_callback(target, &data);
    }
    JSValue::undefined().raw()
}

/// Interceptor.detachAll() — 仅拆除 attach listener；replace 由 revert 管理。
pub(crate) unsafe extern "C" fn js_interceptor_detach_all(
    _ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let hooks = with_registry_mut(&HOOK_REGISTRY, |registry| {
        let targets = registry
            .iter()
            .filter_map(|(target, data)| (data.kind == HookKind::Interceptor).then_some(*target))
            .collect::<Vec<_>>();
        targets
            .into_iter()
            .filter_map(|target| registry.remove(&target).map(|data| (target, data)))
            .collect::<Vec<_>>()
    })
    .unwrap_or_default();
    for (target, data) in hooks {
        super::remove_single_hook(target, &data);
    }
    let listeners = registry::take_all_interceptor_listeners();
    super::free_interceptor_listeners(&listeners);
    JSValue::undefined().raw()
}

/// Interceptor.flush() — 我们每次装 hook 都即时生效，无需 batch flush。保留空实现兼容脚本。
pub(crate) unsafe extern "C" fn js_interceptor_flush(
    _ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    JSValue::undefined().raw()
}

/// listener.detach() — 拆除 Interceptor.attach 返回的单个 listener
unsafe extern "C" fn js_listener_detach(
    ctx: *mut ffi::JSContext,
    this_val: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let addr = get_js_u64_property(ctx, this_val, "__addr");
    let listener_id = get_js_u64_property(ctx, this_val, "__listenerId");
    if addr == 0 || listener_id == 0 {
        return JSValue::undefined().raw();
    }

    set_js_u64_property(ctx, this_val, "__listenerId", 0);
    let (removed, target_is_empty) = registry::remove_interceptor_listener(addr, listener_id);
    if target_is_empty {
        let data = with_registry_mut(&HOOK_REGISTRY, |registry| {
            if registry
                .get(&addr)
                .is_some_and(|data| data.kind == HookKind::Interceptor)
            {
                registry.remove(&addr)
            } else {
                None
            }
        })
        .flatten();
        if let Some(data) = data {
            super::remove_single_hook(addr, &data);
        }
    }
    if let Some(listener) = removed {
        super::free_interceptor_listener_callback(&listener);
    }

    JSValue::undefined().raw()
}
