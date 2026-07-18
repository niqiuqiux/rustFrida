use crate::ffi;
use crate::jsapi::callback_util::{extract_string_arg, with_registry, with_registry_mut};
use crate::jsapi::console::output_verbose;
use crate::value::JSValue;

use super::super::callback::*;
use super::super::jni_core::*;

pub(in crate::jsapi::java) unsafe extern "C" fn js_java_unhook(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 3 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Java.unhook() requires 3 arguments: class, method, signature\0".as_ptr() as *const _,
        );
    }

    let class_arg = JSValue(*argv);
    let method_arg = JSValue(*argv.add(1));
    let sig_arg = JSValue(*argv.add(2));

    let class_name = match extract_string_arg(ctx, class_arg, b"Java.unhook() first argument must be a string\0") {
        Ok(value) => value,
        Err(err) => return err,
    };

    let method_name = match extract_string_arg(ctx, method_arg, b"Java.unhook() second argument must be a string\0") {
        Ok(value) => value,
        Err(err) => return err,
    };

    let sig_str = match extract_string_arg(ctx, sig_arg, b"Java.unhook() third argument must be a string\0") {
        Ok(value) => value,
        Err(err) => return err,
    };

    let actual_sig = if let Some(stripped) = sig_str.strip_prefix("static:") {
        stripped.to_string()
    } else {
        sig_str
    };

    let key = method_key(&class_name, &method_name, &actual_sig);
    let art_method_addr = with_registry(&JAVA_HOOK_REGISTRY, |registry| {
        registry.iter().find(|(_, v)| v.method_key == key).map(|(k, _)| *k)
    })
    .flatten();

    let art_method_addr = match art_method_addr {
        Some(am) => am,
        None => {
            return ffi::JS_ThrowInternalError(ctx, b"method not hooked\0".as_ptr() as *const _);
        }
    };

    let hook_data = with_registry(&JAVA_HOOK_REGISTRY, |registry| registry.get(&art_method_addr).cloned()).flatten();

    let hook_data = match hook_data {
        Some(d) => d,
        None => {
            return ffi::JS_ThrowInternalError(ctx, b"method not hooked\0".as_ptr() as *const _);
        }
    };

    output_verbose(&format!(
        "[java unhook] 开始: art_method={:#x}, type={:?}",
        hook_data.art_method, hook_data.hook_type
    ));

    // Step 1: 删除 art_router 映射，切断路由
    delete_replacement_method(hook_data.art_method);

    // Step 2: 移除 Layer 3 per-method hook + stealth2 revert
    super::super::remove_per_method_hook(&hook_data);

    // Step 3: 移除 registered native fnPtr hook
    super::super::remove_native_entry_hook(&hook_data);

    // Step 4: 恢复 ArtMethod 原始字段
    super::super::restore_art_method_fields(&hook_data);

    // Step 5: 等待 in-flight callbacks 自然退出。
    // 若仍有线程在 callback/thunk 内，不能释放 JSValue、replacement ArtMethod 或 native
    // trampoline；这些线程醒来后可能仍会访问它们。此时宁可 leak 到进程退出。
    let drained = wait_for_in_flight_java_hook_callbacks(std::time::Duration::from_millis(500));
    if !drained {
        output_verbose(&format!(
            "[java unhook] 等待 in-flight callbacks 超时，保留资源到 cleanup 阶段释放，remaining={}",
            in_flight_java_hook_callbacks()
        ));

        with_registry_mut(&JAVA_HOOK_REGISTRY, |registry| {
            if let Some(data) = registry.get_mut(&art_method_addr) {
                match &mut data.hook_type {
                    HookType::NativeEntry => {}
                    HookType::Replaced {
                        per_method_hook_target, ..
                    }
                    | HookType::Quick {
                        per_method_hook_target, ..
                    }
                    | HookType::Managed {
                        per_method_hook_target, ..
                    } => {
                        *per_method_hook_target = None;
                    }
                }
                data.native_entry_hook_target = 0;
                data.native_entry_trampoline = 0;
            }
        });
        output_verbose(&format!(
            "[java unhook] 完成: {}.{}{}",
            class_name, method_name, actual_sig
        ));
        return JSValue::bool(true).raw();
    }

    // Step 6: registry 中删除 hook data；此时 in-flight 已归零，$orig 不再需要查表。
    let hook_data = with_registry_mut(&JAVA_HOOK_REGISTRY, |registry| registry.remove(&art_method_addr))
        .flatten()
        .unwrap_or(hook_data);

    // Step 7: 移除 native trampoline，释放 JS/JNI 资源并退休 ART-visible methods。
    super::super::remove_native_trampoline(&hook_data);
    let env_opt = if crate::is_raw_clone_js_thread() {
        None
    } else {
        get_thread_env().ok()
    };
    super::super::free_java_hook_resources(&hook_data, env_opt);

    output_verbose(&format!(
        "[java unhook] 完成: {}.{}{}",
        class_name, method_name, actual_sig
    ));

    JSValue::bool(true).raw()
}
