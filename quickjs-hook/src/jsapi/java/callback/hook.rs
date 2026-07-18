// ============================================================================
// Argument marshalling — convert raw JNI register values to JS values
// ============================================================================

/// Convert a raw JNI argument (from register) to a JS value based on its JNI type descriptor.
///
/// Primitive types become JS numbers/booleans/bigints.
/// String objects become JS strings (read via GetStringUTFChars).
/// Other objects become wrapped `{__jptr, __jclass}` for Proxy-based field access.
/// Falls back to BigUint64 if type info is unavailable.
///
/// `fp_raw`: value from the corresponding d-register (for float/double args).
unsafe fn marshal_jni_arg_to_js(
    ctx: *mut ffi::JSContext,
    env: JniEnv,
    raw: u64,
    fp_raw: u64,
    type_sig: Option<&str>,
) -> ffi::JSValue {
    let sig = match type_sig {
        Some(s) if !s.is_empty() => s,
        _ => return ffi::JS_NewBigUint64(ctx, raw),
    };

    match sig.as_bytes()[0] {
        b'Z' => JSValue::bool(raw != 0).raw(),
        b'B' => JSValue::int(raw as i8 as i32).raw(),
        b'C' => {
            // char → JS string (single UTF-16 character)
            let ch = std::char::from_u32(raw as u32).unwrap_or('\0');
            let s = ch.to_string();
            JSValue::string(ctx, &s).raw()
        }
        b'S' => JSValue::int(raw as i16 as i32).raw(),
        b'I' => JSValue::int(raw as i32).raw(),
        b'J' => ffi::JS_NewBigUint64(ctx, raw),
        b'F' => {
            // ARM64 ABI: floats are passed in d0-d7 (FP registers).
            // fp_raw comes from HookContext.d[fp_index].
            let f = f32::from_bits(fp_raw as u32);
            JSValue::float(f as f64).raw()
        }
        b'D' => {
            // ARM64 ABI: doubles are passed in d0-d7 (FP registers).
            // fp_raw comes from HookContext.d[fp_index].
            let d = f64::from_bits(fp_raw);
            JSValue::float(d).raw()
        }
        b'L' | b'[' => {
            // Object or array — raw is a jobject local ref
            let obj = raw as *mut std::ffi::c_void;
            if obj.is_null() {
                return ffi::qjs_null();
            }
            // 快速路径: 签名是 String 时直接读 UTF，避免 get_runtime_class_name
            if sig == "Ljava/lang/String;" {
                let get_str: GetStringUtfCharsFn = jni_fn!(env, GetStringUtfCharsFn, JNI_GET_STRING_UTF_CHARS);
                let rel_str: ReleaseStringUtfCharsFn = jni_fn!(env, ReleaseStringUtfCharsFn, JNI_RELEASE_STRING_UTF_CHARS);
                let chars = get_str(env, obj, std::ptr::null_mut());
                if !chars.is_null() {
                    let s = std::ffi::CStr::from_ptr(chars).to_string_lossy().to_string();
                    rel_str(env, obj, chars);
                    return JSValue::string(ctx, &s).raw();
                }
                jni_check_exc(env);
                return ffi::qjs_null();
            }
            // 轻量路径: 用签名类名直接构造 {__jptr, __jclass} wrapper
            // 跳过 get_runtime_class_name (省 2-3 次 JNI/参数)
            let class_name = jni_object_sig_to_class_name(sig);
            wrap_java_object_value(ctx, raw, &class_name)
        }
        _ => ffi::JS_NewBigUint64(ctx, raw),
    }
}

#[inline]
unsafe fn extract_critical_native_arg(
    hook_ctx: &hook_ffi::HookContext,
    is_fp: bool,
    gp_index: &mut usize,
    fp_index: &mut usize,
    stack_index: &mut usize,
) -> (u64, u64) {
    if is_fp {
        let fp_val = if *fp_index < 8 {
            hook_ctx.d[*fp_index]
        } else {
            let sp = hook_ctx.sp as usize;
            let value = *((sp + *stack_index * 8) as *const u64);
            *stack_index += 1;
            value
        };
        *fp_index += 1;
        (0, fp_val)
    } else {
        let gp_val = if *gp_index < 8 {
            hook_ctx.x[*gp_index]
        } else {
            let sp = hook_ctx.sp as usize;
            let value = *((sp + *stack_index * 8) as *const u64);
            *stack_index += 1;
            value
        };
        *gp_index += 1;
        (gp_val, 0)
    }
}

unsafe fn marshal_critical_native_arg_to_js(
    ctx: *mut ffi::JSContext,
    raw: u64,
    fp_raw: u64,
    type_sig: Option<&str>,
) -> ffi::JSValue {
    match type_sig.and_then(|s| s.as_bytes().first().copied()) {
        Some(b'Z') => JSValue::bool(raw != 0).raw(),
        Some(b'B') => JSValue::int(raw as i8 as i32).raw(),
        Some(b'C') => {
            let ch = std::char::from_u32(raw as u32).unwrap_or('\0');
            JSValue::string(ctx, &ch.to_string()).raw()
        }
        Some(b'S') => JSValue::int(raw as i16 as i32).raw(),
        Some(b'I') => JSValue::int(raw as i32).raw(),
        Some(b'J') => ffi::JS_NewBigUint64(ctx, raw),
        Some(b'F') => JSValue::float(f32::from_bits(fp_raw as u32) as f64).raw(),
        Some(b'D') => JSValue::float(f64::from_bits(fp_raw)).raw(),
        _ => ffi::JS_NewBigUint64(ctx, raw),
    }
}

#[inline]
unsafe fn write_primitive_return_to_context(
    ctx_ptr: *mut hook_ffi::HookContext,
    return_type: u8,
    ret_raw: u64,
) {
    if matches!(return_type, b'F' | b'D') {
        (*ctx_ptr).d[0] = ret_raw;
    }
    (*ctx_ptr).x[0] = ret_raw;
}

struct NormalizedHookRefs {
    env: JniEnv,
    refs: Vec<*mut std::ffi::c_void>,
    return_ref: std::cell::Cell<u64>,
}

impl NormalizedHookRefs {
    fn preserve_return_ref(&self, raw: u64) {
        if self.refs.iter().any(|local| *local as u64 == raw) {
            self.return_ref.set(raw);
        }
    }
}

impl Drop for NormalizedHookRefs {
    fn drop(&mut self) {
        unsafe {
            for local in self.refs.drain(..) {
                // A local returned from the native replacement must remain live
                // until ART consumes it. ART releases it with the JNI frame.
                if local as u64 != self.return_ref.get() {
                    raw_delete_local_ref(self.env, local);
                }
            }
        }
    }
}

unsafe fn decode_transition_frame_ref(reference: u64, stack_pointer: u64) -> Option<u64> {
    const MAX_FRAME_DISTANCE: u64 = 256 * 1024;

    if reference & 0x3 != 0
        || reference.abs_diff(stack_pointer) > MAX_FRAME_DISTANCE
        || !crate::jsapi::util::is_addr_accessible(reference, std::mem::size_of::<u32>())
    {
        return None;
    }

    // API 36 JNI transition refs point at a StackReference<Object>, whose
    // only field is ART's 32-bit compressed mirror::Object pointer.
    let mirror = std::ptr::read_volatile(reference as *const u32) as u64;
    if mirror < 0x10000
        || mirror & 0x7 != 0
        || !crate::jsapi::util::is_addr_accessible(mirror, std::mem::size_of::<u32>())
    {
        return None;
    }

    Some(mirror)
}

unsafe fn normalize_hook_object_slot(
    env: JniEnv,
    stack_pointer: u64,
    slot: *mut u64,
    refs: &mut Vec<*mut std::ffi::c_void>,
) {
    let original = *slot;
    if original == 0 {
        return;
    }

    let Some(mirror) = super::art_class::decode_jobject(env, original as *mut std::ffi::c_void)
        .or_else(|| decode_transition_frame_ref(original, stack_pointer))
    else {
        crate::jsapi::console::output_verbose(&format!(
            "[java hook] unable to normalize object reference {:#x}",
            original
        ));
        return;
    };
    let local = raw_mirror_to_local_ref(env, mirror);
    if local.is_null() {
        crate::jsapi::console::output_verbose(&format!(
            "[java hook] unable to create local ref for mirror {:#x}",
            mirror
        ));
        return;
    }

    *slot = local as u64;
    refs.push(local);
}

/// Android 16 may pass object arguments as transition-frame references backed
/// by the caller's quick stack frame. Our replacement trampoline adds a native
/// frame, so CheckJNI no longer accepts those references as belonging to the
/// current frame. Decode their live roots and create ordinary local refs before
/// making any nested JNI/executor call.
unsafe fn normalize_hook_transition_refs(
    ctx_ptr: *mut hook_ffi::HookContext,
    env: JniEnv,
    is_static: bool,
    param_count: usize,
    param_types: &[String],
) -> NormalizedHookRefs {
    let mut normalized = NormalizedHookRefs {
        env,
        refs: Vec::new(),
        return_ref: std::cell::Cell::new(0),
    };
    if env.is_null() {
        return normalized;
    }

    super::art_class::with_runnable_thread(env, || {
        let hook_ctx = &mut *ctx_ptr;
        let stack_pointer = hook_ctx.sp;
        if !is_static {
            normalize_hook_object_slot(
                env,
                stack_pointer,
                &mut hook_ctx.x[1],
                &mut normalized.refs,
            );
        }

        let mut gp_index = 0usize;
        let mut fp_index = 0usize;
        let mut stack_index = 0usize;
        for type_sig in param_types.iter().take(param_count) {
            if is_floating_point_type(Some(type_sig.as_str())) {
                if fp_index >= 8 {
                    stack_index += 1;
                }
                fp_index += 1;
                continue;
            }

            let slot = if gp_index < 6 {
                &mut hook_ctx.x[2 + gp_index] as *mut u64
            } else {
                let slot = (hook_ctx.sp as usize + stack_index * 8) as *mut u64;
                stack_index += 1;
                slot
            };
            gp_index += 1;

            if is_object_sig(Some(type_sig.as_str())) {
                normalize_hook_object_slot(env, stack_pointer, slot, &mut normalized.refs);
            }
        }
    });

    normalized
}

// ============================================================================
// Hook callback (runs in hooked thread, called by ART JNI trampoline)
// ============================================================================

/// Callback invoked by the native hook trampoline when a hooked Java method is called.
/// After "replace with native", ART's JNI trampoline calls our thunk which calls this.
///
/// HookContext contains JNI calling convention registers:
///   x0 = JNIEnv*, x1 = jobject this (instance) or jclass (static), x2-x7 = Java args
///
/// user_data = ArtMethod* address (used for registry lookup).
pub(super) unsafe extern "C" fn java_hook_callback(
    ctx_ptr: *mut hook_ffi::HookContext,
    user_data: *mut std::ffi::c_void,
) {
    if ctx_ptr.is_null() || user_data.is_null() {
        return;
    }

    let _in_flight_guard = InFlightJavaHookGuard::enter();
    let _callback_scope = JavaHookCallbackScope::enter();
    let _gate_guard = crate::jsapi::java::art_controller::CallbackGateGuard;

    // user_data is ArtMethod* address (used as registry key)
    let art_method_addr = user_data as u64;

    // Copy callback data then release lock before QuickJS operations.
    let (
        ctx_usize,
        callback_bytes,
        is_static,
        param_count,
        return_type,
        return_type_sig,
        param_types,
        class_global_ref,
        quick_trampoline,
        native_entry_trampoline,
    ) = {
        let guard = match JAVA_HOOK_REGISTRY.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        let registry = match guard.as_ref() {
            Some(r) => r,
            None => {
                (*ctx_ptr).x[0] = 0;
                return;
            }
        };
        let hook_data = match registry.get(&art_method_addr) {
            Some(d) => d,
            None => {
                (*ctx_ptr).x[0] = 0;
                return;
            }
        };
        (
            hook_data.ctx,
            hook_data.callback_bytes,
            hook_data.is_static,
            hook_data.param_count,
            hook_data.return_type,
            hook_data.return_type_sig.clone(),
            hook_data.param_types.clone(),
            hook_data.class_global_ref,
            hook_data.quick_trampoline,
            hook_data.native_entry_trampoline,
        )
    }; // lock released

    let hook_ctx_env: JniEnv = (*ctx_ptr).x[0] as JniEnv;
    let _normalized_refs = normalize_hook_transition_refs(
        ctx_ptr,
        hook_ctx_env,
        is_static,
        param_count,
        &param_types,
    );
    let drained = drain_raw_clone_executor(hook_ctx_env);
    if drained != 0 {
        crate::jsapi::console::output_verbose(&format!("[java executor] drained {} raw-clone task(s)", drained));
    }

    // Track whether handle_result was called (false if JS exception occurred)
    let result_was_set = std::cell::Cell::new(false);

    let had_js_exception = invoke_hook_callback_common_with_env(
        ctx_usize,
        &callback_bytes,
        "java hook",
        art_method_addr,
        hook_ctx_env as *mut std::ffi::c_void,
        |ctx| {
            let js_ctx = ffi::JS_NewObject(ctx);
            let hook_ctx = &*ctx_ptr;
            let env: JniEnv = hook_ctx.x[0] as JniEnv;
            let atoms = hot_atoms();

            // thisObj for instance methods (x1 = jobject this)
            if !is_static {
                set_js_u64_property_atom(ctx, js_ctx, atoms.this_obj, hook_ctx.x[1]);
            }

            // args[] — ARM64 JNI calling convention (GP x2-x7, FP d0-d7 independent)
            {
                let arr = ffi::JS_NewArray(ctx);
                let mut gp_index: usize = 0;
                let mut fp_index: usize = 0;
                let mut stack_index: usize = 0;
                for i in 0..param_count {
                    let type_sig = param_types.get(i).map(|s| s.as_str());
                    let (raw, fp_raw) = extract_jni_arg(
                        hook_ctx,
                        is_floating_point_type(type_sig),
                        &mut gp_index,
                        &mut fp_index,
                        &mut stack_index,
                    );
                    let val = marshal_jni_arg_to_js(ctx, env, raw, fp_raw, type_sig);
                    ffi::JS_SetPropertyUint32(ctx, arr, i as u32, val);
                }
                set_js_value_property_atom(ctx, js_ctx, atoms.args, arr);
            }

            // env (JNIEnv* — from x0)
            set_js_u64_property_atom(ctx, js_ctx, atoms.env, hook_ctx.x[0]);

            // Bind per-callback state to the JS context object so orig()
            // remains valid across nested hook callbacks and JS-side wrappers.
            set_js_u64_property_atom(ctx, js_ctx, atoms.hook_ctx_ptr, ctx_ptr as usize as u64);
            set_js_u64_property_atom(ctx, js_ctx, atoms.hook_art_method, art_method_addr);

            // orig()
            set_js_cfunction_property(ctx, js_ctx, "orig", js_call_original, 0);

            js_ctx
        },
        // 处理返回值：根据 return_type 将 JS 返回值写入 HookContext.x[0]
        |ctx, _js_ctx, result| {
            result_was_set.set(true);
            if return_type != b'V' {
                let result_val = JSValue(result);
                let ret_u64 = match return_type {
                    b'F' => {
                        if let Some(f) = result_val.to_float() {
                            (f as f32).to_bits() as u64
                        } else {
                            0u64
                        }
                    }
                    b'D' => {
                        if let Some(f) = result_val.to_float() {
                            f.to_bits()
                        } else {
                            0u64
                        }
                    }
                    b'L' | b'[' => {
                        // 优先从 __origJobject 读取原始 JNI ref（ctx.orig() 对 unboxed 值设置）。
                        // 确保 String/Integer/Boolean/Array 等所有类型安全 round-trip。
                        if result_val.is_object() {
                            let atoms = hot_atoms();
                            let orig_raw = ffi::qjs_get_property(ctx, result_val.raw(), atoms.orig_jobject);
                            let orig = JSValue(orig_raw);
                            if !orig.is_undefined() && !orig.is_null() {
                                let r = js_value_to_u64_or_zero(ctx, orig);
                                orig.free(ctx);
                                r
                            } else {
                                orig.free(ctx);
                                let env: JniEnv = hook_ctx_env;
                                if !env.is_null() {
                                    marshal_js_to_jvalue(ctx, env, result_val, Some(&return_type_sig))
                                } else {
                                    js_value_to_u64_or_zero(ctx, result_val)
                                }
                            }
                        } else if result_val.is_null() || result_val.is_undefined() {
                            0u64
                        } else {
                            // JS primitive (string/number/boolean) — 用户自己构造的返回值
                            let env: JniEnv = hook_ctx_env;
                            if !env.is_null() {
                                marshal_js_to_jvalue(ctx, env, result_val, Some(&return_type_sig))
                            } else {
                                0u64
                            }
                        }
                    }
                    _ => {
                        js_value_to_u64_or_zero(ctx, result_val)
                    }
                };
                write_primitive_return_to_context(ctx_ptr, return_type, ret_u64);
            }
        },
        // JS 抛异常透明递传: 调用 js_call_original 代替直接 invoke_original_jni。
        //
        // 为什么不能直接 invoke_original_jni? API 36 上 JS 异常 unwind 后直接进 JNI 会触发:
        //   - "Failed to recognize implicit suspend check ... state=Native" (SIGABRT), 或
        //   - dispatchMessage OAT 代码内 SEGV (stale heap ptr)
        //
        // 实测: 同样参数经 js_call_original 入口 (属性读 + JAVA_HOOK_REGISTRY Mutex + invoke)
        // 则 537+ 次异常 + 完整 UI nav 稳定不崩。推测 Mutex acquire/release barrier
        // 或 QuickJS 属性读清掉了 JS 异常 unwind 留下的脏 CPU/thread state。
        // 详见 memory: js-exception-orig-detour.md
        |ctx, js_ctx_val| {
            let result = js_call_original(ctx, js_ctx_val, 0, std::ptr::null_mut());
            if return_type != b'V' {
                let ret_u64 = js_result_to_raw(ctx, JSValue(result), return_type);
                write_primitive_return_to_context(ctx_ptr, return_type, ret_u64);
            }
            ffi::qjs_free_value(ctx, result);
            result_was_set.set(true);
        },
    );

    // 兜底: JS 异常路径应已通过 on_js_exception 设置返回值；如果 registry/context
    // 异常导致没有返回值，调用原方法保持正确语义。
    let _ = had_js_exception;
    if !result_was_set.get() {
        let env = hook_ctx_env;
        if native_entry_trampoline != 0 {
            let ret = hook_ffi::hook_invoke_trampoline(
                ctx_ptr,
                native_entry_trampoline as *mut std::ffi::c_void,
            );
            if return_type != b'V' {
                if !matches!(return_type, b'F' | b'D') {
                    (*ctx_ptr).x[0] = ret;
                }
            }
        } else if !env.is_null() {
            let hook_ctx = &*ctx_ptr;
            if !is_static && hook_ctx.x[1] == 0 {
                if return_type != b'V' {
                    write_primitive_return_to_context(ctx_ptr, return_type, 0);
                }
            } else {
                let jargs = build_jargs_from_registers(hook_ctx, param_count, &param_types);
                let jargs_ptr = if param_count > 0 {
                    jargs.as_ptr() as *const std::ffi::c_void
                } else {
                    std::ptr::null()
                };
                let ret = invoke_original_jni(
                    env, art_method_addr, class_global_ref,
                    hook_ctx.x[1], return_type, is_static, jargs_ptr, quick_trampoline, false,
                );
                if return_type != b'V' {
                    write_primitive_return_to_context(ctx_ptr, return_type, ret);
                }
            }
        } else {
            (*ctx_ptr).x[0] = 0;
        }
    }

    if matches!(return_type, b'L' | b'[') {
        _normalized_refs.preserve_return_ref((*ctx_ptr).x[0]);
    }
}

/// Callback for @CriticalNative registered entries.
///
/// Critical native ABI has no JNIEnv*/jclass receiver:
///   x0-x7 / d0-d7 = Java primitive arguments directly.
///
/// Object parameters/returns are not valid for CriticalNative and are rejected
/// during installation.
pub(super) unsafe extern "C" fn java_critical_native_hook_callback(
    ctx_ptr: *mut hook_ffi::HookContext,
    user_data: *mut std::ffi::c_void,
) {
    if ctx_ptr.is_null() || user_data.is_null() {
        return;
    }

    let _in_flight_guard = InFlightJavaHookGuard::enter();
    let _callback_scope = JavaHookCallbackScope::enter();
    let _gate_guard = crate::jsapi::java::art_controller::CallbackGateGuard;

    let art_method_addr = user_data as u64;
    let (
        ctx_usize,
        callback_bytes,
        param_count,
        return_type,
        param_types,
        native_entry_trampoline,
    ) = {
        let guard = match JAVA_HOOK_REGISTRY.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        let registry = match guard.as_ref() {
            Some(r) => r,
            None => {
                (*ctx_ptr).x[0] = 0;
                return;
            }
        };
        let hook_data = match registry.get(&art_method_addr) {
            Some(d) => d,
            None => {
                (*ctx_ptr).x[0] = 0;
                return;
            }
        };
        (
            hook_data.ctx,
            hook_data.callback_bytes,
            hook_data.param_count,
            hook_data.return_type,
            hook_data.param_types.clone(),
            hook_data.native_entry_trampoline,
        )
    };

    let result_was_set = std::cell::Cell::new(false);

    invoke_hook_callback_common(
        ctx_usize,
        &callback_bytes,
        "java critical native hook",
        art_method_addr,
        |ctx| {
            let js_ctx = ffi::JS_NewObject(ctx);
            let hook_ctx = &*ctx_ptr;
            let atoms = hot_atoms();

            let arr = ffi::JS_NewArray(ctx);
            let mut gp_index: usize = 0;
            let mut fp_index: usize = 0;
            let mut stack_index: usize = 0;
            for i in 0..param_count {
                let type_sig = param_types.get(i).map(|s| s.as_str());
                let (raw, fp_raw) = extract_critical_native_arg(
                    hook_ctx,
                    is_floating_point_type(type_sig),
                    &mut gp_index,
                    &mut fp_index,
                    &mut stack_index,
                );
                let val = marshal_critical_native_arg_to_js(ctx, raw, fp_raw, type_sig);
                ffi::JS_SetPropertyUint32(ctx, arr, i as u32, val);
            }
            set_js_value_property_atom(ctx, js_ctx, atoms.args, arr);

            set_js_u64_property_atom(ctx, js_ctx, atoms.env, 0);
            set_js_u64_property_atom(ctx, js_ctx, atoms.hook_ctx_ptr, ctx_ptr as usize as u64);
            set_js_u64_property_atom(ctx, js_ctx, atoms.hook_art_method, art_method_addr);
            set_js_cfunction_property(ctx, js_ctx, "orig", js_call_original, 0);

            js_ctx
        },
        |ctx, _js_ctx, result| {
            result_was_set.set(true);
            if return_type != b'V' {
                let ret_u64 = js_result_to_raw(ctx, JSValue(result), return_type);
                write_primitive_return_to_context(ctx_ptr, return_type, ret_u64);
            }
        },
        |ctx, js_ctx_val| {
            let result = js_call_original(ctx, js_ctx_val, 0, std::ptr::null_mut());
            if return_type != b'V' {
                let ret_u64 = js_result_to_raw(ctx, JSValue(result), return_type);
                write_primitive_return_to_context(ctx_ptr, return_type, ret_u64);
            }
            ffi::qjs_free_value(ctx, result);
            result_was_set.set(true);
        },
    );

    if !result_was_set.get() && native_entry_trampoline != 0 {
        let ret = hook_ffi::hook_invoke_trampoline(
            ctx_ptr,
            native_entry_trampoline as *mut std::ffi::c_void,
        );
        if return_type != b'V' {
            let ret_raw = if matches!(return_type, b'F' | b'D') {
                (*ctx_ptr).d[0]
            } else {
                ret
            };
            write_primitive_return_to_context(ctx_ptr, return_type, ret_raw);
        }
    }
}

/// 把 js_call_original 返回的 JSValue 还原为写 x[0] 的 u64。
/// 覆盖 L/[ (__origJobject / __jptr / null) + F/D (bits) + 基本类型。
unsafe fn js_result_to_raw(
    ctx: *mut ffi::JSContext,
    result_val: JSValue,
    return_type: u8,
) -> u64 {
    match return_type {
        b'V' => 0,
        b'F' => result_val.to_float().map(|f| (f as f32).to_bits() as u64).unwrap_or(0),
        b'D' => result_val.to_float().map(|f| f.to_bits()).unwrap_or(0),
        b'L' | b'[' => {
            if result_val.is_null() || result_val.is_undefined() {
                return 0;
            }
            if result_val.is_object() {
                // js_call_original L/[ 返回两种 shape:
                //   {__jptr, __jclass}        — 普通 Object
                //   {value, __origJobject}    — unboxed (String/Integer 等)
                let atoms = hot_atoms();
                let origj = JSValue(ffi::qjs_get_property(ctx, result_val.raw(), atoms.orig_jobject));
                if !origj.is_undefined() && !origj.is_null() {
                    let r = js_value_to_u64_or_zero(ctx, origj);
                    origj.free(ctx);
                    return r;
                }
                origj.free(ctx);
                let jptr = JSValue(ffi::qjs_get_property(ctx, result_val.raw(), atoms.jptr));
                if !jptr.is_undefined() && !jptr.is_null() {
                    let r = js_value_to_u64_or_zero(ctx, jptr);
                    jptr.free(ctx);
                    return r;
                }
                jptr.free(ctx);
            }
            js_value_to_u64_or_zero(ctx, result_val)
        }
        _ => js_value_to_u64_or_zero(ctx, result_val),
    }
}

// ============================================================================
// Quick dispatch — 从 art_router found path 直接调用 JS callback
// ============================================================================

/// ART Quick 调用约定 → JS callback dispatch
///
/// 从 art_router found path 直接调用。HookContext 包含 Quick 调用约定寄存器：
///   x0 = ArtMethod* (original, 通过 user_data 传入)
///   x1 = this (instance) 或 jclass (static)
///   x2-x7 = Java 参数 (GP)
///   d0-d7 = Java 参数 (FP)
///   x19 = Thread* (ART 约定)
///
/// 不经过 JNI trampoline，直接调用 JS callback 并将结果写回 HookContext。
/// 跳过了 ART 的 JNI epilogue，因此:
///   - 需要手动 MonitorEnter/Exit (synchronized 方法)
///   - 对象参数是裸 mirror::Object*，需要标记为 JniTransition 后 NewLocalRef 包装
///   - float/double 返回值写入 d[0]

#[no_mangle]
#[allow(dead_code)]
pub unsafe extern "C" fn java_hook_dispatch_from_quick(
    ctx_ptr: *mut hook_ffi::HookContext,
    user_data: *mut std::ffi::c_void,
) {
    if ctx_ptr.is_null() || user_data.is_null() {
        return;
    }
    let _in_flight_guard = InFlightJavaHookGuard::enter();
    let _callback_scope = JavaHookCallbackScope::enter();
    let _gate_guard = crate::jsapi::java::art_controller::CallbackGateGuard;

    let art_method_addr = user_data as u64;

    // 复制 callback 数据，然后释放 lock
    let (ctx_usize, callback_bytes, is_static, param_count, return_type, param_types) = {
        let guard = match JAVA_HOOK_REGISTRY.lock() {
            Ok(g) => g,
            Err(_) => {
                return;
            }
        };
        let registry = match guard.as_ref() {
            Some(r) => r,
            None => {
                return;
            }
        };
        let hook_data = match registry.get(&art_method_addr) {
            Some(d) => d,
            None => {
                return;
            }
        };
        (
            hook_data.ctx,
            hook_data.callback_bytes,
            hook_data.is_static,
            hook_data.param_count,
            hook_data.return_type,
            hook_data.param_types.clone(),
        )
    }; // lock released

    invoke_hook_callback_common(
        ctx_usize,
        &callback_bytes,
        "java hook (quick)",
        art_method_addr,
        // 构建 JS 上下文对象 — 纯数值, 不调 JNI
        |ctx| {
            let js_ctx = ffi::JS_NewObject(ctx);
            let hook_ctx = &*ctx_ptr;
            let atoms = hot_atoms();

            // thisObj: 原始值 (BigUint64)
            if !is_static {
                set_js_u64_property_atom(ctx, js_ctx, atoms.this_obj, hook_ctx.x[1]);
            }

            // args[] — 从寄存器读取原始值, 不转 JNI handle
            {
                let arr = ffi::JS_NewArray(ctx);
                let mut gp_index: usize = if is_static { 1 } else { 2 };
                let mut fp_index: usize = 0;
                for i in 0..param_count {
                    let type_sig = param_types.get(i).map(|s| s.as_str());
                    let is_fp = is_floating_point_type(type_sig);
                    let (raw, fp_raw) = if is_fp {
                        let fp_raw = if fp_index < 8 { hook_ctx.d[fp_index] } else { 0 };
                        fp_index += 1;
                        (0, fp_raw)
                    } else {
                        let raw = if gp_index < 8 {
                            hook_ctx.x[gp_index]
                        } else {
                            let sp = hook_ctx.sp as usize;
                            *((sp + (gp_index - 8) * 8) as *const u64)
                        };
                        gp_index += 1;
                        (raw, 0)
                    };
                    // Quick path 不做 JNI marshal。对象/数组以裸 mirror 指针传给 JS。
                    let val = match type_sig.map(|s| s.as_bytes().first().copied()) {
                        Some(Some(b'Z')) => JSValue::bool(raw != 0).raw(),
                        Some(Some(b'B')) => JSValue::int(raw as i8 as i32).raw(),
                        Some(Some(b'C')) => JSValue::int(raw as u16 as i32).raw(),
                        Some(Some(b'S')) => JSValue::int(raw as i16 as i32).raw(),
                        Some(Some(b'I')) => JSValue::int(raw as i32).raw(),
                        Some(Some(b'J')) => ffi::JS_NewBigUint64(ctx, raw),
                        Some(Some(b'F')) => JSValue::float(f32::from_bits(fp_raw as u32) as f64).raw(),
                        Some(Some(b'D')) => JSValue::float(f64::from_bits(fp_raw)).raw(),
                        _ => ffi::JS_NewBigUint64(ctx, raw), // J, L, [, 等 → BigUint64
                    };
                    ffi::JS_SetPropertyUint32(ctx, arr, i as u32, val);
                }
                set_js_value_property_atom(ctx, js_ctx, atoms.args, arr);
            }

            set_js_u64_property_atom(ctx, js_ctx, atoms.env, 0);
            set_js_u64_property_atom(ctx, js_ctx, atoms.hook_ctx_ptr, ctx_ptr as usize as u64);
            set_js_u64_property_atom(ctx, js_ctx, atoms.hook_art_method, art_method_addr);
            set_js_cfunction_property(ctx, js_ctx, "orig", js_call_original, 0);

            js_ctx
        },
        // undefined = 继续原函数；其他值 = 直接替换返回值
        |ctx, _js_ctx, result| {
            let result_val = JSValue(result);
            if result_val.is_undefined() {
                return;
            }
            if return_type != b'V' {
                (*ctx_ptr).x[0] = js_result_to_raw(ctx, result_val, return_type);
            }
            (*ctx_ptr).intercept_leave = 1;
        },
        // JS 异常时保持默认 action=call original。
        |_ctx, _js_ctx| {},
    );
}
