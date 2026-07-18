// ============================================================================
// callOriginal() — JS CFunction invoked from user's hook callback
// ============================================================================

/// Dispatch a JNI call via either static or nonvirtual variant, based on `$is_static`.
/// Consolidates the static/instance arms into one match expression.
macro_rules! dispatch_call {
    ($env:expr, $static_idx:expr, $nonvirt_idx:expr,
     $cls:expr, $this:expr, $mid:expr, $args:expr, $is_static:expr, $ret_ty:ty) => {{
        if $is_static {
            type F = unsafe extern "C" fn(
                JniEnv,
                *mut std::ffi::c_void,
                *mut std::ffi::c_void,
                *const std::ffi::c_void,
            ) -> $ret_ty;
            let f: F = jni_fn!($env, F, $static_idx);
            f($env, $cls, $mid, $args)
        } else {
            type F = unsafe extern "C" fn(
                JniEnv,
                *mut std::ffi::c_void,
                *mut std::ffi::c_void,
                *mut std::ffi::c_void,
                *const std::ffi::c_void,
            ) -> $ret_ty;
            let f: F = jni_fn!($env, F, $nonvirt_idx);
            f($env, $this, $cls, $mid, $args)
        }
    }};
}

struct MarshaledJValue {
    raw: u64,
    owned_local_ref: bool,
}

impl MarshaledJValue {
    fn raw(raw: u64) -> Self {
        Self {
            raw,
            owned_local_ref: false,
        }
    }

    fn local(raw: u64) -> Self {
        Self {
            raw,
            owned_local_ref: raw != 0,
        }
    }
}

unsafe fn raw_clone_object_arg_to_local(
    ctx: *mut ffi::JSContext,
    env: JniEnv,
    val: JSValue,
) -> Option<MarshaledJValue> {
    if !crate::is_raw_clone_js_thread() || !val.is_object() {
        return None;
    }

    let jptr_val = val.get_property(ctx, "__jptr");
    if jptr_val.is_undefined() || jptr_val.is_null() {
        jptr_val.free(ctx);
        return None;
    }
    let raw = js_value_to_u64_or_zero(ctx, jptr_val);
    jptr_val.free(ctx);
    if raw == 0 {
        return Some(MarshaledJValue::raw(0));
    }

    let raw_flag = val.get_property(ctx, "__jraw");
    let is_raw = raw_flag.to_bool().unwrap_or(false);
    raw_flag.free(ctx);
    if !is_raw {
        return Some(MarshaledJValue::raw(raw));
    }

    let local = raw_mirror_to_local_ref(env, raw) as u64;
    Some(MarshaledJValue::local(local))
}

/// Convert a JS value to a JNI jvalue (u64) based on the parameter type descriptor.
///
/// Handles: primitives (Z/B/C/S/I/J/F/D), String (JS string → NewStringUTF),
/// objects ({__jptr} or Proxy → extract raw pointer), BigUint64 (raw pointer),
/// null/undefined → 0.
pub(super) unsafe fn marshal_js_to_jvalue(
    ctx: *mut ffi::JSContext,
    env: JniEnv,
    val: JSValue,
    type_sig: Option<&str>,
) -> u64 {
    marshal_js_to_jvalue_owned(ctx, env, val, type_sig).raw
}

unsafe fn marshal_js_to_jvalue_owned(
    ctx: *mut ffi::JSContext,
    env: JniEnv,
    val: JSValue,
    type_sig: Option<&str>,
) -> MarshaledJValue {
    if val.is_null() || val.is_undefined() {
        return MarshaledJValue::raw(0);
    }

    let sig = match type_sig {
        Some(s) if !s.is_empty() => s,
        _ => {
            // No type info — try number or bigint
            return MarshaledJValue::raw(js_value_to_u64_or_zero(ctx, val));
        }
    };

    match sig.as_bytes()[0] {
        b'Z' => {
            if let Some(b) = val.to_bool() {
                MarshaledJValue::raw(b as u64)
            } else if let Some(n) = val.to_i64(ctx) {
                MarshaledJValue::raw((n != 0) as u64)
            } else {
                MarshaledJValue::raw(0)
            }
        }
        b'B' | b'S' | b'I' => {
            if let Some(n) = val.to_i64(ctx) {
                MarshaledJValue::raw(n as u64)
            } else {
                MarshaledJValue::raw(0)
            }
        }
        b'C' => {
            // char: JS string (first char) or number
            if let Some(s) = val.to_string(ctx) {
                MarshaledJValue::raw(s.chars().next().map(|c| c as u64).unwrap_or(0))
            } else if let Some(n) = val.to_i64(ctx) {
                MarshaledJValue::raw(n as u64)
            } else {
                MarshaledJValue::raw(0)
            }
        }
        b'J' => {
            MarshaledJValue::raw(js_value_to_u64_or_zero(ctx, val))
        }
        b'F' => {
            if let Some(f) = val.to_float() {
                MarshaledJValue::raw((f as f32).to_bits() as u64)
            } else {
                MarshaledJValue::raw(0)
            }
        }
        b'D' => {
            if let Some(f) = val.to_float() {
                MarshaledJValue::raw(f.to_bits())
            } else {
                MarshaledJValue::raw(0)
            }
        }
        b'[' => {
            if let Some(raw_arg) = raw_clone_object_arg_to_local(ctx, env, val) {
                return raw_arg;
            }
            if crate::is_raw_clone_js_thread() {
                crate::jsapi::console::output_verbose(
                    "[java.marshal] raw clone refuses JS array -> Java array JNI allocation",
                );
                return MarshaledJValue::raw(0);
            }
            // 数组类型: JS array → Java primitive array (via NewXxxArray + SetXxxArrayRegion)
            // byte[] 额外接受 ArrayBuffer / TypedArray，按原始字节拷贝。
            // Fallback: JS object with __jptr (已存在的 Java 数组) → 透传
            if sig == "[B" {
                if let Some(jarr) = js_byte_buffer_to_java_byte_array(ctx, env, val) {
                    return MarshaledJValue::local(jarr);
                }
            }
            if ffi::JS_IsArray(ctx, val.raw()) != 0 {
                return MarshaledJValue::local(
                    js_array_to_java_primitive_array(ctx, env, val, sig).unwrap_or(0),
                );
            }
            if val.is_object() {
                let jptr_val = val.get_property(ctx, "__jptr");
                if !jptr_val.is_undefined() && !jptr_val.is_null() {
                    let result = js_value_to_u64_or_zero(ctx, jptr_val);
                    jptr_val.free(ctx);
                    return MarshaledJValue::raw(result);
                }
                jptr_val.free(ctx);
            }
            MarshaledJValue::raw(0)
        }
        b'L' => {
            if let Some(raw_arg) = raw_clone_object_arg_to_local(ctx, env, val) {
                return raw_arg;
            }
            if crate::is_raw_clone_js_thread() {
                crate::jsapi::console::output_verbose(
                    "[java.marshal] raw clone refuses JS value -> Java object JNI allocation/autobox",
                );
                return MarshaledJValue::raw(0);
            }
            // JS string → NewStringUTF for ANY Object type (not just Ljava/lang/String;).
            // ctx.orig() 返回 String 时 marshal_jni_arg_to_js 会 unbox 为 JS string，
            // 但 return_type_sig 可能是 Ljava/lang/Object; (如 HashMap.put)。
            // 必须对所有 L 类型创建 JNI String，否则 fallback 返回 QuickJS 内部指针 → SIGSEGV。
            if val.is_string() {
                if let Some(s) = val.to_string(ctx) {
                    let cstr = match CString::new(s) {
                        Ok(c) => c,
                        Err(_) => return MarshaledJValue::raw(0),
                    };
                    let new_str: NewStringUtfFn =
                        jni_fn!(env, NewStringUtfFn, JNI_NEW_STRING_UTF);
                    let jstr = new_str(env, cstr.as_ptr());
                    return MarshaledJValue::local(jstr as u64);
                }
                return MarshaledJValue::raw(0);
            }
            // JS array → Java Object[] (每个元素按 Ljava/lang/Object; 再 marshal);
            // 只在目标是 Object/Serializable/Comparable 等通用 L 类型时触发, 避免遮蔽
            // 其它 L 类型 (例 Ljava/util/Map; 用户手动 __jptr 传递)。
            if ffi::JS_IsArray(ctx, val.raw()) != 0 {
                let is_generic_object = matches!(
                    sig,
                    "Ljava/lang/Object;" | "Ljava/io/Serializable;" | "Ljava/lang/Comparable;"
                );
                if is_generic_object {
                    return MarshaledJValue::local(js_array_to_java_primitive_array(
                        ctx, env, val, "[Ljava/lang/Object;",
                    )
                    .unwrap_or(0));
                }
            }
            // JS object → try __jptr property (Proxy-wrapped or {__jptr, __jclass})
            if val.is_object() {
                let jptr_val = val.get_property(ctx, "__jptr");
                if !jptr_val.is_undefined() && !jptr_val.is_null() {
                    let result = js_value_to_u64_or_zero(ctx, jptr_val);
                    jptr_val.free(ctx);
                    return MarshaledJValue::raw(result);
                }
                jptr_val.free(ctx);
            }
            // Autobox: JS number/boolean/bigint → Java 包装类型
            // 传入目标类型签名，精确匹配 Long/Float/Short/Byte 等
            if let Some(boxed) = autobox_primitive_to_jobject(ctx, env, val, sig) {
                return MarshaledJValue::local(boxed);
            }
            MarshaledJValue::raw(0)
        }
        _ => MarshaledJValue::raw(js_value_to_u64_or_zero(ctx, val)),
    }
}

/// 读 JS 数组长度 (通过 length property).
unsafe fn js_array_len(ctx: *mut ffi::JSContext, arr: JSValue) -> i32 {
    let len_atom = ffi::JS_NewAtom(ctx, b"length\0".as_ptr() as *const _);
    let len_val_raw = ffi::qjs_get_property(ctx, arr.raw(), len_atom);
    ffi::JS_FreeAtom(ctx, len_atom);
    let len_val = JSValue(len_val_raw);
    let len = len_val.to_i64(ctx).unwrap_or(0);
    len_val.free(ctx);
    if len < 0 || len > i32::MAX as i64 { 0 } else { len as i32 }
}

/// ArrayBuffer / TypedArray → Java byte[].
unsafe fn js_byte_buffer_to_java_byte_array(
    ctx: *mut ffi::JSContext,
    env: JniEnv,
    val: JSValue,
) -> Option<u64> {
    let mut size: usize = 0;
    let buf_ptr = ffi::JS_GetArrayBuffer(ctx, &mut size, val.raw());
    if !buf_ptr.is_null() {
        return new_java_byte_array_from_bytes(env, std::slice::from_raw_parts(buf_ptr, size));
    }
    crate::jsapi::callback_util::discard_pending_exception(ctx);

    let mut byte_offset: usize = 0;
    let mut byte_length: usize = 0;
    let mut bpe: usize = 0;
    let typed_ab = ffi::JS_GetTypedArrayBuffer(ctx, val.raw(), &mut byte_offset, &mut byte_length, &mut bpe);
    if ffi::qjs_is_exception(typed_ab) != 0 {
        let exc = ffi::JS_GetException(ctx);
        ffi::qjs_free_value(ctx, exc);
        return None;
    }

    let typed_ab_val = JSValue(typed_ab);
    let mut result = None;
    if byte_length == 0 {
        result = new_java_byte_array_from_bytes(env, &[]);
    } else {
        let mut ab_size: usize = 0;
        let ab_ptr = ffi::JS_GetArrayBuffer(ctx, &mut ab_size, typed_ab);
        if !ab_ptr.is_null() && byte_offset + byte_length <= ab_size {
            let bytes = std::slice::from_raw_parts(ab_ptr.add(byte_offset), byte_length);
            result = new_java_byte_array_from_bytes(env, bytes);
        }
    }
    typed_ab_val.free(ctx);
    result
}

unsafe fn new_java_byte_array_from_bytes(env: JniEnv, bytes: &[u8]) -> Option<u64> {
    let len = i32::try_from(bytes.len()).ok()?;
    let new_fn: NewPrimitiveArrayFn = jni_fn!(env, NewPrimitiveArrayFn, JNI_NEW_BYTE_ARRAY);
    let jarr = new_fn(env, len);
    if jni_null_or_exc(env, jarr) {
        return None;
    }
    if len > 0 {
        let set_fn: SetByteArrayRegionFn =
            jni_fn!(env, SetByteArrayRegionFn, JNI_SET_BYTE_ARRAY_REGION);
        set_fn(env, jarr, 0, len, bytes.as_ptr() as *const i8);
        if jni_check_exc(env) {
            let delete: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
            delete(env, jarr);
            return None;
        }
    }
    Some(jarr as u64)
}

/// JS array → Java 原始类型数组 (`[B`/`[Z`/`[C`/`[S`/`[I`/`[J`/`[F`/`[D`)。
/// 非原始类型数组 (如 `[Ljava/lang/String;`) 不处理, 返回 None。
///
/// 流程: NewXxxArray(len) → Rust Vec 填值 → SetXxxArrayRegion → 返回 jobject。
unsafe fn js_array_to_java_primitive_array(
    ctx: *mut ffi::JSContext,
    env: JniEnv,
    arr: JSValue,
    sig: &str,
) -> Option<u64> {
    let elem_type = sig.as_bytes().get(1).copied()?;
    let len = js_array_len(ctx, arr);

    macro_rules! build_array {
        ($new_idx:ident, $set_idx:ident, $set_fn:ident, $elem:ty, $convert:expr) => {{
            let new_fn: NewPrimitiveArrayFn = jni_fn!(env, NewPrimitiveArrayFn, $new_idx);
            let jarr = new_fn(env, len);
            if jarr.is_null() {
                return None;
            }
            let mut buf: Vec<$elem> = Vec::with_capacity(len as usize);
            for i in 0..len {
                let elem_raw = ffi::JS_GetPropertyUint32(ctx, arr.raw(), i as u32);
                let elem = JSValue(elem_raw);
                buf.push($convert(ctx, elem));
                elem.free(ctx);
            }
            let set_fn: $set_fn = jni_fn!(env, $set_fn, $set_idx);
            set_fn(env, jarr, 0, len, buf.as_ptr());
            Some(jarr as u64)
        }};
    }

    match elem_type {
        b'Z' => build_array!(
            JNI_NEW_BOOLEAN_ARRAY, JNI_SET_BOOLEAN_ARRAY_REGION, SetBooleanArrayRegionFn, u8,
            |_ctx: *mut ffi::JSContext, v: JSValue| {
                if let Some(b) = v.to_bool() { b as u8 }
                else { v.to_i64(_ctx).map(|n| (n != 0) as u8).unwrap_or(0) }
            }
        ),
        b'B' => build_array!(
            JNI_NEW_BYTE_ARRAY, JNI_SET_BYTE_ARRAY_REGION, SetByteArrayRegionFn, i8,
            |ctx: *mut ffi::JSContext, v: JSValue| v.to_i64(ctx).unwrap_or(0) as i8
        ),
        b'C' => build_array!(
            JNI_NEW_CHAR_ARRAY, JNI_SET_CHAR_ARRAY_REGION, SetCharArrayRegionFn, u16,
            |ctx: *mut ffi::JSContext, v: JSValue| {
                if let Some(s) = v.to_string(ctx) {
                    s.chars().next().map(|c| c as u16).unwrap_or(0)
                } else {
                    v.to_i64(ctx).unwrap_or(0) as u16
                }
            }
        ),
        b'S' => build_array!(
            JNI_NEW_SHORT_ARRAY, JNI_SET_SHORT_ARRAY_REGION, SetShortArrayRegionFn, i16,
            |ctx: *mut ffi::JSContext, v: JSValue| v.to_i64(ctx).unwrap_or(0) as i16
        ),
        b'I' => build_array!(
            JNI_NEW_INT_ARRAY, JNI_SET_INT_ARRAY_REGION, SetIntArrayRegionFn, i32,
            |ctx: *mut ffi::JSContext, v: JSValue| v.to_i64(ctx).unwrap_or(0) as i32
        ),
        b'J' => build_array!(
            JNI_NEW_LONG_ARRAY, JNI_SET_LONG_ARRAY_REGION, SetLongArrayRegionFn, i64,
            |ctx: *mut ffi::JSContext, v: JSValue| v.to_i64(ctx).unwrap_or(0)
        ),
        b'F' => build_array!(
            JNI_NEW_FLOAT_ARRAY, JNI_SET_FLOAT_ARRAY_REGION, SetFloatArrayRegionFn, f32,
            |_ctx: *mut ffi::JSContext, v: JSValue| v.to_float().unwrap_or(0.0) as f32
        ),
        b'D' => build_array!(
            JNI_NEW_DOUBLE_ARRAY, JNI_SET_DOUBLE_ARRAY_REGION, SetDoubleArrayRegionFn, f64,
            |_ctx: *mut ffi::JSContext, v: JSValue| v.to_float().unwrap_or(0.0)
        ),
        b'L' | b'[' => {
            // 对象数组 `[Ljava/...;` 或嵌套数组 `[[X`。
            // 对象数组: 元素类名取 inner_sig 的 `L...;` 去壳 (例: "java/lang/String")
            // 嵌套数组: 元素类名本身就是 inner_sig (例: "[I" / "[[B" / "[Ljava/lang/String;")
            // FindClass 对 array-of-primitive / nested-array 形式都接受 JNI 签名字符串。
            let inner_sig = &sig[1..];
            let elem_class_name: String = if elem_type == b'L' {
                if !inner_sig.starts_with('L') || !inner_sig.ends_with(';') {
                    return None;
                }
                inner_sig[1..inner_sig.len() - 1].to_string()
            } else {
                // nested array — FindClass 吃 "[I" / "[[Ljava/lang/String;" 原样
                inner_sig.to_string()
            };
            let cls = super::reflect::find_class_safe(env, &elem_class_name);
            if cls.is_null() {
                return None;
            }
            let new_obj_arr: NewObjectArrayFn = jni_fn!(env, NewObjectArrayFn, JNI_NEW_OBJECT_ARRAY);
            let jarr = new_obj_arr(env, len, cls, std::ptr::null_mut());
            let delete: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
            if jarr.is_null() {
                delete(env, cls);
                return None;
            }
            let set_elem: SetObjectArrayElementFn =
                jni_fn!(env, SetObjectArrayElementFn, JNI_SET_OBJECT_ARRAY_ELEMENT);
            for i in 0..len {
                let elem_raw = ffi::JS_GetPropertyUint32(ctx, arr.raw(), i as u32);
                let elem = JSValue(elem_raw);
                // 递归 marshal: 内层若是 "[X" 会再进 js_array_to_java_primitive_array,
                // 内层若是 "Ljava/.../X;" 走 L 分支 (string/autobox/__jptr)
                let elem_jval = marshal_js_to_jvalue_owned(ctx, env, elem, Some(inner_sig));
                elem.free(ctx);
                set_elem(env, jarr, i, elem_jval.raw as *mut std::ffi::c_void);
                if elem_jval.owned_local_ref && elem_jval.raw != 0 {
                    delete(env, elem_jval.raw as *mut std::ffi::c_void);
                }
                if jni_check_exc(env) {
                    delete(env, cls);
                    return None;
                }
            }
            delete(env, cls);
            Some(jarr as u64)
        }
        _ => None,
    }
}

/// Autobox JS primitive → Java wrapper object via JNI static valueOf().
/// 根据目标类型签名精确选择装箱类型，fallback 到默认推断。
unsafe fn autobox_primitive_to_jobject(
    _ctx: *mut ffi::JSContext,
    env: JniEnv,
    val: JSValue,
    target_sig: &str,
) -> Option<u64> {
    use super::jni_core::*;
    use super::reflect::find_class_safe;

    macro_rules! box_via_valueof {
        ($class:expr, $sig:expr, $raw:expr) => {{
            let cls = find_class_safe(env, $class);
            if cls.is_null() { return None; }
            let get_mid: GetStaticMethodIdFn = jni_fn!(env, GetStaticMethodIdFn, JNI_GET_STATIC_METHOD_ID);
            let mid = get_mid(env, cls, b"valueOf\0".as_ptr() as _, $sig.as_ptr() as _);
            let delete: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
            if mid.is_null() { delete(env, cls); return None; }
            let call: CallStaticObjectMethodAFn =
                jni_fn!(env, CallStaticObjectMethodAFn, JNI_CALL_STATIC_OBJECT_METHOD_A);
            let jval: u64 = $raw;
            let result = call(env, cls, mid, &jval as *const u64 as *const std::ffi::c_void);
            delete(env, cls);
            if result.is_null() { None } else { Some(result as u64) }
        }};
    }

    // boolean → Boolean
    if val.is_bool() {
        let b = val.to_bool().unwrap_or(false);
        return box_via_valueof!("java/lang/Boolean", b"(Z)Ljava/lang/Boolean;\0", b as u64);
    }

    // number → 根据目标签名选择精确的包装类型
    if let Some(f) = val.to_float() {
        return match target_sig {
            "Ljava/lang/Byte;" => box_via_valueof!("java/lang/Byte", b"(B)Ljava/lang/Byte;\0", f as i8 as u8 as u64),
            "Ljava/lang/Short;" => box_via_valueof!("java/lang/Short", b"(S)Ljava/lang/Short;\0", f as i16 as u16 as u64),
            "Ljava/lang/Long;" => box_via_valueof!("java/lang/Long", b"(J)Ljava/lang/Long;\0", f as i64 as u64),
            "Ljava/lang/Float;" => box_via_valueof!("java/lang/Float", b"(F)Ljava/lang/Float;\0", (f as f32).to_bits() as u64),
            "Ljava/lang/Double;" => box_via_valueof!("java/lang/Double", b"(D)Ljava/lang/Double;\0", f.to_bits()),
            "Ljava/lang/Integer;" => box_via_valueof!("java/lang/Integer", b"(I)Ljava/lang/Integer;\0", f as i32 as u32 as u64),
            _ => {
                // 默认: int 范围→Integer, 否则→Double
                let fits_int = f == (f as i32 as f64) && f.abs() < (i32::MAX as f64);
                if fits_int {
                    box_via_valueof!("java/lang/Integer", b"(I)Ljava/lang/Integer;\0", f as i32 as u32 as u64)
                } else {
                    box_via_valueof!("java/lang/Double", b"(D)Ljava/lang/Double;\0", f.to_bits())
                }
            }
        };
    }

    // bigint → 根据目标签名选择
    if let Some(n) = val.to_i64(_ctx) {
        return match target_sig {
            "Ljava/lang/Integer;" => box_via_valueof!("java/lang/Integer", b"(I)Ljava/lang/Integer;\0", n as i32 as u32 as u64),
            "Ljava/lang/Short;" => box_via_valueof!("java/lang/Short", b"(S)Ljava/lang/Short;\0", n as i16 as u16 as u64),
            "Ljava/lang/Byte;" => box_via_valueof!("java/lang/Byte", b"(B)Ljava/lang/Byte;\0", n as i8 as u8 as u64),
            _ => box_via_valueof!("java/lang/Long", b"(J)Ljava/lang/Long;\0", n as u64),
        };
    }

    None
}

/// Invoke original ArtMethod via JNI using provided jvalue args.
///
/// 2-ArtMethod 模型: 直接用原始 ArtMethod 地址作为 JNI method ID，
/// 无需 clone，declaring_class_ 由 GC 自动维护。
///
/// Shared by `js_call_original` (JS callback) and defensive original-call paths.
/// Returns the raw u64 return value for writing to HookContext.x[0].
/// For void methods, returns 0.
/// app 原方法抛的 Java 异常 **不 clear, 不 take** — 保留 pending 在 JNIEnv,
/// 让它沿标准 JNI 路径自然传播到 Java 调用方 (Frida 行为)。
///
/// 约束: JS 回调里如果 orig() 后再做 JNI 调用, CheckJNI 见 pending 会 abort;
/// 用户需自己处理 (try/catch 或避免后续 JNI)。
pub(crate) unsafe fn invoke_original_jni(
    env: JniEnv,
    art_method_addr: u64,
    class_global_ref: usize,
    this_obj: u64,
    return_type: u8,
    is_static: bool,
    jargs_ptr: *const std::ffi::c_void,
    quick_trampoline: u64,
    _use_blr: bool,
) -> u64 {
    let raw_clone = crate::is_raw_clone_js_thread();
    let raw_clone_jni_allowed = raw_clone_executor_jni_scope_active();
    if !raw_clone || raw_clone_jni_allowed {
        jni_check_exc(env);
    } else {
        crate::jsapi::console::output_verbose(
            "[java.orig] raw clone refuses JNI Call*MethodA original-call fallback",
        );
        return 0;
    }

    let thread_id = crate::current_thread_id_u64();
    let method_id_addr = lookup_call_original_method_id(art_method_addr);

    // Generic JNI entry point does not have the original HookContext here, so
    // only callers that can patch the router frame should use the BLR fast path.

    // Fallback: full JNI path
    crate::jsapi::java::art_controller::set_call_original_bypass(art_method_addr);

    let bypass_set = if quick_trampoline != 0 {
        hook_ffi::orig_bypass_set(thread_id, art_method_addr, quick_trampoline) == 0
    } else {
        false
    };

    let (call_this_obj, delete_local_after) = if !is_static {
        if this_obj == 0 {
            (0, false)
        } else {
            let local = if crate::is_raw_clone_js_thread() {
                raw_mirror_to_local_ref(env, this_obj) as u64
            } else {
                let new_local_ref: NewLocalRefFn = jni_fn!(env, NewLocalRefFn, JNI_NEW_LOCAL_REF);
                new_local_ref(env, this_obj as *mut std::ffi::c_void) as u64
            };
            if local == 0 || ((!raw_clone || raw_clone_jni_allowed) && jni_check_exc(env)) {
                if bypass_set {
                    hook_ffi::orig_bypass_clear(thread_id);
                }
                crate::jsapi::java::art_controller::clear_call_original_bypass();
                return 0;
            }
            (local, true)
        }
    } else {
        (this_obj, false)
    };

    let result = invoke_original_jni_inner(
        env, method_id_addr, class_global_ref, call_this_obj, return_type, is_static, jargs_ptr,
    );

    if delete_local_after {
        if crate::is_raw_clone_js_thread() {
            raw_delete_local_ref(env, call_this_obj as *mut std::ffi::c_void);
        } else {
            let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
            delete_local_ref(env, call_this_obj as *mut std::ffi::c_void);
        }
    }

    if bypass_set {
        hook_ffi::orig_bypass_clear(thread_id);
    }
    crate::jsapi::java::art_controller::clear_call_original_bypass();
    result
}

unsafe fn lookup_call_original_method_id(art_method_addr: u64) -> u64 {
    let clone_addr = {
        let guard = JAVA_HOOK_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
        guard
            .as_ref()
            .and_then(|registry| registry.get(&art_method_addr))
            .map(|data| data.clone_addr)
            .unwrap_or(0)
    };
    if clone_addr != 0 {
        let declaring_class = std::ptr::read_volatile(art_method_addr as *const u32);
        std::ptr::write_volatile(clone_addr as *mut u32, declaring_class);
        clone_addr
    } else {
        art_method_addr
    }
}

unsafe fn invoke_original_jni_inner(
    env: JniEnv,
    art_method_addr: u64,
    class_global_ref: usize,
    this_obj: u64,
    return_type: u8,
    is_static: bool,
    jargs_ptr: *const std::ffi::c_void,
) -> u64 {
    let method_id = art_method_addr as *mut std::ffi::c_void;
    let delete_class_local = class_global_ref == 0;
    let cls = if class_global_ref != 0 {
        class_global_ref as *mut std::ffi::c_void
    } else {
        let cls = local_class_ref_for_art_method(env, art_method_addr);
        let raw_clone_jni_allowed = raw_clone_executor_jni_scope_active();
        if cls.is_null() || ((!crate::is_raw_clone_js_thread() || raw_clone_jni_allowed) && jni_check_exc(env)) {
            return 0;
        }
        cls
    };
    let this_ptr = this_obj as *mut std::ffi::c_void;

    let result = match return_type {
        b'V' => {
            dispatch_call!(
                env,
                JNI_CALL_STATIC_VOID_METHOD_A,
                JNI_CALL_NONVIRTUAL_VOID_METHOD_A,
                cls,
                this_ptr,
                method_id,
                jargs_ptr,
                is_static,
                ()
            );
            0
        }
        b'Z' => {
            let ret: u8 = dispatch_call!(
                env,
                JNI_CALL_STATIC_BOOLEAN_METHOD_A,
                JNI_CALL_NONVIRTUAL_BOOLEAN_METHOD_A,
                cls,
                this_ptr,
                method_id,
                jargs_ptr,
                is_static,
                u8
            );
            ret as u64
        }
        b'I' | b'B' | b'C' | b'S' => {
            let ret: i32 = dispatch_call!(
                env,
                JNI_CALL_STATIC_INT_METHOD_A,
                JNI_CALL_NONVIRTUAL_INT_METHOD_A,
                cls,
                this_ptr,
                method_id,
                jargs_ptr,
                is_static,
                i32
            );
            ret as u64
        }
        b'J' => {
            let ret: i64 = dispatch_call!(
                env,
                JNI_CALL_STATIC_LONG_METHOD_A,
                JNI_CALL_NONVIRTUAL_LONG_METHOD_A,
                cls,
                this_ptr,
                method_id,
                jargs_ptr,
                is_static,
                i64
            );
            ret as u64
        }
        b'F' => {
            let ret: f32 = dispatch_call!(
                env,
                JNI_CALL_STATIC_FLOAT_METHOD_A,
                JNI_CALL_NONVIRTUAL_FLOAT_METHOD_A,
                cls,
                this_ptr,
                method_id,
                jargs_ptr,
                is_static,
                f32
            );
            jni_check_exc(env);
            ret.to_bits() as u64
        }
        b'D' => {
            let ret: f64 = dispatch_call!(
                env,
                JNI_CALL_STATIC_DOUBLE_METHOD_A,
                JNI_CALL_NONVIRTUAL_DOUBLE_METHOD_A,
                cls,
                this_ptr,
                method_id,
                jargs_ptr,
                is_static,
                f64
            );
            jni_check_exc(env);
            ret.to_bits()
        }
        b'L' | b'[' => {
            let ret: *mut std::ffi::c_void = dispatch_call!(
                env,
                JNI_CALL_STATIC_OBJECT_METHOD_A,
                JNI_CALL_NONVIRTUAL_OBJECT_METHOD_A,
                cls,
                this_ptr,
                method_id,
                jargs_ptr,
                is_static,
                *mut std::ffi::c_void
            );
            ret as u64
        }
        _ => 0,
    };

    if delete_class_local {
        if crate::is_raw_clone_js_thread() {
            raw_delete_local_ref(env, cls);
        } else {
            let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
            delete_local_ref(env, cls);
        }
    }

    result
}

/// Build jvalue args from HookContext registers (ARM64 JNI calling convention).
pub(crate) unsafe fn build_jargs_from_registers(
    hook_ctx: &hook_ffi::HookContext,
    param_count: usize,
    param_types: &[String],
) -> Vec<u64> {
    let mut jargs: Vec<u64> = Vec::with_capacity(param_count);
    let mut gp_index: usize = 0;
    let mut fp_index: usize = 0;
    let mut stack_index: usize = 0;
    for i in 0..param_count {
        let type_sig = param_types.get(i).map(|s| s.as_str());
        let (gp_val, fp_val) = extract_jni_arg(
            hook_ctx,
            is_floating_point_type(type_sig),
            &mut gp_index,
            &mut fp_index,
            &mut stack_index,
        );
        jargs.push(if is_floating_point_type(type_sig) {
            fp_val
        } else {
            gp_val
        });
    }
    jargs
}

unsafe fn delete_owned_jvalue_refs(env: JniEnv, refs: &[u64]) {
    if refs.is_empty() {
        return;
    }
    if crate::is_raw_clone_js_thread() {
        for &raw in refs {
            raw_delete_local_ref(env, raw as *mut std::ffi::c_void);
        }
    } else {
        let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
        for &raw in refs {
            delete_local_ref(env, raw as *mut std::ffi::c_void);
        }
    }
}

unsafe fn build_jargs_from_js_args(
    ctx: *mut ffi::JSContext,
    env: JniEnv,
    argc: i32,
    argv: *mut ffi::JSValue,
    param_count: usize,
    param_types: &[String],
) -> Result<(Vec<u64>, Vec<u64>), ffi::JSValue> {
    if argc as usize != param_count {
        let msg = format!(
            "orig(...args) expected {} argument(s), got {}\0",
            param_count, argc
        );
        return Err(ffi::JS_ThrowTypeError(ctx, msg.as_ptr() as *const _));
    }

    let mut jargs = Vec::with_capacity(param_count);
    let mut owned_refs = Vec::new();
    for i in 0..param_count {
        let val = JSValue(*argv.add(i));
        let type_sig = param_types.get(i).map(|s| s.as_str());
        let marshaled = marshal_js_to_jvalue_owned(ctx, env, val, type_sig);
        if marshaled.owned_local_ref && marshaled.raw != 0 {
            owned_refs.push(marshaled.raw);
        }
        jargs.push(marshaled.raw);
    }
    Ok((jargs, owned_refs))
}

unsafe fn js_value_from_jni_return(
    ctx: *mut ffi::JSContext,
    env: JniEnv,
    ret_raw: u64,
    return_type: u8,
    return_type_sig: &str,
) -> ffi::JSValue {
    match return_type {
        b'V' => ffi::qjs_undefined(),
        b'Z' => JSValue::bool(ret_raw != 0).raw(),
        b'I' | b'B' | b'C' | b'S' => JSValue::int(ret_raw as i32).raw(),
        b'J' => ffi::JS_NewBigUint64(ctx, ret_raw),
        b'F' => JSValue::float(f32::from_bits(ret_raw as u32) as f64).raw(),
        b'D' => JSValue::float(f64::from_bits(ret_raw)).raw(),
        b'L' | b'[' => {
            if ret_raw == 0 {
                ffi::qjs_null()
            } else {
                let js_val = marshal_jni_arg_to_js(ctx, env, ret_raw, 0, Some(return_type_sig));
                // 如果 marshal 返回了 {__jptr} wrapper（普通 Object），直接用
                if JSValue(js_val).is_object() {
                    let jptr = JSValue(js_val).get_property(ctx, "__jptr");
                    let has_jptr = !jptr.is_undefined();
                    jptr.free(ctx);
                    if has_jptr {
                        return js_val;
                    }
                }
                // unboxed (String/Integer/Boolean/Array 等):
                // 包装为 {value: 可读值, __origJobject: 原始 jobject}
                // handle_result 优先读 __origJobject，确保所有类型安全 round-trip
                let wrapper = ffi::JS_NewObject(ctx);
                let w = JSValue(wrapper);
                w.set_property(ctx, "value", JSValue(js_val));
                let ptr_val = ffi::JS_NewBigUint64(ctx, ret_raw);
                w.set_property(ctx, "__origJobject", JSValue(ptr_val));
                // toString() 返回可读值，console.log 友好
                let to_str_src = b"(function(){return String(this.value);})\0";
                let to_str = ffi::JS_Eval(ctx, to_str_src.as_ptr() as *const _,
                    (to_str_src.len() - 1) as _, b"<toString>\0".as_ptr() as *const _, 0);
                if ffi::qjs_is_exception(to_str) == 0 {
                    w.set_property(ctx, "toString", JSValue(to_str));
                } else {
                    ffi::qjs_free_value(ctx, to_str);
                }
                wrapper
            }
        }
        _ => ffi::qjs_undefined(),
    }
}

unsafe fn js_value_from_primitive_return(
    ctx: *mut ffi::JSContext,
    ret_raw: u64,
    return_type: u8,
) -> ffi::JSValue {
    match return_type {
        b'V' => ffi::qjs_undefined(),
        b'Z' => JSValue::bool(ret_raw != 0).raw(),
        b'I' | b'B' | b'C' | b'S' => JSValue::int(ret_raw as i32).raw(),
        b'J' => ffi::JS_NewBigUint64(ctx, ret_raw),
        b'F' => JSValue::float(f32::from_bits(ret_raw as u32) as f64).raw(),
        b'D' => JSValue::float(f64::from_bits(ret_raw)).raw(),
        _ => ffi::qjs_undefined(),
    }
}

unsafe fn js_value_from_quick_return(
    ctx: *mut ffi::JSContext,
    ret_raw: u64,
    return_type: u8,
) -> ffi::JSValue {
    match return_type {
        b'L' | b'[' => ffi::JS_NewBigUint64(ctx, ret_raw),
        _ => js_value_from_primitive_return(ctx, ret_raw, return_type),
    }
}

#[inline]
fn is_object_sig(type_sig: Option<&str>) -> bool {
    matches!(type_sig, Some(s) if s.starts_with('L') || s.starts_with('['))
}

/// Patch the router frame's saved quick object registers from live JNI refs.
///
/// The BLR fast-orig path keeps the router frame across the replacement JNI
/// callback. Object values saved there are raw mirror pointers and are not GC
/// roots. If GC moves objects while the script callback runs, restoring those
/// raw values will crash in original quick code. Before setting the fast-orig
/// flag, decode the callback's live JNI transition refs to fresh mirror
/// pointers and write them back to the saved quick register slots.
pub(crate) unsafe fn prepare_fast_orig_router_frame(
    env: JniEnv,
    hook_ctx: &hook_ffi::HookContext,
    is_static: bool,
    param_count: usize,
    param_types: &[String],
) -> bool {
    if env.is_null() {
        return false;
    }

    let thread_id = crate::current_thread_id_u64();
    let frame = hook_ffi::fast_orig_current_frame(thread_id) as *mut u64;
    if frame.is_null() {
        return false;
    }

    const ROUTER_X1_WORD: usize = 80 / 8;

    if !is_static {
        let receiver_ref = hook_ctx.x[1] as *mut std::ffi::c_void;
        if receiver_ref.is_null() {
            return false;
        }
        let Some(receiver_raw) = crate::jsapi::java::art_class::decode_jobject(env, receiver_ref) else {
            return false;
        };
        *frame.add(ROUTER_X1_WORD) = receiver_raw;
    }

    let mut gp_index: usize = 0;
    let mut fp_index: usize = 0;
    let mut stack_index: usize = 0;
    for i in 0..param_count {
        let type_sig = param_types.get(i).map(|s| s.as_str());
        let is_fp = is_floating_point_type(type_sig);
        let (gp_val, _fp_val) =
            extract_jni_arg(hook_ctx, is_fp, &mut gp_index, &mut fp_index, &mut stack_index);
        if !is_object_sig(type_sig) || gp_val == 0 {
            continue;
        }

        let quick_reg_index = if is_static {
            1usize.saturating_add(gp_index - 1)
        } else {
            2usize.saturating_add(gp_index - 1)
        };
        if quick_reg_index >= 8 {
            return false;
        }

        let Some(raw) =
            crate::jsapi::java::art_class::decode_jobject(env, gp_val as *mut std::ffi::c_void)
        else {
            return false;
        };
        *frame.add(ROUTER_X1_WORD + quick_reg_index - 1) = raw;
    }

    true
}

/// JS CFunction: ctx.orig() or ctx.orig(arg0, arg1, ...)
///
/// No arguments: invokes the original method with the original register arguments.
/// With arguments: invokes the original method with user-specified arguments (JS → jvalue conversion).
///
/// 2-ArtMethod 模型: 直接用原始 ArtMethod 地址作为 JNI method ID 调用。
/// Returns the method's return value as a JS value.
///
/// Must be called from a hook context object created by java_hook_callback.
unsafe extern "C" fn js_call_original(
    ctx: *mut ffi::JSContext,
    this_val: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let atoms = hot_atoms();
    let art_method_addr = get_js_u64_property_atom(ctx, this_val, atoms.hook_art_method);
    let ctx_ptr = get_js_u64_property_atom(ctx, this_val, atoms.hook_ctx_ptr) as *mut hook_ffi::HookContext;
    if ctx_ptr.is_null() || art_method_addr == 0 {
        return ffi::JS_ThrowInternalError(
            ctx,
            b"orig() can only be called inside a hook callback\0".as_ptr() as *const _,
        );
    }

    // Look up hook data
    let (
        class_global_ref,
        return_type,
        return_type_sig,
        param_count,
        is_static,
        param_types,
        quick_trampoline,
        use_blr,
        native_entry_trampoline,
        native_entry_critical,
    ) = {
        let guard = match JAVA_HOOK_REGISTRY.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        let registry = match guard.as_ref() {
            Some(r) => r,
            None => {
                return ffi::JS_ThrowInternalError(
                    ctx,
                    b"orig: hook registry not initialized\0".as_ptr() as *const _,
                );
            }
        };
        let data = match registry.get(&art_method_addr) {
            Some(d) => d,
            None => {
                return ffi::JS_ThrowInternalError(
                    ctx,
                    b"orig: hook data not found\0".as_ptr() as *const _,
                );
            }
        };
        (
            data.class_global_ref,
            data.return_type,
            data.return_type_sig.clone(),
            data.param_count,
            data.is_static,
            data.param_types.clone(),
            data.quick_trampoline,
            data.use_blr,
            data.native_entry_trampoline,
            data.native_entry_critical,
        )
    }; // lock released

    // art_method_addr 已在上方检查 (!=0), 此处无需再检查

    let hook_ctx = &*ctx_ptr;

    // Compiled quick callbacks use ART quick ABI:
    //   x0=ArtMethod*, x1=this/raw class, x2+=args.
    // Do not route this through JNI CallNonvirtual*; x1 is a raw mirror
    // pointer, not a jobject transition ref. Invoke the relocated quick
    // trampoline with the saved quick registers instead.
    if hook_ctx.x[0] == art_method_addr && quick_trampoline != 0 && native_entry_trampoline == 0 {
        let ret_x0 = hook_ffi::hook_invoke_trampoline(
            ctx_ptr,
            quick_trampoline as *mut std::ffi::c_void,
        );
        let ret_raw = if matches!(return_type, b'F' | b'D') {
            (*ctx_ptr).d[0]
        } else {
            ret_x0
        };
        (*ctx_ptr).x[0] = ret_x0;
        return js_value_from_quick_return(ctx, ret_raw, return_type);
    }

    if native_entry_trampoline != 0 && native_entry_critical {
        if argc > 0 {
            return ffi::JS_ThrowTypeError(
                ctx,
                b"orig(...args) is not supported for critical native hooks\0".as_ptr() as *const _,
            );
        }
        let ret_x0 = hook_ffi::hook_invoke_trampoline(
            ctx_ptr,
            native_entry_trampoline as *mut std::ffi::c_void,
        );
        let ret_raw = if matches!(return_type, b'F' | b'D') {
            (*ctx_ptr).d[0]
        } else {
            ret_x0
        };
        (*ctx_ptr).x[0] = ret_x0;
        return js_value_from_primitive_return(ctx, ret_raw, return_type);
    }

    // Unified JNI calling convention: x0=JNIEnv*, x1=this/class, x2+=args
    let env: JniEnv = {
        let e = hook_ctx.x[0] as JniEnv;
        if e.is_null() {
            return ffi::JS_ThrowInternalError(
                ctx,
                b"orig: JNIEnv* is null\0".as_ptr() as *const _,
            );
        }
        e
    };

    let (supplied_jargs, supplied_owned_refs) = if argc > 0 {
        match build_jargs_from_js_args(ctx, env, argc, argv, param_count, &param_types) {
            Ok(v) => (Some(v.0), v.1),
            Err(e) => return e,
        }
    } else {
        (None, Vec::new())
    };

    if native_entry_trampoline != 0 {
        if let Some(ref jargs) = supplied_jargs {
            let jargs_ptr = if jargs.is_empty() {
                std::ptr::null()
            } else {
                jargs.as_ptr() as *const std::ffi::c_void
            };
            let ret_raw = invoke_original_jni(
                env,
                art_method_addr,
                class_global_ref,
                hook_ctx.x[1],
                return_type,
                is_static,
                jargs_ptr,
                quick_trampoline,
                use_blr,
            );
            delete_owned_jvalue_refs(env, &supplied_owned_refs);
            return js_value_from_jni_return(ctx, env, ret_raw, return_type, &return_type_sig);
        }

        let ret_x0 = hook_ffi::hook_invoke_trampoline(
            ctx_ptr,
            native_entry_trampoline as *mut std::ffi::c_void,
        );
        let ret_raw = if matches!(return_type, b'F' | b'D') {
            (*ctx_ptr).d[0]
        } else {
            ret_x0
        };
        (*ctx_ptr).x[0] = ret_x0;
        return js_value_from_jni_return(ctx, env, ret_raw, return_type, &return_type_sig);
    }

    // 无参 orig() 仍从 hook_ctx 寄存器读原始 transition refs；显式
    // orig(arg0, ...) 则使用 JS 传入值，支持 hook 中改参后调用原方法。
    let jargs = supplied_jargs.unwrap_or_else(|| build_jargs_from_registers(hook_ctx, param_count, &param_types));
    let jargs_ptr = if param_count > 0 {
        jargs.as_ptr() as *const std::ffi::c_void
    } else {
        std::ptr::null()
    };

    if !is_static && hook_ctx.x[1] == 0 {
        delete_owned_jvalue_refs(env, &supplied_owned_refs);
        return match return_type {
            b'V' => ffi::qjs_undefined(),
            b'Z' => JSValue::bool(false).raw(),
            b'I' | b'B' | b'C' | b'S' => JSValue::int(0).raw(),
            b'J' => ffi::JS_NewBigUint64(ctx, 0),
            b'F' | b'D' => JSValue::float(0.0).raw(),
            b'L' | b'[' => ffi::qjs_null(),
            _ => ffi::qjs_undefined(),
        };
    }

    // The BLR router invokes the original only after this callback returns.
    // JNI locals created while marshaling explicit JS arguments must therefore
    // stay on the synchronous Call*MethodA path, where we can release them
    // after the original has consumed them.
    if supplied_owned_refs.is_empty()
        && use_blr
        && quick_trampoline != 0
        && prepare_fast_orig_router_frame(env, hook_ctx, is_static, param_count, &param_types)
    {
        let thread_id = crate::current_thread_id_u64();
        if hook_ffi::fast_orig_set(thread_id, art_method_addr, quick_trampoline) == 0 {
            delete_owned_jvalue_refs(env, &supplied_owned_refs);
            return match return_type {
                b'V' => ffi::qjs_undefined(),
                b'Z' => JSValue::bool(false).raw(),
                b'I' | b'B' | b'C' | b'S' => JSValue::int(0).raw(),
                b'J' => ffi::JS_NewBigUint64(ctx, 0),
                b'F' | b'D' => JSValue::float(0.0).raw(),
                b'L' | b'[' => ffi::qjs_null(),
                _ => ffi::qjs_undefined(),
            };
        }
    }

    let ret_raw = invoke_original_jni(
        env,
        art_method_addr,
        class_global_ref,
        hook_ctx.x[1],
        return_type,
        is_static,
        jargs_ptr,
        quick_trampoline,
        use_blr,
    );
    delete_owned_jvalue_refs(env, &supplied_owned_refs);

    js_value_from_jni_return(ctx, env, ret_raw, return_type, &return_type_sig)
}
