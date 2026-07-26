// ============================================================================
// Java array 访问：JS 侧 arr.length / arr[i] → JNI GetArrayLength / GetObjectArrayElement
//
// Java proxy wrapper 对 __jclass[0] == '[' 的对象（数组类型）调这两个 helper：
// - `Java._arrayLength(jptr)`：返回长度
// - `Java._arrayGet(jptr, idx, arrClass)`：返回元素的 wrapper / 原始值
//
// raw clone 线程不能安全重入 JNI，因此 raw clone 分支只允许把全局引用
// 投递到 Java executor，在真实 Java 线程上执行数组 JNI 操作。
// ============================================================================

use crate::ffi;
use crate::value::JSValue;

use super::callback::wrap_java_object_ref_for_array_elem;
use super::jni_core::get_thread_env;
use super::jni_core::{
    jni_check_exc, jni_fn_ptr, jni_null_or_exc, GetArrayLengthFn, GetObjectArrayElementFn, JniEnv,
    JNI_GET_ARRAY_LENGTH, JNI_GET_BOOLEAN_ARRAY_REGION, JNI_GET_BYTE_ARRAY_REGION, JNI_GET_CHAR_ARRAY_REGION,
    JNI_GET_DOUBLE_ARRAY_REGION, JNI_GET_FLOAT_ARRAY_REGION, JNI_GET_INT_ARRAY_REGION, JNI_GET_LONG_ARRAY_REGION,
    JNI_GET_OBJECT_ARRAY_ELEMENT, JNI_GET_SHORT_ARRAY_REGION,
};

/// `Get<Type>ArrayRegion(env, array, start, length, buffer)`
type GetPrimitiveArrayRegionFn = unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, i32, i32, *mut std::ffi::c_void);

/// Read one element out of a primitive array.
///
/// `GetObjectArrayElement` on a primitive array is a hard JNI error that aborts
/// the runtime, so the element type decides which accessor to use before any
/// call is made.
unsafe fn primitive_array_element(
    ctx: *mut ffi::JSContext,
    env: JniEnv,
    array: *mut std::ffi::c_void,
    index: i32,
    element_signature: char,
) -> Option<ffi::JSValue> {
    let (region_index, size) = match element_signature {
        'Z' => (JNI_GET_BOOLEAN_ARRAY_REGION, 1usize),
        'B' => (JNI_GET_BYTE_ARRAY_REGION, 1),
        'C' => (JNI_GET_CHAR_ARRAY_REGION, 2),
        'S' => (JNI_GET_SHORT_ARRAY_REGION, 2),
        'I' => (JNI_GET_INT_ARRAY_REGION, 4),
        'J' => (JNI_GET_LONG_ARRAY_REGION, 8),
        'F' => (JNI_GET_FLOAT_ARRAY_REGION, 4),
        'D' => (JNI_GET_DOUBLE_ARRAY_REGION, 8),
        _ => return None,
    };

    let get_region: GetPrimitiveArrayRegionFn = std::mem::transmute(jni_fn_ptr(env, region_index));
    let mut buffer = [0u8; 8];
    get_region(env, array, index, 1, buffer.as_mut_ptr() as *mut std::ffi::c_void);
    if jni_check_exc(env) {
        return Some(ffi::qjs_undefined());
    }

    let bytes = &buffer[..size];
    Some(match element_signature {
        'Z' => JSValue::bool(bytes[0] != 0).raw(),
        'B' => JSValue::int(bytes[0] as i8 as i32).raw(),
        'C' => JSValue::int(u16::from_ne_bytes([bytes[0], bytes[1]]) as i32).raw(),
        'S' => JSValue::int(i16::from_ne_bytes([bytes[0], bytes[1]]) as i32).raw(),
        'I' => JSValue::int(i32::from_ne_bytes(bytes.try_into().expect("4 bytes"))).raw(),
        'J' => ffi::qjs_new_int64(ctx, i64::from_ne_bytes(bytes.try_into().expect("8 bytes"))),
        'F' => ffi::qjs_new_float64(ctx, f32::from_ne_bytes(bytes.try_into().expect("4 bytes")) as f64),
        'D' => ffi::qjs_new_float64(ctx, f64::from_ne_bytes(bytes.try_into().expect("8 bytes"))),
        _ => unreachable!("signature was matched above"),
    })
}

fn element_class_from_array_class(arr_class: &str) -> String {
    if !arr_class.starts_with('[') {
        return arr_class.to_string();
    }
    let inner = &arr_class[1..];
    if inner.starts_with('L') && inner.ends_with(';') && inner.len() >= 2 {
        inner[1..inner.len() - 1].to_string()
    } else {
        inner.to_string()
    }
}

fn element_sig_from_array_class(arr_class: &str) -> String {
    if arr_class.starts_with('[') && arr_class.len() > 1 {
        arr_class[1..].to_string()
    } else {
        format!("L{};", arr_class.replace('.', "/"))
    }
}

/// JS: `_arrayLength(jptr) -> number`
pub(super) unsafe extern "C" fn js_java_array_length(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return JSValue::int(-1).raw();
    }
    let jptr_val = JSValue(*argv);
    let jptr = match jptr_val.to_u64(ctx) {
        Some(p) if p != 0 => p,
        _ => return JSValue::int(-1).raw(),
    };
    let is_global = if argc >= 2 {
        JSValue(*argv.add(1)).to_bool().unwrap_or(false)
    } else {
        false
    };

    if crate::is_raw_clone_js_thread() {
        if is_global {
            return super::callback::array_length_via_executor(ctx, jptr, true);
        }
        return JSValue::int(-1).raw();
    }

    let env = match get_thread_env() {
        Ok(e) => e,
        Err(_) => return JSValue::int(-1).raw(),
    };

    let get_len: GetArrayLengthFn =
        std::mem::transmute::<*const std::ffi::c_void, GetArrayLengthFn>(jni_fn_ptr(env, JNI_GET_ARRAY_LENGTH));
    let len = get_len(env, jptr as *mut std::ffi::c_void);
    if jni_check_exc(env) {
        return JSValue::int(-1).raw();
    }
    JSValue::int(len).raw()
}

/// JS: `_arrayGet(jptr, idx, arrClass) -> wrapper | 原始值`
/// arrClass 例如 `"[Ljava.lang.StackTraceElement;"`（对象数组）或 `"[I"`（基本类型）。
/// 对象数组返回 wrapper；基本类型数组返回对应的 JS 数值/布尔值。
pub(super) unsafe extern "C" fn js_java_array_get(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 3 {
        return ffi::qjs_undefined();
    }
    let jptr_val = JSValue(*argv);
    let idx_val = JSValue(*argv.add(1));
    let cls_val = JSValue(*argv.add(2));

    let jptr = match jptr_val.to_u64(ctx) {
        Some(p) if p != 0 => p,
        _ => return ffi::qjs_null(),
    };
    let idx = match idx_val.to_i64(ctx) {
        Some(n) if n >= 0 && n < i32::MAX as i64 => n as i32,
        _ => return ffi::qjs_undefined(),
    };
    let arr_class = match cls_val.to_string(ctx) {
        Some(s) => s,
        None => return ffi::qjs_undefined(),
    };
    let is_global = if argc >= 4 {
        JSValue(*argv.add(3)).to_bool().unwrap_or(false)
    } else {
        false
    };

    let elem_class = element_class_from_array_class(&arr_class);

    if crate::is_raw_clone_js_thread() {
        if is_global {
            return super::callback::array_get_via_executor(
                ctx,
                jptr,
                true,
                idx,
                element_sig_from_array_class(&arr_class),
            );
        }
        return ffi::qjs_undefined();
    }

    let env = match get_thread_env() {
        Ok(e) => e,
        Err(_) => return ffi::qjs_null(),
    };

    // Primitive arrays must not go through GetObjectArrayElement.
    if let Some(signature) = arr_class.strip_prefix('[').and_then(|rest| rest.chars().next()) {
        if let Some(value) = primitive_array_element(ctx, env, jptr as *mut std::ffi::c_void, idx, signature) {
            return value;
        }
    }

    let get_elem: GetObjectArrayElementFn = std::mem::transmute::<*const std::ffi::c_void, GetObjectArrayElementFn>(
        jni_fn_ptr(env, JNI_GET_OBJECT_ARRAY_ELEMENT),
    );
    let obj = get_elem(env, jptr as *mut std::ffi::c_void, idx);
    if jni_null_or_exc(env, obj) {
        return ffi::qjs_null();
    }

    // 转全局引用 + 生成 {__jptr, __jclass} wrapper，让 JS 侧可继续调方法。
    wrap_java_object_ref_for_array_elem(ctx, env, obj, &elem_class)
}
