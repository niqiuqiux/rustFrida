//! Native helpers for the Frida-compatible `Java` surface (Goal 08).
//!
//! The JavaScript bootstrap assembles the upstream-shaped API on top of these;
//! anything that needs JNI or the process environment lives here.

use super::jni_core::{
    get_thread_env, jni_check_exc, jni_fn_ptr, DeleteGlobalRefFn, IsInstanceOfFn, MonitorEnterFn, MonitorExitFn,
    NewGlobalRefFn, NewObjectArrayFn, SetObjectArrayElementFn, JNI_DELETE_GLOBAL_REF, JNI_IS_INSTANCE_OF,
    JNI_MONITOR_ENTER, JNI_MONITOR_EXIT, JNI_NEW_BOOLEAN_ARRAY, JNI_NEW_BYTE_ARRAY, JNI_NEW_CHAR_ARRAY,
    JNI_NEW_DOUBLE_ARRAY, JNI_NEW_FLOAT_ARRAY, JNI_NEW_GLOBAL_REF, JNI_NEW_INT_ARRAY, JNI_NEW_LONG_ARRAY,
    JNI_NEW_OBJECT_ARRAY, JNI_NEW_SHORT_ARRAY, JNI_SET_BOOLEAN_ARRAY_REGION, JNI_SET_BYTE_ARRAY_REGION,
    JNI_SET_CHAR_ARRAY_REGION, JNI_SET_DOUBLE_ARRAY_REGION, JNI_SET_FLOAT_ARRAY_REGION, JNI_SET_INT_ARRAY_REGION,
    JNI_SET_LONG_ARRAY_REGION, JNI_SET_OBJECT_ARRAY_ELEMENT, JNI_SET_SHORT_ARRAY_REGION,
};

/// `New<Type>Array(env, length)`
type NewPrimitiveArrayFn = unsafe extern "C" fn(super::jni_core::JniEnv, i32) -> *mut std::ffi::c_void;
/// `Set<Type>ArrayRegion(env, array, start, length, buffer)`
type SetPrimitiveArrayRegionFn =
    unsafe extern "C" fn(super::jni_core::JniEnv, *mut std::ffi::c_void, i32, i32, *const std::ffi::c_void);
use crate::ffi;
use crate::jsapi::callback_util::throw_internal_error;
use crate::value::JSValue;

/// Whether this process has an ART runtime loaded.
///
/// Checked by looking for libart in the mappings rather than by attaching:
/// upstream's `Java.available` is a question a script asks *before* touching
/// anything else, so it must not itself initialise JNI.
fn art_runtime_loaded() -> bool {
    let Some(maps) = crate::jsapi::util::read_proc_self_maps() else {
        return false;
    };
    maps.lines().any(|line| {
        line.contains("/libart.so") && line.split_whitespace().nth(1).is_some_and(|perms| perms.contains('x'))
    })
}

unsafe extern "C" fn js_java_available(
    _ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    JSValue::bool(art_runtime_loaded()).raw()
}

/// Read the platform release string, e.g. `"16"`.
///
/// Upstream reads `android.os.Build.VERSION.RELEASE`; the system property it is
/// populated from gives the same answer without needing a JNI call, which keeps
/// this usable before the class loader is ready.
fn android_release() -> Option<String> {
    unsafe extern "C" {
        fn __system_property_get(name: *const libc::c_char, value: *mut libc::c_char) -> libc::c_int;
    }
    // PROP_VALUE_MAX
    let mut buffer = [0u8; 92];
    let length = unsafe { __system_property_get(c"ro.build.version.release".as_ptr(), buffer.as_mut_ptr() as *mut _) };
    if length <= 0 {
        return None;
    }
    String::from_utf8(buffer[..length as usize].to_vec()).ok()
}

unsafe extern "C" fn js_java_android_version(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let Some(release) = android_release() else {
        return throw_internal_error(ctx, "Java.androidVersion is unavailable on this platform");
    };
    ffi::JS_NewStringLen(ctx, release.as_ptr() as *const _, release.len())
}

/// The VM's main thread is the process's initial thread.
unsafe extern "C" fn js_java_is_main_thread(
    _ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let tid = libc::syscall(libc::SYS_gettid) as i32;
    JSValue::bool(tid == libc::getpid()).raw()
}

/// Read a jobject handle passed from JavaScript.
unsafe fn required_handle(
    ctx: *mut ffi::JSContext,
    argc: i32,
    argv: *mut ffi::JSValue,
    operation: &str,
) -> Result<*mut std::ffi::c_void, ffi::JSValue> {
    if argc < 1 {
        return Err(throw_internal_error(
            ctx,
            format!("{operation}() requires an object handle"),
        ));
    }
    let Some(handle) = JSValue(*argv).to_u64(ctx).filter(|handle| *handle != 0) else {
        return Err(throw_internal_error(
            ctx,
            format!("{operation}() requires a live Java object"),
        ));
    };
    Ok(handle as *mut std::ffi::c_void)
}

unsafe extern "C" fn js_java_monitor_enter(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let handle = match required_handle(ctx, argc, argv, "Java.synchronized") {
        Ok(value) => value,
        Err(error) => return error,
    };
    let Ok(env) = get_thread_env() else {
        return throw_internal_error(ctx, "Java.synchronized() could not attach the current thread");
    };
    let monitor_enter: MonitorEnterFn = std::mem::transmute(jni_fn_ptr(env, JNI_MONITOR_ENTER));
    if monitor_enter(env, handle) != 0 || jni_check_exc(env) {
        return throw_internal_error(ctx, "Java.synchronized() could not enter the object monitor");
    }
    JSValue::undefined().raw()
}

unsafe extern "C" fn js_java_monitor_exit(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let handle = match required_handle(ctx, argc, argv, "Java.synchronized") {
        Ok(value) => value,
        Err(error) => return error,
    };
    let Ok(env) = get_thread_env() else {
        return throw_internal_error(ctx, "Java.synchronized() could not attach the current thread");
    };
    let monitor_exit: MonitorExitFn = std::mem::transmute(jni_fn_ptr(env, JNI_MONITOR_EXIT));
    // Report the failure but always clear: leaving a pending exception would
    // surface later at an unrelated call site.
    let failed = monitor_exit(env, handle) != 0;
    let had_exception = jni_check_exc(env);
    if failed || had_exception {
        return throw_internal_error(ctx, "Java.synchronized() could not leave the object monitor");
    }
    JSValue::undefined().raw()
}

/// `Java._enumerateLoadedClasses()` — every loaded class name.
unsafe extern "C" fn js_java_enumerate_loaded_classes(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let names = match super::jvmti::jvmti_loaded_class_names() {
        Ok(value) => value,
        Err(error) => return throw_internal_error(ctx, format!("Java.enumerateLoadedClasses(): {error}")),
    };
    let array = ffi::JS_NewArray(ctx);
    for (index, name) in names.iter().enumerate() {
        let value = ffi::JS_NewStringLen(ctx, name.as_ptr() as *const _, name.len());
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, value);
    }
    array
}

/// `Java._newGlobalRef(jptr)` — promote a handle so it survives the frame.
///
/// The caller owns the result and must pass it back to `_deleteGlobalRef`;
/// `Java.retain()` ties that to the wrapper's `$dispose()`.
unsafe extern "C" fn js_java_new_global_ref(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let handle = match required_handle(ctx, argc, argv, "Java.retain") {
        Ok(value) => value,
        Err(error) => return error,
    };
    let Ok(env) = get_thread_env() else {
        return throw_internal_error(ctx, "Java.retain() could not attach the current thread");
    };
    let new_global_ref: NewGlobalRefFn = std::mem::transmute(jni_fn_ptr(env, JNI_NEW_GLOBAL_REF));
    let global = new_global_ref(env, handle);
    if global.is_null() || jni_check_exc(env) {
        return throw_internal_error(ctx, "Java.retain() could not create a global reference");
    }
    ffi::qjs_new_int64(ctx, global as i64)
}

unsafe extern "C" fn js_java_delete_global_ref(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    // Disposing twice is a no-op rather than an error: scripts commonly call
    // $dispose() in a finally block that may run after an earlier dispose.
    if argc < 1 {
        return JSValue::undefined().raw();
    }
    let Some(handle) = JSValue(*argv).to_u64(ctx).filter(|handle| *handle != 0) else {
        return JSValue::undefined().raw();
    };
    let Ok(env) = get_thread_env() else {
        return JSValue::undefined().raw();
    };
    let delete_global_ref: DeleteGlobalRefFn = std::mem::transmute(jni_fn_ptr(env, JNI_DELETE_GLOBAL_REF));
    delete_global_ref(env, handle as *mut std::ffi::c_void);
    jni_check_exc(env);
    JSValue::undefined().raw()
}

/// `Java._isInstanceOf(jptr, className)` — the check behind `Java.cast()`.
unsafe extern "C" fn js_java_is_instance_of(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let handle = match required_handle(ctx, argc, argv, "Java.cast") {
        Ok(value) => value,
        Err(error) => return error,
    };
    if argc < 2 {
        return throw_internal_error(ctx, "Java.cast() requires a target class name");
    }
    let Some(class_name) = JSValue(*argv.add(1)).to_string(ctx) else {
        return throw_internal_error(ctx, "Java.cast() target class must be a string");
    };
    let Ok(env) = get_thread_env() else {
        return throw_internal_error(ctx, "Java.cast() could not attach the current thread");
    };

    let class_object = super::reflect::find_class_safe(env, &class_name);
    if class_object.is_null() {
        return throw_internal_error(ctx, format!("Java.cast(): class not found: {class_name}"));
    }
    let is_instance_of: IsInstanceOfFn = std::mem::transmute(jni_fn_ptr(env, JNI_IS_INSTANCE_OF));
    let matches = is_instance_of(env, handle, class_object) != 0;
    jni_check_exc(env);
    JSValue::bool(matches).raw()
}

/// One primitive array flavour: how to create it and how to fill it.
struct PrimitiveArray {
    /// Element type as written in `Java.array("int", ...)`.
    name: &'static str,
    new_index: usize,
    set_region_index: usize,
    element_size: usize,
}

const PRIMITIVE_ARRAYS: &[PrimitiveArray] = &[
    PrimitiveArray {
        name: "boolean",
        new_index: JNI_NEW_BOOLEAN_ARRAY,
        set_region_index: JNI_SET_BOOLEAN_ARRAY_REGION,
        element_size: 1,
    },
    PrimitiveArray {
        name: "byte",
        new_index: JNI_NEW_BYTE_ARRAY,
        set_region_index: JNI_SET_BYTE_ARRAY_REGION,
        element_size: 1,
    },
    PrimitiveArray {
        name: "char",
        new_index: JNI_NEW_CHAR_ARRAY,
        set_region_index: JNI_SET_CHAR_ARRAY_REGION,
        element_size: 2,
    },
    PrimitiveArray {
        name: "short",
        new_index: JNI_NEW_SHORT_ARRAY,
        set_region_index: JNI_SET_SHORT_ARRAY_REGION,
        element_size: 2,
    },
    PrimitiveArray {
        name: "int",
        new_index: JNI_NEW_INT_ARRAY,
        set_region_index: JNI_SET_INT_ARRAY_REGION,
        element_size: 4,
    },
    PrimitiveArray {
        name: "long",
        new_index: JNI_NEW_LONG_ARRAY,
        set_region_index: JNI_SET_LONG_ARRAY_REGION,
        element_size: 8,
    },
    PrimitiveArray {
        name: "float",
        new_index: JNI_NEW_FLOAT_ARRAY,
        set_region_index: JNI_SET_FLOAT_ARRAY_REGION,
        element_size: 4,
    },
    PrimitiveArray {
        name: "double",
        new_index: JNI_NEW_DOUBLE_ARRAY,
        set_region_index: JNI_SET_DOUBLE_ARRAY_REGION,
        element_size: 8,
    },
];

/// Pack one JavaScript value into the element encoding the array expects.
unsafe fn encode_primitive_element(
    ctx: *mut ffi::JSContext,
    kind: &PrimitiveArray,
    value: JSValue,
    output: &mut Vec<u8>,
) -> Result<(), ()> {
    match kind.name {
        "boolean" => output.push(u8::from(value.to_bool().unwrap_or(false))),
        "byte" => output.push(value.to_i64(ctx).ok_or(())? as i8 as u8),
        "char" => output.extend_from_slice(&(value.to_i64(ctx).ok_or(())? as u16).to_ne_bytes()),
        "short" => output.extend_from_slice(&(value.to_i64(ctx).ok_or(())? as i16).to_ne_bytes()),
        "int" => output.extend_from_slice(&(value.to_i64(ctx).ok_or(())? as i32).to_ne_bytes()),
        "long" => output.extend_from_slice(&value.to_i64(ctx).ok_or(())?.to_ne_bytes()),
        "float" => {
            let mut number = 0f64;
            if ffi::qjs_to_float64(ctx, &mut number, value.raw()) != 0 {
                return Err(());
            }
            output.extend_from_slice(&(number as f32).to_ne_bytes());
        }
        "double" => {
            let mut number = 0f64;
            if ffi::qjs_to_float64(ctx, &mut number, value.raw()) != 0 {
                return Err(());
            }
            output.extend_from_slice(&number.to_ne_bytes());
        }
        _ => return Err(()),
    }
    Ok(())
}

/// `Java._newArray(type, elements)` — build a Java array from a JS array.
///
/// Primitive arrays are filled with one `Set<Type>ArrayRegion` call; object
/// arrays take the element class from `type` and store handles one by one.
unsafe extern "C" fn js_java_new_array(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return throw_internal_error(ctx, "Java.array(type, elements) requires two arguments");
    }
    let Some(type_name) = JSValue(*argv).to_string(ctx) else {
        return throw_internal_error(ctx, "Java.array() element type must be a string");
    };
    let elements = JSValue(*argv.add(1));
    let length_value = JSValue(ffi::JS_GetPropertyStr(ctx, elements.raw(), c"length".as_ptr()));
    let length = length_value.to_i64(ctx);
    length_value.free(ctx);
    let Some(length) = length.filter(|length| (0..=0x7fff_ffff).contains(length)) else {
        return throw_internal_error(ctx, "Java.array() elements must be an array");
    };
    let length = length as i32;

    let Ok(env) = get_thread_env() else {
        return throw_internal_error(ctx, "Java.array() could not attach the current thread");
    };

    if let Some(kind) = PRIMITIVE_ARRAYS.iter().find(|kind| kind.name == type_name) {
        let new_array: NewPrimitiveArrayFn = std::mem::transmute(jni_fn_ptr(env, kind.new_index));
        let array = new_array(env, length);
        if array.is_null() || jni_check_exc(env) {
            return throw_internal_error(ctx, format!("Java.array(): could not allocate {type_name}[{length}]"));
        }

        let mut buffer = Vec::with_capacity(length as usize * kind.element_size);
        for index in 0..length {
            let element = JSValue(ffi::JS_GetPropertyUint32(ctx, elements.raw(), index as u32));
            let encoded = encode_primitive_element(ctx, kind, element, &mut buffer);
            element.free(ctx);
            if encoded.is_err() {
                return throw_internal_error(ctx, format!("Java.array(): element {index} is not a {type_name}"));
            }
        }
        if length != 0 {
            let set_region: SetPrimitiveArrayRegionFn = std::mem::transmute(jni_fn_ptr(env, kind.set_region_index));
            set_region(env, array, 0, length, buffer.as_ptr() as *const std::ffi::c_void);
            if jni_check_exc(env) {
                return throw_internal_error(ctx, "Java.array(): could not populate the array");
            }
        }
        return ffi::qjs_new_int64(ctx, array as i64);
    }

    let element_class = super::reflect::find_class_safe(env, &type_name);
    if element_class.is_null() {
        return throw_internal_error(ctx, format!("Java.array(): class not found: {type_name}"));
    }
    let new_object_array: NewObjectArrayFn = std::mem::transmute(jni_fn_ptr(env, JNI_NEW_OBJECT_ARRAY));
    let array = new_object_array(env, length, element_class, std::ptr::null_mut());
    if array.is_null() || jni_check_exc(env) {
        return throw_internal_error(ctx, format!("Java.array(): could not allocate {type_name}[{length}]"));
    }
    let set_element: SetObjectArrayElementFn = std::mem::transmute(jni_fn_ptr(env, JNI_SET_OBJECT_ARRAY_ELEMENT));
    for index in 0..length {
        let element = JSValue(ffi::JS_GetPropertyUint32(ctx, elements.raw(), index as u32));
        // The bootstrap hands us raw handles, so a null element is a real null.
        let handle = element.to_u64(ctx).unwrap_or(0);
        element.free(ctx);
        set_element(env, array, index, handle as *mut std::ffi::c_void);
        if jni_check_exc(env) {
            return throw_internal_error(ctx, format!("Java.array(): could not store element {index}"));
        }
    }
    ffi::qjs_new_int64(ctx, array as i64)
}

pub(super) fn register_java_compat_api(ctx_ptr: *mut ffi::JSContext, java_obj: ffi::JSValue) {
    use crate::jsapi::util::add_cfunction_to_object;

    unsafe {
        add_cfunction_to_object(ctx_ptr, java_obj, "_available", js_java_available, 0);
        add_cfunction_to_object(ctx_ptr, java_obj, "_androidVersion", js_java_android_version, 0);
        add_cfunction_to_object(ctx_ptr, java_obj, "_isMainThread", js_java_is_main_thread, 0);
        add_cfunction_to_object(ctx_ptr, java_obj, "_monitorEnter", js_java_monitor_enter, 1);
        add_cfunction_to_object(ctx_ptr, java_obj, "_monitorExit", js_java_monitor_exit, 1);
        add_cfunction_to_object(
            ctx_ptr,
            java_obj,
            "_enumerateLoadedClasses",
            js_java_enumerate_loaded_classes,
            0,
        );
        add_cfunction_to_object(ctx_ptr, java_obj, "_newGlobalRef", js_java_new_global_ref, 1);
        add_cfunction_to_object(ctx_ptr, java_obj, "_deleteGlobalRef", js_java_delete_global_ref, 1);
        add_cfunction_to_object(ctx_ptr, java_obj, "_isInstanceOf", js_java_is_instance_of, 2);
        add_cfunction_to_object(ctx_ptr, java_obj, "_newArray", js_java_new_array, 2);
    }
}
