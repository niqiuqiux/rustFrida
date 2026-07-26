//! JNI reflection — method ID decoding, class resolution, method enumeration
//!
//! Contains: decode_method_id, ReflectIds, cache_reflect_ids, find_class_safe,
//! MethodInfo, java_type_to_jni, enumerate_methods.

use crate::jsapi::console::output_verbose;
use std::collections::HashMap;
use std::ffi::CString;
use std::sync::Mutex;

use super::jni_core::*;

// ============================================================================
// Encoded jmethodID / jfieldID decoder (Android 11+)
// ============================================================================

/// Generic JNI ID decoder.  Shared logic for both jmethodID and jfieldID.
///
/// Strategy (对标 Frida unwrapGenericId):
/// 1. 快速路径: jni_ids_indirection_ == kPointer → 直接返回
/// 2. bit 0 == 0 → 原始指针，无需解码
/// 3. JniIdManager decode 函数 (dlsym 直接调用)
/// 4. Fallback: ToReflected* → reflect 对象 → art* 字段 (long)
/// Common fn signature for ToReflectedMethod / ToReflectedField
type ToReflectedFn =
    unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, u8) -> *mut std::ffi::c_void;

unsafe fn decode_jni_id<F1, F2>(
    env: JniEnv,
    cls: *mut std::ffi::c_void,
    id: u64,
    is_static: bool,
    label: &str,
    art_label: &str,
    art_short: &str,
    decode_via_manager: F1,
    get_reflect_field_id: F2,
    to_reflected_fn: ToReflectedFn,
) -> u64
where
    F1: FnOnce(u64) -> Option<u64>,
    F2: FnOnce(&ReflectIds) -> *mut std::ffi::c_void,
{
    if id == 0 {
        return 0;
    }

    if super::jni_core::is_jni_pointer_mode() {
        return id;
    }

    if id & 1 == 0 {
        return id;
    }

    // Strategy 1: JniIdManager decode (对标 Frida unwrapGenericId)
    if let Some(result) = decode_via_manager(id) {
        if result != id {
            output_verbose(&format!(
                "[jni] decode_{label}({id:#x}): Decode → {art_label}={result:#x}"
            ));
        }
        return result;
    }

    // Strategy 2: Fallback — ToReflected* → art* 字段 (long)
    let art_field_id = match REFLECT_IDS.get() {
        Some(r) => {
            let fid = get_reflect_field_id(r);
            if fid.is_null() {
                output_verbose(&format!(
                    "[jni] decode_{label}({id:#x}): no decoder available, returning raw"
                ));
                return id;
            }
            fid
        }
        _ => {
            output_verbose(&format!(
                "[jni] decode_{label}({id:#x}): no decoder available, returning raw"
            ));
            return id;
        }
    };

    let get_long: GetLongFieldFn = jni_fn!(env, GetLongFieldFn, JNI_GET_LONG_FIELD);
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);

    let reflected_obj = to_reflected_fn(env, cls, id as *mut std::ffi::c_void, if is_static { 1 } else { 0 });
    if jni_null_or_exc(env, reflected_obj) {
        output_verbose(&format!("[jni] decode_{label}({id:#x}): ToReflected failed"));
        return id;
    }

    let art_ptr = get_long(env, reflected_obj, art_field_id) as u64;
    delete_local_ref(env, reflected_obj);

    output_verbose(&format!(
        "[jni] decode_{label}({id:#x}) → {art_short}={art_ptr:#x} (via reflection)"
    ));

    art_ptr
}

pub(super) unsafe fn decode_method_id(env: JniEnv, cls: *mut std::ffi::c_void, method_id: u64, is_static: bool) -> u64 {
    let to_reflected: ToReflectedMethodFn = jni_fn!(env, ToReflectedMethodFn, JNI_TO_REFLECTED_METHOD);
    decode_jni_id(
        env,
        cls,
        method_id,
        is_static,
        "method_id",
        "ArtMethod*",
        "artMethod",
        |id| super::jni_core::decode_method_id_via_manager(id),
        |r| r.art_method_field_id,
        to_reflected,
    )
}

#[allow(dead_code)]
pub(super) unsafe fn decode_field_id(env: JniEnv, cls: *mut std::ffi::c_void, field_id: u64, is_static: bool) -> u64 {
    let to_reflected: ToReflectedFieldFn = jni_fn!(env, ToReflectedFieldFn, JNI_TO_REFLECTED_FIELD);
    decode_jni_id(
        env,
        cls,
        field_id,
        is_static,
        "field_id",
        "ArtField*",
        "artField",
        |id| super::jni_core::decode_field_id_via_manager(id),
        |r| r.art_field_field_id,
        to_reflected,
    )
}

// ============================================================================
// Cached JNI reflection method IDs (safe to reuse across threads)
// ============================================================================

/// Pre-cached JNI method IDs for field reflection.
/// Initialized once from the safe init thread (via `register_java_api`),
/// then used from hook callback threads without calling FindClass.
pub(super) struct ReflectIds {
    /// Class.getField(String) → Field
    #[allow(dead_code)]
    pub(super) get_field_mid: *mut std::ffi::c_void,
    /// Class.getDeclaredField(String) → Field
    #[allow(dead_code)]
    pub(super) get_declared_field_mid: *mut std::ffi::c_void,
    /// Field.getType() → Class
    #[allow(dead_code)]
    pub(super) field_get_type_mid: *mut std::ffi::c_void,
    /// Class.getName() → String
    pub(super) class_get_name_mid: *mut std::ffi::c_void,
    /// Global ref to java.lang.String class (for IsInstanceOf checks in callbacks)
    #[allow(dead_code)]
    pub(super) string_class: *mut std::ffi::c_void,
    // 下面六个和 string_class 一样，是初始化时一次性查好的 List/Array marshaling id。
    // 现在的 marshal 路径按 JNI 签名分派，还没有回头读它们。
    /// Global ref to java.util.List for automatic List/ArrayList marshaling
    #[allow(dead_code)]
    pub(super) list_class: *mut std::ffi::c_void,
    /// java.util.List.size() -> int
    #[allow(dead_code)]
    pub(super) list_size_mid: *mut std::ffi::c_void,
    /// java.util.List.get(int) -> Object
    #[allow(dead_code)]
    pub(super) list_get_mid: *mut std::ffi::c_void,
    /// Global ref to java.lang.reflect.Array for automatic Java array marshaling
    #[allow(dead_code)]
    pub(super) array_class: *mut std::ffi::c_void,
    /// Array.getLength(Object) -> int
    #[allow(dead_code)]
    pub(super) array_get_length_mid: *mut std::ffi::c_void,
    /// Array.get(Object, int) -> Object
    #[allow(dead_code)]
    pub(super) array_get_mid: *mut std::ffi::c_void,
    /// java.lang.Boolean.booleanValue() -> boolean
    pub(super) boolean_value_mid: *mut std::ffi::c_void,
    /// java.lang.Byte.byteValue() -> byte
    pub(super) byte_value_mid: *mut std::ffi::c_void,
    /// java.lang.Character.charValue() -> char
    pub(super) char_value_mid: *mut std::ffi::c_void,
    /// java.lang.Short.shortValue() -> short
    pub(super) short_value_mid: *mut std::ffi::c_void,
    /// java.lang.Integer.intValue() -> int
    pub(super) int_value_mid: *mut std::ffi::c_void,
    /// java.lang.Long.longValue() -> long
    pub(super) long_value_mid: *mut std::ffi::c_void,
    /// java.lang.Float.floatValue() -> float
    pub(super) float_value_mid: *mut std::ffi::c_void,
    /// java.lang.Double.doubleValue() -> double
    pub(super) double_value_mid: *mut std::ffi::c_void,
    /// Global ref to the app's ClassLoader (for loading app classes from native threads)
    pub(super) app_classloader: *mut std::ffi::c_void,
    /// ClassLoader.loadClass(String) method ID
    pub(super) load_class_mid: *mut std::ffi::c_void,
    /// Field ID for java.lang.reflect.Executable.artMethod (long) — used to decode encoded jmethodIDs
    pub(super) art_method_field_id: *mut std::ffi::c_void,
    /// Field ID for java.lang.reflect.Field.artField (long) — used to decode encoded jfieldIDs
    #[allow(dead_code)]
    pub(super) art_field_field_id: *mut std::ffi::c_void,
}

unsafe impl Send for ReflectIds {}
unsafe impl Sync for ReflectIds {}

pub(super) static REFLECT_IDS: std::sync::OnceLock<ReflectIds> = std::sync::OnceLock::new();

pub(crate) fn is_reflect_ids_ready() -> bool {
    REFLECT_IDS.get().is_some()
}

// ClassLoader 动态覆盖：spawn 模式下 jsinit 时 ClassLoader 不可用，
// Java.ready() gate 触发后通过 update_app_classloader() 设置。
use std::sync::atomic::AtomicU64;
/// app ClassLoader global ref（由 Java._updateClassLoader 设置）
pub(super) static CL_OVERRIDE: AtomicU64 = AtomicU64::new(0);
/// ClassLoader.loadClass method ID（随 CL_OVERRIDE 一起设置）
pub(super) static LC_MID_OVERRIDE: AtomicU64 = AtomicU64::new(0);
/// JS 枚举接口临时持有的 ClassLoader global refs，供 cleanup 时统一释放。
static ENUMERATED_CLASSLOADER_REFS: Mutex<Vec<u64>> = Mutex::new(Vec::new());
/// 已解析类的 global refs，避免在 hook callback 中再次触发 FindClass/WalkStack。
static CACHED_CLASS_REFS: Mutex<Option<HashMap<String, u64>>> = Mutex::new(None);

pub(super) struct ClassLoaderInfo {
    pub(super) ptr: u64,
    pub(super) source: String,
    pub(super) loader_class_name: String,
    pub(super) description: String,
}

unsafe fn read_java_string(env: JniEnv, jstr: *mut std::ffi::c_void) -> Option<String> {
    if jstr.is_null() {
        return None;
    }

    let get_str: GetStringUtfCharsFn = jni_fn!(env, GetStringUtfCharsFn, JNI_GET_STRING_UTF_CHARS);
    let rel_str: ReleaseStringUtfCharsFn = jni_fn!(env, ReleaseStringUtfCharsFn, JNI_RELEASE_STRING_UTF_CHARS);
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);

    let chars = get_str(env, jstr, std::ptr::null_mut());
    if chars.is_null() {
        delete_local_ref(env, jstr);
        jni_check_exc(env);
        return None;
    }

    let value = std::ffi::CStr::from_ptr(chars).to_string_lossy().to_string();
    rel_str(env, jstr, chars);
    delete_local_ref(env, jstr);
    Some(value)
}

unsafe fn describe_classloader(env: JniEnv, loader: *mut std::ffi::c_void) -> (String, String) {
    if env.is_null() || loader.is_null() {
        return ("<null>".to_string(), "<null>".to_string());
    }

    let find_class: FindClassFn = jni_fn!(env, FindClassFn, JNI_FIND_CLASS);
    let get_mid: GetMethodIdFn = jni_fn!(env, GetMethodIdFn, JNI_GET_METHOD_ID);
    let get_object_class: GetObjectClassFn = jni_fn!(env, GetObjectClassFn, JNI_GET_OBJECT_CLASS);
    let call_obj: CallObjectMethodAFn = jni_fn!(env, CallObjectMethodAFn, JNI_CALL_OBJECT_METHOD_A);
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);

    let loader_cls = get_object_class(env, loader);
    let loader_class_name = if jni_null_or_exc(env, loader_cls) {
        "<unknown>".to_string()
    } else {
        let name = get_class_name_unchecked(env as u64, loader_cls as u64).unwrap_or_else(|| "<unknown>".to_string());
        delete_local_ref(env, loader_cls);
        name
    };

    let object_cls_name = CString::new("java/lang/Object").unwrap();
    let object_cls = find_class(env, object_cls_name.as_ptr());
    if jni_null_or_exc(env, object_cls) {
        return (loader_class_name.clone(), loader_class_name);
    }

    let to_string_name = CString::new("toString").unwrap();
    let to_string_sig = CString::new("()Ljava/lang/String;").unwrap();
    let to_string_mid = get_mid(env, object_cls, to_string_name.as_ptr(), to_string_sig.as_ptr());
    let to_string_failed = jni_null_or_exc(env, to_string_mid);
    delete_local_ref(env, object_cls);
    if to_string_failed {
        return (loader_class_name.clone(), loader_class_name);
    }

    let desc = call_obj(env, loader, to_string_mid, std::ptr::null());
    if jni_null_or_exc(env, desc) {
        return (loader_class_name.clone(), loader_class_name);
    }

    let description = read_java_string(env, desc).unwrap_or_else(|| loader_class_name.clone());
    (loader_class_name, description)
}

unsafe fn remember_enumerated_classloader_ref(ptr: u64) {
    if ptr == 0 {
        return;
    }
    let mut refs = ENUMERATED_CLASSLOADER_REFS.lock().unwrap_or_else(|e| e.into_inner());
    refs.push(ptr);
}

fn is_known_global_classloader_ref(ptr: u64) -> bool {
    if ptr == 0 {
        return false;
    }
    let override_cl = CL_OVERRIDE.load(std::sync::atomic::Ordering::Acquire);
    if override_cl == ptr {
        return true;
    }
    if REFLECT_IDS.get().map_or(false, |r| r.app_classloader as u64 == ptr) {
        return true;
    }
    let refs = ENUMERATED_CLASSLOADER_REFS.lock().unwrap_or_else(|e| e.into_inner());
    refs.contains(&ptr)
}

pub(super) fn set_classloader_override_global_fast(loader_ptr: u64) -> bool {
    if loader_ptr == 0 {
        return false;
    }

    let current_mid = LC_MID_OVERRIDE.load(std::sync::atomic::Ordering::Acquire);
    let reflect_mid = REFLECT_IDS.get().map_or(0, |r| r.load_class_mid as u64);
    let load_class_mid = if current_mid != 0 { current_mid } else { reflect_mid };
    if load_class_mid == 0 {
        output_verbose("[java.classloader] fast setClassLoader skipped: loadClass method ID unavailable");
        return false;
    }
    if !is_known_global_classloader_ref(loader_ptr) {
        output_verbose(&format!(
            "[java.classloader] fast setClassLoader skipped: loader is not a known global ref ({:#x})",
            loader_ptr
        ));
        return false;
    }

    CL_OVERRIDE.store(loader_ptr, std::sync::atomic::Ordering::Release);
    LC_MID_OVERRIDE.store(load_class_mid, std::sync::atomic::Ordering::Release);
    output_verbose(&format!(
        "[java.classloader] fast setClassLoader override -> {:#x}",
        loader_ptr
    ));
    true
}

unsafe fn is_same_object_ref(env: JniEnv, left: *mut std::ffi::c_void, right: *mut std::ffi::c_void) -> bool {
    if env.is_null() || left.is_null() || right.is_null() {
        return false;
    }
    if left == right {
        return true;
    }
    let is_same_object: IsSameObjectFn = jni_fn!(env, IsSameObjectFn, JNI_IS_SAME_OBJECT);
    let same = is_same_object(env, left, right) != 0;
    let had_exc = jni_check_exc(env);
    same && !had_exc
}

unsafe fn classloader_already_listed(env: JniEnv, out: &[ClassLoaderInfo], loader: *mut std::ffi::c_void) -> bool {
    out.iter()
        .any(|info| is_same_object_ref(env, info.ptr as *mut std::ffi::c_void, loader))
}

unsafe fn jni_ptr_failed(env: JniEnv, ptr: *mut std::ffi::c_void) -> bool {
    let had_exc = jni_check_exc(env);
    ptr.is_null() || had_exc
}

#[inline]
fn normalize_class_name(class_name: &str) -> String {
    class_name.replace('/', ".")
}

unsafe fn get_cached_class_local_ref(env: JniEnv, class_name: &str) -> *mut std::ffi::c_void {
    let key = normalize_class_name(class_name);
    let ptr = {
        let refs = CACHED_CLASS_REFS.lock().unwrap_or_else(|e| e.into_inner());
        refs.as_ref().and_then(|m| m.get(&key).copied()).unwrap_or(0)
    };
    if ptr == 0 {
        return std::ptr::null_mut();
    }

    let new_local_ref: NewLocalRefFn = jni_fn!(env, NewLocalRefFn, JNI_NEW_LOCAL_REF);
    let local = new_local_ref(env, ptr as *mut std::ffi::c_void);
    if jni_null_or_exc(env, local) {
        return std::ptr::null_mut();
    }
    local
}

unsafe fn cache_class_global_ref(env: JniEnv, class_name: &str, cls_local: *mut std::ffi::c_void) {
    if cls_local.is_null() {
        return;
    }

    let key = normalize_class_name(class_name);
    {
        let refs = CACHED_CLASS_REFS.lock().unwrap_or_else(|e| e.into_inner());
        if refs.as_ref().map(|m| m.contains_key(&key)).unwrap_or(false) {
            return;
        }
    }

    let new_global_ref: NewGlobalRefFn = jni_fn!(env, NewGlobalRefFn, JNI_NEW_GLOBAL_REF);
    let gref = new_global_ref(env, cls_local);
    if jni_null_or_exc(env, gref) {
        return;
    }

    let mut refs = CACHED_CLASS_REFS.lock().unwrap_or_else(|e| e.into_inner());
    let map = refs.get_or_insert_with(HashMap::new);
    map.entry(key).or_insert(gref as u64);
}

pub(super) unsafe fn cleanup_enumerated_classloader_refs(env: JniEnv) {
    if env.is_null() {
        return;
    }
    let delete_global_ref: DeleteGlobalRefFn = jni_fn!(env, DeleteGlobalRefFn, JNI_DELETE_GLOBAL_REF);
    let mut refs = ENUMERATED_CLASSLOADER_REFS.lock().unwrap_or_else(|e| e.into_inner());
    for ptr in refs.drain(..) {
        if ptr != 0 {
            delete_global_ref(env, ptr as *mut std::ffi::c_void);
        }
    }
}

pub(super) unsafe fn cleanup_cached_class_refs(env: JniEnv) {
    let delete_global_ref: DeleteGlobalRefFn = jni_fn!(env, DeleteGlobalRefFn, JNI_DELETE_GLOBAL_REF);
    let mut refs = CACHED_CLASS_REFS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(map) = refs.as_mut() {
        for (_name, ptr) in map.drain() {
            if ptr != 0 {
                delete_global_ref(env, ptr as *mut std::ffi::c_void);
            }
        }
    }
}

unsafe fn capture_activitythread_app_classloader(env: JniEnv) -> *mut std::ffi::c_void {
    let find_class: FindClassFn = jni_fn!(env, FindClassFn, JNI_FIND_CLASS);
    let get_mid: GetMethodIdFn = jni_fn!(env, GetMethodIdFn, JNI_GET_METHOD_ID);
    let get_static_mid: GetStaticMethodIdFn = jni_fn!(env, GetStaticMethodIdFn, JNI_GET_STATIC_METHOD_ID);
    let call_static_obj: CallStaticObjectMethodAFn =
        jni_fn!(env, CallStaticObjectMethodAFn, JNI_CALL_STATIC_OBJECT_METHOD_A);
    let call_obj: CallObjectMethodAFn = jni_fn!(env, CallObjectMethodAFn, JNI_CALL_OBJECT_METHOD_A);
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);

    let c_at = CString::new("android/app/ActivityThread").unwrap();
    let at_cls = find_class(env, c_at.as_ptr());
    if jni_null_or_exc(env, at_cls) {
        return std::ptr::null_mut();
    }

    let c_cur = CString::new("currentActivityThread").unwrap();
    let c_cur_sig = CString::new("()Landroid/app/ActivityThread;").unwrap();
    let cur_mid = get_static_mid(env, at_cls, c_cur.as_ptr(), c_cur_sig.as_ptr());
    if jni_null_or_exc(env, cur_mid) {
        delete_local_ref(env, at_cls);
        return std::ptr::null_mut();
    }

    let at_obj = call_static_obj(env, at_cls, cur_mid, std::ptr::null());
    if jni_null_or_exc(env, at_obj) {
        delete_local_ref(env, at_cls);
        return std::ptr::null_mut();
    }

    let c_get_app = CString::new("getApplication").unwrap();
    let c_get_app_sig = CString::new("()Landroid/app/Application;").unwrap();
    let get_app_mid = get_mid(env, at_cls, c_get_app.as_ptr(), c_get_app_sig.as_ptr());
    let get_app_failed = jni_null_or_exc(env, get_app_mid);
    delete_local_ref(env, at_cls);
    if get_app_failed {
        delete_local_ref(env, at_obj);
        return std::ptr::null_mut();
    }

    let app = call_obj(env, at_obj, get_app_mid, std::ptr::null());
    delete_local_ref(env, at_obj);
    if jni_null_or_exc(env, app) {
        return std::ptr::null_mut();
    }

    let c_ctx = CString::new("android/content/Context").unwrap();
    let ctx_cls = find_class(env, c_ctx.as_ptr());
    if jni_null_or_exc(env, ctx_cls) {
        delete_local_ref(env, app);
        return std::ptr::null_mut();
    }

    let c_gcl = CString::new("getClassLoader").unwrap();
    let c_gcl_sig = CString::new("()Ljava/lang/ClassLoader;").unwrap();
    let gcl_mid = get_mid(env, ctx_cls, c_gcl.as_ptr(), c_gcl_sig.as_ptr());
    let gcl_failed = jni_null_or_exc(env, gcl_mid);
    delete_local_ref(env, ctx_cls);
    if gcl_failed {
        delete_local_ref(env, app);
        return std::ptr::null_mut();
    }

    let cl = call_obj(env, app, gcl_mid, std::ptr::null());
    delete_local_ref(env, app);
    if jni_null_or_exc(env, cl) {
        return std::ptr::null_mut();
    }

    cl
}

unsafe fn capture_thread_context_classloader(env: JniEnv) -> *mut std::ffi::c_void {
    let find_class: FindClassFn = jni_fn!(env, FindClassFn, JNI_FIND_CLASS);
    let get_mid: GetMethodIdFn = jni_fn!(env, GetMethodIdFn, JNI_GET_METHOD_ID);
    let get_static_mid: GetStaticMethodIdFn = jni_fn!(env, GetStaticMethodIdFn, JNI_GET_STATIC_METHOD_ID);
    let call_static_obj: CallStaticObjectMethodAFn =
        jni_fn!(env, CallStaticObjectMethodAFn, JNI_CALL_STATIC_OBJECT_METHOD_A);
    let call_obj: CallObjectMethodAFn = jni_fn!(env, CallObjectMethodAFn, JNI_CALL_OBJECT_METHOD_A);
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);

    let c_thread = CString::new("java/lang/Thread").unwrap();
    let thread_cls = find_class(env, c_thread.as_ptr());
    if jni_null_or_exc(env, thread_cls) {
        return std::ptr::null_mut();
    }

    let c_cur = CString::new("currentThread").unwrap();
    let c_cur_sig = CString::new("()Ljava/lang/Thread;").unwrap();
    let cur_mid = get_static_mid(env, thread_cls, c_cur.as_ptr(), c_cur_sig.as_ptr());
    if jni_null_or_exc(env, cur_mid) {
        delete_local_ref(env, thread_cls);
        return std::ptr::null_mut();
    }

    let thread = call_static_obj(env, thread_cls, cur_mid, std::ptr::null());
    if jni_null_or_exc(env, thread) {
        delete_local_ref(env, thread_cls);
        return std::ptr::null_mut();
    }

    let c_get_ctx = CString::new("getContextClassLoader").unwrap();
    let c_get_ctx_sig = CString::new("()Ljava/lang/ClassLoader;").unwrap();
    let get_ctx_mid = get_mid(env, thread_cls, c_get_ctx.as_ptr(), c_get_ctx_sig.as_ptr());
    let get_ctx_failed = jni_null_or_exc(env, get_ctx_mid);
    delete_local_ref(env, thread_cls);
    if get_ctx_failed {
        delete_local_ref(env, thread);
        return std::ptr::null_mut();
    }

    let loader = call_obj(env, thread, get_ctx_mid, std::ptr::null());
    delete_local_ref(env, thread);
    if jni_null_or_exc(env, loader) {
        return std::ptr::null_mut();
    }

    loader
}

unsafe fn capture_system_classloader(env: JniEnv) -> *mut std::ffi::c_void {
    let find_class: FindClassFn = jni_fn!(env, FindClassFn, JNI_FIND_CLASS);
    let get_static_mid: GetStaticMethodIdFn = jni_fn!(env, GetStaticMethodIdFn, JNI_GET_STATIC_METHOD_ID);
    let call_static_obj: CallStaticObjectMethodAFn =
        jni_fn!(env, CallStaticObjectMethodAFn, JNI_CALL_STATIC_OBJECT_METHOD_A);
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);

    let c_cl = CString::new("java/lang/ClassLoader").unwrap();
    let cl_cls = find_class(env, c_cl.as_ptr());
    if jni_null_or_exc(env, cl_cls) {
        return std::ptr::null_mut();
    }

    let c_get_sys = CString::new("getSystemClassLoader").unwrap();
    let c_get_sys_sig = CString::new("()Ljava/lang/ClassLoader;").unwrap();
    let get_sys_mid = get_static_mid(env, cl_cls, c_get_sys.as_ptr(), c_get_sys_sig.as_ptr());
    if jni_null_or_exc(env, get_sys_mid) {
        delete_local_ref(env, cl_cls);
        return std::ptr::null_mut();
    }

    let loader = call_static_obj(env, cl_cls, get_sys_mid, std::ptr::null());
    delete_local_ref(env, cl_cls);
    if jni_null_or_exc(env, loader) {
        return std::ptr::null_mut();
    }

    loader
}

unsafe fn append_classloader_chain(
    env: JniEnv,
    root: *mut std::ffi::c_void,
    source: &str,
    root_is_global_ref: bool,
    out: &mut Vec<ClassLoaderInfo>,
) {
    if root.is_null() {
        return;
    }

    let new_global_ref: NewGlobalRefFn = jni_fn!(env, NewGlobalRefFn, JNI_NEW_GLOBAL_REF);
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
    let find_class: FindClassFn = jni_fn!(env, FindClassFn, JNI_FIND_CLASS);
    let get_mid: GetMethodIdFn = jni_fn!(env, GetMethodIdFn, JNI_GET_METHOD_ID);
    let call_obj: CallObjectMethodAFn = jni_fn!(env, CallObjectMethodAFn, JNI_CALL_OBJECT_METHOD_A);

    let c_cl = CString::new("java/lang/ClassLoader").unwrap();
    let cl_cls = find_class(env, c_cl.as_ptr());
    if jni_null_or_exc(env, cl_cls) {
        if !root_is_global_ref {
            delete_local_ref(env, root);
        }
        return;
    }

    let c_parent = CString::new("getParent").unwrap();
    let c_parent_sig = CString::new("()Ljava/lang/ClassLoader;").unwrap();
    let parent_mid = get_mid(env, cl_cls, c_parent.as_ptr(), c_parent_sig.as_ptr());
    let parent_mid_failed = jni_null_or_exc(env, parent_mid);
    delete_local_ref(env, cl_cls);
    if parent_mid_failed {
        if !root_is_global_ref {
            delete_local_ref(env, root);
        }
        return;
    }

    let mut current = root;
    let mut is_global = root_is_global_ref;
    let mut depth = 0usize;

    loop {
        if current.is_null() || depth >= 16 {
            break;
        }

        let (global, owned_global) = if is_global {
            (current, false)
        } else {
            let g = new_global_ref(env, current);
            delete_local_ref(env, current);
            if jni_null_or_exc(env, g) {
                break;
            }
            (g, true)
        };

        if classloader_already_listed(env, out, global) {
            if owned_global {
                let delete_global_ref: DeleteGlobalRefFn = jni_fn!(env, DeleteGlobalRefFn, JNI_DELETE_GLOBAL_REF);
                delete_global_ref(env, global);
            }
            break;
        }

        if owned_global {
            remember_enumerated_classloader_ref(global as u64);
        }

        let (loader_class_name, description) = describe_classloader(env, global);
        out.push(ClassLoaderInfo {
            ptr: global as u64,
            source: if depth == 0 {
                source.to_string()
            } else {
                format!("{}#parent{}", source, depth)
            },
            loader_class_name,
            description,
        });

        let parent = call_obj(env, global, parent_mid, std::ptr::null());
        if jni_null_or_exc(env, parent) {
            break;
        }

        current = parent;
        is_global = false;
        depth += 1;
    }
}

unsafe fn vmdebug_enumerate_classloader_refs(
    env: JniEnv,
    classloader_cls: *mut std::ffi::c_void,
) -> Result<Vec<*mut std::ffi::c_void>, String> {
    let find_class: FindClassFn = jni_fn!(env, FindClassFn, JNI_FIND_CLASS);
    let get_static_mid: GetStaticMethodIdFn = jni_fn!(env, GetStaticMethodIdFn, JNI_GET_STATIC_METHOD_ID);
    let call_static_obj: CallStaticObjectMethodAFn =
        jni_fn!(env, CallStaticObjectMethodAFn, JNI_CALL_STATIC_OBJECT_METHOD_A);
    let new_obj_array: NewObjectArrayFn = jni_fn!(env, NewObjectArrayFn, JNI_NEW_OBJECT_ARRAY);
    let set_obj_array_elem: SetObjectArrayElementFn =
        jni_fn!(env, SetObjectArrayElementFn, JNI_SET_OBJECT_ARRAY_ELEMENT);
    let get_arr_len: GetArrayLengthFn = jni_fn!(env, GetArrayLengthFn, JNI_GET_ARRAY_LENGTH);
    let get_arr_elem: GetObjectArrayElementFn = jni_fn!(env, GetObjectArrayElementFn, JNI_GET_OBJECT_ARRAY_ELEMENT);
    let new_global_ref: NewGlobalRefFn = jni_fn!(env, NewGlobalRefFn, JNI_NEW_GLOBAL_REF);
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);

    let c_class = CString::new("java/lang/Class").unwrap();
    let class_cls = find_class(env, c_class.as_ptr());
    if jni_ptr_failed(env, class_cls) {
        return Err("java.lang.Class not found".to_string());
    }

    let c_vmdebug = CString::new("dalvik/system/VMDebug").unwrap();
    let vmdebug_cls = find_class(env, c_vmdebug.as_ptr());
    if jni_ptr_failed(env, vmdebug_cls) {
        delete_local_ref(env, class_cls);
        return Err("dalvik.system.VMDebug not found".to_string());
    }

    let c_name_main = CString::new("getInstancesOfClasses").unwrap();
    let c_name_native = CString::new("getInstancesOfClassesNative").unwrap();
    let c_sig_2d = CString::new("([Ljava/lang/Class;Z)[[Ljava/lang/Object;").unwrap();
    let c_sig_1d = CString::new("([Ljava/lang/Class;Z)[Ljava/lang/Object;").unwrap();

    let mut mid = get_static_mid(env, vmdebug_cls, c_name_main.as_ptr(), c_sig_2d.as_ptr());
    let mut is_2d = true;
    if mid.is_null() {
        jni_check_exc(env);
        mid = get_static_mid(env, vmdebug_cls, c_name_main.as_ptr(), c_sig_1d.as_ptr());
        is_2d = false;
    }
    if mid.is_null() {
        jni_check_exc(env);
        mid = get_static_mid(env, vmdebug_cls, c_name_native.as_ptr(), c_sig_1d.as_ptr());
        is_2d = false;
    }
    if jni_ptr_failed(env, mid) {
        delete_local_ref(env, class_cls);
        delete_local_ref(env, vmdebug_cls);
        return Err("VMDebug.getInstancesOfClasses[Native] unavailable".to_string());
    }

    let classes_arr = new_obj_array(env, 1, class_cls, std::ptr::null_mut());
    if jni_ptr_failed(env, classes_arr) {
        delete_local_ref(env, class_cls);
        delete_local_ref(env, vmdebug_cls);
        return Err("NewObjectArray(Class[1]) failed".to_string());
    }
    set_obj_array_elem(env, classes_arr, 0, classloader_cls);
    if jni_check_exc(env) {
        delete_local_ref(env, classes_arr);
        delete_local_ref(env, class_cls);
        delete_local_ref(env, vmdebug_cls);
        return Err("SetObjectArrayElement failed".to_string());
    }

    let args: [u64; 2] = [classes_arr as u64, 1];
    let raw_result = call_static_obj(env, vmdebug_cls, mid, args.as_ptr() as *const std::ffi::c_void);

    delete_local_ref(env, classes_arr);
    delete_local_ref(env, class_cls);
    delete_local_ref(env, vmdebug_cls);

    if jni_ptr_failed(env, raw_result) {
        if !raw_result.is_null() {
            delete_local_ref(env, raw_result);
        }
        return Err("VMDebug.getInstancesOfClasses returned null or threw".to_string());
    }

    let instances_arr = if is_2d {
        let inner = get_arr_elem(env, raw_result, 0);
        delete_local_ref(env, raw_result);
        if jni_ptr_failed(env, inner) {
            return Err("VMDebug result[0] is null".to_string());
        }
        inner
    } else {
        raw_result
    };

    let len = get_arr_len(env, instances_arr);
    if jni_negative_or_exc(env, len) {
        delete_local_ref(env, instances_arr);
        return Err("GetArrayLength failed".to_string());
    }

    let mut out = Vec::new();
    for i in 0..len {
        let loader = get_arr_elem(env, instances_arr, i);
        if jni_ptr_failed(env, loader) {
            continue;
        }
        let global = new_global_ref(env, loader);
        delete_local_ref(env, loader);
        if jni_ptr_failed(env, global) {
            continue;
        }
        out.push(global);
    }
    delete_local_ref(env, instances_arr);

    Ok(out)
}

unsafe fn append_vmdebug_classloaders(env: JniEnv, out: &mut Vec<ClassLoaderInfo>) {
    let find_class: FindClassFn = jni_fn!(env, FindClassFn, JNI_FIND_CLASS);
    let new_global_ref: NewGlobalRefFn = jni_fn!(env, NewGlobalRefFn, JNI_NEW_GLOBAL_REF);
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
    let delete_global_ref: DeleteGlobalRefFn = jni_fn!(env, DeleteGlobalRefFn, JNI_DELETE_GLOBAL_REF);

    let c_cl = CString::new("java/lang/ClassLoader").unwrap();
    let cl_local = find_class(env, c_cl.as_ptr());
    if jni_ptr_failed(env, cl_local) {
        return;
    }
    let cl_global = new_global_ref(env, cl_local);
    delete_local_ref(env, cl_local);
    if jni_ptr_failed(env, cl_global) {
        return;
    }

    let loaders = match vmdebug_enumerate_classloader_refs(env, cl_global) {
        Ok(v) => v,
        Err(err) => {
            output_verbose(&format!("[java.classloader] VMDebug enumerate failed: {}", err));
            delete_global_ref(env, cl_global);
            return;
        }
    };
    delete_global_ref(env, cl_global);

    let mut index = 0usize;
    for loader in loaders {
        if loader.is_null() {
            continue;
        }
        if classloader_already_listed(env, out, loader) {
            delete_global_ref(env, loader);
            continue;
        }

        remember_enumerated_classloader_ref(loader as u64);
        let (loader_class_name, description) = describe_classloader(env, loader);
        out.push(ClassLoaderInfo {
            ptr: loader as u64,
            source: format!("vmdebug#{}", index),
            loader_class_name,
            description,
        });
        index += 1;
    }
}

pub(super) unsafe fn enumerate_classloaders(env: JniEnv) -> Vec<ClassLoaderInfo> {
    let mut out = Vec::new();

    let override_cl = CL_OVERRIDE.load(std::sync::atomic::Ordering::Acquire);
    if override_cl != 0 {
        append_classloader_chain(env, override_cl as *mut std::ffi::c_void, "override", true, &mut out);
    }

    if let Some(reflect) = REFLECT_IDS.get() {
        if !reflect.app_classloader.is_null() {
            append_classloader_chain(env, reflect.app_classloader, "cached_app", true, &mut out);
        }
    }

    let activitythread_cl = capture_activitythread_app_classloader(env);
    append_classloader_chain(env, activitythread_cl, "activity_thread", false, &mut out);

    let thread_ctx_cl = capture_thread_context_classloader(env);
    append_classloader_chain(env, thread_ctx_cl, "thread_context", false, &mut out);

    let system_cl = capture_system_classloader(env);
    append_classloader_chain(env, system_cl, "system", false, &mut out);

    append_vmdebug_classloaders(env, &mut out);

    out
}

pub(super) unsafe fn set_classloader_override(env: JniEnv, loader: *mut std::ffi::c_void) -> bool {
    if env.is_null() || loader.is_null() {
        output_verbose("[java.classloader] setClassLoader skipped: null JNIEnv or loader");
        return false;
    }
    update_app_classloader(env, loader)
}

pub(super) unsafe fn find_class_with_loader(
    env: JniEnv,
    loader: *mut std::ffi::c_void,
    class_name: &str,
) -> Option<&'static str> {
    if env.is_null() || loader.is_null() {
        return None;
    }

    jni_check_exc(env);

    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
    let result = find_loaded_class_via_loader(env, loader, class_name);
    if result.is_null() {
        return None;
    }
    delete_local_ref(env, result);
    Some("findLoadedClass")
}

unsafe fn find_class_via_single_loader(
    env: JniEnv,
    loader: *mut std::ffi::c_void,
    class_name: &str,
    load_class_mid: *mut std::ffi::c_void,
) -> *mut std::ffi::c_void {
    if env.is_null() || loader.is_null() {
        return std::ptr::null_mut();
    }

    let new_string_utf: NewStringUtfFn = jni_fn!(env, NewStringUtfFn, JNI_NEW_STRING_UTF);
    let call_obj: CallObjectMethodAFn = jni_fn!(env, CallObjectMethodAFn, JNI_CALL_OBJECT_METHOD_A);
    let get_object_class: GetObjectClassFn = jni_fn!(env, GetObjectClassFn, JNI_GET_OBJECT_CLASS);
    let get_mid: GetMethodIdFn = jni_fn!(env, GetMethodIdFn, JNI_GET_METHOD_ID);
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);

    let lc_mid = if !load_class_mid.is_null() {
        load_class_mid
    } else {
        let loader_cls = get_object_class(env, loader);
        if jni_null_or_exc(env, loader_cls) {
            return std::ptr::null_mut();
        }
        let c_lc = CString::new("loadClass").unwrap();
        let c_lc_sig = CString::new("(Ljava/lang/String;)Ljava/lang/Class;").unwrap();
        let mid = get_mid(env, loader_cls, c_lc.as_ptr(), c_lc_sig.as_ptr());
        let mid_failed = jni_null_or_exc(env, mid);
        delete_local_ref(env, loader_cls);
        if mid_failed {
            return std::ptr::null_mut();
        }
        mid
    };

    let dot_name = class_name.replace('/', ".");
    let c_dot = match CString::new(dot_name) {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(),
    };
    let jstr = new_string_utf(env, c_dot.as_ptr());
    if jni_null_or_exc(env, jstr) {
        return std::ptr::null_mut();
    }

    let args: [*mut std::ffi::c_void; 1] = [jstr];
    let result = call_obj(env, loader, lc_mid, args.as_ptr() as *const std::ffi::c_void);
    let result_failed = jni_null_or_exc(env, result);
    delete_local_ref(env, jstr);
    if result_failed {
        return std::ptr::null_mut();
    }

    result
}

unsafe fn find_loaded_class_via_loader(
    env: JniEnv,
    loader: *mut std::ffi::c_void,
    class_name: &str,
) -> *mut std::ffi::c_void {
    if env.is_null() || loader.is_null() {
        return std::ptr::null_mut();
    }

    let get_object_class: GetObjectClassFn = jni_fn!(env, GetObjectClassFn, JNI_GET_OBJECT_CLASS);
    let get_mid: GetMethodIdFn = jni_fn!(env, GetMethodIdFn, JNI_GET_METHOD_ID);
    let new_string_utf: NewStringUtfFn = jni_fn!(env, NewStringUtfFn, JNI_NEW_STRING_UTF);
    let call_obj: CallObjectMethodAFn = jni_fn!(env, CallObjectMethodAFn, JNI_CALL_OBJECT_METHOD_A);
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);

    let loader_cls = get_object_class(env, loader);
    if jni_null_or_exc(env, loader_cls) {
        return std::ptr::null_mut();
    }

    let c_find_loaded = CString::new("findLoadedClass").unwrap();
    let c_find_loaded_sig = CString::new("(Ljava/lang/String;)Ljava/lang/Class;").unwrap();
    let mid = get_mid(env, loader_cls, c_find_loaded.as_ptr(), c_find_loaded_sig.as_ptr());
    let mid_failed = jni_null_or_exc(env, mid);
    delete_local_ref(env, loader_cls);
    if mid_failed {
        return std::ptr::null_mut();
    }

    let dot_name = class_name.replace('/', ".");
    let c_dot = match CString::new(dot_name) {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(),
    };
    let jstr = new_string_utf(env, c_dot.as_ptr());
    if jni_null_or_exc(env, jstr) {
        return std::ptr::null_mut();
    }

    let args: [*mut std::ffi::c_void; 1] = [jstr];
    let result = call_obj(env, loader, mid, args.as_ptr() as *const std::ffi::c_void);
    let result_failed = jni_null_or_exc(env, result);
    delete_local_ref(env, jstr);
    if result_failed {
        return std::ptr::null_mut();
    }

    result
}

/// 绕过 Android hidden API 限制。
/// 调用 VMRuntime.getRuntime().setHiddenApiExemptions(new String[]{""})
/// 使所有隐藏 API 对反射可见（getDeclaredFields 等不再过滤）。
unsafe fn bypass_hidden_api_restrictions(env: JniEnv) {
    let find_class: FindClassFn = jni_fn!(env, FindClassFn, JNI_FIND_CLASS);
    let get_static_mid: GetStaticMethodIdFn = jni_fn!(env, GetStaticMethodIdFn, JNI_GET_STATIC_METHOD_ID);
    let get_mid: GetMethodIdFn = jni_fn!(env, GetMethodIdFn, JNI_GET_METHOD_ID);
    let call_static_obj: CallStaticObjectMethodAFn =
        jni_fn!(env, CallStaticObjectMethodAFn, JNI_CALL_STATIC_OBJECT_METHOD_A);
    let call_void: CallVoidMethodAFn = jni_fn!(env, CallVoidMethodAFn, JNI_CALL_VOID_METHOD_A);
    let new_string_utf: NewStringUtfFn = jni_fn!(env, NewStringUtfFn, JNI_NEW_STRING_UTF);
    let new_obj_array: NewObjectArrayFn = jni_fn!(env, NewObjectArrayFn, JNI_NEW_OBJECT_ARRAY);
    let set_obj_array_elem: SetObjectArrayElementFn =
        jni_fn!(env, SetObjectArrayElementFn, JNI_SET_OBJECT_ARRAY_ELEMENT);
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);

    // 1. FindClass("dalvik/system/VMRuntime")
    let c_vmrt = CString::new("dalvik/system/VMRuntime").unwrap();
    let vmrt_cls = find_class(env, c_vmrt.as_ptr());
    if jni_null_or_exc(env, vmrt_cls) {
        output_verbose("[java] hidden API bypass: VMRuntime class not found (pre-Android 9?)");
        return;
    }

    // 2. VMRuntime.getRuntime() → VMRuntime instance
    let c_get_runtime = CString::new("getRuntime").unwrap();
    let c_get_runtime_sig = CString::new("()Ldalvik/system/VMRuntime;").unwrap();
    let get_runtime_mid = get_static_mid(env, vmrt_cls, c_get_runtime.as_ptr(), c_get_runtime_sig.as_ptr());
    if jni_null_or_exc(env, get_runtime_mid) {
        delete_local_ref(env, vmrt_cls);
        output_verbose("[java] hidden API bypass: getRuntime() not found");
        return;
    }
    let runtime = call_static_obj(env, vmrt_cls, get_runtime_mid, std::ptr::null());
    if jni_null_or_exc(env, runtime) {
        delete_local_ref(env, vmrt_cls);
        output_verbose("[java] hidden API bypass: getRuntime() returned null");
        return;
    }

    // 3. setHiddenApiExemptions(String[])
    let c_set = CString::new("setHiddenApiExemptions").unwrap();
    let c_set_sig = CString::new("([Ljava/lang/String;)V").unwrap();
    let set_mid = get_mid(env, vmrt_cls, c_set.as_ptr(), c_set_sig.as_ptr());
    if jni_null_or_exc(env, set_mid) {
        delete_local_ref(env, runtime);
        delete_local_ref(env, vmrt_cls);
        output_verbose("[java] hidden API bypass: setHiddenApiExemptions not found (pre-Android 10?)");
        return;
    }

    // 4. 构造 new String[]{""} — 空前缀匹配所有 API
    let c_str_cls = CString::new("java/lang/String").unwrap();
    let str_cls = find_class(env, c_str_cls.as_ptr());
    if jni_null_or_exc(env, str_cls) {
        delete_local_ref(env, runtime);
        delete_local_ref(env, vmrt_cls);
        return;
    }
    let c_empty = CString::new("").unwrap();
    let empty_str = new_string_utf(env, c_empty.as_ptr());
    let arr = new_obj_array(env, 1, str_cls, std::ptr::null_mut());
    if !arr.is_null() && !empty_str.is_null() {
        set_obj_array_elem(env, arr, 0, empty_str);

        // 5. 调用: runtime.setHiddenApiExemptions(arr)
        let args: [*mut std::ffi::c_void; 1] = [arr];
        call_void(env, runtime, set_mid, args.as_ptr() as *const std::ffi::c_void);
        if jni_check_exc(env) {
            output_verbose("[java] hidden API bypass: setHiddenApiExemptions threw exception");
        } else {
            output_verbose("[java] hidden API bypass: setHiddenApiExemptions(\"\") OK");
        }
    }

    if !arr.is_null() {
        delete_local_ref(env, arr);
    }
    if !empty_str.is_null() {
        delete_local_ref(env, empty_str);
    }
    delete_local_ref(env, str_cls);
    delete_local_ref(env, runtime);
    delete_local_ref(env, vmrt_cls);
    jni_check_exc(env);
}

/// Cache reflection method IDs. Must be called from a safe thread (not a hook callback)
/// because it uses FindClass which triggers ART stack walking.
pub(crate) unsafe fn ensure_reflect_ids(env: JniEnv) {
    cache_reflect_ids(env);
}

pub(super) unsafe fn cache_reflect_ids(env: JniEnv) {
    REFLECT_IDS.get_or_init(|| {
        // 初始化 JNI ID 解码器 (对标 Frida unwrapGenericId)
        // 优先使用 DecodeMethodId/DecodeFieldId dlsym 直接调用
        // 仅当 decode 函数不可用时才 fallback 强制写 kPointer
        super::jni_core::init_jni_id_decoder();

        // --- 绕过 Android hidden API 过滤 (API 28+) ---
        // VMRuntime.setHiddenApiExemptions(new String[]{""}) 将所有隐藏 API 豁免，
        // 使 getDeclaredFields() 能返回 mPackageName 等被过滤的字段。
        bypass_hidden_api_restrictions(env);

        let find_class: FindClassFn = jni_fn!(env, FindClassFn, JNI_FIND_CLASS);
        let get_mid: GetMethodIdFn = jni_fn!(env, GetMethodIdFn, JNI_GET_METHOD_ID);
        let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
        let new_global_ref: NewGlobalRefFn = jni_fn!(env, NewGlobalRefFn, JNI_NEW_GLOBAL_REF);

        let c_class_cls = CString::new("java/lang/Class").unwrap();
        let c_field_cls = CString::new("java/lang/reflect/Field").unwrap();
        let c_string_cls = CString::new("java/lang/String").unwrap();
        let c_list_cls = CString::new("java/util/List").unwrap();
        let c_array_cls = CString::new("java/lang/reflect/Array").unwrap();
        let c_boolean_cls = CString::new("java/lang/Boolean").unwrap();
        let c_byte_cls = CString::new("java/lang/Byte").unwrap();
        let c_character_cls = CString::new("java/lang/Character").unwrap();
        let c_short_cls = CString::new("java/lang/Short").unwrap();
        let c_integer_cls = CString::new("java/lang/Integer").unwrap();
        let c_long_cls = CString::new("java/lang/Long").unwrap();
        let c_float_cls = CString::new("java/lang/Float").unwrap();
        let c_double_cls = CString::new("java/lang/Double").unwrap();

        let class_cls = find_class(env, c_class_cls.as_ptr());
        let field_cls = find_class(env, c_field_cls.as_ptr());
        let string_cls_local = find_class(env, c_string_cls.as_ptr());
        let list_cls_local = find_class(env, c_list_cls.as_ptr());
        let array_cls_local = find_class(env, c_array_cls.as_ptr());
        let boolean_cls = find_class(env, c_boolean_cls.as_ptr());
        let byte_cls = find_class(env, c_byte_cls.as_ptr());
        let character_cls = find_class(env, c_character_cls.as_ptr());
        let short_cls = find_class(env, c_short_cls.as_ptr());
        let integer_cls = find_class(env, c_integer_cls.as_ptr());
        let long_cls = find_class(env, c_long_cls.as_ptr());
        let float_cls = find_class(env, c_float_cls.as_ptr());
        let double_cls = find_class(env, c_double_cls.as_ptr());
        jni_check_exc(env);

        // Create global refs for classes that must remain valid in hook callbacks
        let string_class = if !string_cls_local.is_null() {
            let g = new_global_ref(env, string_cls_local);
            delete_local_ref(env, string_cls_local);
            g
        } else {
            std::ptr::null_mut()
        };
        let list_class = if !list_cls_local.is_null() {
            let g = new_global_ref(env, list_cls_local);
            delete_local_ref(env, list_cls_local);
            g
        } else {
            std::ptr::null_mut()
        };
        let array_class = if !array_cls_local.is_null() {
            let g = new_global_ref(env, array_cls_local);
            delete_local_ref(env, array_cls_local);
            g
        } else {
            std::ptr::null_mut()
        };

        let c_get_field = CString::new("getField").unwrap();
        let c_get_declared = CString::new("getDeclaredField").unwrap();
        let c_field_sig = CString::new("(Ljava/lang/String;)Ljava/lang/reflect/Field;").unwrap();
        let c_get_type = CString::new("getType").unwrap();
        let c_get_type_sig = CString::new("()Ljava/lang/Class;").unwrap();
        let c_get_name = CString::new("getName").unwrap();
        let c_get_name_sig = CString::new("()Ljava/lang/String;").unwrap();
        let c_size = CString::new("size").unwrap();
        let c_size_sig = CString::new("()I").unwrap();
        let c_get = CString::new("get").unwrap();
        let c_list_get_sig = CString::new("(I)Ljava/lang/Object;").unwrap();
        let c_array_get_length = CString::new("getLength").unwrap();
        let c_array_get_length_sig = CString::new("(Ljava/lang/Object;)I").unwrap();
        let c_array_get = CString::new("get").unwrap();
        let c_array_get_sig = CString::new("(Ljava/lang/Object;I)Ljava/lang/Object;").unwrap();
        let c_boolean_value = CString::new("booleanValue").unwrap();
        let c_boolean_value_sig = CString::new("()Z").unwrap();
        let c_byte_value = CString::new("byteValue").unwrap();
        let c_byte_value_sig = CString::new("()B").unwrap();
        let c_char_value = CString::new("charValue").unwrap();
        let c_char_value_sig = CString::new("()C").unwrap();
        let c_short_value = CString::new("shortValue").unwrap();
        let c_short_value_sig = CString::new("()S").unwrap();
        let c_int_value = CString::new("intValue").unwrap();
        let c_int_value_sig = CString::new("()I").unwrap();
        let c_long_value = CString::new("longValue").unwrap();
        let c_long_value_sig = CString::new("()J").unwrap();
        let c_float_value = CString::new("floatValue").unwrap();
        let c_float_value_sig = CString::new("()F").unwrap();
        let c_double_value = CString::new("doubleValue").unwrap();
        let c_double_value_sig = CString::new("()D").unwrap();

        let get_field_mid = get_mid(env, class_cls, c_get_field.as_ptr(), c_field_sig.as_ptr());
        let get_declared_field_mid = get_mid(env, class_cls, c_get_declared.as_ptr(), c_field_sig.as_ptr());
        let field_get_type_mid = get_mid(env, field_cls, c_get_type.as_ptr(), c_get_type_sig.as_ptr());
        let class_get_name_mid = get_mid(env, class_cls, c_get_name.as_ptr(), c_get_name_sig.as_ptr());
        let get_static_mid: GetStaticMethodIdFn = jni_fn!(env, GetStaticMethodIdFn, JNI_GET_STATIC_METHOD_ID);
        let get_mid_if = |cls: *mut std::ffi::c_void, name: &CString, sig: &CString| {
            if cls.is_null() {
                std::ptr::null_mut()
            } else {
                get_mid(env, cls, name.as_ptr(), sig.as_ptr())
            }
        };
        let get_static_mid_if = |cls: *mut std::ffi::c_void, name: &CString, sig: &CString| {
            if cls.is_null() {
                std::ptr::null_mut()
            } else {
                get_static_mid(env, cls, name.as_ptr(), sig.as_ptr())
            }
        };

        let list_size_mid = get_mid_if(list_class, &c_size, &c_size_sig);
        let list_get_mid = get_mid_if(list_class, &c_get, &c_list_get_sig);
        let array_get_length_mid = get_static_mid_if(array_class, &c_array_get_length, &c_array_get_length_sig);
        let array_get_mid = get_static_mid_if(array_class, &c_array_get, &c_array_get_sig);
        let boolean_value_mid = get_mid_if(boolean_cls, &c_boolean_value, &c_boolean_value_sig);
        let byte_value_mid = get_mid_if(byte_cls, &c_byte_value, &c_byte_value_sig);
        let char_value_mid = get_mid_if(character_cls, &c_char_value, &c_char_value_sig);
        let short_value_mid = get_mid_if(short_cls, &c_short_value, &c_short_value_sig);
        let int_value_mid = get_mid_if(integer_cls, &c_int_value, &c_int_value_sig);
        let long_value_mid = get_mid_if(long_cls, &c_long_value, &c_long_value_sig);
        let float_value_mid = get_mid_if(float_cls, &c_float_value, &c_float_value_sig);
        let double_value_mid = get_mid_if(double_cls, &c_double_value, &c_double_value_sig);
        jni_check_exc(env);

        // Clean up local refs for the Class objects (method IDs are global)
        if !class_cls.is_null() {
            delete_local_ref(env, class_cls);
        }
        if !field_cls.is_null() {
            delete_local_ref(env, field_cls);
        }
        for cls in [
            boolean_cls,
            byte_cls,
            character_cls,
            short_cls,
            integer_cls,
            long_cls,
            float_cls,
            double_cls,
        ] {
            if !cls.is_null() {
                delete_local_ref(env, cls);
            }
        }

        // --- Capture app ClassLoader for loading app classes from native threads ---
        // ActivityThread.currentActivityThread().getApplication().getClassLoader()
        // Use CallObjectMethodA / CallStaticObjectMethodA with null jvalue* for no-arg methods
        let call_static_obj_a: CallStaticObjectMethodAFn =
            jni_fn!(env, CallStaticObjectMethodAFn, JNI_CALL_STATIC_OBJECT_METHOD_A);
        let call_obj_a: CallObjectMethodAFn = jni_fn!(env, CallObjectMethodAFn, JNI_CALL_OBJECT_METHOD_A);
        let get_static_mid: GetStaticMethodIdFn = jni_fn!(env, GetStaticMethodIdFn, JNI_GET_STATIC_METHOD_ID);

        let mut app_classloader: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut load_class_mid: *mut std::ffi::c_void = std::ptr::null_mut();
        let null_args: *const std::ffi::c_void = std::ptr::null();

        // Try to get the app ClassLoader
        let c_at = CString::new("android/app/ActivityThread").unwrap();
        let at_cls = find_class(env, c_at.as_ptr());
        if !jni_null_or_exc(env, at_cls) {
            let c_cur = CString::new("currentActivityThread").unwrap();
            let c_cur_sig = CString::new("()Landroid/app/ActivityThread;").unwrap();
            let cur_mid = get_static_mid(env, at_cls, c_cur.as_ptr(), c_cur_sig.as_ptr());

            if !jni_null_or_exc(env, cur_mid) {
                let at_obj = call_static_obj_a(env, at_cls, cur_mid, null_args);
                if !jni_null_or_exc(env, at_obj) {
                    let c_get_app = CString::new("getApplication").unwrap();
                    let c_get_app_sig = CString::new("()Landroid/app/Application;").unwrap();
                    let get_app_mid = get_mid(env, at_cls, c_get_app.as_ptr(), c_get_app_sig.as_ptr());

                    if !jni_null_or_exc(env, get_app_mid) {
                        let app = call_obj_a(env, at_obj, get_app_mid, null_args);
                        if !jni_null_or_exc(env, app) {
                            let c_ctx = CString::new("android/content/Context").unwrap();
                            let ctx_cls = find_class(env, c_ctx.as_ptr());
                            if !jni_null_or_exc(env, ctx_cls) {
                                let c_gcl = CString::new("getClassLoader").unwrap();
                                let c_gcl_sig = CString::new("()Ljava/lang/ClassLoader;").unwrap();
                                let gcl_mid = get_mid(env, ctx_cls, c_gcl.as_ptr(), c_gcl_sig.as_ptr());
                                if !jni_null_or_exc(env, gcl_mid) {
                                    let cl = call_obj_a(env, app, gcl_mid, null_args);
                                    if !jni_null_or_exc(env, cl) {
                                        app_classloader = new_global_ref(env, cl);
                                        jni_check_exc(env);
                                        let c_cl_cls = CString::new("java/lang/ClassLoader").unwrap();
                                        let cl_cls = find_class(env, c_cl_cls.as_ptr());
                                        if !jni_null_or_exc(env, cl_cls) {
                                            let c_lc = CString::new("loadClass").unwrap();
                                            let c_lc_sig =
                                                CString::new("(Ljava/lang/String;)Ljava/lang/Class;").unwrap();
                                            load_class_mid = get_mid(env, cl_cls, c_lc.as_ptr(), c_lc_sig.as_ptr());
                                            jni_check_exc(env);
                                            delete_local_ref(env, cl_cls);
                                        }
                                        delete_local_ref(env, cl);
                                    }
                                }
                                delete_local_ref(env, ctx_cls);
                            }
                            delete_local_ref(env, app);
                        }
                        delete_local_ref(env, at_obj);
                    }
                }
            }
            delete_local_ref(env, at_cls);
        }
        jni_check_exc(env);

        // --- Cache artMethod field ID for decoding encoded jmethodIDs (Android 11+) ---
        let get_field_id_fn: GetFieldIdFn = jni_fn!(env, GetFieldIdFn, JNI_GET_FIELD_ID);
        let mut art_method_field_id: *mut std::ffi::c_void = std::ptr::null_mut();

        for parent_cls_name in &[
            "java/lang/reflect/Executable",
            "java/lang/reflect/AbstractMethod",
            "java/lang/reflect/Method",
        ] {
            let c_cls_name = CString::new(*parent_cls_name).unwrap();
            let parent_cls = find_class(env, c_cls_name.as_ptr());
            if jni_null_or_exc(env, parent_cls) {
                continue;
            }
            let c_art = CString::new("artMethod").unwrap();
            let c_j = CString::new("J").unwrap();
            let fid = get_field_id_fn(env, parent_cls, c_art.as_ptr(), c_j.as_ptr());
            delete_local_ref(env, parent_cls);
            if !jni_null_or_exc(env, fid) {
                art_method_field_id = fid;
                output_verbose(&format!("[java] cached artMethod field ID from {}", parent_cls_name));
                break;
            }
        }

        // --- Cache artField field ID for decoding encoded jfieldIDs (Android 11+) ---
        let mut art_field_field_id: *mut std::ffi::c_void = std::ptr::null_mut();
        {
            let c_field_cls_name = CString::new("java/lang/reflect/Field").unwrap();
            let field_reflect_cls = find_class(env, c_field_cls_name.as_ptr());
            if !jni_null_or_exc(env, field_reflect_cls) {
                let c_art_field = CString::new("artField").unwrap();
                let c_j = CString::new("J").unwrap();
                let fid = get_field_id_fn(env, field_reflect_cls, c_art_field.as_ptr(), c_j.as_ptr());
                delete_local_ref(env, field_reflect_cls);
                if !jni_null_or_exc(env, fid) {
                    art_field_field_id = fid;
                    output_verbose("[java] cached artField field ID from java/lang/reflect/Field");
                }
            }
        }

        ReflectIds {
            get_field_mid,
            get_declared_field_mid,
            field_get_type_mid,
            class_get_name_mid,
            string_class,
            list_class,
            list_size_mid,
            list_get_mid,
            array_class,
            array_get_length_mid,
            array_get_mid,
            boolean_value_mid,
            byte_value_mid,
            char_value_mid,
            short_value_mid,
            int_value_mid,
            long_value_mid,
            float_value_mid,
            double_value_mid,
            app_classloader,
            load_class_mid,
            art_method_field_id,
            art_field_field_id,
        }
    });
}

/// 更新 app ClassLoader（由 Java.ready() gate hook 在 Instrumentation.newApplication 中调用）。
/// 将 local ref 转为 global ref 并缓存 loadClass method ID。
pub(super) unsafe fn update_app_classloader(env: JniEnv, cl_local: *mut std::ffi::c_void) -> bool {
    if env.is_null() || cl_local.is_null() {
        output_verbose("[java.classloader] update skipped: null JNIEnv or loader");
        return false;
    }

    let new_global_ref: NewGlobalRefFn = jni_fn!(env, NewGlobalRefFn, JNI_NEW_GLOBAL_REF);
    let delete_global_ref: DeleteGlobalRefFn = jni_fn!(env, DeleteGlobalRefFn, JNI_DELETE_GLOBAL_REF);
    let gl = new_global_ref(env, cl_local);
    if jni_null_or_exc(env, gl) {
        return false;
    }

    let get_object_class: GetObjectClassFn = jni_fn!(env, GetObjectClassFn, JNI_GET_OBJECT_CLASS);
    let get_mid: GetMethodIdFn = jni_fn!(env, GetMethodIdFn, JNI_GET_METHOD_ID);
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);

    // 避免在 Java.ready gate hook 中触发 FindClass → WalkStack/GetDexPc。
    // 这里已有 cl_local，直接取其运行时 Class 即可拿到对应 loadClass 方法。
    let cl_cls = get_object_class(env, gl);
    if jni_null_or_exc(env, cl_cls) {
        delete_global_ref(env, gl);
        return false;
    }
    let c_lc = CString::new("loadClass").unwrap();
    let c_lc_sig = CString::new("(Ljava/lang/String;)Ljava/lang/Class;").unwrap();
    let lc_mid = get_mid(env, cl_cls, c_lc.as_ptr(), c_lc_sig.as_ptr());
    let mid_failed = jni_null_or_exc(env, lc_mid);
    delete_local_ref(env, cl_cls);
    if mid_failed {
        delete_global_ref(env, gl);
        return false;
    }

    let old = CL_OVERRIDE.swap(gl as u64, std::sync::atomic::Ordering::AcqRel);
    LC_MID_OVERRIDE.store(lc_mid as u64, std::sync::atomic::Ordering::Release);
    if old != 0 && old != gl as u64 {
        delete_global_ref(env, old as *mut std::ffi::c_void);
    }
    jni_check_exc(env);
    true
}

/// 检查 app ClassLoader 是否可用（init 阶段或 override 阶段均算）
pub(super) fn is_classloader_ready() -> bool {
    if CL_OVERRIDE.load(std::sync::atomic::Ordering::Relaxed) != 0
        && LC_MID_OVERRIDE.load(std::sync::atomic::Ordering::Relaxed) != 0
    {
        return true;
    }
    REFLECT_IDS
        .get()
        .map_or(false, |r| !r.app_classloader.is_null() && !r.load_class_mid.is_null())
}

pub(super) unsafe fn get_app_classloader_local_ref(env: JniEnv) -> *mut std::ffi::c_void {
    let classloader = {
        let override_cl = CL_OVERRIDE.load(std::sync::atomic::Ordering::Acquire);
        if override_cl != 0 {
            override_cl as *mut std::ffi::c_void
        } else {
            match REFLECT_IDS.get() {
                Some(r) if !r.app_classloader.is_null() => r.app_classloader,
                _ => return std::ptr::null_mut(),
            }
        }
    };

    let new_local_ref: NewLocalRefFn = jni_fn!(env, NewLocalRefFn, JNI_NEW_LOCAL_REF);
    let local = new_local_ref(env, classloader);
    if jni_null_or_exc(env, local) {
        std::ptr::null_mut()
    } else {
        local
    }
}

/// 主动重新探测 app ClassLoader（spawn resume-first 场景）。
/// jsinit 时 app 可能尚未初始化，此函数在 Java.ready 安装 hook 后再次尝试，
/// 通过 ActivityThread.currentActivityThread().getApplication().getClassLoader() 探测。
/// 如果成功，更新缓存的 classloader 并返回 true。
/// 最多重试 8 次（每次 50ms sleep），总等待 ~400ms。
pub(super) unsafe fn reprobe_classloader() -> bool {
    if is_classloader_ready() {
        return true;
    }
    // Poll: app 初始化需要时间，重试几次
    for attempt in 0..8 {
        if attempt > 0 {
            crate::raw_thread::sleep_ms(50);
        }
        if reprobe_classloader_once() {
            crate::jsapi::console::output_verbose(&format!("[Java.ready] reprobe succeeded after {}ms", attempt * 50));
            return true;
        }
    }
    crate::jsapi::console::output_verbose("[Java.ready] reprobe_classloader: 400ms timeout, app not ready");
    false
}

pub(super) unsafe fn reprobe_classloader_once() -> bool {
    if is_classloader_ready() {
        return true;
    }
    let env = match super::jni_core::get_thread_env() {
        Ok(e) => e,
        Err(_) => return false,
    };
    reprobe_classloader_once_with_env(env)
}

pub(super) unsafe fn reprobe_classloader_once_with_env(env: JniEnv) -> bool {
    if is_classloader_ready() {
        return true;
    }

    let find_class: FindClassFn = jni_fn!(env, FindClassFn, JNI_FIND_CLASS);
    let get_static_mid: GetStaticMethodIdFn = jni_fn!(env, GetStaticMethodIdFn, JNI_GET_STATIC_METHOD_ID);
    let call_static_obj_a: CallStaticObjectMethodAFn =
        jni_fn!(env, CallStaticObjectMethodAFn, JNI_CALL_STATIC_OBJECT_METHOD_A);
    let call_obj_a: CallObjectMethodAFn = jni_fn!(env, CallObjectMethodAFn, JNI_CALL_OBJECT_METHOD_A);
    let get_mid: GetMethodIdFn = jni_fn!(env, GetMethodIdFn, JNI_GET_METHOD_ID);
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
    let null_args: *const std::ffi::c_void = std::ptr::null();

    let c_at = CString::new("android/app/ActivityThread").unwrap();
    let at_cls = find_class(env, c_at.as_ptr());
    if jni_null_or_exc(env, at_cls) {
        return false;
    }

    let c_cur = CString::new("currentActivityThread").unwrap();
    let c_cur_sig = CString::new("()Landroid/app/ActivityThread;").unwrap();
    let cur_mid = get_static_mid(env, at_cls, c_cur.as_ptr(), c_cur_sig.as_ptr());
    if jni_null_or_exc(env, cur_mid) {
        delete_local_ref(env, at_cls);
        return false;
    }

    let at_obj = call_static_obj_a(env, at_cls, cur_mid, null_args);
    if jni_null_or_exc(env, at_obj) {
        delete_local_ref(env, at_cls);
        return false;
    }

    let c_get_app = CString::new("getApplication").unwrap();
    let c_get_app_sig = CString::new("()Landroid/app/Application;").unwrap();
    let get_app_mid = get_mid(env, at_cls, c_get_app.as_ptr(), c_get_app_sig.as_ptr());
    if jni_null_or_exc(env, get_app_mid) {
        delete_local_ref(env, at_obj);
        delete_local_ref(env, at_cls);
        return false;
    }

    let app = call_obj_a(env, at_obj, get_app_mid, null_args);
    delete_local_ref(env, at_obj);
    delete_local_ref(env, at_cls);
    if jni_null_or_exc(env, app) {
        return false;
    }

    let c_ctx = CString::new("android/content/Context").unwrap();
    let ctx_cls = find_class(env, c_ctx.as_ptr());
    if jni_null_or_exc(env, ctx_cls) {
        delete_local_ref(env, app);
        return false;
    }

    let c_gcl = CString::new("getClassLoader").unwrap();
    let c_gcl_sig = CString::new("()Ljava/lang/ClassLoader;").unwrap();
    let gcl_mid = get_mid(env, ctx_cls, c_gcl.as_ptr(), c_gcl_sig.as_ptr());
    let gcl_failed = jni_null_or_exc(env, gcl_mid);
    delete_local_ref(env, ctx_cls);
    if gcl_failed {
        delete_local_ref(env, app);
        return false;
    }

    let cl = call_obj_a(env, app, gcl_mid, null_args);
    delete_local_ref(env, app);
    if jni_null_or_exc(env, cl) {
        return false;
    }

    let updated = update_app_classloader(env, cl);
    delete_local_ref(env, cl);

    if updated && is_classloader_ready() {
        crate::jsapi::console::output_verbose("[Java.ready] reprobe_classloader: app ClassLoader found");
        true
    } else {
        false
    }
}

/// Resolve a class name directly via `Class.getName()`.
///
/// This is intended for JNI refs we already obtained from the VM, such as the
/// result of `GetObjectClass()`, where ART-side ref decoding may be unavailable
/// even though the JNI reference itself is valid.
pub(crate) unsafe fn get_class_name_unchecked(env_ptr: u64, cls_ptr: u64) -> Option<String> {
    let env = env_ptr as JniEnv;
    let cls = cls_ptr as *mut std::ffi::c_void;
    if env.is_null() || cls.is_null() {
        return None;
    }

    let class_get_name_mid = if let Some(reflect) = REFLECT_IDS.get() {
        reflect.class_get_name_mid
    } else {
        let find_class: FindClassFn = jni_fn!(env, FindClassFn, JNI_FIND_CLASS);
        let get_mid: GetMethodIdFn = jni_fn!(env, GetMethodIdFn, JNI_GET_METHOD_ID);
        let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);

        let c_class = CString::new("java/lang/Class").unwrap();
        let class_cls = find_class(env, c_class.as_ptr());
        if jni_null_or_exc(env, class_cls) {
            return None;
        }

        let c_get_name = CString::new("getName").unwrap();
        let c_get_name_sig = CString::new("()Ljava/lang/String;").unwrap();
        let mid = get_mid(env, class_cls, c_get_name.as_ptr(), c_get_name_sig.as_ptr());
        let mid_failed = jni_null_or_exc(env, mid);
        delete_local_ref(env, class_cls);
        if mid_failed {
            return None;
        }
        mid
    };

    let call_obj: CallObjectMethodAFn = jni_fn!(env, CallObjectMethodAFn, JNI_CALL_OBJECT_METHOD_A);
    let get_str: GetStringUtfCharsFn = jni_fn!(env, GetStringUtfCharsFn, JNI_GET_STRING_UTF_CHARS);
    let rel_str: ReleaseStringUtfCharsFn = jni_fn!(env, ReleaseStringUtfCharsFn, JNI_RELEASE_STRING_UTF_CHARS);
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);

    let name_jstr = call_obj(env, cls, class_get_name_mid, std::ptr::null());
    if jni_null_or_exc(env, name_jstr) {
        return None;
    }

    let chars = get_str(env, name_jstr, std::ptr::null_mut());
    if chars.is_null() {
        delete_local_ref(env, name_jstr);
        jni_check_exc(env);
        return None;
    }

    let name = std::ffi::CStr::from_ptr(chars).to_string_lossy().to_string();
    rel_str(env, name_jstr, chars);
    delete_local_ref(env, name_jstr);

    Some(name)
}

/// Find a Java class by name.
/// `class_name` can use either `.` or `/` notation.
/// Returns a JNI local ref to the jclass, or null on failure.
///
/// 策略 (与 hook callback 上下文无关, 统一路径):
///   1. cache 命中 → 直接返回
///   2. ClassLoader 就绪 → loadClass (首选, 不触发 WalkStack)
///   3. fallback → JNI FindClass
///   4. 最后自动枚举 ClassLoader，逐个 findLoadedClass，命中后切换当前 loader
///
/// 注: 历史上 hook callback 里 block 过 FindClass (GetCallingClass→WalkStack 怕踩 hook 帧),
/// 但 walkstack guards (hook_replace GetOatQuickMethodHeader + 内联 OAT patch +
/// PrettyMethod + SIGSEGV handler) 已到位, WalkStack 碰 hook 帧现在是安全的,
/// 无需 block/绕行.
pub(crate) unsafe fn find_class_safe(env: JniEnv, class_name: &str) -> *mut std::ffi::c_void {
    // Clear any stale exception before calling FindClass.
    // ART's FindClass asserts no pending exception — calling it with one → SIGABRT.
    jni_check_exc(env);

    let cached = get_cached_class_local_ref(env, class_name);
    if !cached.is_null() {
        return cached;
    }

    let mut has_classloader = is_classloader_ready();
    if !has_classloader && reprobe_classloader_once_with_env(env) {
        has_classloader = true;
    }

    if has_classloader {
        let result = find_class_via_classloader(env, class_name);
        if !result.is_null() {
            cache_class_global_ref(env, class_name, result);
            return result;
        }
        // loadClass 失败 (ClassNotFoundException 等) → 继续 fallback 到 JNI FindClass
    }

    // JNI FindClass: ClassLoader 未就绪时, 或 loadClass 失败后兜底
    let find_class: FindClassFn = jni_fn!(env, FindClassFn, JNI_FIND_CLASS);
    let jni_name = class_name.replace('.', "/");
    let c_name = match CString::new(jni_name) {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(),
    };
    let cls = find_class(env, c_name.as_ptr());
    if !jni_null_or_exc(env, cls) {
        cache_class_global_ref(env, class_name, cls);
        return cls;
    }

    if should_try_enumerated_classloaders(class_name) {
        let result = find_class_via_enumerated_classloaders(env, class_name);
        if !result.is_null() {
            cache_class_global_ref(env, class_name, result);
            return result;
        }
    }

    std::ptr::null_mut()
}

fn should_try_enumerated_classloaders(class_name: &str) -> bool {
    if class_name.is_empty() || class_name.starts_with('[') {
        return false;
    }
    !matches!(class_name, "Z" | "B" | "C" | "S" | "I" | "J" | "F" | "D" | "V")
}

/// 通过 ClassLoader.loadClass 查找类（不触发 WalkStack）
unsafe fn find_class_via_classloader(env: JniEnv, class_name: &str) -> *mut std::ffi::c_void {
    let (app_cl, lc_mid) = {
        let ovr_cl = CL_OVERRIDE.load(std::sync::atomic::Ordering::Acquire);
        let ovr_mid = LC_MID_OVERRIDE.load(std::sync::atomic::Ordering::Acquire);
        if ovr_cl != 0 && ovr_mid != 0 {
            (ovr_cl as *mut std::ffi::c_void, ovr_mid as *mut std::ffi::c_void)
        } else {
            match REFLECT_IDS.get() {
                Some(r) if !r.app_classloader.is_null() && !r.load_class_mid.is_null() => {
                    (r.app_classloader, r.load_class_mid)
                }
                _ => return std::ptr::null_mut(),
            }
        }
    };

    find_class_via_single_loader(env, app_cl, class_name, lc_mid)
}

unsafe fn find_class_via_enumerated_classloaders(env: JniEnv, class_name: &str) -> *mut std::ffi::c_void {
    let loaders = enumerate_classloaders(env);
    for loader in loaders {
        let loader_ref = loader.ptr as *mut std::ffi::c_void;
        let result = find_loaded_class_via_loader(env, loader_ref, class_name);
        if result.is_null() {
            continue;
        }

        let _ = update_app_classloader(env, loader_ref);
        output_verbose(&format!(
            "[java.findClass] '{}' resolved via loaded ClassLoader {} ({})",
            class_name, loader.description, loader.source
        ));
        return result;
    }

    std::ptr::null_mut()
}

// ============================================================================
// JNI reflection — enumerate methods for auto-overload detection
// ============================================================================

#[derive(Clone)]
pub(crate) struct MethodInfo {
    pub(crate) name: String,
    pub(crate) sig: String,
    pub(crate) is_static: bool,
    pub(crate) modifiers: i32,
}

/// Convert Java type name (from Class.getName()) to JNI type descriptor.
pub(crate) fn java_type_to_jni(type_name: &str) -> String {
    match type_name {
        "void" => "V".to_string(),
        "boolean" => "Z".to_string(),
        "byte" => "B".to_string(),
        "char" => "C".to_string(),
        "short" => "S".to_string(),
        "int" => "I".to_string(),
        "long" => "J".to_string(),
        "float" => "F".to_string(),
        "double" => "D".to_string(),
        _ => {
            if type_name.starts_with('[') {
                // Array type: Class.getName() returns e.g. "[Ljava.lang.String;"
                type_name.replace('.', "/")
            } else {
                format!("L{};", type_name.replace('.', "/"))
            }
        }
    }
}

/// Enumerate methods of a Java class via JNI reflection.
/// Uses getDeclaredMethods() to include private/protected methods.
/// Falls back to getMethods() for inherited public methods if no match found.
pub(crate) unsafe fn enumerate_methods(env: JniEnv, class_name: &str) -> Result<Vec<MethodInfo>, String> {
    enumerate_methods_inner(env, class_name, false)
}

pub(crate) unsafe fn enumerate_methods_declared_only(env: JniEnv, class_name: &str) -> Result<Vec<MethodInfo>, String> {
    enumerate_methods_inner(env, class_name, true)
}

unsafe fn enumerate_methods_inner(
    env: JniEnv,
    class_name: &str,
    declared_only: bool,
) -> Result<Vec<MethodInfo>, String> {
    use std::ffi::CStr;
    use std::ptr;

    // Defensive: clear any stale JNI exception before we start.
    // Prevents SIGABRT if a prior operation left an uncleared exception.
    jni_check_exc(env);

    let find_class: FindClassFn = jni_fn!(env, FindClassFn, JNI_FIND_CLASS);
    let get_mid: GetMethodIdFn = jni_fn!(env, GetMethodIdFn, JNI_GET_METHOD_ID);
    let call_obj: CallObjectMethodAFn = jni_fn!(env, CallObjectMethodAFn, JNI_CALL_OBJECT_METHOD_A);
    let call_int: CallIntMethodAFn = jni_fn!(env, CallIntMethodAFn, JNI_CALL_INT_METHOD_A);
    let get_str: GetStringUtfCharsFn = jni_fn!(env, GetStringUtfCharsFn, JNI_GET_STRING_UTF_CHARS);
    let rel_str: ReleaseStringUtfCharsFn = jni_fn!(env, ReleaseStringUtfCharsFn, JNI_RELEASE_STRING_UTF_CHARS);
    let get_arr_len: GetArrayLengthFn = jni_fn!(env, GetArrayLengthFn, JNI_GET_ARRAY_LENGTH);
    let get_arr_elem: GetObjectArrayElementFn = jni_fn!(env, GetObjectArrayElementFn, JNI_GET_OBJECT_ARRAY_ELEMENT);
    let push_frame: PushLocalFrameFn = jni_fn!(env, PushLocalFrameFn, JNI_PUSH_LOCAL_FRAME);
    let pop_frame: PopLocalFrameFn = jni_fn!(env, PopLocalFrameFn, JNI_POP_LOCAL_FRAME);

    // Push local frame to auto-free local references
    if push_frame(env, 512) < 0 {
        return Err("PushLocalFrame failed".to_string());
    }

    // FindClass for target — use find_class_safe to support app classes via ClassLoader
    let cls = find_class_safe(env, class_name);
    if cls.is_null() {
        pop_frame(env, ptr::null_mut());
        return Err(format!("FindClass('{}') failed", class_name));
    }

    // Get reflection class/method IDs (system classes — FindClass is fine)
    let c_class_cls = CString::new("java/lang/Class").unwrap();
    let c_method_cls = CString::new("java/lang/reflect/Method").unwrap();
    let class_cls = find_class(env, c_class_cls.as_ptr());
    let method_cls = find_class(env, c_method_cls.as_ptr());
    if class_cls.is_null() || method_cls.is_null() {
        jni_check_exc(env);
        pop_frame(env, ptr::null_mut());
        return Err("Failed to find reflection classes".to_string());
    }

    let c_get_declared = CString::new("getDeclaredMethods").unwrap();
    let c_get_public = CString::new("getMethods").unwrap();
    let c_get_methods_sig = CString::new("()[Ljava/lang/reflect/Method;").unwrap();
    let c_get_name = CString::new("getName").unwrap();
    let c_str_ret = CString::new("()Ljava/lang/String;").unwrap();
    let c_get_params = CString::new("getParameterTypes").unwrap();
    let c_get_params_sig = CString::new("()[Ljava/lang/Class;").unwrap();
    let c_get_ret = CString::new("getReturnType").unwrap();
    let c_get_ret_sig = CString::new("()Ljava/lang/Class;").unwrap();
    let c_get_mods = CString::new("getModifiers").unwrap();
    let c_get_mods_sig = CString::new("()I").unwrap();

    let get_methods_mid = get_mid(env, class_cls, c_get_declared.as_ptr(), c_get_methods_sig.as_ptr());
    let get_public_methods_mid = get_mid(env, class_cls, c_get_public.as_ptr(), c_get_methods_sig.as_ptr());
    let get_name_mid = get_mid(env, method_cls, c_get_name.as_ptr(), c_str_ret.as_ptr());
    let get_params_mid = get_mid(env, method_cls, c_get_params.as_ptr(), c_get_params_sig.as_ptr());
    let get_ret_mid = get_mid(env, method_cls, c_get_ret.as_ptr(), c_get_ret_sig.as_ptr());
    let get_mods_mid = get_mid(env, method_cls, c_get_mods.as_ptr(), c_get_mods_sig.as_ptr());
    let class_get_name_mid = get_mid(env, class_cls, c_get_name.as_ptr(), c_str_ret.as_ptr());

    if jni_check_exc(env) {
        pop_frame(env, ptr::null_mut());
        return Err("Failed to get reflection method IDs".to_string());
    }

    // Call getDeclaredMethods()
    let methods_array = call_obj(env, cls, get_methods_mid, ptr::null());
    if jni_null_or_exc(env, methods_array) {
        pop_frame(env, ptr::null_mut());
        return Err("getDeclaredMethods() failed".to_string());
    }

    let len = get_arr_len(env, methods_array);
    if jni_negative_or_exc(env, len) {
        pop_frame(env, ptr::null_mut());
        return Err("getDeclaredMethods() length failed".to_string());
    }
    let mut results = Vec::with_capacity(len as usize);
    let mut seen = std::collections::HashSet::new();

    let mut collect_methods = |method_array: *mut std::ffi::c_void| {
        if method_array.is_null() {
            return;
        }

        let method_len = get_arr_len(env, method_array);
        if jni_negative_or_exc(env, method_len) {
            return;
        }
        for i in 0..method_len {
            let method_obj = get_arr_elem(env, method_array, i);
            if jni_null_or_exc(env, method_obj) {
                continue;
            }

            // getName()
            let name_jstr = call_obj(env, method_obj, get_name_mid, ptr::null());
            if jni_null_or_exc(env, name_jstr) {
                continue;
            }
            let name_chars = get_str(env, name_jstr, ptr::null_mut());
            if name_chars.is_null() {
                jni_check_exc(env);
                continue;
            }
            let name = CStr::from_ptr(name_chars).to_string_lossy().to_string();
            rel_str(env, name_jstr, name_chars);

            // getModifiers()
            let modifiers = call_int(env, method_obj, get_mods_mid, ptr::null());
            if jni_check_exc(env) {
                continue;
            }
            let is_static = (modifiers & 0x0008) != 0;

            // getParameterTypes() → build JNI signature
            let param_array = call_obj(env, method_obj, get_params_mid, ptr::null());
            let param_count = if jni_null_or_exc(env, param_array) {
                0
            } else {
                let count = get_arr_len(env, param_array);
                if jni_negative_or_exc(env, count) {
                    0
                } else {
                    count
                }
            };
            let mut sig = String::from("(");

            for j in 0..param_count {
                let pcls = get_arr_elem(env, param_array, j);
                if jni_null_or_exc(env, pcls) {
                    continue;
                }
                let pname_jstr = call_obj(env, pcls, class_get_name_mid, ptr::null());
                if !jni_null_or_exc(env, pname_jstr) {
                    let pc = get_str(env, pname_jstr, ptr::null_mut());
                    if pc.is_null() {
                        jni_check_exc(env);
                        continue;
                    }
                    let pname = CStr::from_ptr(pc).to_string_lossy().to_string();
                    rel_str(env, pname_jstr, pc);
                    sig.push_str(&java_type_to_jni(&pname));
                }
            }
            sig.push(')');

            // getReturnType()
            let ret_cls = call_obj(env, method_obj, get_ret_mid, ptr::null());
            if !jni_null_or_exc(env, ret_cls) {
                let rname_jstr = call_obj(env, ret_cls, class_get_name_mid, ptr::null());
                if !jni_null_or_exc(env, rname_jstr) {
                    let rc = get_str(env, rname_jstr, ptr::null_mut());
                    if rc.is_null() {
                        jni_check_exc(env);
                        continue;
                    }
                    let rname = CStr::from_ptr(rc).to_string_lossy().to_string();
                    rel_str(env, rname_jstr, rc);
                    sig.push_str(&java_type_to_jni(&rname));
                }
            }

            let key = format!("{}|{}|{}", name, sig, is_static as u8);
            if seen.insert(key) {
                results.push(MethodInfo {
                    name,
                    sig,
                    is_static,
                    modifiers,
                });
            }
        }
    };

    collect_methods(methods_array);

    // Add inherited public methods (getMethods) — may be slow on complex class hierarchies
    if !declared_only && !get_public_methods_mid.is_null() {
        let public_methods_array = call_obj(env, cls, get_public_methods_mid, ptr::null());
        if !jni_null_or_exc(env, public_methods_array) {
            collect_methods(public_methods_array);
        }
    }

    // Enumerate constructors via getDeclaredConstructors()
    // Constructors have name "<init>" and return type void.
    let c_constructor_cls = CString::new("java/lang/reflect/Constructor").unwrap();
    let constructor_cls = find_class(env, c_constructor_cls.as_ptr());
    if !jni_null_or_exc(env, constructor_cls) {
        let c_get_ctors = CString::new("getDeclaredConstructors").unwrap();
        let c_get_ctors_sig = CString::new("()[Ljava/lang/reflect/Constructor;").unwrap();
        let get_ctors_mid = get_mid(env, class_cls, c_get_ctors.as_ptr(), c_get_ctors_sig.as_ptr());

        if !jni_null_or_exc(env, get_ctors_mid) {
            let ctors_array = call_obj(env, cls, get_ctors_mid, ptr::null());
            if !jni_null_or_exc(env, ctors_array) {
                let ctor_len = get_arr_len(env, ctors_array);
                if jni_negative_or_exc(env, ctor_len) {
                    return Ok(results);
                }

                // Constructor.getParameterTypes() — same signature as Method.getParameterTypes()
                let ctor_get_params_mid =
                    get_mid(env, constructor_cls, c_get_params.as_ptr(), c_get_params_sig.as_ptr());
                let ctor_get_params_available = !jni_null_or_exc(env, ctor_get_params_mid);

                for i in 0..ctor_len {
                    let ctor_obj = get_arr_elem(env, ctors_array, i);
                    if jni_null_or_exc(env, ctor_obj) {
                        continue;
                    }

                    // Build signature: (params)V — constructors always return void
                    let param_array = if ctor_get_params_available {
                        call_obj(env, ctor_obj, ctor_get_params_mid, ptr::null())
                    } else {
                        ptr::null_mut()
                    };
                    let param_count = if jni_null_or_exc(env, param_array) {
                        0
                    } else {
                        let count = get_arr_len(env, param_array);
                        if jni_negative_or_exc(env, count) {
                            0
                        } else {
                            count
                        }
                    };
                    let mut sig = String::from("(");

                    for j in 0..param_count {
                        let pcls = get_arr_elem(env, param_array, j);
                        if jni_null_or_exc(env, pcls) {
                            continue;
                        }
                        let pname_jstr = call_obj(env, pcls, class_get_name_mid, ptr::null());
                        if !jni_null_or_exc(env, pname_jstr) {
                            let pc = get_str(env, pname_jstr, ptr::null_mut());
                            if pc.is_null() {
                                jni_check_exc(env);
                                continue;
                            }
                            let pname = CStr::from_ptr(pc).to_string_lossy().to_string();
                            rel_str(env, pname_jstr, pc);
                            sig.push_str(&java_type_to_jni(&pname));
                        }
                    }
                    sig.push_str(")V"); // constructors always return void

                    results.push(MethodInfo {
                        name: "<init>".to_string(),
                        sig,
                        is_static: false,
                        modifiers: 0,
                    });
                }
            }
        }
        jni_check_exc(env);
    } else {
        jni_check_exc(env);
    }

    pop_frame(env, ptr::null_mut());
    Ok(results)
}
