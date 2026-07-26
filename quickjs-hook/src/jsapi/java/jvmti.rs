//! ART JVMTI instance enumeration backend.
//!
//! This follows Frida's reliable `Java.choose()` path for modern ART:
//! load/register `libopenjdkjvmti.so`, obtain an ART-TI env, tag live
//! instances through JVMTI, and convert the returned jobjects to globals.

use std::ffi::{c_char, c_void};
use std::ptr;
use std::sync::atomic::{AtomicI64, Ordering};

use crate::jsapi::console::output_verbose;

use super::jni_core::{get_or_init_vm, jni_fn_ptr, jni_null_or_exc, JniEnv, NewGlobalRefFn, JNI_NEW_GLOBAL_REF};

const JNI_OK: i32 = 0;
const K_ART_TI_VERSION: i32 = 0x7001_0200;
const JVMTI_ITERATION_ABORT: i32 = 0;
const JVMTI_ITERATION_CONTINUE: i32 = 1;
const JVMTI_HEAP_OBJECT_EITHER: i32 = 3;
const JVMTI_ERROR_NONE: i32 = 0;

const JVMTI_DEALLOCATE: usize = 47;
const JVMTI_GET_CLASS_SIGNATURE: usize = 48;
const JVMTI_GET_LOADED_CLASSES: usize = 78;
const JVMTI_SET_TAG: usize = 107;
const JVMTI_ITERATE_OVER_INSTANCES_OF_CLASS: usize = 112;
const JVMTI_GET_OBJECTS_WITH_TAGS: usize = 114;
const JVMTI_ADD_CAPABILITIES: usize = 142;

static NEXT_TAG: AtomicI64 = AtomicI64::new(0x7275_7374_6672_0001);

type JavaVmGetEnvFn = unsafe extern "C" fn(*mut c_void, *mut *mut c_void, i32) -> i32;
type ArtPluginInitializeFn = unsafe extern "C" fn() -> bool;

type JvmtiDeallocateFn = unsafe extern "C" fn(*mut c_void, *mut u8) -> i32;
type JvmtiGetClassSignatureFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void, *mut *mut c_char, *mut *mut c_char) -> i32;
type JvmtiGetLoadedClassesFn = unsafe extern "C" fn(*mut c_void, *mut i32, *mut *mut *mut c_void) -> i32;
type JvmtiSetTagFn = unsafe extern "C" fn(*mut c_void, *mut c_void, i64) -> i32;
type JvmtiAddCapabilitiesFn = unsafe extern "C" fn(*mut c_void, *const u64) -> i32;
type JvmtiIterateOverInstancesOfClassFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void, i32, JvmtiHeapObjectCallback, *mut c_void) -> i32;
type JvmtiGetObjectsWithTagsFn =
    unsafe extern "C" fn(*mut c_void, i32, *const i64, *mut i32, *mut *mut *mut c_void, *mut *mut i64) -> i32;
type JvmtiHeapObjectCallback = unsafe extern "C" fn(i64, i64, *mut i64, *mut c_void) -> i32;

struct TagState {
    tag: i64,
    seen: usize,
    max_count: usize,
}

unsafe extern "C" fn tag_matching_object(
    _class_tag: i64,
    _size: i64,
    tag_ptr: *mut i64,
    user_data: *mut c_void,
) -> i32 {
    if user_data.is_null() {
        return JVMTI_ITERATION_ABORT;
    }
    let state = &mut *(user_data as *mut TagState);
    if state.max_count != 0 && state.seen >= state.max_count {
        return JVMTI_ITERATION_ABORT;
    }
    if !tag_ptr.is_null() {
        *tag_ptr = state.tag;
        state.seen = state.seen.saturating_add(1);
        if state.max_count != 0 && state.seen >= state.max_count {
            return JVMTI_ITERATION_ABORT;
        }
    }
    JVMTI_ITERATION_CONTINUE
}

pub(super) unsafe fn jvmti_enumerate_instances(
    env: JniEnv,
    target_cls: *mut c_void,
    max_count: usize,
) -> Result<Vec<*mut c_void>, String> {
    let hits = collect_tagged_instances(target_cls, max_count)?;

    let new_global_ref: NewGlobalRefFn = std::mem::transmute(jni_fn_ptr(env, JNI_NEW_GLOBAL_REF));
    let mut out = Vec::with_capacity(hits.objects.len());
    for obj in &hits.objects {
        let g = new_global_ref(env, *obj);
        if jni_null_or_exc(env, g) {
            continue;
        }
        out.push(g);
    }

    clear_tags_and_deallocate(hits);
    Ok(out)
}

pub(super) unsafe fn jvmti_enumerate_instance_mirrors(
    target_cls: *mut c_void,
    max_count: usize,
) -> Result<Vec<u64>, String> {
    let hits = collect_tagged_instances(target_cls, max_count)?;

    let mut out = Vec::with_capacity(hits.objects.len());
    for obj in &hits.objects {
        if let Some(mirror) = decode_jvmti_object_ref(*obj) {
            out.push(mirror);
        }
    }

    clear_tags_and_deallocate(hits);
    Ok(out)
}

pub(super) unsafe fn jvmti_enumerate_instance_mirrors_by_signature(
    class_signature: &str,
    max_count: usize,
) -> Result<Vec<u64>, String> {
    let jvmti = get_or_init_jvmti_env()?;
    let Some(target) = find_loaded_class_by_signature(jvmti, class_signature)? else {
        return Err(format!("loaded class not found: {}", class_signature));
    };

    output_verbose(&format!(
        "[jvmti] loaded class signature matched {} -> {:?}",
        class_signature, target.klass
    ));

    let hits = collect_tagged_instances(target.klass, max_count);
    deallocate_if_nonnull(jvmti, target.classes_raw as *mut u8);
    let hits = hits?;

    let mut out = Vec::with_capacity(hits.objects.len());
    for obj in &hits.objects {
        if let Some(mirror) = decode_jvmti_object_ref(*obj) {
            out.push(mirror);
        }
    }

    clear_tags_and_deallocate(hits);
    Ok(out)
}

/// Every loaded class, as Java-style names such as `java.lang.String`.
///
/// JVMTI reports JNI signatures (`Ljava/lang/String;`); array and primitive
/// entries are reported verbatim by upstream too, so only object signatures are
/// rewritten here.
pub(super) unsafe fn jvmti_loaded_class_names() -> Result<Vec<String>, String> {
    let jvmti = get_or_init_jvmti_env()?;
    let get_loaded_classes: JvmtiGetLoadedClassesFn =
        std::mem::transmute(jvmti_fn_ptr(jvmti, JVMTI_GET_LOADED_CLASSES));
    let get_class_signature: JvmtiGetClassSignatureFn =
        std::mem::transmute(jvmti_fn_ptr(jvmti, JVMTI_GET_CLASS_SIGNATURE));

    let mut count: i32 = 0;
    let mut classes: *mut *mut c_void = ptr::null_mut();
    let ret = get_loaded_classes(jvmti, &mut count, &mut classes);
    if ret != JVMTI_ERROR_NONE {
        return Err(format!("GetLoadedClasses failed: {}", ret));
    }

    let mut names = Vec::with_capacity(count.max(0) as usize);
    for index in 0..count.max(0) as usize {
        let klass = *classes.add(index);
        if klass.is_null() {
            continue;
        }
        let mut signature: *mut c_char = ptr::null_mut();
        let mut generic: *mut c_char = ptr::null_mut();
        if get_class_signature(jvmti, klass, &mut signature, &mut generic) == JVMTI_ERROR_NONE && !signature.is_null() {
            let raw = std::ffi::CStr::from_ptr(signature).to_string_lossy();
            names.push(class_name_from_signature(raw.as_ref()));
        }
        deallocate_if_nonnull(jvmti, signature as *mut u8);
        deallocate_if_nonnull(jvmti, generic as *mut u8);
    }
    deallocate_if_nonnull(jvmti, classes as *mut u8);
    Ok(names)
}

/// `Ljava/lang/String;` becomes `java.lang.String`; anything else is kept.
fn class_name_from_signature(signature: &str) -> String {
    match signature.strip_prefix('L').and_then(|rest| rest.strip_suffix(';')) {
        Some(name) => name.replace('/', "."),
        None => signature.to_string(),
    }
}

pub(super) unsafe fn jvmti_class_mirror_by_signature(class_signature: &str) -> Result<Option<u64>, String> {
    let jvmti = get_or_init_jvmti_env()?;
    let Some(target) = find_loaded_class_by_signature(jvmti, class_signature)? else {
        return Ok(None);
    };

    output_verbose(&format!(
        "[jvmti] loaded class signature matched {} -> {:?}",
        class_signature, target.klass
    ));

    let mirror = decode_jvmti_object_ref(target.klass);
    deallocate_if_nonnull(jvmti, target.classes_raw as *mut u8);
    Ok(mirror)
}

struct LoadedClassMatch {
    klass: *mut c_void,
    classes_raw: *mut *mut c_void,
}

unsafe fn find_loaded_class_by_signature(
    jvmti: *mut c_void,
    expected_signature: &str,
) -> Result<Option<LoadedClassMatch>, String> {
    let get_loaded_classes: JvmtiGetLoadedClassesFn =
        std::mem::transmute(jvmti_fn_ptr(jvmti, JVMTI_GET_LOADED_CLASSES));
    let get_class_signature: JvmtiGetClassSignatureFn =
        std::mem::transmute(jvmti_fn_ptr(jvmti, JVMTI_GET_CLASS_SIGNATURE));

    let mut count: i32 = 0;
    let mut classes: *mut *mut c_void = ptr::null_mut();
    let ret = get_loaded_classes(jvmti, &mut count, &mut classes);
    if ret != JVMTI_ERROR_NONE {
        return Err(format!("GetLoadedClasses failed: {}", ret));
    }

    let mut matched = None;
    let n = count.max(0) as usize;
    for i in 0..n {
        let klass = *classes.add(i);
        if klass.is_null() {
            continue;
        }

        let mut signature: *mut c_char = ptr::null_mut();
        let mut generic: *mut c_char = ptr::null_mut();
        let ret = get_class_signature(jvmti, klass, &mut signature, &mut generic);
        if ret == JVMTI_ERROR_NONE && !signature.is_null() {
            let sig = std::ffi::CStr::from_ptr(signature).to_string_lossy();
            if sig.as_ref() == expected_signature {
                matched = Some(klass);
            }
        }
        deallocate_if_nonnull(jvmti, signature as *mut u8);
        deallocate_if_nonnull(jvmti, generic as *mut u8);

        if matched.is_some() {
            break;
        }
    }

    if let Some(klass) = matched {
        Ok(Some(LoadedClassMatch {
            klass,
            classes_raw: classes,
        }))
    } else {
        deallocate_if_nonnull(jvmti, classes as *mut u8);
        Ok(None)
    }
}

struct TaggedInstances {
    jvmti: *mut c_void,
    objects_raw: *mut *mut c_void,
    tags_raw: *mut i64,
    objects: Vec<*mut c_void>,
}

unsafe fn collect_tagged_instances(target_cls: *mut c_void, max_count: usize) -> Result<TaggedInstances, String> {
    let jvmti = get_or_init_jvmti_env()?;
    add_tagging_capability(jvmti)?;

    let tag = NEXT_TAG.fetch_add(1, Ordering::Relaxed);
    if tag == 0 {
        return Err("internal tag counter wrapped to zero".to_string());
    }

    let iterate: JvmtiIterateOverInstancesOfClassFn =
        std::mem::transmute(jvmti_fn_ptr(jvmti, JVMTI_ITERATE_OVER_INSTANCES_OF_CLASS));
    let mut tag_state = TagState {
        tag,
        seen: 0,
        max_count,
    };
    let ret = iterate(
        jvmti,
        target_cls,
        JVMTI_HEAP_OBJECT_EITHER,
        tag_matching_object,
        &mut tag_state as *mut TagState as *mut c_void,
    );
    if ret != JVMTI_ERROR_NONE {
        return Err(format!("IterateOverInstancesOfClass failed: {}", ret));
    }

    let get_objects: JvmtiGetObjectsWithTagsFn = std::mem::transmute(jvmti_fn_ptr(jvmti, JVMTI_GET_OBJECTS_WITH_TAGS));
    let mut count: i32 = 0;
    let mut objects: *mut *mut c_void = ptr::null_mut();
    let mut tags: *mut i64 = ptr::null_mut();
    let ret = get_objects(jvmti, 1, &tag, &mut count, &mut objects, &mut tags);
    if ret != JVMTI_ERROR_NONE {
        return Err(format!("GetObjectsWithTags failed: {}", ret));
    }

    let cap = if max_count == 0 { usize::MAX } else { max_count };
    let n = (count.max(0) as usize).min(cap);
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let obj = *objects.add(i);
        if obj.is_null() {
            continue;
        }
        out.push(obj);
    }

    Ok(TaggedInstances {
        jvmti,
        objects_raw: objects,
        tags_raw: tags,
        objects: out,
    })
}

unsafe fn clear_tags_and_deallocate(hits: TaggedInstances) {
    let set_tag: JvmtiSetTagFn = std::mem::transmute(jvmti_fn_ptr(hits.jvmti, JVMTI_SET_TAG));
    for obj in &hits.objects {
        if !obj.is_null() {
            let _ = set_tag(hits.jvmti, *obj, 0);
        }
    }

    deallocate_if_nonnull(hits.jvmti, hits.objects_raw as *mut u8);
    deallocate_if_nonnull(hits.jvmti, hits.tags_raw as *mut u8);
}

unsafe fn decode_jvmti_object_ref(obj: *mut c_void) -> Option<u64> {
    const KIND_MASK: u64 = 0x3;
    const KIND_LOCAL: u64 = 0x1;

    let raw = obj as u64;
    if raw == 0 {
        return None;
    }

    let entry = match raw & KIND_MASK {
        KIND_LOCAL => raw & !KIND_MASK,
        0 => raw,
        _ => return None,
    };
    if entry < 0x1000 || !crate::jsapi::util::is_addr_accessible(entry, 4) {
        return None;
    }

    let compressed = std::ptr::read_volatile(entry as *const u32) as u64;
    if compressed >= 0x1000 && crate::jsapi::util::is_addr_accessible(compressed, 4) {
        return Some(compressed);
    }

    let raw_root = std::ptr::read_volatile(entry as *const u64) & super::PAC_STRIP_MASK;
    if raw_root >= 0x1000 && crate::jsapi::util::is_addr_accessible(raw_root, 4) {
        return Some(raw_root);
    }

    None
}

unsafe fn get_or_init_jvmti_env() -> Result<*mut c_void, String> {
    if crate::is_raw_clone_js_thread() {
        return Err("JVMTI is disabled on raw clone JS threads".to_string());
    }

    let vm = get_or_init_vm()?;
    if is_openjdk_jvmti_mapped() {
        if let Some(env) = try_get_jvmti_env(vm) {
            return Ok(env);
        }
    }

    if !allow_jvmti_late_load() {
        return Err(
            "JVMTI late-load disabled by default; use heap-scan/VMDebug or set RF_JAVA_CHOOSE_JVMTI_LATE_LOAD=1"
                .to_string(),
        );
    }

    if let Some(env) = try_get_jvmti_env(vm) {
        return Ok(env);
    }

    let handle = load_openjdk_jvmti()?;
    let init = resolve_art_plugin_initialize(handle)?;
    if !init() {
        return Err("ArtPlugin_Initialize returned false".to_string());
    }
    output_verbose("[jvmti] ArtPlugin_Initialize ok");

    try_get_jvmti_env(vm).ok_or_else(|| "JavaVM.GetEnv(kArtTiVersion) failed after plugin init".to_string())
}

fn is_openjdk_jvmti_mapped() -> bool {
    std::fs::read_to_string("/proc/self/maps")
        .map(|maps| maps.contains("libopenjdkjvmti.so"))
        .unwrap_or(false)
}

fn allow_jvmti_late_load() -> bool {
    std::env::var("RF_JAVA_CHOOSE_JVMTI_LATE_LOAD")
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

unsafe fn try_get_jvmti_env(vm: *mut c_void) -> Option<*mut c_void> {
    let vm_table = *(vm as *const *const *const c_void);
    let get_env: JavaVmGetEnvFn = std::mem::transmute(*vm_table.add(6));
    let mut env: *mut c_void = ptr::null_mut();
    let ret = get_env(vm, &mut env, K_ART_TI_VERSION);
    (ret == JNI_OK && !env.is_null()).then_some(env)
}

unsafe fn load_openjdk_jvmti() -> Result<*mut c_void, String> {
    let paths = [
        "/apex/com.android.art/lib64/libopenjdkjvmti.so",
        "/apex/com.android.art/lib/libopenjdkjvmti.so",
        "libopenjdkjvmti.so",
    ];
    for path in paths {
        let handle =
            crate::jsapi::module::module_dlopen_load_from_libart_namespace(path, libc::RTLD_NOW | libc::RTLD_GLOBAL);
        if !handle.is_null() {
            output_verbose(&format!("[jvmti] loaded {}", path));
            return Ok(handle);
        }
    }
    Err("dlopen(libopenjdkjvmti.so) failed".to_string())
}

unsafe fn resolve_art_plugin_initialize(handle: *mut c_void) -> Result<ArtPluginInitializeFn, String> {
    let sym_name = std::ffi::CString::new("ArtPlugin_Initialize").unwrap();
    let sym = libc::dlsym(handle, sym_name.as_ptr());
    if sym.is_null() {
        return Err("dlsym(ArtPlugin_Initialize) failed".to_string());
    }
    Ok(std::mem::transmute(sym))
}

unsafe fn add_tagging_capability(jvmti: *mut c_void) -> Result<(), String> {
    let add_capabilities: JvmtiAddCapabilitiesFn = std::mem::transmute(jvmti_fn_ptr(jvmti, JVMTI_ADD_CAPABILITIES));
    let capabilities: u64 = 1;
    let ret = add_capabilities(jvmti, &capabilities);
    if ret == JVMTI_ERROR_NONE {
        Ok(())
    } else {
        Err(format!("AddCapabilities(can_tag_objects) failed: {}", ret))
    }
}

unsafe fn deallocate_if_nonnull(jvmti: *mut c_void, ptr: *mut u8) {
    if ptr.is_null() {
        return;
    }
    let deallocate: JvmtiDeallocateFn = std::mem::transmute(jvmti_fn_ptr(jvmti, JVMTI_DEALLOCATE));
    let _ = deallocate(jvmti, ptr);
}

unsafe fn jvmti_fn_ptr(jvmti: *mut c_void, one_based_index: usize) -> *const c_void {
    let table = *(jvmti as *const *const *const c_void);
    *table.add(one_based_index - 1)
}
