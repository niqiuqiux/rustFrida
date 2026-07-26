// ============================================================================
// Field cache — pre-enumerated at hook time (safe thread), used from callbacks
// ============================================================================

pub(super) struct CachedFieldInfo {
    pub(super) jni_sig: String,
    pub(super) field_id: *mut std::ffi::c_void, // jfieldID — stable across threads
    pub(super) field_offset: u32,
    pub(super) is_static: bool,
}

unsafe impl Send for CachedFieldInfo {}
unsafe impl Sync for CachedFieldInfo {}

/// Cached field info per class: className → (fieldName → CachedFieldInfo)
pub(super) static FIELD_CACHE: Mutex<Option<HashMap<String, HashMap<String, CachedFieldInfo>>>> =
    Mutex::new(None);

/// Enumerate and cache all fields (instance + static) for a class (including inherited).
/// Must be called from a safe thread (not a hook callback).
pub(super) unsafe fn cache_fields_for_class(env: JniEnv, class_name: &str) {
    // Initialize cache if needed
    {
        let mut guard = FIELD_CACHE.lock().unwrap_or_else(|e| e.into_inner());
        if guard.is_none() {
            *guard = Some(HashMap::new());
        }
        // Skip if already cached
        if guard.as_ref().unwrap().contains_key(class_name) {
            return;
        }
    }

    if crate::is_raw_clone_js_thread() {
        let fields = match enumerate_fields_by_dex(env, class_name) {
            Some(fields) => fields,
            None => {
                output_verbose(&format!(
                    "[field cache] raw clone dex self-parse failed: {}",
                    class_name
                ));
                return;
            }
        };

        let mut field_map = HashMap::new();
        for field in fields {
            field_map.entry(field.name).or_insert_with(|| CachedFieldInfo {
                jni_sig: field.jni_sig,
                field_id: field.field_id,
                field_offset: field.field_offset,
                is_static: field.is_static,
            });
        }

        let mut guard = FIELD_CACHE.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(cache) = guard.as_mut() {
            cache.insert(class_name.to_string(), field_map);
        }
        return;
    }

    // Enumerate fields using JNI reflection (safe from init thread)
    let fields = match enumerate_class_fields(env, class_name) {
        Ok(f) => f,
        Err(_e) => return,
    };

    // Resolve field IDs and store in cache
    let get_field_id: GetFieldIdFn = jni_fn!(env, GetFieldIdFn, JNI_GET_FIELD_ID);
    let get_static_field_id: GetStaticFieldIdFn =
        jni_fn!(env, GetStaticFieldIdFn, JNI_GET_STATIC_FIELD_ID);
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);

    let cls = find_class_safe(env, class_name);
    if cls.is_null() {
        return;
    }

    let mut field_map = HashMap::new();
    for (name, type_name, is_static) in &fields {
        let jni_sig = java_type_to_jni(type_name);
        let c_name = match CString::new(name.as_str()) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let c_sig = match CString::new(jni_sig.as_str()) {
            Ok(c) => c,
            Err(_) => continue,
        };
        // IMPORTANT: Always clear pending exceptions before calling Get[Static]FieldID.
        // GetFieldID will abort (SIGABRT) if there's already a pending exception.
        jni_check_exc(env);
        let fid = if *is_static {
            get_static_field_id(env, cls, c_name.as_ptr(), c_sig.as_ptr())
        } else {
            get_field_id(env, cls, c_name.as_ptr(), c_sig.as_ptr())
        };
        if fid.is_null() {
            jni_check_exc(env); // Clear exception from failed GetFieldID
            continue;
        }
        field_map.insert(
            name.clone(),
            CachedFieldInfo {
                jni_sig,
                field_id: fid,
                field_offset: art_field_offset(fid).unwrap_or(0),
                is_static: *is_static,
            },
        );
    }

    delete_local_ref(env, cls);

    let mut guard = FIELD_CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(cache) = guard.as_mut() {
        cache.insert(class_name.to_string(), field_map);
    }
}

/// 从 class mirror 指针建字段缓存，给拿不到 jclass 的 raw clone 线程用。目前那条路径
/// 还是走 cache_fields_for_class()，所以这里暂时没有调用方。
#[allow(dead_code)]
pub(super) unsafe fn cache_fields_for_class_mirror(_env: JniEnv, class_name: &str, class_mirror: u64) {
    super::safe_mem::refresh_mem_regions();
    if class_mirror < 0x1000 || !super::safe_mem::is_readable(class_mirror, 4) {
        output_verbose(&format!(
            "[field cache] raw clone mirror unreadable {} -> {:#x}",
            class_name, class_mirror
        ));
        return;
    }

    output_verbose(&format!(
        "[field cache] raw clone mirror cache start {} -> {:#x}",
        class_name, class_mirror
    ));

    {
        let mut guard = FIELD_CACHE.lock().unwrap_or_else(|e| e.into_inner());
        if guard.is_none() {
            *guard = Some(HashMap::new());
        }
        if guard.as_ref().unwrap().contains_key(class_name) {
            return;
        }
    }

    let fields = match enumerate_fields_by_dex_from_mirror(class_mirror, class_name) {
        Some(fields) => fields,
        None => {
            output_verbose(&format!(
                "[field cache] raw clone dex self-parse failed from mirror: {} -> {:#x}",
                class_name, class_mirror
            ));
            return;
        }
    };

    output_verbose(&format!(
        "[field cache] raw clone mirror cache parsed {} fields for {}",
        fields.len(),
        class_name
    ));

    let mut field_map = HashMap::new();
    for field in fields {
        field_map.entry(field.name).or_insert_with(|| CachedFieldInfo {
            jni_sig: field.jni_sig,
            field_id: field.field_id,
            field_offset: field.field_offset,
            is_static: field.is_static,
        });
    }

    let mut guard = FIELD_CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(cache) = guard.as_mut() {
        cache.insert(class_name.to_string(), field_map);
    }
}

pub(super) unsafe fn art_field_offset(field_id: *mut std::ffi::c_void) -> Option<u32> {
    let spec = get_art_field_spec()?;
    let art_field = field_id as u64;
    if art_field < 0x1000 || !super::safe_mem::is_readable(art_field + spec.offset_offset as u64, 4) {
        return None;
    }
    Some(super::safe_mem::safe_read_u32(art_field + spec.offset_offset as u64))
}

/// Enumerate fields of a class and all its superclasses via JNI reflection.
/// Returns Vec<(fieldName, typeName, is_static)>.
unsafe fn enumerate_class_fields(
    env: JniEnv,
    class_name: &str,
) -> Result<Vec<(String, String, bool)>, String> {
    use std::ffi::CStr;

    let reflect = REFLECT_IDS.get().ok_or("reflection IDs not cached")?;

    let find_class: FindClassFn = jni_fn!(env, FindClassFn, JNI_FIND_CLASS);
    let get_mid: GetMethodIdFn = jni_fn!(env, GetMethodIdFn, JNI_GET_METHOD_ID);
    let call_obj: CallObjectMethodAFn = jni_fn!(env, CallObjectMethodAFn, JNI_CALL_OBJECT_METHOD_A);
    let call_int: CallIntMethodAFn = jni_fn!(env, CallIntMethodAFn, JNI_CALL_INT_METHOD_A);
    let get_str: GetStringUtfCharsFn = jni_fn!(env, GetStringUtfCharsFn, JNI_GET_STRING_UTF_CHARS);
    let rel_str: ReleaseStringUtfCharsFn =
        jni_fn!(env, ReleaseStringUtfCharsFn, JNI_RELEASE_STRING_UTF_CHARS);
    let get_arr_len: GetArrayLengthFn = jni_fn!(env, GetArrayLengthFn, JNI_GET_ARRAY_LENGTH);
    let get_arr_elem: GetObjectArrayElementFn =
        jni_fn!(env, GetObjectArrayElementFn, JNI_GET_OBJECT_ARRAY_ELEMENT);
    let push_frame: PushLocalFrameFn = jni_fn!(env, PushLocalFrameFn, JNI_PUSH_LOCAL_FRAME);
    let pop_frame: PopLocalFrameFn = jni_fn!(env, PopLocalFrameFn, JNI_POP_LOCAL_FRAME);

    if push_frame(env, 512) < 0 {
        return Err("PushLocalFrame failed".to_string());
    }

    let cls = find_class_safe(env, class_name);
    if cls.is_null() {
        pop_frame(env, std::ptr::null_mut());
        return Err("FindClass failed".to_string());
    }

    // Get reflection method IDs (system classes — FindClass is fine)
    let c_class_cls = CString::new("java/lang/Class").unwrap();
    let c_field_cls = CString::new("java/lang/reflect/Field").unwrap();
    let class_cls = find_class(env, c_class_cls.as_ptr());
    let field_cls = find_class(env, c_field_cls.as_ptr());

    let c_get_fields = CString::new("getFields").unwrap();
    let c_get_fields_sig = CString::new("()[Ljava/lang/reflect/Field;").unwrap();
    let c_get_declared_fields = CString::new("getDeclaredFields").unwrap();
    let c_get_name = CString::new("getName").unwrap();
    let c_str_sig = CString::new("()Ljava/lang/String;").unwrap();
    let c_get_type = CString::new("getType").unwrap();
    let c_get_type_sig = CString::new("()Ljava/lang/Class;").unwrap();
    let c_get_mods = CString::new("getModifiers").unwrap();
    let c_get_mods_sig = CString::new("()I").unwrap();

    let get_fields_mid = get_mid(
        env,
        class_cls,
        c_get_fields.as_ptr(),
        c_get_fields_sig.as_ptr(),
    );
    let get_declared_fields_mid = get_mid(
        env,
        class_cls,
        c_get_declared_fields.as_ptr(),
        c_get_fields_sig.as_ptr(),
    );
    let field_get_name_mid = get_mid(env, field_cls, c_get_name.as_ptr(), c_str_sig.as_ptr());
    let field_get_type_mid = get_mid(env, field_cls, c_get_type.as_ptr(), c_get_type_sig.as_ptr());
    let field_get_mods_mid = get_mid(env, field_cls, c_get_mods.as_ptr(), c_get_mods_sig.as_ptr());

    jni_check_exc(env);

    let mut results = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // Helper: extract fields from a Field[] array
    let mut extract_fields = |arr: *mut std::ffi::c_void| {
        if arr.is_null() {
            return;
        }
        let len = get_arr_len(env, arr);
        for i in 0..len {
            let field = get_arr_elem(env, arr, i);
            if field.is_null() {
                continue;
            }

            // getName()
            let name_jstr = call_obj(env, field, field_get_name_mid, std::ptr::null());
            if name_jstr.is_null() {
                continue;
            }
            let name_chars = get_str(env, name_jstr, std::ptr::null_mut());
            let name = CStr::from_ptr(name_chars).to_string_lossy().to_string();
            rel_str(env, name_jstr, name_chars);

            if seen.contains(&name) {
                continue;
            }

            // getModifiers() — check for static (0x0008)
            let modifiers = if !field_get_mods_mid.is_null() {
                call_int(env, field, field_get_mods_mid, std::ptr::null())
            } else {
                0
            };
            let is_static = (modifiers & 0x0008) != 0;

            // getType().getName()
            let type_cls_obj = call_obj(env, field, field_get_type_mid, std::ptr::null());
            if type_cls_obj.is_null() {
                continue;
            }
            let type_name_jstr = call_obj(
                env,
                type_cls_obj,
                reflect.class_get_name_mid,
                std::ptr::null(),
            );
            if type_name_jstr.is_null() {
                continue;
            }
            let tc = get_str(env, type_name_jstr, std::ptr::null_mut());
            let type_name = CStr::from_ptr(tc).to_string_lossy().to_string();
            rel_str(env, type_name_jstr, tc);

            seen.insert(name.clone());
            results.push((name, type_name, is_static));
        }
    };

    // Walk the entire class hierarchy: getDeclaredFields() on each class
    // to capture protected/private inherited fields (e.g. mBase in ContextWrapper).
    {
        let c_get_superclass = CString::new("getSuperclass").unwrap();
        let c_get_superclass_sig = CString::new("()Ljava/lang/Class;").unwrap();
        let get_superclass_mid = get_mid(
            env,
            class_cls,
            c_get_superclass.as_ptr(),
            c_get_superclass_sig.as_ptr(),
        );

        let mut current_cls = cls;
        loop {
            if current_cls.is_null() {
                break;
            }

            // getDeclaredFields() on current class
            if !get_declared_fields_mid.is_null() {
                let arr = call_obj(env, current_cls, get_declared_fields_mid, std::ptr::null());
                if jni_check_exc(env) { /* skip */
                } else {
                    extract_fields(arr);
                }
            }

            // Walk to superclass
            if get_superclass_mid.is_null() {
                break;
            }
            let super_cls = call_obj(env, current_cls, get_superclass_mid, std::ptr::null());
            if jni_null_or_exc(env, super_cls) {
                break;
            }
            current_cls = super_cls;
        }
    }

    // getFields() — all public inherited fields (catches interface constants, etc.)
    if !get_fields_mid.is_null() {
        let arr = call_obj(env, cls, get_fields_mid, std::ptr::null());
        if jni_check_exc(env) { /* skip */
        } else {
            extract_fields(arr);
        }
    }

    pop_frame(env, std::ptr::null_mut());
    Ok(results)
}
