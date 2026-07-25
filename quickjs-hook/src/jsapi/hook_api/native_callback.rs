#[cfg(feature = "frida-ffi")]
use super::native_ffi;
use crate::ffi;
use crate::jsapi::callback_util::{acquire_js_engine_for_callback, dup_callback_to_bytes, handle_js_exception};
#[cfg(not(feature = "frida-ffi"))]
use crate::jsapi::callback_util::{
    js_i64_to_js_number_or_bigint, js_u64_to_js_number_or_bigint, js_value_to_u64_or_zero,
};
use crate::jsapi::ptr::{create_native_pointer, native_pointer_prototype};
use crate::value::JSValue;
use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Condvar, Mutex};

const NATIVE_CALLBACK_CLASS_NAME: &[u8] = b"NativeCallback\0";
#[cfg(not(feature = "frida-ffi"))]
const MAX_CALLBACK_ARGUMENTS: usize = 256;

static NATIVE_CALLBACK_CLASS_ID: AtomicU32 = AtomicU32::new(0);
static NATIVE_CALLBACKS: Mutex<Option<HashMap<u64, Box<NativeCallbackData>>>> = Mutex::new(None);
static RETIRED_NATIVE_CALLBACKS: Mutex<Vec<Box<NativeCallbackData>>> = Mutex::new(Vec::new());
static NEXT_NATIVE_CALLBACK_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
static IN_FLIGHT_NATIVE_CALLBACKS: Mutex<usize> = Mutex::new(0);
static IN_FLIGHT_NATIVE_CALLBACKS_CV: Condvar = Condvar::new();

#[cfg(not(feature = "frida-ffi"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ScalarKind {
    Void,
    Signed { size: u8 },
    Unsigned { size: u8 },
    Pointer,
    Float,
    Double,
}

#[cfg(not(feature = "frida-ffi"))]
impl ScalarKind {
    fn is_floating(self) -> bool {
        matches!(self, Self::Float | Self::Double)
    }
}

#[cfg(not(feature = "frida-ffi"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ArgumentLocation {
    Gpr(u8),
    Fpr(u8),
    Stack(u16),
}

#[cfg(not(feature = "frida-ffi"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ArgumentPlan {
    kind: ScalarKind,
    location: ArgumentLocation,
}

#[cfg(not(feature = "frida-ffi"))]
#[repr(C)]
struct NativeCallbackFrame {
    gpr: [u64; 8],
    fpr: [u64; 8],
    caller_sp: u64,
    return_address: u64,
    result_gpr: u64,
    result_fpr: u64,
}

struct NativeCallbackData {
    id: u64,
    ctx: usize,
    callback_bytes: [u8; 16],
    callback_alive: bool,
    #[cfg(not(feature = "frida-ffi"))]
    return_kind: ScalarKind,
    #[cfg(not(feature = "frida-ffi"))]
    arguments: Vec<ArgumentPlan>,
    #[cfg(feature = "frida-ffi")]
    signature: native_ffi::NativeFfiSignature,
    #[cfg(feature = "frida-ffi")]
    _closure: usize,
    thunk: usize,
    #[cfg(not(feature = "frida-ffi"))]
    mapping_size: usize,
    active: AtomicBool,
}

unsafe impl Send for NativeCallbackData {}
unsafe impl Sync for NativeCallbackData {}

struct NativeCallbackHandle {
    id: u64,
}

struct InFlightNativeCallbackGuard;

impl InFlightNativeCallbackGuard {
    fn enter() -> Self {
        let mut count = IN_FLIGHT_NATIVE_CALLBACKS
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        *count += 1;
        Self
    }
}

impl Drop for InFlightNativeCallbackGuard {
    fn drop(&mut self) {
        let mut count = IN_FLIGHT_NATIVE_CALLBACKS
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        *count = count.saturating_sub(1);
        if *count == 0 {
            IN_FLIGHT_NATIVE_CALLBACKS_CV.notify_all();
        }
    }
}

#[cfg(not(feature = "frida-ffi"))]
extern "C" {
    fn native_callback_entry();
}

#[cfg(target_os = "android")]
extern "C" {
    #[link_name = "__errno"]
    fn platform_errno_location() -> *mut i32;
}

#[cfg(all(not(target_os = "android"), target_os = "linux"))]
extern "C" {
    #[link_name = "__errno_location"]
    fn platform_errno_location() -> *mut i32;
}

unsafe fn get_system_error() -> i32 {
    #[cfg(any(target_os = "android", target_os = "linux"))]
    {
        *platform_errno_location()
    }
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    {
        0
    }
}

unsafe fn set_system_error(value: i32) {
    #[cfg(any(target_os = "android", target_os = "linux"))]
    {
        *platform_errno_location() = value;
    }
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    let _ = value;
}

fn next_callback_id() -> u64 {
    loop {
        let id = NEXT_NATIVE_CALLBACK_ID.fetch_add(1, Ordering::Relaxed);
        if id != 0 {
            return id;
        }
    }
}

#[cfg(not(feature = "frida-ffi"))]
fn scalar_kind(name: &str, allow_void: bool) -> Result<ScalarKind, String> {
    let kind = match name {
        "void" if allow_void => ScalarKind::Void,
        "bool" | "char" | "int8" => ScalarKind::Signed { size: 1 },
        "uchar" | "uint8" => ScalarKind::Unsigned { size: 1 },
        "short" | "int16" => ScalarKind::Signed { size: 2 },
        "ushort" | "uint16" => ScalarKind::Unsigned { size: 2 },
        "int" | "int32" => ScalarKind::Signed { size: 4 },
        "uint" | "uint32" => ScalarKind::Unsigned { size: 4 },
        "long" | "int64" | "ssize_t" => ScalarKind::Signed { size: 8 },
        "ulong" | "uint64" | "size_t" => ScalarKind::Unsigned { size: 8 },
        "pointer" => ScalarKind::Pointer,
        "float" => ScalarKind::Float,
        "double" => ScalarKind::Double,
        "void" => return Err("'void' can only be the return type".to_string()),
        _ => return Err(format!("unknown type '{name}'")),
    };
    Ok(kind)
}

#[cfg(not(feature = "frida-ffi"))]
fn plan_arguments(kinds: &[ScalarKind]) -> Vec<ArgumentPlan> {
    let mut gpr = 0u8;
    let mut fpr = 0u8;
    let mut stack = 0u16;
    kinds
        .iter()
        .copied()
        .map(|kind| {
            let location = if kind.is_floating() {
                if fpr < 8 {
                    let location = ArgumentLocation::Fpr(fpr);
                    fpr += 1;
                    location
                } else {
                    let location = ArgumentLocation::Stack(stack);
                    stack += 1;
                    location
                }
            } else if gpr < 8 {
                let location = ArgumentLocation::Gpr(gpr);
                gpr += 1;
                location
            } else {
                let location = ArgumentLocation::Stack(stack);
                stack += 1;
                location
            };
            ArgumentPlan { kind, location }
        })
        .collect()
}

#[cfg(not(feature = "frida-ffi"))]
unsafe fn read_type_name(
    ctx: *mut ffi::JSContext,
    value: ffi::JSValue,
    position: &str,
) -> Result<String, ffi::JSValue> {
    if ffi::JS_IsArray(ctx, value) != 0 {
        return Err(ffi::JS_ThrowTypeError(
            ctx,
            b"NativeCallback: struct-by-value types are not implemented yet\0".as_ptr() as *const _,
        ));
    }
    JSValue(value).to_string(ctx).ok_or_else(|| {
        let message =
            std::ffi::CString::new(format!("NativeCallback: {position} type must be a string")).unwrap_or_default();
        ffi::JS_ThrowTypeError(ctx, message.as_ptr())
    })
}

#[cfg(not(feature = "frida-ffi"))]
unsafe fn parse_signature(
    ctx: *mut ffi::JSContext,
    return_value: ffi::JSValue,
    argument_values: ffi::JSValue,
) -> Result<(ScalarKind, Vec<ArgumentPlan>), ffi::JSValue> {
    let return_name = read_type_name(ctx, return_value, "return")?;
    let return_kind = scalar_kind(&return_name, true).map_err(|message| {
        let message = std::ffi::CString::new(format!("NativeCallback: {message}")).unwrap_or_default();
        ffi::JS_ThrowTypeError(ctx, message.as_ptr())
    })?;
    if ffi::JS_IsArray(ctx, argument_values) == 0 {
        return Err(ffi::JS_ThrowTypeError(
            ctx,
            b"NativeCallback: argument types must be an array\0".as_ptr() as *const _,
        ));
    }
    let length_value = ffi::JS_GetPropertyStr(ctx, argument_values, b"length\0".as_ptr() as *const _);
    let length = JSValue(length_value).to_i64(ctx).unwrap_or(-1);
    ffi::qjs_free_value(ctx, length_value);
    if !(0..=MAX_CALLBACK_ARGUMENTS as i64).contains(&length) {
        return Err(ffi::JS_ThrowRangeError(
            ctx,
            b"NativeCallback: too many arguments\0".as_ptr() as *const _,
        ));
    }
    let mut kinds = Vec::with_capacity(length as usize);
    for index in 0..length as u32 {
        let value = ffi::JS_GetPropertyUint32(ctx, argument_values, index);
        if ffi::qjs_is_exception(value) != 0 {
            return Err(value);
        }
        let name = match read_type_name(ctx, value, "argument") {
            Ok(name) => name,
            Err(error) => {
                ffi::qjs_free_value(ctx, value);
                return Err(error);
            }
        };
        ffi::qjs_free_value(ctx, value);
        let kind = scalar_kind(&name, false).map_err(|message| {
            let message = std::ffi::CString::new(format!("NativeCallback: {message}")).unwrap_or_default();
            ffi::JS_ThrowTypeError(ctx, message.as_ptr())
        })?;
        kinds.push(kind);
    }
    Ok((return_kind, plan_arguments(&kinds)))
}

unsafe fn validate_abi(ctx: *mut ffi::JSContext, argc: i32, argv: *mut ffi::JSValue) -> Result<(), ffi::JSValue> {
    if argc < 4 {
        return Ok(());
    }
    let abi = JSValue(*argv.add(3));
    if abi.is_undefined() || abi.is_null() {
        return Ok(());
    }
    let Some(name) = abi.to_string(ctx) else {
        return Err(ffi::JS_ThrowTypeError(
            ctx,
            b"NativeCallback: ABI must be a string\0".as_ptr() as *const _,
        ));
    };
    if matches!(name.as_str(), "default" | "sysv") {
        Ok(())
    } else {
        Err(ffi::JS_ThrowTypeError(
            ctx,
            b"NativeCallback: unsupported ABI on ARM64 Android\0".as_ptr() as *const _,
        ))
    }
}

#[cfg(not(feature = "frida-ffi"))]
unsafe fn allocate_thunk(data: *mut NativeCallbackData) -> Result<(usize, usize), String> {
    let page_size = libc::sysconf(libc::_SC_PAGESIZE);
    if page_size <= 0 {
        return Err("unable to query page size".to_string());
    }
    let mapping_size = page_size as usize;
    let mapping = libc::mmap(
        std::ptr::null_mut(),
        mapping_size,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    );
    if mapping == libc::MAP_FAILED {
        return Err(format!("mmap failed: {}", std::io::Error::last_os_error()));
    }
    let code = mapping as *mut u8;
    let words = [0x5800_0090u32, 0x5800_00b1u32, 0xd61f_0220u32, 0xd503_201fu32];
    std::ptr::copy_nonoverlapping(words.as_ptr() as *const u8, code, std::mem::size_of_val(&words));
    std::ptr::write_unaligned(code.add(16) as *mut usize, data as usize);
    std::ptr::write_unaligned(code.add(24) as *mut usize, native_callback_entry as *const () as usize);
    ffi::qjs_clear_cache(mapping, code.add(32) as *mut c_void);
    if libc::mprotect(mapping, mapping_size, libc::PROT_READ | libc::PROT_EXEC) != 0 {
        let error = std::io::Error::last_os_error();
        libc::munmap(mapping, mapping_size);
        return Err(format!("mprotect RX failed: {error}"));
    }
    Ok((mapping as usize, mapping_size))
}

unsafe extern "C" fn native_callback_finalizer(_runtime: *mut ffi::JSRuntime, value: ffi::JSValue) {
    let class_id = NATIVE_CALLBACK_CLASS_ID.load(Ordering::Relaxed);
    if class_id == 0 {
        return;
    }
    let opaque = ffi::JS_GetOpaque(value, class_id);
    if !opaque.is_null() {
        drop(Box::from_raw(opaque as *mut NativeCallbackHandle));
    }
}

unsafe fn destroy_unpublished_callback(mut data: Box<NativeCallbackData>) {
    data.active.store(false, Ordering::Release);
    if data.callback_alive {
        let value: ffi::JSValue = std::ptr::read(data.callback_bytes.as_ptr() as *const _);
        ffi::qjs_free_value(data.ctx as *mut ffi::JSContext, value);
        data.callback_alive = false;
    }
    #[cfg(feature = "frida-ffi")]
    native_ffi::free_callback_closure(data._closure as *mut c_void);
    #[cfg(not(feature = "frida-ffi"))]
    if data.thunk != 0 && data.mapping_size != 0 {
        libc::munmap(data.thunk as *mut c_void, data.mapping_size);
    }
}

fn get_or_init_class_id(ctx: *mut ffi::JSContext) -> u32 {
    let mut class_id = NATIVE_CALLBACK_CLASS_ID.load(Ordering::Relaxed);
    if class_id == 0 {
        let mut new_id = 0u32;
        new_id = unsafe { ffi::JS_NewClassID(&mut new_id) };
        class_id = NATIVE_CALLBACK_CLASS_ID
            .compare_exchange(0, new_id, Ordering::SeqCst, Ordering::Relaxed)
            .unwrap_or_else(|existing| existing);
    }
    unsafe {
        let definition = ffi::JSClassDef {
            class_name: NATIVE_CALLBACK_CLASS_NAME.as_ptr() as *const _,
            finalizer: Some(native_callback_finalizer),
            gc_mark: None,
            call: None,
            exotic: std::ptr::null_mut(),
        };
        let _ = ffi::JS_NewClass(ffi::JS_GetRuntime(ctx), class_id, &definition);
    }
    class_id
}

unsafe extern "C" fn js_native_callback_construct(
    ctx: *mut ffi::JSContext,
    new_target: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 3 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"NativeCallback requires function, return type, and argument types\0".as_ptr() as *const _,
        );
    }
    let callback = JSValue(*argv);
    if !callback.is_function(ctx) {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"NativeCallback: first argument must be a function\0".as_ptr() as *const _,
        );
    }
    if let Err(error) = validate_abi(ctx, argc, argv) {
        return error;
    }
    #[cfg(feature = "frida-ffi")]
    let signature = match native_ffi::NativeFfiSignature::parse_callback(ctx, *argv.add(1), *argv.add(2)) {
        Ok(signature) => signature,
        Err(error) => return error,
    };
    #[cfg(not(feature = "frida-ffi"))]
    let (return_kind, arguments) = match parse_signature(ctx, *argv.add(1), *argv.add(2)) {
        Ok(signature) => signature,
        Err(error) => return error,
    };
    let id = next_callback_id();
    let mut data = Box::new(NativeCallbackData {
        id,
        ctx: ctx as usize,
        callback_bytes: dup_callback_to_bytes(ctx, callback.raw()),
        callback_alive: true,
        #[cfg(not(feature = "frida-ffi"))]
        return_kind,
        #[cfg(not(feature = "frida-ffi"))]
        arguments,
        #[cfg(feature = "frida-ffi")]
        signature,
        #[cfg(feature = "frida-ffi")]
        _closure: 0,
        thunk: 0,
        #[cfg(not(feature = "frida-ffi"))]
        mapping_size: 0,
        active: AtomicBool::new(true),
    });
    #[cfg(feature = "frida-ffi")]
    let allocation = {
        let data_pointer = (&mut *data as *mut NativeCallbackData).cast::<c_void>();
        native_ffi::allocate_callback_closure(data.signature.cif_mut(), native_callback_ffi_dispatch, data_pointer)
            .map(|(closure, code)| (code as usize, closure as usize))
    };
    #[cfg(not(feature = "frida-ffi"))]
    let allocation = allocate_thunk(&mut *data);
    let (thunk, allocation_data) = match allocation {
        Ok(allocation) => allocation,
        Err(message) => {
            destroy_unpublished_callback(data);
            let message = std::ffi::CString::new(format!("NativeCallback: {message}")).unwrap_or_default();
            return ffi::JS_ThrowInternalError(ctx, message.as_ptr());
        }
    };
    data.thunk = thunk;
    #[cfg(feature = "frida-ffi")]
    {
        data._closure = allocation_data;
    }
    #[cfg(not(feature = "frida-ffi"))]
    {
        data.mapping_size = allocation_data;
    }
    let class_id = get_or_init_class_id(ctx);
    let prototype = ffi::JS_GetPropertyStr(ctx, new_target, c"prototype".as_ptr());
    if ffi::qjs_is_exception(prototype) != 0 {
        destroy_unpublished_callback(data);
        return prototype;
    }
    let object = ffi::JS_NewObjectProtoClass(ctx, prototype, class_id);
    ffi::qjs_free_value(ctx, prototype);
    if ffi::qjs_is_exception(object) != 0 {
        destroy_unpublished_callback(data);
        return object;
    }
    ffi::JS_SetOpaque(
        object,
        Box::into_raw(Box::new(NativeCallbackHandle { id })) as *mut c_void,
    );
    let mut registry = NATIVE_CALLBACKS.lock().unwrap_or_else(|error| error.into_inner());
    registry.get_or_insert_with(HashMap::new).insert(id, data);
    object
}

pub(crate) unsafe fn register_native_callback_api(ctx: *mut ffi::JSContext, global: ffi::JSValue) {
    let class_id = get_or_init_class_id(ctx);
    let prototype = ffi::JS_NewObject(ctx);
    let pointer_prototype = native_pointer_prototype(ctx);
    ffi::JS_SetPrototype(ctx, prototype, pointer_prototype);
    ffi::qjs_free_value(ctx, pointer_prototype);
    ffi::JS_SetClassProto(ctx, class_id, prototype);

    let constructor = ffi::JS_NewCFunction2(
        ctx,
        Some(js_native_callback_construct),
        NATIVE_CALLBACK_CLASS_NAME.as_ptr() as *const _,
        3,
        ffi::JSCFunctionEnum_JS_CFUNC_constructor,
        0,
    );
    let class_prototype = ffi::JS_GetClassProto(ctx, class_id);
    ffi::JS_SetConstructor(ctx, constructor, class_prototype);
    ffi::qjs_free_value(ctx, class_prototype);
    ffi::JS_SetPropertyStr(
        ctx,
        global,
        NATIVE_CALLBACK_CLASS_NAME.as_ptr() as *const _,
        constructor,
    );
}

pub(crate) fn native_callback_address(value: ffi::JSValue) -> Option<u64> {
    let class_id = NATIVE_CALLBACK_CLASS_ID.load(Ordering::Relaxed);
    if class_id == 0 {
        return None;
    }
    let handle = unsafe { ffi::JS_GetOpaque(value, class_id) as *const NativeCallbackHandle };
    if handle.is_null() {
        return None;
    }
    let id = unsafe { (*handle).id };
    let registry = NATIVE_CALLBACKS.lock().unwrap_or_else(|error| error.into_inner());
    registry.as_ref()?.get(&id).map(|data| data.thunk as u64)
}

#[cfg(not(feature = "frida-ffi"))]
fn raw_argument(frame: &NativeCallbackFrame, argument: ArgumentPlan) -> u64 {
    match argument.location {
        ArgumentLocation::Gpr(index) => frame.gpr[index as usize],
        ArgumentLocation::Fpr(index) => frame.fpr[index as usize],
        ArgumentLocation::Stack(index) => unsafe { *((frame.caller_sp as *const u64).add(index as usize)) },
    }
}

#[cfg(not(feature = "frida-ffi"))]
unsafe fn argument_to_js(ctx: *mut ffi::JSContext, raw: u64, kind: ScalarKind) -> ffi::JSValue {
    match kind {
        ScalarKind::Void => JSValue::undefined().raw(),
        ScalarKind::Signed { size: 1 } => ffi::qjs_new_int64(ctx, raw as u8 as i8 as i64),
        ScalarKind::Signed { size: 2 } => ffi::qjs_new_int64(ctx, raw as u16 as i16 as i64),
        ScalarKind::Signed { size: 4 } => ffi::qjs_new_int64(ctx, raw as u32 as i32 as i64),
        ScalarKind::Signed { .. } => js_i64_to_js_number_or_bigint(ctx, raw as i64),
        ScalarKind::Unsigned { size: 1 } => ffi::qjs_new_uint32(ctx, raw as u8 as u32),
        ScalarKind::Unsigned { size: 2 } => ffi::qjs_new_uint32(ctx, raw as u16 as u32),
        ScalarKind::Unsigned { size: 4 } => ffi::qjs_new_uint32(ctx, raw as u32),
        ScalarKind::Unsigned { .. } => js_u64_to_js_number_or_bigint(ctx, raw),
        ScalarKind::Pointer => create_native_pointer(ctx, raw).raw(),
        ScalarKind::Float => ffi::qjs_new_float64(ctx, f32::from_bits(raw as u32) as f64),
        ScalarKind::Double => ffi::qjs_new_float64(ctx, f64::from_bits(raw)),
    }
}

#[cfg(not(feature = "frida-ffi"))]
unsafe fn store_result(
    ctx: *mut ffi::JSContext,
    result: ffi::JSValue,
    kind: ScalarKind,
    frame: &mut NativeCallbackFrame,
) {
    match kind {
        ScalarKind::Void => {}
        ScalarKind::Signed { size } | ScalarKind::Unsigned { size } => {
            let raw = js_value_to_u64_or_zero(ctx, JSValue(result));
            frame.result_gpr = match size {
                1 => raw as u8 as u64,
                2 => raw as u16 as u64,
                4 => raw as u32 as u64,
                _ => raw,
            };
        }
        ScalarKind::Pointer => frame.result_gpr = js_value_to_u64_or_zero(ctx, JSValue(result)),
        ScalarKind::Float => {
            frame.result_fpr = (JSValue(result).to_float().unwrap_or(0.0) as f32).to_bits() as u64;
        }
        ScalarKind::Double => frame.result_fpr = JSValue(result).to_float().unwrap_or(0.0).to_bits(),
    }
}

unsafe fn invoke_native_callback<BuildArguments, StoreResult>(
    data: *mut NativeCallbackData,
    return_address: u64,
    build_arguments: BuildArguments,
    store_result: StoreResult,
) where
    BuildArguments: FnOnce(*mut ffi::JSContext, &NativeCallbackData) -> Vec<ffi::JSValue>,
    StoreResult: FnOnce(*mut ffi::JSContext, &NativeCallbackData, ffi::JSValue) -> Result<(), ffi::JSValue>,
{
    if data.is_null() {
        return;
    }
    let _in_flight = InFlightNativeCallbackGuard::enter();
    let data = &*data;
    if !data.active.load(Ordering::Acquire) || !data.callback_alive {
        return;
    }
    let ctx = data.ctx as *mut ffi::JSContext;
    let _engine = match acquire_js_engine_for_callback(ctx, "NativeCallback", data.id) {
        Some(guard) => guard,
        None => return,
    };
    if !data.active.load(Ordering::Acquire) {
        return;
    }
    let saved_error = get_system_error();
    let callback: ffi::JSValue = std::ptr::read(data.callback_bytes.as_ptr() as *const _);
    let callback = ffi::qjs_dup_value(ctx, callback);
    let this_object = ffi::JS_NewObject(ctx);
    JSValue(this_object).set_property(ctx, "errno", JSValue(ffi::qjs_new_int64(ctx, saved_error as i64)));
    ffi::JS_SetPropertyStr(
        ctx,
        this_object,
        b"returnAddress\0".as_ptr() as *const _,
        create_native_pointer(ctx, return_address).raw(),
    );

    let mut arguments = build_arguments(ctx, data);
    let result = ffi::JS_Call(
        ctx,
        callback,
        this_object,
        arguments.len() as i32,
        arguments.as_mut_ptr(),
    );
    for argument in arguments {
        ffi::qjs_free_value(ctx, argument);
    }
    if !handle_js_exception(ctx, result, "NativeCallback") {
        match store_result(ctx, data, result) {
            Ok(()) => {
                let errno_value = ffi::JS_GetPropertyStr(ctx, this_object, b"errno\0".as_ptr() as *const _);
                set_system_error(JSValue(errno_value).to_i64(ctx).unwrap_or(saved_error as i64) as i32);
                ffi::qjs_free_value(ctx, errno_value);
            }
            Err(error) => {
                handle_js_exception(ctx, error, "NativeCallback");
                set_system_error(saved_error);
            }
        }
    } else {
        set_system_error(saved_error);
    }
    ffi::qjs_free_value(ctx, result);
    ffi::qjs_free_value(ctx, this_object);
    ffi::qjs_free_value(ctx, callback);
}

#[no_mangle]
#[cfg(not(feature = "frida-ffi"))]
unsafe extern "C" fn native_callback_dispatch(data: *mut NativeCallbackData, frame: *mut NativeCallbackFrame) {
    if frame.is_null() {
        return;
    }
    let return_address = (*frame).return_address;
    invoke_native_callback(
        data,
        return_address,
        |ctx, data| {
            data.arguments
                .iter()
                .map(|argument| argument_to_js(ctx, raw_argument(&*frame, *argument), argument.kind))
                .collect()
        },
        |ctx, data, result| {
            store_result(ctx, result, data.return_kind, &mut *frame);
            Ok(())
        },
    );
}

#[cfg(feature = "frida-ffi")]
#[inline(always)]
unsafe fn current_return_address() -> u64 {
    #[cfg(target_arch = "aarch64")]
    {
        let address: u64;
        std::arch::asm!("mov {address}, x30", address = out(reg) address, options(nomem, nostack, preserves_flags));
        address
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        0
    }
}

#[cfg(feature = "frida-ffi")]
unsafe extern "C" fn native_callback_ffi_dispatch(
    _cif: *mut native_ffi::FfiCif,
    return_value: *mut c_void,
    arguments: *mut *mut c_void,
    user_data: *mut c_void,
) {
    let data = user_data.cast::<NativeCallbackData>();
    if data.is_null() {
        return;
    }
    let signature = &(*data).signature;
    if !return_value.is_null() {
        std::ptr::write_bytes(return_value.cast::<u8>(), 0, signature.return_type().size());
    }
    invoke_native_callback(
        data,
        current_return_address(),
        |ctx, data| {
            data.signature
                .arguments()
                .iter()
                .enumerate()
                .map(|(index, plan)| native_ffi::read_value(ctx, plan, *arguments.add(index).cast::<*const u8>()))
                .collect()
        },
        |ctx, data, result| {
            native_ffi::write_value(ctx, result, data.signature.return_type(), return_value.cast::<u8>())
        },
    );
}

pub(crate) fn cut_native_callbacks() {
    let registry = NATIVE_CALLBACKS.lock().unwrap_or_else(|error| error.into_inner());
    if let Some(callbacks) = registry.as_ref() {
        for callback in callbacks.values() {
            callback.active.store(false, Ordering::Release);
        }
    }
}

pub(crate) fn wait_for_in_flight_native_callbacks(timeout: std::time::Duration) -> bool {
    let start = std::time::Instant::now();
    let mut count = IN_FLIGHT_NATIVE_CALLBACKS
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    while *count != 0 {
        let Some(remaining) = timeout.checked_sub(start.elapsed()) else {
            return false;
        };
        let (next, wait) = IN_FLIGHT_NATIVE_CALLBACKS_CV
            .wait_timeout(count, remaining)
            .unwrap_or_else(|error| error.into_inner());
        count = next;
        if wait.timed_out() && *count != 0 {
            return false;
        }
    }
    true
}

pub(crate) fn free_native_callbacks() {
    let callbacks = {
        let mut registry = NATIVE_CALLBACKS.lock().unwrap_or_else(|error| error.into_inner());
        registry.take().unwrap_or_default().into_values().collect::<Vec<_>>()
    };
    let mut retired = RETIRED_NATIVE_CALLBACKS
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    for mut callback in callbacks {
        callback.active.store(false, Ordering::Release);
        if callback.callback_alive {
            unsafe {
                let value: ffi::JSValue = std::ptr::read(callback.callback_bytes.as_ptr() as *const _);
                ffi::qjs_free_value(callback.ctx as *mut ffi::JSContext, value);
            }
            callback.callback_alive = false;
            callback.callback_bytes = [0; 16];
            callback.ctx = 0;
        }
        retired.push(callback);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plans_integer_and_floating_registers_independently() {
        let kinds = [
            ScalarKind::Signed { size: 4 },
            ScalarKind::Double,
            ScalarKind::Pointer,
            ScalarKind::Float,
        ];
        let plan = plan_arguments(&kinds);
        assert_eq!(plan[0].location, ArgumentLocation::Gpr(0));
        assert_eq!(plan[1].location, ArgumentLocation::Fpr(0));
        assert_eq!(plan[2].location, ArgumentLocation::Gpr(1));
        assert_eq!(plan[3].location, ArgumentLocation::Fpr(1));
    }

    #[test]
    fn spills_each_exhausted_register_class_in_declaration_order() {
        let mut kinds = vec![ScalarKind::Unsigned { size: 8 }; 9];
        kinds.extend(std::iter::repeat(ScalarKind::Double).take(9));
        let plan = plan_arguments(&kinds);
        assert_eq!(plan[8].location, ArgumentLocation::Stack(0));
        assert_eq!(plan[17].location, ArgumentLocation::Stack(1));
    }

    #[test]
    fn rejects_void_arguments_and_unknown_types() {
        assert!(scalar_kind("void", false).is_err());
        assert!(scalar_kind("int", false).is_ok());
        assert!(scalar_kind("vector", false).is_err());
    }
}
