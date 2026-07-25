use crate::ffi;
use crate::jsapi::callback_util::{
    extract_pointer_address, js_i64_to_js_number_or_bigint, js_u64_to_js_number_or_bigint, throw_internal_error,
};
use crate::jsapi::ptr::create_native_pointer;
use crate::jsapi::stalker::with_native_call_context;
use crate::jsapi::util::add_cfunction_to_object;
use crate::value::JSValue;
use std::ffi::c_void;
use std::sync::atomic::{AtomicU32, Ordering};

pub(super) const FFI_OK: i32 = 0;
const FFI_SYSV: u32 = 1;
const FFI_TYPE_STRUCT: u16 = 13;
const MAX_ARGUMENTS: usize = 256;
const SIGNATURE_CLASS_NAME: &[u8] = b"NativeFfiSignature\0";
const FFI_CLOSURE_SIZE_ARM64: usize = 48;

static SIGNATURE_CLASS_ID: AtomicU32 = AtomicU32::new(0);

#[repr(C)]
pub(super) struct FfiType {
    size: usize,
    alignment: u16,
    kind: u16,
    elements: *mut *mut FfiType,
}

#[repr(C)]
#[derive(Default)]
pub(super) struct FfiCif {
    abi: u32,
    nargs: u32,
    arg_types: *mut *mut FfiType,
    return_type: *mut FfiType,
    bytes: u32,
    flags: u32,
}

#[repr(C)]
#[derive(Default)]
struct NativeFfiException {
    kind: u32,
    memory_operation: u32,
    address: usize,
    memory_address: usize,
}

extern "C" {
    #[link_name = "_frida_ffi_type_void"]
    static mut FFI_TYPE_VOID: FfiType;
    #[link_name = "_frida_ffi_type_uint8"]
    static mut FFI_TYPE_UINT8: FfiType;
    #[link_name = "_frida_ffi_type_sint8"]
    static mut FFI_TYPE_SINT8: FfiType;
    #[link_name = "_frida_ffi_type_uint16"]
    static mut FFI_TYPE_UINT16: FfiType;
    #[link_name = "_frida_ffi_type_sint16"]
    static mut FFI_TYPE_SINT16: FfiType;
    #[link_name = "_frida_ffi_type_uint32"]
    static mut FFI_TYPE_UINT32: FfiType;
    #[link_name = "_frida_ffi_type_sint32"]
    static mut FFI_TYPE_SINT32: FfiType;
    #[link_name = "_frida_ffi_type_uint64"]
    static mut FFI_TYPE_UINT64: FfiType;
    #[link_name = "_frida_ffi_type_sint64"]
    static mut FFI_TYPE_SINT64: FfiType;
    #[link_name = "_frida_ffi_type_float"]
    static mut FFI_TYPE_FLOAT: FfiType;
    #[link_name = "_frida_ffi_type_double"]
    static mut FFI_TYPE_DOUBLE: FfiType;
    #[link_name = "_frida_ffi_type_pointer"]
    static mut FFI_TYPE_POINTER: FfiType;

    #[link_name = "_frida_ffi_prep_cif"]
    fn ffi_prep_cif(
        cif: *mut FfiCif,
        abi: u32,
        argument_count: u32,
        return_type: *mut FfiType,
        argument_types: *mut *mut FfiType,
    ) -> i32;
    #[link_name = "_frida_ffi_prep_cif_var"]
    fn ffi_prep_cif_var(
        cif: *mut FfiCif,
        abi: u32,
        fixed_count: u32,
        total_count: u32,
        return_type: *mut FfiType,
        argument_types: *mut *mut FfiType,
    ) -> i32;
    #[link_name = "_frida_ffi_closure_alloc"]
    fn ffi_closure_alloc(size: usize, code: *mut *mut c_void) -> *mut c_void;
    #[link_name = "_frida_ffi_closure_free"]
    fn ffi_closure_free(closure: *mut c_void);
    #[link_name = "_frida_ffi_prep_closure_loc"]
    fn ffi_prep_closure_loc(
        closure: *mut c_void,
        cif: *mut FfiCif,
        callback: unsafe extern "C" fn(*mut FfiCif, *mut c_void, *mut *mut c_void, *mut c_void),
        user_data: *mut c_void,
        code: *mut c_void,
    ) -> i32;

    fn rf_native_ffi_call(
        cif: *mut FfiCif,
        function: *mut c_void,
        result: *mut c_void,
        arguments: *mut *mut c_void,
        steal_exceptions: i32,
        ignore_interceptor: i32,
        system_error: *mut i32,
        exception: *mut NativeFfiException,
    ) -> i32;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ScalarType {
    Void,
    Bool,
    Signed(u8),
    Unsigned(u8),
    Pointer,
    Float,
    Double,
}

enum TypeStorage {
    Scalar(ScalarType),
    Structure {
        fields: Vec<TypePlan>,
        ffi_type: Box<FfiType>,
        _elements: Box<[*mut FfiType]>,
    },
}

pub(super) struct TypePlan {
    storage: TypeStorage,
}

impl TypePlan {
    fn ffi_type(&self) -> *mut FfiType {
        match &self.storage {
            TypeStorage::Scalar(kind) => unsafe { scalar_ffi_type(*kind) },
            TypeStorage::Structure { ffi_type, .. } => &**ffi_type as *const FfiType as *mut FfiType,
        }
    }

    fn promoted(self) -> Self {
        match self.storage {
            TypeStorage::Scalar(ScalarType::Bool) => Self {
                storage: TypeStorage::Scalar(ScalarType::Signed(4)),
            },
            TypeStorage::Scalar(ScalarType::Signed(size)) if size < 4 => Self {
                storage: TypeStorage::Scalar(ScalarType::Signed(4)),
            },
            TypeStorage::Scalar(ScalarType::Unsigned(size)) if size < 4 => Self {
                storage: TypeStorage::Scalar(ScalarType::Unsigned(4)),
            },
            TypeStorage::Scalar(ScalarType::Float) => Self {
                storage: TypeStorage::Scalar(ScalarType::Double),
            },
            storage => Self { storage },
        }
    }

    pub(super) fn size(&self) -> usize {
        unsafe { (*self.ffi_type()).size.max(1) }
    }

    fn alignment(&self) -> usize {
        unsafe { (*self.ffi_type()).alignment.max(1) as usize }
    }
}

pub(super) struct NativeFfiSignature {
    return_type: TypePlan,
    arguments: Vec<TypePlan>,
    _argument_types: Vec<*mut FfiType>,
    cif: FfiCif,
    fixed_count: usize,
    variadic: bool,
}

unsafe fn scalar_ffi_type(kind: ScalarType) -> *mut FfiType {
    match kind {
        ScalarType::Void => &raw mut FFI_TYPE_VOID,
        ScalarType::Bool => &raw mut FFI_TYPE_SINT8,
        ScalarType::Signed(1) => &raw mut FFI_TYPE_SINT8,
        ScalarType::Unsigned(1) => &raw mut FFI_TYPE_UINT8,
        ScalarType::Signed(2) => &raw mut FFI_TYPE_SINT16,
        ScalarType::Unsigned(2) => &raw mut FFI_TYPE_UINT16,
        ScalarType::Signed(4) => &raw mut FFI_TYPE_SINT32,
        ScalarType::Unsigned(4) => &raw mut FFI_TYPE_UINT32,
        ScalarType::Signed(_) => &raw mut FFI_TYPE_SINT64,
        ScalarType::Unsigned(_) => &raw mut FFI_TYPE_UINT64,
        ScalarType::Pointer => &raw mut FFI_TYPE_POINTER,
        ScalarType::Float => &raw mut FFI_TYPE_FLOAT,
        ScalarType::Double => &raw mut FFI_TYPE_DOUBLE,
    }
}

fn scalar_type(name: &str, allow_void: bool) -> Result<ScalarType, String> {
    match name {
        "void" if allow_void => Ok(ScalarType::Void),
        "bool" => Ok(ScalarType::Bool),
        "char" | "int8" => Ok(ScalarType::Signed(1)),
        "uchar" | "uint8" => Ok(ScalarType::Unsigned(1)),
        "short" | "int16" => Ok(ScalarType::Signed(2)),
        "ushort" | "uint16" => Ok(ScalarType::Unsigned(2)),
        "int" | "int32" => Ok(ScalarType::Signed(4)),
        "uint" | "uint32" => Ok(ScalarType::Unsigned(4)),
        "long" | "int64" | "ssize_t" => Ok(ScalarType::Signed(8)),
        "ulong" | "uint64" | "size_t" => Ok(ScalarType::Unsigned(8)),
        "pointer" => Ok(ScalarType::Pointer),
        "float" => Ok(ScalarType::Float),
        "double" => Ok(ScalarType::Double),
        "void" => Err("'void' can only be the return type".to_string()),
        _ => Err(format!("unknown type '{name}'")),
    }
}

unsafe fn array_length(
    ctx: *mut ffi::JSContext,
    value: ffi::JSValue,
    description: &str,
) -> Result<usize, ffi::JSValue> {
    if ffi::JS_IsArray(ctx, value) == 0 {
        let message = std::ffi::CString::new(format!("{description} must be an array")).unwrap_or_default();
        return Err(ffi::JS_ThrowTypeError(ctx, message.as_ptr()));
    }
    let length = ffi::JS_GetPropertyStr(ctx, value, c"length".as_ptr());
    if ffi::qjs_is_exception(length) != 0 {
        return Err(length);
    }
    let parsed = JSValue(length).to_i64(ctx);
    ffi::qjs_free_value(ctx, length);
    match parsed {
        Some(length) if (0..=MAX_ARGUMENTS as i64).contains(&length) => Ok(length as usize),
        _ => Err(ffi::JS_ThrowRangeError(
            ctx,
            b"invalid array length\0".as_ptr() as *const _,
        )),
    }
}

unsafe fn parse_type(
    ctx: *mut ffi::JSContext,
    value: ffi::JSValue,
    allow_void: bool,
) -> Result<TypePlan, ffi::JSValue> {
    if ffi::JS_IsArray(ctx, value) != 0 {
        let length = array_length(ctx, value, "struct type")?;
        let mut fields = Vec::with_capacity(length);
        for index in 0..length {
            let field = ffi::JS_GetPropertyUint32(ctx, value, index as u32);
            if ffi::qjs_is_exception(field) != 0 {
                return Err(field);
            }
            let parsed = parse_type(ctx, field, false);
            ffi::qjs_free_value(ctx, field);
            fields.push(parsed?);
        }
        let mut elements = fields.iter().map(TypePlan::ffi_type).collect::<Vec<_>>();
        elements.push(std::ptr::null_mut());
        let mut elements = elements.into_boxed_slice();
        let ffi_type = Box::new(FfiType {
            size: 0,
            alignment: 0,
            kind: FFI_TYPE_STRUCT,
            elements: elements.as_mut_ptr(),
        });
        return Ok(TypePlan {
            storage: TypeStorage::Structure {
                fields,
                ffi_type,
                _elements: elements,
            },
        });
    }
    let js_value = JSValue(value);
    if !js_value.is_string() {
        return Err(ffi::JS_ThrowTypeError(
            ctx,
            b"invalid type specified\0".as_ptr() as *const _,
        ));
    }
    let name = js_value.to_string(ctx).unwrap_or_default();
    let kind = scalar_type(&name, allow_void).map_err(|message| {
        let message = std::ffi::CString::new(message).unwrap_or_default();
        ffi::JS_ThrowTypeError(ctx, message.as_ptr())
    })?;
    Ok(TypePlan {
        storage: TypeStorage::Scalar(kind),
    })
}

impl NativeFfiSignature {
    unsafe fn parse(
        ctx: *mut ffi::JSContext,
        return_value: ffi::JSValue,
        argument_values: ffi::JSValue,
    ) -> Result<Self, ffi::JSValue> {
        let return_type = parse_type(ctx, return_value, true)?;
        let length = array_length(ctx, argument_values, "argument types")?;
        let mut arguments = Vec::with_capacity(length);
        let mut fixed_count = length;
        let mut variadic = false;
        for index in 0..length {
            let value = ffi::JS_GetPropertyUint32(ctx, argument_values, index as u32);
            if ffi::qjs_is_exception(value) != 0 {
                return Err(value);
            }
            let marker = JSValue(value).is_string() && JSValue(value).to_string(ctx).as_deref() == Some("...");
            if marker {
                ffi::qjs_free_value(ctx, value);
                if index == 0 || variadic {
                    return Err(ffi::JS_ThrowTypeError(
                        ctx,
                        b"only one variadic marker may be specified, and it cannot be first\0".as_ptr() as *const _,
                    ));
                }
                fixed_count = arguments.len();
                variadic = true;
                continue;
            }
            let parsed = parse_type(ctx, value, false);
            ffi::qjs_free_value(ctx, value);
            let parsed = parsed?;
            arguments.push(if variadic { parsed.promoted() } else { parsed });
        }
        if variadic && fixed_count == arguments.len() {
            return Err(ffi::JS_ThrowTypeError(
                ctx,
                b"variadic signature must provide at least one trailing type\0".as_ptr() as *const _,
            ));
        }
        let mut argument_types = arguments.iter().map(TypePlan::ffi_type).collect::<Vec<_>>();
        let mut cif = FfiCif::default();
        let status = if variadic {
            ffi_prep_cif_var(
                &mut cif,
                FFI_SYSV,
                fixed_count as u32,
                arguments.len() as u32,
                return_type.ffi_type(),
                argument_types.as_mut_ptr(),
            )
        } else {
            ffi_prep_cif(
                &mut cif,
                FFI_SYSV,
                arguments.len() as u32,
                return_type.ffi_type(),
                argument_types.as_mut_ptr(),
            )
        };
        if status != FFI_OK {
            return Err(throw_internal_error(ctx, "failed to compile native call interface"));
        }
        Ok(Self {
            return_type,
            arguments,
            _argument_types: argument_types,
            cif,
            fixed_count,
            variadic,
        })
    }

    fn plan_for_argument(&self, index: usize) -> &TypePlan {
        if index < self.arguments.len() {
            &self.arguments[index]
        } else {
            let tail_count = self.arguments.len() - self.fixed_count;
            &self.arguments[self.fixed_count + ((index - self.fixed_count) % tail_count)]
        }
    }

    pub(super) unsafe fn parse_callback(
        ctx: *mut ffi::JSContext,
        return_value: ffi::JSValue,
        argument_values: ffi::JSValue,
    ) -> Result<Self, ffi::JSValue> {
        let signature = Self::parse(ctx, return_value, argument_values)?;
        if signature.variadic {
            return Err(ffi::JS_ThrowTypeError(
                ctx,
                b"NativeCallback does not support variadic signatures\0".as_ptr() as *const _,
            ));
        }
        Ok(signature)
    }

    pub(super) fn cif_mut(&mut self) -> *mut FfiCif {
        &mut self.cif
    }

    pub(super) fn return_type(&self) -> &TypePlan {
        &self.return_type
    }

    pub(super) fn arguments(&self) -> &[TypePlan] {
        &self.arguments
    }
}

pub(super) unsafe fn allocate_callback_closure(
    cif: *mut FfiCif,
    callback: unsafe extern "C" fn(*mut FfiCif, *mut c_void, *mut *mut c_void, *mut c_void),
    user_data: *mut c_void,
) -> Result<(*mut c_void, *mut c_void), String> {
    let mut code = std::ptr::null_mut();
    let closure = ffi_closure_alloc(FFI_CLOSURE_SIZE_ARM64, &mut code);
    if closure.is_null() || code.is_null() {
        return Err("failed to allocate closure".to_string());
    }
    if ffi_prep_closure_loc(closure, cif, callback, user_data, code) != FFI_OK {
        ffi_closure_free(closure);
        return Err("failed to prepare closure".to_string());
    }
    Ok((closure, code))
}

pub(super) unsafe fn free_callback_closure(closure: *mut c_void) {
    if !closure.is_null() {
        ffi_closure_free(closure);
    }
}

unsafe extern "C" fn signature_finalizer(_runtime: *mut ffi::JSRuntime, value: ffi::JSValue) {
    let class_id = SIGNATURE_CLASS_ID.load(Ordering::Relaxed);
    if class_id == 0 {
        return;
    }
    let signature = ffi::JS_GetOpaque(value, class_id) as *mut NativeFfiSignature;
    if !signature.is_null() {
        drop(Box::from_raw(signature));
    }
}

fn signature_class_id(ctx: *mut ffi::JSContext) -> u32 {
    let mut class_id = SIGNATURE_CLASS_ID.load(Ordering::Relaxed);
    if class_id == 0 {
        let mut allocated = 0;
        allocated = unsafe { ffi::JS_NewClassID(&mut allocated) };
        class_id = SIGNATURE_CLASS_ID
            .compare_exchange(0, allocated, Ordering::SeqCst, Ordering::Relaxed)
            .unwrap_or_else(|existing| existing);
    }
    unsafe {
        let definition = ffi::JSClassDef {
            class_name: SIGNATURE_CLASS_NAME.as_ptr() as *const _,
            finalizer: Some(signature_finalizer),
            gc_mark: None,
            call: None,
            exotic: std::ptr::null_mut(),
        };
        let _ = ffi::JS_NewClass(ffi::JS_GetRuntime(ctx), class_id, &definition);
    }
    class_id
}

unsafe extern "C" fn js_native_ffi_prepare(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"native FFI signature requires return and argument types\0".as_ptr() as *const _,
        );
    }
    let signature = match NativeFfiSignature::parse(ctx, *argv, *argv.add(1)) {
        Ok(signature) => signature,
        Err(error) => return error,
    };
    let object = ffi::JS_NewObjectClass(ctx, signature_class_id(ctx) as i32);
    if ffi::qjs_is_exception(object) != 0 {
        return object;
    }
    ffi::JS_SetOpaque(object, Box::into_raw(Box::new(signature)) as *mut c_void);
    object
}

struct AlignedValue {
    words: Vec<u64>,
}

impl AlignedValue {
    fn zeroed(size: usize) -> Self {
        Self {
            words: vec![0; size.max(8).div_ceil(8)],
        }
    }

    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.words.as_mut_ptr() as *mut u8
    }
}

pub(super) unsafe fn write_value(
    ctx: *mut ffi::JSContext,
    value: ffi::JSValue,
    plan: &TypePlan,
    destination: *mut u8,
) -> Result<(), ffi::JSValue> {
    match &plan.storage {
        TypeStorage::Scalar(ScalarType::Void) => Ok(()),
        TypeStorage::Scalar(ScalarType::Bool) => {
            let value = ffi::JS_ToBool(ctx, value);
            if value < 0 {
                return Err(ffi::qjs_exception());
            }
            std::ptr::write_unaligned(destination as *mut i8, (value != 0) as i8);
            Ok(())
        }
        TypeStorage::Scalar(ScalarType::Pointer) => {
            let address = extract_pointer_address(ctx, JSValue(value), "NativeFunction")?;
            std::ptr::write_unaligned(destination as *mut usize, address as usize);
            Ok(())
        }
        TypeStorage::Scalar(ScalarType::Signed(size)) => {
            let number = JSValue(value).to_i64(ctx).ok_or_else(|| {
                ffi::JS_ThrowTypeError(ctx, b"native integer argument expected\0".as_ptr() as *const _)
            })?;
            match size {
                1 => std::ptr::write_unaligned(destination as *mut i8, number as i8),
                2 => std::ptr::write_unaligned(destination as *mut i16, number as i16),
                4 => std::ptr::write_unaligned(destination as *mut i32, number as i32),
                _ => std::ptr::write_unaligned(destination as *mut i64, number),
            }
            Ok(())
        }
        TypeStorage::Scalar(ScalarType::Unsigned(size)) => {
            let number = extract_pointer_address(ctx, JSValue(value), "NativeFunction")?;
            match size {
                1 => std::ptr::write_unaligned(destination, number as u8),
                2 => std::ptr::write_unaligned(destination as *mut u16, number as u16),
                4 => std::ptr::write_unaligned(destination as *mut u32, number as u32),
                _ => std::ptr::write_unaligned(destination as *mut u64, number),
            }
            Ok(())
        }
        TypeStorage::Scalar(ScalarType::Float) => {
            let mut number = 0.0;
            if ffi::qjs_to_float64(ctx, &mut number, value) != 0 {
                return Err(ffi::qjs_exception());
            }
            std::ptr::write_unaligned(destination as *mut f32, number as f32);
            Ok(())
        }
        TypeStorage::Scalar(ScalarType::Double) => {
            let mut number = 0.0;
            if ffi::qjs_to_float64(ctx, &mut number, value) != 0 {
                return Err(ffi::qjs_exception());
            }
            std::ptr::write_unaligned(destination as *mut f64, number);
            Ok(())
        }
        TypeStorage::Structure { fields, .. } => {
            let length = array_length(ctx, value, "struct value")?;
            if length != fields.len() {
                return Err(ffi::JS_ThrowTypeError(
                    ctx,
                    b"provided array length does not match number of fields\0".as_ptr() as *const _,
                ));
            }
            let mut offset = 0usize;
            for (index, field) in fields.iter().enumerate() {
                offset = offset.next_multiple_of(field.alignment());
                let field_value = ffi::JS_GetPropertyUint32(ctx, value, index as u32);
                if ffi::qjs_is_exception(field_value) != 0 {
                    return Err(field_value);
                }
                let result = write_value(ctx, field_value, field, destination.add(offset));
                ffi::qjs_free_value(ctx, field_value);
                result?;
                offset += field.size();
            }
            Ok(())
        }
    }
}

pub(super) unsafe fn read_value(ctx: *mut ffi::JSContext, plan: &TypePlan, source: *const u8) -> ffi::JSValue {
    match &plan.storage {
        TypeStorage::Scalar(ScalarType::Void) => JSValue::undefined().raw(),
        TypeStorage::Scalar(ScalarType::Bool) => {
            ffi::qjs_new_bool(ctx, (std::ptr::read_unaligned(source as *const i8) != 0) as i32)
        }
        TypeStorage::Scalar(ScalarType::Pointer) => {
            create_native_pointer(ctx, std::ptr::read_unaligned(source as *const usize) as u64).raw()
        }
        TypeStorage::Scalar(ScalarType::Signed(size)) => {
            let value = match size {
                1 => std::ptr::read_unaligned(source as *const i8) as i64,
                2 => std::ptr::read_unaligned(source as *const i16) as i64,
                4 => std::ptr::read_unaligned(source as *const i32) as i64,
                _ => std::ptr::read_unaligned(source as *const i64),
            };
            js_i64_to_js_number_or_bigint(ctx, value)
        }
        TypeStorage::Scalar(ScalarType::Unsigned(size)) => {
            let value = match size {
                1 => std::ptr::read_unaligned(source) as u64,
                2 => std::ptr::read_unaligned(source as *const u16) as u64,
                4 => std::ptr::read_unaligned(source as *const u32) as u64,
                _ => std::ptr::read_unaligned(source as *const u64),
            };
            js_u64_to_js_number_or_bigint(ctx, value)
        }
        TypeStorage::Scalar(ScalarType::Float) => {
            ffi::qjs_new_float64(ctx, std::ptr::read_unaligned(source as *const f32) as f64)
        }
        TypeStorage::Scalar(ScalarType::Double) => {
            ffi::qjs_new_float64(ctx, std::ptr::read_unaligned(source as *const f64))
        }
        TypeStorage::Structure { fields, .. } => {
            let result = ffi::JS_NewArray(ctx);
            let mut offset = 0usize;
            for (index, field) in fields.iter().enumerate() {
                offset = offset.next_multiple_of(field.alignment());
                ffi::JS_SetPropertyUint32(ctx, result, index as u32, read_value(ctx, field, source.add(offset)));
                offset += field.size();
            }
            result
        }
    }
}

unsafe fn throw_native_exception(ctx: *mut ffi::JSContext, exception: &NativeFfiException) -> ffi::JSValue {
    let kind = match exception.kind {
        1 => "abort",
        2 => "access-violation",
        3 => "guard-page",
        4 => "illegal-instruction",
        5 => "stack-overflow",
        6 => "arithmetic",
        7 => "breakpoint",
        8 => "single-step",
        _ => "system",
    };
    let error = ffi::JS_NewError(ctx);
    let value = JSValue(error);
    value.set_property(ctx, "type", JSValue::string(ctx, kind));
    value.set_property(ctx, "address", create_native_pointer(ctx, exception.address as u64));
    let memory = ffi::JS_NewObject(ctx);
    let operation = match exception.memory_operation {
        1 => "read",
        2 => "write",
        3 => "execute",
        _ => "invalid",
    };
    JSValue(memory).set_property(ctx, "operation", JSValue::string(ctx, operation));
    JSValue(memory).set_property(
        ctx,
        "address",
        create_native_pointer(ctx, exception.memory_address as u64),
    );
    value.set_property(ctx, "memory", JSValue(memory));
    value.set_property(
        ctx,
        "message",
        JSValue::string(ctx, &format!("native exception {kind} at 0x{:x}", exception.address)),
    );
    ffi::JS_Throw(ctx, error)
}

unsafe extern "C" fn js_native_ffi_call(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 7 {
        return ffi::JS_ThrowTypeError(ctx, b"invalid native FFI call\0".as_ptr() as *const _);
    }
    let signature = ffi::JS_GetOpaque(*argv, signature_class_id(ctx)) as *mut NativeFfiSignature;
    if signature.is_null() {
        return ffi::JS_ThrowTypeError(ctx, b"invalid native FFI signature\0".as_ptr() as *const _);
    }
    let signature = &mut *signature;
    let address = match extract_pointer_address(ctx, JSValue(*argv.add(1)), "NativeFunction") {
        Ok(address) => address,
        Err(error) => return error,
    };
    let values = *argv.add(2);
    let value_count = match array_length(ctx, values, "NativeFunction arguments") {
        Ok(length) => length,
        Err(error) => return error,
    };
    if (!signature.variadic && value_count != signature.arguments.len())
        || (signature.variadic && value_count < signature.fixed_count)
    {
        return ffi::JS_ThrowTypeError(ctx, b"bad native argument count\0".as_ptr() as *const _);
    }
    let native_count = if signature.variadic {
        value_count.max(signature.arguments.len())
    } else {
        value_count
    };
    let mut buffers = (0..native_count)
        .map(|index| AlignedValue::zeroed(signature.plan_for_argument(index).size()))
        .collect::<Vec<_>>();
    for index in 0..value_count {
        let value = ffi::JS_GetPropertyUint32(ctx, values, index as u32);
        if ffi::qjs_is_exception(value) != 0 {
            return value;
        }
        let marshaled = write_value(
            ctx,
            value,
            signature.plan_for_argument(index),
            buffers[index].as_mut_ptr(),
        );
        ffi::qjs_free_value(ctx, value);
        if let Err(error) = marshaled {
            return error;
        }
    }
    let mut argument_pointers = buffers
        .iter_mut()
        .map(|buffer| buffer.as_mut_ptr() as *mut c_void)
        .collect::<Vec<_>>();
    let mut dynamic_types;
    let mut dynamic_cif = FfiCif::default();
    let cif = if native_count > signature.arguments.len() {
        dynamic_types = (0..native_count)
            .map(|index| signature.plan_for_argument(index).ffi_type())
            .collect::<Vec<_>>();
        if ffi_prep_cif_var(
            &mut dynamic_cif,
            FFI_SYSV,
            signature.fixed_count as u32,
            native_count as u32,
            signature.return_type.ffi_type(),
            dynamic_types.as_mut_ptr(),
        ) != FFI_OK
        {
            return throw_internal_error(ctx, "failed to compile variadic native call interface");
        }
        &mut dynamic_cif
    } else {
        &mut signature.cif
    };
    let capture_system_error = JSValue(*argv.add(3)).to_bool() == Some(true);
    let cooperative = JSValue(*argv.add(4)).to_bool() != Some(false);
    let steal_exceptions = JSValue(*argv.add(5)).to_bool() != Some(false);
    let trap_mode = JSValue(*argv.add(6)).to_int().unwrap_or(0);
    let mut result = AlignedValue::zeroed(signature.return_type.size());
    let mut system_error = 0i32;
    let mut exception = NativeFfiException::default();
    let operation = || {
        rf_native_ffi_call(
            cif,
            address as *mut c_void,
            result.as_mut_ptr() as *mut c_void,
            argument_pointers.as_mut_ptr(),
            steal_exceptions as i32,
            (trap_mode == 1) as i32,
            &mut system_error,
            &mut exception,
        )
    };
    let status = match with_native_call_context(ctx, address, cooperative, trap_mode != 1, operation) {
        Ok(status) => status,
        Err(error) => return throw_internal_error(ctx, format!("NativeFunction: {error}")),
    };
    if status != 0 {
        return throw_native_exception(ctx, &exception);
    }
    let value = read_value(ctx, &signature.return_type, result.as_mut_ptr());
    crate::jsapi::module::drain_process_observer_events(ctx);
    if capture_system_error {
        let wrapper = ffi::JS_NewObject(ctx);
        JSValue(wrapper).set_property(ctx, "value", JSValue(value));
        JSValue(wrapper).set_property(ctx, "errno", JSValue(ffi::qjs_new_int64(ctx, system_error as i64)));
        wrapper
    } else {
        value
    }
}

pub(crate) unsafe fn register_native_ffi_api(ctx: *mut ffi::JSContext, global: ffi::JSValue) {
    signature_class_id(ctx);
    add_cfunction_to_object(ctx, global, "__nativeFfiPrepare", js_native_ffi_prepare, 2);
    add_cfunction_to_object(ctx, global, "__nativeFfiCall", js_native_ffi_call, 7);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_layout_matches_android_arm64_libffi() {
        assert_eq!(std::mem::size_of::<FfiType>(), 24);
        assert_eq!(std::mem::size_of::<FfiCif>(), 32);
        assert_eq!(FFI_CLOSURE_SIZE_ARM64, 48);
    }

    #[test]
    fn scalar_names_match_gumjs() {
        assert_eq!(scalar_type("bool", false), Ok(ScalarType::Bool));
        assert_eq!(scalar_type("size_t", false), Ok(ScalarType::Unsigned(8)));
        assert_eq!(scalar_type("double", false), Ok(ScalarType::Double));
        assert!(scalar_type("void", false).is_err());
    }
}
