//! Frida-compatible diagnostics facade backed by agent-provided Gum services.

use crate::context::JSContext;
use crate::ffi;
use crate::jsapi::callback_util::{extract_pointer_address, throw_internal_error};
use crate::jsapi::ptr::{create_native_pointer, get_native_pointer_addr};
use crate::jsapi::util::add_cfunction_to_object;
use crate::value::JSValue;
use std::sync::Mutex;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DebugSymbolDetails {
    pub address: u64,
    pub name: Option<String>,
    pub module_name: Option<String>,
    pub file_name: Option<String>,
    pub line_number: Option<u32>,
    pub column: Option<u32>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct DiagnosticsCpuContext {
    pub pc: u64,
    pub sp: u64,
    pub nzcv: u64,
    pub x: [u64; 29],
    pub fp: u64,
    pub lr: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstructionShift {
    pub kind: String,
    pub value: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstructionMemoryOperand {
    pub base: Option<String>,
    pub index: Option<String>,
    pub displacement: i32,
}

#[derive(Clone, Debug, PartialEq)]
pub enum InstructionOperandValue {
    Register(String),
    Immediate(i64),
    Memory(InstructionMemoryOperand),
    Float(f64),
    Integer(i64),
}

#[derive(Clone, Debug, PartialEq)]
pub struct InstructionOperand {
    pub kind: String,
    pub value: InstructionOperandValue,
    pub shift: Option<InstructionShift>,
    pub ext: Option<String>,
    pub vas: Option<String>,
    pub vector_index: Option<i32>,
    pub access: String,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct InstructionDetails {
    pub address: u64,
    pub next: u64,
    pub size: u32,
    pub mnemonic: String,
    pub op_str: String,
    pub operands: Vec<InstructionOperand>,
    pub regs_accessed_read: Vec<String>,
    pub regs_accessed_written: Vec<String>,
    pub regs_read: Vec<String>,
    pub regs_written: Vec<String>,
    pub groups: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApiResolverMatch {
    pub name: String,
    pub address: u64,
    pub size: Option<u32>,
}

#[derive(Clone, Copy)]
pub struct DiagnosticsBackend {
    pub debug_symbol_from_address: fn(u64) -> DebugSymbolDetails,
    pub debug_symbol_from_name: fn(&str) -> DebugSymbolDetails,
    pub debug_symbol_get_function_by_name: fn(&str) -> Result<u64, String>,
    pub debug_symbol_find_functions_named: fn(&str) -> Vec<u64>,
    pub debug_symbol_find_functions_matching: fn(&str) -> Vec<u64>,
    pub debug_symbol_load: fn(&str) -> Result<(), String>,
    pub backtrace: fn(Option<&DiagnosticsCpuContext>, u32, usize) -> Result<Vec<u64>, String>,
    pub parse_instruction: fn(u64, &[u8]) -> Result<InstructionDetails, String>,
    pub enumerate_module_api_matches: fn(&str) -> Result<Vec<ApiResolverMatch>, String>,
}

static DIAGNOSTICS_BACKEND: Mutex<Option<DiagnosticsBackend>> = Mutex::new(None);

pub fn install_diagnostics_backend(backend: DiagnosticsBackend) {
    *DIAGNOSTICS_BACKEND.lock().unwrap_or_else(|error| error.into_inner()) = Some(backend);
}

fn backend_or_throw(ctx: *mut ffi::JSContext) -> Result<DiagnosticsBackend, ffi::JSValue> {
    DIAGNOSTICS_BACKEND
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .as_ref()
        .copied()
        .ok_or_else(|| unsafe { throw_internal_error(ctx, "diagnostics backend is not available") })
}

unsafe fn string_argument(
    ctx: *mut ffi::JSContext,
    argc: i32,
    argv: *mut ffi::JSValue,
    index: usize,
    name: &str,
) -> Result<String, ffi::JSValue> {
    if argc <= index as i32 {
        return Err(throw_internal_error(ctx, format!("{name} is required")));
    }
    let value = JSValue(*argv.add(index));
    if !value.is_string() {
        return Err(throw_internal_error(ctx, format!("{name} must be a string")));
    }
    value
        .to_string(ctx)
        .ok_or_else(|| throw_internal_error(ctx, format!("failed to read {name}")))
}

unsafe fn set_property(ctx: *mut ffi::JSContext, object: ffi::JSValue, name: &str, value: ffi::JSValue) {
    let name = std::ffi::CString::new(name).expect("property name");
    ffi::JS_SetPropertyStr(ctx, object, name.as_ptr(), value);
}

unsafe fn string_or_null(ctx: *mut ffi::JSContext, value: Option<&str>) -> ffi::JSValue {
    value
        .map(|value| JSValue::string(ctx, value).raw())
        .unwrap_or_else(|| JSValue::null().raw())
}

unsafe fn debug_symbol_to_js(ctx: *mut ffi::JSContext, details: DebugSymbolDetails) -> ffi::JSValue {
    let result = ffi::JS_NewObject(ctx);
    set_property(
        ctx,
        result,
        "address",
        create_native_pointer(ctx, details.address).raw(),
    );
    set_property(ctx, result, "name", string_or_null(ctx, details.name.as_deref()));
    set_property(
        ctx,
        result,
        "moduleName",
        string_or_null(ctx, details.module_name.as_deref()),
    );
    set_property(
        ctx,
        result,
        "fileName",
        string_or_null(ctx, details.file_name.as_deref()),
    );
    set_property(
        ctx,
        result,
        "lineNumber",
        details
            .line_number
            .map(|value| ffi::qjs_new_uint32(ctx, value))
            .unwrap_or_else(|| JSValue::null().raw()),
    );
    set_property(
        ctx,
        result,
        "column",
        details
            .column
            .map(|value| ffi::qjs_new_uint32(ctx, value))
            .unwrap_or_else(|| JSValue::null().raw()),
    );
    result
}

unsafe fn pointer_array_to_js(ctx: *mut ffi::JSContext, addresses: Vec<u64>) -> ffi::JSValue {
    let result = ffi::JS_NewArray(ctx);
    for (index, address) in addresses.into_iter().enumerate() {
        if ffi::JS_SetPropertyUint32(ctx, result, index as u32, create_native_pointer(ctx, address).raw()) < 0 {
            ffi::qjs_free_value(ctx, result);
            return ffi::qjs_exception();
        }
    }
    result
}

unsafe extern "C" fn js_debug_symbol_from_address(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return throw_internal_error(ctx, "address is required");
    }
    let address = match extract_pointer_address(ctx, JSValue(*argv), "DebugSymbol.fromAddress") {
        Ok(value) => value,
        Err(error) => return error,
    };
    let backend = match backend_or_throw(ctx) {
        Ok(value) => value,
        Err(error) => return error,
    };
    debug_symbol_to_js(ctx, (backend.debug_symbol_from_address)(address))
}

unsafe extern "C" fn js_debug_symbol_from_name(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let name = match string_argument(ctx, argc, argv, 0, "name") {
        Ok(value) => value,
        Err(error) => return error,
    };
    let backend = match backend_or_throw(ctx) {
        Ok(value) => value,
        Err(error) => return error,
    };
    debug_symbol_to_js(ctx, (backend.debug_symbol_from_name)(&name))
}

unsafe extern "C" fn js_debug_symbol_get_function_by_name(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let name = match string_argument(ctx, argc, argv, 0, "name") {
        Ok(value) => value,
        Err(error) => return error,
    };
    let backend = match backend_or_throw(ctx) {
        Ok(value) => value,
        Err(error) => return error,
    };
    match (backend.debug_symbol_get_function_by_name)(&name) {
        Ok(address) => create_native_pointer(ctx, address).raw(),
        Err(error) => throw_internal_error(ctx, error),
    }
}

unsafe extern "C" fn js_debug_symbol_find_functions_named(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let name = match string_argument(ctx, argc, argv, 0, "name") {
        Ok(value) => value,
        Err(error) => return error,
    };
    let backend = match backend_or_throw(ctx) {
        Ok(value) => value,
        Err(error) => return error,
    };
    pointer_array_to_js(ctx, (backend.debug_symbol_find_functions_named)(&name))
}

unsafe extern "C" fn js_debug_symbol_find_functions_matching(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let pattern = match string_argument(ctx, argc, argv, 0, "pattern") {
        Ok(value) => value,
        Err(error) => return error,
    };
    let backend = match backend_or_throw(ctx) {
        Ok(value) => value,
        Err(error) => return error,
    };
    pointer_array_to_js(ctx, (backend.debug_symbol_find_functions_matching)(&pattern))
}

unsafe extern "C" fn js_debug_symbol_load(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let path = match string_argument(ctx, argc, argv, 0, "path") {
        Ok(value) => value,
        Err(error) => return error,
    };
    let backend = match backend_or_throw(ctx) {
        Ok(value) => value,
        Err(error) => return error,
    };
    match (backend.debug_symbol_load)(&path) {
        Ok(()) => JSValue::undefined().raw(),
        Err(error) => throw_internal_error(ctx, error),
    }
}

unsafe fn get_context_register(ctx: *mut ffi::JSContext, object: ffi::JSValue, name: &str) -> Option<u64> {
    let name = std::ffi::CString::new(name).ok()?;
    let value = JSValue(ffi::JS_GetPropertyStr(ctx, object, name.as_ptr()));
    let result = if value.is_undefined() || value.is_null() {
        None
    } else {
        get_native_pointer_addr(ctx, value).or_else(|| value.to_u64(ctx))
    };
    value.free(ctx);
    result
}

unsafe fn parse_cpu_context(
    ctx: *mut ffi::JSContext,
    value: JSValue,
) -> Result<Option<DiagnosticsCpuContext>, ffi::JSValue> {
    if value.is_null() || value.is_undefined() {
        return Ok(None);
    }
    if !value.is_object() {
        return Err(throw_internal_error(ctx, "cpuContext must be an object or null"));
    }

    let mut result = DiagnosticsCpuContext::default();
    result.pc = get_context_register(ctx, value.raw(), "pc").unwrap_or(0);
    result.sp = get_context_register(ctx, value.raw(), "sp").unwrap_or(0);
    result.nzcv = get_context_register(ctx, value.raw(), "nzcv").unwrap_or(0);
    for index in 0..29 {
        result.x[index] = get_context_register(ctx, value.raw(), &format!("x{index}")).unwrap_or(0);
    }
    result.fp = get_context_register(ctx, value.raw(), "fp")
        .or_else(|| get_context_register(ctx, value.raw(), "x29"))
        .unwrap_or(0);
    result.lr = get_context_register(ctx, value.raw(), "lr")
        .or_else(|| get_context_register(ctx, value.raw(), "x30"))
        .unwrap_or(0);
    Ok(Some(result))
}

unsafe extern "C" fn js_thread_backtrace(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let context_value = if argc >= 1 { JSValue(*argv) } else { JSValue::null() };
    let cpu_context = match parse_cpu_context(ctx, context_value) {
        Ok(value) => value,
        Err(error) => return error,
    };
    let backtracer = if argc >= 2 {
        match JSValue(*argv.add(1)).to_i64(ctx) {
            Some(value) if value == 1 || value == 2 => value as u32,
            _ => return throw_internal_error(ctx, "invalid backtracer enum value"),
        }
    } else {
        1
    };
    let limit = if argc >= 3 {
        match JSValue(*argv.add(2))
            .to_u64(ctx)
            .and_then(|value| usize::try_from(value).ok())
        {
            Some(value) => value,
            None => return throw_internal_error(ctx, "backtrace limit must be an unsigned integer"),
        }
    } else {
        0
    };
    let backend = match backend_or_throw(ctx) {
        Ok(value) => value,
        Err(error) => return error,
    };
    match (backend.backtrace)(cpu_context.as_ref(), backtracer, limit) {
        Ok(addresses) => pointer_array_to_js(ctx, addresses),
        Err(error) => throw_internal_error(ctx, error),
    }
}

unsafe fn string_array_to_js(ctx: *mut ffi::JSContext, values: Vec<String>) -> ffi::JSValue {
    let result = ffi::JS_NewArray(ctx);
    for (index, value) in values.into_iter().enumerate() {
        if ffi::JS_SetPropertyUint32(ctx, result, index as u32, JSValue::string(ctx, &value).raw()) < 0 {
            ffi::qjs_free_value(ctx, result);
            return ffi::qjs_exception();
        }
    }
    result
}

unsafe fn memory_operand_to_js(ctx: *mut ffi::JSContext, memory: InstructionMemoryOperand) -> ffi::JSValue {
    let result = ffi::JS_NewObject(ctx);
    if let Some(base) = memory.base {
        set_property(ctx, result, "base", JSValue::string(ctx, &base).raw());
    }
    if let Some(index) = memory.index {
        set_property(ctx, result, "index", JSValue::string(ctx, &index).raw());
    }
    set_property(ctx, result, "disp", JSValue::int(memory.displacement).raw());
    result
}

unsafe fn instruction_operand_to_js(ctx: *mut ffi::JSContext, operand: InstructionOperand) -> ffi::JSValue {
    let result = ffi::JS_NewObject(ctx);
    set_property(ctx, result, "type", JSValue::string(ctx, &operand.kind).raw());
    let value = match operand.value {
        InstructionOperandValue::Register(value) => JSValue::string(ctx, &value).raw(),
        InstructionOperandValue::Immediate(value) => ffi::JS_NewBigInt64(ctx, value),
        InstructionOperandValue::Memory(value) => memory_operand_to_js(ctx, value),
        InstructionOperandValue::Float(value) => ffi::qjs_new_float64(ctx, value),
        InstructionOperandValue::Integer(value) => ffi::qjs_new_int64(ctx, value),
    };
    set_property(ctx, result, "value", value);
    if let Some(shift) = operand.shift {
        let shift_object = ffi::JS_NewObject(ctx);
        set_property(ctx, shift_object, "type", JSValue::string(ctx, &shift.kind).raw());
        set_property(ctx, shift_object, "value", ffi::qjs_new_uint32(ctx, shift.value));
        set_property(ctx, result, "shift", shift_object);
    }
    if let Some(ext) = operand.ext {
        set_property(ctx, result, "ext", JSValue::string(ctx, &ext).raw());
    }
    if let Some(vas) = operand.vas {
        set_property(ctx, result, "vas", JSValue::string(ctx, &vas).raw());
    }
    if let Some(vector_index) = operand.vector_index {
        set_property(ctx, result, "vectorIndex", JSValue::int(vector_index).raw());
    }
    set_property(ctx, result, "access", JSValue::string(ctx, &operand.access).raw());
    result
}

unsafe fn instruction_to_js(ctx: *mut ffi::JSContext, details: InstructionDetails) -> ffi::JSValue {
    let result = ffi::JS_NewObject(ctx);
    set_property(
        ctx,
        result,
        "address",
        create_native_pointer(ctx, details.address).raw(),
    );
    set_property(ctx, result, "next", create_native_pointer(ctx, details.next).raw());
    set_property(ctx, result, "size", ffi::qjs_new_uint32(ctx, details.size));
    set_property(ctx, result, "mnemonic", JSValue::string(ctx, &details.mnemonic).raw());
    set_property(ctx, result, "opStr", JSValue::string(ctx, &details.op_str).raw());

    let operands = ffi::JS_NewArray(ctx);
    for (index, operand) in details.operands.into_iter().enumerate() {
        if ffi::JS_SetPropertyUint32(ctx, operands, index as u32, instruction_operand_to_js(ctx, operand)) < 0 {
            ffi::qjs_free_value(ctx, operands);
            ffi::qjs_free_value(ctx, result);
            return ffi::qjs_exception();
        }
    }
    set_property(ctx, result, "operands", operands);

    let regs_accessed = ffi::JS_NewObject(ctx);
    set_property(
        ctx,
        regs_accessed,
        "read",
        string_array_to_js(ctx, details.regs_accessed_read),
    );
    set_property(
        ctx,
        regs_accessed,
        "written",
        string_array_to_js(ctx, details.regs_accessed_written),
    );
    set_property(ctx, result, "regsAccessed", regs_accessed);
    set_property(ctx, result, "regsRead", string_array_to_js(ctx, details.regs_read));
    set_property(
        ctx,
        result,
        "regsWritten",
        string_array_to_js(ctx, details.regs_written),
    );
    set_property(ctx, result, "groups", string_array_to_js(ctx, details.groups));
    result
}

unsafe extern "C" fn js_instruction_parse(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return throw_internal_error(ctx, "address is required");
    }
    let address = match extract_pointer_address(ctx, JSValue(*argv), "Instruction.parse") {
        Ok(value) => value,
        Err(error) => return error,
    };
    let address = crate::jsapi::util::canonicalize_user_address(address);
    let mut bytes = [0u8; 4];
    if let Err(error) = crate::jsapi::memory::safe_read_exact(address, &mut bytes) {
        return throw_internal_error(ctx, format!("unable to read instruction at 0x{address:x}: {error}"));
    }
    let backend = match backend_or_throw(ctx) {
        Ok(value) => value,
        Err(error) => return error,
    };
    match (backend.parse_instruction)(address, &bytes) {
        Ok(details) => instruction_to_js(ctx, details),
        Err(error) => throw_internal_error(ctx, error),
    }
}

unsafe extern "C" fn js_api_resolver_enumerate_matches(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let query = match string_argument(ctx, argc, argv, 0, "query") {
        Ok(value) => value,
        Err(error) => return error,
    };
    let backend = match backend_or_throw(ctx) {
        Ok(value) => value,
        Err(error) => return error,
    };
    let matches = match (backend.enumerate_module_api_matches)(&query) {
        Ok(value) => value,
        Err(error) => return throw_internal_error(ctx, error),
    };
    let result = ffi::JS_NewArray(ctx);
    for (index, entry) in matches.into_iter().enumerate() {
        let object = ffi::JS_NewObject(ctx);
        set_property(ctx, object, "name", JSValue::string(ctx, &entry.name).raw());
        set_property(ctx, object, "address", create_native_pointer(ctx, entry.address).raw());
        if let Some(size) = entry.size {
            set_property(ctx, object, "size", ffi::qjs_new_uint32(ctx, size));
        }
        if ffi::JS_SetPropertyUint32(ctx, result, index as u32, object) < 0 {
            ffi::qjs_free_value(ctx, result);
            return ffi::qjs_exception();
        }
    }
    result
}

pub fn register_diagnostics_api(ctx: &JSContext) {
    let global = ctx.global_object();
    unsafe {
        let raw = global.raw();
        add_cfunction_to_object(
            ctx.as_ptr(),
            raw,
            "__rf_debug_symbol_from_address",
            js_debug_symbol_from_address,
            1,
        );
        add_cfunction_to_object(
            ctx.as_ptr(),
            raw,
            "__rf_debug_symbol_from_name",
            js_debug_symbol_from_name,
            1,
        );
        add_cfunction_to_object(
            ctx.as_ptr(),
            raw,
            "__rf_debug_symbol_get_function_by_name",
            js_debug_symbol_get_function_by_name,
            1,
        );
        add_cfunction_to_object(
            ctx.as_ptr(),
            raw,
            "__rf_debug_symbol_find_functions_named",
            js_debug_symbol_find_functions_named,
            1,
        );
        add_cfunction_to_object(
            ctx.as_ptr(),
            raw,
            "__rf_debug_symbol_find_functions_matching",
            js_debug_symbol_find_functions_matching,
            1,
        );
        add_cfunction_to_object(ctx.as_ptr(), raw, "__rf_debug_symbol_load", js_debug_symbol_load, 1);
        add_cfunction_to_object(ctx.as_ptr(), raw, "__rf_thread_backtrace", js_thread_backtrace, 3);
        add_cfunction_to_object(ctx.as_ptr(), raw, "__rf_instruction_parse", js_instruction_parse, 1);
        add_cfunction_to_object(
            ctx.as_ptr(),
            raw,
            "__rf_api_resolver_enumerate_matches",
            js_api_resolver_enumerate_matches,
            1,
        );
    }
    global.free(ctx.as_ptr());

    match ctx.eval(include_str!("diagnostics_boot.js"), "<diagnostics_boot>") {
        Ok(value) => value.free(ctx.as_ptr()),
        Err(error) => crate::jsapi::console::output_message(&format!("[diagnostics] bootstrap failed: {error}")),
    }
}
