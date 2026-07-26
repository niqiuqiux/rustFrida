//! Gum-backed implementation of the QuickJS diagnostics facade.

use frida_gum_sys as gum_sys;
use quickjs_hook::{
    ApiResolverMatch, DebugSymbolDetails, DiagnosticsBackend, DiagnosticsCpuContext, InstructionDetails,
    InstructionMemoryOperand, InstructionOperand, InstructionOperandValue, InstructionShift,
};
use std::ffi::{CStr, CString};
use std::mem::MaybeUninit;
use std::ptr::{null, null_mut};

fn c_string(value: &str, label: &str) -> Result<CString, String> {
    CString::new(value).map_err(|_| format!("{label} contains a NUL byte"))
}

unsafe fn fixed_c_string(value: *const gum_sys::gchar) -> String {
    CStr::from_ptr(value).to_string_lossy().into_owned()
}

fn option_nonempty(value: String) -> Option<String> {
    (!value.is_empty()).then_some(value)
}

fn is_offset_placeholder(value: &str) -> bool {
    value
        .strip_prefix("0x")
        .is_some_and(|digits| !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn debug_symbol_from_address(address: u64) -> DebugSymbolDetails {
    let fallback = crate::linker::resolve_symbol(address as usize);
    let mut raw = MaybeUninit::<gum_sys::GumDebugSymbolDetails>::zeroed();
    let resolved =
        unsafe { gum_sys::gum_symbol_details_from_address(address as usize as *mut _, raw.as_mut_ptr()) != 0 };
    if resolved {
        let raw = unsafe { raw.assume_init() };
        let mut name = option_nonempty(unsafe { fixed_c_string(raw.symbol_name.as_ptr()) });
        if name.as_deref().is_none_or(is_offset_placeholder) && fallback.symbol.is_some() {
            name = fallback.symbol;
        }
        return DebugSymbolDetails {
            address: raw.address,
            name,
            module_name: option_nonempty(unsafe { fixed_c_string(raw.module_name.as_ptr()) }).or(fallback.module),
            file_name: option_nonempty(unsafe { fixed_c_string(raw.file_name.as_ptr()) }),
            line_number: Some(raw.line_number),
            column: Some(raw.column),
        };
    }

    if fallback.symbol.is_some() {
        DebugSymbolDetails {
            address,
            name: fallback.symbol,
            module_name: fallback.module,
            file_name: None,
            line_number: None,
            column: None,
        }
    } else {
        DebugSymbolDetails {
            address,
            ..DebugSymbolDetails::default()
        }
    }
}

fn find_function(name: &str) -> Option<u64> {
    let addresses = function_array(name, false);
    addresses
        .iter()
        .copied()
        .find(|address| debug_symbol_from_address(*address).name.as_deref() == Some(name))
        .or_else(|| addresses.into_iter().next())
}

fn debug_symbol_from_name(name: &str) -> DebugSymbolDetails {
    find_function(name).map(debug_symbol_from_address).unwrap_or_default()
}

fn debug_symbol_get_function_by_name(name: &str) -> Result<u64, String> {
    find_function(name).ok_or_else(|| format!("unable to find function with name '{name}'"))
}

fn function_array(pattern: &str, matching: bool) -> Vec<u64> {
    let Ok(pattern) = c_string(pattern, "function name") else {
        return Vec::new();
    };
    let array = unsafe {
        if matching {
            gum_sys::gum_find_functions_matching(pattern.as_ptr())
        } else {
            gum_sys::gum_find_functions_named(pattern.as_ptr())
        }
    };
    let mut result = if array.is_null() {
        Vec::new()
    } else {
        let result = unsafe {
            let array_ref = &*array;
            let items =
                std::slice::from_raw_parts(array_ref.data as *const *mut std::ffi::c_void, array_ref.len as usize);
            items
                .iter()
                .map(|address| *address as usize as u64)
                .filter(|address| crate::linker::is_address_mapped(*address as usize))
                .collect()
        };
        unsafe {
            gum_sys::_frida_g_array_free(array, 1);
        }
        result
    };
    for address in quickjs_hook::find_loaded_function_addresses(pattern.to_str().unwrap_or_default(), matching) {
        if !result.contains(&address) {
            result.push(address);
        }
    }
    result.sort_unstable();
    result
}

fn debug_symbol_find_functions_named(name: &str) -> Vec<u64> {
    function_array(name, false)
}

fn debug_symbol_find_functions_matching(pattern: &str) -> Vec<u64> {
    function_array(pattern, true)
}

fn debug_symbol_load(path: &str) -> Result<(), String> {
    let path = c_string(path, "symbol path")?;
    if unsafe { gum_sys::gum_load_symbols(path.as_ptr()) } != 0 {
        Ok(())
    } else {
        Err("unable to load symbols".to_string())
    }
}

fn backtrace(context: Option<&DiagnosticsCpuContext>, kind: u32, limit: usize) -> Result<Vec<u64>, String> {
    let backtracer = unsafe {
        match kind {
            1 => gum_sys::gum_backtracer_make_accurate(),
            2 => gum_sys::gum_backtracer_make_fuzzy(),
            _ => return Err("invalid backtracer enum value".to_string()),
        }
    };
    if backtracer.is_null() {
        let alternative = if kind == 1 { "FUZZY" } else { "ACCURATE" };
        return Err(format!(
            "backtracer not yet available for this platform; please try Thread.backtrace(context, Backtracer.{alternative})"
        ));
    }

    let mut gum_context = context.map(|context| unsafe {
        let mut result = MaybeUninit::<gum_sys::GumCpuContext>::zeroed().assume_init();
        result.pc = context.pc;
        result.sp = context.sp;
        result.nzcv = context.nzcv;
        result.x = context.x;
        result.fp = context.fp;
        result.lr = context.lr;
        result
    });
    let context_ptr = gum_context
        .as_mut()
        .map(|context| context as *mut gum_sys::GumCpuContext as *const gum_sys::GumCpuContext)
        .unwrap_or(null());
    let mut addresses = MaybeUninit::<gum_sys::GumReturnAddressArray>::uninit();
    unsafe {
        if limit == 0 {
            gum_sys::gum_backtracer_generate(backtracer, context_ptr, addresses.as_mut_ptr());
        } else {
            gum_sys::gum_backtracer_generate_with_limit(
                backtracer,
                context_ptr,
                addresses.as_mut_ptr(),
                limit.min(16) as u32,
            );
        }
        gum_sys::g_object_unref(backtracer as *mut _);
    }

    let addresses = unsafe { addresses.assume_init() };
    Ok(addresses.items[..(addresses.len as usize).min(addresses.items.len())]
        .iter()
        .map(|address| *address as usize as u64)
        .collect())
}

struct Capstone(gum_sys::csh);

impl Capstone {
    fn new() -> Result<Self, String> {
        unsafe {
            gum_sys::_frida_cs_arch_register_arm64();
        }
        let mut handle = 0;
        let error = unsafe {
            gum_sys::_frida_cs_open(
                gum_sys::cs_arch_CS_ARCH_ARM64,
                gum_sys::cs_mode_CS_MODE_LITTLE_ENDIAN,
                &mut handle,
            )
        };
        if error != gum_sys::cs_err_CS_ERR_OK {
            return Err(format!(
                "unable to initialize ARM64 disassembler: Capstone error {error}"
            ));
        }
        let error = unsafe {
            gum_sys::_frida_cs_option(
                handle,
                gum_sys::cs_opt_type_CS_OPT_DETAIL,
                gum_sys::cs_opt_value_CS_OPT_ON as usize,
            )
        };
        if error != gum_sys::cs_err_CS_ERR_OK {
            unsafe {
                gum_sys::_frida_cs_close(&mut handle);
            }
            return Err(format!(
                "unable to enable ARM64 instruction details: Capstone error {error}"
            ));
        }
        Ok(Self(handle))
    }

    unsafe fn name_from_ptr(value: *const std::ffi::c_char) -> String {
        if value.is_null() {
            String::new()
        } else {
            CStr::from_ptr(value).to_string_lossy().into_owned()
        }
    }

    unsafe fn register_name(&self, register: u32) -> String {
        Self::name_from_ptr(gum_sys::_frida_cs_reg_name(self.0, register))
    }

    unsafe fn group_name(&self, group: u8) -> String {
        Self::name_from_ptr(gum_sys::_frida_cs_group_name(self.0, group as u32))
    }
}

impl Drop for Capstone {
    fn drop(&mut self) {
        unsafe {
            gum_sys::_frida_cs_close(&mut self.0);
        }
    }
}

fn access_name(access: u8) -> String {
    match access {
        value if value == gum_sys::cs_ac_type_CS_AC_INVALID as u8 => "",
        value if value == gum_sys::cs_ac_type_CS_AC_READ as u8 => "r",
        value if value == gum_sys::cs_ac_type_CS_AC_WRITE as u8 => "w",
        value if value == (gum_sys::cs_ac_type_CS_AC_READ | gum_sys::cs_ac_type_CS_AC_WRITE) as u8 => "rw",
        _ => "",
    }
    .to_string()
}

fn shift_name(kind: gum_sys::arm64_shifter) -> Option<&'static str> {
    match kind {
        gum_sys::arm64_shifter_ARM64_SFT_LSL => Some("lsl"),
        gum_sys::arm64_shifter_ARM64_SFT_MSL => Some("msl"),
        gum_sys::arm64_shifter_ARM64_SFT_LSR => Some("lsr"),
        gum_sys::arm64_shifter_ARM64_SFT_ASR => Some("asr"),
        gum_sys::arm64_shifter_ARM64_SFT_ROR => Some("ror"),
        _ => None,
    }
}

fn extender_name(ext: gum_sys::arm64_extender) -> Option<&'static str> {
    match ext {
        gum_sys::arm64_extender_ARM64_EXT_UXTB => Some("uxtb"),
        gum_sys::arm64_extender_ARM64_EXT_UXTH => Some("uxth"),
        gum_sys::arm64_extender_ARM64_EXT_UXTW => Some("uxtw"),
        gum_sys::arm64_extender_ARM64_EXT_UXTX => Some("uxtx"),
        gum_sys::arm64_extender_ARM64_EXT_SXTB => Some("sxtb"),
        gum_sys::arm64_extender_ARM64_EXT_SXTH => Some("sxth"),
        gum_sys::arm64_extender_ARM64_EXT_SXTW => Some("sxtw"),
        gum_sys::arm64_extender_ARM64_EXT_SXTX => Some("sxtx"),
        _ => None,
    }
}

fn vas_name(vas: gum_sys::arm64_vas) -> Option<&'static str> {
    match vas {
        gum_sys::arm64_vas_ARM64_VAS_16B => Some("16b"),
        gum_sys::arm64_vas_ARM64_VAS_8B => Some("8b"),
        gum_sys::arm64_vas_ARM64_VAS_4B => Some("4b"),
        gum_sys::arm64_vas_ARM64_VAS_1B => Some("1b"),
        gum_sys::arm64_vas_ARM64_VAS_8H => Some("8h"),
        gum_sys::arm64_vas_ARM64_VAS_4H => Some("4h"),
        gum_sys::arm64_vas_ARM64_VAS_2H => Some("2h"),
        gum_sys::arm64_vas_ARM64_VAS_1H => Some("1h"),
        gum_sys::arm64_vas_ARM64_VAS_4S => Some("4s"),
        gum_sys::arm64_vas_ARM64_VAS_2S => Some("2s"),
        gum_sys::arm64_vas_ARM64_VAS_1S => Some("1s"),
        gum_sys::arm64_vas_ARM64_VAS_2D => Some("2d"),
        gum_sys::arm64_vas_ARM64_VAS_1D => Some("1d"),
        gum_sys::arm64_vas_ARM64_VAS_1Q => Some("1q"),
        _ => None,
    }
}

unsafe fn parse_operand(capstone: &Capstone, operand: &gum_sys::cs_arm64_op) -> Option<InstructionOperand> {
    let (kind, value) = match operand.type_ {
        gum_sys::arm64_op_type_ARM64_OP_REG => (
            "reg",
            InstructionOperandValue::Register(capstone.register_name(operand.__bindgen_anon_1.reg)),
        ),
        gum_sys::arm64_op_type_ARM64_OP_IMM => {
            ("imm", InstructionOperandValue::Immediate(operand.__bindgen_anon_1.imm))
        }
        gum_sys::arm64_op_type_ARM64_OP_MEM => {
            let memory = operand.__bindgen_anon_1.mem;
            (
                "mem",
                InstructionOperandValue::Memory(InstructionMemoryOperand {
                    base: (memory.base != 0).then(|| capstone.register_name(memory.base)),
                    index: (memory.index != 0).then(|| capstone.register_name(memory.index)),
                    displacement: memory.disp,
                }),
            )
        }
        gum_sys::arm64_op_type_ARM64_OP_FP => ("fp", InstructionOperandValue::Float(operand.__bindgen_anon_1.fp)),
        gum_sys::arm64_op_type_ARM64_OP_CIMM => {
            ("cimm", InstructionOperandValue::Immediate(operand.__bindgen_anon_1.imm))
        }
        gum_sys::arm64_op_type_ARM64_OP_REG_MRS => (
            "reg-mrs",
            InstructionOperandValue::Register(capstone.register_name(operand.__bindgen_anon_1.reg)),
        ),
        gum_sys::arm64_op_type_ARM64_OP_REG_MSR => (
            "reg-msr",
            InstructionOperandValue::Register(capstone.register_name(operand.__bindgen_anon_1.reg)),
        ),
        gum_sys::arm64_op_type_ARM64_OP_PSTATE => (
            "pstate",
            InstructionOperandValue::Integer(operand.__bindgen_anon_1.pstate as i64),
        ),
        gum_sys::arm64_op_type_ARM64_OP_SYS => (
            "sys",
            InstructionOperandValue::Integer(operand.__bindgen_anon_1.sys as i64),
        ),
        gum_sys::arm64_op_type_ARM64_OP_PREFETCH => (
            "prefetch",
            InstructionOperandValue::Integer(operand.__bindgen_anon_1.prefetch as i64),
        ),
        gum_sys::arm64_op_type_ARM64_OP_BARRIER => (
            "barrier",
            InstructionOperandValue::Integer(operand.__bindgen_anon_1.barrier as i64),
        ),
        gum_sys::arm64_op_type_ARM64_OP_SVCR => ("svcr", InstructionOperandValue::Integer(operand.svcr as i64)),
        gum_sys::arm64_op_type_ARM64_OP_SME_INDEX => {
            let index = operand.__bindgen_anon_1.sme_index;
            (
                "sme-index",
                InstructionOperandValue::Memory(InstructionMemoryOperand {
                    base: (index.reg != 0).then(|| capstone.register_name(index.reg)),
                    index: (index.base != 0).then(|| capstone.register_name(index.base)),
                    displacement: index.disp,
                }),
            )
        }
        _ => return None,
    };

    Some(InstructionOperand {
        kind: kind.to_string(),
        value,
        shift: shift_name(operand.shift.type_).map(|kind| InstructionShift {
            kind: kind.to_string(),
            value: operand.shift.value,
        }),
        ext: extender_name(operand.ext).map(str::to_string),
        vas: vas_name(operand.vas).map(str::to_string),
        vector_index: (operand.vector_index != -1).then_some(operand.vector_index),
        access: access_name(operand.access),
    })
}

unsafe fn register_names(capstone: &Capstone, registers: &[u16]) -> Vec<String> {
    registers
        .iter()
        .map(|register| capstone.register_name(*register as u32))
        .collect()
}

fn parse_instruction(address: u64, bytes: &[u8]) -> Result<InstructionDetails, String> {
    let capstone = Capstone::new()?;
    let mut instruction = null_mut();
    let count =
        unsafe { gum_sys::_frida_cs_disasm(capstone.0, bytes.as_ptr(), bytes.len(), address, 1, &mut instruction) };
    if count == 0 || instruction.is_null() {
        return Err("invalid instruction".to_string());
    }

    let result = unsafe {
        let instruction_ref = &*instruction;
        if instruction_ref.detail.is_null() {
            Err("ARM64 instruction details are unavailable".to_string())
        } else {
            let detail = &*instruction_ref.detail;
            let arm64 = detail.__bindgen_anon_1.arm64;
            let operands = arm64.operands[..(arm64.op_count as usize).min(arm64.operands.len())]
                .iter()
                .filter_map(|operand| parse_operand(&capstone, operand))
                .collect();

            let mut accessed_read = [0u16; 64];
            let mut accessed_written = [0u16; 64];
            let mut accessed_read_count = 0u8;
            let mut accessed_written_count = 0u8;
            let access_error = gum_sys::_frida_cs_regs_access(
                capstone.0,
                instruction_ref,
                accessed_read.as_mut_ptr(),
                &mut accessed_read_count,
                accessed_written.as_mut_ptr(),
                &mut accessed_written_count,
            );
            if access_error != gum_sys::cs_err_CS_ERR_OK {
                Err(format!(
                    "unable to compute ARM64 register access: Capstone error {access_error}"
                ))
            } else {
                Ok(InstructionDetails {
                    address: instruction_ref.address,
                    next: address.wrapping_add(instruction_ref.size as u64),
                    size: instruction_ref.size as u32,
                    mnemonic: CStr::from_ptr(instruction_ref.mnemonic.as_ptr())
                        .to_string_lossy()
                        .into_owned(),
                    op_str: CStr::from_ptr(instruction_ref.op_str.as_ptr())
                        .to_string_lossy()
                        .into_owned(),
                    operands,
                    regs_accessed_read: register_names(
                        &capstone,
                        &accessed_read[..(accessed_read_count as usize).min(accessed_read.len())],
                    ),
                    regs_accessed_written: register_names(
                        &capstone,
                        &accessed_written[..(accessed_written_count as usize).min(accessed_written.len())],
                    ),
                    regs_read: register_names(
                        &capstone,
                        &detail.regs_read[..(detail.regs_read_count as usize).min(detail.regs_read.len())],
                    ),
                    regs_written: register_names(
                        &capstone,
                        &detail.regs_write[..(detail.regs_write_count as usize).min(detail.regs_write.len())],
                    ),
                    groups: detail.groups[..(detail.groups_count as usize).min(detail.groups.len())]
                        .iter()
                        .map(|group| capstone.group_name(*group))
                        .collect(),
                })
            }
        }
    };
    unsafe {
        gum_sys::_frida_cs_free(instruction, count);
    }
    result
}

unsafe extern "C" fn collect_api_match(
    details: *const gum_sys::GumApiDetails,
    user_data: gum_sys::gpointer,
) -> gum_sys::gboolean {
    if details.is_null() || user_data.is_null() {
        return 0;
    }
    let details = &*details;
    let matches = &mut *(user_data as *mut Vec<ApiResolverMatch>);
    matches.push(ApiResolverMatch {
        name: fixed_c_string(details.name),
        address: details.address,
        size: (details.size >= 0).then(|| u32::try_from(details.size).ok()).flatten(),
    });
    1
}

fn enumerate_module_api_matches(query: &str) -> Result<Vec<ApiResolverMatch>, String> {
    let kind = c_string("module", "ApiResolver type")?;
    let resolver = unsafe { gum_sys::gum_api_resolver_make(kind.as_ptr()) };
    if resolver.is_null() {
        return Err("the module ApiResolver is not available".to_string());
    }
    let query = match c_string(query, "ApiResolver query") {
        Ok(value) => value,
        Err(error) => {
            unsafe { gum_sys::g_object_unref(resolver as *mut _) };
            return Err(error);
        }
    };

    let mut matches = Vec::new();
    let mut error = null_mut();
    unsafe {
        gum_sys::gum_api_resolver_enumerate_matches(
            resolver,
            query.as_ptr(),
            Some(collect_api_match),
            &mut matches as *mut Vec<ApiResolverMatch> as *mut _,
            &mut error,
        );
        gum_sys::g_object_unref(resolver as *mut _);
    }
    if error.is_null() {
        Ok(matches)
    } else {
        let message = unsafe {
            let value =
                option_nonempty(fixed_c_string((*error).message)).unwrap_or_else(|| "invalid module query".to_string());
            gum_sys::_frida_g_error_free(error);
            value
        };
        Err(message)
    }
}

pub fn install_quickjs_backend() {
    quickjs_hook::install_diagnostics_backend(DiagnosticsBackend {
        debug_symbol_from_address,
        debug_symbol_from_name,
        debug_symbol_get_function_by_name,
        debug_symbol_find_functions_named,
        debug_symbol_find_functions_matching,
        debug_symbol_load,
        backtrace,
        parse_instruction,
        enumerate_module_api_matches,
    });
}
