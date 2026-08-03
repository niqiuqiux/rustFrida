//! Gum-backed implementation of the ARM64 writer and relocator opcodes that the
//! QuickJS facade exposes on a Stalker transform iterator.
//!
//! The opcode numbering and argument specs live in
//! `quickjs_hook::jsapi::stalker_writer`, so every arm below references the
//! generated constant rather than a literal. Arguments arrive as a flat `u64`
//! slice validated against the same spec before dispatch.

use frida_gum_sys as gum_sys;
use quickjs_hook::stalker_writer as spec;
use quickjs_hook::StalkerWriterEnums;
use std::ffi::c_void;

/// Argument kinds accepted by `putCallAddressWithArguments` and friends.
const ARG_KIND_REGISTER: u64 = 0;
const ARG_KIND_ADDRESS: u64 = 1;

/// Register, condition and index-mode names accepted by the JavaScript API.
///
/// The lists mirror upstream `writer_enums["arm64"]` in
/// `frida-gum/bindings/gumjs/generate-bindings.py`, so a script written against
/// Frida's `Arm64Writer` keeps working unchanged.
pub fn writer_enums() -> StalkerWriterEnums {
    let mut registers: Vec<(String, u32)> = Vec::with_capacity(160);

    let x_registers = [
        gum_sys::arm64_reg_ARM64_REG_X0,
        gum_sys::arm64_reg_ARM64_REG_X1,
        gum_sys::arm64_reg_ARM64_REG_X2,
        gum_sys::arm64_reg_ARM64_REG_X3,
        gum_sys::arm64_reg_ARM64_REG_X4,
        gum_sys::arm64_reg_ARM64_REG_X5,
        gum_sys::arm64_reg_ARM64_REG_X6,
        gum_sys::arm64_reg_ARM64_REG_X7,
        gum_sys::arm64_reg_ARM64_REG_X8,
        gum_sys::arm64_reg_ARM64_REG_X9,
        gum_sys::arm64_reg_ARM64_REG_X10,
        gum_sys::arm64_reg_ARM64_REG_X11,
        gum_sys::arm64_reg_ARM64_REG_X12,
        gum_sys::arm64_reg_ARM64_REG_X13,
        gum_sys::arm64_reg_ARM64_REG_X14,
        gum_sys::arm64_reg_ARM64_REG_X15,
        gum_sys::arm64_reg_ARM64_REG_X16,
        gum_sys::arm64_reg_ARM64_REG_X17,
        gum_sys::arm64_reg_ARM64_REG_X18,
        gum_sys::arm64_reg_ARM64_REG_X19,
        gum_sys::arm64_reg_ARM64_REG_X20,
        gum_sys::arm64_reg_ARM64_REG_X21,
        gum_sys::arm64_reg_ARM64_REG_X22,
        gum_sys::arm64_reg_ARM64_REG_X23,
        gum_sys::arm64_reg_ARM64_REG_X24,
        gum_sys::arm64_reg_ARM64_REG_X25,
        gum_sys::arm64_reg_ARM64_REG_X26,
        gum_sys::arm64_reg_ARM64_REG_X27,
        gum_sys::arm64_reg_ARM64_REG_X28,
        gum_sys::arm64_reg_ARM64_REG_X29,
        gum_sys::arm64_reg_ARM64_REG_X30,
    ];
    for (index, value) in x_registers.iter().enumerate() {
        registers.push((format!("x{index}"), *value as u32));
    }

    let w_registers = [
        gum_sys::arm64_reg_ARM64_REG_W0,
        gum_sys::arm64_reg_ARM64_REG_W1,
        gum_sys::arm64_reg_ARM64_REG_W2,
        gum_sys::arm64_reg_ARM64_REG_W3,
        gum_sys::arm64_reg_ARM64_REG_W4,
        gum_sys::arm64_reg_ARM64_REG_W5,
        gum_sys::arm64_reg_ARM64_REG_W6,
        gum_sys::arm64_reg_ARM64_REG_W7,
        gum_sys::arm64_reg_ARM64_REG_W8,
        gum_sys::arm64_reg_ARM64_REG_W9,
        gum_sys::arm64_reg_ARM64_REG_W10,
        gum_sys::arm64_reg_ARM64_REG_W11,
        gum_sys::arm64_reg_ARM64_REG_W12,
        gum_sys::arm64_reg_ARM64_REG_W13,
        gum_sys::arm64_reg_ARM64_REG_W14,
        gum_sys::arm64_reg_ARM64_REG_W15,
        gum_sys::arm64_reg_ARM64_REG_W16,
        gum_sys::arm64_reg_ARM64_REG_W17,
        gum_sys::arm64_reg_ARM64_REG_W18,
        gum_sys::arm64_reg_ARM64_REG_W19,
        gum_sys::arm64_reg_ARM64_REG_W20,
        gum_sys::arm64_reg_ARM64_REG_W21,
        gum_sys::arm64_reg_ARM64_REG_W22,
        gum_sys::arm64_reg_ARM64_REG_W23,
        gum_sys::arm64_reg_ARM64_REG_W24,
        gum_sys::arm64_reg_ARM64_REG_W25,
        gum_sys::arm64_reg_ARM64_REG_W26,
        gum_sys::arm64_reg_ARM64_REG_W27,
        gum_sys::arm64_reg_ARM64_REG_W28,
        gum_sys::arm64_reg_ARM64_REG_W29,
        gum_sys::arm64_reg_ARM64_REG_W30,
    ];
    for (index, value) in w_registers.iter().enumerate() {
        registers.push((format!("w{index}"), *value as u32));
    }

    for (name, value) in [
        ("sp", gum_sys::arm64_reg_ARM64_REG_SP),
        ("lr", gum_sys::arm64_reg_ARM64_REG_LR),
        ("fp", gum_sys::arm64_reg_ARM64_REG_FP),
        ("wsp", gum_sys::arm64_reg_ARM64_REG_WSP),
        ("wzr", gum_sys::arm64_reg_ARM64_REG_WZR),
        ("xzr", gum_sys::arm64_reg_ARM64_REG_XZR),
        ("nzcv", gum_sys::arm64_reg_ARM64_REG_NZCV),
        ("ip0", gum_sys::arm64_reg_ARM64_REG_IP0),
        ("ip1", gum_sys::arm64_reg_ARM64_REG_IP1),
    ] {
        registers.push((name.to_string(), value as u32));
    }

    // Capstone numbers the S/D/Q banks contiguously, so the first element of
    // each bank plus the index is the register the name refers to.
    for index in 0..32u32 {
        registers.push((format!("s{index}"), gum_sys::arm64_reg_ARM64_REG_S0 as u32 + index));
        registers.push((format!("d{index}"), gum_sys::arm64_reg_ARM64_REG_D0 as u32 + index));
        registers.push((format!("q{index}"), gum_sys::arm64_reg_ARM64_REG_Q0 as u32 + index));
    }

    let conditions = [
        ("eq", gum_sys::arm64_cc_ARM64_CC_EQ),
        ("ne", gum_sys::arm64_cc_ARM64_CC_NE),
        ("hs", gum_sys::arm64_cc_ARM64_CC_HS),
        ("lo", gum_sys::arm64_cc_ARM64_CC_LO),
        ("mi", gum_sys::arm64_cc_ARM64_CC_MI),
        ("pl", gum_sys::arm64_cc_ARM64_CC_PL),
        ("vs", gum_sys::arm64_cc_ARM64_CC_VS),
        ("vc", gum_sys::arm64_cc_ARM64_CC_VC),
        ("hi", gum_sys::arm64_cc_ARM64_CC_HI),
        ("ls", gum_sys::arm64_cc_ARM64_CC_LS),
        ("ge", gum_sys::arm64_cc_ARM64_CC_GE),
        ("lt", gum_sys::arm64_cc_ARM64_CC_LT),
        ("gt", gum_sys::arm64_cc_ARM64_CC_GT),
        ("le", gum_sys::arm64_cc_ARM64_CC_LE),
        ("al", gum_sys::arm64_cc_ARM64_CC_AL),
        ("nv", gum_sys::arm64_cc_ARM64_CC_NV),
    ]
    .iter()
    .map(|(name, value)| (name.to_string(), *value as u32))
    .collect();

    let index_modes = [
        ("post-adjust", gum_sys::_GumArm64IndexMode_GUM_INDEX_POST_ADJUST),
        ("signed-offset", gum_sys::_GumArm64IndexMode_GUM_INDEX_SIGNED_OFFSET),
        ("pre-adjust", gum_sys::_GumArm64IndexMode_GUM_INDEX_PRE_ADJUST),
    ]
    .iter()
    .map(|(name, value)| (name.to_string(), *value))
    .collect();

    StalkerWriterEnums {
        registers,
        conditions,
        index_modes,
    }
}

/// Decode `[count, kind, value, ...]` into the array Gum expects.
fn decode_gum_arguments(raw: &[u64]) -> Option<Vec<gum_sys::GumArgument>> {
    let count = *raw.first()? as usize;
    let mut arguments = Vec::with_capacity(count);
    for index in 0..count {
        let kind = *raw.get(1 + index * 2)?;
        let value = *raw.get(2 + index * 2)?;
        let argument = match kind {
            ARG_KIND_REGISTER => gum_sys::GumArgument {
                type_: gum_sys::_GumArgType_GUM_ARG_REGISTER as _,
                value: gum_sys::_GumArgument__bindgen_ty_1 { reg: value as i32 },
            },
            ARG_KIND_ADDRESS => gum_sys::GumArgument {
                type_: gum_sys::_GumArgType_GUM_ARG_ADDRESS as _,
                value: gum_sys::_GumArgument__bindgen_ty_1 { address: value },
            },
            _ => return None,
        };
        arguments.push(argument);
    }
    Some(arguments)
}

/// Number of `u64` slots the spec characters before `index` occupy, so an arm
/// can address its own operands without recomputing offsets by hand.
fn slot_offset(arg_spec: &str, index: usize) -> usize {
    arg_spec.chars().take(index).filter_map(spec::spec_slot_count).sum()
}

struct Operands<'a> {
    args: &'a [u64],
    arg_spec: &'a str,
}

impl Operands<'_> {
    fn u64(&self, index: usize) -> u64 {
        self.args[slot_offset(self.arg_spec, index)]
    }

    fn i64(&self, index: usize) -> i64 {
        self.u64(index) as i64
    }

    fn reg(&self, index: usize) -> gum_sys::arm64_reg {
        self.u64(index) as gum_sys::arm64_reg
    }
}

/// Create an independently owned `GumArm64Writer` for the JavaScript
/// `Arm64Writer` facade.
///
/// The Stalker transform writer is owned by `GumStalkerOutput`, whereas this
/// one is explicitly owned by a QuickJS object. Upstream disables implicit
/// flush-on-destroy for the latter, so unresolved labels never cause an
/// unexpected write during GC or reload.
///
/// # Safety
///
/// `code_address` must point at writable memory large enough for the emitted
/// code. The caller owns that memory; this function owns only the Gum writer.
pub unsafe extern "C" fn standalone_writer_create(code_address: u64, pc: u64, pc_specified: u32) -> usize {
    if code_address == 0 {
        return 0;
    }
    let writer = gum_sys::gum_arm64_writer_new(code_address as *mut c_void);
    if writer.is_null() {
        return 0;
    }
    (*writer).flush_on_destroy = 0;
    if pc_specified != 0 {
        (*writer).pc = pc;
    }
    writer as usize
}

/// Release the owner reference created by [`standalone_writer_create`].
/// `GumArm64Relocator` retains its own reference, so a relocator can safely
/// finish after its source writer has been disposed from JavaScript.
///
/// # Safety
///
/// `writer` must be either zero or a pointer returned by
/// [`standalone_writer_create`] that has not already been released.
pub unsafe extern "C" fn standalone_writer_destroy(writer: usize) {
    if writer != 0 {
        gum_sys::gum_arm64_writer_unref(writer as *mut gum_sys::GumArm64Writer);
    }
}

/// Apply the standalone `Arm64Writer.reset()` semantics. Gum's reset does not
/// flush pending labels, while GumJS explicitly flushes before replacing the
/// output buffer, so preserve that ordering here.
///
/// # Safety
///
/// `writer` must be a live standalone writer and `code_address` must name a
/// writable output buffer.
pub unsafe extern "C" fn standalone_writer_reset(writer: usize, code_address: u64, pc: u64, pc_specified: u32) -> i32 {
    if writer == 0 || code_address == 0 {
        return -1;
    }
    let writer = writer as *mut gum_sys::GumArm64Writer;
    if gum_sys::gum_arm64_writer_flush(writer) == 0 {
        return -1;
    }
    gum_sys::gum_arm64_writer_reset(writer, code_address as *mut c_void);
    if pc_specified != 0 {
        (*writer).pc = pc;
    }
    1
}

/// Dispatch one ARM64 writer opcode against `writer`.
///
/// # Safety
///
/// `writer` must be a live `GumArm64Writer` owned either by a Stalker output
/// during its transform callback or by a standalone `Arm64Writer` object.
/// `args` must point to `argc` readable `u64` values.
pub unsafe extern "C" fn writer_invoke(writer: usize, opcode: u32, args: *const u64, argc: u32, out: *mut u64) -> i32 {
    let Some(method) = spec::lookup_writer_method(opcode) else {
        return -1;
    };
    if writer == 0 {
        return -1;
    }
    let args = if args.is_null() || argc == 0 {
        &[][..]
    } else {
        std::slice::from_raw_parts(args, argc as usize)
    };
    if spec::validate_arg_encoding(method.arg_spec, args).is_none() {
        return -1;
    }
    let operands = Operands {
        args,
        arg_spec: method.arg_spec,
    };
    let self_ = writer as *mut gum_sys::GumArm64Writer;

    let store = |value: u64| {
        if !out.is_null() {
            out.write(value);
        }
    };

    match opcode {
        spec::OP_BASE => {
            store((*self_).base as u64);
            1
        }
        spec::OP_CODE => {
            store((*self_).code as u64);
            1
        }
        spec::OP_PC => {
            store((*self_).pc);
            1
        }
        spec::OP_OFFSET => {
            store(gum_sys::gum_arm64_writer_offset(self_) as u64);
            1
        }
        spec::OP_CAN_BRANCH_DIRECTLY_BETWEEN => {
            gum_sys::gum_arm64_writer_can_branch_directly_between(self_, operands.u64(0), operands.u64(1)) as i32
        }
        spec::OP_FLUSH => gum_sys::gum_arm64_writer_flush(self_) as i32,
        spec::OP_RESET => {
            gum_sys::gum_arm64_writer_reset(self_, operands.u64(0) as *mut c_void);
            1
        }
        spec::OP_SKIP => {
            gum_sys::gum_arm64_writer_skip(self_, operands.u64(0) as u32);
            1
        }
        spec::OP_SIGN => {
            store(gum_sys::gum_arm64_writer_sign(self_, operands.u64(0)));
            1
        }
        spec::OP_PUT_LABEL => gum_sys::gum_arm64_writer_put_label(self_, operands.u64(0) as *const c_void) as i32,

        spec::OP_PUT_CALL_ADDRESS_WITH_ARGUMENTS => {
            let Some(arguments) = decode_gum_arguments(&args[slot_offset(method.arg_spec, 1)..]) else {
                return -1;
            };
            gum_sys::gum_arm64_writer_put_call_address_with_arguments_array(
                self_,
                operands.u64(0),
                arguments.len() as u32,
                arguments.as_ptr(),
            );
            1
        }
        spec::OP_PUT_CALL_REG_WITH_ARGUMENTS => {
            let Some(arguments) = decode_gum_arguments(&args[slot_offset(method.arg_spec, 1)..]) else {
                return -1;
            };
            gum_sys::gum_arm64_writer_put_call_reg_with_arguments_array(
                self_,
                operands.reg(0),
                arguments.len() as u32,
                arguments.as_ptr(),
            );
            1
        }
        spec::OP_PUT_BRANCH_ADDRESS => {
            gum_sys::gum_arm64_writer_put_branch_address(self_, operands.u64(0));
            1
        }
        spec::OP_PUT_B_IMM => gum_sys::gum_arm64_writer_put_b_imm(self_, operands.u64(0)) as i32,
        spec::OP_PUT_B_LABEL => {
            gum_sys::gum_arm64_writer_put_b_label(self_, operands.u64(0) as *const c_void);
            1
        }
        spec::OP_PUT_B_COND_LABEL => {
            gum_sys::gum_arm64_writer_put_b_cond_label(
                self_,
                operands.u64(0) as gum_sys::arm64_cc,
                operands.u64(1) as *const c_void,
            );
            1
        }
        spec::OP_PUT_BL_IMM => gum_sys::gum_arm64_writer_put_bl_imm(self_, operands.u64(0)) as i32,
        spec::OP_PUT_BL_LABEL => {
            gum_sys::gum_arm64_writer_put_bl_label(self_, operands.u64(0) as *const c_void);
            1
        }
        spec::OP_PUT_BR_REG => gum_sys::gum_arm64_writer_put_br_reg(self_, operands.reg(0)) as i32,
        spec::OP_PUT_BR_REG_NO_AUTH => gum_sys::gum_arm64_writer_put_br_reg_no_auth(self_, operands.reg(0)) as i32,
        spec::OP_PUT_BLR_REG => gum_sys::gum_arm64_writer_put_blr_reg(self_, operands.reg(0)) as i32,
        spec::OP_PUT_BLR_REG_NO_AUTH => gum_sys::gum_arm64_writer_put_blr_reg_no_auth(self_, operands.reg(0)) as i32,
        spec::OP_PUT_RET => {
            gum_sys::gum_arm64_writer_put_ret(self_);
            1
        }
        spec::OP_PUT_RET_REG => gum_sys::gum_arm64_writer_put_ret_reg(self_, operands.reg(0)) as i32,

        spec::OP_PUT_CBZ_REG_IMM => {
            gum_sys::gum_arm64_writer_put_cbz_reg_imm(self_, operands.reg(0), operands.u64(1)) as i32
        }
        spec::OP_PUT_CBNZ_REG_IMM => {
            gum_sys::gum_arm64_writer_put_cbnz_reg_imm(self_, operands.reg(0), operands.u64(1)) as i32
        }
        spec::OP_PUT_CBZ_REG_LABEL => {
            gum_sys::gum_arm64_writer_put_cbz_reg_label(self_, operands.reg(0), operands.u64(1) as *const c_void);
            1
        }
        spec::OP_PUT_CBNZ_REG_LABEL => {
            gum_sys::gum_arm64_writer_put_cbnz_reg_label(self_, operands.reg(0), operands.u64(1) as *const c_void);
            1
        }
        spec::OP_PUT_TBZ_REG_IMM_IMM => gum_sys::gum_arm64_writer_put_tbz_reg_imm_imm(
            self_,
            operands.reg(0),
            operands.u64(1) as u32,
            operands.u64(2),
        ) as i32,
        spec::OP_PUT_TBNZ_REG_IMM_IMM => gum_sys::gum_arm64_writer_put_tbnz_reg_imm_imm(
            self_,
            operands.reg(0),
            operands.u64(1) as u32,
            operands.u64(2),
        ) as i32,
        spec::OP_PUT_TBZ_REG_IMM_LABEL => {
            gum_sys::gum_arm64_writer_put_tbz_reg_imm_label(
                self_,
                operands.reg(0),
                operands.u64(1) as u32,
                operands.u64(2) as *const c_void,
            );
            1
        }
        spec::OP_PUT_TBNZ_REG_IMM_LABEL => {
            gum_sys::gum_arm64_writer_put_tbnz_reg_imm_label(
                self_,
                operands.reg(0),
                operands.u64(1) as u32,
                operands.u64(2) as *const c_void,
            );
            1
        }

        spec::OP_PUT_PUSH_REG_REG => {
            gum_sys::gum_arm64_writer_put_push_reg_reg(self_, operands.reg(0), operands.reg(1)) as i32
        }
        spec::OP_PUT_POP_REG_REG => {
            gum_sys::gum_arm64_writer_put_pop_reg_reg(self_, operands.reg(0), operands.reg(1)) as i32
        }
        spec::OP_PUT_PUSH_ALL_X_REGISTERS => {
            gum_sys::gum_arm64_writer_put_push_all_x_registers(self_);
            1
        }
        spec::OP_PUT_POP_ALL_X_REGISTERS => {
            gum_sys::gum_arm64_writer_put_pop_all_x_registers(self_);
            1
        }
        spec::OP_PUT_PUSH_ALL_Q_REGISTERS => {
            gum_sys::gum_arm64_writer_put_push_all_q_registers(self_);
            1
        }
        spec::OP_PUT_POP_ALL_Q_REGISTERS => {
            gum_sys::gum_arm64_writer_put_pop_all_q_registers(self_);
            1
        }

        spec::OP_PUT_LDR_REG_ADDRESS => {
            gum_sys::gum_arm64_writer_put_ldr_reg_address(self_, operands.reg(0), operands.u64(1)) as i32
        }
        spec::OP_PUT_LDR_REG_U32 => {
            gum_sys::gum_arm64_writer_put_ldr_reg_u32(self_, operands.reg(0), operands.u64(1) as u32) as i32
        }
        spec::OP_PUT_LDR_REG_U64 => {
            gum_sys::gum_arm64_writer_put_ldr_reg_u64(self_, operands.reg(0), operands.u64(1)) as i32
        }
        spec::OP_PUT_LDR_REG_U32_PTR => {
            gum_sys::gum_arm64_writer_put_ldr_reg_u32_ptr(self_, operands.reg(0), operands.u64(1)) as i32
        }
        spec::OP_PUT_LDR_REG_U64_PTR => {
            gum_sys::gum_arm64_writer_put_ldr_reg_u64_ptr(self_, operands.reg(0), operands.u64(1)) as i32
        }
        spec::OP_PUT_LDR_REG_REF => {
            store(gum_sys::gum_arm64_writer_put_ldr_reg_ref(self_, operands.reg(0)) as u64);
            1
        }
        spec::OP_PUT_LDR_REG_VALUE => {
            gum_sys::gum_arm64_writer_put_ldr_reg_value(self_, operands.u64(0) as u32, operands.u64(1));
            1
        }
        spec::OP_PUT_LDR_REG_REG => {
            gum_sys::gum_arm64_writer_put_ldr_reg_reg(self_, operands.reg(0), operands.reg(1)) as i32
        }
        spec::OP_PUT_LDR_REG_REG_OFFSET => {
            gum_sys::gum_arm64_writer_put_ldr_reg_reg_offset(self_, operands.reg(0), operands.reg(1), operands.u64(2))
                as i32
        }
        spec::OP_PUT_LDR_REG_REG_OFFSET_MODE => gum_sys::gum_arm64_writer_put_ldr_reg_reg_offset_mode(
            self_,
            operands.reg(0),
            operands.reg(1),
            operands.i64(2),
            operands.u64(3) as gum_sys::GumArm64IndexMode,
        ) as i32,
        spec::OP_PUT_LDRSW_REG_REG_OFFSET => {
            gum_sys::gum_arm64_writer_put_ldrsw_reg_reg_offset(self_, operands.reg(0), operands.reg(1), operands.u64(2))
                as i32
        }
        spec::OP_PUT_ADRP_REG_ADDRESS => {
            gum_sys::gum_arm64_writer_put_adrp_reg_address(self_, operands.reg(0), operands.u64(1)) as i32
        }
        spec::OP_PUT_STR_REG_REG => {
            gum_sys::gum_arm64_writer_put_str_reg_reg(self_, operands.reg(0), operands.reg(1)) as i32
        }
        spec::OP_PUT_STR_REG_REG_OFFSET => {
            gum_sys::gum_arm64_writer_put_str_reg_reg_offset(self_, operands.reg(0), operands.reg(1), operands.u64(2))
                as i32
        }
        spec::OP_PUT_STR_REG_REG_OFFSET_MODE => gum_sys::gum_arm64_writer_put_str_reg_reg_offset_mode(
            self_,
            operands.reg(0),
            operands.reg(1),
            operands.i64(2),
            operands.u64(3) as gum_sys::GumArm64IndexMode,
        ) as i32,
        spec::OP_PUT_LDP_REG_REG_REG_OFFSET => gum_sys::gum_arm64_writer_put_ldp_reg_reg_reg_offset(
            self_,
            operands.reg(0),
            operands.reg(1),
            operands.reg(2),
            operands.i64(3),
            operands.u64(4) as gum_sys::GumArm64IndexMode,
        ) as i32,
        spec::OP_PUT_STP_REG_REG_REG_OFFSET => gum_sys::gum_arm64_writer_put_stp_reg_reg_reg_offset(
            self_,
            operands.reg(0),
            operands.reg(1),
            operands.reg(2),
            operands.i64(3),
            operands.u64(4) as gum_sys::GumArm64IndexMode,
        ) as i32,

        spec::OP_PUT_MOV_REG_REG => {
            gum_sys::gum_arm64_writer_put_mov_reg_reg(self_, operands.reg(0), operands.reg(1)) as i32
        }
        spec::OP_PUT_MOV_REG_NZCV => {
            gum_sys::gum_arm64_writer_put_mov_reg_nzcv(self_, operands.reg(0));
            1
        }
        spec::OP_PUT_MOV_NZCV_REG => {
            gum_sys::gum_arm64_writer_put_mov_nzcv_reg(self_, operands.reg(0));
            1
        }
        spec::OP_PUT_UXTW_REG_REG => {
            gum_sys::gum_arm64_writer_put_uxtw_reg_reg(self_, operands.reg(0), operands.reg(1)) as i32
        }
        spec::OP_PUT_ADD_REG_REG_IMM => {
            gum_sys::gum_arm64_writer_put_add_reg_reg_imm(self_, operands.reg(0), operands.reg(1), operands.u64(2))
                as i32
        }
        spec::OP_PUT_ADD_REG_REG_REG => {
            gum_sys::gum_arm64_writer_put_add_reg_reg_reg(self_, operands.reg(0), operands.reg(1), operands.reg(2))
                as i32
        }
        spec::OP_PUT_SUB_REG_REG_IMM => {
            gum_sys::gum_arm64_writer_put_sub_reg_reg_imm(self_, operands.reg(0), operands.reg(1), operands.u64(2))
                as i32
        }
        spec::OP_PUT_SUB_REG_REG_REG => {
            gum_sys::gum_arm64_writer_put_sub_reg_reg_reg(self_, operands.reg(0), operands.reg(1), operands.reg(2))
                as i32
        }
        spec::OP_PUT_AND_REG_REG_IMM => {
            gum_sys::gum_arm64_writer_put_and_reg_reg_imm(self_, operands.reg(0), operands.reg(1), operands.u64(2))
                as i32
        }
        spec::OP_PUT_EOR_REG_REG_REG => {
            gum_sys::gum_arm64_writer_put_eor_reg_reg_reg(self_, operands.reg(0), operands.reg(1), operands.reg(2))
                as i32
        }
        spec::OP_PUT_UBFM => gum_sys::gum_arm64_writer_put_ubfm(
            self_,
            operands.reg(0),
            operands.reg(1),
            operands.u64(2) as u8,
            operands.u64(3) as u8,
        ) as i32,
        spec::OP_PUT_LSL_REG_IMM => {
            gum_sys::gum_arm64_writer_put_lsl_reg_imm(self_, operands.reg(0), operands.reg(1), operands.u64(2) as u8)
                as i32
        }
        spec::OP_PUT_LSR_REG_IMM => {
            gum_sys::gum_arm64_writer_put_lsr_reg_imm(self_, operands.reg(0), operands.reg(1), operands.u64(2) as u8)
                as i32
        }
        spec::OP_PUT_TST_REG_IMM => {
            gum_sys::gum_arm64_writer_put_tst_reg_imm(self_, operands.reg(0), operands.u64(1)) as i32
        }
        spec::OP_PUT_CMP_REG_REG => {
            gum_sys::gum_arm64_writer_put_cmp_reg_reg(self_, operands.reg(0), operands.reg(1)) as i32
        }
        spec::OP_PUT_XPACI_REG => gum_sys::gum_arm64_writer_put_xpaci_reg(self_, operands.reg(0)) as i32,

        spec::OP_PUT_NOP => {
            gum_sys::gum_arm64_writer_put_nop(self_);
            1
        }
        spec::OP_PUT_BRK_IMM => {
            gum_sys::gum_arm64_writer_put_brk_imm(self_, operands.u64(0) as u16);
            1
        }
        spec::OP_PUT_MRS => gum_sys::gum_arm64_writer_put_mrs(self_, operands.reg(0), operands.u64(1) as u16) as i32,
        spec::OP_PUT_INSTRUCTION => {
            gum_sys::gum_arm64_writer_put_instruction(self_, operands.u64(0) as u32);
            1
        }
        spec::OP_PUT_BYTES => {
            let pointer = operands.u64(0) as *const u8;
            let length = operands.u64(1);
            if pointer.is_null() || length > u32::MAX as u64 {
                return -1;
            }
            gum_sys::gum_arm64_writer_put_bytes(self_, pointer, length as u32) as i32
        }

        _ => -1,
    }
}

// The relocator API is present in the pinned Gum archive but is not part of the
// devkit header, so the bindings do not cover it.
unsafe extern "C" {
    fn gum_arm64_relocator_new(input_code: *const c_void, output: *mut c_void) -> *mut c_void;
    fn gum_arm64_relocator_unref(relocator: *mut c_void);
    fn gum_arm64_relocator_reset(relocator: *mut c_void, input_code: *const c_void, output: *mut c_void);
    fn gum_arm64_relocator_read_one(relocator: *mut c_void, instruction: *mut *const c_void) -> u32;
    fn gum_arm64_relocator_peek_next_write_insn(relocator: *mut c_void) -> *const c_void;
    fn gum_arm64_relocator_peek_next_write_source(relocator: *mut c_void) -> *mut c_void;
    fn gum_arm64_relocator_skip_one(relocator: *mut c_void) -> i32;
    fn gum_arm64_relocator_write_one(relocator: *mut c_void) -> i32;
    fn gum_arm64_relocator_write_all(relocator: *mut c_void);
    fn gum_arm64_relocator_eob(relocator: *mut c_void) -> i32;
    fn gum_arm64_relocator_eoi(relocator: *mut c_void) -> i32;
}

/// The relocator tracks the address it is currently reading, so the facade can
/// report `input` without another Gum call.
struct RelocatorHandle {
    relocator: *mut c_void,
    input_start: u64,
    input_cursor: u64,
}

/// # Safety
///
/// `writer` must be a live `GumArm64Writer`; the returned handle stays valid
/// only while that writer does.
pub unsafe extern "C" fn relocator_create(writer: usize, input_code: u64) -> usize {
    if writer == 0 || input_code == 0 {
        return 0;
    }
    let relocator = gum_arm64_relocator_new(input_code as *const c_void, writer as *mut c_void);
    if relocator.is_null() {
        return 0;
    }
    Box::into_raw(Box::new(RelocatorHandle {
        relocator,
        input_start: input_code,
        input_cursor: input_code,
    })) as usize
}

/// # Safety
///
/// `handle` must come from [`relocator_create`] and must not be used afterwards.
pub unsafe extern "C" fn relocator_destroy(handle: usize) {
    if handle == 0 {
        return;
    }
    let handle = Box::from_raw(handle as *mut RelocatorHandle);
    gum_arm64_relocator_unref(handle.relocator);
}

/// # Safety
///
/// `handle` must come from [`relocator_create`] and still be alive, and `args`
/// must point to `argc` readable `u64` values.
pub unsafe extern "C" fn relocator_invoke(
    handle: usize,
    opcode: u32,
    args: *const u64,
    argc: u32,
    out: *mut u64,
) -> i32 {
    let Some(method) = spec::lookup_relocator_method(opcode) else {
        return -1;
    };
    if handle == 0 {
        return -1;
    }
    let args = if args.is_null() || argc == 0 {
        &[][..]
    } else {
        std::slice::from_raw_parts(args, argc as usize)
    };
    if spec::validate_arg_encoding(method.arg_spec, args).is_none() {
        return -1;
    }
    let handle = &mut *(handle as *mut RelocatorHandle);
    let relocator = handle.relocator;

    let store = |value: u64| {
        if !out.is_null() {
            out.write(value);
        }
    };

    match opcode {
        spec::RELOC_OP_EOB => gum_arm64_relocator_eob(relocator),
        spec::RELOC_OP_EOI => gum_arm64_relocator_eoi(relocator),
        spec::RELOC_OP_INPUT => {
            store(handle.input_cursor);
            1
        }
        spec::RELOC_OP_PEEK_NEXT_WRITE_INSN => {
            store(gum_arm64_relocator_peek_next_write_insn(relocator) as u64);
            1
        }
        spec::RELOC_OP_PEEK_NEXT_WRITE_SOURCE => {
            store(gum_arm64_relocator_peek_next_write_source(relocator) as u64);
            1
        }
        spec::RELOC_OP_READ_ONE => {
            let mut instruction: *const c_void = std::ptr::null();
            let consumed = gum_arm64_relocator_read_one(relocator, &mut instruction);
            handle.input_cursor = handle.input_start.saturating_add(consumed as u64);
            store(consumed as u64);
            1
        }
        spec::RELOC_OP_RESET => {
            let input_code = args[0];
            let output = args[1];
            if input_code == 0 || output == 0 {
                return -1;
            }
            gum_arm64_relocator_reset(relocator, input_code as *const c_void, output as *mut c_void);
            handle.input_start = input_code;
            handle.input_cursor = input_code;
            1
        }
        spec::RELOC_OP_SKIP_ONE => gum_arm64_relocator_skip_one(relocator),
        spec::RELOC_OP_WRITE_ALL => {
            gum_arm64_relocator_write_all(relocator);
            1
        }
        spec::RELOC_OP_WRITE_ONE => gum_arm64_relocator_write_one(relocator),
        _ => -1,
    }
}
