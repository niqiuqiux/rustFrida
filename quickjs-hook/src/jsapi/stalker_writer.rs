//! ARM64 code writer surface shared by the QuickJS facade and the Gum backend.
//!
//! The facade owns the opcode numbering so the JavaScript bindings can be table
//! driven, while the backend implements each opcode against the Gum writer that
//! belongs to the current `GumStalkerOutput`. Both sides reference the same
//! generated constants, so adding or renaming a method is a compile-time change
//! on the backend rather than a silent behaviour drift.
//!
//! Arguments are flattened into a `u64` slice. Every spec character consumes one
//! slot except `b` (pointer + length) and `A` (count followed by kind/value
//! pairs), which the backend decodes using the same spec string.

/// One writer method as exposed to JavaScript.
#[derive(Clone, Copy, Debug)]
pub struct StalkerWriterMethod {
    /// Frida-compatible JavaScript name.
    pub name: &'static str,
    pub opcode: u32,
    /// Per-argument encoding; see the module docs for the character meanings.
    pub arg_spec: &'static str,
    /// Result encoding handed back to JavaScript.
    pub result: StalkerWriterResult,
    /// Whether upstream exposes this member as a getter or as a callable. It is
    /// stated rather than derived: `flush` and `readOne` both take no arguments,
    /// yet upstream makes only the latter's sibling `eoi` a property.
    pub kind: StalkerWriterKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StalkerWriterKind {
    Function,
    Property,
}

impl StalkerWriterKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Function => "function",
            Self::Property => "property",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StalkerWriterResult {
    /// `undefined`
    Void,
    /// Gum returned a `gboolean`; a false result is reported as an exception.
    Bool,
    /// Unsigned integer read from the out parameter.
    Unsigned,
    /// NativePointer built from the out parameter.
    Pointer,
}

impl StalkerWriterResult {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Void => "void",
            Self::Bool => "bool",
            Self::Unsigned => "uint",
            Self::Pointer => "pointer",
        }
    }
}

macro_rules! stalker_writer_methods {
    ($($konst:ident => $name:literal, $spec:literal, $result:ident, $kind:ident;)*) => {
        stalker_writer_methods!(@constants 1u32, $($konst,)*);

        pub const STALKER_WRITER_METHODS: &[StalkerWriterMethod] = &[
            $(StalkerWriterMethod {
                name: $name,
                opcode: $konst,
                arg_spec: $spec,
                result: StalkerWriterResult::$result,
                kind: StalkerWriterKind::$kind,
            },)*
        ];
    };
    (@constants $next:expr,) => {};
    (@constants $next:expr, $konst:ident, $($rest:ident,)*) => {
        pub const $konst: u32 = $next;
        stalker_writer_methods!(@constants $next + 1, $($rest,)*);
    };
}

stalker_writer_methods! {
    // Writer state.
    OP_BASE => "base", "", Pointer, Property;
    OP_CODE => "code", "", Pointer, Property;
    OP_PC => "pc", "", Pointer, Property;
    OP_OFFSET => "offset", "", Unsigned, Property;
    OP_CAN_BRANCH_DIRECTLY_BETWEEN => "canBranchDirectlyBetween", "aa", Bool, Function;
    OP_FLUSH => "flush", "", Bool, Function;
    OP_RESET => "reset", "a", Void, Function;
    OP_SKIP => "skip", "u", Void, Function;
    OP_SIGN => "sign", "a", Pointer, Function;
    OP_PUT_LABEL => "putLabel", "l", Bool, Function;

    // Calls and branches.
    OP_PUT_CALL_ADDRESS_WITH_ARGUMENTS => "putCallAddressWithArguments", "aA", Void, Function;
    OP_PUT_CALL_REG_WITH_ARGUMENTS => "putCallRegWithArguments", "rA", Void, Function;
    OP_PUT_BRANCH_ADDRESS => "putBranchAddress", "a", Void, Function;
    OP_PUT_B_IMM => "putBImm", "a", Bool, Function;
    OP_PUT_B_LABEL => "putBLabel", "l", Void, Function;
    OP_PUT_B_COND_LABEL => "putBCondLabel", "cl", Void, Function;
    OP_PUT_BL_IMM => "putBlImm", "a", Bool, Function;
    OP_PUT_BL_LABEL => "putBlLabel", "l", Void, Function;
    OP_PUT_BR_REG => "putBrReg", "r", Bool, Function;
    OP_PUT_BR_REG_NO_AUTH => "putBrRegNoAuth", "r", Bool, Function;
    OP_PUT_BLR_REG => "putBlrReg", "r", Bool, Function;
    OP_PUT_BLR_REG_NO_AUTH => "putBlrRegNoAuth", "r", Bool, Function;
    OP_PUT_RET => "putRet", "", Void, Function;
    OP_PUT_RET_REG => "putRetReg", "r", Bool, Function;

    // Compare and branch.
    OP_PUT_CBZ_REG_IMM => "putCbzRegImm", "ra", Bool, Function;
    OP_PUT_CBNZ_REG_IMM => "putCbnzRegImm", "ra", Bool, Function;
    OP_PUT_CBZ_REG_LABEL => "putCbzRegLabel", "rl", Void, Function;
    OP_PUT_CBNZ_REG_LABEL => "putCbnzRegLabel", "rl", Void, Function;
    OP_PUT_TBZ_REG_IMM_IMM => "putTbzRegImmImm", "rua", Bool, Function;
    OP_PUT_TBNZ_REG_IMM_IMM => "putTbnzRegImmImm", "rua", Bool, Function;
    OP_PUT_TBZ_REG_IMM_LABEL => "putTbzRegImmLabel", "rul", Void, Function;
    OP_PUT_TBNZ_REG_IMM_LABEL => "putTbnzRegImmLabel", "rul", Void, Function;

    // Stack.
    OP_PUT_PUSH_REG_REG => "putPushRegReg", "rr", Bool, Function;
    OP_PUT_POP_REG_REG => "putPopRegReg", "rr", Bool, Function;
    OP_PUT_PUSH_ALL_X_REGISTERS => "putPushAllXRegisters", "", Void, Function;
    OP_PUT_POP_ALL_X_REGISTERS => "putPopAllXRegisters", "", Void, Function;
    OP_PUT_PUSH_ALL_Q_REGISTERS => "putPushAllQRegisters", "", Void, Function;
    OP_PUT_POP_ALL_Q_REGISTERS => "putPopAllQRegisters", "", Void, Function;

    // Loads and stores.
    OP_PUT_LDR_REG_ADDRESS => "putLdrRegAddress", "ra", Bool, Function;
    OP_PUT_LDR_REG_U32 => "putLdrRegU32", "ru", Bool, Function;
    OP_PUT_LDR_REG_U64 => "putLdrRegU64", "ru", Bool, Function;
    OP_PUT_LDR_REG_U32_PTR => "putLdrRegU32Ptr", "ra", Bool, Function;
    OP_PUT_LDR_REG_U64_PTR => "putLdrRegU64Ptr", "ra", Bool, Function;
    OP_PUT_LDR_REG_REF => "putLdrRegRef", "r", Unsigned, Function;
    OP_PUT_LDR_REG_VALUE => "putLdrRegValue", "ua", Void, Function;
    OP_PUT_LDR_REG_REG => "putLdrRegReg", "rr", Bool, Function;
    OP_PUT_LDR_REG_REG_OFFSET => "putLdrRegRegOffset", "rru", Bool, Function;
    OP_PUT_LDR_REG_REG_OFFSET_MODE => "putLdrRegRegOffsetMode", "rrsm", Bool, Function;
    OP_PUT_LDRSW_REG_REG_OFFSET => "putLdrswRegRegOffset", "rru", Bool, Function;
    OP_PUT_ADRP_REG_ADDRESS => "putAdrpRegAddress", "ra", Bool, Function;
    OP_PUT_STR_REG_REG => "putStrRegReg", "rr", Bool, Function;
    OP_PUT_STR_REG_REG_OFFSET => "putStrRegRegOffset", "rru", Bool, Function;
    OP_PUT_STR_REG_REG_OFFSET_MODE => "putStrRegRegOffsetMode", "rrsm", Bool, Function;
    OP_PUT_LDP_REG_REG_REG_OFFSET => "putLdpRegRegRegOffset", "rrrsm", Bool, Function;
    OP_PUT_STP_REG_REG_REG_OFFSET => "putStpRegRegRegOffset", "rrrsm", Bool, Function;

    // Data processing.
    OP_PUT_MOV_REG_REG => "putMovRegReg", "rr", Bool, Function;
    OP_PUT_MOV_REG_NZCV => "putMovRegNzcv", "r", Void, Function;
    OP_PUT_MOV_NZCV_REG => "putMovNzcvReg", "r", Void, Function;
    OP_PUT_UXTW_REG_REG => "putUxtwRegReg", "rr", Bool, Function;
    OP_PUT_ADD_REG_REG_IMM => "putAddRegRegImm", "rru", Bool, Function;
    OP_PUT_ADD_REG_REG_REG => "putAddRegRegReg", "rrr", Bool, Function;
    OP_PUT_SUB_REG_REG_IMM => "putSubRegRegImm", "rru", Bool, Function;
    OP_PUT_SUB_REG_REG_REG => "putSubRegRegReg", "rrr", Bool, Function;
    OP_PUT_AND_REG_REG_IMM => "putAndRegRegImm", "rru", Bool, Function;
    OP_PUT_EOR_REG_REG_REG => "putEorRegRegReg", "rrr", Bool, Function;
    OP_PUT_UBFM => "putUbfm", "rruu", Bool, Function;
    OP_PUT_LSL_REG_IMM => "putLslRegImm", "rru", Bool, Function;
    OP_PUT_LSR_REG_IMM => "putLsrRegImm", "rru", Bool, Function;
    OP_PUT_TST_REG_IMM => "putTstRegImm", "ru", Bool, Function;
    OP_PUT_CMP_REG_REG => "putCmpRegReg", "rr", Bool, Function;
    OP_PUT_XPACI_REG => "putXpaciReg", "r", Bool, Function;

    // Raw emission.
    OP_PUT_NOP => "putNop", "", Void, Function;
    OP_PUT_BRK_IMM => "putBrkImm", "u", Void, Function;
    OP_PUT_MRS => "putMrs", "ru", Bool, Function;
    OP_PUT_INSTRUCTION => "putInstruction", "u", Void, Function;
    OP_PUT_BYTES => "putBytes", "b", Bool, Function;
}

/// Relocator methods. The relocator is created against the writer of the active
/// transform callback, so its handle shares that callback's lifetime.
macro_rules! stalker_relocator_methods {
    ($($konst:ident => $name:literal, $spec:literal, $result:ident, $kind:ident;)*) => {
        stalker_relocator_methods!(@constants 1u32, $($konst,)*);

        pub const STALKER_RELOCATOR_METHODS: &[StalkerWriterMethod] = &[
            $(StalkerWriterMethod {
                name: $name,
                opcode: $konst,
                arg_spec: $spec,
                result: StalkerWriterResult::$result,
                kind: StalkerWriterKind::$kind,
            },)*
        ];
    };
    (@constants $next:expr,) => {};
    (@constants $next:expr, $konst:ident, $($rest:ident,)*) => {
        pub const $konst: u32 = $next;
        stalker_relocator_methods!(@constants $next + 1, $($rest,)*);
    };
}

stalker_relocator_methods! {
    RELOC_OP_EOB => "eob", "", Bool, Property;
    RELOC_OP_EOI => "eoi", "", Bool, Property;
    RELOC_OP_INPUT => "input", "", Pointer, Property;
    RELOC_OP_PEEK_NEXT_WRITE_INSN => "peekNextWriteInsn", "", Pointer, Function;
    RELOC_OP_PEEK_NEXT_WRITE_SOURCE => "peekNextWriteSource", "", Pointer, Function;
    RELOC_OP_READ_ONE => "readOne", "", Unsigned, Function;
    RELOC_OP_RESET => "reset", "aa", Void, Function;
    RELOC_OP_SKIP_ONE => "skipOne", "", Bool, Function;
    RELOC_OP_WRITE_ALL => "writeAll", "", Void, Function;
    RELOC_OP_WRITE_ONE => "writeOne", "", Bool, Function;
}

/// The opcode tables are validated at compile time because `quickjs-hook` only
/// builds for the Android target, so `cargo test` cannot run them on the host.
/// `tests/compat/test_frida_surface.py` additionally checks the method names
/// against the upstream `gumjs_arm64_writer_entries` baseline.
const fn opcodes_are_dense(methods: &[StalkerWriterMethod]) -> bool {
    let mut index = 0;
    while index < methods.len() {
        if methods[index].opcode != index as u32 + 1 {
            return false;
        }
        index += 1;
    }
    true
}

const _: () = assert!(opcodes_are_dense(STALKER_WRITER_METHODS));
const _: () = assert!(opcodes_are_dense(STALKER_RELOCATOR_METHODS));
// Upstream `gumjs_arm64_writer_entries` exposes 77 members; `dispose` stays in
// the facade because the Stalker output writer is owned by Gum.
const _: () = assert!(STALKER_WRITER_METHODS.len() == 76);
const _: () = assert!(STALKER_RELOCATOR_METHODS.len() == 10);

/// Number of `u64` slots a fixed-width spec character occupies.
pub fn spec_slot_count(spec: char) -> Option<usize> {
    match spec {
        'r' | 'c' | 'm' | 'u' | 's' | 'a' | 'l' => Some(1),
        'b' => Some(2),
        _ => None,
    }
}

pub fn lookup_writer_method(opcode: u32) -> Option<&'static StalkerWriterMethod> {
    STALKER_WRITER_METHODS.iter().find(|method| method.opcode == opcode)
}

pub fn lookup_relocator_method(opcode: u32) -> Option<&'static StalkerWriterMethod> {
    STALKER_RELOCATOR_METHODS.iter().find(|method| method.opcode == opcode)
}

/// Decode the `u64` slice handed to a backend dispatcher against `arg_spec`.
///
/// Returns the number of slots consumed, or `None` when the encoding does not
/// match the spec. The backend uses this to reject malformed calls instead of
/// reading past the end of the slice.
pub fn validate_arg_encoding(arg_spec: &str, args: &[u64]) -> Option<usize> {
    let mut cursor = 0usize;
    for spec in arg_spec.chars() {
        match spec {
            'A' => {
                let count = *args.get(cursor)? as usize;
                cursor = cursor.checked_add(1)?;
                let pairs = count.checked_mul(2)?;
                cursor = cursor.checked_add(pairs)?;
                if cursor > args.len() {
                    return None;
                }
            }
            other => {
                let slots = spec_slot_count(other)?;
                cursor = cursor.checked_add(slots)?;
                if cursor > args.len() {
                    return None;
                }
            }
        }
    }
    (cursor == args.len()).then_some(cursor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn method_names_are_unique() {
        let mut seen = HashSet::new();
        for method in STALKER_WRITER_METHODS {
            assert!(seen.insert(method.name), "duplicate method name {}", method.name);
        }
        seen.clear();
        for method in STALKER_RELOCATOR_METHODS {
            assert!(seen.insert(method.name), "duplicate relocator name {}", method.name);
        }
    }

    #[test]
    fn every_arg_spec_uses_known_characters() {
        for method in STALKER_WRITER_METHODS.iter().chain(STALKER_RELOCATOR_METHODS) {
            for spec in method.arg_spec.chars() {
                assert!(
                    spec == 'A' || spec_slot_count(spec).is_some(),
                    "method {} uses unknown spec character {spec}",
                    method.name
                );
            }
        }
    }

    #[test]
    fn validates_fixed_width_encodings() {
        assert_eq!(validate_arg_encoding("rr", &[1, 2]), Some(2));
        assert_eq!(validate_arg_encoding("rr", &[1]), None);
        assert_eq!(validate_arg_encoding("rr", &[1, 2, 3]), None);
        assert_eq!(validate_arg_encoding("b", &[0x1000, 4]), Some(2));
    }

    #[test]
    fn validates_argument_array_encoding() {
        // putCallAddressWithArguments(func, [reg x0, address 0x40])
        assert_eq!(validate_arg_encoding("aA", &[0x1000, 2, 0, 199, 1, 0x40]), Some(6));
        assert_eq!(validate_arg_encoding("aA", &[0x1000, 2, 0, 199]), None);
        assert_eq!(validate_arg_encoding("aA", &[0x1000, 0]), Some(2));
    }
}
