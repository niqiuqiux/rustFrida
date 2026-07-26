use super::{return_is_object, FieldRef, MethodRef};

#[derive(Clone, Debug)]
pub(in crate::jsapi::java::java_hook_api) struct DexCode {
    pub registers_size: u16,
    pub ins_size: u16,
    pub outs_size: u16,
    pub insns: Vec<CodeWord>,
    pub try_items: Vec<DexTryItem>,
}

impl DexCode {
    pub(super) fn new(registers_size: u16, ins_size: u16, outs_size: u16) -> Self {
        Self {
            registers_size,
            ins_size,
            outs_size,
            insns: Vec::new(),
            try_items: Vec::new(),
        }
    }

    pub(super) fn raw(&mut self, word: u16) {
        self.insns.push(CodeWord::Raw(word));
    }

    pub(super) fn type_idx(&mut self, ty: impl Into<String>) {
        self.insns.push(CodeWord::Type(ty.into()));
    }

    pub(super) fn string_idx(&mut self, value: impl Into<String>) {
        self.insns.push(CodeWord::String(value.into()));
    }

    pub(super) fn field_idx(&mut self, field: FieldRef) {
        self.insns.push(CodeWord::Field(field));
    }

    pub(super) fn method_idx(&mut self, method: MethodRef) {
        self.insns.push(CodeWord::Method(method));
    }
}

#[derive(Clone, Debug)]
pub(in crate::jsapi::java::java_hook_api) struct DexTryItem {
    pub start_addr: u32,
    pub insn_count: u16,
    pub handlers: Vec<DexCatchHandler>,
    pub catch_all_addr: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::jsapi::java::java_hook_api) struct DexCatchHandler {
    pub handler_type: String,
    pub handler_addr: u32,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct DexLabel(usize);

pub(super) struct DexIrBuilder {
    registers_size: u16,
    ins_size: u16,
    outs_size: u16,
    instrs: Vec<IrInstr>,
    labels: Vec<Option<usize>>,
    try_items: Vec<IrTryItem>,
}

impl DexIrBuilder {
    pub(super) fn new(registers_size: u16, ins_size: u16, outs_size: u16) -> Self {
        Self {
            registers_size,
            ins_size,
            outs_size,
            instrs: Vec::new(),
            labels: Vec::new(),
            try_items: Vec::new(),
        }
    }

    pub(super) fn new_label(&mut self) -> DexLabel {
        let id = self.labels.len();
        self.labels.push(None);
        DexLabel(id)
    }

    pub(super) fn bind(&mut self, label: DexLabel) -> Result<(), String> {
        let offset = self.current_offset();
        let slot = self
            .labels
            .get_mut(label.0)
            .ok_or_else(|| format!("invalid dex label {}", label.0))?;
        if slot.is_some() {
            return Err(format!("dex label {} bound twice", label.0));
        }
        *slot = Some(offset);
        Ok(())
    }

    pub(super) fn const4(&mut self, dst: u8, literal: i8) {
        self.instrs.push(IrInstr::Const4 { dst, literal });
    }

    pub(super) fn const16(&mut self, dst: u8, literal: i16) {
        self.instrs.push(IrInstr::Const16 { dst, literal });
    }

    pub(super) fn const32(&mut self, dst: u8, literal: i32) {
        self.instrs.push(IrInstr::Const32 { dst, literal });
    }

    pub(super) fn const_string(&mut self, dst: u8, value: impl Into<String>) {
        self.instrs.push(IrInstr::ConstString {
            dst,
            value: value.into(),
        });
    }

    pub(super) fn move_from16(&mut self, dst: u8, src: u16, kind: ValueKind) {
        self.instrs.push(IrInstr::MoveFrom16 { dst, src, kind });
    }

    pub(super) fn move_exception(&mut self, dst: u8) {
        self.instrs.push(IrInstr::MoveException { dst });
    }

    pub(super) fn if_cmp(&mut self, op: IfCmpOp, left: u8, right: u8, target: DexLabel) {
        self.instrs.push(IrInstr::IfCmp {
            op,
            left,
            right,
            target,
        });
    }

    pub(super) fn if_eqz(&mut self, reg: u8, target: DexLabel) {
        self.instrs.push(IrInstr::IfEqz { reg, target });
    }

    pub(super) fn if_nez(&mut self, reg: u8, target: DexLabel) {
        self.instrs.push(IrInstr::IfNez { reg, target });
    }

    pub(super) fn goto16(&mut self, target: DexLabel) {
        self.instrs.push(IrInstr::Goto16 { target });
    }

    pub(super) fn packed_switch(&mut self, reg: u8, first_key: i32, targets: Vec<DexLabel>, default_target: DexLabel) {
        self.instrs.push(IrInstr::PackedSwitch {
            reg,
            first_key,
            targets,
            default_target,
        });
    }

    pub(super) fn sparse_switch(&mut self, reg: u8, keys: Vec<i32>, targets: Vec<DexLabel>, default_target: DexLabel) {
        self.instrs.push(IrInstr::SparseSwitch {
            reg,
            keys,
            targets,
            default_target,
        });
    }

    pub(super) fn new_instance(&mut self, dst: u8, ty: impl Into<String>) {
        self.instrs.push(IrInstr::NewInstance { dst, ty: ty.into() });
    }

    pub(super) fn check_cast(&mut self, reg: u8, ty: impl Into<String>) {
        self.instrs.push(IrInstr::CheckCast { reg, ty: ty.into() });
    }

    pub(super) fn instance_of(&mut self, dst: u8, obj: u8, ty: impl Into<String>) {
        self.instrs.push(IrInstr::InstanceOf {
            dst,
            obj,
            ty: ty.into(),
        });
    }

    pub(super) fn array_length(&mut self, dst: u8, array: u8) {
        self.instrs.push(IrInstr::ArrayLength { dst, array });
    }

    pub(super) fn new_array(&mut self, dst: u8, size: u8, ty: impl Into<String>) {
        self.instrs.push(IrInstr::NewArray {
            dst,
            size,
            ty: ty.into(),
        });
    }

    pub(super) fn aget(&mut self, dst: u8, array: u8, index: u8, kind: ValueKind) {
        self.instrs.push(IrInstr::Aget {
            dst,
            array,
            index,
            kind,
        });
    }

    pub(super) fn aput(&mut self, src: u8, array: u8, index: u8, kind: ValueKind) {
        self.instrs.push(IrInstr::Aput {
            src,
            array,
            index,
            kind,
        });
    }

    pub(super) fn invoke_direct(&mut self, args: Vec<u8>, method: MethodRef) {
        self.instrs.push(IrInstr::InvokeDirect { args, method });
    }

    pub(super) fn invoke_virtual(&mut self, args: Vec<u8>, method: MethodRef) {
        self.instrs.push(IrInstr::InvokeVirtual { args, method });
    }

    pub(super) fn invoke_static(&mut self, args: Vec<u8>, method: MethodRef) {
        self.instrs.push(IrInstr::InvokeStatic { args, method });
    }

    pub(super) fn invoke_interface(&mut self, args: Vec<u8>, method: MethodRef) {
        self.instrs.push(IrInstr::InvokeInterface { args, method });
    }

    pub(super) fn invoke_direct_range(&mut self, first_reg: u16, arg_words: u8, method: MethodRef) {
        self.instrs.push(IrInstr::InvokeDirectRange {
            first_reg,
            arg_words,
            method,
        });
    }

    pub(super) fn invoke_static_range(&mut self, first_reg: u16, arg_words: u8, method: MethodRef) {
        self.instrs.push(IrInstr::InvokeStaticRange {
            first_reg,
            arg_words,
            method,
        });
    }

    pub(super) fn invoke_virtual_range(&mut self, first_reg: u16, arg_words: u8, method: MethodRef) {
        self.instrs.push(IrInstr::InvokeVirtualRange {
            first_reg,
            arg_words,
            method,
        });
    }

    pub(super) fn invoke_interface_range(&mut self, first_reg: u16, arg_words: u8, method: MethodRef) {
        self.instrs.push(IrInstr::InvokeInterfaceRange {
            first_reg,
            arg_words,
            method,
        });
    }

    pub(super) fn sput_object(&mut self, src: u8, field: FieldRef) {
        self.instrs.push(IrInstr::SputObject { src, field });
    }

    pub(super) fn iget(&mut self, dst: u8, obj: u8, field: FieldRef, kind: ValueKind) {
        self.instrs.push(IrInstr::Iget { dst, obj, field, kind });
    }

    pub(super) fn iput(&mut self, src: u8, obj: u8, field: FieldRef, kind: ValueKind) {
        self.instrs.push(IrInstr::Iput { src, obj, field, kind });
    }

    pub(super) fn sget(&mut self, dst: u8, field: FieldRef, kind: ValueKind) {
        self.instrs.push(IrInstr::Sget { dst, field, kind });
    }

    pub(super) fn sput(&mut self, src: u8, field: FieldRef, kind: ValueKind) {
        self.instrs.push(IrInstr::Sput { src, field, kind });
    }

    pub(super) fn int_binop(&mut self, op: DexIntBinOp, dst: u8, left: u8, right: u8) {
        self.instrs.push(IrInstr::IntBinOp { op, dst, left, right });
    }

    pub(super) fn int_binop_lit8(&mut self, op: DexIntLit8Op, dst: u8, src: u8, literal: i8) {
        self.instrs.push(IrInstr::IntBinOpLit8 { op, dst, src, literal });
    }

    pub(super) fn int_binop_lit16(&mut self, op: DexIntLit16Op, dst: u8, src: u8, literal: i16) {
        self.instrs.push(IrInstr::IntBinOpLit16 { op, dst, src, literal });
    }

    pub(super) fn move_result_object(&mut self, dst: u8) {
        self.instrs.push(IrInstr::MoveResultObject { dst });
    }

    pub(super) fn move_result(&mut self, dst: u8) {
        self.instrs.push(IrInstr::MoveResult { dst });
    }

    pub(super) fn move_result_wide(&mut self, dst: u8) {
        self.instrs.push(IrInstr::MoveResultWide { dst });
    }

    pub(super) fn return_object(&mut self, src: u8) {
        self.instrs.push(IrInstr::ReturnObject { src });
    }

    pub(super) fn return_value(&mut self, src: u8) {
        self.instrs.push(IrInstr::Return { src });
    }

    pub(super) fn return_wide(&mut self, src: u8) {
        self.instrs.push(IrInstr::ReturnWide { src });
    }

    pub(super) fn return_void(&mut self) {
        self.instrs.push(IrInstr::ReturnVoid);
    }

    pub(super) fn throw_value(&mut self, src: u8) {
        self.instrs.push(IrInstr::Throw { src });
    }

    pub(super) fn add_try_handlers(
        &mut self,
        start: DexLabel,
        end: DexLabel,
        handlers: Vec<IrCatchHandler>,
        catch_all: Option<DexLabel>,
    ) {
        self.try_items.push(IrTryItem {
            start,
            end,
            handlers,
            catch_all,
        });
    }

    pub(super) fn finish(self) -> Result<DexCode, String> {
        let mut offsets = Vec::with_capacity(self.instrs.len());
        let mut offset = 0usize;
        for instr in &self.instrs {
            offsets.push(offset);
            offset += instr.width_at(offset);
        }

        for (idx, label) in self.labels.iter().enumerate() {
            if label.is_none() {
                return Err(format!("dex label {} was never bound", idx));
            }
        }

        let mut code = DexCode::new(self.registers_size, self.ins_size, self.outs_size);
        for (idx, instr) in self.instrs.into_iter().enumerate() {
            instr.emit(&mut code, offsets[idx], &self.labels)?;
        }
        for item in self.try_items {
            let start_addr = label_offset(item.start, &self.labels, "try start")? as u32;
            let end_addr = label_offset(item.end, &self.labels, "try end")?;
            if end_addr < start_addr as usize {
                return Err("try end is before try start".to_string());
            }
            let insn_count = end_addr - start_addr as usize;
            if insn_count == 0 {
                return Err("try block cannot be empty".to_string());
            }
            if insn_count > u16::MAX as usize {
                return Err(format!("try block too large: {} code units", insn_count));
            }
            code.try_items.push(DexTryItem {
                start_addr,
                insn_count: insn_count as u16,
                handlers: item
                    .handlers
                    .into_iter()
                    .map(|handler| {
                        Ok(DexCatchHandler {
                            handler_type: handler.handler_type,
                            handler_addr: label_offset(handler.handler, &self.labels, "catch handler")? as u32,
                        })
                    })
                    .collect::<Result<Vec<_>, String>>()?,
                catch_all_addr: item
                    .catch_all
                    .map(|handler| label_offset(handler, &self.labels, "catch-all handler").map(|offset| offset as u32))
                    .transpose()?,
            });
        }
        Ok(code)
    }

    fn current_offset(&self) -> usize {
        let mut offset = 0usize;
        for instr in &self.instrs {
            offset += instr.width_at(offset);
        }
        offset
    }
}

struct IrTryItem {
    start: DexLabel,
    end: DexLabel,
    handlers: Vec<IrCatchHandler>,
    catch_all: Option<DexLabel>,
}

pub(super) struct IrCatchHandler {
    pub(super) handler_type: String,
    pub(super) handler: DexLabel,
}

enum IrInstr {
    Const4 {
        dst: u8,
        literal: i8,
    },
    Const16 {
        dst: u8,
        literal: i16,
    },
    Const32 {
        dst: u8,
        literal: i32,
    },
    ConstString {
        dst: u8,
        value: String,
    },
    MoveFrom16 {
        dst: u8,
        src: u16,
        kind: ValueKind,
    },
    MoveException {
        dst: u8,
    },
    IfCmp {
        op: IfCmpOp,
        left: u8,
        right: u8,
        target: DexLabel,
    },
    IfEqz {
        reg: u8,
        target: DexLabel,
    },
    IfNez {
        reg: u8,
        target: DexLabel,
    },
    Goto16 {
        target: DexLabel,
    },
    PackedSwitch {
        reg: u8,
        first_key: i32,
        targets: Vec<DexLabel>,
        default_target: DexLabel,
    },
    SparseSwitch {
        reg: u8,
        keys: Vec<i32>,
        targets: Vec<DexLabel>,
        default_target: DexLabel,
    },
    NewInstance {
        dst: u8,
        ty: String,
    },
    CheckCast {
        reg: u8,
        ty: String,
    },
    InstanceOf {
        dst: u8,
        obj: u8,
        ty: String,
    },
    ArrayLength {
        dst: u8,
        array: u8,
    },
    NewArray {
        dst: u8,
        size: u8,
        ty: String,
    },
    Aget {
        dst: u8,
        array: u8,
        index: u8,
        kind: ValueKind,
    },
    Aput {
        src: u8,
        array: u8,
        index: u8,
        kind: ValueKind,
    },
    InvokeDirect {
        args: Vec<u8>,
        method: MethodRef,
    },
    InvokeVirtual {
        args: Vec<u8>,
        method: MethodRef,
    },
    InvokeStatic {
        args: Vec<u8>,
        method: MethodRef,
    },
    InvokeInterface {
        args: Vec<u8>,
        method: MethodRef,
    },
    InvokeDirectRange {
        first_reg: u16,
        arg_words: u8,
        method: MethodRef,
    },
    InvokeStaticRange {
        first_reg: u16,
        arg_words: u8,
        method: MethodRef,
    },
    InvokeVirtualRange {
        first_reg: u16,
        arg_words: u8,
        method: MethodRef,
    },
    InvokeInterfaceRange {
        first_reg: u16,
        arg_words: u8,
        method: MethodRef,
    },
    SputObject {
        src: u8,
        field: FieldRef,
    },
    Iget {
        dst: u8,
        obj: u8,
        field: FieldRef,
        kind: ValueKind,
    },
    Iput {
        src: u8,
        obj: u8,
        field: FieldRef,
        kind: ValueKind,
    },
    Sget {
        dst: u8,
        field: FieldRef,
        kind: ValueKind,
    },
    Sput {
        src: u8,
        field: FieldRef,
        kind: ValueKind,
    },
    IntBinOp {
        op: DexIntBinOp,
        dst: u8,
        left: u8,
        right: u8,
    },
    IntBinOpLit8 {
        op: DexIntLit8Op,
        dst: u8,
        src: u8,
        literal: i8,
    },
    IntBinOpLit16 {
        op: DexIntLit16Op,
        dst: u8,
        src: u8,
        literal: i16,
    },
    MoveResult {
        dst: u8,
    },
    MoveResultWide {
        dst: u8,
    },
    MoveResultObject {
        dst: u8,
    },
    Return {
        src: u8,
    },
    ReturnWide {
        src: u8,
    },
    ReturnObject {
        src: u8,
    },
    Throw {
        src: u8,
    },
    ReturnVoid,
}

#[derive(Clone, Copy)]
pub(super) enum IfCmpOp {
    Eq,
    Ne,
    Lt,
    Ge,
    Gt,
    Le,
}

#[derive(Clone, Copy)]
pub(super) enum DexIntBinOp {
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    Ushr,
}

#[derive(Clone, Copy)]
pub(super) enum DexIntLit8Op {
    Add,
    Rsub,
    Mul,
    Div,
    Rem,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    Ushr,
}

#[derive(Clone, Copy)]
pub(super) enum DexIntLit16Op {
    Add,
    Rsub,
    Mul,
    Div,
    Rem,
    And,
    Or,
    Xor,
}

impl DexIntBinOp {
    fn opcode(self) -> u16 {
        match self {
            DexIntBinOp::Add => 0x0090,
            DexIntBinOp::Sub => 0x0091,
            DexIntBinOp::Mul => 0x0092,
            DexIntBinOp::Div => 0x0093,
            DexIntBinOp::Rem => 0x0094,
            DexIntBinOp::And => 0x0095,
            DexIntBinOp::Or => 0x0096,
            DexIntBinOp::Xor => 0x0097,
            DexIntBinOp::Shl => 0x0098,
            DexIntBinOp::Shr => 0x0099,
            DexIntBinOp::Ushr => 0x009a,
        }
    }
}

impl DexIntLit16Op {
    fn opcode(self) -> u16 {
        match self {
            DexIntLit16Op::Add => 0x00d0,
            DexIntLit16Op::Rsub => 0x00d1,
            DexIntLit16Op::Mul => 0x00d2,
            DexIntLit16Op::Div => 0x00d3,
            DexIntLit16Op::Rem => 0x00d4,
            DexIntLit16Op::And => 0x00d5,
            DexIntLit16Op::Or => 0x00d6,
            DexIntLit16Op::Xor => 0x00d7,
        }
    }
}

impl DexIntLit8Op {
    fn opcode(self) -> u16 {
        match self {
            DexIntLit8Op::Add => 0x00d8,
            DexIntLit8Op::Rsub => 0x00d9,
            DexIntLit8Op::Mul => 0x00da,
            DexIntLit8Op::Div => 0x00db,
            DexIntLit8Op::Rem => 0x00dc,
            DexIntLit8Op::And => 0x00dd,
            DexIntLit8Op::Or => 0x00de,
            DexIntLit8Op::Xor => 0x00df,
            DexIntLit8Op::Shl => 0x00e0,
            DexIntLit8Op::Shr => 0x00e1,
            DexIntLit8Op::Ushr => 0x00e2,
        }
    }
}

impl IfCmpOp {
    fn opcode(self) -> u16 {
        match self {
            IfCmpOp::Eq => 0x0032,
            IfCmpOp::Ne => 0x0033,
            IfCmpOp::Lt => 0x0034,
            IfCmpOp::Ge => 0x0035,
            IfCmpOp::Gt => 0x0036,
            IfCmpOp::Le => 0x0037,
        }
    }

    fn name(self) -> &'static str {
        match self {
            IfCmpOp::Eq => "if-eq",
            IfCmpOp::Ne => "if-ne",
            IfCmpOp::Lt => "if-lt",
            IfCmpOp::Ge => "if-ge",
            IfCmpOp::Gt => "if-gt",
            IfCmpOp::Le => "if-le",
        }
    }

    pub(super) fn invert(self) -> Self {
        match self {
            IfCmpOp::Eq => IfCmpOp::Ne,
            IfCmpOp::Ne => IfCmpOp::Eq,
            IfCmpOp::Lt => IfCmpOp::Ge,
            IfCmpOp::Ge => IfCmpOp::Lt,
            IfCmpOp::Gt => IfCmpOp::Le,
            IfCmpOp::Le => IfCmpOp::Gt,
        }
    }
}

impl IrInstr {
    fn width_at(&self, offset: usize) -> usize {
        match self {
            IrInstr::Const4 { .. } => 1,
            IrInstr::Const16 { .. } => 2,
            IrInstr::Const32 { .. } => 3,
            IrInstr::ConstString { .. } => 2,
            IrInstr::MoveFrom16 { .. } => 2,
            IrInstr::MoveException { .. } => 1,
            IrInstr::IfCmp { .. } => 2,
            IrInstr::IfEqz { .. } | IrInstr::IfNez { .. } => 2,
            IrInstr::Goto16 { .. } => 2,
            IrInstr::PackedSwitch { targets, .. } => 5 + switch_payload_padding(offset + 5) + 4 + targets.len() * 2,
            IrInstr::SparseSwitch { keys, .. } => 5 + switch_payload_padding(offset + 5) + 2 + keys.len() * 4,
            IrInstr::NewInstance { .. } => 2,
            IrInstr::CheckCast { .. } => 2,
            IrInstr::InstanceOf { .. } => 2,
            IrInstr::ArrayLength { .. } => 1,
            IrInstr::NewArray { .. } => 2,
            IrInstr::Aget { .. } | IrInstr::Aput { .. } => 2,
            IrInstr::InvokeDirect { .. }
            | IrInstr::InvokeVirtual { .. }
            | IrInstr::InvokeStatic { .. }
            | IrInstr::InvokeInterface { .. } => 3,
            IrInstr::InvokeDirectRange { .. }
            | IrInstr::InvokeStaticRange { .. }
            | IrInstr::InvokeVirtualRange { .. }
            | IrInstr::InvokeInterfaceRange { .. } => 3,
            IrInstr::SputObject { .. } => 2,
            IrInstr::Iget { .. } | IrInstr::Iput { .. } | IrInstr::Sget { .. } | IrInstr::Sput { .. } => 2,
            IrInstr::IntBinOp { .. } | IrInstr::IntBinOpLit8 { .. } | IrInstr::IntBinOpLit16 { .. } => 2,
            IrInstr::MoveResult { .. } | IrInstr::MoveResultWide { .. } => 1,
            IrInstr::MoveResultObject { .. } => 1,
            IrInstr::Return { .. } | IrInstr::ReturnWide { .. } => 1,
            IrInstr::ReturnObject { .. } => 1,
            IrInstr::Throw { .. } => 1,
            IrInstr::ReturnVoid => 1,
        }
    }

    fn emit(self, code: &mut DexCode, offset: usize, labels: &[Option<usize>]) -> Result<(), String> {
        match self {
            IrInstr::Const4 { dst, literal } => {
                require_nibble(dst, "const/4 dst")?;
                if !(-8..=7).contains(&literal) {
                    return Err(format!("const/4 literal out of range: {}", literal));
                }
                code.raw(0x0012 | ((dst as u16) << 8) | (((literal as i16 as u16) & 0x0f) << 12));
            }
            IrInstr::Const16 { dst, literal } => {
                require_byte(dst, "const/16 dst")?;
                code.raw(0x0013 | ((dst as u16) << 8));
                code.raw(literal as u16);
            }
            IrInstr::Const32 { dst, literal } => {
                require_byte(dst, "const/32 dst")?;
                code.raw(0x0014 | ((dst as u16) << 8));
                code.raw(literal as u32 as u16);
                code.raw(((literal as u32) >> 16) as u16);
            }
            IrInstr::ConstString { dst, value } => {
                require_byte(dst, "const-string dst")?;
                code.raw(0x001a | ((dst as u16) << 8));
                code.string_idx(value);
            }
            IrInstr::MoveFrom16 { dst, src, kind } => {
                require_byte(dst, "move/from16 dst")?;
                let opcode = match kind {
                    ValueKind::Wide => 0x0005,
                    ValueKind::Object => 0x0008,
                    ValueKind::Narrow | ValueKind::Boolean | ValueKind::Byte | ValueKind::Char | ValueKind::Short => {
                        0x0002
                    }
                };
                code.raw(opcode | ((dst as u16) << 8));
                code.raw(src);
            }
            IrInstr::MoveException { dst } => {
                require_byte(dst, "move-exception dst")?;
                code.raw(0x000d | ((dst as u16) << 8));
            }
            IrInstr::IfCmp {
                op,
                left,
                right,
                target,
            } => {
                require_nibble(left, "if-cmp left")?;
                require_nibble(right, "if-cmp right")?;
                code.raw(op.opcode() | ((left as u16) << 8) | ((right as u16) << 12));
                code.raw(branch_offset(offset, target, labels, op.name())? as u16);
            }
            IrInstr::IfEqz { reg, target } => {
                require_byte(reg, "if-eqz reg")?;
                code.raw(0x0038 | ((reg as u16) << 8));
                code.raw(branch_offset(offset, target, labels, "if-eqz")? as u16);
            }
            IrInstr::IfNez { reg, target } => {
                require_byte(reg, "if-nez reg")?;
                code.raw(0x0039 | ((reg as u16) << 8));
                code.raw(branch_offset(offset, target, labels, "if-nez")? as u16);
            }
            IrInstr::Goto16 { target } => {
                code.raw(0x0029);
                code.raw(branch_offset(offset, target, labels, "goto/16")? as u16);
            }
            IrInstr::PackedSwitch {
                reg,
                first_key,
                targets,
                default_target,
            } => {
                require_byte(reg, "packed-switch reg")?;
                code.raw(0x002b | ((reg as u16) << 8));
                let payload_offset = 5 + switch_payload_padding(offset + 5);
                write_i32_code_units(code, payload_offset as i32);
                code.raw(0x0029);
                code.raw(branch_offset(offset + 3, default_target, labels, "packed-switch default goto")? as u16);
                if payload_offset > 5 {
                    code.raw(0x0000);
                }
                code.raw(0x0100);
                code.raw(targets.len() as u16);
                write_i32_code_units(code, first_key);
                for target in targets {
                    write_i32_code_units(code, branch_offset_i32(offset, target, labels, "packed-switch target")?);
                }
            }
            IrInstr::SparseSwitch {
                reg,
                keys,
                targets,
                default_target,
            } => {
                require_byte(reg, "sparse-switch reg")?;
                if keys.len() != targets.len() {
                    return Err("sparse-switch key/target count mismatch".to_string());
                }
                code.raw(0x002c | ((reg as u16) << 8));
                let payload_offset = 5 + switch_payload_padding(offset + 5);
                write_i32_code_units(code, payload_offset as i32);
                code.raw(0x0029);
                code.raw(branch_offset(offset + 3, default_target, labels, "sparse-switch default goto")? as u16);
                if payload_offset > 5 {
                    code.raw(0x0000);
                }
                code.raw(0x0200);
                code.raw(keys.len() as u16);
                for key in &keys {
                    write_i32_code_units(code, *key);
                }
                for target in targets {
                    write_i32_code_units(code, branch_offset_i32(offset, target, labels, "sparse-switch target")?);
                }
            }
            IrInstr::NewInstance { dst, ty } => {
                require_byte(dst, "new-instance dst")?;
                code.raw(0x0022 | ((dst as u16) << 8));
                code.type_idx(ty);
            }
            IrInstr::CheckCast { reg, ty } => {
                require_byte(reg, "check-cast reg")?;
                code.raw(0x001f | ((reg as u16) << 8));
                code.type_idx(ty);
            }
            IrInstr::InstanceOf { dst, obj, ty } => {
                require_nibble(dst, "instance-of dst")?;
                require_nibble(obj, "instance-of obj")?;
                code.raw(0x0020 | ((dst as u16) << 8) | ((obj as u16) << 12));
                code.type_idx(ty);
            }
            IrInstr::ArrayLength { dst, array } => {
                require_nibble(dst, "array-length dst")?;
                require_nibble(array, "array-length array")?;
                code.raw(0x0021 | ((dst as u16) << 8) | ((array as u16) << 12));
            }
            IrInstr::NewArray { dst, size, ty } => {
                require_nibble(dst, "new-array dst")?;
                require_nibble(size, "new-array size")?;
                code.raw(0x0023 | ((dst as u16) << 8) | ((size as u16) << 12));
                code.type_idx(ty);
            }
            IrInstr::Aget {
                dst,
                array,
                index,
                kind,
            } => {
                require_byte(dst, "aget dst")?;
                require_byte(array, "aget array")?;
                require_byte(index, "aget index")?;
                code.raw(array_opcode(false, kind) | ((dst as u16) << 8));
                code.raw((array as u16) | ((index as u16) << 8));
            }
            IrInstr::Aput {
                src,
                array,
                index,
                kind,
            } => {
                require_byte(src, "aput src")?;
                require_byte(array, "aput array")?;
                require_byte(index, "aput index")?;
                code.raw(array_opcode(true, kind) | ((src as u16) << 8));
                code.raw((array as u16) | ((index as u16) << 8));
            }
            IrInstr::InvokeDirect { args, method } => {
                emit_invoke35c(code, 0x70, &args, method)?;
            }
            IrInstr::InvokeVirtual { args, method } => {
                emit_invoke35c(code, 0x6e, &args, method)?;
            }
            IrInstr::InvokeStatic { args, method } => {
                emit_invoke35c(code, 0x71, &args, method)?;
            }
            IrInstr::InvokeInterface { args, method } => {
                emit_invoke35c(code, 0x72, &args, method)?;
            }
            IrInstr::InvokeDirectRange {
                first_reg,
                arg_words,
                method,
            } => {
                emit_invoke3rc(code, 0x76, first_reg, arg_words, method)?;
            }
            IrInstr::InvokeStaticRange {
                first_reg,
                arg_words,
                method,
            } => {
                emit_invoke3rc(code, 0x77, first_reg, arg_words, method)?;
            }
            IrInstr::InvokeVirtualRange {
                first_reg,
                arg_words,
                method,
            } => {
                emit_invoke3rc(code, 0x74, first_reg, arg_words, method)?;
            }
            IrInstr::InvokeInterfaceRange {
                first_reg,
                arg_words,
                method,
            } => {
                emit_invoke3rc(code, 0x78, first_reg, arg_words, method)?;
            }
            IrInstr::SputObject { src, field } => {
                require_byte(src, "sput-object src")?;
                code.raw(0x0069 | ((src as u16) << 8));
                code.field_idx(field);
            }
            IrInstr::Iget { dst, obj, field, kind } => {
                require_nibble(dst, "iget dst")?;
                require_nibble(obj, "iget obj")?;
                code.raw(field_opcode(false, false, kind) | ((dst as u16) << 8) | ((obj as u16) << 12));
                code.field_idx(field);
            }
            IrInstr::Iput { src, obj, field, kind } => {
                require_nibble(src, "iput src")?;
                require_nibble(obj, "iput obj")?;
                code.raw(field_opcode(false, true, kind) | ((src as u16) << 8) | ((obj as u16) << 12));
                code.field_idx(field);
            }
            IrInstr::Sget { dst, field, kind } => {
                require_byte(dst, "sget dst")?;
                code.raw(field_opcode(true, false, kind) | ((dst as u16) << 8));
                code.field_idx(field);
            }
            IrInstr::Sput { src, field, kind } => {
                require_byte(src, "sput src")?;
                code.raw(field_opcode(true, true, kind) | ((src as u16) << 8));
                code.field_idx(field);
            }
            IrInstr::IntBinOp { op, dst, left, right } => {
                require_byte(dst, "int binop dst")?;
                require_byte(left, "int binop left")?;
                require_byte(right, "int binop right")?;
                code.raw(op.opcode() | ((dst as u16) << 8));
                code.raw((left as u16) | ((right as u16) << 8));
            }
            IrInstr::IntBinOpLit8 { op, dst, src, literal } => {
                require_byte(dst, "int binop/lit8 dst")?;
                require_byte(src, "int binop/lit8 src")?;
                code.raw(op.opcode() | ((dst as u16) << 8));
                code.raw((src as u16) | (((literal as i16 as u16) & 0xff) << 8));
            }
            IrInstr::IntBinOpLit16 { op, dst, src, literal } => {
                require_nibble(dst, "int binop/lit16 dst")?;
                require_nibble(src, "int binop/lit16 src")?;
                code.raw(op.opcode() | ((dst as u16) << 8) | ((src as u16) << 12));
                code.raw(literal as u16);
            }
            IrInstr::MoveResult { dst } => {
                require_byte(dst, "move-result dst")?;
                code.raw(0x000a | ((dst as u16) << 8));
            }
            IrInstr::MoveResultWide { dst } => {
                require_byte(dst, "move-result-wide dst")?;
                code.raw(0x000b | ((dst as u16) << 8));
            }
            IrInstr::MoveResultObject { dst } => {
                require_byte(dst, "move-result-object dst")?;
                code.raw(0x000c | ((dst as u16) << 8));
            }
            IrInstr::Return { src } => {
                require_byte(src, "return src")?;
                code.raw(0x000f | ((src as u16) << 8));
            }
            IrInstr::ReturnWide { src } => {
                require_byte(src, "return-wide src")?;
                code.raw(0x0010 | ((src as u16) << 8));
            }
            IrInstr::ReturnObject { src } => {
                require_byte(src, "return-object src")?;
                code.raw(0x0011 | ((src as u16) << 8));
            }
            IrInstr::Throw { src } => {
                require_byte(src, "throw src")?;
                code.raw(0x0027 | ((src as u16) << 8));
            }
            IrInstr::ReturnVoid => {
                code.raw(0x000e);
            }
        }
        Ok(())
    }
}

fn emit_invoke35c(code: &mut DexCode, opcode: u16, args: &[u8], method: MethodRef) -> Result<(), String> {
    if args.len() > 5 {
        return Err(format!("invoke supports at most 5 args, got {}", args.len()));
    }
    for (idx, reg) in args.iter().enumerate() {
        require_nibble(*reg, &format!("invoke arg {}", idx))?;
    }
    let mut regs = [0u8; 5];
    for (idx, reg) in args.iter().enumerate() {
        regs[idx] = *reg;
    }
    let g = if args.len() == 5 { regs[4] } else { 0 };
    code.raw(opcode | ((g as u16) << 8) | ((args.len() as u16) << 12));
    code.method_idx(method);
    code.raw((regs[0] as u16) | ((regs[1] as u16) << 4) | ((regs[2] as u16) << 8) | ((regs[3] as u16) << 12));
    Ok(())
}

fn emit_invoke3rc(
    code: &mut DexCode,
    opcode: u16,
    first_reg: u16,
    arg_words: u8,
    method: MethodRef,
) -> Result<(), String> {
    code.raw(opcode | ((arg_words as u16) << 8));
    code.method_idx(method);
    code.raw(first_reg);
    Ok(())
}

#[derive(Clone, Copy, Debug)]
pub(super) enum ValueKind {
    Narrow,
    Wide,
    Object,
    Boolean,
    Byte,
    Char,
    Short,
}

pub(super) fn value_kind_from_descriptor(desc: &str) -> Result<ValueKind, String> {
    match desc {
        "Z" => Ok(ValueKind::Boolean),
        "B" => Ok(ValueKind::Byte),
        "C" => Ok(ValueKind::Char),
        "S" => Ok(ValueKind::Short),
        "I" | "F" => Ok(ValueKind::Narrow),
        "J" | "D" => Ok(ValueKind::Wide),
        value if return_is_object(value) => Ok(ValueKind::Object),
        other => Err(format!("unsupported value descriptor '{}'", other)),
    }
}

fn field_opcode(is_static: bool, is_put: bool, kind: ValueKind) -> u16 {
    match (is_static, is_put, kind) {
        (false, false, ValueKind::Narrow) => 0x52,
        (false, false, ValueKind::Wide) => 0x53,
        (false, false, ValueKind::Object) => 0x54,
        (false, false, ValueKind::Boolean) => 0x55,
        (false, false, ValueKind::Byte) => 0x56,
        (false, false, ValueKind::Char) => 0x57,
        (false, false, ValueKind::Short) => 0x58,
        (false, true, ValueKind::Narrow) => 0x59,
        (false, true, ValueKind::Wide) => 0x5a,
        (false, true, ValueKind::Object) => 0x5b,
        (false, true, ValueKind::Boolean) => 0x5c,
        (false, true, ValueKind::Byte) => 0x5d,
        (false, true, ValueKind::Char) => 0x5e,
        (false, true, ValueKind::Short) => 0x5f,
        (true, false, ValueKind::Narrow) => 0x60,
        (true, false, ValueKind::Wide) => 0x61,
        (true, false, ValueKind::Object) => 0x62,
        (true, false, ValueKind::Boolean) => 0x63,
        (true, false, ValueKind::Byte) => 0x64,
        (true, false, ValueKind::Char) => 0x65,
        (true, false, ValueKind::Short) => 0x66,
        (true, true, ValueKind::Narrow) => 0x67,
        (true, true, ValueKind::Wide) => 0x68,
        (true, true, ValueKind::Object) => 0x69,
        (true, true, ValueKind::Boolean) => 0x6a,
        (true, true, ValueKind::Byte) => 0x6b,
        (true, true, ValueKind::Char) => 0x6c,
        (true, true, ValueKind::Short) => 0x6d,
    }
}

fn array_opcode(is_put: bool, kind: ValueKind) -> u16 {
    match (is_put, kind) {
        (false, ValueKind::Narrow) => 0x44,
        (false, ValueKind::Wide) => 0x45,
        (false, ValueKind::Object) => 0x46,
        (false, ValueKind::Boolean) => 0x47,
        (false, ValueKind::Byte) => 0x48,
        (false, ValueKind::Char) => 0x49,
        (false, ValueKind::Short) => 0x4a,
        (true, ValueKind::Narrow) => 0x4b,
        (true, ValueKind::Wide) => 0x4c,
        (true, ValueKind::Object) => 0x4d,
        (true, ValueKind::Boolean) => 0x4e,
        (true, ValueKind::Byte) => 0x4f,
        (true, ValueKind::Char) => 0x50,
        (true, ValueKind::Short) => 0x51,
    }
}

fn branch_offset(
    source_offset: usize,
    target: DexLabel,
    labels: &[Option<usize>],
    opname: &str,
) -> Result<i16, String> {
    let target_offset = labels
        .get(target.0)
        .and_then(|v| *v)
        .ok_or_else(|| format!("{} target label {} is not bound", opname, target.0))?;
    let delta = target_offset as isize - source_offset as isize;
    if delta < i16::MIN as isize || delta > i16::MAX as isize {
        return Err(format!("{} branch offset out of range: {}", opname, delta));
    }
    Ok(delta as i16)
}

fn label_offset(target: DexLabel, labels: &[Option<usize>], opname: &str) -> Result<usize, String> {
    labels
        .get(target.0)
        .and_then(|v| *v)
        .ok_or_else(|| format!("{} label {} is not bound", opname, target.0))
}

fn branch_offset_i32(
    source_offset: usize,
    target: DexLabel,
    labels: &[Option<usize>],
    opname: &str,
) -> Result<i32, String> {
    let target_offset = labels
        .get(target.0)
        .and_then(|v| *v)
        .ok_or_else(|| format!("{} target label {} is not bound", opname, target.0))?;
    let delta = target_offset as isize - source_offset as isize;
    if delta < i32::MIN as isize || delta > i32::MAX as isize {
        return Err(format!("{} branch offset out of range: {}", opname, delta));
    }
    Ok(delta as i32)
}

fn switch_payload_padding(offset_after_goto: usize) -> usize {
    offset_after_goto & 1
}

fn write_i32_code_units(code: &mut DexCode, value: i32) {
    let value = value as u32;
    code.raw((value & 0xffff) as u16);
    code.raw((value >> 16) as u16);
}

fn require_nibble(value: u8, what: &str) -> Result<(), String> {
    if value > 0x0f {
        return Err(format!(
            "{} register out of range for nibble encoding: v{}",
            what, value
        ));
    }
    Ok(())
}

fn require_byte(value: u8, what: &str) -> Result<(), String> {
    if value == u8::MAX {
        return Err(format!("{} invalid register v{}", what, value));
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub(in crate::jsapi::java::java_hook_api) enum CodeWord {
    Raw(u16),
    String(String),
    Type(String),
    Field(FieldRef),
    Method(MethodRef),
}
