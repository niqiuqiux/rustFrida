use std::collections::{BTreeMap, BTreeSet};

use super::dex_ir::{CodeWord, DexCatchHandler, DexCode};
use super::{FieldRef, MethodRef, ProtoSpec, ACC_FINAL, ACC_PUBLIC};

const TYPE_HEADER_ITEM: u16 = 0x0000;
const TYPE_STRING_ID_ITEM: u16 = 0x0001;
const TYPE_TYPE_ID_ITEM: u16 = 0x0002;
const TYPE_PROTO_ID_ITEM: u16 = 0x0003;
const TYPE_FIELD_ID_ITEM: u16 = 0x0004;
const TYPE_METHOD_ID_ITEM: u16 = 0x0005;
const TYPE_CLASS_DEF_ITEM: u16 = 0x0006;
const TYPE_MAP_LIST: u16 = 0x1000;
const TYPE_TYPE_LIST: u16 = 0x1001;
const TYPE_CLASS_DATA_ITEM: u16 = 0x2000;
const TYPE_CODE_ITEM: u16 = 0x2001;
const TYPE_STRING_DATA_ITEM: u16 = 0x2002;

impl ProtoSpec {
    fn shorty(&self) -> String {
        let mut out = String::with_capacity(self.params.len() + 1);
        out.push(shorty_char(&self.return_type));
        for param in &self.params {
            out.push(shorty_char(param));
        }
        out
    }
}

#[derive(Clone, Debug)]
struct ClassField {
    field: FieldRef,
    access_flags: u32,
}

#[derive(Clone, Debug)]
struct ClassMethod {
    method: MethodRef,
    access_flags: u32,
    code: Option<DexCode>,
}

#[derive(Clone, Debug)]
pub(super) struct DexClass {
    class_type: String,
    access_flags: u32,
    super_type: String,
    source_file: Option<String>,
    static_fields: Vec<ClassField>,
    instance_fields: Vec<ClassField>,
    direct_methods: Vec<ClassMethod>,
    virtual_methods: Vec<ClassMethod>,
}

impl DexClass {
    pub(super) fn new(class_type: impl Into<String>) -> Self {
        Self {
            class_type: class_type.into(),
            access_flags: ACC_PUBLIC | ACC_FINAL,
            super_type: "Ljava/lang/Object;".to_string(),
            source_file: None,
            static_fields: Vec::new(),
            instance_fields: Vec::new(),
            direct_methods: Vec::new(),
            virtual_methods: Vec::new(),
        }
    }

    pub(super) fn source_file(mut self, source_file: impl Into<String>) -> Self {
        self.source_file = Some(source_file.into());
        self
    }

    pub(super) fn super_type(mut self, super_type: impl Into<String>) -> Self {
        self.super_type = super_type.into();
        self
    }

    pub(super) fn static_field(&mut self, name: &str, type_name: &str, access_flags: u32) -> FieldRef {
        let field = FieldRef::new(self.class_type.clone(), type_name.to_string(), name.to_string());
        self.static_fields.push(ClassField {
            field: field.clone(),
            access_flags,
        });
        field
    }

    pub(super) fn direct_method(
        &mut self,
        name: &str,
        return_type: &str,
        params: Vec<String>,
        access_flags: u32,
        code: DexCode,
    ) -> MethodRef {
        let method = MethodRef::new(
            self.class_type.clone(),
            name.to_string(),
            return_type.to_string(),
            params,
        );
        self.direct_methods.push(ClassMethod {
            method: method.clone(),
            access_flags,
            code: Some(code),
        });
        method
    }

    pub(super) fn native_direct_method(
        &mut self,
        name: &str,
        return_type: &str,
        params: Vec<String>,
        access_flags: u32,
    ) -> MethodRef {
        let method = MethodRef::new(
            self.class_type.clone(),
            name.to_string(),
            return_type.to_string(),
            params,
        );
        self.direct_methods.push(ClassMethod {
            method: method.clone(),
            access_flags,
            code: None,
        });
        method
    }

    pub(super) fn virtual_method(
        &mut self,
        name: &str,
        return_type: &str,
        params: Vec<String>,
        access_flags: u32,
        code: DexCode,
    ) -> MethodRef {
        let method = MethodRef::new(
            self.class_type.clone(),
            name.to_string(),
            return_type.to_string(),
            params,
        );
        self.virtual_methods.push(ClassMethod {
            method: method.clone(),
            access_flags,
            code: Some(code),
        });
        method
    }
}

pub(super) struct DexBuilder {
    classes: Vec<DexClass>,
    field_refs: BTreeSet<FieldRef>,
    method_refs: BTreeSet<MethodRef>,
}

impl DexBuilder {
    pub(super) fn new() -> Self {
        Self {
            classes: Vec::new(),
            field_refs: BTreeSet::new(),
            method_refs: BTreeSet::new(),
        }
    }

    pub(super) fn add_class(&mut self, class: DexClass) {
        self.classes.push(class);
    }

    /// 目前生成的 helper dex 只引用方法，不引用字段，所以还没有调用方。留着是因为
    /// field_ids 段本身是写出去的，缺的只是往里加项的入口。
    #[allow(dead_code)]
    pub(super) fn add_field_ref(&mut self, field: FieldRef) -> FieldRef {
        self.field_refs.insert(field.clone());
        field
    }

    pub(super) fn add_method_ref(&mut self, method: MethodRef) -> MethodRef {
        self.method_refs.insert(method.clone());
        method
    }

    pub(super) fn build(mut self) -> Result<Vec<u8>, String> {
        if self.classes.is_empty() {
            return Err("dex builder requires at least one class".to_string());
        }

        for class in &self.classes {
            for field in class.static_fields.iter().chain(class.instance_fields.iter()) {
                self.field_refs.insert(field.field.clone());
            }
            for method in class.direct_methods.iter().chain(class.virtual_methods.iter()) {
                self.method_refs.insert(method.method.clone());
                if let Some(code) = &method.code {
                    for word in &code.insns {
                        match word {
                            CodeWord::Field(field) => {
                                self.field_refs.insert(field.clone());
                            }
                            CodeWord::Method(method) => {
                                self.method_refs.insert(method.clone());
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        let mut string_set = BTreeSet::<String>::new();
        let mut type_set = BTreeSet::<String>::new();
        let mut proto_set = BTreeSet::<ProtoSpec>::new();

        for class in &self.classes {
            type_set.insert(class.class_type.clone());
            type_set.insert(class.super_type.clone());
            if let Some(source_file) = &class.source_file {
                string_set.insert(source_file.clone());
            }
        }
        for field in &self.field_refs {
            type_set.insert(field.class_type.clone());
            type_set.insert(field.type_name.clone());
            string_set.insert(field.name.clone());
        }
        for method in &self.method_refs {
            type_set.insert(method.class_type.clone());
            type_set.insert(method.proto.return_type.clone());
            for param in &method.proto.params {
                type_set.insert(param.clone());
            }
            string_set.insert(method.name.clone());
            string_set.insert(method.proto.shorty());
            proto_set.insert(method.proto.clone());
        }
        for class in &self.classes {
            for method in class.direct_methods.iter().chain(class.virtual_methods.iter()) {
                if let Some(code) = &method.code {
                    for item in &code.try_items {
                        for handler in &item.handlers {
                            type_set.insert(handler.handler_type.clone());
                        }
                    }
                    for word in &code.insns {
                        match word {
                            CodeWord::String(value) => {
                                string_set.insert(value.clone());
                            }
                            CodeWord::Type(ty) => {
                                type_set.insert(ty.clone());
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
        for ty in &type_set {
            string_set.insert(ty.clone());
        }

        let strings: Vec<String> = string_set.into_iter().collect();
        let string_idx: BTreeMap<String, u32> =
            strings.iter().enumerate().map(|(i, s)| (s.clone(), i as u32)).collect();

        let mut types: Vec<String> = type_set.into_iter().collect();
        types.sort_by_key(|ty| string_idx[ty]);
        let type_idx: BTreeMap<String, u32> = types.iter().enumerate().map(|(i, s)| (s.clone(), i as u32)).collect();

        let mut protos: Vec<ProtoSpec> = proto_set.into_iter().collect();
        protos.sort_by_key(|p| {
            (
                type_idx[&p.return_type],
                p.params.iter().map(|ty| type_idx[ty]).collect::<Vec<_>>(),
                string_idx[&p.shorty()],
            )
        });
        let proto_idx: BTreeMap<ProtoSpec, u32> =
            protos.iter().enumerate().map(|(i, p)| (p.clone(), i as u32)).collect();

        let mut fields: Vec<FieldRef> = self.field_refs.into_iter().collect();
        fields.sort_by_key(|f| (type_idx[&f.class_type], string_idx[&f.name], type_idx[&f.type_name]));
        let field_idx: BTreeMap<FieldRef, u32> =
            fields.iter().enumerate().map(|(i, f)| (f.clone(), i as u32)).collect();

        let mut methods: Vec<MethodRef> = self.method_refs.into_iter().collect();
        methods.sort_by_key(|m| (type_idx[&m.class_type], string_idx[&m.name], proto_idx[&m.proto]));
        let method_idx: BTreeMap<MethodRef, u32> =
            methods.iter().enumerate().map(|(i, m)| (m.clone(), i as u32)).collect();

        let mut type_lists = BTreeSet::<Vec<u32>>::new();
        for proto in &protos {
            if !proto.params.is_empty() {
                type_lists.insert(proto.params.iter().map(|p| type_idx[p]).collect());
            }
        }

        let header_size = 0x70usize;
        let string_ids_off = header_size;
        let type_ids_off = align4(string_ids_off + strings.len() * 4);
        let proto_ids_off = align4(type_ids_off + types.len() * 4);
        let field_ids_off = align4(proto_ids_off + protos.len() * 12);
        let method_ids_off = align4(field_ids_off + fields.len() * 8);
        let class_defs_off = align4(method_ids_off + methods.len() * 8);
        let data_off = align4(class_defs_off + self.classes.len() * 32);

        let mut data = Vec::new();
        let mut type_list_offsets = BTreeMap::<Vec<u32>, u32>::new();
        let first_type_list_off = if type_lists.is_empty() { 0 } else { data_off as u32 };
        for key in &type_lists {
            align_vec4(&mut data);
            let off = (data_off + data.len()) as u32;
            write_u32(&mut data, key.len() as u32);
            for idx in key {
                write_u16(&mut data, *idx as u16);
            }
            if key.len() % 2 != 0 {
                write_u16(&mut data, 0);
            }
            type_list_offsets.insert(key.clone(), off);
        }

        let first_string_data_off = (data_off + data.len()) as u32;
        let mut string_data_offsets = Vec::with_capacity(strings.len());
        for s in &strings {
            string_data_offsets.push((data_off + data.len()) as u32);
            write_uleb128(&mut data, s.chars().count() as u32);
            data.extend_from_slice(s.as_bytes());
            data.push(0);
        }

        let mut class_data_offsets = Vec::<u32>::with_capacity(self.classes.len());
        let mut code_patch_offsets = Vec::<(usize, DexCode)>::new();
        for class in &self.classes {
            align_vec4(&mut data);
            let class_data_off = (data_off + data.len()) as u32;
            class_data_offsets.push(class_data_off);
            write_class_data_item(&mut data, class, &field_idx, &method_idx, &mut code_patch_offsets)?;
        }

        let mut code_offsets = Vec::<u32>::new();
        for (patch_pos, code) in code_patch_offsets {
            align_vec4(&mut data);
            let code_off = (data_off + data.len()) as u32;
            data[patch_pos..patch_pos + 5].copy_from_slice(&uleb128_padded5(code_off));
            code_offsets.push(code_off);
            write_code_item(&mut data, &code, &string_idx, &type_idx, &field_idx, &method_idx)?;
        }

        align_vec4(&mut data);
        let map_off = (data_off + data.len()) as u32;
        write_map_list(
            &mut data,
            &[
                (TYPE_HEADER_ITEM, 1, 0),
                (
                    TYPE_STRING_ID_ITEM,
                    strings.len() as u32,
                    section_off(strings.len(), string_ids_off),
                ),
                (
                    TYPE_TYPE_ID_ITEM,
                    types.len() as u32,
                    section_off(types.len(), type_ids_off),
                ),
                (
                    TYPE_PROTO_ID_ITEM,
                    protos.len() as u32,
                    section_off(protos.len(), proto_ids_off),
                ),
                (
                    TYPE_FIELD_ID_ITEM,
                    fields.len() as u32,
                    section_off(fields.len(), field_ids_off),
                ),
                (
                    TYPE_METHOD_ID_ITEM,
                    methods.len() as u32,
                    section_off(methods.len(), method_ids_off),
                ),
                (TYPE_CLASS_DEF_ITEM, self.classes.len() as u32, class_defs_off as u32),
                (TYPE_MAP_LIST, 1, map_off),
                (TYPE_TYPE_LIST, type_lists.len() as u32, first_type_list_off),
                (TYPE_CLASS_DATA_ITEM, self.classes.len() as u32, class_data_offsets[0]),
                (
                    TYPE_CODE_ITEM,
                    code_offsets.len() as u32,
                    code_offsets.first().copied().unwrap_or(0),
                ),
                (TYPE_STRING_DATA_ITEM, strings.len() as u32, first_string_data_off),
            ],
        );

        let file_size = data_off + data.len();
        let mut out = vec![0u8; data_off];
        out.extend_from_slice(&data);

        out[0..8].copy_from_slice(b"dex\n035\0");
        write_u32_at(&mut out, 32, file_size as u32);
        write_u32_at(&mut out, 36, header_size as u32);
        write_u32_at(&mut out, 40, 0x1234_5678);
        write_u32_at(&mut out, 52, map_off);
        write_u32_at(&mut out, 56, strings.len() as u32);
        write_u32_at(&mut out, 60, section_off(strings.len(), string_ids_off));
        write_u32_at(&mut out, 64, types.len() as u32);
        write_u32_at(&mut out, 68, section_off(types.len(), type_ids_off));
        write_u32_at(&mut out, 72, protos.len() as u32);
        write_u32_at(&mut out, 76, section_off(protos.len(), proto_ids_off));
        write_u32_at(&mut out, 80, fields.len() as u32);
        write_u32_at(&mut out, 84, section_off(fields.len(), field_ids_off));
        write_u32_at(&mut out, 88, methods.len() as u32);
        write_u32_at(&mut out, 92, section_off(methods.len(), method_ids_off));
        write_u32_at(&mut out, 96, self.classes.len() as u32);
        write_u32_at(&mut out, 100, class_defs_off as u32);
        write_u32_at(&mut out, 104, (file_size - data_off) as u32);
        write_u32_at(&mut out, 108, data_off as u32);

        for (i, off) in string_data_offsets.iter().enumerate() {
            write_u32_at(&mut out, string_ids_off + i * 4, *off);
        }
        for (i, ty) in types.iter().enumerate() {
            write_u32_at(&mut out, type_ids_off + i * 4, string_idx[ty]);
        }
        for (i, proto) in protos.iter().enumerate() {
            let params: Vec<u32> = proto.params.iter().map(|p| type_idx[p]).collect();
            let params_off = if params.is_empty() {
                0
            } else {
                type_list_offsets[&params]
            };
            let off = proto_ids_off + i * 12;
            write_u32_at(&mut out, off, string_idx[&proto.shorty()]);
            write_u32_at(&mut out, off + 4, type_idx[&proto.return_type]);
            write_u32_at(&mut out, off + 8, params_off);
        }
        for (i, field) in fields.iter().enumerate() {
            let off = field_ids_off + i * 8;
            write_u16_at(&mut out, off, type_idx[&field.class_type] as u16);
            write_u16_at(&mut out, off + 2, type_idx[&field.type_name] as u16);
            write_u32_at(&mut out, off + 4, string_idx[&field.name]);
        }
        for (i, method) in methods.iter().enumerate() {
            let off = method_ids_off + i * 8;
            write_u16_at(&mut out, off, type_idx[&method.class_type] as u16);
            write_u16_at(&mut out, off + 2, proto_idx[&method.proto] as u16);
            write_u32_at(&mut out, off + 4, string_idx[&method.name]);
        }

        for (i, class) in self.classes.iter().enumerate() {
            let off = class_defs_off + i * 32;
            write_u32_at(&mut out, off, type_idx[&class.class_type]);
            write_u32_at(&mut out, off + 4, class.access_flags);
            write_u32_at(&mut out, off + 8, type_idx[&class.super_type]);
            write_u32_at(&mut out, off + 12, 0);
            let source_idx = class.source_file.as_ref().map(|s| string_idx[s]).unwrap_or(0xffff_ffff);
            write_u32_at(&mut out, off + 16, source_idx);
            write_u32_at(&mut out, off + 20, 0);
            write_u32_at(&mut out, off + 24, class_data_offsets[i]);
            write_u32_at(&mut out, off + 28, 0);
        }

        let signature = sha1_digest(&out[32..]);
        out[12..32].copy_from_slice(&signature);
        let checksum = adler32(&out[12..]);
        write_u32_at(&mut out, 8, checksum);

        Ok(out)
    }
}

fn write_class_data_item(
    out: &mut Vec<u8>,
    class: &DexClass,
    field_idx: &BTreeMap<FieldRef, u32>,
    method_idx: &BTreeMap<MethodRef, u32>,
    code_patch_offsets: &mut Vec<(usize, DexCode)>,
) -> Result<(), String> {
    write_uleb128(out, class.static_fields.len() as u32);
    write_uleb128(out, class.instance_fields.len() as u32);
    write_uleb128(out, class.direct_methods.len() as u32);
    write_uleb128(out, class.virtual_methods.len() as u32);

    write_encoded_fields(out, &class.static_fields, field_idx)?;
    write_encoded_fields(out, &class.instance_fields, field_idx)?;
    write_encoded_methods(out, &class.direct_methods, method_idx, code_patch_offsets)?;
    write_encoded_methods(out, &class.virtual_methods, method_idx, code_patch_offsets)?;
    Ok(())
}

fn write_encoded_fields(
    out: &mut Vec<u8>,
    fields: &[ClassField],
    field_idx: &BTreeMap<FieldRef, u32>,
) -> Result<(), String> {
    let mut entries = fields
        .iter()
        .map(|f| {
            let idx = *field_idx
                .get(&f.field)
                .ok_or_else(|| format!("missing field index for {}", f.field.name))?;
            Ok((idx, f.access_flags))
        })
        .collect::<Result<Vec<_>, String>>()?;
    entries.sort_by_key(|(idx, _)| *idx);

    let mut prev = 0u32;
    for (idx, access) in entries {
        write_uleb128(out, idx - prev);
        write_uleb128(out, access);
        prev = idx;
    }
    Ok(())
}

fn write_encoded_methods(
    out: &mut Vec<u8>,
    methods: &[ClassMethod],
    method_idx: &BTreeMap<MethodRef, u32>,
    code_patch_offsets: &mut Vec<(usize, DexCode)>,
) -> Result<(), String> {
    let mut entries = methods
        .iter()
        .map(|m| {
            let idx = *method_idx
                .get(&m.method)
                .ok_or_else(|| format!("missing method index for {}", m.method.name))?;
            Ok((idx, m.access_flags, m.code.clone()))
        })
        .collect::<Result<Vec<_>, String>>()?;
    entries.sort_by_key(|(idx, _, _)| *idx);

    let mut prev = 0u32;
    for (idx, access, code) in entries {
        write_uleb128(out, idx - prev);
        write_uleb128(out, access);
        if let Some(code) = code {
            let patch_pos = out.len();
            out.extend_from_slice(&[0, 0, 0, 0, 0]);
            code_patch_offsets.push((patch_pos, code));
        } else {
            write_uleb128(out, 0);
        }
        prev = idx;
    }
    Ok(())
}

fn write_code_item(
    out: &mut Vec<u8>,
    code: &DexCode,
    string_idx: &BTreeMap<String, u32>,
    type_idx: &BTreeMap<String, u32>,
    field_idx: &BTreeMap<FieldRef, u32>,
    method_idx: &BTreeMap<MethodRef, u32>,
) -> Result<(), String> {
    write_u16(out, code.registers_size);
    write_u16(out, code.ins_size);
    write_u16(out, code.outs_size);
    write_u16(out, code.try_items.len() as u16);
    write_u32(out, 0);
    write_u32(out, code.insns.len() as u32);
    for word in &code.insns {
        match word {
            CodeWord::Raw(value) => write_u16(out, *value),
            CodeWord::String(value) => write_u16(out, lookup_u16(string_idx, value, "string")?),
            CodeWord::Type(ty) => write_u16(out, lookup_u16(type_idx, ty, "type")?),
            CodeWord::Field(field) => write_u16(out, lookup_u16(field_idx, field, "field")?),
            CodeWord::Method(method) => write_u16(out, lookup_u16(method_idx, method, "method")?),
        }
    }
    if !code.try_items.is_empty() {
        let (handler_offsets, handler_blob) = build_encoded_catch_handlers(code, type_idx)?;
        if code.insns.len() % 2 != 0 {
            write_u16(out, 0);
        }
        for (idx, item) in code.try_items.iter().enumerate() {
            write_u32(out, item.start_addr);
            write_u16(out, item.insn_count);
            write_u16(out, handler_offsets[idx]);
        }
        out.extend_from_slice(&handler_blob);
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct EncodedCatchHandler {
    handlers: Vec<DexCatchHandler>,
    catch_all_addr: Option<u32>,
}

fn build_encoded_catch_handlers(
    code: &DexCode,
    type_idx: &BTreeMap<String, u32>,
) -> Result<(Vec<u16>, Vec<u8>), String> {
    let mut unique_handlers: Vec<EncodedCatchHandler> = Vec::new();
    let mut handler_indices = Vec::with_capacity(code.try_items.len());
    for item in &code.try_items {
        if item.handlers.is_empty() && item.catch_all_addr.is_none() {
            return Err("try item requires at least one typed catch or catch-all handler".to_string());
        }
        let handler = EncodedCatchHandler {
            handlers: item.handlers.clone(),
            catch_all_addr: item.catch_all_addr,
        };
        let index = unique_handlers
            .iter()
            .position(|existing| existing == &handler)
            .unwrap_or_else(|| {
                unique_handlers.push(handler);
                unique_handlers.len() - 1
            });
        handler_indices.push(index);
    }

    let mut handler_blob = Vec::new();
    write_uleb128(&mut handler_blob, unique_handlers.len() as u32);
    let mut unique_offsets = Vec::with_capacity(unique_handlers.len());
    for handler in &unique_handlers {
        let offset = handler_blob.len();
        if offset > u16::MAX as usize {
            return Err(format!("encoded catch handler offset too large: {}", offset));
        }
        unique_offsets.push(offset as u16);

        if handler.catch_all_addr.is_some() {
            write_sleb128(&mut handler_blob, -(handler.handlers.len() as i32));
        } else {
            write_sleb128(&mut handler_blob, handler.handlers.len() as i32);
        }
        for typed in &handler.handlers {
            let type_index = *type_idx
                .get(&typed.handler_type)
                .ok_or_else(|| format!("missing catch type index for {}", typed.handler_type))?;
            write_uleb128(&mut handler_blob, type_index);
            write_uleb128(&mut handler_blob, typed.handler_addr);
        }
        if let Some(catch_all_addr) = handler.catch_all_addr {
            write_uleb128(&mut handler_blob, catch_all_addr);
        }
    }

    let mut handler_offsets = Vec::with_capacity(handler_indices.len());
    for index in handler_indices {
        let Some(offset) = unique_offsets.get(index).copied() else {
            return Err("internal encoded catch handler index error".to_string());
        };
        handler_offsets.push(offset);
    }
    Ok((handler_offsets, handler_blob))
}

fn lookup_u16<K: Ord + std::fmt::Debug>(map: &BTreeMap<K, u32>, key: &K, kind: &str) -> Result<u16, String> {
    let value = *map
        .get(key)
        .ok_or_else(|| format!("missing {} index for {:?}", kind, key))?;
    if value > u16::MAX as u32 {
        return Err(format!("{} index too large: {}", kind, value));
    }
    Ok(value as u16)
}

fn section_off(count: usize, offset: usize) -> u32 {
    if count == 0 {
        0
    } else {
        offset as u32
    }
}

fn shorty_char(descriptor: &str) -> char {
    match descriptor.as_bytes().first().copied() {
        Some(b'V') => 'V',
        Some(b'Z') => 'Z',
        Some(b'B') => 'B',
        Some(b'S') => 'S',
        Some(b'C') => 'C',
        Some(b'I') => 'I',
        Some(b'J') => 'J',
        Some(b'F') => 'F',
        Some(b'D') => 'D',
        _ => 'L',
    }
}

fn write_map_list(out: &mut Vec<u8>, entries: &[(u16, u32, u32)]) {
    let mut filtered: Vec<(u16, u32, u32)> = entries.iter().copied().filter(|(_, size, _)| *size != 0).collect();
    filtered.sort_by_key(|(_, _, off)| *off);
    write_u32(out, filtered.len() as u32);
    for (ty, size, off) in filtered {
        write_u16(out, ty);
        write_u16(out, 0);
        write_u32(out, size);
        write_u32(out, off);
    }
}

fn uleb128_padded5(mut value: u32) -> [u8; 5] {
    let mut out = [0u8; 5];
    for (i, slot) in out.iter_mut().enumerate() {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if i != 4 {
            byte |= 0x80;
        }
        *slot = byte;
    }
    out
}

fn write_uleb128(out: &mut Vec<u8>, mut value: u32) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

fn write_sleb128(out: &mut Vec<u8>, mut value: i32) {
    loop {
        let byte = (value as u8) & 0x7f;
        value >>= 7;
        let done = (value == 0 && (byte & 0x40) == 0) || (value == -1 && (byte & 0x40) != 0);
        out.push(if done { byte } else { byte | 0x80 });
        if done {
            break;
        }
    }
}

fn align4(value: usize) -> usize {
    (value + 3) & !3
}

fn align_vec4(out: &mut Vec<u8>) {
    while out.len() % 4 != 0 {
        out.push(0);
    }
}

fn write_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_u16_at(out: &mut [u8], offset: usize, value: u16) {
    out[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32_at(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn adler32(bytes: &[u8]) -> u32 {
    const MOD: u32 = 65_521;
    let mut a = 1u32;
    let mut b = 0u32;
    for byte in bytes {
        a = (a + *byte as u32) % MOD;
        b = (b + a) % MOD;
    }
    (b << 16) | a
}

fn sha1_digest(bytes: &[u8]) -> [u8; 20] {
    let mut h0 = 0x6745_2301u32;
    let mut h1 = 0xefcd_ab89u32;
    let mut h2 = 0x98ba_dcfeu32;
    let mut h3 = 0x1032_5476u32;
    let mut h4 = 0xc3d2_e1f0u32;

    let bit_len = (bytes.len() as u64) * 8;
    let mut msg = bytes.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            let off = i * 4;
            w[i] = u32::from_be_bytes([chunk[off], chunk[off + 1], chunk[off + 2], chunk[off + 3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;

        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5a82_7999),
                20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
                _ => (b ^ c ^ d, 0xca62_c1d6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut out = [0u8; 20];
    out[0..4].copy_from_slice(&h0.to_be_bytes());
    out[4..8].copy_from_slice(&h1.to_be_bytes());
    out[8..12].copy_from_slice(&h2.to_be_bytes());
    out[12..16].copy_from_slice(&h3.to_be_bytes());
    out[16..20].copy_from_slice(&h4.to_be_bytes());
    out
}
