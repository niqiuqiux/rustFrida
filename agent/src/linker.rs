//! Minimal linker-style helpers backed by `/proc/self/maps` and in-memory ELF
//! dynamic tables. This module intentionally avoids libc/linker APIs such as
//! `dladdr`, `dlopen`, `dlsym`, `dlclose`, and `dl_iterate_phdr`.

use libc::c_void;

#[derive(Clone, Debug)]
struct MapEntry {
    start: usize,
    end: usize,
    offset: usize,
    readable: bool,
    name: String,
}

#[derive(Clone, Debug)]
pub(crate) struct ResolvedSymbol {
    pub(crate) module: Option<String>,
    pub(crate) symbol: Option<String>,
}

#[repr(C)]
struct Elf64Ehdr {
    e_ident: [u8; 16],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

#[repr(C)]
struct Elf64Phdr {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
}

#[repr(C)]
struct Elf64Dyn {
    d_tag: i64,
    d_val: u64,
}

#[repr(C)]
struct Elf64Sym {
    st_name: u32,
    st_info: u8,
    st_other: u8,
    st_shndx: u16,
    st_value: u64,
    st_size: u64,
}

const EM_AARCH64: u16 = 183;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const DT_NULL: i64 = 0;
const DT_HASH: i64 = 4;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_STRSZ: i64 = 10;
const DT_GNU_HASH: i64 = 0x6ffffef5;
const SHN_UNDEF: u16 = 0;

pub(crate) fn resolve_symbol(addr: usize) -> ResolvedSymbol {
    let maps = parse_maps();
    let Some(map) = find_map_for_addr(addr, &maps) else {
        return ResolvedSymbol {
            module: None,
            symbol: None,
        };
    };

    let base = module_base_for_map(map, &maps);
    let module = if map.name.is_empty() {
        None
    } else {
        Some(map.name.rsplit('/').next().unwrap_or(map.name.as_str()).to_string())
    };

    let base_is_readable = maps.iter().any(|entry| entry.start == base && entry.readable);
    if map.name.is_empty() || !base_is_readable {
        return ResolvedSymbol { module, symbol: None };
    }

    ResolvedSymbol {
        module,
        symbol: unsafe { elf_find_nearest_symbol(base, addr) },
    }
}

pub(crate) fn is_address_mapped(addr: usize) -> bool {
    let maps = parse_maps();
    find_map_for_addr(addr, &maps).is_some()
}

fn parse_maps() -> Vec<MapEntry> {
    let Ok(raw) = std::fs::read_to_string("/proc/self/maps") else {
        return Vec::new();
    };

    raw.lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 5 {
                return None;
            }

            let mut range = parts[0].split('-');
            let start = usize::from_str_radix(range.next()?, 16).ok()?;
            let end = usize::from_str_radix(range.next()?, 16).ok()?;
            let offset = usize::from_str_radix(parts[2], 16).ok()?;
            let readable = parts[1].as_bytes().first() == Some(&b'r');
            let name = if parts.len() > 5 {
                parts[5..].join(" ")
            } else {
                String::new()
            };

            Some(MapEntry {
                start,
                end,
                offset,
                readable,
                name,
            })
        })
        .collect()
}

fn find_map_for_addr(addr: usize, maps: &[MapEntry]) -> Option<&MapEntry> {
    maps.iter().find(|m| addr >= m.start && addr < m.end)
}

fn module_base_for_map(map: &MapEntry, maps: &[MapEntry]) -> usize {
    maps.iter()
        .find(|m| m.offset == 0 && !m.name.is_empty() && m.name == map.name)
        .map(|m| m.start)
        .unwrap_or(map.start.saturating_sub(map.offset))
}

unsafe fn valid_elf(base: usize) -> bool {
    let ehdr = &*(base as *const Elf64Ehdr);
    ehdr.e_ident[0] == 0x7f
        && ehdr.e_ident[1] == b'E'
        && ehdr.e_ident[2] == b'L'
        && ehdr.e_ident[3] == b'F'
        && ehdr.e_ident[4] == 2
        && ehdr.e_ident[5] == 1
        && ehdr.e_machine == EM_AARCH64
        && ehdr.e_phoff != 0
        && ehdr.e_phnum != 0
}

unsafe fn ptr_from_dynamic(base: usize, value: u64) -> usize {
    let value = value as usize;
    if value >= base {
        value
    } else {
        base + value
    }
}

unsafe fn gnu_hash_nsyms(gnu_hash: *const u32) -> usize {
    if gnu_hash.is_null() {
        return 0;
    }

    let nbuckets = *gnu_hash.add(0) as usize;
    let symoffset = *gnu_hash.add(1) as usize;
    let bloom_size = *gnu_hash.add(2) as usize;
    let buckets = gnu_hash.add(4 + bloom_size * (std::mem::size_of::<usize>() / std::mem::size_of::<u32>()));
    let chains = buckets.add(nbuckets);

    let mut max_sym = 0usize;
    for i in 0..nbuckets {
        max_sym = max_sym.max(*buckets.add(i) as usize);
    }
    if max_sym < symoffset {
        return symoffset;
    }

    let mut i = max_sym - symoffset;
    while (*chains.add(i) & 1) == 0 {
        i += 1;
    }
    symoffset + i + 1
}

unsafe fn sysv_hash_nsyms(sysv_hash: *const u32) -> usize {
    if sysv_hash.is_null() {
        0
    } else {
        *sysv_hash.add(1) as usize
    }
}

unsafe fn elf_dynamic_info(base: usize) -> Option<(*const Elf64Sym, *const u8, usize, usize)> {
    if !valid_elf(base) {
        return None;
    }

    let ehdr = &*(base as *const Elf64Ehdr);
    let phdrs = (base + ehdr.e_phoff as usize) as *const Elf64Phdr;
    let mut load_bias = base;
    for i in 0..ehdr.e_phnum as usize {
        let phdr = &*phdrs.add(i);
        if phdr.p_type == PT_LOAD {
            load_bias = base.saturating_sub(phdr.p_vaddr as usize);
            break;
        }
    }

    let mut dynamic = std::ptr::null::<Elf64Dyn>();
    for i in 0..ehdr.e_phnum as usize {
        let phdr = &*phdrs.add(i);
        if phdr.p_type == PT_DYNAMIC {
            dynamic = (load_bias + phdr.p_vaddr as usize) as *const Elf64Dyn;
            break;
        }
    }
    if dynamic.is_null() {
        return None;
    }

    let mut symtab = std::ptr::null::<Elf64Sym>();
    let mut strtab = std::ptr::null::<u8>();
    let mut strsz = 0usize;
    let mut gnu_hash = std::ptr::null::<u32>();
    let mut sysv_hash = std::ptr::null::<u32>();

    let mut dynp = dynamic;
    while (*dynp).d_tag != DT_NULL {
        match (*dynp).d_tag {
            DT_SYMTAB => symtab = ptr_from_dynamic(load_bias, (*dynp).d_val) as *const Elf64Sym,
            DT_STRTAB => strtab = ptr_from_dynamic(load_bias, (*dynp).d_val) as *const u8,
            DT_STRSZ => strsz = (*dynp).d_val as usize,
            DT_GNU_HASH => gnu_hash = ptr_from_dynamic(load_bias, (*dynp).d_val) as *const u32,
            DT_HASH => sysv_hash = ptr_from_dynamic(load_bias, (*dynp).d_val) as *const u32,
            _ => {}
        }
        dynp = dynp.add(1);
    }

    if symtab.is_null() || strtab.is_null() || strsz == 0 {
        return None;
    }

    let mut nsyms = gnu_hash_nsyms(gnu_hash);
    if nsyms == 0 {
        nsyms = sysv_hash_nsyms(sysv_hash);
    }
    if nsyms == 0 && (strtab as usize) > (symtab as usize) {
        nsyms = ((strtab as usize) - (symtab as usize)) / std::mem::size_of::<Elf64Sym>();
    }
    if nsyms == 0 || nsyms > 262_144 {
        return None;
    }

    Some((symtab, strtab, strsz, nsyms))
}

unsafe fn symbol_name(strtab: *const u8, strsz: usize, name_off: u32) -> Option<&'static str> {
    let name_off = name_off as usize;
    if name_off >= strsz {
        return None;
    }

    let ptr = strtab.add(name_off);
    let mut len = 0usize;
    while name_off + len < strsz && *ptr.add(len) != 0 {
        len += 1;
    }

    std::str::from_utf8(std::slice::from_raw_parts(ptr, len)).ok()
}

unsafe fn elf_find_nearest_symbol(base: usize, addr: usize) -> Option<String> {
    let (symtab, strtab, strsz, nsyms) = elf_dynamic_info(base)?;
    let mut best_name = None;
    let mut best_addr = 0usize;

    for i in 0..nsyms {
        let sym = &*symtab.add(i);
        if sym.st_name == 0 || sym.st_shndx == SHN_UNDEF || sym.st_value == 0 {
            continue;
        }

        let sym_addr = base + sym.st_value as usize;
        if sym_addr <= addr && sym_addr >= best_addr {
            if let Some(name) = symbol_name(strtab, strsz, sym.st_name) {
                best_addr = sym_addr;
                best_name = Some(name.to_string());
            }
        }
    }

    best_name
}

#[allow(dead_code)]
pub(crate) fn exported_function_marker(_: *mut c_void) {}
