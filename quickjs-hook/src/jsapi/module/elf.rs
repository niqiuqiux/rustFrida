// ============================================================================
// ELF symbol lookup — Frida-style (gum_elf_module)
//
// Strategy: file from disk first, memory at base_address as fallback.
// One read, one pass through .symtab, batch-extract all needed symbols.
//
// Reference: gumelfmodule.c — gum_elf_module_load_file_data():
//   1. g_mapped_file_new(path) → mmap from disk
//   2. If file not readable (ONLINE mode) → use base_address as data pointer
// ============================================================================

/// Batch lookup symbols from an ELF module's `.symtab` or `.dynsym`.
///
/// Strategy (Frida-style, gum_elf_module):
/// 1. Try read file from disk → parse `.symtab`/`.dynsym` in one pass
/// 2. If file not accessible → read from in-memory ELF mapping at base_address
///
/// **IFUNC handling**: on Android ARM64, libc exports many symbols
/// (`strlen`, `memcpy`, `strcmp`, ...) as `STT_GNU_IFUNC`. The `.symtab`
/// address is the *resolver*, not the real implementation. We detect
/// IFUNC entries and call the resolver with the bionic (hwcap, &arg)
/// convention so the returned address matches `dlsym()`.
///
/// Returns HashMap of found symbols: name -> resolved runtime address.
unsafe fn elf_module_find_symbols(
    file_path: &str,
    base_address: u64,
    wanted: &[&str],
) -> HashMap<String, u64> {
    if wanted.is_empty() || !is_symbol_scan_candidate_path(file_path, base_address) {
        return HashMap::new();
    }

    let is_memfd_module = is_memfd_path(file_path);
    let wanted_set: HashSet<&str> = wanted.iter().copied().collect();
    let mut result = HashMap::new();
    let mut ifunc_names: HashSet<String> = HashSet::new();

    // Compute load_bias from in-memory program headers
    let load_bias = elf_compute_load_bias(base_address);

    // Strategy 1: read file from disk (one read, one pass).
    let mut file_symbol_tables_scanned = false;
    let file_read_ok = if is_memfd_module {
        false
    } else if let Ok(data) = std::fs::read(file_path) {
        file_symbol_tables_scanned =
            elf_find_symbols_in_data(&data, &wanted_set, load_bias, &mut result, &mut ifunc_names);
        true
    } else {
        false
    };

    if (!file_read_ok || !file_symbol_tables_scanned) && wanted_set.iter().any(|name| !result.contains_key(*name)) {
        // Strategy 2: read the runtime dynamic symbol table from PT_DYNAMIC.
        // This keeps lookups exact while avoiding a hard dependency on readable
        // on-disk files or section headers, which stripped in-memory ELFs often
        // do not map.
        elf_find_symbols_in_dynamic_memory(
            base_address,
            &wanted_set,
            load_bias,
            &mut result,
            &mut ifunc_names,
        );
    }

    if !file_read_ok
        && !is_memfd_module
        && wanted_set.iter().any(|name| !result.contains_key(*name))
    {
        // Strategy 3: read section headers from in-memory ELF at base_address.
        // Section headers usually are not in any PT_LOAD for stripped libs, so
        // this rarely succeeds — keep the diagnostic in verbose mode only.
        crate::jsapi::console::output_verbose(&format!(
            "[module] file read failed for {}, trying section headers in memory at {:#x}",
            file_path, base_address
        ));
        elf_find_symbols_in_memory(
            base_address,
            &wanted_set,
            load_bias,
            &mut result,
            &mut ifunc_names,
        );
    }

    resolve_ifunc_entries(&ifunc_names, &mut result);
    result
}

const MAX_ELF_PHDRS: usize = 1024;
const MAX_ELF_SHDRS: usize = 8192;
const MAX_FILE_SYMBOLS: usize = 1_000_000;
const MAX_FILE_RELAS: usize = 1_000_000;
const MAX_MEMORY_SYMBOLS: usize = 262_144;
const MAX_MEMORY_TABLE_BYTES: usize = 128 * 1024 * 1024;
const MAX_MEMORY_STRTAB_BYTES: usize = 128 * 1024 * 1024;

fn checked_file_range(data_len: usize, offset: usize, size: usize) -> Option<std::ops::Range<usize>> {
    let end = offset.checked_add(size)?;
    if end <= data_len {
        Some(offset..end)
    } else {
        None
    }
}

fn elf_section_headers_from_data(data_len: usize, ehdr: &Elf64Ehdr) -> Option<(usize, usize, usize)> {
    let shdr_off = usize::try_from(ehdr.e_shoff).ok()?;
    let shdr_size = ehdr._e_shentsize as usize;
    let shnum = ehdr.e_shnum as usize;
    if shdr_off == 0 || shdr_size < std::mem::size_of::<Elf64Shdr>() || shnum == 0 || shnum > MAX_ELF_SHDRS {
        return None;
    }
    let shdr_bytes = shnum.checked_mul(shdr_size)?;
    checked_file_range(data_len, shdr_off, shdr_bytes)?;
    Some((shdr_off, shdr_size, shnum))
}

unsafe fn elf_section_header_at<'a>(
    data: &'a [u8],
    shdr_off: usize,
    shdr_size: usize,
    index: usize,
) -> Option<&'a Elf64Shdr> {
    let offset = shdr_off.checked_add(index.checked_mul(shdr_size)?)?;
    checked_file_range(data.len(), offset, std::mem::size_of::<Elf64Shdr>())?;
    Some(&*(data.as_ptr().add(offset) as *const Elf64Shdr))
}

fn bounded_entry_count(byte_size: u64, entry_size: usize, max_entries: usize) -> Option<usize> {
    if entry_size == 0 {
        return None;
    }
    let byte_size = usize::try_from(byte_size).ok()?;
    let count = byte_size / entry_size;
    if count <= max_entries {
        Some(count)
    } else {
        None
    }
}

fn checked_indexed_addr(base: u64, index: usize, entry_size: usize) -> Option<u64> {
    let offset = index.checked_mul(entry_size)?;
    base.checked_add(offset as u64)
}

/// Bionic's ARM64 IFUNC resolver argument block.
/// Reference: `linker/linker_relocate.cpp`.
#[repr(C)]
struct IfuncArg {
    size: u64,
    hwcap: u64,
    hwcap2: u64,
}

const IFUNC_ARG_HWCAP: u64 = 1 << 62;

/// Lazily-initialized (hwcap_arg, ifunc_arg) tuple reused by every IFUNC call.
fn ifunc_resolver_context() -> (u64, &'static IfuncArg) {
    static CTX: std::sync::OnceLock<(u64, IfuncArg)> = std::sync::OnceLock::new();
    let cached = CTX.get_or_init(|| unsafe {
        let arg = IfuncArg {
            size: std::mem::size_of::<IfuncArg>() as u64,
            hwcap: libc::getauxval(libc::AT_HWCAP),
            hwcap2: libc::getauxval(libc::AT_HWCAP2),
        };
        let hwcap_arg = arg.hwcap | IFUNC_ARG_HWCAP;
        (hwcap_arg, arg)
    });
    (cached.0, &cached.1)
}

/// Call an IFUNC resolver with the bionic (hwcap, &arg) ABI; returns the resolved
/// runtime address, or 0 if the resolver returns null.
unsafe fn resolve_ifunc_address(resolver_addr: u64) -> u64 {
    if resolver_addr == 0 {
        return 0;
    }
    type IfuncResolver = unsafe extern "C" fn(u64, *const IfuncArg) -> u64;
    let resolver: IfuncResolver = std::mem::transmute(resolver_addr);
    let (hwcap_arg, arg) = ifunc_resolver_context();
    resolver(hwcap_arg, arg)
}

/// Call IFUNC resolvers to replace resolver addresses with real implementation
/// addresses for symbols captured by the batch lookup above.
unsafe fn resolve_ifunc_entries(ifunc_names: &HashSet<String>, result: &mut HashMap<String, u64>) {
    for name in ifunc_names {
        let Some(resolver_addr) = result.get(name).copied() else {
            continue;
        };
        let resolved = resolve_ifunc_address(resolver_addr);
        if resolved != 0 {
            result.insert(name.clone(), resolved);
        }
    }
}

/// Compute load_bias from in-memory ELF at base_address.
/// load_bias = base_address - first_PT_LOAD.p_vaddr
unsafe fn elf_compute_load_bias(base_address: u64) -> u64 {
    if base_address == 0 {
        return 0;
    }
    if !is_addr_accessible(base_address, std::mem::size_of::<Elf64Ehdr>()) {
        return base_address;
    }

    let ehdr = &*(base_address as *const Elf64Ehdr);
    if ehdr.e_ident[0..4] != *b"\x7fELF" || ehdr.e_ident[4] != 2 {
        return base_address;
    }

    let phnum = ehdr.e_phnum as usize;
    let phentsize = ehdr.e_phentsize as usize;
    if phnum == 0 || phnum > MAX_ELF_PHDRS || phentsize < std::mem::size_of::<Elf64Phdr>() {
        return base_address;
    }
    let Some(phdr_base) = base_address.checked_add(ehdr.e_phoff) else {
        return base_address;
    };
    let Some(phdr_bytes) = phnum.checked_mul(phentsize) else {
        return base_address;
    };
    if !is_addr_accessible(phdr_base, phdr_bytes) {
        return base_address;
    }

    for i in 0..phnum {
        let Some(phdr_addr) = checked_indexed_addr(phdr_base, i, phentsize) else {
            return base_address;
        };
        let phdr = &*(phdr_addr as *const Elf64Phdr);
        if phdr.p_type == PT_LOAD {
            return base_address.wrapping_sub(phdr.p_vaddr);
        }
    }
    base_address
}

unsafe fn elf_find_symbols_in_dynamic_memory(
    base_address: u64,
    wanted: &HashSet<&str>,
    load_bias: u64,
    result: &mut HashMap<String, u64>,
    ifunc_names: &mut HashSet<String>,
) {
    if base_address == 0 || wanted.iter().all(|name| result.contains_key(*name)) {
        return;
    }

    let Some((symtab, strtab, strsz, nsyms)) = elf_dynamic_symbol_info(base_address, load_bias) else {
        return;
    };

    for idx in 0..nsyms {
        if wanted.iter().all(|name| result.contains_key(*name)) {
            break;
        }

        let sym = &*((symtab as *const Elf64Sym).add(idx));
        if sym.st_name == 0 || sym.st_value == 0 || sym.st_shndx == SHN_UNDEF {
            continue;
        }

        if let Some(name) = dynamic_symbol_name(strtab, strsz, sym.st_name) {
            if wanted.contains(name) && !result.contains_key(name) {
                result.insert(name.to_string(), load_bias + sym.st_value);
                if sym.st_type() == STT_GNU_IFUNC {
                    ifunc_names.insert(name.to_string());
                }
            }
        }
    }
}

unsafe fn elf_dynamic_symbol_info(base_address: u64, load_bias: u64) -> Option<(u64, u64, usize, usize)> {
    const MAX_DYN_ENTRIES: usize = 4096;
    const MAX_DYNAMIC_SYMBOLS: usize = 262_144;
    const MAX_DYNAMIC_STRTAB_BYTES: usize = 128 * 1024 * 1024;

    if !is_addr_accessible(base_address, std::mem::size_of::<Elf64Ehdr>()) {
        return None;
    }

    let ehdr = &*(base_address as *const Elf64Ehdr);
    if ehdr.e_ident[0..4] != *b"\x7fELF" || ehdr.e_ident[4] != 2 {
        return None;
    }

    let phnum = ehdr.e_phnum as usize;
    let phentsize = ehdr.e_phentsize as usize;
    if phnum == 0 || phnum > MAX_ELF_PHDRS || phentsize < std::mem::size_of::<Elf64Phdr>() {
        return None;
    }

    let phdr_base = base_address.checked_add(ehdr.e_phoff)?;
    let phdr_size = phnum.checked_mul(phentsize)?;
    if !is_addr_accessible(phdr_base, phdr_size) {
        return None;
    }

    let mut dynamic_addr = 0u64;
    let mut dynamic_size = 0usize;
    for idx in 0..phnum {
        let phdr = &*(checked_indexed_addr(phdr_base, idx, phentsize)? as *const Elf64Phdr);
        if phdr.p_type == PT_DYNAMIC {
            dynamic_addr = load_bias.checked_add(phdr.p_vaddr)?;
            dynamic_size = usize::try_from(phdr._p_memsz).ok()?;
            break;
        }
    }

    if dynamic_addr == 0 || dynamic_size < std::mem::size_of::<Elf64Dyn>() {
        return None;
    }

    let max_dyn_entries = (dynamic_size / std::mem::size_of::<Elf64Dyn>()).min(MAX_DYN_ENTRIES);
    let dynamic_bytes = max_dyn_entries.checked_mul(std::mem::size_of::<Elf64Dyn>())?;
    if !is_addr_accessible(dynamic_addr, dynamic_bytes) {
        return None;
    }

    let mut symtab = 0u64;
    let mut strtab = 0u64;
    let mut strsz = 0usize;
    let mut gnu_hash = 0u64;
    let mut sysv_hash = 0u64;

    let dynamic = dynamic_addr as *const Elf64Dyn;
    for idx in 0..max_dyn_entries {
        let dyn_entry = &*dynamic.add(idx);
        if dyn_entry.d_tag == DT_NULL {
            break;
        }

        match dyn_entry.d_tag {
            DT_SYMTAB => symtab = dynamic_ptr(load_bias, dyn_entry.d_val),
            DT_STRTAB => strtab = dynamic_ptr(load_bias, dyn_entry.d_val),
            DT_STRSZ => strsz = dyn_entry.d_val as usize,
            DT_GNU_HASH => gnu_hash = dynamic_ptr(load_bias, dyn_entry.d_val),
            DT_HASH => sysv_hash = dynamic_ptr(load_bias, dyn_entry.d_val),
            _ => {}
        }
    }

    if symtab == 0 || strtab == 0 || strsz == 0 || strsz > MAX_DYNAMIC_STRTAB_BYTES {
        return None;
    }

    let mut nsyms = dynamic_gnu_hash_nsyms(gnu_hash);
    if nsyms == 0 {
        nsyms = dynamic_sysv_hash_nsyms(sysv_hash);
    }
    if nsyms == 0 && strtab > symtab {
        nsyms = ((strtab - symtab) as usize) / std::mem::size_of::<Elf64Sym>();
    }
    if nsyms == 0 || nsyms > MAX_DYNAMIC_SYMBOLS {
        return None;
    }

    let symtab_size = nsyms.checked_mul(std::mem::size_of::<Elf64Sym>())?;
    if !is_addr_accessible(symtab, symtab_size) || !is_addr_accessible(strtab, strsz) {
        return None;
    }

    Some((symtab, strtab, strsz, nsyms))
}

fn dynamic_ptr(load_bias: u64, value: u64) -> u64 {
    if value >= load_bias {
        value
    } else {
        load_bias.wrapping_add(value)
    }
}

unsafe fn dynamic_gnu_hash_nsyms(gnu_hash: u64) -> usize {
    const MAX_GNU_BUCKETS: usize = 262_144;
    const MAX_GNU_CHAIN_SCAN: usize = 262_144;

    if gnu_hash == 0 || !is_addr_accessible(gnu_hash, 16) {
        return 0;
    }

    let gnu_hash = gnu_hash as *const u32;
    let nbuckets = *gnu_hash.add(0) as usize;
    let symoffset = *gnu_hash.add(1) as usize;
    let bloom_size = *gnu_hash.add(2) as usize;
    if nbuckets == 0 || nbuckets > MAX_GNU_BUCKETS || bloom_size > MAX_GNU_BUCKETS {
        return 0;
    }

    let bloom_u32_words = match bloom_size.checked_mul(std::mem::size_of::<usize>() / std::mem::size_of::<u32>()) {
        Some(words) => words,
        None => return 0,
    };
    let buckets_index = match 4usize.checked_add(bloom_u32_words) {
        Some(index) => index,
        None => return 0,
    };
    let buckets = gnu_hash.add(buckets_index);
    let bucket_bytes = match nbuckets.checked_mul(std::mem::size_of::<u32>()) {
        Some(bytes) => bytes,
        None => return 0,
    };
    if !is_addr_accessible(buckets as u64, bucket_bytes) {
        return 0;
    }

    let mut max_sym = 0usize;
    for idx in 0..nbuckets {
        max_sym = max_sym.max(*buckets.add(idx) as usize);
    }
    if max_sym < symoffset {
        return symoffset;
    }

    let chains = buckets.add(nbuckets);
    let mut chain_idx = max_sym - symoffset;
    for _ in 0..MAX_GNU_CHAIN_SCAN {
        let chain = chains.add(chain_idx);
        if !is_addr_accessible(chain as u64, std::mem::size_of::<u32>()) {
            return 0;
        }
        if (*chain & 1) != 0 {
            return symoffset + chain_idx + 1;
        }
        chain_idx += 1;
    }

    0
}

unsafe fn dynamic_sysv_hash_nsyms(sysv_hash: u64) -> usize {
    if sysv_hash == 0 || !is_addr_accessible(sysv_hash, 8) {
        return 0;
    }
    let sysv_hash = sysv_hash as *const u32;
    let nchain = *sysv_hash.add(1) as usize;
    if nchain > 262_144 {
        0
    } else {
        nchain
    }
}

unsafe fn dynamic_symbol_name(strtab: u64, strsz: usize, name_off: u32) -> Option<&'static str> {
    let name_off = name_off as usize;
    if name_off >= strsz {
        return None;
    }

    let ptr_addr = strtab.checked_add(name_off as u64)?;
    let ptr = ptr_addr as *const u8;
    let mut len = 0usize;
    while name_off + len < strsz && *ptr.add(len) != 0 {
        len += 1;
    }

    std::str::from_utf8(std::slice::from_raw_parts(ptr, len)).ok()
}

/// Find symbols in .symtab/.dynsym from file data (byte slice). One pass.
/// Symbols whose type is `STT_GNU_IFUNC` have their names recorded in
/// `ifunc_names` so the caller can resolve them after parsing.
fn elf_find_symbols_in_data(
    data: &[u8],
    wanted: &HashSet<&str>,
    load_bias: u64,
    result: &mut HashMap<String, u64>,
    ifunc_names: &mut HashSet<String>,
) -> bool {
    if data.len() < std::mem::size_of::<Elf64Ehdr>() {
        return false;
    }

    unsafe {
        let ehdr = &*(data.as_ptr() as *const Elf64Ehdr);
        if ehdr.e_ident[0..4] != *b"\x7fELF" || ehdr.e_ident[4] != 2 {
            return false;
        }

        let Some((shdr_off, shdr_size, shnum)) = elf_section_headers_from_data(data.len(), ehdr) else {
            return false;
        };

        // Scan both .symtab and .dynsym. Android's linker64 exposes some
        // public __loader_* names only in .dynsym while .symtab contains the
        // internal __dl___loader_* aliases, so preferring one table loses
        // valid lookups.
        let mut symtab_shdr: Option<&Elf64Shdr> = None;
        let mut dynsym_shdr: Option<&Elf64Shdr> = None;
        for i in 0..shnum {
            let Some(shdr) = elf_section_header_at(data, shdr_off, shdr_size, i) else {
                return false;
            };
            match shdr.sh_type {
                SHT_SYMTAB if symtab_shdr.is_none() => symtab_shdr = Some(shdr),
                SHT_DYNSYM if dynsym_shdr.is_none() => dynsym_shdr = Some(shdr),
                _ => {}
            }
        }

        let tables = [symtab_shdr, dynsym_shdr];
        let mut scanned_any_table = false;
        for symtab in tables.into_iter().flatten() {
            if wanted.iter().all(|name| result.contains_key(*name)) {
                break;
            }

            let strtab_idx = symtab.sh_link as usize;
            if strtab_idx >= shnum {
                continue;
            }
            let Some(strtab_shdr) = elf_section_header_at(data, shdr_off, shdr_size, strtab_idx) else {
                continue;
            };
            if strtab_shdr.sh_type != SHT_STRTAB {
                continue;
            }

            let Some(strtab_off) = usize::try_from(strtab_shdr.sh_offset).ok() else {
                continue;
            };
            let Some(strtab_size) = usize::try_from(strtab_shdr.sh_size).ok() else {
                continue;
            };
            let Some(strtab_range) = checked_file_range(data.len(), strtab_off, strtab_size) else {
                continue;
            };

            let Some(symtab_off) = usize::try_from(symtab.sh_offset).ok() else {
                continue;
            };
            let sym_size = if symtab.sh_entsize > 0 {
                symtab.sh_entsize as usize
            } else {
                std::mem::size_of::<Elf64Sym>()
            };
            if sym_size < std::mem::size_of::<Elf64Sym>() {
                continue;
            }
            let Some(nsyms) = bounded_entry_count(symtab.sh_size, sym_size, MAX_FILE_SYMBOLS) else {
                continue;
            };
            let Some(symtab_bytes) = nsyms.checked_mul(sym_size) else {
                continue;
            };
            if checked_file_range(data.len(), symtab_off, symtab_bytes).is_none() {
                continue;
            }

            scanned_any_table = true;
            for idx in 0..nsyms {
                if wanted.iter().all(|name| result.contains_key(*name)) {
                    break;
                }

                let Some(sym_off) = idx
                    .checked_mul(sym_size)
                    .and_then(|offset| symtab_off.checked_add(offset))
                else {
                    break;
                };
                let sym = &*(data.as_ptr().add(sym_off) as *const Elf64Sym);
                if sym.st_name == 0 || sym.st_value == 0 {
                    continue;
                }

                let Some(name_off) = strtab_range.start.checked_add(sym.st_name as usize) else {
                    continue;
                };
                if name_off >= strtab_range.end {
                    continue;
                }

                // Read null-terminated name
                let name_slice = &data[name_off..strtab_range.end];
                let name_len = name_slice.iter().position(|&b| b == 0).unwrap_or(0);
                if name_len == 0 {
                    continue;
                }

                if let Ok(name) = std::str::from_utf8(&name_slice[..name_len]) {
                    if wanted.contains(name) && !result.contains_key(name) {
                        result.insert(name.to_string(), load_bias.wrapping_add(sym.st_value));
                        if sym.st_type() == STT_GNU_IFUNC {
                            ifunc_names.insert(name.to_string());
                        }
                    }
                }
            }
        }
        scanned_any_table
    }
}

/// Find symbols in .symtab/.dynsym from in-memory ELF at base_address.
///
/// Fallback when file is not readable on disk.
/// Uses mincore(2) to check page accessibility before each read.
///
/// Reference: gumelfmodule.c line 570-572 — ONLINE mode fallback:
///   self->file_bytes = g_bytes_new_static(base_address, G_MAXSIZE - base_address)
unsafe fn elf_find_symbols_in_memory(
    base_address: u64,
    wanted: &HashSet<&str>,
    load_bias: u64,
    result: &mut HashMap<String, u64>,
    ifunc_names: &mut HashSet<String>,
) {
    if base_address == 0 {
        return;
    }

    // Check ELF header accessible
    if !is_addr_accessible(base_address, std::mem::size_of::<Elf64Ehdr>()) {
        return;
    }

    let ehdr = &*(base_address as *const Elf64Ehdr);
    if ehdr.e_ident[0..4] != *b"\x7fELF" || ehdr.e_ident[4] != 2 {
        return;
    }

    let shdr_size = ehdr._e_shentsize as usize;
    let shnum = ehdr.e_shnum as usize;
    if shdr_size < std::mem::size_of::<Elf64Shdr>() || shnum == 0 || shnum > MAX_ELF_SHDRS {
        return;
    }
    let Some(shdr_addr) = base_address.checked_add(ehdr.e_shoff) else {
        return;
    };
    let Some(shdr_bytes) = shnum.checked_mul(shdr_size) else {
        return;
    };
    if shdr_bytes > MAX_MEMORY_TABLE_BYTES {
        return;
    }

    // Check section headers accessible
    if !is_addr_accessible(shdr_addr, shdr_bytes) {
        crate::jsapi::console::output_verbose("[module] section headers not accessible in memory");
        return;
    }

    // Scan both tables for the same reason as the file-backed path above.
    let mut symtab_shdr: Option<Elf64ShdrCopy> = None;
    let mut dynsym_shdr: Option<Elf64ShdrCopy> = None;
    for i in 0..shnum {
        let Some(shdr_ptr) = checked_indexed_addr(shdr_addr, i, shdr_size) else {
            return;
        };
        let shdr = &*(shdr_ptr as *const Elf64Shdr);
        let copy = Elf64ShdrCopy {
            sh_offset: shdr.sh_offset,
            sh_size: shdr.sh_size,
            sh_link: shdr.sh_link,
            sh_entsize: shdr.sh_entsize,
        };
        match shdr.sh_type {
            SHT_SYMTAB if symtab_shdr.is_none() => symtab_shdr = Some(copy),
            SHT_DYNSYM if dynsym_shdr.is_none() => dynsym_shdr = Some(copy),
            _ => {}
        }
    }

    if symtab_shdr.is_none() && dynsym_shdr.is_none() {
        crate::jsapi::console::output_verbose(
            "[module] .symtab/.dynsym not found in memory ELF",
        );
        return;
    }

    let tables = [symtab_shdr, dynsym_shdr];
    for symtab in tables.into_iter().flatten() {
        if wanted.iter().all(|name| result.contains_key(*name)) {
            break;
        }

        let strtab_idx = symtab.sh_link as usize;
        if strtab_idx >= shnum {
            continue;
        }
        let Some(strtab_shdr_addr) = checked_indexed_addr(shdr_addr, strtab_idx, shdr_size) else {
            continue;
        };
        let strtab_shdr = &*(strtab_shdr_addr as *const Elf64Shdr);
        if strtab_shdr.sh_type != SHT_STRTAB {
            continue;
        }

        // Check .symtab/.dynsym and linked string table data are accessible.
        let Some(symtab_data_addr) = base_address.checked_add(symtab.sh_offset) else {
            continue;
        };
        let Some(strtab_data_addr) = base_address.checked_add(strtab_shdr.sh_offset) else {
            continue;
        };

        let sym_size = if symtab.sh_entsize > 0 {
            symtab.sh_entsize as usize
        } else {
            std::mem::size_of::<Elf64Sym>()
        };
        if sym_size < std::mem::size_of::<Elf64Sym>() {
            continue;
        }
        let Some(nsyms) = bounded_entry_count(symtab.sh_size, sym_size, MAX_MEMORY_SYMBOLS) else {
            continue;
        };
        let Some(symtab_bytes) = nsyms.checked_mul(sym_size) else {
            continue;
        };
        if symtab_bytes == 0 || symtab_bytes > MAX_MEMORY_TABLE_BYTES {
            continue;
        }
        let Some(strtab_size) = usize::try_from(strtab_shdr.sh_size).ok() else {
            continue;
        };
        if strtab_size == 0 || strtab_size > MAX_MEMORY_STRTAB_BYTES {
            continue;
        }

        if !is_addr_accessible(symtab_data_addr, symtab_bytes) {
            crate::jsapi::console::output_verbose("[module] symbol table data not accessible in memory");
            continue;
        }
        if !is_addr_accessible(strtab_data_addr, strtab_size) {
            crate::jsapi::console::output_verbose("[module] string table data not accessible in memory");
            continue;
        }

        crate::jsapi::console::output_verbose(&format!(
            "[module] reading symbol table from memory: {} symbols",
            nsyms
        ));

        for idx in 0..nsyms {
            if wanted.iter().all(|name| result.contains_key(*name)) {
                break;
            }

            let Some(sym_addr) = checked_indexed_addr(symtab_data_addr, idx, sym_size) else {
                break;
            };
            let sym = &*(sym_addr as *const Elf64Sym);
            if sym.st_name == 0 || sym.st_value == 0 {
                continue;
            }

            let name_off = sym.st_name as usize;
            if name_off >= strtab_size {
                continue;
            }

            let Some(name_addr) = strtab_data_addr.checked_add(name_off as u64) else {
                continue;
            };
            let name_ptr = name_addr as *const u8;
            let max_len = strtab_size - name_off;
            let name_slice = std::slice::from_raw_parts(name_ptr, max_len);
            let name_len = name_slice.iter().position(|&b| b == 0).unwrap_or(0);
            if name_len == 0 {
                continue;
            }

            if let Ok(name) = std::str::from_utf8(&name_slice[..name_len]) {
                if wanted.contains(name) && !result.contains_key(name) {
                    result.insert(name.to_string(), load_bias.wrapping_add(sym.st_value));
                    if sym.st_type() == STT_GNU_IFUNC {
                        ifunc_names.insert(name.to_string());
                    }
                }
            }
        }
    }
}

/// Minimal copy of Elf64Shdr fields needed for .symtab processing.
/// Avoids holding a reference into memory that might be invalidated.
struct Elf64ShdrCopy {
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_entsize: u64,
}
