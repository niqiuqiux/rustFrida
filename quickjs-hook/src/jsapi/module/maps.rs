// ============================================================================
// /proc/self/maps parsing
// ============================================================================

/// Parse /proc/self/maps to find the libart.so address range and file path.
///
/// 只识别系统 ART：basename 精确为 `libart.so` 且落在系统路径白名单
/// (`/apex/`、`/system/`、`/system_ext/`)，避免命中 APK 打包的同名伪装文件。
pub(crate) fn probe_libart_range() -> (u64, u64) {
    let snapshot = ModuleSnapshot::load_current();
    let summary = snapshot.summarize_matching_paths(is_system_libart_path);
    let found_path = summary.as_ref().map(|summary| summary.first_path.clone());

    let _ = LIBART_PATH.set(found_path.clone());

    if let Some(summary) = summary {
        output_message(&format!(
            "[module] libart.so range: {:#x}-{:#x}, path: {:?}",
            summary.base, summary.end, found_path
        ));
        (summary.base, summary.end)
    } else {
        (0, 0)
    }
}

/// 通过 /proc/self/maps 获取指定模块的地址范围 (start, end)。
/// 返回 (0, 0) 表示未找到。
pub(crate) fn probe_module_range(module_name: &str) -> (u64, u64) {
    let snapshot = ModuleSnapshot::load_current();
    snapshot
        .summarize_matching_paths(|path| matches_exact_module_name(path, module_name))
        .map(|summary| (summary.base, summary.end))
        .unwrap_or((0, 0))
}

/// Find a loaded module's file path and base address by name.
/// Returns `None` if not found. Used by `module_dlsym` for direct ELF parsing.
fn find_module_path_and_base(module_name: &str) -> Option<(String, u64)> {
    {
        let guard = module_cache().read().unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(found) = guard.snapshot.find_module_path_and_base(module_name) {
            return Some(found);
        }
    }

    let snapshot = refresh_module_snapshot_cache();
    snapshot.find_module_path_and_base(module_name)
}

/// Parse /proc/self/maps to find a module's base address.
pub(crate) fn find_module_base(module_name: &str) -> u64 {
    {
        let guard = module_cache().read().unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(base) = guard.snapshot.find_module_base(module_name) {
            return base;
        }
    }

    let snapshot = refresh_module_snapshot_cache();
    snapshot.find_module_base(module_name).unwrap_or(0)
}

/// Module info from /proc/self/maps
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ModuleInfo {
    pub name: String,
    pub base: u64,
    pub size: u64,
    pub path: String,
}

impl ModuleInfo {
    fn from_path_range(path: String, base: u64, end: u64) -> Self {
        let name = module_basename(&path).to_string();
        Self {
            name,
            base,
            size: end - base,
            path,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ModuleMapEntry {
    start: u64,
    end: u64,
    prot_flags: i32,
    path: String,
}

impl ModuleMapEntry {
    fn from_proc_map_entry(entry: crate::jsapi::util::ProcMapEntry<'_>) -> Option<Self> {
        let path = entry.path?;
        if !is_proc_maps_module_path(path) {
            return None;
        }

        Some(Self {
            start: entry.start,
            end: entry.end,
            prot_flags: entry.prot_flags(),
            path: path.to_string(),
        })
    }

    fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }

    fn path_score(&self) -> u8 {
        if self.path.starts_with("/dev/") {
            1
        } else {
            0
        }
    }

    fn is_executable(&self) -> bool {
        self.prot_flags & libc::PROT_EXEC != 0
    }
}

#[derive(Clone, Debug, Default)]
struct ModuleSnapshot {
    entries: Vec<ModuleMapEntry>,
    modules: Vec<ModuleInfo>,
    modules_by_path: HashMap<String, ModuleInfo>,
}

impl ModuleSnapshot {
    fn from_entries(mut entries: Vec<ModuleMapEntry>) -> Self {
        entries.sort_by(|a, b| {
            a.start
                .cmp(&b.start)
                .then_with(|| a.end.cmp(&b.end))
                .then_with(|| a.path.cmp(&b.path))
        });

        let modules = aggregate_modules(&entries);
        let modules_by_path = modules
            .iter()
            .cloned()
            .map(|module| (module.path.clone(), module))
            .collect();

        Self {
            entries,
            modules,
            modules_by_path,
        }
    }

    fn load_current() -> Self {
        Self::from_entries(read_module_map_entries())
    }

    fn summarize_matching_paths(&self, mut matches_path: impl FnMut(&str) -> bool) -> Option<PathMapSummary> {
        let mut base = u64::MAX;
        let mut end = 0;
        let mut first_path = None;

        for entry in &self.entries {
            let path = entry.path.as_str();
            if !matches_path(path) {
                continue;
            }

            if entry.start < base {
                base = entry.start;
            }
            if entry.end > end {
                end = entry.end;
            }
            if first_path.is_none() {
                first_path = Some(path.to_string());
            }
        }

        first_path.map(|first_path| PathMapSummary { base, end, first_path })
    }

    fn find_module_base(&self, module_name: &str) -> Option<u64> {
        self.entries
            .iter()
            .find_map(|entry| matches_module_lookup_name(&entry.path, module_name).then_some(entry.start))
    }

    fn find_module_path_and_base(&self, module_name: &str) -> Option<(String, u64)> {
        const MAX_MODULE_CLUSTER_GAP: u64 = 64 * 1024 * 1024;

        let mut fallback: Option<(String, u64)> = None;
        let mut cluster_path: Option<String> = None;
        let mut cluster_base = 0u64;
        let mut cluster_end = 0u64;
        let mut cluster_has_exec = false;

        let finish_cluster = |path: &mut Option<String>,
                              base: u64,
                              has_exec: bool,
                              fallback: &mut Option<(String, u64)>|
         -> Option<(String, u64)> {
            let Some(path_value) = path.take() else {
                return None;
            };
            let candidate = (path_value, base);
            if has_exec {
                return Some(candidate);
            }
            if fallback.is_none() {
                *fallback = Some(candidate);
            }
            None
        };

        for entry in self
            .entries
            .iter()
            .filter(|entry| matches_module_lookup_name(&entry.path, module_name))
        {
            let same_cluster = cluster_path.as_ref().map_or(false, |path| {
                path == &entry.path && entry.start <= cluster_end.saturating_add(MAX_MODULE_CLUSTER_GAP)
            });

            if !same_cluster {
                if let Some(found) = finish_cluster(&mut cluster_path, cluster_base, cluster_has_exec, &mut fallback) {
                    return Some(found);
                }
                cluster_path = Some(entry.path.clone());
                cluster_base = entry.start;
                cluster_end = entry.end;
                cluster_has_exec = entry.is_executable();
                continue;
            }

            if entry.start < cluster_base {
                cluster_base = entry.start;
            }
            if entry.end > cluster_end {
                cluster_end = entry.end;
            }
            cluster_has_exec |= entry.is_executable();
        }

        if let Some(found) = finish_cluster(&mut cluster_path, cluster_base, cluster_has_exec, &mut fallback) {
            return Some(found);
        }

        fallback
    }

    fn find_module_by_address(&self, addr: u64) -> Option<(ModuleMapEntry, ModuleInfo)> {
        let entry = self
            .entries
            .iter()
            .filter(|entry| entry.contains(addr))
            .min_by(|a, b| {
                a.path_score()
                    .cmp(&b.path_score())
                    .then_with(|| (a.end - a.start).cmp(&(b.end - b.start)))
                    .then_with(|| b.start.cmp(&a.start))
            })
            .cloned()?;

        let module = self.modules_by_path.get(&entry.path)?.clone();
        Some((entry, module))
    }
}

#[derive(Clone, Debug)]
struct AddressLookupHint {
    entry: ModuleMapEntry,
    module: ModuleInfo,
}

#[derive(Clone, Debug, Default)]
struct ModuleCache {
    snapshot: ModuleSnapshot,
    lookup_hint: Option<AddressLookupHint>,
}

impl ModuleCache {
    fn new(snapshot: ModuleSnapshot) -> Self {
        Self {
            snapshot,
            lookup_hint: None,
        }
    }

    fn refresh_snapshot(&mut self, snapshot: ModuleSnapshot) {
        self.snapshot = snapshot;
        self.lookup_hint = None;
    }

    fn lookup_hint(&self, addr: u64) -> Option<ModuleInfo> {
        self.lookup_hint
            .as_ref()
            .filter(|hint| hint.entry.contains(addr))
            .map(|hint| hint.module.clone())
    }

    fn update_lookup_hint(&mut self, entry: ModuleMapEntry, module: ModuleInfo) -> ModuleInfo {
        self.lookup_hint = Some(AddressLookupHint {
            entry,
            module: module.clone(),
        });
        module
    }
}

static MODULE_CACHE: std::sync::OnceLock<std::sync::RwLock<ModuleCache>> = std::sync::OnceLock::new();

#[derive(Clone, Debug)]
struct AggregatedModuleRange {
    path: String,
    base: u64,
    end: u64,
}

impl AggregatedModuleRange {
    fn from_entry(entry: &ModuleMapEntry) -> Self {
        Self {
            path: entry.path.clone(),
            base: entry.start,
            end: entry.end,
        }
    }

    fn include(&mut self, entry: &ModuleMapEntry) {
        if entry.start < self.base {
            self.base = entry.start;
        }
        if entry.end > self.end {
            self.end = entry.end;
        }
    }

    fn into_module_info(self) -> ModuleInfo {
        ModuleInfo::from_path_range(self.path, self.base, self.end)
    }
}

/// Parse file-backed VMAs from /proc/self/maps without merging gaps.
fn parse_module_map_entries(maps: &str) -> Vec<ModuleMapEntry> {
    let entries: Vec<ModuleMapEntry> = crate::jsapi::util::proc_maps_entries(maps)
        .filter_map(ModuleMapEntry::from_proc_map_entry)
        .collect();
    filter_non_shared_object_memfd_entries(entries)
}

fn read_module_map_entries() -> Vec<ModuleMapEntry> {
    let maps = match super::util::read_proc_self_maps() {
        Some(s) => s,
        None => return Vec::new(),
    };

    parse_module_map_entries(&maps)
}

fn module_cache() -> &'static std::sync::RwLock<ModuleCache> {
    MODULE_CACHE.get_or_init(|| std::sync::RwLock::new(ModuleCache::new(ModuleSnapshot::load_current())))
}

fn refresh_module_snapshot_cache() -> ModuleSnapshot {
    let snapshot = ModuleSnapshot::load_current();
    let mut guard = module_cache().write().unwrap_or_else(|poisoned| poisoned.into_inner());
    guard.refresh_snapshot(snapshot.clone());
    snapshot
}

fn aggregate_modules(entries: &[ModuleMapEntry]) -> Vec<ModuleInfo> {
    collect_module_ranges(entries.iter())
        .into_iter()
        .map(AggregatedModuleRange::into_module_info)
        .collect()
}

/// Parse /proc/self/maps and aggregate VMAs per unique path.
pub(crate) fn enumerate_modules_from_maps() -> Vec<ModuleInfo> {
    refresh_module_snapshot_cache().modules
}

#[cfg(test)]
fn find_module_by_address_in_entries(
    entries: impl IntoIterator<Item = ModuleMapEntry>,
    addr: u64,
) -> Option<ModuleInfo> {
    let snapshot = ModuleSnapshot::from_entries(entries.into_iter().collect());
    snapshot.find_module_by_address(addr).map(|(_, module)| module)
}

fn try_find_module_by_address_in_cache(addr: u64) -> Option<ModuleInfo> {
    {
        let guard = module_cache().read().unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(module) = guard.lookup_hint(addr) {
            return Some(module);
        }
    }

    let mut guard = module_cache().write().unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(module) = guard.lookup_hint(addr) {
        return Some(module);
    }

    let (entry, module) = guard.snapshot.find_module_by_address(addr)?;
    Some(guard.update_lookup_hint(entry, module))
}

fn refresh_and_find_module_by_address(addr: u64) -> Option<ModuleInfo> {
    let snapshot = ModuleSnapshot::load_current();
    let found = snapshot.find_module_by_address(addr);

    let mut guard = module_cache().write().unwrap_or_else(|poisoned| poisoned.into_inner());
    guard.refresh_snapshot(snapshot);
    guard.lookup_hint = found.as_ref().map(|(entry, module)| AddressLookupHint {
        entry: entry.clone(),
        module: module.clone(),
    });

    found.map(|(_, module)| module)
}

/// Find the module containing `addr` and return the module-wide aggregated range.
fn find_module_by_address(addr: u64) -> Option<ModuleInfo> {
    try_find_module_by_address_in_cache(addr).or_else(|| refresh_and_find_module_by_address(addr))
}

pub(crate) fn is_address_in_loaded_module(addr: u64) -> bool {
    if addr == 0 {
        return false;
    }

    let maps = match super::util::read_proc_self_maps() {
        Some(s) => s,
        None => return false,
    };

    let found = crate::jsapi::util::proc_maps_entries(&maps).any(|entry| {
        entry.contains(addr)
            && entry.path.is_some()
            && entry.prot_flags() & libc::PROT_EXEC != 0
    });
    found
}

fn collect_module_ranges<'a>(entries: impl IntoIterator<Item = &'a ModuleMapEntry>) -> Vec<AggregatedModuleRange> {
    let mut module_indices: HashMap<&str, usize> = HashMap::new();
    let mut modules: Vec<AggregatedModuleRange> = Vec::new();

    for entry in entries {
        if let Some(&index) = module_indices.get(entry.path.as_str()) {
            modules[index].include(entry);
        } else {
            module_indices.insert(entry.path.as_str(), modules.len());
            modules.push(AggregatedModuleRange::from_entry(entry));
        }
    }

    modules
}

fn normalized_module_path(path: &str) -> &str {
    path.strip_suffix(" (deleted)").unwrap_or(path)
}

fn module_basename(path: &str) -> &str {
    let path = normalized_module_path(path);
    path.rsplit('/').next().unwrap_or(path)
}

fn is_memfd_path(path: &str) -> bool {
    let path = normalized_module_path(path);
    path.starts_with("/memfd:") || path.starts_with("memfd:")
}

fn is_proc_maps_module_path(path: &str) -> bool {
    let path = normalized_module_path(path);
    path.starts_with('/') && !path.starts_with('[')
}

fn is_symbol_scan_candidate_path(path: &str, base_address: u64) -> bool {
    let path = normalized_module_path(path);
    if !is_proc_maps_module_path(path) {
        return false;
    }
    if is_memfd_path(path) {
        return is_memory_elf_shared_object(base_address);
    }

    let basename = module_basename(path);
    basename == "linker"
        || basename == "linker64"
        || basename.ends_with(".so")
        || basename.contains(".so.")
        || basename.contains(".so!")
        || path.contains(".apk")
}

fn filter_non_shared_object_memfd_entries(entries: Vec<ModuleMapEntry>) -> Vec<ModuleMapEntry> {
    let mut memfd_bases: HashMap<String, u64> = HashMap::new();
    for entry in &entries {
        if !is_memfd_path(&entry.path) {
            continue;
        }
        memfd_bases
            .entry(entry.path.clone())
            .and_modify(|base| *base = (*base).min(entry.start))
            .or_insert(entry.start);
    }

    if memfd_bases.is_empty() {
        return entries;
    }

    let shared_object_memfds: HashSet<String> = memfd_bases
        .iter()
        .filter_map(|(path, &base)| is_memory_elf_shared_object(base).then_some(path.clone()))
        .collect();

    entries
        .into_iter()
        .filter(|entry| !is_memfd_path(&entry.path) || shared_object_memfds.contains(&entry.path))
        .collect()
}

fn is_memory_elf_shared_object(base_address: u64) -> bool {
    const MAX_MEMFD_ELF_PHDRS: usize = 1024;

    if base_address == 0 || !is_addr_accessible(base_address, std::mem::size_of::<Elf64Ehdr>()) {
        return false;
    }

    unsafe {
        let ehdr = &*(base_address as *const Elf64Ehdr);
        if ehdr.e_ident[0..4] != *b"\x7fELF" || ehdr.e_ident[4] != 2 || ehdr.e_type != ET_DYN {
            return false;
        }

        let phnum = ehdr.e_phnum as usize;
        let phentsize = ehdr.e_phentsize as usize;
        if phnum == 0 || phnum > MAX_MEMFD_ELF_PHDRS || phentsize < std::mem::size_of::<Elf64Phdr>() {
            return false;
        }

        let Some(phdr_base) = base_address.checked_add(ehdr.e_phoff) else {
            return false;
        };
        let Some(phdr_bytes) = phnum.checked_mul(phentsize) else {
            return false;
        };
        if !is_addr_accessible(phdr_base, phdr_bytes) {
            return false;
        }

        let mut has_load = false;
        let mut has_dynamic = false;
        for idx in 0..phnum {
            let Some(offset) = idx.checked_mul(phentsize) else {
                return false;
            };
            let Some(phdr_addr) = phdr_base.checked_add(offset as u64) else {
                return false;
            };
            let phdr = &*(phdr_addr as *const Elf64Phdr);
            has_load |= phdr.p_type == PT_LOAD;
            has_dynamic |= phdr.p_type == PT_DYNAMIC;
            if has_load && has_dynamic {
                return true;
            }
        }
    }

    false
}

fn matches_exact_module_name(path: &str, module_name: &str) -> bool {
    path.contains(module_name) && module_basename(path) == module_name
}

/// 系统 libart.so 路径白名单：basename 精确匹配 + 系统目录前缀。
fn is_system_libart_path(path: &str) -> bool {
    if module_basename(path) != "libart.so" {
        return false;
    }
    path.starts_with("/apex/") || path.starts_with("/system/") || path.starts_with("/system_ext/")
}

fn matches_module_lookup_name(path: &str, module_name: &str) -> bool {
    if !path.contains(module_name) {
        return false;
    }

    let basename = module_basename(path);
    basename == module_name || basename.starts_with(&format!("{}.", module_name)) || path.ends_with(module_name)
}

struct PathMapSummary {
    base: u64,
    end: u64,
    first_path: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_by_address_returns_the_aggregated_module_range() {
        let maps = "\
1000-2000 r-xp 00000000 00:00 0 /tmp/libfoo.so
2000-3000 r--p 00001000 00:00 0 /tmp/libfoo.so
9000-a000 r-xp 00000000 00:00 0 /tmp/libfoo.so
a000-b000 r--p 00001000 00:00 0 /tmp/libfoo.so
";

        let module = find_module_by_address_in_entries(parse_module_map_entries(maps), 0x9500)
            .expect("expected matching module");

        assert_eq!(
            module,
            ModuleInfo {
                name: "libfoo.so".to_string(),
                base: 0x1000,
                size: 0xa000,
                path: "/tmp/libfoo.so".to_string(),
            }
        );
    }

    #[test]
    fn enumerate_modules_still_aggregates_by_path() {
        let maps = "\
1000-2000 r-xp 00000000 00:00 0 /tmp/libfoo.so
2000-2800 r--p 00001000 00:00 0 /tmp/libfoo.so
";

        let entries = parse_module_map_entries(maps);
        let modules = aggregate_modules(&entries);

        assert_eq!(
            modules,
            vec![ModuleInfo {
                name: "libfoo.so".to_string(),
                base: 0x1000,
                size: 0x1800,
                path: "/tmp/libfoo.so".to_string(),
            }]
        );
    }
}
