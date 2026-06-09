// ============================================================================
// Dex-backed ArtMethod resolver
// ============================================================================
//
// This path avoids Class.getDeclaredMethods()/GetMethodID for already-loaded
// classes. It scans mirror::Class for candidate methods_ arrays and matches
// ArtMethod.dex_method_index_ against in-process dex images parsed directly
// from memory. Avoiding ArtClassSpec probing here is intentional: probing via
// GetFieldID/GetMethodID can throw on raw clone threads, and ART's exception
// stack walking is not safe there.

#[derive(Clone, Debug)]
struct DexImage {
    base: u64,
    size: usize,
    data_base: u64,
    data_size: usize,
    kind: DexImageKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DexImageKind {
    Standard,
    Compact,
}

pub(crate) struct DexFieldInfo {
    pub(crate) name: String,
    pub(crate) jni_sig: String,
    pub(crate) field_id: *mut std::ffi::c_void,
    pub(crate) field_offset: u32,
    pub(crate) is_static: bool,
}

const DEX_HEADER_SIZE: usize = 0x70;
const DEX_V41_HEADER_SIZE: usize = 0x78;
const DEX_MAGIC_DEX: &[u8; 4] = b"dex\n";
const DEX_MAGIC_CDEX: &[u8; 4] = b"cdex";
const VDEX_MAGIC: &[u8; 4] = b"vdex";
const ART_IMAGE_MAGIC: &[u8; 4] = b"art\n";
const OAT_MAGIC: &[u8; 4] = b"oat\n";
const ART_METHOD_DEX_METHOD_INDEX_CANDIDATE_OFFSETS: [usize; 3] = [8, 4, 12];
const ART_METHOD_ARRAY_FIRST_ELEMENT_OFFSETS: [usize; 2] = [0, 8];
const ART_METHOD_SIZE_CANDIDATES: [usize; 6] = [40, 32, 48, 24, 56, 64];
const ART_FIELD_DEX_FIELD_INDEX_CANDIDATE_OFFSETS: [usize; 3] = [8, 16, 12];
const K_ACC_STATIC: u32 = 0x0008;

static CLASS_MIRROR_CACHE: OnceLock<Mutex<HashMap<String, u64>>> = OnceLock::new();
static CLASS_MIRROR_DEX_IMAGE_CACHE: OnceLock<Mutex<HashMap<u64, DexImage>>> = OnceLock::new();
static LAST_DEX_RESOLVER_FAILURE: OnceLock<Mutex<Option<String>>> = OnceLock::new();
static RAW_CLASS_MIRROR_SCAN_MISSES: OnceLock<Mutex<std::collections::HashSet<String>>> = OnceLock::new();
static RAW_FRAMEWORK_DEX_SCAN_DISABLED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[derive(Clone, Copy, Debug)]
struct ClassMirrorScanRegion {
    start: u64,
    end: u64,
}

#[derive(Clone, Copy, Debug)]
struct ArtImageSection {
    offset: u32,
    size: u32,
}

#[derive(Clone, Debug)]
struct ArtImage {
    base: u64,
    end: u64,
    path: String,
    image_size: u32,
    header_sections_off: u32,
    sections: Vec<ArtImageSection>,
    class_tables: Vec<ArtClassTable>,
}

#[derive(Clone, Debug)]
struct ArtClassTable {
    section_index: usize,
    start: u64,
    size: usize,
    entries: u64,
    num_elements: u64,
    num_buckets: u64,
}

#[derive(Clone, Debug)]
struct VdexImage {
    base: u64,
    version: [u8; 4],
    dex_count: Option<u32>,
    dex_section: Option<ClassMirrorScanRegion>,
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
struct OatImage {
    base: u64,
    end: u64,
    version: [u8; 4],
    dex_file_count: u32,
    oat_dex_files_offset: u32,
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
struct OatDexFileInfo {
    location: String,
    checksum: u32,
    dex_file_offset: u32,
    class_offsets_offset: u32,
    lookup_table_offset: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClassMirrorSeedMode {
    AdjacentIndices,
    LooseIndex,
}

impl ArtImage {
    fn from_mapping(start: u64, end: u64, path: &str) -> Option<Self> {
        if end <= start || !super::safe_mem::is_readable(start, DEX_HEADER_SIZE) {
            return None;
        }
        let magic = unsafe { std::slice::from_raw_parts(start as *const u8, 4) };
        if magic != ART_IMAGE_MAGIC {
            return None;
        }

        let mut best: Option<((u8, u8, u8, u8), Self)> = None;
        for (layout_priority, image_size_off, sections_off, section_count) in
            art_image_header_layout_candidates(start, end)
        {
            let Some(image_size) = read_u32(start + image_size_off) else {
                continue;
            };
            if !(DEX_HEADER_SIZE as u32..=(1024 * 1024 * 1024)).contains(&image_size) {
                continue;
            }
            let mapped_len = end.saturating_sub(start);
            if mapped_len < image_size.min(DEX_HEADER_SIZE as u32) as u64 {
                continue;
            }

            let Some(sections) = parse_art_image_sections(start, end, image_size, sections_off, section_count) else {
                continue;
            };
            let class_tables = parse_art_class_tables(start, image_size, section_count, &sections);

            let candidate = ArtImage {
                base: start,
                end,
                path: path.to_string(),
                image_size,
                header_sections_off: sections_off,
                sections,
                class_tables,
            };

            let score = art_image_candidate_score(layout_priority, section_count, &candidate.class_tables);
            if best.as_ref().is_none_or(|(best_score, _)| score < *best_score) {
                best = Some((score, candidate));
            }
        }

        best.map(|(_, candidate)| candidate)
    }

    fn object_region(&self) -> Option<ClassMirrorScanRegion> {
        art_section_region(self.base, self.image_size, self.sections.first()?)
            .filter(|region| region.end <= self.end)
    }
}

fn art_image_header_layout_candidates(start: u64, end: u64) -> Vec<(u8, u64, u32, usize)> {
    const HEADER_SCAN_LIMIT: u64 = 0x100;
    const MIN_SECTION_COUNT: usize = 7;
    const MAX_SECTION_COUNT: usize = 18;

    let mut out = Vec::new();
    for image_size_off in [0x14u64, 0x0c] {
        for sections_off in [0x48u32, 0x40] {
            for section_count in MIN_SECTION_COUNT..=MAX_SECTION_COUNT {
                out.push((0, image_size_off, sections_off, section_count));
            }
        }
    }

    let max_header = end.saturating_sub(start).min(HEADER_SCAN_LIMIT);
    for image_size_off in (0x0cu64..max_header).step_by(4) {
        for sections_off in (0x30u32..max_header as u32).step_by(4) {
            if sections_off as u64 <= image_size_off {
                continue;
            }
            for section_count in MIN_SECTION_COUNT..=MAX_SECTION_COUNT {
                if out.iter().any(|(_, known_size_off, known_sections_off, known_count)| {
                    *known_size_off == image_size_off
                        && *known_sections_off == sections_off
                        && *known_count == section_count
                }) {
                    continue;
                }
                out.push((1, image_size_off, sections_off, section_count));
            }
        }
    }

    out
}

impl VdexImage {
    fn from_mapping(start: u64, end: u64) -> Option<Self> {
        if end <= start || !super::safe_mem::is_readable(start, 12) {
            return None;
        }
        let magic = unsafe { std::slice::from_raw_parts(start as *const u8, 4) };
        if magic != VDEX_MAGIC {
            return None;
        }
        let mut version = [0u8; 4];
        for (i, slot) in version.iter_mut().enumerate() {
            *slot = read_u8(start + 4 + i as u64)?;
        }

        if let Some((dex_count, dex_section)) = parse_vdex_section_header_layout(start, end) {
            return Some(VdexImage {
                base: start,
                version,
                dex_count: Some(dex_count),
                dex_section,
            });
        }

        if let Some((dex_count, dex_section)) = parse_vdex_legacy_layout(start, end) {
            return Some(VdexImage {
                base: start,
                version,
                dex_count: Some(dex_count),
                dex_section: Some(dex_section),
            });
        }

        Some(VdexImage {
            base: start,
            version,
            dex_count: None,
            dex_section: Some(ClassMirrorScanRegion { start, end }),
        })
    }

    fn dex_images(&self) -> Vec<DexImage> {
        let Some(scan) = self.dex_section else {
            return Vec::new();
        };
        scan_dex_images_in_range(scan.start, scan.end, self.dex_count.unwrap_or(128) as usize)
    }
}

#[allow(dead_code)]
impl OatImage {
    fn from_mapping(start: u64, end: u64) -> Option<Self> {
        let header = find_oat_header_in_mapping(start, end)?;
        if !super::safe_mem::is_readable(header, 0x40) {
            return None;
        }
        let mut version = [0u8; 4];
        for (i, slot) in version.iter_mut().enumerate() {
            *slot = read_u8(header + 4 + i as u64)?;
        }
        let dex_file_count = read_u32(header + 0x14)?;
        let oat_dex_files_offset = read_u32(header + 0x18)?;
        if dex_file_count == 0 || dex_file_count > 4096 {
            return None;
        }
        if oat_dex_files_offset < 0x40 || header + oat_dex_files_offset as u64 >= end {
            return None;
        }
        Some(OatImage {
            base: header,
            end,
            version,
            dex_file_count,
            oat_dex_files_offset,
        })
    }

    fn oat_dex_files(&self) -> Vec<OatDexFileInfo> {
        let mut out = Vec::new();
        let mut cursor = self.base + self.oat_dex_files_offset as u64;
        let old_inline_class_offsets = self.version_number().is_some_and(|version| version < 75);
        for index in 0..self.dex_file_count.min(512) {
            let Some(location_size) = read_u32(cursor) else {
                break;
            };
            cursor += 4;
            if location_size == 0 || location_size > 4096 || cursor + location_size as u64 > self.end {
                break;
            }
            let location = if super::safe_mem::is_readable(cursor, location_size as usize) {
                let bytes = unsafe { std::slice::from_raw_parts(cursor as *const u8, location_size as usize) };
                String::from_utf8_lossy(bytes).into_owned()
            } else {
                break;
            };
            cursor += location_size as u64;

            let oat_version = self.version_number().unwrap_or(0);
            let (checksum, dex_file_offset, data_bytes) = if oat_version >= 244 {
                let Some(checksum) = read_u32(cursor + 8) else {
                    break;
                };
                let Some(dex_file_offset) = read_u32(cursor + 32) else {
                    break;
                };
                (checksum, dex_file_offset, 36u64)
            } else {
                let Some(checksum) = read_u32(cursor) else {
                    break;
                };
                let Some(dex_file_offset) = read_u32(cursor + 4) else {
                    break;
                };
                (checksum, dex_file_offset, 8u64)
            };
            if cursor + data_bytes > self.end {
                break;
            }
            cursor += data_bytes;

            if old_inline_class_offsets {
                let class_offsets_offset = cursor.saturating_sub(self.base) as u32;
                let class_defs_size = if dex_file_offset != 0 {
                    read_u32(self.base + dex_file_offset as u64 + 0x60).unwrap_or(0)
                } else {
                    0
                };
                let class_offsets_bytes = class_defs_size as u64 * 4;
                if cursor + class_offsets_bytes > self.end {
                    break;
                }
                cursor += class_offsets_bytes;
                out.push(OatDexFileInfo {
                    location,
                    checksum,
                    dex_file_offset,
                    class_offsets_offset,
                    lookup_table_offset: 0,
                });
            } else {
                let Some(class_offsets_offset) = read_u32(cursor) else {
                    break;
                };
                let Some(lookup_table_offset) = read_u32(cursor + 4) else {
                    break;
                };
                cursor += 8;
                out.push(OatDexFileInfo {
                    location,
                    checksum,
                    dex_file_offset,
                    class_offsets_offset,
                    lookup_table_offset,
                });
            }

            if index + 1 < self.dex_file_count.min(512) {
                if let Some(next_cursor) = find_next_oat_dex_file_entry(cursor, self.end) {
                    cursor = next_cursor;
                }
            }
        }
        out
    }

    fn version_number(&self) -> Option<u32> {
        let mut value = 0u32;
        let mut seen_digit = false;
        for byte in self.version {
            if !byte.is_ascii_digit() {
                break;
            }
            seen_digit = true;
            value = value.checked_mul(10)?.checked_add((byte - b'0') as u32)?;
        }
        seen_digit.then_some(value)
    }
}

fn find_next_oat_dex_file_entry(cursor: u64, end: u64) -> Option<u64> {
    for tail_bytes in [0u64, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 48, 64] {
        let candidate = cursor.checked_add(tail_bytes)?;
        if looks_like_oat_dex_file_entry(candidate, end) {
            return Some(candidate);
        }
    }

    None
}

fn looks_like_oat_dex_file_entry(addr: u64, end: u64) -> bool {
    let Some(location_size) = read_u32(addr) else {
        return false;
    };
    if location_size == 0 || location_size > 4096 {
        return false;
    }
    let location_start = addr + 4;
    let location_end = location_start + location_size as u64;
    if location_end + 8 > end || !super::safe_mem::is_readable(location_start, location_size as usize) {
        return false;
    }
    let bytes = unsafe { std::slice::from_raw_parts(location_start as *const u8, location_size as usize) };
    bytes.iter().all(|byte| byte.is_ascii_graphic())
}

fn parse_art_image_sections(
    base: u64,
    end: u64,
    image_size: u32,
    sections_off: u32,
    section_count: usize,
) -> Option<Vec<ArtImageSection>> {
    if !(7..=18).contains(&section_count) {
        return None;
    }
    let mut sections = Vec::with_capacity(section_count);
    for index in 0..section_count {
        let addr = base + sections_off as u64 + (index * 8) as u64;
        if addr + 8 > end || !super::safe_mem::is_readable(addr, 8) {
            return None;
        }
        let offset = read_u32(addr)?;
        let size = read_u32(addr + 4)?;
        if offset > image_size
            || (size != 0 && offset.checked_add(size).is_none_or(|section_end| section_end > image_size))
        {
            return None;
        }
        sections.push(ArtImageSection { offset, size });
    }
    Some(sections)
}

fn parse_art_class_tables(
    image_base: u64,
    image_size: u32,
    _section_count: usize,
    sections: &[ArtImageSection],
) -> Vec<ArtClassTable> {
    let Some(object_region) = sections
        .first()
        .and_then(|section| art_section_region(image_base, image_size, section))
    else {
        return Vec::new();
    };

    let mut tables = sections
        .iter()
        .enumerate()
        .filter_map(|(section_index, section)| {
            parse_art_class_table(image_base, image_size, object_region, section_index, section)
                .map(|table| (class_table_scan_priority(&table), table))
        })
        .collect::<Vec<_>>();
    tables.sort_by_key(|(priority, table)| (*priority, table.section_index, table.start));
    tables.into_iter().map(|(_, table)| table).collect()
}

fn art_section_region(
    image_base: u64,
    image_size: u32,
    section: &ArtImageSection,
) -> Option<ClassMirrorScanRegion> {
    if section.size == 0 {
        return None;
    }
    if section
        .offset
        .checked_add(section.size)
        .is_none_or(|section_end| section_end > image_size)
    {
        return None;
    }
    let start = image_base.checked_add(section.offset as u64)?;
    let end = start.checked_add(section.size as u64)?;
    super::safe_mem::is_readable(start, (end - start).min(DEX_HEADER_SIZE as u64) as usize)
        .then_some(ClassMirrorScanRegion { start, end })
}

fn parse_art_class_table(
    image_base: u64,
    image_size: u32,
    object_region: ClassMirrorScanRegion,
    section_index: usize,
    section: &ArtImageSection,
) -> Option<ArtClassTable> {
    const HASH_SET_PREFIX_SIZE: u64 = 40;
    if section.size < HASH_SET_PREFIX_SIZE as u32 {
        return None;
    }
    let start = image_base + section.offset as u64;
    if !super::safe_mem::is_readable(start, HASH_SET_PREFIX_SIZE as usize) {
        return None;
    }
    let num_elements = read_u64(start)?;
    let num_buckets = read_u64(start + 8)?;
    let elements_until_expand = read_u64(start + 16)?;
    let min_load = read_f64(start + 24)?;
    let max_load = read_f64(start + 32)?;
    if num_elements == 0
        || num_buckets == 0
        || num_elements > num_buckets
        || num_buckets > 4_000_000
        || elements_until_expand < num_elements
        || !(0.05..=0.95).contains(&min_load)
        || !(0.10..=0.99).contains(&max_load)
        || min_load >= max_load
    {
        return None;
    }
    let table_size = HASH_SET_PREFIX_SIZE.checked_add(num_buckets.checked_mul(4)?)?;
    if table_size > section.size as u64 {
        return None;
    }
    if section.offset.checked_add(table_size as u32).is_none_or(|end| end > image_size) {
        return None;
    }
    let entries = start + HASH_SET_PREFIX_SIZE;
    if !art_class_table_entries_look_plausible(entries, num_elements, num_buckets, object_region) {
        return None;
    }
    Some(ArtClassTable {
        section_index,
        start,
        size: table_size as usize,
        entries,
        num_elements,
        num_buckets,
    })
}

fn art_class_table_entries_look_plausible(
    entries: u64,
    num_elements: u64,
    num_buckets: u64,
    object_region: ClassMirrorScanRegion,
) -> bool {
    const MAX_LINEAR_SAMPLE_BUCKETS: u64 = 64 * 1024;
    const MAX_STRIDED_SAMPLE_BUCKETS: u64 = 64 * 1024;

    fn sample_bucket(
        entries: u64,
        index: u64,
        object_region: ClassMirrorScanRegion,
        non_zero: &mut u64,
        object_like: &mut u64,
    ) -> Option<()> {
        let slot = read_u32(entries.checked_add(index.checked_mul(4)?)?)?;
        if slot == 0 {
            return Some(());
        }
        *non_zero += 1;
        let object = (slot & !0x7) as u64;
        if object >= object_region.start
            && object + 4 <= object_region.end
            && super::safe_mem::is_readable(object, 4)
        {
            *object_like += 1;
        }
        Some(())
    }

    let mut non_zero = 0u64;
    let mut object_like = 0u64;
    let linear = num_buckets.min(MAX_LINEAR_SAMPLE_BUCKETS);
    for index in 0..linear {
        if sample_bucket(entries, index, object_region, &mut non_zero, &mut object_like).is_none() {
            return false;
        }
    }

    if object_like == 0 && num_buckets > linear {
        let stride = (num_buckets / MAX_STRIDED_SAMPLE_BUCKETS).max(1);
        let mut index = 0u64;
        let mut sampled = 0u64;
        while index < num_buckets && sampled < MAX_STRIDED_SAMPLE_BUCKETS {
            if sample_bucket(entries, index, object_region, &mut non_zero, &mut object_like).is_none() {
                return false;
            }
            index = index.saturating_add(stride);
            sampled += 1;
        }
    }

    if object_like == 0 {
        return false;
    }

    let required = num_elements.min(4).max(1);
    if num_buckets <= MAX_LINEAR_SAMPLE_BUCKETS && object_like < required {
        return false;
    }

    non_zero <= num_elements.saturating_mul(2).max(16) && object_like.saturating_mul(4) >= non_zero
}

fn class_table_scan_priority(table: &ArtClassTable) -> (u8, u64, u64) {
    let load_distance = table.num_buckets.saturating_sub(table.num_elements);
    (0, load_distance, table.num_buckets)
}

fn art_image_candidate_score(
    layout_priority: u8,
    section_count: usize,
    class_tables: &[ArtClassTable],
) -> (u8, u8, u8, u8) {
    (
        if class_tables.is_empty() { 1 } else { 0 },
        layout_priority,
        32u8.saturating_sub(class_tables.len().min(32) as u8),
        32u8.saturating_sub(section_count.min(32) as u8),
    )
}

fn parse_vdex_section_header_layout(start: u64, end: u64) -> Option<(u32, Option<ClassMirrorScanRegion>)> {
    let number_of_sections = read_u32(start + 8)?;
    if !(2..=16).contains(&number_of_sections) {
        return None;
    }
    let section_table = start + 12;
    if section_table + number_of_sections as u64 * 12 > end {
        return None;
    }
    let mut dex_count = None;
    let mut dex_section = None;
    for i in 0..number_of_sections {
        let entry = section_table + i as u64 * 12;
        let kind = read_u32(entry)?;
        let offset = read_u32(entry + 4)?;
        let size = read_u32(entry + 8)?;
        if offset as u64 + size as u64 > end - start {
            return None;
        }
        match kind {
            0 => dex_count = Some(size / 4),
            1 if size != 0 => {
                dex_section = Some(ClassMirrorScanRegion {
                    start: start + offset as u64,
                    end: start + offset as u64 + size as u64,
                })
            }
            _ => {}
        }
    }
    Some((dex_count.unwrap_or(0), dex_section))
}

fn parse_vdex_legacy_layout(start: u64, end: u64) -> Option<(u32, ClassMirrorScanRegion)> {
    if end - start < 24 {
        return None;
    }
    let number_of_dex_files = read_u32(start + 12)?;
    if number_of_dex_files == 0 || number_of_dex_files > 4096 {
        return None;
    }

    // Android 10/11 verifier deps header:
    // magic, verifier_deps_version, dex_section_version, number, verifier_deps_size,
    // bootclasspath checksum string size, class loader context size.
    if end - start >= 40 {
        let dex_section_version = [
            read_u8(start + 8)?,
            read_u8(start + 9)?,
            read_u8(start + 10)?,
            read_u8(start + 11)?,
        ];
        if dex_section_version != [b'0', b'0', b'0', 0] {
            let dex_section_header = start + 28 + number_of_dex_files as u64 * 4;
            if dex_section_header + 12 <= end {
                let dex_size = read_u32(dex_section_header)?;
                let dex_shared_data_size = read_u32(dex_section_header + 4)?;
                let dex_start = dex_section_header + 12;
                let dex_end = dex_start + dex_size as u64 + dex_shared_data_size as u64;
                if dex_size != 0 && dex_end <= end {
                    return Some((
                        number_of_dex_files,
                        ClassMirrorScanRegion {
                            start: dex_start,
                            end: dex_end,
                        },
                    ));
                }
            }
        }
    }

    // Android 8/9 style header: magic, version, number, dex_size, verifier_deps_size,
    // quickening_info_size; DEX data follows immediately.
    let dex_size = read_u32(start + 16)?;
    let checksums_size = number_of_dex_files as u64 * 4;
    let dex_start = start + 24 + checksums_size;
    let dex_end = dex_start + dex_size as u64;
    if dex_size != 0 && dex_end <= end {
        return Some((
            number_of_dex_files,
            ClassMirrorScanRegion {
                start: dex_start,
                end: dex_end,
            },
        ));
    }

    None
}

fn scan_dex_images_in_range(start: u64, end: u64, max_images: usize) -> Vec<DexImage> {
    let mut out = Vec::new();
    let mut addr = start;
    let mut scanned = 0usize;
    const MAX_SCAN_BYTES: u64 = 256 * 1024 * 1024;
    while addr + DEX_HEADER_SIZE as u64 <= end && addr - start <= MAX_SCAN_BYTES {
        if !super::safe_mem::is_readable(addr, 4) {
            addr += 4;
            continue;
        }
        let word = unsafe { super::safe_mem::safe_read_u32(addr) };
        if word == u32::from_le_bytes(*DEX_MAGIC_DEX) || word == u32::from_le_bytes(*DEX_MAGIC_CDEX) {
            if let Some(image) = DexImage::from_base(addr) {
                if image.base + image.size as u64 <= end || image.kind == DexImageKind::Compact {
                    addr = align_up_u64(image.base + image.size.max(4) as u64, 4);
                    out.push(image);
                    if out.len() >= max_images {
                        break;
                    }
                    continue;
                }
            }
        }
        scanned += 1;
        if scanned > 2_000_000 {
            break;
        }
        addr += 4;
    }
    out
}

fn find_oat_header_in_mapping(start: u64, end: u64) -> Option<u64> {
    let mut addr = start;
    let scan_end = end.min(start.saturating_add(16 * 1024 * 1024));
    while addr + 0x40 <= scan_end {
        if super::safe_mem::is_readable(addr, 4)
            && unsafe { std::slice::from_raw_parts(addr as *const u8, 4) } == OAT_MAGIC
        {
            return Some(addr);
        }
        addr += 4;
    }
    None
}

fn align_up_u64(value: u64, align: u64) -> u64 {
    if align == 0 {
        value
    } else {
        (value + align - 1) & !(align - 1)
    }
}

fn modified_utf8_hash(s: &str) -> u32 {
    s.as_bytes()
        .iter()
        .fold(0u32, |hash, byte| hash.wrapping_mul(31).wrapping_add(*byte as u32))
}

pub(super) unsafe fn resolve_art_method_by_dex(
    env: JniEnv,
    class_name: &str,
    method_name: &str,
    signature: &str,
    force_static: bool,
) -> Option<(u64, bool)> {
    if method_name.is_empty() || signature.is_empty() {
        return None;
    }
    clear_dex_resolver_failure();

    refresh_mem_regions();

    let class_obj = class_mirror_for_name(env, class_name)?;
    resolve_art_method_by_dex_from_mirror(class_obj, class_name, method_name, signature, force_static)
}

pub(crate) unsafe fn resolve_art_method_by_dex_from_mirror(
    class_obj: u64,
    class_name: &str,
    method_name: &str,
    signature: &str,
    force_static: bool,
) -> Option<(u64, bool)> {
    if class_obj < 0x1000 || !crate::jsapi::util::is_addr_accessible(class_obj, 4) {
        return None;
    }

    refresh_mem_regions();

    let mut class_obj = class_obj;
    let mut class_descriptor = class_name_to_descriptor(class_name);

    for depth in 0..32 {
        remember_class_mirror(&descriptor_to_class_name(&class_descriptor), class_obj);

        let image = match dex_image_from_class(class_obj) {
            Some(image) => image,
            None => {
                let reason = format!(
                    "[dex resolver] no DexFile image from Class/DexCache for {}.{}{} depth={} class={:#x}",
                    class_name, method_name, signature, depth, class_obj
                );
                set_dex_resolver_failure(reason);
                return None;
            }
        };

        if let Some(resolved) = resolve_from_class_methods(
            class_obj,
            std::slice::from_ref(&image),
            &class_descriptor,
            class_name,
            method_name,
            signature,
            force_static,
        ) {
            if depth != 0 {
                output_verbose(&format!(
                    "[dex resolver] resolved inherited depth {} {}.{}{} declaring={}",
                    depth, class_name, method_name, signature, class_descriptor
                ));
            }
            return Some(resolved);
        }

        if method_name == "<init>" {
            break;
        }

        let Some(next_descriptor) = image.super_descriptor_for_class(&class_descriptor).flatten() else {
            break;
        };
        let Some(super_class) = resolve_super_class_mirror(class_obj, &next_descriptor) else {
            output_verbose(&format!(
                "[dex resolver] super_class_ mirror unavailable while resolving {}.{}{} -> {}",
                class_name, method_name, signature, next_descriptor
            ));
            break;
        };
        class_obj = super_class;
        class_descriptor = next_descriptor;
    }

    None
}

pub(crate) unsafe fn enumerate_methods_by_dex(
    env: JniEnv,
    class_name: &str,
) -> Option<Vec<MethodInfo>> {
    refresh_mem_regions();

    let class_obj = class_mirror_for_name(env, class_name)?;
    let image = dex_image_from_class(class_obj)?;
    let class_descriptor = class_name_to_descriptor(class_name);
    let methods = image.declared_methods_for_class(&class_descriptor)?;
    output_verbose(&format!(
        "[dex resolver] enumerated {} methods for {} from dex",
        methods.len(),
        class_name
    ));
    Some(methods)
}

pub(crate) unsafe fn enumerate_fields_by_dex(
    env: JniEnv,
    class_name: &str,
) -> Option<Vec<DexFieldInfo>> {
    refresh_mem_regions();

    let class_obj = class_mirror_for_name(env, class_name)?;
    enumerate_fields_by_dex_from_mirror(class_obj, class_name)
}

pub(crate) unsafe fn enumerate_fields_by_dex_from_mirror(
    class_obj: u64,
    class_name: &str,
) -> Option<Vec<DexFieldInfo>> {
    refresh_mem_regions();

    let mut class_obj = class_obj;
    let mut class_descriptor = class_name_to_descriptor(class_name);
    let mut fields = Vec::new();
    output_verbose(&format!(
        "[dex resolver] enumerate fields from mirror start {} -> {:#x}",
        class_name, class_obj
    ));

    for depth in 0..32 {
        remember_class_mirror(&descriptor_to_class_name(&class_descriptor), class_obj);

        let image = match dex_image_from_class(class_obj) {
            Some(image) => image,
            None => {
                output_verbose(&format!(
                    "[dex resolver] no dex image for {} at depth {} class={:#x}",
                    class_descriptor, depth, class_obj
                ));
                break;
            }
        };
        output_verbose(&format!(
            "[dex resolver] field depth {} descriptor={} class={:#x} dex={:#x}",
            depth, class_descriptor, class_obj, image.base
        ));
        if let Some(dex_fields) = image.declared_fields_for_class(&class_descriptor) {
            output_verbose(&format!(
                "[dex resolver] dex declared fields {} count={}",
                class_descriptor,
                dex_fields.len()
            ));
            if let Some(mut declared) = resolve_declared_fields_from_class(class_obj, &dex_fields) {
                fields.append(&mut declared);
            }
        } else {
            output_verbose(&format!(
                "[dex resolver] field class_def unavailable for {} at depth {}",
                class_descriptor, depth
            ));
        }

        let Some(next_descriptor) = image.super_descriptor_for_class(&class_descriptor).flatten() else {
            break;
        };
        let Some(super_class) = resolve_super_class_mirror(class_obj, &next_descriptor) else {
            if depth == 0 {
                output_verbose(
                    "[dex resolver] super_class_ mirror unavailable; raw field enumeration is declared-only",
                );
            }
            break;
        };
        class_obj = super_class;
        class_descriptor = next_descriptor;
    }

    output_verbose(&format!(
        "[dex resolver] enumerated {} fields for {} from dex",
        fields.len(),
        class_name
    ));
    Some(fields)
}

pub(crate) unsafe fn class_mirror_for_name(env: JniEnv, class_name: &str) -> Option<u64> {
    if let Some(cached) = cached_class_mirror(class_name) {
        if crate::is_raw_clone_js_thread() {
            output_verbose(&format!(
                "[dex resolver] raw clone class mirror cache hit {} -> {:#x}",
                class_name, cached
            ));
        }
        return Some(cached);
    }

    if crate::is_raw_clone_js_thread() {
        if let Some(mirror) = super::callback::registered_class_mirror_for_class(class_name) {
            remember_class_mirror(class_name, mirror);
            return Some(mirror);
        }
        if let Some(mirror) = scan_framework_class_mirror_for_name(class_name) {
            remember_class_mirror(class_name, mirror);
            output_verbose(&format!(
                "[dex resolver] raw clone framework class mirror scan hit {} -> {:#x}",
                class_name, mirror
            ));
            return Some(mirror);
        }
        output_verbose(&format!(
            "[dex resolver] raw clone: skip JVMTI class mirror lookup for {}",
            class_name
        ));
        output_verbose(&format!(
            "[dex resolver] raw clone class mirror cache miss for {}; deferring to Java executor",
            class_name
        ));
        return None;
    }

    let class_ref = find_class_safe(env, class_name);
    if class_ref.is_null() {
        jni_check_exc(env);
        return None;
    }

    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
    let class_obj = super::art_class::with_runnable_thread(env, || {
        super::art_class::decode_jobject(env, class_ref)
    });
    delete_local_ref(env, class_ref);

    if let Some(mirror) = class_obj {
        remember_class_mirror(class_name, mirror);
    }
    class_obj
}

fn cached_class_mirror(class_name: &str) -> Option<u64> {
    let cache = CLASS_MIRROR_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mirror = *cache
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(class_name)?;
    (mirror >= 0x1000 && super::safe_mem::is_readable(mirror, 4)).then_some(mirror)
}

fn remember_class_mirror(class_name: &str, mirror: u64) {
    if mirror < 0x1000 || !super::safe_mem::is_readable(mirror, 4) {
        return;
    }
    let cache = CLASS_MIRROR_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    cache
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(class_name.to_string(), mirror);
}

fn cached_dex_image_for_class(class_obj: u64) -> Option<DexImage> {
    CLASS_MIRROR_DEX_IMAGE_CACHE
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&class_obj)
        .cloned()
}

fn remember_class_mirror_dex_image(class_obj: u64, image: &DexImage) {
    if class_obj < 0x1000 || !super::safe_mem::is_readable(class_obj, 4) {
        return;
    }
    CLASS_MIRROR_DEX_IMAGE_CACHE
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(class_obj, image.clone());
}

fn clear_dex_resolver_failure() {
    let failure = LAST_DEX_RESOLVER_FAILURE.get_or_init(|| Mutex::new(None));
    *failure.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

fn set_dex_resolver_failure(reason: String) {
    output_verbose(&reason);
    let failure = LAST_DEX_RESOLVER_FAILURE.get_or_init(|| Mutex::new(None));
    *failure.lock().unwrap_or_else(|e| e.into_inner()) = Some(reason);
}

pub(super) fn last_dex_resolver_failure() -> Option<String> {
    LAST_DEX_RESOLVER_FAILURE
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

fn remember_raw_class_mirror_scan_miss(class_name: &str) {
    let misses = RAW_CLASS_MIRROR_SCAN_MISSES.get_or_init(|| Mutex::new(std::collections::HashSet::new()));
    misses
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(class_name.to_string());
}

fn raw_class_mirror_scan_missed(class_name: &str) -> bool {
    RAW_CLASS_MIRROR_SCAN_MISSES
        .get_or_init(|| Mutex::new(std::collections::HashSet::new()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .contains(class_name)
}

fn scan_framework_class_mirror_for_name(class_name: &str) -> Option<u64> {
    if raw_class_mirror_scan_missed(class_name) {
        return None;
    }

    refresh_mem_regions();

    let descriptor = class_name_to_descriptor(class_name);
    let started = std::time::Instant::now();
    const SCAN_BUDGET: std::time::Duration = std::time::Duration::from_millis(1500);

    let seed_image = find_framework_dex_image_for_descriptor(&descriptor, started, SCAN_BUDGET);
    let seed = seed_image.as_ref().and_then(|image| {
        image
            .class_def_and_type_idx_by_descriptor(&descriptor)
            .map(|(class_def_idx, class_idx)| (image, class_def_idx, class_idx))
    });

    if let Some((image, class_def_idx, class_idx)) = seed {
        output_verbose(&format!(
            "[dex resolver] raw clone framework class mirror resolve {}: dex={:#x} class_def_idx={} type_idx={}",
            class_name, image.base, class_def_idx, class_idx
        ));
    } else if let Some(image) = seed_image.as_ref() {
        output_verbose(&format!(
            "[dex resolver] raw clone framework class mirror seed unavailable for {}: class_def unavailable in dex {:#x}; trying self-described boot ClassTable",
            class_name, image.base
        ));
    } else {
        output_verbose(&format!(
            "[dex resolver] raw clone framework class mirror seed unavailable for {}; trying self-described boot ClassTable",
            class_name
        ));
    }

    if let Some(mirror) = scan_boot_class_table_for_descriptor(&descriptor, seed) {
        output_verbose(&format!(
            "[dex resolver] raw clone boot image class table hit {} -> {:#x}",
            class_name, mirror
        ));
        return Some(mirror);
    }

    let Some((image, class_def_idx, class_idx)) = seed else {
        remember_raw_class_mirror_scan_miss(class_name);
        set_dex_resolver_failure(format!(
            "[dex resolver] raw clone framework class mirror scan miss for {}: boot class table miss and no dex/index seed",
            class_name
        ));
        return None;
    };

    let regions = enumerate_framework_class_regions();
    if regions.is_empty() {
        remember_raw_class_mirror_scan_miss(class_name);
        output_verbose(&format!(
            "[dex resolver] raw clone framework class mirror scan miss for {}: boot class table miss and no object regions",
            class_name
        ));
        return None;
    }

    output_verbose(&format!(
        "[dex resolver] raw clone boot class table miss for {}; falling back to bounded object scan regions={}",
        class_name,
        regions.len()
    ));

    const MAX_CANDIDATES: usize = 4;

    let mut candidates = Vec::new();
    let mut checked = 0usize;
    let mut hit_mode = None;
    for mode in [ClassMirrorSeedMode::AdjacentIndices, ClassMirrorSeedMode::LooseIndex] {
        let before = candidates.len();
        'outer: for region in &regions {
            let mut field_addr = region.start;
            while field_addr + 8 <= region.end {
                checked += 1;
                if (checked & 0xfff) == 0 && started.elapsed() >= SCAN_BUDGET {
                    output_verbose(&format!(
                        "[dex resolver] raw clone class mirror scan timeout for {} after {} words",
                        class_name, checked
                    ));
                    break 'outer;
                }

                if !class_mirror_seed_matches(field_addr, class_def_idx, class_idx, mode) {
                    field_addr += 4;
                    continue;
                }

                for object_offset in (0..0x100u64).step_by(4) {
                    let Some(class_obj) = field_addr.checked_sub(object_offset) else {
                        continue;
                    };
                    if (class_obj & 0x7) != 0 || class_obj < region.start || class_obj + 0x40 > region.end {
                        continue;
                    }
                    if candidates.contains(&class_obj) {
                        continue;
                    }
                    if class_mirror_candidate_matches(class_obj, &descriptor, Some((image, class_def_idx, class_idx))) {
                        candidates.push(class_obj);
                        if candidates.len() >= MAX_CANDIDATES {
                            break 'outer;
                        }
                    }
                }

                field_addr += 4;
            }
        }

        if candidates.len() != before {
            hit_mode = Some(mode);
            break;
        }
        if mode == ClassMirrorSeedMode::AdjacentIndices {
            output_verbose(&format!(
                "[dex resolver] raw clone framework class mirror adjacent-index seed miss for {}; trying loose-index scan",
                class_name
            ));
        }
    }

    match candidates.as_slice() {
        [one] => {
            output_verbose(&format!(
                "[dex resolver] raw clone framework class mirror scan hit {} mode={:?} -> {:#x}",
                class_name,
                hit_mode.unwrap_or(ClassMirrorSeedMode::LooseIndex),
                one
            ));
            Some(*one)
        }
        [] => {
            remember_raw_class_mirror_scan_miss(class_name);
            set_dex_resolver_failure(format!(
                "[dex resolver] raw clone framework class mirror scan miss for {} (checked {} words)",
                class_name, checked
            ));
            None
        }
        many => {
            output_verbose(&format!(
                "[dex resolver] raw clone framework class mirror scan ambiguous for {} mode={:?}: {} candidates, using first {:#x}",
                class_name,
                hit_mode.unwrap_or(ClassMirrorSeedMode::LooseIndex),
                many.len(),
                many[0]
            ));
            Some(many[0])
        }
    }
}

fn class_mirror_seed_matches(field_addr: u64, class_def_idx: u32, type_idx: u32, mode: ClassMirrorSeedMode) -> bool {
    let first = unsafe { std::ptr::read_unaligned(field_addr as *const u32) };
    match mode {
        ClassMirrorSeedMode::AdjacentIndices => {
            let second = unsafe { std::ptr::read_unaligned((field_addr + 4) as *const u32) };
            (first == class_def_idx && second == type_idx) || (first == type_idx && second == class_def_idx)
        }
        ClassMirrorSeedMode::LooseIndex => first == class_def_idx || first == type_idx,
    }
}

fn find_framework_dex_image_for_descriptor(
    descriptor: &str,
    started: std::time::Instant,
    budget: std::time::Duration,
) -> Option<DexImage> {
    if RAW_FRAMEWORK_DEX_SCAN_DISABLED.load(std::sync::atomic::Ordering::Acquire) {
        return None;
    }

    if let Some(image) = find_framework_vdex_image_for_descriptor(descriptor, started, budget) {
        return Some(image);
    }

    let Some(maps) = crate::jsapi::util::read_proc_self_maps() else {
        return None;
    };

    let mut map_entries: Vec<(u8, u64, u64, u64, &str)> = Vec::new();
    for line in maps.lines() {
        let Some((start, end, perms, file_offset, path)) = parse_maps_line_for_class_scan(line) else {
            continue;
        };
        if !perms.starts_with('r') || end <= start || !is_framework_dex_region_name(path) {
            continue;
        }
        map_entries.push((framework_dex_region_priority(path, descriptor), file_offset, start, end, path));
    }
    map_entries.sort_by_key(|(priority, file_offset, start, _, _)| (*priority, *file_offset, *start));

    let mut checked_candidates = 0usize;
    for (_priority, file_offset, start, end, path) in &map_entries {
        if started.elapsed() >= budget {
            output_verbose(&format!(
                "[dex resolver] raw clone framework dex image scan timeout for {} after {} candidates",
                descriptor, checked_candidates
            ));
            return None;
        }

        if let Some(image) = find_framework_dex_image_by_magic_in_mapping(
            *start,
            *end,
            path,
            descriptor,
            started,
            budget,
            &mut checked_candidates,
        ) {
            return Some(image);
        }

        if *file_offset != 0 {
            continue;
        }

        if let Some(image) = find_framework_dex_image_in_jar_mapping(
            *start,
            *end,
            path,
            descriptor,
            started,
            budget,
            &mut checked_candidates,
        ) {
            return Some(image);
        }
    }

    output_verbose(&format!(
        "[dex resolver] raw clone framework structured dex sources miss for {}; trying bounded magic fallback",
        descriptor
    ));

    for (_priority, _file_offset, start, end, path) in &map_entries {
        if let Some(image) = find_framework_dex_image_by_magic_in_mapping(
            *start,
            *end,
            path,
            descriptor,
            started,
            budget,
            &mut checked_candidates,
        ) {
            return Some(image);
        }
    }

    None
}

fn find_framework_dex_image_by_magic_in_mapping(
    start: u64,
    end: u64,
    path: &str,
    descriptor: &str,
    started: std::time::Instant,
    budget: std::time::Duration,
    checked_candidates: &mut usize,
) -> Option<DexImage> {
    const DEX_SCAN_WINDOW: u64 = 256 * 1024;

    let mut addr = start;
    let scan_end = end.min(start.saturating_add(DEX_SCAN_WINDOW));
    while addr + DEX_HEADER_SIZE as u64 <= scan_end {
        if started.elapsed() >= budget {
            output_verbose(&format!(
                "[dex resolver] raw clone framework dex image scan timeout for {} after {} candidates",
                descriptor, checked_candidates
            ));
            return None;
        }

        let word = if super::safe_mem::is_readable(addr, 4) {
            unsafe { super::safe_mem::safe_read_u32(addr) }
        } else {
            0
        };
        if word == u32::from_le_bytes(*DEX_MAGIC_DEX) || word == u32::from_le_bytes(*DEX_MAGIC_CDEX) {
            *checked_candidates += 1;
            if let Some(image) = DexImage::from_base(addr) {
                if image.class_def_and_type_idx_by_descriptor(descriptor).is_some() {
                    output_verbose(&format!(
                        "[dex resolver] raw clone framework dex magic fallback hit {} -> base={:#x} path={}",
                        descriptor, image.base, path
                    ));
                    return Some(image);
                }
                addr = align_up_u64(image.base + image.size.max(4) as u64, 4);
                continue;
            }
        }

        addr += 1;
    }

    None
}

fn find_framework_dex_image_in_jar_mapping(
    start: u64,
    end: u64,
    path: &str,
    descriptor: &str,
    started: std::time::Instant,
    budget: std::time::Duration,
    checked_candidates: &mut usize,
) -> Option<DexImage> {
    const ZIP_END_OF_CENTRAL_DIRECTORY_MAGIC: u32 = 0x0605_4b50;
    const ZIP_CENTRAL_DIRECTORY_FILE_HEADER_MAGIC: u32 = 0x0201_4b50;
    const ZIP_LOCAL_FILE_HEADER_MAGIC: u32 = 0x0403_4b50;
    const ZIP_END_OF_CENTRAL_DIRECTORY_SIZE: u64 = 22;
    const ZIP_CENTRAL_DIRECTORY_FILE_HEADER_SIZE: u64 = 46;
    const ZIP_LOCAL_FILE_HEADER_SIZE: u64 = 30;
    const ZIP_FLAG_DATA_DESCRIPTOR: u16 = 0x0008;
    const MAX_ZIP_ENTRIES: usize = 4096;
    const MAX_ZIP_SCAN_BYTES: u64 = 96 * 1024 * 1024;

    if end <= start + ZIP_END_OF_CENTRAL_DIRECTORY_SIZE {
        return None;
    }

    let eocd_scan_start = end.saturating_sub(start).saturating_sub(66 * 1024);
    let mut eocd = None;
    let mut cursor = end.saturating_sub(ZIP_END_OF_CENTRAL_DIRECTORY_SIZE);
    while cursor >= start + eocd_scan_start {
        if read_u32(cursor) == Some(ZIP_END_OF_CENTRAL_DIRECTORY_MAGIC) {
            eocd = Some(cursor);
            break;
        }
        if cursor == start {
            break;
        }
        cursor -= 1;
    }

    if let Some(eocd) = eocd {
        let entry_count = read_u16(eocd + 10)? as usize;
        let central_directory_size = read_u32(eocd + 12)? as u64;
        let central_directory_off = read_u32(eocd + 16)? as u64;
        if entry_count != 0
            && entry_count <= MAX_ZIP_ENTRIES
            && central_directory_size != u32::MAX as u64
            && central_directory_off != u32::MAX as u64
        {
            let mut entry = start.checked_add(central_directory_off)?;
            let central_directory_end = entry.checked_add(central_directory_size)?;
            let mut index = 0usize;
            while index < entry_count && entry + ZIP_CENTRAL_DIRECTORY_FILE_HEADER_SIZE <= central_directory_end {
                if started.elapsed() >= budget {
                    output_verbose(&format!(
                        "[dex resolver] raw clone framework jar dex scan timeout for {} after {} candidates",
                        descriptor, checked_candidates
                    ));
                    return None;
                }
                if entry + ZIP_CENTRAL_DIRECTORY_FILE_HEADER_SIZE > end
                    || read_u32(entry) != Some(ZIP_CENTRAL_DIRECTORY_FILE_HEADER_MAGIC)
                {
                    break;
                }

                let compression_method = read_u16(entry + 10)?;
                let file_name_len = read_u16(entry + 28)? as u64;
                let extra_len = read_u16(entry + 30)? as u64;
                let comment_len = read_u16(entry + 32)? as u64;
                let local_header_off = read_u32(entry + 42)? as u64;
                if file_name_len == 0 || file_name_len > 4096 {
                    break;
                }
                let name_start = entry.checked_add(ZIP_CENTRAL_DIRECTORY_FILE_HEADER_SIZE)?;
                if name_start + file_name_len > end || !super::safe_mem::is_readable(name_start, file_name_len as usize)
                {
                    break;
                }

                let file_name =
                    unsafe { std::slice::from_raw_parts(name_start as *const u8, file_name_len as usize) };
                if file_name.ends_with(b".dex") && compression_method == 0 {
                    let local_header = start.checked_add(local_header_off)?;
                    if local_header + ZIP_LOCAL_FILE_HEADER_SIZE <= end
                        && read_u32(local_header) == Some(ZIP_LOCAL_FILE_HEADER_MAGIC)
                    {
                        let local_name_len = read_u16(local_header + 26)? as u64;
                        let local_extra_len = read_u16(local_header + 28)? as u64;
                        let data_start = local_header
                            .checked_add(ZIP_LOCAL_FILE_HEADER_SIZE)?
                            .checked_add(local_name_len)?
                            .checked_add(local_extra_len)?;
                        if data_start + DEX_HEADER_SIZE as u64 <= end {
                            *checked_candidates += 1;
                            if let Some(image) = DexImage::from_base(data_start) {
                                if image.class_def_and_type_idx_by_descriptor(descriptor).is_some() {
                                    output_verbose(&format!(
                                        "[dex resolver] raw clone framework jar dex image hit {} -> base={:#x} path={} entry={}",
                                        descriptor,
                                        image.base,
                                        path,
                                        String::from_utf8_lossy(file_name)
                                    ));
                                    return Some(image);
                                }
                            }
                        }
                    }
                }

                entry = name_start
                    .checked_add(file_name_len)?
                    .checked_add(extra_len)?
                    .checked_add(comment_len)?;
                index += 1;
            }
        }
    }

    if read_u32(start) != Some(ZIP_LOCAL_FILE_HEADER_MAGIC) {
        return None;
    }

    let mut cursor = start;
    for _ in 0..MAX_ZIP_ENTRIES {
        if started.elapsed() >= budget {
            output_verbose(&format!(
                "[dex resolver] raw clone framework jar dex scan timeout for {} after {} candidates",
                descriptor, checked_candidates
            ));
            return None;
        }
        if cursor < start || cursor - start > MAX_ZIP_SCAN_BYTES || cursor + ZIP_LOCAL_FILE_HEADER_SIZE > end {
            break;
        }
        if read_u32(cursor) != Some(ZIP_LOCAL_FILE_HEADER_MAGIC) {
            break;
        }

        let flags = read_u16(cursor + 6)?;
        let compression_method = read_u16(cursor + 8)?;
        let compressed_size = read_u32(cursor + 18)? as u64;
        let file_name_len = read_u16(cursor + 26)? as u64;
        let extra_len = read_u16(cursor + 28)? as u64;
        if file_name_len == 0 || file_name_len > 4096 {
            break;
        }

        let name_start = cursor.checked_add(ZIP_LOCAL_FILE_HEADER_SIZE)?;
        let data_start = name_start.checked_add(file_name_len)?.checked_add(extra_len)?;
        if data_start > end || !super::safe_mem::is_readable(name_start, file_name_len as usize) {
            break;
        }

        let file_name = unsafe { std::slice::from_raw_parts(name_start as *const u8, file_name_len as usize) };
        let is_dex_entry = file_name.ends_with(b".dex");
        if is_dex_entry && compression_method == 0 && data_start + DEX_HEADER_SIZE as u64 <= end {
            *checked_candidates += 1;
            if let Some(image) = DexImage::from_base(data_start) {
                if image.class_def_and_type_idx_by_descriptor(descriptor).is_some() {
                    output_verbose(&format!(
                        "[dex resolver] raw clone framework jar dex image hit {} -> base={:#x} path={} entry={}",
                        descriptor,
                        image.base,
                        path,
                        String::from_utf8_lossy(file_name)
                    ));
                    return Some(image);
                }
            }
        }

        if flags & ZIP_FLAG_DATA_DESCRIPTOR != 0 || compressed_size == u32::MAX as u64 {
            break;
        }
        let next = data_start.checked_add(compressed_size)?;
        if next <= cursor {
            break;
        }
        cursor = next;
    }

    None
}

fn find_framework_vdex_image_for_descriptor(
    descriptor: &str,
    started: std::time::Instant,
    budget: std::time::Duration,
) -> Option<DexImage> {
    let Some(maps) = crate::jsapi::util::read_proc_self_maps() else {
        return None;
    };

    let mut map_entries: Vec<(u8, u64, u64, &str)> = Vec::new();
    for line in maps.lines() {
        let Some((start, end, perms, _file_offset, path)) = parse_maps_line_for_class_scan(line) else {
            continue;
        };
        if !perms.starts_with('r') || end <= start || !is_framework_vdex_region_name(path) {
            continue;
        }
        map_entries.push((framework_vdex_region_priority(path, descriptor), start, end, path));
    }
    map_entries.sort_by_key(|(priority, start, _, _)| (*priority, *start));

    let mut checked = 0usize;
    for (_priority, start, end, path) in map_entries {
        if started.elapsed() >= budget {
            output_verbose(&format!(
                "[dex resolver] raw clone framework vdex scan timeout for {} after {} candidates",
                descriptor, checked
            ));
            return None;
        }

        let Some(vdex) = VdexImage::from_mapping(start, end) else {
            continue;
        };
        let version = String::from_utf8_lossy(&vdex.version).trim_end_matches('\0').to_string();
        for image in vdex.dex_images() {
            checked += 1;
            if image.class_def_and_type_idx_by_descriptor(descriptor).is_some() {
                output_verbose(&format!(
                    "[dex resolver] raw clone framework vdex hit {} -> dex={:#x} kind={:?} vdex={:#x} version={} path={}",
                    descriptor, image.base, image.kind, vdex.base, version, path
                ));
                return Some(image);
            }
        }
    }

    None
}

fn scan_boot_class_table_for_descriptor(descriptor: &str, seed: Option<(&DexImage, u32, u32)>) -> Option<u64> {
    let descriptor_hash = modified_utf8_hash(descriptor);
    let art_images = enumerate_boot_art_images();
    if art_images.is_empty() {
        return None;
    }

    let mut candidates = Vec::new();
    'images: for art_image in art_images.iter().filter(|img| !img.class_tables.is_empty()) {
        for table in &art_image.class_tables {
            let before = candidates.len();
            scan_art_class_table_probe_candidates(table, descriptor_hash, descriptor, seed, &mut candidates);
            if candidates.len() != before {
                output_verbose(&format!(
                    "[dex resolver] boot image class table hash probe hit {} section={}",
                    descriptor, table.section_index
                ));
                output_verbose(&format!(
                    "[dex resolver] boot image class table {} section={} entries={} buckets={} image={} sections_off={:#x} class_table={:#x}+{}",
                    art_image.path,
                    table.section_index,
                    table.num_elements,
                    table.num_buckets,
                    art_image.image_size,
                    art_image.header_sections_off,
                    table.start,
                    table.size
                ));
                break 'images;
            }

            for tag_filter in [Some(descriptor_hash & 0x7), None] {
                let before = candidates.len();
                scan_art_class_table_candidates(table, tag_filter, descriptor, seed, &mut candidates);
                if candidates.len() != before {
                    if tag_filter.is_none() {
                        output_verbose(&format!(
                            "[dex resolver] boot image class table tag fallback hit {} section={}",
                            descriptor, table.section_index
                        ));
                    }
                    break;
                }
            }
            if !candidates.is_empty() {
                output_verbose(&format!(
                    "[dex resolver] boot image class table {} section={} entries={} buckets={} image={} sections_off={:#x} class_table={:#x}+{}",
                    art_image.path,
                    table.section_index,
                    table.num_elements,
                    table.num_buckets,
                    art_image.image_size,
                    art_image.header_sections_off,
                    table.start,
                    table.size
                ));
                break 'images;
            }
        }
    }

    match candidates.as_slice() {
        [one] => Some(*one),
        [] => None,
        many => {
            output_verbose(&format!(
                "[dex resolver] boot image class table ambiguous for {}: {} candidates, using first {:#x}",
                descriptor,
                many.len(),
                many[0]
            ));
            Some(many[0])
        }
    }
}

fn scan_art_class_table_probe_candidates(
    table: &ArtClassTable,
    descriptor_hash: u32,
    descriptor: &str,
    seed: Option<(&DexImage, u32, u32)>,
    candidates: &mut Vec<u64>,
) {
    if table.num_buckets == 0 {
        return;
    }

    const MAX_LINEAR_PROBE: u64 = 1024;
    let start = descriptor_hash as u64 % table.num_buckets;
    let limit = table.num_buckets.min(MAX_LINEAR_PROBE);
    for step in 0..limit {
        let index = (start + step) % table.num_buckets;
        let slot_addr = table.entries + index * 4;
        let Some(slot) = read_u32(slot_addr) else {
            break;
        };
        if slot == 0 {
            break;
        }
        let class_obj = (slot & !0x7) as u64;
        if class_obj < 0x1000 || candidates.contains(&class_obj) {
            continue;
        }
        if class_mirror_candidate_matches(class_obj, descriptor, seed) {
            candidates.push(class_obj);
            break;
        }
    }
}

fn scan_art_class_table_candidates(
    table: &ArtClassTable,
    tag_filter: Option<u32>,
    descriptor: &str,
    seed: Option<(&DexImage, u32, u32)>,
    candidates: &mut Vec<u64>,
) {
    const MAX_VALIDATED_CANDIDATES: u64 = 256;
    let mut seen_non_zero = 0u64;
    let mut validated_candidates = 0u64;
    for index in 0..table.num_buckets {
        let slot_addr = table.entries + index * 4;
        let Some(slot) = read_u32(slot_addr) else {
            continue;
        };
        if slot == 0 {
            continue;
        }
        seen_non_zero += 1;
        if tag_filter.is_some_and(|tag| (slot & 0x7) != tag) {
            continue;
        }
        validated_candidates += 1;
        if validated_candidates > MAX_VALIDATED_CANDIDATES {
            break;
        }
        let class_obj = (slot & !0x7) as u64;
        if class_obj < 0x1000 || candidates.contains(&class_obj) {
            continue;
        }
        if class_mirror_candidate_matches(class_obj, descriptor, seed) {
            candidates.push(class_obj);
            break;
        }
        if seen_non_zero > table.num_elements.saturating_mul(2).max(4096) {
            break;
        }
    }
}

fn enumerate_framework_class_regions() -> Vec<ClassMirrorScanRegion> {
    let art_regions: Vec<ClassMirrorScanRegion> = enumerate_boot_art_images()
        .into_iter()
        .filter_map(|image| image.object_region())
        .collect();
    if !art_regions.is_empty() {
        output_verbose(&format!(
            "[dex resolver] boot image object sections available: {} regions",
            art_regions.len()
        ));
        return art_regions;
    }

    let Some(maps) = crate::jsapi::util::read_proc_self_maps() else {
        return Vec::new();
    };

    let mut regions = Vec::new();
    for line in maps.lines() {
        let Some((start, end, perms, _file_offset, path)) = parse_maps_line_for_class_scan(line) else {
            continue;
        };
        if !perms.starts_with('r') || end <= start {
            continue;
        }
        if is_framework_class_region_name(path) {
            regions.push((framework_class_region_priority(path), ClassMirrorScanRegion { start, end }));
        }
    }
    regions.sort_by_key(|(priority, region)| (*priority, region.start));
    let regions = regions.into_iter().map(|(_, region)| region).collect();
    regions
}

fn enumerate_boot_art_images() -> Vec<ArtImage> {
    let Some(maps) = crate::jsapi::util::read_proc_self_maps() else {
        return Vec::new();
    };
    let mut images = Vec::new();
    for line in maps.lines() {
        let Some((start, end, perms, _file_offset, path)) = parse_maps_line_for_class_scan(line) else {
            continue;
        };
        if !perms.starts_with('r') || end <= start || !is_framework_art_region_name(path) {
            continue;
        }
        if let Some(image) = ArtImage::from_mapping(start, end, path) {
            images.push((framework_art_region_priority(path), image));
        }
    }
    images.sort_by_key(|(priority, image)| (*priority, image.base));
    images.into_iter().map(|(_, image)| image).collect()
}

#[allow(dead_code)]
fn enumerate_framework_oat_images() -> Vec<OatImage> {
    let Some(maps) = crate::jsapi::util::read_proc_self_maps() else {
        return Vec::new();
    };
    let mut images = Vec::new();
    for line in maps.lines() {
        let Some((start, end, perms, _file_offset, path)) = parse_maps_line_for_class_scan(line) else {
            continue;
        };
        if !perms.starts_with('r') || end <= start || !is_framework_oat_region_name(path) {
            continue;
        }
        if let Some(image) = OatImage::from_mapping(start, end) {
            images.push(image);
        }
    }
    images
}

fn parse_maps_line_for_class_scan(line: &str) -> Option<(u64, u64, &str, u64, &str)> {
    let mut rest = line.trim_start();
    let sp1 = rest.find(' ')?;
    let range = &rest[..sp1];
    rest = rest[sp1..].trim_start();
    let sp2 = rest.find(' ')?;
    let perms = &rest[..sp2];
    rest = rest[sp2..].trim_start();
    let sp3 = rest.find(' ')?;
    let file_offset = u64::from_str_radix(&rest[..sp3], 16).ok()?;
    rest = rest[sp3..].trim_start();
    let sp4 = rest.find(' ')?;
    rest = rest[sp4..].trim_start();
    let sp5 = rest.find(|c: char| c.is_whitespace())?;
    rest = rest[sp5..].trim_start();
    let path = rest.trim_end();

    let mut parts = range.splitn(2, '-');
    let start = u64::from_str_radix(parts.next()?, 16).ok()?;
    let end = u64::from_str_radix(parts.next()?, 16).ok()?;
    Some((start, end, perms, file_offset, path))
}

fn is_framework_class_region_name(path: &str) -> bool {
    if path.is_empty() {
        return false;
    }
    if is_framework_art_region_name(path) {
        return true;
    }
    let path = normalized_framework_map_path(path);
    path.starts_with("[anon:dalvik-/system/framework/")
        || path.starts_with("[anon:dalvik-/apex/")
        || path.starts_with("[anon:dalvik-/system_ext/framework/")
        || path.starts_with("[anon:dalvik-/product/framework/")
        || path.starts_with("[anon:dalvik-/vendor/framework/")
}

fn framework_class_region_priority(path: &str) -> u8 {
    framework_art_region_priority(path)
}

fn is_framework_art_region_name(path: &str) -> bool {
    if path.is_empty() {
        return false;
    }
    let path = normalized_framework_map_path(path);
    path.contains(".art") && is_framework_runtime_image_path(path)
}

fn framework_art_region_priority(path: &str) -> u8 {
    let path = normalized_framework_map_path(path);
    if path.ends_with("/boot-framework.art") {
        0
    } else if path.ends_with("/boot.art") {
        1
    } else if path.ends_with("/boot-core-libart.art") {
        2
    } else {
        3
    }
}

fn is_framework_vdex_region_name(path: &str) -> bool {
    let path = normalized_framework_map_path(path);
    if path.is_empty() || !path.contains(".vdex") {
        return false;
    }
    is_framework_runtime_image_path(path)
}

fn framework_vdex_region_priority(path: &str, descriptor: &str) -> u8 {
    let path = normalized_framework_map_path(path);
    if descriptor.starts_with("Landroid/") && path.contains("boot-framework.vdex") {
        0
    } else if (descriptor.starts_with("Ljava/") || descriptor.starts_with("Ljavax/"))
        && (path.contains("boot-core-oj.vdex") || path.contains("boot.vdex"))
    {
        0
    } else if path.contains("boot-framework.vdex") {
        1
    } else if path.contains("boot-core-oj.vdex") || path.contains("boot.vdex") {
        2
    } else {
        3
    }
}

fn is_framework_oat_region_name(path: &str) -> bool {
    let path = normalized_framework_map_path(path);
    if path.is_empty() || !(path.contains(".oat") || path.contains(".odex") || path.ends_with(".art")) {
        return false;
    }
    is_framework_runtime_image_path(path)
}

fn is_framework_dex_region_name(path: &str) -> bool {
    if path.is_empty() {
        return false;
    }
    let path = normalized_framework_map_path(path);
    if !path.ends_with(".jar") {
        return false;
    }
    path.starts_with("/system/framework/")
        || path.starts_with("/system_ext/framework/")
        || path.starts_with("/product/framework/")
        || path.starts_with("/vendor/framework/")
        || path.starts_with("/apex/")
}

fn framework_dex_region_priority(path: &str, descriptor: &str) -> u8 {
    let path = normalized_framework_map_path(path);
    if descriptor.starts_with("Landroid/") && path.ends_with("/framework.jar") {
        0
    } else if (descriptor.starts_with("Ljava/") || descriptor.starts_with("Ljavax/")) && path.ends_with("/core-oj.jar") {
        0
    } else if path.ends_with("/framework.jar") {
        1
    } else if path.ends_with("/core-oj.jar") || path.ends_with("/core-libart.jar") {
        2
    } else {
        3
    }
}

fn normalized_framework_map_path(path: &str) -> &str {
    let path = path.trim_end();
    let path = path.strip_suffix(" (deleted)").unwrap_or(path);
    path.strip_suffix(']').unwrap_or(path)
}

fn is_framework_runtime_image_path(path: &str) -> bool {
    path.starts_with("[anon:dalvik-/system/framework/")
        || path.starts_with("[anon:dalvik-/apex/")
        || path.starts_with("[anon:dalvik-/system_ext/framework/")
        || path.starts_with("[anon:dalvik-/product/framework/")
        || path.starts_with("[anon:dalvik-/vendor/framework/")
        || path.contains("/system/framework/")
        || path.contains("/system_ext/framework/")
        || path.contains("/product/framework/")
        || path.contains("/vendor/framework/")
        || path.contains("/apex/")
        || path.contains("/data/dalvik-cache/")
        || path.contains("/data/misc/apexdata/")
}

fn class_mirror_candidate_matches(
    class_obj: u64,
    descriptor: &str,
    seed: Option<(&DexImage, u32, u32)>,
) -> bool {
    if class_obj < 0x1000 || !super::safe_mem::is_readable(class_obj, 0x40) {
        return false;
    }

    if let Some(candidate_image) = dex_image_from_class_with_logging(class_obj, false) {
        if candidate_image.class_object_matches_descriptor(class_obj, descriptor) {
            let seed_base = seed.map(|(image, _, _)| image.base);
            output_verbose(&format!(
                "[dex resolver] Class {:#x} validated by own DexFile base={:#x} kind={:?}{}",
                class_obj,
                candidate_image.base,
                candidate_image.kind,
                seed_base.map_or_else(String::new, |base| format!("; seed dex={:#x}", base))
            ));
            remember_class_mirror_dex_image(class_obj, &candidate_image);
            return true;
        }

        if seed.is_some_and(|(image, _, _)| candidate_image.base == image.base) {
            return false;
        }
    }

    let Some((image, class_def_idx, class_idx)) = seed else {
        return false;
    };
    if !image.class_object_matches_descriptor_by_indices(class_obj, class_def_idx, class_idx) {
        return false;
    }
    remember_class_mirror_dex_image(class_obj, image);
    true
}

fn resolve_super_class_mirror(class_obj: u64, expected_descriptor: &str) -> Option<u64> {
    const CANDIDATES_MIN: usize = 8;
    const CANDIDATES_MAX: usize = 96;
    const MAX_FAILURE_SAMPLES: usize = 8;

    let mut hits = Vec::new();
    let mut samples = Vec::new();
    for offset in (CANDIDATES_MIN..=CANDIDATES_MAX).step_by(4) {
        let Some(candidate) = (unsafe { read_heap_ref(class_obj + offset as u64) }) else {
            continue;
        };
        let Some(image) = dex_image_from_class(candidate) else {
            continue;
        };
        if image.class_object_descriptor_matches(candidate, expected_descriptor) {
            hits.push((offset, candidate));
        } else if samples.len() < MAX_FAILURE_SAMPLES {
            let descriptors = image.class_object_descriptors(candidate);
            if !descriptors.is_empty() {
                samples.push(format!(
                    "Class+{:#x}->{:#x} [{}]",
                    offset,
                    candidate,
                    descriptors
                        .into_iter()
                        .take(4)
                        .map(|(off, desc)| format!("{:#x}:{}", off, desc))
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
        }
    }

    match hits.len() {
        0 => {
            output_verbose(&format!(
                "[dex resolver] no super_class_ mirror matched {}; candidates={}",
                expected_descriptor,
                if samples.is_empty() {
                    "<none>".to_string()
                } else {
                    samples.join(" | ")
                }
            ));
            None
        }
        1 => Some(hits[0].1),
        _ => {
            output_verbose(&format!(
                "[dex resolver] ambiguous super_class_ mirrors for {}, using Class+{:#x}",
                expected_descriptor, hits[0].0
            ));
            Some(hits[0].1)
        }
    }
}

struct DexDeclaredField {
    dex_field_index: u32,
    name: String,
    jni_sig: String,
    access_flags: u32,
}

fn resolve_declared_fields_from_class(
    class_obj: u64,
    dex_fields: &[DexDeclaredField],
) -> Option<Vec<DexFieldInfo>> {
    let Some(field_spec) = get_art_field_spec() else {
        output_verbose("[dex resolver] ArtField spec unavailable for field self-parse");
        return None;
    };

    const MAX_CLASS_SCAN: usize = 0x100;
    const MAX_FIELDS_PER_CLASS: u32 = 4096;
    let mut out = Vec::with_capacity(dex_fields.len());
    if dex_fields.is_empty() {
        return Some(out);
    }

    let mut expected = HashMap::with_capacity(dex_fields.len());
    for (idx, dex_field) in dex_fields.iter().enumerate() {
        expected.insert(dex_field.dex_field_index, idx);
    }

    let mut resolved: HashMap<u32, u64> = HashMap::new();

    for offset in (0..MAX_CLASS_SCAN).step_by(4) {
        let fields_array = unsafe { safe_read_u64(class_obj + offset as u64) } & PAC_STRIP_MASK;
        if fields_array < 0x1000 || !super::safe_mem::is_readable(fields_array, 4) {
            continue;
        }

        let fields_len = unsafe { super::safe_mem::safe_read_u32(fields_array) };
        if fields_len == 0 || fields_len > MAX_FIELDS_PER_CLASS {
            continue;
        }

        let before = resolved.len();
        collect_fields_from_array(
            fields_array,
            fields_len,
            field_spec.size,
            &expected,
            dex_fields,
            &mut resolved,
        );
        if resolved.len() != before {
            output_verbose(&format!(
                "[dex resolver] Class {:#x}+{:#x} fields_ array {:#x} len={} matched {} dex fields",
                class_obj,
                offset,
                fields_array,
                fields_len,
                resolved.len() - before
            ));
        }
        if resolved.len() >= dex_fields.len() {
            break;
        }
    }

    for dex_field in dex_fields {
        if let Some(art_field) = resolved.get(&dex_field.dex_field_index).copied() {
            let field_offset = unsafe {
                super::safe_mem::safe_read_u32(art_field + field_spec.offset_offset as u64)
            };
            out.push(DexFieldInfo {
                name: dex_field.name.clone(),
                jni_sig: dex_field.jni_sig.clone(),
                field_id: art_field as *mut std::ffi::c_void,
                field_offset,
                is_static: (dex_field.access_flags & K_ACC_STATIC) != 0,
            });
        }
    }

    Some(out)
}

fn collect_fields_from_array(
    fields_array: u64,
    fields_len: u32,
    field_size: usize,
    expected: &HashMap<u32, usize>,
    dex_fields: &[DexDeclaredField],
    resolved: &mut HashMap<u32, u64>,
) {
    const FIRST_FIELD_OFFSET: usize = 4;
    for index in 0..fields_len as usize {
        let art_field = fields_array + FIRST_FIELD_OFFSET as u64 + (index * field_size) as u64;
        if !super::safe_mem::is_readable(art_field, field_size) {
            continue;
        }

        for dex_offset in ART_FIELD_DEX_FIELD_INDEX_CANDIDATE_OFFSETS {
            if dex_offset + 4 > field_size {
                continue;
            }
            let field_index = unsafe { super::safe_mem::safe_read_u32(art_field + dex_offset as u64) };
            if resolved.contains_key(&field_index) {
                continue;
            }

            let Some(dex_field_idx) = expected.get(&field_index).copied() else {
                continue;
            };
            let dex_field = &dex_fields[dex_field_idx];
            if art_field_access_flags_match(art_field, field_size, dex_offset, dex_field.access_flags) {
                resolved.insert(field_index, art_field);
                break;
            }
        }
    }
}

fn art_field_access_flags_match(
    art_field: u64,
    field_size: usize,
    dex_field_index_offset: usize,
    dex_access_flags: u32,
) -> bool {
    const DEX_ACCESS_MASK: u32 = 0x0000_ffff;
    for offset in [4usize, 12, 16] {
        if offset == dex_field_index_offset
            || offset + 4 > field_size
            || !super::safe_mem::is_readable(art_field + offset as u64, 4)
        {
            continue;
        }
        let flags = unsafe { super::safe_mem::safe_read_u32(art_field + offset as u64) };
        if (flags & K_ACC_STATIC) == (dex_access_flags & K_ACC_STATIC)
            && ((dex_access_flags & DEX_ACCESS_MASK) == 0
                || (flags & DEX_ACCESS_MASK) == (dex_access_flags & DEX_ACCESS_MASK))
        {
            return true;
        }
    }

    true
}

fn art_method_access_flags_match(
    art_method: u64,
    method_size: usize,
    dex_method_index_offset: usize,
    dex_access_flags: u32,
) -> bool {
    const DEX_ACCESS_MASK: u32 = 0x0000_ffff;
    const CANDIDATES: [usize; 6] = [4, 36, 12, 20, 28, 32];

    for offset in CANDIDATES {
        if offset == dex_method_index_offset
            || offset + 4 > method_size
            || !super::safe_mem::is_readable(art_method + offset as u64, 4)
        {
            continue;
        }
        let flags = unsafe { super::safe_mem::safe_read_u32(art_method + offset as u64) };
        if (dex_access_flags & DEX_ACCESS_MASK) != 0
            && (flags & DEX_ACCESS_MASK) == (dex_access_flags & DEX_ACCESS_MASK)
        {
            return true;
        }
    }

    true
}

fn resolve_from_class_methods(
    class_obj: u64,
    images: &[DexImage],
    class_descriptor: &str,
    class_name: &str,
    method_name: &str,
    signature: &str,
    force_static: bool,
) -> Option<(u64, bool)> {
    if images.is_empty() {
        return None;
    }

    const MAX_CLASS_SCAN: usize = 0x100;
    const MAX_METHODS_PER_CLASS: u32 = 8192;

    for offset in (0..MAX_CLASS_SCAN).step_by(4) {
        let methods_array = unsafe { safe_read_u64(class_obj + offset as u64) } & PAC_STRIP_MASK;
        if methods_array < 0x1000 || !super::safe_mem::is_readable(methods_array, 4) {
            continue;
        }

        let methods_len = unsafe { super::safe_mem::safe_read_u32(methods_array) };
        if methods_len == 0 || methods_len > MAX_METHODS_PER_CLASS {
            continue;
        }

        if let Some(resolved) = resolve_from_methods_array(
            methods_array,
            methods_len,
            images,
            class_descriptor,
            class_name,
            method_name,
            signature,
            force_static,
        ) {
            output_verbose(&format!(
                "[dex resolver] methods_ candidate Class+{:#x} matched {}.{}{}",
                offset, class_name, method_name, signature
            ));
            return Some(resolved);
        }
    }

    log_class_method_candidates(
        class_obj,
        images,
        class_name,
        method_name,
        signature,
    );
    None
}

fn log_class_method_candidates(
    class_obj: u64,
    images: &[DexImage],
    class_name: &str,
    method_name: &str,
    signature: &str,
) {
    const MAX_CLASS_SCAN: usize = 0x100;
    const MAX_METHODS_PER_CLASS: u32 = 8192;
    const MAX_ARRAY_LOGS: usize = 6;
    const MAX_METHOD_LOGS: usize = 6;

    let mut arrays_logged = 0usize;
    for offset in (0..MAX_CLASS_SCAN).step_by(4) {
        if arrays_logged >= MAX_ARRAY_LOGS {
            break;
        }

        let methods_array = unsafe { safe_read_u64(class_obj + offset as u64) } & PAC_STRIP_MASK;
        if methods_array < 0x1000 || !super::safe_mem::is_readable(methods_array, 4) {
            continue;
        }

        let methods_len = unsafe { super::safe_mem::safe_read_u32(methods_array) };
        if methods_len == 0 || methods_len > MAX_METHODS_PER_CLASS {
            continue;
        }

        let mut decoded = Vec::new();
        for first_method_offset in ART_METHOD_ARRAY_FIRST_ELEMENT_OFFSETS {
            for method_size in ART_METHOD_SIZE_CANDIDATES {
                for index in 0..(methods_len as usize).min(MAX_METHOD_LOGS) {
                    let art_method =
                        methods_array + first_method_offset as u64 + (index * method_size) as u64;
                    if !super::safe_mem::is_readable(art_method, method_size) {
                        continue;
                    }

                    let mut parts = Vec::new();
                    for dex_offset in ART_METHOD_DEX_METHOD_INDEX_CANDIDATE_OFFSETS {
                        let dex_method_index =
                            unsafe { super::safe_mem::safe_read_u32(art_method + dex_offset as u64) };
                        if let Some(desc) = images
                            .iter()
                            .find_map(|image| image.method_description(dex_method_index))
                        {
                            parts.push(format!("+{}:{}={}", dex_offset, dex_method_index, desc));
                        }
                    }
                    if !parts.is_empty() {
                        decoded.push(format!(
                            "off{} sz{}#{} {:#x} [{}]",
                            first_method_offset,
                            method_size,
                            index,
                            art_method,
                            parts.join(", ")
                        ));
                    }
                }
            }
        }

        output_verbose(&format!(
            "[dex resolver] no match for {}.{}{}; candidate Class+{:#x} array={:#x} len={} sample={}",
            class_name,
            method_name,
            signature,
            offset,
            methods_array,
            methods_len,
            if decoded.is_empty() {
                "<none>".to_string()
            } else {
                decoded.join(" | ")
            }
        ));
        arrays_logged += 1;
    }
}

fn resolve_from_methods_array(
    methods_array: u64,
    methods_len: u32,
    images: &[DexImage],
    class_descriptor: &str,
    class_name: &str,
    method_name: &str,
    signature: &str,
    force_static: bool,
) -> Option<(u64, bool)> {
    for first_method_offset in ART_METHOD_ARRAY_FIRST_ELEMENT_OFFSETS {
        for method_size in ART_METHOD_SIZE_CANDIDATES {
            if let Some(resolved) = resolve_from_methods_array_with_layout(
                methods_array,
                methods_len,
                first_method_offset,
                method_size,
                images,
                class_descriptor,
                class_name,
                method_name,
                signature,
                force_static,
            ) {
                return Some(resolved);
            }
        }
    }

    None
}

fn resolve_from_methods_array_with_layout(
    methods_array: u64,
    methods_len: u32,
    first_method_offset: usize,
    method_size: usize,
    images: &[DexImage],
    class_descriptor: &str,
    class_name: &str,
    method_name: &str,
    signature: &str,
    force_static: bool,
) -> Option<(u64, bool)> {
    let mut static_match: Option<u64> = None;
    for index in 0..methods_len as usize {
        let art_method = methods_array + first_method_offset as u64 + (index * method_size) as u64;
        if !super::safe_mem::is_readable(art_method, method_size) {
            continue;
        }

        let Some((dex_method_index_offset, dex_method_index, dex_access_flags)) =
            find_matching_dex_method_index(art_method, images, class_descriptor, method_name, signature)
        else {
            continue;
        };
        let is_static = (dex_access_flags & K_ACC_STATIC) != 0;

        if force_static && !is_static {
            continue;
        }

        if dex_method_index_offset != ART_METHOD_DEX_METHOD_INDEX_CANDIDATE_OFFSETS[0] {
            output_verbose(&format!(
                "[dex resolver] dex_method_index offset adapted: ArtMethod={:#x}, offset={}, index={}",
                art_method, dex_method_index_offset, dex_method_index
            ));
        }
        if first_method_offset != ART_METHOD_ARRAY_FIRST_ELEMENT_OFFSETS[0] {
            output_verbose(&format!(
                "[dex resolver] methods_ first-element offset adapted: array={:#x}, offset={}",
                methods_array, first_method_offset
            ));
        }
        if method_size != ART_METHOD_SIZE_CANDIDATES[0] {
            output_verbose(&format!(
                "[dex resolver] ArtMethod size adapted: array={:#x}, size={}",
                methods_array, method_size
            ));
        }

        let Some(spec) =
            validate_art_method_candidate(art_method, method_size, dex_method_index_offset, dex_access_flags)
        else {
            continue;
        };
        if ART_METHOD_SPEC.get().is_none() {
            cache_art_method_spec_from_self_parse(spec);
        }

        if is_static {
            static_match = Some(art_method);
            if force_static {
                output_verbose(&format!(
                    "[dex resolver] resolved static {}.{}{} -> ArtMethod={:#x}",
                    class_name, method_name, signature, art_method
                ));
                return Some((art_method, true));
            }
            continue;
        }

        output_verbose(&format!(
            "[dex resolver] resolved instance {}.{}{} -> ArtMethod={:#x}",
            class_name, method_name, signature, art_method
        ));
        return Some((art_method, false));
    }

    if !force_static {
        if let Some(art_method) = static_match {
            output_verbose(&format!(
                "[dex resolver] resolved fallback static {}.{}{} -> ArtMethod={:#x}",
                class_name, method_name, signature, art_method
            ));
            return Some((art_method, true));
        }
    }

    None
}

fn find_matching_dex_method_index(
    art_method: u64,
    images: &[DexImage],
    class_descriptor: &str,
    method_name: &str,
    signature: &str,
) -> Option<(usize, u32, u32)> {
    for offset in ART_METHOD_DEX_METHOD_INDEX_CANDIDATE_OFFSETS {
        let dex_method_index =
            unsafe { super::safe_mem::safe_read_u32(art_method + offset as u64) };
        if let Some(access_flags) = images.iter().find_map(|image| {
            image.method_access_flags(
                dex_method_index,
                class_descriptor,
                method_name,
                signature,
            )
        }) {
            return Some((offset, dex_method_index, access_flags));
        }
    }

    None
}

fn validate_art_method_candidate(
    art_method: u64,
    method_size: usize,
    dex_method_index_offset: usize,
    dex_access_flags: u32,
) -> Option<ArtMethodSpec> {
    let spec = if let Some(cached) = ART_METHOD_SPEC.get().copied() {
        cached
    } else {
        infer_art_method_spec(art_method, method_size, dex_method_index_offset, dex_access_flags)?
    };

    if !art_method_candidate_matches_spec(art_method, method_size, &spec, dex_access_flags) {
        return None;
    }

    Some(spec)
}

fn art_method_candidate_matches_spec(
    art_method: u64,
    method_size: usize,
    spec: &ArtMethodSpec,
    dex_access_flags: u32,
) -> bool {
    const DEX_ACCESS_MASK: u32 = 0x0000_ffff;

    if method_size < spec.size
        || spec.entry_point_offset + 8 > method_size
        || spec.access_flags_offset + 4 > method_size
        || !super::safe_mem::is_readable(art_method + spec.entry_point_offset as u64, 8)
        || !super::safe_mem::is_readable(art_method + spec.access_flags_offset as u64, 4)
    {
        output_verbose(&format!(
            "[dex resolver] reject ArtMethod candidate {:#x}: layout too small (candidate_size={}, spec={:?})",
            art_method, method_size, spec
        ));
        return false;
    }

    let entry_point = unsafe { super::safe_mem::safe_read_u64(art_method + spec.entry_point_offset as u64) };
    if !is_code_pointer(entry_point) {
        output_verbose(&format!(
            "[dex resolver] reject ArtMethod candidate {:#x}: entry_point at +{} is not executable ({:#x})",
            art_method, spec.entry_point_offset, entry_point
        ));
        return false;
    }

    let flags = unsafe { super::safe_mem::safe_read_u32(art_method + spec.access_flags_offset as u64) };
    if (dex_access_flags & DEX_ACCESS_MASK) != 0
        && (flags & DEX_ACCESS_MASK) != (dex_access_flags & DEX_ACCESS_MASK)
    {
        output_verbose(&format!(
            "[dex resolver] reject ArtMethod candidate {:#x}: access_flags mismatch at +{} runtime={:#x}, dex={:#x}",
            art_method, spec.access_flags_offset, flags, dex_access_flags
        ));
        return false;
    }

    true
}

fn infer_art_method_spec(
    art_method: u64,
    method_size: usize,
    dex_method_index_offset: usize,
    dex_access_flags: u32,
) -> Option<ArtMethodSpec> {
    let entry_point_offset = infer_entry_point_offset(art_method, method_size)?;
    let data_offset = entry_point_offset.checked_sub(8)?;
    let access_flags_offset =
        infer_access_flags_offset(art_method, method_size, dex_method_index_offset, dex_access_flags);
    let size = method_size.max(entry_point_offset + 8).max(access_flags_offset + 4);

    Some(ArtMethodSpec {
        access_flags_offset,
        data_offset,
        entry_point_offset,
        size,
    })
}

fn infer_entry_point_offset(art_method: u64, method_size: usize) -> Option<usize> {
    const CANDIDATES: [usize; 7] = [24, 32, 16, 40, 8, 48, 56];

    for offset in CANDIDATES {
        if offset + 8 > method_size || !super::safe_mem::is_readable(art_method + offset as u64, 8) {
            continue;
        }
        let value = unsafe { super::safe_mem::safe_read_u64(art_method + offset as u64) };
        if is_code_pointer(value) {
            if offset != CANDIDATES[0] {
                output_verbose(&format!(
                    "[art spec] entry_point offset adapted by self-parse: ArtMethod={:#x}, offset={}, value={:#x}",
                    art_method, offset, value
                ));
            }
            return Some(offset);
        }
    }

    output_verbose(&format!(
        "[art spec] entry_point self-parse rejected: no executable candidate for ArtMethod={:#x}, size={}",
        art_method, method_size
    ));
    None
}

fn infer_access_flags_offset(
    art_method: u64,
    method_size: usize,
    dex_method_index_offset: usize,
    dex_access_flags: u32,
) -> usize {
    const DEX_ACCESS_MASK: u32 = 0x0000_ffff;
    const CANDIDATES: [usize; 6] = [4, 36, 12, 20, 28, 32];

    for offset in CANDIDATES {
        if offset == dex_method_index_offset
            || offset + 4 > method_size
            || !super::safe_mem::is_readable(art_method + offset as u64, 4)
        {
            continue;
        }
        let flags = unsafe { super::safe_mem::safe_read_u32(art_method + offset as u64) };
        if (dex_access_flags & DEX_ACCESS_MASK) != 0
            && (flags & DEX_ACCESS_MASK) == (dex_access_flags & DEX_ACCESS_MASK)
        {
            if offset != CANDIDATES[0] {
                output_verbose(&format!(
                    "[art spec] access_flags offset adapted by dex flags: ArtMethod={:#x}, offset={}, flags={:#x}, dex_flags={:#x}",
                    art_method, offset, flags, dex_access_flags
                ));
            }
            return offset;
        }
    }

    let api_level = get_android_api_level();
    if api_level >= 36 && method_size >= 40 {
        return 36;
    }

    4
}

fn dex_image_from_class(class_obj: u64) -> Option<DexImage> {
    dex_image_from_class_with_logging(class_obj, true)
}

fn dex_image_from_class_with_logging(class_obj: u64, log: bool) -> Option<DexImage> {
    unsafe {
        for class_off in (8..0x40).step_by(4) {
            let Some(dex_cache_obj) = read_heap_ref(class_obj + class_off) else {
                continue;
            };
            let Some(image) = dex_image_from_dex_cache_with_logging(dex_cache_obj, log) else {
                continue;
            };
            if log {
                output_verbose(&format!(
                    "[dex resolver] Class+{:#x} DexCache={:#x} -> DexFile image base={:#x}",
                    class_off, dex_cache_obj, image.base
                ));
            }
            return Some(image);
        }
    }
    if let Some(image) = cached_dex_image_for_class(class_obj) {
        if log {
            output_verbose(&format!(
                "[dex resolver] Class {:#x} -> cached framework DexImage base={:#x}",
                class_obj, image.base
            ));
        }
        return Some(image);
    }
    None
}

unsafe fn dex_image_from_dex_cache_with_logging(dex_cache_obj: u64, log: bool) -> Option<DexImage> {
    if !super::safe_mem::is_readable(dex_cache_obj, 0x20) {
        return None;
    }

    for dex_file_off in (8..0x180).step_by(8) {
        let dex_file = safe_read_u64(dex_cache_obj + dex_file_off) & PAC_STRIP_MASK;
        let Some(image) = dex_image_from_dex_file_with_logging(dex_file, log) else {
            continue;
        };
        if log {
            output_verbose(&format!(
                "[dex resolver] DexCache+{:#x} DexFile*={:#x}",
                dex_file_off, dex_file
            ));
        }
        return Some(image);
    }

    None
}

unsafe fn dex_image_from_dex_file_with_logging(dex_file: u64, log: bool) -> Option<DexImage> {
    if dex_file < 0x1000 || !super::safe_mem::is_readable(dex_file, 0x40) {
        return None;
    }

    // DexFile is a C++ object and has varied across releases. Scan its early
    // pointer-sized fields for a Begin() pointer instead of hardcoding a vtable
    // dependent offset.
    for begin_off in (0..0x80).step_by(8) {
        let begin = safe_read_u64(dex_file + begin_off) & PAC_STRIP_MASK;
        if begin < 0x1000 || !super::safe_mem::is_readable(begin, DEX_HEADER_SIZE) {
            continue;
        }
        let magic = std::slice::from_raw_parts(begin as *const u8, 4);
        if magic == DEX_MAGIC_DEX {
            if let Some(image) = DexImage::from_base(begin) {
                if log {
                    output_verbose(&format!(
                        "[dex resolver] DexFile+{:#x} Begin={:#x}",
                        begin_off, begin
                    ));
                }
                return Some(image);
            }
        } else if magic == DEX_MAGIC_CDEX {
            if let Some(image) = DexImage::from_base(begin) {
                if log {
                    output_verbose(&format!(
                        "[dex resolver] DexFile+{:#x} Begin={:#x} compact dex",
                        begin_off, begin
                    ));
                }
                return Some(image);
            }
        }
    }

    None
}

unsafe fn read_heap_ref(addr: u64) -> Option<u64> {
    if !super::safe_mem::is_readable(addr, 4) {
        return None;
    }
    let raw = super::safe_mem::safe_read_u32(addr) as u64;
    if raw < 0x10000 || (raw & 0x7) != 0 || !super::safe_mem::is_readable(raw, 4) {
        return None;
    }
    Some(raw & PAC_STRIP_MASK)
}

impl DexImage {
    fn from_base(base: u64) -> Option<Self> {
        if !super::safe_mem::is_readable(base, DEX_HEADER_SIZE) {
            return None;
        }
        let magic = unsafe { std::slice::from_raw_parts(base as *const u8, 4) };
        let kind = if magic == DEX_MAGIC_DEX {
            DexImageKind::Standard
        } else if magic == DEX_MAGIC_CDEX {
            DexImageKind::Compact
        } else {
            return None;
        };

        let file_size = read_u32(base + 0x20)? as usize;
        let header_size = read_u32(base + 0x24)? as usize;
        let endian_tag = read_u32(base + 0x28)?;
        if endian_tag != 0x1234_5678 {
            return None;
        }
        if !(DEX_HEADER_SIZE..=(512 << 20)).contains(&file_size) {
            return None;
        }
        if !super::safe_mem::is_readable(base, file_size.min(DEX_HEADER_SIZE)) {
            return None;
        }

        let (data_base, data_size) = match kind {
            DexImageKind::Standard => {
                if header_size != DEX_HEADER_SIZE && header_size != DEX_V41_HEADER_SIZE {
                    return None;
                }
                (base, file_size)
            }
            DexImageKind::Compact => {
                let data_size = read_u32(base + 0x68)? as usize;
                let data_off = read_u32(base + 0x6c)? as usize;
                if data_size == 0 || data_size > (512 << 20) || data_off > (1024 << 20) {
                    return None;
                }
                let data_base = base.checked_add(data_off as u64)?;
                if !super::safe_mem::is_readable(data_base, data_size.min(DEX_HEADER_SIZE)) {
                    return None;
                }
                (data_base, data_size)
            }
        };

        let image = DexImage {
            base,
            size: file_size,
            data_base,
            data_size,
            kind,
        };
        if image.validate_header() {
            Some(image)
        } else {
            None
        }
    }

    fn validate_header(&self) -> bool {
        self.table_valid(0x38, 0x3c, 4)
            && self.table_valid(0x40, 0x44, 4)
            && self.table_valid(0x48, 0x4c, 12)
            && self.table_valid(0x50, 0x54, 8)
            && self.table_valid(0x58, 0x5c, 8)
            && self.table_valid(0x60, 0x64, 32)
    }

    fn table_valid(&self, size_off: u64, off_off: u64, elem_size: usize) -> bool {
        let Some(count) = self.read_u32(size_off) else {
            return false;
        };
        let Some(off) = self.read_u32(off_off) else {
            return false;
        };
        if count == 0 {
            return off == 0 || (off as usize) <= self.size;
        }
        let off = off as usize;
        let len = count as usize * elem_size;
        off >= DEX_HEADER_SIZE && off.checked_add(len).is_some_and(|end| end <= self.size)
    }

    fn method_access_flags(
        &self,
        dex_method_index: u32,
        class_descriptor: &str,
        method_name: &str,
        signature: &str,
    ) -> Option<u32> {
        let Some(method_ids_size) = self.read_u32(0x58) else {
            return None;
        };
        let Some(method_ids_off) = self.read_u32(0x5c) else {
            return None;
        };
        if dex_method_index >= method_ids_size {
            return None;
        }

        let method_id = method_ids_off as u64 + dex_method_index as u64 * 8;
        let Some(class_idx) = self.read_u16(method_id) else {
            return None;
        };
        let Some(proto_idx) = self.read_u16(method_id + 2) else {
            return None;
        };
        let Some(name_idx) = self.read_u32(method_id + 4) else {
            return None;
        };

        if self.type_descriptor(class_idx as u32).as_deref() != Some(class_descriptor)
            || self.string_by_idx(name_idx).as_deref() != Some(method_name)
            || self.proto_signature(proto_idx as u32).as_deref() != Some(signature)
        {
            return None;
        }

        self.encoded_method_access_flags(class_idx as u32, dex_method_index)
            .or(Some(0))
    }

    fn method_description(&self, dex_method_index: u32) -> Option<String> {
        let method_ids_size = self.read_u32(0x58)?;
        let method_ids_off = self.read_u32(0x5c)?;
        if dex_method_index >= method_ids_size {
            return None;
        }

        let method_id = method_ids_off as u64 + dex_method_index as u64 * 8;
        let class_idx = self.read_u16(method_id)? as u32;
        let proto_idx = self.read_u16(method_id + 2)? as u32;
        let name_idx = self.read_u32(method_id + 4)?;

        Some(format!(
            "{}.{}{}",
            self.type_descriptor(class_idx)?,
            self.string_by_idx(name_idx)?,
            self.proto_signature(proto_idx)?
        ))
    }

    fn declared_methods_for_class(&self, class_descriptor: &str) -> Option<Vec<MethodInfo>> {
        let class_idx = self.class_idx_by_descriptor(class_descriptor)?;
        let class_data_off = self.class_data_off_by_class_idx(class_idx)?;
        if class_data_off == 0 {
            return Some(Vec::new());
        }
        self.class_data_declared_methods(class_data_off as usize)
    }

    fn declared_method_indices_for_class(&self, class_descriptor: &str) -> Option<Vec<(u32, u32)>> {
        let class_idx = self.class_idx_by_descriptor(class_descriptor)?;
        let class_data_off = self.class_data_off_by_class_idx(class_idx)?;
        if class_data_off == 0 {
            return Some(Vec::new());
        }
        self.class_data_declared_method_indices(class_data_off as usize)
    }

    fn declared_fields_for_class(&self, class_descriptor: &str) -> Option<Vec<DexDeclaredField>> {
        let class_idx = self.class_idx_by_descriptor(class_descriptor)?;
        let class_data_off = self.class_data_off_by_class_idx(class_idx)?;
        if class_data_off == 0 {
            return Some(Vec::new());
        }
        self.class_data_declared_fields(class_data_off as usize)
    }

    fn declared_field_indices_for_class(&self, class_descriptor: &str) -> Option<Vec<(u32, u32)>> {
        Some(
            self.declared_fields_for_class(class_descriptor)?
                .into_iter()
                .map(|field| (field.dex_field_index, field.access_flags))
                .collect(),
        )
    }

    fn super_descriptor_for_class(&self, class_descriptor: &str) -> Option<Option<String>> {
        let class_idx = self.class_idx_by_descriptor(class_descriptor)?;
        let class_defs_size = self.read_u32(0x60)?;
        let class_defs_off = self.read_u32(0x64)?;

        for i in 0..class_defs_size {
            let class_def = class_defs_off as u64 + i as u64 * 32;
            if self.read_u32(class_def)? != class_idx {
                continue;
            }
            let super_idx = self.read_u32(class_def + 8)?;
            if super_idx == u32::MAX {
                return Some(None);
            }
            return Some(self.type_descriptor(super_idx));
        }

        None
    }

    fn class_object_matches_descriptor(&self, class_obj: u64, expected_descriptor: &str) -> bool {
        if self.class_object_descriptor_matches(class_obj, expected_descriptor) {
            return true;
        }

        self.class_object_has_declared_method_index(class_obj, expected_descriptor)
            || self.class_object_has_declared_field_index(class_obj, expected_descriptor)
    }

    fn class_object_matches_descriptor_by_indices(&self, class_obj: u64, class_def_idx: u32, type_idx: u32) -> bool {
        if self.class_object_has_adjacent_class_def_and_type_idx(class_obj, class_def_idx, type_idx) {
            return true;
        }
        self.class_object_has_class_def_idx(class_obj, class_def_idx)
            && (self.class_object_has_type_idx(class_obj, type_idx)
                || self.class_object_has_declared_method_index_by_class_def(class_obj, class_def_idx)
                || self.class_object_has_declared_field_index_by_class_def(class_obj, class_def_idx))
    }

    fn class_object_has_adjacent_class_def_and_type_idx(&self, class_obj: u64, class_def_idx: u32, type_idx: u32) -> bool {
        const MAX_CLASS_SCAN: usize = 0x100;
        for offset in (0..MAX_CLASS_SCAN).step_by(4) {
            if !super::safe_mem::is_readable(class_obj + offset as u64, 8) {
                continue;
            }
            let candidate_class_def = unsafe { super::safe_mem::safe_read_u32(class_obj + offset as u64) };
            let candidate_type = unsafe { super::safe_mem::safe_read_u32(class_obj + offset as u64 + 4) };
            if candidate_class_def == class_def_idx && candidate_type == type_idx {
                return true;
            }
        }
        false
    }

    fn class_object_has_class_def_idx(&self, class_obj: u64, class_def_idx: u32) -> bool {
        const MAX_CLASS_SCAN: usize = 0x100;
        let Some(class_defs_size) = self.read_u32(0x60) else {
            return false;
        };
        if class_def_idx >= class_defs_size {
            return false;
        }
        for offset in (0..MAX_CLASS_SCAN).step_by(4) {
            if !super::safe_mem::is_readable(class_obj + offset as u64, 4) {
                continue;
            }
            if unsafe { super::safe_mem::safe_read_u32(class_obj + offset as u64) } == class_def_idx {
                return true;
            }
        }
        false
    }

    fn class_object_has_type_idx(&self, class_obj: u64, type_idx: u32) -> bool {
        const MAX_CLASS_SCAN: usize = 0x100;
        let Some(type_ids_size) = self.read_u32(0x40) else {
            return false;
        };
        if type_idx >= type_ids_size {
            return false;
        }
        for offset in (0..MAX_CLASS_SCAN).step_by(4) {
            if !super::safe_mem::is_readable(class_obj + offset as u64, 4) {
                continue;
            }
            if unsafe { super::safe_mem::safe_read_u32(class_obj + offset as u64) } == type_idx {
                return true;
            }
        }
        false
    }

    fn class_object_has_declared_method_index_by_class_def(&self, class_obj: u64, class_def_idx: u32) -> bool {
        let Some(class_descriptor) = self.class_descriptor_by_class_def_idx(class_def_idx) else {
            return false;
        };
        self.class_object_has_declared_method_index(class_obj, &class_descriptor)
    }

    fn class_object_has_declared_field_index_by_class_def(&self, class_obj: u64, class_def_idx: u32) -> bool {
        let Some(class_descriptor) = self.class_descriptor_by_class_def_idx(class_def_idx) else {
            return false;
        };
        self.class_object_has_declared_field_index(class_obj, &class_descriptor)
    }

    fn class_object_descriptor_matches(&self, class_obj: u64, expected_descriptor: &str) -> bool {
        self.class_object_descriptors(class_obj)
            .into_iter()
            .any(|(_, descriptor)| descriptor == expected_descriptor)
    }

    fn class_object_descriptors(&self, class_obj: u64) -> Vec<(usize, String)> {
        const MAX_CLASS_SCAN: usize = 0x100;

        let Some(class_defs_size) = self.read_u32(0x60) else {
            return Vec::new();
        };
        let Some(class_defs_off) = self.read_u32(0x64) else {
            return Vec::new();
        };
        let Some(type_ids_size) = self.read_u32(0x40) else {
            return Vec::new();
        };
        let mut out = Vec::new();

        for offset in (0..MAX_CLASS_SCAN).step_by(4) {
            if !super::safe_mem::is_readable(class_obj + offset as u64, 8) {
                continue;
            }

            let class_def_idx = unsafe { super::safe_mem::safe_read_u32(class_obj + offset as u64) };
            let type_idx = unsafe { super::safe_mem::safe_read_u32(class_obj + offset as u64 + 4) };
            if class_def_idx >= class_defs_size || type_idx >= type_ids_size {
                continue;
            }

            let class_def = class_defs_off as u64 + class_def_idx as u64 * 32;
            if self.read_u32(class_def) != Some(type_idx) {
                continue;
            }

            if let Some(descriptor) = self.type_descriptor(type_idx) {
                if descriptor.starts_with('L') {
                    out.push((offset, descriptor));
                }
            }
        }

        out
    }

    fn class_object_has_declared_method_index(&self, class_obj: u64, class_descriptor: &str) -> bool {
        const MAX_CLASS_SCAN: usize = 0x100;
        const MAX_METHODS_PER_CLASS: u32 = 8192;

        let Some(expected) = self.declared_method_indices_for_class(class_descriptor) else {
            return false;
        };
        if expected.is_empty() {
            return false;
        }

        for offset in (0..MAX_CLASS_SCAN).step_by(4) {
            let methods_array = unsafe { safe_read_u64(class_obj + offset as u64) } & PAC_STRIP_MASK;
            if methods_array < 0x1000 || !super::safe_mem::is_readable(methods_array, 4) {
                continue;
            }

            let methods_len = unsafe { super::safe_mem::safe_read_u32(methods_array) };
            if methods_len == 0 || methods_len > MAX_METHODS_PER_CLASS {
                continue;
            }

            for first_method_offset in ART_METHOD_ARRAY_FIRST_ELEMENT_OFFSETS {
                for method_size in ART_METHOD_SIZE_CANDIDATES {
                    for index in 0..methods_len as usize {
                        let art_method =
                            methods_array + first_method_offset as u64 + (index * method_size) as u64;
                        if !super::safe_mem::is_readable(art_method, method_size) {
                            continue;
                        }

                        for dex_offset in ART_METHOD_DEX_METHOD_INDEX_CANDIDATE_OFFSETS {
                            if dex_offset + 4 > method_size {
                                continue;
                            }
                            let dex_method_index =
                                unsafe { super::safe_mem::safe_read_u32(art_method + dex_offset as u64) };
                            if let Some((_, dex_access_flags)) =
                                expected.iter().find(|(idx, _)| *idx == dex_method_index)
                            {
                                if art_method_access_flags_match(
                                    art_method,
                                    method_size,
                                    dex_offset,
                                    *dex_access_flags,
                                ) {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        }

        false
    }

    fn class_object_has_declared_field_index(&self, class_obj: u64, class_descriptor: &str) -> bool {
        const MAX_CLASS_SCAN: usize = 0x100;
        const MAX_FIELDS_PER_CLASS: u32 = 8192;

        let Some(expected) = self.declared_field_indices_for_class(class_descriptor) else {
            return false;
        };
        if expected.is_empty() {
            return false;
        }
        let Some(field_spec) = get_art_field_spec() else {
            return false;
        };

        for offset in (0..MAX_CLASS_SCAN).step_by(4) {
            let fields_array = unsafe { safe_read_u64(class_obj + offset as u64) } & PAC_STRIP_MASK;
            if fields_array < 0x1000 || !super::safe_mem::is_readable(fields_array, 4) {
                continue;
            }

            let fields_len = unsafe { super::safe_mem::safe_read_u32(fields_array) };
            if fields_len == 0 || fields_len > MAX_FIELDS_PER_CLASS {
                continue;
            }

            for index in 0..fields_len as usize {
                let art_field = fields_array + 4 + (index * field_spec.size) as u64;
                if !super::safe_mem::is_readable(art_field, field_spec.size) {
                    continue;
                }

                for dex_offset in ART_FIELD_DEX_FIELD_INDEX_CANDIDATE_OFFSETS {
                    if dex_offset + 4 > field_spec.size {
                        continue;
                    }
                    let dex_field_index =
                        unsafe { super::safe_mem::safe_read_u32(art_field + dex_offset as u64) };
                    if let Some((_, dex_access_flags)) =
                        expected.iter().find(|(idx, _)| *idx == dex_field_index)
                    {
                        if art_field_access_flags_match(
                            art_field,
                            field_spec.size,
                            dex_offset,
                            *dex_access_flags,
                        ) {
                            return true;
                        }
                    }
                }
            }
        }

        false
    }

    fn class_idx_by_descriptor(&self, class_descriptor: &str) -> Option<u32> {
        let type_ids_size = self.read_u32(0x40)?;
        for type_idx in 0..type_ids_size {
            if self.type_descriptor(type_idx).as_deref() == Some(class_descriptor) {
                return Some(type_idx);
            }
        }
        None
    }

    fn class_def_and_type_idx_by_descriptor(&self, class_descriptor: &str) -> Option<(u32, u32)> {
        let class_idx = self.class_idx_by_descriptor(class_descriptor)?;
        let class_defs_size = self.read_u32(0x60)?;
        let class_defs_off = self.read_u32(0x64)?;

        for i in 0..class_defs_size {
            let class_def = class_defs_off as u64 + i as u64 * 32;
            if self.read_u32(class_def)? == class_idx {
                return Some((i, class_idx));
            }
        }

        None
    }

    fn class_descriptor_by_class_def_idx(&self, class_def_idx: u32) -> Option<String> {
        let class_defs_size = self.read_u32(0x60)?;
        let class_defs_off = self.read_u32(0x64)?;
        if class_def_idx >= class_defs_size {
            return None;
        }
        let class_def = class_defs_off as u64 + class_def_idx as u64 * 32;
        let class_idx = self.read_u32(class_def)?;
        self.type_descriptor(class_idx)
    }

    fn class_data_off_by_class_idx(&self, class_idx: u32) -> Option<u32> {
        let class_defs_size = self.read_u32(0x60)?;
        let class_defs_off = self.read_u32(0x64)?;

        for i in 0..class_defs_size {
            let class_def = class_defs_off as u64 + i as u64 * 32;
            if self.read_u32(class_def)? == class_idx {
                return self.read_u32(class_def + 24);
            }
        }

        None
    }

    fn class_data_declared_methods(&self, class_data_off: usize) -> Option<Vec<MethodInfo>> {
        if class_data_off >= self.data_size {
            return None;
        }

        let mut cursor = self.data_base + class_data_off as u64;
        let static_fields_size = read_uleb128(self.data_base, self.data_size, &mut cursor)?;
        let instance_fields_size = read_uleb128(self.data_base, self.data_size, &mut cursor)?;
        let direct_methods_size = read_uleb128(self.data_base, self.data_size, &mut cursor)?;
        let virtual_methods_size = read_uleb128(self.data_base, self.data_size, &mut cursor)?;

        for _ in 0..static_fields_size + instance_fields_size {
            let _field_idx_diff = read_uleb128(self.data_base, self.data_size, &mut cursor)?;
            let _access_flags = read_uleb128(self.data_base, self.data_size, &mut cursor)?;
        }

        let mut out = Vec::with_capacity((direct_methods_size + virtual_methods_size) as usize);
        let mut direct_idx = 0u32;
        for _ in 0..direct_methods_size {
            let method_idx_diff = read_uleb128(self.data_base, self.data_size, &mut cursor)?;
            direct_idx = direct_idx.checked_add(method_idx_diff)?;
            let access_flags = read_uleb128(self.data_base, self.data_size, &mut cursor)?;
            let _code_off = read_uleb128(self.data_base, self.data_size, &mut cursor)?;
            if let Some(method) = self.method_info(direct_idx, access_flags) {
                out.push(method);
            }
        }

        let mut virtual_idx = 0u32;
        for _ in 0..virtual_methods_size {
            let method_idx_diff = read_uleb128(self.data_base, self.data_size, &mut cursor)?;
            virtual_idx = virtual_idx.checked_add(method_idx_diff)?;
            let access_flags = read_uleb128(self.data_base, self.data_size, &mut cursor)?;
            let _code_off = read_uleb128(self.data_base, self.data_size, &mut cursor)?;
            if let Some(method) = self.method_info(virtual_idx, access_flags) {
                out.push(method);
            }
        }

        Some(out)
    }

    fn class_data_declared_method_indices(&self, class_data_off: usize) -> Option<Vec<(u32, u32)>> {
        if class_data_off >= self.data_size {
            return None;
        }

        let mut cursor = self.data_base + class_data_off as u64;
        let static_fields_size = read_uleb128(self.data_base, self.data_size, &mut cursor)?;
        let instance_fields_size = read_uleb128(self.data_base, self.data_size, &mut cursor)?;
        let direct_methods_size = read_uleb128(self.data_base, self.data_size, &mut cursor)?;
        let virtual_methods_size = read_uleb128(self.data_base, self.data_size, &mut cursor)?;

        for _ in 0..static_fields_size + instance_fields_size {
            let _field_idx_diff = read_uleb128(self.data_base, self.data_size, &mut cursor)?;
            let _access_flags = read_uleb128(self.data_base, self.data_size, &mut cursor)?;
        }

        let mut out = Vec::with_capacity((direct_methods_size + virtual_methods_size) as usize);
        let mut direct_idx = 0u32;
        for _ in 0..direct_methods_size {
            let method_idx_diff = read_uleb128(self.data_base, self.data_size, &mut cursor)?;
            direct_idx = direct_idx.checked_add(method_idx_diff)?;
            let access_flags = read_uleb128(self.data_base, self.data_size, &mut cursor)?;
            let _code_off = read_uleb128(self.data_base, self.data_size, &mut cursor)?;
            out.push((direct_idx, access_flags));
        }

        let mut virtual_idx = 0u32;
        for _ in 0..virtual_methods_size {
            let method_idx_diff = read_uleb128(self.data_base, self.data_size, &mut cursor)?;
            virtual_idx = virtual_idx.checked_add(method_idx_diff)?;
            let access_flags = read_uleb128(self.data_base, self.data_size, &mut cursor)?;
            let _code_off = read_uleb128(self.data_base, self.data_size, &mut cursor)?;
            out.push((virtual_idx, access_flags));
        }

        Some(out)
    }

    fn class_data_declared_fields(&self, class_data_off: usize) -> Option<Vec<DexDeclaredField>> {
        if class_data_off >= self.data_size {
            return None;
        }

        let mut cursor = self.data_base + class_data_off as u64;
        let static_fields_size = read_uleb128(self.data_base, self.data_size, &mut cursor)?;
        let instance_fields_size = read_uleb128(self.data_base, self.data_size, &mut cursor)?;
        let direct_methods_size = read_uleb128(self.data_base, self.data_size, &mut cursor)?;
        let virtual_methods_size = read_uleb128(self.data_base, self.data_size, &mut cursor)?;

        let mut out = Vec::with_capacity((static_fields_size + instance_fields_size) as usize);
        let mut static_idx = 0u32;
        for _ in 0..static_fields_size {
            let field_idx_diff = read_uleb128(self.data_base, self.data_size, &mut cursor)?;
            static_idx = static_idx.checked_add(field_idx_diff)?;
            let access_flags = read_uleb128(self.data_base, self.data_size, &mut cursor)? | K_ACC_STATIC;
            if let Some(field) = self.field_info(static_idx, access_flags) {
                out.push(field);
            }
        }

        let mut instance_idx = 0u32;
        for _ in 0..instance_fields_size {
            let field_idx_diff = read_uleb128(self.data_base, self.data_size, &mut cursor)?;
            instance_idx = instance_idx.checked_add(field_idx_diff)?;
            let access_flags = read_uleb128(self.data_base, self.data_size, &mut cursor)?;
            if let Some(field) = self.field_info(instance_idx, access_flags & !K_ACC_STATIC) {
                out.push(field);
            }
        }

        for _ in 0..direct_methods_size + virtual_methods_size {
            let _method_idx_diff = read_uleb128(self.data_base, self.data_size, &mut cursor)?;
            let _access_flags = read_uleb128(self.data_base, self.data_size, &mut cursor)?;
            let _code_off = read_uleb128(self.data_base, self.data_size, &mut cursor)?;
        }

        Some(out)
    }

    fn method_info(&self, dex_method_index: u32, access_flags: u32) -> Option<MethodInfo> {
        let method_ids_size = self.read_u32(0x58)?;
        let method_ids_off = self.read_u32(0x5c)?;
        if dex_method_index >= method_ids_size {
            return None;
        }

        let method_id = method_ids_off as u64 + dex_method_index as u64 * 8;
        let proto_idx = self.read_u16(method_id + 2)? as u32;
        let name_idx = self.read_u32(method_id + 4)?;
        Some(MethodInfo {
            name: self.string_by_idx(name_idx)?,
            sig: self.proto_signature(proto_idx)?,
            is_static: (access_flags & K_ACC_STATIC) != 0,
            modifiers: access_flags as i32,
        })
    }

    fn field_info(&self, dex_field_index: u32, access_flags: u32) -> Option<DexDeclaredField> {
        let field_ids_size = self.read_u32(0x50)?;
        let field_ids_off = self.read_u32(0x54)?;
        if dex_field_index >= field_ids_size {
            return None;
        }

        let field_id = field_ids_off as u64 + dex_field_index as u64 * 8;
        let type_idx = self.read_u16(field_id + 2)? as u32;
        let name_idx = self.read_u32(field_id + 4)?;
        Some(DexDeclaredField {
            dex_field_index,
            name: self.string_by_idx(name_idx)?,
            jni_sig: self.type_descriptor(type_idx)?,
            access_flags,
        })
    }

    fn encoded_method_access_flags(&self, class_idx: u32, dex_method_index: u32) -> Option<u32> {
        let class_data_off = self.class_data_off_by_class_idx(class_idx)?;
        if class_data_off == 0 {
            return None;
        }
        self.class_data_method_access_flags(class_data_off as usize, dex_method_index)
    }

    fn class_data_method_access_flags(&self, class_data_off: usize, dex_method_index: u32) -> Option<u32> {
        if class_data_off >= self.data_size {
            return None;
        }

        let mut cursor = self.data_base + class_data_off as u64;
        let static_fields_size = read_uleb128(self.data_base, self.data_size, &mut cursor)?;
        let instance_fields_size = read_uleb128(self.data_base, self.data_size, &mut cursor)?;
        let direct_methods_size = read_uleb128(self.data_base, self.data_size, &mut cursor)?;
        let virtual_methods_size = read_uleb128(self.data_base, self.data_size, &mut cursor)?;

        for _ in 0..static_fields_size + instance_fields_size {
            let _field_idx_diff = read_uleb128(self.data_base, self.data_size, &mut cursor)?;
            let _access_flags = read_uleb128(self.data_base, self.data_size, &mut cursor)?;
        }

        let mut method_idx = 0u32;
        for _ in 0..direct_methods_size + virtual_methods_size {
            let method_idx_diff = read_uleb128(self.data_base, self.data_size, &mut cursor)?;
            method_idx = method_idx.checked_add(method_idx_diff)?;
            let access_flags = read_uleb128(self.data_base, self.data_size, &mut cursor)?;
            let _code_off = read_uleb128(self.data_base, self.data_size, &mut cursor)?;
            if method_idx == dex_method_index {
                return Some(access_flags);
            }
        }

        None
    }

    fn proto_signature(&self, proto_idx: u32) -> Option<String> {
        let proto_ids_size = self.read_u32(0x48)?;
        let proto_ids_off = self.read_u32(0x4c)?;
        if proto_idx >= proto_ids_size {
            return None;
        }
        let proto = proto_ids_off as u64 + proto_idx as u64 * 12;
        let return_type_idx = self.read_u32(proto + 4)?;
        let parameters_off = self.read_u32(proto + 8)?;

        let mut out = String::from("(");
        if parameters_off != 0 {
            if parameters_off as usize + 4 > self.data_size {
                return None;
            }
            let size = self.read_data_u32(parameters_off as u64)?;
            let list_bytes = 4usize.checked_add(size as usize * 2)?;
            if parameters_off as usize + list_bytes > self.data_size {
                return None;
            }
            for i in 0..size {
                let type_idx = self.read_data_u16(parameters_off as u64 + 4 + i as u64 * 2)?;
                out.push_str(&self.type_descriptor(type_idx as u32)?);
            }
        }
        out.push(')');
        out.push_str(&self.type_descriptor(return_type_idx)?);
        Some(out)
    }

    fn type_descriptor(&self, type_idx: u32) -> Option<String> {
        let type_ids_size = self.read_u32(0x40)?;
        let type_ids_off = self.read_u32(0x44)?;
        if type_idx >= type_ids_size {
            return None;
        }
        let descriptor_idx = self.read_u32(type_ids_off as u64 + type_idx as u64 * 4)?;
        self.string_by_idx(descriptor_idx)
    }

    fn string_by_idx(&self, string_idx: u32) -> Option<String> {
        let string_ids_size = self.read_u32(0x38)?;
        let string_ids_off = self.read_u32(0x3c)?;
        if string_idx >= string_ids_size {
            return None;
        }
        let data_off = self.read_u32(string_ids_off as u64 + string_idx as u64 * 4)? as usize;
        if data_off >= self.data_size {
            return None;
        }

        let mut cursor = self.data_base + data_off as u64;
        let _utf16_len = read_uleb128(self.data_base, self.data_size, &mut cursor)?;
        let start = cursor;
        let mut end = start;
        while (end - self.data_base) < self.data_size as u64 {
            let b = read_u8(end)?;
            if b == 0 {
                let len = (end - start) as usize;
                if !super::safe_mem::is_readable(start, len) {
                    return None;
                }
                let bytes = unsafe { std::slice::from_raw_parts(start as *const u8, len) };
                return Some(String::from_utf8_lossy(bytes).into_owned());
            }
            end += 1;
        }
        None
    }

    fn read_u16(&self, off: u64) -> Option<u16> {
        if off as usize + 2 > self.size {
            return None;
        }
        read_u16(self.base + off)
    }

    fn read_u32(&self, off: u64) -> Option<u32> {
        if off as usize + 4 > self.size {
            return None;
        }
        read_u32(self.base + off)
    }

    fn read_data_u16(&self, off: u64) -> Option<u16> {
        if off as usize + 2 > self.data_size {
            return None;
        }
        read_u16(self.data_base + off)
    }

    fn read_data_u32(&self, off: u64) -> Option<u32> {
        if off as usize + 4 > self.data_size {
            return None;
        }
        read_u32(self.data_base + off)
    }
}

fn class_name_to_descriptor(class_name: &str) -> String {
    let normalized = class_name.replace('.', "/");
    if normalized.starts_with('[') {
        normalized
    } else if normalized.starts_with('L') && normalized.ends_with(';') {
        normalized
    } else {
        format!("L{};", normalized)
    }
}

fn descriptor_to_class_name(descriptor: &str) -> String {
    if descriptor.starts_with('L') && descriptor.ends_with(';') {
        descriptor[1..descriptor.len() - 1].replace('/', ".")
    } else {
        descriptor.replace('/', ".")
    }
}

fn read_u8(addr: u64) -> Option<u8> {
    if !super::safe_mem::is_readable(addr, 1) {
        return None;
    }
    Some(unsafe { std::ptr::read_unaligned(addr as *const u8) })
}

fn read_u16(addr: u64) -> Option<u16> {
    if !super::safe_mem::is_readable(addr, 2) {
        return None;
    }
    Some(u16::from_le(unsafe {
        std::ptr::read_unaligned(addr as *const u16)
    }))
}

fn read_u32(addr: u64) -> Option<u32> {
    if !super::safe_mem::is_readable(addr, 4) {
        return None;
    }
    Some(u32::from_le(unsafe {
        std::ptr::read_unaligned(addr as *const u32)
    }))
}

fn read_u64(addr: u64) -> Option<u64> {
    if !super::safe_mem::is_readable(addr, 8) {
        return None;
    }
    Some(u64::from_le(unsafe {
        std::ptr::read_unaligned(addr as *const u64)
    }))
}

fn read_f64(addr: u64) -> Option<f64> {
    Some(f64::from_bits(read_u64(addr)?))
}

fn read_uleb128(base: u64, size: usize, cursor: &mut u64) -> Option<u32> {
    let mut result = 0u32;
    let mut shift = 0u32;
    for _ in 0..5 {
        if (*cursor - base) as usize >= size {
            return None;
        }
        let byte = read_u8(*cursor)?;
        *cursor += 1;
        result |= ((byte & 0x7f) as u32) << shift;
        if (byte & 0x80) == 0 {
            return Some(result);
        }
        shift += 7;
    }
    None
}
