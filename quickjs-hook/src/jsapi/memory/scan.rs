//! Frida-compatible synchronous memory scanning.

use super::helpers::get_addr_from_arg;
use super::safe_access::{read_exact, MemoryAccessError};
use crate::ffi;
use crate::jsapi::ptr::create_native_pointer;
use crate::value::JSValue;

const MAX_SCAN_SIZE: u64 = 0x7fff_ffff;
const MAX_PATTERN_SIZE: usize = 1024 * 1024;
const SCAN_CHUNK_SIZE: usize = 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
struct MatchPattern {
    bytes: Vec<u8>,
    masks: Vec<u8>,
}

impl MatchPattern {
    fn parse(input: &str) -> Result<Self, &'static str> {
        let mut parts = input.split(':');
        let match_part = parts.next().unwrap_or_default();
        let mask_part = parts.next();
        if parts.next().is_some() {
            return Err("invalid match pattern");
        }

        let match_nibbles = compact_nibbles(match_part, true)?;
        if match_nibbles.is_empty() || match_nibbles.len() % 2 != 0 {
            return Err("invalid match pattern");
        }
        let size = match_nibbles.len() / 2;
        if size > MAX_PATTERN_SIZE {
            return Err("match pattern is too large");
        }

        let explicit_mask = match mask_part {
            Some(mask) => {
                let nibbles = compact_nibbles(mask, false)?;
                if nibbles.len() != match_nibbles.len() {
                    return Err("invalid match pattern");
                }
                Some(nibbles)
            }
            None => None,
        };

        let mut bytes = Vec::with_capacity(size);
        let mut masks = Vec::with_capacity(size);
        for index in (0..match_nibbles.len()).step_by(2) {
            let (upper_value, upper_mask) = pattern_nibble(match_nibbles[index])?;
            let (lower_value, lower_mask) = pattern_nibble(match_nibbles[index + 1])?;
            let mut mask = (upper_mask << 4) | lower_mask;
            if let Some(explicit) = explicit_mask.as_ref() {
                mask &= (hex_nibble(explicit[index])? << 4) | hex_nibble(explicit[index + 1])?;
            }
            bytes.push((upper_value << 4) | lower_value);
            masks.push(mask);
        }

        // Gum rejects patterns beginning or ending in a full-byte wildcard.
        if masks.first() == Some(&0) || masks.last() == Some(&0) {
            return Err("invalid match pattern");
        }

        Ok(Self { bytes, masks })
    }

    fn len(&self) -> usize {
        self.bytes.len()
    }

    fn matches(&self, candidate: &[u8]) -> bool {
        self.bytes
            .iter()
            .zip(&self.masks)
            .zip(candidate)
            .all(|((&expected, &mask), &actual)| (actual & mask) == (expected & mask))
    }
}

fn compact_nibbles(input: &str, allow_wildcards: bool) -> Result<Vec<u8>, &'static str> {
    let mut result = Vec::with_capacity(input.len());
    for byte in input.bytes() {
        if byte.is_ascii_whitespace() {
            continue;
        }
        if byte.is_ascii_hexdigit() || (allow_wildcards && byte == b'?') {
            result.push(byte);
        } else {
            return Err("invalid match pattern");
        }
    }
    Ok(result)
}

fn hex_nibble(byte: u8) -> Result<u8, &'static str> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("invalid match pattern"),
    }
}

fn pattern_nibble(byte: u8) -> Result<(u8, u8), &'static str> {
    if byte == b'?' {
        Ok((0, 0))
    } else {
        Ok((hex_nibble(byte)?, 0x0f))
    }
}

fn scan_range(address: u64, size: usize, pattern: &MatchPattern) -> Result<Vec<u64>, MemoryAccessError> {
    if size < pattern.len() {
        return Ok(Vec::new());
    }

    let mut matches = Vec::new();
    let mut tail = Vec::new();
    let mut offset = 0usize;
    let mut next_allowed = address;

    while offset < size {
        let amount = (size - offset).min(SCAN_CHUNK_SIZE);
        let mut chunk = vec![0u8; amount];
        read_exact(address + offset as u64, &mut chunk)?;

        let tail_len = tail.len();
        let combined_base = address + offset as u64 - tail_len as u64;
        tail.extend_from_slice(&chunk);

        let mut index = 0usize;
        while index + pattern.len() <= tail.len() {
            let candidate_address = combined_base + index as u64;
            if candidate_address >= next_allowed && pattern.matches(&tail[index..index + pattern.len()]) {
                if matches.try_reserve(1).is_err() {
                    return Err(MemoryAccessError {
                        operation: super::safe_access::MemoryOperation::Read,
                        address: candidate_address,
                        size: pattern.len(),
                        errno: libc::ENOMEM,
                    });
                }
                matches.push(candidate_address);
                next_allowed = candidate_address + pattern.len() as u64;
                index += pattern.len();
            } else {
                index += 1;
            }
        }

        let keep = pattern.len().saturating_sub(1).min(tail.len());
        if keep == 0 {
            tail.clear();
        } else {
            let keep_start = tail.len() - keep;
            tail.copy_within(keep_start.., 0);
            tail.truncate(keep);
        }
        offset += amount;
    }

    Ok(matches)
}

unsafe fn throw_message(ctx: *mut ffi::JSContext, message: &str) -> ffi::JSValue {
    let message = format!("{}\0", message);
    ffi::JS_ThrowRangeError(
        ctx,
        b"%s\0".as_ptr() as *const _,
        message.as_ptr() as *const libc::c_char,
    )
}

pub(super) unsafe extern "C" fn memory_scan_sync(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 3 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Memory.scanSync(address, size, pattern) requires 3 arguments\0".as_ptr() as *const _,
        );
    }
    let address = match get_addr_from_arg(ctx, JSValue(*argv)) {
        Some(value) => value,
        None => {
            return ffi::JS_ThrowTypeError(
                ctx,
                b"Memory.scanSync: address must be a pointer\0".as_ptr() as *const _,
            )
        }
    };
    let raw_size = match JSValue(*argv.add(1)).to_i64(ctx) {
        Some(value) if value >= 0 && value as u64 <= MAX_SCAN_SIZE => value as usize,
        _ => return throw_message(ctx, "Memory.scanSync: invalid size"),
    };
    if address.checked_add(raw_size as u64).is_none() {
        return throw_message(ctx, "Memory.scanSync: address range overflow");
    }
    let pattern_value = JSValue(*argv.add(2));
    if !pattern_value.is_string() {
        return ffi::JS_ThrowTypeError(ctx, b"Memory.scanSync: pattern must be a string\0".as_ptr() as *const _);
    }
    let pattern_string = match pattern_value.to_string(ctx) {
        Some(value) => value,
        None => {
            return ffi::JS_ThrowTypeError(ctx, b"Memory.scanSync: pattern must be a string\0".as_ptr() as *const _)
        }
    };
    let pattern = match MatchPattern::parse(&pattern_string) {
        Ok(value) => value,
        Err(message) => return throw_message(ctx, message),
    };
    let found = match scan_range(address, raw_size, &pattern) {
        Ok(value) => value,
        Err(error) => return throw_message(ctx, &format!("Memory.scanSync: {}", error)),
    };

    let result = ffi::JS_NewArray(ctx);
    if ffi::qjs_is_exception(result) != 0 {
        return result;
    }
    for (index, match_address) in found.into_iter().enumerate() {
        let item = ffi::JS_NewObject(ctx);
        if ffi::qjs_is_exception(item) != 0 {
            ffi::qjs_free_value(ctx, result);
            return item;
        }
        let item_value = JSValue(item);
        if !item_value.set_property(ctx, "address", create_native_pointer(ctx, match_address))
            || !item_value.set_property(ctx, "size", JSValue::int(pattern.len() as i32))
        {
            ffi::qjs_free_value(ctx, item);
            ffi::qjs_free_value(ctx, result);
            return ffi::qjs_exception();
        }
        if ffi::JS_SetPropertyUint32(ctx, result, index as u32, item) < 0 {
            ffi::qjs_free_value(ctx, result);
            return ffi::qjs_exception();
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::{scan_range, MatchPattern, SCAN_CHUNK_SIZE};

    #[test]
    fn parses_exact_wildcard_and_mask_patterns() {
        let pattern = MatchPattern::parse("13 A? ?7 ff : ff f0 0f ff").unwrap();
        assert_eq!(pattern.bytes, vec![0x13, 0xa0, 0x07, 0xff]);
        assert_eq!(pattern.masks, vec![0xff, 0xf0, 0x0f, 0xff]);
        assert!(pattern.matches(&[0x13, 0xab, 0x47, 0xff]));
        assert!(!pattern.matches(&[0x12, 0xab, 0x47, 0xff]));
    }

    #[test]
    fn rejects_invalid_and_edge_wildcard_patterns() {
        for invalid in ["", " ", "1", "13+37", "??", "?? 13", "13 ??", "13 37 : ff"] {
            assert!(MatchPattern::parse(invalid).is_err(), "accepted {invalid:?}");
        }
    }

    #[test]
    fn finds_a_match_crossing_a_chunk_boundary() {
        let pattern = MatchPattern::parse("13 37 42").unwrap();
        let mut haystack = vec![0u8; SCAN_CHUNK_SIZE + 8];
        let match_offset = SCAN_CHUNK_SIZE - 2;
        haystack[match_offset..match_offset + pattern.len()].copy_from_slice(&[0x13, 0x37, 0x42]);
        let base = haystack.as_ptr() as u64;

        assert_eq!(
            scan_range(base, haystack.len(), &pattern).unwrap(),
            vec![base + match_offset as u64]
        );
    }
}
