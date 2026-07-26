//! `Memory.findPointers()` and `Memory.checkCodePointer()`.
//!
//! Both walk memory that the caller does not control, so every read goes
//! through the safe-access helpers and an unreadable page ends a range instead
//! of faulting the process.

use super::safe_access::read_exact;
use crate::ffi;
use crate::jsapi::callback_util::{extract_pointer_address, throw_internal_error};
use crate::jsapi::ptr::create_native_pointer;
use crate::jsapi::util::canonicalize_user_address;
use crate::value::JSValue;
use std::collections::HashSet;

const POINTER_SIZE: usize = std::mem::size_of::<u64>();
/// Read in page-sized chunks so one unreadable page only costs that page.
const SCAN_CHUNK: usize = 64 * 1024;

struct Range {
    base: u64,
    size: usize,
}

unsafe fn parse_ranges(ctx: *mut ffi::JSContext, value: JSValue) -> Result<Vec<Range>, ffi::JSValue> {
    let length = JSValue(ffi::JS_GetPropertyStr(ctx, value.raw(), c"length".as_ptr()));
    let count = length.to_u64(ctx);
    length.free(ctx);
    let Some(count) = count else {
        return Err(throw_internal_error(
            ctx,
            "Memory.findPointers() ranges must be an array of {base, size}",
        ));
    };

    let mut ranges = Vec::with_capacity(count as usize);
    for index in 0..count {
        let entry = JSValue(ffi::JS_GetPropertyUint32(ctx, value.raw(), index as u32));
        let base_value = JSValue(ffi::JS_GetPropertyStr(ctx, entry.raw(), c"base".as_ptr()));
        let base = extract_pointer_address(ctx, base_value, "Memory.findPointers() range base");
        base_value.free(ctx);
        let size_value = JSValue(ffi::JS_GetPropertyStr(ctx, entry.raw(), c"size".as_ptr()));
        let size = size_value.to_i64(ctx);
        size_value.free(ctx);
        entry.free(ctx);

        let base = base?;
        let Some(size) = size.filter(|size| *size >= 0 && *size <= 0x7fff_ffff) else {
            return Err(throw_internal_error(ctx, "Memory.findPointers() invalid range size"));
        };
        ranges.push(Range {
            base,
            size: size as usize,
        });
    }
    Ok(ranges)
}

unsafe fn parse_values(ctx: *mut ffi::JSContext, value: JSValue) -> Result<HashSet<u64>, ffi::JSValue> {
    let length = JSValue(ffi::JS_GetPropertyStr(ctx, value.raw(), c"length".as_ptr()));
    let count = length.to_u64(ctx);
    length.free(ctx);
    let Some(count) = count else {
        return Err(throw_internal_error(
            ctx,
            "Memory.findPointers() values must be an array of pointers",
        ));
    };

    let mut values = HashSet::with_capacity(count as usize);
    for index in 0..count {
        let entry = JSValue(ffi::JS_GetPropertyUint32(ctx, value.raw(), index as u32));
        let address = extract_pointer_address(ctx, entry, "Memory.findPointers() value");
        entry.free(ctx);
        values.insert(address?);
    }
    Ok(values)
}

/// Scan `range` for pointer-aligned words whose masked value is in `values`.
fn find_in_range(range: &Range, values: &HashSet<u64>, mask: u64, matches: &mut Vec<(u64, u64)>) {
    if range.size < POINTER_SIZE {
        return;
    }
    let base = canonicalize_user_address(range.base);
    let mut offset = 0usize;
    let mut buffer = vec![0u8; SCAN_CHUNK];

    while offset + POINTER_SIZE <= range.size {
        let amount = (range.size - offset).min(SCAN_CHUNK);
        let chunk = &mut buffer[..amount];
        if read_exact(base + offset as u64, chunk).is_err() {
            // Skip the unreadable stretch rather than abandoning the range: a
            // module range routinely contains guard pages.
            offset += SCAN_CHUNK;
            continue;
        }

        let usable = amount - (amount % POINTER_SIZE);
        let mut index = 0usize;
        while index + POINTER_SIZE <= usable {
            let word = u64::from_ne_bytes(chunk[index..index + POINTER_SIZE].try_into().expect("8 bytes"));
            if values.contains(&(word & mask)) {
                matches.push((base + (offset + index) as u64, word));
            }
            index += POINTER_SIZE;
        }
        // Keep the cursor pointer-aligned so a short tail cannot shift it.
        offset += if usable == 0 { POINTER_SIZE } else { usable };
    }
}

pub(super) unsafe extern "C" fn memory_find_pointers(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return throw_internal_error(ctx, "Memory.findPointers() requires (ranges, values[, options])");
    }
    let ranges = match parse_ranges(ctx, JSValue(*argv)) {
        Ok(value) => value,
        Err(error) => return error,
    };
    let values = match parse_values(ctx, JSValue(*argv.add(1))) {
        Ok(value) => value,
        Err(error) => return error,
    };

    let mut mask = u64::MAX;
    if argc >= 3 {
        let options = JSValue(*argv.add(2));
        if !options.is_undefined() && !options.is_null() {
            let mask_value = JSValue(ffi::JS_GetPropertyStr(ctx, options.raw(), c"mask".as_ptr()));
            if !mask_value.is_undefined() && !mask_value.is_null() {
                let parsed = extract_pointer_address(ctx, mask_value, "Memory.findPointers() mask");
                mask_value.free(ctx);
                mask = match parsed {
                    Ok(value) => value,
                    Err(error) => return error,
                };
            } else {
                mask_value.free(ctx);
            }
        }
    }

    let mut matches = Vec::new();
    for range in &ranges {
        find_in_range(range, &values, mask, &mut matches);
    }

    let result = ffi::JS_NewArray(ctx);
    for (index, (address, value)) in matches.iter().enumerate() {
        let entry = ffi::JS_NewObject(ctx);
        ffi::JS_SetPropertyStr(
            ctx,
            entry,
            c"address".as_ptr(),
            create_native_pointer(ctx, *address).raw(),
        );
        ffi::JS_SetPropertyStr(ctx, entry, c"value".as_ptr(), create_native_pointer(ctx, *value).raw());
        ffi::JS_SetPropertyUint32(ctx, result, index as u32, entry);
    }
    result
}

/// `Memory.checkCodePointer(ptr)` — read the first byte of a code pointer.
///
/// The pointer is stripped of any pointer-authentication bits first, matching
/// upstream, so a signed pointer taken from a register can be checked directly.
pub(super) unsafe extern "C" fn memory_check_code_pointer(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return throw_internal_error(ctx, "Memory.checkCodePointer() requires a pointer");
    }
    let address = match extract_pointer_address(ctx, JSValue(*argv), "Memory.checkCodePointer") {
        Ok(value) => value,
        Err(error) => return error,
    };
    let address = canonicalize_user_address(strip_code_pointer(address));

    let mut byte = [0u8; 1];
    if read_exact(address, &mut byte).is_err() {
        return throw_internal_error(ctx, format!("Memory.checkCodePointer(): 0x{address:x} is not readable"));
    }
    ffi::qjs_new_int64(ctx, byte[0] as i64)
}

/// Clear the pointer-authentication signature from a code pointer.
///
/// XPACI faults as an undefined instruction on cores without ARMv8.3-PAuth, so
/// this checks HWCAP first. The instruction is emitted as a raw word because the
/// project's baseline target does not enable the `pauth` assembler extension.
#[cfg(target_arch = "aarch64")]
fn strip_code_pointer(address: u64) -> u64 {
    /// HWCAP_PACA — address authentication is implemented.
    const HWCAP_PACA: libc::c_ulong = 1 << 30;

    if unsafe { libc::getauxval(libc::AT_HWCAP) } & HWCAP_PACA == 0 {
        return address;
    }

    let stripped: u64;
    unsafe {
        std::arch::asm!(
            // xpaci x0
            ".inst 0xdac143e0",
            inlateout("x0") address => stripped,
            options(nomem, nostack, preserves_flags)
        );
    }
    stripped
}

#[cfg(not(target_arch = "aarch64"))]
fn strip_code_pointer(address: u64) -> u64 {
    address
}
