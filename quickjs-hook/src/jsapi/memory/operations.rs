//! Higher-level Memory operations shared by the Frida-compatible API.

use super::helpers::get_addr_from_arg;
use super::safe_access::{read_exact, write_exact, MemoryAccessError};
use crate::ffi;
use crate::jsapi::ptr::create_owned_native_pointer;
use crate::jsapi::util::query_page_protection;
use crate::value::JSValue;

const MAX_OPERATION_SIZE: u64 = 0x7fff_ffff;
const MAX_OWNED_ALLOCATION: usize = 256 * 1024 * 1024;
const COPY_CHUNK_SIZE: usize = 64 * 1024;

unsafe fn throw_message(ctx: *mut ffi::JSContext, message: &str) -> ffi::JSValue {
    let message = format!("{}\0", message);
    ffi::JS_ThrowRangeError(
        ctx,
        b"%s\0".as_ptr() as *const _,
        message.as_ptr() as *const libc::c_char,
    )
}

unsafe fn parse_size(ctx: *mut ffi::JSContext, value: JSValue, operation: &str) -> Result<usize, ffi::JSValue> {
    match value.to_i64(ctx) {
        Some(size) if size >= 0 && size as u64 <= MAX_OPERATION_SIZE => Ok(size as usize),
        _ => Err(throw_message(ctx, &format!("{}: invalid size", operation))),
    }
}

fn copy_memory(destination: u64, source: u64, size: usize) -> Result<(), MemoryAccessError> {
    if size == 0 || destination == source {
        return Ok(());
    }

    let source_end = source.checked_add(size as u64).ok_or(MemoryAccessError {
        operation: super::safe_access::MemoryOperation::Read,
        address: source,
        size,
        errno: libc::EOVERFLOW,
    })?;
    destination.checked_add(size as u64).ok_or(MemoryAccessError {
        operation: super::safe_access::MemoryOperation::Write,
        address: destination,
        size,
        errno: libc::EOVERFLOW,
    })?;

    let mut buffer = vec![0u8; COPY_CHUNK_SIZE.min(size)];
    if destination > source && destination < source_end {
        let mut remaining = size;
        while remaining != 0 {
            let amount = remaining.min(buffer.len());
            let offset = remaining - amount;
            read_exact(source + offset as u64, &mut buffer[..amount])?;
            write_exact(destination + offset as u64, &buffer[..amount])?;
            remaining = offset;
        }
    } else {
        let mut offset = 0usize;
        while offset < size {
            let amount = (size - offset).min(buffer.len());
            read_exact(source + offset as u64, &mut buffer[..amount])?;
            write_exact(destination + offset as u64, &buffer[..amount])?;
            offset += amount;
        }
    }

    Ok(())
}

pub(super) unsafe extern "C" fn memory_copy(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 3 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Memory.copy(destination, source, size) requires 3 arguments\0".as_ptr() as *const _,
        );
    }
    let destination = match get_addr_from_arg(ctx, JSValue(*argv)) {
        Some(value) => value,
        None => {
            return ffi::JS_ThrowTypeError(
                ctx,
                b"Memory.copy: destination must be a pointer\0".as_ptr() as *const _,
            )
        }
    };
    let source = match get_addr_from_arg(ctx, JSValue(*argv.add(1))) {
        Some(value) => value,
        None => return ffi::JS_ThrowTypeError(ctx, b"Memory.copy: source must be a pointer\0".as_ptr() as *const _),
    };
    let size = match parse_size(ctx, JSValue(*argv.add(2)), "Memory.copy") {
        Ok(value) => value,
        Err(error) => return error,
    };

    match copy_memory(destination, source, size) {
        Ok(()) => JSValue::undefined().raw(),
        Err(error) => throw_message(ctx, &format!("Memory.copy: {}", error)),
    }
}

pub(super) unsafe extern "C" fn memory_dup(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Memory.dup(source, size) requires 2 arguments\0".as_ptr() as *const _,
        );
    }
    let source = match get_addr_from_arg(ctx, JSValue(*argv)) {
        Some(value) => value,
        None => return ffi::JS_ThrowTypeError(ctx, b"Memory.dup: source must be a pointer\0".as_ptr() as *const _),
    };
    let size = match parse_size(ctx, JSValue(*argv.add(1)), "Memory.dup") {
        Ok(value) if value > 0 && value <= MAX_OWNED_ALLOCATION => value,
        Ok(_) => return throw_message(ctx, "Memory.dup: invalid size"),
        Err(error) => return error,
    };

    let allocation = libc::calloc(1, size);
    if allocation.is_null() {
        return ffi::JS_ThrowInternalError(ctx, b"Memory.dup: allocation failed\0".as_ptr() as *const _);
    }
    if let Err(error) = copy_memory(allocation as u64, source, size) {
        libc::free(allocation);
        return throw_message(ctx, &format!("Memory.dup: {}", error));
    }
    create_owned_native_pointer(ctx, allocation as u64).raw()
}

pub(super) unsafe extern "C" fn memory_query_protection(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Memory.queryProtection(address) requires 1 argument\0".as_ptr() as *const _,
        );
    }
    let address = match get_addr_from_arg(ctx, JSValue(*argv)) {
        Some(value) => value,
        None => {
            return ffi::JS_ThrowTypeError(
                ctx,
                b"Memory.queryProtection: address must be a pointer\0".as_ptr() as *const _,
            )
        }
    };
    let protection = match query_page_protection(address) {
        Some(value) => value,
        None => return throw_message(ctx, "Memory.queryProtection: failed to query address"),
    };
    let text = [
        if protection & libc::PROT_READ != 0 { 'r' } else { '-' },
        if protection & libc::PROT_WRITE != 0 { 'w' } else { '-' },
        if protection & libc::PROT_EXEC != 0 { 'x' } else { '-' },
    ]
    .iter()
    .collect::<String>();
    JSValue::string(ctx, &text).raw()
}

#[cfg(test)]
mod tests {
    use super::copy_memory;

    #[test]
    fn copies_overlapping_ranges_like_memmove() {
        let mut bytes = *b"abcdefgh";
        let base = bytes.as_mut_ptr() as u64;
        copy_memory(base + 2, base, 6).unwrap();
        assert_eq!(&bytes, b"ababcdef");

        copy_memory(base, base + 2, 6).unwrap();
        assert_eq!(&bytes, b"abcdefef");
    }
}
