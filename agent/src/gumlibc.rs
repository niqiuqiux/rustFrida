use libc::{c_char, c_int, c_long};
use std::arch::asm;
use std::ffi::{c_void, CStr};

unsafe extern "C" {
    #[link_name = "__real_dlsym"]
    fn real_dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
}

/// Bionic's dlsym uses the caller address to determine its linker namespace.
/// A custom-mapped agent has no soinfo, so bootstrap the symbols Gum needs
/// before it discovers Android's unrestricted linker API.
#[no_mangle]
pub unsafe extern "C" fn __wrap_dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void {
    if !symbol.is_null() {
        let name = CStr::from_ptr(symbol).to_bytes();
        let address = match name {
            b"exit" => Some(libc::exit as *const () as *mut c_void),
            b"open" => Some(libc::open as *const () as *mut c_void),
            b"dl_iterate_phdr" => Some(libc::dl_iterate_phdr as *const () as *mut c_void),
            _ => None,
        };
        if let Some(address) = address {
            return address;
        }
    }

    real_dlsym(handle, symbol)
}

/// Frida Gum uses Android's low-level log entry-point for diagnostics. The
/// custom agent loader does not resolve liblog, so keep this symbol local and
/// forward the message to stderr without taking any runtime locks.
#[no_mangle]
pub unsafe extern "C" fn __android_log_write(
    _priority: c_int,
    _tag: *const libc::c_char,
    text: *const libc::c_char,
) -> c_int {
    if text.is_null() {
        return -1;
    }

    let bytes = std::ffi::CStr::from_ptr(text).to_bytes();
    let _ = libc::write(libc::STDERR_FILENO, bytes.as_ptr().cast(), bytes.len());
    let newline = b"\n";
    let _ = libc::write(libc::STDERR_FILENO, newline.as_ptr().cast(), newline.len());
    1
}

pub fn gum_libc_syscall_4(n: c_long, a: usize, b: usize, c: usize, d: usize) -> usize {
    let result: usize;
    unsafe {
        asm!(
            "svc 0x0",
            in("x8") n,
            inout("x0") a => result,
            in("x1") b,
            in("x2") c,
            in("x3") d,
        )
    }
    result
}
