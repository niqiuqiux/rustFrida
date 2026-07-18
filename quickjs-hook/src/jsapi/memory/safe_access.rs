//! Fault-safe access to the current process address space.
//!
//! Direct Rust pointer dereferences can terminate the target when a mapping is
//! concurrently removed. Kernel-assisted copies report `EFAULT` instead.

use crate::jsapi::util::{canonicalize_user_address, range_has_protection};
use std::fmt;
use std::mem::MaybeUninit;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum MemoryOperation {
    Read,
    Write,
}

impl fmt::Display for MemoryOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read => f.write_str("read"),
            Self::Write => f.write_str("write"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct MemoryAccessError {
    pub operation: MemoryOperation,
    pub address: u64,
    pub size: usize,
    pub errno: i32,
}

impl fmt::Display for MemoryAccessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "memory {} failed at {:#x} (size {}, errno {})",
            self.operation, self.address, self.size, self.errno
        )
    }
}

fn last_errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO)
}

unsafe fn process_vm_transfer(
    operation: MemoryOperation,
    address: u64,
    buffer: *mut u8,
    size: usize,
) -> Result<(), MemoryAccessError> {
    let kernel_address = canonicalize_user_address(address);
    let mut completed = 0usize;
    while completed < size {
        let local = libc::iovec {
            iov_base: buffer.add(completed) as *mut libc::c_void,
            iov_len: size - completed,
        };
        let remote = libc::iovec {
            iov_base: (kernel_address + completed as u64) as usize as *mut libc::c_void,
            iov_len: size - completed,
        };
        let syscall_number = match operation {
            MemoryOperation::Read => libc::SYS_process_vm_readv,
            MemoryOperation::Write => libc::SYS_process_vm_writev,
        };
        let result = libc::syscall(
            syscall_number,
            libc::getpid(),
            &local as *const libc::iovec,
            1usize,
            &remote as *const libc::iovec,
            1usize,
            0usize,
        ) as isize;
        if result > 0 {
            completed += result as usize;
            continue;
        }
        let errno = if result == 0 { libc::EIO } else { last_errno() };
        if errno == libc::EINTR {
            continue;
        }
        return Err(MemoryAccessError {
            operation,
            address: address + completed as u64,
            size: size - completed,
            errno,
        });
    }
    Ok(())
}

unsafe fn proc_mem_read(address: u64, buffer: *mut u8, size: usize) -> Result<(), MemoryAccessError> {
    let fd = libc::open(
        b"/proc/self/mem\0".as_ptr() as *const libc::c_char,
        libc::O_RDONLY | libc::O_CLOEXEC,
    );
    if fd < 0 {
        return Err(MemoryAccessError {
            operation: MemoryOperation::Read,
            address,
            size,
            errno: last_errno(),
        });
    }

    let kernel_address = canonicalize_user_address(address);
    let mut completed = 0usize;
    let result = loop {
        if completed == size {
            break Ok(());
        }
        let offset = match i64::try_from(kernel_address + completed as u64) {
            Ok(offset) => offset as libc::off_t,
            Err(_) => {
                break Err(MemoryAccessError {
                    operation: MemoryOperation::Read,
                    address: address + completed as u64,
                    size: size - completed,
                    errno: libc::EOVERFLOW,
                });
            }
        };
        let n = libc::pread(fd, buffer.add(completed) as *mut libc::c_void, size - completed, offset);
        if n > 0 {
            completed += n as usize;
            continue;
        }
        let errno = if n == 0 { libc::EIO } else { last_errno() };
        if errno == libc::EINTR {
            continue;
        }
        break Err(MemoryAccessError {
            operation: MemoryOperation::Read,
            address: address + completed as u64,
            size: size - completed,
            errno,
        });
    };
    libc::close(fd);
    result
}

pub(super) fn read_exact(address: u64, output: &mut [u8]) -> Result<(), MemoryAccessError> {
    if output.is_empty() {
        return Ok(());
    }
    let kernel_address = canonicalize_user_address(address);
    if kernel_address == 0 || kernel_address.checked_add(output.len() as u64).is_none() {
        return Err(MemoryAccessError {
            operation: MemoryOperation::Read,
            address,
            size: output.len(),
            errno: libc::EFAULT,
        });
    }

    let result = unsafe { process_vm_transfer(MemoryOperation::Read, address, output.as_mut_ptr(), output.len()) };
    match result {
        Err(error) if matches!(error.errno, libc::ENOSYS | libc::EPERM | libc::EACCES) => unsafe {
            proc_mem_read(address, output.as_mut_ptr(), output.len())
        },
        other => other,
    }
}

pub(super) fn write_exact(address: u64, input: &[u8]) -> Result<(), MemoryAccessError> {
    if input.is_empty() {
        return Ok(());
    }
    let kernel_address = canonicalize_user_address(address);
    if kernel_address == 0
        || kernel_address.checked_add(input.len() as u64).is_none()
        || !range_has_protection(address, input.len(), libc::PROT_WRITE)
    {
        return Err(MemoryAccessError {
            operation: MemoryOperation::Write,
            address,
            size: input.len(),
            errno: libc::EFAULT,
        });
    }

    unsafe { process_vm_transfer(MemoryOperation::Write, address, input.as_ptr() as *mut u8, input.len()) }
}

pub(super) fn read_value<T: Copy>(address: u64) -> Result<T, MemoryAccessError> {
    let mut value = MaybeUninit::<T>::uninit();
    let bytes = unsafe { std::slice::from_raw_parts_mut(value.as_mut_ptr() as *mut u8, std::mem::size_of::<T>()) };
    read_exact(address, bytes)?;
    Ok(unsafe { value.assume_init() })
}

pub(super) fn write_value<T: Copy>(address: u64, value: &T) -> Result<(), MemoryAccessError> {
    let bytes = unsafe { std::slice::from_raw_parts(value as *const T as *const u8, std::mem::size_of::<T>()) };
    write_exact(address, bytes)
}

#[cfg(test)]
mod tests {
    use super::{read_exact, read_value, write_exact, write_value};

    #[test]
    fn safely_reads_and_writes_local_memory() {
        let mut value = 0x1122_3344u32;
        let address = (&mut value as *mut u32) as u64;
        assert_eq!(read_value::<u32>(address).unwrap(), value);
        write_value(address, &0xaabb_ccddu32).unwrap();
        assert_eq!(value, 0xaabb_ccdd);
    }

    #[test]
    fn rejects_invalid_addresses_without_dereferencing_them() {
        let mut output = [0u8; 8];
        assert!(read_exact(1, &mut output).is_err());
        assert!(write_exact(1, &[1, 2, 3]).is_err());
    }
}
