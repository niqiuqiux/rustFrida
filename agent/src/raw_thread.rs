use crate::gumlibc::gum_libc_syscall_4;
use libc::{
    c_int, c_long, mmap, pid_t, timespec, SYS_clone, SYS_exit, SYS_nanosleep, CLONE_FILES, CLONE_FS, CLONE_SIGHAND,
    CLONE_SYSVSEM, CLONE_THREAD, CLONE_VM, MAP_ANONYMOUS, MAP_PRIVATE, PROT_READ, PROT_WRITE, PR_SET_NAME,
};
use std::arch::asm;
use std::ptr::null_mut;
use std::sync::OnceLock;

const STACK_SIZE: usize = 2 * 1024 * 1024;
const CLONE_SETTLS_RAW: u64 = 0x0008_0000;
const CLONE_PARENT_SETTID_RAW: u64 = 0x0010_0000;
const CLONE_CHILD_CLEARTID_RAW: u64 = 0x0020_0000;
const CLONE_CHILD_SETTID_RAW: u64 = 0x0100_0000;

const TLS_SLOT_MIN: isize = -1;
const TLS_SLOT_BIONIC_TLS: isize = -1;
const TLS_SLOT_THREAD_ID: isize = 1;
const TLS_SLOT_ART_THREAD_SELF: isize = 7;
const BIONIC_TLS_SLOTS: usize = 9;

const BIONIC_THREAD_TID_OFFSET: usize = 16;
const BIONIC_THREAD_CACHED_PID_OFFSET: usize = 20;
const BIONIC_THREAD_ATTR_OFFSET: usize = 24;
const BIONIC_THREAD_ATTR_SIZE: usize = 56;
const PTHREAD_ATTR_FLAGS_OFFSET: usize = 0;
const PTHREAD_ATTR_STACK_BASE_OFFSET: usize = 8;
const PTHREAD_ATTR_STACK_SIZE_OFFSET: usize = 16;
const PTHREAD_ATTR_GUARD_SIZE_OFFSET: usize = 24;
const BIONIC_THREAD_JOIN_STATE_OFFSET: usize = BIONIC_THREAD_ATTR_OFFSET + BIONIC_THREAD_ATTR_SIZE;
const THREAD_DETACHED: i32 = 3;
const SHADOW_PTHREAD_SIZE: usize = 4096;
const SHADOW_BIONIC_TLS_SIZE: usize = 16 * 1024;

type InitTcbFn = unsafe extern "C" fn(*mut usize, *mut u8);
type InitTcbOnlyFn = unsafe extern "C" fn(*mut usize);
type InitBionicTlsPtrsFn = unsafe extern "C" fn(*mut usize, *mut u8);

struct BionicTlsInit {
    init_tcb: Option<InitTcbFn>,
    init_tcb_dtv: Option<InitTcbOnlyFn>,
    init_tcb_stack_guard: Option<InitTcbOnlyFn>,
    init_bionic_tls_ptrs: Option<InitBionicTlsPtrsFn>,
}

static BIONIC_TLS_INIT: OnceLock<BionicTlsInit> = OnceLock::new();

struct RawThreadStart {
    name: &'static [u8],
    func: Option<Box<dyn FnOnce() + Send>>,
    shadow: RawThreadTls,
}

#[repr(C, align(16))]
struct RawThreadTls {
    tcb_slots: [usize; BIONIC_TLS_SLOTS],
    pthread: [u8; SHADOW_PTHREAD_SIZE],
    bionic_tls: [u8; SHADOW_BIONIC_TLS_SIZE],
}

impl RawThreadTls {
    fn new(stack_base: *mut std::ffi::c_void) -> Self {
        let mut tls = Self {
            tcb_slots: [0; BIONIC_TLS_SLOTS],
            pthread: [0; SHADOW_PTHREAD_SIZE],
            bionic_tls: [0; SHADOW_BIONIC_TLS_SIZE],
        };

        unsafe {
            let parent_tp = read_thread_pointer();
            if !parent_tp.is_null() {
                let parent_tcb = parent_tp.offset(TLS_SLOT_MIN);
                for i in 0..BIONIC_TLS_SLOTS {
                    tls.tcb_slots[i] = *parent_tcb.add(i);
                }
            }

            let pthread = tls.pthread.as_mut_ptr();
            write_i32(pthread, BIONIC_THREAD_TID_OFFSET, 0);
            write_i32(pthread, BIONIC_THREAD_CACHED_PID_OFFSET, libc::getpid());
            write_i32(pthread, BIONIC_THREAD_JOIN_STATE_OFFSET, THREAD_DETACHED);
            let attr = pthread.add(BIONIC_THREAD_ATTR_OFFSET);
            write_u32(attr, PTHREAD_ATTR_FLAGS_OFFSET, 0);
            write_usize(attr, PTHREAD_ATTR_STACK_BASE_OFFSET, stack_base as usize);
            write_usize(attr, PTHREAD_ATTR_STACK_SIZE_OFFSET, STACK_SIZE);
            write_usize(attr, PTHREAD_ATTR_GUARD_SIZE_OFFSET, 0);

            let bionic_tls = tls.bionic_tls.as_mut_ptr() as usize;
            let tcb = tls.tcb_slots.as_mut_ptr();
            if let Some(init) = bionic_tls_init() {
                if let Some(f) = init.init_tcb {
                    f(tcb, pthread);
                } else {
                    tls.set_slot(TLS_SLOT_THREAD_ID, pthread as usize);
                }
                if let Some(f) = init.init_tcb_dtv {
                    f(tcb);
                }
                if let Some(f) = init.init_tcb_stack_guard {
                    f(tcb);
                }
                if let Some(f) = init.init_bionic_tls_ptrs {
                    f(tcb, bionic_tls as *mut u8);
                } else {
                    tls.set_slot(TLS_SLOT_BIONIC_TLS, bionic_tls);
                }
            } else {
                tls.set_slot(TLS_SLOT_BIONIC_TLS, bionic_tls);
                tls.set_slot(TLS_SLOT_THREAD_ID, pthread as usize);
            }
            tls.set_slot(TLS_SLOT_ART_THREAD_SELF, 0);
        }

        tls
    }

    fn child_tls(&mut self) -> *mut usize {
        unsafe { self.tcb_slots.as_mut_ptr().offset(-TLS_SLOT_MIN) }
    }

    fn child_tid_ptr(&mut self) -> *mut i32 {
        unsafe { self.pthread.as_mut_ptr().add(BIONIC_THREAD_TID_OFFSET) as *mut i32 }
    }

    fn set_slot(&mut self, slot: isize, value: usize) {
        self.tcb_slots[(slot - TLS_SLOT_MIN) as usize] = value;
    }
}

pub(crate) fn spawn_detached<F>(name: &'static [u8], func: F) -> Result<pid_t, String>
where
    F: FnOnce() + Send + 'static,
{
    let stack_base = unsafe {
        mmap(
            null_mut(),
            STACK_SIZE,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if stack_base == libc::MAP_FAILED {
        return Err("raw thread stack mmap failed".into());
    }

    let mut start = Box::new(RawThreadStart {
        name,
        func: Some(Box::new(func)),
        shadow: RawThreadTls::new(stack_base),
    });
    let child_tls = start.shadow.child_tls();
    let child_tid = start.shadow.child_tid_ptr();
    let start = Box::into_raw(start);
    let child_stack = unsafe { (stack_base as *mut u8).add(STACK_SIZE) as *mut usize };
    let flags = (CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM) as u64
        | CLONE_SETTLS_RAW
        | CLONE_PARENT_SETTID_RAW
        | CLONE_CHILD_SETTID_RAW
        | CLONE_CHILD_CLEARTID_RAW;

    match unsafe {
        raw_clone(
            raw_thread_entry as *mut usize,
            start as usize,
            flags,
            child_stack,
            child_tid,
            child_tls,
        )
    } {
        Ok(tid) => Ok(tid),
        Err(e) => {
            unsafe {
                drop(Box::from_raw(start));
            }
            Err(e)
        }
    }
}

pub(crate) fn sleep_ms(ms: i64) {
    let req = timespec {
        tv_sec: ms / 1000,
        tv_nsec: (ms % 1000) * 1_000_000,
    };
    gum_libc_syscall_4(SYS_nanosleep as c_long, &req as *const timespec as usize, 0, 0, 0);
}

unsafe fn raw_clone(
    child_func: *mut usize,
    arg: usize,
    flags: u64,
    child_stack: *mut usize,
    child_tid: *mut i32,
    child_tls: *mut usize,
) -> Result<pid_t, String> {
    let mut result: i64;

    *(child_stack.sub(1)) = child_func as usize;
    *(child_stack.sub(2)) = arg;

    asm!(
        "svc 0x0",
        "cbnz x0, 1f",
        "ldp x0, x1, [sp], #16",
        "blr x1",
        "mov x8, {exit_syscall}",
        "mov x0, #0",
        "svc 0x0",
        "1:",
        in("x8") SYS_clone,
        inout("x0") flags => result,
        in("x1") child_stack.sub(2),
        in("x2") child_tid,
        in("x3") child_tls,
        in("x4") child_tid,
        exit_syscall = const SYS_exit,
        options(nostack, preserves_flags),
        clobber_abi("C"),
    );

    if result < 0 {
        Err(format!("raw clone failed: {}", -result))
    } else {
        Ok(result as pid_t)
    }
}

unsafe fn read_thread_pointer() -> *const usize {
    let tp: usize;
    asm!("mrs {}, tpidr_el0", out(reg) tp, options(nostack, nomem, preserves_flags));
    tp as *const usize
}

unsafe fn write_i32(base: *mut u8, offset: usize, value: i32) {
    (base.add(offset) as *mut i32).write(value);
}

unsafe fn write_u32(base: *mut u8, offset: usize, value: u32) {
    (base.add(offset) as *mut u32).write(value);
}

unsafe fn write_usize(base: *mut u8, offset: usize, value: usize) {
    (base.add(offset) as *mut usize).write(value);
}

fn bionic_tls_init() -> Option<&'static BionicTlsInit> {
    let init = BIONIC_TLS_INIT.get_or_init(|| unsafe {
        BionicTlsInit {
            init_tcb: resolve_libc_local_symbol("_Z10__init_tcbP10bionic_tcbP18pthread_internal_t")
                .map(|p| std::mem::transmute(p)),
            init_tcb_dtv: resolve_libc_local_symbol("_Z14__init_tcb_dtvP10bionic_tcb").map(|p| std::mem::transmute(p)),
            init_tcb_stack_guard: resolve_libc_local_symbol("_Z22__init_tcb_stack_guardP10bionic_tcb")
                .map(|p| std::mem::transmute(p)),
            init_bionic_tls_ptrs: resolve_libc_local_symbol("_Z22__init_bionic_tls_ptrsP10bionic_tcbP10bionic_tls")
                .map(|p| std::mem::transmute(p)),
        }
    });

    (init.init_tcb.is_some()
        || init.init_tcb_dtv.is_some()
        || init.init_tcb_stack_guard.is_some()
        || init.init_bionic_tls_ptrs.is_some())
    .then_some(init)
}

unsafe fn resolve_libc_local_symbol(name: &str) -> Option<usize> {
    let (base, path) = find_libc_mapping()?;
    let data = std::fs::read(path).ok()?;
    find_elf_symbol(&data, base, name)
}

fn find_libc_mapping() -> Option<(usize, String)> {
    let maps = std::fs::read_to_string("/proc/self/maps").ok()?;
    for line in maps.lines() {
        let mut parts = line.split_whitespace();
        let range = parts.next()?;
        let _perms = parts.next()?;
        let offset = usize::from_str_radix(parts.next()?, 16).ok()?;
        let _dev = parts.next()?;
        let _inode = parts.next()?;
        let path = parts.next()?;
        if offset != 0 || !path.ends_with("/libc.so") {
            continue;
        }
        let start = usize::from_str_radix(range.split('-').next()?, 16).ok()?;
        return Some((start, path.to_string()));
    }
    None
}

#[repr(C)]
#[derive(Clone, Copy)]
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
#[derive(Clone, Copy)]
struct Elf64Shdr {
    sh_name: u32,
    sh_type: u32,
    sh_flags: u64,
    sh_addr: u64,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_info: u32,
    sh_addralign: u64,
    sh_entsize: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Elf64Sym {
    st_name: u32,
    st_info: u8,
    st_other: u8,
    st_shndx: u16,
    st_value: u64,
    st_size: u64,
}

const SHT_SYMTAB: u32 = 2;
const SHT_DYNSYM: u32 = 11;

unsafe fn read_unaligned_at<T: Copy>(data: &[u8], offset: usize) -> Option<T> {
    if offset.checked_add(std::mem::size_of::<T>())? > data.len() {
        return None;
    }
    Some(std::ptr::read_unaligned(data.as_ptr().add(offset) as *const T))
}

unsafe fn find_elf_symbol(data: &[u8], base: usize, wanted: &str) -> Option<usize> {
    let ehdr: Elf64Ehdr = read_unaligned_at(data, 0)?;
    if ehdr.e_ident.get(0..4) != Some(b"\x7fELF") || ehdr.e_ident[4] != 2 {
        return None;
    }

    let shoff = ehdr.e_shoff as usize;
    let shentsize = ehdr.e_shentsize as usize;
    let shnum = ehdr.e_shnum as usize;
    if shoff == 0 || shentsize < std::mem::size_of::<Elf64Shdr>() {
        return None;
    }

    for i in 0..shnum {
        let sh: Elf64Shdr = read_unaligned_at(data, shoff + i * shentsize)?;
        if sh.sh_type != SHT_SYMTAB && sh.sh_type != SHT_DYNSYM {
            continue;
        }
        let str_sh: Elf64Shdr = read_unaligned_at(data, shoff + sh.sh_link as usize * shentsize)?;
        let str_off = str_sh.sh_offset as usize;
        let str_size = str_sh.sh_size as usize;
        if str_off.checked_add(str_size)? > data.len() {
            continue;
        }

        let sym_off = sh.sh_offset as usize;
        let sym_size = if sh.sh_entsize == 0 {
            std::mem::size_of::<Elf64Sym>()
        } else {
            sh.sh_entsize as usize
        };
        let sym_count = sh.sh_size as usize / sym_size;
        for idx in 0..sym_count {
            let sym: Elf64Sym = read_unaligned_at(data, sym_off + idx * sym_size)?;
            if sym.st_name == 0 || sym.st_value == 0 {
                continue;
            }
            let name_off = str_off + sym.st_name as usize;
            if name_off >= str_off + str_size {
                continue;
            }
            let names = &data[name_off..str_off + str_size];
            let len = names.iter().position(|&b| b == 0)?;
            if std::str::from_utf8(&names[..len]).ok()? == wanted {
                return Some(base + sym.st_value as usize);
            }
        }
    }

    None
}

extern "C" fn raw_thread_entry(arg: usize) -> c_int {
    let start = unsafe { &mut *(arg as *mut RawThreadStart) };
    gum_libc_syscall_4(
        libc::SYS_prctl as c_long,
        PR_SET_NAME as usize,
        start.name.as_ptr() as usize,
        0,
        0,
    );

    if let Some(func) = start.func.take() {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(func));
    }

    0
}
