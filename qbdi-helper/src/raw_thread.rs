use libc::{
    c_int, mmap, pid_t, timespec, SYS_clone, SYS_exit, SYS_nanosleep, SYS_prctl, CLONE_FILES, CLONE_FS, CLONE_SIGHAND,
    CLONE_SYSVSEM, CLONE_THREAD, CLONE_VM, MAP_ANONYMOUS, MAP_PRIVATE, PROT_READ, PROT_WRITE, PR_SET_NAME,
};
use std::arch::asm;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

const STACK_SIZE: usize = 1024 * 1024;

pub(crate) struct RawThreadHandle {
    #[allow(dead_code)]
    tid: pid_t,
    done: Arc<AtomicBool>,
}

struct RawThreadStart {
    name: &'static [u8],
    done: Arc<AtomicBool>,
    func: Option<Box<dyn FnOnce() + Send>>,
}

pub(crate) fn spawn(name: &'static [u8], func: impl FnOnce() + Send + 'static) -> Result<RawThreadHandle, String> {
    let done = Arc::new(AtomicBool::new(false));
    let tid = spawn_with_done(name, Arc::clone(&done), func)?;
    Ok(RawThreadHandle { tid, done })
}

impl RawThreadHandle {
    pub(crate) fn is_finished(&self) -> bool {
        self.done.load(Ordering::Acquire)
    }

    pub(crate) fn join_timeout_ms(&self, timeout_ms: u64) -> bool {
        let start = std::time::Instant::now();
        let timeout = std::time::Duration::from_millis(timeout_ms);
        while !self.done.load(Ordering::Acquire) {
            if start.elapsed() >= timeout {
                return false;
            }
            raw_sleep_ms(10);
        }
        true
    }

    pub(crate) fn join(self) {
        while !self.done.load(Ordering::Acquire) {
            raw_sleep_ms(10);
        }
    }
}

fn spawn_with_done(
    name: &'static [u8],
    done: Arc<AtomicBool>,
    func: impl FnOnce() + Send + 'static,
) -> Result<pid_t, String> {
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

    let start = Box::into_raw(Box::new(RawThreadStart {
        name,
        done,
        func: Some(Box::new(func)),
    }));
    let child_stack = unsafe { (stack_base as *mut u8).add(STACK_SIZE) as *mut usize };
    let flags = (CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM) as u64;

    match unsafe { raw_clone(raw_thread_entry as *mut usize, start as usize, flags, child_stack) } {
        Ok(tid) => Ok(tid),
        Err(e) => {
            unsafe {
                drop(Box::from_raw(start));
            }
            Err(e)
        }
    }
}

unsafe fn raw_clone(child_func: *mut usize, arg: usize, flags: u64, child_stack: *mut usize) -> Result<pid_t, String> {
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
        in("x2") 0usize,
        in("x3") 0usize,
        in("x4") 0usize,
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

extern "C" fn raw_thread_entry(arg: usize) -> c_int {
    let mut start = unsafe { Box::from_raw(arg as *mut RawThreadStart) };
    raw_set_name(start.name);

    if let Some(func) = start.func.take() {
        func();
    }
    start.done.store(true, Ordering::Release);

    0
}

fn raw_set_name(name: &'static [u8]) {
    unsafe {
        let mut result: isize;
        asm!(
            "svc 0x0",
            in("x8") SYS_prctl,
            inout("x0") PR_SET_NAME as usize => result,
            in("x1") name.as_ptr() as usize,
            in("x2") 0usize,
            in("x3") 0usize,
            in("x4") 0usize,
            options(nostack, preserves_flags),
        );
        let _ = result;
    }
}

fn raw_sleep_ms(ms: i64) {
    let req = timespec {
        tv_sec: ms / 1000,
        tv_nsec: (ms % 1000) * 1_000_000,
    };
    unsafe {
        let mut result: isize;
        asm!(
            "svc 0x0",
            in("x8") SYS_nanosleep,
            inout("x0") &req as *const timespec as usize => result,
            in("x1") 0usize,
            options(nostack, preserves_flags),
        );
        let _ = result;
    }
}
