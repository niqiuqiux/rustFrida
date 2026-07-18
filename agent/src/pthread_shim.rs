use libc::{
    c_int, c_long, c_void, clockid_t, mmap, pthread_key_t, pthread_t, timespec, SYS_clock_gettime, SYS_clone, SYS_exit,
    SYS_nanosleep, CLOCK_REALTIME, CLONE_FILES, CLONE_FS, CLONE_SIGHAND, CLONE_SYSVSEM, CLONE_THREAD, CLONE_VM,
    MAP_ANONYMOUS, MAP_PRIVATE, PROT_READ, PROT_WRITE,
};
use std::arch::asm;
use std::sync::atomic::{AtomicI32, AtomicU32, AtomicU64, Ordering};

const STACK_SIZE: usize = 1024 * 1024;
const TLS_KEY_COUNT: usize = 128;
const TLS_VALUE_SLOTS: usize = 512;
const MUTEX_SLOT_COUNT: usize = 2048;
const ONCE_IN_PROGRESS: i32 = 1;
const ONCE_DONE: i32 = 2;
const RWLOCK_WRITER: i32 = -1;

struct ShimThreadStart {
    start: unsafe extern "C" fn(*mut c_void) -> *mut c_void,
    arg: *mut c_void,
}

static NEXT_TLS_KEY: AtomicU32 = AtomicU32::new(1);
static TLS_KEY_ACTIVE: [AtomicU32; TLS_KEY_COUNT] = [const { AtomicU32::new(0) }; TLS_KEY_COUNT];
static TLS_SLOT_THREAD: [AtomicU64; TLS_VALUE_SLOTS] = [const { AtomicU64::new(0) }; TLS_VALUE_SLOTS];
static TLS_SLOT_KEY: [AtomicU32; TLS_VALUE_SLOTS] = [const { AtomicU32::new(0) }; TLS_VALUE_SLOTS];
static TLS_SLOT_VALUE: [AtomicU64; TLS_VALUE_SLOTS] = [const { AtomicU64::new(0) }; TLS_VALUE_SLOTS];
static MUTEX_SLOT_ADDRESS: [AtomicU64; MUTEX_SLOT_COUNT] = [const { AtomicU64::new(0) }; MUTEX_SLOT_COUNT];
static MUTEX_SLOT_OWNER: [AtomicU64; MUTEX_SLOT_COUNT] = [const { AtomicU64::new(0) }; MUTEX_SLOT_COUNT];
static MUTEX_SLOT_DEPTH: [AtomicU32; MUTEX_SLOT_COUNT] = [const { AtomicU32::new(0) }; MUTEX_SLOT_COUNT];

#[cfg(not(test))]
unsafe extern "C" {
    #[link_name = "__real_pthread_mutex_lock"]
    fn real_pthread_mutex_lock(mutex: *mut c_void) -> c_int;
    #[link_name = "__real_pthread_mutex_unlock"]
    fn real_pthread_mutex_unlock(mutex: *mut c_void) -> c_int;
    #[link_name = "__real_pthread_mutex_destroy"]
    fn real_pthread_mutex_destroy(mutex: *mut c_void) -> c_int;
}

#[cfg(test)]
unsafe fn real_pthread_mutex_lock(mutex: *mut c_void) -> c_int {
    libc::pthread_mutex_lock(mutex.cast())
}

#[cfg(test)]
unsafe fn real_pthread_mutex_unlock(mutex: *mut c_void) -> c_int {
    libc::pthread_mutex_unlock(mutex.cast())
}

#[cfg(test)]
unsafe fn real_pthread_mutex_destroy(mutex: *mut c_void) -> c_int {
    libc::pthread_mutex_destroy(mutex.cast())
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn __wrap_pthread_mutex_lock(mutex: *mut c_void) -> c_int {
    if mutex.is_null() {
        return libc::EINVAL;
    }
    let Some(slot) = mutex_slot(mutex as u64, false) else {
        return real_pthread_mutex_lock(mutex);
    };
    let state = &*(mutex as *const AtomicI32);
    let thread_id = current_os_thread_id();
    if MUTEX_SLOT_OWNER[slot].load(Ordering::Acquire) == thread_id {
        MUTEX_SLOT_DEPTH[slot].fetch_add(1, Ordering::Relaxed);
        return 0;
    }

    let mut spins = 0u32;
    loop {
        if state
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            MUTEX_SLOT_DEPTH[slot].store(1, Ordering::Relaxed);
            MUTEX_SLOT_OWNER[slot].store(thread_id, Ordering::Release);
            return 0;
        }
        if spins < 64 {
            asm!("yield", options(nomem, nostack, preserves_flags));
            spins += 1;
        } else {
            sleep_for_ns(100_000);
        }
    }
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn __wrap_pthread_mutex_unlock(mutex: *mut c_void) -> c_int {
    if mutex.is_null() {
        return libc::EINVAL;
    }
    let Some(slot) = mutex_slot(mutex as u64, false) else {
        return real_pthread_mutex_unlock(mutex);
    };
    let state = &*(mutex as *const AtomicI32);
    let thread_id = current_os_thread_id();
    if MUTEX_SLOT_OWNER[slot].load(Ordering::Acquire) != thread_id {
        return libc::EPERM;
    }
    let depth = MUTEX_SLOT_DEPTH[slot].load(Ordering::Relaxed);
    if depth > 1 {
        MUTEX_SLOT_DEPTH[slot].store(depth - 1, Ordering::Relaxed);
        return 0;
    }
    MUTEX_SLOT_DEPTH[slot].store(0, Ordering::Relaxed);
    MUTEX_SLOT_OWNER[slot].store(0, Ordering::Release);
    state.store(0, Ordering::Release);
    0
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn pthread_mutex_init(mutex: *mut c_void, _attr: *const c_void) -> c_int {
    if mutex.is_null() {
        return libc::EINVAL;
    }
    let state = &*(mutex as *const AtomicI32);
    state.store(0, Ordering::Release);
    let Some(slot) = mutex_slot(mutex as u64, true) else {
        return libc::ENOMEM;
    };
    MUTEX_SLOT_OWNER[slot].store(0, Ordering::Release);
    MUTEX_SLOT_DEPTH[slot].store(0, Ordering::Release);
    0
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn __wrap_pthread_mutex_destroy(mutex: *mut c_void) -> c_int {
    if mutex.is_null() {
        return libc::EINVAL;
    }
    let Some(slot) = mutex_slot(mutex as u64, false) else {
        return real_pthread_mutex_destroy(mutex);
    };
    if MUTEX_SLOT_OWNER[slot].load(Ordering::Acquire) != 0 {
        return libc::EBUSY;
    }
    MUTEX_SLOT_DEPTH[slot].store(0, Ordering::Release);
    let _ = MUTEX_SLOT_ADDRESS[slot].compare_exchange(mutex as u64, 0, Ordering::AcqRel, Ordering::Acquire);
    0
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn pthread_cond_init(cond: *mut c_void, _attr: *const c_void) -> c_int {
    if cond.is_null() {
        return libc::EINVAL;
    }
    (*(cond as *const AtomicU32)).store(0, Ordering::Release);
    0
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn pthread_cond_destroy(_cond: *mut c_void) -> c_int {
    0
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn pthread_cond_signal(cond: *mut c_void) -> c_int {
    if cond.is_null() {
        return libc::EINVAL;
    }
    (*(cond as *const AtomicU32)).fetch_add(1, Ordering::Release);
    0
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn pthread_cond_broadcast(cond: *mut c_void) -> c_int {
    pthread_cond_signal(cond)
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn pthread_cond_wait(cond: *mut c_void, mutex: *mut c_void) -> c_int {
    wait_on_cond(cond, mutex, std::ptr::null())
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn pthread_cond_timedwait(
    cond: *mut c_void,
    mutex: *mut c_void,
    abstime: *const timespec,
) -> c_int {
    wait_on_cond(cond, mutex, abstime)
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn pthread_once(once: *mut c_void, init_routine: Option<unsafe extern "C" fn()>) -> c_int {
    if once.is_null() {
        return libc::EINVAL;
    }
    let state = &*(once as *const AtomicI32);
    loop {
        match state.load(Ordering::Acquire) {
            ONCE_DONE => return 0,
            0 => {
                if state
                    .compare_exchange(0, ONCE_IN_PROGRESS, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    if let Some(f) = init_routine {
                        f();
                    }
                    state.store(ONCE_DONE, Ordering::Release);
                    return 0;
                }
            }
            _ => sleep_for_ns(1_000_000),
        }
    }
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn pthread_rwlock_init(lock: *mut c_void, _attr: *const c_void) -> c_int {
    if lock.is_null() {
        return libc::EINVAL;
    }
    (*(lock as *const AtomicI32)).store(0, Ordering::Release);
    0
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn pthread_rwlock_destroy(_lock: *mut c_void) -> c_int {
    0
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn pthread_rwlock_rdlock(lock: *mut c_void) -> c_int {
    if lock.is_null() {
        return libc::EINVAL;
    }
    let state = &*(lock as *const AtomicI32);
    loop {
        let current = state.load(Ordering::Acquire);
        if current >= 0
            && state
                .compare_exchange(current, current + 1, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
        {
            return 0;
        }
        asm!("yield", options(nomem, nostack, preserves_flags));
    }
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn pthread_rwlock_wrlock(lock: *mut c_void) -> c_int {
    if lock.is_null() {
        return libc::EINVAL;
    }
    let state = &*(lock as *const AtomicI32);
    loop {
        if state
            .compare_exchange(0, RWLOCK_WRITER, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            return 0;
        }
        asm!("yield", options(nomem, nostack, preserves_flags));
    }
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn pthread_rwlock_unlock(lock: *mut c_void) -> c_int {
    if lock.is_null() {
        return libc::EINVAL;
    }
    let state = &*(lock as *const AtomicI32);
    let current = state.load(Ordering::Acquire);
    if current == RWLOCK_WRITER {
        state.store(0, Ordering::Release);
    } else if current > 0 {
        state.fetch_sub(1, Ordering::Release);
    }
    0
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn pthread_key_create(
    key: *mut pthread_key_t,
    _destructor: Option<unsafe extern "C" fn(*mut c_void)>,
) -> c_int {
    if key.is_null() {
        return libc::EINVAL;
    }
    let id = NEXT_TLS_KEY.fetch_add(1, Ordering::AcqRel);
    if id == 0 || id as usize >= TLS_KEY_COUNT {
        return libc::EAGAIN;
    }
    TLS_KEY_ACTIVE[id as usize].store(1, Ordering::Release);
    *key = id as pthread_key_t;
    0
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn pthread_key_delete(key: pthread_key_t) -> c_int {
    let id = key as usize;
    if id == 0 || id >= TLS_KEY_COUNT {
        return libc::EINVAL;
    }
    TLS_KEY_ACTIVE[id].store(0, Ordering::Release);
    for idx in 0..TLS_VALUE_SLOTS {
        if TLS_SLOT_KEY[idx].load(Ordering::Acquire) == key as u32 {
            TLS_SLOT_VALUE[idx].store(0, Ordering::Release);
            TLS_SLOT_THREAD[idx].store(0, Ordering::Release);
            TLS_SLOT_KEY[idx].store(0, Ordering::Release);
        }
    }
    0
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn pthread_getspecific(key: pthread_key_t) -> *mut c_void {
    let id = key as usize;
    if id == 0 || id >= TLS_KEY_COUNT || TLS_KEY_ACTIVE[id].load(Ordering::Acquire) == 0 {
        return std::ptr::null_mut();
    }
    let thread = current_thread_token();
    for idx in 0..TLS_VALUE_SLOTS {
        if TLS_SLOT_THREAD[idx].load(Ordering::Acquire) == thread
            && TLS_SLOT_KEY[idx].load(Ordering::Acquire) == key as u32
        {
            return TLS_SLOT_VALUE[idx].load(Ordering::Acquire) as *mut c_void;
        }
    }
    std::ptr::null_mut()
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn pthread_setspecific(key: pthread_key_t, value: *const c_void) -> c_int {
    let id = key as usize;
    if id == 0 || id >= TLS_KEY_COUNT || TLS_KEY_ACTIVE[id].load(Ordering::Acquire) == 0 {
        return libc::EINVAL;
    }
    let thread = current_thread_token();
    for idx in 0..TLS_VALUE_SLOTS {
        if TLS_SLOT_THREAD[idx].load(Ordering::Acquire) == thread
            && TLS_SLOT_KEY[idx].load(Ordering::Acquire) == key as u32
        {
            TLS_SLOT_VALUE[idx].store(value as u64, Ordering::Release);
            return 0;
        }
    }
    for idx in 0..TLS_VALUE_SLOTS {
        if TLS_SLOT_THREAD[idx]
            .compare_exchange(0, thread, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            TLS_SLOT_VALUE[idx].store(value as u64, Ordering::Release);
            TLS_SLOT_KEY[idx].store(key as u32, Ordering::Release);
            return 0;
        }
    }
    libc::ENOMEM
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn pthread_create(
    thread: *mut pthread_t,
    _attr: *const c_void,
    start: Option<unsafe extern "C" fn(*mut c_void) -> *mut c_void>,
    arg: *mut c_void,
) -> c_int {
    let Some(start) = start else {
        return libc::EINVAL;
    };
    let stack = mmap(
        std::ptr::null_mut(),
        STACK_SIZE,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    if stack == libc::MAP_FAILED {
        return libc::ENOMEM;
    }
    let state = Box::into_raw(Box::new(ShimThreadStart { start, arg }));
    let child_stack = (stack as *mut u8).add(STACK_SIZE) as *mut usize;
    let flags = (CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM) as u64;
    match raw_clone(shim_thread_entry as *mut usize, state as usize, flags, child_stack) {
        Ok(tid) => {
            if !thread.is_null() {
                *thread = tid as pthread_t;
            }
            0
        }
        Err(errno) => {
            drop(Box::from_raw(state));
            errno
        }
    }
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn pthread_detach(_thread: pthread_t) -> c_int {
    0
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn nanosleep(req: *const timespec, rem: *mut timespec) -> c_int {
    let mut result: c_long;
    asm!(
        "svc 0x0",
        in("x8") SYS_nanosleep,
        inout("x0") req as usize => result,
        in("x1") rem as usize,
        options(nostack, preserves_flags),
    );
    if result < 0 {
        -1
    } else {
        result as c_int
    }
}

unsafe fn raw_clone(child_func: *mut usize, arg: usize, flags: u64, child_stack: *mut usize) -> Result<i32, c_int> {
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
        Err((-result) as c_int)
    } else {
        Ok(result as i32)
    }
}

extern "C" fn shim_thread_entry(arg: usize) -> c_int {
    let state = unsafe { Box::from_raw(arg as *mut ShimThreadStart) };
    unsafe {
        (state.start)(state.arg);
    }
    0
}

#[inline]
fn current_thread_token() -> u64 {
    let tpidr: u64;
    unsafe { asm!("mrs {}, tpidr_el0", out(reg) tpidr, options(nomem, nostack, preserves_flags)) };
    if tpidr != 0 {
        tpidr
    } else {
        unsafe { libc::syscall(libc::SYS_gettid) as u64 }
    }
}

#[inline]
fn current_os_thread_id() -> u64 {
    unsafe { libc::syscall(libc::SYS_gettid) as u64 }
}

fn mutex_slot(address: u64, create: bool) -> Option<usize> {
    let start = ((address >> 3) as usize) % MUTEX_SLOT_COUNT;
    for offset in 0..MUTEX_SLOT_COUNT {
        let index = (start + offset) % MUTEX_SLOT_COUNT;
        let current = MUTEX_SLOT_ADDRESS[index].load(Ordering::Acquire);
        if current == address {
            return Some(index);
        }
        if current == 0
            && create
            && MUTEX_SLOT_ADDRESS[index]
                .compare_exchange(0, address, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            return Some(index);
        }
    }
    None
}

unsafe fn wait_on_cond(cond: *mut c_void, mutex: *mut c_void, abstime: *const timespec) -> c_int {
    if cond.is_null() || mutex.is_null() {
        return libc::EINVAL;
    }
    let state = &*(cond as *const AtomicU32);
    let observed = state.load(Ordering::Acquire);
    let _ = __wrap_pthread_mutex_unlock(mutex);
    loop {
        if state.load(Ordering::Acquire) != observed {
            let _ = __wrap_pthread_mutex_lock(mutex);
            return 0;
        }
        if !abstime.is_null() && realtime_reached(abstime) {
            let _ = __wrap_pthread_mutex_lock(mutex);
            return libc::ETIMEDOUT;
        }
        sleep_for_ns(1_000_000);
    }
}

fn realtime_reached(abstime: *const timespec) -> bool {
    let mut now = timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe {
        if clock_gettime_raw(CLOCK_REALTIME as clockid_t, &mut now) != 0 {
            return false;
        }
        now.tv_sec > (*abstime).tv_sec || (now.tv_sec == (*abstime).tv_sec && now.tv_nsec >= (*abstime).tv_nsec)
    }
}

fn sleep_for_ns(ns: c_long) {
    let req = timespec { tv_sec: 0, tv_nsec: ns };
    unsafe {
        let _ = nanosleep(&req, std::ptr::null_mut());
    }
}

unsafe fn clock_gettime_raw(clock_id: clockid_t, ts: *mut timespec) -> c_int {
    let mut result: c_long;
    asm!(
        "svc 0x0",
        in("x8") SYS_clock_gettime,
        inout("x0") clock_id as usize => result,
        in("x1") ts as usize,
        options(nostack, preserves_flags),
    );
    result as c_int
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutex_supports_recursive_locking() {
        let mutex = AtomicI32::new(0);
        let pointer = (&mutex as *const AtomicI32).cast_mut().cast::<c_void>();
        unsafe {
            assert_eq!(pthread_mutex_init(pointer, std::ptr::null()), 0);
            assert_eq!(__wrap_pthread_mutex_lock(pointer), 0);
            assert_eq!(__wrap_pthread_mutex_lock(pointer), 0);
            assert_eq!(mutex.load(Ordering::Acquire), 1);
            assert_eq!(__wrap_pthread_mutex_unlock(pointer), 0);
            assert_eq!(mutex.load(Ordering::Acquire), 1);
            assert_eq!(__wrap_pthread_mutex_unlock(pointer), 0);
            assert_eq!(mutex.load(Ordering::Acquire), 0);
            assert_eq!(__wrap_pthread_mutex_destroy(pointer), 0);
        }
    }
}
