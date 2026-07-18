//! Hook callback wrapper (cross-thread safety, context building) — replace mode
//!
//! The thunk saves context and calls on_enter, then restores x0 and returns.
//! The callback can optionally call the original function via $orig().

use crate::ffi;
use crate::ffi::hook as hook_ffi;
use crate::jsapi::callback_util::{
    acquire_js_engine_for_callback, dup_callback_to_bytes, get_js_u64_property_atom, handle_js_exception, hot_atoms,
    invoke_hook_callback_common, js_u64_to_js_number_or_bigint, js_value_to_u64_or_zero, set_js_cfunction_property,
    set_js_u64_property_atom, set_js_value_property_atom,
};
use crate::jsapi::ptr::create_native_pointer;
use crate::value::JSValue;
use std::cell::{Cell, RefCell};
use std::ffi::c_void;
use std::sync::{Condvar, Mutex};

use super::registry::{self, HookKind, HOOK_REGISTRY};

#[derive(Clone, Copy)]
struct NativeHookFrame {
    ctx_ptr: usize,
    trampoline: u64,
    orig_called: bool,
}

// JS 回调在全局引擎锁下串行执行，因此用一个栈保存 native hook 回调状态即可支持嵌套 hook。
static NATIVE_HOOK_STACK: Mutex<Vec<NativeHookFrame>> = Mutex::new(Vec::new());
static IN_FLIGHT_NATIVE_HOOK_CALLBACKS: Mutex<usize> = Mutex::new(0);
static IN_FLIGHT_NATIVE_HOOK_CALLBACKS_CV: Condvar = Condvar::new();

struct InFlightNativeHookGuard;

impl InFlightNativeHookGuard {
    fn enter() -> Self {
        let mut in_flight = IN_FLIGHT_NATIVE_HOOK_CALLBACKS
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *in_flight += 1;
        Self
    }
}

impl Drop for InFlightNativeHookGuard {
    fn drop(&mut self) {
        let mut in_flight = IN_FLIGHT_NATIVE_HOOK_CALLBACKS
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *in_flight = in_flight.saturating_sub(1);
        if *in_flight == 0 {
            IN_FLIGHT_NATIVE_HOOK_CALLBACKS_CV.notify_all();
        }
    }
}

fn push_native_hook_frame(ctx_ptr: *mut hook_ffi::HookContext, trampoline: u64) {
    let mut stack = NATIVE_HOOK_STACK.lock().unwrap_or_else(|e| e.into_inner());
    stack.push(NativeHookFrame {
        ctx_ptr: ctx_ptr as usize,
        trampoline,
        orig_called: false,
    });
}

fn pop_native_hook_frame(ctx_ptr: *mut hook_ffi::HookContext, trampoline: u64) -> bool {
    let mut stack = NATIVE_HOOK_STACK.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(frame) = stack.pop() {
        debug_assert_eq!(frame.ctx_ptr, ctx_ptr as usize);
        debug_assert_eq!(frame.trampoline, trampoline);
        frame.orig_called
    } else {
        false
    }
}

fn mark_native_hook_frame_orig_called(ctx_ptr: *mut hook_ffi::HookContext, trampoline: u64) -> bool {
    let mut stack = NATIVE_HOOK_STACK.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(frame) = stack
        .iter_mut()
        .rfind(|frame| frame.ctx_ptr == ctx_ptr as usize && frame.trampoline == trampoline)
    {
        frame.orig_called = true;
        true
    } else {
        false
    }
}

fn current_native_hook_frame() -> Option<(*mut hook_ffi::HookContext, u64)> {
    let stack = NATIVE_HOOK_STACK.lock().unwrap_or_else(|e| e.into_inner());
    stack
        .last()
        .map(|frame| (frame.ctx_ptr as *mut hook_ffi::HookContext, frame.trampoline))
}

fn native_callback_would_reenter_js_engine() -> bool {
    crate::JS_ENGINE_OWNER_THREAD.load(std::sync::atomic::Ordering::Acquire) == crate::current_thread_id_u64()
}

pub(crate) fn wait_for_in_flight_native_hook_callbacks(timeout: std::time::Duration) -> bool {
    let start = std::time::Instant::now();
    let mut in_flight = IN_FLIGHT_NATIVE_HOOK_CALLBACKS
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    while *in_flight != 0 {
        let Some(remaining) = timeout.checked_sub(start.elapsed()) else {
            return false;
        };
        let (guard, wait_result) = IN_FLIGHT_NATIVE_HOOK_CALLBACKS_CV
            .wait_timeout(in_flight, remaining)
            .unwrap_or_else(|e| e.into_inner());
        in_flight = guard;
        if wait_result.timed_out() && *in_flight != 0 {
            return false;
        }
    }
    true
}

pub(super) fn in_flight_native_hook_callbacks() -> usize {
    *IN_FLIGHT_NATIVE_HOOK_CALLBACKS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

pub(crate) type NativeAttachCallback = unsafe extern "C" fn(*mut hook_ffi::HookContext, *mut c_void);

pub(crate) struct NativeAttachCallbacks {
    pub(crate) on_enter: Option<NativeAttachCallback>,
    pub(crate) on_leave: Option<NativeAttachCallback>,
    pub(crate) user_data: *mut c_void,
}

pub(crate) unsafe extern "C" fn native_attach_on_enter_wrapper(
    ctx_ptr: *mut hook_ffi::HookContext,
    user_data: *mut c_void,
) {
    if user_data.is_null() {
        return;
    }
    let callbacks = &*(user_data as *const NativeAttachCallbacks);
    if let Some(on_enter) = callbacks.on_enter {
        on_enter(ctx_ptr, callbacks.user_data);
    }
    if callbacks.on_leave.is_none() && !ctx_ptr.is_null() {
        (*ctx_ptr).intercept_leave = 0;
    }
}

pub(crate) unsafe extern "C" fn native_attach_on_leave_wrapper(
    ctx_ptr: *mut hook_ffi::HookContext,
    user_data: *mut c_void,
) {
    if user_data.is_null() {
        return;
    }
    let callbacks = &*(user_data as *const NativeAttachCallbacks);
    if let Some(on_leave) = callbacks.on_leave {
        on_leave(ctx_ptr, callbacks.user_data);
    }
}

pub(crate) unsafe fn free_native_attach_callbacks(ptr: usize) {
    if ptr != 0 {
        drop(Box::from_raw(ptr as *mut NativeAttachCallbacks));
    }
}

/// Hook callback that calls the JS function (replace mode)
pub(crate) unsafe extern "C" fn hook_callback_wrapper(
    ctx_ptr: *mut hook_ffi::HookContext,
    user_data: *mut std::ffi::c_void,
) {
    if ctx_ptr.is_null() || user_data.is_null() {
        return;
    }
    let _in_flight_guard = InFlightNativeHookGuard::enter();

    let target_addr = user_data as u64;

    // Copy callback data then release the lock before QuickJS operations.
    let (ctx_usize, callback_bytes, trampoline) = {
        let guard = match HOOK_REGISTRY.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        let registry = match guard.as_ref() {
            Some(r) => r,
            None => return,
        };
        let hook_data = match registry.get(&target_addr) {
            Some(d) => d,
            None => return,
        };
        (hook_data.ctx, hook_data.callback_bytes, hook_data.trampoline)
    }; // HOOK_REGISTRY lock released here

    if native_callback_would_reenter_js_engine() {
        if trampoline != 0 {
            (*ctx_ptr).x[0] = hook_ffi::hook_invoke_trampoline(ctx_ptr, trampoline as *mut std::ffi::c_void);
        }
        return;
    }

    push_native_hook_frame(ctx_ptr, trampoline);

    // Track whether the JS callback completed without exception and wrote back x0.
    let mut result_was_set = false;

    invoke_hook_callback_common(
        ctx_usize,
        &callback_bytes,
        "hook",
        target_addr,
        // 构建 JS 上下文对象：x0-x30, sp, pc, trampoline, $orig()
        |ctx| {
            let js_ctx = ffi::JS_NewObject(ctx);
            let hook_ctx = &*ctx_ptr;
            let atoms = hot_atoms();

            for i in 0..31 {
                set_js_u64_property_atom(ctx, js_ctx, atoms.x[i], hook_ctx.x[i]);
            }
            set_js_u64_property_atom(ctx, js_ctx, atoms.sp, hook_ctx.sp);
            set_js_u64_property_atom(ctx, js_ctx, atoms.pc, hook_ctx.pc);
            set_js_u64_property_atom(ctx, js_ctx, atoms.trampoline, trampoline);
            // Bind callback-local state to the context object so ctx.$orig() remains stable
            // even if nested hooks temporarily overwrite the global fallback state.
            set_js_u64_property_atom(ctx, js_ctx, atoms.hook_ctx_ptr, ctx_ptr as usize as u64);
            set_js_u64_property_atom(ctx, js_ctx, atoms.hook_trampoline, trampoline);
            set_js_cfunction_property(ctx, js_ctx, "$orig", js_native_call_original, 0);

            js_ctx
        },
        // 处理返回值：
        // 1. 先同步 JS ctx 上所有被修改的寄存器到 C HookContext
        // 2. 显式 return 值 → 覆盖 x0
        // 3. 不 return（undefined）→ 保持 ctx.x0 的值（可能被 JS 修改或被 $orig() 写入）
        |ctx, js_ctx, result| {
            result_was_set = true;
            // 同步 JS ctx 属性 → C HookContext（用户可能修改了 ctx.x0 等）
            let atoms = hot_atoms();
            for i in 0..31 {
                (*ctx_ptr).x[i] = get_js_u64_property_atom(ctx, js_ctx, atoms.x[i]);
            }
            // 显式 return 值覆盖 x0
            let result_val = ffi::JSValue {
                u: result.u,
                tag: result.tag,
            };
            if ffi::qjs_is_undefined(result_val) == 0 {
                (*ctx_ptr).x[0] = js_value_to_u64_or_zero(ctx, crate::value::JSValue(result_val));
            }
            // undefined 时保持 ctx.x0 (可能是 $orig() 写入的返回值或 JS 修改的值)
        },
        // native hook 不需要 JS 异常内 fallback (外层 trampoline 兜底已够)
        |_ctx, _js_ctx| {},
    );

    let orig_called = pop_native_hook_frame(ctx_ptr, trampoline);

    // Fallback: if the JS callback threw an exception before producing a result,
    // treat the hook as transparent and invoke the original function.
    if !result_was_set && trampoline != 0 && !orig_called {
        (*ctx_ptr).x[0] = hook_ffi::hook_invoke_trampoline(ctx_ptr, trampoline as *mut std::ffi::c_void);
    }
}

/// JS CFunction: ctx.$orig()
///
/// 无参数: 先同步 JS ctx 对象上被修改的寄存器到 C HookContext，再调用 trampoline。
/// 兼容旧脚本的有参数形式: 用传入的参数覆盖 x0-xN，其余寄存器同步自 JS ctx。
/// 新脚本优先写 this.xN 后无参数调用 $orig()；固定继续原函数应使用 attach。
///
/// 返回原函数的返回值 (BigUint64 或 Number)，同时写入 ctx.x[0]。
unsafe extern "C" fn js_native_call_original(
    ctx: *mut ffi::JSContext,
    this_val: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let atoms = hot_atoms();
    let ctx_ptr = {
        let value = get_js_u64_property_atom(ctx, this_val, atoms.hook_ctx_ptr) as *mut hook_ffi::HookContext;
        if !value.is_null() {
            value
        } else {
            current_native_hook_frame()
                .map(|(ctx_ptr, _)| ctx_ptr)
                .unwrap_or(std::ptr::null_mut())
        }
    };
    let trampoline = {
        let value = get_js_u64_property_atom(ctx, this_val, atoms.hook_trampoline);
        if value != 0 {
            value
        } else {
            current_native_hook_frame()
                .map(|(_, trampoline)| trampoline)
                .unwrap_or(0)
        }
    };

    if ctx_ptr.is_null() || trampoline == 0 {
        return ffi::JS_ThrowInternalError(
            ctx,
            b"$orig() can only be called inside a hook callback\0".as_ptr() as *const _,
        );
    }

    // 同步 JS ctx 属性到 C HookContext（用户可能修改了 ctx.x0 等）
    let hook_ctx = &mut *ctx_ptr;
    for i in 0..31 {
        hook_ctx.x[i] = get_js_u64_property_atom(ctx, this_val, atoms.x[i]);
    }
    hook_ctx.sp = get_js_u64_property_atom(ctx, this_val, atoms.sp);

    // 如果 $orig() 传了参数，按顺序覆盖 x0-xN (最多 x0-x30)
    let max_args = (argc as usize).min(31);
    for i in 0..max_args {
        let val = crate::value::JSValue(*argv.add(i));
        hook_ctx.x[i] = js_value_to_u64_or_zero(ctx, val);
    }

    let _ = mark_native_hook_frame_orig_called(ctx_ptr, trampoline);
    let result = hook_ffi::hook_invoke_trampoline(ctx_ptr, trampoline as *mut std::ffi::c_void);

    // Write result back to HookContext.x[0] so the thunk's final RET returns this value
    (*ctx_ptr).x[0] = result;

    // 同步返回值到 JS ctx.x0 属性，使 ctx.$orig() 后读 ctx.x0 能拿到返回值
    set_js_u64_property_atom(ctx, this_val, atoms.x[0], result);

    // Return value: Number (≤2^53) or BigUint64
    js_u64_to_js_number_or_bigint(ctx, result)
}

// ══════════════════════════════════════════════════════════════════════════════
// Attach 模式 (Frida Interceptor.attach)
//
// 每个 target 只安装一个底层 hook，多个 JS listener 在 Rust 中按 attach 顺序分发。
// 每次 invocation 为每个 listener 创建独立 `this`，并保留到对应 onLeave。
// ══════════════════════════════════════════════════════════════════════════════

#[cfg(target_os = "android")]
extern "C" {
    #[link_name = "__errno"]
    fn platform_errno_location() -> *mut i32;
}

#[cfg(all(not(target_os = "android"), target_os = "linux"))]
extern "C" {
    #[link_name = "__errno_location"]
    fn platform_errno_location() -> *mut i32;
}

#[inline]
unsafe fn get_system_error() -> i32 {
    #[cfg(any(target_os = "android", target_os = "linux"))]
    {
        *platform_errno_location()
    }
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    {
        0
    }
}

#[inline]
unsafe fn set_system_error(value: i32) {
    #[cfg(any(target_os = "android", target_os = "linux"))]
    {
        *platform_errno_location() = value;
    }
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    let _ = value;
}

struct SystemErrorGuard {
    value: i32,
}

impl SystemErrorGuard {
    unsafe fn capture() -> Self {
        Self {
            value: get_system_error(),
        }
    }
}

impl Drop for SystemErrorGuard {
    fn drop(&mut self) {
        unsafe {
            set_system_error(self.value);
        }
    }
}

#[derive(Clone, Copy)]
struct OwnedInterceptorListener {
    id: u64,
    has_on_enter: bool,
    has_on_leave: bool,
    on_enter_bytes: [u8; 16],
    on_leave_bytes: [u8; 16],
}

struct InvocationListenerState {
    listener_id: u64,
    this_bytes: [u8; 16],
    on_leave_bytes: [u8; 16],
}

struct InvocationFrame {
    id: u64,
    target: u64,
    ctx: usize,
    listeners: Vec<InvocationListenerState>,
}

thread_local! {
    static INVOCATION_STACK: RefCell<Vec<InvocationFrame>> = const { RefCell::new(Vec::new()) };
    static NEXT_INVOCATION_ID: Cell<u64> = const { Cell::new(1) };
}

fn invocation_begin(target: u64, ctx: usize) -> (u64, u32) {
    let id = NEXT_INVOCATION_ID.with(|next| {
        let id = next.get();
        let candidate = id.wrapping_add(1);
        next.set(if candidate == 0 { 1 } else { candidate });
        id
    });
    INVOCATION_STACK.with(|stack| {
        let mut stack = stack.borrow_mut();
        let depth = stack.len().min(u32::MAX as usize) as u32;
        stack.push(InvocationFrame {
            id,
            target,
            ctx,
            listeners: Vec::new(),
        });
        (id, depth)
    })
}

fn invocation_append(frame_id: u64, listener: InvocationListenerState) -> bool {
    INVOCATION_STACK.with(|stack| {
        let mut stack = stack.borrow_mut();
        let Some(frame) = stack.iter_mut().rev().find(|frame| frame.id == frame_id) else {
            return false;
        };
        frame.listeners.push(listener);
        true
    })
}

/// 完成 enter 阶段。无 onLeave 状态时移除空 frame，并让 thunk 走 tail-jump。
fn invocation_finish_enter(frame_id: u64) -> bool {
    INVOCATION_STACK.with(|stack| {
        let mut stack = stack.borrow_mut();
        let Some(index) = stack.iter().rposition(|frame| frame.id == frame_id) else {
            return false;
        };
        if stack[index].listeners.is_empty() {
            stack.remove(index);
            false
        } else {
            true
        }
    })
}

fn invocation_take(target: u64) -> Option<InvocationFrame> {
    INVOCATION_STACK.with(|stack| {
        let mut stack = stack.borrow_mut();
        let index = if stack.last().is_some_and(|frame| frame.target == target) {
            stack.len() - 1
        } else {
            stack.iter().rposition(|frame| frame.target == target)?
        };
        let frame = &stack[index];
        let marker = InvocationFrame {
            id: frame.id,
            target: frame.target,
            ctx: frame.ctx,
            listeners: Vec::new(),
        };
        Some(std::mem::replace(&mut stack[index], marker))
    })
}

fn invocation_end_leave(frame_id: u64) {
    INVOCATION_STACK.with(|stack| {
        let mut stack = stack.borrow_mut();
        if let Some(index) = stack.iter().rposition(|frame| frame.id == frame_id) {
            stack.remove(index);
        }
    });
}

struct InvocationLeaveGuard {
    frame_id: u64,
}

impl Drop for InvocationLeaveGuard {
    fn drop(&mut self) {
        invocation_end_leave(self.frame_id);
    }
}

#[inline]
unsafe fn js_value_from_bytes(bytes: &[u8; 16]) -> ffi::JSValue {
    std::ptr::read(bytes.as_ptr() as *const ffi::JSValue)
}

#[inline]
fn js_value_to_bytes(value: ffi::JSValue) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    unsafe {
        std::ptr::copy_nonoverlapping(
            &value as *const ffi::JSValue as *const u8,
            bytes.as_mut_ptr(),
            bytes.len(),
        );
    }
    bytes
}

#[inline]
unsafe fn duplicate_stored_js_value(ctx: *mut ffi::JSContext, bytes: &[u8; 16]) -> [u8; 16] {
    dup_callback_to_bytes(ctx, js_value_from_bytes(bytes))
}

#[inline]
unsafe fn free_stored_js_value(ctx: *mut ffi::JSContext, bytes: &[u8; 16]) {
    ffi::qjs_free_value(ctx, js_value_from_bytes(bytes));
}

unsafe fn snapshot_interceptor_listeners(ctx: *mut ffi::JSContext, target: u64) -> Vec<OwnedInterceptorListener> {
    registry::interceptor_listener_snapshot(target)
        .into_iter()
        .filter(|listener| listener.ctx == ctx as usize)
        .map(|listener| OwnedInterceptorListener {
            id: listener.id,
            has_on_enter: listener.has_on_enter,
            has_on_leave: listener.has_on_leave,
            on_enter_bytes: if listener.has_on_enter {
                duplicate_stored_js_value(ctx, &listener.on_enter_bytes)
            } else {
                [0; 16]
            },
            on_leave_bytes: if listener.has_on_leave {
                duplicate_stored_js_value(ctx, &listener.on_leave_bytes)
            } else {
                [0; 16]
            },
        })
        .collect()
}

#[inline]
unsafe fn set_pointer_property(ctx: *mut ffi::JSContext, object: ffi::JSValue, atom: ffi::JSAtom, value: u64) {
    set_js_value_property_atom(ctx, object, atom, create_native_pointer(ctx, value).raw());
}

#[inline]
unsafe fn set_float_property(ctx: *mut ffi::JSContext, object: ffi::JSValue, atom: ffi::JSAtom, value: f64) {
    set_js_value_property_atom(ctx, object, atom, JSValue::float(value).raw());
}

#[inline]
unsafe fn get_u64_like_property(ctx: *mut ffi::JSContext, object: ffi::JSValue, atom: ffi::JSAtom) -> u64 {
    let raw = ffi::qjs_get_property(ctx, object, atom);
    let value = js_value_to_u64_or_zero(ctx, JSValue(raw));
    ffi::qjs_free_value(ctx, raw);
    value
}

#[inline]
unsafe fn get_i32_property(ctx: *mut ffi::JSContext, object: ffi::JSValue, atom: ffi::JSAtom) -> i32 {
    let raw = ffi::qjs_get_property(ctx, object, atom);
    let value = JSValue(raw).to_i64(ctx).unwrap_or(0) as i32;
    ffi::qjs_free_value(ctx, raw);
    value
}

#[inline]
unsafe fn get_float_property(ctx: *mut ffi::JSContext, object: ffi::JSValue, atom: ffi::JSAtom, fallback: f64) -> f64 {
    let raw = ffi::qjs_get_property(ctx, object, atom);
    let value = JSValue(raw).to_float().unwrap_or(fallback);
    ffi::qjs_free_value(ctx, raw);
    value
}

#[inline]
fn current_os_thread_id() -> u64 {
    #[cfg(any(target_os = "android", target_os = "linux"))]
    unsafe {
        return libc::syscall(libc::SYS_gettid) as u64;
    }
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    {
        crate::current_thread_id_u64()
    }
}

unsafe fn refresh_invocation_registers(
    ctx: *mut ffi::JSContext,
    js_ctx: ffi::JSValue,
    hook_ctx_ptr: *mut hook_ffi::HookContext,
    system_error: i32,
) {
    let hook_ctx = &*hook_ctx_ptr;
    let atoms = hot_atoms();
    for i in 0..31 {
        set_pointer_property(ctx, js_ctx, atoms.x[i], hook_ctx.x[i]);
    }
    for i in 0..8 {
        set_float_property(ctx, js_ctx, atoms.d[i], f64::from_bits(hook_ctx.d[i]));
    }
    set_pointer_property(ctx, js_ctx, atoms.sp, hook_ctx.sp);
    set_pointer_property(ctx, js_ctx, atoms.pc, hook_ctx.pc);
    set_pointer_property(ctx, js_ctx, atoms.fp, hook_ctx.x[29]);
    set_pointer_property(ctx, js_ctx, atoms.lr, hook_ctx.x[30]);
    set_js_u64_property_atom(ctx, js_ctx, atoms.nzcv, hook_ctx.nzcv);
    set_js_value_property_atom(ctx, js_ctx, atoms.errno, ffi::qjs_new_int64(ctx, system_error as i64));
}

/// 构造 Frida 风格 invocation context。
/// `context` 指向同一对象，使标准 `this.context.x0` 与旧有 `this.x0` 同时可用。
unsafe fn build_invocation_ctx(
    ctx: *mut ffi::JSContext,
    hook_ctx_ptr: *mut hook_ffi::HookContext,
    depth: u32,
    system_error: i32,
) -> ffi::JSValue {
    let js_ctx = ffi::JS_NewObject(ctx);
    let hook_ctx = &*hook_ctx_ptr;
    let atoms = hot_atoms();
    refresh_invocation_registers(ctx, js_ctx, hook_ctx_ptr, system_error);
    set_pointer_property(ctx, js_ctx, atoms.return_address, hook_ctx.x[30]);
    set_js_value_property_atom(ctx, js_ctx, atoms.context, ffi::qjs_dup_value(ctx, js_ctx));
    set_js_u64_property_atom(ctx, js_ctx, atoms.thread_id, current_os_thread_id());
    set_js_u64_property_atom(ctx, js_ctx, atoms.depth, depth as u64);
    set_js_u64_property_atom(ctx, js_ctx, atoms.hook_ctx_ptr, hook_ctx_ptr as usize as u64);
    js_ctx
}

/// 把可写 CPU context 同步回 C HookContext。
unsafe fn sync_js_ctx_to_hook_ctx(
    ctx: *mut ffi::JSContext,
    js_ctx: ffi::JSValue,
    hook_ctx_ptr: *mut hook_ffi::HookContext,
) {
    let hook_ctx = &mut *hook_ctx_ptr;
    let atoms = hot_atoms();
    for i in 0..29 {
        hook_ctx.x[i] = get_u64_like_property(ctx, js_ctx, atoms.x[i]);
    }
    hook_ctx.x[29] = get_u64_like_property(ctx, js_ctx, atoms.fp);
    hook_ctx.x[30] = get_u64_like_property(ctx, js_ctx, atoms.lr);
    hook_ctx.sp = get_u64_like_property(ctx, js_ctx, atoms.sp);
    hook_ctx.pc = get_u64_like_property(ctx, js_ctx, atoms.pc);
    hook_ctx.nzcv = get_u64_like_property(ctx, js_ctx, atoms.nzcv);
    for i in 0..8 {
        let current = f64::from_bits(hook_ctx.d[i]);
        hook_ctx.d[i] = get_float_property(ctx, js_ctx, atoms.d[i], current).to_bits();
    }
}

/// 调用 JS 全局 helper `helper_name(userFn, js_ctx)`。
/// helper 由 interceptor_boot.js 提供（args/retval proxy 包装）。
/// helper 不存在时降级直接调 userFn(js_ctx)。
unsafe fn call_interceptor_helper(
    ctx: *mut ffi::JSContext,
    user_bytes: &[u8; 16],
    js_ctx: ffi::JSValue,
    helper_name: &[u8], // 必须带末尾 \0
    log_tag: &str,
) {
    let user_fn: ffi::JSValue = std::ptr::read(user_bytes.as_ptr() as *const ffi::JSValue);
    let user_dup = ffi::qjs_dup_value(ctx, user_fn);
    let global = ffi::JS_GetGlobalObject(ctx);
    let helper = ffi::JS_GetPropertyStr(ctx, global, helper_name.as_ptr() as *const _);
    let result = if ffi::JS_IsFunction(ctx, helper) != 0 {
        let mut args = [user_dup, js_ctx];
        ffi::JS_Call(ctx, helper, global, 2, args.as_mut_ptr())
    } else {
        let mut args = [js_ctx];
        ffi::JS_Call(ctx, user_dup, global, 1, args.as_mut_ptr())
    };
    let _ = handle_js_exception(ctx, result, log_tag);
    ffi::qjs_free_value(ctx, result);
    ffi::qjs_free_value(ctx, helper);
    ffi::qjs_free_value(ctx, global);
    ffi::qjs_free_value(ctx, user_dup);
}

/// 地址级 onEnter 分发器。listener 回调在调用前全部 Dup，允许回调内部安全 detach。
pub(crate) unsafe extern "C" fn attach_on_enter_wrapper(
    ctx_ptr: *mut hook_ffi::HookContext,
    user_data: *mut std::ffi::c_void,
) {
    let mut system_error = SystemErrorGuard::capture();
    if ctx_ptr.is_null() || user_data.is_null() {
        return;
    }
    (*ctx_ptr).intercept_leave = 0;
    let _in_flight_guard = InFlightNativeHookGuard::enter();

    let target_addr = user_data as u64;

    let ctx_usize = {
        let guard = match HOOK_REGISTRY.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        let registry = match guard.as_ref() {
            Some(r) => r,
            None => return,
        };
        let data = match registry.get(&target_addr) {
            Some(data) if data.kind == HookKind::Interceptor => data,
            None => return,
            Some(_) => return,
        };
        data.ctx
    };

    let ctx = ctx_usize as *mut ffi::JSContext;
    let _js_guard = match acquire_js_engine_for_callback(ctx, "interceptor.onEnter", target_addr) {
        Some(g) => g,
        None => return,
    };

    let listeners = snapshot_interceptor_listeners(ctx, target_addr);
    let (frame_id, depth) = invocation_begin(target_addr, ctx_usize);

    for listener in listeners {
        if !registry::interceptor_listener_is_active(target_addr, listener.id) {
            if listener.has_on_enter {
                free_stored_js_value(ctx, &listener.on_enter_bytes);
            }
            if listener.has_on_leave {
                free_stored_js_value(ctx, &listener.on_leave_bytes);
            }
            continue;
        }

        let js_ctx = build_invocation_ctx(ctx, ctx_ptr, depth, system_error.value);
        if listener.has_on_enter {
            call_interceptor_helper(
                ctx,
                &listener.on_enter_bytes,
                js_ctx,
                b"__interceptorEnter\0",
                "interceptor.onEnter",
            );
            free_stored_js_value(ctx, &listener.on_enter_bytes);
        }

        sync_js_ctx_to_hook_ctx(ctx, js_ctx, ctx_ptr);
        system_error.value = get_i32_property(ctx, js_ctx, hot_atoms().errno);

        if listener.has_on_leave && registry::interceptor_listener_is_active(target_addr, listener.id) {
            let state = InvocationListenerState {
                listener_id: listener.id,
                this_bytes: js_value_to_bytes(js_ctx),
                on_leave_bytes: listener.on_leave_bytes,
            };
            if !invocation_append(frame_id, state) {
                free_stored_js_value(ctx, &listener.on_leave_bytes);
                ffi::qjs_free_value(ctx, js_ctx);
            }
        } else {
            if listener.has_on_leave {
                free_stored_js_value(ctx, &listener.on_leave_bytes);
            }
            ffi::qjs_free_value(ctx, js_ctx);
        }
    }

    if invocation_finish_enter(frame_id) {
        (*ctx_ptr).intercept_leave = 1;
    }
}

/// 地址级 onLeave 分发器。只调用进入时存在且离开时仍处于 attached 状态的 listener。
pub(crate) unsafe extern "C" fn attach_on_leave_wrapper(
    ctx_ptr: *mut hook_ffi::HookContext,
    user_data: *mut std::ffi::c_void,
) {
    let mut system_error = SystemErrorGuard::capture();
    if ctx_ptr.is_null() || user_data.is_null() {
        return;
    }
    let _in_flight_guard = InFlightNativeHookGuard::enter();

    let target_addr = user_data as u64;
    let Some(frame) = invocation_take(target_addr) else {
        return;
    };
    let _leave_guard = InvocationLeaveGuard { frame_id: frame.id };
    let ctx = frame.ctx as *mut ffi::JSContext;
    let _js_guard = match acquire_js_engine_for_callback(ctx, "interceptor.onLeave", target_addr) {
        Some(g) => g,
        // JS engine 已销毁时不能再触碰旧 JSValue；让原始字节随 frame 泄漏到进程退出。
        None => return,
    };

    for listener in frame.listeners {
        let js_ctx = js_value_from_bytes(&listener.this_bytes);
        if registry::interceptor_listener_is_active(frame.target, listener.listener_id) {
            refresh_invocation_registers(ctx, js_ctx, ctx_ptr, system_error.value);
            call_interceptor_helper(
                ctx,
                &listener.on_leave_bytes,
                js_ctx,
                b"__interceptorLeave\0",
                "interceptor.onLeave",
            );
            sync_js_ctx_to_hook_ctx(ctx, js_ctx, ctx_ptr);
            system_error.value = get_i32_property(ctx, js_ctx, hot_atoms().errno);
        }
        free_stored_js_value(ctx, &listener.on_leave_bytes);
        ffi::qjs_free_value(ctx, js_ctx);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invocation_stack_tracks_nested_depth_and_target() {
        let (outer_id, outer_depth) = invocation_begin(0x1000, 1);
        assert_eq!(outer_depth, 0);
        assert!(invocation_append(
            outer_id,
            InvocationListenerState {
                listener_id: 11,
                this_bytes: [0; 16],
                on_leave_bytes: [0; 16],
            }
        ));

        let (_inner_id, inner_depth) = invocation_begin(0x2000, 1);
        assert_eq!(inner_depth, 1);
        let inner = invocation_take(0x2000).expect("inner invocation");
        assert_eq!(inner.target, 0x2000);
        let (leave_nested_id, leave_nested_depth) = invocation_begin(0x3000, 1);
        assert_eq!(leave_nested_depth, 2);
        assert!(!invocation_finish_enter(leave_nested_id));
        invocation_end_leave(inner.id);

        let outer = invocation_take(0x1000).expect("outer invocation");
        assert_eq!(outer.listeners.len(), 1);
        assert_eq!(outer.listeners[0].listener_id, 11);
        invocation_end_leave(outer.id);
        assert!(invocation_take(0x1000).is_none());
    }
}
