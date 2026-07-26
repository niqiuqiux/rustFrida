//! Shared callback utilities for hook and java hook callbacks
//!
//! Contains: JS engine lock acquisition, JS exception handling,
//! and registry initialization helpers.

use crate::ffi;
use crate::jsapi::console::output_message;
use crate::jsapi::ptr::get_native_pointer_addr;
use crate::jsapi::util::JSCFn;
use crate::value::JSValue;
use crate::JSEngine;
use std::cell::UnsafeCell;
use std::ffi::CString;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::MutexGuard;

const JS_MAX_SAFE_INTEGER: u64 = 1u64 << 53;

// ──────────────────────────────────────────────────────────────────────────
// 热路径 atom 缓存
//
// 每次 hook callback 原本要为 x0..x30 + sp/pc/lr/returnAddress/trampoline/
// __hookCtxPtr/__hookTrampoline 共 ~37 个属性名反复 CString::new + JS_NewAtom +
// JS_FreeAtom，在高频 hook 下制造大量 Rust 堆 / QuickJS atom 表抖动。
//
// 这里在 JSEngine 构造时一次性 `JS_NewAtom` 全部热点名字，跨线程以 JS_ENGINE
// Mutex 为串行点 (hot path 永远在持锁期间读取)。JSRuntime 销毁前 (JSEngine::drop)
// 显式 JS_FreeAtom 归还引用。
//
// 字段布局固定，callback 直接按下标取，无哈希/查表开销。
// ──────────────────────────────────────────────────────────────────────────

#[repr(C)]
pub(crate) struct HotAtoms {
    // ─── native hook (replace + attach) ──────────────────────────
    pub x: [ffi::JSAtom; 31],
    pub d: [ffi::JSAtom; 8],
    pub sp: ffi::JSAtom,
    pub pc: ffi::JSAtom,
    pub fp: ffi::JSAtom,
    pub lr: ffi::JSAtom,
    pub nzcv: ffi::JSAtom,
    pub return_address: ffi::JSAtom,
    pub context: ffi::JSAtom,
    pub errno: ffi::JSAtom,
    pub thread_id: ffi::JSAtom,
    pub depth: ffi::JSAtom,
    pub trampoline: ffi::JSAtom,
    pub hook_ctx_ptr: ffi::JSAtom,
    pub hook_trampoline: ffi::JSAtom,
    // ─── java hook ───────────────────────────────────────────────
    pub this_obj: ffi::JSAtom,
    pub env: ffi::JSAtom,
    pub hook_art_method: ffi::JSAtom,
    pub args: ffi::JSAtom,
    pub orig_jobject: ffi::JSAtom,
    pub jptr: ffi::JSAtom,
    // ─── Stalker transform ────────────────────────────────────────
    pub stalker_dispatch_transform: ffi::JSAtom,
    pub stalker_dispatch_callout: ffi::JSAtom,
}

impl HotAtoms {
    const fn zeros() -> Self {
        Self {
            x: [0; 31],
            d: [0; 8],
            sp: 0,
            pc: 0,
            fp: 0,
            lr: 0,
            nzcv: 0,
            return_address: 0,
            context: 0,
            errno: 0,
            thread_id: 0,
            depth: 0,
            trampoline: 0,
            hook_ctx_ptr: 0,
            hook_trampoline: 0,
            this_obj: 0,
            env: 0,
            hook_art_method: 0,
            args: 0,
            orig_jobject: 0,
            jptr: 0,
            stalker_dispatch_transform: 0,
            stalker_dispatch_callout: 0,
        }
    }
}

pub(crate) struct HotAtomsCell(UnsafeCell<HotAtoms>);
// Safety: 变更只发生在 init_hot_atoms / free_hot_atoms（都在 JS_ENGINE 锁下调用）,
// hot path 读取也必然在 JS_ENGINE 锁下。
unsafe impl Sync for HotAtomsCell {}

/// Serializes the agent's own background threads before they reach for the
/// JavaScript engine.
///
/// Hook, Stalker and Java callbacks run on threads the target already owns, and
/// the engine lock alone is enough for them. Two agent-created threads racing
/// for it — the timer pump and an async scan — is a different case and has
/// proven unsafe in practice, so they queue here first.
pub(crate) static BACKGROUND_JS_GATE: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub(crate) static HOT_ATOMS: HotAtomsCell = HotAtomsCell(UnsafeCell::new(HotAtoms::zeros()));
pub(crate) static HOT_ATOMS_READY: AtomicBool = AtomicBool::new(false);

unsafe fn new_atom_cstr(ctx: *mut ffi::JSContext, name: &str) -> ffi::JSAtom {
    let c = CString::new(name).unwrap();
    ffi::JS_NewAtom(ctx, c.as_ptr())
}

/// 初始化热路径 atom 缓存。调用方必须持有 JS_ENGINE 锁并提供合法 ctx。
/// 幂等：已初始化时直接返回。
pub(crate) unsafe fn init_hot_atoms(ctx: *mut ffi::JSContext) {
    if HOT_ATOMS_READY.load(Ordering::Acquire) {
        return;
    }
    let atoms = &mut *HOT_ATOMS.0.get();
    for i in 0..31 {
        atoms.x[i] = new_atom_cstr(ctx, &format!("x{}", i));
    }
    for i in 0..8 {
        atoms.d[i] = new_atom_cstr(ctx, &format!("d{}", i));
    }
    atoms.sp = new_atom_cstr(ctx, "sp");
    atoms.pc = new_atom_cstr(ctx, "pc");
    atoms.fp = new_atom_cstr(ctx, "fp");
    atoms.lr = new_atom_cstr(ctx, "lr");
    atoms.nzcv = new_atom_cstr(ctx, "nzcv");
    atoms.return_address = new_atom_cstr(ctx, "returnAddress");
    atoms.context = new_atom_cstr(ctx, "context");
    atoms.errno = new_atom_cstr(ctx, "errno");
    atoms.thread_id = new_atom_cstr(ctx, "threadId");
    atoms.depth = new_atom_cstr(ctx, "depth");
    atoms.trampoline = new_atom_cstr(ctx, "trampoline");
    atoms.hook_ctx_ptr = new_atom_cstr(ctx, "__hookCtxPtr");
    atoms.hook_trampoline = new_atom_cstr(ctx, "__hookTrampoline");
    atoms.this_obj = new_atom_cstr(ctx, "thisObj");
    atoms.env = new_atom_cstr(ctx, "env");
    atoms.hook_art_method = new_atom_cstr(ctx, "__hookArtMethod");
    atoms.args = new_atom_cstr(ctx, "args");
    atoms.orig_jobject = new_atom_cstr(ctx, "__origJobject");
    atoms.jptr = new_atom_cstr(ctx, "__jptr");
    atoms.stalker_dispatch_transform = new_atom_cstr(ctx, "__rf_stalker_dispatch_transform");
    atoms.stalker_dispatch_callout = new_atom_cstr(ctx, "__rf_stalker_dispatch_callout");
    HOT_ATOMS_READY.store(true, Ordering::Release);
}

/// 释放热路径 atom。必须在 JSContext 仍有效时调用 (JSEngine::drop 里, context 字段 drop 之前)。
/// 幂等。
pub(crate) unsafe fn free_hot_atoms(ctx: *mut ffi::JSContext) {
    if !HOT_ATOMS_READY.swap(false, Ordering::AcqRel) {
        return;
    }
    let atoms = &mut *HOT_ATOMS.0.get();
    for i in 0..31 {
        if atoms.x[i] != 0 {
            ffi::JS_FreeAtom(ctx, atoms.x[i]);
            atoms.x[i] = 0;
        }
    }
    for i in 0..8 {
        if atoms.d[i] != 0 {
            ffi::JS_FreeAtom(ctx, atoms.d[i]);
            atoms.d[i] = 0;
        }
    }
    macro_rules! free_field {
        ($($f:ident),+ $(,)?) => {
            $(
                if atoms.$f != 0 {
                    ffi::JS_FreeAtom(ctx, atoms.$f);
                    atoms.$f = 0;
                }
            )+
        };
    }
    free_field!(
        sp,
        pc,
        fp,
        lr,
        nzcv,
        return_address,
        context,
        errno,
        thread_id,
        depth,
        trampoline,
        hook_ctx_ptr,
        hook_trampoline,
        this_obj,
        env,
        hook_art_method,
        args,
        orig_jobject,
        jptr,
        stalker_dispatch_transform,
        stalker_dispatch_callout,
    );
}

/// 读取热路径 atom 缓存。调用方必须持有 JS_ENGINE 锁。
#[inline]
pub(crate) unsafe fn hot_atoms() -> &'static HotAtoms {
    debug_assert!(HOT_ATOMS_READY.load(Ordering::Relaxed), "hot atoms not initialized");
    &*HOT_ATOMS.0.get()
}

pub(crate) enum JsEngineCallbackGuard {
    Locked {
        _guard: MutexGuard<'static, Option<JSEngine>>,
    },
    Reentrant,
    Cooperative {
        _guard: MutexGuard<'static, ()>,
        previous_owner: u64,
    },
}

impl Drop for JsEngineCallbackGuard {
    fn drop(&mut self) {
        match self {
            JsEngineCallbackGuard::Locked { .. } => crate::clear_js_engine_owner_current_thread(),
            JsEngineCallbackGuard::Cooperative { previous_owner, .. } => {
                crate::leave_cooperative_js_callback();
                crate::JS_ENGINE_OWNER_THREAD.store(*previous_owner, Ordering::Release);
            }
            JsEngineCallbackGuard::Reentrant => {}
        }
    }
}

/// Acquire JS_ENGINE lock for a hook callback.
///
/// Same-thread reentrant callbacks reuse the current JS engine owner context.
/// Other threads block until the global JS engine is available. JS callbacks are
/// not a high-frequency path; if a user installs one, it must run instead of
/// being silently bypassed.
pub(crate) unsafe fn acquire_js_engine_for_callback(
    ctx: *mut ffi::JSContext,
    _context_name: &str,
    _target_id: u64,
) -> Option<JsEngineCallbackGuard> {
    let current_thread = crate::current_thread_id_u64();

    if crate::JS_ENGINE_OWNER_THREAD.load(std::sync::atomic::Ordering::Acquire) == current_thread {
        ffi::qjs_update_stack_top(ctx);
        return Some(JsEngineCallbackGuard::Reentrant);
    }

    if crate::COOPERATIVE_JS_OWNER_THREAD.load(Ordering::Acquire) != 0 {
        let guard = crate::COOPERATIVE_JS_GATE
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if crate::COOPERATIVE_JS_OWNER_THREAD.load(Ordering::Acquire) != 0 {
            let previous_owner = crate::JS_ENGINE_OWNER_THREAD.swap(current_thread, Ordering::AcqRel);
            crate::enter_cooperative_js_callback();
            ffi::qjs_update_stack_top(ctx);
            return Some(JsEngineCallbackGuard::Cooperative {
                _guard: guard,
                previous_owner,
            });
        }
        drop(guard);
    }

    let g = match crate::JS_ENGINE.lock() {
        Ok(g) => g,
        Err(e) => e.into_inner(),
    };
    crate::mark_js_engine_owner_current_thread();
    ffi::qjs_update_stack_top(ctx);
    Some(JsEngineCallbackGuard::Locked { _guard: g })
}

/// Check for JS exception, extract message + stack, and output error.
///
/// Returns true if an exception was found (caller should do cleanup and return).
/// 输出格式: `[{ctx} error] {message}\n{stack}` — stack 含 QuickJS 行号/函数名, 便于定位。
/// Handles secondary exceptions from toString gracefully.
pub(crate) unsafe fn handle_js_exception(ctx: *mut ffi::JSContext, result: ffi::JSValue, context_name: &str) -> bool {
    if ffi::qjs_is_exception(result) == 0 {
        return false;
    }
    let exc = ffi::JS_GetException(ctx);
    let exc_val = JSValue(exc);

    // message: Error.prototype.message 或 fallback 到 exception 本身 toString
    let msg_prop = exc_val.get_property(ctx, "message");
    let msg = if let Some(s) = msg_prop.to_string(ctx) {
        msg_prop.free(ctx);
        s
    } else {
        msg_prop.free(ctx);
        let fallback = exc_val
            .to_string(ctx)
            .unwrap_or_else(|| "[unknown exception]".to_string());
        // 吞掉 toString 可能抛出的二级异常
        let secondary = ffi::JS_GetException(ctx);
        let secondary_val = JSValue(secondary);
        if !secondary_val.is_null() && !secondary_val.is_undefined() {
            secondary_val.free(ctx);
        }
        fallback
    };

    // stack: QuickJS 在 Error 对象上自动生成, 含 "<anonymous>@<file>:<line>" 每一帧
    let stack_prop = exc_val.get_property(ctx, "stack");
    let stack = stack_prop.to_string(ctx).filter(|s| !s.is_empty());
    stack_prop.free(ctx);

    match stack {
        Some(s) => output_message(&format!("[{} error] {}\n{}", context_name, msg, s.trim_end())),
        None => output_message(&format!("[{} error] {}", context_name, msg)),
    }
    exc_val.free(ctx);
    true
}

/// Initialize a Mutex<Option<HashMap>> registry if not already initialized (idempotent).
pub(crate) fn ensure_registry_initialized<K: std::hash::Hash + Eq, V>(
    registry: &std::sync::Mutex<Option<std::collections::HashMap<K, V>>>,
) {
    let mut guard = registry.lock().unwrap_or_else(|e| e.into_inner());
    if guard.is_none() {
        *guard = Some(std::collections::HashMap::new());
    }
}

/// Acquire registry lock and call f with immutable reference to the HashMap.
/// Returns None if the registry is not initialized.
pub(crate) fn with_registry<K, V, R>(
    registry: &std::sync::Mutex<Option<std::collections::HashMap<K, V>>>,
    f: impl FnOnce(&std::collections::HashMap<K, V>) -> R,
) -> Option<R>
where
    K: std::hash::Hash + Eq,
{
    let guard = registry.lock().unwrap_or_else(|e| e.into_inner());
    guard.as_ref().map(f)
}

/// Acquire registry lock and call f with mutable reference to the HashMap.
/// Returns None if the registry is not initialized.
pub(crate) fn with_registry_mut<K, V, R>(
    registry: &std::sync::Mutex<Option<std::collections::HashMap<K, V>>>,
    f: impl FnOnce(&mut std::collections::HashMap<K, V>) -> R,
) -> Option<R>
where
    K: std::hash::Hash + Eq,
{
    let mut guard = registry.lock().unwrap_or_else(|e| e.into_inner());
    guard.as_mut().map(f)
}

/// Bidirectional map backed by two Mutex<Option<HashMap<u64, u64>>>.
/// Provides synchronized forward and reverse lookups.
pub(crate) struct BiMap {
    forward: std::sync::Mutex<Option<std::collections::HashMap<u64, u64>>>,
    reverse: std::sync::Mutex<Option<std::collections::HashMap<u64, u64>>>,
}

impl BiMap {
    pub(crate) const fn new() -> Self {
        Self {
            forward: std::sync::Mutex::new(None),
            reverse: std::sync::Mutex::new(None),
        }
    }

    /// 初始化双向映射（幂等）
    pub(crate) fn init(&self) {
        ensure_registry_initialized(&self.forward);
        ensure_registry_initialized(&self.reverse);
    }

    /// 插入 forward(left → right) + reverse(right → left)
    pub(crate) fn insert(&self, left: u64, right: u64) {
        with_registry_mut(&self.forward, |map| {
            map.insert(left, right);
        });
        with_registry_mut(&self.reverse, |map| {
            map.insert(right, left);
        });
    }

    /// 通过 forward key 查找 value
    pub(crate) fn get_forward(&self, left: u64) -> Option<u64> {
        with_registry(&self.forward, |map| map.get(&left).copied()).flatten()
    }

    /// 通过 reverse key 查找是否存在
    pub(crate) fn contains_reverse(&self, right: u64) -> bool {
        with_registry(&self.reverse, |map| map.contains_key(&right)).unwrap_or(false)
    }

    /// 删除 forward(left) 及对应的 reverse 条目，返回被删除的 right 值
    pub(crate) fn remove_by_forward(&self, left: u64) -> Option<u64> {
        let right = with_registry_mut(&self.forward, |map| map.remove(&left)).flatten();
        if let Some(r) = right {
            with_registry_mut(&self.reverse, |map| {
                map.remove(&r);
            });
        }
        right
    }
}

/// Extract a u64 address from a JSValue that is either a NativePointer or a numeric value.
///
/// Returns Ok(addr) on success, Err(js_exception) on failure (exception already thrown).
pub(crate) unsafe fn extract_pointer_address(
    ctx: *mut ffi::JSContext,
    arg: JSValue,
    func_name: &str,
) -> Result<u64, ffi::JSValue> {
    if let Some(a) = get_native_pointer_addr(ctx, arg) {
        return Ok(a);
    }
    if let Some(a) = arg.to_u64(ctx) {
        return Ok(a);
    }
    let msg = std::ffi::CString::new(format!("{}() argument must be a pointer", func_name)).unwrap_or_default();
    Err(ffi::JS_ThrowTypeError(ctx, msg.as_ptr()))
}

/// Extract a string argument from JSValue.
pub(crate) unsafe fn extract_string_arg(
    ctx: *mut ffi::JSContext,
    arg: JSValue,
    error_msg: &[u8],
) -> Result<String, ffi::JSValue> {
    arg.to_string(ctx)
        .ok_or_else(|| ffi::JS_ThrowTypeError(ctx, error_msg.as_ptr() as *const _))
}

/// Ensure a JSValue is a function.
pub(crate) unsafe fn ensure_function_arg(
    ctx: *mut ffi::JSContext,
    arg: JSValue,
    error_msg: &[u8],
) -> Result<(), ffi::JSValue> {
    if arg.is_function(ctx) {
        Ok(())
    } else {
        Err(ffi::JS_ThrowTypeError(ctx, error_msg.as_ptr() as *const _))
    }
}

/// Throw a type error from a static byte string.
pub(crate) unsafe fn throw_type_error(ctx: *mut ffi::JSContext, error_msg: &[u8]) -> ffi::JSValue {
    // error_msg 是 &[u8] 常量短字符串（不超 256 字节），继续用内置路径
    ffi::JS_ThrowTypeError(ctx, error_msg.as_ptr() as *const _)
}

/// Throw an internal error from an owned Rust string.
///
/// 绕开 QuickJS `JS_ThrowInternalError` 内部 `char buf[256]` + vsnprintf 的双重坑:
///   1. 256 字节硬截断 (Java 异常 + cause 链容易超过)
///   2. 消息被当 printf 格式字符串 (含 % 会被误解析/崩溃)
///
/// 使用 `qjs_throw_error_with_message` 直接 `new InternalError(msg)` 走 JS 构造器路径，
/// 消息长度无限制，`%` 原样保留。
pub(crate) unsafe fn throw_internal_error(ctx: *mut ffi::JSContext, message: impl AsRef<str>) -> ffi::JSValue {
    let msg = message.as_ref();
    let bytes = msg.as_bytes();
    let class_name = b"InternalError\0";
    ffi::qjs_throw_error_with_message(
        ctx,
        class_name.as_ptr() as *const std::os::raw::c_char,
        bytes.as_ptr() as *const std::os::raw::c_char,
        bytes.len(),
    )
}

/// Set a u64 property on a JS object. Uses Number for values ≤ 2^53, BigUint64 otherwise.
///
/// 封装 CString → JS_NewAtom → (Number | BigUint64) → qjs_set_property → JS_FreeAtom。
/// 热路径应直接用 `set_js_u64_property_atom` 跳过 CString / atom 分配。
pub(crate) unsafe fn set_js_u64_property(ctx: *mut ffi::JSContext, obj: ffi::JSValue, name: &str, value: u64) {
    let cname = std::ffi::CString::new(name).unwrap();
    let atom = ffi::JS_NewAtom(ctx, cname.as_ptr());
    let val = js_u64_to_js_number_or_bigint(ctx, value);
    ffi::qjs_set_property(ctx, obj, atom, val);
    ffi::JS_FreeAtom(ctx, atom);
}

/// Atom 版 u64 属性写入：直接用预缓存 atom，不做 CString/atom 分配，值走 Number-or-BigInt。
#[inline]
pub(crate) unsafe fn set_js_u64_property_atom(
    ctx: *mut ffi::JSContext,
    obj: ffi::JSValue,
    atom: ffi::JSAtom,
    value: u64,
) {
    let val = js_u64_to_js_number_or_bigint(ctx, value);
    ffi::qjs_set_property(ctx, obj, atom, val);
}

/// Atom 版通用属性写入：调用方已构造好 value，跳过 CString/atom 分配。
///
/// qjs_set_property 接管 value 的引用计数（成功时消耗，失败时也会 free），
/// 语义与 JSValue::set_property 一致。
#[inline]
pub(crate) unsafe fn set_js_value_property_atom(
    ctx: *mut ffi::JSContext,
    obj: ffi::JSValue,
    atom: ffi::JSAtom,
    value: ffi::JSValue,
) {
    ffi::qjs_set_property(ctx, obj, atom, value);
}

/// Set a CFunction property on a JS object.
pub(crate) unsafe fn set_js_cfunction_property(
    ctx: *mut ffi::JSContext,
    obj: ffi::JSValue,
    name: &str,
    func: JSCFn,
    argc: i32,
) {
    let cname = CString::new(name).unwrap();
    let func_val = ffi::qjs_new_cfunction(ctx, Some(func), cname.as_ptr(), argc);
    JSValue(obj).set_property(ctx, name, JSValue(func_val));
}

/// Read a u64-like property from a JS object. Non-numeric values fall back to 0.
pub(crate) unsafe fn get_js_u64_property(ctx: *mut ffi::JSContext, obj: ffi::JSValue, name: &str) -> u64 {
    let prop = JSValue(obj).get_property(ctx, name);
    let value = prop.to_u64(ctx).unwrap_or(0);
    prop.free(ctx);
    value
}

/// Atom 版 u64 属性读取：绕开 CString / atom 临时分配。
#[inline]
pub(crate) unsafe fn get_js_u64_property_atom(ctx: *mut ffi::JSContext, obj: ffi::JSValue, atom: ffi::JSAtom) -> u64 {
    let prop = ffi::qjs_get_property(ctx, obj, atom);
    let jv = JSValue(prop);
    let value = jv.to_u64(ctx).unwrap_or(0);
    jv.free(ctx);
    value
}

/// Convert a JS numeric/BigInt value to u64, defaulting to 0 on conversion failure.
pub(crate) unsafe fn js_value_to_u64_or_zero(ctx: *mut ffi::JSContext, value: JSValue) -> u64 {
    get_native_pointer_addr(ctx, value)
        .or_else(|| value.to_u64(ctx))
        .unwrap_or(0)
}

/// Encode a u64 as Number when it fits JS safe integer range, otherwise BigUint64.
pub(crate) unsafe fn js_u64_to_js_number_or_bigint(ctx: *mut ffi::JSContext, value: u64) -> ffi::JSValue {
    if value <= JS_MAX_SAFE_INTEGER {
        ffi::qjs_new_int64(ctx, value as i64)
    } else {
        ffi::JS_NewBigUint64(ctx, value)
    }
}

/// Encode an i64 as Number when it fits JS safe integer range, otherwise BigInt64.
pub(crate) unsafe fn js_i64_to_js_number_or_bigint(ctx: *mut ffi::JSContext, value: i64) -> ffi::JSValue {
    if value.unsigned_abs() <= JS_MAX_SAFE_INTEGER {
        ffi::qjs_new_int64(ctx, value)
    } else {
        ffi::JS_NewBigInt64(ctx, value)
    }
}

/// Duplicate a JS callback value and return its raw bytes for Send/Sync-safe storage.
///
/// The caller is responsible for eventually freeing the duplicated value via qjs_free_value.
pub(crate) unsafe fn dup_callback_to_bytes(ctx: *mut ffi::JSContext, callback: ffi::JSValue) -> [u8; 16] {
    let callback_dup = ffi::qjs_dup_value(ctx, callback);
    let mut bytes = [0u8; 16];
    std::ptr::copy_nonoverlapping(
        &callback_dup as *const ffi::JSValue as *const u8,
        bytes.as_mut_ptr(),
        16,
    );
    bytes
}

/// 统一的 hook 回调骨架：获取 JS 锁 → 提取 callback → 构建上下文对象 → JS_Call → 异常处理 → 清理。
///
/// 将 native hook 和 Java hook 回调的公共流程提取为一个函数。
/// 调用方负责：锁 registry 复制数据、设置/清除 atomics。
///
/// - `ctx_raw`: QuickJS context 指针（usize）
/// - `callback_bytes`: 16 字节 JS callback value（由 dup_callback_to_bytes 生成）
/// - `context_name`: 日志标识（"hook" / "java hook"）
/// - `target_id`: 目标地址（用于日志）
/// - `build_context`: 闭包，构建传给 JS 回调的上下文对象（返回 JSValue）
/// - `handle_result`: 闭包，处理 JS 回调返回值（仅无异常时调用）；
///   参数为 (ctx, js_ctx_obj, call_result)，可同时访问上下文对象和调用结果
/// - `on_js_exception`: 闭包，JS 抛异常时在 **JS_ENGINE 锁仍持有、QuickJS stack_top
///   仍有效** 的上下文里调用。用于需要"与 ctx.orig() 同等 ART 可见状态"的 fallback。
///   传 `|| {}` 跳过。
///
/// 返回值: `true` 表示 JS 回调抛异常（handle_result 未被调用），`false` 表示正常执行。
/// JS 执行期间 ART suspend 检查点。
///
/// QuickJS interrupt handler 周期性调用此函数。通过 ExceptionCheck JNI 调用
/// 触发 kNative→kRunnable→kNative 转换，让 ART 处理 pending suspend/checkpoint 请求。
/// 解决 JS_Call 长时间 kNative → SuspendThreadByPeer 超时 → SIGABRT。
pub(crate) static ART_CHECKPOINT_ENV: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// QuickJS interrupt handler — 注册到 JS_SetInterruptHandler。
/// QuickJS 每执行一定数量的操作码后调用一次（默认 ~255 条指令）。
pub(crate) unsafe extern "C" fn art_interrupt_handler(_rt: *mut ffi::JSRuntime, _opaque: *mut std::ffi::c_void) -> i32 {
    let env = ART_CHECKPOINT_ENV.load(std::sync::atomic::Ordering::Acquire);
    if env != 0 {
        let env_ptr = env as *mut std::ffi::c_void;
        let vtable = *(env_ptr as *const *const usize);
        type ExcCheckFn = unsafe extern "C" fn(*mut std::ffi::c_void) -> u8;
        let exc_check: ExcCheckFn = std::mem::transmute(*(vtable.add(228)));
        exc_check(env_ptr);
    }
    if crate::js_execution_deadline_expired() {
        1
    } else {
        0
    }
}

pub(crate) unsafe fn invoke_hook_callback_common(
    ctx_raw: usize,
    callback_bytes: &[u8; 16],
    context_name: &str,
    target_id: u64,
    build_context: impl FnOnce(*mut ffi::JSContext) -> ffi::JSValue,
    handle_result: impl FnOnce(*mut ffi::JSContext, ffi::JSValue, ffi::JSValue),
    on_js_exception: impl FnOnce(*mut ffi::JSContext, ffi::JSValue),
) -> bool {
    invoke_hook_callback_common_with_env(
        ctx_raw,
        callback_bytes,
        context_name,
        target_id,
        std::ptr::null_mut(),
        build_context,
        handle_result,
        on_js_exception,
    )
}

pub(crate) unsafe fn invoke_hook_callback_common_with_env(
    ctx_raw: usize,
    callback_bytes: &[u8; 16],
    context_name: &str,
    target_id: u64,
    jni_env: *mut std::ffi::c_void,
    build_context: impl FnOnce(*mut ffi::JSContext) -> ffi::JSValue,
    handle_result: impl FnOnce(*mut ffi::JSContext, ffi::JSValue, ffi::JSValue),
    on_js_exception: impl FnOnce(*mut ffi::JSContext, ffi::JSValue),
) -> bool {
    let ctx = ctx_raw as *mut ffi::JSContext;

    // 获取 JS 引擎锁（try_lock 避免死锁）
    let _js_guard = match acquire_js_engine_for_callback(ctx, context_name, target_id) {
        Some(g) => g,
        None => return false,
    };

    let callback: ffi::JSValue = std::ptr::read(callback_bytes.as_ptr() as *const ffi::JSValue);
    let callback_dup = ffi::qjs_dup_value(ctx, callback);

    let js_ctx = build_context(ctx);

    // ART suspend 兼容: 设置 interrupt handler 的 JNIEnv（JS_Call 期间周期性
    // 调用 ExceptionCheck 做 kNative→kRunnable→kNative 转换，处理 ART suspend 请求，
    // 避免 SuspendThreadByPeer 超时 → SIGABRT）。
    let prev_env = ART_CHECKPOINT_ENV.swap(jni_env as usize, std::sync::atomic::Ordering::Release);

    let global = ffi::JS_GetGlobalObject(ctx);
    let result = ffi::JS_Call(ctx, callback_dup, global, 1, &js_ctx as *const _ as *mut _);

    ART_CHECKPOINT_ENV.store(prev_env, std::sync::atomic::Ordering::Release);

    let had_exception = handle_js_exception(ctx, result, context_name);
    if had_exception {
        on_js_exception(ctx, js_ctx);
    } else {
        handle_result(ctx, js_ctx, result);
    }

    ffi::qjs_free_value(ctx, js_ctx);
    ffi::qjs_free_value(ctx, result);
    ffi::qjs_free_value(ctx, global);
    ffi::qjs_free_value(ctx, callback_dup);

    had_exception
}
pub(crate) unsafe fn discard_pending_exception(ctx: *mut ffi::JSContext) {
    let exception = ffi::JS_GetException(ctx);
    ffi::qjs_free_value(ctx, exception);
}
