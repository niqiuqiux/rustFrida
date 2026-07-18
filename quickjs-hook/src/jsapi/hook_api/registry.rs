//! Hook registry: StealthMode, HookData, HOOK_REGISTRY, error constants

use crate::jsapi::callback_util::ensure_registry_initialized;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

// Error codes from hook_engine.h
pub(crate) const HOOK_OK: i32 = 0;
const HOOK_ERROR_NOT_INITIALIZED: i32 = -1;
const HOOK_ERROR_INVALID_PARAM: i32 = -2;
const HOOK_ERROR_ALREADY_HOOKED: i32 = -3;
const HOOK_ERROR_ALLOC_FAILED: i32 = -4;
const HOOK_ERROR_MPROTECT_FAILED: i32 = -5;
const HOOK_ERROR_NOT_FOUND: i32 = -6;
const HOOK_ERROR_BUFFER_TOO_SMALL: i32 = -7;
const HOOK_ERROR_WXSHADOW_FAILED: i32 = -8;

/// Convert hook error code to error message
pub(crate) fn hook_error_message(code: i32) -> &'static [u8] {
    match code {
        HOOK_ERROR_NOT_INITIALIZED => b"hook engine not initialized\0",
        HOOK_ERROR_INVALID_PARAM => b"invalid parameter\0",
        HOOK_ERROR_ALREADY_HOOKED => b"address already hooked\0",
        HOOK_ERROR_ALLOC_FAILED => b"memory allocation failed\0",
        HOOK_ERROR_MPROTECT_FAILED => b"mprotect failed: cannot change memory protection\0",
        HOOK_ERROR_NOT_FOUND => b"hook not found at address\0",
        HOOK_ERROR_BUFFER_TOO_SMALL => b"buffer too small for jump instruction\0",
        HOOK_ERROR_WXSHADOW_FAILED => {
            b"wxshadow prctl write failed: load hook_module.ko + wxshadow_module.ko with kernel_hook/loader\0"
        }
        _ => b"unknown hook error\0",
    }
}

/// Hook stealth 模式
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StealthMode {
    /// 普通 inline hook（直接 patch 原始代码）
    Normal = 0,
    /// stealth1（hook_module-backed wxshadow_module prctl 后端）
    WxShadow = 1,
    /// recomp stealth（页级重编译，在重编译页上 hook）
    Recomp = 2,
}

/// JS 常量值
pub(crate) const STEALTH_NORMAL: i32 = StealthMode::Normal as i32;
pub(crate) const STEALTH_WXSHADOW: i32 = StealthMode::WxShadow as i32;
pub(crate) const STEALTH_RECOMP: i32 = StealthMode::Recomp as i32;

impl StealthMode {
    /// 从 JS 参数解析 stealth 模式
    /// - 0 / false / omitted → Normal
    /// - 1 / true → WxShadow
    /// - 2 → Recomp
    pub(crate) fn from_js_arg(val: i64) -> Self {
        match val {
            1 => StealthMode::WxShadow,
            2 => StealthMode::Recomp,
            _ => StealthMode::Normal,
        }
    }
}

/// Hook 安装种类: Replace 单阶段（hook_replace） or Attach 双阶段（hook_attach）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HookKind {
    /// hook_replace: 完全替换，thunk 只在进入时调 on_enter；callOriginal 靠 ctx.$orig() 显式触发
    Replace,
    /// hook_attach: Frida-style，thunk 自动 BLR 原函数；on_enter 观察/改参数，on_leave 观察/改返回值
    Attach,
    /// Interceptor.attach: 一个地址级底层 hook，可承载多个独立 JS listener
    Interceptor,
}

/// Stored hook callback data - stores raw bytes to avoid Send/Sync issues
#[derive(Clone, Copy)]
pub(crate) struct HookData {
    pub(crate) ctx: usize,                // Store as usize to avoid Send/Sync issues
    pub(crate) callback_bytes: [u8; 16],  // on_enter / replace callback (JSValue 16 字节)
    pub(crate) on_leave_bytes: [u8; 16],  // on_leave (attach 模式) — has_on_leave=false 时全 0
    pub(crate) has_on_enter: bool,        // attach 模式下 onEnter 可缺省
    pub(crate) has_on_leave: bool,        // attach 模式下 onLeave 可缺省
    pub(crate) trampoline: u64,           // Trampoline address for callOriginal (replace mode)
    pub(crate) kind: HookKind,            // Replace or Attach
    pub(crate) mode: StealthMode,         // hook 模式（unhook 时需要）
    pub(crate) recomp_addr: u64,          // Recomp 模式下的重编译地址
    pub(crate) native_attach_data: usize, // attachNative callback storage (Box<NativeAttachCallbacks>)
}

// SAFETY: HookData only contains Copy types now (usize, [u8; 16])
// The actual pointer usage is only done within unsafe blocks on the JS thread
unsafe impl Send for HookData {}
unsafe impl Sync for HookData {}

/// Global hook registry
pub(crate) static HOOK_REGISTRY: Mutex<Option<HashMap<u64, HookData>>> = Mutex::new(None);

/// Interceptor listener 是地址级底层 hook 之上的逻辑观察者。
///
/// JSValue 以原始字节保存，所有复制和释放都必须在持有 JS engine 锁时完成。
#[derive(Clone, Copy)]
pub(crate) struct InterceptorListenerData {
    pub(crate) id: u64,
    pub(crate) target: u64,
    pub(crate) ctx: usize,
    pub(crate) on_enter_bytes: [u8; 16],
    pub(crate) on_leave_bytes: [u8; 16],
    pub(crate) has_on_enter: bool,
    pub(crate) has_on_leave: bool,
}

unsafe impl Send for InterceptorListenerData {}
unsafe impl Sync for InterceptorListenerData {}

/// 按 target 保持 attach 顺序，onEnter/onLeave 均按该顺序分发。
static INTERCEPTOR_LISTENERS: Mutex<Option<HashMap<u64, Vec<InterceptorListenerData>>>> = Mutex::new(None);
static NEXT_INTERCEPTOR_LISTENER_ID: AtomicU64 = AtomicU64::new(1);

/// Initialize hook registry
pub(crate) fn init_registry() {
    ensure_registry_initialized(&HOOK_REGISTRY);
    ensure_registry_initialized(&INTERCEPTOR_LISTENERS);
}

fn next_interceptor_listener_id() -> u64 {
    loop {
        let id = NEXT_INTERCEPTOR_LISTENER_ID.fetch_add(1, Ordering::Relaxed);
        if id != 0 {
            return id;
        }
    }
}

pub(crate) fn add_interceptor_listener(mut listener: InterceptorListenerData) -> u64 {
    init_registry();
    listener.id = next_interceptor_listener_id();
    let id = listener.id;
    let mut guard = INTERCEPTOR_LISTENERS.lock().unwrap_or_else(|e| e.into_inner());
    guard
        .as_mut()
        .expect("interceptor listener registry initialized")
        .entry(listener.target)
        .or_default()
        .push(listener);
    id
}

pub(crate) fn interceptor_listener_snapshot(target: u64) -> Vec<InterceptorListenerData> {
    let guard = INTERCEPTOR_LISTENERS.lock().unwrap_or_else(|e| e.into_inner());
    guard
        .as_ref()
        .and_then(|registry| registry.get(&target).cloned())
        .unwrap_or_default()
}

pub(crate) fn interceptor_listener_is_active(target: u64, listener_id: u64) -> bool {
    let guard = INTERCEPTOR_LISTENERS.lock().unwrap_or_else(|e| e.into_inner());
    guard
        .as_ref()
        .and_then(|registry| registry.get(&target))
        .is_some_and(|listeners| listeners.iter().any(|listener| listener.id == listener_id))
}

/// 返回 `(被移除的 listener, 该 target 是否已没有 listener)`。
pub(crate) fn remove_interceptor_listener(target: u64, listener_id: u64) -> (Option<InterceptorListenerData>, bool) {
    let mut guard = INTERCEPTOR_LISTENERS.lock().unwrap_or_else(|e| e.into_inner());
    let Some(registry) = guard.as_mut() else {
        return (None, true);
    };
    let Some(listeners) = registry.get_mut(&target) else {
        return (None, true);
    };
    let removed = listeners
        .iter()
        .position(|listener| listener.id == listener_id)
        .map(|index| listeners.remove(index));
    let target_is_empty = listeners.is_empty();
    if target_is_empty {
        registry.remove(&target);
    }
    (removed, target_is_empty)
}

pub(crate) fn take_interceptor_listeners(target: u64) -> Vec<InterceptorListenerData> {
    let mut guard = INTERCEPTOR_LISTENERS.lock().unwrap_or_else(|e| e.into_inner());
    guard
        .as_mut()
        .and_then(|registry| registry.remove(&target))
        .unwrap_or_default()
}

pub(crate) fn take_all_interceptor_listeners() -> Vec<InterceptorListenerData> {
    let mut guard = INTERCEPTOR_LISTENERS.lock().unwrap_or_else(|e| e.into_inner());
    guard
        .take()
        .into_iter()
        .flat_map(|registry| registry.into_values().flatten())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listener(target: u64) -> InterceptorListenerData {
        InterceptorListenerData {
            id: 0,
            target,
            ctx: 1,
            on_enter_bytes: [0; 16],
            on_leave_bytes: [0; 16],
            has_on_enter: false,
            has_on_leave: false,
        }
    }

    #[test]
    fn interceptor_listeners_keep_order_and_detach_independently() {
        let target = 0xf000_0000_0000_0101;
        let first = add_interceptor_listener(listener(target));
        let second = add_interceptor_listener(listener(target));

        let snapshot = interceptor_listener_snapshot(target);
        assert_eq!(snapshot.iter().map(|item| item.id).collect::<Vec<_>>(), [first, second]);

        let (removed, empty) = remove_interceptor_listener(target, first);
        assert_eq!(removed.map(|item| item.id), Some(first));
        assert!(!empty);
        assert!(!interceptor_listener_is_active(target, first));
        assert!(interceptor_listener_is_active(target, second));

        let (removed, empty) = remove_interceptor_listener(target, second);
        assert_eq!(removed.map(|item| item.id), Some(second));
        assert!(empty);
        assert!(interceptor_listener_snapshot(target).is_empty());
    }
}
