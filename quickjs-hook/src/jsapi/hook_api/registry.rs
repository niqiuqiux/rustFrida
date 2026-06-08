//! Hook registry: StealthMode, HookData, HOOK_REGISTRY, error constants

use crate::jsapi::callback_util::ensure_registry_initialized;
use std::collections::HashMap;
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

/// Initialize hook registry
pub(crate) fn init_registry() {
    ensure_registry_initialized(&HOOK_REGISTRY);
}
