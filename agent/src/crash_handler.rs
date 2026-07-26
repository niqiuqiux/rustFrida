//! Rust panic hook for the agent.
//!
//! 这个模块曾经还通过 libsigchain 的 special handler API 安装一套原生崩溃转储器
//! （寄存器/代码字节/backtrace）。它从一开始就没有 claim SIGSEGV/SIGBUS——ART 依赖
//! signal chain 实现 managed 空指针检查与栈溢出检测，抢这条链会在启动阶段打断
//! null-check——后来连剩下的 SIGABRT/SIGFPE/SIGILL/SIGTRAP 也停用了，agent 崩溃改用
//! 系统 tombstone 加符号化排查（见 doc/frida-upgrade-roadmap.md §5.7）。转储器随之
//! 删除，只留下这条约定：**agent 不接管任何崩溃信号**。
//!
//! `memory_monitor` 是唯一的例外，而且是有范围的：只有脚本真的建了
//! MemoryAccessMonitor 时，Gum 的 exceptor 才会去 claim SIGSEGV，卸载时立刻交还。

use crate::communication::log_msg;
use std::process;

/// 安装Rust panic hook，捕获panic并输出带符号的backtrace
pub(crate) fn install_panic_hook() {
    use std::backtrace::Backtrace;

    std::panic::set_hook(Box::new(|panic_info| {
        // 强制捕获backtrace，无视环境变量
        let bt = Backtrace::force_capture();

        // 获取panic位置
        let location = panic_info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "unknown".to_string());

        // 获取panic消息
        let payload = panic_info
            .payload()
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| panic_info.payload().downcast_ref::<String>().map(|s| s.as_str()))
            .unwrap_or("unknown panic");

        let msg = format!(
            "\n\n=== RUST PANIC ===\n\
             Location: {}\n\
             Message: {}\n\
             PID: {}, TID: {}\n\n\
             Backtrace:\n{}\n\
             =================\n\n",
            location,
            payload,
            process::id(),
            unsafe { libc::gettid() },
            bt
        );

        log_msg(msg);
    }));
}
