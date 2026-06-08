#![cfg(all(target_os = "android", target_arch = "aarch64"))]

use rustyline::completion::{Completer, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::{CompletionType, Config, Context, Editor, Helper};
use std::sync::Arc;
use std::sync::OnceLock;

use crate::communication::send_command;
use crate::logger::{GRAY, GREEN, HIGHLIGHT_BG, HIGHLIGHT_FG, RED, RESET, YELLOW};
use crate::session::Session;
use crate::{log_error, log_info, log_warn};

const JSEVAL_ERROR_PREFIX: &str = "__RF_JSEVAL_ERROR__:";
pub(crate) const EVAL_DEFAULT_TIMEOUT_SECS: u64 = 5;
pub(crate) const EVAL_RECOMP_TIMEOUT_SECS: u64 = 8;
pub(crate) const EVAL_JAVA_TIMEOUT_SECS: u64 = 60;
pub(crate) const LOAD_DEFAULT_TIMEOUT_SECS: u64 = 5;
pub(crate) const LOAD_JAVA_TIMEOUT_SECS: u64 = 60;
pub(crate) const LOAD_STOP_WORKER_TIMEOUT_SECS: u64 = 2;
pub(crate) const LOAD_PRE_RESUME_JAVA_TIMEOUT_SECS: u64 = 30;
pub(crate) const JAVA_EXECUTOR_BOOTSTRAP_TIMEOUT_SECS: u64 = 35;
pub(crate) const JAVA_STEALTH_TIMEOUT_SECS: u64 = 1;
pub(crate) const JSCLEAN_SOFT_TIMEOUT_SECS: u64 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PostResumeJavaWorkerMode {
    Auto,
    Skip,
    Full,
}

impl PostResumeJavaWorkerMode {
    pub(crate) fn from_env() -> Result<Self, String> {
        if let Ok(raw) = std::env::var("RF_POST_RESUME_JAVA_WORKER_MODE") {
            return Self::parse(&raw);
        }
        let skip = std::env::var("RF_SKIP_POST_RESUME_JAVA_WORKER")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        Ok(if skip { Self::Skip } else { Self::Auto })
    }

    fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "" | "auto" | "lazy" | "on-demand" => Ok(Self::Auto),
            "full" | "start" | "worker" => Ok(Self::Full),
            "skip" | "none" | "off" => Ok(Self::Skip),
            _ => Err(format!(
                "未知 RF_POST_RESUME_JAVA_WORKER_MODE='{}'，可用值: auto|skip|full",
                raw
            )),
        }
    }
}

fn script_filename(script_path: &str) -> String {
    std::path::Path::new(script_path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("script.js")
        .to_string()
}

fn parse_loadjs_payload_for_host(payload: &str) -> (&str, &str) {
    if !payload.starts_with('[') {
        return ("", payload);
    }
    let first_line_end = payload.find('\n').unwrap_or(payload.len());
    let first_line = &payload[..first_line_end];
    if !first_line.ends_with(']') {
        return ("", payload);
    }
    let filename = &first_line[1..first_line.len() - 1];
    if filename.is_empty() || filename.contains('[') || filename.contains(']') {
        return ("", payload);
    }
    let script_start = if first_line_end < payload.len() {
        first_line_end + 1
    } else {
        payload.len()
    };
    (filename, &payload[script_start..])
}

pub(crate) fn ensure_java_worker_ready(session: &Session) -> Result<(), String> {
    if session.java_worker_ready.load(std::sync::atomic::Ordering::Acquire) {
        return Ok(());
    }
    let sender = session.get_sender().ok_or("agent 未连接")?;
    session.eval_state.clear();
    crate::process::thaw_cgroup_freezer(session.pid.load(std::sync::atomic::Ordering::Acquire));
    send_command(sender, "javaworker_init").map_err(|e| format!("发送 Java worker 初始化失败: {}", e))?;
    match session
        .eval_state
        .recv_timeout(std::time::Duration::from_secs(JAVA_EXECUTOR_BOOTSTRAP_TIMEOUT_SECS))
    {
        Some(Ok(_)) => {
            session
                .java_worker_ready
                .store(true, std::sync::atomic::Ordering::Release);
            Ok(())
        }
        Some(Err(e)) => Err(format!("Java worker 初始化失败: {}", e)),
        None => Err(format!(
            "等待 Java worker 初始化超时({}s)",
            JAVA_EXECUTOR_BOOTSTRAP_TIMEOUT_SECS
        )),
    }
}

pub(crate) fn cut_pre_resume_java_executor_hook(session: &Session) -> Result<(), String> {
    let sender = session.get_sender().ok_or("agent 未连接")?;
    session.eval_state.clear();
    send_command(sender, "javaexecutor_cut").map_err(|e| format!("发送 Java executor cut 失败: {}", e))?;
    match session
        .eval_state
        .recv_timeout(std::time::Duration::from_secs(JAVA_STEALTH_TIMEOUT_SECS))
    {
        Some(Ok(_)) => Ok(()),
        Some(Err(e)) => Err(format!("Java executor cut 失败: {}", e)),
        None => Err(format!("等待 Java executor cut 超时({}s)", JAVA_STEALTH_TIMEOUT_SECS)),
    }
}

pub(crate) fn ensure_java_worker_ready_after_resume(session: &Session, java_worker_needed: bool) -> Result<(), String> {
    run_post_resume_java_worker_mode(session, PostResumeJavaWorkerMode::from_env()?, java_worker_needed)
}

pub(crate) fn run_post_resume_java_worker_mode(
    session: &Session,
    mode: PostResumeJavaWorkerMode,
    java_worker_needed: bool,
) -> Result<(), String> {
    match mode {
        PostResumeJavaWorkerMode::Auto => {
            if !java_worker_needed {
                log_info!("spawn 已恢复，未检测到 Java 操作，Java worker 延迟到首次 Java API 时启动");
                return Ok(());
            }
            if session.java_worker_ready.load(std::sync::atomic::Ordering::Acquire) {
                return Ok(());
            }
            log_info!("spawn 已恢复，检测到 Java 操作，启动 Java worker");
            ensure_java_worker_ready(session)
        }
        PostResumeJavaWorkerMode::Skip => {
            log_warn!("RF_POST_RESUME_JAVA_WORKER_MODE=skip，跳过 spawn 恢复后的 Java worker 启动");
            Ok(())
        }
        PostResumeJavaWorkerMode::Full => {
            if session.java_worker_ready.load(std::sync::atomic::Ordering::Acquire) {
                return Ok(());
            }
            log_info!("spawn 已恢复，启动 Java worker 作为后续 Java 操作执行线程");
            ensure_java_worker_ready(session)
        }
    }
}

pub(crate) fn try_loadjs_on_main_thread_if_java(session: &Session, line: &str) -> Result<bool, String> {
    let Some(rest) = line
        .strip_prefix("loadjs ")
        .or_else(|| line.strip_prefix("loadjs\n"))
        .or_else(|| line.strip_prefix("loadjs"))
    else {
        return Ok(false);
    };
    let (_filename, script) = parse_loadjs_payload_for_host(rest);

    if script_uses_java_api(script) {
        log_info!("检测到 Java loadjs，发送到 Java worker 执行");
        ensure_java_worker_ready(session)?;
        let sender = session.get_sender().ok_or("agent 未连接")?;
        crate::process::thaw_cgroup_freezer(session.pid.load(std::sync::atomic::Ordering::Acquire));
        session.eval_state.clear();
        send_command(sender, format!("java_loadjs {}", rest))
            .map_err(|e| format!("发送 Java loadjs 到 Java worker 失败: {}", e))?;
        return Ok(true);
    }
    Ok(false)
}

pub(crate) fn try_jseval_on_main_thread_if_java_or_dsl(session: &Session, line: &str) -> Result<bool, String> {
    let Some(expr) = line
        .strip_prefix("jseval ")
        .or_else(|| line.strip_prefix("jseval\n"))
        .or_else(|| line.strip_prefix("jseval"))
    else {
        return Ok(false);
    };

    if !script_uses_java_api(expr) && !script_uses_managed_dsl_api(expr) {
        return Ok(false);
    }

    let expr = wrap_jseval_expr(expr);
    if script_uses_java_api(&expr) {
        log_info!("检测到 Java jseval，发送到 Java worker 执行");
    } else {
        log_info!("检测到 Managed DSL jseval，发送到 Java worker 执行");
    }
    ensure_java_worker_ready(session)?;
    let sender = session.get_sender().ok_or("agent 未连接")?;
    crate::process::thaw_cgroup_freezer(session.pid.load(std::sync::atomic::Ordering::Acquire));
    session.eval_state.clear();
    send_command(sender, format!("java_jseval {}", expr))
        .map_err(|e| format!("发送 Java jseval 到 Java worker 失败: {}", e))?;
    return Ok(true);
}

fn js_string_literal(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

pub(crate) fn try_managedcounter_on_main_thread(session: &Session, line: &str) -> Result<bool, String> {
    let Some(rest) = line.strip_prefix("managedcounter ") else {
        return Ok(false);
    };
    let mut parts = rest.split_whitespace();
    let helper_class = parts.next().unwrap_or("");
    let field_name = parts.next().unwrap_or("");
    if helper_class.is_empty() || field_name.is_empty() || parts.next().is_some() {
        return Err("用法: managedcounter <helperClass> <fieldName>".to_string());
    }

    log_info!("managedcounter 切到目标主线程读取");
    let expr = format!(
        "(() => {{ try {{ return String(Java.managedReadCounter({}, {})); }} catch (e) {{ return '[managedcounter error] ' + String(e); }} }})()",
        js_string_literal(helper_class),
        js_string_literal(field_name)
    );
    crate::remote_agent::eval_js_on_main_thread(session, &expr, "", false)
        .map_err(|e| format!("主线程读取 managedcounter 失败: {}", e))?;
    Ok(true)
}

fn wrap_jseval_expr(expr: &str) -> String {
    format!(
        "(() => {{ try {{ return eval({}); }} catch (e) {{ let msg = String((e && e.message) ? ((e.name || 'Error') + ': ' + e.message) : e); let st = ''; try {{ st = (e && e.stack) ? String(e.stack) : ''; }} catch (_) {{}} let s = st ? (st.indexOf(msg) >= 0 ? st : (msg + '\\n' + st)) : msg; return {} + s; }} }})()",
        js_string_literal(expr),
        js_string_literal(JSEVAL_ERROR_PREFIX)
    )
}

pub(crate) fn rewrite_jseval_for_agent(line: &str) -> Option<String> {
    let expr = line
        .strip_prefix("jseval ")
        .or_else(|| line.strip_prefix("jseval\n"))
        .or_else(|| line.strip_prefix("jseval"))?;
    Some(format!("jseval {}", wrap_jseval_expr(expr)))
}

pub(crate) enum PreResumeLoad {
    Loaded { uses_java_api: bool },
    DeferredEvalCompleted,
}

impl PreResumeLoad {
    pub(crate) fn needs_post_resume_java_worker(&self) -> bool {
        match self {
            Self::Loaded { uses_java_api } => *uses_java_api,
            Self::DeferredEvalCompleted => true,
        }
    }
}

fn is_ident_byte(b: u8) -> bool {
    b == b'_' || b == b'$' || b.is_ascii_alphanumeric()
}

fn skip_ws_and_comments(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() {
        match bytes[i] {
            b' ' | b'\t' | b'\r' | b'\n' => i += 1,
            b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'/' => {
                i += 2;
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'*' => {
                i += 2;
                while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    i += 1;
                }
                i = (i + 2).min(bytes.len());
            }
            _ => break,
        }
    }
    i
}

fn skip_js_quoted(bytes: &[u8], mut i: usize, quote: u8) -> usize {
    i += 1;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i = (i + 2).min(bytes.len());
        } else if bytes[i] == quote {
            return i + 1;
        } else {
            i += 1;
        }
    }
    i
}

fn java_member_accesses(script: &str) -> Vec<(usize, String)> {
    let bytes = script.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;

    while i < bytes.len() {
        match bytes[i] {
            b'\'' | b'"' | b'`' => {
                i = skip_js_quoted(bytes, i, bytes[i]);
            }
            b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'/' => {
                i += 2;
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'*' => {
                i += 2;
                while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    i += 1;
                }
                i = (i + 2).min(bytes.len());
            }
            b'J' if bytes.get(i..i + 4) == Some(b"Java")
                && (i == 0 || !is_ident_byte(bytes[i - 1]))
                && (i + 4 >= bytes.len() || !is_ident_byte(bytes[i + 4])) =>
            {
                let dot = skip_ws_and_comments(bytes, i + 4);
                if dot < bytes.len() && bytes[dot] == b'.' {
                    let start = skip_ws_and_comments(bytes, dot + 1);
                    let mut end = start;
                    while end < bytes.len() && is_ident_byte(bytes[end]) {
                        end += 1;
                    }
                    if end > start {
                        if let Ok(member) = std::str::from_utf8(&bytes[start..end]) {
                            out.push((i, member.to_string()));
                        }
                    }
                }
                i += 4;
            }
            _ => i += 1,
        }
    }

    out
}

pub(crate) fn script_uses_java_api(script: &str) -> bool {
    !java_member_accesses(script).is_empty()
}

pub(crate) fn script_uses_managed_dsl_api(script: &str) -> bool {
    const NEEDLES: &[&str] = &[
        "dslRead",
        "dslDrain",
        "dslTake",
        "dslInfo",
        "dslImpl",
        "managedDrainMessages",
        "managedReadCounter",
    ];
    NEEDLES.iter().any(|needle| script.contains(needle))
}

pub(crate) fn detect_java_stealth_mode(script: &str) -> Option<i32> {
    let idx = java_member_accesses(script)
        .into_iter()
        .find_map(|(idx, member)| (member == "setStealth").then_some(idx))?;
    let rest = &script[idx..];
    let open = rest.find('(')?;
    let rest = &rest[open + 1..];
    let close = rest.find(')')?;
    let arg = rest[..close].trim();
    let arg = arg.trim_matches(|c: char| c == ';' || c.is_whitespace());

    if arg == "2" || arg == "Hook.RECOMP" || arg == "RECOMP" || arg == "Java.RECOMP" {
        Some(2)
    } else if arg == "1" || arg == "true" || arg == "Hook.WXSHADOW" || arg == "WXSHADOW" || arg == "Java.WXSHADOW" {
        Some(1)
    } else if arg == "0" || arg == "false" || arg == "Hook.NORMAL" || arg == "NORMAL" || arg == "Java.NORMAL" {
        Some(0)
    } else {
        None
    }
}

pub(crate) fn preconfigure_java_stealth_if_declared(session: &Session, script: &str) -> Result<(), String> {
    let Some(mode) = detect_java_stealth_mode(script) else {
        return Ok(());
    };
    let sender = session.get_sender().ok_or_else(|| "agent 未连接".to_string())?;
    log_info!("脚本声明 Java.setStealth({})，预配置到 artinit/jsinit 之前", mode);
    session.eval_state.clear();
    send_command(sender, format!("javastealth {}", mode)).map_err(|e| format!("发送 javastealth 失败: {}", e))?;
    match session
        .eval_state
        .recv_timeout(std::time::Duration::from_secs(JAVA_STEALTH_TIMEOUT_SECS))
    {
        None => Err(format!("等待 javastealth 超时({}s)", JAVA_STEALTH_TIMEOUT_SECS)),
        Some(Err(e)) => Err(format!("javastealth 失败: {}", e)),
        Some(Ok(_)) => Ok(()),
    }
}

/// 当前构建实际可用的命令列表（编译时由 feature 控制）
pub(crate) fn commands() -> &'static [(&'static str, &'static str, &'static str)] {
    static CMDS: OnceLock<Vec<(&'static str, &'static str, &'static str)>> = OnceLock::new();
    CMDS.get_or_init(|| {
        #[allow(unused_mut)]
        let mut v: Vec<(&'static str, &'static str, &'static str)> = vec![
            ("trace", "[tid]", "ptrace 指令追踪"),
            ("jhook", "", "Java/JNI hooking"),
            ("jsinit", "", "初始化 QuickJS 引擎"),
            ("loadjs", "<script>", "执行 JavaScript 代码"),
            ("jseval", "<expr>", "求值 JS 表达式并显示结果"),
            ("jsclean", "", "清理 QuickJS 引擎"),
            ("jsrepl", "", "进入 JS REPL 模式（Tab 动态补全）"),
            ("%reload", "[path]", "重载脚本（jsclean+jsinit+loadjs，不退出）"),
            ("help", "", "显示此帮助信息"),
            ("exit", "", "退出程序（quit 同效）"),
        ];
        #[cfg(feature = "frida-gum")]
        {
            v.push(("stalker", "[tid]", "Frida Stalker 追踪 [frida-gum ✓]"));
            v.push(("hfl", "<module> <offset>", "Interceptor hook 指定偏移 [frida-gum ✓]"));
        }
        #[cfg(not(feature = "frida-gum"))]
        {
            v.push(("stalker", "[tid]", "Frida Stalker 追踪 [--features frida-gum 启用]"));
            v.push((
                "hfl",
                "<module> <offset>",
                "Interceptor hook 指定偏移 [--features frida-gum 启用]",
            ));
        }
        v
    })
}

/// Tab 补全器：仅补全第一个 token（命令名）
pub(crate) struct CommandCompleter;

impl CommandCompleter {
    pub(crate) fn new() -> Self {
        CommandCompleter
    }
}

impl Completer for CommandCompleter {
    type Candidate = Pair;

    fn complete(&self, line: &str, pos: usize, _ctx: &Context<'_>) -> rustyline::Result<(usize, Vec<Pair>)> {
        // 只在光标处于第一个 token 范围内时补全
        let before_cursor = &line[..pos];
        if before_cursor.contains(' ') {
            return Ok((pos, vec![]));
        }
        let prefix = before_cursor;
        let candidates: Vec<Pair> = commands()
            .iter()
            .filter(|(cmd, _, _)| cmd.starts_with(prefix))
            .map(|(cmd, _, _)| Pair {
                display: cmd.to_string(),
                replacement: cmd.to_string(),
            })
            .collect();
        Ok((0, candidates))
    }
}

impl Hinter for CommandCompleter {
    type Hint = String;
}
impl Highlighter for CommandCompleter {}
impl Validator for CommandCompleter {}
impl Helper for CommandCompleter {}

/// JS REPL 补全器：通过 socket 向 agent 发送 jscomplete 请求，同步等待结果。
struct JsReplCompleter {
    session: Arc<Session>,
    /// Cache the last completion results for the hinter to display
    last_candidates: std::cell::RefCell<(String, Vec<String>)>,
}

impl JsReplCompleter {
    fn new(session: Arc<Session>) -> Self {
        JsReplCompleter {
            session,
            last_candidates: std::cell::RefCell::new((String::new(), vec![])),
        }
    }

    /// 向 agent 发送 jscomplete 请求，持锁等待响应（≤300 ms），避免竞态。
    fn fetch_completions(&self, prefix: &str) -> Vec<String> {
        let timeout = std::time::Duration::from_millis(300);
        let cmd = format!("jscomplete {}", prefix);
        let sender = match self.session.get_sender() {
            Some(s) => s.clone(),
            None => return vec![],
        };
        // 持锁 clear + 发命令 + wait，原子消除竞态窗口
        self.session
            .complete_state
            .clear_then_recv(timeout, || {
                let _ = send_command(&sender, cmd);
            })
            .unwrap_or_default()
    }
}

impl Completer for JsReplCompleter {
    type Candidate = Pair;

    fn complete(&self, line: &str, pos: usize, _ctx: &Context<'_>) -> rustyline::Result<(usize, Vec<Pair>)> {
        let before_cursor = &line[..pos];

        // Determine the replacement start position.  After the last '.' we only
        // replace the property fragment, but we send the *full* before_cursor
        // (e.g. "console.l") so the agent can resolve the object and enumerate
        // its properties.
        let (start, query) = if let Some(dot_pos) = before_cursor.rfind('.') {
            // start is right after the dot so rustyline replaces only the property part
            (dot_pos + 1, before_cursor)
        } else {
            (0, before_cursor)
        };

        let names = self.fetch_completions(query);
        // Cache for hinter
        *self.last_candidates.borrow_mut() = (before_cursor.to_string(), names.clone());

        let candidates: Vec<Pair> = names
            .into_iter()
            .map(|name| Pair {
                display: name.clone(),
                replacement: name,
            })
            .collect();

        Ok((start, candidates))
    }
}

impl Hinter for JsReplCompleter {
    type Hint = String;
    fn hint(&self, line: &str, pos: usize, _ctx: &Context<'_>) -> Option<String> {
        let before_cursor = &line[..pos];
        let cache = self.last_candidates.borrow();
        let (ref cached_prefix, ref candidates) = *cache;

        // Only show hint if the current input is a prefix of the cached query
        // and there are multiple candidates
        if candidates.len() <= 1 || cached_prefix.is_empty() {
            return None;
        }

        // Check if current input matches the cached prefix context
        if !cached_prefix.starts_with(before_cursor) && !before_cursor.starts_with(cached_prefix.as_str()) {
            return None;
        }

        // Get the property fragment after the last dot
        let prop_part = if let Some(dot_pos) = before_cursor.rfind('.') {
            &before_cursor[dot_pos + 1..]
        } else {
            before_cursor
        };

        // Filter candidates that match current typing
        let matching: Vec<&String> = candidates
            .iter()
            .filter(|c| c.starts_with(prop_part) && c.as_str() != prop_part)
            .collect();

        if matching.is_empty() {
            return None;
        }

        // Build hint: show as " [debug|error|info|log|warn]"
        let hint_list = matching.iter().map(|s| s.as_str()).collect::<Vec<_>>().join("|");
        Some(format!(" [{}]", hint_list))
    }
}
impl Highlighter for JsReplCompleter {
    fn highlight_hint<'h>(&self, hint: &'h str) -> std::borrow::Cow<'h, str> {
        std::borrow::Cow::Owned(format!("{GRAY}{hint}{RESET}"))
    }
    fn highlight_candidate<'c>(&self, candidate: &'c str, completion: CompletionType) -> std::borrow::Cow<'c, str> {
        if completion == CompletionType::List {
            std::borrow::Cow::Owned(format!("{HIGHLIGHT_BG}{HIGHLIGHT_FG}{candidate}{RESET}"))
        } else {
            std::borrow::Cow::Borrowed(candidate)
        }
    }
}
impl Validator for JsReplCompleter {}
impl Helper for JsReplCompleter {}

/// 加载脚本文件并在 agent 中执行。
///
/// * `reset=false`：首次加载，仅 `jsinit`（若引擎已初始化则复用）+ `loadjs`
/// * `reset=true`：`%reload` 用，先 `jsclean` 重置引擎，再 `jsinit` + `loadjs`
///
/// 返回 `Ok(())` 仅表示脚本已送达并收到响应（响应内容由 `print_eval_result` 打印）。
pub(crate) fn load_script_file(session: &Session, script_path: &str, reset: bool) -> Result<(), String> {
    load_script_file_with_mode(session, script_path, reset, false).map(|_| ())
}

pub(crate) fn load_script_file_pre_resume(session: &Session, script_path: &str) -> Result<PreResumeLoad, String> {
    load_script_file_with_mode(session, script_path, false, true)
}

fn load_script_file_with_mode(
    session: &Session,
    script_path: &str,
    reset: bool,
    stop_worker_after_load: bool,
) -> Result<PreResumeLoad, String> {
    let sender = session.get_sender().ok_or_else(|| "agent 未连接".to_string())?;
    let script =
        std::fs::read_to_string(script_path).map_err(|e| format!("读取脚本文件 '{}' 失败: {}", script_path, e))?;

    if reset {
        log_info!("重载脚本: {}", script_path);
        // jsclean_soft：完整 unhook + drain=0 + 销毁 runtime，保留基础设施和 RWX 内存。
        // 引擎未初始化时 agent 回 Err("未初始化")，视为非致命跳过。
        // drain 超时时 agent 返回 Err，中止 reload 避免 UAF 旧 callback。
        session.eval_state.clear();
        if send_command(sender, "jsclean_soft").is_ok() {
            match session
                .eval_state
                .recv_timeout(std::time::Duration::from_secs(JSCLEAN_SOFT_TIMEOUT_SECS))
            {
                None => return Err(format!("等待 jsclean_soft 超时({}s)", JSCLEAN_SOFT_TIMEOUT_SECS)),
                Some(Err(ref e)) if e.contains("未初始化") => {}
                Some(Err(e)) if e.contains("drain timeout") => {
                    return Err(format!("软清理失败: {} — reload 中止，旧脚本继续运行", e));
                }
                Some(Err(e)) => log_warn!("jsclean_soft 失败: {}（继续）", e),
                Some(Ok(_)) => {}
            }
        }
    } else {
        log_info!("加载脚本: {}", script_path);
    }

    if script.is_empty() {
        log_info!("脚本为空，跳过加载: {}", script_path);
        return Ok(PreResumeLoad::Loaded { uses_java_api: false });
    }

    preconfigure_java_stealth_if_declared(session, &script)?;

    let uses_java_api = script_uses_java_api(&script);
    if uses_java_api && stop_worker_after_load && !session.java_worker_ready.load(std::sync::atomic::Ordering::Acquire)
    {
        log_info!("检测到 pre-resume Java 脚本，先发送到 raw clone TLS JS worker 执行");
    } else if uses_java_api {
        log_info!("检测到 Java 脚本，发送到 Java worker 执行");
    } else {
        log_info!("脚本发送到 raw clone TLS JS worker 执行");
    }
    let filename = script_filename(script_path);
    session.eval_state.clear();
    if uses_java_api {
        if stop_worker_after_load && !session.java_worker_ready.load(std::sync::atomic::Ordering::Acquire) {
            send_command(sender, format!("loadjs_init [{}]\n{}", filename, script))
                .map_err(|e| format!("发送 pre-resume Java 脚本到 raw clone TLS JS worker 失败: {}", e))?;
            match session
                .eval_state
                .recv_timeout(std::time::Duration::from_secs(LOAD_PRE_RESUME_JAVA_TIMEOUT_SECS))
            {
                None => {
                    return Err(format!(
                        "pre-resume Java 脚本执行超时({}s)，未恢复子进程以避免错过早期 Java hook",
                        LOAD_PRE_RESUME_JAVA_TIMEOUT_SECS
                    ))
                }
                Some(Err(e)) => return Err(format!("pre-resume Java 脚本执行失败: {}", e)),
                Some(Ok(out)) => {
                    if !out.is_empty() {
                        println!("{GREEN}=> {out}{RESET}");
                    }
                    cut_pre_resume_java_executor_hook(session)?;
                    return Ok(PreResumeLoad::DeferredEvalCompleted);
                }
            }
        }
        ensure_java_worker_ready(session)?;
        crate::process::thaw_cgroup_freezer(session.pid.load(std::sync::atomic::Ordering::Acquire));
        session.eval_state.clear();
        send_command(sender, format!("java_loadjs [{}]\n{}", filename, script))
            .map_err(|e| format!("发送脚本到 Java worker 失败: {}", e))?;
        print_eval_result(session, LOAD_JAVA_TIMEOUT_SECS);
        return Ok(PreResumeLoad::Loaded { uses_java_api });
    }
    send_command(sender, format!("loadjs_init [{}]\n{}", filename, script))
        .map_err(|e| format!("发送脚本到 raw clone TLS JS worker 失败: {}", e))?;
    print_eval_result(
        session,
        if stop_worker_after_load {
            LOAD_STOP_WORKER_TIMEOUT_SECS
        } else if uses_java_api {
            LOAD_JAVA_TIMEOUT_SECS
        } else {
            LOAD_DEFAULT_TIMEOUT_SECS
        },
    );
    Ok(PreResumeLoad::Loaded { uses_java_api })
}

/// 打印 eval 响应：等待 session.eval_state 结果并格式化输出。
pub(crate) fn print_eval_result(session: &Session, timeout_secs: u64) {
    match session
        .eval_state
        .recv_timeout(std::time::Duration::from_secs(timeout_secs))
    {
        None => crate::logger::stdout_line(
            &format!("{YELLOW}[timeout] 等待执行结果超时({}s){RESET}", timeout_secs),
            &format!("[timeout] 等待执行结果超时({}s)", timeout_secs),
        ),
        Some(Ok(output)) => {
            if let Some(err) = output.strip_prefix(JSEVAL_ERROR_PREFIX) {
                crate::logger::stdout_line(
                    &format!("{RED}[JS error] {}{RESET}", err),
                    &format!("[JS error] {}", err),
                );
            } else if !output.is_empty() {
                crate::logger::stdout_line(&format!("{GREEN}=> {}{RESET}", output), &format!("=> {}", output));
            }
        }
        Some(Err(err)) => crate::logger::stdout_line(
            &format!("{RED}[JS error] {}{RESET}", err),
            &format!("[JS error] {}", err),
        ),
    }
}

/// 打印命令帮助表
pub(crate) fn print_help() {
    use crate::logger::{BOLD, CYAN, DIM, GREEN, RESET, YELLOW};
    println!("\n{BOLD}{CYAN}可用命令:{RESET}");
    println!("{DIM}  {:<10} {:<22} {}{RESET}", "命令", "参数", "说明");
    println!("{DIM}  {:-<10} {:-<22} {:-<20}{RESET}", "", "", "");
    for (cmd, args, desc) in commands() {
        println!("  {BOLD}{GREEN}{:<10}{RESET} {YELLOW}{:<22}{RESET} {}", cmd, args, desc);
    }
    println!();
    println!("{BOLD}{CYAN}JavaScript API（在 loadjs/jseval/jsrepl 中可用）:{RESET}");
    println!("{DIM}  console{RESET}      log/info/warn/error/debug");
    println!("{DIM}  ptr(addr){RESET}    创建指针对象，addr 为数字或十六进制字符串");
    println!("{DIM}  Memory{RESET}       .readU8/16/32/64(ptr)  → number");
    println!("{DIM}             {RESET}  .readPointer(ptr)      → ptr");
    println!("{DIM}             {RESET}  .readCString(ptr)      → string（最多 4096 字节）");
    println!("{DIM}             {RESET}  .readByteArray(ptr, n) → ArrayBuffer");
    println!("{DIM}             {RESET}  .writeU8/16/32/64(ptr, val)");
    println!("{DIM}             {RESET}  .writePointer(ptr, val)");
    println!("{DIM}             {RESET}  无效地址抛 RangeError，不会 crash");
    println!("{DIM}  hook{RESET}         hook(target_ptr, replacement_ptr[, retval])");
    println!("{DIM}             {RESET}  replacement_ptr 为 JS 函数或 NativePointer");
    println!("{DIM}  unhook{RESET}       unhook(target_ptr)");
    println!("{DIM}  callNative{RESET}   callNative(addr, retType, argTypes, ...args)");
    println!("{DIM}             {RESET}  retType/argType: 'void'|'int'|'long'|'ptr'|'float'");
    println!("{DIM}  Module{RESET}       .findExportByName/.findBaseAddress/.findByAddress");
    println!("{DIM}             {RESET}  .enumerateModules() → Array<{{name,base,size,path}}>");
    println!("{DIM}  Java{RESET}         .use(class) → class wrapper (Proxy)");
    println!("{DIM}             {RESET}  .$new(...args) → new Java object");
    println!("{DIM}             {RESET}  .method.impl = fn → hook (auto-detect overload)");
    println!("{DIM}             {RESET}  .method.overload(sig).impl = fn");
    println!("{DIM}             {RESET}  .method.impl = null → unhook");
    println!("{DIM}  Jni{RESET}          .FindClass/.RegisterNatives ... → JNI 函数地址");
    println!("{DIM}             {RESET}  .addr(env, \"FindClass\") / .addr(\"FindClass\")");
    println!("{DIM}             {RESET}  .find(env, \"FindClass\") / .entries(env) / .table.FindClass");
    println!("{DIM}             {RESET}  .helper.env.getObjectClassName(obj)");
    println!("{DIM}             {RESET}  .helper.structs.JNINativeMethod.readArray(ptr, n)");
    println!("{DIM}             {RESET}  .helper.structs.jvalue.readArray(ptr, \"(ILjava/lang/String;)V\")");
    println!("{DIM}  示例:{RESET}");
    println!("{DIM}    jseval Memory.readCString(ptr(0x7f000000)){RESET}");
    println!("{DIM}    jseval JSON.stringify(Module.findByAddress(ptr(0x7f000000))){RESET}");
    println!("{DIM}    loadjs hook(ptr(0x1234), function(ctx){{console.log('hit')}}){RESET}");
    println!("{DIM}    loadjs var A=Java.use(\"android.app.Activity\"); A.onResume.impl=function(ctx){{console.log('hit')}}{RESET}");
    println!("{DIM}    loadjs hook(Jni.addr(\"FindClass\"), function(ctx){{console.log(Memory.readCString(ptr(ctx.x1))); return ctx.orig()}}){RESET}");
    println!("{DIM}    loadjs hook(Jni.addr(\"RegisterNatives\"), function(ctx){{console.log(JSON.stringify(Jni.structs.JNINativeMethod.readArray(ptr(ctx.x2), Number(ctx.x3)))); return ctx.orig()}}){RESET}");
    println!("{DIM}    loadjs hook(Jni.addr(\"GetMethodID\"), function(ctx){{console.log(Jni.env.getClassName(ctx.x1), Memory.readCString(ptr(ctx.x2)), Memory.readCString(ptr(ctx.x3))); return ctx.orig()}}){RESET}");
    println!("{DIM}    loadjs var P=Java.use(\"android.os.Process\"); console.log(P.myPid()){RESET}");
    println!(
        "{DIM}    loadjs var S=Java.use(\"java.lang.String\"); var s=S.$new(\"hello\"); console.log(s.length()){RESET}"
    );
    println!();
}

/// Enter an interactive JS REPL mode.
///
/// Every line is sent as `loadjs <line>` to the agent.  Tab completion
/// queries the live QuickJS global scope via `jscomplete`.
/// Type `exit` or press Ctrl-D / Ctrl-C to return to the main prompt.
pub(crate) fn run_js_repl(session: &Arc<Session>) {
    use crate::logger::{BOLD, CYAN, DIM, RESET};

    let sender = match session.get_sender() {
        Some(s) => s,
        None => {
            log_error!("jsrepl: agent 未连接");
            return;
        }
    };

    // Auto-initialize JS engine: send jsinit and wait for EVAL confirmation.
    // Accept both Ok (just initialized) and Err containing "已初始化" (already was ready).
    {
        let result =
            session
                .eval_state
                .clear_then_recv(std::time::Duration::from_secs(EVAL_DEFAULT_TIMEOUT_SECS), || {
                    let _ = send_command(sender, "jsinit");
                });
        match result {
            None => {
                log_error!("jsrepl: jsinit 超时({}s)，JS 引擎未就绪", EVAL_DEFAULT_TIMEOUT_SECS);
                return;
            }
            Some(Ok(_)) => {}
            Some(Err(ref e)) if e.contains("已初始化") => {}
            Some(Err(e)) => {
                log_error!("jsrepl: jsinit 失败: {}", e);
                return;
            }
        }
    }

    println!("\n{BOLD}{CYAN}进入 JS REPL 模式{RESET} {DIM}(输入 exit 或按 Ctrl-D 退出){RESET}\n");

    let config = Config::builder().completion_type(CompletionType::Circular).build();
    let mut rl: Editor<JsReplCompleter, _> = match Editor::with_config(config) {
        Ok(e) => e,
        Err(e) => {
            log_error!("初始化 JS REPL 行编辑器失败: {}", e);
            return;
        }
    };
    rl.set_helper(Some(JsReplCompleter::new(session.clone())));
    let _ = rl.load_history(".rustfrida_js_history");

    loop {
        match rl.readline("js> ") {
            Ok(line) => {
                let line = line.trim().to_string();
                if line.is_empty() {
                    continue;
                }
                let _ = rl.add_history_entry(&line);
                if line == "exit" || line == "quit" {
                    println!("{DIM}退出 JS REPL 模式{RESET}");
                    break;
                }
                // 发送前清空 eval 状态
                session.eval_state.clear();
                let cmd = format!("loadjs {}", line);
                match try_loadjs_on_main_thread_if_java(session, &cmd) {
                    Ok(true) => {}
                    Ok(false) => {
                        if let Err(e) = send_command(sender, cmd) {
                            log_error!("发送 JS 命令失败: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        log_error!("{}", e);
                        continue;
                    }
                }
                print_eval_result(session, EVAL_DEFAULT_TIMEOUT_SECS);
            }
            Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => {
                println!("{DIM}退出 JS REPL 模式{RESET}");
                break;
            }
            Err(e) => {
                log_error!("读取 JS REPL 输入失败: {}", e);
                break;
            }
        }
    }
    let _ = rl.save_history(".rustfrida_js_history");
}
