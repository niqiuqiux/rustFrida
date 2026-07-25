# rustFrida

ARM64 Android 动态插桩框架。

Frida 兼容性差异、上游源码基线和后续分步升级计划见 [Frida 17.15.5 差异与升级路线](doc/frida-upgrade-roadmap.md)。

## 环境要求

- Android NDK 25+（默认路径 `~/Android/Sdk/ndk/`）
- Rust toolchain + `aarch64-linux-android` target
- Python 3（构建 loader shellcode）
- `.cargo/config.toml` 已配置交叉编译（仓库自带）
- 可选 QBDI Trace：`qbdi/libQBDI.a` 必须是真实 archive；若 clone 后只是 Git LFS pointer，需要先安装 `git-lfs` 并拉取，或手动替换为真实 `libQBDI.a`
- 可选 `Hook.WXSHADOW` / `writeBytes(..., 1)`：设备侧需先通过 `/home/qiu/Android/kernel_hook/loader` 加载 `hook_module.ko` 和 `wxshadow_module.ko`

首次 clone 后先拉取子仓库：

```bash
git submodule update --init --recursive
```

`quickjs-hook/third_party/tinycc` 是 RF 的 CModule 编译器子仓库，默认跟随 `https://github.com/kkkbbb/tinycc.git` 的 `rf/cmodule-runtime` 分支。

## 构建

最终产物 `rustfrida` 通过 `include_bytes!` 内嵌了 loader shellcode 和 agent SO，有严格的**构建顺序**：

```
loader shellcode  ──┐
                    ├──→  rustfrida (主程序)
agent (libagent.so) ┘
```

> **平台说明**：仓库自带的 `.cargo/config.toml` 默认交叉编译到 `aarch64-linux-android`。下面的 1–3 步**以 Linux / WSL2 为准**（loader 脚本调用 `python3`、内核 LKM 用 bash）。在 **Windows 原生环境**构建请看本章的 [Windows 原生交叉编译](#windows-原生交叉编译) 一节——主程序、agent、loader、QBDI 组件均可在 Windows 上交叉编译，唯独 eBPF（`--watch-so`）因 `bpf-linker` 不支持 Windows 而无法构建。

### 1. 构建 loader shellcode（bootstrapper + rustfrida-loader）

```bash
python3 loader/build_helpers.py
# 输出:
#   loader/build/bootstrapper.bin
#   loader/build/rustfrida-loader.bin
```

loader 是 bare-metal ARM64 shellcode，被 `rustfrida` 通过 `include_bytes!` 嵌入。`rust_frida/build.rs` 会在输入比输出新时自动重建；手动修改 loader C 代码后也可以直接运行此步确认输出。

### 2. 构建 agent（libagent.so）

```bash
cargo build -p agent --release
# 输出: target/aarch64-linux-android/release/libagent.so
```

agent 是注入到目标进程的动态库，包含 hook 引擎、QuickJS、Java hook 等。**必须先于 rustfrida 构建**，因为 rustfrida 通过 `include_bytes!` 嵌入 agent SO。

### 3. 构建 rustfrida（主程序）

```bash
cargo build -p rust_frida --release
# 输出: target/aarch64-linux-android/release/rustfrida
```

rustfrida 内嵌了 `bootstrapper.bin` + `rustfrida-loader.bin` + `libagent.so`，是一个自包含的单文件。

### 符号化构建

标准构建会在剥离 release 产物的同时生成链接器 map。map 与设备实际运行的二进制来自同一次链接，不会因为额外 debuginfo 改变注入代码布局：

```bash
cargo build -p agent --release
cargo build -p rust_frida --release
# 输出:
#   target/aarch64-linux-android/release/libagent.so
#   target/aarch64-linux-android/release/rustfrida
#   target/aarch64-linux-android/release/libagent.map
#   target/aarch64-linux-android/release/rustfrida.map
```

解析 Android tombstone 中 `/memfd:wwb_so` 的 PC 时，将 backtrace 的 `pc` 与该行显示的 `offset` 相加，所得 ELF 虚拟地址可在 `libagent.map` 中查找最近符号。例如 `pc 0x8f33c (offset 0x303000)` 对应 `0x39233c`。

`rustfrida` 默认嵌入与自身相同 profile 下的 agent，并会正确跟随自定义 `CARGO_TARGET_DIR`；高级场景可通过 `RUSTFRIDA_AGENT_PROFILE` 选择已有 agent 目录。启用 QBDI 时默认使用与 agent 相同 profile 下的 `libqbdi_helper.so`，也可通过 `RUSTFRIDA_QBDI_PROFILE` 单独覆盖。

### Windows 原生交叉编译

在 Windows 上直接交叉编译到 `aarch64-linux-android`，无需 WSL。已在 **NDK 28.1.13356709 + Rust 1.92（MSVC host）** 实测通过：主程序、agent、loader shellcode、QBDI 组件均可构建。

**前置**

- Android NDK 25+（Windows 版，须含 `toolchains/llvm/prebuilt/windows-x86_64`）
- `rustup target add aarch64-linux-android`
- Python 3（Windows 下命令通常为 `python`，无 `python3`）

**1) 配置 `.cargo/config.toml`**

仓库的 `.cargo/config.toml` 默认启用 Linux 配置，并保留了一份注释状态的 Windows 配置模板（指向 `windows-x86_64` 工具链：`*-clang.cmd` / `llvm-ar.exe` / sysroot / `clang/19` builtins）。在 Windows 原生环境中，用模板替换当前的 `[target.aarch64-linux-android]` 和 `[env]` 段，并把 NDK 路径换成你自己的：

```toml
[build]
target = "aarch64-linux-android"

[target.aarch64-linux-android]
linker = "<NDK>/toolchains/llvm/prebuilt/windows-x86_64/bin/aarch64-linux-android33-clang.cmd"
ar = "<NDK>/toolchains/llvm/prebuilt/windows-x86_64/bin/llvm-ar.exe"
rustflags = ["-l","clang_rt.builtins-aarch64-android","-L","<NDK>/toolchains/llvm/prebuilt/windows-x86_64/lib/clang/19/lib/linux"]

[env]
CC_aarch64-linux-android = "<NDK>/toolchains/llvm/prebuilt/windows-x86_64/bin/aarch64-linux-android33-clang.cmd"
AR_aarch64-linux-android = "<NDK>/toolchains/llvm/prebuilt/windows-x86_64/bin/llvm-ar.exe"
AR_aarch64_linux_android = "<NDK>/toolchains/llvm/prebuilt/windows-x86_64/bin/llvm-ar.exe"
BINDGEN_EXTRA_CLANG_ARGS = "--sysroot=<NDK>/toolchains/llvm/prebuilt/windows-x86_64/sysroot/"
```

> NDK 的 `*-clang.cmd` 包装脚本能被 cc crate / rustc 调用，但**不能**被 Python 的 `subprocess`（CreateProcess）直接执行——`loader/build_helpers.py` 已跨平台处理（Windows 下改用 `clang.exe` + 显式 `-target`，并修正了控制台 UTF-8 输出）。

**2) 三步构建**（PowerShell；用 `NDK_PATH` 锁定本次使用的 NDK，避免环境里残留的其它 NDK 干扰）

```powershell
$env:NDK_PATH = "<NDK>"   # 例: C:\Users\<you>\AppData\Local\Android\Sdk\ndk\28.1.13356709

python loader\build_helpers.py                 # 1) loader shellcode（注意是 python，不是 python3）
cargo build -p agent --release                 # 2) agent
cargo build -p rust_frida --release            # 3) 主程序 → target\aarch64-linux-android\release\rustfrida
```

**QBDI trace（可选）**：`qbdi-helper/build.rs` 会按 host 自动选用 `windows-x86_64` 的 libc++ 静态库，直接构建即可：

```powershell
cargo build -p qbdi-helper --release           # → libqbdi_helper.so
cargo build -p agent --release --features qbdi
cargo build -p rust_frida --release --features qbdi
```

**限制：eBPF / `--watch-so` 在 Windows 不可用**

`--watch-so`（eBPF 监听 SO 加载自动附加）经 `ldmonitor → aya_build → bpf-linker`，而 `bpf-linker` 仅支持 Linux/macOS。为此 `rust_frida` 新增了 `watch-so` feature 并把 `ldmonitor` 设为可选依赖，**默认关闭**——Windows 默认构建不含该功能（运行 `--watch-so` 时会给出提示）。要启用需在 Linux / WSL2：

```bash
cargo build -p rust_frida --release --features watch-so
```

### 可选组件（单独构建）

这些不在 default-members 里，按需构建：

**QBDI Trace 支持：** 需要先构建 qbdi-helper SO，再用 `--features qbdi` 编译 agent 和 rustfrida：

```bash
cargo build -p qbdi-helper --release           # → libqbdi_helper.so
cargo build -p agent --release --features qbdi  # agent 启用 qbdi feature
cargo build -p rust_frida --release --features qbdi  # rustfrida 嵌入 qbdi-helper SO
```

构建 `qbdi-helper` 时会校验 `qbdi/libQBDI.a`：如果文件仍是 LFS pointer 或不是 `ar` archive，会直接报错。NDK 路径按 `NDK_PATH`、`ANDROID_NDK_HOME`、`ANDROID_NDK_ROOT`、`ANDROID_HOME/ndk`、`ANDROID_SDK_ROOT/ndk` 的顺序推断。

运行时 `rustfrida` 会把内嵌的 `libqbdi_helper.so` 发送给 agent；agent 会写入目标 App 私有目录：

```text
/data/user/0/<package>/files/.rustfrida/libqbdi_helper.so
```

这里故意不使用 `/data/local/tmp`，因为普通 App 进程在 SELinux Enforcing 下通常无法访问该目录里的 SO。

QBDI trace 明文 dump 工具：

```bash
cargo build -p qbdi-trace-dump
cargo run -p qbdi-trace-dump -- --limit 200 /path/to/trace_bundle.pb
cargo run -p qbdi-trace-dump -- --summary-only /path/to/trace_bundle.pb
```

**eBPF SO 加载监控（`--watch-so`）：** ldmonitor 是 rustfrida 的编译依赖，默认构建已包含，`--watch-so` 无需额外步骤。如需独立使用 ldmonitor 命令行工具：

```bash
cargo build -p ldmonitor --release    # → ldmonitor 独立二进制
```

**WXSHADOW 内核后端：** stealth1 现在依赖 `/home/qiu/Android/kernel_hook` 下的普通 LKM，而不是旧 KPM。必须先加载 `hook_module.ko`，再加载 `wxshadow_module.ko`：

```bash
cd /home/qiu/Android/kernel_hook
./build_module.sh

cd /home/qiu/Android/kernel_hook/wxshadow
./build_module.sh
./load_with_loader.sh
```

`load_with_loader.sh` 会构建并使用 `/home/qiu/Android/kernel_hook/loader` 的 Rust loader。不要把 `insmod` 当成默认路径；loader 会在设备端解析 ELF、补未定义符号并调用 `init_module`。

### TinyCC 子仓库维护

RF 的 CModule 功能依赖 `quickjs-hook/third_party/tinycc`。该目录是 git submodule，RF 定制修改维护在 `rf/cmodule-runtime` 分支：

```bash
git -C quickjs-hook/third_party/tinycc remote -v
# origin   https://github.com/kkkbbb/tinycc.git
# upstream https://github.com/frida/tinycc.git

git -C quickjs-hook/third_party/tinycc status --short --branch
```

同步上游时，在子仓库 rebase 后更新父仓库的 gitlink：

```bash
git -C quickjs-hook/third_party/tinycc fetch upstream
git -C quickjs-hook/third_party/tinycc rebase upstream/main
git -C quickjs-hook/third_party/tinycc push origin rf/cmodule-runtime

git add quickjs-hook/third_party/tinycc
git commit -m "Update tinycc submodule"
```

如果修改了 TinyCC 本身，先在子仓库提交并 push，再回到父仓库提交 submodule 指针。

## 部署 & 运行

```bash
adb push target/aarch64-linux-android/release/rustfrida /data/local/tmp/

# PID 注入
./rustfrida --pid <pid>
./rustfrida --pid <pid> -l script.js

# Spawn 模式（启动时注入）
./rustfrida --spawn com.example.app
./rustfrida --spawn com.example.app -l script.js

# 等待 SO 加载后注入（eBPF）
./rustfrida --watch-so libnative.so

# 详细日志
./rustfrida --pid <pid> --verbose

# 同步输出日志到文件（终端仍正常输出，文件为纯文本）
./rustfrida --pid <pid> -l script.js -o /data/local/tmp/rustfrida.log
```

### REPL 命令

```
jsinit              # 初始化 JS 引擎
jseval <expr>       # 求值表达式
loadjs <script>     # 执行脚本
jsrepl              # 交互式 REPL（Tab 补全）
exit                # 退出
```

---

## 快速上手

最常见的工作流是：写一个 `script.js`，用 `-l` 加载到目标进程，然后通过日志、RPC 或文件把结果带出来。

```bash
# 已运行的进程
./rustfrida --pid <pid> -l script.js

# 从启动阶段注入，适合抓 Application / ClassLoader 初始化
./rustfrida --spawn com.example.app -l script.js

# 先进入交互，再手动 loadjs / jseval
./rustfrida --pid <pid>
```

最小脚本：

```js
console.log("agent loaded");

Java.ready(function() {
    console.log("Java is ready");
});
```

### 能力地图

| 你想做什么 | 优先使用 | 典型入口 |
| --- | --- | --- |
| Hook Java 方法、改参数/返回值 | `Java.use()` | `Class.method.impl = function (...) { ... }` |
| 高频 Java 方法 Hook | Managed DSL 动态编译器 | `method.dslImpl = script` |
| Hook native 函数并继续跑原函数 | `Interceptor.attach` | `onEnter(args)` / `onLeave(retval)` |
| 完全替换 native 函数 | `hook()` 或 `Interceptor.replace()` | `return value` / 条件性 `this.$orig()` |
| 高频 native Hook | `CModule` + `attachNative` / `hookNative` | `void cb(HookContext *ctx, void *data)` |
| 查找 so、符号、导入导出 | `Module` | `findExportByName()` / `enumerateSymbols()` |
| 读写目标进程内存 | `Memory` / `ptr()` | `p.readU32()` / `p.writeBytes()` |
| 监控 JNI 注册 | `Jni` + native hook | `Jni.addr("RegisterNatives")` |
| 远程触发脚本能力 | HTTP RPC | `rpc.exports = { ... }` |
| 采集指令 trace 用于回放分析 | `qbdi` | `registerTraceCallbacks()` |

### 常见场景

#### Hook Java 方法

适合看业务参数、绕过判断、替换返回值。Spawn 模式下务必放在 `Java.ready()` 里。

```js
Java.ready(function() {
    var Login = Java.use("com.example.LoginManager");

    Login.checkPassword.impl = function(user, pass) {
        console.log("checkPassword", user, pass);
        return true;              // 直接改返回值，不调原方法
    };
});
```

需要保留原逻辑时调用 `$orig()`：

```js
Java.ready(function() {
    var Log = Java.use("android.util.Log");

    Log.i.overload("java.lang.String", "java.lang.String").impl = function(tag, msg) {
        console.log("[Log.i]", tag, msg);
        return this.$orig(tag, msg);
    };
});
```

#### Hook Native 函数并修改参数

只改参数然后继续执行原函数，优先用 `Interceptor.attach({ onEnter })`。

```js
var open = Module.findExportByName("libc.so", "open");

Interceptor.attach(open, {
    onEnter(args) {
        var path = args[0].readCString();
        console.log("open", path);

        if (path.indexOf("/proc/self/maps") >= 0) {
            args[0] = Memory.allocUtf8String("/data/local/tmp/fake_maps");
        }
    }
});
```

#### Hook Native 函数并修改返回值

需要返回值时加 `onLeave`。

```js
var getuid = Module.findExportByName("libc.so", "getuid");

Interceptor.attach(getuid, {
    onLeave(retval) {
        console.log("getuid =>", retval.toUInt32());
        retval.replace(0);
    }
});
```

#### 条件性调用原 native 函数

如果你需要“有时调原函数、有时直接返回”，用 `hook()` 更直接。

```js
var getpid = Module.findExportByName("libc.so", "getpid");

hook(getpid, function() {
    if (Date.now() & 1) {
        return this.$orig();    // 调原函数，参数默认来自当前寄存器
    }
    return 12345;               // 跳过原函数
});
```

#### 监控 RegisterNatives

适合定位 Java native 方法和 so 内真实函数地址。

```js
Interceptor.attach(Jni.addr("RegisterNatives"), {
    onEnter(args) {
        var cls = Jni.env.getClassName(args[1]);
        var methods = Jni.structs.JNINativeMethod.readArray(args[2], Number(args[3]));

        console.log("RegisterNatives:", cls);
        methods.forEach(function(m) {
            var mod = Module.findByAddress(m.fnPtr);
            var where = mod ? mod.name + "+" + m.fnPtr.sub(mod.base) : m.fnPtr.toString();
            console.log("  " + m.name + " " + m.sig + " -> " + where);
        });
    }
});
```

#### 远程调用脚本能力

当你希望工具常驻，然后由 host 脚本、UI 或自动化流程触发功能时，用 `rpc.exports`。

```js
rpc.exports = {
    ping: function() { return "pong"; },
    app: function() {
        var ActivityThread = Java.use("android.app.ActivityThread");
        var app = ActivityThread.currentApplication();
        return String(app.getPackageName());
    }
};
```

启动时加 `--rpc-port`，host 侧通过 `curl` 调用：

```bash
adb forward tcp:9191 tcp:9191
./rustfrida --pid <pid> -l script.js --rpc-port 9191
curl -X POST http://127.0.0.1:9191/rpc/0/ping
```

### 选择建议

- 普通 Java 逻辑先用 `Java.use().impl`，稳定后再考虑 DSL。
- 高频 Java Hook 用 DSL 动态编译器，避免每次命中都进 JS runtime。
- Native 只改参数并继续执行，用 `Interceptor.attach({ onEnter })`。
- Native 需要决定是否调用原函数，用 `hook()` / `Interceptor.replace()`。
- 高频 Native 热路径用 `CModule` 写 C callback，再用 `attachNative` / `hookNative` 安装。
- 不知道用哪个 stealth 模式时先用默认模式；遇到检测或只读代码页问题再切 `Hook.WXSHADOW` / `Hook.RECOMP`。

---

## HTTP RPC 远程调用

脚本里用 Frida 风格的 `rpc.exports` 注册方法，host 端通过 HTTP POST 调用，返回值会 `JSON.stringify` 后透传回来。适合把 agent 当成一个常驻服务用——UI、自动化脚本、测试框架都可以直接 `curl` 触发。

### 启动

在 legacy 单会话或 `--server` 多会话模式下，加上 `--rpc-port` 即可启动 HTTP 服务器。参数可以是纯端口号（默认绑 `0.0.0.0`），也可以是完整地址：

```bash
# legacy 模式：attach + 加载脚本 + 开 RPC 端口
./rustfrida --pid 1234 -l rpc_test.js --rpc-port 9191

# server 模式：多 session 共享同一个 RPC 端口，按 session id 路由
./rustfrida --server --rpc-port 127.0.0.1:9191

# 本机访问通过 adb forward 最简单
adb forward tcp:9191 tcp:9191
```

### JS 侧注册

```js
// 整体替换
rpc.exports = {
    ping: function() { return "pong"; },
    add: function(a, b) { return a + b; },
    echo: function(obj) { return { received: obj, ts: Date.now() }; },

    // 读取当前 App 的 package name + label
    getAppName: function() {
        var ActivityThread = Java.use("android.app.ActivityThread");
        var app = ActivityThread.currentApplication();
        var ctx = app.getApplicationContext();
        var pm = ctx.getPackageManager();
        return {
            packageName: String(ctx.getPackageName()),
            label: String(pm.getApplicationLabel(ctx.getApplicationInfo())),
        };
    }
};

// 或者单独追加
rpc.export('version', function() { return "1.0.0"; });
```

`rpc.exports` 就是个普通 JS 对象，**现场 lookup，不需要向 host 注册方法列表**——你可以任意时刻增删改，下一次 HTTP 请求立刻生效。

### HTTP 路由

| 方法 | 路径 | Body | 说明 |
| --- | --- | --- | --- |
| `GET` | `/` / `/health` | — | 健康检查 |
| `GET` | `/sessions` | — | 列出所有 session（id/pid/label/status）|
| `POST` | `/rpc/<session>/<method>` | JSON 数组 | 调用 `rpc.exports[method].apply(null, args)`；空 body 等价 `[]` |

`<session>` 在 legacy 模式下固定为 `0`，在 `--server` 模式下对应 `list` 命令显示的 id。

### 调用示例

```bash
# 简单调用
curl -X POST http://127.0.0.1:9191/rpc/0/ping
# → {"ok":true,"result":"pong"}

# 位置参数（JSON 数组）
curl -X POST http://127.0.0.1:9191/rpc/0/add -d '[3,4]'
# → {"ok":true,"result":7}

# 对象参数
curl -X POST http://127.0.0.1:9191/rpc/0/echo -d '[{"foo":1,"bar":"hi"}]'
# → {"ok":true,"result":{"received":{"foo":1,"bar":"hi"},"ts":1775806588866}}

# Java 集成
curl -X POST http://127.0.0.1:9191/rpc/0/getAppName
# → {"ok":true,"result":{"packageName":"com.android.settings","label":"设置"}}

# 列出 session
curl http://127.0.0.1:9191/sessions
# → [{"id":0,"pid":1234,"label":"PID:1234","status":"connected"}]
```

成功响应统一是 `{"ok":true,"result":<value>}`；失败是 `{"ok":false,"error":"<msg>"}`，HTTP 状态码 400（参数错）/404（session/method 不存在）/503（session 未连接）/500（JS 异常或超时）。

### 行为约束

- **返回值必须 JSON-safe**：`JSON.stringify` 在 JS 侧执行，函数/循环引用/`undefined` 会被跳过。直接 `return` 一个 Java wrapper 只会得到指针字面量——请手动 `String(obj.method())` 或构造 plain object。
- **并发串行化**：同一 session 内 HTTP 请求排队执行；跨 session 完全并行。
- **超时 30 秒**：超时返回 `{"ok":false,"error":"rpc call timed out"}`。长耗时任务请改用轮询接口。
- **仅同步**：不支持 `async` / Promise——Promise 会被 `JSON.stringify` 成 `{}`。

---

## JS API 参考

### 全局对象一览

`console`, `gc()`, `ptr()`, `Int64`, `UInt64`, `Memory`, `File`, `Process`, `Module`, `DebugSymbol`, `Thread`, `Backtracer`, `Instruction`, `ApiResolver`, `Interceptor`, `Stalker`, `CModule`, `NativeFunction`, `NativeCallback`, `SystemFunction`, `hook()`, `hookNative()`, `attachNative()`, `unhook()`, `callNative()`, `qbdi`, `Java`, `Jni`

### 常用类型别名

| 类型名 | 实际含义 |
| --- | --- |
| `AddressLike` | `NativePointer \| number \| bigint \| "0x..."` |
| `NativePointer` | `ptr()` 创建的指针对象 |
| `JavaObjectProxy` | `Java.use()` / Java hook 中返回的 Java 对象代理 |

### 结构体 / 上下文对象

```ts
type ModuleInfo = {
  name: string; base: NativePointer; size: number; path: string
}

// Native / Java hook 回调都是 Frida 风格：arguments = 参数，this = 上下文载体

type NativeHookThis = {
  x0 ~ x30: bigint             // ARM64 通用寄存器（读/写）
  sp: bigint
  pc: bigint
  trampoline: bigint
  $orig(): bigint              // 调原函数；默认使用当前寄存器（入口原参数，或你已写入的 this.xN）
}

// native hook 写法：
// hook(addr, function(a, b, c) {     // arguments[0..7] = x0..x7（BigInt）
//   this.x0 = ptr("0x1234");          // 改寄存器
//   return this.$orig();              // replace hook 中显式调原函数
// });

type JavaInstanceThis = JavaObjectProxy & {
  // 继承 JavaObjectProxy: 字段 this.field.value / 方法 this.method(args) / this.$className / this.__jptr
  $orig(...args: any[]): any    // 调原方法，不传参用原始参数
}

type JavaStaticThis = {
  $orig(...args: any[]): any
  $className: string
  $static: true
}

// hook 写法：
// Cls.method.impl = function(a, b, c) {   // arguments = Java 参数（对象自动 Proxy）
//   this.$className           // 始终可读
//   this.field.value          // 实例方法: 直接读字段
//   return this.$orig(a, b, c) // 调原方法
// }

// Interceptor.attach 双阶段：args 是 NativePointer 代理（args[0] = x0），
// retval 支持 .replace() / .toInt32()；this 在 onEnter/onLeave 之间共享
type InterceptorArgs = {
  [i: number]: NativePointer    // args[0..30] ⇄ ctx.x0..x30（读/写）
}
type InterceptorRetval = NativePointer & {
  replace(v: AddressLike): void // 改返回值
  toInt32(): number
  toUInt32(): number
}
type InterceptorThis = {
  x0 ~ x30: bigint; sp: bigint; pc: bigint
  lr: bigint; returnAddress: bigint
  // + 用户自定义字段，onEnter/onLeave 跨阶段共享（Frida 兼容）
}
type InvocationListener = { detach(): boolean }

type JniEntry = { name: string; index: number; address: NativePointer }

type JNINativeMethodInfo = {
  address: NativePointer; namePtr: NativePointer; sigPtr: NativePointer
  fnPtr: NativePointer; name: string | null; sig: string | null
}
```

---

## Native Hook

Frida 风格：**`arguments`** = x0..x7（前 8 个整型参数，BigInt），**`this`** = register 上下文（含 x0-x30 / sp / pc / $orig）。

```js
// 固定继续执行原函数：用 attach，不要用 hook()+$orig() 透传
Interceptor.attach(Module.findExportByName("libc.so", "open"), {
    onEnter(args) {
        console.log("open:", args[0].readCString(), "flags=" + args[1]);
    }
});

// 修改返回值（直接 return 覆盖）
hook(Module.findExportByName("libc.so", "getpid"), function() {
    return 12345;              // 调用方拿到 12345
});

// 条件性调用原函数：用 hook()/replace；无参数 $orig() 会使用当前 this.xN
hook(target, function(a, b) {
    if (Number(a) === 0) {
        return -1;             // 跳过原函数
    }
    this.x0 = ptr("0x1234");   // 改第一个参数
    this.x1 = 100;             // 改第二个参数
    return this.$orig();       // 用当前寄存器调原函数
});

// 不 return 也行 — this.x0 赋值会同步回 C 层
hook(Module.findExportByName("libc.so", "getuid"), function() {
    this.$orig();
    this.x0 = 77777;          // 调用方拿到 77777
});

// 移除 hook
unhook(Module.findExportByName("libc.so", "open"));

// 直接调用 native 函数（最多 6 个参数，走 x0-x5）
var pid = callNative(Module.findExportByName("libc.so", "getpid"));
```

### NativeFunction / SystemFunction / NativeCallback

默认 agent 构建启用 Frida FFI，提供 Frida 兼容的 `NativeFunction`、`SystemFunction` 和 `NativeCallback`。三者都是 `NativePointer` 子类；`NativeFunction`/`SystemFunction` 还是可调用对象，并支持 `call()` / `apply()` 通过 receiver 临时覆盖调用地址。

```js
var open = new NativeFunction(
    Module.findExportByName("libc.so", "open"),
    "int",                            // 返回类型
    ["pointer", "int"]                // 参数类型
);
var fd = open(Memory.allocUtf8String("/tmp/foo"), 0);

var atan2 = new NativeFunction(
    Module.findExportByName("libm.so", "atan2"),
    "double",
    ["double", "double"]
);
atan2(1.0, 2.0);

var openWithErrno = new SystemFunction(
    Module.findExportByName("libc.so", "open"),
    "int",
    ["pointer", "int"]
);
var result = openWithErrno(Memory.allocUtf8String("/missing"), 0);
console.log(result.value, result.errno);
```

**支持的类型**：`void`, `bool`, `char`/`uchar`, `int8`/`uint8`, `short`/`ushort`, `int16`/`uint16`, `int`/`uint`, `int32`/`uint32`, `long`/`ulong` (64-bit), `int64`/`uint64`, `size_t`/`ssize_t`, `pointer`, `float`, `double`。

结构体按 Frida 的嵌套数组类型描述，例如 `["int32", "int32"]`；参数和返回值均支持 struct-by-value。变参签名使用 `"..."` 分隔固定参数和变参类型，小整数与 `float` 会按 C 默认规则提升：

```js
var Pair = ["int32", "int32"];
var transformPair = new NativeFunction(address, Pair, [Pair, "int32"]);
var pair = transformPair([10, 20], 3);

var sum = new NativeFunction(sumAddress, "double", ["int", "...", "float"]);
sum(2, 1.25, 2.5);
```

第四个参数接受 ABI 字符串或 options：Android ARM64 支持 `abi: "default" | "sysv"`、`scheduling: "cooperative" | "exclusive"`、`exceptions: "steal" | "propagate"` 和 `traps: "default" | "none" | "all"`。`SystemFunction` 使用同样的签名和 options，但返回 `{ value, errno }`；`exceptions: "steal"` 会把 native fault 转成带 `type/address/memory` 的 JavaScript 异常。

`NativeCallback` 将 JavaScript 函数变成可传给 C API、`Interceptor.replace()` 或 Stalker 原生 callback 位置的函数指针：

```js
var compare = new NativeCallback(function(left, right) {
    console.log(this.returnAddress, this.errno);
    return left - right;
}, "int", ["int", "int"], "sysv");
```

callback 可从任意 native 线程同步进入 JS，并允许在 callback 内重入 `NativeFunction`。`this.errno` 可读写当前线程的 system error，`this.returnAddress` 是调用方地址。native 注册点会持有 callback root，因此 JavaScript GC 不会提前释放 thunk；reload/shutdown 会先切断入口并等待 in-flight 调用，再释放 JS 引用。为避免 native 端保存旧函数指针后发生 UAF，可执行 closure 会退休到进程结束，退休后的旧指针只返回零且不会再次进入 JS。`gc()` 可显式触发当前 QuickJS runtime 的垃圾回收。

仅直接构建未启用 `frida-ffi` feature 的 `quickjs-hook` 时，使用 ARM64 标量 fallback：整数/指针填 x0-x7、浮点填 d0-d7，溢出参数走栈；该 fallback 不支持 struct、variadic 和高级 options。


### CModule 和 native C callback

`CModule` 用内置 TinyCC 在目标进程里动态编译 C 代码，适合把高频 native hook 的热路径从 JS callback 下沉到 C callback。CModule 对象持有编译后的代码内存；只要 hook 还在使用其中的函数指针，就必须保留 JS 引用，避免 GC 释放代码。

```js
var cm = new CModule(`
    #include <rfhook.h>

    void on_getuid(HookContext *ctx, void *user_data) {
        uint64_t real = hook_invoke_trampoline(ctx, ctx->trampoline);
        ctx->x[0] = (real == 0 ? 0 : 20000);
    }
`);

globalThis.keep_getuid_cmodule = cm;        // hook 存活期间必须保留引用

var getuid = Module.findExportByName("libc.so", "getuid");
var trampoline = hookNative(getuid, cm.on_getuid);
```

`hookNative(target, callbackPtr, userData?, mode?)` 是 replace 语义：原函数不会自动执行。需要原函数时，在 C callback 里调用 `hook_invoke_trampoline(ctx, ctx->trampoline)`；不需要原函数时直接改 `ctx->x[0]`。

```js
var cm = new CModule(`
    #include <rfhook.h>

    struct Counter {
        uint64_t calls;
    };

    void on_enter(HookContext *ctx, void *user_data) {
        struct Counter *counter = (struct Counter *) user_data;
        counter->calls++;
        ctx->x[1] = 0;        // 改第二个参数
    }

    void on_leave(HookContext *ctx, void *user_data) {
        if ((int64_t) ctx->x[0] < 0) {
            ctx->x[0] = 0;    // onLeave 中 x0 是返回值
        }
    }
`);

globalThis.keep_open_cmodule = cm;

var state = Memory.alloc(8);
state.writeU64(0);

var open = Module.findExportByName("libc.so", "open");
attachNative(open, {
    onEnter: cm.on_enter,
    onLeave: cm.on_leave,
    data: state,
    mode: Hook.NORMAL
});
```

`attachNative(target, { onEnter?, onLeave?, data?, mode? })` 是 attach 语义：hook engine 会自动执行原函数。只提供 `onEnter` 时走 tail-jump 快路径，不保留 leave 状态；提供 `onLeave` 时才会在原函数返回后进入 leave callback。`onEnter` 和 `onLeave` 的 C 函数签名相同：

```c
void callback(HookContext *ctx, void *user_data);
```

两者区别只在时机和 `ctx` 内容：

| 阶段 | `ctx->x[0..]` 含义 | 原函数 |
| --- | --- | --- |
| `onEnter` | 入参寄存器，可改参数 | 返回后自动执行 |
| `onLeave` | `x0` 是返回值，可改返回值 | 已经执行完 |

如果安装了 `onLeave`，`onEnter` 可用 `ctx->intercept_leave = 0` 跳过本次 leave；没有安装 `onLeave` 时设置这个字段没有意义。

CModule 默认注入这些头：`stdint.h`, `stddef.h`, `stdbool.h`, `string.h`, `rfhook.h`。`rfhook.h` 暴露 `HookContext`、`RfHookCallback` 和 `hook_invoke_trampoline()`：

```c
typedef struct {
    uint64_t x[31];
    uint64_t sp;
    uint64_t pc;
    uint64_t nzcv;
    void *trampoline;
    uint64_t d[8];
    uint64_t intercept_leave;
} HookContext;

typedef void (*RfHookCallback)(HookContext *ctx, void *user_data);
uint64_t hook_invoke_trampoline(HookContext *ctx, void *trampoline);
```

也可以把 JS 侧找到的 native symbol 传给 CModule：

```js
var cm = new CModule(`
    extern int puts(const char *);

    void say_hi(void) {
        puts("hello from CModule");
    }
`, {
    puts: Module.findExportByName("libc.so", "puts")
});

new NativeFunction(cm.say_hi, "void", [])();
```

调试符号：

```js
console.log(cm.base, cm.size);
console.log(cm.findSymbolByName("on_enter"));
cm.dropMetadata();     // 可选：释放 TinyCC 元数据；函数代码仍保留到 CModule 被 GC
```

### Interceptor（Frida 兼容双阶段）

Frida 原生语法。`hook()` 是 replace 单阶段，通过 `this.$orig()` 手动调用原函数；`Interceptor.attach` 自动执行原函数并提供 `onEnter` / `onLeave` 双阶段拦截，`this` 在两阶段之间共享。

```js
// 双阶段 attach: onEnter 前置 + 自动调原函数 + onLeave 后置
var listener = Interceptor.attach(Module.findExportByName("libc.so", "open"), {
    onEnter(args) {
        // args[0..30] 是 NativePointer 代理，args[N] = value 会写回 xN
        this.path = args[0].readCString();
        this.t0 = Date.now();
    },
    onLeave(retval) {
        // retval 是 NativePointer，.replace(v) 改返回值
        console.log("open(" + this.path + ") = " + retval.toInt32()
                  + " took " + (Date.now() - this.t0) + "ms");
        if (retval.toInt32() < 0) retval.replace(0);
    }
});
listener.detach();

// 仅 onEnter — 改参数后让原函数自己跑（C 侧走 tail-jump 快路径，无栈帧残留）
Interceptor.attach(target, {
    onEnter(args) { args[1] = ptr(100); }
});

// Interceptor.replace — 完全替换（等价于 hook()，不跑原函数）
Interceptor.replace(Module.findExportByName("libc.so", "getpid"), function() {
    return 1234;
});

// 清理：单个 / 全部
listener.detach();
Interceptor.detachAll();
Interceptor.flush();           // no-op，兼容脚本
```

第三参数可选 stealth 模式（同 `hook()`）：`Interceptor.attach(target, cbs, Hook.WXSHADOW)`。

### Native Hook 怎么选

先按你的目标选择 API，再按检测强度选择 `stealth` 参数。

| 目标 | 推荐写法 | 原函数 | 说明 |
| --- | --- | --- | --- |
| 只看参数 | `Interceptor.attach(target, { onEnter })` | 自动执行 | 日志、统计、轻量过滤 |
| 改参数后继续执行 | `Interceptor.attach(target, { onEnter })` | 自动执行 | `args[n] = value` 会写回参数 |
| 看返回值或改返回值 | `Interceptor.attach(target, { onLeave })` | 自动执行 | `retval.replace(v)` 改返回值 |
| 有时跳过原函数 | `hook(target, fn)` | 手动 `this.$orig()` | 适合条件分支、绕过、完整替换 |
| Frida replace 风格 | `Interceptor.replace(target, fn)` | 手动 | 等价于 `hook(target, fn)` |
| 高频 C callback | `attachNative(target, {onEnter, onLeave})` | 自动执行 | CModule 热路径，支持 onEnter/onLeave |
| 高频完整替换 | `hookNative(target, callback)` | 手动 | CModule replace，回调内按需 `hook_invoke_trampoline(ctx, ctx->trampoline)` |

选择建议：

- 只改参数并继续跑原函数：优先用 `Interceptor.attach(..., { onEnter })`。
- 需要“有时调原函数、有时直接返回”：用 `hook()` / `Interceptor.replace()`，在回调里显式 `this.$orig()`。
- 固定调原函数：用 `Interceptor.attach` / `attachNative`，无 `onLeave` 时直接 tail-jump 原函数，不再回到 hook 代码。
- 高频热路径不要无条件 `this.$orig()` 透传；这种场景 `attach onEnter` 更省，或者把逻辑下沉到 DSL / native fast path。

### Stealth 模式

```js
hook(target, callback, Hook.NORMAL)     // 0: mprotect 直写（默认）
hook(target, callback, Hook.WXSHADOW)   // 1: wxshadow_module prctl 写入，需先加载内核模块
hook(target, callback, Hook.RECOMP)     // 2: 代码页重编译，仅 4B patch
hook(target, callback, 1)               // 数字也行
hook(target, callback, true)            // true = WXSHADOW
```

`Hook.WXSHADOW` 通过 `prctl(PR_WXSHADOW_PATCH, pid, addr, buf, len)` 调用 `wxshadow_module.ko`。本地 hook engine 会保存原字节，`unhook()` / `listener.detach()` / cleanup 时再通过同一 prctl 路径恢复。失败不会降级到 `mprotect`，否则会破坏 stealth1 的检测边界。

使用前确认内核模块已按顺序加载：

```bash
cd /home/qiu/Android/kernel_hook/wxshadow
./load_with_loader.sh
```

### API 速查

| API | 参数 | 返回 |
| --- | --- | --- |
| `hook(target, callback, stealth?)` | `AddressLike, Function, number?` | `boolean` |
| `unhook(target)` | `AddressLike` | `boolean` |
| `Interceptor.attach(target, {onEnter?, onLeave?}, stealth?)` | `AddressLike, Object, number?` | `InvocationListener` |
| `Interceptor.replace(target, replacement, stealth?)` | `AddressLike, Function, number?` | `boolean` |
| `Interceptor.detachAll()` | — | `undefined` |
| `listener.detach()` | — | `boolean` |
| `CModule(source, symbols?)` | `string, Object?` | `CModule` |
| `hookNative(target, callbackPtr, data?, stealth?)` | `AddressLike, NativePointer, AddressLike?, number?` | `NativePointer` trampoline |
| `attachNative(target, callbackPtr, data?, stealth?)` | `AddressLike, NativePointer, AddressLike?, number?` | `boolean` |
| `attachNative(target, {onEnter?, onLeave?, data?, mode?})` | `AddressLike, Object` | `boolean` |
| `callNative(func, ...args)` | `AddressLike, ...AddressLike` (最多6个) | `number \| bigint` |
| `new NativeFunction(addr, retType, argTypes, options?)` | `AddressLike, NativeType, NativeType[], object?` | `NativePointer & Function` |
| `new SystemFunction(addr, retType, argTypes, options?)` | `AddressLike, NativeType, NativeType[], object?` | 返回 `{value, errno}` 的可调用指针 |
| `new NativeCallback(fn, retType, argTypes, abi?)` | `Function, NativeType, NativeType[], string?` | `NativePointer` callback thunk |
| `gc()` | — | `undefined` |
| `diagAllocNear(addr)` | `AddressLike` | `undefined` |

---

## Java Hook

Frida 风格：**`this`** = 实例（静态方法时为 class 载体），**`arguments`** = Java 参数。

```js
Java.ready(function() {
    var Activity = Java.use("android.app.Activity");

    // hook 实例方法
    Activity.onResume.impl = function() {
        console.log("onResume:", this.$className);  // this = 实例 Proxy
        return this.$orig();                         // 调原方法
    };

    // hook 构造函数（参数走 arguments）
    var MyClass = Java.use("com.example.MyClass");
    MyClass.$init.impl = function(a, b) {
        console.log("new MyClass, arg0 =", a);
        return this.$orig(a, b);
    };

    // 修改参数传给原方法
    MyClass.test.impl = function(arg) {
        return this.$orig("patched_arg");
    };

    // 指定 overload（Java 类型名或 JNI 签名都行）
    MyClass.foo.overload("int", "java.lang.String").impl = function(i, s) {
        return this.$orig(i, s);
    };

    // 静态方法：this 没有实例 Proxy，但 $orig / $className / $static 可用
    Java.use("android.util.Log").i
        .overload("java.lang.String", "java.lang.String").impl = function(tag, msg) {
            console.log("[static]", this.$className, this.$static, tag, msg);
            return this.$orig(tag, msg);
        };

    // 直接返回值覆盖（不调 $orig）
    MyClass.getCount.impl = function() { return 42; };

    // 移除 hook
    Activity.onResume.impl = null;
});
```

### Java.use 对象操作

```js
var JString = Java.use("java.lang.String");
var s = JString.$new("hello");     // 创建对象
console.log(s.length());           // 调实例方法
console.log(s.$className);         // 类名

var Process = Java.use("android.os.Process");
console.log(Process.myPid());      // 调静态方法

// $new 重载（Frida 兼容 .overload(...)）
var bytes = [65, 66, 67];
var s2 = JString.$new.overload("[B")(bytes);   // String(byte[])
var s3 = JString.$new.overload("java.lang.String")("copy");  // String(String)

// 方法重载
var Arr = Java.use("java.util.Arrays");
Arr.toString.overload("[I")([1, 2, 3]);   // 锁定 int[] 版本
Arr.asList.overload("[Ljava.lang.Object;")([1, "mix", obj]);
```

### 字段访问（Frida 兼容 .value 模式）

字段通过 `.value` 读写，每次直接走 JNI，无缓存锁：

```js
// 静态字段
var Build = Java.use("android.os.Build");
console.log(Build.MODEL.value);          // 读: "Pixel 6"
Build.MODEL.value = "FakeModel";         // 写

// 实例字段（hook 回调中 / $new 创建的对象）
var Point = Java.use("android.graphics.Point");
var p = Point.$new(10, 20);
console.log(p.x.value, p.y.value);      // 读: 10, 20
p.x.value = 100;                         // 写: JVM 同步更新
console.log(p.toString());               // "Point(100, 20)"

// hook 中访问 this 字段
Activity.onResume.impl = function() {
    var name = this.mComponent.value;   // 读实例字段
    console.log("resuming:", name);
    return this.$orig();
};
```

**字段/方法同名**：Java 允许同名字段和方法共存。此时返回 hybrid——既可调用（方法）又有 `.value`（字段）：

```js
var map = HashMap.$new();
map.size();        // 调用 size() 方法
map.size.value;    // 读取 size 字段
```

### Java.ready

Spawn 模式下 app ClassLoader 未就绪，用 `Java.ready` 延迟执行。PID 注入模式下立即执行。

### Managed DSL 高频 Hook

DSL 是为应对高频 Java hook 开发的小型 JS-Java 动态编译器。普通 `Java.use().impl = function (...) { ... }` 每次命中都会进入 JS runtime；DSL 会把受限的 JS/Java 风格代码编译成 dex callback，让热路径在 ART/Java 侧执行，适合已进入 compiled/JIT quick code 的高频 Java 方法。DSL 后续会继续优化语法、类型推断和可用能力。

DSL 只支持独立 quick entrypoint，不会为 nterp/shared ART entrypoint 安装共享入口路由。目标方法仍在解释器或 shared entry 上时，`dslImpl` 会直接报错；先显式调用 `method.opt("auto")` / `method.compile("auto")`，确认方法被编译后再安装 DSL。

#### 什么时候用 DSL

| 场景 | 建议 |
| --- | --- |
| 低频、调试、需要 JS 对象/闭包/console | 用 `impl` |
| 高频、只做判断/改参数/改返回/计数 | 用 DSL |
| 高频里需要少量数据回 JS | DSL 里 `send()`，JS 侧低频 `dslRead()` / `dslDrain()` |
| 逻辑还不稳定 | 先用 JS callback 探路，稳定后搬到 DSL |

DSL 语法接近 JS/Java，但不是完整 JS runtime。它不能访问 JS 变量、闭包、`console.log`、`setInterval`、Promise。把它理解成“写在 JS 字符串里的 Java 热路径代码”更准确。

#### 最推荐写法

```js
Java.ready(function () {
    var HashMap = Java.use("java.util.HashMap");
    var put = HashMap.put.overload("java.lang.Object", "java.lang.Object");

    console.log(JSON.stringify(put.opt("auto")));

    put.dsl({ buff: 4096 }).dslImpl = `
        count("put");

        let n: int = this.size();
        let has: boolean = this.containsKey(arg0);
        let selected: java.lang.Object = (arg0 != null ? arg0 : arg1);

        if ((n & 1023) == 0) {
            send("size", n);
        }

        if (has && selected != null) {
            java.lang.String.valueOf(selected);
        }

        return orig(arg0, arg1);
    `;

    // JS 侧低频拉取 DSL 发出的消息。不要在 DSL 热路径里 print 或进 JS。
    var drained = HashMap.put.dslRead(64);
    for (var i = 0; i < drained.length; i++) {
        var m = drained[i];        // { name: "size", value: 123, code: 1 }
        console.log(m.name, m.value);
    }
});
```

#### 不指定 overload

```js
HashMap.put.dslImpl = `
    count("put");
    return orig();
`;
```

不指定 overload 时，会把同一段 DSL 批量安装到该方法名的全部 overload。适合 DSL 只用 `orig()`、`count()` 这类不依赖具体参数签名的场景。

如果 DSL 里使用了固定参数数量、固定返回类型、某个特定字段/方法调用，建议显式 `.overload(...)`，错误信息也会更直接。

#### DSL 内置名字

| 名称 | 含义 |
| --- | --- |
| `this` | 实例方法的当前对象；静态方法中没有普通实例 |
| `arg0`, `arg1`, ... | Java 方法参数 |
| `orig()` / `orig(a, b, ...)` | 调原方法；可放在任意位置 |
| `last` | 上一条对象表达式语句的结果 |
| `result` | 部分调用/字段访问结果的临时目标；通常优先用局部变量接住 |

常见返回方式：

```js
return orig();             // 原参数调用原方法
return orig(arg0, arg1);   // 改参数后调用原方法
return null;               // 对象返回值可返回 null
return 0;                  // int/boolean 等按目标返回类型校验
return;                    // void 方法
```

#### 变量和类型

类型能推断时可以省略，但高频 hook 里建议复杂对象写清类型，方便 overload 推断和 dex 校验。

```js
let n: int = this.size();
let selected: java.lang.Object = (arg0 != null ? arg0 : arg1);
let text: java.lang.String = java.lang.String.valueOf(selected);

let obj: java.lang.Object;    // 无初始化时必须写类型，默认 null/0/false
let asObj: java.lang.Object = text as java.lang.Object;
```

`let` / `var` 当前都按块作用域处理。

#### 方法调用

```js
let n: int = this.size();                         // 实例方法
let s: java.lang.String = java.lang.String.valueOf(arg0); // 静态方法
```

overload 能唯一推断时直接写 `obj.method(arg)`。报歧义时显式指定：

```js
this.get.overload("java.lang.Object")(arg0);
java.lang.String.valueOf.overload("java.lang.Object")(arg0);
```

接口接收者通常会自动走 interface 调用。推断不出来时显式写：

```js
it.hasNext.interface.overload("java.util.Iterator", "()Z")();
```

#### 字段访问

字段用 Java 原生风格写：无括号是字段，有括号是方法。

```js
let v: int = this.someField;
this.someField = 123;
this.someField += 1;
this.someField++;

let name: java.lang.String = com.example.Config.name;
com.example.Config.name = "patched";
```

字段按 Java 访问逻辑解析：从接收者静态类型开始查找，子类字段隐藏父类同名字段时优先子类；如果局部变量声明成父类类型，就访问父类字段。

#### 创建对象和数组

构造函数按普通 Java/JS 直觉写，参数类型会自动推断并选择唯一匹配的 constructor overload：

```js
let sb: java.lang.StringBuilder = new java.lang.StringBuilder("hi");
let copy: java.lang.StringBuilder = java.lang.StringBuilder.$new(sb);
let list: java.util.ArrayList = new java.util.ArrayList();
```

如果构造 overload 歧义，才把完整 JNI 构造签名放在第一个参数：

```js
let sb: java.lang.StringBuilder = new java.lang.StringBuilder("(Ljava/lang/String;)V", "hi");
```

数组：

```js
let arr: int[] = new int[4];
arr[0] = 7;
arr[0]++;

let objs: java.lang.Object[] = [arg0, arg1, null];
let first: java.lang.Object = objs[0];
let len: int = objs.length;
```

#### 条件和控制流

条件、三元、循环按 JS/Java 直觉写即可。几个差异点：

- 可能为 null 的对象必须先保护：`obj != null && obj.method()`。
- `switch case` 需要用 `{ ... }` 包住语句块。
- `try` 支持 `catch`，暂不支持 `finally`。
- 整数字面量当前按 int16 解析；较大常量建议通过 Java 字段/方法或计算得到。

```js
if (arg0 != null && this.containsKey(arg0)) {
    count("hit");
}

let selected: java.lang.Object = (arg0 != null ? arg0 : arg1);

if ((this.size() & 1023) == 0) {
    send("size", this.size());
}

switch (this.size()) {
    case 0: { return orig(arg0, arg1); }
    default: { count("nonzero"); }
}

try {
    java.lang.String.valueOf(arg0);
} catch (java.lang.Throwable e) {
    return orig(arg0, arg1);
}
```

#### DSL 和外部通信

`count("name")` 是热路径计数器，适合确认 DSL 是否命中。

DSL 热路径不会直接回调 JS，也不会直接和 host 通信。`count()` 和 `send()` 都编译进生成的 dex helper：

- `count("name")` 更新 helper 类里的 `static volatile int` 计数器。
- `send("channel", value)` 把消息写入 helper 类里的固定大小环形缓冲区。
- JS 侧在低频位置主动拉取这些数据，再用 `console.log`、RPC 或脚本逻辑发给外部。

这意味着高频命中时不会进入 QuickJS runtime；外部通信是“热路径写缓冲区，冷路径批量读取”的模型。

JS 侧有三层读取 API：

| API | 用途 |
| --- | --- |
| `method.dslRead(max)` | 推荐封装，返回 `{ code, name, value }` 数组 |
| `method.dslTake(name, max)` | 只读取某个 channel，返回 value 数组 |
| `method.dslDrain(max)` | 读取原始消息数组，不补 channel name |
| `Java.managedDrainMessages(info, max)` | 底层 API，直接按 `dslInfo` drain |

示例：

```js
// DSL
send("size", this.size());
send("text", java.lang.String.valueOf(arg0));

// JS
var items = HashMap.put.dslRead(128);
items.forEach(function (m) {
    if (m.name === "size") console.log("size =", m.value);
    if (m.name === "text") console.log("text =", m.value);
});

// 只取某个通道，直接拿 value 数组
var sizes = HashMap.put.dslTake("size", 128);

// 底层读取接口；info 可以是 method.dslInfo 或 Java.managedHookDsl(...) 的返回值
var raw = Java.managedDrainMessages(HashMap.put.dslInfo, 128);
```

限制：

- `send()` 的值只能是 `int` 或 `java.lang.String`。
- `buff` 是环形缓冲区容量，默认 `4096`，必须是 2 的幂，最大 `1048576`。
- 缓冲区满时会丢弃新的消息并增加 `dropped` 计数，热路径不会阻塞。
- `Java.managedDrainMessages()` 返回的数组带有 `head`、`tail`、`dropped`、`capacity` 属性；`dslRead()` 会补上 channel name。
- 高频方法里不要每次都 `send()`，除非你明确能接受缓冲区覆盖。需要完整流量时应把逻辑放在 DSL 内完成，只低频上报结果。

#### 调试和排错

确认 DSL 是否安装成功：

```js
console.log(JSON.stringify(HashMap.put.dslInfo));
```

常见错误：

| 错误/现象 | 处理 |
| --- | --- |
| `receiver ... may be null` | 加 `obj != null && obj.method()` |
| overload 歧义 | 写 `.overload(...)`，或给局部变量补类型 |
| 字段解析失败 | 确认接收者静态类型、字段名和 static/instance 用法 |
| `send() value must be int or java.lang.String` | 先 `String.valueOf(obj)` 或只发 int |
| 不指定 overload 后某个签名安装失败 | 改成显式 `.overload(...)` 分签名安装 |
| 想在 DSL 里 `console.log` | 不支持；用 `count()` / `send()` |

#### 高频写法

- 尽量让 DSL 内部完成判断、计数、返回值修改，只把摘要通过 `send()` 发给 JS。
- 不要把每次命中的完整数据都发回 JS；这会把问题重新变成跨 runtime 压力。
- 不要在 DSL 中做无界循环、阻塞等待、频繁分配大对象。
- 复杂对象、复杂返回值优先写清类型。
- 需要 hook 复杂业务对象时，先用 JS callback 探路，稳定后把热路径搬到 DSL。

### Java.choose 枚举存活实例（Frida 兼容）

扫描 ART 堆，把目标类的所有存活实例交给 `onMatch`：

```js
Java.choose("android.app.Activity", {
    onMatch: function(instance) {
        console.log(instance.$className, "=>", instance.toString());
        // return "stop";   // 提前终止
    },
    onComplete: function() { console.log("done"); },
    subtypes: true,         // 包含子类（rustFrida 扩展）
    maxCount: 1000          // 最多枚举数量，默认 16384；0 = 不限
});

// 第三参等价 subtypes（位置参数形式）
Java.choose("java.util.List", { onMatch: fn }, true);
```

**生命周期**：传给 `onMatch` 的 wrapper **仅在 onMatch 执行期间有效**。函数返回后 `__jptr` 被置 0。若要跨回调保留实例，请在 `onMatch` 内调 `String(obj.method())` 拷字段，或自行 `NewGlobalRef`。

**后端**：Android ≤13 走 `VMDebug.getInstancesOfClasses`；API 36 自动降级为堆暴力扫描。

### ClassLoader 控制

```js
var loaders = Java.classLoaders();             // → 数组: app + boot + system
Java.setClassLoader(loaders[0]);               // 切换 Java.use() 查找上下文
var MyCls = Java.findClassWithLoader(loaders[0], "com.example.MyClass");
```

`loader` 参数接受 loader 对象、`{__jptr}` wrapper 或 `NativePointer`。Spawn 模式下 app loader 就绪前 `Java.classLoaders()` 可能只返回 boot loader，应在 `Java.ready()` 里调。

### Stealth 模式（Java hook）

```js
Java.setStealth(0);  // Normal: mprotect 直写
Java.setStealth(1);  // WxShadow: wxshadow_module prctl 后端
Java.setStealth(2);  // Recomp: 代码页重编译
Java.getStealth();   // 查询当前模式 (0/1/2)
```

须在 `Java.use().impl` 之前设置。`Java.setStealth(1)` 同样要求设备端已加载 `hook_module.ko + wxshadow_module.ko`。

### Deopt API

```js
Java.deopt();                  // 清空 JIT 缓存（InvalidateAllMethods）
Java.deoptimizeBootImage();    // boot image AOT 降级为 interpreter (API >= 26)
Java.deoptimizeEverything();   // 全局强制解释执行
Java.deoptimizeMethod("com.example.Test", "foo", "(I)V");  // 单方法降级
```

手动调用的工具函数，hook 流程不自动使用。

### 类型 Marshal 规则（Java ↔ JS 自动转换）

Hook 回调的 `arguments`、`$orig()` / `Class.method()` 返回值、字段 `.value` 读写、`Java.choose` 的 `onMatch` 参数都走同一套 marshal 规则。

#### Java → JS（参数 / 返回值 / 字段读）

**自动转换为原生 JS 值：**

| Java 类型 | JNI 签名 | JS 值 | 说明 |
| --- | --- | --- | --- |
| `boolean` | `Z` | `boolean` | |
| `byte` | `B` | `number` | 有符号 i8 |
| `char` | `C` | `string` | 长度为 1 的字符串 |
| `short` | `S` | `number` | i16 |
| `int` | `I` | `number` | i32 |
| `long` | `J` | `BigInt` | u64 |
| `float` | `F` | `number` | |
| `double` | `D` | `number` | |
| `java.lang.String` | `Ljava/lang/String;` | `string` | 走 `GetStringUTFChars` |
| `null` | — | `null` | |
| Java 原始类型数组 `T[]`（T 为 Z/B/C/S/I/J/F/D）| `[T` | `Array` of 对应 JS 值 | 一次 `GetXxxArrayRegion` 批量拷贝，无装箱 |
| Java 对象数组 `T[]` | `[LT;` | `Array` of wrapper（或 `string` 若 T=`String`）| 逐个 `GetObjectArrayElement` |
| Java 嵌套数组 `[[...` | `[[X` | `Array` of Array（递归 marshal）| 深度不限 |

**保留为 Java wrapper `{__jptr, __jclass}`（不自动转换，需手动处理）：**

- **装箱类型 NOT unboxed**：`Integer` / `Long` / `Float` / `Double` / `Boolean` / `Byte` / `Short` / `Character` 全部返回 wrapper，**不会**自动变成 JS number/boolean。需要原始值手动转：
  ```js
  var n = boxed.intValue();              // Integer → int
  var d = boxed.doubleValue();           // Double → number
  var s = String(boxed);                 // 走 toString
  ```
- **容器不展开**：`List` / `Map` / `Set` / `ArrayList` / `HashMap` 等保留 wrapper，手动遍历：
  ```js
  var list = obj.getList();
  for (var i = 0; i < list.size(); i++) {
      var item = list.get(i);            // 仍是 wrapper（除非是 String）
  }
  var keys = map.keySet().toArray();     // → JS Array of wrappers
  ```
- **其他任意对象类型**：用户类、`Context`、`Activity`、`File` 等一律 wrapper，通过 `.method()` / `.field.value` 链式访问。

**`$new` 强制 wrapper 特例**：`Java.use("java.lang.String").$new("hi")` 即使构造出 String 也保留为 wrapper（便于链式 `.length()` / `.charAt()`）——这是唯一跳过 String → JS string 自动转换的场景。

#### JS → Java（`$orig(args)` / `Class.method(args)` / 字段写 / `$new(args)`）

按目标参数的 JNI 签名 marshal：

| 目标签名 | 接受的 JS 值 |
| --- | --- |
| `Z` | `boolean` / `number`（非零即 true）|
| `B` / `S` / `I` / `J` | `number` / `BigInt` |
| `C` | `string`（取首字符）/ `number` |
| `F` / `D` | `number` |
| `Ljava/lang/String;` 或任意 `L...;` 场景下的 JS string | → `NewStringUTF` |
| 任意 `L...;`（已是 Java 对象）| `{__jptr}` wrapper / `Proxy` → 提取原始 jobject 指针 |
| 装箱类型 `Ljava/lang/Integer;` 等 | JS number/boolean/bigint 走 **autobox**（JNI `Xxx.valueOf()`）|
| `[B` / `[Z` / `[C` / `[S` / `[I` / `[J` / `[F` / `[D` | JS `Array` → `NewXxxArray + SetXxxArrayRegion` 批量填 |
| `[Ljava/lang/String;` | JS `Array` of string → 逐个 `NewStringUTF + SetObjectArrayElement` |
| `[Lxxx;` 任意引用数组 | 每个元素按 `Lxxx;` 递归 marshal（string / Proxy `__jptr` / autobox）|
| `[[X` / `[[Lxxx;` 嵌套数组 | 递归进入 `[X` 分支创建内层 Java 数组 |
| `Ljava/lang/Object;` / `Ljava/io/Serializable;` + JS Array | 自动降级 `Object[]`（元素按 `Ljava/lang/Object;` 再 marshal）|
| 任意类型 | `null` / `undefined` → JNI null (0) |

**autobox 规则**：目标签名精确匹配时按目标类型装箱（`Ljava/lang/Long;` → `Long.valueOf(J)`）；无精确签名时按 JS 值推断 —— 整数 fit i32 → `Integer`，否则 → `Double`；boolean → `Boolean`。

**多 overload 自动消歧（数组按元素范围打分）**：

```js
void foo(byte[] b)
void foo(int[] i)
void foo(long[] l)
```

| JS 输入 | `[B` 分 | `[S` 分 | `[I` 分 | `[J` 分 | 选中 |
| --- | --- | --- | --- | --- | --- |
| `[1, 2, 3]`（都在 byte 范围）| **10** | 9 | 8 | 7 | `byte[]` |
| `[1, 200, 3]`（溢出 byte，在 short）| -1 | **9** | 8 | 7 | `short[]` |
| `[1, 100000]`（溢出 short，在 int）| -1 | -1 | **8** | 7 | `int[]` |
| `[5000000000]`（溢出 int）| -1 | -1 | -1 | **7** | `long[]` |
| `[1n, 2n]`（全 BigInt）| -1 | -1 | -1 | **10** | `long[]` |
| `[true, false]` | -1 | -1 | -1 | -1 | `boolean[]` |
| `[1.5, 2.5]` | -1 | -1 | -1 | -1 | `float[]` / `double[]` |

手动覆写用 `.overload(sig)`：

```js
obj.foo.overload("[I")([1, 2, 3]);    // 强制 int[]（否则自动选 byte[]）
obj.foo.overload("[B")([1, 200, 3]);  // 强制 byte[]，200 按位截断为 -56
```

**常见陷阱：**

- 传普通 JS object（非 wrapper、无 `__jptr`）给非数组 `L...;` 参数会 marshal 成 0 → Java 侧 NPE。
- 传 `undefined` 等同 `null`，别依赖默认行为——显式写 `null`。
- `Map.put(Object, Object)` 传 `number` 会被 autobox 成 `Integer` / `Double`，取出来**仍是 wrapper**，要 `.intValue()` 才能拿回 JS number。
- JS string 会为**所有** `L...;` 目标类型创建 `java.lang.String`（即使签名是 `Ljava/lang/Object;`），不会抛类型错误。
- 强制 `.overload("[B")` 传入越界元素（如 200）按 `as i8` **按位截断**，不报错（和 Frida 一致）。

### API 速查

| API | 参数 | 返回 |
| --- | --- | --- |
| `Java.use(className)` | `string` | `JavaClassWrapper` |
| `Class.$new(...args)` | 任意 | `JavaObjectProxy` |
| `Class.method.impl = fn` | `function(...args) { this.$orig(...) }`（this = 实例/static 载体） | setter |
| `Class.method.impl = null` | — | setter |
| `Class.method.overload(...types)` | `string...` | `MethodWrapper` |
| `Java.ready(fn)` | `() => void` | `void` |
| `Java.choose(cls, callbacks, subtypes?)` | `string, {onMatch,onComplete?,subtypes?,maxCount?}, bool?` | `void` |
| `Java.classLoaders()` | — | `LoaderInfo[]` |
| `Java.findClassWithLoader(loader, cls)` | `Loader, string` | `JavaClassWrapper` |
| `Java.setClassLoader(loader)` | `Loader` | — |
| `Java.deopt()` | — | `boolean` |
| `Java.deoptimizeBootImage()` | — | `boolean` |
| `Java.deoptimizeEverything()` | — | `boolean` |
| `Java.deoptimizeMethod(cls, method, sig)` | `string, string, string` | `boolean` |
| `Java.setStealth(mode)` | `number (0/1/2)` | — |
| `Java.getStealth()` | — | `number` |
| `obj.field.value` | — | `any` (读字段) |
| `obj.field.value = x` | — | — (写字段) |
| `Java.getField(objPtr, cls, field, sig)` | `AddressLike, string, string, string` | `any` (低层 API) |

---

## JNI API

```js
Jni.addr("RegisterNatives")       // → NativePointer
Jni.FindClass                     // 属性直接取地址
Jni.find("FindClass")             // → { name, index, address }
Jni.table                         // 整张 JNI 函数表
Jni.addr(envPtr, "FindClass")     // 指定 JNIEnv
```

### Jni.env / Jni.structs

```js
Jni.env.ptr                         // 当前线程 JNIEnv*
Jni.env.getClassName(jclass)        // → "android.app.Activity"
Jni.env.getObjectClassName(jobject) // → 对象的类名
Jni.env.readJString(jstring)        // → JS string
Jni.env.getObjectClass(obj)         // → jclass
Jni.env.getSuperclass(clazz)        // → jclass (Object 返 null)
Jni.env.isSameObject(a, b)          // → boolean
Jni.env.isInstanceOf(obj, clazz)    // → boolean
Jni.env.exceptionCheck()            // → boolean
Jni.env.exceptionClear()
Jni.env.exceptionOccurred()         // → jthrowable | null

// 构造/引用 (Rust 直路, 不走 callNative → dladdr, hook context 内安全)
Jni.env.findClass("java/lang/String") // → jclass | null
Jni.env.newStringUtf("hello")         // → jstring | null
Jni.env.newLocalRef(obj)              // → jobject | null
Jni.env.deleteLocalRef(obj)           // → undefined

Jni.structs.JNINativeMethod.readArray(addr, count)  // → JNINativeMethodInfo[]
Jni.structs.jvalue.readArray(addr, typesOrSig)      // → any[]
```

**ref API 都接受**：`NativePointer` / BigInt / 十六进制字符串 / `{__jptr: ...}` wrapper。**所有方法都接受可选 env 首参**：`Jni.env.findClass(envPtr, "java/lang/String")`，省略则走 `ensure_jni_initialized` 自动 attach 当前线程。所有 JNI 调用失败后异常被兜底 clear，不会串到下一次调用。

### API 速查

| API | 参数 | 返回 |
| --- | --- | --- |
| `Jni.addr(name)` | `string` | `NativePointer` |
| `Jni.addr(env, name)` | `AddressLike, string` | `NativePointer` |
| `Jni.find(name)` | `string` | `JniEntry` |
| `Jni.entries()` | — | `JniEntry[]` |
| `Jni.table` | — | `Record<string, JniEntry>` |
| `Jni.env.getClassName(clazz)` | `AddressLike` | `string \| null` |
| `Jni.env.readJString(jstr)` | `AddressLike` | `string \| null` |
| `Jni.env.findClass(name)` | `string` | `NativePointer \| null` |
| `Jni.env.newStringUtf(str)` | `string` | `NativePointer \| null` |
| `Jni.env.newLocalRef(obj)` | `AddressLike` | `NativePointer \| null` |
| `Jni.env.deleteLocalRef(obj)` | `AddressLike` | `true` |
| `Jni.structs.JNINativeMethod.readArray(addr, count)` | `AddressLike, number` | `JNINativeMethodInfo[]` |

### 实战：监控 RegisterNatives

```js
Interceptor.attach(Jni.addr("RegisterNatives"), {
    onEnter(args) {
        var cls = Jni.env.getClassName(args[1]);
        var n = Number(args[3]);
        console.log(cls + " (" + n + " methods)");

        var methods = Jni.structs.JNINativeMethod.readArray(args[2], n);
        for (var i = 0; i < methods.length; i++) {
            var m = methods[i];
            var mod = Module.findByAddress(m.fnPtr);
            var where = mod === null ? m.fnPtr.toString() : mod.name + "+" + m.fnPtr.sub(mod.base);
            console.log("  " + (m.name || "<null>") + " " + (m.sig || "<null>") + " → " + where);
        }
    }
}, Hook.WXSHADOW);
```

---

## Memory

**双风格 Frida 兼容**：`Memory.readXxx(addr)` ≡ `addr.readXxx()`，所有 read/write 方法同时挂在 `Memory` 和 `NativePointer.prototype` 上。

```js
// Memory.* 风格
var pid = Memory.readU32(ptr("0x7f1234"));
Memory.writeU64(dst, 0xdeadbeefn);
var cls = Memory.readCString(ptr(this.x1));

// ptr.* 风格（推荐，支持链式）
var p = ptr("0x7f1234");
p.readU32();
p.writeU64(0xdeadbeefn);
p.add(8).readPointer().readCString();     // 解指针再读字符串
p.add(0x10).readByteArray(32);            // → ArrayBuffer

// 写入代码后刷 I-cache
var code = Memory.alloc(16);
code.writeU32(0xd65f03c0);                // ret
Memory.flushCodeCache(code, 16);
```

| API | 参数 | 返回 |
| --- | --- | --- |
| **读** | | |
| `Memory.readU8/U16(addr)` / `p.readU8/U16()` | `AddressLike` | `number` |
| `Memory.readU32/U64(addr)` / `p.readU32/U64()` | `AddressLike` | `bigint` |
| `Memory.readPointer(addr)` / `p.readPointer()` | `AddressLike` | `NativePointer` |
| `Memory.readCString(addr)` / `p.readCString()` | `AddressLike` | `string` (最多 4096B) |
| `Memory.readUtf8String(addr)` / `p.readUtf8String()` | `AddressLike` | `string` |
| `Memory.readByteArray(addr, len)` / `p.readByteArray(len)` | `AddressLike, number` | `ArrayBuffer` (≤1GB) |
| **写** | | |
| `Memory.writeU8/U16/U32(addr, v)` / `p.writeU8/U16/U32(v)` | `AddressLike, number` | `undefined` |
| `Memory.writeU64(addr, v)` / `p.writeU64(v)` | `AddressLike, bigint` | `undefined` |
| `Memory.writePointer(addr, v)` / `p.writePointer(v)` | `AddressLike, AddressLike` | `undefined` |
| `Memory.writeBytes(addr, bytes, stealth?)` / `p.writeBytes(bytes, stealth?)` | `AddressLike, ArrayBuffer\|TypedArray\|number[], 0\|1` | `undefined` |
| `Memory.writest(addr, bytes)` / `p.writest(bytes)` | `AddressLike, 4B 倍数指令字节` | `undefined` |
| **分配 / 维护** | | |
| `Memory.alloc(size)` | `number` (≤ 256MB) | `NativePointer` (RWX, 零初始化) |
| `Memory.allocUtf8String(s)` | `string` | `NativePointer` (RWX，末尾 `\0`) |
| `Memory.flushCodeCache(addr, size)` | `AddressLike, number` | `undefined` |

**约束**：
- 无效地址抛 `RangeError`；`readCString` 超过 4096B 抛
- `Memory.alloc*` 是 RWX 堆内存；原指针及其 `add/sub/ptr(existing)` 派生指针全部被 GC 后自动释放，勿 `munmap`
- 写入代码后必须 `Memory.flushCodeCache` 刷 I-cache
- `writeXxx` 不会自动 mprotect；只读段写入抛错，需先 `Memory.protect`

### Memory.protect / writeBytes / writest

| API | 适用段 | read 可见 | 用途 |
| --- | --- | --- | --- |
| `Memory.protect(addr, size, "rwx")` | 任意 | — | 改页权限（页级 mprotect） |
| `p.writeBytes(bytes, 0)` 默认 | 可写段 | 可见 | 覆盖 N 字节（数据/结构体） |
| `p.writeBytes(bytes, 1)` | r-x | 不可见 | wxshadow_module prctl 覆盖 N 字节（短 patch，最多跨 2 页） |
| `p.writest(bytes)` | r-x | 不可见 | 1 条指令 → N 条指令替换（PC-rel 自动 relocate） |

`writeBytes(bytes, 1)` 会记录 patch 起始地址，`unhook(addr)` 统一清理 hook / writest / writeBytes(1) 留下的 patch。跨 4KB 边界时按“先第二页、再第一页”的顺序拆写，首段失败会回滚第二段；超过 2 页直接拒绝。

```js
var addr = Module.findExportByName("libc.so", "getpid");

// 隐身短 patch: getpid() → 42, readByteArray 仍看原字节
addr.writeBytes(new Uint8Array([0x40,0x05,0x80,0xd2, 0xc0,0x03,0x5f,0xd6]), 1);

// 指令级替换: 原第一条指令被这 3 条顶替, 原第二条及以后保留
addr.writest(new Uint8Array([
    0x80,0x46,0x82,0x52,  // MOVZ W0, #0x1234
    0xa0,0x79,0xb5,0x72,  // MOVK W0, #0xABCD, LSL #16
    0xc0,0x03,0x5f,0xd6,  // RET
]));

// 写数据段: 先开写权限
Memory.protect(dataAddr, 8, "rwx");
dataAddr.writeU64(0xdeadbeefn);
Memory.protect(dataAddr, 8, "r--");
```

**writest 细节**：patch 不带 RET/B 时末尾自动 fall-through 到 `addr+4`；`ADR/ADRP/BL/LDR literal/CBZ/TBZ/B.cond` 自动 relocate；patch 内部分支 ≤64 条指令有效；同地址重装需先 `unhook`。

## Module

| API | 参数 | 返回 |
| --- | --- | --- |
| `Module.findExportByName(module, symbol)` | `string, string` | `NativePointer \| null` |
| `Module.findBaseAddress(module)` | `string` | `NativePointer \| null` |
| `Module.findByAddress(addr)` | `AddressLike` | `ModuleInfo \| null` |
| `Module.enumerateModules()` | — | `ModuleInfo[]` |
| `Module.enumerateExports(name)` | `string` | `{type, name, address}[]` |
| `Module.enumerateImports(name)` | `string` | `{type, name, slot, address}[]` |
| `Module.enumerateSymbols(name)` | `string` | `{type, name, address, isGlobal, isDefined}[]` |
| `Module.enumerateRanges(name, prot?)` | `string, "rwx" 风格` | `{base, size, protection, file:{path}}[]` |
| `Module.load(path, flagsOrTagged?, tagged?)` | `string, int\|bool?, bool?` | `ModuleInfo` / 抛异常 |

```js
// 导出：defined + global/weak 符号
Module.enumerateExports("libc.so").slice(0, 3);
// [{type:"function", name:"__cxa_finalize", address:"0x7200f0e0a0"}, ...]

// 按内存权限过滤 (prot 里 '-' 是通配, "r-x" 会匹配 r-x 和 rwx)
Module.enumerateRanges("libc.so", "r-x");

// 外部引用符号 + PLT/GOT slot 地址
Module.enumerateImports("libart.so").filter(i => i.type === "function");
```

枚举的来源是模块的磁盘 ELF；memfd 或无文件支撑的合成模块返回空数组。

### Module.load — 运行时加载 SO

默认先走 libc `dlopen()`。如果失败，再用 unrestricted linker (`__loader_dlopen`) 选择一个已加载 App SO 作为 caller，尽量进入 App namespace；非 App 私有路径才会继续回退到 linker trusted caller。加载成功后从 `/proc/self/maps` 解析 `{name, base, size, path}` 返回；失败抛带 `dlerror` 原始消息的 `InternalError`。

第三个参数或第二个布尔参数为 `true` 时，先把 SO 读入 `memfd_create("wwb_<basename>")`，再用 `android_dlopen_ext` 的 `library_fd` 加载。这样 `/proc/<pid>/maps` 中会出现 `wwb_` 标记；默认或显式 `false` 保持普通路径加载。

```js
// 短名：走 linker 搜索路径
var m = Module.load("libz.so");
// { name: "libz.so", base: 0x7062dec000, size: 110592, path: "/vendor/lib64/libz.so" }

// 绝对路径
Module.load("/system/lib64/libsqlite.so");

// 自定义 flags（默认 RTLD_NOW = 2；RTLD_LAZY = 1）
Module.load("/data/local/tmp/mylib.so", 1);

// 显式普通加载：maps 中保留真实文件路径
Module.load("/data/local/tmp/mylib.so", false);

// tagged 加载：maps 中显示 /memfd:wwb_mylib.so (deleted)
Module.load("/data/local/tmp/mylib.so", true);
Module.load("/data/local/tmp/mylib.so", 2, true);

// App 私有目录路径推荐普通加载；这类路径不会回退到 linker trusted caller
Module.load("/data/user/0/com.example.app/files/libcustom.so");

// 错误处理
try {
    Module.load("/does/not/exist.so");
} catch (e) {
    console.log(e.message);
    // → "Module.load: dlopen('/does/not/exist.so') failed: library \"...\" not found"
}

// 加载后立刻查符号
var m = Module.load("libcustom.so");
var addr = Module.findExportByName(m.name, "my_func");
```

**注意**：
- tagged/memfd 加载会改变模块在 maps 和 `dladdr()` 等路径视角下的名字，适合需要 `wwb_` 标记的场景；依赖真实文件路径自检的 SO 建议用默认加载。
- tagged 加载返回模块信息时优先匹配 `/memfd:wwb_*`，避免误返回原始磁盘路径模块。
- `Module.findExportByName(null, symbol)` 会解析已加载模块的 ELF 动态符号；全局扫描只考虑真实 SO、App 路径 SO 和 `wwb_` memfd SO，避免误扫 `/memfd:jit-cache` 之类非 ELF 区域导致卡顿或断连。
- 若模块被 `hide_soinfo` 隐藏或 maps 聚合失败，返回 `{name, path, base: <dlopen handle>, size: 0}` 作 fallback。
- `Module.load` 不会重复加载同一个 SO — linker 对已加载模块返回现有 handle。

## ptr / NativePointer

```js
var p = ptr("0x7f12345678");   // hex string / number / BigInt / NativePointer
p.add(0x100).sub(0x10);        // 算术，返回新 NativePointer
p.toString();                  // → "0x7f12345678"
p.toInt();                     // → bigint (等价 toNumber)
p.toInt32();                   // → 有符号低 32 位
p.toUInt32();                  // → 无符号低 32 位

// Frida 兼容读写（完整 API 见上面 Memory 章节）
p.readU32();                   // 等价 Memory.readU32(p)
p.writeU64(0xdeadbeefn);       // 自动 mprotect
p.readPointer().readCString(); // 链式解引用
```

| API | 参数 | 返回 |
| --- | --- | --- |
| `ptr(value)` | `number \| bigint \| string \| NativePointer` | `NativePointer` |
| `p.add(offset)` / `p.sub(offset)` | `AddressLike` | `NativePointer` |
| `p.toString()` / `p.toJSON()` | — | `string` (`"0x..."`) |
| `p.toNumber()` / `p.toInt()` | — | `bigint` |
| `p.toInt32()` / `p.toUInt32()` | — | `number`（低 32 位） |
| `p.readU8/U16/U32/U64/Pointer()` | — | `number \| bigint \| NativePointer` |
| `p.readCString()` / `p.readUtf8String()` | — | `string` |
| `p.readByteArray(len)` | `number` | `ArrayBuffer` |
| `p.writeU8/U16/U32/U64/Pointer(val)` | 值 | `undefined` |
| `p.writeBytes(bytes, stealth?)` | `ArrayBuffer\|TypedArray\|number[], 0\|1` | `undefined` |
| `p.writest(bytes)` | `ArrayBuffer\|TypedArray\|number[]` (4B 倍数) | `undefined` |

所有读写方法的语义、错误处理、i-cache 约束与 `Memory.*` 完全一致；`writeBytes` / `writest` 的行为见 Memory 章节的表格。

## console

`console.log(...)` / `console.info(...)` / `console.warn(...)` / `console.error(...)` / `console.debug(...)`

## File

Frida 兼容的同步文件 API。适合在 agent 内直接读写目标进程可访问的路径；`new File()` 底层按 `fopen()` 的 mode 字符串打开，GC 时会自动关闭，但长脚本建议显式 `close()`。

```js
// 静态读写
File.writeAllText("/data/local/tmp/demo.txt", "hello\n");
var text = File.readAllText("/data/local/tmp/demo.txt");

var bytes = new Uint8Array([0x41, 0x42, 0x43]).buffer;
File.writeAllBytes("/data/local/tmp/demo.bin", bytes);
var roundtrip = File.readAllBytes("/data/local/tmp/demo.bin");

// 流式读写
var f = new File("/data/local/tmp/demo.txt", "rb");
console.log(f.readLine());          // 保留行尾 \n，和 Frida 一致
console.log(f.tell());
f.seek(0, File.SEEK_SET);
console.log(f.readText(5));
f.close();

var out = new File("/data/local/tmp/out.bin", "wb");
out.write(roundtrip);               // string / ArrayBuffer / TypedArray / number[]
out.flush();
out.close();
```

| API | 参数 | 返回 |
| --- | --- | --- |
| `File.readAllBytes(path)` | `string` | `ArrayBuffer` |
| `File.readAllText(path)` | `string` | `string` (UTF-8) |
| `File.writeAllBytes(path, data)` | `string, ArrayBuffer\|TypedArray\|number[]` | `undefined` |
| `File.writeAllText(path, text)` | `string, string` | `undefined` |
| `new File(path, mode)` | `string, string` | `File` |
| `file.tell()` | — | `number` |
| `file.seek(offset, whence?)` | `number, File.SEEK_*?` | `number` (`fseek` 结果) |
| `file.readBytes(size?)` | `number?` | `ArrayBuffer` |
| `file.readText(size?)` | `number?` | `string` (UTF-8) |
| `file.readLine()` | — | `string` |
| `file.write(data)` | `string\|ArrayBuffer\|TypedArray\|number[]` | `undefined` |
| `file.flush()` | — | `undefined` |
| `file.close()` | — | `undefined` |

常量：`File.SEEK_SET`、`File.SEEK_CUR`、`File.SEEK_END`。

## Stalker Trace

Android ARM64 下通过 Frida Gum 17.15.5 提供线程级动态跟踪。事件缓冲区在 `follow()` 时一次性分配；跟踪回调只写入有界缓冲区，队列满后丢弃新事件，不会在目标线程的回调路径中扩容。

```js
var tid = Process.getCurrentThreadId();
var target = Module.findExportByName("libdemo.so", "target_function");

Stalker.follow(tid, {
    transform: function (iterator) {
        var instruction;
        while ((instruction = iterator.next()) !== null) {
            console.log(instruction.address + " " + instruction);
            if (instruction.address.equals(target)) {
                iterator.putCallout(function (context) {
                    console.log("x0=" + context.x0 + " pc=" + context.pc);
                    context.x0 = ptr(123);
                });
            }
            iterator.keep();
        }
    },
    events: { call: true, ret: true },
    onReceive: function (events) {
        var rows = Stalker.parse(events, {
            annotate: true,
            stringify: true
        });
        console.log(JSON.stringify(rows));
    },
    onCallSummary: function (summary) {
        console.log(JSON.stringify(summary));
    }
});

// 在当前线程调用需要跟踪的 native 函数后收尾。
Stalker.unfollow(tid);
Stalker.flush();
Stalker.garbageCollect();

// 调用探针只对被 Stalker 跟踪线程上的调用生效；args 可在回调内读写。
var probeId = Stalker.addCallProbe(target, function (args) {
    console.log(args[0]);
    args[0] = ptr(123);
});
Stalker.removeCallProbe(probeId);
```

| API | 参数 | 说明 |
| --- | --- | --- |
| `Stalker.supported` | — | 当前平台是否支持 Stalker |
| `Stalker.follow(threadId?, options?)` | `number?, object?` | 跟踪线程；支持 JavaScript `transform`、队列回调及原生 `onEvent/data` 事件回调 |
| `Stalker.unfollow(threadId?)` | `number?` | 停止跟踪并派发剩余事件 |
| `Stalker.flush()` | — | 刷新并派发当前缓冲区 |
| `Stalker.garbageCollect()` | — | 回收 Gum 翻译块并派发剩余事件 |
| `Stalker.parse(events, options?)` | `ArrayBuffer, object?` | 解析 Gum 事件；支持 `annotate/stringify` |
| `Stalker.exclude(range)` | `{base, size}` | 排除一段地址范围 |
| `Stalker.invalidate(address)` | `AddressLike` | 使所有线程对应翻译块失效 |
| `Stalker.invalidate(threadId, address)` | `number, AddressLike` | 使指定线程对应翻译块失效 |
| `Stalker.addCallProbe(target, callback, data?)` | `AddressLike, function/AddressLike, AddressLike?` | 添加 JavaScript 或 CModule/原生调用探针；JavaScript 回调接收可读写的 `args[n]` |
| `Stalker.removeCallProbe(id)` | `uint32` | 独立移除指定调用探针；重复移除为空操作 |
| `Stalker.trustThreshold` | `int32` | 读写 Gum 信任阈值 |
| `Stalker.queueCapacity` | `uint32` | 后续 `follow()` 使用的事件数上限 |
| `Stalker.queueDrainInterval` | `uint32` | 后续 `follow()` 的自动派发周期（毫秒）；`0` 禁用 |

`transform(iterator)` 当前提供 `iterator.next()`、`iterator.keep()`、`iterator.memoryAccess`、`iterator.putCallout(callback, data?)` 和 `iterator.putChainingReturn()`。`next()` 返回的指令快照包含 `id/address/next/size/mnemonic/opStr/bytes` 与 `toString()`；iterator 只在当前 transform 回调内有效。

JavaScript callout 在被跟踪线程同步执行，接收实时可读写的 ARM64 `CpuContext`：`pc/sp/nzcv/x0..x28/fp/lr/q0..q31`。通用寄存器返回 `NativePointer`，`nzcv` 返回整数，向量寄存器返回 16 字节 `ArrayBuffer`，赋值时也接受 `ArrayBuffer`、TypedArray 或字节数组。该对象只在当前 callout 回调内有效，离开回调后继续访问会抛出异常。

原生事件、callout 和调用探针回调与 Frida Gum ABI 一致，并在被跟踪线程同步执行。`onEvent` 的签名为 `void callback(const GumEvent *event, GumCpuContext *cpu_context, void *data)`，原生 callout 的签名为 `void callback(GumCpuContext *cpu_context, void *data)`，原生 call probe 的签名为 `void callback(GumCallDetails *details, void *data)`。这些位置可直接传入 CModule 导出的指针；实现会持有回调、CModule 和 `data`，直到对应探针移除或 Gum 翻译块回收。

`%reload` 会先停止 Stalker 并注销当前脚本的模块观察器，但保留进程级 Gum/GLib runtime；新脚本初始化时重新注册观察器。只有 agent 最终退出时才释放 Gum，避免同一进程内重复初始化 Frida 的 startup callbacks。

与 Frida 17.15.5 的当前主要差异是 transform 尚未暴露 ARM64 writer 方法。`putCallout()`、`onEvent/data` 与 `addCallProbe()` 已支持 JavaScript、`NativeCallback` 或 CModule/原生指针回调；JavaScript callout 可同步读写完整 ARM64 `CpuContext`，调用探针也可同步读取和修改参数。`queueDrainInterval` 已按每次 `follow()` 时的配置周期派发 `onReceive/onCallSummary`，设为 `0` 可禁用自动派发；`unfollow()`、`flush()` 和 `garbageCollect()` 仍会同步排空队列。

## QBDI Trace

| API | 参数 | 返回 |
| --- | --- | --- |
| `qbdi.newVM()` | — | `number` |
| `qbdi.destroyVM(vm)` | `number` | `boolean` |
| `qbdi.addInstrumentedModuleFromAddr(vm, addr)` | `number, AddressLike` | `boolean` |
| `qbdi.addInstrumentedRange(vm, start, end)` | `number, AddressLike, AddressLike` | `boolean` |
| `qbdi.removeInstrumentedRange(vm, start, end)` | `number, AddressLike, AddressLike` | `boolean` |
| `qbdi.removeAllInstrumentedRanges(vm)` | `number` | `boolean` |
| `qbdi.allocateVirtualStack(vm, size)` | `number, number` | `boolean` |
| `qbdi.simulateCall(vm, retAddr, ...args)` | `number, AddressLike, ...AddressLike` | `boolean` |
| `qbdi.call(vm, target, ...args)` | `number, AddressLike, ...AddressLike` | `number \| bigint \| null` |
| `qbdi.run(vm, start, stop)` | `number, AddressLike, AddressLike` | `boolean` |
| `qbdi.getGPR(vm, reg)` | `number, number` | `NativePointer` |
| `qbdi.setGPR(vm, reg, value)` | `number, number, AddressLike` | `boolean` |
| `qbdi.setTraceBundleMetadata(path, base)` | `string, AddressLike` | `boolean` |
| `qbdi.registerTraceCallbacks(vm, target, outDir?)` | `number, AddressLike, string?` | `boolean` |
| `qbdi.unregisterTraceCallbacks(vm)` | `number` | `boolean` |
| `qbdi.lastError()` | — | `string` |

常用寄存器常量：`qbdi.REG_RETURN`, `qbdi.REG_SP`, `qbdi.REG_LR`, `qbdi.REG_PC`

```js
var vm = qbdi.newVM();
qbdi.addInstrumentedModuleFromAddr(vm, target);
qbdi.allocateVirtualStack(vm, 0x100000);
qbdi.simulateCall(vm, 0, arg0, arg1);
qbdi.registerTraceCallbacks(vm, target);
qbdi.run(vm, target, 0);
var ret = qbdi.getGPR(vm, qbdi.REG_RETURN);
qbdi.unregisterTraceCallbacks(vm);
qbdi.destroyVM(vm);
```

`registerTraceCallbacks(vm, target, outDir?)` 会同步直写 `TRB1 + length-delimited TraceBundleEvent` 到：

```text
<outDir>/trace_bundle.pb
```

如果未传 `outDir`，默认使用注入字符串表里的 `output_path`。`--watch-so` 模式会按目标 uid 自动填 App data dir；普通 `--pid` / `--spawn` 场景需要稳定路径时建议直接传第三参数，或显式设置 `--string output_path=<dir>`。`-o` 只控制 host 侧日志文件，不等价于 QBDI 输出目录。

```js
qbdi.registerTraceCallbacks(vm, target, "/data/user/0/com.example.app/files");
```

QBDI helper 运行时会被写入 App 私有目录再加载：

```text
/data/user/0/<package>/files/.rustfrida/libqbdi_helper.so
```

这规避了 SELinux Enforcing 下普通 App 不能访问 `/data/local/tmp` SO 的问题。
同一目标进程后续注入会复用这份 helper；agent shutdown 会结束 trace 并清空 VM/元数据状态，helper 映射随目标进程退出而释放。

Host 侧可用 `qbdi-trace-dump` 直接输出明文：

```bash
adb pull /data/user/0/com.example.app/files/trace_bundle.pb .
cargo run -p qbdi-trace-dump -- --limit 200 trace_bundle.pb
cargo run -p qbdi-trace-dump -- --summary-only trace_bundle.pb
```

`qbdi.unregisterTraceCallbacks(vm)` 会 flush 并发布最终 `trace_bundle.pb`；`qbdi.call()` / `qbdi.switchStackAndCall()` 返回前也会 flush 当前线程 chunk。

---

## 注意事项

- **Native hook 回调签名：** `function(a, b, c) { ... }`，`arguments[0..7]` = x0..x7 (BigInt)、`this` = register 上下文（`this.x0..x30` / `this.sp` / `this.pc` / `this.$orig()`）；改参数先写 `this.xN = v`，再 `this.$orig()`；`return value` 覆盖返回值
- **Java hook 回调签名：** `function(a, b, c) { ... }`，`this` = 实例（静态方法为 class 载体）、`arguments` = Java 参数、`this.$orig(...)` = 原方法；`return value` 改返回值
- **Java 字段访问必须用 `.value`：** `obj.field` 返回 FieldWrapper，`obj.field.value` 才是真实值
- **`Java.choose` 的 wrapper 仅在 `onMatch` 内有效**，跨回调保留需要自己提取字段值
- Spawn 模式下 Java hook 必须放在 `Java.ready(fn)` 里（`Java.classLoaders()` / `Java.choose` 同理）
- `Java.setStealth()` 必须在 `Java.use().impl` 之前调用
- `callNative()` 仅支持整数/指针参数（最多 6 个），需要浮点/任意签名用 `NativeFunction`
- 自修改代码后需 `Memory.flushCodeCache(addr, size)` 清 I-cache

---

## 免责声明

本项目仅供安全研究、逆向工程学习和授权测试用途。使用者应确保在合法授权范围内使用本工具，遵守所在地区的法律法规。作者不对任何滥用、非法使用或由此造成的损失承担责任。使用本项目即表示您同意自行承担所有风险。
