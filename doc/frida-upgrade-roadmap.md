# Frida 17.15.5 差异与升级路线

> 状态：执行中（Goal 00、Goal 01 和 Goal 02 已完成）
>
> 更新日期：2026-07-25
>
> 目标平台：Android ARM64
>
> 用途：为后续 goal 任务提供固定范围、依赖顺序和验收条件

## 1. 对比基线

本文件中的“最新版 Frida”特指本机 `/home/qiu/Android/frida` 当前检出的源码，不代表未经核对的远端最新版本。

| 项目 | 基线 |
| --- | --- |
| rustFrida | `c7daef081b7965ce7e578e16b134a21a168d7646` |
| 当前 Gum devkit | `frida-gum-sys/FRIDA_VERSION = 17.15.5` |
| Frida 根仓库 | `200c682e13094e2e1b0ede9e663a701b5a988f72`，`17.15.5-5-g200c682` |
| Frida 根仓库的 `17.15.5` 标签 | `fdd722a991009eef0331dc0d6f68b70b4f91df63` |
| frida-gum 子仓库 | `867975dc6cfebbba872d608585afb90a73e86381`，`17.15.5-7-g867975dc` |
| frida-gum 的 `17.15.5` 标签 | `b3baae444049bbd2448debe0030cebacb1d26a50` |
| 上游 GumJS 类型基线 | `@types/frida-gum 19.9.0`，由本地 frida-core package lock 指定 |

主要证据来源：

- 上游模块注册顺序：`/home/qiu/Android/frida/subprojects/frida-gum/bindings/gumjs/gumquickscript.c`
- 上游 QuickJS API：同目录的 `gumquick*.c` 和 `runtime/core.js`
- 当前 JS API 注册：`quickjs-hook/src/jsapi/mod.rs`
- 当前 Stalker 后端：`agent/src/stalker.rs` 与 `quickjs-hook/src/jsapi/stalker.rs`
- 当前公开能力说明：`README.md`

对比范围以目标进程内的 GumJS、Interceptor、Stalker 和 Android Java 能力为主。Frida Device/Session、Portal、编译服务、远程传输协议等 frida-core host 能力不直接纳入兼容目标，因为 rustFrida 使用自己的注入器、REPL 和 HTTP RPC。

## 2. 结论

1. 当前二进制依赖已经对齐最新稳定版 `17.15.5`，不存在需要立即处理的大版本 ABI 跨越。
2. 本地 frida-gum 比标签多 7 个提交。对 Android ARM64 直接有价值的是模块卸载时清理 Interceptor hook；其余主要是 x86 AVX-512/XMM 支持和测试维护。
3. 主要差异不在 Gum 版本，而在 JS 层。rustFrida 使用自研 QuickJS facade，只实现了 GumJS 的一部分，因此修改 `FRIDA_VERSION` 不会自动获得完整 Frida API。
4. 当前项目在 Android 注入、ART hook、CModule、stealth patch 和 Stalker 生命周期方面有自己的扩展，升级必须采用“增加官方兼容入口，同时保留现有扩展”的方式。
5. 后续工作应先建立可自动比较的 API/行为基线，再补功能。否则 README、实现和最新版 Frida 会继续独立漂移。

## 3. 上游源码增量

`frida-gum` 从 `17.15.5` 标签到本地 HEAD 的增量如下：

| 提交 | 内容 | Android ARM64 决策 |
| --- | --- | --- |
| `8f514005` | 模块卸载时丢弃 Gum Interceptor hooks | P0，需要受控回移或本地 devkit 验证 |
| `a87ea3c4` | x86 CpuContext 暴露 XMM | 当前不处理 |
| `9f6d2c8f`、`d626636e`、`1420144b` | x86 AVX-512 检测、writer 和 Stalker 保存 | 当前不处理 |
| `9446b797` | bytecode 测试卸载顺序 | 作为生命周期测试参考，不直接移植运行时代码 |
| `867975dc` | 更新 releng 子仓库 | 不单独移植 |

当前 `ModuleRegistryObserver` 只在模块移除时调用 `discard_native_hooks_in_range()`，覆盖的是 rustFrida 自研 hook engine。它不能替代 `8f514005` 对 Gum Interceptor 内部状态的修复，特别是 legacy `hfollow` 或未来直接使用 Gum Interceptor 的路径。

frida-core 标签后的变化主要涉及 spawn gating、control service、跨平台 helper 和构建系统。rustFrida 没有使用 Frida 的 HostSession/Device 协议，不能整包合并；只有在明确追求 Frida host 工具兼容时才另立项目评估。

## 4. 功能矩阵

状态定义：

- **已有**：当前接口可用，仍需持续做行为回归。
- **部分**：覆盖常见用法，但 API 形状、边界语义或生命周期与 GumJS 不完全一致。
- **缺失**：当前未注册对应公开对象或能力。
- **扩展**：rustFrida 自有能力，不应为兼容 Frida 而删除。

| 领域 | 当前 rustFrida | 最新 GumJS | 状态 | 优先级 |
| --- | --- | --- | --- | --- |
| 核心运行时 | QuickJS、`console`、HTTP `rpc.exports` | `Frida`、`Script`、`send/recv`、timer、`gc`、`Worker`、`hexdump` | 部分 | P1/P2 |
| 数值与指针 | `ptr`、`NULL`、NativePointer 大部分运算和读写 | 另有 `Int64`、`UInt64`、pointer sign/blend、`ArrayBuffer.wrap/unwrap` | 部分 | P1 |
| Native 调用 | ARM64 `NativeFunction`，标量/指针/浮点和栈参数 | 另有 ABI/options、struct、variadic、`SystemFunction` | 部分 | P1 |
| Native callback | CModule 函数指针可用于高频 callback | 通用 `NativeCallback` | 缺失 | P0/P1 |
| Memory | 同步读写、分配、protect、copy/dup、scanSync、queryProtection、stealth patch | 另有 alloc options、patchCode、异步 scan、findPointers、MemoryAccessMonitor | 部分 | P1 |
| Module | 旧式静态 `Module.findExportByName(module, name)` 和 ELF 枚举 | `Module` 实例、ModuleMap、sections/dependencies、ensureInitialized、version | 部分 | P1 |
| Process | 基本属性、模块/范围/线程枚举和目录查询 | 另有 observer、findThread、runOnThread、exception handler、system/function ranges | 部分 | P1 |
| Thread/符号诊断 | Stalker 内有 instruction snapshot | `Thread`、Backtracer、DebugSymbol、ApiResolver、Instruction、CFG | 缺失 | P0/P1 |
| Interceptor | 自研 engine 的 attach/replace/revert/detachAll；`flush` 是兼容 no-op；支持 stealth | Gum Interceptor defaults/options、replaceFast、事务 flush、完整 invocation context | 部分/扩展 | P1 |
| Stalker | follow/unfollow、事件、parse、transform 遍历、callout、probe、native sink、reload cleanup | transform iterator 同时暴露架构 writer，和 Instruction/Writer/Relocator 深度集成 | 部分 | P0/P1 |
| CModule | TinyCC、symbol 注入、导出指针、metadata 回收 | 官方 CModule builtins、dispose 和完整 ownership 语义 | 部分/扩展 | P2 |
| File | 同步 File 构造、读写、seek、静态 read/write helpers | GumJS File 行为及异步 I/O 生态 | 部分 | P2 |
| Stream/Socket | 无 | IOStream、InputStream、OutputStream、Socket | 缺失 | P2 |
| 工具模块 | 无 | Checksum、SQLite、Cloak、Sampler、Profiler、Kernel | 缺失 | P2/P3 |
| Java | `use`、`implementation/impl`、overload、choose、class loader、deopt、字段、DSL/fast hook | 官方 bridge 另有 perform、ClassFactory、retain/cast/array、loaded-class、main-thread 等生态 | 部分/扩展 | P1 |
| Host 协议 | 自研注入器、REPL、HTTP RPC | Device、Session、Script message、Portal、Compiler | 不同架构 | 非当前范围 |

### 4.1 当前已经做得较完整的部分

- NativePointer 的基础算术、比较、格式化和常用内存读写。
- Memory 的同步访问、UTF-8/UTF-16、保护查询、同步 pattern scan。
- ARM64 NativeFunction 的常见标量调用。
- Interceptor 双阶段回调、CModule native callback 和自研 stealth 模式。
- Android Java hook 的常用 `use/overload/implementation/choose` 路径，以及项目特有的 managed DSL。
- Stalker 的事件队列、JS/native callback、call probe、callout、reload/shutdown 生命周期。

### 4.2 影响常见 Frida 脚本迁移的缺口

1. 缺少 `NativeCallback`，导致大量标准 `Interceptor.replace()`、C API callback 和 Stalker callback 脚本必须改写成 CModule。
2. 缺少 `DebugSymbol`、`Thread.backtrace()`、`Backtracer`、`ApiResolver` 和全局 `Instruction.parse()`，诊断脚本迁移成本高。
3. `Module` 仍是旧式静态 facade，不是最新版 GumJS 的实例模型；官方脚本常用的 `Process.getModuleByName(...).enumerateExports()` 无法直接复用。
4. Stalker transform 只能遍历、keep、callout 和 chaining return，不能调用 ARM64 writer 发射或替换指令。
5. 缺少 `send/recv`、timer 和 Script 生命周期 API，依赖 Frida message loop 的脚本无法直接运行。
6. Java 常用入口仍以 `Java.ready()` 为主，缺少 `Java.perform()/performNow()` 等标准入口和部分对象生命周期工具。

## 5. 架构与稳定性风险

### 5.1 两套插桩状态

当前 Native hook 主要走自研 hook engine，Stalker 和少量 legacy 功能走 Gum。增加官方兼容 API 时必须明确每个对象的 owner，不能让同一 target 同时被两套 Interceptor 无序管理。

### 5.2 QuickJS 重入与线程归属

Stalker、Interceptor、Java worker 都可能从 native 线程同步进入 JS。任何 timer、Worker、NativeCallback 或异步 scan 都必须复用已有 runtime suspend/resume 和 owner guard，不能另建未经治理的 JS 入口。

### 5.3 callback 生命周期

每个 callback 必须同时持有 JSValue、CModule/可执行内存、user data 和对应 native registration，直到 detach、module unload、reload 或 Gum GC 真正完成。仅以 JS 对象是否可达判断生命周期不够。

### 5.4 API 形状兼容

兼容层应新增最新版 API，同时保留以下项目接口：

- `Module.findExportByName(module, name)` 等旧式静态方法。
- `Java.ready()`、`.impl`、managed DSL、stealth hook。
- `hook()`、`hookNative()`、`attachNative()`、`writest()` 和 QBDI。

不允许为了表面一致性一次性改变这些接口的返回类型或清理时机。

### 5.5 构建来源

`auto-download` 当前只按 `17.15.5` 下载 release devkit，无法表达本地 Gum HEAD。需要为 release devkit、受控 backport 和本地源码 devkit 建立明确的 revision/checksum 记录，避免构建结果只依赖缓存目录内容。

### 5.6 已知可观测性缺口

- Stalker 队列满时静默丢弃事件，没有 dropped counter。
- call-probe anchor 会保留到 Stalker runtime 关闭，需要覆盖目标模块卸载和地址复用场景。
- README 仍有个别实现漂移，例如 `Memory.alloc()` 源码使用 `calloc`，文档却描述为 RWX；应由 API 基线 goal 统一校正。

## 6. Goal 路线

后续 goal 应按下列边界独立执行。除 Goal 00 外，不建议把两项合并成一个大任务。

### Goal 00：冻结上游基线与 API 快照（P0）

状态：**已完成（2026-07-19）**。

落地证据：

- `tests/compat/frida_surface.py` 可生成并校验上游/当前 API 基线。
- `doc/frida-api-surface.json` 保存 revision、模块和函数表，包含生成的 ARM64 writer/relocator 表面。
- `doc/frida-api-surface.md` 提供可审阅摘要。
- `tests/device/rfhook_frida_surface.js` 已在 `com.example.rfhooktarget` 实机通过并正常 shutdown。
- `python3 -m unittest discover -s tests/compat -p 'test_*.py' -v` 共 5 项通过。

目标：让“当前支持什么、上游新增了什么”可由工具重复生成，而不是只靠人工阅读。

范围：

- 保存 Frida root、frida-gum、devkit 和类型定义 revision。
- 增加设备端 capability 脚本，输出所有公开全局对象、关键属性和函数类型。
- 增加上游 GumJS 注册表提取脚本，生成可 diff 的 JSON/Markdown。
- 将项目扩展标为 `extension`，避免被误判成上游差异。

验收：

- 同一 commit 重跑生成器无差异。
- API 快照至少覆盖 Core、Memory、Module、Process、Interceptor、Stalker、Java。
- README 中的全局对象列表由快照校验，发现漂移时测试失败。

### Goal 01：受控同步 Gum tag 后修复（P0）

状态：**已完成（2026-07-24）**。

落地证据：

- 本地 devkit 固定 Gum `867975dc` 和必需修复 `8f514005`；构建时校验 manifest/artifact，并以唯一名称 `libfrida-gum-pinned.a` 链接，避免旧缓存 archive 污染。
- Gum Interceptor、自研 native hook 和 Stalker probe anchor 均覆盖模块卸载、换址重载和再次安装；未映射 target 的 hfollow 清理不再解码已卸载代码。
- `tests/device/run_goal01_module_unload.py --mode hfollow` 在 PLC110 实机完成两轮 hfollow 卸载/重载回归。
- `tests/device/run_goal01_module_unload.py --mode full` 在同一设备完成 `%reload` 前后各两轮完整回归，最后一枚 probe 与 call/ret sink 均继续产出事件。
- 两种设备回归最终 shutdown 均正常，目标进程存活且无新增 tombstone；兼容测试 10 项、API 快照、devkit `--check`、rustfmt 和 diff 检查均通过。

当前 devkit 证据：

- `frida-gum-sys/FRIDA_GUM_DEVKIT.json` 固定 Frida root `200c682e`、Gum `867975dc` 和必需修复 `8f514005`。
- 构建目标为 Android arm64/API 21，使用 NDK `29.0.14206865`；NDK 归档 SHA-1 为 `87e2bb7e9be5d6a1c6cdf5ec40dd4e0c6d07c30b`。
- manifest 同时固定 configure 参数、`frida-gum.h` 和 `libfrida-gum.a` 的文件大小与 SHA-256。
- `scripts/build-frida-gum-devkit.py` 在构建前校验源码 revision、工作树和 NDK，在构建后校验 artifact。
- 设置 `FRIDA_GUM_DEVKIT_DIR` 时，`frida-gum-sys/build.rs` 会重新校验 manifest 和 artifact；不设置时仍使用 `FRIDA_VERSION = 17.15.5` 的官方 release devkit。

复建与选择本地 devkit：

```bash
python3 scripts/build-frida-gum-devkit.py \
  --frida-source /home/qiu/Android/frida \
  --ndk /home/qiu/Android/Sdk/ndk/29.0.14206865

export FRIDA_GUM_DEVKIT_DIR=/home/qiu/Android/frida/subprojects/frida-gum/build/gum/devkit
cargo build --offline --release --target aarch64-linux-android
```

只复核已存在的 devkit 时增加 `--check`，不会重新配置或编译 Gum。NDK r29 的官方归档地址为 `https://dl.google.com/android/repository/android-ndk-r29-linux.zip`，安装时应保留现有 r28，不能覆盖项目当前默认工具链。

目标：吸收 `8f514005` 的模块卸载安全修复，同时保持 devkit 可复现。

范围：

- 选择“本地源码 devkit”或“最小 backport”，禁止只把版本字符串改成不存在的 release。
- 记录源码 revision、构建参数和 artifact checksum。
- 同时验证 Gum Interceptor、自研 Interceptor、Stalker probe anchor 的模块卸载行为。

验收：

- 加载测试 SO、安装 hook/probe、卸载、重新加载、再次安装均正常。
- `%reload` 和最终 shutdown 正常，进程存活，无 tombstone。
- 现有最后一枚 probe + call/ret sink 回归继续通过。

### Goal 02：补齐诊断基础对象（P0）

状态：**已完成（2026-07-25）**。

落地证据：

- QuickJS facade 已提供 `Int64`、`UInt64`、`DebugSymbol`、`Thread.backtrace()`、`Backtracer`、`Instruction.parse()` 和 `ApiResolver('module')`，并由固定 Gum/Capstone 后端实现诊断能力。
- `DebugSymbol` 按名称查询会合并 Gum 当前映射结果与边界校验后的磁盘 ELF 结果；Android 16 上同路径的只读 ELF mirror 不会被误作 load bias，卸载重载后也不会返回 Gum 缓存中的旧地址。
- `tests/device/run_goal02_diagnostics.py --device 3B65AU009YA00000` 在 PLC110 实机完成两轮回归；`%reload` 后测试 SO 从 `0x7b8f734620` 换址到 `0x7b0d51c620`，按名称查询返回新地址。
- native hook 的 returnAddress 和 `Thread.backtrace()` 均输出 `librf_goal01_control.so!rf_goal01_call`；无符号地址、匿名可执行 JIT 映射和模块卸载后的地址查询均正常。
- 两轮回归后最终 shutdown 正常，目标进程存活且没有新增 tombstone；兼容 surface、静态语法、rustfmt 和 diff 检查均通过。

目标：优先覆盖最常见且低侵入的 Frida 脚本依赖。

范围：

- `DebugSymbol`、`Thread.backtrace()`、`Backtracer`。
- `Instruction.parse()`，ARM64 指令字段与生命周期。
- `ApiResolver('module')` 的 enumerateMatches；其他 resolver 类型按平台能力返回清晰错误。
- `Int64/UInt64` 或与现有 BigInt 的严格兼容包装。

验收：

- 可对 native hook 的 returnAddress 输出符号化 backtrace。
- 无符号地址、JIT/memfd 地址和模块卸载后查询不崩溃。
- 输出结构与上游同名 API 的关键字段一致。

### Goal 03：升级 Module/Process 对象模型（P1）

目标：支持最新版实例式 Module API，同时保留旧式静态 API。

范围：

- `Process.get/findModuleByName/Address()` 返回 Module 实例。
- Module 实例方法、`Module.findGlobalExportByName()`、`ModuleMap`。
- sections、dependencies、ensureInitialized、findSymbolByName。
- module/thread observer；runOnThread 和 exception handler 另设 feature gate，避免先扩大重入面。

验收：

- 新旧两种 Module 调用方式结果一致。
- observer 在 load/unload 时只通知一次，可 detach，reload 后无旧 callback。
- memfd、隐藏 soinfo、同名模块的行为有设备测试。

### Goal 04：通用 NativeCallback 与完整调用 ABI（P0/P1）

目标：让标准 Frida native callback 脚本不再依赖 CModule 改写。

范围：

- `NativeCallback` 的签名解析、可执行 thunk、JS 调度和 GC ownership。
- `SystemFunction` 和 system error 返回。
- NativeFunction options、ABI、variadic/struct 支持分阶段实现；不支持的组合必须构造时拒绝。
- Interceptor.replace/attach 和 Stalker native callback 统一 ownership 规则。

验收：

- 覆盖整数、指针、float/double、混合寄存器、栈参数、回调重入。
- callback 被 native 端持有时，JS GC 不得释放 thunk。
- detach/revert/reload 后 thunk 不再执行，并在安全点回收。

### Goal 05：Stalker ARM64 writer 与可观测性（P0/P1）

目标：补齐上游 transform 的代码生成能力，并提高事件丢弃可见性。

范围：

- 将 GumStalkerOutput/Arm64Writer 安全地暴露给 transform iterator。
- 先实现常用 writer 方法，再补 Arm64Relocator；对象仅在 transform callback 内有效。
- 增加 dropped-events、active traces、retired callbacks 等统计。
- 处理 probe anchor 在模块卸载和 target 地址复用时的生命周期。

验收：

- transform 可替换一条指令、插入 callout、发射跳转，并保持原函数语义。
- writer/iterator 过期访问稳定抛异常。
- queue 满时不扩容、不崩溃，并能读取准确 dropped count。
- 全部现有 Stalker device regression 继续通过。

### Goal 06：Memory 高级能力与 W^X 语义（P1）

目标：补齐常用高级 Memory API，并统一代码写入策略。

范围：

- `Memory.alloc(size, { near, maxDistance, protection })`。
- `Memory.patchCode()`、异步 `Memory.scan()`、`findPointers()`。
- `MemoryAccessMonitor`，先限定 Android ARM64 支持范围。
- 修正文档和实际页权限、flush、owned pointer 生命周期差异。

验收：

- 4K/16K/64K 页设备或模拟测试覆盖对齐计算。
- patchCode 后 I-cache 正确刷新，失败不会留下半写状态。
- monitor/scan callback 在 reload/unload 时可取消且不重入已销毁 runtime。

### Goal 07：标准消息循环与 Script API（P1/P2）

目标：支持依赖 Frida message loop 的通用脚本。

范围：

- `send/recv` 与现有 socket/HTTP RPC 的消息映射。
- timer、`Script.nextTick()`、pin/unpin、weak binding。
- Worker 最后实现，且必须有独立 runtime 与清晰的 terminate/join。

验收：

- 消息顺序、binary data、超时和取消行为有 host/device 联合测试。
- timer callback 与 Java/Stalker callback 并发时无 QuickJS owner 冲突。
- reload 会取消旧 timer/recv/worker，最终 shutdown 无残留线程。

### Goal 08：Java 标准 facade 兼容（P1）

目标：在保留 ART fast hook 和 managed DSL 的前提下，提高 frida-java-bridge 脚本复用率。

范围：

- 首批 aliases：`perform/performNow`、`available`、`androidVersion`。
- loaded class、class loader、`cast/retain/array`、对象 dispose 生命周期。
- `ClassFactory`、registerClass/openClassFile、main-thread 调度分成后续子 goal。
- 在开始实现前固定一份 frida-java-bridge 源码或版本；当前 `/home/qiu/Android/frida` 不包含该仓库的完整源码，不能只凭记忆追平。

验收：

- 同一测试 App 分别由官方 Frida 和 rustFrida 运行兼容脚本，比较结构化结果。
- spawn/attach、boot/app ClassLoader、静态/实例/重载方法均覆盖。
- retain/dispose 后不泄漏 JNI global ref，不访问退休 ArtMethod。

### Goal 09：按需补充外围模块（P2/P3）

候选：Checksum、Cloak、Socket/Stream、SQLite、Sampler、Profiler、Kernel。

选择原则：

- Cloak 对 stealth 和自有线程/范围隐藏有直接价值，可优先于网络/数据库。
- Socket/Stream 只有在明确需要 agent 内网络协议时实现，避免与现有 host transport 重复。
- Profiler/Sampler 依赖 Interceptor、Backtracer 和 callback 生命周期，必须排在 Goal 02/04 之后。
- Android 不需要的 Kernel 或跨平台 API可以返回明确的 unsupported，不追求空壳对象。

## 7. 推荐执行顺序

| 阶段 | Goals | 原因 |
| --- | --- | --- |
| A | 00 -> 01 | 先固定基线和 Gum 来源，防止后续在不确定 artifact 上开发 |
| B | 02 -> 03 | 低风险补齐诊断与对象模型，为后续测试提供工具 |
| C | 04 -> 05 | 先解决 callback ABI，再扩展 Stalker writer 和 native callback 组合 |
| D | 06、07 | Memory 可相对独立；消息循环需要已有 callback/owner 模型 |
| E | 08 | Java 差异大，应在通用 runtime 生命周期稳定后推进 |
| F | 09 | 按实际使用需求选择，不作为“完整 Frida”阻塞项 |

## 8. 所有 Goal 的统一验收门槛

每个 goal 完成时至少执行：

```bash
cargo build --release --target aarch64-linux-android
git diff --check
```

并满足：

- 新增 Rust 单元测试或 host 侧解析测试。
- 新增单一职责的 `tests/device/rfhook_*.js`。
- 覆盖正常执行、重复调用、显式清理、`%reload`、最终 shutdown。
- 目标进程保持存活，无 tombstone、SIGTRAP、BRK、use-after-free 或 cleanup timeout。
- 对官方兼容 API，优先增加“官方 Frida 与 rustFrida 在同一测试 App 上输出同一 JSON”的 differential test。
- 不把设备路径、PID、构建缓存或展开后的 Git LFS 二进制提交到源码 commit。

## 9. Goal 请求模板

后续可按以下格式启动任务：

```text
执行 doc/frida-upgrade-roadmap.md 的 Goal XX。
基线使用文档记录的 Frida/root/gum revision；如本地 revision 已变化，先更新差异记录。
严格限制在该 Goal 的范围内，保留 rustFrida 现有扩展和 legacy API。
完成实现、单元测试、设备回归、reload/shutdown 验证，并按逻辑分步 commit。
若上游语义与当前架构冲突，先把决策和可复现证据写回文档，不要静默改变行为。
```

## 10. 不采用的升级方式

- 不通过只修改 `FRIDA_VERSION` 来声称已追平最新版。
- 不一次性嵌入完整 GumJS runtime 与现有 QuickJS runtime 并行运行。
- 不删除现有 stealth、managed DSL、HTTP RPC、QBDI 或 legacy API 来换取表面兼容。
- 不为当前 Android ARM64 目标移植纯 x86 AVX-512 增量。
- 不在没有 differential test 和 lifecycle test 的情况下引入通用 callback、timer 或 Worker。
