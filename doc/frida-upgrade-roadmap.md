# Frida 17.15.5 差异与升级路线

> 状态：执行中（Goal 00 至 Goal 08b 已完成；八项设备回归全部通过。Goal 09、Goal 10 待做，
> 其中 Goal 10 来自 §4.2 的成员级实测）
>
> 更新日期：2026-07-26
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
| 核心运行时 | QuickJS、`console`、`gc`、`send/recv`、timer、`Script`、`Frida`、`hexdump`、HTTP `rpc.exports` | 同名 API 另有 `Worker` | 部分 | P1/P2 |
| 数值与指针 | `ptr`、`NULL`、NativePointer 大部分运算和读写 | 另有 `Int64`、`UInt64`、pointer sign/blend、`ArrayBuffer.wrap/unwrap` | 部分 | P1 |
| Native 调用 | ARM64 `NativeFunction`、`SystemFunction`，支持 ABI/options、variadic、嵌套 struct | 同名 API | 已有 | P1 |
| Native callback | 通用 `NativeCallback`；CModule 函数指针继续用于高频 callback | 通用 `NativeCallback` | 已有/扩展 | P0/P1 |
| Memory | 同步读写、alloc options、protect、copy/dup、scanSync、异步 scan、patchCode、findPointers、checkCodePointer、queryProtection、MemoryAccessMonitor、stealth patch | 同名 API | 已有/扩展 | P1 |
| Module | 实例 API、ModuleMap、sections/dependencies/ensureInitialized/findSymbol；保留旧式静态入口 | 最新实例 API；旧式静态入口已由上游移除 | 已有/扩展 | P1 |
| Process | 基本属性、模块/范围/线程枚举和目录查询、module/thread observer | 另有 findThread、runOnThread、exception handler、system/function ranges | 部分 | P1 |
| Thread/符号诊断 | `Thread.backtrace()`、Backtracer、DebugSymbol、ApiResolver(module)、Instruction | 另有非 module resolver、硬件断点/观察点、CFG | 部分 | P0/P1 |
| Interceptor | 自研 engine 的 attach/replace/revert/detachAll；`flush` 是兼容 no-op；支持 stealth | Gum Interceptor defaults/options、replaceFast、事务 flush、完整 invocation context | 部分/扩展 | P1 |
| Stalker | follow/unfollow、事件、parse、transform 遍历、callout、probe、native sink、reload cleanup、iterator 上的 Arm64Writer/Arm64Relocator、statistics | transform iterator 同时暴露架构 writer，和 Instruction/Writer/Relocator 深度集成 | 已有/扩展 | P0/P1 |
| CModule | TinyCC、symbol 注入、导出指针、metadata 回收 | 官方 CModule builtins、dispose 和完整 ownership 语义 | 部分/扩展 | P2 |
| File | 同步 File 构造、读写、seek、静态 read/write helpers | GumJS File 行为及异步 I/O 生态 | 部分 | P2 |
| Stream/Socket | 无 | IOStream、InputStream、OutputStream、Socket | 缺失 | P2 |
| 工具模块 | 无 | Checksum、SQLite、Cloak、Sampler、Profiler、Kernel | 缺失 | P2/P3 |
| Java | `use`、`perform/performNow`、`available`、`androidVersion`、`cast/retain/array`、`synchronized`、`ACC_*`、`vm`、`scheduleOnMainThread`、overload、choose、class loader、loaded class、deopt、字段、DSL/fast hook | 官方 bridge 另有 ClassFactory、registerClass、openClassFile、enumerateMethods、backtrace | 部分/扩展 | P1 |
| Host 协议 | 自研注入器、REPL、HTTP RPC | Device、Session、Script message、Portal、Compiler | 不同架构 | 非当前范围 |

### 4.1 当前已经做得较完整的部分

- NativePointer 的基础算术、比较、格式化和常用内存读写。
- Memory 的同步访问、UTF-8/UTF-16、保护查询、同步 pattern scan。
- ARM64 NativeFunction/SystemFunction 的标量、variadic、嵌套 struct、options 与 system error 语义。
- NativeCallback 的跨线程 JS 调度、重入、errno、GC ownership 和 reload retirement。
- Module 实例/ModuleMap、全局导出查询以及 module/thread observer 生命周期。
- Int64/UInt64、DebugSymbol、Thread.backtrace、Backtracer、Instruction 和 module ApiResolver。
- Interceptor 双阶段回调、CModule native callback 和自研 stealth 模式。
- Android Java hook 的常用 `use/overload/implementation/choose` 路径，以及项目特有的 managed DSL。
- Stalker 的事件队列、JS/native callback、call probe、callout、reload/shutdown 生命周期。

### 4.2 影响常见 Frida 脚本迁移的缺口

以下清单来自 2026-07-26 的一次设备实测：把 `doc/frida-api-surface.json` 里抽取的上游成员表
（`gumjs_*_entries`）逐条在真机运行时上 resolve，261 条成员里 60 条缺失。其中约一半是
形状差异而非能力差异——`DebugSymbol`、`Instruction`、`Module` 实例在上游是 class，在
rustFrida 是带同名字段的普通对象，脚本读得到；`Interceptor.attach()` 的返回值同样有
`detach()`，`onEnter` 的 `this` 同样有 `context`/`threadId`/`depth`/`returnAddress`。
剩下的是真缺口：

1. 缺少 `Worker`、`Java.ClassFactory` 与 `Java.registerClass`。
2. `Arm64Writer` 没有独立全局，`Arm64Relocator` 只接受 Stalker transform iterator 作为
   output。也就是说「`Memory.alloc()` + `new Arm64Writer(ptr)` 自己生成一段代码」这种
   上游常见写法在 rustFrida 上跑不了；ARM64 writer 的能力目前只在 transform 回调内可达。
3. `Interceptor` 少 `replaceFast` 与 `defaults`。
4. `Script` 的弱引用三件套只有两件：有 `bindWeak`/`unbindWeak`，没有 `derefWeak`；
   另外少 `load`、`evaluate`、`registerSourceMap`、`findSourceMap`、`setGlobalAccessHandler`，
   `SourceMap` 类也没有。
5. `Process` 少 `runOnThread`、`setExceptionHandler`、`findThreadById`、
   `enumerateSystemRanges`、`findFunctionRange`。
6. `NativePointer` 少 `sign`/`blend`（ARM64 PAC），`ArrayBuffer` 少 `wrap`/`unwrap`。
7. `Thread` 少 `sleep`；`ModuleMap` 实例少 `handle`（rustFrida 的 ModuleMap 是 JS facade，
   没有底层 Gum 句柄）。

已核实**不是**缺口的：`recv(...).wait()` 存在（上游靠内部 `_waitForEvent` 实现，
rustFrida 自己实现了同样的同步等待）；`NativeFunction` 接受 `exceptions`/`scheduling`
选项；`ptr().toMatchPattern()` 存在。

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

- `pthread_shim` 的线程不带独立 TLS，agent 因此只能有一个后台 JS 线程；见 Goal 07 的 §7.1。

Stalker 队列丢弃计数与 call-probe anchor 生命周期已由 Goal 05 处理；`Memory.alloc()` 的页权限与生命周期漂移已由 Goal 06 校正；shutdown 阶段的两处线程崩溃已由 §5.7 修复。

### 5.7 shutdown 阶段不得留下无人等待的线程

两处 tombstone 都是同一个形态：某个线程还在执行 agent 代码，而 shutdown 已经把它脚下的东西拆掉了。两者都在 `993d41c` 修复。

**Gum 不再 deinit。** 丢弃最后一个 `Gum` 句柄会执行 `gum_deinit_embedded()`，它在拆除过程中重新进入 `gobject_perform_init`（gtype.c:4481）——此时 GObject 类型系统已被销毁，取 rwlock 用的指针丢掉了 load base，每次都是 `0x47c00`，在 `wwb-loader` 线程上 SIGSEGV。符号化方法见下。修复是让 `release_gum()` 泄漏该句柄：此时更早的清理阶段已经 unfollow Stalker、revert Interceptor、disconnect module-registry observer，没有任何 Gum 回调还指向 agent；Gum 自己的析构器链表在它的堆里而不是 `atexit`，agent 被 munmap 后不会有人去跑它。

**延时任务必须走 pump。** `schedule_internal_shared_entry_refresh` 原先起一个 detached 线程，在三次尝试之间 sleep。没有人 join 它，shutdown 可以在它还在 agent 里时就 munmap——Goal 08 关闭后观察到 `rf-art-refresh` 线程在已卸载内存上执行。改为投递到 timer pump 的延时后台任务：teardown 会丢弃未开始的任务并 join pump，同时也守住了 §7.1 的单后台线程约束。

符号化 tombstone 的可复现步骤（`release` 构建被 strip，符号必须来自产生该 tombstone 的同一个二进制）：

1. `cargo build --profile release-symbols --target aarch64-linux-android`，跑两遍（`rustfrida` 用 `include_bytes!` 嵌入 `libagent.so`，一遍只会嵌入上一次的 agent）。
2. 用 `--rustfrida target/aarch64-linux-android/release-symbols/rustfrida` 复现。
3. `load_base = pc − (mapping_offset + pc_in_module + delta)`，其中 `delta` 是可执行 LOAD 段的 `vaddr − offset`（`llvm-readelf -lW`）。tombstone 的寄存器区通常已经带着 load base——本例中 `x23` 就是。
4. `llvm-addr2line -f -C -i -e libagent.so <vaddr>`。`lr` 同样要符号化：崩溃点往往只说明"锁坏了"，调用者才说明是谁把它弄坏的。

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

状态：**已完成（2026-07-26）**。

落地证据：

- `Process.get/findModuleByName/Address()` 和 `Process.mainModule` 均返回最新版实例式 `Module`；旧式静态枚举/查询入口继续保留，实例与静态导出查询结果一致。
- Module 实例已提供 ranges/imports/exports/symbols、sections、dependencies、`ensureInitialized()` 和 `find/getSymbolByName()`；`Module.find/getGlobalExportByName()` 使用 Gum 的 unrestricted `RTLD_DEFAULT` 语义，加载顺序与 reload 不改变结果。
- `ModuleMap` 提供过滤快照、地址/名称/路径查询和显式 `update()`；卸载模块会从实时 Process 查询移除，同时旧 ModuleMap 快照保持不变直到更新。
- module/thread observer 支持初始快照、added/removed/renamed、幂等 detach 和 reload 清理；Gum 信号缺失时由实时 modules/threads 快照 reconcile，并以 `{path, base}` 或 thread id 去重。
- `tests/device/run_goal03_module_process.py --device 3B65AU009YA00000` 在 PLC110（Android 16）完成两轮 `%reload`，覆盖普通 SO load/unload、同 SONAME 不同完整路径、memfd、隐藏 soinfo 和线程创建/改名/退出；目标进程存活且没有新增 tombstone。
- maps-only/memfd 的 dependencies 使用带可读 VMA 边界校验的内存 `PT_DYNAMIC` / `DT_NEEDED` 解析，避免 Gum 在线 ELF 解析越过不可读映射；兼容 surface、交叉构建、rustfmt 和 diff 检查均通过。
- `runOnThread` 与 exception handler 按本 Goal 的既定范围继续保留为显式缺口，后续需独立 feature gate 和重入/生命周期验收。

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

状态：**已完成（2026-07-26）**。

落地证据：

- 默认 agent 构建启用 Frida FFI closure；`NativeFunction`、`SystemFunction` 和 `NativeCallback` 均保持最新版 NativePointer 子类形状，支持 `call/apply` receiver override、`default/sysv` ABI 与 scheduling/exceptions/traps options。
- NativeFunction/SystemFunction 支持标量、浮点、栈溢出、C variadic 默认提升、小型及嵌套大型 struct-by-value；SystemFunction 返回 `{value, errno}`，`exceptions: "steal"` 将 native fault 转为结构化 JavaScript 异常。
- NativeCallback 支持标量及嵌套 struct 参数/返回值、任意 native 线程同步进入 JS、callback 内重入 NativeFunction、`this.errno`/`returnAddress`，并可直接用于 `Interceptor.replace()` 与 Stalker 原生 callback 位置。
- callback root 由 native 注册点持有；reload/shutdown 按切断入口、等待 in-flight、释放 JS 引用的顺序清理。由于无法证明外部 native 代码已丢弃旧函数指针，可执行 closure 退休到进程结束；旧指针稳定返回零，不再访问已销毁的 QuickJS runtime。
- `tests/device/run_goal04_native_abi.py --device 3B65AU009YA00000` 在 PLC110（Android 16）完成两轮 `%reload` 和最终 shutdown，覆盖 GPR/FPR、栈参数、pthread callback、errno、variadic、struct、options/fault、重入、Interceptor replace/revert、native/Stalker 持有 callback 后的显式 GC，以及 reload 后旧 callback retirement；目标进程存活且没有新增 tombstone。
- 无 FFI 的标量 fallback 编译、agent/rustfrida release 构建、兼容 surface、JavaScript/Python 语法和 rustfmt 检查均纳入回归。

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

状态：**已完成（2026-07-26）**。

落地证据：

- transform iterator 现在同时是 ARM64 writer，暴露上游 `gumjs_arm64_writer_entries` 的全部 76 个成员（`dispose` 由 facade 持有，因为 Stalker output writer 归 Gum 所有）；`Arm64Relocator` 暴露上游全部 10 个成员。
- opcode 编号、参数规格和 property/function 划分由 `quickjs-hook/src/jsapi/stalker_writer.rs` 单一定义，agent 侧按常量分发，JS 侧完全由 spec 表驱动；寄存器/条件码/index mode 名称由 Gum 绑定生成，不在 JS 侧硬编码 Capstone 数值。
- `tests/compat/test_frida_surface.py` 直接解析该 Rust 表并与上游基线交叉验证成员集合与 kind；该测试在开发中即抓出把 `eoi`/`readOne` 误判为 property/function 的偏差。
- writer 与 relocator 仅在 transform callback 内有效：token 失效后每个成员稳定抛异常，callback 返回时 facade 先销毁该次创建的全部 relocator 再释放 frame。
- `Stalker.statistics()`（rustFrida 扩展）报告 dropped events、active/pending/retired traces、call probe 与 anchor 数量以及每线程队列水位；队列满时只计数不扩容。
- call-probe anchor 记录建立时的模块 identity，地址被另一模块复用时重建；不再被任何用户 probe 需要且没有线程被 follow 时在安全点回收。
- `tests/device/run_goal05_stalker_writer.py --device 3B65AU009YA00000` 在 PLC110（Android 16）完成两轮 `%reload` 与最终 shutdown，45 项断言全部通过；目标进程存活且没有新增 tombstone。
- 设备回归覆盖：用 relocator 手工重发指令后原函数语义不变、`putBLabel`/`putLabel` 跳转确实被执行（否则受保护的 fallthrough 会写标志位）、callout 从生成代码触发、writer 拒绝未知寄存器/条件码、relocator dispose 后拒绝使用且可重复 dispose、一格队列产生可读的 dropped count 且结果不被破坏。
- Goal 02/03/04 设备回归、兼容测试 16 项、API 快照 `--check`、rustfmt 和 diff 检查均通过。

已知既有缺口（不由本 Goal 引入）：

- ~~`tests/device/run_goal01_module_unload.py` 的 `--mode full` 与 `--mode hfollow` 在当前设备上于 shutdown 阶段（`cut_process_observers` 之后）稳定产生 tombstone~~：已在 `993d41c` 修复，详见 §5.7。

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

状态：**已完成（2026-07-26）**。

落地证据：

- `Memory.alloc(size, {protection, near, maxDistance})` 对齐上游语义：亚页大小走堆分配且只读写，页倍数走 mmap 并应用请求的 protection，要求可执行或 `near` 时必须是页倍数。页分配由 NativePointer 的 owner 释放（munmap 而非 free），修正了此前 `calloc` 与 README 所述 RWX 的漂移。
- `near/maxDistance` 由 `/proc/self/maps` 的空洞驱动，候选按到目标的距离排序，用 `MAP_FIXED_NOREPLACE` 放置以免覆盖既有映射；旧内核忽略该 flag 时退化为 hint，结果仍按请求窗口复核。
- `Memory.patchCode(address, size, apply)` 临时提权后调用 JS，优先保留 EXEC 位以免正在执行该页的线程失去执行权；无论 apply 是否抛异常都恢复保护并刷 I-cache，异常原样传播。
- `Memory.findPointers(ranges, values, {mask})` 与 `Memory.checkCodePointer(ptr)` 落地；前者按指针对齐扫描并跳过不可读区段，后者先用 XPACI 剥离 PAC（按 HWCAP 判定，指令以原始编码发射以避开未启用的 `pauth` 汇编扩展）。
- `Memory.scan()` 在独立线程扫描，onMatch/onError/onComplete 经既有引擎 guard 同步进入 JS；清理路径先 `cut_memory_scans()` 再等待 in-flight 回调，长扫描无法活过它要回调的 runtime。
- `MemoryAccessMonitor.enable/disable` 由 Gum backend 实现。GumExceptor 只在 enable 时按需获取、disable 时释放，因此默认路径仍不 claim SIGSEGV（见 `agent/src/crash_handler.rs` 对 ART signal chain 的说明）。
- `tests/device/run_goal06_memory.py --device 3B65AU009YA00000` 在 PLC110（Android 16）完成两轮 `%reload` 与最终 shutdown，每轮 49 项断言全部通过；目标进程存活且没有新增 tombstone。
- 兼容测试 16 项、API 快照 `--check`、交叉构建、rustfmt 和 diff 检查均通过。

已知限制：

- `Memory.scan()` 只提供上游 `_scan` 的 callbacks 形态。上游的 Promise 包装来自 `runtime/core.js`，需要 job queue 才能 settle，随 Goal 07 的消息循环一并补齐。
- 监视区被访问时每次 fault 都同步进入 JS，被监视线程因此显著变慢；这与上游模型一致，但在 rustFrida 的单引擎模型下更明显。相应地，由 `NativeFunction` 调用触发的访问会先被该调用自身的 fault 处理接管，不会报给监视器——监视器面向的是目标自身代码的访问。
- 设备回归据此用独立 fixture 线程触发访问，并直接校验 disable 后每个页的保护位已恢复，而不是依赖被拖慢的线程跑完若干轮。

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

状态：**已完成（2026-07-26）**。

落地证据：

- `send(payload, data?)` 与 `recv(type?, callback)` 落地。新增 agent→host 的 `0x88` SEND 帧与 host→agent 的 `0x03` POST 帧，body 均为 `[json_len:u32][json][binary]`；REPL 新增 `post <json>` 命令，纯文本会被包装成 `{"type":"send","payload":...}`。recv 采用上游的一次性回调语义，未被认领的消息留在队列里等待后续 `recv()`。
- `setTimeout/setInterval/clearTimeout/clearInterval/setImmediate/clearImmediate` 与 `Script.nextTick` 由一个懒启动的 pump 线程驱动；它经既有引擎 guard 进入 JS，并在每次回调后 drain QuickJS job queue——这正是 promise 在顶层脚本返回后仍能 settle 的原因。未调度任何 timer 的脚本不会创建该线程。
- `Script`（runtime/id/nextTick/pin/unpin/bindWeak/unbindWeak）、`Frida`（version/heapSize）与 `hexdump()` 落地。
- `Memory.scan()` 现在返回 Promise（Goal 06 遗留项），callbacks 形态保留。
- `tests/device/run_goal07_messaging.py --device 3B65AU009YA00000` 在 PLC110（Android 16）完成两轮 `%reload` 与最终 shutdown，每轮 33 项断言全部通过；目标进程存活且没有新增 tombstone。覆盖 nextTick 先于零延迟 timeout、短延迟先于长延迟、clearTimeout 生效、setInterval 自停、promise 由 timer settle、send 携带二进制数据到达 host、recv 的通配与具名一次性回调、`Memory.scan` promise 解析与坏 pattern 同步抛出、hexdump 输出。
- Goal 02/03/04/05/06 设备回归、兼容测试 16 项、API 快照 `--check`、交叉构建、rustfmt 和 diff 检查均通过。

### 7.1 单后台线程约束（本 Goal 发现并处理）

`agent/src/pthread_shim.rs` 的 `pthread_create` 用 `raw_clone` 建线程，**不带 `CLONE_SETTLS`**（tls 参数为 0）。因此 shim 创建的所有线程共享同一块 TLS，同时只能安全运行一个：两个并发的 `Memory.scan()` 就足以让目标进程崩溃，与 timer 无关。这是既有限制，Goal 06 只用单个 scan 所以未暴露，Goal 07 的常驻 pump 线程让它必然触发。

处理方式是让 agent 只保留一个后台 JS 线程：timer pump 兼作通用后台执行器，`Memory.scan()` 通过 `submit_background_task()` 把工作交给它，不再自建线程。代价是长扫描会延后 timer，收益是所有后台 JS 入口都归一处治理，符合 §5.2。要根治需要给 shim 补 `CLONE_SETTLS` 并正确分配 TCB，属于独立课题。

期间修掉的其它三类生命周期缺陷，同样值得记录以免重复踩：

- pump 线程用标志表示"已结束"而调用方随即卸载 agent——标志只说明循环退出，线程还有代码要跑；改为 join。
- `cut_timers()` 不释放 callback 导致 `JS_FreeRuntime` 的引用计数断言 abort；改为先等 pump 离开 JS，再在持有引擎的线程上释放。
- 在 phase1 join pump 会与持有引擎的清理线程死锁；改为 phase1 只等回调离开 JS，join 推迟到 phase4 `cleanup_engine` 之后——那时引擎已销毁，pump 不可能再阻塞于它。

未纳入本 Goal 的部分：

- `Worker` 尚未实现，按本 Goal 原定顺序排在最后，需要独立 runtime 与明确的 terminate/join。

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

状态：**首批范围已完成（2026-07-26）**；`scheduleOnMainThread` 与 `Java.vm` 已由 Goal 08b 补齐，`ClassFactory`、`registerClass`、`openClassFile`、`enumerateMethods`、`backtrace` 仍留作后续子 goal。

前置条件（已满足）：

- frida-java-bridge 不在本机 Frida 检出里，改由 frida-tools 的 `agents/tracer/package-lock.json` 固定：版本 `7.0.12`，integrity `sha512-xpoTFPQk…CHRTqg==`，tarball sha256 `8a3b6323…b2b850`。基线记录在 `tests/compat/frida-java-bridge.json`，包含从 `index.d.ts` 提取的 36 个公开成员及其分类。
- `tests/compat/test_frida_surface.py` 校验该基线：版本与 integrity 必须与本机 Frida 的 lock 一致；每个上游成员必须落在"已实现/本 Goal/后续"三类之一，未分类即失败——固定的 bridge 一旦变动不会无人察觉。

落地证据：

- `Java.perform/performNow`、`available`、`androidVersion`、`isMainThread`、`synchronized`、12 个 `ACC_*` 常量落地。`perform` 复用既有 `Java.ready()` 的就绪语义（含 raw-clone worker 路径），`performNow` 同步执行。
- `Java.cast`、`retain`、`array` 落地。`cast` 走真实的 `IsInstanceOf` 校验，转换到无关类会抛错而不是产出一个方法逐个失败的 wrapper；`retain` 建立 global ref 并由 wrapper 的 `$dispose()` 释放，重复 dispose 是空操作；`array` 支持 8 种基本类型与对象数组。
- `Java.enumerateLoadedClasses(+Sync)` 经 JVMTI 的 `GetLoadedClasses` 实现，签名转成 Java 风格类名。
- `Java.ready()`、`.impl`、managed DSL、stealth hook、`hook/fastHook/deopt` 等既有扩展全部保留，兼容层建立在它们之上而非替换。
- `tests/device/run_goal08_java.py --device 3B65AU009YA00000` 在 PLC110（Android 16）spawn `com.example.rfhooktarget`，完成 `%reload` 前后两轮，每轮 47 项断言全部通过；App 存活且没有新增 tombstone。
- Goal 05/06/07 设备回归、兼容测试 19 项、API 快照 `--check`、交叉构建、rustfmt 和 diff 检查均通过。

已知限制：

- `enumerateLoadedClasses` 依赖 JVMTI，而 agent 默认不 late-load JVMTI 插件（需要目标进程环境里 `RF_JAVA_CHOOSE_JVMTI_LATE_LOAD=1`）。该默认是有意的安全策略，因此这里没有绕过它；API 在插件不可用时抛出说明该前提的错误，设备回归据此做条件性校验。上游在 ART 上走 `art::ClassLinker::VisitClasses`，不需要 JVMTI——补齐它需要解析该符号与 ClassLinker 实例并处理 runnable thread，属于独立课题。
- ~~`Java._arrayGet()` 只为对象数组设计，传基本类型数组会使目标进程崩溃~~：已在 `2e4aea2` 修复。`js_java_array_get` 现按元素签名分派到八个 `Get<Type>ArrayRegion`，索引访问也会把对象元素包成 wrapper 再交给脚本；回归改为直接读回元素，同时保留经 `java.util.Arrays.toString` 的 Java 侧校验。

目标：在保留 ART fast hook 和 managed DSL 的前提下，提高 frida-java-bridge 脚本复用率。

范围：

- 首批 aliases：`perform/performNow`、`available`、`androidVersion`。
- loaded class、class loader、`cast/retain/array`、对象 dispose 生命周期。
- `ClassFactory`、registerClass/openClassFile、main-thread 调度分成后续子 goal（main-thread 调度与 `Java.vm` 已由 Goal 08b 完成）。
- 在开始实现前固定一份 frida-java-bridge 源码或版本；当前 `/home/qiu/Android/frida` 不包含该仓库的完整源码，不能只凭记忆追平。

验收：

- 同一测试 App 分别由官方 Frida 和 rustFrida 运行兼容脚本，比较结构化结果。
- spawn/attach、boot/app ClassLoader、静态/实例/重载方法均覆盖。
- retain/dispose 后不泄漏 JNI global ref，不访问退休 ArtMethod。

### Goal 08b：`Java.vm` 与 `Java.scheduleOnMainThread`（P1）

状态：**已完成（2026-07-26）**。

实现前按 Goal 08 的前置条件取回固定版本的源码：`frida-java-bridge-7.0.12.tgz` 的 sha256 与 `tests/compat/frida-java-bridge.json` 记录的 `8a3b6323…b2b850` 一致，语义据此对照而非凭记忆。基线固定的是成员名单，语义须回到源码核对——这次正是这样用的。

落地证据：

- `Java.vm` 的 `perform/getEnv/tryGetEnv` 落地。JavaVM 早已由 `jni_core::get_or_init_vm()` 缓存、invoke table 的封装也已存在，缺的只是 JS 绑定。`getEnv` 背后的查询刻意不做 attach——`getEnv` 与 `tryGetEnv` 的区别只在于对未 attach 线程的处理，两种情况必须可分；`perform` 在需要时 attach，且只在 attach 是自己做的时候才 detach。抛错文案与上游逐字一致。
- `Env` 只带 `handle` 与 `vm`，即上游 `Env` 构造函数写死的两个字段。脚本取 `Java.vm` 是为了拿一个能交给自己 NativeFunction 的 `JNIEnv*`，这一点是精确的；上游那一百多个 JNI 封装是另一层表面，项目自有的 `Jni` 对象已经覆盖，且上游 `index.d.ts` 把 `Env` 标成 `any`，没有承诺更多。
- `Java.scheduleOnMainThread` 落地。JS 函数在没有 `registerClass` 的前提下无法作为 Runnable 交给 Java，因此任务入队后由主线程必经的 native 点取走；与上游一样选 `epoll_wait`（主 Looper 空闲时阻塞在其中），并用绑定主 Looper 的 Handler 唤醒它。
- `tests/device/run_goal08_java.py --device 3B65AU009YA00000` 在 PLC110（Android 16）完成 `%reload` 前后两轮，每轮 65 项断言全部通过；主线程任务按 FIFO 各执行一次，抛错的任务不阻断其后队列；App 存活且没有新增 tombstone。
- 八项设备回归、兼容测试 19 项、API 快照 `--check`、rustfmt 和 diff 检查均通过。

与上游的一处有意分歧：

- 上游的 `epoll_wait` 探针装上就不再卸载。rustFrida 不能这样：进入 JavaScript 要取引擎锁，而那个等待没有超时，常驻探针会让任意一段慢脚本在持锁期间卡住 App 主线程。因此探针只在有待办任务时存在，队列排空后摘除，没有调度时主线程完全不进引擎。摘除动作放在 pump 上执行，而不是在正被摘除的探针内部完成。
- 唤醒用的 Handler 每次调用重建而不缓存：缓存的 wrapper 需要一个 global ref，而 reload 时没有任何环节会释放它。

仍然延后的成员及原因（各自需要独立的重型基础设施，不适合并进本子 goal）：

- `backtrace`：上游用一个大 CModule 实现 ART `StackVisitor` 子类。走 `Thread.getStackTrace()` 只能得到 className/methodName/fileName，缺 `signature`/`origin`/`methodFlags`/`id`——形状不全的 `Java.backtrace()` 比没有更糟，脚本会读到 `undefined`。
- `registerClass`：需要运行时 DEX 生成（上游的 `lib/mkdex.js`）。
- `openClassFile`：依赖 `registerClass` 那条 DexFile 路径。
- `enumerateMethods`：需要 `"java"` 类型的 ApiResolver，而当前 ApiResolver 只支持 module 类型。
- `classFactory`：`loader` 的读写点已经具备（`reflect.rs` 的 `get_app_classloader_local_ref` 与 `set_classloader_override`），但上游的 `ClassFactory.get(loader)` 是 per-factory 的 loader scoping，而当前 `Java.setClassLoader` 是进程级全局覆盖；补齐需要把 loader 显式传进 `find_class_safe`。

### Goal 09：按需补充外围模块（P2/P3）

候选：Checksum、Cloak、Socket/Stream、SQLite、Sampler、Profiler、Kernel。

选择原则：

- Cloak 对 stealth 和自有线程/范围隐藏有直接价值，可优先于网络/数据库。
- Socket/Stream 只有在明确需要 agent 内网络协议时实现，避免与现有 host transport 重复。
- Profiler/Sampler 依赖 Interceptor、Backtracer 和 callback 生命周期，必须排在 Goal 02/04 之后。
- Android 不需要的 Kernel 或跨平台 API可以返回明确的 unsupported，不追求空壳对象。

### Goal 10：独立代码生成与 Interceptor 补齐（P1/P2）

状态：**未开始**。由 2026-07-26 的成员级实测发现（见 §4.2），此前不属于任何 Goal。

目标：让 ARM64 代码生成脱离 Stalker transform 回调，并补上 Interceptor 的两个上游入口。

范围：

- 独立 `Arm64Writer`：能对任意可写内存（典型是 `Memory.alloc()` 的返回值）构造。当前
  writer 的方法只挂在 transform iterator 上，opcode 表（`quickjs-hook/src/jsapi/stalker_writer.rs`）
  已经齐备，缺的是一个不依赖 transform token 的 writer 宿主。
- 独立 `Arm64Relocator`：`output` 参数接受上面的 writer，而不是只认 transform iterator。
- `Interceptor.replaceFast`、`Interceptor.defaults`。
- 顺带评估 `CModule.builtins` 与 `CModule.prototype.dispose`，它们和代码生成的
  ownership 模型是同一类问题。

约束与风险：

- 独立 writer 的生命周期不再由 Gum 的 transform 输出托管，`dispose` 必须真的做事，
  而 transform iterator 上的 `dispose` 必须继续保持 no-op（写出的代码归 Gum 所有）。
  这两条语义不能共用同一个实现。
- `flush()` 与 I-cache 刷新的责任要写清楚：独立 writer 写完后由谁刷，重复 flush 是否幂等。
- `replaceFast` 走的是 Gum Interceptor 的快速路径，而 rustFrida 的 native hook 走自研
  engine。落地前必须先明确这个 target 的 owner 是谁，不能让两套 Interceptor 同时管
  （见 §5.1）。

验收：

- `Memory.alloc()` + `new Arm64Writer()` 生成一段可调用的函数并通过 `NativeFunction` 执行。
- 独立 relocator 把一段已有代码搬到新位置后仍可执行。
- Stalker transform 内的 writer 行为不变，Goal 05 的设备回归继续通过。
- `%reload` 与 shutdown 后不残留可执行映射或未 dispose 的 writer。

## 7. 推荐执行顺序

| 阶段 | Goals | 原因 |
| --- | --- | --- |
| A | 00 -> 01 | 先固定基线和 Gum 来源，防止后续在不确定 artifact 上开发 |
| B | 02 -> 03 | 低风险补齐诊断与对象模型，为后续测试提供工具 |
| C | 04 -> 05 | 先解决 callback ABI，再扩展 Stalker writer 和 native callback 组合 |
| D | 06、07 | Memory 可相对独立；消息循环需要已有 callback/owner 模型 |
| E | 08 | Java 差异大，应在通用 runtime 生命周期稳定后推进 |
| F | 10 | 独立 writer 复用 Goal 05 已建好的 opcode 表；`replaceFast` 需要 §5.1 的 owner 结论已经稳定 |
| G | 09 | 按实际使用需求选择，不作为“完整 Frida”阻塞项 |

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
