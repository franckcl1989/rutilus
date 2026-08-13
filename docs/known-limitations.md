# Rutilus 已知限制

> 本文档如实记录当前 master 实现的已知限制与风险登记。**所有条目都有代码/配置事实依据**，
> 每条后标注来源文件；不编造、不粉饰。随实现变化，本清单应同步更新。

## 一、明确不提供的上游操作（OutOfScope，3 项）

0.8.0 能力冻结时，`nv-redfish` 0.13.0 的 43 个公开类型化写操作中，3 项被明确记录为
`OutOfScope`（有意不提供，区别于"应该实现但尚未实现"的 Unmapped；冻结计数
`FROZEN_OUT_OF_SCOPE_OPERATION_COUNT = 3`，由门禁测试 pin 死，既不能静默增加也不能静默删除）。
来源：`infra-redfish/src/release_baseline.rs`。

| 操作码 | 上游面 | 理由（冻结记录原文要点） |
|---|---|---|
| `system.set-boot-order` | `ComputerSystem::set_boot_order` | 产品 Boot 家族只提供 `BootSourceOverride`（一次性/连续覆盖），**永不提供持久 boot-order 变更**——§22 精神应用于操作面 |
| `update.simple` | `UpdateService::simple_update` | SimpleUpdate 接受远程镜像 URI；§14.3 更新流程只上传制品字节，**不接受用户提供的 URI** |
| `update.start` | `UpdateService::start_update` | §14.3 更新流程是完整 multipart/http-push 上传即应用路径（`RedfishCommand::Update(UpdateCommand::StartUpdate)`），独立 StartUpdate 入口不提供 |

## 二、未实现的 UI 表单

操作表单提供 9 个命令家族（Account、System/Manager/Chassis Reset、BootSourceOverride、
SecureBoot、EventSubscription、FirmwareUpdate、OEM-NVIDIA）。以下家族**没有专用表单**：

| 家族 | 表单现状 | 事实来源 |
|---|---|---|
| Telemetry | `CommandFamilyView::ALL` 刻意不含 Telemetry；表单选择器返回 `OperationFormError::FamilyRequired`；界面提示 "The telemetry write form is a later milestone."；已持久化的遥测命令通过 `wire_command_summary` 在卡片中渲染 | `ui/src/lib.rs` 第 5171、6289-6291、6438 行（`CommandFamilyView::ALL` 9 家族 `:5171`、表单选择器 `FamilyRequired` `:6289-6291`、Telemetry 表单拒绝 `:6438`、later-milestone 提示文案串 `i18n.rs:1654` `hint_telemetry_later`） |
| Log（清空日志 `log.clear`） | 无专用表单（`CommandFamilyView` 中不存在 Log 变体），表单选择器拒绝 | `ui/src/lib.rs` `CommandFamilyView` |
| Control（控制更新 `control.update`） | 同上，无专用表单 | 同上 |
| 管理员设置用户口令（S3-4） | **API 已提供**（`POST /api/v1/admin/users/{principal_id}/password`，管理员可给任意用户——含无口令新建用户——设置/重置口令，`web/src/auth.rs:2363` `set_user_password`，DTO `api/src/lib.rs::AdminSetPasswordRequest`，ROUTE_TABLE 的 `POST /api/v1/admin/users*` 条目 Admin 守卫 + CSRF，审计按 change-password 记录；wave-one S3-4 修复落地，commit 5cd75ae）；**UI 表单为 later milestone**——管理员用户视图只提供创建（`post_create_user` 仅 name+role）、启停、改角色三个动作，无口令字段（`ui/src/lib.rs:9791-9802`）；新建用户需由 **API** 侧设置口令后才能登录（CLI 不存在该命令） | `web/src/auth.rs:2363` `set_user_password`；`api/src/lib.rs` `AdminSetPasswordRequest`；`ui/src/lib.rs:9791-9802` |

命令本身已完整映射到领域 `RedfishCommand` 与执行引擎（`infra-redfish/src/release_baseline.rs`），
限制仅在前端表单面；telemetry 表单明确为 later milestone。

## 三、依赖风险登记（deny.toml 事实）

`deny.toml` 的 `[advisories] ignore` 记录（原文要点）：

### 3.1 quick-xml（RUSTSEC-2026-0194 / RUSTSEC-2026-0195）

- `nv-redfish` 0.13.0 只在它的 CSDL 构建编译器里 pin `quick-xml 0.38.4`；两个漏洞均在
  `quick-xml >= 0.41.0` 修复；
- 产品侧评估的实际风险为低：quick-xml 只编译**可信的 CSDL 输入**（构建期），从不处理运行时、
  设备或用户控制的 XML，且 `csdl-compiler` 从不调用 `NsReader`；
- 每条 ignore 带 **TRIGGER 注释**：一旦上游 csdl-compiler 接受 quick-xml >= 0.41.0，
  必须删除该条目并升级 `nv-redfish`。

### 3.2 rkyv（RUSTSEC-2026-0235）

- 该条目已从 ignore 列表移除：rkyv 是 `rust_decimal` 的**未激活可选依赖**，从不编译，
  在 cargo-deny 图中不可达（`cargo tree --workspace --target all -i rkyv` 无输出）——lockfile 噪音；
- 注释注明：若后续启用 cargo-audit 独立门禁，需要重新登记该条目——该门禁已于 2026-08-12 启用，
  条目以 ci.yml audit 步骤的 CLI `--ignore RUSTSEC-2026-0235` 重新登记（cargo-audit 不读
  deny.toml，见 §七「cargo audit 独立门禁已启用」）。

### 3.3 信息性 unmaintained（RUSTSEC-2024-0436 / RUSTSEC-2026-0173）

- 信息性 unmaintained，无修复版本；由 **leptos 0.9 迁移**一并解决。

### 3.4 依赖禁令（`[bans] deny`）

`lapin`/`rdkafka`（产品不用外部消息代理）、`native-tls`/`openssl`（TLS 用 rustls）、
`postgres`/`tokio-postgres`（只用内嵌 SQLite）、`redis`（不用外部缓存或队列）。
`multiple-versions = "deny"`、`wildcards = "deny"`；`[sources]` 仅允许 crates.io，`allow-git = []`。

## 四、Windows 高并发测试 flake 缓解（--test-threads 4）

- 现象：测试套件在默认每 CPU 并发下，HTTPS mock-server 频繁创建/销毁导致 Windows
  临时端口池耗尽（WSA 10055），在 32 核机器上验证复现（2026-08-12）；
- 缓解：`cargo nextest run --test-threads 4` 与 `cargo llvm-cov ... -- --test-threads 4`
  固定为 4 线程，该数值在本地与 CI（ubuntu）均确定；
- 来源：`.github/workflows/ci.yml`（nextest 与 llvm-cov 步骤注释原文）。

## 五、测试基础设施局限（合成 fixture 非真实设备响应）

- 测试与演示使用**自研 Mock BMC**（`test-support`）：固定资源树、固定确定性证书；
  vendor profile（Dell / XFusion / Inspur）只是身份字符串或固定表面的变体，**不是真实设备的响应**；
- 代码库中**尚无**脱敏真实设备 fixture 目录（设计 §19.1 要求 Dell/HPE/Lenovo/xFusion/Inspur
  各固件版本的真实响应 fixture 并随上游升级回归）——属于 0.9.0 内容；
- 真实设备验证（五厂商至少各一台进入 1.0.0 认证矩阵，§19.1）尚未达成；
- 含义：当前对真实 BMC 兼容性的结论都应视为"基于上游类型面与 mock/fixture 验证"，不是实测认证。
- 进程级故障注入演练套件（`scripts/drills/`，2026-08-12 落地）同样基于 **mock-bmc + 自研
  delay relay 合成 fixture**（非真实设备、非真实中断形态）：`drill-sqlite-write-interruption`
  受 Windows 文件语义限制只能模拟「启动时不可用」，无法模拟运行中句柄被外部抢占；`drill-bmc-restart-during-task`
  的 mock 不推进 Task 状态（操作恒滞留 `WaitingRemote`）；**首轮实跑 6/6 SKIP**（2026-08-12，
  如实登记：执行上下文（Claude Code 工具进程 spawn）ConPTY 不可用——伪控制台子进程一律
  0xC0000142 启动失败、零输出（含 cmd.exe 对照），产品 rutilus.exe 在普通管道下正确报错退出 1
  （"local unlock requires an interactive terminal"），非产品问题；该问题同时暴露套件硬挂起
  缺陷，挂起防护修复后快速 FAIL 路径已验证），**功能验证待真实交互控制台会话复跑**；
  **磁盘空间不足场景未覆盖**（无管理员权限的可靠模拟手段受限）。
  修复记录（迭代十二，2026-08-12，commit 318eadd）：`Invoke-MockHttps` 证书 Pin 原用
  `GetCertHashString()`（.NET Framework 上为 SHA-1）比对 mock-bmc 的 SHA-256 指纹恒失败
  （drill-kill-mid-operation 幂等断言健康环境必然 FAIL），已改为 C# 委托（脚本块回调在无
  runspace 的 TLS 工作线程无法执行）SHA-256-of-DER 归一比对，与产品侧
  `Sha256::digest(certificate_der)`（`domain/src/endpoint.rs:490`）逐字节同值，真实 mock-bmc
  端到端验证（正确 pin→200、篡改→拒绝）；另修 `[string]$Body=$null` 强转 '' 致 GET 带空
  StringContent（ProtocolViolationException）与 `Start-MockBmc` 缺省 -Port 传空参数列表致
  Start-Process 参数校验异常（改传 '0' 由 mock-bmc 自选端口 + stdout URL 回读，.Port 恒为
  真实端口，探针验证启动/连接/清理）。
  另登记两项 drill 已知限制（实跑前可不修）：`Get-FreeTcpPort`
  （`drill-lib.ps1:90-96`）为 bind-0/释放/重绑模式——探测与真实绑定之间端口可能被
  抢占（TOCTOU），串行执行下概率极低，仅偶发伪 FAIL；`drill-large-file-interruption`
  的「chunk 6 在飞」由固定 400ms 睡眠启发式保证
  （`drill-large-file-interruption.ps1:129-133`），快/慢机器上时序漂移可能
  伪 FAIL/伪 PASS。

## 六、发布级容量建议已发布（release 构建数据，正式规模环境复核仍待做）

- 设计 §0.9.0 的"最低验证规模"（单 Site 200 Endpoint、单 Center 100 Site、中心汇总
  5,000 Endpoint）已由合成规模压力/容量套件**实测落地**（`persistence/tests/stress_capacity.rs`
  3 个测试，2026-08-12：开发机 debug 构建 + WAL 基线，及 release 构建 3 次全过；详见 §八与
  `docs/operations-manual.md` §九），不再是"仅测试目标"；
- **发布级容量建议已发布（release 构建数据，2026-08-12，见 `docs/operations-manual.md` §九）**：
  设计 §0.9.0 要求"测试后发布真实容量建议"（`redfish-management-product-final-design.md:2810`），
  release 构建实测数据（Windows 11 Pro x64 开发机、单机、合成 fixture 规模）已作为发布级
  建议的第一依据；**正式规模环境复核仍待做**；
- 中心为单节点 SQLite 生产中心，非主动—主动集群（§9.1、§15.7）——这是有意设计，不是缺陷；
- 已知的产品侧规模约束（非容量测试结果）：批量操作/批量刷新目标上限 128、刷新并发 4、
  单次查询上限 1000、制品分块 4 MiB、CSV 导入 1 MiB / 10,000 行、中心协议帧 8 MiB。

## 七、其他现状限制（如实）

| 限制 | 说明 | 事实来源 |
|---|---|---|
| 遥测保留期只能 CLI 配置 | 保留期已可配置：`rutilus run` / `service install` / `service run` 的 `--telemetry-retention-days`（默认 7 天，范围 1–365，`app/src/telemetry_sampler.rs` 的 `TelemetryRetention`）；"设置页"形态的设置面仍是 later iteration | `app/src/telemetry_sampler.rs`；`app/src/main.rs` |
| 事件监听器失败后不自动恢复 | 连续 10 次重连失败（预算约 4 分钟）后端点监听器标记 Failed 并退出；supervisor 周期重扫**刻意不**重新拉起 Failed 端点（重新拉起是 later iteration），Failed 状态在本次进程运行内保持终态，重启后由首轮重扫恢复 | `app/src/event_listener.rs` |
| 事件监听懒启动已实现 | 监听器随登记端点存在性驱动（§14.4 EventService SSE）：supervisor 每 10 秒重扫登记集（`LISTENER_RECONCILE_INTERVAL`），首轮扫立即执行并拉起全部已登记端点（重启恢复），运行中登记的端点在其后 10 秒内自动拉起监听，端点离开登记集则停止其监听器（结构化 drain）；登记集枚举走轻量端点表查询（`store.list_endpoints()`，与遥测采样共用 `StandaloneEndpointLister`），不再是启动时的资源清单查询 | `app/src/event_listener.rs`；`app/src/standalone_runtime.rs` |
| 日志设施范围受限 | 设计 §6.2 的 `tracing` + `tracing-subscriber` 已进入 workspace；app/application/platform 的运行诊断经 `tracing::error!`/`warn!` 记录，由 app 二进制在启动时初始化 stderr subscriber（`RUST_LOG` 过滤，默认 `info`）；**CLI 用户可见输出**（init 向导、backup 结果、doctor 报告、console 横幅、bootstrap code）仍为 `println!`（§7.6 用户信息与诊断信息分离），测试基础设施与测试内诊断（`test-support` mock、`infra-redfish` 测试）仍用 `eprintln!`（无 subscriber 上下文）；运行路径已接入 span/`#[instrument]`，`--log-format json`（`LogFormat`/`init_tracing`）输出结构化 JSON，`RUST_LOG` 过滤不变 | 根 `Cargo.toml`；`app/src/main.rs`；`app/src/event_listener.rs` 注释 |
| `cargo audit` 独立门禁已启用 | 独立 `cargo audit --deny warnings` 门禁已入 CI（2026-08-12，§19.4）；cargo-audit 只读 audit.toml、不读 deny.toml，故 ignore 列表以 CLI `--ignore` 镜像 deny.toml `[advisories]`（quick-xml 两条 TRIGGER、两条 unmaintained、以及 §3.2 预告的 rkyv RUSTSEC-2026-0235），需与 deny.toml 同步维护 | `.github/workflows/ci.yml` |
| CI 与发布目标差异 | CI 编译验证 linux-gnu / windows-msvc / darwin x86_64 + wasm32 UI 产物 + x86_64/aarch64 musl + macOS Universal 2（lipo 合并）；windows/macos 任务运行跨平台 E2E 套件；`aarch64-pc-windows-msvc` 未入 CI（hosted x64 Windows runner 无 ARM64 MSVC 工具链，见 ci.yml 注释） | `.github/workflows/ci.yml`；`deny.toml` |
| 产品版本号（已统一）+ Git Commit 嵌入 | workspace 版本 = `0.9.0`（生产候选，`rutilus version` 输出），单一版本来源 = 根 `Cargo.toml` `[workspace.package] version`（`Cargo.toml:14`）；`rutilus version` 输出**三行**（`app/src/main.rs:733-737`）：产品版本 / `nv-redfish` 开发基线 / `git commit`——CI 构建经 job 级 `RUTILUS_GIT_COMMIT` 注入（`ci.yml:60-71`，值为 `github.sha`），`GIT_COMMIT` 常量嵌入（`app/src/main.rs:38-40`），本地构建（无该变量）降级为 `dev`（不 spawn git 子进程）；版本/日志格式测试断言由 `env!("CARGO_PKG_VERSION")`、`NV_REDFISH_DEVELOPMENT_BASELINE` 与编译期 `RUTILUS_GIT_COMMIT` 派生（`app/tests/version.rs:27-36`、`app/tests/log_format.rs:23-28`），升级只改一处 | 根 `Cargo.toml:14`；`ci.yml:60-71`；`app/src/main.rs:38-40, 733-737`；`app/tests/version.rs:8-11, 27-36`；`app/tests/log_format.rs:7-10, 23-28` |
| macOS 非绝对静态链接 | macOS 上只承诺单文件、无随包动态库、仅系统框架（不做"绝对零动态依赖"承诺，§5.3） | 设计文档 §5.3 |
| UI 本地化（✅ 完整：827 键 En/Zh 双语 + 运行时语言选择器 + URL fragment 持久化） | ✅ 完整（commit d3f7769 + 0f91c17 + c4dd335）：`ui/src/i18n.rs` 目录扩至 **827 键 En/Zh 双语**（`strings_catalog!` 宏 `i18n.rs:43-160`、目录体 `i18n.rs:163-1858`）、`Lang::{En, Zh}` 运行时语言选择（`thread_local!` `i18n.rs:1938-1942`、`L()` `i18n.rs:1968-1973`、`format_catalog` `i18n.rs:1984-2006`）；lib.rs `LanguageSelector` 组件（`lib.rs:11640-11658`）——**URL fragment 持久化方案**：语言选择写入 `#lang=` fragment，因为当前 web-sys feature 面只暴露 `Window`/`Location`——fragment 是唯一可用的浏览器存储（`i18n.rs:1901-1905` `LANG_FRAGMENT_PREFIX`）；**迭代七（T-H，commit c4dd335）已把持久化拆为纯函数 + 薄封装**：`stored_lang_code_from`/`lang_fragment_value`（`i18n.rs:1915-1936`，host 可测、不触 web-sys）＋`stored_lang_code`/`persist_language`/`apply_language`（`ui/src/lib.rs` wasm `browser` 模块 `lib.rs:11607-11635`，仅读写 `window.location`，运行时行为不变）；启动时经 fragment 恢复（`start()` `lib.rs:11661-11664`），切换后 reload 全量重挂载；**localStorage 后续触点**：localStorage 持久化需扩展 web-sys feature（`Storage` 面当前未启用），与更多语言同为后续触点；深度翻译已全部完成（facts/健康词汇/`OEM_UNSUPPORTED_NOTICE` 均入目录，`i18n.rs:825-829, 867`）；i18n 15 测试（既有 11 个 `i18n.rs:2009-2185` + fragment 纯函数 4 个 `i18n.rs:2192-2259`）、ui 141 测试全过、clippy/fmt 干净；J2 审计 3 处 zh 译法微修已合入（`type_nvidia_profile_file`/`fact_power_load_percent`/`fact_metric_values`，`i18n.rs:444, 597, 733`）。审计（I1）MINOR 保持：`i18n.rs:1` 头注释 §5.1 引用不可核验（设计文档无「本地化/i18n」条目）、`L.action_delete`/`L.field_role` 语义复用；「`aria-label="Loading"` 未抽取」已在 H5 解决（aria-label 全部走目录键，如 `lib.rs:11955` `L().aria_loading`）；后续项登记见 `milestone-status.md` §7.2-A「UI 本地化」行 | `ui/src/i18n.rs`；`ui/src/lib.rs:11607-11664`；`web/assets/` |
| 发布管道（签名 + SBOM + 校验清单）代码侧就绪 | 🟡 代码侧完成（commit 34503ea + d77d54e）：`scripts/` 5 脚本（sign-windows.ps1 / sign-macos.sh / sign-linux.sh / checksums.sh / checksums.ps1）+ ci.yml `release-artifacts` job（`ci.yml:424-704`：`v*` tag / `workflow_dispatch` 触发、`needs: ci` 门禁先行、签名步骤仅在 secret 配置时执行、base64 物化、Windows thumbprint-only 模式、cargo-cyclonedx@0.5.9 钉版 SBOM、SHA-256 清单、artifact 上传）；证书未到位，签名在首跑前保持 "signing skipped: certificate not configured"；**首跑确认点 6 项**（证书到位后核验）：① musl-tools 安装（`ci.yml:499`）② cargo-cyclonedx@0.5.9 钉版（`ci.yml:667`）③ base64 物化（`ci.yml:552-562, 577-586, 610-617`）④ env 的 `&&`/`||` 表达式（`ci.yml:570, 600, 628`）⑤ thumbprint-only 模式（`ci.yml:567-572`）⑥ 上传权限（`ci.yml:689-694`） | `.github/workflows/ci.yml`；`scripts/`；`release-readiness.md` 条件 17 |
| HTTP 成功不等于业务成功 | 200/201/202/204 不直接等于业务成功，写操作后必须重新读取验证；响应丢失时非幂等操作标记 Unknown 而不盲重试（§13.5） | `operation-engine`；设计文档 §13 |
| 登录限速窗口固定 | 每用户名 5 次 / 每地址 20 次失败、15 分钟窗口，为代码内常量；桶键内存有界（`BUCKET_PRUNE_THRESHOLD` 4096 周期剪枝，T-D commit e7aef53，见 §九该行） | `web/src/auth.rs` |
| 事件流重连预算有限 | 超出预算的长期不可达端点以 Failed 呈现而非无限重试（有意设计，见上） | `app/src/event_listener.rs` |
| Center 角色站点作用域 | 中心角色可限定到某些 Site，但用户与会话管理仅 Administrator（有意设计） | `web/src/auth.rs` |
| 审计只追加 | 审计记录不通过正常 ORM Repository 更新或删除（§16.3） | `domain/src/audit.rs` |
| 密码策略：至少 12 字符（API 边界执行） | 产品密码策略 = 至少 12 个 Unicode 标量字符（`MIN_PASSWORD_CHARS`，`password_satisfies_policy`，与 UI 表单同一检查）；**执行边界在 API**（`web/src/auth.rs:1519`）：登录入口在限速/查找/验证之前拒绝，不占限速预算、不写审计（策略违规不是登录尝试；响应本身即记录）；控制台表单的 12 字符下限是客户端便利，不是控制面（深度审查批次 B1，commit 8147bc9） | `web/src/auth.rs:1488-1489, 1519, 1739, 1897` |
| 429 限速拒绝不写审计 | 登录限速拒绝（429）**不写审计事件**：请求在验证前就被拒绝，从未构成一次登录尝试，429 本身即记录；写 started+failed 对会令审计表随拒绝洪泛无界增长，且每次审计追加都串行在 persistence 写门（`Semaphore(1)`）上，429 洪泛会饿死合法 session/telemetry/event/operation 写入（深度审查批次 B2，commit 8147bc9；§16.3 审计的是"已运行的登录结果"，被拒请求从未运行） | `web/src/auth.rs:1540-1566` |
| ETag 现状（PATCH 家族真实生效，快照接线已处置） | `update` 写家族（PATCH 家族）携带**本次执行读取时**的目标文档 ETag：带 `@odata.etag` 时发送 `If-Match: <etag>`，BMC `412 Precondition Failed` 即证明写未执行（gateway 报告 `CommandExecutionError::PreconditionFailed`，先重读目标，并发变更不被覆盖）；无 ETag 的文档保持传输层存在性 `If-Match: *`（§13.4 第二段，无并发保护）；action/create/delete 家族在类型化 API 中无 If-Match 通道，从不发送（深度审查批次 commit 6128a17）；**快照 ETag 接线已处置（§九，决策 c，2026-08-12）**——快照已持久化 ETag（`domain/src/resource_snapshot.rs:606-655, 790`、`persistence/src/resource_snapshot_repository.rs:402, 553-554, 605-608`），operation-executor 无消费方是登记过的决策而非遗留：执行时读取恒为分派时刻最新 ETag，快照 ETag（恒更旧）无独立写路径价值，接入不实施（理由与证据见 §九该行） | `infra-redfish/src/redfish_gateway.rs:598-611, 12653-12690, 14002-14062` |
| 迁移 down 先子后父纪律 | 多表迁移的 `down` 先删引用子表再删父表（外键顺序），如 `m20260805_000005_operations.rs:131-138` 先 `OperationTarget` 后 `Operation`（深度审查批次 commit 1711329）；机械门禁已落地：`migration/tests/down_order_gate.rs`（2026-08-12 迭代十）纯静态机械检查全部迁移 down 的 DROP 顺序——builder `drop_table` 与 raw `DROP TABLE`（含 rebuild 型 down）均覆盖，依赖图自 FK 边（builder 链 + raw `ALTER ... REFERENCES`）跨文件聚合提取，注释/字符串不参与，与裸 SQL 门禁同款无库形态 | `migration/src/` |
| Secret 扫描门禁白名单纪律 | `security/tests/secret_leak_gate.rs` 的 `ALLOWED_CONSTANT_HITS` 是仅有的 2 处白名单（`app/src/backup.rs:88, 89`：`ENTRY_MASTER_KEY`/`ENTRY_SYSTEM_MASTER_KEY` 备份条目名，值非秘密材料）；每条绑定 path+line+name+literal 四元组——常量移动/改名/值变都会使门禁失败，需重新审查确认无秘密后再更新条目（deny.toml TRIGGER 注释同款纪律）；测试作用域与 `test-support` crate 按**上下文**豁免而非按值白名单（值白名单会掩盖未来真实秘密；`test-support` 目录级豁免属 E3b 原始提交 eefde7e，深度审查批次 commit e8424df 另补 `strings_catalog!` 宏体结构豁免——CATALOG_MACRO 帧识别 + 新测试 `strings_catalog_macro_bodies_are_copy_construction_not_secret_assignments`，wave-one（commit 73d480d）另补间接赋值盲区，见 `milestone-status.md` §7.4/§7.6） | `security/tests/secret_leak_gate.rs:366-373, 96-101, 1258` |

## 八、与设计文档的已知偏差（实现状态，如实）

| 设计项 | 现状 |
|---|---|
| §19.1 Fixture 测试（真实响应 fixture 目录） | 尚未建立 |
| §19.1 Physical Device Test（五厂商真实设备认证矩阵） | 尚未达成 |
| §0.9.0 性能容量测试与真实容量建议 | 部分：合成规模压力容量套件已落地并实测（`persistence/tests/stress_capacity.rs` 3 个测试：200 Endpoint Generation 一致刷新 / 100 Site outbox-inbox-cursor / 5,000 Endpoint 中心投影幂等重投，2026-08-12）；实测数据为**开发机 debug 构建合成数据**（5,000 投影写入 ≈865 行/s、清单查询 0.482s；写路径受 `write_gate`（`Semaphore(1)`）全局串行化，`persistence/src/lib.rs:101, 240`）；**发布级容量建议已发布（release 构建数据，2026-08-12，见 `docs/operations-manual.md` §九）**——设计 §0.9.0 要求"测试后发布真实容量建议"（`redfish-management-product-final-design.md:2810`），正式规模环境复核仍待 |
| §6.2 tracing 日志选型 | 已实现（app 诊断日志 + `RUST_LOG` 过滤的 stderr subscriber）；用户可见输出仍为 `println!`，测试/工具输出仍为 `eprintln!`（见 §七"日志设施范围受限"）；运行路径已接入 span/`#[instrument]`，`--log-format json`（`LogFormat`/`init_tracing`）输出结构化 JSON，`RUST_LOG` 过滤不变 |
| §14.4 遥测保留周期可配置 | 已实现：`--telemetry-retention-days`（默认 7 天，范围 1–365，`TelemetryRetention` 在边界校验）；设置页形态为后续迭代 |
| §14.4 Event 存储增长（展示有界、存储无界） | `events` 表仅有查询层有界（`migration/src/m20260805_000008_events.rs:84-86` 所注 bounded recent-event listing，console 展示「最新 5 条」有界，与设计 §14.4 一致），**无存储级删除路径**，表随运行时长增长——存储增长为已知边界（设计 §14.4 仅 Telemetry 要求「有界历史 + 保留周期可配置」，Event 项未要求保留周期），未来引入保留周期配置时处理 |
| §12.4 诊断中的解码错误路径 / ExtendedInfo 展示 | ✅ 已实现（E1，commit ce2b8b3）：记录层——`ResourceExtendedInfo`/`ResourceDecodeFailure`（`application/src/resource_diagnostics.rs:36, 249`）、api 契约 9 字段（`api/src/lib.rs:1894-1905`）、web 投影（`web/src/lib.rs:4235` `project_resource_diagnostics`）、ui 只读区块（`ui/src/lib.rs:15495`）、端到端测试（`web/tests/diagnostics_path.rs` 7 个测试，含 `:1008` `refresh_capture_flows_into_the_diagnostics_response`）；**生产捕获点已实现**：刷新解码失败由 gateway 捕获（`DecodeFailureObservation`，`infra-redfish/src/redfish_gateway.rs:8720`；捕获函数 `capture_fetch_failure`/`capture_projection_failure`/`capture_segment_decode_failure` `:8904/:8931/:8977`），经刷新结果 `outcome.decode_failures()`（`:8831`）流入同代事务提交（`persistence/src/resource_snapshot_repository.rs:81-147`），生产链路直连（`application/src/endpoint_refresh.rs:350-355`），持久化于新表 `resource_decode_failures`（entity `entity/src/lib.rs:28`、`entity/src/resource_decode_failure.rs:13`；迁移 `migration/src/m20260812_000001`）——真实解码失败会出现在诊断视图中。**如实注记**：① 捕获时 `odata_type` 为 `None`（`capture_fetch_failure` 恒传 None，`redfish_gateway.rs:8915-8922`，解码失败记录不带 OData 类型）；② 表约束经 E4 修复（`migration/src/m20260812_000002` 重建 `resources`/`resource_decode_failures` 两表，`ck_*_feature` 允许域 = 领域枚举全部 47 码，此前 resources 37 / resource_decode_failures 36 且互相不一致；`down` 对称恢复 37/36；防回归机械测试 `migration/tests/resource_feature_lists.rs`）；③ 真实设备上的解码失败形态仍需实测（B 类演练项）；④ 贯通测试已补齐（T-G 8482d85，见 §九该行） |

## 九、深度审查遗留项登记（2026-08-12，LOW/NOTE）

> 多角色多维度深度审查（HEAD = a4950fc：52 项发现 / 16 项对抗验证 / 2 HIGH + 13 MEDIUM 已修复 /
> 1 项结论被推翻，详见 `docs/milestone-status.md` §7.4）后剩余的低优先级项与后续迭代触点。
> 全部为 LOW/NOTE 级，不阻塞 0.9.0/1.0.0 功能面；按主题登记，如实记录现状与后续方案。
> **迭代七（2026-08-12，HEAD = 61b9cc5）已把 8 项全部落地/处置**：T-A 84451b9（mock-bmc 统一
> 二进制）、T-I 044bae2（AMI/HPE 真网关 E2E）、T-H c4dd335（fragment 纯函数测试）、T-G 8482d85
> （decode-failures 贯通测试）、T-B 4897b22（入网首刷走端点读门）、T-D e7aef53（限流器桶键
> 剪枝）、T-E 02459dc（恢复前快照）、T-F 83ff07f（free-port 竞态消除），T-C 为文档化决策
> （快照 ETag 保持只读角色，无独立写路径消费价值，不实施接线）；第 9 个提交 61b9cc5
> （secret-gate 白名单行号 83/84→88/89 对齐 backup.rs 头文档漂移——`ALLOWED_CONSTANT_HITS`
> 的 path+line+name+literal 四元组绑定使常量移动即门禁失败，触发本提交刷新并重新确认无秘密
> 材料，门禁漂移检测触发-修复闭环）；三批五维审计全部 APPROVE，
> 审计记录见 `docs/milestone-status.md` §7.5。下表各行已同步为最终状态。
> **2026-08-13 追加两行**：N2-6（sessions 无界增长——软撤销有意决策 + 无清理路径 + 增长特征
> 登记）与 C5-8（`Hello.last_acked_sequence` 死字段——契约漂移处置：保留、不接线、不改 wire），
> 均为 NOTE 级如实登记。

| 遗留项 | 级别 | 现状 / 后续方案 | 事实来源 |
|---|---|---|---|
| 限流器桶键淘汰 | LOW | ✅ **已实现**（2026-08-12，T-D，commit e7aef53）：周期剪枝——`BucketMap` 随新键插入计数，达 `BUCKET_PRUNE_THRESHOLD`（4096，`web/src/auth.rs:133`）触发全表清扫，回收全部过期桶（dormant 键随窗口滑动清理，含仅 `allows` 创建的空桶；`prune_if_due` `:1106-1121`、`prune_expired` `:1122-1133`，`BucketMap` `:976-1160`）；清扫与访问路径共用同一过期判定，限速判定逐字节不变；内存有界 = 一个窗口内活跃桶工作集 + 4096，不再随时间线性累积。测试：`rate_limiter_prunes_expired_buckets_to_a_bounded_size`（`:3238`）/`rate_limiter_prune_spares_active_buckets`（`:3306`）/`rate_limiter_prune_reclaims_compensated_empty_buckets`（`:3350`，wave-one S3-3 原子 reserve/refund 后由 `..._created_by_allows_only` 更名）/`prune_expired_reclaims_only_buckets_whose_entries_left_the_window`（`:3385`），web 147 测试全过 | `web/src/auth.rs`（§16.2 限速器区块）；`docs/security-review.md` §三 N3 |
| i18n fragment 纯函数测试 | NOTE | ✅ 已落实（2026-08-12，T-H，commit c4dd335）：`#lang=` 语言持久化拆分为纯函数 `stored_lang_code_from`/`lang_fragment_value`（`ui/src/i18n.rs:1915-1936`，host 可测、不触 web-sys）＋薄封装 `stored_lang_code`/`persist_language`/`apply_language`（`ui/src/lib.rs` wasm `browser` 模块 `:11607-11635`，仅读写 `window.location`，运行时行为不变）；纯函数单元测试 4 项（`fragment_reading_extracts_only_the_lang_value` `:2192`、`fragment_persistence_writes_the_lang_value` `:2218`、`fragment_persistence_round_trips_both_languages` `:2229`、`fragment_lang_selection_falls_back_to_en` `:2248`，覆盖前缀解析、写入值、格式往返、空/未知码降级边界）与既有 i18n 测试同模块同风格，host 运行；ui 141 测试全过 | `ui/src/i18n.rs:1915-1936, 2192-2259`；`ui/src/lib.rs:11607-11635` |
| decode_failures 贯通测试（endpoint_refresh） | NOTE | ✅ 已补齐（2026-08-12，T-G，commit 8482d85）：经 `endpoint_refresh` 生产链路的贯通测试 4 项（`application/tests/refresh_decode_failures.rs`，头注释 `:3-22`），真实 `EndpointRefresh` + 真实 `SqliteStore`（application dev-dependency 引入，dev 环为 cargo 允许形态）：解码失败经读产物 `outcome.decode_failures()`（`endpoint_refresh.rs:353`）同代事务落 `resource_decode_failures` 且与快照同 Generation 原子可见（成功路径）；提交失败记录随该代一起回滚；能力探测失败后已提交记录仍与快照原子保留；记录按 Generation 作用域、跨刷新不泄漏。构造忠实网关捕获语义（`odata_type` 恒 `None`、标准 feature 无 OEM namespace）；application 322 测试全过 | `application/tests/refresh_decode_failures.rs`；`application/src/endpoint_refresh.rs:350-355` |
| AMI/HPE 真网关 E2E | LOW | ✅ 已实现（2026-08-12，T-I，commit 044bae2）：AMI/HPE 读取家族（`AmiServiceRoot`/`ConfigBmc`、`HpeiLoServiceExt`/`HpeiLo`）通过**真实网关**的 E2E 解码 5 测试已合入（`test-support/tests/gateway_mock_bmc.rs`：`ami_profile_probes_oem_ami_supported_with_standard_surface_unchanged` `:1793`、`ami_profile_reads_oem_ami_snapshots` `:1861`、`hpe_profile_probes_oem_hpe_supported_with_standard_surface_unchanged` `:2003`、`hpe_profile_reads_oem_hpe_segments_snapshot` `:2070`、`namespace_free_endpoint_leaves_ami_and_hpe_families_absent` `:2202`）；该套件现共 **28 测试**（原 23 + 5），头注释已更新（`:3-17`） | `test-support/tests/gateway_mock_bmc.rs`；`test-support/src/mock_bmc/profile.rs` |
| restore 预恢复副本 | LOW | ✅ 已实现（2026-08-12，T-E，commit 02459dc）：`restore_backup` 在首个覆盖动作前把当前数据目录复制进同级临时目录（`create_pre_restore_snapshot`，`app/src/backup.rs:300-308, 636-664`，与迁移前恢复副本同款 length-verified 拷贝 + 同步），此后才进入覆盖阶段（`restore_data_phase` `:342-372`）。**三态**：① 恢复成功——临时快照随 TempDir drop 自动清除（`:310-315`）；② 恢复中途失败——快照保留并随错误报告其位置供人工回滚（`:317-324`，`RestoreFailedPreservingSnapshot`）；③ 快照创建失败——恢复中止、数据目录原样未动（`:306-308`）。测试：`a_failed_restore_preserves_the_pre_restore_data_for_rollback`（`:1324`）/`a_successful_restore_cleans_up_the_pre_restore_snapshot`（`:1401`）/`a_failed_pre_restore_copy_leaves_the_source_untouched`（`:1421`）；rutilus 152 测试全过 | `app/src/backup.rs:246-341, 636-664` |
| free_port TOCTOU | NOTE | ✅ 已消除（2026-08-12，T-F，commit 83ff07f）：各绑定点改为端口重试——探测端口在探测与真实 bind 之间被抢占时（bind 返回 `AddrInUse`）换新端口重试，不再因竞态窗口失败（`is_raced_*_bind` 判定 + 重试循环）；`center_acceptor.rs` 的 `bind_acceptor_with_options` 探测可注入（`app/src/center_acceptor.rs:1011-1026`，`is_raced_bind` `:997-1010`），确定性重试测试 `the_bind_retries_when_the_probed_port_was_grabbed`（`:1038`）证明竞态消除；另发现并修复同款内联第 5 处（`a_not_bound_refusal_from_the_center_converges_the_local_binding` 的 acceptor bind，`site_runtime.rs:2079`）；`connect_with_retry_stops_on_the_stop_signal` 的「无人监听端口」用途保持探测语义（其后无真实 bind 可重试，`center_client.rs:886`）；同款修复分布：`center_runtime.rs:901-927`、`center_client.rs:629-654`、`site_runtime.rs:1507-1544`（`is_raced_site_bind`/`is_raced_center_bind`/`bind_site`） | `app/src/center_acceptor.rs`；`app/src/center_runtime.rs`；`app/src/center_client.rs`；`app/src/site_runtime.rs` |
| 入网首刷绕端点门 | LOW | ✅ 已实现（2026-08-12，T-B，commit 4897b22）：端点登记（enrollment）后的首次刷新改走 `endpoint_read_gate`——`EndpointEnrollment::enroll` 在 `refresh.execute` 前经进程级端点读门获取 permit（`application/src/endpoint_enrollment.rs:168-179`，失败分类为 `EndpointEnrollmentError::InitialRefreshCoordination` 并新增 `EndpointReadGateError` 导出，`application/src/lib.rs:85-86`），首刷与并发批量刷新同一端点不再重叠（注释 `:158-167`）；`refresh.execute(endpoint_id)`（`:190`）在持门期间执行；web 侧新增 `InitialRefreshCoordination` 错误映射（`web/src/lib.rs:3307`）；对抗测试 `initial_refresh_and_concurrent_batch_refresh_of_the_same_endpoint_never_overlap`（`endpoint_enrollment.rs:643`）钉死不重叠 | `application/src/endpoint_enrollment.rs:158-202`；`application/src/batch_refresh.rs:98-129`；`application/src/lib.rs` |
| 快照 ETag 接线（domain/persistence/operation_executor） | LOW | ✅ 已处置（决策 c，2026-08-12）：写路径语义已完备，快照 ETag 无独立消费价值，接线不实施。① 执行时读取 = 分派时刻可得的最新 ETag——PATCH 家族每次写都在同一次执行内重读目标文档并携带其 ETag（Boot `redfish_gateway.rs:6447-6451`、SecureBoot `:6496-6499`、UpdateService Patch `:6381-6384`、Control `:6220-6224`、Account 三写 `:6797/:6839-6841/:6883-6885`，commit 6128a17），已满足 §13.4「写操作必须使用 ETag」；快照 ETag 恒比执行时读取更旧（陈旧度随刷新节奏无界），不可替代。② 候选 a（快照 ETag 差异诊断）不成立：快照 ETag ≠ 执行时 ETag 是常态（期间发生一次刷新即变化），不是并发修改证据，比较产生噪音而非信号；412 冲突诊断已由 gateway 重读携带当前 ETag（`PreconditionReRead::Read { current_etag }`，`redfish_gateway.rs:12664-12674, 14014-14048` → `infra-redfish/src/application_adapter.rs:363, 435-446` `DispatchVerdict::NotExecuted` → 操作 `Failed`，绝不重派/覆盖），无需新增信息通道（executor 的 Store 泛型也无快照读取角色，`operation_executor.rs:123-127`）。③ 候选 b（恢复路径带旧 ETag）结构性不存在：`recover_operation` 只重读判定、从不派发写（`operation_executor.rs:465-511`），gateway 从不接受执行外部 ETag（唯一例外 `LogEntriesETag` 是操作者经 ClearLog 命令 payload 显式提供的前置条件，`redfish_gateway.rs:6048, 6081`）。快照 ETag 保持只读侧既有角色（诊断展示与中心投影：`endpoint_resources.rs:1084`、`resource_diagnostics.rs:495`、`api/src/lib.rs:660-696, 1898-1952`、`center_sync.rs:1301-1303`）。§13.4「无 ETag 时保存操作前快照」条款由传输层 `If-Match: *` + 执行后重读覆盖（无并发保护，如实标注），与本次决策无关 | `domain/src/resource_snapshot.rs:606-655, 790, 827, 858`；`persistence/src/resource_snapshot_repository.rs:402, 553-554, 605-608`；`infra-redfish/src/redfish_gateway.rs:598-611, 6447-6451, 12664-12674, 14014-14048`；`application/src/operation_executor.rs:123-127, 465-511`；`operation-engine/src/`（无 etag 引用，已核实） |
| sessions 无界增长（软撤销无清理路径） | NOTE | ✅ 已登记（2026-08-13，本行）：`sessions` 表一行一次登录（§16.2），撤销是有意的软写——`revoked_at` 置位、行**永不物理删除**，会话历史保持可审计（repository 与迁移文档同款表述）；repository 无任何删除/剪枝路径（仅 create/find/list/touch/revoke/revoke_sessions_for_principal 六操作）；已撤销/已过期行无限保留——过期行仍可读回，由调用方经 `Session::is_active` 判定（过期是读侧语义，不是存储侧清理）；增长特征：表随登录次数线性增长（每行两枚 32 字节哈希 + 生命周期时间，行小、有主键与 principal 索引），无上限、无保留周期；后续方案：未来引入已撤销/过期会话保留周期（如按 `revoked_at`/`expires_at` 定期剪枝）时处理，与 §八 events 存储增长同款登记 | `persistence/src/session_repository.rs:25-62, 64-71, 159-167, 217-250`；`migration/src/m20260807_000005_product_users.rs:32-36` |
| `Hello.last_acked_sequence` 死字段（契约漂移） | NOTE | ✅ 已处置（决策，2026-08-13）：字段**保留、不接线、不改 wire 语义**——续传实际由 durable outbox 重发 + 逐帧 Ack 完成。① 生产发送方恒写 0（`center_client.rs:256-259` 注释原文：durable outbox 是 runtime slice 的关切，新连接从零开始）；② acceptor 的 `receive_hello` 只把信封 `sequence` 记为对端水位，**从不读该字段**（`center_acceptor.rs:720-745`）；③ 重连续传走 `center_sync::connected_loop` 的初始 outbox flush（未确认条目重发，§15.4）+ `acked_sequence` 捎带与显式 `Ack` 消息逐帧确认（`center_sync.rs:595-668`），Hello 字段在其中无角色；④ proto 注释已改为契约漂移标注（字段为 wire 稳定性保留、恒零、永不复用），本行登记；测试/mock 中的构造值（`center-protocol` sample_hello 42、`mock_center` 0、acceptor/client 测试 0）保持原样，字段编解码不变 | `center-protocol/proto/rutilus/center/v1/center.proto:87-94`；`app/src/center_client.rs:248-261`；`app/src/center_acceptor.rs:720-745`；`application/src/center_sync.rs:595-668` |

> **第一波对抗审查（wave-one，2026-08-13，HEAD = 5cd75ae）**：6 透镜并行攻击，38 条 → 定案
> 31 confirmed + 2 refuted（C5-9/W6-6）+ 1 降级（W6-1）+ 4 半/部分；**27 项确认发现全部修复**
> （9 个提交：8a4d271 / 2a4340b / bcef349 / 73d480d / 6ca207c / 3f312b2 / 31a4232 / d3b966a /
> 5cd75ae，见 `docs/milestone-status.md` 头注与 §7.6）——**含 2 HIGH（S3-1 操作历史 API 回声明文
> BMC 口令、S3-2 首启未认领窗口 GuardedOnly 整面开放）+ 1 HIGH（D4-1 中心控制台审计事件无法
> 持久化），全部已修复并如实登记**；另 3 条已登记（C5-8/C1-5/N2-6，含上行两行）、2 条 refuted
> （C5-9/W6-6）、1 条并入 C5-1（C1-1）。逐项最终状态见下表「第一波块」。
> **第二波对抗审查（wave-two，2026-08-13，进行中）**：6 透镜并行攻击，**61 条发现**（31
> confirmed + 29 reported + F4-6 部分成立，无 refuted），逐项登记见下表「第二波块」；
> 其中 12 条为 D6 文档真实性发现（D6-1..D6-12），由 2026-08-13 文档收口批次处置（本批），
> A5-8 同批处置，其余 **fixes pending**（待后续代码批次，修复前每个提交须五维交叉审计
> APPROVE）。

| 遗留项 | 级别 | 现状 / 后续方案 | 事实来源 |
|---|---|---|---|
| **第一波块（wave-one 对抗修复，2026-08-13，全部处置）** | | | |
| S3-1 操作历史 API 回声明文 BMC 口令 | **HIGH** | ✅ **已修复**（d3b966a）：五个响应投影经 redacting helper 序列化命令输出 `[REDACTED]`（`web/src/lib.rs` 投影层），域 `Serialize` 保持无损——at-rest 信封与中心载荷依赖；测试 `operation_history_routes_never_expose_account_passwords`（`web/tests/operation_path.rs:867`）钉死 | `web/src/lib.rs`；`web/tests/operation_path.rs` |
| S3-2 首启未认领窗口整面 GuardedOnly 开放 | **HIGH** | ✅ **已修复**（d3b966a）：`PendingBootstrap` 策略下每个 `GuardedOnly` 路由无论门是否 armed 一律要求会话（`web/src/auth.rs:151, 158-166` `AuthPolicy::PendingBootstrap`），控制台 401 时重跑认证决策；测试 `auth_gate_starts_open_and_arms_guarded`（`auth.rs:3483`） | `web/src/auth.rs` |
| D4-1 中心控制台审计事件无法持久化 | **HIGH** | ✅ **已修复**（d3b966a）：`m20260813_000001_audit_center_actions` 扩展 action/outcome CHECK 补三个中心动作与两个中心失败码，web 写路径本已产生这些事件；迁移测试 `migration/tests/audit_center_actions.rs` | `migration/src/m20260813_000001`；`migration/tests/audit_center_actions.rs` |
| C5-1 制品分块组装不抗重投（含 C1-1，同根因合并） | MEDIUM | ✅ **已修复**（d3b966a）：chunk 按 index 定位写偏移（`application/src/center/projection.rs:880`），file-before-row / row-before-cursor 双崩溃窗口在重投时愈合 | `application/src/center/projection.rs`；`application/src/artifact_store.rs` |
| C5-2 事件时间线零时钟容差 | MEDIUM | ✅ **已修复**（d3b966a）：60s 时钟容差内接受并把观测时间钳制到事件时间，超出容差分类跳过（不再静默永久丢弃） | `application/src/center_sync.rs` |
| C5-3 事件入库无站点归属校验 | MEDIUM | ✅ **已修复**（d3b966a）：事件批次按 reporting site 校验每个 endpoint 归属（测试 `an_offer_for_another_site_is_dropped` 同款纪律） | `application/src/center_sync.rs:3614` |
| C5-4 ArtifactChunk 消费不校验制品归属站点 | LOW | ✅ **已修复**（d3b966a）：chunk 消费前 `find_artifact_site` 校验 | `application/src/center/projection.rs` |
| C5-5 操作回执不校验回复站点 | LOW | ✅ **已修复**（d3b966a）：回执只从 offer_site 计分，外站回复拒收并记录（测试 `a_duplicate_of_a_rejected_offer_stays_rejected` `center_sync.rs:3638`） | `application/src/center_sync.rs` |
| C5-6 dispatch 重试双 offer 双执行 | LOW | ✅ **已修复**（d3b966a）：同键重试幂等返回既有操作（`a_duplicate_of_a_completed_offer_returns_the_recorded_outcome` `center_sync.rs:3688`），TTL 内复活沿用同一 id | `application/src/center_sync.rs` |
| C5-7 Queued offer 无 TTL | LOW | ✅ **已修复**（d3b966a）：过期 queued offer 终结不重发（测试 `an_expired_offer_rejects_with_expired` `center_sync.rs:3471`、`an_offer_with_an_unparseable_expiry_is_refused_as_expired` `:3495`） | `application/src/center_sync.rs` |
| C5-8 `Hello.last_acked_sequence` 死字段 | NOTE | ✅ 已登记（6ca207c，见上行本行） | 本行 |
| C5-9 重复回执产生重复 inbox 行 | NOTE | **refuted**（验证：inbox 按 operation_id 查重 `DuplicateResolved`） | `persistence/src/center_inbox_repository.rs` |
| C5-10 Hello 声明身份不校验 | NOTE | ✅ **已修复**（5cd75ae）：admission 把 Hello 声明 instance id 与证书绑定身份比对，不一致答 `identity-mismatch`（词汇新增、无 wire 变更；`center_acceptor.rs:262, 348-349`） | `app/src/center_acceptor.rs` |
| C1-2 恢复判定覆盖并发推进中的操作 | LOW | ✅ **已修复**（d3b966a）：`apply_transition_if_current` CAS 三臂（`operation_engine.rs:665`），陈旧读不再覆盖已推进操作 | `operation-engine/src/operation_engine.rs` |
| C1-3 expires_at_unix 不可解析 fail-open | NOTE | ✅ **已修复**（d3b966a）：不可解析按过期拒绝（fail-closed，测试 `an_offer_with_an_unparseable_expiry_is_refused_as_expired`） | `application/src/center_sync.rs:3495` |
| C1-4 Unknown/Cancelled 折叠成 Failed | NOTE | ✅ **已修复**（d3b966a）：summary 状态码区分 Unknown/Cancelled 与 Failed，wire 不变 | `application/src/command_executor.rs` |
| C1-5 端点读门注册表只增不减 | NOTE | ✅ 已登记（6ca207c）：注释如实化——site 的 managed-endpoint 路径当前无移除，条目存活至进程生命周期、以全量舰队规模为界（`batch_refresh.rs:98-129`） | `application/src/batch_refresh.rs` |
| N2-1 Argon2id 在 async worker 同步执行 | MEDIUM | ✅ **已修复**（d3b966a）：验证与派生走 blocking 池（`auth.rs` 登录/认领/改密三入口，测试 `change_password_runs_verification_and_derivation_off_the_async_worker` `auth.rs:3983`、`bootstrap_runs_password_derivation_off_the_async_worker` `:4056`） | `web/src/auth.rs` |
| N2-2 优雅关停对在飞请求无时限 | MEDIUM | ✅ **已修复**（5cd75ae）：TimeoutLayer 限每个 console handler + drain 与 10s `GRACEFUL_DRAIN_TIMEOUT` 赛跑，慢/挂客户端不能拖住 stop；SCM wait-hint 注释如实化 | `app/src/standalone_runtime.rs:1596`（`serve_with_bounded_drain`）；`app/src/site_runtime.rs` |
| N2-3 调度器单 tick 队首阻塞 | MEDIUM | ✅ **已修复**（d3b966a）：scheduler 在每端点写门后并发驱动操作（`buffer_unordered`），task-monitor 通道并行，单 BMC 挂起不再卡整条流水线 | `application/src/scheduler.rs`；`application/src/task_monitor.rs` |
| N2-4 prune_stale 死代码 / 僵尸 site | MEDIUM | ✅ **已修复**（5cd75ae）：`DisconnectOnDrop` guard 在连接任务结束（含 panic/abort）时把 site 移出会话注册表；从未接线的 prune_stale 兜底作为死代码移除 | `application/src/center/session.rs`；`app/src/center_runtime.rs` |
| N2-5 遥测采样时间戳无单调校验 | LOW | ✅ **已修复**（6ca207c）：回拨 instant 以 `ClockRollback` 分类错误拒绝（不钳制——不伪造从未存在的时间；等值 instant 同 sweep 接受；测试 `a_clock_rollback_is_refused_and_history_stays_monotonic` `telemetry_sampler.rs:1034`） | `application/src/telemetry_sampler.rs:602, 708` |
| N2-6 sessions 无界增长 | NOTE | ✅ 已登记（6ca207c，见上行本行） | 本行 |
| S3-3 登录限速 check-then-act 竞态 | LOW | ✅ **已修复**（d3b966a）：原子 reserve/refund（`auth.rs:1012-1094`），并发放大竞态关闭（测试 `rate_limiter_prune_reclaims_compensated_empty_buckets` 更名对应） | `web/src/auth.rs` |
| S3-4 新建用户无口令配置路径 | LOW | ✅ **已修复**（5cd75ae）：`POST /api/v1/admin/users/{id}/password` 两端面可用（`auth.rs:2363`），B4 分支不再使无口令账户永久不可登录；UI 表单保持 later milestone（本表 §二 S3-4 行） | `web/src/auth.rs:2363` |
| S3-5 cookie_value 前缀早退 | NOTE | ✅ **已修复**（d3b966a）：畸形前缀对跳过继续扫描其余 cookie | `web/src/auth.rs` |
| D4-2 恢复兼容性检查忽略 WAL | MEDIUM | ✅ **已修复**（d3b966a）：暂存目录先回放 WAL 再读 applied migrations，`NewerSchema` 门看到真实状态（测试 `compatibility_replays_the_wal_before_reading_the_applied_migrations` `backup_snapshot.rs:653`） | `persistence/src/backup_snapshot.rs` |
| D4-3 中心投影 upsert 无 Generation 守卫 | LOW | ✅ **已修复**（d3b966a）：`StaleGeneration` 拒绝旧代 | `persistence/src/center_projection_repository.rs` |
| D4-4 迁移前备份目录从不清理 | LOW | ✅ **已修复**（d3b966a）：保留最近 3 份（`migration_backup.rs`，`PRE_MIGRATION_BACKUP_RETENTION`） | `persistence/src/migration_backup.rs` |
| D4-5 endpoints.health/refresh_generation 无 CHECK | LOW | ✅ **已修复**（d3b966a）：`m20260813_000002` 重建八表 CHECK 家族（`migration/tests/endpoint_health_checks.rs`） | `migration/src/m20260813_000002` |
| D4-6 迁移注册顺序错位 | NOTE | ✅ **已修复**（d3b966a）：按文件名序重排 | `migration/src/lib.rs` |
| W6-1 测试型门禁无 ran-断言（降级） | MEDIUM（降级） | ✅ **已修复**（bcef349）：`scripts/assert-tests-ran.sh` floor 断言——Secret leak gate（floor 8）与 Migration test（floor 38）；Release baseline / Capability ledger / workspace Test 登记为后续候选（ci.yml:364-371 注释） | `scripts/assert-tests-ran.sh`；`ci.yml:364-371` |
| W6-2 PR 可改工作流删门禁 | MEDIUM | ✅ **已修复**（bcef349）：`.github/CODEOWNERS` 要求 `.github/` 变更显式评审；branch protection 如实登记为仓库外防线 | `.github/CODEOWNERS` |
| W6-3 bare_sql_gate 首词盲区（CTAS/TRIGGER 内嵌 DML） | MEDIUM | ✅ **已修复**（73d480d）：`ddl_embedded_dml` 词扫描（首词后继续扫），`AS /* copy */ SELECT` 词对间距、引用字面量误报边界如实登记；门禁现 626 行 | `migration/tests/bare_sql_gate.rs` |
| W6-4 secret_leak_gate 间接赋值盲区 | MEDIUM | ✅ **已修复**（73d480d）：`wrapper_or_indirect`（String::from/format!/concat!/to_string 包装 + 两步间接，作用域感知传递解析，赋值失效含入），wrapper 漏报形状如实登记 | `security/tests/secret_leak_gate.rs:836` |
| W6-5 路由授权表与路由器无机械同步 | MEDIUM | ✅ **已修复**（5cd75ae）：`EDGE_ROUTES`/`CENTER_ROUTES` 单一注册源折叠进两路由器 + 穷举 kind 分派，双向门禁测试点名 ROUTE_TABLE 每条注册路由与每个表条目（`auth.rs:2684` `route_table_pins_the_authorization_matrix`） | `web/src/auth.rs:586, 890`；`web/src/lib.rs:717` |
| W6-6 down_order_gate 跨文件 down 序盲区 | LOW | **refuted**（验证：引错文件 + 门禁本就跨文件聚合 FK 边） | `migration/tests/down_order_gate.rs` |
| W6-7 门禁扫描面（build.rs 逃逸 / 非递归） | LOW | ✅ **已修复**（73d480d + 2a4340b）：两门禁递归扫描 + secret gate 覆盖 build.rs | `migration/tests/bare_sql_gate.rs`；`security/tests/secret_leak_gate.rs:1344`（`crate_scan_includes_build_scripts`） |
| W6-8 ci.yml 缓存注释过时 | NOTE | ✅ **已修复**（bcef349）：按事实改写（action 无缓存步骤、PR 缓存 ref 作用域） | `.github/workflows/ci.yml:189-207` |
| **第二波块（wave-two 对抗发现，2026-08-13，61 条）** | | | |
| P1-1 Overview/详情页 O(N²) | P1 | **confirmed**（验证者：O(N²) 成立，系数实为 2N²+7N+1），fixes pending | `application/src/overview.rs:386-423`；`application/src/endpoint_resources.rs:960-989`；`persistence/src/endpoint_repository.rs:138-160` |
| P1-2 调度器每 2s 全表扫描 + 逐行 AEAD 解密 | P1 | **confirmed**（验证者：每 tick 无条件调、索引被绕过、4 态索引查询替代可行），fixes pending | `operation-engine/src/operation_engine.rs:359-369`；`application/src/scheduler.rs:418-421`；`persistence/src/operation_repository.rs:540-569, 734-795` |
| P1-3 dispatch 幂等扫描全表 + 全 outbox 逐行解密 | P1 | **confirmed（一处修正）**（outbox 扫描有短路；acked 行永不清理），fixes pending | `application/src/center/dispatch.rs:346, 386-466, 535-549`；`persistence/src/center_outbox_repository.rs:242-260, 425-433` |
| P2-4 事件批次逐条处理（每事件 1 读 + 1 独立写门事务） | P2 | **confirmed**，fixes pending | `application/src/center/projection.rs:697-758, 728-738`；`persistence/src/event_repository.rs:42, 80` |
| P2-5 投影 upsert 无条件删插地址/信任行 | P2 | **confirmed**（与幂等重投 2× 实测相符），fixes pending | `persistence/src/center_projection_repository.rs:131-183` |
| P2-6 中心侧 artifact finalize 整文件读入内存哈希 | P2 | **confirmed**（站点侧 64KiB 流式非对称），fixes pending | `application/src/center/projection.rs:970-981` |
| P2-7 每 chunk 3 读 + 2 写门事务 + 每次 open/seek | P2 | **confirmed**，fixes pending | `application/src/center/projection.rs:803-959, 1259-1271` |
| P3-8 站点投影汇总全行物化求 count/max | P3 | reported，待验证/修复 | `persistence/src/center_projection_repository.rs:525-547` |
| P3-9 每回执 2-3 个独立写门事务 | P3 | reported，待验证/修复 | `application/src/center/dispatch.rs:666-821` |
| P3-10 重连全量重放 + outbox acked 行永不清理 | P3 | reported，待验证/修复 | `application/src/center_sync.rs:1136-1193, 620` |
| P3-11 读/写门注册表无回收 | P3 | reported；**已文档化**（既有登记：C1-5 行，端点删除路径落地时需接线），fixes pending | `application/src/batch_refresh.rs:98-124`；`application/src/scheduler.rs:103-123` |
| P4-12 Argon2id blocking 池无并发上限 | P4 | reported，待验证/修复 | `app/src/standalone_runtime.rs:605-653`；`web/src/auth.rs:403-467` |
| E3-1 绑定轮询瞬态错误被当撤销（站点永久掉线） | HIGH | **confirmed**（验证者：Err 可瞬态、无 supervisor 复活、控制台恒显示 Bound），fixes pending | `app/src/site_runtime.rs:1406-1414, 1370-1379` |
| E3-2 identity-mismatch 无终态处理 | MED-HIGH | **confirmed**（与 not-bound 自愈对比收敛成立），fixes pending | `app/src/center_client.rs:509-517`；`application/src/center_sync.rs:537-571` |
| E3-3 持续时钟回拨无界 error 风暴 | MEDIUM | **confirmed**（回拨只返回 Err 不重锚），fixes pending | `application/src/telemetry_sampler.rs:585-606, 337-339, 620-633` |
| E3-4 CapabilityUnsupported 审计/wire/单操作 UI 三面不可见 | MEDIUM | **confirmed**，fixes pending | `application/src/operation_executor.rs:288-293, 777-795`；`web/src/lib.rs:2639-2653`；`application/src/center_sync.rs:1169-1176` |
| E3-5 终态操作被记 error「could not be driven」 | MEDIUM | **confirmed**（终态永不重驱却持续记 error，对 Unknown 还误导重派），fixes pending | `application/src/scheduler.rs:518-522` |
| E3-6 事件不可解码仍推进游标（站点/中心静默分叉） | MED-LOW | **confirmed**（error+continue 后无条件 advance_cursor，与 delta 流 warn 不一致），fixes pending | `application/src/center/projection.rs:710-757` |
| E3-7 HelloIdentityMismatch 未净化写日志 | MED-LOW | reported，待验证/修复 | `app/src/center_runtime.rs:780-784`；`application/src/center/session.rs:109-113` |
| E3-8 损坏 outbox 行每次重连永久 error | LOW-MED | reported，待验证/修复 | `application/src/center_sync.rs:705-725`；`application/src/center/session.rs:727-743` |
| E3-9 list_center_operations 静默丢弃不可解码信封 | LOW | reported，待验证/修复 | `app/src/center_runtime.rs:522-531` |
| E3-10 CSV 导入错误丢弃底层原因 | LOW | reported，待验证/修复 | `application/src/endpoint_csv.rs:132, 146-148, 204-206` |
| D6-1 第一波 27 项修复文档零登记 | HIGH | ✅ **已修复**（2026-08-13 D6 文档收口批次，本批）：本表第一波块 + `milestone-status.md` 头注/§7.6 + `security-review.md` §三/§四 | 本批各文档 |
| D6-2 测试计数全面过时（1731 vs 实测 1800） | HIGH | ✅ **已修复**（2026-08-13 D6 文档收口批次）：`cargo test --workspace -- --list` 实测 1800，per-crate 全量登记（`milestone-status.md` 头注、`release-readiness.md` 头注/§五） | 本批各文档 |
| D6-3 web/src/auth.rs 行号引用漂移（+114..+390） | HIGH | ✅ **已修复**（2026-08-13 D6 文档收口批次）：全文档 auth.rs 引用按当前 master 重锚（security-review §二/§三/§四、known-limitations §七/§九、release-readiness、milestone-status） | 本批各文档 |
| D6-4 七文档 ci.yml 引用漂移（+7..+93） | HIGH | ✅ **已修复**（2026-08-13 D6 文档收口批次）：七文档 ci.yml 引用全量重锚；operations-manual「cargo deny 0.20.2」按 ci.yml 事实修正 | 本批各文档 |
| D6-5 迁移/备份计数失同步（23→25、20→23、24/23→26/25） | HIGH | ✅ **已修复**（2026-08-13 D6 文档收口批次）：25 迁移文件、23 迁移测试文件、备份 pin 26/25（`backup_snapshot.rs:646-647`）三文档同步 | 本批各文档 |
| D6-6 web/src/lib.rs 行号引用漂移（+223..+657） | MEDIUM | ✅ **已修复**（2026-08-13 D6 文档收口批次）：全文档 web lib.rs 引用重锚 | 本批各文档 |
| D6-7 其余 wave 触达文件行号漂移 | MEDIUM | ✅ **已修复**（2026-08-13 D6 文档收口批次）：backup.rs/center_sync.rs/operation_engine.rs/negotiation.rs/batch_refresh.rs/web tests 引用重锚 | 本批各文档 |
| D6-8 milestone-status 自身行号被跨文档引用漂移（+2） | MEDIUM | ✅ **已修复**（2026-08-13 D6 文档收口批次）：release-readiness/security-review 对 milestone-status 的引用按新行号重锚 | 本批各文档 |
| D6-9 release-readiness「本版」HEAD 自述落后（6f8b698 vs 5cd75ae） | MEDIUM | ✅ **已修复**（2026-08-13 D6 文档收口批次）：头注 bump 至 5cd75ae，§五/§六 历史标记注明基准 | `release-readiness.md` |
| D6-10 user-manual §5.1 ETag 段与 T-C 决策矛盾 | MEDIUM | ✅ **已修复**（2026-08-13 D6 文档收口批次）：改为「已处置（决策 c，不实施）」；ui 行号 +2 重锚 | `user-manual.md` §5.1 |
| D6-11 support-matrix §4.4 Mock profile 清单过时 | LOW | ✅ **已修复**（2026-08-13 D6 文档收口批次）：更新为 11 个变体 | `support-matrix.md` §4.4 |
| D6-12 门禁计数细项过时（security 8→9、down_order_gate 8→11、migration 38→48） | LOW | ✅ **已修复**（2026-08-13 D6 文档收口批次）：release-readiness §五 / milestone-status 头注按实测更新；`assert-tests-ran.sh:19` 注释的 floor 8/38 为下界 pin 保持不动 | 本批各文档 |
| F4-1 CI 第三方 action 移动 tag 无 SHA 钉版、无 Dependabot、release-artifacts 暴露签名 secrets | MEDIUM | **confirmed**（验证者：六 action 全移动 tag、job 级 env 暴露三组签名 secrets），fixes pending（修复批次进行中：`.github/dependabot.yml` 已入工作树） | `.github/workflows/ci.yml:90, 95, 102, 119, 210, 690, 700` |
| F4-2 quick-xml 0194 忽略理由答非所问 | LOW-MED | **confirmed**（验证者：0194 含 NsReader 路径、csdl-compiler 的 de::from_str 内部构造 NsReader；真正缓解是「输入可信」），fixes pending | `deny.toml:32-33` |
| F4-3 bans skip 表只覆盖可达重复版本 | LOW-MED | **confirmed**（不可达多版本零登记、纯手工维护），fixes pending | `deny.toml:65-85` |
| F4-4 tokio-util 0.7.19 两处声明绕过 workspace 单一来源 | LOW | **confirmed**，fixes pending | `app/Cargo.toml:38`；`infra-redfish/Cargo.toml:35` |
| F4-5 SBOM 步骤无 --locked 且含 dev-deps/wasm 图成员 | LOW | **confirmed**，fixes pending | `ci.yml:671` |
| F4-6 wasm-bindgen-cli 每次 CI 现装 | LOW | **部分成立**（验证者：属实但 rust-cache 覆盖 target/rutilus-tools，编译成本已缓解），fixes pending | `ci.yml:278` |
| F4-7 公告忽略双列表无机制同步 | LOW | **confirmed**（双列表仅靠注释锁步、deny 注释已脱节），fixes pending | `deny.toml:21-24`；`ci.yml:227-232` |
| A5-1 SetPasswordRequest 文档声称无强度策略、wire 实际强制 12 字符 | LOW-MED | **confirmed**（handler 强制 12 字符、known-limitations 同证、AdminSetPasswordRequest 文档正确反衬），fixes pending | `api/src/lib.rs:4893-4896` vs `web/src/auth.rs:1897-1902` |
| A5-2 proto 只列 3 个拒绝码、实际出货 5 个 | LOW | reported，待验证/修复 | `center-protocol/proto/rutilus/center/v1/center.proto:103-106` |
| A5-3 UI 声称渲染 wire 字段名、实际标签非 wire 名 | LOW | reported，待验证/修复 | `ui/src/lib.rs:8110-8116` vs `domain/src/redfish_command.rs:1786-1790` |
| A5-4 兄弟 detail 路由同类错误返回不同 wire 形态 | LOW | reported，待验证/修复 | `web/src/lib.rs:2308-2310, 2363-2364` |
| A5-5 NVIDIA debug token（token_data）明文过响应 wire | LOW | reported；边界已文档承认，属范围记录 | `api/src/lib.rs:3625-3687`；`domain/src/redfish_command.rs:3810, 2865-2869` |
| A5-6 product_version 声称「recorded by the peer」实际中心侧从不读取 | NOTE | reported，待验证/修复 | `center-protocol/src/negotiation.rs:6-7`；`center.proto:63-64` |
| A5-7 站点侧 identity-mismatch 与未知码不可区分 | NOTE | reported，待验证/修复 | `app/src/center_client.rs:509-517`；`center-protocol/src/center_transport.rs:24-29` |
| A5-8 S3-4 行声称「CLI/API 侧设置口令」、CLI 不存在该命令 | NOTE | ✅ **已修复**（2026-08-13 D6 文档收口批次）：本表 §二 S3-4 行改为「**API** 侧」 | 本表 §二 |
| T1-1 W6-5 路由门可被通配符遮蔽形态骗过 | HIGH | **confirmed**（验证者：pattern_covers 无段边界、首个命中即返回、ANY 放行 Viewer、通配实为 14 条、pin 仅一个 ANY 路径），fixes pending | `web/src/auth.rs:862, 2973-3003` |
| T1-2 内嵌 DML 检查可被 SQL 注释绕过 | MED-HIGH | **confirmed**（`AS /* copy */ SELECT` 词对不再相邻、CTAS 拷贝漏网且未登记），fixes pending | `migration/tests/bare_sql_gate.rs:266-299` |
| T1-3 down 体外 helper 中 builder 式 drop 不可见 | MED | **confirmed**（现树无违例属潜伏、未来漂移洞），fixes pending | `migration/tests/down_order_gate.rs:832-855, 913-927` |
| T1-4 [R2] 跨字面量拆分 PEM 私钥逃逸 | MED | **confirmed**（wrapper_literal 只取首段、跨段即漏、未登记），fixes pending | `security/tests/secret_leak_gate.rs:886-890` |
| T1-5 JSON 诊断层无任何可证伪测试 | MED-HIGH | **confirmed**（三处测试均不经 init_tracing、JSON 形状测试自建 subscriber），fixes pending | `app/tests/log_format.rs:36-38`；`app/src/main.rs:255` |
| T1-6 resource 投影 upsert 结果全丢弃且无代际检查 | MED | **confirmed**（upsert_resource_projection 无代际比较、ON CONFLICT 无条件覆盖；与 endpoint 侧不对称），fixes pending | `persistence/tests/stress_capacity.rs:1008-1052`；`persistence/src/center_projection_repository.rs:262-347` |
| T1-7 dummy_credential 测试自证自足 | MED | **confirmed**（断言恒等于构造源、定长数组编译期恒真），fixes pending | `web/src/auth.rs:3442-3454` |
| T1-8 覆盖声称与实跑不符（1731 vs 1800） | MED | reported，待验证/修复（D6-2 已同步文档计数，本行指文档其余过时表述） | `release-readiness.md:79-81`；`ci.yml:348-359` |
| T1-9 新测试重蹈硬编码步数陷阱 | LOW-MED | **confirmed**（全 migration/tests 唯一硬编码 down(Some(1))），fixes pending | `migration/tests/endpoint_health_checks.rs:182` |
| T1-10 stop_watch 测试只能挂死不能失败 | LOW-MED | **confirmed**（两次裸 await 零断言无 timeout），fixes pending | `application/src/scheduler.rs:1236-1245` |
| T1-11 capability_path 只序列化单一状态值 | LOW | **confirmed**（domain 七种 CapabilityState 只测两种），fixes pending | `web/tests/capability_path.rs:858` |
| T1-12 错误消息断言仅为存在性 | LOW | **confirmed**（空串即过、文案零咬合），fixes pending | `web/tests/event_path.rs:727`；`web/tests/telemetry_path.rs:793` |

> 以上偏差均为当前 master 的真实状态；对应设计条款见仓库根目录
> `redfish-management-product-final-design.md`。
