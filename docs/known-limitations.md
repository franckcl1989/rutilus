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
| Telemetry | `CommandFamilyView::ALL` 刻意不含 Telemetry；表单选择器返回 `OperationFormError::FamilyRequired`；界面提示 "The telemetry write form is a later milestone."；已持久化的遥测命令通过 `wire_command_summary` 在卡片中渲染 | `ui/src/lib.rs` 第 10821-10830、6289-6291、6438 行（`CommandFamilyView::ALL` 9 家族 `:10821-10830`、表单选择器 `FamilyRequired` `:6289-6291`、Telemetry 表单拒绝 `:6438`、later-milestone 提示文案串 `i18n.rs:1654` `hint_telemetry_later`） |
| Log（清空日志 `log.clear`） | 无专用表单（`CommandFamilyView` 中不存在 Log 变体），表单选择器拒绝 | `ui/src/lib.rs` `CommandFamilyView` |
| Control（控制更新 `control.update`） | 同上，无专用表单 | 同上 |
| 管理员设置用户口令（S3-4） | **API 已提供**（`POST /api/v1/admin/users/{principal_id}/password`，管理员可给任意用户——含无口令新建用户——设置/重置口令，`web/src/auth.rs:2738` `set_user_password`，DTO `api/src/lib.rs::AdminSetPasswordRequest`，ROUTE_TABLE 的 `POST /api/v1/admin/users*` 条目 Admin 守卫 + CSRF，审计按 change-password 记录；wave-one S3-4 修复落地，commit 5cd75ae）；**UI 表单为 later milestone**——管理员用户视图只提供创建（`post_create_user` 仅 name+role，`ui/src/lib.rs:9798`）、启停、改角色三个动作，无口令字段（用户视图区 `:10096`）；新建用户需由 **API** 侧设置口令后才能登录（CLI 不存在该命令） | `web/src/auth.rs:2738` `set_user_password`；`api/src/lib.rs` `AdminSetPasswordRequest`；`ui/src/lib.rs:9798, 10096` |

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
| 产品版本号（已统一）+ Git Commit 嵌入 | workspace 版本 = `0.9.0`（生产候选，`rutilus version` 输出），单一版本来源 = 根 `Cargo.toml` `[workspace.package] version`（`Cargo.toml:14`）；`rutilus version` 输出**三行**（`app/src/main.rs:733-737`）：产品版本 / `nv-redfish` 开发基线 / `git commit`——CI 构建经 job 级 `RUTILUS_GIT_COMMIT` 注入（`ci.yml:84`，值为 `github.sha`），`GIT_COMMIT` 常量嵌入（`app/src/main.rs:38-40`），本地构建（无该变量）降级为 `dev`（不 spawn git 子进程）；版本/日志格式测试断言由 `env!("CARGO_PKG_VERSION")`、`NV_REDFISH_DEVELOPMENT_BASELINE` 与编译期 `RUTILUS_GIT_COMMIT` 派生（`app/tests/version.rs:27-36`、`app/tests/log_format.rs:23-28`），升级只改一处 | 根 `Cargo.toml:14`；`ci.yml:84`；`app/src/main.rs:38-40, 733-737`；`app/tests/version.rs:8-11, 27-36`；`app/tests/log_format.rs:7-10, 23-28` |
| macOS 非绝对静态链接 | macOS 上只承诺单文件、无随包动态库、仅系统框架（不做"绝对零动态依赖"承诺，§5.3） | 设计文档 §5.3 |
| UI 本地化（✅ 完整：827 键 En/Zh 双语 + 运行时语言选择器 + URL fragment 持久化） | ✅ 完整（commit d3f7769 + 0f91c17 + c4dd335）：`ui/src/i18n.rs` 目录扩至 **827 键 En/Zh 双语**（`strings_catalog!` 宏 `i18n.rs:43-160`、目录体 `i18n.rs:163-1858`）、`Lang::{En, Zh}` 运行时语言选择（`thread_local!` `i18n.rs:1938-1942`、`L()` `i18n.rs:1968-1973`、`format_catalog` `i18n.rs:1984-2006`）；lib.rs `LanguageSelector` 组件（`lib.rs:11725`）——**URL fragment 持久化方案**：语言选择写入 `#lang=` fragment，因为当前 web-sys feature 面只暴露 `Window`/`Location`——fragment 是唯一可用的浏览器存储（`i18n.rs:1901-1905` `LANG_FRAGMENT_PREFIX`）；**迭代七（T-H，commit c4dd335）已把持久化拆为纯函数 + 薄封装**：`stored_lang_code_from`/`lang_fragment_value`（`i18n.rs:1915-1936`，host 可测、不触 web-sys）＋`stored_lang_code`/`persist_language`/`apply_language`（`ui/src/lib.rs` wasm `browser` 模块 `lib.rs:11692-11724`，仅读写 `window.location`，运行时行为不变）；启动时经 fragment 恢复（`start()` `lib.rs:11746`），切换后 reload 全量重挂载；**localStorage 后续触点**：localStorage 持久化需扩展 web-sys feature（`Storage` 面当前未启用），与更多语言同为后续触点；深度翻译已全部完成（facts/健康词汇/`OEM_UNSUPPORTED_NOTICE` 均入目录，`i18n.rs:825-829, 867`）；i18n 15 测试（既有 11 个 `i18n.rs:2009-2185` + fragment 纯函数 4 个 `i18n.rs:2192-2259`）、ui 144 测试全过、clippy/fmt 干净；J2 审计 3 处 zh 译法微修已合入（`type_nvidia_profile_file`/`fact_power_load_percent`/`fact_metric_values`，`i18n.rs:444, 597, 733`）。审计（I1）MINOR 保持：`i18n.rs:1` 头注释 §5.1 引用不可核验（设计文档无「本地化/i18n」条目）、`L.action_delete`/`L.field_role` 语义复用；「`aria-label="Loading"` 未抽取」已在 H5 解决（aria-label 全部走目录键，如 `lib.rs:11962` `L().aria_loading`）；后续项登记见 `milestone-status.md` §7.2-A「UI 本地化」行 | `ui/src/i18n.rs`；`ui/src/lib.rs:11692-11746`；`web/assets/` |
| 发布管道（签名 + SBOM + 校验清单）代码侧就绪 | 🟡 代码侧完成（commit 34503ea + d77d54e）：`scripts/` 5 脚本（sign-windows.ps1 / sign-macos.sh / sign-linux.sh / checksums.sh / checksums.ps1）+ ci.yml `release-artifacts` job（`ci.yml:609-911`：`v*` tag / `workflow_dispatch` 触发、`needs: ci` 门禁先行、签名步骤仅在 secret 配置时执行、base64 物化、Windows thumbprint-only 模式、cargo-cyclonedx@0.5.9 钉版 SBOM、SHA-256 清单、artifact 上传）；证书未到位，签名在首跑前保持 "signing skipped: certificate not configured"；**首跑确认点 6 项**（证书到位后核验）：① musl-tools 安装（`ci.yml:692`）② cargo-cyclonedx@0.5.9 钉版（`ci.yml:867-874`）③ base64 物化（`ci.yml:748-757, 773-781, 805-808`）④ env 的 `&&`/`||` 表达式（`ci.yml:765, 795`〔Linux 同款〕）⑤ thumbprint-only 模式（`ci.yml:759-765`）⑥ 上传权限（`ci.yml:901-911`） | `.github/workflows/ci.yml`；`scripts/`；`release-readiness.md` 条件 17 |
| HTTP 成功不等于业务成功 | 200/201/202/204 不直接等于业务成功，写操作后必须重新读取验证；响应丢失时非幂等操作标记 Unknown 而不盲重试（§13.5） | `operation-engine`；设计文档 §13 |
| 登录限速窗口固定 | 每用户名 5 次 / 每地址 20 次失败、15 分钟窗口，为代码内常量；桶键内存有界（`BUCKET_PRUNE_THRESHOLD` 4096 周期剪枝，T-D commit e7aef53，见 §九该行） | `web/src/auth.rs` |
| 事件流重连预算有限 | 超出预算的长期不可达端点以 Failed 呈现而非无限重试（有意设计，见上） | `app/src/event_listener.rs` |
| Center 角色站点作用域 | 中心角色可限定到某些 Site，但用户与会话管理仅 Administrator（有意设计） | `web/src/auth.rs` |
| 审计只追加 | 审计记录不通过正常 ORM Repository 更新或删除（§16.3） | `domain/src/audit.rs` |
| 密码策略：至少 12 字符（API 边界执行） | 产品密码策略 = 至少 12 个 Unicode 标量字符（`MIN_PASSWORD_CHARS`，`password_satisfies_policy`，与 UI 表单同一检查）；**执行边界在 API**（`web/src/auth.rs:1711`）：登录入口在限速/查找/验证之前拒绝，不占限速预算、不写审计（策略违规不是登录尝试；响应本身即记录）；控制台表单的 12 字符下限是客户端便利，不是控制面（深度审查批次 B1，commit 8147bc9） | `web/src/auth.rs:113, 1680, 1711, 1957, 2170` |
| 429 限速拒绝不写审计 | 登录限速拒绝（429）**不写审计事件**：请求在验证前就被拒绝，从未构成一次登录尝试，429 本身即记录；写 started+failed 对会令审计表随拒绝洪泛无界增长，且每次审计追加都串行在 persistence 写门（`Semaphore(1)`）上，429 洪泛会饿死合法 session/telemetry/event/operation 写入（深度审查批次 B2，commit 8147bc9；§16.3 审计的是"已运行的登录结果"，被拒请求从未运行；wave-five V5C-2 起 bootstrap 认领 429 同款不写审计） | `web/src/auth.rs:1733-1740` |
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
| §12.4 诊断中的解码错误路径 / ExtendedInfo 展示 | ✅ 已实现（E1，commit ce2b8b3）：记录层——`ResourceExtendedInfo`/`ResourceDecodeFailure`（`application/src/resource_diagnostics.rs:36, 249`）、api 契约 9 字段（`api/src/lib.rs:1903-1920`）、web 投影（`web/src/lib.rs:4464` `project_resource_diagnostics`）、ui 只读区块（`ui/src/lib.rs:15502`）、端到端测试（`web/tests/diagnostics_path.rs` 7 个测试，含 `:1008` `refresh_capture_flows_into_the_diagnostics_response`）；**生产捕获点已实现**：刷新解码失败由 gateway 捕获（`DecodeFailureObservation`，`infra-redfish/src/redfish_gateway.rs:8811`；捕获函数 `capture_fetch_failure`/`capture_projection_failure`/`capture_segment_decode_failure` `:8995/:9022/:9068`），经刷新结果 `outcome.decode_failures()`（`:8922`）流入同代事务提交（`persistence/src/resource_snapshot_repository.rs:81-147`），生产链路直连（`application/src/endpoint_refresh.rs:350-355`），持久化于新表 `resource_decode_failures`（entity `entity/src/lib.rs:28`、`entity/src/resource_decode_failure.rs:13`；迁移 `migration/src/m20260812_000001`）——真实解码失败会出现在诊断视图中。**如实注记**：① 捕获时 `odata_type` 为 `None`（`capture_fetch_failure` 恒传 None，`redfish_gateway.rs:9006-9013`，解码失败记录不带 OData 类型）；② 表约束经 E4 修复（`migration/src/m20260812_000002` 重建 `resources`/`resource_decode_failures` 两表，`ck_*_feature` 允许域 = 领域枚举全部 47 码，此前 resources 37 / resource_decode_failures 36 且互相不一致；`down` 对称恢复 37/36；防回归机械测试 `migration/tests/resource_feature_lists.rs`）；③ 真实设备上的解码失败形态仍需实测（B 类演练项）；④ 贯通测试已补齐（T-G 8482d85，见 §九该行） |

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
| 限流器桶键淘汰 | LOW | ✅ **已实现**（2026-08-12，T-D，commit e7aef53）：周期剪枝——`BucketMap` 随新键插入计数，达 `BUCKET_PRUNE_THRESHOLD`（4096，`web/src/auth.rs:147`）触发全表清扫，回收全部过期桶（dormant 键随窗口滑动清理，含仅 `allows` 创建的空桶；`prune_if_due` `:1269-1284`、`prune_expired` `:1285-1291`，`BucketMap` `:1065-1160`）；清扫与访问路径共用同一过期判定，限速判定逐字节不变；内存有界 = 一个窗口内活跃桶工作集 + 4096，不再随时间线性累积。测试：`rate_limiter_prunes_expired_buckets_to_a_bounded_size`（`:4135`）/`rate_limiter_prune_spares_active_buckets`（`:4203`）/`rate_limiter_prune_reclaims_compensated_empty_buckets`（`:4247`，wave-one S3-3 原子 reserve/refund 后由 `..._created_by_allows_only` 更名）/`prune_expired_reclaims_only_buckets_whose_entries_left_the_window`（`:4282`），web 172 测试全过 | `web/src/auth.rs`（§16.2 限速器区块）；`docs/security-review.md` §三 N3 |
| i18n fragment 纯函数测试 | NOTE | ✅ 已落实（2026-08-12，T-H，commit c4dd335）：`#lang=` 语言持久化拆分为纯函数 `stored_lang_code_from`/`lang_fragment_value`（`ui/src/i18n.rs:1915-1936`，host 可测、不触 web-sys）＋薄封装 `stored_lang_code`/`persist_language`/`apply_language`（`ui/src/lib.rs` wasm `browser` 模块 `:11607-11635`，仅读写 `window.location`，运行时行为不变）；纯函数单元测试 4 项（`fragment_reading_extracts_only_the_lang_value` `:2192`、`fragment_persistence_writes_the_lang_value` `:2218`、`fragment_persistence_round_trips_both_languages` `:2229`、`fragment_lang_selection_falls_back_to_en` `:2248`，覆盖前缀解析、写入值、格式往返、空/未知码降级边界）与既有 i18n 测试同模块同风格，host 运行；ui 141 测试全过 | `ui/src/i18n.rs:1915-1936, 2192-2259`；`ui/src/lib.rs:11607-11635` |
| decode_failures 贯通测试（endpoint_refresh） | NOTE | ✅ 已补齐（2026-08-12，T-G，commit 8482d85）：经 `endpoint_refresh` 生产链路的贯通测试 4 项（`application/tests/refresh_decode_failures.rs`，头注释 `:3-22`），真实 `EndpointRefresh` + 真实 `SqliteStore`（application dev-dependency 引入，dev 环为 cargo 允许形态）：解码失败经读产物 `outcome.decode_failures()`（`endpoint_refresh.rs:353`）同代事务落 `resource_decode_failures` 且与快照同 Generation 原子可见（成功路径）；提交失败记录随该代一起回滚；能力探测失败后已提交记录仍与快照原子保留；记录按 Generation 作用域、跨刷新不泄漏。构造忠实网关捕获语义（`odata_type` 恒 `None`、标准 feature 无 OEM namespace）；application 322 测试全过（2026-08-14 现 361） | `application/tests/refresh_decode_failures.rs`；`application/src/endpoint_refresh.rs:350-355` |
| AMI/HPE 真网关 E2E | LOW | ✅ 已实现（2026-08-12，T-I，commit 044bae2）：AMI/HPE 读取家族（`AmiServiceRoot`/`ConfigBmc`、`HpeiLoServiceExt`/`HpeiLo`）通过**真实网关**的 E2E 解码 5 测试已合入（`test-support/tests/gateway_mock_bmc.rs`：`ami_profile_probes_oem_ami_supported_with_standard_surface_unchanged` `:1793`、`ami_profile_reads_oem_ami_snapshots` `:1861`、`hpe_profile_probes_oem_hpe_supported_with_standard_surface_unchanged` `:2003`、`hpe_profile_reads_oem_hpe_segments_snapshot` `:2070`、`namespace_free_endpoint_leaves_ami_and_hpe_families_absent` `:2202`）；该套件现共 **28 测试**（原 23 + 5），头注释已更新（`:3-17`） | `test-support/tests/gateway_mock_bmc.rs`；`test-support/src/mock_bmc/profile.rs` |
| restore 预恢复副本 | LOW | ✅ 已实现（2026-08-12，T-E，commit 02459dc）：`restore_backup` 在首个覆盖动作前把当前数据目录复制进同级临时目录（`create_pre_restore_snapshot`，`app/src/backup.rs:300-308, 636-664`，与迁移前恢复副本同款 length-verified 拷贝 + 同步），此后才进入覆盖阶段（`restore_data_phase` `:342-372`）。**三态**：① 恢复成功——临时快照随 TempDir drop 自动清除（`:310-315`）；② 恢复中途失败——快照保留并随错误报告其位置供人工回滚（`:317-324`，`RestoreFailedPreservingSnapshot`）；③ 快照创建失败——恢复中止、数据目录原样未动（`:306-308`）。测试：`a_failed_restore_preserves_the_pre_restore_data_for_rollback`（`:1324`）/`a_successful_restore_cleans_up_the_pre_restore_snapshot`（`:1401`）/`a_failed_pre_restore_copy_leaves_the_source_untouched`（`:1421`）；rutilus 152 测试全过 | `app/src/backup.rs:246-341, 636-664` |
| free_port TOCTOU | NOTE | ✅ 已消除（2026-08-12，T-F，commit 83ff07f）：各绑定点改为端口重试——探测端口在探测与真实 bind 之间被抢占时（bind 返回 `AddrInUse`）换新端口重试，不再因竞态窗口失败（`is_raced_*_bind` 判定 + 重试循环）；`center_acceptor.rs` 的 `bind_acceptor_with_options` 探测可注入（`app/src/center_acceptor.rs:1011-1026`，`is_raced_bind` `:997-1010`），确定性重试测试 `the_bind_retries_when_the_probed_port_was_grabbed`（`:1038`）证明竞态消除；另发现并修复同款内联第 5 处（`a_not_bound_refusal_from_the_center_converges_the_local_binding` 的 acceptor bind，`site_runtime.rs:2079`）；`connect_with_retry_stops_on_the_stop_signal` 的「无人监听端口」用途保持探测语义（其后无真实 bind 可重试，`center_client.rs:886`）；同款修复分布：`center_runtime.rs:901-927`、`center_client.rs:629-654`、`site_runtime.rs:1507-1544`（`is_raced_site_bind`/`is_raced_center_bind`/`bind_site`） | `app/src/center_acceptor.rs`；`app/src/center_runtime.rs`；`app/src/center_client.rs`；`app/src/site_runtime.rs` |
| 入网首刷绕端点门 | LOW | ✅ 已实现（2026-08-12，T-B，commit 4897b22）：端点登记（enrollment）后的首次刷新改走 `endpoint_read_gate`——`EndpointEnrollment::enroll` 在 `refresh.execute` 前经进程级端点读门获取 permit（`application/src/endpoint_enrollment.rs:168-179`，失败分类为 `EndpointEnrollmentError::InitialRefreshCoordination` 并新增 `EndpointReadGateError` 导出，`application/src/lib.rs:85-86`），首刷与并发批量刷新同一端点不再重叠（注释 `:158-167`）；`refresh.execute(endpoint_id)`（`:190`）在持门期间执行；web 侧新增 `InitialRefreshCoordination` 错误映射（`web/src/lib.rs:3425`）；对抗测试 `initial_refresh_and_concurrent_batch_refresh_of_the_same_endpoint_never_overlap`（`endpoint_enrollment.rs:643`）钉死不重叠 | `application/src/endpoint_enrollment.rs:158-202`；`application/src/batch_refresh.rs:98-129`；`application/src/lib.rs` |
| 快照 ETag 接线（domain/persistence/operation_executor） | LOW | ✅ 已处置（决策 c，2026-08-12）：写路径语义已完备，快照 ETag 无独立消费价值，接线不实施。① 执行时读取 = 分派时刻可得的最新 ETag——PATCH 家族每次写都在同一次执行内重读目标文档并携带其 ETag（Boot `redfish_gateway.rs:6447-6451`、SecureBoot `:6496-6499`、UpdateService Patch `:6381-6384`、Control `:6220-6224`、Account 三写 `:6797/:6839-6841/:6883-6885`，commit 6128a17），已满足 §13.4「写操作必须使用 ETag」；快照 ETag 恒比执行时读取更旧（陈旧度随刷新节奏无界），不可替代。② 候选 a（快照 ETag 差异诊断）不成立：快照 ETag ≠ 执行时 ETag 是常态（期间发生一次刷新即变化），不是并发修改证据，比较产生噪音而非信号；412 冲突诊断已由 gateway 重读携带当前 ETag（`PreconditionReRead::Read { current_etag }`，`redfish_gateway.rs:12664-12674, 14014-14048` → `infra-redfish/src/application_adapter.rs:363, 435-446` `DispatchVerdict::NotExecuted` → 操作 `Failed`，绝不重派/覆盖），无需新增信息通道（executor 的 Store 泛型也无快照读取角色，`operation_executor.rs:123-127`）。③ 候选 b（恢复路径带旧 ETag）结构性不存在：`recover_operation` 只重读判定、从不派发写（`operation_executor.rs:465-511`），gateway 从不接受执行外部 ETag（唯一例外 `LogEntriesETag` 是操作者经 ClearLog 命令 payload 显式提供的前置条件，`redfish_gateway.rs:6048, 6081`）。快照 ETag 保持只读侧既有角色（诊断展示与中心投影：`endpoint_resources.rs:1084`、`resource_diagnostics.rs:495`、`api/src/lib.rs:660-696, 1903-1920`、`center_sync.rs:1667-1713`）。§13.4「无 ETag 时保存操作前快照」条款由传输层 `If-Match: *` + 执行后重读覆盖（无并发保护，如实标注），与本次决策无关 | `domain/src/resource_snapshot.rs:606-655, 790, 827, 858`；`persistence/src/resource_snapshot_repository.rs:402, 553-554, 605-608`；`infra-redfish/src/redfish_gateway.rs:598-611, 6447-6451, 12664-12674, 14014-14048`；`application/src/operation_executor.rs:123-127, 465-511`；`operation-engine/src/`（无 etag 引用，已核实） |
| sessions 无界增长（软撤销无清理路径） | NOTE | ✅ 已登记（2026-08-13，本行）：`sessions` 表一行一次登录（§16.2），撤销是有意的软写——`revoked_at` 置位、行**永不物理删除**，会话历史保持可审计（repository 与迁移文档同款表述）；repository 无任何删除/剪枝路径（仅 create/find/list/touch/revoke/revoke_sessions_for_principal 六操作）；已撤销/已过期行无限保留——过期行仍可读回，由调用方经 `Session::is_active` 判定（过期是读侧语义，不是存储侧清理）；增长特征：表随登录次数线性增长（每行两枚 32 字节哈希 + 生命周期时间，行小、有主键与 principal 索引），无上限、无保留周期；后续方案：未来引入已撤销/过期会话保留周期（如按 `revoked_at`/`expires_at` 定期剪枝）时处理，与 §八 events 存储增长同款登记 | `persistence/src/session_repository.rs:25-62, 64-71, 159-167, 217-250`；`migration/src/m20260807_000005_product_users.rs:32-36` |
| `Hello.last_acked_sequence` 死字段（契约漂移） | NOTE | ✅ 已处置（决策，2026-08-13）：字段**保留、不接线、不改 wire 语义**——续传实际由 durable outbox 重发 + 逐帧 Ack 完成。① 生产发送方恒写 0（`center_client.rs:256-259` 注释原文：durable outbox 是 runtime slice 的关切，新连接从零开始）；② acceptor 的 `receive_hello` 只把信封 `sequence` 记为对端水位，**从不读该字段**（`center_acceptor.rs:720-745`）；③ 重连续传走 `center_sync::connected_loop` 的初始 outbox flush（未确认条目重发，§15.4）+ `acked_sequence` 捎带与显式 `Ack` 消息逐帧确认（`center_sync.rs:756-820`），Hello 字段在其中无角色；④ proto 注释已改为契约漂移标注（字段为 wire 稳定性保留、恒零、永不复用），本行登记；测试/mock 中的构造值（`center-protocol` sample_hello 42、`mock_center` 0、acceptor/client 测试 0）保持原样，字段编解码不变 | `center-protocol/proto/rutilus/center/v1/center.proto:87-94`；`app/src/center_client.rs:248-261`；`app/src/center_acceptor.rs:720-745`；`application/src/center_sync.rs:756-820` |

> **第一波对抗审查（wave-one，2026-08-13，HEAD = 5cd75ae）**：6 透镜并行攻击，38 条 → 定案
> 31 confirmed + 2 refuted（C5-9/W6-6）+ 1 降级（W6-1）+ 4 半/部分；**27 项确认发现全部修复**
> （10 个提交：8a4d271 / 2a4340b / bcef349 / e652831 / 73d480d / 6ca207c / 3f312b2 / 31a4232 /
> d3b966a / 5cd75ae，见 `docs/milestone-status.md` 头注与 §7.6）——**含 2 HIGH（S3-1 操作历史 API 回声明文
> BMC 口令、S3-2 首启未认领窗口 GuardedOnly 整面开放）+ 1 HIGH（D4-1 中心控制台审计事件无法
> 持久化），全部已修复并如实登记**；另 3 条已登记（C5-8/C1-5/N2-6，含上行两行）、2 条 refuted
> （C5-9/W6-6）、1 条并入 C5-1（C1-1）。逐项最终状态见下表「第一波块」。
> **第二波对抗审查（wave-two，2026-08-13，已合入）**：6 透镜并行攻击，**61 条发现**（31
> confirmed + 29 reported + F4-6 部分成立，无 refuted），逐项登记见下表「第二波块」；
> 其中 12 条为 D6 文档真实性发现（D6-1..D6-12）与 A5-8 由 2026-08-13 文档收口批次处置，
> **其余 48 条全部已修复（e59b14a，60 项确认修复含 F1 追加发现）**——单提交落地前已通过
> 全部门禁复跑（fmt 干净、clippy `-D warnings` 零警告、1837 测试 0 失败），逐项状态见下表；
> F4-6（部分成立）的缓解已如实化（rust-cache 覆盖 target/rutilus-tools 注释）；F1 为 D 批
> 审计追加发现（多候选重试回退 offer 历史同 id 重投），同批修复并登记于本表末尾。

| 遗留项 | 级别 | 现状 / 后续方案 | 事实来源 |
|---|---|---|---|
| **第一波块（wave-one 对抗修复，2026-08-13，全部处置）** | | | |
| S3-1 操作历史 API 回声明文 BMC 口令 | **HIGH** | ✅ **已修复**（d3b966a）：五个响应投影经 redacting helper 序列化命令输出 `[REDACTED]`（`web/src/lib.rs` 投影层），域 `Serialize` 保持无损——at-rest 信封与中心载荷依赖；测试 `operation_history_routes_never_expose_account_passwords`（`web/tests/operation_path.rs:899`）钉死 | `web/src/lib.rs`；`web/tests/operation_path.rs` |
| S3-2 首启未认领窗口整面 GuardedOnly 开放 | **HIGH** | ✅ **已修复**（d3b966a）：`PendingBootstrap` 策略下每个 `GuardedOnly` 路由无论门是否 armed 一律要求会话（`web/src/auth.rs:165` `AuthPolicy::PendingBootstrap`、`is_guarded` `:176, 210`、门检查 `:1352`），控制台 401 时重跑认证决策；测试 `auth_gate_starts_open_and_arms_guarded`（`auth.rs:4414`） | `web/src/auth.rs` |
| D4-1 中心控制台审计事件无法持久化 | **HIGH** | ✅ **已修复**（d3b966a）：`m20260813_000001_audit_center_actions` 扩展 action/outcome CHECK 补三个中心动作与两个中心失败码，web 写路径本已产生这些事件；迁移测试 `migration/tests/audit_center_actions.rs` | `migration/src/m20260813_000001`；`migration/tests/audit_center_actions.rs` |
| C5-1 制品分块组装不抗重投（含 C1-1，同根因合并） | MEDIUM | ✅ **已修复**（d3b966a）：chunk 按 index 定位写偏移（`application/src/center/projection.rs:880`），file-before-row / row-before-cursor 双崩溃窗口在重投时愈合 | `application/src/center/projection.rs`；`application/src/artifact_store.rs` |
| C5-2 事件时间线零时钟容差 | MEDIUM | ✅ **已修复**（d3b966a）：60s 时钟容差内接受并把观测时间钳制到事件时间，超出容差分类跳过（不再静默永久丢弃） | `application/src/center_sync.rs` |
| C5-3 事件入库无站点归属校验 | MEDIUM | ✅ **已修复**（d3b966a）：事件批次按 reporting site 校验每个 endpoint 归属（测试 `an_offer_for_another_site_is_dropped` 同款纪律） | `application/src/center_sync.rs:3974` |
| C5-4 ArtifactChunk 消费不校验制品归属站点 | LOW | ✅ **已修复**（d3b966a）：chunk 消费前 `find_artifact_site` 校验 | `application/src/center/projection.rs` |
| C5-5 操作回执不校验回复站点 | LOW | ✅ **已修复**（d3b966a）：回执只从 offer_site 计分，外站回复拒收并记录（测试 `a_duplicate_of_a_rejected_offer_stays_rejected` `center_sync.rs:3998`） | `application/src/center_sync.rs` |
| C5-6 dispatch 重试双 offer 双执行 | LOW | ✅ **已修复**（d3b966a）：同键重试幂等返回既有操作（`a_duplicate_of_a_completed_offer_returns_the_recorded_outcome` `center_sync.rs:4048`），TTL 内复活沿用同一 id | `application/src/center_sync.rs` |
| C5-7 Queued offer 无 TTL | LOW | ✅ **已修复**（d3b966a）：过期 queued offer 终结不重发（测试 `an_expired_offer_rejects_with_expired` `center_sync.rs:3471`、`an_offer_with_an_unparseable_expiry_is_refused_as_expired` `:3495`） | `application/src/center_sync.rs` |
| C5-8 `Hello.last_acked_sequence` 死字段 | NOTE | ✅ 已登记（6ca207c，见上行本行） | 本行 |
| C5-9 重复回执产生重复 inbox 行 | NOTE | **refuted**（验证：inbox 按 operation_id 查重 `DuplicateResolved`） | `persistence/src/center_inbox_repository.rs` |
| C5-10 Hello 声明身份不校验 | NOTE | ✅ **已修复**（5cd75ae）：admission 把 Hello 声明 instance id 与证书绑定身份比对，不一致答 `identity-mismatch`（词汇新增、无 wire 变更；`center_acceptor.rs:262, 348-349`） | `app/src/center_acceptor.rs` |
| C1-2 恢复判定覆盖并发推进中的操作 | LOW | ✅ **已修复**（d3b966a）：`apply_transition_if_current` CAS 三臂（`operation_engine.rs:665`），陈旧读不再覆盖已推进操作 | `operation-engine/src/operation_engine.rs` |
| C1-3 expires_at_unix 不可解析 fail-open | NOTE | ✅ **已修复**（d3b966a）：不可解析按过期拒绝（fail-closed，测试 `an_offer_with_an_unparseable_expiry_is_refused_as_expired`） | `application/src/center_sync.rs:3896` |
| C1-4 Unknown/Cancelled 折叠成 Failed | NOTE | ✅ **已修复**（d3b966a）：summary 状态码区分 Unknown/Cancelled 与 Failed，wire 不变 | `application/src/command_executor.rs` |
| C1-5 端点读门注册表只增不减 | NOTE | ✅ 已登记（6ca207c）：注释如实化——site 的 managed-endpoint 路径当前无移除，条目存活至进程生命周期、以全量舰队规模为界（`batch_refresh.rs:98-129`） | `application/src/batch_refresh.rs` |
| N2-1 Argon2id 在 async worker 同步执行 | MEDIUM | ✅ **已修复**（d3b966a）：验证与派生走 blocking 池（`auth.rs` 登录/认领/改密三入口，测试 `change_password_runs_verification_and_derivation_off_the_async_worker` `auth.rs:4987`、`bootstrap_runs_password_derivation_off_the_async_worker` `:5060`） | `web/src/auth.rs` |
| N2-2 优雅关停对在飞请求无时限 | MEDIUM | ✅ **已修复**（5cd75ae）：TimeoutLayer 限每个 console handler + drain 与 10s `GRACEFUL_DRAIN_TIMEOUT` 赛跑，慢/挂客户端不能拖住 stop；SCM wait-hint 注释如实化 | `app/src/standalone_runtime.rs:1596`（`serve_with_bounded_drain`）；`app/src/site_runtime.rs` |
| N2-3 调度器单 tick 队首阻塞 | MEDIUM | ✅ **已修复**（d3b966a）：scheduler 在每端点写门后并发驱动操作（`buffer_unordered`），task-monitor 通道并行，单 BMC 挂起不再卡整条流水线 | `app/src/scheduler.rs`；`application/src/task_monitor.rs` |
| N2-4 prune_stale 死代码 / 僵尸 site | MEDIUM | ✅ **已修复**（5cd75ae）：`DisconnectOnDrop` guard 在连接任务结束（含 panic/abort）时把 site 移出会话注册表；从未接线的 prune_stale 兜底作为死代码移除 | `application/src/center/session.rs`；`app/src/center_runtime.rs` |
| N2-5 遥测采样时间戳无单调校验 | LOW | ✅ **已修复**（6ca207c）：回拨 instant 以 `ClockRollback` 分类错误拒绝（不钳制——不伪造从未存在的时间；等值 instant 同 sweep 接受；测试 `a_clock_rollback_is_refused_and_history_stays_monotonic` `telemetry_sampler.rs:1034`） | `application/src/telemetry_sampler.rs:602, 708` |
| N2-6 sessions 无界增长 | NOTE | ✅ 已登记（6ca207c，见上行本行） | 本行 |
| S3-3 登录限速 check-then-act 竞态 | LOW | ✅ **已修复**（d3b966a）：原子 reserve/refund（`auth.rs:1012-1094`），并发放大竞态关闭（测试 `rate_limiter_prune_reclaims_compensated_empty_buckets` 更名对应） | `web/src/auth.rs` |
| S3-4 新建用户无口令配置路径 | LOW | ✅ **已修复**（5cd75ae）：`POST /api/v1/admin/users/{id}/password` 两端面可用（`auth.rs:2738`），B4 分支不再使无口令账户永久不可登录；UI 表单保持 later milestone（本表 §二 S3-4 行） | `web/src/auth.rs:2738` |
| S3-5 cookie_value 前缀早退 | NOTE | ✅ **已修复**（d3b966a）：畸形前缀对跳过继续扫描其余 cookie | `web/src/auth.rs` |
| D4-2 恢复兼容性检查忽略 WAL | MEDIUM | ✅ **已修复**（d3b966a）：暂存目录先回放 WAL 再读 applied migrations，`NewerSchema` 门看到真实状态（测试 `compatibility_replays_the_wal_before_reading_the_applied_migrations` `backup_snapshot.rs:653`） | `persistence/src/backup_snapshot.rs` |
| D4-3 中心投影 upsert 无 Generation 守卫 | LOW | ✅ **已修复**（d3b966a）：`StaleGeneration` 拒绝旧代 | `persistence/src/center_projection_repository.rs` |
| D4-4 迁移前备份目录从不清理 | LOW | ✅ **已修复**（d3b966a）：保留最近 3 份（`migration_backup.rs`，`PRE_MIGRATION_BACKUP_RETENTION`） | `persistence/src/migration_backup.rs` |
| D4-5 endpoints.health/refresh_generation 无 CHECK | LOW | ✅ **已修复**（d3b966a）：`m20260813_000002` 重建八表 CHECK 家族（`migration/tests/endpoint_health_checks.rs`） | `migration/src/m20260813_000002` |
| D4-6 迁移注册顺序错位 | NOTE | ✅ **已修复**（d3b966a）：按文件名序重排 | `migration/src/lib.rs` |
| W6-1 测试型门禁无 ran-断言（降级） | MEDIUM（降级） | ✅ **已修复**（bcef349）：`scripts/assert-tests-ran.sh` floor 断言——Secret leak gate（floor 10）与 Migration test（floor 50，V4I-3/4 重测后同步）；Release baseline / Capability ledger / workspace Test 登记为后续候选（ci.yml:550-556 注释） | `scripts/assert-tests-ran.sh`；`ci.yml:550-556` |
| W6-2 PR 可改工作流删门禁 | MEDIUM | ✅ **已修复**（bcef349）：`.github/CODEOWNERS` 要求 `.github/` 变更显式评审；branch protection 如实登记为仓库外防线 | `.github/CODEOWNERS` |
| W6-3 bare_sql_gate 首词盲区（CTAS/TRIGGER 内嵌 DML） | MEDIUM | ✅ **已修复**（73d480d）：`ddl_embedded_dml` 词扫描（首词后继续扫），`AS /* copy */ SELECT` 词对间距、引用字面量误报边界如实登记；门禁现 626 行 | `migration/tests/bare_sql_gate.rs` |
| W6-4 secret_leak_gate 间接赋值盲区 | MEDIUM | ✅ **已修复**（73d480d）：`wrapper_or_indirect`（String::from/format!/concat!/to_string 包装 + 两步间接，作用域感知传递解析，赋值失效含入），wrapper 漏报形状如实登记 | `security/tests/secret_leak_gate.rs:836` |
| W6-5 路由授权表与路由器无机械同步 | MEDIUM | ✅ **已修复**（5cd75ae）：`EDGE_ROUTES`/`CENTER_ROUTES` 单一注册源折叠进两路由器 + 穷举 kind 分派，双向门禁测试点名 ROUTE_TABLE 每条注册路由与每个表条目（`auth.rs:3145` `route_table_pins_the_authorization_matrix`） | `web/src/lib.rs:875, 1217`（`EDGE_ROUTES`/`CENTER_ROUTES`）；`web/src/lib.rs:1105, 1341`（折叠进路由器） |
| W6-6 down_order_gate 跨文件 down 序盲区 | LOW | **refuted**（验证：引错文件 + 门禁本就跨文件聚合 FK 边） | `migration/tests/down_order_gate.rs` |
| W6-7 门禁扫描面（build.rs 逃逸 / 非递归） | LOW | ✅ **已修复**（73d480d + 2a4340b）：两门禁递归扫描 + secret gate 覆盖 build.rs | `migration/tests/bare_sql_gate.rs`；`security/tests/secret_leak_gate.rs:1344`（`crate_scan_includes_build_scripts`） |
| W6-8 ci.yml 缓存注释过时 | NOTE | ✅ **已修复**（bcef349）：按事实改写（action 无缓存步骤、PR 缓存 ref 作用域） | `.github/workflows/ci.yml:209-220` |
| **第二波块（wave-two 对抗发现，2026-08-13，61 条）** | | | |
| P1-1 Overview/详情页 O(N²) | P1 | ✅ **已修复**（e59b14a）：overview 页一次库存读取 + 一次批量能力查询（`application/src/capability_query.rs` 新增、`endpoint_capability_repository.rs` 批量读），替代 O(N²) 逐端点往返 | `application/src/overview.rs`；`application/src/capability_query.rs`；`persistence/src/endpoint_capability_repository.rs` |
| P1-2 调度器每 2s 全表扫描 + 逐行 AEAD 解密 | P1 | ✅ **已修复**（e59b14a）：scheduler 经状态索引恢复 pending 操作（`recover_pending` 走 4 态索引查询），终态行永不扫描/解密 | `operation-engine/src/operation_engine.rs:359-369`；`app/src/scheduler.rs:418-421`；`persistence/src/operation_repository.rs` |
| P1-3 dispatch 幂等扫描全表 + 全 outbox 逐行解密 | P1 | ✅ **已修复**（e59b14a）：幂等只扫候选态与 pending offers，acked 历史永不进解密路径 | `application/src/center/dispatch.rs:346, 386-466, 535-549`；`persistence/src/center_outbox_repository.rs:242-260, 425-433` |
| P2-4 事件批次逐条处理（每事件 1 读 + 1 独立写门事务） | P2 | ✅ **已修复**（e59b14a）：事件批次预载 + 单事务写入 | `application/src/center/projection.rs`；`persistence/src/event_repository.rs` |
| P2-5 投影 upsert 无条件删插地址/信任行 | P2 | ✅ **已修复**（e59b14a）：未变 address/trust 行跳过 delete+insert | `persistence/src/center_projection_repository.rs:131-183` |
| P2-6 中心侧 artifact finalize 整文件读入内存哈希 | P2 | ✅ **已修复**（e59b14a）：finalize 流式哈希（与站点侧 64KiB 流式对齐） | `application/src/center/projection.rs:970-981` |
| P2-7 每 chunk 3 读 + 2 写门事务 + 每次 open/seek | P2 | ✅ **已修复**（e59b14a）：chunk 写复用单一有界文件句柄（`OpenArtifactFile` 单槽缓存），open/seek 逐 chunk 成本消除 | `application/src/center/projection.rs:562, 1396-1445` |
| P3-8 站点投影汇总全行物化求 count/max | P3 | ✅ **已修复**（e59b14a）：`center_site_projection_summary` 改 SQL 聚合（`COUNT` + `MAX`），不再物化全行 | `persistence/src/center_projection_repository.rs:620-652` |
| P3-9 每回执 2-3 个独立写门事务 | P3 | ✅ **已修复**（e59b14a）：回执插入 + 相位推进合并为单写门事务（`log_reply`），重复回执才走既有推进路径 | `application/src/center/dispatch.rs:955-975` |
| P3-10 重连全量重放 + outbox acked 行永不清理 | P3 | ✅ **已修复**（e59b14a）：重连只上报状态变化（delta 化，`enqueue_resource_delta` 有状态变化才入队），acked 行语义如实 | `application/src/center_sync.rs:1597, 1696` |
| P3-11 读/写门注册表无回收 | P3 | ✅ **已登记**（既有登记：C1-5 行，端点删除路径落地时需接线；当前无删除路径，不构成待修复项） | `application/src/batch_refresh.rs:98-124`；`app/src/scheduler.rs:103-123` |
| P4-12 Argon2id blocking 池无并发上限 | P4 | ✅ **已修复**（e59b14a）：`PASSWORD_DERIVATION_SLOTS`（`Semaphore::const_new(MAX_CONCURRENT_PASSWORD_DERIVATIONS)`）有界并发 | `app/src/standalone_runtime.rs:130-131`；`web/src/auth.rs` |
| E3-1 绑定轮询瞬态错误被当撤销（站点永久掉线） | HIGH | ✅ **已修复**（e59b14a）：绑定 watch 把消失行与 store 错误当瞬态继续轮询，只有真实撤销停止同步，日志记录实际发生的事 | `app/src/site_runtime.rs:1406-1414, 1370-1379` |
| E3-2 identity-mismatch 无终态处理 | MED-HIGH | ✅ **已修复**（e59b14a）：站点侧分类（`is_identity_mismatch`），连续三次拒绝中止并走 re-bind 修复路径，绝不撤销生效中绑定 | `app/src/center_client.rs:509-517`；`application/src/center_sync.rs:680` |
| E3-3 持续时钟回拨无界 error 风暴 | MEDIUM | ✅ **已修复**（e59b14a）：持续回拨在首个 error 后降级 warn（不再无界 error） | `application/src/telemetry_sampler.rs:585-606, 337-339, 620-633` |
| E3-4 CapabilityUnsupported 审计/wire/单操作 UI 三面不可见 | MEDIUM | ✅ **已修复**（e59b14a）：审计（`AuditFailure::CapabilityUnsupported` `operation_executor.rs:295`）+ wire（`failed-unsupported` `center_sync.rs:1515`）+ 操作响应（`project_failure_kind` `web/src/lib.rs:2763`，list 与 detail 路由均携带）；**UI 分类徽标渲染仍为后续迭代**（`ui/src/lib.rs:8168-8175` 注释原文：延迟的是渲染不是 wire，fetch 层已解析） | `application/src/operation_executor.rs:282-295`；`web/src/lib.rs:2737-2763`；`application/src/center_sync.rs:1496, 1515`；`ui/src/lib.rs:8168-8175` |
| E3-5 终态操作被记 error「could not be driven」 | MEDIUM | ✅ **已修复**（e59b14a）：终态操作如实记录（注释 `scheduler.rs:518-522`：失败即最终定论、终态排除恢复扫描，不再误导重派） | `app/src/scheduler.rs:518-522` |
| E3-6 事件不可解码仍推进游标（站点/中心静默分叉） | MED-LOW | ✅ **已修复**（e59b14a）：跳过事件与 delta 流同款 warn（`tracing::warn!` `projection.rs:797-802`），不再静默 | `application/src/center/projection.rs:710-757, 797-802` |
| E3-7 HelloIdentityMismatch 未净化写日志 | MED-LOW | ✅ **已修复**（e59b14a）：声明身份净化后写日志 | `app/src/center_runtime.rs:780-784`；`application/src/center/session.rs:109-113` |
| E3-8 损坏 outbox 行每次重连永久 error | LOW-MED | ✅ **已修复**（e59b14a）：corrupt-outbox 错误以 warn 重复（不再永久 error） | `application/src/center_sync.rs:881, 2071-2081`；`application/src/center/session.rs:727-743` |
| E3-9 list_center_operations 静默丢弃不可解码信封 | LOW | ✅ **已修复**（e59b14a）：控制台视图记录跳过的信封 | `app/src/center_runtime.rs:522-531` |
| E3-10 CSV 导入错误丢弃底层原因 | LOW | ✅ **已修复**（e59b14a）：CSV 错误携带解析器来源 | `application/src/endpoint_csv.rs:132, 146-148, 204-206` |
| D6-1 第一波 27 项修复文档零登记 | HIGH | ✅ **已修复**（2026-08-13 D6 文档收口批次，本批）：本表第一波块 + `milestone-status.md` 头注/§7.6 + `security-review.md` §三/§四 | 本批各文档 |
| D6-2 测试计数全面过时（1731 vs 实测 1800） | HIGH | ✅ **已修复**（2026-08-13 D6 文档收口批次）：`cargo test --workspace -- --list` 实测 1800，per-crate 全量登记（`milestone-status.md` 头注、`release-readiness.md` 头注/§五） | 本批各文档 |
| D6-3 web/src/auth.rs 行号引用漂移（+114..+390） | HIGH | ✅ **已修复**（2026-08-13 D6 文档收口批次）：全文档 auth.rs 引用按当前 master 重锚（security-review §二/§三/§四、known-limitations §七/§九、release-readiness、milestone-status） | 本批各文档 |
| D6-4 七文档 ci.yml 引用漂移（+7..+93） | HIGH | ✅ **已修复**（2026-08-13 D6 文档收口批次）：七文档 ci.yml 引用全量重锚；operations-manual「cargo deny 0.20.2」按 ci.yml 事实修正 | 本批各文档 |
| D6-5 迁移/备份计数失同步（23→25、21→23、24/23→26/25） | HIGH | ✅ **已修复**（2026-08-13 D6 文档收口批次）：25 迁移文件、23 迁移测试文件（wave-one 前基线 21，452a291 实测）、备份 pin 26/25（`backup_snapshot.rs:646-647`）三文档同步 | 本批各文档 |
| D6-6 web/src/lib.rs 行号引用漂移（+223..+657） | MEDIUM | ✅ **已修复**（2026-08-13 D6 文档收口批次）：全文档 web lib.rs 引用重锚 | 本批各文档 |
| D6-7 其余 wave 触达文件行号漂移 | MEDIUM | ✅ **已修复**（2026-08-13 D6 文档收口批次）：backup.rs/center_sync.rs/operation_engine.rs/negotiation.rs/batch_refresh.rs/web tests 引用重锚 | 本批各文档 |
| D6-8 milestone-status 自身行号被跨文档引用漂移（+2） | MEDIUM | ✅ **已修复**（2026-08-13 D6 文档收口批次）：release-readiness/security-review 对 milestone-status 的引用按新行号重锚 | 本批各文档 |
| D6-9 release-readiness「本版」HEAD 自述落后（6f8b698 vs 5cd75ae） | MEDIUM | ✅ **已修复**（2026-08-13 D6 文档收口批次）：头注 bump 至 5cd75ae，§五/§六 历史标记注明基准 | `release-readiness.md` |
| D6-10 user-manual §5.1 ETag 段与 T-C 决策矛盾 | MEDIUM | ✅ **已修复**（2026-08-13 D6 文档收口批次）：改为「已处置（决策 c，不实施）」；ui 行号 +2 重锚 | `user-manual.md` §5.1 |
| D6-11 support-matrix §4.4 Mock profile 清单过时 | LOW | ✅ **已修复**（2026-08-13 D6 文档收口批次）：更新为 11 个变体 | `support-matrix.md` §4.4 |
| D6-12 门禁计数细项过时（security 8→9、down_order_gate 8→11、migration 38→48） | LOW | ✅ **已修复**（2026-08-13 D6 文档收口批次）：release-readiness §五 / milestone-status 头注按实测更新；`assert-tests-ran.sh:19` 注释的 floor 8/38 为下界 pin 保持不动 | 本批各文档 |
| F4-1 CI 第三方 action 移动 tag 无 SHA 钉版、无 Dependabot、release-artifacts 暴露签名 secrets | MEDIUM | ✅ **已修复**（a4ab972 + e59b14a）：六 action 全部 SHA 钉版（`ci.yml:103, 108, 115, 132, 223, 901, 911`，tag 注释行内）+ `.github/dependabot.yml` 每周 bump PR + CODEOWNERS 评审（`.github/` 变更显式评审） | `.github/workflows/ci.yml`；`.github/dependabot.yml`；`.github/CODEOWNERS` |
| F4-2 quick-xml 0194 忽略理由答非所问 | LOW-MED | ✅ **已修复**（a4ab972）：deny.toml 理由按事实修正（输入可信是真正缓解） | `deny.toml:32-33` |
| F4-3 bans skip 表只覆盖可达重复版本 | LOW-MED | ✅ **已修复**（a4ab972）：skip 条目按可达性登记（`deny.toml:65-85`） | `deny.toml:65-85` |
| F4-4 tokio-util 0.7.19 两处声明绕过 workspace 单一来源 | LOW | ✅ **已修复**（a4ab972）：tokio-util 单一来源（根 `Cargo.toml`），app/infra-redfish 不再各自声明 | 根 `Cargo.toml`；`app/Cargo.toml`；`infra-redfish/Cargo.toml` |
| F4-5 SBOM 步骤无 --locked 且含 dev-deps/wasm 图成员 | LOW | ✅ **已修复**（e59b14a）：SBOM 步骤先 `cargo metadata --locked` 断言锁定图（`ci.yml:881`）；dev-deps 保留为如实登记（cargo-cyclonedx 无 --no-dev-deps，`--no-build-deps` 会丢构建期必需组件，注释原文） | `ci.yml:878-891` |
| F4-6 wasm-bindgen-cli 每次 CI 现装 | LOW | ✅ **已处置**（e59b14a，部分成立）：缓解如实化——rust-cache 覆盖 target/rutilus-tools 的注释入 ci.yml（`ci.yml:113`），编译成本已缓解的事实成文 | `ci.yml:113-114` |
| F4-7 公告忽略双列表无机制同步 | LOW | ✅ **已修复**（a4ab972）：双列表注释双向锁步（deny.toml 注释指回 ci.yml，`ci.yml:227-245` 审计忽略列表注释原文） | `deny.toml:21-24`；`ci.yml:227-245` |
| A5-1 SetPasswordRequest 文档声称无强度策略、wire 实际强制 12 字符 | LOW-MED | ✅ **已修复**（e59b14a）：文档声明强制 12 字符策略（`api/src/lib.rs` SetPasswordRequest 文档按 handler 事实修正） | `api/src/lib.rs:4958-4960`；`web/src/auth.rs:2170` |
| A5-2 proto 只列 3 个拒绝码、实际出货 5 个 | LOW | ✅ **已修复**（e59b14a）：proto 文档列全 5 个拒绝码 | `center-protocol/proto/rutilus/center/v1/center.proto:103-106` |
| A5-3 UI 声称渲染 wire 字段名、实际标签非 wire 名 | LOW | ✅ **已修复**（e59b14a）：UI 标签与 wire 名一致（`service_enabled` 等，`ui/src/lib.rs:8110-8116`） | `ui/src/lib.rs:8110-8116`；`domain/src/redfish_command.rs:1786-1790` |
| A5-4 兄弟 detail 路由同类错误返回不同 wire 形态 | LOW | ✅ **已修复**（e59b14a）：detail 路由统一 JSON 错误体（`json_error` + 具名 id 消息，`web/src/lib.rs` endpoint/resource/diagnostics/capability/operation detail 均收敛） | `web/src/lib.rs:1539, 1587-1590, 1707-1713` |
| A5-5 NVIDIA debug token（token_data）明文过响应 wire | LOW | 边界已文档承认，属范围记录（未改 wire，保持如实）：响应脱敏助手只替换成员名 `password`（`api/src/lib.rs:3643-3666` `serialize_redacted_command`），`token_data` 不在其列；域载荷 `token_data` 字段与样例（`domain/src/redfish_command.rs:2861-2881, 3810`） | `api/src/lib.rs:3643-3666`；`domain/src/redfish_command.rs:2861-2881, 3810` |
| A5-6 product_version 声称「recorded by the peer」实际中心侧从不读取 | NOTE | ✅ **已修复**（e59b14a）：product_version 文档如实化（中心侧从不读取） | `center-protocol/src/negotiation.rs:6-7`；`center.proto:63-64` |
| A5-7 站点侧 identity-mismatch 与未知码不可区分 | NOTE | ✅ **已修复**（e59b14a）：站点侧区分诊断（`is_identity_mismatch` 分类，`app/src/center_transport.rs:24-29`） | `app/src/center_client.rs:509-517`；`app/src/center_transport.rs:24-29` |
| A5-8 S3-4 行声称「CLI/API 侧设置口令」、CLI 不存在该命令 | NOTE | ✅ **已修复**（2026-08-13 D6 文档收口批次）：本表 §二 S3-4 行改为「**API** 侧」 | 本表 §二 |
| T1-1 W6-5 路由门可被通配符遮蔽形态骗过 | HIGH | ✅ **已修复**（e59b14a）：路由门检查权限级而非仅存在性——每条注册 (method, path, kind) 必须解析到其 kind 声明的访问，窄权限路由被通配符遮蔽会失败门禁 | `web/src/auth.rs:985-990`（`table_entry` 解析）；`web/src/auth.rs:3145`（`route_table_pins_the_authorization_matrix`） |
| T1-2 内嵌 DML 检查可被 SQL 注释绕过 | MED-HIGH | ✅ **已修复**（e59b14a）：bare-SQL 门禁先剥 SQL 注释再扫描（`strip_sql_comments`，引号字面量保留、边界如实登记） | `migration/tests/bare_sql_gate.rs:266-299` |
| T1-3 down 体外 helper 中 builder 式 drop 不可见 | MED | ✅ **已修复**（e59b14a）：`file_wide_drop_sequence` 文件级收集 builder + raw 两种 drop 形状（含 helper 内），测试 `gate_checks_builder_drops_in_helpers_outside_the_down_body` | `migration/tests/down_order_gate.rs:832-855, 913-927` |
| T1-4 [R2] 跨字面量拆分 PEM 私钥逃逸 | MED | ✅ **已修复**（e59b14a）：`pem_fragment_violation` 标记跨段 PEM 片段（`concat!`/`format!` wrapper 内），漏报形状如实登记 | `security/tests/secret_leak_gate.rs:849-901` |
| T1-5 JSON 诊断层无任何可证伪测试 | MED-HIGH | ✅ **已修复**（e59b14a）：JSON 诊断层真实断言 JSON 产出的测试（`json_log_format_is_accepted_and_keeps_user_visible_output`） | `app/tests/log_format.rs:17-36`；`app/src/main.rs:255` |
| T1-6 resource 投影 upsert 结果全丢弃且无代际检查 | MED | ✅ **已修复**（e59b14a）：resource 投影获 `StaleGeneration` guard + 真实测试（`persistence/tests/stress_capacity.rs` 计数型断言） | `persistence/tests/stress_capacity.rs:1008-1052`；`persistence/src/center_projection_repository.rs:262-347` |
| T1-7 dummy_credential 测试自证自足 | MED | ✅ **已修复**（e59b14a）：dummy 凭据逐字节 pin（字面量比较，非自证自足） | `web/src/auth.rs:4356`（`dummy_credential_is_a_fixed_constant_in_the_argon2id_format`） |
| T1-8 覆盖声称与实跑不符（1731 vs 1800） | MED | ✅ **已处置**（D6-2 + 本批）：计数已同步实测（1800 → 1837 → 1913，`cargo test --workspace -- --list`），文档其余过时表述随本批收口 | `release-readiness.md` 头注；`ci.yml:196-200`（llvm-cov 80% 门） |
| T1-9 新测试重蹈硬编码步数陷阱 | LOW-MED | ✅ **已处置**（e59b14a 登记）：`down(Some(1))` 是「回滚到 health-check 迁移本身」的单步回滚（注释原文，`endpoint_health_checks.rs:179-182`），与 `migrations_before` 派生 steps 的既有纪律同文件共存；该行保留为唯一硬编码单步场景并如实注释（`Some(steps)` 派生路径已覆盖多数文件） | `migration/tests/endpoint_health_checks.rs:91-92, 179-182` |
| T1-10 stop_watch 测试只能挂死不能失败 | LOW-MED | ✅ **已修复**（e59b14a）：`stop_watch_resolves_on_signal_and_on_signal_drop` 两处等待均包 5s `tokio::time::timeout`（挂死即失败）+ 停止断言 | `app/src/scheduler.rs:1233-1252` |
| T1-11 capability_path 只序列化单一状态值 | LOW | ✅ **已修复**（e59b14a 登记）：`distinguishes_capability_route_states` 覆盖 ledger 全量条目 + 未知端点/错误方法/未探测（空态）等路由状态（`web/tests/capability_path.rs:865-935`）；`CapabilityState` 序列化全变体由 web 投影 `project_capability_state` 逐变体覆盖（`web/src/lib.rs:6388`） | `web/tests/capability_path.rs:865-935`；`web/src/lib.rs:6388` |
| T1-12 错误消息断言仅为存在性 | LOW | ✅ **已修复**（e59b14a）：detail 路由错误消息精确断言（`diagnostics_path.rs` 新增 `assert_eq!(body["message"], "endpoint id is invalid")` 等，A5-4 同批）；限流/参数错误路径消息存在性断言保留为宽松形态（消息文案本身非契约，如实） | `web/tests/diagnostics_path.rs:1104-1120`；`web/tests/event_path.rs:727`；`web/tests/telemetry_path.rs:793` |
| F1 多候选重试遇 acked offer 回退 offer 历史同 id 重投（D 批审计追加发现） | — | ✅ **已修复**（e59b14a）：候选解析回退全量 offer 历史，在飞/已 ack offer 同 id 重投——绝不新造 id、绝不双执行 | `application/src/center/dispatch.rs:414-490, 520-571` |

> **第三波对抗审查（wave-three，2026-08-13，HEAD = e768473，1 个提交）**：4 透镜旋转攻击
> （修复验证 / 安全 / 并发 / 契约），30 条发现 → **29 confirmed** + 1 HIGH 降级 LOW（验证者
> 证明登录限速器已界住声称的泄漏面）；**29 项确认发现全部修复（e768473）**——单提交落地前
> 已通过全部门禁复跑（fmt 干净、clippy `-D warnings` 零警告、1862 测试 0 失败），逐项状态
> 见下表「第三波块」。
> **第四波对抗审查（wave-four，2026-08-13，HEAD = 3a23b9b，1 个提交）**：4 透镜（修复交互 /
> 安全 / 性能 / 集成），30 条发现 → **29 confirmed** + 1 HIGH 双透镜双确认（V4I-1/V4R-1）；
> **29 项确认发现全部修复（3a23b9b）**——落地前全部门禁复跑（fmt / clippy `-D warnings`
> 零警告、1878 测试 0 失败（16 新增）），逐项状态见下表「第四波块」。
> **第五波对抗审查（wave-five，2026-08-13，HEAD = e85560a，1 个提交）**：4 透镜（迁移 / 审计
> 可问责 / 中心协议端到端 / 新鲜正确性），25 条发现**全部 confirmed（含 5 HIGH）**；
> **25 项确认发现全部修复（e85560a）**——落地前全部门禁复跑（fmt / clippy `-D warnings`
> 零警告、1913 测试 0 失败（35 新增），2026-08-14 `cargo test --workspace -- --list`
> 实测同数），逐项状态见下表「第五波块」。
> **第六波对抗审查（wave-six，2026-08-14，HEAD = 7c6ac9d，2 个提交）**：6 透镜（并发 / 安全 /
> 数据迁移 / 中心协议 / web+UI+CI / 测试质量与文档）并行攻击 wave-five 状态，58 条发现 → 跨
> 透镜去重后 54 条交独立怀疑者核验 → **48 confirmed + 3 partial + 3 refuted**；48 项确认发现
> 全部修复（fcf7257）+ 3 项链式发现（R6-W-3 伪造 center 归因 400 拒绝、R6-W-6 制品声明尺寸
> 2 GiB 封顶、R6-E-11 审计偏移分页）与 A1 新拒绝码接线（7c6ac9d）——落地前全部门禁复跑
> （fmt / clippy `-D warnings` 零警告、**1963 测试 0 失败**（2026-08-14 实测，`--list` 口径：
> lib/集成 1962 + doc 1，增量 1913→1963 +50；提交消息的 1958/45 为 fcf7257 中间计数，链式
> 提交另 +5）），逐项状态见下表
> 「第六波块」；refuted 3 条含 R6-W-3 的 inbox 污染半边（验证：回执走 offer 定向查询与既有
> 查重，伪造 source 不产生 inbox 行）。
> **第七波对抗审查（wave-seven，2026-08-14，HEAD = a0b2bc0，1 个提交）**：7 透镜（修复验证 /
> 安全 / 并发 / 数据迁移 / 中心协议 / web+UI+CI / 性能）并行攻击 wave-six 状态，40+ 条发现 →
> 跨透镜去重约 30 条交 4 个独立怀疑者核验 → **27 confirmed + 4 refuted（W7-P-10 已登记设计 /
> W7-L-2 已登记决策 / W7-C-5 不可达 / W7-H-1 前提被 runner-images 六代历史源码证伪）+ 3
> partial 降级**；27 项确认发现全部修复（a0b2bc0）——落地前全部门禁复跑（fmt / clippy
> `-D warnings` 零警告、**1997 测试 0 失败**（2026-08-14 实测，增量 1963→1997 +34）），逐项
> 状态见下表「第七波块」；refuted/partial 与 NOTE 级未修项如实登记于下。
> **第八波对抗审查（wave-eight，2026-08-14，HEAD = 6d5e90e，1 个提交）**：7 透镜并行攻击
> wave-seven 状态，25 条发现 → 去重约 20 条交 3 个独立怀疑者 → **16 confirmed + 1 refuted
> （W8-C-3 代计数器回绕，2^64 次注册双不可达）+ 5 partial 降级**；16 项确认发现全部修复
> （6d5e90e）——落地前全部门禁复跑（fmt / clippy `-D warnings` 零警告、**2013 测试 0 失败**
> （增量 1997→2013 +16）），逐项状态见下表「第八波块」；refuted/partial 与 NOTE 级未修项
> 如实登记于下。

| 遗留项 | 级别 | 现状 / 后续方案 | 事实来源 |
|---|---|---|---|
| **第三波块（wave-three 对抗发现，2026-08-13，29 条）** | | | |
| W3F-1 单候选修复合并异目标 dispatch（静默丢合法派发） | MED-HIGH | ✅ **已修复**（e768473）：单候选修复经 `offer_history` 解析候选目标——候选目标与在飞操作不一致绝不并入其 id（`dispatch.rs:490` 注释原文「The single-candidate repair read (W3F-1, W3F-5)」、`offer_history` `:581`）；对抗测试 `a_single_candidate_repair_never_merges_a_different_target_dispatch`（`:3028`）钉死不再静默丢弃合法 dispatch | `application/src/center/dispatch.rs:436-437, 490, 549, 566, 581, 3028` |
| W3S-1 改密可饿死登录的 Argon2 槽 | MEDIUM | ✅ **已修复**（e768473）：改密携带登录同形限速预算（`password_change_limiter` `auth.rs:1003`）；派生等待队列有界（`MAX_QUEUED_PASSWORD_DERIVATIONS = 8` `standalone_runtime.rs:152`、`PASSWORD_DERIVATION_QUEUE` `:173`），队列满答 503 HashGateBusy（`auth.rs:1819-1824`，503 即记录不写审计），Viewer 不再能饿死登录派生槽 | `web/src/auth.rs:1003, 1819-1824`；`app/src/standalone_runtime.rs:143-173` |
| W3S-2 set-user-password 审计不具名 / 撤销失败伪装认证失败 | MEDIUM | ✅ **已修复**（e768473）：`AuditAction::ChangePassword` 具名目标 principal（`domain/src/audit.rs:167, 188` 注释原文「names the principal whose credential the action replaces」）；撤销失败记 `session-revocation-failed`（`:364, 1288, 1448-1449`），不再伪装成认证失败 | `domain/src/audit.rs` |
| W3C-1 响应 DTO 拒绝未知字段（兼容方向反了） | MEDIUM | ✅ **已修复**（e768473）：响应方向不再拒绝未知字段——旧控制台包可解析富化载荷（`api/src/lib.rs:3725, 3907, 5811, 5842, 5957, 6035` 注释原文「The response direction never rejects unknown fields (W3C-1)」），兼容性声明方向与实现一致 | `api/src/lib.rs` |
| W3C-2 操作 list/detail 缺失败分类（E3-4 第三面） | MEDIUM | ✅ **已修复**（e768473）：list（`web/src/lib.rs:2737-2758`）与 detail（`:4271`）均携带持久化分类，`project_failure_kind`（`:2763`） | `web/src/lib.rs:2737-2763, 4271` |
| W3F-2 HEAD 请求绕过 GET 授权入口 | MEDIUM | ✅ **已修复**（e768473）：axum HEAD 经 GET handler 解析（`auth.rs:972` 注释原文「W3F-2: axum answers HEAD through the GET handlers」），未认证 HEAD 不再能执行 admin handler；测试区 `auth.rs:6166` | `web/src/auth.rs:972` |
| W3N-2 TTL 再投递竞态滞留中心错误判定 | MEDIUM | ✅ **已修复**（e768473）：站点把收到条目愈合成 in-progress 相位后再应答（`center_sync.rs:1189, 1240`；TTL 退休竞态注记 `:4141`），中心跟踪不再滞留错误判定 | `application/src/center_sync.rs:1189, 1240, 4141` |
| W3S-3 声明身份净化只逃逸 C0/C1 | MED-LOW | ✅ **已修复**（e768473）：净化逃逸完整 bidi 控制类（LRM/RLM U+200E/U+200F 等，`application/src/center/session.rs:112-136`，W3S-3 注释 `:136`）；测试 `declared_identity_sanitization_escapes_every_bidi_control_character`（`:1156`）、显示层 `a_hello_identity_mismatch_display_keeps_bidi_controls_escaped`（`:1187`） | `application/src/center/session.rs:112-136, 1156, 1187` |
| W3S-4 用户名预算被分布式失败锁死 | MED-LOW | ✅ **已修复**（e768473）：用户名预算只计呈现场地址（`auth.rs:117-118` 注释原文「counted per presenting address (W3S-4)」、`:1033`、`:1061-1062`），5 个分布式地址的失败不能锁死一个用户名 | `web/src/auth.rs:117-118, 1033, 1061-1062` |
| W3C-3 中心不识 failed-unsupported 前缀、不持久化分类 | MED-LOW | ✅ **已修复**（e768473）：中心识别 `failed-unsupported` 摘要前缀并在自身跟踪记录持久化分类（`center_sync.rs:1496, 1515`；站点侧汇总分类 `dispatch.rs:3736`） | `application/src/center_sync.rs:1496, 1515`；`application/src/center/dispatch.rs:3736` |
| W3F-3 bare-SQL 门禁漏括号/CTE 拼写 | MED-LOW | ✅ **已修复**（e768473）：`AS ( SELECT` 与 `AS WITH ... SELECT` 两种拼写均被门禁捕获（`bare_sql_gate.rs:362-385`，头注释 `:41-51`，测试 `:770-786`）；`AS (VALUES ...)` 残差如实登记（头注释 `:49-51`） | `migration/tests/bare_sql_gate.rs:41-51, 362-385, 770-786` |
| W3N-3 重复 offer 进度不进重放映射（重连重发陈旧进度） | MED-LOW | ✅ **已修复**（e768473）：重复 offer 应答记录进进度映射（`center_sync.rs:1192` 注释原文「state in the progress map (W3N-3)」、`:1251`；审计跟进 `:4097`），重连不再重发陈旧进度 | `application/src/center_sync.rs:1192, 1251, 4097` |
| W3S-5..10 / W3C-4/5 / W3F-4/5 / W3N-1/4/5（LOW/NOTE 组） | LOW/NOTE | ✅ **已修复**（e768473）：管理员口令路径时序均衡（`dummy_admin_derivation` `auth.rs:2607, 2681, 2806`）、限速拒绝 warn 降级与逐调用拒绝判定（`center_sync.rs`）、泛型失败下收敛计数存活（`center_sync.rs:639-641, 703-708, 5914-5918`）、proto 注释如实化（`center.proto`）、派生任务内持 permit、CI secret 作用域化到存在性旗标（`ci.yml:395, 620-626`） | `web/src/auth.rs`；`application/src/center_sync.rs`；`center-protocol/proto/rutilus/center/v1/center.proto`；`.github/workflows/ci.yml` |
| **第四波块（wave-four 对抗发现，2026-08-13，29 条）** | | | |
| V4I-1/V4R-1 审计 outcome CHECK 缺 13 码失败词汇（两透镜双确认 HIGH） | **HIGH** | ✅ **已修复**（3a23b9b）：`m20260813_000003` 重建审计表，`ck_audit_events_outcome` 携带完整十三码失败词汇（`m20260813_000003_audit_failure_vocabulary.rs:317, 450`），session-revocation-failed / capability-unsupported 事件不再被 CHECK 静默拒绝；域-CHECK 双向绑定测试 `full_failure_vocabulary_and_target_principal_persist_foreign_shapes_are_refused` 钉死不再漂移 | `migration/src/m20260813_000003_audit_failure_vocabulary.rs`；`migration/tests/audit_failure_vocabulary.rs` |
| V4P-1 操作历史每行 N+1 事务 | MED-HIGH | ✅ **已修复**（3a23b9b）：`list_operations_classified` 单查询带失败分类（`persistence/src/operation_repository.rs:639`，测试 `:1565`），store 与 StandaloneState 双接线 | `persistence/src/operation_repository.rs:639, 1565` |
| V4P-2 中心跟踪视图逐端点查询 + offer 扫描无界 | MEDIUM | ✅ **已修复**（3a23b9b）：涉及端点一次 `IN` 查询解析（`app/src/center_runtime.rs:477, 514` 注释原文 V4P-2），offer 扫描界到最新窗口（`persistence/src/center_outbox_repository.rs:264, 651`） | `app/src/center_runtime.rs:477, 514`；`persistence/src/center_outbox_repository.rs:264, 651` |
| V4P-3 offer 历史回退读无界（单候选路径） | MEDIUM | ✅ **已修复**（3a23b9b）：单候选回退读有界（`dispatch.rs:436-437, 549, 566`）——安全因重试复用既有 id、站点吸收重复；多候选路径刻意保持无界（截断会铸新 id 双执行，注释原文） | `application/src/center/dispatch.rs:436-437, 549, 566` |
| V4I-2 三个中心响应信封拒绝未知字段 | MEDIUM | ✅ **已修复**（3a23b9b）：三信封响应方向不再拒绝未知字段（`api/src/lib.rs:5811, 5842, 5957, 6035` 注释原文），与 W3C-1 声称一致；§15.5 凭据边界保留在端点视图条目 | `api/src/lib.rs:5811, 5842, 5957, 6035` |
| V4R-2 改密成功不保留限速预留（每请求双派生循环） | MEDIUM | ✅ **已修复**（3a23b9b）：改密成功保留其预留槽（`auth.rs:29` 注释原文「a successful change keeps its reserved slots (V4R-2)」、`:1001, 1099, 1134`），凭据持有者不能再每请求循环两次派生 | `web/src/auth.rs:1001, 1099, 1134` |
| V4R-3 审计目标 principal 未持久化 | MEDIUM | ✅ **已修复**（3a23b9b）：`target_principal_id` 列 + 形状 CHECK（`m20260813_000003_audit_failure_vocabulary.rs:328, 351-352`，`ck_audit_events_target_principal`），持久轨迹具名被替换凭据者 | `migration/src/m20260813_000003_audit_failure_vocabulary.rs:328, 351-352` |
| V4S-2/V4R-4 FailureKindResponse 无容错 fallback | MED-LOW/LOW | ✅ **已修复**（3a23b9b）：`#[serde(other)]` fallback（`api/src/lib.rs:3558, 6093`），未来词汇扩展保持旧控制台可解析 | `api/src/lib.rs:3558, 6093` |
| V4S-3/V4R-8 管理 404 分支无哑派生 / 管理改密无预算 | MED-LOW/LOW | ✅ **已修复**（3a23b9b）：三个管理 404 分支均跑哑派生（`dummy_admin_derivation` `auth.rs:2607, 2681, 2806`），管理改密路径带 change-password 预算 | `web/src/auth.rs:2607, 2681, 2806` |
| V4S-5/V4R-6 failed-unsupported 前缀无边界匹配 | MED-LOW/LOW | ✅ **已修复**（3a23b9b）：前缀匹配要求边界（精确或冒号分隔，`center_sync.rs:1496-1515`） | `application/src/center_sync.rs:1496, 1515` |
| V4R-5 退款弹错地址条目 | LOW | ✅ **已修复**（3a23b9b）：退款恰好弹出呈现场地址条目（`auth.rs:1137, 1243` 注释原文「the presenting address recorded (V4R-5) — never another」） | `web/src/auth.rs:1137, 1243` |
| V4R-7 重绑端点永久冻结 | LOW | ✅ **已修复**（3a23b9b）：前站点绑定被撤销后重绑端点自愈重归位（`binding.rs:30, 763` 注释原文 V4R-7） | `application/src/center/binding.rs:30, 763` |
| V4I-3/4 门禁 pin 重测 | LOW | ✅ **已修复**（3a23b9b）：门禁 pin 重测为实测值（secret leak gate 10 测试、migration 50 测试） | `security/tests/secret_leak_gate.rs`；`migration/tests/` |
| V4I-6 TODO 措辞 | NOTE | ✅ **已修复**（3a23b9b）：TODO 措辞如实化 | — |
| V4P-4..7 / V4S-1/6（修复归属未来边界） | LOW/NOTE | ✅ 已登记（3a23b9b）：修复归属未来边界处如实登记，不冒充已修复 | — |
| **第五波块（wave-five 对抗发现，2026-08-13，25 条）** | | | |
| V5A-1 执行审计 CHECK 冻结 17 个写家族（audit 拒 start 事件 → 每 tick 永远重试） | **HIGH** | ✅ **已修复**（e85560a）：`m20260813_000004` 把执行审计 CHECK 扩至全部 31 码（`m20260813_000004_audit_operation_vocabulary.rs:393` `ck_audit_events_action`、`:477` `ck_audit_events_outcome`），被冻结家族恢复审计并执行；编译钉死词汇绑定测试 `operation_vocabulary_binds_the_domain_matrix_and_persists` | `migration/src/m20260813_000004_audit_operation_vocabulary.rs`；`migration/tests/audit_operation_vocabulary.rs` |
| V5A-2 持久审计表无生产读面（重启丢历史） | **HIGH** | ✅ **已修复**（e85560a）：控制台审计尾启动时从存储预热（`warm_audit_tail` `standalone_runtime.rs:506`、启动调用 `:1757`、重启回填测试 `:3512`），失败回退有界持久化列表（`:498`；`persistence/src/audit_repository.rs:99`） | `app/src/standalone_runtime.rs:498, 506, 1757, 3512`；`persistence/src/audit_repository.rs:99` |
| V5A-3 执行审计归因不随姿态/操作来源 | **HIGH** | ✅ **已修复**（e85560a）：归因随姿态与操作来源——Site 执行记 Site/local-operator（控制台提交）或 System/Site（中心派发）（`operation_executor.rs:676, 692` `execution_attribution`） | `application/src/operation_executor.rs:676, 692` |
| V5E-1 端点删除后终态回执不计入（操作不可见永不终态） | **HIGH** | ✅ **已修复**（e85560a）：回执计分回退持久 offer 事实（`dispatch.rs:857, 954, 1023, 1063` 注释原文 V5E-1；投影与 offer 事实双缺失时如实不记 `:3530`，测试 `a_reply_is_recorded_but_never_credited_when_the_offer_history_is_gone_too` `:3528`） | `application/src/center/dispatch.rs:857, 954, 1023, 1063, 3528` |
| V5E-2 绑定不拒在效前绑定（revoke-before-rebind 排序失守） | **HIGH** | ✅ **已修复**（e85560a）：指纹仍持 `Bound` 前绑定的重绑被拒（`binding.rs:604, 706-710, 758-785`，revoke-before-rebind 排序，模块文档 `:22-34`） | `application/src/center/binding.rs:22-34, 604, 706-710, 758-785` |
| V5C-1 TOTP 列表失败静默降级为仅口令 | MEDIUM | ✅ **已修复**（e85560a）：TOTP 列表失败 fail-closed（`auth.rs:1809` 注释原文「the sign-in fails closed (V5C-1) instead of falling back」、`:1813`），存储错误不再把登录静默降级为仅口令 | `web/src/auth.rs:1809-1813` |
| V5C-2 bootstrap 认领无限速预算 | MEDIUM | ✅ **已修复**（e85560a）：认领携带登录同形预算（`bootstrap_limiter` `auth.rs:1004-1011` 注释原文 V5C-2），认领洪泛被窗口预算界住；429 拒绝不写审计（B2 同款） | `web/src/auth.rs:1004-1011` |
| V5A-4 终态审计追加失败静默丢失 | MEDIUM | ✅ **已修复**（e85560a）：失败追加入有界补偿队列（`AUDIT_COMPENSATION_EVENTS = 256` `standalone_runtime.rs:97`、进程级队列 `:109`），后台 drain 重试（`:432-448, 573-578`） | `app/src/standalone_runtime.rs:89-109, 432-448, 573-578` |
| V5A-6 审计尾镜像毒化静默丢事件 | MEDIUM | ✅ **已修复**（e85560a）：毒化镜像回退持久化列表（`standalone_runtime.rs:436, 479, 514, 542` 注释原文 V5A-6），不再静默丢事件 | `app/src/standalone_runtime.rs:436, 479, 514, 542` |
| V5A-7 tls-trust-failed / csv-invalid 无生产者 | LOW | ✅ **已修复**（e85560a）：两条失败码现在有生产者（`web/src/lib.rs:1848-1862` TLS 指纹拒绝记 `tls-trust-failed`、`:1908-1929` CSV 畸形记 `csv-invalid`；路由测试 `:13315, :13429`） | `web/src/lib.rs:1848-1862, 1908-1929, 13315, 13429` |
| V5A-9 中心拒绝码不稳定 / handler 侧 403 不审计 | MEDIUM | ✅ **已修复**（e85560a）：§15.6 拒绝携带稳定 wire 码（`api/src/lib.rs:6065, 6097`），handler 侧 403 记审计（`web/src/lib.rs:4105, 4172, 13226, 13241`） | `api/src/lib.rs:6065, 6097`；`web/src/lib.rs:4105, 4172, 13226, 13241` |
| V5E-3 归属吸收事件静默消失 | MEDIUM | ✅ **已修复**（e85560a）：归属吸收记录以持久死信行落地（`projection.rs:65-74, 784-798, 841-879`），游标推进前先落死信、不静默丢 | `application/src/center/projection.rs:65-74, 784-798, 841-879` |
| V5E-4 CenterOperationResponse 缺 failure_kind（W3C-3 wire 侧） | MEDIUM | ✅ **已修复**（e85560a）：`failure_kind` 上 wire（`api/src/lib.rs:5859, 5937`；跟踪视图投影 `web/src/lib.rs:387, 434, 4257, 13499`），视图折叠点保持登记 | `api/src/lib.rs:5859, 5937`；`web/src/lib.rs:387, 434, 4257, 13499` |
| V5E-5 重绑不清亡实例在途 offer | MEDIUM | ✅ **已修复**（e85560a）：重绑退休亡实例待发 offer（`retire_site_offers` `binding.rs:783-785, 807`，模块文档 `:33-34`） | `application/src/center/binding.rs:33-34, 783-785, 807` |
| V5C-4 改密 401 不审计 | LOW | ✅ **已修复**（e85560a）：改密 401 分支记录审计（`auth.rs:2155, 2210, 2243` 注释原文 V5C-4，测试区 `:5750-5758`） | `web/src/auth.rs:2155, 2210, 2243` |
| V5C-5 TOTP 未来窗口行为未钉死 | LOW | ✅ **已修复**（e85560a）：未来窗口接受行为钉死并文档化（`domain/src/totp.rs:13-15, 211-214, 398-405` 注释原文 V5C-5） | `domain/src/totp.rs:13-15, 211-214, 398-405` |
| V5C-6 observed_at 不记接收时间 | LOW | ✅ **已修复**（e85560a）：事件 `observed_at` 如实记录接收时间、与事件时间两时钟分离（`projection.rs:25, 1310, 2743, 2779` 注释原文 V5C-6） | `application/src/center/projection.rs:25, 1310, 2743, 2779` |
| V5M-1..4 / V5A-10（词汇绑定 / 字节级 down / 下迁可观测 / actor 钉死） | LOW/NOTE | ✅ **已修复**（e85560a）：穷举词汇绑定（`migration/tests/audit_operation_vocabulary.rs` 4 测试：`operation_vocabulary_binds_the_domain_matrix_and_persists` / `operation_rebuild_preserves_existing_audit_rows` / `down_refuses_new_codes_with_migration_context_and_preserves_representable_rows` / `down_restores_the_000003_shape_byte_for_byte`，实测 `cargo test --workspace -- --list`）、字节级 down 恢复检查（`down_restores_the_000003_shape_byte_for_byte`，备份快照字节精确语义 `persistence/src/backup_snapshot.rs:52-83`）、下迁可观测性、target-principal CHECK 钉死 actor（`m20260813_000004_audit_operation_vocabulary.rs:362`） | `migration/tests/audit_operation_vocabulary.rs`；`persistence/src/backup_snapshot.rs`；`migration/src/m20260813_000004` |
| CI wasm 产物新鲜度门禁（第五轮 CI 附带修复） | — | ✅ **已修复**（e85560a）：构建 remap 宿主机路径（`ci.yml:381-387`）、比较归一化分隔符、显式安装 rust-src（`:317`）、失配上传 CI 生成产物供取证（`:341`）；宿主机工具链三元组残差如实登记（下次 ubuntu 运行按设计红一次） | `.github/workflows/ci.yml:311-341, 381-387` |
| **第六波块（wave-six 对抗发现，2026-08-14，58 条 → 48 confirmed + 3 partial + 3 refuted）** | | | |
| R6-C-1 并发双派发铸双 id 双执行 | **HIGH** | ✅ **已修复**（fcf7257）：dispatch 幂等原为 check-then-act——两个并发相同派发各铸一个 operation id，站点同写两次。修复：`StandaloneState` per-site `dispatch_gates`（`app/src/standalone_runtime.rs:307-313`），`dispatch_center_operation` 把绑定检查→find_undecided→create_operation→enqueue_offer 整体纳入同一临界区（`app/src/center_runtime.rs:472-515`）。测试 `two_concurrent_identical_dispatches_create_one_operation`（`center_runtime.rs:1566`）钉死同一 id + 恰 1 条非终态操作 | `app/src/standalone_runtime.rs:307-313`；`app/src/center_runtime.rs:472-515, 1566` |
| R6-E-01 Unknown 后重派发铸新 id 逃过 inbox 去重 | **HIGH** | ✅ **已修复**（fcf7257）：`CenterDispatchError::UnknownOutcomePending { operation_id }`（`application/src/center/dispatch.rs:283-300`）——find_undecided 无候选后检查同 (site, endpoint, command) 的终态 Unknown 操作（站点经 outbox 定向行确认，防 re-home 误伤），存在则类型化拒绝且不铸新 id（`dispatch.rs:389-397, 655-697`）。测试 `a_retry_after_an_unknown_outcome_is_refused_with_the_existing_operation_id`（`:3978`） | `application/src/center/dispatch.rs:283-300, 389-397, 655-697, 3978` |
| R6-C-2 重绑 TOCTOU | MEDIUM | ✅ **已修复**（fcf7257）：`bind_with_code` 事务内追加复查——同 `site_cert_fingerprint` 且 `state='bound'` 且 id≠本行 → 回滚 + `FingerprintAlreadyBound`（`persistence/src/center_binding_repository.rs:194-223, 423-426`）；revoked 行不阻塞同站重绑。测试 `bind_refuses_a_fingerprint_already_bound_to_another_registration`（`:683`） | `persistence/src/center_binding_repository.rs:194-223, 423-426, 683` |
| R6-E-02 吊销站可派发 | MEDIUM | ✅ **已修复**（fcf7257）：dispatch 临界区内检查 binding 状态，非 Bound → 类型化拒绝（web 层照常审计 Refused 结局）（`app/src/center_runtime.rs:489-503`）；`list_center_endpoints` 过滤绑定不在效站点的投影端点（`:343-381`）。测试 `dispatch_to_a_revoked_site_is_refused_and_the_revocation_ends_the_session`（`:1606`） | `app/src/center_runtime.rs:343-381, 489-503, 1606` |
| R6-E-03 re-home 后回执被拒、操作永久 Running | MEDIUM | ✅ **已修复**（fcf7257）：`offer_site` 在投影与回执站点不一致时走 `offer_site_from_offer_facts`（按 operation_id 定向查询）确认，回执站队列持 offer 即授信；两侧都不同意才拒绝（`application/src/center/dispatch.rs:1103-1140`）。测试 `a_reply_from_the_original_site_credits_after_the_endpoint_was_re_homed`（`:4052`） | `application/src/center/dispatch.rs:1103-1140, 4052` |
| R6-E-04 outbox 无剪枝 + O(N) 解密 | MEDIUM | ✅ **已修复**（fcf7257）：新迁移 `m20260814_000001_center_outbox_operation_ids`（`center_outbox` 加 plaintext `operation_id` 列 + `ix_center_outbox_instance_operation` 索引；down 删索引/删列）；插入时从同条 payload 解析写入（`center_outbox_repository.rs:93-100, 132-140`）；`ack_outbox_entry` 剪枝同 operation 的其他 acked 行保留最新一条（`:380-393, 590-620`）；resolve_candidate 与 offer 事实回退改定向查询（`dispatch.rs:602-615, 1122-1140`）；迁移前 NULL 行惰性回填（`:420-477`，F1 双执行防护跨升级成立） | `migration/src/m20260814_000001`；`persistence/src/center_outbox_repository.rs:93-140, 331-477`；`application/src/center/dispatch.rs:602-615` |
| R6-C-3 优雅停机丢弃整条补偿队列 | MEDIUM | ✅ **已修复**（fcf7257）：停机两分支在 join drain 任务前先做有界最终排空 `drain_audit_compensation_final`——循环排空至队列空或 2s 预算耗尽（`AUDIT_COMPENSATION_FINAL_DRAIN_TIMEOUT`），耗尽时 warn 携带剩余条数（`app/src/standalone_runtime.rs:2651-2682, 2366, 2386`） | `app/src/standalone_runtime.rs:2651-2682, 2366, 2386` |
| R6-S-1 会话撤销 fail-open | MEDIUM | ✅ **已修复**（fcf7257）：`SessionRevocation::{Revoked, NotFound, AlreadyRevoked}` 三态边界结果（`web/src/auth.rs:339, 370`）——Revoked/AlreadyRevoked→200 + ManageSessions 审计（幂等成功），NotFound→404 不审计，存储类失败→500 + 失败审计事件（仿 B3 纪律，`auth.rs:2617-2660`；运行时分类映射 `app/src/standalone_runtime.rs:801-820`）。测试 `revoke_session_surfaces_a_storage_failure_as_500_with_audit`（`web/src/lib.rs:12817`）等三枚 | `web/src/auth.rs:339, 370, 2617-2660`；`app/src/standalone_runtime.rs:801-820` |
| R6-W-1/W-2 wasm 门禁 known-red + tr 整文件掩蔽 0x5C/0x2F 字节差 | MEDIUM | ✅ **已修复**（fcf7257）：ci.yml 曾自述「下一次 ubuntu 运行必红、triple 归一化计划下一迭代」——现为目标化 python3 变换：`1.97.1-<host-triple> -> 1.97.1-toolchain`（覆盖 `.cargo-home` 与 rustup 路径类）+ 目标化 `\`→`/` 归一（仅登记的两类路径段：`.cargo-home` 段、`ui\src`/`ui/src` 前缀段；1368 个 0x5C 字节中 946 个代码段 LEB128 不再触碰）；注释如实描述归一化仅覆盖已登记路径类；合成 ubuntu 侧副本收敛字节一致，**真实 ubuntu 收敛待下一次 CI 实跑**（已如实标注） | `.github/workflows/ci.yml`（Build wasm32 UI artifact 步骤注释与变换代码） |
| R6-W-3 伪造 center 归因（R6-E-11 链式前项） | MEDIUM | ✅ **已修复**（7c6ac9d）：`create_operation` 服务端 pin——HTTP 控制台面只接受 `standalone`/`site`（Site 姿态提交 `site`、Standalone 姿态提交 `standalone`，缺省 `standalone`），`center` 是中心 offer 流保留源，wire 串一律 400 拒绝且不落库（`web/src/lib.rs:2312-2323`）；`project_operation_source` 只读侧不变（`:2923-2927`）。测试 `accepts_an_explicit_operation_source`（`web/tests/operation_path.rs:1168`）：standalone/site → 201、`center` → 400；inbox 污染半边 refuted | `web/src/lib.rs:2312-2323, 2923-2927`；`web/tests/operation_path.rs:1168` |
| R6-W-6 制品无大小上限（R6-E-11 链式前项） | MEDIUM | ✅ **已修复**（7c6ac9d）：`ARTIFACT_MAX_SIZE_BYTES = 2 GiB`（服务器 BMC 固件实际至多数百 MiB，留一个数量级余量；cap 是 create 时的声明总大小约束——4 MiB wire 上限管单请求、`ChunkExceedsSize` 管累计不超声明，两层合起来累计永不超 cap）（`application/src/artifact_store.rs:66-76`）；`size_bytes == 0`（既有 `ZeroSize`）与超限（新 `SizeExceedsLimit`）都拒绝（`:242-252`）；web create 映射 400（`web/src/lib.rs:2565-2568`）。测试 `create_refuses_a_declared_size_above_the_artifact_cap`（`artifact_store.rs:1023`）、`chunks_at_the_cap_boundary_stay_bounded_by_the_declared_size`（`:1068`） | `application/src/artifact_store.rs:66-76, 242-252, 1023, 1068`；`web/src/lib.rs:2565-2568` |
| R6-E-11 审计历史超内存尾不可达（R6-E-11 链式前项） | MEDIUM | ✅ **已修复**（7c6ac9d）：`GET /api/v1/audit` 解析 `offset`（非负、缺省 0、上限 `AUDIT_QUERY_MAX_OFFSET = 10_000_000`，重复参数拒绝）（`web/src/lib.rs:2141-2171, 1693-1698, 3422-3478`）；`offset == 0` 走内存尾、`offset > 0` 走 `list_recent_events_with_offset`（store 有界列表，fail-closed 503 不变）；响应加 `has_more`（`api/src/lib.rs:2831-2871`，`#[serde(default)]` + 响应方向不拒未知字段）；UI AuditView 加「加载更早」按钮（`ui/src/lib.rs:4452-4524, 14960-14976`，双语 `i18n.rs:233, 1635-1636`）。测试 `pages_the_audit_history_with_an_offset`（`web/tests/write_path.rs:1421`）、`audit_paging_appends_older_pages_and_tracks_the_next_offset`（`ui/src/lib.rs:21611`） | `web/src/lib.rs:2141-2171`；`api/src/lib.rs:2831-2871`；`ui/src/lib.rs:4452-4524, 14960-14976` |
| R6-S-3 secret-gate 标识符集缺口 | MEDIUM | ✅ **已修复**（fcf7257）：`SENSITIVE_IDENTIFIERS` 加入 `binding_code`；`SENSITIVE_IDENTIFIER_SUFFIXES` 无条件加入 `_pwd/_passwd/_pw/_passcode`；`_key/_pin` 按误报张力单独登记（`TENSION_IDENTIFIER_SUFFIXES`，仅绑定非空字面量触发 [R1]、不进 [R3] 日志集）；`_key` 后缀新增命中的 5 个生产常量进 `ALLOWED_CONSTANT_HITS`（2→7 条，path+line+name+value 绑定）（`security/tests/secret_leak_gate.rs:517-601`）。测试 `binding_code_and_new_compound_suffixes_are_flagged`（`:1853`） | `security/tests/secret_leak_gate.rs:517-601, 1853` |
| R6-D-1 down_order_gate 多语句 DROP 漏剥分号 | MEDIUM | ✅ **已修复**（fcf7257）：`sql_identifier` 先 trim 空白、剥引号/括号、再 `trim_end_matches(';')`；`drop_table_names` 按 `;` 切分（兼容 `parents;DROP` 粘连形态），空段丢弃（`migration/tests/down_order_gate.rs:268, 279`）。自检 `gate_checks_multi_statement_raw_drops_separated_by_semicolons`（`:1276`），门禁现 13 自检 | `migration/tests/down_order_gate.rs:268, 279, 1276` |
| R6-A1 接线（A1 区域新变体，A6 收口） | MEDIUM | ✅ **已修复**（7c6ac9d）：`CenterOperationRefusal` 新增 `SiteBindingRevoked` 与 `UnknownOutcomePending { operation_id }`（`web/src/lib.rs:621-624`）；`CenterOperationRefusalCode` 稳定码 `site_binding_revoked`/`unknown_outcome_pending`（`api/src/lib.rs:6109-6113`，`serde(other)` 兜底不变）；两变体均映射 **409 Conflict**——refusal 家族里 403 保留给 actor 授权判定、422 保留给 body 引用未知，吊销绑定与未决 unknown 是「判定而非授权」状态（`web/src/lib.rs:4269-4327`）；`center_runtime.rs` 两个 `TODO(R6-A6)` 临时映射替换为类型化变体（`app/src/center_runtime.rs:500-507, 541-548`）。测试 `the_site_binding_and_unknown_outcome_refusals_map_to_conflict_with_stable_codes`（`web/src/lib.rs:13743`） | `api/src/lib.rs:6109-6113`；`web/src/lib.rs:621-624, 4269-4327, 13743`；`app/src/center_runtime.rs:500-507, 541-548` |
| R6-C-4/R6-C-7/R6-5/R6-4 补偿队列批次（僵尸条目 / 排水吞吐 / 驱逐可观测 / warm-up 真实验证） | LOW/NOTE | ✅ **已修复**（fcf7257）：① `append_audit_event` 幂等分支（trail 末事件 id 相同 → `Ok(())` 不插入，`persistence/src/audit_repository.rs:59-67`；镜像同步去重 `app/src/standalone_runtime.rs:603-613`）；② drain 对域校验类错误分类为不可重试（error! 点名 event_id/action、不再入队），仅瞬时性错误保留重试（`standalone_runtime.rs:1788-1812, 653-712`）；③ 排水每 tick 批量排空至队列空或连续 8 次失败（`standalone_runtime.rs:653-712, 107`）；④ 满队驱逐 warn + `AUDIT_COMPENSATION_EVICTIONS` 计数（`:731-749, 128, 719-722`）；⑤ warm-up 旗标生产路径真实注入验证（`:3783-3850`）。测试：`reappending_the_trail_terminal_event_is_idempotent`（persistence:815）、`a_permanently_invalid_queued_append_is_dropped_not_requeued`（app:3931）、`one_drain_pass_replays_the_whole_queued_batch`（app:4033）、`a_corrupt_persisted_row_warms_the_tail_into_the_failed_state`（app:3783） | `persistence/src/audit_repository.rs:59-67`；`app/src/standalone_runtime.rs:603-712, 731-749, 1788-1812, 3783-3850` |
| R6-S-12 死代码 run_standalone | NOTE | ✅ **已修复**（fcf7257）：删除 `run_standalone`（`AuthPolicy::Open` 旧控制台路径）及其 `pub use`，全仓 grep 零调用方（`run_initialized_standalone`/`run_background_services` 为唯一运行路径） | `app/src/standalone_runtime.rs`（删除区段）；`app/src/lib.rs:53-57`（pub use 移除） |
| R6-D-4 补偿队列限制（基线即存在，仅登记） | NOTE | ✅ 已登记（fcf7257）：补偿队列纯内存（无持久 outbox，crash/停机时未重试成功的事件丢失——语义是进程存活期内尽力重试，R6-C-3 把停机丢失从整队丢弃缩小到预算内尽力排空）；256 上限丢最旧；drain 间隔 30s；幂等前提以「同 id 即视为已落盘」为契约（同 id 不同内容重发会静默视为已应用） | `app/src/standalone_runtime.rs:89-97`；本表本行 |
| R6-E-06/E-08/R6-C-6 协议面批次（进度折叠 / 未知回执吸收 / 退役竞态） | LOW/NOTE | ✅ **已修复**（fcf7257）：① `reply_target` 解析 wire `OperationProgress.state`，`waiting-remote` → `ReplyTarget::WaitingRemote`（`application/src/center/dispatch.rs:788-796, 1344-1358`）；② `on_reply` 对不可解析 id / 找不到操作的回复先写吸收型回执行（envelope 原样入库、id 用确定性 UUIDv5 派生键）再 warn+Ok（`:950-995, 1178-1198, 1271-1302`）；③ `CenterSessionRegistry` per-site disconnect 信号（Notify 语义竞态不丢唤醒），撤销成功后踢除并触发信号（`application/src/center/session.rs:305-311, 377-410`；`app/src/center_runtime.rs:449-456, 1037-1076`） | `application/src/center/dispatch.rs:788-1358`；`application/src/center/session.rs:305-410, 1340, 1373`；`app/src/center_runtime.rs:449-456, 1037-1076` |
| R6-S-2/S-8/S-9/S-10/S-13/W-4/W-9/R6-C-5 认证/限速面批次 | LOW/NOTE | ✅ **已修复**（fcf7257）：① 双重 Set-Cookie——logout/change-password 的清除头不再被续期头覆盖（`web/src/auth.rs:1494-1508`）；② bootstrap 未知主体分支补审计（`:2136-2146`）；③ 用户名限速键归一化投影（trim + lowercase + 截断，`:1404-1427`）；④ admin 404 分支（set_user_state/assign_user_role）挂 password-change 同形预算（`:2770-2810, 2875-2915`）；⑤ `me` 的 bootstrap 闸读失败倒向「claim 待定」而非「产品已开放」（`:2509-2519`）；⑥ IPv4-mapped 地址归一化防双桶（`:1682-1698`）；⑦ `me` 挂轻量 per-IP 查询限速（`ME_IP_QUERY_LIMIT = 60`，`:143-147, 1041-1056, 2488-2519`）；⑧ refund token 精确化（PARTIAL：桶条目铸 token、refund 按 token 精确删除，同地址并发交错不再身份互换，`:1134-1364`）。测试：`logout_and_password_change_carry_exactly_one_set_cookie`（web/src/lib.rs:12989）、`rate_limiter_username_key_normalizes_case_and_whitespace`（auth.rs:4609）、`admin_state_and_role_404_floods_are_rate_limited`（web/src/lib.rs:13046）、`me_answers_claim_pending_when_the_bootstrap_read_fails`（auth.rs:5638）、`request_ip_normalizes_ipv4_mapped_addresses`（auth.rs:4137）、`me_answers_429_under_a_per_address_query_flood`（web/src/lib.rs:13106）、`rate_limiter_refund_conserves_the_count_under_concurrent_interleaving`（auth.rs:4427） | `web/src/auth.rs:143-147, 1134-1364, 1404-1427, 1494-1508, 1682-1698, 2136-2146, 2488-2519, 2770-2915, 4137-4609`；`web/src/lib.rs:12989, 13046, 13106` |
| R6-S-4/S-5/S-6/S-7/A4-B1/S-11 secret-gate 与 master-key 批次 | LOW/NOTE | ✅ **已修复**（fcf7257）：① PEM 转义击穿——`parse_plain_string` 完整转义解码（`\xNN`/`\u{...}`/续行等），content 与编译值一致（`secret_leak_gate.rs:306-339`）；② `print!`/`eprint!` 入输出宏集（3→5，`:654`）；③ const/static 链与方法调用形态盲区如实登记（头文档 `:43-50`）；④ concat! 片段规则改跨片段三元组判定（BEGIN+END+PRIVATE KEY 三片齐备即报 [R2]，不论绑定名，`:1132`）；⑤ tokenizer 两机械缺陷——`b'x'` 字节字符字面量整字面量消费 + 多行 raw 字符串/续行换行计数补偿（报点行号恢复真实源行，`:273-296, 339, 497`）；⑥ master-key KDF 对齐产品基线（64 MiB/3 趟/1 并行，`security/src/master_key.rs:447-497`），信封魔数升版 `RUTMK001→RUTMK002`，旧版信封仍可解锁且解锁后经 `rewrap_master_key` 迁移重保护落盘（`MasterKeyFile::replace` 原子替换，`platform/src/master_key_file.rs:97`）。测试：`escaped_pem_literals_are_flagged_after_escape_decoding`（gate:2025）、`byte_char_literals_do_not_derail_the_tokenizer`（gate:2085）、`multi_line_literals_do_not_drift_reported_lines`（gate:2066）、`concat_format_fragments_with_pem_material_are_flagged`（gate:2122）、`legacy_v1_envelope_unlocks_and_rewraps_to_the_current_format`（master_key.rs:965）；门禁现 15 测试 | `security/tests/secret_leak_gate.rs:273-339, 497, 517-654, 1132, 1853-2221`；`security/src/master_key.rs:16-21, 225-250, 447-497, 965`；`platform/src/master_key_file.rs:97, 315` |
| R6-W-7/W-8/R6-8 CI 面批次（floor 掏空 / 无 ran-断言 / deny unmatched-skip） | LOW/NOTE | ✅ **已修复**（fcf7257）：① `assert-tests-ran.sh` 新增 `--expect-tests name1,name2,...`——不只计数，断言关键测试名存在且运行（`#[ignore]` 视为未运行），secret gate 传入 4 名、migration 传入 down_order_gate 6 名；② Capability ledger / Release baseline / workspace Test 三步全改走 `assert-tests-ran.sh <pin>`（pin 为本机实测 295/14/1913），五步 ran-断言全覆盖；③ cargo-deny 加 `command-arguments: --deny warnings`，8 条不可达 skip 条目删除（保留即 warning 恒在必红；`cargo tree --workspace --target all --all-features -i` 核实不可达；删后可达即需复核语义由 multiple-versions 承接） | `scripts/assert-tests-ran.sh`；`.github/workflows/ci.yml`；`deny.toml` |
| R6-D-2/D-3/D-5/D-6/D-7/D-8 数据面批次 | LOW/NOTE | ✅ **已修复**（fcf7257）：① backup_snapshot `NewerSchema` 计数硬编码改 `Migrator::migrations().len()` 动态派生（`persistence/src/backup_snapshot.rs:943-944, 983-985`）；② 000004 up 补对称预检（`action='change-password' AND target_principal_id IS NOT NULL AND actor <> 'user'` 遗留行具名拒绝，`migration/src/m20260813_000004_audit_operation_vocabulary.rs:158-191`）；③ restore 非原子——`<db>-restore-pending` 侧车记录指纹，下次 open 校验，混合对以 `RestoreInterrupted` 拒绝（`persistence/src/backup_snapshot.rs:208-324`、`persistence/src/lib.rs:209, 318`）；④ dead-letter 构造失败路径补 error 日志（`application/src/center/projection.rs:866, 878, 1410`；无界性登记为残余）；⑤ `Center.` 命名空间保留给中心自身 dead-letter，中心接收端拒绝站点上报该前缀（`projection.rs:1337`）；⑥ 词表测试锚定改约束名区间定位防静默漂移（`migration/tests/audit_operation_vocabulary.rs:148`）。测试：`an_interrupted_restore_is_refused_at_the_next_open`（backup_snapshot.rs:730）等三枚、`up_refuses_target_principal_under_non_user_actor_with_migration_context`（audit_operation_vocabulary.rs:389）、`events_reporting_the_reserved_center_namespace_are_refused`（projection.rs:3098） | `persistence/src/backup_snapshot.rs:208-324, 941-944`；`persistence/src/lib.rs:209, 318`；`migration/src/m20260813_000004_audit_operation_vocabulary.rs:158-191`；`application/src/center/projection.rs:866-1410, 3098`；`migration/tests/audit_operation_vocabulary.rs:148, 389` |
| **第七波块（wave-seven 对抗发现，2026-08-14，27 confirmed + 4 refuted + 3 partial）** | | | |
| W7-E-1 WaitingRemote 后 Succeeded 回执被吸收、中心操作永久卡死 | **HIGH** | ✅ **已修复**（a0b2bc0）：`ReplyTarget::Succeeded.events()` 的 lead-in 缺 `RemoteTaskCompleted`——从 WaitingRemote 出发四事件全部 InvalidTransition 被 `let _` 吸收（站点真实行为：WaitingRemote 发 `progress{state:"waiting-remote"}`、Task 成功后发 `OperationCompleted{succeeded:true}`）。修复：lead-in 在 `ExecutionAccepted` 前插入 `RemoteTaskCompleted`（从 WaitingRemote 走既有合法路径 WaitingRemote→(RemoteTaskCompleted)→Verifying→(VerificationPassed)→Succeeded；从 Running/Queued/Validating 出发该事件无效被吸收、其余照旧）。测试 `a_succeeded_report_closes_a_waiting_remote_record`（dispatch.rs:4292）、`a_failed_report_closes_a_waiting_remote_record`（:4364） | `application/src/center/dispatch.rs:866-881`；`domain/src/operation.rs:306-316` |
| W7-S-1 中心侧制品流完全无 2 GiB 封顶 | **HIGH** | ✅ **已修复**（a0b2bc0）：R6-W-6 的 cap 只加在站点侧 Web 面，中心侧整链（decode_manifest→declare_center_artifact→consume_artifact_chunk→write_chunk_at）无任何累计约束，受信站点可无限填满中心磁盘且 Uploading/Failed 文件永久留盘。修复：`decode_manifest` 对 `total_bytes > ARTIFACT_MAX_SIZE_BYTES` 拒绝，走既有 decode 失败吸收惯例（warn + 光标推进，行不创建、文件不落盘）；声明被 cap 界住后 chunk 累计由既有 `end <= size_bytes` 检查界住（与站点侧两层语义一致）。测试 `an_over_cap_manifest_is_absorbed_without_a_row`、`an_exactly_cap_manifest_is_accepted`（projection.rs tests） | `application/src/center/projection.rs:1453` |
| W7-P-1 per-site 闸门内 5 次全局扫描串行化 | **HIGH** | ✅ **已修复**（a0b2bc0）：`find_undecided` 逐候选态 `list_operations(Some(state))` 全表列出并逐行 XChaCha20 解密，加两次全局写锁全部在闸门内——单 site 派发成本随全局在飞操作数线性增长。修复：新 repository 方法 `list_operations_for_endpoint(state, endpoint_id)`——先经 `operation_targets` 的 endpoint 索引（新建 `ix_operation_targets_endpoint`，`m20260814_000003`）取 id 集再按 id 取行；`OperationStore` trait 加默认方法；find_undecided 与 find_unknown_outcome 的 5+1 次扫描全部换用。测试 `list_operations_for_endpoint_filters_by_endpoint_in_acceptance_order`（operation_repository.rs:1637） | `persistence/src/operation_repository.rs:644-702`；`operation-engine/src/operation_store.rs:185-204, 320-326`；`application/src/center/dispatch.rs:462-476, 681-687` |
| W7-F-1 = W7-E-2 ack 剪枝无实例隔离、拆除 R6-E-01/R6-E-03 证据面 | MEDIUM | ✅ **已修复**（a0b2bc0）：剪枝的 keeper 与 delete 只有 OperationId + State=="acked" + Id.ne(keeper)，而 sequence 每实例独立分配——re-home 同 id 双站形态下 B 的 ack 删掉 A 的 acked 证据行。修复：`ack_outbox_entry` 把本行 instance_id 传进剪枝，keeper 按 (InstanceId, OperationId, acked) 取最新、delete 加实例过滤。测试 `ack_pruning_is_scoped_to_the_acked_rows_instance`（center_outbox_repository.rs:1582） | `persistence/src/center_outbox_repository.rs:401-414, 745-789` |
| W7-E-3 R6-E-01 防护被端点 re-home 旁路 | MEDIUM | ✅ **已修复**（a0b2bc0）：`find_unknown_outcome` 的确认读只查请求站点自己的队列，re-home 后 offer 行在原站点队列 → 不拦截 → 铸新 id 双执行（风险是端点作用域的）。修复：新 trait 方法 `find_offer_by_operation_across_instances`（默认 = per-site 降级，生产仓库按 operation_id 列查任意实例，新单列索引 `ix_center_outbox_operation`）+ NULL 行跨实例惰性回填。**顺带修复**：`&Outbox` blanket 缺 `find_offer_by_operation` 委托——R6-E-04 定向读自 wave-six 起在生产运行时被静默遮蔽走全量扫描，两条委托补上。测试 `the_cross_instance_offer_lookup_confirms_an_offer_in_any_instances_queue`（:1754）、`an_unknown_outcome_blocks_the_re_homed_endpoints_dispatch`（dispatch.rs:4419） | `persistence/src/center_outbox_repository.rs:542-619`；`application/src/center_sync.rs:231-249, 291-305`；`application/src/center/dispatch.rs:674-717`；`migration/src/m20260814_000003` |
| W7-F-3 = W7-E-4 Unknown 扫描缺 target 维度 | MEDIUM | ✅ **已修复**（a0b2bc0）：同 endpoint 上 target-A 的终态 Unknown 永久误伤 target-B 的同 command 派发（无 reconcile 路径）。修复：确认读到 offer 行后按 offer 事实的 target 与请求比对，一致才 409。测试 `an_unknown_outcome_on_one_target_does_not_block_another_targets_dispatch`（dispatch.rs:4480） | `application/src/center/dispatch.rs:702-711` |
| W7-C-1 撤销与连接注册赛跑（R6-C-6 覆盖缺口） | MEDIUM | ✅ **已修复**（a0b2bc0）：admission 与 `mark_connected` 之间落地的撤销被 `disconnect` 的 no-op 吞掉，已吊销站点保持在线。修复：`run_center_connection` 在 `mark_connected` 后、构造 guard/engine 前用新鲜 store 读复查 binding（`center_binding_still_in_force`，读失败 fail-closed），已吊销即自断；复查在撤销之后落地则走 R6-C-6 既有 Notify 路径。测试 `a_revocation_landing_before_registration_closes_the_new_connection`（app:1799） | `app/src/center_runtime.rs:1129-1178, 605-623` |
| W7-C-2 陈旧连接清理误删新会话条目 | MEDIUM | ✅ **已修复**（a0b2bc0）：`mark_disconnected`/`DisconnectOnDrop` 无条件按 site 键 remove。修复：registry 引入单调注册代（`mark_connected` 返回该代），清理仅在当前条目仍属同一代时 remove。测试 `a_stale_cleanup_never_removes_the_successor_session`（session.rs:1486） | `application/src/center/session.rs:311-330, 343-407, 444-474, 513-528, 727-743`；`app/src/center_runtime.rs:1108-1120` |
| W7-C-3 补偿队列在 Center 姿态从不排空 | MEDIUM | ✅ **已修复**（a0b2bc0）：drain 只在 `run_background_services` spawn，Center 的 `run_center_services` 没有——终态审计事件入队后永不重试、退出整队丢弃。修复：Center 姿态 spawn 同款 drain + 两条停机分支 final drain。测试 `the_center_runtime_retries_queued_audit_appends`（app:2018，完整集成） | `app/src/center_runtime.rs:854-861, 900-906, 917-923` |
| W7-P-2 定向读 miss 无条件全队列解密 | MEDIUM | ✅ **已修复**（a0b2bc0）：「列已回填但行不存在」与「列未回填」不可区分，从未入队的 id 每次调用全扫。修复：回退前先做 `operation_id IS NULL` 存在性检查（SQLite NULL 键入索引，成本 log N），无 NULL 行直接返回 None；扫描本身收窄到 NULL 列行。测试 `a_directed_read_miss_on_a_backfilled_queue_never_decrypts_anything`（:1656，损坏密文行证明扫描未跑） | `persistence/src/center_outbox_repository.rs:449-481, 556-580` |
| W7-P-6 me_limiter 的 by_ip 桶永不剪枝（N3 矛盾） | MEDIUM | ✅ **已修复**（a0b2bc0）：me 处理器只走 `reserve_ip`，该路径从不调用 `sweep_if_due`——by_ip 键进程生命周期只增不减。修复：`reserve_ip` 在 IP 桶 inserts 达阈值时触发全表清扫，判定语义不变；N3 注释补 me_limiter 说明。测试 `me_limiter_reserve_ip_prunes_expired_ip_buckets_to_a_bounded_size`（auth.rs:4737） | `web/src/auth.rs:1230-1243, 1082-1095` |
| W7-F-2 restore 标记重跑覆盖混合对 | MEDIUM | ✅ **已修复**（a0b2bc0）：`restore_database_files` 无条件先写标记，重跑把第一代崩溃留下的混合对记成 pre，open 校验「untouched」接受混合对。修复：写标记前检查 `-restore-pending` 残留，存在即拒绝（`RestoreError::RestoreInterrupted`，指引操作员先 open 校验）。测试 `a_rerun_restore_refuses_to_legitimize_a_mixed_pair_from_the_first_generation`（backup_snapshot.rs:897-948） | `persistence/src/backup_snapshot.rs:241-266, 667-674` |
| W7-D-1 审计分页排序键非全序 | MEDIUM | ✅ **已修复**（a0b2bc0）：`(OccurredAt, EventSequence)` 双列倒序缺决胜列，等值键上 offset 翻页漏行/重行（outbox 侧有 Id 决胜列纪律）。修复：加 `order_by_desc(Id)`；`warm_audit_tail` 复用同一查询自动对齐。测试 `equal_key_rows_page_in_a_stable_total_order_by_event_id` | `persistence/src/audit_repository.rs:144-152` |
| W7-M-1 assert-tests-ran.sh 无法表达全限定名 | MEDIUM | ✅ **已修复**（a0b2bc0）：裸名后缀匹配无法区分跨模块同名，名字校验 `[A-Za-z0-9_]+` 拒绝 `::`。修复：逐 `::` 段校验（每段 Rust 标识符），匹配保持后缀语义，注释说明跨模块同名须全限定名；ci.yml 21 名保持裸名（全仓唯一）。cargo 桩测试 T5/T6 全过 | `scripts/assert-tests-ran.sh:115-140` |
| W7-C-4 停机 final drain 与后台 drain 并发 | LOW | ✅ **已修复**（a0b2bc0）：先 `drain_audit_compensation_final` 再 join 后台 drain——在飞事件绕过 final drain 预算。修复：调换顺序（先 join 后 final drain）。测试 `a_shutdown_requeue_from_the_background_drain_reaches_the_final_drain` | `app/src/standalone_runtime.rs:2463-2467, 2493-2499` |
| W7-E-8 撤销窗口内仍可投递一整批 offer | LOW | ✅ **已修复**（a0b2bc0）：flush 在 select 之外，撤销后本迭代仍可交付最多 64 个 pending offer。修复：`flush_outbox` 每帧经 `registry.is_current(site, generation)` 轻量探针，disconnect 一落地立即停投。测试 `a_disconnect_mid_flush_stops_the_remaining_offer_delivery`（session.rs:2318） | `application/src/center/session.rs:906-915, 462-474` |
| W7-F-7a revoke 与 dispatch 的 TOCTOU | LOW | ✅ **已修复**（a0b2bc0）：revoke 不取闸门，binding 检查与 enqueue 之间撤销可提交产生 stranded offer。修复：`revoke_center_binding` 撤销前取同一 per-site dispatch 闸门（锁序一致：先闸门后写门）。测试 `revoke_and_dispatch_serialize_through_the_site_gate`（app:1881） | `app/src/center_runtime.rs:433-489` |
| W7-P-7 dispatch_gates 键永不回收 | LOW | ✅ **已修复**（a0b2bc0）：撤销成功后 `drop_dispatch_gate` 移除该 site 键。测试 `revoke_releases_the_sites_dispatch_gate_key`（app:1953） | `app/src/center_runtime.rs:480-489, 625-633` |
| W7-F-4 RUTMK002 迁移失败锁死解锁 | LOW | ✅ **已修复**（a0b2bc0）：迁移失败 `?` 传播——目录只读/写盘失败时口令正确也无法解锁。修复：open/initialize 两路径对称降级为 warn 继续用旧信封（旧信封同样 AEAD 认证；下次 open 再试迁移）；删除不可达的 `MasterKeyMigration` 变体；cfg(test) 注入 seam。测试 `a_failed_legacy_envelope_migration_degrades_to_a_warned_open` | `app/src/standalone_runtime.rs:1909-1935, 2900-2937`；`app/src/initialization_runtime.rs:135-156` |
| W7-D-2 drain 丢弃「已提交但报错」的非末事件（尾/库分叉） | LOW | ✅ **已修复**（a0b2bc0）：drain 重发非末事件被 NonContiguous 分类丢弃且从不镜像。修复：持久化失败后先做事件存在性检查——在库则仅按时间位镜像进内存尾 + ack，不重插不丢弃；不在库走既有路径。测试 `a_committed_but_errored_append_is_mirrored_by_the_drain_not_dropped` | `app/src/standalone_runtime.rs:713-766, 642-679`；`persistence/src/audit_repository.rs:164-182` |
| W7-S-3 = W7-P-4 审计分页无覆盖索引 | LOW | ✅ **已修复**（a0b2bc0）：ORDER BY 双列只有 occurred_at 单列索引，深翻页全表扫描 + 外部排序。修复：`m20260814_000002` 建三列覆盖索引（occurred_at DESC, event_sequence DESC, id DESC，与查询完全对齐），down 对称删除。测试 `migration/tests/audit_paging_index.rs`（PRAGMA index_list 双向断言） | `migration/src/m20260814_000002_audit_paging_index.rs` |
| W7-N-2 offset 违规报 limit 文案 | LOW | ✅ **已修复**（a0b2bc0）：`ParseAuditError` 三变体（Limit/Offset/Parameter），handler 按类回各自文案。测试 `bounds_the_audit_query_limit` 扩精确断言 | `web/src/lib.rs:2150-2178, 3499-3513` |
| W7-L-3 / W7-N-1 UI 分页失败静默 + Loading 清空整窗 | LOW | ✅ **已修复**（a0b2bc0）：`AuditPage` 加 `load_failed` 标志（失败保留窗口 + form-error 显示新文案，重试成功清除）；`Loading(Option<AuditPage>)` 翻页期间保留已载窗口渲染与计数。i18n 新键 `error_audit_load_earlier`（En/Zh）。测试 `a_failed_load_earlier_keeps_the_window_and_shows_the_error_until_the_retry_succeeds`（ui:21773）、`loading_a_page_keeps_the_loaded_window_rendered`（ui:21732） | `ui/src/lib.rs:4459-4520, 14953-15025`；`ui/src/i18n.rs:1250` |
| W7-D-5 down_order_gate 三盲区 | NOTE→修 | ✅ **已修复**（a0b2bc0）：①剥 SQL 注释后分词（`DROP /* reason */ TABLE parents` 不再被 `/*` 吃掉；`raw_alter_references`/`raw_create_table_references` 对称闭掉）；②`ALTER TABLE x RENAME TO y` 改活表引用——`raw_renames` + `apply_renames` 把 FK 边重定向为 y；③引号感知语句切分（`DROP TABLE "weird;name"` 整体归位）。自检 13→16 | `migration/tests/down_order_gate.rs:293, 351, 419, 433, 812, 847, 867, 912, 951` |
| W7-D-6 bare_sql_gate 多语句串只查首词 | NOTE→修 | ✅ **已修复**（a0b2bc0）：`ALTER TABLE x ADD COLUMN y; DELETE FROM z` 首词 ALTER 通过、`;` 后 DML 静默放行。修复：同款引号感知语句切分，整串原始首词判定通过后逐 `;` 段独立过 DDL 与 `ddl_embedded_dml`。自检 5→6 | `migration/tests/bare_sql_gate.rs:372, 441, 759, 793, 834` |
| W7-D-7 000001 down 崩溃续跑无路 | NOTE→修 | ✅ **已修复**（a0b2bc0）：sea-orm-migration 2.0.1 对 SQLite 默认不包事务，down 两条语句各自自动提交、两步间崩溃后重跑必失败。修复：覆盖 `use_transaction → Some(true)`（与重建类迁移纪律对齐）。新测试 up→down→up 往返（模拟崩溃续跑） | `migration/src/m20260814_000001_center_outbox_operation_ids.rs:50`；`migration/tests/m20260814_000001_center_outbox_operation_ids.rs` |
| W7-E-6 中心侧无 Running/WaitingRemote 超时与 reaper | NOTE | ✅ 已登记（本行）：全库无中心侧操作 reaper/TTL（offer 有 15 分钟 TTL），站点永久离线后 Running/WaitingRemote 永久非终态、阻塞同键重派发；E-1 修复后本项仍为独立缺口——未来引入操作超时/reaper 时处理 | 本行 |
| W7-E-7b 409 拒绝响应无结构化 operation_id | NOTE | ✅ 已登记（本行）：`CenterOperationDispatchRefusalResponse` 只有 {code, message}，operation_id 仅嵌 message 文本；核验确认设计文档 §15.6 对拒绝响应**本无契约**（无被违反的结构化要求），属 API 人体工学注记 | `api/src/lib.rs:6127-6131`；`web/src/lib.rs:4321-4325` |
| W7-D-4 重建类迁移 down 具名预检不对称 | NOTE | ✅ 已登记（本行）：000001/000003/000006/000012 与审计重建 down 遇不可表示行报裸 CHECK 错（事务回滚、数据无损），仅 000004 有具名双侧预检——操作指引面缺口，未来补齐纪律 | `migration/src/m20260807_000001_nvidia_families.rs:47-49, 235-260` |
| W7-F-5 = W7-D-3 迁移前 NULL 行永不剪枝 | NOTE | ✅ 已登记（本行）：ack 剪枝触发依赖非 NULL 的 operation_id 列，惰性回填只回填被定向读命中的最新行——同一 operation 的旧 NULL 行永不被回填也不被剪；升级时点的一次性有界增长（每操作至多重试次数行） | `persistence/src/center_outbox_repository.rs:385-392, 440-471, 605-630` |
| W7-P-8 drain 持续故障下每 tick 重放 8 次完整 append | NOTE | ✅ 已登记（本行）：失败事件 push 回队尾，持续故障下每 30s tick 旋转重试；CSV 导入级大 trail 时每 tick 8 次全 trail 重读——低速自转的固定开销，不构成洪泛 | `app/src/standalone_runtime.rs:653-703` |
| W7-P-9 restore marker 全文件读 + SHA-256 | NOTE | ✅ 已登记（本行）：`write_restore_marker` 对活 db + 活 WAL 各做全文件读入 + 哈希（峰值 ≈ max(db, wal) 一份，顺序读后释放）；本产品验证规模（数十至数百 MB，operations-manual §九）下为边际成本 | `persistence/src/backup_snapshot.rs:275-307, 264-269` |
| W7-C-6 outbox 回填与 ack 剪枝并发返回已删行 | NOTE | ✅ 已登记（本行）：回填 UPDATE 不检查 rows_affected、影响 0 行仍返回 Ok(Some)；被剪行必为 acked 行，调用方判定与 keeper 判定一致，无害竞态 | `persistence/src/center_outbox_repository.rs:440-470` |
| W7-C-7 = W7-L-1 offset 分页在并发追加下边界重复 | NOTE | ✅ 已登记（本行）：两次请求间新事件插入使 store 窗口下移，page N 末行在 page N+1 头部重复（UI `with_older` 纯 extend 无去重）；事件不可删故无空洞；与 D-1 修复独立（Id 决胜列不消除窗口漂移）——offset 分页固有问题，如实登记 | `persistence/src/audit_repository.rs:135-141`；`ui/src/lib.rs:4484-4491` |
| W7-N-3 workspace 人口断言是固定 floor | NOTE | ✅ 已登记（本行）：`count > 100` 非人口核对；walk 与计数共用同一枚举函数，「静默漏掉整批 crate」需 crate 目录本身消失，漏检场景比声称苛刻 | `security/tests/secret_leak_gate.rs:1709-1716` |
| W7-S-4 secret-gate [R3] 宏集外输出面（Term::stderr / io::Write） | NOTE | ✅ 已登记（本行）：`Term::stderr` 6 处调用点全部为 prompt_secret（口令输入不回显）+ 非机密文案，当前无实弹；未来经 Term/io::Write 输出机密名变量时门禁不拦截——盲区登记 | `app/src/main.rs:336-461`；`security/tests/secret_leak_gate.rs:652-654` |
| W7-S-2 制品无删除 API / 无总量配额 | NOTE | ✅ 已登记（本行）：全仓生产代码无制品删除路径（EDGE_ROUTES 只有 Create/List/Append/Finalize/Detail），无总量配额——Operator 可积累磁盘占用且无恢复路径；单制品已有 2 GiB cap（R6-W-6 + W7-S-1），聚合面为设计空白；未来引入制品生命周期管理时处理 | `web/src/lib.rs:993-1017` |
| W7-P-3 ack 剪枝每次 ack 4 条 SQL 写门事务 | NOTE | ✅ 已登记（本行）：keeper 查询已随 F-1 修复加实例过滤收窄；剩余 update+find+keeper+delete 为剪枝固有成本，写门串行下的写放大在既有规模（stress_capacity 实测）下未构成瓶颈——登记为权衡，未来按需批量剪枝 | `persistence/src/center_outbox_repository.rs:341-398` |
| W7-P-10 admin 404 预算与改密共享（refuted） | — | **refuted**（已登记设计，wave-six R6-S-10 有意为之：admin 404 探测走 password_change_limiter 是有意设计，A3.md:14 登记原文「探测不能免费跑 dummy 派生门」；管理员自锁是设计接受的权衡） | `docs/r6-findings/A3.md:14` |
| W7-L-2 事件级 deny_unknown_fields（refuted） | — | **refuted**（已登记决策：A6.md:36 明确记录事件级严格性由 `audit_contract_is_secret_free_and_strict` 钉死，未来加字段时先按 W3C-1 放宽——登记重申，非新发现；唯一新信息是 api 注释措辞覆盖全响应方向，登记价值近零） | `docs/r6-findings/A6.md:36` |
| W7-C-5 限速 token 计数器 u64 回绕（refuted） | — | **refuted**（不可达：2^64 次 reserve 需 584 万年，且回绕前条目早已过期被 prune；纯理论注记无修复价值） | `web/src/auth.rs:1252-1256, 1258` |
| W7-H-1 wasm 门禁 $HOME 前提错误（refuted） | — | **refuted**（核验员抓取 runner-images 2019→2026 六代 rust.sh 历史源码：RUSTUP_HOME/CARGO_HOME 从未写入 /etc/environment（仅 PATH 进），/etc/skel 符号链接 + 模板一贯；ci.yml 的 $HOME 前提与真实行为逐字吻合，门禁预期绿；「待 CI 实跑」作为未竟项已由 A5 登记） | `docs/r6-findings/A5.md` 未竟项 #1 |
| W7-E-5 投影一致时跳过 offer 事实（partial） | — | **partial**：代码事实成立（offer_site 投影一致即提前返回），但「伪造回执」变体需受信绑定站点恶意行为（在既有信任模型外）；真实双授信变体经 F-1 机制成立并已随 F-1 修复（跨站证据保留 + 双站回执按事实链各自计分） | `application/src/center/dispatch.rs:1089-1120` |
| **第八波块（wave-eight 对抗发现，2026-08-14，16 confirmed + 1 refuted + 5 partial）** | | | |
| W8-E-2 未决路径 re-home 双执行（W7-E-3 的孪生漏洞） | **HIGH** | ✅ **已修复**（6d5e90e）：re-home 时非终态操作的单候选修复读（旧 dispatch.rs:533、resolve_candidate :612-616）走 per-site `find_offer_by_operation`，offer 位于他站队列 → 判「从未入队」→ `deliver_retry` 同 id 重投（多候选铸新 id）→ 同一物理写双执行且全程 200。修复：两处定向读全部换用跨实例读 `find_offer_by_operation_across_instances`——命中他站 offer = 已在飞 → 返回既有 operation id 不重投、不铸新 id；仅全库无行才走 stranded-offer 修复。顺带修复：旧 per-site 确认闸在「跨站 offer 目标不同」场景漏过并复用旧 id 投递不同目标——现在正确 fresh start 铸新 id。TTL 过期与 acked keeper 语义不变。测试 4 个（dispatch.rs:4576/4636/4699/4754） | `application/src/center/dispatch.rs:547, 564-581, 638` |
| W8-F-2 target 裸字符串比对可被拼写变体绕过 | MEDIUM | ✅ **已修复**（6d5e90e）：未决/Unknown 两闸门的 target 比对无规范化——无需 re-home，同站用大小写/尾斜杠/%xx 变体重试即双执行（Redfish URI 大小写不敏感）。修复：共享 `canonical_target_key`（百分号解码→ASCII 小写→去尾斜杠；%20 与字面空格收敛），两处比对双方同函数；offer 写入侧保持原样字符串（线上格式与站点共享 + 写入侧归一化会使修复前遗留行漏闸的向后兼容论证）。测试 2 个（dispatch.rs:4894/4977） | `application/src/center/dispatch.rs:811-863, 648-659, 739-747` |
| W8-P-1 = W8-F-6 端点全历史扫描 + 32766 参数硬顶 | MEDIUM | ✅ **已修复**（6d5e90e）：id 集查询无 state 过滤无 LIMIT（终态行永不剪枝）、每 dispatch 6 次重复、bundled SQLite 3.51.3 变量上限 32766 超限即该端点派发永久失败。修复：state 过滤 JOIN 进 id 查询（id 集收窄为该状态在飞操作数）+ IN 分批（`IN_PARAMETER_CHUNK = 999`）+ 分批后按 (created_at, id) 全局排序恢复 acceptance order。测试 `list_operations_for_endpoint_bounds_the_id_set_by_state_and_chunks_the_in_list`（operation_repository.rs:1797） | `persistence/src/operation_repository.rs:27-38, 656-723` |
| W8-C-1 = W8-F-1 Center 停机 drain 顺序与 W7-C-4 纪律相反 | MEDIUM | ✅ **已修复**（6d5e90e）：Center 两停机分支先 final drain 后 join（在飞 pass 的失败重入队绕过预算被静默丢弃），与 Edge 正序（先 join 后 final）相反且注释自称「同款纪律」。修复：两分支调序 + 注释引用 W7-C-4 纪律。确定性两序区分测试 `a_center_shutdown_requeue_from_the_background_drain_reaches_the_final_drain`（center_runtime.rs:2167：写闸钉住 pass 在飞 + DROP TABLE 使 append 必败 + 预算耗尽断言 remaining=2 vs 颠倒序 remaining=1） | `app/src/center_runtime.rs:895-934, 2167` |
| W8-D-1 000003 漏 use_transaction（W7-D-7 复发） | MEDIUM | ✅ **已修复**（6d5e90e）：up/down 各两条索引语句无事务覆盖，崩溃在两条之间重跑必败（"index already exists"/"no such index" 永久卡死回滚链）。修复：覆盖 `use_transaction → Some(true)`（与 000001 的 W7-D-7 修复同款）+ 往返测试 `migration/tests/m20260814_000003_center_outbox_operation_lookup.rs` | `migration/src/m20260814_000003_center_outbox_operation_lookup.rs:36-57` |
| W8-D-2 = W8-C-2 = W8-F-3 审计尾与 store 权威序分叉（三模式） | LOW | ✅ **已修复**（6d5e90e）：①镜像新端无条件 push_back（提交序与 occurred_at 序相反时旧事件显示为最新）②等 occurred_at 组内时间位插入与 (sequence, id) 规范序无关 ③offset==0 尾页与 offset>0 store 页跨页重复/漏/倒挂。修复：查询侧 `canonical_audit_tail_order`（store 三列 DESC 的升序镜像），offset==0 路径全尾规范序排序后返回——三模式一次消除，mirror 插入逻辑不动，warm-up 规范序幂等无害。测试 2 个（standalone_runtime.rs） | `app/src/standalone_runtime.rs:503-528, 587-604` |
| W8-S-2 = W8-W-1 = W8-F-9 门禁注释剥离器引号标识符漏报 | LOW | ✅ **已修复**（6d5e90e）：`strip_sql_comments` 只保护单引号——`CREATE TABLE "a--b" AS SELECT * FROM src`（合法标识符 + 真实 CTAS）与 `DROP TABLE "a--b"; DELETE FROM operations`（DML 尾段连同 `;` 被行注释吞掉）均零违规；down_order 侧已登记残差、bare_sql 侧是未登记的 fail-open 漏报方向（A5.md:28 的「既有登记边界同款」为误述）。修复：两门禁 strip 补四引号态（`'` 含 `''` 转义、`"` 含 `""`、反引号、`[...]`），与同文件 split 侧对齐——「same strip-then-split shape」声称真正成立。自检 bare_sql 6→7、down_order 16→17 | `migration/tests/bare_sql_gate.rs`；`migration/tests/down_order_gate.rs` |
| W8-P-5 accept 循环 connections Vec 无界累积 | LOW | ✅ **已修复**（6d5e90e）：运行期只 push、停机才 join（重连风暴下 ~29 万条目 ≈ 15-20MB）。修复：`reap_finished_connections` 每次接受后回收已完成的 JoinHandle（JoinError 按停机同款纪律带 site id 记录），Vec 恒有界于在飞连接 + 1。测试 `the_accept_loop_reaping_keeps_the_connection_tracking_bounded` | `app/src/center_runtime.rs:1073-1076, 1115-1141` |
| W8-E-4 mock 跨实例读与生产语义分歧 | NOTE→修 | ✅ **已修复**（6d5e90e）：mock 升序取最旧（生产降序取最新）、corrupt 行 `.ok()` 跳过 fail-open（生产 Corrupt 503 fail-closed）。修复：mock 对齐生产（降序按 (created_at, id) 取最新；corrupt 行返回 Err）。测试 `the_mock_cross_instance_read_matches_production_semantics`（dispatch.rs:5041） | `application/src/center/dispatch.rs:2150-2202` |
| W8-C-6 backfill 注释「the gate」措辞歧义 | NOTE→修 | ✅ **已修复**（6d5e90e）：两处注释改为「no caller of this read holds the *write gate*」+ 注记 dispatch 持 per-site 闸门（另一把锁）调用的事实。无死锁（write_gate 持有者无 write_gate→闸门路径） | `persistence/src/center_outbox_repository.rs:496-503, 601-608` |
| W8-W-5 Loading 文案臂错文案陷阱 | NOTE→修 | ✅ **已修复**（6d5e90e）：`Loading(_) => unavailable_audit` 被 is_failed 守卫挡住今天不可达、守卫一变即爆。修复：抽 `error_hint_text()` 纯方法，`Loading(Some(page)) if page.load_failed` 与 Ready 同款按携带页标志选 `error_audit_load_earlier`。测试 `a_retry_in_flight_after_a_failed_load_earlier_keeps_the_earlier_failure_hint`（ui:21857） | `ui/src/lib.rs:4576-4588, 15046-15047` |
| W8-E-1 超 cap manifest 注释与实现矛盾 | LOW | ✅ **已修复（注释如实化，行为零改动）**（6d5e90e）：原注释声称「at-least-once outbox keeps the frame until the site learns of the skip」——实际是吸收 + ack + 双方游标前进，站点无任何反馈、制品从中心视图消失。重写为真实行为描述 + 注明协议级拒绝反馈为未来工作（本行登记）。同版本站点对不可自然产生（站点侧同 cap 同校验），需版本倾斜或存量行——LOW | `application/src/center/projection.rs:1440-1452` |
| W8-D-3 = W8-F-10 混合对恢复死锁 + 人工删标记洗白 | LOW | ✅ **已修复（文案/文档，判定逻辑不动）**（6d5e90e）：混合对时重跑 restore 被拒 + open 拒 + 文档「只能通过 store open 解决」自相矛盾 + 删标记出口无指引（且删标记后重跑再失败会把混合对洗白为 pre）。修复：错误文案删除「resolve the marker manually」出口、明示洗白后果与正确步骤（先构完整对 → open 校验清标记 → 重跑）；模块文档分情形描述；operations-manual 新增 §6.5「恢复中断（混合对）处置」 | `persistence/src/backup_snapshot.rs:225-236, 663-671`；`docs/operations-manual.md` §6.5 |
| W8-E-3 = W8-S-1 终态 Unknown 永久冻结无出路 | NOTE | ✅ **已登记 + 文档化**（6d5e90e）：机制链全证实（跨实例确认丢弃实例维度 + acked keeper 永存 + 无清除路径 + Unknown 终态吸收 + 站点侧终态跳过）——意外 Unknown 后 (endpoint, command, target) 键对全舰队永久 409，唯一出路是人工改库。核验员按 W7-E-5 先例把「恶意站点对每个 offer 报 unknown」切片划出威胁模型；「无出路 + 无文档」切片由 user-manual 新增 §10.1「Unknown 终态与 409 unknown_outcome_pending 对账」（触发场景/operation_id 含义（可能他站操作）/对账三步/已知边界）处置。机制不改（无解锁 API 为 E-6/E-7b 已登记面的延伸） | `docs/user-manual.md` §10.1；`application/src/center/dispatch.rs:674-717` |
| W8-W-2/W-3/W-4 M-2 重锚遗漏 + pin 注释未同步 | LOW/NOTE | ✅ **已修复**（6d5e90e）：三处「UI 本地化」现行状态行的 ui lib.rs 锚点重锚（11647→11725、11614-11636→11692-11724、11668→11746，计数 141→144）；security-review.md:195 的 ci.yml:285→307-309 与 milestone-status 459→513 重锚；ci.yml Migration 注释按实测 67 重写（集成复跑后为 68：17 down_order_gate + 7 bare_sql_gate + 44 其他，注释已注明）；历史点-时登记保留 | `docs/release-readiness.md`；`docs/milestone-status.md`；`docs/known-limitations.md`；`docs/security-review.md`；`.github/workflows/ci.yml` |
| W8-F-4 = W8-P-6 revoke 持闸门阻塞同 site 派发（partial→登记） | LOW | ✅ 已登记（本行）：revoke 持 per-site 闸门跨 binding 读 + revoke 写（busy 等待上限 5s），期间该 site 全部派发排队——W7-F-7a 原子性修复的必要代价（核验员确认「闸门外先读、闸门内只写」的优化会破坏 binding 读与 revoke 写的同临界区前提），无死锁（锁序闸门→写门两路径一致）。登记为已知可用性耦合 | `app/src/center_runtime.rs:442-471`；`persistence/src/center_binding_repository.rs:300-335` |
| W8-C-5 = W8-F-5 复查 fail-closed 的级联放大（partial→登记） | NOTE | ✅ 已登记（本行）：每连接两次 store 读（admission + W7-C-1 复查），store 故障时复查 fail-closed 关闭全站新连接、重连-被断循环叠加负载——刻意的 fail-closed（注释明示），触发面窄（WAL 下 SELECT 几乎不因竞争失败，需连接池耗尽或 store 实际故障），自限（store 恢复即自愈） | `app/src/center_runtime.rs:1137-1162` |
| W8-C-4 touch 无代际校验污染后继会话 last_seen（partial→登记） | NOTE | ✅ 已登记（本行）：旧引擎退出窗口内处理一帧时 touch 更新后继会话 B 的 last_seen——纯展示失真（last_seen 全库唯一用途是 list_online 排序，liveness 是信号驱动非超时驱动），无安全影响。为观感问题避免扩大 diff（与 A2 区 W7-C-2 修复时的同一决策） | `application/src/center/session.rs:434-441, 830-832` |
| W8-P-2 NULL 门使每 miss 定向读查询数翻倍（partial→登记） | NOTE | ✅ 已登记（本行）：miss 路径现为定向读 + NULL 存在性门两查询，NULL 门本身 O(1)（IS NULL 键入索引 LIMIT 1 命中即停）——常数因子、无容量上限、miss 为常态路径，接受 | `persistence/src/center_outbox_repository.rs:546-568, 474-480` |
| W8-P-3 覆盖索引写放大（partial，两透镜结论矛盾已仲裁） | NOTE | ✅ 已登记（本行）：audit_events 现 4 索引（新增三列覆盖索引最大），每 append 维护 4 索引 +~20-40% 一阶写放大且在全局写门内——核验员按 D 透镜仲裁：SQLite 页批量写 + WAL 缓冲下实际增量微秒级，对写路径排队影响量级可忽略，登记说明即可 | `migration/src/m20260814_000002_audit_paging_index.rs`；`persistence/src/audit_repository.rs:36-40` |
| W8-P-4 flush 探针每条目一次全站共享 std Mutex（partial→登记） | NOTE | ✅ 已登记（本行）：is_current 每 pending 条目锁 registry 全局 std Mutex（flush_limit=64 内），100 site 高频下 ~640k lock/s ≈ 十几 ms/s 聚合 CPU——临界区微秒级、无争用常态下可忽略，登记为常数成本 | `application/src/center/session.rs:468-474, 906-915` |
| W8-F-8 反向改名（park 活表）未来陷阱（partial→登记） | NOTE | ✅ 已登记（本行，A5.md:31 登记的场景延伸）：`is_staging_name` 只认 _rebuild/_new/_old——未来 `audit_events RENAME TO audit_events_previous`（park 活表重建）会被当活表改名把全部边重指向 _previous，新建裸表无边 → 未来父先子 drop 违规对闸门隐形。当前树 39 处 RENAME 全部 staging→活表方向，零现网影响；未来写 park 形态时需同步扩展 staging 名单 | `migration/tests/down_order_gate.rs:847-851, 867-923` |
| W8-F-11 永久性迁移失败使旧信封无限期滞留（partial→登记） | NOTE | ✅ 已登记（本行）：ACL 锁死等永久失败下每次 open 重试 + 一条 warn（非风暴，每进程启动一次）；若未来版本移除 RUTMK001 解析路径，仍持旧信封的实例会被锁死——W7-F-4 降级登记的未来后果切片 | `app/src/standalone_runtime.rs:1926-1934`；`app/src/initialization_runtime.rs:147-155` |
| W8-C-3 = W8-F-7 代计数器 u64 回绕（refuted） | — | **refuted**（双不可达：2^64 次注册需 5.8 万年 + 碰撞后果还需旧会话清理任务恰好同时运行；纯理论注记无登记价值） | `application/src/center/session.rs:383-386` |
| W8-P-3 量级争议（partial 仲裁记录） | — | 攻击透镜估 30-40% 写放大 MEDIUM、数据透镜称「量级微不足道」——核验员按 SQLite 页批量写 + WAL 缓冲的实际机制仲裁为数据透镜（降 NOTE，见上 W8-P-3 行） | — |
| A1 诚实未竟项：trait 默认 per-site 读的同型 fail-open 分歧 | NOTE | ✅ 已登记（本行，A1 未竟项 1）：`CenterOutbox::find_offer_by_operation` 的 trait 默认实现（web/binding/session 测试 mock 继承）对 corrupt payload 行 `.ok()` 跳过 fail-open，生产报 Corrupt fail-closed——生产唯一实现是 SqliteStore（已覆盖），默认实现仅测试面，下一轮收紧时需同步审计继承默认实现的 store | `application/src/center_sync.rs:191-210` |
| A1 诚实未竟项：center_sync.rs:1236 target 比对未规范化 | NOTE | ✅ 已登记（本行，A1 未竟项 2）：站点侧 offer 接受校验的 target 比对未规范化——拼写变体不会造成双执行（变体 → 拒绝 → fail-closed 方向），但合法变体 offer 会被误拒为 TargetStateChanged；与 W8-F-2 同族，下一轮处理 | `application/src/center_sync.rs:1236` |

> 以上偏差均为当前 master 的真实状态；对应设计条款见仓库根目录
> `redfish-management-product-final-design.md`。
