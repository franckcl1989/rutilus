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
| Telemetry | `CommandFamilyView::ALL` 刻意不含 Telemetry；表单选择器返回 `OperationFormError::FamilyRequired`；界面提示 "The telemetry write form is a later milestone."；已持久化的遥测命令通过 `wire_command_summary` 在卡片中渲染 | `ui/src/lib.rs` 第 5170、6289、6361、6437 行（`CommandFamilyView::ALL` 9 家族 `:5170`、Telemetry 表单拒绝 `:6289, 6361, 6437`、later-milestone 提示文案串 `i18n.rs:1654` `hint_telemetry_later`） |
| Log（清空日志 `log.clear`） | 无专用表单（`CommandFamilyView` 中不存在 Log 变体），表单选择器拒绝 | `ui/src/lib.rs` `CommandFamilyView` |
| Control（控制更新 `control.update`） | 同上，无专用表单 | 同上 |

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

## 六、发布级容量建议未发布（合成规模已实测）

- 设计 §0.9.0 的"最低验证规模"（单 Site 200 Endpoint、单 Center 100 Site、中心汇总
  5,000 Endpoint）已由合成规模压力/容量套件**实测落地**（`persistence/tests/stress_capacity.rs`
  3 个测试，2026-08-12，开发机 debug 构建 + WAL；详见 §八与 `docs/operations-manual.md` §九），
  不再是"仅测试目标"；
- **发布级容量建议尚未发布**：设计 §0.9.0 要求"测试后发布真实容量建议"
  （`redfish-management-product-final-design.md:2810`），正式容量建议仍待 release 构建/
  正式规模环境复核后发布；在此之前，本产品没有已发布的容量建议；
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
| 产品版本号（已统一）+ Git Commit 嵌入 | workspace 版本 = `0.9.0`（生产候选，`rutilus version` 输出），单一版本来源 = 根 `Cargo.toml` `[workspace.package] version`（`Cargo.toml:14`）；`rutilus version` 输出**三行**（`app/src/main.rs:733-737`）：产品版本 / `nv-redfish` 开发基线 / `git commit`——CI 构建经 job 级 `RUTILUS_GIT_COMMIT` 注入（`ci.yml:53-64`，值为 `github.sha`），`GIT_COMMIT` 常量嵌入（`app/src/main.rs:38-40`），本地构建（无该变量）降级为 `dev`（不 spawn git 子进程）；版本/日志格式测试断言由 `env!("CARGO_PKG_VERSION")`、`NV_REDFISH_DEVELOPMENT_BASELINE` 与编译期 `RUTILUS_GIT_COMMIT` 派生（`app/tests/version.rs:27-36`、`app/tests/log_format.rs:23-28`），升级只改一处 | 根 `Cargo.toml:14`；`ci.yml:53-64`；`app/src/main.rs:38-40, 733-737`；`app/tests/version.rs:8-11, 27-36`；`app/tests/log_format.rs:7-10, 23-28` |
| macOS 非绝对静态链接 | macOS 上只承诺单文件、无随包动态库、仅系统框架（不做"绝对零动态依赖"承诺，§5.3） | 设计文档 §5.3 |
| UI 本地化（✅ 完整：827 键 En/Zh 双语 + 运行时语言选择器 + URL fragment 持久化） | ✅ 完整（commit d3f7769 + 0f91c17）：`ui/src/i18n.rs` 目录扩至 **827 键 En/Zh 双语**（`strings_catalog!` 宏 `i18n.rs:43-160`、目录体 `i18n.rs:163-1858`）、`Lang::{En, Zh}` 运行时语言选择（`thread_local!` `i18n.rs:1909-1928`、`L()` `i18n.rs:1938-1944`、`format_catalog` `i18n.rs:1955-1977`）；lib.rs `LanguageSelector` 组件（`lib.rs:11641-11660`）——**URL fragment 持久化方案**：语言选择写入 `#lang=` fragment（`stored_lang_code`/`persist_language`/`apply_language`，`lib.rs:11609-11637`），因为当前 web-sys feature 面只暴露 `Window`/`Location`——fragment 是唯一可用的浏览器存储（`lib.rs:11600-11603`）；启动时经 fragment 恢复（`start()` `lib.rs:11662-11666`），切换后 reload 全量重挂载；**localStorage 后续触点**：localStorage 持久化需扩展 web-sys feature（`Storage` 面当前未启用），与更多语言同为后续触点；深度翻译已全部完成（facts/健康词汇/`OEM_UNSUPPORTED_NOTICE` 均入目录，`i18n.rs:825-829, 867`）；i18n 11 测试（`i18n.rs:1980-2172`）、ui 136 测试全过、clippy/fmt 干净；J2 审计 3 处 zh 译法微修已合入（`type_nvidia_profile_file`/`fact_power_load_percent`/`fact_metric_values`，`i18n.rs:444, 597, 733`）。审计（I1）MINOR 保持：`i18n.rs:1` 头注释 §5.1 引用不可核验（设计文档无「本地化/i18n」条目）、`L.action_delete`/`L.field_role` 语义复用；「`aria-label="Loading"` 未抽取」已在 H5 解决（aria-label 全部走目录键，如 `lib.rs:11952` `L().aria_loading`）；后续项登记见 `milestone-status.md` §7.2-A「UI 本地化」行 | `ui/src/i18n.rs`；`ui/src/lib.rs:11600-11666`；`web/assets/` |
| 发布管道（签名 + SBOM + 校验清单）代码侧就绪 | 🟡 代码侧完成（commit 34503ea + d77d54e）：`scripts/` 5 脚本（sign-windows.ps1 / sign-macos.sh / sign-linux.sh / checksums.sh / checksums.ps1）+ ci.yml `release-artifacts` job（`ci.yml:332-611`：`v*` tag / `workflow_dispatch` 触发、`needs: ci` 门禁先行、签名步骤仅在 secret 配置时执行、base64 物化、Windows thumbprint-only 模式、cargo-cyclonedx@0.5.9 钉版 SBOM、SHA-256 清单、artifact 上传）；证书未到位，签名在首跑前保持 "signing skipped: certificate not configured"；**首跑确认点 6 项**（证书到位后核验）：① musl-tools 安装（`ci.yml:423`）② cargo-cyclonedx@0.5.9 钉版（`ci.yml:575`）③ base64 物化（`ci.yml:468-478, 493-502, 526-533`）④ env 的 `&&`/`||` 表达式（`ci.yml:486, 516, 544`）⑤ thumbprint-only 模式（`ci.yml:480-488`）⑥ 上传权限（`ci.yml:596-611`） | `.github/workflows/ci.yml`；`scripts/`；`release-readiness.md` 条件 17 |
| HTTP 成功不等于业务成功 | 200/201/202/204 不直接等于业务成功，写操作后必须重新读取验证；响应丢失时非幂等操作标记 Unknown 而不盲重试（§13.5） | `operation-engine`；设计文档 §13 |
| 登录限速窗口固定 | 每用户名 5 次 / 每地址 20 次失败、15 分钟窗口，为代码内常量 | `web/src/auth.rs` |
| 事件流重连预算有限 | 超出预算的长期不可达端点以 Failed 呈现而非无限重试（有意设计，见上） | `app/src/event_listener.rs` |
| Center 角色站点作用域 | 中心角色可限定到某些 Site，但用户与会话管理仅 Administrator（有意设计） | `web/src/auth.rs` |
| 审计只追加 | 审计记录不通过正常 ORM Repository 更新或删除（§16.3） | `domain/src/audit.rs` |
| 密码策略：至少 12 字符（API 边界执行） | 产品密码策略 = 至少 12 个 Unicode 标量字符（`MIN_PASSWORD_CHARS`，`password_satisfies_policy`，与 UI 表单同一检查）；**执行边界在 API**（`web/src/auth.rs:1305-1315`）：登录入口在限速/查找/验证之前拒绝，不占限速预算、不写审计（策略违规不是登录尝试；响应本身即记录）；控制台表单的 12 字符下限是客户端便利，不是控制面（深度审查批次 B1，commit 8147bc9） | `web/src/auth.rs:1267-1276, 1305-1315, 1544-1549, 1699-1703` |
| 429 限速拒绝不写审计 | 登录限速拒绝（429）**不写审计事件**：请求在验证前就被拒绝，从未构成一次登录尝试，429 本身即记录；写 started+failed 对会令审计表随拒绝洪泛无界增长，且每次审计追加都串行在 persistence 写门（`Semaphore(1)`）上，429 洪泛会饿死合法 session/telemetry/event/operation 写入（深度审查批次 B2，commit 8147bc9；§16.3 审计的是"已运行的登录结果"，被拒请求从未运行） | `web/src/auth.rs:1321-1335` |
| ETag 现状（PATCH 家族真实生效，快照接线后续迭代） | `update` 写家族（PATCH 家族）携带**本次执行读取时**的目标文档 ETag：带 `@odata.etag` 时发送 `If-Match: <etag>`，BMC `412 Precondition Failed` 即证明写未执行（gateway 报告 `CommandExecutionError::PreconditionFailed`，先重读目标，并发变更不被覆盖）；无 ETag 的文档保持传输层存在性 `If-Match: *`（§13.4 第二段，无并发保护）；action/create/delete 家族在类型化 API 中无 If-Match 通道，从不发送（深度审查批次 commit 6128a17）；**快照 ETag 接线为后续迭代**——快照已持久化 ETag（`domain/src/resource_snapshot.rs:606-632, 790`、`persistence/src/resource_snapshot_repository.rs:402, 553-554, 605-608`），但 operation-executor 尚无消费方（写前校验未接快照值） | `infra-redfish/src/redfish_gateway.rs:598-611, 12653-12690, 14002-14062` |
| 迁移 down 先子后父纪律 | 多表迁移的 `down` 先删引用子表再删父表（外键顺序），如 `m20260805_000005_operations.rs:131-138` 先 `OperationTarget` 后 `Operation`（深度审查批次 commit 1711329）；无机械门禁覆盖该顺序（与裸 SQL 门禁不同），靠审查与迁移测试维护（如实注记） | `migration/src/` |
| Secret 扫描门禁白名单纪律 | `security/tests/secret_leak_gate.rs` 的 `ALLOWED_CONSTANT_HITS` 是仅有的 2 处白名单（`app/src/backup.rs:83, 84`：`ENTRY_MASTER_KEY`/`ENTRY_SYSTEM_MASTER_KEY` 备份条目名，值非秘密材料）；每条绑定 path+line+name+literal 四元组——常量移动/改名/值变都会使门禁失败，需重新审查确认无秘密后再更新条目（deny.toml TRIGGER 注释同款纪律）；测试作用域与 `test-support` crate 按**上下文**豁免而非按值白名单（值白名单会掩盖未来真实秘密；`test-support` 目录级豁免属 E3b 原始提交 eefde7e，深度审查批次 commit e8424df 另补 `strings_catalog!` 宏体结构豁免——CATALOG_MACRO 帧识别 + 新测试 `strings_catalog_macro_bodies_are_copy_construction_not_secret_assignments`，见 `milestone-status.md` §7.4） | `security/tests/secret_leak_gate.rs:325-333, 55-59, 1000-1002` |

## 八、与设计文档的已知偏差（实现状态，如实）

| 设计项 | 现状 |
|---|---|
| §19.1 Fixture 测试（真实响应 fixture 目录） | 尚未建立 |
| §19.1 Physical Device Test（五厂商真实设备认证矩阵） | 尚未达成 |
| §0.9.0 性能容量测试与真实容量建议 | 部分：合成规模压力容量套件已落地并实测（`persistence/tests/stress_capacity.rs` 3 个测试：200 Endpoint Generation 一致刷新 / 100 Site outbox-inbox-cursor / 5,000 Endpoint 中心投影幂等重投，2026-08-12）；实测数据为**开发机 debug 构建合成数据**（5,000 投影写入 ≈865 行/s、清单查询 0.482s；写路径受 `write_gate`（`Semaphore(1)`）全局串行化，`persistence/src/lib.rs:101, 240`），**不是最终发布容量建议**——设计 §0.9.0 要求"测试后发布真实容量建议"（`redfish-management-product-final-design.md:2810`），正式容量建议仍待 release 构建/正式环境复核后发布（详见 `docs/operations-manual.md` §九） |
| §6.2 tracing 日志选型 | 已实现（app 诊断日志 + `RUST_LOG` 过滤的 stderr subscriber）；用户可见输出仍为 `println!`，测试/工具输出仍为 `eprintln!`（见 §七"日志设施范围受限"）；运行路径已接入 span/`#[instrument]`，`--log-format json`（`LogFormat`/`init_tracing`）输出结构化 JSON，`RUST_LOG` 过滤不变 |
| §14.4 遥测保留周期可配置 | 已实现：`--telemetry-retention-days`（默认 7 天，范围 1–365，`TelemetryRetention` 在边界校验）；设置页形态为后续迭代 |
| §12.4 诊断中的解码错误路径 / ExtendedInfo 展示 | ✅ 已实现（E1，commit ce2b8b3）：记录层——`ResourceExtendedInfo`/`ResourceDecodeFailure`（`application/src/resource_diagnostics.rs:36, 249`）、api 契约 9 字段（`api/src/lib.rs:1894-1905`）、web 投影（`web/src/lib.rs:3961-3991`）、ui 只读区块（`ui/src/lib.rs:15492`）、端到端测试（`web/tests/diagnostics_path.rs` 7 个测试，含 `:998` `refresh_capture_flows_into_the_diagnostics_response`）；**生产捕获点已实现**：刷新解码失败由 gateway 捕获（`DecodeFailureObservation`，`infra-redfish/src/redfish_gateway.rs:8720`；捕获函数 `capture_fetch_failure`/`capture_projection_failure`/`capture_segment_decode_failure` `:8904/:8931/:8977`），经刷新结果 `outcome.decode_failures()`（`:8831`）流入同代事务提交（`persistence/src/resource_snapshot_repository.rs:81-147`），生产链路直连（`application/src/endpoint_refresh.rs:350-355`），持久化于新表 `resource_decode_failures`（entity `entity/src/lib.rs:28`、`entity/src/resource_decode_failure.rs:13`；迁移 `migration/src/m20260812_000001`）——真实解码失败会出现在诊断视图中。**如实注记**：① 捕获时 `odata_type` 为 `None`（`capture_fetch_failure` 恒传 None，`redfish_gateway.rs:8915-8922`，解码失败记录不带 OData 类型）；② 表约束经 E4 修复（`migration/src/m20260812_000002` 重建 `resources`/`resource_decode_failures` 两表，`ck_*_feature` 允许域 = 领域枚举全部 47 码，此前 resources 37 / resource_decode_failures 36 且互相不一致；`down` 对称恢复 37/36；防回归机械测试 `migration/tests/resource_feature_lists.rs`）；③ 真实设备上的解码失败形态仍需实测（B 类演练项） |

## 九、深度审查遗留项登记（2026-08-12，LOW/NOTE）

> 多角色多维度深度审查（HEAD = a4950fc：52 项发现 / 16 项对抗验证 / 2 HIGH + 13 MEDIUM 已修复 /
> 1 项结论被推翻，详见 `docs/milestone-status.md` §7.4）后剩余的低优先级项与后续迭代触点。
> 全部为 LOW/NOTE 级，不阻塞 0.9.0/1.0.0 功能面；按主题登记，如实记录现状与后续方案。

| 遗留项 | 级别 | 现状 / 后续方案 | 事实来源 |
|---|---|---|---|
| 限流器桶键淘汰 | LOW | `LoginRateLimiter` 桶键只在被再次访问时剪枝，dormant 键不清理（security-review §三 N3 登记）：条目数 = 攻击者可控 distinct 键数 × 每键 ≤20 个 Instant，多 IP 分布式攻击可致内存线性增长；后续方案 = 周期剪枝（随窗口滑动清理过期桶） | `web/src/auth.rs:863-937`；`docs/security-review.md` §三 N3 |
| i18n fragment 纯函数测试 | NOTE | URL fragment 语言持久化（`#lang=`）目前经 UI 组件测试覆盖，无独立纯函数测试；后续补 `stored_lang_code`/`persist_language`/`apply_language` 的纯函数单元测试 | `ui/src/lib.rs:11609-11637` |
| decode_failures 贯通测试（endpoint_refresh） | NOTE | E1 生产捕获链路（gateway 捕获 → 同代事务提交 → `application/src/endpoint_refresh.rs:350-355` 直连）无贯通测试——现有覆盖为 web 层端到端（`web/tests/diagnostics_path.rs`）与 gateway 单测；后续补经 `endpoint_refresh` 生产链路的贯通测试 | `application/src/endpoint_refresh.rs:350-355` |
| AMI/HPE 真网关 E2E | LOW | AMI/HPE 读取家族（`AmiServiceRoot`/`ConfigBmc`、`HpeiLoServiceExt`/`HpeiLo`）仅有 mock/profile 级覆盖，无真实网关解码 E2E；后续补 mock 网关 fixture 扩展或真设备验证 | `test-support/src/mock_bmc/profile.rs` |
| restore 预恢复副本 | LOW | `restore_backup` 直接覆盖目标数据目录，**不保留恢复前的当前数据副本**——恢复中途失败后旧实例数据不可回退（只读校验失败即报错，但覆盖已发生）；后续方案 = 恢复前先快照当前数据目录，再执行恢复 | `app/src/backup.rs:224-302` |
| free_port TOCTOU | NOTE | 测试助手 `free_port` 先 bind 取端口后立即 drop 再使用（`app/src/site_runtime.rs:1498-1503` 等 4 处同款），探测与真实 bind 之间存在竞态窗口（端口可能被占用）；测试基建级，非产品代码；后续方案 = 复用已绑定 listener 或端口重试 | `app/src/site_runtime.rs:1498-1503`、`center_runtime.rs:892`、`center_client.rs:620`、`center_acceptor.rs:955` |
| 入网首刷绕端点门 | LOW | 端点登记（enrollment）后的首次刷新直接 `refresh.execute(endpoint_id)`（`application/src/endpoint_enrollment.rs:156-166`），不经端点读门（`batch_refresh.rs:87-109`）——首刷与并发批量刷新理论上可重叠同一端点；实际影响低（入网瞬间并发刷新同一新端点需先建立该端点）；后续方案 = 入网首刷也走 `endpoint_read_gate` | `application/src/endpoint_enrollment.rs:156-166`；`application/src/batch_refresh.rs:87-109` |
| 快照 ETag 接线（domain/persistence/operation_executor） | LOW | 快照已持久化 ETag（domain `resource_snapshot.rs:606-632, 790`、persistence `resource_snapshot_repository.rs:402, 553-554, 605-608`），但 operation-executor 无消费方——写前校验仍用执行时读取的 ETag（PATCH 家族，commit 6128a17）；后续方案 = 把快照 ETag 接入写前校验/差异展示（需评估快照陈旧度语义） | `domain/src/resource_snapshot.rs`；`persistence/src/resource_snapshot_repository.rs`；`operation-engine/src/`（无 etag 引用） |

> 以上偏差均为当前 master 的真实状态；对应设计条款见仓库根目录
> `redfish-management-product-final-design.md`。
