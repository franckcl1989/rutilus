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
| 产品版本号（已统一）+ Git Commit 嵌入 | workspace 版本 = `0.9.0`（生产候选，`rutilus version` 输出），单一版本来源 = 根 `Cargo.toml` `[workspace.package] version`（`Cargo.toml:14`）；`rutilus version` 输出**三行**（`app/src/main.rs:733-737`）：产品版本 / `nv-redfish` 开发基线 / `git commit`——CI 构建经 job 级 `RUTILUS_GIT_COMMIT` 注入（`ci.yml:53-64`，值为 `github.sha`），`GIT_COMMIT` 常量嵌入（`app/src/main.rs:38-40`），本地构建（无该变量）降级为 `dev`（不 spawn git 子进程）；版本/日志格式测试断言由 `env!("CARGO_PKG_VERSION")`、`NV_REDFISH_DEVELOPMENT_BASELINE` 与编译期 `RUTILUS_GIT_COMMIT` 派生（`app/tests/version.rs:27-36`、`app/tests/log_format.rs:23-28`），升级只改一处 | 根 `Cargo.toml:14`；`ci.yml:53-64`；`app/src/main.rs:38-40, 733-737`；`app/tests/version.rs:8-11, 27-36`；`app/tests/log_format.rs:7-10, 23-28` |
| macOS 非绝对静态链接 | macOS 上只承诺单文件、无随包动态库、仅系统框架（不做"绝对零动态依赖"承诺，§5.3） | 设计文档 §5.3 |
| UI 本地化（✅ 完整：827 键 En/Zh 双语 + 运行时语言选择器 + URL fragment 持久化） | ✅ 完整（commit d3f7769 + 0f91c17 + c4dd335）：`ui/src/i18n.rs` 目录扩至 **827 键 En/Zh 双语**（`strings_catalog!` 宏 `i18n.rs:43-160`、目录体 `i18n.rs:163-1858`）、`Lang::{En, Zh}` 运行时语言选择（`thread_local!` `i18n.rs:1938-1942`、`L()` `i18n.rs:1968-1973`、`format_catalog` `i18n.rs:1984-2006`）；lib.rs `LanguageSelector` 组件（`lib.rs:11640-11658`）——**URL fragment 持久化方案**：语言选择写入 `#lang=` fragment，因为当前 web-sys feature 面只暴露 `Window`/`Location`——fragment 是唯一可用的浏览器存储（`i18n.rs:1901-1905` `LANG_FRAGMENT_PREFIX`）；**迭代七（T-H，commit c4dd335）已把持久化拆为纯函数 + 薄封装**：`stored_lang_code_from`/`lang_fragment_value`（`i18n.rs:1915-1936`，host 可测、不触 web-sys）＋`stored_lang_code`/`persist_language`/`apply_language`（`ui/src/lib.rs` wasm `browser` 模块 `lib.rs:11607-11635`，仅读写 `window.location`，运行时行为不变）；启动时经 fragment 恢复（`start()` `lib.rs:11661-11664`），切换后 reload 全量重挂载；**localStorage 后续触点**：localStorage 持久化需扩展 web-sys feature（`Storage` 面当前未启用），与更多语言同为后续触点；深度翻译已全部完成（facts/健康词汇/`OEM_UNSUPPORTED_NOTICE` 均入目录，`i18n.rs:825-829, 867`）；i18n 15 测试（既有 11 个 `i18n.rs:2009-2185` + fragment 纯函数 4 个 `i18n.rs:2192-2259`）、ui 141 测试全过、clippy/fmt 干净；J2 审计 3 处 zh 译法微修已合入（`type_nvidia_profile_file`/`fact_power_load_percent`/`fact_metric_values`，`i18n.rs:444, 597, 733`）。审计（I1）MINOR 保持：`i18n.rs:1` 头注释 §5.1 引用不可核验（设计文档无「本地化/i18n」条目）、`L.action_delete`/`L.field_role` 语义复用；「`aria-label="Loading"` 未抽取」已在 H5 解决（aria-label 全部走目录键，如 `lib.rs:11951` `L().aria_loading`）；后续项登记见 `milestone-status.md` §7.2-A「UI 本地化」行 | `ui/src/i18n.rs`；`ui/src/lib.rs:11607-11664`；`web/assets/` |
| 发布管道（签名 + SBOM + 校验清单）代码侧就绪 | 🟡 代码侧完成（commit 34503ea + d77d54e）：`scripts/` 5 脚本（sign-windows.ps1 / sign-macos.sh / sign-linux.sh / checksums.sh / checksums.ps1）+ ci.yml `release-artifacts` job（`ci.yml:332-611`：`v*` tag / `workflow_dispatch` 触发、`needs: ci` 门禁先行、签名步骤仅在 secret 配置时执行、base64 物化、Windows thumbprint-only 模式、cargo-cyclonedx@0.5.9 钉版 SBOM、SHA-256 清单、artifact 上传）；证书未到位，签名在首跑前保持 "signing skipped: certificate not configured"；**首跑确认点 6 项**（证书到位后核验）：① musl-tools 安装（`ci.yml:423`）② cargo-cyclonedx@0.5.9 钉版（`ci.yml:575`）③ base64 物化（`ci.yml:468-478, 493-502, 526-533`）④ env 的 `&&`/`||` 表达式（`ci.yml:486, 516, 544`）⑤ thumbprint-only 模式（`ci.yml:480-488`）⑥ 上传权限（`ci.yml:596-611`） | `.github/workflows/ci.yml`；`scripts/`；`release-readiness.md` 条件 17 |
| HTTP 成功不等于业务成功 | 200/201/202/204 不直接等于业务成功，写操作后必须重新读取验证；响应丢失时非幂等操作标记 Unknown 而不盲重试（§13.5） | `operation-engine`；设计文档 §13 |
| 登录限速窗口固定 | 每用户名 5 次 / 每地址 20 次失败、15 分钟窗口，为代码内常量；桶键内存有界（`BUCKET_PRUNE_THRESHOLD` 4096 周期剪枝，T-D commit e7aef53，见 §九该行） | `web/src/auth.rs` |
| 事件流重连预算有限 | 超出预算的长期不可达端点以 Failed 呈现而非无限重试（有意设计，见上） | `app/src/event_listener.rs` |
| Center 角色站点作用域 | 中心角色可限定到某些 Site，但用户与会话管理仅 Administrator（有意设计） | `web/src/auth.rs` |
| 审计只追加 | 审计记录不通过正常 ORM Repository 更新或删除（§16.3） | `domain/src/audit.rs` |
| 密码策略：至少 12 字符（API 边界执行） | 产品密码策略 = 至少 12 个 Unicode 标量字符（`MIN_PASSWORD_CHARS`，`password_satisfies_policy`，与 UI 表单同一检查）；**执行边界在 API**（`web/src/auth.rs:1386-1397`）：登录入口在限速/查找/验证之前拒绝，不占限速预算、不写审计（策略违规不是登录尝试；响应本身即记录）；控制台表单的 12 字符下限是客户端便利，不是控制面（深度审查批次 B1，commit 8147bc9） | `web/src/auth.rs:1355-1357, 1386-1397, 1625-1631, 1780-1785` |
| 429 限速拒绝不写审计 | 登录限速拒绝（429）**不写审计事件**：请求在验证前就被拒绝，从未构成一次登录尝试，429 本身即记录；写 started+failed 对会令审计表随拒绝洪泛无界增长，且每次审计追加都串行在 persistence 写门（`Semaphore(1)`）上，429 洪泛会饿死合法 session/telemetry/event/operation 写入（深度审查批次 B2，commit 8147bc9；§16.3 审计的是"已运行的登录结果"，被拒请求从未运行） | `web/src/auth.rs:1402-1416` |
| ETag 现状（PATCH 家族真实生效，快照接线已处置） | `update` 写家族（PATCH 家族）携带**本次执行读取时**的目标文档 ETag：带 `@odata.etag` 时发送 `If-Match: <etag>`，BMC `412 Precondition Failed` 即证明写未执行（gateway 报告 `CommandExecutionError::PreconditionFailed`，先重读目标，并发变更不被覆盖）；无 ETag 的文档保持传输层存在性 `If-Match: *`（§13.4 第二段，无并发保护）；action/create/delete 家族在类型化 API 中无 If-Match 通道，从不发送（深度审查批次 commit 6128a17）；**快照 ETag 接线已处置（§九，决策 c，2026-08-12）**——快照已持久化 ETag（`domain/src/resource_snapshot.rs:606-655, 790`、`persistence/src/resource_snapshot_repository.rs:402, 553-554, 605-608`），operation-executor 无消费方是登记过的决策而非遗留：执行时读取恒为分派时刻最新 ETag，快照 ETag（恒更旧）无独立写路径价值，接入不实施（理由与证据见 §九该行） | `infra-redfish/src/redfish_gateway.rs:598-611, 12653-12690, 14002-14062` |
| 迁移 down 先子后父纪律 | 多表迁移的 `down` 先删引用子表再删父表（外键顺序），如 `m20260805_000005_operations.rs:131-138` 先 `OperationTarget` 后 `Operation`（深度审查批次 commit 1711329）；机械门禁已落地：`migration/tests/down_order_gate.rs`（2026-08-12 迭代十）纯静态机械检查全部迁移 down 的 DROP 顺序——builder `drop_table` 与 raw `DROP TABLE`（含 rebuild 型 down）均覆盖，依赖图自 FK 边（builder 链 + raw `ALTER ... REFERENCES`）跨文件聚合提取，注释/字符串不参与，与裸 SQL 门禁同款无库形态 | `migration/src/` |
| Secret 扫描门禁白名单纪律 | `security/tests/secret_leak_gate.rs` 的 `ALLOWED_CONSTANT_HITS` 是仅有的 2 处白名单（`app/src/backup.rs:88, 89`：`ENTRY_MASTER_KEY`/`ENTRY_SYSTEM_MASTER_KEY` 备份条目名，值非秘密材料）；每条绑定 path+line+name+literal 四元组——常量移动/改名/值变都会使门禁失败，需重新审查确认无秘密后再更新条目（deny.toml TRIGGER 注释同款纪律）；测试作用域与 `test-support` crate 按**上下文**豁免而非按值白名单（值白名单会掩盖未来真实秘密；`test-support` 目录级豁免属 E3b 原始提交 eefde7e，深度审查批次 commit e8424df 另补 `strings_catalog!` 宏体结构豁免——CATALOG_MACRO 帧识别 + 新测试 `strings_catalog_macro_bodies_are_copy_construction_not_secret_assignments`，见 `milestone-status.md` §7.4） | `security/tests/secret_leak_gate.rs:325-333, 55-59, 1000-1002` |

## 八、与设计文档的已知偏差（实现状态，如实）

| 设计项 | 现状 |
|---|---|
| §19.1 Fixture 测试（真实响应 fixture 目录） | 尚未建立 |
| §19.1 Physical Device Test（五厂商真实设备认证矩阵） | 尚未达成 |
| §0.9.0 性能容量测试与真实容量建议 | 部分：合成规模压力容量套件已落地并实测（`persistence/tests/stress_capacity.rs` 3 个测试：200 Endpoint Generation 一致刷新 / 100 Site outbox-inbox-cursor / 5,000 Endpoint 中心投影幂等重投，2026-08-12）；实测数据为**开发机 debug 构建合成数据**（5,000 投影写入 ≈865 行/s、清单查询 0.482s；写路径受 `write_gate`（`Semaphore(1)`）全局串行化，`persistence/src/lib.rs:101, 240`）；**发布级容量建议已发布（release 构建数据，2026-08-12，见 `docs/operations-manual.md` §九）**——设计 §0.9.0 要求"测试后发布真实容量建议"（`redfish-management-product-final-design.md:2810`），正式规模环境复核仍待 |
| §6.2 tracing 日志选型 | 已实现（app 诊断日志 + `RUST_LOG` 过滤的 stderr subscriber）；用户可见输出仍为 `println!`，测试/工具输出仍为 `eprintln!`（见 §七"日志设施范围受限"）；运行路径已接入 span/`#[instrument]`，`--log-format json`（`LogFormat`/`init_tracing`）输出结构化 JSON，`RUST_LOG` 过滤不变 |
| §14.4 遥测保留周期可配置 | 已实现：`--telemetry-retention-days`（默认 7 天，范围 1–365，`TelemetryRetention` 在边界校验）；设置页形态为后续迭代 |
| §12.4 诊断中的解码错误路径 / ExtendedInfo 展示 | ✅ 已实现（E1，commit ce2b8b3）：记录层——`ResourceExtendedInfo`/`ResourceDecodeFailure`（`application/src/resource_diagnostics.rs:36, 249`）、api 契约 9 字段（`api/src/lib.rs:1894-1905`）、web 投影（`web/src/lib.rs:3970-4001`）、ui 只读区块（`ui/src/lib.rs:15491`）、端到端测试（`web/tests/diagnostics_path.rs` 7 个测试，含 `:998` `refresh_capture_flows_into_the_diagnostics_response`）；**生产捕获点已实现**：刷新解码失败由 gateway 捕获（`DecodeFailureObservation`，`infra-redfish/src/redfish_gateway.rs:8720`；捕获函数 `capture_fetch_failure`/`capture_projection_failure`/`capture_segment_decode_failure` `:8904/:8931/:8977`），经刷新结果 `outcome.decode_failures()`（`:8831`）流入同代事务提交（`persistence/src/resource_snapshot_repository.rs:81-147`），生产链路直连（`application/src/endpoint_refresh.rs:350-355`），持久化于新表 `resource_decode_failures`（entity `entity/src/lib.rs:28`、`entity/src/resource_decode_failure.rs:13`；迁移 `migration/src/m20260812_000001`）——真实解码失败会出现在诊断视图中。**如实注记**：① 捕获时 `odata_type` 为 `None`（`capture_fetch_failure` 恒传 None，`redfish_gateway.rs:8915-8922`，解码失败记录不带 OData 类型）；② 表约束经 E4 修复（`migration/src/m20260812_000002` 重建 `resources`/`resource_decode_failures` 两表，`ck_*_feature` 允许域 = 领域枚举全部 47 码，此前 resources 37 / resource_decode_failures 36 且互相不一致；`down` 对称恢复 37/36；防回归机械测试 `migration/tests/resource_feature_lists.rs`）；③ 真实设备上的解码失败形态仍需实测（B 类演练项）；④ 贯通测试已补齐（T-G 8482d85，见 §九该行） |

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

| 遗留项 | 级别 | 现状 / 后续方案 | 事实来源 |
|---|---|---|---|
| 限流器桶键淘汰 | LOW | ✅ **已实现**（2026-08-12，T-D，commit e7aef53）：周期剪枝——`BucketMap` 随新键插入计数，达 `BUCKET_PRUNE_THRESHOLD`（4096，`web/src/auth.rs:131`）触发全表清扫，回收全部过期桶（dormant 键随窗口滑动清理，含仅 `allows` 创建的空桶；`prune_if_due` `:989-998`、`prune_expired` `:1005-1015`，`BucketMap` `:893-1016`）；清扫与访问路径共用同一过期判定，限速判定逐字节不变；内存有界 = 一个窗口内活跃桶工作集 + 4096，不再随时间线性累积。测试：`rate_limiter_prunes_expired_buckets_to_a_bounded_size`（`:2848`）/`rate_limiter_prune_spares_active_buckets`（`:2901`）/`rate_limiter_prune_reclaims_buckets_created_by_allows_only`（`:2945`）/`prune_expired_reclaims_only_buckets_whose_entries_left_the_window`（`:2973`），web 133 测试全过 | `web/src/auth.rs`（§16.2 限速器区块）；`docs/security-review.md` §三 N3 |
| i18n fragment 纯函数测试 | NOTE | ✅ 已落实（2026-08-12，T-H，commit c4dd335）：`#lang=` 语言持久化拆分为纯函数 `stored_lang_code_from`/`lang_fragment_value`（`ui/src/i18n.rs:1915-1936`，host 可测、不触 web-sys）＋薄封装 `stored_lang_code`/`persist_language`/`apply_language`（`ui/src/lib.rs` wasm `browser` 模块 `:11607-11635`，仅读写 `window.location`，运行时行为不变）；纯函数单元测试 4 项（`fragment_reading_extracts_only_the_lang_value` `:2192`、`fragment_persistence_writes_the_lang_value` `:2218`、`fragment_persistence_round_trips_both_languages` `:2229`、`fragment_lang_selection_falls_back_to_en` `:2248`，覆盖前缀解析、写入值、格式往返、空/未知码降级边界）与既有 i18n 测试同模块同风格，host 运行；ui 141 测试全过 | `ui/src/i18n.rs:1915-1936, 2192-2259`；`ui/src/lib.rs:11607-11635` |
| decode_failures 贯通测试（endpoint_refresh） | NOTE | ✅ 已补齐（2026-08-12，T-G，commit 8482d85）：经 `endpoint_refresh` 生产链路的贯通测试 4 项（`application/tests/refresh_decode_failures.rs`，头注释 `:3-22`），真实 `EndpointRefresh` + 真实 `SqliteStore`（application dev-dependency 引入，dev 环为 cargo 允许形态）：解码失败经读产物 `outcome.decode_failures()`（`endpoint_refresh.rs:353`）同代事务落 `resource_decode_failures` 且与快照同 Generation 原子可见（成功路径）；提交失败记录随该代一起回滚；能力探测失败后已提交记录仍与快照原子保留；记录按 Generation 作用域、跨刷新不泄漏。构造忠实网关捕获语义（`odata_type` 恒 `None`、标准 feature 无 OEM namespace）；application 301 测试全过 | `application/tests/refresh_decode_failures.rs`；`application/src/endpoint_refresh.rs:350-355` |
| AMI/HPE 真网关 E2E | LOW | ✅ 已实现（2026-08-12，T-I，commit 044bae2）：AMI/HPE 读取家族（`AmiServiceRoot`/`ConfigBmc`、`HpeiLoServiceExt`/`HpeiLo`）通过**真实网关**的 E2E 解码 5 测试已合入（`test-support/tests/gateway_mock_bmc.rs`：`ami_profile_probes_oem_ami_supported_with_standard_surface_unchanged` `:1793`、`ami_profile_reads_oem_ami_snapshots` `:1861`、`hpe_profile_probes_oem_hpe_supported_with_standard_surface_unchanged` `:2003`、`hpe_profile_reads_oem_hpe_segments_snapshot` `:2070`、`namespace_free_endpoint_leaves_ami_and_hpe_families_absent` `:2202`）；该套件现共 **28 测试**（原 23 + 5），头注释已更新（`:3-17`） | `test-support/tests/gateway_mock_bmc.rs`；`test-support/src/mock_bmc/profile.rs` |
| restore 预恢复副本 | LOW | ✅ 已实现（2026-08-12，T-E，commit 02459dc）：`restore_backup` 在首个覆盖动作前把当前数据目录复制进同级临时目录（`create_pre_restore_snapshot`，`app/src/backup.rs:300-308, 619-643`，与迁移前恢复副本同款 length-verified 拷贝 + 同步），此后才进入覆盖阶段（`restore_data_phase` `:342-372`）。**三态**：① 恢复成功——临时快照随 TempDir drop 自动清除（`:310-315`）；② 恢复中途失败——快照保留并随错误报告其位置供人工回滚（`:317-324`，`RestoreFailedPreservingSnapshot`）；③ 快照创建失败——恢复中止、数据目录原样未动（`:306-308`）。测试：`a_failed_restore_preserves_the_pre_restore_data_for_rollback`（`:1307`）/`a_successful_restore_cleans_up_the_pre_restore_snapshot`（`:1384`）/`a_failed_pre_restore_copy_leaves_the_source_untouched`（`:1404`）；rutilus 145 测试全过 | `app/src/backup.rs:246-327, 619-643` |
| free_port TOCTOU | NOTE | ✅ 已消除（2026-08-12，T-F，commit 83ff07f）：各绑定点改为端口重试——探测端口在探测与真实 bind 之间被抢占时（bind 返回 `AddrInUse`）换新端口重试，不再因竞态窗口失败（`is_raced_*_bind` 判定 + 重试循环）；`center_acceptor.rs` 的 `bind_acceptor_with_options` 探测可注入（`app/src/center_acceptor.rs:978-993`，`is_raced_bind` `:964-975`），确定性重试测试 `the_bind_retries_when_the_probed_port_was_grabbed`（`:1005`）证明竞态消除；另发现并修复同款内联第 5 处（`a_not_bound_refusal_from_the_center_converges_the_local_binding` 的 acceptor bind，`site_runtime.rs:2079`）；`connect_with_retry_stops_on_the_stop_signal` 的「无人监听端口」用途保持探测语义（其后无真实 bind 可重试，`center_client.rs:886`）；同款修复分布：`center_runtime.rs:901-927`、`center_client.rs:629-654`、`site_runtime.rs:1507-1544`（`is_raced_site_bind`/`is_raced_center_bind`/`bind_site`） | `app/src/center_acceptor.rs`；`app/src/center_runtime.rs`；`app/src/center_client.rs`；`app/src/site_runtime.rs` |
| 入网首刷绕端点门 | LOW | ✅ 已实现（2026-08-12，T-B，commit 4897b22）：端点登记（enrollment）后的首次刷新改走 `endpoint_read_gate`——`EndpointEnrollment::enroll` 在 `refresh.execute` 前经进程级端点读门获取 permit（`application/src/endpoint_enrollment.rs:168-179`，失败分类为 `EndpointEnrollmentError::InitialRefreshCoordination` 并新增 `EndpointReadGateError` 导出，`application/src/lib.rs:85-86`），首刷与并发批量刷新同一端点不再重叠（注释 `:158-167`）；`refresh.execute(endpoint_id)`（`:190`）在持门期间执行；web 侧新增 `InitialRefreshCoordination` 错误映射（`web/src/lib.rs:3042-3050`）；对抗测试 `initial_refresh_and_concurrent_batch_refresh_of_the_same_endpoint_never_overlap`（`endpoint_enrollment.rs:643`）钉死不重叠 | `application/src/endpoint_enrollment.rs:158-202`；`application/src/batch_refresh.rs:87-110`；`application/src/lib.rs` |
| 快照 ETag 接线（domain/persistence/operation_executor） | LOW | ✅ 已处置（决策 c，2026-08-12）：写路径语义已完备，快照 ETag 无独立消费价值，接线不实施。① 执行时读取 = 分派时刻可得的最新 ETag——PATCH 家族每次写都在同一次执行内重读目标文档并携带其 ETag（Boot `redfish_gateway.rs:6447-6451`、SecureBoot `:6496-6499`、UpdateService Patch `:6381-6384`、Control `:6220-6224`、Account 三写 `:6797/:6839-6841/:6883-6885`，commit 6128a17），已满足 §13.4「写操作必须使用 ETag」；快照 ETag 恒比执行时读取更旧（陈旧度随刷新节奏无界），不可替代。② 候选 a（快照 ETag 差异诊断）不成立：快照 ETag ≠ 执行时 ETag 是常态（期间发生一次刷新即变化），不是并发修改证据，比较产生噪音而非信号；412 冲突诊断已由 gateway 重读携带当前 ETag（`PreconditionReRead::Read { current_etag }`，`redfish_gateway.rs:12664-12674, 14014-14048` → `application_adapter.rs:366-367, 430-446` `DispatchVerdict::NotExecuted` → 操作 `Failed`，绝不重派/覆盖），无需新增信息通道（executor 的 Store 泛型也无快照读取角色，`operation_executor.rs:123-127`）。③ 候选 b（恢复路径带旧 ETag）结构性不存在：`recover_operation` 只重读判定、从不派发写（`operation_executor.rs:453-510`），gateway 从不接受执行外部 ETag（唯一例外 `LogEntriesETag` 是操作者经 ClearLog 命令 payload 显式提供的前置条件，`redfish_gateway.rs:6048, 6081`）。快照 ETag 保持只读侧既有角色（诊断展示与中心投影：`endpoint_resources.rs:1084`、`resource_diagnostics.rs:495`、`api/src/lib.rs:660-696, 1898-1952`、`center_sync.rs:1301-1303`）。§13.4「无 ETag 时保存操作前快照」条款由传输层 `If-Match: *` + 执行后重读覆盖（无并发保护，如实标注），与本次决策无关 | `domain/src/resource_snapshot.rs:606-655, 790, 827, 858`；`persistence/src/resource_snapshot_repository.rs:402, 553-554, 605-608`；`infra-redfish/src/redfish_gateway.rs:598-611, 6447-6451, 12664-12674, 14014-14048`；`application/src/operation_executor.rs:123-127, 453-510`；`operation-engine/src/`（无 etag 引用，已核实） |

> 以上偏差均为当前 master 的真实状态；对应设计条款见仓库根目录
> `redfish-management-product-final-design.md`。
