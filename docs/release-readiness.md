# Rutilus 发布就绪盘点（0.9.0 生产候选验收 + 1.0.0 全功能生产交付）

> 本文档供 0.9.0「生产候选」发布评审与 1.0.0「全功能生产交付」评审使用：
> 逐项对照设计文档 §0.9.0「验收」（`redfish-management-product-final-design.md:2812-2819`）
> 与 §1.0.0「发布条件」18 项（`:2829-2848`），并给出剩余工作分类与 1.0.0 就绪度结论。
>
> 方法与红线：只读代码 + 只写本文档。所有证据为当前 master 真实存在的 file:line 或已提交
> docs 的章节，每条新引用在本轮盘点中打开文件核实（见 §六 自检记录）。**严格区分「结构性
> 证据」（代码/门禁/测试钉死的事实）与「实测认证」（真实设备/演练/外部评估得出的结论）**：
> 结构证据不写成已实测，未做之事不声称已做。
>
> 状态标记沿用仓库文档：✅ 达成（结构或实测，表中注明性质）；🟡 部分（有结构证据，演练/
> 评估/发布级验证未做）；⏳ 待做（无代码或文档证据）。
>
> 修订说明：本版为 **E1 捕获点合并后复核版**（HEAD = 53b6402）。E1（commit ce2b8b3，§12.4
> 诊断解码失败生产捕获点：gateway 捕获 + SQLite 同代事务持久化）已合入，本文档先前标注
> 「E1 合并后需复验」的全部行号已逐条重核为当前 master 实际值（见 §五、§六）；迭代三/四
> 其余合并项（E3a Git Commit 嵌入、E3b Secret 扫描门禁、E3c N5 处置、E4 约束修复）已一并
> 登记。迭代五（H1/H2）已合入：UI 本地化基础层（commit 8e8ac6f：`ui/src/i18n.rs` 新增
> `strings_catalog!` 宏 / `Strings` 81 键 / `Lang` 骨架 / `const L`，lib.rs 导航与公共元素
> 文案改 `{L.x}` 引用）+ `web/assets/rutilus_ui.js/.wasm` 再生成（commit 53b6402，二次生成
> 字节一致），§三-A「UI 本地化」行已同步为 🟡 部分。全仓门禁复跑全绿：migration 30 /
> persistence 190+3 / application 293 / infra 291 / web 全过 / **ui 127** / rutilus 141 /
> security 门禁 7，clippy 全 crate 零警告、fmt 干净（2026-08-12）。

## 一、0.9.0 验收逐项对照（设计文档 §0.9.0「验收」）

验收原文：`redfish-management-product-final-design.md:2812-2819`。0.8.0 冻结基线事实
（47 账本 / 29 模块 / 43 操作 / 未映射 0）见 `docs/milestone-status.md` §一-§五。

| 验收项 | 状态 | 证据 | 剩余差距 / 前置条件 |
|---|---|---|---|
| P0/P1 缺陷清零 | ⏳ 发布评审流程项 | 仓库无公开缺陷台账；安全审查无 BLOCKER（`docs/security-review.md` §三） | 无缺陷台账即无「清零」的独立证据。前置条件：① 0.9.0 发布评审给出 P0/P1 清零结论（E1 捕获点已合入并通过全部门禁，门禁清单见 `ci.yml:3-21`） |
| 无已知凭据泄漏 | 🟡 部分 | 结构性证据链充分：BMC 凭据 at-rest 加密（`security/src/lib.rs:184-251`）、Master Key 不入库明文（`platform/src/master_key_file.rs`）、内存 Secret 包装与 Debug 脱敏、错误不回声（`security/src/master_key.rs:446-472`）、审计类型构造上禁秘密（`domain/src/audit.rs:318-394`）、API 不回声秘密（`web/tests/write_path.rs:784, 816, 918`）、Center 投影排除凭据（`docs/security-review.md` §二#4）、命令列与中心队列 at-rest 加密（`security/src/command_cipher.rs`）、备份包只有密文（`security/src/backup_package.rs:19-23`）；结论性判断见 `security-review.md` §4.4 | 仓库级独立 Secret 泄漏扫描已落地（E3b，`security/tests/secret_leak_gate.rs`）；运行时抓包/日志复核与外部安全评估未做（`security-review.md` §4.3）——「无**已知**泄漏」的条件性结论成立，但非独立认证。前置条件：运行时复核（§四-B）+ 可选外部评估 |
| 无已知重复执行 | ✅ 结构性 | 事件去重键（`domain/src/event.rs:383` `dedup_key`）、批量重投 no-op（`operation-engine/src/operation_engine.rs:1332` `create_batch_redelivery_is_a_no_op_that_never_duplicates_children`）、重复 offer 幂等（`application/src/center_sync.rs:3478` 拒绝态不可复活、`:3528` 完成态返回记录结果）、重连重复突发只生效一次（`center_sync.rs:4448` 风暴测试） | 无已知差距；前述证据均为自动化测试钉死的结构性事实 |
| 无已知错误成功报告 | 🟡 部分 | 写后重读验证系列（`infra-redfish/src/redfish_gateway.rs` `verifies_*` 测试群，如 `:29667`）、响应丢失→Unknown 不盲重试（`redfish_gateway.rs:28807` `classifies_a_dropped_connection_during_the_write_as_result_unknown`）、`docs/known-limitations.md` §七「HTTP 成功不等于业务成功」 | 结构性证据充分；「整体清零」是评审结论而非可自动化断言的事实。前置条件：0.9.0 发布评审对证据链复核并给出清零结论 |
| 三平台安装、升级、备份、恢复通过 | ⏳ 演练未执行 | 备份/恢复自动化往返已覆盖（`app/src/backup.rs:765` 往返保数据、`:799` 拒绝他实例包、`:825` 跨机恢复需源信封、`:912` 源口令对全新信封、`:944` 需停止实例、`:970` 拒绝未初始化目录、`:981` 拒绝不同产品版本）；恢复流程实现见 `docs/operations-manual.md` §六-§七 | 三平台（Windows/macOS/Linux）安装、升级、备份、恢复的**发布包级演练**未执行（§四-B）。前置条件：三平台环境 + 发布包 + 签名产物（签名本身为 C 类，见 §四-C） |
| Center/Site 长时间断线重连通过 | 🟡 部分 | 单连接语义（如 `center_sync.rs:2853` 断线退避重连）与**多连接并发重连风暴**（`center_sync.rs:4328` 全部 outbox 从最后 Ack 续传、`:4448` 重复突发幂等、`:4838` 心跳与重连交错、`:4968` 断线期间本地队列累积并按序排空）+ 重连进度重发（`:4615`）；合计 33 个测试全过（`docs/milestone-status.md:201`）；断线行为语义见 `docs/operations-manual.md` §5.3（心跳 30s、断线判定 90s、重连退避 120s） | 长时间（跨进程/跨天）真实断线演练未执行（§四-B）。前置条件：站点 + 中心运行环境 |

### 1.1 0.9.0「内容」逐项盘点（汇总）

设计 §0.9.0「内容」清单（`redfish-management-product-final-design.md:2778-2798`）的逐项
证据链已完整记录于 `docs/milestone-status.md` §7.1（2026-08-12 复核），此处只给汇总状态，
细节引用该节：

| 内容项 | 状态 | 关键证据位置 |
|---|---|---|
| 五厂商实验室 | ⏳ | `milestone-status.md:196`；§四-B |
| 所有 Fixture 回归 | 🟡 | 合成 mock 回归齐备，脱敏真实响应 fixture 目录尚无（`known-limitations.md:76-79`） |
| 故障注入 | 🟡 | §19.3 多数场景单进程覆盖（`milestone-status.md:198`）；跨进程剩余项见 §四-B |
| 跨平台 E2E | ✅ | `ci.yml:122-138`（windows/macos 任务，web/tests 9 个路径套件 + `app/tests/version.rs`） |
| 数据库压力 | ✅ | `persistence/tests/stress_capacity.rs` 3 测试（`:336, :585, :832`），规模常量对齐设计最低验证规模（`:47-52`） |
| 中心重连风暴 | ✅ | `center_sync.rs` 33 测试（风暴 4 + 重发 1，见上表） |
| 大文件更新 | 🟡 | 分块机制全链路覆盖（`milestone-status.md:202`）；真实固件端到端演练未做（§四-B） |
| Secret 泄漏检查 | ✅ | 结构性防护（`milestone-status.md:203`）+ 独立扫描门禁已落地（E3b：`security/tests/secret_leak_gate.rs`，3 规则 R1/R2/R3、7 测试；CI 独立步骤 `ci.yml:216-218` Secret leak gate，`cargo test --locked -p rutilus-security --test secret_leak_gate`，machete 之后、wasm32 之前，`if: matrix.is_default`，header 注记 `ci.yml:15-17`；运行时抓包/日志复核仍为 §四-B 演练项） |
| 权限测试 | ✅ | 角色掩码/中心站点作用域/限速/BMC 写权限拒绝（`milestone-status.md:204`） |
| 安全审查 | 🟡 | `docs/security-review.md` 已交付（8 范围 + §7.7 扫描，无 BLOCKER）；MINOR-1 已修复（`web/src/auth.rs:1214, 1221, 1242-1253, 1305`）；N5 已关闭（E3c 编译期 const assert，`web/src/lib.rs:1223`） |
| Migration 回归 | ✅ | `migration/tests/` 20 个测试文件（含 E4 防回归 `resource_feature_lists.rs`）；迁移总数 23；CI 门禁 `ci.yml:299-301` |
| 备份恢复演练 | 🟡 | 自动化往返 8 测试（见上表证据）；三平台演练未执行（§四-B） |
| 签名构建 / SBOM | ⏳ | 无签名与 SBOM 工具链证据（§四-C） |
| 用户/运维/支持矩阵/已知限制手册 | ✅ | `docs/user-manual.md`、`docs/operations-manual.md`、`docs/support-matrix.md`、`docs/known-limitations.md` |
| 性能容量测试 | 🟡 | 合成规模已实测（`docs/operations-manual.md` §九，2026-08-12 本机 debug 构建）；**发布级容量建议未发布**（设计要求「测试后发布真实容量建议」，`design:2810`）——见 §四-B |

### 1.2 最低验证规模对照

设计 §0.9.0「最低验证规模」（`design:2800-2808`）：单 Site ≥200 Endpoint、单 Center
≥100 Site、中心汇总 ≥5,000 Endpoint。合成规模压力套件已按该规模实测落地
（`stress_capacity.rs:47-52` 常量 200/100/5,000；实测数据
`operations-manual.md` §九），**不再是「仅测试目标」**；「测试后发布真实容量建议」
（`design:2810`）仍未完成。

## 二、1.0.0 发布条件 18 项逐条对照

1.0.0「全功能」定义（`design:2825-2828`）：**对 `NvRedfishReleaseBaseline` 所有公开功能
完成 100% 产品映射，并具备多服务器、单机、站点、中心、安全、任务、审计、备份、恢复和
跨平台交付所需的完整支撑能力。** 发布条件原文：`design:2829-2848`。

性质标注：**结构性** = 代码/门禁/测试钉死的事实，可复验；**实测** = 真实设备/演练/外部
评估得出的结论，有前置条件。

| # | 发布条件 | 状态 | 性质 | 证据（file:line） | 差距说明 |
|---|---|---|---|---|---|
| 1 | 能力账本 100% | ✅ | 结构性 | 账本 47 条 = 0.13.0 全部公开能力（`domain/src/capability.rs:401` 47 条、`:462` 14 OEM）；账本缺口为空（`milestone-status.md:82`，`release_baseline.rs:1236`）；账本 Hash 与协商 golden 钉死（`release_baseline.rs:1049-1052, 1577`；`center-protocol/src/negotiation.rs`） | 无。0.8.0 验收达成（`milestone-status.md` §二 验收 1） |
| 2 | 标准 feature 全覆盖 | ✅ | 结构性 | 编译完整面 58 个 = 0.13.0 全集 59 减 `default`；显式 17 个与 workspace 清单双向校验（`milestone-status.md:28-36`；`release_baseline.rs:79, 111`）；33 个标准账本条目全部落在编译面 | 「全覆盖」= 编译面完全覆盖，已由门禁钉死；设备侧实际暴露面是条件 8 的实测范围 |
| 3 | OEM feature 全覆盖 | ✅ | 结构性 | 14 个 `oem-*` 全编译（根 `Cargo.toml:35`；`domain/src/capability.rs:462`）；编译面与领域 OEM 账本同序逐一相等（`infra-redfish/src/lib.rs:158` 测试） | 无。probe-only 的 2 项（cper/fabrics）读取面如实登记（`milestone-status.md:153`） |
| 4 | 所有写操作均类型化 | ✅ | 结构性 | 43 个公开写操作全部经 `nv-redfish` 类型化面（`release_baseline.rs:677`；`milestone-status.md` §1.4）；NVIDIA 9 个 OEM action 均类型化（`support-matrix.md:124-130`） | 无 |
| 5 | 不存在原始 BMC 写请求 | ✅ | 结构性 | 唯一 `nv-redfish` 依赖 crate = infra-redfish（`infra-redfish/Cargo.toml:14`）；`UpstreamBmc = HttpBmc<NvHttpClient>` 传输注入（`redfish_gateway.rs:338, 1115`）；0.8.0 验收 4 达成（`milestone-status.md` §二 验收 4） | 无 |
| 6 | 不存在裸 SQL | ✅ | 结构性 | 机械门禁：迁移 crate 只允许 DDL 裸语句、DML 词全禁（`migration/tests/bare_sql_gate.rs:35, 40, 445, 456`）；表重建数据复制全部 SeaQuery（`milestone-status.md:119`） | 无 |
| 7 | 三平台单二进制发布 | 🟡 | 结构性（构建矩阵）+ 实测缺位 | 构建矩阵入 CI：x86_64 musl（`ci.yml:245-250`）、aarch64 musl cargo-zigbuild（`ci.yml:257-261`）、macOS Universal 2 lipo 合并 + `lipo -verify_arch x86_64 arm64` 校验（`ci.yml:280-295`）；三平台编译 + wasm32 UI 产物 diff（`ci.yml:63-72, 225-235`）；Windows ARM64 明确不入 CI（`ci.yml:263-270` 注释：hosted x64 runner 无 ARM64 MSVC 链接器与 SDK 导入库）；发布配置与 §5.4 一致（`Cargo.toml:110-116`；`rust-toolchain.toml` 已固定；Cargo.lock 已提交）；单二进制自包含边界（`support-matrix.md:85-88`） | ① Windows ARM64 发布目标无 CI 构建、无安装验证（§四-B，前置：原生 ARM64 runner 或本地 ARM64 主机）；② 三平台**发布包级**安装/运行验证并入条件 15 演练（§四-B）；③ 签名（条件 17）前置 |
| 8 | 五厂商标准能力验证 | ⏳ | 实测 | Mock 层已覆盖五厂商 profile（`test-support/src/mock_bmc/profile.rs:47-134`）；§19.1 Physical Device Test「五厂商至少各一台真实设备进入 1.0.0 认证矩阵」未达成（`design:2320-2322`；`known-limitations.md:78-79`） | 前置条件：五厂商真实设备实验室（§四-B）。当前结论只能是「基于上游类型面与 mock/fixture 验证」，不是实测认证（`known-limitations.md:79`） |
| 9 | Dell、HPE、Lenovo 上游 OEM 能力验证 | ⏳ | 实测 | Dell/HPE/Lenovo OEM 读取面已编译并映射（`support-matrix.md:113-118`）；真实设备验证未达成（同上） | 前置条件：Dell/HPE/Lenovo 设备各一台（§四-B）；验证范围限标准 feature + 上游已有 OEM feature，不声称覆盖全部 OEM API（`design:2326-2334`） |
| 10 | xFusion、Inspur 标准模式限制明确 | ✅ | 结构性（文档）+ 实测缺位 | 限制已明确成文：上游无 xFusion/Inspur OEM feature，只能用标准 Redfish 能力，OEM-only 标 `NotAvailableInNvRedfishBaseline`（`support-matrix.md:135-142`；`design:2336-2352`）；mock 变体验证标准模式行为 | 「限制明确」这一文档条件达成；设备侧标准模式验证并入条件 8（§四-B） |
| 11 | 所有异步操作可恢复 | ✅ | 结构性（恢复路径实测于自动化测试）+ 发布级演练缺位 | 升级流程含「恢复 Task 跟踪（扫描 WaitingRemote、重建 Session、继续读取 Task）」（`operations-manual.md:216-218`）；remote_tasks 迁移回归（`migration/tests/remote_tasks.rs`）；执行引擎恢复语义（`operation-engine`，`operations-manual.md` §七） | 跨进程重启恢复已有实现与自动化覆盖；真实升级演练（备份→停→换二进制→启动→任务恢复）并入 §四-B 演练 |
| 12 | 所有写操作有最终验证 | 🟡 | 结构性 | 写后重读验证系列与响应丢失→Unknown 语义（见 §一「无已知错误成功报告」行；`redfish_gateway.rs` `verifies_*` 测试群）；`known-limitations.md` §七「HTTP 成功不等于业务成功」 | 结构性证据充分；「所有写操作均有最终验证」的完整结论依赖 0.9.0 发布评审对证据链的复核与清零结论（§一） |
| 13 | Center 不保存 BMC Secret | ✅ | 结构性 | Center 投影只含 display_name/address/generation/health/resources，注释「the center never sees credentials or sessions」（`application/src/center_sync.rs:1282-1326`）；投影表无凭据列（`persistence/src/center_projection_repository.rs` 全文件 grep 无 credential/password/secret 命中）；安全审查范围 4 结论（`security-review.md` §二#4）；Site 本地解密边界（凭据表只存在于 Site 库） | 无。0.7.0 验收「Center 不保存 BMC 密码」达成（`design:2728-2735`） |
| 14 | Site 脱离 Center 完整运行 | ✅ | 结构性 | 0.7.0 验收达成（`design:2728-2735`）；断线后端点刷新/操作/本地 GUI 继续运行（`operations-manual.md:161`）；断线期间本地队列累积、重连按序排空（`center_sync.rs:4968`）；中心不可用不影响站点已接受任务（`operations-manual.md:110`） | 无 |
| 15 | 备份恢复通过 | 🟡 | 结构性（自动化往返 8 测试）+ 实测缺位 | `app/src/backup.rs:765, 799, 825, 912, 944, 970, 981`（见 §一第 5 行证据）；流程与身份校验（`operations-manual.md` §六）；§20.1/20.2 对照（`design:2403-2446`） | 三平台安装/升级/备份/恢复演练未执行（§四-B）——0.9.0 验收同项 |
| 16 | 数据库 Migration 通过 | ✅ | 结构性 | 23 个 migration（`operations-manual.md:221`；`migration/tests/initial_storage.rs`；E1/E4 新增 `m20260812_000001_resource_decode_failures` 与 `m20260812_000002_resource_feature_lists`）；20 个测试文件回归 + CI 独立门禁（`ci.yml:299-301`）；裸 SQL 机械门禁（条件 6）；迁移前自动备份（`persistence/src/lib.rs:510`） | 无 |
| 17 | 正式签名和 SBOM | ⏳ | 待做 | 仓库无签名工具链/CI 步骤证据（`milestone-status.md:208-209`）；SBOM 无生成工具与产物（同上）；§5.4 发布配置要求（`design:647-657`）；另：§5.4「构建结果嵌入 Git Commit」**已实现**（E3a：CI 在 job 级注入 `RUTILUS_GIT_COMMIT`（`ci.yml:45-55`），二进制经 `GIT_COMMIT` 常量嵌入（`app/src/main.rs:38-40`），`rutilus version` 输出三行（`:733-737`），本地无该变量时降级 `dev`；`app/src/standalone_runtime.rs:1456` WebProductInfo 嵌入） | 前置条件：Windows Authenticode 证书、macOS Developer ID + 公证账号、Linux 签名密钥/服务、SBOM 工具（cargo-cyclonedx 等）（§四-C）。**1.0.0 发布硬条件** |
| 18 | 用户、运维、兼容和故障文档完成 | ✅ | 结构性 | `docs/user-manual.md`（431 行）；`docs/operations-manual.md`（数据/服务/备份/升级/诊断/容量，§8.1 含 `--log-format json`）；`docs/support-matrix.md`（基线/平台/厂商/不承诺）；`docs/known-limitations.md`（OutOfScope/依赖风险/测试基建局限/容量/偏差）；故障语义与诊断（`operations-manual.md` §八、`known-limitations.md` §七） | 「故障文档」由 known-limitations（已知限制与偏差）+ operations §八（doctor/诊断）承担，与设计 §0.9.0 内容一致；故障注入演练结果文档待 §四-B 完成后补充 |

## 三、剩余工作分类

### A. 代码/CI 可做（不依赖外部资源，可直接进入迭代）

| 工作项 | 状态 | 负责方 | 前置条件 | 证据/来源 |
|---|---|---|---|---|
| §12.4 诊断解码失败**生产捕获点**（gateway 捕获 + SQLite 持久化） | ✅ 已合入（E1，commit ce2b8b3） | 全组评审复验（证据链见下） | 无（已合并，全部门禁复跑通过） | 网关捕获：`DecodeFailureObservation`（`infra-redfish/src/redfish_gateway.rs:8720`），捕获函数 `capture_fetch_failure`/`capture_projection_failure`/`capture_segment_decode_failure`（`:8904, :8931, :8977`），刷新结果经 `outcome.decode_failures()` 流出（`:8831`）；同代事务提交：`persistence/src/resource_snapshot_repository.rs:81-147`（`commit_resource_generation` 在快照同一事务内写 `resource_decode_failures`），生产链路 `application/src/endpoint_refresh.rs:350-355` 直连；新表 + entity（`entity/src/lib.rs:28`、`entity/src/resource_decode_failures.rs:13`）+ 迁移 `m20260812_000001`（E4 由 `m20260812_000002` 重建约束为领域枚举 47 码）；web 端到端 7 测试（`web/tests/diagnostics_path.rs:838-1175`，含 `refresh_capture_flows_into_the_diagnostics_response` `:998`）；现状登记见 `known-limitations.md` §八「§12.4」行 |
| 独立 Secret 泄漏扫描（仓库级自动扫描 + 运行时抓包/日志复核） | ✅ 仓库级已落地（E3b）/ 运行时复核待做 | 安全评审 + CI | 无（仓库级部分）；运行时复核需三平台演示环境（可并入 B） | `security/tests/secret_leak_gate.rs`：3 规则（R1 硬编码秘密 / R2 内嵌私钥 PEM / R3 明文输出宏泄露）、7 测试（`:974, :985, :996, :1006, :1062, :1096, :1130`）、白名单 = `ALLOWED_CONSTANT_HITS` 2 处（path+line+name+literal 四元组绑定，`app/src/backup.rs:83, 84` 备份条目名）；门禁为 CI 独立步骤（`ci.yml:216-218` Secret leak gate，`cargo test --locked -p rutilus-security --test secret_leak_gate`，`if: matrix.is_default`，machete 之后、wasm32 之前；header 注记 `ci.yml:15-17`）；运行时抓包/日志复核仍为 §四-B 项（`security-review.md:110, 128-135`） |
| UI 本地化 | 🟡 部分：基础层已落地（H1 8e8ac6f：`ui/src/i18n.rs` 的 `strings_catalog!` 宏 + `Strings` 81 键 + `Lang` 骨架（含 `En`）+ `const L`，lib.rs 导航/公共元素文案改 `{L.x}` 引用；H2 53b6402：`web/assets` 产物再生成字节一致） | 前端组 | 深度翻译（视图标题/空态/不可用消息/`CommandFamilyView` 标签/facts 词汇表/健康词汇/`OEM_UNSUPPORTED_NOTICE`）与语言选择器为后续迭代；1.0.0 定义与 18 项条件均不涉及，**不阻塞 1.0.0** | `known-limitations.md:106`；`milestone-status.md:236` |
| N5 `unreachable!` 处置（可选，NOTE 级） | ✅ 已完成（E3c） | — | 无 | `security-review.md` §三 N5 已关闭：`web/src/lib.rs:1223` 编译期 `const _: () = assert!(rutilus_api::OVERVIEW_RECENT_EVENTS > 0);` 钉死常量正性（注释 `:1213-1222`），运行时 guard 保留为已被断言证明不可达的防御分支（`:1224-1226`） |
| 发布级 CI 扩展（Windows ARM64 原生 runner） | 🟡 | CI/基础设施 | 原生 ARM64 Windows runner 或本地 ARM64 主机验证后另行处理 | `ci.yml:263-270` 注释 |

### B. 依赖演练环境（物理设备 / 规模环境 / 三平台流程）

| 工作项 | 说明 | 前置条件 | 对应 1.0.0 条件 |
|---|---|---|---|
| 五厂商实验室 / 真实设备认证矩阵 | Dell/HPE/Lenovo/xFusion/Inspur 各至少一台真实设备进入认证矩阵；验证标准 feature + 上游已有 OEM feature（Dell/HPE/Lenovo）、标准模式限制（xFusion/Inspur） | 五厂商设备与网络环境 | 8、9、10 |
| 真实响应 fixture 目录 | 五厂商各固件版本脱敏真实响应，随 nv-redfish 升级回归（§19.1 Fixture Test） | 设备抓取 → 脱敏 → 入库 | 8、9 的回归基础 |
| 进程级故障注入演练 | 产品进程在任务中被终止、BMC 更新中重启、SQLite 写入中断、磁盘空间不足（§19.3 剩余项，跨进程形态） | 三平台测试环境 | 11、12 的实测面 |
| 大文件更新端到端演练 | 真实大固件文件的上传→校验→分发→应用 | 真实固件制品 + 设备或等价测试台 | 12 的实测面 |
| 三平台安装/升级/备份/恢复演练 | 0.9.0 验收第 5 项、1.0.0 条件 15：Windows/macOS/Linux 各跑安装→备份→升级→恢复→任务恢复 | 三平台机器 + 发布包 + 签名产物（签名属 C） | 7、15 |
| Center/Site 长时间断线重连演练 | 0.9.0 验收第 6 项：跨进程/跨天真实断线（自动化风暴已覆盖单进程形态） | 站点 + 中心运行环境 | 14 的实测面 |
| 发布级容量建议 | 设计要求「测试后发布真实容量建议」：release 构建 + 正式规模环境复核后发布（当前仅开发机 debug 合成数据，`operations-manual.md` §九） | release 构建 + 正式规模环境 | 7 的配套交付物 |
| Windows ARM64 发布验证 | `aarch64-pc-windows-msvc` 发布目标：构建 + 安装/运行验证 | 原生 ARM64 Windows runner 或本地 ARM64 主机 | 7 |

### C. 依赖发布管道（外部证书 / 签名服务 / 发布流程）

| 工作项 | 说明 | 前置条件 | 对应条款 |
|---|---|---|---|
| Windows Authenticode 签名 | 发布包代码签名 | 代码签名证书（含时间戳服务） | `design:654`；条件 17 |
| macOS 签名与公证 | Developer ID 签名 + notarization + staple | Apple Developer 账号与证书 | `design:655`；条件 17 |
| Linux 独立签名 | 独立签名 + 公钥发布路径 | 签名密钥/签名服务 | `design:656`；条件 17 |
| SBOM 生成与发布 | cargo-cyclonedx 等工具生成 SPDX/CycloneDX，随发布产物发布 | 工具选型与发布流程挂接 | `design:652`；条件 17 |
| §5.4 构建信息嵌入补齐 | ✅ 已完成（E3a）：Git Commit 经 job 级 `RUTILUS_GIT_COMMIT` 注入（`ci.yml:45-55`）、`GIT_COMMIT` 常量嵌入（`app/src/main.rs:38-40`）、`rutilus version` 三行输出（`:733-737`）、本地无变量时降级 `dev`（`app/tests/version.rs:8-11, 27-36` 派生断言）；§5.4 四项构建结果（产品版本 + Git Commit + 基线 + 账本 Hash）已全部嵌入 | 无 | `design:657` |
| SHA-256 校验清单 | 发布产物清单随包发布 | 发布流程 | `design:653` |

## 四、1.0.0 就绪度结论

按 1.0.0 定义（`design:2825-2828`）拆解：

**1. 功能映射面（「NvRedfishReleaseBaseline 所有公开功能 100% 产品映射」）：结构性 100% 达成。**
条件 1-6 全部 ✅：47 账本 / 29 模块 / 43 操作 / 未映射 0 由 0.8.0 冻结 + 门禁钉死
（`milestone-status.md` §一-§二），写操作全类型化、无原始 BMC 写请求、无裸 SQL 均为机械
门禁可复验事实。此面**不依赖外部资源**；E1 已合入且 Release Baseline / Capability Ledger /
Migration 门禁已复跑通过（`ci.yml:297-320`），本版行号均按合并后 master 复核。

**2. 支撑能力面（安全、任务、审计、备份、恢复、跨平台交付）：结构性支撑充分，实测认证缺位。**
- 已结构达成：Center 不保存 BMC Secret（13 ✅）、Site 脱离 Center 完整运行（14 ✅）、
  数据库 Migration（16 ✅）、文档四件套（18 ✅）、异步操作恢复实现（11 ✅ 结构性）。
- 缺实测认证：真实设备验证（8/9/10 ⏳）、三平台备份恢复演练（15 🟡）、所有写操作最终
  验证的评审清零结论（12 🟡）、发布级容量建议（🟡）。
- 硬缺口：签名与 SBOM（17 ⏳）——这是唯一**完全无进展**的 1.0.0 硬条件，且依赖外部证书
  与账号（C 类），应最早启动以并行于 B 类演练（Git Commit 嵌入已补齐，见条件 17）。

**3. 差距清单（按 1.0.0 发布阻塞度）：**

| 级别 | 差距 | 类别 | 前置条件 |
|---|---|---|---|
| 阻塞（硬条件未达成） | 条件 17 签名与 SBOM | C | 证书/账号/签名服务/工具选型 |
| 阻塞（硬条件未达成） | 条件 8/9/10 五厂商真实设备验证 | B | 五厂商设备 |
| 阻塞（硬条件未达成） | 条件 15 三平台备份恢复演练（0.9.0 验收第 5 项同） | B | 三平台 + 发布包（含签名，链条依赖 C） |
| 阻塞（硬条件未达成） | 条件 7 的 Windows ARM64 发布目标验证 | B/基础设施 | 原生 ARM64 runner |
| 评审前须完成 | 0.9.0 验收第 1/4 项评审结论（P0/P1 清零、错误成功报告清零） | 评审流程 | 上述证据链 |
| 评审建议完成 | Secret 泄漏扫描的运行时复核（仓库级门禁已落地，E3b） | A（运行时复核并入 B） | 三平台演示环境 |
| 评审建议完成 | 发布级容量建议 | B | release 构建 + 正式规模环境 |
| 不阻塞 | UI 本地化（基础层已落地，深度翻译与语言选择器为后续迭代） | A | 后续迭代 |

**4. 结论：** 0.9.0 六项验收中 1 项 ✅、3 项 🟡、2 项 ⏳，**尚不满足 0.9.0 发布条件**——
缺口全部集中在「评审流程结论」与「B/C 类演练/管道」，无结构性缺陷登记（安全审查无
BLOCKER；N5 已关闭、Secret 扫描门禁已落地、E1 捕获点与 E4 约束修复已合入）。1.0.0 的
功能映射面已结构性 100% 达成；距 1.0.0 发布的差距为**可枚举、有明确前置条件的 B/C 类
工作 + 评审流程结论**，不存在未知的架构性风险。建议路径：C 类（证书/签名/SBOM 启动，
链路最长）先行并尽早启动 B 类设备与三平台环境，B 类逐项执行并以演练结果回填本文档
§一/§二状态。

## 五、引用与复验纪律

- 本版（HEAD = 53b6402）已消除全部「E1 合并后需复验」标注：E1（commit ce2b8b3）合入后，
  原标注项已逐条按合并后 master 重核（§六记录）。E1/E3a/E3b/E3c/E4 触面（infra-redfish /
  persistence / entity / migration / application / web / app / ci.yml）的每个 file:line 均在
  本轮打开文件核实。
- 门禁复跑（2026-08-12，HEAD bfb001e）：`ci.yml:297-320`（Migration、Capability Ledger、
  Release Baseline）与全 workspace 测试全绿（migration 30 / persistence 190+3 / application
  293 / infra 291 / web 全过 / rutilus 141 / security 门禁 7），clippy 全 crate 零警告、fmt 干净。
- 引用自检记录见下节（每个 file:line 均在本轮打开核实）。

## 六、引用自检记录（2026-08-12，HEAD 53b6402 复核）

本轮逐一打开核实的引用（含全部 E1/E3a/E3b/E3c/E4 触面）：

| 引用 | 核实结果 |
|---|---|
| `design:2778-2819`（§0.9.0 内容/规模/验收）、`:2823-2848`（1.0.0 定义与 18 项）、`:2280-2397`（§19 测试/故障注入/CI 门槛）、`:2403-2464`（§20 备份恢复升级）、`:633-657`（§5.4 发布配置）、`:2728-2766`（0.7.0/0.8.0 验收） | 打开核实，行号一致（设计文档冻结，未变） |
| `domain/src/capability.rs:401, 462`（47 账本 / 14 OEM） | 打开核实，`:401` 47 条、`:462` 14 条 |
| `domain/src/event.rs:383`（dedup_key）、`domain/src/audit.rs:318-394`（审计构造上禁秘密） | 打开核实，行号一致 |
| `operation-engine/src/operation_engine.rs:1332`（批量重投 no-op 测试）、`:986`（时钟回拨） | 打开核实，行号一致 |
| `release_baseline.rs:59, 68, 79, 111, 177, 280-285, 296-308, 372, 646, 677, 745, 778, 790, 1025, 1039, 1049-1052, 1236, 1395, 1422, 1457, 1471, 1506-1513, 1517, 1577, 1589, 1638, 1688, 1705, 1734` | 打开核实，全部一致（E1/E3 未触达该文件） |
| `app/src/main.rs:27`（PRODUCT_VERSION）、`:38-40`（GIT_COMMIT，E3a）、`:58-64`（LogFormat 枚举）、`:97, 144`（backup/restore 子命令）、`:255-273`（init_tracing）、`:733-737`（version 三行输出） | 打开核实（旧引用 38-39/240-258/720 漂移，已按实际值引用） |
| `app/tests/version.rs:8-11, 27-36`、`app/tests/log_format.rs:7-10, 23-28`（三行派生断言，E3a） | 打开核实 |
| `app/src/backup.rs:765, 799, 825, 912, 944, 970, 981`（备份恢复 7 测试）、`:83-84`（备份条目名常量） | 打开核实，行号一致 |
| `app/src/standalone_runtime.rs:1456`（WebProductInfo 嵌入）、`app/src/site_runtime.rs:568` | 打开核实（旧 1454 漂移 +2） |
| `web/src/auth.rs:83, 89-93, 502, 851-854, 851-925, 938-944, 1061-1068, 1082-1107, 1135-1147, 1188-1201, 1214, 1221, 1242-1253, 1305, 1467（bootstrap_complete）, 1616, 1672, 1963-1967, 2023-2027, 2119-2168, 2185-2187, 2581`（M1 哑 Argon2id 与限速/会话/审计面） | 打开核实（旧 1409-1555/1609-1615/1903-1910/1965-1970/2042-2072/2126-2161/2523 漂移，已按实际值引用） |
| `web/src/lib.rs:108`（ARTIFACT_CHUNK_BODY_LIMIT）、`:911`（DefaultBodyLimit）、`:1223`（N5 编译期 const assert，E3c）、`:1368`（AUDIT_QUERY_MAX_LIMIT）、`:1374`（credential_inventory）、`:1454`（begin_endpoint_trust）、`:3961-3991`（资源诊断投影含 decode_failures）、`:9316`（password_verifications 计数）、`:10666, :10730`（两分支计数断言）、`:10856`（role_masks 测试）、`:11729, :11773`（中心站点作用域）、`:6225`（secret-free 清单测试） | 打开核实（旧 97-107/908-911/1347-1350/1352-1379/1432-1456/3949/9247/10649/10713/10525/11398/11442/6156 漂移，已按实际值引用） |
| `web/tests/write_path.rs:784, 816, 918`（secret-free 测试） | 打开核实（旧 783/815/917 各 +1） |
| `web/tests/diagnostics_path.rs`（7 个测试：`:838, :893, :935, :998, :1076, :1143, :1175`，E1 新增 `refresh_capture_flows_into_the_diagnostics_response` `:998`） | 打开核实（旧 6 个测试 651/706/748/811/878/910 漂移） |
| `ui/src/lib.rs:2773`（ConsoleView::ALL 17 视图）、`:5032`（CommandFamilyView::ALL 9 家族）、`:6290-6296`（telemetry 表单拒绝）、`:11132-11141`（later-milestone 文案串 `:11139`）、`:15277-15288`（DiagnosticsReady 只读区块，含 decode_failures 投影） | 打开核实（旧 2772/4955/6219/11064 漂移，已按实际值引用；H1 合入后该文件行内替换净 -2，文案串 `:11141`→`:11139`、诊断区块 `:15279-15290`→`:15277-15288`） |
| `ui/src/i18n.rs`（`strings_catalog!` 宏 `:34-63`、81 键 `:65-235`、`Lang` `:237-251`、`const L` `:259`、3 测试 `:268-308`）、`ui/src/lib.rs:45`（`mod i18n`）、`:11729`（`aria-label="Loading"` 未抽取）、tests 模块 40 处翻译敏感字面量断言（与目录值同串，如 `:20265, :22430-22432, :22466-22475`）、`web/assets/rutilus_ui.js` + `rutilus_ui_bg.wasm`（H2 再生成字节一致） | 打开核实（H1/H2 新引用；设计文档全文无「本地化/i18n」条目、§5.1 为「单二进制」定义——印证 i18n.rs 头注释 §5.1 引用不可核验的 MINOR） |
| `center-protocol/src/lib.rs:50, 59, 62, 67, 75, 383`、`negotiation.rs:162, 269`、`framing.rs:18-31, 176-199, 219-238` | 打开核实，行号一致 |
| `Cargo.toml:14`（workspace 版本 0.9.0）、`:35`（16 个 nv-redfish feature）、`:110-116`（§5.4 发布配置一致）、`infra-redfish/Cargo.toml:14`、`Cargo.lock:2486-2490`、`deny.toml:21-24, 29-34` | 打开核实，行号一致 |
| `rust-toolchain.toml` 存在、Cargo.lock 已提交 | 打开核实 |
| `ci.yml`：`:3-21`（门禁清单注释，含 secret-leak gate `:15-17`）、`:45-55`（RUTILUS_GIT_COMMIT job 级注入，E3a）、`:63-72`（三平台矩阵）、`:112-114`（全 workspace Test）、`:122-138`（跨平台 E2E）、`:188-196`（cargo audit）、`:216-218`（Secret leak gate 独立步骤，E3b/G1）、`:225-235`（wasm32 UI 产物 diff）、`:245-250`（musl x86_64）、`:257-261`（aarch64 zigbuild）、`:263-270`（Windows ARM64 不入 CI 注释）、`:280-295`（Universal 2 + lipo verify_arch）、`:299-301`（Migration 门禁）、`:306-308`（Capability Ledger）、`:318-320`（Release Baseline） | 打开核实（E3a 注入段 +3、G1 Secret gate 步骤段再 +17，两阶段漂移后按实际值引用） |
| E1 触面（合并后复核）：`redfish_gateway.rs:338, 1115, 8720, 8831, 8904, 8931, 8977`（捕获点）、`resource_snapshot_repository.rs:81-147`（同代事务）、`endpoint_refresh.rs:350-355`（生产链路）、`endpoint_inventory.rs:47, 94, 105, 123`、`resource_diagnostics.rs:36, 249, 430`、`entity/src/lib.rs:28`、`entity/src/resource_decode_failures.rs:13`、`migration/src/m20260812_000001_resource_decode_failures.rs`、`migration/src/m20260812_000002_resource_feature_lists.rs`、`migration/tests/resource_feature_lists.rs:248`、`persistence/src/backup_snapshot.rs:624-627`（backup_applied 24 / supported 23） | 打开核实，按合并后行号引用 |
| E3b 触面：`security/tests/secret_leak_gate.rs`（R1/R2/R3 `:21-42`、`ALLOWED_CONSTANT_HITS` `:318-331`、7 测试 `:974-1130`） | 打开核实 |
| `stress_capacity.rs:47-52, 336, 585, 832`（3 测试）；`center_sync.rs:2853, 3478, 3528, 3693, 4328, 4448, 4615, 4838, 4968`（风暴/幂等/重发） | 打开核实（旧 582/829/3477/3527/3692/4327/4447/4614/4837/4967 漂移 +1~3，已按实际值引用） |
