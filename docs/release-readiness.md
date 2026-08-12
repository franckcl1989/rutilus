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
> 修订说明：本版为 **迭代七合入后复核版**（HEAD = 61b9cc5）。迭代六（H4/H5）已合入：
> **UI 本地化完整落地**（H5 d3f7769：`strings_catalog!` 目录扩至 827 键 En/Zh 双语、
> `Lang::{En, Zh}` 运行时语言选择器、URL fragment 持久化（`#lang=`，纯函数 `ui/src/i18n.rs:1915-1936`
> + wasm 薄封装 `ui/src/lib.rs:11607-11635`）；0f91c17 `web/assets/rutilus_ui.js/.wasm` 再生成）
> 与**发布管道代码侧**（H4 34503ea + d77d54e：`scripts/` 5 脚本 + ci.yml `release-artifacts`
> job，证书到位即启用）。深度审查批次（2026-08-12 多角色多维度）已合入 9 个修复提交
> （0984fd4 backup 断言派生 / e8424df secret gate strings_catalog 宏体豁免 /
> e611ed7 test-support 借用 / 8147bc9 认证边界硬化 B1-B4 / 1711329 迁移 down 先子后父 /
> 6128a17 ETag 携带 + 412 专用路径 / 02370db 端点读门 + 恢复判定 / fb660d5 + a4950fc i18n 槽位
> 与本地化 + 产物）：52 项发现、16 项对抗验证、2 HIGH + 13 MEDIUM 已修复、1 项此前结论被推翻
> （M1 残留面，security-review §三 M1 行），详见 `milestone-status.md` §7.4。**迭代七
> （2026-08-12）已合入 9 个提交**（84451b9 mock-bmc 统一二进制 / 044bae2 AMI/HPE 真网关 E2E /
> c4dd335 i18n fragment 纯函数测试 / 8482d85 decode-failures 贯通测试 / 4897b22 入网首刷走
> 端点读门 / e7aef53 限流器桶键剪枝 / 02459dc 恢复前快照 / 83ff07f free-port 竞态消除 /
> 61b9cc5 secret-gate 白名单行号 83/84→88/89 对齐 backup.rs 漂移，门禁漂移检测触发-修复
> 闭环——文档行号值不受该提交影响），
> §九 遗留 8 项清零 + T-C 快照 ETag 决策，三批五维审计 APPROVE，详见 `milestone-status.md`
> §7.5；§一/§二相关行已按新事实更新（备份恢复行补预快照三态、条件 12 的快照 ETag 差距改为
> 已处置）、**本轮所有受影响 file:line 已逐条打开文件重核为当前 master 实际值**（auth.rs
> T-D +263 净行、backup.rs T-E +431 净行、batch_refresh.rs/endpoint_enrollment.rs/web
> lib.rs/ui i18n.rs/ui lib.rs/test-support/app 四文件等漂移，见 §六）。**门禁复跑全绿
> （2026-08-12，master 61b9cc5）：fmt 干净、clippy `-D warnings` 全 workspace 零警告、
> 1723 测试 0 失败**（`cargo test --workspace -- --list` 口径：lib/集成 1723 + doc 1 = 1724；
> per-crate：migration 30 / persistence 190+3 / application 301 / infra 291 /
> test-support 55 / web 133 / ui 141（含 15 个 i18n 测试）/ rutilus 145 / security 门禁 8）。

## 一、0.9.0 验收逐项对照（设计文档 §0.9.0「验收」）

验收原文：`redfish-management-product-final-design.md:2812-2819`。0.8.0 冻结基线事实
（47 账本 / 29 模块 / 43 操作 / 未映射 0）见 `docs/milestone-status.md` §一-§五。

| 验收项 | 状态 | 证据 | 剩余差距 / 前置条件 |
|---|---|---|---|
| P0/P1 缺陷清零 | ⏳ 发布评审流程项 | 仓库无公开缺陷台账；安全审查无 BLOCKER（`docs/security-review.md` §三） | 无缺陷台账即无「清零」的独立证据。前置条件：① 0.9.0 发布评审给出 P0/P1 清零结论（E1 捕获点已合入并通过全部门禁，门禁清单见 `ci.yml:3-24`） |
| 无已知凭据泄漏 | 🟡 部分 | 结构性证据链充分：BMC 凭据 at-rest 加密（`security/src/lib.rs:184-251`）、Master Key 不入库明文（`platform/src/master_key_file.rs`）、内存 Secret 包装与 Debug 脱敏、错误不回声（`security/src/master_key.rs:446-472`）、审计类型构造上禁秘密（`domain/src/audit.rs:318-394`）、API 不回声秘密（`web/tests/write_path.rs:784, 816, 918`）、Center 投影排除凭据（`docs/security-review.md` §二#4）、命令列与中心队列 at-rest 加密（`security/src/command_cipher.rs`）、备份包只有密文（`security/src/backup_package.rs:19-23`）；结论性判断见 `security-review.md` §4.4 | 仓库级独立 Secret 泄漏扫描已落地（E3b，`security/tests/secret_leak_gate.rs`）；运行时抓包/日志复核与外部安全评估未做（`security-review.md` §4.3）——「无**已知**泄漏」的条件性结论成立，但非独立认证。前置条件：运行时复核（§四-B）+ 可选外部评估 |
| 无已知重复执行 | ✅ 结构性 | 事件去重键（`domain/src/event.rs:383` `dedup_key`）、批量重投 no-op（`operation-engine/src/operation_engine.rs:1332` `create_batch_redelivery_is_a_no_op_that_never_duplicates_children`）、重复 offer 幂等（`application/src/center_sync.rs:3478` 拒绝态不可复活、`:3528` 完成态返回记录结果）、重连重复突发只生效一次（`center_sync.rs:4448` 风暴测试） | 无已知差距；前述证据均为自动化测试钉死的结构性事实 |
| 无已知错误成功报告 | 🟡 部分 | 写后重读验证系列（`infra-redfish/src/redfish_gateway.rs` `verifies_*` 测试群，如 `:29667`）、响应丢失→Unknown 不盲重试（`redfish_gateway.rs:28807` `classifies_a_dropped_connection_during_the_write_as_result_unknown`）、**412 冲突专用路径**（`CommandExecutionError::PreconditionFailed`：BMC `412` 证明写未执行 + 重读目标不覆盖并发变更，`redfish_gateway.rs:598-611, 12653-12690, 14002-14062`，深度审查批次 commit 6128a17）、`docs/known-limitations.md` §七「HTTP 成功不等于业务成功」 | 结构性证据充分；「整体清零」是评审结论而非可自动化断言的事实。前置条件：0.9.0 发布评审对证据链复核并给出清零结论 |
| 三平台安装、升级、备份、恢复通过 | ⏳ 演练未执行 | 备份/恢复自动化往返已覆盖（`app/src/backup.rs:1051` 往返保数据、`:1095` 拒绝他实例包、`:1121` 跨机恢复需源信封、`:1208` 源口令对全新信封、`:1240` 需停止实例、`:1266` 拒绝未初始化目录、`:1277` 拒绝不同产品版本；**迭代七 T-E 02459dc 补恢复前预快照三态**：`:1307` 失败保留供回滚、`:1384` 成功清除、`:1404` 拷贝失败不动源目录）；恢复流程实现见 `docs/operations-manual.md` §六-§七 | 三平台（Windows/macOS/Linux）安装、升级、备份、恢复的**发布包级演练**未执行（§四-B）。前置条件：三平台环境 + 发布包 + 签名产物（签名本身为 C 类，见 §四-C） |
| Center/Site 长时间断线重连通过 | 🟡 部分 | 单连接语义（如 `center_sync.rs:2853` 断线退避重连）与**多连接并发重连风暴**（`center_sync.rs:4328` 全部 outbox 从最后 Ack 续传、`:4448` 重复突发幂等、`:4838` 心跳与重连交错、`:4968` 断线期间本地队列累积并按序排空）+ 重连进度重发（`:4615`）；合计 33 个测试全过（`docs/milestone-status.md:240`）；断线行为语义见 `docs/operations-manual.md` §5.3（心跳 30s、断线判定 90s、重连退避 120s） | 长时间（跨进程/跨天）真实断线演练未执行（§四-B）。前置条件：站点 + 中心运行环境 |

### 1.1 0.9.0「内容」逐项盘点（汇总）

设计 §0.9.0「内容」清单（`redfish-management-product-final-design.md:2778-2798`）的逐项
证据链已完整记录于 `docs/milestone-status.md` §7.1（2026-08-12 复核），此处只给汇总状态，
细节引用该节：

| 内容项 | 状态 | 关键证据位置 |
|---|---|---|
| 五厂商实验室 | ⏳ | `milestone-status.md:235`；§四-B |
| 所有 Fixture 回归 | 🟡 | 合成 mock 回归齐备，脱敏真实响应 fixture 目录尚无（`known-limitations.md:76-79`） |
| 故障注入 | 🟡 | §19.3 多数场景单进程覆盖（`milestone-status.md:237`）；跨进程剩余项见 §四-B |
| 跨平台 E2E | ✅ | `ci.yml:130-147`（windows/macos 任务，web/tests 9 个路径套件 + `app/tests/version.rs`） |
| 数据库压力 | ✅ | `persistence/tests/stress_capacity.rs` 3 测试（`:336, :585, :832`），规模常量对齐设计最低验证规模（`:47-52`） |
| 中心重连风暴 | ✅ | `center_sync.rs` 33 测试（风暴 4 + 重发 1，见上表） |
| 大文件更新 | 🟡 | 分块机制全链路覆盖（`milestone-status.md:241`）；真实固件端到端演练未做（§四-B） |
| Secret 泄漏检查 | ✅ | 结构性防护（`milestone-status.md:242`）+ 独立扫描门禁已落地（E3b：`security/tests/secret_leak_gate.rs`，3 规则 R1/R2/R3、8 测试、`test-support` crate 目录级豁免（E3b 原始提交 eefde7e）`:55-59, 1000-1002`、深度审查批次 e8424df 补 `strings_catalog!` 宏体结构豁免（CATALOG_MACRO 帧识别 + 新测试 `strings_catalog_macro_bodies_are_copy_construction_not_secret_assignments` `:1195`）；CI 独立步骤 `ci.yml:225-227` Secret leak gate，`cargo test --locked -p rutilus-security --test secret_leak_gate`，machete 之后、wasm32 之前，`if: matrix.is_default`，header 注记 `ci.yml:15-17`；运行时抓包/日志复核仍为 §四-B 演练项） |
| 权限测试 | ✅ | 角色掩码/中心站点作用域/限速/BMC 写权限拒绝（`milestone-status.md:243`） |
| 安全审查 | 🟡 | `docs/security-review.md` 已交付（8 范围 + §7.7 扫描，无 BLOCKER）；MINOR-1 已修复（`web/src/auth.rs:1307, 1314, 1335-1346, 1438`）；N5 已关闭（E3c 编译期 const assert，`web/src/lib.rs:1223`）；深度审查批次补认证边界硬化（B1-B4，commit 8147bc9：密码策略 API 边界 / 429 不写审计 / 撤销信号 / M1 残留面证反关闭，见 §三 B1-B4 行）；**迭代七**：N3 限速器桶键淘汰已实现（T-D e7aef53，web 133 全过），§九 8 项遗留全部落地/处置（`milestone-status.md` §7.5） |
| Migration 回归 | ✅ | `migration/tests/` 20 个测试文件（含 E4 防回归 `resource_feature_lists.rs`）；迁移总数 23；CI 门禁 `ci.yml:306-310` |
| 备份恢复演练 | 🟡 | 自动化往返 10 测试（见上表证据，含迭代七 T-E 预快照三态 3 测试）；三平台演练未执行（§四-B） |
| 签名构建 / SBOM | 🟡 | 代码侧完成（`scripts/` 5 脚本 + `release-artifacts` job，commit 34503ea + d77d54e）；证书未到位、首次实跑未做（条件 17、§四-C） |
| 用户/运维/支持矩阵/已知限制手册 | ✅ | `docs/user-manual.md`、`docs/operations-manual.md`、`docs/support-matrix.md`、`docs/known-limitations.md` |
| 性能容量测试 | 🟡 | 合成规模已实测（`docs/operations-manual.md` §九，2026-08-12：debug 构建基线 + **release 构建数据已出**）；**发布级容量建议已发布（release 构建数据）**，正式规模环境复核仍待做（设计要求「测试后发布真实容量建议」，`design:2810`）——见 §四-B |

### 1.2 最低验证规模对照

设计 §0.9.0「最低验证规模」（`design:2800-2808`）：单 Site ≥200 Endpoint、单 Center
≥100 Site、中心汇总 ≥5,000 Endpoint。合成规模压力套件已按该规模实测落地
（`stress_capacity.rs:47-52` 常量 200/100/5,000；实测数据
`operations-manual.md` §九），**不再是「仅测试目标」**；「测试后发布真实容量建议」
（`design:2810`）：release 构建数据已出（2026-08-12，见 `operations-manual.md` §九），
正式规模环境复核仍待做。

## 二、1.0.0 发布条件 18 项逐条对照

1.0.0「全功能」定义（`design:2825-2828`）：**对 `NvRedfishReleaseBaseline` 所有公开功能
完成 100% 产品映射，并具备多服务器、单机、站点、中心、安全、任务、审计、备份、恢复和
跨平台交付所需的完整支撑能力。** 发布条件原文：`design:2829-2848`。

性质标注：**结构性** = 代码/门禁/测试钉死的事实，可复验；**实测** = 真实设备/演练/外部
评估得出的结论，有前置条件。

| # | 发布条件 | 状态 | 性质 | 证据（file:line） | 差距说明 |
|---|---|---|---|---|---|
| 1 | 能力账本 100% | ✅ | 结构性 | 账本 47 条 = 0.13.0 全部公开能力（`domain/src/capability.rs:401` 47 条、`:462` 14 OEM）；账本缺口为空（`milestone-status.md:89`，`release_baseline.rs:1236`）；账本 Hash 与协商 golden 钉死（`release_baseline.rs:1049-1052, 1577`；`center-protocol/src/negotiation.rs`） | 无。0.8.0 验收达成（`milestone-status.md` §二 验收 1） |
| 2 | 标准 feature 全覆盖 | ✅ | 结构性 | 编译完整面 58 个 = 0.13.0 全集 59 减 `default`；显式 17 个与 workspace 清单双向校验（`milestone-status.md:31-39`；`release_baseline.rs:79, 111`）；33 个标准账本条目全部落在编译面 | 「全覆盖」= 编译面完全覆盖，已由门禁钉死；设备侧实际暴露面是条件 8 的实测范围 |
| 3 | OEM feature 全覆盖 | ✅ | 结构性 | 14 个 `oem-*` 全编译（根 `Cargo.toml:35`；`domain/src/capability.rs:462`）；编译面与领域 OEM 账本同序逐一相等（`infra-redfish/src/lib.rs:158` 测试） | 无。probe-only 的 2 项（cper/fabrics）读取面如实登记（`milestone-status.md:160`） |
| 4 | 所有写操作均类型化 | ✅ | 结构性 | 43 个公开写操作全部经 `nv-redfish` 类型化面（`release_baseline.rs:677`；`milestone-status.md` §1.4）；NVIDIA 9 个 OEM action 均类型化（`support-matrix.md:124-130`） | 无 |
| 5 | 不存在原始 BMC 写请求 | ✅ | 结构性 | 唯一 `nv-redfish` 依赖 crate = infra-redfish（`infra-redfish/Cargo.toml:14`）；`UpstreamBmc = HttpBmc<NvHttpClient>` 传输注入（`redfish_gateway.rs:338, 1115`）；0.8.0 验收 4 达成（`milestone-status.md` §二 验收 4） | 无 |
| 6 | 不存在裸 SQL | ✅ | 结构性 | 机械门禁：迁移 crate 只允许 DDL 裸语句、DML 词全禁（`migration/tests/bare_sql_gate.rs:35, 40, 445, 456`）；表重建数据复制全部 SeaQuery（`milestone-status.md:120`） | 无 |
| 7 | 三平台单二进制发布 | 🟡 | 结构性（构建矩阵）+ 实测缺位 | 构建矩阵入 CI：x86_64 musl（`ci.yml:254-259`）、aarch64 musl cargo-zigbuild（`ci.yml:266-270`）、macOS Universal 2 lipo 合并 + `lipo -verify_arch x86_64 arm64` 校验（`ci.yml:289-304`）；三平台编译 + wasm32 UI 产物 diff（`ci.yml:65-81, 234-244`）；Windows ARM64 明确不入 CI（`ci.yml:272-279` 注释：hosted x64 runner 无 ARM64 MSVC 链接器与 SDK 导入库）；发布配置与 §5.4 一致（`Cargo.toml:110-116`；`rust-toolchain.toml` 已固定；Cargo.lock 已提交）；单二进制自包含边界（`support-matrix.md:85-88`） | ① Windows ARM64 发布目标无 CI 构建、无安装验证（§四-B，前置：原生 ARM64 runner 或本地 ARM64 主机）；② 三平台**发布包级**安装/运行验证并入条件 15 演练（§四-B）；③ 签名（条件 17）前置 |
| 8 | 五厂商标准能力验证 | ⏳ | 实测 | Mock 层已覆盖五厂商 profile（`test-support/src/mock_bmc/profile.rs:47-134`）；§19.1 Physical Device Test「五厂商至少各一台真实设备进入 1.0.0 认证矩阵」未达成（`design:2320-2322`；`known-limitations.md:78-79`） | 前置条件：五厂商真实设备实验室（§四-B）。当前结论只能是「基于上游类型面与 mock/fixture 验证」，不是实测认证（`known-limitations.md:79`） |
| 9 | Dell、HPE、Lenovo 上游 OEM 能力验证 | ⏳ | 实测 | Dell/HPE/Lenovo OEM 读取面已编译并映射（`support-matrix.md:113-118`）；真实设备验证未达成（同上） | 前置条件：Dell/HPE/Lenovo 设备各一台（§四-B）；验证范围限标准 feature + 上游已有 OEM feature，不声称覆盖全部 OEM API（`design:2326-2334`） |
| 10 | xFusion、Inspur 标准模式限制明确 | ✅ | 结构性（文档）+ 实测缺位 | 限制已明确成文：上游无 xFusion/Inspur OEM feature，只能用标准 Redfish 能力，OEM-only 标 `NotAvailableInNvRedfishBaseline`（`support-matrix.md:135-142`；`design:2336-2352`）；mock 变体验证标准模式行为 | 「限制明确」这一文档条件达成；设备侧标准模式验证并入条件 8（§四-B） |
| 11 | 所有异步操作可恢复 | ✅ | 结构性（恢复路径实测于自动化测试）+ 发布级演练缺位 | 升级流程含「恢复 Task 跟踪（扫描 WaitingRemote、重建 Session、继续读取 Task）」（`operations-manual.md:216-218`）；remote_tasks 迁移回归（`migration/tests/remote_tasks.rs`）；执行引擎恢复语义（`operation-engine`，`operations-manual.md` §七） | 跨进程重启恢复已有实现与自动化覆盖；真实升级演练（备份→停→换二进制→启动→任务恢复）并入 §四-B 演练 |
| 12 | 所有写操作有最终验证 | 🟡 | 结构性 | 写后重读验证系列与响应丢失→Unknown 语义（见 §一「无已知错误成功报告」行；`redfish_gateway.rs` `verifies_*` 测试群）；**ETag/412 冲突路径已真实生效**（深度审查批次，commit 6128a17）：`update` 写家族携带执行时读取的 ETag、`412 Precondition Failed` 走 `CommandExecutionError::PreconditionFailed`（重读目标、并发变更不被覆盖，`redfish_gateway.rs:598-611, 12653-12690, 14002-14062`，测试 `:25432, 27314-27420`）；**快照 ETag 接线已处置**（迭代七，决策 c，2026-08-12——快照 ETag 无独立写路径消费价值，接线不实施，论证见 `known-limitations.md` §九该行）；action/create/delete 家族无 If-Match 通道为已知差距（§13.4 第二段如实标注）；`known-limitations.md` §七「HTTP 成功不等于业务成功」 | 结构性证据充分；「所有写操作均有最终验证」的完整结论依赖 0.9.0 发布评审对证据链的复核与清零结论（§一） |
| 13 | Center 不保存 BMC Secret | ✅ | 结构性 | Center 投影只含 display_name/address/generation/health/resources，注释「the center never sees credentials or sessions」（`application/src/center_sync.rs:1282-1326`）；投影表无凭据列（`persistence/src/center_projection_repository.rs` 全文件 grep 无 credential/password/secret 命中）；安全审查范围 4 结论（`security-review.md` §二#4）；Site 本地解密边界（凭据表只存在于 Site 库） | 无。0.7.0 验收「Center 不保存 BMC 密码」达成（`design:2728-2735`） |
| 14 | Site 脱离 Center 完整运行 | ✅ | 结构性 | 0.7.0 验收达成（`design:2728-2735`）；断线后端点刷新/操作/本地 GUI 继续运行（`operations-manual.md:161`）；断线期间本地队列累积、重连按序排空（`center_sync.rs:4968`）；中心不可用不影响站点已接受任务（`operations-manual.md:110`） | 无 |
| 15 | 备份恢复通过 | 🟡 | 结构性（自动化往返 10 测试，含 T-E 预快照三态）+ 实测缺位 | `app/src/backup.rs:1051, 1095, 1121, 1208, 1240, 1266, 1277, 1307, 1384, 1404`（见 §一第 5 行证据；迭代七 T-E 02459dc 新增 3 个预快照测试）；流程与身份校验（`operations-manual.md` §六）；§20.1/20.2 对照（`design:2403-2446`） | 三平台安装/升级/备份/恢复演练未执行（§四-B）——0.9.0 验收同项 |
| 16 | 数据库 Migration 通过 | ✅ | 结构性 | 23 个 migration（`operations-manual.md:221`；`migration/tests/initial_storage.rs`；E1/E4 新增 `m20260812_000001_resource_decode_failures` 与 `m20260812_000002_resource_feature_lists`）；20 个测试文件回归 + CI 独立门禁（`ci.yml:306-310`）；裸 SQL 机械门禁（条件 6）；迁移前自动备份（`persistence/src/lib.rs:510`） | 无 |
| 17 | 正式签名和 SBOM | 🟡 代码侧完成（流水线就绪，证书未到位） | 结构性（管道已入 CI；首次实跑未做） | 管道证据：`scripts/` 5 脚本（sign-windows.ps1 / sign-macos.sh / sign-linux.sh / checksums.sh / checksums.ps1，commit 34503ea）；ci.yml `release-artifacts` job（commit d77d54e，`ci.yml:332-611`）——`v*` tag push / `workflow_dispatch` 触发（`ci.yml:28-40`）、`needs: ci` 门禁先行（`ci.yml:367`）、签名步骤仅在对应 secret 配置时执行（`ci.yml:340-343`，未配置则 "signing skipped: certificate not configured"）、Windows Authenticode（PFX base64 物化 `ci.yml:468-478` 或 thumbprint-only `ci.yml:480-488`）、macOS Developer ID + notarization（`.p8` 物化 `ci.yml:493-502`）、Linux minisign（密钥物化 `ci.yml:526-533`）、SBOM cargo-cyclonedx@0.5.9 钉版（`ci.yml:571-587`）、SHA-256 清单（`ci.yml:592-594`）、artifact 上传（`ci.yml:596-611`）；§5.4「构建结果嵌入 Git Commit」**已实现**（E3a：CI 在 job 级注入 `RUTILUS_GIT_COMMIT`（`ci.yml:53-64`），二进制经 `GIT_COMMIT` 常量嵌入（`app/src/main.rs:38-40`），`rutilus version` 输出三行（`:733-737`），本地无该变量时降级 `dev`；`app/src/standalone_runtime.rs:1456` WebProductInfo 嵌入）。**6 项首跑确认点**（证书到位后首次实跑核验）：① musl-tools 安装（`ci.yml:423`）；② cargo-cyclonedx@0.5.9 钉版（`ci.yml:575`）；③ base64 物化（`ci.yml:468-478, 493-502, 526-533`）；④ env 的 `&&`/`||` 表达式（`ci.yml:486, 516, 544`）；⑤ thumbprint-only 模式（`ci.yml:480-488`）；⑥ 上传权限（`ci.yml:596-611`；workflow `permissions: contents: read` `ci.yml:42-43`） | 前置条件：证书/账号——RUTILUS_WINDOWS_CERT_B64/THUMBPRINT(+PASSWORD)、RUTILUS_MAC_CERT_ID + RUTILUS_NOTARY_KEY_ID/B64/TEAM_ID、RUTILUS_LINUX_SIGN_KEY_B64（`ci.yml:355-362`；§四-C）。**1.0.0 发布硬条件** |
| 18 | 用户、运维、兼容和故障文档完成 | ✅ | 结构性 | `docs/user-manual.md`（431 行）；`docs/operations-manual.md`（数据/服务/备份/升级/诊断/容量，§8.1 含 `--log-format json`）；`docs/support-matrix.md`（基线/平台/厂商/不承诺）；`docs/known-limitations.md`（OutOfScope/依赖风险/测试基建局限/容量/偏差）；故障语义与诊断（`operations-manual.md` §八、`known-limitations.md` §七） | 「故障文档」由 known-limitations（已知限制与偏差）+ operations §八（doctor/诊断）承担，与设计 §0.9.0 内容一致；故障注入演练结果文档待 §四-B 完成后补充 |

## 三、剩余工作分类

### A. 代码/CI 可做（不依赖外部资源，可直接进入迭代）

> （2026-08-12，master d77d54e）本表 A 类工作项已全部完成或移交：E1 / E3b（仓库级）/ E3c /
> N5 均 ✅；UI 本地化本轮转 ✅；Windows ARM64 已移交 §三-B（依赖原生 runner，非 A 类可做）。
> **A 类不再有未完成项。**

| 工作项 | 状态 | 负责方 | 前置条件 | 证据/来源 |
|---|---|---|---|---|
| §12.4 诊断解码失败**生产捕获点**（gateway 捕获 + SQLite 持久化） | ✅ 已合入（E1，commit ce2b8b3） | 全组评审复验（证据链见下） | 无（已合并，全部门禁复跑通过） | 网关捕获：`DecodeFailureObservation`（`infra-redfish/src/redfish_gateway.rs:8720`），捕获函数 `capture_fetch_failure`/`capture_projection_failure`/`capture_segment_decode_failure`（`:8904, :8931, :8977`），刷新结果经 `outcome.decode_failures()` 流出（`:8831`）；同代事务提交：`persistence/src/resource_snapshot_repository.rs:81-147`（`commit_resource_generation` 在快照同一事务内写 `resource_decode_failures`），生产链路 `application/src/endpoint_refresh.rs:350-355` 直连；新表 + entity（`entity/src/lib.rs:28`、`entity/src/resource_decode_failure.rs:13`）+ 迁移 `m20260812_000001`（E4 由 `m20260812_000002` 重建约束为领域枚举 47 码）；web 端到端 7 测试（`web/tests/diagnostics_path.rs:838-1175`，含 `refresh_capture_flows_into_the_diagnostics_response` `:998`）；现状登记见 `known-limitations.md` §八「§12.4」行 |
| 独立 Secret 泄漏扫描（仓库级自动扫描 + 运行时抓包/日志复核） | ✅ 仓库级已落地（E3b）/ 运行时复核待做 | 安全评审 + CI | 无（仓库级部分）；运行时复核需三平台演示环境（可并入 B） | `security/tests/secret_leak_gate.rs`：3 规则（R1 硬编码秘密 / R2 内嵌私钥 PEM / R3 明文输出宏泄露）、8 测试（`:1054, :1066, :1077, :1087, :1146, :1195, :1227, :1265`）、白名单 = `ALLOWED_CONSTANT_HITS` 2 处（path+line+name+literal 四元组绑定，`app/src/backup.rs:88, 89` 备份条目名，T-E 后重核）、`test-support` crate 目录级豁免（fixture scope，`:55-59, 1000-1002`，E3b 原始提交 eefde7e）+ `strings_catalog!` 宏体结构豁免（深度审查批次 commit e8424df：CATALOG_MACRO 帧识别 `:534, 815-822`，新测试 `strings_catalog_macro_bodies_are_copy_construction_not_secret_assignments` `:1195`）；门禁为 CI 独立步骤（`ci.yml:225-227` Secret leak gate，`cargo test --locked -p rutilus-security --test secret_leak_gate`，`if: matrix.is_default`，machete 之后、wasm32 之前；header 注记 `ci.yml:15-17`）；运行时抓包/日志复核仍为 §四-B 项（`security-review.md:110, 128-135`） |
| UI 本地化 | ✅ 已完整落地（H5 d3f7769 + 0f91c17 + T-H c4dd335：`strings_catalog!` 目录 827 键 En/Zh 双语（`i18n.rs:163-1858`）、`Lang::{En, Zh}` 运行时语言选择（`thread_local!` `i18n.rs:1938-1942` + `L()` `i18n.rs:1968-1973`）、lib.rs `LanguageSelector` 组件（`lib.rs:11640-11658`）与 URL fragment 持久化（**迭代七 T-H 已拆为纯函数 + 薄封装**：`stored_lang_code_from`/`lang_fragment_value` `i18n.rs:1915-1936`、wasm 封装 `lib.rs:11607-11635`、启动恢复 `start()` `lib.rs:11661-11664`）；ui 141 测试全过；深度审查批次补 `format_catalog` 槽位硬化与本地化（fb660d5 + a4950fc，`i18n.rs:1984-2006`，见 `milestone-status.md` §7.4）） | 前端组 | 后续触点：localStorage 持久化（需扩展 web-sys feature）与更多语言；1.0.0 定义与 18 项条件均不涉及，**不阻塞 1.0.0** | `known-limitations.md:107`；`milestone-status.md:290` |
| N5 `unreachable!` 处置（可选，NOTE 级） | ✅ 已完成（E3c） | — | 无 | `security-review.md` §三 N5 已关闭：`web/src/lib.rs:1223` 编译期 `const _: () = assert!(rutilus_api::OVERVIEW_RECENT_EVENTS > 0);` 钉死常量正性（注释 `:1213-1222`），运行时 guard 保留为已被断言证明不可达的防御分支（`:1224-1226`） |
| 发布级 CI 扩展（Windows ARM64 原生 runner） | ✅ 移交 §三-B（依赖原生 runner，非 A 类可做） | — | 原生 ARM64 Windows runner 或本地 ARM64 主机验证后另行处理 | `ci.yml:272-279` 注释；§三-B「Windows ARM64 发布验证」行 |

### B. 依赖演练环境（物理设备 / 规模环境 / 三平台流程）

| 工作项 | 说明 | 前置条件 | 对应 1.0.0 条件 |
|---|---|---|---|
| 五厂商实验室 / 真实设备认证矩阵 | Dell/HPE/Lenovo/xFusion/Inspur 各至少一台真实设备进入认证矩阵；验证标准 feature + 上游已有 OEM feature（Dell/HPE/Lenovo）、标准模式限制（xFusion/Inspur） | 五厂商设备与网络环境 | 8、9、10 |
| 真实响应 fixture 目录 | 五厂商各固件版本脱敏真实响应，随 nv-redfish 升级回归（§19.1 Fixture Test） | 设备抓取 → 脱敏 → 入库 | 8、9 的回归基础 |
| 进程级故障注入演练 | 产品进程在任务中被终止、BMC 更新中重启、SQLite 写入中断、磁盘空间不足（§19.3 剩余项，跨进程形态） | 三平台测试环境 | 11、12 的实测面 |
| 大文件更新端到端演练 | 真实大固件文件的上传→校验→分发→应用 | 真实固件制品 + 设备或等价测试台 | 12 的实测面 |
| 三平台安装/升级/备份/恢复演练 | 0.9.0 验收第 5 项、1.0.0 条件 15：Windows/macOS/Linux 各跑安装→备份→升级→恢复→任务恢复 | 三平台机器 + 发布包 + 签名产物（签名属 C） | 7、15 |
| Center/Site 长时间断线重连演练 | 0.9.0 验收第 6 项：跨进程/跨天真实断线（自动化风暴已覆盖单进程形态） | 站点 + 中心运行环境 | 14 的实测面 |
| 发布级容量建议 | 设计要求「测试后发布真实容量建议」：release 构建数据已出（2026-08-12，`operations-manual.md` §九），正式规模环境复核后定稿发布 | 正式规模环境 | 7 的配套交付物 |
| Windows ARM64 发布验证 | `aarch64-pc-windows-msvc` 发布目标：构建 + 安装/运行验证 | 原生 ARM64 Windows runner 或本地 ARM64 主机 | 7 |

### C. 依赖发布管道（外部证书 / 签名服务 / 发布流程）

> （2026-08-12，master d77d54e）代码侧已就绪：`scripts/` 5 脚本 + ci.yml `release-artifacts`
> job（commit 34503ea + d77d54e，条件 17）——本表各项剩余前置仅为证书/账号与证书到位后的
> 首次实跑；新增「首次 release 实跑演练」行如下。

| 工作项 | 说明 | 前置条件 | 对应条款 |
|---|---|---|---|
| Windows Authenticode 签名 | 发布包代码签名 | 代码签名证书（含时间戳服务） | `design:654`；条件 17 |
| macOS 签名与公证 | Developer ID 签名 + notarization + staple | Apple Developer 账号与证书 | `design:655`；条件 17 |
| Linux 独立签名 | 独立签名 + 公钥发布路径 | 签名密钥/签名服务 | `design:656`；条件 17 |
| SBOM 生成与发布 | cargo-cyclonedx 等工具生成 SPDX/CycloneDX，随发布产物发布 | 工具选型与发布流程挂接 | `design:652`；条件 17 |
| §5.4 构建信息嵌入补齐 | ✅ 已完成（E3a）：Git Commit 经 job 级 `RUTILUS_GIT_COMMIT` 注入（`ci.yml:53-64`）、`GIT_COMMIT` 常量嵌入（`app/src/main.rs:38-40`）、`rutilus version` 三行输出（`:733-737`）、本地无变量时降级 `dev`（`app/tests/version.rs:8-11, 27-36` 派生断言）；§5.4 四项构建结果（产品版本 + Git Commit + 基线 + 账本 Hash）已全部嵌入 | 无 | `design:657` |
| SHA-256 校验清单 | 发布产物清单随包发布（`release-artifacts` job 已用 `scripts/checksums.sh` 生成 `release/SHA256SUMS`，`ci.yml:592-594`） | 发布流程 | `design:653` |
| 证书到位后首次 release 实跑演练 | 签名/SBOM/校验链全流程首跑：Windows Authenticode、macOS 签名与公证、Linux minisign、SBOM 生成、SHA-256 清单、artifact 上传——核验 **6 项确认点**（musl-tools 安装 / cargo-cyclonedx@0.5.9 钉版 / base64 物化 / env `&&`·`||` 表达式 / thumbprint-only 模式 / 上传权限，见条件 17） | 证书/账号（RUTILUS_WINDOWS_CERT_* / RUTILUS_MAC_* / RUTILUS_NOTARY_* / RUTILUS_LINUX_SIGN_* secrets，`ci.yml:355-362`） | 条件 17 |

## 四、1.0.0 就绪度结论

按 1.0.0 定义（`design:2825-2828`）拆解：

**1. 功能映射面（「NvRedfishReleaseBaseline 所有公开功能 100% 产品映射」）：结构性 100% 达成。**
条件 1-6 全部 ✅：47 账本 / 29 模块 / 43 操作 / 未映射 0 由 0.8.0 冻结 + 门禁钉死
（`milestone-status.md` §一-§二），写操作全类型化、无原始 BMC 写请求、无裸 SQL 均为机械
门禁可复验事实。此面**不依赖外部资源**；E1 已合入且 Release Baseline / Capability Ledger /
Migration 门禁已复跑通过（`ci.yml:306-330`），本版行号均按合并后 master 复核。

**2. 支撑能力面（安全、任务、审计、备份、恢复、跨平台交付）：结构性支撑充分，实测认证缺位。**
- 已结构达成：Center 不保存 BMC Secret（13 ✅）、Site 脱离 Center 完整运行（14 ✅）、
  数据库 Migration（16 ✅）、文档四件套（18 ✅）、异步操作恢复实现（11 ✅ 结构性）。
- 缺实测认证：真实设备验证（8/9/10 ⏳）、三平台备份恢复演练（15 🟡）、所有写操作最终
  验证的评审清零结论（12 🟡）、发布级容量建议的正式规模环境复核（🟡；release 构建数据已出，
  2026-08-12，见 `operations-manual.md` §九）。
- 硬缺口：签名与 SBOM（17 🟡）——代码侧已就绪（`scripts/` 5 脚本 + `release-artifacts` job，
  commit 34503ea + d77d54e），剩余全部为外部证书与账号（C 类）+ 证书到位后的首次实跑
  （6 项确认点，见条件 17）；应最早启动证书申请以并行于 B 类演练（Git Commit 嵌入已补齐，
  见条件 17）。

**3. 差距清单（按 1.0.0 发布阻塞度）：**

| 级别 | 差距 | 类别 | 前置条件 |
|---|---|---|---|
| 阻塞（硬条件未达成） | 条件 17 签名与 SBOM（代码侧已完成，待证书与首次实跑） | C | 证书/账号 + 6 项首跑确认点（见条件 17） |
| 阻塞（硬条件未达成） | 条件 8/9/10 五厂商真实设备验证 | B | 五厂商设备 |
| 阻塞（硬条件未达成） | 条件 15 三平台备份恢复演练（0.9.0 验收第 5 项同） | B | 三平台 + 发布包（含签名，链条依赖 C） |
| 阻塞（硬条件未达成） | 条件 7 的 Windows ARM64 发布目标验证 | B/基础设施 | 原生 ARM64 runner |
| 评审前须完成 | 0.9.0 验收第 1/4 项评审结论（P0/P1 清零、错误成功报告清零） | 评审流程 | 上述证据链 |
| 评审建议完成 | Secret 泄漏扫描的运行时复核（仓库级门禁已落地，E3b） | A（运行时复核并入 B） | 三平台演示环境 |
| 评审建议完成 | 发布级容量建议（release 构建数据已出，2026-08-12）；正式规模环境复核 | B | 正式规模环境 |
| 不阻塞 | UI 本地化（✅ 已完整落地：827 键 En/Zh 双语 + 运行时语言选择器 + URL fragment 持久化） | A | — |

**4. 结论：** 0.9.0 六项验收中 1 项 ✅、3 项 🟡、2 项 ⏳，**尚不满足 0.9.0 发布条件**——
缺口全部集中在「评审流程结论」与「B/C 类演练/管道」，无结构性缺陷登记（安全审查无
BLOCKER；N5 已关闭、Secret 扫描门禁已落地、E1 捕获点与 E4 约束修复已合入）。1.0.0 的
功能映射面已结构性 100% 达成；距 1.0.0 发布的差距为**可枚举、有明确前置条件的 B/C 类
工作 + 评审流程结论**，不存在未知的架构性风险。建议路径：C 类（证书申请启动——签名/SBOM
代码侧已就绪，链路剩余为证书 + 首次实跑）先行并尽早启动 B 类设备与三平台环境，B 类逐项
执行并以演练结果回填本文档 §一/§二状态。

## 五、引用与复验纪律

- 本版（HEAD = 61b9cc5）已登记迭代六（H4/H5）落地（UI 本地化完整落地 d3f7769 + 0f91c17、
  发布管道代码侧 34503ea + d77d54e）、**深度审查批次**（9 个修复提交，2026-08-12，详见
  `milestone-status.md` §7.4）与**迭代七**（9 个提交 + T-C 决策，2026-08-12，§九遗留 8 项
  清零，详见 `milestone-status.md` §7.5）。深度审查批次触面（`web/src/auth.rs`、
  `infra-redfish/src/redfish_gateway.rs`、`application/src/batch_refresh.rs`、
  `application/src/operation_executor.rs`、`migration/src/`、`ui/src/i18n.rs`、
  `app/src/backup.rs`、`security/tests/secret_leak_gate.rs`）的每个 file:line 均在本轮打开
  文件核实（§六记录）；**迭代七触面（`web/src/auth.rs` +263 净行、`app/src/backup.rs` +431
  净行、`application/src/endpoint_enrollment.rs`/`batch_refresh.rs`、`web/src/lib.rs` +9、
  `ui/src/i18n.rs` +103、`ui/src/lib.rs`、`test-support/`、`app/src/center_acceptor.rs`/
  `center_runtime.rs`/`center_client.rs`/`site_runtime.rs` +271 行分布、`application/src/lib.rs`）
  的全部既有引用已逐条打开文件重核为当前 master 实际行号并修正（§六记录）**；此前的
  E1/E3a/E3b/E3c/E4、H1/H2、H4/H5 触面行号保持合并后已核实的值；遗留旧 ci.yml 引用已
  在前轮全部重核换算完毕。
- 门禁复跑（2026-08-12，HEAD 61b9cc5）：**fmt 干净、clippy `-D warnings` 全 workspace 零警告、
  1723 测试 0 失败**（`cargo test --workspace -- --list` 口径：lib/集成 1723 + doc 1 = 1724）；`ci.yml:306-330`（Migration `:306-310`、Capability Ledger `:312-317`、
  Release Baseline `:319-330`）独立门禁复跑通过；per-crate 口径（本轮实测）：
  migration 30 / persistence 190+3 / application 301 / infra 291 / test-support 55 /
  web 133 / ui 141（含 15 个 i18n 测试）/ rutilus 145 / security 门禁 8。
- 引用自检记录见下节（每个 file:line 均在本轮打开核实）。

## 六、引用自检记录（2026-08-12，HEAD 61b9cc5 复核，F3/迭代七）

本轮逐一打开核实的引用（含全部 E1/E3a/E3b/E3c/E4、H1/H2、H4/H5、深度审查批次触面与
**迭代七触面**——迭代七新增触面的旧引用一律打开文件按当前 master 重核，不沿用前轮值）：

| 引用 | 核实结果 |
|---|---|
| `design:2778-2819`（§0.9.0 内容/规模/验收）、`:2823-2848`（1.0.0 定义与 18 项）、`:2280-2397`（§19 测试/故障注入/CI 门槛）、`:2403-2464`（§20 备份恢复升级）、`:633-657`（§5.4 发布配置）、`:2728-2766`（0.7.0/0.8.0 验收） | 打开核实，行号一致（设计文档冻结，未变） |
| `domain/src/capability.rs:401, 462`（47 账本 / 14 OEM） | 打开核实，`:401` 47 条、`:462` 14 条 |
| `domain/src/event.rs:383`（dedup_key）、`domain/src/audit.rs:318-394`（审计构造上禁秘密） | 打开核实，行号一致 |
| `operation-engine/src/operation_engine.rs:1332`（批量重投 no-op 测试）、`:986`（时钟回拨） | 打开核实，行号一致 |
| `release_baseline.rs:59, 68, 79, 111, 177, 280-285, 296-308, 372, 646, 677, 745, 778, 790, 1025, 1039, 1049-1052, 1236, 1395, 1422, 1457, 1471, 1506-1513, 1517, 1577, 1589, 1638, 1688, 1705, 1734` | 打开核实，全部一致（E1/E3 未触达该文件） |
| `app/src/main.rs:27`（PRODUCT_VERSION）、`:38-40`（GIT_COMMIT，E3a）、`:58-64`（LogFormat 枚举）、`:97, 144`（backup/restore 子命令）、`:255-273`（init_tracing）、`:733-737`（version 三行输出） | 打开核实（旧引用 38-39/240-258/720 漂移，已按实际值引用） |
| `app/tests/version.rs:8-11, 27-36`、`app/tests/log_format.rs:7-10, 23-28`（三行派生断言，E3a） | 打开核实 |
| `app/src/backup.rs:765, 799, 825, 912, 944, 970, 981`（备份恢复 7 测试）、`:83-84`（备份条目名常量） | 打开核实（a4950fc 轮，行号一致）；**F3 重核（T-E 02459dc +431 净行）：7 测试 → `:1051, 1095, 1121, 1208, 1240, 1266, 1277`（备份条目名常量 `:88-89`）；T-E 新增 3 测试 `:1307, 1384, 1404`；`create_backup` `:170-211`、`restore_backup` `:246-327`、`create_pre_restore_snapshot` `:619-643`、`check_product_version` `:739-750`、schema 断言派生 `:1068-1072`** |
| `app/src/standalone_runtime.rs:1456`（WebProductInfo 嵌入）、`app/src/site_runtime.rs:568` | 打开核实（旧 1454 漂移 +2） |
| `web/src/auth.rs:83, 101-116, 514, 863-866, 863-937, 950-956, 1078-1080, 1096-1112, 1147-1159, 1200-1213, 1226, 1233, 1254-1265, 1267-1276（B1 密码策略）, 1305-1315, 1321-1335（B1/B2 登录入口与 429）, 1357（M1 未知用户名分支调用）, 1365-1400（B4 哑验证）, 1533（bootstrap_complete）, 1749-1776（B3 撤销信号与改密撤销）, 2066-2071, 2128-2131（禁用/角色变更撤销）, 2208-2257（登录审计）, 2261-2284（管理事件）, 2289-2292（best-effort）, 2688`（M1/B1-B4 与限速/会话/审计面） | 打开核实；F2 复核修正残留漂移（记录见左列前值）。**F3 重核（T-D e7aef53 +263 净行，限速器区段重构后全部后移）：`SESSION_COOKIE_NAME` 83→73、限速常量 101-116→102-118、`RouteAccess::Public` 504 / bootstrap 路由 514→529、`LoginRateLimiter` 863-866/863-937→886-889/886-1016（`BucketMap` 893、`prune_if_due` 989、`prune_expired` 1005、`RATE_LIMIT_USERNAME_CHARS` 118、`bounded_username_key` 1031）、resolve_session touch 1078-1080→1159-1161（`resolve_session` 1115）、CSRF 1096-1112→1177-1200、session_cookie 1147-1159→1228-1245（字面量 1237）、is_https 1200-1213→1281-1294、DUMMY_SALT/DUMMY_HASH 1226/1233→1307/1314、哑验证 1254-1265→1335-1346、B1 1267-1276→1355-1357（登录入口 1386-1397、bootstrap 1625-1631、改密 1780-1785）、B2 1321-1335→1402-1416、M1 未知用户名调用 1357→1438、B4 1365-1400→1446-1461/1469-1481、bootstrap_complete 1533→1614、B3 1749-1776→1830-1853、禁用撤销 2066-2071→2145-2152、角色撤销 2128-2131→2207-2212、record_login_failure/success 2208-2257→2289-2338、管理事件 2261-2284→2342-2365、best-effort 2289-2292→2373-2405（注释 2370-2371）、限速测试 2688→2769（T-D 新增 4 个有界性测试 2848/2901/2945/2973）、防御性 unwrap_or 1002/1158/1449/1808→1083/1239/1530/1889** |
| `web/src/lib.rs:108`（ARTIFACT_CHUNK_BODY_LIMIT）、`:911`（DefaultBodyLimit）、`:1223`（N5 编译期 const assert，E3c）、`:1368`（AUDIT_QUERY_MAX_LIMIT）、`:1374`（credential_inventory）、`:1454`（begin_endpoint_trust）、`:3961-3992`（资源诊断投影含 decode_failures）、`:9270`（password_verifications 计数）、`:10715, :10779`（两分支计数断言）、`:11376`（role_masks 测试）、`:12251, :12295`（中心站点作用域）、`:6229`（secret-free 清单测试） | 打开核实；F2 复核修正残留漂移（记录见左列前值）。**F3 重核（T-B 4897b22 在 `:3039` 处插入 `InitialRefreshCoordination` 错误映射 9 行，其后 +9；`:3043` 前不受影响）：108/911/1223/1368/1374/1454/1637-1666（refresh_endpoints 路由，T-B 前 1637-1652 区段现含错误映射前不变）全部一致；诊断投影 3961-3992→3970-4001、secret-free 测试 6229→6238、password_verifications 计数 9270→9279、未知用户名计数断言测试 10715→10725（断言 10750/10766/10776-10779）、口令错误断言测试 10779→10789（断言 10806）、role_masks 测试 11376→11385、中心站点作用域 12251/12295→12260/12304、新错误映射 `:3042-3050`** |
| `web/tests/write_path.rs:784, 816, 918`（secret-free 测试） | 打开核实（旧 783/815/917 各 +1） |
| `web/tests/diagnostics_path.rs`（7 个测试：`:838, :893, :935, :998, :1076, :1143, :1175`，E1 新增 `refresh_capture_flows_into_the_diagnostics_response` `:998`） | 打开核实（旧 6 个测试 651/706/748/811/878/910 漂移） |
| `ui/src/lib.rs:2902`（ConsoleView::ALL 17 视图）、`:5170`（CommandFamilyView::ALL 9 家族）、`:6289, 6361, 6437`（telemetry 表单拒绝）、`:11292`（later-milestone 提示，文案入目录 `i18n.rs:1654` `hint_telemetry_later`）、`:15492`（DiagnosticsReady 只读区块，含 decode_failures 投影） | 打开核实（H5 后行号重核：H1 期旧值已漂移；文案串已入目录、aria-label 全部走目录键）。**F3 重核（T-H c4dd335 浏览器模块重构）：`ConsoleView::ALL` 2902 一致、`CommandFamilyView::ALL` 5170→5171、表单选择器 FamilyRequired 6289/6361→6289-6291、Telemetry 表单拒绝 6437→6438、later-milestone 提示 11292→11295-11302（`L().hint_telemetry_later` 渲染 11302）、DiagnosticsReady 15492→15491、`aria_loading` 11952→11951、fragment 区段 11600-11666→11602-11667（`stored_lang_code` 11607、`persist_language` 11617、`apply_language` 11629、`LanguageSelector` 11640-11658、`start()` 11661-11664）、zh 断言 `"总览"` 22748→22762** |
| `ui/src/i18n.rs`（H5 后：`strings_catalog!` 宏 `:43-160`、827 键目录体 `:163-1858`、`Lang`/`Lang::strings` `:1860-1881`、`lang_code`/`parse_lang` `:1884-1899`、`thread_local!`/`set_lang`/`current_lang`/`L()` `:1909-1944`、`format_catalog` `:1955-1977`、11 测试 `:1980-2172`）、`ui/src/lib.rs:45`（`mod i18n`）、`:11600-11666`（fragment 持久化 + `LanguageSelector` + `start()`）、`web/assets/rutilus_ui.js` + `rutilus_ui_bg.wasm`（H2/0f91c17 再生成） | 打开核实（H5 后行号重核：H1 期旧值已过时；F2 复核修正残留漂移记录见左列前值；测试断言现按 zh 值断言；旧 MINOR「`aria-label="Loading"` 未抽取」已在 H5 解决——aria-label 全部走目录键；设计文档全文无「本地化/i18n」条目——i18n.rs 头注释 §5.1 引用不可核验的 MINOR 保持）。**F3 重核（T-H c4dd335 +103 行插入 1901-1936 与 2187-2259 区段）：宏 `:43-160`、目录体 `:163-1858`、`Lang`/`Lang::strings` `:1860-1881`、`lang_code`/`parse_lang` `:1884-1899` 一致；`LANG_FRAGMENT_PREFIX` 1905、`stored_lang_code_from`/`lang_fragment_value` 1915-1936（新）、`thread_local!` 1938-1942、`set_lang` 1950、`current_lang` 1955、`L()` 1968-1973、`format_catalog` 1984-2006（旧 1955-1977 +29）、tests 2009-2185（11 个既有测试，旧 1980-2172）+ 新 fragment 纯函数测试 2192-2259（`fragment_reading_extracts_only_the_lang_value` 2192 / `fragment_persistence_writes_the_lang_value` 2218 / `fragment_persistence_round_trips_both_languages` 2229 / `fragment_lang_selection_falls_back_to_en` 2248）；`FORMAT_KEYS` 93、槽位测试 2055/2137（旧 2000-2030/2046-2073/2108-2139 漂移）** |
| `center-protocol/src/lib.rs:50, 59, 62, 67, 75, 383`、`negotiation.rs:162, 269`、`framing.rs:18-31, 176-199, 219-238` | 打开核实，行号一致 |
| `Cargo.toml:14`（workspace 版本 0.9.0）、`:35`（16 个 nv-redfish feature）、`:110-116`（§5.4 发布配置一致）、`infra-redfish/Cargo.toml:14`、`Cargo.lock:2486-2490`、`deny.toml:21-24, 29-34` | 打开核实，行号一致 |
| `rust-toolchain.toml` 存在、Cargo.lock 已提交 | 打开核实 |
| `ci.yml`：`:3-24`（门禁清单注释，含 secret-leak gate `:15-17`）、`:53-64`（RUTILUS_GIT_COMMIT job 级注入，E3a）、`:65-81`（三平台矩阵）、`:121-123`（全 workspace Test）、`:130-147`（跨平台 E2E 注释+步骤，mock_center_client 不纳入注释 `:139-141`）、`:197-205`（cargo audit）、`:225-227`（Secret leak gate 独立步骤，E3b/G1）、`:234-244`（wasm32 UI 产物 diff）、`:254-259`（musl x86_64）、`:266-270`（aarch64 zigbuild）、`:272-279`（Windows ARM64 不入 CI 注释）、`:289-304`（Universal 2 + lipo verify_arch）、`:306-310`（Migration 门禁）、`:312-317`（Capability Ledger）、`:319-330`（Release Baseline） | 打开核实（d77d54e 重排 `on:` 块（新增 `v*` tag / `workflow_dispatch`，`:28-40`）与门禁段注释，旧 ci.yml 行号漂移 **+1~+8 不等**：RUTILUS_GIT_COMMIT 注入 45-55→53-64、三平台矩阵 63-72→65-81、跨平台 E2E 122-138→130-147、cargo audit 188-196→197-205、Secret leak gate 216-218→225-227、wasm32 产物 diff 225-235→234-244、musl 245-250→254-259、zigbuild 257-261→266-270、ARM64 注释 263-270→272-279、Universal 2 280-295→289-304、Migration 299-301→306-310、Capability Ledger 306-308→312-317、Release Baseline 318-320→319-330；本行已按新行号引用；旧 ci.yml 引用的统一换算已在本轮完成——milestone-status §四/§六/§7.1/§7.2-A、operations-manual §十、user-manual §1.1 的旧行号引用均已逐处重核改写，见各文档修订） |
| E1 触面（合并后复核）：`redfish_gateway.rs:338, 1115, 8720, 8831, 8904, 8931, 8977`（捕获点）、`resource_snapshot_repository.rs:81-147`（同代事务）、`endpoint_refresh.rs:350-355`（生产链路）、`endpoint_inventory.rs:47, 94, 105, 123`、`resource_diagnostics.rs:36, 249, 430`、`entity/src/lib.rs:28`、`entity/src/resource_decode_failure.rs:13`、`migration/src/m20260812_000001_resource_decode_failures.rs`、`migration/src/m20260812_000002_resource_feature_lists.rs`、`migration/tests/resource_feature_lists.rs:248`、`persistence/src/backup_snapshot.rs:624-627`（backup_applied 24 / supported 23） | 打开核实，按合并后行号引用（entity 文件名经 `entity/src/` 目录清点修正为单数 `resource_decode_failure.rs`） |
| E3b 触面：`security/tests/secret_leak_gate.rs`（R1/R2/R3 `:21-42`、`ALLOWED_CONSTANT_HITS` `:325-333`、8 测试 `:1054-1306`、`test-support` 目录级豁免 `:55-59, 1000-1002`；深度审查批次 e8424df 补 `strings_catalog!` 宏体豁免 `:534, 815-822, 1195`） | 打开核实；本轮（F2 复核）修正残留漂移：`ALLOWED_CONSTANT_HITS` 318-331→325-333、7 测试 `:974-1130`→8 测试 `:1054-1306`（e8424df 新增 `strings_catalog_macro_bodies_are_copy_construction_not_secret_assignments` `:1195`） |
| `stress_capacity.rs:47-52, 336, 585, 832`（3 测试）；`center_sync.rs:2853, 3478, 3528, 3693, 4328, 4448, 4615, 4838, 4968`（风暴/幂等/重发） | 打开核实（旧 582/829/3477/3527/3692/4327/4447/4614/4837/4967 漂移 +1~3，已按实际值引用） |
| `scripts/`（sign-windows.ps1 / sign-macos.sh / sign-linux.sh / checksums.sh / checksums.ps1，commit 34503ea）、ci.yml `release-artifacts` job（`ci.yml:332-611`：触发 `:28-40`、`needs: ci` `:367`、gated 签名 `:340-343, 468-546`、base64 物化 `:468-478, 493-502, 526-533`、thumbprint-only `:480-488`、SBOM `:571-587`、SHA-256 `:592-594`、上传 `:596-611`；`permissions: contents: read` `:42-43`；musl-tools `:423`；env `&&`/`||` `:486, 516, 544`；H4 audit 注释 BLOCKER 1/2、MINOR 1/3/4 `:353, 372, 422, 552, 567`） | 打开核实（H4 新引用） |
| 深度审查批次触面（打开核实）：`web/src/auth.rs:1267-1276`（B1 密码策略）、`:1305-1315, 1321-1335`（B1/B2 登录入口与 429 拒绝）、`:1365-1400`（B4 disabled/credential-missing 哑验证）、`:1749-1776`（B3 撤销信号）；`redfish_gateway.rs:598-611, 12653-12690, 14002-14062, 25432, 27314-27420`（ETag/412）；`application/src/batch_refresh.rs:87-109, 303-316`（端点读门）；`application/src/operation_executor.rs:1685-1699`（恢复判定）；`migration/src/m20260805_000005_operations.rs:131-138`（down 先子后父）；`ui/src/i18n.rs:1955-1977, 2000-2030, 2046-2073, 2108-2139`（槽位硬化）；`app/src/backup.rs:776-786`（schema 断言派生）；`security/tests/secret_leak_gate.rs:55-59, 1000-1002`（`test-support` 目录豁免，E3b 原始提交 eefde7e）+ `:534, 815-822, 1195`（`strings_catalog!` 宏体豁免，commit e8424df）；`entity/src/` 全目录清点（文件名全部单数：`endpoint_capability.rs`、`resource_decode_failure.rs` 等） | 打开核实；F2 复核修正残留（记录见左列前值）。**F3 重核（迭代七漂移）：auth.rs B1 1267-1276→1355-1357、B1/B2 登录入口 1305-1335→1386-1416、B4 1365-1400→1446-1481、B3 1749-1776→1830-1853（详见 auth.rs 行）；batch_refresh.rs 端点读门 87-109→87-110（`ENDPOINT_READ_GATES` 87、`endpoint_read_gate` 102-110）、refresh_one 303-316→287-335（两处 Coordination 获取失败 296-320，变体 394-396）；i18n.rs 槽位硬化 1955-1977→1984-2006（槽位测试见 i18n.rs 行）；backup.rs schema 断言派生 776-786→1068-1072；redfish_gateway.rs/operation_executor.rs/migration/secret_leak_gate.rs/entity 均未受迭代七触达，行号一致** |
| 迭代七新增触面（F3 本轮打开核实）：`application/src/endpoint_enrollment.rs`（T-B +214/-8）：`enroll` 流程 `:116-208`、读门获取 `:168-179`、`refresh.execute` `:190`、`InitialRefreshCoordination` 变体 `:292-297`、`EndpointReadGateError` `:331+`、对抗测试 `initial_refresh_and_concurrent_batch_refresh_of_the_same_endpoint_never_overlap` `:643`；`application/src/lib.rs:85-86`（`EndpointReadGateError` 导出）；`application/tests/refresh_decode_failures.rs`（T-G 新文件，4 测试，头注释 `:3-22`）；`test-support/src/lib.rs`（T-A 头文档 +3）：`:19, 46` 区段保持（mock-bmc 位置参数说明入头文档）；`test-support/src/bin/mock-bmc.rs`（T-A 重写 +54/-19，位置参数解析）；`test-support/tests/gateway_mock_bmc.rs`（T-I +479/-2）：头注释 `:3-17`、AMI/HPE 测试 `:1793, 1861, 2003, 2070, 2202`、共 28 测试；`app/src/center_acceptor.rs`（T-F）：`is_raced_bind` `:964-975`、`bind_acceptor_with_options` `:978-993`、测试 `the_bind_retries_when_the_probed_port_was_grabbed` `:1005`；`app/src/center_runtime.rs`：`is_raced_bind` `:901-904`、`bind_acceptor` `:912-927`；`app/src/center_client.rs`：`is_raced_bind` `:629-632`、`bind_acceptor` `:641-654`、`connect_with_retry_stops_on_the_stop_signal` `:886`；`app/src/site_runtime.rs`：`is_raced_site_bind` `:1507-1513`、`is_raced_center_bind` `:1517-1523`、`bind_site` `:1529-1544`、`a_not_bound_refusal_from_the_center_converges_the_local_binding`（第 5 处内联修复）`:2048-2079`；`app/src/site_runtime.rs:210-213/499-527/604-606/635`（既有引用，T-F 后重核不变） | 打开核实（本轮新增）；既有旧行号（`endpoint_enrollment.rs:156-166`、`batch_refresh.rs:87-109/303-316` 等）已按当前值修正，全文不再引用旧值 |
