# Rutilus 里程碑状态（0.8.0 能力冻结 + 0.9.0 进展）

> 本文档记录 0.8.0「1.0 能力冻结」里程碑的达成状态与证据链，并逐项盘点 0.9.0「生产候选」
> 进展，供 0.9.0/1.0.0 评审使用。
> §一-§五（0.8.0 冻结事实）基于冻结时 master（commit 4ad8c4a）；§六（0.9.0 剩余工作清单）
> 与 §七（0.9.0 进展盘点）基于 master 61b9cc5（本轮 HEAD，迭代三+四已合入：E1 §12.4 生产
> 捕获点 ce2b8b3、E3a Git Commit 嵌入 99d5670、E3b Secret 扫描门禁 eefde7e、E3c N5 处置
> 8a9ab82/34315c8、E4 约束修复 76af80f + bfb001e；迭代五已合入：H1 UI 本地化基础层 8e8ac6f、
> H2 web/assets UI 产物再生成 53b6402；迭代六（H4/H5）已合入：H5 UI 本地化完整落地 d3f7769
> （827 键 En/Zh 双语目录 + 运行时语言选择器 + URL fragment 持久化）与产物再生成 0f91c17、
> H4 发布管道代码侧 34503ea（scripts/ 5 脚本）+ d77d54e（ci.yml release-artifacts job，证书
> 到位即启用）；深度审查批次（2026-08-12 多角色多维度）已合入 9 个修复提交：0984fd4（backup
> 断言派生）、e8424df（secret gate strings_catalog 宏体豁免）、e611ed7（test-support 借用）、8147bc9（认证
> 边界硬化 B1-B4）、1711329（迁移 down 先子后父）、6128a17（ETag 携带 + 412 路径）、02370db
> （端点读门 + 恢复判定）、fb660d5 + a4950fc（i18n 槽位/本地化 + 产物），详见 §7.4；
> **迭代七已合入（2026-08-12，HEAD = 61b9cc5，9 个提交）**：84451b9（mock-bmc 统一二进制）、
> 044bae2（AMI/HPE 真网关 E2E）、c4dd335（i18n fragment 纯函数测试）、8482d85（decode-failures
> 贯通测试）、4897b22（入网首刷走端点读门）、e7aef53（限流器桶键剪枝）、02459dc（恢复前
> 快照）、83ff07f（free-port 竞态消除）、61b9cc5（secret-gate 白名单行号对齐 backup.rs 漂移，
> 门禁漂移检测触发-修复闭环），§九 遗留 8 项清零 + T-C 文档化决策，三批五维审计
> APPROVE，详见 §7.5）。
> **迭代八已落地（2026-08-12，HEAD = d1b375c）**：进程级故障注入演练套件 `scripts/drills/`
> 9 个文件（7 个 PowerShell 脚本——drill-lib.ps1 共享库 + 6 个 drill〔backup-restore-cycle /
> sqlite-write-interruption / bmc-restart-during-task / large-file-interruption /
> kill-mid-operation / delay-proxy〕+ RESULTS.md 结果登记表 + 内嵌 .gitignore）入库（**本批
> 6 个提交**：a80edda（drills 套件）、9f9606e（容量建议）、3fd0a46（gitignore）、3dc4f74
> （迭代八登记）、6a42a96（挂起防护一致性修复）、d1b375c（行号修复））：覆盖设计 §19.3 剩余
> 4 项中的 3 项（产品进程在任务中被终止 /
> BMC 更新中重启 / SQLite 写入中断）+ §20.1/§20.2 备份恢复 + §0.4.0 大文件中断，套件仅依赖
> 本机 mock-bmc 与自研 delay relay（TCP 延迟中继），无物理设备/外部证书依赖；**磁盘空间不足
> 仍保持未覆盖**（无管理员权限的可靠模拟手段受限，成本/收益评估后登记）。**首轮实跑 6/6 SKIP**
> （2026-08-12，如实登记）：执行上下文（Claude Code 工具进程 spawn）ConPTY 不可用——伪控制台
> 子进程一律 0xC0000142 启动失败、零输出（含 cmd.exe 对照），产品 rutilus.exe 在普通管道下
> 正确报错退出 1（"local unlock requires an interactive terminal"），非产品问题；同时暴露套件
> 硬挂起缺陷（>20 分钟）。挂起防护修复已完成（只改 drill-lib.ps1：Start-ConPtyProcess 启动
> 探测 / Wait-ConPtyOutput 超时〔默认 60s〕/ Stop-ConPtySession·Dispose 看门狗化），同环境
> 复测 3 次均 0.6s 快速 FAIL、超时分支 3.2s 有界返回、清理 0s；**功能验证待真实交互控制台
> 会话复跑**（人工依赖项）。发布级容量建议已发布（提交 9f9606e 已在容量主题提交，见 §六与
> §7.1「性能容量测试」行）；详见 §7.1「故障注入」行与 §7.2-B。
> **迭代十已落地（2026-08-12，HEAD = 7533c03，3 个提交）**：`c607ae9`（test(migration)：迁移
> down 顺序机械门禁 `migration/tests/down_order_gate.rs`（1286 行，迭代十二修复后）——FK 边跨文件静态提取
> （`ForeignKey::create` from/to + `DeriveIden` iden 解析 + raw `ALTER TABLE REFERENCES`）、
> 双序列检查（down 函数体内 drop 序 + 全文件 raw `DROP TABLE` 序）、循环对豁免
> （credentials↔credential_versions 由 `m20260805_000001` 的 NULL-out update 破环）、8 测试
> （含注入坏序/不可解析表名自检）；真实突变验证（父先子后注入 → 精确 file:line 报错）；迁移
> 全量 23 目标全过、clippy/fmt 干净；该纪律此前靠审查维护（深度审查批次 1711329），现已
> 机械化）、`5359f2f`（fix(ci)：按实际产物名收集 cyclonedx SBOM——本机试跑 cargo-cyclonedx
> 0.5.9 实证：产出 `<包名>.cdx.json`（15 个，per-crate 目录）而非 bom.json，原
> `find -name bom.json` 首跑必然失败；已改 `-name '*.cdx.json'` + 注释如实化；ubuntu 实跑
> 仍属首跑确认点——消掉首跑确认点 1 项：工具行为与 workspace 兼容性已本地验证）、`7533c03`
> （docs：release-readiness 头注 bump，后经迭代十一 NOTE 修复统一为「迭代八合入后复核版
> HEAD=d1b375c」口径）；**迭代十一已落地（2026-08-12，HEAD = b685818）**：`74570bc`（docs:
> register iteration ten and sync the gate counts）+ `b685818`（test(migration): precise the
> down-order gate comments，注释精确化：FK 来源三文件明细 + 诚实规则缝隙注记，8/8 复跑全绿）。
> 所有条目均基于真实代码/测试事实，标注来源文件与测试名；不写设计
> 文档没有且代码不支持的内容。设计基线见仓库根目录 `redfish-management-product-final-design.md`
> （修订冻结版）。全文「file:line」引用已逐一核对当前 master 实际行号（2026-08-12 复核）：
> §一-§五 的事实锚定冻结时 commit 4ad8c4a，行号一律以当前 master 为准。

## 一、冻结基线事实（nv-redfish）

### 1.1 版本记录与锁定

| 项 | 值 | 事实来源 |
|---|---|---|
| 冻结的发布基线版本（`NV_REDFISH_RELEASE_BASELINE_VERSION`） | `0.13.0`（2026-08-04 发布） | `infra-redfish/src/release_baseline.rs:59` |
| 已知更新正式版本（`NV_REDFISH_KNOWN_NEWER_STABLE_VERSION`） | `0.14.2`（2026-08-10 发布，未 yank）——升级决策留给冻结评审，评审时评估 | 同上 `release_baseline.rs:68` |
| 冻结策略 | 选择当时最新且已验证的稳定版本；评审期间开发基线允许先行于冻结版本（不把 `DEVELOPMENT == RELEASE` 当不变量断言） | `release_baseline.rs:14-25`；设计文档 §2.3 |
| workspace 固定方式 | `nv-redfish = { version = "=0.13.0", default-features = false, ... }`（精确版本 + 16 个显式 feature） | 根 `Cargo.toml:35` |
| Cargo.lock 锁定 | `nv-redfish 0.13.0`，checksum `038dbfb6b44e79e1246ef66683cad4c265069f4b0b92567553b380d8b8ee763c`；CI 全程 `--locked` | `Cargo.lock:2486-2490`；`.github/workflows/ci.yml` |
| Schema 层版本 | `nv-redfish-schema` / `nv-redfish-core` / `nv-redfish-bmc-http` / `nv-redfish-csdl-compiler` 均为 `0.13.0`，由测试逐项对 Cargo.lock 校验 | `release_baseline.rs:280-285`；测试 `release_baseline_schema_versions_match_the_committed_lockfile`（`release_baseline.rs:1734`） |

### 1.2 Feature 面

- 显式启用 17 个（根 `Cargo.toml` 16 个 + `infra-redfish/Cargo.toml` 追加的 `update-service-deprecated`），
  由门禁测试与 workspace 清单**双向**校验（多一个或少一个都失败）；
- 编译完整面 58 个（`RELEASE_BASELINE_ENABLED_FEATURES`）：0.13.0 feature 全集 59 个中仅 `default`
  不编译（`default-features = false`）。

事实来源：`infra-redfish/src/release_baseline.rs:79`（显式 17）、`:111`（编译 58）、`:177`（0.13.0 全集 59）；
测试 `release_baseline_explicit_features_match_the_workspace_manifests_bidirectionally`
（`release_baseline.rs:1395`）、`release_baseline_enabled_features_are_the_complete_compiled_surface`
（`release_baseline.rs:1422`）。

### 1.3 模块面

- 公开模块 29 个，全部带产品分类与决策（`RELEASE_BASELINE_MODULES`）：
  19 能力映射 / 8 基础设施 / 0 遗留兼容 / 2 内部；
- 门禁测试断言分布冻结，并与 vendored `nv-redfish-0.13.0/src/lib.rs` 双向核对（记录无缺漏、无虚记）。

事实来源：`release_baseline.rs:372`；测试 `release_baseline_every_module_is_classified_with_a_decision`
（`release_baseline.rs:1471`，断言 19/8/0/2 于 `1506-1513`）、
`release_baseline_module_inventory_matches_the_vendored_lib_rs`（`release_baseline.rs:1589`）。

### 1.4 操作面

- 公开类型化写操作 43 个，全部有显式映射状态（`RELEASE_BASELINE_OPERATIONS`）：
  映射 31、编译 CSDL 面 6、基础设施 2、内部 1、明确不提供（OutOfScope）3；
- **未映射操作 = 0**（`FROZEN_UNMAPPED_OPERATION_COUNT`），OutOfScope 冻结计数 = 3
  （`FROZEN_OUT_OF_SCOPE_OPERATION_COUNT`）——两项都由门禁测试 pin 死，既不能静默增加也不能静默删除。

事实来源：`release_baseline.rs:677`（43 项清单）、`:1025`（未映射 = 0）、`:1039`（OutOfScope = 3）。

### 1.5 能力账本与 Hash

- 账本 47 条（33 标准 + 14 OEM）：`CAPABILITY_LEDGER_ORDER`（`domain/src/capability.rs:401`）、
  `OEM_CAPABILITY_LEDGER_ORDER`（`capability.rs:462`）；
- 账本 Hash（§15.3 算法：SHA-256 over 账本顺序产品码串接，无分隔符）：

```text
84caf558f9ae77ea9cd4c3e7a2271de63a65253881fd70bb0aae185e2356d24f
```

  `RELEASE_BASELINE_LEDGER_HASH`（`release_baseline.rs:1049-1052`），与中心协商 golden 一致
  （`center-protocol/src/negotiation.rs:162` `GOLDEN_LEDGER_HASH`）；
- 测试 `release_baseline_ledger_hash_matches_the_negotiation_golden`（`release_baseline.rs:1577`）证明
  快照 = 新鲜计算值 = 协商 golden，两侧任何漂移都会失败。

## 二、五条验收达成证据链

验收原文见设计文档 §0.8.0「验收」（`redfish-management-product-final-design.md:2758-2766`）。

### 验收 1：公开能力账本覆盖率 = 100%

| 证据 | 位置 |
|---|---|
| 账本 47 条 = 0.13.0 全部公开能力（33 标准 + 14 OEM），`CAPABILITY_LEDGER_ORDER` | `domain/src/capability.rs:401` |
| 账本缺口为空：`PENDING_LEDGER_FEATURES = []`——0.12.1→0.13.0 新增的 `ports` 已入账，未来出现缺口表现为门禁失败而非静默遗漏 | `infra-redfish/src/release_baseline.rs:1236` |
| 编译面与领域账本双向对齐：`compiled_oem_features_match_the_domain_oem_capabilities_exactly`（14 个 OEM feature 与 `OEM_CAPABILITY_LEDGER_ORDER` 同序逐一相等） | `infra-redfish/src/lib.rs:158` |
| 每个标准 feature 恰好被一个模块或文档化 schema 面覆盖：`release_baseline_ledger_mapped_modules_are_exactly_the_ledger_features` | `release_baseline.rs:1517` |
| 账本 Hash 同时被冻结记录与中心协商 golden 钉死（见 §1.5） | `release_baseline.rs:1577`、`center-protocol/src/negotiation.rs:269` |

### 验收 2：未分类公开模块 = 0

| 证据 | 位置 |
|---|---|
| 29 个模块条目全部带 `BaselineModuleClassification` 分类 + 产品决策（`§2.4`「产品决策」要求应用到模块轴） | `release_baseline.rs:372`（分类枚举 `296-308`） |
| 门禁测试逐条断言分类非空、名称无重复、账本映射模块必有门控 feature，并把分布冻结为 19/8/0/2 | `release_baseline.rs:1471`（断言 `1506-1513`） |
| 与 vendored 源双向核对：每个记录模块真实存在于 `nv-redfish-0.13.0/src/lib.rs`，每个公开模块都被记录 | `release_baseline.rs:1589` |
| 每个模块的门控 feature 都在编译面内（`release_baseline_every_module_gating_feature_is_compiled`） | `release_baseline.rs:1457` |

### 验收 3：未映射公开操作 = 0

| 证据 | 位置 |
|---|---|
| `FROZEN_UNMAPPED_OPERATION_COUNT = 0`，门禁测试清点全部 43 条并断言 = 冻结计数 | `release_baseline.rs:1025`；测试 `release_baseline_unmapped_operation_count_is_frozen`（`release_baseline.rs:1688`） |
| 43 条逐条有状态（Mapped / CompiledCsdlOnly / Infrastructure / Internal / OutOfScope），12 个 `RedfishCommand` 家族全部被至少一个操作条目覆盖（双向映射表） | `release_baseline.rs:677`；测试 `release_baseline_operations_inventory_is_internally_consistent`（`release_baseline.rs:1638`） |
| OutOfScope 3 项各带一行理由与完整决策注记，计数冻结（`FROZEN_OUT_OF_SCOPE_OPERATION_COUNT = 3`）：`system.set-boot-order`（Boot 家族只提供 `BootSourceOverride`，永不提供持久 boot-order 变更）、`update.simple`（SimpleUpdate 接受远程镜像 URI，§14.3 只上传制品字节）、`update.start`（§14.3 是完整上传即应用路径，独立 StartUpdate 入口不提供） | `release_baseline.rs:745, 778, 790`、`:1039`；测试 `release_baseline_out_of_scope_operation_count_is_frozen`（`release_baseline.rs:1705`） |

### 验收 4：私有 BMC HTTP 请求 = 0

| 证据 | 位置 |
|---|---|
| 架构边界：全仓 `Cargo.toml` 核查，唯一声明 `nv-redfish` 依赖的 crate 是 `infra-redfish`（根 `Cargo.toml:35` 仅为 workspace 依赖声明，其余 14 个 crate 均无该依赖） | `infra-redfish/Cargo.toml:14` |
| 所有 BMC HTTP 经 nv-redfish 类型化传输：`UpstreamBmc = HttpBmc<NvHttpClient>`，传输由 `NvHttpClient::with_client` 注入 | `infra-redfish/src/redfish_gateway.rs:32-33, 338, 1115` |
| 编译期边界标记 `CompiledCapabilityBoundary`：所有 BMC schema 类型只经此 crate 进入（`PhantomData<fn() -> nv_redfish::schema::...>`） | `infra-redfish/src/lib.rs:116-138` |
| TLS 栈为 rustls 全栈；`native-tls`/`openssl` 在 `deny.toml [bans] deny` 禁令内，设备连接只走 HTTPS，无私有 HTTP 客户端 | 根 `Cargo.toml:40-44`；`deny.toml` |

### 验收 5：裸 SQL = 0

| 证据 | 位置 |
|---|---|
| 机械门禁（DDL-only 例外边界）：迁移 crate 只允许 `CREATE`/`ALTER`/`DROP`/`PRAGMA` 裸语句（SeaQuery 表达不了的 SQLite DDL）；`SELECT`/`INSERT`/`UPDATE`/`DELETE` 等 9 类 DML 词在任何字符串字面量中都被禁止 | `migration/tests/bare_sql_gate.rs:35, 40` |
| 门禁逐文件扫描（注释/属性忽略、普通与 raw 字符串字面量均识别，无法用引号绕过）：`migration_bare_sql_is_ddl_only`、`persistence_raw_sql_is_test_only_pragma`（persistence 例外仅测试作用域 PRAGMA） | `bare_sql_gate.rs:445, 456` |
| 表重建的数据复制全部改写为 SeaQuery `INSERT ... SELECT`（`select_from`）：16 处，分布于 8 个迁移文件（`m20260807_000001/000003/000005/000006/000007/000008_nvidia_families` 系列与 `m20260810_000001/000002`） | `migration/src/` 全目录清点（如 `m20260810_000001_center_data_sites.rs:102,150,209`） |

## 三、0.8.0 冻结产物清单

设计文档 §0.8.0「内容」逐项对照（`redfish-management-product-final-design.md:2745-2756`）：

| 冻结产物 | 冻结值 | 事实来源 |
|---|---|---|
| Cargo.lock | `nv-redfish 0.13.0`（checksum `038dbfb6...`） | `Cargo.lock:2486-2490` |
| Feature 面 | 显式 17 / 编译 58（0.13.0 全集 59 减 `default`） | `release_baseline.rs:79, 111` |
| Schema | `nv-redfish-schema/-core/-bmc-http/-csdl-compiler` 全部 `0.13.0` | `release_baseline.rs:280-285` |
| 模块 | 29（19 能力映射 / 8 基础设施 / 0 遗留 / 2 内部） | `release_baseline.rs:372` |
| 操作 | 43（映射 31 / CSDL 面 6 / 基础设施 2 / 内部 1 / OutOfScope 3） | `release_baseline.rs:677` |
| 能力账本 Hash | `84caf558...d24f`（见 §1.5） | `release_baseline.rs:1049-1052` |
| Center Protocol | v1（`CENTER_PROTOCOL_VERSION = 1`，由 `protocol_constants_are_pinned` 测试钉死） | `center-protocol/src/lib.rs:50`（测试 `lib.rs:383`） |
| 数据库 Schema | 21 个 migration（`m20260805_*` 11 + `m20260807_*` 8 + `m20260810_*` 2）；迭代三/四新增 2 个（`m20260812_000001_resource_decode_failures`、`m20260812_000002_resource_feature_lists`），现共 **23 个** | `migration/src/`（迁移测试 `migration/tests/initial_storage.rs`、`migration/tests/resource_feature_lists.rs`） |
| UI 导航 | 17 个视图（`ConsoleView::ALL: [ConsoleView; 17]`：Overview/Groups/Credentials/AddEndpoint/Import/Audit/Capabilities/Operations/Events/Artifacts/Telemetry/Diagnostics/Users/Sessions/CenterSites/CenterOperations/CenterBindings） | `ui/src/lib.rs:2902` |

## 四、0.8.0 期间新增能力盘点（简表）

| 面 | 新增内容 | 事实来源 |
|---|---|---|
| 命令家族（12 个全部落地） | 全部 12 个 `RedfishCommand` 家族有产品映射：account（5 操作）、单资源动作（system/manager/chassis reset 与 manager.reset-to-defaults、power-supply.reset 共 5）、log.clear、control.update、telemetry（7：enable + metric/report definition 生命周期）、event 订阅（2）、boot/secure-boot（CSDL 面 4）、update（patch/http-push/multipart 3 路径）、oem（NVIDIA 9 个类型化 action） | `release_baseline.rs:646-659`（`REDFISH_COMMAND_FAMILIES`）；`domain/src/redfish_command.rs:3069`（12 变体）；telemetry 家族落地 merge 8587f72 |
| OEM 读取 | 新增 AMI/HPE/LiteOn/Delta 4 个读取家族（6 个读取面：AMI `AmiServiceRoot` + `ConfigBmc`、HPE `HpeiLoServiceExt` + `HpeiLo`、LiteOn 电源、Delta 电源）；叠加既有 Dell/NVIDIA/Lenovo/Supermicro，14 个 OEM feature 全编译 | commit 1618577（`feat(infra-redfish): read the ami hpe liteon and delta oem families`）；`api/src/lib.rs` §0.5.0 OEM family member 面；`infra-redfish/src/lib.rs:55-70` |
| at-rest 加密 | 命令列 + 中心队列：`operations.command` / `batch_operations.command` / `center_outbox.payload_json` / `center_inbox.payload_json` 用 XChaCha20-Poly1305 信封（`RUTC1:` 前缀版本化，AD 绑定行身份，可区分加密行与历史明文行）保护 | `security/src/command_cipher.rs:1-43` |
| CI 门禁补全 | nextest（`--test-threads 4`）、llvm-cov（`--fail-under-lines 80`）、machete、deny、clippy `-D warnings`、wasm32 UI 产物 diff、Capability Ledger Check、Release Baseline Check | `.github/workflows/ci.yml:108-244`（§19.4 门禁步骤：clippy `:115-116`、nextest `:157-159`、llvm-cov `:168-172`、deny `:181-185`、machete `:211-213`、wasm32 产物 diff `:234-244`）与 `:312-330`（Capability Ledger Check `:315-317`、Release Baseline Check `:327-329`） |
| 测试基建 | 故障注入与 Supermicro E2E 覆盖落地 | commit 4ad8c4a（`merge: land the fault-injection and supermicro e2e coverage`） |
| Overview 聚合 | §14.2 首页聚合区块落地：`GET /api/v1/overview` 服务端聚合（api 契约 + application `OverviewQuery` + web 路由），UI 首页仪表盘（Endpoint 计数/厂商分布/健康分布/运行中 Operation/最近事件/固件摘要/能力覆盖/数据陈旧程度），批量刷新与清单刷新后同步重载 | commit 4d1d27c（`feat(ui): render the §14.2 homepage overview dashboard`），链路 commit c3d7198 / e7f8dd4 / 70279c0 |

## 五、已知边界（冻结时如实记录）

| 边界 | 说明 | 事实来源 |
|---|---|---|
| OutOfScope 3 项 | `system.set-boot-order`（Boot 家族只提供 `BootSourceOverride` 一次性/连续覆盖，永不提供持久 boot-order 变更）；`update.simple`（SimpleUpdate 接受远程镜像 URI，§14.3 只上传制品字节、不接受用户 URI）；`update.start`（完整上传即应用路径已由 `RedfishCommand::Update(UpdateCommand::StartUpdate)` 覆盖，独立 StartUpdate 入口不提供）——均为显式产品决策，区别于"应该实现但尚未实现"的 Unmapped | `docs/known-limitations.md` §一 |
| probe-only 的 OEM 项 | `oem-nvidia-cper` / `oem-nvidia-fabrics`：能力状态在命名空间广告粒度判定（Nvidia 命名空间存在即 Supported）；CPER 记录与 fabric 数据子面"only distinguishable when the read slice actually reads the OEM resource"，当前读取面不呈现记录数据 | `infra-redfish/src/redfish_gateway.rs:13311-13317`（`OemNamespaceProbe` 文档，`domain/src/capability.rs:105-115`） |
| UI 表单 later-milestone | telemetry 写表单明确 later milestone（`CommandFamilyView::ALL` 不含 Telemetry，表单选择器返回 `OperationFormError::FamilyRequired`，界面提示 "The telemetry write form is a later milestone."）；log/control 无专用表单；命令执行面本身已完整映射 | `ui/src/lib.rs:5171, 6289-6291, 6438`（`CommandFamilyView::ALL` 9 家族 `:5171`、表单选择器 `FamilyRequired` `:6289-6291`、Telemetry 拒绝 `:6438`、提示文案串 `i18n.rs:1654` `hint_telemetry_later`）；`docs/known-limitations.md` §二 |
| 依赖风险登记 | quick-xml 0.38.4 两个 advisory（RUSTSEC-2026-0194 / 0195）在 `deny.toml [advisories] ignore`，每条带 **TRIGGER** 注释：一旦上游 csdl-compiler 接受 quick-xml >= 0.41.0，必须删除该条目并升级 nv-redfish；产品侧风险评估为低（仅编译期处理可信 CSDL 输入，csdl-compiler 从不调用 `NsReader`） | `deny.toml:29-34` |

## 六、0.9.0 剩余工作清单

来源：设计文档 §0.9.0「内容」与「最低验证规模」（`redfish-management-product-final-design.md:2778-2810`）、
`docs/known-limitations.md` §五-§八、`docs/support-matrix.md` §三。

| 工作项 | 目标/说明 | 来源 |
|---|---|---|
| 进程级演练（评审跟踪项 #9/#15） | 0.8.0 已落地故障注入覆盖（§19.3）与单进程测试；跨进程演练（操作执行 §13 与中心协议 §15 路径）属 0.9.0 | 设计文档 §19.3、§0.9.0 内容；`docs/known-limitations.md` §五 |
| 真实设备认证矩阵 | 五厂商至少各一台真实设备进入 1.0.0 认证矩阵（§19.1 Physical Device Test）；当前结论基于上游类型面与 mock/fixture 验证，不是实测认证 | 设计文档 §19.1；`docs/known-limitations.md` §五 |
| 容量测试 | 🟡 部分：合成规模压力/容量套件已落地（`persistence/tests/stress_capacity.rs` 3 个测试，覆盖设计最低验证规模：200 Endpoint Generation 一致刷新 / 100 Site outbox-inbox-cursor / 5,000 Endpoint 中心投影幂等重投，全部断言正确性不变量）；本机实测数据已记录（2026-08-12：debug 构建、WAL、Windows 开发机基线 + release 构建 3 次全过）；**发布级容量建议已发布（release 构建数据，2026-08-12，见 `operations-manual.md` §九）**；正式规模环境复核仍待做 | 设计文档 §0.9.0（2800-2810）；`stress_capacity.rs:47-52`；`docs/operations-manual.md` §九 |
| 发布构建验证 | 🟡 部分：aarch64 musl（cargo-zigbuild 交叉链接）与 macOS Universal 2（arm64 原生 + x86_64 交叉 + lipo 合并）构建步骤已入 CI（`.github/workflows/ci.yml:266-270, 289-304`）；Windows ARM64 **明确不入 CI**（hosted x64 Windows runner 无法提供 ARM64 MSVC 链接器与 SDK 导入库，真实原因注释于 `ci.yml:272-279`） | `docs/support-matrix.md` §三；`ci.yml` |
| 签名与 SBOM | Windows Authenticode 签名、macOS 签名和公证、Linux 独立签名、SBOM 生成（§5.4 发布配置） | 设计文档 §0.9.0（2792-2793）、§1.0.0（2847） |
| tracing 深化 | ✅ 已落地：`#[instrument]` span 接入 main/backup/center_client/center_runtime/event_listener/scheduler/site_runtime/standalone_runtime/telemetry_sampler（口令等敏感值 `skip_all`）；`--log-format <text|json>` 全局选项与 `init_tracing` 双格式层（默认 text，stderr + `RUST_LOG` 过滤不变） | `app/src/main.rs:27-41, 255-273`；`docs/operations-manual.md` §8.1 |
| 真实响应 fixture 目录 | §19.1 要求 Dell/HPE/Lenovo/xFusion/Inspur 各固件版本的脱敏真实响应 fixture 并随上游升级回归；当前代码库尚无 fixture 目录 | `docs/known-limitations.md` §五 |
| 其他 | UI 本地化（✅ 已完整落地：827 键 En/Zh 双语 + 运行时语言选择器 + URL fragment 持久化，见 §7.2-A「UI 本地化」行）；诊断解码错误路径展示（§12.4）与产品版本号统一策略已从本行移出（记录层已完成、捕获点待做与策略落地分别见 §7.1/§7.2-A） | `docs/known-limitations.md` §七、§八 |

## 七、0.9.0 进展盘点（2026-08-12，master a4950fc）

> 对照设计文档 §0.9.0「内容」（`redfish-management-product-final-design.md:2778-2798`）
> 逐项标注状态。0.8.0 冻结后与 0.9.0 相关的新事实：故障注入与 Supermicro E2E 覆盖落地
> （commit 4ad8c4a）、x86_64 musl 发布构建进入 CI（commit 3b1ab30）。
> 迭代二（master edead80）落地：产品版本号统一策略（commit 2de4351）、§12.4 诊断记录层
> （commit edead80）、NOTE 收尾（JoinError 记录、center_sync 重连进度重发测试、lipo
> verify_arch，commit f9a2da2/283e583/c017b7f）、安全审查 M1 修复（commit 72eccb5）。
> 迭代三+四（master bfb001e）落地：**E1 §12.4 生产捕获点**（gateway 捕获 + SQLite
> 同代事务持久化 + 新表，commit ce2b8b3）、**E3a Git Commit 嵌入**（`RUTILUS_GIT_COMMIT`
> job 级注入 + `dev` 降级，`rutilus version` 三行输出，commit 99d5670）、**E3b Secret 泄漏
> 扫描门禁**（commit eefde7e）、**E3c N5 处置**（编译期 const assert，commit 8a9ab82/34315c8）、
> **E4 约束修复**（`m20260812_000002` 重建两表 CHECK = 领域枚举 47 码 + 防回归机械测试，
> commit 76af80f + bfb001e），全部通过门禁（本机复跑实证：migration 30 / persistence 190+3 /
> application 293 / infra 291 / web 全过 / rutilus 141 / security 门禁 8 全过、
> `center_sync.rs` 33 测试全过、clippy 全 crate 零警告、fmt 干净，2026-08-12；迁移总数现为
> 23）。§六「其他」与 §7.1/§7.2-A 相关行已按新事实同步修订；
> `docs/known-limitations.md` §七「产品版本号」行与 §八 §12.4 行已同步更新（以 known-limitations 为准）。
> 迭代六（master d77d54e）落地：**UI 本地化完整落地**（H5 d3f7769：`strings_catalog!` 目录
> 扩至 827 键 En/Zh 双语、`Lang::{En, Zh}` 运行时语言选择、lib.rs `LanguageSelector` 组件与
> URL fragment 持久化（`#lang=`）；0f91c17 web/assets 产物再生成，§7.2-A「UI 本地化」行已转 ✅，
> ui 测试 127→136）与**发布管道代码侧**（H4 34503ea + d77d54e：`scripts/` 5 脚本 + ci.yml
> `release-artifacts` job，证书到位即启用，§7.2-A 新增「发布管道（代码侧）」行）；
> §7.1「签名构建」「SBOM」两行按新事实同步修订为 🟡 代码侧完成；
> `docs/known-limitations.md` §七「UI 本地化」「发布管道」行与 `docs/release-readiness.md`
> 条件 17 已同步更新（以 release-readiness 为准）。
> 深度审查批次（master a4950fc，本轮）落地：**9 个修复提交**（认证边界硬化 B1-B4 / ETag 携带
> 与 412 专用路径 / 端点读门与恢复判定 / 迁移 down 先子后父 / i18n 槽位与本地化 / secret gate
> strings_catalog 宏体豁免 / backup 断言派生 / test-support 借用），§7.2-A 新增 6 行、§7.1 相关行更新并新增
> §7.4 深度审查小节；全 workspace 门禁复跑全绿（fmt / clippy `-D warnings` 零警告 / 1701
> （`cargo test --workspace -- --list` 口径：lib/集成 1700 + doc 1）0 失败，2026-08-12）。
> 迭代七（master 61b9cc5，本轮）落地：**§九 遗留 8 项清零**（9 个提交 + T-C 文档化决策，见
> §7.5）：T-A 84451b9（mock-bmc 统一二进制，支持位置参数，删除未跟踪的 mock_bmc_server.rs
> 副本）、T-I 044bae2（AMI/HPE 真网关 E2E 5 测试，`gateway_mock_bmc.rs` 28 测试）、T-H
> c4dd335（fragment 纯函数拆分 + 4 测试，ui 141 全过）、T-G 8482d85（decode-failures 贯通
> 4 测试，application 301 全过）、T-B 4897b22（入网首刷走端点读门）、T-D e7aef53（限流器
> 桶键 4096 阈值剪枝，web 133 全过）、T-E 02459dc（恢复前快照三态，rutilus 145 全过）、
> T-F 83ff07f（bind 重试消除探测竞态，含第 5 处内联修复）、61b9cc5（secret-gate
> `ALLOWED_CONSTANT_HITS` 白名单行号 83/84→88/89 对齐 backup.rs 头文档漂移——门禁漂移检测
> 机制触发-修复闭环）；三批五维审计 APPROVE（审计记录
> 见 §7.5）；§7.1/§7.2-A 相关行按新事实同步（「所有 Fixture 回归」补 AMI/HPE 5 测试、
> 「备份恢复演练」补预快照三态与 10 测试、UI 本地化行补 T-H 拆分、端点读门行「遗留」已转 ✅、
> ETag 行「后续迭代」改为决策 c、备份往返测试与 auth.rs 全部行号按当前 master 重核）；
> `docs/known-limitations.md` §九 8 行与 `docs/security-review.md` N3 行已同步为最终状态
> （以 known-limitations 为准）。全 workspace 门禁复跑全绿（fmt / clippy `-D warnings`
> 零警告 / **1723**（`cargo test --workspace -- --list` 口径：lib/集成 1723 + doc 1 = 1724）
> 0 失败，2026-08-12；per-crate：test-support 55 / ui 141 / application 301 / web 133 /
> rutilus 145）。

### 7.1 逐项盘点

| 0.9.0 内容 | 状态 | 证据 |
|---|---|---|
| 五厂商实验室 | ⏳ 待做（依赖物理设备） | Mock 层已覆盖五厂商 profile（Dell/HPE/Lenovo/xFusion/Inspur，外加 NVIDIA/AMI/LiteOn/Delta/Supermicro，共 11 个 `MockProfile`，`test-support/src/mock_bmc/profile.rs:47-134`）；§19.1 Physical Device Test「五厂商至少各一台真实设备进入 1.0.0 认证矩阵」未达成（`docs/known-limitations.md` §五） |
| 所有 Fixture 回归 | 🟡 部分 | 合成 fixture（Mock BMC 固定资源树 + 确定性证书）回归已有：`test-support/tests/gateway_mock_bmc.rs` **28 个测试**（Service Root 读取/47 能力探测/核心资源读取/会话生命周期/各厂商 profile；迭代七 T-I 044bae2 补 AMI/HPE 真网关解码 E2E 5 个：`ami_profile_*` `:1793, :1861`、`hpe_profile_*` `:2003, :2070`、`namespace_free_endpoint_leaves_ami_and_hpe_families_absent` `:2202`）、`test-support/src/mock_bmc/tests.rs` 21 个，合计 test-support 55 测试全过；§19.1 Fixture Test 要求的**脱敏真实响应 fixture 目录**（五厂商各固件版本，随 nv-redfish 升级回归）尚无（`known-limitations.md` §五） |
| 故障注入 | 🟡 部分 | §19.3 多数场景已有单进程自动化覆盖：BMC 慢响应（`redfish_gateway.rs:24192, 25091`、`tls_probe.rs:568`）、TLS 证书变化（`domain/src/endpoint.rs:327` `verify_identity`/`TlsIdentityChanged`）、JSON 字段类型错误（`redfish_gateway.rs:19215, 19466` undecodable 成员跳过）、Action 响应丢失/写连接丢弃（`redfish_gateway.rs:28766, 28807`）、Task 消失（`redfish_gateway.rs:23109`）、SSE 流中断/解码失败（`redfish_gateway.rs:32605, 32674`）、重复消息/重复 Operation（`center_sync.rs:3478, 3528`、`operation_engine.rs:1332` 批量重投 no-op、`event_repository.rs:328` 事件去重）、大文件上传中断（`web/tests/artifact_path.rs:735`）、系统时间变化（`application/src/telemetry_sampler.rs:1050, 1076`、`operation_engine.rs:986` 时钟回拨如实记录）、文件写失败（`artifact_store.rs:1476`）、**登录 Token 失效**（`redfish_gateway.rs:23331` 任务轮询 401 → `AuthenticationFailed` 分类 + 临时 Session 删除、下轮自动重认证（清会话重建），`:33313-33347` SSE 请求 401 → `Reconnectable` 会话重建信号、端点不作消失处理）、**Schema 缺字段**（最小 schema 的字符串字段为 `Option` + missing-field 默认值：serde 把缺失属性与显式 null 同映射 `None`，`redfish_gateway.rs:4124`）；**未覆盖 4 项已更新（迭代八，2026-08-12）**：产品进程在任务中终止、BMC 更新中重启、SQLite 写入中断 3 项已有 Windows 侧进程级演练套件（`scripts/drills/`，见 7.2-B），**首轮实跑因执行上下文 ConPTY 不可用 6/6 SKIP**（防护修复后快速 FAIL 路径已验证），**功能验证待真实交互控制台复跑**；磁盘空间不足仍保持未覆盖（无管理员权限的可靠模拟手段受限） |
| 跨平台 E2E | ✅ 已完成 | windows/macos 任务新增跨平台 E2E 套件步骤（`ci.yml:130-147`）：`cargo test --locked -p rutilus-web`（`web/tests/` 9 个路径套件，均为无 socket/子进程/定时器的内存假件）+ `cargo test --locked -p rutilus --test version`；`app/tests/mock_center_client.rs`（回环 mTLS/WebSocket 中心互操作）因真实 socket 与握手/协商时序**故意不纳入**非默认任务（`ci.yml:139-141` 注释）——三平台 E2E 运行达成 |
| 数据库压力 | ✅ 已完成 | 压力/容量测试套件落地：`persistence/tests/stress_capacity.rs` 3 个测试（`two_hundred_endpoints_round_trip_with_generation_consistent_refreshes` :336、`one_hundred_sites_advance_outbox_inbox_and_sync_cursors` :585、`five_thousand_endpoint_projections_round_trip_at_the_center` :832），规模常量对齐设计最低验证规模（200/100/5,000，`:47-52`）；本机复跑 3 测试全过（2026-08-12，debug 构建、WAL） |
| 中心重连风暴 | ✅ 已完成 | 4 个**多连接并发**重连风暴测试（`center_sync.rs:4328` a_concurrent_reconnect_storm_resumes_every_outbox_from_its_last_ack、`:4448` a_reconnect_duplicate_burst_is_idempotent_and_effects_each_operation_once、`:4838` heartbeats_and_reconnects_interleave_without_interference、`:4968` the_local_queue_keeps_accumulating_while_disconnected_and_drains_in_order_on_reconnect）+ 1 个重连进度重发测试（`:4615` reconnect_resends_progress_for_active_operations_and_skips_completed_ones，NOTE 收尾 commit 283e583）；与既有 28 个单连接语义测试合计 33 个全过（本机复跑 2026-08-12） |
| 大文件更新 | 🟡 部分 | 分块上传机制全链路覆盖：4 MiB chunk 上限（`application/src/artifact_store.rs:64` `ARTIFACT_CHUNK_BASE64_MAX_BYTES`）、断点续传（`artifact_store.rs:1364`、`web/tests/artifact_path.rs:735`）、digest 校验（`artifact_path.rs:939`）、multipart 更新（`redfish_gateway.rs:32073, 32112` `verifies_update_*` 系列、`:31689` 断连 multipart 上传）、中心 manifest+chunk 分发（`center_sync.rs:3693`、`application/src/center/projection.rs:1729`）、8 MiB 帧上限（`center-protocol/src/framing.rs:18-31`）；Windows 侧进程级演练套件已落地（scripts/drills，2026-08-12，见 7.2-B）；真实大固件文件的端到端更新演练未做 |
| Secret 泄漏检查 | ✅ 结构性（含独立扫描门禁） | 结构性防护已有：API 永不回声秘密（`web/tests/write_path.rs:784, 816, 918`、`web/src/lib.rs:6238` `exposes_secret_free_complete_endpoint_inventory`、`persistence/src/credential_repository.rs:604`）、审计类型**构造上**不能携带秘密（`domain/src/audit.rs:318, 383`：非秘密身份数据/封闭类型参数摘要）、Center 投影排除凭据与会话（`application/src/center/projection.rs:55`）、命令载荷 at-rest 加密（`security/src/command_cipher.rs`）；**独立扫描门禁已落地（E3b）**：`security/tests/secret_leak_gate.rs` 3 规则（R1 硬编码秘密 / R2 内嵌私钥 PEM / R3 明文输出宏泄露）、8 测试、白名单 2 处（`ALLOWED_CONSTANT_HITS`，path+line+name+literal 绑定），作为 **CI 独立步骤**（`ci.yml:225-227` Secret leak gate：`cargo test --locked -p rutilus-security --test secret_leak_gate`，`if: matrix.is_default`）；E3b 原始提交 eefde7e 已含 `test-support` crate **目录级豁免**（fixture scope by definition——dev-only 测试替身 workspace crate，其秘密命名常量为 fixture 协议值，`secret_leak_gate.rs:55-59` 文档、`:1000-1002` 代码）；深度审查批次（commit e8424df）补 **`strings_catalog!` 宏体结构豁免**（CATALOG_MACRO 帧识别——豁免绑定宏帧而非值：`secret_leak_gate.rs:534` 常量、`:815-822` 扫描识别、`:60-66` 文档；新测试 `strings_catalog_macro_bodies_are_copy_construction_not_secret_assignments` `:1195`）；运行时抓包/日志复核未做（7.2-A/B） |
| 权限测试 | ✅ 已完成 | `role_masks_are_enforced_on_guarded_routes`（`web/src/lib.rs:11385`）、中心角色站点作用域（`web/src/lib.rs:12260, 12304`）、登录限速预算（`web/src/auth.rs:2769` rate_limiter_enforces_per_username_and_per_ip_budgets，迭代七 T-D 后重核）、BMC 写权限拒绝（`redfish_gateway.rs:29142` `rejects_the_write_when_permission_is_denied`） |
| 安全审查 | 🟡 已启动 | 启动交付物 `docs/security-review.md`（8 个审查范围 + §7.7 扫描全完成，无 BLOCKER）；MINOR-1（登录时间侧信道）已于迭代二修复（commit 72eccb5：未知用户名路径哑 Argon2id 验证，`web/src/auth.rs:1335-1346, 1438`）；N5 已于迭代三关闭（E3c 编译期 const assert，`web/src/lib.rs:1223`）；独立泄漏扫描门禁已落地（E3b）；**深度审查批次（2026-08-12）**：认证边界硬化（commit 8147bc9）——B1 密码策略 12 字符以 API 为执行边界（`web/src/auth.rs:1355-1357`，登录入口 enforce `:1386-1397`）、B2 429 限速拒绝不写审计（`:1402-1416`）、B3 改密后撤销失败不再静默——显式 500 + 审计失败记录（`:1830-1853`）、B4 disabled/credential-missing 分支补哑 Argon2id 验证（`:1446-1461, 1469-1481`，M1 残留面「需先已知用户名」理由已证反并关闭）；**迭代七**：N3 限速器桶键淘汰已实现（T-D e7aef53，见 §7.5），§九 其余 7 项已全部落地（见 §7.5），行号按当前 master 重核；外部评估仍待做（见 7.2-A「安全审查（启动）」行与 §7.4） |
| Migration 回归 | ✅ 已完成 | `migration/tests/` 20 个测试文件（initial_storage/operations/batch_operations/telemetry/events/groups_tags/center_tables/center_data_sites/center_role_sites/product_users/remote_tasks/artifacts/operation_failure_kinds/nvidia_families/nvidia_power_families/lenovo_families/bare_sql_gate/audit_action_shapes/audit_execute_operation/resource_feature_lists）；迁移总数 23（21 基线 + `m20260812_000001` + `m20260812_000002`）；迁移前自动备份（`persistence/src/lib.rs:510` backs_up_a_closed_database_before_applying_pending_migrations）；CI 独立 Migration Test 门禁（`ci.yml:306-310`）；**down 先子后父纪律**（深度审查批次，commit 1711329：先删引用子表再删父表，如 `m20260805_000005_operations.rs:131-138` 先 `OperationTarget` 后 `Operation`） |
| 备份恢复演练 | 🟡 部分 | 自动化往返覆盖完整（`app/src/backup.rs` 测试区 10 个）：`:1051`（往返保数据）、`:1095`（拒绝他实例包）、`:1121`（跨机恢复需源信封）、`:1208`（源口令对全新信封）、`:1240`（需停止实例）、`:1266`（拒绝未初始化目录）、`:1277`（拒绝不同产品版本）；**迭代七 T-E（commit 02459dc）补恢复前预快照三态**：`:1307`（失败恢复保留预恢复数据供回滚）、`:1384`（成功恢复清除预快照）、`:1404`（预快照拷贝失败不动源目录）——恢复流程见 `app/src/backup.rs:246-327`；CLI `rutilus backup`/`restore`（`app/src/main.rs:97, 144`）；备份快照计数钉死（`persistence/src/backup_snapshot.rs:624-627`：backup_applied 24 / supported 23）；**schema 版本断言已改为派生**（深度审查批次，commit 0984fd4：`app/src/backup.rs:1068-1072` 从 `rutilus_persistence::migration_counts` 读取 applied+pending 派生，加迁移不会再留陈旧断言）；0.9.0 验收「三平台安装、升级、备份、恢复通过」的演练未执行；Windows 侧进程级演练套件已落地（scripts/drills，2026-08-12，drill-backup-restore-cycle 覆盖 §20.1/§20.2 备份恢复进程级形态，见 7.2-B） |
| 签名构建 | 🟡 代码侧完成（证书未到位） | `scripts/` 签名脚本 3 份（sign-windows.ps1 / sign-macos.sh / sign-linux.sh）+ ci.yml `release-artifacts` job 的签名步骤已合入（commit 34503ea + d77d54e；步骤仅在对应 secret 配置时执行，未配置则 "signing skipped: certificate not configured"，`ci.yml:340-343, 468-546`）；Windows Authenticode、macOS 签名与公证、Linux minisign 独立签名在证书到位前保持跳过；首次实跑未做（6 项首跑确认点见 `release-readiness.md` 条件 17） | §5.4 发布配置；`release-readiness.md` 条件 17 |
| SBOM | 🟡 代码侧完成（首跑未做） | cargo-cyclonedx@0.5.9 钉版 + 每 crate BOM 收集步骤已入 `release-artifacts` job（`ci.yml:571-587`，commit d77d54e）；首次实跑生成并随包发布未做（证书到位后随发布演练） | §5.4 发布配置；`release-readiness.md` 条件 17 |
| 用户手册 | ✅ 已完成 | `docs/user-manual.md`（436 行，条目后标注来源文件；`rutilus version` 输出已更新为三行，含 Git Commit） |
| 运维手册 | ✅ 已完成 | `docs/operations-manual.md`（数据目录/主密钥/服务/备份恢复/升级/诊断/容量现状；§8.1 已补充 `--log-format json` 结构化输出与 span 上下文，§九已补充合成规模实测容量数据） |
| 支持矩阵 | ✅ 已完成 | `docs/support-matrix.md`（190 行：上游基线/平台矩阵/厂商支持现状/不承诺项）；§三「CI 现状」已更新（windows/macos E2E 套件、aarch64 musl、macOS Universal 2 入 CI，Windows ARM64 未入 CI 的真实原因，`support-matrix.md:90-95`） |
| 已知限制 | ✅ 已完成 | `docs/known-limitations.md`（OutOfScope 3 项/依赖风险登记/测试基建局限/容量现状等）；§八「§0.9.0 性能容量测试与真实容量建议」行已同步为部分落地（`known-limitations.md:135`：合成规模套件已实测、发布级容量建议已发布（release 构建数据，见 operations-manual §九））；§八「§12.4 诊断中的解码错误路径 / ExtendedInfo 展示」行已同步为**已实现**（`known-limitations.md:138`：E1 生产捕获点已合入，如实注记 odata_type 捕获时为 None 等）；§六标题已同步修订为「发布级容量建议未发布（合成规模已实测）」（2026-08-12，与 §八、operations-manual §九 一致），同日再更新为「发布级容量建议已发布（release 构建数据，正式规模环境复核仍待做）」（release 实测数据登记，2026-08-12，见 operations-manual §九）；§七新增深度审查批次条目（密码策略 API 边界 / 429 不写审计 / ETag 现状 / 迁移 down 纪律，`known-limitations.md:123-126`）；§九新增深度审查遗留项登记 8 项（`known-limitations.md:157-164`），迭代七已全部落地/处置（见 §7.5） |
| 性能容量测试 | 🟡 部分 | 压力/容量套件已落地（`persistence/tests/stress_capacity.rs`，规模达设计最低验证规模）并有本机实测数据（2026-08-12：debug 构建、WAL、Windows 开发机基线 + release 构建 3 次全过）：debug 下 5,000 投影写入 5.78s（≈865 行/s）、幂等重投 9.72s、5,000 行清单查询 0.482s，release 下 5,000 投影首次写入 ≈3.5–4.2s、幂等重投 ≈7.9s、清单查询 ≈0.16–0.20s；关键观察：写路径被 `write_gate`（`Semaphore(1)`，`persistence/src/lib.rs:101, 240`）全局串行化，5,000 规模耗时 ≈ 事务数 × 单事务成本——这是发布真实容量建议时最有价值的记录；**发布级容量建议已发布（release 构建数据，2026-08-12，见 `operations-manual.md` §九）**；正式规模环境复核仍待做 |

### 7.2 剩余工作精确分类

**A. 代码/CI 可做（不依赖外部资源，可直接进入迭代）**

迭代三+四（master bfb001e）已落地并从下表移出（详见 §7.1 与 §六）：数据库压力测试套件（`stress_capacity.rs`）、
中心重连风暴测试（`center_sync.rs` 并发测试）、跨平台 E2E 运行（`ci.yml:130-147`）、
`cargo audit` 独立门禁（`ci.yml:197-205`）、tracing 深化（`app/src/main.rs:255-273`）。
深度审查批次（master a4950fc，2026-08-12）已落地并从下表移出（详见 §7.4 深度审查小节）：
认证边界硬化（B1-B4）、ETag 携带与 412 专用路径、端点读门与恢复判定、迁移 down 先子后父、
i18n 槽位与本地化、secret gate strings_catalog 宏体豁免、backup 断言派生、test-support 借用修复。
迭代二（master edead80）落地：产品版本号统一策略（✅，下表该行已标证据）、安全审查
M1 修复（✅，下表「安全审查（启动）」行）；§12.4 诊断记录层部分落地（记录层完成、
生产捕获点待做，下表该行标 🟡）。迭代三+四（master bfb001e）落地：**§12.4 生产捕获点**
（E1，下表该行已转 ✅）、**Git Commit 嵌入**（E3a，并入「产品版本号统一策略」行）、
**Secret 泄漏扫描门禁**（E3b，并入「安全审查（启动）」行）、**N5 处置**（E3c）、**约束
修复**（E4）——详见下表各行的 ✅ 证据。迭代五（master 53b6402）落地：**UI 本地化
基础层**（H1 8e8ac6f + H2 53b6402，下表「UI 本地化」行已转 🟡，后续项登记于该行）。
迭代六（master d77d54e）落地：**UI 本地化完整落地**（H5 d3f7769 + 0f91c17，
下表「UI 本地化」行已转 ✅）与**发布管道代码侧**（H4 34503ea + d77d54e，下表新增
「发布管道（代码侧）」行，证书到位即启用）。
迭代七（master 61b9cc5）落地：**§九 遗留 8 项清零**（T-A 84451b9 / T-I 044bae2 /
T-H c4dd335 / T-G 8482d85 / T-B 4897b22 / T-D e7aef53 / T-E 02459dc / T-F 83ff07f /
61b9cc5（secret-gate 白名单行号对齐）+ T-C 快照 ETag 文档化决策，三批五维审计 APPROVE）
——下表「端点读门 + 恢复判定」行的
「遗留：入网首刷不经端点门」已转 ✅（T-B）、「ETag 携带 + 412 专用路径」行的「快照 ETag
接线为后续迭代」改为决策 c 已处置（T-C）、「UI 本地化」行补 T-H 纯函数拆分（c4dd335）、
「备份恢复演练」行补 T-E 预快照三态；详见 §7.5。

| 工作项 | 说明 | 证据/来源 |
|---|---|---|
| §12.4 诊断解码错误路径 / ExtendedInfo 展示 | ✅ 已实现（E1，commit ce2b8b3）：记录层——`ResourceExtendedInfo`/`ResourceDecodeFailure`（`resource_diagnostics.rs:36, 249`）、api 契约 9 字段（`api/src/lib.rs:1894-1905`）、web 投影（`web/src/lib.rs:3970-4001`，T-B 后重核）、ui 只读区块（`ui/src/lib.rs:15491`，T-H 后重核）、端到端测试（`web/tests/diagnostics_path.rs` 7 个测试，含 E1 新增 `:998` `refresh_capture_flows_into_the_diagnostics_response`）；**生产捕获点已实现**——gateway 捕获（`redfish_gateway.rs:8720` `DecodeFailureObservation`、`:8904/:8931/:8977` 捕获函数）、同代事务提交（`persistence/src/resource_snapshot_repository.rs:81-147`）、生产链路直连（`application/src/endpoint_refresh.rs:350-355`）、新表 + entity + 迁移（`migration/src/m20260812_000001`，E4 由 `m20260812_000002` 重建约束为领域枚举 47 码）；如实注记：捕获时 `odata_type` 为 `None`（`redfish_gateway.rs:8915-8922` `capture_fetch_failure` 恒传 None，解码失败记录不带类型） | `known-limitations.md` §八 |
| 产品版本号统一策略 + Git Commit 嵌入 | ✅ 已落地（commit 2de4351 + E3a 99d5670）：workspace 版本 = `0.9.0`（生产候选，与里程碑对齐），单一来源 = 根 `Cargo.toml` `[workspace.package] version`（`Cargo.toml:14`）；`rutilus version` 输出**三行**（`app/src/main.rs:733-737`）：产品版本 / `nv-redfish` 基线 / `git commit`（CI 注入 `RUTILUS_GIT_COMMIT`，`ci.yml:53-64`；`GIT_COMMIT` 常量 `main.rs:38-40`；本地无变量降级 `dev`）；`app/tests/version.rs:8-11, 27-36` 与 `app/tests/log_format.rs:7-10, 23-28` 派生断言（三行）；升级只改一处 | 根 `Cargo.toml:6-14`；`app/tests/version.rs`；`app/tests/log_format.rs` |
| UI 本地化 | ✅ 已完整落地（H5，commit d3f7769 + 0f91c17 + c4dd335）：`strings_catalog!` 目录扩至 **827 键 En/Zh 双语**（宏 `i18n.rs:43-160`，目录体 `i18n.rs:163-1858`；单一来源：字段声明 + En/Zh 构造器 + 完整性测试表）；`Lang::{En, Zh}` 与 `Lang::strings`（`i18n.rs:1860-1881`）、`thread_local!` 运行时语言选择（`i18n.rs:1938-1942`，测试线程各持己态）、`L()` 按当前语言解析 `'static` 目录（`i18n.rs:1968-1973`）、`format_catalog` 运行时槽位填充（`i18n.rs:1984-2006`）；lib.rs `LanguageSelector` 组件（`lib.rs:11640-11658`）+ **URL fragment 持久化**（fragment 是当前 web-sys feature 面唯一可用的浏览器存储，切换经 reload 全量重挂载；**迭代七 T-H c4dd335 已拆为纯函数 + 薄封装**：`stored_lang_code_from`/`lang_fragment_value` `i18n.rs:1915-1936`（host 可测）+ `stored_lang_code`/`persist_language`/`apply_language` `lib.rs:11607-11635`（wasm `browser` 模块薄封装，运行时行为不变）；启动恢复 `start()` `lib.rs:11661-11664`）；深度翻译完成（facts/健康词汇/`OEM_UNSUPPORTED_NOTICE` 等均入目录，`i18n.rs:825-829, 867`）；i18n 15 个测试（既有 11 个：完整性/占位符/双语同键/切换/格式化，`i18n.rs:2009-2185`；T-H 新增 fragment 纯函数 4 个：`i18n.rs:2192-2259`），ui **141 测试全过**、clippy/fmt 干净；J2 审计 3 处 zh 译法微修已合入（`type_nvidia_profile_file`/`fact_power_load_percent`/`fact_metric_values`，`i18n.rs:444, 597, 733`）。**后续触点**：localStorage 持久化（需扩展 web-sys feature）与更多语言 | `ui/src/i18n.rs`；`ui/src/lib.rs:11607-11664`；`web/assets/`；`known-limitations.md` §七 |
| 发布管道（签名 + SBOM + 校验清单，代码侧） | ✅ 代码侧完成（H4，commit 34503ea + d77d54e，证书到位即启用）：`scripts/` 5 脚本（sign-windows.ps1 / sign-macos.sh / sign-linux.sh / checksums.sh / checksums.ps1）；ci.yml `release-artifacts` job（`ci.yml:332-611`）——`v*` tag push 与 `workflow_dispatch` 触发（`ci.yml:28-40`）、`needs: ci` 门禁先行（`ci.yml:367`）、签名步骤仅在 secret 配置时执行（`ci.yml:340-343`）、base64 物化（`ci.yml:468-478, 493-502, 526-533`）、Windows thumbprint-only 模式（`ci.yml:480-488`）、cargo-cyclonedx@0.5.9 钉版 SBOM（`ci.yml:571-587`）、SHA-256 清单（`ci.yml:592-594`）、artifact 上传（`ci.yml:596-611`）；H4 审计处置已内嵌（musl-tools 补齐 `ci.yml:423`、单行 if 判定 `ci.yml:548-558` 等）；**首跑确认点 6 项**（证书到位后核验：musl-tools 安装 / cargo-cyclonedx@0.5.9 钉版 / base64 物化 / env `&&`·`||` 表达式 / thumbprint-only 模式 / 上传权限，详见 `release-readiness.md` 条件 17） | `scripts/`；`.github/workflows/ci.yml`；`release-readiness.md` 条件 17 |
| 安全审查（启动） | ✅ 已交付：`docs/security-review.md`（8 个审查范围 + §7.7 扫描全完成，无 BLOCKER）；**M1 已修复**（MINOR-1 登录时间侧信道，commit 72eccb5：`web/src/auth.rs:1335-1346` 哑 Argon2id 验证 + `:1438` 未知用户名分支调用），验证方式 = 调用计数对称断言而非墙钟计时（`web/src/lib.rs:9279` 计数、`:10725` 与 `:10789` 两分支各 1 次/失败、限速拒绝 0 次）；**N5 已关闭**（E3c：`web/src/lib.rs:1223` 编译期 const assert 钉死常量正性）；**独立 Secret 泄漏扫描门禁已落地**（E3b：`security/tests/secret_leak_gate.rs` 3 规则、8 测试；CI 独立步骤 `ci.yml:225-227` Secret leak gate）；**深度审查批次**：认证边界硬化（commit 8147bc9，B1-B4，详见 §7.1「安全审查」行与 §7.4）；**迭代七**：§九 8 项遗留全部落地/处置（N3 即 T-D e7aef53，详见 §7.5）；剩余：运行时抓包/日志复核与外部评估（1.0.0 发布评审建议项） | `docs/security-review.md`；设计文档 §0.9.0 |
| 约束修复（E4） | ✅ 已落地（commit 76af80f + bfb001e）：`migration/src/m20260812_000002_resource_feature_lists.rs` 重建 `resources`/`resource_decode_failures` 两表，`ck_resources_feature`/`ck_resource_decode_failures_feature` 允许域 = 领域枚举全部 47 码（此前 resources 37 / resource_decode_failures 36 且互相不一致）；`down` 对称恢复 37/36；防回归机械测试 `migration/tests/resource_feature_lists.rs`（`:248` 单测试，域码与约束逐字符双向钉死，不触库）；备份快照计数钉死 `persistence/src/backup_snapshot.rs:624-627`（backup_applied 24 / supported 23） | `migration/src/m20260812_000002`；`migration/tests/resource_feature_lists.rs` |
| 发布构建矩阵补齐（剩余部分） | aarch64 musl（cargo-zigbuild）与 macOS Universal 2（lipo）已入 CI（`ci.yml:266-270, 289-304`）；Windows ARM64 明确不入 CI——hosted x64 Windows runner 无法提供 ARM64 MSVC 链接器与 SDK 导入库（`ci.yml:272-279` 注释），需原生 ARM64 Windows runner 或本地验证后另行处理 | `ci.yml` |
| 认证边界硬化（B1-B4） | ✅ 已落地（commit 8147bc9，深度审查批次）：**B1 密码策略 12 字符**——`password_satisfies_policy`（Unicode 标量计数 ≥ `MIN_PASSWORD_CHARS`，`web/src/auth.rs:1355-1357`），登录入口在限速/查找/验证之前执行（`:1386-1397`：不占限速预算、不写审计——策略违规不是登录尝试）；**B2 429 拒绝不写审计**——限速拒绝无审计事件，429 本身即记录（`:1402-1416`：防审计表无界增长 + 写门饥饿）；**B3 撤销信号非可选**——改密后 `revoke_sessions_for_principal` 失败不再静默：显式 500 + 审计失败 outcome（`:1830-1853`）；**B4 disabled/credential-missing 分支哑验证**——两分支补同款哑 Argon2id（`:1446-1461, 1469-1481`），M1「需先已知用户名」残留面已证反并关闭（security-review §三 M1 行更新）；行号在迭代七（T-D e7aef53）后按当前 master 重核 | `web/src/auth.rs`；`docs/security-review.md` §三 |
| ETag 携带 + 412 专用路径 | ✅ 已落地（commit 6128a17，深度审查批次）：每个类型化 `update` 写携带**本次执行读取时**的目标文档 ETag——文档带 `@odata.etag` 时发送 `If-Match: <etag>`，BMC 以 `412 Precondition Failed` 拒绝即证明写未执行，gateway 报告 `CommandExecutionError::PreconditionFailed`（先重读目标，并发变更不被覆盖）；无 ETag 的文档保持传输层存在性 `If-Match: *`（§13.4 第二段）；action/create/delete 家族在类型化 API 中无 If-Match 通道，从不发送（`redfish_gateway.rs:598-611` 模块文档、`:12653-12690` 错误变体、`:14002-14062` 412 分类器、测试 `:25432, 27314-27420`）；**快照 ETag 接线已处置（决策 c，2026-08-12，T-C，见 §7.5 与 known-limitations §九该行）**——快照已持久化 ETag（`domain/src/resource_snapshot.rs:606-655, 790`、`persistence/src/resource_snapshot_repository.rs:402, 553-554, 605-608`），operation-executor 无消费方是登记过的决策而非遗留（执行时读取恒为分派时刻最新 ETag，快照 ETag 恒更旧、无独立写路径价值，接线不实施） | `infra-redfish/src/redfish_gateway.rs`；`known-limitations.md` §九 |
| 端点读门 + 恢复判定 | ✅ 已落地（commit 02370db，深度审查批次 + 迭代七 T-B 4897b22）：**端点读门**——进程级每端点 `Semaphore(1)`（`ENDPOINT_READ_GATES` `application/src/batch_refresh.rs:87`、`endpoint_read_gate` `:102-110`），批量与单端点刷新（web 路由统一走 `BatchEndpointRefresh`，`web/src/lib.rs:1637-1666`）在 `refresh_one` 全程持门（读取/Generation 提交/能力重探/快照替换，`batch_refresh.rs:287-335`），两处获取失败均分类为 `Coordination`（`:296-320`，`EndpointRefreshFailureKind::Coordination` `:394-396`）；**入网首刷已纳入同一读门（T-B，commit 4897b22）**——`EndpointEnrollment::enroll` 在 `refresh.execute` 前经 `endpoint_read_gate` 获取 permit（`endpoint_enrollment.rs:168-179`，失败分类为 `InitialRefreshCoordination`，web 错误映射 `web/src/lib.rs:3042-3050`），对抗测试 `initial_refresh_and_concurrent_batch_refresh_of_the_same_endpoint_never_overlap`（`endpoint_enrollment.rs:643`）钉死不重叠——known-limitations §九该行已转 ✅；**恢复判定**——只有 Running（dispatch 结果未知，§13.5）与 Verifying（重读在途）可恢复，`Validating` 经 `execute_operation` 续跑、`WaitingRemote` 归 Task monitor、终态为终（`application/src/operation_executor.rs:1685-1699` `NotRecoverable`，测试 `:4416` 非可恢复态无副作用拒绝、`:4516` 恢复竞态报告） | `application/src/batch_refresh.rs`；`application/src/endpoint_enrollment.rs`；`application/src/operation_executor.rs` |
| 迁移 down 先子后父 | ✅ 已落地（commit 1711329，深度审查批次）：多表 down 先删引用子表再删父表——`m20260805_000005_operations.rs:131-138` 先 `OperationTarget` 后 `Operation`；与既有 down 对称恢复（E4 `m20260812_000002` 重建约束）共同构成下迁纪律；机械门禁已落地：`migration/tests/down_order_gate.rs`（2026-08-12 迭代十），与裸 SQL 门禁同款纯静态扫描（无库），见 `known-limitations.md` §七该行 | `migration/src/` |
| i18n 槽位 + 本地化（+产物） | ✅ 已落地（commit fb660d5 + a4950fc，深度审查批次）：`format_catalog` 槽位填充硬化——`{}` 与命名槽位按模板出现顺序填充，**缺参时槽位原样呈现**（不静默丢文本，`ui/src/i18n.rs:1984-2006`，T-H 后重核）；`FORMAT_KEYS` 白名单（`:93`）+ 无游离占位符测试（`catalogs_have_no_stray_placeholders` `:2030`）+ 双语槽位序对齐测试（`zh_templates_keep_the_en_placeholder_order` `:2082`）+ 运行时格式化测试（`format_catalog_interpolates_positional_and_named_slots` `:2137`，缺参原样同测试内断言）；本地化补齐与 `web/assets` 产物再生成（a4950fc） | `ui/src/i18n.rs`；`web/assets/` |
| Secret 扫描门禁 strings_catalog 宏体豁免 | ✅ 已落地（commit e8424df，深度审查批次）：`strings_catalog!` 宏体（ui/src/i18n.rs）是**目录构造而非代码**——宏内字段名是 i18n 键、字面量是双语文案，[R1] 会把目录条目误读为秘密赋值；豁免按**结构**绑定宏帧（CATALOG_MACRO 帧识别，`security/tests/secret_leak_gate.rs:534` 常量、`:815-822` 扫描识别、`:60-66` 文档），宏外同文件真实秘密赋值仍会被扫出，不白名单任何值；新测试 `strings_catalog_macro_bodies_are_copy_construction_not_secret_assignments`（`:1195`）；`test-support` crate 的**目录级豁免**（fixture scope by definition——dev-only 测试替身，mock 固定 `SESSION_TOKEN` 等为 fixture 协议值，不随发布产物出货，豁免绑定 crate 名而非值）属 E3b 原始提交 eefde7e（`:55-59` 文档、`:1000-1002` 实现）；新 crate 默认仍在扫描范围（`crate_directories` 相对 `CARGO_MANIFEST_DIR` 自动发现，`:867-882`） | `security/tests/secret_leak_gate.rs` |

**B. 依赖演练环境（物理设备 / 规模环境 / 三平台流程）**

| 工作项 | 说明 | 来源 |
|---|---|---|
| 五厂商实验室 | Dell/HPE/Lenovo/xFusion/Inspur 各至少一台真实设备进入 1.0.0 认证矩阵 | 设计文档 §19.1 |
| 真实响应 fixture 目录 | 五厂商各固件版本脱敏真实响应 + 随 nv-redfish 升级回归（fixture 抓取依赖设备） | 设计文档 §19.1 Fixture Test |
| 进程级故障注入演练 | **套件已落地（迭代八，2026-08-12）**：`scripts/drills/` 7 脚本 + RESULTS.md（Windows 本机形态：mock-bmc + 自研 delay relay，无物理设备/外部证书依赖），覆盖产品进程在任务中被终止（drill-kill-mid-operation）、BMC 更新中重启（drill-bmc-restart-during-task）、SQLite 写入中断（drill-sqlite-write-interruption）、备份恢复（drill-backup-restore-cycle，§20.1/§20.2）与大文件中断（drill-large-file-interruption，§0.4.0）；**首轮实跑 6/6 SKIP**（2026-08-12，如实登记：执行上下文 ConPTY 不可用——伪控制台子进程 0xC0000142 启动失败、零输出，非产品问题），挂起防护修复完成（只改 drill-lib.ps1，复测 3 次均 0.6s 快速 FAIL、超时分支 3.2s 有界返回、清理 0s），**功能验证待真实交互控制台会话复跑**；**磁盘空间不足仍未覆盖**（无管理员权限的可靠模拟手段受限，成本/收益评估后保持） | 设计文档 §19.3；`scripts/drills/` |
| 大文件更新演练 | 真实大固件文件的端到端更新（当前为分块机制级覆盖） | 设计文档 §0.9.0 |
| 备份恢复演练 | 三平台安装/升级/备份/恢复（0.9.0 验收） | 设计文档 §0.9.0 验收 |
| 性能容量测试 | 合成规模压力套件已落地并实测（`stress_capacity.rs`，2026-08-12）；**发布级容量建议已发布（release 构建数据，见 `operations-manual.md` §九）**；正式规模环境复核仍待做 | 设计文档 §0.9.0（2800-2810）；`operations-manual.md` §九 |
| Center/Site 长时间断线重连演练 | 0.9.0 验收项；并发重连风暴已自动化覆盖（`center_sync.rs:4328, 4448, 4615, 4838, 4968`），长时间（跨进程/跨天）真实断线演练仍未执行 | 设计文档 §0.9.0 验收 |

**C. 依赖发布管道（外部证书 / 签名服务 / 发布流程）**

| 工作项 | 说明 | 来源 |
|---|---|---|
| 签名构建 | Windows Authenticode、macOS 签名与公证、Linux 独立签名（§5.4 发布配置） | 设计文档 §0.9.0、§1.0.0 |
| SBOM | 生成并随发布产物发布 | 设计文档 §0.9.0、§1.0.0 |

### 7.3 0.9.0 验收对照（设计文档 §0.9.0「验收」，2812-2819 行）

| 验收项 | 现状 |
|---|---|
| P0/P1 缺陷清零 | ⏳ 发布评审流程项，无公开缺陷台账证据 |
| 无已知凭据泄漏 | 🟡 结构性证据充分（API 不回声/审计类型禁秘密/Center 投影排除/at-rest 加密），**独立扫描门禁已落地**（E3b，仓库级）；运行时抓包/日志复核未做 |
| 无已知重复执行 | ✅ 事件去重（`domain/src/event.rs:383`）、批量重投 no-op（`operation_engine.rs:1332`）、重复 offer 幂等（`center_sync.rs:3478, 3528`） |
| 无已知错误成功报告 | 🟡 写后重读验证（`redfish_gateway.rs:29667` 等 `verifies_*` 系列）、响应丢失→Unknown（`redfish_gateway.rs:28807`）；整体清零结论待评审 |
| 三平台安装、升级、备份、恢复通过 | ⏳ 演练未执行（7.2-B） |
| Center/Site 长时间断线重连通过 | 🟡 单连接语义（`center_sync.rs:2853` 等）与**并发重连风暴**（`center_sync.rs:4328, 4448, 4615, 4838, 4968`，33 测试全过）均已自动化覆盖；长时间（跨进程/跨天）真实断线演练未执行 |

### 7.4 深度审查（2026-08-12，多角色多维度）

> 多角色（安全 / 并发 / 数据 / 前端 / CI）多维度深度审查记录（HEAD = a4950fc）。方法：
> 只读代码 + 对抗验证（**16 项对抗验证**——对既有结论构造反例）；结果：**52 项发现**，其中
> **2 HIGH + 13 MEDIUM 已修复**（9 个修复提交，见下表），**1 项此前结论被推翻**（security-review
> §三 M1 行残留面「disabled/credential-missing 分支需先已知有效用户名、在威胁模型之外」——
> 对抗验证证反：已禁用/无凭据账户同样构成用户名存在性 oracle 且行为可观察，故 B4 补哑验证并
> 关闭该残留面，见 §7.1「安全审查」行）。**门禁复跑全绿（2026-08-12，master a4950fc）：fmt
> 干净、clippy `-D warnings` 全 workspace 零警告、1701 测试 0 失败**（9 提交合入后全量复跑；
> `cargo test --workspace -- --list` 口径：lib/集成 1700 + doc 1）。修复提交与
> 代码证据：

| 修复提交 | 内容 | 代码证据 |
|---|---|---|
| `0984fd4` | backup schema 版本断言派生（加迁移不再留陈旧断言） | `app/src/backup.rs:1068-1072`（从 `rutilus_persistence::migration_counts` 的 applied+pending 派生；T-E 后重核） |
| `e8424df` | Secret 扫描门禁 `strings_catalog!` 宏体结构豁免 | `security/tests/secret_leak_gate.rs:534`（`CATALOG_MACRO` 常量）、`:815-822`（扫描帧识别）、`:60-66`（文档）；新测试 `strings_catalog_macro_bodies_are_copy_construction_not_secret_assignments` `:1195` |
| `e611ed7` | test-support 借用修复（无文档触面） | `test-support/`（mock 状态借用/所有权调整） |
| `8147bc9` | 认证边界硬化（B1 密码策略 / B2 429 审计 / B3 撤销信号 / B4 哑验证补齐） | `web/src/auth.rs:1355-1357, 1386-1397, 1402-1416, 1446-1481, 1830-1853`（T-D 后重核） |
| `1711329` | 迁移 down 先子后父 | `migration/src/m20260805_000005_operations.rs:131-138` |
| `6128a17` | ETag 携带 + 412 专用路径 | `infra-redfish/src/redfish_gateway.rs:598-611, 12653-12690, 14002-14062`；测试 `:25432, 27314-27420` |
| `02370db` | 端点读门 + 恢复判定 | `application/src/batch_refresh.rs:87, 102-110, 287-335`；`application/src/operation_executor.rs:1685-1699`（测试 `:4416, 4516`） |
| `fb660d5` | i18n 槽位 + 本地化 | `ui/src/i18n.rs:1984-2006, 2030, 2082, 2137-2176`（T-H 后重核） |
| `a4950fc` | web/assets UI 产物再生成（i18n 本地化配套） | `web/assets/rutilus_ui.js`、`web/assets/rutilus_ui_bg.wasm` |

遗留项（LOW/NOTE，全部登记于 `docs/known-limitations.md` §九）：限流器桶键淘汰、i18n fragment
纯函数测试、decode_failures 贯通测试（endpoint_refresh 生产链路）、AMI/HPE 真网关 E2E、restore
预恢复副本、free_port TOCTOU、入网首刷绕端点门、快照 ETag 接线
（domain/persistence/operation_executor）。**以上 8 项已由迭代七全部落地/处置（2026-08-12，
master 61b9cc5，9 个提交 + T-C 决策，三批五维审计 APPROVE）——见 §7.5 与本行对应更新；§九
各行已转 ✅ 最终状态（以 known-limitations 为准）。**

### 7.5 迭代七：§九遗留项清零（2026-08-12，HEAD = 61b9cc5）

> 深度审查遗留的 8 项 LOW/NOTE（`docs/known-limitations.md` §九）经迭代七全部落地/处置：
> **9 个代码/测试提交**（T-A/T-I/T-H/T-G/T-B/T-D/T-E/T-F + 61b9cc5）+ **1 项文档化决策**
> （T-C：快照 ETag 保持只读角色，无独立写路径消费价值，接线不实施）。三批五维审计全部
> APPROVE（方法/结果/minor 观察见下）。§九 8 行、§七 ETag 行、`docs/security-review.md`
> §三 N3 行与 §4.3 行均已同步为最终状态（以 known-limitations 为准）。全 workspace 门禁
> 复跑全绿（fmt / clippy `-D warnings` 零警告 / **1723** 测试 0 失败，2026-08-12；口径
> `cargo test --workspace -- --list`：lib/集成 1723 + doc 1 = 1724）。

**落地提交与代码证据**：

| 提交 | 内容（§九 项） | 代码/测试证据 |
|---|---|---|
| `84451b9` | T-A：mock-bmc 支持位置参数（`mock-bmc <port> <profile>`），未跟踪的 `mock_bmc_server.rs` 副本已删除，统一为唯一规范 CLI | `test-support/src/bin/mock-bmc.rs`（`--help`/位置参数解析）；`test-support/src/lib.rs` 头文档 `:19, 46` 区段 |
| `044bae2` | T-I：AMI/HPE 读取家族经真实网关的 E2E 解码测试 5 个（`AmiServiceRoot`/`ConfigBmc`、`HpeiLoServiceExt`/`HpeiLo`），`gateway_mock_bmc.rs` 23→28 测试 | `test-support/tests/gateway_mock_bmc.rs:1793, 1861, 2003, 2070, 2202`（AMI/HPE probe+snapshot+absent，头注释 `:3-17`） |
| `c4dd335` | T-H：`#lang=` fragment 持久化拆为纯函数 + 薄封装，纯函数单测 4 个；ui 136→141 | `ui/src/i18n.rs:1915-1936`（`stored_lang_code_from`/`lang_fragment_value`）、`:2192-2259`（4 测试）；`ui/src/lib.rs:11607-11635`（wasm 薄封装） |
| `8482d85` | T-G：decode-failures 生产链路贯通测试 4 个（真实 `EndpointRefresh` + 真实 `SqliteStore`）；application 293→301 | `application/tests/refresh_decode_failures.rs`（头注释 `:3-22`）；`application/src/endpoint_refresh.rs:350-355` |
| `4897b22` | T-B：入网首刷改走 `endpoint_read_gate`，与批量刷新不再重叠；新增 `EndpointReadGateError` 导出 | `application/src/endpoint_enrollment.rs:158-202`（gate 获取 `:168-179`、`refresh.execute` `:190`）、对抗测试 `:643`；`application/src/lib.rs:85-86`；`web/src/lib.rs:3042-3050`（错误映射） |
| `e7aef53` | T-D：限速器桶键 4096 阈值周期剪枝，内存有界 = 窗口活跃工作集 + 4096；web 全过（现 133） | `web/src/auth.rs:131`（`BUCKET_PRUNE_THRESHOLD`）、`:886-1016`（`LoginRateLimiter`/`BucketMap`/`prune_if_due`/`prune_expired`）；有界性测试 `:2848, 2901, 2945, 2973` |
| `02459dc` | T-E：恢复前先快照当前数据目录（三态：成功清除 / 失败保留供回滚 / 创建失败中止不动原目录）；rutilus 141→145 | `app/src/backup.rs:246-327`（`create_pre_restore_snapshot` `:300-308, 619-643`）、测试 `:1307, 1384, 1404` |
| `83ff07f` | T-F：free-port 探测竞态消除——各绑定点 `AddrInUse` 换端口重试（`is_raced_*_bind` + 重试循环），含第 5 处内联修复 | `app/src/center_acceptor.rs:964-993, 1005`；`app/src/center_runtime.rs:901-927`；`app/src/center_client.rs:629-654, 886`；`app/src/site_runtime.rs:1507-1544, 2048-2079` |
| `61b9cc5` | 第 9 个提交：secret-gate 白名单行号刷新——`ALLOWED_CONSTANT_HITS` 的 backup.rs 条目 83/84→88/89（对齐 T-E 后 backup.rs 头文档漂移）；path+line+name+literal 四元组绑定使常量移动即门禁失败，触发本提交刷新并重新确认无秘密材料（门禁漂移检测触发-修复闭环）；仅 2 行，无测试面变化 | `security/tests/secret_leak_gate.rs:325-333`（`ALLOWED_CONSTANT_HITS` `:325`，两条目 `:326-331`） |
| T-C（无提交） | 快照 ETag 接线为**文档化决策**：不实施 | 决策论证与证据见 `known-limitations.md` §九「快照 ETag 接线」行；快照 ETag 保持只读侧既有角色（诊断展示/中心投影） |

**三批五维审计记录**：

- **方法与维度**：与 §7.4 深度审查同框架的**五维审计**（安全 / 并发 / 数据 / 前端 / CI），
  分 3 批进行；每批对当批提交逐项核对：实现与 §九 登记方案的对应关系、关键 file:line
  **打开文件核实**（不凭 agent 报告转述）、测试计数复跑（per-crate 与 workspace 口径）、
  无回归面核查（既有测试全绿 + clippy/fmt 干净）。
- **结果**：3 批全部 **APPROVE**，无新增需转登记的发现（无 BLOCKER/HIGH/MEDIUM 级）；8 项
  遗留的登记行全部转 ✅ 最终状态。
- **minor 观察（保持既有登记，不阻塞）**：① T-F 的 `connect_with_retry_stops_on_the_stop_signal`
  「无人监听端口」用途保持探测语义（其后无真实 bind 可重试，`center_client.rs:886`）；② T-C
  决策下 §13.4「无 ETag 时保存操作前快照」由传输层 `If-Match: *` + 执行后重读覆盖，无并发
  保护，如实标注（`known-limitations.md` §九该行）；③ T-G 覆盖的解码失败记录 `odata_type`
  恒 `None`（捕获函数恒传 None，`known-limitations.md` §八注记）；④ 审计 I1 保持：
  `i18n.rs:1` 头注释 §5.1 引用不可核验（设计文档无「本地化/i18n」条目）。各批详细审计
  结论由实现 agent 侧持有，本行登记总指挥确认结论与可复核代码证据。

**测试计数（2026-08-12，迭代七合入后本机复跑，口径 `cargo test -p <crate> -- --list` / `cargo test --workspace -- --list` + `grep ": test$"`）**：

- per-crate：test-support **55**（gateway_mock_bmc.rs 28〔23 + T-I 新增 5〕+ mock_bmc/tests.rs
  21 + mock_center 5〔mod.rs 4 + tls.rs 1〕+ lib.rs 头文档 doc-test 1）、ui **141**（T-H 新增 fragment 纯函数测试 4 个；
  上轮登记 136，本轮复跑 141）、application **301**（293 + T-G 贯通 4 + T-B 对抗 4）、
  web **133**（T-D 新增有界性测试 4 个）、rutilus **145**（141 + T-E 预快照 3 + T-F 重试 1）；
- workspace 总计：**1723**（lib/集成 1723 + doc 1 = 1724），0 失败；fmt / clippy
  `-D warnings` 全 workspace 零警告；迭代八无新增 Rust 测试（drills 为脚本形态）。

**测试计数（2026-08-12，迭代十合入后本机复跑，口径 `cargo test --workspace --locked -- --test-threads 4`）**：

- per-crate：migration **38**（30 基线 + down_order_gate 新增 8）；五个核心 crate 与迭代七基线
  相等——test-support **55** / ui **141** / application **301** / web **133** / rutilus(app) **145**；
- workspace 总计：**1731**（lib/集成 1731 + doc 1 = 1732），0 失败；增量恰 +8（down_order_gate）；
  fmt / clippy `-D warnings` 全 workspace 零警告。
