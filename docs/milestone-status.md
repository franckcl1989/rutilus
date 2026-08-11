# Rutilus 里程碑状态（0.8.0 能力冻结）

> 本文档记录 0.8.0「1.0 能力冻结」里程碑的达成状态与证据链，供 0.9.0/1.0.0 评审使用。
> 所有条目均基于当前 master（commit 4ad8c4a）的真实代码/测试事实，标注来源文件与测试名；
> 不写设计文档没有且代码不支持的内容。设计基线见仓库根目录
> `redfish-management-product-final-design.md`（修订冻结版）。

## 一、冻结基线事实（nv-redfish）

### 1.1 版本记录与锁定

| 项 | 值 | 事实来源 |
|---|---|---|
| 冻结的发布基线版本（`NV_REDFISH_RELEASE_BASELINE_VERSION`） | `0.13.0`（2026-08-04 发布） | `infra-redfish/src/release_baseline.rs:59` |
| 已知更新正式版本（`NV_REDFISH_KNOWN_NEWER_STABLE_VERSION`） | `0.14.2`（2026-08-10 发布，未 yank）——升级决策留给冻结评审，评审时评估 | 同上 `release_baseline.rs:68` |
| 冻结策略 | 选择当时最新且已验证的稳定版本；评审期间开发基线允许先行于冻结版本（不把 `DEVELOPMENT == RELEASE` 当不变量断言） | `release_baseline.rs:14-25`；设计文档 §2.3 |
| workspace 固定方式 | `nv-redfish = { version = "=0.13.0", default-features = false, ... }`（精确版本 + 16 个显式 feature） | 根 `Cargo.toml:28` |
| Cargo.lock 锁定 | `nv-redfish 0.13.0`，checksum `038dbfb6b44e79e1246ef66683cad4c265069f4b0b92567553b380d8b8ee763c`；CI 全程 `--locked` | `Cargo.lock:2478-2481`；`.github/workflows/ci.yml` |
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
| 编译面与领域账本双向对齐：`compiled_oem_features_match_the_domain_oem_capabilities_exactly`（14 个 OEM feature 与 `OEM_CAPABILITY_LEDGER_ORDER` 同序逐一相等） | `infra-redfish/src/lib.rs:156` |
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
| 架构边界：全仓 `Cargo.toml` 核查，唯一声明 `nv-redfish` 依赖的 crate 是 `infra-redfish`（根 `Cargo.toml:28` 仅为 workspace 依赖声明，其余 14 个 crate 均无该依赖） | `infra-redfish/Cargo.toml:14` |
| 所有 BMC HTTP 经 nv-redfish 类型化传输：`UpstreamBmc = HttpBmc<NvHttpClient>`，传输由 `NvHttpClient::with_client` 注入 | `infra-redfish/src/redfish_gateway.rs:32-33, 338, 1114` |
| 编译期边界标记 `CompiledCapabilityBoundary`：所有 BMC schema 类型只经此 crate 进入（`PhantomData<fn() -> nv_redfish::schema::...>`） | `infra-redfish/src/lib.rs:116-138` |
| TLS 栈为 rustls 全栈；`native-tls`/`openssl` 在 `deny.toml [bans] deny` 禁令内，设备连接只走 HTTPS，无私有 HTTP 客户端 | 根 `Cargo.toml:33-37`；`deny.toml` |

### 验收 5：裸 SQL = 0

| 证据 | 位置 |
|---|---|
| 机械门禁（DDL-only 例外边界）：迁移 crate 只允许 `CREATE`/`ALTER`/`DROP`/`PRAGMA` 裸语句（SeaQuery 表达不了的 SQLite DDL）；`SELECT`/`INSERT`/`UPDATE`/`DELETE` 等 9 类 DML 词在任何字符串字面量中都被禁止 | `migration/tests/bare_sql_gate.rs:35, 40` |
| 门禁逐文件扫描（注释/属性忽略、普通与 raw 字符串字面量均识别，无法用引号绕过）：`migration_bare_sql_is_ddl_only`、`persistence_raw_sql_is_test_only_pragma`（persistence 例外仅测试作用域 PRAGMA） | `bare_sql_gate.rs:444, 455` |
| 表重建的数据复制全部改写为 SeaQuery `INSERT ... SELECT`（`select_from`）：16 处，分布于 8 个迁移文件（`m20260807_000001/000003/000005/000006/000007/000008_nvidia_families` 系列与 `m20260810_000001/000002`） | `migration/src/` 全目录清点（如 `m20260810_000001_center_data_sites.rs:102,150,209`） |

## 三、0.8.0 冻结产物清单

设计文档 §0.8.0「内容」逐项对照（`redfish-management-product-final-design.md:2745-2756`）：

| 冻结产物 | 冻结值 | 事实来源 |
|---|---|---|
| Cargo.lock | `nv-redfish 0.13.0`（checksum `038dbfb6...`） | `Cargo.lock:2478-2481` |
| Feature 面 | 显式 17 / 编译 58（0.13.0 全集 59 减 `default`） | `release_baseline.rs:79, 111` |
| Schema | `nv-redfish-schema/-core/-bmc-http/-csdl-compiler` 全部 `0.13.0` | `release_baseline.rs:280-285` |
| 模块 | 29（19 能力映射 / 8 基础设施 / 0 遗留 / 2 内部） | `release_baseline.rs:372` |
| 操作 | 43（映射 31 / CSDL 面 6 / 基础设施 2 / 内部 1 / OutOfScope 3） | `release_baseline.rs:677` |
| 能力账本 Hash | `84caf558...d24f`（见 §1.5） | `release_baseline.rs:1049-1052` |
| Center Protocol | v1（`CENTER_PROTOCOL_VERSION = 1`，由 `protocol_constants_are_pinned` 测试钉死） | `center-protocol/src/lib.rs:50`（测试 `lib.rs:383`） |
| 数据库 Schema | 21 个 migration（`m20260805_*` 11 + `m20260807_*` 8 + `m20260810_*` 2） | `migration/src/`（迁移测试 `migration/tests/initial_storage.rs`） |
| UI 导航 | 17 个视图（`ConsoleView::ALL: [ConsoleView; 17]`：Overview/Groups/Credentials/AddEndpoint/Import/Audit/Capabilities/Operations/Events/Artifacts/Telemetry/Diagnostics/Users/Sessions/CenterSites/CenterOperations/CenterBindings） | `ui/src/lib.rs:2771` |

## 四、0.8.0 期间新增能力盘点（简表）

| 面 | 新增内容 | 事实来源 |
|---|---|---|
| 命令家族（12 个全部落地） | 全部 12 个 `RedfishCommand` 家族有产品映射：account（5 操作）、单资源动作（system/manager/chassis reset 与 manager.reset-to-defaults、power-supply.reset 共 5）、log.clear、control.update、telemetry（7：enable + metric/report definition 生命周期）、event 订阅（2）、boot/secure-boot（CSDL 面 4）、update（patch/http-push/multipart 3 路径）、oem（NVIDIA 9 个类型化 action） | `release_baseline.rs:646-659`（`REDFISH_COMMAND_FAMILIES`）；`domain/src/redfish_command.rs:3069`（12 变体）；telemetry 家族落地 merge 8587f72 |
| OEM 读取 | 新增 AMI/HPE/LiteOn/Delta 4 个读取家族（6 个读取面：AMI `AmiServiceRoot` + `ConfigBmc`、HPE `HpeiLoServiceExt` + `HpeiLo`、LiteOn 电源、Delta 电源）；叠加既有 Dell/NVIDIA/Lenovo/Supermicro，14 个 OEM feature 全编译 | commit 1618577（`feat(infra-redfish): read the ami hpe liteon and delta oem families`）；`api/src/lib.rs` §0.5.0 OEM family member 面；`infra-redfish/src/lib.rs:55-70` |
| at-rest 加密 | 命令列 + 中心队列：`operations.command` / `batch_operations.command` / `center_outbox.payload_json` / `center_inbox.payload_json` 用 XChaCha20-Poly1305 信封（`RUTC1:` 前缀版本化，AD 绑定行身份，可区分加密行与历史明文行）保护 | `security/src/command_cipher.rs:1-43` |
| CI 门禁补全 | nextest（`--test-threads 4`）、llvm-cov（`--fail-under-lines 80`）、machete、deny、clippy `-D warnings`、wasm32 UI 产物 diff、Capability Ledger Check、Release Baseline Check | `.github/workflows/ci.yml:110-193` |
| 测试基建 | 故障注入与 Supermicro E2E 覆盖落地 | commit 4ad8c4a（`merge: land the fault-injection and supermicro e2e coverage`） |
| Overview 聚合 | §14.2 首页聚合区块落地：`GET /api/v1/overview` 服务端聚合（api 契约 + application `OverviewQuery` + web 路由），UI 首页仪表盘（Endpoint 计数/厂商分布/健康分布/运行中 Operation/最近事件/固件摘要/能力覆盖/数据陈旧程度），批量刷新与清单刷新后同步重载 | commit 4d1d27c（`feat(ui): render the §14.2 homepage overview dashboard`），链路 commit c3d7198 / e7f8dd4 / 70279c0 |

## 五、已知边界（冻结时如实记录）

| 边界 | 说明 | 事实来源 |
|---|---|---|
| OutOfScope 3 项 | `system.set-boot-order`（Boot 家族只提供 `BootSourceOverride` 一次性/连续覆盖，永不提供持久 boot-order 变更）；`update.simple`（SimpleUpdate 接受远程镜像 URI，§14.3 只上传制品字节、不接受用户 URI）；`update.start`（完整上传即应用路径已由 `RedfishCommand::Update(UpdateCommand::StartUpdate)` 覆盖，独立 StartUpdate 入口不提供）——均为显式产品决策，区别于"应该实现但尚未实现"的 Unmapped | `docs/known-limitations.md` §一 |
| probe-only 的 OEM 项 | `oem-nvidia-cper` / `oem-nvidia-fabrics`：能力状态在命名空间广告粒度判定（Nvidia 命名空间存在即 Supported）；CPER 记录与 fabric 数据子面"only distinguishable when the read slice actually reads the OEM resource"，当前读取面不呈现记录数据 | `infra-redfish/src/redfish_gateway.rs:12134-12140`；`domain/src/capability.rs:105-115` |
| UI 表单 later-milestone | telemetry 写表单明确 later milestone（`CommandFamilyView::ALL` 不含 Telemetry，表单选择器返回 `OperationFormError::FamilyRequired`，界面提示 "The telemetry write form is a later milestone."）；log/control 无专用表单；命令执行面本身已完整映射 | `ui/src/lib.rs:4749, 6010, 10860`；`docs/known-limitations.md` §二 |
| 依赖风险登记 | quick-xml 0.38.4 两个 advisory（RUSTSEC-2026-0194 / 0195）在 `deny.toml [advisories] ignore`，每条带 **TRIGGER** 注释：一旦上游 csdl-compiler 接受 quick-xml >= 0.41.0，必须删除该条目并升级 nv-redfish；产品侧风险评估为低（仅编译期处理可信 CSDL 输入，csdl-compiler 从不调用 `NsReader`） | `deny.toml:29-34` |

## 六、0.9.0 剩余工作清单

来源：设计文档 §0.9.0「内容」与「最低验证规模」（`redfish-management-product-final-design.md:2778-2810`）、
`docs/known-limitations.md` §五-§八、`docs/support-matrix.md` §三。

| 工作项 | 目标/说明 | 来源 |
|---|---|---|
| 进程级演练（评审跟踪项 #9/#15） | 0.8.0 已落地故障注入覆盖（§19.3）与单进程测试；跨进程演练（操作执行 §13 与中心协议 §15 路径）属 0.9.0 | 设计文档 §19.3、§0.9.0 内容；`docs/known-limitations.md` §五 |
| 真实设备认证矩阵 | 五厂商至少各一台真实设备进入 1.0.0 认证矩阵（§19.1 Physical Device Test）；当前结论基于上游类型面与 mock/fixture 验证，不是实测认证 | 设计文档 §19.1；`docs/known-limitations.md` §五 |
| 容量测试 | 最低验证规模：单 Site 200 Endpoint、单 Center 100 Site、中心汇总 5,000 Endpoint；测试后发布真实容量建议（当前为测试目标，不是已实测能力） | 设计文档 §0.9.0（2800-2810）；`docs/known-limitations.md` §六 |
| 发布构建验证 | musl（x86_64/aarch64）、Windows ARM64、macOS Universal 2 合并构建尚未在 CI 编译验证（CI 当前验证 linux-gnu / windows-msvc / darwin x86_64 + wasm32 UI 产物） | `docs/support-matrix.md` §三；`docs/known-limitations.md` §七 |
| 签名与 SBOM | Windows Authenticode 签名、macOS 签名和公证、Linux 独立签名、SBOM 生成（§5.4 发布配置） | 设计文档 §0.9.0（2792-2793）、§1.0.0（2847） |
| tracing 深化 | app 诊断日志已引入（§6.2：`tracing` + `tracing-subscriber`，`RUST_LOG` 过滤的 stderr subscriber，见 `docs/operations-manual.md` §8.1）；span/`#[instrument]`、结构化输出、其余诊断点的进一步接入为后续迭代 | `docs/known-limitations.md` §七、§八 |
| 真实响应 fixture 目录 | §19.1 要求 Dell/HPE/Lenovo/xFusion/Inspur 各固件版本的脱敏真实响应 fixture 并随上游升级回归；当前代码库尚无 fixture 目录 | `docs/known-limitations.md` §五 |
| 其他 | `cargo audit` 独立门禁、诊断解码错误路径展示（§12.4）、产品版本号统一策略、UI 本地化等 | `docs/known-limitations.md` §七、§八 |
