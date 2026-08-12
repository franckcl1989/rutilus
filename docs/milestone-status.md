# Rutilus 里程碑状态（0.8.0 能力冻结 + 0.9.0 进展）

> 本文档记录 0.8.0「1.0 能力冻结」里程碑的达成状态与证据链，并逐项盘点 0.9.0「生产候选」
> 进展，供 0.9.0/1.0.0 评审使用。
> §一-§五（0.8.0 冻结事实）基于冻结时 master（commit 4ad8c4a）；§六（0.9.0 剩余工作清单）
> 与 §七（0.9.0 进展盘点）基于 master d77d54e（本轮 HEAD，迭代三+四已合入：E1 §12.4 生产
> 捕获点 ce2b8b3、E3a Git Commit 嵌入 99d5670、E3b Secret 扫描门禁 eefde7e、E3c N5 处置
> 8a9ab82/34315c8、E4 约束修复 76af80f + bfb001e；迭代五已合入：H1 UI 本地化基础层 8e8ac6f、
> H2 web/assets UI 产物再生成 53b6402；迭代六（H4/H5）已合入：H5 UI 本地化完整落地 d3f7769
> （827 键 En/Zh 双语目录 + 运行时语言选择器 + URL fragment 持久化）与产物再生成 0f91c17、
> H4 发布管道代码侧 34503ea（scripts/ 5 脚本）+ d77d54e（ci.yml release-artifacts job，证书
> 到位即启用））。所有条目均基于真实代码/测试事实，标注
> 来源文件与测试名；不写设计文档没有且代码不支持的内容。设计基线见仓库根目录
> `redfish-management-product-final-design.md`（修订冻结版）。全文「file:line」引用已逐一核对
> 当前 master 实际行号（2026-08-12 复核）：§一-§五 的事实锚定冻结时 commit 4ad8c4a，行号
> 一律以当前 master 为准。

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
| CI 门禁补全 | nextest（`--test-threads 4`）、llvm-cov（`--fail-under-lines 80`）、machete、deny、clippy `-D warnings`、wasm32 UI 产物 diff、Capability Ledger Check、Release Baseline Check | `.github/workflows/ci.yml:99-235`（§19.4 门禁步骤：clippy `:106-107`、nextest `:148-150`、llvm-cov `:159-163`、deny `:172-176`、machete `:202-204`、wasm32 产物 diff `:225-235`）与 `:297-320`（Capability Ledger Check `:306-308`、Release Baseline Check `:318-320`） |
| 测试基建 | 故障注入与 Supermicro E2E 覆盖落地 | commit 4ad8c4a（`merge: land the fault-injection and supermicro e2e coverage`） |
| Overview 聚合 | §14.2 首页聚合区块落地：`GET /api/v1/overview` 服务端聚合（api 契约 + application `OverviewQuery` + web 路由），UI 首页仪表盘（Endpoint 计数/厂商分布/健康分布/运行中 Operation/最近事件/固件摘要/能力覆盖/数据陈旧程度），批量刷新与清单刷新后同步重载 | commit 4d1d27c（`feat(ui): render the §14.2 homepage overview dashboard`），链路 commit c3d7198 / e7f8dd4 / 70279c0 |

## 五、已知边界（冻结时如实记录）

| 边界 | 说明 | 事实来源 |
|---|---|---|
| OutOfScope 3 项 | `system.set-boot-order`（Boot 家族只提供 `BootSourceOverride` 一次性/连续覆盖，永不提供持久 boot-order 变更）；`update.simple`（SimpleUpdate 接受远程镜像 URI，§14.3 只上传制品字节、不接受用户 URI）；`update.start`（完整上传即应用路径已由 `RedfishCommand::Update(UpdateCommand::StartUpdate)` 覆盖，独立 StartUpdate 入口不提供）——均为显式产品决策，区别于"应该实现但尚未实现"的 Unmapped | `docs/known-limitations.md` §一 |
| probe-only 的 OEM 项 | `oem-nvidia-cper` / `oem-nvidia-fabrics`：能力状态在命名空间广告粒度判定（Nvidia 命名空间存在即 Supported）；CPER 记录与 fabric 数据子面"only distinguishable when the read slice actually reads the OEM resource"，当前读取面不呈现记录数据 | `infra-redfish/src/redfish_gateway.rs:13311-13317`（`OemNamespaceProbe` 文档，`domain/src/capability.rs:105-115`） |
| UI 表单 later-milestone | telemetry 写表单明确 later milestone（`CommandFamilyView::ALL` 不含 Telemetry，表单选择器返回 `OperationFormError::FamilyRequired`，界面提示 "The telemetry write form is a later milestone."）；log/control 无专用表单；命令执行面本身已完整映射 | `ui/src/lib.rs:5170, 6289, 6361, 6437`（`CommandFamilyView::ALL` 9 家族 `:5170`、Telemetry 拒绝 `:6289, 6361, 6437`、提示文案串 `i18n.rs:1654` `hint_telemetry_later`）；`docs/known-limitations.md` §二 |
| 依赖风险登记 | quick-xml 0.38.4 两个 advisory（RUSTSEC-2026-0194 / 0195）在 `deny.toml [advisories] ignore`，每条带 **TRIGGER** 注释：一旦上游 csdl-compiler 接受 quick-xml >= 0.41.0，必须删除该条目并升级 nv-redfish；产品侧风险评估为低（仅编译期处理可信 CSDL 输入，csdl-compiler 从不调用 `NsReader`） | `deny.toml:29-34` |

## 六、0.9.0 剩余工作清单

来源：设计文档 §0.9.0「内容」与「最低验证规模」（`redfish-management-product-final-design.md:2778-2810`）、
`docs/known-limitations.md` §五-§八、`docs/support-matrix.md` §三。

| 工作项 | 目标/说明 | 来源 |
|---|---|---|
| 进程级演练（评审跟踪项 #9/#15） | 0.8.0 已落地故障注入覆盖（§19.3）与单进程测试；跨进程演练（操作执行 §13 与中心协议 §15 路径）属 0.9.0 | 设计文档 §19.3、§0.9.0 内容；`docs/known-limitations.md` §五 |
| 真实设备认证矩阵 | 五厂商至少各一台真实设备进入 1.0.0 认证矩阵（§19.1 Physical Device Test）；当前结论基于上游类型面与 mock/fixture 验证，不是实测认证 | 设计文档 §19.1；`docs/known-limitations.md` §五 |
| 容量测试 | 🟡 部分：合成规模压力/容量套件已落地（`persistence/tests/stress_capacity.rs` 3 个测试，覆盖设计最低验证规模：200 Endpoint Generation 一致刷新 / 100 Site outbox-inbox-cursor / 5,000 Endpoint 中心投影幂等重投，全部断言正确性不变量）；本机实测数据已记录（2026-08-12，debug 构建、WAL、Windows 开发机）；**发布真实容量建议**（设计要求的"测试后发布"）仍待办 | 设计文档 §0.9.0（2800-2810）；`stress_capacity.rs:47-52`；`docs/operations-manual.md` §九 |
| 发布构建验证 | 🟡 部分：aarch64 musl（cargo-zigbuild 交叉链接）与 macOS Universal 2（arm64 原生 + x86_64 交叉 + lipo 合并）构建步骤已入 CI（`.github/workflows/ci.yml:265-270, 288-304`）；Windows ARM64 **明确不入 CI**（hosted x64 Windows runner 无法提供 ARM64 MSVC 链接器与 SDK 导入库，真实原因注释于 `ci.yml:271-278`） | `docs/support-matrix.md` §三；`ci.yml` |
| 签名与 SBOM | Windows Authenticode 签名、macOS 签名和公证、Linux 独立签名、SBOM 生成（§5.4 发布配置） | 设计文档 §0.9.0（2792-2793）、§1.0.0（2847） |
| tracing 深化 | ✅ 已落地：`#[instrument]` span 接入 main/backup/center_client/center_runtime/event_listener/scheduler/site_runtime/standalone_runtime/telemetry_sampler（口令等敏感值 `skip_all`）；`--log-format <text|json>` 全局选项与 `init_tracing` 双格式层（默认 text，stderr + `RUST_LOG` 过滤不变） | `app/src/main.rs:27-41, 255-273`；`docs/operations-manual.md` §8.1 |
| 真实响应 fixture 目录 | §19.1 要求 Dell/HPE/Lenovo/xFusion/Inspur 各固件版本的脱敏真实响应 fixture 并随上游升级回归；当前代码库尚无 fixture 目录 | `docs/known-limitations.md` §五 |
| 其他 | UI 本地化（✅ 已完整落地：827 键 En/Zh 双语 + 运行时语言选择器 + URL fragment 持久化，见 §7.2-A「UI 本地化」行）；诊断解码错误路径展示（§12.4）与产品版本号统一策略已从本行移出（记录层已完成、捕获点待做与策略落地分别见 §7.1/§7.2-A） | `docs/known-limitations.md` §七、§八 |

## 七、0.9.0 进展盘点（2026-08-12，master d77d54e）

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
> application 293 / infra 291 / web 全过 / rutilus 141 / security 门禁 7 全过、
> `center_sync.rs` 33 测试全过、clippy 全 crate 零警告、fmt 干净，2026-08-12；迁移总数现为
> 23）。§六「其他」与 §7.1/§7.2-A 相关行已按新事实同步修订；
> `docs/known-limitations.md` §七「产品版本号」行与 §八 §12.4 行已同步更新（以 known-limitations 为准）。
> 迭代六（master d77d54e，本轮）落地：**UI 本地化完整落地**（H5 d3f7769：`strings_catalog!` 目录
> 扩至 827 键 En/Zh 双语、`Lang::{En, Zh}` 运行时语言选择、lib.rs `LanguageSelector` 组件与
> URL fragment 持久化（`#lang=`）；0f91c17 web/assets 产物再生成，§7.2-A「UI 本地化」行已转 ✅，
> ui 测试 127→136）与**发布管道代码侧**（H4 34503ea + d77d54e：`scripts/` 5 脚本 + ci.yml
> `release-artifacts` job，证书到位即启用，§7.2-A 新增「发布管道（代码侧）」行）；
> §7.1「签名构建」「SBOM」两行按新事实同步修订为 🟡 代码侧完成；
> `docs/known-limitations.md` §七「UI 本地化」「发布管道」行与 `docs/release-readiness.md`
> 条件 17 已同步更新（以 release-readiness 为准）。

### 7.1 逐项盘点

| 0.9.0 内容 | 状态 | 证据 |
|---|---|---|
| 五厂商实验室 | ⏳ 待做（依赖物理设备） | Mock 层已覆盖五厂商 profile（Dell/HPE/Lenovo/xFusion/Inspur，外加 NVIDIA/AMI/LiteOn/Delta/Supermicro，共 11 个 `MockProfile`，`test-support/src/mock_bmc/profile.rs:47-134`）；§19.1 Physical Device Test「五厂商至少各一台真实设备进入 1.0.0 认证矩阵」未达成（`docs/known-limitations.md` §五） |
| 所有 Fixture 回归 | 🟡 部分 | 合成 fixture（Mock BMC 固定资源树 + 确定性证书）回归已有：`test-support/tests/gateway_mock_bmc.rs` 23 个测试（Service Root 读取/47 能力探测/核心资源读取/会话生命周期/各厂商 profile）、`test-support/src/mock_bmc/tests.rs` 21 个；§19.1 Fixture Test 要求的**脱敏真实响应 fixture 目录**（五厂商各固件版本，随 nv-redfish 升级回归）尚无（`known-limitations.md` §五） |
| 故障注入 | 🟡 部分 | §19.3 多数场景已有单进程自动化覆盖：BMC 慢响应（`redfish_gateway.rs:24192, 25091`、`tls_probe.rs:568`）、TLS 证书变化（`domain/src/endpoint.rs:327` `verify_identity`/`TlsIdentityChanged`）、JSON 字段类型错误（`redfish_gateway.rs:19215, 19466` undecodable 成员跳过）、Action 响应丢失/写连接丢弃（`redfish_gateway.rs:28766, 28807`）、Task 消失（`redfish_gateway.rs:23109`）、SSE 流中断/解码失败（`redfish_gateway.rs:32605, 32674`）、重复消息/重复 Operation（`center_sync.rs:3478, 3528`、`operation_engine.rs:1332` 批量重投 no-op、`event_repository.rs:328` 事件去重）、大文件上传中断（`web/tests/artifact_path.rs:735`）、系统时间变化（`application/src/telemetry_sampler.rs:1050, 1076`、`operation_engine.rs:986` 时钟回拨如实记录）、文件写失败（`artifact_store.rs:1476`）；**未覆盖**：产品进程在任务中终止、BMC 更新中重启、SQLite 写入中断、磁盘空间不足（跨进程演练形态，见 7.2-B） |
| 跨平台 E2E | ✅ 已完成 | windows/macos 任务新增跨平台 E2E 套件步骤（`ci.yml:130-146`）：`cargo test --locked -p rutilus-web`（`web/tests/` 9 个路径套件，均为无 socket/子进程/定时器的内存假件）+ `cargo test --locked -p rutilus --test version`；`app/tests/mock_center_client.rs`（回环 mTLS/WebSocket 中心互操作）因真实 socket 与握手/协商时序**故意不纳入**非默认任务（`ci.yml:129-133` 注释）——三平台 E2E 运行达成 |
| 数据库压力 | ✅ 已完成 | 压力/容量测试套件落地：`persistence/tests/stress_capacity.rs` 3 个测试（`two_hundred_endpoints_round_trip_with_generation_consistent_refreshes` :336、`one_hundred_sites_advance_outbox_inbox_and_sync_cursors` :585、`five_thousand_endpoint_projections_round_trip_at_the_center` :832），规模常量对齐设计最低验证规模（200/100/5,000，`:47-52`）；本机复跑 3 测试全过（2026-08-12，debug 构建、WAL） |
| 中心重连风暴 | ✅ 已完成 | 4 个**多连接并发**重连风暴测试（`center_sync.rs:4328` a_concurrent_reconnect_storm_resumes_every_outbox_from_its_last_ack、`:4448` a_reconnect_duplicate_burst_is_idempotent_and_effects_each_operation_once、`:4838` heartbeats_and_reconnects_interleave_without_interference、`:4968` the_local_queue_keeps_accumulating_while_disconnected_and_drains_in_order_on_reconnect）+ 1 个重连进度重发测试（`:4615` reconnect_resends_progress_for_active_operations_and_skips_completed_ones，NOTE 收尾 commit 283e583）；与既有 28 个单连接语义测试合计 33 个全过（本机复跑 2026-08-12） |
| 大文件更新 | 🟡 部分 | 分块上传机制全链路覆盖：4 MiB chunk 上限（`application/src/artifact_store.rs:64` `ARTIFACT_CHUNK_BASE64_MAX_BYTES`）、断点续传（`artifact_store.rs:1364`、`web/tests/artifact_path.rs:735`）、digest 校验（`artifact_path.rs:939`）、multipart 更新（`redfish_gateway.rs:32073, 32112` `verifies_update_*` 系列、`:31689` 断连 multipart 上传）、中心 manifest+chunk 分发（`center_sync.rs:3693`、`application/src/center/projection.rs:1729`）、8 MiB 帧上限（`center-protocol/src/framing.rs:18-31`）；真实大固件文件的端到端更新演练未做 |
| Secret 泄漏检查 | ✅ 结构性（含独立扫描门禁） | 结构性防护已有：API 永不回声秘密（`web/tests/write_path.rs:784, 816, 918`、`web/src/lib.rs:6225` `exposes_secret_free_complete_endpoint_inventory`、`persistence/src/credential_repository.rs:604`）、审计类型**构造上**不能携带秘密（`domain/src/audit.rs:318, 383`：非秘密身份数据/封闭类型参数摘要）、Center 投影排除凭据与会话（`application/src/center/projection.rs:55`）、命令载荷 at-rest 加密（`security/src/command_cipher.rs`）；**独立扫描门禁已落地（E3b）**：`security/tests/secret_leak_gate.rs` 3 规则（R1 硬编码秘密 / R2 内嵌私钥 PEM / R3 明文输出宏泄露）、7 测试、白名单 2 处（`ALLOWED_CONSTANT_HITS`，path+line+name+literal 绑定），作为 **CI 独立步骤**（`ci.yml:224-226` Secret leak gate：`cargo test --locked -p rutilus-security --test secret_leak_gate`，`if: matrix.is_default`）；运行时抓包/日志复核未做（7.2-A/B） |
| 权限测试 | ✅ 已完成 | `role_masks_are_enforced_on_guarded_routes`（`web/src/lib.rs:10856`）、中心角色站点作用域（`web/src/lib.rs:11729, 11773`）、登录限速预算（`web/src/auth.rs:2581` rate_limiter_enforces_per_username_and_per_ip_budgets）、BMC 写权限拒绝（`redfish_gateway.rs:28696`） |
| 安全审查 | 🟡 已启动 | 启动交付物 `docs/security-review.md`（8 个审查范围 + §7.7 扫描全完成，无 BLOCKER）；MINOR-1（登录时间侧信道）已于迭代二修复（commit 72eccb5：未知用户名路径哑 Argon2id 验证，`web/src/auth.rs:1242-1253, 1305`）；N5 已于迭代三关闭（E3c 编译期 const assert，`web/src/lib.rs:1223`）；独立泄漏扫描门禁已落地（E3b），外部评估仍待做（见 7.2-A「安全审查（启动）」行） |
| Migration 回归 | ✅ 已完成 | `migration/tests/` 20 个测试文件（initial_storage/operations/batch_operations/telemetry/events/groups_tags/center_tables/center_data_sites/center_role_sites/product_users/remote_tasks/artifacts/operation_failure_kinds/nvidia_families/nvidia_power_families/lenovo_families/bare_sql_gate/audit_action_shapes/audit_execute_operation/resource_feature_lists）；迁移总数 23（21 基线 + `m20260812_000001` + `m20260812_000002`）；迁移前自动备份（`persistence/src/lib.rs:510` backs_up_a_closed_database_before_applying_pending_migrations）；CI 独立 Migration Test 门禁（`ci.yml:306-310`） |
| 备份恢复演练 | 🟡 部分 | 自动化往返覆盖完整：`app/src/backup.rs:765`（往返保数据）、`:799`（拒绝他实例包）、`:825`（跨机恢复需源信封）、`:912`（源口令对全新信封）、`:944`（需停止实例）、`:981`（拒绝不同产品版本）、`:970`（拒绝未初始化目录）；CLI `rutilus backup`/`restore`（`app/src/main.rs:97, 144`）；备份快照计数钉死（`persistence/src/backup_snapshot.rs:624-627`：backup_applied 24 / supported 23）；0.9.0 验收「三平台安装、升级、备份、恢复通过」的演练未执行 |
| 签名构建 | 🟡 代码侧完成（证书未到位） | `scripts/` 签名脚本 3 份（sign-windows.ps1 / sign-macos.sh / sign-linux.sh）+ ci.yml `release-artifacts` job 的签名步骤已合入（commit 34503ea + d77d54e；步骤仅在对应 secret 配置时执行，未配置则 "signing skipped: certificate not configured"，`ci.yml:340-343, 468-546`）；Windows Authenticode、macOS 签名与公证、Linux minisign 独立签名在证书到位前保持跳过；首次实跑未做（6 项首跑确认点见 `release-readiness.md` 条件 17） | §5.4 发布配置；`release-readiness.md` 条件 17 |
| SBOM | 🟡 代码侧完成（首跑未做） | cargo-cyclonedx@0.5.9 钉版 + 每 crate BOM 收集步骤已入 `release-artifacts` job（`ci.yml:571-587`，commit d77d54e）；首次实跑生成并随包发布未做（证书到位后随发布演练） | §5.4 发布配置；`release-readiness.md` 条件 17 |
| 用户手册 | ✅ 已完成 | `docs/user-manual.md`（431 行，条目后标注来源文件；`rutilus version` 输出已更新为三行，含 Git Commit） |
| 运维手册 | ✅ 已完成 | `docs/operations-manual.md`（数据目录/主密钥/服务/备份恢复/升级/诊断/容量现状；§8.1 已补充 `--log-format json` 结构化输出与 span 上下文，§九已补充合成规模实测容量数据） |
| 支持矩阵 | ✅ 已完成 | `docs/support-matrix.md`（189 行：上游基线/平台矩阵/厂商支持现状/不承诺项）；§三「CI 现状」已更新（windows/macos E2E 套件、aarch64 musl、macOS Universal 2 入 CI，Windows ARM64 未入 CI 的真实原因，`support-matrix.md:90-95`） |
| 已知限制 | ✅ 已完成 | `docs/known-limitations.md`（OutOfScope 3 项/依赖风险登记/测试基建局限/容量现状等）；§八「§0.9.0 性能容量测试与真实容量建议」行已同步为部分落地（`known-limitations.md:120`：合成规模套件已实测、正式容量建议待发布）；§八「§12.4 诊断中的解码错误路径 / ExtendedInfo 展示」行已同步为**已实现**（`known-limitations.md:123`：E1 生产捕获点已合入，如实注记 odata_type 捕获时为 None 等）；§六标题已同步修订为「发布级容量建议未发布（合成规模已实测）」（2026-08-12，与 §八、operations-manual §九 一致） |
| 性能容量测试 | 🟡 部分 | 压力/容量套件已落地（`persistence/tests/stress_capacity.rs`，规模达设计最低验证规模）并有本机实测数据（2026-08-12，debug 构建、WAL、Windows 开发机）：5,000 投影写入 5.78s（≈865 行/s）、幂等重投 9.72s、5,000 行清单查询 0.482s；关键观察：写路径被 `write_gate`（`Semaphore(1)`，`persistence/src/lib.rs:101, 240`）全局串行化，5,000 规模耗时 ≈ 事务数 × 单事务成本——这是发布真实容量建议时最有价值的记录；**最终发布容量建议**未发布（`operations-manual.md` §九） |

### 7.2 剩余工作精确分类

**A. 代码/CI 可做（不依赖外部资源，可直接进入迭代）**

迭代三+四（master bfb001e）已落地并从下表移出（详见 §7.1 与 §六）：数据库压力测试套件（`stress_capacity.rs`）、
中心重连风暴测试（`center_sync.rs` 并发测试）、跨平台 E2E 运行（`ci.yml:130-146`）、
`cargo audit` 独立门禁（`ci.yml:196-204`）、tracing 深化（`app/src/main.rs:255-273`）。
迭代二（master edead80）落地：产品版本号统一策略（✅，下表该行已标证据）、安全审查
M1 修复（✅，下表「安全审查（启动）」行）；§12.4 诊断记录层部分落地（记录层完成、
生产捕获点待做，下表该行标 🟡）。迭代三+四（master bfb001e）落地：**§12.4 生产捕获点**
（E1，下表该行已转 ✅）、**Git Commit 嵌入**（E3a，并入「产品版本号统一策略」行）、
**Secret 泄漏扫描门禁**（E3b，并入「安全审查（启动）」行）、**N5 处置**（E3c）、**约束
修复**（E4）——详见下表各行的 ✅ 证据。迭代五（master 53b6402，本轮）落地：**UI 本地化
基础层**（H1 8e8ac6f + H2 53b6402，下表「UI 本地化」行已转 🟡，后续项登记于该行）。
迭代六（master d77d54e，本轮）落地：**UI 本地化完整落地**（H5 d3f7769 + 0f91c17，
下表「UI 本地化」行已转 ✅）与**发布管道代码侧**（H4 34503ea + d77d54e，下表新增
「发布管道（代码侧）」行，证书到位即启用）。

| 工作项 | 说明 | 证据/来源 |
|---|---|---|
| §12.4 诊断解码错误路径 / ExtendedInfo 展示 | ✅ 已实现（E1，commit ce2b8b3）：记录层——`ResourceExtendedInfo`/`ResourceDecodeFailure`（`resource_diagnostics.rs:36, 249`）、api 契约 9 字段（`api/src/lib.rs:1894-1905`）、web 投影（`web/src/lib.rs:3961-3991`）、ui 只读区块（`ui/src/lib.rs:15492`）、端到端测试（`web/tests/diagnostics_path.rs` 7 个测试，含 E1 新增 `:998` `refresh_capture_flows_into_the_diagnostics_response`）；**生产捕获点已实现**——gateway 捕获（`redfish_gateway.rs:8720` `DecodeFailureObservation`、`:8904/:8931/:8977` 捕获函数）、同代事务提交（`persistence/src/resource_snapshot_repository.rs:81-147`）、生产链路直连（`application/src/endpoint_refresh.rs:350-355`）、新表 + entity + 迁移（`migration/src/m20260812_000001`，E4 由 `m20260812_000002` 重建约束为领域枚举 47 码）；如实注记：捕获时 `odata_type` 为 `None`（`redfish_gateway.rs:8915-8922` `capture_fetch_failure` 恒传 None，解码失败记录不带类型） | `known-limitations.md` §八 |
| 产品版本号统一策略 + Git Commit 嵌入 | ✅ 已落地（commit 2de4351 + E3a 99d5670）：workspace 版本 = `0.9.0`（生产候选，与里程碑对齐），单一来源 = 根 `Cargo.toml` `[workspace.package] version`（`Cargo.toml:14`）；`rutilus version` 输出**三行**（`app/src/main.rs:733-737`）：产品版本 / `nv-redfish` 基线 / `git commit`（CI 注入 `RUTILUS_GIT_COMMIT`，`ci.yml:53-64`；`GIT_COMMIT` 常量 `main.rs:38-40`；本地无变量降级 `dev`）；`app/tests/version.rs:8-11, 27-36` 与 `app/tests/log_format.rs:7-10, 23-28` 派生断言（三行）；升级只改一处 | 根 `Cargo.toml:6-14`；`app/tests/version.rs`；`app/tests/log_format.rs` |
| UI 本地化 | ✅ 已完整落地（H5，commit d3f7769 + 0f91c17）：`strings_catalog!` 目录扩至 **827 键 En/Zh 双语**（宏 `i18n.rs:43-160`，目录体 `i18n.rs:163-1858`；单一来源：字段声明 + En/Zh 构造器 + 完整性测试表）；`Lang::{En, Zh}` 与 `Lang::strings`（`i18n.rs:1860-1881`）、`thread_local!` 运行时语言选择（`i18n.rs:1909-1928`，测试线程各持己态）、`L()` 按当前语言解析 `'static` 目录（`i18n.rs:1938-1944`）、`format_catalog` 运行时槽位填充（`i18n.rs:1955-1977`）；lib.rs `LanguageSelector` 组件（`lib.rs:11640-11659`）+ **URL fragment 持久化**（`#lang=` 前缀 `lib.rs:11603`；`stored_lang_code`/`persist_language`/`apply_language` `lib.rs:11605-11636`——fragment 是当前 web-sys feature 面唯一可用的浏览器存储，切换经 reload 全量重挂载；启动恢复 `start()` `lib.rs:11661-11665`）；深度翻译完成（facts/健康词汇/`OEM_UNSUPPORTED_NOTICE` 等均入目录，`i18n.rs:825-829, 867`）；i18n 11 个测试（完整性/占位符/双语同键/切换/格式化，`i18n.rs:1980-2172`），ui **136 测试全过**、clippy/fmt 干净；J2 审计 3 处 zh 译法微修已合入（`type_nvidia_profile_file`/`fact_power_load_percent`/`fact_metric_values`，`i18n.rs:444, 597, 733`）。**后续触点**：localStorage 持久化（需扩展 web-sys feature）与更多语言 | `ui/src/i18n.rs`；`ui/src/lib.rs:11599-11665`；`web/assets/`；`known-limitations.md` §七 |
| 发布管道（签名 + SBOM + 校验清单，代码侧） | ✅ 代码侧完成（H4，commit 34503ea + d77d54e，证书到位即启用）：`scripts/` 5 脚本（sign-windows.ps1 / sign-macos.sh / sign-linux.sh / checksums.sh / checksums.ps1）；ci.yml `release-artifacts` job（`ci.yml:332-611`）——`v*` tag push 与 `workflow_dispatch` 触发（`ci.yml:28-40`）、`needs: ci` 门禁先行（`ci.yml:367`）、签名步骤仅在 secret 配置时执行（`ci.yml:340-343`）、base64 物化（`ci.yml:468-478, 493-502, 526-533`）、Windows thumbprint-only 模式（`ci.yml:480-488`）、cargo-cyclonedx@0.5.9 钉版 SBOM（`ci.yml:571-587`）、SHA-256 清单（`ci.yml:592-594`）、artifact 上传（`ci.yml:596-611`）；H4 审计处置已内嵌（musl-tools 补齐 `ci.yml:423`、单行 if 判定 `ci.yml:548-558` 等）；**首跑确认点 6 项**（证书到位后核验：musl-tools 安装 / cargo-cyclonedx@0.5.9 钉版 / base64 物化 / env `&&`·`||` 表达式 / thumbprint-only 模式 / 上传权限，详见 `release-readiness.md` 条件 17） | `scripts/`；`.github/workflows/ci.yml`；`release-readiness.md` 条件 17 |
| 安全审查（启动） | ✅ 已交付：`docs/security-review.md`（8 个审查范围 + §7.7 扫描全完成，无 BLOCKER）；**M1 已修复**（MINOR-1 登录时间侧信道，commit 72eccb5：`web/src/auth.rs:1242-1253` 哑 Argon2id 验证 + `:1305` 未知用户名分支调用），验证方式 = 调用计数对称断言而非墙钟计时（`web/src/lib.rs:9316` 计数、`:10666` 与 `:10730` 两分支各 1 次/失败、限速拒绝 0 次）；**N5 已关闭**（E3c：`web/src/lib.rs:1223` 编译期 const assert 钉死常量正性）；**独立 Secret 泄漏扫描门禁已落地**（E3b：`security/tests/secret_leak_gate.rs` 3 规则、7 测试；CI 独立步骤 `ci.yml:224-226` Secret leak gate）；剩余：运行时抓包/日志复核与外部评估（1.0.0 发布评审建议项） | `docs/security-review.md`；设计文档 §0.9.0 |
| 约束修复（E4） | ✅ 已落地（commit 76af80f + bfb001e）：`migration/src/m20260812_000002_resource_feature_lists.rs` 重建 `resources`/`resource_decode_failures` 两表，`ck_resources_feature`/`ck_resource_decode_failures_feature` 允许域 = 领域枚举全部 47 码（此前 resources 37 / resource_decode_failures 36 且互相不一致）；`down` 对称恢复 37/36；防回归机械测试 `migration/tests/resource_feature_lists.rs`（`:248` 单测试，域码与约束逐字符双向钉死，不触库）；备份快照计数钉死 `persistence/src/backup_snapshot.rs:624-627`（backup_applied 24 / supported 23） | `migration/src/m20260812_000002`；`migration/tests/resource_feature_lists.rs` |
| 发布构建矩阵补齐（剩余部分） | aarch64 musl（cargo-zigbuild）与 macOS Universal 2（lipo）已入 CI（`ci.yml:265-270, 288-304`）；Windows ARM64 明确不入 CI——hosted x64 Windows runner 无法提供 ARM64 MSVC 链接器与 SDK 导入库（`ci.yml:271-278` 注释），需原生 ARM64 Windows runner 或本地验证后另行处理 | `ci.yml` |

**B. 依赖演练环境（物理设备 / 规模环境 / 三平台流程）**

| 工作项 | 说明 | 来源 |
|---|---|---|
| 五厂商实验室 | Dell/HPE/Lenovo/xFusion/Inspur 各至少一台真实设备进入 1.0.0 认证矩阵 | 设计文档 §19.1 |
| 真实响应 fixture 目录 | 五厂商各固件版本脱敏真实响应 + 随 nv-redfish 升级回归（fixture 抓取依赖设备） | 设计文档 §19.1 Fixture Test |
| 进程级故障注入演练 | 产品进程在任务中被终止、BMC 更新中重启、SQLite 写入中断、磁盘空间不足（§19.3 剩余项） | 设计文档 §19.3 |
| 大文件更新演练 | 真实大固件文件的端到端更新（当前为分块机制级覆盖） | 设计文档 §0.9.0 |
| 备份恢复演练 | 三平台安装/升级/备份/恢复（0.9.0 验收） | 设计文档 §0.9.0 验收 |
| 性能容量测试 | 合成规模压力套件已落地并实测（`stress_capacity.rs`，2026-08-12）；**发布真实容量建议**（含 release 构建/正式环境复核）仍待办 | 设计文档 §0.9.0（2800-2810）；`operations-manual.md` §九 |
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
