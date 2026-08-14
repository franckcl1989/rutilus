# Rutilus 用户手册

> 本文档面向运维人员，描述 Rutilus 产品的日常使用。
> 产品定义以仓库根目录 `redfish-management-product-final-design.md`（修订冻结版）为准；
> 本文档描述的界面、命令和行为均基于当前 master 的实际代码实现，并在条目后标注事实来源文件。
> 当前产品版本号为 `0.9.0`（生产候选，workspace 版本，`rutilus version` 输出；根 `Cargo.toml`），
> 版本号单一来源 = 根 `Cargo.toml` `[workspace.package] version`（`Cargo.toml:14`）：产品版本与里程碑
> 对齐、随里程碑升级（设计文档 0.1.0→1.0.0 为产品发布阶段编号），一次升级只改这一处；`rutilus version`
> 输出三行（产品版本 / `nv-redfish` 开发基线 / 构建 Git Commit）与版本/日志格式测试断言均由
> `CARGO_PKG_VERSION`、基线常量与编译期 `RUTILUS_GIT_COMMIT` 派生（`app/tests/version.rs`、`app/tests/log_format.rs`）。

## 一、产品概述

Rutilus 是一个由 Rust 实现、通过浏览器 GUI 使用、基于 `nv-redfish` 的多服务器管理卡统一管理产品。
它解决的核心问题是：运维人员不再需要分别打开 iDRAC / iLO / XCC / iBMC 等不同界面逐台操作，
而是打开一个统一管理界面，接入多台不同厂商 BMC，在同一产品形态中查看和执行各 BMC 实际支持的能力。

产品形态（`redfish-management-product-final-design.md` §1、§5）：

- **单二进制**：每个目标平台和架构交付一个自包含可执行文件，内嵌 Web GUI（Leptos WASM，`rust-embed` 编译进二进制）、Web 后端、SQLite 数据库和 Migration、全部 `nv-redfish` 标准与 OEM 能力；
- **浏览器 GUI**：所有日常操作在浏览器中完成；CLI 只提供初始化、运行、服务、备份、诊断等有限子命令（§18.1）；
- **三种运行姿态**：Standalone（单机）、Site（站点）、Center（中心），同一个二进制内切换（§4）。

能力边界（§2）：服务器管理卡功能以 `nv-redfish` 0.13.0 基线为绝对边界——
上游公开什么，产品完整映射什么；上游没有的，产品不通过私有 HTTP、OEM Adapter、脚本或网页抓包自行补齐。

### 1.1 当前版本事实

| 项目 | 值 | 来源 |
|---|---|---|
| 产品 crate 版本 | `0.9.0`（生产候选，与里程碑对齐、随里程碑升级；单一版本来源） | 根 `Cargo.toml` `[workspace.package] version`（`Cargo.toml:14`） |
| `nv-redfish` 开发/发布基线 | `0.13.0`（2026-08-04 发布） | `infra-redfish/src/lib.rs`、`infra-redfish/src/release_baseline.rs` |
| 已知更新正式版本 | `0.14.2`（2026-08-10 发布，未 yank），升级决策留待冻结评审 | `infra-redfish/src/release_baseline.rs` |
| 能力账本规模 | 47 条（33 标准 + 14 OEM） | `domain/src/capability.rs` |
| 构建 Git Commit 嵌入 | CI 构建注入 `RUTILUS_GIT_COMMIT`（`github.sha`），本地构建降级 `dev`；`rutilus version` 第三行输出 | `ci.yml:84`；`app/src/main.rs:38-40` |
| CLI 名称 | `rutilus` | `app/src/main.rs` |

运行 `rutilus version` 可打印产品版本、`nv-redfish` 开发基线与构建 Git Commit（三行，
`app/src/main.rs:733-737`）：

```text
rutilus 0.9.0
nv-redfish development baseline 0.13.0
git commit dev
```

第三行 `git commit`：CI 构建由 job 级 `RUTILUS_GIT_COMMIT` 环境变量注入构建时的
`github.sha`（`ci.yml:84`），二进制经 `GIT_COMMIT` 常量嵌入（`app/src/main.rs:38-40`）；
本地构建未设置该变量时降级输出 `dev`（不调用 git 子进程）。版本/日志格式测试断言与二进制
同源派生（`app/tests/version.rs:27-36`、`app/tests/log_format.rs:23-28`）。

### 1.2 三级部署的使用场景

| 姿态 | 适用场景 | 运行方式 | 特性 |
|---|---|---|---|
| Standalone | 现场笔记本、几台到十几台服务器、完全离线环境、无法部署长期服务的环境 | `rutilus init` 后 `rutilus run` | 默认仅监听回环地址；启动后自动打开浏览器（`--no-open` 关闭）；不需要中心、不需要安装数据库、不需要管理员权限 |
| Site | 客户环境内的一台主机长期运行，多人浏览器访问 | `rutilus run --site --listen HOST:PORT` 或系统服务 | 可监听管理网；非回环监听强制 HTTPS；可选连接中心；中心断开后仍完整运行（§4.2） |
| Center | 汇总多个站点、统一设备与任务视图、分发更新制品 | `rutilus run --center --listen ... --center-listen ...` 或系统服务 | 不直接连接 BMC；不保存 BMC 明文凭据（§4.3、§10.1）；单节点生产中心，非集群（§9.1、§15.7） |

Standalone 与 Site 使用同一套代码（Edge Role），Standalone 可以在不迁移数据的情况下绑定中心并转为 Site（§4.4）。

## 二、快速开始

### 2.1 初始化

```text
rutilus init [--portable]
```

- 无 `--portable` 时数据保存在系统数据目录（Windows `%LOCALAPPDATA%\rutilus`、macOS `~/Library/Application Support/rutilus`、Linux `$XDG_DATA_HOME/rutilus` 或 `~/.local/share/rutilus`）；
- `--portable` 时数据保存在二进制旁的 `rutilus-data/` 目录，适合现场笔记本（`platform/src/runtime_paths.rs`）；
- 初始化要求交互式终端，输入两次"本地解锁口令"（passphrase），用于保护实例 Master Key 的加密信封（`app/src/main.rs`）；
- 初始化会建立实例标记、数据库、Master Key 信封，并**生成一次性 Bootstrap Code 打印到终端**（`app/src/initialization_runtime.rs`）：

```text
Rutilus bootstrap code: XXXX...
Enter this code in the console's first-run screen to set the administrator password.
```

> 该代码只在初始化时打印一次，数据库只保存其 SHA-256 哈希（`domain/src/user.rs`），请立即抄录。

### 2.2 启动与首次登录

```text
rutilus run [--portable] [--no-open]
```

- Standalone 前台运行：绑定 IPv4 回环地址的随机端口，默认自动打开系统浏览器（`app/src/standalone_runtime.rs`）；
- 浏览器打开后显示**首次运行认领屏幕**（Bootstrap 视图）：输入终端打印的 Bootstrap Code、设置管理员密码（可选同时启用 TOTP）（`ui/src/lib.rs:9911` `BootstrapView` 组件，渲染于 `:11964`；`web/src/auth.rs`）；
- 认领完成后进入登录页，用管理员账户登录。

### 2.3 登录与安全基线

- 密码使用 Argon2id 存储，无默认密码（`security/src/password_hash.rs`；§16.2）；
- 支持可选 TOTP（RFC 6238 窗口验证，`web/src/auth.rs`）；
- 登录失败限速：每用户名 5 次失败、每客户端地址 20 次失败，窗口 15 分钟（`web/src/auth.rs`）；
- 会话使用 `rutilus_session` Cookie（Secure、HttpOnly、SameSite），服务端只存令牌的 SHA-256 哈希；变更密码或角色会撤销旧会话（§16.2）；
- 所有变更请求校验 CSRF 令牌（常数时间比较，`web/src/auth.rs`）；
- 非回环监听强制 HTTPS：Site/Center 没有 TLS 材料时拒绝远程登录（`app/src/site_runtime.rs`）。

### 2.4 角色与权限

产品只提供内置账户，不接入 LDAP/AD/OIDC/SAML/RADIUS（§16.1）。三个角色：

| 角色 | 权限要点 | 事实来源 |
|---|---|---|
| Administrator | 管理 Endpoint、管理 Credential、执行全部设备操作、管理用户与会话、管理中心绑定、备份恢复 | §16.1；`web/src/lib.rs` 路由授权表；`ui/src/lib.rs`（Users/Sessions/CenterBindings 视图仅 Administrator） |
| Operator | 查看所有设备、执行允许的设备操作；不读取或管理明文 Credential；不管理用户和系统安全配置 | §16.1 |
| Viewer | 只读 | §16.1 |

审计记录中的权限词汇（`domain/src/audit.rs` 的 `ProductPermission`）：
`manage-endpoints`、`refresh-endpoints`、`execute-operations`、`manage-credentials`、`manage-users`、
`manage-backups`、`manage-site-settings`、`manage-center-bindings`（仅 Administrator）、
`dispatch-center-operations`（Administrator 与 Operator）、`authenticate`。

中心角色的授权可以限定到某些 Site（站点作用域，`web/src/auth.rs` 的视图/派发作用域检查）。

## 三、管理 BMC（端点）

### 3.1 添加单个 BMC（信任优先流程）

界面路径：`Add endpoint`（导航中的 "Add endpoint" 视图）。流程与设计 §14.1 一致，实现上的信任建立遵循"无凭据先观察 TLS"：

```text
输入 URL
→ 获取 TLS 证书（不发送任何凭据）
→ 系统 CA 验证通过：正常建立信任
   或 系统 CA 验证不通过：显示证书指纹，管理员明确 Pin
→ 选择或创建 Credential
→ 认证（SessionService 优先，X-Auth-Token；无法使用时 Basic，并记录为端点能力状态）
→ 读取 Service Root
→ 探测 47 项能力（Compiled ∩ Advertised ∩ Usable）
→ 建立 Endpoint
→ 第一次完整刷新（Generation 语义，刷新失败保留最后一次完整快照并标注数据陈旧程度）
```

事实来源：`application/src/endpoint_trust.rs`（无凭据 TLS 观察、`ExplicitPinRequired` 挑战、`accept_pin`）、
`application/src/endpoint_onboarding.rs`（认证后才探测、探测后才持久化）、`infra-redfish/src/redfish_gateway.rs`。

失败必须明确区分（§14.1）：网络不可达、TLS 不可信、认证失败、权限不足、不是 Redfish 服务、Schema 不兼容、服务可用但能力有限。

### 3.2 凭据

- 凭据保存在**直接连接 BMC 的 Edge 实例**上，Center 只知道"已配置、最近验证结果、引用 ID"（§10.1、`app/src/backup.rs` 模块文档）；
- 一份凭据可以被多台 Endpoint 复用；每个 Endpoint 只有一个明确的活动凭据（`domain/src/credential.rs`；§10.2）；
- 认证失败**不会**自动遍历其他凭据；
- BMC 密码使用 XChaCha20-Poly1305 加密存储，内存中为 Secret 包装，日志与错误统一脱敏（§10.3、`security/src/command_cipher.rs`）；
- 创建凭据的界面入口为 "Credentials" 视图（`ui/src/lib.rs` 的 "Protected BMC access" 区块）。

### 3.3 CSV 批量导入

`Import` 视图支持 CSV 批量导入端点（`application/src/endpoint_csv.rs`）：

| 项 | 值 |
|---|---|
| 固定表头（顺序固定） | `display_name,address,credential_id,tls_sha256` |
| 文档大小上限 | 1 MiB |
| 行数上限 | 10,000 行 |
| 信任方式 | 每行 `tls_sha256` 指纹作为信任期望（`EndpointImportTrust`） |

导入按行独立报告结果，并写入审计（`application/src/endpoint_csv_import.rs`）。

### 3.4 刷新

- 单端点刷新或批量刷新（`refresh_endpoints` API，`web/src/lib.rs`）；
- 批量刷新上限 128 个端点，并发上限 4（32 波内完成一批；`application/src/batch_refresh.rs`）；
- 刷新以 Generation 为单位提交，不会出现"旧系统数据 + 新内存数据"混合展示（§9.5）；
- 刷新失败保留最后一次完整快照，并标明 `LastSuccessfulRefreshAt`、`CurrentRefreshError`、`DataStaleness`。

## 四、日常使用

### 4.1 导航结构

Edge 控制台视图（`ui/src/lib.rs` 的 `ConsoleView`，共 17 个视图，其中 3 个仅中心姿态）：

| 视图 | 说明 |
|---|---|
| Overview | 首页总览 |
| Groups | 分组管理（静态分组） |
| Credentials | 凭据管理 |
| Add endpoint / Import | 添加单个端点 / CSV 导入 |
| Audit | 审计记录 |
| Capabilities | 能力账本视图 |
| Operations | 操作任务 |
| Events | 事件 |
| Artifacts | 更新制品 |
| Telemetry | 遥测（MetricDefinition / MetricReport） |
| Diagnostics | 高级诊断 |
| Users / Sessions | 用户与会话管理（仅 Administrator） |
| Center sites / Center operations / Center bindings | 中心姿态视图（仅 Center 控制台显示） |

中心控制台提供已注册站点列表、聚合端点详情、中心操作派发、绑定管理（`ui/src/lib.rs:10335` `CenterSitesView`、
`:10526` `CenterOperationsView`、`:11338` `CenterBindingsView`，渲染于 `:12581-12583`）。
界面文案经 i18n 目录解析（`ui/src/lib.rs` 的 `ConsoleView::label()` 返回 `L().nav_*` 目录键，
`lib.rs:2922-2940`；运行时语言选择 En/Zh，`ui/src/i18n.rs`），与设计文档 §12.1 的一级导航对应关系为：
总览 = Overview（多服务器清单视图，见 §4.2）；分组 = Groups；操作任务 = Operations；事件 = Events；
更新制品 = Artifacts；凭据 = Credentials；用户与权限 = Users/Sessions；中心连接 = Center bindings；
审计 = Audit。设计文档中的"服务器/管理端点/设置"在实现中不以独立导航视图存在——
服务器与管理端点统一由 Overview 清单呈现（每张端点卡片显示 Systems/Chassis/Managers 资源计数与核心资源列表，
`ui/src/lib.rs:12589` `EndpointCard`，"No resource counts are published until a complete refresh succeeds."
提示 `:12666`），"设置"尚无对应视图（如实标注）。

### 4.2 多服务器首页（Overview）

Overview 视图即多服务器首页（"Inventory"）：上方为 §14.2 聚合仪表盘（一次 `GET /api/v1/overview`
服务端聚合，`web/src/lib.rs` 的 overview 路由），下方为端点清单——每张端点卡片显示统一健康徽标
（Unified endpoint health）、信任徽标、快照状态标签
（"No resource counts are published until a complete refresh succeeds."，`ui/src/lib.rs:12666`）、
Systems/Chassis/Managers 资源计数与核心资源列表（`ui/src/lib.rs:12589` `EndpointCard` 起，资源计数 `:12597-12599`）。

聚合仪表盘（§14.2"首页显示"列表）展示：

- Endpoint 数量（含当前快照 / 等待首次刷新拆分——产品不建模在线/离线/认证失败可达性，
  快照拆分是其如实对应）；
- 厂商分布（§12.3 统一厂商，未发布的端点归入 "Unpublished" 桶）；
- 健康分布（§12.3 统一健康：System/Chassis/Manager 最差 `Health`）；
- 运行中 Operation 数（§13.2 活动态：queued 到 verifying，含 §13.6 远程 Task 监控）；
- 最近事件（服务端保留的最新 5 条，§14.4 原始 `MessageId`/`Severity`）；
- 固件清单摘要（§2.1 `SoftwareInventory` 成员数、端点数与去重版本数）；
- 能力覆盖（§2.4 账本中已观测条目的 Supported 占比，未探针条目不计入）；
- 数据陈旧程度（最近成功刷新时间的年龄分桶：从未刷新 / 1 小时内 / 1 天内 / 7 天内 / 7 天以上）。

已实现的支持能力（§14.2 的"支持"列表）：

- 搜索（按名称或地址）；
- 标签筛选（过滤片）；
- 厂商筛选（过滤片，从清单卡片自动汇总厂商取值）；
- 健康筛选（过滤片）；
- 批量刷新（"Refresh selected"，上限 128 端点、并发 4）；
- 批量类型化操作（见 §五.3）；
- 端点能力查看（每张卡片的 "View capabilities"）。

聚合仪表盘随清单刷新同步重新加载（"Refresh inventory" 与批量刷新后都会重新拉取）。
1.0.0 不设计动态规则组和通用查询语言（§14.2）。

### 4.3 Endpoint 页面（能力驱动呈现）

每个端点的详情页根据该端点实际暴露的能力动态呈现（`domain/src/capability.rs` 的 `UiLocation`，25 个页面位置）。
不支持的模块默认折叠，可在 "Capabilities"（能力）页面查看原因，不产生空白假页面（§12.2）。

Endpoint 页面呈现（§3.1 功能映射的部分事实）：

| 产品功能域 | 呈现位置 |
|---|---|
| 计算系统 | Systems |
| 管理控制器、网络协议 | Managers |
| 机箱、组件、装配件 | Chassis / Assembly |
| 处理器、内存 | Processors / Memory |
| PCIe、网络接口 | Pcie / Network |
| 电源、环境、风扇、传感器 | Power（含 Controls/PowerEquipment/PowerSupplies）/ Thermal / Sensors |
| 配置 | BIOS / Boot / Secure Boot |
| 账户 | Accounts |
| 存储 | Storage |
| 日志 | Logs |
| 事件 | Events |
| 遥测 | Telemetry |
| 更新 | Update |
| 任务 | Tasks |
| OEM | OEM（单页，按厂商命名空间分区块） |
| 诊断 | Diagnostics（只读） |

统一呈现原则（§12.3）：统一字段（名称、厂商、型号、序列号、固件、健康状态、当前状态、更新时间）同时保留厂商原始值与来源（例如统一 Warning + 原始 Warning + 来源 OData URI）。

### 4.4 Advanced Diagnostics

每个资源的诊断面板（`ui/src/lib.rs` "Diagnostics" 面板；`application/src/resource_diagnostics.rs`）只读展示：

- OData URI、OData Type、ETag；
- 对应的 `nv-redfish` feature；
- 持久化的 `TypedPayloadJson` 原文（含 OEM Namespace 与载荷内 Task URI）；
- Refresh Generation。

不允许修改 Method、填写任意 JSON、发送任意请求（§12.4）。解码失败的成员在刷新时即被跳过、不进入快照存储，因此诊断视图不为不存在的资源伪造记录。

## 五、操作任务

### 5.1 操作模型

所有写操作（无论来自 Standalone GUI、Site GUI 还是 Center）都转化为同一套持久化 Operation（§13.1）：

```text
Queued → Validating → Running → WaitingRemote → Verifying → Succeeded
终止：Failed / Cancelled / Unknown
```

`Unknown` 表示"请求可能已被 BMC 接受，但产品当前无法证明最终结果"，不是普通失败（§13.2）。
HTTP 返回 200/201/202/204 都不直接等于业务成功——写操作后必须重新读取目标资源并验证预期结果（§13.3）。

执行流程（§13.3）：读取当前资源 → 检查能力 → 检查权限 → 检查参数 → 持久化 Operation → 调用 `nv-redfish` 类型化方法 → 处理同步响应或 Task → 重新读取 → 验证 → 写入最终状态与审计。

**ETag 现状（如实）**：`update` 写家族（PATCH 家族）携带**本次执行读取时**的目标文档 ETag——文档带 `@odata.etag` 时发送 `If-Match: <etag>`，BMC 以 `412 Precondition Failed` 拒绝即证明写未执行，产品先重读目标并报告冲突，并发变更不被覆盖；无 ETag 的文档保持传输层 `If-Match: *`（仅存在性检查）；action/create/delete 家族在类型化 API 中无 If-Match 通道。**快照 ETag 接线已处置（决策 c，2026-08-12：快照 ETag 无独立写路径消费价值，接线不实施）**——执行时读取恒为分派时刻最新 ETag，快照 ETag 恒更旧、不可替代，论证见 `docs/known-limitations.md` §九该行。实现证据：`infra-redfish/src/redfish_gateway.rs:598-611, 12653-12690, 14002-14062`。

### 5.2 操作表单（当前实现的命令家族）

操作表单提供 **9 个命令家族**（`ui/src/lib.rs` 的 `CommandFamilyView::ALL`）：

| 表单家族 | 对应命令 |
|---|---|
| Account | 创建/更新账户、更新密码、更新用户名、删除账户 |
| System reset | 系统 Reset |
| Manager reset | 管理控制器 Reset、Reset to defaults |
| Chassis reset | 机箱 Reset、电源供应单元 Reset |
| Boot source override | 启动源覆盖（一次性/连续） |
| Secure Boot | 启用、禁用、重置密钥 |
| Event subscription | 创建/删除事件订阅 |
| Firmware update | 制品上传并应用（见 §六） |
| OEM (NVIDIA) | 系统配置 Profile（Update/FactoryReset/Activate）、Debug Token（Generate/Install/Disable/Erase）、Power Smoothing（ActivatePresetProfile/ApplyAdminOverrides） |

Telemetry 家族的专用表单**尚未实现**（"The telemetry write form is a later milestone"），
Log（清空日志）与 Control（控制更新）家族同样没有专用表单——表单选择器会明确拒绝而不是伪造
（`ui/src/lib.rs:6290, 6362, 6438` 返回 `OperationFormError::FamilyRequired`，变体定义 `:6530`，wave-two 后重核）。
已持久化的这些家族命令仍会在操作卡片中正确渲染摘要（`wire_command_summary`）。

### 5.3 批量操作

批量操作是对一组 Endpoint 或 Resource 执行同一种类型化命令（§13.7）：

- 上限 128 个目标（`operation-engine/src/operation_engine.rs` 的 `MAX_BATCH_TARGETS`）；
- 结果按目标独立报告：`Succeeded` / `Failed` / `Unknown` / `Unsupported`，不允许因部分失败伪造整体成功；
- 它不是分布式事务；
- 并发约束：同一 Endpoint 写操作串行；读取有界；固件上传更低并发。

### 5.4 Task 跟踪

BMC 端异步任务（Task）持久保存 Task URI、TaskMonitor URI、OperationId、EndpointId、最后状态、消息、进度、最后检查时间（§13.6）。
程序重启后扫描 `WaitingRemote` 状态的 Operation，重新建立 Session 并继续读取 Task、恢复验证。
浏览器刷新不影响后台任务（§17.2）。

## 六、固件更新

仅使用 `nv-redfish` UpdateService 能力（§14.3）。流程：

```text
上传固件制品（分块，每块 ≤ 4 MiB base64，断点续传）
→ 计算 SHA-256
→ 保存 Artifact（制品字节存文件，元数据存数据库）
→ 读取 SoftwareInventory
→ 检查目标 UpdateService
→ 选择可用更新方法（multipart；或 legacy HttpPushUri 兼容面）
→ 提交（RedfishCommand::Update）
→ 追踪 Task
→ 等待 BMC 可能重启
→ 重新连接
→ 重新读取 SoftwareInventory
→ 验证版本
```

事实来源：`application/src/artifact_store.rs`（分块上传与断点）、`application/src/update_executor.rs`、
`infra-redfish/src/release_baseline.rs`（`update.multipart`、`update.http-push`、`update.patch` 映射）、
`operation-engine/src/operation_engine.rs`。

不提供（§14.3）：自动访问厂商网站下载固件、通用固件适用性数据库、产品自行判断厂商升级依赖、产品自行实现固件回滚。

制品管理界面为 "Artifacts" 视图；已就绪（Ready）的制品才能在固件更新表单中被选择（`ui/src/lib.rs` 的更新草稿校验）。

## 七、事件与遥测

### 7.1 事件

- 每个已登记端点后台监听其 EventService SSE 流（`app/src/event_listener.rs`）：启动时恢复全部已登记端点，运行中新登记的端点在 10 秒内自动拉起监听（懒启动），端点离开登记集则停止监听；
- 支持订阅（创建/删除 EventDestination）与 SSE；记录事件来源，展示原始 MessageId 与 Severity（§14.4）；
- 断线重连有界：指数退避从 1 秒翻倍至上限 60 秒，连续 10 次失败后该端点监听器标记为失败并退出（预算约 4 分钟，可吸收典型 BMC 重启）；
- 一个端点的监听器失败不影响其他端点（失败隔离）；
- 事件查询上限每次 1000 条（`web/src/lib.rs` 的 `EVENT_QUERY_MAX_LIMIT`）。

### 7.2 遥测

- 展示 MetricDefinition 与 MetricReport；支持当前值和有界历史（§14.4）；
- 采样节奏：每 60 秒一次（`app/src/telemetry_sampler.rs` 的 `TELEMETRY_SAMPLE_INTERVAL`）；
- 历史保留：**默认 7 天**，可通过 `--telemetry-retention-days` 配置（`rutilus run`、`rutilus service install` / `service run`；范围 1–365 天，`app/src/telemetry_sampler.rs` 的 `TelemetryRetention`）；"设置页"形态的设置面为 later iteration；
- 遥测查询上限每次 1000 条样本（`TELEMETRY_QUERY_MAX_LIMIT`）；
- 不把产品变成通用时序数据库。

## 八、审计

审计记录（`domain/src/audit.rs`、`application/src/audit_log.rs`；§16.3）：

- 谁（actor：system / local-operator / user）；
- 从 Standalone、Site 还是 Center 发起；
- 操作目标；参数摘要；
- 使用的产品权限（`ProductPermission`）；
- Redfish 操作类型（`AuditRedfishOperation`）；
- 开始、进度和结果；错误；验证结果。

秘密永不进入审计。审计记录只追加，不通过正常 ORM Repository 更新或删除。审计查询上限 1000 条（`AUDIT_QUERY_MAX_LIMIT`）。

## 九、常见操作流程

### 9.1 添加 BMC（完整流程）

1. 进入 "Add endpoint" 视图，输入 BMC URL；
2. 产品获取 TLS 证书（无凭据观察）：
   - 系统 CA 验证通过 → 自动建立信任；
   - 否则显示证书 SHA-256 指纹 → 管理员核对后明确 Pin（`application/src/endpoint_trust.rs`）；
3. 选择已有凭据或创建新凭据（"Credentials" 视图）；
4. 认证并读取 Service Root，探测能力；
5. 完成首次完整刷新；页面按能力呈现该端点的可用模块。

### 9.2 固件更新（完整流程）

1. "Artifacts" 视图上传固件文件（支持大文件分块与断点续传）；
2. 上传完成并校验后，进入端点 Update 页或操作表单，选择 "Firmware update"；
3. 选择已就绪制品（可选填 push URI——仅当端点只提供 legacy HttpPushUri 面时）；
4. 提交后到 "Operations" 视图观察 Operation 状态（WaitingRemote 期间由 Task 跟踪）；
5. BMC 重启后产品自动重连，最终从 SoftwareInventory 验证版本。

### 9.3 批量操作（完整流程）

1. 在列表中筛选/选择多个端点（或使用分组、标签）；
2. 发起批量刷新（上限 128 端点）或选择同一种类型化命令执行（上限 128 目标）；
3. 到 "Operations" 视图查看批量结果，按目标独立查看 Succeeded / Failed / Unknown / Unsupported。

## 十、常见问题（与边界）

| 现象 | 说明 |
|---|---|
| 某台设备缺少某功能页 | 该设备未暴露对应能力，或凭据权限不足；在 "Capabilities" 页查看原因（§12.2），不是产品缺陷 |
| 操作状态为 Unknown | 请求可能已到达 BMC 但结果无法证明；产品会重新读取资源或 Task 后再判断（§13.5） |
| 中心连接断开 | 站点本地继续完整运行；中心恢复后从最后确认序号继续同步（§15.4） |
| 部分厂商 OEM 数据不可见 | 见支持矩阵与已知限制文档（`docs/support-matrix.md`、`docs/known-limitations.md`） |

### 10.1 Unknown 终态与 409 unknown_outcome_pending 对账

**触发场景**：在中心控制台向站点端点派发操作时，若该 (站点, 端点, 命令, 目标) 键上已存在**终态 Unknown** 操作（响应丢失、结果无法证明，§13.5），派发被拒绝：HTTP 409 Conflict、稳定码 `unknown_outcome_pending`，消息形如 `operation <id> is pending an unknown outcome; the retry is refused`。拒绝本身会写入审计（结局 Refused）。产品拒绝盲重试是**设计行为**——同一操作的重复执行可能造成双重效果。

**operation_id 含义**：消息中的操作 id 是既有 Unknown 操作的操作 id，可在中心「Operations」视图查询其命令、目标、actor 与时间；它**可能是他站操作**——端点重新归属（re-home）后，确认读会跨实例核对，命中的 offer 可能来自原绑定站点实例的队列，被拒的不一定是当前站点的操作。

**对账步骤**：

1. 在中心操作视图按返回的 operation_id 定位该操作，确认命令与目标；
2. 人工核验 BMC 实际状态（如更新是否已生效）：
   - **效果已发生** → Unknown 是如实记录，无需重试；409 拒绝是正确行为；
   - **效果未发生** → 见下方已知边界；
3. 确认无安全风险后，按业务判断结束对账——Unknown 是终态，产品不自动重派发。

**已知边界（需人工介入）**：终态 Unknown 没有解锁/清除 API——操作终态吸收后续回执、站点侧跳过终态事件、中心无 reaper 与清除路径，且 409 拒绝响应本身不携带结构化 operation_id（仅嵌在消息文本中）。效果未发生场景下，同键重新派发在控制台上不可行；该冻结与重派发限制已登记为已知限制（`docs/known-limitations.md` §九第七波块 W7-E-6「中心侧无 Running/WaitingRemote 超时与 reaper」、W7-E-7b「409 拒绝响应无结构化 operation_id」），未来引入操作超时/reaper 或解锁路径时处理。

## 附：CLI 命令一览

| 命令 | 用途 |
|---|---|
| `rutilus init [--portable]` | 初始化受保护的 Standalone 数据目录，打印一次性 Bootstrap Code |
| `rutilus run [--portable] [--no-open] [--telemetry-retention-days DAYS]` | 前台运行 Standalone；`--site --listen HOST:PORT [--cert/--key]` 运行 Site；`--center --listen ... --center-listen ...` 运行 Center；`--telemetry-retention-days` 配置遥测历史保留天数（默认 7） |
| `rutilus service install/uninstall` | 安装/卸载系统服务（Windows SCM、launchd、systemd） |
| `rutilus backup create [--portable] [--output PATH]` | 创建加密备份包（需实例已停止） |
| `rutilus backup restore [--portable] PATH` | 离线恢复备份包 |
| `rutilus unbind [--portable]` | 离线解除站点与中心的绑定 |
| `rutilus doctor [--portable]` | 自检（数据目录、数据库、迁移、主密钥、服务、TLS） |
| `rutilus licenses` | 打印第三方许可证清单 |
| `rutilus version` | 打印产品版本、nv-redfish 开发基线与构建 Git Commit（三行） |

事实来源：`app/src/main.rs`。日常 Redfish 操作不设计成 CLI（§18.1）。
