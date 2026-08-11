# 多厂商 Redfish 统一管理产品

## 0.1.0 → 1.0.0 最终设计基线（修订冻结版）

这次重新设计以后，产品不再从“完整 Redfish 平台应该有什么”反推功能，而是严格遵循四条硬约束：

1. **交付物是单个、自包含、跨平台的可执行二进制。**
2. **所有服务器管理卡能力均以 `nv-redfish` 为唯一技术边界。**
3. **产品只是一个统一接入并集中管理多台服务器管理卡的图形化产品。**
4. **实现必须贯彻 Rust 的类型安全、显式状态、错误可控、依赖收敛和编译期约束，而不只是“后端语言用了 Rust”。**

此前设计中超出这个边界的部分全部撤销，包括：

- 自研超聚变、浪潮 OEM Redfish 适配；
- 为了“完整 Redfish”自行补齐 `nv-redfish` 没有的 Schema；
- PostgreSQL、Redis、消息队列、微服务、插件进程；
- 任意脚本、任意 HTTP 请求和通用工作流引擎；
- LDAP、OIDC、复杂审批、多租户、自动整改等非核心能力；
- 虚拟介质、证书服务等当前 `nv-redfish` 未提供的能力；
- 中心主动连接客户 BMC；
- 厂商网页、私有 REST 接口和网页自动化兜底。

---

# 一、最终产品定义

产品正式定义为：

> **一个由 Rust 实现、通过浏览器 GUI 使用、基于 `nv-redfish` 的多服务器管理卡统一管理产品。**

它解决的问题非常明确：

```text
现在：
运维人员
→ 分别打开 iDRAC / iLO / XCC / iBMC / BMC
→ 使用不同界面
→ 逐台查看和操作

产品：
运维人员
→ 打开统一管理界面
→ 接入多台不同厂商 BMC
→ 在同一种产品形态中查看和执行其实际支持的能力
```

产品统一的是：

- 接入方式；
- 页面结构；
- 设备列表；
- 资源导航；
- 操作入口；
- 任务状态；
- 批量使用方式；
- 错误表达；
- 审计记录；
- 中心与站点协同。

产品**不强行统一**不同厂商本来就不等价的语义。

例如两个厂商都提供某个名为 `Operator` 的角色，产品不会只因为名称相同就认定权限完全一致；某台设备没有暴露某项 Redfish 资源，也不会因为其他厂商有而伪造一个功能入口。

---

# 二、功能边界的唯一权威：`nv-redfish`

## 2.1 当前事实基线

截至 **2026 年 8 月 4 日**，`nv-redfish` 开发基线（`NvRedfishDevelopmentBaseline`）为 **0.13.0**，发布于 2026 年 8 月 4 日；**0.14.2** 为已知更新正式版本，在 0.8.0 能力冻结评审时评估是否跟进。它是模块化、按 Cargo feature 编译的 Redfish 客户端栈，不启用任何默认 feature；`std-redfish` 提供较广的标准 Redfish Schema 面，OEM 能力则通过独立 feature 启用。

当前标准功能 feature 包括：

```text
accounts
assembly
bios
boot-options
chassis
computer-systems
controls
ethernet-interfaces
event-service
host-interfaces
log-services
manager-network-protocol
managers
memory
network-adapters
network-device-functions
pcie-devices
ports
power
power-equipment
power-supplies
processors
secure-boot
sensors
session-service
storages
task-service
telemetry-service
thermal
update-service
```

注：`environment-metrics` 不是 `std-redfish` 的独立成员（0.12.1 与 0.13.0 一致），它由 `controls` 与 `sensors` 传递启用，产品仍通过这两个 feature 编译环境指标能力；`ports` 为 0.13.0 新增的 `std-redfish` 成员。

当前 OEM feature 包括：

```text
AMI
Dell
Dell Attributes
HPE
Lenovo
Supermicro
NVIDIA
NVIDIA CPER
NVIDIA Fabrics
NVIDIA Power Management
NVIDIA Profiles
NVIDIA Security
LiteOn
Delta
```

注：0.13.0 移除了 0.12.1 的 `oem-nvidia-bluefield` 与 `oem-nvidia-baseboard`，按能力族拆分为 `oem-nvidia-cper`、`oem-nvidia-fabrics`、`oem-nvidia-power-management`、`oem-nvidia-profiles`、`oem-nvidia-security`；`oem-nvidia` 本身覆盖包括 BlueField DPU 在内的全部 NVIDIA 平台。

当前没有：

```text
xFusion OEM
Inspur OEM
```

因此，超聚变和浪潮在本产品中只能使用它们实际实现、且 `nv-redfish` 已覆盖的**标准 Redfish 能力**。不能通过产品私下调用 OEM URL 补洞。

`nv-redfish` 同时包含：

- CSDL 生成的强类型资源；
- `GET`、`expand`、`filter`；
- 类型化 `create`、`update`、`delete`；
- 类型化 Redfish Action；
- multipart 固件上传；
- SSE 数据流；
- Session 创建；
- Task 处理。

这些能力通过其 `Bmc` trait 和生成类型暴露。

但 `nv-redfish` 官方也明确说明：高层易用封装目前仍然是不断扩充的标准服务子集，不应把“Schema 已生成”误解成“所有资源都有完整高级 SDK”。产品因此必须同时使用：

```text
nv-redfish 高层封装
+
nv-redfish 公开生成类型
+
nv-redfish Bmc trait
```

不能只使用少数高层 wrapper，也不能绕开 `nv-redfish` 自己发送原始请求。

---

## 2.2 “`nv-redfish` 有什么，我们就做什么”的精确定义

一项能力只有满足下列任一条件，才被视为 `nv-redfish` 正式能力：

1. 存在公开 Cargo feature；
2. 存在公开模块或公开生成类型；
3. 存在公开的类型化 Create、Update、Delete 或 Action；
4. 存在公开的 Upload、Stream、Session、Task 接口；
5. 存在公开 OEM 类型。

以下内容不计入：

- 仓库里存在但没有公开 API 的内部代码；
- `main` 分支上尚未正式发布的实验性代码；
- 只存在于 DMTF 标准、但尚未进入 `nv-redfish` 的资源；
- 产品自己猜测出来的 JSON 字段；
- 厂商文档中的私有 REST API；
- 网页抓包获得的接口；
- 用户输入的任意 URI、Method 或 JSON。

---

## 2.3 1.0.0 的上游能力冻结机制

今天无法诚实预测产品发布 1.0.0 时，`nv-redfish` 又会新增哪些 feature。

因此采用明确的能力冻结机制：

### 当前开发起点

```text
NvRedfishDevelopmentBaseline = 0.13.0
```

### 0.1.0 至 0.7.0

每个产品版本开始开发时：

- 评估最新正式 `nv-redfish`；
- 仅升级到正式发布版本；
- 不直接追踪 `main`；
- 将新增公开能力纳入产品能力账本；
- 对 API 破坏进行适配。

### 0.8.0

定义：

```text
NvRedfishReleaseBaseline
```

其内容包括：

```text
精确 crate 版本
Cargo.lock
启用的全部公开 feature
Schema 版本信息
公开模块清单
公开操作清单
能力账本 Hash
```

0.8.0 冻结时，选择当时最新且已经验证的稳定 `nv-redfish` 版本。

### 0.9.0 至 1.0.0

只允许：

- 安全修复；
- 严重 Bug 修复；
- 不增加产品能力面的兼容更新。

冻结后出现的新 `nv-redfish` 功能进入产品 1.1.0，而不是不断推迟 1.0.0。

---

## 2.4 能力账本

项目维护一份机器可读的 `Capability Ledger`：

```rust
struct CapabilityRecord {
    upstream_feature: NvFeature,
    upstream_module: ModulePath,
    resource_types: Vec<ODataType>,
    supported_operations: OperationSet,
    product_surface: ProductSurface,
    ui_location: UiLocation,
    test_status: TestStatus,
    vendor_status: Vec<VendorValidation>,
}
```

每一项能力必须被分类为：

```text
UserFacing
    用户可查看或操作

Infrastructure
    Session、Task、Transport 等内部能力

LegacyCompatibility
    上游保留的旧设备兼容能力

Internal
    Patch helper 等产品内部使用能力
```

1.0.0 发布门槛是：

> **`NvRedfishReleaseBaseline` 的所有公开能力，在能力账本中覆盖率达到 100%。**

不允许存在：

```text
上游已经公开
但产品没人知道有没有使用
```

---

# 三、设备功能范围

## 3.1 当前标准能力到产品功能的映射

| 产品功能域 | `nv-redfish` feature | 产品呈现 |
|---|---|---|
| 服务与连接 | `bmc-http`、`session-service` | 服务根、认证方式、Session 生命周期、连接状态 |
| 计算系统 | `computer-systems` | 系统列表、状态、型号、序列号、UUID、启动和 Action |
| 管理控制器 | `managers`、`manager-network-protocol` | BMC 信息、固件、网络协议和 Manager Action |
| 机箱 | `chassis`、`assembly` | 机箱、组件、装配件、冗余和关联资源 |
| 处理器与内存 | `processors`、`memory` | CPU、内存、指标和状态 |
| PCIe 与网络 | `pcie-devices`、`network-adapters`、`network-device-functions`、`ethernet-interfaces`、`host-interfaces` | PCIe、网卡、接口、功能、MAC、IP、VLAN 等 |
| 电源与环境 | `power`、`power-equipment`、`power-supplies`、`controls`、`environment-metrics`、`sensors`、`thermal` | 功耗、电源、风扇、温度、传感器、功率控制 |
| 配置 | `bios`、`boot-options`、`secure-boot` | BIOS、启动选项、Secure Boot 和公开 Action |
| 账户 | `accounts` | AccountService、ManagerAccount、账户属性和公开写操作 |
| 存储 | `storages` | Storage、Controller、Drive、Volume、指标和公开操作 |
| 日志 | `log-services` | LogService、日志条目、公开 Action |
| 事件 | `event-service` | EventService、订阅、事件流和事件记录 |
| 遥测 | `telemetry-service` | MetricDefinition、MetricReport、Trigger 等 |
| 任务 | `task-service` | 异步 Task 跟踪、状态、结果和取消能力 |
| 更新 | `update-service` | SoftwareInventory、UpdateService、上传和公开更新操作 |
| OEM | 所有公开 OEM feature | 上游已类型化的 OEM 数据和操作 |

这里的“公开操作”统一指：

> `nv-redfish` 基线提供了类型化操作，并且目标 BMC 实际暴露、当前账户也有权限执行。

---

## 3.2 统一产品形态不是最低公共能力集合

产品不会只保留所有厂商都支持的最小交集。

正确模型是：

```text
产品完整编译能力
∩
当前 BMC 实际暴露能力
∩
当前凭据实际权限
=
该管理端点当前可用功能
```

因此：

- Dell 设备可以显示 `nv-redfish` 已支持的 Dell OEM 数据；
- HPE 设备可以显示已支持的 HPE OEM 数据；
- Lenovo 同理；
- 超聚变、浪潮主要走标准 Redfish；
- 某台旧设备只暴露部分标准资源时，页面只显示相应部分；
- 不支持不会被视为错误，也不会被伪造为支持。

---

## 3.3 当前明确不承诺的设备能力

以当前 0.13.0 为起点，以下内容不在正式范围，除非它们在 0.8.0 能力冻结前进入正式 `nv-redfish`：

- `VirtualMedia`；
- `CertificateService`；
- `LicenseService`；
- 厂商私有 Job Service；
- 超聚变 OEM Action；
- 浪潮 OEM Action；
- 任意厂商私有配置导入导出；
- 厂商网页内部接口。

这条边界比“以后可能做”更严格：

> **上游没有，产品就没有。**

---

## 3.4 上游缺失能力的处理原则

发现真实设备需要某项能力但 `nv-redfish` 尚未支持时：

```text
发现缺口
→ 建立最小复现
→ 向 nv-redfish 提交 Issue / PR
→ 等待正式上游能力
→ 升级正式版本
→ 纳入产品
```

不采用：

```text
在产品里长期维护一份私有 OEM 实现
```

允许短期使用上游已合并、尚未发布的精确 Commit 进行开发验证，但正式 1.0.0 必须锁定到：

- 正式上游 Release；或
- 经过完整审计、可复现、带明确上游来源的固定 Commit。

不得追踪浮动分支。

---

# 四、三级部署架构

三级结构正式保留：

```text
单机级 Standalone
站点级 Site
中心级 Center
```

## 4.1 单机级

```text
现场笔记本
└── 单个产品二进制
    ├── 内嵌 Web GUI
    ├── 内嵌 SQLite
    ├── 本地凭据
    └── 直接连接现场 BMC
```

适用于：

- 客户现场临时使用；
- 几台、十几台服务器；
- 完全离线环境；
- 无法部署长期服务的环境。

默认：

```text
监听 127.0.0.1
启动后自动打开浏览器
不需要中心
不需要安装数据库
不需要管理员权限
```

---

## 4.2 站点级

```text
客户环境内的一台主机
└── 同一个产品二进制
    ├── 长期服务运行
    ├── 浏览器多人访问
    ├── 直接连接本环境 BMC
    └── 可选连接中心
```

站点实例是本环境 BMC 的唯一产品执行主体。

它持有：

- BMC 地址；
- BMC 凭据；
- TLS 信任；
- 当前设备事实；
- 操作状态；
- 本地审计。

中心断开后仍完整运行。

---

## 4.3 中心级

```text
中心实例
    ↑
    │ 环境实例主动建立的 mTLS 长连接
    │
站点 A ──→ A 环境 BMC
站点 B ──→ B 环境 BMC
站点 C ──→ C 环境 BMC
```

中心负责：

- 汇总多个站点；
- 统一设备视图；
- 统一健康和任务视图；
- 从中心发起类型化操作；
- 统一查看操作结果；
- 分发更新制品。

中心不负责：

- 直接连接 BMC；
- 保存 BMC 明文凭据；
- 代替站点执行 Redfish；
- 绕过站点本地状态和权限。

云上自有服务器同样部署一个站点实例：

```text
中心
  ↓
云环境站点实例
  ↓
云环境 BMC
```

---

## 4.4 Standalone 与 Site 的关系

Standalone 和 Site 不使用两套代码。

内部只有两个运行角色：

```text
Edge Role
    Standalone 与 Site 共用

Center Role
    中心使用
```

区别只是运行姿态：

| 项目 | Standalone | Site |
|---|---|---|
| 监听地址 | 默认仅回环 | 可监听管理网 |
| 服务运行 | 前台 | 系统服务 |
| 多用户 | 可选 | 正式支持 |
| 中心连接 | 默认关闭 | 可选启用 |
| 数据位置 | 用户数据目录或便携目录 | 系统数据目录 |
| 自动打开浏览器 | 是 | 否 |

Standalone 可以在不迁移数据的情况下绑定中心并转为 Site。

---

# 五、单二进制交付

## 5.1 “单二进制”的精确定义

它不是指一个文件同时在 Windows、macOS 和 Linux 上运行。

它指：

> **每个目标平台和架构只交付一个自包含的可执行文件。**

该文件内包含：

- Edge Role；
- Center Role；
- 全部 `nv-redfish` 标准 feature；
- 全部正式 OEM feature；
- Web 后端；
- Web 前端 WASM、JavaScript Glue 和 CSS；
- 数据库 Migration；
- 默认配置模板；
- 翻译资源；
- OpenAPI/协议定义；
- 第三方许可证信息；
- 静态资源。

不随产品分发：

- `.dll`；
- `.so`；
- `.dylib`；
- Node.js；
- Python；
- JVM；
- PostgreSQL；
- Redis；
- Nginx；
- 厂商 Sidecar；
- 动态插件。

运行时当然仍会产生：

```text
配置
SQLite 数据库
日志
更新制品
备份
证书和密钥材料
```

“单二进制”是**分发和运行依赖语义**，不是“程序不能写任何数据文件”。

---

## 5.2 平台矩阵

1.0.0 正式目标：

| 平台 | 架构 | 构建目标 |
|---|---|---|
| Linux | x86_64 | `x86_64-unknown-linux-musl` |
| Linux | ARM64 | `aarch64-unknown-linux-musl` |
| Windows | x86_64 | `x86_64-pc-windows-msvc` |
| Windows | ARM64 | `aarch64-pc-windows-msvc` |
| macOS | Intel + Apple Silicon | Universal 2，由两个 Darwin 构建合并 |

---

## 5.3 “静态链接”的跨平台真实边界

### Linux

使用 musl 构建：

- Rust 依赖静态链接；
- SQLite 静态链接；
- 不依赖目标机器 glibc 版本；
- 生成静态 PIE。

### Windows

- Rust 依赖静态链接；
- MSVC CRT 使用 `crt-static`；
- 不分发额外 VC Runtime；
- 仍正常使用 Windows 系统 DLL。

### macOS

macOS 不适合作为“完全不依赖任何系统动态库”的纯静态平台。

产品保证：

- 单一可执行文件；
- 不分发自有 `.dylib`；
- Rust 依赖和应用资源均进入可执行文件；
- 仅使用 macOS 自带系统框架和系统库。

因此正式交付术语为：

> **Self-contained single executable，无第三方运行时和随包动态库依赖。**

而不是在 macOS 上作无法兑现的“绝对零动态依赖”承诺。

---

## 5.4 构建配置

发布构建统一采用：

```toml
[profile.release]
opt-level = 3
lto = "fat"
codegen-units = 1
panic = "abort"
strip = "symbols"
incremental = false
```

同时：

- 固定 `rust-toolchain.toml`；
- 提交 `Cargo.lock`；
- 所有依赖精确审计；
- 生成 SBOM；
- 生成 SHA-256；
- Windows Authenticode 签名；
- macOS 签名和公证；
- Linux 提供独立签名；
- 构建结果嵌入版本、Git Commit、`nv-redfish` 基线和能力账本 Hash。

---

# 六、技术选型

## 6.1 总体架构

采用：

> **单二进制、模块化单体、内嵌 Web GUI、内嵌 SQLite。**

不采用微服务。

```text
┌──────────────────────────────────────┐
│          Leptos Web GUI              │
├──────────────────────────────────────┤
│         Axum HTTP / WebSocket        │
├──────────────────────────────────────┤
│      Application Use Cases           │
├──────────────────────────────────────┤
│        Domain State Machines         │
├──────────────────────────────────────┤
│ Redfish Gateway     Center Protocol  │
├──────────────────────────────────────┤
│ nv-redfish          SeaORM           │
├──────────────────────────────────────┤
│ Rustls / SQLite / File Storage       │
└──────────────────────────────────────┘
```

---

## 6.2 选型清单

| 范围 | 最终选择 | 原因 |
|---|---|---|
| 异步运行时 | Tokio | 与 Axum、Reqwest、`nv-redfish` 生态一致 |
| Web 服务 | Axum + Tower | 类型化 Extractor、中间件组合和明确错误模型 |
| TLS | Rustls | 避免 OpenSSL 运行时依赖 |
| Web GUI | Leptos CSR/WASM | 前后端均使用 Rust 类型，构建产物可内嵌 |
| 静态资源 | `rust-embed` | 将前端资源编译进最终二进制 |
| ORM | SeaORM | 异步、类型化 Entity、关系与 Migration |
| Migration | SeaORM Migration + SeaQuery | 不使用裸 SQL |
| 数据库 | SQLite WAL，bundled SQLite | 单二进制、跨平台、无需外部服务 |
| Redfish | `nv-redfish` 全能力构建 | 唯一设备能力来源 |
| 序列化 | Serde | Rust 生态标准 |
| 中心协议 | Protobuf + WebSocket | 强类型、版本化、长连接双向通信 |
| 错误 | `thiserror`，二进制边界可使用 `anyhow` | 明确错误类型和调用链 |
| 日志 | `tracing` + `tracing-subscriber` | 结构化、异步上下文友好 |
| 密码 | Argon2id | 本地账户密码保护 |
| 秘密加密 | XChaCha20-Poly1305 | 本地敏感数据加密 |
| Secret 内存保护 | `secrecy` + `zeroize` | 避免意外输出并主动清理 |
| CLI | Clap | 类型化命令行 |
| ID | UUID 新类型 | 避免对象 ID 混用 |
| 时间 | `time::OffsetDateTime`，数据库统一 UTC | 时间语义明确 |

---

# 七、Rust 工程哲学

“充分 Rust 哲学”在本项目中不是口号，而是以下工程约束。

## 7.1 让非法状态难以表达

禁止使用：

```rust
status: String
kind: String
id: String
```

核心状态使用强类型：

```rust
struct EndpointId(Uuid);
struct OperationId(Uuid);
struct CredentialId(Uuid);

enum OperationState {
    Queued,
    Validating,
    Running,
    WaitingRemote,
    Verifying,
    Succeeded,
    Failed,
    Unknown,
    Cancelled,
}
```

状态变更必须经过显式转换函数：

```rust
fn transition(
    current: OperationState,
    event: OperationEvent,
) -> Result<OperationState, InvalidTransition>;
```

数据库里存在某个字符串，不代表应用可以绕过状态机写入任意状态。

---

## 7.2 Domain、ORM 和协议类型严格分离

严格禁止：

```text
SeaORM Model
直接进入业务层、Web API 或 Redfish 层
```

正式结构：

```text
SeaORM Entity
    ↓ Repository 映射
Domain Model
    ↓ DTO 映射
HTTP / Center Protocol

nv-redfish Type
    ↓ Redfish Gateway 映射
Domain Snapshot / Domain Command
```

这样能够防止：

- 数据库结构成为业务语义；
- `nv-redfish` 0.x API 变化扩散到整个项目；
- Web 前端直接依赖上游 Schema 类型；
- ORM ActiveModel 被业务代码随意修改。

---

## 7.3 裸 SQL 禁止策略

应用代码不允许使用：

```rust
sqlx::query(...)
execute_unprepared(...)
"SELECT ..."
"UPDATE ..."
```

数据库访问全部通过：

- SeaORM Entity；
- ActiveModel；
- Query Builder；
- SeaQuery；
- SeaORM Transaction；
- SeaORM Migration。

进一步通过依赖边界限制：

```text
只有 persistence crate 可以依赖 sea-orm
domain / application / web 不得依赖 sqlx
```

数据库驱动参数使用类型化连接配置。

正常业务 CRUD 和 Migration 不允许手写 SQL。

---

## 7.4 BMC 原始 HTTP 禁止策略

只有 `infra-redfish` crate 可以依赖：

```text
nv-redfish
nv-redfish-bmc-http
```

其他 crate 不能直接依赖 BMC HTTP Client。

特别禁止：

```rust
reqwest
    .post("/redfish/v1/...")
    .json(&serde_json::json!({...}))
```

业务层只能调用：

```rust
RedfishGateway::query(...)
RedfishGateway::execute(...)
```

所有 BMC 写操作必须来自类型化 `nv-redfish` 类型。

---

## 7.5 不把所有东西抽象成 Trait

Rust 最佳实践不是“到处 Trait”。

项目遵循：

- 业务命令使用 `enum` 和穷尽匹配；
- 所有 `nv-redfish` feature 编译进同一程序，因此使用静态模块和枚举分派；
- Trait 只用于真正的边界，例如 Repository、Clock、SecretProtector、BmcFactory；
- 内部默认静态分派；
- 只有需要运行时切换实现时使用 `dyn Trait`。

例如：

```rust
enum RedfishCommand {
    Account(AccountCommand),
    Bios(BiosCommand),
    Boot(BootCommand),
    Manager(ManagerCommand),
    System(SystemCommand),
    Storage(StorageCommand),
    Update(UpdateCommand),
    Event(EventCommand),
    Telemetry(TelemetryCommand),
    Oem(OemCommand),
}
```

新增上游功能后，编译器会强制所有穷尽匹配位置处理新 Variant。

---

## 7.6 错误处理

库 crate 使用明确错误枚举：

```rust
enum RedfishOperationError {
    TlsTrust(TlsTrustError),
    Authentication(AuthenticationError),
    Authorization(AuthorizationError),
    Transport(TransportError),
    Unsupported(UnsupportedCapability),
    SchemaDecode(SchemaDecodeError),
    ProtocolViolation(ProtocolViolation),
    Conflict(ResourceConflict),
    PreconditionFailed(PreconditionFailure),
    RemoteTaskFailed(RemoteTaskFailure),
    VerificationFailed(VerificationFailure),
    UnknownOutcome(UnknownOutcome),
}
```

规则：

- 不把错误变成普通字符串；
- 保留 Source Chain；
- 保留 Redfish ExtendedInfo；
- 用户信息和诊断信息分离；
- 任何未知结果不得伪装成失败或成功；
- `anyhow` 只允许出现在 `main`、CLI 和最外层任务边界。

---

## 7.7 Panic 与 Unsafe

生产代码：

```text
禁止 unwrap
禁止 expect
禁止 todo!
禁止 unimplemented!
禁止主动 panic
```

绝大多数 workspace crate：

```rust
#![forbid(unsafe_code)]
```

只有确实需要平台 API 的独立 crate 可以申请使用 `unsafe`，且必须：

- 封装成最小安全接口；
- 单独安全审计；
- 有平台测试；
- 不向上层暴露裸指针。

---

## 7.8 异步与并发

- 不在 Tokio worker 中执行阻塞文件操作；
- 哈希、大文件压缩、备份使用 `spawn_blocking`；
- 所有 Channel 有界；
- 所有任务具有取消令牌；
- 所有长连接具有 Shutdown 信号；
- 每个端点限制并发；
- 写操作默认每个端点串行；
- 读取有全局和端点级 Semaphore；
- 不创建无法追踪的 detached task；
- 应用退出时进行结构化排空。

---

# 八、Cargo Workspace

```text
workspace/
├── app
│   └── 最终唯一二进制入口
├── domain
│   └── ID、实体、状态机、错误和不变量
├── application
│   └── 用例、权限、事务协调
├── infra-redfish
│   └── 唯一依赖 nv-redfish 的 crate
├── persistence
│   └── SeaORM Repository
├── entity
│   └── SeaORM Entity
├── migration
│   └── SeaORM Migration
├── security
│   └── 密码、加密、Secret、Session
├── operation-engine
│   └── 持久任务和恢复
├── center-protocol
│   └── Protobuf 消息和版本协商
├── web
│   └── Axum API 和中间件
├── ui
│   └── Leptos 前端
├── platform
│   └── Windows/macOS/Linux 服务和路径
└── test-support
    └── Mock、Fixture、故障注入
```

依赖方向：

```text
domain
  ↑
application
  ↑
web / operation-engine
  ↑
infra-redfish / persistence / security / platform
  ↑
app
```

`domain` 不依赖：

- Axum；
- SeaORM；
- Leptos；
- `nv-redfish`；
- SQLite；
- 操作系统 API。

---

# 九、数据设计

## 9.1 数据库统一选择

Standalone、Site、Center 全部使用：

```text
SQLite + WAL
```

原因：

- 单二进制；
- 无外部数据库；
- 目标主要是几台、十几台到中等规模服务器；
- 一个实例只有一个活动进程；
- 中心失效不会影响站点执行；
- 数据可以直接备份、迁移和恢复。

1.0.0 的 Center 是：

> **单节点生产中心，不是主动—主动集群。**

不为了未来可能出现的大规模需求提前引入 PostgreSQL。

如果未来需要中心水平扩展，应作为新的架构版本处理，不能在当前设计中同时维护两套数据库语义。

---

## 9.2 SQLite 运行规则

- bundled SQLite 静态链接；
- WAL；
- Foreign Key 开启；
- Busy Timeout；
- 小型连接池；
- 写事务通过应用级写 Semaphore 限制；
- 单个数据目录不允许两个进程同时运行；
- 禁止将数据库放在 NFS、SMB 等网络文件系统；
- 每次启动执行 Migration；
- Migration 前自动建立可恢复备份；
- 数据库错误进入明确只读或启动失败状态，不静默重建。

---

## 9.3 核心表

### 实例与中心

```text
instances
center_bindings
center_outbox
center_inbox
sync_cursors
```

### BMC 与 Redfish 资源

```text
endpoints
endpoint_addresses
endpoint_trust
endpoint_capabilities
resources
resource_snapshots
resource_links
```

### 凭据

```text
credentials
credential_versions
endpoint_credentials
```

### 资源投影

```text
systems
chassis
managers
hardware_index
health_index
```

这些是搜索和首页展示投影，不替代完整 Resource Snapshot。

### 任务

```text
operations
operation_targets
operation_steps
remote_tasks
operation_events
```

### 事件和遥测

```text
events
telemetry_series
telemetry_samples
```

### 制品

```text
artifacts
artifact_references
artifact_transfers
```

### 产品用户

```text
principals
password_credentials
totp_authenticators
sessions
role_assignments
```

### 组织与标签

```text
groups
group_members
tags
resource_tags
```

### 审计

```text
audit_events
```

---

## 9.4 Redfish 资源存储方式

不为每一种 Redfish Schema 创建一套独立关系表。

采用混合模型：

### 稳定关系模型

保存：

- Endpoint；
- System；
- Manager；
- Chassis；
- Credential；
- Operation；
- User；
- Group；
- Artifact。

### 版本化 Resource Snapshot

保存：

```text
EndpointId
ODataId
ODataType
ETag
Feature
TypedPayloadJson
ObservedAt
Generation
```

`TypedPayloadJson` 只能来自：

```text
nv-redfish 类型成功反序列化
→ 再由 Serde 序列化
```

不保存未经校验的任意写入 JSON。

这样可以兼顾：

- Schema 随上游变化；
- OEM 类型变化；
- 统一查询；
- 历史诊断；
- ORM 管理。

---

## 9.5 数据一致性

设备刷新必须以 Generation 为单位：

```text
开始刷新 Generation N
→ 读取所有目标资源
→ 完成校验
→ 事务提交资源和投影
→ Generation N 成为当前版本
```

不允许刷新到一半，就让首页同时展示：

```text
旧系统数据
+
新内存数据
+
未知来源的电源状态
```

刷新失败时继续保留最后一次完整快照，并标明：

```text
LastSuccessfulRefreshAt
CurrentRefreshError
DataStaleness
```

---

# 十、秘密与凭据

## 10.1 BMC 凭据归属

BMC 凭据只存在于直接连接 BMC 的 Edge 实例。

Center 只知道：

```text
凭据已经配置
最近验证成功或失败
凭据引用 ID
```

Center 永远不知道明文秘密。

---

## 10.2 凭据模型

```text
Credential
├── CredentialId
├── Name
├── UserName
└── ActiveVersionId

CredentialVersion
├── VersionId
├── EncryptedSecret
├── Nonce
├── CreatedAt
└── State
```

一份凭据可以被多台 Endpoint 复用。

正常运行时：

```text
一个 Endpoint
→ 一个明确活动 Credential
→ 一个明确活动 CredentialVersion
```

认证失败不得自动遍历其他凭据。

---

## 10.3 加密

- 实例首次初始化生成 256-bit Master Key；
- BMC 密码使用 XChaCha20-Poly1305；
- Associated Data 绑定 `CredentialId + VersionId`；
- 每份秘密使用独立随机 Nonce；
- 内存使用 Secret 包装；
- 不实现 `Debug` 明文输出；
- 日志和错误统一脱敏；
- Master Key 不进入数据库明文。

### Master Key 保护

Standalone：

- 默认交互式本地解锁；
- 可选使用操作系统安全存储。

Site/Center：

- 使用系统账户保护的独立密钥文件；
- Windows 可使用 DPAPI；
- macOS 可使用 Keychain；
- Linux 可使用受保护密钥文件或系统密钥设施；
- 不把主密钥放在命令行或普通配置。

---

## 10.4 TLS 信任

添加 BMC 时先获取证书，不发送凭据。

流程：

```text
连接目标 HTTPS
→ 获取证书
→ 系统 CA 验证
或
→ 显示证书指纹
→ 管理员明确 Pin
→ 保存信任
→ 再提交 BMC 凭据
```

禁止全局：

```text
accept_invalid_certs = true
```

证书变化必须进入：

```text
TlsIdentityChanged
```

不能自动接受。

---

# 十一、Redfish Gateway

## 11.1 唯一 BMC 边界

```rust
struct RedfishGateway {
    client_factory: BmcFactory,
    baseline: NvRedfishBaseline,
}
```

它负责：

- 创建 `HttpBmc`；
- 建立 Session；
- 管理 Token；
- 创建 `ServiceRoot`；
- 遍历资源；
- 调用类型化操作；
- 转换上游错误；
- 输出 Domain Snapshot；
- 追踪 Task；
- 重新读取并验证结果。

其他模块不能访问 `HttpBmc`。

---

## 11.2 Session 策略

优先：

```text
SessionService + X-Auth-Token
```

设备没有或无法可靠使用 SessionService 时，允许：

```text
Basic Authentication
```

但必须被记录为 Endpoint 能力状态。

Session Token：

- 只存在内存；
- 不写入备份；
- 不传给 Center；
- 程序重启后重新建立；
- 删除 Endpoint 或更换凭据时主动清理。

---

## 11.3 能力发现

每个 Endpoint 建立：

```text
CompiledCapability
AdvertisedCapability
UsableCapability
```

### Compiled

当前二进制是否包含对应 `nv-redfish` feature。

### Advertised

BMC 是否通过 Service Root、导航链接、资源和 Action 暴露。

### Usable

当前认证、权限、Schema 解码和设备状态是否允许使用。

最终状态：

```text
Supported
ReadOnly
Unauthorized
TemporarilyUnavailable
SchemaIncompatible
NotAdvertised
NotCompiled
```

---

## 11.4 不硬编码资源路径

禁止假设：

```text
/redfish/v1/Systems/1
/redfish/v1/Managers/1
/redfish/v1/Chassis/1
```

所有资源必须从：

- Service Root；
- Navigation Property；
- Collection Member；
- Action Target；
- OData Link；

动态发现。

---

## 11.5 OEM 处理

OEM 数据只有两种合法处理方式：

### 上游已有强类型 OEM

通过对应 `nv-redfish` OEM feature 读取和操作。

### 上游没有

保留标准部分，OEM 功能显示：

```text
UnsupportedByNvRedfishBaseline
```

不得退回：

- 原始 JSON 写操作；
- 厂商私有 URL；
- 网页接口；
- 产品私有插件。

---

# 十二、统一 GUI

## 12.1 一级导航

所有厂商使用同一种页面结构：

```text
总览
服务器
管理端点
分组
操作任务
事件
更新制品
凭据
用户与权限
中心连接
审计
设置
```

---

## 12.2 Endpoint 页面

根据能力动态呈现：

```text
概览
Systems
Chassis
Managers
Assembly
Processors
Memory
PCIe
Network
Power
Thermal
Sensors
BIOS
Boot
Secure Boot
Storage
Accounts
Logs
Events
Telemetry
Update
Tasks
OEM
Diagnostics
```

不支持的模块：

- 默认折叠；
- 可在“能力”页面查看原因；
- 不产生空白假页面。

---

## 12.3 统一呈现原则

产品统一字段：

```text
名称
厂商
型号
序列号
固件
健康状态
当前状态
更新时间
```

同时保留厂商原始值。

例如健康状态可以展示：

```text
统一：Warning
原始：Warning
来源：/redfish/v1/Chassis/...
```

不能只留下统一值而丢失来源。

---

## 12.4 Advanced Diagnostics

高级诊断允许查看：

- OData URI；
- OData Type；
- ETag；
- 原始只读响应；
- 解码错误路径；
- `nv-redfish` feature；
- OEM Namespace；
- Task URI；
- ExtendedInfo。

不允许：

- 修改 Method；
- 填写任意 JSON；
- 发送任意请求；
- 绕过正常权限和任务模型。

---

# 十三、操作模型

## 13.1 所有写操作都是持久 Operation

无论来自：

- Standalone GUI；
- Site GUI；
- Center；

都转化为同一套：

```text
Operation
```

```rust
struct Operation {
    id: OperationId,
    source: OperationSource,
    command: RedfishCommand,
    targets: Vec<TargetId>,
    state: OperationState,
    created_at: OffsetDateTime,
}
```

---

## 13.2 状态机

```text
Queued
→ Validating
→ Running
→ WaitingRemote
→ Verifying
→ Succeeded
```

终止状态还包括：

```text
Failed
Cancelled
Unknown
```

`Unknown` 表示：

> 请求可能已经被 BMC 接受，但产品当前无法证明最终结果。

这不是普通失败。

---

## 13.3 执行流程

```text
1. 读取当前资源
2. 检查能力
3. 检查权限
4. 检查操作参数
5. 检查 ETag 或前置条件
6. 持久化 Operation
7. 调用 nv-redfish 类型化方法
8. 处理同步响应或 Task
9. 重新读取目标资源
10. 验证预期结果
11. 写入最终状态和审计
```

HTTP 返回 200、201、202 或 204，都不直接等于业务成功。

---

## 13.4 ETag 与并发修改

存在 ETag 时：

- 写操作必须使用 ETag；
- 发生 `PreconditionFailed` 时停止；
- 重新读取当前状态；
- 不自动覆盖他人修改。

不存在 ETag 时：

- 保存操作前快照；
- 执行后重新读取；
- 明确标注缺少并发保护。

---

## 13.5 重试

自动重试仅适用于：

- GET；
- Expand；
- Filter；
- 明确幂等的读取；
- 能够确认未送达的请求。

以下操作响应丢失后不得直接重试：

- Create；
- Delete；
- Action；
- 密码修改；
- 固件提交；
- Volume 创建；
- Reset。

正确处理：

```text
响应丢失
→ 标记 Unknown
→ 重新读取资源或 Task
→ 判断是否已经发生
→ 再决定后续
```

---

## 13.6 Task

异步任务持久保存：

```text
Task URI
TaskMonitor URI
OperationId
EndpointId
LastState
LastMessage
PercentComplete
LastCheckedAt
```

程序重启后：

```text
扫描 WaitingRemote
→ 重新建立 Session
→ 继续读取 Task
→ 恢复验证
```

---

## 13.7 批量操作

批量操作是：

> 对一组 Endpoint 或 Resource 执行同一种类型化命令。

它不是分布式事务。

结构：

```text
BatchOperation
├── Child Operation A
├── Child Operation B
└── Child Operation C
```

结果按目标独立：

```text
Succeeded: 8
Failed: 1
Unknown: 1
Unsupported: 2
```

不允许因为部分失败就伪造整体成功。

默认并发：

- 同一 Endpoint 写操作：1；
- 同一 Endpoint 读取：有界；
- Site 全局操作：有界；
- 固件上传：更低并发。

---

# 十四、具体使用流程

## 14.1 添加 BMC

```text
输入 URL
→ 获取 TLS 证书
→ 建立信任
→ 选择或创建 Credential
→ 认证
→ 读取 Service Root
→ 探测 feature
→ 建立 Endpoint
→ 第一次完整刷新
```

失败必须明确区分：

```text
网络不可达
TLS 不可信
认证失败
权限不足
不是 Redfish 服务
Schema 不兼容
服务可用但能力有限
```

---

## 14.2 多服务器首页

首页显示：

- Endpoint 数量；
- 在线、离线、认证失败；
- 厂商分布；
- 健康状态；
- 运行中的 Task；
- 最近事件；
- 固件清单摘要；
- 能力覆盖；
- 数据陈旧程度。

支持：

- 搜索；
- 标签；
- 静态分组；
- 厂商筛选；
- 健康筛选；
- 功能筛选；
- 批量刷新；
- 批量类型化操作。

1.0.0 不设计动态规则组和通用查询语言。

---

## 14.3 固件更新

仅使用 `nv-redfish` UpdateService 能力。

```text
上传固件制品
→ 计算 SHA-256
→ 保存 Artifact
→ 读取 SoftwareInventory
→ 检查目标 UpdateService
→ 选择可用更新方法
→ 提交 multipart 或公开接口
→ 追踪 Task
→ 等待 BMC 可能重启
→ 重新连接
→ 重新读取 SoftwareInventory
→ 验证版本
```

不提供：

- 自动访问厂商网站下载固件；
- 通用固件适用性数据库；
- 产品自行判断厂商升级依赖；
- 产品自行实现固件回滚。

---

## 14.4 Event 与 Telemetry

Event：

- 使用 EventService 公开能力；
- 支持订阅和 SSE；
- 记录事件来源；
- 去除明显重复；
- 展示原始 MessageId 和 Severity。

Telemetry：

- 展示 MetricDefinition；
- 展示 MetricReport；
- 支持当前值和有界历史；
- 不把产品变成通用时序数据库；
- 历史保留周期可配置。

---

# 十五、中心与站点协议

## 15.1 连接方向

```text
Site 主动连接 Center
```

Center 不进入客户网络。

传输：

```text
TLS 1.3
mTLS
WebSocket
Protobuf
```

---

## 15.2 消息类型

```text
Hello
CapabilityManifest
EndpointSnapshot
ResourceDelta
EventBatch
OperationOffer
OperationAccepted
OperationRejected
OperationProgress
OperationCompleted
ArtifactManifest
ArtifactChunk
Ack
Heartbeat
```

---

## 15.3 版本协商

连接时交换：

```text
ProductVersion
CenterProtocolVersion
NvRedfishBaseline
CapabilityLedgerHash
InstanceId
```

没有共同协议版本：

```text
拒绝中心协同
但 Site 继续本地运行
```

---

## 15.4 可靠传输

每个站点维护：

```text
Outbox Sequence
```

Center 返回：

```text
Ack Sequence
```

重连后：

```text
从最后 Ack 继续
```

中心下发 Operation 使用稳定 `OperationId`。

Site 对重复 Operation：

```text
已经存在
→ 返回已有状态
→ 不重复执行
```

采用：

> 至少一次消息传递，幂等处理，单次业务效果。

---

## 15.5 Center 数据

Center 保存：

- Site 实例信息；
- Endpoint 摘要；
- Resource 投影；
- 健康；
- 事件；
- Operation；
- Artifact；
- 审计。

Center 不保存：

- BMC 密码；
- BMC Session Token；
- Site Master Key；
- Site 解锁秘密；
- Site 原始私钥。

---

## 15.6 Center 操作

Center 下发：

```text
RedfishCommand
+
Target
+
OperationId
+
ExpiresAt
+
ActorContext
```

不下发：

```text
URL
HTTP Method
Headers
JSON Body
脚本
```

Site 必须重新检查：

- Endpoint 是否仍存在；
- 能力是否仍存在；
- 凭据是否有效；
- 目标状态是否仍适用；
- Operation 是否过期。

只有 Site 明确 `Accepted` 后，才转移执行责任。

---

## 15.7 Center 1.0.0 可用性边界

1.0.0 Center：

- 单个活动实例；
- SQLite；
- 可由 systemd、launchd 或 Windows Service 自动拉起；
- 支持加密备份和恢复；
- 允许冷备或主机级高可用；
- 不提供产品内部多节点集群。

这是有意设计：

> Center 暂时不可用只影响集中视图和新中心操作，不影响 Site 已接受任务和本地管理。

---

# 十六、产品用户和权限

## 16.1 1.0.0 保持简单

只提供内置产品账户，不接入：

- LDAP；
- Active Directory；
- OIDC；
- SAML；
- RADIUS。

内置角色：

```text
Administrator
Operator
Viewer
```

### Administrator

- 管理 Endpoint；
- 管理 Credential；
- 执行全部设备操作；
- 管理用户；
- 管理中心绑定；
- 备份恢复。

### Operator

- 查看所有设备；
- 执行允许的设备操作；
- 不读取或管理明文 Credential；
- 不管理用户和系统安全配置。

### Viewer

- 只读。

Center 角色可以限定到某些 Site。

---

## 16.2 登录安全

- 密码使用 Argon2id；
- 无默认密码；
- 首次启动生成一次性 Bootstrap Code；
- 管理员首次进入时必须设置密码；
- 支持可选 TOTP；
- 非回环监听时强制 HTTPS；
- Session Cookie 使用 Secure、HttpOnly、SameSite；
- CSRF 防护；
- 登录失败限速；
- 密码或角色变化撤销旧 Session。

WebAuthn 和企业身份源不进入 1.0.0，以避免偏离产品核心。

---

## 16.3 审计

记录：

- 谁；
- 从 Standalone、Site 还是 Center 发起；
- 操作目标；
- 参数摘要；
- 使用的产品权限；
- Redfish Operation 类型；
- 开始、进度和结果；
- 错误；
- 验证结果。

秘密永不进入审计。

审计记录只追加，不通过正常 ORM Repository 更新或删除。

---

# 十七、前端设计

## 17.1 Leptos 使用方式

采用：

```text
Leptos CSR
→ 编译为 WASM
→ rust-embed 进入最终二进制
→ Axum 提供静态资源和 API
```

前后端共享：

- ID；
- 枚举；
- DTO；
- OperationState；
- CapabilityState；
- ErrorCode。

但不共享：

- Domain Entity 内部不变量；
- SeaORM Model；
- `nv-redfish` 类型；
- Secret 类型。

---

## 17.2 实时更新

通过产品自己的 WebSocket：

- Operation Progress；
- Endpoint Online State；
- Event；
- Task；
- Refresh Completion。

浏览器刷新不影响后台任务。

---

# 十八、跨平台运行

## 18.1 CLI

唯一二进制提供有限子命令：

```text
product init
product run
product service install
product service uninstall
product backup create
product backup restore
product doctor
product version
product licenses
```

不把日常 Redfish 操作设计成 CLI。

---

## 18.2 数据目录

### Portable

```text
product run --portable
```

数据保存在二进制旁的独立目录，适合现场笔记本。

### Installed

- Windows：ProgramData / LocalAppData；
- macOS：Application Support；
- Linux：XDG 或 `/var/lib`。

站点和中心建议使用独立 OS 账户。

---

## 18.3 系统服务

同一二进制自行生成和注册：

- Windows Service；
- launchd；
- systemd。

不分发额外 Service Wrapper。

---

# 十九、测试和兼容认证

## 19.1 测试分层

### Domain Unit Test

- 状态机；
- 权限；
- Capability 交集；
- 批量结果；
- 错误分类；
- 数据不变量。

### ORM Integration Test

- Migration；
- Repository；
- Transaction；
- 并发写；
- 崩溃恢复；
- 备份恢复。

### `nv-redfish-bmc-mock`

使用 `nv-redfish` 自带 Mock BMC，覆盖 GET、PATCH、POST/Create、DELETE、Action、SSE 和 Session 创建。

### Fixture Test

保存脱敏的真实 BMC Response：

```text
Dell / 固件版本
HPE / 固件版本
Lenovo / 固件版本
xFusion / 固件版本
Inspur / 固件版本
```

每次升级 `nv-redfish` 时执行回归。

### Physical Device Test

目标五个厂商至少各有一台真实设备进入 1.0.0 认证矩阵。

---

## 19.2 厂商验证原则

### Dell、HPE、Lenovo

验证：

- 标准 feature；
- 上游已有 OEM feature；
- 不声称覆盖其全部 OEM API。

### 超聚变、浪潮

验证：

- Service Root；
- Systems；
- Chassis；
- Managers；
- Session；
- Task；
- 当前基线支持的标准资源。

OEM-only 功能明确标为：

```text
NotAvailableInNvRedfishBaseline
```

---

## 19.3 故障注入

必须覆盖：

- BMC 慢响应；
- TLS 证书变化；
- 登录 Token 失效；
- JSON 字段类型错误；
- Schema 缺字段；
- Action 响应丢失；
- Task 消失；
- BMC 更新中重启；
- 产品进程在任务中被终止；
- SQLite 写入中断；
- Center/Site 断线；
- 重复消息；
- 重复 Operation；
- 大文件上传中断；
- 磁盘空间不足；
- 系统时间变化。

---

## 19.4 CI 质量门槛

每个合并请求必须通过：

```text
cargo fmt --check
cargo clippy --workspace --all-targets --all-features
cargo test
cargo nextest
cargo llvm-cov
cargo deny
cargo audit
cargo machete
跨平台 Build
Migration Test
Capability Ledger Check
```

禁止警告进入主分支。

---

# 二十、备份、恢复和升级

## 20.1 备份

备份内容：

- SQLite 一致性快照；
- Master Key 的受保护包装；
- Credential 密文；
- 配置；
- 中心绑定状态；
- Artifact 元数据；
- 可选 Artifact 文件。

备份过程：

```text
暂停新写事务
→ 等待当前写事务结束
→ 关闭或安全冻结 SQLite
→ 复制一致数据库
→ 重新开放写入
→ 创建加密备份包
→ 校验备份
```

不依赖手写 SQL。

---

## 20.2 恢复

恢复必须离线进行：

```text
停止实例
→ 验证备份完整性
→ 解密
→ 检查 Product 和 Schema 版本
→ 恢复数据
→ 启动
→ 重新建立 BMC Session
→ 恢复未完成 Operation
```

恢复出的 Site 与 Center 重连时必须验证实例身份，避免同一实例备份被同时启动两次。

---

## 20.3 产品升级

```text
验证新二进制签名
→ 创建备份
→ 停止接收新操作
→ 持久化运行状态
→ 停止旧进程
→ 替换单二进制
→ 启动新版本
→ SeaORM Migration
→ 恢复 Task 跟踪
```

不实现自动后台自更新。

---

# 二十一、版本路线图

每个版本都是可真实使用的纵向闭环，不做只存在接口的空壳版本。

---

## 0.1.0：单机基础闭环

### 目标

> 在 Windows、macOS、Linux 上用一个二进制安全接入多台 BMC，并读取核心资源。

### 内容

- 三平台构建；
- Standalone；
- Axum + Leptos；
- Embedded Assets；
- SeaORM + SQLite；
- Migration；
- Master Key；
- Credential 加密；
- TLS Trust；
- Endpoint 添加；
- CSV 批量导入；
- SessionService；
- Service Root；
- Systems；
- Chassis；
- Managers；
- 基础 Resource Snapshot；
- 基础审计；
- 当前 `nv-redfish` 基线信息展示。

### 验收

- 单文件运行；
- 不安装数据库；
- 不安装浏览器插件；
- 五个目标厂商至少完成核心读取；
- 不硬编码资源 URI；
- 凭据不明文；
- 数据库升级可重复执行。

---

## 0.2.0：标准只读能力全覆盖

### 目标

> 完成当前 `nv-redfish` 所有标准资源 feature 的读取和统一呈现。

### 内容

- Accounts；
- Assembly；
- BIOS；
- Boot Options；
- Controls；
- Ethernet Interfaces；
- Host Interfaces；
- Log Services；
- Manager Network Protocol；
- Memory；
- Network Adapters；
- Network Device Functions；
- PCIe；
- Power；
- Power Equipment；
- Power Supplies；
- Processors；
- Secure Boot；
- Sensors；
- Storage；
- Thermal；
- Task；
- Event；
- Telemetry；
- Software Inventory；
- Capability Ledger；
- 分组、标签、搜索；
- 完整 Endpoint 页面；
- Advanced Diagnostics。

### 验收

- 标准公开 feature 读取映射覆盖 100%；
- 任意 feature 缺失都有明确原因；
- Schema 解码失败不会导致整个 Endpoint 不可用；
- 首页数据来自完整 Refresh Generation。

---

## 0.3.0：类型化写操作与任务恢复

### 目标

> 将 `nv-redfish` 已公开的 Create、Update、Delete 和 Action 全部接入统一 Operation Engine。

### 内容

- `RedfishCommand`；
- Operation State Machine；
- TaskService；
- ETag；
- 并发锁；
- 结果验证；
- Unknown Outcome；
- Crash Recovery；
- Accounts 写操作；
- BIOS 写操作；
- Boot 写操作；
- Secure Boot；
- Manager Network Protocol；
- ComputerSystem Action；
- Manager Action；
- Chassis Action；
- LogService Action；
- Storage 公开操作；
- Event Subscription；
- Telemetry 公开写操作。

### 验收

- 所有写操作经过持久状态机；
- 进程中断后可恢复；
- 非幂等请求不盲重试；
- 写操作后重新读取验证；
- 不支持的操作不能发送。

---

## 0.4.0：Update、事件流和遥测

### 目标

> 完成上游生命周期和流式能力。

### 内容

- UpdateService；
- Artifact Store；
- Multipart Upload；
- 上游保留的 Legacy Update 兼容；
- SoftwareInventory；
- Update Task；
- SSE；
- Event Subscription；
- Event History；
- MetricDefinition；
- MetricReport；
- Telemetry 有界历史；
- 大文件断点和进度；
- BMC 重启后的重连。

### 验收

- 固件上传中断可恢复或明确失败；
- BMC 重启后继续追踪；
- 最终固件版本重新读取；
- Event/SSE 异常不会拖垮进程；
- Telemetry 存储有明确上限。

---

## 0.5.0：OEM 与多厂商闭环

### 目标

> 对当前上游所有公开 OEM feature 完成产品映射。

### 内容

- AMI；
- Dell；
- Dell Attributes；
- HPE；
- Lenovo；
- Supermicro；
- NVIDIA；
- NVIDIA 产品 feature；
- LiteOn；
- Delta；
- OEM 页面；
- OEM 类型化 Action；
- OEM Capability Ledger；
- 五厂商真实 Fixture；
- Dell/HPE/Lenovo 真实 OEM 测试；
- xFusion/Inspur 标准模式验证；
- 批量读取和批量类型化操作。

### 验收

- OEM 公开能力映射覆盖 100%；
- 不存在产品私有 OEM 请求；
- xFusion/Inspur 不会误显示其他厂商功能；
- 批量任务按 Endpoint 独立报告。

---

## 0.6.0：站点生产形态

### 目标

> 同一个二进制能够长期部署在客户管理网。

### 内容

- Site 模式；
- 非回环 HTTPS；
- 系统服务安装；
- 内置用户；
- Administrator/Operator/Viewer；
- 可选 TOTP；
- Session 管理；
- 审计；
- 数据保留；
- 正式备份恢复；
- Portable 和 Installed 模式；
- Doctor；
- 资源限流；
- Graceful Shutdown；
- 多用户实时界面。

### 验收

- Windows Service、launchd、systemd 通过；
- 非 HTTPS 不允许远程登录；
- 最后一个管理员不能被删除；
- 备份可在另一台同平台或异平台机器恢复；
- 正在运行的 Redfish Task 不因服务重启丢失。

---

## 0.7.0：中心形态

### 目标

> 多个站点通过一个中心统一查看和操作。

### 内容

- Center 模式；
- Site 身份；
- 一次性绑定；
- mTLS；
- Protobuf；
- WebSocket 长连接；
- Capability Manifest；
- 数据增量同步；
- Outbox/Inbox；
- Center Endpoint 视图；
- Center Operation；
- Operation TTL；
- 离线队列；
- Artifact 中心分发；
- 中心用户与站点作用域；
- 单中心绑定；
- 断线重连和幂等。

### 验收

- Center 不连接 BMC；
- Center 不保存 BMC 密码；
- Site 断线后本地继续工作；
- 已接受 Operation 继续运行；
- 重连不重复执行；
- Standalone 可原地绑定并成为 Site。

---

## 0.8.0：1.0 能力冻结

### 目标

> 追平并冻结正式 1.0.0 所使用的 `nv-redfish` 基线。

### 内容

- 升级至当时最新稳定 `nv-redfish`；
- 重新生成 Capability Ledger；
- 纳入从 0.13.0 到冻结版本新增的所有公开 feature；
- 纳入新增公开 OEM feature；
- 完成所有新增类型化操作；
- 固定 Cargo.lock；
- 固定 Schema；
- 固定 Center Protocol；
- 固定数据库 Schema；
- 固定 UI 导航和操作语义。

### 验收

```text
公开能力账本覆盖率 = 100%
未分类公开模块 = 0
未映射公开操作 = 0
私有 BMC HTTP 请求 = 0
裸 SQL = 0
```

0.8.0 后不再增加功能域。

---

## 0.9.0：生产候选

### 目标

> 只做正确性、兼容性、安全、性能和交付。

### 内容

- 五厂商实验室；
- 所有 Fixture 回归；
- 故障注入；
- 跨平台 E2E；
- 数据库压力；
- 中心重连风暴；
- 大文件更新；
- Secret 泄漏检查；
- 权限测试；
- 安全审查；
- Migration 回归；
- 备份恢复演练；
- 签名构建；
- SBOM；
- 用户手册；
- 运维手册；
- 支持矩阵；
- 已知限制；
- 性能容量测试。

### 最低验证规模

作为 0.9.0 的测试目标，而不是现在宣称的实测能力：

```text
单个 Site：至少 200 个 Endpoint
单个 Center：至少 100 个 Site
中心汇总：至少 5,000 个 Endpoint
```

测试后发布真实容量建议。

### 验收

- P0/P1 缺陷清零；
- 无已知凭据泄漏；
- 无已知重复执行；
- 无已知错误成功报告；
- 三平台安装、升级、备份、恢复通过；
- Center/Site 长时间断线重连通过。

---

## 1.0.0：全功能生产交付

1.0.0 的“全功能”正式定义为：

> **对 `NvRedfishReleaseBaseline` 所有公开功能完成 100% 产品映射，并具备多服务器、单机、站点、中心、安全、任务、审计、备份、恢复和跨平台交付所需的完整支撑能力。**

发布条件：

1. 能力账本 100%；
2. 标准 feature 全覆盖；
3. OEM feature 全覆盖；
4. 所有写操作均类型化；
5. 不存在原始 BMC 写请求；
6. 不存在裸 SQL；
7. 三平台单二进制发布；
8. 五厂商标准能力验证；
9. Dell、HPE、Lenovo 上游 OEM 能力验证；
10. xFusion、Inspur 标准模式限制明确；
11. 所有异步操作可恢复；
12. 所有写操作有最终验证；
13. Center 不保存 BMC Secret；
14. Site 脱离 Center 完整运行；
15. 备份恢复通过；
16. 数据库 Migration 通过；
17. 正式签名和 SBOM；
18. 用户、运维、兼容和故障文档完成。

---

# 二十二、1.0.0 明确不包含

即使未来有价值，下面也不进入本次 1.0.0，除非成为冻结基线中的正式 `nv-redfish` 能力：

- SSH；
- WinRM；
- Agent；
- KVM；
- SOL；
- 文件传输；
- 端口转发；
- OS 管理；
- 任意脚本；
- 通用工作流；
- 配置自动整改；
- CMDB；
- 通用监控平台；
- 动态插件；
- 原始 Redfish 代理；
- 私有 OEM Adapter；
- 厂商网页抓包；
- 外部企业身份源；
- 复杂审批；
- 多租户 SaaS；
- Center 主动—主动集群；
- PostgreSQL；
- Redis；
- 消息队列；
- 多种产品 SKU；
- 精简版与完整版二进制。

---

# 二十三、五要素全量交叉审计

## 23.1 哲学统一

产品始终是：

```text
统一接入多台服务器管理卡
+
集中呈现 nv-redfish 能力
+
统一执行和追踪
```

没有扩展成：

- 数据中心全栈平台；
- 操作系统运维平台；
- 自动化编排平台；
- 厂商私有 API 集合。

**审计结果：通过。**

---

## 23.2 语义一致

关键概念保持唯一含义：

| 概念 | 唯一语义 |
|---|---|
| 产品能力 | 二进制编译进来的 `nv-redfish` 能力 |
| 设备能力 | 具体 BMC 实际暴露的能力 |
| 可用能力 | 产品、设备、权限三者的交集 |
| Endpoint | 一个 Redfish 服务入口 |
| Resource | Endpoint 下的 Redfish 资源 |
| Operation | 一次持久化产品操作 |
| Task | BMC 端异步任务 |
| Standalone | 本地 Edge 姿态 |
| Site | 长期运行的 Edge 姿态 |
| Center | 不直接连接 BMC 的集中层 |
| 单二进制 | 每个平台一个自包含可执行文件 |
| 全功能 | 冻结基线公开能力 100% 产品映射 |

**审计结果：通过。**

---

## 23.3 逻辑自洽

关键逻辑链成立：

```text
功能完全依赖 nv-redfish
→ 不允许私有 BMC HTTP
→ 不允许产品私有 OEM Adapter
→ xFusion/Inspur 只能走标准能力
→ 上游新增能力通过版本升级进入产品
```

```text
产品必须单二进制
→ 选择嵌入式 SQLite
→ 不引入外部数据库
→ Center 为单节点
→ Site 本地自治降低 Center 故障影响
```

```text
产品必须统一管理
→ 使用统一 GUI 和 Operation
→ 不强行假设各厂商能力相同
→ 使用动态 Capability 交集
```

**审计结果：通过。**

---

## 23.4 真实有效

设计明确承认：

- 未来 `nv-redfish` 功能现在无法预知；
- 因此需要 0.8.0 能力冻结；
- 当前没有 xFusion、Inspur OEM feature；
- macOS 不做虚假的绝对全静态承诺；
- SQLite Center 是单节点，不假装是集群；
- BMC Action 不一定幂等；
- HTTP 成功不等于最终设备状态成功；
- 某个资源存在不等于当前账户有权操作；
- OEM feature 存在不等于覆盖厂商全部 OEM API。

**审计结果：通过。**

---

## 23.5 完整可靠

设计已经覆盖：

```text
构建
分发
首次初始化
凭据
TLS
Endpoint 接入
资源发现
资源持久化
统一 GUI
写操作
Task
崩溃恢复
批量操作
事件
遥测
更新
OEM
站点
中心
权限
审计
备份
恢复
升级
测试
兼容认证
生产发布
```

同时覆盖：

```text
成功
失败
不支持
权限不足
Schema 不兼容
网络断开
响应丢失
结果未知
BMC 重启
产品重启
Center 断开
重复消息
部分成功
```

**审计结果：通过。**

---

# 最终冻结结论

> **本项目最终交付为一个跨 Windows、macOS、Linux 的自包含单二进制产品。一个二进制内同时包含 Standalone、Site、Center 三种运行姿态、内嵌 Web GUI、SeaORM、SQLite、全部冻结 `nv-redfish` 标准和 OEM 能力。**
>
> **服务器管理卡功能以正式 `nv-redfish` 基线为绝对边界：上游公开什么，产品完整映射什么；上游没有什么，产品不通过私有 HTTP、OEM Adapter、脚本或网页抓包自行补齐。**
>
> **产品采用统一但能力驱动的多服务器管理界面，所有厂商共用同一种接入、资源、操作、任务和审计模型，同时保留各厂商真实能力差异。**
>
> **项目实现以强类型、显式状态机、SeaORM、类型化 Redfish、Rustls、结构化并发、无裸 SQL、无原始 BMC 写请求、无外部运行时依赖为工程基线。**
>
> **0.8.0 冻结 1.0.0 的正式 `nv-redfish` 能力基线，0.9.0 完成兼容、安全、故障和跨平台认证，1.0.0 作为规划能力完整、可正式生产使用和交付的版本发布。**
