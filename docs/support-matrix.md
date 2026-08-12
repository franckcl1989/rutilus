# Rutilus 支持矩阵

> 本文档基于当前 master 的真实事实（上游基线记录、workspace 清单、代码实现），
> 不写设计文档里没有且代码不支持的内容。所有条目后标注来源文件。

## 一、上游基线事实（nv-redfish）

### 1.1 版本记录

| 项 | 值 | 事实来源 |
|---|---|---|
| 冻结的发布基线版本（`NvRedfishReleaseBaseline`） | `0.13.0` | `infra-redfish/src/release_baseline.rs` |
| 发布日期 | 2026-08-04 | 设计文档 §2.1（基线记录注释） |
| 已知更新正式版本 | `0.14.2`（2026-08-10 发布，未 yank） | 同上 `NV_REDFISH_KNOWN_NEWER_STABLE_VERSION` |
| 冻结策略 | 0.8.0 冻结选择当时最新且已验证的稳定版本；0.9.0 至 1.0.0 只允许安全修复、严重 Bug 修复、不增加产品能力面的兼容更新（§2.3） | 设计文档 §2.3 |
| workspace 固定方式 | `nv-redfish = "=0.13.0"`（精确版本），`default-features = false` | 根 `Cargo.toml` |
| Schema 层版本 | `nv-redfish-schema` / `nv-redfish-core` / `nv-redfish-bmc-http` / `nv-redfish-csdl-compiler` 均为 0.13.0（测试对 Cargo.lock 逐项校验） | `infra-redfish/src/release_baseline.rs` |

### 1.2 Feature 面

显式启用的 17 个 feature（根 `Cargo.toml` 16 个 + `infra-redfish/Cargo.toml` 追加的
`update-service-deprecated`，由门禁测试双向校验）：

```text
bmc-http  std-redfish  oem-ami  oem-dell  oem-dell-attributes  oem-delta  oem-hpe
oem-lenovo  oem-liteon  oem-nvidia  oem-nvidia-cper  oem-nvidia-fabrics
oem-nvidia-power-management  oem-nvidia-profiles  oem-nvidia-security
oem-supermicro  update-service-deprecated
```

启用后完整编译面共 58 个 feature（0.13.0 feature 全集 59 个中仅 `default` 未编译）：
`std-redfish` 展开为 30 个服务 feature（含 0.13.0 新增的 `ports`；`environment-metrics` 由
`controls`/`sensors` 传递启用，不是独立成员），`oem-*` 链启用 `oem`，服务 feature 启用
`patch`/`impl-entity-link`/`impl-nv-bmc-expand`/`resource-status`/`environment-metrics` 等辅助面。
完整列表见 `infra-redfish/src/release_baseline.rs` 的 `RELEASE_BASELINE_ENABLED_FEATURES`。

### 1.3 模块面与操作面

- 公开模块 29 个，全部带产品分类（19 个能力映射、8 个基础设施、2 个内部；0 个遗留兼容模块）；
- 公开类型化写操作 43 个，全部有产品映射：映射 31、编译 CSDL 面 6、基础设施 2、内部 1、明确不提供 3
  （`OutOfScope`，见 `docs/known-limitations.md`）；**未映射操作 = 0**（0.8.0 验收达成）；
- 能力账本：47 条（33 标准 + 14 OEM），有冻结的账本哈希快照（`RELEASE_BASELINE_LEDGER_HASH`，
  与中心协商 golden 一致）。

事实来源：`infra-redfish/src/release_baseline.rs`（模块与操作清单由门禁测试对照 vendored
`nv-redfish-0.13.0/src/lib.rs` 与 workspace 清单逐项校验）。

## 二、标准能力映射（§3.1）

| 产品功能域 | `nv-redfish` feature | 产品呈现位置（`domain/src/capability.rs` 的 `UiLocation`） |
|---|---|---|
| 服务与连接 | `bmc-http`、`session-service` | Infrastructure（数据页之外） |
| 计算系统 | `computer-systems` | Systems |
| 管理控制器 | `managers`、`manager-network-protocol` | Managers |
| 机箱 | `chassis`、`assembly` | Chassis / Assembly |
| 处理器与内存 | `processors`、`memory` | Processors / Memory |
| PCIe 与网络 | `pcie-devices`、`network-adapters`、`network-device-functions`、`ethernet-interfaces`、`host-interfaces`、`ports` | Pcie / Network |
| 电源与环境 | `power`、`power-equipment`、`power-supplies`、`controls`、`environment-metrics`、`sensors`、`thermal` | Power / Thermal / Sensors |
| 配置 | `bios`、`boot-options`、`secure-boot` | BIOS / Boot / Secure Boot |
| 账户 | `accounts` | Accounts |
| 存储 | `storages` | Storage |
| 日志 | `log-services` | Logs |
| 事件 | `event-service` | Events |
| 遥测 | `telemetry-service` | Telemetry |
| 任务 | `task-service` | Tasks |
| 更新 | `update-service`、`update-service-deprecated`（legacy HttpPushUri） | Update |
| OEM | 全部 14 个 `oem-*` | OEM（单页，按厂商命名空间分区块） |

"公开操作"统一指：`nv-redfish` 基线提供了类型化操作，并且目标 BMC 实际暴露、当前账户也有权限执行（§3.1）。

## 三、平台矩阵（§5.2，发布目标）

| 平台 | 架构 | 构建目标 |
|---|---|---|
| Linux | x86_64 | `x86_64-unknown-linux-musl` |
| Linux | ARM64 | `aarch64-unknown-linux-musl` |
| Windows | x86_64 | `x86_64-pc-windows-msvc` |
| Windows | ARM64 | `aarch64-pc-windows-msvc` |
| macOS | Intel + Apple Silicon | Universal 2（两个 Darwin 构建合并） |

事实来源：设计文档 §5.2（目标矩阵）、`deny.toml` `[graph] targets`（6 个目标 + `wasm32-unknown-unknown`）。
发布构建配置（§5.4）：`opt-level 3`、`lto = "fat"`、`codegen-units 1`、`panic = "abort"`、
`strip = "symbols"`（根 `Cargo.toml` `[profile.release]` 完全一致）。

静态链接的真实边界（§5.3，如实）：Linux musl 静态链接且不依赖目标机 glibc 版本；Windows MSVC CRT
使用 `crt-static`、不分发 VC Runtime、仍使用系统 DLL；macOS 不做"绝对零动态依赖"承诺，
保证单一可执行文件、不分发自有 `.dylib`、仅使用系统框架。正式交付术语为
"Self-contained single executable，无第三方运行时和随包动态库依赖"。

CI 现状（`.github/workflows/ci.yml`，2026-08-12）：编译矩阵验证 `x86_64-unknown-linux-gnu`、
`x86_64-pc-windows-msvc`、`x86_64-apple-darwin` 三平台 + wasm32 UI 产物 diff，windows/macos
任务另运行跨平台 E2E 套件（`web/tests` 9 个路径文件与 `app/tests/version.rs`）。发布构建矩阵：
x86_64 musl（commit 3b1ab30 起）与 aarch64 musl（cargo-zigbuild）在 ubuntu 任务构建，macOS
Universal 2 由 macos 任务 lipo 合并两个 Darwin 构建；`aarch64-pc-windows-msvc` 尚未入 CI
（GitHub hosted x64 Windows runner 不提供 ARM64 MSVC 链接工具链，见 ci.yml 注释，如实标注）。

## 四、厂商支持现状

### 4.1 通用原则

- **标准 Redfish：所有厂商通用**。任何实现标准 Redfish 服务（Service Root、System、Chassis、
  Manager、Session、Task 及基线支持的标准资源）的设备都可以接入；
- **统一产品形态不是最低公共能力集合**（§3.2）：产品完整编译能力 ∩ 当前 BMC 实际暴露能力 ∩
  当前凭据实际权限 = 该管理端点当前可用功能。Dell 设备可以显示 Dell OEM 数据，HPE 显示 HPE OEM 数据，
  某台旧设备只暴露部分标准资源时页面只显示相应部分；
- 不支持不会被视为错误，也不会被伪造为支持。

### 4.2 OEM 厂商读取面现状

所有 OEM 读取都通过 `nv-redfish` 的强类型生成类型完成（`infra-redfish/src/redfish_gateway.rs`），
不存在产品私有 OEM 请求。`nv-redfish` 0.13.0 各 OEM feature 的实际读取面：

| 厂商 | feature | 读取面（代码事实） | 写面 |
|---|---|---|---|
| AMI | `oem-ami` | Service Root 的 `Oem.Ami` 段、Manager 的 `Oem.Ami` 段（含 Redfish Technology Pack 信息） | 无类型化写操作（0.13.0 只读导航） |
| Dell | `oem-dell`、`oem-dell-attributes` | `Dell` 命名空间；`DellAttributes` 资源 | 无类型化写操作 |
| HPE | `oem-hpe` | Service Root `Oem.Hpe` 段、Manager 的 `Oem.Hpe`（`HpeiLo`、`HpeiLoServiceExt`） | 无类型化写操作 |
| Lenovo | `oem-lenovo` | Manager `Oem.Lenovo`（`LenovoManagerSchema`）、Security Service、Resource | 无类型化写操作 |
| Supermicro | `oem-supermicro` | `Supermicro` 命名空间 | 无类型化写操作 |
| NVIDIA | `oem-nvidia` + 5 个子 feature | 大面积：NvidiaManager v1_9_0、ComputerSystem、Chassis、ManagedEntity(Group)、PowerDomain、PowerPolicy、PowerSmoothing、PowerStateGroup、PSC、PSU(State/Redundancy)、SystemConfigProfile、DebugToken(Management)、PowerComplianceManager 等 | **9 个类型化 action**（见下） |
| LiteOn | `oem-liteon` | 电源供应单元面（`LiteonPowerSupply` 等）；**不按命名空间广告**，按机箱 Manufacturer 硬件 ID "LITE-ON TECHNOLOGY CORP." 信号启用（`domain/src/capability.rs`） | 无类型化写操作 |
| Delta | `oem-delta` | 电源供应单元面（`deltaenergysystems` 命名空间） | 无类型化写操作 |

NVIDIA 类型化写操作（9 个，全部映射到 `RedfishCommand::Oem`；`infra-redfish/src/release_baseline.rs`）：

| 操作码 | 上游面 |
|---|---|
| `oem-nvidia.profile-update` / `profile-factory-reset` / `profile-activate` | NvidiaSystemConfigProfile#Update / FactoryReset、NvidiaSystemProfile#Activate（CSDL action） |
| `oem-nvidia.debug-token-generate` / `install` / `disable` / `erase` | NvidiaDebugToken(Management)#GenerateToken / InstallToken / DisableToken / EraseToken |
| `oem-nvidia.power-smoothing.activate-preset-profile` / `apply-admin-overrides` | NvidiaPowerSmoothing#ActivatePresetProfile / ApplyAdminOverrides |

> 注意：OEM feature 存在不等于覆盖厂商全部 OEM API（§23.4 审计项）。Dell、HPE、Lenovo 只验证
> 标准 feature 与上游已有 OEM feature，不声称覆盖其全部 OEM API（§19.2）。

### 4.3 超聚变（xFusion）与浪潮（Inspur）

- **当前 `nv-redfish` 没有 xFusion OEM 与 Inspur OEM feature**（§2.1），
  因此这两家在本产品中只能使用它们实际实现、且 `nv-redfish` 已覆盖的**标准 Redfish 能力**；
- OEM-only 功能明确标为 `NotAvailableInNvRedfishBaseline`，不会误显示其他厂商的功能；
- 验证范围（§19.2）：Service Root、Systems、Chassis、Managers、Session、Task、当前基线支持的标准资源；
- 测试支持中有 `XFusion` 与 `Inspur` 厂商 profile 的 mock BMC 变体（只改身份字符串、无任何 OEM
  表面，`test-support/src/lib.rs`），用于验证标准模式行为。

### 4.4 测试与验证状态（如实）

| 手段 | 现状 |
|---|---|
| Mock BMC（`test-support`） | 可运行的 loopback HTTPS Mock Redfish BMC，固定确定性证书与固定资源树；profile：默认 Rutilus、Dell（DellAttributes 表面）、XFusion、Inspur |
| Mock Center | scripted mTLS 中心（Hello/NegotiationResult、二进制帧 WebSocket），驱动真实 CenterClient 互操作测试 |
| Fixture | 设计 §19.1 要求保存脱敏真实 BMC 响应（Dell/HPE/Lenovo/xFusion/Inspur 各固件版本）并随上游升级回归；**当前代码库中尚无 fixture 目录**（如实标注，属于 0.9.0 内容） |
| 真实设备验证 | 设计目标为五个厂商至少各一台真实设备进入 1.0.0 认证矩阵（§19.1）；**尚未达成**，属于 0.9.0 实验室工作 |
| 进程级故障注入演练 | `scripts/drills/` 7 脚本 + RESULTS.md（2026-08-12 落地），Windows 本机形态（mock-bmc + delay relay，无物理设备/外部证书依赖）：§19.3 剩余 4 项覆盖 3 项（产品进程在任务中被终止 / BMC 更新中重启 / SQLite 写入中断；**磁盘空间不足未覆盖**）+ §20.1/§20.2 备份恢复 + §0.4.0 大文件中断；**首轮实跑 6/6 SKIP**（2026-08-12，执行上下文 ConPTY 不可用，非产品问题；挂起防护修复后快速 FAIL 路径已验证），**功能验证待真实交互控制台会话复跑**；Linux/macOS 等价脚本未编写 |

## 五、明确不承诺项

### 5.1 设备能力（§3.3）

以下内容不在正式范围，除非在 0.8.0 能力冻结前进入正式 `nv-redfish`：

- `VirtualMedia`；
- `CertificateService`；
- `LicenseService`；
- 厂商私有 Job Service；
- 超聚变 OEM Action；
- 浪潮 OEM Action；
- 任意厂商私有配置导入导出；
- 厂商网页内部接口。

边界：**上游没有，产品就没有。**

### 5.2 产品范围（§22，1.0.0 明确不包含）

SSH、WinRM、Agent、KVM、SOL、文件传输、端口转发、OS 管理、任意脚本、通用工作流、
配置自动整改、CMDB、通用监控平台、动态插件、原始 Redfish 代理、私有 OEM Adapter、
厂商网页抓包、外部企业身份源（LDAP/OIDC/SAML/RADIUS）、复杂审批、多租户 SaaS、
Center 主动—主动集群、PostgreSQL、Redis、消息队列、多种产品 SKU、精简版与完整版二进制。

### 5.3 操作面（OutOfScope，3 项）

`system.set-boot-order`、`update.simple`、`update.start` 三项上游公开操作被明确记录为不提供，
理由见 `docs/known-limitations.md` §一。

## 六、会话与认证方式

| 项 | 支持 |
|---|---|
| 设备认证 | SessionService + X-Auth-Token 优先；设备不支持时 Basic（记录为端点能力状态，§11.2） |
| TLS 信任 | 系统 CA 或管理员显式 Pin 证书指纹；禁止全局 `accept_invalid_certs`；证书变化进入 `TlsIdentityChanged`（§10.4） |
| 产品账户 | 内置账户（Administrator / Operator / Viewer），Argon2id，可选 TOTP；无外部身份源（§16.1/§16.2） |
| 中心协议 | 站点主动连接；TLS 1.3 + mTLS + WebSocket + Protobuf；`CENTER_PROTOCOL_VERSION` = 1（`center-protocol/src/lib.rs`） |
