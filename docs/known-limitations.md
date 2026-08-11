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
| Telemetry | `CommandFamilyView::ALL` 刻意不含 Telemetry；表单选择器返回 `OperationFormError::FamilyRequired`；界面提示 "The telemetry write form is a later milestone."；已持久化的遥测命令通过 `wire_command_summary` 在卡片中渲染 | `ui/src/lib.rs` 第 4748、6010 行附近 |
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
- 注释注明：若后续启用 cargo-audit 独立门禁，需要重新登记该条目。

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

## 六、容量与性能未实测

- 设计 §0.9.0 的"最低验证规模"（单 Site 200 Endpoint、单 Center 100 Site、中心汇总
  5,000 Endpoint）是**测试目标，不是已实测能力**；当前没有已发布的容量建议；
- 中心为单节点 SQLite 生产中心，非主动—主动集群（§9.1、§15.7）——这是有意设计，不是缺陷；
- 已知的产品侧规模约束（非容量测试结果）：批量操作/批量刷新目标上限 128、刷新并发 4、
  单次查询上限 1000、制品分块 4 MiB、CSV 导入 1 MiB / 10,000 行、中心协议帧 8 MiB。

## 七、其他现状限制（如实）

| 限制 | 说明 | 事实来源 |
|---|---|---|
| 遥测保留期不可配置 | 7 天是产品常量（`TELEMETRY_RETENTION`）；"历史保留周期可配置"（§14.4）尚未实现为设置项，代码注释明确是 later iteration | `app/src/telemetry_sampler.rs` |
| 事件监听器失败后不自动恢复 | 连续 10 次重连失败（预算约 4 分钟）后端点监听器标记 Failed 并退出；周期性重新拉起是 later iteration | `app/src/event_listener.rs` |
| 事件监听按启动扫描拉起 | 启动时枚举全部端点拉起 SSE 监听；登记端点时懒启动是 later iteration | 同上 |
| 无统一日志设施 | 设计 §6.2 的 `tracing` 未进入 workspace；运行失败经 stderr（`eprintln!`）记录；统一日志设施为后续迭代 | 根 `Cargo.toml`；`app/src/event_listener.rs` 注释 |
| `cargo audit` 独立门禁未启用 | advisory 扫描已由 `cargo deny check` 覆盖；独立 audit 门禁为后续工作 | `.github/workflows/ci.yml` 注释 |
| CI 与发布目标差异 | CI 当前编译验证 linux-gnu / windows-msvc / darwin（x86_64）+ wasm32；musl、aarch64、ARM64、macOS Universal 2 合并构建尚未在 CI 验证 | `.github/workflows/ci.yml`；`deny.toml` |
| 产品版本号 | crates.io workspace 版本仍为 `0.1.0`（`rutilus version` 输出），里程碑编号（0.1.0→0.8.0）独立于版本号；发布前需要统一版本策略 | 根 `Cargo.toml` |
| macOS 非绝对静态链接 | macOS 上只承诺单文件、无随包动态库、仅系统框架（不做"绝对零动态依赖"承诺，§5.3） | 设计文档 §5.3 |
| 界面文案为英文 | UI 标签为静态英文（"Overview"、"Groups" 等）；界面本地化不在当前实现中 | `ui/src/lib.rs` `label()` |
| HTTP 成功不等于业务成功 | 200/201/202/204 不直接等于业务成功，写操作后必须重新读取验证；响应丢失时非幂等操作标记 Unknown 而不盲重试（§13.5） | `operation-engine`；设计文档 §13 |
| 登录限速窗口固定 | 每用户名 5 次 / 每地址 20 次失败、15 分钟窗口，为代码内常量 | `web/src/auth.rs` |
| 事件流重连预算有限 | 超出预算的长期不可达端点以 Failed 呈现而非无限重试（有意设计，见上） | `app/src/event_listener.rs` |
| Center 角色站点作用域 | 中心角色可限定到某些 Site，但用户与会话管理仅 Administrator（有意设计） | `web/src/auth.rs` |
| 审计只追加 | 审计记录不通过正常 ORM Repository 更新或删除（§16.3） | `domain/src/audit.rs` |

## 八、与设计文档的已知偏差（实现状态，如实）

| 设计项 | 现状 |
|---|---|
| §19.1 Fixture 测试（真实响应 fixture 目录） | 尚未建立 |
| §19.1 Physical Device Test（五厂商真实设备认证矩阵） | 尚未达成 |
| §0.9.0 性能容量测试与真实容量建议 | 尚未执行/发布 |
| §6.2 tracing 日志选型 | 尚未引入 workspace |
| §14.4 遥测保留周期可配置 | 尚未实现（产品常量） |
| §12.4 诊断中的解码错误路径 / ExtendedInfo 展示 | 解码失败的成员在刷新时跳过、不留下记录，诊断视图不显示（`application/src/resource_diagnostics.rs`）——与 §12.4"允许查看解码错误路径"的设计表述存在实现差异，属 0.9.0 待办 |

> 以上偏差均为当前 master 的真实状态；对应设计条款见仓库根目录
> `redfish-management-product-final-design.md`。
