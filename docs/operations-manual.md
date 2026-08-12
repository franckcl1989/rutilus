# Rutilus 运维手册

> 本文档面向部署与维护人员，覆盖数据目录、系统服务、备份恢复、升级、诊断与容量现状。
> 所有描述均基于当前 master 的实际代码/配置事实，条目后标注来源文件。
> 产品设计基线见仓库根目录 `redfish-management-product-final-design.md`（修订冻结版）。

## 一、数据目录

### 1.1 Portable 与 Installed

| 模式 | 位置 | 用途 | 事实来源 |
|---|---|---|---|
| Portable（`--portable`） | 二进制所在目录旁的 `rutilus-data/` | 现场笔记本、便携演示 | `platform/src/runtime_paths.rs` |
| Installed（默认） | Windows：`%LOCALAPPDATA%\rutilus`；macOS：`~/Library/Application Support/rutilus`；Linux：`$XDG_DATA_HOME/rutilus` 或 `~/.local/share/rutilus` | 站点、中心长期部署 | 同上 |

站点与中心建议使用独立 OS 账户运行（§18.2）。

### 1.2 数据目录文件布局

| 文件/目录 | 内容 |
|---|---|
| `rutilus.db` | SQLite 数据库（WAL 模式，bundled SQLite 静态链接） |
| `master-key.rut` | Master Key 的口令加密信封（passphrase envelope，可跨机携带） |
| `system-master-key.rut` | Master Key 的 OS 保护信封（Windows DPAPI / macOS Keychain / Linux 受保护密钥文件，绑定本机） |
| `instance.rut` | 实例初始化完成标记 |
| `.rutilus.lock` | 运行时独占锁（同一数据目录不允许两个进程同时运行） |
| `tls/` | Site TLS 证书对（`cert.pem` / `key.pem`）；中心 CA（`center-ca.crt` / `center-ca.key`） |
| `backups/` | 默认备份输出目录：`backup-<uuid>.rut` |

事实来源：`platform/src/runtime_paths.rs`、`app/src/backup.rs`。

### 1.3 SQLite 运行规则

- WAL、外键开启、Busy Timeout、小型连接池、应用级写信号量（§9.2）；
- **禁止将数据库放在 NFS、SMB 等网络文件系统**（§9.2）；
- 每次启动执行 Migration；Migration 前自动建立可恢复备份；
- 数据库错误进入明确只读或启动失败状态，不静默重建（§9.2）。

## 二、主密钥与解锁模型

- 实例首次初始化生成 256-bit Master Key（§10.3）；
- BMC 密码用 XChaCha20-Poly1305 加密（Associated Data 绑定 CredentialId + VersionId，每份秘密独立 Nonce）；
- Master Key 不进入数据库明文。

解锁（`app/src/main.rs`、`app/src/standalone_runtime.rs`）：

| 场景 | 解锁方式 |
|---|---|
| Standalone 前台运行 | 交互输入本地解锁口令（passphrase），对应 `master-key.rut` |
| Site/Center 系统服务 | 安装服务时把 Master Key 重封装（rewrap）到 OS 保护信封（`system-master-key.rut`），服务启动无人值守解锁 |
| 备份/恢复/解绑命令 | 存在系统信封时自动使用；否则交互输入口令（`prompt_backup_unlock`） |

```text
rutilus service install 检测到实例还没有系统信封时，会提示输入本地解锁口令并完成 rewrap。
```

## 三、系统服务

同一二进制自行生成并注册服务，不分发额外 Service Wrapper（§18.3、`platform/src/service.rs`）。

### 3.1 各平台机制

| 平台 | 机制 | 注册名 | 安装即激活 | 事实来源 |
|---|---|---|---|---|
| Windows | SCM（`CreateServiceW` + `StartServiceW`） | `rutilus`（显示名 "Rutilus Site Service"） | 是，启动失败为硬错误 | `platform/src/service/windows.rs` |
| macOS | launchd LaunchAgent plist | `com.rutilus.site`（`RunAtLoad` + `KeepAlive`） | 是，`launchctl bootstrap gui/<uid>`；激活失败仅报告 | `platform/src/service.rs` |
| Linux | systemd 用户单元 | `rutilus.service`（`Type=simple`，`Restart=on-failure`，`WantedBy=default.target`） | 是，`systemctl --user enable --now`；激活失败仅报告 | 同上 |

卸载（`uninstall`）先停用后移除注册（SCM stop-then-delete、`launchctl bootout`、`systemctl --user disable --now`），
不触碰主密钥和数据目录。

### 3.2 服务安装要求

```text
rutilus service install --site --listen 0.0.0.0:8443 [--cert cert.pem --key key.pem]
rutilus service install --center --listen 0.0.0.0:8443 --center-listen 0.0.0.0:8444
```

- 服务必须是 Site 或 Center（Standalone 前台运行，不注册服务）；
- **禁止 portable 数据目录承载系统服务**；
- 需要实例已初始化（否则报 "run `rutilus init` first"）；
- 注册的命令行是"当前可执行文件 + 隐藏的 `service run` 子命令 + Site/Center 参数"，
  服务启动的仍是人类可运行的前台运行时（`platform/src/service.rs` 模块文档）；
- `--cert` 与 `--key` 必须成对提供。

## 四、运行配置

### 4.1 Site

```text
rutilus run --site --listen HOST:PORT [--cert cert.pem --key key.pem]
```

- 监听地址为 `HOST:PORT`（IPv4/IPv6 字面量或 DNS 名，`app/src/site_runtime.rs` 的 `ListenAddress`）；
- **非回环监听强制 HTTPS**（rustls，仅 TLS 1.3），无明文 HTTP 回退；启动时检查此约束（"非 HTTPS 不允许远程登录"验收）；
- TLS 材料优先级：CLI 提供对 → `tls/` 下已持久化对 → 都不存在时自动生成自签名证书（SAN 覆盖监听主机名，私钥权限 0600）；
- 启动打印监听 URL 与证书 SHA-256 指纹，供带外核对；
- 仅回环监听且无任何 TLS 材料时才以明文服务。

### 4.2 Center

```text
rutilus run --center --listen 0.0.0.0:8443 --center-listen 0.0.0.0:8444
```

- 一个实例运行两个监听器：Web 控制台（同 Site 控制台姿态）+ 专用中心协议端口（mTLS，TLS 1.3，`app/src/center_runtime.rs`）；
- 中心 CA 在首次启动时生成并持久化到 `tls/center-ca.crt` / `center-ca.key`；一个 CA 同时服务连接准入与站点证书签发；
- 启动横幅打印 §10.4 pin 材料：中心服务器证书与 CA 指纹（站点绑定操作时使用）；
- 中心是单活动实例（SQLite），可由 systemd / launchd / Windows Service 拉起；允许冷备或主机级高可用，不提供产品内部多节点集群（§15.7）；
- 中心不可用只影响集中视图和新中心操作，不影响站点已接受任务和本地管理（§15.7）。

### 4.3 遥测保留期

```text
rutilus run --telemetry-retention-days 30
rutilus service install --site --listen 0.0.0.0:8443 --telemetry-retention-days 30
```

- 本地采样循环（Standalone 与 Site）按 `now - 保留期` 计算 prune 截止，超出即删除（`app/src/telemetry_sampler.rs` 的 `TelemetryRetention`）；
- 范围 1–365 天，默认 7 天：0 天会在首个采样 tick 清空全部历史，超过 365 天违背 §14.4"有界历史"承诺（非法值在 CLI 解析时拒绝）；
- Center 没有本地采样循环，忽略该参数；
- 系统服务安装时传入的参数写入注册的命令行（`--telemetry-retention-days`），服务启动即生效（`platform/src/service.rs` 的 `ServiceArguments`）。

## 五、中心与站点运维

### 5.1 连接方向与传输

- **Site 主动连接 Center**；Center 不进入客户网络（§15.1）；
- 传输：TLS 1.3 + mTLS + WebSocket（路径 `/center/v1`）+ Protobuf 帧（帧上限 8 MiB）（`app/src/center_client.rs`、`center-protocol/src/lib.rs`）；
- 连接时交换 `Hello`/`NegotiationResult`：产品版本、`CENTER_PROTOCOL_VERSION`（当前 1）、`NV_REDFISH_BASELINE`（0.13.0）、能力账本 Hash、实例 ID；
- 没有共同协议版本时拒绝中心协同，但 Site 继续本地运行（§15.3）。

### 5.2 绑定流程

```text
中心生成一次性绑定码（20 字符 base32，100-bit 熵，仅存 SHA-256 哈希，只显示一次）
→ 站点在 "Center connection" 界面输入绑定码与中心地址
→ 中心校验后为站点签发客户端证书（身份指纹绑定进私钥扩展）
→ 站点保存绑定：中心地址 + 中心 CA（唯一信任锚）+ 操作员 pin 的中心服务器指纹 + 站点客户端证书
→ 建立连接
```

事实来源：`security/src/binding_code.rs`、`application/src/center/binding.rs`、
`app/src/center_ca.rs`、`app/src/center_client.rs`。

信任要求（§10.4、`app/src/center_client.rs`）：链必须根植于中心 CA **且** 出示的叶子必须匹配操作员 pin 的指纹，
任何证书不能替代被 pin 的证书。解除绑定：运行中站点遇到中心"未绑定"拒绝会自动撤销本地绑定并停止同步引擎；
离线运维路径为 `rutilus unbind`（同样要求实例停止并解锁）。

### 5.3 断线与恢复行为

| 参数 | 值 | 来源 |
|---|---|---|
| Site 心跳间隔 | 30 秒 | `center-protocol/src/lib.rs` `SITE_HEARTBEAT_INTERVAL` |
| 中心判定断开 | 90 秒无心跳 | `CENTER_DISCONNECT_AFTER` |
| 单次连接尝试超时 | 10 秒 | `app/src/center_client.rs` `CONNECT_TIMEOUT` |
| 重连退避 | 120 秒 | `SITE_RECONNECT_AFTER` |

- 每个站点维护持久 Outbox 序号；中心返回 Ack；重连后从最后 Ack 继续（§15.4 至少一次、幂等、单次业务效果）；
- 中心下发 Operation 使用稳定 OperationId，重复下发返回已有状态、不重复执行；
- Site 断线后：端点刷新、操作、本地 GUI 全部继续运行（`application/src/center_sync.rs` 模块文档）；
- 中心操作 Offer 有效期 15 分钟（`application/src/center/dispatch.rs` `CENTER_OFFER_TTL`），站点必须重新检查端点/能力/凭据/目标状态/过期后才会 `Accepted`（§15.6）。

## 六、备份与恢复

### 6.1 备份（`rutilus backup create`）

```text
rutilus backup create [--portable] [--output PATH]
```

- **实例必须已停止**：写门是进程本地的，CLI 无法暂停另一个进程的写入；命令通过运行时锁强制（`app/src/backup.rs`）；
- 默认输出：`backups/backup-<uuid>.rut`（数据目录下）；
- 备份内容：SQLite 一致快照（含 WAL）、Master Key 的受保护信封（**永不含明文密钥**）、实例标记、Site TLS 证书对（若存在）、制品文件（`artifact-<id>` 条目）；
- 打包用实例 Master Key 加密认证（XChaCha20-Poly1305），机密性等于主密钥的机密性，只能被自己的实例打开（实例身份绑定）；
- 流程（§20.1）：暂停写 → 等待当前写事务 → 一致快照 → 复制 → 重开 → 加密打包 → **重新打开校验**（条目数核对）后报告。

### 6.2 恢复（`rutilus backup restore`）

```text
rutilus backup restore [--portable] PATH
```

- 离线进行：**实例必须已停止**（运行时锁强制）；
- 流程（§20.2）：验证完整性 → 解密 → 检查产品版本（版本不同报 `ProductVersionMismatch`）→
  检查 Schema 兼容（备份 Schema 更新时报 `NewerSchema` 拒绝）→ 恢复数据库、密钥信封、实例标记、TLS 对、制品文件 →
  只读校验恢复后的数据库与备份快照字节一致 → 报告剩余待执行迁移数（下次启动应用）。

### 6.3 跨机器恢复（重要注意事项）

备份用实例主密钥加密，因此跨机器恢复**必须携带密钥本身**，而不只是备份包：

1. 在目标机器初始化一个实例并保持停止；
2. 把源机器的口令信封 `master-key.rut`（源数据目录下）复制覆盖到目标机器数据目录；
3. 用源信封创建时使用的口令执行 `rutilus backup restore`。

- 口令信封是可移植文件，支持跨机器、跨平台恢复（有测试证明，`app/src/backup.rs`）；
- **OS 保护信封（`system-master-key.rut`，DPAPI/Keychain）绑定创建它的机器，不能携带**；
  Site/Center 实例总是使用系统信封（§10.3），因此**不能跨机器恢复**；
- 未携带信封的朴素恢复会以密钥不匹配失败，错误信息会同时提示两种可能原因（口令错误，或备份属于另一实例）。

### 6.4 恢复后的身份注意

恢复出的 Site 与 Center 重连时必须验证实例身份，避免同一实例的备份被同时启动两次（§20.2）。

## 七、产品升级

升级流程（§20.3）：

```text
验证新二进制签名
→ 创建备份（backup create，实例停止后执行）
→ 停止旧进程
→ 替换单二进制
→ 启动新版本
→ 每次启动自动执行 SeaORM Migration（迁移前自动建立可恢复备份）
→ 恢复 Task 跟踪（扫描 WaitingRemote，重建 Session，继续读取 Task）
```

- 不实现自动后台自更新（§20.3）；
- 当前数据库 Schema 版本：23 个 Migration（`migration/src/`，2026-08-05 至 2026-08-12 的 23 个文件：`m20260805_*` 11 + `m20260807_*` 8 + `m20260810_*` 2 + `m20260812_000001_resource_decode_failures` + `m20260812_000002_resource_feature_lists`）；备份快照的已应用/支持计数由测试钉死（`persistence/src/backup_snapshot.rs:624-627`：backup_applied 24 / supported 23，备份含未来迁移时恢复拒绝）；
- Migration 只允许 DDL（`CREATE`/`ALTER`/`DROP`/`PRAGMA` 开头），数据搬迁通过 SeaQuery 表达，
  该边界由 `migration/tests/bare_sql_gate.rs` 机械检查（§7.3）；
- 升级前可用 `rutilus doctor` 确认当前实例健康。

## 八、Doctor 与诊断

```text
rutilus doctor [--portable]
```

自检项（`app/src/doctor.rs`），输出 `[OK]` / `[WARN]` / `[FAIL]` 前缀，存在任何 FAIL 时退出码非零：

| 检查项 | 说明 | FAIL/WARN 语义 |
|---|---|---|
| 数据目录 | 解析路径 | 解析失败 = FAIL |
| 实例状态 | 读取 `instance.rut` | 未初始化 = WARN（提示先 `rutilus init`） |
| 数据库文件 | 常规文件检查与大小 | 缺失/符号链接 = FAIL |
| 数据库迁移 | 已应用/待应用（**只读检查，不迁移**） | 待应用 = WARN（下次启动会迁移）；无法检查 = FAIL |
| 主密钥 | 系统信封有效，或口令信封可恢复 | 信封不可恢复 = FAIL |
| 系统服务 | 平台服务管理器注册状态 | 未安装 = WARN（前台运行不受影响） |
| TLS 证书 | `tls/cert.pem` 存在则打印 SHA-256 指纹 | 未配置 = WARN（回环控制台无 TLS 运行）；无法解析 = FAIL |

### 8.1 日志与诊断现状（如实）

- **统一日志设施已引入**：设计文档 §6.2 选型清单中的 `tracing` + `tracing-subscriber` 已进入
  workspace（根 `Cargo.toml` 的 `[workspace.dependencies]`）；app 二进制在启动时经 `init_tracing`
  初始化 stderr subscriber（`app/src/main.rs:255-273`）；
- **输出格式可选**：全局 `--log-format <text|json>`（默认 `text`；`Cli.log_format` 字段
  `main.rs:53`、`LogFormat` 枚举 `main.rs:58-64`）——`text` 为人类可读行，`json` 为每行一条
  newline-delimited 结构化 JSON 记录；
  两种格式都输出到 stderr，过滤级别都来自 `RUST_LOG`（未设置或非法时默认 `info`，例如
  `RUST_LOG=debug rutilus run --log-format json`），**`RUST_LOG` 过滤行为不变**；CLI 解析失败时
  `--log-format` 在命令运行前被拒绝（`app/tests/log_format.rs`）；
- **运行路径已接入 span 上下文**：`#[instrument]` 覆盖 main 命令入口、backup、center_client、
  center_runtime、event_listener、scheduler、site_runtime、standalone_runtime、telemetry_sampler
  的入口函数（口令等敏感参数一律 `skip_all` 不进入 span 字段，`app/src/center_client.rs:162, 179`
  等）；JSON 格式下 span 字段（如 `command`、`data_directory`、`endpoint_id`）随记录输出，便于
  按请求/端点聚合排查；
- 运行中的操作性失败现经 `tracing::error!` / `tracing::warn!` 记录（事件监听器、遥测采样循环、调度循环、
  中心同步引擎、服务激活命令失败等，见 `app/src/event_listener.rs`、`app/src/telemetry_sampler.rs`、
  `application/src/center_sync.rs`、`platform/src/service.rs`）；
- **CLI 用户可见输出仍走 stdout `println!`**（init 向导、backup 结果、doctor 报告、console 横幅、
  bootstrap code 显示），与 stderr 诊断分离（§7.6 用户信息与诊断信息分离）——`--log-format json`
  只影响 stderr 诊断，stdout 用户可见输出字节不变（`app/tests/log_format.rs` 断言）；
- 测试基础设施与测试内诊断（`test-support` mock、`mock-bmc` 工具、`infra-redfish` 测试）仍用
  `eprintln!`/`println!`（测试上下文无 subscriber）；
- 因此生产排查目前依赖：stderr 诊断日志（`RUST_LOG` 可调级别、`--log-format json` 结构化输出）、
  审计记录（界面 Audit 视图）、端点级 Advanced Diagnostics 与 Capabilities 页面。

## 九、性能与容量现状（如实）

设计文档 §0.9.0 的"最低验证规模"（单 Site 200 Endpoint / 单 Center 100 Site / 中心汇总
5,000 Endpoint）已由合成规模压力套件落地并实测（`persistence/tests/stress_capacity.rs`，
2026-08-12）。**下面的数字是本机（Windows 开发机）debug 构建 + WAL 下的合成数据，不是最终发布
容量建议**——设计 §0.9.0 要求"测试后发布真实容量建议"（`redfish-management-product-final-design.md:2810`），
正式容量建议需在 release 构建与正式规模环境复核后发布。

**合成规模实测数据（2026-08-12，开发机 debug 构建、WAL）**

压力套件 3 个测试全部断言正确性不变量（行数、设计 §9.5 Generation 一致、§17 队列与游标有序、
§15.4 at-least-once 重投 no-op），**不断言任何墙钟时间**（CI 方差不是测试输入，
`stress_capacity.rs:11-12`）；`println!` 计时即设计要求发布的实测容量证据（`:10`）。本机复跑结果：

| 规模场景 | 实测耗时 | 折算吞吐 | 计时点 |
|---|---|---|---|
| 5,000 Endpoint 投影首次写入（100 Site x 50） | 5.78s | ≈865 行/s | `stress_capacity.rs:865` |
| 5,000 Endpoint 投影幂等重投（at-least-once） | 9.72s | ≈515 行/s（更新路径） | `stress_capacity.rs:924` |
| 5,000 行投影清单查询（含 100 个 per-site 视图） | 0.482s | ≈10,400 行/s | `stress_capacity.rs:906` |
| 200 Endpoint 首轮 Generation 提交（7 snapshot/Endpoint） | 0.30s | — | `stress_capacity.rs:441` |
| 200 Endpoint 二轮 Generation 提交 + 当前视图重载 | 0.32s | — | `stress_capacity.rs:491` |
| 100 Site 建库 + 1,000 outbox 入队 | 0.01s / 0.53s | — | `stress_capacity.rs:602, 626` |
| 500 outbox Ack（含重复 Ack no-op） | 0.141s | — | `stress_capacity.rs:652` |
| 400 inbox 幂等生命周期（100 Site x 4） | 0.31s | — | `stress_capacity.rs:760` |
| 800 sync cursor 推进（100 Site x 4 流 x 2） | 0.28s | — | `stress_capacity.rs:795` |

**关键观察（发布容量建议时最有价值的记录）**：persistence 的写路径被 `write_gate`
（`Semaphore(1)` 全局应用级写信号量，`persistence/src/lib.rs:101, 240`）串行化——同一时刻全库
只有一个写事务。因此 5,000 规模的写耗时 ≈ **事务数 × 单事务成本**，与并发数无关；扩容方向是
减少事务数（批量合并）或放宽串行化（需先评估设计 §9.2 的写门语义与备份一致性依赖），而不是堆并发。

当前代码中可确认的规模相关事实：

| 项 | 值 | 来源 |
|---|---|---|
| 批量操作目标上限 | 128 | `operation-engine/src/operation_engine.rs` `MAX_BATCH_TARGETS` |
| 批量刷新目标上限 / 并发 | 128 / 4 | `application/src/batch_refresh.rs` |
| 同一端点写操作并发 | 1（串行） | §13.7、`operation-engine` |
| 事件/审计/遥测单次查询上限 | 1000 | `web/src/lib.rs` |
| 遥测采样周期 / 保留 | 60 秒 / 默认 7 天（`--telemetry-retention-days` 可配置，1–365 天） | `app/src/telemetry_sampler.rs`；`app/src/main.rs` |
| 制品分块上限 | 4 MiB（base64） | `application/src/artifact_store.rs` |
| CSV 导入上限 | 1 MiB / 10,000 行 | `application/src/endpoint_csv.rs` |
| 中心协议帧上限 | 8 MiB | `center-protocol/src/lib.rs` |
| 中心操作 Offer 有效期 | 15 分钟 | `application/src/center/dispatch.rs` |
| 事件流重连预算 | 1s 起指数退避至 60s，10 次失败后标记失败 | `app/src/event_listener.rs` |

数据库为 SQLite + WAL（§9.1），1.0.0 Center 是单节点生产中心，不是主动—主动集群；中心失效不影响站点执行。
目标规模以几台、十几台到中等规模服务器为主。

## 十、CI 与发布门禁现状

CI 门禁与 §19.4 的对照（`.github/workflows/ci.yml`）：

| 门禁 | 现状 |
|---|---|
| fmt / clippy（`-D warnings`）/ 全 workspace 测试 | 已启用（ubuntu-latest 默认 job；windows/macos 跑全目标编译 + 跨平台 E2E 套件） |
| 跨平台 E2E 套件（windows/macos） | 已启用：`cargo test --locked -p rutilus-web`（9 个路径套件，内存假件）+ `cargo test --locked -p rutilus --test version`（`ci.yml:130-147`）；`app/tests/mock_center_client.rs`（回环 mTLS/WebSocket 互操作）因真实 socket 与握手时序不纳入（`ci.yml:139-141` 注释） |
| nextest（`--test-threads 4`）/ llvm-cov（行覆盖 ≥ 80%，本地实测 90.14%，2026-08-12） | 已启用 |
| cargo deny（advisories/bans/licenses/sources） | 已启用（版本 0.20.2） |
| cargo audit 独立门禁 | **已启用**（2026-08-12，`ci.yml:197-205`）：`cargo audit --deny warnings`，`--ignore` 镜像 deny.toml `[advisories]` 全部 4 条（quick-xml 0194/0195 两条 TRIGGER、unmaintained 0436/0173）+ 重新登记的 rkyv RUSTSEC-2026-0235（deny.toml 注释预言 cargo-audit 启用时会重新登记，`deny.toml:21-24`）；cargo-audit 只读 audit.toml、不读 deny.toml，故以 CLI 旗标镜像，需与 deny.toml 同步维护（`ci.yml:187-196` 注释） |
| Secret 泄漏扫描门禁 | **已启用**（2026-08-12，E3b）：`security/tests/secret_leak_gate.rs`——3 规则（R1 硬编码秘密 / R2 内嵌私钥 PEM 块 / R3 明文输出宏泄露）、8 测试、`ALLOWED_CONSTANT_HITS` 白名单 2 处（path+line+name+literal 绑定，`app/src/backup.rs:83, 84`）、`test-support` crate 目录级豁免（fixture scope，E3b 原始提交 eefde7e，`secret_leak_gate.rs:55-59, 1000-1002`；深度审查批次 e8424df 另补 `strings_catalog!` 宏体结构豁免——CATALOG_MACRO 帧识别 + 新测试 `strings_catalog_macro_bodies_are_copy_construction_not_secret_assignments` `:1195`）；**CI 独立步骤**（`ci.yml:225-227` Secret leak gate：`cargo test --locked -p rutilus-security --test secret_leak_gate`，`if: matrix.is_default`，machete 之后、wasm32 之前，header 注记 `ci.yml:15-17`） |
| cargo machete | 已启用（3 处误报均在忽略清单中注明） |
| 跨平台构建与发布矩阵 | CI 编译 `x86_64-unknown-linux-gnu`、`x86_64-pc-windows-msvc`、`x86_64-apple-darwin` + `wasm32-unknown-unknown` UI 产物并 diff 校验（ubuntu 默认 job）；发布构建：x86_64 musl（`ci.yml:253-259`）与 aarch64 musl（cargo-zigbuild 交叉链接，`ci.yml:266-270`）在 ubuntu 任务构建，macOS Universal 2 由 macos 任务构建两个 darwin 目标并经 lipo 合并（`ci.yml:289-304`）；**`aarch64-pc-windows-msvc` 明确不入 CI**——hosted x64 Windows runner 无法提供 ARM64 MSVC 链接器与 SDK 导入库，注释注明需原生 ARM64 runner 或本地验证后处理（`ci.yml:272-279`） |
| Migration / 能力账本 / 发布基线检查 | 已启用 |

发布目标矩阵（§5.2）为 Linux `x86_64-unknown-linux-musl` / `aarch64-unknown-linux-musl`、
Windows `x86_64-pc-windows-msvc` / `aarch64-pc-windows-msvc`、macOS Universal 2（Intel + Apple Silicon）；
`deny.toml` 的 `[graph] targets` 已列出全部发布目标。CI 现状（2026-08-12）：musl x86_64/aarch64 与
macOS Universal 2 的构建步骤均已入 CI（见上表），Linux 门禁本身仍跑 gnu 目标；Windows ARM64 构建
未入 CI（真实原因见上表注释引用）。
