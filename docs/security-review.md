# Rutilus 安全审查记录（0.9.0「安全审查」启动项）

> 本文档是 0.9.0「安全审查」（设计文档 §0.9.0 内容「安全审查」，milestone-status §7.2-A
> 「安全审查（启动）：基于现有代码的审查与记录（流程启动项）」）的启动交付物：
> 基于当前 master（commit c4168c5）的**代码级自查记录**；审查后 master 已推进至 edead80
> （迭代二，MINOR-1 已修复并转登记，见 §三 M1 行与 §四），并继续推进至 bfb001e（迭代三+四：
> N5 已关闭（E3c 编译期 const assert）、Secret 泄漏扫描门禁已落地（E3b）、§12.4 生产捕获点
> 已合入（E1）、约束修复已合入（E4），见 §三 N5 行与 §四 4.3），再推进至 a4950fc（深度审查
> 批次 2026-08-12：M1 残留面已证反并关闭（B4）、B1-B3 已修复（commit 8147bc9），见 §三
> B1-B4 行与 §四）。
>
> 审查方法：只读代码，逐项对照设计文档安全条款给出结论 + 「证据 file:line」；
> 所有行号均在本轮审查中打开文件核实，不凭记忆转述。测试代码（`#[cfg(test)]`）不在
> 生产扫描范围（§7.7 扫描注明）。不确定的判断标注「审查推断」。
>
> 状态标记：✅ 结构有证据（代码实现 + 测试钉死）；🟡 部分（结构有证据但演练/评估未做）；
> ⏳ 待做（无代码证据）。本文档不修改任何代码，只做记录。

## 一、审查基准与范围

审查基准条款（设计文档 `redfish-management-product-final-design.md`）：

| 条款 | 内容 | 位置 |
|---|---|---|
| §6.2 选型 | Argon2id / XChaCha20-Poly1305 / secrecy+zeroize / rustls | `redfish-management-product-final-design.md:708-710, 697` |
| §7.6 错误处理 | 用户信息与诊断信息分离、错误非字符串化 | `:906-934` |
| §7.7 Panic 与 Unsafe | 生产禁 unwrap/expect/todo!/unimplemented!/主动 panic；`#![forbid(unsafe_code)]` | `:938-962` |
| §7.8 异步与并发 | 有界 Channel、取消令牌、端点限并发、写串行、Semaphore | `:965-976` |
| §10 秘密与凭据 | 256-bit Master Key、XChaCha20-Poly1305、AD 绑定 CredentialId+VersionId、独立 Nonce、Secret 包装、无 Debug 明文、日志脱敏、Master Key 不入库明文 | `:1267-1341` |
| §10.4 TLS 信任 | 先取证书后交凭据、管理员显式 Pin、禁全局 accept_invalid_certs、证书变化进 TlsIdentityChanged | `:1344-1373` |
| §11.2 Session 策略 | SessionService+X-Auth-Token 优先、Basic 兜底记能力状态、Token 只存内存/不入备份/不传 Center/重启重建/删除时清理 | `:1405-1427` |
| §15 中心链路 | Site 主动连 Center、TLS 1.3 + mTLS + WebSocket + Protobuf、Center 不保存 BMC 密码/Token/Master Key/解锁秘密/原始私钥、at-least-once 幂等 | `:1925-2079` |
| §16.2 登录安全 | Argon2id、无默认密码、一次性 Bootstrap Code、管理员首登设密码、可选 TOTP、非回环强制 HTTPS、Cookie Secure/HttpOnly/SameSite、CSRF、登录限速、密码/角色变化撤销旧 Session | `:2144-2157` |
| §16.3 审计 | 谁/来源/目标/参数摘要/权限/操作类型/开始进度结果/错误/验证结果；秘密永不进入审计；只追加 | `:2161-2177` |

审查范围（8 项 + 第 9 项扫描）：

1. 凭据与秘密 at-rest 加密与内存保护；
2. 认证与会话（Argon2id / Bootstrap / TOTP / Cookie / CSRF / 限速 / 撤销）；
3. TLS（rustls 全栈、无 accept_invalid_certs、Pin 流程、自签证书与 key-match）；
4. 中心链路（mTLS、Center 不保存 BMC 秘密、幂等、Site 本地解密边界）；
5. 注入与边界（裸 SQL 门禁、无原始 BMC 写请求、CSV 导入注入面、上传路径穿越面）；
6. 审计完整性（只追加、秘密构造上不可进审计、覆盖范围）；
7. 备份恢复（加密信封、Master Key 受保护包装、跨机恢复、异实例拒绝）；
8. 并发与 DoS 面（限速、写 Semaphore、分块上限、帧上限、端点并发限制）；
9. 生产代码 unwrap/expect/panic!/todo!/unimplemented! 扫描。

## 二、逐项结论表

| # | 范围 | 结论 | 证据（file:line） | 风险登记 |
|---|---|---|---|---|
| 1 | 凭据与秘密 at-rest | ✅ | BMC 密码 XChaCha20-Poly1305 加密、24 字节随机 Nonce、AD 绑定 CredentialId+VersionId：`security/src/lib.rs:184-207`（encrypt_credential）、`:246-251`（associated_data = credential_id‖version_id 32 字节）、`:190-191`（getrandom 独立 Nonce）；只存密文列：`persistence/src/credential_repository.rs:121`（encrypted_secret）；Debug 脱敏：`security/src/lib.rs:94-102, 166-175`、`security/src/master_key.rs:103-107`（`MasterKey([REDACTED])`）；Master Key 生成与口令包装信封（RUTMK001、Argon2id 派生包装钥、盐/Nonce 随机、格式+盐为 AAD）：`security/src/master_key.rs:82-90, 157-190, 402-423`；Master Key 文件写入 no-clobber + 读时拒绝符号链接/非定长文件：`platform/src/master_key_file.rs:39-83, 91-130`；命令列（operations/batch_operations/center_outbox/inbox payload）同信封加密：`security/src/command_cipher.rs:76-103, 118-155`（RUTC1: 前缀、AD 绑行身份）；TOTP 秘密入库前 Master Key 加密：`persistence/src/bootstrap_repository.rs:202-234` | 无 |
| 1a | 日志/错误脱敏 | ✅ | 全部错误类型为枚举 Display 文案，不含秘密值：`security/src/lib.rs:270-302`、`security/src/master_key.rs:446-472`（错误文案不含口令）；测试断言错误不回声：`security/src/master_key.rs:661-662`（wrong_error.to_string() 不含 "incorrect"）；`tracing` span 对敏感值 skip_all：`app/src/main.rs:300, 407`、`app/src/backup.rs:223, 328, 353`；凭证接口 Debug 脱敏：`api/src/lib.rs:290-299`（password 字段 "[REDACTED]"） | 无 |
| 2 | 认证与会话 | ✅ | Argon2id v1.3 64 MiB / t=3 / p=1、16 字节盐、32 字节哈希：`domain/src/password.rs:39-47`、`security/src/password_hash.rs:37-49, 61-70`；Bootstrap Code 20 字符无歧义 base32（100-bit）、只存 SHA-256：`security/src/bootstrap_code.rs:23, 35-43, 52-55`、`app/src/initialization_runtime.rs:219-229`；一次性消费为单事务（事务内重读 used_at，杜绝竞态双消费）：`persistence/src/bootstrap_repository.rs:134-173`；TOTP 160-bit 秘密 + RFC 6238 单步窗口 + last_used_step 防重放：`security/src/totp.rs:30-38`、`domain/src/totp.rs:11, 31-37, 192-195`；Session/CSRF Token 32 字节随机、库中只存 SHA-256：`security/src/session_token.rs:22, 48-67, 137-145`；Cookie `Path=/; HttpOnly; SameSite=Strict`、HTTPS 时加 Secure、固定 8 小时绝对有效期（活动不延长）：`web/src/auth.rs:73`（`SESSION_COOKIE_NAME`）、`:85`（`SESSION_LIFETIME` 8 小时）、`:1228-1245`（`session_cookie`，字面量 `:1237`）、`resolve_session` 的 touch 只更新 last_used_at 不延长 expires_at `:1154-1161`；CSRF 常量时间比较：`web/src/auth.rs:1177-1200`（`csrf_matches`）；登录失败限速（5/用户名、20/地址、15 分钟滑动窗口，用户名键截断防内存增长）：`web/src/auth.rs:102-118`（限速常量）、`:886-1016`（`LoginRateLimiter`/`BucketMap`，`RATE_LIMIT_USERNAME_CHARS` 截断 `:118`、`bounded_username_key` `:1031`）；密码变更撤销该用户全部 Session：`web/src/auth.rs:1830-1853`（B3 撤销信号区）；禁用用户撤销：`:2145-2152`；角色变更撤销：`:2207-2212`；非回环强制 HTTPS：`app/src/site_runtime.rs:210-213, 499-527`；Standalone 只绑回环：`app/src/standalone_runtime.rs:1383-1395`；无默认密码（首次启动必须 bootstrap claim 设密码）：`web/src/auth.rs:1614`（`bootstrap_complete`）、`app/src/initialization_runtime.rs` | 见问题 N2/N3/N4 |
| 3 | TLS | ✅ | rustls 全栈、无任何 accept_invalid_certs/danger_accept（全仓 grep 零命中）；BMC 连接信任双模式：系统 CA 验证 + 指纹守卫（`SystemCaIdentityVerifier`，先指纹后 WebPKI 链验证）：`infra-redfish/src/redfish_gateway.rs:14390-14454`；精确指纹 Pin（`PinnedCertificateVerifier`，rustls 仍验证 CertificateVerify 签名证明密钥持有）：`:14459-14517`；证书变化拒绝握手并记录 → `TlsIdentityChanged`：`domain/src/endpoint.rs:325-343`、`infra-redfish/src/redfish_gateway.rs:14339-14351`（`take_change`/`record_validation_rejection`）；信任流程先取证书后交凭据：`application/src/endpoint_trust.rs:8-16`（TlsIdentityProbe「without credentials or HTTP data」）、`web/src/lib.rs:1454`（begin_endpoint_trust 无凭据观察）、`:1479, 1504`（enroll 前重观察声明的信任策略）；站点自签证书生成 + key-match 校验（validate_key_matches_cert）：`app/src/site_runtime.rs:232-305, 344, 378`；站点 TLS 对持久化于 `tls/` 目录复用身份：`:444-470`；启动打印指纹供带外核对：`:579` | 见问题 N6 |
| 4 | 中心链路 | ✅ | mTLS：Center 监听 TLS 1.3 only + WebPkiClientVerifier（必需客户端证书，CA 为唯一信任锚）：`app/src/center_acceptor.rs:779-808`；Site 客户端携带 CA 签发的 ClientAuth 证书（EKU）：`app/src/center_client.rs:117-126`、`app/src/center_ca.rs:135`；Center 不保存 BMC 秘密——投影只含 display_name/address/generation/health/resources：`application/src/center_sync.rs:1282-1326`（§15.5 注释「the center never sees credentials or sessions」）、`persistence/src/center_projection_repository.rs`（该文件全文件 grep 无 credential/password/secret 命中）；at-least-once 幂等：重复 OperationOffer 返回已记录结果、不重复执行（测试钉死）：`application/src/center_sync.rs:3478-3525`（拒绝态不可复活）、`:3528-3561`（完成态返回记录结果）、重连重复突发只生效一次（`center_sync.rs:4448` 测试）；Outbox 从最后 Ack 续传：`center_sync.rs` 重连风暴套件 `:4328-4780`；Site 本地解密边界：BMC 凭据只在 Edge 实例（`persistence/src/credential_repository.rs` 只存在于 Site 库，Center 库无凭据表——投影表无凭据列，见上）；中心队列 payload 加密：`security/src/command_cipher.rs:1-43` | 无 |
| 5 | 注入与边界 | ✅ | 裸 SQL 门禁：全仓 grep 无 query_raw/execute_raw/sql! 命中；机械门禁仅允许迁移 crate 的 DDL（`DDL_FIRST_WORDS = [CREATE, ALTER, DROP, PRAGMA]`，DML 家族词禁止，含 raw 字符串识别）：`migration/tests/bare_sql_gate.rs:35, 40, 445-456`（milestone-status §二 验收 5）；无原始 BMC 写请求：唯一 nv-redfish 依赖 crate 是 infra-redfish，`UpstreamBmc = HttpBmc<NvHttpClient>`（传输经 `NvHttpClient::with_client` 注入）：`infra-redfish/src/redfish_gateway.rs:338, 1115`；CSV 导入注入面：1 MiB 上限 / 10,000 行上限 / 精确表头 / 域名验证（EndpointAddress、CredentialId、指纹解析）/ 重复地址拒绝 / 错误不回声输入值：`application/src/endpoint_csv.rs:13-20, 117-175`（测试 `endpoint_csv.rs:381` 断言错误不回声）；上传路径穿越面：文件路径是 `data_dir/artifacts/{artifact_id}.bin`（UUID 纯函数，名称/用户输入不参与路径）：`persistence/src/artifact_repository.rs:363-378`；分块位移纪律（乱序拒绝、超声明大小拒绝、base64 上限）：`application/src/artifact_store.rs:285-310, 649-662`；备份恢复的条目名也不进路径（固定常量 + `artifact-{UUID}` 前缀白名单解析）：`app/src/backup.rs:513-527` | 无 |
| 6 | 审计完整性 | ✅ | 秘密构造上不可进审计：审计目标只允许非秘密身份数据：`domain/src/audit.rs:318-324`（AuditTarget：Product/EndpointAddress/Endpoint）；参数摘要为封闭类型枚举，变体不含秘密槽：`:383-394`（AuditParameterSummary 只有 credential_id/trust/row_count）；TLS 信任只记分类不记证书材料：`:348-353`；只追加：审计仓库无 update/delete 面，写入前校验顺序（缺 start/跳号/乱序/终态后追加均拒绝）：`persistence/src/audit_repository.rs:33-34, 99-150`；覆盖谁/什么/何时：登录成功失败（`record_login_failure` `web/src/auth.rs:2289-2316`、`record_login_success` `:2319-2338`；**429 限速拒绝不写审计**——B2 设计确认：被拒请求从未运行、429 本身即记录，见 §三 B2 行）、管理动作 start/terminal 对（`record_management_event` `:2342-2365`）；审计追加失败不阻塞请求（文档化 best-effort，`record_outcome` `:2373-2405`，注释 `:2370-2371`） | 见问题 N7 |
| 7 | 备份恢复 | ✅ | 备份包加密信封：magic+版本+清单（AAD 认证）+ 随机 Nonce + XChaCha20-Poly1305 密文，清单逐条目 SHA-256 校验，包内只有已加密凭据与受保护信封、无明文密钥：`security/src/backup_package.rs:39-47, 242-314, 323-427`；Master Key 受保护包装（RUTMK001 口令信封或 RUTOSK001 系统信封）随包作普通条目：`security/src/backup_package.rs:19-23`、`app/src/backup.rs:443-455`（`collect_backup_entries`，master-key 条目 `:444, 451`）；跨机恢复需源信封：`app/src/backup.rs:232-236`（文档）、测试 `:1121`（cross_machine_restore_requires_carrying_the_source_envelope）；拒绝异实例包（密钥不匹配 → AuthenticationFailed）：测试 `:1095`（restore_rejects_another_instances_package）、`app/src/backup.rs:270-273`；拒绝不同产品版本：`:274, 739-750`（check_product_version）、测试 `:1277`；恢复前必须实例停止（RuntimeLock）+ 已初始化：`:251, 379-397`（`acquire_stopped_instance`）；写后重开验证：`:196-204`（备份包重开）、`:351-366`（恢复库重开只读比对）；**恢复前预快照**（T-E，commit 02459dc）：首个覆盖动作前复制当前数据目录进同级临时目录（`:300-308, 619-643`），失败保留供回滚、成功随 TempDir 清除（`:310-324`），测试 `:1307, 1384, 1404`；备份快照计数钉死（backup_applied 24 / supported 23，备份含未来迁移时恢复拒绝）：`persistence/src/backup_snapshot.rs:624-627` | 无 |
| 8 | 并发与 DoS | ✅ | 全局写串行：`persistence/src/lib.rs:101, 240`（write_gate = `Semaphore(1)`，测试 `:485` 断言）；批量刷新并发上限 4、目标上限 128：`application/src/batch_refresh.rs:52-67`（`MAX_CONCURRENT_REFRESHES` `:67`，批目标对齐 §13.7 `:52`；T-B commit 4897b22 后入网首刷亦走端点读门，见 #2 与 `known-limitations.md` §九）；制品分块 4 MiB base64 上限 + 传输层 DefaultBodyLimit 413 前置：`application/src/artifact_store.rs:304-310`、`web/src/lib.rs:108, 911`；中心协议帧 8 MiB 上限（编解码双侧，声明超限拒绝）：`center-protocol/src/lib.rs:59`、`center-protocol/src/framing.rs:176-199, 219-238`；登录限速（见 #2；桶键有界剪枝见 N3）；审计查询 limit 上限 1000：`web/src/lib.rs:1368`；CSV 导入 1 MiB/10,000 行（见 #5）；TLS 握手超时 10 秒防挂死监听：`app/src/site_runtime.rs:604-606, 635` | 见问题 N3 |
| 9 | 禁 unwrap/panic 扫描 | ✅ | 全仓生产代码扫描（web/app/security/persistence/domain/application/platform/center-protocol，剔除 `#[cfg(test)]` 与注释）：零 `.unwrap()`/`.expect()`/`panic!`/`todo!`/`unimplemented!`；命中全部为防御性 `unwrap_or*`（如 `web/src/auth.rs:1083, 1239, 1530, 1889`、`app/src/standalone_runtime.rs:853`、`center-protocol/src/framing.rs:230` 等，均为显式默认值回退，非 §7.7 禁止形态）；唯一生产 `unreachable!` 一处（E3c 已处置，见问题 N5）：`web/src/lib.rs:1224-1226`（`OVERVIEW_RECENT_EVENTS` 正性 totality guard 的防御分支，编译期 `const _: () = assert!(...)` 于 `:1223` 证明其不可达）；`#![forbid(unsafe_code)]`：`security/src/lib.rs:1`、`app/src/main.rs:1` | 见问题 N5 |

## 三、发现的问题清单

无 BLOCKER。问题按严重度排序：

| 级别 | 编号 | 问题 | 推理链 / 复现路径 |
|---|---|---|---|
| MINOR | M1 | 登录路径存在用户枚举时间侧信道——**已修复** | 原状：用户名不存在时在 Argon2id 之前提前返回，口令错误分支执行完整 Argon2id（64 MiB/3 轮），耗时差异可枚举有效账户名。**修复（commit 72eccb5）**：未知用户名分支执行一次哑 Argon2id 验证——固定盐/哈希 `DUMMY_SALT`/`DUMMY_HASH`（`web/src/auth.rs:1307, 1314`），`dummy_password_verification`（`:1335-1346`），未知用户名分支调用（`:1438`，分支注释引用 MINOR-1 `:1433-1437`）——耗时与口令错误分支对称；审计与限速覆盖不变（两分支均 `record_login_failure` + 限速计次）。**验证方式**：结构对称断言而非墙钟计时——测试 mock 统计 `verify_password` 边界调用次数（`web/src/lib.rs:9279` `password_verifications`），断言未知用户名路径每次失败 1 次、限速拒绝 0 次（`:10725` 测试 `unknown_username_sign_in_runs_one_dummy_verification_per_attempt`，计数断言 `:10750, :10766, :10776-10779`），口令错误路径同为每次 1 次（`:10789` 测试 `wrong_password_sign_in_verifies_once_per_attempt`，断言 `:10806`），两分支计数对称（`:10745-10749` 注释：墙钟计时断言过于 flaky，调用计数对称是结构性保证）。**残留面附注（已关闭，深度审查批次）**：disabled-principal（`auth.rs:1446-1461`）与 credential-missing（`:1469-1481`）分支曾快速返回、不执行哑验证，原以「需先已知有效用户名才可达（未知用户名已在前一分支拦截）、在威胁模型之外」附注；深度审查对抗验证（2026-08-12，commit 8147bc9）**证反该理由**——已禁用/无凭据账户的登录分支同样构成用户名存在性 oracle（账户已知存在，响应差异可观察），两分支现补同款哑 Argon2id 验证（B4，`:1447-1453`/`:1469-1473` 分支注释），残留面关闭。 |
| MEDIUM | B1 | 密码策略缺 API 边界执行——**已修复**（深度审查批次） | 原状：密码最小长度仅由控制台表单前端约束，API 可直接接收任意短密码（固定 `admin` 名 + 5 次/15 分钟预算下单字符密码数小时可破）。**修复（commit 8147bc9）**：`password_satisfies_policy`（≥12 个 Unicode 标量字符，`web/src/auth.rs:1355-1357`）在登录/认领/改密三个入口 enforce（`:1386-1397, 1625-1631, 1780-1785`）——拒绝发生在限速/查找/验证之前，不占限速预算、不写审计（策略违规不是登录尝试）；表单 12 字符下限保留为客户端便利。登记见 `known-limitations.md` §七。 |
| MEDIUM | B2 | 429 限速拒绝不写审计——**已处置**（设计确认并成文，深度审查批次） | 深度审查发现限速拒绝路径无审计记录。处置（commit 8147bc9）：确认为**有意设计**并写入代码注释——被拒请求从未运行、429 本身即记录；写 started+failed 对会让审计表随拒绝洪泛无界增长，且每次审计追加串行在 persistence 写门（`Semaphore(1)`）上，429 洪泛会饿死合法 session/telemetry/event/operation 写入（`web/src/auth.rs:1402-1416` 注释原文 `:1403-1411`）。行为登记见 `known-limitations.md` §七。 |
| MEDIUM | B3 | 改密后会话撤销失败静默——**已修复**（深度审查批次） | 原状：改密后 `revoke_sessions_for_principal` 失败被静默忽略（`?` 吞掉），旧 token 保持有效至 8 小时绝对期限且无用户/审计信号（违反 §16.2「控制静默失效」）。**修复（commit 8147bc9，`web/src/auth.rs:1830-1853`）**：撤销不再可选——失败显式 500 + 审计 failed outcome（改密本身成功不回滚，部分状态可见可查）。 |
| NOTE | N1 | 登录限速器为进程内存态，重启清空归零 | `web/src/auth.rs:886-889`（`LoginRateLimiter` 纯内存 HashMap）。单机产品进程重启后预算重置。影响有限（重启需要本机访问权限），作为运维事实登记，非缺陷。 |
| NOTE | N2 | `x-forwarded-proto` 头无条件参与 Secure 判定 | `web/src/auth.rs:1281-1294`（`is_https` 直接信任请求头）。恶意客户端可让明文回环控制台的 Set-Cookie 带 `; Secure`，后果是该客户端自身后续无法在 http 上携带 cookie（自伤型，无法借此窃取或伪造他人会话）；若产品将来部署在不可信代理之后，该信任点需要配置化边界。当前形态非可利用缺陷。 |
| NOTE | N3 | 限速器桶不驱逐，长期运行内存随（用户名, IP）对增长——**已实现**（2026-08-12，T-D，commit e7aef53） | 原状：桶键只在被再次访问时剪枝（`web/src/auth.rs:886-1016` `LoginRateLimiter`/`BucketMap`，访问路径剪枝 `allows_key`/`record_key` `:940-984`），dormant 键不清理。用户名键已有 `RATE_LIMIT_USERNAME_CHARS` 截断保护（`:118`，`bounded_username_key` `:1031`，避免无限长键）；IP 键为 SocketAddr 字符串，天然有界；条目总数为「攻击者可控的 distinct 键数」× 每键 ≤20 个 Instant。多 IP 分布式攻击可致内存线性增长。**修复**：周期剪枝——新键插入计数达 `BUCKET_PRUNE_THRESHOLD`（4096，`:131`）触发全表清扫（`prune_if_due` `:989-998`），回收全部过期桶（dormant 键随窗口滑动清理，含仅 `allows` 创建的空桶；`prune_expired` `:1005-1015`）；清扫与访问路径共用同一过期判定，限速判定逐字节不变；内存有界 = 窗口内活跃桶工作集 + 4096。有界性测试 4 个：`rate_limiter_prunes_expired_buckets_to_a_bounded_size`（`:2848`）、`rate_limiter_prune_spares_active_buckets`（`:2901`）、`rate_limiter_prune_reclaims_buckets_created_by_allows_only`（`:2945`）、`prune_expired_reclaims_only_buckets_whose_entries_left_the_window`（`:2973`）；web 133 测试全过。 |
| NOTE | N4 | bootstrap 认领端点无登录限速 | `web/src/auth.rs:1614`（`bootstrap_complete` 不经过 `LoginRateLimiter`；路由表 `:529` 标 Public）。风险被三层结构抵消：码为 100-bit 一次性（`security/src/bootstrap_code.rs:13-15`）、库中只存 SHA-256（`hash_bootstrap_code`）、消费为单事务（`persistence/src/bootstrap_repository.rs:134-173`，已用码必然 AlreadyUsed）。暴力枚举 100-bit 码不可行；登记为观察项。 |
| NOTE | N5 | 生产代码存在 1 处 `unreachable!`——**已关闭（迭代三，E3c）** | 原状：`web/src/lib.rs:1211-1213` 的 `NonZeroU64::new(rutilus_api::OVERVIEW_RECENT_EVENTS)` else 分支 `unreachable!`。**处置（commit 8a9ab82/34315c8）**：升级为编译期断言——`web/src/lib.rs:1223` `const _: () = assert!(rutilus_api::OVERVIEW_RECENT_EVENTS > 0);` 在编译期钉死常量正性（注释 `:1213-1222` 说明 totality 论证与镜像断言位置），运行时 guard 保留为已被编译期断言证明不可达的防御分支（`:1224-1226`）。语义安全由编译器保证而非注释；§7.7 禁止清单本未列 `unreachable!`（只列 unwrap/expect/todo!/unimplemented!/主动 panic），现已在「禁止主动 panic」精神内完成机器校验。 |
| NOTE | N6 | Pin 模式验证器有意跳过链/主机名/有效期验证 | `infra-redfish/src/redfish_gateway.rs:14459-14484`：`PinnedCertificateVerifier::verify_server_cert` 只做精确指纹比对，不验证链/主机名/有效期（注释明确「Exact SHA-256 pinning replaces CA, hostname, and validity checks」），rustls 仍验证 CertificateVerify 签名（密钥持有证明）。与设计 §10.4「显示证书指纹 → 管理员明确 Pin」一致——Pin 决策发生在信任建立时（`web/src/lib.rs:1454` 先取证书后交凭据）。审查推断：可接受的设计决策；指纹更新后旧指纹立即失效（`TlsIdentityChanged` 路径），1.0.0 前建议纳入外部评估清单。 |
| NOTE | N7 | 审计追加失败不阻塞业务请求 | `web/src/auth.rs:2404`（`record_outcome` 对 append 失败静默忽略 `:2390, :2404`，文档化 best-effort，注释 `:2370-2371`）。审计完整性 vs 可用性权衡（§16.3 要求记录，但审计故障不应使登录失败）；仓库层仍保证已写入事件的追加序正确（`persistence/src/audit_repository.rs:99-150`）。登记为已知权衡，建议未来提供审计健康度可见性。 |
| NOTE | N8 | macOS 系统信封镜像文件携带原始密钥字节 | `platform/src/system_secret_store.rs:21-27`（模块文档已如实声明：macOS Keychain 为权威、持久化镜像仅备份用途、无恢复消费者）。已登记于 known-limitations 的精神范围内；未来备份恢复功能必须重建 Keychain 条目而非仅恢复文件。审查确认现状为文档化限制，非静默缺陷。 |
| NOTE | N9 | 回环明文控制台的会话 Cookie 不带 Secure | `web/src/auth.rs:1555-1560`（登录成功处 `secure = is_https(...)`，回环 http 下无 `; Secure`；`session_cookie` `:1228-1245`）。这是设计内行为（本地控制台必须可用），Secure 只在非 https 流量会发送 cookie 的威胁模型下才有意义——回环明文流量不离开本机；非回环监听已被 `site_runtime.rs:210-213` 强制 HTTPS。非缺陷，记录以明确边界。 |

## 四、审查结论（0.9.0 启动项达成情况）

### 4.1 启动项达成

「安全审查（启动）：基于现有代码的审查与记录」**达成**：本记录即流程启动交付物。八个审查
范围 + §7.7 扫描全部完成，**每一项都有真实代码行号证据**，无 BLOCKER，NOTE 8 项
（见第三节）；原 MINOR 1 项（M1 时间侧信道）已于迭代二修复并转登记（commit 72eccb5，
见第三节 M1 行）；N5 已于迭代三关闭（E3c 编译期 const assert，见第三节 N5 行）。
迭代三+四新增结构证据：Secret 泄漏扫描门禁（E3b，`security/tests/secret_leak_gate.rs`）、
§12.4 生产捕获点（E1）与约束修复（E4）均已合入（见 §4.3/§4.4 与 milestone-status §7.2-A）。
深度审查批次（2026-08-12，master a4950fc）新增修复登记：B1（密码策略 API 边界执行）、
B2（429 不写审计，设计确认并成文）、B3（撤销信号非可选）、B4（M1 残留面证反并关闭），
全部为 commit 8147bc9（认证边界硬化），见第三节 B1-B4 行与 `milestone-status.md` §7.4。
迭代七（2026-08-12，master 61b9cc5）：§九 遗留 8 项已全部落地/处置——N3 已实现（T-D，
commit e7aef53，见第三节 N3 行），其余 7 项（i18n fragment 纯函数测试 / decode_failures
贯通测试 / AMI/HPE 真网关 E2E / restore 预恢复快照 / free_port TOCTOU / 入网首刷走端点门 /
快照 ETag 决策 c）落地记录与三批五维审计 APPROVE 见 `milestone-status.md` §7.5；第 9 个
提交 61b9cc5（secret-gate 白名单行号 83/84→88/89 对齐 backup.rs 漂移，门禁漂移检测触发-
修复闭环）已登记；§4.3「深度审查遗留项」行已同步。B1-B4 行不受本轮影响，其 auth.rs 行号
已按当前 master 重核。

### 4.2 结构证据充分、无需改动的面

- 凭据 at-rest 加密、Master Key 信封、内存 Secret 包装与 Debug 脱敏（范围 1）：证据链完整，
  含负向测试（`security/src/lib.rs:402-423` debug 脱敏断言、`security/src/master_key.rs:642-664`
  错误不回声断言）。
- TLS 信任与 Pin 流程（范围 3）：双模式验证器 + `TlsIdentityChanged` + 先取证书后交凭据，
  全仓无 accept_invalid_certs。
- 中心链路（范围 4）：mTLS 必需客户端证书、投影表无凭据列（grep 零命中）、重复 offer 幂等
  有专门测试钉死。
- 注入与边界（范围 5）：裸 SQL 机械门禁、唯一 BMC HTTP 依赖 crate、CSV/上传均有界。
- 审计（范围 6）：构造上禁秘密 + 只追加 + 顺序校验。
- 备份（范围 7）：加密信封 + 异实例/版本拒绝 + 跨机源信封要求 + 恢复前预快照三态（T-E），
  自动化往返覆盖 10 个测试（`app/src/backup.rs` 测试区 `:1051-1404`）。
- 并发（范围 8）：写 Semaphore(1)、4 MiB 分块、8 MiB 帧、128 目标/4 并发批量。
- §7.7 扫描（范围 9）：唯一生产 `unreachable!` 为常量 totality guard（N5，已于迭代三关闭：
  编译期 `const _: () = assert!(...)` 钉死正性，`web/src/lib.rs:1223`），其余全部为
  防御性 `unwrap_or`。

### 4.3 需要演练 / 外部评估的项

| 项 | 说明 | 依据 |
|---|---|---|
| 独立 Secret 泄漏扫描 | ✅ 仓库级已落地（迭代三，E3b）：`security/tests/secret_leak_gate.rs`（3 规则 R1/R2/R3、8 测试、`ALLOWED_CONSTANT_HITS` 白名单 2 处、`test-support` crate 目录级豁免（E3b 原始提交 eefde7e）`:55-59, 1000-1002`、深度审查批次 e8424df 补 `strings_catalog!` 宏体豁免 `:534, 815-822, 1195`、全 workspace 扫描全绿），**CI 独立步骤**（`ci.yml:225-227` Secret leak gate：`cargo test --locked -p rutilus-security --test secret_leak_gate`，`if: matrix.is_default`，machete 之后、wasm32 之前）；**运行时复核未做**：内存转储检查、API 响应抓包/日志复核仍为 1.0.0 发布评审建议项。milestone-status §7.1「Secret 泄漏检查」已转 ✅ 结构性 | `docs/milestone-status.md:349` |
| M1 时间侧信道处置 | ✅ 已处置：未知用户名路径已补哑 Argon2id 验证（commit 72eccb5，`web/src/auth.rs:1335-1346, 1438`），验证方式 = 调用计数对称断言（`web/src/lib.rs:10725, 10789`）；残留面（disabled / credential-missing 分支）已于深度审查批次**证反并关闭**（B4，commit 8147bc9：`web/src/auth.rs:1446-1461, 1469-1481` 补同款哑验证），见 §三 M1 行 | 本文档 M1 |
| 深度审查遗留项（LOW/NOTE） | ✅ 8 项已全部落地/处置（迭代七，2026-08-12，master 61b9cc5）：限流器桶键淘汰（T-D e7aef53，N3 关闭）/ i18n fragment 纯函数测试（T-H c4dd335）/ decode_failures 贯通测试（T-G 8482d85）/ AMI/HPE 真网关 E2E（T-I 044bae2）/ restore 预恢复副本（T-E 02459dc）/ free_port TOCTOU（T-F 83ff07f）/ 入网首刷绕端点门（T-B 4897b22）/ 快照 ETag 接线（决策 c，不实施）；另第 9 个提交 61b9cc5（secret-gate 白名单行号对齐 backup.rs 88/89，门禁漂移检测触发-修复闭环）；三批五维审计 APPROVE 记录见 `milestone-status.md` §7.5 | `docs/known-limitations.md` §九 |
| Pin 模式验证器外部评估（N6） | 设计内行为，但「跳过链验证」属于需要安全专家确认的权衡面 | 本文档 N6 |
| 真实设备认证矩阵 | 与凭据泄漏无直接关系，但影响「设备侧凭据处理」的整体结论（当前仅 mock 验证） | `docs/known-limitations.md:72-79` |

### 4.4 对 1.0.0「无已知凭据泄漏」验收的支撑判断

**结构性支撑成立，结论有条件成立**：

- 已满足的支撑面：BMC 凭据 at-rest 加密（XChaCha20-Poly1305 + AD 绑定 + 随机 Nonce，
  `security/src/lib.rs:184-251`）；Master Key 不入库明文且文件 no-clobber/非符号链接加载
  （`platform/src/master_key_file.rs:39-130`）；内存 Secret 包装 + zeroize + 全 Debug 脱敏；
  错误类型不回声秘密（`security/src/master_key.rs:446-472`）；审计类型构造上禁秘密
  （`domain/src/audit.rs:318-394`）；API 不回声秘密（`web/src/lib.rs:1374` `credential_inventory`
  无秘密字段、`api/src/lib.rs:290-311`）；Center 投影/协议类型排除凭据
  （`application/src/center_sync.rs:1282-1326`）；命令列与中心队列 payload at-rest 加密
  （`security/src/command_cipher.rs`）；备份包只有密文与受保护信封（`security/src/backup_package.rs:19-23`）；
  日志/span 对敏感值 skip_all（`app/src/main.rs:300, 407`）。
- 附加条件：该结论当前基于**代码审查与结构证据**；仓库级独立泄漏扫描已落地（迭代三 E3b：
  `security/tests/secret_leak_gate.rs` 3 规则、8 测试、扫描全绿），运行时抓包/日志复核与
  外部评估仍未做；M1 时序侧信道不构成「凭据泄漏」（不泄露密码/哈希，只泄露账户存在性），
  已于迭代二修复（commit 72eccb5，见 §三 M1 行），其残留面（disabled/credential-missing
  分支）亦已于深度审查批次证反并关闭（B4，commit 8147bc9，见 §三 M1/B4 行），不再构成
  开放项。
  建议 1.0.0 发布评审时补充：运行时抓包/日志复核、一次外部安全评估（含 §7.7 合规、Pin
  验证器、备份包格式），并将本文档的 NOTE 逐条关闭或转登记为已知限制（N5 已于迭代三关闭，
  见 §三 N5 行）。

---

> 审查日期：2026-08-12；审查对象：master c4168c5；审查方式：只读代码自查。
> 修订：2026-08-12（迭代二，master edead80）——M1 已修复（commit 72eccb5）并转登记为
> 「已修复 + 验证方式」，§三 M1 行与 §四 4.1/4.3/4.4 相应更新。
> 修订：2026-08-12（迭代三+四，master bfb001e）——N5 已关闭（E3c 编译期 const assert，
> commit 8a9ab82/34315c8，§三 N5 行）；Secret 泄漏扫描门禁已落地（E3b，commit eefde7e，
> §二 #9 与 §四 4.3/4.4）；全文 file:line 按 bfb001e 重核（E1 触面 redfish_gateway.rs 等）。
> 修订：2026-08-12（深度审查批次，master a4950fc）——M1 残留面已证反并关闭（B4，commit
> 8147bc9：disabled/credential-missing 分支补哑验证，§三 M1 行）；B1-B3 修复登记（密码策略
> API 边界 / 429 不写审计设计确认 / 撤销信号非可选，§三 B1-B3 行）；§四 4.1/4.3/4.4 相应
> 更新；深度审查遗留项 8 项登记于 `known-limitations.md` §九。
> 修订：2026-08-12（迭代七，master 61b9cc5）——§九 遗留 8 项已全部落地/处置：N3 已实现
> （T-D，commit e7aef53，§三 N3 行补原状/修复/有界性测试 4 个）；§二 #2/#6/#7/#8/#9 与
> §三 M1/B1-B3/N1-N4/N7/N9 行的 auth.rs/backup.rs 行号按当前 master 逐处打开重核（T-D
> auth.rs +263 净行、T-E backup.rs +431 净行漂移）；§四 4.1/4.2/4.3 相应更新；其余 7 项
> 落地记录见 `milestone-status.md` §7.5；第 9 个提交 61b9cc5（secret-gate 白名单行号
> 83/84→88/89 对齐 backup.rs，门禁漂移检测触发-修复闭环）已登记。
> 本文档为流程启动项记录，后续演练/外部评估结论应追加到对应小节。
