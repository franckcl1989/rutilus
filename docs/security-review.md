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
| 2 | 认证与会话 | ✅ | Argon2id v1.3 64 MiB / t=3 / p=1、16 字节盐、32 字节哈希：`domain/src/password.rs:39-47`、`security/src/password_hash.rs:37-49, 61-70`；Bootstrap Code 20 字符无歧义 base32（100-bit）、只存 SHA-256：`security/src/bootstrap_code.rs:23, 35-43, 52-55`、`app/src/initialization_runtime.rs:219-229`；一次性消费为单事务（事务内重读 used_at，杜绝竞态双消费）：`persistence/src/bootstrap_repository.rs:134-173`；TOTP 160-bit 秘密 + RFC 6238 单步窗口 + last_used_step 防重放：`security/src/totp.rs:30-38`、`domain/src/totp.rs:11, 31-37, 192-195`；Session/CSRF Token 32 字节随机、库中只存 SHA-256：`security/src/session_token.rs:22, 48-67, 137-145`；Cookie `Path=/; HttpOnly; SameSite=Strict`、HTTPS 时加 Secure、固定 8 小时绝对有效期（活动不延长）：`web/src/auth.rs:86`（`SESSION_COOKIE_NAME`）、`:98`（`SESSION_LIFETIME` 8 小时）、`:1515-1526`（`session_cookie`，字面量 `:1524`）、`resolve_session` 的 touch 只更新 last_used_at 不延长 expires_at `:1400-1410`；CSRF 常量时间比较：`web/src/auth.rs:1462`（`csrf_matches`）；登录失败限速（5/用户名、20/地址、15 分钟滑动窗口，用户名键截断防内存增长）：`web/src/auth.rs:117-134`（限速常量）、`:1054-1160`（`LoginRateLimiter`/`BucketMap`，`RATE_LIMIT_USERNAME_CHARS` 截断 `:134`、`bounded_username_key` `:1307-1310`）；密码变更撤销该用户全部 Session：`web/src/auth.rs:2297-2310`（B3 撤销信号区）；禁用用户撤销：`:2573-2627`；角色变更撤销：`:2647-2701`；非回环强制 HTTPS：`app/src/site_runtime.rs:213, 485-497`；Standalone 只绑回环：`app/src/standalone_runtime.rs:1461-1476`；无默认密码（首次启动必须 bootstrap claim 设密码）：`web/src/auth.rs:1945`（`bootstrap_complete`）、`app/src/initialization_runtime.rs` | 见问题 N2/N3/N4 |
| 3 | TLS | ✅ | rustls 全栈、无任何 accept_invalid_certs/danger_accept（全仓 grep 零命中）；BMC 连接信任双模式：系统 CA 验证 + 指纹守卫（`SystemCaIdentityVerifier`，先指纹后 WebPKI 链验证）：`infra-redfish/src/redfish_gateway.rs:14390-14454`；精确指纹 Pin（`PinnedCertificateVerifier`，rustls 仍验证 CertificateVerify 签名证明密钥持有）：`:14459-14517`；证书变化拒绝握手并记录 → `TlsIdentityChanged`：`domain/src/endpoint.rs:325-343`、`infra-redfish/src/redfish_gateway.rs:14339-14351`（`take_change`/`record_validation_rejection`）；信任流程先取证书后交凭据：`application/src/endpoint_trust.rs:8-16`（TlsIdentityProbe「without credentials or HTTP data」）、`web/src/lib.rs:1719`（begin_endpoint_trust 无凭据观察）、`:1784-1786`（enroll 前重观察声明的信任策略）；站点自签证书生成 + key-match 校验（validate_key_matches_cert）：`app/src/site_runtime.rs:232-305, 344, 378`；站点 TLS 对持久化于 `tls/` 目录复用身份：`:444-470`；启动打印指纹供带外核对：`:579` | 见问题 N6 |
| 4 | 中心链路 | ✅ | mTLS：Center 监听 TLS 1.3 only + WebPkiClientVerifier（必需客户端证书，CA 为唯一信任锚）：`app/src/center_acceptor.rs:807-830`；Site 客户端携带 CA 签发的 ClientAuth 证书（EKU）：`app/src/center_client.rs:126`、`app/src/center_ca.rs:135`；Center 不保存 BMC 秘密——投影只含 display_name/address/generation/health/resources：`application/src/center_sync.rs:1649`（§15.5 注释「the center never sees credentials or sessions」）、`persistence/src/center_projection_repository.rs`（该文件全文件 grep 无 credential/password/secret 命中）；at-least-once 幂等：重复 OperationOffer 返回已记录结果、不重复执行（测试钉死）：`application/src/center_sync.rs:3974`（拒绝态不可复活）、`:4048`（完成态返回记录结果）、重连重复突发只生效一次（`center_sync.rs:5124` 测试）；Outbox 从最后 Ack 续传：`center_sync.rs` 重连风暴套件 `:5004-6269`；Site 本地解密边界：BMC 凭据只在 Edge 实例（`persistence/src/credential_repository.rs` 只存在于 Site 库，Center 库无凭据表——投影表无凭据列，见上）；中心队列 payload 加密：`security/src/command_cipher.rs:1-43` | 无 |
| 5 | 注入与边界 | ✅ | 裸 SQL 门禁：全仓 grep 无 query_raw/execute_raw/sql! 命中；机械门禁仅允许迁移 crate 的 DDL（`DDL_FIRST_WORDS = [CREATE, ALTER, DROP, PRAGMA]`，DML 家族词禁止，含 raw 字符串识别）：`migration/tests/bare_sql_gate.rs:35, 40, 445-456`（milestone-status §二 验收 5）；无原始 BMC 写请求：唯一 nv-redfish 依赖 crate 是 infra-redfish，`UpstreamBmc = HttpBmc<NvHttpClient>`（传输经 `NvHttpClient::with_client` 注入）：`infra-redfish/src/redfish_gateway.rs:338, 1115`；CSV 导入注入面：1 MiB 上限 / 10,000 行上限 / 精确表头 / 域名验证（EndpointAddress、CredentialId、指纹解析）/ 重复地址拒绝 / 错误不回声输入值：`application/src/endpoint_csv.rs:13-20, 117-175`（测试 `endpoint_csv.rs:381` 断言错误不回声）；上传路径穿越面：文件路径是 `data_dir/artifacts/{artifact_id}.bin`（UUID 纯函数，名称/用户输入不参与路径）：`persistence/src/artifact_repository.rs:363-378`；分块位移纪律（乱序拒绝、超声明大小拒绝、base64 上限）：`application/src/artifact_store.rs:285-310, 649-662`；备份恢复的条目名也不进路径（固定常量 + `artifact-{UUID}` 前缀白名单解析）：`app/src/backup.rs:513-527` | 无 |
| 6 | 审计完整性 | ✅ | 秘密构造上不可进审计：审计目标只允许非秘密身份数据：`domain/src/audit.rs:403`（AuditTarget：Product/EndpointAddress/Endpoint）；参数摘要为封闭类型枚举，变体不含秘密槽：`:468`（AuditParameterSummary 只有 credential_id/trust/row_count）；TLS 信任只记分类不记证书材料：`:433-454`（AuditTlsTrust）；只追加：审计仓库无 update/delete 面，写入前校验顺序（缺 start/跳号/乱序/终态后追加均拒绝）：`persistence/src/audit_repository.rs:33-34, 99-150`；覆盖谁/什么/何时：登录成功失败（`record_login_failure` `web/src/auth.rs:2954`、`record_login_success` `:2985`；**429 限速拒绝不写审计**——B2 设计确认：被拒请求从未运行、429 本身即记录，见 §三 B2 行）、管理动作 start/terminal 对（`record_management_event` `:3009`）；审计追加失败不阻塞请求（文档化 best-effort，`record_outcome` `:3044`） | 见问题 N7 |
| 7 | 备份恢复 | ✅ | 备份包加密信封：magic+版本+清单（AAD 认证）+ 随机 Nonce + XChaCha20-Poly1305 密文，清单逐条目 SHA-256 校验，包内只有已加密凭据与受保护信封、无明文密钥：`security/src/backup_package.rs:39-47, 242-314, 323-427`；Master Key 受保护包装（RUTMK001 口令信封或 RUTOSK001 系统信封）随包作普通条目：`security/src/backup_package.rs:19-23`、`app/src/backup.rs:441-455`（`collect_backup_entries`，master-key 条目 `:444, 451`）；跨机恢复需源信封：`app/src/backup.rs:232-236`（文档）、测试 `:1138`（cross_machine_restore_requires_carrying_the_source_envelope）；拒绝异实例包（密钥不匹配 → AuthenticationFailed）：测试 `:1112`（restore_rejects_another_instances_package）、`app/src/backup.rs:270-273`；拒绝不同产品版本：`:274, 756-765`（check_product_version）、测试 `:1294`；恢复前必须实例停止（RuntimeLock）+ 已初始化：`:251, 396-415`（`acquire_stopped_instance`）；写后重开验证：`:196-204`（备份包重开）、`:351-372`（恢复库重开只读比对）；**恢复前预快照**（T-E，commit 02459dc）：首个覆盖动作前复制当前数据目录进同级临时目录（`:300-308, 636-664`），失败保留供回滚、成功随 TempDir 清除（`:310-324`），测试 `:1324, 1401, 1421`；备份快照计数钉死（backup_applied 28 / supported 27，备份含未来迁移时恢复拒绝；wave-four/five 新增两个迁移后重测）：`persistence/src/backup_snapshot.rs:646-647` | 无 |
| 8 | 并发与 DoS | ✅ | 全局写串行：`persistence/src/lib.rs:101, 240`（write_gate = `Semaphore(1)`，测试 `:485` 断言）；批量刷新并发上限 4、目标上限 128：`application/src/batch_refresh.rs:52-67`（`MAX_CONCURRENT_REFRESHES` `:67`，批目标对齐 §13.7 `:52`；T-B commit 4897b22 后入网首刷亦走端点读门，见 #2 与 `known-limitations.md` §九）；制品分块 4 MiB base64 上限 + 传输层 DefaultBodyLimit 413 前置：`application/src/artifact_store.rs:285-310`、`web/src/lib.rs:108, 1134`；中心协议帧 8 MiB 上限（编解码双侧，声明超限拒绝）：`center-protocol/src/lib.rs:59`、`center-protocol/src/framing.rs:176-199, 219-238`；登录限速（见 #2；桶键有界剪枝见 N3）；审计查询 limit 上限 1000：`web/src/lib.rs:1633`；CSV 导入 1 MiB/10,000 行（见 #5）；TLS 握手超时 10 秒防挂死监听：`app/src/site_runtime.rs:639-670` | 见问题 N3 |
| 9 | 禁 unwrap/panic 扫描 | ✅ | 全仓生产代码扫描（web/app/security/persistence/domain/application/platform/center-protocol，剔除 `#[cfg(test)]` 与注释）：零 `.unwrap()`/`.expect()`/`panic!`/`todo!`/`unimplemented!`；命中全部为防御性 `unwrap_or*`（如 `web/src/auth.rs:985, 1368, 1526, 1855`、`app/src/standalone_runtime.rs:623`、`center-protocol/src/framing.rs:230` 等，均为显式默认值回退，非 §7.7 禁止形态）；唯一生产 `unreachable!` 一处（E3c 已处置，见问题 N5）：`web/src/lib.rs:1513-1514`（`OVERVIEW_RECENT_EVENTS` 正性 totality guard 的防御分支，编译期 `const _: () = assert!(...)` 于 `:1511` 证明其不可达）；`#![forbid(unsafe_code)]`：`security/src/lib.rs:1`、`app/src/main.rs:1` | 见问题 N5 |

## 三、发现的问题清单

无 BLOCKER。问题按严重度排序。

> **HIGH 口径更新（2026-08-13，wave-one 对抗审查；2026-08-14 续 wave-three/four/five）**：
> 截至 2026-08-12 深度审查批次，本记录无 HIGH 级问题；**2026-08-13 对抗第一波发现 2 项
> HIGH——S3-1（操作历史 API 回声明文 BMC 口令）与 S3-2（首启未认领窗口 GuardedOnly 整面
> 开放）——均已修复**（commit d3b966a，见下表 S3-1/S3-2 行与 `milestone-status.md` §7.6）；
> 另有 D4-1 定级 HIGH（中心控制台审计事件无法持久化）亦已修复。**后续三波**：wave-three 的
> 1 项 HIGH 经独立验证降级 LOW（登录限速器已界住声称的泄漏面，e768473）；wave-four 的 1 项
> HIGH（V4I-1/V4R-1 审计 outcome CHECK 缺十三码词汇，审计完整性面）双透镜双确认并已修复
> （3a23b9b，m20260813_000003）；wave-five 的 5 项 HIGH（V5A-1 执行审计 CHECK 冻结 17 个
> 写家族、V5A-2 审计持久表无生产读面、V5A-3 审计归因不随姿态/来源、V5E-1 端点删除后回执
> 不计入、V5E-2 revoke-before-rebind 失守——均为审计可问责/中心协议面）全部已修复
> （e85560a，m20260813_000004），逐项登记见 `known-limitations.md` §九（第五波块）。
> **当前 master 无 HIGH 残留**；时间线如实陈述：无 HIGH（2026-08-12 深度审查）→ 2+1 HIGH
> 发现（2026-08-13 对抗第一波）→ 全部修复（d3b966a，1787 测试绿）→ wave-three 1 HIGH 降级
> （e768473）→ wave-four 1 HIGH 修复（3a23b9b）→ wave-five 5 HIGH 修复（e85560a，1913 测试绿）。

| 级别 | 编号 | 问题 | 推理链 / 复现路径 |
|---|---|---|---|
| MINOR | M1 | 登录路径存在用户枚举时间侧信道——**已修复** | 原状：用户名不存在时在 Argon2id 之前提前返回，口令错误分支执行完整 Argon2id（64 MiB/3 轮），耗时差异可枚举有效账户名。**修复（commit 72eccb5）**：未知用户名分支执行一次哑 Argon2id 验证——固定盐/哈希 `DUMMY_SALT`/`DUMMY_HASH`（`web/src/auth.rs:1594, 1601`），`dummy_password_verification`（`:1626-1643`），未知用户名分支调用（`:1766`，分支注释引用 MINOR-1）——耗时与口令错误分支对称；审计与限速覆盖不变（两分支均 `record_login_failure` + 限速计次）。**验证方式**：结构对称断言而非墙钟计时——测试 mock 统计 `verify_password` 边界调用次数（`web/src/lib.rs:9798` `password_verifications`），断言未知用户名路径每次失败 1 次、限速拒绝 0 次（`:11292` 测试 `unknown_username_sign_in_runs_one_dummy_verification_per_attempt`，计数断言 `:11317` 等），口令错误路径同为每次 1 次（`:11356` 测试 `wrong_password_sign_in_verifies_once_per_attempt`，断言 `:11385` 等），两分支计数对称（注释：墙钟计时断言过于 flaky，调用计数对称是结构性保证）。**残留面附注（已关闭，深度审查批次）**：disabled-principal（`auth.rs:1771-1794`）与 credential-missing（同区段）分支曾快速返回、不执行哑验证，原以「需先已知有效用户名才可达（未知用户名已在前一分支拦截）、在威胁模型之外」附注；深度审查对抗验证（2026-08-12，commit 8147bc9）**证反该理由**——已禁用/无凭据账户的登录分支同样构成用户名存在性 oracle（账户已知存在，响应差异可观察），两分支现补同款哑 Argon2id 验证（B4，`auth.rs:1771-1794` 分支注释），残留面关闭。 |
| MEDIUM | B1 | 密码策略缺 API 边界执行——**已修复**（深度审查批次） | 原状：密码最小长度仅由控制台表单前端约束，API 可直接接收任意短密码（固定 `admin` 名 + 5 次/15 分钟预算下单字符密码数小时可破）。**修复（commit 8147bc9）**：`password_satisfies_policy`（≥12 个 Unicode 标量字符，`web/src/auth.rs:113, 1680`）在登录/认领/改密三个入口 enforce（`:1711, 1957, 2170`）——拒绝发生在限速/查找/验证之前，不占限速预算、不写审计（策略违规不是登录尝试）；表单 12 字符下限保留为客户端便利。登记见 `known-limitations.md` §七。 |
| MEDIUM | B2 | 429 限速拒绝不写审计——**已处置**（设计确认并成文，深度审查批次） | 深度审查发现限速拒绝路径无审计记录。处置（commit 8147bc9）：确认为**有意设计**并写入代码注释——被拒请求从未运行、429 本身即记录；写 started+failed 对会让审计表随拒绝洪泛无界增长，且每次审计追加串行在 persistence 写门（`Semaphore(1)`）上，429 洪泛会饿死合法 session/telemetry/event/operation 写入（`web/src/auth.rs:1733-1740` 注释原文 `:1733-1740`）。行为登记见 `known-limitations.md` §七。 |
| MEDIUM | B3 | 改密后会话撤销失败静默——**已修复**（深度审查批次） | 原状：改密后 `revoke_sessions_for_principal` 失败被静默忽略（`?` 吞掉），旧 token 保持有效至 8 小时绝对期限且无用户/审计信号（违反 §16.2「控制静默失效」）。**修复（commit 8147bc9，`web/src/auth.rs:2297-2310`）**：撤销不再可选——失败显式 500 + 审计 failed outcome（改密本身成功不回滚，部分状态可见可查）。 |
| HIGH | S3-1 | 操作历史 API 回声明文 BMC 口令——**已修复**（wave-one，d3b966a） | 原状：五个响应投影直接序列化命令载荷，Account 命令的 `password` 字段以明文进入 `GET /api/v1/operations*` 响应（操作历史面存在已持久化的命令原文）。**修复（commit d3b966a）**：五个投影统一经 redacting helper 序列化命令输出 `[REDACTED]`（`web/src/lib.rs` 投影层）；域 `Serialize` 保持无损——at-rest 命令列信封与中心载荷依赖无损序列化；防回声测试 `operation_history_routes_never_expose_account_passwords`（`web/tests/operation_path.rs:899`）钉死。登记见 `known-limitations.md` §九（第一波块）。 |
| HIGH | S3-2 | 首启未认领窗口 GuardedOnly 整面开放——**已修复**（wave-one，d3b966a） | 原状：bootstrap 门 armed 前 `AuthGate` 为 Open，首启未认领窗口内全部 GuardedOnly 路由（端点/凭据/操作/备份等）无需会话即可访问。**修复（commit d3b966a）**：`PendingBootstrap` 策略下每个 GuardedOnly 路由无论门是否 armed 一律要求会话（`web/src/auth.rs:165` `AuthPolicy::PendingBootstrap`、`is_guarded` `:176, 210`、门检查 `:1352`），控制台 401 时重跑认证决策；测试 `auth_gate_starts_open_and_arms_guarded`（`auth.rs:4414`）钉死门状态机。登记见 `known-limitations.md` §九（第一波块）。 |
| NOTE | N1 | 登录限速器为进程内存态，重启清空归零 | `web/src/auth.rs:1054-1058`（`LoginRateLimiter` 纯内存 HashMap）。单机产品进程重启后预算重置。影响有限（重启需要本机访问权限），作为运维事实登记，非缺陷。 |
| NOTE | N2 | `x-forwarded-proto` 头无条件参与 Secure 判定 | `web/src/auth.rs:1568`（`is_https` 直接信任请求头）。恶意客户端可让明文回环控制台的 Set-Cookie 带 `; Secure`，后果是该客户端自身后续无法在 http 上携带 cookie（自伤型，无法借此窃取或伪造他人会话）；若产品将来部署在不可信代理之后，该信任点需要配置化边界。当前形态非可利用缺陷。 |
| NOTE | N3 | 限速器桶不驱逐，长期运行内存随（用户名, IP）对增长——**已实现**（2026-08-12，T-D，commit e7aef53） | 原状：桶键只在被再次访问时剪枝（`web/src/auth.rs:1054-1160` `LoginRateLimiter`/`BucketMap`，访问路径剪枝 `reserve`/`refund` `:1081-1140`），dormant 键不清理。用户名键已有 `RATE_LIMIT_USERNAME_CHARS` 截断保护（`:134`，`bounded_username_key` `:1307-1310`，避免无限长键）；IP 键为 SocketAddr 字符串，天然有界；条目总数为「攻击者可控的 distinct 键数」× 每键 ≤20 个 Instant。多 IP 分布式攻击可致内存线性增长。**修复**：周期剪枝——新键插入计数达 `BUCKET_PRUNE_THRESHOLD`（4096，`:147`）触发全表清扫（`prune_if_due` `:1269-1284`），回收全部过期桶（dormant 键随窗口滑动清理，含仅 `allows` 创建的空桶；`prune_expired` `:1285-1291`）；清扫与访问路径共用同一过期判定，限速判定逐字节不变；内存有界 = 窗口内活跃桶工作集 + 4096。有界性测试 4 个：`rate_limiter_prunes_expired_buckets_to_a_bounded_size`（`:4135`）、`rate_limiter_prune_spares_active_buckets`（`:4203`）、`rate_limiter_prune_reclaims_compensated_empty_buckets`（`:4247`，wave-one S3-3 原子 reserve/refund 后由 `..._created_by_allows_only` 更名）、`prune_expired_reclaims_only_buckets_whose_entries_left_the_window`（`:4282`）；web 172 测试全过。 |
| NOTE | N4 | bootstrap 认领端点无登录限速 | `web/src/auth.rs:1945`（`bootstrap_complete` 不经过 `LoginRateLimiter`；路由表 `:633` 标 Public）。风险被三层结构抵消：码为 100-bit 一次性（`security/src/bootstrap_code.rs:13-15`）、库中只存 SHA-256（`hash_bootstrap_code`）、消费为单事务（`persistence/src/bootstrap_repository.rs:134-173`，已用码必然 AlreadyUsed）。暴力枚举 100-bit 码不可行；登记为观察项。wave-five V5C-2 起认领改走登录同形预算（`bootstrap_limiter` `auth.rs:1004-1011`），本观察项的 DoS 面进一步收窄。 |
| NOTE | N5 | 生产代码存在 1 处 `unreachable!`——**已关闭（迭代三，E3c）** | 原状：`web/src/lib.rs:1512-1514` 的 `NonZeroU64::new(rutilus_api::OVERVIEW_RECENT_EVENTS)` else 分支 `unreachable!`。**处置（commit 8a9ab82/34315c8）**：升级为编译期断言——`web/src/lib.rs:1511` `const _: () = assert!(rutilus_api::OVERVIEW_RECENT_EVENTS > 0);` 在编译期钉死常量正性（注释 `:1505-1510` 说明 totality 论证与镜像断言位置），运行时 guard 保留为已被编译期断言证明不可达的防御分支（`:1512-1514`）。语义安全由编译器保证而非注释；§7.7 禁止清单本未列 `unreachable!`（只列 unwrap/expect/todo!/unimplemented!/主动 panic），现已在「禁止主动 panic」精神内完成机器校验。 |
| NOTE | N6 | Pin 模式验证器有意跳过链/主机名/有效期验证 | `infra-redfish/src/redfish_gateway.rs:14459-14484`：`PinnedCertificateVerifier::verify_server_cert` 只做精确指纹比对，不验证链/主机名/有效期（注释明确「Exact SHA-256 pinning replaces CA, hostname, and validity checks」），rustls 仍验证 CertificateVerify 签名（密钥持有证明）。与设计 §10.4「显示证书指纹 → 管理员明确 Pin」一致——Pin 决策发生在信任建立时（`web/src/lib.rs:1719` 先取证书后交凭据）。审查推断：可接受的设计决策；指纹更新后旧指纹立即失效（`TlsIdentityChanged` 路径），1.0.0 前建议纳入外部评估清单。 |
| NOTE | N7 | 审计追加失败不阻塞业务请求 | `web/src/auth.rs:3044`（`record_outcome` 对 append 失败静默忽略 `let _ = ...append_audit_event(...).await`，文档化 best-effort）。审计完整性 vs 可用性权衡（§16.3 要求记录，但审计故障不应使登录失败）；仓库层仍保证已写入事件的追加序正确（`persistence/src/audit_repository.rs:99-150`）。登记为已知权衡，建议未来提供审计健康度可见性；wave-five V5A-4 起追加失败的终态审计事件进有界补偿队列后台重试（`app/src/standalone_runtime.rs:89-109`），静默丢失面收窄。 |
| NOTE | N8 | macOS 系统信封镜像文件携带原始密钥字节 | `platform/src/system_secret_store.rs:21-27`（模块文档已如实声明：macOS Keychain 为权威、持久化镜像仅备份用途、无恢复消费者）。已登记于 known-limitations 的精神范围内；未来备份恢复功能必须重建 Keychain 条目而非仅恢复文件。审查确认现状为文档化限制，非静默缺陷。 |
| NOTE | N9 | 回环明文控制台的会话 Cookie 不带 Secure | `web/src/auth.rs:1880`（登录成功处 `secure = is_https(...)`，回环 http 下无 `; Secure`；`session_cookie` `:1515-1526`）。这是设计内行为（本地控制台必须可用），Secure 只在非 https 流量会发送 cookie 的威胁模型下才有意义——回环明文流量不离开本机；非回环监听已被 `site_runtime.rs:213` 强制 HTTPS。非缺陷，记录以明确边界。 |
| MEDIUM | W3S-1 | 改密路径可饿死登录的 Argon2 槽——**已修复**（wave-three，e768473） | 原状：改密派生与登录共用无界派生面，凭据持有者可借改密请求耗尽 Argon2 槽饿死登录。**修复（commit e768473）**：改密携带登录同形限速预算（`password_change_limiter` `web/src/auth.rs:1003`）；派生等待队列有界（`MAX_QUEUED_PASSWORD_DERIVATIONS = 8` `app/src/standalone_runtime.rs:152`、`PASSWORD_DERIVATION_QUEUE` `:173`），队列满答 503 HashGateBusy（`auth.rs:1819-1824`，503 即记录不写审计）——Viewer 不再能饿死登录派生槽。登记见 `known-limitations.md` §九（第三波块）。 |
| MEDIUM | W3S-2 | set-user-password 审计不具名 / 撤销失败伪装认证失败——**已修复**（wave-three，e768473） | 原状：改密审计事件不指名目标 principal，且会话撤销失败被记成认证失败（审计可问责性与 §16.3 要求不符）。**修复（commit e768473）**：`AuditAction::ChangePassword` 具名目标 principal（`domain/src/audit.rs:167, 188` 注释原文「names the principal whose credential the action replaces」）；撤销失败记 `session-revocation-failed`（`:364, 1288, 1448-1449`），不再伪装认证失败。登记见 `known-limitations.md` §九（第三波块）。 |
| MED-LOW | W3S-3 | 声明身份净化只逃逸 C0/C1——**已修复**（wave-three，e768473） | 原状：Hello 声明身份净化只处理 C0/C1 控制字符，bidi 控制类（LRM/RLM U+200E/U+200F 等）可原样进日志/显示（显示层欺骗面）。**修复（commit e768473）**：净化逃逸完整 bidi 控制类（`application/src/center/session.rs:112-136`，W3S-3 注释 `:136`）；测试 `declared_identity_sanitization_escapes_every_bidi_control_character`（`:1156`）、显示层 `a_hello_identity_mismatch_display_keeps_bidi_controls_escaped`（`:1187`）。登记见 `known-limitations.md` §九（第三波块）。 |
| MED-LOW | W3S-4 | 用户名预算被分布式失败锁死——**已修复**（wave-three，e768473） | 原状：用户名限速预算统计全部失败尝试（含来自任意地址的），5 个分布式地址各打满即可锁死一个用户名（DoS）。**修复（commit e768473）**：用户名预算只计呈现场地址（`web/src/auth.rs:117-118` 注释原文「counted per presenting address (W3S-4)」、`:1033`、`:1061-1062`）——每个地址的预算独立，分布式失败不能锁死用户名（每地址 20 次窗口上限仍界住）。登记见 `known-limitations.md` §九（第三波块）。 |
| LOW/NOTE | W3S-5..10 | 第三波其余安全 LOW/NOTE 组——**已修复**（wave-three，e768473） | 管理员口令路径时序均衡（`dummy_admin_derivation` `web/src/auth.rs:2607, 2681, 2806`，与 W3S-1 预算同界）、限速拒绝 warn 降级与逐调用拒绝判定（`application/src/center_sync.rs`）、CI 签名 secret 作用域化到存在性旗标（`.github/workflows/ci.yml:395, 620-626`，secret 值永不进 `if:` 表达式）。逐项登记见 `known-limitations.md` §九（第三波块 LOW/NOTE 组）。 |
| MEDIUM | V4R-2 | 改密成功不保留限速预留（每请求双派生循环）——**已修复**（wave-four，3a23b9b） | 原状：改密成功路径释放预留槽，凭据持有者可对同一请求循环两次派生（消耗翻倍）。**修复（commit 3a23b9b）**：改密成功保留其预留槽（`web/src/auth.rs:29` 注释原文「a successful change keeps its reserved slots (V4R-2)」、`:1001, 1099, 1134`）。登记见 `known-limitations.md` §九（第四波块）。 |
| MEDIUM | V4R-3 | 审计目标 principal 未持久化——**已修复**（wave-four，3a23b9b） | 原状：改密审计事件在响应 DTO 中具名目标，但持久轨迹不落 `target_principal_id`（重启后无从追查谁的凭据被替换）。**修复（commit 3a23b9b）**：`target_principal_id` 列 + 形状 CHECK（`migration/src/m20260813_000003_audit_failure_vocabulary.rs:328, 351-352`，`ck_audit_events_target_principal`——非 change-password 动作不得带目标 principal）。登记见 `known-limitations.md` §九（第四波块）。 |
| MED-LOW/LOW | V4S-2/V4R-4 | FailureKindResponse 无容错 fallback——**已修复**（wave-four，3a23b9b） | 原状：失败词汇枚举严格解析，未来词汇扩展会令旧控制台解析失败。**修复（commit 3a23b9b）**：`#[serde(other)]` fallback（`api/src/lib.rs:3558, 6093`），未来词汇保持旧控制台可解析。登记见 `known-limitations.md` §九（第四波块）。 |
| MED-LOW/LOW | V4S-3/V4R-8 | 管理 404 分支无哑派生 / 管理改密无预算——**已修复**（wave-four，3a23b9b） | 原状：三个管理 404 分支（未知用户/未知 principal）不跑哑派生（用户名存在性 oracle 残留面），管理改密路径无 change-password 预算。**修复（commit 3a23b9b）**：三个管理 404 分支均跑哑派生（`dummy_admin_derivation` `web/src/auth.rs:2607, 2681, 2806`），管理改密路径带 change-password 预算（测试 `unknown_principal_admin_changes_keep_the_404_when_the_derivation_gate_is_busy` `:6032`）。登记见 `known-limitations.md` §九（第四波块）。 |
| MED-LOW/LOW | V4S-5/V4R-6 | failed-unsupported 前缀无边界匹配——**已修复**（wave-four，3a23b9b） | 原状：站点对失败摘要的 `failed-unsupported` 前缀匹配无边界（如 `failed-unsupportedxyz` 也命中），攻击者可伪造分类。**修复（commit 3a23b9b）**：前缀匹配要求边界（精确或冒号分隔，`application/src/center_sync.rs:1496-1515`）。登记见 `known-limitations.md` §九（第四波块）。 |
| LOW | V4R-5 | 退款弹错地址条目——**已修复**（wave-four，3a23b9b） | 原状：限速退款从桶内弹出任意条目而非本地址条目（预算归因错位）。**修复（commit 3a23b9b）**：退款恰好弹出呈现场地址条目（`web/src/auth.rs:1137, 1243` 注释原文「the presenting address recorded (V4R-5) — never another」）。登记见 `known-limitations.md` §九（第四波块）。 |
| LOW | V4R-7 | 重绑端点永久冻结——**已修复**（wave-four，3a23b9b） | 原状：端点换身份重绑后，前站点绑定未撤销时重绑路径不推进，端点永久冻结（可用性面）。**修复（commit 3a23b9b）**：前站点绑定被撤销后重绑端点自愈重归位（`application/src/center/binding.rs:30, 763` 注释原文 V4R-7）。登记见 `known-limitations.md` §九（第四波块）。 |
| LOW/NOTE | V4S-1/6 | 第四波未来边界登记——**已登记**（wave-four，3a23b9b） | 修复归属未来边界处如实登记，不冒充已修复（`known-limitations.md` §九（第四波块）V4P-4..7/V4S-1/6 行）。 |
| MEDIUM | V5C-1 | TOTP 列表失败静默降级为仅口令——**已修复**（wave-five，e85560a） | 原状：登录路径列出 TOTP authenticator 失败时静默跳过 TOTP 验证（存储错误把登录降级为仅口令，MFA 静默失效）。**修复（commit e85560a）**：TOTP 列表失败 fail-closed（`web/src/auth.rs:1809` 注释原文「the sign-in fails closed (V5C-1) instead of falling back」、`:1813`），存储错误不再把登录静默降级。登记见 `known-limitations.md` §九（第五波块）。 |
| MEDIUM | V5C-2 | bootstrap 认领无限速预算——**已修复**（wave-five，e85560a） | 原状：认领路径不经过限速器（N4 观察项同面），认领洪泛可占满派生槽。**修复（commit e85560a）**：认领携带登录同形预算（`bootstrap_limiter` `web/src/auth.rs:1004-1011` 注释原文 V5C-2），认领洪泛被窗口预算界住；429 拒绝不写审计（B2 同款）。登记见 `known-limitations.md` §九（第五波块）。 |
| LOW | V5C-4 | 改密 401 不审计——**已修复**（wave-five，e85560a） | 原状：自改密路径的错误口令分支（401）不写审计（认证失败路径无记录）。**修复（commit e85560a）**：改密 401 分支记录 started+failed 审计（`web/src/auth.rs:2155, 2210, 2243` 注释原文 V5C-4，测试区 `:5750-5758`）。登记见 `known-limitations.md` §九（第五波块）。 |
| LOW | V5C-5 | TOTP 未来窗口行为未钉死——**已修复**（wave-five，e85560a） | 原状：未来窗口接受行为是实现的偶然结果，无文档无测试钉死（时钟快偏时行为不可预期）。**修复（commit e85560a）**：未来窗口接受行为钉死并文档化（`domain/src/totp.rs:13-15, 211-214, 398-405` 注释原文 V5C-5——接受即按自身 step 消费，代价文档化）。登记见 `known-limitations.md` §九（第五波块）。 |
| LOW | V5C-6 | observed_at 不记接收时间——**已修复**（wave-five，e85560a） | 原状：中心持久化事件把 `observed_at` 记成事件时间（两时钟混淆，审计时间线失真）。**修复（commit e85560a）**：事件 `observed_at` 如实记录接收时间、与事件时间两时钟分离（`application/src/center/projection.rs:25, 1310, 2743, 2779` 注释原文 V5C-6）。登记见 `known-limitations.md` §九（第五波块）。 |
| MEDIUM | V5A-4 | 终态审计追加失败静默丢失——**已修复**（wave-five，e85560a） | 原状：终态审计追加失败被静默忽略（N7 权衡面在终态判定处放大——终态已定但审计永不落）。**修复（commit e85560a）**：失败追加入有界补偿队列（`AUDIT_COMPENSATION_EVENTS = 256` `app/src/standalone_runtime.rs:97`、进程级队列 `:109`），后台 drain 重试（`:432-448, 573-578`）。登记见 `known-limitations.md` §九（第五波块）。 |
| MEDIUM | V5A-6 | 审计尾镜像毒化静默丢事件——**已修复**（wave-five，e85560a） | 原状：内存审计尾缓存锁毒化后控制台审计查询静默失败（事件看似丢失）。**修复（commit e85560a）**：毒化镜像回退持久化列表（`app/src/standalone_runtime.rs:436, 479, 514, 542` 注释原文 V5A-6），不再静默丢事件。登记见 `known-limitations.md` §九（第五波块）。 |
| LOW | V5A-7 | tls-trust-failed / csv-invalid 无生产者——**已修复**（wave-five，e85560a） | 原状：两条失败码入词汇表但无生产者（对应失败不写审计）。**修复（commit e85560a）**：TLS 指纹拒绝记 `tls-trust-failed`（`web/src/lib.rs:1848-1862`）、CSV 畸形记 `csv-invalid`（`:1908-1929`），路由测试 `:13315, :13429`。登记见 `known-limitations.md` §九（第五波块）。 |
| MEDIUM | V5A-9 | 中心拒绝码不稳定 / handler 侧 403 不审计——**已修复**（wave-five，e85560a） | 原状：§15.6 中心派发拒绝的 wire 码不稳定（解析侧脆弱），handler 侧 403 无审计。**修复（commit e85560a）**：拒绝携带稳定 wire 码（`api/src/lib.rs:6065, 6097`），handler 侧 403 记审计（`web/src/lib.rs:4105, 4172, 13226, 13241`）。登记见 `known-limitations.md` §九（第五波块）。 |

## 四、审查结论（0.9.0 启动项达成情况）

### 4.1 启动项达成

「安全审查（启动）：基于现有代码的审查与记录」**达成**：本记录即流程启动交付物。八个审查
范围 + §7.7 扫描全部完成，**每一项都有真实代码行号证据**，无 BLOCKER，NOTE 9 项（N1-N9，N8/N9 为后续修订追加；另 2 HIGH〔S3-1/S3-2，wave-one 已修复〕见第三节）
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
迭代十五（wave-one，2026-08-13，master 5cd75ae）：**对抗第一波发现 2 项 HIGH（S3-1 操作
历史 API 回声明文 BMC 口令、S3-2 首启未认领窗口 GuardedOnly 整面开放）并已修复**（commit
d3b966a，见第三节 S3-1/S3-2 行；另有 D4-1 定级 HIGH 同批修复）——时间线如实陈述：深度
审查批次（2026-08-12）无 HIGH，对抗第一波（2026-08-13）发现 3 HIGH，d3b966a 全部修复，
**当前 master 无 HIGH 残留**；S3-3（限速原子化）/S3-4（管理员设口令端点，5cd75ae）/
S3-5（cookie 前缀早退）同批处置；B1-B4/M1/N1-N9 行号按 wave-one 重写后的 auth.rs 全量重核。
迭代十七~十九（wave-three/four/five，2026-08-13，master e768473 / 3a23b9b / e85560a）：
**第三波安全发现 4 项（W3S-1..4）全部修复**（e768473：改密登录同形预算 + 派生队列有界、
审计具名 + session-revocation-failed、全 bidi 类净化、呈现场地址预算；LOW/NOTE 组
W3S-5..10 同批），第三波原 1 项 HIGH 经独立验证降级 LOW（登录限速器已界住声称泄漏面）；
**第四波安全发现 7 项（V4R-2/3/5/7、V4S-2/3/5）全部修复**（3a23b9b：改密保留预留、
target_principal_id 持久化、退款弹呈现场地址、重绑自愈、serde(other) fallback、404 哑
派生、前缀边界），V4S-1/6 未来边界如实登记；**第五波认证面 5 项（V5C-1/2/4/5/6）与审计
面 4 项（V5A-4/6/7/9）全部修复**（e85560a：TOTP 列表 fail-closed、bootstrap 登录同形
预算、改密 401 审计、TOTP 未来窗口钉死、observed_at 记接收时间、审计补偿队列、毒化镜像
回退、失败码生产者、中心拒绝稳定码 + 403 审计）；wave-five 的 5 项 HIGH（V5A-1/2/3、
V5E-1/2，审计可问责/中心协议面）已修复（见第三节头部时间线与 `known-limitations.md`
§九第五波块），**当前 master 无 HIGH 残留**（认证面）；新增行全部按当前 master 行号核实。

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
  自动化往返覆盖 10 个测试（`app/src/backup.rs` 测试区 `:1068-1421`）。
- 并发（范围 8）：写 Semaphore(1)、4 MiB 分块、8 MiB 帧、128 目标/4 并发批量。
- §7.7 扫描（范围 9）：唯一生产 `unreachable!` 为常量 totality guard（N5，已于迭代三关闭：
  编译期 `const _: () = assert!(...)` 钉死正性，`web/src/lib.rs:1511`），其余全部为
  防御性 `unwrap_or`。

### 4.3 需要演练 / 外部评估的项

| 项 | 说明 | 依据 |
|---|---|---|
| 独立 Secret 泄漏扫描 | ✅ 仓库级已落地（迭代三，E3b）：`security/tests/secret_leak_gate.rs`（3 规则 R1/R2/R3、**10 测试（V4I-3 重测）**、`ALLOWED_CONSTANT_HITS` 白名单 2 处、`test-support` crate 目录级豁免（E3b 原始提交 eefde7e）`:96-101, 1258`、深度审查批次 e8424df 补 `strings_catalog!` 宏体豁免 `:575, 1038-1043, 1521`、wave-one（73d480d）补间接赋值盲区 `:836`、wave-two（e59b14a）补跨字面量 PEM 片段盲区 `:886`、全 workspace 扫描全绿），**CI 独立步骤**（`ci.yml:285` Secret leak gate：`bash scripts/assert-tests-ran.sh 10 --locked -p rutilus-security --test secret_leak_gate`，`if: matrix.is_default`，machete 之后、wasm32 之前，W6-1 ran-断言 floor 10）；**运行时复核未做**：内存转储检查、API 响应抓包/日志复核仍为 1.0.0 发布评审建议项。milestone-status §7.1「Secret 泄漏检查」已转 ✅ 结构性 | `docs/milestone-status.md:459` |
| M1 时间侧信道处置 | ✅ 已处置：未知用户名路径已补哑 Argon2id 验证（commit 72eccb5，`web/src/auth.rs:1626, 1766`），验证方式 = 调用计数对称断言（`web/src/lib.rs:11292, 11356`）；残留面（disabled / credential-missing 分支）已于深度审查批次**证反并关闭**（B4，commit 8147bc9：`web/src/auth.rs:1771-1794` 补同款哑验证），见 §三 M1 行 | 本文档 M1 |
| 深度审查遗留项（LOW/NOTE） | ✅ 8 项已全部落地/处置（迭代七，2026-08-12，master 61b9cc5）：限流器桶键淘汰（T-D e7aef53，N3 关闭）/ i18n fragment 纯函数测试（T-H c4dd335）/ decode_failures 贯通测试（T-G 8482d85）/ AMI/HPE 真网关 E2E（T-I 044bae2）/ restore 预恢复副本（T-E 02459dc）/ free_port TOCTOU（T-F 83ff07f）/ 入网首刷绕端点门（T-B 4897b22）/ 快照 ETag 接线（决策 c，不实施）；另第 9 个提交 61b9cc5（secret-gate 白名单行号对齐 backup.rs 88/89，门禁漂移检测触发-修复闭环）；三批五维审计 APPROVE 记录见 `milestone-status.md` §7.5 | `docs/known-limitations.md` §九 |
| Pin 模式验证器外部评估（N6） | 设计内行为，但「跳过链验证」属于需要安全专家确认的权衡面 | 本文档 N6 |
| 真实设备认证矩阵 | 与凭据泄漏无直接关系，但影响「设备侧凭据处理」的整体结论（当前仅 mock 验证） | `docs/known-limitations.md:73-80` |

### 4.4 对 1.0.0「无已知凭据泄漏」验收的支撑判断

**结构性支撑成立，结论有条件成立**：

- 已满足的支撑面：BMC 凭据 at-rest 加密（XChaCha20-Poly1305 + AD 绑定 + 随机 Nonce，
  `security/src/lib.rs:184-251`）；Master Key 不入库明文且文件 no-clobber/非符号链接加载
  （`platform/src/master_key_file.rs:39-130`）；内存 Secret 包装 + zeroize + 全 Debug 脱敏；
  错误类型不回声秘密（`security/src/master_key.rs:446-472`）；审计类型构造上禁秘密
  （`domain/src/audit.rs:403, 468`）；API 不回声秘密（`web/src/lib.rs:1668` `credential_inventory`
  无秘密字段、`api/src/lib.rs:290-311`）；Center 投影/协议类型排除凭据
  （`application/src/center_sync.rs:1649`）；命令列与中心队列 payload at-rest 加密
  （`security/src/command_cipher.rs`）；备份包只有密文与受保护信封（`security/src/backup_package.rs:19-23`）；
  日志/span 对敏感值 skip_all（`app/src/main.rs:300, 407`）。
- 附加条件：该结论当前基于**代码审查与结构证据**；仓库级独立泄漏扫描已落地（迭代三 E3b：
  `security/tests/secret_leak_gate.rs` 3 规则、9 测试、扫描全绿），运行时抓包/日志复核与
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
> 修订：2026-08-13（迭代十五，wave-one 对抗修复，master 5cd75ae）——**2 HIGH（S3-1/S3-2）
> 发现并已修复**（d3b966a），另有 D4-1 定级 HIGH 同批修复；§三新增 S3-1/S3-2 行，§三
> 头部补 HIGH 口径时间线；§二 #2/#6/#7/#8/#9 与 §三 M1/B1-B4/N1-N9 的 auth.rs/lib.rs/
> backup.rs 行号按 wave-one 重写后逐处打开重核（d3b966a 重写 auth.rs +1119 行、web lib.rs
> +420 行；T-D 测试第三个更名）；备份 pin 24/23→26/25（`backup_snapshot.rs:646-647`）；
> Secret 门禁 8→9 测试；§四 4.1/4.2/4.3/4.4 相应更新；wave-one 27 项修复与 wave-two 61 条
> 发现的登记见 `known-limitations.md` §九。
> 修订：2026-08-14（迭代十七~十九，wave-three/four/five 对抗修复，master e768473 /
> 3a23b9b / e85560a）——§三新增第三波（W3S-1..4 + W3S-5..10 组）、第四波（V4R-2/3/5/7、
> V4S-2/3/5 + V4S-1/6 登记）、第五波（V5C-1/2/4/5/6、V5A-4/6/7/9）共 21 行；§三头部
> HIGH 口径时间线续记 wave-three 降级 1 + wave-four 1 + wave-five 5（审计可问责/中心协议面）
> 全部修复；§四 4.1 补迭代十七~十九段落；§4.3「独立 Secret 泄漏扫描」行补 V4I-3 重测
> （10 测试）并重锚 `milestone-status.md:392`→`:459`（该文档头注 +47 行推偏 + 复核注记 +4 行）；auth.rs /
> standalone_runtime.rs / center_sync.rs / binding.rs / projection.rs / domain audit.rs /
> totp.rs / api lib.rs / web lib.rs 新增行号全部按当前 master 逐处打开核实；wave-three/
> four/five 逐项登记见 `known-limitations.md` §九（第三/四/五波块）。
> 本文档为流程启动项记录，后续演练/外部评估结论应追加到对应小节。
