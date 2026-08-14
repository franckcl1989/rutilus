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
> **迭代十二已落地（2026-08-12，HEAD = 452a291，3 个提交）**：`318eadd`（fix(scripts)：
> drill-lib.ps1 证书 Pin 修复——Invoke-MockHttps 原用 `GetCertHashString()`（.NET Framework
> 上为 SHA-1）比对 mock-bmc 的 SHA-256 指纹恒失败（drill-kill-mid-operation 幂等断言健康
> 环境必然 FAIL），改为 C# 委托（脚本块回调在无 runspace 的 TLS 工作线程无法执行）
> SHA-256-of-DER 归一比对，与产品侧 `Sha256::digest(certificate_der)`
> （domain/src/endpoint.rs:490）逐字节同值，真实 mock-bmc 端到端验证（正确 pin→200、
> 篡改→拒绝）；同函数另修 2 缺陷（`[string]$Body=$null` 强转 '' 致 GET 带空
> StringContent〔ProtocolViolationException〕、Start-MockBmc 缺省 -Port 传空参数列表致
> Start-Process 参数校验异常——改传 '0' 由 mock-bmc 自选端口 + stdout URL 回读，.Port 恒为
> 真实端口，探针验证启动/连接/清理））、`64125e0`（fix(migration)：m20260810_000002 down
> 未恢复 000005 形状（MEDIUM）——拆 rebuild_up（000010 形状不变）/rebuild_down（严格 000005
> 形状：4 列 + role CHECK + 2 FK，无 site_id/scope CHECK，形状核实自
> m20260807_000005_product_users.rs:355-396），测试改 PRAGMA table_info 断言 + scoped
> 插入判别 + role CHECK 存活，负向实证旧代码下 FAILED；migration 38 测试全过、clippy/fmt
> 干净）、`452a291`（docs：深度审查边界登记——down_order_gate raw-CREATE-REFERENCES 盲区
> 活表案例（000002 role_assignments_rebuild REFERENCES instances/principals）、ci.yml
> ref_name 斜杠边界（可见失败、不 sanitize 为决策）、known-limitations §八 events 存储增长
> 登记、§五 drill TOCTOU 与 400ms 时序启发式、milestone-status down_order_gate 行数 1286）；
> 第二批五维深度审查（安全+并发 / 数据+前端+CI）无 BLOCKER/HIGH/MEDIUM 残留（MEDIUM 1 +
> LOW 3 已修复、NOTE 全部登记、对抗验证 13 项全部「维持」），详见 §7.4。
> **迭代十三已落地（2026-08-13，HEAD = 6bbdf1c）**：`6bbdf1c`（docs：re-anchor the
> cross-document line references after iteration twelve——迭代十二登记（0a5e64b 头注 +20 行）
> 与 §五 drill 修复（+15 行）再次推偏 17 处跨文档引用（含迭代九修复的 6 处 §7.1 锚，累积
> +38）；全部按当前 master 逐行核实后重新锚定（release-readiness 12 / security-review 1 /
> milestone-status 4）；注记：头注自检纪律只覆盖代码 file:line 引用、不覆盖跨文档引用，
> 建议 0.9.0 评审前做最终全量核对）。
> **收尾批次（2026-08-13，HEAD = c8bc30b，2 个提交——为人工复跑扫清前置）**：`d9a9a8e`
> （feat(scripts)：add the one-command drill runner——`scripts/drills/run-all-drills.ps1`
> （432 行）：顺序运行 5 个独立 drill（各自独立 powershell.exe 5.1 子进程、stdout/stderr
> 重定向 logs/、watchdog 超时 taskkill /T /F）、解析 DRILL PASSED/FAILED、0xC0000142/ConPTY
> launch failed 模式诚实注解、summary 文件（start/end/PS/OS/git head/二进制时间戳/product
> version/逐 drill 结果/totals）、-KeepWorkDir 透传、-Drill 单跑（别名容忍）、
> -DrillTimeoutMinutes（默认 30）、退出码 0 全 PASS / 1 有 FAIL；纯 ASCII、PARSE OK、无效
> -Drill 冒烟通过；五维审计 APPROVE）、`c8bc30b`（docs：sync the RESULTS.md references
> after the runtime cleanup——tmp/（4 探针 + 2 挂起 workdir）与 logs/（诊断 + 实跑日志）
> 运行时产物清理（约 178 MB，gitignore 覆盖不入库），RESULTS.md 3 处引用同步为「清理后
> 不再保留」措辞、证据结论零损失；3 个遗留 worktree（wb23-stress/wb24-e2e/wb25-version，
> 无未提交改动）移除、分支保留；首轮实跑历史记录（f6ef715 构建等）保持原样；审计
> APPROVE）；**复跑前置已齐备**：run-all 脚本 + 最新 debug 二进制（已确认即 HEAD 产物——
> cargo build 0 编译步骤，最后 Rust 源码提交 64125e0 早于二进制构建 23:36-23:37）+ 空
> logs//tmp/。
> **迭代十四（2026-08-13，HEAD = 6f8b698，4 个提交）——CI 首跑修复批次**：首个 GitHub
> push/CI run 暴露 4 类本地（Windows）不可见的解析/平台缺陷，已全部修复：`26ad869`（fix(ci)：
> quote the signing-skip echo——workflow 级 YAML 缺陷：`run: echo "signing skipped: certificate
> not configured"` 是 plain scalar、值含 ": " 被 YAML 解析为 mapping 指示符，workflow 文件整体
> 非法、每个 push 事件在解析期失败（run 31660470408 "workflow file issue"）；单引号修复后以
> yq/go-yaml（GitHub Actions 所用引擎）全文件解析通过——该文件此前从未被 GitHub 解析过，
> release-artifacts 的 CI 侧冒烟仍为跟进项，yq 成为本地校验路径）、`43fcbae`（fix(ci)：gate the
> release signing on env-mapped secrets——GitHub 拒绝 `if:` 条件引用 secrets context
> （"Unrecognized named-value: 'secrets'"，release-artifacts 9 处）；7 个签名相关 secret 改 job 级
> env 映射（env 值可消费 secrets）、受影响 `if:` 全部改比 env.X，表达式逻辑逐字节一致、步骤级
> env 物化不动；安全注记：job 级映射把 env 暴露面扩到全部步骤（值被 mask、无步骤 echo），与
> 物化步骤既有机制相同）、`c8ccb86`（fix(platform)：clear the linux-target clippy errors——首轮
> CI 暴露 3 处跨平台 lint 错误（Windows 本地构建从不编译）：`require_private_permissions` 的
> permissions 参数按值传入只读（改引用，Unix 孪生同步、调用点借用），2 个 Linux 透传 secret-store
> 函数 async 签名无 await（Linux 孪生保留签名 + 函数级 allow：Windows/macOS 孪生必须 await
> spawn_blocking 且 SystemSecretStore 调用点刻意 cfg-free，统一签名是设计）；linux 目标本地复现
> 三处全修、双平台零警告、workspace check/fmt/tests 绿）、`6f8b698`（fix(migration)：hold the
> test tempdir for the pool connection lifetime——4 个 connect() 辅助（audit_action_shapes /
> audit_execute_operation / center_tables / product_users）只返回 DatabaseConnection、TempDir 在
> 池的 eager 连接仍持有数据库时被 drop：Windows 不能删除打开的文件故测试存活，Linux unlink
> 成功、首个写语句创建 rollback journal 时 stat 已不存在的路径——SQLITE_IOERR_FSTAT /
> "disk I/O error"，即首个 ubuntu CI run 报告的失败；改为随连接一并返回 TempDir（存活期覆盖
> 连接），与 center_data_sites/center_role_sites 既有 tuple 形态一致）。**测试计数复核
> （2026-08-13，`cargo test --workspace -- --list` 口径）：总数 1731（lib/集成 1730 + doc 1，
> doc = test-support 头文档），与迭代十登记总数一致（迭代十登记的分解「lib/集成 1731 + doc 1
> = 1732」与 `--list` 口径不符——`--list` 总数 1731 已含 doc 1，即 lib/集成 1730）、迭代
> 十一~十四无 Rust 测试增删；per-crate
> 修正：infra-redfish 291→295（旧 291 为迭代三+四 bfb001e 实测，深度审查批次 6128a17 已 +4：
> redfish_gateway.rs 246→249、application_adapter.rs 18→19）与 test-support 55→54（历史 55 混入
> 头文档 doc-test 1，与新 `--list` 口径分离；54 = 26 lib〔mock_bmc/tests.rs 21 + mock_center/mod.rs 4 +
> mock_center/tls.rs 1〕+ 28 集成〔gateway_mock_bmc.rs〕），其余 per-crate 与迭代十登记一致）**。
> **迭代十五已落地（2026-08-13，HEAD = 5cd75ae，10 个提交）——wave-one 对抗修复批次**：第一波
> 对抗审查（2026-08-13，6 透镜并行攻击，38 条 → 定案 31 confirmed + 2 refuted〔C5-9/W6-6〕+
> 1 降级〔W6-1〕+ 4 半/部分）的 27 项确认发现全部修复：`8a4d271`（test(migration)：down_order_gate
> 补 raw `CREATE TABLE ... REFERENCES` 盲区——`*_rebuild` 暂存名归一活表（SQLite 改名即改引用）、
> FK 边跨文件提取，8→10 测试）、`2a4340b`（test(migration)：门禁源扫描递归进子目录，门禁 11
> 测试、25 迁移正扫全绿）、`bcef349`（ci：`scripts/assert-tests-ran.sh` 门禁 ran-断言〔Secret leak
> floor 8 / Migration floor 38〕+ `.github/CODEOWNERS` + cargo-deny 缓存注释按事实修正〔action 无
> 缓存步骤〕）、`e652831`（docs：首轮 CI 修复后的发布文档对账与计数复核——迭代十四登记、1731 实测、
> infra 291→295 / test-support 55→54 修正、24 处跨文档行号重锚）、`73d480d`（test(gates)：
> bare_sql_gate 内嵌 DML 盲区〔CTAS/TRIGGER 体〕+ secret_leak_gate 间接赋值盲区〔wrapper 形状/两步
> 间接，作用域感知传递解析〕，两门禁递归扫描 + build.rs 覆盖，漏报边界如实登记）、`6ca207c`
> （fix(application)：遥测时间戳非单调拒绝——ClockRollback 分类错误〔不钳制：不伪造从未存在的
> 时间〕+ 端点读门注册表注释如实化 + §九追加登记 N2-6/C5-8）、`3f312b2`（fix(ci)：三平台首跑失败
> ——ubuntu umask 0600 钉 fixture、windows cargo-deny-action 为 Docker 容器 action 仅 Linux 可跑
> 〔改 `matrix.is_default` 门控 + 删不声明的 version 输入〕、macos `trivially_copy_pass_by_ref`）、
> `31a4232`（fix(ci)：install-action 输入实为 `tool:`（单数）——首跑 `tools:` 被静默忽略致
> nextest/llvm-cov/machete/audit/zigbuild 从未安装、首个 nextest 步骤 "no such command" 死因；
> 三处 install 步骤改名 + 注释如实化 + macos 测试模块 cfg 门控）、`d3b966a`（fix：第一波 22 项
> 确认发现闭环——**2 HIGH（S3-1 操作历史 API 回声明文 BMC 口令已脱敏〔五个响应投影经 redacting
> helper 输出 [REDACTED]，域序列化保持无损供 at-rest 信封与中心载荷依赖〕、S3-2 首启未认领窗口
> 整面 GuardedOnly 开放已封〔PendingBootstrap 强制每路由会话 + 控制台 401 重决策〕）+ 1 HIGH
> （D4-1 中心控制台审计事件无法持久化已修〔m20260813_000001 扩展 action/outcome CHECK〕）** +
> 6 MEDIUM（C5-1/C5-2/C5-3/D4-2/N2-1/N2-3）+ 9 LOW（C5-4~C5-7/C1-2/S3-3/D4-3~D4-5）+ 4 NOTE
> （S3-5/D4-6/C1-3/C1-4）；m20260813_000002 重建八表 CHECK 家族；1787 测试绿）、`5cd75ae`
> （fix：wave-one 余 5 项——S3-4 管理员设口令端点〔`POST /api/v1/admin/users/{id}/password`，UI
> 表单保持 later milestone〕、W6-5 路由注册表双向防漂移门禁〔EDGE_ROUTES/CENTER_ROUTES 单一注册源 +
> ROUTE_TABLE 双向命名〕、N2-2 优雅关停有界〔TimeoutLayer + 10s GRACEFUL_DRAIN_TIMEOUT〕、
> N2-4 DisconnectOnDrop 清理僵尸 site〔移除死代码 prune_stale〕、C5-10 Hello 声明 instance id 对
> 证书身份校验〔identity-mismatch 词汇新增、无 wire 变更〕；1800 测试绿）。**测试计数复核
> （2026-08-13，`cargo test --workspace -- --list` 口径）：总数 1800（lib/集成 1799 + doc 1，
> doc = test-support 头文档）**，增量 1731→1800（+69，全部来自 wave-one 测试面）；per-crate 以
> 实测为准：rutilus 152 / api 82 / application 322 / center-protocol 30 / domain 209 /
> infra-redfish 295 / migration 48 / operation-engine 33 / persistence 202 / platform 32 /
> security 52（含门禁 9）/ test-support 54+1〔lib/集成 54 + 头文档 doc-test 1〕/ ui 141 / web 147；
> 相对迭代十登记的变化：migration 38→48、persistence 190+3→202、application 301→322、
> web 133→147、rutilus 145→152，infra 295 / ui 141 / test-support 54 不变。门禁计数同步：
> security 8→9、down_order_gate 8→11、migration 38→48（`assert-tests-ran.sh` 的 floor 8/38 为
> 下界 pin、低于新实测值，保持不动）；迁移文件 23→25（新增 m20260813_000001_audit_center_actions /
> m20260813_000002_endpoint_health_checks）、迁移测试文件 21→23、备份 pin 24/23→26/25
> （`persistence/src/backup_snapshot.rs:646-647`）。
> **迭代十六已落地（2026-08-13，HEAD = e59b14a，2 个提交）——wave-two 对抗修复批次**：
> `a4ab972`（fix(ci)：assert-tests-ran.sh 单数字 pin 修复——`[1-9][0-9]*` 拒绝个位数 pin（CI
> 首跑 Secret leak gate pin 8 被拒），补 `[1-9]` 独立分支；**该提交还意外携带依赖供应链批次
> （F4-1..7：六 action SHA 钉版 + dependabot.yml + deny 理由修正 + tokio-util 单一来源 +
> audit 忽略列表锁步），e59b14a 提交说明如实披露此混合提交事实**）、`e59b14a`（fix：第二波
> 61 条发现中 60 项确认修复 + F1 追加发现——**2 HIGH（T1-1 路由门权限级检查、E3-1 绑定轮询瞬态
> 错误不再当撤销）+ 1 HIGH 组（D6-1..5 文档登记）** + MEDIUM-HIGH（T1-2 裸 SQL 门禁剥注释、
> T1-5 JSON 诊断层可证伪测试、E3-2 identity-mismatch 站点分类 + 三次拒绝中止）+ MEDIUM
> （P1-1..3 索引化/批量查询、P2-4..7 单事务/流式/句柄复用、P3-8..10 SQL 聚合/单事务/增量重连、
> E3-3..6 回拨降级/分类三面/终态如实/跳过 warn、T1-3/4/6/7 门禁盲区封闭、F4-1..7 供应链、
> A5-1 文档修正）+ LOW/NOTE（E3-7..10、A5-2..8、T1-8..12、F4-4..7、P4-12、D6-6..12）；
> 全部门禁复跑绿：fmt 干净、clippy `-D warnings` 零警告、**1837 测试 0 失败（37 新增）**；
> lipo `-verify_arch` 参数顺序修正（run 31674299719 首次真实执行暴露）；逐项登记见
> `docs/known-limitations.md` §九（第二波块）与 §7.6。
> **迭代十七已落地（2026-08-13，HEAD = e768473，1 个提交）——wave-three 对抗修复批次**：
> 第三波对抗审查（4 透镜旋转：修复验证 / 安全 / 并发 / 契约，30 条 → 29 confirmed + 1 HIGH
> 降级 LOW〔验证者证明登录限速器已界住声称的泄漏面〕）的 29 项确认发现全部修复（`e768473`：
> MEDIUM-HIGH〔W3F-1 单候选修复不再合并异目标 dispatch〕+ MEDIUM〔W3S-1 改密登录同形预算 +
> 派生队列有界 8 等待者/503 HashGateBusy、W3S-2 set-user-password 审计具名 +
> session-revocation-failed、W3C-1 响应 DTO 不再拒未知字段、W3C-2 操作 list/detail 携带
> 失败分类、W3F-2 HEAD 走 GET 授权入口、W3N-2 TTL 再投递竞态愈合〕+ MEDIUM-LOW〔W3S-3
> 全 bidi 控制类逃逸、W3S-4 用户名预算按呈现场地址、W3C-3 failed-unsupported 前缀识别、
> W3F-3 括号/CTE 拼写捕获 + AS (VALUES) 残差如实登记、W3N-3 重复 offer 进度入重放映射〕+
> LOW/NOTE 组〔W3S-5..10 / W3C-4/5 / W3F-4/5 / W3N-1/4/5〕）；落地前门禁复跑全绿：fmt
> 干净、clippy `-D warnings` 零警告、**1862 测试 0 失败（25 新增）**；逐项登记见
> `docs/known-limitations.md` §九（第三波块）与 §7.6。
> **迭代十八已落地（2026-08-13，HEAD = 3a23b9b，1 个提交）——wave-four 对抗修复批次**：
> 第四波对抗审查（4 透镜：修复交互 / 安全 / 性能 / 集成，30 条 → 29 confirmed + 1 HIGH
> 双透镜双确认〔V4I-1/V4R-1〕）的 29 项确认发现全部修复（`3a23b9b`：**1 HIGH（V4I-1/V4R-1
> 审计 outcome CHECK 十三码失败词汇 m20260813_000003 + 域-CHECK 双向绑定测试）** +
> MEDIUM-HIGH（V4P-1 `list_operations_classified` 单查询消 N+1）+ MEDIUM（V4P-2 中心跟踪
> 视图 IN 查询 + offer 扫描界窗、V4P-3 单候选回退读有界/多候选刻意无界、V4I-2 三中心信封
> 兼容、V4R-2 改密成功保留限速预留、V4R-3 `target_principal_id` 持久化 + 形状 CHECK）+
> MEDIUM-LOW/LOW/NOTE（V4S-2/V4R-4 `#[serde(other)]` fallback、V4S-3/V4R-8 三管理 404
> 哑派生 + 改密预算、V4S-5/V4R-6 前缀边界匹配、V4R-5 退款弹呈现场地址、V4R-7 重绑自愈
> 重归位、V4I-3/4 门禁 pin 重测〔secret 10 / migration 50〕、V4I-6 TODO 措辞、
> V4P-4..7/V4S-1/6 未来边界如实登记）；落地前门禁复跑全绿：fmt / clippy `-D warnings`
> 零警告、**1878 测试 0 失败（16 新增）**；逐项登记见 `docs/known-limitations.md` §九
> （第四波块）与 §7.6。
> **迭代十九已落地（2026-08-13，HEAD = e85560a，1 个提交）——wave-five 对抗修复批次**：
> 第五波对抗审查（4 透镜：迁移 / 审计可问责 / 中心协议端到端 / 新鲜正确性）25 条发现
> **全部 confirmed（含 5 HIGH）**，全部修复（`e85560a`：**5 HIGH（V5A-1 执行审计 CHECK 31
> 码 m20260813_000004〔wave-four 重建冻结的 17 个写家族恢复审计并执行〕、V5A-2 持久审计表
> 生产读面〔控制台尾启动预热 + 有界持久回退〕、V5A-3 执行审计归因随姿态/操作来源、
> V5E-1 回执计分回退持久 offer 事实、V5E-2 revoke-before-rebind 强制）** + MEDIUM/MED-HIGH/
> LOW（V5C-1 TOTP 列表失败 fail-closed、V5C-2 bootstrap 认领登录同形预算、V5A-4 审计补偿
> 队列 256 + 后台 drain、V5A-6 毒化镜像回退持久列表、V5A-7 tls-trust-failed/csv-invalid
> 生产者、V5A-9 中心拒绝稳定 wire 码 + 403 审计、V5E-3 归属吸收死信行、V5E-4
> CenterOperationResponse failure_kind、V5E-5 重绑退休亡实例 offer、V5C-4 改密 401 审计、
> V5C-5 TOTP 未来窗口钉死、V5C-6 observed_at 记接收时间、V5M-1..4/V5A-10 词汇绑定/字节级
> down/下迁可观测/actor 钉死）+ CI wasm 产物新鲜度门禁真修复〔路径 remap + 分隔符归一 +
> rust-src 显式安装 + 失配取证上传，宿主机工具链三元组残差如实登记〕）；落地前门禁复跑
> 全绿：fmt / clippy `-D warnings` 零警告、**1913 测试 0 失败（35 新增）**（2026-08-14
> `cargo test --workspace -- --list` 实测同数：lib/集成 1912 + doc 1；per-crate 实测：
> rutilus 167 / api 85 / application 361 / center-protocol 30 / domain 212 / infra-redfish
> 295 / migration 57 / operation-engine 34 / persistence 219 / platform 32 / security 53 /
> test-support 54+1 / ui 141 / web 172；相对迭代十六：migration 50→57、application
> 339→361、web 148→172、rutilus 158→167、persistence 209→219、domain 209→212、api 84→85，
> 其余不变）；迁移文件 25→27（新增 m20260813_000003_audit_failure_vocabulary /
> m20260813_000004_audit_operation_vocabulary）、迁移测试文件 23→25；逐项登记见
> `docs/known-limitations.md` §九（第五波块）与 §7.6。
> **迭代二十已落地（2026-08-14，HEAD = 7c6ac9d，2 个提交）——wave-six 对抗修复批次**：
> 第六波对抗审查（6 透镜：并发 / 安全 / 数据迁移 / 中心协议 / web+UI+CI / 测试质量与文档）
> 并行攻击 wave-five 状态，58 条发现 → 跨透镜去重 54 条交独立怀疑者核验 → **48 confirmed +
> 3 partial + 3 refuted**；48 项确认发现全部修复（`fcf7257`，52 文件 +5659/-830）+ 3 项链式
> 发现与 A1 新拒绝码接线（`7c6ac9d`，11 文件 +841/-101）：**2 HIGH（R6-C-1 并发双派发铸双
> id 双执行——per-site dispatch 闸门临界区、R6-E-01 Unknown 后重派发逃过 inbox 去重——
> `UnknownOutcomePending` 类型化拒绝）+ 1 MEDIUM 组（R6-C-2 rebind TOCTOU、R6-C-3 停机排空
> 补偿队列、R6-E-02 吊销站可派发、R6-E-03 re-home 回执仲裁、R6-E-04 outbox 剪枝 + 定向查询
> （`m20260814_000001`）、R6-S-1 会话撤销 fail-open、R6-S-3 secret-gate 标识符集、R6-D-1
> down_order_gate 分号、R6-W-1/2 wasm 门禁 known-red 真修复、R6-W-3 伪造 center 归因 400、
> R6-W-6 制品 2 GiB 封顶、R6-E-11 审计偏移分页、R6-A1 拒绝码 409 接线）** + LOW/NOTE 组
> （补偿队列批次、认证/限速面 8 项、secret-gate 5 项含 RUTMK002 master-key rewrap、CI 三步
> ran-断言 + `--expect-tests` 名字断言、数据面 6 项、协议面 3 项、run_standalone 死代码）；
> **1963 测试 0 失败**（2026-08-14 实测，`cargo test --workspace -- --list` 口径：lib/集成
> 1962 + doc 1 = 1963；增量 1913→1963（+50）——提交消息声称的 1958/45 为 fcf7257 时的中间
> 计数，链式提交 7c6ac9d 另 +5；per-crate 实测：rutilus 167→175 / api 85 / application
> 361→371 / center-protocol 30 / domain 212 / infra-redfish 295 / migration 57→59 /
> operation-engine 34 / persistence 219→228 / platform 32→33 / security 53→59（含
> secret_leak_gate 15） / test-support 54+1 / ui 141→142 / web 172→185），fmt / clippy
> `-D warnings` 干净；wasm 产物再生成（A6，
> 1.97.1 工具链 + 已登记 remaps）；新迁移 `m20260814_000001_center_outbox_operation_ids`
> （迁移文件 27→28、迁移测试文件 25→26；旧静态备份 pin——backup_applied 28 / supported 27，
> 原 `backup_snapshot.rs:646-647`——由 R6-D-2 改为动态派生 `Migrator::migrations().len()`，
> 现 `:489, 1043, 1074-1075, 1115-1116`（wave-seven/eight 推偏后 W9-D-2 重锚），各文档对该 pin 的引用按新事实同步）；逐项登记见
> `known-limitations.md` §九（第六波块）与 `docs/r6-findings/`（A1-A6 + A8 区域登记）；
> refuted 3 条含 R6-W-3 inbox 污染半边（验证：回执走 offer 定向查询与既有查重）。
> **迭代二十一已落地（2026-08-14，HEAD = a0b2bc0，1 个提交）——wave-seven 对抗修复批次**：
> 第七波对抗审查（7 透镜：修复验证 / 安全 / 并发 / 数据迁移 / 中心协议 / web+UI+CI / 性能）
> 并行攻击 wave-six 状态，40+ 条发现 → 跨透镜去重约 30 条交 4 个独立怀疑者核验 → **27
> confirmed + 4 refuted（W7-P-10 已登记设计、W7-L-2 已登记决策、W7-C-5 不可达、W7-H-1
> 前提被 runner-images 六代历史源码证伪）+ 3 partial 降级**；27 项确认发现全部修复
> （`a0b2bc0`，34 文件 +4591/-360，5 个区域修复 agent A1-A5 并行 + 主 agent 集成）：
> **3 HIGH（W7-E-1 WaitingRemote 后 Succeeded 回执被状态机吸收永久卡死——Succeeded lead-in
> 补 RemoteTaskCompleted 走既有 WaitingRemote→Verifying→Succeeded 路径、W7-S-1 中心侧制品流
> 完全没有 2 GiB 封顶——decode_manifest 超 cap 吸收拒绝、W7-P-1 per-site 闸门内 5 次全局扫描
> 串行化——幂等扫描改 endpoint 作用域 + 新索引）** + MEDIUM 组（W7-F-1=W7-E-2 剪枝加实例
> 维度、W7-E-3 Unknown 确认改跨实例查询（新 operation_id 单列索引）、W7-F-3=W7-E-4 Unknown
> 扫描补 target 维度、W7-C-1 注册后 binding 复查自断、W7-C-2 registry 注册代代际校验、
> W7-C-3 Center 姿态补偿 drain 接线、W7-P-2 定向读 NULL 存在性门、W7-P-6 me_limiter 剪枝、
> W7-F-2 restore 标记残留预检、W7-D-1 审计分页 Id 决胜列 + 三列覆盖索引
> `m20260814_000002`、W7-M-1 assert-tests-ran.sh 全限定名）+ LOW/NOTE 组（W7-C-4 停机顺序
> 调换、W7-E-8 flush 代际探针、W7-F-7a revoke 取闸门、W7-P-7 闸门键回收、W7-F-4 rewrap
> 失败降级 warn、W7-D-2 drain 镜像已提交事件、W7-N-2 offset 文案、W7-L-3/N-1 UI 分页体验、
> W7-D-5 down_order_gate 三盲区〔注释藏 DROP / RENAME 改引用 / 引号内分号〕、W7-D-6
> bare_sql_gate 逐段判定、W7-D-7 000001 事务化 + 往返测试）；**顺带修复**：`&Outbox` blanket
> 缺 find_offer_by_operation 委托——R6-E-04 定向读自 wave-six 起在生产运行时被静默遮蔽走全量
> 扫描，两条委托补上；**1997 测试 0 失败**（2026-08-14 实测，`--list` 口径：lib/集成 1996 +
> doc 1，增量 1963→1997（+34）；per-crate 实测：rutilus 175→183 / api 85 / application
> 371→380 / center-protocol 30 / domain 212 / infra-redfish 295 / migration 59→65 /
> operation-engine 34 / persistence 228→236 / platform 33 / security 59（含 secret_leak_gate
> 15） / test-support 54+1 / ui 142→144 / web 185→186），fmt / clippy `-D warnings` 干净；
> 迁移文件 28→30（新增 `m20260814_000002_audit_paging_index` / `m20260814_000003_center_
> outbox_operation_lookup`）、迁移测试文件 26→28；wasm 产物再生成（A4）；逐项登记见
> `known-limitations.md` §九（第七波块）与 `docs/r7-findings/`（A1-A5 区域登记）。
> **迭代二十二已落地（2026-08-14，HEAD = 6d5e90e，1 个提交）——wave-eight 对抗修复批次**：
> 第八波对抗审查（7 透镜：修复验证 / 安全 / 并发 / 数据迁移 / 中心协议 / web+UI+CI / 性能）
> 并行攻击 wave-seven 状态，25 条发现 → 跨透镜去重约 20 条交 3 个独立怀疑者核验 → **16
> confirmed + 1 refuted（W8-C-3 代计数器回绕，双不可达）+ 5 partial 降级**；16 项确认发现
> 全部修复（`6d5e90e`，18 文件 +1958/-142，4 个区域修复 agent A1-A4 并行 + 主 agent 集成）：
> **1 HIGH（W8-E-2 W7-E-3 的「未决路径」孪生漏洞——re-home 时非终态操作的单候选修复读仍
> per-site，判「从未入队」同 id 重投（多候选铸新 id）→ 同一物理写双执行；修复读全部换跨实例
> 查询，命中他站 offer = 已在飞 → 返回既有 id 不重投，顺带修掉跨站异目标复用旧 id 的潜伏
> 怪癖）** + MEDIUM 组（W8-F-2 target 裸字符串比对无规范化——`canonical_target_key`
> 百分号解码+小写+去尾斜杠两侧同函数、W8-P-1=F-6 端点全历史扫描 + 32766 参数硬顶——state
> 过滤 JOIN 进 id 查询 + IN 分批 999、W8-C-1=F-1 Center 停机顺序与 W7-C-4 纪律相反——两分支
> 调序 + 确定性两序区分测试、W8-D-1 000003 漏 use_transaction——补覆盖 + 往返测试）+
> LOW/NOTE 组（W8-D-2=C-2=F-3 审计尾三模式分叉——offset==0 查询侧规范序排序、W8-S-2=W-1=F-9
> 门禁注释剥离器四引号态、W8-P-5 connections Vec 回收、W8-E-4 mock 对齐生产、W8-C-6 注释
> 澄清、W8-W-5 文案臂、W8-E-1 projection 注释如实化、W8-D-3=F-10 混合对错误文案+运维指引、
> W8-E-3=S-1 user-manual 对账小节、W8-W-2/3/4 重锚与 pin 注释）；**2013 测试 0 失败**
> （2026-08-14 实测，增量 1997→2013（+16）；per-crate：rutilus 183→187 / application
> 380→387 / migration 65→68 / persistence 236→237 / ui 144→145，其余不变），fmt / clippy
> `-D warnings` 干净；wasm 产物再生成（A4，二次生成字节一致）；逐项登记见
> `known-limitations.md` §九（第八波块）与 `docs/r8-findings/`（A1-A4 区域登记）。
> **迭代二十三已落地（2026-08-14，HEAD = ba110ce，1 个提交）——wave-nine 对抗修复批次**：
> 第九波对抗审查（7 透镜）并行攻击 wave-eight 状态，约 22 条发现 → 去重约 14 条交 3 个
> 独立怀疑者 → **13 confirmed + 1 refuted（W9-D-4 按「历史点-时登记保留原文」惯例）+ 多条
> PARTIAL 降级**——**本轮无一条发现按声称的 HIGH/MEDIUM 成立**：最强的 W9-C-2（跨实例
> check-then-act）两条承重前提均被代码证伪（生产无秒级 write_gate 长占者——备份仅对已停止
> 实例运行；真实 re-home 模型要求旧站吊销使「两站各自执行」不成立）降为加固项，点段绕过族
> 被攻击透镜漏掉的 `has_resource` 精确匹配门阻断降为登记，acked keeper TTL 黑窗判为 W8-E-2
> 正确性修复的必要代价降为登记。13 项确认修复全部落地（`ba110ce`，24 文件 +2231/-78，4 个
> 区域修复 agent A1-A4 并行）：**W9-C-1 三姿态停机窗口**（server drain 移到 final drain 前，
> Edge/Center 各配「固定序过、旧序必败」双向测试，Center 版经 derivation-gate 钩子确定性）、
> **W9-C-2 加固**（重投后 settle_duplicate_offers 复核去重，任意交错收敛至恰一 pending 行）、
> **W9-E-3 三态穿出**（单候选跨实例读 2→1，两读间竞态结构性消除）、**W9-D-1 十个建表迁移
> 事务化**（缺陷第三次复发面收口，26/26 多语句迁移全覆盖 + 3 枚往返测试，机械检查建议登记）、
> **W9-S-2 restore 一致性检查**（Ready 行↔文件双向核对 + ArtifactFileMissing 显式分类 +
> 备份侧 warn）、**W9-S-3 流式分发**（1 MiB 分块 + 容量 1 有界通道）、**W9-T-1 两个 acked
> 测试**（生产 acked 维度零钉扎收口）、W9-F-6 贯通测试、W9-CI-1/2 注释、W9-D-1/D-2 锚点、
> W9-D-3 手册限定、W9-T-2/T-3 测试补缺；**2029 测试 0 失败**（2026-08-14 实测，增量
> 2013→2029（+16）；per-crate：rutilus 187→191 / application 387→393 / migration 68→74 /
> persistence 237 / ui 145，其余不变），fmt / clippy `-D warnings` 干净；逐项登记见
> `known-limitations.md` §九（第九波块）与 `docs/r9-findings/`（A1-A4 区域登记）。
> **迭代二十四已落地（2026-08-14，HEAD = 57617bb，1 个提交）——wave-ten 对抗修复批次**：
> 第十波对抗审查（7 透镜）并行攻击 wave-nine 状态，约 25 条发现 → 去重约 19 条交 3 个独立
> 怀疑者核验 → **13 项确认修复 + 2 项建议并入既有登记 + 派发族 3 项经部署模型仲裁降注释
> 修正**。本轮实质收获 = **制品条件族**（D-1 缺文件楔死整同步面 / D-2 空截断静默丢失 /
> E-2 半套无界累积，三项 MEDIUM 全 CONFIRMED）：持久失败在 report_artifacts 内**吸收**
> （error 日志带修复路径、游标停在制品前、offer 通道存活、文件恢复自动愈合）、EOF 字节
> 与声明 size 比对（`ArtifactSizeMismatch` 带诊断）、outbox 半套按 artifact_id 退休收敛；
> 「置 Failed 终态」经三层证据机械不可行（domain 拒绝终态覆写 + store TerminalConflict），
> 替代语义如实论证登记。核验员的重要推翻：C-1 自败分支机制被 axum 0.8.9 依赖源码推翻
> （serve 不可报错、resolve ⟹ 连接任务已排空，分支不可达）——修复理由改为分支一致性；
> F-1 派发族经部署模型仲裁（单活动实例 + RuntimeLock + R6-C-1 闸门）降为 settle 注释修正 +
> 幂等 re-settle 防御性补强。**2036 测试 0 失败**（2026-08-14 实测，增量 2029→2036（+7）；
> per-crate：application 393→400 / rutilus 191 / migration 74，其余不变），fmt / clippy
> `-D warnings` 干净；逐项登记见 `known-limitations.md` §九（第十波块）与
> `docs/r10-findings/`（A1-A2 区域登记）。
> **迭代二十五已落地（2026-08-14，HEAD = eda3810，3 个提交）——wave-eleven 对抗修复批次**：
> 第十一波对抗审查（7 透镜）并行攻击 wave-ten 状态，发现集中在制品流收尾与跨文档锚点纪律两块。
> 代码侧（`eda3810`，fix(application)，668+/-145）：**W11-P-1 吸收后停滞无界**——吸收保持连接
> 存活、报告每连接只跑一次、心跳跨过所有空闲超时，稳定网络下重试永远不会到来；停滞计时器在
> 一个重连周期后主动结束连接，借 connect loop 退避让重试有界发生。**W11-D-3 同尺寸摘要不符**——
> 字节数与 manifest 一致但字节与声明 digest 不符的文件此前会完整分发（错字节入库）；现流式
> SHA-256 比对，不符入吸收族（多一次内存内哈希、零额外 I/O）。**W11-F-1 不可读文件**——目录
> 占位符等（PermissionDenied / IsADirectory）原走泛型读错误风暴；现同缺文件族吸收。
> **W11-F-2/C-2/C-3 派发台账**——每次派发入队精确记账（`distribution_entries`），失败退休只扫
> fresh partial set（修「队列最老窗口被无关条目占满时退休够不到」的窗口突破），零入队失败退休
> 为空，退休失败升级为轮次错误绝不吞。**W11-S-1 内容行 ack 即删**——终态投递，生产仓库删除被
> ack 的内容行（剪枝永不触碰 acked 行），退休路径复用同语义清掉退休半套。摘要校验使 5 个旧测试
> 的占位 digest 与存储字节不符被吸收——全部改为按真实字节哈希；补缺的退休升级测试（armed-outbox
> helper 原无调用方）；停滞臂改无 expect/unwrap 绑定（`ignored_unit_patterns` / `expect_used` /
> `clone_on_copy` 三 lint 修复）、heal 测试 timeout-join-result 三层显式匹配；旧「缺文件不拖连接」
> 「瞬态读错误仍中止」2 测试被新 absorption/heal 与 classification 测试语义覆盖后合并移除。门禁
> 全绿：fmt / clippy `-D warnings` 零警告 / **2038 测试 0 失败**（2026-08-14 `--list` 口径实测；
> 增量 2036→2038：center_sync 49→51〔+4 新 −2 合并〕、application 400→402，其余 per-crate 与
> wave-ten 登记一致）。
> 文档侧（`d7f1a07` docs + 本登记提交）：**W11-T-1 跨文档锚点机械门禁**
> （`scripts/check-doc-anchors.sh`，CI `Doc anchor gate` 步骤 `ci.yml:302-304`）——十轮审计反复
> 暴露手工重锚系统性漏检（wave-six 推偏 ~+98 锚点五轮未被发现），门禁机械化：越界硬失败 + 内容
> 指纹 review 级 + 裸 `:NNN` 续引最近路径继承（W11-T-2）+ r*-findings 点-时登记豁免（W9-D-4
> 惯例）+ 按文件行数缓存；**门禁首跑即抓出 6 处指纹级漂移与 73 处此前完全不可见的裸续引越界**，
> 全部按符号逐行核验重锚（ui/src/lib.rs 两次非均匀推偏 +104/+111 下约 20 处、ci.yml 门禁步骤
> 接入 +15 再推偏 34 处、center_sync.rs W11 推偏 17 处）；门禁自身首轮也暴露并修复两处盲区
> （续行裸引不可见、背引号内逗号续接数），残余盲区（token 共享漂移等）如实登记于脚本头；
> **1130 引用全在界**。逐项登记见 `known-limitations.md` §九（第十一波块）与 `docs/r11-findings/`
> （A1-A3 区域登记）。
> 所有条目均基于真实代码/测试事实，标注来源文件与测试名；不写设计
> 文档没有且代码不支持的内容。设计基线见仓库根目录 `redfish-management-product-final-design.md`
> （修订冻结版）。全文「file:line」引用已逐一核对当前 master 实际行号（2026-08-13 复核，wave-one
> 触面 auth.rs/web lib.rs/ci.yml 等按当前值重锚；**2026-08-14 复核，迭代十七~十九（wave-three/
> four/five，HEAD = e85560a）新增条目全部按当前 master 逐行核实，第六轮验证器 R6-1 触发的
> 既有锚点全量重锚亦同批完成**——auth.rs/center_sync.rs/web lib.rs/api lib.rs/domain audit.rs/
> ui lib.rs/ci.yml/operation_path.rs/backup_snapshot 等推偏锚点按当前行号修正，R6-3 确认的
> 登记时即错锚点（stress_capacity 3 测试 336/585/832、operation_engine.rs:1763、
> redfish_gateway.rs:28807）已修正并在 `release-readiness.md` 头注注明；§7.4/§7.5 历史批次的
> 登记保留其当时 HEAD 下的事实）：§一-§五 的事实锚定冻结时 commit 4ad8c4a，行号一律以当前
> master 为准。

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
  （`center-protocol/src/negotiation.rs:178` `GOLDEN_LEDGER_HASH`）；
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
| 账本 Hash 同时被冻结记录与中心协商 golden 钉死（见 §1.5） | `release_baseline.rs:1577`、`center-protocol/src/negotiation.rs:287` |

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
| 数据库 Schema | 21 个 migration（`m20260805_*` 11 + `m20260807_*` 8 + `m20260810_*` 2）；迭代三/四新增 2 个（`m20260812_000001_resource_decode_failures`、`m20260812_000002_resource_feature_lists`），迭代十五（wave-one）新增 2 个（`m20260813_000001_audit_center_actions`、`m20260813_000002_endpoint_health_checks`），迭代十八（wave-four）新增 `m20260813_000003_audit_failure_vocabulary`、迭代十九（wave-five）新增 `m20260813_000004_audit_operation_vocabulary`，现共 **27 个** | `migration/src/`（迁移测试 `migration/tests/initial_storage.rs`、`migration/tests/resource_feature_lists.rs`、`migration/tests/audit_center_actions.rs`、`migration/tests/endpoint_health_checks.rs`、`migration/tests/audit_failure_vocabulary.rs`、`migration/tests/audit_operation_vocabulary.rs`） |
| UI 导航 | 17 个视图（`ConsoleView::ALL: [ConsoleView; 17]`：Overview/Groups/Credentials/AddEndpoint/Import/Audit/Capabilities/Operations/Events/Artifacts/Telemetry/Diagnostics/Users/Sessions/CenterSites/CenterOperations/CenterBindings） | `ui/src/lib.rs:2902` |

## 四、0.8.0 期间新增能力盘点（简表）

| 面 | 新增内容 | 事实来源 |
|---|---|---|
| 命令家族（12 个全部落地） | 全部 12 个 `RedfishCommand` 家族有产品映射：account（5 操作）、单资源动作（system/manager/chassis reset 与 manager.reset-to-defaults、power-supply.reset 共 5）、log.clear、control.update、telemetry（7：enable + metric/report definition 生命周期）、event 订阅（2）、boot/secure-boot（CSDL 面 4）、update（patch/http-push/multipart 3 路径）、oem（NVIDIA 9 个类型化 action） | `release_baseline.rs:646-659`（`REDFISH_COMMAND_FAMILIES`）；`domain/src/redfish_command.rs:3069`（12 变体）；telemetry 家族落地 merge 8587f72 |
| OEM 读取 | 新增 AMI/HPE/LiteOn/Delta 4 个读取家族（6 个读取面：AMI `AmiServiceRoot` + `ConfigBmc`、HPE `HpeiLoServiceExt` + `HpeiLo`、LiteOn 电源、Delta 电源）；叠加既有 Dell/NVIDIA/Lenovo/Supermicro，14 个 OEM feature 全编译 | commit 1618577（`feat(infra-redfish): read the ami hpe liteon and delta oem families`）；`api/src/lib.rs` §0.5.0 OEM family member 面；`infra-redfish/src/lib.rs:55-70` |
| at-rest 加密 | 命令列 + 中心队列：`operations.command` / `batch_operations.command` / `center_outbox.payload_json` / `center_inbox.payload_json` 用 XChaCha20-Poly1305 信封（`RUTC1:` 前缀版本化，AD 绑定行身份，可区分加密行与历史明文行）保护 | `security/src/command_cipher.rs:1-43` |
| CI 门禁补全 | nextest（`--test-threads 4`）、llvm-cov（`--fail-under-lines 80`）、machete、deny、clippy `-D warnings`、wasm32 UI 产物 diff、Capability Ledger Check、Release Baseline Check | `.github/workflows/ci.yml:136-688`（§19.4 门禁步骤：fmt `:136-138`、clippy `:143-145`、Test (full workspace) `:167-169`、跨平台 E2E `:189-193`、nextest `:203-205`、llvm-cov `:214-218`、deny `:252-257`、audit `:274-282`、machete `:288-290`、Secret leak gate `:315-317`、wasm32 产物 diff `:414-521`、Migration test `:630-632`、Capability Ledger Check `:653-655`、Release Baseline Check `:671-673`；W7-M-2 重核 2026-08-14，wave-six 的 +149/-62 推偏旧锚点 40~280 行；W11-D-2 重核 2026-08-14，wave-nine/ten 注释增长再推偏 +8/+11 行） |
| 测试基建 | 故障注入与 Supermicro E2E 覆盖落地 | commit 4ad8c4a（`merge: land the fault-injection and supermicro e2e coverage`） |
| Overview 聚合 | §14.2 首页聚合区块落地：`GET /api/v1/overview` 服务端聚合（api 契约 + application `OverviewQuery` + web 路由），UI 首页仪表盘（Endpoint 计数/厂商分布/健康分布/运行中 Operation/最近事件/固件摘要/能力覆盖/数据陈旧程度），批量刷新与清单刷新后同步重载 | commit 4d1d27c（`feat(ui): render the §14.2 homepage overview dashboard`），链路 commit c3d7198 / e7f8dd4 / 70279c0 |

## 五、已知边界（冻结时如实记录）

| 边界 | 说明 | 事实来源 |
|---|---|---|
| OutOfScope 3 项 | `system.set-boot-order`（Boot 家族只提供 `BootSourceOverride` 一次性/连续覆盖，永不提供持久 boot-order 变更）；`update.simple`（SimpleUpdate 接受远程镜像 URI，§14.3 只上传制品字节、不接受用户 URI）；`update.start`（完整上传即应用路径已由 `RedfishCommand::Update(UpdateCommand::StartUpdate)` 覆盖，独立 StartUpdate 入口不提供）——均为显式产品决策，区别于"应该实现但尚未实现"的 Unmapped | `docs/known-limitations.md` §一 |
| probe-only 的 OEM 项 | `oem-nvidia-cper` / `oem-nvidia-fabrics`：能力状态在命名空间广告粒度判定（Nvidia 命名空间存在即 Supported）；CPER 记录与 fabric 数据子面"only distinguishable when the read slice actually reads the OEM resource"，当前读取面不呈现记录数据 | `infra-redfish/src/redfish_gateway.rs:13311-13317`（`OemNamespaceProbe` 文档，`domain/src/capability.rs:105-115`） |
| UI 表单 later-milestone | telemetry 写表单明确 later milestone（`CommandFamilyView::ALL` 不含 Telemetry，表单选择器返回 `OperationFormError::FamilyRequired`，界面提示 "The telemetry write form is a later milestone."）；log/control 无专用表单；命令执行面本身已完整映射 | `ui/src/lib.rs:5275-5284, 6393-6395, 6542`（`CommandFamilyView::ALL` 9 家族 `:5275-5284`、表单选择器 `FamilyRequired` `:6393-6395`、Telemetry 拒绝 `:6542`、提示文案串 `i18n.rs:1661` `hint_telemetry_later`）；`docs/known-limitations.md` §二 |
| 依赖风险登记 | quick-xml 0.38.4 两个 advisory（RUSTSEC-2026-0194 / 0195）在 `deny.toml [advisories] ignore`，每条带 **TRIGGER** 注释：一旦上游 csdl-compiler 接受 quick-xml >= 0.41.0，必须删除该条目并升级 nv-redfish；产品侧风险评估为低（仅编译期处理可信 CSDL 输入，csdl-compiler 从不调用 `NsReader`） | `deny.toml:29-34` |

## 六、0.9.0 剩余工作清单

来源：设计文档 §0.9.0「内容」与「最低验证规模」（`redfish-management-product-final-design.md:2778-2810`）、
`docs/known-limitations.md` §五-§八、`docs/support-matrix.md` §三。

| 工作项 | 目标/说明 | 来源 |
|---|---|---|
| 进程级演练（评审跟踪项 #9/#15） | 0.8.0 已落地故障注入覆盖（§19.3）与单进程测试；跨进程演练（操作执行 §13 与中心协议 §15 路径）属 0.9.0 | 设计文档 §19.3、§0.9.0 内容；`docs/known-limitations.md` §五 |
| 真实设备认证矩阵 | 五厂商至少各一台真实设备进入 1.0.0 认证矩阵（§19.1 Physical Device Test）；当前结论基于上游类型面与 mock/fixture 验证，不是实测认证 | 设计文档 §19.1；`docs/known-limitations.md` §五 |
| 容量测试 | 🟡 部分：合成规模压力/容量套件已落地（`persistence/tests/stress_capacity.rs` 3 个测试，覆盖设计最低验证规模：200 Endpoint Generation 一致刷新 / 100 Site outbox-inbox-cursor / 5,000 Endpoint 中心投影幂等重投，全部断言正确性不变量）；本机实测数据已记录（2026-08-12：debug 构建、WAL、Windows 开发机基线 + release 构建 3 次全过）；**发布级容量建议已发布（release 构建数据，2026-08-12，见 `operations-manual.md` §九）**；正式规模环境复核仍待做 | 设计文档 §0.9.0（2800-2810）；`stress_capacity.rs:47-52`；`docs/operations-manual.md` §九 |
| 发布构建验证 | 🟡 部分：aarch64 musl（cargo-zigbuild 交叉链接）与 macOS Universal 2（arm64 原生 + x86_64 交叉 + lipo 合并）构建步骤已入 CI（`.github/workflows/ci.yml:565-569, 580-613`）；Windows ARM64 **明确不入 CI**（hosted x64 Windows runner 无法提供 ARM64 MSVC 链接器与 SDK 导入库，真实原因注释于 `ci.yml:573-579`） | `docs/support-matrix.md` §三；`ci.yml` |
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
> 0 失败，2026-08-12；per-crate：test-support 54 / ui 141 / application 301 / web 133 /
> rutilus 145）。

### 7.1 逐项盘点

| 0.9.0 内容 | 状态 | 证据 |
|---|---|---|
| 五厂商实验室 | ⏳ 待做（依赖物理设备） | Mock 层已覆盖五厂商 profile（Dell/HPE/Lenovo/xFusion/Inspur，外加 NVIDIA/AMI/LiteOn/Delta/Supermicro，共 11 个 `MockProfile`，`test-support/src/mock_bmc/profile.rs:47-134`）；§19.1 Physical Device Test「五厂商至少各一台真实设备进入 1.0.0 认证矩阵」未达成（`docs/known-limitations.md` §五） |
| 所有 Fixture 回归 | 🟡 部分 | 合成 fixture（Mock BMC 固定资源树 + 确定性证书）回归已有：`test-support/tests/gateway_mock_bmc.rs` **28 个测试**（Service Root 读取/47 能力探测/核心资源读取/会话生命周期/各厂商 profile；迭代七 T-I 044bae2 补 AMI/HPE 真网关解码 E2E 5 个：`ami_profile_*` `:1793, :1861`、`hpe_profile_*` `:2003, :2070`、`namespace_free_endpoint_leaves_ami_and_hpe_families_absent` `:2202`）、`test-support/src/mock_bmc/tests.rs` 21 个、mock_center 5〔mod.rs 4 + tls.rs 1〕，合计 test-support 54 测试全过（lib 26 + 集成 28，头文档 doc-test 不计入）；§19.1 Fixture Test 要求的**脱敏真实响应 fixture 目录**（五厂商各固件版本，随 nv-redfish 升级回归）尚无（`known-limitations.md` §五） |
| 故障注入 | 🟡 部分 | §19.3 多数场景已有单进程自动化覆盖：BMC 慢响应（`redfish_gateway.rs:24192, 25091`、`tls_probe.rs:568`）、TLS 证书变化（`domain/src/endpoint.rs:327` `verify_identity`/`TlsIdentityChanged`）、JSON 字段类型错误（`redfish_gateway.rs:19215, 19466` undecodable 成员跳过）、Action 响应丢失/写连接丢弃（`redfish_gateway.rs:28766`、`classifies_a_dropped_connection_during_the_write_as_result_unknown` `:29253`）、Task 消失（`redfish_gateway.rs:23109`）、SSE 流中断/解码失败（`redfish_gateway.rs:32605, 32674`）、重复消息/重复 Operation（`center_sync.rs:4699, 4749`、`operation_engine.rs:1863` 批量重投 no-op、`event_repository.rs:328` 事件去重）、大文件上传中断（`web/tests/artifact_path.rs:745`）、系统时间变化（`application/src/telemetry_sampler.rs:1034, 1185, 1211`、`operation_engine.rs:1417` 时钟回拨如实记录）、文件写失败（`artifact_store.rs:1476`）、**登录 Token 失效**（`redfish_gateway.rs:23331` 任务轮询 401 → `AuthenticationFailed` 分类 + 临时 Session 删除、下轮自动重认证（清会话重建），`:33313-33347` SSE 请求 401 → `Reconnectable` 会话重建信号、端点不作消失处理）、**Schema 缺字段**（最小 schema 的字符串字段为 `Option` + missing-field 默认值：serde 把缺失属性与显式 null 同映射 `None`，`redfish_gateway.rs:4124`）；**未覆盖 4 项已更新（迭代八，2026-08-12）**：产品进程在任务中终止、BMC 更新中重启、SQLite 写入中断 3 项已有 Windows 侧进程级演练套件（`scripts/drills/`，见 7.2-B），**首轮实跑因执行上下文 ConPTY 不可用 6/6 SKIP**（防护修复后快速 FAIL 路径已验证），**功能验证待真实交互控制台复跑**；磁盘空间不足仍保持未覆盖（无管理员权限的可靠模拟手段受限） |
| 跨平台 E2E | ✅ 已完成 | windows/macos 任务新增跨平台 E2E 套件步骤（`ci.yml:169-185`）：`cargo test --locked -p rutilus-web`（`web/tests/` 9 个路径套件，均为无 socket/子进程/定时器的内存假件）+ `cargo test --locked -p rutilus --test version`；`app/tests/mock_center_client.rs`（回环 mTLS/WebSocket 中心互操作）因真实 socket 与握手/协商时序**故意不纳入**非默认任务（`ci.yml:176-179` 注释）——三平台 E2E 运行达成 |
| 数据库压力 | ✅ 已完成 | 压力/容量测试套件落地：`persistence/tests/stress_capacity.rs` 3 个测试（`two_hundred_endpoints_round_trip_with_generation_consistent_refreshes` :336、`one_hundred_sites_advance_outbox_inbox_and_sync_cursors` :585、`five_thousand_endpoint_projections_round_trip_at_the_center` :832），规模常量对齐设计最低验证规模（200/100/5,000，`:47-52`）；本机复跑 3 测试全过（2026-08-12，debug 构建、WAL） |
| 中心重连风暴 | ✅ 已完成 | 4 个**多连接并发**重连风暴测试（`center_sync.rs:6468` a_concurrent_reconnect_storm_resumes_every_outbox_from_its_last_ack、`:6588` a_reconnect_duplicate_burst_is_idempotent_and_effects_each_operation_once、`:7603` heartbeats_and_reconnects_interleave_without_interference、`:7733` the_local_queue_keeps_accumulating_while_disconnected_and_drains_in_order_on_reconnect）+ 1 个重连进度重发测试（`:6757` reconnect_resends_progress_for_active_operations_and_skips_completed_ones，NOTE 收尾 commit 283e583）+ wave-two 新增 5 个（identity-mismatch 中止 / failed-unsupported 分类 / 无分类摘要 / 重连不重放 / 首报发现遗留条目）；`center_sync.rs` 现共 **51 个测试全过**（2026-08-14 实测，`cargo test --workspace -- --list`） |
| 大文件更新 | 🟡 部分 | 分块上传机制全链路覆盖：4 MiB chunk 上限（`application/src/artifact_store.rs:64` `ARTIFACT_CHUNK_BASE64_MAX_BYTES`）、断点续传（`artifact_store.rs:1364`、`web/tests/artifact_path.rs:745`）、digest 校验（`artifact_path.rs:949`）、multipart 更新（`redfish_gateway.rs:32073, 32112` `verifies_update_*` 系列、`:31689` 断连 multipart 上传）、中心 manifest+chunk 分发（`center_sync.rs:2280-2320`、`application/src/center/projection.rs:599-603, 762-880`）、8 MiB 帧上限（`center-protocol/src/framing.rs:18-31`）；Windows 侧进程级演练套件已落地（scripts/drills，2026-08-12，见 7.2-B）；真实大固件文件的端到端更新演练未做 |
| Secret 泄漏检查 | ✅ 结构性（含独立扫描门禁） | 结构性防护已有：API 永不回声秘密（`web/tests/write_path.rs:794, 826, 928`、`web/src/lib.rs:6734` `exposes_secret_free_complete_endpoint_inventory`、`persistence/src/credential_repository.rs:604`）、审计类型**构造上**不能携带秘密（`domain/src/audit.rs:403, 468`：非秘密身份数据/封闭类型参数摘要）、Center 投影排除凭据与会话（`application/src/center/projection.rs:85`）、命令载荷 at-rest 加密（`security/src/command_cipher.rs`）；**独立扫描门禁已落地（E3b）**：`security/tests/secret_leak_gate.rs` 3 规则（R1 硬编码秘密 / R2 内嵌私钥 PEM / R3 明文输出宏泄露）、10 测试、白名单 2 处（`ALLOWED_CONSTANT_HITS`，path+line+name+literal 绑定），作为 **CI 独立步骤**（`ci.yml:322-324` Secret leak gate：`bash scripts/assert-tests-ran.sh 10 --locked -p rutilus-security --test secret_leak_gate`，`if: matrix.is_default`，W6-1 ran-断言 floor 10）；E3b 原始提交 eefde7e 已含 `test-support` crate **目录级豁免**（fixture scope by definition——dev-only 测试替身 workspace crate，其秘密命名常量为 fixture 协议值，`secret_leak_gate.rs:96-101` 文档、`:1258` 代码）；深度审查批次（commit e8424df）补 **`strings_catalog!` 宏体结构豁免**（CATALOG_MACRO 帧识别——豁免绑定宏帧而非值：`secret_leak_gate.rs:575` 常量、`:1038-1043` 扫描识别、`:101-106` 文档；新测试 `strings_catalog_macro_bodies_are_copy_construction_not_secret_assignments` `:1521`）；迭代十五（wave-one，commit 73d480d）补 **间接赋值盲区**（wrapper 形状/两步间接 + build.rs 覆盖，漏报边界如实登记）；迭代十六（e59b14a）补 **跨字面量拆分 PEM 片段盲区**（`pem_fragment_violation` `:886`，门禁现 10 测试）；运行时抓包/日志复核未做（7.2-A/B） |
| 权限测试 | ✅ 已完成 | `role_masks_are_enforced_on_guarded_routes`（`web/src/lib.rs:12284`）、中心角色站点作用域（`web/src/lib.rs:13754` `the_center_views_apply_the_d3_site_scope_of_the_role_assignment`、`:13857` `the_center_mutation_routes_enforce_the_role_and_the_site_scope`）、登录限速预算（`web/src/auth.rs:3877` rate_limiter_enforces_per_username_and_per_ip_budgets，wave-one 后重核）、BMC 写权限拒绝（`redfish_gateway.rs:29142` `rejects_the_write_when_permission_is_denied`） |
| 安全审查 | 🟡 已启动 | 启动交付物 `docs/security-review.md`（8 个审查范围 + §7.7 扫描全完成，无 BLOCKER）；MINOR-1（登录时间侧信道）已于迭代二修复（commit 72eccb5：未知用户名路径哑 Argon2id 验证，`web/src/auth.rs:1626`，未知用户名分支调用 `:1766`）；N5 已于迭代三关闭（E3c 编译期 const assert，`web/src/lib.rs:1511`）；独立泄漏扫描门禁已落地（E3b）；**深度审查批次（2026-08-12）**：认证边界硬化（commit 8147bc9）——B1 密码策略 12 字符以 API 为执行边界（`web/src/auth.rs:113, 1680`，登录入口 enforce `:1711`）、B2 429 限速拒绝不写审计（`:1733-1740`）、B3 改密后撤销失败不再静默——显式 500 + 审计失败记录（`:2297-2310`）、B4 disabled/credential-missing 分支补哑 Argon2id 验证（`:1771-1794`，M1 残留面「需先已知用户名」理由已证反并关闭）；**迭代七**：N3 限速器桶键淘汰已实现（T-D e7aef53，见 §7.5），§九 其余 7 项已全部落地（见 §7.5），行号按当前 master 重核；**迭代十五（wave-one，2026-08-13）**：对抗审查发现 **2 HIGH（S3-1 操作历史 API 回声明文 BMC 口令、S3-2 首启未认领窗口 GuardedOnly 整面开放）均已修复**（d3b966a，见 §7.6），S3-3 限速原子化、S3-4 管理员设口令端点（5cd75ae）、S3-5 cookie 前缀早退均已处置；**迭代十七~十九（wave-three/four/five）**：W3S-1..4 / V4R-2/3/5/7 / V4S-2/3/5 / V5C-1/2/4/5/6 等安全面发现全部修复（见 `security-review.md` §三新增行）；外部评估仍待做（见 7.2-A「安全审查（启动）」行与 §7.4） |
| Migration 回归 | ✅ 已完成 | `migration/tests/` 25 个测试文件（initial_storage/operations/batch_operations/telemetry/events/groups_tags/center_tables/center_data_sites/center_role_sites/product_users/remote_tasks/artifacts/operation_failure_kinds/nvidia_families/nvidia_power_families/lenovo_families/bare_sql_gate/audit_action_shapes/audit_execute_operation/resource_feature_lists/audit_center_actions/down_order_gate/endpoint_health_checks/audit_failure_vocabulary/audit_operation_vocabulary）；迁移总数 27（21 基线 + `m20260812_000001` + `m20260812_000002` + `m20260813_000001` + `m20260813_000002` + `m20260813_000003` + `m20260813_000004`）；迁移前自动备份（`persistence/src/lib.rs:510` backs_up_a_closed_database_before_applying_pending_migrations）；CI 独立 Migration Test 门禁（`ci.yml:562`，W6-1 ran-断言 floor 50，V4I-4 重测后同步）；**down 先子后父纪律**（深度审查批次，commit 1711329：先删引用子表再删父表，如 `m20260805_000005_operations.rs:131-138` 先 `OperationTarget` 后 `Operation`；机械门禁 `down_order_gate.rs` 迭代十落地后 wave-one 再补 raw `CREATE TABLE REFERENCES` 与递归扫描盲区，现 12 测试） |
| 备份恢复演练 | 🟡 部分 | 自动化往返覆盖完整（`app/src/backup.rs` 测试区 10 个）：`:1068`（往返保数据）、`:1112`（拒绝他实例包）、`:1138`（跨机恢复需源信封）、`:1225`（源口令对全新信封）、`:1257`（需停止实例）、`:1283`（拒绝未初始化目录）、`:1294`（拒绝不同产品版本）；**迭代七 T-E（commit 02459dc）补恢复前预快照三态**：`:1324`（失败恢复保留预恢复数据供回滚）、`:1401`（成功恢复清除预快照）、`:1421`（预快照拷贝失败不动源目录）——恢复流程见 `app/src/backup.rs:246-341`；CLI `rutilus backup`/`restore`（`app/src/main.rs:97, 144`）；备份快照 NewerSchema 计数断言已改动态派生（R6-D-2，wave-six：`Migrator::migrations().len() + 1` / `.len()`，`persistence/src/backup_snapshot.rs:489, 1043, 1074-1075, 1115-1116`，取代旧静态 pin backup_applied 28 / supported 27，加迁移不会再留陈旧断言）；**schema 版本断言已改为派生**（深度审查批次，commit 0984fd4：`app/src/backup.rs:1068-1072` 从 `rutilus_persistence::migration_counts` 读取 applied+pending 派生，加迁移不会再留陈旧断言）；0.9.0 验收「三平台安装、升级、备份、恢复通过」的演练未执行；Windows 侧进程级演练套件已落地（scripts/drills，2026-08-12，drill-backup-restore-cycle 覆盖 §20.1/§20.2 备份恢复进程级形态，见 7.2-B） |
| 签名构建 | 🟡 代码侧完成（证书未到位） | `scripts/` 签名脚本 3 份（sign-windows.ps1 / sign-macos.sh / sign-linux.sh）+ ci.yml `release-artifacts` job 的签名步骤已合入（commit 34503ea + d77d54e；步骤仅在对应 secret 配置时执行，未配置则 "signing skipped: certificate not configured"（`ci.yml:763, 788, 820` 守卫、`:837` 单行标记））；Windows Authenticode、macOS 签名与公证、Linux minisign 独立签名在证书到位前保持跳过；首次实跑未做（6 项首跑确认点见 `release-readiness.md` 条件 17） | §5.4 发布配置；`release-readiness.md` 条件 17 |
| SBOM | 🟡 代码侧完成（首跑未做） | cargo-cyclonedx@0.5.9 钉版 + 每 crate BOM 收集步骤已入 `release-artifacts` job（`ci.yml:969-999`，commit d77d54e；wave-two e59b14a 补 `cargo metadata --locked` 锁定图断言；W7-M-2 重核 2026-08-14）；首次实跑生成并随包发布未做（证书到位后随发布演练） | §5.4 发布配置；`release-readiness.md` 条件 17 |
| 用户手册 | ✅ 已完成 | `docs/user-manual.md`（436 行，条目后标注来源文件；`rutilus version` 输出已更新为三行，含 Git Commit） |
| 运维手册 | ✅ 已完成 | `docs/operations-manual.md`（数据目录/主密钥/服务/备份恢复/升级/诊断/容量现状；§8.1 已补充 `--log-format json` 结构化输出与 span 上下文，§九已补充合成规模实测容量数据） |
| 支持矩阵 | ✅ 已完成 | `docs/support-matrix.md`（190 行：上游基线/平台矩阵/厂商支持现状/不承诺项）；§三「CI 现状」已更新（windows/macos E2E 套件、aarch64 musl、macOS Universal 2 入 CI，Windows ARM64 未入 CI 的真实原因，`support-matrix.md:90-95`） |
| 已知限制 | ✅ 已完成 | `docs/known-limitations.md`（OutOfScope 3 项/依赖风险登记/测试基建局限/容量现状等）；§八「§0.9.0 性能容量测试与真实容量建议」行已同步为部分落地（`known-limitations.md:151`：合成规模套件已实测、发布级容量建议已发布（release 构建数据，见 operations-manual §九））；§八「§12.4 诊断中的解码错误路径 / ExtendedInfo 展示」行已同步为**已实现**（`known-limitations.md:155`：E1 生产捕获点已合入，如实注记 odata_type 捕获时为 None 等）；§六标题已同步修订为「发布级容量建议未发布（合成规模已实测）」（2026-08-12，与 §八、operations-manual §九 一致），同日再更新为「发布级容量建议已发布（release 构建数据，正式规模环境复核仍待做）」（release 实测数据登记，2026-08-12，见 operations-manual §九）；§七新增深度审查批次条目（密码策略 API 边界 / 429 不写审计 / ETag 现状 / 迁移 down 纪律，`known-limitations.md:139-142`）；§九新增深度审查遗留项登记 8 项（`known-limitations.md:177-184`），迭代七已全部落地/处置（见 §7.5）；迭代十五（wave-one）再追加第一波/第二波对抗发现登记（见 §九） |
| 性能容量测试 | 🟡 部分 | 压力/容量套件已落地（`persistence/tests/stress_capacity.rs`，规模达设计最低验证规模）并有本机实测数据（2026-08-12：debug 构建、WAL、Windows 开发机基线 + release 构建 3 次全过）：debug 下 5,000 投影写入 5.78s（≈865 行/s）、幂等重投 9.72s、5,000 行清单查询 0.482s，release 下 5,000 投影首次写入 ≈3.5–4.2s、幂等重投 ≈7.9s、清单查询 ≈0.16–0.20s；关键观察：写路径被 `write_gate`（`Semaphore(1)`，`persistence/src/lib.rs:101, 240`）全局串行化，5,000 规模耗时 ≈ 事务数 × 单事务成本——这是发布真实容量建议时最有价值的记录；**发布级容量建议已发布（release 构建数据，2026-08-12，见 `operations-manual.md` §九）**；正式规模环境复核仍待做 |

### 7.2 剩余工作精确分类

**A. 代码/CI 可做（不依赖外部资源，可直接进入迭代）**

迭代三+四（master bfb001e）已落地并从下表移出（详见 §7.1 与 §六）：数据库压力测试套件（`stress_capacity.rs`）、
中心重连风暴测试（`center_sync.rs` 并发测试）、跨平台 E2E 运行（`ci.yml:161-175`）、
`cargo audit` 独立门禁（`ci.yml:224-232`）、tracing 深化（`app/src/main.rs:255-273`）。
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
| §12.4 诊断解码错误路径 / ExtendedInfo 展示 | ✅ 已实现（E1，commit ce2b8b3）：记录层——`ResourceExtendedInfo`/`ResourceDecodeFailure`（`resource_diagnostics.rs:36, 249`）、api 契约 9 字段（`api/src/lib.rs:1903-1920`）、web 投影（`web/src/lib.rs:4464` `project_resource_diagnostics`，wave-one 后重核）、ui 只读区块（`ui/src/lib.rs:15502`，wave-one 后重核）、端到端测试（`web/tests/diagnostics_path.rs` 7 个测试，含 E1 新增 `:1008` `refresh_capture_flows_into_the_diagnostics_response`）；**生产捕获点已实现**——gateway 捕获（`redfish_gateway.rs:8811` `DecodeFailureObservation`、`:8995/:9022/:9068` 捕获函数）、同代事务提交（`persistence/src/resource_snapshot_repository.rs:81-147`）、生产链路直连（`application/src/endpoint_refresh.rs:350-355`）、新表 + entity + 迁移（`migration/src/m20260812_000001`，E4 由 `m20260812_000002` 重建约束为领域枚举 47 码）；如实注记：捕获时 `odata_type` 为 `None`（`redfish_gateway.rs:9006-9013` `capture_fetch_failure` 恒传 None，解码失败记录不带类型） | `known-limitations.md` §八 |
| 产品版本号统一策略 + Git Commit 嵌入 | ✅ 已落地（commit 2de4351 + E3a 99d5670）：workspace 版本 = `0.9.0`（生产候选，与里程碑对齐），单一来源 = 根 `Cargo.toml` `[workspace.package] version`（`Cargo.toml:14`）；`rutilus version` 输出**三行**（`app/src/main.rs:733-737`）：产品版本 / `nv-redfish` 基线 / `git commit`（CI 注入 `RUTILUS_GIT_COMMIT`，`ci.yml:84`；`GIT_COMMIT` 常量 `main.rs:38-40`；本地无变量降级 `dev`）；`app/tests/version.rs:8-11, 27-36` 与 `app/tests/log_format.rs:7-10, 23-28` 派生断言（三行）；升级只改一处 | 根 `Cargo.toml:6-14`；`app/tests/version.rs`；`app/tests/log_format.rs` |
| UI 本地化 | ✅ 已完整落地（H5，commit d3f7769 + 0f91c17 + c4dd335）：`strings_catalog!` 目录扩至 **827 键 En/Zh 双语**（宏 `i18n.rs:43-160`，目录体 `i18n.rs:163-1858`；单一来源：字段声明 + En/Zh 构造器 + 完整性测试表）；`Lang::{En, Zh}` 与 `Lang::strings`（`i18n.rs:1860-1881`）、`thread_local!` 运行时语言选择（`i18n.rs:1938-1942`，测试线程各持己态）、`L()` 按当前语言解析 `'static` 目录（`i18n.rs:1968-1973`）、`format_catalog` 运行时槽位填充（`i18n.rs:1984-2006`）；lib.rs `LanguageSelector` 组件（`lib.rs:11751`）+ **URL fragment 持久化**（fragment 是当前 web-sys feature 面唯一可用的浏览器存储，切换经 reload 全量重挂载；**迭代七 T-H c4dd335 已拆为纯函数 + 薄封装**：`stored_lang_code_from`/`lang_fragment_value` `i18n.rs:1915-1936`（host 可测）+ `stored_lang_code`/`persist_language`/`apply_language` `lib.rs:11718-11746`（wasm `browser` 模块薄封装，运行时行为不变）；启动恢复 `start()` `lib.rs:11772`）；深度翻译完成（facts/健康词汇/`OEM_UNSUPPORTED_NOTICE` 等均入目录，`i18n.rs:825-829, 867`）；i18n 15 个测试（既有 11 个：完整性/占位符/双语同键/切换/格式化，`i18n.rs:2009-2185`；T-H 新增 fragment 纯函数 4 个：`i18n.rs:2192-2259`），ui **144 测试全过**、clippy/fmt 干净；J2 审计 3 处 zh 译法微修已合入（`type_nvidia_profile_file`/`fact_power_load_percent`/`fact_metric_values`，`i18n.rs:444, 597, 733`）。**后续触点**：localStorage 持久化（需扩展 web-sys feature）与更多语言 | `ui/src/i18n.rs`；`ui/src/lib.rs:11718-11772`；`web/assets/`；`known-limitations.md` §七 |
| 发布管道（签名 + SBOM + 校验清单，代码侧） | ✅ 代码侧完成（H4，commit 34503ea + d77d54e，证书到位即启用）：`scripts/` 5 脚本（sign-windows.ps1 / sign-macos.sh / sign-linux.sh / checksums.sh / checksums.ps1）；ci.yml `release-artifacts` job（`ci.yml:624-926`）——`v*` tag push 与 `workflow_dispatch` 触发（`ci.yml:48-60`）、`needs: ci` 门禁先行（`ci.yml:628`）、签名步骤仅在 secret 配置时执行（`ci.yml:763, 788, 820`，未配置走 "signing skipped" 单行标记 `:837`）、base64 物化（`ci.yml:763-772, 788-796, 820-823`）、Windows thumbprint-only 模式（`ci.yml:774-780`）、cargo-cyclonedx@0.5.9 钉版 SBOM（`ci.yml:882-897`）、SHA-256 清单（`ci.yml:913`）、artifact 上传（`ci.yml:916-926`）；H4 审计处置已内嵌（musl-tools 补齐 `ci.yml:707`、单行 if 判定 `ci.yml:852` 等）；**首跑确认点 6 项**（证书到位后核验：musl-tools 安装 / cargo-cyclonedx@0.5.9 钉版 / base64 物化 / env `&&`·`||` 表达式 / thumbprint-only 模式 / 上传权限，详见 `release-readiness.md` 条件 17） | `scripts/`；`.github/workflows/ci.yml`；`release-readiness.md` 条件 17 |
| 安全审查（启动） | ✅ 已交付：`docs/security-review.md`（8 个审查范围 + §7.7 扫描全完成，无 BLOCKER）；**M1 已修复**（MINOR-1 登录时间侧信道，commit 72eccb5：`web/src/auth.rs:1626` 哑 Argon2id 验证 + `:1766` 未知用户名分支调用），验证方式 = 调用计数对称断言而非墙钟计时（`web/src/lib.rs:9798` 计数、`:11292` 与 `:11356` 两分支各 1 次/失败、限速拒绝 0 次）；**N5 已关闭**（E3c：`web/src/lib.rs:1511` 编译期 const assert 钉死常量正性）；**独立 Secret 泄漏扫描门禁已落地**（E3b：`security/tests/secret_leak_gate.rs` 3 规则、10 测试；CI 独立步骤 `ci.yml:285` Secret leak gate）；**深度审查批次**：认证边界硬化（commit 8147bc9，B1-B4，详见 §7.1「安全审查」行与 §7.4）；**迭代七**：§九 8 项遗留全部落地/处置（N3 即 T-D e7aef53，详见 §7.5）；**迭代十五（wave-one）**：S3-1/S3-2 两 HIGH 已修复（d3b966a，见 §7.6）；**迭代十七~十九（wave-three/four/five）**：安全面发现（W3S-1..4、V4R-2/3/5/7、V4S-2/3/5、V5C-1/2/4/5/6 等）全部修复（见 `security-review.md` §三新增行）；剩余：运行时抓包/日志复核与外部评估（1.0.0 发布评审建议项） | `docs/security-review.md`；设计文档 §0.9.0 |
| 约束修复（E4） | ✅ 已落地（commit 76af80f + bfb001e）：`migration/src/m20260812_000002_resource_feature_lists.rs` 重建 `resources`/`resource_decode_failures` 两表，`ck_resources_feature`/`ck_resource_decode_failures_feature` 允许域 = 领域枚举全部 47 码（此前 resources 37 / resource_decode_failures 36 且互相不一致）；`down` 对称恢复 37/36；防回归机械测试 `migration/tests/resource_feature_lists.rs`（`:248` 单测试，域码与约束逐字符双向钉死，不触库）；备份快照 NewerSchema 计数断言已改动态派生（R6-D-2，wave-six：`Migrator::migrations().len()`，`persistence/src/backup_snapshot.rs:489, 1043, 1074-1075, 1115-1116`，取代旧静态 pin） | `migration/src/m20260812_000002`；`migration/tests/resource_feature_lists.rs` |
| 发布构建矩阵补齐（剩余部分） | aarch64 musl（cargo-zigbuild）与 macOS Universal 2（lipo）已入 CI（`ci.yml:343-347, 366-391`）；Windows ARM64 明确不入 CI——hosted x64 Windows runner 无法提供 ARM64 MSVC 链接器与 SDK 导入库（`ci.yml:349-356` 注释），需原生 ARM64 Windows runner 或本地验证后另行处理 | `ci.yml` |
| 认证边界硬化（B1-B4） | ✅ 已落地（commit 8147bc9，深度审查批次）：**B1 密码策略 12 字符**——`password_satisfies_policy`（Unicode 标量计数 ≥ `MIN_PASSWORD_CHARS`，`web/src/auth.rs:113, 1680`），登录入口在限速/查找/验证之前执行（`:1711`：不占限速预算、不写审计——策略违规不是登录尝试）；**B2 429 拒绝不写审计**——限速拒绝无审计事件，429 本身即记录（`:1733-1740`：防审计表无界增长 + 写门饥饿）；**B3 撤销信号非可选**——改密后 `revoke_sessions_for_principal` 失败不再静默：显式 500 + 审计失败 outcome（`:2297-2310`）；**B4 disabled/credential-missing 分支哑验证**——两分支补同款哑 Argon2id（`:1771-1794`），M1「需先已知用户名」残留面已证反并关闭（security-review §三 M1 行更新）；行号在迭代十五（wave-one，auth.rs 重写 +1119 行）与迭代十七~十九（wave-three/four/five，auth.rs 再扩展）后按当前 master 重核 | `web/src/auth.rs`；`docs/security-review.md` §三 |
| ETag 携带 + 412 专用路径 | ✅ 已落地（commit 6128a17，深度审查批次）：每个类型化 `update` 写携带**本次执行读取时**的目标文档 ETag——文档带 `@odata.etag` 时发送 `If-Match: <etag>`，BMC 以 `412 Precondition Failed` 拒绝即证明写未执行，gateway 报告 `CommandExecutionError::PreconditionFailed`（先重读目标，并发变更不被覆盖）；无 ETag 的文档保持传输层存在性 `If-Match: *`（§13.4 第二段）；action/create/delete 家族在类型化 API 中无 If-Match 通道，从不发送（`redfish_gateway.rs:598-611` 模块文档、`:12653-12690` 错误变体、`:14002-14062` 412 分类器、测试 `:25432, 27314-27420`）；**快照 ETag 接线已处置（决策 c，2026-08-12，T-C，见 §7.5 与 known-limitations §九该行）**——快照已持久化 ETag（`domain/src/resource_snapshot.rs:606-655, 790`、`persistence/src/resource_snapshot_repository.rs:402, 553-554, 605-608`），operation-executor 无消费方是登记过的决策而非遗留（执行时读取恒为分派时刻最新 ETag，快照 ETag 恒更旧、无独立写路径价值，接线不实施） | `infra-redfish/src/redfish_gateway.rs`；`known-limitations.md` §九 |
| 端点读门 + 恢复判定 | ✅ 已落地（commit 02370db，深度审查批次 + 迭代七 T-B 4897b22）：**端点读门**——进程级每端点 `Semaphore(1)`（`ENDPOINT_READ_GATES` `application/src/batch_refresh.rs:98`、`endpoint_read_gate` `:113-129`），批量与单端点刷新（web 路由统一走 `BatchEndpointRefresh`，`web/src/lib.rs:1993`）在 `refresh_one` 全程持门（读取/Generation 提交/能力重探/快照替换，`batch_refresh.rs:298-336`），两处获取失败均分类为 `Coordination`（`:310-328`，`EndpointRefreshFailureKind::Coordination` `:406`）；**入网首刷已纳入同一读门（T-B，commit 4897b22）**——`EndpointEnrollment::enroll` 在 `refresh.execute` 前经 `endpoint_read_gate` 获取 permit（`endpoint_enrollment.rs:168-179`，失败分类为 `InitialRefreshCoordination`，web 错误映射 `web/src/lib.rs:3425`），对抗测试 `initial_refresh_and_concurrent_batch_refresh_of_the_same_endpoint_never_overlap`（`endpoint_enrollment.rs:643`）钉死不重叠——known-limitations §九该行已转 ✅；**恢复判定**——只有 Running（dispatch 结果未知，§13.5）与 Verifying（重读在途）可恢复，`Validating` 经 `execute_operation` 续跑、`WaitingRemote` 归 Task monitor、终态为终（`application/src/operation_executor.rs:1695-1700` `NotRecoverable`，测试 `:4548` 非可恢复态无副作用拒绝、`:4648` 恢复竞态报告） | `application/src/batch_refresh.rs`；`application/src/endpoint_enrollment.rs`；`application/src/operation_executor.rs` |
| 迁移 down 先子后父 | ✅ 已落地（commit 1711329，深度审查批次）：多表 down 先删引用子表再删父表——`m20260805_000005_operations.rs:131-138` 先 `OperationTarget` 后 `Operation`；与既有 down 对称恢复（E4 `m20260812_000002` 重建约束）共同构成下迁纪律；机械门禁已落地：`migration/tests/down_order_gate.rs`（2026-08-12 迭代十），与裸 SQL 门禁同款纯静态扫描（无库），见 `known-limitations.md` §七该行 | `migration/src/` |
| i18n 槽位 + 本地化（+产物） | ✅ 已落地（commit fb660d5 + a4950fc，深度审查批次）：`format_catalog` 槽位填充硬化——`{}` 与命名槽位按模板出现顺序填充，**缺参时槽位原样呈现**（不静默丢文本，`ui/src/i18n.rs:1984-2006`，T-H 后重核）；`FORMAT_KEYS` 白名单（`:93`）+ 无游离占位符测试（`catalogs_have_no_stray_placeholders` `:2030`）+ 双语槽位序对齐测试（`zh_templates_keep_the_en_placeholder_order` `:2082`）+ 运行时格式化测试（`format_catalog_interpolates_positional_and_named_slots` `:2137`，缺参原样同测试内断言）；本地化补齐与 `web/assets` 产物再生成（a4950fc） | `ui/src/i18n.rs`；`web/assets/` |
| Secret 扫描门禁 strings_catalog 宏体豁免 | ✅ 已落地（commit e8424df，深度审查批次）：`strings_catalog!` 宏体（ui/src/i18n.rs）是**目录构造而非代码**——宏内字段名是 i18n 键、字面量是双语文案，[R1] 会把目录条目误读为秘密赋值；豁免按**结构**绑定宏帧（CATALOG_MACRO 帧识别，`security/tests/secret_leak_gate.rs:575` 常量、`:1038-1043` 扫描识别、`:101-106` 文档），宏外同文件真实秘密赋值仍会被扫出，不白名单任何值；新测试 `strings_catalog_macro_bodies_are_copy_construction_not_secret_assignments`（`:1521`）；`test-support` crate 的**目录级豁免**（fixture scope by definition——dev-only 测试替身，mock 固定 `SESSION_TOKEN` 等为 fixture 协议值，不随发布产物出货，豁免绑定 crate 名而非值）属 E3b 原始提交 eefde7e（`:96-101` 文档、`:1258` 实现）；新 crate 默认仍在扫描范围（`crate_directories` 相对 `CARGO_MANIFEST_DIR` 自动发现，`:996-1260` 区段）；迭代十五（wave-one，commit 73d480d）补 wrapper/间接赋值盲区（`:836` `wrapper_or_indirect`，漏报边界如实登记） | `security/tests/secret_leak_gate.rs` |

**B. 依赖演练环境（物理设备 / 规模环境 / 三平台流程）**

| 工作项 | 说明 | 来源 |
|---|---|---|
| 五厂商实验室 | Dell/HPE/Lenovo/xFusion/Inspur 各至少一台真实设备进入 1.0.0 认证矩阵 | 设计文档 §19.1 |
| 真实响应 fixture 目录 | 五厂商各固件版本脱敏真实响应 + 随 nv-redfish 升级回归（fixture 抓取依赖设备） | 设计文档 §19.1 Fixture Test |
| 进程级故障注入演练 | **套件已落地（迭代八，2026-08-12）**：`scripts/drills/` 7 脚本 + RESULTS.md（Windows 本机形态：mock-bmc + 自研 delay relay，无物理设备/外部证书依赖），覆盖产品进程在任务中被终止（drill-kill-mid-operation）、BMC 更新中重启（drill-bmc-restart-during-task）、SQLite 写入中断（drill-sqlite-write-interruption）、备份恢复（drill-backup-restore-cycle，§20.1/§20.2）与大文件中断（drill-large-file-interruption，§0.4.0）；**首轮实跑 6/6 SKIP**（2026-08-12，如实登记：执行上下文 ConPTY 不可用——伪控制台子进程 0xC0000142 启动失败、零输出，非产品问题），挂起防护修复完成（只改 drill-lib.ps1，复测 3 次均 0.6s 快速 FAIL、超时分支 3.2s 有界返回、清理 0s），**功能验证待真实交互控制台会话复跑**；**磁盘空间不足仍未覆盖**（无管理员权限的可靠模拟手段受限，成本/收益评估后保持） | 设计文档 §19.3；`scripts/drills/` |
| 大文件更新演练 | 真实大固件文件的端到端更新（当前为分块机制级覆盖） | 设计文档 §0.9.0 |
| 备份恢复演练 | 三平台安装/升级/备份/恢复（0.9.0 验收） | 设计文档 §0.9.0 验收 |
| 性能容量测试 | 合成规模压力套件已落地并实测（`stress_capacity.rs`，2026-08-12）；**发布级容量建议已发布（release 构建数据，见 `operations-manual.md` §九）**；正式规模环境复核仍待做 | 设计文档 §0.9.0（2800-2810）；`operations-manual.md` §九 |
| Center/Site 长时间断线重连演练 | 0.9.0 验收项；并发重连风暴已自动化覆盖（`center_sync.rs:6468, 6588, 6757, 7603, 7733`），长时间（跨进程/跨天）真实断线演练仍未执行 | 设计文档 §0.9.0 验收 |

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
| 无已知重复执行 | ✅ 事件去重（`domain/src/event.rs:383`）、批量重投 no-op（`operation_engine.rs:1863`）、重复 offer 幂等（`center_sync.rs:3974, 4048`） |
| 无已知错误成功报告 | 🟡 写后重读验证（`redfish_gateway.rs:29667` 等 `verifies_*` 系列）、响应丢失→Unknown（`redfish_gateway.rs:29253`）；整体清零结论待评审 |
| 三平台安装、升级、备份、恢复通过 | ⏳ 演练未执行（7.2-B） |
| Center/Site 长时间断线重连通过 | 🟡 单连接语义（`center_sync.rs:4026` `a_closed_connection_reconnects_after_the_backoff` 等）与**并发重连风暴**（`center_sync.rs:5004, 5124, 5293, 6139, 6269`，center_sync.rs 现 42 测试全过）均已自动化覆盖；长时间（跨进程/跨天）真实断线演练未执行 |

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
| `e8424df` | Secret 扫描门禁 `strings_catalog!` 宏体结构豁免 | `security/tests/secret_leak_gate.rs:575`（`CATALOG_MACRO` 常量）、`:1038-1043`（扫描帧识别）、`:101-106`（文档）；新测试 `strings_catalog_macro_bodies_are_copy_construction_not_secret_assignments` `:1521` |
| `e611ed7` | test-support 借用修复（无文档触面） | `test-support/`（mock 状态借用/所有权调整） |
| `8147bc9` | 认证边界硬化（B1 密码策略 / B2 429 审计 / B3 撤销信号 / B4 哑验证补齐） | `web/src/auth.rs:113, 1680, 1711, 1733-1740, 1771-1794, 2297-2310`（wave-one d3b966a 重写 + wave-three/four/five 扩展后重核） |
| `1711329` | 迁移 down 先子后父 | `migration/src/m20260805_000005_operations.rs:131-138` |
| `6128a17` | ETag 携带 + 412 专用路径 | `infra-redfish/src/redfish_gateway.rs:598-611, 12653-12690, 14002-14062`；测试 `:25432, 27314-27420` |
| `02370db` | 端点读门 + 恢复判定 | `application/src/batch_refresh.rs:98, 113-129, 298-336`；`application/src/operation_executor.rs:1695-1700`（测试 `:4548, 4648`） |
| `fb660d5` | i18n 槽位 + 本地化 | `ui/src/i18n.rs:1984-2006, 2030, 2082, 2137-2176`（T-H 后重核） |
| `a4950fc` | web/assets UI 产物再生成（i18n 本地化配套） | `web/assets/rutilus_ui.js`、`web/assets/rutilus_ui_bg.wasm` |

遗留项（LOW/NOTE，全部登记于 `docs/known-limitations.md` §九）：限流器桶键淘汰、i18n fragment
纯函数测试、decode_failures 贯通测试（endpoint_refresh 生产链路）、AMI/HPE 真网关 E2E、restore
预恢复副本、free_port TOCTOU、入网首刷绕端点门、快照 ETag 接线
（domain/persistence/operation_executor）。**以上 8 项已由迭代七全部落地/处置（2026-08-12，
master 61b9cc5，9 个提交 + T-C 决策，三批五维审计 APPROVE）——见 §7.5 与本行对应更新；§九
各行已转 ✅ 最终状态（以 known-limitations 为准）。**

> **第二批五维深度审查（2026-08-12，HEAD = 452a291，安全+并发 / 数据+前端+CI）**：
> 对第一批处置后状态（迭代七 T-A~T-F / 迭代八 drills / 迭代十 down_order_gate 机械门禁
> 合入后）做五维再审查。方法：只读代码 + 对抗验证（**13 项对抗验证**——对既有登记结论
> 构造反例：B4 分支覆盖 / 限流剪枝 / 会话撤销结构性免疫 / 白名单零漂移 / 并发刷新串行化 /
> 写门无饥饿 / 重启无竞态 / center at-least-once / Generation 中断 / 备份迁移竞争 / 恢复
> 一致性 / 下迁数据丢失 / 两门禁 23 迁移全量对抗）。结果：**无 BLOCKER/HIGH/MEDIUM 残留**——
> **MEDIUM 1 + LOW 3 已修复**（2 个修复提交，见下表），NOTE 全部登记（`452a291` docs
> 提交）；对抗验证 **13 项全部「维持」**（无新反例成立）；drills 无新增真实秘密材料；既有
> 登记结论无被推翻项。修复提交与代码证据：

| 修复提交 | 内容 | 代码证据 |
|---|---|---|
| `318eadd` | fix(scripts)：drill-lib.ps1 证书 Pin 修复（MEDIUM）——Invoke-MockHttps 原用 `GetCertHashString()`（.NET Framework 上为 SHA-1）比对 mock-bmc 的 SHA-256 指纹恒失败（drill-kill-mid-operation 幂等断言健康环境必然 FAIL）；改为 C# 委托（脚本块回调在无 runspace 的 TLS 工作线程无法执行）SHA-256-of-DER 归一比对，与产品侧 `Sha256::digest(certificate_der)`（domain/src/endpoint.rs:490）逐字节同值；真实 mock-bmc 端到端验证（正确 pin→200、篡改→拒绝）；同函数另修 2 缺陷（LOW）：`[string]$Body=$null` 强转 '' 致 GET 带空 StringContent（ProtocolViolationException）、Start-MockBmc 缺省 -Port 传空参数列表致 Start-Process 参数校验异常（改传 '0' 由 mock-bmc 自选端口 + stdout URL 回读，.Port 恒为真实端口，探针验证启动/连接/清理） | `scripts/drills/drill-lib.ps1`（`Invoke-MockHttps` `:869`、`Start-MockBmc` `:450`、Pin 辅助 C# 类型 `:825-838`） |
| `64125e0` | fix(migration)：m20260810_000002 down 未恢复 000005 形状（MEDIUM）——原 down 复用 up 的 rebuild DDL（site_id 列/外键/scope CHECK 全保留），且测试断言有歧义（随机 UUID 插入被外键拒绝，两种假设下都通过）；拆 `rebuild_up`（000010 形状不变）/`rebuild_down`（严格 000005 形状：4 列 + role CHECK + 2 FK，无 site_id/scope CHECK，形状核实自 m20260807_000005_product_users.rs:355-396）；测试改 PRAGMA table_info 断言 4 列 + scoped 插入（seeded site）判别 + role CHECK 存活；负向实证（旧代码下新断言 FAILED）；migration 38 测试全过、clippy/fmt 干净、两静态门禁兼容 | `migration/src/m20260810_000002_center_role_sites.rs`（`rebuild_up` `:55`、`rebuild_down` `:86`）；`migration/tests/center_role_sites.rs` |

**NOTE 登记（`452a291`，docs）**：down_order_gate raw-CREATE-REFERENCES 盲区活表案例
（000002 role_assignments_rebuild REFERENCES instances/principals——当下无害、为将来
down 序依赖挂旗）、ci.yml `ref_name` 斜杠边界（可见失败、不 sanitize 为决策）、
known-limitations §八 events 存储增长（§14.4 展示有界/存储无界）与 §五 drill
`Get-FreeTcpPort` TOCTOU / 400ms 时序启发式、milestone-status down_order_gate 行数 1286。

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
| `c4dd335` | T-H：`#lang=` fragment 持久化拆为纯函数 + 薄封装，纯函数单测 4 个；ui 136→141 | `ui/src/i18n.rs:1915-1936`（`stored_lang_code_from`/`lang_fragment_value`）、`:2192-2259`（4 测试）；`ui/src/lib.rs:11716-11745`（wasm 薄封装） |
| `8482d85` | T-G：decode-failures 生产链路贯通测试 4 个（真实 `EndpointRefresh` + 真实 `SqliteStore`）；application 293→301 | `application/tests/refresh_decode_failures.rs`（头注释 `:3-22`）；`application/src/endpoint_refresh.rs:350-355` |
| `4897b22` | T-B：入网首刷改走 `endpoint_read_gate`，与批量刷新不再重叠；新增 `EndpointReadGateError` 导出 | `application/src/endpoint_enrollment.rs:158-202`（gate 获取 `:168-179`、`refresh.execute` `:190`）、对抗测试 `:643`；`application/src/lib.rs:85-86`；`web/src/lib.rs:3425`（错误映射） |
| `e7aef53` | T-D：限速器桶键 4096 阈值周期剪枝，内存有界 = 窗口活跃工作集 + 4096；web 全过（当时 133，wave-one 后 147，wave-five 后 172） | `web/src/auth.rs:147`（`BUCKET_PRUNE_THRESHOLD`）、`:1054-1160`（`LoginRateLimiter`/`BucketMap`/`prune_if_due` `:1269`/`prune_expired` `:1285`）；有界性测试 `:4135, 4203, 4247, 4282`（S3-3 原子 reserve/refund 后第三个测试更名为 `rate_limiter_prune_reclaims_compensated_empty_buckets`） |
| `02459dc` | T-E：恢复前先快照当前数据目录（三态：成功清除 / 失败保留供回滚 / 创建失败中止不动原目录）；rutilus 141→145 | `app/src/backup.rs:246-341`（`create_pre_restore_snapshot` `:300-308, 636-664`）、测试 `:1324, 1401, 1421` |
| `83ff07f` | T-F：free-port 探测竞态消除——各绑定点 `AddrInUse` 换端口重试（`is_raced_*_bind` + 重试循环），含第 5 处内联修复 | `app/src/center_acceptor.rs:964-993, 1005`；`app/src/center_runtime.rs:901-927`；`app/src/center_client.rs:629-654, 886`；`app/src/site_runtime.rs:1507-1544, 2048-2079` |
| `61b9cc5` | 第 9 个提交：secret-gate 白名单行号刷新——`ALLOWED_CONSTANT_HITS` 的 backup.rs 条目 83/84→88/89（对齐 T-E 后 backup.rs 头文档漂移）；path+line+name+literal 四元组绑定使常量移动即门禁失败，触发本提交刷新并重新确认无秘密材料（门禁漂移检测触发-修复闭环）；仅 2 行，无测试面变化 | `security/tests/secret_leak_gate.rs:366-373`（`ALLOWED_CONSTANT_HITS` `:366`，两条目 `:367-372`） |
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

- per-crate：test-support **54**（gateway_mock_bmc.rs 28〔23 + T-I 新增 5〕+ mock_bmc/tests.rs
  21 + mock_center 5〔mod.rs 4 + tls.rs 1〕，即 lib 26 + 集成 28；lib.rs 头文档 doc-test 1
  已与新 `--list` 口径分离、不计入）、ui **141**（T-H 新增 fragment 纯函数测试 4 个；
  上轮登记 136，本轮复跑 141）、application **301**（293 + T-G 贯通 4 + T-B 对抗 4）、
  web **133**（T-D 新增有界性测试 4 个）、rutilus **145**（141 + T-E 预快照 3 + T-F 重试 1）；
- workspace 总计：**1723**（lib/集成 1723 + doc 1 = 1724），0 失败；fmt / clippy
  `-D warnings` 全 workspace 零警告；迭代八无新增 Rust 测试（drills 为脚本形态）。

**测试计数（2026-08-12，迭代十合入后本机复跑，口径 `cargo test --workspace --locked -- --test-threads 4`）**：

- per-crate：migration **38**（30 基线 + down_order_gate 新增 8）；五个核心 crate 与迭代七基线
  相等——test-support **54** / ui **141** / application **301** / web **133** / rutilus(app) **145**；
- workspace 总计：**1731**（lib/集成 1731 + doc 1 = 1732），0 失败；增量恰 +8（down_order_gate）；
  fmt / clippy `-D warnings` 全 workspace 零警告。

### 7.6 对抗审查修复批次（迭代十五~十九：wave-one 至 wave-five，2026-08-13~14）

> 第一波对抗审查（2026-08-13，6 透镜并行攻击）的 27 项确认发现全部修复（10 个提交：
> 8a4d271 / 2a4340b / bcef349 / e652831 / 73d480d / 6ca207c / 3f312b2 / 31a4232 / d3b966a /
> 5cd75ae，逐项登记见头注）。发现定案：38 条 → 31 confirmed + 2 refuted（C5-9 重复回执重复
> inbox 行——inbox 按 operation_id 查重；W6-6 down_order_gate 跨文件 down 序盲区——引错文件 +
> 门禁全局聚合 FK 边）+ 1 降级（W6-1 测试型门禁无 ran-断言——llvm-cov 80% 为隐式防线，降级后
> 仍修复）+ 4 半/部分（C5-7 半确认后修复、W6-7 部分修复等）。**27 项修复中 2 HIGH（S3-1/S3-2）
> + 1 HIGH（D4-1）**，全部如实登记于 `docs/known-limitations.md` §九（第一波块）与
> `docs/security-review.md` §三/§四。
> **第二波对抗审查（2026-08-13，61 条发现，无 refuted，F4-6 部分成立）已于迭代十六
> （HEAD = e59b14a）全部处置**：60 项确认修复 + F1 追加发现，逐项登记于
> `docs/known-limitations.md` §九（第二波块，全部转 ✅）；12 条 D6 文档真实性发现由 2026-08-13
> 文档收口批次处置。
> **第三波对抗审查（2026-08-13，4 透镜旋转，30 条 → 29 confirmed + 1 HIGH 降级 LOW）已于
> 迭代十七（HEAD = e768473）全部修复**，逐项登记于 `docs/known-limitations.md` §九（第三波块，
> 全部转 ✅）。
> **第四波对抗审查（2026-08-13，4 透镜，30 条 → 29 confirmed + 1 HIGH 双透镜双确认）已于
> 迭代十八（HEAD = 3a23b9b）全部修复**，逐项登记于 `docs/known-limitations.md` §九（第四波块，
> 全部转 ✅）。
> **第五波对抗审查（2026-08-13，4 透镜，25 条全部 confirmed，含 5 HIGH）已于迭代十九
> （HEAD = e85560a）全部修复**，逐项登记于 `docs/known-limitations.md` §九（第五波块，全部
> 转 ✅）。
> 门禁与计数：security 门禁 8→9→10（V4I-3 重测）、down_order_gate 8→11→12、bare_sql_gate
> 4→5（W3F-3 括号/CTE 拼写补入既有测试，测试数不变）、migration 38→48→50→57、迁移文件
> 25→27、迁移测试文件 23→25、备份 pin 26/25→28/27（wave-four/five 各 +1 迁移后重测，
> `persistence/src/backup_snapshot.rs:646-647` 断言现为 backup_applied 28 / supported 27；
> wave-six R6-D-2 起改动态派生，见下 wave-six 段）、
> workspace 测试 1837→1913（`cargo test --workspace -- --list` 口径，2026-08-14 实测，见头注）。

> 本节标题已从「迭代十五：wave-one 对抗修复」改为「迭代十五~十九：wave-one 至 wave-five」，
> 段落编号 §7.6 不变（既有跨文档引用按节号有效）；wave-three/four/five 的逐项登记以
> `docs/known-limitations.md` §九（第三/四/五波块）为准。
> **第六波对抗审查（wave-six，2026-08-14，HEAD = 7c6ac9d，2 个提交）**：6 透镜（并发 /
> 安全 / 数据迁移 / 中心协议 / web+UI+CI / 测试质量与文档）并行攻击 wave-five 状态，58 条
> 发现 → 跨透镜去重 54 条交独立怀疑者核验 → **48 confirmed + 3 partial + 3 refuted**；48 项
> 确认发现全部修复（fcf7257）+ 3 项链式发现与 A1 拒绝码接线（7c6ac9d）——含 **2 HIGH
> （R6-C-1 并发双派发铸双 id 双执行、R6-E-01 Unknown 后重派发逃过 inbox 去重）**与 MEDIUM 组
> （R6-C-2/R6-C-3/R6-E-02/R6-E-03/R6-E-04/R6-S-1/R6-S-3/R6-D-1/R6-W-1/2/R6-W-3/R6-W-6/
> R6-E-11/R6-A1 接线），逐项状态见 `docs/known-limitations.md` §九（第六波块，全部转 ✅）；
> 区域修复登记见 `docs/r6-findings/`（A1-A6 + A8）；refuted 3 条含 R6-W-3 inbox 污染半边。
> **门禁与计数（2026-08-14 实测）**：fmt 干净、clippy `-D warnings` 全 workspace 零警告、
> **1963 测试 0 失败**（`cargo test --workspace -- --list` 口径：lib/集成 1962 + doc 1 =
> 1963；增量 1913→1963（+50）——提交消息声称的 1958/45 为 fcf7257 中间计数，链式提交
> 7c6ac9d 另 +5）；per-crate：rutilus 167→175 / api 85 / application 361→371 /
> center-protocol 30 / domain 212 / infra-redfish 295 / migration 57→59 / operation-engine
> 34 / persistence 219→228 / platform 32→33 / security 53→59（含 secret_leak_gate 15） /
> test-support 54+1 / ui 141→142 / web 172→185；新迁移 `m20260814_000001_center_outbox_
> operation_ids`（迁移文件 27→28、迁移测试文件 25→26）；旧静态备份 pin（backup_applied 28 /
> supported 27，原 `backup_snapshot.rs:646-647`）由 R6-D-2 改动态派生
> （`Migrator::migrations().len()`，现 `:943-944, 983-985`），加迁移不再留陈旧断言。
> 本节标题保持「迭代十五~十九」（wave-one 至 wave-five）——wave-six 的逐项登记以
> `docs/known-limitations.md` §九（第六波块）与 `docs/r6-findings/` 为准。
> **第七波对抗审查（wave-seven，2026-08-14，HEAD = a0b2bc0，1 个提交）**：7 透镜（修复
> 验证 / 安全 / 并发 / 数据迁移 / 中心协议 / web+UI+CI / 性能）并行攻击 wave-six 状态，
> 40+ 条发现 → 去重约 30 条交 4 个独立怀疑者 → **27 confirmed + 4 refuted + 3 partial
> 降级**；27 项全部修复（a0b2bc0，A1-A5 区域并行）——含 **3 HIGH（W7-E-1 WaitingRemote
> 卡死、W7-S-1 中心侧制品无 cap、W7-P-1 闸门内全局扫描）**；refuted 4 条（W7-P-10 已登记
> 设计、W7-L-2 已登记决策、W7-C-5 不可达、W7-H-1 前提被 runner-images 六代历史源码证伪，
> ci.yml 的 $HOME 前提正确）；partial 3 条降级登记（W7-E-5 真实变体随 F-1 修复、W7-E-7b
> §15.6 对拒绝响应无契约可对照、W7-P-9 量级修正）；**1997 测试 0 失败（+34）**，逐项状态见
> `docs/known-limitations.md` §九（第七波块，全部转 ✅）+ refuted/partial 登记；区域修复
> 登记见 `docs/r7-findings/`（A1-A5）。NOTE 级未修项（W7-E-6 无中心侧 reaper、W7-D-4 重建
> 类 down 具名预检不对称、W7-F-5=D-3 迁移前 NULL 行不剪、W7-P-8 drain 每 tick 8 次重放、
> W7-C-6 回填/剪枝无害竞态、W7-C-7=L-1 offset 分页重复行、W7-N-3 workspace floor、W7-S-4
> 门禁输出面、W7-S-2 制品无删除 API/配额、W7-P-3 ack 4 条 SQL 写放大）如实登记于
> `known-limitations.md` §九第七波块。
> **第八波对抗审查（wave-eight，2026-08-14，HEAD = 6d5e90e，1 个提交）**：7 透镜并行攻击
> wave-seven 状态，25 条发现 → 去重约 20 条交 3 个独立怀疑者 → **16 confirmed + 1 refuted
> （W8-C-3 代回绕双不可达）+ 5 partial 降级**；16 项全部修复（6d5e90e，A1-A4 区域并行）——
> 含 **1 HIGH（W8-E-2 未决路径 re-home 双执行——W7-E-3 的孪生漏洞，修复读换跨实例）**与
> MEDIUM 组（F-2 target 规范化、P-1 state 过滤 + IN 分批、C-1 Center 停机调序 + 确定性测试、
> D-1 000003 事务化）；**2013 测试 0 失败（+16）**，逐项状态见 `known-limitations.md` §九
> （第八波块）+ refuted/partial 与 NOTE 级登记（F-4/P-6 revoke 耦合、C-5 级联、C-4 touch、
> P-2/P-3/P-4、F-8 park 陷阱、F-11 旧信封滞留、E-1 吸收行为、E-3 永久冻结 + user-manual
> §10.1 对账文档、A1 两条未竟项）；区域修复登记见 `docs/r8-findings/`（A1-A4）。
> **第九波对抗审查（wave-nine，2026-08-14，HEAD = ba110ce，1 个提交）**：7 透镜并行攻击
> wave-eight 状态，约 22 条发现 → 去重约 14 条交 3 个独立怀疑者 → **13 confirmed + 1
> refuted + 多条 partial 降级**——**本轮无一条按声称的 HIGH/MEDIUM 成立**：C-2（跨实例
> check-then-act）两条承重前提被代码证伪降加固、点段族被 `has_resource` 精确匹配门阻断降
> 登记、acked keeper TTL 黑窗判为必要代价降登记。13 项修复（ba110ce）：W9-C-1 三姿态停机
> 窗口、C-2 settle 加固、E-3 三态穿出、D-1 十个建表迁移事务化（缺陷第三次复发面收口 +
> 机械检查建议登记）、S-2 restore 一致性检查、S-3 流式分发、T-1 acked 测试、F-6 贯通测试、
> CI-1/2 注释、D-1/D-2 锚点、D-3 手册限定、T-2/T-3 测试补缺；**2029 测试 0 失败（+16）**；
> 逐项状态见 `known-limitations.md` §九（第九波块）；区域修复登记见 `docs/r9-findings/`
> （A1-A4）。
> **第十波对抗审查（wave-ten，2026-08-14，HEAD = 57617bb，1 个提交）**：7 透镜并行攻击
> wave-nine 状态，约 25 条发现 → 去重约 19 条交 3 个独立怀疑者 → **13 项确认修复 + 2 项
> 并入既有登记 + 3 项部署模型仲裁降注释修正**——本轮实质收获为制品条件族（D-1 缺文件
> 楔死 / D-2 空截断静默丢失 / E-2 半套累积，全部 MEDIUM CONFIRMED，统一吸收 + EOF 比对 +
> outbox 退休修复，置 Failed 经三层证据机械不可行）；核验员的重要推翻：C-1 自败分支机制
> 被 axum 0.8.9 依赖源码推翻（分支不可达）→ 修复理由改分支一致性；F-1 派发族经部署模型
> 仲裁降 settle 注释修正 + 幂等 re-settle；**2036 测试 0 失败（+7）**；逐项状态见
> `known-limitations.md` §九（第十波块）；区域修复登记见 `docs/r10-findings/`（A1-A2）。
