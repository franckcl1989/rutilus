# Rutilus 发布就绪盘点（0.9.0 生产候选验收 + 1.0.0 全功能生产交付）

> 本文档供 0.9.0「生产候选」发布评审与 1.0.0「全功能生产交付」评审使用：
> 逐项对照设计文档 §0.9.0「验收」（`redfish-management-product-final-design.md:2812-2819`）
> 与 §1.0.0「发布条件」18 项（`:2829-2848`），并给出剩余工作分类与 1.0.0 就绪度结论。
>
> 方法与红线：只读代码 + 只写本文档。所有证据为当前 master 真实存在的 file:line 或已提交
> docs 的章节，每条新引用在本轮盘点中打开文件核实（见 §六 自检记录）。**严格区分「结构性
> 证据」（代码/门禁/测试钉死的事实）与「实测认证」（真实设备/演练/外部评估得出的结论）**：
> 结构证据不写成已实测，未做之事不声称已做。
>
> 状态标记沿用仓库文档：✅ 达成（结构或实测，表中注明性质）；🟡 部分（有结构证据，演练/
> 评估/发布级验证未做）；⏳ 待做（无代码或文档证据）。
>
> 修订说明：本版为 **迭代二十二（wave-eight 对抗修复）后复核版**（HEAD = 6d5e90e，2026-08-14）。
> 迭代六（H4/H5）已合入：
> **UI 本地化完整落地**（H5 d3f7769：`strings_catalog!` 目录扩至 827 键 En/Zh 双语、
> `Lang::{En, Zh}` 运行时语言选择器、URL fragment 持久化（`#lang=`，纯函数 `ui/src/i18n.rs:1915-1936`
> + wasm 薄封装 `ui/src/lib.rs:11607-11635`）；0f91c17 `web/assets/rutilus_ui.js/.wasm` 再生成）
> 与**发布管道代码侧**（H4 34503ea + d77d54e：`scripts/` 5 脚本 + ci.yml `release-artifacts`
> job，证书到位即启用）。深度审查批次（2026-08-12 多角色多维度）已合入 9 个修复提交
> （0984fd4 backup 断言派生 / e8424df secret gate strings_catalog 宏体豁免 /
> e611ed7 test-support 借用 / 8147bc9 认证边界硬化 B1-B4 / 1711329 迁移 down 先子后父 /
> 6128a17 ETag 携带 + 412 专用路径 / 02370db 端点读门 + 恢复判定 / fb660d5 + a4950fc i18n 槽位
> 与本地化 + 产物）：52 项发现、16 项对抗验证、2 HIGH + 13 MEDIUM 已修复、1 项此前结论被推翻
> （M1 残留面，security-review §三 M1 行），详见 `milestone-status.md` §7.4。**迭代七
> （2026-08-12）已合入 9 个提交**（84451b9 mock-bmc 统一二进制 / 044bae2 AMI/HPE 真网关 E2E /
> c4dd335 i18n fragment 纯函数测试 / 8482d85 decode-failures 贯通测试 / 4897b22 入网首刷走
> 端点读门 / e7aef53 限流器桶键剪枝 / 02459dc 恢复前快照 / 83ff07f free-port 竞态消除 /
> 61b9cc5 secret-gate 白名单行号 83/84→88/89 对齐 backup.rs 漂移，门禁漂移检测触发-修复
> 闭环——文档行号值不受该提交影响），
> §九 遗留 8 项清零 + T-C 快照 ETag 决策，三批五维审计 APPROVE，详见 `milestone-status.md`
> §7.5；§一/§二相关行已按新事实更新（备份恢复行补预快照三态、条件 12 的快照 ETag 差距改为
> 已处置）、**本轮所有受影响 file:line 已逐条打开文件重核为当前 master 实际值**（auth.rs
> T-D +263 净行、backup.rs T-E +431 净行、batch_refresh.rs/endpoint_enrollment.rs/web
> lib.rs/ui i18n.rs/ui lib.rs/test-support/app 四文件等漂移，见 §六）。**迭代八（2026-08-12）
> 已合入 6 个提交（HEAD = d1b375c）**：a80edda（进程级故障注入演练套件 `scripts/drills/` 9 个
> 文件入库——7 个 PowerShell 脚本 + RESULTS.md + .gitignore，覆盖 §19.3 剩余 4 项中的 3 项 +
> §20.1/§20.2 备份恢复 + §0.4.0 大文件中断；首轮实跑 6/6 SKIP 如实登记，挂起防护修复后快速
> FAIL 路径已验证，功能验证待真实交互控制台复跑）、9f9606e（发布级容量建议，release 构建
> 数据）、3fd0a46（release-staging 构建输出 gitignore）、3dc4f74（迭代八登记）、6a42a96
> （挂起防护一致性修复）、d1b375c（行号修复，跨文档行号引用——迭代八登记的配套收尾，归入
> 本批内）；§一「故障注入」「性能容量测试」行与 §四-B 相关行已按新事实更新（详见
> `milestone-status.md` §7.1/§7.2-B）；迭代八无 Rust 测试变化（drills 为脚本形态、行号修复
> 为纯文档），门禁计数沿用 61b9cc5 轮；**迭代十（2026-08-12，HEAD = 7533c03，3 个提交）已合入**
> （down 顺序机械门禁 `migration/tests/down_order_gate.rs` c607ae9 / SBOM 按实际产物名收集修复
> 5359f2f / 头注 bump 7533c03，详见 `milestone-status.md` 头注），计数已更新。**门禁复跑全绿（2026-08-12，
> HEAD = 7533c03）：fmt 干净、clippy `-D warnings` 全 workspace 零警告、
> 1731 测试 0 失败**（`cargo test --workspace --locked -- --test-threads 4` 口径：lib/集成
> 1731 + doc 1 = 1732；迭代十增量恰 +8，全部来自 down_order_gate）；per-crate：migration
> 38（30 基线 + 8）/ persistence 190+3 / application 301 / infra 295 /
> test-support 54 / web 133 / ui 141（含 15 个 i18n 测试）/ rutilus 145 / security 门禁 8）。
> **迭代十一（2026-08-12，HEAD = b685818，74570bc + b685818）已合入**：迭代十登记与
> 计数同步（74570bc）+ down 门禁注释精确化（b685818，注释-only 变更，down_order_gate
> 8/8 复跑全绿），计数沿用 7533c03 轮。**迭代十二（2026-08-12，HEAD = 452a291）与迭代十三
> （2026-08-13，HEAD = 6bbdf1c）已合入**：drill-lib.ps1 证书 Pin 修复（318eadd，MEDIUM）、
> m20260810_000002 down 形状修复（64125e0，MEDIUM）、深度审查边界登记（452a291）与头注
> 登记（0a5e64b，+20 行）；迭代十二登记与 §五 drill 修复（+15 行）再次推偏 17 处跨文档引用
> （含迭代九修复的 6 处 §7.1 锚，累积 +38），6bbdf1c 全部按当前 master 逐行核实后重新锚定
> （release-readiness 12 / security-review 1 / milestone-status 4），详见 `milestone-status.md`
> 头注。**收尾批次（2026-08-13，HEAD = c8bc30b，2 个提交）**：一键 drill 运行器
> `run-all-drills.ps1`（d9a9a8e）+ 运行时产物清理与 RESULTS.md 引用同步（c8bc30b，约 178 MB、
> gitignore 覆盖、证据结论零损失），人工复跑前置齐备，详见 `milestone-status.md` 头注。
> **CI 首跑修复批次（2026-08-13，HEAD = 6f8b698，4 个提交）**：首个 GitHub push/CI run 暴露
> 4 类本地（Windows）不可见的解析/平台缺陷，已全部修复：`26ad869`（fix(ci)：签名跳过 echo 的
> plain scalar 含 ": " 被 YAML 解析为 mapping 指示符、workflow 文件整体非法、每个 push 在解析期
> 失败（run 31660470408 "workflow file issue"）；单引号修复 + yq/go-yaml 全文件解析验证——该
> 文件此前从未被 GitHub 解析过）、`43fcbae`（fix(ci)：GitHub 拒绝 `if:` 条件引用 secrets context
> （"Unrecognized named-value: 'secrets'"，release-artifacts 9 处）；7 个签名相关 secret 改 job 级
> env 映射、`if:` 改比 env.X，表达式逻辑逐字节一致）、`c8ccb86`（fix(platform)：linux 目标 clippy
> 3 处——`require_private_permissions` 的 permissions 参数按值只读改引用（Unix 孪生同步、调用点
> 借用），2 个 Linux 透传 secret-store 函数 async 无 await（保留签名 + 函数级 allow，统一签名是
> 设计）；linux 目标本地复现三处全修、双平台零警告）、`6f8b698`（fix(migration)：4 个测试
> connect() 辅助的 TempDir 在池连接存活期前被 drop——Windows 删不了打开的文件故本地存活，
> Linux unlink 成功、首个写语句建 rollback journal 时 stat 已不存在的路径（SQLITE_IOERR_FSTAT
> "disk I/O error"），即首个 ubuntu CI run 报告的失败；改为随连接返回 TempDir）。**本版跨文档
> 引用已全量核对重锚（2026-08-13）**：milestone-status 头注新增行推偏 12 处指向该文档的行号
> 引用（release-readiness 11 + security-review 1），逐条打开核实重锚；known-limitations /
> support-matrix / operations-manual / security-review 锚点本轮逐条核实一致。**测试计数复核
> （2026-08-13，`cargo test --workspace -- --list` 口径）：总数 1731（lib/集成 1730 + doc 1，
> doc = test-support 头文档），与迭代十登记总数一致（迭代十登记的分解「lib/集成 1731 + doc 1
> = 1732」与 `--list` 口径不符——`--list` 总数 1731 已含 doc 1，即 lib/集成 1730）、迭代
> 十一~十四无 Rust 测试增删；per-crate
> 修正 infra-redfish 291→295（旧 291 为迭代三+四 bfb001e 实测，深度审查批次 6128a17 已 +4）与
> test-support 55→54（历史 55 混入头文档 doc-test 1，与新 `--list` 口径分离；54 = 26 lib
> 〔mock_bmc/tests.rs 21 + mock_center/mod.rs 4 + mock_center/tls.rs 1〕+ 28 集成〔gateway_mock_bmc.rs〕）**。
> **迭代十五已落地（2026-08-13，HEAD = 5cd75ae，10 个提交）——wave-one 对抗修复批次**：第一波
> 对抗审查（6 透镜，38 条 → 31 confirmed + 2 refuted + 1 降级 + 4 半/部分）的 27 项确认发现
> 全部修复（8a4d271 / 2a4340b / bcef349 / e652831 / 73d480d / 6ca207c / 3f312b2 / 31a4232 /
> d3b966a〔22 项，含 **2 HIGH：S3-1 操作历史 API 回声明文 BMC 口令、S3-2 首启未认领窗口
> GuardedOnly 整面开放**，均已修复〕/ 5cd75ae〔余 5 项：S3-4 管理员设口令端点、W6-5 路由表
> 防漂移门禁、N2-2 关停时限、N2-4 DisconnectOnDrop、C5-10 Hello 身份校验〕），逐项登记见
> `milestone-status.md` 头注/§7.6 与 `known-limitations.md` §九（第一波块）。**测试计数复核
> （2026-08-13，`cargo test --workspace -- --list` 口径）：总数 1800（lib/集成 1799 + doc 1，
> doc = test-support 头文档）**，增量 1731→1800（+69，全部来自 wave-one 测试面）；per-crate 以
> 实测为准：rutilus 152 / api 82 / application 322 / center-protocol 30 / domain 209 /
> infra-redfish 295 / migration 48 / operation-engine 33 / persistence 202 / platform 32 /
> security 52（含门禁 9）/ test-support 54+1 / ui 141 / web 147；相对迭代十登记的变化：
> migration 38→48、persistence 190+3→202、application 301→322、web 133→147、rutilus
> 145→152（infra 295 / ui 141 / test-support 54 不变）；门禁计数：security 8→9、
> down_order_gate 8→11、migration 38→48；迁移文件 25、迁移测试文件 23、备份 pin 26/25
> （`persistence/src/backup_snapshot.rs:646-647`）。
> **迭代十六已落地（2026-08-13，HEAD = e59b14a，2 个提交）——wave-two 对抗修复批次**：
> `a4ab972`（fix(ci)：assert-tests-ran.sh 单数字 pin 修复——`[1-9][0-9]*` 拒绝个位数 pin（CI
> 首跑 Secret leak gate pin 8 被拒），补 `[1-9]` 独立分支；**该提交还意外携带依赖供应链批次
> （F4-1..7：六 action SHA 钉版 + dependabot.yml + deny 理由修正 + tokio-util 单一来源 +
> audit 忽略列表锁步），e59b14a 提交说明如实披露此混合提交事实**）、`e59b14a`（fix：第二波
> 61 条发现中 60 项确认修复 + F1 追加发现，含 **2 HIGH（T1-1 路由门权限级检查、E3-1 绑定轮询
> 瞬态错误不再当撤销）**；全部门禁复跑绿：fmt 干净、clippy `-D warnings` 零警告、**1837 测试
> 0 失败（+37，wave-two 测试面）**；lipo `-verify_arch` 参数顺序修正（run 31674299719 首次
> 真实执行暴露）；per-crate 实测：rutilus 158 / api 84 / application 339 / center-protocol 30 /
> domain 209 / infra-redfish 295 / migration 50 / operation-engine 34 / persistence 209 /
> platform 32 / security 53（含 secret_leak_gate 10）/ test-support 54+1 / ui 141 / web 148；
> 相对迭代十五：center_sync.rs 34→39、down_order_gate 11→12、bare_sql_gate 4→5、secret
> leak gate 9→10；逐项登记见 `known-limitations.md` §九（第二波块）与 `milestone-status.md`
> 头注/§7.6）。**本版跨文档引用已全量核对重锚（2026-08-13，wave-two 触面
> auth.rs/web lib.rs/ci.yml/redfish_gateway.rs 等）**，§五/§六 历史登记注明其当时基准。
> **迭代十七~十九已落地（2026-08-13，HEAD = e768473 / 3a23b9b / e85560a，各 1 个提交）
> ——wave-three/four/five 对抗修复批次**：第三波（4 透镜旋转，30 条 → 29 confirmed + 1
> HIGH 降级 LOW）29 项全部修复（`e768473`：W3F-1 单候选修复不合并异目标 dispatch、
> W3S-1 改密登录同形预算 + 派生队列有界 8 等待者/503 HashGateBusy、W3S-2 审计具名 +
> session-revocation-failed、W3C-1 响应 DTO 兼容方向修正、W3C-2 失败分类上 list/detail、
> W3F-2 HEAD 走 GET 授权、W3N-2 TTL 再投递竞态愈合、W3S-3 全 bidi 类逃逸、W3S-4 用户名
> 预算按呈现场地址、W3C-3 failed-unsupported 前缀识别、W3F-3 括号/CTE 拼写捕获、W3N-3
> 重复 offer 进度入重放映射 + LOW/NOTE 组，1862 测试绿）；第四波（4 透镜，30 条 → 29
> confirmed + 1 HIGH 双透镜双确认）29 项全部修复（`3a23b9b`：**1 HIGH（V4I-1/V4R-1 审计
> outcome CHECK 十三码词汇 m20260813_000003 + 双向绑定测试）** + V4P-1..3 性能、V4I-2 信封
> 兼容、V4R-2 改密保留预留、V4R-3 target_principal_id 持久化、V4S-2/V4R-4 serde other、
> V4S-3/V4R-8 404 哑派生、V4S-5/V4R-6 前缀边界、V4R-5 退款弹呈现场地址、V4R-7 重绑自愈
> 等，1878 测试绿）；第五波（4 透镜，25 条全部 confirmed，**含 5 HIGH**）全部修复
> （`e85560a`：**5 HIGH（V5A-1 执行审计 CHECK 31 码 m20260813_000004、V5A-2 审计持久读面
> 预热、V5A-3 审计归因随姿态/来源、V5E-1 回执计分回退持久 offer 事实、V5E-2
> revoke-before-rebind 强制）** + V5C-1/2/4/5/6 认证面、V5A-4/6/7/9 审计面、V5E-3/4/5
> 中心协议面、V5M-1..4/V5A-10 + CI wasm 新鲜度门禁真修复）；**测试计数复核（2026-08-14，
> `cargo test --workspace -- --list` 实测）：总数 1913（lib/集成 1912 + doc 1）**，与提交
> 消息口径一致（增量 1837→1913，+76 = wave-three 25 + wave-four 16 + wave-five 35）；
> per-crate 实测：rutilus 167 / api 85 / application 361 / center-protocol 30 / domain 212 /
> infra-redfish 295 / migration 57 / operation-engine 34 / persistence 219 / platform 32 /
> security 53（含 secret_leak_gate 10）/ test-support 54+1 / ui 141 / web 172；迁移文件
> 25→27、迁移测试文件 23→25；逐项登记见 `known-limitations.md` §九（第三/四/五波块）与
> `milestone-status.md` 头注/§7.6。**本版跨文档引用已全量核对重锚（2026-08-14）**：
> milestone-status 头注新增 47 行推偏 10 处指向该文档的行号引用（本文件 9 处 + security-review
> 1 处），全部按当前 master 逐行核实后重锚到实际内容行（§1.1 `:242`、§1.5 `:284`、§二 验收 5
> `:339`、§五 `:374`、§7.1 逐项表 `:452-460`，见 §一/§二 对应条目）；known-limitations 新增
> 第三/四/五波块位于 §九 尾部，其前既有行号引用不受影响。
> **第六轮验证器 R6-1/2/3 重锚（2026-08-14，与迭代十七~十九登记同批）**：waves 3-5 代码改动
> 推偏的既有锚点全部按当前 master 逐行核实重锚——auth.rs（T-D 限流器 `:147, 1065, 1269-1291`
> 与测试 `:4135, 4203, 4247, 4282`、S3-4 `:2738`、B1 `:113, 1680, 1711, 1957, 2170`、B2
> `:1733-1740`、B3 `:2297-2310`、B4/M1 哑验证 `:1594, 1601, 1626, 1766-1794`、N2 `:1568`、
> N4 `:1945`、N7 `:3044`、N9 `:1880`、S3-2 `:165, 176, 210, 1352, 4414`、N2-1 测试 `:4987,
> 5060`）、center_sync.rs（风暴/幂等/重发 `:5004, 5124, 5293, 6139, 6269`、C5-3/C5-5/C5-6
> `:3974, 3998, 4048`、C1-3 `:3896`、P3-10 `:1597, 1696`、E3-2 `:680`、E3-4 `:1496, 1515`、
> E3-8 `:881, 2071-2081`、C5-8 `:756-820`、§15.5 注释 `:1649`）、web/src/lib.rs（
> `project_resource_diagnostics` `:4464`、`InitialRefreshCoordination` `:3425`、
> `credential_inventory` `:1668`、`project_capability_state` `:6388`、secret-free 清单 `:6734`、
> N5 `:1511-1514`、M1 计数 `:9798, 11292, 11356`、权限面 `:12284, 13754, 13857`、
> `BatchEndpointRefresh` `:1993`）、api/src/lib.rs（§12.4 契约 `:1903-1920`、A5-1 `:4958`、
> A5-5 脱敏边界 `:3643-3666`）、domain/src/audit.rs（`:403, 433-454, 468`）、ui/src/lib.rs
> （`CommandFamilyView::ALL` `:10821-10830`、wasm 封装 `:11614-11668`、`DiagnosticsReady`
> `:15502`）、ci.yml（release-artifacts `:609-911`、Migration 门禁 `:547` floor 50、Secret
> 门禁 `:285` floor 10、ledger/baseline `:561-575`、SBOM `:867-882`、checksums `:898`、
> 上传 `:901-911`）、web/tests/operation_path.rs `:899`、backup pin 26/25→28/27
> （`backup_snapshot.rs:646-647`）。**R6-3 登记时即错锚点**（非漂移，已修正并在 §五/§六
> 注明）：stress_capacity.rs 3 测试锚点 336/585/832→338/587/834（取 `#[tokio::test]`
> 属性行，旧值为注释行）、operation_engine.rs:1763→1863（`create_batch_redelivery_*`）、
> redfish_gateway.rs:28807→29253（`classifies_a_dropped_connection_during_the_write_*`）。
> 历史点-时登记（迭代十五/十六头注、§五 门禁复跑记录、release-readiness §六 自检记录、
> known-limitations §九 T-H/T-G/T-E/T-F 等点-时行）按惯例保留原文。
> **迭代二十已落地（2026-08-14，HEAD = 7c6ac9d，2 个提交）——wave-six 对抗修复批次**：
> 第六波对抗审查（6 透镜：并发 / 安全 / 数据迁移 / 中心协议 / web+UI+CI / 测试质量与文档）
> 并行攻击 wave-five 状态，58 条发现 → 跨透镜去重 54 条交独立怀疑者核验 → **48 confirmed +
> 3 partial + 3 refuted**；48 项确认发现全部修复（`fcf7257`，52 文件 +5659/-830）+ 3 项链式
> 发现与 A1 新拒绝码接线（`7c6ac9d`，11 文件 +841/-101）：**2 HIGH（R6-C-1 并发双派发铸双
> id 双执行——per-site dispatch 闸门临界区、R6-E-01 Unknown 后重派发逃过 inbox 去重——
> `UnknownOutcomePending` 类型化拒绝 + 409 稳定码）** + MEDIUM 组（R6-C-2 rebind TOCTOU、
> R6-C-3 停机排空补偿队列、R6-E-02 吊销站可派发、R6-E-03 re-home 回执仲裁、R6-E-04 outbox
> 剪枝 + 定向查询（`m20260814_000001`）、R6-S-1 会话撤销 fail-open、R6-S-3 secret-gate
> 标识符集、R6-D-1 down_order_gate 分号、R6-W-1/2 wasm 门禁 known-red 真修复、R6-W-3 伪造
> center 归因 400、R6-W-6 制品 2 GiB 封顶、R6-E-11 审计偏移分页）+ LOW/NOTE 组；**测试计数
> 复核（2026-08-14，`cargo test --workspace -- --list` 实测）：总数 1963（lib/集成 1962 +
> doc 1）**，增量 1913→1963（+50）——提交消息的 1958/45 为 fcf7257 中间计数，链式提交
> 7c6ac9d 另 +5；per-crate 实测：rutilus 167→175 / api 85 / application 361→371 /
> center-protocol 30 / domain 212 / infra-redfish 295 / migration 57→59 / operation-engine
> 34 / persistence 219→228 / platform 32→33 / security 53→59（含 secret_leak_gate 15） /
> test-support 54+1 / ui 141→142 / web 172→185；迁移文件 27→28、迁移测试文件 25→26；旧
> 静态备份 pin（backup_applied 28 / supported 27，原 `backup_snapshot.rs:646-647`）由
> R6-D-2 改动态派生（现 `:943-944, 983-985`），本文件 §一/§五 对该 pin 的引用已按新事实
> 同步；逐项登记见 `known-limitations.md` §九（第六波块）与 `docs/r6-findings/`
> （A1-A6 + A8 区域登记）。
> **迭代二十一已落地（2026-08-14，HEAD = a0b2bc0，1 个提交）——wave-seven 对抗修复批次**：
> 第七波对抗审查（7 透镜：修复验证 / 安全 / 并发 / 数据迁移 / 中心协议 / web+UI+CI / 性能）
> 并行攻击 wave-six 状态，40+ 条发现 → 去重约 30 条交 4 个独立怀疑者 → **27 confirmed + 4
> refuted + 3 partial 降级**；27 项全部修复（a0b2bc0，34 文件 +4591/-360，A1-A5 区域并行）：
> **3 HIGH（W7-E-1 WaitingRemote 卡死——Succeeded lead-in 补 RemoteTaskCompleted、W7-S-1
> 中心侧制品无 cap——decode_manifest 拒绝、W7-P-1 闸门内全局扫描——endpoint 作用域 + 索引）**
> + MEDIUM 组（F-1/E-2 剪枝实例维度、E-3 跨实例 Unknown 确认、F-3/E-4 target 维度、C-1/C-2
> 会话代际、C-3 Center 排空、P-2 NULL 存在性门、P-6 me_limiter 剪枝、F-2 restore 标记预检、
> D-1 决胜列 + 覆盖索引、M-1 全限定名）+ LOW/NOTE 组（C-4/E-8/F-7a/P-7/F-4/D-2/N-2/L-3/
> N-1/D-5/D-6/D-7 等）；**顺带修复 `&Outbox` blanket 委托缺失**（R6-E-04 定向读自 wave-six
> 起在生产运行时被静默遮蔽）；**测试计数复核（2026-08-14，`cargo test --workspace -- --list`
> 实测）：总数 1997（lib/集成 1996 + doc 1）**，增量 1963→1997（+34）；per-crate 实测：
> rutilus 175→183 / api 85 / application 371→380 / center-protocol 30 / domain 212 /
> infra-redfish 295 / migration 59→65 / operation-engine 34 / persistence 228→236 /
> platform 33 / security 59（含 secret_leak_gate 15）/ test-support 54+1 / ui 142→144 /
> web 185→186；迁移文件 28→30、迁移测试文件 26→28；**W7-M-2 文档锚点全量重核**（本文件
> ci.yml 行 15 处 + web lib.rs 行全组 + 对 milestone-status 的跨文档引用 + operations-manual
> §十 + security-review/milestone-status 内 ci.yml 引用——wave-six 的 +149/-62 与 wave-seven
> 触面推偏 40~280 行，全部按当前 master 逐符号 grep 重锚）；逐项登记见 `known-limitations.md`
> §九（第七波块）与 `docs/r7-findings/`（A1-A5 区域登记）。
> **迭代二十二已落地（2026-08-14，HEAD = 6d5e90e，1 个提交）——wave-eight 对抗修复批次**：
> 第八波对抗审查（7 透镜）并行攻击 wave-seven 状态，25 条发现 → 去重约 20 条交 3 个独立
> 怀疑者 → **16 confirmed + 1 refuted（W8-C-3 代回绕）+ 5 partial 降级**；16 项全部修复
> （6d5e90e，18 文件 +1958/-142，A1-A4 区域并行）：**1 HIGH（W8-E-2 未决路径 re-home
> 双执行——W7-E-3 的孪生漏洞，修复读全部换跨实例查询）** + MEDIUM 组（W8-F-2 target
> 规范化 `canonical_target_key`、W8-P-1 state 过滤 JOIN + IN 分批 999、W8-C-1 Center 停机
> 调序 + 确定性两序区分测试、W8-D-1 000003 事务化）+ LOW/NOTE 组（审计尾规范序、门禁四
> 引号态、connections 回收、mock 对齐、文案/注释/文档族）；**测试计数复核（2026-08-14，
> `cargo test --workspace -- --list` 实测）：总数 2013（lib/集成 2012 + doc 1）**，增量
> 1997→2013（+16）；per-crate：rutilus 183→187 / application 380→387 / migration 65→68
> / persistence 236→237 / ui 144→145，其余不变；逐项登记见 `known-limitations.md` §九
> （第八波块）与 `docs/r8-findings/`（A1-A4 区域登记）；本轮登记对 milestone-status 的
> 推偏（+20 行）已同步重锚本文件与 security-review 的全部交叉引用。

## 一、0.9.0 验收逐项对照（设计文档 §0.9.0「验收」）

验收原文：`redfish-management-product-final-design.md:2812-2819`。0.8.0 冻结基线事实
（47 账本 / 29 模块 / 43 操作 / 未映射 0）见 `docs/milestone-status.md` §一-§五。

| 验收项 | 状态 | 证据 | 剩余差距 / 前置条件 |
|---|---|---|---|
| P0/P1 缺陷清零 | ⏳ 发布评审流程项 | 仓库无公开缺陷台账；安全审查无 BLOCKER（`docs/security-review.md` §三；wave-one 两 HIGH 已修复，当前无 HIGH 残留） | 无缺陷台账即无「清零」的独立证据。前置条件：① 0.9.0 发布评审给出 P0/P1 清零结论（E1 捕获点已合入并通过全部门禁，门禁清单见 `ci.yml:5-21`） |
| 无已知凭据泄漏 | 🟡 部分 | 结构性证据链充分：BMC 凭据 at-rest 加密（`security/src/lib.rs:184-251`）、Master Key 不入库明文（`platform/src/master_key_file.rs`）、内存 Secret 包装与 Debug 脱敏、错误不回声（`security/src/master_key.rs:446-472`）、审计类型构造上禁秘密（`domain/src/audit.rs:403, 468`）、API 不回声秘密（`web/tests/write_path.rs:794, 826, 928`；wave-one S3-1 已修复操作历史 API 回声明文口令面，见 `security-review.md` §三 S3-1 行）、Center 投影排除凭据（`docs/security-review.md` §二#4）、命令列与中心队列 at-rest 加密（`security/src/command_cipher.rs`）、备份包只有密文（`security/src/backup_package.rs:19-23`）；结论性判断见 `security-review.md` §4.4 | 仓库级独立 Secret 泄漏扫描已落地（E3b，`security/tests/secret_leak_gate.rs`）；运行时抓包/日志复核与外部安全评估未做（`security-review.md` §4.3）——「无**已知**泄漏」的条件性结论成立，但非独立认证。前置条件：运行时复核（§四-B）+ 可选外部评估 |
| 无已知重复执行 | ✅ 结构性 | 事件去重键（`domain/src/event.rs:383` `dedup_key`）、批量重投 no-op（`operation-engine/src/operation_engine.rs:1863` `create_batch_redelivery_is_a_no_op_that_never_duplicates_children`）、重复 offer 幂等（`application/src/center_sync.rs:3974` 拒绝态不可复活、`:4048` 完成态返回记录结果）、重连重复突发只生效一次（`center_sync.rs:5124` 风暴测试） | 无已知差距；前述证据均为自动化测试钉死的结构性事实 |
| 无已知错误成功报告 | 🟡 部分 | 写后重读验证系列（`infra-redfish/src/redfish_gateway.rs` `verifies_*` 测试群，如 `:29667`）、响应丢失→Unknown 不盲重试（`redfish_gateway.rs:29253` `classifies_a_dropped_connection_during_the_write_as_result_unknown`）、**412 冲突专用路径**（`CommandExecutionError::PreconditionFailed`：BMC `412` 证明写未执行 + 重读目标不覆盖并发变更，`redfish_gateway.rs:598-611, 12653-12690, 14002-14062`，深度审查批次 commit 6128a17）、`docs/known-limitations.md` §七「HTTP 成功不等于业务成功」 | 结构性证据充分；「整体清零」是评审结论而非可自动化断言的事实。前置条件：0.9.0 发布评审对证据链复核并给出清零结论 |
| 三平台安装、升级、备份、恢复通过 | ⏳ 演练未执行 | 备份/恢复自动化往返已覆盖（`app/src/backup.rs:1068` 往返保数据、`:1112` 拒绝他实例包、`:1138` 跨机恢复需源信封、`:1225` 源口令对全新信封、`:1257` 需停止实例、`:1283` 拒绝未初始化目录、`:1294` 拒绝不同产品版本；**迭代七 T-E 02459dc 补恢复前预快照三态**：`:1324` 失败保留供回滚、`:1401` 成功清除、`:1421` 拷贝失败不动源目录）；恢复流程实现见 `docs/operations-manual.md` §六-§七 | 三平台（Windows/macOS/Linux）安装、升级、备份、恢复的**发布包级演练**未执行（§四-B）。前置条件：三平台环境 + 发布包 + 签名产物（签名本身为 C 类，见 §四-C） |
| Center/Site 长时间断线重连通过 | 🟡 部分 | 单连接语义（如 `center_sync.rs:3325` `a_closed_connection_reconnects_after_the_backoff` 断线退避重连）与**多连接并发重连风暴**（`center_sync.rs:5004` 全部 outbox 从最后 Ack 续传、`:5124` 重复突发幂等、`:6139` 心跳与重连交错、`:6269` 断线期间本地队列累积并按序排空）+ 重连进度重发（`:5293`）；`center_sync.rs` 现 **42 测试全过**（2026-08-14 实测，含 wave-two 新增 5 个）；断线行为语义见 `docs/operations-manual.md` §5.3（心跳 30s、断线判定 90s、重连退避 120s） | 长时间（跨进程/跨天）真实断线演练未执行（§四-B）。前置条件：站点 + 中心运行环境 |

### 1.1 0.9.0「内容」逐项盘点（汇总）

设计 §0.9.0「内容」清单（`redfish-management-product-final-design.md:2778-2798`）的逐项
证据链已完整记录于 `docs/milestone-status.md` §7.1（2026-08-12 复核），此处只给汇总状态，
细节引用该节：

| 内容项 | 状态 | 关键证据位置 |
|---|---|---|
| 五厂商实验室 | ⏳ | `milestone-status.md:526`（§7.1 行）；§四-B |
| 所有 Fixture 回归 | 🟡 | 合成 mock 回归齐备，脱敏真实响应 fixture 目录尚无（`known-limitations.md:77-79`） |
| 故障注入 | 🟡 | §19.3 多数场景单进程覆盖（`milestone-status.md:528`，§7.1 行）；**Windows 侧进程级演练套件已落地（`scripts/drills/` 7 脚本 + RESULTS.md，2026-08-12，覆盖 §19.3 剩余 4 项中的 3 项 + §20.1/§20.2 备份恢复 + §0.4.0 大文件中断）**，首轮实跑因执行上下文 ConPTY 不可用 6/6 SKIP、挂起防护修复后快速 FAIL 路径已验证，功能验证待真实交互控制台会话复跑；磁盘空间不足未覆盖；Linux/macOS 等价脚本未编写（ps1 为 Windows 专属）；详见 §四-B |
| 跨平台 E2E | ✅ | `ci.yml:169-185`（windows/macos 任务，web/tests 9 个路径套件 + `app/tests/version.rs`） |
| 数据库压力 | ✅ | `persistence/tests/stress_capacity.rs` 3 测试（`:338, :587, :834`），规模常量对齐设计最低验证规模（`:47-52`） |
| 中心重连风暴 | ✅ | `center_sync.rs` 42 测试（风暴 4 + 重发 1 + 单连接语义 32 + wave-two 5，见上表） |
| 大文件更新 | 🟡 | 分块机制全链路覆盖（`milestone-status.md:532`，§7.1 行）；真实固件端到端演练未做（§四-B） |
| Secret 泄漏检查 | ✅ | 结构性防护（`milestone-status.md:533`，§7.1 行）+ 独立扫描门禁已落地（E3b：`security/tests/secret_leak_gate.rs`，3 规则 R1/R2/R3、10 测试（V4I-3 重测）、`test-support` crate 目录级豁免（E3b 原始提交 eefde7e）`:96-101, 1258`、深度审查批次 e8424df 补 `strings_catalog!` 宏体结构豁免（CATALOG_MACRO 帧识别 + 新测试 `strings_catalog_macro_bodies_are_copy_construction_not_secret_assignments` `:1521`）、wave-one 73d480d 补间接赋值盲区 `:836`、wave-two e59b14a 补跨字面量 PEM 片段盲区、V4I-3 重测 10 测试；CI 独立步骤 `ci.yml:307-309` Secret leak gate，`bash scripts/assert-tests-ran.sh 10 --locked -p rutilus-security --test secret_leak_gate`，machete 之后、wasm32 之前，`if: matrix.is_default`，header 注记 `ci.yml:15-17`；运行时抓包/日志复核仍为 §四-B 演练项） |
| 权限测试 | ✅ | 角色掩码/中心站点作用域/限速/BMC 写权限拒绝（`milestone-status.md:534`，§7.1 行） |
| 安全审查 | 🟡 | `docs/security-review.md` 已交付（8 范围 + §7.7 扫描，无 BLOCKER）；MINOR-1 已修复（`web/src/auth.rs:1594, 1601, 1626`（`DUMMY_SALT`/`DUMMY_HASH`/`dummy_password_verification`）、未知用户名分支调用 `:1766`）；N5 已关闭（E3c 编译期 const assert，`web/src/lib.rs:1511`）；深度审查批次补认证边界硬化（B1-B4，commit 8147bc9：密码策略 API 边界 / 429 不写审计 / 撤销信号 / M1 残留面证反关闭，见 §三 B1-B4 行）；**迭代七**：N3 限速器桶键淘汰已实现（T-D e7aef53，web 147 全过），§九 8 项遗留全部落地/处置（`milestone-status.md` §7.5）；**迭代十五（wave-one）**：对抗第一波发现 2 HIGH（S3-1/S3-2）均已修复（d3b966a，见 `security-review.md` §三 S3-1/S3-2 行）；**迭代十七~十九（wave-three/four/five）**：第三波 S 类（W3S-1..10，改密预算/派生队列有界/审计具名/bidi 净化/呈现场地址计数等）与第四波（V4R-2/3/5/7、V4S-2/3/5）及第五波认证面（V5C-1/2/4/5/6）全部修复（e768473 / 3a23b9b / e85560a，见 `security-review.md` §三新增行），**当前 master 无 HIGH 残留**（wave-five 的 5 HIGH 为审计可问责/中心协议面，非认证面，见 `known-limitations.md` §九第五波块） |
| Migration 回归 | ✅ | `migration/tests/` 25 个测试文件（含 E4 防回归 `resource_feature_lists.rs`、wave-one 新增 `audit_center_actions.rs`/`endpoint_health_checks.rs`、wave-four/five 新增 `audit_failure_vocabulary.rs`/`audit_operation_vocabulary.rs`）；迁移总数 27；CI 门禁 `ci.yml:547`（W6-1 ran-断言 floor 50，V4I-4 重测后同步） |
| 备份恢复演练 | 🟡 | 自动化往返 10 测试（见上表证据，含迭代七 T-E 预快照三态 3 测试）；三平台演练未执行（§四-B） |
| 签名构建 / SBOM | 🟡 | 代码侧完成（`scripts/` 5 脚本 + `release-artifacts` job，commit 34503ea + d77d54e）；证书未到位、首次实跑未做（条件 17、§四-C） |
| 用户/运维/支持矩阵/已知限制手册 | ✅ | `docs/user-manual.md`、`docs/operations-manual.md`、`docs/support-matrix.md`、`docs/known-limitations.md` |
| 性能容量测试 | 🟡 | 合成规模已实测（`docs/operations-manual.md` §九，2026-08-12：debug 构建基线 + **release 构建数据已出**）；**发布级容量建议已发布（release 构建数据）**，正式规模环境复核仍待做（设计要求「测试后发布真实容量建议」，`design:2810`）——见 §四-B |

### 1.2 最低验证规模对照

设计 §0.9.0「最低验证规模」（`design:2800-2808`）：单 Site ≥200 Endpoint、单 Center
≥100 Site、中心汇总 ≥5,000 Endpoint。合成规模压力套件已按该规模实测落地
（`stress_capacity.rs:47-52` 常量 200/100/5,000；实测数据
`operations-manual.md` §九），**不再是「仅测试目标」**；「测试后发布真实容量建议」
（`design:2810`）：release 构建数据已出（2026-08-12，见 `operations-manual.md` §九），
正式规模环境复核仍待做。

## 二、1.0.0 发布条件 18 项逐条对照

1.0.0「全功能」定义（`design:2825-2828`）：**对 `NvRedfishReleaseBaseline` 所有公开功能
完成 100% 产品映射，并具备多服务器、单机、站点、中心、安全、任务、审计、备份、恢复和
跨平台交付所需的完整支撑能力。** 发布条件原文：`design:2829-2848`。

性质标注：**结构性** = 代码/门禁/测试钉死的事实，可复验；**实测** = 真实设备/演练/外部
评估得出的结论，有前置条件。

| # | 发布条件 | 状态 | 性质 | 证据（file:line） | 差距说明 |
|---|---|---|---|---|---|
| 1 | 能力账本 100% | ✅ | 结构性 | 账本 47 条 = 0.13.0 全部公开能力（`domain/src/capability.rs:401` 47 条、`:462` 14 OEM）；账本缺口为空（`milestone-status.md:358`〔§1.5〕，`release_baseline.rs:1236`）；账本 Hash 与协商 golden 钉死（`release_baseline.rs:1049-1052, 1577`；`center-protocol/src/negotiation.rs:178, 287`） | 无。0.8.0 验收达成（`milestone-status.md` §二 验收 1） |
| 2 | 标准 feature 全覆盖 | ✅ | 结构性 | 编译完整面 58 个 = 0.13.0 全集 59 减 `default`；显式 17 个与 workspace 清单双向校验（`milestone-status.md:316`〔§1.1〕；`release_baseline.rs:79, 111`）；33 个标准账本条目全部落在编译面 | 「全覆盖」= 编译面完全覆盖，已由门禁钉死；设备侧实际暴露面是条件 8 的实测范围 |
| 3 | OEM feature 全覆盖 | ✅ | 结构性 | 14 个 `oem-*` 全编译（根 `Cargo.toml:35`；`domain/src/capability.rs:462`）；编译面与领域 OEM 账本同序逐一相等（`infra-redfish/src/lib.rs:158` 测试） | 无。probe-only 的 2 项（cper/fabrics）读取面如实登记（`milestone-status.md:448`〔§五〕） |
| 4 | 所有写操作均类型化 | ✅ | 结构性 | 43 个公开写操作全部经 `nv-redfish` 类型化面（`release_baseline.rs:677`；`milestone-status.md` §1.4）；NVIDIA 9 个 OEM action 均类型化（`support-matrix.md:124-130`） | 无 |
| 5 | 不存在原始 BMC 写请求 | ✅ | 结构性 | 唯一 `nv-redfish` 依赖 crate = infra-redfish（`infra-redfish/Cargo.toml:14`）；`UpstreamBmc = HttpBmc<NvHttpClient>` 传输注入（`redfish_gateway.rs:338, 1115`）；0.8.0 验收 4 达成（`milestone-status.md` §二 验收 4） | 无 |
| 6 | 不存在裸 SQL | ✅ | 结构性 | 机械门禁：迁移 crate 只允许 DDL 裸语句、DML 词全禁（`migration/tests/bare_sql_gate.rs:35, 40, 445, 456`；wave-one 73d480d 补 CTAS/TRIGGER 内嵌 DML 扫描；wave-three W3F-3 补括号/CTE 拼写）；表重建数据复制全部 SeaQuery（`milestone-status.md:413`〔§二 验收 5〕） | 无 |
| 7 | 三平台单二进制发布 | 🟡 | 结构性（构建矩阵）+ 实测缺位 | 构建矩阵入 CI：x86_64 musl（`ci.yml:538-543`）、aarch64 musl cargo-zigbuild（`ci.yml:550-554`）、macOS Universal 2 lipo 合并 + `lipo -verify_arch x86_64 arm64` 校验（`ci.yml:565-598`）；三平台编译 + wasm32 UI 产物 diff（`ci.yml:85-101, 406-521`）；Windows ARM64 明确不入 CI（`ci.yml:558-564` 注释：hosted x64 runner 无 ARM64 MSVC 链接器与 SDK 导入库）；发布配置与 §5.4 一致（`Cargo.toml:110-116`；`rust-toolchain.toml` 已固定；Cargo.lock 已提交）；单二进制自包含边界（`support-matrix.md:85-88`） | ① Windows ARM64 发布目标无 CI 构建、无安装验证（§四-B，前置：原生 ARM64 runner 或本地 ARM64 主机）；② 三平台**发布包级**安装/运行验证并入条件 15 演练（§四-B）；③ 签名（条件 17）前置 |
| 8 | 五厂商标准能力验证 | ⏳ | 实测 | Mock 层已覆盖五厂商 profile（`test-support/src/mock_bmc/profile.rs:47-133`）；§19.1 Physical Device Test「五厂商至少各一台真实设备进入 1.0.0 认证矩阵」未达成（`design:2320-2322`；`known-limitations.md:79`） | 前置条件：五厂商真实设备实验室（§四-B）。当前结论只能是「基于上游类型面与 mock/fixture 验证」，不是实测认证（`known-limitations.md:80`） |
| 9 | Dell、HPE、Lenovo 上游 OEM 能力验证 | ⏳ | 实测 | Dell/HPE/Lenovo OEM 读取面已编译并映射（`support-matrix.md:113-118`）；真实设备验证未达成（同上） | 前置条件：Dell/HPE/Lenovo 设备各一台（§四-B）；验证范围限标准 feature + 上游已有 OEM feature，不声称覆盖全部 OEM API（`design:2326-2334`） |
| 10 | xFusion、Inspur 标准模式限制明确 | ✅ | 结构性（文档）+ 实测缺位 | 限制已明确成文：上游无 xFusion/Inspur OEM feature，只能用标准 Redfish 能力，OEM-only 标 `NotAvailableInNvRedfishBaseline`（`support-matrix.md:135-142`；`design:2336-2352`）；mock 变体验证标准模式行为 | 「限制明确」这一文档条件达成；设备侧标准模式验证并入条件 8（§四-B） |
| 11 | 所有异步操作可恢复 | ✅ | 结构性（恢复路径实测于自动化测试）+ 发布级演练缺位 | 升级流程含「恢复 Task 跟踪（扫描 WaitingRemote、重建 Session、继续读取 Task）」（`operations-manual.md:216-218`）；remote_tasks 迁移回归（`migration/tests/remote_tasks.rs`）；执行引擎恢复语义（`operation-engine`，`operations-manual.md` §七） | 跨进程重启恢复已有实现与自动化覆盖；真实升级演练（备份→停→换二进制→启动→任务恢复）并入 §四-B 演练 |
| 12 | 所有写操作有最终验证 | 🟡 | 结构性 | 写后重读验证系列与响应丢失→Unknown 语义（见 §一「无已知错误成功报告」行；`redfish_gateway.rs` `verifies_*` 测试群）；**ETag/412 冲突路径已真实生效**（深度审查批次，commit 6128a17）：`update` 写家族携带执行时读取的 ETag、`412 Precondition Failed` 走 `CommandExecutionError::PreconditionFailed`（重读目标、并发变更不被覆盖，`redfish_gateway.rs:598-611, 12653-12690, 14002-14062`，测试 `:25432, 27314-27420`）；**快照 ETag 接线已处置**（迭代七，决策 c，2026-08-12——快照 ETag 无独立写路径消费价值，接线不实施，论证见 `known-limitations.md` §九该行）；action/create/delete 家族无 If-Match 通道为已知差距（§13.4 第二段如实标注）；`known-limitations.md` §七「HTTP 成功不等于业务成功」 | 结构性证据充分；「所有写操作均有最终验证」的完整结论依赖 0.9.0 发布评审对证据链的复核与清零结论（§一） |
| 13 | Center 不保存 BMC Secret | ✅ | 结构性 | Center 投影只含 display_name/address/generation/health/resources，注释「the center never sees credentials or sessions」（`application/src/center_sync.rs:1649`）；投影表无凭据列（`persistence/src/center_projection_repository.rs` 全文件 grep 无 credential/password/secret 命中）；安全审查范围 4 结论（`security-review.md` §二#4）；Site 本地解密边界（凭据表只存在于 Site 库） | 无。0.7.0 验收「Center 不保存 BMC 密码」达成（`design:2728-2735`） |
| 14 | Site 脱离 Center 完整运行 | ✅ | 结构性 | 0.7.0 验收达成（`design:2728-2735`）；断线后端点刷新/操作/本地 GUI 继续运行（`operations-manual.md:161`）；断线期间本地队列累积、重连按序排空（`center_sync.rs:6269`）；中心不可用不影响站点已接受任务（`operations-manual.md:110`） | 无 |
| 15 | 备份恢复通过 | 🟡 | 结构性（自动化往返 10 测试，含 T-E 预快照三态）+ 实测缺位 | `app/src/backup.rs:1068, 1112, 1138, 1225, 1257, 1283, 1294, 1324, 1401, 1421`（见 §一第 5 行证据；迭代七 T-E 02459dc 新增 3 个预快照测试）；流程与身份校验（`operations-manual.md` §六）；§20.1/20.2 对照（`design:2403-2446`） | 三平台安装/升级/备份/恢复演练未执行（§四-B）——0.9.0 验收同项 |
| 16 | 数据库 Migration 通过 | ✅ | 结构性 | 27 个 migration（`operations-manual.md:221`；`migration/tests/initial_storage.rs`；E1/E4 新增 `m20260812_000001_resource_decode_failures` 与 `m20260812_000002_resource_feature_lists`，wave-one 新增 `m20260813_000001_audit_center_actions` 与 `m20260813_000002_endpoint_health_checks`，wave-four 新增 `m20260813_000003_audit_failure_vocabulary`，wave-five 新增 `m20260813_000004_audit_operation_vocabulary`）；25 个测试文件回归 + CI 独立门禁（`ci.yml:547`）；裸 SQL 机械门禁（条件 6）；迁移前自动备份（`persistence/src/lib.rs:510`） | 无 |
| 17 | 正式签名和 SBOM | 🟡 代码侧完成（流水线就绪，证书未到位） | 结构性（管道已入 CI；首次实跑未做） | 管道证据：`scripts/` 5 脚本（sign-windows.ps1 / sign-macos.sh / sign-linux.sh / checksums.sh / checksums.ps1，commit 34503ea）；ci.yml `release-artifacts` job（commit d77d54e，`ci.yml:609-911`）——`v*` tag push / `workflow_dispatch` 触发（`ci.yml:48-60`）、`needs: ci` 门禁先行（`ci.yml:613`）、签名步骤仅在对应 secret 配置时执行（`ci.yml:748, 773, 805`，未配置则 "signing skipped: certificate not configured"（`ci.yml:837`））、Windows Authenticode（PFX base64 物化 `ci.yml:748-757` 或 thumbprint-only `ci.yml:759-765`）、macOS Developer ID + notarization（`.p8` 物化 `ci.yml:773-781`）、Linux minisign（密钥物化 `ci.yml:805-808`）、SBOM cargo-cyclonedx@0.5.9 钉版（`ci.yml:867-882`）、SHA-256 清单（`ci.yml:898`）、artifact 上传（`ci.yml:901-911`）；§5.4「构建结果嵌入 Git Commit」**已实现**（E3a：CI 在 job 级注入 `RUTILUS_GIT_COMMIT`（`ci.yml:84`），二进制经 `GIT_COMMIT` 常量嵌入（`app/src/main.rs:38-40`），`rutilus version` 输出三行（`:733-737`），本地无该变量时降级 `dev`；`app/src/standalone_runtime.rs:1541` WebProductInfo 嵌入）。**6 项首跑确认点**（证书到位后首次实跑核验）：① musl-tools 安装（`ci.yml:692`）；② cargo-cyclonedx@0.5.9 钉版（`ci.yml:867-874`）；③ base64 物化（`ci.yml:748-757, 773-781, 805-808`）；④ env 的 `&&`/`||` 表达式（`ci.yml:765, 795`〔Linux 同款〕）；⑤ thumbprint-only 模式（`ci.yml:759-765`）；⑥ 上传权限（`ci.yml:901-911`；workflow `permissions: contents: read` `ci.yml:63`） | 前置条件：证书/账号——RUTILUS_WINDOWS_CERT_B64/THUMBPRINT(+PASSWORD)、RUTILUS_MAC_CERT_ID + RUTILUS_NOTARY_KEY_ID/B64/TEAM_ID、RUTILUS_LINUX_SIGN_KEY_B64（`ci.yml:634-640`；§四-C）。**1.0.0 发布硬条件** |
| 18 | 用户、运维、兼容和故障文档完成 | ✅ | 结构性 | `docs/user-manual.md`（436 行）；`docs/operations-manual.md`（数据/服务/备份/升级/诊断/容量，§8.1 含 `--log-format json`）；`docs/support-matrix.md`（基线/平台/厂商/不承诺）；`docs/known-limitations.md`（OutOfScope/依赖风险/测试基建局限/容量/偏差）；故障语义与诊断（`operations-manual.md` §八、`known-limitations.md` §七） | 「故障文档」由 known-limitations（已知限制与偏差）+ operations §八（doctor/诊断）承担，与设计 §0.9.0 内容一致；故障注入演练结果文档待 §四-B 完成后补充 |

## 三、剩余工作分类

### A. 代码/CI 可做（不依赖外部资源，可直接进入迭代）

> （2026-08-12，master d77d54e）本表 A 类工作项已全部完成或移交：E1 / E3b（仓库级）/ E3c /
> N5 均 ✅；UI 本地化本轮转 ✅；Windows ARM64 已移交 §三-B（依赖原生 runner，非 A 类可做）。
> **A 类不再有未完成项。**

| 工作项 | 状态 | 负责方 | 前置条件 | 证据/来源 |
|---|---|---|---|---|
| §12.4 诊断解码失败**生产捕获点**（gateway 捕获 + SQLite 持久化） | ✅ 已合入（E1，commit ce2b8b3） | 全组评审复验（证据链见下） | 无（已合并，全部门禁复跑通过） | 网关捕获：`DecodeFailureObservation`（`infra-redfish/src/redfish_gateway.rs:8811`），捕获函数 `capture_fetch_failure`/`capture_projection_failure`/`capture_segment_decode_failure`（`:8995, :9022, :9068`），刷新结果经 `outcome.decode_failures()` 流出（`:8922`）；同代事务提交：`persistence/src/resource_snapshot_repository.rs:81-147`（`commit_resource_generation` 在快照同一事务内写 `resource_decode_failures`），生产链路 `application/src/endpoint_refresh.rs:350-355` 直连；新表 + entity（`entity/src/lib.rs:28`、`entity/src/resource_decode_failure.rs:13`）+ 迁移 `m20260812_000001`（E4 由 `m20260812_000002` 重建约束为领域枚举 47 码）；web 端到端 7 测试（`web/tests/diagnostics_path.rs:848-1185`，含 `refresh_capture_flows_into_the_diagnostics_response` `:1008`）；现状登记见 `known-limitations.md` §八「§12.4」行 |
| 独立 Secret 泄漏扫描（仓库级自动扫描 + 运行时抓包/日志复核） | ✅ 仓库级已落地（E3b）/ 运行时复核待做 | 安全评审 + CI | 无（仓库级部分）；运行时复核需三平台演示环境（可并入 B） | `security/tests/secret_leak_gate.rs`：3 规则（R1 硬编码秘密 / R2 内嵌私钥 PEM / R3 明文输出宏泄露）、10 测试（`:1427, :1439, :1450, :1460, :1485, :1588, :1637, :1669, :1716, :1760`，e59b14a 后实测——wave-two T1-4 补跨字面量拆分 PEM 私钥盲区）、白名单 = `ALLOWED_CONSTANT_HITS` 2 处（path+line+name+literal 四元组绑定，`app/src/backup.rs:88, 89` 备份条目名）、`test-support` crate 目录级豁免（fixture scope，`:96-101, 1258`，E3b 原始提交 eefde7e）+ `strings_catalog!` 宏体结构豁免（深度审查批次 commit e8424df：CATALOG_MACRO 帧识别 `:575, 1038-1043`，新测试 `strings_catalog_macro_bodies_are_copy_construction_not_secret_assignments` `:1521`）+ wave-one 间接赋值盲区（73d480d：`wrapper_or_indirect` `:836`）+ wave-two 跨字面量拆分 PEM 私钥盲区（e59b14a，T1-4，`pem_fragment_violation` `:886`）；门禁为 CI 独立步骤（`ci.yml:307-309` Secret leak gate，`bash scripts/assert-tests-ran.sh 10 --locked -p rutilus-security --test secret_leak_gate`，`if: matrix.is_default`，machete 之后、wasm32 之前；header 注记 `ci.yml:15-17`）；运行时抓包/日志复核仍为 §四-B 项（`security-review.md:183`） |
| UI 本地化 | ✅ 已完整落地（H5 d3f7769 + 0f91c17 + T-H c4dd335：`strings_catalog!` 目录 827 键 En/Zh 双语（`i18n.rs:163-1858`）、`Lang::{En, Zh}` 运行时语言选择（`thread_local!` `i18n.rs:1938-1942` + `L()` `i18n.rs:1968-1973`）、lib.rs `LanguageSelector` 组件（`lib.rs:11725`）与 URL fragment 持久化（**迭代七 T-H 已拆为纯函数 + 薄封装**：`stored_lang_code_from`/`lang_fragment_value` `i18n.rs:1915-1936`、wasm 封装 `lib.rs:11692-11724`、启动恢复 `start()` `lib.rs:11746`）；ui 144 测试全过；深度审查批次补 `format_catalog` 槽位硬化与本地化（fb660d5 + a4950fc，`i18n.rs:1984-2006`，见 `milestone-status.md` §7.4）） | 前端组 | 后续触点：localStorage 持久化（需扩展 web-sys feature）与更多语言；1.0.0 定义与 18 项条件均不涉及，**不阻塞 1.0.0** | `known-limitations.md:132`；`milestone-status.md:578` |
| N5 `unreachable!` 处置（可选，NOTE 级） | ✅ 已完成（E3c） | — | 无 | `security-review.md` §三 N5 已关闭：`web/src/lib.rs:1511` 编译期 `const _: () = assert!(rutilus_api::OVERVIEW_RECENT_EVENTS > 0);` 钉死常量正性（注释 `:1505-1510`），运行时 guard 保留为已被断言证明不可达的防御分支（`:1512-1514`） |
| 发布级 CI 扩展（Windows ARM64 原生 runner） | ✅ 移交 §三-B（依赖原生 runner，非 A 类可做） | — | 原生 ARM64 Windows runner 或本地 ARM64 主机验证后另行处理 | `ci.yml:558-564` 注释；§三-B「Windows ARM64 发布验证」行 |

### B. 依赖演练环境（物理设备 / 规模环境 / 三平台流程）

| 工作项 | 说明 | 前置条件 | 对应 1.0.0 条件 |
|---|---|---|---|
| 五厂商实验室 / 真实设备认证矩阵 | Dell/HPE/Lenovo/xFusion/Inspur 各至少一台真实设备进入认证矩阵；验证标准 feature + 上游已有 OEM feature（Dell/HPE/Lenovo）、标准模式限制（xFusion/Inspur） | 五厂商设备与网络环境 | 8、9、10 |
| 真实响应 fixture 目录 | 五厂商各固件版本脱敏真实响应，随 nv-redfish 升级回归（§19.1 Fixture Test） | 设备抓取 → 脱敏 → 入库 | 8、9 的回归基础 |
| 进程级故障注入演练 | **Windows 侧套件已落地（`scripts/drills/` 7 脚本 + RESULTS.md，2026-08-12）**：覆盖产品进程在任务中被终止 / BMC 更新中重启 / SQLite 写入中断（§19.3 剩余 4 项中的 3 项）+ 备份恢复（§20.1/§20.2）+ 大文件中断（§0.4.0）；首轮实跑因执行上下文 ConPTY 不可用 6/6 SKIP、挂起防护修复后快速 FAIL 路径已验证，**功能验证待真实交互控制台会话复跑**；**磁盘空间不足未覆盖**；Linux/macOS 等价脚本未编写（ps1 为 Windows 专属） | Windows 本机：debug 构建（rutilus.exe + mock-bmc.exe）+ 真实交互控制台（ConPTY）；跨平台等价脚本待编写 | 11、12 的实测面 |
| 大文件更新端到端演练 | 真实大固件文件的上传→校验→分发→应用 | 真实固件制品 + 设备或等价测试台 | 12 的实测面 |
| 三平台安装/升级/备份/恢复演练 | 0.9.0 验收第 5 项、1.0.0 条件 15：Windows/macOS/Linux 各跑安装→备份→升级→恢复→任务恢复 | 三平台机器 + 发布包 + 签名产物（签名属 C） | 7、15 |
| Center/Site 长时间断线重连演练 | 0.9.0 验收第 6 项：跨进程/跨天真实断线（自动化风暴已覆盖单进程形态） | 站点 + 中心运行环境 | 14 的实测面 |
| 发布级容量建议 | 设计要求「测试后发布真实容量建议」：release 构建数据已出（2026-08-12，`operations-manual.md` §九），正式规模环境复核后定稿发布 | 正式规模环境 | 7 的配套交付物 |
| Windows ARM64 发布验证 | `aarch64-pc-windows-msvc` 发布目标：构建 + 安装/运行验证 | 原生 ARM64 Windows runner 或本地 ARM64 主机 | 7 |

### C. 依赖发布管道（外部证书 / 签名服务 / 发布流程）

> （2026-08-12，master d77d54e）代码侧已就绪：`scripts/` 5 脚本 + ci.yml `release-artifacts`
> job（commit 34503ea + d77d54e，条件 17）——本表各项剩余前置仅为证书/账号与证书到位后的
> 首次实跑；新增「首次 release 实跑演练」行如下。

| 工作项 | 说明 | 前置条件 | 对应条款 |
|---|---|---|---|
| Windows Authenticode 签名 | 发布包代码签名 | 代码签名证书（含时间戳服务） | `design:654`；条件 17 |
| macOS 签名与公证 | Developer ID 签名 + notarization + staple | Apple Developer 账号与证书 | `design:655`；条件 17 |
| Linux 独立签名 | 独立签名 + 公钥发布路径 | 签名密钥/签名服务 | `design:656`；条件 17 |
| SBOM 生成与发布 | cargo-cyclonedx 等工具生成 SPDX/CycloneDX，随发布产物发布 | 工具选型与发布流程挂接 | `design:652`；条件 17 |
| §5.4 构建信息嵌入补齐 | ✅ 已完成（E3a）：Git Commit 经 job 级 `RUTILUS_GIT_COMMIT` 注入（`ci.yml:84`）、`GIT_COMMIT` 常量嵌入（`app/src/main.rs:38-40`）、`rutilus version` 三行输出（`:733-737`）、本地无变量时降级 `dev`（`app/tests/version.rs:8-11, 27-36` 派生断言）；§5.4 四项构建结果（产品版本 + Git Commit + 基线 + 账本 Hash）已全部嵌入 | 无 | `design:657` |
| SHA-256 校验清单 | 发布产物清单随包发布（`release-artifacts` job 已用 `scripts/checksums.sh` 生成 `release/SHA256SUMS`，`ci.yml:898`） | 发布流程 | `design:653` |
| 证书到位后首次 release 实跑演练 | 签名/SBOM/校验链全流程首跑：Windows Authenticode、macOS 签名与公证、Linux minisign、SBOM 生成、SHA-256 清单、artifact 上传——核验 **6 项确认点**（musl-tools 安装 / cargo-cyclonedx@0.5.9 钉版 / base64 物化 / env `&&`·`||` 表达式 / thumbprint-only 模式 / 上传权限，见条件 17） | 证书/账号（RUTILUS_WINDOWS_CERT_* / RUTILUS_MAC_* / RUTILUS_NOTARY_* / RUTILUS_LINUX_SIGN_* secrets，`ci.yml:634-640`） | 条件 17 |

## 四、1.0.0 就绪度结论

按 1.0.0 定义（`design:2825-2828`）拆解：

**1. 功能映射面（「NvRedfishReleaseBaseline 所有公开功能 100% 产品映射」）：结构性 100% 达成。**
条件 1-6 全部 ✅：47 账本 / 29 模块 / 43 操作 / 未映射 0 由 0.8.0 冻结 + 门禁钉死
（`milestone-status.md` §一-§二），写操作全类型化、无原始 BMC 写请求、无裸 SQL 均为机械
门禁可复验事实。此面**不依赖外部资源**；E1 已合入且 Release Baseline / Capability Ledger /
Migration 门禁已复跑通过（`ci.yml:547, 561-563, 573-575`），本版行号均按合并后 master 复核。

**2. 支撑能力面（安全、任务、审计、备份、恢复、跨平台交付）：结构性支撑充分，实测认证缺位。**
- 已结构达成：Center 不保存 BMC Secret（13 ✅）、Site 脱离 Center 完整运行（14 ✅）、
  数据库 Migration（16 ✅）、文档四件套（18 ✅）、异步操作恢复实现（11 ✅ 结构性）。
- 缺实测认证：真实设备验证（8/9/10 ⏳）、三平台备份恢复演练（15 🟡）、所有写操作最终
  验证的评审清零结论（12 🟡）、发布级容量建议的正式规模环境复核（🟡；release 构建数据已出，
  2026-08-12，见 `operations-manual.md` §九）。
- 硬缺口：签名与 SBOM（17 🟡）——代码侧已就绪（`scripts/` 5 脚本 + `release-artifacts` job，
  commit 34503ea + d77d54e），剩余全部为外部证书与账号（C 类）+ 证书到位后的首次实跑
  （6 项确认点，见条件 17）；应最早启动证书申请以并行于 B 类演练（Git Commit 嵌入已补齐，
  见条件 17）。

**3. 差距清单（按 1.0.0 发布阻塞度）：**

| 级别 | 差距 | 类别 | 前置条件 |
|---|---|---|---|
| 阻塞（硬条件未达成） | 条件 17 签名与 SBOM（代码侧已完成，待证书与首次实跑） | C | 证书/账号 + 6 项首跑确认点（见条件 17） |
| 阻塞（硬条件未达成） | 条件 8/9/10 五厂商真实设备验证 | B | 五厂商设备 |
| 阻塞（硬条件未达成） | 条件 15 三平台备份恢复演练（0.9.0 验收第 5 项同） | B | 三平台 + 发布包（含签名，链条依赖 C） |
| 阻塞（硬条件未达成） | 条件 7 的 Windows ARM64 发布目标验证 | B/基础设施 | 原生 ARM64 runner |
| 评审前须完成 | 0.9.0 验收第 1/4 项评审结论（P0/P1 清零、错误成功报告清零） | 评审流程 | 上述证据链 |
| 评审建议完成 | Secret 泄漏扫描的运行时复核（仓库级门禁已落地，E3b） | A（运行时复核并入 B） | 三平台演示环境 |
| 评审建议完成 | 发布级容量建议（release 构建数据已出，2026-08-12）；正式规模环境复核 | B | 正式规模环境 |
| 不阻塞 | UI 本地化（✅ 已完整落地：827 键 En/Zh 双语 + 运行时语言选择器 + URL fragment 持久化） | A | — |

**4. 结论：** 0.9.0 六项验收中 1 项 ✅、3 项 🟡、2 项 ⏳，**尚不满足 0.9.0 发布条件**——
缺口全部集中在「评审流程结论」与「B/C 类演练/管道」，无结构性缺陷登记（安全审查无
BLOCKER；N5 已关闭、Secret 扫描门禁已落地、E1 捕获点与 E4 约束修复已合入）。1.0.0 的
功能映射面已结构性 100% 达成；距 1.0.0 发布的差距为**可枚举、有明确前置条件的 B/C 类
工作 + 评审流程结论**，不存在未知的架构性风险。建议路径：C 类（证书申请启动——签名/SBOM
代码侧已就绪，链路剩余为证书 + 首次实跑）先行并尽早启动 B 类设备与三平台环境，B 类逐项
执行并以演练结果回填本文档 §一/§二状态。

## 五、引用与复验纪律

> 本节的登记为历史记录：各条目描述其登记时（HEAD = d1b375c 起逐轮推进）的核实状态，注明
> 当时的基准 HEAD 与口径。**2026-08-13 迭代十五（wave-one）后的全量重核见头注**：wave-one
> 触面（auth.rs 重写 +1119 行、web lib.rs +420 行、ci.yml 重排、backup.rs/center_sync.rs/
> operation_engine.rs/negotiation.rs/batch_refresh.rs/web tests 等）的全部既有引用已逐条打开
> 文件按 5cd75ae 重锚，本节的旧值不构成当前事实。
- 本版（HEAD = d1b375c）已登记迭代六（H4/H5）落地（UI 本地化完整落地 d3f7769 + 0f91c17、
  发布管道代码侧 34503ea + d77d54e）、**深度审查批次**（9 个修复提交，2026-08-12，详见
  `milestone-status.md` §7.4）、**迭代七**（9 个提交 + T-C 决策，2026-08-12，§九遗留 8 项
  清零，详见 `milestone-status.md` §7.5）与**迭代八**（drills 套件 + 容量建议 + 行号修复，
  6 个提交，2026-08-12，详见 `milestone-status.md` §7.1/§7.2-B）。深度审查批次触面（`web/src/auth.rs`、
  `infra-redfish/src/redfish_gateway.rs`、`application/src/batch_refresh.rs`、
  `application/src/operation_executor.rs`、`migration/src/`、`ui/src/i18n.rs`、
  `app/src/backup.rs`、`security/tests/secret_leak_gate.rs`）的每个 file:line 均在本轮打开
  文件核实（§六记录）；**迭代七触面（`web/src/auth.rs` +263 净行、`app/src/backup.rs` +431
  净行、`application/src/endpoint_enrollment.rs`/`batch_refresh.rs`、`web/src/lib.rs` +9、
  `ui/src/i18n.rs` +103、`ui/src/lib.rs`、`test-support/`、`app/src/center_acceptor.rs`/
  `center_runtime.rs`/`center_client.rs`/`site_runtime.rs` +271 行分布、`application/src/lib.rs`）
  的全部既有引用已逐条打开文件重核为当前 master 实际行号并修正（§六记录）**；此前的
  E1/E3a/E3b/E3c/E4、H1/H2、H4/H5 触面行号保持合并后已核实的值；遗留旧 ci.yml 引用已
  在前轮全部重核换算完毕。
- 门禁复跑（2026-08-13，迭代十五后，HEAD = 5cd75ae）：**fmt 干净、clippy `-D warnings` 全 workspace 零警告、
  1800 测试 0 失败**（`cargo test --workspace -- --list` 口径：lib/集成 1799 + doc 1 = 1800；
  增量 1731→1800，+69 全部来自 wave-one 测试面）；`ci.yml:393-423`（Migration `:393-395`、Capability Ledger `:409-411`、
  Release Baseline `:421-423`）独立门禁复跑通过；per-crate 口径（2026-08-13 实测）：migration 48 /
  persistence 202 / application 322 / infra 295 / test-support 54（+1 doc-test）/
  web 147 / ui 141（含 15 个 i18n 测试）/ rutilus 152 / security 52（门禁 9）。
  上一轮（迭代十，2026-08-12，HEAD = 7533c03）的 1731/38/301/133/145/门禁 8 为当时实测，保留为历史基准。
- 门禁复跑（2026-08-13，迭代十六后，HEAD = e59b14a）：**fmt 干净、clippy `-D warnings` 全 workspace 零警告、
  **1837 测试 0 失败**（`cargo test --workspace -- --list` 口径：lib/集成 1836 + doc 1 = 1837；
  增量 1800→1837，+37 全部来自 wave-two 测试面）；per-crate 口径（2026-08-13 实测）：
  rutilus 158 / api 84 / application 339 / center-protocol 30 / domain 209 / infra-redfish 295 /
  migration 50 / operation-engine 34 / persistence 209 / platform 32 / security 53（含门禁 10）/
  test-support 54（+1 doc-test）/ ui 141 / web 148；门禁计数：down_order_gate 11→12、
  bare_sql_gate 4→5、secret leak gate 9→10（`assert-tests-ran.sh` floor 8/38 为下界 pin 保持不动）。
- 门禁复跑（2026-08-14，迭代十九后，HEAD = e85560a）：**fmt 干净、clippy `-D warnings` 全 workspace 零警告、
  **1913 测试 0 失败**（`cargo test --workspace -- --list` 实测：lib/集成 1912 + doc 1 = 1913；
  增量 1837→1913，+76 = wave-three 25 + wave-four 16 + wave-five 35，与三提交消息口径一致）；
  per-crate 口径（2026-08-14 实测）：rutilus 167 / api 85 / application 361 / center-protocol 30 /
  domain 212 / infra-redfish 295 / migration 57 / operation-engine 34 / persistence 219 /
  platform 32 / security 53（含 secret_leak_gate 10）/ test-support 54（+1 doc-test）/ ui 141 /
  web 172；门禁计数：down_order_gate 12、bare_sql_gate 5（W3F-3 括号/CTE 拼写补入既有测试，
  测试数不变）、secret leak gate 10（V4I-3 重测）、migration 50→57；迁移文件 25→27、迁移
  测试文件 23→25；`assert-tests-ran.sh` 现用 pin 为 10/50（与 ci.yml 门禁步骤一致，2026-08-14
  已同步注释）。
- 引用自检记录见下节（每个 file:line 均在本轮打开核实）。

## 六、引用自检记录（2026-08-12，HEAD d1b375c 复核，迭代八后；历史记录）

> 本节的每一行是**历史核实记录**，描述其登记轮次（迭代八~迭代十四）当时打开文件核实的结果；
> 其引用的行号值已在 2026-08-13 迭代十五（wave-one）复核中按 5cd75ae 全量重锚（见头注），
> 本节旧值不构成当前事实，仅保留核实过程的可追溯性。

本轮逐一打开核实的引用（含全部 E1/E3a/E3b/E3c/E4、H1/H2、H4/H5、深度审查批次触面与
**迭代七触面**——迭代七新增触面的旧引用一律打开文件按当前 master 重核，不沿用前轮值）：

| 引用 | 核实结果 |
|---|---|
| `design:2778-2819`（§0.9.0 内容/规模/验收）、`:2823-2848`（1.0.0 定义与 18 项）、`:2280-2397`（§19 测试/故障注入/CI 门槛）、`:2403-2464`（§20 备份恢复升级）、`:633-657`（§5.4 发布配置）、`:2728-2766`（0.7.0/0.8.0 验收） | 打开核实，行号一致（设计文档冻结，未变） |
| `domain/src/capability.rs:401, 462`（47 账本 / 14 OEM） | 打开核实，`:401` 47 条、`:462` 14 条 |
| `domain/src/event.rs:383`（dedup_key）、`domain/src/audit.rs:318-394`（审计构造上禁秘密） | 打开核实，行号一致 |
| `operation-engine/src/operation_engine.rs:1332`（批量重投 no-op 测试）、`:986`（时钟回拨） | 打开核实，行号一致 |
| `release_baseline.rs:59, 68, 79, 111, 177, 280-285, 296-308, 372, 646, 677, 745, 778, 790, 1025, 1039, 1049-1052, 1236, 1395, 1422, 1457, 1471, 1506-1513, 1517, 1577, 1589, 1638, 1688, 1705, 1734` | 打开核实，全部一致（E1/E3 未触达该文件） |
| `app/src/main.rs:27`（PRODUCT_VERSION）、`:38-40`（GIT_COMMIT，E3a）、`:58-64`（LogFormat 枚举）、`:97, 144`（backup/restore 子命令）、`:255-273`（init_tracing）、`:733-737`（version 三行输出） | 打开核实（旧引用 38-39/240-258/720 漂移，已按实际值引用） |
| `app/tests/version.rs:8-11, 27-36`、`app/tests/log_format.rs:7-10, 23-28`（三行派生断言，E3a） | 打开核实 |
| `app/src/backup.rs:765, 799, 825, 912, 944, 970, 981`（备份恢复 7 测试）、`:83-84`（备份条目名常量） | 打开核实（a4950fc 轮，行号一致）；**F3 重核（T-E 02459dc +431 净行）：7 测试 → `:1051, 1095, 1121, 1208, 1240, 1266, 1277`（备份条目名常量 `:88-89`）；T-E 新增 3 测试 `:1307, 1384, 1404`；`create_backup` `:170-211`、`restore_backup` `:246-327`、`create_pre_restore_snapshot` `:619-643`、`check_product_version` `:739-750`、schema 断言派生 `:1068-1072`** |
| `app/src/standalone_runtime.rs:1456`（WebProductInfo 嵌入）、`app/src/site_runtime.rs:568` | 打开核实（旧 1454 漂移 +2） |
| `web/src/auth.rs:83, 101-116, 514, 863-866, 863-937, 950-956, 1078-1080, 1096-1112, 1147-1159, 1200-1213, 1226, 1233, 1254-1265, 1267-1276（B1 密码策略）, 1305-1315, 1321-1335（B1/B2 登录入口与 429）, 1357（M1 未知用户名分支调用）, 1365-1400（B4 哑验证）, 1533（bootstrap_complete）, 1749-1776（B3 撤销信号与改密撤销）, 2066-2071, 2128-2131（禁用/角色变更撤销）, 2208-2257（登录审计）, 2261-2284（管理事件）, 2289-2292（best-effort）, 2688`（M1/B1-B4 与限速/会话/审计面） | 打开核实；F2 复核修正残留漂移（记录见左列前值）。**F3 重核（T-D e7aef53 +263 净行，限速器区段重构后全部后移）：`SESSION_COOKIE_NAME` 83→73、限速常量 101-116→102-118、`RouteAccess::Public` 504 / bootstrap 路由 514→529、`LoginRateLimiter` 863-866/863-937→886-889/886-1016（`BucketMap` 893、`prune_if_due` 989、`prune_expired` 1005、`RATE_LIMIT_USERNAME_CHARS` 118、`bounded_username_key` 1031）、resolve_session touch 1078-1080→1159-1161（`resolve_session` 1115）、CSRF 1096-1112→1177-1200、session_cookie 1147-1159→1228-1245（字面量 1237）、is_https 1200-1213→1281-1294、DUMMY_SALT/DUMMY_HASH 1226/1233→1307/1314、哑验证 1254-1265→1335-1346、B1 1267-1276→1355-1357（登录入口 1386-1397、bootstrap 1625-1631、改密 1780-1785）、B2 1321-1335→1402-1416、M1 未知用户名调用 1357→1438、B4 1365-1400→1446-1461/1469-1481、bootstrap_complete 1533→1614、B3 1749-1776→1830-1853、禁用撤销 2066-2071→2145-2152、角色撤销 2128-2131→2207-2212、record_login_failure/success 2208-2257→2289-2338、管理事件 2261-2284→2342-2365、best-effort 2289-2292→2373-2405（注释 2370-2371）、限速测试 2688→2769（T-D 新增 4 个有界性测试 2848/2901/2945/2973）、防御性 unwrap_or 1002/1158/1449/1808→1083/1239/1530/1889** |
| `web/src/lib.rs:110`（ARTIFACT_CHUNK_BODY_LIMIT）、`:1183`（DefaultBodyLimit）、`:1537`（N5 编译期 const assert，E3c）、`:1688`（AUDIT_QUERY_MAX_LIMIT）、`:1699`（credential_inventory）、`:1779`（begin_endpoint_trust）、`:4610`（资源诊断投影含 decode_failures）、`:10055`（password_verifications 计数）、`:11474, :11538`（两分支计数断言）、`:12472`（role_masks 测试）、`:14412, :14515`（中心站点作用域）、`:6884`（secret-free 清单测试）、`:3552`（InitialRefreshCoordination 错误映射） | 打开核实。**W7-M-2 重核（2026-08-14）**：wave-six（fcf7257/7c6ac9d）与 wave-seven（A4 的 ParseAuditError 拆分 + audit handler 重排、A1 的 web 侧无改动）把本行全部锚点再次推偏——108→110（ARTIFACT_CHUNK_BODY_LIMIT_BYTES）、911→1183（DefaultBodyLimit）、1223→1537（N5 const assert）、1368→1688（AUDIT_QUERY_MAX_LIMIT，常量定义行）、1374→1699（credential_inventory）、1454→1779（begin_endpoint_trust）、InitialRefreshCoordination 3042-3050→3552、诊断投影 3970-4001→4610、secret-free 6238→6884、password_verifications 9279→10055、未知用户名计数断言 10725→11474、口令错误断言 10789→11538、role_masks 11385→12472、中心站点作用域 12260/12304→14412/14515；本行已按当前 master 逐符号 grep 重锚 |
| `web/tests/write_path.rs:784, 816, 918`（secret-free 测试） | 打开核实（旧 783/815/917 各 +1） |
| `web/tests/diagnostics_path.rs`（7 个测试：`:838, :893, :935, :998, :1076, :1143, :1175`，E1 新增 `refresh_capture_flows_into_the_diagnostics_response` `:998`） | 打开核实（旧 6 个测试 651/706/748/811/878/910 漂移） |
| `ui/src/lib.rs:2902`（ConsoleView::ALL 17 视图）、`:5170`（CommandFamilyView::ALL 9 家族）、`:6289, 6361, 6437`（telemetry 表单拒绝）、`:11292`（later-milestone 提示，文案入目录 `i18n.rs:1654` `hint_telemetry_later`）、`:15492`（DiagnosticsReady 只读区块，含 decode_failures 投影） | 打开核实（H5 后行号重核：H1 期旧值已漂移；文案串已入目录、aria-label 全部走目录键）。**F3 重核（T-H c4dd335 浏览器模块重构）：`ConsoleView::ALL` 2902 一致、`CommandFamilyView::ALL` 5170→5171、表单选择器 FamilyRequired 6289/6361→6289-6291、Telemetry 表单拒绝 6437→6438、later-milestone 提示 11292→11295-11302（`L().hint_telemetry_later` 渲染 11302）、DiagnosticsReady 15492→15491、`aria_loading` 11952→11951、fragment 区段 11600-11666→11602-11667（`stored_lang_code` 11607、`persist_language` 11617、`apply_language` 11629、`LanguageSelector` 11640-11658、`start()` 11661-11664）、zh 断言 `"总览"` 22748→22762** |
| `ui/src/i18n.rs`（H5 后：`strings_catalog!` 宏 `:43-160`、827 键目录体 `:163-1858`、`Lang`/`Lang::strings` `:1860-1881`、`lang_code`/`parse_lang` `:1884-1899`、`thread_local!`/`set_lang`/`current_lang`/`L()` `:1909-1944`、`format_catalog` `:1955-1977`、11 测试 `:1980-2172`）、`ui/src/lib.rs:45`（`mod i18n`）、`:11600-11666`（fragment 持久化 + `LanguageSelector` + `start()`）、`web/assets/rutilus_ui.js` + `rutilus_ui_bg.wasm`（H2/0f91c17 再生成） | 打开核实（H5 后行号重核：H1 期旧值已过时；F2 复核修正残留漂移记录见左列前值；测试断言现按 zh 值断言；旧 MINOR「`aria-label="Loading"` 未抽取」已在 H5 解决——aria-label 全部走目录键；设计文档全文无「本地化/i18n」条目——i18n.rs 头注释 §5.1 引用不可核验的 MINOR 保持）。**F3 重核（T-H c4dd335 +103 行插入 1901-1936 与 2187-2259 区段）：宏 `:43-160`、目录体 `:163-1858`、`Lang`/`Lang::strings` `:1860-1881`、`lang_code`/`parse_lang` `:1884-1899` 一致；`LANG_FRAGMENT_PREFIX` 1905、`stored_lang_code_from`/`lang_fragment_value` 1915-1936（新）、`thread_local!` 1938-1942、`set_lang` 1950、`current_lang` 1955、`L()` 1968-1973、`format_catalog` 1984-2006（旧 1955-1977 +29）、tests 2009-2185（11 个既有测试，旧 1980-2172）+ 新 fragment 纯函数测试 2192-2259（`fragment_reading_extracts_only_the_lang_value` 2192 / `fragment_persistence_writes_the_lang_value` 2218 / `fragment_persistence_round_trips_both_languages` 2229 / `fragment_lang_selection_falls_back_to_en` 2248）；`FORMAT_KEYS` 93、槽位测试 2055/2137（旧 2000-2030/2046-2073/2108-2139 漂移）** |
| `center-protocol/src/lib.rs:50, 59, 62, 67, 75, 383`、`negotiation.rs:162, 269`、`framing.rs:18-31, 176-199, 219-238` | 打开核实，行号一致 |
| `Cargo.toml:14`（workspace 版本 0.9.0）、`:35`（16 个 nv-redfish feature）、`:110-116`（§5.4 发布配置一致）、`infra-redfish/Cargo.toml:14`、`Cargo.lock:2486-2490`、`deny.toml:21-24, 29-34` | 打开核实，行号一致 |
| `rust-toolchain.toml` 存在、Cargo.lock 已提交 | 打开核实 |
| `ci.yml`：`:3-21`（门禁清单注释，含 secret-leak gate `:15-17`）、`:73-84`（RUTILUS_GIT_COMMIT job 级注入，E3a）、`:85-101`（三平台矩阵）、`:159-161`（全 workspace Test）、`:169-185`（跨平台 E2E 注释+步骤，mock_center_client 不纳入注释 `:176-179`）、`:266-274`（cargo audit）、`:307-309`（Secret leak gate 独立步骤，E3b/G1）、`:406-521`（wasm32 UI 构建 + 归一化 + 产物 diff）、`:538-543`（musl x86_64）、`:550-554`（aarch64 zigbuild）、`:558-564`（Windows ARM64 不入 CI 注释）、`:565-598`（Universal 2 + lipo verify_arch）、`:619-621`（Migration 门禁）、`:642-644`（Capability Ledger）、`:660-662`（Release Baseline） | 打开核实。**W7-M-2 重核（2026-08-14，wave-six 的 fcf7257 对 ci.yml +149/-62——ran-断言注释块 + wasm python 变换——使本行全部锚点漂移 40~280 行，此前的「本行已按新行号引用」随 d77d54e 时代失效；本轮逐条 grep 重锚为当前值：RUTILUS_GIT_COMMIT 53-64→73-84、三平台矩阵 65-81→85-101、全 workspace Test 121-123→159-161、跨平台 E2E 130-147→169-185、cargo audit 197-205→266-274、Secret leak gate 225-227→307-309、wasm32 diff 234-244→406-521、musl 254-259→538-543、zigbuild 266-270→550-554、ARM64 注释 272-279→558-564、Universal 2 289-304→565-598、Migration 306-310→619-621、Ledger 312-317→642-644、Baseline 319-330→660-662；门禁清单注释 3-24→3-21。旧 ci.yml 引用的统一换算已在本轮完成——milestone-status §四/§六/§7.1/§7.2-A、operations-manual §十、user-manual §1.1 的旧行号引用均已逐处重核改写，见各文档修订） |
| E1 触面（合并后复核）：`redfish_gateway.rs:338, 1115, 8720, 8831, 8904, 8931, 8977`（捕获点）、`resource_snapshot_repository.rs:81-147`（同代事务）、`endpoint_refresh.rs:350-355`（生产链路）、`endpoint_inventory.rs:47, 94, 105, 123`、`resource_diagnostics.rs:36, 249, 430`、`entity/src/lib.rs:28`、`entity/src/resource_decode_failure.rs:13`、`migration/src/m20260812_000001_resource_decode_failures.rs`、`migration/src/m20260812_000002_resource_feature_lists.rs`、`migration/tests/resource_feature_lists.rs:248`、`persistence/src/backup_snapshot.rs:624-627`（backup_applied 24 / supported 23） | 打开核实，按合并后行号引用（entity 文件名经 `entity/src/` 目录清点修正为单数 `resource_decode_failure.rs`） |
| E3b 触面：`security/tests/secret_leak_gate.rs`（R1/R2/R3 `:21-42`、`ALLOWED_CONSTANT_HITS` `:325-333`、8 测试 `:1054-1306`、`test-support` 目录级豁免 `:55-59, 1000-1002`；深度审查批次 e8424df 补 `strings_catalog!` 宏体豁免 `:534, 815-822, 1195`） | 打开核实；本轮（F2 复核）修正残留漂移：`ALLOWED_CONSTANT_HITS` 318-331→325-333、7 测试 `:974-1130`→8 测试 `:1054-1306`（e8424df 新增 `strings_catalog_macro_bodies_are_copy_construction_not_secret_assignments` `:1195`） |
| `stress_capacity.rs:47-52, 338, 587, 834`（3 测试，锚点取 `#[tokio::test]` 属性行——旧 336/585/832 为注释行，登记时即错，R6-3 修正）；`center_sync.rs:2853, 3478, 3528, 3693, 4328, 4448, 4615, 4838, 4968`（风暴/幂等/重发） | 打开核实（旧 582/829/3477/3527/3692/4327/4447/4614/4837/4967 漂移 +1~3，已按实际值引用） |
| `scripts/`（sign-windows.ps1 / sign-macos.sh / sign-linux.sh / checksums.sh / checksums.ps1，commit 34503ea）、ci.yml `release-artifacts` job（`ci.yml:332-611`：触发 `:28-40`、`needs: ci` `:367`、gated 签名 `:340-343, 468-546`、base64 物化 `:468-478, 493-502, 526-533`、thumbprint-only `:480-488`、SBOM `:571-587`、SHA-256 `:592-594`、上传 `:596-611`；`permissions: contents: read` `:42-43`；musl-tools `:423`；env `&&`/`||` `:486, 516, 544`；H4 audit 注释 BLOCKER 1/2、MINOR 1/3/4 `:353, 372, 422, 552, 567`） | 打开核实（H4 新引用） |
| 深度审查批次触面（打开核实）：`web/src/auth.rs:1267-1276`（B1 密码策略）、`:1305-1315, 1321-1335`（B1/B2 登录入口与 429 拒绝）、`:1365-1400`（B4 disabled/credential-missing 哑验证）、`:1749-1776`（B3 撤销信号）；`redfish_gateway.rs:598-611, 12653-12690, 14002-14062, 25432, 27314-27420`（ETag/412）；`application/src/batch_refresh.rs:87-109, 303-316`（端点读门）；`application/src/operation_executor.rs:1685-1699`（恢复判定）；`migration/src/m20260805_000005_operations.rs:131-138`（down 先子后父）；`ui/src/i18n.rs:1955-1977, 2000-2030, 2046-2073, 2108-2139`（槽位硬化）；`app/src/backup.rs:776-786`（schema 断言派生）；`security/tests/secret_leak_gate.rs:55-59, 1000-1002`（`test-support` 目录豁免，E3b 原始提交 eefde7e）+ `:534, 815-822, 1195`（`strings_catalog!` 宏体豁免，commit e8424df）；`entity/src/` 全目录清点（文件名全部单数：`endpoint_capability.rs`、`resource_decode_failure.rs` 等） | 打开核实；F2 复核修正残留（记录见左列前值）。**F3 重核（迭代七漂移）：auth.rs B1 1267-1276→1355-1357、B1/B2 登录入口 1305-1335→1386-1416、B4 1365-1400→1446-1481、B3 1749-1776→1830-1853（详见 auth.rs 行）；batch_refresh.rs 端点读门 87-109→87-110（`ENDPOINT_READ_GATES` 87、`endpoint_read_gate` 102-110）、refresh_one 303-316→287-335（两处 Coordination 获取失败 296-320，变体 394-396）；i18n.rs 槽位硬化 1955-1977→1984-2006（槽位测试见 i18n.rs 行）；backup.rs schema 断言派生 776-786→1068-1072；redfish_gateway.rs/operation_executor.rs/migration/secret_leak_gate.rs/entity 均未受迭代七触达，行号一致** |
| 迭代七新增触面（F3 本轮打开核实）：`application/src/endpoint_enrollment.rs`（T-B +214/-8）：`enroll` 流程 `:116-208`、读门获取 `:168-179`、`refresh.execute` `:190`、`InitialRefreshCoordination` 变体 `:292-297`、`EndpointReadGateError` `:331+`、对抗测试 `initial_refresh_and_concurrent_batch_refresh_of_the_same_endpoint_never_overlap` `:643`；`application/src/lib.rs:85-86`（`EndpointReadGateError` 导出）；`application/tests/refresh_decode_failures.rs`（T-G 新文件，4 测试，头注释 `:3-22`）；`test-support/src/lib.rs`（T-A 头文档 +3）：`:19, 46` 区段保持（mock-bmc 位置参数说明入头文档）；`test-support/src/bin/mock-bmc.rs`（T-A 重写 +54/-19，位置参数解析）；`test-support/tests/gateway_mock_bmc.rs`（T-I +479/-2）：头注释 `:3-17`、AMI/HPE 测试 `:1793, 1861, 2003, 2070, 2202`、共 28 测试；`app/src/center_acceptor.rs`（T-F）：`is_raced_bind` `:964-975`、`bind_acceptor_with_options` `:978-993`、测试 `the_bind_retries_when_the_probed_port_was_grabbed` `:1005`；`app/src/center_runtime.rs`：`is_raced_bind` `:901-904`、`bind_acceptor` `:912-927`；`app/src/center_client.rs`：`is_raced_bind` `:629-632`、`bind_acceptor` `:641-654`、`connect_with_retry_stops_on_the_stop_signal` `:886`；`app/src/site_runtime.rs`：`is_raced_site_bind` `:1507-1513`、`is_raced_center_bind` `:1517-1523`、`bind_site` `:1529-1544`、`a_not_bound_refusal_from_the_center_converges_the_local_binding`（第 5 处内联修复）`:2048-2079`；`app/src/site_runtime.rs:210-213/499-527/604-606/635`（既有引用，T-F 后重核不变） | 打开核实（本轮新增）；既有旧行号（`endpoint_enrollment.rs:156-166`、`batch_refresh.rs:87-109/303-316` 等）已按当前值修正，全文不再引用旧值 |
