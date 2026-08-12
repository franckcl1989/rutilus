# Drill 实跑结果登记表

## 执行摘要（2026-08-12 首轮实跑）

- 日期/环境：2026-08-12，Windows 11 Pro 10.0.26200（ConPTY 要求满足：≥1809），PowerShell 5.1.26100.8972，debug 构建 commit f6ef715（target/debug/rutilus.exe 与 mock-bmc.exe 均为本轮构建，可用）。
- 结果：PASS 0 / FAIL 0 / **SKIP 6**（其中 5 个为环境原因——本执行上下文中 ConPTY 不可用，drill 的伪控制台驱动无法 spawn 任何子进程；1 个为共享组件非独立 drill）。
- 总耗时：约 55 分钟（其中 drill 1 尝试实跑挂起 >20 分钟后终止，其余时间用于根因诊断）。
- 根因证据：logs/diagnostic-conpty-probes-20260812.log（cmd.exe 对照 + rutilus 实测 + 全契约实现复测 + 普通管道对照），探针脚本保留在 tmp/conpty-probe*.ps1。
- 处置建议（供总指挥决策）：在**有真实交互控制台（如用户自己的 Windows Terminal/PowerShell 窗口）的会话**中复跑本套件验证 ConPTY 是否恢复；同时建议 drill 套件维护者评估 ConPTY 失败时的挂起防护（当前故障形态为硬挂起而非 FAIL，见 drill-backup-restore-cycle 行备注）。

## 复测小节（2026-08-12，挂起防护修复后）

- 原 6 SKIP 根因回顾：本执行上下文（Claude Code 工具进程 spawn）中 ConPTY 不可用——伪控制台子进程一律以 0xC0000142 启动失败、零输出；且原实现的故障形态是硬挂起而非 FAIL（Wait-ConPtyOutput 后置清理中的 ClosePseudoConsole 永久阻塞，首跑 >20 分钟无 FAIL 行）。
- 防护修复（仅改 scripts/drills/drill-lib.ps1）：(1) Start-ConPtyProcess 新增启动探测——子进程在探测窗口内退出且零输出即判定 ConPTY 启动失败，有界清理后抛错，使 drill 秒级 FAIL；(2) Wait-ConPtyOutput 超时后清理会话并记录诊断事实（进程存活/退出码/输出长度），返回可判定失败信号；(3) 清理路径全程有界——Ctrl-C 仅在子进程存活时发送、WaitExit 硬超时、Dispose 的 ClosePseudoConsole 与挂起句柄关闭交由看门狗线程限时 4s，永不永久阻塞。语法检查 Parser.ParseFile PARSE OK；文件保持纯 ASCII（PS 5.1 无 BOM 解析兼容）。
- 复测结果（同环境）：drill-backup-restore-cycle 实跑 3 次均快速 FAIL（每次 0.6s，退出码 1），FAIL 行含 exitCode=-1073741502（0xC0000142）与 outputLen=0 诊断事实；另直接构造死进程会话验证 Wait-ConPtyOutput 超时分支：3s 超时有界返回单值 $false 并完成清理（总 3.2s），Stop-ConPtySession -Force 清理 0s 返回——清理路径不再永久阻塞。环境根因未变，本环境复测只能验证防护路径；套件功能验证仍需在有真实交互控制台的会话中复跑。

本表在每次实跑后由执行者如实登记；未实跑前保持留空。

登记规则：

- 每次实跑（无论 PASS 还是 FAIL）追加一行，不覆盖、不删除历史登记；PASS 记录关键观察，FAIL 行必须记录失败观察与根因线索，供复跑与修复使用。
- 演练已知限制与实证结论（如 mock-bmc 的静态 Task 固件、Windows 文件共享语义）在对应 drill 行的"观察与备注"列如实记录，脚本中以 "see RESULTS.md" 引用的 caveat 均指向这里。

| Drill 名称 | 日期 | 环境 | 结果 PASS-FAIL | 观察与备注 | 对应设计条款 |
|---|---|---|---|---|---|
| drill-backup-restore-cycle | 2026-08-12 | Windows 11 Pro 10.0.26200 + PowerShell 5.1.26100 + debug 构建 commit f6ef715 | SKIP（环境：ConPTY 不可用） | 尝试实跑：`rutilus init --portable` 阶段挂起 >20 分钟（日志 logs/drill-backup-restore-cycle-20260812-210650.log 仅含 2 个 STEP、无 FAIL 行），手动终止。诊断（见 logs/diagnostic-conpty-probes-20260812.log）：drill-lib.ps1 的 ConPTY 驱动在本执行上下文 spawn 的所有子进程（含 cmd.exe 对照）均以 0xC0000142 STATUS_DLL_INIT_FAILED 启动失败、输出为零；即便完整实现 ConPTY 契约（SetHandleInformation + bInheritHandles=true，探针 conpty-probe4.ps1）亦然。普通管道 spawn 正常（cmd echo 输出 OK），产品 rutilus.exe 在非交互管道下正确报错退出 1（"local unlock requires an interactive terminal"）——非产品问题。附带发现：ConPTY 子进程启动失败时 drill 的 Wait-ConPtyOutput 不超时、Stop-ConPtySession 的 ClosePseudoConsole 阻塞清理——故障表现为硬挂起而非 FAIL。 | §20.1 backup / §20.2 restore |
| drill-sqlite-write-interruption | 2026-08-12 | 同上 | SKIP（环境：ConPTY 不可用） | 未实跑：与 drill 1 同一 ConPTY 依赖（init/run/doctor 全走伪控制台交互），ConPTY 不可用使该 drill 必然以相同方式挂起，不硬跑。根因证据同 drill-backup-restore-cycle 行。 | §19.3 SQLite 写入中断 |
| drill-bmc-restart-during-task | 2026-08-12 | 同上 | SKIP（环境：ConPTY 不可用） | 未实跑：同样依赖 ConPTY 驱动 init/run。mock-bmc 进程本身可正常 spawn（Start-Process 管道重定向路径不依赖 ConPTY），但 drill 的 CLI 交互阶段无法进行。根因证据同上。 | §19.3 / §13.6 |
| drill-large-file-interruption | 2026-08-12 | 同上 | SKIP（环境：ConPTY 不可用） | 未实跑：同样依赖 ConPTY 驱动 init/run。根因证据同上。 | §19.3 大文件上传中断 / §0.4.0 |
| drill-kill-mid-operation | 2026-08-12 | 同上 | SKIP（环境：ConPTY 不可用） | 未实跑：同样依赖 ConPTY 驱动 init/run。delay relay（drill-delay-proxy.ps1）为独立 PowerShell 进程 + TCP 代理，不依赖 ConPTY，本可工作；但 drill 整体无法推进。根因证据同上。 | §19.3 / §13.5 / §15.4 |
| drill-delay-proxy | 2026-08-12 | 同上 | SKIP（共享组件，非独立 drill） | 头注释明确其为共享中继组件（由 drill-lib.ps1 Start-DelayRelay 以独立进程启动，供 drill-kill-mid-operation 使用），非独立可运行 drill，按指令不单独实跑；其功能在 drill-kill-mid-operation 实跑时会覆盖验证（本次因 ConPTY 环境原因未覆盖到）。 | — |
| drill-backup-restore-cycle | 2026-08-12 | 同环境（挂起防护修复后的复测） | FAIL（预期性：ConPTY 启动失败被启动探测捕获，秒级 FAIL 而非挂起） | 复测：drill-lib.ps1 挂起防护修复后在本环境（ConPTY 不可用）实跑，`rutilus init --portable` 的 Start-ConPtyProcess 启动探测（5s 窗口）捕获子进程启动即死（exitCode=-1073741502 = 0xC0000142，outputLen=0），经有界清理后抛错走 FAIL 路径，总耗时 0.6s（修复前此阶段挂起 >20 分钟）；FAIL 行含退出码/输出长度诊断事实。3 次复跑均稳定 0.6s FAIL（logs/drill-backup-restore-cycle-20260812-213502.log 为最后一次）。 | §20.1 backup / §20.2 restore |
