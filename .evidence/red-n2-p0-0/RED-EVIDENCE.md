# N2 P0-0 契约冻结 Red Evidence（2026-10-03）

轨道：`n2/p0-0-contract-freeze`（worktree `~/workspace/track-n2-p0-0`，基线 `be361f9`）。

Contract-First §5 要求：新契约场景必须在旧实现上跑出明确的 FAIL / BLOCKED，
证明"场景在实现前确实失败"，然后冻结期望。

运行器：`run_red.py`（本目录），判定语义忠实复刻
`engineering/nexus-harness/src/scenario.rs`（equals / one_of / non_empty；
字段路径先扁平键精确匹配、再按 `.` 下钻；stdout 非 JSON 即 FAIL）。

## A. n2-* 新契约场景（11 个，P0-1..P0-4 实现，当前全 Red）

| 场景 id | 命令 | Red 状态 | 原因 |
|---|---|---|---|
| product.n2-use-loop | `nexus use dev-svc --json` | FAIL | 无 `use` 子命令（unknown command，exit 2，无 JSON） |
| product.n2-plan-preview | `nexus plan dev-svc --json` | FAIL | 只有 `plan explain`，`plan <resource>` 未实现 |
| product.n2-resource-list | `nexus resource list --json` | FAIL | 无 `resource` 子命令 |
| product.n2-resource-show | `nexus resource show dev-svc --json` | FAIL | 无 `resource` 子命令 |
| product.n2-resource-publish | `nexus resource publish … --json` | FAIL | 无 `resource` 子命令 |
| product.n2-resource-revoke | `nexus resource revoke dev-svc --json` | FAIL | 无 `resource` 子命令 |
| product.n2-session-list | `nexus session list --json` | FAIL | 无 `session list` 子命令 |
| product.n2-session-watch | `nexus session watch sess-n2-e4-1 --json` | FAIL | 走 daemon LocalAPI，无 daemon → 结构化不可达 FAIL（verdict=FAIL ≠ PASS） |
| product.n2-session-close | `nexus session close sess-n2-e4-2 --json` | FAIL | 无 `session close` 子命令 |
| product.n2-grant-deny-audit | `nexus use restricted-svc --json` | FAIL | 无 `use` 入口、无 grant 表 |
| product.n2-provider-offline | `nexus use svc-on-b --json`（E5） | FAIL | 无 `use` 入口 |

原始输出：`red-n2-scenarios.json`（本目录）。

## B. `nexus run` 诚实化 requirement-change（Red → Green）

新期望（`daemon_run_remote_service_flow.toml` 2026-10-03 版、
`daemon_run_with_command.toml`）在**旧实现**（stash 前）上：

| 场景 id | 旧代码 verdict | 原因 |
|---|---|---|
| product.daemon-run-remote-service-flow | FAIL | 旧 session_id 为随机 mock（`sess-18daedeb7e2166ae`），≠ 真实 `sess-remote-service-1`；无 plan_id 字段 |
| product.daemon-run-with-command | FAIL | 旧代码把 `--` 静默忽略，按普通 run 假执行（verdict=PASS） |
| product.daemon-run-workspace-flow | PASS | 行为未变（`run workspace` → UNSUPPORTED） |
| product.cli-run-command | PASS | RC1 期望（非空 session_id 等）在旧代码上仍成立 |

原始输出：`red-run-honesty-oldcode.json`（本目录）。

同一组场景在**新实现**（D4 诚实化后）上：4/4 PASS。
原始输出：`green-run-honesty-newcode.json`（本目录）。

## 结论

- 11 个 n2-* 场景全部 Red（FAIL），契约已冻结，等待 P0-1..P0-4 实现使其变绿。
  实现阶段禁止修改这些期望（Protected）；若契约本身有误，走 requirement-change。
- `nexus run` 诚实化完成 Red → Green 闭环；旧证据（mock session_id 时代）已 STALE。
