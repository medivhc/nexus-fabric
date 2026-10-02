# Contract Amendment B1 — Disposed phase 拒绝追加事件

- date: 2026-10-03
- module: `nexus-session` (`crates/nexus-session/src/lib.rs`)
- task_type: bugfix
- 决策：D5（bug 修复轨道 T2，2026-10-03）

## 背景

`transition_phase` 允许 `Allocating → Disposed`（合法迁移），此时 outcome 仍为 `None`。
但 `request_cancellation` / `record_connectivity_established` / `record_connectivity_failed`
只以 `outcome.is_some()` 为闸，于是 `{phase: Disposed, outcome: Unfinished}` 的会话仍可被
追加 `CancellationRequested` / `Connectivity*` 事件，违反"Disposed 后不可再变"
（AGENTS.md §14：资源物理生命周期最终进入 `Disposed`）。

## 行为变更（仅以下三点）

1. `SessionOwner::request_cancellation`、`record_connectivity_established`、
   `record_connectivity_failed` 新增门控：`phase == Disposed → Err(SessionError::AlreadyTerminated)`。
   - 门控顺序：先 `outcome.is_some()`（保持原有携带真实 outcome 的错误信息），再 `phase == Disposed`。
   - 错误变体：复用 `AlreadyTerminated`（D5 决定，不新增变体，保持 public API 最小）。
     `{phase: Disposed, outcome: Unfinished}` 时其 `outcome` 字段填 `TerminalOutcome::Unfinished`；
     语义依据：Disposed 是终点 lifecycle phase，"terminated" 指生命周期终结，不只指 outcome 已提交。
2. `commit_outcome` 不变（超出本次 bug 范围；commit-once 不变量只要求恰一次提交，
   未要求提交必须早于 Disposed）。
3. `reconcile_session_records` 连带：`{phase: Disposed, outcome: Unfinished}` 的记录
   不再被判为孤儿、不再被覆盖重写为 Failed；reconcile 对一切 `phase == Disposed` 的记录
   直接跳过（cleanup 已完成，无事可做）。修复后的 Owner API 已无法产生该状态，
   该路径不可达，由单测锁定。

## 不变量

- Disposed 之后事件历史不可再追加（`events()` 长度冻结）。
- 已有行为不变：`outcome.is_some()` 时的 `AlreadyTerminated`（携带真实 outcome）优先触发。

## Red Evidence

`.evidence/red-2026-10-03-session-p0/red.log`（新测试在旧实现上 FAIL）：
- `disposed_phase_rejects_event_recording`
- `reconcile_skips_disposed_unfinished_record_without_overwrite`
