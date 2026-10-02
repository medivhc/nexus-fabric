# Contract Amendment B2 — reconcile 重放"终态但 phase≠Disposed"的 cleanup

- date: 2026-10-03
- module: `nexus-session` (`crates/nexus-session/src/lib.rs`)
- task_type: bugfix
- 决策：D5（bug 修复轨道 T2，2026-10-03）

## 背景

`reconcile_session_records` 原逻辑 `if terminal || process_alive { continue; }` 不看 phase。
进程若在 `commit_outcome` 之后、`transition_phase(Disposed)` 之前崩溃，持久记录停留在
`{phase: Active/Draining, outcome: terminal}`，会被此后每一次 reconcile 跳过，
cleanup 迁移永不重放（"打洞成功≠最优"之外另一处"成功≠收尾"）。

## 行为变更（仅以下三点）

1. reconcile 改为 phase 感知（按顺序判定）：
   - `phase == Disposed` → 跳过（cleanup 已完成；含 B1 连带的 `{Disposed, Unfinished}` 不可达路径）。
   - `terminal && phase != Disposed` → **重放 cleanup 迁移到 Disposed 并回写记录**，
     outcome 原样保留；**不重新 commit outcome**（outcome 已终态，Owner 唯一写入者原则不变）；
     不计入 `orphans_classified`（不是孤儿）。
   - `!terminal && process_alive` → 跳过（不变）。
   - `!terminal && !process_alive && phase != Disposed` → 孤儿路径（不变：
     恰一次提交 Failed → 清理到 Disposed → 回写）。
2. cleanup 重放路径（按迁移表补足，经 `SessionOwner::transition_phase` 权威校验）：
   `Allocating → Disposed`；`Active → Draining → Disposed`；`Draining → Disposed`。
   重建 Owner 用私有的 `SessionOwner::from_record`（恢复 phase 与已提交 outcome，
   不产生 `Started` 事件；public API 不变）。
3. 幂等性：回写后记录为 `{phase: Disposed, outcome: terminal}`，再次 reconcile 命中
   `phase == Disposed` 跳过分支，不重复任何动作；reconcile 中途崩溃时，已回写的下次跳过、
   未处理的下次继续（与既有 durable-marker 原子替换论证一致）。

## 不变量

- outcome 一旦终态，reconcile 永不改写它（只动 phase）。
- `SessionReconcileReport` 字段不变（`nexusd` 对其做全字段解构，不新增可观测字段）。

## Red Evidence

`.evidence/red-2026-10-03-session-p0/red.log`（新测试在旧实现上 FAIL）：
- `reconcile_replays_cleanup_for_terminal_not_disposed`
- `reconcile_terminal_cleanup_is_idempotent`（第二条在旧实现上碰巧通过，锁定新行为）
