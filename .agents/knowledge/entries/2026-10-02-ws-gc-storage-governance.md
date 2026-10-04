---
id: 2026-10-02-ws-gc-storage-governance
date: 2026-10-02
module: nexus-workspace
category: architecture-decision
task_type: feature
---

# Workspace 存储治理（v9 §20）：两阶段 GC + Shallow/Sparse + Quota + 后台调度

## 背景

`nexus-workspace` 已有 Commit DAG/HeadSet/合并/Journal，但缺 v9 §20 的存储治理。
`nexus-storage` 已有 `ReachabilityGc` trait，但只有浅层的 mark/sweep（无传递闭包、
无 tombstone），且 `ContentStore` 无枚举/删除原语。

## 方案

### 两阶段 GC（`src/gc.rs`）

`plan_gc`（纯规划：可达闭包）→ `apply_tombstones`（Tombstone/Deletion Intent
持久化）→ `sweep`（保留期后物理删除）。`sweep` 前重验可达性：tombstone 期间
复活的对象撤销 tombstone，不删除。

关键细节：

- **每次 `persist_state` 都会产生新的 state 对象**，上一个 state_root 随即成为
  "被取代的旧 state"候选。这是正确的生命周期，不是 bug——测试断言必须考虑
  这一点（第二轮 plan 只应含 `SupersededState` 原因的候选）。
- `delete_object` 是 `ReachabilityGc` 的 GC 专用原语，`ContentStore` 本身只读/写
  （删除是 GC 特权，不是存储基本操作）。
- DurableState 格式 v2（tombstone/retain/hold/shallow 行），`from_bytes`
  向前兼容 v1（header 首 token 相同）。

### 保留期默认值

`DEFAULT_RETENTION_SECS` = 14 天（v9 §20 移动端默认值）。桌面/服务端可配更长。

### D1=A 的落地

GC 永不在 commit 热路径上：`commit_changes`/`journal_pending` 只做 pin/hold
标记；实际回收由 `GcScheduler` 后台线程（soft 配额压力触发）或手动 `run_gc`
执行。调度器是 §15 Structured Concurrency 形状：Owner + AtomicBool 取消 +
join 回收，无 fire-and-forget。

### Shallow/Sparse 的诚实边界

- `read_at_commit` 返回三态 `ReadOutcome`：shallow/sparse 下"本地没有"是预期
  状态（`NotHeldLocally`），不是损坏——调用方据此 `deepen`。
- `shallow_clone`/`deepen` 做内容寻址校验：fetch 回来的字节必须对上请求 id，
  否则 `CorruptState`（防传输损坏，不静默接受）。
- `ObjectFetcher` 只是 trait 形状；真正的远端传输由 Composition Root 适配
  （W2 的 Resource Delivery Request → Planner 是 natural 的下一步接线）。

## 教训

- E4 断言的精确计数必须手算验证（如 reachable=7 含 pin），不能拍脑袋；
  先跑一遍、人工确认数字正确后再冻结。
- 测试里"复活"语义的验证：pin → sweep → resurrected 计数 + tombstone 撤销，
  再 unpin → 重新成为候选——三段式才算完整。
- 给 `InMemoryContentStore` 加 `#[cfg(test)]` 的 `put_at` 已存在，保留期语义
  用它做确定性测试，不要在 E4 里玩系统时钟。
