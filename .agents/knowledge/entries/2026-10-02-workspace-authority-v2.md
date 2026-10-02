---
id: ws-authority-v2
date: 2026-10-02
module: nexus-workspace
category: architecture-decision
task_type: requirement-change
---

# Workspace 权威模型 v2：内容哈希 CommitId + Conflict 持久化 + Head 交换

## 背景

v9 §17 要求"每个 WorkspaceCommit 使用内容哈希作为 CommitId"，§18 要求冲突为
持久化 Conflict Object。但实现用 `C{seq}` 序列号（`next_commit_id`），冲突时直接
`Err(MergeConflict)` 未持久化，无 Head 交换协议。这是 requirement-change（breaking），
不是 bugfix。

## 决策

### 1. CommitId = hex16(fnv1a_64(canonical_bytes))

```text
"nexus-commit-v1\n"
+ "parents:" + join(sorted(parent_ids), ",") + "\n"
+ "root:" + root_manifest_id + "\n"
+ "author:" + author + "\n"
+ "timestamp:" + unix_secs + "\n"
```

- 与 CAS 的 `object_id_of` 同一哈希函数（复用，不引入新依赖）。
- `timestamp` 是逻辑元数据（v9 §17 要求 Commit 含 Logical Metadata），保证每次
  `commit()` 调用产生不同提交；同一提交对象在所有节点算出同一 ID（跨端对账基础）。
- `journal_pending` 时一次算出，`commit_pending`/`reconcile` 复用，不重算。
- `open()` 逐提交校验 `id == hash(content)`（防篡改）。

### 2. 不做自动迁移

`DurableState` header `v1` → `v2`；`open()` 拒绝 v1 并报明确错误。
Workspace 功能尚未发布，无生产数据，静默迁移的复杂度不值得。

### 3. ConflictObject：CAS 存不可变记录，解决状态存索引

CAS 是不可变的，所以冲突字节（base/local/remote/paths）进 CAS，
`ConflictState::{Unresolved, Resolved{merge_commit}}` 只存于工作区索引
（进 DurableState v2，重启可恢复）。`merge_heads` 冲突时返回
`Ok(MergeReport{conflict: Some(id)})` 而非 `Err`，Head 集不变；
`resolve_conflict` 生成双 parent Merge Commit 后标记 Resolved。

教训：第一版把 state 写进 CAS 字节，导致 from_bytes 重算 id 时状态对不上；
拆分"不可变记录 / 可变状态"是 CAS 上建模的通用模式。

### 4. Head 交换协议（文本帧，零新依赖）

```text
HEADS:<ids> -> HEADS-ACK:<ids>
WANT-COMMITS:<ids> -> COMMITS:<n> + n×COMMIT 帧
WANT-OBJECTS:<ids> -> OBJECTS:<n> + n×OBJECT-DATA:<id>:<hex>
SYNC-DONE
```

- 收到 COMMIT 逐个校验 `id == hash(content)`，不通过拒绝。
- manifest 随提交拉取（合并需要）；blob 按需（读时再取，与 §20 on-demand 一致）。
- `sync_with_remote`（主动）+ `serve_sync`（被动），`WorkspaceTransport` 零新增依赖边。

### 5. 序列化格式教训

`split_whitespace()` 会吞掉空字段——`commit <id> <root>  author:...`（空 parents）
解析时 parents 会吃掉 `author:` token。改成所有字段显式 `key:` 前缀。
文本协议里永远不要依赖位置+可空字段。

## 影响面

- `Workspace::init/open` 签名加 `author: AuthorId`（10 处调用方已更新）。
- 冻结场景变更（requirement-change 显式列出）：`workspace_offline_merge.toml`
  （去 C0）、`daemon_run_workspace_flow.toml`/`remote_workspace_commit_flow.toml`
  （parent 改 non_empty）、`observability_workspace_conflicts.toml`（冲突不再 Err）。
- `remote_workspace_commit_flow` 的 E4 驱动加 `HEAD?` 查询（parent 必须为真实 ID）。
- 新增场景 `workspace_authority_v2.toml`（12 期望，E4 全绿）。
