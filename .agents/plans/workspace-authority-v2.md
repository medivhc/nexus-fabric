# Requirement Change: Workspace 权威模型 v2（内容哈希 CommitId + Conflict 持久化 + Head 交换）

- 类型：`requirement-change`
- 依据：v9 §17（CommitId 内容哈希）、§18（Conflict Object 持久化）、repo `AGENTS.md` §16（禁用标量 Generation）
- 现状（2026-10-02，`origin/master` @ `cdeb957`）：
  - `CommitId(pub String)` 由 `next_commit_id()` 生成 `C{seq}` 序列号——**不是内容哈希**，违反 v9 §17。
  - 冲突时 `merge_heads` 直接返回 `Err(MergeConflict)`，冲突未持久化——违反 v9 §18（Conflict 是 Workspace 状态的一部分）。
  - 无 Head Set 交换协议：`merge_heads` 假设双端提交已在本地；`RemoteWorkspaceSession` 只有单提交推送。
  - 无标量 Generation（已查，无漏网之鱼）。

## 变更内容

### 1. CommitId → 内容哈希（breaking）

```
commit_id = hex16(fnv1a_64(canonical_bytes))
canonical_bytes =
  "nexus-commit-v1\n"
  + "parents:" + join(sorted(parent_ids), ",") + "\n"
  + "root:" + root_manifest_id.0 + "\n"
  + "author:" + author.0 + "\n"
  + "timestamp:" + created_at_unix + "\n"
```

- 哈希函数与 CAS 的 `object_id_of` 一致（FNV-1a 64），系统内单一哈希语义。
- `WorkspaceCommit` 新增 `author: AuthorId(pub String)`（v9 §17 要求的 Author/NodeId；本地不透明字符串，不引入新跨 crate 身份类型）。
- `timestamp` 为逻辑元数据（秒级 unix），保证每次 `commit()` 调用产生不同提交；同一提交对象在所有节点算出同一 ID（跨端对账基础）。
- `journal_pending` 时一次算出 ID 并写入 `JournalEntry`（`commit_pending` 复用，不重算）。
- 删除 `next_seq`（序列权威的残留）。
- 持久状态 `DurableState::HEADER` 由 `nexus-workspace-state v1` → `v2`；`open()` 拒绝 v1 并报 `CorruptState{reason: "unsupported state version v1, expected v2"}`。
  - **不做自动迁移**：Workspace 功能尚未发布，无生产数据；旧测试/场景按新语义更新。

### 2. Conflict Object 持久化（v9 §18）

- 新类型：
  ```rust
  pub struct ConflictObject {
      pub id: String,              // hex16(fnv1a_64("nexus-conflict-v1\n" + base + local + remote + sorted paths))
      pub base: CommitId,
      pub local: CommitId,
      pub remote: CommitId,
      pub paths: Vec<String>,      // 冲突路径（排序）
      pub state: ConflictState,    // Unresolved | Resolved { merge_commit: CommitId }
  }
  ```
- 冲突字节进 CAS（`store.put`）；`Workspace.conflicts: HashMap<String, ConflictObject>` 进 `DurableState v2`（重启可恢复）。
- `merge_heads` 冲突时不再 `Err`：持久化 ConflictObject，返回
  `MergeReport { disposition: Diverged, conflict: Some(id), merge_commit: None, .. }`，Head 集不变。
- 新 API：`resolve_conflict(conflict_id, &[ (path, ConflictResolution) ])` →
  生成 Merge Commit（内容哈希 ID，双 parent），标记 `Resolved`，Heads 收敛为 1。
  - `ConflictResolution::{ TakeLocal, TakeRemote, Custom(Vec<u8>) }`
- `WorkspaceError::MergeConflict` 变体保留（API 兼容），但 `merge_heads` 不再用它返回冲突；
  用于 `resolve_conflict` 的非法调用（未知 conflict_id、已解决）。

### 3. Head Set 交换协议（补齐）

基于已冻结的 `WorkspaceTransport` 帧通道（不新增依赖边）：

```text
A -> B: HEADS:<json [commit_id]>
B -> A: HEADS-ACK:<json [commit_id]>
# 双端各自判定：AlreadyEqual / FastForward / Diverged（复用 merge_heads 判定逻辑）
A -> B: WANT:<json [missing_commit_id]>      # A 缺的（BFS 自远端 head，排除本地已有）
B -> A: COMMIT:<json {commit}>                # 含 id/parents/root/author/timestamp
A -> B: OBJECT:<object_id>                    # manifest / blob 按需
B -> A: OBJECT-DATA:<id>:<base64>
# 双方各自 merge_heads 收敛
```

- 新 API：`exchange_heads(transport) -> HeadExchangeReport`、
  `sync_with_remote(transport) -> SyncReport`（交换 + 拉取 + 合并全流程）。
- 收到 COMMIT 时校验 `id == hash(content)`（防篡改/错乱，不校验则拒绝）。

### 4. 受影响的冻结场景（本 requirement-change 显式列出）

- `scenarios/product/workspace_offline_merge.toml`：`base_commit = "C0"` 等序列 ID 期望失效，
  改为内容哈希语义（由新 example 输出的真实 ID 断言，禁止硬编码）。
- 新增 `scenarios/product/workspace_authority_v2.toml`（E4）：
  双端同内容同 author → 同一 CommitId；异内容 → 不同 ID；
  离线分叉 → Head 交换 → three-way merge；
  同路径冲突 → ConflictObject 落盘（CAS 可查）→ resolve → Merge Commit（双 parent）；
  跨端对账 ID 一致。

## 迁移与兼容

- v1 持久状态：拒绝并报明确错误，不静默迁移（无生产数据）。
- `RemoteWorkspaceSession` 的 `OK:HEAD:<id>` 帧：ID 为不透明字符串，协议不变。

## Evidence 计划

- Red：新 scenario 在旧实现上 BLOCKED（新 API 不存在，example 编译失败）。
- 实现后：新 E4 PASS；`cargo test -p nexus-workspace` 全过；`verify --fast` 8/8。
- 真机 E4：xc-pc-linux（双端模拟走内存 transport；另做 kill -9 恢复抽查）。
