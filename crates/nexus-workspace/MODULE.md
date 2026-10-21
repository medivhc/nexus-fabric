# nexus-workspace Module Contract

## Responsibility

实现 Workspace Commit DAG、Head Set、Namespace/Manifest、Merge/Conflict、WorkspaceGraph、Profile、WorkingSet、Prefetch 与 Projection 语义。

## Non-Responsibilities

不直接实现平台 FUSE/File Provider；不绕过 Core Planner 选择远端 Replica/Path。

## Inputs

- 仅接受公开类型、DTO、trait、事件或稳定协议对象。
- 输入必须可被结构化验证；不得依赖未声明的全局隐式状态。

## Outputs

- 结构化 Result / Event / DTO。
- 失败必须保留可诊断原因，不以日志文本代替错误类型。

## Failures

Merge/Commit/持久化路径必须返回结构化 `WorkspaceError`，不得 panic 或以自由文本代替错误类型：

- 未知提交（`UnknownCommit`）、内容对象缺失（`MissingObject`）、Manifest 损坏（`CorruptManifest`）；
- 持久状态对象无法解析或校验失败（`CorruptState`）、底层存储失败（`StoreFailure`）；
- 双端相对合并基修改同一路径且内容不同 → `MergeConflict::ConflictingPath`，要求显式冲突解决，且不得改变 Head 集；
- 两个提交之间不存在公共祖先 → `NoCommonAncestor`。

## Allowed Dependencies

- `nexus-domain`
- `nexus-session`
- `nexus-delivery`
- `nexus-storage`

## Forbidden Dependencies

- `engineering/` 下的 Harness/Plugin。
- 未在 `policies/architecture.toml` 声明的 Nexus 内部 crate。
- Portable 模块中的平台专有 Framework/API。
- 通过“便利”依赖绕过公开领域边界。

## Invariants

- 权威版本使用不可变 Commit DAG + Head Set。
- **CommitId 是内容哈希**（`hex16(fnv1a_64)`，与 CAS 的 `object_id_of` 同一哈希语义；
  输入：排序后的 Parent CommitIds + RootManifestId + Author/NodeId + 逻辑元数据）。
  标量序列号永不作为版本权威；`DurableState` header `v2`，拒绝 `v1`。
- 离线分叉不得丢弃本地提交。
- 冲突落为持久化 Conflict Object（进 CAS，含 Base/Local/Remote 与 Resolution State），
  是 Workspace 状态的一部分；解决后才产生 Merge Commit。
- Head 交换后收到的提交必须校验 `id == hash(content)`，不通过则拒绝。
- WorkspaceGraph/WorkingSet/Cache 不是权威内容。
- GC 只能删除不再被 protected roots 可达且过安全保留期的对象。

## Side Effects

- 仅允许 Responsibility 所需且在架构层中明确归属的副作用。
- 新增副作用前必须更新本契约和 Scenario/Policy（如影响外部行为）。

## Public API

- 默认最小 surface：`private -> pub(crate) -> pub`。
- Public API 变更必须保持结构化、可版本化并有调用方验证。

### 冻结契约（remote P0 扩展，scenarios/product/remote_workspace_commit_flow.toml）

- `pub trait WorkspaceTransport`：注入的帧通道，避免 workspace -> transport 依赖边（架构允许依赖仅 domain/session/delivery/storage）；由组合根以 `transport::FrameStream` 适配装配。
  - `pub fn send_frame(&mut self, payload: &[u8]) -> Result<(), WorkspaceError>`
  - `pub fn recv_frame(&mut self) -> Result<Vec<u8>, WorkspaceError>`
- `pub struct RemoteWorkspaceSession`：远程提交会话（PRODUCT §6）。
  - `pub fn commit(transport: Box<dyn WorkspaceTransport>, change_set: &[u8]) -> Result<Self, WorkspaceError>`
    在已认证帧通道上发送 ChangeSet 帧并接收结果帧；响应 `OK:HEAD:<commit_id>` 提取新 Head 后进入 Active，`REJECTED` 视为提供方拒绝。
  - `pub fn phase(&self) -> WorkspaceRemotePhase`
  - `pub fn head(&self) -> Option<&CommitId>`
- `pub enum WorkspaceRemotePhase { Sending, Active, Closed }`
- `WorkspaceError` 新增变体：`Transport` / `RemoteRejected` / `RemoteProtocol`。

### 冻结契约（platform.workspace-projection-channels E4）

- `pub struct NativeApiWorkspaceAccess<S: ContentStore>`：Native API 访问通道。
  - `pub fn new(workspace: Workspace<S>) -> Self`：包裹已有 Workspace 实例。
  - `pub fn into_workspace(self) -> Workspace<S>`：消费通道，拿回内部 Workspace。
  - WorkingSet 语义：`write_file` 写入内存暂存 `HashMap<String, Vec<u8>>`；
    `delete` 写入内存暂存 `HashSet<String>`（标记删除）；`read_file` 先查 WorkingSet
    （含暂存删 → `NotFound`），再从当前 Head Manifest 经 ContentStore 读取；
    `list_dir` 合并 WorkingSet 暂存变更与当前 Head Manifest。
  - `commit()`：把 WorkingSet 暂存内容 + 删除集合落成新 Commit
    （复用 `journal_pending` / `commit_pending` 或等价路径），Head 前进，
    WorkingSet 清空。返回新 CommitId。
  - `pub struct MaterializedDirectoryAccess<S: ContentStore>`：物化目录访问通道。
  - `pub fn materialize(workspace: Workspace<S>, dir: PathBuf) -> Result<Self, WorkspaceError>`：
    构造时把当前 Head Manifest 的全部文件物化到 `dir`（递归创建子目录）。
  - `pub fn into_parts(self) -> (Workspace<S>, PathBuf)`：消费通道，拿回 Workspace 与目录路径。
  - `read_file` / `write_file` / `list_dir` / `delete`：直接操作本地文件系统。
  - `commit()`：扫描 `dir` 与构造时快照（Manifest）的差异——
    新增 / 修改文件 → `Change`，删除文件 → 从 Manifest 移除——构建 ChangeSet
    提交回 Workspace，Head 前进。
- `WorkspaceError` 新增变体：`NotFound { path: String }`（读取 / 删除不存在的路径）、`PathTraversal { path: String }`（路径越界）。
- 场景映射：`scenarios/platform/workspace_projection_channels.toml` 由
  `crates/nexus-workspace/examples/workspace_projection_channels.rs` 驱动，经
  harness 的 `product-scenarios` gate 求值。
- 不变量：两个通道都不改变 Commit DAG / Head Set / Manifest 的权威语义；
  `product_semantics_preserved` 由组合根按场景契约输出。

### 冻结语义

远程提交必须显式完成往返后才 Active；提供方拒绝（RemoteRejected）与协议未识别帧（RemoteProtocol）是可诊断失败，不得吞为成功；未知 parent 的 ChangeSet 由提供方按现有 `UnknownCommit` 语义拒绝。

### 冻结契约（platform.workspace-projection-fallback E4）

- `pub enum WorkspaceAccessProvider { NativeMountDirectory, MaterializedDirectory, NativeApi }`：
  Workspace 的访问通道（PRODUCT §4——无 FUSE/Mount 环境仍可通过 Native API、
  Materialization 或平台式 Projection 使用 Workspace）。
- `pub fn select_access_provider(native_mount: bool, materialization: bool) -> WorkspaceAccessProvider`：
  纯函数、确定性。`native_mount=true` → `NativeMountDirectory`；否则
  `materialization=true` → `MaterializedDirectory`；否则 → `NativeApi`
  （PRODUCT §4 保证的兜底通道，总可用）。
- 任何通道都必须保持产品语义（Commit DAG / Head Set / Manifest 仍完整可用）；
  `product_semantics_preserved` 由组合根按场景契约输出。
- 场景映射：`scenarios/platform/workspace_projection_fallback.toml` 由
  `crates/nexus-workspace/examples/workspace_projection_fallback.rs` 驱动，经
  harness 的 `product-scenarios` gate 求值。

### 冻结契约（W4：CacheManager + ProjectedWorkspace 适配，v9 §22）

- `pub mod cache`：`CacheManager`（确定性内存对象缓存，逻辑时钟）。
  - `pub enum CachePin`：铁律集合 { DirtyJournal, UniqueReplica,
    ComputeSnapshot, PendingArtifact, UnreplicatedCommit, ConflictState,
    Explicit }——被 pin 的条目永不被普通驱逐/`remove`。
  - 驱逐评分：`utility = (hits+1)*(1+ws_prob)*(1+centrality)*(1+refetch_cost)
    / (size*(1+age))`，从低到高驱逐；`ws_prob`/`centrality` 是可选信号
    （W2），永不做正确性依赖。
  - Cache Eviction ≠ CAS GC：只丢缓存副本，不删 CAS 对象；pin 分类与
    §20 Protected Roots 同口径（W1 对齐）。
- `pub struct WorkspaceProjection<A: WorkspaceAccess + Send>`：
  `nexus_platform::ProjectedWorkspace` 的 workspace 侧适配（错误映射
  WorkspaceError → PlatformError）。新增依赖 `nexus-platform`
 （domain → portable trait 方向，已有先例，已在 architecture.toml 声明）。
- 场景映射：`scenarios/product/workspace_cache_eviction.toml` 由
  `crates/nexus-workspace/examples/cache_eviction.rs` 驱动。

### 冻结契约（requirement-change：workspace-authority-v2）

- `pub struct AuthorId(pub String)`：提交作者/节点的不透明标识（v9 §17）。
- `pub struct WorkspaceCommit { id: CommitId, parents: Vec<CommitId>, root_manifest_id: ObjectId, author: AuthorId, created_at_unix: u64 }`。
- `pub fn commit_id_of(parents: &[CommitId], root: &ObjectId, author: &AuthorId, created_at_unix: u64) -> CommitId`：
  纯函数、确定性；同一提交对象在所有节点算出同一 ID。
- `pub struct ConflictObject { id: String, base: CommitId, local: CommitId, remote: CommitId, paths: Vec<String>, state: ConflictState }`；
  `pub enum ConflictState { Unresolved, Resolved { merge_commit: CommitId } }`；
  `pub enum ConflictResolution { TakeLocal, TakeRemote, Custom(Vec<u8>) }`。
- `merge_heads` 冲突时不再返回 `Err(MergeConflict)`：持久化 ConflictObject（字节进 CAS，
  索引进 `DurableState v2`），返回 `MergeReport { conflict: Some(id), merge_commit: None, .. }`，Head 集不变。
- `pub fn resolve_conflict(&mut self, conflict_id: &str, resolutions: &[(String, ConflictResolution)]) -> Result<CommitId, WorkspaceError>`：
  生成 Merge Commit（内容哈希 ID，双 parent），标记 Resolved，Heads 收敛。
- Head 交换（基于已冻结 `WorkspaceTransport`）：
  `pub fn exchange_heads(&mut self, transport: &mut dyn WorkspaceTransport) -> Result<HeadExchangeReport, WorkspaceError>`；
  `pub fn sync_with_remote(&mut self, transport: &mut dyn WorkspaceTransport) -> Result<SyncReport, WorkspaceError>`
  （交换 Head → 拉取缺失提交（含 manifest/blob）→ 逐对 merge_heads 收敛）。
- 场景映射：`scenarios/product/workspace_authority_v2.toml` 由
  `crates/nexus-workspace/examples/workspace_authority_v2.rs` 驱动。

## Verification

### N3 Snapshot 契约增补（待实现）

固定唯一 Commit 与所选文件清单，产生 SnapshotRef；接受后不跟随 Head/工作目录变动。
N3 文件/清单的 SHA-256 与长度在物化前核实；既有 FNV Commit/ObjectId 不作安全校验。
规则、路径规范、symlink 拒绝和目标平台名称碰撞见 `docs/N3-MODEL-CONTRACT.md` §4。
Task durable pin、Pending Artifact、Pending Delivery 为 GC protected roots；
冷启动恢复 roots 后才可 GC，Task 释放 pin 不解除其他合法保留根。
仅管理 Snapshot/物化及 roots，不执行命令、不拥有 TaskOutcome、不自行挑 Provider。
验收：`n3-snapshot-immutable`、`n3-input-integrity`、`n3-gc-roots`；PRODUCT §17。

最低：

```text
cargo check -p nexus-workspace
cargo clippy -p nexus-workspace --all-targets -- -D warnings
```

如果该模块影响产品行为，还必须映射 Integration/Scenario Evidence。

本模块映射五个 E4 场景：

- `scenarios/product/workspace_offline_merge.toml`：由
  `crates/nexus-workspace/examples/workspace_offline_merge.rs` 驱动，经 harness 的
  `product-scenarios` gate 求值；
- `scenarios/regression/crash_recovery.toml`：由
  `crates/nexus-workspace/examples/crash_recovery.rs` 驱动（含 nexus-session 会话记录
  reconcile），经 harness 的 `regression` gate 求值；
- `scenarios/platform/workspace_projection_channels.toml`：由
  `crates/nexus-workspace/examples/workspace_projection_channels.rs` 驱动，经
  harness 的 `product-scenarios` gate 求值；
- `scenarios/product/workspace_gc.toml`（v9 §20）：由
  `crates/nexus-workspace/examples/workspace_gc.rs` 驱动，经 harness 的
  `product-scenarios` gate 求值；
- `scenarios/product/workspace_shallow_sparse.toml`（v9 §20）：由
  `crates/nexus-workspace/examples/workspace_shallow.rs` 驱动，经 harness 的
  `product-scenarios` gate 求值。

### 冻结契约（v9 §20 存储治理，`src/gc.rs`）

- 两阶段 GC：`plan_gc`（纯规划，可达闭包）→ `apply_tombstones`
  （Tombstone/Deletion Intent 持久化）→ `sweep`（保留期后物理删除）。
  `sweep` 前重验可达性：tombstone 期间复活的对象撤销 tombstone，不删除。
- Protected Roots：当前 Heads、显式保留 Snapshot（`retain_snapshot`）、未合并分支、
  Conflict 相关提交（W3 扩展点）、journal pending 的 manifest、当前 `state_root`、
  active pin（内存态）、legal/user hold（持久态）。
- `sweep` 跳过 in-flight fetch 的对象；超 `max_sweep_per_run` 限速；pin/hold
  阻止删除并计数。
- 默认保留期 `DEFAULT_RETENTION_SECS` = 14 天（v9 §20 移动端默认值）。
- DurableState 格式 v2（按本模块 Invariants 拒绝 v1 解析）：新增 `tombstone` / `retain` /
  `hold` / `shallow` 行；tombstone/retain/hold/shallow_frontier 持久化。
- Shallow/Sparse：`ReplicaPolicy { max_depth, sparse_paths }`；
  `shallow_clone` 按老→新导入并做内容寻址校验（id 不匹配 → `CorruptState`）；
  `deepen` 按需拉取缺失祖先，不改变 CommitId；`read_at_commit` 返回三态
  `ReadOutcome`（`NotHeldLocally` 是预期状态，不是损坏）。
- `ObjectFetcher` 由 Composition Root 适配传输实现；portable-core 只定义形状。
- 后台调度器 `GcScheduler`（§15 Structured Concurrency：Owner + AtomicBool
  取消 + join 回收）：soft 配额压力触发 GC，hard 压力经 `QuotaHandler`
  通知（W2/W4 扩展点）；`GcRunPolicy::can_run_now` 预留移动端"仅 WiFi/充电"策略。
- 配额：`QuotaPolicy { soft_bytes: 10GiB, hard_bytes: 20GiB }` 默认值；
  `pressure()` 边界取高等级。
- `compact()`：清理目标已不存在的 tombstone 记录并重写 state，不改变 CommitId。
- Stop Condition：任何情况下不删除仍可达或未合并的数据；`delete_object`
  是 `ReachabilityGc` 的 GC 专用原语，`ContentStore` 本身只读/写。

## Performance Budget

未定义性能预算的路径不得宣称“性能完成”。进入 hot path 后必须在 Contract 中增加 baseline、noise tolerance、warning threshold 与 blocking threshold。

## Observability

稳定结构化字段优先于自由文本；如涉及 Session/Provider/Path/Workspace，应携带对应 correlation id。

## Recovery Semantics

Workspace 持久状态（DAG + Heads + Journal）序列化为单个 CAS 对象，`commit_changes`
以写前日志执行：`journal_pending`（marker 先落盘，提交不可见）→ 提交落 DAG →
`commit_pending`（清除 marker）。冷启动必须先 `open` 恢复 durable state，再
`reconcile_journal` 幂等回放：提交已在 DAG 则确认（confirmed），不在则从 marker
重放（redone），journal 清空后持久化。任何情况下不丢失已写入数据，重复
reconcile 无副作用。孤儿会话归类见 `nexus-session` 的 `reconcile_session_records`。

## Platform Constraints

平台专有代码只允许存在于 `nexus-platform-*` 或 Composition Root。Portable crate 必须通过相应 portability gate。

### N3-12 有界固定 Commit freeze

按 docs/N3-12-SNAPSHOT-STAGING-CONTRACT.md，新增有界 freeze 路径，保持原 freeze API/选择与 SHA-256 清单语义。只读取指定现存 DAG Commit，不选 Head/WorkingSet，不自动创建 Workspace/修补 anchor；bounded ContentStore 的 descriptor 分配前检查归属 app adapter。Portable workspace 保持无 OS 副作用，不执行命令、不拥有 upload预算/授权。旧 anchor 非 fsync 写入边界不扩大为 power-loss 保证。
