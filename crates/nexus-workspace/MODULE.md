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
- 离线分叉不得丢弃本地提交。
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

## Verification

最低：

```text
cargo check -p nexus-workspace
cargo clippy -p nexus-workspace --all-targets -- -D warnings
```

如果该模块影响产品行为，还必须映射 Integration/Scenario Evidence。

本模块映射两个 E4 场景：

- `scenarios/product/workspace_offline_merge.toml`：由
  `crates/nexus-workspace/examples/workspace_offline_merge.rs` 驱动，经 harness 的
  `product-scenarios` gate 求值；
- `scenarios/regression/crash_recovery.toml`：由
  `crates/nexus-workspace/examples/crash_recovery.rs` 驱动（含 nexus-session 会话记录
  reconcile），经 harness 的 `regression` gate 求值。

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
