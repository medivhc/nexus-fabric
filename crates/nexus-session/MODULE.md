# nexus-session Module Contract

## Responsibility

管理 Plan 的运行生命周期、Replan、Structured Concurrency、LifecyclePhase 与 TerminalOutcome；也承载运行时 durable 记录（`SessionRecord` 与链路 `link_marker`）。

## Non-Responsibilities

不复制 Planner 逻辑，不直接绑定 OS API。

## Inputs

- 仅接受公开类型、DTO、trait、事件或稳定协议对象。
- 输入必须可被结构化验证；不得依赖未声明的全局隐式状态。

## Outputs

- 结构化 Result / Event / DTO。
- 失败必须保留可诊断原因，不以日志文本代替错误类型。

## Allowed Dependencies

- `nexus-domain`

## Forbidden Dependencies

- `engineering/` 下的 Harness/Plugin。
- 未在 `policies/architecture.toml` 声明的 Nexus 内部 crate。
- Portable 模块中的平台专有 Framework/API。
- 通过“便利”依赖绕过公开领域边界。

## Invariants

- TerminalOutcome 与 LifecyclePhase 双轨分离。
- Completed/Failed/Cancelled Exactly-Once。
- Worker 只发事件，Owner State Machine 唯一提交 Outcome。

## Side Effects

- 仅允许 Responsibility 所需且在架构层中明确归属的副作用。
- 新增副作用前必须更新本契约和 Scenario/Policy（如影响外部行为）。

## Public API

- 默认最小 surface：`private -> pub(crate) -> pub`。
- Public API 变更必须保持结构化、可版本化并有调用方验证。
- 本骨架只提供最小编译锚点；业务 API 在实现阶段增量添加。

已实现（revision f8c7113+）：

- `SessionOwner`：Owner 状态机，`commit_outcome` 为 `TerminalOutcome` 唯一写入入口（commit-once 守卫），`transition_phase` 执行合法迁移校验，`request_cancellation` 仅记录取消事件（已终态或 phase=`Disposed` 后拒绝记录，`AlreadyTerminated`）。
- `SessionEvent`：Worker 上报事件（Started/PhaseChanged/Progress/CancellationRequested/ConnectivityEstablished/ConnectivityFailed/OutcomeCommitted）。
- `record_connectivity_established` / `record_connectivity_failed`：Worker 上报 Connectivity 事件（不写 Outcome；已终态或 phase=`Disposed` 后拒绝记录，`AlreadyTerminated`）。
- `CancelToken` 与 `AbortOnDropHandle`：std 实现的协作取消原语（Portable，无 tokio 依赖）；JoinSet/Reaper 运行时接线由 domain-runtime 层完成。
- `SessionError`：结构化会话错误，`From<SessionError> for NexusError` 转换。
- `SessionRecord` / `SessionRecordStore` / `reconcile_session_records`：冷启动会话记录 reconcile（幂等、孤儿分类，AGENTS.md §15；phase 感知：`Disposed` 直接跳过，终态但未 `Disposed` 重放 cleanup 到 `Disposed` 且不重写 outcome）。
- `SessionRecord.plan_snapshot: Option<PlanSnapshot>`（N2 P0-3 D3）：Session 内嵌
  `PlanSnapshot{plan, decision_trace}`；Plan 可重算、不独立持久化；reconcile 回写时
  原样搬运、不重算；P0-4 的 SessionManager 在建 Session 时填充（`None` = 旧记录）。

N2 P0-4 增补（SessionManager，D1/D4/D7）：

- `SessionManager`：Session 生命周期的**唯一 Owner**（§13 结构化并发，daemon
  组合根装配唯一实例；提供方侧只做 admission＋租约，不另建领域 Session）。
  `open`（PlanSnapshot 内嵌＋持久化）/ `get` / `list` / `attach` /
  `close`（→Cancelled）/ `complete` / `note_client_detached` /
  `sweep_detached`（attach window 外→Cancelled(ClientDetached)）/
  `note_provider_lost`（→Failed）/ `note_revoked`（→Cancelled(Revoked)）。
- 终态语义（D7）：断开 ≠ Failed——连接丢失的 Session 终态为 **Unfinished**
  （可重连；attach window 内保持 Active/Unfinished），只有明确失败才 Failed；
  `TerminalOutcome` 唯一 Owner（§14，`SessionManager` 经 `commit_outcome`）。
- Attach window：默认 `DEFAULT_ATTACH_WINDOW_SECS = 300`；CLI 退出重进后
  可按 `SessionId` `attach` 查询状态＋历史 `DecisionTrace`（`nexus session list/watch`）。
- `SessionRecordStore` 持久化由 Composition Root 注入
  （`apps/nexus` 的 `KvSessionRecordStore`：FileKvStore 落盘）。
- Deletion Test（AGENTS.md §12）：SessionManager 过了——它是 §13 要求的
  Owner 语义（Cancellation/Join/Reap 归属）＋ §14 的 Outcome 唯一写入者的
  具象化；删掉它改"直接操作 SessionRecordStore"，会失去 Outcome 唯一写入点
  和 attach window 状态机的独立变化维度。

已实现（2026-10-26，P1′ 接缝④：链路 durable marker 迁入）：

- `link_marker::LinkMarker { link_id, kind, locator, established_at_unix, stale }`
  + `LinkMarker::established(...)`；
- `link_marker::LinkMarkerKind { Direct, Relay }` + `as_str()` / `parse()`
  （锁定 `links.json` 的 `"direct"` / `"relay"` 字符串）；
- `link_marker::LinkMarkerStore`（`load` / `save` upsert 契约）；
- `link_marker::LinkReconcileReport { markers_checked, marked_stale }`；
- `link_marker::reconcile_link_markers`（幂等；只标记不建连）。

以上 5 项同时以 `nexus_session::{…}` 重导出。

## Verification

### N3 边界增补（待实现）

SessionManager 仍是资源 Session 的唯一 Owner；TaskOwner 在 nexus-compute，
不得为了 N3 在本 crate 增加 compute 依赖或第二个 SessionManager。
客户端重连可创建新的资源 Session，关联到原 TaskId；不重建执行契约或重新 spawn。
现有 orphan Session reconcile 的 Failed 仅表示该 Session，不证明远端 Task 的结局。
验收：`n3-client-reattach`、`n3-crash-reconcile`；PRODUCT §17。

最低：

```text
cargo check -p nexus-session
cargo clippy -p nexus-session --all-targets -- -D warnings
```

如果该模块影响产品行为，还必须映射 Integration/Scenario Evidence。

## Performance Budget

未定义性能预算的路径不得宣称“性能完成”。进入 hot path 后必须在 Contract 中增加 baseline、noise tolerance、warning threshold 与 blocking threshold。

## Observability

稳定结构化字段优先于自由文本；如涉及 Session/Provider/Path/Workspace，应携带对应 correlation id。

## Recovery Semantics

v9 §15.2/§15.3（Session 范围，`feature/crash-recovery`）：

- Durable 状态：`SessionRecord { session, phase, outcome }`（轻量 marker）。
  文件实现由 Composition Root 注入（`SessionRecordStore` trait；见 `nexusd::recovery::FileSessionRecordStore`）。
- Durable 状态（链路 marker，2026-10-26 接缝④迁入）：`link_marker::LinkMarker
  { link_id, kind: LinkMarkerKind, locator, established_at_unix, stale }`。
  文件实现由 Composition Root 注入（`LinkMarkerStore` trait；见
  `nexusd::recovery::FileLinkMarkerStore`）。`links.json` 的字节格式（字段名、字典序、
  `"direct"`/`"relay"` 字符串值）由 `apps/nexusd` 的 fixture 测试锁定，不随迁移改变。
  冷启动 `link_marker::reconcile_link_markers` 把未 stale 的 marker 标为 stale（进程死亡
  = socket 死亡，触发重建；已 stale → 跳过；幂等）；本函数只标记不建连。
- 保真度契约：durable 记录只保留分类 + 失败原因字符串；`Failed` 的完整类型化
  `NexusError` 不持久化（load 时重建为 `Internal{message}`）。
- 冷启动 `reconcile_session_records`（phase 感知，amendment B1/B2 2026-10-03）：
  `phase == Disposed` → 跳过（含 `{Disposed, Unfinished}` 不可达路径，永不判为孤儿）；
  已终态但 `phase != Disposed` → 重放 cleanup 迁移（`Allocating→Disposed` /
  `Active→Draining→Disposed` / `Draining→Disposed`，经 `SessionOwner::transition_phase`
  校验）到 `Disposed` 并回写，**不重新 commit outcome**；未终态且进程死亡 →
  孤儿 → 经 `SessionOwner` 恰一次提交 `Failed` 并清理到 `Disposed`，回写记录；幂等。
- Journal：不需要。所有写都是单文件原子替换；reconcile 幂等。

## Platform Constraints

平台专有代码只允许存在于 `nexus-platform-*` 或 Composition Root。Portable crate 必须通过相应 portability gate。
