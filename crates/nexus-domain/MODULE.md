# nexus-domain Module Contract

## Responsibility

定义稳定核心领域类型：Resource、Provider、Node、Intent、Constraint、Plan、Session、Measurement 及核心不变量。

含跨栈 NAT 词汇（`nat::NatType` / `nat::StunMapping`）：v9 CLI 运行时与 N1 运行时共用的纯类型（2026-10-26 由 `nexus-connectivity::nat` 逐字迁入）。

## Non-Responsibilities

不执行 I/O，不依赖平台 API，不做发现、网络建连、存储、调度或协议解析。不做 STUN 编解码、不建连（NAT 词汇只承载类型，不含行为）。

`FlowContext.egress_hint` 的语义边界：它是“建议出口 tag”的**非身份、非资源**提示，
只用于缩小 Provider 候选快照（`build_snapshot` 单候选过滤）；它不改变 Resource/
Provider 身份，不构成 Plan，也不表示出口已建立。`None` 表示无提示（防御性空候选由
组合根处理），不得把 hint 当作已解析的 Provider。

## Inputs

- 仅接受公开类型、DTO、trait、事件或稳定协议对象。
- 输入必须可被结构化验证；不得依赖未声明的全局隐式状态。

## Outputs

- 结构化 Result / Event / DTO。
- 失败必须保留可诊断原因，不以日志文本代替错误类型。

## Allowed Dependencies

- 无 Nexus 内部依赖。

## Forbidden Dependencies

- `engineering/` 下的 Harness/Plugin。
- 未在 `policies/architecture.toml` 声明的 Nexus 内部 crate。
- Portable 模块中的平台专有 Framework/API。
- 通过“便利”依赖绕过公开领域边界。

## Invariants

- Resource != Provider；Provider != Node；Identity != Locator。
- Plan 与 Session 分离；Measurement 是事实而非 Score。
- 核心类型必须保持 Portable Core。

## Side Effects

- 仅允许 Responsibility 所需且在架构层中明确归属的副作用。
- 新增副作用前必须更新本契约和 Scenario/Policy（如影响外部行为）。

## Public API

- 默认最小 surface：`private -> pub(crate) -> pub`。
- Public API 变更必须保持结构化、可版本化并有调用方验证。
- 本骨架只提供最小编译锚点；业务 API 在实现阶段增量添加。

跨栈 NAT 词汇（2026-10-26，P1 接缝①）：

- `nat::NatType { FullCone, RestrictedCone, PortRestrictedCone, Symmetric, Unknown }`
  （derives `Debug, Clone, Copy, PartialEq, Eq`，逐字迁自 `nexus-connectivity::nat`，
  变体顺序与 doc 不变；线格式映射仍在 `nexus-nat-traversal::signal`）。
- `nat::StunMapping { local: SocketAddr, public: SocketAddr }`（derives `Debug, Clone`）。
- `nexus-connectivity` 以 `pub use nexus_domain::nat::{NatType, StunMapping}` 保旧路径。

已实现（revision f8c7113+）：

- `PlanExtension` 类型化领域扩展：`NetworkPlanExtension` / `WorkspacePlanExtension` / `ComputePlanExtension` / `ServicePlanExtension`，各带 `version` 字段；`Plan.extension: Option<PlanExtension>`（替代原 `domain_extension_type: Option<String>`）。
- `NexusError` 结构化失败枚举（PRODUCT §2 七类失败 + `Unsupported` / `Internal`）与 `FailureDisposition`（Retry/Fallback/Abort/Escalate）。
- `TerminalOutcome` 改造：`Failed(NexusError)` 携带结构化错误；`Cancelled` 无 payload（原因经 Session 事件记录）。
- `ConnectivityEvaluation`（v9 §8.1）：规划期连通性可行性 DTO（版本化，`VERSION=1`）——
  `direct_likely` / `punching_likely` / `relay_available` / `existing_link_available` /
  `estimated_setup_cost_ms: Option<u32>`（`None` = 无可行路径）/
  `confidence_percent: u8`；`has_feasible_path()` 任一路径可行即 true。
  由 `nexus-connectivity::evaluation::evaluate_connectivity` 纯函数产生，
  作为 Core Planner 的 Connectivity Feasibility 输入。

已实现（N2 P0-1，2026-10-03）：

- 身份/寻址类型：`WorkspaceId` / `NodeId`（内容派生，`IdentityManager::peer_id_of`，
  Identity≠Locator）/ `ResourceName`（校验：ASCII 字母数字/`-`/`_`，≤128）/
  `ResourceRef{workspace, name}`（kind 不进地址，D2）/ `ResourceKind`
  （Network/Service/Workspace/Compute/Device，目录属性）/
  `ResourceOperation{Use, Manage}`。
- 授权词汇：`DenyReason{NoSuchGrant/WrongWorkspace/OperationNotGranted/Expired/Revoked}`
  （`code()` 为审计/JSON 稳定判别名）/ `AuthorizationDecision{Allow, Deny}`。
- `NexusError` 新增：`NotFound{kind, id}`（Abort）、`NodeIdentityUnavailable{reason}`
  （Abort）、`PersistenceFailed{path, reason}`（Escalate）。

已实现（N2 P0-3，2026-10-03）：

- 规划决策轨迹 DTO（从 `nexus-planner` 迁移至此；`nexus-session` 只允许依赖
  `nexus-domain`，Session 内嵌快照需要零依赖的 DTO 位置）：
  `RejectReason`（结构化拒绝原因，稳定 `label()`；"为什么没被选"的唯一出口）/
  `ScoreComponent{name, contribution, detail}`（打分明细项；各项之和恒等于总分）/
  `ConsideredCandidate`（加厚：`rejected_reason` / `connectivity` /
  `measurement: Option<MeasurementSnapshot>` / `score` / `score_breakdown`）/
  `DecisionTrace{considered, selected}`。
- `MeasurementSnapshot`：决策时 `LinkMeasurement` 的领域侧值拷贝（快照语义，
  不随后续测量更新；`nexus-planner` 负责填充）。
- `PlanId(pub String)`：FNV-1a 64 位十六进制确定性摘要（非密码学，只作标识符，
  不做安全边界）；`plan_id_of(&Plan, &DecisionTrace)` 规范编码全部决策字段，
  同一输入跨运行恒得同一 Id；`fnv1a_64_hex` 为底层原语。
- `PlanSnapshot{plan_id, plan, decision_trace}`：一次规划决策的不透明记录
  （D3：Plan 可重算、不独立持久化；Session 记录内嵌本快照）；
  `PlanSnapshot::from_planned` 由内容派生 `plan_id`。

## Verification

### N3 契约增补（待实现）

PRODUCT §17 与 `docs/N3-MODEL-CONTRACT.md` 定义 N3 类型区：TaskId / SnapshotId /
ArtifactId、SnapshotRef、SubmitTaskRequest、TaskView、ArtifactRecord 和版本化错误/状态 DTO。
标识符及跨模块 DTO 在本 crate，TaskOwner/存储/命令执行不在本 crate。
TaskPhase 与 TaskOutcome、execution/delivery/cancellation/observation 分离；
Task 不增加 Core Plan 固定字段，Session != Task。
JSON 形状由 `docs/contracts/n3-task-v1.schema.json` 冻结；Rust API 在实现阶段补充。
关联场景：`scenarios/product/n3-*.toml`；现有 API 语义保持不变。

最低：

```text
cargo check -p nexus-domain
cargo clippy -p nexus-domain --all-targets -- -D warnings
```

如果该模块影响产品行为，还必须映射 Integration/Scenario Evidence。

## Performance Budget

未定义性能预算的路径不得宣称“性能完成”。进入 hot path 后必须在 Contract 中增加 baseline、noise tolerance、warning threshold 与 blocking threshold。

## Observability

稳定结构化字段优先于自由文本；如涉及 Session/Provider/Path/Workspace，应携带对应 correlation id。

## Recovery Semantics

任何持久状态或长期任务都必须定义 crash 后的 reconcile 行为。无持久状态的纯模块应保持可重建。

## Platform Constraints

平台专有代码只允许存在于 `nexus-platform-*` 或 Composition Root。Portable crate 必须通过相应 portability gate。
