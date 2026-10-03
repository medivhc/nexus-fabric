# nexus-domain Module Contract

## Responsibility

定义稳定核心领域类型：Resource、Provider、Node、Intent、Constraint、Plan、Session、Measurement 及核心不变量。

## Non-Responsibilities

不执行 I/O，不依赖平台 API，不做发现、网络建连、存储、调度或协议解析。

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

## Verification

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
