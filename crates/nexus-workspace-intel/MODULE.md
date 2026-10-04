# nexus-workspace-intel Module Contract

## Responsibility

v9 §21 Workspace Intelligence：非权威、可丢失重建的访问智能层。

- `AccessTrace`：访问轨迹记录（事实输入）；
- `WorkspaceGraph`：Static Dependency Graph（manifest containment）+ Observed Access Graph（轨迹共现）；
- `Profile`：典型使用情境（声明式 / 从轨迹捕获）；
- `WorkingSetEstimator`：纯函数，按 Snapshot/Profile/Graph/Trace/TaskContext/CacheState 打分（0..=10000，确定性）；
- `PrefetchScheduler`：只决定预取什么、何时、并发和预算（贪心装入预算）；**不选 Provider/Path**；
- `ResourceDeliveryRequest`（DTO 在 `nexus-domain`）：缺失 Object/Chunk → Core Planner 的标准请求；
- `IntelStore`：智能状态的独立 JSON 持久化（与权威状态物理隔离）。

## Non-Responsibilities

- 不做正确性判断：权威 DAG/HeadSet/Journal 语义归 `nexus-workspace`；
- 不选 Provider/Path：归 Core Planner（Planner ≠ Estimator）；
- 不实现平台 FUSE/File Provider：归 `nexus-platform-*`；
- 不做网络 I/O：本 crate 零 I/O（`IntelStore` 的文件读写除外，调用方驱动）。

## Inputs

- 快照路径列表（`&[String]` 或只读 `&Workspace<S>`）；
- 访问轨迹、Profile、TaskContext、CacheState、预算（全为值对象）。

## Outputs

- `Vec<ScoredPath>`（分数降序，同分路径升序，确定性）；
- `PrefetchPlan`（items / skipped_cached / skipped_budget / suggested_concurrency）；
- `ResourceDeliveryRequest`（DTO，版本化）。

## Allowed Dependencies

- `nexus-domain`（DTO：ResourceDeliveryRequest/Intent/Constraint/ResourceId/ProviderId）
- `nexus-workspace`（只读：`Workspace::list_head_paths` 建静态图；**反向零依赖**）
- `nexus-planner`（类型：`PlanningSnapshot` 转换；不调用规划决策之外的逻辑）
- `nexus-registry`（类型：`ProviderRecord` 过滤）
- `nexus-storage`（`ContentStore` bound，用于 `build_from_workspace` 的泛型约束）

## Forbidden Dependencies

- `nexus-transport` / `nexus-fabric`（无网络 I/O）；
- `engineering/` 下的 Harness/Plugin；
- 未在 `policies/architecture.toml` 声明的 Nexus 内部 crate。

## Invariants

1. **可丢失性**：删除 `IntelStore` 文件后，本 crate 所有状态可从新轨迹重建；`nexus-workspace` 正确性不受影响（Deletion Test，见 lib.rs）。
2. **确定性**：`estimate` / `schedule` / `build` 为纯函数；同分按路径字典序；"现在"取轨迹最大时刻（不读系统时钟）。
3. **只读性**：对 `nexus-workspace` 的唯一使用是读路径列表；绝不修改权威状态。
4. **不选路**：`PrefetchScheduler` 输出不含 Provider/Path；取回必须经 `ResourceDeliveryRequest` → Core Planner。
5. **预算诚实**：`PrefetchPlan.items` 总字节 ≤ `max_bytes`；已缓存路径永不进入拉取列表。

## Side Effects

- `IntelStore::save/delete` 写文件（原子 tmp+rename）；其余 API 无副作用。

## Public API

`AccessTrace`、`WorkspaceGraph`、`Profile`、`WorkingSetEstimator`、`EstimatorInput`、
`ScoredPath`、`TaskContext`、`CacheState`、`PrefetchScheduler`、`PrefetchBudget`、
`PrefetchItem`、`PrefetchPlan`、`to_snapshot`、`IntelStore`、`IntelSnapshot`。

## Verification

- 单测：trace/graph/profile/estimator/prefetch/store/delivery 全覆盖（含确定性、预算、缓存排除）；
- E4：`scenarios/product/workspace_intel.toml`（访问模式 → 预测 → prefetch → 缺失对象走 Planner）。

## Performance Budget

- `estimate`：O(P·(E+P))，P=路径数，E=边数；万级路径以下无优化需求（记录实测后再定 budget）。

## Observability

- `ScoredPath.reasons`：每路径非零分项的可解释记录；
- `PrefetchPlan.skipped_cached/skipped_budget`：计数器。

## Recovery Semantics

- 智能状态丢失 = 回到空轨迹；下次访问重建。无恢复义务（非权威）。

## Platform Constraints

无（纯计算 + 可选文件持久化，调用方选路径）。
