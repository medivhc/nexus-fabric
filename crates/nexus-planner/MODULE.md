# nexus-planner Module Contract

## Responsibility

唯一系统级 Planner：根据 Resource + Intent + Constraint 决定 Provider、Placement、Path、Execution Strategy，并生成 DecisionTrace。

## Non-Responsibilities

不直接执行网络 I/O、Connectivity Establishment、Workspace Prefetch 或 Compute Execution。

## Inputs

- 仅接受公开类型、DTO、trait、事件或稳定协议对象。
- 输入必须可被结构化验证；不得依赖未声明的全局隐式状态。

## Outputs

- 结构化 Result / Event / DTO。
- 失败必须保留可诊断原因，不以日志文本代替错误类型。

## Allowed Dependencies

- `nexus-domain`
- `nexus-registry`
- `nexus-measurement`

## Forbidden Dependencies

- `engineering/` 下的 Harness/Plugin。
- 未在 `policies/architecture.toml` 声明的 Nexus 内部 crate。
- Portable 模块中的平台专有 Framework/API。
- 通过“便利”依赖绕过公开领域边界。

## Invariants

- 全系统只有一个 Core Planner。
- Domain-specific 信息通过类型化 DomainExtension。
- 同等输入应产生可解释、可重放的决策。
- 本地优先（白皮书原则 #4）是确定性输入的一部分：`PlanningSnapshot.local_provider`
  为 `None` 时不应用偏好；指定后本地候选恒得 `LOCALITY_BONUS` 加成（记入 score
  breakdown，可解释）。
- v9 §7：本 crate 永不调用领域 Estimator；代价估计只作为输入进入类型化 extension。

## Side Effects

- 仅允许 Responsibility 所需且在架构层中明确归属的副作用。
- 新增副作用前必须更新本契约和 Scenario/Policy（如影响外部行为）。

## Public API

- 默认最小 surface：`private -> pub(crate) -> pub`。
- Public API 变更必须保持结构化、可版本化并有调用方验证。
- 已实现（阶段 A）：
  - 两阶段求解：`filter_candidates`（硬谓词短路，被拒候选不进评分）/ `score_candidates`（打分明细 `breakdown`：`rtt` 归一化分量 [0, 10_000] ＋ `locality` 本地优先分量；各分量之和恒等于总分）；
  - `RejectReason` 结构化拒绝原因枚举（含稳定 `label()`，取代自由文本；"为什么这个 Provider 没被选"的唯一出口）；
  - `PlanningSnapshot`（规划周期一致视图；`with_local_provider` 指定本地 Provider，应用白皮书原则 #4 本地优先加成 `LOCALITY_BONUS`）；
  - `plan_from_snapshot` / `plan`（K2→K3→确定性选优组装；DecisionTrace 加厚：每候选的拒绝原因 / Connectivity Evaluation / Measurement 快照 / 分数与打分明细）；
  - `Planned { plan, trace }` / `DecisionTrace` / `ConsideredCandidate`。
- 类型归属（N2 P0-3）：`RejectReason` / `ScoreComponent` / `ConsideredCandidate` /
  `DecisionTrace` / `PlanId` / `MeasurementSnapshot` / `PlanSnapshot` /
  `plan_id_of` 已迁移至 `nexus-domain`（Session 记录内嵌 `PlanSnapshot` 需要零依赖的
  DTO 位置；`nexus-session` 只允许依赖 `nexus-domain`）。求解逻辑仍在本 crate；
  本 crate 经 `use nexus_domain::{...}` 重用这些类型。
- 已实现（v9 §8.1 Connectivity Feasibility，scenarios/product/connectivity_evaluation.toml）：
  - `PlanningSnapshot.connectivity: Vec<(ProviderId, ConnectivityEvaluation)>` +
    `with_connectivity` builder（空 = 未评估，保持旧行为）；
  - `RejectReason::NoFeasibleConnectivityPath`（label `no_feasible_connectivity_path`）；
  - `connectivity_gate(&PlanningSnapshot) -> Vec<(ProviderId, RejectReason)>` 纯函数；
  - `plan_from_snapshot` 在 Filter 后应用门控（不覆盖已有拒绝原因）；
  - `ConsideredCandidate.connectivity: Option<ConnectivityEvaluation>`（trace 可见评估贡献）。
- 已实现（N2 P0-3 D3，scenarios/product/n2-plan-preview.toml）：
  - `LOCALITY_BONUS: u32 = 1_000`（白皮书原则 #4 本地优先；策略常数，调参需同步更新 explain 文案）；
  - `SCORE_TERM_RTT` / `SCORE_TERM_LOCALITY` 打分分量名；
  - `ExplainMode::{History, Estimate}` + `classify_explain_arg`（`plan explain` 双模式分类；`sess-` 前缀 → 历史模式）+ `commitment_note()`（估算模式必须展示"估算非承诺"）；
  - `PlanHistory` trait（`plan explain <session-id>` 读口；P0-3 只定义契约，P0-4 SessionManager 落地写口；查无记录不得回退重算）；
  - `ExplainedPlan::{history, estimate}` + `verify_plan_id()`。
- v9 §7 红线：领域 Estimator 不得生成第二套系统级 Plan；compute 代价估计只能作为
  Planner 输入（`ComputePlanExtension` 字段）。`plan_from_snapshot` 的 extension
  处理处有显式注释；本 crate 永不调用 Estimator。

## Verification

最低：

```text
cargo check -p nexus-planner
cargo clippy -p nexus-planner --all-targets -- -D warnings
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
