//! nexus-planner
//!
//! 全系统唯一的系统级 Core Planner：根据 Resource + Intent + Constraint，
//! 在候选 Provider 中决定 Provider / Placement / Path / ExecutionStrategy，
//! 并生成可解释、可重放的 DecisionTrace。
//!
//! 边界（ARCHITECTURE §5 / §6）：
//! - 规划阶段只做评估与选择，不执行网络 I/O，不做 Connectivity Establishment；
//! - 领域特有信息只进入类型化、版本化的 PlanExtension；
//! - 同等输入必然产出同等决策（确定性），Measurement 只作为事实，不引入业务评分权重。
//!
//! 求解模型（吸收开源标杆 kube-scheduler 的 Scheduling Framework）：
//! - **Filter 硬谓词短路**（K2）：不满足硬约束的候选被拒绝，绝不进入评分阶段；
//! - **Connectivity Feasibility 门控**（v9 §8.1）：`PlanningSnapshot.connectivity`
//!   携带的评估中，无任何可行路径的候选被拒绝（`NoFeasibleConnectivityPath`），
//!   无评估的候选保持旧行为；DecisionTrace 记录每个候选的评估；
//! - **Score 归一化加权**（K3）：只对可行候选评分；打分明细
//!   （`ScoreComponent`：`rtt` 分量 + `locality` 分量）写入 DecisionTrace，
//!   各分量之和恒等于总分；
//! - **本地优先**（白皮书原则 #4）：`PlanningSnapshot.local_provider` 指定的
//!   本地 Provider 得 `LOCALITY_BONUS` 加成（默认偏好，非绝对优先——
//!   未知 RTT 仍严格排在已测候选之后）；
//! - **规划快照**（K5）：一次规划使用一致的 candidates + constraints 视图；
//! - **结构化拒绝原因**（K4）：DecisionTrace 记录结构化枚举，而非自由文本。
//!
//! v9 §7 红线（P0-3 显式约束）：领域 Estimator **不能**生成第二套系统级 Plan。
//! compute 等领域的代价估计只能作为 Planner 的**输入**
//! （`ComputePlanExtension` 的 `queue_delay_ms` / `execution_estimate_ms` 等字段），
//! Planner 永不调用 Estimator、永不把估计结果当作另一套 Plan 执行。
//! 见 `plan_from_snapshot` 中 extension 处理处的注释。
//!
//! 本 crate 是 Portable Core：纯计算、零 I/O，可编译到 WASI。
//! 详细边界见同目录 `MODULE.md`。

#![forbid(unsafe_code)]

use std::collections::HashMap;

use nexus_domain::{
    ConnectivityEvaluation, ConsideredCandidate, Constraint, DecisionTrace, Intent,
    MeasurementSnapshot, NetworkPlanExtension, NexusError, Plan, PlanExtension, PlanId,
    PlanSnapshot, ProviderId, RejectReason, ResourceId, ScoreComponent, SessionId, plan_id_of,
};
use nexus_measurement::LinkMeasurement;
use nexus_registry::ProviderRecord;

/// 能力约束键（与 nexus-policy 的 CONSTRAINT_CAPABILITY 同值；planner 不依赖 policy crate）。
const CONSTRAINT_CAPABILITY: &str = "capability";

/// Placement 硬约束键：要求候选的 `ProviderRecord.placement` 等于约束值。
///
/// 与 `capability` 同级——**候选级可判定**的硬谓词，被违反时给出结构化
/// `RejectReason::ExcludedByConstraint`（D3："为什么没被选"的出口，P1-16）。
/// `exit-dns` / `authorization` 等约束不是候选级谓词（前者进 PlanExtension，
/// 后者由 policy/授权层判定），planner 不据此过滤——未知键一律不产生拒绝原因，
/// 避免"静默把候选全拒掉"。
const CONSTRAINT_PLACEMENT: &str = "placement";

/// 归一化评分满分（万分比整数，避免浮点不确定性）。
const SCORE_SCALE: u64 = 10_000;

/// 本地优先加成（白皮书原则 #4"本地优先是一项默认偏好"）。
///
/// 加在归一化 RTT 分之上的固定整数项（记入 score breakdown 的 `locality` 分量）；
/// 总分区间为 [0, SCORE_SCALE + LOCALITY_BONUS]。数值是策略选择（默认偏好强度），
/// 不是物理量；调参需同步更新 DecisionTrace 的 explain 文案。
pub const LOCALITY_BONUS: u32 = 1_000;

/// 打分分量名：RTT 归一化分量。
pub const SCORE_TERM_RTT: &str = "rtt";
/// 打分分量名：本地优先分量。
pub const SCORE_TERM_LOCALITY: &str = "locality";

// ---------- 规划快照（吸收点 K5） ----------

/// 规划快照：一次规划周期内使用的**一致视图**（candidates + constraints 不可变）。
///
/// 规划开始前冻结，全程使用同一快照，避免规划过程中状态漂移导致不一致决策。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanningSnapshot {
    /// 事实候选（含 Presence 与能力广告）。
    pub candidates: Vec<ProviderRecord>,
    /// 冻结的硬约束。
    pub constraints: Vec<Constraint>,
    /// per-provider Connectivity Evaluation（v9 §8.1）；空 = 未评估（保持旧行为）。
    pub connectivity: Vec<(ProviderId, ConnectivityEvaluation)>,
    /// 本地 Provider（白皮书原则 #4 本地优先；`None` = 不应用本地偏好）。
    pub local_provider: Option<ProviderId>,
}

impl PlanningSnapshot {
    /// 构造规划快照。
    #[must_use]
    pub fn new(candidates: Vec<ProviderRecord>, constraints: Vec<Constraint>) -> Self {
        Self {
            candidates,
            constraints,
            connectivity: Vec::new(),
            local_provider: None,
        }
    }

    /// 附上 Connectivity Evaluation（builder；`connectivity_gate` 的输入）。
    #[must_use]
    pub fn with_connectivity(
        mut self,
        connectivity: Vec<(ProviderId, ConnectivityEvaluation)>,
    ) -> Self {
        self.connectivity = connectivity;
        self
    }

    /// 指定本地 Provider（builder；本地优先加成的对象）。
    #[must_use]
    pub fn with_local_provider(mut self, local: ProviderId) -> Self {
        self.local_provider = Some(local);
        self
    }
}

// ---------- 两阶段求解接口（吸收点 K2/K3） ----------

/// Filter 阶段输出：候选 + 拒绝原因（`None` = 通过硬谓词）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilteredCandidate {
    /// 候选 Provider 事实记录。
    pub record: ProviderRecord,
    /// 拒绝原因；`None` 表示可行（进入 Score 阶段）。
    pub reason: Option<RejectReason>,
}

/// Score 阶段输出：可行候选 + 归一化分数 + 打分明细。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScoredCandidate {
    /// 可行候选 Provider 事实记录。
    pub record: ProviderRecord,
    /// 总分（`rtt` 分量 + `locality` 分量之和；区间 [0, SCORE_SCALE + LOCALITY_BONUS]）。
    pub score: u32,
    /// 打分明细（D3 加厚）；各项 `contribution` 之和恒等于 `score`。
    pub breakdown: Vec<ScoreComponent>,
}

/// `LinkMeasurement` → 领域侧快照（`MeasurementSnapshot`）的显式转换。
///
/// 放在 planner 而非 `From` impl：orphan 规则禁止为两个外部类型实现外部 trait；
/// 普通函数同样表达"决策时拷贝"的快照语义。
fn snapshot_measurement(m: &LinkMeasurement) -> MeasurementSnapshot {
    MeasurementSnapshot {
        rtt_ms: m.rtt_ms,
        loss_permyriad: m.loss_permyriad,
        jitter_ms: m.jitter_ms,
        throughput_kbps: m.throughput_kbps,
        confidence_percent: m.confidence_percent,
    }
}

/// Planner 的决策产物：领域中立 Plan + 决策轨迹。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Planned {
    /// 领域中立 Plan（领域信息封装在类型化 extension 中）。
    pub plan: Plan,
    /// 可解释决策轨迹。
    pub trace: DecisionTrace,
}

fn constraint_value<'a>(constraints: &'a [Constraint], key: &str) -> Option<&'a str> {
    constraints
        .iter()
        .find(|c| c.key == key)
        .map(|c| c.value.as_str())
}

// ---------- Connectivity Feasibility 门控（v9 §8.1） ----------

/// 基于 [`PlanningSnapshot`] 中 Connectivity Evaluation 的可行性门控。
///
/// 对每个携带评估的候选：若评估显示无任何可行路径（direct/punch/relay/
/// existing 全不可行），返回 `(provider, RejectReason::NoFeasibleConnectivityPath)`。
/// 无评估的候选不受影响（未知 ≠ 不可行，保持旧行为）。
///
/// 纯函数，确定性；`plan_from_snapshot` 在 Filter 之后应用此门控（硬谓词语义，
/// 但不覆盖已有的拒绝原因——先被拒绝者保留原原因）。
#[must_use]
pub fn connectivity_gate(snapshot: &PlanningSnapshot) -> Vec<(ProviderId, RejectReason)> {
    snapshot
        .connectivity
        .iter()
        .filter(|(_, ev)| !ev.has_feasible_path())
        .map(|(id, _)| (id.clone(), RejectReason::NoFeasibleConnectivityPath))
        .collect()
}

/// 阶段一：硬谓词过滤（K2）。
///
/// 短路语义：返回的每个候选要么带结构化拒绝原因，要么可行（`reason: None`）；
/// 被拒候选**绝不进入评分阶段**。
///
/// 判定的候选级硬约束（其余约束键不产生拒绝原因）：
/// - `capability`：候选必须广告该能力，否则 `MissingCapability`；
/// - `placement`：候选的 `ProviderRecord.placement` 必须等于约束值，否则
///   `ExcludedByConstraint{key:"placement"}`（P1-16：该变体此前无生产者，
///   非能力类硬约束被拒时静默无 reason）。
#[must_use]
pub fn filter_candidates(
    constraints: &[Constraint],
    candidates: &[ProviderRecord],
) -> Vec<FilteredCandidate> {
    let required = constraint_value(constraints, CONSTRAINT_CAPABILITY);
    let required_placement = constraint_value(constraints, CONSTRAINT_PLACEMENT);
    candidates
        .iter()
        .map(|c| {
            let reason = if !c.present {
                Some(RejectReason::NotPresent)
            } else if let Some(cap) = required {
                if c.has_capability(cap) {
                    placement_reason(c, required_placement)
                } else {
                    Some(RejectReason::MissingCapability {
                        required: cap.to_string(),
                    })
                }
            } else {
                // 无能力约束：不按能力过滤（保持 present 者可行）。
                placement_reason(c, required_placement)
            };
            FilteredCandidate {
                record: c.clone(),
                reason,
            }
        })
        .collect()
}

/// placement 硬约束判定（`None` = 无该约束或满足）。
fn placement_reason(c: &ProviderRecord, required: Option<&str>) -> Option<RejectReason> {
    let want = required?;
    if c.placement == want {
        None
    } else {
        Some(RejectReason::ExcludedByConstraint {
            key: CONSTRAINT_PLACEMENT.to_string(),
            value: want.to_string(),
        })
    }
}

/// 对候选集合做**一次**测量采样，返回 `ProviderId → LinkMeasurement` 快照。
///
/// D3（P1-4）：Measurement 快照必须与打分所用的值同源，否则
/// "trace 快照 ≠ 打分值"，`plan explain` 不可重放。真实测量源（主动探测）
/// 下重复调用还意味着成本三倍。
#[must_use]
fn measure_all<F>(candidates: &[ProviderRecord], measure: &F) -> HashMap<ProviderId, LinkMeasurement>
where
    F: Fn(&ProviderId) -> Option<LinkMeasurement>,
{
    candidates
        .iter()
        .filter_map(|c| measure(&c.id).map(|m| (c.id.clone(), m)))
        .collect()
}

/// 阶段二：软评分（K2/K3）+ 本地优先（白皮书原则 #4）。
///
/// 只对通过 Filter 的候选评分。打分明细（`ScoredCandidate.breakdown`）：
/// - `rtt`：RTT 越小分越高，归一化到 [0, 10_000]；未知 RTT 得 0 分
///   （显式"未知"不是最优）；
/// - `locality`：`local` 命中的本地 Provider 得 `LOCALITY_BONUS` 加成，
///   其余为 0（加项恒记录，explain 可见"为什么没加成"）。
///
/// 总分 = 各分量之和（单测锁定该不变量）。排序：已知 RTT 恒先于未知
/// （D3：未知严格排最后，与分数/本地偏好无关）→ 总分降序 → ProviderId
/// 字典序（确定性 tie-break）。`max_rtt == 0`（全未知）时保持旧行为。
///
/// D3/P1-4：`measurements` 是**一次性采样**的测量快照（由 `measure_all` 产出）；
/// 打分与 DecisionTrace 共用同一份值。
#[must_use]
pub fn score_candidates_with(
    feasible: &[ProviderRecord],
    measurements: &HashMap<ProviderId, LinkMeasurement>,
    local: Option<&ProviderId>,
) -> Vec<ScoredCandidate> {
    let max_rtt = feasible
        .iter()
        .filter_map(|c| measurements.get(&c.id).and_then(|m| m.rtt_ms))
        .max()
        .unwrap_or(0);

    let mut scored: Vec<(ScoredCandidate, bool)> = feasible
        .iter()
        .map(|c| {
            let measurement = measurements.get(&c.id);
            let rtt = measurement
                .and_then(|m| m.rtt_ms)
                .filter(|_| max_rtt > 0);
            let rtt_term = rtt.map_or(0, |ms| {
                let scaled = (max_rtt.saturating_sub(ms)) as u64 * SCORE_SCALE / max_rtt as u64;
                scaled as u32
            });
            let is_local = local == Some(&c.id);
            let locality_term = if is_local { LOCALITY_BONUS } else { 0 };
            let breakdown = vec![
                ScoreComponent {
                    name: SCORE_TERM_RTT,
                    contribution: rtt_term,
                    detail: Some(match rtt {
                        Some(ms) => format!("rtt_ms={ms}"),
                        None => "unknown_rtt".to_string(),
                    }),
                },
                ScoreComponent {
                    name: SCORE_TERM_LOCALITY,
                    contribution: locality_term,
                    detail: is_local.then(|| "local".to_string()),
                },
            ];
            (
                ScoredCandidate {
                    record: c.clone(),
                    score: rtt_term + locality_term,
                    breakdown,
                },
                rtt.is_some(),
            )
        })
        .collect();

    // 降序：最高分最优；但已知 RTT 恒先于未知（D3）；同类内同分按 id 字典序
    //（确定性 tie-break）。max_rtt == 0 时全为未知，退化为旧行为。
    scored.sort_by(|a, b| {
        b.1.cmp(&a.1)
            .then_with(|| b.0.score.cmp(&a.0.score))
            .then_with(|| a.0.record.id.0.cmp(&b.0.record.id.0))
    });
    scored.into_iter().map(|(s, _)| s).collect()
}

/// [`score_candidates_with`] 的便捷封装：内部对 `feasible` 每候选只测一次。
#[must_use]
pub fn score_candidates<F>(
    feasible: &[ProviderRecord],
    measure: F,
    local: Option<&ProviderId>,
) -> Vec<ScoredCandidate>
where
    F: Fn(&ProviderId) -> Option<LinkMeasurement>,
{
    let measurements = measure_all(feasible, &measure);
    score_candidates_with(feasible, &measurements, local)
}

/// 在约束下对候选做确定性规划（K2→K3→选优组装）。
///
/// `measure` 把 Provider 映射到其事实测量（未观测返回 None）。选择规则：
/// 1. 无候选 → `NoProvider`；
/// 2. 没有任何候选满足能力约束 → `ConstraintUnsatisfied`；
/// 3. Filter 拒绝者不进 Score；可行者按"RTT 归一化分 + 本地优先加成"选优，
///    未知 RTT 排最后（不把"未观测"当作"最优"），同分按 ProviderId 字典序，
///    从而保证确定性与可重放；
/// 4. DecisionTrace 为每个候选记录：拒绝原因 / Connectivity Evaluation /
///    Measurement 快照 / 分数与打分明细（D3 加厚）。
///
/// v9 §7 红线：领域 Estimator 不能生成第二套系统级 Plan。此处组装的 extension
/// 只读取调用方传入的输入（含 `ComputePlanExtension` 的代价估计字段，
/// 如 `queue_delay_ms` / `execution_estimate_ms`——那是 Planner 的**输入**，
/// 不是另一套 Plan）；Planner 永不调用 Estimator，也永不把估计结果单独成 Plan。
pub fn plan_from_snapshot<F>(
    resource: &ResourceId,
    snapshot: &PlanningSnapshot,
    intent: &Intent,
    measure: F,
) -> Result<Planned, NexusError>
where
    F: Fn(&ProviderId) -> Option<LinkMeasurement>,
{
    if snapshot.candidates.is_empty() {
        return Err(NexusError::NoProvider {
            resource: resource.clone(),
            intent: intent.profile.clone(),
        });
    }

    // 能力约束必须显式存在，避免在没有约束时静默放宽选择。
    let Some(required_capability) = constraint_value(&snapshot.constraints, CONSTRAINT_CAPABILITY)
    else {
        return Err(NexusError::ConstraintUnsatisfied {
            constraint: Constraint {
                key: CONSTRAINT_CAPABILITY.into(),
                value: "<missing>".into(),
            },
        });
    };
    let required_constraint = Constraint {
        key: CONSTRAINT_CAPABILITY.into(),
        value: required_capability.to_string(),
    };
    let exit_dns = constraint_value(&snapshot.constraints, "exit-dns");

    // 阶段一：Filter（硬谓词短路）。
    let gated = connectivity_gate(snapshot);
    let filtered: Vec<FilteredCandidate> =
        filter_candidates(&snapshot.constraints, &snapshot.candidates)
            .into_iter()
            .map(|mut f| {
                // Connectivity 门控：仅对尚未被拒绝的候选生效（先被拒绝者保留原原因）。
                if f.reason.is_none() && gated.iter().any(|(id, _)| *id == f.record.id) {
                    f.reason = Some(RejectReason::NoFeasibleConnectivityPath);
                }
                f
            })
            .collect();
    let evaluation_of = |id: &ProviderId| {
        snapshot
            .connectivity
            .iter()
            .find(|(pid, _)| pid == id)
            .map(|(_, ev)| ev.clone())
    };
    let feasible: Vec<ProviderRecord> = filtered
        .iter()
        .filter(|f| f.reason.is_none())
        .map(|f| f.record.clone())
        .collect();

    if feasible.is_empty() {
        return Err(NexusError::ConstraintUnsatisfied {
            constraint: required_constraint,
        });
    }

    // 阶段二：Score（归一化加权 + 本地优先）+ 确定性选优。
    //
    // D3/P1-4：`measure` 对每个候选**只调用一次**，结果缓存进 `measurements`：
    // 打分（`max_rtt` 归一化、每候选 rtt 项）与下面 DecisionTrace 的
    // Measurement 快照共用同一份值——trace 快照恒等于打分所用值（explain 可重放），
    // 且真实测量源的成本不再三倍。
    let measurements = measure_all(&snapshot.candidates, &measure);
    let scored = score_candidates_with(
        &feasible,
        &measurements,
        snapshot.local_provider.as_ref(),
    );
    let score_of = |id: &ProviderId| scored.iter().find(|s| s.record.id == *id);
    let considered: Vec<ConsideredCandidate> = filtered
        .iter()
        .map(|f| {
            let scored_hit = score_of(&f.record.id);
            ConsideredCandidate {
                provider: f.record.id.clone(),
                rejected_reason: f.reason.clone(),
                connectivity: evaluation_of(&f.record.id),
                // D3 加厚：决策时的测量快照（`None` = 决策时无测量，显式未知）。
                measurement: measurements.get(&f.record.id).map(snapshot_measurement),
                score: scored_hit.map(|s| s.score),
                score_breakdown: scored_hit.map(|s| s.breakdown.clone()),
            }
        })
        .collect();
    let chosen = &scored[0].record;

    // v9 §7 红线（见本函数文档）：extension 只承载调用方传入的领域输入；
    // 即使未来此处处理 `ComputePlanExtension`，其代价估计字段也只是 Planner
    // 输入——Planner 不调用 Estimator，不产生第二套系统级 Plan。
    let plan = Plan {
        resource_id: resource.clone(),
        provider_id: chosen.id.clone(),
        placement: chosen.placement.clone(),
        path: vec![chosen.locator.clone()],
        execution_strategy: "direct".into(),
        extension: Some(PlanExtension::Network(NetworkPlanExtension {
            version: NetworkPlanExtension::VERSION,
            exit_dns_binding: exit_dns.map(str::to_string),
            preferred_transport: None,
        })),
    };

    Ok(Planned {
        plan,
        trace: DecisionTrace {
            considered,
            selected: chosen.id.clone(),
        },
    })
}

/// 便捷入口：内部构造一次规划快照后求解（语义同 `plan_from_snapshot`）。
pub fn plan<F>(
    resource: &ResourceId,
    intent: &Intent,
    constraints: &[Constraint],
    candidates: &[ProviderRecord],
    measure: F,
) -> Result<Planned, NexusError>
where
    F: Fn(&ProviderId) -> Option<LinkMeasurement>,
{
    let snapshot = PlanningSnapshot::new(candidates.to_vec(), constraints.to_vec());
    plan_from_snapshot(resource, &snapshot, intent, measure)
}

// ---------- plan explain 双模式（D3 / mimo 独立规划建议） ----------

/// `plan explain` 双模式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExplainMode {
    /// 读历史真实记录：`<session-id>` 命中 Session 内嵌的 PlanSnapshot。
    History,
    /// 按当前快照重算：输出必须显式标注"估算非承诺"。
    Estimate,
}

impl ExplainMode {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::History => "history",
            Self::Estimate => "estimate",
        }
    }

    /// 模式对应的承诺声明（`plan explain` 输出的必填字段）。
    #[must_use]
    pub fn commitment_note(&self) -> &'static str {
        match self {
            Self::History => "历史真实记录：该 Session 建连时内嵌的 PlanSnapshot，非事后重算。",
            Self::Estimate => {
                "估算非承诺：按当前快照重算的预览，不是对未来的承诺；实际建连时的决策以 Session 内嵌快照为准。"
            }
        }
    }
}

/// SessionId 的形状约定：`nexus use` 产生的会话 id 使用 `sess-` 前缀
///（见 nexus-session 用例与 n2 场景 `sess-n2-e4-1`）。
/// `plan explain` 据此外形区分双模式；不以此前缀开头的参数一律按资源名处理。
pub const SESSION_ID_PREFIX: &str = "sess-";

/// 把 `plan explain <arg>` 分类为双模式之一（纯函数，可单测）。
#[must_use]
pub fn classify_explain_arg(arg: &str) -> ExplainMode {
    if arg.starts_with(SESSION_ID_PREFIX) {
        ExplainMode::History
    } else {
        ExplainMode::Estimate
    }
}

/// PlanSnapshot 历史查询（`plan explain <session-id>` 的读口）。
///
/// P0-3 只定义读契约：Session 持久化在 P0-4 落地（SessionManager 负责写
/// `SessionRecord.plan_snapshot`）。调用方在查无记录时返回结构化
/// `SESSION_HISTORY_NOT_FOUND`，**不得**回退为"按资源重算"（那会伪造历史）。
pub trait PlanHistory {
    /// 按 SessionId 查历史 PlanSnapshot；无记录返回 `None`。
    fn lookup(&self, session: &SessionId) -> Option<PlanSnapshot>;
}

/// 一次 explain 输出的领域数据（渲染层再转 JSON/文本）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExplainedPlan {
    pub mode: ExplainMode,
    pub snapshot: PlanSnapshot,
}

impl ExplainedPlan {
    /// 历史模式：快照必须来自 `PlanHistory`（真实记录）。
    #[must_use]
    pub fn history(snapshot: PlanSnapshot) -> Self {
        Self {
            mode: ExplainMode::History,
            snapshot,
        }
    }

    /// 估算模式：快照为当前重算（调用方必须向用户展示 `commitment_note`）。
    #[must_use]
    pub fn estimate(snapshot: PlanSnapshot) -> Self {
        Self {
            mode: ExplainMode::Estimate,
            snapshot,
        }
    }

    /// 该模式的承诺声明（`plan explain` 输出的必填字段）。
    #[must_use]
    pub fn commitment_note(&self) -> &'static str {
        self.mode.commitment_note()
    }

    /// PlanId（内容确定性派生；历史/估算模式通用）。
    #[must_use]
    pub fn plan_id(&self) -> &PlanId {
        &self.snapshot.plan_id
    }

    /// 引用 `plan_id_of`，保证"同一决策同一 Id"在 explain 路径同样成立。
    #[must_use]
    pub fn verify_plan_id(&self) -> bool {
        plan_id_of(&self.snapshot.plan, &self.snapshot.decision_trace) == self.snapshot.plan_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resource() -> ResourceId {
        ResourceId("internet-access".into())
    }
    fn intent() -> Intent {
        Intent {
            profile: "Balanced".into(),
        }
    }
    fn constraints() -> Vec<Constraint> {
        vec![
            Constraint {
                key: "capability".into(),
                value: "internet-access".into(),
            },
            Constraint {
                key: "exit-dns".into(),
                value: "bound".into(),
            },
        ]
    }
    fn candidate(id: &str, placement: &str, caps: &[&str], present: bool) -> ProviderRecord {
        ProviderRecord {
            id: ProviderId(id.into()),
            resource: resource(),
            placement: placement.into(),
            locator: format!("loc-{id}"),
            capabilities: caps.iter().map(|s| (*s).to_string()).collect(),
            present,
        }
    }
    fn rtt(id: &ProviderId, ms: u32) -> Option<LinkMeasurement> {
        match id.0.as_str() {
            "fast" | "slow" | "mid" | "a" | "b" | "zeta" | "alpha" => Some(LinkMeasurement {
                rtt_ms: Some(ms),
                ..Default::default()
            }),
            _ => None,
        }
    }

    // ---- plan() 行为保持（回归） ----

    #[test]
    fn no_candidates_is_no_provider() {
        let err = plan(&resource(), &intent(), &constraints(), &[], |_| None).unwrap_err();
        assert!(matches!(err, NexusError::NoProvider { .. }));
    }

    #[test]
    fn missing_capability_is_constraint_unsatisfied() {
        let cands = vec![candidate("p1", "east", &["other"], true)];
        let err = plan(&resource(), &intent(), &constraints(), &cands, |_| None).unwrap_err();
        assert!(matches!(err, NexusError::ConstraintUnsatisfied { .. }));
    }

    #[test]
    fn selects_lowest_rtt_and_records_trace() {
        let cands = vec![
            candidate("slow", "west", &["internet-access"], true),
            candidate("fast", "east", &["internet-access"], true),
        ];
        let out = plan(&resource(), &intent(), &constraints(), &cands, |p| {
            rtt(p, if p.0 == "fast" { 20 } else { 80 })
        })
        .unwrap();
        assert_eq!(out.plan.provider_id, ProviderId("fast".into()));
        assert_eq!(out.plan.placement, "east");
        assert_eq!(out.plan.path, vec!["loc-fast".to_string()]);
        assert_eq!(out.trace.selected, ProviderId("fast".into()));
        assert_eq!(out.trace.considered.len(), 2);
        match &out.plan.extension {
            Some(PlanExtension::Network(n)) => {
                assert_eq!(n.version, 1);
                assert_eq!(n.exit_dns_binding.as_deref(), Some("bound"));
            }
            other => panic!("expected network extension, got {other:?}"),
        }
    }

    #[test]
    fn unknown_rtt_sorts_last_and_tie_breaks_by_id() {
        let cands = vec![
            candidate("zeta", "z", &["internet-access"], true),
            candidate("alpha", "a", &["internet-access"], true),
        ];
        // 两者都无测量：按 id 字典序选 alpha。
        let out = plan(&resource(), &intent(), &constraints(), &cands, |_| None).unwrap();
        assert_eq!(out.plan.provider_id, ProviderId("alpha".into()));
    }

    #[test]
    fn absent_candidate_rejected_but_other_chosen() {
        let cands = vec![
            candidate("down", "d", &["internet-access"], false),
            candidate("up", "u", &["internet-access"], true),
        ];
        let out = plan(&resource(), &intent(), &constraints(), &cands, |_| None).unwrap();
        assert_eq!(out.plan.provider_id, ProviderId("up".into()));
        let down = out
            .trace
            .considered
            .iter()
            .find(|c| c.provider.0 == "down")
            .unwrap();
        assert!(down.rejected_reason.is_some());
    }

    #[test]
    fn planning_is_deterministic() {
        let cands = vec![
            candidate("a", "a", &["internet-access"], true),
            candidate("b", "b", &["internet-access"], true),
        ];
        let first = plan(&resource(), &intent(), &constraints(), &cands, |p| {
            rtt(p, 30)
        })
        .unwrap();
        let second = plan(&resource(), &intent(), &constraints(), &cands, |p| {
            rtt(p, 30)
        })
        .unwrap();
        assert_eq!(first, second);
    }

    // ---- Filter / Score 两阶段（K2/K3/K4） ----

    #[test]
    fn filter_rejects_not_present_and_missing_capability() {
        let cands = vec![
            candidate("down", "d", &["internet-access"], false),
            candidate("nocap", "n", &["other"], true),
            candidate("ok", "o", &["internet-access"], true),
        ];
        let filtered = filter_candidates(&constraints(), &cands);
        assert_eq!(filtered.len(), 3);
        assert_eq!(filtered[0].reason, Some(RejectReason::NotPresent));
        assert_eq!(
            filtered[1].reason,
            Some(RejectReason::MissingCapability {
                required: "internet-access".into()
            })
        );
        assert_eq!(filtered[2].reason, None);
    }

    #[test]
    fn rejected_candidates_never_enter_score() {
        let cands = vec![
            candidate("down", "d", &["internet-access"], false),
            candidate("fast", "e", &["internet-access"], true),
        ];
        let filtered = filter_candidates(&constraints(), &cands);
        let feasible: Vec<ProviderRecord> = filtered
            .iter()
            .filter(|f| f.reason.is_none())
            .map(|f| f.record.clone())
            .collect();
        assert_eq!(feasible.len(), 1);
        assert_eq!(feasible[0].id, ProviderId("fast".into()));
    }

    // ---- P1-16：非能力类硬约束的结构化拒绝原因 ----

    #[test]
    fn placement_constraint_produces_excluded_by_constraint() {
        // `RejectReason::ExcludedByConstraint` 此前无生产者；placement 是
        // planner 能直接判定的候选级硬约束，违反即结构化拒绝。
        let mut local = candidate("loc", "l", &["internet-access"], true);
        local.placement = "local".into();
        let mut remote = candidate("rem", "r", &["internet-access"], true);
        remote.placement = "region-a".into();
        let cs = vec![
            Constraint {
                key: CONSTRAINT_CAPABILITY.into(),
                value: "internet-access".into(),
            },
            Constraint {
                key: CONSTRAINT_PLACEMENT.into(),
                value: "local".into(),
            },
        ];
        let filtered = filter_candidates(&cs, &[local, remote]);
        assert_eq!(filtered[0].reason, None);
        assert_eq!(
            filtered[1].reason,
            Some(RejectReason::ExcludedByConstraint {
                key: "placement".into(),
                value: "local".into(),
            })
        );
        // label 稳定可读（D3 契约）。
        assert_eq!(
            filtered[1]
                .reason
                .as_ref()
                .map(RejectReason::label)
                .unwrap(),
            "excluded_by_constraint"
        );
    }

    #[test]
    fn unknown_constraint_keys_never_reject_candidates() {
        // `exit-dns` / `authorization` 不是候选级谓词：不得据此静默拒候选。
        let cands = vec![candidate("ok", "o", &["internet-access"], true)];
        let cs = vec![
            Constraint {
                key: CONSTRAINT_CAPABILITY.into(),
                value: "internet-access".into(),
            },
            Constraint {
                key: "exit-dns".into(),
                value: "1.1.1.1".into(),
            },
            Constraint {
                key: "authorization".into(),
                value: "explicit".into(),
            },
        ];
        let filtered = filter_candidates(&cs, &cands);
        assert_eq!(filtered[0].reason, None);
    }

    #[test]
    fn not_present_wins_over_excluded_by_constraint() {
        // 拒绝原因顺序稳定：Presence 先判（`NotPresent` 优先）。
        let mut down = candidate("down", "d", &["internet-access"], false);
        down.placement = "region-b".into();
        let cs = vec![
            Constraint {
                key: CONSTRAINT_CAPABILITY.into(),
                value: "internet-access".into(),
            },
            Constraint {
                key: CONSTRAINT_PLACEMENT.into(),
                value: "local".into(),
            },
        ];
        assert_eq!(
            filter_candidates(&cs, &[down])[0].reason,
            Some(RejectReason::NotPresent)
        );
    }

    // ---- P1-4：测量只采样一次，trace 快照恒等于打分所用值 ----

    #[test]
    fn measure_is_sampled_once_per_candidate() {
        use std::cell::RefCell;
        let calls: RefCell<Vec<String>> = RefCell::new(Vec::new());
        let cands = vec![
            candidate("a", "a", &["internet-access"], true),
            candidate("b", "b", &["internet-access"], true),
            candidate("down", "d", &["internet-access"], false),
        ];
        let out = plan(&resource(), &intent(), &constraints(), &cands, |p| {
            calls.borrow_mut().push(p.0.clone());
            rtt(p, 10)
        })
        .unwrap();
        let sampled = calls.borrow();
        // 每候选恰好一次（旧实现对可行候选调用三次）。
        assert_eq!(sampled.len(), cands.len(), "calls: {sampled:?}");
        for c in &cands {
            assert_eq!(
                sampled.iter().filter(|p| **p == c.id.0).count(),
                1,
                "candidate {} measured more than once",
                c.id.0
            );
        }
        // 打分与 trace 快照同源：快照里的 rtt 与 breakdown 里记录的 rtt 一致。
        for considered in &out.trace.considered {
            let Some(m) = considered.measurement.as_ref() else {
                // 被拒候选（NotPresent）不进评分，无 breakdown；断言其快照缺省。
                assert!(considered.rejected_reason.is_some());
                continue;
            };
            let from_breakdown = considered
                .score_breakdown
                .as_ref()
                .and_then(|b| b.iter().find(|c| c.name == SCORE_TERM_RTT))
                .map(|c| c.detail.clone().unwrap_or_default())
                .unwrap_or_default();
            assert_eq!(from_breakdown, format!("rtt_ms={}", m.rtt_ms.unwrap()));
        }
    }

    #[test]
    fn trace_measurement_matches_score_source_under_fluctuating_source() {
        // 抖动测量源：trace 快照必须等于打分所用的那次值，而不是后续再采样的值。
        use std::cell::Cell;
        let n = Cell::new(0u32);
        let cands = vec![
            candidate("a", "a", &["internet-access"], true),
            candidate("b", "b", &["internet-access"], true),
        ];
        let out = plan(&resource(), &intent(), &constraints(), &cands, |p| {
            n.set(n.get() + 1);
            // 每次采样都返回不同的 rtt。
            (p.0 == "a").then(|| LinkMeasurement {
                rtt_ms: Some(10 + n.get() * 7),
                ..Default::default()
            })
        })
        .unwrap();
        assert_eq!(n.get(), 2, "one sample per candidate");
        let a = out
            .trace
            .considered
            .iter()
            .find(|c| c.provider.0 == "a")
            .unwrap();
        // 第一次采样 = 17ms（10 + 1*7），且与 breakdown 记录一致。
        assert_eq!(a.measurement.as_ref().unwrap().rtt_ms, Some(17));
        assert_eq!(
            a.score_breakdown.as_ref().unwrap()[0].detail.as_deref(),
            Some("rtt_ms=17")
        );
    }

    #[test]
    fn score_is_normalized_and_lower_rtt_wins() {
        let feasible = vec![
            candidate("slow", "w", &["internet-access"], true),
            candidate("fast", "e", &["internet-access"], true),
        ];
        let scored = score_candidates(
            &feasible,
            |p| rtt(p, if p.0 == "fast" { 20 } else { 80 }),
            None,
        );
        assert_eq!(scored.len(), 2);
        assert_eq!(scored[0].record.id, ProviderId("fast".into()));
        // 归一化：fast = (80-20)*10000/80 = 7500；slow = 0。
        assert_eq!(scored[0].score, 7_500);
        assert_eq!(scored[1].score, 0);
    }

    #[test]
    fn unknown_rtt_scores_zero_and_sorts_last() {
        let feasible = vec![
            candidate("measured", "m", &["internet-access"], true),
            candidate("unknown", "u", &["internet-access"], true),
        ];
        let scored = score_candidates(
            &feasible,
            |p| match p.0.as_str() {
                "measured" => Some(LinkMeasurement {
                    rtt_ms: Some(50),
                    ..Default::default()
                }),
                _ => None,
            },
            None,
        );
        assert_eq!(scored[0].record.id, ProviderId("measured".into()));
        assert_eq!(scored[1].record.id, ProviderId("unknown".into()));
        assert_eq!(scored[1].score, 0);
    }

    #[test]
    fn unknown_rtt_strictly_sorts_last() {
        // D3 (2026-10-03)：未知 RTT 必须严格排在所有已测候选之后，
        // 与 ProviderId 字典序无关（旧代码按同分 tie-break，id 更小的
        // 未知候选会排到已测候选前面）。
        let feasible = vec![
            candidate("aaa-unknown", "a", &["internet-access"], true),
            candidate("zzz-measured", "z", &["internet-access"], true),
        ];
        let scored = score_candidates(
            &feasible,
            |p| match p.0.as_str() {
                "zzz-measured" => Some(LinkMeasurement {
                    rtt_ms: Some(50),
                    ..Default::default()
                }),
                _ => None,
            },
            None,
        );
        assert_eq!(
            scored[0].record.id,
            ProviderId("zzz-measured".into()),
            "measured candidate must sort strictly before unknown, regardless of id order"
        );
        assert_eq!(scored[1].record.id, ProviderId("aaa-unknown".into()));
    }

    #[test]
    fn same_score_tie_breaks_by_id() {
        let feasible = vec![
            candidate("zeta", "z", &["internet-access"], true),
            candidate("alpha", "a", &["internet-access"], true),
        ];
        let scored = score_candidates(&feasible, |_| None, None);
        assert_eq!(scored[0].record.id, ProviderId("alpha".into()));
        assert_eq!(scored[1].record.id, ProviderId("zeta".into()));
        assert_eq!(scored[0].score, scored[1].score);
    }

    #[test]
    fn snapshot_preserves_consistent_view() {
        let cands = vec![candidate("fast", "e", &["internet-access"], true)];
        let snapshot = PlanningSnapshot::new(cands, constraints());
        let out = plan_from_snapshot(&resource(), &snapshot, &intent(), |p| rtt(p, 20)).unwrap();
        assert_eq!(out.plan.provider_id, ProviderId("fast".into()));
    }

    // 注：`RejectReason::label()` 稳定性单测已随类型迁移到 nexus-domain
    //（`reject_reason_labels_are_stable`），此处不重复。

    // ---- Connectivity Feasibility 门控（v9 §8.1） ----

    fn evaluation(feasible: bool) -> ConnectivityEvaluation {
        ConnectivityEvaluation {
            version: ConnectivityEvaluation::VERSION,
            direct_likely: feasible,
            punching_likely: false,
            relay_available: false,
            existing_link_available: false,
            estimated_setup_cost_ms: feasible.then_some(100),
            confidence_percent: 100,
        }
    }

    #[test]
    fn connectivity_gate_rejects_only_infeasible() {
        let cands = vec![
            candidate("good", "g", &["internet-access"], true),
            candidate("bad", "b", &["internet-access"], true),
            candidate("unevaluated", "u", &["internet-access"], true),
        ];
        let snapshot = PlanningSnapshot::new(cands, constraints()).with_connectivity(vec![
            (ProviderId("good".into()), evaluation(true)),
            (ProviderId("bad".into()), evaluation(false)),
        ]);
        let gate = connectivity_gate(&snapshot);
        assert_eq!(gate.len(), 1);
        assert_eq!(gate[0].0, ProviderId("bad".into()));
        assert_eq!(gate[0].1, RejectReason::NoFeasibleConnectivityPath);
    }

    #[test]
    fn plan_rejects_infeasible_candidate_but_keeps_feasible() {
        let cands = vec![
            candidate("bad", "b", &["internet-access"], true),
            candidate("good", "g", &["internet-access"], true),
        ];
        let snapshot = PlanningSnapshot::new(cands, constraints()).with_connectivity(vec![
            (ProviderId("good".into()), evaluation(true)),
            (ProviderId("bad".into()), evaluation(false)),
        ]);
        let out = plan_from_snapshot(&resource(), &snapshot, &intent(), |_| None).unwrap();
        // 可行者被选中；不可行者在 trace 中带精确拒绝原因 + 评估。
        assert_eq!(out.plan.provider_id, ProviderId("good".into()));
        let bad = out
            .trace
            .considered
            .iter()
            .find(|c| c.provider.0 == "bad")
            .unwrap();
        assert_eq!(
            bad.rejected_reason,
            Some(RejectReason::NoFeasibleConnectivityPath)
        );
        assert_eq!(bad.connectivity, Some(evaluation(false)));
        let good = out
            .trace
            .considered
            .iter()
            .find(|c| c.provider.0 == "good")
            .unwrap();
        assert_eq!(good.rejected_reason, None);
        assert_eq!(good.connectivity, Some(evaluation(true)));
    }

    #[test]
    fn all_infeasible_is_constraint_unsatisfied() {
        let cands = vec![candidate("bad", "b", &["internet-access"], true)];
        let snapshot = PlanningSnapshot::new(cands, constraints())
            .with_connectivity(vec![(ProviderId("bad".into()), evaluation(false))]);
        let err = plan_from_snapshot(&resource(), &snapshot, &intent(), |_| None).unwrap_err();
        assert!(matches!(err, NexusError::ConstraintUnsatisfied { .. }));
    }

    #[test]
    fn no_evaluation_keeps_legacy_behavior() {
        // 无评估 → 门控不生效，旧行为（未知 RTT 按 id 字典序）。
        let cands = vec![
            candidate("zeta", "z", &["internet-access"], true),
            candidate("alpha", "a", &["internet-access"], true),
        ];
        let snapshot = PlanningSnapshot::new(cands, constraints());
        assert!(connectivity_gate(&snapshot).is_empty());
        let out = plan_from_snapshot(&resource(), &snapshot, &intent(), |_| None).unwrap();
        assert_eq!(out.plan.provider_id, ProviderId("alpha".into()));
        assert!(
            out.trace
                .considered
                .iter()
                .all(|c| c.connectivity.is_none())
        );
    }

    #[test]
    fn gate_does_not_override_existing_rejection() {
        // 已因 NotPresent 被拒的候选，即使评估也无可行路径，保留原拒绝原因。
        let cands = vec![
            candidate("down", "d", &["internet-access"], false),
            candidate("up", "u", &["internet-access"], true),
        ];
        let snapshot = PlanningSnapshot::new(cands, constraints()).with_connectivity(vec![
            (ProviderId("down".into()), evaluation(false)),
            (ProviderId("up".into()), evaluation(true)),
        ]);
        let out = plan_from_snapshot(&resource(), &snapshot, &intent(), |_| None).unwrap();
        assert_eq!(out.plan.provider_id, ProviderId("up".into()));
        let down = out
            .trace
            .considered
            .iter()
            .find(|c| c.provider.0 == "down")
            .unwrap();
        assert_eq!(down.rejected_reason, Some(RejectReason::NotPresent));
    }

    // ---- D3 加厚：score breakdown / Measurement 快照 / 本地优先 ----

    #[test]
    fn score_breakdown_sums_to_total() {
        // 不变量：各分量 contribution 之和恒等于总分。
        let feasible = vec![
            candidate("fast", "e", &["internet-access"], true),
            candidate("slow", "w", &["internet-access"], true),
        ];
        let scored = score_candidates(
            &feasible,
            |p| rtt(p, if p.0 == "fast" { 20 } else { 80 }),
            None,
        );
        for s in &scored {
            let sum: u32 = s.breakdown.iter().map(|t| t.contribution).sum();
            assert_eq!(sum, s.score, "breakdown must sum to score");
            assert_eq!(s.breakdown.len(), 2);
            assert_eq!(s.breakdown[0].name, SCORE_TERM_RTT);
            assert_eq!(s.breakdown[1].name, SCORE_TERM_LOCALITY);
        }
        // 无本地偏好时 locality 分量为 0（显式记录"没加成"）。
        assert!(scored.iter().all(|s| s.breakdown[1].contribution == 0));
        assert_eq!(scored[0].score, 7_500);
    }

    #[test]
    fn locality_bonus_prefers_local_provider() {
        // 白皮书原则 #4：同等条件下本地优先；加成记入 breakdown。
        let feasible = vec![
            candidate("remote", "r", &["internet-access"], true),
            candidate("local", "l", &["internet-access"], true),
        ];
        let local = ProviderId("local".into());
        let scored = score_candidates(&feasible, |p| rtt(p, 40), Some(&local));
        // 同 RTT：本地 0 + 1000 > 远端 0。
        assert_eq!(scored[0].record.id, local);
        assert_eq!(scored[0].score, LOCALITY_BONUS);
        assert_eq!(scored[0].breakdown[1].contribution, LOCALITY_BONUS);
        assert_eq!(scored[0].breakdown[1].detail.as_deref(), Some("local"));
        assert_eq!(scored[1].score, 0);
    }

    #[test]
    fn unknown_rtt_still_sorts_after_measured_despite_locality() {
        // D3 排序键优先级：已知/未知 > 分数（含本地加成）> id。
        let feasible = vec![
            candidate("local-unknown", "l", &["internet-access"], true),
            candidate("remote-measured", "r", &["internet-access"], true),
        ];
        let local = ProviderId("local-unknown".into());
        let scored = score_candidates(
            &feasible,
            |p| match p.0.as_str() {
                "remote-measured" => Some(LinkMeasurement {
                    rtt_ms: Some(50),
                    ..Default::default()
                }),
                _ => None,
            },
            Some(&local),
        );
        assert_eq!(scored[0].record.id, ProviderId("remote-measured".into()));
        assert_eq!(scored[1].record.id, local);
    }

    #[test]
    fn trace_carries_measurement_snapshot_and_breakdown() {
        // D3 加厚：trace 记录决策时的测量快照 + 分数 + 打分明细；
        // 被拒绝者三者皆为 None（从未进入评分）。
        let cands = vec![
            candidate("down", "d", &["internet-access"], false),
            candidate("up", "u", &["internet-access"], true),
        ];
        let snapshot = PlanningSnapshot::new(cands, constraints());
        let out = plan_from_snapshot(&resource(), &snapshot, &intent(), |p| {
            if p.0 == "up" {
                Some(LinkMeasurement {
                    rtt_ms: Some(25),
                    loss_permyriad: Some(7),
                    confidence_percent: 90,
                    ..Default::default()
                })
            } else {
                None
            }
        })
        .unwrap();
        let up = out
            .trace
            .considered
            .iter()
            .find(|c| c.provider.0 == "up")
            .unwrap();
        assert_eq!(up.rejected_reason, None);
        let m = up.measurement.as_ref().expect("measurement snapshot");
        assert_eq!(m.rtt_ms, Some(25));
        assert_eq!(m.loss_permyriad, Some(7));
        assert_eq!(m.confidence_percent, 90);
        let score = up.score.expect("score");
        let bd = up.score_breakdown.as_ref().expect("breakdown");
        assert_eq!(bd.iter().map(|t| t.contribution).sum::<u32>(), score);

        let down = out
            .trace
            .considered
            .iter()
            .find(|c| c.provider.0 == "down")
            .unwrap();
        assert_eq!(down.rejected_reason, Some(RejectReason::NotPresent));
        assert_eq!(down.score, None);
        assert_eq!(down.score_breakdown, None);
        // 被拒绝者的测量仍记录（决策时可见的事实），分数为空。
        assert_eq!(down.measurement, None);
    }

    #[test]
    fn plan_selects_local_when_snapshot_marks_it() {
        // PlanningSnapshot.local_provider → plan_from_snapshot 应用本地优先。
        let cands = vec![
            candidate("remote", "r", &["internet-access"], true),
            candidate("local", "l", &["internet-access"], true),
        ];
        let snapshot = PlanningSnapshot::new(cands, constraints())
            .with_local_provider(ProviderId("local".into()));
        let out = plan_from_snapshot(&resource(), &snapshot, &intent(), |_| None).unwrap();
        assert_eq!(out.plan.provider_id, ProviderId("local".into()));
        assert_eq!(out.trace.selected, ProviderId("local".into()));
    }

    // ---- plan explain 双模式 ----

    #[test]
    fn classify_explain_arg_routes_by_shape() {
        assert_eq!(classify_explain_arg("sess-n2-e4-1"), ExplainMode::History);
        assert_eq!(classify_explain_arg("sess-abc"), ExplainMode::History);
        assert_eq!(classify_explain_arg("dev-svc"), ExplainMode::Estimate);
        assert_eq!(
            classify_explain_arg("internet-access"),
            ExplainMode::Estimate
        );
        assert_eq!(classify_explain_arg(""), ExplainMode::Estimate);
    }

    #[test]
    fn explain_modes_carry_commitment_notes() {
        assert_eq!(ExplainMode::History.as_str(), "history");
        assert_eq!(ExplainMode::Estimate.as_str(), "estimate");
        assert!(
            ExplainMode::History
                .commitment_note()
                .contains("历史真实记录")
        );
        // 估算模式必须显式标注"估算非承诺"（mimo 双模式要求）。
        assert!(
            ExplainMode::Estimate
                .commitment_note()
                .contains("估算非承诺")
        );
    }

    struct MemHistory {
        snapshots: Vec<(SessionId, PlanSnapshot)>,
    }
    impl PlanHistory for MemHistory {
        fn lookup(&self, session: &SessionId) -> Option<PlanSnapshot> {
            self.snapshots
                .iter()
                .find(|(id, _)| id == session)
                .map(|(_, s)| s.clone())
        }
    }

    #[test]
    fn explain_history_reads_recorded_snapshot_not_recompute() {
        // `<session-id>` 读历史真实记录：返回当时内嵌的快照（含 PlanId）。
        let cands = vec![candidate("up", "u", &["internet-access"], true)];
        let snapshot = PlanningSnapshot::new(cands, constraints());
        let planned = plan_from_snapshot(&resource(), &snapshot, &intent(), |_| None).unwrap();
        let recorded = PlanSnapshot::from_planned(planned.plan.clone(), planned.trace.clone());
        let history = MemHistory {
            snapshots: vec![(SessionId("sess-n2-e4-1".into()), recorded.clone())],
        };
        assert_eq!(classify_explain_arg("sess-n2-e4-1"), ExplainMode::History);
        let found = history
            .lookup(&SessionId("sess-n2-e4-1".into()))
            .expect("history hit");
        let explained = ExplainedPlan::history(found);
        assert_eq!(explained.snapshot, recorded);
        assert!(explained.verify_plan_id());
        assert!(explained.commitment_note().contains("历史真实记录"));
        // 查无记录 → None（调用方报 SESSION_HISTORY_NOT_FOUND，不得回退重算）。
        assert!(history.lookup(&SessionId("sess-missing".into())).is_none());
    }

    #[test]
    fn explain_estimate_labels_non_commitment() {
        // `<resource>` 显式标注"估算非承诺"。
        let cands = vec![candidate("up", "u", &["internet-access"], true)];
        let snapshot = PlanningSnapshot::new(cands, constraints());
        let planned = plan_from_snapshot(&resource(), &snapshot, &intent(), |_| None).unwrap();
        let explained =
            ExplainedPlan::estimate(PlanSnapshot::from_planned(planned.plan, planned.trace));
        assert_eq!(explained.mode, ExplainMode::Estimate);
        assert!(explained.commitment_note().contains("估算非承诺"));
        assert!(explained.verify_plan_id());
    }
}
