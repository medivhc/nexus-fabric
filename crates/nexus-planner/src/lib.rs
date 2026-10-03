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
//! - **Score 归一化加权**（K3）：只对可行候选评分，归一化到 [0, 10_000] 整数；
//! - **规划快照**（K5）：一次规划使用一致的 candidates + constraints 视图；
//! - **结构化拒绝原因**（K4）：DecisionTrace 记录结构化枚举，而非自由文本。
//!
//! 本 crate 是 Portable Core：纯计算、零 I/O，可编译到 WASI。
//! 详细边界见同目录 `MODULE.md`。

#![forbid(unsafe_code)]

use nexus_domain::{
    ConnectivityEvaluation, Constraint, Intent, NetworkPlanExtension, NexusError, Plan,
    PlanExtension, ProviderId, ResourceId,
};
use nexus_measurement::LinkMeasurement;
use nexus_registry::ProviderRecord;

/// 能力约束键（与 nexus-policy 的 CONSTRAINT_CAPABILITY 同值；planner 不依赖 policy crate）。
const CONSTRAINT_CAPABILITY: &str = "capability";

/// 归一化评分满分（万分比整数，避免浮点不确定性）。
const SCORE_SCALE: u64 = 10_000;

// ---------- 结构化拒绝原因（吸收点 K4） ----------

/// 结构化拒绝原因：候选被 Filter 拒绝的机器可读原因。
///
/// 取代自由文本 `String`，保证 DecisionTrace 可被 explain / 自动化消费。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RejectReason {
    /// Provider 未广告 Presence（不可达/不在线）。
    NotPresent,
    /// Provider 缺少规划所需能力。
    MissingCapability {
        /// 缺失的能力名。
        required: String,
    },
    /// 被某条硬约束排除。
    ExcludedByConstraint {
        /// 约束键。
        key: String,
        /// 约束值。
        value: String,
    },
    /// 无可行连通路径（Connectivity Evaluation：direct/punch/relay/existing 全不可行）。
    NoFeasibleConnectivityPath,
}

impl RejectReason {
    /// 稳定的机器可读标签（供 DecisionTrace 序列化 / explain 使用）。
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::NotPresent => "not_present",
            Self::MissingCapability { .. } => "missing_capability",
            Self::ExcludedByConstraint { .. } => "excluded_by_constraint",
            Self::NoFeasibleConnectivityPath => "no_feasible_connectivity_path",
        }
    }
}

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
}

impl PlanningSnapshot {
    /// 构造规划快照。
    #[must_use]
    pub fn new(candidates: Vec<ProviderRecord>, constraints: Vec<Constraint>) -> Self {
        Self {
            candidates,
            constraints,
            connectivity: Vec::new(),
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

/// Score 阶段输出：可行候选 + 归一化分数（[0, 10_000]，越高越优）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScoredCandidate {
    /// 可行候选 Provider 事实记录。
    pub record: ProviderRecord,
    /// 归一化加权分（确定性，整数）。
    pub score: u32,
}

/// 单个候选的评估记录（DecisionTrace 节点）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsideredCandidate {
    /// 候选 Provider。
    pub provider: ProviderId,
    /// 被拒绝原因；`None` 表示可行。
    pub rejected_reason: Option<RejectReason>,
    /// 该候选的 Connectivity Evaluation（快照携带时；`None` = 未评估）。
    /// 让 DecisionTrace 可见 evaluation 对决策的贡献（v9 §8.1）。
    pub connectivity: Option<ConnectivityEvaluation>,
}

/// 决策轨迹：记录全部候选、拒绝原因与最终选择，支持 explain / replay。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionTrace {
    /// 按输入顺序记录的候选评估。
    pub considered: Vec<ConsideredCandidate>,
    /// 最终选中的 Provider。
    pub selected: ProviderId,
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
#[must_use]
pub fn filter_candidates(
    constraints: &[Constraint],
    candidates: &[ProviderRecord],
) -> Vec<FilteredCandidate> {
    let required = constraint_value(constraints, CONSTRAINT_CAPABILITY);
    candidates
        .iter()
        .map(|c| {
            let reason = if !c.present {
                Some(RejectReason::NotPresent)
            } else if let Some(cap) = required {
                if c.has_capability(cap) {
                    None
                } else {
                    Some(RejectReason::MissingCapability {
                        required: cap.to_string(),
                    })
                }
            } else {
                // 无能力约束：不按能力过滤（保持 present 者可行）。
                None
            };
            FilteredCandidate {
                record: c.clone(),
                reason,
            }
        })
        .collect()
}

/// 阶段二：软评分（K2/K3）。
///
/// 只对通过 Filter 的候选评分；RTT 越小分越高，归一化到 [0, 10_000]。
/// 未知 RTT 得 0 分（显式"未知"不是最优）；同分按 ProviderId 字典序稳定排序。
///
/// D3（2026-10-03）：未知 RTT **严格**排在所有已测候选之后（排序键显式区分
/// 已知/未知，与分数无关）。`max_rtt == 0`（全未知）时保持旧行为。
#[must_use]
pub fn score_candidates<F>(feasible: &[ProviderRecord], measure: F) -> Vec<ScoredCandidate>
where
    F: Fn(&ProviderId) -> Option<LinkMeasurement>,
{
    let max_rtt = feasible
        .iter()
        .filter_map(|c| measure(&c.id).and_then(|m| m.rtt_ms))
        .max()
        .unwrap_or(0);

    let mut scored: Vec<(ScoredCandidate, bool)> = feasible
        .iter()
        .map(|c| {
            let rtt = measure(&c.id)
                .and_then(|m| m.rtt_ms)
                .filter(|_| max_rtt > 0);
            let score = rtt.map_or(0, |ms| {
                let scaled = (max_rtt.saturating_sub(ms)) as u64 * SCORE_SCALE / max_rtt as u64;
                scaled as u32
            });
            (
                ScoredCandidate {
                    record: c.clone(),
                    score,
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

/// 在约束下对候选做确定性规划（K2→K3→选优组装）。
///
/// `measure` 把 Provider 映射到其事实测量（未观测返回 None）。选择规则：
/// 1. 无候选 → `NoProvider`；
/// 2. 没有任何候选满足能力约束 → `ConstraintUnsatisfied`；
/// 3. Filter 拒绝者不进 Score；可行者按归一化分选优，未知 RTT 排最后
///    （不把"未观测"当作"最优"），同分按 ProviderId 字典序，从而保证确定性与可重放。
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
    let considered: Vec<ConsideredCandidate> = filtered
        .iter()
        .map(|f| ConsideredCandidate {
            provider: f.record.id.clone(),
            rejected_reason: f.reason.clone(),
            connectivity: evaluation_of(&f.record.id),
        })
        .collect();
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

    // 阶段二：Score（归一化加权）+ 确定性选优。
    let scored = score_candidates(&feasible, measure);
    let chosen = &scored[0].record;

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

    #[test]
    fn score_is_normalized_and_lower_rtt_wins() {
        let feasible = vec![
            candidate("slow", "w", &["internet-access"], true),
            candidate("fast", "e", &["internet-access"], true),
        ];
        let scored = score_candidates(&feasible, |p| rtt(p, if p.0 == "fast" { 20 } else { 80 }));
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
        let scored = score_candidates(&feasible, |p| match p.0.as_str() {
            "measured" => Some(LinkMeasurement {
                rtt_ms: Some(50),
                ..Default::default()
            }),
            _ => None,
        });
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
        let scored = score_candidates(&feasible, |p| match p.0.as_str() {
            "zzz-measured" => Some(LinkMeasurement {
                rtt_ms: Some(50),
                ..Default::default()
            }),
            _ => None,
        });
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
        let scored = score_candidates(&feasible, |_| None);
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

    #[test]
    fn reject_reason_labels_are_stable() {
        assert_eq!(RejectReason::NotPresent.label(), "not_present");
        assert_eq!(
            RejectReason::MissingCapability {
                required: "x".into()
            }
            .label(),
            "missing_capability"
        );
        assert_eq!(
            RejectReason::ExcludedByConstraint {
                key: "k".into(),
                value: "v".into()
            }
            .label(),
            "excluded_by_constraint"
        );
        assert_eq!(
            RejectReason::NoFeasibleConnectivityPath.label(),
            "no_feasible_connectivity_path"
        );
    }

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
}
