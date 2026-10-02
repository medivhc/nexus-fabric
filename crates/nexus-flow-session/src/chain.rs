//! 首包链：FlowContext → Policy → Core Planner（同步纯函数部分，D5）。
//!
//! 建连（Establish Connectivity）是异步的，由 [`crate::SessionManager`] 在后台线程执行；
//! 本模块只跑同步可重放部分，可在包线程直接调用，永不阻塞。

use nexus_domain::{FlowContext, ProviderId};
use nexus_measurement::LinkMeasurement;
use nexus_planner::{Planned, PlanningSnapshot, plan_from_snapshot};
use nexus_policy::{PolicyEngine, PolicyTraceEntry};

/// 规划快照构造器。
pub type SnapshotBuilder = Box<dyn Fn(&FlowContext) -> PlanningSnapshot + Send + Sync>;
/// 事实测量函数。
pub type MeasureFn = Box<dyn Fn(&ProviderId) -> Option<LinkMeasurement> + Send + Sync>;

/// 首包链依赖（可注入；测试用静态快照，生产接 Registry）。
pub struct ChainDeps {
    /// 策略引擎。
    pub policy: PolicyEngine,
    /// 规划快照构造器（生产：Registry 一致视图；测试：静态）。
    pub build_snapshot: SnapshotBuilder,
    /// 事实测量（Measurement != Score；仅客观 RTT）。
    pub measure: MeasureFn,
}

/// 首包链产物。
#[derive(Debug)]
pub struct ChainOutcome {
    /// 规划结果（含 DecisionTrace）。
    pub planned: Planned,
    /// Policy 决策轨迹（E4 `policy_planner_consulted` 的证明）。
    pub policy_trace: Vec<PolicyTraceEntry>,
}

/// 首包链错误（结构化，可映射为 Drop/RST 决策）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainError {
    /// Policy 终态拒绝。
    PolicyRejected { reason: String },
    /// Planner 无可用 Provider / 约束不满足。
    PlanFailed { reason: String },
}

impl std::fmt::Display for ChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PolicyRejected { reason } => write!(f, "policy rejected: {reason}"),
            Self::PlanFailed { reason } => write!(f, "plan failed: {reason}"),
        }
    }
}

/// 跑首包链（同步，纯函数，可重放）。
///
/// # Errors
///
/// - `PolicyRejected`：策略终态拒绝 → dataplane 应 Drop（TCP 可选 RST）。
/// - `PlanFailed`：无可用 Provider → dataplane 应 Drop（TCP 发 RST，不静默黑洞）。
pub fn run_first_packet_chain(
    flow: &FlowContext,
    deps: &ChainDeps,
) -> Result<ChainOutcome, ChainError> {
    // 1) Policy：动作化有序链求值（首匹配即终止）——Flow -> Intent + Constraint。
    let policy_result = deps.policy.evaluate(flow);
    if let Some(reason) = policy_result.rejected {
        return Err(ChainError::PolicyRejected { reason });
    }

    // 2) Core Planner：唯一系统级规划，快照一致视图。
    let snapshot = (deps.build_snapshot)(flow);
    let planned = plan_from_snapshot(
        &flow.resource,
        &snapshot,
        &policy_result.decision.intent,
        |p| (deps.measure)(p),
    )
    .map_err(|e| ChainError::PlanFailed {
        reason: e.to_string(),
    })?;

    Ok(ChainOutcome {
        planned,
        policy_trace: policy_result.trace,
    })
}

#[cfg(test)]
mod tests {
    use nexus_domain::{Constraint, FlowOrigin, Intent, ProviderId, ResourceId};
    use nexus_planner::PlanningSnapshot;
    use nexus_registry::{ProviderRecord, Registry};

    use super::*;

    fn test_flow() -> FlowContext {
        FlowContext {
            origin: FlowOrigin::VirtualPacketInterface,
            resource: ResourceId("internet-access".into()),
            destination: "93.184.216.34:443".into(),
            profile: "Balanced".into(),
        }
    }

    fn test_deps() -> ChainDeps {
        ChainDeps {
            policy: PolicyEngine::default_network(),
            build_snapshot: Box::new(|flow: &FlowContext| {
                let mut registry = Registry::new();
                registry.register(ProviderRecord {
                    id: ProviderId("provider-edge-a".into()),
                    resource: flow.resource.clone(),
                    placement: "local-edge".into(),
                    locator: "edge-a.exit".into(),
                    capabilities: vec!["internet-access".into()],
                    present: true,
                });
                let candidates = registry.candidates(&flow.resource);
                // Policy 决策的 constraints 直接透传（测试用默认 Policy 的产出）。
                let probe = PolicyEngine::default_network().evaluate(flow);
                PlanningSnapshot::new(candidates, probe.decision.constraints)
            }),
            measure: Box::new(|_| None),
        }
    }

    #[test]
    fn chain_runs_policy_then_planner() {
        let flow = test_flow();
        let deps = test_deps();
        let out = run_first_packet_chain(&flow, &deps).expect("chain ok");
        assert!(!out.policy_trace.is_empty(), "policy trace 非空");
        assert!(
            !out.planned.trace.considered.is_empty() || !out.planned.plan.provider_id.0.is_empty(),
            "planner 有决策"
        );
    }

    #[test]
    fn chain_is_deterministic() {
        let flow = test_flow();
        let deps = test_deps();
        let a = run_first_packet_chain(&flow, &deps).expect("ok");
        let b = run_first_packet_chain(&flow, &deps).expect("ok");
        assert_eq!(
            a.planned.plan.provider_id, b.planned.plan.provider_id,
            "相同输入相同规划（可重放）"
        );
    }

    #[test]
    fn chain_fails_when_no_provider() {
        let flow = test_flow();
        let deps = ChainDeps {
            policy: PolicyEngine::default_network(),
            build_snapshot: Box::new(|flow: &FlowContext| {
                let probe = PolicyEngine::default_network().evaluate(flow);
                PlanningSnapshot::new(Vec::new(), probe.decision.constraints)
            }),
            measure: Box::new(|_| None),
        };
        let err = run_first_packet_chain(&flow, &deps).expect_err("无候选应失败");
        assert!(matches!(err, ChainError::PlanFailed { .. }), "{err:?}");
    }

    #[test]
    fn unused_imports_guard() {
        // 编译期断言测试依赖存在。
        let _ = Constraint {
            key: "k".into(),
            value: "v".into(),
        };
        let _ = Intent {
            profile: "p".into(),
        };
    }
}
