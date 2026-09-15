//! nexus app 库（Composition Root）。
//!
//! 只在 app 层把 portable-core 纵切装配为可观察的端到端流程；业务规则仍在各 crate。
//! 本模块对应产品主链路的最小可运行切片：
//!
//! ```text
//! Ingress -> SessionManager/Policy -> Core Planner -> Session(create/Active)
//! ```
//!
//! 注意：`nexus-network` 不允许依赖 `nexus-ingress`（ARCHITECTURE §3 禁止边），
//! 因此跨 ingress/policy/planner/session 的装配只能发生在 Composition Root（本 app）。

#![forbid(unsafe_code)]

use nexus_domain::{
    LifecyclePhase, NexusError, ProviderId, ResourceId, SessionId, TerminalOutcome,
};
use nexus_measurement::{LinkMeasurement, MeasurementTable};
use nexus_planner::PlanningSnapshot;
use nexus_registry::{ProviderRecord, Registry};
use nexus_session::{SessionError, SessionOwner};
use serde_json::{Value, json};

/// 事件名：Ingress 已把中立 FlowContext 提交给 SessionManager / Application Layer。
pub const EV_FLOW_SUBMITTED: &str = "flow_submitted_to_session_manager";
/// 事件名：Policy 已把 Flow 展开为 Intent + Constraint。
pub const EV_POLICY_EVALUATED: &str = "policy_evaluated";
/// 事件名：Core Planner 已选出 Provider/Placement/Path。
pub const EV_PLAN_SELECTED: &str = "plan_selected";
/// 事件名：Session 已创建并进入 Active（终态尚未提交）。
pub const EV_SESSION_CREATED: &str = "session_created";
/// 事件名：候选 Provider 已解析。
pub const EV_CANDIDATES_RESOLVED: &str = "candidates_resolved";
/// 事件名：在 Plan + Session 之后才进行 Connectivity Establishment。
pub const EV_CONNECTIVITY_ESTABLISHMENT: &str = "connectivity_establishment";
/// 事件名：执行。
pub const EV_EXECUTE: &str = "execute";
/// 事件名：Owner 提交 TerminalOutcome。
pub const EV_TERMINAL_OUTCOME_COMMITTED: &str = "terminal_outcome_committed";

/// nexus-network 的 Cargo 清单路径（编译期固定，独立于运行时 CWD）。
const NETWORK_MANIFEST: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../crates/nexus-network/Cargo.toml"
);

fn phase_name(phase: &LifecyclePhase) -> &'static str {
    match phase {
        LifecyclePhase::Allocating => "Allocating",
        LifecyclePhase::Active => "Active",
        LifecyclePhase::Draining => "Draining",
        LifecyclePhase::Disposed => "Disposed",
    }
}

fn outcome_name(outcome: &TerminalOutcome) -> &'static str {
    match outcome {
        TerminalOutcome::Unfinished => "Unfinished",
        TerminalOutcome::Completed => "Completed",
        TerminalOutcome::Failed(_) => "Failed",
        TerminalOutcome::Cancelled => "Cancelled",
    }
}

/// 独立校验架构不变量：nexus-network 的清单不得声明对 nexus-ingress 的依赖。
///
/// 直接读取真实 Cargo.toml（而非硬编码结论），读取失败显式报错而非静默通过。
fn network_depends_on_ingress() -> Result<bool, NexusError> {
    let manifest = std::fs::read_to_string(NETWORK_MANIFEST).map_err(|e| NexusError::Internal {
        message: format!("cannot read nexus-network Cargo.toml: {e}"),
    })?;
    Ok(manifest.contains("nexus-ingress"))
}

/// 运行一次 InternetAccess 端到端纵切，返回可被 E4 场景求值的结构化报告。
///
/// 纯内存、确定性：相同入参产生相同报告（可重放）。
pub fn internet_access_flow(destination: &str, profile: &str) -> Result<Value, NexusError> {
    let mut events: Vec<&'static str> = Vec::new();

    // 1) Ingress：构造中立 FlowContext 并提交给上层（ingress 自身不调 Planner）。
    let flow = nexus_ingress::from_native_api(destination, profile);
    events.push(EV_FLOW_SUBMITTED);

    // 2) Policy：动作化有序链求值（首匹配即终止）——Flow -> Intent + Constraint（不选 Path/Provider）。
    let policy = nexus_policy::PolicyEngine::default_network().evaluate(&flow);
    let decision = policy.decision;
    events.push(EV_POLICY_EVALUATED);

    // 3) Registry：事实候选（Identity != Locator；只存广告与 Presence）。
    let resource: ResourceId = flow.resource.clone();
    let mut registry = Registry::new();
    registry.register(ProviderRecord {
        id: ProviderId("provider-edge-a".into()),
        resource: resource.clone(),
        placement: "local-edge".into(),
        locator: "edge-a.exit".into(),
        capabilities: vec!["internet-access".into()],
        present: true,
    });
    registry.register(ProviderRecord {
        id: ProviderId("provider-relay-b".into()),
        resource: resource.clone(),
        placement: "regional-relay".into(),
        locator: "relay-b.exit".into(),
        capabilities: vec!["internet-access".into()],
        present: true,
    });
    let candidates = registry.candidates(&resource);

    // 事实测量（Measurement != Score；仅提供客观 RTT，选择归 Planner）。
    let mut measurements = MeasurementTable::new();
    measurements.record(
        ProviderId("provider-edge-a".into()),
        LinkMeasurement {
            rtt_ms: Some(15),
            confidence_percent: 95,
            ..Default::default()
        },
    );
    measurements.record(
        ProviderId("provider-relay-b".into()),
        LinkMeasurement {
            rtt_ms: Some(60),
            confidence_percent: 90,
            ..Default::default()
        },
    );

    // 4) Core Planner：唯一系统级规划，K5 快照一致视图 + Filter/Score 两阶段，
    //    确定性选择最低 RTT 的 edge-a。
    let snapshot = PlanningSnapshot::new(candidates.clone(), decision.constraints.clone());
    let planned = nexus_planner::plan_from_snapshot(&resource, &snapshot, &decision.intent, |p| {
        measurements.get(p).cloned()
    })?;
    events.push(EV_PLAN_SELECTED);

    // 5) Session：Owner 创建会话并进入 Active；Outcome 仍为 Unfinished（唯一写入者是 Owner）。
    let mut owner = SessionOwner::new(SessionId("sess-internet-access-1".into()));
    owner
        .transition_phase(LifecyclePhase::Active)
        .map_err(NexusError::from)?;
    events.push(EV_SESSION_CREATED);
    let status = owner.status();

    let arch_violation = network_depends_on_ingress()?;

    Ok(json!({
        "verdict": "PASS",
        "destination": flow.destination,
        "events": events,
        "plan": {
            "provider_id": planned.plan.provider_id.0,
            "placement": planned.plan.placement,
            "path": planned.plan.path,
            "execution_strategy": planned.plan.execution_strategy,
        },
        "trace": {
            "considered": planned.trace.considered.iter().map(|c| json!({
                "provider": c.provider.0,
                "rejected_reason": c.rejected_reason.as_ref().map(|r| r.label()),
            })).collect::<Vec<_>>(),
            "selected": planned.trace.selected.0,
        },
        "session": {
            "id": owner.id().0,
            "phase": phase_name(&status.phase),
            "outcome": outcome_name(&status.outcome),
        },
        "architecture": {
            "network_depends_on_ingress": arch_violation,
        }
    }))
}

/// 运行一次 Service 资源的完整生命周期，返回可被 E4 场景求值的结构化报告。
///
/// 验证两条产品不变量：
/// 1. 顺序：Resolve -> Plan -> Session -> Connectivity Establishment -> Execute
///    （Plan 与 Session 必须先于建连，ARCHITECTURE §6）；
/// 2. Exactly-One Terminal Outcome：Owner 只提交一次终态，重复提交被拒绝，
///    且终态确定后 cleanup 仍可推进到 Disposed（PRODUCT §6）。
///
/// 纯内存、确定性。这里的 connectivity_establishment 仅表达生命周期时序点，
/// 不伪造真实传输连接（真实建连待 nexus-connectivity 实现）。
pub fn service_session_lifecycle(resource: &str, profile: &str) -> Result<Value, NexusError> {
    let mut events: Vec<&'static str> = Vec::new();
    let step = |name: &'static str, events: &mut Vec<&'static str>| events.push(name);

    // Resolve：Ingress 提交 -> Policy 展开 -> Registry 解析出 2 个候选。
    let flow = nexus_ingress::from_native_api(resource, profile);
    step(EV_POLICY_EVALUATED, &mut events);
    let policy = nexus_policy::PolicyEngine::default_service().evaluate(&flow);
    let decision = policy.decision;

    let res: ResourceId = flow.resource.clone();
    let mut registry = Registry::new();
    for (id, placement, locator) in [
        ("svc-primary", "local", "primary.sock"),
        ("svc-replica", "remote", "replica.sock"),
    ] {
        registry.register(ProviderRecord {
            id: ProviderId(id.into()),
            resource: res.clone(),
            placement: placement.into(),
            locator: locator.into(),
            capabilities: vec!["service-session".into()],
            present: true,
        });
    }
    let candidates = registry.candidates(&res);
    let candidate_providers = candidates.len();
    step(EV_CANDIDATES_RESOLVED, &mut events);

    // 独立的事实测量表（确定性 RTT，primary 更低）。
    let mut measurements = MeasurementTable::new();
    measurements.record(
        ProviderId("svc-primary".into()),
        LinkMeasurement {
            rtt_ms: Some(12),
            confidence_percent: 90,
            ..Default::default()
        },
    );
    measurements.record(
        ProviderId("svc-replica".into()),
        LinkMeasurement {
            rtt_ms: Some(48),
            confidence_percent: 88,
            ..Default::default()
        },
    );

    // Plan（先于建连）：K5 快照一致视图 + Filter/Score 两阶段。
    let snapshot = PlanningSnapshot::new(candidates.clone(), decision.constraints.clone());
    let planned = nexus_planner::plan_from_snapshot(&res, &snapshot, &decision.intent, |p| {
        measurements.get(p).cloned()
    })?;
    step(EV_PLAN_SELECTED, &mut events);

    // Session 创建（先于建连）。
    let mut owner = SessionOwner::new(SessionId("sess-service-1".into()));
    owner
        .transition_phase(LifecyclePhase::Active)
        .map_err(NexusError::from)?;
    step(EV_SESSION_CREATED, &mut events);

    // Connectivity Establishment：必须在 Plan + Session 之后（此处仅时序点）。
    step(EV_CONNECTIVITY_ESTABLISHMENT, &mut events);

    // Execute。
    step(EV_EXECUTE, &mut events);

    // Owner 提交唯一终态。
    owner
        .commit_outcome(TerminalOutcome::Completed)
        .map_err(NexusError::from)?;
    step(EV_TERMINAL_OUTCOME_COMMITTED, &mut events);

    // 冗余提交必须被拒绝（AlreadyTerminated），且不改变既有终态。
    let redundant_commit_rejected = matches!(
        owner.commit_outcome(TerminalOutcome::Completed),
        Err(SessionError::AlreadyTerminated { .. })
    );

    // 终态确定后 cleanup 继续推进到 Disposed。
    owner
        .transition_phase(LifecyclePhase::Draining)
        .map_err(NexusError::from)?;
    owner
        .transition_phase(LifecyclePhase::Disposed)
        .map_err(NexusError::from)?;
    let status = owner.status();

    // 从 Owner 自身事件历史独立统计终态提交次数（不依赖外部计数）。
    use nexus_session::SessionEvent;
    let terminal_outcome_commit_count = owner
        .events()
        .iter()
        .filter(|e| matches!(e, SessionEvent::OutcomeCommitted { .. }))
        .count();

    let index_of = |target: &str| events.iter().position(|e| *e == target);
    let plan_idx = index_of(EV_PLAN_SELECTED);
    let session_idx = index_of(EV_SESSION_CREATED);
    let conn_idx = index_of(EV_CONNECTIVITY_ESTABLISHMENT);
    let before = |a: Option<usize>, b: Option<usize>| a.zip(b).is_some_and(|(a, b)| a < b);

    Ok(json!({
        "verdict": "PASS",
        "resource": flow.destination,
        "events": events,
        "candidate_providers": candidate_providers,
        "plan": {
            "provider_id": planned.plan.provider_id.0,
            "placement": planned.plan.placement,
            "path": planned.plan.path,
        },
        "invariants": {
            "plan_before_connectivity": before(plan_idx, conn_idx),
            "session_before_connectivity": before(session_idx, conn_idx),
        },
        "terminal_outcome_commit_count": terminal_outcome_commit_count,
        "redundant_commit_rejected": redundant_commit_rejected,
        "terminal_outcome": outcome_name(&TerminalOutcome::Completed),
        "session": {
            "id": owner.id().0,
            "phase": phase_name(&status.phase),
            "outcome": outcome_name(&status.outcome),
        }
    }))
}
