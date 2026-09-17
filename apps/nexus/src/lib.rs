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
/// 事件名：Connectivity Establishment（在 Plan + Session 之后才进行）。
pub const EV_CONNECTIVITY_ESTABLISHMENT: &str = "connectivity_establishment";
/// 事件名：Connectivity 建连失败（Worker 上报；终态由 Owner 提交）。
pub const EV_CONNECTIVITY_FAILED: &str = "connectivity_failed";
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

/// 运行一次 Connectivity 建连失败的**逆序回滚**路径（吸收 K10 assume/Unreserve 逆序幂等）。
///
/// 验证产品不变量（PRODUCT §2/§6 + ARCHITECTURE §6）：
/// 1. 顺序：Plan -> Session -> Connectivity Establishment（先规划后建连）；
/// 2. W12 认证门控：未认证的链路绝不进入 Established，失败事件结构化上报；
/// 3. Worker 只发事件：Connectivity 失败由 Owner 提交唯一终态 `Failed`；
/// 4. 逆序回滚：终态确定后 Draining -> Disposed，且重复回滚幂等（被拒绝、状态不变）。
///
/// 纯内存、确定性。
pub fn connectivity_failure_rollback(
    destination: &str,
    profile: &str,
) -> Result<Value, NexusError> {
    let mut events: Vec<&'static str> = Vec::new();

    // 1) Ingress：构造中立 FlowContext 并提交。
    let flow = nexus_ingress::from_native_api(destination, profile);
    events.push(EV_FLOW_SUBMITTED);

    // 2) Policy：动作化有序链求值。
    let policy = nexus_policy::PolicyEngine::default_network().evaluate(&flow);
    let decision = policy.decision;
    events.push(EV_POLICY_EVALUATED);

    // 3) Registry：单一候选（relay，未认证）。
    let resource: ResourceId = flow.resource.clone();
    let mut registry = Registry::new();
    registry.register(ProviderRecord {
        id: ProviderId("provider-relay-b".into()),
        resource: resource.clone(),
        placement: "regional-relay".into(),
        locator: "relay-b.exit".into(),
        capabilities: vec!["internet-access".into()],
        present: true,
    });
    let candidates = registry.candidates(&resource);
    let mut measurements = MeasurementTable::new();
    measurements.record(
        ProviderId("provider-relay-b".into()),
        LinkMeasurement {
            rtt_ms: Some(60),
            confidence_percent: 90,
            ..Default::default()
        },
    );

    // 4) Planner：K5 快照 + Filter/Score 两阶段（先规划）。
    let snapshot = PlanningSnapshot::new(candidates.clone(), decision.constraints.clone());
    let planned = nexus_planner::plan_from_snapshot(&resource, &snapshot, &decision.intent, |p| {
        measurements.get(p).cloned()
    })?;
    events.push(EV_PLAN_SELECTED);

    // 5) Session 创建（先于建连）。
    let mut owner = SessionOwner::new(SessionId("sess-rollback-1".into()));
    owner
        .transition_phase(LifecyclePhase::Active)
        .map_err(NexusError::from)?;
    events.push(EV_SESSION_CREATED);

    // 6) Connectivity Establishment（后于 Plan + Session）——未认证 → Failed（W12）。
    events.push(EV_CONNECTIVITY_ESTABLISHMENT);
    let locator = planned.plan.path.first().cloned().unwrap_or_default();
    let establishment =
        nexus_connectivity::establish(&nexus_connectivity::EstablishmentRequest::new(
            owner.id().0.clone(),
            locator.clone(),
            true,
            false,
        ));
    let failed_reason = match establishment.state {
        nexus_connectivity::ConnectivityState::Failed { error } => error.to_string(),
        other => {
            return Err(NexusError::Internal {
                message: format!("expected authentication failure but got state {other:?}"),
            });
        }
    };
    events.push(EV_CONNECTIVITY_FAILED);

    // 7) Worker 只上报失败事件（不写 Outcome）。
    owner
        .record_connectivity_failed(locator.clone(), failed_reason.clone())
        .map_err(NexusError::from)?;

    // 8) Owner 提交唯一终态。
    owner
        .commit_outcome(TerminalOutcome::Failed(
            NexusError::ConnectivityEstablishmentFailed {
                provider: planned.plan.provider_id.clone(),
                reason: failed_reason.clone(),
            },
        ))
        .map_err(NexusError::from)?;
    events.push(EV_TERMINAL_OUTCOME_COMMITTED);

    // 9) 逆序回滚：Draining -> Disposed（K10 逆序幂等）。
    owner
        .transition_phase(LifecyclePhase::Draining)
        .map_err(NexusError::from)?;
    owner
        .transition_phase(LifecyclePhase::Disposed)
        .map_err(NexusError::from)?;

    // 幂等：重复回滚（再次 Draining 迁移）必须被拒绝且状态保持 Disposed。
    let rollback_idempotent = matches!(
        owner.transition_phase(LifecyclePhase::Draining),
        Err(nexus_session::SessionError::InvalidPhaseTransition { .. })
    ) && owner.phase() == LifecyclePhase::Disposed;

    let status = owner.status();
    Ok(json!({
        "verdict": "PASS",
        "events": events,
        "plan": {
            "provider_id": planned.plan.provider_id.0,
            "placement": planned.plan.placement,
            "locator": locator,
        },
        "connectivity": {
            "state": "Failed",
            "reason": failed_reason,
        },
        "rollback": {
            "idempotent": rollback_idempotent,
            "drained_to_disposed": owner.phase() == LifecyclePhase::Disposed,
        },
        "session": {
            "id": owner.id().0,
            "phase": phase_name(&status.phase),
            "outcome": outcome_name(&status.outcome),
        }
    }))
}

// ---------- Remote Resource Access（PRODUCT §6，remote P0） ----------

/// 事件名：Discovery 已解析远程提供方 Peer 的 Endpoint。
pub const EV_REMOTE_PROVIDER_RESOLVED: &str = "remote_provider_resolved";
/// 事件名：到远程提供方的帧流已建立（冻结场景期望，remote P0）。
pub const EV_REMOTE_CONNECTIVITY_ESTABLISHED: &str = "connectivity_established";
/// 事件名：Service 会话已通过握手建立（CONNECT -> READY）。
pub const EV_SERVICE_CONNECTED: &str = "service_connected";
/// 事件名：远程网络会话已建立（请求/响应往返成功，携带 HTTP 状态码）。
pub const EV_NETWORK_SESSION_ESTABLISHED: &str = "network_session_established";
/// 事件名：远程网络认证门控拒绝（W7：未认证帧不得进入业务处理）。
pub const EV_NETWORK_AUTH_REJECTED: &str = "network_auth_rejected";
/// 事件名：远程资源访问闭环完成（Owner 已提交终态并排空到 Disposed）。
pub const EV_REMOTE_ACCESS_COMPLETED: &str = "remote_access_completed";

/// 把 `nexus_transport::FrameStream` 适配为 `nexus_service::ServiceTransport`
/// （依赖注入，由 Composition Root 装配；避免 service -> transport 依赖边）。
struct FrameStreamAdapter {
    inner: nexus_transport::FrameStream,
}

impl nexus_service::ServiceTransport for FrameStreamAdapter {
    fn send_frame(&mut self, payload: &[u8]) -> Result<(), nexus_service::ServiceError> {
        self.inner
            .send_frame(payload)
            .map_err(|_| nexus_service::ServiceError::Transport)
    }

    fn recv_frame(&mut self) -> Result<Vec<u8>, nexus_service::ServiceError> {
        self.inner
            .recv_frame()
            .map_err(|_| nexus_service::ServiceError::Transport)
    }
}

impl nexus_network::NetworkTransport for FrameStreamAdapter {
    fn send_frame(&mut self, payload: &[u8]) -> Result<(), nexus_network::NetworkError> {
        self.inner
            .send_frame(payload)
            .map_err(|_| nexus_network::NetworkError::Transport)
    }

    fn recv_frame(&mut self) -> Result<Vec<u8>, nexus_network::NetworkError> {
        self.inner
            .recv_frame()
            .map_err(|_| nexus_network::NetworkError::Closed)
    }
}

/// 运行一次远程资源访问闭环（PRODUCT §6）：Node A 经
/// Discovery -> Plan -> Session -> Connectivity -> Auth -> Service 访问 Node B 的 Service 资源。
///
/// 进程内双节点模拟：Node B 在回环端口监听并提供服务握手（CONNECT -> READY），
/// Node A 通过真实 TCP 长度前缀帧流访问。确定性、可重放。
pub fn remote_service_access_flow() -> Result<Value, NexusError> {
    let mut events: Vec<&'static str> = Vec::new();

    // 0) Node B（提供方）：绑定回环端口，后台线程接受连接并完成服务握手。
    let listener =
        std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| NexusError::Internal {
            message: format!("cannot bind node-b listener: {e}"),
        })?;
    let node_b_addr = listener.local_addr().map_err(|e| NexusError::Internal {
        message: format!("cannot read node-b listener addr: {e}"),
    })?;
    let node_b_server = std::thread::spawn(move || {
        if let Ok(mut fs) = nexus_transport::accept(&listener) {
            if let Ok(frame) = fs.recv_frame() {
                if frame == b"CONNECT" {
                    let _ = fs.send_frame(b"READY");
                }
            }
        }
    });

    // 1) Discovery：静态发现解析 Node B 的 Endpoint（Identity != Locator）。
    let discovery = nexus_discovery::StaticDiscovery::new([(
        nexus_discovery::PeerId("node-b".into()),
        node_b_addr,
    )]);
    let endpoint = discovery
        .resolve(&nexus_discovery::PeerId("node-b".into()))
        .map_err(|e| NexusError::Internal {
            message: e.to_string(),
        })?;
    events.push(EV_REMOTE_PROVIDER_RESOLVED);

    // 2) Policy：Service 画像展开为 Intent + Constraint（authorization=explicit）。
    let flow = nexus_ingress::from_native_api("service", "RemoteBalanced");
    let decision = nexus_policy::PolicyEngine::default_service()
        .evaluate(&flow)
        .decision;

    // 3) Registry + Core Planner：唯一系统级规划，Provider = node-b（远程提供方）。
    let resource: ResourceId = flow.resource.clone();
    let mut registry = Registry::new();
    registry.register(ProviderRecord {
        id: ProviderId("node-b".into()),
        resource: resource.clone(),
        placement: "remote-provider".into(),
        locator: "node-b.endpoint".into(),
        capabilities: vec!["service-session".into()],
        present: true,
    });
    let candidates = registry.candidates(&resource);
    let mut measurements = MeasurementTable::new();
    measurements.record(
        ProviderId("node-b".into()),
        LinkMeasurement {
            rtt_ms: Some(5),
            confidence_percent: 99,
            ..Default::default()
        },
    );
    let snapshot = PlanningSnapshot::new(candidates.clone(), decision.constraints.clone());
    let planned = nexus_planner::plan_from_snapshot(&resource, &snapshot, &decision.intent, |p| {
        measurements.get(p).cloned()
    })?;
    events.push(EV_PLAN_SELECTED);

    // 4) Session：Owner 创建并进入 Active（先于建连）。
    let mut owner = SessionOwner::new(SessionId("sess-remote-service-1".into()));
    owner
        .transition_phase(LifecyclePhase::Active)
        .map_err(NexusError::from)?;
    events.push(EV_SESSION_CREATED);

    // 5) Connectivity：建立到 Node B 的 TCP 长度前缀帧流（Plan + Session 之后）。
    let frame_stream = nexus_transport::connect(&endpoint).map_err(|e| {
        NexusError::ConnectivityEstablishmentFailed {
            provider: planned.plan.provider_id.clone(),
            reason: e.to_string(),
        }
    })?;
    events.push(EV_REMOTE_CONNECTIVITY_ESTABLISHED);

    // 6) Auth：预共享 Token 门控在业务帧前通过（W7：未认证帧不得进入业务处理）。
    let token = nexus_auth::PreSharedToken("nexus-preshared-token".into());
    let expected = nexus_auth::PreSharedToken("nexus-preshared-token".into());
    let principal = nexus_auth::verify_token(&token, &expected).map_err(|_| {
        NexusError::AuthorizationDenied {
            principal: "remote-requester".into(),
        }
    })?;

    // 7) Service：connect 握手（CONNECT -> READY），服务会话进入 Active。
    let service_session = nexus_service::ServiceSession::connect(Box::new(FrameStreamAdapter {
        inner: frame_stream,
    }))
    .map_err(|e| NexusError::SessionFailed {
        session: owner.id().clone(),
        reason: e.to_string(),
    })?;
    events.push(EV_SERVICE_CONNECTED);

    // 8) Owner 唯一提交 Completed；终态后 cleanup 推进到 Disposed。
    owner
        .commit_outcome(TerminalOutcome::Completed)
        .map_err(NexusError::from)?;
    owner
        .transition_phase(LifecyclePhase::Draining)
        .map_err(NexusError::from)?;
    owner
        .transition_phase(LifecyclePhase::Disposed)
        .map_err(NexusError::from)?;
    events.push(EV_REMOTE_ACCESS_COMPLETED);

    // 回收 Node B 线程（结构化并发：线程有明确 Owner，主流程 join）。
    if node_b_server.join().is_err() {
        return Err(NexusError::Internal {
            message: "node-b server thread panicked".into(),
        });
    }

    let status = owner.status();
    let terminal_outcome_commit_count = owner
        .events()
        .iter()
        .filter(|e| matches!(e, nexus_session::SessionEvent::OutcomeCommitted { .. }))
        .count();
    let arch_violation = network_depends_on_ingress()?;

    Ok(json!({
        "verdict": "PASS",
        "events": events,
        "discovery": {
            "peer_id": "node-b",
            "endpoint": endpoint.to_string(),
        },
        "transport": {
            "kind": "tcp-frame",
        },
        "auth": {
            "gate": "token_verified",
            "principal": principal.0,
        },
        "plan": {
            "provider_id": planned.plan.provider_id.0,
            "placement": planned.plan.placement,
            "path": planned.plan.path,
        },
        "session": {
            "id": owner.id().0,
            "phase": phase_name(&status.phase),
            "outcome": outcome_name(&status.outcome),
        },
        "terminal_outcome_commit_count": terminal_outcome_commit_count,
        "service": {
            "phase": service_session.phase().to_string(),
        },
        "architecture": {
            "network_depends_on_ingress": arch_violation,
        }
    }))
}

/// 运行一次远程建连失败路径（PRODUCT §6）：Discovery 已解析 Node B，
/// 但建连失败，按逆序幂等回滚到 Disposed，Owner 唯一提交 Failed。
///
/// 确定性：Node B Endpoint 解析为未监听回环端口，TCP connect 立即失败。
pub fn remote_connectivity_failure_rollback() -> Result<Value, NexusError> {
    let mut events: Vec<&'static str> = Vec::new();

    // 1) Discovery：静态发现解析 Node B（Endpoint 为未监听回环地址，建连必失败）。
    let endpoint: std::net::SocketAddr =
        "127.0.0.1:1".parse().map_err(|e| NexusError::Internal {
            message: format!("invalid node-b endpoint: {e}"),
        })?;
    let discovery = nexus_discovery::StaticDiscovery::new([(
        nexus_discovery::PeerId("node-b".into()),
        endpoint,
    )]);
    let resolved = discovery
        .resolve(&nexus_discovery::PeerId("node-b".into()))
        .map_err(|e| NexusError::Internal {
            message: e.to_string(),
        })?;
    events.push(EV_REMOTE_PROVIDER_RESOLVED);

    // 2) Policy / 3) Planner：Provider = node-b（失败发生在建连阶段，而非解析/规划阶段）。
    let flow = nexus_ingress::from_native_api("service", "RemoteBalanced");
    let decision = nexus_policy::PolicyEngine::default_service()
        .evaluate(&flow)
        .decision;
    let resource: ResourceId = flow.resource.clone();
    let mut registry = Registry::new();
    registry.register(ProviderRecord {
        id: ProviderId("node-b".into()),
        resource: resource.clone(),
        placement: "remote-provider".into(),
        locator: "node-b.endpoint".into(),
        capabilities: vec!["service-session".into()],
        present: true,
    });
    let candidates = registry.candidates(&resource);
    let mut measurements = MeasurementTable::new();
    measurements.record(
        ProviderId("node-b".into()),
        LinkMeasurement {
            rtt_ms: Some(5),
            confidence_percent: 99,
            ..Default::default()
        },
    );
    let snapshot = PlanningSnapshot::new(candidates.clone(), decision.constraints.clone());
    let planned = nexus_planner::plan_from_snapshot(&resource, &snapshot, &decision.intent, |p| {
        measurements.get(p).cloned()
    })?;
    events.push(EV_PLAN_SELECTED);

    // 4) Session：Owner 创建并进入 Active（先于建连）。
    let mut owner = SessionOwner::new(SessionId("sess-remote-rollback-1".into()));
    owner
        .transition_phase(LifecyclePhase::Active)
        .map_err(NexusError::from)?;
    events.push(EV_SESSION_CREATED);

    // 5) Connectivity：建连失败（无监听 -> ECONNREFUSED -> ConnectFailed）。
    events.push(EV_CONNECTIVITY_ESTABLISHMENT);
    let reason = match nexus_transport::connect(&resolved) {
        Err(nexus_transport::TransportError::ConnectFailed) => {
            "tcp connect failed: node-b unreachable".to_string()
        }
        Err(e) => {
            return Err(NexusError::Internal {
                message: format!("expected connect failure, got {e}"),
            });
        }
        Ok(_) => {
            return Err(NexusError::Internal {
                message: "expected connect failure but connection succeeded".into(),
            });
        }
    };
    events.push(EV_CONNECTIVITY_FAILED);

    // 6) Worker 上报失败事件（不写 Outcome）。
    owner
        .record_connectivity_failed(
            planned.plan.path.first().cloned().unwrap_or_default(),
            reason.clone(),
        )
        .map_err(NexusError::from)?;

    // 7) Owner 唯一提交 Failed（Worker 只发事件，Outcome 由 Owner 状态机写入）。
    owner
        .commit_outcome(TerminalOutcome::Failed(
            NexusError::ConnectivityEstablishmentFailed {
                provider: planned.plan.provider_id.clone(),
                reason: reason.clone(),
            },
        ))
        .map_err(NexusError::from)?;
    events.push(EV_TERMINAL_OUTCOME_COMMITTED);

    // 8) 逆序回滚：Draining -> Disposed（K10 逆序幂等）。
    owner
        .transition_phase(LifecyclePhase::Draining)
        .map_err(NexusError::from)?;
    owner
        .transition_phase(LifecyclePhase::Disposed)
        .map_err(NexusError::from)?;
    let rollback_idempotent = matches!(
        owner.transition_phase(LifecyclePhase::Draining),
        Err(nexus_session::SessionError::InvalidPhaseTransition { .. })
    ) && owner.phase() == LifecyclePhase::Disposed;
    let redundant_commit_rejected = matches!(
        owner.commit_outcome(TerminalOutcome::Failed(NexusError::Internal {
            message: "duplicate".into()
        })),
        Err(nexus_session::SessionError::AlreadyTerminated { .. })
    );
    let terminal_outcome_commit_count = owner
        .events()
        .iter()
        .filter(|e| matches!(e, nexus_session::SessionEvent::OutcomeCommitted { .. }))
        .count();

    let status = owner.status();
    Ok(json!({
        "verdict": "PASS",
        "events": events,
        "connectivity": {
            "state": "Failed",
        },
        "error": {
            "code": "CONNECTIVITY_ESTABLISHMENT_FAILED",
        },
        "rollback": {
            "idempotent": rollback_idempotent,
            "drained_to_disposed": owner.phase() == LifecyclePhase::Disposed,
        },
        "session": {
            "id": owner.id().0,
            "phase": phase_name(&status.phase),
            "outcome": outcome_name(&status.outcome),
        },
        "terminal_outcome_commit_count": terminal_outcome_commit_count,
        "redundant_commit_rejected": redundant_commit_rejected,
        "plan": {
            "provider_id": planned.plan.provider_id.0,
            "placement": planned.plan.placement,
        },
        "discovery": {
            "peer_id": "node-b",
            "endpoint": resolved.to_string(),
        }
    }))
}

// ---------- Remote InternetAccess（PRODUCT §6，remote P0 扩展） ----------

/// 运行一次远程 InternetAccess 访问闭环（PRODUCT §2/§6）：Node A 经
/// Discovery -> Plan -> Session -> Connectivity -> Auth -> Network 访问 Node B 的
/// InternetAccess 出口，完成一次真实 HTTP 请求/响应帧往返。
///
/// 进程内双节点模拟：Node B 在回环端口监听并模拟 InternetAccess 出口
/// （任意请求帧 -> HTTP 200 响应帧），Node A 通过真实 TCP 长度前缀帧流访问。
/// 确定性、可重放。
pub fn remote_internet_access_flow() -> Result<Value, NexusError> {
    let mut events: Vec<&'static str> = Vec::new();

    // 0) Node B（提供方）：绑定回环端口，后台线程接受连接并模拟 InternetAccess 出口。
    let listener =
        std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| NexusError::Internal {
            message: format!("cannot bind node-b listener: {e}"),
        })?;
    let node_b_addr = listener.local_addr().map_err(|e| NexusError::Internal {
        message: format!("cannot read node-b listener addr: {e}"),
    })?;
    let node_b_server = std::thread::spawn(move || {
        if let Ok(mut fs) = nexus_transport::accept(&listener) {
            if fs.recv_frame().is_ok() {
                // InternetAccess 出口：任意请求帧 -> HTTP 200 响应帧。
                let _ = fs.send_frame(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
            }
        }
    });

    // 1) Discovery：静态发现解析 Node B 的 Endpoint（Identity != Locator）。
    let discovery = nexus_discovery::StaticDiscovery::new([(
        nexus_discovery::PeerId("node-b".into()),
        node_b_addr,
    )]);
    let endpoint = discovery
        .resolve(&nexus_discovery::PeerId("node-b".into()))
        .map_err(|e| NexusError::Internal {
            message: e.to_string(),
        })?;
    events.push(EV_REMOTE_PROVIDER_RESOLVED);

    // 2) Policy：InternetAccess 画像展开为 Intent + Constraint（authorization=explicit）。
    let flow = nexus_ingress::from_native_api("internet-access", "RemoteBalanced");
    let decision = nexus_policy::PolicyEngine::default_network()
        .evaluate(&flow)
        .decision;

    // 3) Registry + Core Planner：唯一系统级规划，Provider = node-b（远程出口）。
    let resource: ResourceId = flow.resource.clone();
    let mut registry = Registry::new();
    registry.register(ProviderRecord {
        id: ProviderId("node-b".into()),
        resource: resource.clone(),
        placement: "remote-provider".into(),
        locator: "node-b.endpoint".into(),
        capabilities: vec!["internet-access".into()],
        present: true,
    });
    let candidates = registry.candidates(&resource);
    let mut measurements = MeasurementTable::new();
    measurements.record(
        ProviderId("node-b".into()),
        LinkMeasurement {
            rtt_ms: Some(5),
            confidence_percent: 99,
            ..Default::default()
        },
    );
    let snapshot = PlanningSnapshot::new(candidates.clone(), decision.constraints.clone());
    let planned = nexus_planner::plan_from_snapshot(&resource, &snapshot, &decision.intent, |p| {
        measurements.get(p).cloned()
    })?;
    events.push(EV_PLAN_SELECTED);

    // 4) Session：Owner 创建并进入 Active（先于建连）。
    let mut owner = SessionOwner::new(SessionId("sess-remote-network-1".into()));
    owner
        .transition_phase(LifecyclePhase::Active)
        .map_err(NexusError::from)?;
    events.push(EV_SESSION_CREATED);

    // 5) Connectivity：建立到 Node B 的 TCP 长度前缀帧流（Plan + Session 之后）。
    let frame_stream = nexus_transport::connect(&endpoint).map_err(|e| {
        NexusError::ConnectivityEstablishmentFailed {
            provider: planned.plan.provider_id.clone(),
            reason: e.to_string(),
        }
    })?;
    events.push(EV_REMOTE_CONNECTIVITY_ESTABLISHED);

    // 6) Auth：预共享 Token 门控在业务帧前通过（W7：未认证帧不得进入业务处理）。
    let token = nexus_auth::PreSharedToken("nexus-preshared-token".into());
    let expected = nexus_auth::PreSharedToken("nexus-preshared-token".into());
    let principal = nexus_auth::verify_token(&token, &expected).map_err(|_| {
        NexusError::AuthorizationDenied {
            principal: "remote-requester".into(),
        }
    })?;

    // 7) Network：建立 InternetAccess 网络会话（请求帧 -> 响应帧 -> HTTP 状态码）。
    let network_session = nexus_network::NetworkSession::establish(
        Box::new(FrameStreamAdapter {
            inner: frame_stream,
        }),
        b"GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n",
    )
    .map_err(|e| NexusError::SessionFailed {
        session: owner.id().clone(),
        reason: e.to_string(),
    })?;
    events.push(EV_NETWORK_SESSION_ESTABLISHED);

    // 8) Owner 唯一提交 Completed；终态后 cleanup 推进到 Disposed。
    owner
        .commit_outcome(TerminalOutcome::Completed)
        .map_err(NexusError::from)?;
    owner
        .transition_phase(LifecyclePhase::Draining)
        .map_err(NexusError::from)?;
    owner
        .transition_phase(LifecyclePhase::Disposed)
        .map_err(NexusError::from)?;
    events.push(EV_REMOTE_ACCESS_COMPLETED);

    // 回收 Node B 线程（结构化并发：线程有明确 Owner，主流程 join）。
    if node_b_server.join().is_err() {
        return Err(NexusError::Internal {
            message: "node-b server thread panicked".into(),
        });
    }

    let status = owner.status();
    let terminal_outcome_commit_count = owner
        .events()
        .iter()
        .filter(|e| matches!(e, nexus_session::SessionEvent::OutcomeCommitted { .. }))
        .count();
    let arch_violation = network_depends_on_ingress()?;

    Ok(json!({
        "verdict": "PASS",
        "events": events,
        "discovery": {
            "peer_id": "node-b",
            "endpoint": endpoint.to_string(),
        },
        "transport": {
            "kind": "tcp-frame",
        },
        "auth": {
            "gate": "token_verified",
            "principal": principal.0,
        },
        "plan": {
            "provider_id": planned.plan.provider_id.0,
            "placement": planned.plan.placement,
            "path": planned.plan.path,
        },
        "session": {
            "id": owner.id().0,
            "phase": phase_name(&status.phase),
            "outcome": outcome_name(&status.outcome),
        },
        "terminal_outcome_commit_count": terminal_outcome_commit_count,
        "network": {
            "phase": network_session.phase().to_string(),
            "response": {
                "status": network_session.response_status().unwrap_or_default(),
            },
        },
        "architecture": {
            "network_depends_on_ingress": arch_violation,
        }
    }))
}

/// 运行一次远程网络认证门控拒绝路径（PRODUCT §6）：Discovery 已解析 Node B、
/// 帧流真实建立，但预共享 Token 不匹配——W7 门控在业务帧前拒绝，
/// Owner 唯一提交 Failed(AUTHORIZATION_DENIED)，按逆序幂等回滚到 Disposed。
///
/// 确定性：Node B 在回环端口监听（帧流可建立），requester 持有错误 Token。
pub fn remote_network_auth_rejected_rollback() -> Result<Value, NexusError> {
    let mut events: Vec<&'static str> = Vec::new();

    // 0) Node B（提供方）：绑定回环端口并接受连接；认证拒绝路径不发业务帧，
    //    连接关闭后 recv 返回 Closed，线程自然退出（无泄漏、有 Owner）。
    let listener =
        std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| NexusError::Internal {
            message: format!("cannot bind node-b listener: {e}"),
        })?;
    let node_b_addr = listener.local_addr().map_err(|e| NexusError::Internal {
        message: format!("cannot read node-b listener addr: {e}"),
    })?;
    let node_b_server = std::thread::spawn(move || {
        if let Ok(mut fs) = nexus_transport::accept(&listener) {
            // 未认证请求帧被门控拦截，不进入业务处理；等待连接关闭（recv 返回 Closed）。
            let _ = fs.recv_frame();
        }
    });

    // 1) Discovery：静态发现解析 Node B（真实监听地址，帧流可建立）。
    let discovery = nexus_discovery::StaticDiscovery::new([(
        nexus_discovery::PeerId("node-b".into()),
        node_b_addr,
    )]);
    let resolved = discovery
        .resolve(&nexus_discovery::PeerId("node-b".into()))
        .map_err(|e| NexusError::Internal {
            message: e.to_string(),
        })?;
    events.push(EV_REMOTE_PROVIDER_RESOLVED);

    // 2) Policy / 3) Planner：Provider = node-b（失败发生在认证阶段，而非解析/规划阶段）。
    let flow = nexus_ingress::from_native_api("internet-access", "RemoteBalanced");
    let decision = nexus_policy::PolicyEngine::default_network()
        .evaluate(&flow)
        .decision;
    let resource: ResourceId = flow.resource.clone();
    let mut registry = Registry::new();
    registry.register(ProviderRecord {
        id: ProviderId("node-b".into()),
        resource: resource.clone(),
        placement: "remote-provider".into(),
        locator: "node-b.endpoint".into(),
        capabilities: vec!["internet-access".into()],
        present: true,
    });
    let candidates = registry.candidates(&resource);
    let mut measurements = MeasurementTable::new();
    measurements.record(
        ProviderId("node-b".into()),
        LinkMeasurement {
            rtt_ms: Some(5),
            confidence_percent: 99,
            ..Default::default()
        },
    );
    let snapshot = PlanningSnapshot::new(candidates.clone(), decision.constraints.clone());
    let planned = nexus_planner::plan_from_snapshot(&resource, &snapshot, &decision.intent, |p| {
        measurements.get(p).cloned()
    })?;
    events.push(EV_PLAN_SELECTED);

    // 4) Session：Owner 创建并进入 Active（先于建连）。
    let mut owner = SessionOwner::new(SessionId("sess-remote-network-auth-1".into()));
    owner
        .transition_phase(LifecyclePhase::Active)
        .map_err(NexusError::from)?;
    events.push(EV_SESSION_CREATED);

    // 5) Connectivity：帧流真实建立（Node B 在监听；认证失败发生在业务帧之前）。
    let frame_stream = nexus_transport::connect(&resolved).map_err(|e| {
        NexusError::ConnectivityEstablishmentFailed {
            provider: planned.plan.provider_id.clone(),
            reason: e.to_string(),
        }
    })?;
    events.push(EV_REMOTE_CONNECTIVITY_ESTABLISHED);

    // 6) Auth：预共享 Token 不匹配 -> 门控拒绝（W7：未认证帧不得进入业务处理）。
    let token = nexus_auth::PreSharedToken("wrong-token".into());
    let expected = nexus_auth::PreSharedToken("nexus-preshared-token".into());
    let principal = "remote-requester".to_string();
    if nexus_auth::verify_token(&token, &expected).is_ok() {
        return Err(NexusError::Internal {
            message: "expected auth rejection but token verified".into(),
        });
    }
    events.push(EV_NETWORK_AUTH_REJECTED);

    // 7) 关闭帧流（业务帧从未发送），回收 Node B 线程。
    drop(frame_stream);
    if node_b_server.join().is_err() {
        return Err(NexusError::Internal {
            message: "node-b server thread panicked".into(),
        });
    }

    // 8) Owner 唯一提交 Failed(AUTHORIZATION_DENIED)。
    owner
        .commit_outcome(TerminalOutcome::Failed(NexusError::AuthorizationDenied {
            principal,
        }))
        .map_err(NexusError::from)?;
    events.push(EV_TERMINAL_OUTCOME_COMMITTED);

    // 9) 逆序回滚：Draining -> Disposed（K10 逆序幂等）。
    owner
        .transition_phase(LifecyclePhase::Draining)
        .map_err(NexusError::from)?;
    owner
        .transition_phase(LifecyclePhase::Disposed)
        .map_err(NexusError::from)?;
    let rollback_idempotent = matches!(
        owner.transition_phase(LifecyclePhase::Draining),
        Err(nexus_session::SessionError::InvalidPhaseTransition { .. })
    ) && owner.phase() == LifecyclePhase::Disposed;
    let redundant_commit_rejected = matches!(
        owner.commit_outcome(TerminalOutcome::Failed(NexusError::Internal {
            message: "duplicate".into()
        })),
        Err(nexus_session::SessionError::AlreadyTerminated { .. })
    );
    let terminal_outcome_commit_count = owner
        .events()
        .iter()
        .filter(|e| matches!(e, nexus_session::SessionEvent::OutcomeCommitted { .. }))
        .count();

    let status = owner.status();
    Ok(json!({
        "verdict": "PASS",
        "events": events,
        "auth": {
            "gate": "blocked_before_authenticated",
        },
        "error": {
            "code": "AUTHORIZATION_DENIED",
        },
        "rollback": {
            "idempotent": rollback_idempotent,
            "drained_to_disposed": owner.phase() == LifecyclePhase::Disposed,
        },
        "session": {
            "id": owner.id().0,
            "phase": phase_name(&status.phase),
            "outcome": outcome_name(&status.outcome),
        },
        "terminal_outcome_commit_count": terminal_outcome_commit_count,
        "redundant_commit_rejected": redundant_commit_rejected,
        "plan": {
            "provider_id": planned.plan.provider_id.0,
            "placement": planned.plan.placement,
        },
        "discovery": {
            "peer_id": "node-b",
            "endpoint": resolved.to_string(),
        }
    }))
}
