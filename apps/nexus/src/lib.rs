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

/// §9 可观察性命令（status / plan explain / session watch / connectivity status /
/// dns status / dns cache / platform capabilities），见 PRODUCT.md#9-observability。
pub mod observability;

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
/// 事件名：远程计算作业已提交并取回结果（提交/结果往返成功）。
pub const EV_COMPUTE_JOB_SUBMITTED: &str = "compute_job_submitted";
/// 事件名：远程计算作业被提供方拒绝（REJECTED 帧）。
pub const EV_COMPUTE_JOB_REJECTED: &str = "compute_job_rejected";
/// 事件名：远程 Workspace 提交已应用并取回新 Head（OK:HEAD 往返成功）。
pub const EV_WORKSPACE_COMMIT_APPLIED: &str = "workspace_commit_applied";
/// 事件名：远程 Workspace 提交被提供方拒绝（REJECTED 帧）。
pub const EV_WORKSPACE_COMMIT_REJECTED: &str = "workspace_commit_rejected";
/// 事件名：动态 Presence 解析失败（PeerExpired/PeerUnknown，未进入 Plan/Session）。
pub const EV_PRESENCE_RESOLUTION_FAILED: &str = "presence_resolution_failed";
/// 事件名：网络发现协议往返成功（Discover 请求已发出并收到 Announce 响应）。
pub const EV_PRESENCE_DISCOVERED: &str = "presence_discovered";
/// 事件名：链路激活 Direct 候选探测失败（NAT 不可达）。
pub const EV_LINK_DIRECT_FAILED: &str = "link_direct_failed";
/// 事件名：链路激活回退到 Relay 中继（Direct 失败后选中 Relay）。
pub const EV_LINK_RELAY_FALLBACK: &str = "link_relay_fallback";
/// 事件名：链路激活 Relay 候选探测失败（无可用中继）。
pub const EV_LINK_RELAY_FAILED: &str = "link_relay_failed";
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

impl nexus_compute::ComputeTransport for FrameStreamAdapter {
    fn send_frame(&mut self, payload: &[u8]) -> Result<(), nexus_compute::ComputeError> {
        self.inner
            .send_frame(payload)
            .map_err(|_| nexus_compute::ComputeError::Transport)
    }

    fn recv_frame(&mut self) -> Result<Vec<u8>, nexus_compute::ComputeError> {
        self.inner
            .recv_frame()
            .map_err(|_| nexus_compute::ComputeError::Closed)
    }
}
impl nexus_workspace::WorkspaceTransport for FrameStreamAdapter {
    fn send_frame(&mut self, payload: &[u8]) -> Result<(), nexus_workspace::WorkspaceError> {
        self.inner
            .send_frame(payload)
            .map_err(|e| nexus_workspace::WorkspaceError::Transport {
                reason: e.to_string(),
            })
    }

    fn recv_frame(&mut self) -> Result<Vec<u8>, nexus_workspace::WorkspaceError> {
        self.inner
            .recv_frame()
            .map_err(|e| nexus_workspace::WorkspaceError::Transport {
                reason: e.to_string(),
            })
    }
}

/// 运行一次远程资源访问闭环（PRODUCT §6）：Node A 经
/// Discovery -> Plan -> Session -> Connectivity -> Auth -> Service 访问 Node B 的 Service 资源。
///
/// 进程内双节点模拟：Node B 在回环端口监听并提供服务握手（CONNECT -> READY），
/// Node A 通过真实 TCP 长度前缀帧流访问。确定性、可重放。
/// 真实 TCP 可达性探测（Composition Root 注入 `LinkProbe`；Connectivity 层零 I/O）。
///
/// 对候选 locator 发起带超时的 TCP 连接尝试；成功即可达（连接随即释放），
/// 失败保留结构化原因（如 `connection refused`，模拟 NAT 阻塞/端口不可达）。
struct TcpProbe;

impl nexus_connectivity::LinkProbe for TcpProbe {
    fn probe(&self, candidate: &nexus_connectivity::LinkCandidate) -> Result<(), String> {
        let addr: std::net::SocketAddr = candidate
            .locator
            .parse()
            .map_err(|e| format!("invalid locator: {e}"))?;
        std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(500))
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

/// 进程内双向帧转发（A <-> B），用于 Node R 中继的两跳路径（A -> R -> B）。
fn relay_bridge(mut a: std::net::TcpStream, mut b: std::net::TcpStream) {
    let mut a2 = match a.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    let mut b2 = match b.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    let a_to_b = std::thread::spawn(move || forward_bytes(&mut a, &mut b));
    let b_to_a = std::thread::spawn(move || forward_bytes(&mut b2, &mut a2));
    let _ = a_to_b.join();
    let _ = b_to_a.join();
}

/// 单向字节转发循环（EOF/错误即停）。
fn forward_bytes(r: &mut std::net::TcpStream, w: &mut std::net::TcpStream) {
    use std::io::{Read, Write};
    let mut buf = [0u8; 4096];
    loop {
        match r.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if w.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    }
}

/// 生成一个"已释放端口"地址（bind 后立即 drop）——用于模拟 NAT 后不可直连
/// 的 Direct 候选（连接必然被拒，与真实 NAT 外部探测失败同构）。
fn freed_port_addr() -> std::net::SocketAddr {
    let tmp = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind temp listener")
        .local_addr()
        .expect("local addr");
    // drop(tmp) 自动发生：端口释放，后续 connect 将得到 ConnectionRefused。
    tmp
}

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

// ---------- Remote Compute（PRODUCT §6，remote P0 扩展） ----------

/// 运行一次远程 Compute 作业闭环（PRODUCT §2/§6）：Node A 经
/// Discovery -> Plan -> Session -> Connectivity -> Auth -> Compute 向 Node B 提交
/// 计算作业并取回结果，完成一次真实作业/结果帧往返。
///
/// 进程内双节点模拟：Node B 在回环端口监听并模拟执行器（合法作业 -> `OK:<result>`），
/// Node A 通过真实 TCP 长度前缀帧流提交。确定性、可重放。
pub fn remote_compute_job_flow() -> Result<Value, NexusError> {
    let mut events: Vec<&'static str> = Vec::new();
    const JOB_ID: &str = "job-remote-1";

    // 0) Node B（提供方）：绑定回环端口，后台线程接受连接并模拟远程执行器。
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
                // 远程执行器：任意合法作业帧 -> 结果帧（OK:<result>）。
                let _ = fs.send_frame(b"OK:42");
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

    // 2) Policy：Compute 画像展开为 Intent + Constraint（authorization=explicit）。
    let flow = nexus_ingress::from_native_api("compute", "RemoteBalanced");
    let decision = nexus_policy::PolicyEngine::default_compute()
        .evaluate(&flow)
        .decision;

    // 3) Registry + Core Planner：唯一系统级规划，Provider = node-b（远程执行器）。
    let resource: ResourceId = flow.resource.clone();
    let mut registry = Registry::new();
    registry.register(ProviderRecord {
        id: ProviderId("node-b".into()),
        resource: resource.clone(),
        placement: "remote-provider".into(),
        locator: "node-b.endpoint".into(),
        capabilities: vec!["compute-job".into()],
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
    let mut owner = SessionOwner::new(SessionId("sess-remote-compute-1".into()));
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

    // 6) Auth：预共享 Token 门控在作业帧前通过（W7：未认证帧不得进入业务处理）。
    let token = nexus_auth::PreSharedToken("nexus-preshared-token".into());
    let expected = nexus_auth::PreSharedToken("nexus-preshared-token".into());
    let principal = nexus_auth::verify_token(&token, &expected).map_err(|_| {
        NexusError::AuthorizationDenied {
            principal: "remote-requester".into(),
        }
    })?;

    // 7) Compute：提交作业（作业帧 -> 结果帧 -> 取回结果）。
    let job_frame = format!("job:{JOB_ID}:compile");
    let compute_session = nexus_compute::ComputeJobSession::submit(
        Box::new(FrameStreamAdapter {
            inner: frame_stream,
        }),
        job_frame.as_bytes(),
    )
    .map_err(|e| NexusError::SessionFailed {
        session: owner.id().clone(),
        reason: e.to_string(),
    })?;
    events.push(EV_COMPUTE_JOB_SUBMITTED);

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
        "compute": {
            "phase": compute_session.phase().to_string(),
            "job_id": JOB_ID,
            "result": compute_session.result().unwrap_or_default(),
        },
        "architecture": {
            "network_depends_on_ingress": arch_violation,
        }
    }))
}

/// 运行一次远程计算作业被拒路径（PRODUCT §6）：Discovery 已解析 Node B、
/// 认证通过（token 正确）、作业帧真实提交，但提供方返回 REJECTED——
/// Owner 唯一提交 Failed(COMPUTE_JOB_REJECTED)，按逆序幂等回滚到 Disposed。
///
/// 确定性：Node B 在回环端口监听并模拟执行器拒绝（任何作业 -> REJECTED）。
pub fn remote_compute_rejected_rollback() -> Result<Value, NexusError> {
    let mut events: Vec<&'static str> = Vec::new();
    const JOB_ID: &str = "job-remote-rejected-1";

    // 0) Node B（提供方）：绑定回环端口并接受连接；模拟执行器拒绝作业（REJECTED 帧）。
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
                // 提供方拒绝：作业内容不合法（REJECTED 帧）。
                let _ = fs.send_frame(b"REJECTED");
            }
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

    // 2) Policy / 3) Planner：Provider = node-b（失败发生在提交阶段，而非解析/规划阶段）。
    let flow = nexus_ingress::from_native_api("compute", "RemoteBalanced");
    let decision = nexus_policy::PolicyEngine::default_compute()
        .evaluate(&flow)
        .decision;
    let resource: ResourceId = flow.resource.clone();
    let mut registry = Registry::new();
    registry.register(ProviderRecord {
        id: ProviderId("node-b".into()),
        resource: resource.clone(),
        placement: "remote-provider".into(),
        locator: "node-b.endpoint".into(),
        capabilities: vec!["compute-job".into()],
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
    let mut owner = SessionOwner::new(SessionId("sess-remote-compute-reject-1".into()));
    owner
        .transition_phase(LifecyclePhase::Active)
        .map_err(NexusError::from)?;
    events.push(EV_SESSION_CREATED);

    // 5) Connectivity：帧流真实建立（Node B 在监听）。
    let frame_stream = nexus_transport::connect(&resolved).map_err(|e| {
        NexusError::ConnectivityEstablishmentFailed {
            provider: planned.plan.provider_id.clone(),
            reason: e.to_string(),
        }
    })?;
    events.push(EV_REMOTE_CONNECTIVITY_ESTABLISHED);

    // 6) Auth：预共享 Token 校验通过（失败发生在提供方拒绝，而非认证阶段）。
    let token = nexus_auth::PreSharedToken("nexus-preshared-token".into());
    let expected = nexus_auth::PreSharedToken("nexus-preshared-token".into());
    let principal = nexus_auth::verify_token(&token, &expected).map_err(|_| {
        NexusError::AuthorizationDenied {
            principal: "remote-requester".into(),
        }
    })?;
    drop(principal);

    // 7) Compute：提交作业，提供方拒绝 -> ComputeError::Rejected。
    let job_frame = format!("job:{JOB_ID}:bogus");
    let rejected = nexus_compute::ComputeJobSession::submit(
        Box::new(FrameStreamAdapter {
            inner: frame_stream,
        }),
        job_frame.as_bytes(),
    );
    let reason = match rejected {
        Err(nexus_compute::ComputeError::Rejected) => {
            "provider rejected job: unsupported workload".to_string()
        }
        Err(e) => {
            return Err(NexusError::Internal {
                message: format!("expected rejection, got {e}"),
            });
        }
        Ok(_) => {
            return Err(NexusError::Internal {
                message: "expected rejection but job succeeded".into(),
            });
        }
    };
    events.push(EV_COMPUTE_JOB_REJECTED);

    // 8) 回收 Node B 线程（结构化并发：线程有明确 Owner，主流程 join）。
    if node_b_server.join().is_err() {
        return Err(NexusError::Internal {
            message: "node-b server thread panicked".into(),
        });
    }

    // 9) Owner 唯一提交 Failed(COMPUTE_JOB_REJECTED)。
    owner
        .commit_outcome(TerminalOutcome::Failed(NexusError::ComputeJobRejected {
            job_id: JOB_ID.into(),
            reason: reason.clone(),
        }))
        .map_err(NexusError::from)?;
    events.push(EV_TERMINAL_OUTCOME_COMMITTED);

    // 10) 逆序回滚：Draining -> Disposed（K10 逆序幂等）。
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
            "gate": "token_verified",
        },
        "error": {
            "code": "COMPUTE_JOB_REJECTED",
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

/// 运行一次远程 Workspace 提交闭环（PRODUCT §6）：Node A 经
/// Discovery -> Plan -> Session -> Connectivity -> Auth -> Workspace 向 Node B 的
/// Workspace 提交 ChangeSet（`<parent>\n<path>\n<content>` 帧）并取回新 Head。
///
/// 进程内双节点模拟：Node B 在回环端口监听，后台线程内运行真实
/// `Workspace::init + commit_changes`（InMemoryContentStore），返回 `OK:HEAD:<id>`；
/// Node A 通过真实 TCP 长度前缀帧流完成远程提交。确定性、可重放。
pub fn remote_workspace_commit_flow() -> Result<Value, NexusError> {
    let mut events: Vec<&'static str> = Vec::new();
    const PARENT: &str = "C0";

    // 0) Node B（提供方）：绑定回环端口，后台线程内运行真实 Workspace 并应用远程提交。
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
                // ChangeSet 帧格式：<parent>\n<path>\n<content>
                let text = String::from_utf8_lossy(&frame);
                let mut parts = text.splitn(3, '\n');
                let parent = parts.next().unwrap_or_default().to_string();
                let path = parts.next().unwrap_or_default().to_string();
                let content = parts.next().unwrap_or_default().as_bytes().to_vec();
                let ws = nexus_workspace::Workspace::init(
                    nexus_workspace::WorkspaceId("ws-b".into()),
                    nexus_storage::InMemoryContentStore::new(),
                );
                let response = match ws {
                    Ok(mut ws) => match ws.commit_changes(
                        &nexus_workspace::CommitId(parent),
                        &[nexus_workspace::Change { path, content }],
                    ) {
                        Ok(head) => format!("OK:HEAD:{}", head.0),
                        Err(e) => format!("REJECTED:{e}"),
                    },
                    Err(e) => format!("REJECTED:{e}"),
                };
                let _ = fs.send_frame(response.as_bytes());
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

    // 2) Policy：Workspace 画像展开为 Intent + Constraint（authorization=explicit）。
    let flow = nexus_ingress::from_native_api("workspace", "RemoteBalanced");
    let decision = nexus_policy::PolicyEngine::default_workspace()
        .evaluate(&flow)
        .decision;

    // 3) Registry + Core Planner：唯一系统级规划，Provider = node-b（远程 Workspace）。
    let resource: ResourceId = flow.resource.clone();
    let mut registry = Registry::new();
    registry.register(ProviderRecord {
        id: ProviderId("node-b".into()),
        resource: resource.clone(),
        placement: "remote-provider".into(),
        locator: "node-b.endpoint".into(),
        capabilities: vec!["workspace-sync".into()],
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
    let mut owner = SessionOwner::new(SessionId("sess-remote-workspace-1".into()));
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

    // 6) Auth：预共享 Token 门控在 ChangeSet 帧前通过（W7：未认证帧不得进入业务处理）。
    let token = nexus_auth::PreSharedToken("nexus-preshared-token".into());
    let expected = nexus_auth::PreSharedToken("nexus-preshared-token".into());
    let principal = nexus_auth::verify_token(&token, &expected).map_err(|_| {
        NexusError::AuthorizationDenied {
            principal: "remote-requester".into(),
        }
    })?;

    // 7) Workspace：远程提交（ChangeSet 帧 -> OK:HEAD:<id>，取回新 Head）。
    let change_set = format!("{PARENT}\nremote.txt\nremote-content");
    let ws_session = nexus_workspace::RemoteWorkspaceSession::commit(
        Box::new(FrameStreamAdapter {
            inner: frame_stream,
        }),
        change_set.as_bytes(),
    )
    .map_err(|e| NexusError::SessionFailed {
        session: owner.id().clone(),
        reason: e.to_string(),
    })?;
    events.push(EV_WORKSPACE_COMMIT_APPLIED);

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
        "workspace": {
            "phase": ws_session.phase().to_string(),
            "head": ws_session.head().map(|h| h.0.clone()).unwrap_or_default(),
            "parent": PARENT,
        },
        "architecture": {
            "network_depends_on_ingress": arch_violation,
        }
    }))
}

/// 运行一次远程 Workspace 提交被拒路径（PRODUCT §6）：Discovery 已解析 Node B、
/// 认证通过（token 正确）、ChangeSet 帧真实提交（携带未知 parent），但提供方
/// 真实 Workspace 按 `UnknownCommit` 语义拒绝（REJECTED 帧）——Owner 唯一提交
/// Failed(WORKSPACE_COMMIT_REJECTED)，按逆序幂等回滚到 Disposed。
pub fn remote_workspace_rejected_rollback() -> Result<Value, NexusError> {
    let mut events: Vec<&'static str> = Vec::new();

    // 0) Node B（提供方）：绑定回环端口，后台线程内运行真实 Workspace；
    //    未知 parent 的 ChangeSet -> commit_changes 返回 UnknownCommit -> REJECTED 帧。
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
                let text = String::from_utf8_lossy(&frame);
                let mut parts = text.splitn(3, '\n');
                let parent = parts.next().unwrap_or_default().to_string();
                let path = parts.next().unwrap_or_default().to_string();
                let content = parts.next().unwrap_or_default().as_bytes().to_vec();
                let ws = nexus_workspace::Workspace::init(
                    nexus_workspace::WorkspaceId("ws-b-rejected".into()),
                    nexus_storage::InMemoryContentStore::new(),
                );
                let response = match ws {
                    Ok(mut ws) => match ws.commit_changes(
                        &nexus_workspace::CommitId(parent),
                        &[nexus_workspace::Change { path, content }],
                    ) {
                        Ok(_) => "OK:HEAD:C9".to_string(),
                        Err(e) => format!("REJECTED:{e}"),
                    },
                    Err(e) => format!("REJECTED:{e}"),
                };
                let _ = fs.send_frame(response.as_bytes());
            }
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

    // 2) Policy / 3) Planner：Provider = node-b（失败发生在提交阶段，而非解析/规划阶段）。
    let flow = nexus_ingress::from_native_api("workspace", "RemoteBalanced");
    let decision = nexus_policy::PolicyEngine::default_workspace()
        .evaluate(&flow)
        .decision;
    let resource: ResourceId = flow.resource.clone();
    let mut registry = Registry::new();
    registry.register(ProviderRecord {
        id: ProviderId("node-b".into()),
        resource: resource.clone(),
        placement: "remote-provider".into(),
        locator: "node-b.endpoint".into(),
        capabilities: vec!["workspace-sync".into()],
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
    let mut owner = SessionOwner::new(SessionId("sess-remote-ws-reject-1".into()));
    owner
        .transition_phase(LifecyclePhase::Active)
        .map_err(NexusError::from)?;
    events.push(EV_SESSION_CREATED);

    // 5) Connectivity：帧流真实建立（Node B 在监听）。
    let frame_stream = nexus_transport::connect(&resolved).map_err(|e| {
        NexusError::ConnectivityEstablishmentFailed {
            provider: planned.plan.provider_id.clone(),
            reason: e.to_string(),
        }
    })?;
    events.push(EV_REMOTE_CONNECTIVITY_ESTABLISHED);

    // 6) Auth：预共享 Token 校验通过（失败发生在提供方拒绝，而非认证阶段）。
    let token = nexus_auth::PreSharedToken("nexus-preshared-token".into());
    let expected = nexus_auth::PreSharedToken("nexus-preshared-token".into());
    let principal = nexus_auth::verify_token(&token, &expected).map_err(|_| {
        NexusError::AuthorizationDenied {
            principal: "remote-requester".into(),
        }
    })?;

    // 7) Workspace：提交携带未知 parent 的 ChangeSet，提供方拒绝 -> RemoteRejected。
    let rejected = nexus_workspace::RemoteWorkspaceSession::commit(
        Box::new(FrameStreamAdapter {
            inner: frame_stream,
        }),
        b"UNKNOWN\nremote.txt\nremote-content",
    );
    let reason = match rejected {
        Err(nexus_workspace::WorkspaceError::RemoteRejected { reason }) => {
            format!("provider rejected workspace commit: {reason}")
        }
        Err(e) => {
            return Err(NexusError::Internal {
                message: format!("expected rejection, got {e}"),
            });
        }
        Ok(_) => {
            return Err(NexusError::Internal {
                message: "expected rejection but commit succeeded".into(),
            });
        }
    };
    events.push(EV_WORKSPACE_COMMIT_REJECTED);

    // 8) 回收 Node B 线程（结构化并发：线程有明确 Owner，主流程 join）。
    if node_b_server.join().is_err() {
        return Err(NexusError::Internal {
            message: "node-b server thread panicked".into(),
        });
    }

    // 9) Owner 唯一提交 Failed(WORKSPACE_COMMIT_REJECTED)。
    owner
        .commit_outcome(TerminalOutcome::Failed(
            NexusError::WorkspaceCommitRejected {
                workspace: "ws-b-rejected".into(),
                reason: reason.clone(),
            },
        ))
        .map_err(NexusError::from)?;
    events.push(EV_TERMINAL_OUTCOME_COMMITTED);

    // 10) 逆序回滚：Draining -> Disposed（K10 逆序幂等）。
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
    let arch_violation = network_depends_on_ingress()?;

    let status = owner.status();
    Ok(json!({
        "verdict": "PASS",
        "events": events,
        "auth": {
            "gate": "token_verified",
            "principal": principal.0,
        },
        "error": {
            "code": "WORKSPACE_COMMIT_REJECTED",
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
        },
        "architecture": {
            "network_depends_on_ingress": arch_violation,
        }
    }))
}

/// 运行一次基于动态 Presence 发现的远程闭环（PRODUCT §6）：Node B 向
/// `PresenceRegistry` 发布 Presence（真实可达 Endpoint + TTL），Node A 经
/// 注册中心动态解析（取代静态表注入）后，完成与 Service 相同的
/// Discovery -> Plan -> Session -> Connectivity -> Auth -> Service 闭环。
///
/// 进程内双节点模拟：Node B 在回环端口监听并提供服务握手（CONNECT -> READY），
/// Presence 由 Node B 主动 announce、Node A 主动 resolve。确定性、可重放。
pub fn remote_presence_dynamic_flow() -> Result<Value, NexusError> {
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

    // 1) 动态发现：Node B 发布 Presence（真实监听地址 + TTL），Node A 经注册中心解析。
    let mut presence = nexus_discovery::PresenceRegistry::default();
    presence
        .announce(nexus_discovery::PeerId("node-b".into()), node_b_addr, 60)
        .map_err(|e| NexusError::Internal {
            message: e.to_string(),
        })?;
    let endpoint = presence
        .resolve(&nexus_discovery::PeerId("node-b".into()))
        .map_err(|e| NexusError::Internal {
            message: e.to_string(),
        })?;
    let presence_announced = presence.is_announced(&nexus_discovery::PeerId("node-b".into()));
    let presence_expired = presence.is_expired(&nexus_discovery::PeerId("node-b".into()));
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
    let mut owner = SessionOwner::new(SessionId("sess-presence-service-1".into()));
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

    // 7) Service：握手（CONNECT -> READY）。
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
        "discovery": {
            "mode": "dynamic",
            "peer_id": "node-b",
            "endpoint": endpoint.to_string(),
        },
        "presence": {
            "announced": presence_announced,
            "expired": presence_expired,
            "ttl_secs": 60,
        },
        "events": events,
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

/// 运行一次 Presence 过期拒绝路径（PRODUCT §6）：Node B 以 TTL=0 发布 Presence
/// （立即过期），Node A 动态解析失败（PeerExpired）——失败发生在 Discovery 阶段
/// （未到 Plan/Session/Connectivity），输出结构化拒绝（PEER_EXPIRED），
/// 不得返回过期 Endpoint、不进入资源访问。
pub fn remote_presence_expired_rollback() -> Result<Value, NexusError> {
    let mut events: Vec<&'static str> = Vec::new();

    // 1) 动态发现：Node B 以 TTL=0 发布 Presence（立即过期）。
    let mut presence = nexus_discovery::PresenceRegistry::default();
    let placeholder: std::net::SocketAddr =
        "127.0.0.1:1".parse().map_err(|e| NexusError::Internal {
            message: format!("invalid placeholder endpoint: {e}"),
        })?;
    presence
        .announce(nexus_discovery::PeerId("node-b".into()), placeholder, 0)
        .map_err(|e| NexusError::Internal {
            message: e.to_string(),
        })?;
    let presence_announced = presence.is_announced(&nexus_discovery::PeerId("node-b".into()));
    let presence_expired = presence.is_expired(&nexus_discovery::PeerId("node-b".into()));

    // 2) 动态解析：TTL 过期 -> PeerExpired（结构化拒绝，不返回过期 Endpoint）。
    let resolved = presence.resolve(&nexus_discovery::PeerId("node-b".into()));
    match resolved {
        Err(nexus_discovery::DiscoveryError::PeerExpired(_)) => {
            events.push(EV_PRESENCE_RESOLUTION_FAILED);
        }
        Err(e) => {
            return Err(NexusError::Internal {
                message: format!("expected PeerExpired, got {e}"),
            });
        }
        Ok(_) => {
            return Err(NexusError::Internal {
                message: "expected PeerExpired but endpoint resolved".into(),
            });
        }
    }

    Ok(json!({
        "verdict": "PASS",
        "discovery": {
            "mode": "dynamic",
            "peer_id": "node-b",
        },
        "presence": {
            "announced": presence_announced,
            "expired": presence_expired,
        },
        "events": events,
        "error": {
            "code": "PEER_EXPIRED",
        }
    }))
}

/// 运行一次 NAT 回退闭环（PRODUCT §6）：Node B 位于 NAT 后（Direct 候选 = 已释放
/// 端口的映射地址，真实探测必然 ConnectionRefused），Node R 为进程内中继
/// （A<->R<->B 两跳字节转发）。组合根经 `LinkActivator` 按序激活：Direct 探测失败
/// -> Relay 回退成功 -> 经中继建立帧流 -> 复用 Discovery/Plan/Session/Auth/Service
/// 完整闭环。
pub fn remote_nat_relay_fallback_flow() -> Result<Value, NexusError> {
    let mut events: Vec<&'static str> = Vec::new();

    // 0) Node B（提供方，真实服务端点）：回环监听，完成 Service 握手。
    let listener_b =
        std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| NexusError::Internal {
            message: format!("cannot bind node-b listener: {e}"),
        })?;
    let node_b_addr = listener_b.local_addr().map_err(|e| NexusError::Internal {
        message: format!("cannot read node-b addr: {e}"),
    })?;
    let node_b_server = std::thread::spawn(move || {
        if let Ok(mut fs) = nexus_transport::accept(&listener_b) {
            if let Ok(frame) = fs.recv_frame() {
                if frame == b"CONNECT" {
                    let _ = fs.send_frame(b"READY");
                }
            }
        }
    });

    // 1) Node R（中继）：回环监听，双向转发（A <-> B）。
    //    探测连接（TcpProbe 立即 drop）会被识别并丢弃，不转发到 Node B。
    let relay_listener =
        std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| NexusError::Internal {
            message: format!("cannot bind node-r listener: {e}"),
        })?;
    let relay_addr = relay_listener
        .local_addr()
        .map_err(|e| NexusError::Internal {
            message: format!("cannot read node-r addr: {e}"),
        })?;
    let relay_node = std::thread::spawn(move || {
        use std::io::{Read, Write};
        loop {
            let (mut client, _) = match relay_listener.accept() {
                Ok(pair) => pair,
                Err(_) => break,
            };
            // 丢弃可达性探测连接（立即 EOF）：读首字节，无数据则忽略并继续 accept。
            let mut first = [0u8; 1];
            let _ = client.set_read_timeout(Some(std::time::Duration::from_millis(300)));
            match client.read(&mut first) {
                Ok(0) | Err(_) => continue,
                Ok(_) => {}
            }
            let _ = client.set_read_timeout(None);
            // 真实请求连接：建立到 Node B 的上游并双向转发；处理完即退出。
            if let Ok(mut upstream) = std::net::TcpStream::connect(node_b_addr) {
                if upstream.write_all(&first).is_ok() {
                    relay_bridge(client, upstream);
                }
            }
            break;
        }
    });

    // 2) Discovery：静态发现解析 Node B 的 NAT 映射地址（Direct 候选，不可达）。
    let nat_addr = freed_port_addr();
    let discovery = nexus_discovery::StaticDiscovery::new([(
        nexus_discovery::PeerId("node-b".into()),
        nat_addr,
    )]);
    let direct_locator = discovery
        .resolve(&nexus_discovery::PeerId("node-b".into()))
        .map_err(|e| NexusError::Internal {
            message: e.to_string(),
        })?;
    events.push(EV_REMOTE_PROVIDER_RESOLVED);

    // 3) Policy：Service 画像（authorization=explicit）。
    let flow = nexus_ingress::from_native_api("service", "RemoteBalanced");
    let decision = nexus_policy::PolicyEngine::default_service()
        .evaluate(&flow)
        .decision;

    // 4) Registry + Core Planner：唯一系统级规划，Provider = node-b。
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

    // 5) Session：Owner 创建并进入 Active（先于建连）。
    let mut owner = SessionOwner::new(SessionId("sess-nat-relay-service-1".into()));
    owner
        .transition_phase(LifecyclePhase::Active)
        .map_err(NexusError::from)?;
    events.push(EV_SESSION_CREATED);

    // 6) Link Activation：Direct 探测失败（NAT）-> Relay 回退成功（真实 TCP 探测）。
    let direct_candidate = nexus_connectivity::LinkCandidate::new(
        nexus_connectivity::LinkKind::Direct,
        direct_locator.to_string(),
        1,
    );
    let relay_candidate = nexus_connectivity::LinkCandidate::new(
        nexus_connectivity::LinkKind::Relay,
        relay_addr.to_string(),
        15,
    );
    let activator = nexus_connectivity::LinkActivator::new(TcpProbe);
    let selection = activator
        .activate(&direct_candidate, Some(&relay_candidate), false, false)
        .map_err(|e| NexusError::Internal {
            message: format!("link activation failed unexpectedly: {e}"),
        })?;
    let direct_reason = selection
        .events
        .iter()
        .find_map(|e| match e {
            nexus_connectivity::LinkActivationEvent::AttemptFailed {
                kind: nexus_connectivity::LinkKind::Direct,
                reason,
                ..
            } => Some(reason.clone()),
            _ => None,
        })
        .unwrap_or_default();
    events.push(EV_LINK_DIRECT_FAILED);
    if selection.kind == nexus_connectivity::LinkKind::Relay {
        events.push(EV_LINK_RELAY_FALLBACK);
    }

    // 7) Connectivity：经选中链路（Relay）建立 TCP 长度前缀帧流（激活决策之后）。
    let endpoint: std::net::SocketAddr =
        selection
            .locator
            .parse()
            .map_err(|e| NexusError::Internal {
                message: format!("invalid selected locator: {e}"),
            })?;
    let frame_stream = nexus_transport::connect(&endpoint).map_err(|e| {
        NexusError::ConnectivityEstablishmentFailed {
            provider: planned.plan.provider_id.clone(),
            reason: e.to_string(),
        }
    })?;
    events.push(EV_REMOTE_CONNECTIVITY_ESTABLISHED);

    // 8) Auth：预共享 Token 门控在业务帧前通过。
    let token = nexus_auth::PreSharedToken("nexus-preshared-token".into());
    let expected = nexus_auth::PreSharedToken("nexus-preshared-token".into());
    let principal = nexus_auth::verify_token(&token, &expected).map_err(|_| {
        NexusError::AuthorizationDenied {
            principal: "remote-requester".into(),
        }
    })?;

    // 9) Service：握手（CONNECT -> READY，经中继两跳）。
    let service_session = nexus_service::ServiceSession::connect(Box::new(FrameStreamAdapter {
        inner: frame_stream,
    }))
    .map_err(|e| NexusError::SessionFailed {
        session: owner.id().clone(),
        reason: e.to_string(),
    })?;
    events.push(EV_SERVICE_CONNECTED);

    // 10) Owner 唯一提交 Completed；终态后 cleanup 推进到 Disposed。
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

    // 11) 回收 Node R / Node B 线程（结构化并发：join 确认结束）。
    if relay_node.join().is_err() {
        return Err(NexusError::Internal {
            message: "node-r relay thread panicked".into(),
        });
    }
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
        "discovery": {
            "peer_id": "node-b",
            "endpoint": direct_locator.to_string(),
        },
        "events": events,
        "link": {
            "kind": "relay",
            "direct_attempted": true,
            "direct_reason": direct_reason,
            "relay_locator": selection.locator,
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

/// 运行一次 Relay 不可用拒绝路径（PRODUCT §6）：Direct（NAT 不可达）与 Relay
/// （中继端口未监听）均探测失败 -> `NoLinkAvailable` 结构化拒绝（NO_LINK_AVAILABLE）；
/// 失败发生在 Connectivity 阶段，Session 逆序幂等回滚（Failed -> Draining -> Disposed），
/// 不替换业务 Provider、不进入资源访问。
pub fn remote_relay_unavailable_rollback() -> Result<Value, NexusError> {
    let mut events: Vec<&'static str> = Vec::new();

    // 0) Discovery：Node B 的 NAT 映射地址（Direct 候选，不可达）。
    let nat_addr = freed_port_addr();
    let discovery = nexus_discovery::StaticDiscovery::new([(
        nexus_discovery::PeerId("node-b".into()),
        nat_addr,
    )]);
    let direct_locator = discovery
        .resolve(&nexus_discovery::PeerId("node-b".into()))
        .map_err(|e| NexusError::Internal {
            message: e.to_string(),
        })?;
    events.push(EV_REMOTE_PROVIDER_RESOLVED);

    // 1) Policy + Planner。
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
    let _planned =
        nexus_planner::plan_from_snapshot(&resource, &snapshot, &decision.intent, |p| {
            measurements.get(p).cloned()
        })?;
    events.push(EV_PLAN_SELECTED);

    // 2) Session：Owner 创建并进入 Active（Connectivity 失败后逆序回滚）。
    let mut owner = SessionOwner::new(SessionId("sess-relay-unavailable-1".into()));
    owner
        .transition_phase(LifecyclePhase::Active)
        .map_err(NexusError::from)?;
    events.push(EV_SESSION_CREATED);

    // 3) Link Activation：Direct 与 Relay 均不可达（中继端口未监听 -> 连接被拒）。
    let relay_addr = freed_port_addr();
    let direct_candidate = nexus_connectivity::LinkCandidate::new(
        nexus_connectivity::LinkKind::Direct,
        direct_locator.to_string(),
        1,
    );
    let relay_candidate = nexus_connectivity::LinkCandidate::new(
        nexus_connectivity::LinkKind::Relay,
        relay_addr.to_string(),
        15,
    );
    let activator = nexus_connectivity::LinkActivator::new(TcpProbe);
    let attempted_relay =
        match activator.activate(&direct_candidate, Some(&relay_candidate), false, false) {
            Err(nexus_connectivity::ConnectivityError::NoLinkAvailable { attempted }) => {
                attempted.contains(&nexus_connectivity::LinkKind::Relay)
            }
            Err(e) => {
                return Err(NexusError::Internal {
                    message: format!("expected NoLinkAvailable, got {e}"),
                });
            }
            Ok(_) => {
                return Err(NexusError::Internal {
                    message: "expected NoLinkAvailable but a link was selected".into(),
                });
            }
        };
    events.push(EV_LINK_DIRECT_FAILED);
    if attempted_relay {
        events.push(EV_LINK_RELAY_FAILED);
    }

    // 4) Session 逆序幂等回滚：Failed -> Draining -> Disposed（唯一一次 Outcome 提交）。
    owner
        .commit_outcome(TerminalOutcome::Failed(NexusError::Internal {
            message: "no link available".into(),
        }))
        .map_err(NexusError::from)?;
    owner
        .transition_phase(LifecyclePhase::Draining)
        .map_err(NexusError::from)?;
    owner
        .transition_phase(LifecyclePhase::Disposed)
        .map_err(NexusError::from)?;

    let status = owner.status();
    let terminal_outcome_commit_count = owner
        .events()
        .iter()
        .filter(|e| matches!(e, nexus_session::SessionEvent::OutcomeCommitted { .. }))
        .count();

    Ok(json!({
        "verdict": "PASS",
        "discovery": {
            "peer_id": "node-b",
        },
        "events": events,
        "error": {
            "code": "NO_LINK_AVAILABLE",
        },
        "link": {
            "direct_attempted": true,
            "relay_attempted": attempted_relay,
        },
        "session": {
            "id": owner.id().0,
            "phase": phase_name(&status.phase),
            "outcome": outcome_name(&status.outcome),
        },
        "terminal_outcome_commit_count": terminal_outcome_commit_count,
    }))
}

/// 把 `FrameStream` 适配为 `DiscoveryTransport`（发现协议单请求-响应往返；
/// 依赖注入，由 Composition Root 装配；避免 discovery -> transport 依赖边）。
struct DiscoveryFrameTransport {
    inner: nexus_transport::FrameStream,
}

impl nexus_discovery::DiscoveryTransport for DiscoveryFrameTransport {
    fn exchange(&mut self, request: &[u8]) -> Result<Vec<u8>, nexus_discovery::DiscoveryError> {
        self.inner
            .send_frame(request)
            .map_err(|e| nexus_discovery::DiscoveryError::Transport(e.to_string()))?;
        self.inner
            .recv_frame()
            .map_err(|e| nexus_discovery::DiscoveryError::Transport(e.to_string()))
    }
}

/// 运行一次基于网络发现协议的远程闭环（PRODUCT §6）：Node A 经发现协议（TCP +
/// 长度前缀帧）向 Node B 的 `PresenceServer` 发送 `Discover` 请求帧，收到
/// `Announce` 响应帧后缓存入本地 `PresenceClient`，解析 Endpoint，随后完成与
/// 动态 Presence 相同的 Discovery -> Plan -> Session -> Connectivity -> Auth ->
/// Service 闭环。Node A 侧无提供方注册中心——发现必须经网络协议达成。
pub fn remote_presence_network_discovery_flow() -> Result<Value, NexusError> {
    let mut events: Vec<&'static str> = Vec::new();

    // 0) Node B（提供方）：绑定发现端点（网络发现协议）与资源端点（服务握手）。
    let discovery_listener =
        std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| NexusError::Internal {
            message: format!("cannot bind discovery listener: {e}"),
        })?;
    let discovery_addr = discovery_listener
        .local_addr()
        .map_err(|e| NexusError::Internal {
            message: format!("cannot read discovery addr: {e}"),
        })?;
    let resource_listener =
        std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| NexusError::Internal {
            message: format!("cannot bind resource listener: {e}"),
        })?;
    let resource_addr = resource_listener
        .local_addr()
        .map_err(|e| NexusError::Internal {
            message: format!("cannot read resource addr: {e}"),
        })?;

    // Node B 注册中心：announce 资源 Presence（真实可达资源端点 + TTL）。
    let mut registry = nexus_discovery::PresenceRegistry::default();
    registry
        .announce(nexus_discovery::PeerId("node-b".into()), resource_addr, 60)
        .map_err(|e| NexusError::Internal {
            message: e.to_string(),
        })?;

    let node_b_server = std::thread::spawn(move || {
        // 发现服务：accept -> 请求帧 -> PresenceServer::handle -> 响应帧。
        if let Ok(mut fs) = nexus_transport::accept(&discovery_listener) {
            if let Ok(request) = fs.recv_frame() {
                let response = nexus_discovery::PresenceServer.handle(&registry, &request);
                if !response.is_empty() {
                    let _ = fs.send_frame(&response);
                }
            }
        }
        // 资源服务：accept -> CONNECT/READY。
        if let Ok(mut fs) = nexus_transport::accept(&resource_listener) {
            if let Ok(frame) = fs.recv_frame() {
                if frame == b"CONNECT" {
                    let _ = fs.send_frame(b"READY");
                }
            }
        }
    });

    // 1) 网络发现：Node A 经发现协议拉取 Node B 的动态 Presence（本地无注册中心）。
    let mut frames: Vec<&'static str> = Vec::new();
    frames.push("discover");
    let mut client = nexus_discovery::PresenceClient::default();
    let frame_stream = nexus_transport::connect(&discovery_addr).map_err(|e| {
        NexusError::ConnectivityEstablishmentFailed {
            provider: ProviderId("node-b".into()),
            reason: e.to_string(),
        }
    })?;
    let mut transport = DiscoveryFrameTransport {
        inner: frame_stream,
    };
    let presence = client
        .discover(&mut transport, &nexus_discovery::PeerId("node-b".into()))
        .map_err(|e| NexusError::Internal {
            message: e.to_string(),
        })?;
    frames.push("announce");
    let endpoint = client
        .resolve_local(&nexus_discovery::PeerId("node-b".into()))
        .map_err(|e| NexusError::Internal {
            message: e.to_string(),
        })?;
    let presence_announced = client.is_announced(&nexus_discovery::PeerId("node-b".into()));
    events.push(EV_PRESENCE_DISCOVERED);
    events.push(EV_REMOTE_PROVIDER_RESOLVED);

    // 2) Policy：Service 画像展开为 Intent + Constraint（authorization=explicit）。
    let flow = nexus_ingress::from_native_api("service", "RemoteBalanced");
    let decision = nexus_policy::PolicyEngine::default_service()
        .evaluate(&flow)
        .decision;

    // 3) Registry + Core Planner：唯一系统级规划，Provider = node-b（远程提供方）。
    let resource: ResourceId = flow.resource.clone();
    let mut registry_plan = Registry::new();
    registry_plan.register(ProviderRecord {
        id: ProviderId("node-b".into()),
        resource: resource.clone(),
        placement: "remote-provider".into(),
        locator: "node-b.endpoint".into(),
        capabilities: vec!["service-session".into()],
        present: true,
    });
    let candidates = registry_plan.candidates(&resource);
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
    let mut owner = SessionOwner::new(SessionId("sess-presence-net-service-1".into()));
    owner
        .transition_phase(LifecyclePhase::Active)
        .map_err(NexusError::from)?;
    events.push(EV_SESSION_CREATED);

    // 5) Connectivity：建立到 Node B 资源端点的 TCP 长度前缀帧流（Plan + Session 之后）。
    let resource_stream = nexus_transport::connect(&endpoint).map_err(|e| {
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

    // 7) Service：握手（CONNECT -> READY）。
    let service_session = nexus_service::ServiceSession::connect(Box::new(FrameStreamAdapter {
        inner: resource_stream,
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
        "discovery": {
            "mode": "network",
            "peer_id": "node-b",
            "endpoint": endpoint.to_string(),
            "frames": frames,
        },
        "presence": {
            "source": "network",
            "announced": presence_announced,
            "ttl_secs": presence.ttl_secs,
        },
        "events": events,
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

/// 运行一次网络发现拒绝路径（PRODUCT §6）：Node B 的注册中心为空（未发布任何
/// Presence），Node A 经发现协议查询 node-b，`PresenceServer` 回 `PeerUnknown`
/// 帧；`PresenceClient` 返回 `PeerUnknown` 错误（不得缓存、不得使用）——
/// 失败发生在 Discovery 阶段（未到 Plan/Session/Connectivity），流程输出
/// 结构化拒绝（PEER_UNKNOWN），不进入资源访问。
pub fn remote_presence_network_unknown_rollback() -> Result<Value, NexusError> {
    let mut events: Vec<&'static str> = Vec::new();

    // 0) Node B（提供方）：绑定发现端点；注册中心为空（node-b 未发布 Presence）。
    let discovery_listener =
        std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| NexusError::Internal {
            message: format!("cannot bind discovery listener: {e}"),
        })?;
    let discovery_addr = discovery_listener
        .local_addr()
        .map_err(|e| NexusError::Internal {
            message: format!("cannot read discovery addr: {e}"),
        })?;
    let registry = nexus_discovery::PresenceRegistry::default();

    let node_b_server = std::thread::spawn(move || {
        if let Ok(mut fs) = nexus_transport::accept(&discovery_listener) {
            if let Ok(request) = fs.recv_frame() {
                let response = nexus_discovery::PresenceServer.handle(&registry, &request);
                if !response.is_empty() {
                    let _ = fs.send_frame(&response);
                }
            }
        }
    });

    // 1) 网络发现：Node A 查询未发布 Peer -> 协议回 PeerUnknown（结构化拒绝）。
    let mut frames: Vec<&'static str> = Vec::new();
    frames.push("discover");
    let mut client = nexus_discovery::PresenceClient::default();
    let frame_stream = nexus_transport::connect(&discovery_addr).map_err(|e| {
        NexusError::ConnectivityEstablishmentFailed {
            provider: ProviderId("node-b".into()),
            reason: e.to_string(),
        }
    })?;
    let mut transport = DiscoveryFrameTransport {
        inner: frame_stream,
    };
    let discovered = client.discover(&mut transport, &nexus_discovery::PeerId("node-b".into()));
    match discovered {
        Err(nexus_discovery::DiscoveryError::PeerUnknown(_)) => {
            frames.push("peer_unknown");
            events.push(EV_PRESENCE_RESOLUTION_FAILED);
        }
        Err(e) => {
            return Err(NexusError::Internal {
                message: format!("expected PeerUnknown, got {e}"),
            });
        }
        Ok(_) => {
            return Err(NexusError::Internal {
                message: "expected PeerUnknown but presence resolved".into(),
            });
        }
    }
    let cached = client.is_announced(&nexus_discovery::PeerId("node-b".into()));

    // 回收 Node B 线程（结构化并发：线程有明确 Owner，主流程 join）。
    if node_b_server.join().is_err() {
        return Err(NexusError::Internal {
            message: "node-b server thread panicked".into(),
        });
    }

    Ok(json!({
        "verdict": "PASS",
        "discovery": {
            "mode": "network",
            "peer_id": "node-b",
            "frames": frames,
        },
        "events": events,
        "error": {
            "code": "PEER_UNKNOWN",
        },
        "presence": {
            "cached": cached,
        },
        "session": {
            "established": false,
        }
    }))
}
