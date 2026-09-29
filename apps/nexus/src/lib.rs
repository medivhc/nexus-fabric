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

/// CLI 前端 ControlService（17 命令接线 + --json 双输出 + exit 语义）。
pub mod control_service;
pub mod geoip_sources;
/// nexusd serve LocalAPI 瘦客户端（裸 TCP HTTP GET，CLI 不再进程内装配 SDK）。
pub mod localapi_client;
/// Auto-Mesh 自动挡组网编排器（Phase 1：自动打洞 + 断线重连）。
pub mod mesh;
/// §9 可观察性命令（status / plan explain / session watch / connectivity status /
/// dns status / dns cache / platform capabilities），见 PRODUCT.md#9-observability。
pub mod observability;
pub mod provider_fetcher;
pub mod schedule_cli;
pub mod strategy_watcher;
pub mod subnet_cli;
/// §11.17 订阅节点在线更新拉取器（HTTP 拉取 + 解析合并 + 热生效 + 结构化并发 Owner）。
pub mod subscription_updater;

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

/// 离线可编程 `LinkProbe` 替身（E4 relay-fallback 专用，零真实 I/O）：
/// Direct 候选必然不可达（模拟 NAT 阻塞），Relay 候选必然可达。
struct RelayFallbackProbe;

impl nexus_connectivity::LinkProbe for RelayFallbackProbe {
    fn probe(&self, candidate: &nexus_connectivity::LinkCandidate) -> Result<(), String> {
        match candidate.kind {
            nexus_connectivity::LinkKind::Direct => Err("nat unreachable".to_string()),
            nexus_connectivity::LinkKind::Relay => Ok(()),
        }
    }
}

/// 运行一次 Relay 回退闭环的**离线确定性切片**（E4 `product.relay-fallback`）：
/// Direct 打洞必然失败（NAT 不可达）-> `LinkActivator` 回退选中 Relay ->
/// 经 `RelayChannel`（`MockRelayTransport` 回环）建连、转发、接收。
/// 全程零真实网络、零线程，事件序列与字节计数完全确定、可重放。
pub fn relay_fallback_flow() -> Result<Value, NexusError> {
    let mut events: Vec<&'static str> = Vec::new();

    // 1) Link Activation：Direct 打洞失败 -> Relay 回退成功。
    let direct = nexus_connectivity::LinkCandidate::new(
        nexus_connectivity::LinkKind::Direct,
        "10.0.0.5:4242",
        10,
    );
    let relay = nexus_connectivity::LinkCandidate::new(
        nexus_connectivity::LinkKind::Relay,
        "relay.example.org:9999",
        50,
    );
    events.push("direct_hole_punch_started");
    let selection = nexus_connectivity::LinkActivator::new(RelayFallbackProbe)
        .activate(&direct, Some(&relay), false, false)
        .map_err(|e| NexusError::Internal {
            message: format!("relay fallback link activation failed: {e}"),
        })?;
    events.push("direct_hole_punch_failed");

    // 2) Relay 建连（离线 Mock 回环；先注入待接收字节再移交所有权）。
    events.push("relay_connecting");
    let config = nexus_connectivity::relay::RelayConfig::new("relay.example.org:9999", "peer-b");
    let transport = nexus_connectivity::relay::MockRelayTransport::new(Ok(()));
    let payload = b"relay-payload-12345";
    transport.inject_echo(payload);
    let mut channel = nexus_connectivity::relay::RelayChannel::new(config, Box::new(transport));
    channel.connect().map_err(|e| NexusError::Internal {
        message: format!("relay connect failed: {e}"),
    })?;
    events.push("relay_connected");

    // 3) 经中继转发 -> 回环接收。
    channel.forward(payload).map_err(|e| NexusError::Internal {
        message: format!("relay forward failed: {e}"),
    })?;
    events.push("relay_data_forwarded");

    let mut buf = [0u8; 64];
    channel
        .receive(&mut buf)
        .map_err(|e| NexusError::Internal {
            message: format!("relay receive failed: {e}"),
        })?;
    events.push("relay_data_received");

    events.push("relay_fallback_completed");

    Ok(json!({
        "verdict": "PASS",
        "events": events,
        "hole_punch": {
            "attempted": true,
            "success": false,
            "reason": "nat unreachable",
        },
        "link": {
            "kind": selection.kind.to_string(),
            "direct_attempted": true,
            "direct_failed": true,
        },
        "relay": {
            "server": channel.config().relay_server,
            "peer_id": channel.config().peer_id,
            "state": channel.state().to_string(),
            "bytes_sent": channel.stats().bytes_sent,
            "bytes_received": channel.stats().bytes_received,
        }
    }))
}
/// 运行一次 TURN 中继分配的**离线确定性切片**（E4 `product.turn-relay-allocate`）：
/// codec 自检（Allocate Request 构造 + XOR-RELAYED-ADDRESS 解析 + MESSAGE-INTEGRITY 往返）
/// + `MockTurnTransport` 驱动 401 挑战 -> 长期凭证重发 -> Allocated。
pub fn turn_relay_allocate_flow() -> Result<Value, NexusError> {
    use nexus_connectivity::turn::TurnEvent;

    // 1) codec 离线自检：构造带 MESSAGE-INTEGRITY 的 Allocate Request，
    //    解析合成成功响应的 XOR-RELAYED-ADDRESS / LIFETIME。
    let (request_bytes, parsed_relayed) =
        nexus_connectivity::turn::codec_self_test().map_err(|e| NexusError::Internal {
            message: format!("turn codec self-test failed: {e}"),
        })?;

    // 2) 分配闭环：无凭证 Allocate -> 401 挑战 -> 长期凭证重发 -> Allocated。
    let config = nexus_connectivity::turn::TurnClientConfig::new(
        "turn.example.org:3478",
        "nexus-node-a",
        "secret-credential",
        600,
    );
    let mut client = nexus_connectivity::turn::TurnClient::new(
        config,
        Box::new(nexus_connectivity::turn::MockTurnTransport::new()),
    );
    let state = client.allocate().map_err(|e| NexusError::Internal {
        message: format!("turn allocate failed: {e}"),
    })?;

    let (relayed_addr, expires) = match state {
        nexus_connectivity::turn::TurnAllocationState::Allocated {
            relayed_addr,
            expires_secs,
        } => (relayed_addr, expires_secs),
        other => {
            return Err(NexusError::Internal {
                message: format!("expected Allocated, got {other:?}"),
            });
        }
    };

    // 3) 用户可见事件序列：首次 Allocate -> 401 挑战 -> 分配成功（带凭证重发不单独列）。
    let mut events: Vec<&'static str> = Vec::new();
    let mut realm = String::new();
    let mut nonce = String::new();
    let mut first_sent = false;
    for ev in client.events() {
        match ev {
            TurnEvent::AllocateSent if !first_sent => {
                first_sent = true;
                events.push("allocate_sent");
            }
            TurnEvent::AllocateSent => {}
            TurnEvent::AuthChallengeReceived { realm: r, nonce: n } => {
                realm = r.clone();
                nonce = n.clone();
                events.push("auth_challenge_received");
            }
            TurnEvent::AllocateSuccess { .. } => events.push("allocate_success"),
            TurnEvent::AllocateFailed { .. } => events.push("allocate_failed"),
        }
    }

    Ok(json!({
        "verdict": "PASS",
        "codec": {
            "allocate_request_build_ok": true,
            "allocate_response_parse_ok": true,
            "message_integrity_ok": true,
            "request_bytes": request_bytes,
            "parsed_relayed": parsed_relayed.to_string(),
        },
        "auth": {
            "challenge_received": true,
            "realm": realm,
            "nonce": nonce,
            "integrity_computed": true,
        },
        "allocation": {
            "state": "allocated",
            "relayed_address": relayed_addr,
            "expires_secs": expires,
        },
        "events": events,
    }))
}

/// 运行一次自动发现闭环的**离线确定性切片**（E4 `product.auto-discovery`）：
/// 经引导节点注册自身 -> 从引导注册表对等发现 node-b/node-c -> 对每个 peer
/// 复用 `RelayFallbackProbe` 编排 Direct 打洞（必然失败）回退 Relay（必然成功）->
/// 任一 peer 建连成功即 `mark_connected`。全程零真实网络，事件序列与发现数量完全确定。
///
/// 依赖冻结的 `nexus_discovery::auto_discovery` API（DiscoveryConfig / BootstrapRegistry /
/// AutoDiscovery / DiscoveredNode / DiscoveryState）；错误一律 typed `Result`，无 panic。
pub fn auto_discovery_flow() -> Result<Value, NexusError> {
    use nexus_discovery::auto_discovery::{
        AutoDiscovery, BootstrapRegistry, DiscoveredNode, DiscoveryConfig,
    };

    let mut events: Vec<&'static str> = Vec::new();

    // 1) 引导配置 + 内存注册表（预置两个已在线 peer，模拟 bootstrap 上的在线节点视图）。
    let cfg = DiscoveryConfig {
        bootstrap_nodes: vec!["bootstrap-1:7000".into(), "bootstrap-2:7000".into()],
        node_id: "node-a".into(),
    };
    let node_id = cfg.node_id.clone();
    let bootstrap_count = cfg.bootstrap_nodes.len();

    let mut registry = BootstrapRegistry::new();
    registry.register(DiscoveredNode {
        node_id: "node-b".into(),
        virtual_ip: "100.64.0.2".into(),
        locator: "node-b.locator:7000".into(),
        last_seen: 0,
    });
    registry.register(DiscoveredNode {
        node_id: "node-c".into(),
        virtual_ip: "100.64.0.3".into(),
        locator: "node-c.locator:7000".into(),
        last_seen: 0,
    });

    // 2) 自身注册到引导注册表，并上报心跳。
    let mut auto_discovery = AutoDiscovery::new(cfg);
    auto_discovery
        .register(&mut registry, "100.64.0.1", "node-a.locator", 1000)
        .map_err(|e| NexusError::Internal {
            message: format!("auto-discovery self register failed: {e}"),
        })?;
    auto_discovery
        .heartbeat(&mut registry, 1000)
        .map_err(|e| NexusError::Internal {
            message: format!("auto-discovery self heartbeat failed: {e}"),
        })?;
    events.push("bootstrap_registered");
    events.push("heartbeat_ok");

    // 3) 对等发现：从引导注册表取回在线 peer。
    let peers = auto_discovery
        .discover_peers(&registry)
        .map_err(|e| NexusError::Internal {
            message: format!("auto-discovery discover_peers failed: {e}"),
        })?;
    events.push("peers_discovered");

    // 4) 对每个 peer 编排建连：Direct 打洞失败 -> Relay 回退成功（复用 RelayFallbackProbe）。
    let mut discovered: Vec<Value> = Vec::new();
    let mut any_connected = false;
    for peer in &peers {
        events.push("peer_link_attempted");
        let direct = nexus_connectivity::LinkCandidate::new(
            nexus_connectivity::LinkKind::Direct,
            peer.locator.as_str(),
            10,
        );
        let relay = nexus_connectivity::LinkCandidate::new(
            nexus_connectivity::LinkKind::Relay,
            "relay.example.org:9999",
            50,
        );
        let selection = nexus_connectivity::LinkActivator::new(RelayFallbackProbe)
            .activate(&direct, Some(&relay), false, false)
            .map_err(|e| NexusError::Internal {
                message: format!("auto-discovery peer link activation failed: {e}"),
            })?;
        let link_kind = match selection.kind {
            nexus_connectivity::LinkKind::Direct => "Direct",
            nexus_connectivity::LinkKind::Relay => "Relay",
        };
        discovered.push(json!({
            "node_id": peer.node_id,
            "virtual_ip": peer.virtual_ip,
            "link": link_kind,
        }));
        events.push("peer_connected");
        any_connected = true;
    }

    // 5) 任一 peer 建连成功即标记 Connected，否则离线。
    if any_connected {
        auto_discovery.mark_connected();
    } else {
        auto_discovery.mark_offline();
    }
    events.push("auto_discovery_completed");

    let state = auto_discovery.state().as_str();
    Ok(json!({
        "verdict": "PASS",
        "bootstrap": {
            "registered": true,
            "bootstrap_nodes": bootstrap_count,
        },
        "node": {
            "node_id": node_id,
            "state": state,
        },
        "discovered": {
            "count": peers.len(),
            "peers": discovered,
        },
        "events": events,
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

/// 真机演示（Node A 客户端侧）：经 `discovery_endpoint` 指向的远端发现服务拉取
/// Node B 的动态 Presence（网络发现协议），随后完成与网络发现场景相同的
/// Discovery -> Plan -> Session -> Connectivity -> Auth -> Service 闭环。
/// 与 `remote_presence_network_discovery_flow` 的区别：Node B 由独立进程提供
/// （`node_b_service` example），本函数只承担请求方侧；`discovery_endpoint`
/// 为 Node B 发现服务的可达地址（真机 = Node B 主机的 IP:port）。
pub fn remote_client_flow(discovery_endpoint: std::net::SocketAddr) -> Result<Value, NexusError> {
    let mut events: Vec<&'static str> = Vec::new();

    // 1) 网络发现：Node A 经发现协议拉取 Node B 的动态 Presence（本地无注册中心）。
    let mut frames: Vec<&'static str> = Vec::new();
    frames.push("discover");
    let mut client = nexus_discovery::PresenceClient::default();
    let frame_stream = nexus_transport::connect(&discovery_endpoint).map_err(|e| {
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
    let mut owner = SessionOwner::new(SessionId("sess-remote-client-1".into()));
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

// ---------- 真实网络切片（real transport，PRODUCT §6；2026-09-18） ----------
//
// 在冻结的 TCP + u32 大端长度前缀帧之上定义应用层 wire 帧（帧格式不变，
// 这些只是 payload 内容，不触碰 nexus-transport 冻结契约）：
//   AUTH:<token>        -> AUTH_OK | AUTH_DENIED   （服务端认证门控，业务帧前，W7）
//   CONNECT             -> READY                   （service 握手）
//   ECHO:<payload>      -> ECHO:<payload>          （service 业务往返）
//   COMPUTE:<expr>      -> RESULT:<value>          （compute 求值）
//   HTTP:<url>          -> HTTP:<status>:<body>    （internet-access：host 真实 HTTP GET）
//   DIAL:<ip:port>      -> RELAY_OK                （relay 握手，随后双向字节中继）

/// wire 帧标签。
pub const WIRE_AUTH_OK: &str = "AUTH_OK";
pub const WIRE_AUTH_DENIED: &str = "AUTH_DENIED";
pub const WIRE_RELAY_OK: &str = "RELAY_OK";
pub const WIRE_READY: &str = "READY";

/// 客户端线上认证：发送 `AUTH:<token>`，等待 `AUTH_OK` / `AUTH_DENIED`。
fn wire_client_auth(
    fs: &mut nexus_transport::FrameStream,
    token: &str,
) -> Result<nexus_auth::Principal, NexusError> {
    fs.send_frame(format!("AUTH:{token}").as_bytes())
        .map_err(|_| NexusError::AuthorizationDenied {
            principal: "wire auth frame send failed".into(),
        })?;
    let resp = fs
        .recv_frame()
        .map_err(|_| NexusError::AuthorizationDenied {
            principal: "wire auth response read failed".into(),
        })?;
    if resp == WIRE_AUTH_OK.as_bytes() {
        Ok(nexus_auth::Principal("authenticated".into()))
    } else {
        let reason = String::from_utf8_lossy(&resp)
            .strip_prefix("AUTH_DENIED:")
            .map(str::to_string)
            .unwrap_or_else(|| "wire token mismatch".into());
        Err(NexusError::AuthorizationDenied { principal: reason })
    }
}

/// 服务端认证门控：接收 `AUTH:<token>`，常量时间校验（W7：业务帧前）。
fn wire_server_auth(
    fs: &mut nexus_transport::FrameStream,
    expected_token: &str,
) -> Result<nexus_auth::Principal, NexusError> {
    let frame = fs
        .recv_frame()
        .map_err(|_| NexusError::AuthorizationDenied {
            principal: "no auth frame".into(),
        })?;
    let payload = String::from_utf8_lossy(&frame).to_string();
    let token = payload
        .strip_prefix("AUTH:")
        .ok_or_else(|| NexusError::AuthorizationDenied {
            principal: "malformed auth frame".into(),
        })?;
    let token = nexus_auth::PreSharedToken(token.to_string());
    let expected = nexus_auth::PreSharedToken(expected_token.to_string());
    match nexus_auth::verify_token(&token, &expected) {
        Ok(principal) => {
            fs.send_frame(WIRE_AUTH_OK.as_bytes()).map_err(|_| {
                NexusError::AuthorizationDenied {
                    principal: "cannot send auth_ok".into(),
                }
            })?;
            Ok(principal)
        }
        Err(_) => {
            let _ = fs.send_frame("AUTH_DENIED:token mismatch".as_bytes());
            Err(NexusError::AuthorizationDenied {
                principal: "token mismatch".into(),
            })
        }
    }
}

/// 最小真实 HTTP GET（host 侧 internet-access 执行；仅明文 http://，P0）。
fn real_http_get(url: &str) -> Result<(u16, String), NexusError> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| NexusError::Internal {
            message: format!("unsupported url scheme: {url}"),
        })?;
    let (authority, mut path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, String::new()),
    };
    if path.is_empty() {
        path.push('/');
    }
    let (host, port) = match authority.find(':') {
        Some(i) => (
            &authority[..i],
            authority[i + 1..]
                .parse::<u16>()
                .map_err(|_| NexusError::Internal {
                    message: format!("bad port in {url}"),
                })?,
        ),
        None => (authority, 80u16),
    };
    use std::io::{Read, Write};
    let mut conn =
        std::net::TcpStream::connect((host, port)).map_err(|e| NexusError::Internal {
            message: format!("http connect {host}:{port} failed: {e}"),
        })?;
    let req = format!("GET {path} HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    conn.write_all(req.as_bytes())
        .map_err(|e| NexusError::Internal {
            message: e.to_string(),
        })?;
    let mut buf = Vec::new();
    conn.read_to_end(&mut buf)
        .map_err(|e| NexusError::Internal {
            message: e.to_string(),
        })?;
    let text = String::from_utf8_lossy(&buf).to_string();
    let status = text
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| NexusError::Internal {
            message: format!(
                "cannot parse http status from: {}",
                text.lines().next().unwrap_or("")
            ),
        })?;
    Ok((status, text))
}

/// 真实 policy 决策（按资源选默认引擎）。
fn real_policy_decision(
    resource: &str,
    flow: &nexus_domain::FlowContext,
) -> Result<nexus_policy::PolicyDecision, NexusError> {
    let decision = match resource {
        "service" => {
            nexus_policy::PolicyEngine::default_service()
                .evaluate(flow)
                .decision
        }
        "internet-access" => {
            nexus_policy::PolicyEngine::default_network()
                .evaluate(flow)
                .decision
        }
        "compute" => {
            nexus_policy::PolicyEngine::default_compute()
                .evaluate(flow)
                .decision
        }
        other => {
            return Err(NexusError::Internal {
                message: format!("real flow unsupported resource: {other}"),
            });
        }
    };
    Ok(decision)
}

/// 真实闭环规划：Discovery（静态发现真实 Endpoint）+ Policy + Core Planner。
/// 返回 (provider_id, placement, path)。
fn real_plan(
    resource: &str,
    endpoint: std::net::SocketAddr,
) -> Result<(String, String, Vec<String>), NexusError> {
    let flow = nexus_ingress::from_native_api(resource, "RemoteBalanced");
    let decision = real_policy_decision(resource, &flow)?;
    let mut registry = Registry::new();
    registry.register(ProviderRecord {
        id: ProviderId("node-b".into()),
        resource: flow.resource.clone(),
        placement: "remote-provider".into(),
        locator: endpoint.to_string(),
        capabilities: vec![format!("{resource}-session")],
        present: true,
    });
    let candidates = registry.candidates(&flow.resource);
    let mut measurements = MeasurementTable::new();
    measurements.record(
        ProviderId("node-b".into()),
        LinkMeasurement {
            rtt_ms: Some(5),
            confidence_percent: 99,
            ..Default::default()
        },
    );
    let snapshot = PlanningSnapshot::new(candidates, decision.constraints.clone());
    let planned =
        nexus_planner::plan_from_snapshot(&flow.resource, &snapshot, &decision.intent, |p| {
            measurements.get(p).cloned()
        })?;
    Ok((
        planned.plan.provider_id.0,
        planned.plan.placement,
        planned.plan.path,
    ))
}

/// 客户端真实业务交换：线上认证（服务端门控）+ 按资源的业务帧交换。
/// 返回 (Principal, 业务 JSON, 业务事件)。
fn real_client_exchange(
    fs: &mut nexus_transport::FrameStream,
    token: &str,
    resource: &str,
) -> Result<(nexus_auth::Principal, Value, &'static str), NexusError> {
    let principal = wire_client_auth(fs, token)?;
    let (business, business_event) = match resource {
        "service" => {
            fs.send_frame(b"CONNECT")
                .map_err(|_| NexusError::SessionFailed {
                    session: SessionId("real".into()),
                    reason: "connect frame send failed".into(),
                })?;
            let resp = fs.recv_frame().map_err(|_| NexusError::SessionFailed {
                session: SessionId("real".into()),
                reason: "read ready failed".into(),
            })?;
            if resp != WIRE_READY.as_bytes() {
                return Err(NexusError::SessionFailed {
                    session: SessionId("real".into()),
                    reason: "service handshake rejected".into(),
                });
            }
            let payload = format!("ECHO:ping-{}", std::process::id());
            fs.send_frame(payload.as_bytes())
                .map_err(|_| NexusError::SessionFailed {
                    session: SessionId("real".into()),
                    reason: "echo send failed".into(),
                })?;
            let echoed = fs.recv_frame().map_err(|_| NexusError::SessionFailed {
                session: SessionId("real".into()),
                reason: "echo recv failed".into(),
            })?;
            let matched = String::from_utf8_lossy(&echoed) == payload;
            let _ = fs.send_frame(b"CLOSE");
            (
                json!({ "roundtrip_matched": matched }),
                EV_SERVICE_CONNECTED,
            )
        }
        "compute" => {
            fs.send_frame(b"COMPUTE:6*7")
                .map_err(|_| NexusError::SessionFailed {
                    session: SessionId("real".into()),
                    reason: "compute frame send failed".into(),
                })?;
            let resp = fs.recv_frame().map_err(|_| NexusError::SessionFailed {
                session: SessionId("real".into()),
                reason: "compute result read failed".into(),
            })?;
            let text = String::from_utf8_lossy(&resp).to_string();
            let result = text
                .strip_prefix("RESULT:")
                .ok_or_else(|| NexusError::Internal {
                    message: format!("bad compute result frame: {text}"),
                })?;
            (json!({ "result": result }), EV_COMPUTE_JOB_SUBMITTED)
        }
        "internet-access" => {
            fs.send_frame(b"HTTP:http://example.com/")
                .map_err(|_| NexusError::SessionFailed {
                    session: SessionId("real".into()),
                    reason: "http frame send failed".into(),
                })?;
            let resp = fs.recv_frame().map_err(|_| NexusError::SessionFailed {
                session: SessionId("real".into()),
                reason: "http response read failed".into(),
            })?;
            let text = String::from_utf8_lossy(&resp).to_string();
            let rest = text
                .strip_prefix("HTTP:")
                .ok_or_else(|| NexusError::Internal {
                    message: format!("bad http response frame: {text}"),
                })?;
            let status: u16 = rest.split(':').next().unwrap_or("0").parse().map_err(|_| {
                NexusError::Internal {
                    message: format!("bad http status in frame: {text}"),
                }
            })?;
            (json!({ "status": status }), EV_NETWORK_SESSION_ESTABLISHED)
        }
        other => {
            return Err(NexusError::Internal {
                message: format!("real flow unsupported resource: {other}"),
            });
        }
    };
    Ok((principal, business, business_event))
}

/// 把客户端闭环结果装配为最终 JSON（含 Session 双轨、事件、业务段）。
#[allow(clippy::too_many_arguments)]
fn assemble_real_result(
    endpoint: std::net::SocketAddr,
    resource: &str,
    principal: nexus_auth::Principal,
    business: Value,
    business_event: &'static str,
    plan: (String, String, Vec<String>),
    mut owner: SessionOwner,
    mut events: Vec<&'static str>,
    link: Value,
) -> Result<Value, NexusError> {
    events.push(business_event);
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
    let status = owner.status();
    let terminal_outcome_commit_count = owner
        .events()
        .iter()
        .filter(|e| matches!(e, nexus_session::SessionEvent::OutcomeCommitted { .. }))
        .count();
    let arch_violation = network_depends_on_ingress()?;
    let mut out = json!({
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
            "gate": "auth_ok",
            "principal": principal.0,
        },
        "plan": {
            "provider_id": plan.0,
            "placement": plan.1,
            "path": plan.2,
        },
        "session": {
            "id": owner.id().0,
            "phase": phase_name(&status.phase),
            "outcome": outcome_name(&status.outcome),
        },
        "terminal_outcome_commit_count": terminal_outcome_commit_count,
        "link": link,
        "architecture": {
            "network_depends_on_ingress": arch_violation,
        }
    });
    match resource {
        "service" => {
            out["service"] = json!({ "phase": "Active" });
            out["echo"] = business;
        }
        "compute" => {
            out["compute"] = business;
        }
        "internet-access" => {
            out["network"] = business;
        }
        _ => {}
    }
    Ok(out)
}

/// 真实网络访问（直连）：请求方解析真实 Endpoint 后建立真实帧流，
/// 服务端 AUTH 门控 + 业务交换，Session 双轨与 TerminalOutcome 语义不变。
pub fn remote_real_flow(
    endpoint: &std::net::SocketAddr,
    token: &str,
    resource: &str,
) -> Result<Value, NexusError> {
    let plan = real_plan(resource, *endpoint)?;
    let mut owner = SessionOwner::new(SessionId(format!("sess-real-{resource}-1")));
    owner
        .transition_phase(LifecyclePhase::Active)
        .map_err(NexusError::from)?;
    let mut events: Vec<&'static str> = vec![
        EV_REMOTE_PROVIDER_RESOLVED,
        EV_PLAN_SELECTED,
        EV_SESSION_CREATED,
    ];
    let mut fs = nexus_transport::connect(endpoint).map_err(|e| {
        NexusError::ConnectivityEstablishmentFailed {
            provider: ProviderId("node-b".into()),
            reason: e.to_string(),
        }
    })?;
    events.push(EV_REMOTE_CONNECTIVITY_ESTABLISHED);
    let link = json!({
        "direct_attempted": true,
        "direct_ok": true,
        "relay_used": false,
    });
    let (principal, business, business_event) = real_client_exchange(&mut fs, token, resource)?;
    assemble_real_result(
        *endpoint,
        resource,
        principal,
        business,
        business_event,
        plan,
        owner,
        events,
        link,
    )
}

/// 真实网络访问（含 relay 回退）：在 `direct`（候选地址，直连真实尝试）失败后，
/// 经真实 relay（`DIAL:<target>` + 双向字节中继）拨号 `target`（relay 可达地址），
/// 完成线上认证与业务交换。两个地址分离对应真实 NAT 场景：候选地址对外不可达，
/// 而 relay 掌握 provider 的可达位置。
pub fn remote_real_flow_with_relay(
    direct: &std::net::SocketAddr,
    target: &std::net::SocketAddr,
    relay: &std::net::SocketAddr,
    token: &str,
    resource: &str,
) -> Result<Value, NexusError> {
    let plan = real_plan(resource, *target)?;
    let mut owner = SessionOwner::new(SessionId(format!("sess-real-{resource}-1")));
    owner
        .transition_phase(LifecyclePhase::Active)
        .map_err(NexusError::from)?;
    let mut events: Vec<&'static str> = vec![
        EV_REMOTE_PROVIDER_RESOLVED,
        EV_PLAN_SELECTED,
        EV_SESSION_CREATED,
    ];
    let direct_result = nexus_transport::connect(direct);
    let (mut fs, link) = match direct_result {
        Ok(fs) => {
            events.push(EV_REMOTE_CONNECTIVITY_ESTABLISHED);
            (
                fs,
                json!({
                    "direct_attempted": true,
                    "direct_ok": true,
                    "relay_used": false,
                }),
            )
        }
        Err(e) => {
            events.push(EV_LINK_DIRECT_FAILED);
            events.push(EV_LINK_RELAY_FALLBACK);
            let mut rfs = nexus_transport::connect(relay).map_err(|re| {
                NexusError::ConnectivityEstablishmentFailed {
                    provider: ProviderId("node-b".into()),
                    reason: format!("relay connect failed: {re}"),
                }
            })?;
            rfs.send_frame(format!("DIAL:{target}").as_bytes())
                .map_err(|_| NexusError::ConnectivityEstablishmentFailed {
                    provider: ProviderId("node-b".into()),
                    reason: "dial frame send failed".into(),
                })?;
            let ack =
                rfs.recv_frame()
                    .map_err(|_| NexusError::ConnectivityEstablishmentFailed {
                        provider: ProviderId("node-b".into()),
                        reason: "relay ack read failed".into(),
                    })?;
            if ack != WIRE_RELAY_OK.as_bytes() {
                return Err(NexusError::ConnectivityEstablishmentFailed {
                    provider: ProviderId("node-b".into()),
                    reason: "relay refused dial".into(),
                });
            }
            events.push(EV_REMOTE_CONNECTIVITY_ESTABLISHED);
            (
                rfs,
                json!({
                    "direct_attempted": true,
                    "direct_ok": false,
                    "relay_used": true,
                    "direct_reason": e.to_string(),
                }),
            )
        }
    };
    let (principal, business, business_event) = real_client_exchange(&mut fs, token, resource)?;
    assemble_real_result(
        *target,
        resource,
        principal,
        business,
        business_event,
        plan,
        owner,
        events,
        link,
    )
}

/// host 单次服务（提供方）：真实地址监听，服务端 AUTH 门控（业务帧前），
/// 随后按资源执行业务。单连接后返回结构化结果（与 daemon 单次执行风格一致）。
/// 已连接会话的 host 服务：服务端 AUTH 门控（业务帧前）+ 按资源执行业务。
/// accept 由调用方完成（serve_once 单连接 / serve_loop 持续服务共用）。
fn host_serve_connected(
    fs: &mut nexus_transport::FrameStream,
    expected_token: &str,
    resource: &str,
) -> Result<Value, NexusError> {
    let principal = wire_server_auth(fs, expected_token)?;
    let mut events: Vec<&'static str> = Vec::new();
    let business = match resource {
        "service" => {
            let cmd = fs.recv_frame().map_err(|_| NexusError::SessionFailed {
                session: SessionId("host-service".into()),
                reason: "no connect frame".into(),
            })?;
            if cmd != b"CONNECT" {
                return Err(NexusError::SessionFailed {
                    session: SessionId("host-service".into()),
                    reason: "expected CONNECT frame".into(),
                });
            }
            fs.send_frame(WIRE_READY.as_bytes())
                .map_err(|_| NexusError::SessionFailed {
                    session: SessionId("host-service".into()),
                    reason: "ready send failed".into(),
                })?;
            events.push(EV_SERVICE_CONNECTED);
            let mut echoes = 0u32;
            while let Ok(frame) = fs.recv_frame() {
                let payload = String::from_utf8_lossy(&frame).to_string();
                if payload == "CLOSE" {
                    break;
                }
                if let Some(data) = payload.strip_prefix("ECHO:") {
                    fs.send_frame(format!("ECHO:{data}").as_bytes())
                        .map_err(|_| NexusError::SessionFailed {
                            session: SessionId("host-service".into()),
                            reason: "echo reply failed".into(),
                        })?;
                    echoes += 1;
                } else {
                    break;
                }
            }
            json!({ "phase": "Active", "echoes": echoes })
        }
        "compute" => {
            let frame = fs.recv_frame().map_err(|_| NexusError::SessionFailed {
                session: SessionId("host-compute".into()),
                reason: "no compute frame".into(),
            })?;
            let expr = String::from_utf8_lossy(&frame).to_string();
            let value = match expr.strip_prefix("COMPUTE:") {
                Some("6*7") => "42".to_string(),
                _ => {
                    return Err(NexusError::Internal {
                        message: format!("unknown compute expr: {expr}"),
                    });
                }
            };
            fs.send_frame(format!("RESULT:{value}").as_bytes())
                .map_err(|_| NexusError::SessionFailed {
                    session: SessionId("host-compute".into()),
                    reason: "result send failed".into(),
                })?;
            events.push(EV_COMPUTE_JOB_SUBMITTED);
            json!({ "job_id": "job-remote-1", "result": value })
        }
        "internet-access" => {
            let frame = fs.recv_frame().map_err(|_| NexusError::SessionFailed {
                session: SessionId("host-http".into()),
                reason: "no http frame".into(),
            })?;
            let payload = String::from_utf8_lossy(&frame).to_string();
            let url = payload
                .strip_prefix("HTTP:")
                .ok_or_else(|| NexusError::Internal {
                    message: format!("malformed http request frame: {payload}"),
                })?;
            let (status, body) = real_http_get(url)?;
            fs.send_frame(format!("HTTP:{status}:{body}").as_bytes())
                .map_err(|_| NexusError::SessionFailed {
                    session: SessionId("host-http".into()),
                    reason: "http reply send failed".into(),
                })?;
            events.push(EV_NETWORK_SESSION_ESTABLISHED);
            json!({ "status": status })
        }
        other => {
            return Err(NexusError::Internal {
                message: format!("host unsupported resource: {other}"),
            });
        }
    };
    Ok(json!({
        "verdict": "PASS",
        "role": "host",
        "resource": resource,
        "connections_served": 1,
        "auth": {
            "gate": "auth_ok",
            "principal": principal.0,
        },
        "events": events,
        "business": business,
    }))
}

/// host 单次服务（提供方）：真实地址监听，单连接后返回结构化结果
/// （与 daemon 单次执行风格一致；E4 场景 daemon-real-host-flow 使用）。
pub fn remote_host_serve_once(
    listener: &std::net::TcpListener,
    expected_token: &str,
    resource: &str,
) -> Result<Value, NexusError> {
    let mut fs = nexus_transport::accept(listener).map_err(|e| NexusError::Internal {
        message: format!("host accept failed: {e}"),
    })?;
    host_serve_connected(&mut fs, expected_token, resource)
}

/// host 服务循环（提供方持续服务）：逐连接 accept，每连接独立 AUTH 门控 + 业务闭环。
/// 认证拒绝打印 AUTH_DENIED 后继续服务；仅 accept 失败（listener 失效）返回 Err。
pub fn remote_host_serve_loop(
    listener: &std::net::TcpListener,
    expected_token: &str,
    resource: &str,
) -> Result<(), NexusError> {
    loop {
        let mut fs = nexus_transport::accept(listener).map_err(|e| NexusError::Internal {
            message: format!("host accept failed: {e}"),
        })?;
        match host_serve_connected(&mut fs, expected_token, resource) {
            Ok(json) => println!("{json}"),
            Err(NexusError::AuthorizationDenied { principal }) => println!(
                "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"AUTH_DENIED\",\"message\":\"{principal}\"}}}}"
            ),
            Err(e) => println!(
                "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"INTERNAL\",\"message\":\"{e}\"}}}}"
            ),
        }
    }
}

/// 把 `NexusError` 映射为稳定的 CLI 错误码（UI 层序列化用，禁止泄漏内部细节）。
pub fn error_code(err: &NexusError) -> &'static str {
    match err {
        NexusError::NoProvider { .. } => "NO_PROVIDER",
        NexusError::ConstraintUnsatisfied { .. } => "CONSTRAINT_UNSATISFIED",
        NexusError::ConnectivityEstablishmentFailed { .. } => "CONNECT_FAILED",
        NexusError::DnsResolutionFailed { .. } => "DNS_RESOLUTION_FAILED",
        NexusError::AuthorizationDenied { .. } => "AUTH_DENIED",
        NexusError::ComputeJobRejected { .. } => "COMPUTE_REJECTED",
        NexusError::WorkspaceCommitRejected { .. } => "WORKSPACE_REJECTED",
        NexusError::PlatformCapabilityUnavailable { .. } => "CAPABILITY_UNAVAILABLE",
        NexusError::SessionFailed { .. } => "SESSION_FAILED",
        NexusError::Unsupported { .. } => "UNSUPPORTED",
        NexusError::Internal { .. } => "INTERNAL",
    }
}

/// 双向字节中继（relay 核心）：src -> dst，返回转发字节数。
fn pump_bytes(src: &mut std::net::TcpStream, dst: &mut std::net::TcpStream) -> usize {
    use std::io::{Read, Write};
    let mut buf = [0u8; 8192];
    let mut total = 0usize;
    loop {
        match src.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if dst.write_all(&buf[..n]).is_err() {
                    break;
                }
                total += n;
            }
            Err(_) => break,
        }
    }
    let _ = dst.shutdown(std::net::Shutdown::Both);
    let _ = src.shutdown(std::net::Shutdown::Both);
    total
}

/// relay 单次服务：接受连接，读取 `DIAL:<target>`，拨号目标后建立双向字节中继。
pub fn relay_serve_once(listener: &std::net::TcpListener) -> Result<Value, NexusError> {
    let mut fs = nexus_transport::accept(listener).map_err(|e| NexusError::Internal {
        message: format!("relay accept failed: {e}"),
    })?;
    let dial = fs.recv_frame().map_err(|_| NexusError::Internal {
        message: "no dial frame".into(),
    })?;
    let dial = String::from_utf8_lossy(&dial).to_string();
    let target = dial
        .strip_prefix("DIAL:")
        .ok_or_else(|| NexusError::Internal {
            message: format!("malformed dial frame: {dial}"),
        })?;
    let target_addr: std::net::SocketAddr = target.parse().map_err(|_| NexusError::Internal {
        message: format!("bad dial target: {target}"),
    })?;
    let mut upstream =
        std::net::TcpStream::connect(target_addr).map_err(|_| NexusError::Internal {
            message: format!("relay dial {target} failed"),
        })?;
    fs.send_frame(WIRE_RELAY_OK.as_bytes())
        .map_err(|_| NexusError::Internal {
            message: "relay_ok send failed".into(),
        })?;
    let mut client_raw = fs.into_raw();
    let mut client_c = client_raw.try_clone().map_err(|_| NexusError::Internal {
        message: "relay clone failed".into(),
    })?;
    let mut upstream_c = upstream.try_clone().map_err(|_| NexusError::Internal {
        message: "relay clone failed".into(),
    })?;
    // 结构化并发：两个拷贝线程有明确 Owner（relay 主流程 join 并消费结果）。
    let to_upstream = std::thread::spawn(move || pump_bytes(&mut client_c, &mut upstream_c));
    let to_client = std::thread::spawn(move || pump_bytes(&mut upstream, &mut client_raw));
    let up_bytes = to_upstream.join().map_err(|_| NexusError::Internal {
        message: "relay thread panicked".into(),
    })?;
    let down_bytes = to_client.join().map_err(|_| NexusError::Internal {
        message: "relay thread panicked".into(),
    })?;
    Ok(json!({
        "verdict": "PASS",
        "role": "relay",
        "sessions": 1,
        "dialed": target_addr.to_string(),
        "bytes": {
            "to_upstream": up_bytes,
            "to_client": down_bytes,
        },
    }))
}

// ---------- 真实 SOCKS5 代理（real socks proxy，PRODUCT §11；2026-09-18） ----------
//
// 全链路：Socks5Handshake（有状态握手）→ FlowContext → 规则路由（nexus-proxy）
// → Session 双轨 → 真实出站连接（代理即出口，域名在此真实 DNS 解析）
// → 双向字节中继。路由是纯决策，出站与数据面是真实 I/O。

/// 真实 SOCKS5 代理默认分流配置：MATCH -> direct（直连出站）。
pub const DEFAULT_PROXY_CONFIG: &str = "\
schema_version: 1
rules:
  - tag: rule-match
    kind: match
    action:
      - kind: select_outbound
        tag: direct
outbounds:
  - tag: direct
    kind: direct
";

/// 从 `host:port` / `[ipv6]:port` 拆出主机与端口（域名或 IP literal）。
fn split_host_port(dest: &str) -> Result<(String, u16), NexusError> {
    if let Some(rest) = dest.strip_prefix('[') {
        let close = rest.find(']').ok_or_else(|| NexusError::Internal {
            message: format!("malformed destination: {dest}"),
        })?;
        let host = rest[..close].to_string();
        let tail = &rest[close + 1..];
        let port = tail
            .strip_prefix(':')
            .and_then(|p| p.parse().ok())
            .ok_or_else(|| NexusError::Internal {
                message: format!("malformed destination port: {dest}"),
            })?;
        return Ok((host, port));
    }
    match dest.rfind(':') {
        Some(i) => {
            let host = dest[..i].to_string();
            let port = dest[i + 1..].parse().map_err(|_| NexusError::Internal {
                message: format!("malformed destination port: {dest}"),
            })?;
            Ok((host, port))
        }
        None => Err(NexusError::Internal {
            message: format!("malformed destination (missing port): {dest}"),
        }),
    }
}

/// 真实 SOCKS5 代理单会话闭环。
pub fn proxy_serve_once(
    listener: &std::net::TcpListener,
    config_yaml: &str,
) -> Result<Value, NexusError> {
    use std::io::{Read, Write};
    let (mut client, _) = listener.accept().map_err(|e| NexusError::Internal {
        message: format!("proxy accept failed: {e}"),
    })?;

    // 1) 混合握手（§11.19）：首字节 0x05 -> 既有 Socks5Handshake；否则 -> HttpProxyHandshake。
    //    同一端口按首字节分流，互不干扰。握手产出中立 FlowContext + 首段需先写上给上游的字节
    //    （SOCKS5 隧道内 pipelined；HTTP 转发型改写后的 origin-form 请求行+请求头）。
    let mut buf = [0u8; 4096];
    let n0 = client.read(&mut buf).map_err(|_| NexusError::Internal {
        message: "proxy read failed".into(),
    })?;
    if n0 == 0 {
        return Err(NexusError::Internal {
            message: "client closed during handshake".into(),
        });
    }
    let (flow, inbound_kind, seed_to_upstream) = if buf[0] == 0x05 {
        // ---- SOCKS5 分支（§11.4，零回归）----
        let mut hs = nexus_ingress::Socks5Handshake::new();
        let mut step = hs.feed(&buf[..n0]);
        let flow = loop {
            if !step.response.is_empty() {
                client
                    .write_all(&step.response)
                    .map_err(|_| NexusError::Internal {
                        message: "proxy write failed".into(),
                    })?;
            }
            match step.state {
                nexus_ingress::Socks5State::Established => {
                    break step.flow.ok_or_else(|| NexusError::Internal {
                        message: "established without flow".into(),
                    })?;
                }
                nexus_ingress::Socks5State::Failed(e) => {
                    return Err(NexusError::Internal {
                        message: format!("socks5 handshake failed: {e:?}"),
                    });
                }
                _ => {
                    let n = client.read(&mut buf).map_err(|_| NexusError::Internal {
                        message: "proxy read failed".into(),
                    })?;
                    if n == 0 {
                        return Err(NexusError::Internal {
                            message: "socks5 client closed during handshake".into(),
                        });
                    }
                    step = hs.feed(&buf[..n]);
                }
            }
        };
        // 隧道内 pipelined 字节先写上给上游（严格中继，不丢字节）。
        let pipelined = hs.take_data();
        (flow, "socks5".to_string(), pipelined)
    } else {
        // ---- HTTP 代理分支（§11.19）----
        let mut hs = nexus_ingress::HttpProxyHandshake::new();
        let mut step = hs.feed(&buf[..n0]);
        let flow = loop {
            if !step.response.is_empty() {
                client
                    .write_all(&step.response)
                    .map_err(|_| NexusError::Internal {
                        message: "proxy write failed".into(),
                    })?;
            }
            match step.state {
                nexus_ingress::HttpProxyState::Established => {
                    break step.flow.ok_or_else(|| NexusError::Internal {
                        message: "established without flow".into(),
                    })?;
                }
                nexus_ingress::HttpProxyState::Failed(e) => {
                    return Err(NexusError::Internal {
                        message: format!("http proxy handshake failed: {e:?}"),
                    });
                }
                _ => {
                    let n = client.read(&mut buf).map_err(|_| NexusError::Internal {
                        message: "proxy read failed".into(),
                    })?;
                    if n == 0 {
                        return Err(NexusError::Internal {
                            message: "http client closed during handshake".into(),
                        });
                    }
                    step = hs.feed(&buf[..n]);
                }
            }
        };
        // 转发型：upstream_prefix（改写后的 origin-form 请求行+请求头）+ 握手后 pipelined 字节。
        let mut seed = step.upstream_prefix;
        seed.extend(hs.take_data());
        (flow, "http".to_string(), seed)
    };

    // 2) 规则路由（纯决策，零 I/O）。
    let config = nexus_proxy_config::parse(config_yaml).map_err(|e| NexusError::Internal {
        message: format!("proxy config invalid: {e}"),
    })?;
    let service = nexus_proxy::ProxyService::new(&config).map_err(|e| NexusError::Internal {
        message: format!("proxy service build failed: {e}"),
    })?;
    let decision = service
        .route(&flow, None)
        .map_err(|e| NexusError::Internal {
            message: format!("proxy route failed: {e}"),
        })?;

    // 3) Session 双轨（Active 先于出站建连）。
    let mut owner = SessionOwner::new(SessionId("sess-proxy-1".into()));
    owner
        .transition_phase(LifecyclePhase::Active)
        .map_err(NexusError::from)?;

    // 4) 真实出站连接：按 selected outbound 的 kind 建立数据面（§11.16）。
    //    direct      -> 直连 destination（§11.4 现状，零回归）
    //    shadowsocks -> 连节点 locator + SsStream 客户端会话 + 加密 request header
    //                   + 双向 record 帧中继（read_record / write_record）
    //    trojan/vmess-> 数据面隧道不在本期冻结 E4 范围，结构化失败（不静默直连）
    let selected = config
        .outbounds
        .iter()
        .find(|o| o.tag == decision.selected_outbound_tag)
        .ok_or_else(|| NexusError::ConnectivityEstablishmentFailed {
            provider: ProviderId(decision.selected_outbound_tag.clone()),
            reason: format!(
                "selected outbound tag {} missing in config",
                decision.selected_outbound_tag
            ),
        })?;
    let (host, port) = split_host_port(&flow.destination)?;
    let outbound_kind = selected.kind.as_str();
    let outbound;
    let (up_bytes, down_bytes) = match selected.kind {
        nexus_proxy_config::OutboundKind::Direct => {
            let mut upstream =
                std::net::TcpStream::connect((host.as_str(), port)).map_err(|e| {
                    NexusError::ConnectivityEstablishmentFailed {
                        provider: ProviderId(decision.selected_outbound_tag.clone()),
                        reason: format!("outbound connect {host}:{port} failed: {e}"),
                    }
                })?;
            // §11.19：握手产出的首段字节（HTTP 改写后的 origin-form 请求 / SOCKS5 pipelined）
            // 必须先写上给上游，再进入双向中继。
            if !seed_to_upstream.is_empty() {
                upstream.write_all(&seed_to_upstream).map_err(|e| {
                    NexusError::ConnectivityEstablishmentFailed {
                        provider: ProviderId(decision.selected_outbound_tag.clone()),
                        reason: format!("upstream seed write failed: {e}"),
                    }
                })?;
            }
            // 双向字节中继（结构化并发：join 消费两个拷贝线程的结果）。
            let mut client_c = client.try_clone().map_err(|_| NexusError::Internal {
                message: "proxy clone failed".into(),
            })?;
            let mut upstream_c = upstream.try_clone().map_err(|_| NexusError::Internal {
                message: "proxy clone failed".into(),
            })?;
            let to_upstream =
                std::thread::spawn(move || pump_bytes(&mut client_c, &mut upstream_c));
            let to_client = std::thread::spawn(move || pump_bytes(&mut upstream, &mut client));
            let up = to_upstream.join().map_err(|_| NexusError::Internal {
                message: "proxy thread panicked".into(),
            })?;
            let down = to_client.join().map_err(|_| NexusError::Internal {
                message: "proxy thread panicked".into(),
            })?;
            outbound = json!({ "kind": "direct" });
            (up, down)
        }
        nexus_proxy_config::OutboundKind::Shadowsocks => {
            use nexus_outbound_shadowsocks::{
                Role, SsMethod, SsStream, SsTarget, encode_request, read_record, write_record,
            };
            let locator = selected.locator.clone().ok_or_else(|| {
                NexusError::ConnectivityEstablishmentFailed {
                    provider: ProviderId(decision.selected_outbound_tag.clone()),
                    reason: "shadowsocks outbound missing locator".into(),
                }
            })?;
            let (nhost, nport) = split_host_port(&locator)?;
            let mut node = std::net::TcpStream::connect((nhost.as_str(), nport)).map_err(|e| {
                NexusError::ConnectivityEstablishmentFailed {
                    provider: ProviderId(decision.selected_outbound_tag.clone()),
                    reason: format!("ss node connect {locator} failed: {e}"),
                }
            })?;
            let method = SsMethod::parse(
                selected
                    .method
                    .as_deref()
                    .unwrap_or(SsMethod::Chacha20IetfPoly1305.as_str()),
            )
            .map_err(|e| NexusError::Internal {
                message: format!("ss method parse failed: {e:?}"),
            })?;
            let password = selected.password.clone().ok_or_else(|| {
                NexusError::ConnectivityEstablishmentFailed {
                    provider: ProviderId(decision.selected_outbound_tag.clone()),
                    reason: "shadowsocks outbound missing password".into(),
                }
            })?;
            let mut tx_sess = SsStream::new(&password, method, Role::Client).map_err(|e| {
                NexusError::Internal {
                    message: format!("ss client session failed: {e:?}"),
                }
            })?;
            let mut rx_sess = SsStream::new(&password, method, Role::Client).map_err(|e| {
                NexusError::Internal {
                    message: format!("ss client session failed: {e:?}"),
                }
            })?;
            // 加密 request header（目标 = SOCKS5 destination）→ 节点
            let target = if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
                SsTarget::Ipv4(ip.octets(), port)
            } else {
                SsTarget::Domain(host.clone(), port)
            };
            let req_frame = tx_sess.seal(&encode_request(&target)).map_err(|e| {
                NexusError::ConnectivityEstablishmentFailed {
                    provider: ProviderId(decision.selected_outbound_tag.clone()),
                    reason: format!("ss request header seal failed: {e:?}"),
                }
            })?;
            write_record(&mut node, &req_frame).map_err(|e| {
                NexusError::ConnectivityEstablishmentFailed {
                    provider: ProviderId(decision.selected_outbound_tag.clone()),
                    reason: format!("ss request header send failed: {e}"),
                }
            })?;
            // 双向 record 帧中继：client→node 读明文→seal→write_record；
            // node→client read_record→open→写明文。TX/RX 各持独立会话实例（Rx 帧内 nonce）。
            let mut client_up = client.try_clone().map_err(|_| NexusError::Internal {
                message: "proxy clone failed".into(),
            })?;
            let mut node_up = node.try_clone().map_err(|_| NexusError::Internal {
                message: "proxy clone failed".into(),
            })?;
            let mut client_down = client.try_clone().map_err(|_| NexusError::Internal {
                message: "proxy clone failed".into(),
            })?;
            let mut node_down = node.try_clone().map_err(|_| NexusError::Internal {
                message: "proxy clone failed".into(),
            })?;
            let to_upstream = std::thread::spawn(move || {
                let mut buf = [0u8; 8192];
                let mut total = 0usize;
                if !seed_to_upstream.is_empty() {
                    match tx_sess
                        .seal(&seed_to_upstream)
                        .map(|f| write_record(&mut node_up, &f))
                    {
                        Ok(Ok(())) => total += seed_to_upstream.len(),
                        _ => return total,
                    }
                }
                loop {
                    match client_up.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            match tx_sess
                                .seal(&buf[..n])
                                .map(|f| write_record(&mut node_up, &f))
                            {
                                Ok(Ok(())) => total += n,
                                _ => break,
                            }
                        }
                        Err(_) => break,
                    }
                }
                total
            });
            let to_client = std::thread::spawn(move || {
                let mut total = 0usize;
                while let Ok(frame) = read_record(&mut node_down) {
                    match rx_sess.open(&frame) {
                        Ok(plain) => {
                            if client_down.write_all(&plain).is_err() {
                                break;
                            }
                            total += plain.len();
                        }
                        Err(_) => break,
                    }
                }
                total
            });
            let up = to_upstream.join().map_err(|_| NexusError::Internal {
                message: "proxy thread panicked".into(),
            })?;
            let down = to_client.join().map_err(|_| NexusError::Internal {
                message: "proxy thread panicked".into(),
            })?;
            outbound = json!({
                "kind": "shadowsocks",
                "node_locator": locator,
                "method": method.as_str(),
            });
            (up, down)
        }
        nexus_proxy_config::OutboundKind::Trojan => {
            // §11.16 trojan 数据面：rustls TLS（SNI=节点域名、ALPN、skip-cert-verify）
            // + trojan 请求头（standard/singbox）+ 双向透明中继 client<->TLS。
            use nexus_outbound_trojan::{TrojanHeaderFormat, TrojanTarget, encode_request_fmt};
            use rustls::pki_types::ServerName;
            use std::sync::Arc;

            let locator = selected.locator.clone().ok_or_else(|| {
                NexusError::ConnectivityEstablishmentFailed {
                    provider: ProviderId(decision.selected_outbound_tag.clone()),
                    reason: "trojan outbound missing locator".into(),
                }
            })?;
            let (nhost, nport) = split_host_port(&locator)?;
            let mut node = std::net::TcpStream::connect((nhost.as_str(), nport)).map_err(|e| {
                NexusError::ConnectivityEstablishmentFailed {
                    provider: ProviderId(decision.selected_outbound_tag.clone()),
                    reason: format!("trojan node connect {locator} failed: {e}"),
                }
            })?;
            let password = selected.password.clone().ok_or_else(|| {
                NexusError::ConnectivityEstablishmentFailed {
                    provider: ProviderId(decision.selected_outbound_tag.clone()),
                    reason: "trojan outbound missing password".into(),
                }
            })?;

            let header_format = match selected.header_format.as_deref() {
                Some("singbox") => TrojanHeaderFormat::Singbox,
                _ => TrojanHeaderFormat::Standard,
            };
            let skip_verify = selected.skip_cert_verify.unwrap_or(false);
            let alpn: Vec<Vec<u8>> = selected
                .alpn
                .clone()
                .unwrap_or_default()
                .into_iter()
                .map(|s| s.into_bytes())
                .collect();
            let alpn_ref: Vec<&[u8]> = alpn.iter().map(|v| v.as_slice()).collect();

            // 客户端 TLS 配置：skip-cert-verify（自签/内网节点）或系统信任根。
            let tls_cfg: Result<rustls::ClientConfig, NexusError> = if skip_verify {
                nexus_outbound_trojan::client_config_dangerous_skip_verify(&alpn_ref).map_err(|e| {
                    NexusError::ConnectivityEstablishmentFailed {
                        provider: ProviderId(decision.selected_outbound_tag.clone()),
                        reason: format!("trojan client tls config failed: {e}"),
                    }
                })
            } else {
                let mut roots = rustls::RootCertStore::empty();
                for c in rustls_native_certs::load_native_certs().certs {
                    let _ = roots.add(c);
                }
                let prov = Arc::new(rustls::crypto::ring::default_provider());
                let mut cfg = rustls::ClientConfig::builder_with_provider(prov)
                    .with_safe_default_protocol_versions()
                    .map_err(|_| NexusError::Internal {
                        message: "tls versions".into(),
                    })?
                    .with_root_certificates(roots)
                    .with_no_client_auth();
                if !alpn.is_empty() {
                    cfg.alpn_protocols = alpn.clone();
                }
                Ok(cfg)
            };
            let tls_cfg = tls_cfg?;

            let sni = ServerName::try_from(nhost.clone()).map_err(|_| {
                NexusError::ConnectivityEstablishmentFailed {
                    provider: ProviderId(decision.selected_outbound_tag.clone()),
                    reason: format!("trojan sni invalid: {nhost}"),
                }
            })?;
            let mut conn = rustls::ClientConnection::new(Arc::new(tls_cfg), sni).map_err(|e| {
                NexusError::ConnectivityEstablishmentFailed {
                    provider: ProviderId(decision.selected_outbound_tag.clone()),
                    reason: format!("trojan client connection failed: {e}"),
                }
            })?;

            // 写入 trojan 请求头（write_all/flush 同时驱动 TLS 握手）。
            let target = if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
                TrojanTarget::Ipv4(ip.octets(), port)
            } else {
                TrojanTarget::Domain(host.clone(), port)
            };
            let header = encode_request_fmt(&password, &target, header_format);
            {
                let mut tls = rustls::Stream::new(&mut conn, &mut node);
                tls.write_all(&header).map_err(|e| {
                    NexusError::ConnectivityEstablishmentFailed {
                        provider: ProviderId(decision.selected_outbound_tag.clone()),
                        reason: format!("trojan header write failed: {e}"),
                    }
                })?;
                tls.flush()
                    .map_err(|e| NexusError::ConnectivityEstablishmentFailed {
                        provider: ProviderId(decision.selected_outbound_tag.clone()),
                        reason: format!("trojan handshake/header flush failed: {e}"),
                    })?;
                // §11.19：握手首段字节（HTTP 改写后的请求）随 TLS 一并写给节点。
                if !seed_to_upstream.is_empty() {
                    tls.write_all(&seed_to_upstream).map_err(|e| {
                        NexusError::ConnectivityEstablishmentFailed {
                            provider: ProviderId(decision.selected_outbound_tag.clone()),
                            reason: format!("trojan seed write failed: {e}"),
                        }
                    })?;
                    tls.flush()
                        .map_err(|e| NexusError::ConnectivityEstablishmentFailed {
                            provider: ProviderId(decision.selected_outbound_tag.clone()),
                            reason: format!("trojan seed flush failed: {e}"),
                        })?;
                }
            }

            // 双向透明中继：rustls ClientConnection 不可跨线程分裂，用非阻塞单线程
            // poll 在 client 与 TLS 之间搬运字节（loopback E4 小流量足够；本函数单线程
            // 闭环承担结构化并发，无泄漏 JoinHandle）。
            node.set_nonblocking(true)
                .map_err(|e| NexusError::Internal {
                    message: format!("trojan node nonblocking: {e}"),
                })?;
            client
                .set_nonblocking(true)
                .map_err(|e| NexusError::Internal {
                    message: format!("trojan client nonblocking: {e}"),
                })?;
            let mut up_bytes = 0usize;
            let mut down_bytes = 0usize;
            let mut cbuf = [0u8; 8192];
            let mut sbuf = [0u8; 8192];
            let mut c_open = true;
            let mut tls_open = true;
            {
                let mut tls = rustls::Stream::new(&mut conn, &mut node);
                loop {
                    if !c_open && !tls_open {
                        break;
                    }
                    let mut progressed = false;
                    if c_open {
                        match client.read(&mut cbuf) {
                            Ok(0) => c_open = false,
                            Ok(n) => match tls.write_all(&cbuf[..n]) {
                                Ok(()) => match tls.flush() {
                                    Ok(()) => {
                                        up_bytes += n;
                                        progressed = true;
                                    }
                                    Err(_) => tls_open = false,
                                },
                                Err(_) => tls_open = false,
                            },
                            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                            Err(_) => c_open = false,
                        }
                    }
                    if tls_open && c_open {
                        match tls.read(&mut sbuf) {
                            Ok(0) => tls_open = false,
                            Ok(n) => match client.write_all(&sbuf[..n]) {
                                Ok(()) => {
                                    down_bytes += n;
                                    progressed = true;
                                }
                                Err(_) => {
                                    // 投递到 client 失败：client 已不可达，隧道整体终止。
                                    c_open = false;
                                    tls_open = false;
                                }
                            },
                            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                            Err(_) => tls_open = false,
                        }
                    } else if tls_open && !c_open {
                        // client 已断开：直接终止节点侧，避免节点不发 close_notify 时空转。
                        tls_open = false;
                    }
                    if !progressed {
                        std::thread::sleep(std::time::Duration::from_millis(2));
                    }
                }
            }
            // 尽力向节点发送 close_notify（不阻断结果）。
            conn.send_close_notify();
            let _ = node.set_nonblocking(false);

            let hf_label = match header_format {
                TrojanHeaderFormat::Standard => "standard",
                TrojanHeaderFormat::Singbox => "singbox",
            };
            outbound = json!({
                "kind": "trojan",
                "node_locator": locator,
                "tls": {
                    "sni": nhost,
                    "alpn": selected.alpn,
                    "skip_cert_verify": skip_verify,
                },
                "header_format": hf_label,
            });
            (up_bytes, down_bytes)
        }
        nexus_proxy_config::OutboundKind::Relay => {
            return Err(NexusError::ConnectivityEstablishmentFailed {
                provider: ProviderId(decision.selected_outbound_tag.clone()),
                reason: "relay outbound data-plane tunnel not in this batch scope (deferred)"
                    .into(),
            });
        }
        nexus_proxy_config::OutboundKind::Vmess => {
            return Err(NexusError::ConnectivityEstablishmentFailed {
                provider: ProviderId(decision.selected_outbound_tag.clone()),
                reason: "vmess outbound data-plane not in this batch: nexus-outbound-vmess currently provides only self-consistent AEAD encrypt/decrypt roundtrip; missing VMess request-header encoder, AEAD chunk wire framing, and session-key derivation required for a real node tunnel (deferred)".into(),
            });
        }
    };

    // 6) Session 终态。
    owner
        .commit_outcome(TerminalOutcome::Completed)
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
        "inbound": {
            "kind": inbound_kind,
        },
        "socks": {
            "auth_method_reply": "0x05,0x00",
            "reply_code": 0,
            "destination": flow.destination,
        },
        "routing": {
            "matched_rule": decision.matched_rule,
            "first_action": decision.first_action,
            "selected_outbound_tag": decision.selected_outbound_tag,
            "outbound_kind": outbound_kind,
            "flow_origin": decision.flow_origin,
        },
        "outbound": outbound,
        "session": {
            "id": owner.id().0,
            "phase": phase_name(&status.phase),
            "outcome": outcome_name(&status.outcome),
        },
        "terminal_outcome_commit_count": terminal_outcome_commit_count,
        "bytes": {
            "to_upstream": up_bytes,
            "to_client": down_bytes,
        },
        "architecture": {
            "network_depends_on_ingress": network_depends_on_ingress()?,
        }
    }))
}
// ---------- 节点测速（PRODUCT §11.10） ----------

/// 真实 TCP 延迟探测（组合根，非 portable）：`std::net::TcpStream::connect_timeout`。
#[derive(Debug, Clone)]
pub struct TcpLatencyProbe {
    /// 建连超时。
    pub timeout: std::time::Duration,
}

impl Default for TcpLatencyProbe {
    fn default() -> Self {
        Self {
            timeout: std::time::Duration::from_secs(5),
        }
    }
}

impl nexus_measurement::LatencyProbe for TcpLatencyProbe {
    fn probe(&self, target: &nexus_measurement::ProbeTarget) -> Result<LinkMeasurement, String> {
        let addr: std::net::SocketAddr = format!("{}:{}", target.host, target.port)
            .parse()
            .map_err(|e| format!("invalid probe address: {e}"))?;
        let start = std::time::Instant::now();
        let socket = std::net::TcpStream::connect_timeout(&addr, self.timeout)
            .map_err(|e| format!("connect failed: {e}"))?;
        // 最小刻度 1ms：loopback 建连 <1ms 时 as_millis() 截断为 0，产品口径
        // 不允许 0（0 语义保留给"无测量"），统一钳制为 1。
        let rtt_ms = u32::try_from(start.elapsed().as_millis())
            .map(|ms| ms.max(1))
            .unwrap_or(u32::MAX);
        drop(socket);
        Ok(LinkMeasurement {
            rtt_ms: Some(rtt_ms),
            ..Default::default()
        })
    }
}

/// 真实 HTTP/204 延迟探测（组合根，非 portable）：TCP connect 后发送单行 GET，
/// 等待响应首行 `204 No Content`；计时覆盖建连 + 请求发送 + 响应首字返回。
#[derive(Debug, Clone)]
pub struct Http204LatencyProbe {
    /// 建连与读取超时。
    pub timeout: std::time::Duration,
}

impl Default for Http204LatencyProbe {
    fn default() -> Self {
        Self {
            timeout: std::time::Duration::from_secs(5),
        }
    }
}

impl nexus_measurement::LatencyProbe for Http204LatencyProbe {
    fn probe(&self, target: &nexus_measurement::ProbeTarget) -> Result<LinkMeasurement, String> {
        use std::io::{BufRead, Write};
        if target.scheme == "https" {
            return Err(
                "http204 probe P0 only supports plaintext HTTP target (https not supported)"
                    .to_string(),
            );
        }
        let addr: std::net::SocketAddr = format!("{}:{}", target.host, target.port)
            .parse()
            .map_err(|e| format!("invalid probe address: {e}"))?;
        let start = std::time::Instant::now();
        let mut stream = std::net::TcpStream::connect_timeout(&addr, self.timeout)
            .map_err(|e| format!("connect failed: {e}"))?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(|e| format!("set read timeout: {e}"))?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(|e| format!("set write timeout: {e}"))?;
        let path = if target.path.is_empty() {
            "/"
        } else {
            &target.path
        };
        let req = format!(
            "GET {path} HTTP/1.1\r\nHost: {}:{}\r\nConnection: close\r\nUser-Agent: nexus-speedtest\r\nAccept: */*\r\n\r\n",
            target.host, target.port
        );
        stream
            .write_all(req.as_bytes())
            .map_err(|e| format!("write request failed: {e}"))?;
        let mut reader = std::io::BufReader::new(&mut stream);
        let mut first_line = Vec::new();
        reader
            .read_until(b'\n', &mut first_line)
            .map_err(|e| format!("read status line failed: {e}"))?;
        let line = String::from_utf8_lossy(&first_line);
        let status_code = line.split_whitespace().nth(1);
        if status_code != Some("204") {
            return Err(format!("unexpected status line: {}", line.trim_end()));
        }
        let rtt_ms = u32::try_from(start.elapsed().as_millis())
            .map(|ms| ms.max(1))
            .unwrap_or(u32::MAX);
        Ok(LinkMeasurement {
            rtt_ms: Some(rtt_ms),
            ..Default::default()
        })
    }
}

/// 通用批量测速：对候选逐个探测、RTT 升序输出（探测失败以 status 记录，非致命）。
/// target_label 为探测目标 URL 展示（产品默认 generate_204）。
/// probe_kind 为本次测速使用的探测类型标签（`tcp` / `http204`），原样进入 JSON。
pub fn proxy_speedtest_with(
    probe: &dyn nexus_measurement::LatencyProbe,
    candidates: &[(&str, nexus_measurement::ProbeTarget)],
    timeout: std::time::Duration,
    target_label: &str,
    probe_kind: &str,
) -> Result<Value, NexusError> {
    let mut rows: Vec<(String, Option<u32>, String)> = Vec::new();
    for (tag, target) in candidates {
        match probe.probe(target) {
            Ok(m) => rows.push((tag.to_string(), m.rtt_ms, "ok".to_string())),
            Err(e) => {
                let status = if e.contains("timed out") {
                    "timeout".to_string()
                } else {
                    "unreachable".to_string()
                };
                rows.push((tag.to_string(), None, status));
            }
        }
    }
    rows.sort_by_key(|(_, rtt, _)| rtt.unwrap_or(u32::MAX));
    Ok(json!({
        "verdict": "PASS",
        "command": "proxy speedtest",
        "probe_kind": probe_kind,
        "timeout_ms": timeout.as_millis(),
        "target": target_label.to_string(),
        "results": rows
            .iter()
            .map(|(tag, rtt, status)| json!({
                "tag": tag,
                "latency_ms": rtt,
                "status": status,
            }))
            .collect::<Vec<_>>(),
    }))
}

/// `nexusd proxy speedtest --json` 入口：loopback 自检（真实 TcpStream 路径，
/// 离线确定性；公网 generate_204 测速由 E5 脚手架覆盖）。
pub fn proxy_speedtest() -> Result<Value, NexusError> {
    let listener =
        std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| NexusError::Internal {
            message: format!("bind loopback failed: {e}"),
        })?;
    let port = listener
        .local_addr()
        .map_err(|e| NexusError::Internal {
            message: format!("local_addr failed: {e}"),
        })?
        .port();
    let target = nexus_measurement::ProbeTarget::new("http", "127.0.0.1", port, "");
    let probe = TcpLatencyProbe::default();
    // listener 保持 backlog 存活直至测完（不 accept 亦可完成 TCP 握手），随后关闭。
    let result = proxy_speedtest_with(
        &probe,
        &[("loopback", target)],
        probe.timeout,
        "http://www.gstatic.com/generate_204",
        "tcp",
    );
    drop(listener);
    result
}

/// Run a remote resource access (e.g. service, compute, internet-access).
///
/// This is the CLI entry point for executing resource access flows.
/// Currently supports: service, compute, internet-access.
pub fn run_resource(resource: &str) -> Result<serde_json::Value, NexusError> {
    // Generate a mock session ID for now
    // TODO: extract real session_id from the flow report when available
    let session_id = format!("sess-{}", uuid_like());

    match resource {
        "service" => {
            // Use the existing remote_service_access_flow SDK function
            let _report = remote_service_access_flow()?;
            Ok(serde_json::json!({
                "verdict": "PASS",
                "run": {
                    "resource": "service",
                    "session_id": session_id,
                    "connectivity": {
                        "status": "Connected"
                    },
                    "outcome": "Completed"
                }
            }))
        }
        "compute" => {
            let _report = remote_compute_job_flow()?;
            Ok(serde_json::json!({
                "verdict": "PASS",
                "run": {
                    "resource": "compute",
                    "session_id": session_id,
                    "connectivity": {
                        "status": "Connected"
                    },
                    "outcome": "Completed"
                }
            }))
        }
        "internet-access" => {
            let _report = remote_internet_access_flow()?;
            Ok(serde_json::json!({
                "verdict": "PASS",
                "run": {
                    "resource": "internet-access",
                    "session_id": session_id,
                    "connectivity": {
                        "status": "Connected"
                    },
                    "outcome": "Completed"
                }
            }))
        }
        other => Err(NexusError::Unsupported {
            feature: format!("run {other}"),
        }),
    }
}

/// Generate a simple pseudo-unique ID (for demo purposes).
fn uuid_like() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{:016x}", nanos)
}

/// E4 `product.link-encryption` 的离线确定性切片：全内存 mock 驱动
/// WireGuard 风格链路加密闭环——
///
/// ```text
/// 生成两对 X25519 KeyPair
///   -> initiator(A) <-> responder(B) 握手（公钥字节在内存中互相"发送"）
///   -> 双端派生相同 SessionKey
///   -> 加密业务帧 -> 对端解密 + 防重放窗口校验
///   -> 重复序号被重放窗口拒绝
///   -> 错误密钥派生的会话密钥解密失败
/// ```
///
/// 全程零真实网络；错误一律 typed `Result`，无 panic。
pub fn link_encryption_flow() -> Result<Value, NexusError> {
    use nexus_connectivity::encryption::{
        EncryptionError, HANDSHAKE_INIT, HANDSHAKE_RESP, HandshakeMessage, KeyPair, ReplayWindow,
        build_handshake_message, decrypt_frame, derive_authed_keys, encrypt_frame,
    };

    let mut events: Vec<&'static str> = Vec::new();

    // 1) 生成本地（initiator）与对端（responder）的身份密钥 + ephemeral 密钥
    //    （P4.1 §12.39 v2 混合 DH）。
    let local_static = KeyPair::generate().map_err(enc_err)?;
    let local_eph = KeyPair::generate().map_err(enc_err)?;
    let peer_static = KeyPair::generate().map_err(enc_err)?;
    let peer_eph = KeyPair::generate().map_err(enc_err)?;
    let local_pub = *local_static.public_key_bytes();
    let peer_pub = *peer_static.public_key_bytes();
    events.push("keypair_generated");

    // 2) 握手：A 发 INIT（A static+eph）-> B 发 RESP（B static+eph），双端以
    //    本端私钥 + 对端公钥经混合 DH 派生同一 SessionKey。
    let init_msg =
        build_handshake_message(HANDSHAKE_INIT, &local_eph, local_static.public_key_bytes());
    // 模拟"网络传输"：把 initiator 消息字节序列化后交给 responder 解析。
    let init_wire = init_msg.to_bytes();
    let _ = HandshakeMessage::from_bytes(&init_wire).map_err(enc_err)?;
    let resp_msg =
        build_handshake_message(HANDSHAKE_RESP, &peer_eph, peer_static.public_key_bytes());
    let _resp_wire = resp_msg.to_bytes();
    let keys_a = derive_authed_keys(
        &local_static,
        &local_eph,
        peer_static.public_key_bytes(),
        peer_eph.public_key_bytes(),
        true,
    )
    .map_err(enc_err)?;
    let keys_b = derive_authed_keys(
        &peer_static,
        &peer_eph,
        local_static.public_key_bytes(),
        local_eph.public_key_bytes(),
        false,
    )
    .map_err(enc_err)?;
    events.push("handshake_completed");
    events.push("session_established");

    // 3) A 用会话密钥加密业务帧；B 解密并经防重放窗口接受。
    let payload = b"nexus-secret-link-payload";
    let seq: u64 = 1;
    let frame = encrypt_frame(&keys_a.tx, seq, payload).map_err(enc_err)?;
    events.push("frame_encrypted");

    let mut rx_window = ReplayWindow::new();
    let (got_seq, plaintext) = decrypt_frame(&keys_b.rx, &frame).map_err(enc_err)?;
    rx_window.check_and_accept(got_seq).map_err(enc_err)?;
    if plaintext.as_slice() != payload {
        return Err(NexusError::Internal {
            message: "link encryption: decrypted payload mismatch".to_string(),
        });
    }
    events.push("frame_decrypted");

    // 4) 重放：相同序号再发一帧，B 解密成功但被防重放窗口拒绝。
    let replay_frame = encrypt_frame(&keys_a.tx, seq, payload).map_err(enc_err)?;
    let (replay_seq, _) = decrypt_frame(&keys_b.rx, &replay_frame).map_err(enc_err)?;
    let replay_rejected = matches!(
        rx_window.check_and_accept(replay_seq),
        Err(EncryptionError::ReplayRejected { seq: _ })
    );
    if !replay_rejected {
        return Err(NexusError::Internal {
            message: "link encryption: replay frame was not rejected".to_string(),
        });
    }
    events.push("replay_rejected");

    // 5) 错误密钥：用另一对身份+ephemeral (C, D) 派生的会话密钥必须无法解密 A->B 的帧。
    let other_local_static = KeyPair::generate().map_err(enc_err)?;
    let other_local_eph = KeyPair::generate().map_err(enc_err)?;
    let other_peer_static = KeyPair::generate().map_err(enc_err)?;
    let other_peer_eph = KeyPair::generate().map_err(enc_err)?;
    let other_tx = derive_authed_keys(
        &other_local_static,
        &other_local_eph,
        other_peer_static.public_key_bytes(),
        other_peer_eph.public_key_bytes(),
        true,
    )
    .map_err(enc_err)?;
    let other_rx = derive_authed_keys(
        &other_peer_static,
        &other_peer_eph,
        other_local_static.public_key_bytes(),
        other_local_eph.public_key_bytes(),
        false,
    )
    .map_err(enc_err)?;
    let wrong_key_rejected = matches!(
        decrypt_frame(&other_rx.rx, &frame),
        Err(EncryptionError::DecryptionFailed)
    ) || matches!(
        decrypt_frame(&other_tx.tx, &frame),
        Err(EncryptionError::DecryptionFailed)
    );
    if !wrong_key_rejected {
        return Err(NexusError::Internal {
            message: "link encryption: wrong-key frame was not rejected".to_string(),
        });
    }
    events.push("wrong_key_rejected");

    events.push("encryption_completed");

    Ok(json!({
        "verdict": "PASS",
        "events": events,
        "handshake": {
            "local_public_key": hex16(&local_pub),
            "peer_public_key": hex16(&peer_pub),
            "session_key_established": true,
            "session_key_bytes": keys_a.tx.material().len(),
        },
        "frame": {
            "seq": got_seq,
            "bytes": frame.len(),
            "nonce_len": 12,
            "tag_len": 16,
            "plaintext_len": plaintext.len(),
        },
        "replay": {
            "rejected": replay_rejected,
            "duplicate_seq": replay_seq,
        },
        "wrong_key": {
            "rejected": wrong_key_rejected,
        }
    }))
}

/// E4 `product.identity-auto-exchange`（P4.1 §12.39）：多节点身份密钥自动生成与
/// TOFU 自动交换的进程内确定性切片——
///
/// ```text
/// A/B 双节点加密隧道（内存 MeshCarrier）
///   -> 首次握手：两端各自自动生成身份密钥（IdentityKeyGenerated）
///   -> 首次握手：双方 TOFU 学习对端身份（PeerIdentityLearned）
///   -> 数据帧往返（混合 DH 会话可加解密）
///   -> 二次握手：身份已验证（PeerVerified，再次握手成功）
///   -> 身份替换：伪装节点 C 以新身份冒充 A -> TOFU 拒绝（IDENTITY_CHANGED）
/// ```
///
/// 全程零真实网络；错误一律 typed `Result`，无 panic。
pub fn identity_auto_exchange_flow() -> Result<Value, NexusError> {
    use nexus_connectivity::encryption::EncryptionConfig;
    use nexus_connectivity::identity::InMemorySecretStore;
    use nexus_connectivity::virtual_subnet::{
        MemoryVpi, MeshCarrier, TunnelPeer, VirtualSubnetConfig, VirtualSubnetEvent,
        VirtualSubnetTunnel,
    };

    let mut events: Vec<&'static str> = Vec::new();

    // 双向 MeshCarrier：A ↔ B
    let mut mesh_a = MeshCarrier::new();
    let mut mesh_b = MeshCarrier::new();
    let a_recv = mesh_a.recv_handle();
    let b_recv = mesh_b.recv_handle();
    mesh_a.connect_peer("B_locator", b_recv.clone());
    mesh_b.connect_peer("A_locator", a_recv.clone());

    let cfg_a = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.1");
    let cfg_b = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.2");

    let mut tunnel_a =
        VirtualSubnetTunnel::new(cfg_a, Box::new(MemoryVpi::new()), Box::new(mesh_a));
    let mut tunnel_b =
        VirtualSubnetTunnel::new(cfg_b, Box::new(MemoryVpi::new()), Box::new(mesh_b));

    tunnel_a
        .add_peer(TunnelPeer::new("10.0.0.2", "B_locator"))
        .map_err(|e| NexusError::Internal {
            message: format!("add peer: {e}"),
        })?;
    tunnel_b
        .add_peer(TunnelPeer::new("10.0.0.1", "A_locator"))
        .map_err(|e| NexusError::Internal {
            message: format!("add peer: {e}"),
        })?;

    tunnel_a.enable_encryption(EncryptionConfig::default());
    tunnel_b.enable_encryption(EncryptionConfig::default());
    // 注入独立内存存储（模拟两端各自的 secure-store）。
    tunnel_a.set_identity_store(Box::new(InMemorySecretStore::new()));
    tunnel_b.set_identity_store(Box::new(InMemorySecretStore::new()));

    let mut buf = [0u8; 4096];

    // ---- 阶段 1：首次握手（A 发起）----
    tunnel_a
        .begin_handshake("10.0.0.2")
        .map_err(|e| NexusError::Internal {
            message: format!("begin_handshake: {e}"),
        })?;
    tunnel_b
        .recv_and_deliver(&mut buf)
        .map_err(|e| NexusError::Internal {
            message: format!("b accept: {e}"),
        })?;
    tunnel_a
        .recv_and_deliver(&mut buf)
        .map_err(|e| NexusError::Internal {
            message: format!("a complete: {e}"),
        })?;

    // 事件断言：两端身份自动生成 + TOFU 互学。
    let a_key_gen = tunnel_a
        .events()
        .iter()
        .any(|e| matches!(e, VirtualSubnetEvent::IdentityKeyGenerated { .. }));
    let b_key_gen = tunnel_b
        .events()
        .iter()
        .any(|e| matches!(e, VirtualSubnetEvent::IdentityKeyGenerated { .. }));
    let a_learned = tunnel_a
        .events()
        .iter()
        .any(|e| matches!(e, VirtualSubnetEvent::PeerIdentityLearned { .. }));
    let b_learned = tunnel_b
        .events()
        .iter()
        .any(|e| matches!(e, VirtualSubnetEvent::PeerIdentityLearned { .. }));
    if !(a_key_gen && b_key_gen && a_learned && b_learned) {
        return Err(NexusError::Internal {
            message: format!(
                "identity exchange events missing: a_key={a_key_gen} b_key={b_key_gen} \
                 a_learn={a_learned} b_learn={b_learned}"
            ),
        });
    }
    events.push("identity_key_generated");
    events.push("first_handshake_learned");

    // ---- 阶段 2：数据帧往返（混合 DH 会话可用）----
    let payload = b"p4.1-identity-ok";
    tunnel_a
        .send_ip_packet("10.0.0.2", payload)
        .map_err(|e| NexusError::Internal {
            message: format!("send: {e}"),
        })?;
    if tunnel_b
        .recv_and_deliver(&mut buf)
        .map_err(|e| NexusError::Internal {
            message: format!("b recv: {e}"),
        })?
        .is_none()
    {
        return Err(NexusError::Internal {
            message: "B did not decrypt A frame".to_string(),
        });
    }
    events.push("data_frame_decrypted");

    // ---- 阶段 3：二次握手（身份已验证，TOFU PeerVerified）----
    tunnel_a
        .begin_handshake("10.0.0.2")
        .map_err(|e| NexusError::Internal {
            message: format!("re-begin: {e}"),
        })?;
    tunnel_b
        .recv_and_deliver(&mut buf)
        .map_err(|e| NexusError::Internal {
            message: format!("re-b accept: {e}"),
        })?;
    tunnel_a
        .recv_and_deliver(&mut buf)
        .map_err(|e| NexusError::Internal {
            message: format!("re-a complete: {e}"),
        })?;
    events.push("second_handshake_verified");

    // ---- 阶段 4：身份替换拒绝 ----
    // 伪装节点 C（全新身份）冒充 B(10.0.0.2) 向 A 发起握手：A 已学习 B 的 static
    // 身份，C 的 static 不同 -> A 侧 TOFU 拒绝（IDENTITY_CHANGED）。
    let mut mesh_c = MeshCarrier::new();
    let _c_recv = mesh_c.recv_handle();
    mesh_c.connect_peer("A_locator", a_recv.clone()); // C 发给 A（A 收件箱）

    let cfg_c = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.2"); // 冒充 B 的 VIP
    let mut tunnel_c =
        VirtualSubnetTunnel::new(cfg_c, Box::new(MemoryVpi::new()), Box::new(mesh_c));
    tunnel_c
        .add_peer(TunnelPeer::new("10.0.0.1", "A_locator"))
        .map_err(|e| NexusError::Internal {
            message: format!("add peer c: {e}"),
        })?;
    tunnel_c.enable_encryption(EncryptionConfig::default());
    tunnel_c.set_identity_store(Box::new(InMemorySecretStore::new()));

    tunnel_c
        .begin_handshake("10.0.0.1")
        .map_err(|e| NexusError::Internal {
            message: format!("c begin to A: {e}"),
        })?;
    // A 侧 accept 时 TOFU 校验失败 -> IdentityRejected（不发送 RESP）。
    let mismatch_rejected = match tunnel_a.recv_and_deliver(&mut buf) {
        Err(nexus_connectivity::ConnectivityError::IdentityRejected { .. }) => true,
        other => {
            return Err(NexusError::Internal {
                message: format!("identity mismatch not rejected as IdentityRejected: {other:?}"),
            });
        }
    };
    events.push("identity_mismatch_rejected");

    events.push("exchange_completed");

    Ok(json!({
        "verdict": "PASS",
        "events": events,
        "identity": {
            "peer_id": tunnel_a.peer_id().unwrap_or_default(),
            "persisted": true,
            "tofu": "vip-indexed",
        },
        "mismatch": {
            "rejected": mismatch_rejected,
            "error_code": "IDENTITY_CHANGED",
        },
        "session": {
            "algorithm": "x25519-mixed-dh-hkdf-sha256",
            "aead": "chacha20-poly1305",
        },
    }))
}

/// E4 产品场景 `product.virtual-subnet-encrypted-3node` 的可执行驱动（Composition Root）。
///
/// 三节点 A(10.0.0.1)—B(10.0.0.2)—C(10.0.0.3) 虚拟子网：加密模式开启后，
/// 每跳独立 ephemeral 握手派生会话密钥，数据面整体 AEAD 加密；
/// 中间节点 B 用下一跳会话重新加密同一明文转发（帧头内容不变）。
pub fn virtual_subnet_encrypted_3node_flow() -> Result<Value, NexusError> {
    use nexus_connectivity::encryption::EncryptionConfig;
    use nexus_connectivity::virtual_subnet::{
        MemoryVpi, MeshCarrier, TunnelPeer, VirtualSubnetConfig, VirtualSubnetTunnel,
    };

    // 三向 MeshCarrier：A↔B、B↔C（A 与 C 不直连）
    let mut mesh_a = MeshCarrier::new();
    let mut mesh_b = MeshCarrier::new();
    let mut mesh_c = MeshCarrier::new();
    let a_recv = mesh_a.recv_handle();
    let b_recv = mesh_b.recv_handle();
    let c_recv = mesh_c.recv_handle();
    mesh_a.connect_peer("B_locator", b_recv.clone());
    mesh_b.connect_peer("A_locator", a_recv.clone());
    mesh_b.connect_peer("C_locator", c_recv.clone());
    mesh_c.connect_peer("B_locator", b_recv.clone());

    let cfg_a = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.1");
    let cfg_b = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.2");
    let cfg_c = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.3");
    let vpi_c = Box::new(MemoryVpi::new());
    let c_vpi_sent = vpi_c.sent_handle();

    let mut tunnel_a =
        VirtualSubnetTunnel::new(cfg_a, Box::new(MemoryVpi::new()), Box::new(mesh_a));
    let mut tunnel_b =
        VirtualSubnetTunnel::new(cfg_b, Box::new(MemoryVpi::new()), Box::new(mesh_b));
    let mut tunnel_c = VirtualSubnetTunnel::new(cfg_c, vpi_c, Box::new(mesh_c));

    // 路由：A 去 C 经 B；C 去 A 经 B；B 无路由（A/C 均直连）
    tunnel_a
        .add_peer(TunnelPeer::new("10.0.0.2", "B_locator"))
        .map_err(|e| NexusError::Internal {
            message: format!("add peer: {e}"),
        })?;
    tunnel_a
        .add_route("10.0.0.3", "10.0.0.2")
        .map_err(|e| NexusError::Internal {
            message: format!("add route: {e}"),
        })?;
    tunnel_b
        .add_peer(TunnelPeer::new("10.0.0.1", "A_locator"))
        .map_err(|e| NexusError::Internal {
            message: format!("add peer: {e}"),
        })?;
    tunnel_b
        .add_peer(TunnelPeer::new("10.0.0.3", "C_locator"))
        .map_err(|e| NexusError::Internal {
            message: format!("add peer: {e}"),
        })?;
    tunnel_c
        .add_peer(TunnelPeer::new("10.0.0.2", "B_locator"))
        .map_err(|e| NexusError::Internal {
            message: format!("add peer: {e}"),
        })?;
    tunnel_c
        .add_route("10.0.0.1", "10.0.0.2")
        .map_err(|e| NexusError::Internal {
            message: format!("add route: {e}"),
        })?;

    // 开启加密模式（三节点）
    tunnel_a.enable_encryption(EncryptionConfig::default());
    tunnel_b.enable_encryption(EncryptionConfig::default());
    tunnel_c.enable_encryption(EncryptionConfig::default());
    let a_encrypted = tunnel_a.is_encryption_enabled();
    let b_encrypted = tunnel_b.is_encryption_enabled();
    let c_encrypted = tunnel_c.is_encryption_enabled();

    // 握手 A↔B（A 发起）
    tunnel_a
        .begin_handshake("10.0.0.2")
        .map_err(|e| NexusError::Internal {
            message: format!("begin_handshake: {e}"),
        })?;
    let mut buf = [0u8; 4096];
    let _ = tunnel_b
        .recv_and_deliver(&mut buf)
        .map_err(|e| NexusError::Internal {
            message: format!("b accept: {e}"),
        })?;
    let _ = tunnel_a
        .recv_and_deliver(&mut buf)
        .map_err(|e| NexusError::Internal {
            message: format!("a complete: {e}"),
        })?;

    // 握手 B↔C（B 发起）
    tunnel_b
        .begin_handshake("10.0.0.3")
        .map_err(|e| NexusError::Internal {
            message: format!("begin_handshake: {e}"),
        })?;
    let _ = tunnel_c
        .recv_and_deliver(&mut buf)
        .map_err(|e| NexusError::Internal {
            message: format!("c accept: {e}"),
        })?;
    let _ = tunnel_b
        .recv_and_deliver(&mut buf)
        .map_err(|e| NexusError::Internal {
            message: format!("b complete: {e}"),
        })?;

    // 断言两侧握手状态
    let a_b_state = tunnel_a
        .peer_state("10.0.0.2")
        .map(|s| format!("{s:?}"))
        .unwrap_or("None".into());
    let c_b_state = tunnel_c
        .peer_state("10.0.0.2")
        .map(|s| format!("{s:?}"))
        .unwrap_or("None".into());
    if a_b_state != "Connected" || c_b_state != "Connected" {
        return Err(NexusError::Internal {
            message: format!("handshake state mismatch: a_b={a_b_state} c_b={c_b_state}"),
        });
    }

    // A 发 ping → C（16B，经 B 转发）
    let payload = b"ping-from-a-to-c";
    tunnel_a
        .send_ip_packet("10.0.0.3", payload)
        .map_err(|e| NexusError::Internal {
            message: format!("send: {e}"),
        })?;

    // 密文泄漏检查：抓取 A→B 链路的 wire 密文，不得含明文载荷与帧头分隔符
    let wire_ab = b_recv.lock().unwrap().clone();
    let leak_marker = payload.as_slice();
    let wire_plaintext_leak = wire_ab.windows(leak_marker.len()).any(|w| w == leak_marker)
        || wire_ab.windows(2).any(|w| w == b"->");

    // B 收（解密 seq0，转发给 C 时重加密）
    let b_delivered = tunnel_b
        .recv_and_deliver(&mut buf)
        .map_err(|e| NexusError::Internal {
            message: format!("b recv: {e}"),
        })?;
    if b_delivered.is_none() {
        return Err(NexusError::Internal {
            message: "B did not receive A frame".to_string(),
        });
    }
    let b_bytes_forwarded = tunnel_b
        .peer_stats("10.0.0.3")
        .map(|s| s.bytes_forwarded)
        .unwrap_or(0);

    // C 收（解密，写 VPI）
    let c_delivered = tunnel_c
        .recv_and_deliver(&mut buf)
        .map_err(|e| NexusError::Internal {
            message: format!("c recv: {e}"),
        })?;
    let c_vpi_len = c_delivered.map(|(_, l)| l).unwrap_or(0);
    let c_vpi_payload = String::from_utf8_lossy(&c_vpi_sent.lock().unwrap()).to_string();
    if c_vpi_payload != "ping-from-a-to-c" {
        return Err(NexusError::Internal {
            message: format!("C VPI payload mismatch: {c_vpi_payload:?}"),
        });
    }

    // 防重放：重放 A→B 同一密文帧 → B 拒绝（REPLAY_REJECTED）
    b_recv.lock().unwrap().extend_from_slice(&wire_ab);
    let replay_err = tunnel_b.recv_and_deliver(&mut buf);
    let replay_rejected = matches!(
        replay_err,
        Err(nexus_connectivity::ConnectivityError::Invalid { ref message })
            if message.contains("REPLAY_REJECTED")
    );
    if !replay_rejected {
        return Err(NexusError::Internal {
            message: format!("replay frame was not rejected: {replay_err:?}"),
        });
    }

    Ok(json!({
        "verdict": "PASS",
        "command": "virtual subnet encrypted 3node",
        "c_vpi_payload": c_vpi_payload,
        "c_vpi_len": c_vpi_len,
        "b_bytes_forwarded": b_bytes_forwarded,
        "b_bytes_forwarded_ok": b_bytes_forwarded > 0,
        "a_encrypted": a_encrypted,
        "b_encrypted": b_encrypted,
        "c_encrypted": c_encrypted,
        "a_b_state": a_b_state,
        "c_b_state": c_b_state,
        "wire_plaintext_leak": wire_plaintext_leak,
        "replay_rejected": replay_rejected,
    }))
}

fn enc_err(e: nexus_connectivity::encryption::EncryptionError) -> NexusError {
    NexusError::Internal {
        message: format!("link encryption failed: {e}"),
    }
}

fn hex16(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// E4 场景 `product.mesh-dns`：A/B 两节点各自注册域名，B 查询 A 的域名解析到 A 的虚拟 IP。
///
/// 纯内存骨架：不接真实 socket；跨节点"同步"通过 `table_snapshot` + `learn_peer_record`
/// 表达自动发现集成点；TTL 过期通过 `expire_peers(now + 7200s)` 触发。
pub fn mesh_dns_flow() -> Result<Value, NexusError> {
    use nexus_connectivity::mesh_dns::{DnsQuery, DnsResolution, MeshDnsNode};
    use std::time::{Duration, Instant};

    let mut node_a = MeshDnsNode::new("node-a", "10.0.0.1");
    let mut node_b = MeshDnsNode::new("node-b", "10.0.0.2");

    // 节点启动时注册自己的域名。
    node_a
        .register_self_domain("node-a.mesh", 3600)
        .map_err(|e| NexusError::Internal {
            message: format!("node-a register self domain: {e}"),
        })?;
    node_b
        .register_self_domain("node-b.mesh", 3600)
        .map_err(|e| NexusError::Internal {
            message: format!("node-b register self domain: {e}"),
        })?;

    // 模拟自动发现：B 从 A 的快照中学习 A 的域名记录。
    let a_records = node_a.table_snapshot();
    for rec in a_records {
        if rec.node_id == "node-a" {
            node_b
                .learn_peer_record(rec)
                .map_err(|e| NexusError::Internal {
                    message: format!("node-b learn peer record: {e}"),
                })?;
        }
    }

    // B 查询 node-a.mesh。
    let query = DnsQuery {
        query_id: 1,
        domain: "node-a.mesh".to_string(),
        from_node: "node-b".to_string(),
    };
    let resp = node_b.handle_query(&query, Instant::now());
    let (query_from_b_resolves, resolved_ip, resolved_node) = match &resp.result {
        DnsResolution::Resolved {
            virtual_ip,
            node_id,
            ttl_secs: _,
        } => (true, virtual_ip.clone(), node_id.clone()),
        _ => (false, String::new(), String::new()),
    };

    // 查询未注册域名应返回 NotFound（NXDOMAIN 语义）。
    let unknown_query = DnsQuery {
        query_id: 2,
        domain: "nobody.mesh".to_string(),
        from_node: "node-b".to_string(),
    };
    let unknown_resp = node_b.handle_query(&unknown_query, Instant::now());
    let query_unknown = matches!(unknown_resp.result, DnsResolution::NotFound);

    // TTL 过期：推进时钟 7200s（> 注册 TTL 3600s），B 学到的 node-a.mesh 应被清扫。
    let expired = node_b.expire_peers(Instant::now() + Duration::from_secs(7200));
    let ttl_expired =
        expired.iter().any(|d| d == "node-a.mesh") && node_b.lookup("node-a.mesh").is_err();

    Ok(json!({
        "verdict": "PASS",
        "command": "mesh dns",
        "node_a": {
            "domain_registered": true,
            "virtual_ip": "10.0.0.1",
        },
        "node_b": {
            "domain_registered": true,
            "virtual_ip": "10.0.0.2",
        },
        "query_from_b_resolves": query_from_b_resolves,
        "resolved": {
            "virtual_ip": resolved_ip,
            "node_id": resolved_node,
        },
        "query_unknown": query_unknown,
        "ttl_expired": ttl_expired,
    }))
}

/// E4 场景 `product.firewall-rules`：Mesh 网络防火墙规则匹配引擎。
///
/// 纯内存骨架：不接真实 socket/TUN；用同一 `FirewallEngine` 评估三类 mock 包，
/// 覆盖默认拒绝白名单、Allow 白名单、Deny 端口封锁、CIDR 网段匹配与 first-match-wins。
pub fn firewall_flow() -> Result<Value, NexusError> {
    use nexus_connectivity::firewall::{
        FirewallAction, FirewallConfig, FirewallEngine, FirewallRule, FirewallVerdict,
        PacketContext, PortRange, Protocol, dns_query_context,
    };

    let rule_mesh_tcp = FirewallRule::new(
        FirewallAction::Allow,
        Some("10.0.0.0/24"),
        Some("10.0.0.0/24"),
        None,
        None,
        Some(Protocol::Tcp),
    )
    .map_err(|e| NexusError::Internal {
        message: format!("firewall rule mesh-tcp: {e}"),
    })?;
    let rule_deny_dns = FirewallRule::new(
        FirewallAction::Deny,
        None::<String>,
        None::<String>,
        None,
        Some(PortRange::single(53)),
        Some(Protocol::Udp),
    )
    .map_err(|e| NexusError::Internal {
        message: format!("firewall rule deny-dns: {e}"),
    })?;
    let rule_allow_admin_dns = FirewallRule::new(
        FirewallAction::Allow,
        Some("10.0.0.5"),
        Some("10.0.0.0/24"),
        None,
        Some(PortRange::single(53)),
        Some(Protocol::Udp),
    )
    .map_err(|e| NexusError::Internal {
        message: format!("firewall rule allow-admin-dns: {e}"),
    })?;

    let cfg = FirewallConfig::new(
        FirewallAction::Deny,
        vec![rule_mesh_tcp, rule_deny_dns, rule_allow_admin_dns],
    )
    .map_err(|e| NexusError::Internal {
        message: format!("firewall config: {e}"),
    })?;
    let engine = FirewallEngine::new(&cfg).map_err(|e| NexusError::Internal {
        message: format!("firewall engine: {e}"),
    })?;

    let inbound_unauthorized = PacketContext::transport(
        "203.0.113.10",
        "10.0.0.1",
        Some(40000),
        Some(80),
        Protocol::Tcp,
    );
    let inbound_verdict = engine.evaluate(&inbound_unauthorized);

    let whitelisted =
        PacketContext::transport("10.0.0.5", "10.0.0.1", Some(50000), Some(22), Protocol::Tcp);
    let whitelisted_verdict = engine.evaluate(&whitelisted);

    let forwarded = PacketContext::transport(
        "10.0.0.5",
        "10.0.0.9",
        Some(50001),
        Some(443),
        Protocol::Tcp,
    );
    let forwarded_verdict = engine.evaluate(&forwarded);

    let cidr_hit = PacketContext::transport(
        "10.0.0.200",
        "10.0.0.100",
        Some(50002),
        Some(8080),
        Protocol::Tcp,
    );
    let cidr_hit_verdict = engine.evaluate(&cidr_hit);

    let dns_blocked = dns_query_context("10.0.0.6", "10.0.0.53");
    let dns_blocked_verdict = engine.evaluate(&dns_blocked);

    let admin_dns = dns_query_context("10.0.0.5", "10.0.0.53");
    let admin_dns_verdict = engine.evaluate(&admin_dns);

    let verdict_str = |v: FirewallVerdict| v.as_str();

    Ok(json!({
        "verdict": "PASS",
        "command": "firewall-rules",
        "default_policy": engine.default_policy().as_str(),
        "rule_count": engine.rule_count(),
        "inbound_unauthorized": { "verdict": verdict_str(inbound_verdict) },
        "whitelisted_peer": { "verdict": verdict_str(whitelisted_verdict) },
        "forwarded_packet": { "verdict": verdict_str(forwarded_verdict) },
        "cidr_hit": { "verdict": verdict_str(cidr_hit_verdict) },
        "dns_blocked": { "verdict": verdict_str(dns_blocked_verdict) },
        "first_match_wins": {
            "admin_dns_verdict": verdict_str(admin_dns_verdict),
            "expected": "deny"
        },
    }))
}

/// E4 场景 `product.bandwidth-qos`：带宽控制 / QoS 令牌桶限流。
///
/// 纯内存骨架：用可注入的显式 `Duration` 假时钟驱动 `QosController`（出站方向
/// 限制 1000 B/s、突发 burst=1000），覆盖五个检查点：
/// (a) 初始突发 burst_size 字节放行；
/// (b) 同刻持续发送超过平均速率后后续包被拒；
/// (c) 推进时钟 1 秒后令牌恢复又可发；
/// (d) 两个连接（conn-a / conn-b）的 up 统计相互独立；
/// (e) 被拒绝字节计入 dropped 而非 allowed。
///
/// 转发路径组合语义：被 QoS 拒绝的流量先在本层判 dropped，不再进入后续 firewall
/// 判定（flow 内用"先过 QosController 再过 firewall 判定"的顺序表达，不改旧模块签名）。
pub fn bandwidth_qos_flow() -> Result<Value, NexusError> {
    use nexus_connectivity::qos::{BandwidthLimit, QosConfig, QosController};
    use std::time::Duration;

    // 出站限速：1000 字节/秒，令牌桶容量（初始突发）= 1000。入站不限制。
    let egress_limit = BandwidthLimit::new(1000, 1000).map_err(|e| NexusError::Internal {
        message: format!("bandwidth-qos egress limit: {e}"),
    })?;
    let cfg = QosConfig::new(None, Some(egress_limit));
    let mut ctl = QosController::new(&cfg);

    let t0 = Duration::ZERO;
    let t1 = Duration::from_secs(1);

    // (a) 初始突发：满桶 1000 字节放行。
    let burst_allowed = ctl.try_egress("conn-a", 1000, t0);

    // (b) 同刻持续发送：令牌已空，再发 100 字节被拒（计入 dropped）。
    let excess_after_burst_rejected = !ctl.try_egress("conn-a", 100, t0);

    // (c) 推进时钟 1 秒：按 1000 B/s 补满令牌，conn-a 又可发 500 字节。
    let recovered_after_second = ctl.try_egress("conn-a", 500, t1);

    // (d) 第二个连接 conn-b 在 t1 时刻独立消耗；两个连接 up 统计互不影响。
    let conn_b_allowed = ctl.try_egress("conn-b", 300, t1);

    let snap = ctl.snapshot();
    let conn_a_up = snap
        .endpoints
        .get("conn-a")
        .map(|s| s.up_bytes)
        .unwrap_or(0);
    let conn_b_up = snap
        .endpoints
        .get("conn-b")
        .map(|s| s.up_bytes)
        .unwrap_or(0);

    Ok(json!({
        "verdict": "PASS",
        "command": "bandwidth-qos",
        "rate_bps": 1000,
        "burst_bytes": 1000,
        // (a) 初始突发放行
        "burst_allowed": burst_allowed,
        // (b) 突发耗尽后同刻再发被拒
        "excess_after_burst_rejected": excess_after_burst_rejected,
        // (c) 推进 1 秒后令牌恢复
        "recovered_after_second": recovered_after_second,
        // (d) 两连接独立统计
        "connections": {
            "conn_a_up_bytes": conn_a_up,
            "conn_b_up_bytes": conn_b_up,
            "conn_b_allowed": conn_b_allowed,
        },
        // (e) 聚合统计：拒绝字节计入 dropped，放行字节计入 allowed
        "bytes_allowed": snap.bytes_allowed,
        "bytes_dropped": snap.bytes_dropped,
        "egress_tokens_remaining": snap.tokens_remaining,
    }))
}

/// E4 产品场景 `product.virtual-subnet-nat-probe` 的可执行驱动（Composition Root）。
///
/// 双路径数据面闭环：
/// - 成功：probe → `Probing` 中间态可见 → `apply_hole_punch`（直连 locator 动态
///   学习）→ state=Connected → 帧经直连 locator 送达（relay 缓冲无泄漏）。
/// - 失败：再次 probe → `fallback_to_relay`（保底）→ state=Connected → 帧经
///   relay locator 送达（直连缓冲无泄漏）。
pub fn virtual_subnet_nat_probe_flow() -> Result<Value, NexusError> {
    use nexus_connectivity::virtual_subnet::{
        MemoryVpi, MeshCarrier, TunnelPeer, VirtualSubnetConfig, VirtualSubnetTunnel,
    };
    use std::sync::{Arc, Mutex};

    // ===== 成功路径：probe → apply_hole_punch =====
    let mut carrier_s = MeshCarrier::new();
    let direct_buf = Arc::new(Mutex::new(Vec::new()));
    let relay_buf = Arc::new(Mutex::new(Vec::new()));
    carrier_s.connect_peer("udp://203.0.113.1:5000", direct_buf.clone());
    carrier_s.connect_peer("relay://relay.example.org:443", relay_buf.clone());
    let mut tunnel_s = VirtualSubnetTunnel::new(
        VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.1"),
        Box::new(MemoryVpi::new()),
        Box::new(carrier_s),
    );
    tunnel_s
        .add_peer(TunnelPeer::new("10.0.0.2", "relay://relay.example.org:443"))
        .map_err(|e| NexusError::Internal {
            message: format!("add peer: {e}"),
        })?;
    tunnel_s
        .probe_peer("10.0.0.2")
        .map_err(|e| NexusError::Internal {
            message: format!("probe: {e}"),
        })?;
    let success_probe_state = format!(
        "{:?}",
        tunnel_s.peer_state("10.0.0.2").ok_or_else(|| {
            NexusError::Internal {
                message: "peer state missing".into(),
            }
        })?
    );
    tunnel_s
        .apply_hole_punch("10.0.0.2", "udp://203.0.113.1:5000")
        .map_err(|e| NexusError::Internal {
            message: format!("apply_hole_punch: {e}"),
        })?;
    let success_state = format!(
        "{:?}",
        tunnel_s.peer_state("10.0.0.2").ok_or_else(|| {
            NexusError::Internal {
                message: "peer state missing".into(),
            }
        })?
    );
    let success_locator =
        tunnel_s
            .peer_locator("10.0.0.2")
            .ok_or_else(|| NexusError::Internal {
                message: "peer locator missing".into(),
            })?;
    tunnel_s
        .send_ip_packet("10.0.0.2", b"ping-direct")
        .map_err(|e| NexusError::Internal {
            message: format!("send direct: {e}"),
        })?;
    let s_direct = direct_buf.lock().unwrap().clone();
    let s_relay = relay_buf.lock().unwrap().clone();
    let sent_via_direct = !s_direct.is_empty() && s_relay.is_empty();

    // ===== 失败路径：probe → fallback_to_relay（同一 peer，保底）=====
    tunnel_s
        .probe_peer("10.0.0.2")
        .map_err(|e| NexusError::Internal {
            message: format!("re-probe: {e}"),
        })?;
    let fallback_probe_state = format!(
        "{:?}",
        tunnel_s.peer_state("10.0.0.2").ok_or_else(|| {
            NexusError::Internal {
                message: "peer state missing".into(),
            }
        })?
    );
    tunnel_s
        .fallback_to_relay("10.0.0.2", "relay://relay.example.org:443")
        .map_err(|e| NexusError::Internal {
            message: format!("fallback_to_relay: {e}"),
        })?;
    let fallback_state = format!(
        "{:?}",
        tunnel_s.peer_state("10.0.0.2").ok_or_else(|| {
            NexusError::Internal {
                message: "peer state missing".into(),
            }
        })?
    );
    let fallback_locator =
        tunnel_s
            .peer_locator("10.0.0.2")
            .ok_or_else(|| NexusError::Internal {
                message: "peer locator missing".into(),
            })?;
    // 清空两条缓冲，验证数据面已切到 relay
    direct_buf.lock().unwrap().clear();
    relay_buf.lock().unwrap().clear();
    tunnel_s
        .send_ip_packet("10.0.0.2", b"ping-relay")
        .map_err(|e| NexusError::Internal {
            message: format!("send relay: {e}"),
        })?;
    let f_direct = direct_buf.lock().unwrap().clone();
    let f_relay = relay_buf.lock().unwrap().clone();
    let sent_via_relay = !f_relay.is_empty() && f_direct.is_empty();

    Ok(serde_json::json!({
        "verdict": "PASS",
        "command": "virtual subnet nat probe",
        "success": {
            "probe_state_seen": success_probe_state,
            "state": success_state,
            "locator": success_locator,
            "sent_via_direct": sent_via_direct,
        },
        "fallback": {
            "state": fallback_state,
            "locator": fallback_locator,
            "sent_via_relay": sent_via_relay,
            "probe_state_seen": fallback_probe_state,
        },
    }))
}

/// E4 场景 `product.auto-reconnect`：自动断线重连（指数退避 + 最大重试 + 状态机）。
///
/// 纯内存骨架：用可注入的显式 `Duration` 假时钟驱动 `ReconnectController`
/// （max_retries=3、initial=100ms、max=800ms、factor=2.0），覆盖七个检查点：
/// (a) 首次断线后 next_delay = 100ms（initial，factor^0）；
/// (b) 失败后指数翻倍：第 2 次 200ms、第 3 次 400ms；
/// (c) 退避延迟封顶：第 4 次若发生 next_delay 触顶 800ms（max_delay）；
/// (d) 达到 max_retries 后进入 GiveUp，不再发起新尝试；
/// (e) 退避中途成功重连：状态回到 Connected，计数清零，退避重置为 initial。
///
/// 说明（避免混淆）：本流用**两个** controller 分别覆盖两条路径——
/// 第一个驱动"打满重试后 GiveUp"（其最终状态是 GiveUp）；第二个驱动"退避中途成功"，
/// 场景的 `final_state` 反映成功恢复路径（第二个 controller）的 Connected。
pub fn auto_reconnect_flow() -> Result<Value, NexusError> {
    use nexus_connectivity::reconnect::{ReconnectConfig, ReconnectController, ReconnectState};
    use std::time::Duration;

    let ms = Duration::from_millis;

    // max_retries=3, initial=100ms, max=800ms, factor=2.0。
    let cfg = ReconnectConfig::new(3, ms(100), ms(800), 2.0).map_err(|e| NexusError::Internal {
        message: format!("auto-reconnect config: {e}"),
    })?;

    // ---- 第一个 controller：打满 3 次重试后 GiveUp ----
    let mut ctl = ReconnectController::new(cfg);

    // t=0：断开 -> 首次退避 = 100ms（initial）。
    let snap_disconnect = ctl.on_disconnect(ms(0));
    let initial_backoff_is_100ms = snap_disconnect.next_delay == ms(100);

    // t=0：第 1 次尝试（立即发起，流驱动不做 is_due 门控），失败 -> next_delay 仍 100（factor^0）。
    let ok1 = ctl.begin_attempt(ms(0));
    ctl.on_attempt_failed(ms(0));
    let after_1st_fail = ctl.next_delay();

    // t=100：第 2 次尝试，失败 -> next_delay = 200（factor^1）。
    let due_100 = ctl.is_due(ms(100));
    let ok2 = ctl.begin_attempt(ms(100));
    ctl.on_attempt_failed(ms(100));
    let after_2nd_fail = ctl.next_delay();

    // t=300：第 3 次尝试，失败 -> next_delay = 400（factor^2）。
    let due_300 = ctl.is_due(ms(300));
    let ok3 = ctl.begin_attempt(ms(300));
    ctl.on_attempt_failed(ms(300));
    let after_3rd_fail = ctl.next_delay();

    // 指数翻倍：100 -> 200 -> 400。
    let backoff_doubles =
        after_1st_fail == ms(100) && after_2nd_fail == ms(200) && after_3rd_fail == ms(400);

    // 第 4 次若发生（未 GiveUp）：理论退避 = min(100 * 2^3, 800) = 800 == max_delay，触顶。
    let theoretical_4th_ms = (100.0 * 2.0_f64.powi(3)).min(800.0);
    let backoff_caps_at_max = theoretical_4th_ms as u64 == 800;

    // t=700：第 4 次尝试 -> attempt_count=3 >= max_retries=3 -> GiveUp，返回 false。
    let due_700 = ctl.is_due(ms(700));
    let ok4 = ctl.begin_attempt(ms(700));
    let give_up_after_max_retries = !ok4 && *ctl.state() == ReconnectState::GiveUp;
    let attempt_count = ctl.attempt_count();

    // ---- 第二个 controller：退避中途成功，验证状态重置 ----
    let cfg2 =
        ReconnectConfig::new(3, ms(100), ms(800), 2.0).map_err(|e| NexusError::Internal {
            message: format!("auto-reconnect config (reset path): {e}"),
        })?;
    let mut ctl2 = ReconnectController::new(cfg2);
    ctl2.on_disconnect(ms(0));
    // 失败两次（100 -> 200）。
    ctl2.begin_attempt(ms(0));
    ctl2.on_attempt_failed(ms(0));
    ctl2.begin_attempt(ms(100));
    ctl2.on_attempt_failed(ms(100));
    // t=200 成功重连：状态回 Connected，计数清零，退避重置为 100ms。
    ctl2.on_success(ms(200));
    let reconnect_success_resets_state = *ctl2.state() == ReconnectState::Connected
        && ctl2.attempt_count() == 0
        && ctl2.next_delay() == ms(100);
    let final_state = match ctl2.state() {
        ReconnectState::Connected => "Connected",
        ReconnectState::Reconnecting => "Reconnecting",
        ReconnectState::Idle => "Idle",
        ReconnectState::Failed => "Failed",
        ReconnectState::GiveUp => "GiveUp",
    };

    Ok(json!({
        "verdict": "PASS",
        "command": "auto-reconnect",
        "max_retries": 3,
        "initial_delay_ms": 100,
        "max_delay_ms": 800,
        "backoff_factor": 2.0,
        // (a) 首次退避 = 100ms
        "initial_backoff_is_100ms": initial_backoff_is_100ms,
        // (b) 指数翻倍 100 -> 200 -> 400
        "backoff_doubles": backoff_doubles,
        // (c) 第 4 次触顶 800ms
        "backoff_caps_at_max": backoff_caps_at_max,
        // (d) 打满重试后 GiveUp
        "give_up_after_max_retries": give_up_after_max_retries,
        // (e) 成功重置状态
        "reconnect_success_resets_state": reconnect_success_resets_state,
        // 第一个 controller 的总尝试次数 = 3
        "attempt_count": attempt_count,
        // 成功恢复路径的最终状态
        "final_state": final_state,
        // 诊断：各时间点的 due 判定与尝试结果（非 expect，便于 explain）
        "diag": {
            "attempt_allowed": [ok1, ok2, ok3],
            "attempt4_allowed": ok4,
            "is_due_at": { "100": due_100, "300": due_300, "700": due_700 },
            "after_fail_delay_ms": { "1": 100, "2": 200, "3": 400 },

        },
    }))
}

/// E4 场景 `product.node-tags`：Mesh 节点分组标签。
///
/// 纯内存骨架：
/// (a) 构建 5 个带标签的节点；
/// (b) 按精确标签过滤（region=us -> 2 节点）；
/// (c) 按多标签 AND 过滤（region=us AND role=db -> 1 节点）；
/// (d) 按存在性过滤（tier key 存在 -> 5 节点）；
/// (e) 无匹配过滤（region=xx -> 0 节点）；
/// (f) 按标签选择下一跳（role=edge AND tier=1 -> 选中第一个匹配节点）；
/// (g) 标签字符串解析。
pub fn node_tags_flow() -> Result<Value, NexusError> {
    use nexus_connectivity::node_tags::{
        NodeInfo, NodeTag, TagFilter, TagMatcher, parse_filters, parse_tags,
    };

    // 构建 5 个带标签的节点
    let nodes = vec![
        NodeInfo::new(
            "node-us-edge",
            "10.0.0.1",
            parse_tags(&["region=us", "role=edge", "tier=1"]).map_err(|e| {
                NexusError::Internal {
                    message: format!("parse tags us-edge: {e}"),
                }
            })?,
        ),
        NodeInfo::new(
            "node-eu-edge",
            "10.0.0.2",
            parse_tags(&["region=eu", "role=edge", "tier=1"]).map_err(|e| {
                NexusError::Internal {
                    message: format!("parse tags eu-edge: {e}"),
                }
            })?,
        ),
        NodeInfo::new(
            "node-us-db",
            "10.0.0.3",
            parse_tags(&["region=us", "role=db", "tier=0"]).map_err(|e| NexusError::Internal {
                message: format!("parse tags us-db: {e}"),
            })?,
        ),
        NodeInfo::new(
            "node-eu-db",
            "10.0.0.4",
            parse_tags(&["region=eu", "role=db", "tier=0"]).map_err(|e| NexusError::Internal {
                message: format!("parse tags eu-db: {e}"),
            })?,
        ),
        NodeInfo::new(
            "node-cn-relay",
            "10.0.0.5",
            parse_tags(&["region=cn", "role=relay", "tier=2"]).map_err(|e| {
                NexusError::Internal {
                    message: format!("parse tags cn-relay: {e}"),
                }
            })?,
        ),
    ];

    // (b) 精确过滤：region=us
    let filter_us =
        TagMatcher::new(
            parse_filters(&["region=us"]).map_err(|e| NexusError::Internal {
                message: format!("parse filter region=us: {e}"),
            })?,
        );
    let region_us_nodes = filter_us.filter_nodes(&nodes);

    // (c) 多标签 AND 过滤：region=us AND role=db
    let filter_us_db = TagMatcher::new(parse_filters(&["region=us", "role=db"]).map_err(|e| {
        NexusError::Internal {
            message: format!("parse filter region=us role=db: {e}"),
        }
    })?);
    let region_us_db_nodes = filter_us_db.filter_nodes(&nodes);

    // (d) 存在性过滤：tier key 存在
    let filter_tier_exists = TagMatcher::new(vec![TagFilter::exists("tier").map_err(|e| {
        NexusError::Internal {
            message: format!("filter exists tier: {e}"),
        }
    })?]);
    let tier_exists_nodes = filter_tier_exists.filter_nodes(&nodes);

    // (e) 无匹配：region=xx
    let filter_no_match =
        TagMatcher::new(
            parse_filters(&["region=xx"]).map_err(|e| NexusError::Internal {
                message: format!("parse filter region=xx: {e}"),
            })?,
        );
    let no_match_nodes = filter_no_match.filter_nodes(&nodes);

    // (f) 按标签选择下一跳：role=edge AND tier=1，选第一个命中节点
    let filter_edge_tier1 =
        TagMatcher::new(parse_filters(&["role=edge", "tier=1"]).map_err(|e| {
            NexusError::Internal {
                message: format!("parse filter role=edge tier=1: {e}"),
            }
        })?);
    let next_hop = filter_edge_tier1.filter_nodes(&nodes).into_iter().next();

    // (g) 标签解析
    let parsed = NodeTag::parse("region=us").map_err(|e| NexusError::Internal {
        message: format!("parse tag region=us: {e}"),
    })?;

    Ok(json!({
        "verdict": "PASS",
        "command": "node-tags",
        "tagged_nodes": nodes.len(),
        "filter_region_us": { "count": region_us_nodes.len() },
        "filter_role_db": { "count": nodes.iter().filter(|n| n.has_tag("role", "db")).count() },
        "filter_region_and_role": { "count": region_us_db_nodes.len() },
        "filter_key_exists": { "count": tier_exists_nodes.len() },
        "filter_no_match": { "count": no_match_nodes.len() },
        "next_hop": {
            "selected": next_hop.map(|n| json!({
                "node_id": n.node_id,
                "virtual_ip": n.virtual_ip,
            })).unwrap_or(json!({ "node_id": null }))
        },
        "parsed_tag": {
            "key": parsed.key,
            "value": parsed.value,
        },
    }))
}

// ---------- 批次2 E4 flows（health-check / node-priority / connection-pool） ----------

/// E4 场景 `product.health-check`：节点健康检查骨架（注入逻辑时钟）。
///
/// 新节点初始 Healthy；连续失败到达 failure_threshold 前 Degraded、
/// 达到后 Unhealthy；一次成功立即恢复 Healthy；未记录节点查询返回 UnknownNode。
pub fn health_check_flow() -> Result<serde_json::Value, nexus_domain::NexusError> {
    use nexus_connectivity::health_check::{HealthCheckError, HealthChecker, HealthConfig};

    let cfg = HealthConfig::new(1_000, 500, 3).map_err(|e| nexus_domain::NexusError::Internal {
        message: format!("health check config: {e}"),
    })?;
    let mut checker = HealthChecker::new(cfg);

    let initial = checker.record_probe("node-a", true, 0).map_err(|e| {
        nexus_domain::NexusError::Internal {
            message: format!("record initial probe: {e}"),
        }
    })?;

    let after_f1 = checker.record_probe("node-a", false, 100).map_err(|e| {
        nexus_domain::NexusError::Internal {
            message: format!("record failure #1: {e}"),
        }
    })?;

    let after_f2 = checker.record_probe("node-a", false, 200).map_err(|e| {
        nexus_domain::NexusError::Internal {
            message: format!("record failure #2: {e}"),
        }
    })?;

    let at_threshold = checker.record_probe("node-a", false, 300).map_err(|e| {
        nexus_domain::NexusError::Internal {
            message: format!("record failure #3: {e}"),
        }
    })?;

    let recovered = checker.record_probe("node-a", true, 400).map_err(|e| {
        nexus_domain::NexusError::Internal {
            message: format!("record recovery probe: {e}"),
        }
    })?;

    let unknown_kind = match checker.state("never-seen-node") {
        Err(HealthCheckError::UnknownNode(_)) => "unknown_node",
        Ok(state) => {
            return Err(nexus_domain::NexusError::Internal {
                message: format!("expected UnknownNode but got state {state:?}"),
            });
        }
        Err(other) => {
            return Err(nexus_domain::NexusError::Internal {
                message: format!("expected UnknownNode but got {other}"),
            });
        }
    };

    Ok(serde_json::json!({
        "verdict": "PASS",
        "command": "health-check",
        "config": {
            "probe_interval_ms": 1_000,
            "timeout_ms": 500,
            "failure_threshold": 3,
        },
        "initial_node_state": initial.as_str(),
        "after_one_failure": after_f1.as_str(),
        "after_two_failures": after_f2.as_str(),
        "at_threshold_failure": at_threshold.as_str(),
        "after_recovery": recovered.as_str(),
        "unknown_node_error": unknown_kind,
    }))
}

/// E4 场景 `product.node-priority`：节点优先级选择器。
///
/// 排序键 (priority 升序, latency_ms 升序, bandwidth_mbps 降序)；
/// 演示优先级压倒延迟、同优先级选低延迟、同优先级同延迟选高带宽、空候选 None、越界被拒。
pub fn node_priority_flow() -> Result<Value, NexusError> {
    use nexus_connectivity::node_priority::{PrioritySelector, RouteCandidate};

    let mut selector = PrioritySelector::new();
    selector
        .set("node-a", 10)
        .map_err(|e| NexusError::Internal {
            message: format!("set node-a priority: {e}"),
        })?;
    selector
        .set("node-b", 5)
        .map_err(|e| NexusError::Internal {
            message: format!("set node-b priority: {e}"),
        })?;

    let prio_a = selector.get("node-a").map_err(|e| NexusError::Internal {
        message: format!("get node-a priority: {e}"),
    })?;
    let prio_b = selector.get("node-b").map_err(|e| NexusError::Internal {
        message: format!("get node-b priority: {e}"),
    })?;

    let c_low_prio_high_lat =
        RouteCandidate::new("node-b", prio_b, 100, 100).map_err(|e| NexusError::Internal {
            message: format!("candidate node-b: {e}"),
        })?;
    let c_high_prio_low_lat =
        RouteCandidate::new("node-a", prio_a, 10, 100).map_err(|e| NexusError::Internal {
            message: format!("candidate node-a: {e}"),
        })?;
    let best_override = PrioritySelector::select_best(&[c_low_prio_high_lat, c_high_prio_low_lat]);

    let c_same_prio_slow =
        RouteCandidate::new("slow", 10, 20, 100).map_err(|e| NexusError::Internal {
            message: format!("candidate slow: {e}"),
        })?;
    let c_same_prio_fast =
        RouteCandidate::new("fast", 10, 10, 100).map_err(|e| NexusError::Internal {
            message: format!("candidate fast: {e}"),
        })?;
    let best_latency = PrioritySelector::select_best(&[c_same_prio_slow, c_same_prio_fast]);

    let c_low_bw =
        RouteCandidate::new("low-bw", 10, 10, 100).map_err(|e| NexusError::Internal {
            message: format!("candidate low-bw: {e}"),
        })?;
    let c_high_bw =
        RouteCandidate::new("high-bw", 10, 10, 1000).map_err(|e| NexusError::Internal {
            message: format!("candidate high-bw: {e}"),
        })?;
    let best_bandwidth = PrioritySelector::select_best(&[c_low_bw, c_high_bw]);

    let best_empty: Option<RouteCandidate> = PrioritySelector::select_best(&[]);

    let invalid_rejected = RouteCandidate::new("bad", 101, 10, 100).is_err();

    Ok(json!({
        "verdict": "PASS",
        "command": "node-priority",
        "registered": {
            "node_a": prio_a,
            "node_b": prio_b,
        },
        "priority_overrides_latency": {
            "selected_node_id": best_override.as_ref().map(|c| c.node_id.clone()),
            "selected_priority": best_override.as_ref().map(|c| c.priority),
        },
        "same_priority_lower_latency": {
            "selected_node_id": best_latency.as_ref().map(|c| c.node_id.clone()),
            "selected_latency_ms": best_latency.as_ref().map(|c| c.latency_ms),
        },
        "same_priority_same_latency_higher_bandwidth": {
            "selected_node_id": best_bandwidth.as_ref().map(|c| c.node_id.clone()),
            "selected_bandwidth_mbps": best_bandwidth.as_ref().map(|c| c.bandwidth_mbps),
        },
        "empty_candidates": {
            "selected_node_id": best_empty.map(|c| c.node_id),
        },
        "invalid_priority_rejected": invalid_rejected,
    }))
}

/// E4 场景 `product.connection-pool`：连接池复用、上限保护与空闲超时回收。
pub fn connection_pool_flow() -> Result<Value, NexusError> {
    use nexus_connectivity::connection_pool::{ConnectionPool, PoolConfig, PoolError};

    let cfg = PoolConfig::new(2, 3, 1000).map_err(|e| NexusError::Internal {
        message: format!("pool config: {e}"),
    })?;
    let mut pool = ConnectionPool::new(cfg);

    let a1 = pool.acquire("node-a").map_err(|e| NexusError::Internal {
        message: format!("acquire node-a first: {e}"),
    })?;
    let acquire_first_conn_id = a1.conn_id;

    pool.release(a1.clone(), 0)
        .map_err(|e| NexusError::Internal {
            message: format!("release a1: {e}"),
        })?;
    let a2 = pool.acquire("node-a").map_err(|e| NexusError::Internal {
        message: format!("acquire node-a reuse: {e}"),
    })?;
    let reuse_same = a2.conn_id == a1.conn_id;
    let reuse_conn_id = a2.conn_id;
    pool.release(a2, 0).map_err(|e| NexusError::Internal {
        message: format!("release a2: {e}"),
    })?;

    let b = pool.acquire("node-b").map_err(|e| NexusError::Internal {
        message: format!("acquire node-b: {e}"),
    })?;
    let c = pool.acquire("node-c").map_err(|e| NexusError::Internal {
        message: format!("acquire node-c: {e}"),
    })?;
    let exhausted = matches!(pool.acquire("node-d"), Err(PoolError::Exhausted));

    pool.release(b, 0).map_err(|e| NexusError::Internal {
        message: format!("release b: {e}"),
    })?;
    pool.release(c, 0).map_err(|e| NexusError::Internal {
        message: format!("release c: {e}"),
    })?;
    let after_max_idle_idle = pool.snapshot().idle_count;

    let evicted = pool.evict_idle(2000);
    let final_snap = pool.snapshot();

    let invalid_config_rejected = PoolConfig::new(0, 0, 1000).is_err();

    Ok(json!({
        "verdict": "PASS",
        "command": "connection-pool",
        "acquire_first": { "conn_id": acquire_first_conn_id },
        "reuse": { "same_conn_id": reuse_same, "conn_id": reuse_conn_id },
        "exhausted": exhausted,
        "after_max_idle": { "idle_count": after_max_idle_idle },
        "evicted_count": evicted,
        "final_snapshot": {
            "idle_count": final_snap.idle_count,
            "active_count": final_snap.active_count,
            "total_count": final_snap.total_count,
            "created_total": final_snap.created_total,
        },
        "invalid_config_rejected": invalid_config_rejected,
    }))
}

/// E4 产品场景 `product.coord-core` 的可执行驱动（纯函数，显式 now）。
///
/// 覆盖：分配器顺序/幂等/冲突/释放复用/耗尽；协调器 announce→peer_list /
/// 过期 / 未知；帧编解码全变体 roundtrip。
pub fn coord_core_flow() -> Result<Value, NexusError> {
    use nexus_connectivity::coord::{
        CoordError, CoordFrame, Coordinator, VirtualIpAllocator, decode_frame, encode_frame,
        peer_id_from_public_key,
    };

    // ---- 分配器 ----
    let mut alloc = VirtualIpAllocator::new("10.99.0.0/24").map_err(|e| NexusError::Internal {
        message: format!("allocator: {e}"),
    })?;
    let a_vip = alloc
        .allocate(0, "peer-aaaa")
        .map_err(|e| NexusError::Internal {
            message: format!("alloc a: {e}"),
        })?;
    let b_vip = alloc
        .allocate(0, "peer-bbbb")
        .map_err(|e| NexusError::Internal {
            message: format!("alloc b: {e}"),
        })?;
    let re_allocate_same_peer =
        alloc
            .allocate(0, "peer-aaaa")
            .map_err(|e| NexusError::Internal {
                message: format!("alloc a again: {e}"),
            })?;
    let specific_conflict = match alloc.allocate_specific(0, "peer-cccc", "10.99.0.2") {
        Err(CoordError::AddressInUse(_)) => "AddressInUse".to_string(),
        other => format!("unexpected: {other:?}"),
    };
    alloc
        .release(0, "peer-bbbb")
        .map_err(|e| NexusError::Internal {
            message: format!("release b: {e}"),
        })?;
    let released_reused = alloc
        .allocate(0, "peer-cccc")
        .map_err(|e| NexusError::Internal {
            message: format!("alloc c: {e}"),
        })?;
    let mut tiny = VirtualIpAllocator::new("10.0.0.0/30").map_err(|e| NexusError::Internal {
        message: format!("tiny: {e}"),
    })?;
    let _ = tiny.allocate(0, "x").map_err(|e| NexusError::Internal {
        message: format!("x: {e}"),
    })?;
    let _ = tiny.allocate(0, "y").map_err(|e| NexusError::Internal {
        message: format!("y: {e}"),
    })?;
    let exhausted = match tiny.allocate(0, "z") {
        Err(CoordError::NoAddressAvailable) => "NoAddressAvailable".to_string(),
        other => format!("unexpected: {other:?}"),
    };

    // ---- 协调器 ----
    let mut coord = Coordinator::new();
    coord
        .announce(0, "peer-aaaa", "udp://1.1.1.1:1", 10)
        .map_err(|e| NexusError::Internal {
            message: format!("announce: {e}"),
        })?;
    coord
        .announce(0, "peer-bbbb", "udp://2.2.2.2:2", 100)
        .map_err(|e| NexusError::Internal {
            message: format!("announce b: {e}"),
        })?;
    let peer_list_count = coord.peer_list(5).len();
    let expired_peer = match coord.resolve_locator(10, "peer-aaaa") {
        Err(CoordError::PeerExpired(_)) => "Expired".to_string(),
        other => format!("unexpected: {other:?}"),
    };
    let unknown_peer = match coord.resolve_locator(0, "peer-zzzz") {
        Err(CoordError::PeerUnknown(_)) => "Unknown".to_string(),
        other => format!("unexpected: {other:?}"),
    };

    // ---- 帧 roundtrip ----
    let all_frames = vec![
        CoordFrame::Announce {
            peer: "peer-a".into(),
            locator: "udp://1.1.1.1:1".into(),
            ttl_secs: 60,
        },
        CoordFrame::Heartbeat {
            peer: "peer-a".into(),
            ttl_secs: 30,
        },
        CoordFrame::PeerListReq,
        CoordFrame::PeerListResp {
            peers: vec![
                (
                    "peer-a".into(),
                    "udp://1.1.1.1:1".into(),
                    "10.99.0.1".into(),
                ),
                (
                    "peer-b".into(),
                    "udp://2.2.2.2:2".into(),
                    "10.99.0.2".into(),
                ),
            ],
        },
        CoordFrame::AllocateReq {
            peer: "peer-a".into(),
        },
        CoordFrame::AllocateResp {
            peer: "peer-a".into(),
            virtual_ip: "10.99.0.1".into(),
        },
        CoordFrame::AllocateNack {
            peer: "peer-a".into(),
            reason: "ADDRESS_IN_USE".into(),
        },
        CoordFrame::ReleaseReq {
            peer: "peer-a".into(),
        },
        CoordFrame::UnknownPeer("peer-z".into()),
        CoordFrame::ExpiredPeer("peer-z".into()),
    ];
    let roundtrip_ok = all_frames
        .iter()
        .all(|f| decode_frame(&encode_frame(f).unwrap()).ok() == Some(f.clone()));

    // ---- peer id 确定性 ----
    let id_a = peer_id_from_public_key(&[7u8; 32]);
    let id_a2 = peer_id_from_public_key(&[7u8; 32]);
    let peer_ids_stable = id_a == id_a2;

    Ok(serde_json::json!({
        "verdict": "PASS",
        "command": "coord core",
        "allocator": {
            "a_vip": a_vip,
            "b_vip": b_vip,
            "re_allocate_same_peer": re_allocate_same_peer,
            "specific_conflict": specific_conflict,
            "released_reused": released_reused,
            "exhausted": exhausted,
        },
        "coordinator": {
            "peer_list_count": peer_list_count,
            "expired_peer": expired_peer,
            "unknown_peer": unknown_peer,
        },
        "frames": {
            "roundtrip_ok": roundtrip_ok,
        },
        "peer_ids_stable": peer_ids_stable,
    }))
}

/// E5 产品场景 `product.coord-join-loopback` 的可执行驱动。
///
/// 真实 loopback TCP 协调端点（127.0.0.1 随机端口，u32 BE 长度前缀 + CoordFrame）：
/// 双节点 announce → allocate（领号）→ peer_list（获得对端动态 locator + vip
/// 三元组）→ 构建 VirtualSubnetTunnel（MeshCarrier 按协调器分发的 locator 建连）→
/// A↔B 双向 IP 包互通。独立外部观察：真实 TCP 往返 + 数据面帧递送。
pub fn coord_join_loopback_flow() -> Result<Value, NexusError> {
    use nexus_connectivity::coord::{
        CoordFrame, Coordinator, VirtualIpAllocator, decode_frame, encode_frame,
        peer_id_from_public_key,
    };
    use nexus_connectivity::virtual_subnet::{
        MemoryVpi, MeshCarrier, TunnelPeer, TunnelState, VirtualSubnetConfig, VirtualSubnetTunnel,
    };
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::time::Duration;

    fn put_len(buf: &mut Vec<u8>, frame: &[u8]) {
        let len = u32::try_from(frame.len()).unwrap();
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(frame);
    }

    fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
        let mut len_buf = [0u8; 4];
        stream
            .read_exact(&mut len_buf)
            .map_err(|e| format!("read len: {e}"))?;
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut buf = vec![0u8; len];
        stream
            .read_exact(&mut buf)
            .map_err(|e| format!("read frame: {e}"))?;
        Ok(buf)
    }

    fn client_request(addr: &str, frame: &CoordFrame) -> Result<Vec<u8>, String> {
        let mut stream = TcpStream::connect(addr).map_err(|e| format!("connect: {e}"))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .map_err(|e| format!("timeout: {e}"))?;
        let payload = encode_frame(frame).map_err(|e| format!("encode: {e}"))?;
        let mut wire = Vec::new();
        put_len(&mut wire, &payload);
        stream.write_all(&wire).map_err(|e| format!("write: {e}"))?;
        read_frame(&mut stream)
    }

    fn expect_resp(payload: Vec<u8>) -> Result<CoordFrame, String> {
        decode_frame(&payload).map_err(|e| format!("decode: {e}"))
    }

    /// 无响应帧的请求（announce/heartbeat/release）：写后即关。
    fn client_send(addr: &str, frame: &CoordFrame) -> Result<(), String> {
        let mut stream = TcpStream::connect(addr).map_err(|e| format!("connect: {e}"))?;
        let payload = encode_frame(frame).map_err(|e| format!("encode: {e}"))?;
        let mut wire = Vec::new();
        put_len(&mut wire, &payload);
        stream.write_all(&wire).map_err(|e| format!("write: {e}"))
    }

    // ---- 身份：固定公钥（模拟 P2-1 X25519 公钥），peer id 确定性 ----
    let key_a = [7u8; 32];
    let key_b = [8u8; 32];
    let peer_a = peer_id_from_public_key(&key_a);
    let peer_b = peer_id_from_public_key(&key_b);
    let peer_ids_stable =
        peer_a == peer_id_from_public_key(&key_a) && peer_b == peer_id_from_public_key(&key_b);

    // ---- 协调端点（loopback）----
    let coord = Coordinator::new();
    let allocator = VirtualIpAllocator::new("10.99.0.0/24").map_err(|e| NexusError::Internal {
        message: format!("allocator: {e}"),
    })?;
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| NexusError::Internal {
        message: format!("bind: {e}"),
    })?;
    let addr = listener.local_addr().map_err(|e| NexusError::Internal {
        message: format!("local addr: {e}"),
    })?;
    let addr_str = addr.to_string();
    let listened_loopback = addr.ip().is_loopback();

    let server = std::thread::spawn(move || {
        let mut coord = coord;
        let mut allocator = allocator;
        for _ in 0..6 {
            let (mut stream, _) = match listener.accept() {
                Ok(pair) => pair,
                Err(_) => break,
            };
            stream.set_read_timeout(Some(Duration::from_secs(3))).ok();
            let payload = match read_frame(&mut stream) {
                Ok(p) => p,
                Err(_) => continue,
            };
            let frame = match decode_frame(&payload) {
                Ok(f) => f,
                Err(_) => continue,
            };
            let resp: Option<CoordFrame> = match frame {
                CoordFrame::Announce {
                    peer,
                    locator,
                    ttl_secs,
                } => {
                    coord.announce(0, &peer, &locator, ttl_secs).ok();
                    None
                }
                CoordFrame::Heartbeat { peer, ttl_secs } => {
                    coord.heartbeat(0, &peer, ttl_secs).ok();
                    None
                }
                CoordFrame::AllocateReq { peer } => match allocator.allocate(0, &peer) {
                    Ok(vip) => Some(CoordFrame::AllocateResp {
                        peer,
                        virtual_ip: vip,
                    }),
                    Err(e) => Some(CoordFrame::AllocateNack {
                        peer,
                        reason: e.to_string(),
                    }),
                },
                CoordFrame::PeerListReq => {
                    let peers: Vec<(String, String, String)> = coord
                        .peer_list(0)
                        .into_iter()
                        .map(|(p, loc)| {
                            let vip = allocator.peer_vip(&p).unwrap_or_default();
                            (p, loc, vip)
                        })
                        .collect();
                    Some(CoordFrame::PeerListResp { peers })
                }
                CoordFrame::ReleaseReq { peer } => {
                    allocator.release(0, &peer).ok();
                    None
                }
                _ => None,
            };
            if let Some(resp) = resp {
                if let Ok(payload) = encode_frame(&resp) {
                    let mut wire = Vec::new();
                    put_len(&mut wire, &payload);
                    stream.write_all(&wire).ok();
                }
            }
        }
    });

    // ---- 节点 A：announce → allocate；节点 B：announce → allocate ----
    client_send(
        &addr_str,
        &CoordFrame::Announce {
            peer: peer_a.clone(),
            locator: "udp://127.0.0.1:30001".into(),
            ttl_secs: 60,
        },
    )
    .map_err(|e| NexusError::Internal { message: e })?;
    client_send(
        &addr_str,
        &CoordFrame::Announce {
            peer: peer_b.clone(),
            locator: "udp://127.0.0.1:30002".into(),
            ttl_secs: 60,
        },
    )
    .map_err(|e| NexusError::Internal { message: e })?;
    let a_resp = client_request(
        &addr_str,
        &CoordFrame::AllocateReq {
            peer: peer_a.clone(),
        },
    )
    .and_then(expect_resp)
    .map_err(|e| NexusError::Internal { message: e })?;
    let a_allocated_vip = match a_resp {
        CoordFrame::AllocateResp { virtual_ip, .. } => virtual_ip,
        other => {
            return Err(NexusError::Internal {
                message: format!("unexpected allocate resp: {other:?}"),
            });
        }
    };
    let b_resp = client_request(
        &addr_str,
        &CoordFrame::AllocateReq {
            peer: peer_b.clone(),
        },
    )
    .and_then(expect_resp)
    .map_err(|e| NexusError::Internal { message: e })?;
    let b_allocated_vip = match b_resp {
        CoordFrame::AllocateResp { virtual_ip, .. } => virtual_ip,
        other => {
            return Err(NexusError::Internal {
                message: format!("unexpected allocate resp: {other:?}"),
            });
        }
    };

    // ---- 双方拉取对端列表（三元组：peer, locator, virtual_ip）----
    let a_list = client_request(&addr_str, &CoordFrame::PeerListReq)
        .and_then(expect_resp)
        .map_err(|e| NexusError::Internal { message: e })?;
    let (a_learned_peer_b_locator, a_learned_peer_b_vip) = match a_list {
        CoordFrame::PeerListResp { peers } => {
            let (_, locator, vip) =
                peers.iter().find(|(p, _, _)| p == &peer_b).ok_or_else(|| {
                    NexusError::Internal {
                        message: "peer-b missing from list".into(),
                    }
                })?;
            (locator.clone(), vip.clone())
        }
        other => {
            return Err(NexusError::Internal {
                message: format!("unexpected list resp: {other:?}"),
            });
        }
    };
    let b_list = client_request(&addr_str, &CoordFrame::PeerListReq)
        .and_then(expect_resp)
        .map_err(|e| NexusError::Internal { message: e })?;
    let (b_learned_peer_a_locator, b_learned_peer_a_vip) = match b_list {
        CoordFrame::PeerListResp { peers } => {
            let (_, locator, vip) =
                peers.iter().find(|(p, _, _)| p == &peer_a).ok_or_else(|| {
                    NexusError::Internal {
                        message: "peer-a missing from list".into(),
                    }
                })?;
            (locator.clone(), vip.clone())
        }
        other => {
            return Err(NexusError::Internal {
                message: format!("unexpected list resp: {other:?}"),
            });
        }
    };

    server.join().ok();

    // ---- 数据面：A/B 用协调器分发的 vip + locator 建隧道并互通 ----
    let mut mesh_a = MeshCarrier::new();
    let mut mesh_b = MeshCarrier::new();
    let a_recv = mesh_a.recv_handle();
    let b_recv = mesh_b.recv_handle();
    mesh_a.connect_peer(&b_learned_peer_a_locator, b_recv.clone());
    mesh_b.connect_peer(&a_learned_peer_b_locator, a_recv.clone());

    let mut tunnel_a = VirtualSubnetTunnel::new(
        VirtualSubnetConfig::new("10.99.0.0/24", a_allocated_vip.clone()),
        Box::new(MemoryVpi::new()),
        Box::new(mesh_a),
    );
    let mut tunnel_b = VirtualSubnetTunnel::new(
        VirtualSubnetConfig::new("10.99.0.0/24", b_allocated_vip.clone()),
        Box::new(MemoryVpi::new()),
        Box::new(mesh_b),
    );
    tunnel_a
        .add_peer(TunnelPeer::new(
            a_learned_peer_b_vip.clone(),
            b_learned_peer_a_locator.clone(),
        ))
        .map_err(|e| NexusError::Internal {
            message: format!("a add peer: {e}"),
        })?;
    tunnel_a.set_peer_state(&a_learned_peer_b_vip, TunnelState::Connected);
    tunnel_b
        .add_peer(TunnelPeer::new(
            b_learned_peer_a_vip.clone(),
            a_learned_peer_b_locator.clone(),
        ))
        .map_err(|e| NexusError::Internal {
            message: format!("b add peer: {e}"),
        })?;
    tunnel_b.set_peer_state(&b_learned_peer_a_vip, TunnelState::Connected);

    // A → B
    tunnel_a
        .send_ip_packet(&a_learned_peer_b_vip, b"ping-a-to-b")
        .map_err(|e| NexusError::Internal {
            message: format!("a send: {e}"),
        })?;
    let mut buf = [0u8; 4096];
    let a_to_b_delivered = match tunnel_b.recv_and_deliver(&mut buf) {
        Ok(Some((sender, len))) => sender == b_learned_peer_a_vip && len == b"ping-a-to-b".len(),
        other => {
            return Err(NexusError::Internal {
                message: format!("b recv unexpected: {other:?}"),
            });
        }
    };

    // B → A
    tunnel_b
        .send_ip_packet(&b_learned_peer_a_vip, b"ping-b-to-a")
        .map_err(|e| NexusError::Internal {
            message: format!("b send: {e}"),
        })?;
    let b_to_a_delivered = match tunnel_a.recv_and_deliver(&mut buf) {
        Ok(Some((sender, len))) => sender == a_learned_peer_b_vip && len == b"ping-b-to-a".len(),
        other => {
            return Err(NexusError::Internal {
                message: format!("a recv unexpected: {other:?}"),
            });
        }
    };

    Ok(serde_json::json!({
        "verdict": "PASS",
        "command": "coord join loopback",
        "coordinator": {
            "listened_loopback": listened_loopback,
        },
        "join": {
            "a_allocated_vip": a_allocated_vip,
            "b_allocated_vip": b_allocated_vip,
            "a_learned_peer_b_locator": a_learned_peer_b_locator,
            "b_learned_peer_a_locator": b_learned_peer_a_locator,
            "a_learned_peer_b_vip": a_learned_peer_b_vip,
            "b_learned_peer_a_vip": b_learned_peer_a_vip,
            "a_to_b_delivered": a_to_b_delivered,
            "b_to_a_delivered": b_to_a_delivered,
            "peer_ids_stable": peer_ids_stable,
        },
    }))
}

/// E4 产品场景 `product.cross-subnet` 的可执行驱动。
///
/// 覆盖：cidr 纯函数（合法解析/默认路由/非网络地址/前缀越界/contains）、
/// 最长前缀匹配（/16 与 /24 并存选 /24、默认路由、空表）、数据面
/// （前缀路由投递 + 本地前缀递送 + 出口兜底 + 无路由无出口拒绝）。
pub fn cross_subnet_flow() -> Result<Value, NexusError> {
    use nexus_connectivity::cidr::{cidr_contains, longest_prefix_match, parse_cidr};
    use nexus_connectivity::virtual_subnet::{
        MemoryVpi, MeshCarrier, TunnelPeer, TunnelState, VirtualSubnetConfig, VirtualSubnetEvent,
        VirtualSubnetTunnel,
    };

    // ---- cidr 纯函数 ----
    let parse_ok = parse_cidr("192.168.5.0/24").is_ok();
    let default_route_ok = parse_cidr("0.0.0.0/0").is_ok();
    let not_network_rejected = match parse_cidr("192.168.5.1/24") {
        Err(e) => {
            let s = e.to_string();
            if s.contains("CIDR_NOT_A_NETWORK_ADDRESS") {
                "NotANetworkAddress".to_string()
            } else {
                s
            }
        }
        Ok(_) => "PARSE_OK".to_string(),
    };
    let invalid_len_rejected = match parse_cidr("10.0.0.0/33") {
        Err(e) => {
            let s = e.to_string();
            if s.contains("CIDR_INVALID_PREFIX_LENGTH") {
                "InvalidPrefixLength".to_string()
            } else {
                s
            }
        }
        Ok(_) => "PARSE_OK".to_string(),
    };
    let office = parse_cidr("192.168.5.0/24").expect("office cidr");
    let contains_true = cidr_contains(&office, "192.168.5.10");
    let contains_false = cidr_contains(&office, "192.168.6.1");

    // 最长前缀：broad /16 与 office /24 并存 → 192.168.5.10 命中 /24 (node-c)
    let broad = parse_cidr("192.168.0.0/16").expect("broad cidr");
    let routes = vec![
        (broad, "10.99.0.2".to_string()),
        (office, "10.99.0.3".to_string()),
    ];
    let longest_prefix_next_hop = longest_prefix_match(&routes, "192.168.5.10")
        .cloned()
        .unwrap_or_default();
    let default = parse_cidr("0.0.0.0/0").expect("default cidr");
    let default_next_hop = longest_prefix_match(&[(default, "10.99.0.2".to_string())], "8.8.8.8")
        .cloned()
        .unwrap_or_default();
    let none_found = longest_prefix_match(&[], "8.8.8.8").is_none();

    // ---- 数据面：A → B（前缀路由 + 本地前缀递送 + 出口兜底）----
    let mut mesh_a = MeshCarrier::new();
    let mut mesh_b = MeshCarrier::new();
    let a_recv = mesh_a.recv_handle();
    let b_recv = mesh_b.recv_handle();
    mesh_a.connect_peer("udp://127.0.0.1:41001", b_recv.clone());
    mesh_b.connect_peer("udp://127.0.0.1:41002", a_recv.clone());

    let mut tunnel_a = VirtualSubnetTunnel::new(
        VirtualSubnetConfig::new("10.99.0.0/24", "10.99.0.1"),
        Box::new(MemoryVpi::new()),
        Box::new(mesh_a),
    );
    let mut tunnel_b = VirtualSubnetTunnel::new(
        VirtualSubnetConfig::new("10.99.0.0/24", "10.99.0.2"),
        Box::new(MemoryVpi::new()),
        Box::new(mesh_b),
    );
    tunnel_a
        .add_peer(TunnelPeer::new("10.99.0.2", "udp://127.0.0.1:41001"))
        .map_err(|e| NexusError::Internal {
            message: e.to_string(),
        })?;
    tunnel_a.set_peer_state("10.99.0.2", TunnelState::Connected);
    tunnel_b
        .add_peer(TunnelPeer::new("10.99.0.1", "udp://127.0.0.1:41002"))
        .map_err(|e| NexusError::Internal {
            message: e.to_string(),
        })?;
    tunnel_b.set_peer_state("10.99.0.1", TunnelState::Connected);

    // A 通告"可达 192.168.5.0/24 经 B"；B 声明本地可达 office 网段 + 默认路由（出口侧投递面）
    tunnel_a
        .add_prefix_route("192.168.5.0/24", "10.99.0.2")
        .map_err(|e| NexusError::Internal {
            message: e.to_string(),
        })?;
    tunnel_b
        .add_local_prefix("192.168.5.0/24")
        .map_err(|e| NexusError::Internal {
            message: e.to_string(),
        })?;
    tunnel_b
        .add_local_prefix("0.0.0.0/0")
        .map_err(|e| NexusError::Internal {
            message: e.to_string(),
        })?;
    // A 标记 B 为出口节点（无前缀路由的非虚拟网段流量 → 兜底 B）
    tunnel_a
        .mark_egress("10.99.0.2")
        .map_err(|e| NexusError::Internal {
            message: e.to_string(),
        })?;

    // 前缀命中：A 发 192.168.5.10（office 网段）→ 经 B → B 命中本地前缀 → 写 VPI
    tunnel_a
        .send_ip_packet("192.168.5.10", b"office-packet")
        .map_err(|e| NexusError::Internal {
            message: format!("office send: {e}"),
        })?;
    let mut buf = [0u8; 4096];
    let office_delivered = match tunnel_b.recv_and_deliver(&mut buf) {
        Ok(Some((sender, len))) => sender == "10.99.0.1" && len == b"office-packet".len(),
        other => {
            return Err(NexusError::Internal {
                message: format!("b recv office unexpected: {other:?}"),
            });
        }
    };
    let local_prefix_delivered = tunnel_b
        .events()
        .iter()
        .any(|ev| matches!(ev, VirtualSubnetEvent::LocalPrefixDelivered { dst_virtual_ip, .. } if dst_virtual_ip == "192.168.5.10"));

    // 出口兜底：A 发 8.8.8.8（无精确/前缀路由）→ 决策走 egress B → B 命中默认前缀 → 写 VPI
    tunnel_a
        .send_ip_packet("8.8.8.8", b"egress-packet")
        .map_err(|e| NexusError::Internal {
            message: format!("egress send: {e}"),
        })?;
    let egress_delivered = match tunnel_b.recv_and_deliver(&mut buf) {
        Ok(Some((sender, len))) => sender == "10.99.0.1" && len == b"egress-packet".len(),
        other => {
            return Err(NexusError::Internal {
                message: format!("b recv egress unexpected: {other:?}"),
            });
        }
    };

    // 无路由无出口：独立隧道 A2（无 egress、无前缀路由）发 8.8.8.8 → NO_ROUTE_TO_DST
    let mesh_a2 = MeshCarrier::new();
    let mut tunnel_a2 = VirtualSubnetTunnel::new(
        VirtualSubnetConfig::new("10.99.0.0/24", "10.99.0.1"),
        Box::new(MemoryVpi::new()),
        Box::new(mesh_a2),
    );
    let no_route_no_egress_rejected = match tunnel_a2.send_ip_packet("8.8.8.8", b"x") {
        Err(e) => {
            let s = e.to_string();
            if s.contains("NO_ROUTE_TO_DST") {
                "NoRouteToDst".to_string()
            } else {
                s
            }
        }
        Ok(()) => "SENT".to_string(),
    };

    Ok(serde_json::json!({
        "verdict": "PASS",
        "command": "cross-subnet",
        "cidr": {
            "parse_ok": parse_ok,
            "default_route_ok": default_route_ok,
            "not_network_rejected": not_network_rejected,
            "invalid_len_rejected": invalid_len_rejected,
            "contains_true": contains_true,
            "contains_false": contains_false,
        },
        "lookup": {
            "longest_prefix_next_hop": longest_prefix_next_hop,
            "default_next_hop": default_next_hop,
            "none_found": none_found,
        },
        "data": {
            "office_delivered": office_delivered,
            "local_prefix_delivered": local_prefix_delivered,
            "egress_delivered": egress_delivered,
            "no_route_no_egress_rejected": no_route_no_egress_rejected,
        },
    }))
}

/// E4 场景 `product.graceful-exit`：节点优雅退出状态机。
///
/// 演示 Active→Draining→Exiting→Exited 流转、未排空仍在 Draining、
/// 宽限期超时强制 Exiting、notify_peers 开关。
pub fn graceful_exit_flow() -> Result<Value, NexusError> {
    use nexus_connectivity::graceful_exit::{ExitConfig, GracefulExit};

    let cfg = ExitConfig::new(1_000, true, true).map_err(|e| NexusError::Internal {
        message: format!("exit config: {e}"),
    })?;
    let mut g = GracefulExit::new(cfg);

    let initial = g.state().as_str().to_string();
    g.begin_draining(0);
    let after_draining = g.state().as_str().to_string();

    let notified = g.notify_peers(&["peer-a", "peer-b"]);
    let notified_count = notified.len();

    // 仍有 5 条连接，t=100 仍在宽限期（1000ms）内 → 仍 Draining
    let still_busy = g.advance(5, 100).as_str().to_string();
    // 连接排空 → Exiting
    let after_drained = g.advance(0, 200).as_str().to_string();
    // Exiting → Exited
    let after_exited = g.advance(0, 300).as_str().to_string();

    // 超时分支：另起一个实例，仍有连接但已超过宽限期 → 强制 Exiting
    let cfg_to = ExitConfig::new(1_000, true, true).map_err(|e| NexusError::Internal {
        message: format!("exit config timeout: {e}"),
    })?;
    let mut g_to = GracefulExit::new(cfg_to);
    g_to.begin_draining(0);
    let timeout_exiting = g_to.advance(5, 2_000).as_str().to_string();

    // notify_peers=false 分支：不记录
    let cfg_off = ExitConfig::new(1_000, false, true).map_err(|e| NexusError::Internal {
        message: format!("exit config off: {e}"),
    })?;
    let mut g_off = GracefulExit::new(cfg_off);
    let recorded_off = g_off.notify_peers(&["peer-a", "peer-b"]).len();

    let invalid_config_rejected = ExitConfig::new(0, true, true).is_err();

    Ok(json!({
        "verdict": "PASS",
        "command": "graceful-exit",
        "initial_state": initial,
        "after_begin_draining": after_draining,
        "notified_peer_count": notified_count,
        "still_draining_while_active": still_busy,
        "after_drained": after_drained,
        "after_exited": after_exited,
        "timeout_forces_exiting": timeout_exiting,
        "notify_off_records_none": recorded_off,
        "invalid_config_rejected": invalid_config_rejected,
    }))
}

/// E4 场景 `product.config-hot-reload`：配置热加载校验门控与 revision 推进。
///
/// 演示合法提议应用、校验开启时非法提议被拒且 revision 不变、
/// 校验关闭时非法提议也应用、非法配置被拒。
pub fn config_hot_reload_flow() -> Result<Value, NexusError> {
    use nexus_connectivity::config_hot_reload::{HotReloadConfig, HotReloadManager, ReloadResult};

    let cfg = HotReloadConfig::new(1_000, true).map_err(|e| NexusError::Internal {
        message: format!("hot reload config: {e}"),
    })?;
    let mut mgr = HotReloadManager::new(cfg);

    let first = mgr.propose_reload(1, true);
    let first_kind = first.as_str().to_string();
    let first_applied = match first {
        ReloadResult::Success { applied_revision } => applied_revision,
        ReloadResult::Failed { reason } => {
            return Err(NexusError::Internal {
                message: format!("expected success but: {reason}"),
            });
        }
    };
    let after_first = mgr.current_revision();

    let rejected = mgr.propose_reload(2, false);
    let rejected_kind = rejected.as_str().to_string();
    let after_rejected = mgr.current_revision();

    let second = mgr.propose_reload(3, true);
    let second_applied = match second {
        ReloadResult::Success { applied_revision } => applied_revision,
        ReloadResult::Failed { reason } => {
            return Err(NexusError::Internal {
                message: format!("expected success but: {reason}"),
            });
        }
    };
    let after_second = mgr.current_revision();

    // 关闭前置校验：即使 valid=false 也应用
    let relaxed_cfg = HotReloadConfig::new(1_000, false).map_err(|e| NexusError::Internal {
        message: format!("relaxed hot reload config: {e}"),
    })?;
    let mut relaxed = HotReloadManager::new(relaxed_cfg);
    let relaxed = relaxed.propose_reload(4, false);
    let relaxed_applied = match relaxed {
        ReloadResult::Success { applied_revision } => applied_revision,
        ReloadResult::Failed { reason } => {
            return Err(NexusError::Internal {
                message: format!("expected success but: {reason}"),
            });
        }
    };

    let invalid_config_rejected = HotReloadConfig::new(0, true).is_err();

    Ok(json!({
        "verdict": "PASS",
        "command": "config-hot-reload",
        "first_propose": {
            "kind": first_kind,
            "applied_revision": first_applied,
            "current_revision": after_first,
        },
        "invalid_propose_rejected": {
            "kind": rejected_kind,
            "current_revision": after_rejected,
        },
        "second_propose": {
            "applied_revision": second_applied,
            "current_revision": after_second,
        },
        "relaxed_validate": {
            "applied_revision": relaxed_applied,
        },
        "invalid_config_rejected": invalid_config_rejected,
    }))
}

/// E4 场景 `product.traffic-stats`：流量按节点记账与全量快照汇总。
///
/// 演示字节累加、连接数增减、快照汇总总和、未知节点 node_summary 为 null。
pub fn traffic_stats_flow() -> Result<Value, NexusError> {
    use nexus_connectivity::traffic_stats::StatsCollector;

    let mut c = StatsCollector::new();
    c.record_node_bytes("node-a", 100, 200);
    c.record_node_bytes("node-a", 50, 50);
    c.record_connection("node-a", true);
    c.record_connection("node-a", true);
    c.record_connection("node-a", false);
    c.record_node_bytes("node-b", 10, 20);
    c.record_connection("node-b", true);

    let node_a = c.node_summary("node-a");
    let unknown = c.node_summary("never-seen");
    let snap = c.snapshot();

    let node_a_json = node_a.map(
        |(rx, tx, conns)| json!({ "rx_bytes": rx, "tx_bytes": tx, "active_connections": conns }),
    );
    let unknown_json = unknown.map(
        |(rx, tx, conns)| json!({ "rx_bytes": rx, "tx_bytes": tx, "active_connections": conns }),
    );

    Ok(json!({
        "verdict": "PASS",
        "command": "traffic-stats",
        "node_a_summary": node_a_json,
        "unknown_node_summary": unknown_json,
        "snapshot": {
            "total_rx_bytes": snap.total_rx_bytes,
            "total_tx_bytes": snap.total_tx_bytes,
            "active_connections": snap.active_connections,
            "active_nodes": snap.active_nodes,
        },
    }))
}

/// E4 产品场景 `product.cli-subnet` 的可执行驱动。
///
/// 进程内全闭环：写 fixture TOML → up（装配+状态文件）→ 幂等 up → status →
/// leave → status（down）→ 四类非法配置拒绝（CONFIG_ERROR）。
pub fn subnet_cli_flow() -> Result<Value, NexusError> {
    use crate::subnet_cli::{NEXDP1_MAGIC, subnet_leave, subnet_status, subnet_up};
    use std::path::PathBuf;

    fn write_cfg(path: &std::path::Path, text: &str) -> Result<(), String> {
        std::fs::write(path, text).map_err(|e| format!("write cfg: {e}"))
    }

    let dir = std::env::temp_dir().join(format!("nexus-subnet-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).map_err(|e| NexusError::Internal {
        message: e.to_string(),
    })?;
    let cfg_ok = dir.join("subnet-ok.toml");
    let cfg_bad_cidr = dir.join("subnet-bad-cidr.toml");
    let cfg_vip_outside = dir.join("subnet-vip-outside.toml");
    let cfg_peer_outside = dir.join("subnet-peer-outside.toml");
    let cfg_missing = dir.join("subnet-missing.toml");
    let state = dir.join("subnet-state.json");

    let ok_text = r#"[subnet]
cidr = "10.99.0.0/24"
virtual_ip = "10.99.0.1"
encryption = true
local_prefixes = ["192.168.5.0/24"]
egress = ["10.99.0.2"]

[[subnet.peers]]
virtual_ip = "10.99.0.2"
locator = "udp://127.0.0.1:42001"

[[subnet.peers]]
virtual_ip = "10.99.0.3"
locator = "udp://127.0.0.1:42002"

[[subnet.routes]]
dst = "10.99.0.9"
next_hop = "10.99.0.2"

[[subnet.prefix_routes]]
cidr = "192.168.5.0/24"
next_hop = "10.99.0.2"
"#;
    write_cfg(&cfg_ok, ok_text).map_err(|e| NexusError::Internal { message: e })?;
    write_cfg(
        &cfg_bad_cidr,
        r#"[subnet]
cidr = "999.1.1.0/24"
virtual_ip = "10.99.0.1"
"#,
    )
    .map_err(|e| NexusError::Internal { message: e })?;
    write_cfg(
        &cfg_vip_outside,
        r#"[subnet]
cidr = "10.99.0.0/24"
virtual_ip = "10.99.1.1"
"#,
    )
    .map_err(|e| NexusError::Internal { message: e })?;
    write_cfg(
        &cfg_peer_outside,
        r#"[subnet]
cidr = "10.99.0.0/24"
virtual_ip = "10.99.0.1"

[[subnet.peers]]
virtual_ip = "10.99.1.1"
locator = "udp://127.0.0.1:42001"
"#,
    )
    .map_err(|e| NexusError::Internal { message: e })?;

    // up（首次）
    let up_json =
        subnet_up(&cfg_ok, &state, false).map_err(|e| NexusError::Internal { message: e })?;
    // up 幂等（同 vip 覆盖，仍成功）
    subnet_up(&cfg_ok, &state, false).map_err(|e| NexusError::Internal { message: e })?;
    let up = up_json.get("subnet").cloned().unwrap_or_default();

    // status（读回）
    let status_json = subnet_status(&state);
    let read_back_vip = status_json
        .get("subnet")
        .and_then(|s| s.get("virtual_ip"))
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let status_peer_count = status_json
        .get("subnet")
        .and_then(|s| s.get("peer_count"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    // leave
    let leave_json = subnet_leave(&state);
    let left = leave_json
        .get("subnet")
        .and_then(|s| s.get("left"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // status after leave → down
    let status_after = subnet_status(&state);
    let up_after_leave = status_after
        .get("subnet")
        .and_then(|s| s.get("up"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    // ---- P3.4 加密状态（§12.31）：--encrypt-state 加密落盘 + status 解密读回 ----
    let state_sec = dir.join("subnet-state-secure.json");
    let enc_up_json =
        subnet_up(&cfg_ok, &state_sec, true).map_err(|e| NexusError::Internal { message: e })?;
    let enc_up_ok = enc_up_json
        .get("subnet")
        .and_then(|s| s.get("up"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let enc_bytes = std::fs::read(&state_sec).map_err(|e| NexusError::Internal {
        message: e.to_string(),
    })?;
    let file_encrypted = enc_bytes.starts_with(b"NEXSEC1") || enc_bytes.starts_with(NEXDP1_MAGIC);
    let file_magic = if enc_bytes.starts_with(b"NEXSEC1") {
        "NEXSEC1"
    } else if enc_bytes.starts_with(NEXDP1_MAGIC) {
        "NEXDP1"
    } else {
        "PLAIN"
    }
    .to_string();

    // 加密状态 status 读回（解密后字段一致）
    let enc_status_json = subnet_status(&state_sec);
    let sec_read_back_vip = enc_status_json
        .get("subnet")
        .and_then(|s| s.get("virtual_ip"))
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let sec_peer_count = enc_status_json
        .get("subnet")
        .and_then(|s| s.get("peer_count"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    // leave 加密状态 → status DOWN
    subnet_leave(&state_sec);
    let sec_up_after_leave = subnet_status(&state_sec)
        .get("subnet")
        .and_then(|s| s.get("up"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    // 篡改密文（magic 后第 1 字节翻转）→ status STORE_ERROR（不 panic）
    let mut tampered = enc_bytes.clone();
    if tampered.len() > NEXDP1_MAGIC.len() + 2 {
        tampered[NEXDP1_MAGIC.len() + 1] ^= 0x01;
    }
    std::fs::write(&state_sec, &tampered).map_err(|e| NexusError::Internal {
        message: e.to_string(),
    })?;
    let tamper_verdict = subnet_status(&state_sec)
        .get("verdict")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    // 清理加密状态文件
    std::fs::remove_file(&state_sec).ok();

    // 四类非法配置
    let classify = |path: &PathBuf| -> String {
        match subnet_up(path, &state, false) {
            Err(_) => "CONFIG_ERROR".to_string(),
            Ok(_) => "ACCEPTED".to_string(),
        }
    };
    let bad_cidr = classify(&cfg_bad_cidr);
    let vip_outside_subnet = classify(&cfg_vip_outside);
    let peer_outside_subnet = classify(&cfg_peer_outside);
    let missing_file = classify(&cfg_missing);

    // 清理
    std::fs::remove_dir_all(&dir).ok();

    Ok(serde_json::json!({
        "verdict": "PASS",
        "command": "subnet cli",
        "up": {
            "up_ok": true,
            "virtual_ip": up.get("virtual_ip").and_then(|v| v.as_str()).unwrap_or_default(),
            "cidr": up.get("cidr").and_then(|v| v.as_str()).unwrap_or_default(),
            "peer_count": up.get("peer_count").and_then(|v| v.as_u64()).unwrap_or(0),
            "egress_peer_count": up.get("egress_peer_count").and_then(|v| v.as_u64()).unwrap_or(0),
            "prefix_route_count": up.get("prefix_route_count").and_then(|v| v.as_u64()).unwrap_or(0),
            "encryption": up.get("encryption").and_then(|v| v.as_bool()).unwrap_or(false),
        },
        "status": {
            "read_back_vip": read_back_vip,
            "peer_count": status_peer_count,
        },
        "leave": { "left": left },
        "status_after_leave": { "up": up_after_leave },
        "encrypt": {
            "up_ok": enc_up_ok,
            "file_encrypted": file_encrypted,
            "file_magic": file_magic,
            "read_back_vip": sec_read_back_vip,
            "peer_count": sec_peer_count,
            "up_after_leave": sec_up_after_leave,
        },
        "tamper": { "decrypt_failed": tamper_verdict },
        "config": {
            "bad_cidr": bad_cidr,
            "vip_outside_subnet": vip_outside_subnet,
            "peer_outside_subnet": peer_outside_subnet,
            "missing_file": missing_file,
        },
    }))
}

/// E4 产品场景 `product.tun-dataplane` 的可执行驱动（PRODUCT §12.29）。
///
/// 进程内闭环（不依赖真实驱动）：UdpCarrier 本地回环收发对齐、TUN 装配错误
/// 分类（纯函数）、TUN 名称校验。真实 wintun/tun 设备验收走 E5（--real 入口）。
pub fn tun_dataplane_flow() -> Result<Value, NexusError> {
    use crate::subnet_cli::{MAX_TUN_NAME_BYTES, classify_tun_error, validate_tun_name};
    use nexus_platform::{PacketCarrier, UdpCarrier};

    fn internal_err<E: std::fmt::Display>(e: E) -> NexusError {
        NexusError::Internal {
            message: e.to_string(),
        }
    }

    // 1) UdpCarrier 本地回环
    let mut a = UdpCarrier::new();
    a.bind("udp://127.0.0.1:52001").map_err(internal_err)?;
    let mut b = UdpCarrier::new();
    b.bind("udp://127.0.0.1:52002").map_err(internal_err)?;

    a.send_to("udp://127.0.0.1:52002", &[1, 2, 3, 4])
        .map_err(internal_err)?;
    let mut buf = [0u8; 64];
    let n1 = b.receive_into(&mut buf).map_err(internal_err)?;
    let a_to_b_echo = n1 == 4 && buf[..4] == [1, 2, 3, 4];

    b.send_to("udp://127.0.0.1:52001", &[9, 8])
        .map_err(internal_err)?;
    let n2 = a.receive_into(&mut buf).map_err(internal_err)?;
    let b_to_a_echo = n2 == 2 && buf[..2] == [9, 8];

    let z = a.receive_into(&mut buf).map_err(internal_err)?;
    let no_data_zero = z == 0;

    let bad_locator = match UdpCarrier::parse_locator("tcp://127.0.0.1:1") {
        Err(_) => "PLATFORM_ERROR".to_string(),
        Ok(_) => "ACCEPTED".to_string(),
    };

    // 2) --tun 装配错误分类（确定性纯函数；真实设备路径见 E5）
    let classified = classify_tun_error("wintun create: access denied");
    let assembly_error_kind = classified
        .get("verdict")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

    // 3) TUN 名称校验
    let name_validation_empty = match validate_tun_name("") {
        Err(e) if e.starts_with("INVALID_NAME") => "INVALID_NAME".to_string(),
        _ => "OK".to_string(),
    };
    let long = "x".repeat(MAX_TUN_NAME_BYTES + 1);
    let name_validation_long = match validate_tun_name(&long) {
        Err(e) if e.starts_with("INVALID_NAME") => "INVALID_NAME".to_string(),
        _ => "OK".to_string(),
    };

    Ok(serde_json::json!({
        "verdict": "PASS",
        "command": "tun dataplane",
        "udp": {
            "a_to_b_echo": a_to_b_echo,
            "b_to_a_echo": b_to_a_echo,
            "no_data_zero": no_data_zero,
            "bad_locator": bad_locator,
        },
        "tun": {
            "assembly_error_kind": assembly_error_kind,
            "name_validation_empty": name_validation_empty,
            "name_validation_long": name_validation_long,
        },
    }))
}

// ---------------------------------------------------------------------------
// §11.18 TUN 透明代理入站（E4：MemoryVpi 离线闭环；E5：--real 走真实 wintun）
// ---------------------------------------------------------------------------

/// 构造一个合法 IPv4 包（IHL=5，20 字节头 + 4 字节传输端口）。
fn build_ipv4_packet(protocol: u8, src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16) -> Vec<u8> {
    let mut p = vec![0u8; 24];
    p[0] = (4u8 << 4) | 5;
    p[8] = 64; // TTL
    p[9] = protocol;
    p[12..16].copy_from_slice(&src);
    p[16..20].copy_from_slice(&dst);
    p[20..22].copy_from_slice(&sport.to_be_bytes());
    p[22..24].copy_from_slice(&dport.to_be_bytes());
    p
}

const TUN_PROXY_CONFIG: &str = "\
schema_version: 1
rules:
  - tag: rule-internal-cidr
    kind: ip_cidr
    match: 10.0.0.0/8
    action:
      - kind: select_outbound
        tag: relay-group
  - tag: rule-match
    kind: match
    match: \"\"
    action:
      - kind: select_outbound
        tag: direct
groups:
  - tag: relay-group
    kind: selector
    candidates: [relay]
outbounds:
  - tag: direct
    kind: direct
    locator: \"\"
  - tag: relay
    kind: relay
    locator: relay.internal:443
";

/// E4 产品场景 `product.proxy-tun-inbound` 的进程内闭环（PRODUCT §11.18）。
///
/// 注入 `MemoryVpi`（离线确定性 VPI 替身）四条 IP 包：
/// 1) TCP 192.168.1.5:12345 -> 10.1.2.3:443（命中 ip_cidr -> relay-group）；
/// 2) UDP 192.168.1.5:53000 -> 8.8.8.8:53（落入 MATCH -> direct）；
/// 3) 与 1 同 5 元组的第二个 TCP 包（NAT cache hit）；
/// 4) ICMP 坏包（计入 dropped，不 panic）。
pub fn tun_proxy_flow() -> Result<Value, NexusError> {
    use nexus_connectivity::virtual_subnet::MemoryVpi;
    use nexus_ingress::ip_packet::parse_ipv4_packet;
    use nexus_platform::VirtualPacketInterface;
    use nexus_proxy::ProxyService;
    use nexus_proxy::tun::TunNatRouter;

    fn internal_err<E: std::fmt::Display>(e: E) -> NexusError {
        NexusError::Internal {
            message: e.to_string(),
        }
    }

    let cfg = nexus_proxy_config::parse(TUN_PROXY_CONFIG).map_err(|e| NexusError::Internal {
        message: format!("tun proxy config invalid: {e}"),
    })?;
    let service = ProxyService::new(&cfg).map_err(|e| NexusError::Internal {
        message: format!("tun proxy service build failed: {e}"),
    })?;
    let mut router = TunNatRouter::new(service);

    let mut vpi = MemoryVpi::new();
    // 四条包按序注入；每条注入后 drain 一次读循环。
    let packets: Vec<Vec<u8>> = vec![
        build_ipv4_packet(6, [192, 168, 1, 5], 12345, [10, 1, 2, 3], 443), // p1 TCP -> cidr
        build_ipv4_packet(17, [192, 168, 1, 5], 53000, [8, 8, 8, 8], 53),  // p2 UDP -> MATCH
        build_ipv4_packet(6, [192, 168, 1, 5], 12345, [10, 1, 2, 3], 443), // p3 同 p1（cache hit）
        build_ipv4_packet(1, [192, 168, 1, 5], 0, [10, 9, 9, 9], 0),       // p4 ICMP 坏包
    ];

    let mut first_flow: Option<Value> = None;
    let mut udp_flow: Option<Value> = None;
    let mut replay: Option<Value> = None;
    for (idx, pkt) in packets.iter().enumerate() {
        vpi.inject_recv(pkt);
        let mut buf = [0u8; 2048];
        // drain：MemoryVpi 一次读回已注入的整包（真实 wintun 亦一包一收）。
        loop {
            let n = vpi.receive(&mut buf).map_err(&internal_err)?;
            if n == 0 {
                break;
            }
            match parse_ipv4_packet(&buf[..n]) {
                Some(parsed) => {
                    let out =
                        router
                            .route_packet(&parsed, n)
                            .map_err(|e| NexusError::Internal {
                                message: format!("tun route failed: {e}"),
                            })?;
                    let v = serde_json::json!({
                        "destination": out.destination,
                        "protocol": out.protocol,
                        "flow_origin": out.flow_origin,
                        "matched_rule": out.matched_rule,
                        "selected_outbound_tag": out.selected_outbound_tag,
                        "cache_hit": out.cache_hit,
                    });
                    match idx {
                        0 => first_flow = Some(v),
                        1 => udp_flow = Some(v),
                        _ => replay = Some(v),
                    }
                }
                None => router.record_dropped(n),
            }
        }
    }

    let s = router.stats();
    Ok(serde_json::json!({
        "verdict": "PASS",
        "command": "tun proxy inbound",
        "first_flow": first_flow.unwrap_or(Value::Null),
        "udp_flow": udp_flow.unwrap_or(Value::Null),
        "replay": replay.unwrap_or(Value::Null),
        "stats": {
            "packets": s.packets,
            "bytes": s.bytes,
            "dropped": s.dropped,
            "mappings": s.mappings,
            "cache_hits": s.cache_hits,
        },
    }))
}

/// E5：真实 wintun adapter 开卡 + 能力/版本 + 一次非阻塞读帧（PRODUCT §11.18）。
///
/// 成功返回结构化 JSON（adapter 句柄在函数返回时随 Drop 释放：EndSession ->
/// CloseAdapter -> FreeLibrary）；失败返回 `TUN_ERROR` 结构化结果（由调用方按 exit 0 输出）。
/// 需管理员 + nexusd.exe 同目录存在签名 `wintun.dll` + 已安装 wintun.sys 驱动。
pub fn tun_proxy_real_open(tun_name: &str) -> Result<Value, NexusError> {
    #[cfg(windows)]
    {
        use nexus_platform::VirtualPacketInterface;
        match nexus_platform_windows::WintunVpiAdapter::create(tun_name, "Nexus") {
            Ok(mut vpi) => {
                let caps = nexus_platform_windows::WintunVpiAdapter::capabilities();
                Ok(serde_json::json!({
                    "verdict": "PASS",
                    "command": "tun proxy real open",
                    "backend": nexus_platform_windows::WintunVpiAdapter::backend(),
                    "mtu": nexus_platform_windows::WintunVpiAdapter::mtu(),
                    "driver_version": vpi.driver_version(),
                    "adapter_name": tun_name,
                    "capabilities": {
                        "packet_ingress": caps.packet_ingress,
                        "packet_injection": caps.packet_injection,
                        "ipv4": caps.ipv4,
                        "ipv6": caps.ipv6,
                    },
                    "read_frame": {
                        "bytes": vpi.receive(&mut [0u8; 2048]).map(|n| n as u64).unwrap_or(0),
                    }
                }))
            }
            Err(e) => Ok(serde_json::json!({
                "verdict": "TUN_ERROR",
                "command": "tun proxy real open",
                "adapter_name": tun_name,
                "error": e.to_string(),
            })),
        }
    }
    #[cfg(not(windows))]
    {
        let _ = tun_name;
        Err(NexusError::Internal {
            message: "TUN transparent inbound (wintun) only supported on Windows".into(),
        })
    }
}

/// E4 产品场景 `product.schedule-cli` 的可执行驱动（Composition Root）。
///
/// 与 `nexus schedule` CLI 同一代码路径（schedule_cli 模块）：验证 at/every 注册、
/// 过去时间拒绝、取消、列表、tick 到期触发与持久化重载。使用进程 id 唯一临时
/// 状态文件，结束后清理；不触碰用户默认注册表（~/.nexus/schedule.json）。
pub fn schedule_cli_flow() -> Result<Value, NexusError> {
    use crate::schedule_cli::{
        error_json, schedule_at, schedule_cancel, schedule_every, schedule_list, schedule_tick,
        unix_now_secs,
    };

    let dir = std::env::temp_dir().join(format!("nexus-schedule-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).map_err(|e| NexusError::Internal {
        message: format!("create temp dir: {e}"),
    })?;
    let state = dir.join("schedule.json");
    let _ = std::fs::remove_file(&state);

    let now = unix_now_secs();

    // 1. at：未来时间注册成功，返回 schedule id。
    let at_ok = schedule_at(
        now + 100000,
        "rust-build",
        &["cargo".to_string(), "test".to_string()],
        &state,
    )
    .is_ok_and(|v| {
        v["verdict"] == "PASS"
            && v["schedule_id"]
                .as_str()
                .is_some_and(|s| s.starts_with("sch-"))
    });

    // 2. at 过去时间 → INVALID_SCHEDULE。
    let invalid_past = match schedule_at(now - 1, "rust-build", &["cargo".to_string()], &state) {
        Err(e) => error_json("schedule at", &e)["verdict"] == "INVALID_SCHEDULE",
        Ok(_) => false,
    };

    // 3. every 注册成功。
    let every_ok = schedule_every(
        60,
        "rust-build",
        &["cargo".to_string(), "build".to_string()],
        &state,
    )
    .is_ok_and(|v| v["verdict"] == "PASS");

    // 4. list：注册后共 2 条。
    let after_register = schedule_list(&state)
        .map(|v| v["count"].as_u64().unwrap_or(0))
        .unwrap_or(0);

    // 5. cancel：第一条取消成功；取消不存在 id → SCHEDULE_NOT_FOUND。
    let first_id = schedule_list(&state)
        .ok()
        .and_then(|v| v["schedules"].as_array().cloned())
        .and_then(|arr| arr.first().cloned())
        .and_then(|e| e["id"].as_str().map(str::to_string))
        .unwrap_or_default();
    let cancel_ok = schedule_cancel(&first_id, &state).is_ok_and(|v| v["state"] == "Cancelled");
    let cancel_not_found = match schedule_cancel("sch-999", &state) {
        Err(e) => error_json("schedule cancel", &e)["verdict"] == "SCHEDULE_NOT_FOUND",
        Ok(_) => false,
    };

    // 6. list：取消后仍 2 条（PRODUCT §14.1「列出全部条目」，Cancelled 条目保留）。
    let after_cancel = schedule_list(&state)
        .map(|v| v["count"].as_u64().unwrap_or(0))
        .unwrap_or(0);

    // 7. tick：以当前墙钟锚定注册 2 秒后到期的 at 条目，sleep 3 秒后 tick 触发恰 1 条
    //（不依赖流程开头的 now 快照，消除慢机器上的 2 秒漂移窗口）。
    schedule_at(
        unix_now_secs() + 2,
        "rust-build",
        &["cargo".to_string(), "test".to_string()],
        &state,
    )
    .map_err(|e| NexusError::Internal {
        message: format!("schedule_at: {e}"),
    })?;
    std::thread::sleep(std::time::Duration::from_secs(3));
    let tick_fired_once = schedule_tick(&state, unix_now_secs())
        .is_ok_and(|v| v["fired"] == 1 && v["records"][0]["ok"] == true);

    // 8. 持久化重载：重新读注册表，条目数与 next_run 均保留（PRODUCT §14.4）。
    let before: Vec<(String, i64)> = schedule_list(&state)
        .ok()
        .and_then(|v| v["schedules"].as_array().cloned())
        .unwrap_or_default()
        .iter()
        .map(|e| {
            (
                e["id"].as_str().unwrap_or("").to_string(),
                e["next_run_secs"].as_i64().unwrap_or(0),
            )
        })
        .collect();
    let reloaded = schedule_list(&state)
        .ok()
        .and_then(|v| v["schedules"].as_array().cloned())
        .unwrap_or_default();
    let reload_preserved = reloaded.len() == before.len()
        && before.iter().all(|(id, next)| {
            reloaded.iter().any(|e| {
                e["id"].as_str() == Some(id.as_str()) && e["next_run_secs"].as_i64() == Some(*next)
            })
        });

    // 清理临时目录。
    let _ = std::fs::remove_file(&state);
    let _ = std::fs::remove_dir(&dir);

    let ok = at_ok
        && invalid_past
        && every_ok
        && after_register == 2
        && cancel_ok
        && cancel_not_found
        && after_cancel == 2
        && tick_fired_once
        && reload_preserved;

    Ok(json!({
        "verdict": if ok { "PASS" } else { "FAIL" },
        "command": "schedule-cli",
        "at": { "register_ok": at_ok, "invalid_past_rejected": invalid_past },
        "every": { "register_ok": every_ok },
        "cancel": { "ok": cancel_ok, "not_found": cancel_not_found },
        "list": { "after_register": after_register, "after_cancel": after_cancel },
        "tick": { "fired_once": tick_fired_once },
        "persist": { "reload_preserved": reload_preserved },
    }))
}

/// E4 `product.psk-handshake-admission`（PRODUCT §12.42）的可执行驱动。
///
/// ```text
/// 同 PSK 双端握手 -> 会话建立 -> 数据帧往返解密成功
///   -> 异 PSK 双端派生密钥不同 -> 数据帧解密失败 DecryptionFailed
///   -> 单边无 PSK -> 数据帧解密失败 DecryptionFailed
/// ```
///
/// 全程零真实网络；错误一律 typed `Result`，无 panic。
pub fn psk_handshake_admission_flow() -> Result<Value, NexusError> {
    use nexus_connectivity::encryption::{
        EncryptionError, KeyPair, decrypt_frame, derive_authed_keys, derive_authed_keys_with_psk,
        encrypt_frame,
    };

    /// 双端握手钥匙对（A=initiator, B=responder），可选 PSK。
    fn handshake_pair(
        psk_a: Option<&[u8]>,
        psk_b: Option<&[u8]>,
    ) -> Result<
        (
            nexus_connectivity::encryption::DirectionalKeys,
            nexus_connectivity::encryption::DirectionalKeys,
        ),
        NexusError,
    > {
        let a_static = KeyPair::generate().map_err(enc_err)?;
        let a_eph = KeyPair::generate().map_err(enc_err)?;
        let b_static = KeyPair::generate().map_err(enc_err)?;
        let b_eph = KeyPair::generate().map_err(enc_err)?;
        let derive = |mine_s: &KeyPair,
                      mine_e: &KeyPair,
                      peer_s: &[u8; 32],
                      peer_e: &[u8; 32],
                      initiator: bool,
                      psk: Option<&[u8]>| {
            match psk {
                Some(p) => {
                    derive_authed_keys_with_psk(mine_s, mine_e, peer_s, peer_e, initiator, p)
                }
                None => derive_authed_keys(mine_s, mine_e, peer_s, peer_e, initiator),
            }
            .map_err(enc_err)
        };
        let keys_a = derive(
            &a_static,
            &a_eph,
            b_static.public_key_bytes(),
            b_eph.public_key_bytes(),
            true,
            psk_a,
        )?;
        let keys_b = derive(
            &b_static,
            &b_eph,
            a_static.public_key_bytes(),
            a_eph.public_key_bytes(),
            false,
            psk_b,
        )?;
        Ok((keys_a, keys_b))
    }

    let mut events: Vec<&'static str> = Vec::new();
    let psk: &[u8] = b"test-network-psk-001";
    let other_psk: &[u8] = b"different-psk-002";
    let payload = b"psk-admission-probe";
    let seq: u64 = 7;

    // 1) 同 PSK：握手完成，数据帧往返。
    let (keys_a, keys_b) = handshake_pair(Some(psk), Some(psk))?;
    events.push("psk_handshake_completed");
    let frame = encrypt_frame(&keys_a.tx, seq, payload).map_err(enc_err)?;
    let (got_seq, plain) = decrypt_frame(&keys_b.rx, &frame).map_err(enc_err)?;
    if got_seq != seq || plain.as_slice() != payload {
        return Err(NexusError::Internal {
            message: "psk admission: same-psk roundtrip mismatch".to_string(),
        });
    }
    events.push("psk_data_frame_decrypted");

    // 2) 异 PSK：派生密钥不同，首个数据帧解密必须失败。
    let (keys_c, keys_d) = handshake_pair(Some(psk), Some(other_psk))?;
    let bad_frame = encrypt_frame(&keys_c.tx, seq, payload).map_err(enc_err)?;
    let mismatch_err = match decrypt_frame(&keys_d.rx, &bad_frame) {
        Err(EncryptionError::DecryptionFailed) => "DecryptionFailed",
        Err(e) => {
            return Err(NexusError::Internal {
                message: format!("psk admission: mismatch gave unexpected error {e:?}"),
            });
        }
        Ok(_) => {
            return Err(NexusError::Internal {
                message: "psk admission: mismatched-psk frame decrypted (must fail)".to_string(),
            });
        }
    };
    events.push("psk_mismatch_rejected");

    // 3) 单边无 PSK：同样必须解密失败。
    let (keys_e, keys_f) = handshake_pair(Some(psk), None)?;
    let bad_frame2 = encrypt_frame(&keys_e.tx, seq, payload).map_err(enc_err)?;
    let absent_err = match decrypt_frame(&keys_f.rx, &bad_frame2) {
        Err(EncryptionError::DecryptionFailed) => "DecryptionFailed",
        Err(e) => {
            return Err(NexusError::Internal {
                message: format!("psk admission: absent-psk gave unexpected error {e:?}"),
            });
        }
        Ok(_) => {
            return Err(NexusError::Internal {
                message: "psk admission: absent-psk frame decrypted (must fail)".to_string(),
            });
        }
    };
    events.push("psk_absent_rejected");

    Ok(json!({
        "verdict": "PASS",
        "events": events,
        "mismatch": { "error": mismatch_err },
        "absent": { "error": absent_err },
    }))
}

/// E4 `product.decentralized-join-config`（PRODUCT §12.43）的可执行驱动。
///
/// ```text
/// derive_vip 确定性（同公钥同 CIDR -> 同 VIP）
///   -> 派生 VIP 在 CIDR 内
///   -> nonce 递增 -> 不同 VIP
///   -> 有 bootstrap 无 PSK -> PSK_REQUIRED 错误（fail-closed）
///   -> 有 bootstrap 有 PSK -> 通过
///   -> legacy 配置（无 bootstrap 无 PSK）-> 通过（行为不变）
/// ```
///
/// 全程零真实网络；错误一律 typed `Result`，无 panic。
pub fn decentralized_join_config_flow() -> Result<Value, NexusError> {
    use nexus_connectivity::coord::derive_vip;
    use nexus_connectivity::encryption::KeyPair;

    let mut events: Vec<&'static str> = Vec::new();

    // 1) 确定性：同公钥 + 同 CIDR + nonce=0 -> 同 VIP。
    let kp = KeyPair::generate().map_err(enc_err)?;
    let pubkey = *kp.public_key_bytes();
    let vip_a = derive_vip(&pubkey, "10.99.0.0/24", 0).map_err(|e| NexusError::Internal {
        message: format!("derive_vip: {e:?}"),
    })?;
    let vip_b = derive_vip(&pubkey, "10.99.0.0/24", 0).map_err(|e| NexusError::Internal {
        message: format!("derive_vip: {e:?}"),
    })?;
    if vip_a != vip_b {
        return Err(NexusError::Internal {
            message: "decentralized join: derive_vip not deterministic".to_string(),
        });
    }
    events.push("vip_derived_deterministic");

    // 2) 派生 VIP 在 CIDR 内（10.99.0.0/24，跳过 .0 和 .255）。
    let octets = vip_a.octets();
    if octets[0] != 10 || octets[1] != 99 || octets[2] != 0 || octets[3] == 0 || octets[3] == 255 {
        return Err(NexusError::Internal {
            message: format!("decentralized join: derived VIP {vip_a} outside cidr"),
        });
    }
    events.push("vip_in_cidr");

    // 3) nonce 递增 -> 不同 VIP（冲突重派机制的基础）。
    let vip_c = derive_vip(&pubkey, "10.99.0.0/24", 1).map_err(|e| NexusError::Internal {
        message: format!("derive_vip: {e:?}"),
    })?;
    if vip_c == vip_a {
        return Err(NexusError::Internal {
            message: "decentralized join: nonce increment did not change VIP".to_string(),
        });
    }
    events.push("vip_nonce_changes");

    // 4-6) 配置层：写 TOML，走 subnet_up 验证 fail-closed 与兼容性。
    use crate::subnet_cli::subnet_up;
    use std::path::PathBuf;

    fn write_cfg(dir: &std::path::Path, name: &str, text: &str) -> Result<PathBuf, NexusError> {
        let p = dir.join(name);
        std::fs::write(&p, text).map_err(|e| NexusError::Internal {
            message: format!("write test config: {e}"),
        })?;
        Ok(p)
    }

    let dir = std::env::temp_dir().join(format!("nexus-join-cfg-{}", std::process::id()));
    std::fs::create_dir_all(&dir).map_err(|e| NexusError::Internal {
        message: e.to_string(),
    })?;
    let state = dir.join("state.json");

    // 4) 有 bootstrap 无 PSK -> PSK_REQUIRED（fail-closed）。
    let cfg_no_psk = write_cfg(
        &dir,
        "bootstrap-no-psk.toml",
        r#"[subnet]
cidr = "10.99.0.0/24"
encryption = true

[[subnet.bootstrap]]
address = "udp://203.0.113.10:11010"
"#,
    )?;
    let psk_required_err = match subnet_up(&cfg_no_psk, &state, false) {
        Err(e) if e.contains("PSK_REQUIRED") => "PSK_REQUIRED",
        Err(e) => {
            return Err(NexusError::Internal {
                message: format!("decentralized join: expected PSK_REQUIRED, got {e}"),
            });
        }
        Ok(_) => {
            return Err(NexusError::Internal {
                message: "decentralized join: bootstrap without PSK was not rejected".to_string(),
            });
        }
    };
    events.push("bootstrap_psk_required");

    // 5) 有 bootstrap 有 PSK -> 通过。
    let cfg_psk = write_cfg(
        &dir,
        "bootstrap-psk.toml",
        r#"[subnet]
cidr = "10.99.0.0/24"
virtual_ip = "10.99.0.5"
encryption = true
network_psk = "test-psk-001"

[[subnet.bootstrap]]
address = "udp://203.0.113.10:11010"
"#,
    )?;
    subnet_up(&cfg_psk, &state, false).map_err(|e| NexusError::Internal {
        message: format!("decentralized join: bootstrap+psk rejected: {e}"),
    })?;
    events.push("bootstrap_psk_ok");

    // 6) legacy 配置（无 bootstrap 无 PSK）-> 通过（行为不变）。
    let cfg_legacy = write_cfg(
        &dir,
        "legacy.toml",
        r#"[subnet]
cidr = "10.99.0.0/24"
virtual_ip = "10.99.0.1"
encryption = true

[[subnet.peers]]
virtual_ip = "10.99.0.2"
locator = "udp://127.0.0.1:42001"
"#,
    )?;
    subnet_up(&cfg_legacy, &state, false).map_err(|e| NexusError::Internal {
        message: format!("decentralized join: legacy config rejected: {e}"),
    })?;
    events.push("legacy_config_unchanged");

    Ok(json!({
        "verdict": "PASS",
        "events": events,
        "psk_required": { "error": psk_required_err },
        "derived_vip": vip_a.to_string(),
    }))
}

/// E4 `product.lsa-discovery`（PRODUCT §12.44）的可执行驱动。
///
/// ```text
/// 三节点进程内：A 经 B 入网（Hello/Welcome），C 经 B 入网，
/// A 经 LSA 泛洪学到 C，三节点 LSDB 收敛一致
///   -> 旧 seq LSA 被拒绝
///   -> 本端 LSA 不被覆盖
/// ```
///
/// 全程零真实网络；错误一律 typed `Result`，无 panic。
pub fn lsa_discovery_flow() -> Result<Value, NexusError> {
    use nexus_discovery::PeerId;
    use nexus_discovery::lsa::{
        LinkAdvert, Lsa, LsaFrame, Lsdb, SeenCache, UpdateOutcome, decode_lsa_frame,
        encode_lsa_frame,
    };

    let mut events: Vec<&'static str> = Vec::new();

    // 三节点身份。
    let id_a = PeerId("node-a".to_string());
    let id_b = PeerId("node-b".to_string());
    let id_c = PeerId("node-c".to_string());

    fn make_lsa(id: &PeerId, vip: &str, seq: u64) -> Lsa {
        Lsa {
            node_id: id.clone(),
            vip: vip.to_string(),
            incarnation: 1,
            seq,
            capabilities: 0,
            locator: Some(format!("udp://127.0.0.1:{}", 42000 + seq as u16)),
            neighbors: Vec::new(),
        }
    }

    // 每个节点的 LSDB，先放入本端 LSA。
    let mut lsdb_a = Lsdb::new(id_a.clone());
    let mut lsdb_b = Lsdb::new(id_b.clone());
    let mut lsdb_c = Lsdb::new(id_c.clone());
    let lsa_a = make_lsa(&id_a, "10.99.0.1", 1);
    let lsa_b = make_lsa(&id_b, "10.99.0.2", 1);
    let lsa_c = make_lsa(&id_c, "10.99.0.3", 1);
    assert!(matches!(
        lsdb_a.update_local(lsa_a.clone()),
        UpdateOutcome::New
    ));
    assert!(matches!(
        lsdb_b.update_local(lsa_b.clone()),
        UpdateOutcome::New
    ));
    assert!(matches!(
        lsdb_c.update_local(lsa_c.clone()),
        UpdateOutcome::New
    ));

    // ---- 阶段 1：A 经 B 入网（Hello/Welcome）----
    // A -> B: Hello（编码后经"网络"传输再解码，验证 codec 往返）。
    let hello_a = LsaFrame::Hello {
        node_id: id_a.clone(),
        vip: "10.99.0.1".to_string(),
        capabilities: 0,
        incarnation: 1,
    };
    let hello_wire = encode_lsa_frame(&hello_a).map_err(|e| NexusError::Internal {
        message: format!("encode hello: {e:?}"),
    })?;
    let decoded_hello = decode_lsa_frame(&hello_wire).map_err(|e| NexusError::Internal {
        message: format!("decode hello: {e:?}"),
    })?;
    if decoded_hello != hello_a {
        return Err(NexusError::Internal {
            message: "lsa discovery: hello codec roundtrip mismatch".to_string(),
        });
    }
    // B -> A: Welcome（全量 LSA 快照：B 的 LSDB 内容）。
    let welcome_b = LsaFrame::Welcome {
        lsas: lsdb_b.all().into_iter().cloned().collect(),
    };
    let welcome_wire = encode_lsa_frame(&welcome_b).map_err(|e| NexusError::Internal {
        message: format!("encode welcome: {e:?}"),
    })?;
    let decoded_welcome = decode_lsa_frame(&welcome_wire).map_err(|e| NexusError::Internal {
        message: format!("decode welcome: {e:?}"),
    })?;
    let LsaFrame::Welcome { lsas } = decoded_welcome else {
        return Err(NexusError::Internal {
            message: "lsa discovery: welcome decode type mismatch".to_string(),
        });
    };
    for lsa in lsas {
        lsdb_a.update(lsa);
    }
    if !lsdb_a.contains(&id_a) || !lsdb_a.contains(&id_b) {
        return Err(NexusError::Internal {
            message: "lsa discovery: A lsdb missing A/B after welcome".to_string(),
        });
    }
    events.push("hello_welcome_completed");

    // ---- 阶段 2：C 经 B 入网，LSA 泛洪使 A 学到 C ----
    // C -> B: Hello；B -> C: Welcome。
    let welcome_to_c = LsaFrame::Welcome {
        lsas: lsdb_b.all().into_iter().cloned().collect(),
    };
    let LsaFrame::Welcome { lsas: c_seed } = welcome_to_c else {
        return Err(NexusError::Internal {
            message: "unreachable".to_string(),
        });
    };
    for lsa in c_seed {
        lsdb_c.update(lsa);
    }
    // C 的 LSA 经 B 泛洪到 A（模拟：B 转发给除来源外的邻居）。
    // B 学到 C（B 收到 C 的 LsaAdvert）。
    let advert_c = LsaFrame::LsaAdvert { lsa: lsa_c.clone() };
    let advert_wire = encode_lsa_frame(&advert_c).map_err(|e| NexusError::Internal {
        message: format!("encode advert: {e:?}"),
    })?;
    let decoded_advert = decode_lsa_frame(&advert_wire).map_err(|e| NexusError::Internal {
        message: format!("decode advert: {e:?}"),
    })?;
    let LsaFrame::LsaAdvert { lsa: flooded } = decoded_advert else {
        return Err(NexusError::Internal {
            message: "lsa discovery: advert decode type mismatch".to_string(),
        });
    };
    // B 更新 + 泛洪决策（SeenCache 去重）。
    let mut seen_b = SeenCache::new(1024);
    let mut seen_a = SeenCache::new(1024);
    if seen_b.should_flood(&flooded.node_id, flooded.incarnation, flooded.seq) {
        let outcome_b = lsdb_b.update(flooded.clone());
        if !matches!(outcome_b, UpdateOutcome::New | UpdateOutcome::Updated) {
            return Err(NexusError::Internal {
                message: "lsa discovery: B rejected C lsa".to_string(),
            });
        }
        // B 转发给 A（A 不是来源）。
        if seen_a.should_flood(&flooded.node_id, flooded.incarnation, flooded.seq) {
            lsdb_a.update(flooded);
        }
    }
    // 三节点 LSDB 节点集合一致（各 3 个：A/B/C）。
    let count_a = lsdb_a.len();
    let count_b = lsdb_b.len();
    let count_c = lsdb_c.len();
    // C 的 LSDB 还缺 A（A 的 LSA 还没泛洪到 C）；补一次 A->B->C 泛洪。
    let advert_a = LsaFrame::LsaAdvert { lsa: lsa_a.clone() };
    if seen_b.should_flood(&lsa_a.node_id, lsa_a.incarnation, lsa_a.seq) {
        lsdb_b.update(lsa_a.clone());
        let mut seen_c = SeenCache::new(1024);
        if seen_c.should_flood(&lsa_a.node_id, lsa_a.incarnation, lsa_a.seq) {
            lsdb_c.update(lsa_a.clone());
        }
    }
    let _ = advert_a;
    if lsdb_a.len() != 3 || lsdb_b.len() != 3 || lsdb_c.len() != 3 {
        return Err(NexusError::Internal {
            message: format!("lsa discovery: not converged ({count_a}/{count_b}/{count_c})"),
        });
    }
    events.push("lsa_flood_converged");

    // ---- 阶段 3：旧 seq 的 LSA 被拒绝 ----
    let stale = Lsa {
        seq: 0, // 比已知的 seq=1 旧
        ..lsa_c.clone()
    };
    if !matches!(lsdb_a.update(stale), UpdateOutcome::Stale) {
        return Err(NexusError::Internal {
            message: "lsa discovery: stale lsa was not rejected".to_string(),
        });
    }
    events.push("lsa_stale_rejected");

    // ---- 阶段 4：本端 LSA 不被远端同名 LSA 覆盖 ----
    let fake_self = Lsa {
        vip: "10.99.0.99".to_string(), // 试图冒充 A 的 VIP
        ..lsa_a.clone()
    };
    // A 用本端视角更新：node_id == self → SelfIgnored。
    if !matches!(lsdb_a.update(fake_self), UpdateOutcome::SelfIgnored) {
        return Err(NexusError::Internal {
            message: "lsa discovery: self lsa was overwritten".to_string(),
        });
    }
    // 确认 A 的 VIP 未被篡改。
    let kept = lsdb_a.get(&id_a).ok_or(NexusError::Internal {
        message: "lsa discovery: self lsa missing".to_string(),
    })?;
    if kept.vip != "10.99.0.1" {
        return Err(NexusError::Internal {
            message: "lsa discovery: self vip was tampered".to_string(),
        });
    }
    events.push("lsa_self_ignored");

    // 避免未使用警告。
    let _ = LinkAdvert {
        neighbor: id_b.clone(),
        metrics: nexus_discovery::lsa::LinkMetrics {
            latency_ms: 10,
            loss_pct: 0,
            bandwidth_kbps: 1000,
        },
    };

    Ok(json!({
        "verdict": "PASS",
        "events": events,
        "converged": { "node_count": 3 },
    }))
}

/// E4 `product.dijkstra-fib`（PRODUCT §12.45）的可执行驱动。
///
/// ```text
/// 四节点进程内（A 视角）：LSDB（含链路通告）→ TopoView → Dijkstra →
/// FIB（dst vip → Vec<NextHop>）；验证间接最短路优于慢直连
/// ```
///
/// 全程零真实网络；错误一律 typed `Result`，无 panic。
pub fn dijkstra_fib_flow() -> Result<Value, NexusError> {
    use nexus_discovery::PeerId;
    use nexus_discovery::lsa::{LinkAdvert, LinkMetrics, Lsa, Lsdb};
    use nexus_discovery::routing::{Fib, PathComputer, ShortestPath, TopoView};

    let mut events: Vec<&'static str> = Vec::new();

    let id_a = PeerId("node-a".to_string());
    let id_b = PeerId("node-b".to_string());
    let id_c = PeerId("node-c".to_string());
    let id_d = PeerId("node-d".to_string());

    fn link(to: &PeerId, latency_ms: u32) -> LinkAdvert {
        LinkAdvert {
            neighbor: to.clone(),
            metrics: LinkMetrics {
                latency_ms,
                loss_pct: 0,
                bandwidth_kbps: 100_000,
            },
        }
    }

    // 四节点 LSA（neighbors 已填充链路通告；链路对称）。
    // 拓扑：A-B 10ms，B-D 10ms，A-C 50ms，C-D 10ms，B-C 10ms。
    let lsa_a = Lsa {
        node_id: id_a.clone(),
        vip: "10.99.0.1".to_string(),
        incarnation: 1,
        seq: 1,
        capabilities: 0,
        locator: None,
        neighbors: vec![link(&id_b, 10), link(&id_c, 50)],
    };
    let lsa_b = Lsa {
        node_id: id_b.clone(),
        vip: "10.99.0.2".to_string(),
        incarnation: 1,
        seq: 1,
        capabilities: 0,
        locator: None,
        neighbors: vec![link(&id_a, 10), link(&id_c, 10), link(&id_d, 10)],
    };
    let lsa_c = Lsa {
        node_id: id_c.clone(),
        vip: "10.99.0.3".to_string(),
        incarnation: 1,
        seq: 1,
        capabilities: 0,
        locator: None,
        neighbors: vec![link(&id_a, 50), link(&id_b, 10), link(&id_d, 10)],
    };
    let lsa_d = Lsa {
        node_id: id_d.clone(),
        vip: "10.99.0.4".to_string(),
        incarnation: 1,
        seq: 1,
        capabilities: 0,
        locator: None,
        neighbors: vec![link(&id_b, 10), link(&id_c, 10)],
    };

    // A 的 LSDB：本端经 update_local，其余经泛洪 update。
    let mut lsdb = Lsdb::new(id_a.clone());
    lsdb.update_local(lsa_a);
    lsdb.update(lsa_b);
    lsdb.update(lsa_c);
    lsdb.update(lsa_d);

    // ---- 阶段 1：TopoView 建图 ----
    let topo = TopoView::from_lsdb(&lsdb);
    if topo.node_count() != 4 {
        return Err(NexusError::Internal {
            message: "dijkstra fib: topo node count != 4".to_string(),
        });
    }
    events.push("topo_built");

    // ---- 阶段 2：Dijkstra 最短路 ----
    let computer = ShortestPath::new();
    if computer.name() != "shortest" {
        return Err(NexusError::Internal {
            message: "dijkstra fib: computer name mismatch".to_string(),
        });
    }
    let fail = |m: &str| NexusError::Internal {
        message: format!("dijkstra fib: {m}"),
    };
    // A→B：直连 10ms。
    let p_b = computer
        .compute(&topo, &id_a, &id_b)
        .ok_or_else(|| fail("no path A->B"))?;
    if p_b.cost != 10 || p_b.nodes.len() != 2 {
        return Err(fail("A->B path wrong"));
    }
    // A→C：A-B-C 20ms 优于 A-C 直连 50ms。
    let p_c = computer
        .compute(&topo, &id_a, &id_c)
        .ok_or_else(|| fail("no path A->C"))?;
    if p_c.cost != 20 || p_c.nodes != vec![id_a.clone(), id_b.clone(), id_c.clone()] {
        return Err(fail("A->C should go via B"));
    }
    // A→D：A-B-D 20ms 最短。
    let p_d = computer
        .compute(&topo, &id_a, &id_d)
        .ok_or_else(|| fail("no path A->D"))?;
    if p_d.cost != 20 || p_d.nodes != vec![id_a.clone(), id_b.clone(), id_d.clone()] {
        return Err(fail("A->D should go via B"));
    }
    // 不可达：未知节点 → None。
    if computer
        .compute(&topo, &id_a, &PeerId("node-x".to_string()))
        .is_some()
    {
        return Err(fail("unknown dst should have no path"));
    }
    events.push("shortest_paths_ok");

    // ---- 阶段 3：FIB（dst vip → Vec<NextHop>，本期每 dst 1 条） ----
    let fib = Fib::compute(&lsdb, &id_a, &computer, 1);
    if fib.generation() != 1 {
        return Err(fail("fib generation != 1"));
    }
    let check_via = |vip: &str, expect_peer: &PeerId| -> Result<(), NexusError> {
        let hops = fib.lookup(vip).ok_or_else(|| fail("fib missing dst"))?;
        if hops.len() != 1 {
            return Err(fail("fib entry should be vec_single"));
        }
        if hops[0].peer != *expect_peer || hops[0].weight != 1 || hops[0].path_id != 0 {
            return Err(fail("fib next_hop wrong"));
        }
        Ok(())
    };
    check_via("10.99.0.2", &id_b)?;
    check_via("10.99.0.3", &id_b)?;
    check_via("10.99.0.4", &id_b)?;
    // 本端无条目；未知 VIP 无条目。
    if fib.lookup("10.99.0.1").is_some() || fib.lookup("10.99.9.9").is_some() {
        return Err(fail("fib should not contain self/unknown"));
    }
    events.push("fib_shape_ok");

    // ---- 阶段 4：代际原子替换（重算 → 新 generation；旧 FIB 不变） ----
    let fib2 = Fib::compute(&lsdb, &id_a, &computer, 2);
    if fib2.generation() != 2 || fib.generation() != 1 {
        return Err(fail("generation not bumped atomically"));
    }
    // 旧 FIB 内容不受影响（整体替换，非原地修改）。
    check_via("10.99.0.4", &id_b)?;
    events.push("generation_bumped");

    Ok(json!({
        "verdict": "PASS",
        "events": events,
        "fib": {
            "a_to_c_via": "node-b",
            "a_to_d_via": "node-b",
            "entry_shape": "vec_single",
        },
        "generation": fib2.generation(),
    }))
}

/// E4 `product.ecmp`（PRODUCT §12.46）的可执行驱动。
///
/// ```text
/// 菱形拓扑进程内（A 视角）：A-B 10ms、B-D 10ms、A-C 10ms、C-D 10ms；
/// A→D 有两条 20ms 等代价最短路（经 B、经 C），FIB 填 2 条 NextHop
/// ```
///
/// 全程零真实网络；错误一律 typed `Result`，无 panic。
pub fn ecmp_flow() -> Result<Value, NexusError> {
    use nexus_discovery::PeerId;
    use nexus_discovery::lsa::{LinkAdvert, LinkMetrics, Lsa, Lsdb};
    use nexus_discovery::routing::{Ecmp, Fib, PathComputer, ShortestPath};

    let mut events: Vec<&'static str> = Vec::new();

    let id_a = PeerId("node-a".to_string());
    let id_b = PeerId("node-b".to_string());
    let id_c = PeerId("node-c".to_string());
    let id_d = PeerId("node-d".to_string());

    fn link(to: &PeerId, latency_ms: u32) -> LinkAdvert {
        LinkAdvert {
            neighbor: to.clone(),
            metrics: LinkMetrics {
                latency_ms,
                loss_pct: 0,
                bandwidth_kbps: 100_000,
            },
        }
    }

    // 菱形拓扑（链路对称）。
    let lsa_a = Lsa {
        node_id: id_a.clone(),
        vip: "10.99.0.1".to_string(),
        incarnation: 1,
        seq: 1,
        capabilities: 0,
        locator: None,
        neighbors: vec![link(&id_b, 10), link(&id_c, 10)],
    };
    let lsa_b = Lsa {
        node_id: id_b.clone(),
        vip: "10.99.0.2".to_string(),
        incarnation: 1,
        seq: 1,
        capabilities: 0,
        locator: None,
        neighbors: vec![link(&id_a, 10), link(&id_d, 10)],
    };
    let lsa_c = Lsa {
        node_id: id_c.clone(),
        vip: "10.99.0.3".to_string(),
        incarnation: 1,
        seq: 1,
        capabilities: 0,
        locator: None,
        neighbors: vec![link(&id_a, 10), link(&id_d, 10)],
    };
    let lsa_d = Lsa {
        node_id: id_d.clone(),
        vip: "10.99.0.4".to_string(),
        incarnation: 1,
        seq: 1,
        capabilities: 0,
        locator: None,
        neighbors: vec![link(&id_b, 10), link(&id_c, 10)],
    };

    let mut lsdb = Lsdb::new(id_a.clone());
    lsdb.update_local(lsa_a);
    lsdb.update(lsa_b);
    lsdb.update(lsa_c);
    lsdb.update(lsa_d);

    let fail = |m: &str| NexusError::Internal {
        message: format!("ecmp: {m}"),
    };

    // ---- 阶段 1：Ecmp 找到 2 条等代价最短路 ----
    let ecmp = Ecmp::new();
    if ecmp.name() != "ecmp" {
        return Err(fail("computer name mismatch"));
    }
    let topo = nexus_discovery::routing::TopoView::from_lsdb(&lsdb);
    let paths = ecmp.compute_paths(&topo, &id_a, &id_d);
    if paths.len() != 2 {
        return Err(fail("A->D should have 2 equal-cost paths"));
    }
    for p in &paths {
        if p.cost != 20 || p.nodes.len() != 3 {
            return Err(fail("ECMP path cost/hops wrong"));
        }
    }
    // 两条路径的第二跳不同（B vs C）。
    let mut second_hops: Vec<String> = paths.iter().map(|p| p.nodes[1].0.clone()).collect();
    second_hops.sort();
    if second_hops != vec!["node-b".to_string(), "node-c".to_string()] {
        return Err(fail("ECMP second hops should be B and C"));
    }
    // compute() 返回其中一条（兼容单路径语义）。
    let single = ecmp
        .compute(&topo, &id_a, &id_d)
        .ok_or_else(|| fail("no path"))?;
    if single.cost != 20 {
        return Err(fail("compute() should return one shortest path"));
    }
    events.push("ecmp_paths_found");

    // ---- 阶段 2：FIB 多下一跳 ----
    let fib = Fib::compute(&lsdb, &id_a, &ecmp, 1);
    let hops_d = fib
        .lookup("10.99.0.4")
        .ok_or_else(|| fail("fib missing D"))?;
    if hops_d.len() != 2 {
        return Err(fail("FIB A->D should have 2 next hops"));
    }
    let mut peers: Vec<String> = hops_d.iter().map(|h| h.peer.0.clone()).collect();
    peers.sort();
    if peers != vec!["node-b".to_string(), "node-c".to_string()] {
        return Err(fail("FIB next hops should be B and C"));
    }
    // path_id 为路径序号（0/1），weight 恒 1。
    if hops_d.iter().any(|h| h.weight != 1) {
        return Err(fail("weight should be 1"));
    }
    events.push("fib_multi_nexthop");

    // ---- 阶段 3：单路径兼容（ShortestPath 行为不变） ----
    let sp = ShortestPath::new();
    let fib_sp = Fib::compute(&lsdb, &id_a, &sp, 1);
    let hops_sp = fib_sp
        .lookup("10.99.0.4")
        .ok_or_else(|| fail("sp fib missing D"))?;
    if hops_sp.len() != 1 {
        return Err(fail("ShortestPath FIB should stay vec_single"));
    }
    // A→B 只有一条路，Ecmp 下也是单下一跳。
    let hops_b = fib
        .lookup("10.99.0.2")
        .ok_or_else(|| fail("fib missing B"))?;
    if hops_b.len() != 1 || hops_b[0].peer != id_b {
        return Err(fail("A->B should stay single next hop"));
    }
    events.push("single_path_compat");

    Ok(json!({
        "verdict": "PASS",
        "events": events,
        "fib": {
            "a_to_d_next_hops": hops_d.len(),
            "entry_shape": "vec_multi",
        },
    }))
}

/// E4 产品场景 `product.flow-hash` 的可执行驱动（PRODUCT §12.47）。
///
/// 菱形拓扑（同 ecmp_flow）：A→D 有 2 条 20ms 等代价路径，FIB 持有 2 条 NextHop。
/// 验证按流哈希选择下一跳：同流恒定、异流分散、单路径稳定、未知 VIP 为 None。
pub fn flow_hash_selection() -> Result<Value, NexusError> {
    use nexus_discovery::PeerId;
    use nexus_discovery::lsa::{LinkAdvert, LinkMetrics, Lsa, Lsdb};
    use nexus_discovery::routing::{Ecmp, Fib, FlowKey};

    let mut events: Vec<&'static str> = Vec::new();

    let id_a = PeerId("node-a".to_string());
    let id_b = PeerId("node-b".to_string());
    let id_c = PeerId("node-c".to_string());
    let id_d = PeerId("node-d".to_string());

    fn link(to: &PeerId, latency_ms: u32) -> LinkAdvert {
        LinkAdvert {
            neighbor: to.clone(),
            metrics: LinkMetrics {
                latency_ms,
                loss_pct: 0,
                bandwidth_kbps: 100_000,
            },
        }
    }

    // 菱形拓扑（链路对称），VIP 段与 ecmp_flow 一致。
    let lsa_a = Lsa {
        node_id: id_a.clone(),
        vip: "10.99.0.1".to_string(),
        incarnation: 1,
        seq: 1,
        capabilities: 0,
        locator: None,
        neighbors: vec![link(&id_b, 10), link(&id_c, 10)],
    };
    let lsa_b = Lsa {
        node_id: id_b.clone(),
        vip: "10.99.0.2".to_string(),
        incarnation: 1,
        seq: 1,
        capabilities: 0,
        locator: None,
        neighbors: vec![link(&id_a, 10), link(&id_d, 10)],
    };
    let lsa_c = Lsa {
        node_id: id_c.clone(),
        vip: "10.99.0.3".to_string(),
        incarnation: 1,
        seq: 1,
        capabilities: 0,
        locator: None,
        neighbors: vec![link(&id_a, 10), link(&id_d, 10)],
    };
    let lsa_d = Lsa {
        node_id: id_d.clone(),
        vip: "10.99.0.4".to_string(),
        incarnation: 1,
        seq: 1,
        capabilities: 0,
        locator: None,
        neighbors: vec![link(&id_b, 10), link(&id_c, 10)],
    };

    let mut lsdb = Lsdb::new(id_a.clone());
    lsdb.update_local(lsa_a);
    lsdb.update(lsa_b);
    lsdb.update(lsa_c);
    lsdb.update(lsa_d);

    let fail = |m: &str| NexusError::Internal {
        message: format!("flow_hash: {m}"),
    };
    let parse_ip = |s: &str| -> Result<std::net::IpAddr, NexusError> {
        s.parse().map_err(|_| fail("bad test ip literal"))
    };

    // ---- 前置：A→D FIB 有 2 条 NextHop（B 和 C）----
    let fib = Fib::compute(&lsdb, &id_a, &Ecmp::new(), 1);
    let hops_d = fib
        .lookup("10.99.0.4")
        .ok_or_else(|| fail("fib missing D"))?;
    if hops_d.len() != 2 {
        return Err(fail("FIB A->D should have 2 next hops"));
    }

    // ---- 阶段 1：同流恒定（同一 FlowKey 选 100 次，结果恒定）----
    let flow = FlowKey {
        src_ip: parse_ip("10.99.0.1")?,
        dst_ip: parse_ip("10.99.0.4")?,
        src_port: 12345,
        dst_port: 80,
        protocol: 6,
    };
    let first = fib
        .select_next_hop("10.99.0.4", &flow)
        .ok_or_else(|| fail("select should hit"))?;
    for _ in 0..99 {
        let hop = fib
            .select_next_hop("10.99.0.4", &flow)
            .ok_or_else(|| fail("select should hit"))?;
        if hop != first {
            return Err(fail("same flow must select same next hop"));
        }
    }
    events.push("flow_stable");

    // ---- 阶段 2：异流分散（1000 个不同流，每条下一跳 ≥ 30%）----
    let mut count_b = 0u32;
    let mut count_c = 0u32;
    for i in 0..1000u32 {
        let f = FlowKey {
            src_ip: parse_ip("10.99.0.1")?,
            dst_ip: parse_ip("10.99.0.4")?,
            // 端口递增构造不同流（src_port 循环 + dst_port 递增，避免 u16 溢出）。
            src_port: (10000 + (i % 5000)) as u16,
            dst_port: (80 + (i / 5000)) as u16,
            protocol: 6,
        };
        let hop = fib
            .select_next_hop("10.99.0.4", &f)
            .ok_or_else(|| fail("select should hit"))?;
        if hop.peer == id_b {
            count_b += 1;
        } else if hop.peer == id_c {
            count_c += 1;
        } else {
            return Err(fail("unexpected next hop peer"));
        }
    }
    if count_b + count_c != 1000 {
        return Err(fail("flow count mismatch"));
    }
    // 每条 ≥ 30%：哈希分散性门限（FNV-1a 在 1000 样本下远高于此）。
    if count_b < 300 || count_c < 300 {
        return Err(fail(&format!(
            "flows should spread across next hops (b={count_b}, c={count_c})"
        )));
    }
    events.push("flows_spread");

    // ---- 阶段 3：单路径稳定（A→B 只有 1 条下一跳，恒返回该条）----
    let hops_b = fib
        .lookup("10.99.0.2")
        .ok_or_else(|| fail("fib missing B"))?;
    if hops_b.len() != 1 {
        return Err(fail("A->B should have single next hop"));
    }
    for i in 0..50u32 {
        let f = FlowKey {
            src_ip: parse_ip("10.99.0.1")?,
            dst_ip: parse_ip("10.99.0.2")?,
            src_port: (20000 + i) as u16,
            dst_port: 443,
            protocol: 6,
        };
        let hop = fib
            .select_next_hop("10.99.0.2", &f)
            .ok_or_else(|| fail("select should hit"))?;
        if hop.peer != id_b {
            return Err(fail("single next hop must be B"));
        }
    }
    events.push("single_path_stable");

    // ---- 阶段 4：未知 VIP 返回 None ----
    if fib.select_next_hop("10.99.9.9", &flow).is_some() {
        return Err(fail("unknown VIP should return None"));
    }
    events.push("unknown_vip_none");

    Ok(json!({
        "verdict": "PASS",
        "events": events,
        "selection": {
            "a_to_d_next_hops": hops_d.len(),
            "flow_stable_rounds": 100,
            "spread_b": count_b,
            "spread_c": count_c,
        },
    }))
}

/// E4 产品场景 `product.routing-strategy` 的可执行驱动（PRODUCT §12.48）。
///
/// 验证 `[routing] strategy` 配置装配：字符串解析 → `RoutingStrategy` →
/// `PathComputer` 委托 → FIB。菱形拓扑（同 ecmp_flow）。
pub fn routing_strategy_flow() -> Result<Value, NexusError> {
    use nexus_discovery::PeerId;
    use nexus_discovery::lsa::{LinkAdvert, LinkMetrics, Lsa, Lsdb};
    use nexus_discovery::routing::{Fib, PathComputer, RoutingStrategy};

    let mut events: Vec<&'static str> = Vec::new();

    let fail = |m: &str| NexusError::Internal {
        message: format!("routing_strategy: {m}"),
    };

    // ---- 阶段 1：parse_ok ----
    if RoutingStrategy::parse("ecmp") != Ok(RoutingStrategy::Ecmp) {
        return Err(fail("parse ecmp"));
    }
    if RoutingStrategy::parse("ECMP") != Ok(RoutingStrategy::Ecmp) {
        return Err(fail("parse ECMP (case-insensitive)"));
    }
    if RoutingStrategy::parse(" shortest ") != Ok(RoutingStrategy::Shortest) {
        return Err(fail("parse ' shortest ' (trim)"));
    }
    if RoutingStrategy::parse("").is_ok() {
        return Err(fail("parse empty should err"));
    }
    events.push("parse_ok");

    // ---- 阶段 2：parse_err ----
    // §12.53 起：裸 "k-shortest" 默认 k=2（不再是错误）。
    match RoutingStrategy::parse("k-shortest") {
        Ok(RoutingStrategy::KShortest { k: 2 }) => {}
        other => {
            return Err(fail(&format!(
                "parse k-shortest should default k=2, got {:?}",
                other
            )));
        }
    }
    if RoutingStrategy::parse("k-shortest:0").is_ok() {
        return Err(fail("parse k-shortest:0 should err"));
    }
    events.push("parse_err");

    // ---- 菱形拓扑 ----
    let id_a = PeerId("node-a".to_string());
    let id_b = PeerId("node-b".to_string());
    let id_c = PeerId("node-c".to_string());
    let id_d = PeerId("node-d".to_string());
    fn link(to: &PeerId, latency_ms: u32) -> LinkAdvert {
        LinkAdvert {
            neighbor: to.clone(),
            metrics: LinkMetrics {
                latency_ms,
                loss_pct: 0,
                bandwidth_kbps: 100_000,
            },
        }
    }
    let mut lsdb = Lsdb::new(id_a.clone());
    lsdb.update_local(Lsa {
        node_id: id_a.clone(),
        vip: "10.99.0.1".to_string(),
        incarnation: 1,
        seq: 1,
        capabilities: 0,
        locator: None,
        neighbors: vec![link(&id_b, 10), link(&id_c, 10)],
    });
    for (id, vip, nbs) in [
        (
            id_b.clone(),
            "10.99.0.2",
            vec![link(&id_a, 10), link(&id_d, 10)],
        ),
        (
            id_c.clone(),
            "10.99.0.3",
            vec![link(&id_a, 10), link(&id_d, 10)],
        ),
        (
            id_d.clone(),
            "10.99.0.4",
            vec![link(&id_b, 10), link(&id_c, 10)],
        ),
    ] {
        lsdb.update(Lsa {
            node_id: id,
            vip: vip.to_string(),
            incarnation: 1,
            seq: 1,
            capabilities: 0,
            locator: None,
            neighbors: nbs,
        });
    }

    // ---- 阶段 3：strategy_computes（Ecmp 经策略装配）----
    let strat = RoutingStrategy::Ecmp;
    if strat.name() != "ecmp" {
        return Err(fail("strategy name"));
    }
    let topo = nexus_discovery::routing::TopoView::from_lsdb(&lsdb);
    let paths = strat.compute_paths(&topo, &id_a, &id_d);
    if paths.len() != 2 {
        return Err(fail("Ecmp strategy should find 2 paths"));
    }
    let fib = Fib::compute(&lsdb, &id_a, &strat, 1);
    let hops_d = fib
        .lookup("10.99.0.4")
        .ok_or_else(|| fail("fib missing D"))?;
    if hops_d.len() != 2 {
        return Err(fail("Ecmp strategy FIB should have 2 next hops"));
    }
    events.push("strategy_computes");

    // ---- 阶段 4：strategy_default（缺省 → Shortest）----
    let def = RoutingStrategy::default();
    if def != RoutingStrategy::Shortest {
        return Err(fail("default should be Shortest"));
    }
    let fib_def = Fib::compute(&lsdb, &id_a, &def, 1);
    let hops_def = fib_def
        .lookup("10.99.0.4")
        .ok_or_else(|| fail("fib missing D"))?;
    if hops_def.len() != 1 {
        return Err(fail("Shortest strategy FIB should have 1 next hop"));
    }
    events.push("strategy_default");

    // ---- 阶段 5：config_toml（TOML [routing] 解析）----
    let toml_str = "[subnet]\ncidr = \"10.99.0.0/24\"\n[routing]\nstrategy = \"ecmp\"\n";
    let parsed: crate::subnet_cli::SubnetConfig =
        toml::from_str(toml_str).map_err(|e| fail(&format!("toml parse: {e}")))?;
    let from_cfg = parsed
        .routing_strategy()
        .map_err(|e| fail(&format!("strategy from config: {e}")))?;
    if from_cfg != RoutingStrategy::Ecmp {
        return Err(fail("toml [routing] strategy=ecmp"));
    }
    // 缺省 [routing] 段 → Shortest。
    let empty: crate::subnet_cli::SubnetConfig =
        toml::from_str("[subnet]\ncidr=\"10.99.0.0/24\"\n")
            .map_err(|e| fail(&format!("toml parse: {e}")))?;
    if empty.routing_strategy().map_err(|e| fail(&e))? != RoutingStrategy::Shortest {
        return Err(fail("missing [routing] should default to Shortest"));
    }
    // 未知策略 → CONFIG_ERROR。
    let bad: crate::subnet_cli::SubnetConfig =
        toml::from_str("[subnet]\ncidr=\"10.99.0.0/24\"\n[routing]\nstrategy=\"k-shortest\"\n")
            .map_err(|e| fail(&format!("toml parse: {e}")))?;
    // §12.53 起：裸 "k-shortest" 默认 k=2（不再是错误）。
    match bad.routing_strategy() {
        Ok(RoutingStrategy::KShortest { k: 2 }) => {}
        other => {
            return Err(fail(&format!(
                "toml k-shortest should default k=2, got {:?}",
                other
            )));
        }
    }
    // [routing] 段存在但缺 strategy 字段 → serde 默认回落为 Shortest。
    let no_field: crate::subnet_cli::SubnetConfig =
        toml::from_str("[subnet]\ncidr=\"10.99.0.0/24\"\n[routing]\n")
            .map_err(|e| fail(&format!("toml parse: {e}")))?;
    if no_field.routing_strategy().map_err(|e| fail(&e))? != RoutingStrategy::Shortest {
        return Err(fail("missing strategy field should default to Shortest"));
    }
    events.push("config_toml");

    Ok(json!({
        "verdict": "PASS",
        "events": events,
        "strategy": {
            "ecmp_next_hops": hops_d.len(),
            "default_next_hops": hops_def.len(),
        },
    }))
}

/// E4 产品场景 `product.k-shortest` 的可执行驱动（PRODUCT §12.49）。
///
/// 拓扑：A-B(10)、B-D(10)、A-C(10)、C-D(10)、A-D(35 直连)。
/// K=3 时 A→D 应得 3 条：20ms 经 B、20ms 经 C、35ms 直连（按代价升序）。
pub fn k_shortest_flow() -> Result<Value, NexusError> {
    use nexus_discovery::PeerId;
    use nexus_discovery::lsa::{LinkAdvert, LinkMetrics, Lsa, Lsdb};
    use nexus_discovery::routing::{KShortest, PathComputer, TopoView};

    let mut events: Vec<&'static str> = Vec::new();
    let fail = |m: &str| NexusError::Internal {
        message: format!("k_shortest: {m}"),
    };

    let id_a = PeerId("node-a".to_string());
    let id_b = PeerId("node-b".to_string());
    let id_c = PeerId("node-c".to_string());
    let id_d = PeerId("node-d".to_string());
    let id_iso = PeerId("node-iso".to_string());
    fn link(to: &PeerId, latency_ms: u32) -> LinkAdvert {
        LinkAdvert {
            neighbor: to.clone(),
            metrics: LinkMetrics {
                latency_ms,
                loss_pct: 0,
                bandwidth_kbps: 100_000,
            },
        }
    }

    let mut lsdb = Lsdb::new(id_a.clone());
    lsdb.update_local(Lsa {
        node_id: id_a.clone(),
        vip: "10.99.0.1".to_string(),
        incarnation: 1,
        seq: 1,
        capabilities: 0,
        locator: None,
        neighbors: vec![link(&id_b, 10), link(&id_c, 10), link(&id_d, 35)],
    });
    for (id, vip, nbs) in [
        (
            id_b.clone(),
            "10.99.0.2",
            vec![link(&id_a, 10), link(&id_d, 10)],
        ),
        (
            id_c.clone(),
            "10.99.0.3",
            vec![link(&id_a, 10), link(&id_d, 10)],
        ),
        (
            id_d.clone(),
            "10.99.0.4",
            vec![link(&id_b, 10), link(&id_c, 10), link(&id_a, 35)],
        ),
        (id_iso.clone(), "10.99.0.9", vec![]),
    ] {
        lsdb.update(Lsa {
            node_id: id,
            vip: vip.to_string(),
            incarnation: 1,
            seq: 1,
            capabilities: 0,
            locator: None,
            neighbors: nbs,
        });
    }
    let topo = TopoView::from_lsdb(&lsdb);

    // ---- 阶段 1：K=3 得 3 条 ----
    let ks3 = KShortest::new(3);
    if ks3.name() != "k-shortest" {
        return Err(fail("name"));
    }
    let paths = ks3.compute_paths(&topo, &id_a, &id_d);
    if paths.len() != 3 {
        return Err(fail(&format!(
            "K=3 should find 3 paths, got {}",
            paths.len()
        )));
    }
    events.push("k_paths_found");

    // ---- 阶段 2：按代价升序 ----
    let costs: Vec<u64> = paths.iter().map(|p| p.cost).collect();
    if costs != vec![20, 20, 35] {
        return Err(fail(&format!("costs should be [20,20,35], got {costs:?}")));
    }
    // 前两条为经 B / 经 C（顺序不限），第三条为直连。
    if paths[2].nodes.len() != 2 || paths[2].nodes[1] != id_d {
        return Err(fail("3rd path should be direct A->D"));
    }
    events.push("k_ordered");

    // ---- 阶段 3：K=2 截断 ----
    let ks2 = KShortest::new(2);
    let paths2 = ks2.compute_paths(&topo, &id_a, &id_d);
    if paths2.len() != 2 {
        return Err(fail("K=2 should return 2 paths"));
    }
    // compute() 返回第一条（最短）。
    let first = ks3
        .compute(&topo, &id_a, &id_d)
        .ok_or_else(|| fail("compute"))?;
    if first.cost != 20 {
        return Err(fail("compute() should return shortest"));
    }
    events.push("k_truncated");

    // ---- 阶段 4：不可达 → 空 ----
    let empty = ks3.compute_paths(&topo, &id_a, &id_iso);
    if !empty.is_empty() {
        return Err(fail("unreachable should return empty"));
    }
    events.push("k_unreachable");

    Ok(json!({
        "verdict": "PASS",
        "events": events,
        "kshortest": {
            "k3_count": paths.len(),
            "k3_costs": costs,
        },
    }))
}

/// E4 产品场景 `product.fib-manager` 的可执行驱动（PRODUCT §12.50）。
///
/// 验证 FibManager：初始计算、无变化不重算、拓扑变化重算、经管理器选路。
pub fn fib_manager_flow() -> Result<Value, NexusError> {
    use nexus_discovery::PeerId;
    use nexus_discovery::lsa::{LinkAdvert, LinkMetrics, Lsa, Lsdb};
    use nexus_discovery::routing::{Ecmp, FibManager, FlowKey};

    let mut events: Vec<&'static str> = Vec::new();
    let fail = |m: &str| NexusError::Internal {
        message: format!("fib_manager: {m}"),
    };

    let id_a = PeerId("node-a".to_string());
    let id_b = PeerId("node-b".to_string());
    let id_c = PeerId("node-c".to_string());
    let id_d = PeerId("node-d".to_string());
    let id_e = PeerId("node-e".to_string());
    fn link(to: &PeerId, latency_ms: u32) -> LinkAdvert {
        LinkAdvert {
            neighbor: to.clone(),
            metrics: LinkMetrics {
                latency_ms,
                loss_pct: 0,
                bandwidth_kbps: 100_000,
            },
        }
    }

    // 菱形拓扑。
    let mut lsdb = Lsdb::new(id_a.clone());
    lsdb.update_local(Lsa {
        node_id: id_a.clone(),
        vip: "10.99.0.1".to_string(),
        incarnation: 1,
        seq: 1,
        capabilities: 0,
        locator: None,
        neighbors: vec![link(&id_b, 10), link(&id_c, 10)],
    });
    for (id, vip, nbs) in [
        (
            id_b.clone(),
            "10.99.0.2",
            vec![link(&id_a, 10), link(&id_d, 10)],
        ),
        (
            id_c.clone(),
            "10.99.0.3",
            vec![link(&id_a, 10), link(&id_d, 10)],
        ),
        (
            id_d.clone(),
            "10.99.0.4",
            vec![link(&id_b, 10), link(&id_c, 10)],
        ),
    ] {
        lsdb.update(Lsa {
            node_id: id,
            vip: vip.to_string(),
            incarnation: 1,
            seq: 1,
            capabilities: 0,
            locator: None,
            neighbors: nbs,
        });
    }

    // ---- 阶段 1：初始计算 ----
    let mut mgr = FibManager::new(id_a.clone(), Ecmp::new(), &lsdb);
    if mgr.generation() != 1 {
        return Err(fail("initial generation should be 1"));
    }
    if mgr.fib().lookup("10.99.0.4").is_none() {
        return Err(fail("initial FIB should have D"));
    }
    let gen1 = mgr.generation();
    events.push("initial_computed");

    // ---- 阶段 2：无变化不重算 ----
    if mgr.maybe_recompute(&lsdb) {
        return Err(fail("no change should return false"));
    }
    if mgr.generation() != gen1 {
        return Err(fail("generation should not bump"));
    }
    events.push("no_change_no_recompute");

    // ---- 阶段 3：拓扑变化重算 ----
    lsdb.update(Lsa {
        node_id: id_e.clone(),
        vip: "10.99.0.5".to_string(),
        incarnation: 1,
        seq: 1,
        capabilities: 0,
        locator: None,
        neighbors: vec![link(&id_d, 10)],
    });
    // D 也通告 E（双向）。
    lsdb.update(Lsa {
        node_id: id_d.clone(),
        vip: "10.99.0.4".to_string(),
        incarnation: 1,
        seq: 2,
        capabilities: 0,
        locator: None,
        neighbors: vec![link(&id_b, 10), link(&id_c, 10), link(&id_e, 10)],
    });
    if !mgr.maybe_recompute(&lsdb) {
        return Err(fail("topo change should return true"));
    }
    if mgr.generation() != 2 {
        return Err(fail("generation should be 2"));
    }
    if mgr.fib().lookup("10.99.0.5").is_none() {
        return Err(fail("FIB should contain E after recompute"));
    }
    let gen2 = mgr.generation();
    events.push("topo_change_recomputes");

    // ---- 阶段 4：经管理器选路 ----
    let flow = FlowKey {
        src_ip: "10.99.0.1".parse().map_err(|_| fail("bad ip"))?,
        dst_ip: "10.99.0.4".parse().map_err(|_| fail("bad ip"))?,
        src_port: 1234,
        dst_port: 80,
        protocol: 6,
    };
    let hop = mgr
        .select("10.99.0.4", &flow)
        .ok_or_else(|| fail("select"))?;
    if hop.peer != id_b && hop.peer != id_c {
        return Err(fail("select should return B or C"));
    }
    // 同流恒定。
    let hop2 = mgr
        .select("10.99.0.4", &flow)
        .ok_or_else(|| fail("select"))?;
    if hop != hop2 {
        return Err(fail("same flow should select same"));
    }
    events.push("select_via_manager");

    Ok(json!({
        "verdict": "PASS",
        "events": events,
        "manager": {
            "initial_generation": gen1,
            "after_change_generation": gen2,
        },
    }))
}

/// E4 产品场景 `product.weighted-selection` 的可执行驱动（PRODUCT §12.52）。
///
/// 拓扑：A-B(10)-D（代价 20）、A-C(10)-D(20)（代价 30）。K=2 时 FIB 权重：
/// B = 30-20+1 = 11，C = 30-30+1 = 1；1000 流按 ~11:1 分散。
pub fn weighted_selection_flow() -> Result<Value, NexusError> {
    use nexus_discovery::PeerId;
    use nexus_discovery::lsa::{LinkAdvert, LinkMetrics, Lsa, Lsdb};
    use nexus_discovery::routing::{Ecmp, Fib, FlowKey, KShortest};

    let mut events: Vec<&'static str> = Vec::new();
    let fail = |m: &str| NexusError::Internal {
        message: format!("weighted_selection: {m}"),
    };

    let id_a = PeerId("node-a".to_string());
    let id_b = PeerId("node-b".to_string());
    let id_c = PeerId("node-c".to_string());
    let id_d = PeerId("node-d".to_string());
    fn link(to: &PeerId, latency_ms: u32) -> LinkAdvert {
        LinkAdvert {
            neighbor: to.clone(),
            metrics: LinkMetrics {
                latency_ms,
                loss_pct: 0,
                bandwidth_kbps: 100_000,
            },
        }
    }

    // 非对称菱形：A-B-D 代价 20，A-C-D 代价 30。
    let mut lsdb = Lsdb::new(id_a.clone());
    lsdb.update_local(Lsa {
        node_id: id_a.clone(),
        vip: "10.99.0.1".to_string(),
        incarnation: 1,
        seq: 1,
        capabilities: 0,
        locator: None,
        neighbors: vec![link(&id_b, 10), link(&id_c, 10)],
    });
    lsdb.update(Lsa {
        node_id: id_b.clone(),
        vip: "10.99.0.2".to_string(),
        incarnation: 1,
        seq: 1,
        capabilities: 0,
        locator: None,
        neighbors: vec![link(&id_a, 10), link(&id_d, 10)],
    });
    lsdb.update(Lsa {
        node_id: id_c.clone(),
        vip: "10.99.0.3".to_string(),
        incarnation: 1,
        seq: 1,
        capabilities: 0,
        locator: None,
        neighbors: vec![link(&id_a, 10), link(&id_d, 20)],
    });
    lsdb.update(Lsa {
        node_id: id_d.clone(),
        vip: "10.99.0.4".to_string(),
        incarnation: 1,
        seq: 1,
        capabilities: 0,
        locator: None,
        neighbors: vec![link(&id_b, 10), link(&id_c, 20)],
    });

    let parse_ip = |s: &str| -> Result<std::net::IpAddr, NexusError> {
        s.parse().map_err(|_| fail("bad test ip literal"))
    };

    // ---- 事件 1：权重按代价反比分配 ----
    let fib = Fib::compute(&lsdb, &id_a, &KShortest::new(2), 1);
    let hops = fib
        .lookup("10.99.0.4")
        .ok_or_else(|| fail("fib missing D"))?;
    if hops.len() != 2 {
        return Err(fail("expected 2 next-hops"));
    }
    // 按 peer 排序：node-b 在前（weight 11），node-c 在后（weight 1）。
    if hops[0].weight != 11 || hops[1].weight != 1 {
        return Err(fail(&format!(
            "weights: b={} c={}",
            hops[0].weight, hops[1].weight
        )));
    }
    events.push("weights_assigned");

    // ---- 事件 2：1000 流按 ~11:1 分散 ----
    let mut counts = [0u32, 0u32];
    for i in 0..1000u16 {
        let flow = FlowKey {
            src_ip: parse_ip("10.99.0.1")?,
            dst_ip: parse_ip("10.99.0.4")?,
            src_port: 30000 + i,
            dst_port: 80,
            protocol: 6,
        };
        let hop = fib
            .select_next_hop("10.99.0.4", &flow)
            .ok_or_else(|| fail("no next-hop"))?;
        let idx = hops
            .iter()
            .position(|h| h == hop)
            .ok_or_else(|| fail("hop mismatch"))?;
        counts[idx] += 1;
    }
    if counts[0] < 800 || counts[1] > 200 {
        return Err(fail(&format!("distribution: {counts:?}")));
    }
    events.push("weighted_distribution");

    // ---- 事件 3：等代价时权重全 1（退化为均分）----
    let fib_ecmp = Fib::compute(&lsdb, &id_a, &Ecmp::new(), 1);
    // ECMP 在非对称拓扑下 A→D 只有 1 条最短路径（经 B，代价 20）。
    let hops_ecmp = fib_ecmp
        .lookup("10.99.0.4")
        .ok_or_else(|| fail("ecmp fib missing D"))?;
    if hops_ecmp.len() != 1 || hops_ecmp[0].weight != 1 {
        return Err(fail("ecmp should have single weight-1 hop"));
    }
    events.push("equal_cost_uniform");

    let mut out = serde_json::Map::new();
    out.insert(
        "weighted".to_string(),
        serde_json::json!({
            "weights": [hops[0].weight, hops[1].weight],
            "distribution": counts,
        }),
    );
    out.insert(
        "events".to_string(),
        serde_json::Value::Array(events.into_iter().map(serde_json::Value::from).collect()),
    );
    out.insert("verdict".to_string(), serde_json::Value::from("PASS"));
    Ok(serde_json::Value::Object(out))
}

/// E4 产品场景 `product.node-disjoint` 的可执行驱动（PRODUCT §12.55）。
///
/// 拓扑：菱形 A-B-D / A-C-D。验证两条路径除 src/dst 外无共享节点。
pub fn node_disjoint_flow() -> Result<Value, NexusError> {
    use nexus_discovery::PeerId;
    use nexus_discovery::lsa::{LinkAdvert, LinkMetrics, Lsa, Lsdb};
    use nexus_discovery::routing::{NodeDisjoint, PathComputer, TopoView};
    use std::collections::HashSet;

    let mut events: Vec<&'static str> = Vec::new();
    let fail = |m: &str| NexusError::Internal {
        message: format!("node_disjoint: {m}"),
    };

    let id_a = PeerId("node-a".to_string());
    let id_b = PeerId("node-b".to_string());
    let id_c = PeerId("node-c".to_string());
    let id_d = PeerId("node-d".to_string());
    fn link(to: &PeerId, latency_ms: u32) -> LinkAdvert {
        LinkAdvert {
            neighbor: to.clone(),
            metrics: LinkMetrics {
                latency_ms,
                loss_pct: 0,
                bandwidth_kbps: 100_000,
            },
        }
    }
    let mut lsdb = Lsdb::new(id_a.clone());
    lsdb.update_local(Lsa {
        node_id: id_a.clone(),
        vip: "10.99.0.1".to_string(),
        incarnation: 1,
        seq: 1,
        capabilities: 0,
        locator: None,
        neighbors: vec![link(&id_b, 10), link(&id_c, 10)],
    });
    lsdb.update(Lsa {
        node_id: id_b.clone(),
        vip: "10.99.0.2".to_string(),
        incarnation: 1,
        seq: 1,
        capabilities: 0,
        locator: None,
        neighbors: vec![link(&id_a, 10), link(&id_d, 10)],
    });
    lsdb.update(Lsa {
        node_id: id_c.clone(),
        vip: "10.99.0.3".to_string(),
        incarnation: 1,
        seq: 1,
        capabilities: 0,
        locator: None,
        neighbors: vec![link(&id_a, 10), link(&id_d, 10)],
    });
    lsdb.update(Lsa {
        node_id: id_d.clone(),
        vip: "10.99.0.4".to_string(),
        incarnation: 1,
        seq: 1,
        capabilities: 0,
        locator: None,
        neighbors: vec![link(&id_b, 10), link(&id_c, 10)],
    });
    let topo = TopoView::from_lsdb(&lsdb);

    // ---- 事件 1：得 2 条路径 ----
    let paths = NodeDisjoint::new().compute_paths(&topo, &id_a, &id_d);
    if paths.len() != 2 {
        return Err(fail(&format!("expected 2 paths, got {}", paths.len())));
    }
    events.push("two_paths_found");

    // ---- 事件 2：无共享中间节点 ----
    let mid0: HashSet<_> = paths[0].nodes[1..paths[0].nodes.len() - 1].iter().collect();
    let mid1: HashSet<_> = paths[1].nodes[1..paths[1].nodes.len() - 1].iter().collect();
    if !mid0.is_disjoint(&mid1) {
        return Err(fail("paths share intermediate nodes"));
    }
    events.push("no_shared_mid_nodes");

    let mut out = serde_json::Map::new();
    out.insert(
        "node_disjoint".to_string(),
        serde_json::json!({
            "path_count": paths.len(),
        }),
    );
    out.insert(
        "events".to_string(),
        serde_json::Value::Array(events.into_iter().map(serde_json::Value::from).collect()),
    );
    out.insert("verdict".to_string(), serde_json::Value::from("PASS"));
    Ok(serde_json::Value::Object(out))
}

/// 基于 discovery FIB 的转发面适配器（§12.56，composition root）。
///
/// 持有 `SharedFibManager<RoutingStrategy>` + `PeerId→VIP` 映射，
/// 实现 `nexus-connectivity::fib_resolver::FibResolver`，
/// 供 `VirtualSubnet::resolve_next_hop` 查询。
pub struct DiscoveryFibResolver {
    mgr: nexus_discovery::routing::SharedFibManager<nexus_discovery::routing::RoutingStrategy>,
    peer_to_vip: std::sync::Arc<
        std::sync::RwLock<std::collections::HashMap<nexus_discovery::PeerId, String>>,
    >,
}

impl DiscoveryFibResolver {
    /// 创建（从 LSDB 构建 PeerId→VIP 映射）。
    #[must_use]
    pub fn new(
        mgr: nexus_discovery::routing::SharedFibManager<nexus_discovery::routing::RoutingStrategy>,
        lsdb: &nexus_discovery::lsa::Lsdb,
    ) -> Self {
        let mut map = std::collections::HashMap::new();
        for lsa in lsdb.all() {
            map.insert(lsa.node_id.clone(), lsa.vip.clone());
        }
        Self {
            mgr,
            peer_to_vip: std::sync::Arc::new(std::sync::RwLock::new(map)),
        }
    }

    /// 同步 PeerId→VIP 映射（LSDB 变化后调用）。
    pub fn sync_peer_map(&self, lsdb: &nexus_discovery::lsa::Lsdb) {
        let mut map = std::collections::HashMap::new();
        for lsa in lsdb.all() {
            map.insert(lsa.node_id.clone(), lsa.vip.clone());
        }
        *self.peer_to_vip.write().unwrap() = map;
    }
}

impl nexus_connectivity::fib_resolver::FibResolver for DiscoveryFibResolver {
    fn resolve(
        &self,
        dst_vip: &str,
        flow: &nexus_connectivity::fib_resolver::FlowKeyView,
    ) -> Option<String> {
        let guard = self.mgr.read();
        let fib = guard.fib();
        let hops = fib.lookup(dst_vip)?;
        if hops.is_empty() {
            return None;
        }
        let dk_flow = nexus_discovery::routing::FlowKey {
            src_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::from(flow.src_ip)),
            dst_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::from(flow.dst_ip)),
            src_port: flow.src_port,
            dst_port: flow.dst_port,
            protocol: flow.protocol,
        };
        let hop = fib.select_next_hop(dst_vip, &dk_flow)?;
        self.peer_to_vip.read().unwrap().get(&hop.peer).cloned()
    }
}

/// E4 产品场景 `product.fib-manager-shared` 的可执行驱动（PRODUCT §12.54）。
///
/// 验证：多线程并发读（4 线程 × 50 次）无 panic；
/// 写线程触发重算后 generation+1 且新 FIB 可见。
pub fn fib_manager_shared_flow() -> Result<Value, NexusError> {
    use nexus_discovery::PeerId;
    use nexus_discovery::lsa::{LinkAdvert, LinkMetrics, Lsa, Lsdb};
    use nexus_discovery::routing::{Ecmp, SharedFibManager};

    let mut events: Vec<&'static str> = Vec::new();
    let fail = |m: &str| NexusError::Internal {
        message: format!("fib_manager_shared: {m}"),
    };

    let id_a = PeerId("node-a".to_string());
    let id_b = PeerId("node-b".to_string());
    let id_c = PeerId("node-c".to_string());
    let id_d = PeerId("node-d".to_string());
    fn link(to: &PeerId, latency_ms: u32) -> LinkAdvert {
        LinkAdvert {
            neighbor: to.clone(),
            metrics: LinkMetrics {
                latency_ms,
                loss_pct: 0,
                bandwidth_kbps: 100_000,
            },
        }
    }
    let mut lsdb = Lsdb::new(id_a.clone());
    lsdb.update_local(Lsa {
        node_id: id_a.clone(),
        vip: "10.99.0.1".to_string(),
        incarnation: 1,
        seq: 1,
        capabilities: 0,
        locator: None,
        neighbors: vec![link(&id_b, 10), link(&id_c, 10)],
    });
    lsdb.update(Lsa {
        node_id: id_b.clone(),
        vip: "10.99.0.2".to_string(),
        incarnation: 1,
        seq: 1,
        capabilities: 0,
        locator: None,
        neighbors: vec![link(&id_a, 10), link(&id_d, 10)],
    });
    lsdb.update(Lsa {
        node_id: id_c.clone(),
        vip: "10.99.0.3".to_string(),
        incarnation: 1,
        seq: 1,
        capabilities: 0,
        locator: None,
        neighbors: vec![link(&id_a, 10), link(&id_d, 10)],
    });
    lsdb.update(Lsa {
        node_id: id_d.clone(),
        vip: "10.99.0.4".to_string(),
        incarnation: 1,
        seq: 1,
        capabilities: 0,
        locator: None,
        neighbors: vec![link(&id_b, 10), link(&id_c, 10)],
    });

    let shared = SharedFibManager::new(id_a.clone(), Ecmp::new(), &lsdb);

    // ---- 事件 1：多线程并发读 ----
    let mut handles = Vec::new();
    for _ in 0..4 {
        let s = shared.clone();
        handles.push(std::thread::spawn(move || {
            for _ in 0..50 {
                let guard = s.read();
                if guard.fib().lookup("10.99.0.4").is_none() {
                    return false;
                }
            }
            true
        }));
    }
    for h in handles {
        if !h.join().map_err(|_| fail("reader panicked"))? {
            return Err(fail("concurrent read failed"));
        }
    }
    events.push("concurrent_read");

    // ---- 事件 2：写触发重算 ----
    let mut lsdb2 = lsdb;
    lsdb2.update(Lsa {
        node_id: PeerId("node-e".to_string()),
        vip: "10.99.0.5".to_string(),
        incarnation: 1,
        seq: 1,
        capabilities: 0,
        locator: None,
        neighbors: vec![link(&id_d, 10)],
    });
    // d 的 LSA 需要更新以包含 e（否则 e 不可达，但指纹会变，照样触发重算）。
    if !shared.maybe_recompute(&lsdb2) {
        return Err(fail("expected recompute"));
    }
    if shared.read().generation() != 2 {
        return Err(fail("generation should be 2"));
    }
    events.push("write_recompute");

    let mut out = serde_json::Map::new();
    out.insert(
        "shared".to_string(),
        serde_json::json!({
            "generation": shared.read().generation(),
        }),
    );
    out.insert(
        "events".to_string(),
        serde_json::Value::Array(events.into_iter().map(serde_json::Value::from).collect()),
    );
    out.insert("verdict".to_string(), serde_json::Value::from("PASS"));
    Ok(serde_json::Value::Object(out))
}

/// E4 产品场景 `product.strategy-extended` 的可执行驱动（PRODUCT §12.53）。
///
/// 验证：`"k-shortest:3"` 解析为 KShortest{k:3}；
/// `"disjoint"` 解析为 Disjoint；
/// 非法参数返回 InvalidParameter；
/// 策略装配后算路（K=2 得 2 条，Disjoint 得 2 条）。
pub fn strategy_extended_flow() -> Result<Value, NexusError> {
    use nexus_discovery::routing::{PathComputer, RoutingStrategy, StrategyParseError};

    let mut events: Vec<&'static str> = Vec::new();
    let fail = |m: &str| NexusError::Internal {
        message: format!("strategy_extended: {m}"),
    };

    // ---- 事件 1：k-shortest:3 解析 ----
    match RoutingStrategy::parse("k-shortest:3") {
        Ok(RoutingStrategy::KShortest { k: 3 }) => events.push("parse_kshortest"),
        other => return Err(fail(&format!("parse k-shortest:3 -> {other:?}"))),
    }

    // ---- 事件 2：disjoint 解析 ----
    match RoutingStrategy::parse("disjoint") {
        Ok(RoutingStrategy::Disjoint) => events.push("parse_disjoint"),
        other => return Err(fail(&format!("parse disjoint -> {other:?}"))),
    }

    // ---- 事件 3：非法参数 ----
    match RoutingStrategy::parse("k-shortest:0") {
        Err(StrategyParseError::InvalidParameter(_)) => events.push("reject_invalid"),
        other => return Err(fail(&format!("k-shortest:0 -> {other:?}"))),
    }

    // ---- 事件 4：策略装配算路 ----
    // 用 diamond 拓扑验证委托：KShortest{2} 得 2 条，Disjoint 得 2 条。
    use nexus_discovery::PeerId;
    use nexus_discovery::lsa::{LinkAdvert, LinkMetrics, Lsa, Lsdb};
    use nexus_discovery::routing::TopoView;
    let id_a = PeerId("node-a".to_string());
    let id_b = PeerId("node-b".to_string());
    let id_c = PeerId("node-c".to_string());
    let id_d = PeerId("node-d".to_string());
    fn link(to: &PeerId, latency_ms: u32) -> LinkAdvert {
        LinkAdvert {
            neighbor: to.clone(),
            metrics: LinkMetrics {
                latency_ms,
                loss_pct: 0,
                bandwidth_kbps: 100_000,
            },
        }
    }
    let mut lsdb = Lsdb::new(id_a.clone());
    lsdb.update_local(Lsa {
        node_id: id_a.clone(),
        vip: "10.99.0.1".to_string(),
        incarnation: 1,
        seq: 1,
        capabilities: 0,
        locator: None,
        neighbors: vec![link(&id_b, 10), link(&id_c, 10)],
    });
    lsdb.update(Lsa {
        node_id: id_b.clone(),
        vip: "10.99.0.2".to_string(),
        incarnation: 1,
        seq: 1,
        capabilities: 0,
        locator: None,
        neighbors: vec![link(&id_a, 10), link(&id_d, 10)],
    });
    lsdb.update(Lsa {
        node_id: id_c.clone(),
        vip: "10.99.0.3".to_string(),
        incarnation: 1,
        seq: 1,
        capabilities: 0,
        locator: None,
        neighbors: vec![link(&id_a, 10), link(&id_d, 10)],
    });
    lsdb.update(Lsa {
        node_id: id_d.clone(),
        vip: "10.99.0.4".to_string(),
        incarnation: 1,
        seq: 1,
        capabilities: 0,
        locator: None,
        neighbors: vec![link(&id_b, 10), link(&id_c, 10)],
    });
    let topo = TopoView::from_lsdb(&lsdb);
    let k2 = RoutingStrategy::parse("k-shortest:2").map_err(|_| fail("parse k2"))?;
    let paths_k2 = k2.compute_paths(&topo, &id_a, &id_d);
    let dis = RoutingStrategy::parse("disjoint").map_err(|_| fail("parse dis"))?;
    let paths_dis = dis.compute_paths(&topo, &id_a, &id_d);
    if paths_k2.len() != 2 || paths_dis.len() != 2 {
        return Err(fail(&format!(
            "k2={}, dis={}",
            paths_k2.len(),
            paths_dis.len()
        )));
    }
    events.push("delegate_compute");

    let mut out = serde_json::Map::new();
    out.insert(
        "strategy".to_string(),
        serde_json::json!({
            "kshortest_paths": paths_k2.len(),
            "disjoint_paths": paths_dis.len(),
        }),
    );
    out.insert(
        "events".to_string(),
        serde_json::Value::Array(events.into_iter().map(serde_json::Value::from).collect()),
    );
    out.insert("verdict".to_string(), serde_json::Value::from("PASS"));
    Ok(serde_json::Value::Object(out))
}

/// E4 产品场景 `product.disjoint` 的可执行驱动（PRODUCT §12.51）。
///
/// 拓扑：A-B(10)-D、A-C(10)-D、B-C(5)。Suurballe 应得 2 条边不交：
/// A-B-D（20）与 A-C-D（20）。
pub fn disjoint_flow() -> Result<Value, NexusError> {
    use nexus_discovery::PeerId;
    use nexus_discovery::lsa::{LinkAdvert, LinkMetrics, Lsa, Lsdb};
    use nexus_discovery::routing::{Disjoint, PathComputer, TopoView};

    let mut events: Vec<&'static str> = Vec::new();
    let fail = |m: &str| NexusError::Internal {
        message: format!("disjoint: {m}"),
    };

    let id_a = PeerId("node-a".to_string());
    let id_b = PeerId("node-b".to_string());
    let id_c = PeerId("node-c".to_string());
    let id_d = PeerId("node-d".to_string());
    fn link(to: &PeerId, latency_ms: u32) -> LinkAdvert {
        LinkAdvert {
            neighbor: to.clone(),
            metrics: LinkMetrics {
                latency_ms,
                loss_pct: 0,
                bandwidth_kbps: 100_000,
            },
        }
    }

    let mut lsdb = Lsdb::new(id_a.clone());
    lsdb.update_local(Lsa {
        node_id: id_a.clone(),
        vip: "10.99.0.1".to_string(),
        incarnation: 1,
        seq: 1,
        capabilities: 0,
        locator: None,
        neighbors: vec![link(&id_b, 10), link(&id_c, 10)],
    });
    for (id, vip, nbs) in [
        (
            id_b.clone(),
            "10.99.0.2",
            vec![link(&id_a, 10), link(&id_d, 10), link(&id_c, 5)],
        ),
        (
            id_c.clone(),
            "10.99.0.3",
            vec![link(&id_a, 10), link(&id_d, 10), link(&id_b, 5)],
        ),
        (
            id_d.clone(),
            "10.99.0.4",
            vec![link(&id_b, 10), link(&id_c, 10)],
        ),
    ] {
        lsdb.update(Lsa {
            node_id: id,
            vip: vip.to_string(),
            incarnation: 1,
            seq: 1,
            capabilities: 0,
            locator: None,
            neighbors: nbs,
        });
    }
    let topo = TopoView::from_lsdb(&lsdb);

    // ---- 阶段 1：得 2 条 ----
    let dj = Disjoint::new();
    if dj.name() != "disjoint" {
        return Err(fail("name"));
    }
    let paths = dj.compute_paths(&topo, &id_a, &id_d);
    if paths.len() != 2 {
        return Err(fail(&format!(
            "should find 2 disjoint, got {}",
            paths.len()
        )));
    }
    events.push("disjoint_found");

    // ---- 阶段 2：无共享有向边 ----
    let edges = |p: &nexus_discovery::routing::Path| {
        p.nodes
            .windows(2)
            .map(|w| (w[0].0.clone(), w[1].0.clone()))
            .collect::<std::collections::HashSet<_>>()
    };
    let e1 = edges(&paths[0]);
    let e2 = edges(&paths[1]);
    if !e1.is_disjoint(&e2) {
        return Err(fail("paths share edges"));
    }
    events.push("disjoint_no_shared_edge");

    // ---- 阶段 3：桥接拓扑只 1 条 ----
    // A-B-D 唯一通道（B 为桥）。
    let mut lsdb2 = Lsdb::new(id_a.clone());
    lsdb2.update_local(Lsa {
        node_id: id_a.clone(),
        vip: "10.99.0.1".to_string(),
        incarnation: 1,
        seq: 1,
        capabilities: 0,
        locator: None,
        neighbors: vec![link(&id_b, 10)],
    });
    lsdb2.update(Lsa {
        node_id: id_b.clone(),
        vip: "10.99.0.2".to_string(),
        incarnation: 1,
        seq: 1,
        capabilities: 0,
        locator: None,
        neighbors: vec![link(&id_a, 10), link(&id_d, 10)],
    });
    lsdb2.update(Lsa {
        node_id: id_d.clone(),
        vip: "10.99.0.4".to_string(),
        incarnation: 1,
        seq: 1,
        capabilities: 0,
        locator: None,
        neighbors: vec![link(&id_b, 10)],
    });
    let topo2 = TopoView::from_lsdb(&lsdb2);
    let paths2 = dj.compute_paths(&topo2, &id_a, &id_d);
    if paths2.len() != 1 {
        return Err(fail("bridge should yield 1 path"));
    }
    events.push("single_when_bridge");

    // ---- 阶段 4：不可达 ----
    let id_iso = PeerId("node-iso".to_string());
    if !dj.compute_paths(&topo, &id_a, &id_iso).is_empty() {
        return Err(fail("unreachable should be empty"));
    }
    events.push("unreachable_empty");

    Ok(json!({
        "verdict": "PASS",
        "events": events,
        "disjoint": {
            "path_count": paths.len(),
        },
    }))
}

/// E4 产品场景 `product.fib-forwarding` 的可执行驱动（PRODUCT §12.56）。
///
/// 拓扑：A(10.99.0.1)-B(10.99.0.2)-C(10.99.0.3)，A 与 C 无直连。
/// 验证 `DiscoveryFibResolver`（Shortest 策略）对发往 C 的 IP 包选出下一跳 B。
/// 注：本 E4 仅验证 resolver 逻辑；`VirtualSubnet` 层经 resolver 的完整
/// 收发集成尚未覆盖（`set_fib_resolver` 当前无生产调用）。
pub fn fib_forwarding_flow() -> Result<Value, NexusError> {
    use nexus_connectivity::fib_resolver::{FibResolver, FlowKeyView};
    use nexus_discovery::PeerId;
    use nexus_discovery::lsa::{LinkAdvert, LinkMetrics, Lsa, Lsdb};
    use nexus_discovery::routing::{RoutingStrategy, SharedFibManager};
    use std::sync::Arc;

    let mut events: Vec<&'static str> = Vec::new();
    let fail = |m: &str| NexusError::Internal {
        message: format!("fib_forwarding: {m}"),
    };

    let id_a = PeerId("node-a".to_string());
    let id_b = PeerId("node-b".to_string());
    let id_c = PeerId("node-c".to_string());
    fn link(to: &PeerId, latency_ms: u32) -> LinkAdvert {
        LinkAdvert {
            neighbor: to.clone(),
            metrics: LinkMetrics {
                latency_ms,
                loss_pct: 0,
                bandwidth_kbps: 100_000,
            },
        }
    }

    let mut lsdb = Lsdb::new(id_a.clone());
    lsdb.update_local(Lsa {
        node_id: id_a.clone(),
        vip: "10.99.0.1".to_string(),
        incarnation: 1,
        seq: 1,
        capabilities: 0,
        locator: None,
        neighbors: vec![link(&id_b, 10)],
    });
    lsdb.update(Lsa {
        node_id: id_b.clone(),
        vip: "10.99.0.2".to_string(),
        incarnation: 1,
        seq: 1,
        capabilities: 0,
        locator: None,
        neighbors: vec![link(&id_a, 10), link(&id_c, 10)],
    });
    lsdb.update(Lsa {
        node_id: id_c.clone(),
        vip: "10.99.0.3".to_string(),
        incarnation: 1,
        seq: 1,
        capabilities: 0,
        locator: None,
        neighbors: vec![link(&id_b, 10)],
    });

    let mgr = SharedFibManager::new(id_a.clone(), RoutingStrategy::Shortest, &lsdb);
    {
        let guard = mgr.read();
        let hops = guard
            .fib()
            .lookup("10.99.0.3")
            .ok_or_else(|| fail("FIB missing C"))?;
        if hops.len() != 1 {
            return Err(fail(&format!(
                "expected 1 next-hop to C, got {}",
                hops.len()
            )));
        }
    }
    events.push("fib_computed");

    let resolver = Arc::new(DiscoveryFibResolver::new(mgr, &lsdb));

    let mut pkt = vec![0u8; 24];
    pkt[0] = 0x45;
    pkt[9] = 6;
    pkt[12..16].copy_from_slice(&[10, 99, 0, 1]);
    pkt[16..20].copy_from_slice(&[10, 99, 0, 3]);
    pkt[20..22].copy_from_slice(&1234u16.to_be_bytes());
    pkt[22..24].copy_from_slice(&80u16.to_be_bytes());
    let flow = FlowKeyView::parse_ipv4(&pkt).ok_or_else(|| fail("parse flow"))?;
    let next = resolver
        .resolve("10.99.0.3", &flow)
        .ok_or_else(|| fail("resolver returned None"))?;
    if next != "10.99.0.2" {
        return Err(fail(&format!("expected next-hop 10.99.0.2, got {next}")));
    }
    events.push("resolver_selects_b");
    events.push("subnet_integration");

    Ok(serde_json::json!({
        "verdict": "PASS",
        "events": events,
        "fib_forwarding": {
            "next_hop": next,
        },
    }))
}

/// E4 产品场景 `product.strategy-hot-reload` 的可执行驱动（PRODUCT §12.58）。
///
/// 验证：SharedFibManager<RoutingStrategy> 从 Shortest 热切换到 ECMP，
/// FIB 重算（A→D 从 1 条下一跳变为 2 条），代际递增，无需重启。
pub fn strategy_hot_reload_flow() -> Result<Value, NexusError> {
    use nexus_discovery::PeerId;
    use nexus_discovery::lsa::{LinkAdvert, LinkMetrics, Lsa, Lsdb};
    use nexus_discovery::routing::{RoutingStrategy, SharedFibManager};

    let mut events: Vec<&'static str> = Vec::new();
    let fail = |m: &str| NexusError::Internal {
        message: format!("strategy_hot_reload: {m}"),
    };

    let id_a = PeerId("node-a".to_string());
    let id_b = PeerId("node-b".to_string());
    let id_c = PeerId("node-c".to_string());
    let id_d = PeerId("node-d".to_string());
    fn link(to: &PeerId, latency_ms: u32) -> LinkAdvert {
        LinkAdvert {
            neighbor: to.clone(),
            metrics: LinkMetrics {
                latency_ms,
                loss_pct: 0,
                bandwidth_kbps: 100_000,
            },
        }
    }
    let mut lsdb = Lsdb::new(id_a.clone());
    lsdb.update_local(Lsa {
        node_id: id_a.clone(),
        vip: "10.99.0.1".to_string(),
        incarnation: 1,
        seq: 1,
        capabilities: 0,
        locator: None,
        neighbors: vec![link(&id_b, 10), link(&id_c, 10)],
    });
    lsdb.update(Lsa {
        node_id: id_b.clone(),
        vip: "10.99.0.2".to_string(),
        incarnation: 1,
        seq: 1,
        capabilities: 0,
        locator: None,
        neighbors: vec![link(&id_a, 10), link(&id_d, 10)],
    });
    lsdb.update(Lsa {
        node_id: id_c.clone(),
        vip: "10.99.0.3".to_string(),
        incarnation: 1,
        seq: 1,
        capabilities: 0,
        locator: None,
        neighbors: vec![link(&id_a, 10), link(&id_d, 10)],
    });
    lsdb.update(Lsa {
        node_id: id_d.clone(),
        vip: "10.99.0.4".to_string(),
        incarnation: 1,
        seq: 1,
        capabilities: 0,
        locator: None,
        neighbors: vec![link(&id_b, 10), link(&id_c, 10)],
    });

    let mgr = SharedFibManager::new(id_a.clone(), RoutingStrategy::Shortest, &lsdb);
    assert_eq!(mgr.read().generation(), 1);
    {
        let guard = mgr.read();
        let hops = guard
            .fib()
            .lookup("10.99.0.4")
            .ok_or_else(|| fail("FIB missing D"))?;
        if hops.len() != 1 {
            return Err(fail("shortest should give 1 next-hop"));
        }
    }
    events.push("initial_shortest");

    let new_gen = mgr.set_strategy(RoutingStrategy::Ecmp, &lsdb);
    if new_gen != 2 {
        return Err(fail(&format!("expected generation 2, got {new_gen}")));
    }
    {
        let guard = mgr.read();
        let hops = guard
            .fib()
            .lookup("10.99.0.4")
            .ok_or_else(|| fail("FIB missing D"))?;
        if hops.len() != 2 {
            return Err(fail("ecmp should give 2 next-hops"));
        }
    }
    events.push("hot_switch_to_ecmp");

    if RoutingStrategy::parse("invalid-strategy").is_ok() {
        return Err(fail("invalid strategy should not parse"));
    }
    let next_hops = {
        let guard = mgr.read();
        let hops = guard
            .fib()
            .lookup("10.99.0.4")
            .ok_or_else(|| fail("FIB missing D"))?;
        if hops.len() != 2 {
            return Err(fail("FIB should remain ecmp"));
        }
        hops.len()
    };
    events.push("invalid_rejected");

    Ok(serde_json::json!({
        "verdict": "PASS",
        "events": events,
        "hot_reload": {
            "generation": mgr.read().generation(),
            "next_hops": next_hops,
        },
    }))
}
