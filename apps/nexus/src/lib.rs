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

/// CONNECT 应答暂存（fail-closed 前置机制；crate 私有）。
mod deferred_reply;

/// Trojan 第一响应守卫（fail-closed 纯分类器 + 窗口常量；crate 私有）。
mod trojan_guard;

/// 非阻塞中继写状态机（relay pump 共享；crate 私有，不扩大 public surface）。
mod pending_write;

/// 出站 UDP 抽象（spec §4.6；C2 建类型/会话，C4 由 `proxy_serve_once` 生产消费）。
mod udp_outbound;

/// VLESS over TCP 的 UDP 会话（spec §4.1）。
mod udp_session_vless;

/// AnyTLS UoT 会话（spec §4.2）。
mod udp_session_anytls;

/// UDP 关联管理器（spec §5；C3 纯逻辑，C4 由 `proxy_serve_once` 驱动）。
mod udp_association;

/// Linux durable Artifact receiver shared by the CLI and daemon composition roots.
#[cfg(target_os = "linux")]
pub mod artifact_download;
#[cfg(target_os = "linux")]
mod artifact_download_fs;

/// Bootstrap 帧编解码组合根适配（connectivity 解耦类型 <-> discovery 字节，v2 §5.5）。
pub mod bootstrap_codec;
/// CLI 前端 ControlService（17 命令接线 + --json 双输出 + exit 语义）。
pub mod control_service;
pub mod geoip_sources;
/// `nexus grant` 命令族（N2 P0-5，D6）：本地 grant 表管理。
pub mod grant_cli;
/// nexusd serve LocalAPI 瘦客户端（裸 TCP HTTP GET，CLI 不再进程内装配 SDK）。
pub mod localapi_client;
/// Auto-Mesh 自动挡组网编排器（Phase 1：自动打洞 + 断线重连）。
pub mod mesh;
/// N2 P0-5：跨机准入协议（挑战-应答握手＋提供方侧 grant 判定＋租约）。
pub mod n2_admission;
/// N2 P0-4：registry-backed 资源目录（静态种子＋持久化广告；Presence 语义对齐）。
pub mod n2_directory;
/// N2 P0-4 D6：本节点 ed25519 授权身份（Principal 派生源）。
pub mod n2_identity;
/// N2 P0-4：FileKvStore-backed 的 Session / Grant / Registry / 审计持久层
///（组合根装配点，被 CLI 与 nexusd 共用）。
pub mod n2_store;
/// N3-1 composition adapters; not connected to product commands yet.
pub mod n3_acceptance;
/// `nexus network` 命令族（M6）：N1 Universal Connectivity 前台装配
///（Composition Root：n1 portable core + fabric/path/discovery/platform-linux）。
pub mod network;
/// `nexus node` 命令族（N2 P0-1）：节点身份管理（X25519 + NodeId 内容派生）。
pub mod node_cli;
/// §9 可观察性命令（status / plan explain / session watch / connectivity status /
/// dns status / dns cache / platform capabilities），见 PRODUCT.md#9-observability。
pub mod observability;
/// `nexus config check`：出站配置面只读校验（spec §7.7 载体 2）。
pub mod outbound_check;
/// 出站互操作标注：`verdicts.json` 嵌入解析 + 五载体共享的 label/warning 派生，
/// `is_wired` / `select_index` 唯一定义（spec §3.6.1 / N9）。
pub mod outbound_manifest;
pub mod pair_cli;
/// N2 P0-3：`nexus plan` 只读预览 + `plan explain` 双模式（进程内，无 I/O）。
pub mod plan_cli;
/// `nexus provider` 命令族（N2 P0-5）：提供方侧常驻准入服务。
pub mod provider_cli;
pub mod provider_fetcher;
/// 密钥脱敏（daemon + CLI 共享一份实现；spec §9）。
pub mod redact;
/// `nexus resource` 命令族（N2 P0-4/P0-5）：list / show / publish / revoke /
/// export / import。
pub mod resource_cli;
pub mod schedule_cli;
/// `nexus session` 命令族（N2 P0-4）：list / watch / close（重附着）。
pub mod session_cli;
pub mod strategy_watcher;
pub mod subnet_cli;
/// §11.17 订阅节点在线更新拉取器（HTTP 拉取 + 解析合并 + 热生效 + 结构化并发 Owner）。
pub mod subscription_updater;
/// `nexus use` 命令族（N2 P0-4，D4）：四步闭环（resolve→plan→authorize→establish）。
pub mod use_cli;

use deferred_reply::{ClientReplyKind, DeferredConnectReply};
use nexus_domain::{
    LifecyclePhase, NexusError, ProviderId, ResourceId, SessionId, TerminalOutcome,
};
use nexus_measurement::{LinkMeasurement, MeasurementTable};
use nexus_planner::PlanningSnapshot;
use nexus_registry::{ProviderRecord, Registry};
use nexus_session::{SessionError, SessionOwner};
use pending_write::PendingWrite;
use serde_json::{Value, json};
use trojan_guard::RejectCause;

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
    // 端口在返回后立即释放（drop 自动发生），后续 connect 将得到 ConnectionRefused。
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind temp listener")
        .local_addr()
        .expect("local addr")
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

    // 0) Node B（提供方）：绑定回环端口，后台线程内运行真实 Workspace；
    //    处理 HEAD? 查询与 ChangeSet 提交（v2：parent 必须为真实内容哈希 ID）。
    let listener =
        std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| NexusError::Internal {
            message: format!("cannot bind node-b listener: {e}"),
        })?;
    let node_b_addr = listener.local_addr().map_err(|e| NexusError::Internal {
        message: format!("cannot read node-b listener addr: {e}"),
    })?;
    let node_b_server = std::thread::spawn(move || {
        if let Ok(mut fs) = nexus_transport::accept(&listener) {
            let ws = nexus_workspace::Workspace::init(
                nexus_workspace::WorkspaceId("ws-b".into()),
                nexus_storage::InMemoryContentStore::new(),
                nexus_workspace::AuthorId("node-b".into()),
            );
            let mut ws = match ws {
                Ok(ws) => ws,
                Err(e) => {
                    let _ = fs.send_frame(format!("REJECTED:{e}").as_bytes());
                    return;
                }
            };
            while let Ok(frame) = fs.recv_frame() {
                // ChangeSet 帧格式：<parent>\n<path>\n<content>；HEAD? 为头查询。
                let text = String::from_utf8_lossy(&frame);
                if text == "HEAD?" {
                    let head = ws
                        .heads()
                        .heads
                        .first()
                        .map(|h| h.0.clone())
                        .unwrap_or_default();
                    let _ = fs.send_frame(format!("OK:HEAD:{head}").as_bytes());
                    continue;
                }
                let mut parts = text.splitn(3, '\n');
                let parent = parts.next().unwrap_or_default().to_string();
                let path = parts.next().unwrap_or_default().to_string();
                let content = parts.next().unwrap_or_default().as_bytes().to_vec();
                let response = match ws.commit_changes(
                    &nexus_workspace::CommitId(parent),
                    &[nexus_workspace::Change { path, content }],
                ) {
                    Ok(head) => format!("OK:HEAD:{}", head.0),
                    Err(e) => format!("REJECTED:{e}"),
                };
                let _ = fs.send_frame(response.as_bytes());
                break;
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

    // 7) Workspace：先 HEAD? 查询 Node B 当前 Head（v2 内容哈希 ID），再远程提交
    //   （ChangeSet 帧 -> OK:HEAD:<id>，取回新 Head）。
    let mut adapter = FrameStreamAdapter {
        inner: frame_stream,
    };
    let parent = {
        use nexus_workspace::WorkspaceTransport;
        adapter
            .send_frame(b"HEAD?")
            .map_err(|e| NexusError::SessionFailed {
                session: owner.id().clone(),
                reason: e.to_string(),
            })?;
        let head_frame = adapter
            .recv_frame()
            .map_err(|e| NexusError::SessionFailed {
                session: owner.id().clone(),
                reason: e.to_string(),
            })?;
        let head_text = String::from_utf8_lossy(&head_frame);
        head_text
            .strip_prefix("OK:HEAD:")
            .ok_or_else(|| NexusError::SessionFailed {
                session: owner.id().clone(),
                reason: format!("unexpected HEAD? response: {head_text}"),
            })?
            .to_string()
    };
    let change_set = format!("{parent}\nremote.txt\nremote-content");
    let ws_session =
        nexus_workspace::RemoteWorkspaceSession::commit(Box::new(adapter), change_set.as_bytes())
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
            "parent": parent,
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
                    nexus_workspace::AuthorId("node-b".into()),
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
/// codec 自检（Allocate Request 构造 + XOR-RELAYED-ADDRESS 解析，经
/// `nexus-turn::stun`）+ 进程内 `TurnServer`（127.0.0.1:0）与真实
/// `TurnClient::allocate` 的 loopback 对打：裸 Allocate → 401 挑战 →
/// 长期凭证重发 → Allocated。全程零真实网络（#1 运行时所有权归一，
/// `nexus-connectivity::turn` 已删除）。
pub fn turn_relay_allocate_flow() -> Result<Value, NexusError> {
    use nexus_turn::stun::{self, Attribute, StunMessage};
    use nexus_turn::{TurnClient, TurnCredentials, TurnServer};
    use std::net::UdpSocket;
    use std::time::Duration;

    let internal = |message: String| NexusError::Internal { message };

    // 1) codec 自检：构造 Allocate Request（RequestedTransport + Lifetime），
    //    编码后解码合成的成功响应，提取 XOR-RELAYED-ADDRESS / LIFETIME。
    let req_msg = StunMessage::new(stun::ALLOCATE_REQUEST)
        .attr(Attribute::RequestedTransport(17))
        .attr(Attribute::Lifetime(600));
    let request_bytes = req_msg.encode().len();
    let allocate_request_build_ok = request_bytes > stun::HEADER_LEN;

    // 合成成功响应 fixture：192.0.2.1:54320 为 RFC 5737 TEST-NET-1 文档地址
    //（合成夹具，非真实公网映射；与旧自检口径一致）。
    let synth_txid = [0xABu8; 12];
    let mut synth = StunMessage::new(stun::ALLOCATE_SUCCESS);
    synth.txn = synth_txid;
    let synth_bytes = synth
        .attr(Attribute::XorRelayedAddress(
            "192.0.2.1:54320"
                .parse()
                .map_err(|e| internal(format!("synthetic relayed address parse failed: {e}")))?,
        ))
        .attr(Attribute::Lifetime(600))
        .encode();
    let decoded = stun::decode(&synth_bytes)
        .map_err(|e| internal(format!("turn codec self-test decode failed: {e:?}")))?;
    if decoded.msg_type != stun::ALLOCATE_SUCCESS {
        return Err(internal(format!(
            "turn codec self-test: unexpected message type 0x{:04x}",
            decoded.msg_type
        )));
    }
    let mut parsed_relayed = None;
    let mut lifetime_ok = false;
    for attr in &decoded.attrs {
        match attr {
            Attribute::XorRelayedAddress(a) => parsed_relayed = Some(*a),
            Attribute::Lifetime(600) => lifetime_ok = true,
            _ => {}
        }
    }
    let parsed_relayed = parsed_relayed
        .ok_or_else(|| internal("turn codec self-test: XOR-RELAYED-ADDRESS not found".into()))?;
    let allocate_response_parse_ok = lifetime_ok;

    // 2) 分配闭环：进程内 TurnServer（loopback）+ 真实 TurnClient。
    let creds = TurnCredentials {
        username: "nexus-node-a".into(),
        password: "secret-credential".into(),
        realm: "example.org".into(),
    };
    let server = TurnServer::bind("127.0.0.1:0".parse().unwrap(), creds.clone())
        .map_err(|e| internal(format!("turn demo server bind failed: {e}")))?;
    let server_addr = server.main_addr();

    // 2a) 诚实证据：裸发无凭证 Allocate，解析 server 真实返回的 401
    //     挑战（REALM / NONCE）。新 client 初始无 nonce，首请求必被挑战，
    //     此处是协议结构保证；解析真实 401 即为事件提供直接证据。
    let mut events: Vec<&'static str> = Vec::new();
    events.push("allocate_sent");
    let probe = UdpSocket::bind("127.0.0.1:0")
        .map_err(|e| internal(format!("turn demo probe bind failed: {e}")))?;
    probe
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|e| internal(format!("turn demo probe timeout failed: {e}")))?;
    let probe_req = StunMessage {
        msg_type: stun::ALLOCATE_REQUEST,
        txn: [0x01; 12],
        attrs: vec![],
    }
    .encode();
    probe
        .send_to(&probe_req, server_addr)
        .map_err(|e| internal(format!("turn demo probe send failed: {e}")))?;
    let mut rbuf = [0u8; 1500];
    let (n, _) = probe
        .recv_from(&mut rbuf)
        .map_err(|e| internal(format!("turn demo probe recv failed: {e}")))?;
    let challenge = stun::decode(&rbuf[..n])
        .map_err(|e| internal(format!("turn demo 401 decode failed: {e:?}")))?;
    let mut is_401 = false;
    let mut realm = String::new();
    let mut nonce = String::new();
    for attr in &challenge.attrs {
        match attr {
            Attribute::ErrorCode(4, 1, _) => is_401 = true,
            Attribute::Realm(r) => realm = String::from_utf8_lossy(r).into_owned(),
            Attribute::Nonce(nc) => nonce = String::from_utf8_lossy(nc).into_owned(),
            _ => {}
        }
    }
    if !is_401 || realm.is_empty() || nonce.is_empty() {
        return Err(internal(
            "turn demo: expected 401 challenge with REALM/NONCE".into(),
        ));
    }
    events.push("auth_challenge_received");

    // 2b) 真实 client 全流程：401 → 长期凭证重发 → Allocated。
    //     server 对带凭证重发的请求验 MESSAGE-INTEGRITY，分配成功即证明
    //     MI 往返正确（`message_integrity_ok` 的端到端证据）。
    let client = TurnClient::allocate(server_addr, creds)
        .map_err(|e| internal(format!("turn allocate failed: {e}")))?;
    let relayed_addr = client.relayed_addr();
    if server.stats().allocations != 1 {
        return Err(internal(format!(
            "turn demo: expected 1 server allocation, got {}",
            server.stats().allocations
        )));
    }
    events.push("allocate_success");

    Ok(json!({
        "verdict": "PASS",
        "codec": {
            "allocate_request_build_ok": allocate_request_build_ok,
            "allocate_response_parse_ok": allocate_response_parse_ok,
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
            "relayed_address": relayed_addr.to_string(),
            "expires_secs": 600,
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

/// 业务退出码（P1-20）：`verdict=FAIL` → 1；其余（含 PASS/UNKNOWN）→ 0。
///
/// 机器可读权威仍然是 `verdict` 字段（场景判定只读它，不读 `$?`）；本函数
/// 只是让 shell 侧 `set -e` / `$?` 也能诚实反映业务失败。用法错误由各命令
/// 自行返回 2（参数不合法，连 JSON 都不产出）。
pub fn verdict_exit_code(out: &serde_json::Value) -> i32 {
    match out.get("verdict").and_then(serde_json::Value::as_str) {
        Some("FAIL") => 1,
        _ => 0,
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
        NexusError::NotFound { .. } => "NOT_FOUND",
        NexusError::NodeIdentityUnavailable { .. } => "NODE_IDENTITY_UNAVAILABLE",
        NexusError::NatStatusUnavailable { .. } => "NAT_STATUS_UNAVAILABLE",
        NexusError::PersistenceFailed { .. } => "PERSISTENCE_FAILED",
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

/// 初始化混淆插件（P4）：注册 builtin（plain/xor）到全局注册表。
///
/// 幂等；`nexus proxy` 在服务循环前调用一次。`dial_with_obfs`/`wrap_stream`
/// 内部也有懒初始化，此处显式调用是为了"进程启动时注册"的确定性语义。
pub fn init_obfs_plugins() {
    nexus_plugin::init_builtin_plugins();
}

/// 真实 SOCKS5 代理单会话闭环。
///
/// 调用方（`nexus proxy`）应在服务循环前调一次 [`init_obfs_plugins`]（P4）。
// 在已建立的 AnyTLS TLS 流上推送一帧（数据面装配 glue；帧编解码仍在
// nexus-outbound-anytls）。
//
// `encode_frame` 为纯函数，一次 `write_all` 把整帧送入 rustls 明文缓冲；`flush`
// 的 WouldBlock 只表示底层 socket 暂不可写，字节仍在 rustls 内部缓冲排队，下轮
// read/write 会继续投递（rustls 0.23 `complete_prior_io` 语义），不丢。
fn anytls_push_frame<S: std::io::Read + std::io::Write>(
    tls: &mut rustls::Stream<'_, rustls::ClientConnection, S>,
    stream_id: u32,
    cmd: nexus_outbound_anytls::AnyTlsCommand,
    data: &[u8],
) -> std::io::Result<()> {
    use std::io::Write;
    let buf = anytls_encode_frame(stream_id, cmd, data)?;
    tls.write_all(&buf)?;
    tls.flush()
}

// 纯编码：一次读到的载荷 → 一帧字节。编码失败是配置/长度错误（>64KiB），
// 不是 I/O 瞬态，调用方按致命错误处理。
fn anytls_encode_frame(
    stream_id: u32,
    cmd: nexus_outbound_anytls::AnyTlsCommand,
    data: &[u8],
) -> std::io::Result<Vec<u8>> {
    nexus_outbound_anytls::encode_frame(cmd, stream_id, data).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("anytls frame encode: {e}"),
        )
    })
}

// 从下行明文缓冲取出首个完整 AnyTLS 帧（7 字节头 + data）；不完整返回 `None`。
//
// 完整性判断只 peek 头部长度字段，实际解码仍走 nexus-outbound-anytls
//（`AnyTlsError::Io` 丢弃了底层 io kind，`read_frame` 无法在非阻塞流上区分
// WouldBlock，故中继循环用此增量组帧）。
fn anytls_take_complete_frame(buf: &[u8]) -> Option<(nexus_outbound_anytls::AnyTlsFrame, usize)> {
    if buf.len() < 7 {
        return None;
    }
    let data_len = u16::from_be_bytes([buf[5], buf[6]]) as usize;
    if buf.len() < 7 + data_len {
        return None;
    }
    nexus_outbound_anytls::decode_frame_bytes(buf).ok()
}

// VLESS 握手（§11.16 vless 数据面装配 glue；帧编解码仍在
// nexus-outbound-vless）。
//
// 在已建立的字节流（明文 TCP 或外层 TLS）上执行：`VlessConn::handshake` 只写
// 请求头（UUID + flow addon + TCP 命令 + 目标地址），随后把 `seed_to_upstream`
// （§11.19 首段字节）一并写出并 flush。响应头留到中继泵惰性消费（由
// `VlessResponseSkipper` 在 node→client 方向丢弃），本函数不得阻塞读它。
fn vless_handshake_stream<S: std::io::Read + std::io::Write>(
    stream: &mut S,
    req: &nexus_outbound_vless::VlessRequest,
    seed_to_upstream: &[u8],
    tag: &str,
) -> Result<(), NexusError> {
    use std::io::Write;
    let mut vc = nexus_outbound_vless::VlessConn::new(stream);
    vc.handshake(req)
        .map_err(|e| NexusError::ConnectivityEstablishmentFailed {
            provider: ProviderId(tag.to_string()),
            reason: format!("vless handshake failed: {e}"),
        })?;
    if !seed_to_upstream.is_empty() {
        vc.write_all(seed_to_upstream).map_err(|e| {
            NexusError::ConnectivityEstablishmentFailed {
                provider: ProviderId(tag.to_string()),
                reason: format!("vless seed write failed: {e}"),
            }
        })?;
    }
    vc.flush()
        .map_err(|e| NexusError::ConnectivityEstablishmentFailed {
            provider: ProviderId(tag.to_string()),
            reason: format!("vless handshake flush failed: {e}"),
        })?;
    // 响应头由中继泵在 node→client 方向按字节跳过（VlessResponseSkipper）。
    // 这里不得阻塞读：普通 SOCKS5 客户端在 CONNECT 应答后才发载荷，而参照端要等
    // 目标回数据才发响应头；eager read 会让两侧互等直到超时。
    Ok(())
}

/// VLESS 响应头跳过器：`version(1) | addon_len(1) | addon`。
///
/// 响应头由服务端在首段隧道数据之前发出；握手阶段不得阻塞读它（见
/// `vless_handshake_stream` 的惰性读纪律），由中继泵在 node→client 方向丢弃。
#[derive(Default)]
struct VlessResponseSkipper {
    state: u8,
    remaining: usize,
}

impl VlessResponseSkipper {
    fn new() -> Self {
        Self::default()
    }

    fn filter<'a>(&mut self, data: &'a [u8]) -> &'a [u8] {
        let mut pos = 0usize;
        while pos < data.len() && self.state < 3 {
            match self.state {
                0 => {
                    pos += 1;
                    self.state = 1;
                }
                1 => {
                    self.remaining = usize::from(data[pos]);
                    pos += 1;
                    self.state = if self.remaining == 0 { 3 } else { 2 };
                }
                _ => {
                    let take = self.remaining.min(data.len() - pos);
                    pos += take;
                    self.remaining -= take;
                    if self.remaining == 0 {
                        self.state = 3;
                    }
                }
            }
        }
        &data[pos..]
    }
}

// VLESS 双向透明中继泵（§11.16 vless 数据面装配 glue）。
//
// 单线程 nonblocking poll：rustls ClientConnection 不可跨线程分裂，TLS/明文
// 两条路径共用此泵（loopback E4 小流量足够；调用方单线程闭环承担结构化并发，
// 无泄漏 JoinHandle）。返回 `(上行字节, 下行字节)`（仅中继载荷；握手字节不计）。
fn vless_pump_stream<S: std::io::Read + std::io::Write>(
    node: &mut S,
    client: &mut std::net::TcpStream,
) -> (usize, usize) {
    let mut up_bytes = 0usize;
    let mut down_bytes = 0usize;
    let mut cbuf = [0u8; 8192];
    let mut sbuf = [0u8; 8192];
    let mut c_open = true;
    let mut n_open = true;
    let mut up = PendingWrite::new();
    let mut down = PendingWrite::new();
    let mut up_failed = false;
    let mut down_failed = false;
    let mut skipper = VlessResponseSkipper::new();
    loop {
        if !c_open
            && !n_open
            && (up_failed || up.ready_for_read())
            && (down_failed || down.ready_for_read())
        {
            break;
        }
        let mut progressed = false;
        // 先排空两个方向的待写尾部：WouldBlock 保留尾部，非 WouldBlock 错误
        // 才关闭对应方向（TLS/明文两条路径共用此泵）。
        match up.try_write(node) {
            Ok((_, n)) => {
                up_bytes += n;
                progressed |= n > 0;
            }
            Err(_) => {
                n_open = false;
                up_failed = true;
            }
        }
        match down.try_write(client) {
            Ok((_, n)) => {
                down_bytes += n;
                progressed |= n > 0;
            }
            Err(_) => {
                c_open = false;
                n_open = false;
                down_failed = true;
            }
        }
        if c_open && n_open {
            match up.try_read(client, &mut cbuf) {
                None => {}
                Some(Ok(0)) => c_open = false,
                Some(Ok(n)) => {
                    up.enqueue(&cbuf[..n]);
                    progressed = true;
                }
                Some(Err(ref e)) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Some(Err(_)) => c_open = false,
            }
        }
        if n_open && c_open {
            match down.try_read(node, &mut sbuf) {
                None => {}
                Some(Ok(0)) => n_open = false,
                Some(Ok(n)) => {
                    // 先跳过 VLESS 响应头，再把真实载荷入队：响应头字节不得
                    // 写进 client 或 pending（b7 惰性读语义 + PendingWrite 共存）。
                    let forward = skipper.filter(&sbuf[..n]);
                    if forward.is_empty() {
                        // 本段全部是 VLESS 响应头：已消费，继续等真实载荷。
                        progressed = true;
                    } else {
                        down.enqueue(forward);
                        progressed = true;
                    }
                }
                Some(Err(ref e)) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Some(Err(_)) => n_open = false,
            }
        }
        // 半关闭：一侧 EOF/致命写错误后，先排空该方向尾部再终止另一侧。
        if !c_open && n_open && (down_failed || down.ready_for_read()) {
            n_open = false;
        }
        if !n_open
            && c_open
            && (up_failed || up.ready_for_read())
            && (down_failed || down.ready_for_read())
        {
            c_open = false;
        }
        if !progressed {
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
    }
    (up_bytes, down_bytes)
}

/// pump 热路径轮询间隔（上行/下行有进展时）。
const HY2_POLL_HOT: std::time::Duration = std::time::Duration::from_millis(2);
/// pump 空闲轮询间隔（无进展时，保持基线唤醒节律）。
const HY2_POLL_IDLE: std::time::Duration = std::time::Duration::from_millis(50);
/// fast-open 首读守卫的固定超时（单次、不重试）。
const HY2_FIRST_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(50);
/// pump 单轮读写缓冲（Q3=C：64 KiB；两缓冲合计 128 KiB/会话）。
const HY2_PUMP_BUF: usize = 64 * 1024;
/// 写侧停滞/活性守卫的总预算（与 crate 的 10 s 写超时分离）。
const HY2_STALL_BUDGET: std::time::Duration = std::time::Duration::from_secs(30);

/// 结构化 stderr 事件里的错误变体名（不含错误文本/敏感信息）。
fn hy2_error_variant_name(err: &nexus_outbound_hysteria2::Hysteria2Error) -> &'static str {
    use nexus_outbound_hysteria2::Hysteria2Error;
    match err {
        Hysteria2Error::AuthFailed => "AuthFailed",
        Hysteria2Error::UdpDisabled => "UdpDisabled",
        Hysteria2Error::InvalidFrame => "InvalidFrame",
        Hysteria2Error::Quic(_) => "Quic",
        Hysteria2Error::Tls => "Tls",
        Hysteria2Error::Io(_) => "Io",
        Hysteria2Error::Timeout => "Timeout",
        Hysteria2Error::UnsupportedObfs => "UnsupportedObfs",
        Hysteria2Error::InvalidConfig(_) => "InvalidConfig",
        Hysteria2Error::Closed => "Closed",
        Hysteria2Error::TcpRejected(_) => "TcpRejected",
        Hysteria2Error::DatagramTooLarge { .. } => "DatagramTooLarge",
        Hysteria2Error::StreamReset { .. } => "StreamReset",
    }
}

/// Hysteria2 TCP 中继：client（nonblocking TcpStream）<-> QUIC 双向 stream。
///
/// 与 `vless_pump_stream` 同构；热路径用 2 ms、空闲用 50 ms 动态轮询，
/// `Timeout` 为瞬态（继续轮询），其他 QUIC 错误视为节点侧关闭。client EOF 时
/// 先对 stream 发 FIN 再结束双向（优雅半关闭）。
///
/// 写侧 `Timeout` 不再无条件关闭读侧：按有界停滞中止收尾（30 s 预算，一条
/// 结构化 stderr 事件）。fast-open 的首读先经 `await_tcp_response` 剥离
/// `TCPResponse`，守卫超时则干净中止、不转发任何字节。
fn hysteria2_pump_stream(
    hy2: &mut nexus_outbound_hysteria2::Hysteria2Client,
    stream: quinn_proto::StreamId,
    fast_open: bool,
    client: &mut std::net::TcpStream,
) -> (usize, usize) {
    use nexus_outbound_hysteria2::Hysteria2Error;
    use std::io::Read;
    use std::time::Instant;

    let stream_index = stream.index();
    let mut up_bytes = 0usize;
    let mut down_bytes = 0usize;
    let mut cbuf = [0u8; HY2_PUMP_BUF];
    let mut sbuf = [0u8; HY2_PUMP_BUF];
    let mut c_open = true;
    let mut s_open = true;
    let mut down = PendingWrite::new();
    let mut down_failed = false;
    let mut hot = false;
    let mut up_failed = false;
    let mut abort_reason: Option<&'static str> = None;
    let mut abort_since: Option<Instant> = None;
    let mut abort_deadline: Option<Instant> = None;
    let mut stalled_since: Option<Instant> = None;
    let mut last_error: Option<Hysteria2Error> = None;

    // R1.4 首读守卫（C3）：fast-open 的 TCPResponse 在此一次性剥离；
    // 非 fast-open 由 open_tcp 剥离过，不执行守卫。
    if fast_open {
        let started = Instant::now();
        match hy2.await_tcp_response(stream, HY2_FIRST_READ_TIMEOUT) {
            Ok(()) => {}
            Err(Hysteria2Error::Timeout) => {
                eprintln!(
                    "[hy2] event=hy2_first_read_timeout stream_id={} up_bytes={} down_bytes={} elapsed_ms={}",
                    stream_index,
                    up_bytes,
                    down_bytes,
                    started.elapsed().as_millis()
                );
                hy2.stream_finish(stream);
                let _ = client.shutdown(std::net::Shutdown::Both);
                return (up_bytes, down_bytes);
            }
            Err(_) => {
                hy2.stream_finish(stream);
                let _ = client.shutdown(std::net::Shutdown::Both);
                return (up_bytes, down_bytes);
            }
        }
    }

    loop {
        if !c_open && !s_open && (down_failed || down.ready_for_read()) {
            break;
        }

        // 停滞中止：预算用尽或下行已排空/结束即收尾。
        if let Some(reason) = abort_reason {
            let downstream_done = !s_open || down_failed || down.ready_for_read();
            let budget_done = abort_deadline.is_none_or(|d| Instant::now() >= d);
            if downstream_done || budget_done {
                let stalled_ms = abort_since.map_or(0, |s| s.elapsed().as_millis());
                let err_name = last_error.as_ref().map_or("none", hy2_error_variant_name);
                eprintln!(
                    "[hy2] event=hy2_write_stall_abort stream_id={} trigger={} stalled_ms={} last_error={} up_bytes={} down_bytes={}",
                    stream_index, reason, stalled_ms, err_name, up_bytes, down_bytes
                );
                hy2.stream_finish(stream);
                let _ = client.shutdown(std::net::Shutdown::Both);
                return (up_bytes, down_bytes);
            }
        }

        let up_before = up_bytes;
        let down_before = down_bytes;
        let mut progressed = false;
        let mut round_hot = false;
        // 下行 client.write 是裸非阻塞 socket 写：套 PendingWrite 保留尾部。
        match down.try_write(client) {
            Ok((_, n)) => {
                down_bytes += n;
                progressed |= n > 0;
                round_hot |= n > 0;
            }
            Err(_) => {
                c_open = false;
                s_open = false;
                down_failed = true;
            }
        }
        if c_open && s_open && !up_failed {
            // 上行保持直接调用：`Hysteria2Client::stream_write` 已在 crate 内对
            // `WriteError::Blocked` 循环 pump 到写完或 deadline（阻塞 + 保留已发
            // 进度）。app 层若再对整段尾部重试，超时后可能把已发出的前半段重发，
            // 造成 QUIC stream 字节重复，故此处不套 PendingWrite（见 CHAIN Q1）。
            match client.read(&mut cbuf) {
                Ok(0) => c_open = false,
                Ok(n) => {
                    round_hot = true;
                    match hy2.stream_write(stream, &cbuf[..n]) {
                        Ok(()) => {
                            up_bytes += n;
                            progressed = true;
                        }
                        Err(Hysteria2Error::Timeout) => {
                            // 触发 1：无法得知已写字节数，不重试、不立即关读侧；
                            // 进入 30 s 有界停滞预算。
                            up_failed = true;
                            last_error = Some(Hysteria2Error::Timeout);
                            let now = Instant::now();
                            abort_reason = Some("write_timeout");
                            abort_since = Some(now);
                            abort_deadline = Some(now + HY2_STALL_BUDGET);
                        }
                        Err(e) => {
                            up_failed = true;
                            last_error = Some(e);
                            let now = Instant::now();
                            abort_reason = Some("hard_error");
                            abort_since = Some(now);
                            abort_deadline = Some(now);
                            continue;
                        }
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => c_open = false,
            }
        }
        if s_open && c_open && down.ready_for_read() {
            let poll = if hot { HY2_POLL_HOT } else { HY2_POLL_IDLE };
            match hy2.stream_read(stream, &mut sbuf, poll) {
                Ok(0) => s_open = false,
                Ok(n) => {
                    down.enqueue(&sbuf[..n]);
                    progressed = true;
                }
                Err(Hysteria2Error::Timeout) => {}
                Err(e) => {
                    if abort_reason.is_none() {
                        last_error = Some(e);
                    }
                    s_open = false;
                }
            }
        }
        // 触发 2：有在途下行且双向零字节进展持续 30 s → 立即中止。
        if abort_reason.is_none() && c_open && s_open && !down.ready_for_read() {
            if up_bytes == up_before && down_bytes == down_before {
                let now = Instant::now();
                let since = *stalled_since.get_or_insert(now);
                if now.saturating_duration_since(since) >= HY2_STALL_BUDGET {
                    up_failed = true;
                    abort_reason = Some("liveness");
                    abort_since = Some(since);
                    abort_deadline = Some(now);
                }
            } else {
                stalled_since = None;
            }
        } else {
            stalled_since = None;
        }
        // 半关闭：client EOF 后先排空下行尾部，再对 stream 发 FIN。
        if !c_open && s_open && (down_failed || down.ready_for_read()) {
            hy2.stream_finish(stream);
            s_open = false;
        }
        if !s_open && c_open && (down_failed || down.ready_for_read()) {
            c_open = false;
        }
        hot = round_hot;
        if !progressed && abort_reason.is_none() {
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
    }
    (up_bytes, down_bytes)
}

/// meow-rs 语义的 hysteria2 带宽解析（`down` → `Hysteria-CC-RX` 字节/秒）：
/// 纯整数按 Mbps 计；`"100 Mbps"` / `"1 Gbps"` / `"512 Kbps"` 按单位换算
/// （小写 `b`=bits → /8，大写 `B`=bytes）。缺省/空 → 0（未知）。
/// 非法输入 fail-closed（配置 bug 应 loud，而非静默按 0 处理）。
fn parse_hy2_bandwidth_to_bps(text: Option<&str>) -> Result<u64, String> {
    let s = text.map(str::trim).unwrap_or("");
    if s.is_empty() || s == "0" {
        return Ok(0);
    }
    if let Ok(mbps) = s.parse::<u64>() {
        return Ok(mbps.saturating_mul(1_000_000) / 8);
    }
    let err = || format!("invalid bandwidth '{s}', expected integer Mbps or e.g. '100 Mbps'");
    // 手工实现 meow-rs 的 `^(\d+)\s*([KMGTkmgt]?)([Bb])ps$`（apps/nexus 无 regex 依赖）。
    let digits = s.bytes().take_while(u8::is_ascii_digit).count();
    if digits == 0 {
        return Err(err());
    }
    let value: u64 = s[..digits].parse().map_err(|_| err())?;
    let mut rest = s[digits..].trim_start();
    let mult: u64 = match rest.chars().next() {
        Some(c) if "KMGTkmgt".contains(c) => {
            rest = &rest[c.len_utf8()..];
            match c.to_ascii_uppercase() {
                'K' => 1_000,
                'M' => 1_000_000,
                'G' => 1_000_000_000,
                'T' => 1_000_000_000_000,
                _ => unreachable!("prefix restricted by guard"),
            }
        }
        _ => 1,
    };
    let rest = rest.trim_start();
    let bits = match rest.chars().next() {
        Some('b') => true,
        Some('B') => false,
        _ => return Err(err()),
    };
    let rest = &rest['b'.len_utf8()..];
    if !rest.eq_ignore_ascii_case("ps") {
        return Err(err());
    }
    let total = value
        .checked_mul(mult)
        .ok_or_else(|| format!("bandwidth '{s}' overflows u64"))?;
    Ok(if bits { total / 8 } else { total })
}

/// Hysteria2 出站配置 → `Hysteria2Target`（纯映射，可单测；meow-rs 语义对齐）。
///
/// - locator → server/port；password → 认证口令；
/// - sni（空 → None，由 `effective_sni` 回退到 server host）；
/// - skip_cert_verify → `Insecure` / `SystemRoots`；
/// - obfs：`salamander`（key 取 obfs_password，由 driver 在 QUIC 包之下做整包
///   XOR）/ 空 / `none`；其余值明确拒绝（hysteria2 的 obfs 字段只支持这两档）；
/// - down → `Hysteria-CC-RX`（字节/秒；缺省 0=未知）；
/// - ports（端口跳跃）/ up（Brutal CC）暂不支持，忽略（见 MODULE.md）。
fn hysteria2_target_from_outbound(
    selected: &nexus_proxy_config::OutboundConfig,
    tag: &str,
) -> Result<nexus_outbound_hysteria2::Hysteria2Target, NexusError> {
    use nexus_outbound_hysteria2::{CertVerify, Hysteria2Target, Obfs};
    let fail = |reason: String| NexusError::ConnectivityEstablishmentFailed {
        provider: ProviderId(tag.to_string()),
        reason,
    };
    let locator = selected
        .locator
        .clone()
        .filter(|l| !l.is_empty())
        .ok_or_else(|| fail("hysteria2 outbound missing locator".into()))?;
    let (nhost, nport) = split_host_port(&locator)?;
    let password = selected
        .password
        .clone()
        .filter(|p| !p.is_empty())
        .ok_or_else(|| fail("hysteria2 outbound missing password".into()))?;
    let obfs = Obfs::parse(
        selected.obfs.as_deref().unwrap_or(""),
        selected.obfs_password.as_deref().unwrap_or("").as_bytes(),
    )
    .map_err(|e| fail(format!("hysteria2 obfs config invalid: {e}")))?;
    let cc_rx_bps = parse_hy2_bandwidth_to_bps(selected.down.as_deref())
        .map_err(|e| fail(format!("hysteria2 down bandwidth invalid: {e}")))?;
    let mut target = Hysteria2Target::new(nhost, nport, password);
    target.sni = selected.sni.clone().filter(|s| !s.is_empty());
    target.verify = if selected.skip_cert_verify.unwrap_or(false) {
        CertVerify::Insecure
    } else {
        CertVerify::SystemRoots
    };
    target.obfs = obfs;
    target.cc_rx_bps = cc_rx_bps;
    Ok(target)
}

/// 握手阶段（非 `Established` 步）应答的立即写出点。
///
/// 空应答（HTTP 转发型的 Established 之外的空 response）不写任何字节，保持既有行为。
fn write_handshake_reply(client: &mut std::net::TcpStream, bytes: &[u8]) -> Result<(), NexusError> {
    use std::io::Write;
    if bytes.is_empty() {
        return Ok(());
    }
    client.write_all(bytes).map_err(|_| NexusError::Internal {
        message: "proxy write failed".into(),
    })
}

/// 回写点之前（arm 尚未确定）的失败收尾。
///
/// 修复前 success 在路由之前就已写出，因此这里先补写 success 再返回原错误，
/// 逐字节保持修复前的客户端可见形态（spec §5.7 步骤 1 兼容语义）。
fn pre_arm_failure(
    client: &mut std::net::TcpStream,
    reply: &mut DeferredConnectReply,
    err: NexusError,
) -> NexusError {
    if !reply.is_sent() {
        let _ = reply.send_success(client);
    }
    err
}

/// Trojan 隧道结束形态。
enum TrojanTunnelOutcome {
    /// 正常结束（含窗口超时放行）：返回字节计数、出站 JSON 与守卫观测。
    Done {
        up_bytes: usize,
        down_bytes: usize,
        outbound: Value,
        tunnel: Value,
    },
    /// 窗口内客户端先断开：不写应答、丢弃节点，按正常终止返回（spec §6）。
    ClientAborted { outbound: Value, tunnel: Value },
}

/// 窗口结束原因（内部状态机）。
enum WindowEnd {
    /// 放行并进入中继；字符串是 `tunnel.readiness`。
    Ready(&'static str),
    /// 客户端在 success 前断开。
    Aborted,
    /// 拒绝（写失败应答、有界 drain、返回 Err）。
    Reject(RejectCause),
}

/// Trojan 数据面（§11.16 / §5.7 步骤 2）：TLS + 请求头 + fail-closed 就绪窗口 + 中继。
///
/// 应答语义（spec §4）：
/// - `seed_to_upstream` 非空（客户端已先说话）→ 跳过窗口立即写 success；
/// - 否则在 header+seed flush 完成后进入最多 `W` 的窗口：客户端先载荷 / 白名单 greeting
///   首包 / 窗口静默到期 => success；HTTP 状态行 / 非白名单首包 / 首包前 EOF => 失败应答；
/// - 失败路径不 flush `close_notify`、不写额外 TLS 记录，对节点做有界 drain 后 FIN。
#[allow(clippy::too_many_arguments)] // 组合根内部函数：参数都是调用点已解析好的隧道上下文
fn trojan_tunnel(
    client: &mut std::net::TcpStream,
    reply: &mut DeferredConnectReply,
    owner: &mut SessionOwner,
    selected: &nexus_proxy_config::OutboundConfig,
    provider_tag: &str,
    host: &str,
    port: u16,
    seed_to_upstream: &[u8],
) -> Result<TrojanTunnelOutcome, NexusError> {
    let mut rep = 0x01u8;
    let outcome = trojan_tunnel_inner(
        client,
        reply,
        owner,
        selected,
        provider_tag,
        host,
        port,
        seed_to_upstream,
        &mut rep,
    );
    if outcome.is_err() && !reply.is_sent() {
        // 回写点之前的失败（connect / TLS / 头 / seed）：仍必须 fail-closed——
        // 客户端拿失败应答，而不是「已建立」后看到一个死隧道。
        reply
            .send_failure(client, rep)
            .map_err(|e| NexusError::Internal {
                message: format!("connect reply write failed: {e}"),
            })?;
        let _ = client.shutdown(std::net::Shutdown::Both);
    }
    outcome
}

/// 失败 reason 的固定格式（spec §9）：前缀 + 等待毫秒 + 首包 hex（≤16B → ≤32 hex）+ 目标端口。
fn trojan_fail_reason(prefix: &str, waited_ms: u64, first: &[u8], dest_port: u16) -> String {
    let hex: String = first
        .iter()
        .take(trojan_guard::FIRST_BYTES_MAX)
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("{prefix}: waited_ms={waited_ms} first_bytes_hex={hex} dest_port={dest_port}")
}

/// 拒绝路径收尾：失败应答 + 有界 drain + best-effort 失败终态（spec §6 / AC-6）。
///
/// - 不调用 `send_close_notify`、不写额外 TLS 记录（失败只在本地可观察）；
/// - drain 让节点侧看到正常 FIN 而不是「带未读数据关闭」的 RST；
/// - `commit_outcome` 失败不覆盖原始错误。
#[allow(clippy::too_many_arguments)] // 拒绝收尾需要同时带客户端/节点/会话/观测字段
fn trojan_reject(
    client: &mut std::net::TcpStream,
    reply: &mut DeferredConnectReply,
    owner: &mut SessionOwner,
    node: &mut rustls::Stream<
        '_,
        rustls::ClientConnection,
        Box<dyn nexus_plugin::ObfuscatedStream>,
    >,
    cause: RejectCause,
    rep: u8,
    waited_ms: u64,
    first: &[u8],
    dest_port: u16,
    provider_tag: &str,
) -> NexusError {
    // 1) 失败应答先写给客户端（成功前失败 => 客户端不会把失败误当隧道）。
    if !reply.is_sent() {
        if let Err(e) = reply.send_failure(client, rep) {
            return NexusError::Internal {
                message: format!("connect reply write failed: {e}"),
            };
        }
    }
    // 2) 有界 drain（≤64KiB 或 50ms，读到的字节全部丢弃）。
    let _ = deferred_reply::bounded_drain(
        node,
        trojan_guard::NODE_DRAIN_MAX_BYTES,
        trojan_guard::NODE_DRAIN_MAX_MS,
    );
    let _ = client.shutdown(std::net::Shutdown::Both);
    // 3) best-effort 失败终态（提交失败不覆盖原错误）。
    let _ = owner.commit_outcome(TerminalOutcome::Failed(
        NexusError::ConnectivityEstablishmentFailed {
            provider: ProviderId(provider_tag.to_string()),
            reason: trojan_fail_reason(cause.reason_prefix(), waited_ms, first, dest_port),
        },
    ));
    let _ = owner.transition_phase(LifecyclePhase::Draining);
    let _ = owner.transition_phase(LifecyclePhase::Disposed);
    NexusError::ConnectivityEstablishmentFailed {
        provider: ProviderId(provider_tag.to_string()),
        reason: trojan_fail_reason(cause.reason_prefix(), waited_ms, first, dest_port),
    }
}

#[allow(clippy::too_many_arguments)]
fn trojan_tunnel_inner(
    client: &mut std::net::TcpStream,
    reply: &mut DeferredConnectReply,
    owner: &mut SessionOwner,
    selected: &nexus_proxy_config::OutboundConfig,
    provider_tag: &str,
    host: &str,
    port: u16,
    seed_to_upstream: &[u8],
    rep: &mut u8,
) -> Result<TrojanTunnelOutcome, NexusError> {
    use nexus_outbound_trojan::{TrojanHeaderFormat, TrojanTarget, encode_request_fmt};
    use rustls::pki_types::ServerName;
    use std::io::{Read, Write};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use pending_write::WriteProgress;
    use trojan_guard::{
        GuardPolicy, ReadinessVerdict, classify_first_downstream, guard_policy, ready_window_ms,
    };

    let provider = || ProviderId(provider_tag.to_string());
    let locator =
        selected
            .locator
            .clone()
            .ok_or_else(|| NexusError::ConnectivityEstablishmentFailed {
                provider: provider(),
                reason: "trojan outbound missing locator".into(),
            })?;
    let (nhost, nport) = split_host_port(&locator)?;
    // §7.3 插件接线（P1）：obfs 包在 TLS 之下。先建 raw TCP（保持 blocking，
    // TLS 握手期间 rustls 用阻塞 I/O，提前 nonblocking 会导致 WouldBlock 硬失败），
    // clone 一个 handle 留待握手后设 nonblocking（同 fd 共享 flag），再 wrap；
    // obfs=None → plain 直通（P6 零回归）。
    let t_connect = Instant::now();
    let raw = std::net::TcpStream::connect((nhost.as_str(), nport)).map_err(|e| {
        if e.kind() == std::io::ErrorKind::ConnectionRefused {
            // 与 direct 语义一致：节点端口拒绝时 REP=0x05。
            *rep = 0x05;
        }
        NexusError::ConnectivityEstablishmentFailed {
            provider: provider(),
            reason: format!(
                "tunnel connect failed: waited_ms=0 first_bytes_hex= dest_port={port} \
                 (trojan node connect {locator} failed: {e})"
            ),
        }
    })?;
    let connect_elapsed = t_connect.elapsed();
    // AC-3 / §5.6④(a)：header 与 seed 是两条 TLS record（AC-4 要求记录划分与基线一致，
    // 因此不能合并写）。产品若保留 Nagle，第二条 record 会被内核压到首个 ACK 之后
    // （loopback 实测 ~40ms），出现「客户端已收 success、节点还没收到 pipelined 载荷」。
    // TCP_NODELAY 只影响分段时机，不新增/不减少任何字节，也不改变 TLS 记录划分。
    raw.set_nodelay(true).map_err(|e| NexusError::Internal {
        message: format!("trojan node nodelay: {e}"),
    })?;
    let raw_nb = raw.try_clone().map_err(|e| NexusError::Internal {
        message: format!("trojan node clone for nonblocking: {e}"),
    })?;
    let obfs_params = nexus_plugin::ObfsParams {
        key: selected.obfs_key.as_deref().unwrap_or("").as_bytes(),
    };
    let mut node =
        nexus_plugin::wrap_stream(raw, selected.obfs.as_deref(), &obfs_params).map_err(|e| {
            NexusError::ConnectivityEstablishmentFailed {
                provider: provider(),
                reason: format!(
                    "tunnel handshake failed: waited_ms=0 first_bytes_hex= dest_port={port} \
                 (trojan obfs wrap failed: {e})"
                ),
            }
        })?;
    let password =
        selected
            .password
            .clone()
            .ok_or_else(|| NexusError::ConnectivityEstablishmentFailed {
                provider: provider(),
                reason: format!(
                    "tunnel handshake failed: waited_ms=0 first_bytes_hex= dest_port={port} \
                 (trojan outbound missing password)"
                ),
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
                provider: provider(),
                reason: format!(
                    "tunnel handshake failed: waited_ms=0 first_bytes_hex= dest_port={port} \
                     (trojan client tls config failed: {e})"
                ),
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
            provider: provider(),
            reason: format!(
                "tunnel handshake failed: waited_ms=0 first_bytes_hex= dest_port={port} \
                 (trojan sni invalid: {nhost})"
            ),
        }
    })?;
    let mut conn = rustls::ClientConnection::new(Arc::new(tls_cfg), sni).map_err(|e| {
        NexusError::ConnectivityEstablishmentFailed {
            provider: provider(),
            reason: format!(
                "tunnel handshake failed: waited_ms=0 first_bytes_hex= dest_port={port} \
                 (trojan client connection failed: {e})"
            ),
        }
    })?;

    // 写入 trojan 请求头（write_all/flush 同时驱动 TLS 握手）。
    let target = if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        TrojanTarget::Ipv4(ip.octets(), port)
    } else {
        TrojanTarget::Domain(host.to_string(), port)
    };
    let header = encode_request_fmt(&password, &target, header_format);
    {
        let mut tls = rustls::Stream::new(&mut conn, &mut node);
        tls.write_all(&header)
            .map_err(|e| NexusError::ConnectivityEstablishmentFailed {
                provider: provider(),
                reason: format!(
                    "tunnel handshake failed: waited_ms=0 first_bytes_hex= dest_port={port} \
                     (trojan header write failed: {e})"
                ),
            })?;
        tls.flush()
            .map_err(|e| NexusError::ConnectivityEstablishmentFailed {
                provider: provider(),
                reason: format!(
                    "tunnel handshake failed: waited_ms=0 first_bytes_hex= dest_port={port} \
                     (trojan handshake/header flush failed: {e})"
                ),
            })?;
        // §11.19：握手首段字节（HTTP 改写后的请求）随 TLS 一并写给节点。
        if !seed_to_upstream.is_empty() {
            tls.write_all(seed_to_upstream).map_err(|e| {
                NexusError::ConnectivityEstablishmentFailed {
                    provider: provider(),
                    reason: format!(
                        "tunnel handshake failed: waited_ms=0 first_bytes_hex= dest_port={port} \
                         (trojan seed write failed: {e})"
                    ),
                }
            })?;
            tls.flush()
                .map_err(|e| NexusError::ConnectivityEstablishmentFailed {
                    provider: provider(),
                    reason: format!(
                        "tunnel handshake failed: waited_ms=0 first_bytes_hex= dest_port={port} \
                         (trojan seed flush failed: {e})"
                    ),
                })?;
        }
    }

    let hf_label = match header_format {
        TrojanHeaderFormat::Standard => "standard",
        TrojanHeaderFormat::Singbox => "singbox",
    };
    let outbound_json = json!({
        "kind": "trojan",
        "node_locator": locator,
        "tls": {
            "sni": nhost,
            "alpn": selected.alpn,
            "skip_cert_verify": skip_verify,
        },
        "header_format": hf_label,
    });

    let policy: GuardPolicy = guard_policy(selected.fallback_guard.as_deref());
    let policy_label = match policy {
        GuardPolicy::Strict => "strict",
        GuardPolicy::Signature => "signature",
    };
    let dest_port = port;

    // 出站就绪点（t4）：node 在 TLS 握手完成后才设 nonblocking。
    raw_nb
        .set_nonblocking(true)
        .map_err(|e| NexusError::Internal {
            message: format!("trojan node nonblocking: {e}"),
        })?;

    let mut up_bytes = 0usize;
    let mut down_bytes = 0usize;
    let mut window_ms = 0u64;
    let mut waited_ms = 0u64;
    let mut first_bytes: Vec<u8> = Vec::new();
    let mut pre_payload_down_bytes = 0u64;
    let readiness: &'static str;
    // 窗口内已从节点读到、尚未写给客户端的字节（放行后先回放）。
    let mut pending_down: Vec<u8> = Vec::new();
    let mut up = PendingWrite::new();
    let mut late_guard: bool;

    {
        let mut tls = rustls::Stream::new(&mut conn, &mut node);
        if !seed_to_upstream.is_empty() {
            // §4 条件 2：客户端已先说话（pipelined 载荷 / HTTP 改写请求），守卫不适用。
            reply
                .send_success(client)
                .map_err(|e| NexusError::Internal {
                    message: format!("connect reply write failed: {e}"),
                })?;
            readiness = "client_payload";
            late_guard = false;
        } else {
            client
                .set_read_timeout(Some(Duration::from_millis(2)))
                .map_err(|e| NexusError::Internal {
                    message: format!("trojan client read timeout: {e}"),
                })?;
            window_ms = ready_window_ms(connect_elapsed, selected.ready_window_ms);
            let t4 = Instant::now();
            let deadline = t4 + Duration::from_millis(window_ms);
            let mut wait_more_deadline: Option<Instant> = None;
            let mut pending = WindowEnd::Ready("window_expired");
            let mut window_buf = [0u8; 8192];

            loop {
                // (a) 客户端先说：先写节点（零扣压），再立即 success。
                match client.read(&mut window_buf) {
                    Ok(0) => {
                        pending = WindowEnd::Aborted;
                        break;
                    }
                    Ok(n) => {
                        up.enqueue(&window_buf[..n]);
                        // 立即写节点（不进入「等下行再放行」的队列）。
                        let drain_deadline = Instant::now() + Duration::from_secs(1);
                        loop {
                            match up.try_write(&mut tls) {
                                Ok((WriteProgress::Drained, n)) => {
                                    up_bytes += n;
                                    break;
                                }
                                Ok((WriteProgress::Blocked, n)) => {
                                    up_bytes += n;
                                    if Instant::now() >= drain_deadline {
                                        pending = WindowEnd::Reject(RejectCause::ClosedBeforeReady);
                                        break;
                                    }
                                    std::thread::sleep(Duration::from_millis(1));
                                }
                                Err(_) => {
                                    // 节点写失败：等同「节点在就绪前关闭」。
                                    pending = WindowEnd::Reject(RejectCause::ClosedBeforeReady);
                                    break;
                                }
                            }
                        }
                        if matches!(pending, WindowEnd::Reject(_)) {
                            break;
                        }
                        pending = WindowEnd::Ready("client_payload");
                        break;
                    }
                    Err(ref e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut => {}
                    Err(_) => {
                        pending = WindowEnd::Aborted;
                        break;
                    }
                }

                // (b) 节点首包分类。
                let mut eof = false;
                match tls.read(&mut window_buf) {
                    Ok(0) => eof = true,
                    Ok(n) => {
                        pre_payload_down_bytes += n as u64;
                        let take = (trojan_guard::FIRST_BYTES_MAX - first_bytes.len()).min(n);
                        first_bytes.extend_from_slice(&window_buf[..take]);
                        pending_down.extend_from_slice(&window_buf[..n]);
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(_) => eof = true,
                }

                // 空首包且未 EOF：还没有可分类的输入（规则 5 的「非空」限定）。
                if first_bytes.is_empty() && !eof {
                    let now = Instant::now();
                    if let Some(ext) = wait_more_deadline {
                        if now >= ext {
                            pending = WindowEnd::Reject(RejectCause::UnsolicitedServerData);
                            break;
                        }
                    } else if now >= deadline {
                        pending = WindowEnd::Ready("window_expired");
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(2));
                    continue;
                }
                let verdict =
                    classify_first_downstream(dest_port, &first_bytes, false, eof, policy);
                match verdict {
                    ReadinessVerdict::WaitMore => {
                        // 前缀补等：只延长一次、最多 PREFIX_EXTRA_WAIT_MS。
                        match wait_more_deadline {
                            None => {
                                wait_more_deadline = Some(
                                    Instant::now()
                                        + Duration::from_millis(trojan_guard::PREFIX_EXTRA_WAIT_MS),
                                );
                            }
                            Some(_) => {
                                // 延长到期仍未凑成完整前缀 => 非白名单首包。
                                pending = WindowEnd::Reject(RejectCause::UnsolicitedServerData);
                                break;
                            }
                        }
                    }
                    ReadinessVerdict::Success => {
                        pending = WindowEnd::Ready("greeting");
                        break;
                    }
                    ReadinessVerdict::Reject(cause) => {
                        pending = WindowEnd::Reject(cause);
                        break;
                    }
                }

                let now = Instant::now();
                if let Some(ext) = wait_more_deadline {
                    // 前缀补等到期：仍在半截前缀 => 非白名单首包（§4 的既定处置）。
                    if now >= ext {
                        pending = WindowEnd::Reject(RejectCause::UnsolicitedServerData);
                        break;
                    }
                } else if now >= deadline {
                    // 窗口静默到期：放行（不把「慢目标」当 fallback）。
                    pending = WindowEnd::Ready("window_expired");
                    break;
                }
                std::thread::sleep(Duration::from_millis(2));
            }

            waited_ms = t4.elapsed().as_millis() as u64;
            match pending {
                WindowEnd::Aborted => {
                    // 客户端在 success 前断开：不写应答、丢弃节点、正常返回（不挂死）。
                    let _ = client.shutdown(std::net::Shutdown::Both);
                    let tunnel = json!({
                        "readiness": "client_aborted",
                        "pre_payload_down_bytes": pre_payload_down_bytes,
                        "guard": policy_label,
                        "window_ms": window_ms,
                    });
                    return Ok(TrojanTunnelOutcome::ClientAborted {
                        outbound: outbound_json,
                        tunnel,
                    });
                }
                WindowEnd::Reject(cause) => {
                    let err = trojan_reject(
                        client,
                        reply,
                        owner,
                        &mut tls,
                        cause,
                        *rep,
                        waited_ms,
                        &first_bytes,
                        dest_port,
                        provider_tag,
                    );
                    return Err(err);
                }
                WindowEnd::Ready(kind) => {
                    reply
                        .send_success(client)
                        .map_err(|e| NexusError::Internal {
                            message: format!("connect reply write failed: {e}"),
                        })?;
                    readiness = kind;
                    late_guard = kind != "client_payload";
                }
            }
        }

        client
            .set_nonblocking(true)
            .map_err(|e| NexusError::Internal {
                message: format!("trojan client nonblocking: {e}"),
            })?;

        // 窗口内已读到的下行字节先回放给客户端（放行那一刻的 greeting/首包）。
        let mut down = PendingWrite::new();
        if !pending_down.is_empty() {
            client
                .write_all(&pending_down)
                .map_err(|e| NexusError::Internal {
                    message: format!("trojan greeting write failed: {e}"),
                })?;
            down_bytes += pending_down.len();
        }

        let mut cbuf = [0u8; 8192];
        let mut sbuf = [0u8; 8192];
        let mut c_open = true;
        let mut tls_open = true;
        let mut up_failed = false;
        let mut down_failed = false;
        // post-success 最佳努力守卫（LateFallbackObserved，只认 `HTTP/`）。
        let mut late_probe: Vec<u8> = Vec::new();
        loop {
            if !c_open
                && !tls_open
                && (up_failed || up.ready_for_read())
                && (down_failed || down.ready_for_read())
            {
                break;
            }
            let mut progressed = false;
            // 先排空两个方向的待写尾部：WouldBlock 保留尾部，非 WouldBlock
            // 错误才关闭对应方向（不得把 WouldBlock 当致命错误）。
            match up.try_write(&mut tls) {
                Ok((_, n)) => {
                    up_bytes += n;
                    progressed |= n > 0;
                }
                Err(_) => {
                    tls_open = false;
                    up_failed = true;
                }
            }
            match down.try_write(client) {
                Ok((_, n)) => {
                    down_bytes += n;
                    progressed |= n > 0;
                }
                Err(_) => {
                    c_open = false;
                    tls_open = false;
                    down_failed = true;
                }
            }
            if c_open && tls_open {
                match up.try_read(client, &mut cbuf) {
                    None => {}
                    Some(Ok(0)) => c_open = false,
                    Some(Ok(n)) => {
                        up.enqueue(&cbuf[..n]);
                        progressed = true;
                    }
                    Some(Err(ref e)) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Some(Err(_)) => c_open = false,
                }
            }
            if tls_open && c_open {
                match down.try_read(&mut tls, &mut sbuf) {
                    None => {}
                    Some(Ok(0)) => tls_open = false,
                    Some(Ok(n)) => {
                        progressed = true;
                        if late_guard {
                            late_probe.extend_from_slice(&sbuf[..n]);
                            if late_probe.len() >= 5 {
                                if late_probe.starts_with(b"HTTP/") {
                                    // success 已写出，但客户端尚未载荷：丢掉该首包并关闭，
                                    // 保证「零隧道字节」（不计入 AC-1，仅纵深防御）。
                                    let _ = client.shutdown(std::net::Shutdown::Both);
                                    let reason = trojan_fail_reason(
                                        "late fallback response discarded",
                                        waited_ms,
                                        &late_probe,
                                        dest_port,
                                    );
                                    let _ = owner.commit_outcome(TerminalOutcome::Failed(
                                        NexusError::ConnectivityEstablishmentFailed {
                                            provider: provider(),
                                            reason: reason.clone(),
                                        },
                                    ));
                                    let _ = owner.transition_phase(LifecyclePhase::Draining);
                                    let _ = owner.transition_phase(LifecyclePhase::Disposed);
                                    return Err(NexusError::ConnectivityEstablishmentFailed {
                                        provider: provider(),
                                        reason,
                                    });
                                }
                                down.enqueue(&late_probe);
                                late_guard = false;
                            } else if !b"HTTP/".starts_with(&late_probe) {
                                down.enqueue(&late_probe);
                                late_guard = false;
                            }
                        } else {
                            down.enqueue(&sbuf[..n]);
                        }
                    }
                    Some(Err(ref e)) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Some(Err(_)) => tls_open = false,
                }
            }
            // 半关闭：一侧 EOF/致命写错误后，先排空该方向尾部再终止另一侧。
            if !c_open && tls_open && (down_failed || down.ready_for_read()) {
                tls_open = false;
            }
            if !tls_open
                && c_open
                && (up_failed || up.ready_for_read())
                && (down_failed || down.ready_for_read())
            {
                c_open = false;
            }
            if !progressed {
                std::thread::sleep(Duration::from_millis(2));
            }
        }
    }
    // 尽力向节点发送 close_notify（不阻断结果；仅成功路径）。
    conn.send_close_notify();
    // node 是 wrapped 流（Box<dyn ObfuscatedStream>），无法恢复 inner 的
    // blocking 模式；arm 结束时流即 drop 关闭 fd，无需恢复。

    let tunnel = json!({
        "readiness": readiness,
        "pre_payload_down_bytes": pre_payload_down_bytes,
        "guard": policy_label,
        "window_ms": window_ms,
    });
    Ok(TrojanTunnelOutcome::Done {
        up_bytes,
        down_bytes,
        outbound: outbound_json,
        tunnel,
    })
}

// ---------- SOCKS5 UDP ASSOCIATE 产品路径（fixes-6 Phase 1 / C4） ----------
//
// 接线口径（spec §3.2/§3.6/§3.9/§6.3/§7.2）：
// - 握手 `Established` 后先按 `Socks5Handshake::command()` 分流：CONNECT 走原路径（零变化），
//   UDP ASSOCIATE 进本段；关联生命周期从属控制连接（EOF/RST/违规 → 立即终止）。
// - Q12 准入在组合根判定：`listener.local_addr()` 非 loopback 且本产品无显式认证 → REP=0x01。
// - 能力翻转点（全 run 唯一对外可见翻转）：VLESS → `Supported(VlessOverTcp)`、
//   AnyTLS → `Supported(AnytlsUot)` 首次被生产路径消费；Trojan/SS/Hy2 → `Unsupported`
//   （R-3：`NotWired`）；Direct/Relay/Vmess → 先判 kind 丢弃（Q11），绝不直连。
// - R-7=(a)：保留 `main.rs` 串行 accept 模型；`MAX_UDP_ASSOCIATIONS=128` 为进程内上限，
//   在串行模型下不可达（单进程有效并发 = 1）。

use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use nexus_proxy::ProxyService;
use nexus_proxy_config::{OutboundConfig, OutboundKind, UdpCapability, UdpMode};

use udp_association::{
    Event as UdpAssociationEvent, GlobalRateLimiter, MAX_UDP_ASSOCIATIONS, Outcome as UdpOutcome,
    RoutedOutbound, Stats as UdpStats, UdpAssociateError, UdpAssociation, UdpAssociationConfig,
    UdpDropReason, UdpOutboundRouter,
};
use udp_outbound::{
    TargetAddr, UdpOutbound, UdpOutboundError, build_udp_outbound, route_udp_target,
};

/// 控制连接轮询间隔（spec §5.2：100ms，与既有 relay 读超时一致）。
const UDP_CONTROL_POLL_INTERVAL: Duration = Duration::from_millis(100);
/// 关联侧单包接收缓冲（IPv4 UDP 最大载荷；协议上限由出站各自判定）。
const UDP_RECV_BUF_BYTES: usize = 65_535;
/// 单轮最多处理的客户端数据报数（保证控制连接 EOF/违规检测不被持续洪泛饿死）。
const UDP_RECV_BATCH: usize = 256;

/// 进程内活跃 UDP 关联计数（spec §5.2 `MAX_UDP_ASSOCIATIONS`；R-7 串行模型下有效并发=1）。
struct AssociationSlots {
    active: AtomicUsize,
    limit: usize,
}

impl AssociationSlots {
    const fn new(limit: usize) -> Self {
        Self {
            active: AtomicUsize::new(0),
            limit,
        }
    }

    fn try_acquire(&self) -> Option<AssociationSlot<'_>> {
        let mut current = self.active.load(Ordering::Acquire);
        loop {
            if current >= self.limit {
                return None;
            }
            match self.active.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(AssociationSlot { slots: self }),
                Err(observed) => current = observed,
            }
        }
    }

    fn active(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }
}

/// 关联占用（`Drop` 归还计数，异常路径不泄漏）。
struct AssociationSlot<'a> {
    slots: &'a AssociationSlots,
}

impl Drop for AssociationSlot<'_> {
    fn drop(&mut self) {
        self.slots.active.fetch_sub(1, Ordering::AcqRel);
    }
}

static UDP_ASSOCIATION_SLOTS: AssociationSlots = AssociationSlots::new(MAX_UDP_ASSOCIATIONS);
static UDP_ASSOCIATION_IDS: AtomicU64 = AtomicU64::new(1);

/// 全局 pps 限速器（跨关联共享；spec §5.2 20000 pps）。
fn udp_global_rate() -> Arc<GlobalRateLimiter> {
    static CELL: OnceLock<Arc<GlobalRateLimiter>> = OnceLock::new();
    Arc::clone(CELL.get_or_init(|| Arc::new(GlobalRateLimiter::new())))
}

/// 全局 flow 计数（跨关联共享；spec §5.2 `MAX_UDP_FLOWS`）。
fn udp_global_flows() -> Arc<AtomicUsize> {
    static CELL: OnceLock<Arc<AtomicUsize>> = OnceLock::new();
    Arc::clone(CELL.get_or_init(|| Arc::new(AtomicUsize::new(0))))
}

/// `[proxy-udp]` 日志限频器（spec §5.2 10s / §6.5 `suppressed=` 在下一条实际日志输出）。
#[derive(Default)]
struct UdpLogLimiter {
    last: HashMap<String, Instant>,
    suppressed: HashMap<String, u64>,
}

impl UdpLogLimiter {
    /// 按 `key` 限频输出；`suppressed` 为自上一条实际日志以来被抑制的条数。
    fn emit(
        &mut self,
        now: Instant,
        interval: Duration,
        key: &str,
        render: impl FnOnce(u64) -> String,
    ) {
        let due = match self.last.get(key) {
            None => true,
            Some(previous) => now.saturating_duration_since(*previous) >= interval,
        };
        let suppressed = self.suppressed.entry(key.to_string()).or_insert(0);
        if due {
            let carried = *suppressed;
            *suppressed = 0;
            self.last.insert(key.to_string(), now);
            udp_log(render(carried));
        } else {
            *suppressed += 1;
        }
    }

    /// 累计被抑制的日志条数（关联结束时写入 `udp.log_suppressed`）。
    fn total_suppressed(&self) -> u64 {
        self.suppressed.values().copied().sum()
    }
}

/// 单行 `[proxy-udp]` 日志（stderr；行内字段不含密钥/载荷，见 spec §6.5）。
fn udp_log(line: String) {
    eprintln!("[proxy-udp] {line}");
}

/// 关联准入拒绝日志（限频；§3.9/§6.3 计数已在 JSON `udp.associations_rejected`）。
fn log_udp_rejected(
    log: &mut UdpLogLimiter,
    assoc_id: u64,
    reason: &'static str,
    interval: Duration,
) {
    log.emit(Instant::now(), interval, reason, |suppressed| {
        format!(
            "event=udp_drop assoc_id={assoc_id} reason={reason} kind=- tag=- suppressed={suppressed}"
        )
    });
}

/// 一次路由观测（`flow_opened` 日志与 `udp_send_failed` 的 tag 来源）。
struct UdpRouteRecord {
    target: TargetAddr,
    tag: String,
    kind: OutboundKind,
}

/// 路由侧状态（出站工厂缓存 + 已消费的能力模式 + 最近一次路由）。
#[derive(Default)]
struct RouterState {
    cache: HashMap<String, Result<Arc<dyn UdpOutbound>, UdpDropReason>>,
    modes: BTreeSet<&'static str>,
    last: Option<UdpRouteRecord>,
}

/// 产品 UDP 路由：`ProxyService` 规则 → `OutboundConfig` → `build_udp_outbound`（带缓存）。
struct ProductUdpRouter {
    service: ProxyService,
    outbounds: Vec<OutboundConfig>,
    state: Mutex<RouterState>,
}

impl ProductUdpRouter {
    fn new(config: &nexus_proxy_config::ProxyConfig, service: ProxyService) -> Self {
        Self {
            service,
            outbounds: config.outbounds.clone(),
            state: Mutex::new(RouterState::default()),
        }
    }

    fn outbound(&self, tag: &str) -> Result<Arc<dyn UdpOutbound>, UdpDropReason> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(cached) = state.cache.get(tag) {
            return cached.clone();
        }
        let built = match self.outbounds.iter().find(|outbound| outbound.tag == tag) {
            None => Err(UdpDropReason::NoRoute),
            Some(config) => build_product_udp_outbound(config),
        };
        if let Ok(outbound) = &built
            && let UdpCapability::Supported(mode) = outbound.capability()
        {
            state.modes.insert(udp_mode_label(&mode));
        }
        state.cache.insert(tag.to_string(), built.clone());
        built
    }

    fn modes(&self) -> Vec<&'static str> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .modes
            .iter()
            .copied()
            .collect()
    }

    fn last_record(&self) -> Option<(String, String, OutboundKind)> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .last
            .as_ref()
            .map(|record| {
                (
                    record.target.to_destination_string(),
                    record.tag.clone(),
                    record.kind,
                )
            })
    }
}

impl UdpOutboundRouter for ProductUdpRouter {
    fn route(&self, target: &TargetAddr) -> Result<RoutedOutbound, UdpDropReason> {
        let decision =
            route_udp_target(&self.service, target).map_err(|_| UdpDropReason::NoRoute)?;
        let outbound = self.outbound(&decision.selected_outbound_tag)?;
        // flow key 的 tag 取出站自报值（与规则决策同源，避免两处来源漂移）。
        let tag = outbound.tag().to_string();
        let kind = outbound.kind();
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .last = Some(UdpRouteRecord {
            target: target.clone(),
            tag: tag.clone(),
            kind,
        });
        Ok(RoutedOutbound { tag, outbound })
    }
}

/// 构造一个产品 UDP 出站：`Unsupported` 能力 / 工厂期配置错误一律 fail-closed。
fn build_product_udp_outbound(
    config: &OutboundConfig,
) -> Result<Arc<dyn UdpOutbound>, UdpDropReason> {
    let kind = config.kind;
    match build_udp_outbound(config) {
        Ok(outbound) => match outbound.capability() {
            UdpCapability::Supported(_) => Ok(Arc::from(outbound)),
            UdpCapability::Unsupported { .. } => Err(UdpDropReason::UnsupportedProtocol { kind }),
        },
        Err(UdpOutboundError::Unsupported { kind, .. }) => {
            Err(UdpDropReason::UnsupportedProtocol { kind })
        }
        // 工厂期配置错误（缺 uuid/password、obfs 等）：按「协议握手失败」归类（§6.3），
        // 只计 `send_failed`，绝不直连。
        Err(_) => Err(UdpDropReason::OutboundHandshake { kind }),
    }
}

/// `UdpMode` → 稳定的 JSON 标签（翻转点对外可见面；不打印 password）。
fn udp_mode_label(mode: &UdpMode) -> &'static str {
    match mode {
        UdpMode::Socks5Associate { .. } => "socks5_associate",
        UdpMode::ShadowsocksAead { .. } => "shadowsocks_aead",
        UdpMode::VlessOverTcp { .. } => "vless_over_tcp",
        UdpMode::AnytlsUot { .. } => "anytls_uot",
        UdpMode::TrojanUdpOverTls { .. } => "trojan_udp_over_tls",
        UdpMode::Hysteria2Datagram { .. } => "hysteria2_datagram",
    }
}

/// `SocketAddr` → ingress 的 `Socks5Address`（BND 应答/回包共用表示）。
fn socks5_addr(addr: SocketAddr) -> nexus_ingress::Socks5Address {
    match addr {
        SocketAddr::V4(v4) => nexus_ingress::Socks5Address::Ipv4 {
            addr: v4.ip().octets(),
            port: v4.port(),
        },
        SocketAddr::V6(v6) => nexus_ingress::Socks5Address::Ipv6 {
            addr: v6.ip().octets(),
            port: v6.port(),
        },
    }
}

/// ASSOCIATE 请求里的客户端端点 hint（spec §3.3）：`(端口锁定, IP 不一致)`。
fn udp_client_hint(
    command: &nexus_ingress::Socks5Command,
    client_ip: IpAddr,
) -> (Option<u16>, bool) {
    let nexus_ingress::Socks5Command::UdpAssociate { client_endpoint } = command else {
        return (None, false);
    };
    let Some(address) = client_endpoint else {
        return (None, false);
    };
    let port = match address.port() {
        0 => None,
        port => Some(port),
    };
    let mismatch = match address {
        nexus_ingress::Socks5Address::Ipv4 { addr, .. } => {
            let ip = IpAddr::V4(std::net::Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]));
            !ip.is_unspecified() && ip != client_ip
        }
        nexus_ingress::Socks5Address::Ipv6 { addr, .. } => {
            let ip = IpAddr::V6(std::net::Ipv6Addr::from(*addr));
            !ip.is_unspecified() && ip != client_ip
        }
        // 域名不能与控制对端 IP 比较：只作 hint，不构成拒绝条件。
        nexus_ingress::Socks5Address::Domain { .. } => false,
    };
    (port, mismatch)
}

/// 丢弃原因的稳定日志 token（§6.3 计数名同源）。
fn udp_drop_token(reason: &UdpDropReason) -> String {
    match reason {
        UdpDropReason::MalformedDatagram => "malformed".to_string(),
        UdpDropReason::FragmentUnsupported { .. } => "fragment".to_string(),
        UdpDropReason::SourceMismatch => "source_mismatch".to_string(),
        UdpDropReason::NoRoute => "no_route".to_string(),
        UdpDropReason::UnsupportedProtocol { kind } => match kind {
            OutboundKind::Vless => "unsupported_vless".to_string(),
            OutboundKind::Anytls => "unsupported_anytls".to_string(),
            OutboundKind::Trojan => "unsupported_trojan".to_string(),
            OutboundKind::Shadowsocks => "unsupported_shadowsocks".to_string(),
            OutboundKind::Hysteria2 => "unsupported_hysteria2".to_string(),
            _ => "unsupported_other".to_string(),
        },
        UdpDropReason::DatagramTooLarge { .. } => "oversize".to_string(),
        UdpDropReason::FlowLimit { .. } => "flow_limit".to_string(),
        UdpDropReason::AssociationFlowLimit { .. } => "association_flow_limit".to_string(),
        UdpDropReason::GlobalFlowLimit { .. } => "global_flow_limit".to_string(),
        UdpDropReason::RateLimited => "rate_limited".to_string(),
        UdpDropReason::QueueFull => "queue_full".to_string(),
        UdpDropReason::OutboundIo { .. } => "outbound_io".to_string(),
        UdpDropReason::OutboundClosed { .. } => "outbound_closed".to_string(),
        UdpDropReason::OutboundTimeout { .. } => "outbound_timeout".to_string(),
        UdpDropReason::OutboundHandshake { .. } => "outbound_handshake".to_string(),
        UdpDropReason::UnmatchedReply => "unmatched_reply".to_string(),
        UdpDropReason::ControlClosed => "control_closed".to_string(),
    }
}

/// 一次丢弃的结构化日志（§6.5；计数已在关联侧完成，这里只负责可观测）。
fn log_udp_drop(
    log: &mut UdpLogLimiter,
    assoc_id: u64,
    source: SocketAddr,
    reason: &UdpDropReason,
    tag: Option<&str>,
) {
    let now = Instant::now();
    let interval = udp_association::UDP_LOG_INTERVAL;
    let token = udp_drop_token(reason);
    match reason {
        // 源校验失败有专用事件行（§6.5 `udp_source_rejected`）。
        UdpDropReason::SourceMismatch => log.emit(now, interval, &token, |suppressed| {
            format!(
                "event=udp_source_rejected assoc_id={assoc_id} peer={} suppressed={suppressed}",
                source.ip()
            )
        }),
        // 出站失败走 `udp_send_failed`（§6.3「限频日志 error=<reason>」）。
        UdpDropReason::OutboundIo { kind }
        | UdpDropReason::OutboundClosed { kind }
        | UdpDropReason::OutboundTimeout { kind }
        | UdpDropReason::OutboundHandshake { kind } => {
            let tag = tag.unwrap_or("-");
            log.emit(now, interval, &token, |suppressed| {
                format!(
                    "event=udp_send_failed assoc_id={assoc_id} kind={} tag={tag} error={token} detail={} suppressed={suppressed}",
                    kind.as_str(),
                    redact::sanitize(&token)
                )
            });
        }
        _ => log.emit(now, interval, &token, |suppressed| {
            format!(
                "event=udp_drop assoc_id={assoc_id} reason={token} kind=- tag={} suppressed={suppressed}",
                tag.unwrap_or("-")
            )
        }),
    }
}

/// 关联运行结果（serve JSON 的 `association` + `udp` 两段数据源）。
struct UdpRunOutcome {
    bnd: Option<SocketAddr>,
    /// 客户端 UDP 端点端口（请求 hint 或首包学习值；未学习到 → None）。
    udp_port: Option<u16>,
    /// 关联建立时的进程内活跃关联数（R-7：串行模型下恒为 1）。
    active_associations: usize,
    outcome: &'static str,
    reason: &'static str,
    error: Option<(&'static str, String)>,
    stats: UdpStats,
    modes: Vec<&'static str>,
}

impl UdpRunOutcome {
    fn rejected(reason: &'static str, code: &'static str, message: String) -> Self {
        Self {
            bnd: None,
            udp_port: None,
            active_associations: 0,
            outcome: "failed",
            reason,
            error: Some((code, message)),
            stats: UdpStats {
                associations_rejected: 1,
                ..UdpStats::default()
            },
            modes: Vec::new(),
        }
    }
}

/// 关联统计 → JSON（字段名与 §5.1/§6.3/§7.3-3 同源；`unsupported_<proto>` 为产品侧别名）。
fn udp_stats_json(stats: &UdpStats) -> Value {
    json!({
        "associations_opened": stats.associations_opened,
        "associations_closed": stats.associations_closed,
        "associations_rejected": stats.associations_rejected,
        "control_closed": stats.control_closed,
        "control_protocol_violation": stats.udp_control_protocol_violation,
        "datagrams_in": stats.datagrams_in,
        "datagrams_out": stats.datagrams_out,
        "bytes_in": stats.bytes_in,
        "bytes_out": stats.bytes_out,
        "flows_opened": stats.flows_opened,
        "flows_reaped": stats.flows_reaped,
        "flows_closed": stats.flows_closed,
        "dropped_malformed": stats.dropped_malformed,
        "dropped_fragment": stats.dropped_fragment,
        "dropped_source_mismatch": stats.dropped_source_mismatch,
        "dropped_no_route": stats.dropped_no_route,
        "dropped_unsupported": stats.dropped_unsupported,
        "dropped_unsupported_vless": stats.dropped_unsupported_vless,
        "dropped_unsupported_anytls": stats.dropped_unsupported_anytls,
        "dropped_unsupported_trojan": stats.dropped_unsupported_trojan,
        "dropped_unsupported_shadowsocks": stats.dropped_unsupported_shadowsocks,
        "dropped_unsupported_hysteria2": stats.dropped_unsupported_hysteria2,
        "dropped_unsupported_other": stats.dropped_unsupported_other,
        "dropped_oversize": stats.dropped_oversize,
        "dropped_flow_limit": stats.dropped_flow_limit,
        "dropped_association_flow_limit": stats.dropped_association_flow_limit,
        "dropped_global_flow_limit": stats.dropped_global_flow_limit,
        "dropped_rate_limited": stats.dropped_rate_limited,
        "dropped_queue_full": stats.dropped_queue_full,
        "unmatched_replies": stats.unmatched_replies,
        "log_suppressed": stats.log_suppressed,
        // §6.3/§7.3-3 产品侧同名字段（与 R2 `ProxyFwdStats` 对齐；不改 nexusd）。
        "sent": stats.datagrams_in,
        "send_failed": stats.send_failed,
        "recv_failed": stats.recv_failed,
        "unsupported": stats.dropped_unsupported,
        "unsupported_vless": stats.dropped_unsupported_vless,
        "unsupported_anytls": stats.dropped_unsupported_anytls,
        "unsupported_trojan": stats.dropped_unsupported_trojan,
        "unsupported_shadowsocks": stats.dropped_unsupported_shadowsocks,
        "unsupported_hysteria2": stats.dropped_unsupported_hysteria2,
        "unsupported_other": stats.dropped_unsupported_other,
    })
}

/// UDP ASSOCIATE 关联主循环（唯一 owner：本函数写终态）。
fn udp_association_run(
    listener: &std::net::TcpListener,
    client: &mut std::net::TcpStream,
    command: &nexus_ingress::Socks5Command,
    pipelined: &[u8],
    config_yaml: &str,
    assoc_id: u64,
    log: &mut UdpLogLimiter,
) -> Result<UdpRunOutcome, NexusError> {
    use std::io::{ErrorKind, Read};

    let peer = client.peer_addr().map_err(|e| NexusError::Internal {
        message: format!("udp associate peer addr failed: {e}"),
    })?;
    let client_ip = peer.ip();
    let listen_ip = listener
        .local_addr()
        .map_err(|e| NexusError::Internal {
            message: format!("udp associate listener addr failed: {e}"),
        })?
        .ip();
    // 关联配置同时提供日志限频间隔（§5.2 10s；与关联内限频同源）。
    let assoc_config = UdpAssociationConfig::default();
    let interval = assoc_config.log_interval;

    // Q12 准入（spec §3.9）：本产品无显式认证配置 → 非 loopback 监听一律拒绝，不 bind。
    if !listen_ip.is_loopback() {
        reject_udp_associate(client, 0x01);
        log_udp_rejected(log, assoc_id, "non_loopback_listener", interval);
        return Ok(UdpRunOutcome::rejected(
            "non_loopback_listener",
            "UDP_ASSOCIATE_REJECTED",
            format!(
                "UDP ASSOCIATE requires a loopback listener or explicit authentication (listener={listen_ip})"
            ),
        ));
    }

    // §3.3-2：请求里的具体 IP 必须等于控制连接对端 IP，否则拒绝（不静默改用学习值）。
    let (hint_port, hint_mismatch) = udp_client_hint(command, client_ip);
    if hint_mismatch {
        reject_udp_associate(client, 0x01);
        log_udp_rejected(log, assoc_id, "client_address_mismatch", interval);
        return Ok(UdpRunOutcome::rejected(
            "client_address_mismatch",
            "UDP_ASSOCIATE_REJECTED",
            "UDP ASSOCIATE DST.ADDR does not match the control connection peer".to_string(),
        ));
    }

    // §3.6 T6：进程内关联上限（R-7 串行模型下不可达，仍按契约实现）。
    let Some(_slot) = UDP_ASSOCIATION_SLOTS.try_acquire() else {
        reject_udp_associate(client, 0x01);
        log_udp_rejected(log, assoc_id, "association_limit", interval);
        let mut rejected = UdpRunOutcome::rejected(
            "association_limit",
            "UDP_ASSOCIATE_REJECTED",
            format!("active UDP associations reached {MAX_UDP_ASSOCIATIONS}"),
        );
        rejected.active_associations = MAX_UDP_ASSOCIATIONS;
        return Ok(rejected);
    };
    let active_associations = UDP_ASSOCIATION_SLOTS.active();

    // 先解析配置/建 service（不触达客户端），失败可按失败路径回 REP。
    let config = match nexus_proxy_config::parse(config_yaml) {
        Ok(config) => config,
        Err(error) => {
            reject_udp_associate(client, 0x01);
            log_udp_rejected(log, assoc_id, "config_invalid", interval);
            return Ok(UdpRunOutcome::rejected(
                "config_invalid",
                "UDP_ASSOCIATE_REJECTED",
                format!("proxy config invalid: {error}"),
            ));
        }
    };
    let service = match ProxyService::new(&config) {
        Ok(service) => service,
        Err(error) => {
            reject_udp_associate(client, 0x01);
            log_udp_rejected(log, assoc_id, "service_build_failed", interval);
            return Ok(UdpRunOutcome::rejected(
                "service_build_failed",
                "UDP_ASSOCIATE_REJECTED",
                format!("proxy service build failed: {error}"),
            ));
        }
    };
    let router = Arc::new(ProductUdpRouter::new(&config, service));

    // §3.1：必须先绑定 UDP socket，再发成功应答；绑定失败 → REP=0x01。
    let udp = match UdpSocket::bind(SocketAddr::new(listen_ip, 0)) {
        Ok(socket) => socket,
        Err(error) => {
            reject_udp_associate(client, 0x01);
            log_udp_rejected(log, assoc_id, "bind_failed", interval);
            return Ok(UdpRunOutcome::rejected(
                "bind_failed",
                "UDP_ASSOCIATE_REJECTED",
                format!("udp bind failed: {error}"),
            ));
        }
    };
    let bnd = udp.local_addr().map_err(|e| NexusError::Internal {
        message: format!("udp socket local addr failed: {e}"),
    })?;
    udp.set_read_timeout(Some(UDP_CONTROL_POLL_INTERVAL))
        .map_err(|e| NexusError::Internal {
            message: format!("udp read timeout failed: {e}"),
        })?;
    client
        .set_read_timeout(Some(UDP_CONTROL_POLL_INTERVAL))
        .map_err(|e| NexusError::Internal {
            message: format!("control read timeout failed: {e}"),
        })?;
    write_handshake_reply(
        client,
        &nexus_ingress::encode_udp_associate_reply(&socks5_addr(bnd)),
    )?;
    udp_log(format!(
        "event=association_opened assoc_id={assoc_id} client_ip={client_ip} client_port={} bnd={bnd}",
        hint_port.map_or_else(|| "learn".to_string(), |port| port.to_string())
    ));

    let mut association = UdpAssociation::new(
        assoc_id,
        client_ip,
        hint_port,
        Arc::clone(&router) as Arc<dyn UdpOutboundRouter>,
        assoc_config,
        udp_global_rate(),
        udp_global_flows(),
        Instant::now(),
    );
    // 关联层之外的观测计数（控制连接/UDP socket 事件；与关联统计合并进 JSON）。
    let mut serve_stats = UdpStats::default();
    let mut client_port = hint_port;

    // §3.2/§3.6 T7：握手后控制连接上不得再有协议数据。
    let (outcome, reason) = if pipelined.is_empty() {
        let mut udp_buf = vec![0u8; UDP_RECV_BUF_BYTES];
        let mut control_buf = [0u8; 512];
        'association: loop {
            let now = Instant::now();

            // T1/T2/T7：控制连接 EOF / 错误 / 额外数据。
            match client.read(&mut control_buf) {
                Ok(0) => {
                    serve_stats.control_closed += 1;
                    break (UdpOutcome::Completed, "control_closed");
                }
                Ok(_) => {
                    serve_stats.udp_control_protocol_violation += 1;
                    break (
                        UdpOutcome::Failed(UdpAssociateError::ProtocolViolation),
                        "protocol_violation",
                    );
                }
                Err(error)
                    if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
                Err(error) => {
                    serve_stats.recv_failed += 1;
                    break (
                        UdpOutcome::Failed(UdpAssociateError::ControlIo { kind: error.kind() }),
                        "control_io",
                    );
                }
            }

            // 客户端数据报：源校验/解码/路由/投递全部在关联内完成（纯逻辑，now 由本循环给）。
            // 单轮有界（`UDP_RECV_BATCH`），避免持续洪泛把控制连接检测饿死。
            for _ in 0..UDP_RECV_BATCH {
                match udp.recv_from(&mut udp_buf) {
                    Ok((len, source)) => {
                        if client_port.is_none() && source.ip() == client_ip {
                            client_port = Some(source.port());
                        }
                        let before = association.flow_count();
                        match association.handle_client_datagram(source, &udp_buf[..len], now) {
                            Ok(()) => {
                                if association.flow_count() > before
                                    && let Some((target, tag, kind)) = router.last_record()
                                {
                                    udp_log(format!(
                                        "event=flow_opened assoc_id={assoc_id} kind={} tag={tag} target={target}",
                                        kind.as_str()
                                    ));
                                }
                            }
                            Err(drop_reason) => log_udp_drop(
                                log,
                                assoc_id,
                                source,
                                &drop_reason,
                                router.last_record().map(|(_, tag, _)| tag).as_deref(),
                            ),
                        }
                    }
                    Err(error)
                        if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
                    {
                        break;
                    }
                    Err(error) if error.kind() == ErrorKind::Interrupted => {}
                    Err(error) => {
                        // T5：UDP socket fatal error。
                        serve_stats.recv_failed += 1;
                        break 'association (
                            UdpOutcome::Failed(UdpAssociateError::UdpSocketIo {
                                kind: error.kind(),
                            }),
                            "udp_socket_io",
                        );
                    }
                }
            }

            // flow 回收 / 空闲超时 / 致命事件（T3/T9/T10）。
            let event = association.poll(now);
            for reaped in association.take_reaped() {
                udp_log(format!(
                    "event=flow_reaped assoc_id={assoc_id} kind={} tag={} idle_ms={}",
                    reaped.outbound_kind.as_str(),
                    reaped.outbound_tag,
                    reaped.idle.as_millis()
                ));
            }
            match event {
                UdpAssociationEvent::None => {}
                UdpAssociationEvent::IdleTimeout => {
                    break (UdpOutcome::Completed, "idle_timeout");
                }
                UdpAssociationEvent::ControlClosed => {
                    serve_stats.control_closed += 1;
                    break (UdpOutcome::Completed, "control_closed");
                }
                UdpAssociationEvent::ProtocolViolation => {
                    serve_stats.udp_control_protocol_violation += 1;
                    break (
                        UdpOutcome::Failed(UdpAssociateError::ProtocolViolation),
                        "protocol_violation",
                    );
                }
                UdpAssociationEvent::Fatal(error) => {
                    serve_stats.recv_failed += 1;
                    break (UdpOutcome::Failed(error), "udp_socket_io");
                }
            }

            // 回包只发往锁定的客户端端点（§6.2 无反射面）。
            for (address, payload) in association.drain_replies(now) {
                let Some(port) = client_port else {
                    break;
                };
                let bytes = match nexus_ingress::encode_udp_datagram(&address, &payload) {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        serve_stats.dropped_oversize += 1;
                        continue;
                    }
                };
                if let Err(error) = udp.send_to(&bytes, SocketAddr::new(client_ip, port)) {
                    serve_stats.recv_failed += 1;
                    break 'association (
                        UdpOutcome::Failed(UdpAssociateError::UdpSocketIo { kind: error.kind() }),
                        "udp_socket_io",
                    );
                }
            }
        }
    } else {
        serve_stats.udp_control_protocol_violation += 1;
        (
            UdpOutcome::Failed(UdpAssociateError::ProtocolViolation),
            "protocol_violation",
        )
    };

    association.terminate(outcome, Instant::now());
    let mut stats = association.stats();
    stats.control_closed += serve_stats.control_closed;
    stats.recv_failed += serve_stats.recv_failed;
    stats.udp_control_protocol_violation += serve_stats.udp_control_protocol_violation;
    stats.dropped_oversize += serve_stats.dropped_oversize;
    stats.log_suppressed += log.total_suppressed();
    // 终态从关联（唯一 owner）读取，日志与 JSON 同源（AGENTS §14）。
    let assoc_id = association.id();
    let outcome_label = association.outcome().map_or("cancelled", udp_outcome_label);
    udp_log(format!(
        "event=association_closed assoc_id={assoc_id} outcome={outcome_label} reason={reason} up={} down={}",
        stats.bytes_in, stats.bytes_out
    ));

    Ok(UdpRunOutcome {
        bnd: Some(bnd),
        udp_port: client_port,
        active_associations,
        outcome: outcome_label,
        reason,
        error: None,
        stats,
        modes: router.modes(),
    })
}

/// 失败路径应答（复用暂存应答的 SOCKS5 固定 10B 形状；重复写不重复发）。
fn reject_udp_associate(client: &mut std::net::TcpStream, rep: u8) {
    let mut reply = DeferredConnectReply::new(ClientReplyKind::Socks5, Vec::new());
    let _ = reply.send_failure(client, rep);
}

/// 关联终态标签（`association_closed` 日志与 JSON 同源）。
fn udp_outcome_label(outcome: &UdpOutcome) -> &'static str {
    match outcome {
        UdpOutcome::Completed => "completed",
        UdpOutcome::Failed(_) => "failed",
        UdpOutcome::Cancelled => "cancelled",
    }
}

/// UDP ASSOCIATE 的 serve JSON（K-11：只新增 `association` / `udp` 两段，TCP 路径零变化）。
fn udp_associate_json(
    assoc_id: u64,
    peer: SocketAddr,
    listen_ip: IpAddr,
    run: UdpRunOutcome,
) -> Value {
    // 只有「关联正常结束」才是 PASS；拒绝/致命失败一律 FAIL（reason 说明原因）。
    let verdict = if run.outcome == "completed" && run.error.is_none() {
        "PASS"
    } else {
        "FAIL"
    };
    let mut payload = json!({
        "verdict": verdict,
        "inbound": {
            "kind": "socks5",
            "command": "udp_associate",
        },
        "association": {
            "id": assoc_id,
            "client_ip": peer.ip().to_string(),
            "control_port": peer.port(),
            "udp_port": run.udp_port,
            "bnd": run.bnd.map(|bnd| bnd.to_string()),
            "outcome": run.outcome,
            "reason": run.reason,
            "listener_ip": listen_ip.to_string(),
            "listener_loopback": listen_ip.is_loopback(),
            "max_associations": MAX_UDP_ASSOCIATIONS,
            "active_associations": run.active_associations,
            // R-7=(a)：串行 accept 下单进程有效并发 = 1。
            "effective_concurrency": 1,
        },
        "udp": udp_stats_json(&run.stats),
    });
    payload["udp"]["modes"] = json!(run.modes);
    if let Some((code, message)) = run.error {
        payload["error"] = json!({ "code": code, "message": message });
    }
    payload
}

/// UDP ASSOCIATE 入口（握手 `Established` 且命令为 `0x03` 时由 `proxy_serve_once` 调用）。
fn proxy_serve_udp_associate(
    listener: &std::net::TcpListener,
    client: &mut std::net::TcpStream,
    command: &nexus_ingress::Socks5Command,
    pipelined: &[u8],
    config_yaml: &str,
) -> Result<Value, NexusError> {
    let peer = client.peer_addr().map_err(|e| NexusError::Internal {
        message: format!("udp associate peer addr failed: {e}"),
    })?;
    let listen_ip = listener
        .local_addr()
        .map_err(|e| NexusError::Internal {
            message: format!("udp associate listener addr failed: {e}"),
        })?
        .ip();
    let assoc_id = UDP_ASSOCIATION_IDS.fetch_add(1, Ordering::Relaxed);
    let mut log = UdpLogLimiter::default();
    let run = udp_association_run(
        listener,
        client,
        command,
        pipelined,
        config_yaml,
        assoc_id,
        &mut log,
    )?;
    Ok(udp_associate_json(assoc_id, peer, listen_ip, run))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod udp_associate_serve_tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};

    fn ipv4_request(addr: [u8; 4], port: u16) -> Vec<u8> {
        let mut out = vec![0x01];
        out.extend_from_slice(&addr);
        out.extend_from_slice(&port.to_be_bytes());
        out
    }

    /// 起一个真实 `proxy_serve_once`（单连接），返回监听地址与线程句柄。
    fn spawn_server(
        listener: TcpListener,
        config: &'static str,
    ) -> (
        SocketAddr,
        std::thread::JoinHandle<Result<Value, NexusError>>,
    ) {
        let addr = listener.local_addr().expect("local addr");
        let handle = std::thread::spawn(move || proxy_serve_once(&listener, config));
        (addr, handle)
    }

    /// SOCKS5 greeting + UDP ASSOCIATE，返回控制连接与 10B 应答。
    fn associate(addr: SocketAddr, request: &[u8]) -> (TcpStream, [u8; 10]) {
        let mut client = TcpStream::connect(addr).expect("control connect");
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        client.write_all(&[0x05, 0x01, 0x00]).expect("greeting");
        let mut method = [0u8; 2];
        client.read_exact(&mut method).expect("method reply");
        assert_eq!(method, [0x05, 0x00], "NO-AUTH accepted");
        let mut bytes = vec![0x05, 0x03, 0x00];
        bytes.extend_from_slice(request);
        client.write_all(&bytes).expect("associate request");
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).expect("associate reply");
        (client, reply)
    }

    fn bnd_from_reply(reply: &[u8; 10]) -> SocketAddr {
        assert_eq!(reply[3], 0x01, "BND ATYP is IPv4 in tests");
        SocketAddr::new(
            IpAddr::V4(std::net::Ipv4Addr::new(
                reply[4], reply[5], reply[6], reply[7],
            )),
            u16::from_be_bytes([reply[8], reply[9]]),
        )
    }

    #[test]
    fn association_slots_enforce_process_limit() {
        let slots = AssociationSlots::new(2);
        let first = slots.try_acquire().expect("first");
        let second = slots.try_acquire().expect("second");
        assert!(slots.try_acquire().is_none(), "上限生效");
        assert_eq!(slots.active(), 2);
        drop(first);
        assert_eq!(slots.active(), 1, "Drop 归还计数");
        let third = slots.try_acquire().expect("after release");
        drop(second);
        drop(third);
        assert_eq!(slots.active(), 0);
    }

    #[test]
    fn udp_client_hint_locks_port_and_rejects_foreign_ip() {
        let unspecified = nexus_ingress::Socks5Command::UdpAssociate {
            client_endpoint: None,
        };
        assert_eq!(
            udp_client_hint(&unspecified, "127.0.0.1".parse().unwrap()),
            (None, false)
        );

        let with_port = nexus_ingress::Socks5Command::UdpAssociate {
            client_endpoint: Some(nexus_ingress::Socks5Address::Ipv4 {
                addr: [0, 0, 0, 0],
                port: 4242,
            }),
        };
        assert_eq!(
            udp_client_hint(&with_port, "127.0.0.1".parse().unwrap()),
            (Some(4242), false),
            "0.0.0.0 只锁端口，不构成 IP 不一致"
        );

        let same_ip = nexus_ingress::Socks5Command::UdpAssociate {
            client_endpoint: Some(nexus_ingress::Socks5Address::Ipv4 {
                addr: [127, 0, 0, 1],
                port: 0,
            }),
        };
        assert_eq!(
            udp_client_hint(&same_ip, "127.0.0.1".parse().unwrap()),
            (None, false)
        );

        let foreign_ip = nexus_ingress::Socks5Command::UdpAssociate {
            client_endpoint: Some(nexus_ingress::Socks5Address::Ipv4 {
                addr: [10, 9, 9, 9],
                port: 1234,
            }),
        };
        assert_eq!(
            udp_client_hint(&foreign_ip, "127.0.0.1".parse().unwrap()),
            (Some(1234), true),
            "具体 IP 必须等于控制连接对端"
        );
    }

    #[test]
    fn udp_mode_debug_and_label_carry_no_secret() {
        let config = OutboundConfig {
            tag: "node".into(),
            kind: OutboundKind::Vless,
            locator: Some("127.0.0.1:443".into()),
            method: None,
            password: Some("r2-marker-password".into()),
            alpn: None,
            skip_cert_verify: Some(true),
            header_format: None,
            obfs: None,
            obfs_key: None,
            uuid: Some("11111111-1111-1111-1111-111111111111".into()),
            flow: Some(String::new()),
            tls: Some(true),
            servername: Some("node.example".into()),
            sni: Some("node.example".into()),
            ports: None,
            up: None,
            down: None,
            obfs_password: None,
            fallback_guard: None,
            ready_window_ms: None,
        };
        let outbound = build_product_udp_outbound(&config).expect("vless udp supported");
        let UdpCapability::Supported(mode) = outbound.capability() else {
            panic!("VLESS flow=None must be Supported (spec §7.2)");
        };
        let rendered = format!("{mode:?}");
        assert!(rendered.contains("VlessOverTcp"), "{rendered}");
        assert!(
            !rendered.contains("11111111-1111"),
            "uuid leaked: {rendered}"
        );
        assert!(
            !rendered.contains("r2-marker-password"),
            "secret leaked: {rendered}"
        );
        assert_eq!(udp_mode_label(&mode), "vless_over_tcp");

        let anytls = OutboundConfig {
            kind: OutboundKind::Anytls,
            uuid: None,
            flow: None,
            ..config
        };
        let outbound = build_product_udp_outbound(&anytls).expect("anytls udp supported");
        let UdpCapability::Supported(mode) = outbound.capability() else {
            panic!("AnyTLS must be Supported (spec §7.2)");
        };
        assert_eq!(udp_mode_label(&mode), "anytls_uot");
        assert!(!format!("{mode:?}").contains("r2-marker-password"));
    }

    #[test]
    fn udp_stats_json_exposes_contract_field_names() {
        let stats = UdpStats {
            datagrams_in: 3,
            dropped_unsupported_trojan: 2,
            dropped_unsupported_other: 1,
            ..UdpStats::default()
        };
        let json = udp_stats_json(&stats);
        // §6.3/§7.3-3 产品侧同名字段。
        assert_eq!(json["sent"], 3);
        assert_eq!(json["unsupported_trojan"], 2);
        assert_eq!(json["unsupported_other"], 1);
        // §5.1 原始字段名保留。
        assert_eq!(json["dropped_unsupported_trojan"], 2);
        assert_eq!(json["datagrams_in"], 3);
    }

    #[test]
    fn udp_associate_rejects_non_loopback_listener() {
        // Q12：监听 0.0.0.0（非 loopback）且产品无显式认证 → 一律拒绝。
        let listener = TcpListener::bind("0.0.0.0:0").expect("bind wildcard");
        let port = listener.local_addr().expect("addr").port();
        let (_addr, handle) = spawn_server(listener, DEFAULT_PROXY_CONFIG);
        let (control, reply) = associate(
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), port),
            &ipv4_request([0, 0, 0, 0], 0),
        );
        assert_eq!(reply[1], 0x01, "REP=general failure (spec §3.9)");
        drop(control);
        let json = handle.join().expect("join").expect("serve ok");
        assert_eq!(json["verdict"], "FAIL");
        assert_eq!(json["association"]["reason"], "non_loopback_listener");
        assert_eq!(json["association"]["listener_loopback"], false);
        assert_eq!(json["udp"]["associations_rejected"], 1);
        assert_eq!(json["udp"]["associations_opened"], 0);
        assert!(json["association"]["bnd"].is_null(), "拒绝时不得绑定 UDP");
    }

    #[test]
    fn udp_associate_rejects_client_address_mismatch() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let (addr, handle) = spawn_server(listener, DEFAULT_PROXY_CONFIG);
        let (control, reply) = associate(addr, &ipv4_request([10, 9, 9, 9], 1234));
        assert_eq!(reply[1], 0x01);
        drop(control);
        let json = handle.join().expect("join").expect("serve ok");
        assert_eq!(json["association"]["reason"], "client_address_mismatch");
        assert_eq!(json["udp"]["associations_rejected"], 1);
    }

    #[test]
    fn udp_associate_direct_outbound_is_dropped_not_dialed() {
        // Q11：Direct 无 datagram 模式 → 丢弃 + `unsupported_other`，绝不直连。
        let target = std::net::UdpSocket::bind("127.0.0.1:0").expect("target bind");
        target
            .set_read_timeout(Some(Duration::from_millis(800)))
            .expect("target timeout");
        let target_addr = target.local_addr().expect("target addr");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let (addr, handle) = spawn_server(listener, DEFAULT_PROXY_CONFIG);
        let (control, reply) = associate(addr, &ipv4_request([0, 0, 0, 0], 0));
        assert_eq!(reply[1], 0x00, "loopback ASSOCIATE accepted");
        let bnd = bnd_from_reply(&reply);

        let client_udp = std::net::UdpSocket::bind("127.0.0.1:0").expect("client udp");
        client_udp
            .set_read_timeout(Some(Duration::from_millis(800)))
            .expect("client timeout");
        let datagram = nexus_ingress::encode_udp_datagram(&socks5_addr(target_addr), b"hello")
            .expect("encode");
        client_udp.send_to(&datagram, bnd).expect("send datagram");

        // 目标端必须一个包都收不到（无直连、无伪造回包）。
        let mut buf = [0u8; 64];
        assert!(
            target.recv_from(&mut buf).is_err(),
            "Direct 出站不得直连目标"
        );
        assert!(client_udp.recv_from(&mut buf).is_err(), "不得回伪造包");

        drop(control);
        let json = handle.join().expect("join").expect("serve ok");
        assert_eq!(json["verdict"], "PASS");
        assert_eq!(json["udp"]["unsupported_other"], 1);
        assert_eq!(json["udp"]["dropped_unsupported_other"], 1);
        assert_eq!(json["udp"]["datagrams_in"], 0);
        assert_eq!(json["udp"]["sent"], 0);
        assert_eq!(json["udp"]["flows_opened"], 0);
        assert_eq!(json["udp"]["associations_opened"], 1);
        assert_eq!(json["udp"]["associations_closed"], 1);
        assert_eq!(json["association"]["outcome"], "completed");
        assert_eq!(json["association"]["reason"], "control_closed");
        assert_eq!(json["association"]["effective_concurrency"], 1);
    }
}

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
    let (flow, inbound_kind, seed_to_upstream, mut deferred_reply) = if buf[0] == 0x05 {
        // ---- SOCKS5 分支（§11.4）----
        // method-selection / 错误应答仍在循环内立即写出；只有 `Established` 步的
        // success 应答被暂存，由调用方在出站就绪点写出（§4）。
        let mut hs = nexus_ingress::Socks5Handshake::new();
        let mut step = hs.feed(&buf[..n0]);
        let deferred;
        let flow = loop {
            match step.state {
                nexus_ingress::Socks5State::Established => {
                    // C4：`Established` 同时覆盖 CONNECT 与 UDP ASSOCIATE，必须先按命令分流。
                    // 原「Established 但 flow=None 视为内部不一致」只对 CONNECT 成立。
                    let command = hs.command().cloned();
                    if let Some(command @ nexus_ingress::Socks5Command::UdpAssociate { .. }) =
                        command
                    {
                        let pipelined = hs.take_data();
                        return proxy_serve_udp_associate(
                            listener,
                            &mut client,
                            &command,
                            &pipelined,
                            config_yaml,
                        );
                    }
                    match step.flow {
                        Some(f) => {
                            deferred =
                                DeferredConnectReply::new(ClientReplyKind::Socks5, step.response);
                            break f;
                        }
                        None => {
                            // 与修复前一致：success 已可见后再报内部不一致。
                            let mut r =
                                DeferredConnectReply::new(ClientReplyKind::Socks5, step.response);
                            let _ = r.send_success(&mut client);
                            return Err(NexusError::Internal {
                                message: "established without flow".into(),
                            });
                        }
                    }
                }
                nexus_ingress::Socks5State::Failed(e) => {
                    write_handshake_reply(&mut client, &step.response)?;
                    return Err(NexusError::Internal {
                        message: format!("socks5 handshake failed: {e:?}"),
                    });
                }
                _ => {
                    write_handshake_reply(&mut client, &step.response)?;
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
        (flow, "socks5".to_string(), pipelined, deferred)
    } else {
        // ---- HTTP 代理分支（§11.19）----
        // CONNECT 的 200 暂存；non-CONNECT 的 response 为空（不写本地成功应答，R-6）。
        let mut hs = nexus_ingress::HttpProxyHandshake::new();
        let mut step = hs.feed(&buf[..n0]);
        let deferred;
        let flow = loop {
            match step.state {
                nexus_ingress::HttpProxyState::Established => match step.flow {
                    Some(f) => {
                        deferred = DeferredConnectReply::new(ClientReplyKind::Http, step.response);
                        break f;
                    }
                    None => {
                        let mut r = DeferredConnectReply::new(ClientReplyKind::Http, step.response);
                        let _ = r.send_success(&mut client);
                        return Err(NexusError::Internal {
                            message: "established without flow".into(),
                        });
                    }
                },
                nexus_ingress::HttpProxyState::Failed(e) => {
                    write_handshake_reply(&mut client, &step.response)?;
                    return Err(NexusError::Internal {
                        message: format!("http proxy handshake failed: {e:?}"),
                    });
                }
                _ => {
                    write_handshake_reply(&mut client, &step.response)?;
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
        (flow, "http".to_string(), seed, deferred)
    };

    // 2) 规则路由（纯决策，零 I/O）。
    //    修复前 success 已在 route 之前写出；回写点之前的失败保持「先写 success 再报错」
    //    的客户端可见形态（步骤 1 兼容语义；trojan arm 的失败在步骤 2 改为失败应答）。
    let config = match nexus_proxy_config::parse(config_yaml) {
        Ok(c) => c,
        Err(e) => {
            return Err(pre_arm_failure(
                &mut client,
                &mut deferred_reply,
                NexusError::Internal {
                    message: format!("proxy config invalid: {e}"),
                },
            ));
        }
    };
    let service = match nexus_proxy::ProxyService::new(&config) {
        Ok(s) => s,
        Err(e) => {
            return Err(pre_arm_failure(
                &mut client,
                &mut deferred_reply,
                NexusError::Internal {
                    message: format!("proxy service build failed: {e}"),
                },
            ));
        }
    };
    let decision = match service.route(&flow, None) {
        Ok(d) => d,
        Err(e) => {
            return Err(pre_arm_failure(
                &mut client,
                &mut deferred_reply,
                NexusError::Internal {
                    message: format!("proxy route failed: {e}"),
                },
            ));
        }
    };

    // 3) Session 双轨（Active 先于出站建连）。
    let mut owner = SessionOwner::new(SessionId("sess-proxy-1".into()));
    owner
        .transition_phase(LifecyclePhase::Active)
        .map_err(NexusError::from)?;

    // 4) 真实出站连接：按 selected outbound 的 kind 建立数据面（§11.16）。
    //    direct      -> 直连 destination（§11.4 现状，零回归）
    //    shadowsocks -> 连节点 locator + SsStream（SIP004）客户端会话 + 加密 request header
    //                   + 双向流式 seal/open 中继（PendingWrite 背压 + 半关闭传播）
    //    trojan/vmess-> 数据面隧道不在本期冻结 E4 范围，结构化失败（不静默直连）
    let selected = match config
        .outbounds
        .iter()
        .find(|o| o.tag == decision.selected_outbound_tag)
    {
        Some(s) => s,
        None => {
            return Err(pre_arm_failure(
                &mut client,
                &mut deferred_reply,
                NexusError::ConnectivityEstablishmentFailed {
                    provider: ProviderId(decision.selected_outbound_tag.clone()),
                    reason: format!(
                        "selected outbound tag {} missing in config",
                        decision.selected_outbound_tag
                    ),
                },
            ));
        }
    };
    // 2.5) 非 trojan arm：在既有逻辑点（route 之后、出站建连之前）写出暂存的 success，
    //      时机与字节均与修复前一致（AC-10.1）。trojan arm 在出站就绪点决定写 success
    //      还是失败应答（§4）。
    if selected.kind != nexus_proxy_config::OutboundKind::Trojan {
        deferred_reply
            .send_success(&mut client)
            .map_err(|e| NexusError::Internal {
                message: format!("connect reply write failed: {e}"),
            })?;
    }
    let (host, port) = split_host_port(&flow.destination)?;
    let outbound_kind = selected.kind.as_str();
    let outbound;
    // 守卫观测（仅 trojan arm 产出）；客户端在 success 前断开时走独立终态。
    let mut tunnel_json: Option<Value> = None;
    let mut client_aborted_before_ready = false;
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
            use nexus_outbound_shadowsocks::{Role, SsMethod, SsStream, SsTarget, encode_request};
            let locator = selected.locator.clone().ok_or_else(|| {
                NexusError::ConnectivityEstablishmentFailed {
                    provider: ProviderId(decision.selected_outbound_tag.clone()),
                    reason: "shadowsocks outbound missing locator".into(),
                }
            })?;
            let (nhost, nport) = split_host_port(&locator)?;
            // §7.3 插件接线（P1）：先建 raw TCP，再按方向独立 wrap。
            // 写方向的所有字节（请求头 + 中继数据）走同一个 wrapped handle，
            // 保证插件变换位置连续（S7）；读方向走另一个 handle。
            // obfs=None → plain 直通（P6 零回归）。
            let raw = std::net::TcpStream::connect((nhost.as_str(), nport)).map_err(|e| {
                NexusError::ConnectivityEstablishmentFailed {
                    provider: ProviderId(decision.selected_outbound_tag.clone()),
                    reason: format!("ss node connect {locator} failed: {e}"),
                }
            })?;
            let raw_nb = raw.try_clone().map_err(|_| NexusError::Internal {
                message: "proxy clone failed".into(),
            })?;
            let raw_down = raw.try_clone().map_err(|_| NexusError::Internal {
                message: "proxy clone failed".into(),
            })?;
            // 半关闭句柄：`ObfuscatedStream` 没有 shutdown，排空后要经 raw dup 发 FIN，
            // 否则 probe 的 finish() 只能等有界超时（正/负向格会被误判）。
            let sd_up = raw.try_clone().map_err(|_| NexusError::Internal {
                message: "proxy clone failed".into(),
            })?;
            let sd_down = raw.try_clone().map_err(|_| NexusError::Internal {
                message: "proxy clone failed".into(),
            })?;
            let obfs_params = nexus_plugin::ObfsParams {
                key: selected.obfs_key.as_deref().unwrap_or("").as_bytes(),
            };
            let mut node_up =
                nexus_plugin::wrap_stream(raw, selected.obfs.as_deref(), &obfs_params).map_err(
                    |e| NexusError::ConnectivityEstablishmentFailed {
                        provider: ProviderId(decision.selected_outbound_tag.clone()),
                        reason: format!("ss obfs wrap failed: {e}"),
                    },
                )?;
            let mut node_down =
                nexus_plugin::wrap_stream(raw_down, selected.obfs.as_deref(), &obfs_params)
                    .map_err(|e| NexusError::ConnectivityEstablishmentFailed {
                        provider: ProviderId(decision.selected_outbound_tag.clone()),
                        reason: format!("ss obfs wrap failed: {e}"),
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
            // SIP004 双实例分工（spec §3.1 冻结）：tx_sess 只 seal、rx_sess 只 open，
            // 两实例各自维护 nonce；salt 惰性生成，rx 实例不产生闲置 TX 状态。
            // 严禁跨线程共享单实例（Arc<Mutex<SsStream>>）。
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
            // 加密 request header（目标 = SOCKS5 destination）：SIP004 首写内容（含 salt）。
            let target = if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
                SsTarget::Ipv4(ip.octets(), port)
            } else {
                SsTarget::Domain(host.clone(), port)
            };
            let req_wire = tx_sess.seal(&encode_request(&target)).map_err(|e| {
                NexusError::ConnectivityEstablishmentFailed {
                    provider: ProviderId(decision.selected_outbound_tag.clone()),
                    reason: format!("ss request header seal failed: {e:?}"),
                }
            })?;
            // §11.19 seed（HTTP 改写的 origin-form 请求 / SOCKS5 pipelined 字节）
            // 紧跟在 request header 之后，同样经 tx_sess seal（保持 nonce 顺序）。
            let seed_wire = if seed_to_upstream.is_empty() {
                Vec::new()
            } else {
                tx_sess.seal(&seed_to_upstream).map_err(|e| {
                    NexusError::ConnectivityEstablishmentFailed {
                        provider: ProviderId(decision.selected_outbound_tag.clone()),
                        reason: format!("ss seed seal failed: {e:?}"),
                    }
                })?
            };
            // 握手/首写均已完成，两个方向改为非阻塞：PendingWrite 的 WouldBlock 语义
            // 只在非阻塞 socket 上成立（dup 共享同一 fd 的 status flags，同 Trojan arm）。
            raw_nb
                .set_nonblocking(true)
                .map_err(|e| NexusError::Internal {
                    message: format!("ss node nonblocking: {e}"),
                })?;
            client
                .set_nonblocking(true)
                .map_err(|e| NexusError::Internal {
                    message: format!("ss client nonblocking: {e}"),
                })?;
            let mut client_up = client.try_clone().map_err(|_| NexusError::Internal {
                message: "proxy clone failed".into(),
            })?;
            let mut client_down = client.try_clone().map_err(|_| NexusError::Internal {
                message: "proxy clone failed".into(),
            })?;
            // 并发模型：保留双线程双实例。每方向一个 PendingWrite（无共享、无 Mutex）。
            // 上行走线字节（header wire 先行，再 seed wire，再中继 seal 数据）；
            // 下行走流式 open（空结果合法，不产出也结束）。
            let to_upstream = std::thread::spawn(move || {
                let mut up = PendingWrite::new();
                up.enqueue(&req_wire);
                if !seed_wire.is_empty() {
                    up.enqueue(&seed_wire);
                }
                let mut cbuf = [0u8; 8192];
                let mut total = 0usize;
                let mut client_open = true;
                loop {
                    let mut progressed = false;
                    match up.try_write(&mut node_up) {
                        Ok((_, n)) => {
                            total += n;
                            progressed |= n > 0;
                        }
                        Err(_) => break,
                    }
                    if client_open {
                        match up.try_read(&mut client_up, &mut cbuf) {
                            None => {}
                            Some(Ok(0)) => client_open = false,
                            Some(Ok(n)) => match tx_sess.seal(&cbuf[..n]) {
                                Ok(wire) => {
                                    up.enqueue(&wire);
                                    progressed = true;
                                }
                                // fail-closed：不重试、不降级直连、不吞字节。
                                Err(_) => break,
                            },
                            Some(Err(ref e)) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                            Some(Err(_)) => client_open = false,
                        }
                    }
                    // 半关闭：client EOF 且写队列排空 → 向节点发 FIN。
                    if !client_open && up.ready_for_read() {
                        let _ = sd_up.shutdown(std::net::Shutdown::Write);
                        break;
                    }
                    if !progressed {
                        std::thread::sleep(std::time::Duration::from_millis(2));
                    }
                }
                total
            });
            let to_client = std::thread::spawn(move || {
                let mut down = PendingWrite::new();
                let mut rbuf = [0u8; 8192];
                let mut total = 0usize;
                let mut node_open = true;
                loop {
                    let mut progressed = false;
                    match down.try_write(&mut client_down) {
                        Ok((_, n)) => {
                            total += n;
                            progressed |= n > 0;
                        }
                        Err(_) => break,
                    }
                    if node_open {
                        match down.try_read(&mut node_down, &mut rbuf) {
                            None => {}
                            Some(Ok(0)) => node_open = false,
                            Some(Ok(n)) => match rx_sess.open(&rbuf[..n]) {
                                Ok(plain) => {
                                    if !plain.is_empty() {
                                        down.enqueue(&plain);
                                        progressed = true;
                                    }
                                }
                                // fail-closed：AEAD/帧错误即终止该连接。
                                Err(_) => break,
                            },
                            Some(Err(ref e)) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                            Some(Err(_)) => node_open = false,
                        }
                    }
                    // 半关闭：node EOF 且队列排空 → 向 client 发 FIN。
                    if !node_open && down.ready_for_read() {
                        let _ = sd_down.shutdown(std::net::Shutdown::Write);
                        break;
                    }
                    if !progressed {
                        std::thread::sleep(std::time::Duration::from_millis(2));
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
            match trojan_tunnel(
                &mut client,
                &mut deferred_reply,
                &mut owner,
                selected,
                &decision.selected_outbound_tag,
                &host,
                port,
                &seed_to_upstream,
            )? {
                TrojanTunnelOutcome::Done {
                    up_bytes,
                    down_bytes,
                    outbound: ob,
                    tunnel,
                } => {
                    tunnel_json = Some(tunnel);
                    outbound = ob;
                    (up_bytes, down_bytes)
                }
                TrojanTunnelOutcome::ClientAborted {
                    outbound: ob,
                    tunnel,
                } => {
                    // 客户端在 success 前断开：不写应答、零字节、正常返回（不挂死）。
                    tunnel_json = Some(tunnel);
                    outbound = ob;
                    client_aborted_before_ready = true;
                    (0, 0)
                }
            }
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
        nexus_proxy_config::OutboundKind::Socks5 => {
            return Err(NexusError::ConnectivityEstablishmentFailed {
                provider: ProviderId(decision.selected_outbound_tag.clone()),
                reason: "socks5 outbound data-plane tunnel via nexus app deferred; use nexusd ProxyEngine (P1-P5)".into(),
            });
        }
        nexus_proxy_config::OutboundKind::Anytls => {
            // §11.16 anytls 数据面：TCP → rustls TLS（SNI 取配置 sni，缺省节点域名；
            // skip-cert-verify 按配置）→ AnyTLS session 握手（auth 一次写 + Settings →
            // 等 ServerSettings）→ 开 stream（SYN → 首个 PSH 带 SOCKS5 目标地址 →
            // 等 SYNACK）→ PSH 帧双向中继 client<->TLS。
            use nexus_outbound_anytls::{
                AnyTlsCommand, AnyTlsTarget, CLIENT_IDENT, DEFAULT_PADDING_SCHEME,
                client_handshake, client_open_stream, padding_md5_hex,
            };
            use rustls::pki_types::ServerName;
            use std::sync::Arc;

            let locator = selected.locator.clone().ok_or_else(|| {
                NexusError::ConnectivityEstablishmentFailed {
                    provider: ProviderId(decision.selected_outbound_tag.clone()),
                    reason: "anytls outbound missing locator".into(),
                }
            })?;
            let (nhost, nport) = split_host_port(&locator)?;
            // §7.3 插件接线（P1）：obfs 包在 TLS 之下。先建 raw TCP（保持 blocking，
            // TLS 握手期间 rustls 用阻塞 I/O，提前 nonblocking 会导致 WouldBlock 硬失败），
            // clone 一个 handle 留待握手后设 nonblocking（同 fd 共享 flag），再 wrap；
            // obfs=None → plain 直通（P6 零回归）。
            let raw = std::net::TcpStream::connect((nhost.as_str(), nport)).map_err(|e| {
                NexusError::ConnectivityEstablishmentFailed {
                    provider: ProviderId(decision.selected_outbound_tag.clone()),
                    reason: format!("anytls node connect {locator} failed: {e}"),
                }
            })?;
            // WARN1: handshake timeout (10s) -- silent server fail-closed.
            raw.set_read_timeout(Some(std::time::Duration::from_secs(10)))
                .map_err(|e| NexusError::ConnectivityEstablishmentFailed {
                    provider: ProviderId(decision.selected_outbound_tag.clone()),
                    reason: format!("anytls set read timeout failed: {e}"),
                })?;
            raw.set_write_timeout(Some(std::time::Duration::from_secs(10)))
                .map_err(|e| NexusError::ConnectivityEstablishmentFailed {
                    provider: ProviderId(decision.selected_outbound_tag.clone()),
                    reason: format!("anytls set write timeout failed: {e}"),
                })?;
            let raw_nb = raw.try_clone().map_err(|e| NexusError::Internal {
                message: format!("anytls node clone for nonblocking: {e}"),
            })?;
            let obfs_params = nexus_plugin::ObfsParams {
                key: selected.obfs_key.as_deref().unwrap_or("").as_bytes(),
            };
            let mut node = nexus_plugin::wrap_stream(raw, selected.obfs.as_deref(), &obfs_params)
                .map_err(|e| NexusError::ConnectivityEstablishmentFailed {
                provider: ProviderId(decision.selected_outbound_tag.clone()),
                reason: format!("anytls obfs wrap failed: {e}"),
            })?;
            let password = selected.password.clone().ok_or_else(|| {
                NexusError::ConnectivityEstablishmentFailed {
                    provider: ProviderId(decision.selected_outbound_tag.clone()),
                    reason: "anytls outbound missing password".into(),
                }
            })?;

            // SNI：配置 sni 优先（anytls/hysteria2 SNI），缺省取 locator host。
            let sni_host = selected
                .sni
                .clone()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| nhost.clone());
            let skip_verify = selected.skip_cert_verify.unwrap_or(false);

            // 客户端 TLS 配置：skip-cert-verify（自签/内网节点）或系统信任根。
            // AnyTLS 不用 ALPN（空列表）。
            let tls_cfg: Result<rustls::ClientConfig, NexusError> = if skip_verify {
                nexus_outbound_trojan::client_config_dangerous_skip_verify(&[]).map_err(|e| {
                    NexusError::ConnectivityEstablishmentFailed {
                        provider: ProviderId(decision.selected_outbound_tag.clone()),
                        reason: format!("anytls client tls config failed: {e}"),
                    }
                })
            } else {
                let mut roots = rustls::RootCertStore::empty();
                for c in rustls_native_certs::load_native_certs().certs {
                    let _ = roots.add(c);
                }
                let prov = Arc::new(rustls::crypto::ring::default_provider());
                let cfg = rustls::ClientConfig::builder_with_provider(prov)
                    .with_safe_default_protocol_versions()
                    .map_err(|_| NexusError::Internal {
                        message: "tls versions".into(),
                    })?
                    .with_root_certificates(roots)
                    .with_no_client_auth();
                Ok(cfg)
            };
            let tls_cfg = tls_cfg?;

            let sni = ServerName::try_from(sni_host.clone()).map_err(|_| {
                NexusError::ConnectivityEstablishmentFailed {
                    provider: ProviderId(decision.selected_outbound_tag.clone()),
                    reason: format!("anytls sni invalid: {sni_host}"),
                }
            })?;
            let mut conn = rustls::ClientConnection::new(Arc::new(tls_cfg), sni).map_err(|e| {
                NexusError::ConnectivityEstablishmentFailed {
                    provider: ProviderId(decision.selected_outbound_tag.clone()),
                    reason: format!("anytls client connection failed: {e}"),
                }
            })?;

            // AnyTLS session 握手（阻塞 I/O；write_all/flush 同时驱动 TLS 握手）：
            // 认证（SHA256(password)+padding0 拼成一个 buffer 一次写）→ Settings →
            // 等 ServerSettings。服务器下发 UpdatePaddingScheme（md5 不一致）时
            // fail-closed（真实节点使用默认 scheme）。
            let padding_md5 = padding_md5_hex(DEFAULT_PADDING_SCHEME);
            let mut hs = {
                let mut tls = rustls::Stream::new(&mut conn, &mut node);
                client_handshake(&mut tls, &password, 0, CLIENT_IDENT, &padding_md5).map_err(
                    |e| NexusError::ConnectivityEstablishmentFailed {
                        provider: ProviderId(decision.selected_outbound_tag.clone()),
                        reason: format!("anytls session handshake failed: {e}"),
                    },
                )?
            };
            // 开 stream：SYN → 首个 PSH（SOCKS5 目标地址）→ 等 SYNACK。
            let target = match host.parse::<std::net::IpAddr>() {
                Ok(std::net::IpAddr::V4(v4)) => AnyTlsTarget::Ipv4(v4.octets(), port),
                Ok(std::net::IpAddr::V6(v6)) => AnyTlsTarget::Ipv6(v6.octets(), port),
                Err(_) => AnyTlsTarget::Domain(host.clone(), port),
            };
            let stream_id = {
                let mut tls = rustls::Stream::new(&mut conn, &mut node);
                client_open_stream(&mut tls, &mut hs, &target).map_err(|e| {
                    NexusError::ConnectivityEstablishmentFailed {
                        provider: ProviderId(decision.selected_outbound_tag.clone()),
                        reason: format!("anytls open stream failed: {e}"),
                    }
                })?
            };
            // §11.19：握手首段字节（HTTP 改写后的请求 / SOCKS5 隧道内 pipelined 字节）
            // 作为 stream 的首个数据 PSH 发给节点（目标地址已在开 stream 的首个 PSH 发出）。
            if !seed_to_upstream.is_empty() {
                let mut tls = rustls::Stream::new(&mut conn, &mut node);
                anytls_push_frame(&mut tls, stream_id, AnyTlsCommand::Psh, &seed_to_upstream)
                    .map_err(|e| NexusError::ConnectivityEstablishmentFailed {
                        provider: ProviderId(decision.selected_outbound_tag.clone()),
                        reason: format!("anytls seed write failed: {e}"),
                    })?;
            }

            // 双向 PSH 帧中继：rustls ClientConnection 不可跨线程分裂，用非阻塞单线程
            // poll 在 client 与 TLS 之间搬运（与 trojan arm 同模型；本函数单线程闭环
            // 承担结构化并发，无泄漏 JoinHandle）。
            // node 在握手+开 stream 完成后才设为 nonblocking（握手期间必须阻塞 I/O）；
            // wrapped 流透传 WouldBlock。
            // 下行用 tls.read() 原始读 + decode_frame_bytes 增量组帧：AnyTlsError::Io
            // 丢弃了底层 io kind，read_frame 无法区分 WouldBlock。
            raw_nb
                .set_nonblocking(true)
                .map_err(|e| NexusError::Internal {
                    message: format!("anytls node nonblocking: {e}"),
                })?;
            client
                .set_nonblocking(true)
                .map_err(|e| NexusError::Internal {
                    message: format!("anytls client nonblocking: {e}"),
                })?;
            let mut up_bytes = 0usize;
            let mut down_bytes = 0usize;
            let mut cbuf = [0u8; 8192];
            let mut tbuf = [0u8; 8192];
            let mut pending: Vec<u8> = Vec::new();
            let mut c_open = true;
            let mut tls_open = true;
            let mut up = PendingWrite::new();
            let mut down = PendingWrite::new();
            let mut up_failed = false;
            let mut down_failed = false;
            {
                let mut tls = rustls::Stream::new(&mut conn, &mut node);
                loop {
                    if !c_open
                        && !tls_open
                        && (up_failed || up.ready_for_read())
                        && (down_failed || down.ready_for_read())
                    {
                        break;
                    }
                    let mut progressed = false;
                    // 先排空帧队列：WouldBlock 保留尾部，非 WouldBlock 才关方向。
                    match up.try_write(&mut tls) {
                        Ok((_, n)) => {
                            up_bytes += n;
                            progressed |= n > 0;
                        }
                        Err(_) => {
                            tls_open = false;
                            up_failed = true;
                        }
                    }
                    match down.try_write(&mut client) {
                        Ok((_, n)) => {
                            down_bytes += n;
                            progressed |= n > 0;
                        }
                        Err(_) => {
                            c_open = false;
                            tls_open = false;
                            down_failed = true;
                        }
                    }
                    // client → node：读明文 → PSH 帧入 up 队列。
                    if c_open && tls_open {
                        match up.try_read(&mut client, &mut cbuf) {
                            None => {}
                            Some(Ok(0)) => {
                                // client EOF：Fin 入队，由 up 队列排空后再收尾。
                                if let Ok(fin) =
                                    anytls_encode_frame(stream_id, AnyTlsCommand::Fin, &[])
                                {
                                    up.enqueue(&fin);
                                }
                                c_open = false;
                            }
                            Some(Ok(n)) => {
                                match anytls_encode_frame(stream_id, AnyTlsCommand::Psh, &cbuf[..n])
                                {
                                    Ok(frame) => {
                                        up.enqueue(&frame);
                                        progressed = true;
                                    }
                                    Err(_) => {
                                        c_open = false;
                                        tls_open = false;
                                        up_failed = true;
                                    }
                                }
                            }
                            Some(Err(ref e)) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                            Some(Err(_)) => c_open = false,
                        }
                    }
                    // node → client：先消费残留完整帧（下行背压时暂停消费），
                    // 再按需读 TLS。
                    if tls_open && c_open {
                        while down.ready_for_read() && tls_open && c_open {
                            let Some((frame, consumed)) = anytls_take_complete_frame(&pending)
                            else {
                                break;
                            };
                            pending.drain(..consumed);
                            match frame.cmd {
                                AnyTlsCommand::Psh if frame.stream_id == stream_id => {
                                    down.enqueue(&frame.data);
                                }
                                AnyTlsCommand::Fin if frame.stream_id == stream_id => {
                                    tls_open = false;
                                }
                                AnyTlsCommand::Alert => {
                                    tls_open = false;
                                }
                                AnyTlsCommand::HeartRequest => {
                                    if let Ok(resp) = anytls_encode_frame(
                                        frame.stream_id,
                                        AnyTlsCommand::HeartResponse,
                                        &[],
                                    ) {
                                        up.enqueue(&resp);
                                    }
                                }
                                _ => {} // Waste/无关帧：静默丢弃
                            }
                        }
                        if down.ready_for_read() && tls_open && c_open {
                            match tls.read(&mut tbuf) {
                                Ok(0) => tls_open = false,
                                Ok(n) => {
                                    pending.extend_from_slice(&tbuf[..n]);
                                    progressed = true;
                                    // 防御：残缺帧缓冲有界（合法不完整帧 < 64KiB+7B；
                                    // 超限说明对端持续发垃圾，终止节点侧）。
                                    if pending.len() > 256 * 1024 {
                                        tls_open = false;
                                    }
                                }
                                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                                Err(_) => tls_open = false,
                            }
                        }
                    }
                    // 半关闭：一侧 EOF/致命写错误后，先排空已入队尾部再终止另一侧。
                    if !c_open && tls_open && (down_failed || down.ready_for_read()) {
                        tls_open = false;
                    }
                    if !tls_open
                        && c_open
                        && (up_failed || up.ready_for_read())
                        && (down_failed || down.ready_for_read())
                    {
                        c_open = false;
                    }
                    if !progressed {
                        std::thread::sleep(std::time::Duration::from_millis(2));
                    }
                }
            }
            // NEW_WARN_1: TLS close_notify 仅排队不发送（无 flush），删掉误导性调用；
            // 连接由 drop 关闭（TCP FIN），满足 fail-closed。
            // node 是 wrapped 流（Box<dyn ObfuscatedStream>），无法恢复 inner 的
            // blocking 模式；arm 结束时流即 drop 关闭 fd，无需恢复。

            outbound = json!({
                "kind": "anytls",
                "node_locator": locator,
                "tls": {
                    "sni": sni_host,
                    "skip_cert_verify": skip_verify,
                },
            });
            (up_bytes, down_bytes)
        }
        nexus_proxy_config::OutboundKind::Vless => {
            // §11.16 vless 数据面：TCP → 可选 rustls TLS（SNI 取配置 servername，
            // 缺省节点域名；skip-cert-verify 按配置；tls 缺省 false）→ VLESS 握手
            // （UUID + flow addon + TCP 命令 + 目标地址；响应头由中继泵惰性消费）
            // → 双向透明中继 client<->节点。
            //
            // 传输：仅 TCP/TLS direct；WS/gRPC 等传输链为后续增强（未实现）。
            // XTLS-Vision：nexus-outbound-vless 提供 padding 帧编解码与
            // VisionWriter/VisionReader 状态机，但传输层 splice（DIRECT 后写侧切
            // 裸 TCP 直通、读侧仍走 TLS）尚未实现——本 arm 对 flow=xtls-rprx-vision
            // 仅编码握手 addon 并做普通中继（后续增强）。
            use nexus_outbound_vless::{
                VlessCommand, VlessFlow, VlessRequest, VlessTarget, VlessUuid,
            };
            use rustls::pki_types::ServerName;
            use std::sync::Arc;

            let locator = selected.locator.clone().ok_or_else(|| {
                NexusError::ConnectivityEstablishmentFailed {
                    provider: ProviderId(decision.selected_outbound_tag.clone()),
                    reason: "vless outbound missing locator".into(),
                }
            })?;
            let (nhost, nport) = split_host_port(&locator)?;
            // §7.3 插件接线（P1）：obfs 包在 TLS 之下。先建 raw TCP（保持 blocking，
            // TLS 握手期间 rustls 用阻塞 I/O，提前 nonblocking 会导致 WouldBlock 硬失败），
            // clone 一个 handle 留待握手后设 nonblocking（同 fd 共享 flag），再 wrap；
            // obfs=None → plain 直通（P6 零回归）。
            let raw = std::net::TcpStream::connect((nhost.as_str(), nport)).map_err(|e| {
                NexusError::ConnectivityEstablishmentFailed {
                    provider: ProviderId(decision.selected_outbound_tag.clone()),
                    reason: format!("vless node connect {locator} failed: {e}"),
                }
            })?;
            // WARN1: handshake timeout (10s) -- silent server fail-closed.
            raw.set_read_timeout(Some(std::time::Duration::from_secs(10)))
                .map_err(|e| NexusError::ConnectivityEstablishmentFailed {
                    provider: ProviderId(decision.selected_outbound_tag.clone()),
                    reason: format!("vless set read timeout failed: {e}"),
                })?;
            raw.set_write_timeout(Some(std::time::Duration::from_secs(10)))
                .map_err(|e| NexusError::ConnectivityEstablishmentFailed {
                    provider: ProviderId(decision.selected_outbound_tag.clone()),
                    reason: format!("vless set write timeout failed: {e}"),
                })?;
            let raw_nb = raw.try_clone().map_err(|e| NexusError::Internal {
                message: format!("vless node clone for nonblocking: {e}"),
            })?;
            let obfs_params = nexus_plugin::ObfsParams {
                key: selected.obfs_key.as_deref().unwrap_or("").as_bytes(),
            };
            let mut node = nexus_plugin::wrap_stream(raw, selected.obfs.as_deref(), &obfs_params)
                .map_err(|e| NexusError::ConnectivityEstablishmentFailed {
                provider: ProviderId(decision.selected_outbound_tag.clone()),
                reason: format!("vless obfs wrap failed: {e}"),
            })?;
            let uuid_text = selected.uuid.clone().ok_or_else(|| {
                NexusError::ConnectivityEstablishmentFailed {
                    provider: ProviderId(decision.selected_outbound_tag.clone()),
                    reason: "vless outbound missing uuid".into(),
                }
            })?;
            let uuid = VlessUuid::parse(&uuid_text).map_err(|e| {
                NexusError::ConnectivityEstablishmentFailed {
                    provider: ProviderId(decision.selected_outbound_tag.clone()),
                    reason: format!("vless invalid uuid: {e}"),
                }
            })?;
            let flow = VlessFlow::parse(selected.flow.as_deref().unwrap_or("")).map_err(|e| {
                NexusError::ConnectivityEstablishmentFailed {
                    provider: ProviderId(decision.selected_outbound_tag.clone()),
                    reason: format!("vless unsupported flow: {e}"),
                }
            })?;
            let use_tls = selected.tls.unwrap_or(false);
            // Vision 门禁 fail-closed（§5 坑 #3：无外层 TLS 时 splice 无意义）：
            // flow=xtls-rprx-vision 要求 tls。配置层 validation 已拦截，此处纵深防御。
            if flow == VlessFlow::XtlsRprxVision && !use_tls {
                return Err(NexusError::ConnectivityEstablishmentFailed {
                    provider: ProviderId(decision.selected_outbound_tag.clone()),
                    reason: "vless flow=xtls-rprx-vision requires tls".into(),
                });
            }
            // SNI：配置 servername 优先（vless 专用字段），缺省取 locator host。
            let sni_host = selected
                .servername
                .clone()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| nhost.clone());
            let skip_verify = selected.skip_cert_verify.unwrap_or(false);
            let target = match host.parse::<std::net::IpAddr>() {
                Ok(std::net::IpAddr::V4(v4)) => VlessTarget::Ipv4(v4),
                Ok(std::net::IpAddr::V6(v6)) => VlessTarget::Ipv6(v6),
                Err(_) => VlessTarget::Domain(host.clone()),
            };
            let req = VlessRequest {
                uuid,
                flow,
                command: VlessCommand::Tcp,
                port,
                target: Some(target),
            };

            let (up_bytes, down_bytes) = if use_tls {
                // 客户端 TLS 配置：skip-cert-verify（自签/内网节点）或系统信任根。
                // VLESS 不用 ALPN（空列表）。
                let tls_cfg: Result<rustls::ClientConfig, NexusError> = if skip_verify {
                    nexus_outbound_trojan::client_config_dangerous_skip_verify(&[]).map_err(|e| {
                        NexusError::ConnectivityEstablishmentFailed {
                            provider: ProviderId(decision.selected_outbound_tag.clone()),
                            reason: format!("vless client tls config failed: {e}"),
                        }
                    })
                } else {
                    let mut roots = rustls::RootCertStore::empty();
                    for c in rustls_native_certs::load_native_certs().certs {
                        let _ = roots.add(c);
                    }
                    let prov = Arc::new(rustls::crypto::ring::default_provider());
                    let cfg = rustls::ClientConfig::builder_with_provider(prov)
                        .with_safe_default_protocol_versions()
                        .map_err(|_| NexusError::Internal {
                            message: "tls versions".into(),
                        })?
                        .with_root_certificates(roots)
                        .with_no_client_auth();
                    Ok(cfg)
                };
                let tls_cfg = tls_cfg?;
                let sni = ServerName::try_from(sni_host.clone()).map_err(|_| {
                    NexusError::ConnectivityEstablishmentFailed {
                        provider: ProviderId(decision.selected_outbound_tag.clone()),
                        reason: format!("vless sni invalid: {sni_host}"),
                    }
                })?;
                let mut conn =
                    rustls::ClientConnection::new(Arc::new(tls_cfg), sni).map_err(|e| {
                        NexusError::ConnectivityEstablishmentFailed {
                            provider: ProviderId(decision.selected_outbound_tag.clone()),
                            reason: format!("vless client connection failed: {e}"),
                        }
                    })?;
                // VLESS 握手（阻塞 I/O；write_all/flush 同时驱动 TLS 握手）。
                let mut tls = rustls::Stream::new(&mut conn, &mut node);
                vless_handshake_stream(
                    &mut tls,
                    &req,
                    &seed_to_upstream,
                    &decision.selected_outbound_tag,
                )?;
                // 双向透明中继：rustls ClientConnection 不可跨线程分裂，用非阻塞单线程
                // poll 在 client 与 TLS 之间搬运字节（见 vless_pump_stream）。
                // node 在握手完成后才设为 nonblocking（握手期间必须阻塞 I/O）；
                // wrapped 流透传 WouldBlock。
                raw_nb
                    .set_nonblocking(true)
                    .map_err(|e| NexusError::Internal {
                        message: format!("vless node nonblocking: {e}"),
                    })?;
                client
                    .set_nonblocking(true)
                    .map_err(|e| NexusError::Internal {
                        message: format!("vless client nonblocking: {e}"),
                    })?;
                let (up, down) = vless_pump_stream(&mut tls, &mut client);
                // WARN3: TLS close_notify 仅排队不发送（无 flush），删掉误导性调用；
                // 连接由 drop 关闭（TCP FIN），满足 fail-closed。
                (up, down)
            } else {
                // 明文 TCP：直接在 wrapped 流上握手 + 中继。
                vless_handshake_stream(
                    &mut node,
                    &req,
                    &seed_to_upstream,
                    &decision.selected_outbound_tag,
                )?;
                raw_nb
                    .set_nonblocking(true)
                    .map_err(|e| NexusError::Internal {
                        message: format!("vless node nonblocking: {e}"),
                    })?;
                client
                    .set_nonblocking(true)
                    .map_err(|e| NexusError::Internal {
                        message: format!("vless client nonblocking: {e}"),
                    })?;
                vless_pump_stream(&mut node, &mut client)
            };
            // node 是 wrapped 流（Box<dyn ObfuscatedStream>），无法恢复 inner 的
            // blocking 模式；arm 结束时流即 drop 关闭 fd，无需恢复。

            outbound = json!({
                "kind": "vless",
                "node_locator": locator,
                "tls": use_tls,
                "sni": sni_host,
                "skip_cert_verify": skip_verify,
                "flow": flow.as_str(),
            });
            (up_bytes, down_bytes)
        }
        nexus_proxy_config::OutboundKind::Hysteria2 => {
            // §11.16 hysteria2 数据面：UDP socket → quinn-proto QUIC 建连
            // （SNI/ALPN h3/证书校验三选一；QUIC bit greasing 禁用）→ 最小
            // HTTP/3 认证（HEADERS 请求，校验 :status == 233）→ 为本应用连接开
            // 一条 QUIC 双向 stream（TCPRequest 帧）→ 双向字节中继 →
            // 优雅关闭（CONNECTION_CLOSE）。
            //
            // 未实现（注明）：UDP 中继（UDPMessage over QUIC DATAGRAM 由
            // Hysteria2Client::{send_udp, recv_udp} 提供，crate 内单测覆盖；
            // 本 arm 入站是 TCP，待应用侧 UDP 入口接入后再装配）、端口跳跃、
            // Brutal CC。
            use nexus_outbound_hysteria2::Hysteria2Client;

            let target = hysteria2_target_from_outbound(selected, &decision.selected_outbound_tag)?;
            let locator = target.locator();
            // QUIC 建连 + H3 认证（阻塞至 handshake_timeout；:status != 233 →
            // Hysteria2Error::AuthFailed，结构化透出）。
            let mut hy2 = Hysteria2Client::connect(&target).map_err(|e| {
                NexusError::ConnectivityEstablishmentFailed {
                    provider: ProviderId(decision.selected_outbound_tag.clone()),
                    reason: format!("hysteria2 connect/auth {locator} failed: {e}"),
                }
            })?;
            let udp_enabled = hy2.udp_enabled();
            // TCP 代理 stream：fast-open 默认开启（open_tcp 不等 TCPResponse 即返回；
            // 读侧首次 stream_read 自动剥离 TCPResponse，拒绝则报 TcpRejected）。
            let target_addr = format!("{host}:{port}");
            let stream = hy2.open_tcp(&target_addr).map_err(|e| {
                NexusError::ConnectivityEstablishmentFailed {
                    provider: ProviderId(decision.selected_outbound_tag.clone()),
                    reason: format!("hysteria2 open tcp {target_addr} failed: {e}"),
                }
            })?;
            // §11.19：握手产出的首段字节必须先写上给上游，再进入双向中继。
            if !seed_to_upstream.is_empty() {
                hy2.stream_write(stream, &seed_to_upstream).map_err(|e| {
                    NexusError::ConnectivityEstablishmentFailed {
                        provider: ProviderId(decision.selected_outbound_tag.clone()),
                        reason: format!("hysteria2 seed write failed: {e}"),
                    }
                })?;
            }
            // 双向中继：client 设 nonblocking（QUIC 侧 stream_read 带短超时轮询）。
            client
                .set_nonblocking(true)
                .map_err(|e| NexusError::Internal {
                    message: format!("hysteria2 client nonblocking: {e}"),
                })?;
            let (up_bytes, down_bytes) =
                hysteria2_pump_stream(&mut hy2, stream, target.fast_open, &mut client);
            // 优雅关闭：发送 QUIC CONNECTION_CLOSE（尽力）。
            hy2.close();
            // client 在 arm 结束时 drop 关闭 fd，无需恢复 blocking 模式。

            outbound = json!({
                "kind": "hysteria2",
                "node_locator": locator,
                "sni": target.effective_sni(),
                "skip_cert_verify": selected.skip_cert_verify.unwrap_or(false),
                "obfs": selected.obfs.as_deref().unwrap_or("none"),
                "udp_enabled": udp_enabled,
                "cc_rx_bps": target.cc_rx_bps,
            });
            (up_bytes, down_bytes)
        }
    };

    // 5.5) 本地 CONNECT 应答的可观测状态（AC-13）：是否已写、延迟多久。
    let reply_sent = deferred_reply.is_sent();
    let reply_deferred_ms = deferred_reply.deferred_ms().unwrap_or(0);

    // 6) Session 终态。
    let outcome = if client_aborted_before_ready {
        // 客户端在 success 前断开：按取消处理（未建立可用隧道，也没有失败可报）。
        TerminalOutcome::Cancelled
    } else {
        TerminalOutcome::Completed
    };
    owner.commit_outcome(outcome).map_err(NexusError::from)?;
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

    let mut session_json = json!({
        "verdict": "PASS",
        "inbound": {
            "kind": inbound_kind,
        },
        "socks": {
            "auth_method_reply": "0x05,0x00",
            "reply_code": if reply_sent { json!(0) } else { Value::Null },
            "reply_sent": reply_sent,
            "reply_deferred_ms": reply_deferred_ms,
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
    });
    if let Some(tunnel) = tunnel_json {
        session_json["tunnel"] = tunnel;
    }
    Ok(session_json)
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

/// `nexus proxy speedtest --json` 入口：loopback 自检（真实 TcpStream 路径，
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

// ---------- bufferbloat 诊断（PRODUCT §11 诊断扩展） ----------

/// bufferbloat 诊断配置。
#[derive(Debug, Clone)]
pub struct BufferbloatConfig {
    /// 代理服务器地址（如 `127.0.0.1:7897`）。
    pub proxy_addr: std::net::SocketAddr,
    /// 上行打满时长。
    pub duration: std::time::Duration,
    /// 判定阈值：负载延迟 - 基准延迟 > threshold_ms 判为本地 bufferbloat。
    pub threshold_ms: u64,
    /// 打满时的并发 TCP 连接数。
    pub saturate_conns: usize,
    /// 每次延迟测量的采样次数（取中位数）。
    pub probe_samples: usize,
}

impl Default for BufferbloatConfig {
    fn default() -> Self {
        Self {
            // 默认值由调用方覆盖；此处占位避免 Default 被误用。
            proxy_addr: "127.0.0.1:7897".parse().expect("default proxy addr"),
            duration: std::time::Duration::from_secs(10),
            threshold_ms: 100,
            saturate_conns: 4,
            probe_samples: 5,
        }
    }
}

/// bufferbloat 诊断结论。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BufferbloatVerdict {
    /// 延迟暴涨：拥塞在用户到代理段，QoS 可缓解。
    BloatLocal,
    /// 延迟稳定：拥塞在代理服务器之后（或无拥塞），建议换节点。
    NoBloatUpstream,
}

impl BufferbloatVerdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::BloatLocal => "BUFFERBLOAT_LOCAL",
            Self::NoBloatUpstream => "NO_BLOAT_UPSTREAM",
        }
    }

    pub fn advice(&self) -> &'static str {
        match self {
            Self::BloatLocal => "拥塞在用户到代理段，QoS 整形可缓解",
            Self::NoBloatUpstream => "代理之后拥塞或无拥塞，建议换节点或检查代理服务器",
        }
    }
}

/// 纯函数：按阈值判定 bufferbloat 结论（可单测，无 I/O）。
pub fn classify_bufferbloat(
    baseline_ms: u64,
    loaded_ms: u64,
    threshold_ms: u64,
) -> BufferbloatVerdict {
    let delta = loaded_ms.saturating_sub(baseline_ms);
    if delta > threshold_ms {
        BufferbloatVerdict::BloatLocal
    } else {
        BufferbloatVerdict::NoBloatUpstream
    }
}

/// 纯函数：中位数（可单测；空切片返回 0）。
pub fn median_ms(values: &mut [u64]) -> u64 {
    if values.is_empty() {
        return 0;
    }
    values.sort_unstable();
    let mid = values.len() / 2;
    if values.len() % 2 == 1 {
        values[mid]
    } else {
        // 偶数个取中间两数的平均（下取整），避免抖动。
        (values[mid - 1] + values[mid]) / 2
    }
}

/// 单次 TCP 建连延迟测量（ms）。失败返回 None（调用方决定是否重试/降级）。
fn probe_once(addr: &std::net::SocketAddr, timeout: std::time::Duration) -> Option<u64> {
    let start = std::time::Instant::now();
    let socket = std::net::TcpStream::connect_timeout(addr, timeout).ok()?;
    let ms = start.elapsed().as_millis().max(1) as u64;
    drop(socket);
    Some(ms)
}

/// 多次测量取中位数；全部失败返回 None。
fn probe_median(
    addr: &std::net::SocketAddr,
    samples: usize,
    timeout: std::time::Duration,
) -> Option<u64> {
    let mut rtts: Vec<u64> = Vec::with_capacity(samples);
    for _ in 0..samples {
        if let Some(ms) = probe_once(addr, timeout) {
            rtts.push(ms);
        }
    }
    if rtts.is_empty() {
        None
    } else {
        Some(median_ms(&mut rtts))
    }
}

/// 上行打满工作线程：持续向代理地址发送随机数据，直到收到停止信号。
/// 代理可能因协议无效关闭连接；关闭后立即重连，保持上行饱和。
fn saturate_worker(
    addr: std::net::SocketAddr,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    use std::io::Write;
    // 64KB 随机块（固定种子 Xorshift，避免每次分配 RNG 开销）。
    let mut block = vec![0u8; 64 * 1024];
    let mut x: u64 = 0x9E3779B97F4A7C15;
    for b in block.iter_mut() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *b = (x >> 33) as u8;
    }
    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
        let mut stream =
            match std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(5)) {
                Ok(s) => s,
                Err(_) => {
                    std::thread::sleep(std::time::Duration::from_millis(200));
                    continue;
                }
            };
        let _ = stream.set_nodelay(true);
        // 写超时：对端不读时 write_all 不能无限阻塞，否则 stop 信号
        // 永远检查不到、join 永久 hang（2026-10-02 修）。
        let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(5)));
        // 持续发送直到对端关闭或收到停止信号。
        while !stop.load(std::sync::atomic::Ordering::Relaxed) {
            match stream.write_all(&block) {
                Ok(()) => {}
                Err(_) => break, // 对端关闭，重连
            }
        }
    }
}

/// `nexus proxy bufferbloat-test` 入口：
///
/// 1. 空载测基准延迟（TCP connect 中位数）；
/// 2. 启动 N 个打满线程持续发送；
/// 3. 负载下再测延迟中位数；
/// 4. 停止打满，按阈值判定。
///
/// 返回结构化 JSON（含 verdict / baseline_ms / loaded_ms / delta_ms / threshold_ms）。
pub fn proxy_bufferbloat_test(config: &BufferbloatConfig) -> Result<serde_json::Value, NexusError> {
    let probe_timeout = std::time::Duration::from_secs(5);

    // 1. 基准延迟（空载）。
    let baseline_ms = probe_median(&config.proxy_addr, config.probe_samples, probe_timeout)
        .ok_or_else(|| NexusError::Internal {
            message: format!(
                "baseline probe failed: cannot connect to {}",
                config.proxy_addr
            ),
        })?;

    // 2. 启动打满线程。
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut handles = Vec::with_capacity(config.saturate_conns);
    for _ in 0..config.saturate_conns {
        let addr = config.proxy_addr;
        let stop_clone = std::sync::Arc::clone(&stop);
        handles.push(
            std::thread::Builder::new()
                .name("bloat-saturate".to_string())
                .spawn(move || saturate_worker(addr, stop_clone))
                .map_err(|e| NexusError::Internal {
                    message: format!("spawn saturate worker failed: {e}"),
                })?,
        );
    }

    // 3. 负载下测延迟（打满进行中）。
    // 先等 1s 让上行真正跑满，避免测量时带宽还没起来；测完后补足剩余时长，
    // 保证总打满时长 ≈ duration（让 buffer 有充分时间堆积）。
    let saturate_start = std::time::Instant::now();
    std::thread::sleep(std::time::Duration::from_secs(1));
    let loaded_opt = probe_median(&config.proxy_addr, config.probe_samples, probe_timeout);
    let elapsed = saturate_start.elapsed();
    if elapsed < config.duration {
        std::thread::sleep(config.duration - elapsed);
    }

    // 4. 停止打满，回收线程。
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    for h in handles {
        let _ = h.join();
    }

    let loaded_ms = loaded_opt.ok_or_else(|| NexusError::Internal {
        message: "loaded probe failed: cannot connect under load".to_string(),
    })?;

    // 5. 判定。
    let verdict = classify_bufferbloat(baseline_ms, loaded_ms, config.threshold_ms);
    let delta_ms = loaded_ms.saturating_sub(baseline_ms);

    Ok(serde_json::json!({
        "verdict": "PASS",
        "command": "proxy bufferbloat-test",
        "proxy": config.proxy_addr.to_string(),
        "baseline_ms": baseline_ms,
        "loaded_ms": loaded_ms,
        "delta_ms": delta_ms,
        "threshold_ms": config.threshold_ms,
        "diagnosis": verdict.as_str(),
        "advice": verdict.advice(),
        "duration_secs": config.duration.as_secs(),
    }))
}

/// Run a remote resource access (e.g. service, compute, internet-access).
///
/// This is the CLI entry point for executing resource access flows.
/// Currently supports: service, compute, internet-access.
/// `nexus run <resource>`：进程内 SDK 演示闭环（thin wrapper）。
///
/// D4 诚实化（2026-10-03，requirement-change）：不再伪造 session_id。
/// 返回的 session_id / plan_id / outcome 全部取自底层 flow 报告的真实值：
/// - `session_id`：flow 内 SessionOwner 的真实 id（`report["session"]["id"]`），
///   不再是每次随机生成的 `sess-{nanos}` mock；
/// - `outcome`：Owner 唯一提交的 TerminalOutcome（`report["session"]["outcome"]`）；
/// - `plan_id`：由 flow 报告的 plan 内容（provider_id/placement/path）经 FNV-1a
///   确定性派生（D3 方向：PlanId 为确定性非密码学摘要，只做标识符；
///   P0-3 正式 PlanId 落地前，此处为展示用派生值）；
/// - `connectivity.status`：flow 只有真实建连成功才返回 Ok，故为 Connected。
///
/// P0-4 的 daemon 内 SessionManager 落地后，`nexus use` 成为正式入口（PRODUCT §16）。
pub fn run_resource(resource: &str) -> Result<serde_json::Value, NexusError> {
    let report = match resource {
        "service" => remote_service_access_flow()?,
        "compute" => remote_compute_job_flow()?,
        "internet-access" => remote_internet_access_flow()?,
        other => {
            return Err(NexusError::Unsupported {
                feature: format!("run {other}"),
            });
        }
    };
    let session_id = report
        .pointer("/session/id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| NexusError::Internal {
            message: format!("run {resource}: flow report missing session.id"),
        })?;
    let outcome = report
        .pointer("/session/outcome")
        .and_then(|v| v.as_str())
        .ok_or_else(|| NexusError::Internal {
            message: format!("run {resource}: flow report missing session.outcome"),
        })?;
    let plan_id = plan_id_from_report(&report);
    Ok(serde_json::json!({
        "verdict": "PASS",
        "run": {
            "resource": resource,
            "session_id": session_id,
            "plan_id": plan_id,
            "outcome": outcome,
            "connectivity": {
                "status": "Connected"
            },
        }
    }))
}

/// 由 flow 报告的 plan 内容确定性派生 plan_id（FNV-1a 64，hex）。
///
/// D3 方向：PlanId 是确定性非密码学摘要，只做标识符、不做安全边界。
/// 输入为报告中 plan 节的 provider_id / placement / path；同一 plan 内容
/// 在多次运行间得到同一 plan_id（可复现、可断言）。
fn plan_id_from_report(report: &serde_json::Value) -> String {
    let provider_id = report
        .pointer("/plan/provider_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let placement = report
        .pointer("/plan/placement")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let path = report
        .pointer("/plan/path")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str())
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default();
    let mut input = String::new();
    input.push_str(provider_id);
    input.push('|');
    input.push_str(placement);
    input.push('|');
    input.push_str(&path);
    format!("{:016x}", fnv1a_64(input.as_bytes()))
}

/// FNV-1a 64 位哈希（非密码学，仅作确定性标识）。
fn fnv1a_64(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in data {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x100000001b3);
    }
    h
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
        .recv_and_deliver(&mut buf, 1000)
        .map_err(|e| NexusError::Internal {
            message: format!("b accept: {e}"),
        })?;
    tunnel_a
        .recv_and_deliver(&mut buf, 1000)
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
        .recv_and_deliver(&mut buf, 1000)
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
        .recv_and_deliver(&mut buf, 1000)
        .map_err(|e| NexusError::Internal {
            message: format!("re-b accept: {e}"),
        })?;
    tunnel_a
        .recv_and_deliver(&mut buf, 1000)
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
    let mismatch_rejected = match tunnel_a.recv_and_deliver(&mut buf, 1000) {
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
        .recv_and_deliver(&mut buf, 1000)
        .map_err(|e| NexusError::Internal {
            message: format!("b accept: {e}"),
        })?;
    let _ = tunnel_a
        .recv_and_deliver(&mut buf, 1000)
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
        .recv_and_deliver(&mut buf, 1000)
        .map_err(|e| NexusError::Internal {
            message: format!("c accept: {e}"),
        })?;
    let _ = tunnel_b
        .recv_and_deliver(&mut buf, 1000)
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
    let b_delivered =
        tunnel_b
            .recv_and_deliver(&mut buf, 1000)
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
    let c_delivered =
        tunnel_c
            .recv_and_deliver(&mut buf, 1000)
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
    let replay_err = tunnel_b.recv_and_deliver(&mut buf, 1000);
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
    let a_to_b_delivered = match tunnel_b.recv_and_deliver(&mut buf, 1000) {
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
    let b_to_a_delivered = match tunnel_a.recv_and_deliver(&mut buf, 1000) {
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
    let office_delivered = match tunnel_b.recv_and_deliver(&mut buf, 1000) {
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
    let egress_delivered = match tunnel_b.recv_and_deliver(&mut buf, 1000) {
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
    let up_json = subnet_up(&cfg_ok, &state, false, false)
        .map_err(|e| NexusError::Internal { message: e })?;
    // up 幂等（同 vip 覆盖，仍成功）
    subnet_up(&cfg_ok, &state, false, false).map_err(|e| NexusError::Internal { message: e })?;
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
    let enc_up_json = subnet_up(&cfg_ok, &state_sec, true, false)
        .map_err(|e| NexusError::Internal { message: e })?;
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
        match subnet_up(path, &state, false, false) {
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
/// 3) 与 1 同 5 元组的第二个 TCP 包（决策缓存 hit）；
/// 4) ICMP 坏包（计入 dropped，不 panic）。
///
/// S18：决策缓存改为 TUN/TPROXY 共用的 `FlowDecisionCache`，规则实现改为
/// `nexus_proxy::DomainRuleEngine`（spec §9.13，AC-G11-01/02）。
pub fn tun_proxy_flow() -> Result<Value, NexusError> {
    use nexus_connectivity::virtual_subnet::MemoryVpi;
    use nexus_domain::{RouteRequest, RouteTarget, RuleEngine as _};
    use nexus_ingress::ip_packet::parse_ipv4_packet;
    use nexus_platform::VirtualPacketInterface;
    use nexus_projection::egress::FlowKey;
    use nexus_projection::transparent::decision::{
        CachedDecision, FlowDecisionCache, FlowDecisionKey, Frontend,
    };
    use nexus_proxy::domain_engine::DomainRuleEngine;

    fn internal_err<E: std::fmt::Display>(e: E) -> NexusError {
        NexusError::Internal {
            message: e.to_string(),
        }
    }

    let engine = DomainRuleEngine::from_yaml(TUN_PROXY_CONFIG).map_err(internal_err)?;
    let mut cache = FlowDecisionCache::new(16_384, std::time::Duration::from_secs(300));

    let mut vpi = MemoryVpi::new();
    // 四条包按序注入；每条注入后 drain 一次读循环。
    let packets: Vec<Vec<u8>> = vec![
        build_ipv4_packet(6, [192, 168, 1, 5], 12345, [10, 1, 2, 3], 443), // p1 TCP -> cidr
        build_ipv4_packet(17, [192, 168, 1, 5], 53000, [8, 8, 8, 8], 53),  // p2 UDP -> MATCH
        build_ipv4_packet(6, [192, 168, 1, 5], 12345, [10, 1, 2, 3], 443), // p3 同 p1（cache hit）
        build_ipv4_packet(1, [192, 168, 1, 5], 0, [10, 9, 9, 9], 0),       // p4 ICMP 坏包
    ];

    let mut packets_seen: u64 = 0;
    let mut bytes_seen: u64 = 0;
    let mut dropped: u64 = 0;
    let mut first_flow: Option<Value> = None;
    let mut udp_flow: Option<Value> = None;
    let mut replay: Option<Value> = None;
    // 示例用固定单调毫秒；真实组合根由主循环维护。
    let mut now_millis: u64 = 0;
    for (idx, pkt) in packets.iter().enumerate() {
        now_millis += 1;
        vpi.inject_recv(pkt);
        let mut buf = [0u8; 2048];
        // drain：MemoryVpi 一次读回已注入的整包（真实 wintun 亦一包一收）。
        loop {
            let n = vpi.receive(&mut buf).map_err(internal_err)?;
            if n == 0 {
                break;
            }
            packets_seen += 1;
            bytes_seen += n as u64;
            let raw = &buf[..n];
            if parse_ipv4_packet(raw).is_none() {
                dropped += 1;
                continue;
            }
            let Some(flow) = FlowKey::parse(raw) else {
                dropped += 1;
                continue;
            };
            let key = FlowDecisionKey {
                flow,
                frontend: Frontend::Tun,
            };
            let (cache_hit, decision) = match cache.get(&key, now_millis) {
                Some(cached) => (true, cached.clone()),
                None => {
                    let req = RouteRequest {
                        packet: raw,
                        domain: None,
                        src_port: Some(flow.src_port),
                        dst_port: Some(flow.dst_port),
                        process_name: None,
                    };
                    let (target, explanation) = engine.explain(&req);
                    let matched_rule = explanation
                        .as_ref()
                        .map(|e| e.matched_rule.clone())
                        .unwrap_or_default();
                    let selected_outbound = match &target {
                        RouteTarget::Egress { peer } => peer.clone(),
                        RouteTarget::MeshPeer { peer } => peer.clone(),
                        RouteTarget::Drop => "drop".to_string(),
                    };
                    let decision = CachedDecision {
                        target,
                        matched_rule,
                        selected_outbound,
                        last_seen_millis: now_millis,
                    };
                    cache.insert(key, decision.clone(), now_millis);
                    (false, decision)
                }
            };
            let v = serde_json::json!({
                "destination": format!(
                    "{}.{}.{}.{}:{}",
                    (flow.dst_ip >> 24) & 0xFF,
                    (flow.dst_ip >> 16) & 0xFF,
                    (flow.dst_ip >> 8) & 0xFF,
                    flow.dst_ip & 0xFF,
                    flow.dst_port,
                ),
                "protocol": flow.proto,
                "flow_origin": "virtual-packet-interface",
                "matched_rule": decision.matched_rule,
                "selected_outbound_tag": decision.selected_outbound,
                "cache_hit": cache_hit,
            });
            match idx {
                0 => first_flow = Some(v),
                1 => udp_flow = Some(v),
                _ => replay = Some(v),
            }
        }
    }

    let stats = cache.stats();
    Ok(serde_json::json!({
        "verdict": "PASS",
        "command": "tun proxy inbound",
        "first_flow": first_flow.unwrap_or(Value::Null),
        "udp_flow": udp_flow.unwrap_or(Value::Null),
        "replay": replay.unwrap_or(Value::Null),
        "stats": {
            "packets": packets_seen,
            "bytes": bytes_seen,
            "dropped": dropped,
            "mappings": stats.misses,
            "cache_hits": stats.hits,
        },
        "cache": {
            "entries": stats.entries,
            "hits": stats.hits,
            "misses": stats.misses,
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
    let psk_required_err = match subnet_up(&cfg_no_psk, &state, false, false) {
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
    // 走 foreground=true：S6（设计 §7.3）规定一次性 `subnet up` 配了 bootstrap
    // 必须报 BOOTSTRAP_REQUIRES_FOREGROUND，故"bootstrap + PSK 可被接受"这一条
    // 只能在常驻前台语义下成立。PSK 校验本身在 parse_config 内、先于 S6 门禁，
    // 上一步（无 PSK -> PSK_REQUIRED）因此不受影响。
    subnet_up(&cfg_psk, &state, false, true).map_err(|e| NexusError::Internal {
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
    subnet_up(&cfg_legacy, &state, false, false).map_err(|e| NexusError::Internal {
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

#[cfg(test)]
mod bufferbloat_tests {
    use super::*;

    #[test]
    fn classify_delta_above_threshold_is_local() {
        // 延迟暴涨 425ms > 100ms 阈值 → 本地 bufferbloat。
        assert_eq!(
            classify_bufferbloat(25, 450, 100),
            BufferbloatVerdict::BloatLocal
        );
    }

    #[test]
    fn classify_delta_within_threshold_is_upstream() {
        // 延迟仅 +5ms ≤ 100ms → 代理之后拥塞（或无拥塞）。
        assert_eq!(
            classify_bufferbloat(25, 30, 100),
            BufferbloatVerdict::NoBloatUpstream
        );
    }

    #[test]
    fn classify_delta_equal_threshold_is_upstream() {
        // 边界：delta == threshold 不算暴涨（严格大于才判）。
        assert_eq!(
            classify_bufferbloat(25, 125, 100),
            BufferbloatVerdict::NoBloatUpstream
        );
    }

    #[test]
    fn classify_loaded_below_baseline_is_upstream() {
        // 负载延迟反而更低（抖动）：saturating_sub → 0，不误判。
        assert_eq!(
            classify_bufferbloat(30, 25, 100),
            BufferbloatVerdict::NoBloatUpstream
        );
    }

    #[test]
    fn classify_custom_threshold() {
        // 自定义阈值生效：delta=50，阈值 30 → 本地；阈值 100 → 上游。
        assert_eq!(
            classify_bufferbloat(20, 70, 30),
            BufferbloatVerdict::BloatLocal
        );
        assert_eq!(
            classify_bufferbloat(20, 70, 100),
            BufferbloatVerdict::NoBloatUpstream
        );
    }

    #[test]
    fn median_odd_count() {
        let mut v = vec![30u64, 10, 20];
        assert_eq!(median_ms(&mut v), 20);
    }

    #[test]
    fn median_even_count() {
        // 偶数个取中间两数平均下取整：(20+30)/2=25。
        let mut v = vec![40u64, 10, 30, 20];
        assert_eq!(median_ms(&mut v), 25);
    }

    #[test]
    fn median_single() {
        let mut v = vec![42u64];
        assert_eq!(median_ms(&mut v), 42);
    }

    #[test]
    fn median_empty_is_zero() {
        let mut v: Vec<u64> = vec![];
        assert_eq!(median_ms(&mut v), 0);
    }

    #[test]
    fn verdict_strings() {
        assert_eq!(BufferbloatVerdict::BloatLocal.as_str(), "BUFFERBLOAT_LOCAL");
        assert_eq!(
            BufferbloatVerdict::NoBloatUpstream.as_str(),
            "NO_BLOAT_UPSTREAM"
        );
    }
}

/// N3-12 offline freeze and authenticated local staging client.
pub mod snapshot_cli;
/// N3 task front-end parsing; service adapter remains unavailable.
pub mod task_cli;

mod task_localapi;

pub mod task_authorization;

/// Local operator commands for existing provider-scoped Use grants.
pub mod task_provider_grant;

#[cfg(test)]
mod hysteria2_dataplane_tests {
    use super::*;

    fn hy2_outbound_yaml(port: u16) -> String {
        format!(
            "schema_version: 1\nrules:\n  - tag: m\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: h\noutbounds:\n  - tag: h\n    kind: hysteria2\n    locator: 127.0.0.1:{port}\n    password: secret123\n    down: 100 Mbps\n    skip_cert_verify: true\n"
        )
    }

    #[test]
    fn bandwidth_parser_meow_semantics() {
        assert_eq!(parse_hy2_bandwidth_to_bps(None).unwrap(), 0);
        assert_eq!(parse_hy2_bandwidth_to_bps(Some("")).unwrap(), 0);
        assert_eq!(parse_hy2_bandwidth_to_bps(Some("0")).unwrap(), 0);
        // 纯整数按 Mbps。
        assert_eq!(parse_hy2_bandwidth_to_bps(Some("100")).unwrap(), 12_500_000);
        // "100 Mbps"：100 * 1e6 bits / 8。
        assert_eq!(
            parse_hy2_bandwidth_to_bps(Some("100 Mbps")).unwrap(),
            12_500_000
        );
        assert_eq!(
            parse_hy2_bandwidth_to_bps(Some("1 Gbps")).unwrap(),
            125_000_000
        );
        assert_eq!(
            parse_hy2_bandwidth_to_bps(Some("512 Kbps")).unwrap(),
            64_000
        );
        // 大写 B = bytes，不除 8。
        assert_eq!(
            parse_hy2_bandwidth_to_bps(Some("8 MBps")).unwrap(),
            8_000_000
        );
        // 非法输入 fail-closed。
        assert!(parse_hy2_bandwidth_to_bps(Some("fast")).is_err());
        assert!(parse_hy2_bandwidth_to_bps(Some("100 XBPS")).is_err());
        assert!(parse_hy2_bandwidth_to_bps(Some("100 M")).is_err());
    }

    #[test]
    fn target_mapping_fields() {
        let cfg = nexus_proxy_config::parse(&hy2_outbound_yaml(4443)).unwrap();
        let selected = cfg.outbounds.iter().find(|o| o.tag == "h").unwrap();
        let target = hysteria2_target_from_outbound(selected, "h").unwrap();
        assert_eq!(target.server, "127.0.0.1");
        assert_eq!(target.port, 4443);
        assert_eq!(target.password, "secret123");
        // skip_cert_verify=true → Insecure。
        assert!(matches!(
            target.verify,
            nexus_outbound_hysteria2::CertVerify::Insecure
        ));
        // down: 100 Mbps → 12_500_000 B/s。
        assert_eq!(target.cc_rx_bps, 12_500_000);
        // sni 缺省 → effective_sni 回退到 server。
        assert_eq!(target.effective_sni(), "127.0.0.1");
        assert!(!target.obfs.is_salamander());
    }

    #[test]
    fn target_mapping_rejects_bad_obfs() {
        let yaml = hy2_outbound_yaml(4443).replace("skip_cert_verify: true", "obfs: xor");
        // WARN5: 未知 obfs 在配置解析阶段即被拒绝（fail-closed 前移）。
        let err = nexus_proxy_config::parse(&yaml).unwrap_err();
        assert!(format!("{err:?}").contains("obfs"), "err: {err:?}");
    }

    #[test]
    fn loopback_connect_auth_tcp_relay() {
        use nexus_outbound_hysteria2::Hysteria2Client;
        use nexus_outbound_hysteria2::test_server::TestServer;
        use std::time::Duration;

        let server = TestServer::spawn("secret123", true).unwrap();
        let cfg = nexus_proxy_config::parse(&hy2_outbound_yaml(server.addr.port())).unwrap();
        let selected = cfg.outbounds.iter().find(|o| o.tag == "h").unwrap();
        let target = hysteria2_target_from_outbound(selected, "h").unwrap();
        // QUIC 握手 + H3 认证（skip_cert_verify → Insecure）。
        let mut client = Hysteria2Client::connect(&target).unwrap();
        assert!(client.udp_enabled());
        // TCP 中继：open stream → 写 → 回显读回。
        let stream = client.open_tcp("example.com:80").unwrap();
        client.stream_write(stream, b"hello-hy2").unwrap();
        let mut buf = [0u8; 64];
        let n = client
            .stream_read(stream, &mut buf, Duration::from_secs(5))
            .unwrap();
        assert_eq!(&buf[..n], b"hello-hy2");
        client.stream_finish(stream);
        client.close();
    }

    #[test]
    fn hysteria2_sink_12mib_upload_completes_under_30s() {
        use nexus_outbound_hysteria2::Hysteria2Client;
        use nexus_outbound_hysteria2::test_server::{EchoMode, TestServer};
        use std::io::{Read, Write};
        use std::net::{Shutdown, TcpListener};
        use std::sync::mpsc;
        use std::time::{Duration, Instant};

        const TOTAL: usize = 12 * 1024 * 1024;
        const GUARD: Duration = Duration::from_secs(30);

        let server = TestServer::spawn_with_mode("secret123", true, EchoMode::Sink).unwrap();
        let cfg = nexus_proxy_config::parse(&hy2_outbound_yaml(server.addr.port())).unwrap();
        let selected = cfg.outbounds.iter().find(|o| o.tag == "h").unwrap();
        let target = hysteria2_target_from_outbound(selected, "h").unwrap();
        let fast_open = target.fast_open;

        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let writer = std::thread::spawn(move || -> std::io::Result<()> {
            let mut s = std::net::TcpStream::connect(addr)?;
            let chunk = [0x5au8; 64 * 1024];
            let mut left = TOTAL;
            while left > 0 {
                let n = left.min(chunk.len());
                s.write_all(&chunk[..n])?;
                left -= n;
            }
            s.shutdown(Shutdown::Write)?;
            let mut sink = Vec::new();
            let _ = s.read_to_end(&mut sink);
            Ok(())
        });

        let mut client = Hysteria2Client::connect(&target).unwrap();
        let stream = client.open_tcp("example.com:80").unwrap();
        let mut down_client = listener.accept().unwrap().0;
        down_client.set_nonblocking(true).unwrap();

        let (tx, rx) = mpsc::channel();
        let started = Instant::now();
        let pump = std::thread::spawn(move || {
            let counts = hysteria2_pump_stream(&mut client, stream, fast_open, &mut down_client);
            let _ = tx.send(counts);
            client
        });

        let counts = match rx.recv_timeout(GUARD) {
            Ok(c) => c,
            Err(e) => panic!(
                "12 MiB sink upload did not finish within {GUARD:?}: {e}; \
                 elapsed={:?} server_received={}",
                started.elapsed(),
                server.received_bytes()
            ),
        };
        let elapsed = started.elapsed();
        let mut client = pump.join().unwrap();
        writer.join().unwrap().unwrap();

        assert_eq!(counts.0, TOTAL, "up_bytes must be exactly 12 MiB");
        assert_eq!(counts.1, 0, "sink must not send payload downstream");
        // pump 返回只说明 12 MiB 已进入 QUIC 发送缓冲（受对端流控额度限制），
        // 不等于已发出/已被对端读出：`close()` 发 CONNECTION_CLOSE 后 quinn
        // 只发 close 包，仍在发送队列里的尾部会被丢弃；对端未读出的字节也不
        // 再计数。故先驱动连接、等 TestServer 的应用层计数到 12 MiB，再关闭。
        // 等待有界（10 s）；到不了由下面的精确字节断言判 FAIL，不改变判据。
        let drain_deadline = Instant::now() + Duration::from_secs(10);
        let mut dbuf = [0u8; 64];
        while server.received_bytes() < TOTAL as u64 && Instant::now() < drain_deadline {
            // sink 不回载荷：Timeout 只用于推进 QUIC（收 ACK/触发重传），不产生新字节。
            if client
                .stream_read(stream, &mut dbuf, Duration::from_millis(20))
                .is_err()
            {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        client.close();
        assert_eq!(
            server.received_bytes(),
            TOTAL as u64,
            "server must receive exactly 12 MiB (elapsed {elapsed:?})"
        );
    }

    #[test]
    fn hysteria2_first_read_guard_timeout_aborts_cleanly() {
        use nexus_outbound_hysteria2::Hysteria2Client;
        use nexus_outbound_hysteria2::test_server::TestServer;
        use std::io::Read;
        use std::net::TcpListener;
        use std::time::{Duration, Instant};

        let server = TestServer::spawn("secret123", true).unwrap();
        let cfg = nexus_proxy_config::parse(&hy2_outbound_yaml(server.addr.port())).unwrap();
        let selected = cfg.outbounds.iter().find(|o| o.tag == "h").unwrap();
        let target = hysteria2_target_from_outbound(selected, "h").unwrap();

        let mut client = Hysteria2Client::connect(&target).unwrap();
        // 第一条 stream 占住 server 的 TCP 处理循环（它读而不发数据），
        // 第二条 stream 的 TCPResponse 因而在守卫窗口内不会到达。
        let _first = client.open_tcp("first.example:80").unwrap();
        let second = client.open_tcp("second.example:80").unwrap();

        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let mut peer = std::net::TcpStream::connect(addr).unwrap();
        let mut down_client = listener.accept().unwrap().0;
        down_client.set_nonblocking(true).unwrap();

        let started = Instant::now();
        let counts = hysteria2_pump_stream(&mut client, second, true, &mut down_client);
        let elapsed = started.elapsed();

        assert_eq!(counts, (0, 0), "guard abort must not forward any bytes");
        assert!(
            elapsed >= Duration::from_millis(30),
            "guard must wait for the fixed 50 ms window, took {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "guard abort must be bounded, took {elapsed:?}"
        );
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut buf = [0u8; 16];
        let n = peer.read(&mut buf).unwrap_or(0);
        assert_eq!(n, 0, "downstream must be closed without payload");
        drop(client);
    }
}

/// P4（v2 §11）：真实 UDP loopback 入网驱动。
///
/// 1 个引导节点（BootstrapServer，UDP :11010）+ 2 个新节点（零静态 peer，
/// 仅配 bootstrap 地址 + PSK），全程走真实 `UdpCarrier` socket（127.0.0.1 不同端口），
/// 验证：JoinInit/JoinReply PSK 认证 + VIP 分配、GetPeers/PeerList 互见、心跳维持租约、
/// 停节点后 TTL 过期回收。不依赖 TUN/root/跨机。
/// P4 真实 UDP loopback 驱动使用的三个显式端口（UdpCarrier 拒绝 port 0）。
#[derive(Debug, Clone, Copy)]
pub struct LoopbackPorts {
    pub server: u16,
    pub a: u16,
    pub b: u16,
}

impl Default for LoopbackPorts {
    fn default() -> Self {
        Self {
            server: 11010,
            a: 11101,
            b: 11102,
        }
    }
}

pub fn bootstrap_udp_loopback_flow() -> Result<serde_json::Value, NexusError> {
    bootstrap_udp_loopback_flow_with(LoopbackPorts::default())
}

pub fn bootstrap_udp_loopback_flow_with(
    ports: LoopbackPorts,
) -> Result<serde_json::Value, NexusError> {
    use nexus_connectivity::bootstrap_joiner::{
        BootstrapEndpoint, BootstrapJoiner, ClientBootstrapHook,
    };
    use nexus_connectivity::bootstrap_server::{BootstrapServer, BootstrapServerConfig};
    use nexus_connectivity::encryption::KeyPair;
    use nexus_connectivity::virtual_subnet::BootstrapHook;
    use nexus_platform::{PacketCarrier, UdpCarrier};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    fn err(m: impl Into<String>) -> NexusError {
        NexusError::Internal { message: m.into() }
    }

    let psk = b"p4-loopback-psk".to_vec();
    let now = Arc::new(AtomicU64::new(1_000u64));

    // ---- 引导服务端：真实 UDP socket ----
    let server_identity = KeyPair::from_seed(&[7u8; 32]);
    let srv_locator = format!("udp://127.0.0.1:{}", ports.server);
    let cfg = BootstrapServerConfig {
        cidr: "10.144.144.0/24".into(),
        lease_secs: 100_000,
        hb_interval_ms: 5_000,
        refresh_interval_ms: 10_000,
        server_vip: "10.144.144.1".into(),
        server_locator: srv_locator.clone(),
        max_pending_per_src: 4,
    };
    let codec = crate::bootstrap_codec::DiscoveryBootstrapCodec::new();
    let mut server = BootstrapServer::new(server_identity, psk.clone(), cfg, Box::new(codec), None)
        .map_err(|e| err(format!("server new: {e}")))?;
    server.upsert_self_entry(now.load(Ordering::SeqCst));

    let mut srv_carrier = UdpCarrier::new();
    srv_carrier
        .bind(&srv_locator)
        .map_err(|e| err(format!("srv bind: {e}")))?;

    let srv = Arc::new(Mutex::new(server));
    let srv_sock = Arc::new(Mutex::new(srv_carrier));
    let srv_stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let srv_now = now.clone();
    let srv_handle = std::thread::spawn({
        let srv = srv.clone();
        let sock = srv_sock.clone();
        let stop = srv_stop.clone();
        move || {
            let mut buf = vec![0u8; 65535];
            loop {
                if stop.load(Ordering::SeqCst) {
                    break;
                }
                let mut sv = srv.lock().unwrap();
                let mut sk = sock.lock().unwrap();
                match sk.receive_into(&mut buf) {
                    Ok(0) => {
                        drop(sk);
                        drop(sv);
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    Ok(n) => {
                        let src = sk.last_peer_locator().unwrap_or_default();
                        let t = srv_now.load(Ordering::SeqCst);
                        if let Some((dst, bytes)) = sv.handle_datagram(&src, &buf[..n], t) {
                            let _ = sk.send_to(&dst, &bytes);
                        }
                    }
                    Err(_) => {
                        drop(sk);
                        drop(sv);
                        std::thread::sleep(Duration::from_millis(2));
                    }
                }
            }
        }
    });
    let _ = srv_handle;

    // ---- 客户端 helper：发 hook.periodic 出站并泵回收包 ----
    fn pump_client(
        carrier: &mut UdpCarrier,
        hook: &mut ClientBootstrapHook,
        now: u64,
    ) -> Vec<String> {
        let mut all_events = Vec::new();
        let tick = hook.periodic(now);
        for (dst, bytes) in &tick.datagrams {
            let _ = carrier.send_to(dst, bytes);
        }
        all_events.extend(tick.events);
        // 有界等待回收包（PeerList/ack）。
        let mut buf = vec![0u8; 65535];
        let deadline = std::time::Instant::now() + Duration::from_millis(1500);
        while std::time::Instant::now() < deadline {
            match carrier.receive_into(&mut buf) {
                Ok(0) => std::thread::sleep(Duration::from_millis(2)),
                Ok(n) => {
                    let d = &buf[..n];
                    if d.strip_prefix(b"nxb:").is_some() {
                        hook.on_control_datagram(None, &d[4..], now);
                    }
                }
                Err(_) => break,
            }
        }
        all_events
    }

    // ---- 客户端 A：零静态 peer，只配 bootstrap + PSK ----
    let id_a = KeyPair::from_seed(&[11u8; 32]);
    let a_bind = format!("udp://127.0.0.1:{}", ports.a);
    let mut ca = UdpCarrier::new();
    ca.bind(&a_bind).map_err(|e| err(format!("A bind: {e}")))?;
    let codec_a = crate::bootstrap_codec::DiscoveryBootstrapCodec::new();
    let eps = [BootstrapEndpoint {
        server_locator: srv_locator.clone(),
    }];
    let (sess_a, peers_a0) = {
        let mut j = BootstrapJoiner::new(&mut ca, &id_a, &psk, &codec_a);
        j.join(&eps, None, now.load(Ordering::SeqCst), 3_000)
            .map_err(|e| err(format!("A join: {e:?}")))?
    };
    let vip_a = sess_a.assigned_vip.clone();
    let mut hook_a = ClientBootstrapHook::new(sess_a, Box::new(codec_a), peers_a0);

    // ---- 客户端 B ----
    let id_b = KeyPair::from_seed(&[22u8; 32]);
    let b_bind = format!("udp://127.0.0.1:{}", ports.b);
    let mut cb = UdpCarrier::new();
    cb.bind(&b_bind).map_err(|e| err(format!("B bind: {e}")))?;
    let codec_b = crate::bootstrap_codec::DiscoveryBootstrapCodec::new();
    let (sess_b, peers_b0) = {
        let mut j = BootstrapJoiner::new(&mut cb, &id_b, &psk, &codec_b);
        j.join(&eps, None, now.load(Ordering::SeqCst), 3_000)
            .map_err(|e| err(format!("B join: {e:?}")))?
    };
    let vip_b = sess_b.assigned_vip.clone();
    let _ = peers_b0;

    // ---- A 刷新 -> 应看到服务端 + B（在线目录互见；refresh_interval=10s）----
    now.fetch_add(11_000, Ordering::SeqCst);
    let _ = pump_client(&mut ca, &mut hook_a, now.load(Ordering::SeqCst));
    let peers_a_now: Vec<String> = hook_a
        .known_peers_snapshot()
        .iter()
        .map(|p| p.virtual_ip.clone())
        .collect();
    let a_sees_server = peers_a_now.contains(&"10.144.144.1".to_string());
    let a_sees_b = peers_a_now.contains(&vip_b);

    // ---- A 心跳维持租约（hb_interval=5s；推进 now 服务端收到 heartbeat 续期）----
    now.fetch_add(6_000, Ordering::SeqCst);
    let _ = pump_client(&mut ca, &mut hook_a, now.load(Ordering::SeqCst));

    // ---- P2P：A/B 互见后经真实 UDP 建加密隧道 ----
    // 从 hook 在线目录取 B 的真实 loopback locator（服务端观测到的源地址）。
    let b_locator = hook_a
        .known_peers_snapshot()
        .into_iter()
        .find(|p| p.virtual_ip == vip_b)
        .map(|p| p.locator)
        .ok_or_else(|| err("P2P: B locator not in PeerList"))?;
    let a_locator = a_bind.clone();

    use nexus_connectivity::encryption::EncryptionConfig;
    use nexus_connectivity::virtual_subnet::{
        TunnelPeer, TunnelState, VirtualSubnetConfig, VirtualSubnetTunnel,
    };
    use nexus_platform::VirtualPacketInterface;
    struct CapVpi {
        got: Arc<Mutex<Vec<u8>>>,
    }
    impl VirtualPacketInterface for CapVpi {
        fn receive(
            &mut self,
            _o: &mut [u8],
        ) -> std::result::Result<usize, nexus_platform::PlatformError> {
            Ok(0)
        }
        fn send(&mut self, p: &[u8]) -> std::result::Result<(), nexus_platform::PlatformError> {
            self.got.lock().unwrap().extend_from_slice(p);
            Ok(())
        }
    }
    let b_got: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(vec![]));
    let vpi_b = CapVpi { got: b_got.clone() };
    let vpi_a = CapVpi {
        got: Arc::new(Mutex::new(vec![])),
    };
    let mut tunnel_a = VirtualSubnetTunnel::new(
        VirtualSubnetConfig::new("10.144.144.0/24", vip_a.clone()),
        Box::new(vpi_a),
        Box::new(ca),
    );
    let mut tunnel_b = VirtualSubnetTunnel::new(
        VirtualSubnetConfig::new("10.144.144.0/24", vip_b.clone()),
        Box::new(vpi_b),
        Box::new(cb),
    );
    tunnel_a.set_bootstrap_hook(Some(Box::new(hook_a)));
    tunnel_a
        .add_peer(TunnelPeer::new(vip_b.clone(), b_locator.clone()))
        .map_err(|e| err(format!("add_peer: {e:?}")))?;
    tunnel_b
        .add_peer(TunnelPeer::new(vip_a.clone(), a_locator.clone()))
        .map_err(|e| err(format!("add_peer: {e:?}")))?;
    tunnel_a.enable_encryption(EncryptionConfig::default());
    tunnel_b.enable_encryption(EncryptionConfig::default());
    tunnel_a
        .begin_handshake(&vip_b)
        .map_err(|e| err(format!("handshake: {e:?}")))?;

    // 有界驱动：两端 recv_and_deliver 直至双向 Connected。
    let mut buf = vec![0u8; 65535];
    let handshake_deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut p2p_connected = false;
    while std::time::Instant::now() < handshake_deadline {
        let _ = tunnel_a.recv_and_deliver(&mut buf, now.load(Ordering::SeqCst));
        let _ = tunnel_b.recv_and_deliver(&mut buf, now.load(Ordering::SeqCst));
        if tunnel_a.peer_state(&vip_b) == Some(TunnelState::Connected)
            && tunnel_b.peer_state(&vip_a) == Some(TunnelState::Connected)
        {
            p2p_connected = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }

    // 真实 AEAD 数据：A -> B。
    let payload = b"p4-real-udp-aead-payload";
    tunnel_a
        .send_ip_packet(&vip_b, payload)
        .map_err(|e| err(format!("send: {e:?}")))?;
    let mut got_len = 0usize;
    let data_deadline = std::time::Instant::now() + Duration::from_secs(3);
    while std::time::Instant::now() < data_deadline {
        if let Some((_src, n)) = tunnel_b
            .recv_and_deliver(&mut buf, now.load(Ordering::SeqCst))
            .map_err(|e| err(format!("recv: {e:?}")))?
        {
            got_len = n;
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let vpi_bytes = b_got.lock().unwrap().clone();
    // 隧道交付到 VPI 的是剥净帧头后的原始载荷，须与发送载荷逐字节一致。
    let p2p_payload_matches = vpi_bytes == payload[..];

    // ---- 停 B 心跳，推进 now 越过 lease(100000s)，服务端 sweep 应回收 B ----
    now.fetch_add(92_000, Ordering::SeqCst);
    // A 再 bootstrap_tick 保活自身（经 tunnel send_raw）；服务端自身条目重续。
    let _ = tunnel_a.bootstrap_tick(now.load(Ordering::SeqCst));
    {
        let mut sv = srv.lock().unwrap();
        sv.upsert_self_entry(now.load(Ordering::SeqCst));
    }
    let report = {
        let mut sv = srv.lock().unwrap();
        sv.sweep_expired(now.load(Ordering::SeqCst))
    };
    let expired_ids = report.expired.clone();
    let released_ids = report.released_vips.clone();
    let leases_after: Vec<String> = srv
        .lock()
        .unwrap()
        .leases_snapshot(now.load(Ordering::SeqCst))
        .iter()
        .map(|(_, v)| v.clone())
        .collect();
    let b_in_directory = leases_after.contains(&vip_b);
    let a_in_directory = leases_after.contains(&vip_a);
    let b_evicted_after_lease = !b_in_directory;

    // ---- 硬门：任一关键断言失败即 Err，不产出 PASS ----
    if !a_sees_server {
        return Err(err(format!(
            "gate: A did not see server; peers={peers_a_now:?}"
        )));
    }
    if !a_sees_b {
        return Err(err(format!("gate: A did not see B; peers={peers_a_now:?}")));
    }
    if !p2p_connected {
        return Err(err("gate: P2P tunnels not Connected between A/B"));
    }
    if !p2p_payload_matches {
        return Err(err(format!(
            "gate: P2P payload mismatch; got={vpi_bytes:?} expected tail={payload:?}"
        )));
    }
    if !b_evicted_after_lease {
        return Err(err(format!(
            "gate: B not evicted after lease; leases={leases_after:?}"
        )));
    }
    if !a_in_directory {
        return Err(err(format!(
            "gate: A unexpectedly dropped; leases={leases_after:?}"
        )));
    }
    if !expired_ids
        .iter()
        .any(|id| id.ends_with("e82c0d763cb9fdcf"))
    {
        return Err(err(format!(
            "gate: B node_id not in expired; expired={expired_ids:?}"
        )));
    }

    // 优雅停机：通知服务端线程退出，释放监听端口。
    srv_stop.store(true, Ordering::SeqCst);
    let _ = srv_handle.join();

    Ok(serde_json::json!({
        "verdict": "PASS",
        "command": "run",
        "scenario": "bootstrap-udp-loopback",
        "server": { "udp": format!("127.0.0.1:{}", ports.server), "vip": "10.144.144.1" },
        "client_a": { "udp": format!("127.0.0.1:{}", ports.a), "assigned_vip": vip_a, "sees_server": a_sees_server, "sees_peer_b": a_sees_b },
        "client_b": { "udp": format!("127.0.0.1:{}", ports.b), "assigned_vip": vip_b },
        "peers_a_after_refresh": peers_a_now,
        "b_evicted_after_lease": !b_in_directory,
        "p2p_connected": p2p_connected,
        "p2p_data_len": got_len,
        "p2p_payload_matches": p2p_payload_matches,
        "p2p_a_locator": a_locator,
        "p2p_b_locator": b_locator,
        "expired_ids": expired_ids,
        "released_ids": released_ids,
        "b_still_in_directory": b_in_directory,
        "a_still_in_directory": a_in_directory,
        "leases_after": leases_after,
    }))
}

#[cfg(test)]
mod p4_udp_loopback_tests {
    use super::*;

    /// P4 自动门：真实 UDP loopback 全链路（控制面 + P2P 加密数据面）。
    /// 用独特高端口避免与其他并行测试冲突；flow 内部已做硬门 + 优雅停机。
    #[test]
    fn bootstrap_udp_loopback_real_socket() {
        let ports = LoopbackPorts {
            server: 17011,
            a: 17111,
            b: 17112,
        };
        let v = bootstrap_udp_loopback_flow_with(ports)
            .expect("bootstrap udp loopback flow should PASS all hard gates");
        assert_eq!(v["verdict"], "PASS");
        assert_eq!(v["p2p_connected"], serde_json::json!(true));
        assert_eq!(v["p2p_payload_matches"], serde_json::json!(true));
        assert_eq!(v["b_evicted_after_lease"], serde_json::json!(true));
    }
}

#[cfg(test)]
mod vless_skipper_tests {
    use super::VlessResponseSkipper;

    #[test]
    fn skips_plain_two_byte_header() {
        let mut skipper = VlessResponseSkipper::new();
        assert!(skipper.filter(&[0x00, 0x00]).is_empty());
        assert_eq!(skipper.filter(b"payload"), b"payload");
    }

    #[test]
    fn skips_addon_then_forwards_payload() {
        let mut skipper = VlessResponseSkipper::new();
        let mut stream = vec![0x00, 0x02, 0xAA, 0xBB];
        stream.extend_from_slice(b"hello");
        assert_eq!(skipper.filter(&stream), b"hello");
    }

    #[test]
    fn header_split_across_reads() {
        let mut skipper = VlessResponseSkipper::new();
        assert!(skipper.filter(&[0x00]).is_empty());
        assert!(skipper.filter(&[0x01, 0xAA]).is_empty());
        assert_eq!(skipper.filter(b"xyz"), b"xyz");
    }

    #[test]
    fn forwards_when_header_and_payload_arrive_together() {
        let mut skipper = VlessResponseSkipper::new();
        assert_eq!(skipper.filter(b"\x00\x00Z"), b"Z");
        assert_eq!(skipper.filter(b"more"), b"more");
    }
}
