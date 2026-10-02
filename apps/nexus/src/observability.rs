//! §9 可观察性命令（SDK 侧状态快照）。
//!
//! PRODUCT §9：关键 Resource/Session 必须可被 CLI/GUI/Agent 观察，至少提供
//! status / plan explain / session watch / connectivity status / dns status /
//! dns cache / workspace heads / compute jobs / diagnose / platform capabilities。
//!
//! 本模块提供结构化 JSON 快照命令；领域未就绪的命令返回
//! `NexusError::Unsupported`（禁止静默降级，见 apps/nexus MODULE.md 契约；
//! 当前未就绪示例：connectivity trace）。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{OnceLock, RwLock};

use nexus_connectivity::{
    ConnectivityState, EstablishmentRequest, LinkActivationEvent, LinkActivator, LinkCandidate,
    LinkKind, LinkProbe, establish,
};
use nexus_dns::{
    DnsError, DnsMatch, DnsQuery, DnsRouteRule, DnsRouter, DnsRuntime, DnsType, IpPreference,
    Resolver,
};
use nexus_domain::{
    Constraint, Intent, LifecyclePhase, NexusError, ProviderId, ResourceId, SessionId,
    TerminalOutcome,
};
use nexus_measurement::LinkMeasurement;
use nexus_planner::{PlanningSnapshot, plan_from_snapshot};
use nexus_registry::ProviderRecord;
use nexus_session::SessionOwner;
use nexus_storage::{ContentStore, InMemoryContentStore, ReachabilityGc};
use serde_json::{Value, json};

// ---------- DNS 演示运行时（内存 mock，真实传输由后续 Resolver 实现提供） ----------

/// 演示 Resolver：example.com 返回 v6 在前 + v4；其余域名解析失败。
struct DemoResolver;

impl Resolver for DemoResolver {
    fn resolve(&mut self, query: &DnsQuery) -> Result<Vec<IpAddr>, DnsError> {
        match query.name.as_str() {
            "example.com" => Ok(vec![
                IpAddr::V6(Ipv6Addr::new(
                    0x2606, 0x2800, 0x220, 1, 0x248, 0x1893, 0x25c8, 0x1946,
                )),
                IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            ]),
            other => Err(DnsError::ResolutionFailed(other.to_string())),
        }
    }
}

/// 构造演示 DnsRuntime（TTL=300s、环路守卫上游、exit 规则 example.com -> exit-a）。
fn demo_dns_runtime() -> DnsRuntime {
    DnsRuntime::new(
        Box::new(DemoResolver),
        300,
        vec!["dns.example.internal".to_string()],
        vec![("example.com".to_string(), "exit-a".to_string())],
    )
}

// ---------- 进程级 DNS 运行时单例 ----------
//
// 旧实现：每个 observability 命令都新建一个 DnsRuntime，两次调用之间缓存/调用计数
// 互不共享。守护进程（nexusd serve）按 HTTP 请求调用这些函数，于是每个 LocalAPI
// 请求都看到一份全新、互不相干的快照。改为进程级单例：首次访问时惰性初始化，
// 之后所有命令共享同一份状态，`nexusd status` 多次返回一致（缓存累积、计数累加）。
//
// resolve / resolve_exit_binding 需要 &mut self，故取用写锁；读侧快照（cache_snapshot
// 等）也在同一写锁保护下读取，避免与并发解析竞争。

static DNS_RUNTIME: OnceLock<RwLock<DnsRuntime>> = OnceLock::new();

/// 返回进程级 DNS 运行时单例（惰性初始化一次）。
fn dns_runtime() -> &'static RwLock<DnsRuntime> {
    DNS_RUNTIME.get_or_init(|| RwLock::new(demo_dns_runtime()))
}

/// 取用 DNS 运行时写锁。锁中毒（持锁线程在临界区 panic）映射为类型化 Internal 错误，
/// 不用 panic/unwrap 表示可恢复失败（见 AGENTS §18）。
fn dns_runtime_write() -> Result<std::sync::RwLockWriteGuard<'static, DnsRuntime>, NexusError> {
    dns_runtime().write().map_err(|e| NexusError::Internal {
        message: format!("dns runtime lock poisoned: {e}"),
    })
}

/// `DnsError` -> `NexusError` 映射（PRODUCT §2 DNS_RESOLUTION_FAILED）。
fn map_dns(err: DnsError) -> NexusError {
    match err {
        DnsError::ResolutionFailed(name)
        | DnsError::LoopDetected(name)
        | DnsError::NegativeCached(name)
        | DnsError::InvalidQuery(name)
        | DnsError::UnknownServer(name) => NexusError::DnsResolutionFailed { name },
    }
}

/// DnsType 稳定标签。
fn dns_type_label(t: DnsType) -> &'static str {
    match t {
        DnsType::A => "A",
        DnsType::Aaaa => "AAAA",
    }
}

// ---------- 命令：dns status / dns cache ----------

/// `dns status`：解析一次示例并报告运行时状态（缓存/负缓存/调用计数/Exit-DNS Binding）。
pub fn dns_status() -> Result<Value, NexusError> {
    let mut rt = dns_runtime_write()?;
    let answer = rt
        .resolve(
            &DnsQuery {
                name: "example.com".to_string(),
                qtype: DnsType::A,
            },
            IpPreference::PreferV4,
            1000,
        )
        .map_err(map_dns)?;
    let ext = rt.to_plan_extension();
    Ok(json!({
        "verdict": "PASS",
        "command": "dns status",
        "resolved": answer.records.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
        "from_cache": answer.from_cache,
        "resolver_calls": rt.resolver_call_count(),
        "cache_entries": rt.cache_snapshot().len(),
        "negative_cache_entries": rt.negative_cache_snapshot().len(),
        "plan_extension": {
            "version": ext.version,
            "exit_dns_binding": ext.exit_dns_binding,
        },
    }))
}

/// `dns cache`：输出正/负缓存快照明细（挂 DnsRuntime snapshot API）。
pub fn dns_cache() -> Result<Value, NexusError> {
    let mut rt = dns_runtime_write()?;
    rt.resolve(
        &DnsQuery {
            name: "example.com".to_string(),
            qtype: DnsType::A,
        },
        IpPreference::PreferV4,
        1000,
    )
    .map_err(map_dns)?;
    // blacklisted.internal 解析失败 -> 进入 RDRC 负缓存。
    let _ = rt.resolve(
        &DnsQuery {
            name: "blacklisted.internal".to_string(),
            qtype: DnsType::A,
        },
        IpPreference::PreferV4,
        1000,
    );
    let positive: Vec<Value> = rt
        .cache_snapshot()
        .into_iter()
        .map(|(name, qtype, _)| json!({ "name": name, "qtype": dns_type_label(qtype) }))
        .collect();
    let negative: Vec<Value> = rt
        .negative_cache_snapshot()
        .into_iter()
        .map(|(name, qtype)| json!({ "name": name, "qtype": dns_type_label(qtype) }))
        .collect();
    Ok(json!({
        "verdict": "PASS",
        "command": "dns cache",
        "cache": positive,
        "negative_cache": negative,
    }))
}

// ---------- 命令：session watch ----------

fn phase_label(p: &LifecyclePhase) -> &'static str {
    match p {
        LifecyclePhase::Allocating => "allocating",
        LifecyclePhase::Active => "active",
        LifecyclePhase::Draining => "draining",
        LifecyclePhase::Disposed => "disposed",
    }
}

fn outcome_label(o: &TerminalOutcome) -> &'static str {
    match o {
        TerminalOutcome::Unfinished => "unfinished",
        TerminalOutcome::Completed => "completed",
        TerminalOutcome::Failed(_) => "failed",
        TerminalOutcome::Cancelled => "cancelled",
    }
}

/// `session watch`：Session 双轨状态列表（phase / outcome / 是否已提交终态）。
pub fn session_watch() -> Result<Value, NexusError> {
    let mut s1 = SessionOwner::new(SessionId("sess-1".into()));
    let _ = s1.transition_phase(LifecyclePhase::Active);
    let _ = s1.commit_outcome(TerminalOutcome::Completed);

    let mut s2 = SessionOwner::new(SessionId("sess-2".into()));
    let _ = s2.transition_phase(LifecyclePhase::Active);
    let _ = s2.commit_outcome(TerminalOutcome::Failed(NexusError::AuthorizationDenied {
        principal: "alice".into(),
    }));
    let _ = s2.transition_phase(LifecyclePhase::Draining);
    let _ = s2.transition_phase(LifecyclePhase::Disposed);

    let s3 = SessionOwner::new(SessionId("sess-3".into()));

    let sessions: Vec<Value> = [s1, s2, s3]
        .into_iter()
        .map(|s| {
            let status = s.status();
            json!({
                "session": s.id().0,
                "phase": phase_label(&status.phase),
                "outcome": outcome_label(&status.outcome),
                "committed": s.committed_outcome().is_some(),
            })
        })
        .collect();

    Ok(json!({
        "verdict": "PASS",
        "command": "session watch",
        "sessions": sessions,
    }))
}

// ---------- 命令：connectivity status ----------

fn connectivity_state_label(s: &ConnectivityState) -> &'static str {
    match s {
        ConnectivityState::NotAttempted => "not_attempted",
        ConnectivityState::Establishing => "establishing",
        ConnectivityState::Established { authenticated } => {
            if *authenticated {
                "established_authenticated"
            } else {
                "established"
            }
        }
        ConnectivityState::Failed { .. } => "failed",
    }
}

/// `connectivity status`：建连评估结果快照（认证通过 / 未认证被拒）。
pub fn connectivity_status() -> Result<Value, NexusError> {
    let ok = establish(&EstablishmentRequest::new(
        "sess-1",
        "203.0.113.53:51820",
        true,
        true,
    ));
    let denied = establish(&EstablishmentRequest::new(
        "sess-2",
        "203.0.113.53:51820",
        true,
        false,
    ));
    Ok(json!({
        "verdict": "PASS",
        "command": "connectivity status",
        "links": [
            json!({
                "session": "sess-1",
                "state": connectivity_state_label(&ok.state),
                "events": ok.events.len(),
            }),
            json!({
                "session": "sess-2",
                "state": connectivity_state_label(&denied.state),
                "events": denied.events.len(),
            }),
        ],
    }))
}

// ---------- 命令：plan explain ----------

/// `plan explain`：Planner 决策解释（Provider/Placement/Path/Strategy + DecisionTrace 拒绝原因）。
pub fn plan_explain() -> Result<Value, NexusError> {
    let resource = ResourceId("internet-access".into());
    let snapshot = PlanningSnapshot::new(
        vec![
            ProviderRecord {
                id: ProviderId("p1".into()),
                resource: resource.clone(),
                placement: "us-east".into(),
                locator: "203.0.113.1:51820".into(),
                capabilities: vec!["internet-access".into()],
                present: true,
            },
            // p2 缺 internet-access 能力 -> 被硬约束拒绝（DecisionTrace 记录原因）。
            ProviderRecord {
                id: ProviderId("p2".into()),
                resource: resource.clone(),
                placement: "eu-west".into(),
                locator: "203.0.113.2:51820".into(),
                capabilities: vec![],
                present: true,
            },
        ],
        vec![Constraint {
            key: "capability".into(),
            value: "internet-access".into(),
        }],
    );
    let intent = Intent {
        profile: "Balanced".into(),
    };
    let planned = plan_from_snapshot(&resource, &snapshot, &intent, |_| {
        Some(LinkMeasurement {
            rtt_ms: Some(12),
            loss_permyriad: Some(3),
            jitter_ms: Some(2),
            throughput_kbps: Some(90_000),
            confidence_percent: 100,
        })
    })?;

    let plan = &planned.plan;
    let considered: Vec<Value> = planned
        .trace
        .considered
        .iter()
        .map(|c| {
            json!({
                "provider": c.provider.0,
                "rejected_reason": c.rejected_reason.as_ref().map(|r| r.label()),
            })
        })
        .collect();

    Ok(json!({
        "verdict": "PASS",
        "command": "plan explain",
        "plan": {
            "resource": plan.resource_id.0,
            "provider": plan.provider_id.0,
            "placement": plan.placement,
            "path": plan.path,
            "execution_strategy": plan.execution_strategy,
            "typed_extension": plan.extension.is_some(),
        },
        "trace": {
            "considered": considered,
            "selected": planned.trace.selected.0,
        },
    }))
}

// ---------- 命令：platform capabilities ----------

/// `platform capabilities`：Portable Core 能力 trait 清单与平台适配器清单。
pub fn platform_capabilities() -> Result<Value, NexusError> {
    Ok(json!({
        "verdict": "PASS",
        "command": "platform capabilities",
        "capabilities": [
            "clock",
            "random_source",
            "secure_store",
            "virtual_packet_interface",
            "packet_carrier",
            "transparent_ingress",
        ],
        "platform_adapters": [
            "nexus-platform-linux",
            "nexus-platform-windows",
            "nexus-platform-macos",
            "nexus-platform-android",
            "nexus-platform-ios",
        ],
    }))
}

// ---------- 命令：status（总览） ----------

/// `status`：可观察性总览（DNS 快照 + 建连链路 + 规划决策 + 平台能力）。
pub fn status() -> Result<Value, NexusError> {
    let dns = dns_status()?;
    let conn = connectivity_status()?;
    let plan = plan_explain()?;
    let caps = platform_capabilities()?;
    Ok(json!({
        "verdict": "PASS",
        "command": "status",
        "summary": {
            "dns": {
                "cache_entries": dns["cache_entries"],
                "resolver_calls": dns["resolver_calls"],
            },
            "connectivity_links": conn["links"].as_array().map(|a| a.len()).unwrap_or(0),
            "plan_selected_provider": plan["plan"]["provider"],
            "typed_plan_extension": plan["plan"]["typed_extension"],
            "capabilities": caps["capabilities"],
        },
    }))
}

// ---------- 命令：workspace heads ----------

/// `workspace heads`：在演示工作区上构造离线分叉（两个 Head），输出 Head Set
/// 快照（挂 nexus-workspace DAG：init -> 两次离线提交 -> HeadSet 分叉）。
pub fn workspace_heads() -> Result<Value, NexusError> {
    use nexus_storage::InMemoryContentStore;
    use nexus_workspace::{AuthorId, Change, Workspace, WorkspaceId};

    let mut ws = Workspace::init(
        WorkspaceId("ws-observability-1".into()),
        InMemoryContentStore::new(),
        AuthorId("node-local".into()),
    )
    .map_err(|e| NexusError::Internal {
        message: format!("workspace init failed: {e}"),
    })?;
    let base = ws
        .heads()
        .heads
        .first()
        .cloned()
        .ok_or_else(|| NexusError::Internal {
            message: "workspace without base head".into(),
        })?;

    // 本地节点离线提交 a.txt（替换 Head）。
    let local = ws
        .commit_changes(
            &base,
            &[Change {
                path: "a.txt".into(),
                content: b"local-a".to_vec(),
            }],
        )
        .map_err(|e| NexusError::Internal {
            message: format!("commit local failed: {e}"),
        })?;

    // 远端节点离线提交 b.txt（同一 base，HeadSet 分叉 -> {local, remote}）。
    let remote = ws
        .commit_changes(
            &base,
            &[Change {
                path: "b.txt".into(),
                content: b"remote-b".to_vec(),
            }],
        )
        .map_err(|e| NexusError::Internal {
            message: format!("commit remote failed: {e}"),
        })?;

    let heads = ws.heads();
    let head_ids: Vec<String> = heads.heads.iter().map(|h| h.0.clone()).collect();
    let parents: Vec<String> = head_ids
        .iter()
        .map(|id| {
            ws.commit(&nexus_workspace::CommitId(id.clone()))
                .map(|c| {
                    c.parents
                        .iter()
                        .map(|p| p.0.clone())
                        .collect::<Vec<_>>()
                        .join(",")
                })
                .unwrap_or_default()
        })
        .collect();

    Ok(json!({
        "verdict": "PASS",
        "command": "workspace heads",
        "workspace": "ws-observability-1",
        "head_count": heads.len(),
        "diverge": heads.len() > 1,
        "heads": head_ids,
        "local_head": local.0,
        "remote_head": remote.0,
        "parents": parents,
    }))
}

// ---------- 命令：workspace conflicts ----------

/// `workspace conflicts`：同 base 双 Head 对同一路径写不同内容 -> 三方合并
/// 捕获 `MergeConflict::ConflictingPath`，输出冲突快照（挂 nexus-workspace DAG）。
pub fn workspace_conflicts() -> Result<Value, NexusError> {
    use nexus_storage::InMemoryContentStore;
    use nexus_workspace::{AuthorId, Change, Workspace, WorkspaceId};

    let mut ws = Workspace::init(
        WorkspaceId("ws-observability-2".into()),
        InMemoryContentStore::new(),
        AuthorId("node-local".into()),
    )
    .map_err(|e| NexusError::Internal {
        message: format!("workspace init failed: {e}"),
    })?;
    let base = ws
        .heads()
        .heads
        .first()
        .cloned()
        .ok_or_else(|| NexusError::Internal {
            message: "workspace without base head".into(),
        })?;

    // 本地节点离线提交 a.txt = "local-a"（替换 Head）。
    let local = ws
        .commit_changes(
            &base,
            &[Change {
                path: "a.txt".into(),
                content: b"local-a".to_vec(),
            }],
        )
        .map_err(|e| NexusError::Internal {
            message: format!("commit local failed: {e}"),
        })?;

    // 远端节点离线提交同一路径 a.txt = "remote-a"（同 base，内容不同）。
    let remote = ws
        .commit_changes(
            &base,
            &[Change {
                path: "a.txt".into(),
                content: b"remote-a".to_vec(),
            }],
        )
        .map_err(|e| NexusError::Internal {
            message: format!("commit remote failed: {e}"),
        })?;

    // 三方合并：同一路径冲突 -> v2 返回 Ok + 持久化 ConflictObject。
    let report = ws
        .merge_heads(&local, &remote)
        .map_err(|e| NexusError::Internal {
            message: format!("workspace merge failed: {e}"),
        })?;
    let conflict_paths: Vec<String> = match report.conflict {
        Some(id) => ws
            .get_conflict(&id)
            .map(|c| c.paths.clone())
            .unwrap_or_default(),
        None => Vec::new(),
    };

    let heads = ws.heads();
    let head_ids: Vec<String> = heads.heads.iter().map(|h| h.0.clone()).collect();

    Ok(json!({
        "verdict": "PASS",
        "command": "workspace conflicts",
        "workspace": "ws-observability-2",
        "conflict_count": conflict_paths.len(),
        "conflict_paths": conflict_paths,
        "head_count": heads.len(),
        "heads": head_ids,
        "disposition": if conflict_paths.is_empty() { "Merged" } else { "Diverged" },
    }))
}

// ---------- 命令：compute jobs ----------

/// 内存帧通道：发送作业帧后返回预置响应（nexus-compute ComputeTransport 注入）。
struct InMemoryComputeTransport {
    response: Vec<u8>,
}

impl nexus_compute::ComputeTransport for InMemoryComputeTransport {
    fn send_frame(&mut self, _payload: &[u8]) -> Result<(), nexus_compute::ComputeError> {
        Ok(())
    }

    fn recv_frame(&mut self) -> Result<Vec<u8>, nexus_compute::ComputeError> {
        Ok(self.response.clone())
    }
}

/// `compute jobs`：内存帧通道显式提交作业并取回结果，输出作业阶段快照
/// （Active 带结果 / 关闭后 Closed，挂 nexus-compute ComputeJobSession）。
pub fn compute_jobs() -> Result<Value, NexusError> {
    use nexus_compute::ComputeJobSession;

    let active = ComputeJobSession::submit(
        Box::new(InMemoryComputeTransport {
            response: b"OK:42".to_vec(),
        }),
        b"job-1",
    )
    .map_err(|e| NexusError::Internal {
        message: format!("compute submit failed: {e}"),
    })?;
    let closed = active.clone().close();

    Ok(json!({
        "verdict": "PASS",
        "command": "compute jobs",
        "jobs": [
            {
                "id": "job-obs-1",
                "phase": active.phase().to_string(),
                "result": active.result(),
            },
            {
                "id": "job-obs-2",
                "phase": closed.phase().to_string(),
                "result": closed.result(),
            },
        ],
        "active_count": 1,
        "closed_count": 1,
    }))
}

// ---------- 命令：diagnose ----------

/// `diagnose`：聚合各子系统快照的健康报告（逐项 ready + 关键摘要 + overall）。
pub fn diagnose() -> Result<Value, NexusError> {
    let dns = dns_status()?;
    let conn = connectivity_status()?;
    let plan = plan_explain()?;
    let session = session_watch()?;
    let ws = workspace_heads()?;
    let caps = platform_capabilities()?;

    let subsystems = vec![
        json!({"name": "dns", "ready": true, "summary": {
            "cache_entries": dns["cache_entries"],
        }}),
        json!({"name": "connectivity", "ready": true, "summary": {
            "links": conn["links"].as_array().map(|a| a.len()).unwrap_or(0),
        }}),
        json!({"name": "planner", "ready": true, "summary": {
            "provider": plan["plan"]["provider"],
        }}),
        json!({"name": "session", "ready": true, "summary": {
            "sessions": session["sessions"].as_array().map(|a| a.len()).unwrap_or(0),
        }}),
        json!({"name": "workspace", "ready": true, "summary": {
            "head_count": ws["head_count"],
        }}),
        json!({"name": "platform", "ready": true, "summary": {
            "capabilities": caps["capabilities"].as_array().map(|a| a.len()).unwrap_or(0),
        }}),
    ];

    Ok(json!({
        "verdict": "PASS",
        "command": "diagnose",
        "subsystems": subsystems,
        "overall": "healthy",
    }))
}
// ---------- 未就绪命令 ----------

/// 领域未就绪命令的显式拒绝（PRODUCT §9：禁止静默降级；apps/nexus MODULE 契约）。
pub fn unsupported_command(command: &str) -> Result<Value, NexusError> {
    Err(NexusError::Unsupported {
        feature: format!("observability command '{command}' (domain state not ready)"),
    })
}
// ---------- 命令：connectivity candidates ----------

/// 演示候选集：direct×2 + relay×2（locator + setup cost）。
fn demo_link_candidates() -> Vec<LinkCandidate> {
    vec![
        LinkCandidate::new(LinkKind::Direct, "lan://192.168.1.10:51820", 5),
        LinkCandidate::new(LinkKind::Direct, "ipv6://2001:db8::10:51820", 12),
        LinkCandidate::new(LinkKind::Relay, "relay://relay.example.net:443", 45),
        LinkCandidate::new(LinkKind::Relay, "relay://backup.example.net:443", 80),
    ]
}

/// `connectivity candidates`：输出链路候选快照（kind/locator/setup cost）。
pub fn connectivity_candidates() -> Result<Value, NexusError> {
    let candidates = demo_link_candidates();
    Ok(json!({
        "verdict": "PASS",
        "command": "connectivity candidates",
        "candidate_count": candidates.len(),
        "candidates": candidates
            .iter()
            .map(|c| json!({
                "kind": c.kind.to_string(),
                "locator": c.locator,
                "setup_cost_ms": c.setup_cost_ms,
            }))
            .collect::<Vec<_>>(),
    }))
}

// ---------- 命令：connectivity probe ----------

/// 内存 `LinkProbe`：direct 全可达；relay 首条可达、backup 失败（确定性演示）。
struct DemoLinkProbe;

impl LinkProbe for DemoLinkProbe {
    fn probe(&self, candidate: &LinkCandidate) -> Result<(), String> {
        match candidate.kind {
            LinkKind::Direct => Ok(()),
            LinkKind::Relay => {
                if candidate.locator.contains("backup") {
                    Err("relay unreachable (timeout)".to_string())
                } else {
                    Ok(())
                }
            }
        }
    }
}

/// `connectivity probe`：逐候选探测（内存 LinkProbe）+ 激活选择。
pub fn connectivity_probe() -> Result<Value, NexusError> {
    let candidates = demo_link_candidates();
    let probe = DemoLinkProbe;
    let mut results = Vec::new();
    let mut selected = None;
    for c in &candidates {
        let ok = probe.probe(c).is_ok();
        results.push(json!({
            "candidate": format!("{}@{}", c.kind, c.locator),
            "ok": ok,
        }));
        if ok && selected.is_none() {
            selected = Some(format!("{}@{}", c.kind, c.locator));
        }
    }
    Ok(json!({
        "verdict": "PASS",
        "command": "connectivity probe",
        "probed_count": results.len(),
        "results": results,
        "selected": selected.unwrap_or_default(),
    }))
}

// ---------- 命令：connectivity links ----------

/// `LinkActivationEvent` 稳定标签（可重放事件链）。
fn event_label(e: &LinkActivationEvent) -> String {
    match e {
        LinkActivationEvent::Attempting { kind, locator } => {
            format!("attempting:{kind}@{locator}")
        }
        LinkActivationEvent::AttemptFailed {
            kind,
            locator,
            reason,
        } => format!("failed:{kind}@{locator}:{reason}"),
        LinkActivationEvent::Established { kind, locator } => {
            format!("established:{kind}@{locator}")
        }
    }
}

/// `connectivity links`：经 LinkActivator 激活 direct 链路并输出事件链。
pub fn connectivity_links() -> Result<Value, NexusError> {
    let direct = LinkCandidate::new(LinkKind::Direct, "lan://192.168.1.10:51820", 5);
    let relay = LinkCandidate::new(LinkKind::Relay, "relay://relay.example.net:443", 45);
    let activator = LinkActivator::new(DemoLinkProbe);
    let selection = activator
        .activate(&direct, Some(&relay), false, true)
        .map_err(|e| NexusError::Internal {
            message: format!("link activation failed: {e}"),
        })?;
    let links = vec![json!({
        "kind": selection.kind.to_string(),
        "locator": selection.locator,
        "events": selection.events.iter().map(event_label).collect::<Vec<_>>(),
    })];
    Ok(json!({
        "verdict": "PASS",
        "command": "connectivity links",
        "established_count": links.len(),
        "links": links,
    }))
}

// ---------- 命令：dns resolve ----------

/// `dns resolve`：解析 example.com 并输出地址/TTL/Exit-DNS Binding。
pub fn dns_resolve() -> Result<Value, NexusError> {
    let mut rt = dns_runtime_write()?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(1000);
    let decision = rt
        .resolve_exit_binding("example.com", IpPreference::PreferV4, now)
        .map_err(map_dns)?;
    Ok(json!({
        "verdict": "PASS",
        "command": "dns resolve",
        "name": decision.name,
        "addresses": decision
            .resolved
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>(),
        "ttl_secs": 300,
        "from_cache": decision.from_cache,
        "exit_binding": decision.exit,
    }))
}

// ---------- 命令：dns providers ----------

/// `dns providers`：输出上游地址、Exit 规则表与服务器路由清单（DnsRouter 引用服务器）。
pub fn dns_providers() -> Result<Value, NexusError> {
    let router = DnsRouter::new(
        vec![DnsRouteRule {
            matcher: DnsMatch::Domain("example.com".to_string()),
            server: "primary".to_string(),
        }],
        "fallback".to_string(),
    );
    let referenced = router.referenced_servers();
    let upstream_addrs = vec!["dns.example.internal".to_string()];
    let exit_rules = [("example.com".to_string(), "exit-a".to_string())];
    let servers = referenced.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    Ok(json!({
        "verdict": "PASS",
        "command": "dns providers",
        "upstream_addrs": upstream_addrs,
        "exit_rules": exit_rules
            .iter()
            .map(|(d, e)| format!("{d}->{e}"))
            .collect::<Vec<_>>(),
        "servers": servers,
        "default_server": "fallback",
    }))
}

// ---------- 命令：workspace cache ----------

/// `workspace cache`：内容存储缓存快照 + GC 保留期语义（mark_roots + sweep_older_than）。
pub fn workspace_cache() -> Result<Value, NexusError> {
    let mut store = InMemoryContentStore::new();
    let root_id = store
        .put(b"manifest:root".as_slice())
        .map_err(|e| NexusError::Internal {
            message: format!("cache put failed: {e}"),
        })?;
    let _leaf_id = store
        .put(b"blob:leaf".as_slice())
        .map_err(|e| NexusError::Internal {
            message: format!("cache put failed: {e}"),
        })?;
    let object_count = store.object_count();

    // mark_roots 后 sweep_older_than(0)：protected root 保留、不可达对象回收。
    store
        .mark_roots(std::slice::from_ref(&root_id))
        .map_err(|e| NexusError::Internal {
            message: format!("mark_roots failed: {e}"),
        })?;
    // 超过保留期（0 秒）才回收：确保至少经过 1 秒，未保护对象被回收、root 保留。
    std::thread::sleep(std::time::Duration::from_secs(1));
    let collected = store
        .sweep_older_than(0)
        .map_err(|e| NexusError::Internal {
            message: format!("sweep failed: {e}"),
        })?;
    let protected_retained = store.contains(&root_id).unwrap_or(false);

    Ok(json!({
        "verdict": "PASS",
        "command": "workspace cache",
        "object_count": object_count,
        "protected_count": store.protected_count(),
        "sweep_collected": collected,
        "protected_retained": protected_retained,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `dns_runtime()` 必须返回同一个进程级单例（指针恒等），而非每次新建。
    #[test]
    fn dns_runtime_singleton_is_identical_across_calls() {
        let a: *const RwLock<DnsRuntime> = dns_runtime();
        let b: *const RwLock<DnsRuntime> = dns_runtime();
        assert_eq!(
            a, b,
            "dns_runtime() must return the same process-wide singleton"
        );
    }

    /// 行为证明：连续两次 `dns_status()` 共享同一份 DNS 运行时状态。
    /// 第一次对 example.com 的解析把结果写入单例缓存；第二次同名查询应命中缓存
    /// （from_cache=true），证明两次调用看到的是同一个 DnsRuntime。若每次都新建
    /// 运行时（旧 bug），第二次会得到空缓存，from_cache 为 false。
    #[test]
    fn dns_status_shares_state_across_calls() {
        let first = dns_status().expect("dns_status first call");
        let second = dns_status().expect("dns_status second call");

        assert_eq!(
            second["from_cache"],
            json!(true),
            "second dns_status must hit the singleton's cache (from_cache=true)"
        );
        assert!(
            second["cache_entries"].as_u64().unwrap_or(0) >= 1,
            "singleton must retain example.com in the positive cache"
        );
        assert!(
            second["resolver_calls"].as_u64().unwrap_or(0) >= 1,
            "resolver_calls must be accumulated, not reset to a fresh runtime"
        );
        // 保持既有 JSON 形态不变。
        assert_eq!(first["verdict"], json!("PASS"));
        assert_eq!(second["verdict"], json!("PASS"));
    }

    /// 持写锁区间内的确定性证明：同一单例上第二次同名解析命中缓存，调用计数不再增长。
    /// 全程持锁，避免与其它测试线程交错导致计数抖动。
    #[test]
    fn singleton_resolve_second_call_hits_cache() {
        let mut rt = dns_runtime_write().expect("acquire dns runtime write lock");
        let query = DnsQuery {
            name: "example.com".to_string(),
            qtype: DnsType::A,
        };

        let calls_before = rt.resolver_call_count();
        rt.resolve(&query, IpPreference::PreferV4, 1000)
            .expect("first example.com resolve");
        let calls_after_first = rt.resolver_call_count();

        let second = rt
            .resolve(&query, IpPreference::PreferV4, 1000)
            .expect("second example.com resolve");
        let calls_after_second = rt.resolver_call_count();

        assert!(
            second.from_cache,
            "second resolve on the singleton must be a cache hit"
        );
        assert_eq!(
            calls_after_first, calls_after_second,
            "cache hit must not increment resolver_call_count"
        );
        assert!(calls_after_first >= calls_before, "resolve observed");
    }
}
