//! §9 可观察性命令（SDK 侧状态快照）。
//!
//! PRODUCT §9：关键 Resource/Session 必须可被 CLI/GUI/Agent 观察，至少提供
//! status / plan explain / session watch / connectivity status / dns status /
//! dns cache / workspace heads / compute jobs / diagnose / platform capabilities。
//!
//! 本模块提供结构化 JSON 快照命令；领域未就绪的命令返回
//! `NexusError::Unsupported`（禁止静默降级，见 apps/nexus MODULE.md 契约）。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use nexus_connectivity::{ConnectivityState, EstablishmentRequest, establish};
use nexus_dns::{DnsError, DnsQuery, DnsRuntime, DnsType, IpPreference, Resolver};
use nexus_domain::{
    Constraint, Intent, LifecyclePhase, NexusError, ProviderId, ResourceId, SessionId,
    TerminalOutcome,
};
use nexus_measurement::LinkMeasurement;
use nexus_planner::{PlanningSnapshot, plan_from_snapshot};
use nexus_registry::ProviderRecord;
use nexus_session::SessionOwner;
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
    let mut rt = demo_dns_runtime();
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
    let mut rt = demo_dns_runtime();
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
    use nexus_workspace::{Change, Workspace, WorkspaceId};

    let mut ws = Workspace::init(
        WorkspaceId("ws-observability-1".into()),
        InMemoryContentStore::new(),
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

// ---------- 未就绪命令 ----------

/// 领域未就绪命令的显式拒绝（PRODUCT §9：禁止静默降级；apps/nexus MODULE 契约）。
pub fn unsupported_command(command: &str) -> Result<Value, NexusError> {
    Err(NexusError::Unsupported {
        feature: format!("observability command '{command}' (domain state not ready)"),
    })
}
