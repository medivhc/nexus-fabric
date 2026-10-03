//! N2 持久层（P0-4）：`FileKvStore`-backed 的 Session / Grant / Registry / 审计存储。
//!
//! 组合根装配点（apps/nexus lib，被 CLI 与 nexusd 共用）：
//! - `N2Store`：`<node_dir>/n2/` 下的 `FileKvStore`（P0-1 `kv.rs` 复用；
//!   tmp＋fsync＋rename 原子写，`put` 即 crash-safe）；
//! - `KvSessionRecordStore`：`nexus_session::SessionRecordStore` 的文件实现，
//!   键 `n2/session/<session-id>`，JSON 含完整 `PlanSnapshot`（D3）；
//! - grant 表持久化（键 `n2/grant/<ws>/<name>/<principal>`）＋
//!   `KvAuditSink`（`nexus_auth::AuditSink` 的文件实现，经
//!   `FileKvStore::journal_append` 落盘——P0-1 Deletion Test 预告的实现）；
//! - 目录（广告）持久化（键 `n2/ad/<provider>/<resource>`）＋名字表
//!   （键 `n2/names`）；
//! - 目录审计事件（`DirectoryAuditEvent`，P0-2 评审遗留：目录变更补结构化审计）；
//! - 控制帧 outbox（`n2/outbox/<seq>`）：`resource revoke` 触发的 AUTH_REVOKE
//!   帧先落盘排队（P0-5 真跨机时实际发送），本地 withdraw 立即执行。
//!
//! Crash Consistency（§15）：`put` 原子；每次 `save` 额外
//! `journal_append` 一条带 tag 的 mutation（审计轨迹＋重放源）；
//! boot 时 `load()`（KV 真相）＋`replay_journal()`（审计轨迹）＋
//! `reconcile_session_records`（幂等），再接受新工作。

use std::path::{Path, PathBuf};
use std::sync::Arc;

use nexus_auth::{AuditRecord, AuditSink};
use nexus_domain::{
    AuthorizationDecision, ConnectivityEvaluation, ConsideredCandidate, DecisionTrace,
    LifecyclePhase, MeasurementSnapshot, NexusError, Plan, PlanExtension, PlanId, PlanSnapshot,
    ProviderId, ResourceId, ResourceKind, ResourceName, ResourceOperation, ResourceRef,
    ScoreComponent, SessionId, TerminalOutcome, WorkspaceId,
};
use nexus_registry::{Discoverability, ProviderAdvertisement, UnavailabilityReason, UsageGrant};
use nexus_session::{SessionRecord, SessionRecordStore};
use nexus_storage::FileKvStore;
use serde_json::{Map, Value, json};

/// N2 存储目录名（node_dir 下）。
pub const N2_DIR_NAME: &str = "n2";

/// N2 存储目录：`<node_dir>/n2/`。
#[must_use]
pub fn n2_dir(node_dir: &Path) -> PathBuf {
    node_dir.join(N2_DIR_NAME)
}

/// 当前 unix 时间（秒）。
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// N2 持久层句柄（组合根持有；`FileKvStore` 自带原子写；`Arc` 共享给子存储）。
pub struct N2Store {
    kv: Arc<FileKvStore>,
}

impl N2Store {
    /// 打开（不存在则创建）`<node_dir>/n2/`。
    pub fn open(node_dir: &Path) -> Result<Self, String> {
        let dir = n2_dir(node_dir);
        let kv = FileKvStore::open(&dir).map_err(|e| format!("open n2 store: {e}"))?;
        Ok(Self { kv: Arc::new(kv) })
    }

    /// 底层 KV（供各子存储构造）。
    #[must_use]
    pub fn kv(&self) -> &FileKvStore {
        &self.kv
    }

    /// 会话记录存储（`SessionRecordStore` 实现；owned，可装入 `SessionManager`）。
    #[must_use]
    pub fn sessions(&self) -> KvSessionRecordStore {
        KvSessionRecordStore {
            kv: Arc::clone(&self.kv),
        }
    }

    /// 审计落点（`nexus_auth::AuditSink` 实现）。
    #[must_use]
    pub fn audit_sink(&self) -> KvAuditSink {
        KvAuditSink {
            kv: Arc::clone(&self.kv),
        }
    }

    /// journal 重放（§15：审计轨迹；返回原始 payload）。
    pub fn replay_journal(&self) -> Result<Vec<Vec<u8>>, String> {
        self.kv
            .journal_replay()
            .map_err(|e| format!("replay n2 journal: {e}"))
    }
}

// ============================================================================
// 会话记录 JSON 编解码（含 PlanSnapshot；durable 格式 v1）
// ============================================================================

fn phase_to_str(p: &LifecyclePhase) -> &'static str {
    match p {
        LifecyclePhase::Allocating => "Allocating",
        LifecyclePhase::Active => "Active",
        LifecyclePhase::Draining => "Draining",
        LifecyclePhase::Disposed => "Disposed",
    }
}

fn parse_phase(s: &str) -> Result<LifecyclePhase, String> {
    match s {
        "Allocating" => Ok(LifecyclePhase::Allocating),
        "Active" => Ok(LifecyclePhase::Active),
        "Draining" => Ok(LifecyclePhase::Draining),
        "Disposed" => Ok(LifecyclePhase::Disposed),
        other => Err(format!("unknown phase: {other}")),
    }
}

/// outcome 判别＋原因（保真度契约同 nexusd::recovery：`Failed` 只保留原因字符串）。
fn outcome_to_json(o: &TerminalOutcome) -> (String, Option<String>) {
    match o {
        TerminalOutcome::Unfinished => ("Unfinished".into(), None),
        TerminalOutcome::Completed => ("Completed".into(), None),
        TerminalOutcome::Failed(e) => ("Failed".into(), Some(format!("{e:?}"))),
        TerminalOutcome::Cancelled => ("Cancelled".into(), None),
    }
}

fn parse_outcome(s: &str, reason: Option<&str>) -> Result<TerminalOutcome, String> {
    match s {
        "Unfinished" => Ok(TerminalOutcome::Unfinished),
        "Completed" => Ok(TerminalOutcome::Completed),
        "Failed" => Ok(TerminalOutcome::Failed(NexusError::Internal {
            message: reason.unwrap_or("unknown").to_string(),
        })),
        "Cancelled" => Ok(TerminalOutcome::Cancelled),
        other => Err(format!("unknown outcome: {other}")),
    }
}

fn encode_extension(ext: &PlanExtension) -> Value {
    match ext {
        PlanExtension::Network(e) => json!({
            "kind": "network",
            "version": e.version,
            "exit_dns_binding": e.exit_dns_binding,
            "preferred_transport": e.preferred_transport,
        }),
        PlanExtension::Workspace(e) => json!({
            "kind": "workspace",
            "version": e.version,
            "pinned_commit": e.pinned_commit,
            "working_set": e.working_set,
        }),
        PlanExtension::Compute(e) => json!({
            "kind": "compute",
            "version": e.version,
            "pinned_snapshot": e.pinned_snapshot,
            "queue_delay_ms": e.queue_delay_ms,
            "execution_estimate_ms": e.execution_estimate_ms,
            "cache_hints": e.cache_hints,
        }),
        PlanExtension::Service(e) => json!({
            "kind": "service",
            "version": e.version,
            "listen": e.listen,
            "loopback_authorization_required": e.loopback_authorization_required,
        }),
    }
}

fn parse_extension(v: &Value) -> Result<PlanExtension, String> {
    use nexus_domain::{
        ComputePlanExtension, NetworkPlanExtension, ServicePlanExtension, WorkspacePlanExtension,
    };
    let kind = v
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| "plan extension missing 'kind'".to_string())?;
    let version = v
        .get("version")
        .and_then(Value::as_u64)
        .ok_or_else(|| "plan extension missing 'version'".to_string())? as u32;
    let opt_str = |k: &str| v.get(k).and_then(Value::as_str).map(String::from);
    let opt_u64 = |k: &str| v.get(k).and_then(Value::as_u64);
    let str_list = |k: &str| {
        v.get(k)
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default()
    };
    match kind {
        "network" => Ok(PlanExtension::Network(NetworkPlanExtension {
            version,
            exit_dns_binding: opt_str("exit_dns_binding"),
            preferred_transport: opt_str("preferred_transport"),
        })),
        "workspace" => Ok(PlanExtension::Workspace(WorkspacePlanExtension {
            version,
            pinned_commit: opt_str("pinned_commit"),
            working_set: str_list("working_set"),
        })),
        "compute" => Ok(PlanExtension::Compute(ComputePlanExtension {
            version,
            pinned_snapshot: opt_str("pinned_snapshot"),
            queue_delay_ms: opt_u64("queue_delay_ms"),
            execution_estimate_ms: opt_u64("execution_estimate_ms"),
            cache_hints: str_list("cache_hints"),
        })),
        "service" => Ok(PlanExtension::Service(ServicePlanExtension {
            version,
            listen: opt_str("listen"),
            loopback_authorization_required: v
                .get("loopback_authorization_required")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        })),
        other => Err(format!("unknown plan extension kind: {other}")),
    }
}

fn encode_connectivity(c: &ConnectivityEvaluation) -> Value {
    json!({
        "version": c.version,
        "direct_likely": c.direct_likely,
        "punching_likely": c.punching_likely,
        "relay_available": c.relay_available,
        "existing_link_available": c.existing_link_available,
        "estimated_setup_cost_ms": c.estimated_setup_cost_ms,
        "confidence_percent": c.confidence_percent,
    })
}

fn parse_connectivity(v: &Value) -> Result<ConnectivityEvaluation, String> {
    let req_bool = |k: &str| {
        v.get(k)
            .and_then(Value::as_bool)
            .ok_or_else(|| format!("connectivity missing '{k}'"))
    };
    Ok(ConnectivityEvaluation {
        version: v
            .get("version")
            .and_then(Value::as_u64)
            .ok_or_else(|| "connectivity missing 'version'".to_string())? as u32,
        direct_likely: req_bool("direct_likely")?,
        punching_likely: req_bool("punching_likely")?,
        relay_available: req_bool("relay_available")?,
        existing_link_available: req_bool("existing_link_available")?,
        estimated_setup_cost_ms: v
            .get("estimated_setup_cost_ms")
            .and_then(Value::as_u64)
            .map(|n| n as u32),
        confidence_percent: v
            .get("confidence_percent")
            .and_then(Value::as_u64)
            .ok_or_else(|| "connectivity missing 'confidence_percent'".to_string())?
            as u8,
    })
}

fn encode_measurement(m: &MeasurementSnapshot) -> Value {
    json!({
        "rtt_ms": m.rtt_ms,
        "loss_permyriad": m.loss_permyriad,
        "jitter_ms": m.jitter_ms,
        "throughput_kbps": m.throughput_kbps,
        "confidence_percent": m.confidence_percent,
    })
}

fn parse_measurement(v: &Value) -> Result<MeasurementSnapshot, String> {
    let opt_u32 = |k: &str| v.get(k).and_then(Value::as_u64).map(|n| n as u32);
    Ok(MeasurementSnapshot {
        rtt_ms: opt_u32("rtt_ms"),
        loss_permyriad: opt_u32("loss_permyriad"),
        jitter_ms: opt_u32("jitter_ms"),
        throughput_kbps: v.get("throughput_kbps").and_then(Value::as_u64),
        confidence_percent: v
            .get("confidence_percent")
            .and_then(Value::as_u64)
            .ok_or_else(|| "measurement missing 'confidence_percent'".to_string())?
            as u8,
    })
}

fn encode_reject_reason(r: &nexus_domain::RejectReason) -> Value {
    use nexus_domain::RejectReason;
    match r {
        RejectReason::NotPresent => json!({"label": "not_present"}),
        RejectReason::MissingCapability { required } => {
            json!({"label": "missing_capability", "required": required})
        }
        RejectReason::ExcludedByConstraint { key, value } => {
            json!({"label": "excluded_by_constraint", "key": key, "value": value})
        }
        RejectReason::NoFeasibleConnectivityPath => {
            json!({"label": "no_feasible_connectivity_path"})
        }
    }
}

fn parse_reject_reason(v: &Value) -> Result<nexus_domain::RejectReason, String> {
    use nexus_domain::RejectReason;
    let label = v
        .get("label")
        .and_then(Value::as_str)
        .ok_or_else(|| "reject reason missing 'label'".to_string())?;
    let req_str = |k: &str| {
        v.get(k)
            .and_then(Value::as_str)
            .map(String::from)
            .ok_or_else(|| format!("reject reason '{label}' missing '{k}'"))
    };
    match label {
        "not_present" => Ok(RejectReason::NotPresent),
        "missing_capability" => Ok(RejectReason::MissingCapability {
            required: req_str("required")?,
        }),
        "excluded_by_constraint" => Ok(RejectReason::ExcludedByConstraint {
            key: req_str("key")?,
            value: req_str("value")?,
        }),
        "no_feasible_connectivity_path" => Ok(RejectReason::NoFeasibleConnectivityPath),
        other => Err(format!("unknown reject reason label: {other}")),
    }
}

fn encode_considered(c: &ConsideredCandidate) -> Value {
    json!({
        "provider": c.provider.0,
        "rejected_reason": c.rejected_reason.as_ref().map(encode_reject_reason),
        "connectivity": c.connectivity.as_ref().map(encode_connectivity),
        "measurement": c.measurement.as_ref().map(encode_measurement),
        "score": c.score,
        "score_breakdown": c.score_breakdown.as_ref().map(|bd| bd.iter().map(|t| json!({
            "name": t.name,
            "contribution": t.contribution,
            "detail": t.detail,
        })).collect::<Vec<_>>()),
    })
}

fn parse_considered(v: &Value) -> Result<ConsideredCandidate, String> {
    let provider = v
        .get("provider")
        .and_then(Value::as_str)
        .ok_or_else(|| "considered missing 'provider'".to_string())?;
    let opt_obj = |k: &str| v.get(k).filter(|x| !x.is_null());
    Ok(ConsideredCandidate {
        provider: ProviderId(provider.to_string()),
        rejected_reason: opt_obj("rejected_reason")
            .map(parse_reject_reason)
            .transpose()?,
        connectivity: opt_obj("connectivity")
            .map(parse_connectivity)
            .transpose()?,
        measurement: opt_obj("measurement").map(parse_measurement).transpose()?,
        score: opt_obj("score").and_then(Value::as_u64).map(|n| n as u32),
        score_breakdown: opt_obj("score_breakdown")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .map(|t| {
                        // ScoreComponent.name 为固定词表（domain 文档）；未知名大声失败，
                        // 与"扩展需同步更新 explain 渲染"的约定一致。
                        let name_str = t
                            .get("name")
                            .and_then(Value::as_str)
                            .ok_or_else(|| "score component missing 'name'".to_string())?;
                        let name: &'static str = match name_str {
                            "rtt" => "rtt",
                            "locality" => "locality",
                            other => return Err(format!("unknown score component: {other}")),
                        };
                        Ok(ScoreComponent {
                            name,
                            contribution: t.get("contribution").and_then(Value::as_u64).ok_or_else(
                                || "score component missing 'contribution'".to_string(),
                            )? as u32,
                            detail: t.get("detail").and_then(Value::as_str).map(String::from),
                        })
                    })
                    .collect::<Result<Vec<_>, String>>()
            })
            .transpose()?,
    })
}

fn encode_plan_snapshot(s: &PlanSnapshot) -> Value {
    let plan = &s.plan;
    json!({
        "plan_id": s.plan_id.as_str(),
        "plan": {
            "resource_id": plan.resource_id.0,
            "provider_id": plan.provider_id.0,
            "placement": plan.placement,
            "path": plan.path,
            "execution_strategy": plan.execution_strategy,
            "extension": plan.extension.as_ref().map(encode_extension),
        },
        "decision_trace": {
            "considered": s.decision_trace.considered.iter().map(encode_considered).collect::<Vec<_>>(),
            "selected": s.decision_trace.selected.0,
        },
    })
}

fn parse_plan_snapshot(v: &Value) -> Result<PlanSnapshot, String> {
    let plan_id = v
        .get("plan_id")
        .and_then(Value::as_str)
        .ok_or_else(|| "plan snapshot missing 'plan_id'".to_string())?;
    let plan_v = v
        .get("plan")
        .ok_or_else(|| "plan snapshot missing 'plan'".to_string())?;
    let req_str = |k: &str| {
        plan_v
            .get(k)
            .and_then(Value::as_str)
            .map(String::from)
            .ok_or_else(|| format!("plan missing '{k}'"))
    };
    let plan = Plan {
        resource_id: ResourceId(req_str("resource_id")?),
        provider_id: ProviderId(req_str("provider_id")?),
        placement: req_str("placement")?,
        path: plan_v
            .get("path")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(String::from)
                    .collect()
            })
            .ok_or_else(|| "plan missing 'path'".to_string())?,
        execution_strategy: req_str("execution_strategy")?,
        extension: plan_v
            .get("extension")
            .filter(|x| !x.is_null())
            .map(parse_extension)
            .transpose()?,
    };
    let trace_v = v
        .get("decision_trace")
        .ok_or_else(|| "plan snapshot missing 'decision_trace'".to_string())?;
    let considered = trace_v
        .get("considered")
        .and_then(Value::as_array)
        .ok_or_else(|| "decision trace missing 'considered'".to_string())?;
    let considered = considered
        .iter()
        .map(parse_considered)
        .collect::<Result<Vec<_>, _>>()?;
    let selected = trace_v
        .get("selected")
        .and_then(Value::as_str)
        .ok_or_else(|| "decision trace missing 'selected'".to_string())?;
    Ok(PlanSnapshot {
        plan_id: PlanId(plan_id.to_string()),
        plan,
        decision_trace: DecisionTrace {
            considered,
            selected: ProviderId(selected.to_string()),
        },
    })
}

/// SessionRecord → JSON（durable v1；`plan_snapshot` 全量内嵌，D3）。
fn encode_session_record(r: &SessionRecord) -> Value {
    let (outcome, reason) = outcome_to_json(&r.outcome);
    let mut obj = Map::new();
    obj.insert("version".into(), json!(1));
    obj.insert("session".into(), Value::String(r.session.0.clone()));
    obj.insert("phase".into(), Value::String(phase_to_str(&r.phase).into()));
    obj.insert("outcome".into(), Value::String(outcome));
    if let Some(reason) = reason {
        obj.insert("reason".into(), Value::String(reason));
    }
    obj.insert(
        "plan_snapshot".into(),
        r.plan_snapshot
            .as_ref()
            .map(encode_plan_snapshot)
            .unwrap_or(Value::Null),
    );
    Value::Object(obj)
}

fn decode_session_record(v: &Value) -> Result<SessionRecord, String> {
    let req_str = |k: &str| {
        v.get(k)
            .and_then(Value::as_str)
            .map(String::from)
            .ok_or_else(|| format!("session record missing '{k}'"))
    };
    Ok(SessionRecord {
        session: SessionId(req_str("session")?),
        phase: parse_phase(&req_str("phase")?)?,
        outcome: parse_outcome(
            &req_str("outcome")?,
            v.get("reason").and_then(Value::as_str),
        )?,
        plan_snapshot: v
            .get("plan_snapshot")
            .filter(|x| !x.is_null())
            .map(parse_plan_snapshot)
            .transpose()?,
    })
}

// ============================================================================
// KvSessionRecordStore
// ============================================================================

const SESSION_KEY_PREFIX: &str = "n2/session/";

fn session_key(id: &SessionId) -> String {
    format!("{SESSION_KEY_PREFIX}{}", id.0)
}

/// `SessionRecordStore` 的 `FileKvStore` 实现（组合根注入；owned，`'static`）。
pub struct KvSessionRecordStore {
    kv: Arc<FileKvStore>,
}

impl SessionRecordStore for KvSessionRecordStore {
    fn load(&self) -> Result<Vec<SessionRecord>, String> {
        let mut records = Vec::new();
        let keys = self
            .kv
            .list()
            .map_err(|e| format!("list session keys: {e}"))?;
        for key in keys {
            let Some(id_part) = key.strip_prefix(SESSION_KEY_PREFIX) else {
                continue;
            };
            let Some(bytes) = self
                .kv
                .get(&key)
                .map_err(|e| format!("read session {id_part}: {e}"))?
            else {
                continue;
            };
            let text = String::from_utf8(bytes)
                .map_err(|e| format!("session {id_part} not utf-8: {e}"))?;
            let v: Value =
                serde_json::from_str(&text).map_err(|e| format!("parse session {id_part}: {e}"))?;
            records.push(decode_session_record(&v)?);
        }
        // 确定性顺序（按 session id）。
        records.sort_by(|a, b| a.session.0.cmp(&b.session.0));
        Ok(records)
    }

    fn save(&mut self, record: &SessionRecord) -> Result<(), String> {
        let data = serde_json::to_string(&encode_session_record(record))
            .map_err(|e| format!("encode session record: {e}"))?;
        let key = session_key(&record.session);
        self.kv
            .put(&key, data.as_bytes())
            .map_err(|e| format!("put session {}: {e}", record.session.0))?;
        // write-ahead 审计轨迹（§15 重放源；KV put 为真相，journal 为轨迹）。
        let mut payload = b"N2SESS:".to_vec();
        payload.extend_from_slice(data.as_bytes());
        self.kv
            .journal_append(&payload)
            .map_err(|e| format!("journal session {}: {e}", record.session.0))?;
        Ok(())
    }
}

// ============================================================================
// 审计：KvAuditSink（auth AuditSink 的文件实现）＋目录审计事件
// ============================================================================

/// journal tag：授权判定审计记录。
const TAG_AUTH_AUDIT: &[u8] = b"N2AUDIT:";
/// journal tag：目录变更审计事件（P0-2 评审遗留）。
const TAG_DIR_AUDIT: &[u8] = b"N2DIR:";

fn encode_audit_record(r: &AuditRecord) -> Value {
    let (decision, deny) = match &r.decision {
        AuthorizationDecision::Allow => ("allow", Value::Null),
        AuthorizationDecision::Deny(reason) => ("deny", Value::String(reason.code().into())),
    };
    json!({
        "at_unix": r.at_unix,
        "workspace": r.workspace.0,
        "resource": r.resource.to_string(),
        "principal": r.principal.0,
        "operation": r.operation.as_str(),
        "decision": decision,
        "deny": deny,
    })
}

/// `nexus_auth::AuditSink` 的文件实现：每次判定 exactly-once 经
/// `FileKvStore::journal_append` 落盘（P0-1 Deletion Test 预告）。
pub struct KvAuditSink {
    kv: Arc<FileKvStore>,
}

impl AuditSink for KvAuditSink {
    fn record(&mut self, record: AuditRecord) {
        let data = serde_json::to_string(&encode_audit_record(&record))
            .unwrap_or_else(|_| "{\"encode_error\":true}".to_string());
        let mut payload = TAG_AUTH_AUDIT.to_vec();
        payload.extend_from_slice(data.as_bytes());
        // 审计不得静默丢失：落盘失败记 stderr（调用方已做判定，不回滚）。
        if let Err(e) = self.kv.journal_append(&payload) {
            eprintln!("[n2] WARN: audit journal append failed: {e}");
        }
    }
}

/// 目录变更审计事件（P0-2 评审遗留：publish/revoke/withdraw 补结构化审计）。
#[derive(Debug, Clone)]
pub struct DirectoryAuditEvent {
    /// 事件时间（unix 秒）。
    pub at_unix: u64,
    /// 操作者（本地节点 principal 字符串；空 = 未知）。
    pub actor: String,
    /// 动作：`publish` / `revoke` / `withdraw`。
    pub action: &'static str,
    /// 目标资源引用。
    pub resource: ResourceRef,
    /// 提供方（publish/revoke 时）。
    pub provider: Option<ProviderId>,
    /// 人读备注。
    pub detail: String,
}

/// 记录一条目录审计事件（journal 落盘；失败记 stderr，不静默丢）。
pub fn record_directory_audit(kv: &FileKvStore, event: &DirectoryAuditEvent) {
    let data = serde_json::to_string(&json!({
        "at_unix": event.at_unix,
        "actor": event.actor,
        "action": event.action,
        "resource": event.resource.to_string(),
        "provider": event.provider.as_ref().map(|p| p.0.as_str()),
        "detail": event.detail,
    }))
    .unwrap_or_else(|_| "{\"encode_error\":true}".to_string());
    let mut payload = TAG_DIR_AUDIT.to_vec();
    payload.extend_from_slice(data.as_bytes());
    if let Err(e) = kv.journal_append(&payload) {
        eprintln!("[n2] WARN: directory audit journal append failed: {e}");
    }
}

/// 从 journal 重放中提取审计条目（`(tag, json_text)`；供查询/取证）。
pub fn replay_audit_entries(kv: &FileKvStore) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    let records = kv
        .journal_replay()
        .map_err(|e| format!("replay journal: {e}"))?;
    for raw in records {
        let (tag, rest) = if let Some(rest) = raw.strip_prefix(TAG_AUTH_AUDIT) {
            ("auth", rest)
        } else if let Some(rest) = raw.strip_prefix(TAG_DIR_AUDIT) {
            ("directory", rest)
        } else if let Some(rest) = raw.strip_prefix(b"N2SESS:") {
            ("session", rest)
        } else {
            continue;
        };
        out.push((tag.to_string(), String::from_utf8_lossy(rest).into_owned()));
    }
    Ok(out)
}

// ============================================================================
// grant 表持久化
// ============================================================================

const GRANT_KEY_PREFIX: &str = "n2/grant/";

fn grant_key(resource: &ResourceRef, principal: &nexus_auth::Principal) -> String {
    format!(
        "{GRANT_KEY_PREFIX}{}/{}/{}",
        resource.workspace, resource.name, principal.0
    )
}

fn encode_grant(g: &nexus_auth::Grant) -> Value {
    json!({
        "workspace": g.resource.workspace.0,
        "name": g.resource.name.as_str(),
        "principal": g.principal.0,
        "operations": g.operations.iter().map(|o| o.as_str()).collect::<Vec<_>>(),
        "not_after": g.not_after,
        "revoked": g.revoked,
    })
}

fn decode_grant(v: &Value) -> Result<nexus_auth::Grant, String> {
    let req_str = |k: &str| {
        v.get(k)
            .and_then(Value::as_str)
            .map(String::from)
            .ok_or_else(|| format!("grant missing '{k}'"))
    };
    let parse_op = |s: &str| match s {
        "use" => Ok(ResourceOperation::Use),
        "manage" => Ok(ResourceOperation::Manage),
        other => Err(format!("unknown operation: {other}")),
    };
    let operations = v
        .get("operations")
        .and_then(Value::as_array)
        .ok_or_else(|| "grant missing 'operations'".to_string())?;
    let operations = operations
        .iter()
        .map(|o| {
            o.as_str()
                .ok_or_else(|| "grant operation not a string".to_string())
                .and_then(parse_op)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(nexus_auth::Grant {
        resource: ResourceRef::new(
            WorkspaceId::new(req_str("workspace")?),
            ResourceName::new(req_str("name")?).map_err(|e| format!("bad grant name: {e:?}"))?,
        ),
        principal: nexus_auth::Principal(req_str("principal")?),
        operations,
        not_after: v.get("not_after").and_then(Value::as_u64),
        revoked: v.get("revoked").and_then(Value::as_bool).unwrap_or(false),
    })
}

/// grant 表持久化 helpers（`N2Store` 上）。
impl N2Store {
    /// 保存一条 grant（upsert）。
    pub fn save_grant(&self, grant: &nexus_auth::Grant) -> Result<(), String> {
        let data = serde_json::to_string(&encode_grant(grant))
            .map_err(|e| format!("encode grant: {e}"))?;
        self.kv
            .put(
                &grant_key(&grant.resource, &grant.principal),
                data.as_bytes(),
            )
            .map_err(|e| format!("put grant: {e}"))?;
        Ok(())
    }

    /// 加载全部 grant。
    pub fn load_grants(&self) -> Result<Vec<nexus_auth::Grant>, String> {
        let mut out = Vec::new();
        let keys = self
            .kv
            .list()
            .map_err(|e| format!("list grant keys: {e}"))?;
        for key in keys {
            if !key.starts_with(GRANT_KEY_PREFIX) {
                continue;
            }
            let Some(bytes) = self
                .kv
                .get(&key)
                .map_err(|e| format!("read grant {key}: {e}"))?
            else {
                continue;
            };
            let text =
                String::from_utf8(bytes).map_err(|e| format!("grant {key} not utf-8: {e}"))?;
            let v: Value =
                serde_json::from_str(&text).map_err(|e| format!("parse grant {key}: {e}"))?;
            out.push(decode_grant(&v)?);
        }
        Ok(out)
    }

    /// 把持久化 grants 装入内存 `GrantTable`。
    pub fn load_grant_table(&self) -> Result<nexus_auth::GrantTable, String> {
        let mut table = nexus_auth::GrantTable::new();
        for g in self.load_grants()? {
            table.upsert(g);
        }
        Ok(table)
    }
}

// ============================================================================
// 目录（广告）持久化
// ============================================================================

const AD_KEY_PREFIX: &str = "n2/ad/";

fn ad_key(provider: &ProviderId, resource: &ResourceId) -> String {
    format!("{AD_KEY_PREFIX}{}/{}", provider.0, resource.0)
}

fn encode_discoverability(d: &Discoverability) -> Value {
    match d {
        Discoverability::Public => json!({"kind": "public"}),
        Discoverability::Restricted { principals } => {
            json!({"kind": "restricted", "principals": principals})
        }
    }
}

fn parse_discoverability(v: &Value) -> Result<Discoverability, String> {
    let kind = v
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| "discoverability missing 'kind'".to_string())?;
    match kind {
        "public" => Ok(Discoverability::Public),
        "restricted" => Ok(Discoverability::Restricted {
            principals: v
                .get("principals")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(String::from)
                        .collect()
                })
                .ok_or_else(|| "restricted discoverability missing 'principals'".to_string())?,
        }),
        other => Err(format!("unknown discoverability kind: {other}")),
    }
}

fn encode_unavailability(u: &UnavailabilityReason) -> Value {
    match u {
        UnavailabilityReason::ProviderOffline => json!({"reason": "ProviderOffline"}),
        UnavailabilityReason::HealthDegraded { detail } => {
            json!({"reason": "HealthDegraded", "detail": detail})
        }
        UnavailabilityReason::NotAcceptingWork { reason } => {
            json!({"reason": "NotAcceptingWork", "reason_detail": reason})
        }
    }
}

fn parse_unavailability(v: &Value) -> Result<UnavailabilityReason, String> {
    let reason = v
        .get("reason")
        .and_then(Value::as_str)
        .ok_or_else(|| "unavailability missing 'reason'".to_string())?;
    match reason {
        "ProviderOffline" => Ok(UnavailabilityReason::ProviderOffline),
        "HealthDegraded" => Ok(UnavailabilityReason::HealthDegraded {
            detail: v
                .get("detail")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        }),
        "NotAcceptingWork" => Ok(UnavailabilityReason::NotAcceptingWork {
            reason: v
                .get("reason_detail")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        }),
        other => Err(format!("unknown unavailability reason: {other}")),
    }
}

fn encode_ad(ad: &ProviderAdvertisement) -> Value {
    json!({
        "provider": ad.provider.0,
        "resource": ad.resource.0,
        "capabilities": ad.capabilities,
        "locators": ad.locators,
        "discoverable_by": encode_discoverability(&ad.discoverable_by),
        "use_grants": ad.use_grants.iter().map(|g| json!({
            "principal": g.principal,
            "operations": g.operations.iter().map(|o| o.as_str()).collect::<Vec<_>>(),
            "not_after_secs": g.not_after_secs,
        })).collect::<Vec<_>>(),
        "unavailable": ad.unavailable.as_ref().map(encode_unavailability),
        "issued_at_secs": ad.issued_at_secs,
        "ttl_secs": ad.ttl_secs,
    })
}

fn parse_ad(v: &Value) -> Result<ProviderAdvertisement, String> {
    let req_str = |k: &str| {
        v.get(k)
            .and_then(Value::as_str)
            .map(String::from)
            .ok_or_else(|| format!("ad missing '{k}'"))
    };
    let str_list = |k: &str| {
        v.get(k)
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(String::from)
                    .collect()
            })
            .ok_or_else(|| format!("ad missing '{k}'"))
    };
    let parse_op = |s: &str| match s {
        "use" => Ok(ResourceOperation::Use),
        "manage" => Ok(ResourceOperation::Manage),
        other => Err(format!("unknown operation: {other}")),
    };
    let use_grants = v
        .get("use_grants")
        .and_then(Value::as_array)
        .ok_or_else(|| "ad missing 'use_grants'".to_string())?;
    let use_grants = use_grants
        .iter()
        .map(|g| {
            let operations = g
                .get("operations")
                .and_then(Value::as_array)
                .ok_or_else(|| "use_grant missing 'operations'".to_string())?;
            Ok(UsageGrant {
                principal: g
                    .get("principal")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "use_grant missing 'principal'".to_string())?
                    .to_string(),
                operations: operations
                    .iter()
                    .map(|o| {
                        o.as_str()
                            .ok_or_else(|| "use_grant operation not a string".to_string())
                            .and_then(parse_op)
                    })
                    .collect::<Result<Vec<_>, String>>()?,
                not_after_secs: g.get("not_after_secs").and_then(Value::as_u64),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(ProviderAdvertisement {
        provider: ProviderId(req_str("provider")?),
        resource: ResourceId(req_str("resource")?),
        capabilities: str_list("capabilities")?,
        locators: str_list("locators")?,
        discoverable_by: parse_discoverability(
            v.get("discoverable_by")
                .ok_or_else(|| "ad missing 'discoverable_by'".to_string())?,
        )?,
        use_grants,
        unavailable: v
            .get("unavailable")
            .filter(|x| !x.is_null())
            .map(parse_unavailability)
            .transpose()?,
        issued_at_secs: v
            .get("issued_at_secs")
            .and_then(Value::as_u64)
            .ok_or_else(|| "ad missing 'issued_at_secs'".to_string())?,
        ttl_secs: v
            .get("ttl_secs")
            .and_then(Value::as_u64)
            .ok_or_else(|| "ad missing 'ttl_secs'".to_string())?,
    })
}

impl N2Store {
    /// 发布/覆盖一条广告（幂等）。
    pub fn save_ad(&self, ad: &ProviderAdvertisement) -> Result<(), String> {
        let data = serde_json::to_string(&encode_ad(ad)).map_err(|e| format!("encode ad: {e}"))?;
        self.kv
            .put(&ad_key(&ad.provider, &ad.resource), data.as_bytes())
            .map_err(|e| format!("put ad: {e}"))?;
        Ok(())
    }

    /// 删除一条广告（幂等；返回是否命中）。
    pub fn delete_ad(&self, provider: &ProviderId, resource: &ResourceId) -> Result<bool, String> {
        let key = ad_key(provider, resource);
        let existed = self
            .kv
            .get(&key)
            .map_err(|e| format!("read ad for delete: {e}"))?
            .is_some();
        self.kv
            .delete(&key)
            .map_err(|e| format!("delete ad: {e}"))?;
        Ok(existed)
    }

    /// 加载全部持久化广告。
    pub fn load_ads(&self) -> Result<Vec<ProviderAdvertisement>, String> {
        let mut out = Vec::new();
        let keys = self.kv.list().map_err(|e| format!("list ad keys: {e}"))?;
        for key in keys {
            if !key.starts_with(AD_KEY_PREFIX) {
                continue;
            }
            let Some(bytes) = self
                .kv
                .get(&key)
                .map_err(|e| format!("read ad {key}: {e}"))?
            else {
                continue;
            };
            let text = String::from_utf8(bytes).map_err(|e| format!("ad {key} not utf-8: {e}"))?;
            let v: Value =
                serde_json::from_str(&text).map_err(|e| format!("parse ad {key}: {e}"))?;
            out.push(parse_ad(&v)?);
        }
        out.sort_by(|a, b| (&a.provider.0, &a.resource.0).cmp(&(&b.provider.0, &b.resource.0)));
        Ok(out)
    }
}

// ============================================================================
// 名字表持久化
// ============================================================================

const NAMES_KEY: &str = "n2/names";

/// 名字表条目（`ResourceRef{workspace,name}` → 不透明 `ResourceId`＋kind）。
#[derive(Debug, Clone)]
pub struct NameEntry {
    pub workspace: WorkspaceId,
    pub name: ResourceName,
    pub resource_id: ResourceId,
    /// 目录 kind 属性（D2）；`None` = 未指定（读出时默认 Service）。
    pub kind: Option<ResourceKind>,
}

/// kind 字符串 ↔ `ResourceKind`（名字表持久化用）。
#[must_use]
pub fn kind_from_str(s: &str) -> Option<ResourceKind> {
    match s {
        "network" => Some(ResourceKind::Network),
        "service" => Some(ResourceKind::Service),
        "workspace" => Some(ResourceKind::Workspace),
        "compute" => Some(ResourceKind::Compute),
        "device" => Some(ResourceKind::Device),
        _ => None,
    }
}

impl N2Store {
    /// 保存名字表（全量覆盖；条目少，P0 可接受）。
    pub fn save_names(&self, entries: &[NameEntry]) -> Result<(), String> {
        let data = serde_json::to_string(&json!(
            entries
                .iter()
                .map(|e| json!({
                    "workspace": e.workspace.0,
                    "name": e.name.as_str(),
                    "resource_id": e.resource_id.0,
                    "kind": e.kind.map(|k| k.as_str()),
                }))
                .collect::<Vec<_>>()
        ))
        .map_err(|e| format!("encode names: {e}"))?;
        self.kv
            .put(NAMES_KEY, data.as_bytes())
            .map_err(|e| format!("put names: {e}"))?;
        Ok(())
    }

    /// 加载名字表（不存在 → 空）。
    pub fn load_names(&self) -> Result<Vec<NameEntry>, String> {
        let Some(bytes) = self
            .kv
            .get(NAMES_KEY)
            .map_err(|e| format!("read names: {e}"))?
        else {
            return Ok(Vec::new());
        };
        let text = String::from_utf8(bytes).map_err(|e| format!("names not utf-8: {e}"))?;
        let v: Value = serde_json::from_str(&text).map_err(|e| format!("parse names: {e}"))?;
        let arr = v
            .as_array()
            .ok_or_else(|| "names: top level must be an array".to_string())?;
        arr.iter()
            .map(|e| {
                let ws = e
                    .get("workspace")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "name entry missing 'workspace'".to_string())?;
                let name = e
                    .get("name")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "name entry missing 'name'".to_string())?;
                let rid = e
                    .get("resource_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "name entry missing 'resource_id'".to_string())?;
                Ok(NameEntry {
                    workspace: WorkspaceId::new(ws),
                    name: ResourceName::new(name).map_err(|e| format!("bad stored name: {e:?}"))?,
                    resource_id: ResourceId(rid.to_string()),
                    kind: e
                        .get("kind")
                        .and_then(Value::as_str)
                        .and_then(kind_from_str),
                })
            })
            .collect()
    }
}

// ============================================================================
// 控制帧 outbox（revoke 触发的 AUTH_REVOKE 先落盘排队）
// ============================================================================

const OUTBOX_PREFIX: &str = "n2/outbox/";

impl N2Store {
    /// 控制帧入队（`seq` 由调用方单调递增；P0-5 发送后删除）。
    pub fn outbox_push(&self, seq: u64, frame_bytes: &[u8]) -> Result<(), String> {
        let key = format!("{OUTBOX_PREFIX}{seq:020}");
        self.kv
            .put(&key, frame_bytes)
            .map_err(|e| format!("outbox push: {e}"))?;
        Ok(())
    }

    /// 列出 outbox（`(seq, bytes)`，按 seq 排序）。
    pub fn outbox_list(&self) -> Result<Vec<(u64, Vec<u8>)>, String> {
        let mut out = Vec::new();
        let keys = self.kv.list().map_err(|e| format!("list outbox: {e}"))?;
        for key in keys {
            let Some(seq_part) = key.strip_prefix(OUTBOX_PREFIX) else {
                continue;
            };
            let seq: u64 = seq_part
                .parse()
                .map_err(|_| format!("bad outbox seq: {seq_part}"))?;
            let bytes = self
                .kv
                .get(&key)
                .map_err(|e| format!("read outbox {seq}: {e}"))?
                .unwrap_or_default();
            out.push((seq, bytes));
        }
        out.sort_by_key(|(s, _)| *s);
        Ok(out)
    }

    /// outbox 下一条 seq（当前最大＋1）。
    pub fn outbox_next_seq(&self) -> Result<u64, String> {
        Ok(self.outbox_list()?.last().map(|(s, _)| s + 1).unwrap_or(0))
    }
}

/// 本地 actor 标识（审计用；节点未初始化时为空串，不伪造）。
pub fn local_actor(node_dir: &Path) -> String {
    let kv = match FileKvStore::open(node_dir) {
        Ok(kv) => kv,
        Err(_) => return String::new(),
    };
    match kv.get("node/identity") {
        Ok(Some(bytes)) => {
            let text = String::from_utf8_lossy(&bytes);
            // 提取 "node_id":"..."（与 node_cli::parse_node_id 同规则，不重复解析）。
            let marker = "\"node_id\":\"";
            text.find(marker)
                .map(|i| {
                    let rest = &text[i + marker.len()..];
                    rest.find('"')
                        .map(|j| rest[..j].to_string())
                        .unwrap_or_default()
                })
                .unwrap_or_default()
        }
        _ => String::new(),
    }
}

/// now_unix（pub，供 CLI 模块复用）。
pub fn now_unix_pub() -> u64 {
    now_unix()
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_auth::Grant;
    use nexus_domain::{DecisionTrace, DenyReason, Plan};
    use nexus_session::SessionRecordStore;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("n2-store-test-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn sample_snapshot() -> PlanSnapshot {
        PlanSnapshot {
            plan_id: PlanId("cafef00dcafef00d".into()),
            plan: Plan {
                resource_id: ResourceId("res-dev-svc".into()),
                provider_id: ProviderId("local-dev-1".into()),
                placement: "local".into(),
                path: vec!["127.0.0.1:8080".into()],
                execution_strategy: "direct".into(),
                extension: None,
            },
            decision_trace: DecisionTrace {
                considered: vec![ConsideredCandidate {
                    provider: ProviderId("local-dev-1".into()),
                    rejected_reason: None,
                    connectivity: Some(ConnectivityEvaluation {
                        version: 1,
                        direct_likely: true,
                        punching_likely: false,
                        relay_available: true,
                        existing_link_available: false,
                        estimated_setup_cost_ms: Some(20),
                        confidence_percent: 80,
                    }),
                    measurement: Some(MeasurementSnapshot {
                        rtt_ms: Some(5),
                        loss_permyriad: Some(0),
                        jitter_ms: None,
                        throughput_kbps: None,
                        confidence_percent: 90,
                    }),
                    score: Some(1500),
                    score_breakdown: None,
                }],
                selected: ProviderId("local-dev-1".into()),
            },
        }
    }

    #[test]
    fn session_record_roundtrip_with_snapshot() {
        let dir = temp_dir("sess");
        let store = N2Store::open(&dir).unwrap();
        let mut sessions = store.sessions();
        let record = SessionRecord {
            session: SessionId("sess-abc".into()),
            phase: LifecyclePhase::Active,
            outcome: TerminalOutcome::Unfinished,
            plan_snapshot: Some(sample_snapshot()),
        };
        sessions.save(&record).unwrap();
        let loaded = sessions.load().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0], record);
        // 快照非重算：plan_id 与决策轨迹原样。
        let snap = loaded[0].plan_snapshot.as_ref().unwrap();
        assert_eq!(snap.plan_id.0, "cafef00dcafef00d");
        assert_eq!(snap.decision_trace.selected.0, "local-dev-1");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn session_save_appends_journal() {
        let dir = temp_dir("sess-j");
        let store = N2Store::open(&dir).unwrap();
        let mut sessions = store.sessions();
        sessions
            .save(&SessionRecord {
                session: SessionId("sess-j1".into()),
                phase: LifecyclePhase::Active,
                outcome: TerminalOutcome::Unfinished,
                plan_snapshot: None,
            })
            .unwrap();
        let entries = replay_audit_entries(store.kv()).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, "session");
        assert!(entries[0].1.contains("sess-j1"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn grant_roundtrip() {
        let dir = temp_dir("grant");
        let store = N2Store::open(&dir).unwrap();
        let grant = Grant::new(
            ResourceRef::new(
                WorkspaceId::new("default"),
                ResourceName::new("dev-svc").unwrap(),
            ),
            nexus_auth::Principal("ed25519:abc".into()),
            vec![ResourceOperation::Use],
            Some(9999),
        );
        store.save_grant(&grant).unwrap();
        let grants = store.load_grants().unwrap();
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0], grant);
        // upsert 覆盖。
        let mut revoked = grant.clone();
        revoked.revoked = true;
        store.save_grant(&revoked).unwrap();
        let grants = store.load_grants().unwrap();
        assert_eq!(grants.len(), 1);
        assert!(grants[0].revoked);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn audit_sink_writes_journal_exactly_once() {
        use nexus_auth::{AuthRequest, GrantTable, VecAuditSink};
        let dir = temp_dir("audit");
        let store = N2Store::open(&dir).unwrap();
        let table = GrantTable::new();
        let mut sink = store.audit_sink();
        let req = AuthRequest {
            workspace: WorkspaceId::new("default"),
            resource: ResourceRef::new(
                WorkspaceId::new("default"),
                ResourceName::new("restricted-svc").unwrap(),
            ),
            principal: nexus_auth::Principal("ed25519:xyz".into()),
            operation: ResourceOperation::Use,
        };
        // 空表 → NoSuchGrant；判定本身写内存槽，文件槽单独验证。
        let mut mem = VecAuditSink::new();
        let d = table.authorize(&req, 1000, &mut mem);
        assert_eq!(d, AuthorizationDecision::Deny(DenyReason::NoSuchGrant));
        sink.record(mem.records[0].clone());
        let entries = replay_audit_entries(store.kv()).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, "auth");
        assert!(entries[0].1.contains("NoSuchGrant"));
        assert!(entries[0].1.contains("restricted-svc"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn directory_audit_event_roundtrip() {
        let dir = temp_dir("diraudit");
        let store = N2Store::open(&dir).unwrap();
        record_directory_audit(
            store.kv(),
            &DirectoryAuditEvent {
                at_unix: 1234,
                actor: "node-1".into(),
                action: "publish",
                resource: ResourceRef::new(
                    WorkspaceId::new("default"),
                    ResourceName::new("dev-svc").unwrap(),
                ),
                provider: Some(ProviderId("local-dev-1".into())),
                detail: "test publish".into(),
            },
        );
        let entries = replay_audit_entries(store.kv()).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, "directory");
        assert!(entries[0].1.contains("\"action\":\"publish\""));
        assert!(entries[0].1.contains("dev-svc"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ad_roundtrip_with_unavailability() {
        let dir = temp_dir("ad");
        let store = N2Store::open(&dir).unwrap();
        let ad = ProviderAdvertisement {
            provider: ProviderId("p1".into()),
            resource: ResourceId("res-x".into()),
            capabilities: vec!["service".into()],
            locators: vec!["tcp://10.0.0.2:9000".into()],
            discoverable_by: Discoverability::Restricted {
                principals: vec!["ed25519:a".into()],
            },
            use_grants: vec![UsageGrant {
                principal: "ed25519:a".into(),
                operations: vec![ResourceOperation::Use],
                not_after_secs: None,
            }],
            unavailable: Some(UnavailabilityReason::HealthDegraded {
                detail: "cpu_saturated".into(),
            }),
            issued_at_secs: 100,
            ttl_secs: 3600,
        };
        store.save_ad(&ad).unwrap();
        let ads = store.load_ads().unwrap();
        assert_eq!(ads.len(), 1);
        assert_eq!(ads[0], ad);
        assert!(
            store
                .delete_ad(&ProviderId("p1".into()), &ResourceId("res-x".into()))
                .unwrap()
        );
        assert!(store.load_ads().unwrap().is_empty());
        // 幂等删除。
        assert!(
            !store
                .delete_ad(&ProviderId("p1".into()), &ResourceId("res-x".into()))
                .unwrap()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn names_roundtrip() {
        let dir = temp_dir("names");
        let store = N2Store::open(&dir).unwrap();
        assert!(store.load_names().unwrap().is_empty());
        store
            .save_names(&[NameEntry {
                workspace: WorkspaceId::new("default"),
                name: ResourceName::new("dev-svc").unwrap(),
                resource_id: ResourceId("res-dev-svc".into()),
                kind: Some(nexus_domain::ResourceKind::Service),
            }])
            .unwrap();
        let names = store.load_names().unwrap();
        assert_eq!(names.len(), 1);
        assert_eq!(names[0].resource_id.0, "res-dev-svc");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn outbox_push_list_seq() {
        let dir = temp_dir("outbox");
        let store = N2Store::open(&dir).unwrap();
        assert_eq!(store.outbox_next_seq().unwrap(), 0);
        store.outbox_push(0, b"frame-0").unwrap();
        store.outbox_push(1, b"frame-1").unwrap();
        assert_eq!(store.outbox_next_seq().unwrap(), 2);
        let items = store.outbox_list().unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0], (0, b"frame-0".to_vec()));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
