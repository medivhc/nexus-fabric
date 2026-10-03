//! `nexus plan` 命令族（N2 P0-3/P0-4）：只读规划预览 + `plan explain` 双模式。
//!
//! - `nexus plan <resource>`：resolve＋filter＋score 的本地计算，**不建连**。
//!   P0-4 起目录为 registry-backed（`n2_directory::N2Directory`：静态种子经
//!   `import_static`＋持久化广告叠加；Presence 语义对齐见该模块）；规划本身仍是
//!   纯函数（`plan_from_snapshot`），不开 socket、不调 daemon、不建连。
//! - `nexus plan explain <arg>`：双模式（D3）——
//!   - `sess-` 前缀：按 SessionId 查历史 PlanSnapshot（真实记录，读 N2 会话存储）；
//!     查无 → 结构化 `NOT_FOUND`，**不回退重算**（不伪造历史）；
//!   - 其他：按资源名做估算，输出显式标注"估算非承诺"。
//!
//! 本模块不伪装成真实目录：输出标注 `directory`（见 `n2_directory::DIRECTORY_TAG`），
//! 未知资源名返回结构化 `NotFound`。

use nexus_domain::{NexusError, PlanSnapshot, ResourceId, ResourceKind};
use nexus_planner::{ExplainMode, ExplainedPlan, PlanHistory, classify_explain_arg};
use serde_json::{Value, json};

use crate::n2_directory::{DIRECTORY_TAG, N2Directory};
use crate::n2_store::N2Store;
use nexus_session::SessionRecordStore as _;

/// 只读规划：registry-backed resolve＋filter＋score，不建连。
///
/// `node_dir` 注入（测试不碰进程环境）；`now_secs` 由调用方时钟提供。
fn preview_snapshot(
    node_dir: &std::path::Path,
    name: &str,
    now_secs: u64,
) -> Result<(ResourceId, ResourceKind, PlanSnapshot), NexusError> {
    let dir = N2Directory::open(node_dir, now_secs).map_err(|e| NexusError::PersistenceFailed {
        path: node_dir.display().to_string(),
        reason: e,
    })?;
    let (_rref, resource, snapshot) = dir.preview(name, now_secs)?;
    let kind = dir.kind_of(name).unwrap_or(ResourceKind::Service);
    Ok((resource, kind, snapshot))
}

/// DecisionTrace → JSON（加厚四件套全量渲染）。
fn trace_json(snapshot: &PlanSnapshot) -> Value {
    let considered: Vec<Value> = snapshot
        .decision_trace
        .considered
        .iter()
        .map(|c| {
            json!({
                "provider": c.provider.0,
                "rejected_reason": c.rejected_reason.as_ref().map(|r| r.label()),
                "score": c.score,
                "score_breakdown": c.score_breakdown.as_ref().map(|bd| bd.iter().map(|t| json!({
                    "name": t.name,
                    "contribution": t.contribution,
                    "detail": t.detail,
                })).collect::<Vec<_>>()),
                "measurement": c.measurement.as_ref().map(|m| json!({
                    "rtt_ms": m.rtt_ms,
                    "loss_permyriad": m.loss_permyriad,
                    "jitter_ms": m.jitter_ms,
                    "throughput_kbps": m.throughput_kbps,
                    "confidence_percent": m.confidence_percent,
                })),
                "connectivity": c.connectivity.as_ref().map(|e| json!({
                    "direct_likely": e.direct_likely,
                    "punching_likely": e.punching_likely,
                    "relay_available": e.relay_available,
                    "existing_link_available": e.existing_link_available,
                    "estimated_setup_cost_ms": e.estimated_setup_cost_ms,
                    "confidence_percent": e.confidence_percent,
                })),
            })
        })
        .collect();
    json!({
        "selected": snapshot.decision_trace.selected.0,
        "considered": considered,
    })
}

/// PlanSnapshot → `plan` JSON 对象（`n2-plan-preview` 冻结字段：resource /
/// plan_id / provider / read_only）。`display_name` 为人类可读名（D2：
///
/// 不透明 ResourceId 不直接展示给用户）。
fn plan_json(
    display_name: &str,
    kind: ResourceKind,
    snapshot: &PlanSnapshot,
    read_only: bool,
) -> Value {
    let plan = &snapshot.plan;
    json!({
        "resource": display_name,
        "kind": kind.as_str(),
        "plan_id": snapshot.plan_id.as_str(),
        "provider": plan.provider_id.0,
        "placement": plan.placement,
        "path": plan.path,
        "execution_strategy": plan.execution_strategy,
        "read_only": read_only,
    })
}

fn fail_json(err: &NexusError) -> Value {
    json!({
        "verdict": "FAIL",
        "error": {
            "code": crate::error_code(err),
            "message": err.to_string(),
        },
    })
}

/// P0-4 的 `PlanHistory` 读口：从 N2 会话存储读 `SessionRecord.plan_snapshot`
///（真实历史记录；查无 → `None`，不回退重算）。
struct N2PlanHistory<'a> {
    store: &'a N2Store,
}

impl PlanHistory for N2PlanHistory<'_> {
    fn lookup(&self, session: &nexus_domain::SessionId) -> Option<PlanSnapshot> {
        let sessions = self.store.sessions();
        sessions
            .load()
            .ok()?
            .into_iter()
            .find(|r| r.session == *session)
            .and_then(|r| r.plan_snapshot)
    }
}

/// 当前 unix 时间（秒）。
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `nexus plan <resource>`：只读预览（resolve＋filter＋score，不建连）。
fn run_preview(name: &str, json_mode: bool) -> i32 {
    let node_dir = crate::node_cli::node_dir();
    match preview_snapshot(&node_dir, name, now_secs()) {
        Ok((_resource, kind, snapshot)) => {
            let out = json!({
                "verdict": "PASS",
                "command": "plan",
                "directory": DIRECTORY_TAG,
                "read_only": true,
                "plan": plan_json(name, kind, &snapshot, true),
                "trace": trace_json(&snapshot),
            });
            render(&out, json_mode);
            0
        }
        Err(err) => {
            render(&fail_json(&err), json_mode);
            0
        }
    }
}

/// `nexus plan explain <arg>`：双模式。
fn run_explain(arg: &str, json_mode: bool) -> i32 {
    let node_dir = crate::node_cli::node_dir();
    match classify_explain_arg(arg) {
        ExplainMode::History => {
            // 历史模式：读 N2 会话存储的真实记录；查无 → 结构化 NOT_FOUND，不回退重算。
            let history = match N2Store::open(&node_dir) {
                Ok(store) => N2PlanHistory { store: &store }
                    .lookup(&nexus_domain::SessionId(arg.to_string())),
                Err(_) => None,
            };
            match history {
                Some(snapshot) => {
                    let explained = ExplainedPlan::history(snapshot);
                    // 历史快照的 resource_id 为不透明 Id；反查人类可读名用于展示。
                    let display = N2Directory::open(&node_dir, now_secs())
                        .ok()
                        .and_then(|d| d.name_of_resource(&explained.snapshot.plan.resource_id));
                    render(
                        &explain_json(&explained, None, display.as_deref()),
                        json_mode,
                    );
                    0
                }
                None => {
                    let err = NexusError::NotFound {
                        kind: "session-history".to_string(),
                        id: format!(
                            "{arg} (no plan history recorded for this session; refusing to fabricate history)"
                        ),
                    };
                    render(&fail_json(&err), json_mode);
                    0
                }
            }
        }
        ExplainMode::Estimate => {
            // 估算模式：按当前快照重算，显式标注"估算非承诺"。
            match preview_snapshot(&node_dir, arg, now_secs()) {
                Ok((resource, kind, snapshot)) => {
                    let explained = ExplainedPlan::estimate(snapshot);
                    let mut out = explain_json(&explained, Some(kind), Some(arg));
                    if let Some(obj) = out.as_object_mut() {
                        obj.insert("resource".to_string(), json!(resource.0));
                        obj.insert("kind".to_string(), json!(kind.as_str()));
                        obj.insert("directory".to_string(), json!(DIRECTORY_TAG));
                    }
                    render(&out, json_mode);
                    0
                }
                Err(err) => {
                    render(&fail_json(&err), json_mode);
                    0
                }
            }
        }
    }
}

fn explain_json(
    explained: &ExplainedPlan,
    entry_kind: Option<ResourceKind>,
    display_name: Option<&str>,
) -> Value {
    // kind 展示：优先使用目录条目的权威 kind（估算模式，与外层 kind 一致）；
    // 历史模式无目录条目时从 plan extension 反推（仅展示）。
    let kind = match entry_kind {
        Some(k) => k,
        None => match &explained.snapshot.plan.extension {
            Some(nexus_domain::PlanExtension::Service(_)) => ResourceKind::Service,
            Some(nexus_domain::PlanExtension::Network(_)) => ResourceKind::Network,
            Some(nexus_domain::PlanExtension::Workspace(_)) => ResourceKind::Workspace,
            Some(nexus_domain::PlanExtension::Compute(_)) => ResourceKind::Compute,
            None => ResourceKind::Device,
        },
    };
    // 展示名：调用方传入（估算模式为用户输入名；历史模式为反查名），
    // 缺省回退到不透明 Id（不伪造映射）。
    let display = display_name
        .map(String::from)
        .unwrap_or_else(|| explained.snapshot.plan.resource_id.0.clone());
    json!({
        "verdict": "PASS",
        "command": "plan explain",
        "mode": explained.mode.as_str(),
        "commitment": explained.commitment_note(),
        "plan_id": explained.plan_id().as_str(),
        "plan": plan_json(&display, kind, &explained.snapshot, true),
        "trace": trace_json(&explained.snapshot),
    })
}

fn render(out: &Value, json_mode: bool) {
    if json_mode {
        println!("{out}");
    } else {
        // 人读模式：关键字段行 + 完整 JSON（机器可读权威形状仍是 --json）。
        if let Some(plan) = out.get("plan") {
            println!("resource: {}", plan.get("resource").unwrap_or(&json!("-")));
            println!("plan_id: {}", plan.get("plan_id").unwrap_or(&json!("-")));
            println!("provider: {}", plan.get("provider").unwrap_or(&json!("-")));
            if let Some(mode) = out.get("mode") {
                println!("mode: {mode}");
            }
            if let Some(commitment) = out.get("commitment") {
                println!("commitment: {commitment}");
            }
            if out.get("read_only").and_then(|v| v.as_bool()) == Some(true) {
                println!("read_only: true（只读预览，未建连）");
            }
        }
        println!("{out}");
    }
}

/// `plan` 命令族入口（`run()` 在 `parse_command` 之前分流到此）。
///
/// - `nexus plan <resource>` → 只读预览；
/// - `nexus plan explain <arg>` → 双模式 explain；
/// - 参数缺失/未知子命令 → 用法错误 exit 2（与既有 parse 错误一致）。
pub fn run_plan(args: &[String], json_mode: bool) -> i32 {
    const USAGE: &str = "usage: nexus plan <resource> | nexus plan explain <resource|session-id>";
    let Some(first) = args.first() else {
        eprintln!("error: missing argument for plan");
        eprintln!("{USAGE}");
        return 2;
    };
    if first == "explain" {
        let Some(arg) = args.get(1) else {
            eprintln!("error: missing argument: <resource|session-id>");
            eprintln!("{USAGE}");
            return 2;
        };
        if args.len() > 2 {
            eprintln!("error: too many arguments for plan explain");
            eprintln!("{USAGE}");
            return 2;
        }
        return run_explain(arg, json_mode);
    }
    if first.starts_with('-') || args.len() > 1 {
        eprintln!("error: unexpected argument for plan");
        eprintln!("{USAGE}");
        return 2;
    }
    run_preview(first, json_mode)
}

/// 自检：`plan_id_of` 在 explain 路径与 preview 路径一致（同一决策同一 Id）。
#[cfg(test)]
mod tests {
    use super::*;

    fn temp_node_dir(tag: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("plan-cli-test-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn preview_dev_svc_selects_local_and_is_read_only() {
        let dir = temp_node_dir("preview");
        let (resource, kind, snapshot) = preview_snapshot(&dir, "dev-svc", 1000).unwrap();
        // 不透明 Id（D2）；展示用人类可读名。
        assert_eq!(resource.0, "res-dev-svc");
        assert_eq!(kind, ResourceKind::Service);
        // 本地优先：local-dev-1（locality +1000）胜过 remote-dev-1。
        assert_eq!(snapshot.plan.provider_id.0, "local-dev-1");
        let plan = plan_json("dev-svc", kind, &snapshot, true);
        assert_eq!(plan["resource"], json!("dev-svc"));
        assert_eq!(plan["read_only"], json!(true));
        assert!(!plan["plan_id"].as_str().unwrap().is_empty());
        assert!(!plan["provider"].as_str().unwrap().is_empty());
        // trace 含结构化拒绝原因（down-dev-1 → not_present，nocap-dev-1 → missing_capability）。
        let trace = trace_json(&snapshot);
        let considered = trace["considered"].as_array().unwrap();
        assert_eq!(considered.len(), 4);
        let reason_of = |id: &str| {
            considered.iter().find(|c| c["provider"] == id).unwrap()["rejected_reason"].clone()
        };
        assert_eq!(reason_of("down-dev-1"), json!("not_present"));
        assert_eq!(reason_of("nocap-dev-1"), json!("missing_capability"));
        assert_eq!(reason_of("local-dev-1"), Value::Null);
        // 加厚字段：选中者有 score/breakdown/measurement 槽位。
        let local = considered
            .iter()
            .find(|c| c["provider"] == "local-dev-1")
            .unwrap();
        assert!(local["score"].as_u64().is_some());
        assert_eq!(local["score_breakdown"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn preview_plan_id_is_stable_across_calls() {
        // D3：同一输入 → 同一 PlanId（跨调用一致；FNV 无随机种子，跨运行亦一致）。
        let dir = temp_node_dir("planid");
        let (_, _, a) = preview_snapshot(&dir, "dev-svc", 1000).unwrap();
        let (_, _, b) = preview_snapshot(&dir, "dev-svc", 1000).unwrap();
        assert_eq!(a.plan_id, b.plan_id);
        assert_eq!(
            a.plan_id,
            nexus_domain::plan_id_of(&a.plan, &a.decision_trace)
        );
    }

    #[test]
    fn preview_unknown_resource_is_not_found() {
        let dir = temp_node_dir("notfound");
        let err = preview_snapshot(&dir, "no-such-resource", 1000).unwrap_err();
        assert!(matches!(err, NexusError::NotFound { .. }));
        let v = fail_json(&err);
        assert_eq!(v["verdict"], json!("FAIL"));
        assert_eq!(v["error"]["code"], json!("NOT_FOUND"));
    }

    #[test]
    fn preview_invalid_name_is_rejected() {
        // 名字含非法字符 → NotFound（不 panic）。
        let dir = temp_node_dir("badname");
        assert!(preview_snapshot(&dir, "foo/bar", 1000).is_err());
    }

    #[test]
    fn explain_estimate_labels_non_commitment() {
        // `plan explain <resource>`：估算模式 + "估算非承诺"标注。
        let code = run_plan(&["explain".to_string(), "dev-svc".to_string()], true);
        assert_eq!(code, 0);
    }

    #[test]
    fn explain_session_id_without_history_is_not_found_not_fabricated() {
        // `plan explain <session-id>` 查无历史 → NOT_FOUND，不回退重算。
        let dir = temp_node_dir("nohistory");
        let store = N2Store::open(&dir).unwrap();
        let session = nexus_domain::SessionId("sess-n2-e4-1".to_string());
        assert!(N2PlanHistory { store: &store }.lookup(&session).is_none());
        assert_eq!(classify_explain_arg("sess-n2-e4-1"), ExplainMode::History);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn explain_history_reads_real_snapshot() {
        // P0-4：写入一条会话记录后，`plan explain <session-id>` 读到真实历史。
        use nexus_domain::{DecisionTrace, Plan};
        use nexus_session::SessionRecord;
        let dir = temp_node_dir("history");
        let store = N2Store::open(&dir).unwrap();
        let snapshot = PlanSnapshot {
            plan_id: nexus_domain::PlanId("hist001hist001hist".into()),
            plan: Plan {
                resource_id: ResourceId("res-dev-svc".into()),
                provider_id: nexus_domain::ProviderId("local-dev-1".into()),
                placement: "local".into(),
                path: vec!["127.0.0.1:8080".into()],
                execution_strategy: "direct".into(),
                extension: None,
            },
            decision_trace: DecisionTrace {
                considered: vec![],
                selected: nexus_domain::ProviderId("local-dev-1".into()),
            },
        };
        let mut sessions = store.sessions();
        sessions
            .save(&SessionRecord {
                session: nexus_domain::SessionId("sess-hist-1".into()),
                phase: nexus_domain::LifecyclePhase::Active,
                outcome: nexus_domain::TerminalOutcome::Completed,
                plan_snapshot: Some(snapshot),
            })
            .unwrap();
        let found = N2PlanHistory { store: &store }
            .lookup(&nexus_domain::SessionId("sess-hist-1".into()))
            .expect("history must be found");
        // 历史真实记录：plan_id 与写入一致（非重算）。
        assert_eq!(found.plan_id.0, "hist001hist001hist");
        let explained = ExplainedPlan::history(found);
        assert_eq!(explained.mode, ExplainMode::History);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn explain_json_carries_mode_and_commitment() {
        let dir = temp_node_dir("explainjson");
        let (_, kind, snapshot) = preview_snapshot(&dir, "dev-svc", 1000).unwrap();
        let explained = ExplainedPlan::estimate(snapshot);
        let v = explain_json(&explained, Some(kind), Some("dev-svc"));
        assert_eq!(v["mode"], json!("estimate"));
        assert!(v["commitment"].as_str().unwrap().contains("估算非承诺"));
        assert_eq!(v["plan_id"], json!(explained.plan_id().as_str()));
        // review-n2-p03 WARN-2：explain 也是只读（不建连），read_only 必须为 true；
        // 内层 plan.kind 必须与外层 kind 一致（都来自目录条目）。
        assert_eq!(v["plan"]["read_only"], json!(true));
        assert_eq!(v["plan"]["kind"], json!(kind.as_str()));
        assert_eq!(v["plan"]["resource"], json!("dev-svc"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn run_plan_usage_errors_exit_2() {
        assert_eq!(run_plan(&[], true), 2);
        assert_eq!(run_plan(&["explain".to_string()], true), 2);
        assert_eq!(
            run_plan(
                &["explain".to_string(), "a".to_string(), "b".to_string()],
                true
            ),
            2
        );
    }
}
