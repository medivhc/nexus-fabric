//! `nexus session` 命令族（N2 P0-4）：`list` / `watch` / `close`。
//!
//! - `nexus session list`：列出 daemon 内 SessionManager 持有的资源会话
//!   （`n2-session-list`；读 N2 会话存储，无需 daemon 在线）；
//! - `nexus session watch <id>`：按 SessionId 查询状态＋历史 DecisionTrace
//!   （`n2-session-watch`；完成标志 #3：CLI 退出重进可查）；
//! - `nexus session close <id>`：主动关闭 → `Cancelled`（`n2-session-close`；
//!   Owner 唯一提交，断开≠Failed 语义下主动关闭的终态为 Cancelled 非 Failed）。
//!
//! 注意：既有 `session watch` 曾走 daemon LocalAPI（§9 可观察性）；P0-4 起
//! N2 语义的 `session` 命令族走进程内 N2 存储（与 `plan` 同模式），daemon 的
//! `/localapi/v0/session/watch` 保留其 §9 冻结行为（`observability_session_watch`
//! 场景不经过本模块）。
//!
//! D1（N2 P1-1）：**终态的唯一写入者**是 daemon 内唯一的 `SessionManager`
//! （`apps/nexusd` 的 `N2_SESSION_MANAGER` + 周期性 `sweep_detached`），它对外
//! 暴露 `/localapi/v0/n2/session/list` 与 `/attach`。本模块的 `list` / `watch`
//! 是**纯读口**——直接读同一份持久化记录，因此与 daemon 看到的会话状态一致；
//! `close` 是写操作，走进程内 manager，但持久记录层的终态 CAS
//! （`KvSessionRecordStore::save` 先到终态获胜）保证它不会覆盖 daemon 已提交的
//! 终态（冲突时报错而非静默改写）。

use nexus_domain::{SessionId, TerminalOutcome};
use nexus_session::{DEFAULT_ATTACH_WINDOW_SECS, SessionManager, SessionManagerError, SessionView};
use serde_json::{Value, json};

use crate::n2_directory::N2Directory;
use crate::n2_store::{N2Store, now_unix_pub};

/// SessionView → JSON（含双轨状态＋历史 trace 摘要）。
fn view_json(view: &SessionView, dir: &N2Directory) -> Value {
    let outcome_label = match &view.outcome {
        TerminalOutcome::Unfinished => "Unfinished",
        TerminalOutcome::Completed => "Completed",
        TerminalOutcome::Failed(_) => "Failed",
        TerminalOutcome::Cancelled => "Cancelled",
    };
    // 人类可读名（反查；查无回退不透明 Id，不伪造）。
    let resource_name = dir
        .name_of_resource(&view.resource)
        .unwrap_or_else(|| view.resource.0.clone());
    let mut obj = json!({
        "id": view.id.0,
        "resource": resource_name,
        "resource_id": view.resource.0,
        "provider": view.provider.0,
        "phase": format!("{:?}", view.phase).to_lowercase(),
        "outcome": outcome_label,
        "reattachable": view.reattachable,
    });
    if let Some(reason) = &view.cancel_reason {
        obj["cancel_reason"] = json!(reason.as_str());
    }
    if let TerminalOutcome::Failed(e) = &view.outcome {
        obj["failure"] = json!(format!("{e:?}"));
    }
    // 历史 DecisionTrace（完成标志 #3；内嵌快照，非重算）。
    // `plan_snapshot.decision_trace` 为场景契约字段路径（n2-session-watch）；
    // `trace` 保留作兼容。
    if let Some(snap) = &view.plan_snapshot {
        obj["plan_id"] = json!(snap.plan_id.as_str());
        let trace = json!({
            "selected": snap.decision_trace.selected.0,
            "considered": snap.decision_trace.considered.iter().map(|c| json!({
                "provider": c.provider.0,
                "rejected_reason": c.rejected_reason.as_ref().map(|r| r.label()),
                "score": c.score,
            })).collect::<Vec<_>>(),
        });
        obj["plan_snapshot"] = json!({
            "plan_id": snap.plan_id.as_str(),
            "decision_trace": trace,
        });
        obj["trace"] = trace;
    }
    obj
}

fn open_manager(node_dir: &std::path::Path) -> Result<(N2Store, SessionManager), Value> {
    let store = N2Store::open(node_dir)
        .map_err(|e| json!({"verdict":"FAIL","error":{"code":"STORE","message":format!("open n2 store: {e}")}}))?;
    let mut manager = SessionManager::new(Box::new(store.sessions()), DEFAULT_ATTACH_WINDOW_SECS);
    manager.load_from_store().map_err(|e| {
        json!({"verdict":"FAIL","error":{"code":"STORE","message":format!("load sessions: {e}")}})
    })?;
    Ok((store, manager))
}

fn manager_error_json(e: SessionManagerError) -> Value {
    match e {
        SessionManagerError::NotFound { session } => json!({
            "verdict": "FAIL",
            "error": {
                "code": "NOT_FOUND",
                "kind": "session",
                "id": session.0,
            },
        }),
        SessionManagerError::AlreadyTerminated { session, outcome } => json!({
            "verdict": "FAIL",
            "error": {
                "code": "ALREADY_TERMINATED",
                "id": session.0,
                "outcome": format!("{outcome:?}"),
            },
        }),
        other => json!({
            "verdict": "FAIL",
            "error": {
                "code": "SESSION",
                "message": other.to_string(),
            },
        }),
    }
}

fn render(out: &Value, _json_mode: bool) {
    // v1: 人读输出与 JSON 同形（`--json` 语义的最小实现）。
    println!("{out}");
}

/// `nexus session list`。
fn run_list(json_mode: bool) -> i32 {
    let node_dir = crate::node_cli::node_dir();
    let now = now_unix_pub();
    let directory = match N2Directory::open(&node_dir, now) {
        Ok(d) => d,
        Err(e) => {
            render(
                &json!({"verdict":"FAIL","error":{"code":"STORE","message":e}}),
                json_mode,
            );
            return 0;
        }
    };
    match open_manager(&node_dir) {
        Ok((_store, manager)) => {
            let sessions: Vec<Value> = manager
                .list()
                .iter()
                .map(|v| view_json(v, &directory))
                .collect();
            render(
                &json!({
                    "verdict": "PASS",
                    "command": "session list",
                    "sessions": sessions,
                }),
                json_mode,
            );
            0
        }
        Err(fail) => {
            render(&fail, json_mode);
            0
        }
    }
}

/// `nexus session watch <id>`：按 SessionId 查询状态＋历史 DecisionTrace。
fn run_watch(id: &str, json_mode: bool) -> i32 {
    let node_dir = crate::node_cli::node_dir();
    let now = now_unix_pub();
    let directory = match N2Directory::open(&node_dir, now) {
        Ok(d) => d,
        Err(e) => {
            render(
                &json!({"verdict":"FAIL","error":{"code":"STORE","message":e}}),
                json_mode,
            );
            return 0;
        }
    };
    match open_manager(&node_dir) {
        Ok((_store, manager)) => {
            let sid = SessionId(id.to_string());
            match manager.attach(&sid) {
                Ok(view) => {
                    render(
                        &json!({
                            "verdict": "PASS",
                            "command": "session watch",
                            "session": view_json(&view, &directory),
                        }),
                        json_mode,
                    );
                    0
                }
                Err(e) => {
                    render(&manager_error_json(e), json_mode);
                    0
                }
            }
        }
        Err(fail) => {
            render(&fail, json_mode);
            0
        }
    }
}

/// `nexus session close <id>`：主动关闭 → `Cancelled`。
fn run_close(id: &str, json_mode: bool) -> i32 {
    let node_dir = crate::node_cli::node_dir();
    let now = now_unix_pub();
    let directory = match N2Directory::open(&node_dir, now) {
        Ok(d) => d,
        Err(e) => {
            render(
                &json!({"verdict":"FAIL","error":{"code":"STORE","message":e}}),
                json_mode,
            );
            return 0;
        }
    };
    match open_manager(&node_dir) {
        Ok((_store, mut manager)) => {
            let sid = SessionId(id.to_string());
            match manager.close(&sid, "session close: user requested") {
                Ok(view) => {
                    render(
                        &json!({
                            "verdict": "PASS",
                            "command": "session close",
                            "session": view_json(&view, &directory),
                        }),
                        json_mode,
                    );
                    0
                }
                Err(e) => {
                    render(&manager_error_json(e), json_mode);
                    0
                }
            }
        }
        Err(fail) => {
            render(&fail, json_mode);
            0
        }
    }
}

/// `nexus session seed <session-id>`：E4 夹具——播种一条固定 id 的会话记录。
///
/// 语义：`Active`/`Unfinished`＋最小 `PlanSnapshot`（`DecisionTrace` 非空形状），
/// 幂等（同 id 重复播种覆盖旧记录）。仅供 harness `[given].fixture` 在 E4 前
/// 准备环境（`n2-session-watch`/`n2-session-close` 的固定 id 前置）；生产路径
/// 不调用——真实会话由 `nexus use` 经 `SessionManager` 建立。
fn run_seed(id: &str, json_mode: bool) -> i32 {
    // id 校验：非空＋安全字符集（KV 键直接由 id 派生，拒绝路径穿越/空白）。
    if id.is_empty()
        || !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        let fail = json!({"verdict":"FAIL","error":{"code":"BAD_SESSION_ID","message":"session id must be non-empty [A-Za-z0-9_-]"}});
        render(&fail, json_mode);
        return 0;
    }
    let node_dir = crate::node_cli::node_dir();
    match seed_session_at(&node_dir, id) {
        Ok(()) => {
            render(
                &json!({
                    "verdict": "PASS",
                    "command": "session seed",
                    "session": {"id": id, "phase": "active", "outcome": "Unfinished"},
                }),
                json_mode,
            );
            0
        }
        Err(e) => {
            render(
                &json!({"verdict":"FAIL","error":{"code":"STORE","message":format!("seed session: {e}")}}),
                json_mode,
            );
            0
        }
    }
}

/// `run_seed` 的可测试内核：目录由调用方注入（测试不碰进程环境）。
fn seed_session_at(node_dir: &std::path::Path, id: &str) -> Result<(), String> {
    let store = N2Store::open(node_dir).map_err(|e| format!("open n2 store: {e}"))?;
    let record = nexus_session::SessionRecord {
        session: SessionId(id.to_string()),
        phase: nexus_domain::LifecyclePhase::Active,
        outcome: TerminalOutcome::Unfinished,
        plan_snapshot: Some(seed_plan_snapshot(id)),
        detached_at_unix: None,
    };
    let mut sessions = store.sessions();
    use nexus_session::SessionRecordStore as _;
    sessions
        .save(&record)
        .map_err(|e| format!("save session: {e}"))
}

/// 夹具用的最小 PlanSnapshot：plan_id 由 session id 确定性派生（FNV-1a 64，
/// 非密码学，仅作标识）；trace 含一条可行候选（形状与真实规划一致）。
fn seed_plan_snapshot(id: &str) -> nexus_domain::PlanSnapshot {
    // FNV-1a 64（D3：PlanId 用确定性非密码学摘要作标识符，不做安全边界）。
    let mut h: u64 = 0xcbf29ce484222325;
    for b in id.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x100000001b3);
    }
    let plan_id = nexus_domain::PlanId(format!("{h:016x}"));
    let provider = nexus_domain::ProviderId("local-dev-1".into());
    nexus_domain::PlanSnapshot {
        plan_id,
        plan: nexus_domain::Plan {
            resource_id: nexus_domain::ResourceId("res-dev-svc".into()),
            provider_id: provider.clone(),
            placement: "local".into(),
            path: vec!["127.0.0.1:8080".into()],
            execution_strategy: "direct".into(),
            extension: None,
        },
        decision_trace: nexus_domain::DecisionTrace {
            considered: vec![nexus_domain::ConsideredCandidate {
                provider: provider.clone(),
                rejected_reason: None,
                connectivity: None,
                measurement: None,
                score: Some(100),
                score_breakdown: None,
            }],
            selected: provider,
        },
    }
}
/// `nexus session` 命令族入口。
pub fn run_session(args: &[String], json_mode: bool) -> i32 {
    const USAGE: &str = "usage: nexus session list | nexus session watch <session-id> | nexus session close <session-id> | nexus session seed <session-id>  # seed 为 E4 夹具";
    match args.first().map(String::as_str) {
        Some("list") if args.len() == 1 => run_list(json_mode),
        Some("watch") => {
            let Some(id) = args.get(1) else {
                eprintln!("error: missing argument: <session-id>");
                eprintln!("{USAGE}");
                return 2;
            };
            if args.len() > 2 {
                eprintln!("error: too many arguments for session watch");
                eprintln!("{USAGE}");
                return 2;
            }
            run_watch(id, json_mode)
        }
        Some("close") => {
            let Some(id) = args.get(1) else {
                eprintln!("error: missing argument: <session-id>");
                eprintln!("{USAGE}");
                return 2;
            };
            if args.len() > 2 {
                eprintln!("error: too many arguments for session close");
                eprintln!("{USAGE}");
                return 2;
            }
            run_close(id, json_mode)
        }
        Some("seed") => {
            let Some(id) = args.get(1) else {
                eprintln!("error: missing argument: <session-id>");
                eprintln!("{USAGE}");
                return 2;
            };
            if args.len() > 2 {
                eprintln!("error: too many arguments for session seed");
                eprintln!("{USAGE}");
                return 2;
            }
            run_seed(id, json_mode)
        }
        _ => {
            eprintln!("error: unknown session subcommand");
            eprintln!("{USAGE}");
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::n2_store::N2Store;
    use nexus_domain::{DecisionTrace, LifecyclePhase, Plan, PlanId, ProviderId, ResourceId};
    use nexus_session::{SessionRecord, SessionRecordStore as _};

    fn temp_node_dir(tag: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("session-cli-test-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// 播种一条会话记录（E4 `sess-n2-e4-*` 夹具的测试替身）。
    fn seed_session(
        dir: &std::path::Path,
        id: &str,
        phase: LifecyclePhase,
        outcome: TerminalOutcome,
    ) {
        let store = N2Store::open(dir).unwrap();
        let mut sessions = store.sessions();
        sessions
            .save(&SessionRecord {
                session: SessionId(id.to_string()),
                phase,
                outcome,
                plan_snapshot: Some(PlanSnapshotForTest::snapshot()),
                detached_at_unix: None,
            })
            .unwrap();
    }

    struct PlanSnapshotForTest;
    impl PlanSnapshotForTest {
        fn snapshot() -> nexus_domain::PlanSnapshot {
            nexus_domain::PlanSnapshot {
                plan_id: PlanId("e4seed00e4seed00".into()),
                plan: Plan {
                    resource_id: ResourceId("res-dev-svc".into()),
                    provider_id: ProviderId("local-dev-1".into()),
                    placement: "local".into(),
                    path: vec!["127.0.0.1:8080".into()],
                    execution_strategy: "direct".into(),
                    extension: None,
                },
                decision_trace: DecisionTrace {
                    considered: vec![],
                    selected: ProviderId("local-dev-1".into()),
                },
            }
        }
    }

    #[test]
    fn session_list_and_watch_roundtrip() {
        let dir = temp_node_dir("list-watch");
        seed_session(
            &dir,
            "sess-n2-e4-1",
            LifecyclePhase::Active,
            TerminalOutcome::Completed,
        );
        let (store, manager) = open_manager(&dir).unwrap();
        let _ = store;
        // list 非空。
        assert_eq!(manager.list().len(), 1);
        // watch 精确回显 id＋历史 trace。
        let view = manager.attach(&SessionId("sess-n2-e4-1".into())).unwrap();
        assert_eq!(view.id.0, "sess-n2-e4-1");
        assert!(matches!(view.outcome, TerminalOutcome::Completed));
        let dir2 = N2Directory::open(&dir, 1000).unwrap();
        let v = view_json(&view, &dir2);
        assert_eq!(v["id"], json!("sess-n2-e4-1"));
        assert_eq!(v["outcome"], json!("Completed"));
        assert_eq!(v["plan_id"], json!("e4seed00e4seed00"));
        assert_eq!(v["trace"]["selected"], json!("local-dev-1"));
        // review-n2-p04（observability 回归）：生产读路径 list/watch 必须回填
        // resource/provider——持久化记录无这两个字段，重建时从
        // plan_snapshot.plan.resource_id/provider_id 回填；空字符串即 FAIL。
        assert_eq!(v["resource"], json!("dev-svc"));
        assert_eq!(v["resource_id"], json!("res-dev-svc"));
        assert_eq!(v["provider"], json!("local-dev-1"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn session_close_active_becomes_cancelled() {
        // n2-session-close 形状：Active 会话关闭 → Cancelled（非 Failed）。
        let dir = temp_node_dir("close");
        seed_session(
            &dir,
            "sess-n2-e4-2",
            LifecyclePhase::Active,
            TerminalOutcome::Unfinished,
        );
        let (_store, mut manager) = open_manager(&dir).unwrap();
        let view = manager
            .close(&SessionId("sess-n2-e4-2".into()), "test")
            .unwrap();
        assert_eq!(view.outcome, TerminalOutcome::Cancelled);
        let dir2 = N2Directory::open(&dir, 1000).unwrap();
        let v = view_json(&view, &dir2);
        assert_eq!(v["id"], json!("sess-n2-e4-2"));
        assert_eq!(v["outcome"], json!("Cancelled"));
        assert_eq!(v["cancel_reason"], json!("UserClosed"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn session_watch_missing_is_not_found() {
        let dir = temp_node_dir("missing");
        let (_store, manager) = open_manager(&dir).unwrap();
        let err = manager.attach(&SessionId("sess-nope".into())).unwrap_err();
        let v = manager_error_json(err);
        assert_eq!(v["verdict"], json!("FAIL"));
        assert_eq!(v["error"]["code"], json!("NOT_FOUND"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn session_seed_is_idempotent_and_watchable() {
        // E4 夹具 `session seed`：播种固定 id 会话；重复播种覆盖（幂等）；
        // 播种后 watch 精确回显 id。
        let dir = temp_node_dir("seed");
        seed_session_at(&dir, "sess-n2-e4-1").unwrap();
        seed_session_at(&dir, "sess-n2-e4-1").unwrap(); // 幂等：不报错
        let (_store, manager) = open_manager(&dir).unwrap();
        let view = manager.attach(&SessionId("sess-n2-e4-1".into())).unwrap();
        assert_eq!(view.id.0, "sess-n2-e4-1");
        assert!(matches!(view.outcome, TerminalOutcome::Unfinished));
        // 快照形状：plan_id 确定性非空，decision_trace 含一条候选。
        let snap = view.plan_snapshot.expect("seed snapshot");
        assert!(!snap.plan_id.as_str().is_empty());
        assert_eq!(snap.decision_trace.considered.len(), 1);
        assert_eq!(snap.decision_trace.selected.0, "local-dev-1");
        // 同一 id 的 plan_id 确定（两次播种一致）。
        let snap2 = seed_plan_snapshot("sess-n2-e4-1");
        assert_eq!(snap.plan_id, snap2.plan_id);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn run_session_usage_errors_exit_2() {
        assert_eq!(run_session(&[], true), 2);
        assert_eq!(run_session(&["bogus".to_string()], true), 2);
        assert_eq!(run_session(&["watch".to_string()], true), 2);
    }
}
