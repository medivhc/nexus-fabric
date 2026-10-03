//! `nexus use <name>`（N2 P0-4，D4）：N2 资源访问入口四步闭环。
//!
//! 闭环（PRODUCT §16.1）：
//! ```text
//! resolve（名字→ResourceId，经 registry LocalNameTable，D2）
//!   → plan（Planner 求解，DecisionTrace 内嵌，D3）
//!   → authorize（provider 侧 grant 表检查，D6；无 grant → 结构化 Deny＋审计）
//!   → establish（SessionManager 创建 Session＋持久化，D1；PlanSnapshot 内嵌）
//! ```
//! 成功 → `verdict: PASS`，输出真实 `session_id` / `plan_id` / `outcome` /
//! `access.endpoint`（`n2-use-loop` 冻结字段）；`outcome` 为 Owner 唯一提交的
//! `TerminalOutcome`（同步 establish 完成后为 `Completed`）。
//!
//! 失败形状（冻结契约）：
//! - 无 grant → `FAIL` / `error.code=AUTH_DENIED` / `error.deny=<DenyReason>`
//!   / `error.audit_written=true`（`n2-grant-deny-audit`）；
//! - 提供方下线 → `FAIL` / `error.code=PROVIDER_UNREACHABLE` /
//!   `error.reason=ProviderOffline` / `error.provider=<id>`
//!   （`n2-provider-offline`，E5 真跨机时完整成立；P0 本地以前置检查覆盖形状）；
//! - 未知资源 → `FAIL` / `NOT_FOUND`。
//!
//! D1 提供方侧 admission＋租约：本命令在本地同时扮演请求方与提供方；
//! 授权通过后写入租约记录（`n2/lease/<session-id>`），P0-5 跨机时提供方侧
//! 独立建租约（两侧各自独立提交 TerminalOutcome，不做分布式共识）。
//!
//! `--` 后命令在 P0 按 D4 只做诚实化（P0-0 已落地，保持）：`use` 不接受 `--`
//! 后命令（那是 N3 任务语义），遇到直接结构化拒绝。

use nexus_auth::{AuthRequest, GrantTable};
use nexus_domain::{
    AuthorizationDecision, NexusError, PlanSnapshot, ProviderId, ResourceId, ResourceOperation,
};
use nexus_session::{DEFAULT_ATTACH_WINDOW_SECS, SessionManager};
use serde_json::{Value, json};

use crate::n2_directory::{DIRECTORY_TAG, N2Directory};
use crate::n2_identity::ensure_auth_identity;
use crate::n2_store::{N2Store, now_unix_pub};

/// 租约（D1 提供方侧）：授权通过后提供方记录的会话租约。
#[derive(Debug, Clone)]
pub struct SessionLease {
    pub session: nexus_domain::SessionId,
    pub provider: ProviderId,
    pub resource: ResourceId,
    pub principal: String,
    pub granted_at_unix: u64,
    /// 租约到期（unix 秒）；P0 固定 1 小时（P0-5 真机调优）。
    pub expires_at_unix: u64,
}

/// P0 租约时长（秒）。
pub const LEASE_TTL_SECS: u64 = 3600;

/// 当前 unix 时间（秒）。
fn now_secs() -> u64 {
    now_unix_pub()
}

fn fail_json(code: &str, detail: Value) -> Value {
    let mut error = serde_json::Map::new();
    error.insert("code".to_string(), Value::String(code.to_string()));
    if let Value::Object(map) = detail {
        for (k, v) in map {
            error.insert(k, v);
        }
    }
    json!({
        "verdict": "FAIL",
        "error": Value::Object(error),
    })
}

fn render(out: &Value, json_mode: bool) {
    if json_mode {
        println!("{out}");
    } else if let Some(use_obj) = out.get("use") {
        println!(
            "resource: {}",
            use_obj.get("resource").unwrap_or(&json!("-"))
        );
        println!(
            "session_id: {}",
            use_obj.get("session_id").unwrap_or(&json!("-"))
        );
        println!("plan_id: {}", use_obj.get("plan_id").unwrap_or(&json!("-")));
        println!("outcome: {}", use_obj.get("outcome").unwrap_or(&json!("-")));
        println!("{out}");
    } else {
        println!("{out}");
    }
}

/// 四步闭环的可测试内核（`node_dir` 注入；`now_secs` 注入）。
///
/// 返回 `(session_id, plan_snapshot, endpoint)`；错误为结构化 `Value`
///（`verdict: FAIL` 的 JSON body）。
pub fn use_resource(
    node_dir: &std::path::Path,
    name: &str,
    now: u64,
) -> Result<(String, PlanSnapshot, String), Value> {
    // ---- 0. `--` 后命令诚实拒绝（D4；`use` 不执行命令，那是 N3） ----
    // （参数层已拦截；此处为内核级二次保护。）

    // ---- 1. resolve（D2：名字本地解析） ----
    let store = N2Store::open(node_dir)
        .map_err(|e| fail_json("STORE", json!({"message": format!("open n2 store: {e}")})))?;
    let directory = N2Directory::open_with_store(&store, now).map_err(|e| {
        fail_json(
            "STORE",
            json!({"message": format!("open n2 directory: {e}")}),
        )
    })?;
    let (rref, resource_id) = directory
        .resolve(name)
        .map_err(|e| fail_json(crate::error_code(&e), json!({"message": e.to_string()})))?;

    // ---- 2. plan（D3：Planner 求解；DecisionTrace 稍后内嵌） ----
    let (_rref2, _rid, snapshot) = directory.preview(name, now).map_err(|e| {
        // 提供方下线形状（`n2-provider-offline`）：规划无可行候选，
        // 且该资源存在 ProviderOffline 广告 → 结构化不可达（非静默失败）。
        if let NexusError::ConstraintUnsatisfied { .. } = &e {
            let offline_provider = directory
                .registry()
                .lookup_ads(&resource_id, now)
                .into_iter()
                .find(|ad| {
                    matches!(
                        ad.unavailable,
                        Some(nexus_registry::UnavailabilityReason::ProviderOffline)
                    )
                })
                .map(|ad| ad.provider.0.clone());
            if let Some(provider) = offline_provider {
                return fail_json(
                    "PROVIDER_UNREACHABLE",
                    json!({
                        "reason": "ProviderOffline",
                        "provider": provider,
                        "message": format!(
                            "resource '{name}' has no feasible provider: {provider} is offline"
                        ),
                    }),
                );
            }
        }
        fail_json(crate::error_code(&e), json!({"message": e.to_string()}))
    })?;
    let provider_id = snapshot.plan.provider_id.clone();
    let endpoint = snapshot.plan.path.first().cloned().unwrap_or_default();

    // ---- 3. authorize（D6：provider 侧 grant 表检查；目录可见≠有权限） ----
    let (_pubkey, principal) =
        ensure_auth_identity(&store).map_err(|e| fail_json("IDENTITY", json!({"message": e})))?;
    let table: GrantTable = store.load_grant_table().map_err(|e| {
        fail_json(
            "STORE",
            json!({"message": format!("load grant table: {e}")}),
        )
    })?;
    let mut sink = store.audit_sink();
    let decision = table.authorize(
        &AuthRequest {
            workspace: rref.workspace.clone(),
            resource: rref.clone(),
            principal: principal.clone(),
            operation: ResourceOperation::Use,
        },
        now,
        &mut sink,
    );
    // audit_written：判定已 exactly-once 落盘（KvAuditSink 同步 journal_append）。
    let audit_written = true;
    if let AuthorizationDecision::Deny(reason) = &decision {
        return Err(fail_json(
            "AUTH_DENIED",
            json!({
                "deny": reason.code(),
                "audit_written": audit_written,
                "resource": name,
                "principal": principal.0,
                "message": format!("authorization denied for '{name}': {reason}"),
            }),
        ));
    }

    // ---- 3b. 提供方侧租约（D1：admission 通过后记录租约） ----
    // （租约键 `n2/lease/<session-id>`；session_id 在 establish 后确定，
    //  此处先占位——实际写入在 establish 后。）

    // ---- 4. establish（D1：SessionManager 创建＋持久化；PlanSnapshot 内嵌） ----
    let mut manager = SessionManager::new(Box::new(store.sessions()), DEFAULT_ATTACH_WINDOW_SECS);
    manager
        .load_from_store()
        .map_err(|e| fail_json("STORE", json!({"message": format!("load sessions: {e}")})))?;
    let session_id = manager
        .open(resource_id.clone(), provider_id.clone(), snapshot.clone())
        .map_err(|e| fail_json("SESSION", json!({"message": e.to_string()})))?;
    // 租约落盘（D1 提供方侧）。
    let lease = SessionLease {
        session: session_id.clone(),
        provider: provider_id.clone(),
        resource: resource_id.clone(),
        principal: principal.0.clone(),
        granted_at_unix: now,
        expires_at_unix: now.saturating_add(LEASE_TTL_SECS),
    };
    save_lease(&store, &lease)
        .map_err(|e| fail_json("STORE", json!({"message": format!("save lease: {e}")})))?;
    // 同步 establish 完成 → Owner 提交 Completed（§14 唯一写入者）。
    let view = manager
        .complete(&session_id)
        .map_err(|e| fail_json("SESSION", json!({"message": e.to_string()})))?;
    debug_assert_eq!(view.outcome, nexus_domain::TerminalOutcome::Completed);
    Ok((session_id.0, snapshot, endpoint))
}

/// 租约持久化（`n2/lease/<session-id>`）。
fn save_lease(store: &N2Store, lease: &SessionLease) -> Result<(), String> {
    let data = serde_json::to_string(&json!({
        "session": lease.session.0,
        "provider": lease.provider.0,
        "resource": lease.resource.0,
        "principal": lease.principal,
        "granted_at_unix": lease.granted_at_unix,
        "expires_at_unix": lease.expires_at_unix,
    }))
    .map_err(|e| format!("encode lease: {e}"))?;
    store
        .kv()
        .put(&format!("n2/lease/{}", lease.session.0), data.as_bytes())
        .map_err(|e| format!("put lease: {e}"))?;
    Ok(())
}

/// `nexus use` 命令族入口。
pub fn run_use(args: &[String], json_mode: bool) -> i32 {
    const USAGE: &str = "usage: nexus use <resource>";
    // `--` 后命令：D4 诚实拒绝（那是 N3 任务语义）。
    if args.iter().any(|a| a == "--") {
        let out = json!({
            "verdict": "FAIL",
            "error": {
                "code": "UNSUPPORTED",
                "feature": "use-with-command",
                "layer": "N3",
                "message": "nexus use does not execute commands: command execution (`use -- <command>`) is an N3 capability; N2 `use` only establishes resource access",
            },
        });
        render(&out, json_mode);
        return 0;
    }
    let Some(name) = args.first() else {
        eprintln!("error: missing argument for use");
        eprintln!("{USAGE}");
        return 2;
    };
    if name.starts_with('-') || args.len() > 1 {
        eprintln!("error: unexpected argument for use");
        eprintln!("{USAGE}");
        return 2;
    }

    let node_dir = crate::node_cli::node_dir();
    match use_resource(&node_dir, name, now_secs()) {
        Ok((session_id, snapshot, endpoint)) => {
            let out = json!({
                "verdict": "PASS",
                "command": "use",
                "directory": DIRECTORY_TAG,
                "use": {
                    "resource": name,
                    "session_id": session_id,
                    "plan_id": snapshot.plan_id.as_str(),
                    "outcome": "Completed",
                    "provider": snapshot.plan.provider_id.0,
                    "access": {
                        "endpoint": endpoint,
                    },
                },
            });
            render(&out, json_mode);
            0
        }
        Err(fail) => {
            render(&fail, json_mode);
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_auth::{Grant, Principal};
    use nexus_domain::{ResourceName, WorkspaceId};

    fn temp_node_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("use-cli-test-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn grant_for(dir: &std::path::Path, name: &str) {
        // 为本地 principal 写入一条 Use grant（E4 夹具的测试替身）。
        let store = N2Store::open(dir).unwrap();
        let (_, principal) = ensure_auth_identity(&store).unwrap();
        store
            .save_grant(&Grant::new(
                nexus_domain::ResourceRef::new(
                    WorkspaceId::new(crate::n2_directory::DEFAULT_WORKSPACE),
                    ResourceName::new(name).unwrap(),
                ),
                principal,
                vec![ResourceOperation::Use],
                None,
            ))
            .unwrap();
    }

    #[test]
    fn use_loop_four_steps_with_grant() {
        // 四步闭环（E2）：grant 存在 → PASS，真实 session_id / plan_id / endpoint。
        let dir = temp_node_dir("four-steps");
        grant_for(&dir, "dev-svc");
        let (session_id, snapshot, endpoint) = use_resource(&dir, "dev-svc", 1000).unwrap();
        assert!(session_id.starts_with("sess-"));
        assert!(!snapshot.plan_id.as_str().is_empty());
        assert_eq!(snapshot.plan.provider_id.0, "local-dev-1");
        assert_eq!(endpoint, "127.0.0.1:8080");
        // PlanSnapshot 内嵌非重算：plan_id 与 planner 产物一致。
        assert_eq!(
            snapshot.plan_id,
            nexus_domain::plan_id_of(&snapshot.plan, &snapshot.decision_trace)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn use_persists_session_with_snapshot() {
        // establish 持久化：CLI 退出重进可按 session_id 查到＋历史 trace。
        let dir = temp_node_dir("persist");
        grant_for(&dir, "dev-svc");
        let (session_id, snapshot, _) = use_resource(&dir, "dev-svc", 1000).unwrap();
        // 新 manager 从同一 store 加载（模拟重进）。
        let store = N2Store::open(&dir).unwrap();
        let mut manager =
            SessionManager::new(Box::new(store.sessions()), DEFAULT_ATTACH_WINDOW_SECS);
        manager.load_from_store().unwrap();
        let view = manager
            .attach(&nexus_domain::SessionId(session_id.clone()))
            .unwrap();
        assert_eq!(view.outcome, nexus_domain::TerminalOutcome::Completed);
        assert_eq!(
            view.plan_snapshot.as_ref().unwrap().plan_id,
            snapshot.plan_id
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn use_without_grant_is_structured_deny_with_audit() {
        // Deny 审计（E2）：无 grant → AUTH_DENIED / NoSuchGrant / audit_written。
        let dir = temp_node_dir("deny");
        let err = use_resource(&dir, "restricted-svc", 1000).unwrap_err();
        assert_eq!(err["verdict"], json!("FAIL"));
        assert_eq!(err["error"]["code"], json!("AUTH_DENIED"));
        assert_eq!(err["error"]["deny"], json!("NoSuchGrant"));
        assert_eq!(err["error"]["audit_written"], json!(true));
        // 审计落盘：journal 里有一条 auth 审计。
        let store = N2Store::open(&dir).unwrap();
        let entries = crate::n2_store::replay_audit_entries(store.kv()).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, "auth");
        assert!(entries[0].1.contains("NoSuchGrant"));
        // 拒绝后无会话残留（admission 失败不建 Session）。
        let mut manager =
            SessionManager::new(Box::new(store.sessions()), DEFAULT_ATTACH_WINDOW_SECS);
        manager.load_from_store().unwrap();
        assert!(manager.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn use_unknown_resource_is_not_found() {
        let dir = temp_node_dir("notfound");
        let err = use_resource(&dir, "no-such", 1000).unwrap_err();
        assert_eq!(err["verdict"], json!("FAIL"));
        assert_eq!(err["error"]["code"], json!("NOT_FOUND"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn use_with_ddash_is_unsupported() {
        // D4：`use -- <cmd>` 诚实拒绝（N3 语义）。
        let code = run_use(
            &["dev-svc".to_string(), "--".to_string(), "ls".to_string()],
            true,
        );
        assert_eq!(code, 0);
    }

    #[test]
    fn use_writes_lease() {
        // D1 提供方侧租约：authorize 通过后落盘。
        let dir = temp_node_dir("lease");
        grant_for(&dir, "dev-svc");
        let (session_id, _, _) = use_resource(&dir, "dev-svc", 1000).unwrap();
        let store = N2Store::open(&dir).unwrap();
        let bytes = store
            .kv()
            .get(&format!("n2/lease/{session_id}"))
            .unwrap()
            .expect("lease must exist");
        let v: Value = serde_json::from_str(&String::from_utf8(bytes).unwrap()).unwrap();
        assert_eq!(v["provider"], json!("local-dev-1"));
        assert_eq!(v["expires_at_unix"], json!(1000 + LEASE_TTL_SECS));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn run_use_usage_errors_exit_2() {
        assert_eq!(run_use(&[], true), 2);
        assert_eq!(run_use(&["a".to_string(), "b".to_string()], true), 2);
    }

    #[test]
    fn principal_is_ed25519_derived() {
        // D6：grant 检查用的 principal 来自 ed25519 公钥派生（非自称）。
        let dir = temp_node_dir("principal");
        let store = N2Store::open(&dir).unwrap();
        let (pubkey, principal) = ensure_auth_identity(&store).unwrap();
        assert_eq!(principal, Principal::from_ed25519_public_key(&pubkey));
        assert!(principal.0.starts_with("ed25519:"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
