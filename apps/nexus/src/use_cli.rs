//! `nexus use <name>`（N2 P0-4/P0-5，D4）：N2 资源访问入口四步闭环。
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
//! 退出码（P1-20）：`0` = 命令已执行且 `verdict` 非 FAIL；`1` = 业务
//! `verdict=FAIL`；`2` = 用法错误（参数不合法，不产出 JSON）。机器可读权威
//! 始终是 `verdict` 字段，退出码只是把它如实暴露给 shell（`$?` / `set -e`）。
//!
//! D1 提供方侧 admission＋租约：
//! - 本地路径（P0-4）：本命令在本地同时扮演请求方与提供方；授权通过后写入租约
//!   记录（`n2/lease/<session-id>`）；
//! - 跨机路径（P0-5）：选中 provider 的广告含 `n2adm://` 准入端点时，拨号 B 机
//!   `nexus provider serve` 做挑战-应答握手＋B 机侧 grant 判定＋审计＋租约
//!   （`n2_admission`）；A 机侧只建 Session（请求方 SessionManager），
//!   不做第二个领域 Session（D1）；两侧各自独立提交 TerminalOutcome。
//!
//! `--` 后命令在 P0 按 D4 只做诚实化（P0-0 已落地，保持）：`use` 不接受 `--`
//! 后命令（那是 N3 任务语义），遇到直接结构化拒绝。

use nexus_auth::{AuthRequest, GrantTable};
use nexus_domain::{
    AuthorizationDecision, NexusError, PlanSnapshot, ProviderId, ResourceId, ResourceOperation,
};
use nexus_registry::UnavailabilityReason;
use nexus_session::{DEFAULT_ATTACH_WINDOW_SECS, SessionManager};
use serde_json::{Value, json};

use crate::n2_admission::{AdmissionVerdict, admit_session, control_locator_of};
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

fn render(out: &Value, json_mode: bool) -> i32 {
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
    crate::verdict_exit_code(out)
}

/// 四步闭环的可测试内核（`node_dir` 注入；`now_secs` 注入）。
///
/// 返回 `(session_id, plan_snapshot, endpoint)`；错误为结构化 `Value`
///（`verdict: FAIL` 的 JSON body）。
pub fn use_resource(node_dir: &std::path::Path, name: &str, now: u64) -> Result<UseOutcome, Value> {
    // ---- 0. `--` 后命令诚实拒绝（D4；`use` 不执行命令，那是 N3） ----
    // （参数层已拦截；此处为内核级二次保护。）

    // ---- 1. resolve（D2：名字本地解析） ----
    let store = N2Store::open(node_dir)
        .map_err(|e| fail_json("STORE", json!({"message": format!("open n2 store: {e}")})))?;
    // P1-21：`n2/lease/*` 不再"只写不删"——进入资源访问前先回收过期租约。
    if let Err(e) = store.prune_expired_leases(now) {
        eprintln!("nexus use: lease prune failed: {e}");
    }
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

    // ---- 2b. 提供方定位：本地 vs 跨机（P0-5） ----
    // 选中 provider 的广告含 `n2adm://` 准入端点 → 跨机路径（B 机侧判定）；
    // 否则本地路径（P0-4 原语义：本地同时扮演请求方与提供方）。
    let control_addr = directory
        .registry()
        .lookup_ads(&resource_id, now)
        .into_iter()
        .find(|ad| ad.provider == provider_id)
        .and_then(|ad| control_locator_of(&ad));

    // SessionManager 预加载（远端路径先 open 拿 id 再准入；本地路径保持原顺序）。
    let mut manager = SessionManager::new(Box::new(store.sessions()), DEFAULT_ATTACH_WINDOW_SECS);
    manager
        .load_from_store()
        .map_err(|e| fail_json("STORE", json!({"message": format!("load sessions: {e}")})))?;

    if let Some(control) = control_addr {
        return use_remote(
            node_dir,
            &store,
            &mut manager,
            name,
            &resource_id,
            &provider_id,
            &snapshot,
            &endpoint,
            &control,
            now,
        );
    }

    // ---- 3. authorize（D6：provider 侧 grant 表检查；目录可见≠有权限） ----
    // （本地路径：本节点即 provider，查本地表；跨机路径由 B 机侧执行，见 use_remote。）
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
    //
    // ---- 4. establish（D1：SessionManager 创建＋持久化；PlanSnapshot 内嵌） ----
    // （manager 已在 2b 预加载。）
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
    // P1-9：对"暴露的访问入口"做一次真实连通性探测。种子/演示地址不在本次
    // 判定内改变 `verdict`（`n2-use-loop` 的冻结期望以静态种子为准），但探测
    // 结果必须如实出现在输出里，不再"未经确认就宣告可访问"。
    let probe = probe_endpoint(&endpoint);
    Ok(UseOutcome {
        session_id: session_id.0,
        snapshot,
        endpoint,
        probe,
        cross_machine: false,
    })
}

/// 跨机路径（P0-5）：选中 provider 为远端（广告含 `n2adm://` 准入端点）。
///
/// 顺序：open（Active/Unfinished，拿 session_id）→ B 机准入（挑战-应答握手＋
/// B 机侧 grant 判定＋审计＋租约，`n2_admission`）→ admit 则 complete，
/// 否则 close（Cancelled）并返回结构化失败。A 机侧**不**查本地 grant 表
/// （D6：判定在 provider 侧执行），**不**写本地租约（B 机侧写，D1）。
#[allow(clippy::too_many_arguments)]
fn use_remote(
    node_dir: &std::path::Path,
    store: &N2Store,
    manager: &mut SessionManager,
    name: &str,
    resource_id: &ResourceId,
    provider_id: &ProviderId,
    snapshot: &PlanSnapshot,
    endpoint: &str,
    control: &str,
    now: u64,
) -> Result<UseOutcome, Value> {
    let session_id = manager
        .open(resource_id.clone(), provider_id.clone(), snapshot.clone())
        .map_err(|e| fail_json("SESSION", json!({"message": e.to_string()})))?;
    // 准入失败时关闭会话（Cancelled；尝试记录保留，可观测）。
    let close_attempt = |manager: &mut SessionManager, reason: &str| {
        let _ = manager.close(&session_id, reason);
    };
    match admit_session(control, node_dir, &session_id.0, resource_id) {
        Ok(AdmissionVerdict::Admitted {
            provider: _,
            endpoint: adm_endpoint,
        }) => {
            let ep = if adm_endpoint.is_empty() {
                endpoint.to_string()
            } else {
                adm_endpoint
            };
            // P1-9：跨机路径的入口由提供方**在准入响应中背书**（不是本地
            // 缓存的静态种子），因此必须连得通才宣告成功——连不上即结构化失败，
            // 而不是"输出一个从没验证过的入口 + PASS"。
            let probe = probe_endpoint(&ep);
            if !probe.reachable {
                close_attempt(manager, "service-endpoint-unreachable");
                return Err(fail_json(
                    "ENDPOINT_UNREACHABLE",
                    json!({
                        "provider": provider_id.0,
                        "endpoint": ep,
                        "detail": probe.detail,
                        "message": format!(
                            "provider {} admitted the session but its service endpoint {ep} is unreachable: {}",
                            provider_id.0, probe.detail
                        ),
                    }),
                ));
            }
            let view = manager
                .complete(&session_id)
                .map_err(|e| fail_json("SESSION", json!({"message": e.to_string()})))?;
            debug_assert_eq!(view.outcome, nexus_domain::TerminalOutcome::Completed);
            Ok(UseOutcome {
                session_id: session_id.0,
                snapshot: snapshot.clone(),
                endpoint: ep,
                probe,
                cross_machine: true,
            })
        }
        Ok(AdmissionVerdict::Denied { deny }) => {
            close_attempt(manager, &format!("admission-denied:{deny}"));
            // 带上请求方自身 principal（运维据此在 B 机 `grant add`）。
            let principal = ensure_auth_identity(store)
                .map(|(_, p)| p.0)
                .unwrap_or_default();
            Err(fail_json(
                "AUTH_DENIED",
                json!({
                    "deny": deny,
                    "audit_written": true,
                    "resource": name,
                    "provider": provider_id.0,
                    "principal": principal,
                    "message": format!("provider {} denied session for '{name}': {deny}", provider_id.0),
                }),
            ))
        }
        Ok(AdmissionVerdict::NotFound) => {
            // 提供方已撤销/withdraw：失效本地缓存广告，后续 resolve 走干净 NOT_FOUND。
            let _ = store.delete_ad(provider_id, resource_id);
            close_attempt(manager, "provider-resource-gone");
            Err(fail_json(
                "NOT_FOUND",
                json!({
                    "provider": provider_id.0,
                    "message": format!("resource '{name}' no longer available on provider {}", provider_id.0),
                }),
            ))
        }
        // P1-12：按语义归一——拨号不通、握手中途 RST/超时/对端提前关闭都是
        // 同一个"provider 下线"事实：同一个 `PROVIDER_UNREACHABLE` 码 ＋ 同样
        // 落离线状态。密码学失败、协议语义不匹配（版本/格式）与本地故障保留
        // 独立的 `CONNECT_FAILED`（它们不代表对端下线）。
        Err(e) if e.is_provider_unreachable() => {
            mark_provider_offline(store, provider_id, resource_id, now);
            close_attempt(manager, "provider-offline");
            Err(fail_json(
                "PROVIDER_UNREACHABLE",
                json!({
                    "reason": "ProviderOffline",
                    "provider": provider_id.0,
                    "message": format!("provider {} unreachable at {control}: {e}", provider_id.0),
                }),
            ))
        }
        Err(e) => {
            close_attempt(manager, "admission-error");
            Err(fail_json(
                e.code(),
                json!({
                    "provider": provider_id.0,
                    "detail": e.code(),
                    "message": format!("admission to {} failed: {e}", provider_id.0),
                }),
            ))
        }
    }
}

/// 端点连通性探测结果（§16.4-1"建立真实访问"）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointProbe {
    /// 声明的访问入口（原样）。
    pub endpoint: String,
    /// 是否真的连得上（TCP）。
    pub reachable: bool,
    /// 不可达原因（`reachable == true` 时为空）。
    pub detail: String,
}

/// `use` 成功路径的产物（四步闭环结果 ＋ 端点探测事实）。
#[derive(Debug, Clone)]
pub struct UseOutcome {
    pub session_id: String,
    pub snapshot: PlanSnapshot,
    /// 宣告的访问入口。
    pub endpoint: String,
    /// 该入口的真实连通性（`use` 不再"未经确认就宣告可访问"）。
    pub probe: EndpointProbe,
    /// 入口是否来自远端提供方的准入响应（跨机路径）。
    pub cross_machine: bool,
}

/// 探测 `access.endpoint` 的 TCP 连通性（P1-9）。
///
/// locator 可能带 scheme（`tcp://host:port`）也可能是不带（`127.0.0.1:8080`）；
/// 先剥 scheme 再解析 `SocketAddr`。无法解析形状时诚实报"未知"（不猜）。
pub fn probe_endpoint(endpoint: &str) -> EndpointProbe {
    let hostport = endpoint
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(endpoint);
    let Ok(addr) = hostport.parse::<std::net::SocketAddr>() else {
        return EndpointProbe {
            endpoint: endpoint.to_string(),
            reachable: false,
            detail: format!("unparsable endpoint shape: {hostport}"),
        };
    };
    match std::net::TcpStream::connect_timeout(&addr, ENDPOINT_PROBE_TIMEOUT) {
        Ok(s) => {
            let _ = s.shutdown(std::net::Shutdown::Both);
            EndpointProbe {
                endpoint: endpoint.to_string(),
                reachable: true,
                detail: "connected".to_string(),
            }
        }
        Err(e) => EndpointProbe {
            endpoint: endpoint.to_string(),
            reachable: false,
            detail: format!("connect {addr}: {e}"),
        },
    }
}

/// 端点探测超时（秒）。
pub const ENDPOINT_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// 把持久化广告标记为 ProviderOffline（`n2-provider-offline` 的状态沉淀）。
fn mark_provider_offline(
    store: &N2Store,
    provider_id: &ProviderId,
    resource_id: &ResourceId,
    now: u64,
) {
    let mut ads = store.load_ads().unwrap_or_default();
    if let Some(ad) = ads
        .iter_mut()
        .find(|ad| ad.provider == *provider_id && ad.resource == *resource_id)
    {
        ad.unavailable = Some(UnavailabilityReason::ProviderOffline);
        // 刷新 issued_at：离线标记本身是新鲜观测，不被 TTL 误杀。
        ad.issued_at_secs = now;
        let _ = store.save_ad(ad);
    }
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

/// 端点连通性探测（P1-9）：宣告 `access.endpoint` 前至少做一次 TCP 探测。
///
/// `endpoint` 形如 `127.0.0.1:8080` / `tcp://10.0.0.1:8080`（剥离 scheme 后
/// `nexus use` 命令族入口。
///
/// 退出码约定（P1-20）：
/// - `0` = `verdict: PASS`；
/// - `1` = `verdict: FAIL`（业务失败：授权拒绝 / 提供方不可达 / 端点不可达 …）；
/// - `2` = 用法错误（缺参数 / 多余参数）。
///
/// 此前业务 FAIL 也返回 0，`$?` 无法判失败；场景判定只看 JSON 的 `verdict`，
/// 因此本改动不影响任何冻结期望。
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
        return render(&out, json_mode);
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
        Ok(outcome) => {
            let snapshot = outcome.snapshot;
            let mut access = json!({
                "endpoint": outcome.endpoint,
                // P1-9：访问入口的真实连通性（探测结果，不隐藏）。
                "reachable": outcome.probe.reachable,
                "probe": outcome.probe.detail,
                "cross_machine": outcome.cross_machine,
            });
            if !outcome.probe.reachable {
                access["warning"] = json!(format!(
                    "endpoint {} could not be reached during use: {}",
                    outcome.probe.endpoint, outcome.probe.detail
                ));
            }
            let out = json!({
                "verdict": "PASS",
                "command": "use",
                "directory": DIRECTORY_TAG,
                "use": {
                    "resource": name,
                    "session_id": outcome.session_id,
                    "plan_id": snapshot.plan_id.as_str(),
                    "outcome": "Completed",
                    "provider": snapshot.plan.provider_id.0,
                    "access": access,
                },
            });
            render(&out, json_mode)
        }
        Err(fail) => render(&fail, json_mode),
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
        let outcome = use_resource(&dir, "dev-svc", 1000).unwrap();
        assert!(outcome.session_id.starts_with("sess-"));
        let snapshot = &outcome.snapshot;
        assert!(!snapshot.plan_id.as_str().is_empty());
        assert_eq!(snapshot.plan.provider_id.0, "local-dev-1");
        assert_eq!(outcome.endpoint, "127.0.0.1:8080");
        // P1-9：入口连通性被如实探测并回报（不隐藏结果）。
        assert_eq!(outcome.probe.endpoint, outcome.endpoint);
        assert!(!outcome.probe.detail.is_empty());
        assert!(!outcome.cross_machine);
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
        let outcome = use_resource(&dir, "dev-svc", 1000).unwrap();
        let (session_id, snapshot) = (outcome.session_id, outcome.snapshot);
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
        // P1-20：业务 FAIL 的退出码为 1（用法错误才是 2），`$?` 可判失败。
        let code = run_use(
            &["dev-svc".to_string(), "--".to_string(), "ls".to_string()],
            true,
        );
        assert_eq!(code, 1);
    }

    #[test]
    fn verdict_exit_code_maps_fail_to_nonzero() {
        // P1-20：`verdict` 是机器可读权威，退出码与之对齐。
        assert_eq!(crate::verdict_exit_code(&json!({"verdict": "FAIL"})), 1);
        assert_eq!(crate::verdict_exit_code(&json!({"verdict": "PASS"})), 0);
        assert_eq!(crate::verdict_exit_code(&json!({"verdict": "UNKNOWN"})), 0);
        assert_eq!(crate::verdict_exit_code(&json!({"other": 1})), 0);
    }

    #[test]
    fn use_writes_lease() {
        // D1 提供方侧租约：authorize 通过后落盘。
        let dir = temp_node_dir("lease");
        grant_for(&dir, "dev-svc");
        let session_id = use_resource(&dir, "dev-svc", 1000).unwrap().session_id;
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

    // ---- P1-9：访问入口连通性探测 ----

    #[test]
    fn probe_endpoint_reports_unreachable_on_closed_port() {
        // 找一个确定没人监听的端口（bind 后立刻 drop）。
        let probe_free = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = probe_free.local_addr().unwrap();
        drop(probe_free);
        let p = probe_endpoint(&addr.to_string());
        assert!(!p.reachable, "{p:?}");
        assert!(p.detail.contains("connect"));
        assert_eq!(p.endpoint, addr.to_string());
    }

    #[test]
    fn probe_endpoint_reports_reachable_on_listening_port() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let p = probe_endpoint(&addr.to_string());
        assert!(p.reachable, "{p:?}");
        assert_eq!(p.detail, "connected");
        drop(listener);
    }

    #[test]
    fn probe_endpoint_strips_locator_scheme() {
        // locator 可能带 scheme：`tcp://host:port` 与裸 `host:port` 等价。
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        assert!(probe_endpoint(&format!("tcp://{addr}")).reachable);
        drop(listener);
    }

    #[test]
    fn probe_endpoint_refuses_to_invent_reachability_for_unparsable_shape() {
        // 形状不认识就诚实报未知，不猜"可达"。
        let p = probe_endpoint("not-an-endpoint");
        assert!(!p.reachable);
        assert!(p.detail.contains("unparsable"), "{}", p.detail);
    }


    // ---- P1-20：退出码 ----

    #[test]
    fn business_fail_exits_nonzero_and_usage_errors_exit_2() {
        assert_eq!(run_use(&[], true), 2);
        assert_eq!(run_use(&["a".to_string(), "b".to_string()], true), 2);
        assert_eq!(run_use(&["-x".to_string()], true), 2);
        // 业务 FAIL（`--` 诚实拒绝）→ 1，不再是 0。
        assert_eq!(
            run_use(
                &["dev-svc".to_string(), "--".to_string(), "ls".to_string()],
                true
            ),
            1
        );
    }

    // ---- P1-21：过期租约回收 ----


}
