//! `nexus grant` 命令族（N2 P0-5，D6）：本地 grant 表管理。
//!
//! grant 表是 P0 授权模型的另一半（`{resource, principal, operations, not_after}`）；
//! P0-4 只在测试替身里写 grant，本命令族给真机运维（B 机为 A 机 principal 授权）。
//!
//! - `nexus grant add --resource <name> --principal <ed25519:...> --op <Use|Manage> [--not-after <unix>]`
//! - `nexus grant add --resource <name> --self --op <Use|Manage>`：把**本机**身份
//!   (`ensure_auth_identity` 派生的 ed25519 principal)写进 grant 表。仍是一条
//!   显式、可审计的 grant 记录（D6 不变：目录可见≠有权限），只是不再需要先
//!   用带外方式读出 principal——E4 夹具无 shell、无法把 `identity show` 的输出
//!   管道进 `--principal`（P1-8）。`--principal` 与 `--self` 互斥。
//! - `nexus grant revoke --resource <name> --principal <ed25519:...>`（tombstone 撤销，
//!   判定落 `DenyReason::Revoked`，记录保留供取证——P1-14）
//! - `nexus grant del --resource <name> --principal <ed25519:...>`（**物理删除**＝purge；
//!   记录与审计线索一并消失，仅用于明确要求"抹掉"的场景）
//! - `nexus grant list [--resource <name>]`
//!
//! 全部进程内 N2 存储操作，不经过 daemon。

use nexus_auth::{Grant, Principal};
use nexus_domain::{ResourceName, ResourceOperation, ResourceRef};
use serde_json::{Value, json};

use crate::n2_directory::{DEFAULT_WORKSPACE, N2Directory};
use crate::n2_store::{N2Store, now_unix_pub};

fn render(out: &Value, _json_mode: bool) -> i32 {
    // v1: 人读输出与 JSON 同形（`--json` 语义的最小实现；与 resource_cli 一致）。
    println!("{out}");
    crate::verdict_exit_code(out)
}

fn store_fail(e: String) -> Value {
    json!({"verdict":"FAIL","error":{"code":"STORE","message": e}})
}

fn parse_op(s: &str) -> Option<ResourceOperation> {
    match s {
        "Use" | "use" => Some(ResourceOperation::Use),
        "Manage" | "manage" => Some(ResourceOperation::Manage),
        _ => None,
    }
}

fn resolve_rref(store: &N2Store, name: &str, now: u64) -> Result<ResourceRef, Value> {
    let directory = N2Directory::open_with_store(store, now).map_err(store_fail)?;
    let (rref, _) = directory.resolve(name).map_err(|e| {
        json!({"verdict":"FAIL","error":{"code": crate::error_code(&e), "message": e.to_string()}})
    })?;
    Ok(rref)
}

/// `nexus grant add` 的可测试内核（`node_dir` 注入）。
pub(crate) fn add_grant_to(
    node_dir: &std::path::Path,
    name: &str,
    principal_s: &str,
    op_s: &str,
    not_after: Option<u64>,
) -> Result<Value, Value> {
    if ResourceName::new(name).is_err() {
        return Err(
            json!({"verdict":"FAIL","error":{"code":"INVALID_NAME","message": format!("bad resource name: {name}")}}),
        );
    }
    let Some(operation) = parse_op(op_s) else {
        return Err(
            json!({"verdict":"FAIL","error":{"code":"INVALID_OP","message": format!("unknown operation: {op_s}")}}),
        );
    };
    let now = now_unix_pub();
    let store = N2Store::open(node_dir).map_err(store_fail)?;
    let rref = resolve_rref(&store, name, now)?;
    let grant = Grant::new(
        rref.clone(),
        Principal(principal_s.to_string()),
        vec![operation],
        not_after,
    );
    store.save_grant(&grant).map_err(store_fail)?;
    // P1-18：AUTH_GRANT 公告（与 revoke 对称的出站泵生产者）——排进 outbox，
    // 由 `provider serve` 在该主体下次准入往返时投递（写成功后出队）。
    store.queue_auth_grant(&grant).map_err(store_fail)?;
    Ok(json!({
        "verdict": "PASS",
        "command": "grant add",
        "grant": {
            "resource": name,
            "workspace": rref.workspace.0,
            "principal": principal_s,
            "operations": [op_s],
            "not_after": not_after,
        },
    }))
}

/// `nexus grant add --resource <name> (--principal <p> | --self) --op <op> [--not-after <unix>]`
///
/// P1-8：`--self` 把本机身份写进 grant 表，让 E4 夹具（无 shell、无法取
/// principal 字符串）可以在干净配置目录里自洽地准备 `use` 前置。
fn run_add(args: &[String], json_mode: bool) -> i32 {
    const USAGE: &str = "usage: nexus grant add --resource <name> --principal <ed25519:...> | --self --op <Use|Manage> [--not-after <unix>]";
    let mut resource: Option<String> = None;
    let mut principal: Option<String> = None;
    let mut self_grant = false;
    let mut op: Option<String> = None;
    let mut not_after: Option<u64> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--resource" => {
                i += 1;
                resource = args.get(i).cloned();
            }
            "--principal" => {
                i += 1;
                principal = args.get(i).cloned();
            }
            "--self" => {
                self_grant = true;
            }
            "--op" => {
                i += 1;
                op = args.get(i).cloned();
            }
            "--not-after" => {
                i += 1;
                not_after = args.get(i).and_then(|s| s.parse::<u64>().ok());
            }
            other => {
                eprintln!("error: unexpected argument for grant add: {other}");
                eprintln!("{USAGE}");
                return 2;
            }
        }
        i += 1;
    }
    let (Some(name), Some(op_s)) = (resource, op) else {
        eprintln!("error: grant add requires --resource, --op and (--principal or --self)");
        eprintln!("{USAGE}");
        return 2;
    };
    if self_grant && principal.is_some() {
        eprintln!("error: --principal and --self are mutually exclusive");
        eprintln!("{USAGE}");
        return 2;
    }
    if !self_grant && principal.is_none() {
        eprintln!("error: grant add requires --principal or --self");
        eprintln!("{USAGE}");
        return 2;
    }
    let node_dir = crate::node_cli::node_dir();
    let principal_s = if self_grant {
        match self_principal(&node_dir) {
            Ok(p) => p,
            Err(fail) => return render(&fail, json_mode),
        }
    } else {
        principal.unwrap_or_default()
    };
    match add_grant_to(&node_dir, &name, &principal_s, &op_s, not_after) {
        Ok(out) => render(&out, json_mode),
        Err(fail) => render(&fail, json_mode),
    }
}

/// `--self`：解析本机身份（`ensure_auth_identity` 派生；未初始化则先创建）。
fn self_principal(node_dir: &std::path::Path) -> Result<String, Value> {
    let store = N2Store::open(node_dir).map_err(store_fail)?;
    crate::n2_identity::ensure_auth_identity(&store)
        .map(|(_, p)| p.0)
        .map_err(|e| json!({"verdict":"FAIL","error":{"code":"IDENTITY","message": e}}))
}

/// `nexus grant del` 的可测试内核（`node_dir` 注入）。
///
/// P1-14：`del` 是**物理删除**（purge 语义）——记录连同审计线索一起消失。
/// 日常"撤销"请用 `nexus grant revoke`（tombstone，判定落 `DenyReason::Revoked`）。
pub(crate) fn del_grant_from(
    node_dir: &std::path::Path,
    name: &str,
    principal_s: &str,
) -> Result<Value, Value> {
    let now = now_unix_pub();
    let store = N2Store::open(node_dir).map_err(store_fail)?;
    let rref = resolve_rref(&store, name, now)?;
    let deleted = store
        .delete_grant(&rref, &Principal(principal_s.to_string()))
        .map_err(store_fail)?;
    // P1-14/P1-18：物理删除也是授权终结，公告撤销（只在真的删掉了条目时）。
    if deleted {
        store
            .queue_auth_revoke(&rref, principal_s)
            .map_err(store_fail)?;
    }
    Ok(json!({
        "verdict": "PASS",
        "command": "grant del",
        "grant": {"resource": name, "principal": principal_s, "deleted": deleted},
    }))
}

/// `nexus grant revoke` 的可测试内核（P1-14：tombstone 撤销）。
///
/// 记录保留（可取证：`grant list` 仍能看出该主体曾被授权、何时被撤销），
/// 判定结果为 `DenyReason::Revoked` 而非 `NoSuchGrant`。
pub(crate) fn revoke_grant_in(
    node_dir: &std::path::Path,
    name: &str,
    principal_s: &str,
) -> Result<Value, Value> {
    let now = now_unix_pub();
    let store = N2Store::open(node_dir).map_err(store_fail)?;
    let rref = resolve_rref(&store, name, now)?;
    let principal = Principal(principal_s.to_string());
    let was_revoked = store
        .load_grants()
        .map_err(store_fail)?
        .iter()
        .any(|g| g.resource == rref && g.principal == principal && g.revoked);
    let revoked = store.revoke_grant(&rref, &principal).map_err(store_fail)?;
    // P1-18：只在**状态真的翻转**时公告（重复 `revoke` 幂等，不再重复播报）。
    if revoked && !was_revoked {
        store
            .queue_auth_revoke(&rref, principal_s)
            .map_err(store_fail)?;
    }
    Ok(json!({
        "verdict": "PASS",
        "command": "grant revoke",
        "grant": {
            "resource": name,
            "workspace": rref.workspace.0,
            "principal": principal_s,
            "revoked": revoked,
            "note": "tombstone: grant record kept for audit; authorization now denies with Revoked",
        },
    }))
}

/// `nexus grant revoke --resource <name> --principal <p>`（tombstone 撤销）。
fn run_revoke(args: &[String], json_mode: bool) -> i32 {
    const USAGE: &str = "usage: nexus grant revoke --resource <name> --principal <ed25519:...>";
    let mut resource: Option<String> = None;
    let mut principal: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--resource" => {
                i += 1;
                resource = args.get(i).cloned();
            }
            "--principal" => {
                i += 1;
                principal = args.get(i).cloned();
            }
            other => {
                eprintln!("error: unexpected argument for grant revoke: {other}");
                eprintln!("{USAGE}");
                return 2;
            }
        }
        i += 1;
    }
    let (Some(name), Some(principal_s)) = (resource, principal) else {
        eprintln!("error: grant revoke requires --resource and --principal");
        eprintln!("{USAGE}");
        return 2;
    };
    let node_dir = crate::node_cli::node_dir();
    // P1-20：统一走 render()->i32（verdict_exit_code）。
    match revoke_grant_in(&node_dir, &name, &principal_s) {
        Ok(out) => render(&out, json_mode),
        Err(fail) => render(&fail, json_mode),
    }
}

/// `nexus grant del --resource <name> --principal <p>`（**物理删除** = purge）。
fn run_del(args: &[String], json_mode: bool) -> i32 {
    const USAGE: &str = "usage: nexus grant del --resource <name> --principal <ed25519:...>";
    let mut resource: Option<String> = None;
    let mut principal: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--resource" => {
                i += 1;
                resource = args.get(i).cloned();
            }
            "--principal" => {
                i += 1;
                principal = args.get(i).cloned();
            }
            other => {
                eprintln!("error: unexpected argument for grant del: {other}");
                eprintln!("{USAGE}");
                return 2;
            }
        }
        i += 1;
    }
    let (Some(name), Some(principal_s)) = (resource, principal) else {
        eprintln!("error: grant del requires --resource and --principal");
        eprintln!("{USAGE}");
        return 2;
    };
    let node_dir = crate::node_cli::node_dir();
    match del_grant_from(&node_dir, &name, &principal_s) {
        Ok(out) => render(&out, json_mode),
        Err(fail) => render(&fail, json_mode),
    }
}

/// `nexus grant list [--resource <name>]`
fn run_list(args: &[String], json_mode: bool) -> i32 {
    const USAGE: &str = "usage: nexus grant list [--resource <name>]";
    let mut resource: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--resource" => {
                i += 1;
                resource = args.get(i).cloned();
            }
            other => {
                eprintln!("error: unexpected argument for grant list: {other}");
                eprintln!("{USAGE}");
                return 2;
            }
        }
        i += 1;
    }
    let node_dir = crate::node_cli::node_dir();
    let store = match N2Store::open(&node_dir) {
        Ok(s) => s,
        Err(e) => {
            return render(&store_fail(e), json_mode);
        }
    };
    let grants = match store.load_grants() {
        Ok(g) => g,
        Err(e) => {
            return render(&store_fail(e), json_mode);
        }
    };
    let items: Vec<Value> = grants
        .into_iter()
        .filter(|g| {
            resource.as_ref().is_none_or(|n| {
                g.resource.workspace.0 == DEFAULT_WORKSPACE && g.resource.name.as_str() == n
            })
        })
        .map(|g| {
            json!({
                "workspace": g.resource.workspace.0,
                "resource": g.resource.name.as_str(),
                "principal": g.principal.0,
                "operations": g.operations.iter().map(|o| format!("{o:?}")).collect::<Vec<_>>(),
                "not_after": g.not_after,
                "revoked": g.revoked,
            })
        })
        .collect();
    render(
        &json!({"verdict":"PASS","command":"grant list","grants": items}),
        json_mode,
    )
}

/// `nexus grant` 命令族入口。
pub fn run_grant(args: &[String], json_mode: bool) -> i32 {
    const USAGE: &str = "usage: nexus grant <add|revoke|del|list> ...";
    let Some(sub) = args.first() else {
        eprintln!("error: missing subcommand for grant");
        eprintln!("{USAGE}");
        return 2;
    };
    match sub.as_str() {
        "add" => run_add(&args[1..], json_mode),
        // P1-14：撤销 = tombstone（判定 Revoked，记录保留）；del = 物理 purge。
        "revoke" => run_revoke(&args[1..], json_mode),
        "del" => run_del(&args[1..], json_mode),
        "list" => run_list(&args[1..], json_mode),
        other => {
            eprintln!("error: unknown grant subcommand: {other}");
            eprintln!("{USAGE}");
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::n2_store::NameEntry;
    use nexus_domain::{ProviderId, ResourceId, WorkspaceId};
    use nexus_registry::{Discoverability, ProviderAdvertisement};

    fn temp_node_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("grant-cli-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn publish(dir: &std::path::Path, name: &str) {
        let store = N2Store::open(dir).unwrap();
        store
            .save_ad(&ProviderAdvertisement {
                provider: ProviderId("prov-t".into()),
                resource: ResourceId(format!("res-{name}")),
                capabilities: vec!["service".into()],
                locators: vec!["tcp://127.0.0.1:9".into()],
                discoverable_by: Discoverability::Public,
                use_grants: vec![],
                unavailable: None,
                issued_at_secs: 1,
                ttl_secs: 0,
            })
            .unwrap();
        // `save_names` 是全量覆盖语义：load → merge → save（与 run_publish 一致）。
        let mut names = store.load_names().unwrap();
        names.retain(|e| e.name.as_str() != name);
        names.push(NameEntry {
            workspace: WorkspaceId::new(DEFAULT_WORKSPACE),
            name: ResourceName::new(name).unwrap(),
            resource_id: ResourceId(format!("res-{name}")),
            kind: Some(nexus_domain::ResourceKind::Service),
        });
        store.save_names(&names).unwrap();
    }

    #[test]
    fn self_principal_is_ed25519_derived_and_stable() {
        // P1-8：`--self` 解析出的 principal 必须与 `use` 侧 authorize 用的是
        // 同一个 ed25519 派生身份，且在同一 node_dir 上幂等。
        let dir = temp_node_dir("self");
        let p1 = self_principal(&dir).unwrap();
        let p2 = self_principal(&dir).unwrap();
        assert!(p1.starts_with("ed25519:"));
        assert_eq!(p1, p2);
        let store = N2Store::open(&dir).unwrap();
        let (_, derived) = crate::n2_identity::ensure_auth_identity(&store).unwrap();
        assert_eq!(p1, derived.0);
        // 写进 grant 表后，授权判定按同一 principal 命中。
        publish(&dir, "svc-self");
        add_grant_to(&dir, "svc-self", &p1, "Use", None).unwrap();
        let grants = store.load_grants().unwrap();
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].principal.0, p1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// P1-18：`grant add` / `grant del` 各排一条**可投递**公告
    /// （AUTH_GRANT / AUTH_REVOKE），主体是被授权方而非本节点；
    /// 重复 `del` 幂等，不再重复播报。
    #[test]
    fn grant_add_and_del_enqueue_addressed_announcements() {
        use nexus_registry::{ControlFrame, decode_control_frame};

        let dir = temp_node_dir("announce");
        publish(&dir, "svc-a");
        add_grant_to(&dir, "svc-a", "ed25519:target", "Use", None).unwrap();
        let store = N2Store::open(&dir).unwrap();
        let items = store.outbox_list().unwrap();
        assert_eq!(items.len(), 1, "grant add must queue one AUTH_GRANT");
        assert!(matches!(
            decode_control_frame(&items[0].1),
            Ok(ControlFrame::AuthGrant { ref announcement })
                if announcement.principal == "ed25519:target"
        ));

        del_grant_from(&dir, "svc-a", "ed25519:target").unwrap();
        let items = store.outbox_list().unwrap();
        assert_eq!(items.len(), 2, "grant del must queue one AUTH_REVOKE");
        assert!(matches!(
            decode_control_frame(&items[1].1),
            Ok(ControlFrame::AuthRevoke { ref principal, .. })
                if principal == "ed25519:target"
        ));

        del_grant_from(&dir, "svc-a", "ed25519:target").unwrap();
        assert_eq!(
            store.outbox_list().unwrap().len(),
            2,
            "idempotent repeat del must not re-announce"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn add_del_roundtrip() {
        // 可测试内核直接注入 node_dir（不碰进程 env）。
        // P1-14：`grant del` = 物理 purge（条目删除），`grant revoke` = tombstone。
        let dir = temp_node_dir("roundtrip");
        publish(&dir, "svc-g");
        let out = add_grant_to(&dir, "svc-g", "ed25519:abc", "Use", None).unwrap();
        assert_eq!(out["verdict"], json!("PASS"));
        let store = N2Store::open(&dir).unwrap();
        let grants = store.load_grants().unwrap();
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].principal.0, "ed25519:abc");
        // `grant del` 物理删除 —— 条目从表中消失。
        let out = del_grant_from(&dir, "svc-g", "ed25519:abc").unwrap();
        assert_eq!(out["grant"]["deleted"], json!(true));
        assert_eq!(store.load_grants().unwrap().len(), 0, "purge must remove the entry");
        // 幂等：再删一次报 deleted=false。
        let out = del_grant_from(&dir, "svc-g", "ed25519:abc").unwrap();
        assert_eq!(out["grant"]["deleted"], json!(false));
        // `grant revoke` 是 tombstone —— 条目保留、标 revoked，
        // 授权判定得到 Deny(Revoked) 而非 NoSuchGrant。
        add_grant_to(&dir, "svc-g", "ed25519:abc", "Use", None).unwrap();
        let out = revoke_grant_in(&dir, "svc-g", "ed25519:abc").unwrap();
        assert_eq!(out["grant"]["revoked"], json!(true));
        let grants = store.load_grants().unwrap();
        assert_eq!(grants.len(), 1, "tombstone must stay in the table");
        assert!(grants[0].revoked);
        // 幂等：再 revoke 一次仍报 revoked=true。
        let out = revoke_grant_in(&dir, "svc-g", "ed25519:abc").unwrap();
        assert_eq!(out["grant"]["revoked"], json!(true));
        // 重新 add 解除撤销（upsert 覆盖 revoked 标记）。
        add_grant_to(&dir, "svc-g", "ed25519:abc", "Use", None).unwrap();
        assert!(!store.load_grants().unwrap()[0].revoked);
        // 不存在的 grant → deleted=false（幂等，不报错）。
        let out = del_grant_from(&dir, "svc-g", "ed25519:missing").unwrap();
        assert_eq!(out["grant"]["deleted"], json!(false));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn add_unknown_resource_fails_not_found() {
        let dir = temp_node_dir("notfound");
        let err = add_grant_to(&dir, "nope", "ed25519:abc", "Use", None).unwrap_err();
        assert_eq!(err["verdict"], json!("FAIL"));
        assert_eq!(err["error"]["code"], json!("NOT_FOUND"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn add_bad_op_fails() {
        let dir = temp_node_dir("badop");
        publish(&dir, "svc-g");
        let err = add_grant_to(&dir, "svc-g", "ed25519:abc", "Execute", None).unwrap_err();
        assert_eq!(err["error"]["code"], json!("INVALID_OP"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn revoke_is_tombstone_and_produces_revoked_deny() {
        // P1-14 回归：`del` 物理删除 → 后续判定是 NoSuchGrant，"曾授权后被撤销"
        // 与"从未授权"在审计里不可区分。`revoke` 打 tombstone → 判定 Revoked，
        // 且记录保留可取证。
        let dir = temp_node_dir("revoke-tombstone");
        publish(&dir, "svc-g");
        add_grant_to(&dir, "svc-g", "ed25519:abc", "Use", None).unwrap();
        let store = N2Store::open(&dir).unwrap();
        let table = store.load_grant_table().unwrap();
        let req = nexus_auth::AuthRequest {
            workspace: WorkspaceId::new(DEFAULT_WORKSPACE),
            resource: nexus_domain::ResourceRef::new(
                WorkspaceId::new(DEFAULT_WORKSPACE),
                ResourceName::new("svc-g").unwrap(),
            ),
            principal: nexus_auth::Principal("ed25519:abc".into()),
            operation: ResourceOperation::Use,
        };
        let mut sink = nexus_auth::VecAuditSink::new();
        assert_eq!(
            table.authorize(&req, 100, &mut sink),
            nexus_domain::AuthorizationDecision::Allow
        );

        let out = revoke_grant_in(&dir, "svc-g", "ed25519:abc").unwrap();
        assert_eq!(out["verdict"], json!("PASS"));
        assert_eq!(out["grant"]["revoked"], json!(true));
        // 记录仍在（可取证）。
        let grants = store.load_grants().unwrap();
        assert_eq!(grants.len(), 1);
        assert!(grants[0].revoked);
        // 判定落 Revoked（非 NoSuchGrant）。
        let table = store.load_grant_table().unwrap();
        assert_eq!(
            table.authorize(&req, 100, &mut sink),
            nexus_domain::AuthorizationDecision::Deny(nexus_domain::DenyReason::Revoked)
        );
        // 幂等：再撤一次仍成功、状态不变。
        assert_eq!(
            revoke_grant_in(&dir, "svc-g", "ed25519:abc").unwrap()["grant"]["revoked"],
            json!(true)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn revoke_unknown_grant_reports_false_not_failure() {
        let dir = temp_node_dir("revoke-missing");
        publish(&dir, "svc-g");
        let out = revoke_grant_in(&dir, "svc-g", "ed25519:nobody").unwrap();
        assert_eq!(out["grant"]["revoked"], json!(false));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resource_revoke_tombstones_its_grants() {
        // P1-14：resource revoke 只删广告不撤 grant 是不够的。
        let dir = temp_node_dir("resource-revoke-grants");
        publish(&dir, "svc-g");
        add_grant_to(&dir, "svc-g", "ed25519:abc", "Use", None).unwrap();
        let store = N2Store::open(&dir).unwrap();
        let rref = nexus_domain::ResourceRef::new(
            WorkspaceId::new(DEFAULT_WORKSPACE),
            ResourceName::new("svc-g").unwrap(),
        );
        assert_eq!(store.revoke_all_grants_for(&rref).unwrap(), 1);
        let table = store.load_grant_table().unwrap();
        let req = nexus_auth::AuthRequest {
            workspace: WorkspaceId::new(DEFAULT_WORKSPACE),
            resource: rref.clone(),
            principal: nexus_auth::Principal("ed25519:abc".into()),
            operation: ResourceOperation::Use,
        };
        let mut sink = nexus_auth::VecAuditSink::new();
        assert_eq!(
            table.authorize(&req, 100, &mut sink),
            nexus_domain::AuthorizationDecision::Deny(nexus_domain::DenyReason::Revoked)
        );
        // 幂等。
        assert_eq!(store.revoke_all_grants_for(&rref).unwrap(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn revoke_all_grants_skips_other_resources() {
        let dir = temp_node_dir("revoke-scope");
        publish(&dir, "svc-a");
        publish(&dir, "svc-b");
        add_grant_to(&dir, "svc-a", "ed25519:abc", "Use", None).unwrap();
        add_grant_to(&dir, "svc-b", "ed25519:abc", "Use", None).unwrap();
        let store = N2Store::open(&dir).unwrap();
        let rref = nexus_domain::ResourceRef::new(
            WorkspaceId::new(DEFAULT_WORKSPACE),
            ResourceName::new("svc-a").unwrap(),
        );
        assert_eq!(store.revoke_all_grants_for(&rref).unwrap(), 1);
        let revoked: Vec<bool> = store
            .load_grants()
            .unwrap()
            .iter()
            .map(|g| g.revoked)
            .collect();
        assert_eq!(revoked, vec![true, false]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
