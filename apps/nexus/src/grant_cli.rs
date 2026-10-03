//! `nexus grant` 命令族（N2 P0-5，D6）：本地 grant 表管理。
//!
//! grant 表是 P0 授权模型的另一半（`{resource, principal, operations, not_after}`）；
//! P0-4 只在测试替身里写 grant，本命令族给真机运维（B 机为 A 机 principal 授权）。
//!
//! - `nexus grant add --resource <name> --principal <ed25519:...> --op <Use|Manage> [--not-after <unix>]`
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

fn render(out: &Value, _json_mode: bool) {
    // v1: 人读输出与 JSON 同形（`--json` 语义的最小实现；与 resource_cli 一致）。
    println!("{out}");
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

/// `nexus grant add --resource <name> --principal <p> --op <op> [--not-after <unix>]`
fn run_add(args: &[String], json_mode: bool) -> i32 {
    const USAGE: &str = "usage: nexus grant add --resource <name> --principal <ed25519:...> --op <Use|Manage> [--not-after <unix>]";
    let mut resource: Option<String> = None;
    let mut principal: Option<String> = None;
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
    let (Some(name), Some(principal_s), Some(op_s)) = (resource, principal, op) else {
        eprintln!("error: grant add requires --resource, --principal and --op");
        eprintln!("{USAGE}");
        return 2;
    };
    let node_dir = crate::node_cli::node_dir();
    match add_grant_to(&node_dir, &name, &principal_s, &op_s, not_after) {
        Ok(out) => {
            render(&out, json_mode);
            0
        }
        Err(fail) => {
            render(&fail, json_mode);
            0
        }
    }
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
    let revoked = store
        .revoke_grant(&rref, &Principal(principal_s.to_string()))
        .map_err(store_fail)?;
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
    match revoke_grant_in(&node_dir, &name, &principal_s) {
        Ok(out) => {
            render(&out, json_mode);
            0
        }
        Err(fail) => {
            render(&fail, json_mode);
            1
        }
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
        Ok(out) => {
            render(&out, json_mode);
            0
        }
        Err(fail) => {
            render(&fail, json_mode);
            0
        }
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
            render(&store_fail(e), json_mode);
            return 0;
        }
    };
    let grants = match store.load_grants() {
        Ok(g) => g,
        Err(e) => {
            render(&store_fail(e), json_mode);
            return 0;
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
    );
    0
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
    fn add_del_roundtrip() {
        // 可测试内核直接注入 node_dir（不碰进程 env）。
        let dir = temp_node_dir("roundtrip");
        publish(&dir, "svc-g");
        let out = add_grant_to(&dir, "svc-g", "ed25519:abc", "Use", None).unwrap();
        assert_eq!(out["verdict"], json!("PASS"));
        let store = N2Store::open(&dir).unwrap();
        let grants = store.load_grants().unwrap();
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].principal.0, "ed25519:abc");
        let out = del_grant_from(&dir, "svc-g", "ed25519:abc").unwrap();
        assert_eq!(out["grant"]["deleted"], json!(true));
        assert!(store.load_grants().unwrap().is_empty());
        // 幂等：再删一次 → deleted=false。
        let out = del_grant_from(&dir, "svc-g", "ed25519:abc").unwrap();
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
