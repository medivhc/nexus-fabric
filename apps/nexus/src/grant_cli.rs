//! `nexus grant` 命令族（N2 P0-5，D6）：本地 grant 表管理。
//!
//! grant 表是 P0 授权模型的另一半（`{resource, principal, operations, not_after}`）；
//! P0-4 只在测试替身里写 grant，本命令族给真机运维（B 机为 A 机 principal 授权）。
//!
//! - `nexus grant add --resource <name> --principal <ed25519:...> --op <Use|Manage> [--not-after <unix>]`
//! - `nexus grant del --resource <name> --principal <ed25519:...>`
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

/// `nexus grant del --resource <name> --principal <p>`（物理删除 → 后续判定为 `NoSuchGrant`）。
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
    const USAGE: &str = "usage: nexus grant <add|del|list> ...";
    let Some(sub) = args.first() else {
        eprintln!("error: missing subcommand for grant");
        eprintln!("{USAGE}");
        return 2;
    };
    match sub.as_str() {
        "add" => run_add(&args[1..], json_mode),
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
        store
            .save_names(&[NameEntry {
                workspace: WorkspaceId::new(DEFAULT_WORKSPACE),
                name: ResourceName::new(name).unwrap(),
                resource_id: ResourceId(format!("res-{name}")),
                kind: Some(nexus_domain::ResourceKind::Service),
            }])
            .unwrap();
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
}
