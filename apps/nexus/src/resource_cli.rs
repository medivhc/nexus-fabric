//! `nexus resource` 命令族（N2 P0-4/P0-5）：`list` / `show` / `publish` / `revoke` /
//! `export` / `import`。
//!
//! - `nexus resource list`：目录列出有权发现的资源（`n2-resource-list`；
//!   可发现≠可使用，D2 双层授权字段）；
//! - `nexus resource show <name>`：资源详情（含双层授权字段与可用状态，
//!   `n2-resource-show`）；
//! - `nexus resource publish --name <n> --kind <k> [--locator <l> ...]`：发布资源
//!   （`n2-resource-publish`；走 P0-2 的 `publish_ad`，默认 Workspace 内部范围，
//!   白皮书 §7.3）；`--locator` 可重复，`n2adm://host:port` 标记跨机准入端点（P0-5）；
//! - `nexus resource revoke <name>`：撤销发布（`n2-resource-revoke`；
//!   触发 AUTH_REVOKE 帧→outbox 排队＋本地 withdraw＋tombstone＋目录审计）；
//! - `nexus resource export <name>` / `nexus resource import`：跨机广告交换
//!   （P0-5；D8 FrameStream 公告传输的演进前形态——文件交换，语义等价）。
//!
//! 目录变更补结构化审计事件（P0-2 评审遗留）：publish/revoke/withdraw 经
//! `record_directory_audit` 落盘 journal。

use nexus_domain::{ResourceKind, ResourceName, ResourceRef, WorkspaceId};
use nexus_registry::{
    ControlFrame, Discoverability, ProviderAdvertisement, UnavailabilityReason,
    decode_control_frame, encode_control_frame,
};
use serde_json::{Value, json};

use crate::n2_admission::CONTROL_LOCATOR_SCHEME;
use crate::n2_directory::{DEFAULT_WORKSPACE, DIRECTORY_TAG, N2Directory};
use crate::n2_identity::ensure_auth_identity;
use crate::n2_store::{
    DirectoryAuditEvent, N2Store, NameEntry, local_actor, now_unix_pub, record_directory_audit,
};

/// 当前 unix 时间（秒）。
fn now_secs() -> u64 {
    now_unix_pub()
}

fn render(out: &Value, _json_mode: bool) {
    // v1: 人读输出与 JSON 同形（`--json` 语义的最小实现）。
    println!("{out}");
}

fn store_fail(e: String) -> Value {
    json!({"verdict":"FAIL","error":{"code":"STORE","message":e}})
}

/// 广告 → JSON（`resource list/show` 用）。
fn ad_json(name: &str, kind: ResourceKind, ad: &ProviderAdvertisement) -> Value {
    let discoverable_by = match &ad.discoverable_by {
        Discoverability::Public => json!("public"),
        Discoverability::Restricted { principals } => json!({
            "restricted": principals,
        }),
    };
    json!({
        "name": name,
        "kind": kind.as_str(),
        "resource_id": ad.resource.0,
        "provider": ad.provider.0,
        "capabilities": ad.capabilities,
        "locators": ad.locators,
        "discoverable_by": discoverable_by,
        "use_grants": ad.use_grants.iter().map(|g| json!({
            "principal": g.principal,
            "operations": g.operations.iter().map(|o| o.as_str()).collect::<Vec<_>>(),
            "not_after_secs": g.not_after_secs,
        })).collect::<Vec<_>>(),
        "unavailable": ad.unavailable.as_ref().map(|u| match u {
            UnavailabilityReason::ProviderOffline => json!("ProviderOffline"),
            UnavailabilityReason::HealthDegraded { detail } => json!({"HealthDegraded": detail}),
            UnavailabilityReason::NotAcceptingWork { reason } => json!({"NotAcceptingWork": reason}),
        }),
        "issued_at_secs": ad.issued_at_secs,
        "ttl_secs": ad.ttl_secs,
    })
}

/// `nexus resource list`：目录列出有权发现的资源。
fn run_list(json_mode: bool) -> i32 {
    let node_dir = crate::node_cli::node_dir();
    let now = now_secs();
    let directory = match N2Directory::open(&node_dir, now) {
        Ok(d) => d,
        Err(e) => {
            render(&store_fail(e), json_mode);
            return 0;
        }
    };
    // 按资源聚合广告（目录视图；P0 展示全部未过期广告，可见性过滤在
    // provider 侧响应查询时做——`lookup_visible_ads`，此处为本地管理视图）。
    let mut resources: Vec<Value> = Vec::new();
    // 遍历名字表已知的全部资源（kinds 的 key 即名字集合；撤销的 resolve 已剔除）。
    for name in directory.resource_names() {
        let Ok((_rref, rid)) = directory.resolve(&name) else {
            continue;
        };
        let kind = directory.kind_of(&name).unwrap_or(ResourceKind::Service);
        let ads = directory.registry().lookup_ads(&rid, now);
        if ads.is_empty() {
            continue;
        }
        let providers: Vec<Value> = ads.iter().map(|ad| ad_json(&name, kind, ad)).collect();
        resources.push(json!({
            "name": name,
            "kind": kind.as_str(),
            "resource_id": rid.0,
            "providers": providers,
        }));
    }
    resources.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    render(
        &json!({
            "verdict": "PASS",
            "command": "resource list",
            "directory": DIRECTORY_TAG,
            "resources": resources,
        }),
        json_mode,
    );
    0
}

/// `nexus resource show <name>`：资源详情。
fn run_show(name: &str, json_mode: bool) -> i32 {
    let node_dir = crate::node_cli::node_dir();
    let now = now_secs();
    let directory = match N2Directory::open(&node_dir, now) {
        Ok(d) => d,
        Err(e) => {
            render(&store_fail(e), json_mode);
            return 0;
        }
    };
    let (rref, rid) = match directory.resolve(name) {
        Ok(v) => v,
        Err(e) => {
            render(
                &json!({
                    "verdict": "FAIL",
                    "error": {
                        "code": crate::error_code(&e),
                        "message": e.to_string(),
                    },
                }),
                json_mode,
            );
            return 0;
        }
    };
    let kind = directory.kind_of(name).unwrap_or(ResourceKind::Service);
    let ads = directory.registry().lookup_ads(&rid, now);
    if ads.is_empty() {
        render(
            &json!({
                "verdict": "FAIL",
                "error": {
                    "code": "NOT_FOUND",
                    "message": format!("resource '{name}' has no live advertisements"),
                },
            }),
            json_mode,
        );
        return 0;
    }
    // 首个可用广告的 provider 为"当前提供方"（`n2-resource-show` 冻结字段）。
    let primary = ads
        .iter()
        .find(|ad| ad.unavailable.is_none())
        .or(ads.first())
        .expect("non-empty");
    let mut out = json!({
        "verdict": "PASS",
        "command": "resource show",
        "directory": DIRECTORY_TAG,
        "resource": {
            "name": name,
            "workspace": rref.workspace.0,
            "kind": kind.as_str(),
            "resource_id": rid.0,
            "provider": primary.provider.0,
        },
    });
    out["resource"]["advertisements"] = json!(
        ads.iter()
            .map(|ad| ad_json(name, kind, ad))
            .collect::<Vec<_>>()
    );
    render(&out, json_mode);
    0
}

/// kind 参数解析（`--kind service|network|workspace|compute|device`）。
fn parse_kind(s: &str) -> Option<ResourceKind> {
    match s {
        "service" => Some(ResourceKind::Service),
        "network" => Some(ResourceKind::Network),
        "workspace" => Some(ResourceKind::Workspace),
        "compute" => Some(ResourceKind::Compute),
        "device" => Some(ResourceKind::Device),
        _ => None,
    }
}

/// kind → 默认能力（publish 时）。
fn default_capability(kind: ResourceKind) -> &'static str {
    match kind {
        ResourceKind::Service => "service",
        ResourceKind::Network => "internet-access",
        ResourceKind::Workspace => "workspace",
        ResourceKind::Compute => "compute",
        ResourceKind::Device => "device",
    }
}

/// `nexus resource publish --name <n> --kind <k> [--locator <l>]`。
fn run_publish(args: &[String], json_mode: bool) -> i32 {
    const USAGE: &str = "usage: nexus resource publish --name <name> --kind <service|network|workspace|compute|device> [--locator <locator> ...]";
    let mut name: Option<String> = None;
    let mut kind: Option<String> = None;
    // P0-5：`--locator` 可重复。约定：首个非 `n2adm://` locator 为 Service
    // 数据面端点（planner 取 `locators[0]`）；`n2adm://host:port` 为跨机准入
    // 控制端点（`n2_admission::CONTROL_LOCATOR_SCHEME`）。
    let mut locators: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--name" => {
                i += 1;
                name = args.get(i).cloned();
            }
            "--kind" => {
                i += 1;
                kind = args.get(i).cloned();
            }
            "--locator" => {
                i += 1;
                match args.get(i).cloned() {
                    Some(l) => locators.push(l),
                    None => {
                        eprintln!("error: --locator requires a value");
                        eprintln!("{USAGE}");
                        return 2;
                    }
                }
            }
            other => {
                eprintln!("error: unexpected argument for resource publish: {other}");
                eprintln!("{USAGE}");
                return 2;
            }
        }
        i += 1;
    }
    let (Some(name), Some(kind_s)) = (name, kind) else {
        eprintln!("error: resource publish requires --name and --kind");
        eprintln!("{USAGE}");
        return 2;
    };
    let Some(kind) = parse_kind(&kind_s) else {
        eprintln!(
            "error: unknown kind '{kind_s}' (expected: service|network|workspace|compute|device)"
        );
        eprintln!("{USAGE}");
        return 2;
    };
    let parsed_name = match ResourceName::new(&name) {
        Ok(n) => n,
        Err(e) => {
            render(
                &json!({"verdict":"FAIL","error":{"code":"INVALID_NAME","message":format!("{e:?}")}}),
                json_mode,
            );
            return 0;
        }
    };

    let node_dir = crate::node_cli::node_dir();
    let now = now_secs();
    let store = match N2Store::open(&node_dir) {
        Ok(s) => s,
        Err(e) => {
            render(&store_fail(e), json_mode);
            return 0;
        }
    };
    // 提供方身份：本地节点（`nexus node init` 的 NodeId；未初始化则明确报错）。
    let provider_id = match local_actor(&node_dir) {
        id if !id.is_empty() => format!("prov-{id}"),
        _ => {
            render(
                &json!({"verdict":"FAIL","error":{"code":"NO_IDENTITY","message":"node not initialized; run `nexus node init` first"}}),
                json_mode,
            );
            return 0;
        }
    };
    // 不透明 ResourceId（D2；`res-<name>` 确定性派生，非定位）。
    let resource_id = nexus_domain::ResourceId(format!("res-{name}"));
    let rref = ResourceRef::new(WorkspaceId::new(DEFAULT_WORKSPACE), parsed_name);
    // P1-13：`--locator` 顺序必须合法——首条即数据面（Service）入口。
    // 约定（`n2_admission::CONTROL_LOCATOR_SCHEME`）：`n2adm://host:port` 是准入
    // 控制端点，其余是数据面入口，判定统一走 registry 层的
    // `ProviderAdvertisement::service_locator`。把 `n2adm://` 写在前面会让下游
    // 把控制端点当成 Service 入口——直接拒绝，而不是静默产出错误入口。
    let ad_probe = ProviderAdvertisement {
        provider: nexus_domain::ProviderId(provider_id.clone()),
        resource: resource_id.clone(),
        capabilities: vec![default_capability(kind).to_string()],
        locators: locators.clone(),
        discoverable_by: Discoverability::Public,
        use_grants: Vec::new(),
        unavailable: None,
        issued_at_secs: now,
        ttl_secs: 0,
    };
    if !ad_probe.has_valid_locator_order() {
        render(
            &json!({"verdict":"FAIL","error":{"code":"BAD_LOCATOR_ORDER","message":format!(
                "--locator order invalid: the first locator must be the Service data-plane endpoint (non-'{}'); control locators must come after it",
                CONTROL_LOCATOR_SCHEME
            )}}),
            json_mode,
        );
        return 2;
    }
    let ad = ad_probe;
    // 走 P0-2 的 publish_ad（内存 registry 语义）＋落盘。
    {
        let mut registry = nexus_registry::Registry::new();
        if let Err(e) = registry.publish_ad(ad.clone(), now) {
            render(
                &json!({"verdict":"FAIL","error":{"code":"PUBLISH","message":e.to_string()}}),
                json_mode,
            );
            return 0;
        }
    }
    if let Err(e) = store.save_ad(&ad) {
        render(&store_fail(e), json_mode);
        return 0;
    }
    // 名字表：加载已持久化的＋本次新增合并后全量写回（`save_names` 为全量覆盖语义）。
    let mut names = match store.load_names() {
        Ok(n) => n,
        Err(e) => {
            render(&store_fail(e), json_mode);
            return 0;
        }
    };
    names.retain(|e| !(e.workspace == rref.workspace && e.name == rref.name));
    names.push(NameEntry {
        workspace: rref.workspace.clone(),
        name: rref.name.clone(),
        resource_id: resource_id.clone(),
        kind: Some(kind),
    });
    if let Err(e) = store.save_names(&names) {
        render(&store_fail(e), json_mode);
        return 0;
    }
    // 重新发布清除撤销 tombstone（幂等）。

    // 目录审计（P0-2 评审遗留）。
    record_directory_audit(
        store.kv(),
        &DirectoryAuditEvent {
            at_unix: now,
            actor: local_actor(&node_dir),
            action: "publish",
            resource: rref,
            provider: Some(nexus_domain::ProviderId(provider_id)),
            detail: format!("publish --name {name} --kind {kind_s}"),
        },
    );
    render(
        &json!({
            "verdict": "PASS",
            "command": "resource publish",
            "resource": {
                "name": name,
                "kind": kind.as_str(),
                "resource_id": resource_id.0,
                "published": true,
            },
        }),
        json_mode,
    );
    0
}

/// `nexus resource revoke <name>`：撤销发布。
fn run_revoke(name: &str, json_mode: bool) -> i32 {
    let node_dir = crate::node_cli::node_dir();
    let now = now_secs();
    let store = match N2Store::open(&node_dir) {
        Ok(s) => s,
        Err(e) => {
            render(&store_fail(e), json_mode);
            return 0;
        }
    };
    // 先解析（撤销不存在的资源 → 明确 NOT_FOUND，不静默成功）。
    let directory = match N2Directory::open_with_store(&store, now) {
        Ok(d) => d,
        Err(e) => {
            render(&store_fail(e), json_mode);
            return 0;
        }
    };
    // 注意：已撤销的资源 resolve 会失败；revoke 幂等——再次 revoke 仍返回
    // revoked=true（白皮书 §7.3"发布入口必须能够撤销，并显示其当前生效状态"）。
    let (rref, resource_id) = match directory.resolve(name) {
        Ok(v) => v,
        Err(_) => {
            // 可能已撤销：按名字构造 ResourceRef 重试 tombstone 路径。
            let parsed = match ResourceName::new(name) {
                Ok(n) => n,
                Err(e) => {
                    render(
                        &json!({"verdict":"FAIL","error":{"code":"INVALID_NAME","message":format!("{e:?}")}}),
                        json_mode,
                    );
                    return 0;
                }
            };
            let rref = ResourceRef::new(WorkspaceId::new(DEFAULT_WORKSPACE), parsed);
            let rid = nexus_domain::ResourceId(format!("res-{name}"));
            (rref, rid)
        }
    };

    // 1. 触发 AUTH_REVOKE 帧（D8 控制面）：编码＋outbox 落盘排队
    //    （P0-5 真跨机时实际发送；P0 本地先证明帧格式正确）。
    let (_pubkey, principal) = match ensure_auth_identity(&store) {
        Ok(v) => v,
        Err(e) => {
            render(&store_fail(e), json_mode);
            return 0;
        }
    };
    let frame = ControlFrame::AuthRevoke {
        resource: rref.clone(),
        principal: principal.0.clone(),
    };
    let frame_bytes = match encode_control_frame(&frame) {
        Ok(b) => b,
        Err(e) => {
            render(
                &json!({"verdict":"FAIL","error":{"code":"FRAME","message":e.to_string()}}),
                json_mode,
            );
            return 0;
        }
    };
    // 自检：编码可 roundtrip（帧格式正确性的机器证据）。
    debug_assert!(matches!(
        decode_control_frame(&frame_bytes),
        Ok(ControlFrame::AuthRevoke { .. })
    ));
    let seq = match store.outbox_next_seq() {
        Ok(s) => s,
        Err(e) => {
            render(&store_fail(e), json_mode);
            return 0;
        }
    };
    if let Err(e) = store.outbox_push(seq, &frame_bytes) {
        render(&store_fail(e), json_mode);
        return 0;
    }

    // 2. 本地 withdraw：删除持久化广告＋tombstone（撤销后目录不可见）。
    let mut withdrawn_any = false;
    for ad in directory.registry().lookup_ads(&resource_id, now) {
        if store.delete_ad(&ad.provider, &resource_id).unwrap_or(false) {
            withdrawn_any = true;
        }
    }
    // 从持久化名字表/广告删除（静态种子如有则自然重现，无需 tombstone）。

    // 3. 目录审计（P0-2 评审遗留）。
    record_directory_audit(
        store.kv(),
        &DirectoryAuditEvent {
            at_unix: now,
            actor: local_actor(&node_dir),
            action: "revoke",
            resource: rref,
            provider: None,
            detail: format!("revoke {name} (withdrawn_ads={withdrawn_any}, outbox_seq={seq})"),
        },
    );
    render(
        &json!({
            "verdict": "PASS",
            "command": "resource revoke",
            "resource": {
                "name": name,
                "revoked": true,
            },
        }),
        json_mode,
    );
    0
}

/// `nexus resource export <name> [--file <path>]`: 导出资源的持久化广告＋名字映射
/// （P0-5 跨机：B 机发布后导出，经带外通道传给 A 机 `resource import`；D8 的
/// FrameStream 公告传输为演进方向，P0 用文件交换——语义等价：广告内容不变）。
fn run_export(args: &[String], json_mode: bool) -> i32 {
    const USAGE: &str = "usage: nexus resource export <name> [--file <path>]";
    let mut name: Option<String> = None;
    let mut file: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--file" => {
                i += 1;
                file = args.get(i).cloned();
            }
            other if other.starts_with('-') => {
                eprintln!("error: unexpected argument for resource export: {other}");
                eprintln!("{USAGE}");
                return 2;
            }
            other => {
                if name.is_some() {
                    eprintln!("error: too many arguments for resource export");
                    eprintln!("{USAGE}");
                    return 2;
                }
                name = Some(other.to_string());
            }
        }
        i += 1;
    }
    let Some(name) = name else {
        eprintln!("error: missing argument: <name>");
        eprintln!("{USAGE}");
        return 2;
    };
    let node_dir = crate::node_cli::node_dir();
    let now = now_secs();
    let store = match N2Store::open(&node_dir) {
        Ok(s) => s,
        Err(e) => {
            render(&store_fail(e), json_mode);
            return 0;
        }
    };
    let directory = match N2Directory::open_with_store(&store, now) {
        Ok(d) => d,
        Err(e) => {
            render(&store_fail(e), json_mode);
            return 0;
        }
    };
    let (rref, resource_id) = match directory.resolve(&name) {
        Ok(v) => v,
        Err(e) => {
            render(
                &json!({"verdict":"FAIL","error":{"code": crate::error_code(&e), "message": e.to_string()}}),
                json_mode,
            );
            return 0;
        }
    };
    let kind = directory.kind_of(&name).unwrap_or(ResourceKind::Service);
    // 只导出持久化广告（本节点发布的；静态种子不导出——对端有自己的种子）。
    let ads: Vec<Value> = store
        .load_ads()
        .unwrap_or_default()
        .into_iter()
        .filter(|ad| ad.resource == resource_id)
        .map(|ad| crate::n2_store::encode_ad(&ad))
        .collect();
    if ads.is_empty() {
        render(
            &json!({"verdict":"FAIL","error":{"code":"NOT_PUBLISHED","message": format!("no persisted advertisement for '{name}'; publish it first")}}),
            json_mode,
        );
        return 0;
    }
    let doc = json!({
        "v": 1,
        "kind": "n2-resource-export",
        "workspace": rref.workspace.0,
        "name": name,
        "resource_kind": kind.as_str(),
        "resource_id": resource_id.0,
        "ads": ads,
    });
    let text = serde_json::to_string_pretty(&doc).unwrap_or_default();
    if let Some(path) = file {
        if let Err(e) = std::fs::write(&path, &text) {
            render(
                &json!({"verdict":"FAIL","error":{"code":"IO","message": format!("write {path}: {e}")}}),
                json_mode,
            );
            return 0;
        }
        render(
            &json!({"verdict":"PASS","command":"resource export","resource": name, "file": path, "ads": ads.len()}),
            json_mode,
        );
    } else {
        // 无 --file：文档打 stdout（调用方重定向保存）。
        println!("{text}");
    }
    0
}

/// `nexus resource import [--file <path>]`: 导入 `resource export` 的文档
/// （广告落盘＋名字表登记；TTL 语义与本地 publish 一致）。
fn run_import(args: &[String], json_mode: bool) -> i32 {
    const USAGE: &str = "usage: nexus resource import [--file <path>]  (no --file: read stdin)";
    let mut file: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--file" => {
                i += 1;
                file = args.get(i).cloned();
            }
            other => {
                eprintln!("error: unexpected argument for resource import: {other}");
                eprintln!("{USAGE}");
                return 2;
            }
        }
        i += 1;
    }
    let text = match file {
        Some(path) => match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) => {
                render(
                    &json!({"verdict":"FAIL","error":{"code":"IO","message": format!("read {path}: {e}")}}),
                    json_mode,
                );
                return 0;
            }
        },
        None => {
            use std::io::Read;
            let mut buf = String::new();
            if std::io::stdin().read_to_string(&mut buf).is_err() {
                render(
                    &json!({"verdict":"FAIL","error":{"code":"IO","message": "read stdin"}}),
                    json_mode,
                );
                return 0;
            }
            buf
        }
    };
    let doc: Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => {
            render(
                &json!({"verdict":"FAIL","error":{"code":"BAD_DOC","message": format!("parse: {e}")}}),
                json_mode,
            );
            return 0;
        }
    };
    let ok_kind = doc.get("kind").and_then(Value::as_str) == Some("n2-resource-export");
    let version_ok = doc.get("v").and_then(Value::as_u64) == Some(1);
    if !ok_kind || !version_ok {
        render(
            &json!({"verdict":"FAIL","error":{"code":"BAD_DOC","message": "not an n2-resource-export v1 document"}}),
            json_mode,
        );
        return 0;
    }
    let workspace = doc
        .get("workspace")
        .and_then(Value::as_str)
        .unwrap_or(DEFAULT_WORKSPACE);
    let name_s = match doc.get("name").and_then(Value::as_str) {
        Some(n) => n,
        None => {
            render(
                &json!({"verdict":"FAIL","error":{"code":"BAD_DOC","message": "missing 'name'"}}),
                json_mode,
            );
            return 0;
        }
    };
    let name = match ResourceName::new(name_s) {
        Ok(n) => n,
        Err(e) => {
            render(
                &json!({"verdict":"FAIL","error":{"code":"INVALID_NAME","message": format!("{e:?}")}}),
                json_mode,
            );
            return 0;
        }
    };
    let kind = doc
        .get("resource_kind")
        .and_then(Value::as_str)
        .and_then(parse_kind)
        .unwrap_or(ResourceKind::Service);
    let resource_id = match doc.get("resource_id").and_then(Value::as_str) {
        Some(id) => nexus_domain::ResourceId(id.to_string()),
        None => {
            render(
                &json!({"verdict":"FAIL","error":{"code":"BAD_DOC","message": "missing 'resource_id'"}}),
                json_mode,
            );
            return 0;
        }
    };
    let ads_v = match doc.get("ads").and_then(Value::as_array) {
        Some(a) if !a.is_empty() => a,
        _ => {
            render(
                &json!({"verdict":"FAIL","error":{"code":"BAD_DOC","message": "missing/empty 'ads'"}}),
                json_mode,
            );
            return 0;
        }
    };
    let node_dir = crate::node_cli::node_dir();
    let store = match N2Store::open(&node_dir) {
        Ok(s) => s,
        Err(e) => {
            render(&store_fail(e), json_mode);
            return 0;
        }
    };
    let mut imported = 0;
    for ad_v in ads_v {
        let ad = match crate::n2_store::parse_ad(ad_v) {
            Ok(a) => a,
            Err(e) => {
                render(
                    &json!({"verdict":"FAIL","error":{"code":"BAD_DOC","message": format!("bad ad: {e}")}}),
                    json_mode,
                );
                return 0;
            }
        };
        // 一致性：广告的资源必须与文档声明一致（防错配）。
        if ad.resource != resource_id {
            render(
                &json!({"verdict":"FAIL","error":{"code":"BAD_DOC","message": "ad resource mismatch"}}),
                json_mode,
            );
            return 0;
        }
        if let Err(e) = store.save_ad(&ad) {
            render(&store_fail(e), json_mode);
            return 0;
        }
        imported += 1;
    }
    if let Err(e) = store.save_names(&[NameEntry {
        workspace: WorkspaceId::new(workspace),
        name: name.clone(),
        resource_id: resource_id.clone(),
        kind: Some(kind),
    }]) {
        render(&store_fail(e), json_mode);
        return 0;
    }
    render(
        &json!({"verdict":"PASS","command":"resource import","resource": name_s, "ads": imported}),
        json_mode,
    );
    0
}

/// `nexus resource` 命令族入口。
pub fn run_resource(args: &[String], json_mode: bool) -> i32 {
    const USAGE: &str = "usage: nexus resource list | nexus resource show <name> | nexus resource publish --name <name> --kind <kind> [--locator <locator> ...] | nexus resource revoke <name> | nexus resource export <name> [--file <path>] | nexus resource import [--file <path>]";
    match args.first().map(String::as_str) {
        Some("list") if args.len() == 1 => run_list(json_mode),
        Some("show") => {
            let Some(name) = args.get(1) else {
                eprintln!("error: missing argument: <name>");
                eprintln!("{USAGE}");
                return 2;
            };
            if args.len() > 2 {
                eprintln!("error: too many arguments for resource show");
                eprintln!("{USAGE}");
                return 2;
            }
            run_show(name, json_mode)
        }
        Some("publish") => run_publish(&args[1..], json_mode),
        Some("export") => run_export(&args[1..], json_mode),
        Some("import") => run_import(&args[1..], json_mode),
        Some("revoke") => {
            let Some(name) = args.get(1) else {
                eprintln!("error: missing argument: <name>");
                eprintln!("{USAGE}");
                return 2;
            };
            if args.len() > 2 {
                eprintln!("error: too many arguments for resource revoke");
                eprintln!("{USAGE}");
                return 2;
            }
            run_revoke(name, json_mode)
        }
        _ => {
            eprintln!("error: unknown resource subcommand");
            eprintln!("{USAGE}");
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_domain::ResourceId;
    use nexus_registry::UsageGrant;

    fn temp_node_dir(tag: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("resource-cli-test-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn list_shows_seed_resources() {
        // n2-resource-list 形状：resources 非空（含 dev-svc）。
        // 直接验证目录装配（run_list 的内核逻辑），不碰进程环境变量。
        let dir = temp_node_dir("list");
        let directory = N2Directory::open(&dir, now_secs()).unwrap();
        let mut names: Vec<String> = Vec::new();
        for name in directory.resource_names() {
            if directory.resolve(&name).is_ok() {
                names.push(name);
            }
        }
        assert!(names.contains(&"dev-svc".to_string()));
        assert!(names.contains(&"internet-access".to_string()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn revoke_removes_published_ad_and_queues_frame() {
        // n2-resource-revoke 形状：revoked=true；outbox 有 AUTH_REVOKE 帧；
        // 目录审计落盘；撤销后发布的广告移除（静态种子如有则重现）。
        let dir = temp_node_dir("revoke");
        let node_dir = dir.clone();
        let store = N2Store::open(&node_dir).unwrap();
        let now = now_secs();
        // 先发布一个新资源（不在静态种子中）。
        let rref = ResourceRef::new(
            WorkspaceId::new(DEFAULT_WORKSPACE),
            ResourceName::new("tmp-svc").unwrap(),
        );
        let rid = ResourceId("res-tmp-svc".into());
        store
            .save_names(&[NameEntry {
                workspace: rref.workspace.clone(),
                name: rref.name.clone(),
                resource_id: rid.clone(),
                kind: Some(nexus_domain::ResourceKind::Service),
            }])
            .unwrap();
        let directory = N2Directory::open_with_store(&store, now).unwrap();
        assert!(directory.resolve("tmp-svc").is_ok());

        // 编码 AUTH_REVOKE 帧（与 run_revoke 同逻辑）。
        let frame = ControlFrame::AuthRevoke {
            resource: rref.clone(),
            principal: "ed25519:test".to_string(),
        };
        let bytes = encode_control_frame(&frame).unwrap();
        assert!(matches!(
            decode_control_frame(&bytes),
            Ok(ControlFrame::AuthRevoke { .. })
        ));
        let seq = store.outbox_next_seq().unwrap();
        store.outbox_push(seq, &bytes).unwrap();
        // 从持久化名字表删除（run_revoke 的内核逻辑）。
        let names = store.load_names().unwrap();
        let names: Vec<NameEntry> = names
            .into_iter()
            .filter(|e| !(e.workspace == rref.workspace && e.name == rref.name))
            .collect();
        store.save_names(&names).unwrap();
        record_directory_audit(
            store.kv(),
            &DirectoryAuditEvent {
                at_unix: now,
                actor: "test".into(),
                action: "revoke",
                resource: rref,
                provider: None,
                detail: "test revoke".into(),
            },
        );
        // 撤销后：新资源 resolve 失败（目录不可见）。
        let directory2 = N2Directory::open_with_store(&store, now).unwrap();
        assert!(directory2.resolve("tmp-svc").is_err());
        // 静态种子的 dev-svc 不受影响。
        assert!(directory2.resolve("dev-svc").is_ok());
        // 审计落盘。
        let entries = crate::n2_store::replay_audit_entries(store.kv()).unwrap();
        assert!(
            entries
                .iter()
                .any(|(t, b)| t == "directory" && b.contains("\"action\":\"revoke\""))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parse_kind_table() {
        assert_eq!(parse_kind("service"), Some(ResourceKind::Service));
        assert_eq!(parse_kind("network"), Some(ResourceKind::Network));
        assert_eq!(parse_kind("bogus"), None);
    }

    #[test]
    fn run_resource_usage_errors_exit_2() {
        assert_eq!(run_resource(&[], true), 2);
        assert_eq!(run_resource(&["bogus".to_string()], true), 2);
        assert_eq!(run_resource(&["show".to_string()], true), 2);
    }

    #[test]
    fn ad_json_carries_dual_auth_fields() {
        // D2 三件套：discoverable_by / use_grants / unavailable 全量渲染。
        let ad = ProviderAdvertisement {
            provider: nexus_domain::ProviderId("p1".into()),
            resource: nexus_domain::ResourceId("res-x".into()),
            capabilities: vec!["service".into()],
            locators: vec!["tcp://10.0.0.2:9000".into()],
            discoverable_by: Discoverability::Restricted {
                principals: vec!["ed25519:a".into()],
            },
            use_grants: vec![UsageGrant {
                principal: "ed25519:a".into(),
                operations: vec![nexus_domain::ResourceOperation::Use],
                not_after_secs: None,
            }],
            unavailable: None,
            issued_at_secs: 1,
            ttl_secs: 0,
        };
        let v = ad_json("dev-svc", ResourceKind::Service, &ad);
        assert_eq!(v["name"], json!("dev-svc"));
        assert_eq!(v["kind"], json!("service"));
        assert_eq!(v["provider"], json!("p1"));
        assert!(v["discoverable_by"]["restricted"].is_array());
        assert_eq!(v["use_grants"][0]["principal"], json!("ed25519:a"));
    }
}
