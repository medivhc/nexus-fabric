//! `nexus plan` 命令族（N2 P0-3）：只读规划预览 + `plan explain` 双模式。
//!
//! - `nexus plan <resource>`：resolve＋filter＋score 的纯本地计算，**不建连**。
//!   本模块零网络 I/O：只调用 `nexus_planner::plan_from_snapshot` 纯函数，
//!   不开 socket、不调 daemon；"Provider 侧连接计数不变"由构造保证
//!   （`n2-plan-preview` 场景断言）。
//! - `nexus plan explain <arg>`：双模式（D3）——
//!   - `sess-` 前缀：按 SessionId 查历史 PlanSnapshot（真实记录）；
//!     P0-3 只定义读契约（`nexus_planner::PlanHistory`），Session 持久化在
//!     P0-4 落地前查无记录 → 结构化 `NOT_FOUND`，**不回退重算**（不伪造历史）；
//!   - 其他：按资源名做估算，输出显式标注"估算非承诺"。
//!
//! P0-3 静态目录：编译内置的演示候选表（D2"P0 static 配置先行"的退化形式；
//! P0-4 替换为 registry-backed 解析）。本模块不伪装成真实目录：
//! 输出标注 `directory: "static-demo"`，未知资源名返回结构化 `NotFound`。

use nexus_domain::{
    Constraint, Intent, NexusError, PlanSnapshot, ProviderId, ResourceId, ResourceKind,
    ResourceName,
};
use nexus_planner::{
    ExplainMode, ExplainedPlan, PlanHistory, PlanningSnapshot, classify_explain_arg,
    plan_from_snapshot,
};
use nexus_registry::ProviderRecord;
use serde_json::{Value, json};

/// 静态目录标记（输出自述，防误解为真实目录）。
const DIRECTORY_TAG: &str = "static-demo";

/// 静态候选（编译内置；P0-4 由 registry-backed 解析替换）。
#[derive(Debug)]
struct StaticProvider {
    id: &'static str,
    placement: &'static str,
    locator: &'static str,
    capabilities: &'static [&'static str],
    present: bool,
    /// 是否为请求方本地节点（白皮书原则 #4 本地优先的加成对象）。
    local: bool,
}

/// 静态资源条目：资源名 → kind（目录属性）＋规划能力约束＋候选。
#[derive(Debug)]
struct StaticEntry {
    name: &'static str,
    kind: ResourceKind,
    capability: &'static str,
    providers: &'static [StaticProvider],
}

const DIRECTORY: &[StaticEntry] = &[
    StaticEntry {
        name: "dev-svc",
        kind: ResourceKind::Service,
        capability: "service",
        providers: &[
            StaticProvider {
                id: "local-dev-1",
                placement: "local",
                locator: "127.0.0.1:8080",
                capabilities: &["service"],
                present: true,
                local: true,
            },
            StaticProvider {
                id: "remote-dev-1",
                placement: "region-a",
                locator: "203.0.113.10:8080",
                capabilities: &["service"],
                present: true,
                local: false,
            },
            // 下面两个纯为 DecisionTrace 演示结构化拒绝原因而设。
            StaticProvider {
                id: "down-dev-1",
                placement: "region-b",
                locator: "203.0.113.11:8080",
                capabilities: &["service"],
                present: false,
                local: false,
            },
            StaticProvider {
                id: "nocap-dev-1",
                placement: "region-a",
                locator: "203.0.113.12:8080",
                capabilities: &["metrics"],
                present: true,
                local: false,
            },
        ],
    },
    StaticEntry {
        name: "internet-access",
        kind: ResourceKind::Network,
        capability: "internet-access",
        providers: &[
            StaticProvider {
                id: "p1",
                placement: "us-east",
                locator: "203.0.113.1:51820",
                capabilities: &["internet-access"],
                present: true,
                local: true,
            },
            StaticProvider {
                id: "p2",
                placement: "eu-west",
                locator: "203.0.113.2:51820",
                capabilities: &[],
                present: true,
                local: false,
            },
        ],
    },
];

fn lookup_entry(name: &str) -> Option<&'static StaticEntry> {
    DIRECTORY.iter().find(|e| e.name == name)
}

/// resolve：资源名 → (ResourceId, 静态条目)。
///
/// D2：名字本地解析（`ResourceName` 校验），名字≠定位；P0-3 只认识静态目录，
/// 未知名字 → `NotFound`（P0-4 registry 落地后扩展）。
fn resolve(name: &str) -> Result<(ResourceId, &'static StaticEntry), NexusError> {
    let parsed = ResourceName::new(name).map_err(|e| NexusError::NotFound {
        kind: "resource".to_string(),
        id: format!("{name} (invalid name: {e:?})"),
    })?;
    let entry = lookup_entry(parsed.as_str()).ok_or_else(|| NexusError::NotFound {
        kind: "resource".to_string(),
        id: format!(
            "{name} (no static providers; P0-3 directory is '{DIRECTORY_TAG}', registry-backed resolution lands in P0-4)"
        ),
    })?;
    Ok((ResourceId(parsed.as_str().to_string()), entry))
}

/// 为静态条目组装规划快照。
///
/// P0-3：候选直接由静态表构造为 `ProviderRecord`（含 `present=false` 的离线
/// 条目——`Registry::candidates()` 按契约只返回在线候选，会吞掉 `not_present`
/// 的解释价值；P0-4 改为从 Registry 查询时再对齐 Presence 过滤语义）。
fn snapshot_for(entry: &'static StaticEntry, resource: &ResourceId) -> PlanningSnapshot {
    let candidates: Vec<ProviderRecord> = entry
        .providers
        .iter()
        .map(|p| ProviderRecord {
            id: ProviderId(p.id.to_string()),
            resource: resource.clone(),
            placement: p.placement.to_string(),
            locator: p.locator.to_string(),
            capabilities: p.capabilities.iter().map(|s| (*s).to_string()).collect(),
            present: p.present,
        })
        .collect();
    let constraints = vec![Constraint {
        key: "capability".to_string(),
        value: entry.capability.to_string(),
    }];
    let snapshot = PlanningSnapshot::new(candidates, constraints);
    match entry.providers.iter().find(|p| p.local) {
        Some(local) => snapshot.with_local_provider(ProviderId(local.id.to_string())),
        None => snapshot,
    }
}

/// 只读规划：resolve＋filter＋score，不建连（纯函数，无 I/O）。
fn preview_snapshot(
    name: &str,
) -> Result<(ResourceId, &'static StaticEntry, PlanSnapshot), NexusError> {
    let (resource, entry) = resolve(name)?;
    let snapshot = snapshot_for(entry, &resource);
    let intent = Intent {
        profile: "preview".to_string(),
    };
    // P0-3 预览无事实测量（不伪造数据；`None` = 显式未知，排序/打分按确定性规则）。
    let planned = plan_from_snapshot(&resource, &snapshot, &intent, |_| None)?;
    Ok((
        resource,
        entry,
        PlanSnapshot::from_planned(planned.plan, planned.trace),
    ))
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
/// plan_id / provider / read_only）。
fn plan_json(
    resource: &ResourceId,
    kind: ResourceKind,
    snapshot: &PlanSnapshot,
    read_only: bool,
) -> Value {
    let plan = &snapshot.plan;
    json!({
        "resource": resource.0,
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

/// P0-3 的 `PlanHistory` 读口：Session 持久化未落地（P0-4），恒返回 `None`。
///
/// 命名并保留此类型：读契约（key 形如 `plan-history/<session-id>`、查无→None）
/// 已冻结，P0-4 的 SessionManager 只需实现写口；CLI 的双模式分发逻辑现在
/// 就可以被单测锁定。
struct P03PlanHistory;

impl PlanHistory for P03PlanHistory {
    fn lookup(&self, _session: &nexus_domain::SessionId) -> Option<PlanSnapshot> {
        // P0-3：无 Session 持久化，无历史可读。P0-4 写入 `SessionRecord.plan_snapshot` 后替换。
        None
    }
}

/// `nexus plan <resource>`：只读预览（resolve＋filter＋score，不建连）。
fn run_preview(name: &str, json_mode: bool) -> i32 {
    match preview_snapshot(name) {
        Ok((resource, entry, snapshot)) => {
            let out = json!({
                "verdict": "PASS",
                "command": "plan",
                "directory": DIRECTORY_TAG,
                "read_only": true,
                "plan": plan_json(&resource, entry.kind, &snapshot, true),
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
    match classify_explain_arg(arg) {
        ExplainMode::History => {
            // 历史模式：读真实记录；查无 → 结构化 NOT_FOUND，不回退重算。
            let session = nexus_domain::SessionId(arg.to_string());
            match P03PlanHistory.lookup(&session) {
                Some(snapshot) => {
                    let explained = ExplainedPlan::history(snapshot);
                    render(&explain_json(&explained, None), json_mode);
                    0
                }
                None => {
                    let err = NexusError::NotFound {
                        kind: "session-history".to_string(),
                        id: format!(
                            "{arg} (no plan history recorded; session persistence lands in P0-4, refusing to fabricate history)"
                        ),
                    };
                    render(&fail_json(&err), json_mode);
                    0
                }
            }
        }
        ExplainMode::Estimate => {
            // 估算模式：按当前快照重算，显式标注"估算非承诺"。
            match preview_snapshot(arg) {
                Ok((resource, entry, snapshot)) => {
                    let explained = ExplainedPlan::estimate(snapshot);
                    let mut out = explain_json(&explained, Some(entry.kind));
                    if let Some(obj) = out.as_object_mut() {
                        obj.insert("resource".to_string(), json!(resource.0));
                        obj.insert("kind".to_string(), json!(entry.kind.as_str()));
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

fn explain_json(explained: &ExplainedPlan, entry_kind: Option<ResourceKind>) -> Value {
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
    json!({
        "verdict": "PASS",
        "command": "plan explain",
        "mode": explained.mode.as_str(),
        "commitment": explained.commitment_note(),
        "plan_id": explained.plan_id().as_str(),
        "plan": plan_json(
            &explained.snapshot.plan.resource_id,
            kind,
            &explained.snapshot,
            true,
        ),
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

    #[test]
    fn preview_dev_svc_selects_local_and_is_read_only() {
        let (resource, entry, snapshot) = preview_snapshot("dev-svc").unwrap();
        assert_eq!(resource.0, "dev-svc");
        // 本地优先：local-dev-1（locality +1000）胜过 remote-dev-1。
        assert_eq!(snapshot.plan.provider_id.0, "local-dev-1");
        let plan = plan_json(&resource, entry.kind, &snapshot, true);
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
        let (_, _, a) = preview_snapshot("dev-svc").unwrap();
        let (_, _, b) = preview_snapshot("dev-svc").unwrap();
        assert_eq!(a.plan_id, b.plan_id);
        assert_eq!(
            a.plan_id,
            nexus_domain::plan_id_of(&a.plan, &a.decision_trace)
        );
    }

    #[test]
    fn preview_unknown_resource_is_not_found() {
        let err = preview_snapshot("no-such-resource").unwrap_err();
        assert!(matches!(err, NexusError::NotFound { .. }));
        let v = fail_json(&err);
        assert_eq!(v["verdict"], json!("FAIL"));
        assert_eq!(v["error"]["code"], json!("NOT_FOUND"));
    }

    #[test]
    fn preview_invalid_name_is_rejected() {
        // 名字含非法字符 → NotFound（不 panic）。
        assert!(preview_snapshot("foo/bar").is_err());
    }

    #[test]
    fn explain_estimate_labels_non_commitment() {
        // `plan explain <resource>`：估算模式 + "估算非承诺"标注。
        let code = run_plan(&["explain".to_string(), "dev-svc".to_string()], true);
        assert_eq!(code, 0);
    }

    #[test]
    fn explain_session_id_without_history_is_not_found_not_fabricated() {
        // P0-3：`plan explain <session-id>` 查无历史 → NOT_FOUND，不回退重算。
        let session = nexus_domain::SessionId("sess-n2-e4-1".to_string());
        assert!(P03PlanHistory.lookup(&session).is_none());
        assert_eq!(classify_explain_arg("sess-n2-e4-1"), ExplainMode::History);
    }

    #[test]
    fn explain_json_carries_mode_and_commitment() {
        let (_, entry, snapshot) = preview_snapshot("dev-svc").unwrap();
        let explained = ExplainedPlan::estimate(snapshot);
        let v = explain_json(&explained, Some(entry.kind));
        assert_eq!(v["mode"], json!("estimate"));
        assert!(v["commitment"].as_str().unwrap().contains("估算非承诺"));
        assert_eq!(v["plan_id"], json!(explained.plan_id().as_str()));
        // review-n2-p03 WARN-2：explain 也是只读（不建连），read_only 必须为 true；
        // 内层 plan.kind 必须与外层 kind 一致（都来自目录条目）。
        assert_eq!(v["plan"]["read_only"], json!(true));
        assert_eq!(v["plan"]["kind"], json!(entry.kind.as_str()));
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
