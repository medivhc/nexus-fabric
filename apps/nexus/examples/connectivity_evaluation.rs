//! Connectivity Evaluation E4 driver（v9 §8.1）。
//!
//! 纯函数评估 + Planner 接入的端到端演示：构造 5 组输入，输出 JSON 供
//! `scenarios/product/connectivity_evaluation.toml` 断言。
//! 内部断言与 toml 期望一一对应；任一不符则 verdict=FAIL。

use std::net::SocketAddr;

use nexus_connectivity::evaluation::{
    evaluate_connectivity, EvaluationInput, PlatformNetworkCapability,
};
use nexus_connectivity::nat::NatType;
use nexus_domain::{ConnectivityEvaluation, Constraint, Intent, ProviderId, ResourceId};
use nexus_measurement::LinkMeasurement;
use nexus_planner::{connectivity_gate, plan_from_snapshot, PlanningSnapshot};
use nexus_registry::ProviderRecord;
use serde_json::{json, Map, Value};

fn locator() -> SocketAddr {
    "203.0.113.7:54321".parse().unwrap()
}

fn platform() -> PlatformNetworkCapability {
    PlatformNetworkCapability {
        udp_supported: true,
        ipv6_supported: false,
    }
}

fn measured_rtt(ms: u32) -> LinkMeasurement {
    LinkMeasurement {
        rtt_ms: Some(ms),
        loss_permyriad: Some(0),
        jitter_ms: None,
        throughput_kbps: None,
        confidence_percent: 90,
    }
}

fn input(
    local: NatType,
    remote: NatType,
    history_permyriad: Option<u32>,
    recent: Option<LinkMeasurement>,
    relay: bool,
    existing: bool,
) -> EvaluationInput {
    EvaluationInput {
        known_locators: vec![locator()],
        local_nat: local,
        remote_nat: remote,
        punch_success_permyriad: history_permyriad,
        recent,
        relay_available: relay,
        existing_link: existing,
        platform: platform(),
    }
}

fn resource() -> ResourceId {
    ResourceId("internet-access".into())
}

fn intent() -> Intent {
    Intent {
        profile: "Balanced".into(),
    }
}

fn candidate(id: &str) -> ProviderRecord {
    ProviderRecord {
        id: ProviderId(id.into()),
        resource: resource(),
        placement: "test".into(),
        locator: format!("loc-{id}"),
        capabilities: vec!["internet-access".into()],
        present: true,
    }
}

/// Planner 接入检查：返回 gate 原因 label（"none" = 未拒绝）。
/// 同时断言 gate 与 plan_from_snapshot 一致，且 trace 携带了评估。
fn planner_rejected(id: &str, eval: &ConnectivityEvaluation, ok: &mut bool) -> String {
    let constraints = vec![Constraint {
        key: "capability".into(),
        value: "internet-access".into(),
    }];
    let pid = ProviderId(id.into());
    let snapshot = PlanningSnapshot::new(vec![candidate(id)], constraints)
        .with_connectivity(vec![(pid.clone(), eval.clone())]);

    let gate_reason: Option<String> = connectivity_gate(&snapshot)
        .into_iter()
        .find(|(p, _)| *p == pid)
        .map(|(_, r)| r.label().to_string());

    let planned = plan_from_snapshot(&resource(), &snapshot, &intent(), |_| None);

    // 门控与规划结果必须一致：被 gate 拒绝 ⇔ plan 失败；未被拒 ⇔ plan 成功。
    let consistent = match (&gate_reason, &planned) {
        (Some(_), Err(_)) | (None, Ok(_)) => true,
        _ => false,
    };
    if !consistent {
        *ok = false;
    }

    // trace 必须携带该候选的评估（DecisionTrace 可见 evaluation 贡献）。
    if let Ok(planned) = &planned {
        let traced = planned.trace.considered.iter().find(|c| c.provider == pid);
        if traced.is_none_or(|c| c.connectivity.as_ref() != Some(eval)) {
            *ok = false;
        }
    }

    gate_reason.unwrap_or_else(|| "none".to_string())
}

fn case(
    name: &str,
    eval: &ConnectivityEvaluation,
    planner_label: String,
    extra: Map<String, Value>,
    ok: &mut bool,
) -> (String, Value) {
    // 确定性：同等输入必然产出同等输出（纯函数要求）。
    let mut obj = Map::new();
    obj.insert(
        "has_feasible_path".into(),
        Value::Bool(eval.has_feasible_path()),
    );
    obj.insert("direct_likely".into(), Value::Bool(eval.direct_likely));
    obj.insert(
        "punching_likely".into(),
        Value::Bool(eval.punching_likely),
    );
    obj.insert(
        "relay_available".into(),
        Value::Bool(eval.relay_available),
    );
    obj.insert(
        "confidence_percent".into(),
        Value::from(eval.confidence_percent),
    );
    if let Some(cost) = eval.estimated_setup_cost_ms {
        obj.insert("estimated_setup_cost_ms".into(), Value::from(cost));
    }
    obj.insert("planner_rejected".into(), Value::String(planner_label));
    for (k, v) in extra {
        obj.insert(k, v);
    }
    let _ = ok;
    (name.to_string(), Value::Object(obj))
}

fn main() {
    let mut ok = true;
    let mut cases = Map::new();

    // Case 1: cone–cone → 打洞可能，Planner 保留。
    let ev = evaluate_connectivity(&input(
        NatType::RestrictedCone,
        NatType::PortRestrictedCone,
        Some(8_500),
        Some(measured_rtt(42)),
        false,
        false,
    ));
    let ev2 = evaluate_connectivity(&input(
        NatType::RestrictedCone,
        NatType::PortRestrictedCone,
        Some(8_500),
        Some(measured_rtt(42)),
        false,
        false,
    ));
    if ev != ev2 {
        ok = false;
    }
    if !ev.punching_likely || ev.direct_likely {
        ok = false;
    }
    let label = planner_rejected("cone-cone", &ev, &mut ok);
    if label != "none" {
        ok = false;
    }
    let (k, v) = case("cone_cone", &ev, label, Map::new(), &mut ok);
    cases.insert(k, v);

    // Case 2: symmetric–symmetric 且无中继 → 无可行路径，Planner 拒绝。
    let ev = evaluate_connectivity(&input(
        NatType::Symmetric,
        NatType::Symmetric,
        None,
        None,
        false,
        false,
    ));
    if ev.has_feasible_path() {
        ok = false;
    }
    let label = planner_rejected("symsym-norelay", &ev, &mut ok);
    if label != "no_feasible_connectivity_path" {
        ok = false;
    }
    let (k, v) = case("symmetric_symmetric_no_relay", &ev, label, Map::new(), &mut ok);
    cases.insert(k, v);

    // Case 3: symmetric–symmetric 但有中继 → relay 可用，Planner 保留。
    let ev = evaluate_connectivity(&input(
        NatType::Symmetric,
        NatType::Symmetric,
        None,
        None,
        true,
        false,
    ));
    if !ev.relay_available || !ev.has_feasible_path() {
        ok = false;
    }
    let label = planner_rejected("symsym-relay", &ev, &mut ok);
    if label != "none" {
        ok = false;
    }
    let (k, v) = case(
        "symmetric_symmetric_with_relay",
        &ev,
        label,
        Map::new(),
        &mut ok,
    );
    cases.insert(k, v);

    // Case 4: 双端未知 → 保守不判打洞可能，置信度 30。
    let ev = evaluate_connectivity(&input(
        NatType::Unknown,
        NatType::Unknown,
        None,
        None,
        false,
        false,
    ));
    if ev.punching_likely || ev.confidence_percent != 30 {
        ok = false;
    }
    let label = planner_rejected("unknown", &ev, &mut ok);
    let (k, v) = case("unknown_nat", &ev, label, Map::new(), &mut ok);
    cases.insert(k, v);

    // Case 5: 本端 FullCone → 直连可能；建连成本取实测 RTT。
    let ev = evaluate_connectivity(&input(
        NatType::FullCone,
        NatType::RestrictedCone,
        Some(9_000),
        Some(measured_rtt(42)),
        false,
        false,
    ));
    if !ev.direct_likely || ev.estimated_setup_cost_ms != Some(42) {
        ok = false;
    }
    let label = planner_rejected("fullcone", &ev, &mut ok);
    if label != "none" {
        ok = false;
    }
    let (k, v) = case("fullcone_direct", &ev, label, Map::new(), &mut ok);
    cases.insert(k, v);

    println!(
        "{}",
        json!({
            "verdict": if ok { "PASS" } else { "FAIL" },
            "cases": cases,
        })
    );
    if !ok {
        std::process::exit(1);
    }
}
