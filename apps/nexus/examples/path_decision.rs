//! P4.2 E4 驱动：NAT 类型驱动的路径选择（PRODUCT §12.9.4）。
//!
//! 单进程离线确定性驱动（NAT 类型由调用方注入，真实 STUN 探测为 E5）：
//! - 决策表全类型断言：FullCone/RestrictedCone/PortRestrictedCone → Direct、
//!   Symmetric → Relay、Unknown → Direct（保守打洞）。
//! - `plan_connectivity` 集成三分支：
//!   * RestrictedCone + target → Direct plan（PathDecided 事件，可继续打洞）；
//!   * Symmetric + relay 配置 → Relay plan（不发 ph 打洞帧）；
//!   * Symmetric 无 relay 配置 → Err(RELAY_NOT_CONFIGURED)。
//!
//! 退出码 0 = verdict PASS；非 0 = FAIL。

#![forbid(unsafe_code)]

use std::process::ExitCode;

use nexus_connectivity::nat::{NatType, PathDecision, nat_path_decision};
use nexus_connectivity::virtual_subnet::{
    ConnectivityPlan, MemoryCarrier, MemoryVpi, TunnelPeer, VirtualSubnetConfig,
    VirtualSubnetEvent, VirtualSubnetTunnel,
};

fn events_of(t: &VirtualSubnetTunnel) -> Vec<String> {
    t.events()
        .iter()
        .map(|e| match e {
            VirtualSubnetEvent::PathDecided { .. } => "path_decided".to_string(),
            VirtualSubnetEvent::HolePunchStarted { .. } => "hole_punch_started".to_string(),
            other => format!("{other:?}"),
        })
        .collect()
}

fn main() -> ExitCode {
    // ---------- 1. 决策表全类型 ----------
    let table = serde_json::json!({
        "full_cone": fmt_decision(nat_path_decision(NatType::FullCone)),
        "restricted_cone": fmt_decision(nat_path_decision(NatType::RestrictedCone)),
        "port_restricted": fmt_decision(nat_path_decision(NatType::PortRestrictedCone)),
        "symmetric": fmt_decision(nat_path_decision(NatType::Symmetric)),
        "unknown": fmt_decision(nat_path_decision(NatType::Unknown)),
    });

    // ---------- 2. Direct plan：RestrictedCone → 继续打洞 ----------
    let cfg_a = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.1");
    let (ca, cb) = MemoryCarrier::connected_pair();
    let mut ta = VirtualSubnetTunnel::new(cfg_a, Box::new(MemoryVpi::new()), Box::new(ca));
    let mut tb = VirtualSubnetTunnel::new(
        VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.2"),
        Box::new(MemoryVpi::new()),
        Box::new(cb),
    );
    ta.add_peer(TunnelPeer::new("10.0.0.2", "mem-b")).unwrap();
    tb.add_peer(TunnelPeer::new("10.0.0.1", "mem-a")).unwrap();

    let mut plan_direct = serde_json::json!({
        "kind": "none", "target": "", "path_decided": false,
    });
    if let Ok(ConnectivityPlan::Direct { target }) =
        ta.plan_connectivity("10.0.0.2", NatType::RestrictedCone, "mem-b")
    {
        plan_direct["kind"] = serde_json::json!("Direct");
        plan_direct["target"] = serde_json::json!(target);
        plan_direct["path_decided"] = serde_json::json!(
            ta.events()
                .iter()
                .any(|e| matches!(e, VirtualSubnetEvent::PathDecided { .. }))
        );
        // Direct plan 后打洞流程可继续（begin_hole_punch 成功发起）
        if ta.begin_hole_punch("10.0.0.2", &target).is_ok() {
            let mut buf = [0u8; 4096];
            for _ in 0..10 {
                tb.recv_and_deliver(&mut buf, 1000).unwrap();
                ta.recv_and_deliver(&mut buf, 1000).unwrap();
                if ta.peer_state("10.0.0.2").is_some_and(|s| {
                    s == nexus_connectivity::virtual_subnet::TunnelState::Connected
                }) {
                    plan_direct["punched"] = serde_json::json!(true);
                    break;
                }
                if ta.punch_tick("10.0.0.2").is_err() {
                    break;
                }
            }
        }
    }

    // ---------- 3. Relay plan：Symmetric + relay 配置 → 不发打洞帧 ----------
    let cfg_c = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.3");
    let cc = MemoryCarrier::new();
    let mut tc = VirtualSubnetTunnel::new(cfg_c, Box::new(MemoryVpi::new()), Box::new(cc));
    tc.add_peer(TunnelPeer::new("10.0.0.4", "dead-target"))
        .unwrap();
    tc.set_relay_locator("10.0.0.4", "relay://relay.example.org:443");

    let mut plan_relay = serde_json::json!({
        "kind": "none", "locator": "", "path_decided": false, "no_punch_frames": false,
    });
    if let Ok(ConnectivityPlan::Relay { locator }) =
        tc.plan_connectivity("10.0.0.4", NatType::Symmetric, "udp://127.0.0.1:9")
    {
        plan_relay["kind"] = serde_json::json!("Relay");
        plan_relay["locator"] = serde_json::json!(locator);
        plan_relay["path_decided"] = serde_json::json!(
            tc.events()
                .iter()
                .any(|e| matches!(e, VirtualSubnetEvent::PathDecided { .. }))
        );
        // Symmetric 直达 relay：不发起打洞（无 HolePunchStarted 事件）
        plan_relay["no_punch_frames"] = serde_json::json!(
            !tc.events()
                .iter()
                .any(|e| { matches!(e, VirtualSubnetEvent::HolePunchStarted { .. }) })
        );
    }

    // ---------- 4. Symmetric 无 relay → Err(RELAY_NOT_CONFIGURED) ----------
    let cfg_e = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.5");
    let ce = MemoryCarrier::new();
    let mut te = VirtualSubnetTunnel::new(cfg_e, Box::new(MemoryVpi::new()), Box::new(ce));
    te.add_peer(TunnelPeer::new("10.0.0.6", "dead2")).unwrap();
    let no_relay_err =
        match te.plan_connectivity("10.0.0.6", NatType::Symmetric, "udp://127.0.0.1:9") {
            Err(e) => e.to_string(),
            Ok(_) => "no-error".to_string(),
        };
    let plan_no_relay = serde_json::json!({
        "err_contains": if no_relay_err.contains("RELAY_NOT_CONFIGURED") {
            "RELAY_NOT_CONFIGURED"
        } else {
            "NO_MATCH"
        },
    });

    // ---------- 判定 ----------
    let table_ok = table["full_cone"] == "Direct"
        && table["restricted_cone"] == "Direct"
        && table["port_restricted"] == "Direct"
        && table["symmetric"] == "Relay"
        && table["unknown"] == "Direct";
    let direct_ok = plan_direct["kind"] == "Direct"
        && plan_direct["target"] == "mem-b"
        && plan_direct["path_decided"] == true
        && plan_direct["punched"] == true;
    let relay_ok = plan_relay["kind"] == "Relay"
        && plan_relay["locator"] == "relay://relay.example.org:443"
        && plan_relay["path_decided"] == true
        && plan_relay["no_punch_frames"] == true;
    let no_relay_ok = plan_no_relay["err_contains"] == "RELAY_NOT_CONFIGURED";

    let out = serde_json::json!({
        "verdict": if table_ok && direct_ok && relay_ok && no_relay_ok { "PASS" } else { "FAIL" },
        "command": "nat path decision",
        "decision_table": table,
        "plan": {
            "direct": plan_direct,
            "relay": plan_relay,
            "no_relay": plan_no_relay,
        },
        "events": { "a": events_of(&ta), "c": events_of(&tc) },
    });
    println!("{out}");
    if table_ok && direct_ok && relay_ok && no_relay_ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

#[must_use]
fn fmt_decision(d: PathDecision) -> String {
    match d {
        PathDecision::Direct => "Direct".to_string(),
        PathDecision::Relay => "Relay".to_string(),
    }
}
