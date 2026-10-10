//! P4.2 E4 驱动：多候选并发打洞（PRODUCT §12.9.5）。
//!
//! 单进程离线确定性驱动：
//! - success 分支：A 对 B targets=["udp://127.0.0.1:9", "mem-b"]——
//!   B 按最后一个来源回 pa，A 落账 Connected，HolePunchSucceeded{target="mem-b"}
//!   （正确候选胜出，先到先用；MemoryCarrier 转发模型下错误候选无回包）。
//! - fallback 分支：C 对 D targets=[两个 dead] + relay 配置——
//!   punch_tick 耗尽 → HolePunchFailed 事件 + RelayFallback → Connected。
//!
//! 退出码 0 = verdict PASS；非 0 = FAIL。

#![forbid(unsafe_code)]

use std::process::ExitCode;

use nexus_connectivity::virtual_subnet::{
    MemoryCarrier, MemoryVpi, TunnelPeer, TunnelState, VirtualSubnetConfig, VirtualSubnetEvent,
    VirtualSubnetTunnel,
};

fn main() -> ExitCode {
    // ---------- 1. 多候选成功（先到先用） ----------
    let (ca, cb) = MemoryCarrier::connected_pair();
    // 模拟 NAT 会话回程：A 发 ph 到 mem-b 时，B 观测来源为 mem-b（可达候选），
    // 回 pa 到 mem-b；A 收 pa 时来源同样为 mem-b → 落账 target=mem-b。
    ca.set_last_source("mem-b");
    cb.set_last_source("mem-b");
    let mut ta = VirtualSubnetTunnel::new(
        VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.1"),
        Box::new(MemoryVpi::new()),
        Box::new(ca),
    );
    let mut tb = VirtualSubnetTunnel::new(
        VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.2"),
        Box::new(MemoryVpi::new()),
        Box::new(cb),
    );
    ta.add_peer(TunnelPeer::new("10.0.0.2", "mem-b")).unwrap();
    tb.add_peer(TunnelPeer::new("10.0.0.1", "mem-a")).unwrap();

    ta.begin_hole_punch_multi(
        "10.0.0.2",
        &["udp://127.0.0.1:9".to_string(), "mem-b".to_string()],
    )
    .unwrap();
    let mut buf = [0u8; 4096];
    for _ in 0..10 {
        tb.recv_and_deliver(&mut buf).unwrap();
        ta.recv_and_deliver(&mut buf).unwrap();
        if ta.peer_state("10.0.0.2") == Some(TunnelState::Connected) {
            break;
        }
        ta.punch_tick("10.0.0.2").unwrap();
    }
    let success_target = ta
        .events()
        .iter()
        .find_map(|e| match e {
            VirtualSubnetEvent::HolePunchSucceeded {
                peer_vip, target, ..
            } if peer_vip == "10.0.0.2" => Some(target.clone()),
            _ => None,
        })
        .unwrap_or_default();
    let success = serde_json::json!({
        "state": fmt_state(ta.peer_state("10.0.0.2")),
        "target": success_target,
        "hole_punch_succeeded": success_target == "mem-b",
    });

    // ---------- 2. 全候选耗尽 → relay 回退 ----------
    let cc = MemoryCarrier::new();
    let mut tc = VirtualSubnetTunnel::new(
        VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.3"),
        Box::new(MemoryVpi::new()),
        Box::new(cc),
    );
    tc.add_peer(TunnelPeer::new("10.0.0.4", "dead-target"))
        .unwrap();
    tc.set_relay_locator("10.0.0.4", "relay://relay.example.org:443");
    tc.begin_hole_punch_multi(
        "10.0.0.4",
        &[
            "udp://127.0.0.1:9001".to_string(),
            "udp://127.0.0.1:9002".to_string(),
        ],
    )
    .unwrap();

    let mut hole_punch_failed = false;
    let mut relay_fallback = false;
    for _ in 0..=10 {
        match tc.punch_tick("10.0.0.4") {
            Ok(()) => {
                if tc.peer_state("10.0.0.4") == Some(TunnelState::Connected) {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    for e in tc.events() {
        match e {
            VirtualSubnetEvent::HolePunchFailed { .. } => hole_punch_failed = true,
            VirtualSubnetEvent::RelayFallback { .. } => relay_fallback = true,
            _ => {}
        }
    }
    let fallback = serde_json::json!({
        "state": fmt_state(tc.peer_state("10.0.0.4")),
        "relay_fallback": relay_fallback,
        "hole_punch_failed": hole_punch_failed,
    });

    // ---------- 判定 ----------
    let success_ok = success["state"] == "Connected"
        && success["target"] == "mem-b"
        && success["hole_punch_succeeded"] == true;
    let fallback_ok = fallback["state"] == "Connected"
        && fallback["relay_fallback"] == true
        && fallback["hole_punch_failed"] == true;

    let out = serde_json::json!({
        "verdict": if success_ok && fallback_ok { "PASS" } else { "FAIL" },
        "command": "hole punch multi",
        "success": success,
        "fallback": fallback,
    });
    println!("{out}");
    if success_ok && fallback_ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn fmt_state(s: Option<TunnelState>) -> String {
    match s {
        Some(TunnelState::Connected) => "Connected".to_string(),
        Some(TunnelState::Probing) => "Probing".to_string(),
        Some(TunnelState::Disconnected) => "Disconnected".to_string(),
        Some(TunnelState::Handshaking) => "Handshaking".to_string(),
        Some(TunnelState::Failed) => "Failed".to_string(),
        None => "None".to_string(),
    }
}
