//! P4.2 E4 驱动：tunnel 级双向打洞状态机——成功直连 / 失败 Relay 回退。
//!
//! 单进程双 tunnel（MemoryCarrier 回环）离线确定性驱动：
//! - 成功路径：A.begin_hole_punch(B) → B 收 `ph` 自动回 `pa` + 学习来源 → A 收 `pa`
//!   落账 Connected → 数据帧 A→B→A 往返成功（roundtrip）。
//! - 失败路径：C 对无监听 target 打洞 → 尝试耗尽 → HolePunchFailed → 自动
//!   fallback_to_relay（保底）→ 帧经 relay 送达。
//!
//! 真实 UDP 双进程打洞（来源学习/NAT 回程）由 E5 example `udp_peer_holepunch` 覆盖。
//!
//! 退出码 0 = verdict PASS（双路径全绿）；非 0 = FAIL。

#![forbid(unsafe_code)]

use std::process::ExitCode;

use nexus_connectivity::virtual_subnet::{
    MemoryCarrier, MemoryVpi, TunnelPeer, TunnelState, VirtualSubnetConfig, VirtualSubnetEvent,
    VirtualSubnetTunnel,
};

fn events_of(t: &VirtualSubnetTunnel) -> Vec<String> {
    t.events()
        .iter()
        .map(|e| match e {
            VirtualSubnetEvent::HolePunchStarted { .. } => "hole_punch_started".to_string(),
            VirtualSubnetEvent::HolePunchSucceeded { .. } => "hole_punch_succeeded".to_string(),
            VirtualSubnetEvent::HolePunchFailed { .. } => "hole_punch_failed".to_string(),
            VirtualSubnetEvent::PeerLocatorUpdated { .. } => "peer_locator_updated".to_string(),
            VirtualSubnetEvent::RelayFallback { .. } => "relay_fallback".to_string(),
            VirtualSubnetEvent::PeerStateChanged {
                new_state: TunnelState::Connected,
                ..
            } => "peer_connected".to_string(),
            other => format!("{other:?}"),
        })
        .collect()
}

fn main() -> ExitCode {
    // ---------- 成功路径：A ↔ B ----------
    let cfg_a = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.1");
    let cfg_b = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.2");
    let (ca, cb) = MemoryCarrier::connected_pair();
    let vpi_b = MemoryVpi::new();
    let vpi_b_sent = vpi_b.sent_handle();
    let mut ta = VirtualSubnetTunnel::new(cfg_a, Box::new(MemoryVpi::new()), Box::new(ca));
    let mut tb = VirtualSubnetTunnel::new(cfg_b, Box::new(vpi_b), Box::new(cb));
    if let Err(e) = ta.add_peer(TunnelPeer::new("10.0.0.2", "mem-b")) {
        eprintln!("add_peer: {e}");
        return ExitCode::from(2);
    }
    if let Err(e) = tb.add_peer(TunnelPeer::new("10.0.0.1", "mem-a")) {
        eprintln!("add_peer: {e}");
        return ExitCode::from(2);
    }

    let mut success = serde_json::json!({
        "probe_state_seen": "none",
        "state": "Disconnected",
        "locator": "mem-b",
        "roundtrip": false,
    });
    let mut buf = [0u8; 4096];
    if let Err(e) = ta.begin_hole_punch("10.0.0.2", "mem-b") {
        eprintln!("begin_hole_punch: {e}");
        return ExitCode::from(1);
    }
    for _ in 0..20 {
        if ta.peer_state("10.0.0.2") == Some(TunnelState::Probing) {
            success["probe_state_seen"] = serde_json::json!("Probing");
        }
        if let Err(e) = tb.recv_and_deliver(&mut buf, 1000) {
            eprintln!("tb.recv: {e}");
            return ExitCode::from(1);
        }
        if let Err(e) = ta.recv_and_deliver(&mut buf, 1000) {
            eprintln!("ta.recv: {e}");
            return ExitCode::from(1);
        }
        if ta.peer_state("10.0.0.2") == Some(TunnelState::Connected) {
            break;
        }
        if let Err(e) = ta.punch_tick("10.0.0.2") {
            eprintln!("punch_tick: {e}");
            break;
        }
    }
    success["state"] = serde_json::json!(format!(
        "{:?}",
        ta.peer_state("10.0.0.2")
            .unwrap_or(TunnelState::Disconnected)
    ));
    success["locator"] = serde_json::json!(ta.peer_locator("10.0.0.2").unwrap_or_default());

    // 数据帧往返：A → B（写 B 的 VPI）→ B 回帧 → A 收。
    if ta.peer_state("10.0.0.2") == Some(TunnelState::Connected)
        && ta.send_ip_packet("10.0.0.2", b"hole-punch-ok").is_ok()
        && tb.recv_and_deliver(&mut buf, 1000).is_ok()
    {
        let payload = {
            let mut v = vpi_b_sent.lock().unwrap();
            let p = String::from_utf8_lossy(&v).to_string();
            v.clear();
            p
        };
        if payload == "hole-punch-ok"
            && tb.send_ip_packet("10.0.0.1", b"ack").is_ok()
            && ta.recv_and_deliver(&mut buf, 1000).is_ok()
        {
            success["roundtrip"] = serde_json::json!(true);
        }
    }

    // ---------- 失败路径：C 对无监听 target → Relay 回退 ----------
    let cfg_c = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.3");
    let cc = MemoryCarrier::new();
    let mut tc = VirtualSubnetTunnel::new(cfg_c, Box::new(MemoryVpi::new()), Box::new(cc));
    if let Err(e) = tc.add_peer(TunnelPeer::new("10.0.0.4", "dead-target")) {
        eprintln!("add_peer: {e}");
        return ExitCode::from(2);
    }
    tc.set_relay_locator("10.0.0.4", "relay://relay.example.org:443");

    let mut fallback = serde_json::json!({
        "probe_state_seen": "none",
        "state": "Disconnected",
        "locator": "dead-target",
        "sent_via_relay": false,
    });
    if tc.begin_hole_punch("10.0.0.4", "udp://127.0.0.1:9").is_ok() {
        for _ in 0..12 {
            if tc.peer_state("10.0.0.4") == Some(TunnelState::Probing) {
                fallback["probe_state_seen"] = serde_json::json!("Probing");
            }
            match tc.punch_tick("10.0.0.4") {
                Ok(()) => {}
                Err(_) => break,
            }
            if tc.peer_state("10.0.0.4") == Some(TunnelState::Connected) {
                break;
            }
        }
    }
    fallback["state"] = serde_json::json!(format!(
        "{:?}",
        tc.peer_state("10.0.0.4")
            .unwrap_or(TunnelState::Disconnected)
    ));
    fallback["locator"] = serde_json::json!(tc.peer_locator("10.0.0.4").unwrap_or_default());
    if tc.peer_state("10.0.0.4") == Some(TunnelState::Connected)
        && tc.peer_locator("10.0.0.4").as_deref() == Some("relay://relay.example.org:443")
        && tc.send_ip_packet("10.0.0.4", b"via-relay").is_ok()
    {
        fallback["sent_via_relay"] = serde_json::json!(true);
    }

    let success_ok = success["probe_state_seen"] == "Probing"
        && success["state"] == "Connected"
        && success["locator"] == "mem-b"
        && success["roundtrip"] == true;
    let fallback_ok = fallback["probe_state_seen"] == "Probing"
        && fallback["state"] == "Connected"
        && fallback["locator"] == "relay://relay.example.org:443"
        && fallback["sent_via_relay"] == true;

    let out = serde_json::json!({
        "verdict": if success_ok && fallback_ok { "PASS" } else { "FAIL" },
        "command": "virtual subnet holepunch",
        "success": success,
        "fallback": fallback,
        "events": {
            "a": events_of(&ta),
            "c": events_of(&tc),
        },
    });
    println!("{out}");
    if success_ok && fallback_ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}
