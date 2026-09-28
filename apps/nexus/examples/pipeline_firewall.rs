//! E4 产品场景 `product.pipeline-firewall` 的可执行驱动（PRODUCT §12.40）。
//!
//! 由 `scenarios/product/pipeline_firewall.toml` 的 [when].command 调用：
//!
//! ```text
//! cargo run --quiet -p nexus --example pipeline_firewall -- --json
//! ```
//!
//! 单进程双 tunnel（MemoryCarrier 回环）：A 端启用数据面管线（firewall），B 端启用空管线
//! 做 NXP1 解封装。A 发 udp/53 流被 deny 丢弃；发 tcp/80 流放行并投递到 B 的 VPI。

#![forbid(unsafe_code)]

use std::process::ExitCode;

use nexus_connectivity::dataplane_pipeline::DataplanePipelineConfig;
use nexus_connectivity::firewall::{
    FirewallAction, FirewallConfig, FirewallEngine, FirewallRule, PortRange, Protocol,
};
use nexus_connectivity::virtual_subnet::{
    MemoryCarrier, MemoryVpi, TunnelPeer, TunnelState, VirtualSubnetConfig, VirtualSubnetTunnel,
};

fn main() -> ExitCode {
    // A=10.0.0.1, B=10.0.0.2
    let (ca, cb) = MemoryCarrier::connected_pair();
    let vpi_b = MemoryVpi::new();
    let vpi_b_sent = vpi_b.sent_handle();
    let mut ta = VirtualSubnetTunnel::new(
        VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.1"),
        Box::new(MemoryVpi::new()),
        Box::new(ca),
    );
    let mut tb = VirtualSubnetTunnel::new(
        VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.2"),
        Box::new(vpi_b),
        Box::new(cb),
    );
    ta.add_peer(TunnelPeer::new("10.0.0.2", "mem-b")).unwrap();
    tb.add_peer(TunnelPeer::new("10.0.0.1", "mem-a")).unwrap();
    ta.set_peer_state("10.0.0.2", TunnelState::Connected);
    tb.set_peer_state("10.0.0.1", TunnelState::Connected);

    // A 端管线：默认 allow，一条 deny udp/53。
    let rule = FirewallRule::new(
        FirewallAction::Deny,
        None::<String>,
        None::<String>,
        None,
        Some(PortRange::new(53, 53).unwrap()),
        Some(Protocol::Udp),
    )
    .unwrap();
    let fw = FirewallEngine::new(&FirewallConfig::new(FirewallAction::Allow, vec![rule]).unwrap())
        .unwrap();
    let mut cfg_a = DataplanePipelineConfig::empty();
    cfg_a.firewall = Some(fw);
    ta.enable_dataplane_pipeline(cfg_a);
    // B 端空管线（仅 NXP1 解封装，无门控）。
    tb.enable_dataplane_pipeline(DataplanePipelineConfig::empty());

    let mut buf = [0u8; 4096];

    // 1) udp/53 流 -> 命中 deny -> 丢弃，不触碰 carrier。
    ta.set_dataplane_defaults(Protocol::Udp, 0, 53);
    let _ = ta.send_ip_packet("10.0.0.2", &[0xAA; 100]);
    // B 不应收到任何东西。
    let denied_flow_dropped = tb.recv_and_deliver(&mut buf).unwrap().is_none();

    // 2) tcp/80 流 -> 默认 allow -> 投递到 B 的 VPI（100 字节载荷）。
    ta.set_dataplane_defaults(Protocol::Tcp, 0, 80);
    ta.send_ip_packet("10.0.0.2", &[0xBB; 100]).unwrap();
    tb.recv_and_deliver(&mut buf).unwrap();
    let delivered: Vec<u8> = {
        let mut v = vpi_b_sent.lock().unwrap();
        let p = v.clone();
        v.clear();
        p
    };
    let allowed_flow_delivered = delivered == vec![0xBB; 100];
    let b_received_bytes = delivered.len() as u64;

    let fw_dropped = ta.pipeline_stats().firewall_dropped;

    let ok =
        denied_flow_dropped && allowed_flow_delivered && b_received_bytes == 100 && fw_dropped == 1;
    let out = serde_json::json!({
        "verdict": if ok { "PASS" } else { "FAIL" },
        "command": "pipeline-firewall",
        "denied_flow_dropped": denied_flow_dropped,
        "allowed_flow_delivered": allowed_flow_delivered,
        "b_received_bytes": b_received_bytes,
        "firewall_dropped": fw_dropped,
    });
    println!("{out}");
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}
