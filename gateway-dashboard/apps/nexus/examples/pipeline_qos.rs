//! E4 产品场景 `product.pipeline-qos` 的可执行驱动（PRODUCT §12.41）。
//!
//! ```text
//! cargo run --quiet -p nexus --example pipeline_qos -- --json
//! ```
//!
//! A 端启用 QoS 令牌桶（egress 1000 B/s，burst 1000），注入逻辑时钟确定性推进：
//! t=0 首包 1000 字节放行；再发 200 字节因令牌耗尽被丢弃；推进到 t=1s 后补满再发 500 字节放行。

#![forbid(unsafe_code)]

use std::process::ExitCode;
use std::time::Duration;

use nexus_connectivity::dataplane_pipeline::DataplanePipelineConfig;
use nexus_connectivity::qos::{BandwidthLimit, QosConfig};
use nexus_connectivity::virtual_subnet::{
    MemoryCarrier, MemoryVpi, TunnelPeer, TunnelState, VirtualSubnetConfig, VirtualSubnetTunnel,
};

/// tunnel frame 头 "10.0.0.1->10.0.0.2:" 长度（QoS 按 inner 字节计，需扣除）。
const HEADER: usize = 19;

fn main() -> ExitCode {
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

    let mut cfg_a = DataplanePipelineConfig::empty();
    cfg_a.qos = Some(QosConfig::new(
        None,
        Some(BandwidthLimit::new(1000, 1000).unwrap()),
    ));
    ta.enable_dataplane_pipeline(cfg_a);
    tb.enable_dataplane_pipeline(DataplanePipelineConfig::empty());

    let mut buf = [0u8; 4096];
    let drained = || -> bool {
        let mut v = vpi_b_sent.lock().unwrap();
        let has = !v.is_empty();
        v.clear();
        has
    };

    // t=0：首包 inner=1000（payload 978），满桶放行。
    ta.set_dataplane_clock(Duration::ZERO);
    ta.send_ip_packet("10.0.0.2", &[0x11; 1000 - HEADER])
        .unwrap();
    let first_send_allowed = tb.recv_and_deliver(&mut buf).is_ok() && drained();

    // t=0：再发 inner=200（payload 178），令牌耗尽 -> 丢弃，B 收不到。
    ta.send_ip_packet("10.0.0.2", &[0x22; 200 - HEADER])
        .unwrap();
    let overflow_send_dropped = tb.recv_and_deliver(&mut buf).unwrap().is_none() && !drained();

    // t=1s：补满 1000 令牌，再发 inner=500（payload 478）放行。
    ta.set_dataplane_clock(Duration::from_secs(1));
    ta.send_ip_packet("10.0.0.2", &[0x33; 500 - HEADER])
        .unwrap();
    let after_refill_allowed = tb.recv_and_deliver(&mut buf).is_ok() && drained();

    let qos_dropped_bytes = ta.pipeline_stats().qos_dropped;

    let ok = first_send_allowed
        && overflow_send_dropped
        && after_refill_allowed
        && qos_dropped_bytes == 200;
    let out = serde_json::json!({
        "verdict": if ok { "PASS" } else { "FAIL" },
        "command": "pipeline-qos",
        "first_send_allowed": first_send_allowed,
        "overflow_send_dropped": overflow_send_dropped,
        "after_refill_allowed": after_refill_allowed,
        "qos_dropped_bytes": qos_dropped_bytes,
    });
    println!("{out}");
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}
