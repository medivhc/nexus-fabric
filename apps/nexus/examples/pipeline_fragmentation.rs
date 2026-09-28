//! E4 产品场景 `product.pipeline-fragmentation` 的可执行驱动（PRODUCT §12.41）。
//!
//! ```text
//! cargo run --quiet -p nexus --example pipeline_fragmentation -- --json
//! ```
//!
//! A/B 两端启用分片管线（max_fragment_size=64）：A 发 200 字节载荷，被切成多片经 carrier
//! 逐片送达 B；B 收齐后重组，逐字节完整投递到 VPI。

#![forbid(unsafe_code)]

use std::process::ExitCode;

use nexus_connectivity::dataplane_pipeline::DataplanePipelineConfig;
use nexus_connectivity::fragmentation::FragmentConfig;
use nexus_connectivity::virtual_subnet::{
    MemoryCarrier, MemoryVpi, TunnelPeer, TunnelState, VirtualSubnetConfig, VirtualSubnetTunnel,
};

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
    cfg_a.fragmentation = Some(FragmentConfig::new(64, 65536, 10000).unwrap());
    ta.enable_dataplane_pipeline(cfg_a);
    let mut cfg_b = DataplanePipelineConfig::empty();
    cfg_b.fragmentation = Some(FragmentConfig::new(64, 65536, 10000).unwrap());
    tb.enable_dataplane_pipeline(cfg_b);

    let payload: Vec<u8> = (0..200u8).collect();
    ta.send_ip_packet("10.0.0.2", &payload).unwrap();
    let fragments_sent = ta.pipeline_stats().fragments_sent;

    let mut buf = [0u8; 8192];
    let mut got: Vec<u8> = Vec::new();
    // 逐片喂给 B；前 N-1 片 NeedMore（不投递），最后一片重组投递。
    for _ in 0..fragments_sent.max(10) {
        match tb.recv_and_deliver(&mut buf) {
            Ok(Some((_, n))) => {
                // 重组完成：VPI 应已收到完整载荷。
                let mut v = vpi_b_sent.lock().unwrap();
                got.extend(v.iter().copied());
                v.clear();
                let _ = n;
                break;
            }
            Ok(None) => continue,
            Err(e) => {
                eprintln!("recv: {e}");
                return ExitCode::from(1);
            }
        }
    }
    let reassembled_ok = got == payload;
    let reassembled_len = got.len() as u64;

    let ok = reassembled_ok && reassembled_len == 200 && fragments_sent == 4;
    let out = serde_json::json!({
        "verdict": if ok { "PASS" } else { "FAIL" },
        "command": "pipeline-fragmentation",
        "reassembled_ok": reassembled_ok,
        "reassembled_len": reassembled_len,
        "fragments_sent": fragments_sent,
    });
    println!("{out}");
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}
