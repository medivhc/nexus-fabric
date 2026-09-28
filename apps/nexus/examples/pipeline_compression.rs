//! E4 产品场景 `product.pipeline-compression` 的可执行驱动（PRODUCT §12.40）。
//!
//! ```text
//! cargo run --quiet -p nexus --example pipeline_compression -- --json
//! ```
//!
//! A/B 两端均启用 gzip 管线：可压缩（重复字节）与不可压缩（高熵）负载经隧道真实
//! gzip 往返后逐字节一致；可压缩负载的 wire 字节显著小于原始（真实压缩）。

#![forbid(unsafe_code)]

use std::process::ExitCode;

use nexus_connectivity::compression::{CompressionAlgorithm, CompressionConfig};
use nexus_connectivity::dataplane_pipeline::DataplanePipelineConfig;
use nexus_connectivity::virtual_subnet::{
    MemoryCarrier, MemoryVpi, TunnelPeer, TunnelState, VirtualSubnetConfig, VirtualSubnetTunnel,
};

/// 高熵不可压缩数据（SplitMix64）。
fn incompressible(n: usize) -> Vec<u8> {
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = || {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    };
    (0..n).map(|_| next() as u8).collect()
}

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
    cfg_a.compression = Some(CompressionConfig::new(CompressionAlgorithm::Gzip, 6, 64).unwrap());
    ta.enable_dataplane_pipeline(cfg_a);
    let mut cfg_b = DataplanePipelineConfig::empty();
    cfg_b.compression = Some(CompressionConfig::new(CompressionAlgorithm::Gzip, 6, 64).unwrap());
    tb.enable_dataplane_pipeline(cfg_b);

    let mut buf = [0u8; 8192];
    let delivered = |_t: &VirtualSubnetTunnel| -> Vec<u8> {
        let mut v = vpi_b_sent.lock().unwrap();
        let p = v.clone();
        v.clear();
        p
    };

    // 可压缩负载（重复字节）。
    let comp = vec![0xAB; 4096];
    let wire_before = ta.pipeline_stats().wire_bytes_sent;
    ta.send_ip_packet("10.0.0.2", &comp).unwrap();
    tb.recv_and_deliver(&mut buf).unwrap();
    let got_comp = delivered(&tb);
    let compressible_roundtrip_ok = got_comp == comp;
    let wire_delta = ta.pipeline_stats().wire_bytes_sent - wire_before;
    // 真实 gzip 把 4096 重复字节压到极小；wire 单元含 ~12 字节头，远小于 4096。
    let compressible_ratio_positive = wire_delta < comp.len() as u64;

    // 不可压缩负载（高熵）。
    let incomp = incompressible(4096);
    ta.send_ip_packet("10.0.0.2", &incomp).unwrap();
    tb.recv_and_deliver(&mut buf).unwrap();
    let got_incomp = delivered(&tb);
    let incompressible_roundtrip_ok = got_incomp == incomp;

    let ok =
        compressible_roundtrip_ok && incompressible_roundtrip_ok && compressible_ratio_positive;
    let out = serde_json::json!({
        "verdict": if ok { "PASS" } else { "FAIL" },
        "command": "pipeline-compression",
        "compressible_roundtrip_ok": compressible_roundtrip_ok,
        "incompressible_roundtrip_ok": incompressible_roundtrip_ok,
        "compressible_ratio_positive": compressible_ratio_positive,
        "algorithm_tag": "gzip",
    });
    println!("{out}");
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}
