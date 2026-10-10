//! E4 产品场景 `product.performance-benchmark` 的可执行驱动（PRODUCT §12.36）。
//!
//! 由 `scenarios/product/performance_benchmark.toml` 的 [when].command 调用：
//!
//! ```text
//! cargo run --quiet -p nexus --example perf_bench -- --json
//! ```
//!
//! 测量（进程内闭环，无真实网络）：
//! - `aead.frame_roundtrip_us`：encrypt_frame+decrypt_frame 单帧往返延迟（µs）
//! - `aead.throughput_mbps`：批量加密吞吐（MB/s，1 KiB payload × N 帧）
//! - `tunnel.throughput_mbps`：VirtualSubnetTunnel 加密模式 UDP 回环端到端吞吐
//! - `tunnel.roundtrip_us`：端到端单帧往返延迟
//!
//! Performance Budget（PRODUCT §12.36）：baseline 首测定格写入
//! `--baseline <path>`（默认 `.evidence/bench-p3c04/baseline.json`）；
//! 后续运行与 baseline 比较（noise ±30% / warning 0.5× 或 2× / blocking
//! 0.2× 或 5×），并设绝对下限防灾难退化。verdict 由预算表计算，不锁绝对值。

#![forbid(unsafe_code)]

use nexus_connectivity::encryption::{EncryptionConfig, SessionKey, decrypt_frame, encrypt_frame};
use nexus_connectivity::virtual_subnet::{
    MemoryVpi, TunnelPeer, VirtualSubnetConfig, VirtualSubnetTunnel,
};
use nexus_platform::{PacketCarrier, UdpCarrier};
use serde_json::{Value, json};
use std::path::Path;
use std::time::Instant;

const PAYLOAD_BYTES: usize = 1024;
const FRAMES: u64 = 2000;
const WARMUP: u64 = 200;

/// 绝对下限（防灾难退化；正常性能远高于此，CI 噪声不会误触）。
const ABS_MIN_AEAD_MBPS: f64 = 1.0;
const ABS_MIN_TUNNEL_MBPS: f64 = 0.5;
const ABS_MAX_ROUNDTRIP_US: f64 = 10_000.0;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let json_mode = args.iter().any(|a| a == "--json");
    let baseline_path = args
        .iter()
        .position(|a| a == "--baseline")
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_else(|| ".evidence/bench-p3c04/baseline.json".to_string());

    // ---- 1) AEAD 帧路径（固定 SessionKey，排除握手噪声） ----
    let skey = SessionKey::from_bytes(&[0x42; 32]).expect("fixed session key");
    let payload = vec![b'A'; PAYLOAD_BYTES];
    for i in 0..WARMUP {
        let f = encrypt_frame(&skey, i, &payload).expect("warmup encrypt");
        let _ = decrypt_frame(&skey, &f).expect("warmup decrypt");
    }
    let t0 = Instant::now();
    for i in 0..FRAMES {
        let f = encrypt_frame(&skey, i, &payload).expect("encrypt");
        let _ = decrypt_frame(&skey, &f).expect("decrypt");
    }
    let aead_roundtrip_us = t0.elapsed().as_secs_f64() * 1e6 / FRAMES as f64;

    let t0 = Instant::now();
    let mut enc_bytes = 0usize;
    for i in 0..FRAMES {
        let f = encrypt_frame(&skey, i, &payload).expect("encrypt");
        enc_bytes += f.len();
    }
    let aead_mbps = enc_bytes as f64 / t0.elapsed().as_secs_f64() / 1e6;

    // ---- 2) 隧道数据面（UDP 回环 + 加密 + 握手） ----
    let mut carrier_a = UdpCarrier::new();
    carrier_a.bind("udp://127.0.0.1:52001").expect("bind a");
    let mut carrier_b = UdpCarrier::new();
    carrier_b.bind("udp://127.0.0.1:52002").expect("bind b");

    let mut tunnel_a = VirtualSubnetTunnel::new(
        VirtualSubnetConfig::new("10.99.0.0/24", "10.99.0.1"),
        Box::new(MemoryVpi::new()),
        Box::new(carrier_a),
    );
    let mut tunnel_b = VirtualSubnetTunnel::new(
        VirtualSubnetConfig::new("10.99.0.0/24", "10.99.0.2"),
        Box::new(MemoryVpi::new()),
        Box::new(carrier_b),
    );
    tunnel_a
        .add_peer(TunnelPeer::new("10.99.0.2", "udp://127.0.0.1:52002"))
        .expect("peer a->b");
    tunnel_b
        .add_peer(TunnelPeer::new("10.99.0.1", "udp://127.0.0.1:52001"))
        .expect("peer b->a");
    tunnel_a.enable_encryption(EncryptionConfig::default());
    tunnel_b.enable_encryption(EncryptionConfig::default());

    // 进程内驱动握手：A 发起 → B 自动 accept → A 自动 complete
    tunnel_a.begin_handshake("10.99.0.2").expect("begin hs");
    let mut buf = [0u8; 2048];
    tunnel_b.recv_and_deliver(&mut buf, 1000).expect("b accept");
    tunnel_a
        .recv_and_deliver(&mut buf, 1000)
        .expect("a complete");
    let tunnel_ready = tunnel_a.peer_state("10.99.0.2")
        == Some(nexus_connectivity::virtual_subnet::TunnelState::Connected)
        && tunnel_b.peer_state("10.99.0.1")
            == Some(nexus_connectivity::virtual_subnet::TunnelState::Connected);

    // 端到端吞吐（A 加密发送 → B 解密投递）
    let t0 = Instant::now();
    let mut rx_bytes = 0usize;
    for _ in 0..FRAMES {
        tunnel_a
            .send_ip_packet("10.99.0.2", &payload)
            .expect("send");
        if let Some((_, n)) = tunnel_b.recv_and_deliver(&mut buf, 1000).expect("recv") {
            rx_bytes += n;
        }
    }
    let tunnel_mbps = rx_bytes as f64 / t0.elapsed().as_secs_f64() / 1e6;

    // 端到端单帧往返延迟（send + recv 一次）
    let t0 = Instant::now();
    tunnel_a
        .send_ip_packet("10.99.0.2", &payload)
        .expect("send rtt");
    let _ = tunnel_b.recv_and_deliver(&mut buf, 1000).expect("recv rtt");
    let tunnel_roundtrip_us = t0.elapsed().as_secs_f64() * 1e6;

    // ---- 3) Performance Budget 判定 ----
    let metrics = json!({
        "aead": {
            "frame_roundtrip_us": round2(aead_roundtrip_us),
            "throughput_mbps": round2(aead_mbps),
        },
        "tunnel": {
            "throughput_mbps": round2(tunnel_mbps),
            "roundtrip_us": round2(tunnel_roundtrip_us),
        },
        "params": { "payload_bytes": PAYLOAD_BYTES, "frames": FRAMES },
        "environment": {
            "target_triple": std::env::consts::ARCH.to_string() + "-" + std::env::consts::OS,
            "baseline_path": baseline_path,
        },
    });

    let baseline_file = Path::new(&baseline_path);
    let verdict = if let Ok(existing) = std::fs::read_to_string(baseline_file) {
        match serde_json::from_str::<Value>(&existing) {
            Ok(base) => evaluate_against_baseline(&metrics, &base),
            Err(_) => Value::String("FAIL".into()),
        }
    } else {
        // 首测：固化为 baseline（后续回归按同指纹比较）
        if let Some(parent) = baseline_file.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(
            baseline_file,
            serde_json::to_string_pretty(&metrics).unwrap(),
        );
        json!({
            "verdict": "PASS",
            "note": "baseline established",
        })
    };

    let mut out = json!({
        "verdict": verdict.get("verdict").and_then(|v| v.as_str()).unwrap_or("FAIL"),
        "aead": metrics["aead"].clone(),
        "tunnel": metrics["tunnel"].clone(),
        "params": metrics["params"].clone(),
        "tunnel_ready": tunnel_ready,
        "budget": verdict,
    });
    out["tunnel_ready"] = json!(tunnel_ready);
    if json_mode {
        println!("{out}");
    } else {
        println!("perf benchmark: {out}");
    }
}

/// 与 baseline 比较（noise ±30% / warning 0.5× 或 2× / blocking 0.2× 或 5×），
/// 外加绝对下限防灾难退化。
fn evaluate_against_baseline(cur: &Value, base: &Value) -> Value {
    let cur_aead_mbps = num(cur, &["aead", "throughput_mbps"]);
    let base_aead_mbps = num(base, &["aead", "throughput_mbps"]);
    let cur_aead_us = num(cur, &["aead", "frame_roundtrip_us"]);
    let base_aead_us = num(base, &["aead", "frame_roundtrip_us"]);
    let cur_tun_mbps = num(cur, &["tunnel", "throughput_mbps"]);
    let base_tun_mbps = num(base, &["tunnel", "throughput_mbps"]);
    let cur_tun_us = num(cur, &["tunnel", "roundtrip_us"]);
    let base_tun_us = num(base, &["tunnel", "roundtrip_us"]);

    let mut flags: Vec<String> = Vec::new();

    // 绝对下限（灾难保护，先于相对判定）
    if cur_aead_mbps < ABS_MIN_AEAD_MBPS {
        flags.push(format!(
            "aead_throughput_below_abs_min ({cur_aead_mbps:.2} MB/s)"
        ));
    }
    if cur_tun_mbps < ABS_MIN_TUNNEL_MBPS {
        flags.push(format!(
            "tunnel_throughput_below_abs_min ({cur_tun_mbps:.2} MB/s)"
        ));
    }
    if cur_aead_us > ABS_MAX_ROUNDTRIP_US || cur_tun_us > ABS_MAX_ROUNDTRIP_US {
        flags.push(format!(
            "roundtrip_above_abs_max (aead {cur_aead_us:.1}us / tun {cur_tun_us:.1}us)"
        ));
    }
    if !flags.is_empty() {
        return json!({ "verdict": "FAIL", "reason": flags.join("; ") });
    }

    // 相对判定：吞吐低于 0.2× 或延迟高于 5× → blocking FAIL；
    // 吞吐低于 0.5× 或延迟高于 2× → WARN；否则 PASS（noise ±30% 内自然 PASS）。
    let mut warns: Vec<String> = Vec::new();
    let mut fails: Vec<String> = Vec::new();
    check_throughput(
        "aead",
        cur_aead_mbps,
        base_aead_mbps,
        &mut warns,
        &mut fails,
    );
    check_throughput(
        "tunnel",
        cur_tun_mbps,
        base_tun_mbps,
        &mut warns,
        &mut fails,
    );
    check_latency("aead", cur_aead_us, base_aead_us, &mut warns, &mut fails);
    check_latency("tunnel", cur_tun_us, base_tun_us, &mut warns, &mut fails);

    let verdict = if !fails.is_empty() {
        "FAIL"
    } else if !warns.is_empty() {
        "WARN"
    } else {
        "PASS"
    };
    json!({
        "verdict": verdict,
        "warns": warns,
        "fails": fails,
        "base_aead_mbps": round2(base_aead_mbps),
        "base_tunnel_mbps": round2(base_tun_mbps),
    })
}

fn check_throughput(
    name: &str,
    cur: f64,
    base: f64,
    warns: &mut Vec<String>,
    fails: &mut Vec<String>,
) {
    if base <= 0.0 {
        return;
    }
    let ratio = cur / base;
    if ratio < 0.2 {
        fails.push(format!("{name}_throughput {ratio:.2}x of baseline"));
    } else if ratio < 0.5 {
        warns.push(format!("{name}_throughput {ratio:.2}x of baseline"));
    }
}

fn check_latency(
    name: &str,
    cur: f64,
    base: f64,
    warns: &mut Vec<String>,
    fails: &mut Vec<String>,
) {
    if base <= 0.0 {
        return;
    }
    let ratio = cur / base;
    if ratio > 5.0 {
        fails.push(format!("{name}_roundtrip {ratio:.2}x of baseline"));
    } else if ratio > 2.0 {
        warns.push(format!("{name}_roundtrip {ratio:.2}x of baseline"));
    }
}

fn num(v: &Value, path: &[&str]) -> f64 {
    let mut cur = v;
    for p in path {
        cur = &cur[p];
    }
    cur.as_f64().unwrap_or(0.0)
}

fn round2(x: f64) -> f64 {
    (x * 100.0).round() / 100.0
}
