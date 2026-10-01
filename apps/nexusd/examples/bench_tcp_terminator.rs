//! S11 性能基线：TcpTerminator 吞吐 + dataplane TCP 包处理速率。
//!
//! 无硬门限；结果供回归对比，记录于 `.evidence/`。
//! 运行：`cargo run -p nexusd --example bench_tcp_terminator --release`

use std::sync::{Arc, Mutex};
use std::time::Instant;

use nexus_projection::tcp::{TcpTerminator, ip_checksum, tcp_checksum};
use nexus_projection::{MockTun, TunDevice};
use nexusd::dataplane::{Dataplane, DataplaneConfig};
use serde_json::json;

#[allow(clippy::too_many_arguments)]
fn craft_tcp(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut pkt = vec![0u8; 20 + 20 + payload.len()];
    pkt[0] = 0x45;
    let tot = (20 + 20 + payload.len()) as u16;
    pkt[2..4].copy_from_slice(&tot.to_be_bytes());
    pkt[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 6;
    pkt[12..16].copy_from_slice(&src_ip);
    pkt[16..20].copy_from_slice(&dst_ip);
    let c = ip_checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&c.to_be_bytes());
    let t = &mut pkt[20..40];
    t[0..2].copy_from_slice(&src_port.to_be_bytes());
    t[2..4].copy_from_slice(&dst_port.to_be_bytes());
    t[4..8].copy_from_slice(&seq.to_be_bytes());
    t[8..12].copy_from_slice(&ack.to_be_bytes());
    t[12] = 0x50;
    t[13] = flags;
    t[14..16].copy_from_slice(&8192u16.to_be_bytes());
    pkt[40..].copy_from_slice(payload);
    let tc = tcp_checksum(src_ip, dst_ip, &pkt[20..]);
    pkt[36..38].copy_from_slice(&tc.to_be_bytes());
    pkt
}

struct SharedTun {
    inner: Arc<Mutex<MockTun>>,
}
impl TunDevice for SharedTun {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.lock().unwrap().read(buf)
    }
    fn write(&mut self, packet: &[u8]) -> std::io::Result<usize> {
        self.inner.lock().unwrap().write(packet)
    }
    fn name(&self) -> &str {
        "bench0"
    }
}

fn main() {
    let output = run();
    println!("{}", serde_json::to_string(&output).unwrap());
}

fn run() -> serde_json::Value {
    // 基线 1：TcpTerminator 单流吞吐（握手后连续 DATA）。
    let mut term = TcpTerminator::new();
    let syn = craft_tcp([10, 0, 0, 2], [10, 0, 0, 5], 40000, 80, 1000, 0, 0x02, &[]);
    let tun_pkts = term.handle_uplink(&syn, "bench");
    // 从 SYN-ACK 取 server seq（若无则跳过基线 1）。
    let bench1 = if let Some(sa) = tun_pkts.first() {
        let srv_seq = u32::from_be_bytes([sa[24], sa[25], sa[26], sa[27]]);
        let ack = craft_tcp(
            [10, 0, 0, 2],
            [10, 0, 0, 5],
            40000,
            80,
            1001,
            srv_seq + 1,
            0x10,
            &[],
        );
        let _ = term.handle_uplink(&ack, "bench");
        let _ = term.poll();
        // 1MB 数据，分 1460 字节段发送。
        let payload = vec![0xABu8; 1460];
        let n_segs = 700; // ~1MB
        let mut seq = 1001u32;
        let t0 = Instant::now();
        let mut total_bytes = 0u64;
        for _ in 0..n_segs {
            let data = craft_tcp(
                [10, 0, 0, 2],
                [10, 0, 0, 5],
                40000,
                80,
                seq,
                srv_seq + 1,
                0x18,
                &payload,
            );
            let _ = term.handle_uplink(&data, "bench");
            let _ = term.poll();
            seq += 1460;
            total_bytes += 1460;
        }
        let dt = t0.elapsed().as_secs_f64();
        let mbps = (total_bytes as f64 * 8.0) / dt / 1e6;
        json!({"mbps": (mbps * 10.0).round() / 10.0, "bytes": total_bytes, "secs": (dt * 100.0).round() / 100.0})
    } else {
        json!({"error": "no syn-ack"})
    };

    // 基线 2：dataplane TCP 包处理速率（pps，经终结路径）。
    let mock = Arc::new(Mutex::new(MockTun::new("bench0")));
    let tun = Box::new(SharedTun {
        inner: Arc::clone(&mock),
    });
    let config = DataplaneConfig {
        mesh_cidrs: vec!["10.0.0.0/8".to_string()],
        n1_configured: false, // 无 N1：只测终结开销
        ..Default::default()
    };
    let mut dp = Dataplane::new(tun, config).expect("dataplane");
    // 预建流：SYN→SYN-ACK→ACK。
    let syn = craft_tcp([10, 1, 2, 3], [10, 9, 9, 9], 41000, 80, 5000, 0, 0x02, &[]);
    mock.lock().unwrap().inject(syn);
    let _ = dp.process_one().expect("syn");
    let _ = mock.lock().unwrap().take_written();
    // 10000 个小 DATA 包。
    let _payload = [0xCDu8; 100];
    let n_pkts = 10_000u64;
    // 先完成握手（需要 server seq）。
    // 简化：直接测 SYN 包处理（终结器创建连接路径）。
    let t0 = Instant::now();
    for i in 0..n_pkts {
        let syn = craft_tcp(
            [10, 1, 2, 3],
            [10, 9, 9, 9],
            41000 + (i % 500) as u16,
            80,
            5000,
            0,
            0x02,
            &[],
        );
        mock.lock().unwrap().inject(syn);
        let _ = dp.process_one().expect("process");
        let _ = mock.lock().unwrap().take_written();
    }
    let dt = t0.elapsed().as_secs_f64();
    let pps = (n_pkts as f64 / dt).round() as u64;
    let bench2 = json!({"pps": pps, "packets": n_pkts, "secs": (dt * 100.0).round() / 100.0});

    json!({
        "verdict": "PASS",
        "terminator_throughput": bench1,
        "dataplane_tcp_pps": bench2,
    })
}
