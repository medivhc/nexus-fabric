//! E5 外部观察：跨主机 UDP 承载往返实测（Windows -> mylinux 172.168.9.202:19999）。
//!
//! 使用仓库真实 `nexus_platform::UdpCarrier`（非 loopback mock），向对端 UDP echo
//! 服务发 N 帧并测量真实 RTT。输出 JSON 供落证据。
//!
//! ```text
//! cargo run -q -p nexus --example nat_real_udp_probe -- --to udp://172.168.9.202:19999 --json
//! ```

#![forbid(unsafe_code)]

use nexus_platform::{PacketCarrier, UdpCarrier};
use serde_json::json;
use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut peer = "udp://172.168.9.202:19999".to_string();
    let mut n = 5u32;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--to" {
            if let Some(v) = args.get(i + 1) {
                peer = v.clone();
                i += 1;
            }
        } else if args[i] == "--count" {
            if let Some(v) = args.get(i + 1) {
                n = v.parse().unwrap_or(5);
                i += 1;
            }
        }
        i += 1;
    }

    let mut carrier = UdpCarrier::new();
    // UdpCarrier locator 不允许 port=0；绑定固定本地端口。
    let bound = match carrier.bind("udp://0.0.0.0:14141") {
        Ok(b) => b,
        Err(e) => {
            println!("{}", json!({"verdict":"FAIL","error":format!("bind: {e}")}));
            return;
        }
    };

    let mut rtts_ms: Vec<u64> = Vec::new();
    let mut ok = 0u32;
    let mut buf = [0u8; 2048];

    for seq in 0..n {
        let frame = format!("nat01-ping-{seq}").into_bytes();
        let start = Instant::now();
        if let Err(e) = carrier.send_to(&peer, &frame) {
            println!(
                "{}",
                json!({"verdict":"FAIL","error":format!("send_to: {e}")})
            );
            return;
        }
        // 轮询接收（carrier 非阻塞，Ok(0)=无数据）
        loop {
            match carrier.receive_into(&mut buf) {
                Ok(0) => {
                    if start.elapsed().as_secs() > 3 {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Ok(nrecv) => {
                    let rtt = start.elapsed().as_millis() as u64;
                    if &buf[..nrecv] == format!("echo:nat01-ping-{seq}").as_bytes() {
                        rtts_ms.push(rtt);
                        ok += 1;
                    }
                    break;
                }
                Err(e) => {
                    println!("{}", json!({"verdict":"FAIL","error":format!("recv: {e}")}));
                    return;
                }
            }
        }
    }

    let avg = if rtts_ms.is_empty() {
        0u64
    } else {
        rtts_ms.iter().sum::<u64>() / rtts_ms.len() as u64
    };
    let out = json!({
        "verdict": if ok == n { "PASS" } else { "FAIL" },
        "carrier": "UdpCarrier",
        "local_bound": bound,
        "peer": peer,
        "frames_sent": n,
        "frames_echoed": ok,
        "rtt_ms_samples": rtts_ms,
        "rtt_ms_avg": avg,
    });
    println!("{out}");
}
