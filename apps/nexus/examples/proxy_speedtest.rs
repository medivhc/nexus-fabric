//! E4 产品场景 `product.proxy-speedtest` 的可执行驱动（Composition Root）。
//!
//! ```text
//! cargo run --quiet -p nexus --example proxy_speedtest -- --json
//! ```
//!
//! 注入离线确定性 LatencyProbe（三个候选 mock RTT：slow=320ms fast=85ms mid=150ms），
//! 执行批量测速并断言 RTT 升序排序（fast -> mid -> slow）。全程离线可复现，
//! 无真实网络探测。

#![forbid(unsafe_code)]

use nexus_measurement::{LinkMeasurement, ProbeTarget};

/// 离线确定性探测：按候选 tag 返回固定 RTT（模拟 LatencyProbe 契约）。
struct MockLatencyProbe;

impl nexus_measurement::LatencyProbe for MockLatencyProbe {
    fn probe(&self, target: &ProbeTarget) -> Result<LinkMeasurement, String> {
        let rtt = match target.host.as_str() {
            "relay-slow" => 320,
            "relay-fast" => 85,
            "relay-mid" => 150,
            other => return Err(format!("unknown candidate {other}")),
        };
        Ok(LinkMeasurement {
            rtt_ms: Some(rtt),
            ..Default::default()
        })
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let as_json = args.iter().any(|a| a == "--json");

    let candidates = vec![
        (
            "relay-slow",
            ProbeTarget::new("http", "relay-slow", 443, ""),
        ),
        (
            "relay-fast",
            ProbeTarget::new("http", "relay-fast", 443, ""),
        ),
        ("relay-mid", ProbeTarget::new("http", "relay-mid", 443, "")),
    ];
    let out = nexus::proxy_speedtest_with(
        &MockLatencyProbe,
        &candidates,
        std::time::Duration::from_secs(5),
        "http://www.gstatic.com/generate_204",
    )
    .expect("speedtest PASS");

    if as_json {
        println!("{out}");
    } else {
        println!(
            "speedtest sorted: {}",
            out["results"]
                .as_array()
                .map(|r| r
                    .iter()
                    .map(|x| format!("{}={}", x["tag"], x["latency_ms"]))
                    .collect::<Vec<_>>()
                    .join(", "))
                .unwrap_or_default()
        );
    }
}
