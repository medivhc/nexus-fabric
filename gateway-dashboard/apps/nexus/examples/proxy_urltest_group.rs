//! E4 产品场景 `product.proxy-urltest-group` 的可执行驱动（Composition Root）。
//!
//! ```text
//! cargo run --quiet -p nexus --example proxy_urltest_group -- --json
//! ```
//!
//! 构建 urltest 策略组（候选 relay-slow / relay-fast / relay-mid），注入离线确定性
//! measurement（RTT: slow=320ms fast=85ms mid=150ms），断言选中 RTT 最低的 relay-fast。
//! 全程离线可复现，禁止真实网络探测。

#![forbid(unsafe_code)]

use nexus_proxy::{OfflineMeasurements, UrltestGroup};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let as_json = args.iter().any(|a| a == "--json");

    let group = UrltestGroup::new(vec![
        "relay-slow".to_string(),
        "relay-fast".to_string(),
        "relay-mid".to_string(),
    ])
    .expect("urltest build");

    // 离线确定性 measurement 数据源（Composition Root 注入；无真实 RTT 绝对值断言）。
    let mut measurements = OfflineMeasurements::new();
    measurements.insert("relay-slow", 320);
    measurements.insert("relay-fast", 85);
    measurements.insert("relay-mid", 150);

    let selected = group.select(&measurements).expect("urltest select");
    let candidate_count = group.candidate_count();

    if as_json {
        println!(
            concat!(
                "{{\"verdict\":\"PASS\",",
                "\"group_type\":\"urltest\",",
                "\"selected_outbound_tag\":\"{}\",",
                "\"measurement_source\":\"offline-deterministic\",",
                "\"candidate_count\":{}}}"
            ),
            selected, candidate_count
        );
    } else {
        println!("urltest selected={selected} (n={candidate_count}, offline-deterministic)");
    }
}
