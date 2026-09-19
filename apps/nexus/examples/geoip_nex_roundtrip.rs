//! E4 产品场景 `product.geoip-nex-roundtrip` 的可执行驱动（Composition Root）。
//!
//! ```text
//! cargo run --quiet -p nexus --example geoip_nex_roundtrip -- --json
//! ```
//!
//! 内存构造 `geoip.nex` 字节流（[`nexus_proxy::geoip_nex::build`]）→
//! [`parse`](nexus_proxy::geoip_nex::parse) 还原为国家码 → CIDR 表 →
//! 注入 `RuleData.geoip` → 决策内核路由：
//! - IP `1.2.3.4` 命中 `geoip: CN`（direct）；
//! - IP `8.8.8.8` 命中 `geoip: US`（direct）；
//! - IP `9.9.9.9` 不命中，走 `MATCH`。
//!
//! 输出携带 `file_size`（字节数）与 `entry_count`（国家数）供场景断言。

#![forbid(unsafe_code)]

use nexus_ingress::{Socks5Handshake, Socks5State};
use nexus_proxy::ProxyService;
use nexus_proxy::geoip_nex::{build, parse};
use nexus_proxy_config::parse as parse_config;

const CONFIG: &str = "\
schema_version: 1
inbounds:
  - tag: socks5-in
    kind: socks5
    listen: 127.0.0.1:1080
rules:
  - tag: rule-geoip-cn
    kind: geoip
    match: CN
    action:
      - kind: select_outbound
        tag: direct
  - tag: rule-geoip-us
    kind: geoip
    match: US
    action:
      - kind: select_outbound
        tag: direct
  - tag: rule-match
    kind: match
    match: \"\"
    action:
      - kind: select_outbound
        tag: fallback-outbound
outbounds:
  - tag: direct
    kind: direct
    locator: \"\"
  - tag: fallback-outbound
    kind: direct
    locator: \"\"
";

fn route(service: &ProxyService, ip: [u8; 4]) -> serde_json::Value {
    let mut hs = Socks5Handshake::new();
    hs.feed(&[0x05, 0x01, 0x00]);
    let step = hs.feed(&[
        0x05, 0x01, 0x00, 0x01, ip[0], ip[1], ip[2], ip[3], 0x1f, 0x90,
    ]);
    let flow = match step.state {
        Socks5State::Established => step.flow.expect("flow produced"),
        other => panic!("unexpected handshake state: {other:?}"),
    };
    let decision = service.route(&flow, None).expect("route");
    serde_json::json!({
        "matched_rule": decision.matched_rule,
        "rule_kind": decision.rule_kind.as_str(),
    })
}

fn main() {
    let as_json = std::env::args().skip(1).any(|a| a == "--json");

    // 生成工具同款布局：CN → 1.0.1.0/24, 1.2.3.0/24；US → 8.8.8.0/24。
    let cn: &[(&str, u8)] = &[("1.0.1.0", 24), ("1.2.3.0", 24)];
    let us: &[(&str, u8)] = &[("8.8.8.0", 24)];
    let bytes = build(&[("CN", cn), ("US", us)]);
    let geoip = parse(&bytes).expect("geoip.nex must parse");
    let entry_count = geoip.len();

    let cfg = parse_config(CONFIG).expect("config must parse");
    let data = nexus_proxy::RuleData {
        geoip,
        ..Default::default()
    };
    let service = ProxyService::with_rule_data(&cfg, &data).expect("service build");

    let case_cn = route(&service, [1, 2, 3, 4]);
    let case_us = route(&service, [8, 8, 8, 8]);
    let case_match = route(&service, [9, 9, 9, 9]);

    if as_json {
        println!(
            "{{\"verdict\":\"PASS\",\"file_size\":{},\"entry_count\":{},\"case_cn\":{},\"case_us\":{},\"case_match\":{}}}",
            bytes.len(),
            entry_count,
            case_cn,
            case_us,
            case_match
        );
    } else {
        println!(
            "file={}B entries={} cn={}({}) us={}({}) match={}({})",
            bytes.len(),
            entry_count,
            case_cn["matched_rule"],
            case_cn["rule_kind"],
            case_us["matched_rule"],
            case_us["rule_kind"],
            case_match["matched_rule"],
            case_match["rule_kind"]
        );
    }
}
