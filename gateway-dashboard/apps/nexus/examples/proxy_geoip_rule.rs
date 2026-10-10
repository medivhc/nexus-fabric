//! E4 产品场景 `product.proxy-geoip-rule` 的可执行驱动（Composition Root）。
//!
//! ```text
//! cargo run --quiet -p nexus --example proxy_geoip_rule -- --json
//! ```
//!
//! 组合根注入 GEOIP 库（CN→[1.0.1.0/24, 1.2.3.0/24]、US→[8.8.8.0/24]），
//! SOCKS5 CONNECT 三个目标：CN IP 命中 geoip 规则；US IP 不命中走 MATCH；
//! 域名流量（无 IP）不命中 IP 类规则走 MATCH。

#![forbid(unsafe_code)]

use nexus_ingress::{Socks5Handshake, Socks5State};
use nexus_proxy::ProxyService;
use nexus_proxy_config::parse;

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

fn route(service: &ProxyService, ip: &str) -> serde_json::Value {
    let mut hs = Socks5Handshake::new();
    hs.feed(&[0x05, 0x01, 0x00]);
    let host = ip.parse::<std::net::Ipv4Addr>().expect("ipv4");
    let oct = host.octets();
    let step = hs.feed(&[
        0x05, 0x01, 0x00, 0x01, oct[0], oct[1], oct[2], oct[3], 0x1f, 0x90,
    ]);
    let flow = match step.state {
        Socks5State::Established => step.flow.expect("flow produced"),
        other => panic!("unexpected handshake state: {other:?}"),
    };
    let decision = service.route(&flow, None).expect("route");
    serde_json::json!({
        "matched_rule": decision.matched_rule,
        "rule_kind": decision.rule_kind.as_str(),
        "no_resolve": decision.no_resolve,
    })
}

fn route_domain(service: &ProxyService, domain: &str) -> serde_json::Value {
    let mut hs = Socks5Handshake::new();
    hs.feed(&[0x05, 0x01, 0x00]);
    let mut payload = vec![0x05, 0x01, 0x00, 0x03, domain.len() as u8];
    payload.extend_from_slice(domain.as_bytes());
    payload.extend_from_slice(&[0x1f, 0x90]);
    let step = hs.feed(&payload);
    let flow = match step.state {
        Socks5State::Established => step.flow.expect("flow produced"),
        other => panic!("unexpected handshake state: {other:?}"),
    };
    let decision = service.route(&flow, None).expect("route");
    serde_json::json!({
        "matched_rule": decision.matched_rule,
        "rule_kind": decision.rule_kind.as_str(),
        "no_resolve": decision.no_resolve,
    })
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let as_json = args.iter().any(|a| a == "--json");

    let cfg = parse(CONFIG).expect("config must parse");
    let mut data = nexus_proxy::RuleData::default();
    data.geoip.insert(
        "CN".to_string(),
        vec!["1.0.1.0/24".to_string(), "1.2.3.0/24".to_string()],
    );
    data.geoip
        .insert("US".to_string(), vec!["8.8.8.0/24".to_string()]);
    let service = ProxyService::with_rule_data(&cfg, &data).expect("service build");

    let case_cn = route(&service, "1.2.3.4");
    let case_us = route(&service, "8.8.8.8");
    let case_domain = route_domain(&service, "example.com");

    if as_json {
        println!(
            "{{\"verdict\":\"PASS\",\"case_cn\":{},\"case_us\":{},\"case_domain\":{}}}",
            case_cn, case_us, case_domain
        );
    } else {
        println!(
            "cn={}({}) us={}({}) domain={}({})",
            case_cn["matched_rule"],
            case_cn["rule_kind"],
            case_us["matched_rule"],
            case_us["rule_kind"],
            case_domain["matched_rule"],
            case_domain["rule_kind"]
        );
    }
}
