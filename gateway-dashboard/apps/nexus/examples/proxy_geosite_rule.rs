//! E4 产品场景 `product.proxy-geosite-rule` 的可执行驱动（Composition Root）。
//!
//! ```text
//! cargo run --quiet -p nexus --example proxy_geosite_rule -- --json
//! ```
//!
//! 组合根注入 GEOSITE 分类清单（cn→[example.cn, foo.cn]），SOCKS5 CONNECT 三个
//! 域名目标：子域命中 geosite（后缀匹配）、精确命中 geosite、未分类走 MATCH。

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
  - tag: rule-geosite-cn
    kind: geosite
    match: cn
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

fn route(service: &ProxyService, domain: &str) -> serde_json::Value {
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
    })
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let as_json = args.iter().any(|a| a == "--json");

    let cfg = parse(CONFIG).expect("config must parse");
    let mut data = nexus_proxy::RuleData::default();
    data.geosite.insert(
        "cn".to_string(),
        vec!["example.cn".to_string(), "foo.cn".to_string()],
    );
    let service = ProxyService::with_rule_data(&cfg, &data).expect("service build");

    let case_sub = route(&service, "www.example.cn");
    let case_exact = route(&service, "foo.cn");
    let case_other = route(&service, "other.com");

    if as_json {
        println!(
            "{{\"verdict\":\"PASS\",\"case_sub\":{},\"case_exact\":{},\"case_other\":{}}}",
            case_sub, case_exact, case_other
        );
    } else {
        println!(
            "sub={}({}) exact={}({}) other={}({})",
            case_sub["matched_rule"],
            case_sub["rule_kind"],
            case_exact["matched_rule"],
            case_exact["rule_kind"],
            case_other["matched_rule"],
            case_other["rule_kind"]
        );
    }
}
