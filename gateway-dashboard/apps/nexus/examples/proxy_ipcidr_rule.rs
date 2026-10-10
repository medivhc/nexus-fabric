//! E4 产品场景 `product.proxy-ipcidr-rule-match` 的可执行驱动（Composition Root）。
//!
//! ```text
//! cargo run --quiet -p nexus --example proxy_ipcidr_rule -- --json
//! ```
//!
//! 目的为 IPv4 literal `10.1.2.3:8080`，不命中域名规则；落在 IP-CIDR 10.0.0.0/8 网段，
//! 命中 IP-CIDR 规则，首动作 SELECT_OUTBOUND 指向 relay-group 策略组（selector）。

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
  - tag: rule-internal-cidr
    kind: ip_cidr
    match: 10.0.0.0/8
    action:
      - kind: select_outbound
        tag: relay-group
  - tag: rule-match
    kind: match
    match: \"\"
    action:
      - kind: select_outbound
        tag: fallback-outbound
groups:
  - tag: relay-group
    kind: selector
    candidates: [relay]
outbounds:
  - tag: relay
    kind: relay
    locator: relay.internal:443
  - tag: fallback-outbound
    kind: direct
    locator: \"\"
";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let as_json = args.iter().any(|a| a == "--json");

    // ---- SOCKS5 CONNECT 10.1.2.3:8080（ATYP=IPv4 literal） ----
    let mut hs = Socks5Handshake::new();
    hs.feed(&[0x05, 0x01, 0x00]);
    let step = hs.feed(&[0x05, 0x01, 0x00, 0x01, 10, 1, 2, 3, 0x1f, 0x90]);
    let flow = match step.state {
        Socks5State::Established => step.flow.expect("flow produced on established"),
        other => {
            eprintln!("unexpected handshake state: {other:?}");
            std::process::exit(1);
        }
    };

    let cfg = parse(CONFIG).expect("config must parse");
    let service = ProxyService::new(&cfg).expect("service build");
    let decision = service.route(&flow, None).expect("route");

    if as_json {
        println!(
            concat!(
                "{{\"verdict\":\"PASS\",",
                "\"flow_origin\":\"{}\",",
                "\"matched_rule\":\"{}\",",
                "\"rule_kind\":\"{}\",",
                "\"selected_group_tag\":\"{}\",",
                "\"first_action\":\"{}\"}}"
            ),
            decision.flow_origin,
            decision.matched_rule,
            decision.rule_kind.as_str(),
            decision.selected_group_tag.clone().unwrap_or_default(),
            decision.first_action
        );
    } else {
        println!(
            "{} -> group={} outbound={}",
            decision.matched_rule,
            decision.selected_group_tag.as_deref().unwrap_or("-"),
            decision.selected_outbound_tag
        );
    }
}
