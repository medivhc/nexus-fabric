//! E4 产品场景 `product.proxy-default-match` 的可执行驱动（Composition Root）。
//!
//! ```text
//! cargo run --quiet -p nexus --example proxy_default_match -- --json
//! ```
//!
//! 目的 `unknown.example.org:443`：不命中 DOMAIN-SUFFIX example.com，也不是 IP literal，
//! 最终命中表尾 MATCH 兜底规则，首动作 SELECT_OUTBOUND 指向 fallback-outbound。

#![forbid(unsafe_code)]

use nexus_connectivity::{LinkActivator, LinkCandidate, LinkKind, LinkProbe};
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
  - tag: rule-example-suffix
    kind: domain_suffix
    match: example.com
    action:
      - kind: select_outbound
        tag: direct
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
  - tag: direct
    kind: direct
    locator: \"\"
  - tag: relay
    kind: relay
    locator: relay.internal:443
  - tag: fallback-outbound
    kind: direct
    locator: \"\"
";

/// 离线确定性可达性探测：永远可达（禁止真实网络 I/O）。
struct AlwaysOkProbe;

impl LinkProbe for AlwaysOkProbe {
    fn probe(&self, _candidate: &LinkCandidate) -> Result<(), String> {
        Ok(())
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let as_json = args.iter().any(|a| a == "--json");

    // ---- SOCKS5 CONNECT unknown.example.org:443 ----
    let mut hs = Socks5Handshake::new();
    hs.feed(&[0x05, 0x01, 0x00]);
    let mut bytes = vec![0x05, 0x01, 0x00, 0x03, 0x13];
    bytes.extend_from_slice(b"unknown.example.org");
    bytes.extend_from_slice(&[0x01, 0xbb]);
    let step = hs.feed(&bytes);
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

    let activator = LinkActivator::new(AlwaysOkProbe);
    let selection = service
        .activate_outbound(&activator, &decision.selected_outbound_tag)
        .expect("activate outbound");
    if selection.kind != LinkKind::Direct {
        eprintln!("expected Direct link, got {:?}", selection.kind);
        std::process::exit(1);
    }

    if as_json {
        println!(
            concat!(
                "{{\"verdict\":\"PASS\",",
                "\"flow_origin\":\"{}\",",
                "\"matched_rule\":\"{}\",",
                "\"rule_kind\":\"{}\",",
                "\"selected_outbound_tag\":\"{}\",",
                "\"first_action\":\"{}\"}}"
            ),
            decision.flow_origin,
            decision.matched_rule,
            decision.rule_kind.as_str(),
            decision.selected_outbound_tag,
            decision.first_action
        );
    } else {
        println!(
            "{} -> {} (kind={})",
            decision.matched_rule,
            decision.selected_outbound_tag,
            decision.rule_kind.as_str()
        );
    }
}
