//! E4 产品场景 `product.proxy-socks5-domain-rule-forward` 的可执行驱动（Composition Root）。
//!
//! ```text
//! cargo run --quiet -p nexus --example proxy_socks5_domain_rule -- --json
//! ```
//!
//! 复用 `nexus-ingress` 的 `Socks5Handshake` 完成 CONNECT 握手，产出 FlowContext；
//! 经 `nexus-proxy-config` 装载 YAML，再由 `nexus-proxy::ProxyService` 执行规则匹配。
//! `mail.example.com` 命中 DOMAIN-SUFFIX example.com 规则，首动作 SELECT_OUTBOUND 指向
//! direct 出站；出站激活委派 `nexus-connectivity::LinkActivator`（离线 mock probe）。

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

/// 离线确定性可达性探测：永远可达（Composition Root 注入，禁止真实网络 I/O）。
struct AlwaysOkProbe;

impl LinkProbe for AlwaysOkProbe {
    fn probe(&self, _candidate: &LinkCandidate) -> Result<(), String> {
        Ok(())
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let as_json = args.iter().any(|a| a == "--json");

    // ---- SOCKS5 CONNECT mail.example.com:443（复用 nexus-ingress 状态机） ----
    let mut hs = Socks5Handshake::new();
    hs.feed(&[0x05, 0x01, 0x00]);
    let mut bytes = vec![0x05, 0x01, 0x00, 0x03, 0x10];
    bytes.extend_from_slice(b"mail.example.com");
    bytes.extend_from_slice(&[0x01, 0xbb]);
    let step = hs.feed(&bytes);
    let flow = match step.state {
        Socks5State::Established => step.flow.expect("flow produced on established"),
        other => {
            eprintln!("unexpected handshake state: {other:?}");
            std::process::exit(1);
        }
    };

    // ---- YAML -> typed structs -> rule engine 编排 ----
    let cfg = parse(CONFIG).expect("config must parse");
    let service = ProxyService::new(&cfg).expect("service build");
    let decision = service.route(&flow, None).expect("route");

    // ---- 出站激活委派 nexus-connectivity（Direct -> Relay 回退） ----
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
            "{} -> {} (rule={}, kind={})",
            decision.matched_rule,
            decision.selected_outbound_tag,
            decision.matched_rule,
            decision.rule_kind.as_str()
        );
    }
}
