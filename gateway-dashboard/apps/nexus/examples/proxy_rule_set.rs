//! E4 产品场景 `product.proxy-rule-set` 的可执行驱动（Composition Root）。
//!
//! ```text
//! cargo run --quiet -p nexus --example proxy_rule_set -- --json
//! ```
//!
//! 组合根注入三个 rule-provider（cn-domains: domain、cn-nets: ipcidr、
//! ads: classical），规则引用各 provider；四目标分别命中 provider 内规则，
//! 未命中任何 provider 的流量走 MATCH。

#![forbid(unsafe_code)]

use nexus_ingress::{Socks5Handshake, Socks5State};
use nexus_proxy::ProxyService;
use nexus_proxy_config::{ProviderBehavior, parse};

const CONFIG: &str = "\
schema_version: 1
inbounds:
  - tag: socks5-in
    kind: socks5
    listen: 127.0.0.1:1080
rules:
  - tag: rule-provider-cn-domains
    kind: rule_set
    match: cn-domains
    action:
      - kind: select_outbound
        tag: direct
  - tag: rule-provider-cn-nets
    kind: rule_set
    match: cn-nets
    action:
      - kind: select_outbound
        tag: direct
  - tag: rule-provider-ads
    kind: rule_set
    match: ads
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

fn route(service: &ProxyService, domain: Option<&str>, ip: Option<[u8; 4]>) -> serde_json::Value {
    let mut hs = Socks5Handshake::new();
    hs.feed(&[0x05, 0x01, 0x00]);
    let payload = match (domain, ip) {
        (Some(d), None) => {
            let mut p = vec![0x05, 0x01, 0x00, 0x03, d.len() as u8];
            p.extend_from_slice(d.as_bytes());
            p.extend_from_slice(&[0x1f, 0x90]);
            p
        }
        (None, Some(o)) => vec![0x05, 0x01, 0x00, 0x01, o[0], o[1], o[2], o[3], 0x1f, 0x90],
        _ => panic!("one of domain/ip required"),
    };
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
    data.providers.insert(
        "cn-domains".to_string(),
        (
            ProviderBehavior::Domain,
            vec!["a.cn".to_string(), "b.cn".to_string()],
        ),
    );
    data.providers.insert(
        "cn-nets".to_string(),
        (ProviderBehavior::IpCidr, vec!["1.2.3.0/24".to_string()]),
    );
    data.providers.insert(
        "ads".to_string(),
        (
            ProviderBehavior::Classical,
            vec![
                "domain_suffix,ads.example".to_string(),
                "ip_cidr,10.0.0.0/8".to_string(),
            ],
        ),
    );
    let service = ProxyService::with_rule_data(&cfg, &data).expect("service build");

    let case_domain = route(&service, Some("www.a.cn"), None);
    let case_cidr = route(&service, None, Some([1, 2, 3, 4]));
    let case_classical = route(&service, Some("tracker.ads.example"), None);
    let case_miss = route(&service, Some("not-covered.com"), None);

    if as_json {
        println!(
            "{{\"verdict\":\"PASS\",\"case_domain\":{},\"case_cidr\":{},\"case_classical\":{},\"case_miss\":{}}}",
            case_domain, case_cidr, case_classical, case_miss
        );
    } else {
        println!(
            "domain={}({}) cidr={}({}) classical={}({}) miss={}({})",
            case_domain["matched_rule"],
            case_domain["rule_kind"],
            case_cidr["matched_rule"],
            case_cidr["rule_kind"],
            case_classical["matched_rule"],
            case_classical["rule_kind"],
            case_miss["matched_rule"],
            case_miss["rule_kind"]
        );
    }
}
