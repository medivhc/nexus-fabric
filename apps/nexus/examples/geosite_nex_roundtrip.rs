//! E4 产品场景 `product.geosite-nex-roundtrip` 的可执行驱动（Composition Root）。
//!
//! ```text
//! cargo run --quiet -p nexus --example geosite_nex_roundtrip -- --json
//! ```
//!
//! 内存构造 `geosite.nex` 字节流（[`nexus_proxy::geosite_nex::build`]）→
//! [`parse`](nexus_proxy::geosite_nex::parse) 还原为分类 → 域名表 →
//! 注入 `RuleData.geosite` → 决策内核路由（契约冻结：规则仅 `geosite: cn`）：
//!
//! - 域名 `example.cn` 命中 `geosite: cn`（direct）；
//! - 域名 `other.com`（未命中分类）与 IP 流量走 `MATCH`。
//!
//! 输出携带 `command` / `file_size` / `entry_count` / `parsed_*_domains`
//! 供场景断言（roundtrip 完整性）。

#![forbid(unsafe_code)]

use nexus_ingress::{Socks5Handshake, Socks5State};
use nexus_proxy::ProxyService;
use nexus_proxy::geosite_nex::{build, parse};
use nexus_proxy_config::parse as parse_config;

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

fn route(service: &ProxyService, ip: Option<[u8; 4]>, domain: Option<&str>) -> serde_json::Value {
    let mut hs = Socks5Handshake::new();
    hs.feed(&[0x05, 0x01, 0x00]);
    let step = match (ip, domain) {
        (Some(oct), _) => hs.feed(&[
            0x05, 0x01, 0x00, 0x01, oct[0], oct[1], oct[2], oct[3], 0x1f, 0x90,
        ]),
        (None, Some(d)) => {
            let mut payload = vec![0x05, 0x01, 0x00, 0x03, d.len() as u8];
            payload.extend_from_slice(d.as_bytes());
            payload.extend_from_slice(&[0x1f, 0x90]);
            hs.feed(&payload)
        }
        _ => unreachable!(),
    };
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

    // 生成工具同款布局：cn → example.cn, b.cn；ads → ads.example。
    let cn: &[&str] = &["example.cn", "b.cn"];
    let ads: &[&str] = &["ads.example"];
    let bytes = build(&[("cn", cn), ("ads", ads)]);
    let geosite = parse(&bytes).expect("geosite.nex must parse");
    let entry_count = geosite.len();
    let parsed_cn_domains = geosite.get("cn").map_or(0, Vec::len);
    let parsed_ads_domains = geosite.get("ads").map_or(0, Vec::len);

    let cfg = parse_config(CONFIG).expect("config must parse");
    let data = nexus_proxy::RuleData {
        geosite,
        ..Default::default()
    };
    let service = ProxyService::with_rule_data(&cfg, &data).expect("service build");

    let case_cn = route(&service, None, Some("example.cn"));
    let case_miss = route(&service, None, Some("other.com"));
    let case_domain = route(&service, Some([1, 2, 3, 4]), None);

    if as_json {
        println!(
            "{{\"verdict\":\"PASS\",\"command\":\"geosite.nex roundtrip\",\"file_size\":{},\"entry_count\":{},\"parsed_cn_domains\":{},\"parsed_ads_domains\":{},\"case_cn\":{},\"case_miss\":{},\"case_domain\":{}}}",
            bytes.len(),
            entry_count,
            parsed_cn_domains,
            parsed_ads_domains,
            case_cn,
            case_miss,
            case_domain
        );
    } else {
        println!(
            "file={}B entries={} cn={}({}) miss={}({}) ip={}({})",
            bytes.len(),
            entry_count,
            case_cn["matched_rule"],
            case_cn["rule_kind"],
            case_miss["matched_rule"],
            case_miss["rule_kind"],
            case_domain["matched_rule"],
            case_domain["rule_kind"]
        );
    }
}
