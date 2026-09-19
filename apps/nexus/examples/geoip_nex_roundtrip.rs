//! E4 产品场景 `product.geoip-nex-roundtrip` 的可执行驱动（Composition Root）。
//!
//! ```text
//! cargo run --quiet -p nexus --example geoip_nex_roundtrip -- --json
//! ```
//!
//! 内存构造 `geoip.nex` 字节流（[`nexus_proxy::geoip_nex::build`]）→
//! [`parse`](nexus_proxy::geoip_nex::parse) 还原为国家码 → CIDR 表 →
//! 注入 `RuleData.geoip` → 决策内核路由（契约冻结：规则仅 `geoip: CN`）：
//!
//! - IP `1.2.3.4` 命中 `geoip: CN`（direct）；
//! - IP `8.8.8.8`（US 库存在但无 US 规则）与域名流量走 `MATCH`。
//!
//! 输出携带 `command` / `file_size` / `entry_count` / `parsed_*_cidrs`
//! 供场景断言（roundtrip 完整性）。

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

    // 生成工具同款布局：CN → 1.0.1.0/24, 1.2.3.0/24；US → 8.8.8.0/24。
    let cn: &[(&str, u8)] = &[("1.0.1.0", 24), ("1.2.3.0", 24)];
    let us: &[(&str, u8)] = &[("8.8.8.0", 24)];
    let bytes = build(&[("CN", cn), ("US", us)]);
    let geoip = parse(&bytes).expect("geoip.nex must parse");
    let entry_count = geoip.len();
    let parsed_cn_cidrs = geoip.get("CN").map_or(0, Vec::len);
    let parsed_us_cidrs = geoip.get("US").map_or(0, Vec::len);

    let cfg = parse_config(CONFIG).expect("config must parse");
    let data = nexus_proxy::RuleData {
        geoip,
        ..Default::default()
    };
    let service = ProxyService::with_rule_data(&cfg, &data).expect("service build");

    let case_cn = route(&service, Some([1, 2, 3, 4]), None);
    let case_us = route(&service, Some([8, 8, 8, 8]), None);
    let case_domain = route(&service, None, Some("example.com"));

    if as_json {
        println!(
            "{{\"verdict\":\"PASS\",\"command\":\"geoip.nex roundtrip\",\"file_size\":{},\"entry_count\":{},\"parsed_cn_cidrs\":{},\"parsed_us_cidrs\":{},\"case_cn\":{},\"case_us\":{},\"case_domain\":{}}}",
            bytes.len(),
            entry_count,
            parsed_cn_cidrs,
            parsed_us_cidrs,
            case_cn,
            case_us,
            case_domain
        );
    } else {
        println!(
            "file={}B entries={} cn={}({}) us={}({}) domain={}({})",
            bytes.len(),
            entry_count,
            case_cn["matched_rule"],
            case_cn["rule_kind"],
            case_us["matched_rule"],
            case_us["rule_kind"],
            case_domain["matched_rule"],
            case_domain["rule_kind"]
        );
    }
}
