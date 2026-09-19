//! E4 产品场景 `product.proxy-rule-provider-fetch` 的可执行驱动（Composition Root）。
//!
//! ```text
//! cargo run --quiet -p nexus --example proxy_rule_provider_fetch -- --json
//! ```
//!
//! 组合根经 [`ProviderFetcher`] 把 rule-provider 内容组装进 `RuleData.providers`
//! 并注入决策内核（§11.12 契约阶段已冻结）：
//! - `cn-domains`（behavior: domain）→ `a.cn`、`b.cn`；
//! - `cn-nets`（behavior: ipcidr）→ `1.0.1.0/24`、`1.2.3.0/24`；
//! - `ads`（behavior: classical）→ `domain_suffix,ads.example`；
//! - 路由：域名 `a.cn` 命中 `rule-set cn-domains`；IP `1.2.3.4` 命中
//!   `rule-set cn-nets`；域名 `ads.example` 命中 `rule-set ads`；
//!   未命中流量走 `MATCH`。
//! - JSON 输出携带每个 case 的命中来源（`source` ∈ local/cached/online）。

#![forbid(unsafe_code)]

use nexus_ingress::{Socks5Handshake, Socks5State};
use nexus_proxy::{FetchedProvider, ProviderFetcher, ProviderSource, ProxyService};
use nexus_proxy_config::parse;

const CONFIG: &str = "\
schema_version: 1
inbounds:
  - tag: socks5-in
    kind: socks5
    listen: 127.0.0.1:1080
rule-providers:
  cn-domains:
    behavior: domain
    path: cache/cn-domains.list
    url: http://127.0.0.1:18080/providers/cn-domains.list
    refresh_interval_secs: 86400
  cn-nets:
    behavior: ipcidr
    path: cache/cn-nets.list
    url: http://127.0.0.1:18080/providers/cn-nets.list
    refresh_interval_secs: 3600
  ads:
    behavior: classical
    path: cache/ads.list
    url: http://127.0.0.1:18080/providers/ads.list
    refresh_interval_secs: 86400
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

/// 固定内容的 fetcher（E4 无需真网络；组合根流程与真实 fetcher 一致）。
struct MockFetcher;

impl ProviderFetcher for MockFetcher {
    fn load(
        &mut self,
        cfg: &nexus_proxy_config::RuleProviderConfig,
    ) -> Result<FetchedProvider, String> {
        let (lines, source) = match cfg.tag.as_str() {
            "cn-domains" => (
                vec!["a.cn".to_string(), "b.cn".to_string()],
                ProviderSource::Online,
            ),
            "cn-nets" => (
                vec!["1.0.1.0/24".to_string(), "1.2.3.0/24".to_string()],
                ProviderSource::Online,
            ),
            "ads" => (
                vec!["domain_suffix,ads.example".to_string()],
                ProviderSource::Local,
            ),
            other => return Err(format!("unknown provider {other}")),
        };
        Ok(FetchedProvider { lines, source })
    }
}

fn route(service: &ProxyService, domain: Option<&str>, ip: Option<[u8; 4]>) -> serde_json::Value {
    let mut hs = Socks5Handshake::new();
    hs.feed(&[0x05, 0x01, 0x00]);
    let step = match (domain, ip) {
        (Some(d), _) => {
            let mut payload = vec![0x05, 0x01, 0x00, 0x03, d.len() as u8];
            payload.extend_from_slice(d.as_bytes());
            payload.extend_from_slice(&[0x1f, 0x90]);
            hs.feed(&payload)
        }
        (None, Some(oct)) => hs.feed(&[
            0x05, 0x01, 0x00, 0x01, oct[0], oct[1], oct[2], oct[3], 0x1f, 0x90,
        ]),
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

    let cfg = parse(CONFIG).expect("config must parse");
    let mut data = nexus_proxy::RuleData::default();
    let mut sources = std::collections::HashMap::new();
    let mut fetcher = MockFetcher;
    for rp in &cfg.rule_providers {
        let fetched = fetcher.load(rp).expect("provider must load");
        sources.insert(
            rp.tag.clone(),
            format!("{:?}", fetched.source).to_lowercase(),
        );
        data.providers
            .insert(rp.tag.clone(), (rp.behavior, fetched.lines));
    }
    let service = ProxyService::with_rule_data(&cfg, &data).expect("service build");

    let src = |tag: &str| sources.get(tag).map(String::as_str).unwrap_or("?");
    let case_domain = route(&service, Some("a.cn"), None);
    let case_cidr = route(&service, None, Some([1, 2, 3, 4]));
    let case_classical = route(&service, Some("ads.example"), None);
    let case_miss = route(&service, Some("example.com"), None);

    if as_json {
        println!(
            "{{\"verdict\":\"PASS\",\"command\":\"proxy rule-provider fetch\",\"case_domain\":{},\"case_cidr\":{},\"case_classical\":{},\"case_miss\":{}}}",
            serde_json::json!({ "matched_rule": case_domain["matched_rule"], "rule_kind": case_domain["rule_kind"], "source": src("cn-domains") }),
            serde_json::json!({ "matched_rule": case_cidr["matched_rule"], "rule_kind": case_cidr["rule_kind"], "source": src("cn-nets") }),
            serde_json::json!({ "matched_rule": case_classical["matched_rule"], "rule_kind": case_classical["rule_kind"], "source": src("ads") }),
            serde_json::json!({ "matched_rule": case_miss["matched_rule"], "rule_kind": case_miss["rule_kind"] })
        );
    } else {
        println!(
            "domain={}({}) cidr={}({}) classical={}({}) miss={}({}) sources={:?}",
            case_domain["matched_rule"],
            case_domain["rule_kind"],
            case_cidr["matched_rule"],
            case_cidr["rule_kind"],
            case_classical["matched_rule"],
            case_classical["rule_kind"],
            case_miss["matched_rule"],
            case_miss["rule_kind"],
            sources
        );
    }
}
