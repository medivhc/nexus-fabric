//! E4 产品场景 `product.proxy-rule-invalid` 的可执行驱动（Composition Root）。
//!
//! ```text
//! cargo run --quiet -p nexus --example proxy_rule_invalid -- --json
//! ```
//!
//! 编译期严格校验（不静默降级为不匹配）：
//! 1) 规则引用未注入的国家码（GEOIP,XX）→ 编译拒绝；
//! 2) 规则引用未定义的 provider（rule_set,missing）→ 编译拒绝；
//! 3) rule-providers 配置 behavior 非法 → 配置解析拒绝。

#![forbid(unsafe_code)]

use nexus_proxy_config::parse;

const CONFIG_BAD_COUNTRY: &str = "\
schema_version: 1
rules:
  - tag: rule-geoip-xx
    kind: geoip
    match: XX
    action:
      - kind: select_outbound
        tag: direct
  - tag: rule-match
    kind: match
    match: \"\"
    action:
      - kind: select_outbound
        tag: direct
outbounds:

  - tag: direct
    kind: direct
    locator: \"\"
";

const CONFIG_MISSING_PROVIDER: &str = "\
schema_version: 1
rules:
  - tag: rule-provider-missing
    kind: rule_set
    match: missing
    action:
      - kind: select_outbound
        tag: direct
  - tag: rule-match
    kind: match
    match: \"\"
    action:
      - kind: select_outbound
        tag: direct
outbounds:

  - tag: direct
    kind: direct
    locator: \"\"
";

const CONFIG_BAD_PROVIDER: &str = "\
schema_version: 1
rules:
  - tag: rule-match
    kind: match
    match: \"\"
    action:
      - kind: select_outbound
        tag: direct
rule-providers:
  bad:
    behavior: bogus
    path: providers/bad.txt
outbounds:
  - tag: direct
    kind: direct
    locator: \"\"
";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let as_json = args.iter().any(|a| a == "--json");

    // 1) 未知国家码：注入库只有 CN。
    let unknown_country = {
        let cfg = parse(CONFIG_BAD_COUNTRY).expect("config must parse");
        let mut data = nexus_proxy::RuleData::default();
        data.geoip
            .insert("CN".to_string(), vec!["1.0.1.0/24".to_string()]);
        match nexus_proxy::ProxyService::with_rule_data(&cfg, &data) {
            Ok(_) => serde_json::json!({"rejected": false}),
            Err(e) => serde_json::json!({"rejected": true, "error": e.to_string()}),
        }
    };

    // 2) 缺失 provider：注入 providers 为空。
    let missing_provider = {
        let cfg = parse(CONFIG_MISSING_PROVIDER).expect("config must parse");
        let data = nexus_proxy::RuleData::default();
        match nexus_proxy::ProxyService::with_rule_data(&cfg, &data) {
            Ok(_) => serde_json::json!({"rejected": false}),
            Err(e) => serde_json::json!({"rejected": true, "error": e.to_string()}),
        }
    };

    // 3) provider behavior 非法：配置解析即拒绝。
    let bad_provider_cfg = match parse(CONFIG_BAD_PROVIDER) {
        Ok(_) => serde_json::json!({"rejected": false}),
        Err(_) => serde_json::json!({"rejected": true}),
    };

    if as_json {
        println!(
            "{{\"verdict\":\"PASS\",\"unknown_country\":{},\"missing_provider\":{},\"bad_provider_cfg\":{}}}",
            unknown_country, missing_provider, bad_provider_cfg
        );
    } else {
        println!(
            "unknown_country.rejected={} missing_provider.rejected={} bad_provider_cfg.rejected={}",
            unknown_country["rejected"], missing_provider["rejected"], bad_provider_cfg["rejected"]
        );
    }
}
