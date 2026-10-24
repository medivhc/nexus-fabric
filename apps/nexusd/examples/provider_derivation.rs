//! E4: `provider_derivation`（spec §9.7.1）— 从 proxy.yaml 派生 Provider。

use nexusd::dataplane::derive_providers;

fn main() {
    let json = std::env::args().any(|a| a == "--json");
    if !json {
        eprintln!("--json required");
        std::process::exit(2);
    }
    let yaml = "\
schema_version: 1
rules:
  - tag: r1
    kind: match
    action:
      - kind: select_outbound
        tag: p1
groups: []
outbounds:
  - tag: direct
    kind: direct
    locator: \"\"
  - tag: p1
    kind: shadowsocks
    locator: 203.0.113.10:8388
    method: chacha20-ietf-poly1305
    password: test-password
  - tag: p2
    kind: trojan
    locator: 203.0.113.11:443
    password: test-password
";
    let config = match nexus_proxy_config::parse(yaml) {
        Ok(c) => c,
        Err(e) => {
            println!("{{\"verdict\":\"FAIL\",\"error\":\"config: {e}\"}}");
            std::process::exit(1);
        }
    };
    let records = match derive_providers(&config) {
        Ok(r) => r,
        Err(e) => {
            println!("{{\"verdict\":\"FAIL\",\"error\":\"derive: {e}\"}}");
            std::process::exit(1);
        }
    };
    let ids: Vec<String> = records.iter().map(|r| r.id.0.clone()).collect();
    let placements: Vec<String> = records.iter().map(|r| r.placement.clone()).collect();
    let pass = records.len() == 2
        && ids == vec!["p1".to_string(), "p2".to_string()]
        && placements == vec!["shadowsocks".to_string(), "trojan".to_string()]
        && records
            .iter()
            .all(|r| r.present && r.resource.0 == "internet-access");
    println!(
        "{{\"verdict\":\"{}\",\"provider_count\":{},\"tags\":{},\"placements\":{},\"direct_in_registry\":{}}}",
        if pass { "PASS" } else { "FAIL" },
        records.len(),
        serde_json::to_string(&ids).unwrap_or_default(),
        serde_json::to_string(&placements).unwrap_or_default(),
        ids.iter().any(|t| t.eq_ignore_ascii_case("direct")),
    );
    std::process::exit(if pass { 0 } else { 1 });
}
