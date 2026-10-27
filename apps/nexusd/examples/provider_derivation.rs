//! E4: `provider_derivation`（spec §9.7.1）— 从 proxy.yaml 派生 Provider。

use nexusd::dataplane::{ProviderDeriveError, derive_providers};

const YAML: &str = r#"schema_version: 1
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
    locator: ""
  - tag: p1
    kind: shadowsocks
    locator: 203.0.113.10:8388
    method: chacha20-ietf-poly1305
    password: test-password
  - tag: p2
    kind: trojan
    locator: 203.0.113.11:443
    password: test-password
"#;

fn variant(error: &ProviderDeriveError) -> &'static str {
    match error {
        ProviderDeriveError::DuplicateTag { .. } => "DuplicateTag",
        ProviderDeriveError::ReservedTag { .. } => "ReservedTag",
        ProviderDeriveError::InvalidTag { .. } => "InvalidTag",
        ProviderDeriveError::MissingLocator { .. } => "MissingLocator",
    }
}

fn main() {
    let json = std::env::args().any(|a| a == "--json");
    if !json {
        eprintln!("--json required");
        std::process::exit(2);
    }
    let config = match nexus_proxy_config::parse(YAML) {
        Ok(c) => c,
        Err(e) => {
            println!(
                "{}",
                serde_json::json!({"verdict": "FAIL", "error": format!("config: {e}")})
            );
            std::process::exit(1);
        }
    };
    let records = match derive_providers(&config) {
        Ok(r) => r,
        Err(e) => {
            println!(
                "{}",
                serde_json::json!({"verdict": "FAIL", "error": format!("derive: {e}")})
            );
            std::process::exit(1);
        }
    };

    let providers: Vec<serde_json::Value> = records
        .iter()
        .map(|r| {
            serde_json::json!({
                "id": r.id.0,
                "resource": r.resource.0,
                "placement": r.placement,
                "locator": r.locator,
                "capabilities": r.capabilities,
                "present": r.present,
            })
        })
        .collect();
    let ids: Vec<String> = records.iter().map(|r| r.id.0.clone()).collect();
    let placements: Vec<String> = records.iter().map(|r| r.placement.clone()).collect();

    let duplicate = {
        let mut cfg = config.clone();
        cfg.outbounds[2].tag = "p1".to_string();
        derive_providers(&cfg).map_or_else(|e| variant(&e).to_string(), |_| String::new())
    };
    let reserved = {
        let mut cfg = config.clone();
        cfg.outbounds[1].tag = "DIRECT".to_string();
        derive_providers(&cfg).map_or_else(|e| variant(&e).to_string(), |_| String::new())
    };
    let invalid = {
        let mut cfg = config.clone();
        cfg.outbounds[1].tag = "p 1".to_string();
        derive_providers(&cfg).map_or_else(|e| variant(&e).to_string(), |_| String::new())
    };
    let missing_locator = {
        let mut cfg = config.clone();
        cfg.outbounds[2].locator = Some(String::new());
        derive_providers(&cfg).map_or_else(|e| variant(&e).to_string(), |_| String::new())
    };

    let fields_ok = records.len() == 2
        && providers[0]["id"] == "p1"
        && providers[0]["resource"] == "internet-access"
        && providers[0]["placement"] == "shadowsocks"
        && providers[0]["locator"] == "203.0.113.10:8388"
        && providers[0]["capabilities"] == serde_json::json!(["internet-access"])
        && providers[0]["present"] == true
        && providers[1]["id"] == "p2"
        && providers[1]["resource"] == "internet-access"
        && providers[1]["placement"] == "trojan"
        && providers[1]["locator"] == "203.0.113.11:443"
        && providers[1]["capabilities"] == serde_json::json!(["internet-access"])
        && providers[1]["present"] == true;
    let errors_ok = duplicate == "DuplicateTag"
        && reserved == "ReservedTag"
        && invalid == "InvalidTag"
        && missing_locator == "MissingLocator";
    let pass = fields_ok && errors_ok && !ids.iter().any(|t| t.eq_ignore_ascii_case("direct"));

    let out = serde_json::json!({
        "verdict": if pass { "PASS" } else { "FAIL" },
        "provider_count": records.len(),
        "providers": providers,
        "tags": ids,
        "placements": placements,
        "direct_in_registry": ids.iter().any(|t| t.eq_ignore_ascii_case("direct")),
        "errors": {
            "duplicate": duplicate,
            "reserved": reserved,
            "invalid": invalid,
            "missing_locator": missing_locator,
        },
    });
    println!("{out}");
    std::process::exit(if pass { 0 } else { 1 });
}
