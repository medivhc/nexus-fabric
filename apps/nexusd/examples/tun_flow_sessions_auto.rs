//! E4: `tun_flow_sessions_auto`（spec §7.6 / §10.4）— 流会话三态。

use nexus_projection::MockTun;
use nexusd::dataplane::{Dataplane, DataplaneConfig, ProductionChainDeps};

const YAML_ONE_PROVIDER: &str = "\
schema_version: 1
rules:
  - tag: r1
    kind: match
    action:
      - kind: select_outbound
        tag: p1
groups: []
outbounds:
  - tag: p1
    kind: socks5
    locator: 127.0.0.1:1080
";

const YAML_NO_PROVIDER: &str = "\
schema_version: 1
rules:
  - tag: r1
    kind: match
    action:
      - kind: select_outbound
        tag: direct
groups: []
outbounds:
  - tag: direct
    kind: direct
    locator: \"\"
";

fn build(
    yaml: &str,
    mode: nexus_proxy_config::FlowSessionsMode,
) -> (String, Option<String>, usize) {
    let tun = Box::new(MockTun::new("mock0"));
    let mut dp = Dataplane::new(tun, DataplaneConfig::default()).expect("dataplane");
    let deps = ProductionChainDeps::from_config(None, Some(yaml)).expect("deps");
    let providers = deps.provider_count();
    dp.set_production_chain_deps(deps);
    dp.enable_flow_sessions_for_config(mode, providers);
    let status = dp.flow_sessions_state();
    (
        status.state.to_string(),
        status.reason.map(str::to_string),
        status.providers,
    )
}

fn main() {
    let json = std::env::args().any(|a| a == "--json");
    if !json {
        eprintln!("--json required");
        std::process::exit(2);
    }
    use nexus_proxy_config::FlowSessionsMode;
    let enabled = build(YAML_ONE_PROVIDER, FlowSessionsMode::Auto);
    let no_provider = build(YAML_NO_PROVIDER, FlowSessionsMode::Auto);
    let off = build(YAML_ONE_PROVIDER, FlowSessionsMode::Disabled);
    let pass = enabled.0 == "enabled"
        && enabled.2 == 1
        && no_provider.0 == "disabled"
        && no_provider.1.as_deref() == Some("no_providers")
        && off.0 == "disabled";
    println!(
        "{{\"verdict\":\"{}\",\"flow_sessions\":{{\"state\":\"{}\",\"reason\":null,\"providers\":{},\"planner_calls\":0}},\"auto_no_provider\":{{\"state\":\"{}\",\"reason\":\"{}\",\"providers\":{}}},\"disabled\":{{\"state\":\"{}\"}}}}",
        if pass { "PASS" } else { "FAIL" },
        enabled.0,
        enabled.2,
        no_provider.0,
        no_provider.1.unwrap_or_default(),
        no_provider.2,
        off.0
    );
    std::process::exit(if pass { 0 } else { 1 });
}
