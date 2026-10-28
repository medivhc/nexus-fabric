//! E4: `tun_flow_sessions_auto`（spec §7.6 / §10.4）— 流会话三态与首包链。
//!
//! 真实驱动：provider 分支跑首包链（planner_calls 同流不增/新流递增）、
//! hint 缺失 Drop、enabled 无源建连失败 RST。

use std::sync::{Arc, Mutex};
use std::time::Duration;

use nexus_domain::{RouteRequest, RouteTarget, RuleEngine};
use nexus_projection::egress::{Rule, SimpleRuleEngine};
use nexus_projection::tcp::{ip_checksum, tcp_checksum};
use nexus_projection::{MockTun, TunDevice};
use nexus_proxy::domain_engine::DomainRuleEngine;
use nexusd::dataplane::{Dataplane, DataplaneConfig, ProductionChainDeps};

const YAML_ONE_PROVIDER: &str = r#"schema_version: 1
rules:
  - tag: proxy-all
    kind: match
    action:
      - kind: select_outbound
        tag: p1
groups: []
outbounds:
  - tag: p1
    kind: socks5
    locator: 127.0.0.1:1
"#;

const YAML_NO_PROVIDER: &str = r#"schema_version: 1
rules:
  - tag: direct-all
    kind: match
    action:
      - kind: select_outbound
        tag: direct
groups: []
outbounds:
  - tag: direct
    kind: direct
    locator: ""
"#;

struct SharedTun(Arc<Mutex<MockTun>>);

impl TunDevice for SharedTun {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().read(buf)
    }
    fn write(&mut self, packet: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().write(packet)
    }
    fn name(&self) -> &str {
        "mock0"
    }
}

fn craft_udp(dst_port: u16, src_port: u16) -> Vec<u8> {
    let mut pkt = vec![0u8; 28];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&28u16.to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 17;
    pkt[12..16].copy_from_slice(&[10, 0, 0, 2]);
    pkt[16..20].copy_from_slice(&[203, 0, 113, 10]);
    pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
    pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
    pkt[24..26].copy_from_slice(&8u16.to_be_bytes());
    pkt
}

fn craft_syn(dst_port: u16, src_port: u16) -> Vec<u8> {
    let src_ip = [10, 0, 0, 2];
    let dst_ip = [203, 0, 113, 10];
    let mut pkt = vec![0u8; 40];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&40u16.to_be_bytes());
    pkt[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 6;
    pkt[12..16].copy_from_slice(&src_ip);
    pkt[16..20].copy_from_slice(&dst_ip);
    let checksum = ip_checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&checksum.to_be_bytes());
    let t = &mut pkt[20..40];
    t[0..2].copy_from_slice(&src_port.to_be_bytes());
    t[2..4].copy_from_slice(&dst_port.to_be_bytes());
    t[4..8].copy_from_slice(&1000u32.to_be_bytes());
    t[12] = 0x50;
    t[13] = 0x02;
    t[14..16].copy_from_slice(&8192u16.to_be_bytes());
    let tcp_cksum = tcp_checksum(src_ip, dst_ip, &pkt[20..]);
    pkt[36..38].copy_from_slice(&tcp_cksum.to_be_bytes());
    pkt
}

fn make_dataplane() -> (Dataplane, Arc<Mutex<MockTun>>) {
    let mock = Arc::new(Mutex::new(MockTun::new("mock0")));
    let dp = Dataplane::new(
        Box::new(SharedTun(Arc::clone(&mock))),
        DataplaneConfig::default(),
        None,
    )
    .expect("dataplane");
    (dp, mock)
}

fn simple_rule(tag: &str) -> SimpleRuleEngine {
    SimpleRuleEngine::new(vec![Rule {
        cidr: "0.0.0.0/0".parse().expect("cidr"),
        target: RouteTarget::Egress {
            peer: tag.to_string(),
        },
    }])
}

struct BlockingEstablisher;

impl nexus_flow_session::ConnectivityEstablisher for BlockingEstablisher {
    fn establish(
        &mut self,
        _session_id: &nexus_domain::SessionId,
        _planned: &nexus_flow_session::Planned,
    ) -> Result<String, String> {
        std::thread::sleep(Duration::from_secs(5));
        Ok("blocked".to_string())
    }
}

fn provider_flow() -> (String, Option<String>, usize, u64, u64, u64, String) {
    let (mut dp, mock) = make_dataplane();
    let deps = ProductionChainDeps::from_config(None, Some(YAML_ONE_PROVIDER)).expect("deps");
    let providers = deps.provider_count();
    dp.set_production_chain_deps(deps);
    dp.set_rule_engine(Box::new(
        DomainRuleEngine::from_yaml(YAML_ONE_PROVIDER).expect("rule engine"),
    ));
    dp.enable_flow_sessions_for_config(nexus_proxy_config::FlowSessionsMode::Auto, providers);
    dp.enable_flow_sessions_with_establisher(Box::new(BlockingEstablisher));

    let first = craft_udp(443, 40_000);
    mock.lock().unwrap().inject(first.clone());
    dp.process_one().expect("first packet");
    let first_calls = dp.flow_sessions_state().planner_calls;

    mock.lock().unwrap().inject(first.clone());
    dp.process_one().expect("same flow");
    let same_calls = dp.flow_sessions_state().planner_calls;

    let second = craft_udp(443, 40_001);
    mock.lock().unwrap().inject(second);
    dp.process_one().expect("second flow");
    let other_calls = dp.flow_sessions_state().planner_calls;

    let key = nexus_flow_session::FlowKey::parse(&first).expect("flow key");
    let outbound = dp.flow_planned_provider(&key).unwrap_or_default();
    let engine = DomainRuleEngine::from_yaml(YAML_ONE_PROVIDER).expect("explain engine");
    let req = RouteRequest {
        packet: &first,
        domain: None,
        src_port: Some(40_000),
        dst_port: Some(443),
        process_name: None,
    };
    let (target, _) = engine.explain(&req);
    let hint = match target {
        RouteTarget::Egress { peer } if peer != "self" => peer,
        _ => String::new(),
    };
    let hint_log = format!("egress_hint={hint} outbound={outbound}");

    let state = dp.flow_sessions_state();
    (
        state.state.to_string(),
        state.reason.map(str::to_string),
        state.providers,
        first_calls,
        same_calls,
        other_calls,
        hint_log,
    )
}

fn enabled_no_provider() -> (String, bool, u64, u64, u64) {
    let (mut dp, mock) = make_dataplane();
    let deps = ProductionChainDeps::from_config(None, Some(YAML_ONE_PROVIDER)).expect("deps");
    let providers = deps.provider_count();
    dp.set_production_chain_deps(deps);
    dp.set_rule_engine(Box::new(simple_rule("p1")));
    dp.enable_flow_sessions_for_config(nexus_proxy_config::FlowSessionsMode::Enabled, providers);
    let state = dp.flow_sessions_state().state.to_string();

    mock.lock().unwrap().inject(craft_syn(443, 40_010));
    dp.process_one().expect("syn");
    let mut rst = false;
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while !rst && std::time::Instant::now() < deadline {
        dp.process_one().expect("pump");
        let written = mock.lock().unwrap().take_written();
        rst = written
            .iter()
            .any(|p| p.len() >= 34 && p[9] == 6 && p[33] & 0x04 != 0);
        if !rst {
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    // D2 后 RST 在 SYN 当场发出，建立失败可能晚于 RST 到达观测点；
    // 三条冻结期望（rst / session_establish_failed / direct_attempts）不变，
    // 因此继续有界泵送直到失败计数可见（不改变断言值，只改变采样时机）。
    let fail_deadline = std::time::Instant::now() + Duration::from_secs(3);
    while dp.flow_establish_failures() == 0 && std::time::Instant::now() < fail_deadline {
        dp.process_one().expect("pump establish");
        std::thread::sleep(Duration::from_millis(2));
    }
    let failures = dp.flow_establish_failures();
    let direct_attempts = dp.stats().direct_tcp_dial_ok;
    let state_after = dp.flow_sessions_state().state.to_string();
    (
        format!("{state}/{state_after}"),
        rst,
        failures,
        direct_attempts,
        0,
    )
}

fn hint_missing() -> (u64, u64) {
    let (mut dp, mock) = make_dataplane();
    let deps = ProductionChainDeps::from_config(None, Some(YAML_ONE_PROVIDER)).expect("deps");
    dp.set_production_chain_deps(deps);
    dp.set_rule_engine(Box::new(simple_rule("missing")));
    dp.enable_flow_sessions_for_config(nexus_proxy_config::FlowSessionsMode::Auto, 1);
    mock.lock().unwrap().inject(craft_udp(443, 40_020));
    dp.process_one().expect("hint missing");
    let stats = dp.stats();
    (stats.outbound_unresolved, stats.dropped)
}

fn main() {
    let json = std::env::args().any(|a| a == "--json");
    if !json {
        eprintln!("--json required");
        std::process::exit(2);
    }

    let (state, reason, providers, first_calls, same_calls, other_calls, hint_log) =
        provider_flow();
    let (enabled_state, rst, establish_failed, direct_attempts, _) = enabled_no_provider();
    let (outbound_unresolved, hint_missing_dropped) = hint_missing();

    let no_provider = {
        let (mut dp, _mock) = make_dataplane();
        let deps = ProductionChainDeps::from_config(None, Some(YAML_NO_PROVIDER)).expect("deps");
        dp.set_production_chain_deps(deps);
        dp.enable_flow_sessions_for_config(nexus_proxy_config::FlowSessionsMode::Auto, 0);
        dp.flow_sessions_state()
    };
    let disabled = {
        let (mut dp, _mock) = make_dataplane();
        let deps = ProductionChainDeps::from_config(None, Some(YAML_ONE_PROVIDER)).expect("deps");
        let providers = deps.provider_count();
        dp.set_production_chain_deps(deps);
        dp.enable_flow_sessions_for_config(
            nexus_proxy_config::FlowSessionsMode::Disabled,
            providers,
        );
        dp.flow_sessions_state()
    };

    let pass = state == "enabled"
        && reason.is_none()
        && providers == 1
        && first_calls == 1
        && same_calls == 1
        && other_calls == 2
        && hint_log == "egress_hint=p1 outbound=p1"
        && enabled_state == "enabled/enabled"
        && rst
        && establish_failed >= 1
        && direct_attempts == 0
        && outbound_unresolved >= 1
        && no_provider.state == "disabled"
        && no_provider.reason == Some("no_providers")
        && no_provider.providers == 0
        && disabled.state == "disabled";

    let out = serde_json::json!({
        "verdict": if pass { "PASS" } else { "FAIL" },
        "flow_sessions": {
            "state": state,
            "reason": reason,
            "providers": providers,
            "planner_calls": other_calls,
        },
        "planner_calls_first": first_calls,
        "planner_calls_same_flow": same_calls,
        "planner_calls_other_flow": other_calls,
        "hint_log": hint_log,
        "enabled_no_provider": {
            "state": enabled_state,
            "rst": rst,
            "direct_attempts": direct_attempts,
            "session_establish_failed": establish_failed,
        },
        "hint_missing": {
            "outbound_unresolved": outbound_unresolved,
            "dropped": hint_missing_dropped,
        },
        "auto_no_provider": {
            "state": no_provider.state,
            "reason": no_provider.reason,
            "providers": no_provider.providers,
        },
        "disabled": {
            "state": disabled.state,
        },
    });
    println!("{out}");
    std::process::exit(if pass { 0 } else { 1 });
}
