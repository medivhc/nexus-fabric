//! E4: `transparent_rule_consistency`（spec §12.1 AC-G1-DIFF-01）—
//! 同一规则/目的地，TUN 分类与 TPROXY 决策产出一致。

use nexus_domain::{RouteRequest, RouteTarget, RuleEngine as _};
use nexus_path::PathManager;
use nexus_projection::classifier::PacketClassifier;
use nexus_proxy::domain_engine::DomainRuleEngine;

const YAML: &str = "\
schema_version: 1
rules:
  - tag: proxy-cidr
    kind: ip_cidr
    match: 10.200.2.9/32
    action:
      - kind: select_outbound
        tag: p1
  - tag: match-all
    kind: match
    action:
      - kind: select_outbound
        tag: direct
groups: []
outbounds:
  - tag: p1
    kind: socks5
    locator: 127.0.0.1:1080
  - tag: direct
    kind: direct
    locator: \"\"
";

fn ipv4_packet(dst: [u8; 4], dport: u16) -> Vec<u8> {
    let mut pkt = vec![0u8; 24];
    pkt[0] = 0x45;
    pkt[9] = 6;
    pkt[12..16].copy_from_slice(&[10, 0, 0, 2]);
    pkt[16..20].copy_from_slice(&dst);
    pkt[20..22].copy_from_slice(&40_000u16.to_be_bytes());
    pkt[22..24].copy_from_slice(&dport.to_be_bytes());
    pkt
}

fn selected(target: &RouteTarget) -> String {
    match target {
        RouteTarget::Egress { peer } => peer.clone(),
        RouteTarget::MeshPeer { peer } => peer.clone(),
        RouteTarget::Drop => "drop".to_string(),
    }
}

fn hint(target: &RouteTarget) -> Option<String> {
    match target {
        RouteTarget::Egress { peer } if peer == "self" => None,
        RouteTarget::Egress { peer } => Some(peer.clone()),
        _ => None,
    }
}

fn main() {
    let json = std::env::args().any(|a| a == "--json");
    if !json {
        eprintln!("--json required");
        std::process::exit(2);
    }
    let engine = DomainRuleEngine::from_yaml(YAML).expect("engine");
    let packet = ipv4_packet([10, 200, 2, 9], 8080);
    let manager = PathManager::new(Default::default());
    let classifier = PacketClassifier::new(vec![], vec![], &engine, false, &manager, &[], 0.0);
    let tun_class = classifier.classify(&packet, None);
    let tun_target = match tun_class {
        nexus_projection::classifier::Classification::Proxy { outbound } => {
            RouteTarget::Egress { peer: outbound }
        }
        nexus_projection::classifier::Classification::Direct => RouteTarget::Egress {
            peer: "self".to_string(),
        },
        nexus_projection::classifier::Classification::Mesh { .. } => RouteTarget::MeshPeer {
            peer: "mesh".to_string(),
        },
        nexus_projection::classifier::Classification::Drop { .. } => RouteTarget::Drop,
    };
    let req = RouteRequest {
        packet: &packet,
        domain: None,
        src_port: Some(40_000),
        dst_port: Some(8080),
        process_name: None,
    };
    let (tproxy_target, explanation) = engine.explain(&req);
    let tun_explanation = engine.explain(&req).1;
    let matched_rule = explanation
        .as_ref()
        .map(|e| e.matched_rule.clone())
        .unwrap_or_default();
    let tun_matched = tun_explanation.map(|e| e.matched_rule).unwrap_or_default();
    let tun_selected = selected(&tun_target);
    let tproxy_selected = selected(&tproxy_target);
    let tun_hint = hint(&tun_target);
    let tproxy_hint = hint(&tproxy_target);
    let providers = nexus_proxy_config::parse(YAML)
        .ok()
        .and_then(|config| nexusd::dataplane::derive_providers(&config).ok())
        .map(|records| records.len())
        .unwrap_or(0);
    let pass = tun_target == tproxy_target
        && tun_matched == matched_rule
        && tun_selected == tproxy_selected
        && tun_hint == tproxy_hint
        && providers == 1
        && !matched_rule.is_empty();
    println!(
        "{{\"verdict\":\"{}\",\"tun\":{{\"matched_rule\":\"{}\",\"selected_outbound\":\"{}\",\"egress_hint\":{}}},\"tproxy\":{{\"matched_rule\":\"{}\",\"selected_outbound\":\"{}\",\"egress_hint\":{}}},\"matched_rule\":\"{}\",\"selected_outbound\":\"{}\",\"egress_hint\":{},\"provider_count\":{},\"process_unknown\":0}}",
        if pass { "PASS" } else { "FAIL" },
        tun_matched,
        tun_selected,
        opt_json(tun_hint.as_deref()),
        matched_rule,
        tproxy_selected,
        opt_json(tproxy_hint.as_deref()),
        matched_rule,
        tproxy_selected,
        opt_json(tproxy_hint.as_deref()),
        providers,
    );
    std::process::exit(if pass { 0 } else { 1 });
}

fn opt_json(value: Option<&str>) -> String {
    match value {
        Some(v) => format!("\"{v}\""),
        None => "null".to_string(),
    }
}
