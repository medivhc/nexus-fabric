//! E4 产品场景 `product.proxy-extended-rules` 的可执行驱动（Composition Root）。
//!
//! ```text
//! cargo run --quiet -p nexus --example proxy_extended_rules -- --json
//! ```
//!
//! 测试三类新规则：
//! - `dst_port 8080`：经 SOCKS5 握手（目的地 example.com:8080），从 destination 解析端口；
//! - `src_port 9000-9100`：直接构造 FlowTarget（src_port=9050）；
//! - `process_name chrome*`：直接构造 FlowTarget（process_name="chrome_renderer"）。
//!
//! 三组目标分别命中对应规则，首动作 SELECT_OUTBOUND 指向各自出站。

#![forbid(unsafe_code)]

use nexus_ingress::{Socks5Handshake, Socks5State};
use nexus_proxy::{FlowTarget, RuleEngine};
use nexus_proxy_config::parse;

const CONFIG: &str = "\
schema_version: 1\n\
inbounds:\n\
  - tag: socks5-in\n\
    kind: socks5\n\
    listen: 127.0.0.1:1080\n\
rules:\n\
  - tag: rule-dst-port\n\
    kind: dst_port\n\
    match: \"8080\"\n\
    action:\n\
      - kind: select_outbound\n\
        tag: proxy-a\n\
  - tag: rule-src-port\n\
    kind: src_port\n\
    match: \"9000-9100\"\n\
    action:\n\
      - kind: select_outbound\n\
        tag: proxy-b\n\
  - tag: rule-process\n\
    kind: process_name\n\
    match: \"chrome*\"\n\
    action:\n\
      - kind: select_outbound\n\
        tag: proxy-c\n\
  - tag: rule-match\n\
    kind: match\n\
    match: \"\"\n\
    action:\n\
      - kind: select_outbound\n\
        tag: fallback-outbound\n\
groups: []\n\
outbounds:\n\
  - tag: proxy-a\n\
    kind: direct\n\
    locator: \"\"\n\
  - tag: proxy-b\n\
    kind: direct\n\
    locator: \"\"\n\
  - tag: proxy-c\n\
    kind: direct\n\
    locator: \"\"\n\
  - tag: fallback-outbound\n\
    kind: direct\n\
    locator: \"\"\n\
";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let as_json = args.iter().any(|a| a == "--json");

    let cfg = parse(CONFIG).expect("config must parse");
    let engine = RuleEngine::new(&cfg).expect("engine build");

    // ---- 1. dst-port：SOCKS5 CONNECT example.com:8080 ----
    // 0x05 0x01 0x00 (greeting) ; 0x05 0x01 0x00 0x03 <len> "example.com" port 8080
    let mut hs = Socks5Handshake::new();
    hs.feed(&[0x05, 0x01, 0x00]);
    let domain = b"example.com";
    let mut req = vec![0x05, 0x01, 0x00, 0x03, domain.len() as u8];
    req.extend_from_slice(domain);
    req.extend_from_slice(&8080u16.to_be_bytes());
    let step = hs.feed(&req);
    let flow = match step.state {
        Socks5State::Established => step.flow.expect("flow produced on established"),
        other => {
            eprintln!("unexpected handshake state: {other:?}");
            std::process::exit(1);
        }
    };
    // SOCKS5 路径：从 destination 解析 dst_port
    let target_dst = FlowTarget::from_destination(&flow.destination).expect("target");
    let routed_dst = engine.route(&target_dst).expect("dst-port route");

    // ---- 2. src-port：直接构造 FlowTarget ----
    let mut target_src = FlowTarget::from_destination("example.com:443").expect("target");
    target_src.src_port = Some(9050);
    let routed_src = engine.route(&target_src).expect("src-port route");

    // ---- 3. process-name：直接构造 FlowTarget ----
    let mut target_proc = FlowTarget::from_destination("example.com:443").expect("target");
    target_proc.process_name = Some("chrome_renderer".to_string());
    let routed_proc = engine.route(&target_proc).expect("process-name route");

    if as_json {
        println!(
            concat!(
                "{{\"verdict\":\"PASS\",",
                "\"dst_port_rule\":\"{}\",",
                "\"dst_port_kind\":\"{}\",",
                "\"src_port_rule\":\"{}\",",
                "\"src_port_kind\":\"{}\",",
                "\"process_rule\":\"{}\",",
                "\"process_kind\":\"{}\"}}"
            ),
            routed_dst.matched_rule,
            routed_dst.rule_kind.as_str(),
            routed_src.matched_rule,
            routed_src.rule_kind.as_str(),
            routed_proc.matched_rule,
            routed_proc.rule_kind.as_str(),
        );
    } else {
        println!(
            "dst-port -> {} ({})",
            routed_dst.matched_rule,
            routed_dst.rule_kind.as_str()
        );
        println!(
            "src-port -> {} ({})",
            routed_src.matched_rule,
            routed_src.rule_kind.as_str()
        );
        println!(
            "process-name -> {} ({})",
            routed_proc.matched_rule,
            routed_proc.rule_kind.as_str()
        );
    }
}
