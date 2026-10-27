//! E4 产品场景 `product.proxy-relay-group` 的可执行驱动（Composition Root）。
//!
//! ```text
//! cargo run --quiet -p nexus --example proxy_relay_group -- --json
//! ```
//!
//! 构建 relay 策略组（跳序 out-a -> out-b），发起一次分流决策，断言完整跳序列表
//! = [out-a, out-b]（两跳均经过），最终出口 tag = out-b。离线确定性，零真实第二跳。

#![forbid(unsafe_code)]

use nexus_domain::{FlowContext, FlowOrigin};
use nexus_proxy::ProxyService;

const YAML: &str = "\
schema_version: 1
rules:
  - tag: r-match
    kind: match
    action:
      - kind: select_outbound
        tag: relay-group
outbounds:
  - tag: out-a
    kind: relay
  - tag: out-b
    kind: direct
groups:
  - tag: relay-group
    kind: relay
    candidates: [out-a, out-b]
";

fn flow() -> FlowContext {
    FlowContext {
        origin: FlowOrigin::Socks5,
        resource: nexus_domain::ResourceId("internet".into()),
        destination: "example.in:443".into(),
        profile: String::new(),
        egress_hint: None,
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let as_json = args.iter().any(|a| a == "--json");

    let cfg = nexus_proxy_config::parse(YAML).expect("config parses");
    let svc = ProxyService::new(&cfg).expect("service builds");

    let d = svc.route(&flow(), None).expect("routes");
    let hop_count = d.relay_hops.len();
    let hop_first = d.relay_hops.first().cloned().unwrap_or_default();
    let hop_last = d.relay_hops.last().cloned().unwrap_or_default();

    let verdict = d.relay_hops == vec!["out-a".to_string(), "out-b".to_string()]
        && d.selected_outbound_tag == "out-b"
        && d.group_type.as_deref() == Some("relay");

    if as_json {
        println!(
            concat!(
                "{{\"verdict\":\"{}\",",
                "\"group_type\":\"relay\",",
                "\"hop_count\":{},",
                "\"hop_first\":\"{}\",",
                "\"hop_last\":\"{}\"}}"
            ),
            if verdict { "PASS" } else { "FAIL" },
            hop_count,
            hop_first,
            hop_last
        );
    } else {
        println!(
            "relay: hops={:?} exit={}",
            d.relay_hops, d.selected_outbound_tag
        );
    }
}
