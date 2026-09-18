//! E4 产品场景 `product.proxy-loadbalance-group` 的可执行驱动（Composition Root）。
//!
//! ```text
//! cargo run --quiet -p nexus --example proxy_loadbalance_group -- --json
//! ```
//!
//! 构建 load_balance 策略组（候选 out-a/out-b/out-c），连续发起 6 次分流决策，
//! 断言 round-robin 均匀分发：每个候选恰好命中 2 次。全程零网络探测。

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
        tag: lb-group
outbounds:
  - tag: out-a
    kind: direct
  - tag: out-b
    kind: direct
  - tag: out-c
    kind: direct
groups:
  - tag: lb-group
    kind: load_balance
    candidates: [out-a, out-b, out-c]
";

fn flow() -> FlowContext {
    FlowContext {
        origin: FlowOrigin::Socks5,
        resource: nexus_domain::ResourceId("internet".into()),
        destination: "example.in:443".into(),
        profile: String::new(),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let as_json = args.iter().any(|a| a == "--json");

    let cfg = nexus_proxy_config::parse(YAML).expect("config parses");
    let svc = ProxyService::new(&cfg).expect("service builds");

    let mut hits_a = 0_u32;
    let mut hits_b = 0_u32;
    let mut hits_c = 0_u32;
    for _ in 0..6 {
        let d = svc.route(&flow(), None).expect("routes");
        match d.selected_outbound_tag.as_str() {
            "out-a" => hits_a += 1,
            "out-b" => hits_b += 1,
            "out-c" => hits_c += 1,
            other => panic!("unexpected selected '{other}'"),
        }
    }
    let total = hits_a + hits_b + hits_c;
    let verdict = hits_a == 2 && hits_b == 2 && hits_c == 2 && total == 6;

    if as_json {
        println!(
            concat!(
                "{{\"verdict\":\"{}\",",
                "\"group_type\":\"load_balance\",",
                "\"hits_a\":{},",
                "\"hits_b\":{},",
                "\"hits_c\":{},",
                "\"total\":{}}}"
            ),
            if verdict { "PASS" } else { "FAIL" },
            hits_a,
            hits_b,
            hits_c,
            total
        );
    } else {
        println!("lb: a={hits_a} b={hits_b} c={hits_c} total={total}");
    }
}
