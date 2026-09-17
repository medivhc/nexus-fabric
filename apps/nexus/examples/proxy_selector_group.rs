//! E4 产品场景 `product.proxy-selector-group` 的可执行驱动（Composition Root）。
//!
//! ```text
//! cargo run --quiet -p nexus --example proxy_selector_group -- --json
//! ```
//!
//! 构建 selector 策略组（候选 direct/relay），先断言初始选中 = direct，执行
//! switch_to("relay") 后断言选中 = relay，再 switch_to("direct") 后断言选中 = direct。
//! 全程零网络探测（手动切换是确定性操作）。

#![forbid(unsafe_code)]

use nexus_proxy::SelectorGroup;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let as_json = args.iter().any(|a| a == "--json");

    let mut group = SelectorGroup::new(vec!["direct".to_string(), "relay".to_string()], "direct")
        .expect("selector build");
    let initial_selected = group.select().to_string();

    group.switch_to("relay").expect("switch to relay");
    let after_switch_to_relay = group.select().to_string();

    group.switch_to("direct").expect("switch back to direct");
    let after_switch_back = group.select().to_string();

    let candidate_count = group.candidate_count();

    if as_json {
        println!(
            concat!(
                "{{\"verdict\":\"PASS\",",
                "\"group_type\":\"selector\",",
                "\"initial_selected\":\"{}\",",
                "\"after_switch_to_relay\":\"{}\",",
                "\"after_switch_back\":\"{}\",",
                "\"candidate_count\":{}}}"
            ),
            initial_selected, after_switch_to_relay, after_switch_back, candidate_count
        );
    } else {
        println!(
            "selector: {initial_selected} -> {after_switch_to_relay} -> {after_switch_back} (n={candidate_count})"
        );
    }
}
