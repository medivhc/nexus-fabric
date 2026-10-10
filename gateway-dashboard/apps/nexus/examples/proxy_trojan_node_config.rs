//! E4 产品场景 product.proxy-trojan-node-config 的可执行驱动。
//!
//! ```text
//! cargo run --quiet -p nexus --example proxy_trojan_node_config -- --json
//! ```
//!
//! 离线纯解析：喂一段含两个 trojan 节点（Singbox + skip-verify + alpn）的 YAML，断言
//! 解析出 2 个 OutboundConfig、kind=trojan、alpn/skip_cert_verify/header_format 字段正确；
//! 再喂一个缺 password 的 trojan 节点 → CONFIG_INVALID。不连网。

#![forbid(unsafe_code)]

use nexus_proxy_config::parse;

const POSITIVE: &str = "\
schema_version: 1
rules:
  - tag: m
    kind: match
    action:
      - kind: select_outbound
        tag: t-a
outbounds:
  - tag: t-a
    kind: trojan
    locator: ty-3.tr202613.com:443
    password: CHANGE_ME
    alpn: [h2, http/1.1]
    skip_cert_verify: true
    header_format: singbox
  - tag: t-b
    kind: trojan
    locator: os-3.tr202613.com:443
    password: CHANGE_ME
    alpn: [h2, http/1.1]
    skip_cert_verify: true
    header_format: singbox
";

const NEGATIVE_MISSING_PASSWORD: &str = "\
schema_version: 1
rules:
  - tag: m
    kind: match
    action:
      - kind: select_outbound
        tag: t
outbounds:
  - tag: t
    kind: trojan
    locator: example:443
";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let as_json = args.iter().any(|a| a == "--json");

    let cfg = parse(POSITIVE).expect("positive config parses");
    let node_count = cfg.outbounds.len();
    let first = &cfg.outbounds[0];

    let alpn_matches = first
        .alpn
        .as_ref()
        .map(|a| a == &vec!["h2".to_string(), "http/1.1".to_string()])
        .unwrap_or(false);
    let skip_cert_verify_true = first.skip_cert_verify == Some(true);
    let header_format_singbox = first.header_format.as_deref() == Some("singbox");
    let kind = first.kind.as_str().to_string();

    let missing_password_rejected = parse(NEGATIVE_MISSING_PASSWORD).is_err();

    let verdict = node_count == 2
        && kind == "trojan"
        && alpn_matches
        && skip_cert_verify_true
        && header_format_singbox
        && missing_password_rejected;

    if as_json {
        println!(
            "{{\"verdict\":\"{}\",\"kind\":\"{}\",\"node_count\":{},\"alpn_matches\":{},\"skip_cert_verify_true\":{},\"header_format_singbox\":{},\"missing_password_rejected\":{}}}",
            if verdict { "PASS" } else { "FAIL" },
            kind,
            node_count,
            alpn_matches,
            skip_cert_verify_true,
            header_format_singbox,
            missing_password_rejected
        );
    } else {
        println!(
            "trojan node config: nodes={} kind={} alpn={} skip={} hf={} missing_pw_rejected={}",
            node_count,
            kind,
            alpn_matches,
            skip_cert_verify_true,
            header_format_singbox,
            missing_password_rejected
        );
    }
}
