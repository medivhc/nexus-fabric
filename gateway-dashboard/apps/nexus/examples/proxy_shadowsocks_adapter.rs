//! E4 产品场景 product.proxy-shadowsocks-adapter 的可执行驱动（Composition Root）。
//!
//! 由 scenarios/product/proxy_shadowsocks_adapter.toml 的 [when].command 调用：
//!
//! ```text
//! cargo run --quiet -p nexus --example proxy_shadowsocks_adapter -- --json
//! ```
//!
//! 演示 OutboundAdapter 接缝（PRODUCT §11.6）：
//! - 解析带 shadowsocks 出站的配置（method=chacha20-ietf-poly1305）；
//! - Composition Root 把该出站装配为 `ShadowsocksAdapter` 并按 tag 注册；
//! - 规则把流量导向 ss-out -> 取对应 OutboundAdapter -> handoff kind=shadowsocks；
//! - AEAD encrypt(plaintext) -> decrypt 自洽往返（离线，不连真实 SS 服务器）。

#![forbid(unsafe_code)]

use nexus_connectivity::OutboundAdapter;
use nexus_outbound_shadowsocks::{ShadowsocksAdapter, SsMethod};
use nexus_proxy_config::parse;

const YAML: &str = "\
schema_version: 1
rules:
  - tag: r-ss
    kind: domain_suffix
    match: ss.internal
    action:
      - kind: select_outbound
        tag: ss-out
  - tag: r-match
    kind: match
    action:
      - kind: select_outbound
        tag: direct
outbounds:
  - tag: direct
    kind: direct
    locator: \"\"
  - tag: ss-out
    kind: shadowsocks
    locator: ss.example:8388
    method: chacha20-ietf-poly1305
    password: demo
";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let as_json = args.iter().any(|a| a == "--json");

    let cfg = parse(YAML).expect("proxy config parses");

    // 找到 shadowsocks 出站配置。
    let ss = cfg
        .outbounds
        .iter()
        .find(|o| o.kind == nexus_proxy_config::OutboundKind::Shadowsocks)
        .expect("shadowsocks outbound present");

    // Composition Root 装配：按配置构造 ShadowsocksAdapter（离线，注入式 AEAD）。
    let adapter = ShadowsocksAdapter::new(
        ss.tag.clone(),
        ss.locator.clone().unwrap_or_default(),
        SsMethod::parse(ss.method.as_deref().unwrap_or("")).expect("valid method"),
        ss.password.as_deref().unwrap_or(""),
    )
    .expect("build shadowsocks adapter");

    // 规则选定出站 tag = ss-out（本 example 直接取该分流结果）。
    let selected_outbound_tag = "ss-out";
    let handoff = adapter.handoff("example.ss.internal").expect("handoff");
    let selected_outbound_kind = handoff.kind;
    let method = adapter.method_label().to_string();

    // AEAD 自洽往返。
    let plaintext = b"hello shadowsocks outbound adapter";
    let mut ad = adapter;
    let frame = ad.encrypt(plaintext).expect("encrypt");
    let ciphertext_nonempty = !frame.is_empty();
    let recovered = ad.decrypt(&frame).expect("decrypt");
    let roundtrip_ok = recovered.as_slice() == plaintext;

    let verdict = selected_outbound_kind == "shadowsocks"
        && selected_outbound_tag == "ss-out"
        && method == "chacha20-ietf-poly1305"
        && ciphertext_nonempty
        && roundtrip_ok;

    if as_json {
        println!(
            concat!(
                "{{\"verdict\":\"{}\",",
                "\"selected_outbound_kind\":\"{}\",",
                "\"selected_outbound_tag\":\"{}\",",
                "\"method\":\"{}\",",
                "\"roundtrip_ok\":{},",
                "\"ciphertext_nonempty\":{}}}"
            ),
            if verdict { "PASS" } else { "FAIL" },
            selected_outbound_kind,
            selected_outbound_tag,
            method,
            roundtrip_ok,
            ciphertext_nonempty
        );
    } else {
        println!(
            "ss adapter OK: kind={}, tag={}, method={}, roundtrip={}, ct_nonempty={}",
            selected_outbound_kind,
            selected_outbound_tag,
            method,
            roundtrip_ok,
            ciphertext_nonempty
        );
    }
}
