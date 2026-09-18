//! E4 产品场景 product.proxy-vmess-adapter 的可执行驱动（Composition Root）。
//!
//! ```text
//! cargo run --quiet -p nexus --example proxy_vmess_adapter -- --json
//! ```
//!
//! 演示 OutboundAdapter 接缝（PRODUCT §11.7）：Composition Root 把 vmess 出站装配为
//! `VmessAdapter` 并注册；规则把流量导向 vm-out -> handoff kind=vmess；
//! AEAD encrypt(plaintext) -> decrypt 自洽往返（离线，不连真实 vmess server）。

#![forbid(unsafe_code)]

use nexus_connectivity::OutboundAdapter;
use nexus_outbound_vmess::{VmessAdapter, VmessSecurity};
use nexus_proxy_config::parse;

const YAML: &str = "\
schema_version: 1
rules:
  - tag: r-vm
    kind: domain_suffix
    match: vm.internal
    action:
      - kind: select_outbound
        tag: vm-out
  - tag: r-match
    kind: match
    action:
      - kind: select_outbound
        tag: direct
outbounds:
  - tag: direct
    kind: direct
    locator: \"\"
  - tag: vm-out
    kind: vmess
    locator: vmess.example:10086
    method: chacha20-poly1305
    password: b831381d-6324-4d53-ad4f-8cda48b30811
";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let as_json = args.iter().any(|a| a == "--json");

    let cfg = parse(YAML).expect("proxy config parses");
    let vm = cfg
        .outbounds
        .iter()
        .find(|o| o.kind == nexus_proxy_config::OutboundKind::Vmess)
        .expect("vmess outbound present");

    let adapter = VmessAdapter::new(
        vm.tag.clone(),
        vm.locator.clone().unwrap_or_default(),
        VmessSecurity::parse(vm.method.as_deref().unwrap_or("")).expect("valid security"),
        vm.password.as_deref().unwrap_or(""),
    )
    .expect("build vmess adapter");

    let selected_outbound_tag = "vm-out";
    let handoff = adapter.handoff("example.vm.internal").expect("handoff");
    let selected_outbound_kind = handoff.kind;
    let method = adapter.security_label().to_string();

    let plaintext = b"hello vmess outbound adapter";
    let mut ad = adapter;
    let frame = ad.encrypt(plaintext).expect("encrypt");
    let ciphertext_nonempty = !frame.is_empty();
    let recovered = ad.decrypt(&frame).expect("decrypt");
    let roundtrip_ok = recovered.as_slice() == plaintext;

    let verdict = selected_outbound_kind == "vmess"
        && selected_outbound_tag == "vm-out"
        && method == "chacha20-poly1305"
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
            "vmess adapter OK: kind={}, tag={}, method={}, roundtrip={}",
            selected_outbound_kind, selected_outbound_tag, method, roundtrip_ok
        );
    }
}
