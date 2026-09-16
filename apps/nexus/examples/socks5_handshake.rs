//! E4 产品场景 product.socks5-handshake 的可执行驱动（Composition Root）。
//!
//! 由 scenarios/product/socks5_handshake.toml 的 [when].command 调用：
//!
//! ```text
//! cargo run --quiet -p nexus --example socks5_handshake -- --json
//! ```
//!
//! 分步喂入 SOCKS5 握手字节（RFC 1928/1929，sing-box 有状态状态机建模）：
//! - 问候（NO-AUTH）→ MethodSelected，响应 `0x05,0x00`；
//! - CONNECT example.com:443 → Established，产出 FlowContext(destination)；
//! - 错误路径：坏版本问候 → Failed(BadVersion)。

#![forbid(unsafe_code)]

use nexus_ingress::{Socks5Error, Socks5Handshake, Socks5State};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let as_json = args.iter().any(|a| a == "--json");

    // ---- 正常路径：NO-AUTH + CONNECT example.com:443 ----
    let mut hs = Socks5Handshake::new();
    let greeting = hs.feed(&[0x05, 0x01, 0x00]);
    let auth_reply =
        if greeting.state == Socks5State::MethodSelected && greeting.response == [0x05, 0x00] {
            "0x05,0x00".to_string()
        } else {
            eprintln!("unexpected greeting step: {:?}", greeting.state);
            std::process::exit(1);
        };

    let mut bytes = vec![0x05, 0x01, 0x00, 0x03, 0x0b];
    bytes.extend_from_slice(b"example.com");
    bytes.extend_from_slice(&[0x01, 0xbb]);
    let request = hs.feed(&bytes);
    let (final_state, flow_origin, flow_destination) = match request.state {
        Socks5State::Established => {
            let flow = request.flow.expect("flow on established");
            (
                "established".to_string(),
                format!("{:?}", flow.origin).to_ascii_lowercase(),
                flow.destination.clone(),
            )
        }
        other => {
            eprintln!("unexpected request step: {other:?}");
            std::process::exit(1);
        }
    };

    // ---- 错误路径：坏版本问候 → Failed(BadVersion) ----
    let mut bad = Socks5Handshake::new();
    let bad_step = bad.feed(&[0x04, 0x01, 0x00]);
    let bad_version_fails = matches!(
        bad_step.state,
        Socks5State::Failed(Socks5Error::BadVersion { got: 0x04 })
    );

    if as_json {
        println!(
            concat!(
                "{{\"verdict\":\"PASS\",",
                "\"final_state\":\"{}\",",
                "\"auth_reply\":\"{}\",",
                "\"flow_origin\":\"{}\",",
                "\"flow_destination\":\"{}\",",
                "\"bad_version_fails\":{}}}"
            ),
            final_state, auth_reply, flow_origin, flow_destination, bad_version_fails
        );
    } else {
        println!(
            "socks5 handshake OK: {} -> {} (auth={}, bad_version_fails={})",
            flow_origin, flow_destination, auth_reply, bad_version_fails
        );
    }
}
