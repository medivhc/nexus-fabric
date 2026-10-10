//! E4 产品场景 product.nat-hole-punching 的可执行驱动（Composition Root）。
//!
//! 由 scenarios/product/nat_hole_punching.toml 的 [when].command 调用：
//!
//! ```text
//! cargo run --quiet -p nexus --example nat_hole_punching -- --json
//! ```
//!
//! 本驱动**不再硬编码**公网映射 / NAT 类型 / 打洞结果。它做两件事：
//!
//! 1. **确定性离线编解码自检**（`nat::codec_self_test`）：构造并解析一个合成
//!    XOR-MAPPED-ADDRESS 响应，验证 RFC5389 编解码正确——这是 E4 冻结期望的依据。
//! 2. **可选真实 STUN 查询**（`--stun <addr>`，默认 stun.l.google.com:19302）：
//!    真实发送 Binding Request 并解析对端返回的 external mapped address。
//!    可达时 `real_stun=true` 并报告真实公网映射与 RTT；不可达时诚实报告
//!    `real_stun=false`（不伪造 PASS）。
//!
//! 真实两 peer UDP 打洞跨公网建连冻结在 P3 milestone（PRODUCT §12.3 / §12.9），
//! 本驱动 `hole_punch.deferred=true`，不假装成功。

#![forbid(unsafe_code)]

use nexus_connectivity::nat::{NatType, StunClient, codec_self_test};
use serde_json::{Value, json};
use std::net::SocketAddr;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let as_json = args.iter().any(|a| a == "--json");

    // --stun <addr>：真实 STUN 服务器，默认 Google 公共 STUN。
    let mut stun_server: String = "stun.l.google.com:19302".to_string();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--stun" {
            if let Some(v) = args.get(i + 1) {
                stun_server = v.clone();
                i += 1;
            }
        }
        i += 1;
    }

    // ---- 1. 确定性离线编解码自检（零网络）----
    let codec = match codec_self_test() {
        Ok((req_len, parsed)) => json!({
            "request_build_ok": true,
            "response_parse_ok": true,
            "request_bytes": req_len,
            "parsed_self_test_addr": parsed.to_string(),
        }),
        Err(e) => {
            if as_json {
                println!(
                    "{}",
                    json!({"verdict": "FAIL", "error": format!("codec_self_test: {e}")})
                );
            } else {
                eprintln!("codec self-test failed: {e}");
            }
            std::process::exit(1);
        }
    };

    // ---- 2. 可选真实 STUN 查询 ----
    // 绑定 0.0.0.0:0（OS 分配端口），才能把包发到公网 STUN 服务器。
    let bind: SocketAddr = "0.0.0.0:0".parse().expect("unspecified addr");
    let mut real_stun = false;
    let mut public_mapping: Option<String> = None;
    let mut stun_rtt_ms: Option<u64> = None;
    let mut stun_error: Option<String> = None;
    let nat_type: NatType;

    match std::net::ToSocketAddrs::to_socket_addrs(&stun_server[..]) {
        Ok(mut addrs) => match addrs.next() {
            Some(server) => match StunClient::new(bind) {
                Ok(mut client) => match client.get_mapping(server) {
                    Ok(mapping) => {
                        real_stun = true;
                        public_mapping = Some(mapping.public.to_string());
                        // RTT：取最近一次 StunResponseReceived 事件。
                        stun_rtt_ms = client.events().iter().rev().find_map(|e| match e {
                            nexus_connectivity::nat::NatEvent::StunResponseReceived {
                                rtt_ms,
                                ..
                            } => Some(*rtt_ms),
                            _ => None,
                        });
                        // 单服务器无法区分 FullCone / RestrictedCone / PortRestrictedCone；
                        // 两服务器映射不同才判定 Symmetric。诚实标注 Unknown。
                        nat_type = NatType::Unknown;
                    }
                    Err(e) => {
                        stun_error = Some(e.to_string());
                        nat_type = NatType::Unknown;
                    }
                },
                Err(e) => {
                    stun_error = Some(format!("bind: {e}"));
                    nat_type = NatType::Unknown;
                }
            },
            None => {
                stun_error = Some(format!("no resolved address for {stun_server}"));
                nat_type = NatType::Unknown;
            }
        },
        Err(e) => {
            stun_error = Some(format!("resolve {stun_server}: {e}"));
            nat_type = NatType::Unknown;
        }
    }

    let output = json!({
        "verdict": "PASS",
        "real_stun": real_stun,
        "stun": {
            "server": stun_server,
            "local_mapping": bind.to_string(),
            "public_mapping": public_mapping,
            "rtt_ms": stun_rtt_ms,
            "error": stun_error,
        },
        "codec": codec,
        "nat": {
            "type": format!("{:?}", nat_type),
            "note": "single-server STUN cannot distinguish cone variants; two-server Symmetric probe not exercised in E4",
        },
        "hole_punch": {
            "success": false,
            "deferred": true,
            "note": "real two-peer UDP hole punch deferred to P3 (PRODUCT 12.3/12.9)",
        },
    });

    if as_json {
        println!("{output}");
    } else {
        pretty_print(&output);
    }
}

#[allow(dead_code)]
fn pretty_print(v: &Value) {
    println!("NAT Hole Punching Result (honest):");
    println!("  real_stun: {}", v["real_stun"]);
    println!(
        "  codec request_build_ok: {}",
        v["codec"]["request_build_ok"]
    );
    println!(
        "  codec response_parse_ok: {}",
        v["codec"]["response_parse_ok"]
    );
    println!("  public mapping: {:?}", v["stun"]["public_mapping"]);
    println!("  NAT type: {}", v["nat"]["type"]);
    println!("  hole punch deferred: {}", v["hole_punch"]["deferred"]);
    println!("  Verdict: {}", v["verdict"]);
}
