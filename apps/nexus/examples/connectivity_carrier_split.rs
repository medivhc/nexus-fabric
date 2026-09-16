//! E4 产品场景 product.connectivity-carrier-split 的可执行驱动（Composition Root）。
//!
//! 由 scenarios/product/connectivity_carrier_split.toml 的 [when].command 调用：
//!
//! ```text
//! cargo run --quiet -p nexus --example connectivity_carrier_split -- --json
//! ```
//!
//! 验证 W2（VPI 与 PacketCarrier 双 trait 解耦）与 W7（认证门控）：
//! - 未认证 `send_frame` 被拒且不触碰 carrier（零发送）；
//! - 认证后帧真实到达 carrier（经共享状态计数，非硬编码）；
//! - IP 包经 VPI 独立往返（不经过 carrier）；
//! - `PlatformError` 结构化映射为 `ConnectivityError::Io`。

#![forbid(unsafe_code)]

use nexus_connectivity::{ConnectivityError, ConnectivityRuntime};
use nexus_platform::{PacketCarrier, PlatformError, VirtualPacketInterface};
use std::sync::{Arc, Mutex};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let as_json = args.iter().any(|a| a == "--json");

    /// 已发送帧的共享记录（peer, frame）。
    type SentFrames = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

    // ---- mock VPI：IP 包写入后可读回；written 计数经共享状态暴露 ----
    struct MockVpi {
        packets: Vec<Vec<u8>>,
        written: Arc<Mutex<usize>>,
    }
    impl VirtualPacketInterface for MockVpi {
        fn receive(&mut self, output: &mut [u8]) -> Result<usize, PlatformError> {
            match self.packets.pop() {
                Some(p) if p.len() <= output.len() => {
                    output[..p.len()].copy_from_slice(&p);
                    Ok(p.len())
                }
                _ => Ok(0),
            }
        }
        fn send(&mut self, packet: &[u8]) -> Result<(), PlatformError> {
            *self.written.lock().unwrap() += 1;
            self.packets.push(packet.to_vec());
            Ok(())
        }
    }

    // ---- mock carrier：帧记录经共享状态暴露；可选注入 I/O 失败 ----
    struct MockCarrier {
        local: Arc<Mutex<Option<String>>>,
        sent: SentFrames,
        fail_send: bool,
    }
    impl PacketCarrier for MockCarrier {
        fn bind(&mut self, local: &str) -> Result<String, PlatformError> {
            *self.local.lock().unwrap() = Some(local.to_string());
            Ok(local.to_string())
        }
        fn send_to(&mut self, peer: &str, frame: &[u8]) -> Result<(), PlatformError> {
            if self.fail_send {
                return Err(PlatformError::Io {
                    operation: "send_to".into(),
                    message: "injected failure".into(),
                });
            }
            self.sent
                .lock()
                .unwrap()
                .push((peer.to_string(), frame.to_vec()));
            Ok(())
        }
        fn receive_into(&mut self, _output: &mut [u8]) -> Result<usize, PlatformError> {
            Ok(0)
        }
        fn local_locator(&self) -> Option<String> {
            self.local.lock().unwrap().clone()
        }
    }

    // ---- 编排：绑定 + 认证门控 + 帧/IP 包独立往返 ----
    let sent = Arc::new(Mutex::new(Vec::new()));
    let written = Arc::new(Mutex::new(0usize));
    let local = Arc::new(Mutex::new(None));

    let mut rt = ConnectivityRuntime::new(
        Box::new(MockVpi {
            packets: Vec::new(),
            written: Arc::clone(&written),
        }),
        Box::new(MockCarrier {
            local: Arc::clone(&local),
            sent: Arc::clone(&sent),
            fail_send: false,
        }),
    );

    let local_locator = rt.bind_local("0.0.0.0:51820").expect("bind_local succeeds");

    // W7：未认证 send_frame 必须被拒，且 carrier 零发送。
    let auth_gate = match rt.send_frame("peer.exit", b"handshake", false) {
        Err(ConnectivityError::AuthenticationRequired { .. }) => "blocked_before_authenticated",
        other => {
            eprintln!("unexpected auth gate result: {other:?}");
            std::process::exit(1);
        }
    };
    if !sent.lock().unwrap().is_empty() {
        eprintln!("W7 violated: unauthenticated frame reached carrier");
        std::process::exit(1);
    }

    // 认证后：帧真实到达 carrier（共享状态计数）。
    rt.send_frame("peer.exit", b"encrypted-frame", true)
        .expect("authenticated send succeeds");
    let carrier_frames = sent.lock().unwrap().len();

    // IP 包经 VPI 独立往返（不经过 carrier；carrier 帧计数不受影响）。
    rt.write_ip_packet(&[0x45, 0x00, 0x00, 0x14]).unwrap();
    let mut ip = [0u8; 64];
    let ip_len = rt.read_ip_packet(&mut ip).unwrap();
    let vpi_packets = *written.lock().unwrap();

    // 错误映射：注入 I/O 失败 → ConnectivityError::Io。
    let mut failing = ConnectivityRuntime::new(
        Box::new(MockVpi {
            packets: Vec::new(),
            written: Arc::new(Mutex::new(0)),
        }),
        Box::new(MockCarrier {
            local: Arc::new(Mutex::new(None)),
            sent: Arc::new(Mutex::new(Vec::new())),
            fail_send: true,
        }),
    );
    let error_mapped = match failing.send_frame("peer.exit", b"x", true) {
        Err(ConnectivityError::Io { operation, .. }) if operation == "send_to" => "io_mapped",
        other => {
            eprintln!("unexpected error mapping: {other:?}");
            std::process::exit(1);
        }
    };

    if as_json {
        println!(
            concat!(
                "{{\"verdict\":\"PASS\",",
                "\"auth_gate\":\"{}\",",
                "\"carrier_frames\":{},",
                "\"vpi_packets\":{},",
                "\"local_locator\":\"{}\",",
                "\"error_mapped\":\"{}\",",
                "\"ip_roundtrip\":{}}}"
            ),
            auth_gate, carrier_frames, vpi_packets, local_locator, error_mapped, ip_len
        );
    } else {
        println!(
            "carrier split OK: auth_gate={} carrier_frames={} vpi_packets={} local={} error_mapped={}",
            auth_gate, carrier_frames, vpi_packets, local_locator, error_mapped
        );
    }
}
