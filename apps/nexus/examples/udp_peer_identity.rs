//! P4.1 真机收尾 E2E：公网 UDP 直连 + 身份密钥 + TOFU 自动交换（E5 证据驱动）。
//!
//! 双进程真实网络（无 WSL、无 TUN、无内存模拟）：
//!
//! ```text
//! initiator（可位于 NAT 后）                    responder（公网）
//!   bind 本地 UDP 端口                           bind 0.0.0.0:<port>
//!   begin_handshake -> INIT ────────────────►   recv_and_deliver（学习来源）
//!                                             accept -> RESP ────►（回包到 NAT 映射地址）
//!   complete_handshake（收到 RESP）
//!   send_ip_packet ────────────────────────►   解密数据帧 -> 回帧 pong
//!   收 pong（解密）
//! ```
//!
//! NAT 会话回程：responder 通过 `PacketCarrier::last_peer_locator` 学习发起方
//! NAT 映射地址（crates/nexus-platform UdpCarrier 来源追踪 + 隧道握手帧
//! 来源刷新），无需双向打洞/TURN（P4.2 范畴）。
//!
//! 用法（两端分别运行）：
//! # responder（公网节点，如 vps）：--role resp --listen udp://0.0.0.0:51820 --vip 10.0.0.2
//! # initiator（本机，NAT 后亦可）：--role init --listen udp://0.0.0.0:51821 --vip 10.0.0.1

#![forbid(unsafe_code)]

use std::process::ExitCode;
use std::time::{Duration, Instant};

use nexus_connectivity::identity::InMemorySecretStore;
use nexus_connectivity::virtual_subnet::{
    MemoryVpi, TunnelPeer, TunnelState, VirtualSubnetConfig, VirtualSubnetEvent,
    VirtualSubnetTunnel,
};
use nexus_platform::PacketCarrier;

/// 命令行参数（极简，手工 E2E 驱动）。
struct Args {
    role: String,
    listen: String,
    vip: String,
    peer_vip: String,
    peer_loc: String,
    json: bool,
}

fn parse_args() -> Args {
    let mut a = Args {
        role: String::new(),
        listen: String::new(),
        vip: String::new(),
        peer_vip: String::new(),
        peer_loc: String::new(),
        json: false,
    };
    let mut it = std::env::args().skip(1);
    while let Some(k) = it.next() {
        match k.as_str() {
            "--role" => a.role = it.next().unwrap_or_default(),
            "--listen" => a.listen = it.next().unwrap_or_default(),
            "--vip" => a.vip = it.next().unwrap_or_default(),
            "--peer-vip" => a.peer_vip = it.next().unwrap_or_default(),
            "--peer-loc" => a.peer_loc = it.next().unwrap_or_default(),
            "--json" => a.json = true,
            other => {
                eprintln!("unknown arg: {other}");
                std::process::exit(2);
            }
        }
    }
    if a.role.is_empty() || a.listen.is_empty() || a.vip.is_empty() || a.peer_vip.is_empty() {
        eprintln!(
            "usage: --role init|resp --listen udp://<ip>:<port> --vip <vip> --peer-vip <vip> --peer-loc udp://<ip>:<port> [--json]"
        );
        std::process::exit(2);
    }
    a
}

fn events_of(t: &VirtualSubnetTunnel) -> Vec<String> {
    t.events()
        .iter()
        .map(|e| match e {
            VirtualSubnetEvent::IdentityKeyGenerated { .. } => "identity_key_generated".to_string(),
            VirtualSubnetEvent::PeerIdentityLearned { .. } => "peer_identity_learned".to_string(),
            VirtualSubnetEvent::PeerIdentityRejected { .. } => "peer_identity_rejected".to_string(),
            VirtualSubnetEvent::PeerLocatorUpdated { .. } => "peer_locator_updated".to_string(),
            VirtualSubnetEvent::PeerStateChanged {
                new_state: TunnelState::Connected,
                ..
            } => "peer_connected".to_string(),
            other => format!("{other:?}"),
        })
        .collect()
}

/// 从 VPI 接收缓冲取出一条 payload（隧道把明文写进 VPI，而非调用方 buffer）。
fn take_vpi_payload(vpi_recv: &std::sync::Mutex<Vec<u8>>) -> Option<String> {
    let mut v = vpi_recv.lock().unwrap();
    if v.is_empty() {
        return None;
    }
    let body = String::from_utf8_lossy(&v).to_string();
    v.clear();
    Some(body)
}

fn main() -> ExitCode {
    let args = parse_args();

    let mut carrier = nexus_platform::UdpCarrier::new();
    if let Err(e) = carrier.bind(&args.listen) {
        eprintln!("bind {} failed: {e}", args.listen);
        return ExitCode::from(2);
    }

    let cfg = VirtualSubnetConfig::new("10.0.0.0/24", &args.vip);
    let vpi = MemoryVpi::new();
    let vpi_recv = vpi.sent_handle();
    let mut tunnel = VirtualSubnetTunnel::new(cfg, Box::new(vpi), Box::new(carrier));
    if let Err(e) = tunnel.add_peer(TunnelPeer::new(&args.peer_vip, &args.peer_loc)) {
        eprintln!("add_peer failed: {e}");
        return ExitCode::from(2);
    }
    tunnel.enable_encryption(nexus_connectivity::encryption::EncryptionConfig::default());
    tunnel.set_identity_store(Box::new(InMemorySecretStore::new()));

    let deadline = Instant::now() + Duration::from_secs(45);
    let mut buf = [0u8; 4096];
    let mut data_roundtrip = false;

    let result = (|| -> Result<(), String> {
        if args.role == "init" {
            tunnel
                .begin_handshake(&args.peer_vip)
                .map_err(|e| format!("begin_handshake: {e}"))?;
            loop {
                if Instant::now() > deadline {
                    return Err("timeout waiting RESP".to_string());
                }
                tunnel
                    .recv_and_deliver(&mut buf)
                    .map_err(|e| format!("recv RESP: {e}"))?;
                if tunnel
                    .peers()
                    .iter()
                    .any(|(_, s)| matches!(s, TunnelState::Connected))
                {
                    break;
                }
                std::thread::sleep(Duration::from_millis(80));
            }
            tunnel
                .send_ip_packet(&args.peer_vip, b"p4.1-real-net-ok")
                .map_err(|e| format!("send: {e}"))?;
            loop {
                if Instant::now() > deadline {
                    return Err("timeout waiting pong".to_string());
                }
                if let Some((_, _)) = tunnel
                    .recv_and_deliver(&mut buf)
                    .map_err(|e| format!("recv pong: {e}"))?
                {
                    if take_vpi_payload(&vpi_recv).as_deref() == Some("pong") {
                        data_roundtrip = true;
                        break;
                    }
                }
                std::thread::sleep(Duration::from_millis(80));
            }
        } else {
            loop {
                if Instant::now() > deadline {
                    return Err("timeout".to_string());
                }
                if let Some((_, _)) = tunnel
                    .recv_and_deliver(&mut buf)
                    .map_err(|e| format!("recv: {e}"))?
                {
                    if take_vpi_payload(&vpi_recv).as_deref() == Some("p4.1-real-net-ok") {
                        tunnel
                            .send_ip_packet(&args.peer_vip, b"pong")
                            .map_err(|e| format!("pong: {e}"))?;
                        break;
                    }
                }
                std::thread::sleep(Duration::from_millis(80));
            }
            data_roundtrip = true;
        }
        Ok(())
    })();

    let events = events_of(&tunnel);
    match result {
        Ok(()) if data_roundtrip => {
            let out = serde_json::json!({
                "verdict": "PASS",
                "role": args.role,
                "listen": args.listen,
                "peer": args.peer_loc,
                "events": events,
                "identity": {
                    "peer_id": tunnel.peer_id().unwrap_or_default(),
                    "tofu": "vip-indexed",
                },
                "data": { "roundtrip": data_roundtrip, "algorithm": "x25519-mixed-dh-hkdf-sha256" },
            });
            if args.json {
                println!("{out}");
            } else {
                println!("udp_peer_identity OK: {out}");
            }
            ExitCode::SUCCESS
        }
        Ok(()) => {
            eprintln!("FAIL: handshake ok but data roundtrip incomplete");
            ExitCode::from(1)
        }
        Err(e) => {
            let out = serde_json::json!({
                "verdict": "FAIL",
                "role": args.role,
                "events": events,
                "error": e,
            });
            if args.json {
                println!("{out}");
            }
            eprintln!("udp_peer_identity FAIL: {e}");
            ExitCode::from(1)
        }
    }
}
