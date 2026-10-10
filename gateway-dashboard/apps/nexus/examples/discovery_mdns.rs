//! E4 产品场景 `product.discovery-mdns` 的可执行驱动（Composition Root）。
//!
//! 由 `scenarios/product/discovery_mdns.toml` 的 [when].command 调用：
//!
//! ```text
//! cargo run --quiet -p nexus --example discovery_mdns -- --json
//! ```
//!
//! 单进程双节点：两个 socket2 UDP socket（SO_REUSEADDR）同绑 5353、
//! 同加 224.0.0.251 组播组，经 loopback 组播互发现。
//! verdict 语义：双向互发现成功 → PASS；环境无组播能力（bind/join 失败，
//! 如沙箱）→ 诚实 SKIP；逻辑错误 → FAIL（不得用 SKIP 掩盖）。
//!
//! mDNS 只做发现不做认证（见 nexus-discovery D3）。

use nexus_discovery::mdns::{MDNS_ADDR, MdnsDiscovery};
use nexus_discovery::{Discovery, PeerId};
use serde_json::json;
use socket2::{Domain, Protocol, Socket, Type};
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::os::fd::{FromRawFd, IntoRawFd};
use std::time::{Duration, Instant};

/// 组播 socket 装配（组合根职责）：bind 5353 + SO_REUSEADDR + 加入组播组。
///
/// `std` 无法设置 SO_REUSEADDR（与本机其他 mDNS 响应者共存必需），故用 socket2。
fn bind_mdns_socket() -> std::io::Result<UdpSocket> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    let bind_addr: SocketAddr = "0.0.0.0:5353".parse().unwrap();
    sock.bind(&bind_addr.into())?;
    sock.join_multicast_v4(&Ipv4Addr::new(224, 0, 0, 251), &Ipv4Addr::UNSPECIFIED)?;
    sock.set_read_timeout(Some(Duration::from_millis(100)))?;
    // 转为 std UdpSocket 以使用更 ergonomics 的收发 API；
    // into_raw_fd 转移所有权，from_raw_fd 接管，无泄漏/双重关闭。
    let std_sock = unsafe { UdpSocket::from_raw_fd(sock.into_raw_fd()) };
    Ok(std_sock)
}

struct Node {
    mdns: MdnsDiscovery,
    sock: UdpSocket,
    peer: PeerId,
}

impl Node {
    fn new(id: &str, service_port: u16, sock: UdpSocket) -> Result<Self, String> {
        let peer = PeerId(id.to_string());
        let mdns = MdnsDiscovery::new(peer.clone(), service_port, IpAddr::V4(Ipv4Addr::LOCALHOST))
            .map_err(|e| format!("mdns new: {e}"))?;
        Ok(Self { mdns, sock, peer })
    }

    /// 发送查询 + 宣告；收包喂给状态机并发出应答。
    fn pump(&mut self, mdns_addr: SocketAddr) -> std::io::Result<()> {
        let now = Instant::now();
        for payload in [self.mdns.encode_query(), self.mdns.encode_announce()] {
            self.sock.send_to(&payload, mdns_addr)?;
        }
        let mut buf = [0u8; 2048];
        loop {
            match self.sock.recv_from(&mut buf) {
                Ok((n, _)) => {
                    let responses = self.mdns.handle_datagram(&buf[..n], now);
                    for r in responses {
                        let _ = self.sock.send_to(&r, mdns_addr);
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                    break;
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

fn skip(reason: String) -> serde_json::Value {
    json!({
        "verdict": "SKIP",
        "command": "discovery-mdns",
        "reason": reason,
    })
}

fn run() -> serde_json::Value {
    let mdns_addr: SocketAddr = MDNS_ADDR.parse().unwrap();

    let sock_a = match bind_mdns_socket() {
        Ok(s) => s,
        Err(e) => return skip(format!("multicast socket unavailable: {e}")),
    };
    let sock_b = match bind_mdns_socket() {
        Ok(s) => s,
        Err(e) => return skip(format!("second multicast socket unavailable: {e}")),
    };
    let mut a = match Node::new("peer-a", 19001, sock_a) {
        Ok(n) => n,
        Err(e) => return skip(e),
    };
    let mut b = match Node::new("peer-b", 19002, sock_b) {
        Ok(n) => n,
        Err(e) => return skip(e),
    };

    // pump 循环：最多约 6 秒，双向发现即停。
    // EPERM/EACCES（PermissionDenied）= 环境无组播发送能力 → 诚实 SKIP；
    // 其他错误 = 逻辑/装配问题 → FAIL。
    let mut a_got_b = false;
    let mut b_got_a = false;
    for _ in 0..60 {
        let r = a.pump(mdns_addr).and(b.pump(mdns_addr));
        match r {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::PermissionDenied => {
                return skip(format!("multicast blocked by OS: {e}"));
            }
            Err(e) => {
                return json!({"verdict": "FAIL", "command": "discovery-mdns", "reason": format!("pump: {e}")});
            }
        }
        a_got_b = !Discovery::resolve(&a.mdns, &b.peer).is_empty();
        b_got_a = !Discovery::resolve(&b.mdns, &a.peer).is_empty();
        if a_got_b && b_got_a {
            break;
        }
    }

    let a_addr = Discovery::resolve(&a.mdns, &b.peer)
        .first()
        .map(|s| s.to_string())
        .unwrap_or_default();
    let b_addr = Discovery::resolve(&b.mdns, &a.peer)
        .first()
        .map(|s| s.to_string())
        .unwrap_or_default();
    // 自回环不得污染缓存。
    let self_clean = Discovery::resolve(&a.mdns, &a.peer).is_empty()
        && Discovery::resolve(&b.mdns, &b.peer).is_empty();

    let ok = a_got_b
        && b_got_a
        && self_clean
        && a_addr == "127.0.0.1:19002"
        && b_addr == "127.0.0.1:19001";
    json!({
        "verdict": if ok { "PASS" } else { "FAIL" },
        "command": "discovery-mdns",
        "a_discovers_b": a_addr,
        "b_discovers_a": b_addr,
        "self_loop_clean": self_clean,
    })
}

fn main() {
    let v = run();
    if std::env::args().any(|a| a == "--json") {
        println!("{}", serde_json::to_string(&v).unwrap());
    } else {
        println!("{v:#}");
    }
    if v["verdict"] == "FAIL" {
        std::process::exit(1);
    }
}
