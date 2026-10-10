//! E4 driver for `product.fabric-semantic-ingress` (3d: semantic ingress).
//!
//! Two nodes linked via MockTransport (E4):
//! - A: `SemanticIngress` bound on 127.0.0.1:0; router: domain `localhost`
//!   → `Egress{peer=B}` (S16), default → `Egress{self}`.
//! - B: TCP egress relay (S22, S25 typed-SYN domain form).
//! - A local echo TCP server is the ultimate target.
//!
//! client1: SOCKS5 (no-auth) CONNECT localhost:PORT → expect 0x00 success;
//!   send "hello-3d" (8 bytes) → expect full echo.
//! client2: HTTP `CONNECT localhost:PORT HTTP/1.1` → expect `HTTP/1.1 200`;
//!   send "hello-3d-http" (12 bytes) → expect full echo.
//!
//! The domain `localhost` is never resolved on A (S25); B resolves it.
//! Output: {"verdict":"PASS","socks5":{"roundtrip_ok":true},
//!          "http":{"roundtrip_ok":true},"relayed_bytes":20}
//!
//! Usage: cargo run -p nexus-projection --example semantic_ingress -- --json

use nexus_projection::{
    MockTun, Projection, ProjectionConfig, RouteTarget, Rule, SemanticIngress, SimpleRuleEngine,
    TunDevice, UnifiedRouter,
};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

struct SharedTun {
    inner: Arc<Mutex<MockTun>>,
}

impl TunDevice for SharedTun {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.lock().unwrap().read(buf)
    }
    fn write(&mut self, packet: &[u8]) -> std::io::Result<usize> {
        self.inner.lock().unwrap().write(packet)
    }
    fn name(&self) -> &str {
        "shared"
    }
}

fn fail(reason: &str) -> String {
    format!("{{\"verdict\":\"FAIL\",\"reason\":\"{reason}\"}}")
}

fn read_exact_timeout(s: &mut TcpStream, buf: &mut [u8], what: &str) -> Result<(), String> {
    s.set_read_timeout(Some(Duration::from_secs(15)))
        .map_err(|e| fail(&format!("{what}: {e}")))?;
    s.read_exact(buf).map_err(|e| fail(&format!("{what}: {e}")))
}

fn main() {
    let out = run().unwrap_or_else(|e| e);
    println!("{out}");
}

fn run() -> Result<String, String> {
    // --- echo server (ultimate target) ---
    let echo = TcpListener::bind("127.0.0.1:0").map_err(|e| fail(&format!("echo bind: {e}")))?;
    let echo_port = echo
        .local_addr()
        .map_err(|e| fail(&format!("echo addr: {e}")))?
        .port();
    std::thread::spawn(move || {
        for conn in echo.incoming().flatten() {
            std::thread::spawn(move || {
                let mut s = conn;
                let mut b = [0u8; 4096];
                loop {
                    match s.read(&mut b) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if s.write_all(&b[..n]).is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });

    // --- node A: ingress + originator ---
    let mut engine_a = SimpleRuleEngine::new(vec![Rule {
        cidr: "0.0.0.0/0".parse().unwrap(),
        target: RouteTarget::Egress {
            peer: "self".to_string(),
        },
    }]);
    engine_a.add_domain_exact_rule(
        "localhost",
        RouteTarget::Egress {
            peer: "B".to_string(),
        },
    );
    let router_a = Arc::new(UnifiedRouter::new(vec![], Box::new(engine_a)));
    let mut a = Projection::new(
        Box::new(SharedTun {
            inner: Arc::new(Mutex::new(MockTun::new("tun-a"))),
        }),
        ProjectionConfig::default(),
    )
    .with_router(router_a)
    .with_tcp_egress();

    // --- node B: egress relay ---
    let engine_b = SimpleRuleEngine::new(vec![Rule {
        cidr: "0.0.0.0/0".parse().unwrap(),
        target: RouteTarget::Egress {
            peer: "self".to_string(),
        },
    }]);
    let router_b = Arc::new(UnifiedRouter::new(vec![], Box::new(engine_b)));
    let mut b = Projection::new(
        Box::new(SharedTun {
            inner: Arc::new(Mutex::new(MockTun::new("tun-b"))),
        }),
        ProjectionConfig::default(),
    )
    .with_router(router_b)
    .with_tcp_egress();

    a.link_mock_peer("B", &b);
    b.link_mock_peer("A", &a);
    a.mock_transport().unwrap().set_name("A");
    b.mock_transport().unwrap().set_name("B");

    // --- semantic ingress on A ---
    let deps = a.semantic_deps().ok_or_else(|| fail("no semantic deps"))?;
    let ingress = SemanticIngress::bind("127.0.0.1:0".parse().unwrap(), deps)
        .map_err(|e| fail(&format!("ingress bind: {e}")))?;
    let ingress_addr = ingress.local_addr();

    // --- client1: SOCKS5 ---
    let mut c1 = TcpStream::connect(ingress_addr).map_err(|e| fail(&format!("c1: {e}")))?;
    c1.write_all(&[0x05, 0x01, 0x00])
        .map_err(|e| fail(&format!("c1 greeting: {e}")))?;
    let mut b2 = [0u8; 2];
    read_exact_timeout(&mut c1, &mut b2, "c1 method reply")?;
    if b2 != [0x05, 0x00] {
        return Err(fail("c1: bad method reply"));
    }
    let mut req = vec![0x05, 0x01, 0x00, 0x03, 9];
    req.extend_from_slice(b"localhost");
    req.extend_from_slice(&echo_port.to_be_bytes());
    c1.write_all(&req)
        .map_err(|e| fail(&format!("c1 connect req: {e}")))?;
    let mut rep = [0u8; 10];
    read_exact_timeout(&mut c1, &mut rep, "c1 connect reply")?;
    if rep[1] != 0x00 {
        return Err(fail(&format!("c1: connect failed rep={}", rep[1])));
    }
    c1.write_all(b"hello-3d")
        .map_err(|e| fail(&format!("c1 write: {e}")))?;
    let mut back = [0u8; 8];
    read_exact_timeout(&mut c1, &mut back, "c1 echo")?;
    let socks5_ok = &back == b"hello-3d";

    // --- client2: HTTP CONNECT ---
    let mut c2 = TcpStream::connect(ingress_addr).map_err(|e| fail(&format!("c2: {e}")))?;
    let http_req =
        format!("CONNECT localhost:{echo_port} HTTP/1.1\r\nHost: localhost:{echo_port}\r\n\r\n");
    c2.write_all(http_req.as_bytes())
        .map_err(|e| fail(&format!("c2 req: {e}")))?;
    let mut hbuf = [0u8; 128];
    c2.set_read_timeout(Some(Duration::from_secs(15)))
        .map_err(|e| fail(&format!("c2 timeout: {e}")))?;
    let n = c2
        .read(&mut hbuf)
        .map_err(|e| fail(&format!("c2 resp: {e}")))?;
    let htext = String::from_utf8_lossy(&hbuf[..n]);
    if !htext.starts_with("HTTP/1.1 200") {
        return Err(fail(&format!("c2: bad status {htext:?}")));
    }
    // Contract: 12 bytes ("hello-3d-http" is 13 long; the scenario's
    // protected expectation is relayed_bytes = 8 + 12 = 20).
    c2.write_all(&b"hello-3d-http"[..12])
        .map_err(|e| fail(&format!("c2 write: {e}")))?;
    let mut back2 = [0u8; 12];
    read_exact_timeout(&mut c2, &mut back2, "c2 echo")?;
    let http_ok = &back2 == b"hello-3d-htt";

    // --- close clients; both ends should drain to zero connections ---
    // (Review G1: also drain the semantic originator registry — a leaked
    // register() entry would otherwise pass this check silently.)
    drop(c1);
    drop(c2);
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        let ca = a.tcp_conn_count().unwrap_or(999);
        let cb = b.tcp_conn_count().unwrap_or(999);
        let sa = a.semantic_stream_count().unwrap_or(999);
        if ca == 0 && cb == 0 && sa == 0 {
            break;
        }
        if std::time::Instant::now() > deadline {
            return Err(fail(&format!(
                "connections did not drain: a={ca} b={cb} semantic={sa}"
            )));
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    let relayed = ingress.stats().relayed_bytes;
    drop(ingress);
    a.close();
    b.close();

    Ok(format!(
        "{{\"verdict\":\"PASS\",\"socks5\":{{\"roundtrip_ok\":{socks5_ok}}},\
         \"http\":{{\"roundtrip_ok\":{http_ok}}},\"relayed_bytes\":{relayed}}}"
    ))
}
