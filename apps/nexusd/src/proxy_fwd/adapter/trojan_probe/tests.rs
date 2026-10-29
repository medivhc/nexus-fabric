//! Trojan 凭据探测单测（PRODUCT §11.9.5 / MODULE P6；test review
//! `test-review-nexusd-trojan-probe-r1` 列出的 U1–U5、I1–I12）。
//!
//! 本地 TLS Trojan 节点（自签）按用例扮演：密码错误时的 fallback（回 404）、密码正确时
//! 对探测目标 close_notify / 直接关 TCP / RST / 不应答，以及对其他目标回显。节点记录每条
//! 连接解密后的请求字节、SNI 与协商出的 ALPN。

use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use nexus_outbound_trojan::{
    TrojanTarget, generate_loopback_identity, parse_request, server_config,
};
use nexus_projection::egress::FlowKey;
use nexus_projection::transparent::{ProxyEgressEvent, ProxyFlowEgress};
use nexus_proxy_transport::TrojanTlsConfig;

use super::*;
use crate::proxy_fwd::{OutboundRegistry, ProxyEngine};
use crate::tproxy_egress::StreamProxyEgress;

const NODE_PASSWORD: &str = "node-password";
const WRONG_PASSWORD: &str = "wrong-password";
const NOT_FOUND: &[u8] =
    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
/// 流拨号的目标（节点对非探测目标只回显，不真正连接）。
const FLOW_TARGET: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 18080));

// ---- U1–U3：缓存、有效期与间隔（时间由参数注入） ----

fn at(base: Instant, ms: u64) -> Instant {
    base + Duration::from_millis(ms)
}

#[test]
fn passed_is_cached_for_ten_minutes_from_probe_end() {
    let t0 = Instant::now();
    let mut state = GateState::default();
    assert_eq!(state.decide(t0), Decision::Probe);
    state.in_flight = true;
    assert_eq!(state.decide(t0), Decision::Wait);
    state.record(Verdict::Passed, t0);
    assert!(!state.in_flight);
    assert_eq!(
        state.decide(at(t0, 599_999)),
        Decision::Use(Verdict::Passed)
    );
    assert_eq!(state.decide(at(t0, 600_000)), Decision::Probe);
}

#[test]
fn rejected_is_cached_for_sixty_seconds_and_a_reprobe_replaces_it() {
    let t0 = Instant::now();
    let mut state = GateState::default();
    state.record(Verdict::Rejected, t0);
    assert_eq!(
        state.decide(at(t0, 59_999)),
        Decision::Use(Verdict::Rejected)
    );
    assert_eq!(state.decide(at(t0, 60_000)), Decision::Probe);
    state.record(Verdict::Passed, at(t0, 61_000));
    assert_eq!(state.decide(at(t0, 61_001)), Decision::Use(Verdict::Passed));
}

#[test]
fn inconclusive_is_not_cached_and_spaces_probes_by_ten_seconds() {
    let t0 = Instant::now();
    let mut state = GateState::default();
    state.record(Verdict::Passed, t0);
    // inconclusive 清掉先前的 passed，不缓存自身；间隔从这次探测结束起算。
    state.record(Verdict::Inconclusive, at(t0, 1_000));
    assert_eq!(
        state.decide(at(t0, 1_000)),
        Decision::Use(Verdict::Inconclusive)
    );
    assert_eq!(
        state.decide(at(t0, 10_999)),
        Decision::Use(Verdict::Inconclusive)
    );
    assert_eq!(state.decide(at(t0, 11_000)), Decision::Probe);
    state.record(Verdict::Rejected, at(t0, 12_000));
    assert_eq!(
        state.decide(at(t0, 12_001)),
        Decision::Use(Verdict::Rejected)
    );
}

// ---- single-flight（闸门层） ----

#[test]
fn concurrent_callers_share_one_probe() {
    let gate = ProbeGate::new("t".to_string());
    let probes = Mutex::new(0usize);
    let verdicts: Vec<Verdict> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..4)
            .map(|_| {
                scope.spawn(|| {
                    gate.verdict(|| {
                        *probes.lock().expect("lock") += 1;
                        std::thread::sleep(Duration::from_millis(300));
                        ProbeReport {
                            verdict: Verdict::Rejected,
                            first_bytes: b"x".to_vec(),
                            elapsed: Duration::from_millis(300),
                        }
                    })
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("join"))
            .collect()
    });
    assert_eq!(*probes.lock().expect("lock"), 1);
    assert_eq!(verdicts, vec![Verdict::Rejected; 4]);
}

#[test]
fn a_panicking_probe_does_not_wedge_the_gate() {
    let gate = ProbeGate::new("t".to_string());
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        gate.verdict(|| panic!("probe panicked"))
    }));
    assert!(unwound.is_err());
    let verdict = gate.verdict(|| ProbeReport {
        verdict: Verdict::Passed,
        first_bytes: Vec::new(),
        elapsed: Duration::ZERO,
    });
    assert_eq!(verdict, Verdict::Passed);
}

// ---- U5：stderr 行 ----

#[test]
fn log_line_format_per_verdict() {
    let rejected = ProbeReport {
        verdict: Verdict::Rejected,
        first_bytes: NOT_FOUND.to_vec(),
        elapsed: Duration::from_millis(12),
    };
    // 前 16 字节 = "HTTP/1.1 404 Not"。
    assert_eq!(
        log_line("t1", &rejected),
        "[nexusd] WARN trojan credential probe tag=t1 result=rejected elapsed_ms=12 \
         first_bytes_hex=485454502f312e3120343034204e6f74"
    );
    for (verdict, word) in [
        (Verdict::Passed, "passed"),
        (Verdict::Inconclusive, "inconclusive"),
    ] {
        let report = ProbeReport {
            verdict,
            first_bytes: Vec::new(),
            elapsed: Duration::from_millis(3001),
        };
        assert_eq!(
            log_line("t1", &report),
            format!(
                "[nexusd] trojan credential probe tag=t1 result={word} elapsed_ms=3001 first_bytes_hex="
            )
        );
    }
}

// ---- 本地 TLS Trojan 节点 ----

/// 节点对一条连接的应答方式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reply {
    /// 回 404 后 close_notify 关闭（fallback）。
    Fallback,
    /// close_notify 后关闭。
    CloseNotify,
    /// 不发 close_notify，直接关 TCP。
    CloseTcp,
    /// `SO_LINGER 0` 关闭：RST。
    Reset,
    /// 不写不关（5 s）。
    Silent,
}

#[derive(Clone)]
struct Spec {
    /// 密码错误时的应答。
    on_wrong: Reply,
    /// 密码正确、目标为探测目标时的应答。
    on_probe: Reply,
    /// 应答前的延迟。
    delay: Duration,
    /// 服务端 ALPN（空 = 不协商）。
    alpn: Vec<Vec<u8>>,
    /// 接受 TCP 后不握手，直接 RST（握手阶段失败）。
    reset_on_accept: bool,
}

impl Default for Spec {
    fn default() -> Self {
        Self {
            on_wrong: Reply::Fallback,
            on_probe: Reply::CloseNotify,
            delay: Duration::ZERO,
            alpn: Vec::new(),
            reset_on_accept: false,
        }
    }
}

#[derive(Debug, Clone)]
struct Conn {
    accepted_at: Instant,
    replied_at: Option<Instant>,
    bytes: Vec<u8>,
    sni: Option<String>,
    alpn: Option<Vec<u8>>,
}

impl Conn {
    fn is_probe(&self) -> bool {
        self.bytes
            .windows(PROBE_HOST.len())
            .any(|w| w == PROBE_HOST.as_bytes())
    }
}

struct Node {
    addr: SocketAddr,
    conns: Arc<Mutex<Vec<Conn>>>,
}

impl Node {
    fn spawn(spec: Spec) -> Self {
        let identity = generate_loopback_identity().expect("identity");
        let mut cfg = server_config(&identity).expect("server config");
        cfg.alpn_protocols = spec.alpn.clone();
        let cfg = Arc::new(cfg);
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let conns = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&conns);
        std::thread::spawn(move || {
            for sock in listener.incoming().flatten() {
                let (cfg, spec, log) = (Arc::clone(&cfg), spec.clone(), Arc::clone(&log));
                std::thread::spawn(move || {
                    let _ = serve(sock, &cfg, &spec, &log);
                });
            }
        });
        Self { addr, conns }
    }

    fn conns(&self) -> Vec<Conn> {
        // 给节点线程留时间记账。
        std::thread::sleep(Duration::from_millis(50));
        self.conns.lock().expect("lock").clone()
    }

    fn probes(&self) -> usize {
        self.conns().iter().filter(|c| c.is_probe()).count()
    }

    fn flows(&self) -> usize {
        self.conns().iter().filter(|c| !c.is_probe()).count()
    }
}

fn linger_zero(sock: &TcpStream) {
    let _ = socket2::SockRef::from(sock).set_linger(Some(Duration::ZERO));
}

/// Trojan 请求头的结束位置：56 字节哈希 + CRLF + 地址行 + CRLF。
fn header_end(bytes: &[u8]) -> Option<usize> {
    let rest = bytes.get(58..)?;
    rest.windows(2)
        .position(|w| w == b"\r\n")
        .map(|pos| 58 + pos + 2)
}

fn serve(
    sock: TcpStream,
    cfg: &Arc<rustls::ServerConfig>,
    spec: &Spec,
    log: &Mutex<Vec<Conn>>,
) -> io::Result<()> {
    let index = {
        let mut conns = log.lock().map_err(|_| io::Error::other("lock"))?;
        conns.push(Conn {
            accepted_at: Instant::now(),
            replied_at: None,
            bytes: Vec::new(),
            sni: None,
            alpn: None,
        });
        conns.len() - 1
    };
    let update = |f: &mut dyn FnMut(&mut Conn)| {
        if let Ok(mut conns) = log.lock() {
            f(&mut conns[index]);
        }
    };
    if spec.reset_on_accept {
        std::thread::sleep(Duration::from_millis(50));
        linger_zero(&sock);
        return Ok(());
    }
    sock.set_read_timeout(Some(Duration::from_secs(2)))?;
    let connection = rustls::ServerConnection::new(Arc::clone(cfg)).map_err(io::Error::other)?;
    let mut tls = rustls::StreamOwned::new(connection, sock);
    while tls.conn.is_handshaking() {
        tls.conn.complete_io(&mut tls.sock)?;
    }
    let sni = tls.conn.server_name().map(str::to_string);
    let alpn = tls.conn.alpn_protocol().map(<[u8]>::to_vec);
    update(&mut |c| {
        c.sni.clone_from(&sni);
        c.alpn.clone_from(&alpn);
    });

    let mut bytes = Vec::new();
    let mut buf = [0u8; 4096];
    let end = loop {
        if let Some(end) = header_end(&bytes) {
            break end;
        }
        let n = tls.read(&mut buf)?;
        if n == 0 {
            return Ok(());
        }
        bytes.extend_from_slice(&buf[..n]);
    };
    let target = parse_request(NODE_PASSWORD, &bytes[..end]);
    let reply = match &target {
        Err(_) => Some(spec.on_wrong),
        Ok(TrojanTarget::Domain(host, port)) if host == PROBE_HOST && *port == PROBE_PORT => {
            Some(spec.on_probe)
        }
        Ok(_) => None,
    };
    if reply.is_some() {
        // 探测请求在请求头之后还有一个 HTTP GET：读到其结尾（≤ 500 ms）以便逐字节断言。
        tls.sock
            .set_read_timeout(Some(Duration::from_millis(500)))?;
        while !bytes[end..].ends_with(b"\r\n\r\n") {
            match tls.read(&mut buf) {
                Ok(n) if n > 0 => bytes.extend_from_slice(&buf[..n]),
                _ => break,
            }
        }
    }
    update(&mut |c| c.bytes.clone_from(&bytes));

    let Some(reply) = reply else {
        // 密码正确、真实目标：回显首包之后的字节，然后回显到 EOF。
        tls.write_all(&bytes[end..])?;
        loop {
            let n = tls.read(&mut buf)?;
            if n == 0 {
                return Ok(());
            }
            tls.write_all(&buf[..n])?;
        }
    };
    std::thread::sleep(spec.delay);
    update(&mut |c| c.replied_at = Some(Instant::now()));
    match reply {
        Reply::Fallback => {
            tls.write_all(NOT_FOUND)?;
            tls.conn.send_close_notify();
            tls.flush()?;
        }
        Reply::CloseNotify => {
            tls.conn.send_close_notify();
            tls.flush()?;
        }
        Reply::CloseTcp => {}
        Reply::Reset => linger_zero(&tls.sock),
        Reply::Silent => std::thread::sleep(Duration::from_secs(5)),
    }
    Ok(())
}

fn probe_config(addr: SocketAddr, password: &str) -> TrojanTlsConfig {
    let mut config = TrojanTlsConfig::new(addr, password.to_string(), "127.0.0.1".to_string());
    config.skip_cert_verify = true;
    config
}

fn closed_port() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.local_addr().expect("addr")
}

// ---- U4 / I3 / I4：判定映射（线缆级） ----

#[test]
fn downstream_bytes_are_rejected_with_first_bytes() {
    let node = Node::spawn(Spec::default());
    let report = run_probe(&probe_config(node.addr, WRONG_PASSWORD));
    assert_eq!(report.verdict, Verdict::Rejected);
    assert_eq!(report.first_bytes, NOT_FOUND[..16].to_vec());
    assert!(report.elapsed < Duration::from_secs(1), "{report:?}");
    let line = log_line("t", &report);
    assert!(!line.contains(WRONG_PASSWORD), "{line}");
    let conns = node.conns();
    let hash = String::from_utf8_lossy(&conns[0].bytes[..56]).to_string();
    assert!(!line.contains(&hash), "{line}");
}

#[test]
fn zero_byte_close_or_reset_is_passed() {
    for reply in [Reply::CloseNotify, Reply::CloseTcp, Reply::Reset] {
        let node = Node::spawn(Spec {
            on_probe: reply,
            ..Spec::default()
        });
        let report = run_probe(&probe_config(node.addr, NODE_PASSWORD));
        assert_eq!(report.verdict, Verdict::Passed, "{reply:?}");
        assert!(report.first_bytes.is_empty(), "{reply:?}");
        assert!(
            report.elapsed < Duration::from_secs(1),
            "{reply:?}: {report:?}"
        );
    }
}

#[test]
fn silence_for_the_read_window_is_inconclusive_after_three_seconds() {
    let node = Node::spawn(Spec {
        on_probe: Reply::Silent,
        ..Spec::default()
    });
    let report = run_probe(&probe_config(node.addr, NODE_PASSWORD));
    assert_eq!(report.verdict, Verdict::Inconclusive);
    assert!(
        report.elapsed >= Duration::from_secs(3) && report.elapsed < Duration::from_millis(3_800),
        "{report:?}"
    );
}

#[test]
fn connect_handshake_or_reset_failures_are_inconclusive() {
    let report = run_probe(&probe_config(closed_port(), NODE_PASSWORD));
    assert_eq!(report.verdict, Verdict::Inconclusive);

    let node = Node::spawn(Spec {
        reset_on_accept: true,
        ..Spec::default()
    });
    let report = run_probe(&probe_config(node.addr, NODE_PASSWORD));
    assert_eq!(report.verdict, Verdict::Inconclusive);

    // 自签节点 + 严格校验：TLS 握手失败。
    let node = Node::spawn(Spec::default());
    let mut config = probe_config(node.addr, NODE_PASSWORD);
    config.skip_cert_verify = false;
    let report = run_probe(&config);
    assert_eq!(report.verdict, Verdict::Inconclusive);
}

// ---- 经 OutboundRegistry 的拨号（I1、I2、I4–I10、I12） ----

fn trojan_outbound(tag: &str, addr: SocketAddr, password: &str, extra: &str) -> String {
    format!(
        "  - tag: {tag}\n    kind: trojan\n    locator: {addr}\n    password: {password}\n    skip_cert_verify: true\n{extra}"
    )
}

fn yaml(outbounds: &[String]) -> String {
    format!(
        "schema_version: 1\nrules:\n  - tag: r1\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: t\noutbounds:\n{}",
        outbounds.concat()
    )
}

fn registry(yaml: &str) -> Arc<OutboundRegistry> {
    OutboundRegistry::build(Some(yaml))
        .expect("registry")
        .expect("some registry")
}

/// 拨号；失败时返回 `reason()`。
fn dial(registry: &OutboundRegistry, tag: &str) -> Result<(), &'static str> {
    registry
        .dialer(tag)
        .expect("dialer")
        .dial_tcp(FLOW_TARGET)
        .map(|_| ())
        .map_err(|error| error.reason())
}

#[test]
fn probe_request_bytes_are_exact() {
    let node = Node::spawn(Spec::default());
    let reg = registry(&yaml(&[trojan_outbound("t", node.addr, NODE_PASSWORD, "")]));
    dial(&reg, "t").expect("passed then dialed");
    let conns = node.conns();
    let probe = conns.iter().find(|c| c.is_probe()).expect("probe");
    let hash = &probe.bytes[..56];
    assert!(
        hash.iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b)),
        "lowercase hex SHA-224"
    );
    let mut expected = hash.to_vec();
    expected.extend_from_slice(b"\r\n\x01\x03\x1ecredential-probe.nexus.invalid\x00\x09\r\n");
    expected.extend_from_slice(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    assert_eq!(probe.bytes, expected);
    assert!(matches!(
        parse_request(NODE_PASSWORD, &probe.bytes[..header_end(&probe.bytes).expect("header")]),
        Ok(TrojanTarget::Domain(host, PROBE_PORT)) if host == PROBE_HOST
    ));

    // header_format: singbox 的探测字节与 standard 完全相同。
    let node2 = Node::spawn(Spec::default());
    let reg = registry(&yaml(&[trojan_outbound(
        "t",
        node2.addr,
        NODE_PASSWORD,
        "    header_format: singbox\n",
    )]));
    dial(&reg, "t").expect("passed then dialed");
    let singbox = node2
        .conns()
        .into_iter()
        .find(Conn::is_probe)
        .expect("probe");
    assert_eq!(singbox.bytes, expected);
}

#[test]
fn probe_uses_the_dial_sni_and_alpn() {
    let node = Node::spawn(Spec {
        alpn: vec![b"http/1.1".to_vec()],
        ..Spec::default()
    });
    let extra = "    sni: probe.example\n    alpn: [h2, http/1.1]\n";
    let reg = registry(&yaml(&[trojan_outbound(
        "t",
        node.addr,
        NODE_PASSWORD,
        extra,
    )]));
    dial(&reg, "t").expect("passed then dialed");
    let conns = node.conns();
    let probe = conns.iter().find(|c| c.is_probe()).expect("probe");
    let flow = conns.iter().find(|c| !c.is_probe()).expect("flow");
    assert_eq!(probe.sni.as_deref(), Some("probe.example"));
    assert_eq!(probe.sni, flow.sni);
    assert_eq!(probe.alpn.as_deref(), Some(b"http/1.1".as_slice()));
    assert_eq!(probe.alpn, flow.alpn);
    let text = String::from_utf8_lossy(&probe.bytes);
    assert!(text.contains("\r\nHost: probe.example\r\n"), "{text}");
}

#[test]
fn rejected_dials_fail_auth_rejected_without_new_connections() {
    let node = Node::spawn(Spec::default());
    let reg = registry(&yaml(&[trojan_outbound(
        "t",
        node.addr,
        WRONG_PASSWORD,
        "",
    )]));
    for _ in 0..3 {
        assert_eq!(dial(&reg, "t"), Err("auth_rejected"));
    }
    let conns = node.conns();
    assert_eq!(conns.len(), 1, "one probe, no flow connections: {conns:?}");
    assert!(conns[0].is_probe());
}

#[test]
fn inconclusive_dials_normally_and_spaces_the_next_probe() {
    let node = Node::spawn(Spec {
        on_probe: Reply::Silent,
        ..Spec::default()
    });
    let reg = registry(&yaml(&[trojan_outbound("t", node.addr, NODE_PASSWORD, "")]));
    dial(&reg, "t").expect("inconclusive dials");
    dial(&reg, "t").expect("within 10 s: no probe, dials");
    assert_eq!(node.probes(), 1);
    assert_eq!(node.flows(), 2);
}

#[test]
fn inconclusive_probe_leaves_the_dial_failure_reason_to_the_dial() {
    // 端口关闭 / 自签节点 + 严格校验：探测 inconclusive，拨号自身的失败原因与关闭探测时
    // 完全相同（探测不改写拨号的失败语义）。
    let node = Node::spawn(Spec::default());
    for (addr, verify) in [(closed_port(), "true"), (node.addr, "false")] {
        let outbound = |probe: bool| {
            format!(
                "  - tag: t\n    kind: trojan\n    locator: {addr}\n    password: {NODE_PASSWORD}\n    skip_cert_verify: {verify}\n    credential_probe: {probe}\n"
            )
        };
        let without_probe = dial(&registry(&yaml(&[outbound(false)])), "t");
        let with_probe = dial(&registry(&yaml(&[outbound(true)])), "t");
        assert!(without_probe.is_err(), "{addr}");
        assert_ne!(with_probe, Err("auth_rejected"), "{addr}");
        assert_eq!(with_probe, without_probe, "{addr}");
    }
}

#[test]
fn outbounds_keep_separate_probe_state() {
    let wrong = Node::spawn(Spec::default());
    let right = Node::spawn(Spec::default());
    let reg = registry(&yaml(&[
        trojan_outbound("t", wrong.addr, WRONG_PASSWORD, ""),
        trojan_outbound("b", right.addr, NODE_PASSWORD, ""),
    ]));
    for _ in 0..2 {
        assert_eq!(dial(&reg, "t"), Err("auth_rejected"));
        dial(&reg, "b").expect("b passed");
    }
    assert_eq!((wrong.probes(), wrong.flows()), (1, 0));
    assert_eq!((right.probes(), right.flows()), (1, 2));
}

#[test]
fn non_trojan_outbounds_ignore_credential_probe() {
    for (kind, extra) in [
        ("socks5", ""),
        (
            "shadowsocks",
            "    method: chacha20-ietf-poly1305\n    password: pwd\n",
        ),
        ("vless", "    uuid: 123e4567-e89b-12d3-a456-426614174000\n"),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let accepted = Arc::new(Mutex::new(0usize));
        let counter = Arc::clone(&accepted);
        std::thread::spawn(move || {
            for sock in listener.incoming().flatten() {
                *counter.lock().expect("lock") += 1;
                drop(sock);
            }
        });
        let outbound = format!(
            "  - tag: t\n    kind: {kind}\n    locator: {addr}\n{extra}    credential_probe: true\n"
        );
        let reg = registry(&yaml(&[outbound]));
        let _ = dial(&reg, "t");
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(*accepted.lock().expect("lock"), 1, "{kind}");
    }
}

#[test]
fn credential_probe_false_never_probes() {
    let node = Node::spawn(Spec::default());
    let reg = registry(&yaml(&[trojan_outbound(
        "t",
        node.addr,
        NODE_PASSWORD,
        "    credential_probe: false\n",
    )]));
    dial(&reg, "t").expect("dial");
    dial(&reg, "t").expect("dial");
    assert_eq!((node.probes(), node.flows()), (0, 2));
}

fn concurrent_dials(reg: &OutboundRegistry) -> Vec<Result<(), &'static str>> {
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..4).map(|_| scope.spawn(|| dial(reg, "t"))).collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("join"))
            .collect()
    })
}

#[test]
fn concurrent_first_dials_wait_for_one_probe_wrong_password() {
    let node = Node::spawn(Spec {
        delay: Duration::from_millis(500),
        ..Spec::default()
    });
    let reg = registry(&yaml(&[trojan_outbound(
        "t",
        node.addr,
        WRONG_PASSWORD,
        "",
    )]));
    assert_eq!(concurrent_dials(&reg), vec![Err("auth_rejected"); 4]);
    assert_eq!(node.conns().len(), 1);
}

#[test]
fn concurrent_first_dials_wait_for_one_probe_right_password() {
    let node = Node::spawn(Spec {
        delay: Duration::from_millis(500),
        ..Spec::default()
    });
    let reg = registry(&yaml(&[trojan_outbound("t", node.addr, NODE_PASSWORD, "")]));
    assert_eq!(concurrent_dials(&reg), vec![Ok(()); 4]);
    let conns = node.conns();
    let probe = conns.iter().find(|c| c.is_probe()).expect("probe");
    let replied = probe.replied_at.expect("replied");
    let flows: Vec<_> = conns.iter().filter(|c| !c.is_probe()).collect();
    assert_eq!(flows.len(), 4);
    assert_eq!(conns.len(), 5);
    assert!(
        flows.iter().all(|f| f.accepted_at >= replied),
        "no dial connects before the probe result"
    );
}

#[test]
fn each_registry_build_starts_with_empty_probe_state() {
    let node = Node::spawn(Spec::default());
    let text = yaml(&[trojan_outbound("t", node.addr, WRONG_PASSWORD, "")]);
    assert_eq!(dial(&registry(&text), "t"), Err("auth_rejected"));
    assert_eq!(dial(&registry(&text), "t"), Err("auth_rejected"));
    assert_eq!(node.probes() + node.flows(), 2, "one probe per registry");
}

#[test]
fn tproxy_open_fails_auth_rejected_and_shares_the_tun_dialer_state() {
    let node = Node::spawn(Spec::default());
    let reg = registry(&yaml(&[trojan_outbound(
        "t",
        node.addr,
        WRONG_PASSWORD,
        "",
    )]));
    let mut egress = StreamProxyEgress::from_registry(Arc::clone(&reg)).expect("egress");
    let key = FlowKey {
        src_ip: u32::from(Ipv4Addr::new(10, 0, 0, 3)),
        dst_ip: u32::from(Ipv4Addr::LOCALHOST),
        src_port: 40001,
        dst_port: 18080,
        proto: 6,
    };
    let SocketAddr::V4(orig_dst) = FLOW_TARGET else {
        unreachable!("FLOW_TARGET is IPv4")
    };
    egress.open_tcp(key, orig_dst, "t").expect("open");
    let deadline = Instant::now() + Duration::from_secs(10);
    let reason = loop {
        let failed = egress.poll().into_iter().find_map(|event| match event {
            ProxyEgressEvent::Failed { key: k, reason } if k == key => Some(reason),
            _ => None,
        });
        if let Some(reason) = failed {
            break reason;
        }
        assert!(Instant::now() < deadline, "no Failed event");
        std::thread::sleep(Duration::from_millis(10));
    };
    assert!(reason.contains("AuthRejected"), "{reason}");
    // TUN 侧同一 tag 共用 dialer：不再探测，直接拒绝。
    assert_eq!(dial(&reg, "t"), Err("auth_rejected"));
    assert_eq!(node.conns().len(), 1, "one probe, no flow connections");
}

// ---- I11 / I13：探测在拨号 worker 上进行；不计入流统计 ----

/// 16 位反码和（IPv4 头 / TCP 伪首部校验和）。
fn ones_complement(words: impl Iterator<Item = u16>) -> u16 {
    let mut sum: u32 = words.map(u32::from).sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

fn be_words(bytes: &[u8]) -> impl Iterator<Item = u16> + '_ {
    bytes
        .chunks(2)
        .map(|w| u16::from_be_bytes([w[0], w.get(1).copied().unwrap_or(0)]))
}

/// 带正确校验和的 IPv4 TCP 段（10.0.0.2:40000 → 127.0.0.1:18080，无载荷）。
fn craft_tcp(seq: u32, ack: u32, flags: u8) -> Vec<u8> {
    let mut pkt = vec![0u8; 40];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&40u16.to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 6;
    pkt[12..16].copy_from_slice(&[10, 0, 0, 2]);
    pkt[16..20].copy_from_slice(&[127, 0, 0, 1]);
    let ip = ones_complement(be_words(&pkt[..20]));
    pkt[10..12].copy_from_slice(&ip.to_be_bytes());
    pkt[20..22].copy_from_slice(&40000u16.to_be_bytes());
    pkt[22..24].copy_from_slice(&FLOW_TARGET.port().to_be_bytes());
    pkt[24..28].copy_from_slice(&seq.to_be_bytes());
    pkt[28..32].copy_from_slice(&ack.to_be_bytes());
    pkt[32] = 0x50;
    pkt[33] = flags;
    pkt[34..36].copy_from_slice(&8192u16.to_be_bytes());
    let pseudo = [&pkt[12..20], &[0, 6, 0, 20]].concat();
    let tcp = ones_complement(be_words(&pseudo).chain(be_words(&pkt[20..40])));
    pkt[36..38].copy_from_slice(&tcp.to_be_bytes());
    pkt
}

/// 引擎写回的 SYN-ACK 的序号。
fn syn_ack_seq(packets: &[Vec<u8>]) -> Option<u32> {
    packets.iter().find_map(|pkt| {
        (pkt.len() >= 40 && pkt[9] == 6 && pkt[33] & 0x12 == 0x12)
            .then(|| u32::from_be_bytes([pkt[24], pkt[25], pkt[26], pkt[27]]))
    })
}

#[test]
fn a_pending_probe_does_not_block_the_engine_and_is_not_a_stream() {
    let node = Node::spawn(Spec {
        on_probe: Reply::Silent,
        ..Spec::default()
    });
    let reg = registry(&yaml(&[trojan_outbound("t", node.addr, NODE_PASSWORD, "")]));
    let mut engine = ProxyEngine::from_registry(reg).expect("engine");
    let started = Instant::now();
    // 终结器在三次握手完成后才发出 Syn 事件并开始拨号。
    let mut written = engine
        .handle_packet(&craft_tcp(1000, 0, 0x02), "t")
        .expect("syn")
        .tun_packets;
    written.extend(engine.poll().tun_packets);
    let server_seq = syn_ack_seq(&written).expect("SYN-ACK");
    engine
        .handle_packet(&craft_tcp(1001, server_seq.wrapping_add(1), 0x10), "t")
        .expect("ack");
    let mut slowest = started.elapsed();
    // 探测进行中（节点不应答，3 s 读窗口）：引擎调用保持快速返回。
    while Instant::now() < started + Duration::from_secs(2) {
        let call = Instant::now();
        let _ = engine.poll();
        slowest = slowest.max(call.elapsed());
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(node.probes(), 1, "probe pending");
    assert!(
        slowest < Duration::from_millis(50),
        "slowest call {slowest:?}"
    );
    // 探测 inconclusive 后照常拨号：只有一条流计入。
    let deadline = Instant::now() + Duration::from_secs(10);
    while engine.stats().tcp_dials_ok == 0 && Instant::now() < deadline {
        let _ = engine.poll();
        std::thread::sleep(Duration::from_millis(10));
    }
    let stats = engine.stats();
    assert_eq!(
        (
            stats.tcp_streams,
            stats.tcp_dials_ok,
            stats.tcp_dials_failed
        ),
        (1, 1, 0)
    );
    assert_eq!(node.flows(), 1);
}
