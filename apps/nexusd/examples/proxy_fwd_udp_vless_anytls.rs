//! E4 产品场景 `product.proxy-fwd-udp-vless-anytls` 的可执行驱动（PRODUCT §11.18.1）。
//!
//! ```text
//! cargo run --quiet -p nexusd --example proxy_fwd_udp_vless_anytls -- --json
//! ```
//!
//! 全 loopback、离线：
//! - 两个本地 UDP echo（回 `echo:` + 载荷，区分回包与原包）；
//! - 本地 VLESS 节点（明文 TCP）：只接受 `command = UDP` 的请求，按目标地址记账，
//!   把长度前缀数据报中继到目标并把回包按同一帧格式写回；
//! - 本地 AnyTLS 节点（TLS 自签）：认证后接受 UoT v2 connect 模式 stream，按目标记账，
//!   PSH 内的长度前缀数据报中继到目标并回写；
//! - TUN 轮：MockTun + 生产 `Dataplane` / `ProxyEngine`，向两个目的地址各发 2 个数据报；
//! - TPROXY 轮：生产 `StreamProxyEgress`（TPROXY 前端的代理出口），2 个数据报。

use std::collections::{HashMap, HashSet};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use nexus_outbound_anytls as anytls;
use nexus_outbound_vless as vless;
use nexus_projection::egress::FlowKey;
use nexus_projection::transparent::{ProxyEgressEvent, ProxyFlowEgress};
use nexus_projection::{MockTun, TunDevice};
use nexusd::dataplane::{Dataplane, DataplaneConfig};
use nexusd::proxy_fwd::{OutboundRegistry, ProxyEngine};
use nexusd::tproxy_egress::StreamProxyEgress;
use serde_json::{Value, json};

const VLESS_UUID: &str = "11111111-1111-1111-1111-111111111111";
const ANYTLS_PASSWORD: &str = "e4-udp-password";
const TUN_SRC: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 5000);
const TPROXY_SRC: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 3), 5001);
/// 一轮从发出到收齐回包的上限（建流 + TLS 握手 + 中继）。
const ROUND_DEADLINE: Duration = Duration::from_secs(10);

/// 节点侧记账：每个目标地址打开过的流数。
type StreamLog = Arc<Mutex<HashMap<SocketAddr, usize>>>;

struct SharedTun(Arc<Mutex<MockTun>>);

impl TunDevice for SharedTun {
    fn name(&self) -> &str {
        "udp-proxy0"
    }
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0
            .lock()
            .map_err(|_| io::Error::other("mock poisoned"))?
            .read(buf)
    }
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .map_err(|_| io::Error::other("mock poisoned"))?
            .write(buf)
    }
}

fn echo_reply(payload: &[u8]) -> Vec<u8> {
    [b"echo:".as_slice(), payload].concat()
}

/// 本地 UDP echo：每个数据报回 `echo:` + 载荷。
fn spawn_udp_echo() -> Result<SocketAddr, String> {
    let socket = UdpSocket::bind("127.0.0.1:0").map_err(|e| format!("bind echo: {e}"))?;
    let addr = socket.local_addr().map_err(|e| e.to_string())?;
    std::thread::spawn(move || {
        let mut buf = [0u8; 2048];
        while let Ok((n, from)) = socket.recv_from(&mut buf) {
            let _ = socket.send_to(&echo_reply(&buf[..n]), from);
        }
    });
    Ok(addr)
}

/// 经一次 UDP 往返取 echo 回包（节点侧把数据报交给真实目标）。
fn relay_once(target: SocketAddr, datagram: &[u8]) -> io::Result<Vec<u8>> {
    let socket = UdpSocket::bind("127.0.0.1:0")?;
    socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    socket.send_to(datagram, target)?;
    let mut buf = [0u8; 2048];
    let (n, _) = socket.recv_from(&mut buf)?;
    Ok(buf[..n].to_vec())
}

fn spawn_vless_node(log: StreamLog) -> Result<SocketAddr, String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("bind vless: {e}"))?;
    let addr = listener.local_addr().map_err(|e| e.to_string())?;
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let log = Arc::clone(&log);
            std::thread::spawn(move || {
                let _ = serve_vless(stream, log);
            });
        }
    });
    Ok(addr)
}

fn serve_vless(mut stream: TcpStream, log: StreamLog) -> Result<(), String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(70)))
        .map_err(|e| e.to_string())?;
    let mut header = Vec::new();
    let mut buf = [0u8; 2048];
    let (request, used) = loop {
        match vless::decode_request(&header) {
            Ok(done) => break done,
            Err(vless::VlessError::TruncatedHeader) => {
                let n = stream.read(&mut buf).map_err(|e| e.to_string())?;
                if n == 0 {
                    return Err("vless client closed before the header".into());
                }
                header.extend_from_slice(&buf[..n]);
            }
            Err(e) => return Err(format!("vless header: {e}")),
        }
    };
    if request.command != vless::VlessCommand::Udp {
        return Err("this node only serves UDP".into());
    }
    let Some(vless::VlessTarget::Ipv4(ip)) = request.target else {
        return Err("expected an IPv4 UDP target".into());
    };
    let target = SocketAddr::new(IpAddr::V4(ip), request.port);
    if let Ok(mut log) = log.lock() {
        *log.entry(target).or_default() += 1;
    }
    stream
        .write_all(&vless::encode_response(&vless::VlessResponse {
            version: 0,
            addon: Vec::new(),
        }))
        .map_err(|e| e.to_string())?;
    let mut reader = io::Cursor::new(header[used..].to_vec())
        .chain(stream.try_clone().map_err(|e| e.to_string())?);
    while let Ok(datagram) = vless::read_udp_datagram(&mut reader) {
        let reply = relay_once(target, &datagram).map_err(|e| e.to_string())?;
        let framed = vless::encode_udp_datagram(&reply).map_err(|e| e.to_string())?;
        stream.write_all(&framed).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn spawn_anytls_node(
    log: StreamLog,
    identity: &anytls::LoopbackIdentity,
) -> Result<SocketAddr, String> {
    let cfg = Arc::new(
        anytls::server_config(&identity).map_err(|e| format!("anytls server config: {e:?}"))?,
    );
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("bind anytls: {e}"))?;
    let addr = listener.local_addr().map_err(|e| e.to_string())?;
    std::thread::spawn(move || {
        for sock in listener.incoming().flatten() {
            let cfg = Arc::clone(&cfg);
            let log = Arc::clone(&log);
            std::thread::spawn(move || {
                let _ = serve_anytls(sock, cfg, log);
            });
        }
    });
    Ok(addr)
}

/// AnyTLS UoT stream 状态（connect 模式：魔法地址 → `0x01` + 真实目标 → 数据报）。
enum UotState {
    AwaitMagic,
    AwaitConnect,
    Ready(SocketAddr),
}

fn serve_anytls(
    sock: TcpStream,
    cfg: Arc<rustls::ServerConfig>,
    log: StreamLog,
) -> Result<(), String> {
    sock.set_read_timeout(Some(Duration::from_secs(70)))
        .map_err(|e| e.to_string())?;
    let conn = rustls::ServerConnection::new(cfg).map_err(|e| e.to_string())?;
    let mut tls = rustls::StreamOwned::new(conn, sock);
    anytls::server_handshake(&mut tls, ANYTLS_PASSWORD, anytls::DEFAULT_PADDING_SCHEME)
        .map_err(|e| format!("anytls handshake: {e:?}"))?;
    let mut streams: HashMap<u32, UotState> = HashMap::new();
    loop {
        let frame = anytls::read_frame(&mut tls).map_err(|e| format!("{e:?}"))?;
        match frame.cmd {
            anytls::AnyTlsCommand::Syn => {
                streams.insert(frame.stream_id, UotState::AwaitMagic);
            }
            anytls::AnyTlsCommand::Fin => {
                streams.remove(&frame.stream_id);
            }
            anytls::AnyTlsCommand::Psh => {
                let Some(state) = streams.get_mut(&frame.stream_id) else {
                    continue;
                };
                let mut data: &[u8] = &frame.data;
                if matches!(state, UotState::AwaitMagic) {
                    let (magic, used) =
                        anytls::decode_socks5_addr(data).map_err(|e| format!("{e:?}"))?;
                    if magic != anytls::uot_magic_target() {
                        return Err("first PSH is not the UoT magic address".into());
                    }
                    data = &data[used..];
                    *state = UotState::AwaitConnect;
                }
                if matches!(state, UotState::AwaitConnect) {
                    if data.is_empty() {
                        continue;
                    }
                    if data[0] != 0x01 {
                        return Err("UoT stream is not in connect mode".into());
                    }
                    let (real, used) =
                        anytls::decode_socks5_addr(&data[1..]).map_err(|e| format!("{e:?}"))?;
                    let anytls::AnyTlsTarget::Ipv4(ip, port) = real else {
                        return Err("expected an IPv4 UoT target".into());
                    };
                    let target = SocketAddr::from((ip, port));
                    if let Ok(mut log) = log.lock() {
                        *log.entry(target).or_default() += 1;
                    }
                    anytls::write_frame(
                        &mut tls,
                        anytls::AnyTlsCommand::SynAck,
                        frame.stream_id,
                        &[],
                    )
                    .map_err(|e| format!("{e:?}"))?;
                    data = &data[1 + used..];
                    *state = UotState::Ready(target);
                }
                let UotState::Ready(target) = *state else {
                    continue;
                };
                if data.is_empty() {
                    continue;
                }
                for datagram in anytls::decode_uot_datagrams(data).map_err(|e| format!("{e:?}"))? {
                    let reply = relay_once(target, &datagram).map_err(|e| e.to_string())?;
                    let framed =
                        anytls::encode_uot_datagram(&reply).map_err(|e| format!("{e:?}"))?;
                    anytls::write_frame(
                        &mut tls,
                        anytls::AnyTlsCommand::Psh,
                        frame.stream_id,
                        &framed,
                    )
                    .map_err(|e| format!("{e:?}"))?;
                }
            }
            _ => {}
        }
    }
}

fn loopback_identity() -> Result<anytls::LoopbackIdentity, String> {
    anytls::generate_loopback_identity().map_err(|e| format!("anytls identity: {e:?}"))
}

/// `--self-test`：用 crate 自带的客户端（不经 nexusd）验证两个本地节点本身可用，
/// 以免把夹具缺陷误判为实现缺陷。
fn self_test(echo: SocketAddr) -> Value {
    let SocketAddr::V4(echo_v4) = echo else {
        return json!({"vless": false, "anytls": false});
    };
    let vless_ok = (|| -> Result<bool, String> {
        let node = spawn_vless_node(Arc::default())?;
        let mut s = TcpStream::connect(node).map_err(|e| e.to_string())?;
        s.set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|e| e.to_string())?;
        let request = vless::VlessRequest {
            uuid: vless::VlessUuid::parse(VLESS_UUID).map_err(|e| e.to_string())?,
            flow: vless::VlessFlow::None,
            command: vless::VlessCommand::Udp,
            port: echo.port(),
            target: Some(vless::VlessTarget::Ipv4(*echo_v4.ip())),
        };
        s.write_all(&vless::encode_request(&request).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        s.write_all(&vless::encode_udp_datagram(b"self").map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        vless::read_response(&mut s).map_err(|e| e.to_string())?;
        Ok(vless::read_udp_datagram(&mut s).map_err(|e| e.to_string())? == echo_reply(b"self"))
    })();
    let anytls_ok = (|| -> Result<bool, String> {
        let identity = loopback_identity()?;
        let node = spawn_anytls_node(Arc::default(), &identity)?;
        let cfg = Arc::new(anytls::client_config(&identity).map_err(|e| format!("{e:?}"))?);
        let sock = TcpStream::connect(node).map_err(|e| e.to_string())?;
        sock.set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|e| e.to_string())?;
        let name =
            rustls::pki_types::ServerName::try_from("localhost").map_err(|e| e.to_string())?;
        let conn = rustls::ClientConnection::new(cfg, name).map_err(|e| e.to_string())?;
        let mut tls = rustls::StreamOwned::new(conn, sock);
        let md5 = anytls::padding_md5_hex(anytls::DEFAULT_PADDING_SCHEME);
        let mut hs =
            anytls::client_handshake(&mut tls, ANYTLS_PASSWORD, 0, anytls::CLIENT_IDENT, &md5)
                .map_err(|e| format!("{e:?}"))?;
        let target = anytls::AnyTlsTarget::Ipv4(echo_v4.ip().octets(), echo.port());
        let id = anytls::client_open_uot_stream(&mut tls, &mut hs, &target)
            .map_err(|e| format!("{e:?}"))?;
        let datagram = anytls::encode_uot_datagram(b"self").map_err(|e| format!("{e:?}"))?;
        anytls::write_frame(&mut tls, anytls::AnyTlsCommand::Psh, id, &datagram)
            .map_err(|e| format!("{e:?}"))?;
        loop {
            let frame = anytls::read_frame(&mut tls).map_err(|e| format!("{e:?}"))?;
            if frame.cmd == anytls::AnyTlsCommand::Psh && frame.stream_id == id {
                let got =
                    anytls::decode_uot_datagrams(&frame.data).map_err(|e| format!("{e:?}"))?;
                return Ok(got == vec![echo_reply(b"self")]);
            }
        }
    })();
    json!({
        "vless": vless_ok.clone().unwrap_or(false),
        "vless_error": vless_ok.err(),
        "anytls": anytls_ok.clone().unwrap_or(false),
        "anytls_error": anytls_ok.err(),
    })
}

fn proxy_yaml(kind: &str, node: SocketAddr) -> String {
    let outbound = match kind {
        "vless" => format!("    kind: vless\n    locator: {node}\n    uuid: {VLESS_UUID}\n"),
        _ => format!(
            "    kind: anytls\n    locator: {node}\n    password: {ANYTLS_PASSWORD}\n    skip_cert_verify: true\n"
        ),
    };
    format!(
        "schema_version: 1\nrules:\n  - tag: r1\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: proxy\noutbounds:\n  - tag: proxy\n{outbound}"
    )
}

fn udp_packet(src: SocketAddrV4, dst: SocketAddr, payload: &[u8]) -> Result<Vec<u8>, String> {
    let IpAddr::V4(dst_ip) = dst.ip() else {
        return Err("destination is not IPv4".into());
    };
    let mut pkt = vec![0u8; 20 + 8 + payload.len()];
    pkt[0] = 0x45;
    let total = u16::try_from(pkt.len()).map_err(|_| "packet too large")?;
    pkt[2..4].copy_from_slice(&total.to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 17;
    pkt[12..16].copy_from_slice(&src.ip().octets());
    pkt[16..20].copy_from_slice(&dst_ip.octets());
    pkt[20..22].copy_from_slice(&src.port().to_be_bytes());
    pkt[22..24].copy_from_slice(&dst.port().to_be_bytes());
    let udp_len = u16::try_from(8 + payload.len()).map_err(|_| "datagram too large")?;
    pkt[24..26].copy_from_slice(&udp_len.to_be_bytes());
    pkt[28..].copy_from_slice(payload);
    Ok(pkt)
}

/// MockTun 写侧的 IPv4/UDP 包 → (源, 目的, 载荷)。
fn parse_udp(pkt: &[u8]) -> Option<(SocketAddr, SocketAddr, Vec<u8>)> {
    if pkt.len() < 28 || pkt[0] >> 4 != 4 || pkt[9] != 17 {
        return None;
    }
    let ihl = usize::from(pkt[0] & 0x0F) * 4;
    let udp = pkt.get(ihl..)?;
    if udp.len() < 8 {
        return None;
    }
    let src = SocketAddr::from((
        [pkt[12], pkt[13], pkt[14], pkt[15]],
        u16::from_be_bytes([udp[0], udp[1]]),
    ));
    let dst = SocketAddr::from((
        [pkt[16], pkt[17], pkt[18], pkt[19]],
        u16::from_be_bytes([udp[2], udp[3]]),
    ));
    Some((src, dst, udp[8..].to_vec()))
}

/// TUN 轮：两个目的地址各 2 个数据报，经生产 Dataplane / ProxyEngine。
fn tun_round(kind: &str, echoes: [SocketAddr; 2]) -> Value {
    let log: StreamLog = Arc::default();
    let result = (|| -> Result<Value, String> {
        let node = match kind {
            "vless" => spawn_vless_node(Arc::clone(&log))?,
            _ => spawn_anytls_node(Arc::clone(&log), &loopback_identity()?)?,
        };
        let yaml = proxy_yaml(kind, node);
        let mock = Arc::new(Mutex::new(MockTun::new("udp-proxy0")));
        let config = DataplaneConfig {
            proxy_configured: true,
            ..Default::default()
        };
        let mut dp = Dataplane::new(Box::new(SharedTun(Arc::clone(&mock))), config, None)
            .map_err(|e| format!("dataplane init: {e}"))?;
        let engine = match ProxyEngine::new(Some(&yaml)) {
            Ok(Some(engine)) => engine,
            Ok(None) => return Err("ProxyEngine::new returned None".into()),
            Err(error) => return Err(format!("engine init: {}", error.variant())),
        };
        dp.set_proxy_engine(engine);
        dp.set_rule_engine(Box::new(
            nexus_proxy::domain_engine::DomainRuleEngine::from_yaml(&yaml)
                .map_err(|e| format!("rule engine: {e}"))?,
        ));
        let epoch = Instant::now();
        let now = || u64::try_from(epoch.elapsed().as_millis()).unwrap_or(u64::MAX);

        let mut expected: HashSet<(SocketAddr, Vec<u8>)> = HashSet::new();
        for (d, echo) in echoes.iter().enumerate() {
            for i in 0..2 {
                let payload = format!("{kind}-tun-{d}-{i}").into_bytes();
                expected.insert((*echo, echo_reply(&payload)));
                mock.lock()
                    .map_err(|e| e.to_string())?
                    .inject(udp_packet(TUN_SRC, *echo, &payload)?);
                dp.tick(now()).map_err(|e| format!("tick: {e}"))?;
            }
        }
        let mut wrong_destination = 0usize;
        let deadline = Instant::now() + ROUND_DEADLINE;
        while !expected.is_empty() && Instant::now() < deadline {
            let _ = dp.tick(now());
            for pkt in mock.lock().map_err(|e| e.to_string())?.take_written() {
                if let Some((src, dst, payload)) = parse_udp(&pkt) {
                    if dst != SocketAddr::V4(TUN_SRC) {
                        wrong_destination += 1;
                    }
                    expected.remove(&(src, payload));
                }
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let _ = dp.tick(now());
        let proxy = dp.proxy_stats().unwrap_or_default();
        let stats = dp.stats();
        Ok(json!({
            "replies_ok": expected.is_empty() && wrong_destination == 0,
            "missing_replies": expected.len(),
            "udp_sent": proxy.udp_sent,
            "udp_unsupported": proxy.udp_unsupported,
            "direct_forwarded": stats.direct_forwarded,
        }))
    })();
    finish_round(result, &log, &echoes)
}

/// TPROXY 轮：生产 `StreamProxyEgress` 的 UDP 路径，同一 flow key 2 个数据报。
fn tproxy_round(kind: &str, echo: SocketAddr) -> Value {
    let log: StreamLog = Arc::default();
    let result = (|| -> Result<Value, String> {
        let node = match kind {
            "vless" => spawn_vless_node(Arc::clone(&log))?,
            _ => spawn_anytls_node(Arc::clone(&log), &loopback_identity()?)?,
        };
        let yaml = proxy_yaml(kind, node);
        let registry = OutboundRegistry::build(Some(&yaml))
            .map_err(|e| format!("registry: {e:?}"))?
            .ok_or("registry is None")?;
        let mut egress =
            StreamProxyEgress::from_registry(registry).ok_or("no TPROXY proxy egress")?;
        let SocketAddr::V4(orig_dst) = echo else {
            return Err("echo is not IPv4".into());
        };
        let key = FlowKey {
            src_ip: u32::from(*TPROXY_SRC.ip()),
            dst_ip: u32::from(*orig_dst.ip()),
            src_port: TPROXY_SRC.port(),
            dst_port: orig_dst.port(),
            proto: 17,
        };
        egress.note_udp_outbound(key, "proxy");
        let mut expected: HashSet<Vec<u8>> = HashSet::new();
        let mut send_errors = 0usize;
        for i in 0..2 {
            let payload = format!("{kind}-tproxy-{i}").into_bytes();
            expected.insert(echo_reply(&payload));
            if egress.send_udp(key, orig_dst, &payload).is_err() {
                send_errors += 1;
            }
        }
        let deadline = Instant::now() + ROUND_DEADLINE;
        while !expected.is_empty() && Instant::now() < deadline {
            for event in egress.poll() {
                if let ProxyEgressEvent::UdpReply { key: k, payload } = event {
                    if k == key {
                        expected.remove(&payload);
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        Ok(json!({
            "replies_ok": expected.is_empty() && send_errors == 0,
            "missing_replies": expected.len(),
            "send_errors": send_errors,
        }))
    })();
    finish_round(result, &log, &[echo])
}

/// 合并一轮结果与节点记账（每个目的地址的流数）。
fn finish_round(result: Result<Value, String>, log: &StreamLog, echoes: &[SocketAddr]) -> Value {
    std::thread::sleep(Duration::from_millis(100));
    let streams: Vec<usize> = log
        .lock()
        .map(|l| {
            echoes
                .iter()
                .map(|e| l.get(e).copied().unwrap_or(0))
                .collect()
        })
        .unwrap_or_default();
    let mut out = result.unwrap_or_else(|error| json!({"error": error, "replies_ok": false}));
    out["one_stream_per_destination"] = json!(streams.iter().all(|&n| n == 1));
    out["streams_per_destination"] = json!(streams);
    out
}

fn main() {
    let echoes = match (spawn_udp_echo(), spawn_udp_echo()) {
        (Ok(a), Ok(b)) => [a, b],
        _ => {
            println!(
                "{}",
                json!({"verdict": "FAIL", "error": "udp echo bind failed"})
            );
            std::process::exit(1);
        }
    };
    if std::env::args().any(|a| a == "--self-test") {
        let report = self_test(echoes[0]);
        let ok = report["vless"] == true && report["anytls"] == true;
        println!("{report}");
        std::process::exit(if ok { 0 } else { 1 });
    }
    let mut report = json!({});
    let mut pass = true;
    for kind in ["vless", "anytls"] {
        let tun = tun_round(kind, echoes);
        let tproxy = tproxy_round(kind, echoes[0]);
        pass &= tun["replies_ok"] == true
            && tun["one_stream_per_destination"] == true
            && tun["udp_sent"] == 4
            && tun["udp_unsupported"] == 0
            && tun["direct_forwarded"] == 0
            && tproxy["replies_ok"] == true
            && tproxy["one_stream_per_destination"] == true;
        report[kind] = json!({"tun": tun, "tproxy": tproxy});
    }
    report["verdict"] = json!(if pass { "PASS" } else { "FAIL" });
    println!("{report}");
    if !pass {
        std::process::exit(1);
    }
}
