//! E4 产品场景 `product.proxy-fwd-udp-vless-anytls` 的可执行驱动（PRODUCT §11.18.1）。
//!
//! ```text
//! cargo run --quiet -p nexusd --example proxy_fwd_udp_vless_anytls -- --json
//! cargo run --quiet -p nexusd --example proxy_fwd_udp_vless_anytls -- --self-test
//! ```
//!
//! 全 loopback、离线，每一轮都用新的节点与 echo（计数互不串）：
//! - UDP echo：回 `echo:` + 载荷，并按收到的数据报计数；
//! - 本地 VLESS 节点（明文 TCP）：只接受配置的 UUID、`flow` 为空、`command = UDP` 的请求；
//! - 本地 AnyTLS 节点（TLS 自签）：认证后接受 UoT v2 connect 模式 stream，按 TLS 会话计数；
//! - 两种节点都按目的地址记录打开的流与经手的数据报，并把回包改写为 `node:` + echo 回包——
//!   绕过节点直发目的地的数据报拿不到 `node:` 前缀，也不会出现在节点计数里。
//! - 节点在本轮全部数据报发出之前不中继（闸门）：所有回包都晚于所有发送，「回包发给最后一个
//!   发送者」一类的串流每次都会暴露。闸门只扣住中继，不保证数据报经过建流队列；闸门超时计入
//!   `gate_timeouts`，夹具故障不会伪装成实现 FAIL。
//! - TUN 轮：MockTun + 生产 `Dataplane` / `ProxyEngine`。源 A 向两个目的地址各发 2 个数据报，
//!   源 B 向第一个目的地址发 2 个：每个（源，目的地址）一条代理流，回包只回到发出它的源。
//! - TPROXY 轮：生产 `StreamProxyEgress`，客户端 A、C 发往第一个目的地址、B 发往第二个，
//!   各 2 个数据报。
//! - `--self-test`：用 crate 自带客户端（不经 nexusd）验证两个本地节点本身可用。

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
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
const TUN_SRC_A: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 5000);
const TUN_SRC_B: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 5002);
const TPROXY_SRC_A: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 3), 5001);
const TPROXY_SRC_B: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 4), 5003);
const TPROXY_SRC_C: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 5), 5004);
/// 一轮从发出到收齐回包的上限（建流 + TLS 握手 + 中继）。
const ROUND_DEADLINE: Duration = Duration::from_secs(10);
/// 收齐后再排空的时长：多余 / 重复 / 串流的回包在此期间暴露。
const DRAIN: Duration = Duration::from_millis(200);

/// 节点侧记账。
#[derive(Default)]
struct NodeLog {
    /// 每个目的地址打开过的代理流数。
    streams: HashMap<SocketAddr, usize>,
    /// 每个目的地址经节点中继的数据报数。
    relayed: HashMap<SocketAddr, usize>,
    /// AnyTLS：接受的 TLS 会话数。
    sessions: usize,
    /// VLESS：因 UUID / flow / command 不符被拒绝的请求数。
    rejected: usize,
    /// 闸门：为 `false` 时节点不中继（本轮数据报全部发出后由驱动打开）。
    relay_open: bool,
    /// 闸门等待超时的次数（夹具故障；期望 0）。
    gate_timeouts: usize,
}

/// 闸门已打开的节点记账（`--self-test` 用）。
fn open_log() -> SharedLog {
    Arc::new(Mutex::new(NodeLog {
        relay_open: true,
        ..NodeLog::default()
    }))
}

fn open_relay(log: &SharedLog) {
    if let Ok(mut log) = log.lock() {
        log.relay_open = true;
    }
}

type SharedLog = Arc<Mutex<NodeLog>>;

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

/// 节点经手的回包：`node:` + echo 回包。
fn via_node(payload: &[u8]) -> Vec<u8> {
    [b"node:".as_slice(), &echo_reply(payload)].concat()
}

/// 本地 UDP echo：每个数据报回 `echo:` + 载荷，并计数。
fn spawn_udp_echo() -> Result<(SocketAddr, Arc<AtomicUsize>), String> {
    let socket = UdpSocket::bind("127.0.0.1:0").map_err(|e| format!("bind echo: {e}"))?;
    let addr = socket.local_addr().map_err(|e| e.to_string())?;
    let received = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&received);
    std::thread::spawn(move || {
        let mut buf = [0u8; 2048];
        while let Ok((n, from)) = socket.recv_from(&mut buf) {
            counter.fetch_add(1, Ordering::SeqCst);
            let _ = socket.send_to(&echo_reply(&buf[..n]), from);
        }
    });
    Ok((addr, received))
}

/// 节点把一个数据报交给真实目的地址，返回 `node:` + echo 回包，并记账。
fn relay_once(log: &SharedLog, target: SocketAddr, datagram: &[u8]) -> io::Result<Vec<u8>> {
    let gate_deadline = Instant::now() + ROUND_DEADLINE;
    while !log.lock().map(|l| l.relay_open).unwrap_or(true) {
        if Instant::now() >= gate_deadline {
            if let Ok(mut log) = log.lock() {
                log.gate_timeouts += 1;
            }
            return Err(io::Error::other("relay gate never opened"));
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    let socket = UdpSocket::bind("127.0.0.1:0")?;
    socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    socket.send_to(datagram, target)?;
    let mut buf = [0u8; 2048];
    let (n, _) = socket.recv_from(&mut buf)?;
    if let Ok(mut log) = log.lock() {
        *log.relayed.entry(target).or_default() += 1;
    }
    Ok([b"node:".as_slice(), &buf[..n]].concat())
}

fn spawn_vless_node(log: SharedLog) -> Result<SocketAddr, String> {
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

fn serve_vless(mut stream: TcpStream, log: SharedLog) -> Result<(), String> {
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
    let uuid = vless::VlessUuid::parse(VLESS_UUID).map_err(|e| e.to_string())?;
    let target = match (&request.target, request.command, request.flow) {
        (Some(vless::VlessTarget::Ipv4(ip)), vless::VlessCommand::Udp, vless::VlessFlow::None)
            if request.uuid == uuid =>
        {
            SocketAddr::new(IpAddr::V4(*ip), request.port)
        }
        _ => {
            if let Ok(mut log) = log.lock() {
                log.rejected += 1;
            }
            return Err("request is not UDP for the configured UUID without flow".into());
        }
    };
    if let Ok(mut log) = log.lock() {
        *log.streams.entry(target).or_default() += 1;
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
        let reply = relay_once(&log, target, &datagram).map_err(|e| e.to_string())?;
        let framed = vless::encode_udp_datagram(&reply).map_err(|e| e.to_string())?;
        stream.write_all(&framed).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn spawn_anytls_node(
    log: SharedLog,
    identity: &anytls::LoopbackIdentity,
) -> Result<SocketAddr, String> {
    let cfg = Arc::new(
        anytls::server_config(identity).map_err(|e| format!("anytls server config: {e:?}"))?,
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
    log: SharedLog,
) -> Result<(), String> {
    sock.set_read_timeout(Some(Duration::from_secs(70)))
        .map_err(|e| e.to_string())?;
    let conn = rustls::ServerConnection::new(cfg).map_err(|e| e.to_string())?;
    let mut tls = rustls::StreamOwned::new(conn, sock);
    anytls::server_handshake(&mut tls, ANYTLS_PASSWORD, anytls::DEFAULT_PADDING_SCHEME)
        .map_err(|e| format!("anytls handshake: {e:?}"))?;
    if let Ok(mut log) = log.lock() {
        log.sessions += 1;
    }
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
                        *log.streams.entry(target).or_default() += 1;
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
                    let reply = relay_once(&log, target, &datagram).map_err(|e| e.to_string())?;
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

fn spawn_node(kind: &str, log: &SharedLog) -> Result<SocketAddr, String> {
    match kind {
        "vless" => spawn_vless_node(Arc::clone(log)),
        _ => spawn_anytls_node(Arc::clone(log), &loopback_identity()?),
    }
}

/// `--self-test`：用 crate 自带的客户端（不经 nexusd）验证两个本地节点本身可用，
/// 以免把夹具缺陷误判为实现缺陷。也验证 VLESS 节点拒绝错误 UUID。
fn self_test() -> Value {
    let Ok((echo, _)) = spawn_udp_echo() else {
        return json!({"vless": false, "anytls": false});
    };
    let SocketAddr::V4(echo_v4) = echo else {
        return json!({"vless": false, "anytls": false});
    };
    let vless_request = |uuid: &str| -> Result<Vec<u8>, String> {
        let request = vless::VlessRequest {
            uuid: vless::VlessUuid::parse(uuid).map_err(|e| e.to_string())?,
            flow: vless::VlessFlow::None,
            command: vless::VlessCommand::Udp,
            port: echo.port(),
            target: Some(vless::VlessTarget::Ipv4(*echo_v4.ip())),
        };
        vless::encode_request(&request).map_err(|e| e.to_string())
    };
    let vless_ok = (|| -> Result<bool, String> {
        let log = open_log();
        let node = spawn_vless_node(Arc::clone(&log))?;
        let mut s = TcpStream::connect(node).map_err(|e| e.to_string())?;
        s.set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|e| e.to_string())?;
        s.write_all(&vless_request(VLESS_UUID)?)
            .map_err(|e| e.to_string())?;
        s.write_all(&vless::encode_udp_datagram(b"self").map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        vless::read_response(&mut s).map_err(|e| e.to_string())?;
        let ok = vless::read_udp_datagram(&mut s).map_err(|e| e.to_string())? == via_node(b"self");
        // 错误 UUID：节点关闭连接、记一次拒绝、不中继。
        let mut bad = TcpStream::connect(node).map_err(|e| e.to_string())?;
        bad.set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|e| e.to_string())?;
        bad.write_all(&vless_request("22222222-2222-2222-2222-222222222222")?)
            .map_err(|e| e.to_string())?;
        let mut sink = Vec::new();
        let _ = bad.read_to_end(&mut sink);
        std::thread::sleep(Duration::from_millis(50));
        let rejected = log.lock().map(|l| l.rejected).unwrap_or(0);
        Ok(ok && sink.is_empty() && rejected == 1)
    })();
    let anytls_ok = (|| -> Result<bool, String> {
        let identity = loopback_identity()?;
        let node = spawn_anytls_node(open_log(), &identity)?;
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
                return Ok(got == vec![via_node(b"self")]);
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

/// 一轮的 echo 目的地址（每轮新建，计数互不串）。
struct Echoes {
    addrs: [SocketAddr; 2],
    received: [Arc<AtomicUsize>; 2],
}

fn spawn_echoes() -> Result<Echoes, String> {
    let (a, ra) = spawn_udp_echo()?;
    let (b, rb) = spawn_udp_echo()?;
    Ok(Echoes {
        addrs: [a, b],
        received: [ra, rb],
    })
}

/// 节点与 echo 的记账（每个目的地址）：流数、经节点数、echo 实收数、AnyTLS 会话数。
fn ledger(log: &SharedLog, echoes: &Echoes) -> Value {
    std::thread::sleep(Duration::from_millis(100));
    let (streams, relayed, sessions, rejected, gate_timeouts) = log
        .lock()
        .map(|l| {
            let per = |m: &HashMap<SocketAddr, usize>| -> Vec<usize> {
                echoes
                    .addrs
                    .iter()
                    .map(|a| m.get(a).copied().unwrap_or(0))
                    .collect()
            };
            (
                per(&l.streams),
                per(&l.relayed),
                l.sessions,
                l.rejected,
                l.gate_timeouts,
            )
        })
        .unwrap_or_default();
    let received: Vec<usize> = echoes
        .received
        .iter()
        .map(|r| r.load(Ordering::SeqCst))
        .collect();
    json!({
        "streams_per_destination": streams,
        "relayed_per_destination": relayed,
        "echo_received_per_destination": received,
        "bypassed": received.iter().zip(&relayed).map(|(r, v)| r.saturating_sub(*v)).sum::<usize>(),
        "anytls_sessions": sessions,
        "vless_rejected": rejected,
        "gate_timeouts": gate_timeouts,
    })
}

/// 一轮期望的回包：(回包目的 = 发出它的源, 回包源 = 目的地址, 载荷)。
type Expected = Vec<(SocketAddr, SocketAddr, Vec<u8>)>;

/// TUN 轮：源 A → 两个目的地址各 2 个，源 B → 第一个目的地址 2 个。
fn tun_round(kind: &str) -> Value {
    let log = SharedLog::default();
    let echoes = match spawn_echoes() {
        Ok(e) => e,
        Err(error) => return json!({"error": error}),
    };
    let result = (|| -> Result<Value, String> {
        let node = spawn_node(kind, &log)?;
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

        let sends = [
            (TUN_SRC_A, echoes.addrs[0]),
            (TUN_SRC_A, echoes.addrs[1]),
            (TUN_SRC_B, echoes.addrs[0]),
        ];
        let mut expected: Expected = Vec::new();
        for (s, (src, dst)) in sends.iter().enumerate() {
            for i in 0..2 {
                let payload = format!("{kind}-tun-{s}-{i}").into_bytes();
                expected.push((SocketAddr::V4(*src), *dst, via_node(&payload)));
                mock.lock()
                    .map_err(|e| e.to_string())?
                    .inject(udp_packet(*src, *dst, &payload)?);
                dp.tick(now()).map_err(|e| format!("tick: {e}"))?;
            }
        }
        open_relay(&log);
        let total_expected = expected.len();
        let mut unexpected = 0usize;
        let mut received = 0usize;
        let mut done_at: Option<Instant> = None;
        let deadline = Instant::now() + ROUND_DEADLINE;
        while Instant::now() < deadline && done_at.is_none_or(|t| t.elapsed() < DRAIN) {
            let _ = dp.tick(now());
            for pkt in mock.lock().map_err(|e| e.to_string())?.take_written() {
                if let Some((src, dst, payload)) = parse_udp(&pkt) {
                    received += 1;
                    match expected
                        .iter()
                        .position(|(to, from, p)| *to == dst && *from == src && *p == payload)
                    {
                        Some(i) => {
                            expected.swap_remove(i);
                        }
                        None => unexpected += 1,
                    }
                }
            }
            if expected.is_empty() && done_at.is_none() {
                done_at = Some(Instant::now());
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let _ = dp.tick(now());
        let proxy = dp.proxy_stats().unwrap_or_default();
        let stats = dp.stats();
        Ok(json!({
            "replies_ok": expected.is_empty() && unexpected == 0 && received == total_expected,
            "missing_replies": expected.len(),
            "unexpected_replies": unexpected,
            "udp_sent": proxy.udp_sent,
            "udp_send_failed": proxy.udp_send_failed,
            "udp_unsupported": proxy.udp_unsupported,
            "udp_unsupported_vless": proxy.udp_unsupported_vless,
            "udp_unsupported_anytls": proxy.udp_unsupported_anytls,
            "proxy_dropped_no_proxy": stats.proxy_dropped_no_proxy,
            "direct_forwarded": stats.direct_forwarded,
        }))
    })();
    let mut out = result.unwrap_or_else(|error| json!({"error": error, "replies_ok": false}));
    out["ledger"] = ledger(&log, &echoes);
    out
}

/// TPROXY 轮：客户端 A、C → 第一个目的地址，B → 第二个，各 2 个数据报。
fn tproxy_round(kind: &str) -> Value {
    let log = SharedLog::default();
    let echoes = match spawn_echoes() {
        Ok(e) => e,
        Err(error) => return json!({"error": error}),
    };
    let result = (|| -> Result<Value, String> {
        let node = spawn_node(kind, &log)?;
        let yaml = proxy_yaml(kind, node);
        let registry = OutboundRegistry::build(Some(&yaml))
            .map_err(|e| format!("registry: {e:?}"))?
            .ok_or("registry is None")?;
        let mut egress =
            StreamProxyEgress::from_registry(registry).ok_or("no TPROXY proxy egress")?;
        let mut expected: Vec<(FlowKey, Vec<u8>)> = Vec::new();
        let mut send_errors = 0usize;
        for (f, (src, echo)) in [
            (TPROXY_SRC_A, echoes.addrs[0]),
            (TPROXY_SRC_B, echoes.addrs[1]),
            (TPROXY_SRC_C, echoes.addrs[0]),
        ]
        .into_iter()
        .enumerate()
        {
            let SocketAddr::V4(orig_dst) = echo else {
                return Err("echo is not IPv4".into());
            };
            let key = FlowKey {
                src_ip: u32::from(*src.ip()),
                dst_ip: u32::from(*orig_dst.ip()),
                src_port: src.port(),
                dst_port: orig_dst.port(),
                proto: 17,
            };
            egress.note_udp_outbound(key, "proxy");
            for i in 0..2 {
                let payload = format!("{kind}-tproxy-{f}-{i}").into_bytes();
                expected.push((key, via_node(&payload)));
                if egress.send_udp(key, orig_dst, &payload).is_err() {
                    send_errors += 1;
                }
            }
        }
        open_relay(&log);
        let total_expected = expected.len();
        let mut unexpected = 0usize;
        let mut received = 0usize;
        let mut done_at: Option<Instant> = None;
        let deadline = Instant::now() + ROUND_DEADLINE;
        while Instant::now() < deadline && done_at.is_none_or(|t| t.elapsed() < DRAIN) {
            for event in egress.poll() {
                if let ProxyEgressEvent::UdpReply { key, payload } = event {
                    received += 1;
                    match expected
                        .iter()
                        .position(|(k, p)| *k == key && *p == payload)
                    {
                        Some(i) => {
                            expected.swap_remove(i);
                        }
                        None => unexpected += 1,
                    }
                }
            }
            if expected.is_empty() && done_at.is_none() {
                done_at = Some(Instant::now());
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        Ok(json!({
            "replies_ok": expected.is_empty()
                && unexpected == 0
                && received == total_expected
                && send_errors == 0,
            "missing_replies": expected.len(),
            "unexpected_replies": unexpected,
            "send_errors": send_errors,
        }))
    })();
    let mut out = result.unwrap_or_else(|error| json!({"error": error, "replies_ok": false}));
    out["ledger"] = ledger(&log, &echoes);
    out
}

fn main() {
    if std::env::args().any(|a| a == "--self-test") {
        let report = self_test();
        let ok = report["vless"] == true && report["anytls"] == true;
        println!("{report}");
        std::process::exit(if ok { 0 } else { 1 });
    }
    let mut report = json!({});
    let mut pass = true;
    for kind in ["vless", "anytls"] {
        let tun = tun_round(kind);
        let tproxy = tproxy_round(kind);
        let sessions_ok =
            |round: &Value, n: usize| kind != "anytls" || round["ledger"]["anytls_sessions"] == n;
        pass &= tun["replies_ok"] == true
            && tun["ledger"]["streams_per_destination"] == json!([2, 1])
            && tun["ledger"]["relayed_per_destination"] == json!([4, 2])
            && tun["ledger"]["echo_received_per_destination"] == json!([4, 2])
            && tun["ledger"]["bypassed"] == 0
            && tun["ledger"]["gate_timeouts"] == 0
            && sessions_ok(&tun, 3)
            && tun["udp_sent"] == 6
            && tun["udp_send_failed"] == 0
            && tun["udp_unsupported"] == 0
            && tun["proxy_dropped_no_proxy"] == 0
            && tun["direct_forwarded"] == 0
            && tproxy["replies_ok"] == true
            && tproxy["ledger"]["streams_per_destination"] == json!([2, 1])
            && tproxy["ledger"]["relayed_per_destination"] == json!([4, 2])
            && tproxy["ledger"]["echo_received_per_destination"] == json!([4, 2])
            && tproxy["ledger"]["bypassed"] == 0
            && tproxy["ledger"]["gate_timeouts"] == 0
            && sessions_ok(&tproxy, 3);
        report[kind] = json!({"tun": tun, "tproxy": tproxy});
    }
    report["verdict"] = json!(if pass { "PASS" } else { "FAIL" });
    println!("{report}");
    if !pass {
        std::process::exit(1);
    }
}
