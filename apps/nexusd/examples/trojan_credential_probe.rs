//! E4 产品场景 `product.nexusd-trojan-credential-probe` 的可执行驱动（PRODUCT §11.9.5）。
//!
//! ```text
//! cargo run --quiet -p nexusd --example trojan_credential_probe -- --json
//! ```
//!
//! 全 loopback、离线：nexusd 引擎（`Dataplane` + `ProxyEngine` + MockTun）+ 本地 TLS
//! Trojan 节点（`nexus_outbound_trojan::server_config` 自签）+ TCP echo 目标。节点对每条
//! 连接解析 Trojan 请求头并记账：
//! - 密码正确 + 探测目标 `credential-probe.nexus.invalid:9` → 立即关闭（模拟解析失败）；
//! - 密码正确 + 其他目标 → 中继到 echo；
//! - 密码错误 → 扮演 fallback：读完请求头立即回 `HTTP/1.1 404` 并关闭。
//!
//! 三个用例各自一套引擎与节点：
//! 1. 密码错误（探测缺省开启）：两条流都被 RST、TUN 下行零字节；节点只收到 1 条探测连接；
//! 2. 密码正确：1 条探测连接 + 2 条流连接，两条流都回显（第二条流不再探测）；
//! 3. `credential_probe: false`：没有探测连接，流回显正常。

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use nexus_outbound_trojan::{generate_loopback_identity, parse_request, server_config};
use nexus_projection::{MockTun, TunDevice};
use nexusd::dataplane::{Dataplane, DataplaneConfig};
use nexusd::proxy_fwd::ProxyEngine;
use serde_json::{Value, json};

const NODE_PASSWORD: &str = "probe-right-password";
const WRONG_PASSWORD: &str = "probe-wrong-password";
const PROBE_HOST: &str = "credential-probe.nexus.invalid";
const PROBE_PORT: u16 = 9;
const PAYLOAD: &[u8] = b"hello-via-nexusd-credential-probe";
const NOT_FOUND: &[u8] =
    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
/// 单条流从 SYN 到出结果的上限（探测 ≤ 3 s + TLS 握手 + 中继）。
const FLOW_DEADLINE: Duration = Duration::from_secs(10);

fn ip_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

fn tcp_checksum(src: [u8; 4], dst: [u8; 4], tcp_seg: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for w in [src, dst] {
        sum += u16::from_be_bytes([w[0], w[1]]) as u32;
        sum += u16::from_be_bytes([w[2], w[3]]) as u32;
    }
    sum += 6;
    sum += tcp_seg.len() as u32;
    let mut i = 0;
    while i + 1 < tcp_seg.len() {
        sum += u16::from_be_bytes([tcp_seg[i], tcp_seg[i + 1]]) as u32;
        i += 2;
    }
    if i < tcp_seg.len() {
        sum += (tcp_seg[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

#[allow(clippy::too_many_arguments)]
fn craft_tcp(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut pkt = vec![0u8; 40 + payload.len()];
    pkt[0] = 0x45;
    let tot = (40 + payload.len()) as u16;
    pkt[2..4].copy_from_slice(&tot.to_be_bytes());
    pkt[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 6;
    pkt[12..16].copy_from_slice(&src_ip);
    pkt[16..20].copy_from_slice(&dst_ip);
    let c = ip_checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&c.to_be_bytes());
    let t = &mut pkt[20..40];
    t[0..2].copy_from_slice(&src_port.to_be_bytes());
    t[2..4].copy_from_slice(&dst_port.to_be_bytes());
    t[4..8].copy_from_slice(&seq.to_be_bytes());
    t[8..12].copy_from_slice(&ack.to_be_bytes());
    t[12] = 0x50;
    t[13] = flags;
    t[14..16].copy_from_slice(&8192u16.to_be_bytes());
    pkt[40..].copy_from_slice(payload);
    let tc = tcp_checksum(src_ip, dst_ip, &pkt[20..]);
    pkt[36..38].copy_from_slice(&tc.to_be_bytes());
    pkt
}

fn tcp_parts(pkt: &[u8]) -> Option<(u32, u32, u8, &[u8])> {
    if pkt.len() < 40 || pkt[9] != 6 {
        return None;
    }
    let seq = u32::from_be_bytes([pkt[24], pkt[25], pkt[26], pkt[27]]);
    let ack = u32::from_be_bytes([pkt[28], pkt[29], pkt[30], pkt[31]]);
    Some((seq, ack, pkt[33], &pkt[40..]))
}

fn start_tcp_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind echo");
    let addr = listener.local_addr().expect("echo addr");
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let mut s = stream;
                let mut buf = [0u8; 8192];
                while let Ok(n) = s.read(&mut buf) {
                    if n == 0 || s.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

/// 从 TLS stream 读到第二个 CRLF（trojan 请求头结束）。
fn read_trojan_header<S: Read>(tls: &mut S) -> Result<Vec<u8>, String> {
    let mut buf = Vec::with_capacity(128);
    let mut one = [0u8; 1];
    loop {
        tls.read_exact(&mut one)
            .map_err(|e| format!("trojan header read: {e}"))?;
        buf.push(one[0]);
        if buf.windows(2).filter(|w| **w == *b"\r\n").count() >= 2 {
            return Ok(buf);
        }
        if buf.len() > 4096 {
            return Err("trojan header too large".to_string());
        }
    }
}

/// 节点侧记账：探测连接与流连接分开计数。
#[derive(Default)]
struct NodeLog {
    probe_connections: usize,
    flow_connections: usize,
    probe_target: Option<String>,
}

/// 本地 TLS Trojan 节点：持续 accept 直到 `stop`，每条连接一个线程。
fn spawn_node(log: Arc<Mutex<NodeLog>>, stop: Arc<AtomicBool>) -> Result<SocketAddr, String> {
    let identity = generate_loopback_identity().map_err(|e| format!("identity: {e:?}"))?;
    let cfg = Arc::new(server_config(&identity).map_err(|e| format!("server config: {e:?}"))?);
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("bind node: {e}"))?;
    let addr = listener
        .local_addr()
        .map_err(|e| format!("node addr: {e}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("node nonblocking: {e}"))?;
    std::thread::spawn(move || {
        while !stop.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((tcp, _)) => {
                    let cfg = Arc::clone(&cfg);
                    let log = Arc::clone(&log);
                    std::thread::spawn(move || {
                        let _ = serve_node_connection(tcp, cfg, log);
                    });
                }
                Err(_) => std::thread::sleep(Duration::from_millis(2)),
            }
        }
    });
    Ok(addr)
}

fn serve_node_connection(
    mut tcp: TcpStream,
    cfg: Arc<rustls::ServerConfig>,
    log: Arc<Mutex<NodeLog>>,
) -> Result<(), String> {
    tcp.set_nonblocking(false).map_err(|e| e.to_string())?;
    tcp.set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    let mut srv = rustls::ServerConnection::new(cfg).map_err(|e| e.to_string())?;
    let mut tls = rustls::Stream::new(&mut srv, &mut tcp);
    let header = read_trojan_header(&mut tls)?;
    let (accepted, target) = match parse_request(NODE_PASSWORD, &header) {
        Ok(target) => (true, target),
        Err(_) => (
            false,
            parse_request(WRONG_PASSWORD, &header).map_err(|e| format!("{e:?}"))?,
        ),
    };
    let is_probe = target.host_label() == PROBE_HOST && target.port() == PROBE_PORT;
    if let Ok(mut log) = log.lock() {
        if is_probe {
            log.probe_connections += 1;
            log.probe_target = Some(format!("{}:{}", target.host_label(), target.port()));
        } else {
            log.flow_connections += 1;
        }
    }
    if !accepted {
        // fallback：读完请求头就应答 404（不等载荷），短暂保持后关闭——与真实服务端一样，
        // 应答先于关闭到达，引擎有机会把它当作隧道数据泵给 TUN（R-5 的 fail-open）。
        tls.write_all(NOT_FOUND).map_err(|e| e.to_string())?;
        tls.flush().map_err(|e| e.to_string())?;
        std::thread::sleep(Duration::from_millis(400));
        return Ok(());
    }
    if is_probe {
        // 密码正确：保留域解析失败 → 关闭，不回任何字节。
        return Ok(());
    }
    let mut echo = TcpStream::connect(("127.0.0.1", target.port())).map_err(|e| e.to_string())?;
    let mut buf = [0u8; 4096];
    let n = tls.read(&mut buf).map_err(|e| e.to_string())?;
    echo.write_all(&buf[..n]).map_err(|e| e.to_string())?;
    let mut back = vec![0u8; n];
    echo.read_exact(&mut back).map_err(|e| e.to_string())?;
    tls.write_all(&back).map_err(|e| e.to_string())?;
    tls.flush().map_err(|e| e.to_string())?;
    // 与 proxy_fwd_trojan_tls_engine 同理：保持隧道一小段，让引擎先泵下行。
    std::thread::sleep(Duration::from_millis(400));
    Ok(())
}

/// 一条 TUN 流的结果。
struct FlowOutcome {
    rst: bool,
    downstream: Vec<u8>,
}

/// 驱动一条 TUN TCP 流：SYN → SYN-ACK → ACK → DATA，然后收集下行直到 RST、回显或超时。
fn run_flow(
    dp: &mut Dataplane,
    mock: &Arc<Mutex<MockTun>>,
    epoch: Instant,
    src_port: u16,
    dst: SocketAddr,
) -> Result<FlowOutcome, String> {
    let now = || u64::try_from(epoch.elapsed().as_millis()).unwrap_or(u64::MAX);
    let src = [10, 0, 0, 2];
    let std::net::IpAddr::V4(dst_ip) = dst.ip() else {
        return Err("target is not IPv4".into());
    };
    let dst_ip = dst_ip.octets();
    let inject = |pkt: Vec<u8>| {
        mock.lock()
            .map(|mut m| m.inject(pkt))
            .map_err(|e| e.to_string())
    };

    inject(craft_tcp(
        src,
        dst_ip,
        src_port,
        dst.port(),
        1000,
        0,
        0x02,
        &[],
    ))?;
    dp.tick(now()).map_err(|e| format!("syn: {e}"))?;
    let written = mock.lock().map_err(|e| e.to_string())?.take_written();
    let srv_seq = written
        .iter()
        .find_map(|pkt| match tcp_parts(pkt) {
            Some((seq, _, flags, _)) if flags & 0x12 == 0x12 => Some(seq),
            _ => None,
        })
        .ok_or("no SYN-ACK from engine")?;
    inject(craft_tcp(
        src,
        dst_ip,
        src_port,
        dst.port(),
        1001,
        srv_seq.wrapping_add(1),
        0x10,
        &[],
    ))?;
    dp.tick(now()).map_err(|e| format!("ack: {e}"))?;
    inject(craft_tcp(
        src,
        dst_ip,
        src_port,
        dst.port(),
        1001,
        srv_seq.wrapping_add(1),
        0x18,
        PAYLOAD,
    ))?;
    dp.tick(now()).map_err(|e| format!("data: {e}"))?;

    let mut outcome = FlowOutcome {
        rst: false,
        downstream: Vec::new(),
    };
    let deadline = Instant::now() + FLOW_DEADLINE;
    while Instant::now() < deadline {
        let _ = dp.tick(now());
        for pkt in mock.lock().map_err(|e| e.to_string())?.take_written() {
            if let Some((_, _, flags, data)) = tcp_parts(&pkt) {
                outcome.rst |= flags & 0x04 != 0;
                outcome.downstream.extend_from_slice(data);
            }
        }
        let echoed = outcome
            .downstream
            .windows(PAYLOAD.len())
            .any(|w| w == PAYLOAD);
        let fallback_seen = outcome.downstream.len() >= NOT_FOUND.len();
        if outcome.rst || echoed || fallback_seen {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    Ok(outcome)
}

/// 一个用例：独立的节点 + 引擎，依次跑 `flows` 条流。
fn run_case(password: &str, probe_field: Option<bool>, flows: u16, echo: SocketAddr) -> Value {
    let log = Arc::new(Mutex::new(NodeLog::default()));
    let stop = Arc::new(AtomicBool::new(false));
    let result = (|| -> Result<Value, String> {
        let node = spawn_node(Arc::clone(&log), Arc::clone(&stop))?;
        let probe_line = probe_field
            .map(|b| format!("    credential_probe: {b}\n"))
            .unwrap_or_default();
        let proxy_yaml = format!(
            "schema_version: 1\nrules:\n  - tag: r1\n    kind: match\n    action:\n      \
             - kind: select_outbound\n        tag: trojan-node\noutbounds:\n  - tag: trojan-node\n    \
             kind: trojan\n    locator: {node}\n    password: {password}\n    skip_cert_verify: true\n\
             {probe_line}"
        );
        let mock = Arc::new(Mutex::new(MockTun::new("trojan-tls0")));
        let config = DataplaneConfig {
            mesh_cidrs: vec!["10.200.0.0/24".into()],
            proxy_configured: true,
            ..Default::default()
        };
        let mut dp = Dataplane::new(Box::new(SharedTun(Arc::clone(&mock))), config, None)
            .map_err(|e| format!("dataplane init: {e}"))?;
        let rule_engine = nexus_proxy::domain_engine::DomainRuleEngine::from_yaml(&proxy_yaml)
            .map_err(|e| format!("rule engine: {e}"))?;
        let engine = match ProxyEngine::new(Some(&proxy_yaml)) {
            Ok(Some(engine)) => engine,
            Ok(None) => return Err("ProxyEngine::new returned None".into()),
            Err(error) => return Err(format!("engine init: {}", error.variant())),
        };
        dp.set_proxy_engine(engine);
        dp.set_rule_engine(Box::new(rule_engine));
        let epoch = Instant::now();
        let mut results = Vec::new();
        for i in 0..flows {
            let outcome = run_flow(&mut dp, &mock, epoch, 42001 + i, echo)?;
            let echo_ok = outcome
                .downstream
                .windows(PAYLOAD.len())
                .any(|w| w == PAYLOAD);
            let fallback_seen = outcome.downstream.windows(9).any(|w| w == b"HTTP/1.1 ");
            results.push(json!({
                "rst": outcome.rst,
                "echo_ok": echo_ok,
                "downstream_bytes": outcome.downstream.len(),
                "fallback_bytes_seen": fallback_seen,
            }));
        }
        let stats = dp.proxy_stats().unwrap_or_default();
        let all = |key: &str| results.iter().all(|f| f[key] == true);
        Ok(json!({
            "all_flows_rst": all("rst"),
            "all_flows_echo": all("echo_ok"),
            "fallback_bytes_seen": results.iter().any(|f| f["fallback_bytes_seen"] == true),
            "downstream_bytes_total": results
                .iter()
                .filter_map(|f| f["downstream_bytes"].as_u64())
                .sum::<u64>(),
            "tcp_dials_failed": stats.tcp_dials_failed,
            "flows": results,
        }))
    })();
    // 让节点线程记完最后一条连接再读账。
    std::thread::sleep(Duration::from_millis(200));
    stop.store(true, Ordering::SeqCst);
    let (probe_connections, flow_connections, probe_target) = log
        .lock()
        .map(|l| {
            (
                l.probe_connections,
                l.flow_connections,
                l.probe_target.clone(),
            )
        })
        .unwrap_or_default();
    let mut out = match result {
        Ok(v) => v,
        Err(error) => json!({"error": error, "flows": []}),
    };
    out["probe_connections"] = json!(probe_connections);
    out["flow_connections"] = json!(flow_connections);
    out["probe_target"] = json!(probe_target);
    out
}

fn flows_all(case: &Value, pred: impl Fn(&Value) -> bool, expected: usize) -> bool {
    case["flows"]
        .as_array()
        .is_some_and(|f| f.len() == expected && f.iter().all(pred))
}

fn main() {
    let echo = start_tcp_echo();
    let wrong = run_case(WRONG_PASSWORD, None, 2, echo);
    let right = run_case(NODE_PASSWORD, None, 2, echo);
    let disabled = run_case(NODE_PASSWORD, Some(false), 1, echo);

    let probe_target = format!("{PROBE_HOST}:{PROBE_PORT}");
    let wrong_ok = wrong["probe_connections"] == 1
        && wrong["flow_connections"] == 0
        && wrong["probe_target"] == probe_target.as_str()
        && flows_all(
            &wrong,
            |f| f["rst"] == true && f["downstream_bytes"] == 0,
            2,
        );
    let right_ok = right["probe_connections"] == 1
        && right["flow_connections"] == 2
        && flows_all(&right, |f| f["echo_ok"] == true, 2);
    let disabled_ok = disabled["probe_connections"] == 0
        && disabled["flow_connections"] == 1
        && flows_all(&disabled, |f| f["echo_ok"] == true, 1);
    let verdict = if wrong_ok && right_ok && disabled_ok {
        "PASS"
    } else {
        "FAIL"
    };
    println!(
        "{}",
        json!({
            "verdict": verdict,
            "probe_target": probe_target,
            "wrong_password": wrong,
            "right_password": right,
            "probe_disabled": disabled,
        })
    );
}

struct SharedTun(Arc<Mutex<MockTun>>);

impl TunDevice for SharedTun {
    fn name(&self) -> &str {
        "trojan-tls0"
    }
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().read(buf)
    }
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().write(buf)
    }
}
