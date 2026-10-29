//! 产品 SOCKS5 UDP ASSOCIATE E1 入口（C-8）：正向 + fail-closed 负向。
//!
//! ```text
//! proxy_udp_associate [--case=<case>] [--json]
//! ```
//!
//! case（默认 `positive`）：
//! - `positive`：真实 `proxy_serve_once` → UDP ASSOCIATE → 经 VLESS 出站往返（本地 VLESS UDP double）；
//! - `non-loopback`：监听 `0.0.0.0` → ASSOCIATE 被拒（Q12）；
//! - `no-route`：规则无可用路由（urltest 无测量）→ 丢弃 + 计数（不直连）；
//! - `direct`：Direct 出站 → 丢弃 + 计数（Q11，不直连）；
//! - `source-mismatch`：异源 IP 的数据报在解析前被拒（§6.1）；
//! - `oversize`：最大合法数据报（65507B）边界不被误判超限，且仍 fail-closed。
//!
//! 退出码：0 全部断言通过；1 断言失败；2 参数/环境错误。
//!
//! 说明：`oversize` 的「超限」规则本体（`len > 65507`）在 UDP 线级不可构造
//! （IP 层最大载荷 = 65507，恰好等于入口上限，判定是严格大于）；该规则由
//! `apps/nexus/src/udp_association.rs::oversize_dropped_before_allocation` 单测承载，
//! 本 case 断言边界与 fail-closed，不伪造超限。

#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::mpsc::{Receiver, channel};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// 本地 VLESS double 使用的固定 UUID（与 probe 模板一致，仅本 example 内使用）。
const UUID: &str = "6af74a31-cd3b-49ee-83fe-34fb1b68497d";
/// 正向往返的数据报数（E4 的 1000 包批量取证在 interop `UdpEcho` 里做）。
const DATAGRAMS: u32 = 16;
const PAYLOAD_LEN: usize = 64;
/// 目标端口取互操作冻结的 UdpEcho 端口（本 example 的 double 直接回显，不监听它）。
const TARGET_PORT: u16 = 26202;
/// SOCKS5 UDP 数据报总长上限（与 ingress 编解码一致）。
const MAX_SOCKS5_UDP: usize = 65_507;

const CASES: [&str; 6] = [
    "positive",
    "non-loopback",
    "no-route",
    "direct",
    "source-mismatch",
    "oversize",
];

/// 单条断言。
struct Assertion {
    name: &'static str,
    ok: bool,
    detail: String,
}

impl Assertion {
    fn new(name: &'static str, ok: bool, detail: impl Into<String>) -> Self {
        Self {
            name,
            ok,
            detail: detail.into(),
        }
    }
}

fn payload_for(seq: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(PAYLOAD_LEN);
    out.extend_from_slice(&u64::from(seq).to_be_bytes());
    out.resize(PAYLOAD_LEN, b'\x5a');
    out
}

// ---------------------------------------------------------------------------
// 本地 VLESS UDP double（明文；只实现请求头 + u16 长度前缀回显）
// ---------------------------------------------------------------------------

struct VlessDouble {
    addr: SocketAddr,
    received: Arc<Mutex<Vec<Vec<u8>>>>,
}

fn read_exact_vec(stream: &mut TcpStream, len: usize) -> Result<Vec<u8>, String> {
    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .map_err(|e| format!("vless double read {len}B: {e}"))?;
    Ok(buf)
}

fn serve_vless(stream: &mut TcpStream, received: &Arc<Mutex<Vec<Vec<u8>>>>) -> Result<(), String> {
    // 请求头：version(1) | uuid(16) | addon_len(1) | addon | cmd(1) | port(2) | atyp | addr
    let prefix = read_exact_vec(stream, 18)?;
    if prefix[0] != 0x00 {
        return Err(format!("vless double bad version {:#04x}", prefix[0]));
    }
    if prefix[17] != 0 {
        return Err("vless double only supports empty addon".into());
    }
    let cmd_port = read_exact_vec(stream, 3)?;
    if cmd_port[0] != 0x02 {
        return Err(format!(
            "vless double expects UDP command, got {:#04x}",
            cmd_port[0]
        ));
    }
    let atyp = read_exact_vec(stream, 1)?[0];
    let addr_len = match atyp {
        0x01 => 4,
        0x02 => usize::from(read_exact_vec(stream, 1)?[0]),
        0x03 => 16,
        other => return Err(format!("vless double bad atyp {other:#04x}")),
    };
    let _target = read_exact_vec(stream, addr_len)?;
    // 响应头：version | addon_len（全 0）。
    stream
        .write_all(&[0x00, 0x00])
        .map_err(|e| format!("vless double response header: {e}"))?;
    loop {
        let mut len_buf = [0u8; 2];
        if stream.read_exact(&mut len_buf).is_err() {
            return Ok(());
        }
        let len = usize::from(u16::from_be_bytes(len_buf));
        let payload = read_exact_vec(stream, len)?;
        received
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(payload.clone());
        stream
            .write_all(&(payload.len() as u16).to_be_bytes())
            .map_err(|e| format!("vless double echo len: {e}"))?;
        stream
            .write_all(&payload)
            .map_err(|e| format!("vless double echo body: {e}"))?;
    }
}

fn start_vless_double() -> Result<VlessDouble, String> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).map_err(|e| format!("bind double: {e}"))?;
    let addr = listener.local_addr().map_err(|e| e.to_string())?;
    let received = Arc::new(Mutex::new(Vec::new()));
    let store = Arc::clone(&received);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let store = Arc::clone(&store);
            thread::spawn(move || {
                let _ = serve_vless(&mut stream, &store);
            });
        }
    });
    Ok(VlessDouble { addr, received })
}

// ---------------------------------------------------------------------------
// proxy.yaml 构造
// ---------------------------------------------------------------------------

fn vless_yaml(double: SocketAddr) -> String {
    format!(
        "schema_version: 1\n\
         rules:\n\
         \x20 - tag: rule-match\n\
         \x20   kind: match\n\
         \x20   match: \"\"\n\
         \x20   action:\n\
         \x20     - kind: select_outbound\n\
         \x20       tag: ref\n\
         outbounds:\n\
         \x20 - tag: ref\n\
         \x20   kind: vless\n\
         \x20   locator: \"{double}\"\n\
         \x20   uuid: \"{UUID}\"\n\
         \x20   flow: \"\"\n\
         \x20   tls: false\n"
    )
}

/// 无可用路由：MATCH → urltest 组；产品 UDP 路由无 measurement source → NoRoute。
fn no_route_yaml() -> &'static str {
    "schema_version: 1\n\
     rules:\n\
     \x20 - tag: rule-match\n\
     \x20   kind: match\n\
     \x20   match: \"\"\n\
     \x20   action:\n\
     \x20     - kind: select_outbound\n\
     \x20       tag: auto\n\
     groups:\n\
     \x20 - tag: auto\n\
     \x20   kind: urltest\n\
     \x20   candidates: [direct]\n\
     outbounds:\n\
     \x20 - tag: direct\n\
     \x20   kind: direct\n"
}

// ---------------------------------------------------------------------------
// SOCKS5 UDP ASSOCIATE 客户端
// ---------------------------------------------------------------------------

struct Association {
    control: TcpStream,
    udp: UdpSocket,
    bnd: Option<SocketAddr>,
    rx: Receiver<Result<serde_json::Value, String>>,
}

type ServeResult = Result<serde_json::Value, String>;

/// 起一个单连接 `proxy_serve_once`。
fn serve_once(yaml: &str, bind: &str) -> Result<(SocketAddr, Receiver<ServeResult>), String> {
    let listener = TcpListener::bind(bind).map_err(|e| format!("bind {bind}: {e}"))?;
    let addr = listener.local_addr().map_err(|e| e.to_string())?;
    let config = yaml.to_string();
    let (tx, rx) = channel();
    thread::spawn(move || {
        let result = nexus::proxy_serve_once(&listener, &config).map_err(|e| format!("{e:?}"));
        let _ = tx.send(result);
    });
    Ok((addr, rx))
}

fn parse_bnd(reply: &[u8; 10]) -> Result<SocketAddr, String> {
    match reply[3] {
        0x01 => Ok(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7])),
            u16::from_be_bytes([reply[8], reply[9]]),
        )),
        // 产品对 loopback 监听只回 IPv4 BND（10B 定长应答）；IPv6 变体不在本工具面。
        other => Err(format!("unexpected BND atyp {other:#04x}")),
    }
}

/// greeting → UDP ASSOCIATE（`0.0.0.0:0`）→ 应答。
fn associate(proxy: SocketAddr) -> Result<(TcpStream, [u8; 10]), String> {
    let timeout = Duration::from_secs(10);
    let mut control =
        TcpStream::connect_timeout(&proxy, timeout).map_err(|e| format!("connect {proxy}: {e}"))?;
    control
        .set_read_timeout(Some(timeout))
        .map_err(|e| e.to_string())?;
    control
        .set_write_timeout(Some(timeout))
        .map_err(|e| e.to_string())?;
    control
        .write_all(&[0x05, 0x01, 0x00])
        .map_err(|e| format!("greeting: {e}"))?;
    let mut method = [0u8; 2];
    control
        .read_exact(&mut method)
        .map_err(|e| format!("greeting reply: {e}"))?;
    if method != [0x05, 0x00] {
        return Err(format!("no-auth rejected: {method:?}"));
    }
    control
        .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .map_err(|e| format!("associate request: {e}"))?;
    let mut reply = [0u8; 10];
    control
        .read_exact(&mut reply)
        .map_err(|e| format!("associate reply: {e}"))?;
    Ok((control, reply))
}

/// 打开关联（保留 serve JSON 的接收端）。
fn open(proxy: SocketAddr, rx: Receiver<ServeResult>) -> Result<Association, String> {
    let (control, reply) = associate(proxy)?;
    let bnd = if reply[1] == 0x00 {
        Some(parse_bnd(&reply)?)
    } else {
        None
    };
    let udp = UdpSocket::bind(("127.0.0.1", 0)).map_err(|e| format!("bind client udp: {e}"))?;
    udp.set_read_timeout(Some(Duration::from_millis(200)))
        .map_err(|e| e.to_string())?;
    Ok(Association {
        control,
        udp,
        bnd,
        rx,
    })
}

fn encode_socks5_udp(payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x00, 0x00, 0x00, 0x01, 127, 0, 0, 1];
    out.extend_from_slice(&TARGET_PORT.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn decode_socks5_udp(datagram: &[u8]) -> Result<Vec<u8>, String> {
    if datagram.len() < 10 || datagram[3] != 0x01 {
        return Err(format!("unexpected udp reply header: {datagram:?}"));
    }
    Ok(datagram[10..].to_vec())
}

fn finish(assoc: Association, wait: Duration) -> (Option<serde_json::Value>, Option<String>) {
    let Association { control, rx, .. } = assoc;
    drop(control);
    match rx.recv_timeout(wait) {
        Ok(Ok(value)) => (Some(value), None),
        Ok(Err(err)) => (None, Some(err)),
        Err(_) => (
            None,
            Some("serve did not terminate within wait window".into()),
        ),
    }
}

fn bind_target_probe() -> Result<UdpSocket, String> {
    let socket = UdpSocket::bind(("127.0.0.1", 0)).map_err(|e| format!("bind target: {e}"))?;
    socket
        .set_read_timeout(Some(Duration::from_millis(500)))
        .map_err(|e| e.to_string())?;
    Ok(socket)
}

// ---------------------------------------------------------------------------
// cases
// ---------------------------------------------------------------------------

fn case_positive() -> Result<Vec<Assertion>, String> {
    let double = start_vless_double()?;
    let (proxy, rx) = serve_once(&vless_yaml(double.addr), "127.0.0.1:0")?;
    let assoc = open(proxy, rx)?;
    let Some(bnd) = assoc.bnd else {
        return Ok(vec![Assertion::new(
            "associate_accepted",
            false,
            "REP != 0",
        )]);
    };
    let mut assertions = vec![Assertion::new(
        "associate_accepted",
        true,
        format!("bnd={bnd}"),
    )];

    for seq in 0..DATAGRAMS {
        assoc
            .udp
            .send_to(&encode_socks5_udp(&payload_for(seq)), bnd)
            .map_err(|e| format!("udp send: {e}"))?;
    }
    let mut replies: Vec<Vec<u8>> = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut buf = vec![0u8; MAX_SOCKS5_UDP];
    while replies.len() < DATAGRAMS as usize && Instant::now() < deadline {
        match assoc.udp.recv_from(&mut buf) {
            Ok((n, _)) => replies.push(decode_socks5_udp(&buf[..n])?),
            Err(_) => continue,
        }
    }
    let echoed = replies.len() == DATAGRAMS as usize
        && replies
            .iter()
            .zip(0..DATAGRAMS)
            .all(|(got, seq)| got == &payload_for(seq));
    assertions.push(Assertion::new(
        "udp_echo_roundtrip",
        echoed,
        format!("replies={}/{}", replies.len(), DATAGRAMS),
    ));

    let (proxy_json, proxy_error) = finish(assoc, Duration::from_secs(10));
    assertions.push(Assertion::new(
        "serve_terminated",
        proxy_json.is_some(),
        proxy_error.unwrap_or_else(|| "ok".to_string()),
    ));
    if let Some(json) = proxy_json {
        assertions.push(Assertion::new(
            "serve_verdict_pass",
            json["verdict"] == "PASS",
            json["verdict"].to_string(),
        ));
        assertions.push(Assertion::new(
            "udp_datagrams_in",
            json["udp"]["datagrams_in"] == DATAGRAMS,
            json["udp"]["datagrams_in"].to_string(),
        ));
        assertions.push(Assertion::new(
            "udp_datagrams_out",
            json["udp"]["datagrams_out"] == DATAGRAMS,
            json["udp"]["datagrams_out"].to_string(),
        ));
        assertions.push(Assertion::new(
            "udp_send_failed_zero",
            json["udp"]["send_failed"] == 0,
            json["udp"]["send_failed"].to_string(),
        ));
        assertions.push(Assertion::new(
            "routing_flow_outbound_kind",
            json["routing"]["flows"][0]["outbound_kind"] == "vless",
            json["routing"]["flows"][0]["outbound_kind"].to_string(),
        ));
        assertions.push(Assertion::new(
            "udp_mode_vless_over_tcp",
            json["udp"]["modes"][0] == "vless_over_tcp",
            json["udp"]["modes"].to_string(),
        ));
    }
    let delivered = double
        .received
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .len();
    assertions.push(Assertion::new(
        "vless_double_received_all",
        delivered == DATAGRAMS as usize,
        format!("received={delivered}/{DATAGRAMS}"),
    ));
    Ok(assertions)
}

fn case_non_loopback() -> Result<Vec<Assertion>, String> {
    let double = start_vless_double()?;
    let (proxy, rx) = serve_once(&vless_yaml(double.addr), "0.0.0.0:0")?;
    let (control, reply) = associate(proxy)?;
    let mut assertions = vec![
        Assertion::new(
            "rejected_rep",
            reply[1] != 0x00,
            format!("rep={:#04x}", reply[1]),
        ),
        Assertion::new(
            "rejected_atyp_is_ipv4",
            reply[3] == 0x01,
            reply[3].to_string(),
        ),
    ];
    let (proxy_json, _) = finish(
        Association {
            control,
            udp: UdpSocket::bind(("127.0.0.1", 0)).map_err(|e| e.to_string())?,
            bnd: None,
            rx,
        },
        Duration::from_secs(10),
    );
    if let Some(json) = proxy_json {
        assertions.push(Assertion::new(
            "reason_non_loopback_listener",
            json["association"]["reason"] == "non_loopback_listener",
            json["association"]["reason"].to_string(),
        ));
        assertions.push(Assertion::new(
            "no_udp_bind",
            json["association"]["bnd"].is_null(),
            json["association"]["bnd"].to_string(),
        ));
        assertions.push(Assertion::new(
            "associations_rejected",
            json["udp"]["associations_rejected"] == 1,
            json["udp"]["associations_rejected"].to_string(),
        ));
        assertions.push(Assertion::new(
            "target_zero_datagrams",
            json["udp"]["datagrams_in"] == 0,
            json["udp"]["datagrams_in"].to_string(),
        ));
    } else {
        assertions.push(Assertion::new("serve_json", false, "no serve json"));
    }
    Ok(assertions)
}

/// 通用 fail-closed 断言：目标端零收包 + 指定丢弃计数 + `sent == 0`。
fn fail_closed_assertions(
    json: &serde_json::Value,
    drop_field: &'static str,
    target: &UdpSocket,
    assertions: &mut Vec<Assertion>,
) {
    assertions.push(Assertion::new(
        "serve_verdict_pass",
        json["verdict"] == "PASS",
        json["verdict"].to_string(),
    ));
    assertions.push(Assertion::new(
        "udp_sent_zero",
        json["udp"]["sent"] == 0,
        json["udp"]["sent"].to_string(),
    ));
    assertions.push(Assertion::new(
        "udp_flows_opened_zero",
        json["udp"]["flows_opened"] == 0,
        json["udp"]["flows_opened"].to_string(),
    ));
    assertions.push(Assertion::new(
        drop_field,
        json["udp"][drop_field] == 1,
        json["udp"][drop_field].to_string(),
    ));
    let mut buf = [0u8; 64];
    let received = target.recv_from(&mut buf).is_ok();
    assertions.push(Assertion::new(
        "target_stats_zero",
        !received,
        "target received 0 datagrams",
    ));
}

fn send_one_and_settle(assoc: &Association) -> Result<(), String> {
    let bnd = assoc.bnd.ok_or("association has no BND")?;
    assoc
        .udp
        .send_to(&encode_socks5_udp(b"dashboard"), bnd)
        .map_err(|e| format!("udp send: {e}"))?;
    thread::sleep(Duration::from_millis(600));
    Ok(())
}

fn case_no_route() -> Result<Vec<Assertion>, String> {
    let target = bind_target_probe()?;
    let (proxy, rx) = serve_once(no_route_yaml(), "127.0.0.1:0")?;
    let assoc = open(proxy, rx)?;
    let accepted = assoc.bnd.is_some();
    send_one_and_settle(&assoc)?;
    let (proxy_json, _) = finish(assoc, Duration::from_secs(10));
    let mut assertions = vec![Assertion::new("associate_accepted", accepted, "")];
    if let Some(json) = proxy_json {
        fail_closed_assertions(&json, "dropped_no_route", &target, &mut assertions);
    } else {
        assertions.push(Assertion::new("serve_json", false, "no serve json"));
    }
    Ok(assertions)
}

fn case_direct() -> Result<Vec<Assertion>, String> {
    let target = bind_target_probe()?;
    let (proxy, rx) = serve_once(nexus::DEFAULT_PROXY_CONFIG, "127.0.0.1:0")?;
    let assoc = open(proxy, rx)?;
    let accepted = assoc.bnd.is_some();
    send_one_and_settle(&assoc)?;
    let (proxy_json, _) = finish(assoc, Duration::from_secs(10));
    let mut assertions = vec![Assertion::new("associate_accepted", accepted, "")];
    if let Some(json) = proxy_json {
        fail_closed_assertions(&json, "dropped_unsupported_other", &target, &mut assertions);
        assertions.push(Assertion::new(
            "unsupported_other_alias",
            json["udp"]["unsupported_other"] == 1,
            json["udp"]["unsupported_other"].to_string(),
        ));
    } else {
        assertions.push(Assertion::new("serve_json", false, "no serve json"));
    }
    Ok(assertions)
}

fn case_source_mismatch() -> Result<Vec<Assertion>, String> {
    let target = bind_target_probe()?;
    let (proxy, rx) = serve_once(nexus::DEFAULT_PROXY_CONFIG, "127.0.0.1:0")?;
    let assoc = open(proxy, rx)?;
    let Some(bnd) = assoc.bnd else {
        return Ok(vec![Assertion::new(
            "associate_accepted",
            false,
            "REP != 0",
        )]);
    };
    // 先由合法端点锁定端口（本条按 Direct 丢弃，不影响后续源校验判定）。
    assoc
        .udp
        .send_to(&encode_socks5_udp(b"legit"), bnd)
        .map_err(|e| format!("udp send legit: {e}"))?;
    thread::sleep(Duration::from_millis(300));
    // 异源：127.0.0.2（loopback /8）→ 源 IP 与控制连接对端不一致。
    let forged = UdpSocket::bind(("127.0.0.2", 0)).map_err(|e| format!("bind forged: {e}"))?;
    forged
        .send_to(&encode_socks5_udp(b"forged"), bnd)
        .map_err(|e| format!("udp send forged: {e}"))?;
    thread::sleep(Duration::from_millis(600));
    let (proxy_json, _) = finish(assoc, Duration::from_secs(10));
    let mut assertions = vec![Assertion::new(
        "associate_accepted",
        true,
        format!("bnd={bnd}"),
    )];
    if let Some(json) = proxy_json {
        assertions.push(Assertion::new(
            "source_mismatch_counted",
            json["udp"]["dropped_source_mismatch"] == 1,
            json["udp"]["dropped_source_mismatch"].to_string(),
        ));
        assertions.push(Assertion::new(
            "forged_not_delivered",
            json["udp"]["sent"] == 0,
            json["udp"]["sent"].to_string(),
        ));
        let mut buf = [0u8; 64];
        assertions.push(Assertion::new(
            "target_stats_zero",
            target.recv_from(&mut buf).is_err(),
            "target received 0 datagrams",
        ));
    } else {
        assertions.push(Assertion::new("serve_json", false, "no serve json"));
    }
    Ok(assertions)
}

fn case_oversize() -> Result<Vec<Assertion>, String> {
    let target = bind_target_probe()?;
    let (proxy, rx) = serve_once(nexus::DEFAULT_PROXY_CONFIG, "127.0.0.1:0")?;
    let assoc = open(proxy, rx)?;
    let Some(bnd) = assoc.bnd else {
        return Ok(vec![Assertion::new(
            "associate_accepted",
            false,
            "REP != 0",
        )]);
    };
    // 最大合法 SOCKS5 UDP 数据报：65507B（IP 层上限 = 入口上限；判定严格大于）。
    let payload = vec![0x5a_u8; MAX_SOCKS5_UDP - 10];
    let datagram = encode_socks5_udp(&payload);
    assoc
        .udp
        .send_to(&datagram, bnd)
        .map_err(|e| format!("udp send max: {e}"))?;
    thread::sleep(Duration::from_millis(600));
    let (proxy_json, _) = finish(assoc, Duration::from_secs(10));
    let mut assertions = vec![
        Assertion::new("associate_accepted", true, format!("bnd={bnd}")),
        Assertion::new(
            "max_datagram_bytes",
            datagram.len() == MAX_SOCKS5_UDP,
            datagram.len().to_string(),
        ),
    ];
    if let Some(json) = proxy_json {
        assertions.push(Assertion::new(
            "oversize_boundary_not_dropped",
            json["udp"]["dropped_oversize"] == 0,
            json["udp"]["dropped_oversize"].to_string(),
        ));
        // 最大合法包仍走 Direct 出站：按 Q11 fail-closed 丢弃，不直连。
        fail_closed_assertions(&json, "dropped_unsupported_other", &target, &mut assertions);
    } else {
        assertions.push(Assertion::new("serve_json", false, "no serve json"));
    }
    Ok(assertions)
}

fn main() -> std::process::ExitCode {
    let mut case = "positive".to_string();
    let mut as_json = false;
    for arg in std::env::args().skip(1) {
        if let Some(value) = arg.strip_prefix("--case=") {
            case = value.to_string();
        } else if arg == "--json" {
            as_json = true;
        } else {
            eprintln!("unknown argument {arg}");
            return std::process::ExitCode::from(2);
        }
    }
    if !CASES.contains(&case.as_str()) {
        eprintln!("unknown case {case}; expected one of {CASES:?}");
        return std::process::ExitCode::from(2);
    }
    let result = match case.as_str() {
        "positive" => case_positive(),
        "non-loopback" => case_non_loopback(),
        "no-route" => case_no_route(),
        "direct" => case_direct(),
        "source-mismatch" => case_source_mismatch(),
        _ => case_oversize(),
    };
    let assertions = match result {
        Ok(assertions) => assertions,
        Err(err) => {
            println!(
                "{}",
                serde_json::json!({"case": case, "verdict": "ERROR", "detail": err})
            );
            return std::process::ExitCode::from(2);
        }
    };
    let pass = assertions.iter().all(|a| a.ok);
    let payload = serde_json::json!({
        "case": case,
        "verdict": if pass { "PASS" } else { "FAIL" },
        "assertions": assertions
            .iter()
            .map(|a| serde_json::json!({"name": a.name, "ok": a.ok, "detail": a.detail}))
            .collect::<Vec<_>>(),
    });
    if as_json {
        println!("{payload}");
    } else {
        println!("case={case} verdict={}", if pass { "PASS" } else { "FAIL" });
        for assertion in &assertions {
            println!(
                "  [{}] {} — {}",
                if assertion.ok { "ok" } else { "FAIL" },
                assertion.name,
                assertion.detail
            );
        }
    }
    std::process::ExitCode::from(if pass { 0 } else { 1 })
}
