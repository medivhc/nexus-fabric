//! IPv6 TCP termination E4（R3 C22）：AC9 无条件部分。
//!
//! 装配链（plan §7.1 铁律）：
//! `ConfigDir::new` → `config::load` → `assembly::build_dataplane_config`
//! → `Dataplane::new(SharedTun(MockTun), cfg, None)`（Proxy 段再注入
//! `ProxyEngine::new(loaded.proxy_yaml)`，与 `main.rs` 的组合根一致）。
//!
//! 覆盖：
//! - Mesh：v6 SYN `[fd00:144::6]:80` → SYN-ACK（TCP 校验和自校验 = 0）
//!   → STREAM SYN 帧（载荷目标 = `[fd00:144::6]:80`）；
//! - Mesh 回显：v6 SYN 到 `[::1]:<echo>`（`::1/128` 在测试夹具里作为
//!   mesh 路由，避免 root 才能绑定的 ULA），B 侧 `TcpRelay` 真实 dial
//!   `[::1]:<echo>`，双向字节一致；
//! - Proxy：v6 SYN 到 Proxy 类 → 终结完成；Shadowsocks 出站不支持 v6
//!   → `UnsupportedTarget` → RST + `ipv6.proxy_dropped` 不增、既有
//!   `proxy_*` 失败计数可见。
//!
//! **不含 CAC-1**（Proxy 端到端回显）——按 plan §6.1 留合并门补跑。
//!
//! 用法：
//! ```text
//! cargo run --quiet -p nexusd --example ipv6_tcp_termination_e4 -- --json
//! ```

#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv6Addr, Shutdown, TcpListener};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nexus_network::n1::N1Error;
use nexus_network::n1::bridge::N1Sender;
use nexus_projection::ip::tcp_udp_checksum_v6;
use nexus_projection::tcp::{
    RelayEvent, STREAM_FIN, STREAM_SYN, TcpRelay, decode_stream_frame, encode_stream_frame,
};
use nexus_projection::{MockTun, TunDevice};
use nexusd::config::ConfigDir;
use nexusd::dataplane::Dataplane;
use serde_json::{Value, json};

const PEER_ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const CLIENT6: &str = "2001:db8::100";
const MESH_DST: &str = "fd00:144::6";
const PROXY_DST: &str = "2001:db8::20";

type Frames = Arc<Mutex<Vec<(IpAddr, Vec<u8>)>>>;

struct SharedTun(Arc<Mutex<MockTun>>);

impl TunDevice for SharedTun {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().read(buf)
    }

    fn write(&mut self, packet: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().write(packet)
    }

    fn name(&self) -> &str {
        "mockv6tcp"
    }
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "nexusd-ipv6tcp-e4-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("temp dir");
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct CaptureSender {
    frames: Frames,
}

impl N1Sender for CaptureSender {
    fn send_to_mesh(&self, dst: IpAddr, packet: &[u8]) -> Result<(), N1Error> {
        self.frames.lock().unwrap().push((dst, packet.to_vec()));
        Ok(())
    }
}

struct Env {
    _dir: TempDir,
    dp: Dataplane,
    mock: Arc<Mutex<MockTun>>,
    frames: Frames,
}

fn daemon_toml() -> String {
    "[tun]\nenabled = true\n[localapi]\naddr = \"127.0.0.1:0\"\n".to_string()
}

fn network_toml(routes6: &[&str]) -> String {
    let mut text = format!(
        "peer_id = \"{PEER_ID}\"\n\
         [[peers]]\n\
         id = \"{PEER_ID}\"\n\
         addrs = [\"127.0.0.1:19001\"]\n\
         [vpi]\n\
         interface = \"nexus0\"\n\
         address = \"10.144.144.1\"\n\
         mtu = 1200\n\
         address6 = \"fd00:144::1\"\n\
         [[vpi.routes]]\n\
         subnet = \"10.144.144.0/24\"\n\
         peer = \"{PEER_ID}\"\n"
    );
    for subnet in routes6 {
        text.push_str(&format!(
            "[[vpi.routes6]]\n\
             subnet = \"{subnet}\"\n\
             peer = \"{PEER_ID}\"\n"
        ));
    }
    text
}

fn proxy_yaml() -> String {
    // Shadowsocks 出站：adapter 不支持 v6 目标（plan §6.1 的 ② 类），
    // dial 阶段返回 UnsupportedTarget → RST。
    "schema_version: 1\n\
     rules:\n\
     \x20 - tag: r1\n\
     \x20   kind: match\n\
     \x20   action:\n\
     \x20     - kind: select_outbound\n\
     \x20       tag: proxy\n\
     groups: []\n\
     outbounds:\n\
     \x20 - tag: proxy\n\
     \x20   kind: shadowsocks\n\
     \x20   locator: 127.0.0.1:8388\n\
     \x20   method: chacha20-ietf-poly1305\n\
     \x20   password: demo-password-123\n"
        .to_string()
}

fn assemble(tag: &str, routes6: &[&str], with_proxy: bool) -> Result<Env, String> {
    let dir = TempDir::new(tag);
    std::fs::write(dir.0.join("daemon.toml"), daemon_toml()).map_err(|e| e.to_string())?;
    std::fs::write(dir.0.join("network.toml"), network_toml(routes6)).map_err(|e| e.to_string())?;
    if with_proxy {
        std::fs::write(dir.0.join("proxy.yaml"), proxy_yaml()).map_err(|e| e.to_string())?;
    }
    let config_dir = ConfigDir::new(&dir.0).map_err(|e| e.to_string())?;
    let loaded = nexusd::config::load(&config_dir).map_err(|e| e.to_string())?;
    let config = nexusd::assembly::build_dataplane_config(&loaded)?;
    let mock = Arc::new(Mutex::new(MockTun::new("mockv6tcp")));
    let mut dp = Dataplane::new(Box::new(SharedTun(Arc::clone(&mock))), config, None)?;
    if with_proxy {
        let engine = nexusd::proxy_fwd::ProxyEngine::new(loaded.proxy_yaml.as_deref())
            .map_err(|e| format!("engine init: {e:?}"))?
            .ok_or_else(|| "proxy engine not constructed".to_string())?;
        dp.set_proxy_engine(engine);
    }
    let frames: Frames = Arc::new(Mutex::new(Vec::new()));
    dp.set_n1_sender(Arc::new(CaptureSender {
        frames: Arc::clone(&frames),
    }));
    Ok(Env {
        _dir: dir,
        dp,
        mock,
        frames,
    })
}

impl Env {
    fn inject(&mut self, packet: Vec<u8>) -> Result<(), String> {
        self.mock.lock().unwrap().inject(packet);
        self.dp.process_one().map(|_| ()).map_err(|e| e.to_string())
    }

    fn written(&mut self) -> Vec<Vec<u8>> {
        self.mock.lock().unwrap().take_written()
    }

    fn frames(&self) -> Vec<(IpAddr, Vec<u8>)> {
        self.frames.lock().unwrap().clone()
    }
}

/// 构造 v6/TCP 包（校验和写全；AC9 要求自校验 = 0）。
#[allow(clippy::too_many_arguments)]
fn v6_tcp(
    src: &str,
    dst: &str,
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let src: Ipv6Addr = src.parse().expect("src v6");
    let dst: Ipv6Addr = dst.parse().expect("dst v6");
    let mut pkt = vec![0u8; 40 + 20 + payload.len()];
    pkt[0] = 0x60;
    pkt[4..6].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    pkt[6] = 6;
    pkt[7] = 64;
    pkt[8..24].copy_from_slice(&src.octets());
    pkt[24..40].copy_from_slice(&dst.octets());
    pkt[40..42].copy_from_slice(&sport.to_be_bytes());
    pkt[42..44].copy_from_slice(&dport.to_be_bytes());
    pkt[44..48].copy_from_slice(&seq.to_be_bytes());
    pkt[48..52].copy_from_slice(&ack.to_be_bytes());
    pkt[52] = 0x50;
    pkt[53] = flags;
    pkt[54..56].copy_from_slice(&8192u16.to_be_bytes());
    pkt[60..].copy_from_slice(payload);
    let tc = tcp_udp_checksum_v6(src, dst, 6, &pkt[40..]);
    pkt[56..58].copy_from_slice(&tc.to_be_bytes());
    pkt
}

fn tcp_fields(pkt: &[u8]) -> Option<(IpAddr, IpAddr, u16, u16, u32, u8, usize)> {
    let view = nexus_projection::ip::parse_ip_packet(pkt).ok()?;
    if view.protocol != 6 {
        return None;
    }
    let tcp = view.payload;
    if tcp.len() < 20 {
        return None;
    }
    let off = view.l4_offset + usize::from(tcp[12] >> 4) * 4;
    Some((
        view.src,
        view.dst,
        u16::from_be_bytes([tcp[0], tcp[1]]),
        u16::from_be_bytes([tcp[2], tcp[3]]),
        u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]),
        tcp[13],
        off,
    ))
}

fn v6_checksum_ok(pkt: &[u8]) -> bool {
    let view = match nexus_projection::ip::parse_ip_packet(pkt) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let (IpAddr::V6(src), IpAddr::V6(dst)) = (view.src, view.dst) else {
        return false;
    };
    tcp_udp_checksum_v6(src, dst, 6, view.payload) == 0
}

fn has_flag(pkt: &[u8], mask: u8) -> bool {
    tcp_fields(pkt).is_some_and(|(.., flags, _)| flags & mask != 0)
}

/// 解出 typed SYN 载荷里的 v6 目标（addr-type `0x02`，C20 wire 格式）。
fn syn_v6_target(payload: &[u8]) -> Option<(Ipv6Addr, u16)> {
    if payload.first() != Some(&0x02) || payload.len() < 19 {
        return None;
    }
    let mut octets = [0u8; 16];
    octets.copy_from_slice(&payload[1..17]);
    Some((
        Ipv6Addr::from(octets),
        u16::from_be_bytes([payload[17], payload[18]]),
    ))
}

fn payload_of(pkt: &[u8]) -> Vec<u8> {
    match tcp_fields(pkt) {
        Some((.., off)) if pkt.len() > off => pkt[off..].to_vec(),
        _ => Vec::new(),
    }
}

/// 本地 v6 echo 服务（只在 `[::1]` 可达，无需 root）。
fn start_echo() -> Result<(u16, std::thread::JoinHandle<Vec<u8>>), String> {
    let listener = TcpListener::bind("[::1]:0").map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let handle = std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().expect("accept");
        let mut buf = Vec::new();
        sock.read_to_end(&mut buf).expect("read");
        sock.write_all(&buf).expect("write echo");
        sock.shutdown(Shutdown::Write).ok();
        buf
    });
    Ok((port, handle))
}

/// Mesh 段：v6 SYN 终结 + STREAM 帧 + B 侧真实 dial 回显。
fn section_mesh() -> Result<Value, String> {
    // `::1/128` 作为 mesh 路由只用于测试：fixture 无法在无 root 下绑定 ULA，
    // 这样回显腿仍走 Mesh 分类 + 生产装配路径。
    let mut env = assemble("mesh", &["fd00:144::/64", "::1/128"], false)?;
    let (port, echo_thread) = start_echo()?;

    // 1) 固定 mesh 地址：SYN-ACK + STREAM SYN 帧目标逐字为 [fd00:144::6]:80。
    env.inject(v6_tcp(CLIENT6, MESH_DST, 40000, 80, 1000, 0, 0x02, &[]))?;
    let syn_ack = env.written();
    let (ack_src, ack_dst, ack_sp, ack_dp, srv_seq, ack_flags, _) = syn_ack
        .first()
        .and_then(|p| tcp_fields(p))
        .ok_or_else(|| "mesh: no SYN-ACK".to_string())?;
    let syn_ack_ok = syn_ack.len() == 1
        && ack_src == MESH_DST.parse::<IpAddr>().unwrap() // fixup 后源 = 原始目的
        && ack_dst == CLIENT6.parse::<IpAddr>().unwrap()
        && (ack_sp, ack_dp) == (80, 40000)
        && ack_flags & 0x12 == 0x12
        && v6_checksum_ok(&syn_ack[0]);
    env.inject(v6_tcp(
        CLIENT6,
        MESH_DST,
        40000,
        80,
        1001,
        srv_seq.wrapping_add(1),
        0x10,
        &[],
    ))?;
    let mesh_frames: Vec<(IpAddr, u8, Vec<u8>)> = env
        .frames()
        .into_iter()
        .filter_map(|(dst, raw)| {
            let (_, flags, payload) = decode_stream_frame(&raw)?;
            Some((dst, flags, payload.to_vec()))
        })
        .collect();
    let mesh_syn_target = mesh_frames.iter().find_map(|(_, flags, payload)| {
        if *flags & STREAM_SYN == 0 {
            return None;
        }
        syn_v6_target(payload)
    });
    let mesh_syn_ok = mesh_syn_target == Some((MESH_DST.parse().expect("mesh dst"), 80));

    // 2) 回显腿：同一 Mesh 分类，B 侧真实 dial [::1]:<echo>。
    let echo_dst = format!("[::1]:{port}");
    env.inject(v6_tcp(CLIENT6, "::1", 40001, port, 2000, 0, 0x02, &[]))?;
    let echo_syn_ack = env.written();
    let (e_src, _, _, _, e_srv_seq, e_flags, _) = echo_syn_ack
        .first()
        .and_then(|p| tcp_fields(p))
        .ok_or_else(|| "echo: no SYN-ACK".to_string())?;
    let echo_synack_ok = e_src == "::1".parse::<IpAddr>().unwrap()
        && e_flags & 0x12 == 0x12
        && v6_checksum_ok(&echo_syn_ack[0]);
    env.inject(v6_tcp(
        CLIENT6,
        "::1",
        40001,
        port,
        2001,
        e_srv_seq.wrapping_add(1),
        0x10,
        &[],
    ))?;
    let echo_frames = env.frames();
    let echo_sid = echo_frames.iter().find_map(|(_, raw)| {
        let (sid, flags, payload) = decode_stream_frame(raw)?;
        if flags & STREAM_SYN == 0 {
            return None;
        }
        match syn_v6_target(payload) {
            Some((_, p)) if p == port => Some(sid),
            _ => None,
        }
    });
    let echo_sid = echo_sid.ok_or_else(|| "echo: no SYN frame".to_string())?;
    let echo_syn_payload = echo_frames
        .iter()
        .find_map(|(_, raw)| {
            let (sid, flags, payload) = decode_stream_frame(raw)?;
            (sid == echo_sid && flags & STREAM_SYN != 0).then(|| payload.to_vec())
        })
        .ok_or_else(|| "echo: SYN payload missing".to_string())?;

    // B 侧：生产 TcpRelay 解析 SYN 载荷并真实 dial。
    let mut relay = TcpRelay::new();
    let _ = relay.handle_frame(echo_sid, STREAM_SYN, &echo_syn_payload, "B");
    env.inject(v6_tcp(
        CLIENT6,
        "::1",
        40001,
        port,
        2001,
        e_srv_seq.wrapping_add(1),
        0x18,
        b"hello",
    ))?;
    let echo_data = env
        .frames()
        .into_iter()
        .find_map(|(_, raw)| {
            let (sid, flags, payload) = decode_stream_frame(&raw)?;
            (sid == echo_sid && flags & STREAM_SYN == 0 && !payload.is_empty())
                .then(|| payload.to_vec())
        })
        .unwrap_or_default();
    let _ = relay.handle_frame(echo_sid, 0, &echo_data, "B");
    let _ = relay.handle_frame(echo_sid, STREAM_FIN, &[], "B");

    let mut echoed = Vec::new();
    let mut relay_closed = false;
    for _ in 0..400 {
        for ev in relay.poll() {
            match ev {
                RelayEvent::Data { bytes, .. } => echoed.extend_from_slice(&bytes),
                RelayEvent::Closed { reset, .. } => {
                    relay_closed = !reset;
                }
            }
        }
        if !echoed.is_empty() && relay_closed {
            break;
        }
        std::thread::sleep(Duration::from_millis(3));
    }
    let _ = echo_thread.join();

    // 回字节经 N1 下行注入 A 的终结器 → 客户端从 TUN 读回。
    env.dp
        .inject_stream_frame_from_n1("B", &encode_stream_frame(echo_sid, 0, &echoed));
    let down_pkts = env.written();
    let down = down_pkts
        .iter()
        .map(|p| payload_of(p))
        .find(|p| !p.is_empty())
        .unwrap_or_default();
    let bytes_up = echo_data == b"hello";
    let bytes_match = echoed == b"hello" && down == b"hello";
    let dial_ok = relay.stats().relayed_bytes >= 5 || !echoed.is_empty();

    let mesh_ok = syn_ack_ok && mesh_syn_ok;
    let echo_ok = echo_synack_ok && dial_ok && bytes_up && bytes_match;
    Ok(json!({
        "mesh": {
            "fd00_synack_ok": syn_ack_ok,
            "mesh_syn_target_ok": mesh_syn_ok,
            "echo_synack_ok": echo_synack_ok,
            "echo_target": echo_dst,
            "dial_ok": dial_ok,
            "bytes_up": bytes_up,
            "bytes_down": echoed == b"hello",
            "client_received": down == b"hello",
            "bytes_match": bytes_match,
        },
        "ok": mesh_ok && echo_ok,
    }))
}

/// Proxy 段：v6 TCP 终结 + 不支持 v6 的出站 → RST + 计数。
fn section_proxy() -> Result<Value, String> {
    let mut env = assemble("proxy", &["fd00:144::/64"], true)?;
    env.inject(v6_tcp(CLIENT6, PROXY_DST, 41000, 80, 5000, 0, 0x02, &[]))?;
    let first = env.written();
    let (src, _, sp, dp, srv_seq, flags, _) = first
        .first()
        .and_then(|p| tcp_fields(p))
        .ok_or_else(|| "proxy: no SYN-ACK".to_string())?;
    let synack_ok = src == PROXY_DST.parse::<IpAddr>().unwrap()
        && (sp, dp) == (80, 41000)
        && flags & 0x12 == 0x12
        && v6_checksum_ok(&first[0]);
    env.inject(v6_tcp(
        CLIENT6,
        PROXY_DST,
        41000,
        80,
        5001,
        srv_seq.wrapping_add(1),
        0x10,
        &[],
    ))?;

    let mut rst = None;
    for tick in 0..800u64 {
        let _ = env.dp.tick(tick);
        let written = env.written();
        if let Some(p) = written.into_iter().find(|p| has_flag(p, 0x04)) {
            rst = Some(p);
            break;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    let rst_ok = rst.as_ref().is_some_and(|p| v6_checksum_ok(p));
    let stats = env.dp.stats();
    let proxy_ok = synack_ok
        && rst.is_some()
        && rst_ok
        && stats.ipv6.tcp == 2
        && stats.ipv6.classified_proxy == 2
        && stats.ipv6.proxy_dropped == 0
        && stats.proxy_tcp_streams == 1
        && stats.proxy_dropped_no_proxy == 1;
    Ok(json!({
        "proxy": {
            "synack_ok": synack_ok,
            "synack_src": src.to_string(),
            "synack_sp": sp,
            "synack_dp": dp,
            "synack_flags": flags,
            "synack_checksum_ok": first.first().is_some_and(|p| v6_checksum_ok(p)),
            "rst_seen": rst.is_some(),
            "rst_checksum_ok": rst_ok,
            "ipv6_tcp": stats.ipv6.tcp,
            "classified_proxy": stats.ipv6.classified_proxy,
            "ipv6_proxy_dropped": stats.ipv6.proxy_dropped,
            "proxy_tcp_streams": stats.proxy_tcp_streams,
            "proxy_dropped_no_proxy": stats.proxy_dropped_no_proxy,
        },
        "ok": proxy_ok,
    }))
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let json_mode = args.iter().any(|a| a == "--json");
    let out = run();
    if json_mode {
        println!("{}", serde_json::to_string(&out).unwrap());
    } else {
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
    }
}

fn run() -> Value {
    let mesh = match section_mesh() {
        Ok(v) => v,
        Err(e) => json!({"error": e, "ok": false}),
    };
    let proxy = match section_proxy() {
        Ok(v) => v,
        Err(e) => json!({"error": e, "ok": false}),
    };
    let ok = mesh["ok"] == Value::Bool(true) && proxy["ok"] == Value::Bool(true);
    json!({
        "verdict": if ok { "PASS" } else { "FAIL" },
        "mesh": mesh,
        "proxy": proxy,
    })
}
