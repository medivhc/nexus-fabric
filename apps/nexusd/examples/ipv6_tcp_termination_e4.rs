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
    assemble_yaml(tag, routes6, with_proxy.then(proxy_yaml))
}

/// 按给定 proxy.yaml 文本装配（`assemble` 的泛化版；CAC-1 各方言腿用）。
fn assemble_yaml(tag: &str, routes6: &[&str], yaml: Option<String>) -> Result<Env, String> {
    let dir = TempDir::new(tag);
    std::fs::write(dir.0.join("daemon.toml"), daemon_toml()).map_err(|e| e.to_string())?;
    std::fs::write(dir.0.join("network.toml"), network_toml(routes6)).map_err(|e| e.to_string())?;
    if let Some(text) = &yaml {
        std::fs::write(dir.0.join("proxy.yaml"), text).map_err(|e| e.to_string())?;
    }
    let config_dir = ConfigDir::new(&dir.0).map_err(|e| e.to_string())?;
    let loaded = nexusd::config::load(&config_dir).map_err(|e| e.to_string())?;
    let config = nexusd::assembly::build_dataplane_config(&loaded)?;
    let mock = Arc::new(Mutex::new(MockTun::new("mockv6tcp")));
    let mut dp = Dataplane::new(Box::new(SharedTun(Arc::clone(&mock))), config, None)?;
    if yaml.is_some() {
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

// ---------- CAC-1（合并门补跑；plan §6.1 / 冻结件 rev3 §7.3） ----------
//
// 冻结断言四条：① TUN 注入精确 v6 TCP SYN、目的为代理类 v6 目标（不走 fake-ip）；
// ② A 完成 v6 TCP 终结（SYN-ACK、校验和正确）；③ `dial_through_proxy` 经 adapter
// 接受 v6 目标、到达 v6 echo server；④ 上下行双向回显一致、`proxy_*` 计数按既有
// 语义增长、`ipv6.proxy_dropped` 不增长。
// 断言边界与 AC9 分开（plan §6.1 写死）：AC9 断言回显**不得**出现（SS 拒例 → RST），
// CAC-1 正例断言回显**必须**出现。方言覆盖（收官报告补跑清单）：socks5 / VLESS /
// AnyTLS v6 正例 + SS / Trojan v6 拒例。三个正例的 server 都是进程内最小实现
// （socks5 手写、VLESS 用 nexus-outbound-vless 的 server 侧编解码、AnyTLS 用
// nexus-outbound-anytls 的 server_handshake/帧 API + loopback 自签身份），
// 只处理一条连接、只做目标记录 + 真实 dial + 双向中继——被测路径（生产
// Dataplane + ProxyEngine + adapter 客户端）与真实部署完全一致。

const CAC1_PAYLOAD: &[u8] = b"cac1-v6-echo";
const CAC1_PASSWORD: &str = "cac1-password";

/// mock server 观测到的目标：(是否为 v6 目标, 地址文本, 端口)。
type Cac1Obs = Arc<Mutex<Option<(bool, String, u16)>>>;

fn cac1_obs() -> Cac1Obs {
    Arc::new(Mutex::new(None))
}

/// 发现本机一个稳定的全局 v6 地址（`/proc/net/if_inet6`，scope=global、
/// 非临时地址）。CAC-1 正例的目标不能用 `::1`：数据面 v6 bypass 默认集
/// （assembly 的 `DEFAULT_BYPASS_CIDRS6` = ULA / link-local / `::1/128`）
/// 把 loopback 分类为 Direct 而非 Proxy；全局单播地址不在 bypass、不在
/// mesh 路由内 → Proxy 分类，且本机真实可达（echo 就绑在该地址上）。
fn discover_global_v6() -> Option<Ipv6Addr> {
    let text = std::fs::read_to_string("/proc/net/if_inet6").ok()?;
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 6 || f[3] != "00" {
            continue;
        }
        let flags = u32::from_str_radix(f[4], 16).unwrap_or(0);
        if flags & 0x01 != 0 {
            continue; // 临时地址（隐私扩展），跳过
        }
        let raw = u128::from_str_radix(f[0], 16).ok()?;
        return Some(Ipv6Addr::from(raw));
    }
    None
}

/// 实时回显服务（绑指定 v6 地址，accept 循环 + 逐块回显；与 `start_echo` 的
/// read-to-end 语义不同——代理中继是交互式的，不能等 FIN 才回）。
fn start_echo_rt(addr: Ipv6Addr) -> Result<u16, String> {
    let listener = TcpListener::bind((addr, 0)).map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut sock) = stream else { continue };
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                loop {
                    match sock.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    Ok(port)
}

/// 双向字节中继（两条 copy 线程，EOF 时半关闭对端写方向）。
fn relay_bidir(a: std::net::TcpStream, b: std::net::TcpStream) {
    fn pump(mut r: std::net::TcpStream, mut w: std::net::TcpStream) {
        let _ = std::io::copy(&mut r, &mut w);
        let _ = w.shutdown(Shutdown::Write);
    }
    let a2 = a.try_clone();
    let b2 = b.try_clone();
    let (Ok(a2), Ok(b2)) = (a2, b2) else { return };
    let t = std::thread::spawn(move || pump(a2, b2));
    pump(b, a);
    let _ = t.join();
}

/// 单出站 proxy.yaml（与 `proxy_yaml()` 同构，只换 outbound 段）。
fn cac1_yaml(kind: &str, extra: &str) -> String {
    format!(
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
         \x20   kind: {kind}\n\
         {extra}"
    )
}

/// 最小 socks5 server（无认证；记录 CONNECT 的 ATYP/地址/端口后真实 dial 并中继）。
fn spawn_socks5(obs: Cac1Obs) -> Result<u16, String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    std::thread::spawn(move || {
        let Ok((mut c, _)) = listener.accept() else {
            return;
        };
        let mut h = [0u8; 2];
        if c.read_exact(&mut h).is_err() || h[0] != 5 {
            return;
        }
        let mut methods = vec![0u8; h[1] as usize];
        if c.read_exact(&mut methods).is_err() || c.write_all(&[5, 0]).is_err() {
            return;
        }
        let mut req = [0u8; 4];
        if c.read_exact(&mut req).is_err() {
            return;
        }
        let atyp = req[3];
        let addr: IpAddr = match atyp {
            0x01 => {
                let mut a = [0u8; 4];
                if c.read_exact(&mut a).is_err() {
                    return;
                }
                IpAddr::V4(a.into())
            }
            0x04 => {
                let mut a = [0u8; 16];
                if c.read_exact(&mut a).is_err() {
                    return;
                }
                IpAddr::V6(a.into())
            }
            _ => return,
        };
        let mut pb = [0u8; 2];
        if c.read_exact(&mut pb).is_err() {
            return;
        }
        let dport = u16::from_be_bytes(pb);
        *obs.lock().unwrap() = Some((atyp == 0x04, addr.to_string(), dport));
        let Ok(target) = std::net::TcpStream::connect((addr, dport)) else {
            return;
        };
        if c.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).is_err() {
            return;
        }
        relay_bidir(c, target);
    });
    Ok(port)
}

/// 最小 VLESS server（用 nexus-outbound-vless 的 server 侧 `decode_request` /
/// `encode_response`；记录目标后真实 dial 并中继）。
fn spawn_vless(obs: Cac1Obs) -> Result<u16, String> {
    use nexus_outbound_vless::{
        VlessError, VlessResponse, VlessTarget, decode_request, encode_response,
    };
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    std::thread::spawn(move || {
        let Ok((mut c, _)) = listener.accept() else {
            return;
        };
        let mut buf: Vec<u8> = Vec::new();
        let mut byte = [0u8; 1];
        let parsed = loop {
            if c.read_exact(&mut byte).is_err() {
                return;
            }
            buf.push(byte[0]);
            match decode_request(&buf) {
                Ok(v) => break Some(v),
                Err(VlessError::TruncatedHeader) if buf.len() < 1024 => continue,
                Err(_) => break None,
            }
        };
        let Some((req, used)) = parsed else { return };
        let Some(target) = req.target else { return };
        let (is_v6, ip) = match target {
            VlessTarget::Ipv6(ip) => (true, IpAddr::V6(ip)),
            VlessTarget::Ipv4(ip) => (false, IpAddr::V4(ip)),
            VlessTarget::Domain(_) => return,
        };
        *obs.lock().unwrap() = Some((is_v6, ip.to_string(), req.port));
        let Ok(mut target_stream) = std::net::TcpStream::connect((ip, req.port)) else {
            return;
        };
        let resp = encode_response(&VlessResponse {
            version: 0,
            addon: Vec::new(),
        });
        if c.write_all(&resp).is_err() || target_stream.write_all(&buf[used..]).is_err() {
            return;
        }
        relay_bidir(c, target_stream);
    });
    Ok(port)
}

/// 最小 AnyTLS server（nexus-outbound-anytls 的 `server_handshake` + 帧 API +
/// loopback 自签身份；首个 PSH 的 SOCKS5 地址即目标，真实 dial 后单线程轮询中继）。
fn spawn_anytls(obs: Cac1Obs) -> Result<u16, String> {
    use nexus_outbound_anytls::{
        AnyTlsCommand, DEFAULT_PADDING_SCHEME, decode_socks5_addr, generate_loopback_identity,
        read_frame, server_config, server_handshake, write_frame,
    };
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    std::thread::spawn(move || {
        let Ok((sock, _)) = listener.accept() else {
            return;
        };
        let Ok(sock_ctl) = sock.try_clone() else {
            return;
        };
        let Ok(identity) = generate_loopback_identity() else {
            return;
        };
        let Ok(cfg) = server_config(&identity) else {
            return;
        };
        let Ok(conn) = rustls::ServerConnection::new(Arc::new(cfg)) else {
            return;
        };
        let mut tls = rustls::StreamOwned::new(conn, sock);
        // 读超时把 read_frame 变成轮询拍（单线程同时喂目标 socket 的回程数据）。
        let _ = sock_ctl.set_read_timeout(Some(Duration::from_millis(200)));
        if server_handshake(&mut tls, CAC1_PASSWORD, DEFAULT_PADDING_SCHEME).is_err() {
            return;
        }
        let mut sid: u32 = 0;
        let mut target: Option<std::net::TcpStream> = None;
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        'outer: while std::time::Instant::now() < deadline {
            match read_frame(&mut tls) {
                Ok(frame) => match frame.cmd {
                    AnyTlsCommand::Syn => sid = frame.stream_id,
                    AnyTlsCommand::Psh if target.is_none() => {
                        let Ok((t, consumed)) = decode_socks5_addr(&frame.data) else {
                            return;
                        };
                        let (is_v6, ip) = match t {
                            nexus_outbound_anytls::AnyTlsTarget::Ipv6(seg, _) => {
                                (true, IpAddr::V6(seg.into()))
                            }
                            nexus_outbound_anytls::AnyTlsTarget::Ipv4(oct, _) => {
                                (false, IpAddr::V4(oct.into()))
                            }
                            nexus_outbound_anytls::AnyTlsTarget::Domain(_, _) => return,
                        };
                        *obs.lock().unwrap() = Some((is_v6, ip.to_string(), t.port()));
                        let Ok(mut ts) = std::net::TcpStream::connect((ip, t.port())) else {
                            return;
                        };
                        let _ = ts.set_nonblocking(true);
                        if write_frame(&mut tls, AnyTlsCommand::SynAck, sid, &[]).is_err() {
                            return;
                        }
                        if frame.data.len() > consumed
                            && ts.write_all(&frame.data[consumed..]).is_err()
                        {
                            return;
                        }
                        target = Some(ts);
                    }
                    AnyTlsCommand::Psh => {
                        if let Some(ts) = target.as_mut() {
                            if ts.write_all(&frame.data).is_err() {
                                return;
                            }
                        }
                    }
                    AnyTlsCommand::Fin => break 'outer,
                    _ => {}
                },
                Err(_) => {
                    // 读超时 = 本拍无帧；其它错误也退出（证据由客户端侧断言呈现）。
                    if target.is_none() {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                }
            }
            if let Some(ts) = target.as_mut() {
                let mut buf = [0u8; 8192];
                match ts.read(&mut buf) {
                    Ok(0) => {
                        let _ = write_frame(&mut tls, AnyTlsCommand::Fin, sid, &[]);
                        break 'outer;
                    }
                    Ok(n) => {
                        if write_frame(&mut tls, AnyTlsCommand::Psh, sid, &buf[..n]).is_err() {
                            return;
                        }
                    }
                    Err(_) => {}
                }
            }
        }
    });
    Ok(port)
}

/// accept 即关的 listener（Trojan 拒例：TLS 握手立即 EOF → dial 快速失败）。
fn spawn_accept_close() -> Result<u16, String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            drop(stream);
        }
    });
    Ok(port)
}

/// CAC-1 正例腿：注入 v6 SYN → [::1]:echo（Proxy 分类）→ 终结 → adapter dial
/// 进程内 server → server 真实 dial v6 echo → 双向回显 + 计数断言。
fn cac1_positive_leg(
    tag: &str,
    yaml: String,
    obs: &Cac1Obs,
    dst: IpAddr,
    echo_port: u16,
) -> Result<Value, String> {
    let mut env = assemble_yaml(tag, &["fd00:144::/64"], Some(yaml))?;
    let dst_s = dst.to_string();
    env.inject(v6_tcp(
        CLIENT6,
        &dst_s,
        42000,
        echo_port,
        7000,
        0,
        0x02,
        &[],
    ))?;
    let first = env.written();
    let (src, _, sp, dp, srv_seq, flags, _) = first
        .first()
        .and_then(|p| tcp_fields(p))
        .ok_or_else(|| "cac1: no SYN-ACK".to_string())?;
    let synack_ok = src == dst
        && (sp, dp) == (echo_port, 42000)
        && flags & 0x12 == 0x12
        && v6_checksum_ok(&first[0]);
    env.inject(v6_tcp(
        CLIENT6,
        &dst_s,
        42000,
        echo_port,
        7001,
        srv_seq.wrapping_add(1),
        0x10,
        &[],
    ))?;
    env.inject(v6_tcp(
        CLIENT6,
        &dst_s,
        42000,
        echo_port,
        7001,
        srv_seq.wrapping_add(1),
        0x18,
        CAC1_PAYLOAD,
    ))?;
    let mut echo_ok = false;
    let mut rst_seen = false;
    for tick in 0..2000u64 {
        let _ = env.dp.tick(tick);
        for p in env.written() {
            if has_flag(&p, 0x04) {
                rst_seen = true;
            }
            if let Some((s, _, sport, _, _, _, _)) = tcp_fields(&p) {
                if s == dst && sport == echo_port && payload_of(&p) == CAC1_PAYLOAD {
                    echo_ok = true;
                }
            }
        }
        if echo_ok {
            break;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    let stats = env.dp.stats();
    let observed = obs.lock().unwrap().clone();
    let target_ok = matches!(&observed, Some((true, a, p)) if a == &dst_s && *p == echo_port);
    let ok = synack_ok
        && echo_ok
        && !rst_seen
        && target_ok
        && stats.ipv6.proxy_dropped == 0
        && stats.proxy_tcp_streams_ok == 1;
    Ok(json!({
        "synack_ok": synack_ok,
        "echo_ok": echo_ok,
        "rst_seen": rst_seen,
        "target_ok": target_ok,
        "observed": observed.map(|(v6, a, p)| json!({"v6": v6, "addr": a, "port": p})),
        "ipv6_tcp": stats.ipv6.tcp,
        "classified_proxy": stats.ipv6.classified_proxy,
        "ipv6_proxy_dropped": stats.ipv6.proxy_dropped,
        "proxy_tcp_streams": stats.proxy_tcp_streams,
        "proxy_tcp_streams_ok": stats.proxy_tcp_streams_ok,
        "proxy_tcp_bytes_down": stats.proxy_tcp_bytes_down,
        "ok": ok,
    }))
}

/// CAC-1 拒例腿：终结成立（SYN-ACK）但出站方言拒 v6 目标 → RST、零回显、
/// streams_ok == 0（与 AC9 的 SS 断言同向；本腿覆盖 Trojan，SS 腿复用 AC9 形态）。
fn cac1_reject_leg(tag: &str, yaml: String) -> Result<Value, String> {
    let mut env = assemble_yaml(tag, &["fd00:144::/64"], Some(yaml))?;
    env.inject(v6_tcp(CLIENT6, PROXY_DST, 41000, 80, 5000, 0, 0x02, &[]))?;
    let first = env.written();
    let (src, _, sp, dp, srv_seq, flags, _) = first
        .first()
        .and_then(|p| tcp_fields(p))
        .ok_or_else(|| "cac1-reject: no SYN-ACK".to_string())?;
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
    env.inject(v6_tcp(
        CLIENT6,
        PROXY_DST,
        41000,
        80,
        5001,
        srv_seq.wrapping_add(1),
        0x18,
        CAC1_PAYLOAD,
    ))?;
    let mut rst_seen = false;
    let mut echo_seen = false;
    for tick in 0..1500u64 {
        let _ = env.dp.tick(tick);
        for p in env.written() {
            if has_flag(&p, 0x04) {
                rst_seen = true;
            }
            if payload_of(&p) == CAC1_PAYLOAD {
                echo_seen = true;
            }
        }
        if rst_seen {
            break;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    let stats = env.dp.stats();
    let ok = synack_ok
        && rst_seen
        && !echo_seen
        && stats.proxy_tcp_streams_ok == 0
        && stats.ipv6.proxy_dropped == 0;
    Ok(json!({
        "synack_ok": synack_ok,
        "rst_seen": rst_seen,
        "echo_seen": echo_seen,
        "ipv6_tcp": stats.ipv6.tcp,
        "classified_proxy": stats.ipv6.classified_proxy,
        "ipv6_proxy_dropped": stats.ipv6.proxy_dropped,
        "proxy_tcp_streams": stats.proxy_tcp_streams,
        "proxy_tcp_streams_ok": stats.proxy_tcp_streams_ok,
        "proxy_dropped_no_proxy": stats.proxy_dropped_no_proxy,
        "ok": ok,
    }))
}

fn cac1_leg(_tag: &str, r: Result<Value, String>) -> Value {
    match r {
        Ok(mut v) => {
            if v.get("ok").is_none() {
                v["ok"] = json!(false);
            }
            v
        }
        Err(e) => json!({"ok": false, "error": e}),
    }
}

/// CAC-1 全腿（`--cac1` 模式）：socks5 / VLESS / AnyTLS 正例 + Trojan / SS 拒例。
fn run_cac1() -> Value {
    let Some(echo_addr) = discover_global_v6() else {
        return json!({"verdict": "FAIL", "cac1": {"error": "no stable global v6 address on this host", "ok": false}});
    };
    let echo_port = match start_echo_rt(echo_addr) {
        Ok(p) => p,
        Err(e) => return json!({"verdict": "FAIL", "cac1": {"error": e, "ok": false}}),
    };
    let echo_dst = IpAddr::V6(echo_addr);
    let obs5 = cac1_obs();
    let socks5 = cac1_leg(
        "socks5",
        spawn_socks5(Arc::clone(&obs5)).and_then(|port| {
            cac1_positive_leg(
                "cac1-socks5",
                cac1_yaml("socks5", &format!("    locator: 127.0.0.1:{port}\n")),
                &obs5,
                echo_dst,
                echo_port,
            )
        }),
    );
    let obsv = cac1_obs();
    let vless = cac1_leg(
        "vless",
        spawn_vless(Arc::clone(&obsv)).and_then(|port| {
            cac1_positive_leg(
                "cac1-vless",
                cac1_yaml(
                    "vless",
                    &format!(
                        "    locator: 127.0.0.1:{port}\n    uuid: 11111111-1111-4111-8111-111111111111\n"
                    ),
                ),
                &obsv,
                echo_dst,
                echo_port,
            )
        }),
    );
    let obsa = cac1_obs();
    let anytls = cac1_leg(
        "anytls",
        spawn_anytls(Arc::clone(&obsa)).and_then(|port| {
            cac1_positive_leg(
                "cac1-anytls",
                cac1_yaml(
                    "anytls",
                    &format!(
                        "    locator: 127.0.0.1:{port}\n    password: {CAC1_PASSWORD}\n    skip_cert_verify: true\n"
                    ),
                ),
                &obsa,
                echo_dst,
                echo_port,
            )
        }),
    );
    let trojan = cac1_leg(
        "trojan",
        spawn_accept_close().and_then(|port| {
            cac1_reject_leg(
                "cac1-trojan",
                cac1_yaml(
                    "trojan",
                    &format!(
                        "    locator: 127.0.0.1:{port}\n    password: {CAC1_PASSWORD}\n    skip_cert_verify: true\n"
                    ),
                ),
            )
        }),
    );
    let ss = cac1_leg("ss", cac1_reject_leg("cac1-ss", proxy_yaml()));
    let ok = [&socks5, &vless, &anytls, &trojan, &ss]
        .iter()
        .all(|v| v["ok"] == Value::Bool(true));
    json!({
        "verdict": if ok { "PASS" } else { "FAIL" },
        "cac1": {
            "socks5": socks5,
            "vless": vless,
            "anytls": anytls,
            "trojan": trojan,
            "ss": ss,
            "ok": ok,
        },
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
    let out = if args.iter().any(|a| a == "--cac1") {
        run_cac1()
    } else {
        run()
    };
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
