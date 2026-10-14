//! E4: product.fabric-over-proxy
//!
//! netns 隔离 + iptables DROP 直连 UDP + 父进程本地 SOCKS5：
//! A 的直连 QUIC 到 B（10.200.0.1:9000 UDP）被 `iptables -A OUTPUT
//! -p udp --dport 9000 -j DROP` 黑洞（包有去无回，无 ICMP），5s 直连预算内
//! 无法握手 → 自动回退到经父进程 SOCKS5（10.200.0.254:1080，TCP 可达）的
//! QUIC，端到端 keepalive echo 打通，父进程 SOCKS5 中继字节 > 0。
//!
//! 拓扑（单子进程 netns；父进程持 veth 另一端跑 SOCKS5）：
//! - 父进程：建 veth 对，保留一端 10.200.0.254/24，起 SOCKS5 代理线程；
//! - 子进程（unshare(CLONE_NEWNET)）：获 veth 另一端 10.200.0.1/24，
//!   同一 netns 内跑 A 与 B 两个逻辑节点：
//!   - B：`FabricListener` UDP 9000（直连监听，仅保证端口开放）+ `TcpListener`
//!     TCP 9000（代理入向），用显式身份 `bind_with_transport_identity` 建
//!     proxied QUIC listener（#3 新增 API：服务端身份必须可预测，否则
//!     `FabricConn::connect_with_transport` 的 PeerPin 校验失败）；
//!   - A：iptables DROP UDP 9000 → `nexus::network::build_session_manager`
//!     （`ProxyConfig::Socks5` 指向父进程）→ `mgr.dial(B)`。
//!
//! 需要 root 能力（sudo -n ip / sudo -n iptables / CAP_SYS_ADMIN unshare）。
//! 无特权环境直接 FAIL（计划 A10：在 xc-pc-linux 特权环境运行）。

use nexus::network::ProxyConfig;
use nexus_fabric::{FabricIdentity, FabricListener};
use nexus_network::n1::N1PeerId;
use nexus_proxy_transport::{ProxyTransport, Socks5ProxyConfig};

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

// ---------- 常量 ----------

/// 父进程 veth 端地址（SOCKS5 监听地址）。
const PARENT_IP: &str = "10.200.0.254";
/// 子进程 veth 端地址（A/B 所在 netns）。
const CHILD_IP: &str = "10.200.0.1";
/// B 的直连 QUIC 与代理 TCP 入向端口。
const PORT: u16 = 9000;
/// 父进程 SOCKS5 端口。
const SOCKS5_PORT: u16 = 1080;
/// 子网前缀。
const CIDR: u8 = 24;
/// 全局看门狗。
const GLOBAL_TIMEOUT: Duration = Duration::from_secs(90);
/// B 的身份种子（确定性：proxied listener 的 PeerId 必须等于 A 配置里的对端）。
const B_IDENTITY_SEED: [u8; 32] = [42; 32];
/// A 的占位身份（64 hex）。
const A_ID_HEX: &str = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
/// keepalive echo 载荷长度。
const ECHO_LEN: usize = 64;
/// DONE 信号文件（父进程轮询）。
const DONE_FILE: &str = "/tmp/n1_proxy_fallback_done";

// ---------- 工具 ----------

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn sudo_ip(args: &[&str]) -> Result<(), String> {
    let out = Command::new("/usr/bin/sudo")
        .arg("-n")
        .arg("/usr/bin/ip")
        .args(args)
        .output()
        .map_err(|e| format!("spawn sudo ip: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "sudo ip {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr)
        ))
    }
}

fn sudo_iptables(args: &[&str]) -> Result<(), String> {
    let out = Command::new("/usr/bin/sudo")
        .arg("-n")
        .arg("/usr/sbin/iptables")
        .args(args)
        .output()
        .map_err(|e| format!("spawn sudo iptables: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "sudo iptables {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr)
        ))
    }
}

fn peer_b() -> Result<(FabricIdentity, N1PeerId), String> {
    let id = FabricIdentity::from_ed25519_seed(B_IDENTITY_SEED)
        .map_err(|e| format!("identity from seed: {e}"))?;
    let n1 = N1PeerId(id.peer_id().0);
    Ok((id, n1))
}

// ---------- SOCKS5 服务器（父进程） ----------

/// 最小 SOCKS5 服务器：greeting → CONNECT → 双向 TCP relay，计数中继字节。
struct Socks5Server {
    listener: TcpListener,
    relayed_bytes: Arc<AtomicU64>,
}

impl Socks5Server {
    fn bind(addr: SocketAddr) -> Result<Self, String> {
        let listener = TcpListener::bind(addr).map_err(|e| format!("socks5 bind {addr}: {e}"))?;
        Ok(Self {
            listener,
            relayed_bytes: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Serve exactly one CONNECT session，然后双向 relay 直到连接关闭。
    fn serve_once(&self) -> Result<(), String> {
        let (mut client, _) = self
            .listener
            .accept()
            .map_err(|e| format!("socks5 accept: {e}"))?;
        client
            .set_read_timeout(Some(Duration::from_secs(30)))
            .map_err(|e| format!("set timeout: {e}"))?;

        // Greeting: VER=5, NMETHODS=1, METHOD=0 (no auth)。
        let mut greet = [0u8; 3];
        client
            .read_exact(&mut greet)
            .map_err(|e| format!("greeting read: {e}"))?;
        if greet[0] != 5 || greet[1] != 1 || greet[2] != 0 {
            return Err(format!(
                "bad socks5 greeting: {greet:?} (expected no-auth)"
            ));
        }
        client
            .write_all(&[5, 0])
            .map_err(|e| format!("greeting reply: {e}"))?;

        // CONNECT 请求：VER=5, CMD=1, RSV=0, ATYP=1 (IPv4), addr(4), port(2)。
        let mut req = [0u8; 10];
        client
            .read_exact(&mut req)
            .map_err(|e| format!("connect req read: {e}"))?;
        if req[0] != 5 || req[1] != 1 || req[3] != 1 {
            return Err(format!("bad socks5 connect req: {req:?}"));
        }
        let target: SocketAddr = (
            std::net::Ipv4Addr::new(req[4], req[5], req[6], req[7]),
            u16::from_be_bytes([req[8], req[9]]),
        )
            .into();
        let mut upstream = TcpStream::connect(target)
            .map_err(|e| format!("socks5 upstream connect {target}: {e}"))?;
        upstream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .ok();
        client
            .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
            .map_err(|e| format!("connect reply: {e}"))?;

        // 双向 relay，计数中继字节。
        let relayed = self.relayed_bytes.clone();
        let mut up_clone = upstream.try_clone().map_err(|e| format!("clone: {e}"))?;
        let mut cl_clone = client.try_clone().map_err(|e| format!("clone: {e}"))?;
        let t1 = std::thread::spawn(move || relay_one(&mut cl_clone, &mut up_clone, &relayed));
        let relayed2 = self.relayed_bytes.clone();
        let t2 = std::thread::spawn(move || {
            relay_one(&mut upstream, &mut client, &relayed2);
        });
        let _ = t1.join();
        let _ = t2.join();
        Ok(())
    }
}

fn relay_one(reader: &mut TcpStream, writer: &mut TcpStream, relayed: &AtomicU64) {
    let mut buf = [0u8; 8192];
    loop {
        let n = match reader.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        relayed.fetch_add(n as u64, Ordering::SeqCst);
        if writer.write_all(&buf[..n]).is_err() {
            break;
        }
    }
}

// ---------- 子进程 ----------

struct ChildCfg {
    veth: String,
}

fn child_main(cfg: ChildCfg) -> Result<(), String> {
    let ret = unsafe { libc::unshare(libc::CLONE_NEWNET) };
    if ret != 0 {
        return Err(format!(
            "unshare(CLONE_NEWNET) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    println!("READY");
    std::io::stdout().flush().map_err(|e| e.to_string())?;

    let mut go = String::new();
    std::io::stdin()
        .read_line(&mut go)
        .map_err(|e| format!("read GO: {e}"))?;
    if go.trim() != "GO" {
        return Err(format!("expected GO, got {go:?}"));
    }

    // 配网：lo → veth underlay。
    sudo_ip(&["link", "set", "lo", "up"])?;
    sudo_ip(&[
        "addr",
        "add",
        &format!("{CHILD_IP}/{CIDR}"),
        "dev",
        &cfg.veth,
    ])?;
    sudo_ip(&["link", "set", &cfg.veth, "up"])?;
    eprintln!("[child] net ready on {CHILD_IP}");

    // B 身份（确定性）。
    let (b_identity, peer_b_n1) = peer_b()?;
    let peer_b_hex = peer_b_n1.to_hex();

    // B 的本地地址（veth underlay）。
    let b_addr: SocketAddr = format!("{CHILD_IP}:{PORT}").parse().unwrap();

    // B：直连 UDP 监听（端口开放；iptables DROP 使 A 永远连不上）。
    let direct_listener = FabricListener::bind(b_addr)
        .map_err(|e| format!("direct listen: {e}"))?;
    let direct_accepted = Arc::new(AtomicBool::new(false));
    let da = Arc::clone(&direct_accepted);
    std::thread::spawn(move || {
        // 阻塞；UDP 被 DROP，正常不会返回。若返回说明 iptables 未生效。
        if direct_listener.accept().is_ok() {
            da.store(true, Ordering::SeqCst);
        }
    });

    // B：TCP 代理入向监听。
    let tcp_listener = TcpListener::bind(b_addr)
        .map_err(|e| format!("tcp bind: {e}"))?;
    let proxy_accepted = Arc::new(AtomicBool::new(false));
    let pa = Arc::clone(&proxy_accepted);
    let (done_tx, done_rx) = mpsc::channel::<()>();
    let b_thread = std::thread::spawn(move || -> Result<(), String> {
        let (stream, _) = tcp_listener
            .accept()
            .map_err(|e| format!("tcp accept: {e}"))?;
        let transport = ProxyTransport::new(stream, b_addr);
        let listener = FabricListener::bind_with_transport_identity(Box::new(transport), &b_identity)
            .map_err(|e| format!("bind_with_transport_identity: {e}"))?;
        pa.store(true, Ordering::SeqCst);
        let conn = listener
            .accept()
            .map_err(|e| format!("quic accept: {e}"))?;
        let (mut send, mut recv) = conn
            .accept_bi()
            .map_err(|e| format!("accept_bi: {e}"))?;
        let mut buf = [0u8; ECHO_LEN];
        let mut off = 0;
        while off < ECHO_LEN {
            let n = recv
                .read(&mut buf[off..])
                .map_err(|e| format!("echo read: {e}"))?;
            if n == 0 {
                return Err("echo: unexpected EOF".into());
            }
            off += n;
        }
        let mut woff = 0;
        while woff < ECHO_LEN {
            let n = send
                .write(&buf[woff..])
                .map_err(|e| format!("echo write: {e}"))?;
            if n == 0 {
                return Err("echo: write returned 0".into());
            }
            woff += n;
        }
        send.finish().map_err(|e| format!("echo finish: {e}"))?;
        // 等 A 确认后再退出，防止连接提前关闭丢数据（proxy_quic 4b 教训）。
        done_rx
            .recv_timeout(Duration::from_secs(30))
            .map_err(|_| "timeout waiting for A done".to_string())?;
        Ok(())
    });

    // A：iptables DROP 直连 UDP。
    sudo_iptables(&["-A", "OUTPUT", "-p", "udp", "--dport", &PORT.to_string(), "-j", "DROP"])?;
    eprintln!("[child] iptables DROP udp dport {PORT} installed");

    // A：network.toml + proxy 配置 → build_session_manager → dial(B)。
    let network_toml = format!(
        "peer_id = \"{A_ID_HEX}\"\n\
         [[peers]]\n\
         id = \"{peer_b_hex}\"\n\
         addrs = [\"{CHILD_IP}:{PORT}\"]\n\
         [vpi]\n\
         interface = \"nexus0\"\n\
         address = \"{CHILD_IP}\"\n\
         mtu = 1200\n\
         [[vpi.routes]]\n\
         subnet = \"10.200.0.0/24\"\n\
         peer = \"{peer_b_hex}\"\n"
    );
    let proxy_cfg = Socks5ProxyConfig {
        server: format!("{PARENT_IP}:{SOCKS5_PORT}").parse().unwrap(),
        auth: None,
        connect_timeout: Duration::from_secs(10),
        handshake_timeout: Duration::from_secs(10),
    };
    let (config, mgr) = nexus::network::build_session_manager(
        &network_toml,
        Some(ProxyConfig::Socks5(proxy_cfg)),
        Arc::new(AtomicBool::new(false)),
    )
    .map_err(|e| format!("build_session_manager: {e}"))?;
    let _ = config;
    let peer_b = N1PeerId::from_hex(&peer_b_hex).map_err(|e| format!("bad peer hex: {e}"))?;

    let dial_start = Instant::now();
    mgr.dial(&peer_b).map_err(|e| format!("dial: {e}"))?;
    let dial_elapsed_ms = dial_start.elapsed().as_millis();

    let conn = mgr
        .connection_for(&peer_b)
        .ok_or_else(|| "no connection for B after dial".to_string())?;
    let payload = [0x5Au8; ECHO_LEN];
    let mut s = conn
        .open_keepalive()
        .map_err(|e| format!("open_keepalive: {e}"))?;
    s.write_all(&payload)
        .map_err(|e| format!("ka write: {e}"))?;
    s.finish().map_err(|e| format!("ka finish: {e}"))?;
    let mut echo = [0u8; ECHO_LEN];
    s.read_exact(&mut echo)
        .map_err(|e| format!("ka read: {e}"))?;
    let echo_ok = echo == payload;

    let _ = done_tx.send(());

    let b_res = b_thread
        .join()
        .map_err(|_| "B thread panicked".to_string())?;
    b_res?;

    // 诚实判定 winner：只有代理路径被接受且直连未被接受 → winner=proxy。
    let winner_kind = if proxy_accepted.load(Ordering::SeqCst)
        && !direct_accepted.load(Ordering::SeqCst)
    {
        "proxy"
    } else {
        "direct"
    };
    let pass = winner_kind == "proxy" && echo_ok;
    let result = format!(
        "{{\"verdict\":\"{}\",\"winner_kind\":\"{}\",\"echo_ok\":{},\"dial_elapsed_ms\":{},\"direct_elapsed_ms\":5000,\"proxy_elapsed_ms\":{}}}",
        if pass { "PASS" } else { "FAIL" },
        winner_kind,
        echo_ok,
        dial_elapsed_ms,
        dial_elapsed_ms.saturating_sub(5000)
    );
    let _ = std::fs::write(DONE_FILE, &result);
    let _ = writeln!(std::io::stdout(), "DONE {result}");
    let _ = std::io::stdout().flush();
    Ok(())
}

// ---------- 父进程 ----------

struct ChildProc {
    child: Child,
    stdin: ChildStdin,
    lines: mpsc::Receiver<String>,
    pid: u32,
}

impl ChildProc {
    fn spawn(veth: &str) -> Result<Self, String> {
        let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
        let mut child = Command::new(exe)
            .arg("--child=ab")
            .arg(format!("--veth={veth}"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| format!("spawn child: {e}"))?;
        let pid = child.id();
        let stdin = child.stdin.take().ok_or("no stdin")?;
        let stdout = child.stdout.take().ok_or("no stdout")?;
        let (tx, rx) = mpsc::channel::<String>();
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        if tx.send(line.trim().to_string()).is_err() {
                            break;
                        }
                    }
                }
            }
        });
        Ok(Self {
            child,
            stdin,
            lines: rx,
            pid,
        })
    }

    fn read_line(&self, what: &str) -> Result<String, String> {
        match self.lines.recv_timeout(Duration::from_secs(60)) {
            Ok(line) => Ok(line),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                Err(format!("timeout waiting for child line ({what})"))
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                Err(format!("child died while waiting for {what}"))
            }
        }
    }

    fn write_line(&mut self, s: &str) -> Result<(), String> {
        self.stdin
            .write_all(format!("{s}\n").as_bytes())
            .map_err(|e| format!("write child stdin: {e}"))?;
        self.stdin.flush().map_err(|e| format!("flush: {e}"))?;
        Ok(())
    }
}

fn parent_main() -> Result<String, String> {
    // 前置检查：sudo -n 可用于 /usr/bin/ip 与 /usr/sbin/iptables。
    let sudo_ip_ok = Command::new("/usr/bin/sudo")
        .args(["-n", "/usr/bin/ip", "-o", "link", "show"])
        .stdout(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !sudo_ip_ok {
        return Err("sudo -n /usr/bin/ip not available (need NOPASSWD)".into());
    }
    let sudo_ipt_ok = Command::new("/usr/bin/sudo")
        .args(["-n", "/usr/sbin/iptables", "-L"])
        .stdout(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !sudo_ipt_ok {
        return Err("sudo -n /usr/sbin/iptables not available (need NOPASSWD)".into());
    }

    let veth_a = format!("vfopa{}", std::process::id() % 100000);
    let veth_b = format!("vfopb{}", std::process::id() % 100000);
    let _ = std::fs::remove_file(DONE_FILE);
    // 清理上次残留的同名 veth（避免 `File exists`）。
    let _ = sudo_ip(&["link", "del", &veth_a]);

    // 看门狗。
    let watchdog_veth = veth_a.clone();
    std::thread::spawn(move || {
        std::thread::sleep(GLOBAL_TIMEOUT);
        eprintln!("[watchdog] global timeout, cleaning up");
        let _ = sudo_ip(&["link", "del", &watchdog_veth]);
        println!(
            "{{\"verdict\":\"FAIL\",\"detail\":\"global timeout after {}s\"}}",
            GLOBAL_TIMEOUT.as_secs()
        );
        std::process::exit(1);
    });

    sudo_ip(&[
        "link",
        "add",
        &veth_a,
        "type",
        "veth",
        "peer",
        "name",
        &veth_b,
    ])?;
    sudo_ip(&["addr", "add", &format!("{PARENT_IP}/{CIDR}"), "dev", &veth_a])?;
    sudo_ip(&["link", "set", &veth_a, "up"])?;

    let result = parent_run(&veth_b);
    // 无论成败都清理 veth（删除一端即删除整对）。
    let _ = sudo_ip(&["link", "del", &veth_a]);
    result
}

fn parent_run(veth_b: &str) -> Result<String, String> {
    let mut child = ChildProc::spawn(veth_b)?;
    let ready = child.read_line("READY from child")?;
    if ready != "READY" {
        return Err(format!("child did not signal READY, got {ready:?}"));
    }
    sudo_ip(&["link", "set", veth_b, "netns", &child.pid.to_string()])?;

    // 父进程 SOCKS5（TCP 可达；A 的直连 UDP 被 DROP，但 TCP 不受影响）。
    let socks_addr: SocketAddr = format!("{PARENT_IP}:{SOCKS5_PORT}").parse().unwrap();
    let server = Socks5Server::bind(socks_addr)?;
    let relayed = server.relayed_bytes.clone();
    let server_thread = std::thread::spawn(move || {
        if let Err(e) = server.serve_once() {
            eprintln!("[parent] socks5 serve error: {e}");
        }
    });

    child.write_line("GO")?;

    // 轮询 DONE 文件。
    let done_start = Instant::now();
    let done_content = loop {
        if let Ok(content) = std::fs::read_to_string(DONE_FILE) {
            let s = content.trim().to_string();
            if !s.is_empty() {
                break s;
            }
        }
        if done_start.elapsed() > Duration::from_secs(80) {
            return Err("timeout waiting for DONE file from child".into());
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    // 等子进程退出与 SOCKS5 relay 收尾（连接关闭后计数才稳定）。
    let _ = child.child.wait();
    let _ = server_thread.join();

    let relayed_bytes = relayed.load(Ordering::SeqCst);

    // 解析 child JSON（`DONE {...}` 或裸 JSON）。
    let child_json = done_content
        .strip_prefix("DONE ")
        .unwrap_or(&done_content)
        .to_string();
    let v: serde_json::Value = serde_json::from_str(&child_json)
        .map_err(|e| format!("bad child json {child_json:?}: {e}"))?;
    let child_pass = v.get("verdict").and_then(|x| x.as_str()) == Some("PASS");
    let winner_kind = v
        .get("winner_kind")
        .and_then(|x| x.as_str())
        .unwrap_or("?");
    let echo_ok = v.get("echo_ok").and_then(|x| x.as_bool()).unwrap_or(false);
    let dial_elapsed_ms = v
        .get("dial_elapsed_ms")
        .and_then(|x| x.as_u64())
        .unwrap_or(0);

    let pass = child_pass
        && winner_kind == "proxy"
        && echo_ok
        && relayed_bytes > 0
        && dial_elapsed_ms >= 5000;

    Ok(format!(
        "{{\"verdict\":\"{}\",\"winner_kind\":\"{}\",\"proxy_relayed_bytes\":{},\"echo_ok\":{},\"dial_elapsed_ms\":{},\"direct_elapsed_ms\":5000,\"proxy_elapsed_ms\":{},\"detail\":\"child={child_json}\"}}",
        if pass { "PASS" } else { "FAIL" },
        winner_kind,
        relayed_bytes,
        echo_ok,
        dial_elapsed_ms,
        dial_elapsed_ms.saturating_sub(5000)
    ))
}

// ---------- 入口 ----------

fn ensure_file_caps(caps_csv: &str, need_bits: u64) {
    if std::env::var_os("NEXUS_E4_REEXECED").is_some() || has_cap_bits(need_bits) {
        return;
    }
    let exe = std::env::current_exe().expect("current_exe");
    let exe_s = exe.to_string_lossy().to_string();
    let ok = std::process::Command::new("sudo")
        .args(["-n", "setcap", &format!("{caps_csv}+ep"), &exe_s])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        eprintln!("E4 需要 file caps ({caps_csv})，sudo -n setcap 失败，无法继续");
        std::process::exit(1);
    }
    // SAFETY: 单线程启动期，仅标记防重入。
    unsafe { std::env::set_var("NEXUS_E4_REEXECED", "1") };
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = std::process::Command::new(&exe)
        .args(&args)
        .status()
        .map(|s| s.code().unwrap_or(1))
        .unwrap_or(1);
    std::process::exit(code);
}

fn has_cap_bits(need: u64) -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("CapEff:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|h| u64::from_str_radix(h, 16).ok())
        })
        .map(|eff| eff & need == need)
        .unwrap_or(false)
}

fn main() {
    // CAP_SYS_ADMIN=21 (unshare)。iptables/ip 走 sudo -n 提权。
    ensure_file_caps("cap_sys_admin", 1u64 << 21);
    let args: Vec<String> = std::env::args().collect();
    let is_child = args.iter().any(|a| a.starts_with("--child="));
    let want_json = args.iter().any(|a| a == "--json");

    let (json, pass) = if is_child {
        let get = |k: &str| {
            args.iter()
                .find(|a| a.starts_with(&format!("--{k}=")))
                .map(|a| a.trim_start_matches(&format!("--{k}=")).to_string())
                .unwrap_or_default()
        };
        let cfg = ChildCfg {
            veth: get("veth"),
        };
        match child_main(cfg) {
            Ok(()) => (String::new(), true),
            Err(e) => {
                // 父进程轮询 DONE 文件；出错时也写 FAIL，避免父进程等到超时。
                let fail = format!(
                    "{{\"verdict\":\"FAIL\",\"detail\":\"child: {}\"}}",
                    esc(&e)
                );
                let _ = std::fs::write(DONE_FILE, &fail);
                (fail, false)
            }
        }
    } else {
        match parent_main() {
            Ok(json) => {
                let pass = json.contains("\"verdict\":\"PASS\"");
                (json, pass)
            }
            Err(e) => (
                format!(
                    "{{\"verdict\":\"FAIL\",\"detail\":\"parent: {}\"}}",
                    esc(&e)
                ),
                false,
            ),
        }
    };
    if want_json || !is_child {
        if !json.is_empty() {
            println!("{json}");
        }
    } else if !pass {
        eprintln!("{json}");
    }
    if !is_child && !pass {
        std::process::exit(1);
    }
    if is_child && !pass {
        std::process::exit(1);
    }
    // 子进程成功完成后强制退出：后台线程（fabric driver、B 线程）可能未停止。
    if is_child && pass {
        std::process::exit(0);
    }
}