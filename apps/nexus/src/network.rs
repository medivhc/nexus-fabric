//! `nexus network` 命令族（M6）：N1 Universal Connectivity 的前台装配。
//!
//! Composition Root：把 `nexus-network` 的 portable n1 core 与
//! fabric / path / discovery / platform-linux 的具体实现装配到一起。
//!
//! - `network up --config <toml>`：前台运行（建 TUN → dial 静态 peers → 起包泵），
//!   按 Enter 或 Ctrl-C 退出（daemon 化后置，见 M6 诚实边界）。
//! - `network status [--config <toml>]`：报告将装配的内容；无 daemon 时诚实标注
//!   `daemon: false`，不虚构运行时状态。
//!
//! 首期 Linux only（E4 在 xc-pc-linux netns；其他平台诚实报错）。

use nexus_control_api::ControlCommand;
use nexus_discovery::{
    AggregateDiscovery, Discovery, PeerId as DiscoveryPeerId, StaticDiscovery, lsa::Lsdb,
    mdns::MdnsDiscovery,
};
use nexus_fabric::{
    ConnConfig, FabricConn, FabricError, PeerId as FabricPeerId, RecvStream, SendStream,
    StdUdpTransport, UdpTransport,
};
use nexus_network::n1::{
    N1Connection, N1Dialer, N1Discovery, N1Error, N1Event, N1EventSink, N1KeepaliveIo,
    N1KeepaliveStream, N1PeerId,
    config::N1Config,
    session::N1SessionManager,
};
// 包泵与路由类型只被 `network_up_linux`（#[cfg(target_os = "linux")]）消费；
// 不加 cfg 的话，非 Linux 构建会因 workspace 的 deny(warnings) 直接编译失败。
#[cfg(target_os = "linux")]
use nexus_network::n1::pump::{Ipv4Route, PeerConnLookup, VpiPump};
use nexus_path::{CandidatePath, FallbackChain, FallbackConfig, PathKind};
#[cfg(target_os = "linux")]
use nexus_platform::VirtualPacketInterface;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::sync::Mutex;
use std::time::Duration;

// ---------- 注入 trait 适配器 ----------

fn map_fabric_err(e: FabricError) -> N1Error {
    match e {
        // B2 根因修复（2026-10-03 W1）：保留关闭码，让 watcher 能区分
        // 对端优雅关闭（application close, code 0）与传输层故障。
        // 注意 `LocallyClosed` 也映射到 `Closed(0)`；watcher 侧本地关闭
        // 恒有 stop 标志位保护，把它当优雅关闭静默退出同样正确（不误报）。
        FabricError::Closed(code) => N1Error::PeerClosed(code),
        FabricError::Timeout => N1Error::Timeout,
        FabricError::PathUnreachable => N1Error::PeerUnknown,
        FabricError::HandshakeFailed(s) => N1Error::Transport(format!("handshake: {s}")),
        FabricError::Transport(s) => N1Error::Transport(s),
    }
}

struct FabricConnAdapter {
    inner: FabricConn,
}

impl N1Connection for FabricConnAdapter {
    fn send_datagram(&self, data: &[u8]) -> Result<(), N1Error> {
        if data.len() > 1200 {
            return Err(N1Error::OversizeDatagram(data.len()));
        }
        self.inner.send_datagram(data).map_err(map_fabric_err)
    }
    fn recv_datagram(&self) -> Result<Vec<u8>, N1Error> {
        self.inner.recv_datagram().map_err(map_fabric_err)
    }
    fn open_keepalive(&self) -> Result<N1KeepaliveStream, N1Error> {
        let (send, recv) = self.inner.open_bi().map_err(map_fabric_err)?;
        Ok(N1KeepaliveStream::new(Box::new(FabricKaStream {
            send,
            recv,
        })))
    }
    fn accept_keepalive(&self) -> Result<N1KeepaliveStream, N1Error> {
        let (send, recv) = self.inner.accept_bi().map_err(map_fabric_err)?;
        Ok(N1KeepaliveStream::new(Box::new(FabricKaStream {
            send,
            recv,
        })))
    }
    fn rebind(&self) -> Result<(), N1Error> {
        self.inner.rebind().map_err(map_fabric_err)
    }
    fn connection_id(&self) -> u64 {
        self.inner.id().0
    }
    fn peer(&self) -> N1PeerId {
        N1PeerId(self.inner.peer().0)
    }
    fn close(&self) {
        self.inner.close(0, b"n1 shutdown");
    }
}

struct FabricKaStream {
    send: SendStream,
    recv: RecvStream,
}

impl N1KeepaliveIo for FabricKaStream {
    fn write_all(&mut self, mut buf: &[u8]) -> Result<(), N1Error> {
        while !buf.is_empty() {
            let n = self.send.write(buf).map_err(map_fabric_err)?;
            if n == 0 {
                return Err(N1Error::Transport("keepalive write returned 0".into()));
            }
            buf = &buf[n..];
        }
        Ok(())
    }
    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), N1Error> {
        let mut off = 0;
        while off < buf.len() {
            match self.recv.read(&mut buf[off..]).map_err(map_fabric_err)? {
                0 => return Err(N1Error::Closed),
                n => off += n,
            }
        }
        Ok(())
    }
    fn finish(&mut self) -> Result<(), N1Error> {
        self.send.finish().map_err(map_fabric_err)
    }
}

struct FabricDialer {
    local_bind: SocketAddr,
    handshake_timeout: Duration,
}

impl FabricDialer {
    fn dial_direct(
        &self,
        peer: FabricPeerId,
        cand: &CandidatePath,
    ) -> Result<Box<dyn N1Connection>, N1Error> {
        let transport: Box<dyn UdpTransport> = Box::new(
            StdUdpTransport::bind(cand.local_addr)
                .map_err(|e| N1Error::Transport(format!("bind {}: {e}", cand.local_addr)))?,
        );
        let cfg = ConnConfig {
            addrs: vec![cand.remote_addr],
            handshake_timeout: self.handshake_timeout,
        };
        let conn =
            FabricConn::connect_with_transport(peer, &cfg, transport).map_err(map_fabric_err)?;
        Ok(Box::new(FabricConnAdapter { inner: conn }))
    }
}

impl N1Dialer for FabricDialer {
    fn dial(
        &self,
        peer: &N1PeerId,
        addrs: &[SocketAddr],
    ) -> Result<Box<dyn N1Connection>, N1Error> {
        let fabric_peer = FabricPeerId(peer.0);
        let config = FallbackConfig {
            proxy: None,
            turn: None,
        };
        let mut last_err = N1Error::PeerUnknown;
        for addr in addrs {
            let chain = FallbackChain::expand(&config, self.local_bind, *addr);
            for cand in chain.candidates() {
                match cand.kind {
                    PathKind::Direct => match self.dial_direct(fabric_peer, cand) {
                        Ok(c) => return Ok(c),
                        Err(e) => last_err = e,
                    },
                    _ => continue,
                }
            }
        }
        Err(last_err)
    }
}

struct DiscoveryAdapter {
    agg: AggregateDiscovery<'static>,
}

impl DiscoveryAdapter {
    fn new(self_id: N1PeerId, static_peers: Vec<(N1PeerId, SocketAddr)>) -> Self {
        let static_src = StaticDiscovery::new(
            static_peers
                .into_iter()
                .map(|(id, addr)| (DiscoveryPeerId(id.to_hex()), addr)),
        );
        let lsdb: &'static Lsdb = Box::leak(Box::new(Lsdb::new(DiscoveryPeerId(self_id.to_hex()))));
        let mdns_src = MdnsDiscovery::new(
            DiscoveryPeerId(self_id.to_hex()),
            9000,
            IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        )
        .expect("mdns discovery construct");
        Self {
            agg: AggregateDiscovery::new(static_src, lsdb, mdns_src),
        }
    }
}

impl N1Discovery for DiscoveryAdapter {
    fn resolve(&self, peer: &N1PeerId) -> Result<Vec<SocketAddr>, N1Error> {
        Ok(Discovery::resolve(
            &self.agg,
            &DiscoveryPeerId(peer.to_hex()),
        ))
    }
}

/// 事件：打日志（本期 Composition Root 落盘/日志，D2）。
struct LogSink;

impl N1EventSink for LogSink {
    fn emit(&self, event: N1Event) {
        eprintln!(
            "[n1-event] peer={} cid={} kind={:?} disposition={:?}",
            &event.peer.to_hex()[..8],
            event.connection_id,
            event.kind,
            event.disposition
        );
    }
}

#[cfg(target_os = "linux")]
struct ManagerLookup(Arc<N1SessionManager>);

#[cfg(target_os = "linux")]
impl PeerConnLookup for ManagerLookup {
    fn connection_for(&self, peer: &N1PeerId) -> Option<Arc<dyn N1Connection>> {
        self.0.connection_for(peer)
    }
    fn all_peers(&self) -> Vec<N1PeerId> {
        self.0.peers()
    }
    fn close_all(&self) {
        self.0.shutdown();
    }
}

// ---------- 命令分发 ----------

/// Composition Root 装配器：从 `network.toml` 文本构造 N1 会话管理器。
///
/// 供 `nexusd`（统一 Composition Root）复用，不复制装配逻辑。
/// 只做构造 + 返回解析后的 `N1Config`；不建 TUN、不 dial（调用方按需 dial）。
///
/// # Errors
/// - `network.toml` 解析失败 → `Err(String)`。
pub fn build_session_manager(
    config_text: &str,
) -> Result<(N1Config, Arc<N1SessionManager>), String> {
    let config =
        N1Config::parse_toml(config_text).map_err(|e| format!("parse network.toml: {e:?}"))?;
    let sink = Arc::new(LogSink);
    let discovery = Arc::new(DiscoveryAdapter::new(
        config.peer_id,
        config
            .peers
            .iter()
            .map(|p| {
                (
                    p.id,
                    p.addrs
                        .first()
                        .copied()
                        .unwrap_or_else(|| "0.0.0.0:0".parse().expect("0.0.0.0:0 parses")),
                )
            })
            .collect(),
    ));
    let dialer = Arc::new(FabricDialer {
        local_bind: "0.0.0.0:0".parse().expect("0.0.0.0:0 parses"),
        handshake_timeout: Duration::from_secs(10),
    });
    let mgr = Arc::new(N1SessionManager::new(
        dialer,
        discovery,
        sink,
        config.link.clone(),
    ));
    Ok((config, mgr))
}

/// `network` 命令族分发（经 Application API 的 ControlCommand）。
pub fn dispatch(command: &ControlCommand, raw_args: &[String], json_mode: bool) -> i32 {
    match command {
        ControlCommand::NetworkUp { config } => network_up(config, json_mode),
        ControlCommand::NetworkStatus => {
            let cfg = raw_args
                .windows(2)
                .find(|w| w[0] == "--config")
                .map(|w| w[1].clone());
            network_status(cfg.as_deref(), json_mode)
        }
        _ => {
            eprintln!("error: not a network command");
            2
        }
    }
}

/// `network up`：前台装配。仅 Linux（TunVpi + `ip` 配置）。
pub fn network_up(config_text: &str, _json_mode: bool) -> i32 {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = config_text;
        eprintln!(
            "error: `nexus network up` is Linux-only in this build (N1 诚实边界：首期 Linux only)"
        );
        return 2;
    }
    #[cfg(target_os = "linux")]
    {
        network_up_linux(config_text)
    }
}

#[cfg(target_os = "linux")]
fn network_up_linux(config_text: &str) -> i32 {
    use nexus_platform_linux::TunVpi;

    let config = match N1Config::parse_toml(config_text) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: bad N1 config: {e}");
            return 2;
        }
    };

    // 1. 建 TUN。
    let tun = match TunVpi::create(&config.vpi.interface) {
        Ok(t) => t,
        Err(e) => {
            eprintln!(
                "error: cannot create TUN {}: {e}\n  hint: need CAP_NET_ADMIN (run as root or setcap cap_net_admin+ep)",
                config.vpi.interface
            );
            return 1;
        }
    };
    // 2. 配地址/MTU/up（经 `ip`；失败则打印手工命令并退出，不留半配置）。
    if let Err(e) = configure_tun(&config) {
        eprintln!("error: {e}");
        return 1;
    }

    // 3. 装配 N1 协议栈。
    let sink = Arc::new(LogSink);
    let discovery = Arc::new(DiscoveryAdapter::new(
        config.peer_id,
        config
            .peers
            .iter()
            .map(|p| {
                (
                    p.id,
                    p.addrs
                        .first()
                        .copied()
                        .unwrap_or("0.0.0.0:0".parse().unwrap()),
                )
            })
            .collect(),
    ));
    let dialer = Arc::new(FabricDialer {
        local_bind: "0.0.0.0:0".parse().unwrap(),
        handshake_timeout: Duration::from_secs(10),
    });
    let mgr = Arc::new(N1SessionManager::new(
        dialer,
        discovery,
        sink,
        config.link.clone(),
    ));
    let mut dialed = 0;
    for peer in &config.peers {
        match mgr.dial(&peer.id) {
            Ok(()) => {
                println!("dialed peer {}", &peer.id.to_hex()[..8]);
                dialed += 1;
            }
            Err(e) => eprintln!("warn: dial peer {} failed: {e}", &peer.id.to_hex()[..8]),
        }
    }
    if dialed == 0 {
        eprintln!("error: no peers connected; N1 not assembled");
        return 1;
    }

    // 4. 起包泵。
    let routes: Vec<Ipv4Route> = config.vpi.routes.clone();
    let vpi: Arc<Mutex<Box<dyn VirtualPacketInterface>>> = Arc::new(Mutex::new(Box::new(tun)));
    let lookup = Arc::new(ManagerLookup(Arc::clone(&mgr)));
    let pump = VpiPump::new(vpi, routes, lookup).start();
    println!(
        "N1 assembled: {} peer(s), {} route(s); press Enter or Ctrl-C to stop",
        dialed,
        config.vpi.routes.len()
    );

    // 前台运行：Enter 优雅退出；Ctrl-C 走默认进程终止（TUN fd 关闭即设备移除）。
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
    println!("shutting down N1...");
    pump.shutdown();
    mgr.shutdown();
    0
}

/// 经 `ip` 配置 TUN（addr/mtu/up + VPI 子网路由）。
#[cfg(target_os = "linux")]
fn configure_tun(config: &N1Config) -> Result<(), String> {
    let ifname = &config.vpi.interface;
    let run = |args: &[&str]| -> Result<(), String> {
        let out = std::process::Command::new("ip")
            .args(args)
            .output()
            .map_err(|e| format!("spawn `ip`: {e} (is iproute2 installed?)"))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(format!(
                "`ip {}` failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            ))
        }
    };
    // 24 位掩码：VPI 地址所在子网（与路由条目一致，首期 /24）。
    let prefix = config
        .vpi
        .routes
        .first()
        .map(|r| r.subnet.prefix_len())
        .unwrap_or(24);
    run(&[
        "addr",
        "add",
        &format!("{}/{}", config.vpi.address, prefix),
        "dev",
        ifname,
    ])?;
    run(&["link", "set", ifname, "mtu", &config.vpi.mtu.to_string()])?;
    run(&["link", "set", ifname, "up"])?;
    for route in &config.vpi.routes {
        let _ = run(&["route", "replace", &route.subnet.to_string(), "dev", ifname]);
    }
    Ok(())
}

/// `network status`：诚实的状态报告（无 daemon → `daemon: false`，不虚构）。
pub fn network_status(config_path: Option<&str>, json_mode: bool) -> i32 {
    let obj = status_json(config_path);
    if json_mode {
        println!("{obj}");
    } else if let Some(cfg) = obj.get("config") {
        println!("daemon: false");
        println!("config: {}", cfg.get("path").unwrap());
        println!("peer_id: {}", cfg.get("peer_id").unwrap());
        println!("interface: {}", cfg.get("interface").unwrap());
    } else {
        println!("daemon: false");
        println!("note: no N1 daemon in this build; run `nexus network up --config <toml>`");
    }
    0
}

/// `network status` 的纯 JSON 构造（ControlService 快照与 CLI 共用）。
pub fn status_json(config_path: Option<&str>) -> serde_json::Value {
    let mut obj = serde_json::json!({
        "command": "network status",
        "daemon": false,
        "assembled_by_this_process": false,
        "note": "no N1 daemon in this build; run `nexus network up --config <toml>` in the foreground",
    });
    if let Some(path) = config_path {
        match std::fs::read_to_string(path) {
            Ok(text) => match N1Config::parse_toml(&text) {
                Ok(c) => {
                    obj["config"] = serde_json::json!({
                        "path": path,
                        "peer_id": c.peer_id.to_hex(),
                        "interface": c.vpi.interface,
                        "vpi_address": c.vpi.address.to_string(),
                        "mtu": c.vpi.mtu,
                        "peers": c.peers.iter().map(|p| serde_json::json!({
                            "id": p.id.to_hex(),
                            "addrs": p.addrs.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
                        })).collect::<Vec<_>>(),
                        "routes": c.vpi.routes.iter().map(|r| serde_json::json!({
                            "subnet": r.subnet.to_string(),
                            "peer": r.peer.to_hex(),
                        })).collect::<Vec<_>>(),
                        "probe_interval_ms": c.link.probe_interval.as_millis(),
                        "heartbeat_timeout_ms": c.link.heartbeat_timeout.as_millis(),
                    });
                    obj["would_assemble"] = serde_json::json!(true);
                }
                Err(e) => {
                    obj["config_error"] = serde_json::json!(e.to_string());
                }
            },
            Err(e) => {
                obj["config_error"] = serde_json::json!(format!("cannot read {path}: {e}"));
            }
        }
    }
    obj
}
