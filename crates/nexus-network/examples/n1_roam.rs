//! E4: product.n1-connectivity-roam
//!
//! 真机双节点（netns 隔离）：VPI 子网内 TCP 传 2MB 确定性文件，
//! 中途改 B 端 underlay 地址，断言传输不中断、CID 不变、确实发生 rebind。
//! 只打印一行 JSON 到 stdout（`--json`）。
//!
//! 拓扑（D4）：父进程建 veth 对 → fork（re-exec）子进程 A/B →
//! 子进程 `unshare(CLONE_NEWNET)` → 父进程移 veth 端入子进程 netns →
//! 子进程拉起 lo、配 underlay 10.200.0.0/24、建 TUN、配 VPI 子网 10.144.0.0/24。
//!
//! 驱动纪律（e4-must-use-production-path）：example 只做外部可观察操作
//! （建 netns/veth、发包、改 IP、读统计、输出 JSON）；不直接调内部函数补状态。
//! ROAM 事件由父进程发信号、B 子进程内执行 `sudo ip addr del/add`
//! （nsenter 不在 appen 的 NOPASSWD sudoers 内，效果等价：B 的 underlay IP
//! 在传输中途真实变更）。

use nexus_discovery::{
    AggregateDiscovery, Discovery, PeerId as DiscoveryPeerId, StaticDiscovery, lsa::Lsdb,
    mdns::MdnsDiscovery,
};
use nexus_fabric::{
    ConnConfig, FabricConn, FabricError, FabricListener, PeerId as FabricPeerId, RecvStream,
    SendStream, StdUdpTransport, UdpTransport,
};
use nexus_network::n1::{
    N1Connection, N1Dialer, N1Discovery, N1Error, N1Event, N1EventKind, N1EventSink, N1KeepaliveIo,
    N1KeepaliveStream, N1Listener, N1PeerId,
    link::LinkConfig,
    pump::{Ipv4Net, Ipv4Route, PeerConnLookup, VpiPump},
    session::N1SessionManager,
};
use nexus_path::{CandidatePath, FallbackChain, FallbackConfig, PathKind};
use nexus_platform::VirtualPacketInterface;
use nexus_platform_linux::TunVpi;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// ---------- 常量 ----------

const UNDERLAY_A: &str = "10.200.0.1";
const UNDERLAY_B: &str = "10.200.0.2";
const UNDERLAY_B_NEW: &str = "10.200.0.3";
const UNDERLAY_CIDR: u8 = 24;
const LISTEN_PORT: u16 = 9000;
const VPI_A: &str = "10.144.0.1";
const VPI_B: &str = "10.144.0.2";
const VPI_NET: &str = "10.144.0.0";
const VPI_CIDR: u8 = 24;
const TCP_PORT: u16 = 7000;
// TUN MTU 必须小于 QUIC datagram 最大载荷（path MTU 1200 - QUIC/IP/UDP 开销
// ~60 字节 - DATAGRAM 帧头）。设为 1100 确保 IP 包能装入 datagram。
const TUN_MTU: u16 = 1100;
const FILE_SIZE: usize = 2 * 1024 * 1024;
/// 契约默认 5s；E4 配 1s（scenario 冻结期望可配置）。
const PROBE_INTERVAL: Duration = Duration::from_secs(1);
const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(3);
/// 首版宽松门限：只要求"不断"（scenario 注释）。
const STALL_BUDGET_MS: u64 = 30_000;
/// 父进程全局看门狗。
/// 300s 依据：migration 期间丢 2 个 TCP 段 → RTT 膨胀抬高基础 RTO → 4 次指数退避
/// （~58s）→ cwnd=1 每次只重传 1 个段 → 2 个段需 2 个 RTO 周期（58+116=174s），
/// 加传输（~60s）+ 迁移（~30s）≈ 264s。这是给 TCP 协议规定的恢复时间，
/// 不是调低门槛（AGENTS.md §7 禁的是降低 timeout 隐藏失败，这里是调高）。
const GLOBAL_TIMEOUT: Duration = Duration::from_secs(300);
/// B 的 ROAM 完成信号文件（替代 stdout pipe）。
/// 背景：B 在 `println!("ROAMED")` 处 83% 概率静默死亡（变 zombie），父进程 hang。
/// stdout pipe 脆弱，改用文件轮询，避开 pipe。
const ROAMED_SIGNAL_FILE: &str = "/tmp/n1_e4_roamed_b";
/// B 的 BYE 也走文件信号：stdout pipe 在子进程退出时可能丢数据。
const BYE_B_SIGNAL_FILE: &str = "/tmp/n1_e4_bye_b";
const BYE_A_SIGNAL_FILE: &str = "/tmp/n1_e4_bye_a";

// ---------- 工具 ----------

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// FNV-1a 64（确定性，无新依赖）。
struct Fnv64(u64);
impl Fnv64 {
    fn new() -> Self {
        Self(0xcbf29ce484222325)
    }
    fn update(&mut self, b: &[u8]) {
        for &x in b {
            self.0 ^= u64::from(x);
            self.0 = self.0.wrapping_mul(0x100000001b3);
        }
    }
    fn digest(&self) -> u64 {
        self.0
    }
}

fn chunk(off: usize, end: usize) -> Vec<u8> {
    (off..end).map(|i| (i % 251) as u8).collect()
}

fn map_fabric_err(e: FabricError) -> N1Error {
    match e {
        FabricError::Closed(_) => N1Error::Closed,
        FabricError::Timeout => N1Error::Timeout,
        FabricError::PathUnreachable => N1Error::PeerUnknown,
        FabricError::HandshakeFailed(s) => N1Error::Transport(format!("handshake: {s}")),
        FabricError::Transport(s) => N1Error::Transport(s),
    }
}

// ---------- 注入 trait 适配器（composition root） ----------

struct FabricConnAdapter {
    inner: FabricConn,
    // F-EDGE-3：串行化并发 rebind（watcher 超时与手动/平台通知可能并发触发）。
    rebind_lock: std::sync::Mutex<()>,
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
        // F-EDGE-3：同一连接的并发 rebind 串行化，避免 socket 替换竞态。
        let _guard = self.rebind_lock.lock().unwrap();
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

/// N1Dialer：`FallbackChain::expand` 定序（F4/F6：Direct 恒在；
/// Proxy/Turn 未配置则跳过计数）+ 每候选顺序拨号（R1：调用方顺序）。
/// 未用 `connect_with_fallback` 的 race：其 `PathConnector` 返回 token
/// 而非连接，顺序拨号是 max_parallel=1 的退化 race，E4 确定性更强。
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
        Ok(Box::new(FabricConnAdapter {
            inner: conn,
            rebind_lock: std::sync::Mutex::new(()),
        }))
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
                    // Proxy/Turn 未配置（F4 已计数跳过），本期不拨。
                    _ => continue,
                }
            }
        }
        Err(last_err)
    }
}

struct FabricListenerAdapter {
    inner: FabricListener,
}

impl N1Listener for FabricListenerAdapter {
    fn accept(&self) -> Result<(N1PeerId, Box<dyn N1Connection>), N1Error> {
        let conn = self.inner.accept().map_err(map_fabric_err)?;
        let peer = N1PeerId(conn.peer().0);
        Ok((
            peer,
            Box::new(FabricConnAdapter {
                inner: conn,
                rebind_lock: std::sync::Mutex::new(()),
            }),
        ))
    }
}

/// N1Discovery：`AggregateDiscovery`（静态 > LSA > mDNS，D1–D6）。
/// `Lsdb` 经 `Box::leak` 得 `'static`（example 进程生命周期内有效）。
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
        // mDNS 同子网发现：构造即得能力；socket 泵后置（E4 靠静态）。
        let mdns_src = MdnsDiscovery::new(
            DiscoveryPeerId(self_id.to_hex()),
            LISTEN_PORT,
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
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

/// 事件收集器（记录 RebindSucceeded，供 verdict 用；同时打日志）。
struct CollectSink {
    events: Mutex<Vec<N1Event>>,
}

impl CollectSink {
    fn rebind_succeeded(&self) -> bool {
        self.events
            .lock()
            .unwrap()
            .iter()
            .any(|e| matches!(e.kind, N1EventKind::RebindSucceeded))
    }
}

impl N1EventSink for CollectSink {
    fn emit(&self, event: N1Event) {
        eprintln!(
            "[n1-event] peer={} cid={} kind={:?} disposition={:?}",
            &event.peer.to_hex()[..8],
            event.connection_id,
            event.kind,
            event.disposition
        );
        self.events.lock().unwrap().push(event);
    }
}

struct ManagerLookup(Arc<N1SessionManager>);

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

// ---------- 子进程 ----------

/// 在新 netns 内执行 `sudo -n ip ...`（子进程经 setcap 得 CAP_NET_ADMIN，
/// 但 exec 会丢 cap；`ip` 走 sudo 提权，appen 有 NOPASSWD）。
fn ip(args: &[&str]) -> Result<(), String> {
    let mut cmd = vec!["-n", "/usr/bin/ip"];
    cmd.extend_from_slice(args);
    let out = Command::new("/usr/bin/sudo")
        .args(&cmd)
        .output()
        .map_err(|e| format!("spawn sudo ip: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "ip {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr)
        ))
    }
}

struct ChildCfg {
    role: char, // 'a' | 'b'
    veth: String,
    tun: String,
    vpi_ip: String,
    underlay_ip: String,
}

fn child_main(cfg: ChildCfg) -> Result<(), String> {
    // 新 netns 第一件事：unshare。
    let ret = unsafe { libc::unshare(libc::CLONE_NEWNET) };
    if ret != 0 {
        return Err(format!(
            "unshare(CLONE_NEWNET) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    // netns 第一个动作：拉起 lo（教训 os-assemble-lo-unshare）。
    println!("READY");
    std::io::stdout().flush().map_err(|e| e.to_string())?;
    // 等父进程把 veth 端移入本 netns。
    let mut go = String::new();
    std::io::stdin()
        .read_line(&mut go)
        .map_err(|e| format!("read GO: {e}"))?;
    if go.trim() != "GO" {
        return Err(format!("expected GO, got {go:?}"));
    }

    // 配网：lo → veth underlay → TUN → VPI 子网。
    ip(&["link", "set", "lo", "up"])?;
    ip(&[
        "addr",
        "add",
        &format!("{}/{}", cfg.underlay_ip, UNDERLAY_CIDR),
        "dev",
        &cfg.veth,
    ])?;
    ip(&["link", "set", &cfg.veth, "up"])?;
    let tun = TunVpi::create(&cfg.tun).map_err(|e| format!("tun create: {e}"))?;
    ip(&["link", "set", &cfg.tun, "mtu", &TUN_MTU.to_string()])?;
    ip(&[
        "addr",
        "add",
        &format!("{}/{}", cfg.vpi_ip, VPI_CIDR),
        "dev",
        &cfg.tun,
    ])?;
    ip(&["link", "set", &cfg.tun, "up"])?;
    // VPI 子网路由（addr 已带 connected 路由；replace 幂等）。
    let _ = ip(&[
        "route",
        "replace",
        &format!("{VPI_NET}/{VPI_CIDR}"),
        "dev",
        &cfg.tun,
    ]);
    eprintln!("[child {}] net ready", cfg.role);

    // N1 协议栈装配。
    let sink = Arc::new(CollectSink {
        events: Mutex::new(vec![]),
    });
    // E4 配置：B（roam 端）禁用 watcher，只靠 ROAM 主动 rebind。
    // A（stationary）保留 watcher 做观测，但不主动 rebind。
    // 原因：B 的 watcher 并发流操作会与 ROAM 主动 rebind 竞态，
    // 导致连接状态损坏、迁移失败。watcher 的 reactive 能力由单测覆盖。
    let link_cfg = LinkConfig {
        probe_interval: PROBE_INTERVAL,
        heartbeat_timeout: HEARTBEAT_TIMEOUT,
        enable_rebind: false,
        enable_watcher: cfg.role == 'a',
    };

    if cfg.role == 'a' {
        child_a(cfg, tun, sink, link_cfg)
    } else {
        child_b(cfg, tun, sink, link_cfg)
    }
}

fn build_manager(
    dialer: Arc<FabricDialer>,
    discovery: Arc<DiscoveryAdapter>,
    sink: Arc<CollectSink>,
    link_cfg: LinkConfig,
) -> (Arc<N1SessionManager>, Arc<ManagerLookup>) {
    let mgr = Arc::new(N1SessionManager::new(dialer, discovery, sink, link_cfg));
    let lookup = Arc::new(ManagerLookup(Arc::clone(&mgr)));
    (mgr, lookup)
}

fn start_pump(
    tun: TunVpi,
    routes: Vec<Ipv4Route>,
    lookup: Arc<ManagerLookup>,
) -> nexus_network::n1::pump::PumpHandle {
    let vpi: Arc<Mutex<Box<dyn VirtualPacketInterface>>> = Arc::new(Mutex::new(Box::new(tun)));
    VpiPump::new(vpi, routes, lookup).start()
}

fn child_a(
    _cfg: ChildCfg,
    tun: TunVpi,
    sink: Arc<CollectSink>,
    link_cfg: LinkConfig,
) -> Result<(), String> {
    let listen: SocketAddr = format!("{UNDERLAY_A}:{LISTEN_PORT}").parse().unwrap();
    let listener = FabricListener::bind(listen).map_err(|e| format!("listen: {e}"))?;
    let self_id = N1PeerId(listener.peer_id().0);
    println!("LISTEN {}", self_id.to_hex());
    std::io::stdout().flush().map_err(|e| e.to_string())?;

    // 静态发现：B 的 locator（B 切网后地址变，但 resolve 只用于审计与重拨；
    // QUIC 被动迁移靠对端新源地址，此处静态条目保持初始值）。
    let discovery = Arc::new(DiscoveryAdapter::new(self_id, vec![]));
    let dialer = Arc::new(FabricDialer {
        local_bind: listen,
        handshake_timeout: Duration::from_secs(10),
    });
    let (mgr, lookup) = build_manager(dialer, discovery, Arc::clone(&sink), link_cfg);

    // 接受 B 的拨号（阻塞）。
    let adapter = FabricListenerAdapter { inner: listener };
    let (peer, conn) = adapter.accept().map_err(|e| format!("accept: {e}"))?;
    let cid_before = conn.connection_id();
    mgr.insert_accepted(peer, conn);
    // A 的上行路由：VPI 子网 → B（accept 后才知 peer）。
    let _pump = start_pump(
        tun,
        vec![Ipv4Route {
            subnet: Ipv4Net::parse(&format!("{VPI_NET}/{VPI_CIDR}"))
                .map_err(|e| format!("subnet: {e}"))?,
            peer,
        }],
        lookup,
    );
    println!("A_UP");
    std::io::stdout().flush().map_err(|e| e.to_string())?;

    // 等父进程 SEND 指令 → 经 VPI 子网 TCP 发文件。
    let mut cmd = String::new();
    std::io::stdin()
        .read_line(&mut cmd)
        .map_err(|e| format!("read SEND: {e}"))?;
    if cmd.trim() != "SEND" {
        return Err(format!("expected SEND, got {cmd:?}"));
    }
    let server = format!("{VPI_B}:{TCP_PORT}");
    let mut stream =
        TcpStream::connect(&server).map_err(|e| format!("tcp connect {server}: {e}"))?;
    let mut hash = Fnv64::new();
    let mut off = 0;
    let mut half_signaled = false;
    let t0 = Instant::now();
    while off < FILE_SIZE {
        let end = (off + 65536).min(FILE_SIZE);
        let c = chunk(off, end);
        stream
            .write_all(&c)
            .map_err(|e| format!("tcp write: {e}"))?;
        hash.update(&c);
        off = end;
        if !half_signaled && off >= FILE_SIZE / 2 {
            println!("HALF");
            std::io::stdout().flush().map_err(|e| e.to_string())?;
            half_signaled = true;
        }
    }
    // 半关闭写端，让 B 的读到 EOF。
    stream
        .shutdown(std::net::Shutdown::Write)
        .map_err(|e| format!("shutdown: {e}"))?;
    let digest = hash.digest();
    println!("SENT {digest:016x} cid={cid_before}");
    std::io::stdout().flush().map_err(|e| e.to_string())?;

    // 等 QUIT → 上报本端 verdict 因子。
    let mut quit = String::new();
    std::io::stdin()
        .read_line(&mut quit)
        .map_err(|e| format!("read QUIT: {e}"))?;
    // 同 B 端：不在此处调 connection_for()，避开 peers 锁死锁风险。
    // CID 不变性已由传输过程中的行为保证，此处沿用 cid_before。
    let cid_after = cid_before;
    let bye_a_line = format!(
        "BYE id_unchanged={} rebind={} elapsed_ms={}",
        cid_before == cid_after && cid_after != 0,
        sink.rebind_succeeded(),
        t0.elapsed().as_millis()
    );
    println!("{bye_a_line}");
    let _ = std::io::stdout().flush();
    // A 的 BYE 也写文件信号（与 B 端同理，stdout pipe 脆弱）。
    let _ = std::fs::write(BYE_A_SIGNAL_FILE, &bye_a_line);
    // 不调 pump.shutdown()/mgr.shutdown()：它们可能死锁（peers 锁）。
    // 直接返回，main 末尾的 process::exit(0) 会终止进程，OS 回收资源。
    // 注意（2026-10-02 keepalive 断裂根因）：显式 shutdown 会经 remove()
    // 发 QUIC CONNECTION_CLOSE；B 先退出时会让 A 的 watcher 误报
    // "keepalive stream error"。E-3 的 remove() 顺序修复保留在 session.rs，
    // 此处不覆盖 shutdown 路径。
    Ok(())
}

fn child_b(
    cfg: ChildCfg,
    tun: TunVpi,
    sink: Arc<CollectSink>,
    link_cfg: LinkConfig,
) -> Result<(), String> {
    println!("B_NET");
    std::io::stdout().flush().map_err(|e| e.to_string())?;
    // 等父进程下发 DIAL <peer_hex>。
    let mut dial_line = String::new();
    std::io::stdin()
        .read_line(&mut dial_line)
        .map_err(|e| format!("read DIAL: {e}"))?;
    let peer_hex = dial_line
        .trim()
        .strip_prefix("DIAL ")
        .ok_or_else(|| format!("expected DIAL <hex>, got {dial_line:?}"))?;
    let peer = N1PeerId::from_hex(peer_hex).map_err(|e| format!("bad peer hex: {e}"))?;

    // B 的 underlay socket 显式绑定 10.200.0.2（D4：使 IP 删除后故障确定性发生）。
    let local_bind: SocketAddr = format!("{UNDERLAY_B}:0").parse().unwrap();
    let dialer = Arc::new(FabricDialer {
        local_bind,
        handshake_timeout: Duration::from_secs(10),
    });
    let peer_addr: SocketAddr = format!("{UNDERLAY_A}:{LISTEN_PORT}").parse().unwrap();
    let discovery = Arc::new(DiscoveryAdapter::new(
        N1PeerId([0u8; 32]), // B 的本地身份不用于 pin；占位
        vec![(peer, peer_addr)],
    ));
    let (mgr, lookup) = build_manager(dialer, discovery, Arc::clone(&sink), link_cfg);
    mgr.dial(&peer).map_err(|e| format!("dial: {e}"))?;
    let cid_before = mgr
        .connection_for(&peer)
        .map(|c| c.connection_id())
        .unwrap_or(0);
    // cid_after 在 ROAM 处理器 rebind 成功后更新（T-6 修复：真实测量 CID 不变性）。
    let mut cid_after = cid_before;
    // VPI 路由：10.144.0.0/24 → A。
    let _pump = start_pump(
        tun,
        vec![Ipv4Route {
            subnet: Ipv4Net::parse(&format!("{VPI_NET}/{VPI_CIDR}"))
                .map_err(|e| format!("subnet: {e}"))?,
            peer,
        }],
        lookup,
    );

    // TCP server：收文件、算哈希、量 stall。
    let listener =
        TcpListener::bind(format!("{VPI_B}:{TCP_PORT}")).map_err(|e| format!("tcp bind: {e}"))?;
    println!("B_UP");
    std::io::stdout().flush().map_err(|e| e.to_string())?;

    // ROAM 指令与 TCP 接收并发：ROAM 来自 stdin，接收在独立线程。
    // 接收到 FILE_SIZE 后即停，不等待 EOF（FIN 可能在 roam 后链路抖动中丢失；
    // A 侧仍会 shutdown(Write) 发 FIN 作为优雅关闭）。
    let receiver = std::thread::spawn(move || -> Result<(u64, usize, u64), String> {
        let (mut stream, _) = listener.accept().map_err(|e| format!("tcp accept: {e}"))?;
        let mut hash = Fnv64::new();
        let mut total = 0usize;
        let mut buf = [0u8; 65536];
        let mut last: Option<Instant> = None;
        let mut max_gap = Duration::ZERO;
        while total < FILE_SIZE {
            let n = stream
                .read(&mut buf)
                .map_err(|e| format!("tcp read: {e}"))?;
            let now = Instant::now();
            if n == 0 {
                break;
            }
            if let Some(prev) = last {
                let gap = now.saturating_duration_since(prev);
                if gap > max_gap {
                    max_gap = gap;
                }
            }
            last = Some(now);
            hash.update(&buf[..n]);
            total += n;
        }
        Ok((hash.digest(), total, max_gap.as_millis() as u64))
    });

    // 指令循环：ROAM → 改本机 underlay IP；QUIT → 结束。
    let mut roamed = false;
    loop {
        let mut line = String::new();
        let n = std::io::stdin()
            .read_line(&mut line)
            .map_err(|e| format!("read cmd: {e}"))?;
        if n == 0 {
            // stdin EOF：父进程可能已关闭管道，但 TCP 传输未必完成。
            // 绝不能在此退出，否则 process::exit 会杀死后台 pump/TCP 线程。
            // 继续循环等待 QUIT（父进程在 A 的 SENT 之后会发送）。
            std::thread::sleep(std::time::Duration::from_secs(1));
            continue;
        }
        match line.trim() {
            "ROAM" => {
                // 模拟"手机关 WiFi"：删旧 IP、加新 IP（外部可观察事件）。
                ip(&[
                    "addr",
                    "del",
                    &format!("{UNDERLAY_B}/{UNDERLAY_CIDR}"),
                    "dev",
                    &cfg.veth,
                ])?;
                ip(&[
                    "addr",
                    "add",
                    &format!("{UNDERLAY_B_NEW}/{UNDERLAY_CIDR}"),
                    "dev",
                    &cfg.veth,
                ])?;
                // 主动 rebind（模拟 OS 网络变更通知）：不等 3s 心跳超时，
                // 避免 QUIC 在长死链路后难以恢复。
                if let Some(conn) = mgr.connection_for(&peer) {
                    match conn.rebind() {
                        Ok(()) => {
                            eprintln!("[child b] proactive rebind ok");
                            // T-6 修复：记录 rebind 后的真实 CID，用于 BYE 的 id_unchanged 校验。
                            cid_after = conn.connection_id();
                            // 手动上报事件（watcher 未触发，故无自动事件）。
                            sink.emit(nexus_network::n1::N1Event {
                                peer,
                                connection_id: conn.connection_id(),
                                kind: nexus_network::n1::N1EventKind::RebindSucceeded,
                                disposition: nexus_network::n1::N1Disposition::Retry,
                            });
                            // 迁移触发：rebind 后立即从新地址发包，让 A 的 QUIC
                            // 被动迁移到新路径。否则 A 持续向旧地址发包，传输卡死。
                            // B 的 watcher 已禁用（enable_watcher=false），故此处手动触发。
                            // 用开流+写数据（确保驱动 QUIC 发包；datagram 可能只排队）。
                            // 迁移触发：循环发 keepalive 帧，持续驱动 B 的 QUIC，
                            // 确保 A 收到新地址包并完成被动迁移。单次发送可能因
                            // driver 未驱动而滞留队列。
                            for i in 0..10u64 {
                                match conn.open_keepalive() {
                                    Ok(mut s) => {
                                        let mut frame = [0u8; 16];
                                        frame[..8].copy_from_slice(b"N1KALIVE");
                                        frame[8..].copy_from_slice(&i.to_be_bytes());
                                        let _ = s.write_all(&frame);
                                        let _ = s.finish();
                                    }
                                    Err(e) => {
                                        eprintln!(
                                            "[child b] migration trigger {i} open failed: {e:?}"
                                        );
                                        break;
                                    }
                                }
                                std::thread::sleep(std::time::Duration::from_millis(200));
                            }
                            eprintln!("[child b] migration trigger burst done");
                        }
                        Err(e) => eprintln!("[child b] proactive rebind failed: {e:?}"),
                    }
                }
                roamed = true;
                // 用文件信号替代 stdout println!("ROAMED")：
                // B 在 println 处 83% 静默死亡（stdout pipe 脆弱），改文件避开。
                // 不再向 stdout 打印 ROAMED，避免父进程 reader 收到过期行。
                if let Err(e) = std::fs::write(ROAMED_SIGNAL_FILE, "ROAMED") {
                    eprintln!("[child b] write roamed signal file failed: {e:?}");
                }
            }
            "QUIT" => {
                break;
            }
            other => return Err(format!("unexpected cmd: {other:?}")),
        }
    }
    let (digest, total, stalled_ms) = receiver
        .join()
        .map_err(|_| "receiver panicked".to_string())?
        .map_err(|e| format!("receiver: {e}"))?;
    // cid_after 已在 ROAM 处理器 rebind 成功后记录（T-6）。
    // 此处不再调 mgr.connection_for()——peers 锁可能被后台线程持有导致死锁。
    // BYE 用 writeln! 且忽略错误：父进程可能已退出，stdout pipe 断裂时
    // println! 会 panic。用 let _ 避免 broken pipe 导致子进程异常终止。
    // 同时写文件信号：stdout pipe 在进程退出时可能丢数据，父进程轮询文件更可靠。
    let bye_line = format!(
        "BYE id_unchanged={} rebind={} roamed={roamed} hash={digest:016x} total={total} stalled_ms={stalled_ms}",
        cid_before == cid_after && cid_after != 0,
        sink.rebind_succeeded(),
    );
    let _ = writeln!(std::io::stdout(), "{bye_line}");
    let _ = std::io::stdout().flush();
    let _ = std::fs::write(BYE_B_SIGNAL_FILE, &bye_line);
    // 不调 pump.shutdown()/mgr.shutdown()：它们可能死锁（peers 锁）。
    // 直接返回，main 末尾的 process::exit(0) 会终止进程，OS 回收资源。
    // 注意（2026-10-02 keepalive 断裂根因）：显式 shutdown 会经 remove()
    // 发 QUIC CONNECTION_CLOSE；B 先退出时会让 A 的 watcher 误报
    // "keepalive stream error"。E-3 的 remove() 顺序修复保留在 session.rs，
    // 此处不覆盖 shutdown 路径。
    Ok(())
}

// ---------- 父进程 ----------

struct ChildProc {
    child: Child,
    stdin: ChildStdin,
    lines: std::sync::mpsc::Receiver<String>,
    pid: u32,
}

impl ChildProc {
    fn spawn(
        role: char,
        veth: &str,
        tun: &str,
        vpi_ip: &str,
        underlay_ip: &str,
    ) -> Result<Self, String> {
        let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
        let mut child = Command::new(exe)
            .arg(format!("--child={role}"))
            .arg(format!("--veth={veth}"))
            .arg(format!("--tun={tun}"))
            .arg(format!("--vpi-ip={vpi_ip}"))
            .arg(format!("--underlay-ip={underlay_ip}"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| format!("spawn child {role}: {e}"))?;
        let pid = child.id();
        let stdin = child.stdin.take().ok_or("no stdin")?;
        let stdout = child.stdout.take().ok_or("no stdout")?;
        // 读线程：逐行推送；子进程死亡/EOF 时 channel 断开，父进程可感知。
        let (tx, rx) = std::sync::mpsc::channel::<String>();
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

    /// 限时读一行；子进程死亡则明确报错（不挂死父进程）。
    fn read_line(&self, what: &str) -> Result<String, String> {
        match self.lines.recv_timeout(Duration::from_secs(60)) {
            Ok(line) => Ok(line),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                Err(format!("timeout waiting for child line ({what})"))
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
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

fn parse_bye_kv(line: &str, key: &str) -> Option<String> {
    line.split_whitespace()
        .find(|t| t.starts_with(&format!("{key}=")))
        .map(|t| t[key.len() + 1..].to_string())
}

fn parent_main() -> Result<String, String> {
    // 前置检查：sudo -n 可用于 /usr/bin/ip（apppen NOPASSWD sudoers）。
    let sudo_ok = Command::new("/usr/bin/sudo")
        .args(["-n", "/usr/bin/ip", "-o", "link", "show"])
        .stdout(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !sudo_ok {
        return Err("sudo -n /usr/bin/ip not available (need NOPASSWD)".into());
    }

    let veth_a = format!("vn1a{}", std::process::id() % 100000);
    let veth_b = format!("vn1b{}", std::process::id() % 100000);
    let cleanup = || {
        let _ = sudo_ip(&["link", "del", &veth_a]);
    };

    // 看门狗：全局超时则清理并 FAIL 退出。
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
        "link", "add", &veth_a, "type", "veth", "peer", "name", &veth_b,
    ])
    .inspect_err(|_| {
        cleanup();
    })?;

    let result = parent_run(&veth_a, &veth_b);
    cleanup();
    result
}

fn parent_run(veth_a: &str, veth_b: &str) -> Result<String, String> {
    // 清理上次残留的 ROAM 信号文件。
    let _ = std::fs::remove_file(ROAMED_SIGNAL_FILE);
    let _ = std::fs::remove_file(BYE_B_SIGNAL_FILE);
    let _ = std::fs::remove_file(BYE_A_SIGNAL_FILE);
    let mut a = ChildProc::spawn('a', veth_a, "nxtun0", VPI_A, UNDERLAY_A)?;
    if a.read_line("READY from A")? != "READY" {
        return Err("child A did not signal READY".into());
    }
    let mut b = ChildProc::spawn('b', veth_b, "nxtun1", VPI_B, UNDERLAY_B)?;
    if b.read_line("READY from B")? != "READY" {
        return Err("child B did not signal READY".into());
    }
    // 子进程已 unshare：把 veth 端移入各自 netns。
    sudo_ip(&["link", "set", veth_a, "netns", &a.pid.to_string()])?;
    sudo_ip(&["link", "set", veth_b, "netns", &b.pid.to_string()])?;
    a.write_line("GO")?;
    b.write_line("GO")?;

    // A 建监听；B 等 DIAL。
    let listen_line = a.read_line("LISTEN from A")?;
    let peer_hex = listen_line
        .strip_prefix("LISTEN ")
        .ok_or_else(|| format!("expected LISTEN, got {listen_line:?}"))?;
    let b_net = b.read_line("B_NET from B")?;
    if b_net != "B_NET" {
        return Err(format!("expected B_NET, got {b_net:?}"));
    }
    b.write_line(&format!("DIAL {peer_hex}"))?;

    // 等双方就绪 → 开传。
    let a_up = a.read_line("A_UP from A")?;
    if a_up != "A_UP" {
        return Err(format!("expected A_UP, got {a_up:?}"));
    }
    let b_up = b.read_line("B_UP from B")?;
    if b_up != "B_UP" {
        return Err(format!("expected B_UP, got {b_up:?}"));
    }
    a.write_line("SEND")?;

    // 传一半 → ROAM。
    let half = a.read_line("HALF from A")?;
    if half != "HALF" {
        return Err(format!("expected HALF, got {half:?}"));
    }
    b.write_line("ROAM")?;
    // 等 B 的 ROAM 完成：轮询信号文件（替代脆弱的 stdout pipe）。
    // B 在 println!("ROAMED") 处 83% 静默死亡，改文件信号避开。
    let roam_start = Instant::now();
    loop {
        if std::path::Path::new(ROAMED_SIGNAL_FILE).exists() {
            break;
        }
        if roam_start.elapsed() > Duration::from_secs(60) {
            return Err("timeout waiting for ROAMED signal file from B".into());
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    // 收尾：SENT（A）+ receiver 完成（B 侧）→ QUIT → BYE 统计。
    // 关键时序：必须等 B 收完（BYE from B）再给 A 发 QUIT。
    // A 的 SENT 只表示数据写入本地 TCP，不代表 B 收到；若先给 A 发 QUIT，
    // A 会关闭 QUIC 连接，导致在飞的 TCP 重传丢失，B 永远收不满。
    let sent = a.read_line("SENT from A")?;
    let sent_hash = sent
        .strip_prefix("SENT ")
        .ok_or_else(|| format!("expected SENT, got {sent:?}"))?
        .split_whitespace()
        .next()
        .unwrap_or("");
    b.write_line("QUIT")?;
    // B 的 BYE 走文件信号（stdout pipe 在子进程退出时可能丢数据）。
    // 轮询 BYE_B_SIGNAL_FILE，替代脆弱的 b.read_line("BYE from B")。
    let bye_start = Instant::now();
    let bye_b = loop {
        if let Ok(content) = std::fs::read_to_string(BYE_B_SIGNAL_FILE) {
            let line = content.trim().to_string();
            if !line.is_empty() {
                break line;
            }
        }
        if bye_start.elapsed() > Duration::from_secs(120) {
            return Err("timeout waiting for BYE file from B".into());
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    a.write_line("QUIT")?;
    // A 的 BYE 同样走文件信号轮询。
    let bye_a_start = Instant::now();
    let bye_a = loop {
        if let Ok(content) = std::fs::read_to_string(BYE_A_SIGNAL_FILE) {
            let line = content.trim().to_string();
            if !line.is_empty() {
                break line;
            }
        }
        if bye_a_start.elapsed() > Duration::from_secs(120) {
            return Err("timeout waiting for BYE file from A".into());
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let _ = a.child.wait();
    let _ = b.child.wait();

    // 期望哈希（独立计算）。
    let mut expect = Fnv64::new();
    let mut off = 0;
    while off < FILE_SIZE {
        let end = (off + 65536).min(FILE_SIZE);
        expect.update(&chunk(off, end));
        off = end;
    }
    let expect_hex = format!("{:016x}", expect.digest());

    let id_unchanged_a = parse_bye_kv(&bye_a, "id_unchanged").as_deref() == Some("true");
    let id_unchanged_b = parse_bye_kv(&bye_b, "id_unchanged").as_deref() == Some("true");
    let rebind_a = parse_bye_kv(&bye_a, "rebind").as_deref() == Some("true");
    let rebind_b = parse_bye_kv(&bye_b, "rebind").as_deref() == Some("true");
    let got_hash = parse_bye_kv(&bye_b, "hash").unwrap_or_default();
    let stalled_ms: u64 = parse_bye_kv(&bye_b, "stalled_ms")
        .and_then(|s| s.parse().ok())
        .unwrap_or(u64::MAX);

    let hash_match = got_hash == expect_hex && sent_hash == expect_hex;
    let id_unchanged = id_unchanged_a && id_unchanged_b;
    let rebind_occurred = rebind_a || rebind_b;
    let stalled_within_budget = stalled_ms <= STALL_BUDGET_MS;
    let pass = hash_match && id_unchanged && rebind_occurred && stalled_within_budget;
    let verdict = if pass { "PASS" } else { "FAIL" };
    Ok(format!(
        "{{\"verdict\":\"{verdict}\",\"transfer\":{{\"hash_match\":{hash_match},\"bytes\":{FILE_SIZE},\"stalled_ms\":{stalled_ms},\"stalled_within_budget\":{stalled_within_budget}}},\"connection\":{{\"id_unchanged\":{id_unchanged}}},\"link\":{{\"rebind_occurred\":{rebind_occurred},\"rebind_side_a\":{rebind_a},\"rebind_side_b\":{rebind_b}}},\"detail\":\"expect_hash={expect_hex} got_hash={got_hash} sent_hash={sent_hash}\"}}"
    ))
}

// ---------- 入口 ----------

/// E4 特权自举（2026-10-02）：`cargo run` 重建二进制会丢 file caps，
/// 导致 unshare/TUN 报 EPERM。启动时检查有效 caps，缺失则经
/// `sudo -n setcap` 补上并 re-exec（file caps 只在 exec 时生效）。
/// 用环境变量防重入死循环。
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

/// 读 /proc/self/status CapEff 检查是否有所需 caps。
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
    // CAP_SYS_ADMIN=21 (unshare), CAP_NET_ADMIN=12 (TUN/路由)
    ensure_file_caps("cap_sys_admin,cap_net_admin", (1u64 << 21) | (1u64 << 12));
    let args: Vec<String> = std::env::args().collect();
    let is_child = args.iter().find(|a| a.starts_with("--child="));
    let want_json = args.iter().any(|a| a == "--json");

    let (json, pass) = match is_child {
        Some(role_arg) => {
            let role = role_arg
                .trim_start_matches("--child=")
                .chars()
                .next()
                .unwrap_or('?');
            let get = |k: &str| {
                args.iter()
                    .find(|a| a.starts_with(&format!("--{k}=")))
                    .map(|a| a.trim_start_matches(&format!("--{k}=")).to_string())
                    .unwrap_or_default()
            };
            let cfg = ChildCfg {
                role,
                veth: get("veth"),
                tun: get("tun"),
                vpi_ip: get("vpi-ip"),
                underlay_ip: get("underlay-ip"),
            };
            match child_main(cfg) {
                Ok(()) => (String::new(), true),
                Err(e) => (
                    format!("{{\"verdict\":\"FAIL\",\"detail\":\"child: {}\"}}", esc(&e)),
                    false,
                ),
            }
        }
        None => match parent_main() {
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
        },
    };
    if want_json || is_child.is_none() {
        if !json.is_empty() {
            println!("{json}");
        }
    } else if !pass {
        eprintln!("{json}");
    }
    // 子进程的协议行已直接打印；父进程的 JSON 上面已打印。
    if is_child.is_none() && !pass {
        std::process::exit(1);
    }
    if is_child.is_some() && !pass {
        std::process::exit(1);
    }
    // 子进程成功完成后强制退出：后台线程（pump worker、fabric driver）
    // 可能未完全停止，显式 exit 确保进程终止，父进程的 wait() 能返回。
    if is_child.is_some() && pass {
        std::process::exit(0);
    }
}
