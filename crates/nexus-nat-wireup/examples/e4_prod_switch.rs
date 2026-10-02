//! E4: NAT production traffic switching.
//!
//! Proves the Phase-1 stack (PathLink + QualityMonitor + PunchManager)
//! switches production traffic after a successful punch:
//!
//!   S1 switch-to-direct: relay transfer running -> background punch ->
//!     direct wins the PathManager race (20%+3s) -> traffic moves to direct
//!     mid-transfer -> every byte echoed correctly, relay stays warm.
//!   S2 direct-loses: direct punched but SLOWER than relay -> stays on relay
//!     ("打洞成功≠最优" in production; the punch still succeeds).
//!
//! Honest impairments: the sim cannot make TURN reliably slower/faster than
//! direct on loopback, so a controlled delay is injected at the MuxTransport
//! (S1: +40ms on TURN-relayed packets; S2: +30ms on direct packets). The
//! measurement -> race -> switch machinery is fully real.
//!
//! Layout: TURN server (3478) --+-- simA -- nodeA (driver: mux transport)
//!                               +-- simB -- nodeB (driver: mux transport)
//!   STUN helpers on 7001/7002/7003.
//!
//! Usage: e4_prod_switch <switch-to-direct|direct-loses>

use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::{
    Arc, Mutex, Weak,
    atomic::{AtomicU64, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

use nexus_connectivity::nat::NatType;
use nexus_fabric::{Cmd, ConnShared, Driver, PeerId as FabricPeerId, StreamShared};
use nexus_nat_quality::{MeasuredPath, PathEventSink, ProbeRole, QualityMonitor};
use nexus_nat_traversal::{LocalCandidates, PortSample, PunchConfig, PunchResult};
use nexus_nat_wireup::{PunchManager, accept_stream_timeout};
use nexus_path::{PathConfig, PathEvent, PathKind, PathManager};
use nexus_projection::PathLink;
use nexus_projection::path_link::ActiveConn;
use nexus_turn::TurnSocket;
use nexus_turn::client::{TurnClient, TurnCredentials};
use nexus_turn::server::TurnServer;

// ---------------------------------------------------------------------------
// Address framing helpers
// ---------------------------------------------------------------------------

fn enc_addr(a: SocketAddr, out: &mut Vec<u8>) {
    let ipb = match a.ip() {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    };
    out.extend_from_slice(&ipb);
    out.extend_from_slice(&a.port().to_be_bytes());
}

fn dec_addr(b: &[u8]) -> Option<SocketAddr> {
    if b.len() < 18 {
        return None;
    }
    let mut ipb = [0u8; 16];
    ipb.copy_from_slice(&b[..16]);
    let port = u16::from_be_bytes([b[16], b[17]]);
    let ip = match IpAddr::from(ipb) {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    };
    Some(SocketAddr::new(ip, port))
}

fn peer_hex(peer: &FabricPeerId) -> String {
    peer.0.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------
// Userspace NAT simulator (restricted cone; honest hole semantics)
// ---------------------------------------------------------------------------

struct Sim {
    int_sock: UdpSocket,
    ext_sock: Mutex<Option<UdpSocket>>,
    holes: Mutex<HashSet<SocketAddr>>,
    node: Mutex<Option<SocketAddr>>,
    drops: AtomicU64,
}

impl Sim {
    fn new(int_port: u16, ext_ip: Ipv4Addr, ext: u16) -> io::Result<Arc<Self>> {
        let int_sock = UdpSocket::bind(("127.0.0.1", int_port))?;
        int_sock.set_nonblocking(true)?;
        let ext_sock = UdpSocket::bind((ext_ip, ext))?;
        ext_sock.set_nonblocking(true)?;
        Ok(Arc::new(Self {
            int_sock,
            ext_sock: Mutex::new(Some(ext_sock)),
            holes: Mutex::new(HashSet::new()),
            node: Mutex::new(None),
            drops: AtomicU64::new(0),
        }))
    }

    fn run(self: &Arc<Self>) {
        let mut buf = [0u8; 65536];
        loop {
            match self.int_sock.recv_from(&mut buf) {
                Ok((n, src)) => {
                    *self.node.lock().unwrap() = Some(src);
                    // [1][dst_ip16][dst_port2][payload]
                    if n >= 19 && buf[0] == 1 {
                        if let Some(dst) = dec_addr(&buf[1..19]) {
                            self.holes.lock().unwrap().insert(dst);
                            let guard = self.ext_sock.lock().unwrap();
                            if let Some(s) = guard.as_ref() {
                                let _ = s.send_to(&buf[19..n], dst);
                            }
                        }
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => break,
            }
            let guard = self.ext_sock.lock().unwrap();
            if let Some(s) = guard.as_ref() {
                match s.recv_from(&mut buf) {
                    Ok((n, src)) => {
                        let allowed = self.holes.lock().unwrap().contains(&src);
                        if !allowed {
                            self.drops.fetch_add(1, Ordering::Relaxed);
                        } else if let Some(node) = *self.node.lock().unwrap() {
                            let mut f = Vec::with_capacity(18 + n);
                            enc_addr(src, &mut f);
                            f.extend_from_slice(&buf[..n]);
                            let _ = self.int_sock.send_to(&f, node);
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(_) => {}
                }
            }
            drop(guard);
            thread::sleep(Duration::from_millis(1));
        }
    }
}

// ---------------------------------------------------------------------------
// STUN echo helper
// ---------------------------------------------------------------------------

fn stun_helper(port: u16) {
    thread::spawn(move || {
        let s = UdpSocket::bind(("127.0.0.1", port)).expect("stun bind");
        let mut buf = [0u8; 1500];
        loop {
            match s.recv_from(&mut buf) {
                Ok((_, src)) => {
                    let mut r = Vec::with_capacity(18);
                    enc_addr(src, &mut r);
                    let _ = s.send_to(&r, src);
                }
                Err(_) => thread::sleep(Duration::from_millis(1)),
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Mux transport: relay targets -> TURN; everything else -> sim.
// Controlled delay injection creates the quality gap the race needs.
// ---------------------------------------------------------------------------

struct MuxTransport {
    turn: TurnSocket,
    sim_link: UdpSocket,
    sim_int: SocketAddr,
    relay_targets: HashSet<SocketAddr>,
    relay_delay: Duration,
    direct_delay: Duration,
}

impl nexus_fabric::transport::UdpTransport for MuxTransport {
    fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        if self.relay_targets.contains(&target) {
            if !self.relay_delay.is_zero() {
                thread::sleep(self.relay_delay);
            }
            return self.turn.send_to(buf, target);
        }
        if !self.direct_delay.is_zero() {
            thread::sleep(self.direct_delay);
        }
        let mut f = Vec::with_capacity(19 + buf.len());
        f.push(1u8);
        enc_addr(target, &mut f);
        f.extend_from_slice(buf);
        self.sim_link.send_to(&f, self.sim_int)?;
        Ok(buf.len())
    }

    fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut tmp = [0u8; 65536];
        match self.sim_link.recv_from(&mut tmp) {
            Ok((n, _)) => {
                if n >= 18 {
                    if let Some(src) = dec_addr(&tmp[..18]) {
                        let len = (n - 18).min(buf.len());
                        buf[..len].copy_from_slice(&tmp[18..18 + len]);
                        return Ok((len, src));
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e),
        }
        self.turn.recv_from(buf)
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.turn.set_read_timeout(timeout)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.sim_link.local_addr()
    }
}

// ---------------------------------------------------------------------------
// Stream helpers (transfer) at ConnShared level
// ---------------------------------------------------------------------------

fn open_stream(conn: &Arc<ConnShared>) -> io::Result<Arc<StreamShared>> {
    let (tx, rx) = std::sync::mpsc::channel();
    conn.tx
        .send(Cmd::OpenBi {
            conn: conn.id.0,
            reply: tx,
        })
        .map_err(|_| io::Error::new(io::ErrorKind::NotConnected, "driver gone"))?;
    rx.recv_timeout(Duration::from_secs(10))
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "open_bi timeout"))?
        .map_err(|e| io::Error::other(format!("{e:?}")))
}

fn xfer_write(s: &Arc<StreamShared>, data: &[u8]) -> io::Result<()> {
    let mut hdr = (data.len() as u32).to_be_bytes().to_vec();
    hdr.extend_from_slice(data);
    nexus_nat_wireup::channel::write_all_stream(s, &hdr)
}

fn xfer_read(s: &Arc<StreamShared>) -> io::Result<Vec<u8>> {
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut lenb = [0u8; 4];
    nexus_nat_wireup::channel::read_exact_deadline(s, &mut lenb, deadline)?;
    let len = u32::from_be_bytes(lenb) as usize;
    let mut buf = vec![0u8; len];
    nexus_nat_wireup::channel::read_exact_deadline(s, &mut buf, deadline)?;
    Ok(buf)
}

/// Signal end-of-stream so the QUIC stream slot is retired (both sides must
/// FIN; otherwise the 100-stream concurrent limit is hit).
fn finish_stream(s: &Arc<StreamShared>) {
    if let Ok(mut st) = s.state.lock() {
        st.send_fin = true;
    }
    let _ = s.tx.send(Cmd::Pump { conn: s.conn_id });
}

// ---------------------------------------------------------------------------
// Node assembly
// ---------------------------------------------------------------------------

struct Node {
    driver: Arc<Driver>,
    my_id: FabricPeerId,
    local: LocalCandidates,
    samples: Vec<PortSample>,
}

struct NodeCfg {
    name: &'static str,
    sim_int: SocketAddr,
    stun_helpers: Vec<SocketAddr>,
    relay_delay: Duration,
    direct_delay: Duration,
}

fn stun_sample(
    sim_link: &UdpSocket,
    sim_int: SocketAddr,
    helpers: &[SocketAddr],
) -> io::Result<(SocketAddr, Vec<PortSample>)> {
    let mut samples = Vec::new();
    let mut reflexive = None;
    for &h in helpers {
        let mut f = vec![1u8];
        enc_addr(h, &mut f);
        f.extend_from_slice(b"stun?");
        sim_link.send_to(&f, sim_int)?;
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut buf = [0u8; 1500];
        loop {
            if Instant::now() > deadline {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "stun sample"));
            }
            match sim_link.recv_from(&mut buf) {
                Ok((n, _)) if n >= 18 => {
                    let payload = &buf[18..n];
                    if payload.len() >= 18 {
                        if let Some(obs) = dec_addr(payload) {
                            reflexive = Some(obs);
                            samples.push(PortSample {
                                port: obs.port(),
                                at_ms: 0,
                            });
                            break;
                        }
                    }
                }
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(2));
                }
                Err(e) => return Err(e),
            }
        }
    }
    Ok((
        reflexive.ok_or_else(|| io::Error::other("no reflexive"))?,
        samples,
    ))
}

fn build_node(cfg: &NodeCfg, client: TurnClient, peer_relayed: SocketAddr) -> io::Result<Node> {
    let relayed = client.relayed_addr();
    client
        .create_permission(peer_relayed)
        .map_err(|e| io::Error::other(format!("{}: create_permission: {e}", cfg.name)))?;

    let sim_link = UdpSocket::bind(("127.0.0.1", 0))?;
    let (reflexive, mut samples) = stun_sample(&sim_link, cfg.sim_int, &cfg.stun_helpers)?;
    for (i, s) in samples.iter_mut().enumerate() {
        s.at_ms = (i as u64) * 100;
    }

    let turn_sock = TurnSocket::new(client);
    let mut relay_targets = HashSet::new();
    relay_targets.insert(peer_relayed);
    let mux = MuxTransport {
        turn: turn_sock,
        sim_link,
        sim_int: cfg.sim_int,
        relay_targets,
        relay_delay: cfg.relay_delay,
        direct_delay: cfg.direct_delay,
    };
    // set_nonblocking for sim_link (MuxTransport::new did this in e4_nat_punch)
    mux.sim_link.set_nonblocking(true).unwrap();
    let driver = Driver::new_server_with_transport(Box::new(mux))
        .map_err(|e| io::Error::other(format!("{}: driver: {e:?}", cfg.name)))?;
    let my_id = driver
        .shared()
        .peer_id
        .ok_or_else(|| io::Error::other("no peer id"))?;

    println!(
        "[e4] {}: relayed={relayed} reflexive={reflexive} id={}",
        cfg.name,
        peer_hex(&my_id)
    );
    Ok(Node {
        driver,
        my_id,
        local: LocalCandidates {
            host: Vec::new(),
            srflx: Some(reflexive),
            srflx_stun: None,
            nat_type: NatType::RestrictedCone,
        },
        samples,
    })
}

// ---------------------------------------------------------------------------
// Production switching stack (mirrors apps/nexusd NatSwitching)
// ---------------------------------------------------------------------------

struct Stack {
    punch: Arc<PunchManager>,
    link: Arc<Mutex<PathLink>>,
    monitor: QualityMonitor<Arc<ConnShared>>,
}

struct StackSink {
    inner: Weak<Stack>,
}

impl PathEventSink for StackSink {
    fn on_path_event(&self, event: PathEvent) {
        let Some(st) = self.inner.upgrade() else {
            return;
        };
        let PathEvent::Switched { from, to, .. } = &event;
        println!(
            "[e4] SWITCH {} ({:?}) -> {} ({:?})",
            from.remote_addr, from.kind, to.remote_addr, to.kind
        );
        st.monitor.set_role(&to.remote_addr, ProbeRole::Active);
        st.monitor.set_role(&from.remote_addr, ProbeRole::Backup);
        st.link.lock().unwrap().handle_event(event);
    }
}

impl Stack {
    fn new(node: &Node) -> Arc<Self> {
        let driver = node.driver.clone();
        let my_id = node.my_id;
        let local = node.local.clone();
        let samples = node.samples.clone();
        let st = Arc::new_cyclic(|weak| {
            let punch = PunchManager::new(driver, my_id);
            punch.set_local(local, samples);
            let pm = Arc::new(Mutex::new(PathManager::new(PathConfig::default())));
            let link = Arc::new(Mutex::new(PathLink::new(pm.clone())));
            let sink: Arc<dyn PathEventSink> = Arc::new(StackSink {
                inner: weak.clone(),
            });
            let monitor = QualityMonitor::new(pm, sink);
            Self {
                punch,
                link,
                monitor,
            }
        });
        st.monitor.start();
        st
    }

    /// Punch-signaling relay: responder only, never races.
    fn register_punch_relay(&self, relay: &Arc<ConnShared>, peer: FabricPeerId) {
        self.punch.register_relay(relay, peer);
    }

    /// Production relay: racing candidate + probing at Active cadence.
    fn add_production_relay(
        &self,
        peer: FabricPeerId,
        relay: &Arc<ConnShared>,
        local: SocketAddr,
        remote: SocketAddr,
    ) {
        let name = peer_hex(&peer);
        self.link.lock().unwrap().register_nat_relay(
            &name,
            relay.clone(),
            PathKind::Turn,
            local,
            remote,
        );
        self.monitor.add_path(MeasuredPath {
            addr: remote,
            kind: PathKind::Turn,
            local_addr: local,
            cost: 5.0,
            transport: relay.clone(),
            role: ProbeRole::Active,
            forward: None,
        });
    }

    /// After a successful punch: direct joins the race (Backup cadence until
    /// it wins and the sink promotes it).
    fn add_direct(&self, peer: FabricPeerId, local: SocketAddr) {
        let name = peer_hex(&peer);
        if let Some(d) = self.punch.direct_conn(&peer) {
            println!("[e4] direct candidate registered for {name} at {}", d.addr);
            self.link
                .lock()
                .unwrap()
                .register_nat_direct(&name, d.conn.clone(), local, d.addr);
            self.monitor.add_path(MeasuredPath {
                addr: d.addr,
                kind: PathKind::Direct,
                local_addr: local,
                cost: 0.0,
                transport: d.conn,
                role: ProbeRole::Backup,
                forward: None,
            });
        }
    }

    fn active_conn(&self, peer: &FabricPeerId) -> Option<Arc<ConnShared>> {
        let link = self.link.lock().unwrap();
        let conns = link.nat_conns(&peer_hex(peer))?;
        Some(match conns.active {
            ActiveConn::Direct => conns.direct.clone()?,
            ActiveConn::Relay => conns.relay.clone(),
        })
    }

    fn active_is_direct(&self, peer: &FabricPeerId) -> bool {
        self.link.lock().unwrap().nat_active(&peer_hex(peer)) == Some(ActiveConn::Direct)
    }

    fn switch_count(&self) -> u64 {
        self.link.lock().unwrap().stats().path_active_switches
    }

    fn shutdown(&self) {
        self.monitor.shutdown();
    }
}

// ---------------------------------------------------------------------------
// Infra
// ---------------------------------------------------------------------------

const TURN_PORT: u16 = 3478;
const SIM_A_INT: u16 = 6001;
const SIM_B_INT: u16 = 6002;
const SIM_A_EXT: u16 = 5001;
const SIM_B_EXT: u16 = 5002;
const STUN1: u16 = 7001;
const STUN2: u16 = 7002;
const STUN3: u16 = 7003;

struct Ctx {
    node_a: Node,
    node_b: Node,
    relay_punch_a: Arc<ConnShared>,
    relay_punch_b: Arc<ConnShared>,
    relay_xfer_a: Arc<ConnShared>,
    relay_xfer_b: Arc<ConnShared>,
    ra: SocketAddr,
    rb: SocketAddr,
}

fn start_infra() -> SocketAddr {
    let turn = TurnServer::bind(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), TURN_PORT),
        TurnCredentials {
            username: "u".into(),
            password: "p".into(),
            realm: "nexus".into(),
        },
    )
    .expect("turn server bind");
    let turn_addr = turn.main_addr();
    std::mem::forget(turn);
    stun_helper(STUN1);
    stun_helper(STUN2);
    stun_helper(STUN3);
    thread::sleep(Duration::from_millis(50));
    let v4 = Ipv4Addr::LOCALHOST;
    let sim_a = Sim::new(SIM_A_INT, v4, SIM_A_EXT).expect("simA");
    let sim_b = Sim::new(SIM_B_INT, v4, SIM_B_EXT).expect("simB");
    let sa = sim_a.clone();
    let sb = sim_b.clone();
    thread::spawn(move || sa.run());
    thread::spawn(move || sb.run());
    turn_addr
}

fn setup(relay_delay: Duration, direct_delay: Duration) -> Ctx {
    let turn_addr = start_infra();
    let v4 = Ipv4Addr::LOCALHOST;
    let stun_helpers = vec![
        SocketAddr::new(IpAddr::V4(v4), STUN1),
        SocketAddr::new(IpAddr::V4(v4), STUN2),
        SocketAddr::new(IpAddr::V4(v4), STUN3),
    ];
    let cfg_a = NodeCfg {
        name: "A",
        sim_int: SocketAddr::new(IpAddr::V4(v4), SIM_A_INT),
        stun_helpers: stun_helpers.clone(),
        relay_delay,
        direct_delay,
    };
    let cfg_b = NodeCfg {
        name: "B",
        sim_int: SocketAddr::new(IpAddr::V4(v4), SIM_B_INT),
        stun_helpers,
        relay_delay,
        direct_delay,
    };
    let creds = || TurnCredentials {
        username: "u".into(),
        password: "p".into(),
        realm: "nexus".into(),
    };
    let ca = TurnClient::allocate(turn_addr, creds()).expect("A allocate");
    let cb = TurnClient::allocate(turn_addr, creds()).expect("B allocate");
    let ra = ca.relayed_addr();
    let rb = cb.relayed_addr();

    let node_a = build_node(&cfg_a, ca, rb).expect("build A");
    let node_b = build_node(&cfg_b, cb, ra).expect("build B");

    // Two relay conns: punch signaling + production transfer (same pattern
    // as e4_nat_punch S1; avoids stream-accept contention on one conn).
    let id_a = node_a.my_id;
    let id_b = node_b.my_id;
    let drv_b = node_b.driver.clone();
    let accept_h = thread::spawn(move || {
        let c1 = drv_b.accept_conn().expect("B relay accept 1");
        let c2 = drv_b.accept_conn().expect("B relay accept 2");
        (c1, c2)
    });
    thread::sleep(Duration::from_millis(100));
    let relay_punch_a = node_a
        .driver
        .connect(id_b, rb, Duration::from_secs(15))
        .expect("A punch relay connect");
    let relay_xfer_a = node_a
        .driver
        .connect(id_b, rb, Duration::from_secs(15))
        .expect("A xfer relay connect");
    let (relay_punch_b, relay_xfer_b) = accept_h.join().unwrap();
    let _ = (id_a, id_b);

    println!("[e4] relay up: A->B via TURN (punch + xfer conns)");
    Ctx {
        node_a,
        node_b,
        relay_punch_a,
        relay_punch_b,
        relay_xfer_a,
        relay_xfer_b,
        ra,
        rb,
    }
}

fn conn_open(conn: &Arc<ConnShared>) -> bool {
    conn.state
        .lock()
        .map(|s| s.closed.is_none())
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Transfer: chunked echo over the CURRENT active conn (production pattern)
// ---------------------------------------------------------------------------

const CHUNKS: usize = 700;
const CHUNK_SIZE: usize = 1024;
const PACE_MS: u64 = 25;

/// B side: echo loop on one conn. Detached; dies with the process.
fn spawn_echo(conn: Arc<ConnShared>, tag: &'static str) {
    thread::spawn(move || {
        loop {
            let s = match accept_stream_timeout(&conn, Duration::from_secs(60)) {
                Ok(s) => s,
                Err(_) => break,
            };
            match xfer_read(&s) {
                Ok(buf) => {
                    if xfer_write(&s, &buf).is_err() {
                        break;
                    }
                }
                Err(e) => {
                    eprintln!("[e4] echo {tag} read: {e}");
                    break;
                }
            }
        }
    });
}

/// B side: wait for the direct conn, then echo on it.
fn spawn_direct_echo(stack_b: Arc<Stack>, id_a: FabricPeerId) {
    thread::spawn(move || {
        let d = loop {
            if let Some(d) = stack_b.punch.direct_conn(&id_a) {
                break d;
            }
            thread::sleep(Duration::from_millis(200));
        };
        println!("[e4] B: direct conn available, echoing on it");
        spawn_echo(d.conn, "direct");
    });
}

struct XferStats {
    ok: bool,
    via_relay: usize,
    via_direct: usize,
}

/// A side: send CHUNKS chunks, each on the current active conn, verify echo.
/// Returns per-path chunk counts (proves the switch moved traffic).
fn run_transfer(stack_a: &Arc<Stack>, id_b: FabricPeerId, relay_id: u64) -> XferStats {
    let mut via_relay = 0usize;
    let mut via_direct = 0usize;
    for i in 0..CHUNKS {
        let conn = match stack_a.active_conn(&id_b) {
            Some(c) => c,
            None => {
                eprintln!("[e4] no active conn at chunk {i}");
                return XferStats {
                    ok: false,
                    via_relay,
                    via_direct,
                };
            }
        };
        let is_direct = conn.id.0 != relay_id;
        let s = match open_stream(&conn) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[e4] chunk {i} open_stream: {e}");
                return XferStats {
                    ok: false,
                    via_relay,
                    via_direct,
                };
            }
        };
        let mut payload = vec![0u8; CHUNK_SIZE];
        payload[..8].copy_from_slice(&(i as u64).to_be_bytes());
        for (j, b) in payload[8..].iter_mut().enumerate() {
            *b = ((i + j) % 251) as u8;
        }
        if xfer_write(&s, &payload).is_err() {
            eprintln!("[e4] chunk {i} write failed");
            return XferStats {
                ok: false,
                via_relay,
                via_direct,
            };
        }
        match xfer_read(&s) {
            Ok(echo) if echo == payload => {}
            _ => {
                eprintln!("[e4] chunk {i} echo mismatch");
                return XferStats {
                    ok: false,
                    via_relay,
                    via_direct,
                };
            }
        }
        finish_stream(&s);
        if is_direct {
            via_direct += 1;
        } else {
            via_relay += 1;
        }
        if i % 100 == 0 {
            println!(
                "[e4] chunk {i}/{CHUNKS} active_direct={} (relay={via_relay} direct={via_direct})",
                stack_a.active_is_direct(&id_b),
            );
        }
        thread::sleep(Duration::from_millis(PACE_MS));
    }
    XferStats {
        ok: true,
        via_relay,
        via_direct,
    }
}

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------

/// Wait for the punch's direct conn, then register it as a racing candidate.
/// Runs on a thread so registration happens DURING the transfer.
fn spawn_direct_registrar(stack: Arc<Stack>, peer: FabricPeerId, local: SocketAddr) {
    thread::spawn(move || {
        loop {
            if stack.punch.direct_conn(&peer).is_some() {
                break;
            }
            thread::sleep(Duration::from_millis(200));
        }
        // Let the other side's adoption settle.
        thread::sleep(Duration::from_secs(1));
        stack.add_direct(peer, local);
    });
}

/// S1: relay is slow (+40ms) -> direct wins the race -> traffic switches
/// mid-transfer; every byte verified; relay stays warm.
fn scenario_switch_to_direct() -> bool {
    println!("=== S1 switch-to-direct ===");
    let ctx = setup(Duration::from_millis(40), Duration::ZERO);
    let id_a = ctx.node_a.my_id;
    let id_b = ctx.node_b.my_id;

    let stack_a = Stack::new(&ctx.node_a);
    let stack_b = Stack::new(&ctx.node_b);

    // Punch signaling on the punch conns; production racing on the xfer conns.
    stack_a.register_punch_relay(&ctx.relay_punch_a, id_b);
    stack_b.register_punch_relay(&ctx.relay_punch_b, id_a);
    let local_a = *ctx.node_a.driver.shared().local_addr.lock().unwrap();
    let local_b = *ctx.node_b.driver.shared().local_addr.lock().unwrap();
    stack_a.add_production_relay(id_b, &ctx.relay_xfer_a, local_a, ctx.rb);
    stack_b.add_production_relay(id_a, &ctx.relay_xfer_b, local_b, ctx.ra);

    // B echoes on relay immediately; on direct once punched.
    spawn_echo(ctx.relay_xfer_b.clone(), "relay");
    spawn_direct_echo(stack_b.clone(), id_a);
    // Register direct candidates as soon as the punch lands (both sides).
    spawn_direct_registrar(stack_a.clone(), id_b, local_a);
    spawn_direct_registrar(stack_b.clone(), id_a, local_b);

    // Transfer starts on relay (direct doesn't exist yet).
    let relay_id = ctx.relay_xfer_a.id.0;
    let st_a = stack_a.clone();
    let xfer_h = thread::spawn(move || run_transfer(&st_a, id_b, relay_id));

    // Background punch (like NatSwitching::on_relay_connected auto_punch).
    thread::sleep(Duration::from_millis(500));
    let punch_a = stack_a.punch.clone();
    let relay_punch_a = ctx.relay_punch_a.clone();
    let punch_h = thread::spawn(move || {
        punch_a.punch_peer(
            &relay_punch_a,
            id_b,
            NatType::RestrictedCone,
            PunchConfig::default(),
        )
    });

    let punch_result = punch_h.join().unwrap();
    println!("[e4] S1 punch={punch_result:?}");
    let xfer = xfer_h.join().unwrap();
    // Let the race settle if the transfer ended first.
    thread::sleep(Duration::from_secs(4));

    let migrated = matches!(punch_result, PunchResult::Migrated { .. });
    let switched = stack_a.switch_count() >= 1;
    let relay_open = conn_open(&ctx.relay_xfer_a) && conn_open(&ctx.relay_xfer_b);
    println!(
        "[e4] S1 ok={} via_relay={} via_direct={} migrated={migrated} switched={switched} relay_open={relay_open}",
        xfer.ok, xfer.via_relay, xfer.via_direct,
    );
    let pass =
        xfer.ok && migrated && switched && xfer.via_relay > 0 && xfer.via_direct > 0 && relay_open;
    println!("S1 verdict: {}", if pass { "PASS" } else { "FAIL" });
    stack_a.shutdown();
    stack_b.shutdown();
    pass
}

/// S2: direct is slow (+30ms) -> punch still succeeds, but direct loses the
/// race -> all traffic stays on relay ("打洞成功≠最优").
fn scenario_direct_loses() -> bool {
    println!("=== S2 direct-loses ===");
    let ctx = setup(Duration::ZERO, Duration::from_millis(30));
    let id_a = ctx.node_a.my_id;
    let id_b = ctx.node_b.my_id;

    let stack_a = Stack::new(&ctx.node_a);
    let stack_b = Stack::new(&ctx.node_b);

    stack_a.register_punch_relay(&ctx.relay_punch_a, id_b);
    stack_b.register_punch_relay(&ctx.relay_punch_b, id_a);
    let local_a = *ctx.node_a.driver.shared().local_addr.lock().unwrap();
    let local_b = *ctx.node_b.driver.shared().local_addr.lock().unwrap();
    stack_a.add_production_relay(id_b, &ctx.relay_xfer_a, local_a, ctx.rb);
    stack_b.add_production_relay(id_a, &ctx.relay_xfer_b, local_b, ctx.ra);

    spawn_echo(ctx.relay_xfer_b.clone(), "relay");
    spawn_direct_echo(stack_b.clone(), id_a);
    spawn_direct_registrar(stack_a.clone(), id_b, local_a);
    spawn_direct_registrar(stack_b.clone(), id_a, local_b);

    let relay_id = ctx.relay_xfer_a.id.0;
    let st_a = stack_a.clone();
    let xfer_h = thread::spawn(move || run_transfer(&st_a, id_b, relay_id));

    thread::sleep(Duration::from_millis(500));
    let punch_a = stack_a.punch.clone();
    let relay_punch_a = ctx.relay_punch_a.clone();
    let punch_h = thread::spawn(move || {
        punch_a.punch_peer(
            &relay_punch_a,
            id_b,
            NatType::RestrictedCone,
            PunchConfig::default(),
        )
    });

    let punch_result = punch_h.join().unwrap();
    println!("[e4] S2 punch={punch_result:?}");
    let xfer = xfer_h.join().unwrap();
    // Let the race run long enough that a switch WOULD have happened.
    thread::sleep(Duration::from_secs(6));

    let migrated = matches!(punch_result, PunchResult::Migrated { .. });
    let switched = stack_a.switch_count() >= 1;
    let stayed_on_relay = !stack_a.active_is_direct(&id_b);
    println!(
        "[e4] S2 ok={} via_relay={} via_direct={} migrated={migrated} switched={switched} stayed_on_relay={stayed_on_relay}",
        xfer.ok, xfer.via_relay, xfer.via_direct,
    );
    let pass = xfer.ok && migrated && !switched && xfer.via_direct == 0 && stayed_on_relay;
    println!("S2 verdict: {}", if pass { "PASS" } else { "FAIL" });
    stack_a.shutdown();
    stack_b.shutdown();
    pass
}

fn main() {
    let arg = std::env::args().nth(1).unwrap_or_default();
    let ok = match arg.as_str() {
        "switch-to-direct" => scenario_switch_to_direct(),
        "direct-loses" => scenario_direct_loses(),
        _ => {
            eprintln!("usage: e4_prod_switch <switch-to-direct|direct-loses>");
            std::process::exit(2);
        }
    };
    thread::sleep(Duration::from_millis(300));
    std::process::exit(if ok { 0 } else { 1 });
}
