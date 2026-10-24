//! E4: end-to-end NAT punch-through wiring on a real machine.
//!
//! Single-process / multi-thread, all on 127.0.0.1. NAT semantics are
//! enforced by a userspace cone/symmetric NAT simulator per node (not by
//! netns), which is equally honest about hole semantics: unsolicited inbound
//! is dropped and counted.
//!
//! Layout per scenario:
//!   TURN server (3478) --+-- simA -- nodeA (driver: mux transport)
//!                         +-- simB -- nodeB (driver: mux transport)
//!   STUN helpers on 7001/7002 (echo observed source).
//!
//! Scenarios:
//!   relay-first   S1: TURN relay first, 256KB transfer, then A punches B;
//!                    asserts Migrated, uninterrupted transfer, tie-break,
//!                    relay stays open (warm backup), sim dropped > 0.
//!   symmetric     S2: both NATs symmetric-sequential; bounded spray; first
//!                    success wins; asserts Migrated + bounded attempts.
//!   unpredictable S3: symmetric-random; asserts fast StayedOnRelay and zero
//!                    punch attempts (no spray storm).
//!
//! Usage: e4_nat_punch <relay-first|symmetric|unpredictable>

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

use nexus_connectivity::nat::NatType;
use nexus_fabric::{Cmd, ConnShared, Driver, PeerId as FabricPeerId, StreamShared};
use nexus_nat_traversal::{PortSample, PunchConfig, PunchResult};
use nexus_nat_wireup::{
    PunchManager, accept_stream_timeout,
    channel::{read_exact_deadline, write_all_stream},
};
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
    // Canonicalize: enc_addr writes V4 as IPv6-mapped; map back so addresses
    // compare equal to the V4 SocketAddrs returned by recv_from (hole keys).
    let ip = match IpAddr::from(ipb) {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    };
    Some(SocketAddr::new(ip, port))
}

// ---------------------------------------------------------------------------
// Userspace NAT simulator (runs on the "public" side of each node)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq)]
enum SimMode {
    Restricted, // one fixed ext port; holes per contacted dst
    Seq,        // symmetric: sequential ports from a pre-bound range
    Rand,       // symmetric: random port per dst
}

/// Hole filtering semantics (RFC 4787 mapping/filtering are independent).
#[derive(Clone, Copy, PartialEq)]
enum FilterMode {
    /// (IP, port)-restricted: inbound source must exactly match a contacted dst.
    Strict,
    /// Address-restricted: inbound source IP must match a contacted dst IP.
    /// Real symmetric NATs exist with this combination (address-dependent
    /// mapping + address-restricted filtering); it is the honest model under
    /// which bounded port prediction can work.
    AddrOnly,
}

struct Sim {
    int_sock: UdpSocket,
    mode: SimMode,
    filter: FilterMode,
    ext_ip: Ipv4Addr,
    fixed_ext: u16,
    seq_base: u16,
    seq_len: u16,
    seq_next: Mutex<u16>,
    ext: Mutex<HashMap<u16, UdpSocket>>,
    map: Mutex<HashMap<SocketAddr, u16>>, // symmetric per-dst mapping
    holes: Mutex<HashMap<u16, HashSet<SocketAddr>>>,
    node: Mutex<Option<SocketAddr>>,
    drops: AtomicU64,
    forwards: AtomicU64,
}

impl Sim {
    fn new(
        int_port: u16,
        mode: SimMode,
        filter: FilterMode,
        ext_ip: Ipv4Addr,
        ext: u16,
        seq_base: u16,
        seq_len: u16,
    ) -> io::Result<Arc<Self>> {
        let int_sock = UdpSocket::bind(("127.0.0.1", int_port))?;
        int_sock.set_nonblocking(true)?;
        let sim = Arc::new(Self {
            int_sock,
            mode,
            filter,
            ext_ip,
            fixed_ext: ext,
            seq_base,
            seq_len,
            seq_next: Mutex::new(0),
            ext: Mutex::new(HashMap::new()),
            map: Mutex::new(HashMap::new()),
            holes: Mutex::new(HashMap::new()),
            node: Mutex::new(None),
            drops: AtomicU64::new(0),
            forwards: AtomicU64::new(0),
        });
        if mode == SimMode::Restricted {
            sim.bind_ext(ext)?;
        }
        Ok(sim)
    }

    fn bind_ext(&self, port: u16) -> io::Result<()> {
        let s = UdpSocket::bind((self.ext_ip, port))?;
        s.set_nonblocking(true)?;
        self.ext.lock().unwrap().insert(port, s);
        Ok(())
    }

    fn alloc_ext(&self, dst: SocketAddr) -> io::Result<u16> {
        match self.mode {
            SimMode::Restricted => {
                self.holes
                    .lock()
                    .unwrap()
                    .entry(self.fixed_ext)
                    .or_default()
                    .insert(dst);
                Ok(self.fixed_ext)
            }
            SimMode::Seq | SimMode::Rand => {
                if let Some(&p) = self.map.lock().unwrap().get(&dst) {
                    self.holes.lock().unwrap().entry(p).or_default().insert(dst);
                    return Ok(p);
                }
                let p = match self.mode {
                    SimMode::Seq => {
                        let mut n = self.seq_next.lock().unwrap();
                        let p = self.seq_base + (*n % self.seq_len);
                        *n += 1;
                        self.bind_ext(p)?;
                        p
                    }
                    _ => {
                        let s = UdpSocket::bind((self.ext_ip, 0))?;
                        s.set_nonblocking(true)?;
                        let p = s.local_addr()?.port();
                        self.ext.lock().unwrap().insert(p, s);
                        p
                    }
                };
                self.map.lock().unwrap().insert(dst, p);
                self.holes.lock().unwrap().entry(p).or_default().insert(dst);
                Ok(p)
            }
        }
    }

    fn handle_out(&self, pkt: &[u8]) {
        // [1][dst_ip16][dst_port2][payload]
        if pkt.len() < 19 || pkt[0] != 1 {
            return;
        }
        let Some(dst) = dec_addr(&pkt[1..19]) else {
            return;
        };
        let Ok(port) = self.alloc_ext(dst) else {
            return;
        };
        let s = self.ext.lock().unwrap().get(&port).map(|s| s.try_clone());
        if let Some(Ok(s)) = s {
            let _ = s.send_to(&pkt[19..], dst);
            self.forwards.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn handle_in(&self, port: u16, src: SocketAddr, pkt: &[u8]) {
        let allowed = self
            .holes
            .lock()
            .unwrap()
            .get(&port)
            .map(|h| match self.filter {
                FilterMode::Strict => h.contains(&src),
                FilterMode::AddrOnly => h.iter().any(|a| a.ip() == src.ip()),
            })
            .unwrap_or(false);
        if !allowed {
            self.drops.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let node = *self.node.lock().unwrap();
        if let Some(node) = node {
            let mut f = Vec::with_capacity(18 + pkt.len());
            enc_addr(src, &mut f);
            f.extend_from_slice(pkt);
            let _ = self.int_sock.send_to(&f, node);
            self.forwards.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn run(self: &Arc<Self>) {
        let mut buf = [0u8; 65536];
        loop {
            match self.int_sock.recv_from(&mut buf) {
                Ok((n, src)) => {
                    *self.node.lock().unwrap() = Some(src);
                    self.handle_out(&buf[..n]);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => break,
            }
            let socks: Vec<(u16, UdpSocket)> = self
                .ext
                .lock()
                .unwrap()
                .iter()
                .filter_map(|(&p, s)| s.try_clone().ok().map(|s| (p, s)))
                .collect();
            for (port, s) in socks {
                match s.recv_from(&mut buf) {
                    Ok((n, src)) => self.handle_in(port, src, &buf[..n]),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(_) => {}
                }
            }
            thread::sleep(Duration::from_millis(1));
        }
    }
}

// ---------------------------------------------------------------------------
// STUN echo helper: replies with the observed source address
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
// Mux transport: relay targets -> TURN; everything else -> sim (proxied)
// ---------------------------------------------------------------------------

struct MuxTransport {
    turn: TurnSocket,
    sim_link: UdpSocket,
    sim_int: SocketAddr,
    relay_targets: HashSet<SocketAddr>,
}

impl MuxTransport {
    fn new(
        turn: TurnSocket,
        sim_link: UdpSocket,
        sim_int: SocketAddr,
        relay_targets: HashSet<SocketAddr>,
    ) -> Self {
        sim_link.set_nonblocking(true).unwrap();
        Self {
            turn,
            sim_link,
            sim_int,
            relay_targets,
        }
    }
}

impl nexus_fabric::transport::UdpTransport for MuxTransport {
    fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        if self.relay_targets.contains(&target) {
            return self.turn.send_to(buf, target);
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

/// Length-prefixed write using the shared channel framing helpers.
fn xfer_write(s: &Arc<StreamShared>, data: &[u8]) -> io::Result<()> {
    let mut hdr = (data.len() as u32).to_be_bytes().to_vec();
    hdr.extend_from_slice(data);
    write_all_stream(s, &hdr)
}

fn xfer_read(s: &Arc<StreamShared>) -> io::Result<Vec<u8>> {
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut lenb = [0u8; 4];
    read_exact_deadline(s, &mut lenb, deadline)?;
    let len = u32::from_be_bytes(lenb) as usize;
    let mut buf = vec![0u8; len];
    read_exact_deadline(s, &mut buf, deadline)?;
    Ok(buf)
}

// Node assembly
// ---------------------------------------------------------------------------

struct Node {
    driver: Arc<Driver>,
    my_id: FabricPeerId,
    manager: Arc<PunchManager>,
}

struct NodeCfg {
    name: &'static str,
    sim_int: SocketAddr,
    nat_type: NatType,
    stun_helpers: Vec<SocketAddr>,
}

/// STUN sampling through the sim: returns (reflexive, samples).
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
                    // payload = [ip16][port2] of observed source
                    let payload = &buf[18..n];
                    if payload.len() >= 18 {
                        if let Some(obs) = dec_addr(payload) {
                            reflexive = Some(obs);
                            samples.push(PortSample {
                                port: obs.port(),
                                at_ms: 0,
                                target: "127.0.0.1:3478".parse().unwrap(),
                                observed_from: "0.0.0.0:0".parse().unwrap(),
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

    // STUN sampling with the same socket the mux will use.
    let sim_link = UdpSocket::bind(("127.0.0.1", 0))?;
    let (reflexive, mut samples) = stun_sample(&sim_link, cfg.sim_int, &cfg.stun_helpers)?;
    for (i, s) in samples.iter_mut().enumerate() {
        s.at_ms = (i as u64) * 100;
    }

    let turn_sock = TurnSocket::new(client);
    let mut relay_targets = HashSet::new();
    relay_targets.insert(peer_relayed);
    let mux = MuxTransport::new(turn_sock, sim_link, cfg.sim_int, relay_targets);
    let driver = Driver::new_server_with_transport(Box::new(mux))
        .map_err(|e| io::Error::other(format!("{}: driver: {e:?}", cfg.name)))?;
    let my_id = driver
        .shared()
        .peer_id
        .ok_or_else(|| io::Error::other("no peer id"))?;

    let manager = PunchManager::new(
        driver.clone(),
        my_id,
        std::sync::Arc::new(nexus_nat_wireup::SystemPunchClock::new()),
    );
    manager.set_local(
        nexus_nat_traversal::LocalCandidates {
            host: Vec::new(),
            srflx: Some(reflexive),
            srflx_stun: None,
            srflx_turn: None,
            nat_type: cfg.nat_type,
        },
        samples,
    );
    println!(
        "[e4] {}: relayed={relayed} reflexive={reflexive} id={}",
        cfg.name,
        hex8(&my_id.0)
    );
    Ok(Node {
        driver,
        my_id,
        manager,
    })
}

fn hex8(b: &[u8; 32]) -> String {
    b[..4].iter().map(|x| format!("{x:02x}")).collect()
}

fn conn_open(conn: &Arc<ConnShared>) -> bool {
    conn.state
        .lock()
        .map(|s| s.closed.is_none())
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------

const TURN_PORT: u16 = 3478;
const SIM_A_INT: u16 = 6001;
const SIM_B_INT: u16 = 6002;
const SIM_A_EXT: u16 = 5001;
const SIM_B_EXT: u16 = 5002;
const STUN1: u16 = 7001;
const STUN2: u16 = 7002;
const STUN3: u16 = 7003;

struct SimSpec {
    mode: SimMode,
    filter: FilterMode,
    ext_ip: Ipv4Addr,
    ext: u16,
    seq_base: u16,
    seq_len: u16,
}

fn start_infra(a: SimSpec, b: SimSpec) -> (SocketAddr, Arc<Sim>, Arc<Sim>) {
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
    std::mem::forget(turn); // server thread owns itself; runs for process life
    stun_helper(STUN1);
    stun_helper(STUN2);
    stun_helper(STUN3);
    thread::sleep(Duration::from_millis(50));
    let sim_a = Sim::new(
        SIM_A_INT, a.mode, a.filter, a.ext_ip, a.ext, a.seq_base, a.seq_len,
    )
    .expect("simA");
    let sim_b = Sim::new(
        SIM_B_INT, b.mode, b.filter, b.ext_ip, b.ext, b.seq_base, b.seq_len,
    )
    .expect("simB");
    let sa = sim_a.clone();
    let sb = sim_b.clone();
    thread::spawn(move || sa.run());
    thread::spawn(move || sb.run());
    (turn_addr, sim_a, sim_b)
}

struct Ctx {
    node_a: Node,
    node_b: Node,
    /// Relay conn dedicated to punch signaling (registered with PunchManager).
    relay_punch_a: Arc<ConnShared>,
    relay_punch_b: Arc<ConnShared>,
    /// Relay conn dedicated to the file transfer (unregistered; proves the
    /// relay data path is independent of punch signaling streams).
    relay_xfer_a: Arc<ConnShared>,
    relay_xfer_b: Arc<ConnShared>,
    sim_a: Arc<Sim>,
    sim_b: Arc<Sim>,
}

/// Build both nodes, connect relay A->B (A initiates), register responders.
fn setup(a: SimSpec, b: SimSpec, a_nat: NatType, b_nat: NatType) -> Ctx {
    let (turn_addr, sim_a, sim_b) = start_infra(a, b);
    // Three DISTINCT targets: symmetric NATs reuse the mapping per dst.
    let stun_helpers = vec![
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), STUN1),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), STUN2),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), STUN3),
    ];
    // Both allocate first so each knows the other's relayed addr.
    let cfg_a = NodeCfg {
        name: "A",
        sim_int: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), SIM_A_INT),
        nat_type: a_nat,
        stun_helpers: stun_helpers.clone(),
    };
    let cfg_b = NodeCfg {
        name: "B",
        sim_int: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), SIM_B_INT),
        nat_type: b_nat,
        stun_helpers,
    };
    // Allocate TURN first (need relayed addrs before permissions).
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

    // Relay: A initiates twice (punch signaling + transfer), B accepts twice.
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

    node_a.manager.register_relay(&relay_punch_a, id_b);
    node_b.manager.register_relay(&relay_punch_b, id_a);
    println!("[e4] relay up: A->B via TURN (punch + xfer conns)");
    Ctx {
        node_a,
        node_b,
        relay_punch_a,
        relay_punch_b,
        relay_xfer_a,
        relay_xfer_b,
        sim_a,
        sim_b,
    }
}

/// S1: relay-first, transfer during punch, tie-break, relay stays open.
fn scenario_relay_first() -> bool {
    println!("=== S1 relay-first ===");
    let v4 = Ipv4Addr::LOCALHOST;
    let ctx = setup(
        SimSpec {
            mode: SimMode::Restricted,
            filter: FilterMode::Strict,
            ext_ip: v4,
            ext: SIM_A_EXT,
            seq_base: 0,
            seq_len: 0,
        },
        SimSpec {
            mode: SimMode::Restricted,
            filter: FilterMode::Strict,
            ext_ip: v4,
            ext: SIM_B_EXT,
            seq_base: 0,
            seq_len: 0,
        },
        NatType::RestrictedCone,
        NatType::RestrictedCone,
    );

    // Proof that the hole is required: junk to B's reflexive before any
    // outbound must be dropped by sim B.
    let drops_before = ctx.sim_b.drops.load(Ordering::Relaxed);
    let junk = UdpSocket::bind(("127.0.0.1", 0)).unwrap();
    junk.send_to(b"junk", ("127.0.0.1", SIM_B_EXT)).unwrap();
    thread::sleep(Duration::from_millis(200));
    let drops_after = ctx.sim_b.drops.load(Ordering::Relaxed);
    let hole_proven = drops_after > drops_before;
    println!("[e4] unsolicited inbound dropped by sim: {hole_proven}");

    // 256KB transfer over the xfer relay conn, concurrent with punch on the
    // punch relay conn.
    let data: Vec<u8> = (0..262_144u32).map(|i| (i % 251) as u8).collect();
    let want_hash: u64 = data.iter().map(|&b| b as u64).sum();
    let relay_a = ctx.relay_xfer_a.clone();
    let relay_b = ctx.relay_xfer_b.clone();
    let tx_h = thread::spawn(move || -> bool {
        let s = match open_stream(&relay_a) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[e4] transfer open: {e}");
                return false;
            }
        };
        if xfer_write(&s, &data).is_err() {
            return false;
        }
        match xfer_read(&s) {
            Ok(echo) => echo.iter().map(|&b| b as u64).sum::<u64>() == want_hash,
            Err(e) => {
                eprintln!("[e4] transfer read echo: {e}");
                false
            }
        }
    });
    let echo_h = thread::spawn(move || -> bool {
        let s = match accept_stream_timeout(&relay_b, Duration::from_secs(20)) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[e4] transfer accept: {e}");
                return false;
            }
        };
        match xfer_read(&s) {
            Ok(buf) => xfer_write(&s, &buf).is_ok(),
            Err(e) => {
                eprintln!("[e4] transfer read: {e}");
                false
            }
        }
    });

    thread::sleep(Duration::from_millis(100));
    let id_b = ctx.node_b.my_id;
    let mgr_a = ctx.node_a.manager.clone();
    let relay_punch_a = ctx.relay_punch_a.clone();
    let punch_t0 = Instant::now();
    let punch_h = thread::spawn(move || {
        mgr_a.punch_peer(
            &relay_punch_a,
            id_b,
            NatType::RestrictedCone,
            PunchConfig::default(),
        )
    });

    let transfer_ok = tx_h.join().unwrap() && echo_h.join().unwrap();
    let result = punch_h.join().unwrap();
    let punch_ms = punch_t0.elapsed().as_millis();
    println!("[e4] S1 transfer_ok={transfer_ok} punch={result:?} ({punch_ms}ms)");

    let migrated = matches!(result, PunchResult::Migrated { .. });
    // Tie-break: the larger PeerId keeps its initiated conn; the other side
    // must have adopted the accepted conn.
    let a_wins = ctx.node_a.my_id.0 > ctx.node_b.my_id.0;
    // Give the loser time to adopt the accepted conn (resolve polls up to 2s).
    thread::sleep(Duration::from_secs(3));
    let da = ctx.node_a.manager.direct_conn(&ctx.node_b.my_id);
    let db = ctx.node_b.manager.direct_conn(&ctx.node_a.my_id);
    let tie_ok = match (a_wins, da.as_ref(), db.as_ref()) {
        (true, Some(a), Some(b)) => a.initiated_locally && !b.initiated_locally,
        (false, Some(a), Some(b)) => !a.initiated_locally && b.initiated_locally,
        _ => false,
    };
    println!(
        "[e4] a_wins={a_wins} da={:?} db={:?} tie_ok={tie_ok}",
        da.as_ref().map(|d| d.initiated_locally),
        db.as_ref().map(|d| d.initiated_locally)
    );

    // Direct conn must actually work: echo 64KB over it.
    let direct_ok = if let Some(d) = da {
        match open_stream(&d.conn) {
            Ok(s) => {
                let payload = vec![7u8; 65536];
                xfer_write(&s, &payload).is_ok()
            }
            Err(e) => {
                eprintln!("[e4] direct open_stream: {e}");
                false
            }
        }
    } else {
        false
    };

    // Relay stays open as warm backup (D4: never closed on migrate).
    let relay_open = conn_open(&ctx.relay_punch_a)
        && conn_open(&ctx.relay_punch_b)
        && conn_open(&ctx.relay_xfer_a)
        && conn_open(&ctx.relay_xfer_b);
    let feed_a = ctx.node_a.manager.feed().count_for(&ctx.node_b.my_id.0);
    println!("[e4] direct_ok={direct_ok} relay_open={relay_open} feed_a={feed_a}");

    let pass = transfer_ok && migrated && tie_ok && direct_ok && relay_open && hole_proven;
    println!(
        "[e4] sim_a drops={} forwards={} | sim_b drops={} forwards={}",
        ctx.sim_a.drops.load(Ordering::Relaxed),
        ctx.sim_a.forwards.load(Ordering::Relaxed),
        ctx.sim_b.drops.load(Ordering::Relaxed),
        ctx.sim_b.forwards.load(Ordering::Relaxed),
    );
    println!("S1 verdict: {}", if pass { "PASS" } else { "FAIL" });
    pass
}

/// S2: symmetric-sequential NATs; bounded spray; first success wins.
fn scenario_symmetric() -> bool {
    println!("=== S2 symmetric-seq ===");
    // Cone-symmetric (§4.3.1): A symmetric-seq base 5096 on 127.0.0.2,
    // B cone on 127.0.0.1:5100. A's spray [5095..5103] covers B's stable
    // 5100; B's spray [5084..5116] covers A's mapped response port 5104.
    // Different loopback IPs avoid bind conflicts. Address-restricted
    // filtering is the RFC 4787 legitimate combination that bounded
    // prediction assumes.
    let ctx = setup(
        SimSpec {
            mode: SimMode::Seq,
            filter: FilterMode::AddrOnly,
            ext_ip: Ipv4Addr::new(127, 0, 0, 2),
            ext: 0,
            seq_base: 5096,
            seq_len: 64,
        },
        SimSpec {
            mode: SimMode::Restricted,
            filter: FilterMode::AddrOnly,
            ext_ip: Ipv4Addr::LOCALHOST,
            ext: 5100,
            seq_base: 0,
            seq_len: 0,
        },
        NatType::Symmetric,
        NatType::RestrictedCone,
    );
    let cfg = PunchConfig {
        spray_k: 4, // 9 candidates; still exercises the spray path
        ..PunchConfig::default()
    };
    let id_b = ctx.node_b.my_id;
    let id_a = ctx.node_a.my_id;
    let mgr_a = ctx.node_a.manager.clone();
    let relay_a = ctx.relay_punch_a.clone();
    let t0 = Instant::now();
    let result = mgr_a.punch_peer(&relay_a, id_b, NatType::RestrictedCone, cfg);
    let ms = t0.elapsed().as_millis();
    let attempts_a = ctx.node_a.manager.punch_attempts(&id_b).unwrap_or(999);
    let attempts_b = ctx.node_b.manager.punch_attempts(&id_a).unwrap_or(999);
    println!("[e4] S2 punch={result:?} ({ms}ms) attempts_a={attempts_a} attempts_b={attempts_b}");
    let migrated = matches!(result, PunchResult::Migrated { .. });
    let bounded = attempts_a == 9 && attempts_b <= 33;
    let direct_ok = ctx
        .node_a
        .manager
        .direct_conn(&id_b)
        .map(|d| conn_open(&d.conn))
        .unwrap_or(false);
    let pass = migrated && bounded && direct_ok;
    println!("S2 verdict: {}", if pass { "PASS" } else { "FAIL" });
    pass
}

/// S3: symmetric-random NAT; must stay on relay quickly, zero attempts.
fn scenario_unpredictable() -> bool {
    println!("=== S3 symmetric-rand ===");
    let v4 = Ipv4Addr::LOCALHOST;
    let ctx = setup(
        SimSpec {
            mode: SimMode::Rand,
            filter: FilterMode::Strict,
            ext_ip: v4,
            ext: 0,
            seq_base: 0,
            seq_len: 0,
        },
        SimSpec {
            mode: SimMode::Restricted,
            filter: FilterMode::Strict,
            ext_ip: v4,
            ext: SIM_B_EXT,
            seq_base: 0,
            seq_len: 0,
        },
        NatType::Symmetric,
        NatType::RestrictedCone,
    );
    let id_b = ctx.node_b.my_id;
    let mgr_a = ctx.node_a.manager.clone();
    let relay_a = ctx.relay_punch_a.clone();
    let t0 = Instant::now();
    let result = mgr_a.punch_peer(
        &relay_a,
        id_b,
        NatType::RestrictedCone,
        PunchConfig::default(),
    );
    let ms = t0.elapsed().as_millis();
    let attempts = ctx.node_a.manager.punch_attempts(&id_b).unwrap_or(999);
    println!("[e4] S3 punch={result:?} ({ms}ms) attempts={attempts}");
    let stayed = matches!(
        result,
        PunchResult::StayedOnRelay {
            reason: nexus_nat_traversal::PunchFailReason::UnpredictableSymmetric
        }
    );
    let fast = ms < 3000;
    let no_storm = attempts == 0;
    let relay_ok = conn_open(&ctx.relay_punch_a) && conn_open(&ctx.relay_punch_b);
    let pass = stayed && fast && no_storm && relay_ok;
    println!("S3 verdict: {}", if pass { "PASS" } else { "FAIL" });
    pass
}

fn main() {
    let arg = std::env::args().nth(1).unwrap_or_default();
    let ok = match arg.as_str() {
        "relay-first" => scenario_relay_first(),
        "symmetric" => scenario_symmetric(),
        "unpredictable" => scenario_unpredictable(),
        _ => {
            eprintln!("usage: e4_nat_punch <relay-first|symmetric|unpredictable>");
            std::process::exit(2);
        }
    };
    // Let detached handshake-failure threads drain; then exit.
    thread::sleep(Duration::from_millis(300));
    std::process::exit(if ok { 0 } else { 1 });
}
