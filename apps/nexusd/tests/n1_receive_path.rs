//! WP7 receive-path acceptance evidence (spec §11.3 AC-N1-3/4/5/6/7).
//!
//! Everything here is `[P]` process evidence: loopback / MockTun / real
//! `FabricListener`/`FabricConn` through the production composition functions
//! (`assemble_n1_with_discovery` + `assemble_n1_runtime`). It can never close
//! the `[R]` ACs.
//!
//! The AC-N1-3 test deliberately does **not** call `inject_from_n1`,
//! `inject_stream_frame_from_n1`, `recv_datagram` or `TcpRelay::handle_frame`
//! from the harness: A's bytes enter through `MockTun` + `process_one` and B's
//! side is driven by the production inbound queue + `pump_n1_inbound` +
//! `n1_egress_poll` installed by `assemble_n1_runtime`.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use nexus_fabric::{ConnConfig, FabricConn, FabricIdentity};
use nexus_network::n1::N1PeerId;
use nexus_projection::tcp::{ip_checksum, tcp_checksum};
use nexus_projection::{MockTun, TunDevice};
use nexusd::config::N1Section;
use nexusd::dataplane::{Dataplane, DataplaneConfig, TcpRelayEgress};
use nexusd::mesh_peer_map::{MeshPeerResolver, StaticMeshPeerMap};
use nexusd::n1_runtime::assemble_n1_runtime;
use nexusd::n1_stats::{N1ListenerState, N1Stats, build_n1_status_json};
use nexusd::nat_chunk_stats::ChunkStats;

const SRC: [u8; 4] = [127, 0, 0, 1];
const SPORT: u16 = 40_000;
const SEG: usize = 1000;
const MIB: usize = 1024 * 1024;

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

struct SharedTun {
    inner: Arc<Mutex<MockTun>>,
}

impl TunDevice for SharedTun {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.lock().unwrap().read(buf)
    }
    fn write(&mut self, packet: &[u8]) -> io::Result<usize> {
        self.inner.lock().unwrap().write(packet)
    }
    fn name(&self) -> &str {
        "test0"
    }
}

fn mock_tun() -> (Box<dyn TunDevice>, Arc<Mutex<MockTun>>) {
    let mock = Arc::new(Mutex::new(MockTun::new("test0")));
    (
        Box::new(SharedTun {
            inner: Arc::clone(&mock),
        }),
        mock,
    )
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
    let mut pkt = vec![0u8; 20 + 20 + payload.len()];
    pkt[0] = 0x45;
    let tot = (20 + 20 + payload.len()) as u16;
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

fn hex32(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn identity(seed: u8) -> FabricIdentity {
    FabricIdentity::from_ed25519_seed([seed; 32]).expect("test identity")
}

fn route(subnet: &str, peer: N1PeerId) -> nexus_network::n1::pump::Ipv4Route {
    nexus_network::n1::pump::Ipv4Route {
        subnet: nexus_network::n1::pump::Ipv4Net::parse(subnet).expect("subnet"),
        peer,
    }
}

fn network_toml(me: &FabricIdentity, peer: &FabricIdentity, peer_addr: &str) -> String {
    format!(
        "peer_id = \"{}\"\n\
         [[peers]]\n\
         id = \"{}\"\n\
         addrs = [\"{peer_addr}\"]\n\
         [vpi]\n\
         interface = \"nexus0\"\n\
         address = \"10.200.0.1\"\n\
         mtu = 1200\n\
         [[vpi.routes]]\n\
         subnet = \"127.0.0.1/32\"\n\
         peer = \"{}\"\n",
        hex32(&me.peer_id().0),
        hex32(&peer.peer_id().0),
        hex32(&peer.peer_id().0),
    )
}

fn dataplane_config() -> DataplaneConfig {
    DataplaneConfig {
        mesh_cidrs: vec!["127.0.0.1/32".to_string()],
        n1_configured: true,
        ..Default::default()
    }
}

/// One node assembled exclusively through production functions.
struct Node {
    asm: nexusd::assembly::N1Assembly,
    accept: Option<std::thread::JoinHandle<()>>,
    rx: Option<std::thread::JoinHandle<()>>,
    stats: Arc<N1Stats>,
    listener_state: N1ListenerState,
    chunk_stats: Arc<ChunkStats>,
    peer: N1PeerId,
    dp: Option<Dataplane>,
    mock: Arc<Mutex<MockTun>>,
}

impl Node {
    /// Build assembly + runtime + dataplane for `seed`; `peer_addr` is the
    /// address this node would dial for `peer` (only the smaller id dials).
    fn new(
        seed: u8,
        peer_seed: u8,
        peer_addr: &str,
        shutdown: Arc<AtomicBool>,
    ) -> (Self, SocketAddr) {
        let me = identity(seed);
        let peer_identity = identity(peer_seed);
        let text = network_toml(&me, &peer_identity, peer_addr);
        let asm = nexusd::assembly::assemble_n1_with_discovery(
            &text,
            None,
            Arc::clone(&shutdown),
            nexus::network::DiscoveryParams::static_only(),
            Some(me),
        )
        .expect("assemble_n1_with_discovery");

        let section = N1Section {
            enabled: true,
            listen_addr: Some("127.0.0.1:0".to_string()),
        };
        let handles = assemble_n1_runtime(&asm, &section, Some(identity(seed)), shutdown);
        let addr = match &handles.listener_state {
            N1ListenerState::Listening { addr } => *addr,
            other => panic!("expected listening, got {other:?}"),
        };

        let (tun, mock) = mock_tun();
        let mut dp = Dataplane::new(tun, dataplane_config(), None).expect("dataplane new");
        dp.set_default_simple_engine().expect("default engine");
        dp.set_n1_sender(asm.bridge.clone());
        let peer = N1PeerId(peer_identity.peer_id().0);
        let peers: Arc<dyn MeshPeerResolver> = Arc::new(StaticMeshPeerMap::from_routes(&[route(
            "127.0.0.1/32",
            peer,
        )]));
        dp.set_mesh_peer_resolver(peers);
        dp.set_n1_inbound_rx(handles.inbound_rx);
        dp.set_n1_stats(Arc::clone(&handles.stats));
        dp.set_n1_relay(Box::new(TcpRelayEgress::new(Arc::clone(&handles.stats))));
        let chunk_stats = Arc::new(ChunkStats::default());
        dp.set_chunk_stats(Arc::clone(&chunk_stats));

        (
            Self {
                asm,
                accept: handles.accept,
                rx: handles.rx,
                stats: handles.stats,
                listener_state: handles.listener_state,
                chunk_stats,
                peer,
                dp: Some(dp),
                mock,
            },
            addr,
        )
    }

    fn take_dp(&mut self) -> Dataplane {
        self.dp.take().expect("dataplane already taken")
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        if let Some(handle) = self.accept.take() {
            let _ = handle.join();
        }
        if let Some(handle) = self.rx.take() {
            let _ = handle.join();
        }
    }
}

struct Fixture {
    shutdown: Arc<AtomicBool>,
    /// Smaller id: dials. Larger id: listens only (tie-break, spec §5.1).
    a: Node,
    b: Node,
    b_loop: Option<std::thread::JoinHandle<()>>,
}

impl Fixture {
    fn new() -> Self {
        // Find seeds such that `a` (dialer) has the smaller id.
        let mut a_seed = 0x81u8;
        let mut b_seed = 0x82u8;
        loop {
            let a = identity(a_seed);
            let b = identity(b_seed);
            if a.peer_id().0 < b.peer_id().0 {
                break;
            }
            std::mem::swap(&mut a_seed, &mut b_seed);
        }
        let shutdown = Arc::new(AtomicBool::new(false));

        // B listens first so A's network.toml can carry the real address.
        let (mut b, b_addr) = Node::new(b_seed, a_seed, "127.0.0.1:1", Arc::clone(&shutdown));
        let (a, _a_addr) = Node::new(a_seed, b_seed, &b_addr.to_string(), Arc::clone(&shutdown));

        let a_peer = N1PeerId(identity(a_seed).peer_id().0);
        let b_peer = N1PeerId(identity(b_seed).peer_id().0);

        // Production mTLS dial (A -> B) must complete before traffic starts.
        let deadline = Instant::now() + Duration::from_secs(15);
        while a.asm.sessions.connection_for(&b_peer).is_none()
            || b.asm.sessions.connection_for(&a_peer).is_none()
        {
            assert!(
                Instant::now() < deadline,
                "N1 session never established (tie-break/mTLS)"
            );
            std::thread::sleep(Duration::from_millis(10));
        }

        // B's dataplane runs the production pump/poll loop.
        let mut dp_b = b.take_dp();
        let loop_shutdown = Arc::clone(&shutdown);
        let b_loop = std::thread::Builder::new()
            .name("wp7-b-dataplane".to_string())
            .spawn(move || {
                while !loop_shutdown.load(Ordering::SeqCst) {
                    dp_b.pump_n1_inbound();
                    dp_b.n1_egress_poll();
                    let _ = dp_b.process_one();
                    std::thread::sleep(Duration::from_millis(1));
                }
            })
            .expect("spawn B dataplane loop");

        Self {
            shutdown,
            a,
            b,
            b_loop: Some(b_loop),
        }
    }

    /// Drive one 1MiB TCP upload from A's MockTun to a local receiver on B.
    /// Returns (received bytes, sha256 hex).
    fn transfer(&mut self, sport: u16, total: usize) -> (Vec<u8>, String) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("receiver bind");
        let port = listener.local_addr().expect("receiver addr").port();
        let (tx, rx) = mpsc::channel();
        let recv = std::thread::Builder::new()
            .name("wp7-local-receiver".to_string())
            .spawn(move || {
                let (mut stream, _) = listener.accept().expect("local accept");
                // Greeting gives the relay a first-evidence event (connect_ok)
                // and proves the egress connect completed before bulk data.
                stream.write_all(b"R").expect("greeting");
                let mut got = Vec::with_capacity(total);
                let mut buf = [0u8; 8192];
                while got.len() < total {
                    let n = stream.read(&mut buf).expect("local read");
                    if n == 0 {
                        break;
                    }
                    got.extend_from_slice(&buf[..n]);
                }
                let _ = tx.send(got);
            })
            .expect("spawn local receiver");

        let connect_ok_before = self.b.stats.snapshot().egress_connect_ok;
        let srv_seq = self.handshake(port, sport);

        let deadline = Instant::now() + Duration::from_secs(10);
        while self.b.stats.snapshot().egress_connect_ok == connect_ok_before {
            assert!(
                Instant::now() < deadline,
                "egress relay never connected to the local receiver: {:?}",
                self.b.stats.snapshot()
            );
            std::thread::sleep(Duration::from_millis(5));
        }

        let mut input = Vec::with_capacity(total);
        let mut seq = 1001u32;
        let mut sent = 0usize;
        while sent < total {
            let n = SEG.min(total - sent);
            let payload: Vec<u8> = (0..n).map(|i| ((sent + i) % 251) as u8).collect();
            input.extend_from_slice(&payload);
            let before = self.b.stats.snapshot().rx_datagrams;
            self.send_data(seq, srv_seq, &payload, sport, port);
            seq += n as u32;
            sent += n;
            // Pace on the production rx counter so the QUIC datagram queue
            // stays bounded (a dropped datagram would fail the SHA oracle).
            let deadline = Instant::now() + Duration::from_secs(5);
            while self.b.stats.snapshot().rx_datagrams == before {
                assert!(
                    Instant::now() < deadline,
                    "N1 datagram {sent}/{total} never reached the rx reader"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
            // Let A consume any reply datagrams (originator-side path).
            self.pump_a();
        }

        let got = rx
            .recv_timeout(Duration::from_secs(60))
            .expect("local receiver did not finish within 60s");
        recv.join().expect("receiver thread");
        assert_eq!(got.len(), total, "receiver got a short stream");
        let sha = sha256_hex(&got);
        (got, sha)
    }

    fn handshake(&mut self, port: u16, sport: u16) -> u32 {
        // Discard any packets left over from an earlier transfer (e.g. the
        // relay greeting that was injected into A's terminator).
        let _ = self.a.mock.lock().unwrap().take_written();
        let syn = craft_tcp(SRC, SRC, sport, port, 1000, 0, 0x02, &[]);
        let dp = self.a.dp.as_mut().expect("A dataplane");
        self.a.mock.lock().unwrap().inject(syn);
        assert!(dp.process_one().expect("A SYN"));
        let written = self.a.mock.lock().unwrap().take_written();
        let synack = written
            .iter()
            .find(|p| p.len() >= 40 && p[33] & 0x12 == 0x12)
            .expect("expected SYN-ACK on A's TUN");
        let srv_seq = u32::from_be_bytes([synack[24], synack[25], synack[26], synack[27]]);
        // Complete the handshake: `TcpEvent::Syn` (and therefore the STREAM
        // SYN frame to the peer) is emitted on the ACK, not on the SYN.
        let ack = craft_tcp(SRC, SRC, sport, port, 1001, srv_seq + 1, 0x10, &[]);
        let dp = self.a.dp.as_mut().expect("A dataplane");
        self.a.mock.lock().unwrap().inject(ack);
        assert!(dp.process_one().expect("A ACK"));
        srv_seq
    }

    fn send_data(&mut self, seq: u32, srv_seq: u32, payload: &[u8], sport: u16, port: u16) {
        let pkt = craft_tcp(SRC, SRC, sport, port, seq, srv_seq + 1, 0x18, payload);
        let dp = self.a.dp.as_mut().expect("A dataplane");
        self.a.mock.lock().unwrap().inject(pkt);
        assert!(dp.process_one().expect("A DATA"));
    }

    fn pump_a(&mut self) {
        let dp = self.a.dp.as_mut().expect("A dataplane");
        dp.pump_n1_inbound();
        dp.n1_egress_poll();
    }

    fn stop(mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(handle) = self.b_loop.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Never let a panicking assertion leave the production threads
        // running forever (accept/rx joins happen in `Node::drop`).
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(handle) = self.b_loop.take() {
            let _ = handle.join();
        }
    }
}

// ---------------------------------------------------------------------------
// AC-N1-3 + AC-N1-6 (enabled side): production assembly, 1MiB, SHA equal.
// ---------------------------------------------------------------------------

#[test]
fn production_assembly_carries_1mib_to_the_egress_relay_with_equal_sha() {
    let mut fx = Fixture::new();

    let (got, got_sha) = fx.transfer(SPORT, MIB);
    let input: Vec<u8> = (0..MIB).map(|i| (i % 251) as u8).collect();
    let a_sha = sha256_hex(&input);
    eprintln!("AC_N1_3 a_sha={a_sha} b_sha={got_sha} bytes={}", got.len());
    assert_eq!(got_sha, a_sha, "1MiB SHA-256 must be equal");
    assert_eq!(got.len(), MIB);

    let b = fx.b.stats.snapshot();
    assert!(b.rx_stream_frames > 0, "B rx.stream_frames > 0: {b:?}");
    assert!(b.dispatch_to_relay > 0, "B dispatch.to_relay > 0: {b:?}");
    assert!(
        b.egress_bytes_to_local >= MIB as u64,
        "B egress.bytes_to_local >= 1MiB: {b:?}"
    );
    assert_eq!(b.egress_connect_failed, 0, "no egress connect failure");
    assert_eq!(b.rx_rejected, 0, "no inbound rejection");
    assert_eq!(b.dispatch_bad_frame, 0, "no bad frame");
    assert_eq!(b.dispatch_unknown_stream, 0, "no unknown stream");
    assert_eq!(b.tx_errors, 0, "no reply tx error");

    let a_chunks = fx.a.chunk_stats.snapshot();
    assert_eq!(a_chunks.fallback_errors, 0, "A fallback_errors == 0");
    assert!(a_chunks.fallback_chunks > 0, "A used the N1 fallback");
    let a_stats = fx.a.dp.as_ref().expect("A dataplane").stats();
    assert!(a_stats.mesh_tcp_frames > 0, "A sent STREAM frames over N1");
    eprintln!(
        "AC_N1_3 b_stats={b:?} a_chunks={a_chunks:?} a_mesh_frames={}",
        a_stats.mesh_tcp_frames
    );

    // AC-N1-6 enabled side: the JSON shape/values come from the same
    // `assemble_n1_runtime` handles that production `run_daemon` publishes.
    let json = build_n1_status_json(fx.b.listener_state.clone(), b, 1);
    assert_eq!(json["runtime"], "enabled");
    assert_eq!(json["listener"]["state"], "listening");
    assert_eq!(
        json["listener"]["addr"],
        fx.b.listener_state_addr().to_string()
    );
    assert!(json["rx"]["stream_frames"].as_u64().unwrap() > 0);
    assert!(json["dispatch"]["to_relay"].as_u64().unwrap() > 0);
    assert!(json["egress"]["bytes_to_local"].as_u64().unwrap() >= MIB as u64);
    assert_eq!(json["egress"]["connect_failed"], 0);
    assert!(json.get("delivered").is_none());
    assert!(json.get("acked").is_none());

    fx.stop();
}

impl Node {
    fn listener_state_addr(&self) -> SocketAddr {
        match self.listener_state {
            N1ListenerState::Listening { addr } => addr,
            ref other => panic!("not listening: {other:?}"),
        }
    }
}

// ---------------------------------------------------------------------------
// AC-N1-4: no `[network.n1]` -> no listener/rx logs, daemon stays up.
// ---------------------------------------------------------------------------

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path =
            std::env::temp_dir().join(format!("nexusd-wp7-{tag}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&path).expect("create temp dir");
        Self(path)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_tcp_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn free_udp_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn write_seed(dir: &Path, seed_byte: u8) -> PathBuf {
    let seed = dir.join("seed.hex");
    std::fs::write(&seed, format!("{seed_byte:02x}").repeat(32)).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&seed, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    seed
}

fn write_network(dir: &Path, me: &FabricIdentity, peer: Option<&FabricIdentity>) {
    let mut text = format!(
        "peer_id = \"{}\"\n\
         [vpi]\n\
         interface = \"nexus0\"\n\
         address = \"10.200.0.1\"\n\
         mtu = 1200\n",
        hex32(&me.peer_id().0)
    );
    if let Some(peer) = peer {
        text = format!(
            "peer_id = \"{}\"\n\
             [[peers]]\n\
             id = \"{}\"\n\
             addrs = [\"127.0.0.1:1\"]\n\
             [vpi]\n\
             interface = \"nexus0\"\n\
             address = \"10.200.0.1\"\n\
             mtu = 1200\n",
            hex32(&me.peer_id().0),
            hex32(&peer.peer_id().0),
        );
    }
    std::fs::write(dir.join("network.toml"), text).unwrap();
}

fn write_localapi(dir: &Path, api_addr: SocketAddr) {
    let token = dir.join("localapi.token");
    std::fs::write(&token, "a".repeat(64)).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    std::fs::write(
        dir.join("daemon.toml"),
        format!(
            "[tun]\n\
             enabled = false\n\
             [localapi]\n\
             addr = \"{api_addr}\"\n"
        ),
    )
    .unwrap();
}

fn spawn_daemon(dir: &Path) -> (Daemon, mpsc::Receiver<String>) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_nexusd"))
        .arg(dir)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn nexusd");
    let stderr = child.stderr.take().expect("stderr piped");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    (Daemon(child), rx)
}

#[test]
fn disabled_daemon_emits_no_n1_runtime_logs_and_stays_up() {
    let dir = TempDir::new("disabled");
    let me = identity(0x91);
    write_network(dir.path(), &me, None);
    write_localapi(
        dir.path(),
        SocketAddr::from((Ipv4Addr::LOCALHOST, free_tcp_port())),
    );

    let (_daemon, rx) = spawn_daemon(dir.path());
    let mut captured = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(line) => captured.push(line),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    let disabled = captured
        .iter()
        .filter(|l| l.as_str() == "[n1-listener] listener disabled reason=no_listen_addr")
        .count();
    assert_eq!(
        disabled, 1,
        "exactly one disabled line; captured:\n{captured:#?}"
    );
    for prefix in [
        "[n1-listener] listening",
        "[n1-listener] accepted",
        "[n1-listen]",
        "[n1-rx]",
        "[n1-egress]",
        "[n1-dial]",
    ] {
        assert!(
            !captured.iter().any(|l| l.starts_with(prefix)),
            "disabled runtime must not emit {prefix}; captured:\n{captured:#?}"
        );
    }
    // The process is still alive after the observation window.
    assert!(
        captured
            .iter()
            .any(|l| l.contains("dataplane") || l.contains("tun"))
    );
}

// ---------------------------------------------------------------------------
// AC-N1-7: mTLS admission (allowlisted accepted, unlisted rejected + §19 line).
// ---------------------------------------------------------------------------

#[test]
fn admission_accepts_allowlisted_and_rejects_unlisted_with_the_spec_log_line() {
    const REJECTION_LINE: &str =
        "[n1-listen] tls handshake rejected (peer unauthenticated or protocol error)";

    let dir = TempDir::new("admission");
    let server = identity(0x5a);
    let allowed = identity(0x5b);
    let stranger = identity(0x5c);
    let seed = write_seed(dir.path(), 0x5a);
    write_network(dir.path(), &server, Some(&allowed));
    let n1_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, free_udp_port()));
    let api_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, free_tcp_port()));
    std::fs::write(
        dir.path().join("daemon.toml"),
        format!(
            "[tun]\n\
             enabled = false\n\
             [localapi]\n\
             addr = \"{api_addr}\"\n\
             [network.identity]\n\
             seed_file = \"{}\"\n\
             [network.n1]\n\
             enabled = true\n\
             listen_addr = \"{n1_addr}\"\n",
            seed.display()
        ),
    )
    .unwrap();

    let (_daemon, rx) = spawn_daemon(dir.path());
    let mut captured = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let line = rx
            .recv_timeout(left)
            .unwrap_or_else(|_| panic!("listener never came up; captured:\n{captured:#?}"));
        let listening = line.starts_with("[n1-listener] listening addr=");
        captured.push(line);
        if listening {
            break;
        }
    }

    let cfg = ConnConfig {
        addrs: vec![n1_addr],
        handshake_timeout: Duration::from_millis(1000),
    };
    let conn = FabricConn::connect_mtls(server.peer_id(), &allowed, &cfg)
        .expect("allowlisted peer must complete mTLS");
    assert_eq!(
        conn.mutually_authenticated_peer(),
        Some(server.peer_id()),
        "the accepted connection carries the verified server identity"
    );
    conn.send_datagram(b"wp7-admission-ok")
        .expect("allowlisted peer can send datagrams");
    conn.close(0, b"done");

    assert!(
        FabricConn::connect_mtls(server.peer_id(), &stranger, &cfg).is_err(),
        "unlisted identity must not complete the mTLS handshake"
    );

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let line = rx
            .recv_timeout(left)
            .unwrap_or_else(|_| panic!("rejection line missing; captured:\n{captured:#?}"));
        let matched = line == REJECTION_LINE;
        captured.push(line);
        if matched {
            break;
        }
    }
    assert_eq!(
        captured.last().map(String::as_str),
        Some(REJECTION_LINE),
        "the §19 sentence must appear verbatim on the real daemon stderr"
    );
    if let Ok(path) = std::env::var("NEXUSD_N1_WP7_ADMISSION_CAPTURE") {
        std::fs::write(&path, format!("{}\n", captured.join("\n"))).unwrap();
    }
}

// ---------------------------------------------------------------------------
// AC-N1-5: reconnect. The child performs the scenario and prints measurements;
// the parent re-runs it as a subprocess so the `[n1-dial]` log lines can be
// counted from real stderr (libtest would otherwise swallow them).
// ---------------------------------------------------------------------------

#[test]
fn reconnect_recovers_within_bounds_and_retransmits_1mib() {
    let exe = std::env::current_exe().expect("current test binary");
    let output = Command::new(exe)
        .args([
            "--exact",
            "reconnect_child_scenario",
            "--ignored",
            "--nocapture",
        ])
        .env("N1_WP7_RECONNECT_CHILD", "1")
        .output()
        .expect("spawn reconnect child");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "reconnect child failed:\n{stderr}\n{}",
        String::from_utf8_lossy(&output.stdout)
    );
    for marker in [
        "WP7_CHILD remove_ms=",
        "WP7_CHILD redial_ms=",
        "WP7_CHILD sha_equal=true",
        "WP7_CHILD cpu_pct=",
    ] {
        assert!(
            stderr.contains(marker),
            "missing child marker {marker}:\n{stderr}"
        );
    }
    let dial_lines = stderr
        .lines()
        .filter(|l| l.starts_with("[n1-dial]"))
        .count();
    assert!(dial_lines >= 1, "expected at least one [n1-dial] line");
    assert!(
        dial_lines <= 120,
        "AC-N1-5: [n1-dial] lines in the 60s recovery window must be <=120, got {dial_lines}"
    );
}

#[test]
#[ignore = "spawned by reconnect_recovers_within_bounds_and_retransmits_1mib"]
fn reconnect_child_scenario() {
    if std::env::var("N1_WP7_RECONNECT_CHILD").is_err() {
        return;
    }
    let mut fx = Fixture::new();

    let (_, sha1) = fx.transfer(SPORT, MIB);
    let input: Vec<u8> = (0..MIB).map(|i| (i % 251) as u8).collect();
    let want = sha256_hex(&input);
    assert_eq!(sha1, want, "first 1MiB transfer SHA");

    let a_peer = fx.b.peer; // A's id as stored on B's side
    let b_peer = fx.a.peer; // B's id as stored on A's side
    let old =
        fx.b.asm
            .sessions
            .connection_for(&a_peer)
            .expect("B holds A's accepted conn");
    let old_id = old.connection_id();
    old.close();

    // reader removes the session within <=1s.
    let start = Instant::now();
    let deadline = start + Duration::from_secs(1);
    while fx.b.asm.sessions.connection_for(&a_peer).is_some() {
        assert!(
            Instant::now() < deadline,
            "B reader did not remove the closed session within 1s"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    let remove_ms = start.elapsed().as_millis();
    eprintln!("WP7_CHILD remove_ms={remove_ms}");

    // A's reader also observes the close; the dialer redials within <=30s.
    let start = Instant::now();
    let deadline = start + Duration::from_secs(30);
    loop {
        if let Some(conn) = fx.a.asm.sessions.connection_for(&b_peer) {
            if conn.connection_id() != old_id && fx.b.asm.sessions.connection_for(&a_peer).is_some()
            {
                break;
            }
        }
        assert!(
            Instant::now() < deadline,
            "dialer did not re-establish the N1 session within 30s"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let redial_ms = start.elapsed().as_millis();
    eprintln!("WP7_CHILD redial_ms={redial_ms}");

    let (_, sha2) = fx.transfer(SPORT + 1, MIB);
    let sha_equal = sha2 == want;
    eprintln!("WP7_CHILD sha_equal={sha_equal}");
    assert!(sha_equal, "post-reconnect 1MiB transfer SHA");

    // AC-N1-5: 60s recovery window. Sample rx/supervisor CPU from /proc.
    let before = n1_rx_thread_cpu_ticks();
    std::thread::sleep(Duration::from_secs(60));
    let after = n1_rx_thread_cpu_ticks();
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) }.max(1) as f64;
    let cpu_pct = (after.saturating_sub(before) as f64) / (hz * 60.0) * 100.0;
    eprintln!("WP7_CHILD cpu_pct={cpu_pct:.3}");
    assert!(
        cpu_pct < 5.0,
        "AC-N1-5: rx/supervisor CPU mean must be <5%, got {cpu_pct:.3}%"
    );

    fx.stop();
}

fn n1_rx_thread_cpu_ticks() -> u64 {
    let mut total = 0u64;
    let Ok(entries) = std::fs::read_dir("/proc/self/task") else {
        return total;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let comm = match std::fs::read_to_string(path.join("comm")) {
            Ok(c) => c,
            Err(_) => continue,
        };
        if !comm.trim_start().starts_with("nexusd-n1-rx") {
            continue;
        }
        let stat = match std::fs::read_to_string(path.join("stat")) {
            Ok(s) => s,
            Err(_) => continue,
        };
        // Fields after the parenthesised comm: state is field 3; utime/stime
        // are fields 14/15 (1-based).
        let Some(rest) = stat.rsplit_once(')').map(|(_, r)| r) else {
            continue;
        };
        let fields: Vec<&str> = rest.split_whitespace().collect();
        if fields.len() < 13 {
            continue;
        }
        let utime = fields[11].parse::<u64>().unwrap_or(0);
        let stime = fields[12].parse::<u64>().unwrap_or(0);
        total += utime + stime;
    }
    total
}

// ---------------------------------------------------------------------------
// SHA-256 (test-local; no new dependency)
// ---------------------------------------------------------------------------

fn sha256_hex(data: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut msg = data.to_vec();
    let bit_len = (data.len() as u64) * 8;
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for block in msg.chunks(64) {
        let mut w = [0u32; 64];
        for (i, c) in block.chunks(4).enumerate() {
            w[i] = u32::from_be_bytes([c[0], c[1], c[2], c[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    h.iter().map(|x| format!("{x:08x}")).collect()
}

// Keep `IpAddr` imported for the route helper's type surface.
#[allow(dead_code)]
fn _ip_addr_marker(ip: IpAddr) -> IpAddr {
    ip
}
