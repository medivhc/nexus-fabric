//! P0 NAT chunk wiring tests (§3.3.8 items 1–9 + the 7b 150-stream regression).
//!
//! All of this is `[P]` process evidence: loopback / fake providers / unit
//! assertions. It can never close AC-C-1; only the `[R]` dual-node window can.

use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nexus_fabric::{ConnShared, Driver, PeerId as FabricPeerId};
use nexus_nat_traversal::PunchClock;
use nexus_nat_wireup::{PunchPeerStatus, PunchState};
use nexus_projection::tcp::{decode_stream_frame, encode_stream_frame, ip_checksum, tcp_checksum};
use nexus_projection::{MockTun, TunDevice};
use nexusd::dataplane::DataplaneConfig;
use nexusd::mesh_peer_map::{MeshPeerResolver, StaticMeshPeerMap};
use nexusd::nat_chunk_recv::{self, DirectGate, NAT_INBOUND_QUEUE_CAP, NatChunkRecvError};
use nexusd::nat_chunk_stats::{ChunkStats, ChunkStatsSnapshot, build_chunk_status_json};
use nexusd::nat_consumer::{NatActiveConn, NatHandleSlot, NatPathProvider};
use nexusd::nat_switch::ChunkPath;

const SRC: [u8; 4] = [10, 200, 0, 2];
const DST: [u8; 4] = [10, 200, 0, 5];
const SPORT: u16 = 40_000;
const DPORT: u16 = 80;

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

type CapturedFrames = Arc<Mutex<Vec<(IpAddr, Vec<u8>)>>>;

struct TestN1Sender {
    frames: CapturedFrames,
}

impl nexus_network::n1::bridge::N1Sender for TestN1Sender {
    fn send_to_mesh(&self, dst: IpAddr, packet: &[u8]) -> Result<(), nexus_network::n1::N1Error> {
        self.frames.lock().unwrap().push((dst, packet.to_vec()));
        Ok(())
    }
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

fn dataplane_with(
    slot: Option<NatHandleSlot>,
    peers: Option<Arc<dyn MeshPeerResolver>>,
    gate: Option<Arc<DirectGate>>,
    stats: Arc<ChunkStats>,
) -> (
    nexusd::dataplane::Dataplane,
    Arc<Mutex<MockTun>>,
    CapturedFrames,
) {
    let mock = Arc::new(Mutex::new(MockTun::new("test0")));
    let tun = Box::new(SharedTun {
        inner: Arc::clone(&mock),
    });
    let config = DataplaneConfig {
        mesh_cidrs: vec!["10.200.0.0/24".to_string()],
        n1_configured: true,
        ..Default::default()
    };
    let mut dp = nexusd::dataplane::Dataplane::new(tun, config, None).expect("dataplane new");
    dp.set_default_simple_engine().expect("default engine");
    let frames: CapturedFrames = Arc::new(Mutex::new(Vec::new()));
    dp.set_n1_sender(Arc::new(TestN1Sender {
        frames: Arc::clone(&frames),
    }));
    if let Some(slot) = slot {
        dp.set_nat_path_slot(slot);
    }
    if let Some(peers) = peers {
        dp.set_mesh_peer_resolver(peers);
    }
    if let Some(gate) = gate {
        dp.set_direct_gate(gate);
    }
    dp.set_chunk_stats(stats);
    (dp, mock, frames)
}

/// SYN → SYN-ACK → ACK; returns the server sequence number.
fn handshake(dp: &mut nexusd::dataplane::Dataplane, mock: &Arc<Mutex<MockTun>>) -> u32 {
    let syn = craft_tcp(SRC, DST, SPORT, DPORT, 1000, 0, 0x02, &[]);
    mock.lock().unwrap().inject(syn);
    assert!(dp.process_one().expect("syn"));
    let written: VecDeque<Vec<u8>> = mock.lock().unwrap().take_written().into_iter().collect();
    assert!(!written.is_empty(), "expected SYN-ACK");
    u32::from_be_bytes([
        written[0][24],
        written[0][25],
        written[0][26],
        written[0][27],
    ])
}

fn send_data(
    dp: &mut nexusd::dataplane::Dataplane,
    mock: &Arc<Mutex<MockTun>>,
    seq: u32,
    srv_seq: u32,
    payload: &[u8],
) {
    let pkt = craft_tcp(SRC, DST, SPORT, DPORT, seq, srv_seq + 1, 0x18, payload);
    mock.lock().unwrap().inject(pkt);
    assert!(dp.process_one().expect("data"));
}

fn route(subnet: &str, peer: FabricPeerId) -> nexus_network::n1::pump::Ipv4Route {
    nexus_network::n1::pump::Ipv4Route {
        subnet: nexus_network::n1::pump::Ipv4Net::parse(subnet).expect("subnet"),
        peer: nexus_network::n1::N1PeerId(peer.0),
    }
}

fn status(peer: FabricPeerId, state: PunchState, last_success_ms: Option<u64>) -> PunchPeerStatus {
    PunchPeerStatus {
        peer,
        phase: Default::default(),
        state,
        last_result: None,
        fail_reason: None,
        last_attempt_ms: None,
        last_success_ms,
        attempts_total: 0,
        migrated_total: 0,
        failed_timeout_total: 0,
        failed_unpredictable_total: 0,
        failed_no_candidates_total: 0,
        failed_channel_closed_total: 0,
        spray_sends_total: 0,
        spray_skipped_total: 0,
        mapping_probe_sends_total: 0,
        prediction_hints_sent_total: 0,
        prediction_hints_recv_total: 0,
        signal_decode_errors_total: 0,
        turn_mapped_loopback: false,
        last_direct_addr: None,
        direct_conn_id: None,
        nat_type_local: nexus_domain::nat::NatType::Unknown,
        nat_type_remote: nexus_domain::nat::NatType::Unknown,
        tunnel_proto: Default::default(),
        relay_source: None,
    }
}

struct GateClock(AtomicU64);
impl GateClock {
    fn new(t: u64) -> Arc<Self> {
        Arc::new(Self(AtomicU64::new(t)))
    }
}
impl PunchClock for GateClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
    fn wall_ms(&self) -> u64 {
        self.now_ms()
    }
    fn sleep_until_ms(&self, _deadline_ms: u64) {}
    fn sleep_ms(&self, _ms: u64) {}
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Return `Ok(Direct)` and record the chunk.
    Direct,
    /// Call the fallback with the KIND-prefixed argument, return `Ok(Fallback)`.
    Fallback,
    /// Return an error (never call fallback).
    Error,
    /// Open a real fabric stream, write, FIN (mirrors `NatSwitching::send_chunk`).
    Real,
}

struct FakeProvider {
    mode: Mode,
    peer: FabricPeerId,
    chunks: Mutex<Vec<Vec<u8>>>,
    send_conn: Option<Arc<ConnShared>>,
    recv_conn: Option<Arc<ConnShared>>,
}

impl FakeProvider {
    fn new(mode: Mode, peer: FabricPeerId) -> Arc<Self> {
        Arc::new(Self {
            mode,
            peer,
            chunks: Mutex::new(Vec::new()),
            send_conn: None,
            recv_conn: None,
        })
    }

    fn with_conns(
        mode: Mode,
        peer: FabricPeerId,
        send_conn: Arc<ConnShared>,
        recv_conn: Arc<ConnShared>,
    ) -> Arc<Self> {
        Arc::new(Self {
            mode,
            peer,
            chunks: Mutex::new(Vec::new()),
            send_conn: Some(send_conn),
            recv_conn: Some(recv_conn),
        })
    }
}

impl NatPathProvider for FakeProvider {
    fn active_conn(&self, _peer_hex: &str) -> Option<NatActiveConn> {
        self.recv_conn.clone().map(NatActiveConn::Direct)
    }

    fn send_chunk(
        &self,
        _peer: FabricPeerId,
        fallback: &dyn Fn(&[u8]) -> std::io::Result<()>,
        chunk: &[u8],
    ) -> std::io::Result<ChunkPath> {
        self.chunks.lock().unwrap().push(chunk.to_vec());
        match self.mode {
            Mode::Direct => Ok(ChunkPath::Direct),
            Mode::Fallback => {
                fallback(chunk)?;
                Ok(ChunkPath::Fallback)
            }
            Mode::Error => Err(io::Error::other("synthetic direct failure")),
            Mode::Real => {
                let Some(conn) = &self.send_conn else {
                    return Err(io::Error::other("no conn"));
                };
                let stream =
                    nexus_nat_wireup::channel::open_bi_stream(conn, Duration::from_secs(5))?;
                nexus_nat_wireup::channel::write_msg(
                    &stream,
                    nexus_nat_wireup::channel::STREAM_TYPE_WORKSPACE_SYNC,
                    chunk,
                )?;
                // Same FIN as the N-1 patch.
                {
                    let mut st = stream
                        .state
                        .lock()
                        .map_err(|_| io::Error::other("stream lock poisoned"))?;
                    st.send_fin = true;
                }
                let _ = stream.tx.send(nexus_fabric::Cmd::Pump {
                    conn: stream.conn_id,
                });
                Ok(ChunkPath::Direct)
            }
        }
    }

    fn peer_statuses(&self) -> Vec<PunchPeerStatus> {
        vec![status(self.peer, PunchState::Succeeded, Some(0))]
    }

    fn path_active_switches(&self) -> u64 {
        0
    }
}

fn conn_pair() -> (Arc<Driver>, Arc<Driver>, Arc<ConnShared>, Arc<ConnShared>) {
    let server = Driver::new_server("127.0.0.1:0".parse().unwrap()).expect("server driver");
    let addr = *server.shared().local_addr.lock().unwrap();
    let server_peer = server.shared().peer_id.expect("server peer id");
    let client = Driver::new_client().expect("client driver");
    let client_conn = client
        .connect(server_peer, addr, Duration::from_secs(5))
        .expect("connect");
    let server_conn = server.accept_conn().expect("accept");
    (client, server, client_conn, server_conn)
}

fn open_gate(peer: FabricPeerId) -> Arc<DirectGate> {
    // now=40000ms, last_success=0ms → both gates open (>=32000).
    let _ = peer;
    Arc::new(DirectGate::new(GateClock::new(40_000)))
}

// ---------------------------------------------------------------------------
// 1. StaticMeshPeerMap
// ---------------------------------------------------------------------------

#[test]
fn peer_map_longest_prefix_and_miss() {
    let a = FabricPeerId([0x11; 32]);
    let b = FabricPeerId([0x22; 32]);
    let map =
        StaticMeshPeerMap::from_routes(&[route("10.200.0.0/16", a), route("10.200.0.5/32", b)]);
    assert_eq!(map.peer_for(Ipv4Addr::new(10, 200, 0, 5)), Some(b));
    assert_eq!(map.peer_for(Ipv4Addr::new(10, 200, 9, 9)), Some(a));
    assert_eq!(map.peer_for(Ipv4Addr::new(192, 0, 2, 1)), None);
    assert_eq!(
        StaticMeshPeerMap::from_toml(None).peer_for(Ipv4Addr::new(10, 200, 0, 5)),
        None
    );
}

// ---------------------------------------------------------------------------
// 2. Dataplane + fake provider: Direct / Fallback / Err
// ---------------------------------------------------------------------------

#[test]
fn dataplane_direct_records_kind_prefixed_chunk() {
    let peer = FabricPeerId([0x21; 32]);
    let stats = Arc::new(ChunkStats::default());
    let provider = FakeProvider::new(Mode::Direct, peer);
    let slot = NatHandleSlot::new();
    slot.set(provider.clone());
    let gate = open_gate(peer);
    let peers: Arc<dyn MeshPeerResolver> = Arc::new(StaticMeshPeerMap::from_routes(&[route(
        "10.200.0.0/24",
        peer,
    )]));
    let (mut dp, mock, frames) =
        dataplane_with(Some(slot), Some(peers), Some(gate), Arc::clone(&stats));
    let srv = handshake(&mut dp, &mock);
    send_data(&mut dp, &mock, 1001, srv, b"hello");

    let chunks = provider.chunks.lock().unwrap();
    assert_eq!(chunks.len(), 1, "one chunk attempted");
    assert_eq!(chunks[0][0], 0x01, "KIND prefix present");
    let (sid, flags, payload) = decode_stream_frame(&chunks[0][1..]).expect("frame");
    assert_eq!(flags, 0x00);
    assert_eq!(payload, b"hello");
    let _ = sid;

    let snap = stats.snapshot();
    assert_eq!(snap.direct_attempts, 1);
    assert_eq!(snap.direct_attempt_bytes, 1 + 5 + 5);
    assert_eq!(snap.fallback_chunks, 0);
    // N1 saw only the SYN frame — no DATA frame leaked.
    let data_frames = frames
        .lock()
        .unwrap()
        .iter()
        .filter(|(_, f)| decode_stream_frame(f).map(|(_, fl, _)| fl) == Some(0x00))
        .count();
    assert_eq!(data_frames, 0);
}

#[test]
fn dataplane_fallback_sends_original_frame_without_kind() {
    let peer = FabricPeerId([0x22; 32]);
    let stats = Arc::new(ChunkStats::default());
    let provider = FakeProvider::new(Mode::Fallback, peer);
    let slot = NatHandleSlot::new();
    slot.set(provider.clone());
    let gate = open_gate(peer);
    let peers: Arc<dyn MeshPeerResolver> = Arc::new(StaticMeshPeerMap::from_routes(&[route(
        "10.200.0.0/24",
        peer,
    )]));
    let (mut dp, mock, frames) =
        dataplane_with(Some(slot), Some(peers), Some(gate), Arc::clone(&stats));
    let srv = handshake(&mut dp, &mock);
    send_data(&mut dp, &mock, 1001, srv, b"hello");

    // The provider received the KIND-wrapped chunk ...
    let chunks = provider.chunks.lock().unwrap();
    assert_eq!(chunks[0][0], 0x01);

    // ... but N1 received the raw STREAM frame (5-byte header + payload).
    let captured = frames.lock().unwrap();
    let data: Vec<&Vec<u8>> = captured
        .iter()
        .map(|(_, f)| f)
        .filter(|f| decode_stream_frame(f).map(|(_, fl, _)| fl) == Some(0x00))
        .collect();
    assert_eq!(data.len(), 1);
    assert_eq!(data[0].len(), 5 + 5, "no extra KIND byte on N1");
    let (_, _, payload) = decode_stream_frame(data[0]).expect("decode");
    assert_eq!(payload, b"hello");

    let snap = stats.snapshot();
    assert_eq!(snap.fallback_chunks, 1);
    assert_eq!(snap.fallback_bytes, 5 + 5);
    assert_eq!(snap.direct_attempts, 0);
}

#[test]
fn dataplane_direct_error_is_not_disguised_as_fallback() {
    let peer = FabricPeerId([0x23; 32]);
    let stats = Arc::new(ChunkStats::default());
    let provider = FakeProvider::new(Mode::Error, peer);
    let slot = NatHandleSlot::new();
    slot.set(provider.clone());
    let gate = open_gate(peer);
    let peers: Arc<dyn MeshPeerResolver> = Arc::new(StaticMeshPeerMap::from_routes(&[route(
        "10.200.0.0/24",
        peer,
    )]));
    let (mut dp, mock, frames) =
        dataplane_with(Some(slot), Some(peers), Some(gate), Arc::clone(&stats));
    let srv = handshake(&mut dp, &mock);
    send_data(&mut dp, &mock, 1001, srv, b"hello");

    let snap = stats.snapshot();
    assert_eq!(snap.direct_errors, 1);
    assert_eq!(snap.fallback_chunks, 0);
    assert_eq!(snap.direct_attempts, 0);
    let data_frames = frames
        .lock()
        .unwrap()
        .iter()
        .filter(|(_, f)| decode_stream_frame(f).map(|(_, fl, _)| fl) == Some(0x00))
        .count();
    assert_eq!(data_frames, 0, "drop-on-error: no retry, no fake fallback");
}

// ---------------------------------------------------------------------------
// 3+6. Counters and JSON
// ---------------------------------------------------------------------------

#[test]
fn chunk_stats_lossless_invariant() {
    let s = ChunkStats::default();
    for _ in 0..7 {
        s.record_direct_attempt(101);
        s.record_recv(100);
    }
    let snap = s.snapshot();
    assert_eq!(snap.direct_attempts, 7);
    assert_eq!(
        snap.direct_attempt_bytes,
        snap.recv_bytes + snap.direct_attempts
    );
    assert_eq!(snap.recv_chunks, snap.direct_attempts);
}

#[test]
fn chunk_status_json_exact() {
    let s = ChunkStats::default();
    for _ in 0..3 {
        s.record_direct_attempt(100);
    }
    for _ in 0..2 {
        s.record_fallback(80, nexusd::nat_chunk_stats::FallbackReason::NoDirect);
    }
    s.record_direct_error(50);
    let v = build_chunk_status_json(true, 4, s.snapshot(), 99);
    assert_eq!(v["runtime"], "enabled");
    assert_eq!(v["chunks"]["direct_attempts"], 3);
    assert_eq!(v["chunks"]["fallback_chunks"], 2);
    assert_eq!(v["chunks"]["direct_errors"], 1);
    assert_eq!(v["path"]["path_active_switches"], 4);

    let disabled = build_chunk_status_json(false, 0, ChunkStatsSnapshot::default(), 1);
    assert_eq!(disabled["runtime"], "disabled");
    assert_eq!(disabled["chunks"]["direct_attempts"], 0);
    assert!(disabled["chunks"].get("delivered").is_none());
    assert!(disabled["chunks"].get("acked").is_none());
}

// ---------------------------------------------------------------------------
// 4. Gate boundaries (fake clock)
// ---------------------------------------------------------------------------

#[test]
fn gate_boundaries_and_per_peer() {
    let peer = FabricPeerId([0x31; 32]);
    let other = FabricPeerId([0x32; 32]);
    let provider = FakeProvider::new(Mode::Direct, peer);
    // FakeProvider only reports `peer`; use a second provider for per-peer.
    let clock = GateClock::new(29_999);
    let gate = Arc::new(DirectGate::new(clock.clone()));
    assert!(!gate.receiver_ready(provider.as_ref(), &peer));
    clock.0.store(30_000, Ordering::SeqCst);
    assert!(gate.receiver_ready(provider.as_ref(), &peer));
    clock.0.store(31_999, Ordering::SeqCst);
    assert!(!gate.sender_allowed(provider.as_ref(), &peer));
    clock.0.store(32_000, Ordering::SeqCst);
    assert!(gate.sender_allowed(provider.as_ref(), &peer));
    assert!(!gate.sender_allowed(provider.as_ref(), &other));
}

// ---------------------------------------------------------------------------
// 5. parse/map error variants
// ---------------------------------------------------------------------------

#[test]
fn parse_and_map_error_variants() {
    assert_eq!(
        nat_chunk_recv::parse_chunk_payload(&[]),
        Err(NatChunkRecvError::UnexpectedEof)
    );
    assert_eq!(
        nat_chunk_recv::parse_chunk_payload(&[0x02, 1, 2, 3, 4]),
        Err(NatChunkRecvError::KindMismatch { got: 0x02 })
    );
    assert_eq!(
        nat_chunk_recv::parse_chunk_payload(&[0x01]),
        Err(NatChunkRecvError::UnexpectedEof)
    );
    assert_eq!(
        nat_chunk_recv::parse_chunk_payload(&[0x01, 9, 9]).unwrap(),
        &[9, 9]
    );

    assert_eq!(
        nat_chunk_recv::map_io_recv_error(io::Error::new(io::ErrorKind::TimedOut, "t")),
        NatChunkRecvError::Timeout
    );
    assert_eq!(
        nat_chunk_recv::map_io_recv_error(io::Error::new(io::ErrorKind::UnexpectedEof, "e")),
        NatChunkRecvError::UnexpectedEof
    );
    assert_eq!(
        nat_chunk_recv::map_io_recv_error(io::Error::new(io::ErrorKind::InvalidData, "d")),
        NatChunkRecvError::BadLength { len: 0 }
    );
    assert_eq!(
        nat_chunk_recv::map_io_recv_error(io::Error::other("poisoned")),
        NatChunkRecvError::Poisoned
    );
}

#[test]
fn read_chunk_frame_rejects_zero_and_oversized_lengths() {
    let (_client, _server, client_conn, server_conn) = conn_pair();
    let deadline = std::time::Instant::now() + Duration::from_secs(2);

    let stream = nexus_nat_wireup::channel::open_bi_stream(&client_conn, Duration::from_secs(2))
        .expect("open");
    nexus_nat_wireup::channel::write_all_stream(&stream, &[0x03, 0, 0, 0, 0]).expect("write");
    let accepted = nexus_nat_wireup::accept_stream_timeout(&server_conn, Duration::from_secs(2))
        .expect("accept");
    assert_eq!(
        nat_chunk_recv::read_chunk_frame(&accepted, deadline),
        Err(NatChunkRecvError::BadLength { len: 0 })
    );

    let stream = nexus_nat_wireup::channel::open_bi_stream(&client_conn, Duration::from_secs(2))
        .expect("open");
    let oversized = (nexus_nat_wireup::channel::MAX_FRAME as u32 + 1).to_be_bytes();
    let mut hdr = vec![0x03];
    hdr.extend_from_slice(&oversized);
    nexus_nat_wireup::channel::write_all_stream(&stream, &hdr).expect("write");
    let accepted = nexus_nat_wireup::accept_stream_timeout(&server_conn, Duration::from_secs(2))
        .expect("accept");
    assert_eq!(
        nat_chunk_recv::read_chunk_frame(&accepted, deadline),
        Err(NatChunkRecvError::FrameTooLarge {
            len: nexus_nat_wireup::channel::MAX_FRAME + 1
        })
    );
}

#[test]
fn all_rejection_variants_count_except_accept_closed() {
    let s = ChunkStats::default();
    let variants = [
        NatChunkRecvError::TypeMismatch { got: 1 },
        NatChunkRecvError::KindMismatch { got: 2 },
        NatChunkRecvError::BadLength { len: 0 },
        NatChunkRecvError::FrameTooLarge { len: 70000 },
        NatChunkRecvError::UnexpectedEof,
        NatChunkRecvError::Timeout,
        NatChunkRecvError::InjectionFull,
        NatChunkRecvError::InjectionClosed,
        NatChunkRecvError::Poisoned,
    ];
    for v in variants {
        let before = s.snapshot().recv_rejected;
        s.record_recv_rejected(v);
        assert_eq!(s.snapshot().recv_rejected, before + 1, "variant {v:?}");
    }
    let before = s.snapshot().recv_rejected;
    s.record_recv_rejected(NatChunkRecvError::AcceptClosed);
    assert_eq!(s.snapshot().recv_rejected, before);
}

// ---------------------------------------------------------------------------
// 7. Loopback 1MiB over a real fabric conn (process evidence only)
// ---------------------------------------------------------------------------

#[test]
fn loopback_1mib_chunk_pipeline_sha_matches() {
    let (_client_driver, _server_driver, client_conn, server_conn) = conn_pair();
    let peer = FabricPeerId([0x41; 32]);
    let stats = Arc::new(ChunkStats::default());
    let provider = FakeProvider::with_conns(Mode::Real, peer, client_conn, server_conn);
    let slot = NatHandleSlot::new();
    slot.set(provider.clone());
    let gate = open_gate(peer);
    let peers: Arc<dyn MeshPeerResolver> = Arc::new(StaticMeshPeerMap::from_routes(&[route(
        "10.200.0.0/24",
        peer,
    )]));
    let (mut dp, mock, _frames) = dataplane_with(
        Some(slot.clone()),
        Some(peers),
        Some(gate.clone()),
        Arc::clone(&stats),
    );

    let (tx, rx) = std::sync::mpsc::sync_channel(NAT_INBOUND_QUEUE_CAP);
    let shutdown = Arc::new(AtomicBool::new(false));
    let handle = nat_chunk_recv::spawn_nat_chunk_receiver(
        slot,
        gate,
        tx,
        Arc::clone(&stats),
        Arc::clone(&shutdown),
    )
    .expect("spawn receiver");
    // Let the supervisor start the acceptor.
    std::thread::sleep(Duration::from_millis(800));

    let srv = handshake(&mut dp, &mock);

    const TOTAL: usize = 1024 * 1024;
    const SEG: usize = 1200;
    let mut input = Vec::with_capacity(TOTAL);
    let mut seq = 1001u32;
    let mut sent = 0usize;
    while sent < TOTAL {
        let n = SEG.min(TOTAL - sent);
        let payload: Vec<u8> = (0..n).map(|i| ((sent + i) % 251) as u8).collect();
        input.extend_from_slice(&payload);
        let before = stats.snapshot().recv_chunks;
        send_data(&mut dp, &mock, seq, srv, &payload);
        seq += n as u32;
        sent += n;
        // Pace: wait for the receiver to take this chunk (keeps the number of
        // concurrent direct streams near 1; the 150-stream test covers quota).
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while stats.snapshot().recv_chunks == before && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    let mut got = Vec::new();
    while let Ok(chunk) = rx.recv_timeout(Duration::from_millis(500)) {
        let (_, flags, payload) = decode_stream_frame(&chunk.stream_frame).expect("frame");
        assert_eq!(flags, 0x00, "only DATA frames are chunked");
        got.extend_from_slice(payload);
    }

    shutdown.store(true, Ordering::SeqCst);
    let _ = handle.join();

    assert_eq!(got.len(), input.len(), "1MiB reassembled");
    assert_eq!(sha256_hex(&got), sha256_hex(&input), "1MiB SHA-256 equal");

    let snap = stats.snapshot();
    assert!(snap.direct_attempts > 0, "chunks went direct");
    assert_eq!(snap.fallback_chunks, 0);
    assert_eq!(snap.direct_errors, 0);
    assert_eq!(snap.recv_rejected, 0);
    assert_eq!(snap.recv_chunks, snap.direct_attempts);
    assert_eq!(
        snap.direct_attempt_bytes,
        snap.recv_bytes + snap.direct_attempts
    );
}

// ---------------------------------------------------------------------------
// 7b. Single conn, serial >=150 chunks (F-001 quota regression)
// ---------------------------------------------------------------------------

#[test]
fn single_conn_serial_150_chunks_all_direct() {
    let (_client_driver, _server_driver, client_conn, server_conn) = conn_pair();
    let peer = FabricPeerId([0x42; 32]);
    let stats = Arc::new(ChunkStats::default());
    let provider = FakeProvider::with_conns(Mode::Real, peer, client_conn, server_conn);
    let slot = NatHandleSlot::new();
    slot.set(provider.clone());
    let gate = open_gate(peer);
    let (tx, rx) = std::sync::mpsc::sync_channel(NAT_INBOUND_QUEUE_CAP);
    let shutdown = Arc::new(AtomicBool::new(false));
    let handle = nat_chunk_recv::spawn_nat_chunk_receiver(
        slot,
        gate,
        tx,
        Arc::clone(&stats),
        Arc::clone(&shutdown),
    )
    .expect("spawn receiver");
    std::thread::sleep(Duration::from_millis(800));

    for i in 0..150u32 {
        let mut chunk = vec![0x01u8];
        chunk.extend_from_slice(&encode_stream_frame(
            i,
            0x00,
            format!("serial-chunk-{i}").as_bytes(),
        ));
        let result = provider.send_chunk(peer, &|_| Ok(()), &chunk);
        assert_eq!(result.expect("direct send"), ChunkPath::Direct, "chunk {i}");
        stats.record_direct_attempt(chunk.len());
        // Strictly serial: wait until the receiver has accepted this chunk.
        rx.recv_timeout(Duration::from_secs(2))
            .unwrap_or_else(|_| panic!("chunk {i} not received"));
    }

    let snap = stats.snapshot();
    assert!(snap.direct_attempts >= 150, "got {}", snap.direct_attempts);
    assert_eq!(snap.direct_errors, 0);
    assert_eq!(snap.recv_chunks, snap.direct_attempts);

    shutdown.store(true, Ordering::SeqCst);
    let _ = handle.join();
}

// ---------------------------------------------------------------------------
// 9. Counterexample: no direct path → N1 bytes equal the baseline fixture
// ---------------------------------------------------------------------------

#[test]
fn no_direct_fallback_matches_golden_fixture() {
    let stats = Arc::new(ChunkStats::default());
    let (mut dp, mock, frames) = dataplane_with(None, None, None, Arc::clone(&stats));
    let srv = handshake(&mut dp, &mock);

    let payloads: Vec<Vec<u8>> = vec![
        b"hello".to_vec(),
        (0u8..17).collect(),
        (0u8..=255).cycle().take(300).collect(),
        (0u8..=255).cycle().take(1200).collect(),
        b"final7!".to_vec(),
    ];
    let mut seq = 1001u32;
    for p in &payloads {
        send_data(&mut dp, &mock, seq, srv, p);
        seq += p.len() as u32;
    }
    let fin = craft_tcp(SRC, DST, SPORT, DPORT, seq, srv + 1, 0x11, &[]);
    mock.lock().unwrap().inject(fin);
    assert!(dp.process_one().expect("fin"));

    // `stream_id` is randomly seeded per TcpTerminator instance, so the
    // reproducible fixture hashes `flags || payload` per frame (see
    // golden-fixture-baseline.txt).
    let mut normalized = Vec::new();
    {
        let captured = frames.lock().unwrap();
        assert_eq!(captured.len(), 7, "frame count must match the baseline");
        for (_, frame) in captured.iter() {
            let (_, flags, payload) = decode_stream_frame(frame).expect("decode");
            normalized.push(flags);
            normalized.extend_from_slice(payload);
        }
    }
    assert_eq!(normalized.len(), 1543);
    assert_eq!(
        sha256_hex(&normalized),
        "aa0c6c24c5bae35e20287ecdcb09084c94bd5891ffe0499d848e6937d3f07abd",
        "AC-H-2/AC-C-4: baseline N1 sequence must be unchanged"
    );

    let snap = stats.snapshot();
    assert_eq!(snap.fallback_chunks, 5, "one per DATA frame");
    assert_eq!(snap.fallback_no_peer, 5, "no route map configured");
    assert_eq!(snap.direct_attempts, 0);
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
