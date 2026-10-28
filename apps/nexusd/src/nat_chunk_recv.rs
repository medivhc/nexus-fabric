//! Direct-path admission gate and (in the receiver commit) the direct chunk
//! stream acceptor.
//!
//! The 30s quiet period exists because the direct connection's accept queue is
//! owned for 30s by the tie-break winner's bind responder; non-BIND streams are
//! peeked and dropped during that window. Senders wait 32s (30s + 2s margin)
//! and receivers only start accepting once the same 30s has elapsed. Both gates
//! are derived from the *same* monotonic `PunchClock` that feeds
//! `last_success_ms`, so the comparison is meaningful.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use nexus_fabric::{PeerId as FabricPeerId, StreamShared};
use nexus_nat_traversal::PunchClock;
use nexus_nat_wireup::{PunchPeerStatus, PunchState};

use crate::nat_chunk_stats::ChunkStats;
use crate::nat_consumer::{NatActiveConn, NatHandleSlot, NatPathProvider};

/// Chunk payload prefix: distinguishes the TUN STREAM frame from other users of
/// the `WORKSPACE_SYNC` (0x03) stream type. Never appears on the N1 fallback.
pub const CHUNK_KIND_TUN_STREAM: u8 = 0x01;

/// One accepted direct chunk, already stripped of the KIND byte.
#[derive(Debug)]
pub struct NatInboundChunk {
    pub peer: FabricPeerId,
    pub stream_frame: Vec<u8>,
}

/// Spawn the direct chunk receiver: a supervisor that tracks peer gate state
/// and one acceptor thread per `(peer, direct conn)`.
pub fn spawn_nat_chunk_receiver(
    slot: NatHandleSlot,
    gate: Arc<DirectGate>,
    tx: SyncSender<NatInboundChunk>,
    stats: Arc<ChunkStats>,
    shutdown: Arc<AtomicBool>,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name("nexusd-nat-chunk-recv".to_string())
        .spawn(move || {
            let mut acceptors: HashMap<(FabricPeerId, u64), std::thread::JoinHandle<()>> =
                HashMap::new();
            let mut was_open: HashMap<FabricPeerId, bool> = HashMap::new();

            loop {
                if shutdown.load(Ordering::Relaxed) {
                    break;
                }
                if let Some(provider) = slot.get() {
                    let gates = gate.snapshot(provider.as_ref());
                    for g in &gates {
                        let name = crate::nat_consumer::peer_hex(&g.peer);
                        let prev = was_open.insert(g.peer, g.sender_allowed);
                        if g.sender_allowed && prev != Some(true) {
                            eprintln!(
                                "[nat-consumer] direct gate open peer={} waited_ms={}",
                                hex16(&name),
                                g.last_success_ms
                            );
                        } else if !g.sender_allowed && prev == Some(true) {
                            let reason = if g.last_success_ms == 0 {
                                "state_not_succeeded"
                            } else {
                                "not_direct"
                            };
                            eprintln!(
                                "[nat-consumer] direct gate closed peer={} reason={reason}",
                                hex16(&name)
                            );
                        }

                        if !g.receiver_ready {
                            continue;
                        }
                        let Some(NatActiveConn::Direct(conn)) = provider.active_conn(&name) else {
                            continue;
                        };
                        let key = (g.peer, conn.id.0);
                        if acceptors.contains_key(&key) {
                            continue;
                        }
                        let acceptor = spawn_acceptor(
                            Arc::clone(&provider),
                            conn,
                            g.peer,
                            name.clone(),
                            tx.clone(),
                            Arc::clone(&stats),
                            Arc::clone(&shutdown),
                        );
                        acceptors.insert(key, acceptor);
                    }
                }
                acceptors.retain(|_, handle| !handle.is_finished());
                std::thread::sleep(Duration::from_millis(NAT_RECV_POLL_MS));
            }

            for (_, handle) in acceptors.drain() {
                let _ = handle.join();
            }
        })
}

#[allow(clippy::too_many_arguments)]
fn spawn_acceptor(
    provider: Arc<dyn NatPathProvider>,
    conn: Arc<nexus_fabric::ConnShared>,
    peer: FabricPeerId,
    name: String,
    tx: SyncSender<NatInboundChunk>,
    stats: Arc<ChunkStats>,
    shutdown: Arc<AtomicBool>,
) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("nexusd-nat-acceptor".to_string())
        .spawn(move || {
            eprintln!(
                "[nat-chunk] recv acceptor peer={} conn={} started (quiet_ms={DIRECT_ACCEPT_QUIET_MS})",
                hex16(&name),
                conn.id.0
            );
            loop {
                if shutdown.load(Ordering::Relaxed) {
                    break;
                }
                match provider.active_conn(&name) {
                    Some(NatActiveConn::Direct(c)) if c.id.0 == conn.id.0 => {}
                    _ => break,
                }
                match nexus_nat_wireup::accept_stream_timeout(&conn, Duration::from_secs(1)) {
                    Err(e) if e.kind() == std::io::ErrorKind::TimedOut => continue,
                    Err(_) => break,
                    Ok(stream) => handle_stream(
                        &peer, &name, &stream, &tx, &stats, &shutdown,
                    ),
                }
            }
            eprintln!(
                "[nat-chunk] recv acceptor peer={} conn={} closed",
                hex16(&name),
                conn.id.0
            );
        })
        .expect("spawn nat acceptor thread")
}

fn handle_stream(
    peer: &FabricPeerId,
    name: &str,
    stream: &Arc<StreamShared>,
    tx: &SyncSender<NatInboundChunk>,
    stats: &ChunkStats,
    shutdown: &AtomicBool,
) {
    let deadline = Instant::now() + Duration::from_millis(NAT_CHUNK_READ_TIMEOUT_MS);
    let read = read_chunk_frame(stream, deadline);
    let frame_ok = read.is_ok();
    match read {
        Ok((0x03, payload)) => match parse_chunk_payload(&payload) {
            Ok(frame) => match tx.try_send(NatInboundChunk {
                peer: *peer,
                stream_frame: frame.to_vec(),
            }) {
                Ok(()) => {
                    stats.record_recv(frame.len());
                    eprintln!(
                        "[nat-chunk] recv chunk peer={} bytes={} result=ok",
                        hex16(name),
                        frame.len()
                    );
                }
                Err(std::sync::mpsc::TrySendError::Full(_)) => {
                    reject(stats, name, NatChunkRecvError::InjectionFull)
                }
                Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                    reject(stats, name, NatChunkRecvError::InjectionClosed)
                }
            },
            Err(e) => reject(stats, name, e),
        },
        Ok((ty, _)) => reject(stats, name, NatChunkRecvError::TypeMismatch { got: ty }),
        Err(e) => reject(stats, name, e),
    }

    // (a) The frame was read: keep reading this direction until EOF so quinn
    // releases the receive half. A frame-read error already consumed the 5s
    // budget, so it does not re-read.
    if frame_ok {
        if let Err(e) = drain_stream_to_eof(stream, deadline) {
            reject(stats, name, e);
        }
    }
    // (b) Always close our send half before dropping the stream — this is the
    // other half of the MAX_STREAMS replenishment.
    finish_send_half(stream);
    if !shutdown.load(Ordering::Relaxed) {
        eprintln!(
            "[nat-chunk] stream closed peer={} (recv_eof; local_fin)",
            hex16(name)
        );
    }
}

fn reject(stats: &ChunkStats, name: &str, e: NatChunkRecvError) {
    stats.record_recv_rejected(e);
    if e == NatChunkRecvError::AcceptClosed {
        return;
    }
    eprintln!(
        "[nat-chunk] recv chunk peer={} rejected reason={}",
        hex16(name),
        reason_token(e)
    );
}

fn reason_token(e: NatChunkRecvError) -> &'static str {
    match e {
        NatChunkRecvError::TypeMismatch { .. } => "type_mismatch",
        NatChunkRecvError::KindMismatch { .. } => "kind_mismatch",
        NatChunkRecvError::BadLength { .. } => "bad_length",
        NatChunkRecvError::FrameTooLarge { .. } => "too_large",
        NatChunkRecvError::UnexpectedEof => "eof",
        NatChunkRecvError::Timeout => "timeout",
        NatChunkRecvError::AcceptClosed => "accept_closed",
        NatChunkRecvError::InjectionClosed => "inject_closed",
        NatChunkRecvError::InjectionFull => "inject_full",
        NatChunkRecvError::Poisoned => "poisoned",
    }
}

fn hex16(name: &str) -> &str {
    &name[..name.len().min(16)]
}

/// Read one `type | u32 BE len | payload` frame.
pub fn read_chunk_frame(
    stream: &Arc<StreamShared>,
    deadline: Instant,
) -> Result<(u8, Vec<u8>), NatChunkRecvError> {
    let mut header = [0u8; 5];
    nexus_nat_wireup::channel::read_exact_deadline(stream, &mut header, deadline)
        .map_err(map_io_recv_error)?;
    let ty = header[0];
    let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
    if len == 0 {
        return Err(NatChunkRecvError::BadLength { len });
    }
    if len > nexus_nat_wireup::channel::MAX_FRAME {
        return Err(NatChunkRecvError::FrameTooLarge { len });
    }
    let mut payload = vec![0u8; len];
    nexus_nat_wireup::channel::read_exact_deadline(stream, &mut payload, deadline)
        .map_err(map_io_recv_error)?;
    Ok((ty, payload))
}

/// Strip the KIND byte; anything but `0x01` is rejected unambiguously.
pub fn parse_chunk_payload(payload: &[u8]) -> Result<&[u8], NatChunkRecvError> {
    let Some((&kind, rest)) = payload.split_first() else {
        return Err(NatChunkRecvError::UnexpectedEof);
    };
    if kind != CHUNK_KIND_TUN_STREAM {
        return Err(NatChunkRecvError::KindMismatch { got: kind });
    }
    if rest.is_empty() {
        return Err(NatChunkRecvError::UnexpectedEof);
    }
    Ok(rest)
}

/// Keep reading the receive direction until EOF (`Ok(0)`). The peer FINs after
/// `write_msg`, so EOF is expected; a timeout is counted, never blocks accept.
pub fn drain_stream_to_eof(
    stream: &Arc<StreamShared>,
    deadline: Instant,
) -> Result<(), NatChunkRecvError> {
    let (_send, mut recv) = nexus_fabric::split_stream(Arc::clone(stream));
    let mut buf = [0u8; 4096];
    loop {
        match recv.read_deadline(&mut buf, deadline) {
            Ok(0) => return Ok(()),
            Ok(_) => continue,
            Err(nexus_fabric::FabricError::Timeout) => return Err(NatChunkRecvError::Timeout),
            Err(_) => return Err(NatChunkRecvError::UnexpectedEof),
        }
    }
}

/// Close our send half (same effect as `split_stream(..).0.finish()`); never
/// panics on a poisoned lock.
pub fn finish_send_half(stream: &Arc<StreamShared>) {
    let (mut send, _recv) = nexus_fabric::split_stream(Arc::clone(stream));
    let _ = send.finish();
}

/// Map transport read errors onto the frozen rejection taxonomy.
#[must_use]
pub fn map_io_recv_error(e: std::io::Error) -> NatChunkRecvError {
    match e.kind() {
        std::io::ErrorKind::TimedOut => NatChunkRecvError::Timeout,
        std::io::ErrorKind::UnexpectedEof => NatChunkRecvError::UnexpectedEof,
        std::io::ErrorKind::InvalidData => NatChunkRecvError::BadLength { len: 0 },
        _ => NatChunkRecvError::Poisoned,
    }
}

/// Receiver-side accept gate (frozen by Q8=A; do not change without a
/// requirement change).
pub const DIRECT_ACCEPT_QUIET_MS: u64 = 30000;
/// Sender-side gate: 30000 + 2000ms safety margin for cross-host clock skew.
pub const DIRECT_SEND_GUARD_MS: u64 = 32000;
/// How often the gate re-reads peer statuses.
pub const DIRECT_GATE_REFRESH_MS: u64 = 500;
/// Receiver supervisor poll interval.
pub const NAT_RECV_POLL_MS: u64 = 500;
/// Per-frame read/drain budget.
pub const NAT_CHUNK_READ_TIMEOUT_MS: u64 = 5000;
/// Inbound chunk queue depth between the receiver thread and the dataplane.
pub const NAT_INBOUND_QUEUE_CAP: usize = 1024;

/// Receiver-side rejection/lifecycle reasons (D-A only; no seq/reorder/ack
/// variants).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatChunkRecvError {
    TypeMismatch {
        got: u8,
    },
    KindMismatch {
        got: u8,
    },
    BadLength {
        len: usize,
    },
    FrameTooLarge {
        len: usize,
    },
    UnexpectedEof,
    Timeout,
    /// The direct connection closed / the acceptor exited. A lifecycle event,
    /// not a rejected chunk.
    AcceptClosed,
    InjectionClosed,
    InjectionFull,
    Poisoned,
}

/// Per-peer gate decision snapshot (used by the supervisor for logging and by
/// unit tests for the boundary checks).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectPeerGate {
    pub peer: FabricPeerId,
    pub last_success_ms: u64,
    pub sender_allowed: bool,
    pub receiver_ready: bool,
}

struct GateCache {
    loaded: bool,
    refreshed_at_ms: u64,
    statuses: Vec<PunchPeerStatus>,
}

/// Shared admission gate. Holds no connection state; only a 500ms status cache.
pub struct DirectGate {
    clock: Arc<dyn PunchClock>,
    cache: Mutex<GateCache>,
}

impl DirectGate {
    #[must_use]
    pub fn new(clock: Arc<dyn PunchClock>) -> Self {
        Self {
            clock,
            cache: Mutex::new(GateCache {
                loaded: false,
                refreshed_at_ms: 0,
                statuses: Vec::new(),
            }),
        }
    }

    fn statuses(&self, provider: &dyn NatPathProvider, now: u64) -> Vec<PunchPeerStatus> {
        // A poisoned cache lock must not take the dataplane down: fall back to
        // the provider's live view.
        let Ok(mut cache) = self.cache.lock() else {
            return provider.peer_statuses();
        };
        if !cache.loaded || now.saturating_sub(cache.refreshed_at_ms) >= DIRECT_GATE_REFRESH_MS {
            cache.statuses = provider.peer_statuses();
            cache.refreshed_at_ms = now;
            cache.loaded = true;
        }
        cache.statuses.clone()
    }

    fn decision(now: u64, status: &PunchPeerStatus) -> DirectPeerGate {
        let last = status.last_success_ms;
        let succeeded = status.state == PunchState::Succeeded && last.is_some();
        let waited = last.map_or(0, |t| now.saturating_sub(t));
        DirectPeerGate {
            peer: status.peer,
            last_success_ms: waited,
            sender_allowed: succeeded && waited >= DIRECT_SEND_GUARD_MS,
            receiver_ready: succeeded && waited >= DIRECT_ACCEPT_QUIET_MS,
        }
    }

    /// Sender-side gate for one peer.
    ///
    /// Reads the live status: a cached view could keep the gate open for up to
    /// `DIRECT_GATE_REFRESH_MS` after a re-punch, which is exactly the window
    /// the guard exists for. The cache is only used by [`Self::snapshot`], whose
    /// caller polls at the same cadence.
    #[must_use]
    pub fn sender_allowed(&self, provider: &dyn NatPathProvider, peer: &FabricPeerId) -> bool {
        let now = self.clock.now_ms();
        provider
            .peer_statuses()
            .iter()
            .find(|s| s.peer == *peer)
            .is_some_and(|s| Self::decision(now, s).sender_allowed)
    }

    /// Receiver-side gate for one peer (live read, same rationale).
    #[must_use]
    pub fn receiver_ready(&self, provider: &dyn NatPathProvider, peer: &FabricPeerId) -> bool {
        let now = self.clock.now_ms();
        provider
            .peer_statuses()
            .iter()
            .find(|s| s.peer == *peer)
            .is_some_and(|s| Self::decision(now, s).receiver_ready)
    }

    /// Full per-peer snapshot (supervisor polls this every 500ms).
    #[must_use]
    pub fn snapshot(&self, provider: &dyn NatPathProvider) -> Vec<DirectPeerGate> {
        let now = self.clock.now_ms();
        self.statuses(provider, now)
            .iter()
            .map(|s| Self::decision(now, s))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct FakeClock(AtomicU64);
    impl FakeClock {
        fn new(t: u64) -> Arc<Self> {
            Arc::new(Self(AtomicU64::new(t)))
        }
        fn set(&self, t: u64) {
            self.0.store(t, Ordering::SeqCst);
        }
    }
    impl PunchClock for FakeClock {
        fn now_ms(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
        fn wall_ms(&self) -> u64 {
            self.now_ms()
        }
        fn sleep_until_ms(&self, _deadline_ms: u64) {}
        fn sleep_ms(&self, _ms: u64) {}
    }

    struct StatusProvider {
        statuses: Mutex<Vec<PunchPeerStatus>>,
    }
    impl StatusProvider {
        fn new(statuses: Vec<PunchPeerStatus>) -> Self {
            Self {
                statuses: Mutex::new(statuses),
            }
        }
        fn replace(&self, statuses: Vec<PunchPeerStatus>) {
            *self.statuses.lock().unwrap() = statuses;
        }
    }
    impl NatPathProvider for StatusProvider {
        fn active_conn(&self, _peer_hex: &str) -> Option<crate::nat_consumer::NatActiveConn> {
            None
        }
        fn send_chunk(
            &self,
            _peer: FabricPeerId,
            fallback: &dyn Fn(&[u8]) -> std::io::Result<()>,
            chunk: &[u8],
        ) -> std::io::Result<crate::nat_switch::ChunkPath> {
            fallback(chunk)?;
            Ok(crate::nat_switch::ChunkPath::Fallback)
        }
        fn peer_statuses(&self) -> Vec<PunchPeerStatus> {
            self.statuses.lock().unwrap().clone()
        }
        fn path_active_switches(&self) -> u64 {
            0
        }
    }

    fn status(peer: u8, state: PunchState, last_success_ms: Option<u64>) -> PunchPeerStatus {
        PunchPeerStatus {
            peer: FabricPeerId([peer; 32]),
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

    #[test]
    fn send_gate_boundaries_31999_and_32000() {
        let clock = FakeClock::new(1_000_000);
        let peer = FabricPeerId([7u8; 32]);
        let provider = StatusProvider::new(vec![status(7, PunchState::Succeeded, Some(0))]);
        let gate = DirectGate::new(clock.clone());
        clock.set(31_999);
        assert!(!gate.sender_allowed(&provider, &peer));
        clock.set(32_000);
        assert!(gate.sender_allowed(&provider, &peer));
    }

    #[test]
    fn receive_gate_boundaries_29999_and_30000() {
        let clock = FakeClock::new(0);
        let peer = FabricPeerId([8u8; 32]);
        let provider = StatusProvider::new(vec![status(8, PunchState::Succeeded, Some(0))]);
        let gate = DirectGate::new(clock.clone());
        clock.set(29_999);
        assert!(!gate.receiver_ready(&provider, &peer));
        clock.set(30_000);
        assert!(gate.receiver_ready(&provider, &peer));
    }

    #[test]
    fn gate_is_per_peer() {
        let clock = FakeClock::new(40_000);
        let a = FabricPeerId([1u8; 32]);
        let b = FabricPeerId([2u8; 32]);
        let provider = StatusProvider::new(vec![
            status(1, PunchState::Succeeded, Some(0)),
            status(2, PunchState::InProgress, None),
        ]);
        let gate = DirectGate::new(clock);
        assert!(gate.sender_allowed(&provider, &a));
        assert!(!gate.sender_allowed(&provider, &b));
    }

    #[test]
    fn updated_last_success_resets_the_gate() {
        let clock = FakeClock::new(50_000);
        let peer = FabricPeerId([3u8; 32]);
        let provider = StatusProvider::new(vec![status(3, PunchState::Succeeded, Some(0))]);
        let gate = DirectGate::new(clock.clone());
        assert!(gate.sender_allowed(&provider, &peer));
        // Re-punch at t=50_000 resets the quiet period.
        provider.replace(vec![status(3, PunchState::Succeeded, Some(50_000))]);
        clock.set(50_001);
        assert!(!gate.sender_allowed(&provider, &peer));
        clock.set(82_000);
        assert!(gate.sender_allowed(&provider, &peer));
    }

    #[test]
    fn non_succeeded_state_closes_the_gate() {
        let clock = FakeClock::new(100_000);
        let peer = FabricPeerId([4u8; 32]);
        let provider = StatusProvider::new(vec![status(4, PunchState::Failed, Some(0))]);
        let gate = DirectGate::new(clock);
        assert!(!gate.sender_allowed(&provider, &peer));
        assert!(!gate.receiver_ready(&provider, &peer));
    }

    #[test]
    fn snapshot_reports_wait_time_per_peer() {
        let clock = FakeClock::new(32_500);
        let provider = StatusProvider::new(vec![status(5, PunchState::Succeeded, Some(0))]);
        let gate = DirectGate::new(clock);
        let snap = gate.snapshot(&provider);
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].last_success_ms, 32_500);
        assert!(snap[0].sender_allowed);
        assert!(snap[0].receiver_ready);
    }
}
