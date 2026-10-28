//! Direct-path admission gate and (in the receiver commit) the direct chunk
//! stream acceptor.
//!
//! The 30s quiet period exists because the direct connection's accept queue is
//! owned for 30s by the tie-break winner's bind responder; non-BIND streams are
//! peeked and dropped during that window. Senders wait 32s (30s + 2s margin)
//! and receivers only start accepting once the same 30s has elapsed. Both gates
//! are derived from the *same* monotonic `PunchClock` that feeds
//! `last_success_ms`, so the comparison is meaningful.

use std::sync::{Arc, Mutex};

use nexus_fabric::PeerId as FabricPeerId;
use nexus_nat_traversal::PunchClock;
use nexus_nat_wireup::{PunchPeerStatus, PunchState};

use crate::nat_consumer::NatPathProvider;

/// Receiver-side accept gate (frozen by Q8=A; do not change without a
/// requirement change).
pub const DIRECT_ACCEPT_QUIET_MS: u64 = 30000;
/// Sender-side gate: 30000 + 2000ms safety margin for cross-host clock skew.
pub const DIRECT_SEND_GUARD_MS: u64 = 32000;
/// How often the gate re-reads peer statuses.
pub const DIRECT_GATE_REFRESH_MS: u64 = 500;

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
