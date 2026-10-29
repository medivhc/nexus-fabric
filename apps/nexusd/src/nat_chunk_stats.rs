//! Chunk path counters and the `/localapi/v0/nat/chunks` status surface.
//!
//! `direct_attempts` counts *send attempts*, never delivery: `send_chunk`
//! returns `Ok(Direct)` as soon as the bytes are queued on a fresh stream.
//! The JSON field names and the disabled behaviour are frozen by the spec.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use serde_json::{Value, json};

use crate::nat_chunk_recv::NatChunkRecvError;
use crate::nat_consumer::NatHandleSlot;

/// Why a chunk took the pre-existing N1 fallback path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FallbackReason {
    /// `send_chunk` returned `Ok(Fallback)` (active path is relay / no direct).
    NoDirect,
    /// No `[[vpi.routes]]` entry matched the destination.
    NoPeer,
    /// No provider in the slot (NAT not started / not configured).
    NoPath,
    /// The direct quiet gate is not open yet.
    QuietGate,
}

/// Twelve monotonic counters shared by the dataplane, receiver and status API.
#[derive(Debug, Default)]
pub struct ChunkStats {
    direct_attempts: AtomicU64,
    direct_attempt_bytes: AtomicU64,
    fallback_chunks: AtomicU64,
    fallback_bytes: AtomicU64,
    direct_errors: AtomicU64,
    fallback_errors: AtomicU64,
    fallback_no_peer: AtomicU64,
    fallback_no_path: AtomicU64,
    fallback_quiet_gate: AtomicU64,
    recv_chunks: AtomicU64,
    recv_bytes: AtomicU64,
    recv_rejected: AtomicU64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ChunkStatsSnapshot {
    pub direct_attempts: u64,
    pub direct_attempt_bytes: u64,
    pub fallback_chunks: u64,
    pub fallback_bytes: u64,
    pub direct_errors: u64,
    pub fallback_errors: u64,
    pub fallback_no_peer: u64,
    pub fallback_no_path: u64,
    pub fallback_quiet_gate: u64,
    pub recv_chunks: u64,
    pub recv_bytes: u64,
    pub recv_rejected: u64,
}

impl ChunkStats {
    pub fn record_direct_attempt(&self, bytes: usize) {
        self.direct_attempts.fetch_add(1, Ordering::Relaxed);
        self.direct_attempt_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn record_fallback(&self, bytes: usize, reason: FallbackReason) {
        self.fallback_chunks.fetch_add(1, Ordering::Relaxed);
        self.fallback_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);
        let counter = match reason {
            FallbackReason::NoDirect => None,
            FallbackReason::NoPeer => Some(&self.fallback_no_peer),
            FallbackReason::NoPath => Some(&self.fallback_no_path),
            FallbackReason::QuietGate => Some(&self.fallback_quiet_gate),
        };
        if let Some(c) = counter {
            c.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn record_direct_error(&self, _bytes: usize) {
        self.direct_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_fallback_error(&self, _bytes: usize) {
        self.fallback_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_recv(&self, bytes: usize) {
        self.recv_chunks.fetch_add(1, Ordering::Relaxed);
        self.recv_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// `AcceptClosed` is a lifecycle event, not a rejected chunk: it does not
    /// increment `recv_rejected`.
    pub fn record_recv_rejected(&self, reason: NatChunkRecvError) {
        if reason != NatChunkRecvError::AcceptClosed {
            self.recv_rejected.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[must_use]
    pub fn snapshot(&self) -> ChunkStatsSnapshot {
        ChunkStatsSnapshot {
            direct_attempts: self.direct_attempts.load(Ordering::Relaxed),
            direct_attempt_bytes: self.direct_attempt_bytes.load(Ordering::Relaxed),
            fallback_chunks: self.fallback_chunks.load(Ordering::Relaxed),
            fallback_bytes: self.fallback_bytes.load(Ordering::Relaxed),
            direct_errors: self.direct_errors.load(Ordering::Relaxed),
            fallback_errors: self.fallback_errors.load(Ordering::Relaxed),
            fallback_no_peer: self.fallback_no_peer.load(Ordering::Relaxed),
            fallback_no_path: self.fallback_no_path.load(Ordering::Relaxed),
            fallback_quiet_gate: self.fallback_quiet_gate.load(Ordering::Relaxed),
            recv_chunks: self.recv_chunks.load(Ordering::Relaxed),
            recv_bytes: self.recv_bytes.load(Ordering::Relaxed),
            recv_rejected: self.recv_rejected.load(Ordering::Relaxed),
        }
    }
}

static CHUNK_STATS: OnceLock<Arc<ChunkStats>> = OnceLock::new();
static NAT_SLOT: OnceLock<NatHandleSlot> = OnceLock::new();

/// Publish the process-wide stats handle (composition root, once).
pub fn publish_chunk_stats(stats: Arc<ChunkStats>) {
    let _ = CHUNK_STATS.set(stats);
}

/// `None` before the composition root publishes the handle.
#[must_use]
pub fn chunk_stats_snapshot() -> Option<ChunkStatsSnapshot> {
    CHUNK_STATS.get().map(|s| s.snapshot())
}

/// Publish the slot so the status surface can report `runtime`.
pub fn publish_nat_slot_for_status(slot: NatHandleSlot) {
    let _ = NAT_SLOT.set(slot);
}

fn now_epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Build the `/localapi/v0/nat/chunks` body.
#[must_use]
pub fn chunk_status() -> Value {
    let provider = NAT_SLOT.get().and_then(|slot| slot.get());
    let runtime_enabled = provider.is_some();
    let path_active_switches = provider.as_ref().map_or(0, |p| p.path_active_switches());
    // Frozen behaviour: disabled means all counters read 0, even though the
    // fallback path may still be recording attempts.
    let snapshot = if runtime_enabled {
        chunk_stats_snapshot().unwrap_or_default()
    } else {
        ChunkStatsSnapshot::default()
    };
    build_chunk_status_json(
        runtime_enabled,
        path_active_switches,
        snapshot,
        now_epoch_ms(),
    )
}

/// Pure JSON builder (unit-testable exact values).
#[must_use]
pub fn build_chunk_status_json(
    runtime_enabled: bool,
    path_active_switches: u64,
    snapshot: ChunkStatsSnapshot,
    generated_at_ms: u64,
) -> Value {
    json!({
        "verdict": "PASS",
        "runtime": if runtime_enabled { "enabled" } else { "disabled" },
        "generated_at_ms": generated_at_ms,
        "chunks": {
            "direct_attempts": snapshot.direct_attempts,
            "direct_attempt_bytes": snapshot.direct_attempt_bytes,
            "fallback_chunks": snapshot.fallback_chunks,
            "fallback_bytes": snapshot.fallback_bytes,
            "direct_errors": snapshot.direct_errors,
            "fallback_errors": snapshot.fallback_errors,
            "fallback_no_peer": snapshot.fallback_no_peer,
            "fallback_no_path": snapshot.fallback_no_path,
            "fallback_quiet_gate": snapshot.fallback_quiet_gate,
            "recv_chunks": snapshot.recv_chunks,
            "recv_bytes": snapshot.recv_bytes,
            "recv_rejected": snapshot.recv_rejected,
        },
        "path": { "path_active_switches": path_active_switches },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_and_lossless_invariant() {
        let s = ChunkStats::default();
        s.record_direct_attempt(101);
        s.record_direct_attempt(51);
        s.record_recv(100);
        s.record_recv(50);
        let snap = s.snapshot();
        assert_eq!(snap.direct_attempts, 2);
        assert_eq!(snap.direct_attempt_bytes, 152);
        assert_eq!(snap.recv_bytes, 150);
        assert_eq!(
            snap.direct_attempt_bytes,
            snap.recv_bytes + snap.direct_attempts
        );
        assert_eq!(snap.recv_chunks, snap.direct_attempts);
    }

    #[test]
    fn fallback_reasons_increment_their_counter() {
        let s = ChunkStats::default();
        s.record_fallback(10, FallbackReason::NoDirect);
        s.record_fallback(20, FallbackReason::NoPeer);
        s.record_fallback(30, FallbackReason::NoPath);
        s.record_fallback(40, FallbackReason::QuietGate);
        let snap = s.snapshot();
        assert_eq!(snap.fallback_chunks, 4);
        assert_eq!(snap.fallback_bytes, 100);
        assert_eq!(snap.fallback_no_peer, 1);
        assert_eq!(snap.fallback_no_path, 1);
        assert_eq!(snap.fallback_quiet_gate, 1);
    }

    #[test]
    fn errors_are_counted_separately() {
        let s = ChunkStats::default();
        s.record_direct_error(10);
        s.record_fallback_error(20);
        let snap = s.snapshot();
        assert_eq!(snap.direct_errors, 1);
        assert_eq!(snap.fallback_errors, 1);
        assert_eq!(snap.direct_attempts, 0);
    }

    #[test]
    fn accept_closed_is_not_a_rejected_chunk() {
        let s = ChunkStats::default();
        s.record_recv_rejected(NatChunkRecvError::AcceptClosed);
        assert_eq!(s.snapshot().recv_rejected, 0);
        s.record_recv_rejected(NatChunkRecvError::Timeout);
        assert_eq!(s.snapshot().recv_rejected, 1);
    }

    #[test]
    fn json_disabled_is_all_zero() {
        let v = build_chunk_status_json(false, 0, ChunkStatsSnapshot::default(), 7);
        assert_eq!(v["runtime"], "disabled");
        assert_eq!(v["chunks"]["direct_attempts"], 0);
        assert_eq!(v["chunks"]["recv_rejected"], 0);
        assert_eq!(v["path"]["path_active_switches"], 0);
    }

    #[test]
    fn json_exact_values_after_scripted_sequence() {
        // 3 direct / 100B, 2 fallback / 80B, 1 direct error / 50B.
        let s = ChunkStats::default();
        for _ in 0..3 {
            s.record_direct_attempt(100);
        }
        for _ in 0..2 {
            s.record_fallback(80, FallbackReason::NoDirect);
        }
        s.record_direct_error(50);
        let v = build_chunk_status_json(true, 4, s.snapshot(), 123);
        assert_eq!(v["verdict"], "PASS");
        assert_eq!(v["runtime"], "enabled");
        assert_eq!(v["generated_at_ms"], 123);
        assert_eq!(v["chunks"]["direct_attempts"], 3);
        assert_eq!(v["chunks"]["direct_attempt_bytes"], 300);
        assert_eq!(v["chunks"]["fallback_chunks"], 2);
        assert_eq!(v["chunks"]["fallback_bytes"], 160);
        assert_eq!(v["chunks"]["direct_errors"], 1);
        assert_eq!(v["path"]["path_active_switches"], 4);
        assert!(v["chunks"].get("delivered").is_none());
        assert!(v["chunks"].get("acked").is_none());
    }
}
