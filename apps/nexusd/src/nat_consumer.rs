//! NAT path provider: a narrow, injectable seam between the NAT control plane
//! and the production dataplane consumer.
//!
//! `NatSwitching` keeps its existing inherent surface (`active_conn`,
//! `send_chunk`, `stats`); this module only *wraps* it behind
//! [`NatPathProvider`] so the dataplane does not depend on the concrete type.
//! The provider is published through [`NatHandleSlot`], which is created by the
//! composition root before the dataplane thread starts and filled once the NAT
//! runtime is up (dataplane first, slot later; an empty slot means "all chunks
//! fallback", the honest degraded mode).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use nexus_fabric::{ConnShared, PeerId as FabricPeerId};
use nexus_nat_wireup::PunchPeerStatus;

use crate::nat_switch::ChunkPath;

/// Narrow consumer-facing view of the NAT path layer.
///
/// Implemented for [`crate::nat_switch::NatSwitching`] in this module so the
/// baseline `nat_switch.rs` keeps a single, unchanged signature surface.
pub trait NatPathProvider: Send + Sync {
    /// Active connection for `peer_hex`, tagged with its path kind. The
    /// receiver only accepts [`NatActiveConn::Direct`]; relay streams are not
    /// stolen from the existing responder.
    fn active_conn(&self, peer_hex: &str) -> Option<NatActiveConn>;

    /// Send one chunk through the active direct connection, or through
    /// `fallback` when no direct path is active.
    fn send_chunk(
        &self,
        peer: FabricPeerId,
        fallback: &dyn Fn(&[u8]) -> std::io::Result<()>,
        chunk: &[u8],
    ) -> std::io::Result<ChunkPath>;

    /// Snapshot of all peer punch statuses (state + `last_success_ms`).
    /// Uses the existing `NatStatusSource::peers()`; never reads private
    /// fields and never uses `direct_conn_id` (it can still be `None` after a
    /// successful punch).
    fn peer_statuses(&self) -> Vec<PunchPeerStatus>;

    /// `PathLinkStats.path_active_switches` (0 before any switch).
    fn path_active_switches(&self) -> u64;
}

/// Typed view of the active path: receivers accept only `Direct`.
#[derive(Debug, Clone)]
pub enum NatActiveConn {
    Direct(Arc<ConnShared>),
    Relay(Arc<ConnShared>),
}

/// Cloneable handle slot filled once by the composition root.
///
/// Deliberately not a global `OnceLock`: tests need independent slots and a
/// process-global would leak state between them. The status surface uses its
/// own global (see `nat_chunk_stats`).
#[derive(Clone, Default)]
pub struct NatHandleSlot {
    inner: Arc<Mutex<Option<Arc<dyn NatPathProvider>>>>,
}

impl NatHandleSlot {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&self, provider: Arc<dyn NatPathProvider>) {
        if let Ok(mut guard) = self.inner.lock() {
            *guard = Some(provider);
        }
    }

    /// `None` when empty or when the lock is poisoned (degraded, with a
    /// one-time warning; never panics).
    #[must_use]
    pub fn get(&self) -> Option<Arc<dyn NatPathProvider>> {
        match self.inner.lock() {
            Ok(guard) => guard.clone(),
            Err(_) => {
                warn_poisoned_once();
                None
            }
        }
    }
}

static POISON_WARNED: AtomicBool = AtomicBool::new(false);

fn warn_poisoned_once() {
    if !POISON_WARNED.swap(true, Ordering::Relaxed) {
        eprintln!("[nat-consumer] WARN: slot poisoned; fallback");
    }
}

impl NatPathProvider for crate::nat_switch::NatSwitching {
    fn active_conn(&self, peer_hex: &str) -> Option<NatActiveConn> {
        // Direct first: `active_direct_conn` returns `Some` only when the
        // active path is Direct. A switch between the two lookups can at worst
        // tag one direct conn as Relay for a cycle; the receiver re-checks
        // every 500ms, so this never sticks.
        if let Some(conn) = crate::nat_switch::NatSwitching::active_direct_conn(self, peer_hex) {
            return Some(NatActiveConn::Direct(conn));
        }
        crate::nat_switch::NatSwitching::active_conn(self, peer_hex).map(NatActiveConn::Relay)
    }

    fn send_chunk(
        &self,
        peer: FabricPeerId,
        fallback: &dyn Fn(&[u8]) -> std::io::Result<()>,
        chunk: &[u8],
    ) -> std::io::Result<ChunkPath> {
        crate::nat_switch::NatSwitching::send_chunk(self, peer, fallback, chunk)
    }

    fn peer_statuses(&self) -> Vec<PunchPeerStatus> {
        crate::nat_status::NatStatusSource::peers(self)
    }

    fn path_active_switches(&self) -> u64 {
        crate::nat_switch::NatSwitching::stats(self).path_active_switches
    }
}

/// Lowercase 64-hex peer id (`PathLink` keys by this string).
#[must_use]
pub fn peer_hex(peer: &FabricPeerId) -> String {
    peer.0.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeProvider;

    impl NatPathProvider for FakeProvider {
        fn active_conn(&self, _peer_hex: &str) -> Option<NatActiveConn> {
            None
        }
        fn send_chunk(
            &self,
            _peer: FabricPeerId,
            fallback: &dyn Fn(&[u8]) -> std::io::Result<()>,
            chunk: &[u8],
        ) -> std::io::Result<ChunkPath> {
            fallback(chunk)?;
            Ok(ChunkPath::Fallback)
        }
        fn peer_statuses(&self) -> Vec<PunchPeerStatus> {
            Vec::new()
        }
        fn path_active_switches(&self) -> u64 {
            0
        }
    }

    #[test]
    fn slot_starts_empty_and_returns_set_value() {
        let slot = NatHandleSlot::new();
        assert!(slot.get().is_none());
        slot.set(Arc::new(FakeProvider));
        assert!(slot.get().is_some());
    }

    #[test]
    fn slot_replacement_returns_new_provider() {
        let slot = NatHandleSlot::new();
        slot.set(Arc::new(FakeProvider));
        slot.set(Arc::new(FakeProvider));
        assert!(slot.get().is_some());
    }

    #[test]
    fn peer_hex_is_lowercase_64_hex() {
        let peer = FabricPeerId([0xabu8; 32]);
        assert_eq!(peer_hex(&peer), "ab".repeat(32));
    }
}
