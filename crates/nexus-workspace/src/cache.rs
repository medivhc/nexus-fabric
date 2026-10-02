//! Workspace object cache (v9 §22).
//!
//! `CacheManager` is a deterministic, in-memory cache for CAS object bytes
//! with a score-based eviction policy. It is **not** authoritative storage:
//! eviction only drops cached copies, never CAS objects.
//!
//! # Iron rule (v9 §22)
//!
//! Entries carrying any [`CachePin`] are **never** evicted by normal cache
//! pressure:
//!
//! ```text
//! DirtyJournal, UniqueReplica, ComputeSnapshot, PendingArtifact,
//! UnreplicatedCommit, ConflictState, Explicit
//! ```
//!
//! # Cache eviction ≠ CAS GC
//!
//! CAS garbage collection (W1, `ReachabilityGc` in `nexus-storage`) reclaims
//! unreachable objects after a retention window. Cache eviction only drops
//! *copies* the cache holds. The two must never delete each other's
//! protected objects: a cache pin does not protect a CAS object from GC,
//! and GC reachability does not force anything into (or out of) the cache.
//! The [`CachePin`] taxonomy mirrors the §20 Protected Roots vocabulary so
//! W1 can align口径.
//!
//! # Eviction scoring
//!
//! Utility (higher = keep):
//!
//! ```text
//! utility = (hits + 1) * (1 + ws_prob) * (1 + centrality)
//!           * (1 + refetch_cost) / (size_bytes * (1 + age_ticks))
//! ```
//!
//! - `hits`: successful `get` count (recency/frequency).
//! - `ws_prob`: optional WorkingSet probability signal from W2
//!   (`set_workingset_probability`); **optional — never a correctness
//!   dependency**. Defaults to 0.0.
//! - `centrality`: optional graph centrality signal. Defaults to 0.0.
//! - `refetch_cost`: normalized weight ≥ 0 (0 = cheap to refetch).
//! - `age_ticks`: logical ticks since insert (deterministic clock).
//!
//! Eviction takes the lowest-utility unpinned entries first; ties break by
//! older `insert_tick`, then key order. Fully deterministic.

#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};

use nexus_storage::ObjectId;

/// Pin kinds — the iron-rule set (v9 §22). A pinned entry is immune to
/// normal cache eviction and to [`CacheManager::remove`].
///
/// Taxonomy mirrors the §20 Protected Roots vocabulary (W1's GC) so the two
/// subsystems align口径 without sharing code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CachePin {
    /// Dirty journal entries not yet checkpointed.
    DirtyJournal,
    /// Data for which this replica is the unique durable holder.
    UniqueReplica,
    /// Active compute snapshot inputs.
    ComputeSnapshot,
    /// Pending build artifact.
    PendingArtifact,
    /// Commits not yet replicated.
    UnreplicatedCommit,
    /// Conflict resolution working state.
    ConflictState,
    /// Explicit user/operator pin.
    Explicit,
}

/// Insert-time signals for eviction scoring (v9 §22).
#[derive(Debug, Clone, Copy)]
pub struct InsertSignals {
    /// Normalized refetch cost weight, ≥ 0 (0 = cheap to refetch).
    pub refetch_cost: u64,
    /// Optional WorkingSet probability from W2 (0.0..=1.0). Optional.
    pub workingset_probability: Option<f64>,
    /// Optional dependency-graph centrality (0.0..=1.0). Optional.
    pub graph_centrality: Option<f64>,
}

/// Cache errors (typed, no panics on business failure).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheError {
    /// Single object larger than total capacity; nothing was evicted.
    TooLarge { size: u64, capacity: u64 },
    /// Pinned entries alone fill the cache; `size` bytes cannot be freed
    /// without violating the iron rule.
    PinnedCapacityExceeded { size: u64, free: u64 },
}

impl std::fmt::Display for CacheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge { size, capacity } => {
                write!(f, "object size {size} exceeds cache capacity {capacity}")
            }
            Self::PinnedCapacityExceeded { size, free } => write!(
                f,
                "cannot free {size} bytes: only {free} bytes free and the rest is pinned"
            ),
        }
    }
}

impl std::error::Error for CacheError {}

struct CacheEntry {
    bytes: Vec<u8>,
    size: u64,
    hits: u64,
    insert_tick: u64,
    refetch_cost: u64,
    ws_prob: f64,
    centrality: f64,
    pins: HashSet<CachePin>,
}

impl CacheEntry {
    fn utility(&self, now_tick: u64) -> f64 {
        let age = now_tick.saturating_sub(self.insert_tick) as f64;
        (self.hits as f64 + 1.0)
            * (1.0 + self.ws_prob)
            * (1.0 + self.centrality)
            * (1.0 + self.refetch_cost as f64)
            / (self.size as f64 * (1.0 + age))
    }
}

/// Deterministic in-memory object cache with pin-aware eviction.
pub struct CacheManager {
    capacity_bytes: u64,
    used_bytes: u64,
    tick: u64,
    entries: HashMap<ObjectId, CacheEntry>,
}

impl CacheManager {
    /// Create a cache holding at most `capacity_bytes` of object data.
    pub fn new(capacity_bytes: u64) -> Self {
        Self {
            capacity_bytes,
            used_bytes: 0,
            tick: 0,
            entries: HashMap::new(),
        }
    }

    /// Insert (or replace) an entry, evicting lowest-utility unpinned
    /// entries until it fits. Returns evicted keys in eviction order.
    ///
    /// Iron rule: pinned entries are never evicted. Re-inserting an
    /// existing key keeps its pins and hit count, refreshes age/signals.
    pub fn insert(
        &mut self,
        key: &ObjectId,
        bytes: Vec<u8>,
        signals: InsertSignals,
    ) -> Result<Vec<ObjectId>, CacheError> {
        let size = bytes.len() as u64;
        if size > self.capacity_bytes {
            return Err(CacheError::TooLarge {
                size,
                capacity: self.capacity_bytes,
            });
        }
        self.tick += 1;

        // Take any existing entry out first (pins/hits preserved on replace).
        // The just-inserted key is never its own eviction victim: silently
        // evicting it would make insert a no-op that reports success.
        let old = self.entries.remove(key);
        if let Some(o) = &old {
            self.used_bytes = self.used_bytes.saturating_sub(o.size);
        }
        let (pins, hits) = old
            .as_ref()
            .map(|o| (o.pins.clone(), o.hits))
            .unwrap_or_else(|| (HashSet::new(), 0));

        self.entries.insert(
            key.clone(),
            CacheEntry {
                bytes,
                size,
                hits,
                insert_tick: self.tick,
                refetch_cost: signals.refetch_cost,
                ws_prob: signals
                    .workingset_probability
                    .unwrap_or(0.0)
                    .clamp(0.0, 1.0),
                centrality: signals.graph_centrality.unwrap_or(0.0).clamp(0.0, 1.0),
                pins,
            },
        );
        self.used_bytes += size;

        // Evict lowest-utility unpinned entries (excluding the new key)
        // until we fit.
        let mut evicted = Vec::new();
        while self.used_bytes > self.capacity_bytes {
            let victim = self
                .entries
                .iter()
                .filter(|(k, e)| *k != key && e.pins.is_empty())
                .map(|(k, e)| {
                    // Total order: utility, then older insert, then key.
                    let u = e.utility(self.tick);
                    (u, e.insert_tick, k.clone())
                })
                .min_by(|a, b| {
                    a.0.partial_cmp(&b.0)
                        .unwrap_or(std::cmp::Ordering::Equal)
                        .then_with(|| a.1.cmp(&b.1))
                        .then_with(|| a.2.0.cmp(&b.2.0))
                })
                .map(|(_, _, k)| k);
            match victim {
                Some(k) => {
                    if let Some(e) = self.entries.remove(&k) {
                        self.used_bytes = self.used_bytes.saturating_sub(e.size);
                        evicted.push(k);
                    }
                }
                None => {
                    // Roll back: remove the new entry, restore the old one.
                    if let Some(e) = self.entries.remove(key) {
                        self.used_bytes = self.used_bytes.saturating_sub(e.size);
                    }
                    if let Some(o) = old {
                        self.used_bytes += o.size;
                        self.entries.insert(key.clone(), o);
                    }
                    return Err(CacheError::PinnedCapacityExceeded {
                        size,
                        free: self.capacity_bytes.saturating_sub(self.used_bytes),
                    });
                }
            }
        }
        Ok(evicted)
    }

    /// Fetch an entry, recording a hit. Returns `None` on miss.
    pub fn get(&mut self, key: &ObjectId) -> Option<&[u8]> {
        // Tick bump first so a hit ages the entry consistently.
        let entry = self.entries.get_mut(key)?;
        self.tick += 1;
        entry.hits += 1;
        Some(&entry.bytes)
    }

    /// Add a pin. Returns `false` if the key is absent.
    pub fn pin(&mut self, key: &ObjectId, pin: CachePin) -> bool {
        match self.entries.get_mut(key) {
            Some(e) => {
                e.pins.insert(pin);
                true
            }
            None => false,
        }
    }

    /// Remove a pin. Returns `false` if the key is absent.
    pub fn unpin(&mut self, key: &ObjectId, pin: CachePin) -> bool {
        match self.entries.get_mut(key) {
            Some(e) => e.pins.remove(&pin),
            None => false,
        }
    }

    /// Whether any pin is held on this key.
    pub fn is_pinned(&self, key: &ObjectId) -> bool {
        self.entries
            .get(key)
            .map(|e| !e.pins.is_empty())
            .unwrap_or(false)
    }

    /// Optional W2 signal: WorkingSet probability. Clamped to 0.0..=1.0.
    /// Returns `false` if the key is absent. Never a correctness dependency.
    pub fn set_workingset_probability(&mut self, key: &ObjectId, p: f64) -> bool {
        match self.entries.get_mut(key) {
            Some(e) => {
                e.ws_prob = p.clamp(0.0, 1.0);
                true
            }
            None => false,
        }
    }

    /// Optional graph centrality signal. Clamped to 0.0..=1.0.
    pub fn set_graph_centrality(&mut self, key: &ObjectId, c: f64) -> bool {
        match self.entries.get_mut(key) {
            Some(e) => {
                e.centrality = c.clamp(0.0, 1.0);
                true
            }
            None => false,
        }
    }

    /// Remove an entry explicitly. Returns `None` if absent **or pinned**
    /// (iron rule: use `unpin` first).
    pub fn remove(&mut self, key: &ObjectId) -> Option<Vec<u8>> {
        if self.is_pinned(key) {
            return None;
        }
        self.entries.remove(key).map(|e| {
            self.used_bytes = self.used_bytes.saturating_sub(e.size);
            e.bytes
        })
    }

    /// `(used_bytes, capacity_bytes)`.
    pub fn usage(&self) -> (u64, u64) {
        (self.used_bytes, self.capacity_bytes)
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache holds no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oid(s: &str) -> ObjectId {
        ObjectId(s.to_string())
    }

    fn sig(cost: u64) -> InsertSignals {
        InsertSignals {
            refetch_cost: cost,
            workingset_probability: None,
            graph_centrality: None,
        }
    }

    #[test]
    fn pinned_entries_survive_pressure() {
        let mut c = CacheManager::new(1000);
        c.insert(&oid("a"), vec![0u8; 300], sig(0)).unwrap();
        c.insert(&oid("b"), vec![0u8; 300], sig(0)).unwrap();
        c.insert(&oid("c"), vec![0u8; 300], sig(0)).unwrap();
        assert!(c.pin(&oid("a"), CachePin::DirtyJournal));
        assert!(c.pin(&oid("b"), CachePin::Explicit));
        let evicted = c.insert(&oid("d"), vec![0u8; 300], sig(0)).unwrap();
        assert_eq!(evicted, vec![oid("c")]);
        assert!(c.get(&oid("a")).is_some());
        assert!(c.get(&oid("b")).is_some());
        assert!(c.get(&oid("d")).is_some());
    }

    #[test]
    fn eviction_is_score_based() {
        let mut c = CacheManager::new(1000);
        c.insert(&oid("x"), vec![0u8; 500], sig(0)).unwrap(); // big, cold, cheap
        c.insert(&oid("y"), vec![0u8; 300], sig(0)).unwrap();
        c.insert(&oid("z"), vec![0u8; 100], sig(10)).unwrap(); // small, hot, expensive
        for _ in 0..5 {
            let _ = c.get(&oid("z"));
        }
        let evicted = c.insert(&oid("w"), vec![0u8; 400], sig(0)).unwrap();
        assert_eq!(evicted, vec![oid("x")]);
        assert!(c.get(&oid("y")).is_some());
        assert!(c.get(&oid("z")).is_some());
    }

    #[test]
    fn oversize_is_rejected_without_side_effects() {
        let mut c = CacheManager::new(500);
        let r = c.insert(&oid("big"), vec![0u8; 600], sig(0));
        assert!(matches!(r, Err(CacheError::TooLarge { .. })));
        assert!(c.is_empty());
    }

    #[test]
    fn unpin_reenables_eviction() {
        let mut c = CacheManager::new(600);
        c.insert(&oid("a"), vec![0u8; 300], sig(0)).unwrap();
        c.insert(&oid("b"), vec![0u8; 300], sig(0)).unwrap();
        assert!(c.pin(&oid("a"), CachePin::ConflictState));
        c.insert(&oid("e"), vec![0u8; 300], sig(0)).unwrap(); // evicts b
        assert!(c.unpin(&oid("a"), CachePin::ConflictState));
        let evicted = c.insert(&oid("f"), vec![0u8; 300], sig(0)).unwrap();
        assert!(evicted.contains(&oid("a")));
    }

    #[test]
    fn remove_refuses_pinned() {
        let mut c = CacheManager::new(1000);
        c.insert(&oid("p"), vec![0u8; 100], sig(0)).unwrap();
        assert!(c.pin(&oid("p"), CachePin::UnreplicatedCommit));
        assert!(c.remove(&oid("p")).is_none());
        assert!(c.unpin(&oid("p"), CachePin::UnreplicatedCommit));
        assert!(c.remove(&oid("p")).is_some());
    }

    #[test]
    fn all_pinned_pressure_errors() {
        let mut c = CacheManager::new(600);
        c.insert(&oid("a"), vec![0u8; 300], sig(0)).unwrap();
        c.insert(&oid("b"), vec![0u8; 300], sig(0)).unwrap();
        assert!(c.pin(&oid("a"), CachePin::Explicit));
        assert!(c.pin(&oid("b"), CachePin::Explicit));
        let r = c.insert(&oid("c"), vec![0u8; 100], sig(0));
        assert!(matches!(r, Err(CacheError::PinnedCapacityExceeded { .. })));
        // Rolled back: a and b intact.
        assert!(c.get(&oid("a")).is_some());
        assert!(c.get(&oid("b")).is_some());
    }

    #[test]
    fn workingset_probability_is_optional_signal() {
        let mut c = CacheManager::new(700);
        c.insert(&oid("a"), vec![0u8; 300], sig(0)).unwrap();
        c.insert(&oid("b"), vec![0u8; 300], sig(0)).unwrap();
        // W2 says b is very likely needed soon.
        assert!(c.set_workingset_probability(&oid("b"), 0.95));
        let evicted = c.insert(&oid("e"), vec![0u8; 300], sig(0)).unwrap();
        assert_eq!(evicted, vec![oid("a")]);
        // Absent key: no panic, returns false.
        assert!(!c.set_workingset_probability(&oid("nope"), 0.5));
    }
}
