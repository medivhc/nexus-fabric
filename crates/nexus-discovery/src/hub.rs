//! Owned discovery hub: one instance per process, explicit `now` injection.
//!
//! The hub owns the mutable state of every discovery source (LSDB, mDNS cache,
//! static table, optional paired table) plus the LSA freshness window, so the
//! daemon has **one** discovery snapshot shared by the N1 adapter, the
//! discovery pump and the peer-source feed.
//!
//! Design contract (MODULE.md / spec §4.10):
//! - the hub does **not** implement [`Discovery`](crate::Discovery): that
//!   trait has no `now` parameter and no way to express freshness, so every
//!   query method takes an explicit `Instant` instead;
//! - all locks cover in-memory state only: no socket I/O, no file I/O, no
//!   thread spawn, no `join` while holding the lock;
//! - `PeerId` ordering in the enumeration surface is the 64-hex string order
//!   (deterministic; never `HashMap` iteration order).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::aggregate::merge_ranked;
use crate::lsa::Lsdb;
use crate::mdns::MdnsDiscovery;
use crate::paired::PairedDiscovery;
use crate::{
    Discovery, DiscoveryMetrics, DiscoveryMetricsSnapshot, DiscoverySource, PeerId, ResolvedAddr,
    StaticDiscovery,
};

/// Single owned discovery snapshot (spec §6.1).
pub struct DiscoveryHub {
    inner: RwLock<HubState>,
    /// Poison recovery must not spam the log (one WARN per process).
    poison_warned: AtomicBool,
}

struct HubState {
    self_id: PeerId,
    lsdb: Lsdb,
    mdns: Option<MdnsDiscovery>,
    static_src: StaticDiscovery,
    paired: Option<PairedDiscovery>,
    /// Last time any frame referencing a node was seen (Hello / LsaAdvert).
    lsa_heard: HashMap<PeerId, Instant>,
    metrics: DiscoveryMetrics,
    lsa_stale_after: Duration,
}

impl DiscoveryHub {
    /// Build the hub from the already-mapped static peers.
    ///
    /// `static_peers` carries **one** address per peer: the representative
    /// address is `N1PeerEntry.addrs[0]` (empty `addrs` → `0.0.0.0:0`
    /// sentinel). That mapping happens exactly once, in
    /// `build_session_manager_with_discovery`.
    pub fn new(
        self_id: PeerId,
        static_peers: impl IntoIterator<Item = (PeerId, SocketAddr)>,
        mdns: Option<MdnsDiscovery>,
        lsa_stale_after: Duration,
    ) -> Self {
        Self {
            inner: RwLock::new(HubState {
                lsdb: Lsdb::new(self_id.clone()),
                self_id,
                mdns,
                static_src: StaticDiscovery::new(static_peers),
                paired: None,
                lsa_heard: HashMap::new(),
                metrics: DiscoveryMetrics::default(),
                lsa_stale_after,
            }),
            poison_warned: AtomicBool::new(false),
        }
    }

    /// Attach the optional paired source (builder addition, D7).
    #[must_use]
    pub fn with_paired(self, paired: PairedDiscovery) -> Self {
        self.write().paired = Some(paired);
        self
    }

    /// This node's id (never present in the enumeration surface).
    #[must_use]
    pub fn self_id(&self) -> PeerId {
        self.read().self_id.clone()
    }

    /// Resolve `peer` at `now`: Paired > Static > LSA > mDNS, deduped by
    /// address (highest priority keeps the address).
    ///
    /// LSA locators are filtered by the freshness window; the mDNS cache is
    /// pruned by the pump (`mdns_prune`), so its entries disappear within one
    /// pump cycle of their TTL (spec §4.8.3).
    #[must_use]
    pub fn resolve(&self, peer: &PeerId, now: Instant) -> Vec<ResolvedAddr> {
        let st = self.read();
        let lsa = FreshLsaView {
            lsdb: &st.lsdb,
            self_id: &st.self_id,
            heard: &st.lsa_heard,
            stale_after: st.lsa_stale_after,
            now,
        };
        let mdns_view = st.mdns.as_ref().map(MdnsView);
        let mdns_src: &dyn Discovery = match &mdns_view {
            Some(v) => v,
            None => &EmptySource,
        };
        let out = merge_ranked(
            st.paired.as_ref().map(|p| p as &dyn Discovery),
            &st.static_src,
            &lsa,
            mdns_src,
            peer,
        );
        record_metrics(&st.metrics, &out);
        out
    }

    /// Peers known at `now` (static ∪ paired ∪ fresh LSA ∪ mDNS cache),
    /// self excluded, 64-hex ascending.
    #[must_use]
    pub fn known_peers(&self, now: Instant) -> Vec<PeerId> {
        let mut out = self.union_peers(now);
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// Per-peer source labels at `now`, 64-hex ascending, self excluded.
    ///
    /// Label order per peer is priority order: paired, static, lsa, mdns.
    #[must_use]
    pub fn peer_source_map(&self, now: Instant) -> Vec<(PeerId, Vec<DiscoverySource>)> {
        let st = self.read();
        let mut map: HashMap<String, Vec<DiscoverySource>> = HashMap::new();
        let mut push = |peer: &PeerId, source: DiscoverySource| {
            if peer == &st.self_id {
                return;
            }
            map.entry(peer.0.clone()).or_default().push(source);
        };
        if let Some(paired) = &st.paired {
            let mut peers = paired.peers();
            peers.sort_by(|a, b| a.0.cmp(&b.0));
            for peer in &peers {
                push(peer, DiscoverySource::Paired);
            }
        }
        let mut static_peers = st.static_src.peers();
        static_peers.sort_by(|a, b| a.0.cmp(&b.0));
        for peer in &static_peers {
            push(peer, DiscoverySource::Static);
        }
        for peer in fresh_lsa_peer_ids(&st, now) {
            push(&peer, DiscoverySource::Lsa);
        }
        if let Some(mdns) = &st.mdns {
            let mut peers = mdns.cached_peers();
            peers.sort_by(|a, b| a.0.cmp(&b.0));
            for peer in &peers {
                push(peer, DiscoverySource::Mdns);
            }
        }
        let mut out: Vec<(PeerId, Vec<DiscoverySource>)> = map
            .into_iter()
            .map(|(id, mut sources)| {
                sources.sort_by_key(|s| source_rank(*s));
                sources.dedup();
                (PeerId(id), sources)
            })
            .collect();
        out.sort_by(|a, b| a.0.0.cmp(&b.0.0));
        out
    }

    /// LSA nodes inside the freshness window (self excluded, ascending).
    #[must_use]
    pub fn fresh_lsa_peers(&self, now: Instant) -> Vec<PeerId> {
        let st = self.read();
        fresh_lsa_peer_ids(&st, now)
    }

    /// LSA neighbour candidates: fresh LSA locators ∪ mDNS cached addresses,
    /// deduped by address (LSA keeps a duplicated address; it is the
    /// authoritative gossip endpoint).
    ///
    /// The caller filters its own `advertise_ip:gossip_port`.
    #[must_use]
    pub fn neighbor_candidates(&self, now: Instant) -> Vec<ResolvedAddr> {
        let st = self.read();
        let mut seen = std::collections::HashSet::new();
        let mut out = Vec::new();
        for peer in fresh_lsa_peer_ids(&st, now) {
            if let Some(lsa) = st.lsdb.get(&peer) {
                if let Some(addr) = lsa.locator.as_deref().and_then(parse_lsa_locator) {
                    if seen.insert(addr) {
                        out.push(ResolvedAddr {
                            addr,
                            source: DiscoverySource::Lsa,
                        });
                    }
                }
            }
        }
        if let Some(mdns) = &st.mdns {
            let mut peers = mdns.cached_peers();
            peers.sort_by(|a, b| a.0.cmp(&b.0));
            for peer in peers {
                for addr in Discovery::resolve(mdns, &peer) {
                    if seen.insert(addr) {
                        out.push(ResolvedAddr {
                            addr,
                            source: DiscoverySource::Mdns,
                        });
                    }
                }
            }
        }
        out
    }

    /// Discovery counters snapshot (hits per source / miss).
    #[must_use]
    pub fn metrics(&self) -> DiscoveryMetricsSnapshot {
        self.read().metrics.snapshot()
    }

    // ---------- lock helpers (poison recovery, never panic) ----------

    fn read(&self) -> std::sync::RwLockReadGuard<'_, HubState> {
        match self.inner.read() {
            Ok(g) => g,
            Err(e) => {
                self.warn_poisoned();
                e.into_inner()
            }
        }
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, HubState> {
        match self.inner.write() {
            Ok(g) => g,
            Err(e) => {
                self.warn_poisoned();
                e.into_inner()
            }
        }
    }

    fn warn_poisoned(&self) {
        if !self.poison_warned.swap(true, Ordering::Relaxed) {
            eprintln!("[discovery] WARN: hub lock poisoned; recovered inner state");
        }
    }

    fn union_peers(&self, now: Instant) -> Vec<PeerId> {
        let st = self.read();
        let mut seen = std::collections::HashSet::new();
        let mut out = Vec::new();
        let mut add = |peer: PeerId| {
            if peer != st.self_id && seen.insert(peer.0.clone()) {
                out.push(peer);
            }
        };
        if let Some(paired) = &st.paired {
            for peer in paired.peers() {
                add(peer);
            }
        }
        for peer in st.static_src.peers() {
            add(peer);
        }
        for peer in fresh_lsa_peer_ids(&st, now) {
            add(peer);
        }
        if let Some(mdns) = &st.mdns {
            for peer in mdns.cached_peers() {
                add(peer);
            }
        }
        out
    }
}

/// Empty source for the `mdns = None` case (keeps `merge_ranked` total).
struct EmptySource;

impl Discovery for EmptySource {
    fn resolve(&self, _peer: &PeerId) -> Vec<SocketAddr> {
        Vec::new()
    }
}

/// mDNS source adapter used inside [`DiscoveryHub`] (delegates to the owned
/// state machine; exists so the borrowed `&dyn Discovery` does not outlive
/// the read guard).
struct MdnsView<'a>(&'a MdnsDiscovery);

impl Discovery for MdnsView<'_> {
    fn resolve(&self, peer: &PeerId) -> Vec<SocketAddr> {
        Discovery::resolve(self.0, peer)
    }

    fn peers(&self) -> Vec<PeerId> {
        self.0.cached_peers()
    }
}

/// Read-only view over the LSDB that only exposes nodes inside the freshness
/// window (and never this node). Private by design: it lets the hub reuse the
/// single priority implementation without growing the public surface.
struct FreshLsaView<'a> {
    lsdb: &'a Lsdb,
    self_id: &'a PeerId,
    heard: &'a HashMap<PeerId, Instant>,
    stale_after: Duration,
    now: Instant,
}

impl FreshLsaView<'_> {
    fn is_fresh(&self, peer: &PeerId) -> bool {
        if peer == self.self_id {
            return false;
        }
        self.heard
            .get(peer)
            .map(|at| *at + self.stale_after > self.now)
            .unwrap_or(false)
    }
}

impl Discovery for FreshLsaView<'_> {
    fn resolve(&self, peer: &PeerId) -> Vec<SocketAddr> {
        if !self.is_fresh(peer) {
            return Vec::new();
        }
        crate::lsa::LsaDiscovery::new(self.lsdb).resolve(peer)
    }

    fn peers(&self) -> Vec<PeerId> {
        self.lsdb
            .peer_ids()
            .into_iter()
            .filter(|p| self.is_fresh(p))
            .collect()
    }
}

fn fresh_lsa_peer_ids(st: &HubState, now: Instant) -> Vec<PeerId> {
    let mut out: Vec<PeerId> = st
        .lsdb
        .peer_ids()
        .into_iter()
        .filter(|peer| peer != &st.self_id)
        .filter(|peer| {
            st.lsa_heard
                .get(peer)
                .map(|at| *at + st.lsa_stale_after > now)
                .unwrap_or(false)
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn parse_lsa_locator(locator: &str) -> Option<SocketAddr> {
    crate::lsa::LsaDiscovery::parse_locator(locator)
}

fn source_rank(source: DiscoverySource) -> u8 {
    match source {
        DiscoverySource::Paired => 0,
        DiscoverySource::Static => 1,
        DiscoverySource::Lsa => 2,
        DiscoverySource::Mdns => 3,
    }
}

/// One `resolve` call updates the counters: every source represented in the
/// ranked result counts a hit; an empty result counts a miss.
fn record_metrics(metrics: &DiscoveryMetrics, out: &[ResolvedAddr]) {
    if out.is_empty() {
        metrics.miss();
        return;
    }
    let mut paired = false;
    let mut stat = false;
    let mut lsa = false;
    let mut mdns = false;
    for r in out {
        match r.source {
            DiscoverySource::Paired => paired = true,
            DiscoverySource::Static => stat = true,
            DiscoverySource::Lsa => lsa = true,
            DiscoverySource::Mdns => mdns = true,
        }
    }
    if paired {
        metrics.hits_paired();
    }
    if stat {
        metrics.hits_static();
    }
    if lsa {
        metrics.hits_lsa();
    }
    if mdns {
        metrics.hits_mdns();
    }
}
