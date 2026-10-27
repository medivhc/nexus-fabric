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
use crate::lsa::{Lsa, Lsdb, SeenCache, UpdateOutcome};
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
    /// Flood dedup cache (`(node, incarnation, seq)`), owned with the LSDB.
    seen: SeenCache,
    /// This node's own LSA (kept out of `all_lsas`, served by `self_lsa`).
    self_lsa: Option<Lsa>,
    /// Most recent injected `now`. `all_lsas()` has no `now` parameter (frozen
    /// signature), so it filters against the last observed time instead of
    /// opening a second, implicit time source.
    last_now: Option<Instant>,
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
                seen: SeenCache::new(1024),
                self_lsa: None,
                last_now: None,
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

    // ---------- LSA state machine (§4.9) ----------

    /// Upsert a received LSA and refresh its liveness stamp.
    ///
    /// Freshness is refreshed for **every** referenced frame, including a
    /// `Stale` outcome: "it is still being advertised" is exactly the liveness
    /// signal, and the LSDB never evicts.
    pub fn upsert_lsa(&self, lsa: Lsa, now: Instant) -> UpdateOutcome {
        let mut st = self.write();
        st.last_now = Some(now);
        let node = lsa.node_id.clone();
        let outcome = st.lsdb.update(lsa);
        st.lsa_heard.insert(node, now);
        outcome
    }

    /// Record that a frame referencing `peer` arrived (Hello / Welcome entry).
    pub fn note_lsa_heard(&self, peer: &PeerId, now: Instant) {
        let mut st = self.write();
        st.last_now = Some(now);
        if peer != &st.self_id {
            st.lsa_heard.insert(peer.clone(), now);
        }
    }

    /// Publish this node's own LSA (into the LSDB and the self slot).
    pub fn set_self_lsa(&self, lsa: Lsa, now: Instant) -> UpdateOutcome {
        let mut st = self.write();
        st.last_now = Some(now);
        let outcome = st.lsdb.update_local(lsa.clone());
        st.self_lsa = Some(lsa);
        outcome
    }

    /// This node's own LSA (never part of [`Self::all_lsas`]).
    #[must_use]
    pub fn self_lsa(&self) -> Option<Lsa> {
        self.read().self_lsa.clone()
    }

    /// Fresh remote LSAs, self excluded (Hello replies / flood fan-out).
    #[must_use]
    pub fn all_lsas(&self) -> Vec<Lsa> {
        let st = self.read();
        let Some(now) = st.last_now else {
            return Vec::new();
        };
        let mut out: Vec<Lsa> = st
            .lsdb
            .all()
            .into_iter()
            .filter(|lsa| lsa.node_id != st.self_id)
            .filter(|lsa| {
                st.lsa_heard
                    .get(&lsa.node_id)
                    .map(|at| *at + st.lsa_stale_after > now)
                    .unwrap_or(false)
            })
            .cloned()
            .collect();
        out.sort_by(|a, b| a.node_id.0.cmp(&b.node_id.0));
        out
    }

    /// Current LSDB entry count (observable; includes stale entries).
    #[must_use]
    pub fn lsdb_len(&self) -> usize {
        self.read().lsdb.len()
    }

    /// Flood dedup decision for `(node, incarnation, seq)`.
    pub fn should_flood(&self, peer: &PeerId, incarnation: u64, seq: u64) -> bool {
        self.write().seen.should_flood(peer, incarnation, seq)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(id: &str) -> PeerId {
        PeerId(id.to_string())
    }

    fn lsa(id: &str, locator: Option<&str>) -> Lsa {
        Lsa {
            node_id: peer(id),
            vip: "10.99.0.1".to_string(),
            incarnation: 1,
            seq: 1,
            capabilities: 0,
            locator: locator.map(str::to_string),
            neighbors: Vec::new(),
        }
    }

    fn hub_with(peers: &[(&str, SocketAddr)]) -> DiscoveryHub {
        DiscoveryHub::new(
            peer("self"),
            peers.iter().map(|(id, a)| (peer(id), *a)),
            None,
            Duration::from_secs(90),
        )
    }

    #[test]
    fn lsa_freshness_window_filters_stale() {
        let hub = hub_with(&[]);
        let t0 = Instant::now();
        hub.upsert_lsa(lsa("n1", Some("udp://10.0.0.9:19010")), t0);
        assert_eq!(hub.fresh_lsa_peers(t0), vec![peer("n1")]);
        assert_eq!(hub.resolve(&peer("n1"), t0).len(), 1);

        // Past the 90s window: the LSDB keeps the entry (no eviction) but the
        // freshness surface hides it.
        let stale = t0 + Duration::from_secs(91);
        assert!(hub.fresh_lsa_peers(stale).is_empty());
        assert!(hub.resolve(&peer("n1"), stale).is_empty());
        assert_eq!(hub.lsdb_len(), 1);
        // `all_lsas` filters with the last injected time.
        hub.note_lsa_heard(&peer("n2"), stale);
        assert!(hub.all_lsas().is_empty());
    }

    #[test]
    fn self_lsa_excluded_from_all_lsas() {
        let hub = hub_with(&[]);
        let t0 = Instant::now();
        hub.set_self_lsa(lsa("self", Some("udp://10.0.0.1:19010")), t0);
        hub.upsert_lsa(lsa("n1", Some("udp://10.0.0.9:19010")), t0);
        let all = hub.all_lsas();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].node_id, peer("n1"));
        assert_eq!(hub.self_lsa().expect("self lsa").node_id, peer("self"));
        // Self is never enumerated as a discovered peer.
        assert!(hub.known_peers(t0).iter().all(|p| p != &peer("self")));
        assert!(hub.resolve(&peer("self"), t0).is_empty());
    }
}
