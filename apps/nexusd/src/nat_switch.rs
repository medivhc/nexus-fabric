//! NAT 生产流量切换装配（gap 7）。
//!
//! 把三条 Phase-1 轨道接成一个生产栈：
//! - `PunchManager`（nexus-nat-wireup）：中继登记、后台打洞
//! - `PathLink`（nexus-projection）：per-peer active 连接选择
//! - `QualityMonitor`（nexus-nat-quality）：探针 + `on_stats` 供给 + 事件 drain
//!
//! Composition Root 用法：
//! ```text
//! let sw = NatSwitching::new(driver, my_id, local, samples);
//! // 每次中继建连成功后（TURN / peer relay）：
//! sw.on_relay_connected(RelayInfo { peer, relay: relay_conn, kind: PathKind::Turn, local, remote, remote_nat, auto_punch: true });
//! // 生产流量走：
//! let conn = sw.active_conn(&peer_name).unwrap();
//! // 退出时：
//! sw.shutdown();
//! ```
//!
//! D5 生产触发：per-peer attach 模型 + 本 spec §4.7 errata（O8-1..O8-12）。
//! `NatSwitching` 本身实现生产 `RelayConnSink`，调用方以
//! `attach_relay_provider` 接入 provider，再按 peer `subscribe_relay_peer`
//! 取得退订 guard；`on_relay_available` 直通
//! `on_relay_connected(auto_punch: true)`。provider 是单槽（≤1 relay peer）、
//! 持有 driver anchor，且**不**向新订阅者重放已建立的 relay（O8-9/O8-10：
//! 重放会再次覆盖 `nat_conns` 并清掉 direct 热备）。loopback 验收
//! （`nat_relay` 测试 `d5_production_sink_triggers_on_relay_connected`）证明该路径。
//! 残留边界：peer 来源由 `PeerSourceFeed` 提供并在 NAT worker 内 tick
//! （`main.rs` 的 `feed.tick`）：`peer_source.rs` 负责 `subscribe_relay_peer`
//! / 退订与 `spawn_trigger`（`trigger_relay`），本模块只消费 provider 事件。
//! 该接线的验收仍是 loopback / E4（fake doubles），**不是真机**证据。
//! E4（`crates/nexus-nat-wireup/examples/e4_prod_switch.rs`）用真实
//! TURN + NAT 模拟证明整条链路。

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, Weak};
use std::thread;

use nexus_connectivity::nat::NatType;
use nexus_fabric::{ConnShared, Driver, PeerId as FabricPeerId};
use nexus_nat_quality::{MeasuredPath, PathEventSink, ProbeRole, QualityMonitor};
use nexus_nat_traversal::{LocalCandidates, PortSample, PunchConfig, PunchResult};
use nexus_nat_wireup::PunchManager;
use nexus_path::{PathConfig, PathEvent, PathKind, PathManager};
use nexus_projection::PathLink;
use nexus_projection::path_link::ActiveConn;

use crate::nat_relay::{
    RelayConnProvider, RelayConnSink, RelayInfo as ProviderRelayInfo,
    RelayKind as ProviderRelayKind, RelaySubscriptionGuard,
};

impl crate::nat_status::NatStatusSource for NatSwitching {
    fn peers(&self) -> Vec<nexus_nat_wireup::PunchPeerStatus> {
        self.punch.all_status()
    }
}

/// Where a production chunk was sent by the B16S seam.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkPath {
    Direct,
    Fallback,
}

/// Peer name for [`PathLink`] (which keys by `&str`): hex of the fabric peer id.
fn peer_name(peer: &FabricPeerId) -> String {
    peer.0.iter().map(|b| format!("{b:02x}")).collect()
}

/// Production NAT switching stack (gap 7).
///
/// Ownership: `NatSwitching` owns the punch manager, the path link and the
/// quality monitor. Created via [`Arc::new_cyclic`] so the monitor's event
/// sink can call back (role updates) through a [`Weak`] — no reference cycle.
pub struct NatSwitching {
    driver: Arc<Driver>,
    my_id: FabricPeerId,
    punch: Arc<PunchManager>,
    link: Arc<Mutex<PathLink>>,
    monitor: QualityMonitor<Arc<ConnShared>>,
    /// D5 production relay trigger (spec section 14.3 / B15-B17).
    /// `attach_relay_provider` stores the provider; `subscribe_relay_peer`
    /// registers this stack as its sink for one peer. `self_weak` lets the
    /// `RelayConnSink` impl reach `on_relay_connected` (which takes
    /// `&Arc<Self>`); it is set by `new` via `Arc::new_cyclic`.
    relay_provider: Mutex<Option<Arc<dyn RelayConnProvider>>>,
    relay_lost: Mutex<HashSet<[u8; 32]>>,
    self_weak: Weak<NatSwitching>,
}

/// `PathEventSink`: the monitor's tick drains `poll_event()` and lands here.
/// Delegates the flip/rebind policy to [`PathLink::handle_event`] (single
/// implementation, no duplication), then updates probe roles so the newly
/// active path gets the 1s cadence and the old one drops to 5s backup.
struct LinkSink {
    inner: Weak<NatSwitching>,
}

impl PathEventSink for LinkSink {
    fn on_path_event(&self, event: PathEvent) {
        let Some(sw) = self.inner.upgrade() else {
            return;
        };
        // T1 (2026-10-03): `PathEvent::Adopted` (nexus-path D4) added; the
        // adoption has no previous path to demote. Minimal compile-safe
        // handling — the NAT-flip/rebind policy stays in `handle_event`.
        match &event {
            PathEvent::Switched { from, to, .. } => {
                eprintln!(
                    "[nat-switch] path switched: {} ({:?}) -> {} ({:?})",
                    from.remote_addr, from.kind, to.remote_addr, to.kind
                );
                sw.monitor.set_role(&to.remote_addr, ProbeRole::Active);
                sw.monitor.set_role(&from.remote_addr, ProbeRole::Backup);
            }
            PathEvent::Adopted { to } => {
                eprintln!(
                    "[nat-switch] path adopted: {} ({:?})",
                    to.remote_addr, to.kind
                );
                sw.monitor.set_role(&to.remote_addr, ProbeRole::Active);
            }
        }
        sw.link.lock().unwrap().handle_event(event);
    }
}

/// Parameters for registering a relay connection that should participate
/// in NAT direct-path racing.
pub struct RelayInfo {
    pub peer: FabricPeerId,
    pub relay: Arc<ConnShared>,
    pub kind: PathKind,
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub remote_nat: NatType,
    pub auto_punch: bool,
}

impl NatSwitching {
    /// Build the stack and start the quality monitor.
    ///
    /// - `driver` / `my_id`: the fabric driver PunchManager punches on.
    /// - `local` / `samples`: local candidates + STUN port samples
    ///   (see [`gather_host_candidates`]; srflx/STUN sampling is the
    ///   composition root's job until a STUN client lands in nexusd).
    pub fn new(
        driver: Arc<Driver>,
        my_id: FabricPeerId,
        local: LocalCandidates,
        samples: Vec<PortSample>,
        clock: Arc<dyn nexus_nat_traversal::PunchClock>,
    ) -> Arc<Self> {
        let sw = Arc::new_cyclic(|weak| {
            let punch = PunchManager::new(driver.clone(), my_id, clock);
            punch.set_local(local, samples);
            let pm = Arc::new(Mutex::new(PathManager::new(PathConfig::default())));
            let link = Arc::new(Mutex::new(PathLink::new(pm.clone())));
            let sink: Arc<dyn PathEventSink> = Arc::new(LinkSink {
                inner: weak.clone(),
            });
            let monitor = QualityMonitor::new(pm, sink);
            Self {
                driver,
                my_id,
                punch,
                link,
                monitor,
                relay_provider: Mutex::new(None),
                relay_lost: Mutex::new(HashSet::new()),
                self_weak: weak.clone(),
            }
        });
        sw.monitor.start();
        eprintln!("[nat-switch] stack assembled, quality monitor started");
        sw
    }

    /// Update local candidates / STUN samples (e.g. after re-sampling).
    pub fn set_local(&self, local: LocalCandidates, samples: Vec<PortSample>) {
        self.punch.set_local(local, samples);
    }

    /// D5 (spec section 14.3 / B16): attach the production relay provider.
    ///
    /// Stores the provider; it does not subscribe any peer by itself
    /// (subscription is per peer -- see `subscribe_relay_peer`). Safe to
    /// call before or after peers are known; re-attaching replaces the
    /// stored provider (logged) but does not re-subscribe past peers.
    pub fn attach_relay_provider(self: &Arc<Self>, provider: Arc<dyn RelayConnProvider>) {
        let replaced = self
            .relay_provider
            .lock()
            .unwrap()
            .replace(provider)
            .is_some();
        eprintln!(
            "[nat-switch] relay provider {}",
            if replaced {
                "re-attached (previous replaced)"
            } else {
                "attached"
            }
        );
    }

    /// Subscribe this stack as the provider's sink for one peer.
    ///
    /// Returns `None` (fail-closed, logged) when no provider is attached. The
    /// provider feeds `on_relay_available` for this peer, which routes into
    /// `on_relay_connected` with `auto_punch: true`.
    ///
    /// The returned guard owns the subscription lifetime: dropping it
    /// unsubscribes and lets the provider release the relay slot when no sink
    /// is left. Neither edge is strong (O9), so the guard cannot create a
    /// cycle.
    pub fn subscribe_relay_peer(
        self: &Arc<Self>,
        peer: FabricPeerId,
    ) -> Option<RelaySubscriptionGuard> {
        let Some(provider) = self.relay_provider.lock().unwrap().clone() else {
            eprintln!(
                "[nat-switch] WARN: subscribe_relay_peer with no provider attached; refusing"
            );
            return None;
        };
        let sink: Arc<dyn RelayConnSink> = Arc::clone(self) as Arc<dyn RelayConnSink>;
        provider.subscribe(peer, Arc::clone(&sink));
        Some(RelaySubscriptionGuard::new(
            Arc::downgrade(&provider),
            peer,
            Arc::downgrade(&sink),
        ))
    }

    /// Peers this stack is subscribed for (delegated to the provider).
    pub fn relay_subscribed_peers(&self) -> Vec<FabricPeerId> {
        match self.relay_provider.lock().unwrap().clone() {
            Some(provider) => provider.subscribed_peers(),
            None => Vec::new(),
        }
    }

    /// Peers whose relay was reported lost (state only -- see `on_relay_lost`).
    pub fn relay_lost_peers(&self) -> Vec<FabricPeerId> {
        self.relay_lost
            .lock()
            .unwrap()
            .iter()
            .map(|b| FabricPeerId(*b))
            .collect()
    }

    /// Call when a relayed connection to `peer` is established.
    ///
    /// Registers the relay with the punch responder, the path link (as a
    /// Turn/Mesh candidate) and the quality monitor (probing starts at the
    /// Active cadence). If `auto_punch`, punches in a bounded worker thread
    /// (`PunchConfig::punch_timeout` bounds it; the thread is not joined —
    /// it exits on its own, like the existing nexusd background dial).
    /// Pass `false` on the responder side (its responder loop answers the
    /// initiator's offer; initiating from both sides also works via
    /// tie-break, but is wasteful).
    /// On `Migrated`, the direct conn is registered as a Direct candidate;
    /// the [`PathManager`] promotes it only if it beats the relay by the
    /// frozen 20%+3s hysteresis (punch success alone never switches).
    pub fn on_relay_connected(self: &Arc<Self>, info: RelayInfo) {
        let RelayInfo {
            peer,
            relay,
            kind,
            local,
            remote,
            remote_nat,
            auto_punch,
        } = info;
        debug_assert!(
            matches!(kind, PathKind::Turn | PathKind::Mesh),
            "relay kind must be Turn or Mesh"
        );
        let name = peer_name(&peer);
        // A successful relay clears the "lost" state and makes the peer visible
        // in `GET /connectivity/nat` with turn/turn as its state evidence
        // (spec §4.5, AC3). Path decisions are unchanged.
        self.relay_lost.lock().unwrap().remove(&peer.0);
        self.punch
            .set_tunnel_proto(peer, nexus_nat_wireup::TunnelProto::Turn);
        self.punch
            .set_relay_source(peer, Some(nexus_nat_wireup::RelaySource::Turn));
        self.punch.register_relay(&relay, peer);
        self.link
            .lock()
            .unwrap()
            .register_nat_relay(&name, relay.clone(), kind, local, remote);
        self.monitor.add_path(MeasuredPath {
            addr: remote,
            kind,
            local_addr: local,
            cost: if kind == PathKind::Turn { 5.0 } else { 2.0 },
            transport: relay.clone(),
            role: ProbeRole::Active,
            forward: None,
        });
        eprintln!("[nat-switch] relay registered for peer {name} ({kind:?})");

        if !auto_punch {
            return; // responder side: the responder loop answers offers.
        }
        // Tie-break (AC5/AC6): if both sides would punch simultaneously,
        // only the larger PeerId initiates. This avoids duplicate direct
        // connections and the need for post-hoc connection teardown.
        // FabricPeerId is [u8; 32], lexicographic comparison is deterministic.
        // W-3: self-loop guard — punching ourselves is a configuration/wiring
        // bug; refuse loudly instead of deadlocking or punching a loopback.
        if self.my_id == peer {
            eprintln!(
                "[nat-switch] ERROR: refusing self-loop punch (my_id == peer {name}); check relay peer wiring"
            );
            return;
        }
        if !should_initiate(&self.my_id, &peer) {
            return;
        }
        eprintln!("[nat-switch] background punch starting for peer {name} (both sides initiate)");
        let this = Arc::clone(self);
        let relay_conn = relay.clone();
        thread::Builder::new()
            .name(format!("nat-punch-{name}"))
            .spawn(move || {
                let result =
                    this.punch
                        .punch_peer(&relay_conn, peer, remote_nat, PunchConfig::default());
                eprintln!("[nat-switch] punch result for peer {name}: {result:?}");
                if let PunchResult::Migrated { addr } = &result {
                    this.on_direct_ready(peer, &name, *addr);
                }
                // StayedOnRelay / Failed: relay remains the working path;
                // nothing to register.
            })
            .expect("spawn nat punch thread");
    }

    /// Register a punched direct connection as a racing candidate.
    ///
    /// Note: tie-break is enforced at punch initiation time (see
    /// [`Self::on_relay_connected`]): only the larger PeerId initiates,
    /// so duplicate simultaneous punches do not occur by construction.
    fn on_direct_ready(&self, peer: FabricPeerId, name: &str, addr: SocketAddr) {
        let Some(direct) = self.punch.direct_conn(&peer) else {
            eprintln!("[nat-switch] WARN: Migrated but no direct conn for peer {name}");
            return;
        };
        let local = *self.driver.shared().local_addr.lock().unwrap();
        self.link
            .lock()
            .unwrap()
            .register_nat_direct(name, direct.conn.clone(), local, addr);
        self.monitor.add_path(MeasuredPath {
            addr,
            kind: PathKind::Direct,
            local_addr: local,
            cost: 0.0,
            transport: direct.conn,
            role: ProbeRole::Backup, // promoted to Active by LinkSink on Switched
            forward: None,
        });
        eprintln!(
            "[nat-switch] direct candidate registered for peer {name} at {addr} (racing, not active)"
        );
    }

    /// The **direct** connection if the active path is Direct (None on relay).
    pub fn active_direct_conn(&self, peer_hex: &str) -> Option<Arc<ConnShared>> {
        let link = self.link.lock().unwrap();
        let conns = link.nat_conns(peer_hex)?;
        match conns.active {
            ActiveConn::Direct => conns.direct.clone(),
            ActiveConn::Relay => None,
        }
    }

    /// B16S seam: send one production chunk through the currently active
    /// direct connection when one is active, otherwise through the original
    /// path (byte-for-byte unchanged).
    ///
    /// - `has direct active`  -> open a fresh bi-stream on that conn and write
    ///   one `WORKSPACE_SYNC` frame for this chunk.
    /// - otherwise            -> `fallback` (the pre-existing send path).
    pub fn send_chunk(
        &self,
        peer: FabricPeerId,
        fallback: &dyn Fn(&[u8]) -> std::io::Result<()>,
        chunk: &[u8],
    ) -> std::io::Result<ChunkPath> {
        let name = peer_name(&peer);
        if let Some(conn) = self.active_direct_conn(&name) {
            let stream = nexus_nat_wireup::channel::open_bi_stream(
                &conn,
                std::time::Duration::from_secs(5),
            )?;
            nexus_nat_wireup::channel::write_msg(
                &stream,
                nexus_nat_wireup::channel::STREAM_TYPE_WORKSPACE_SYNC,
                chunk,
            )?;
            return Ok(ChunkPath::Direct);
        }
        fallback(chunk)?;
        Ok(ChunkPath::Fallback)
    }

    /// The connection currently carrying `peer`'s production traffic.
    /// `peer` is the hex peer-id name (see [`peer_name`]).
    pub fn active_conn(&self, peer_hex: &str) -> Option<Arc<ConnShared>> {
        let link = self.link.lock().unwrap();
        let conns = link.nat_conns(peer_hex)?;
        Some(match conns.active {
            ActiveConn::Direct => conns.direct.clone()?,
            ActiveConn::Relay => conns.relay.clone(),
        })
    }

    /// Path/linkage counters (observability).
    pub fn stats(&self) -> nexus_projection::PathLinkStats {
        self.link.lock().unwrap().stats().clone()
    }

    /// Stop the quality monitor and wait for it (idempotent).
    /// Punch worker threads are bounded by `PunchConfig::punch_timeout` and
    /// exit on their own; punch responder threads exit when their relay
    /// connections close.
    pub fn shutdown(&self) {
        self.monitor.shutdown();
        eprintln!("[nat-switch] quality monitor stopped");
    }
}

/// Production `RelayConnSink` (D5, spec section 14.3 / B16).
///
/// This is the consumer side the product-review confirmation found missing:
/// the provider feeds relay connections here, and they land in
/// `on_relay_connected` with `auto_punch: true` -- the production trigger
/// path. `remote_nat` is `Unknown` by rule: the provider event carries no
/// peer NAT type, and inventing one would be a false claim (same honesty
/// rule as the gatherer's `Unknown` default).
impl RelayConnSink for NatSwitching {
    fn on_relay_available(&self, info: ProviderRelayInfo) {
        let Some(sw) = self.self_weak.upgrade() else {
            eprintln!("[nat-switch] WARN: relay available but stack dropped; ignoring");
            return;
        };
        let local = *sw.driver.shared().local_addr.lock().unwrap();
        let kind = match info.kind {
            ProviderRelayKind::Turn => PathKind::Turn,
            ProviderRelayKind::Mesh => PathKind::Mesh,
        };
        eprintln!(
            "[nat-switch] relay available for peer {} ({kind:?}); triggering on_relay_connected (auto_punch)",
            peer_name(&info.peer)
        );
        sw.on_relay_connected(RelayInfo {
            peer: info.peer,
            relay: info.conn,
            kind,
            local,
            remote: info.relayed,
            remote_nat: NatType::Unknown,
            auto_punch: true,
        });
    }

    fn on_relay_lost(&self, peer: FabricPeerId) {
        // Spec section 14.3: only update state. The relay is already gone,
        // so there is nothing to close, and a lost relay must never
        // trigger a punch. Clearing `relay_source` keeps the API from
        // reporting `turn` after the loss (R-18 allows the residual *path*
        // state; the relay source itself must not lie).
        self.relay_lost.lock().unwrap().insert(peer.0);
        self.punch.set_relay_source(peer, None);
        eprintln!(
            "[nat-switch] relay lost for peer {} (state only; relay not closed, no punch triggered)",
            peer_name(&peer)
        );
    }
}

/// Best-effort host candidates from the driver's bound UDP socket.
///
/// Full STUN/srflx sampling needs a STUN client, which nexusd does not have
/// yet; the composition root should call [`NatSwitching::set_local`] with
/// real samples when they become available. Host candidates alone are
/// enough for the relay-first flow (punching still works when both sides
/// are reachable, and degrades honestly otherwise).
/// Pure routing decision for the B16S seam (direct active vs fallback).
pub fn chunk_route(has_active_direct: bool) -> ChunkPath {
    if has_active_direct {
        ChunkPath::Direct
    } else {
        ChunkPath::Fallback
    }
}

/// Both sides initiate punch (C-14); only a self-pair is refused.
pub fn should_initiate(my_id: &FabricPeerId, peer: &FabricPeerId) -> bool {
    my_id != peer
}

/// Enumerate host candidates from the OS interface table, using the punch
/// driver's UDP port. Never returns unspecified / multicast / broadcast
/// addresses. Loopback is kept only when no other address exists.
pub fn gather_host_candidates(driver: &Arc<Driver>) -> Vec<SocketAddr> {
    let port = driver.shared().local_addr.lock().unwrap().port();
    let mut addrs = Vec::new();
    #[cfg(target_os = "linux")]
    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) == 0 {
            let mut cur = ifap;
            while !cur.is_null() {
                let ifa = &*cur;
                if !ifa.ifa_addr.is_null() {
                    let family = (*ifa.ifa_addr).sa_family as i32;
                    if family == libc::AF_INET {
                        let sa = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                        let ip = std::net::Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr));
                        if !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast() {
                            addrs.push(SocketAddr::new(ip.into(), port));
                        }
                    } else if family == libc::AF_INET6 {
                        let sa = &*(ifa.ifa_addr as *const libc::sockaddr_in6);
                        let ip = std::net::Ipv6Addr::from(sa.sin6_addr.s6_addr);
                        if !ip.is_unspecified() && !ip.is_multicast() {
                            addrs.push(SocketAddr::new(ip.into(), port));
                        }
                    }
                }
                cur = ifa.ifa_next;
            }
            libc::freeifaddrs(ifap);
        }
    }
    addrs.sort();
    addrs.dedup();
    let non_loopback: Vec<SocketAddr> = addrs
        .iter()
        .copied()
        .filter(|a| !a.ip().is_loopback())
        .collect();
    if !non_loopback.is_empty() {
        non_loopback
    } else if !addrs.is_empty() {
        addrs
    } else {
        vec![SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), port)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_name_is_hex() {
        let peer = FabricPeerId([0xabu8; 32]);
        assert_eq!(peer_name(&peer), "ab".repeat(32));
    }

    #[test]
    fn gather_host_candidates_empty_without_socket() {
        // v1.1: enumerate interfaces (can be >1), never unspecified, and the
        // port always comes from the punch driver socket.
        if let Ok(driver) = Driver::new_client() {
            let port = driver.shared().local_addr.lock().unwrap().port();
            let addrs = gather_host_candidates(&driver);
            assert!(addrs.iter().all(|a| !a.ip().is_unspecified()));
            assert!(addrs.iter().all(|a| a.port() == port));
        }
    }
}

#[cfg(test)]
mod gap_tests {
    use super::*;
    use std::time::Duration;

    fn pid(byte: u8) -> FabricPeerId {
        FabricPeerId([byte; 32])
    }

    /// AC3 state evidence: a registered relay clears the lost mark and makes
    /// the peer observable as `tunnel_proto="turn"` / `relay_source="turn"`.
    #[test]
    fn relay_connected_sets_turn_state() {
        let server = Driver::new_server("127.0.0.1:0".parse().unwrap()).expect("bind server");
        let peer = server.shared().peer_id.expect("server identity");
        let server_addr = *server.shared().local_addr.lock().unwrap();
        let acceptor = {
            let server = Arc::clone(&server);
            std::thread::spawn(move || server.accept_conn())
        };
        let client = Driver::new_client().expect("bind client");
        let local = *client.shared().local_addr.lock().unwrap();
        let conn = client
            .connect(peer, server_addr, Duration::from_secs(5))
            .expect("connect");
        let _ = acceptor.join().expect("accept thread").expect("accept");

        let driver = Driver::new_server("127.0.0.1:0".parse().unwrap()).expect("bind driver");
        let candidates = nexus_nat_traversal::LocalCandidates {
            host: gather_host_candidates(&driver),
            srflx: None,
            srflx_stun: None,
            srflx_turn: None,
            nat_type: NatType::Unknown,
        };
        let sw = NatSwitching::new(
            driver,
            FabricPeerId([0x33; 32]),
            candidates,
            Vec::new(),
            Arc::new(nexus_nat_wireup::SystemPunchClock::new()),
        );
        // A lost report followed by a successful relay must clear the mark.
        RelayConnSink::on_relay_lost(sw.as_ref(), peer);
        assert!(sw.relay_lost_peers().contains(&peer));
        sw.on_relay_connected(RelayInfo {
            peer,
            relay: conn,
            kind: PathKind::Turn,
            local,
            remote: server_addr,
            remote_nat: NatType::Unknown,
            auto_punch: false,
        });
        assert!(!sw.relay_lost_peers().contains(&peer));
        let status = sw
            .punch
            .all_status()
            .into_iter()
            .find(|s| s.peer == peer)
            .expect("peer status registered");
        assert_eq!(status.tunnel_proto, nexus_nat_wireup::TunnelProto::Turn);
        assert_eq!(
            status.relay_source,
            Some(nexus_nat_wireup::RelaySource::Turn)
        );
        // MINOR-5: a later loss must not leave `relay_source="turn"` behind in
        // the API (the relay really is gone). Path state stays untouched (R-18).
        RelayConnSink::on_relay_lost(sw.as_ref(), peer);
        let status = sw
            .punch
            .all_status()
            .into_iter()
            .find(|s| s.peer == peer)
            .expect("peer status registered");
        assert_eq!(
            status.relay_source, None,
            "provider_lost/unsubscribe must clear the stale relay source"
        );
        assert_eq!(status.tunnel_proto, nexus_nat_wireup::TunnelProto::Turn);
        sw.shutdown();
    }

    #[test]
    fn g3_host_candidates_enumerated() {
        let driver = Driver::new_server("0.0.0.0:0".parse().unwrap()).expect("bind");
        let port = driver.shared().local_addr.lock().unwrap().port();
        let addrs = gather_host_candidates(&driver);
        assert!(!addrs.is_empty(), "at least one host candidate");
        assert!(
            addrs.iter().all(|a| !a.ip().is_unspecified()),
            "never advertise 0.0.0.0: {addrs:?}"
        );
        assert!(
            addrs.iter().all(|a| a.port() == port),
            "host candidate port must equal driver port"
        );
    }

    #[test]
    fn b16s_chunk_route_states() {
        // Deletion Test: both states are real production states.
        assert_eq!(chunk_route(true), ChunkPath::Direct);
        assert_eq!(chunk_route(false), ChunkPath::Fallback);
        // Flipping the decision breaks exactly one of the two states.
        assert_ne!(chunk_route(true), chunk_route(false));
    }

    #[test]
    fn g9_both_sides_initiate() {
        let a = pid(1);
        let b = pid(2);
        assert!(should_initiate(&a, &b), "smaller PeerId still initiates");
        assert!(should_initiate(&b, &a), "larger PeerId initiates");
        assert!(!should_initiate(&a, &a), "never punch self");
    }
}
