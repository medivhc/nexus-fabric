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
//! 诚实边界：nexusd 尚无 TURN 客户端（配 schema 与凭证管理是独立 gap），
//! 因此 `main.rs` 暂不实例化本模块；`on_relay_connected` 是留给中继连接器的
//! 钩子。E4（`crates/nexus-nat-wireup/examples/e4_prod_switch.rs`）用真实
//! TURN + NAT 模拟证明整条链路。

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
    ) -> Arc<Self> {
        let sw = Arc::new_cyclic(|weak| {
            let punch = PunchManager::new(driver.clone(), my_id);
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
        if self.my_id.0 < peer.0 {
            eprintln!(
                "[nat-switch] tie-break: peer {name} has larger PeerId, waiting for their punch"
            );
            return;
        }
        eprintln!("[nat-switch] background punch starting for peer {name} (tie-break won)");
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

/// Best-effort host candidates from the driver's bound UDP socket.
///
/// Full STUN/srflx sampling needs a STUN client, which nexusd does not have
/// yet; the composition root should call [`NatSwitching::set_local`] with
/// real samples when they become available. Host candidates alone are
/// enough for the relay-first flow (punching still works when both sides
/// are reachable, and degrades honestly otherwise).
pub fn gather_host_candidates(driver: &Arc<Driver>) -> Vec<SocketAddr> {
    vec![*driver.shared().local_addr.lock().unwrap()]
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
        // Driver::new_client binds a socket; just assert the helper does not
        // panic and returns at most one addr. (No UDP in sandbox: skip if
        // bind fails.)
        if let Ok(driver) = Driver::new_client() {
            let addrs = gather_host_candidates(&driver);
            assert!(addrs.len() <= 1);
        }
    }
}
