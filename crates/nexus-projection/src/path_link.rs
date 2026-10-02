//! Path/fabric linkage (S27).
//!
//! `PathLink` owns a [`PathManager`] plus the peer-name → [`FabricConn`]
//! map, and turns [`PathEvent::Switched`] into [`FabricConn::rebind()`]
//! calls. Dependency inversion: `nexus-path` only emits events and stays
//! free of any `nexus-fabric` implementation dependency; the glue lives
//! here in `nexus-projection`.
//!
//! NAT extension (D1): for peers with a hole-punched direct connection,
//! `PathLink` additionally manages per-peer [`PeerConns`] (relay +
//! optional direct [`ConnShared`], with an active marker). `Switched`
//! events for such peers flip the active connection instead of calling
//! `rebind()` — the two connections are distinct QUIC connections (different
//! CIDs), so address migration does not apply.
//!
//! Sync API, zero tokio. `pump()` is synchronous by design: the caller
//! decides which thread drives it (never the downlink hot path — `rebind()`
//! blocks until the new path is active).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use nexus_fabric::{ConnShared, FabricConn};
use nexus_path::{CandidatePath, PathEvent, PathKind, PathManager};

/// Counters for path/linkage behavior (S27: honest, same code for mock and
/// real connections).
#[derive(Debug, Default, Clone)]
pub struct PathLinkStats {
    /// Successful `rebind()` calls driven by `Switched` events.
    pub path_rebinds: u64,
    /// Failed `rebind()` calls; the old connection is left untouched (S2).
    pub path_rebind_errors: u64,
    /// `Switched` events with no mapped peer/conn; ignored, never panics.
    pub path_rebind_no_conn: u64,
    /// Successful active-connection switches for NAT peers (D1).
    pub path_active_switches: u64,
    /// `Switched` to Direct with no direct conn registered; active stays
    /// on Relay (defensive; should not happen in production).
    pub path_active_switch_no_direct: u64,
}

/// Which connection currently carries a NAT peer's production traffic (D1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveConn {
    /// The warm-backup relay connection (TURN or peer relay).
    Relay,
    /// The hole-punched direct connection.
    Direct,
}

/// Per-peer connections for NAT production switching (D1).
///
/// The relay connection is established first and stays as warm backup;
/// the direct connection appears after a successful hole punch. The
/// [`PathManager`] decides which is active via its normal candidate
/// scoring (D2); [`PathLink::pump`] flips [`active`](Self::active)
/// accordingly — never `rebind()`, because these are two distinct QUIC
/// connections.
///
/// Kind mapping (D2, frozen): `DirectP2P`→[`PathKind::Direct`],
/// `TurnRelay`→[`PathKind::Turn`], `PeerRelay`→[`PathKind::Mesh`].
/// Both `Turn` and `Mesh` candidates resolve to the relay connection;
/// only `Direct` resolves to the direct connection.
pub struct PeerConns {
    /// The relay connection (always present; warm backup).
    pub relay: Arc<ConnShared>,
    /// The hole-punched direct connection ([`None`] until punch succeeds).
    pub direct: Option<Arc<ConnShared>>,
    /// Which connection currently carries production traffic.
    pub active: ActiveConn,
}

/// Owns a [`PathManager`] and drives [`FabricConn::rebind()`] on path
/// switches (S27), plus NAT per-peer active-connection switching (D1).
///
/// The manager is shared (`Arc<Mutex<>>`) with the quality monitor
/// (`nexus-nat-quality::QualityMonitor`), which supplies `on_stats` and —
/// in production — is the sole drainer of [`PathManager::poll_event`]
/// (see [`pump`](Self::pump)). Sharing by `Arc` (not `&mut`) is what lets
/// the monitor thread and the composition root use the same manager.
pub struct PathLink {
    manager: Arc<Mutex<PathManager>>,
    conns: HashMap<String, FabricConn>,
    /// NAT peers: peer name → multi-connection state (D1).
    nat_conns: HashMap<String, PeerConns>,
    /// Candidate remote addr → peer name, for resolving `Switched.to`.
    addr_to_peer: HashMap<SocketAddr, String>,
    stats: PathLinkStats,
}

impl PathLink {
    /// Create a link around a shared path manager. The same `Arc` is handed
    /// to `QualityMonitor::new` so supply (monitor) and selection (link)
    /// operate on one manager.
    pub fn new(manager: Arc<Mutex<PathManager>>) -> Self {
        Self {
            manager,
            conns: HashMap::new(),
            nat_conns: HashMap::new(),
            addr_to_peer: HashMap::new(),
            stats: PathLinkStats::default(),
        }
    }

    /// Register a peer's fabric connection.
    pub fn add_conn(&mut self, peer: &str, conn: FabricConn) {
        self.conns.insert(peer.to_string(), conn);
    }

    /// Register a NAT peer's relay connection (D1).
    ///
    /// Also registers the relay as a [`PathManager`] candidate:
    /// `kind` is [`PathKind::Turn`] for a TURN relay or [`PathKind::Mesh`]
    /// for a peer relay (D2 mapping). `remote` is the candidate key used
    /// for stats reports (see [`PathManager::on_stats`]).
    pub fn register_nat_relay(
        &mut self,
        peer: &str,
        relay: Arc<ConnShared>,
        kind: PathKind,
        local: SocketAddr,
        remote: SocketAddr,
    ) {
        debug_assert!(
            matches!(kind, PathKind::Turn | PathKind::Mesh),
            "relay candidate kind must be Turn or Mesh, got {kind:?}"
        );
        self.manager.lock().unwrap().add_candidate(CandidatePath {
            kind,
            local_addr: local,
            remote_addr: remote,
            cost: if kind == PathKind::Turn { 5.0 } else { 2.0 },
        });
        self.addr_to_peer.insert(remote, peer.to_string());
        self.nat_conns.insert(
            peer.to_string(),
            PeerConns {
                relay,
                direct: None,
                active: ActiveConn::Relay,
            },
        );
    }

    /// Register a NAT peer's hole-punched direct connection (D1).
    ///
    /// Registers it as a [`PathKind::Direct`] candidate. The [`PathManager`]
    /// will only switch to it once its score beats the relay by the frozen
    /// hysteresis (D2) — punch success alone never flips [`active`](PeerConns::active).
    pub fn register_nat_direct(
        &mut self,
        peer: &str,
        direct: Arc<ConnShared>,
        local: SocketAddr,
        remote: SocketAddr,
    ) {
        self.manager.lock().unwrap().add_candidate(CandidatePath {
            kind: PathKind::Direct,
            local_addr: local,
            remote_addr: remote,
            cost: 0.0,
        });
        self.addr_to_peer.insert(remote, peer.to_string());
        if let Some(conns) = self.nat_conns.get_mut(peer) {
            conns.direct = Some(direct);
        }
        // If the peer has no relay registration yet, the direct candidate
        // stays registered but unmapped; the relay registration (which must
        // come first in production) will map it. Defensive: never panic.
    }

    /// Which connection is currently active for a NAT peer (D1).
    /// [`None`] for unknown peers or legacy (non-NAT) peers.
    pub fn nat_active(&self, peer: &str) -> Option<ActiveConn> {
        self.nat_conns.get(peer).map(|c| c.active)
    }

    /// Access a NAT peer's connections (for the data path to read the
    /// active connection). [`None`] for unknown / legacy peers.
    pub fn nat_conns(&self, peer: &str) -> Option<&PeerConns> {
        self.nat_conns.get(peer)
    }

    /// Map a candidate's remote address to a peer name, so `Switched.to`
    /// (which carries a [`nexus_path::CandidatePath`]) resolves to a conn.
    pub fn map_peer_addr(&mut self, peer: &str, remote: SocketAddr) {
        self.addr_to_peer.insert(remote, peer.to_string());
    }

    /// Access the shared path manager (to add/remove candidates, feed stats).
    /// The composition root clones this `Arc` into `QualityMonitor::new`.
    pub fn manager(&self) -> Arc<Mutex<PathManager>> {
        Arc::clone(&self.manager)
    }

    /// Linkage counters (S27).
    pub fn stats(&self) -> &PathLinkStats {
        &self.stats
    }

    /// Stats supply + event drain contract (T1↔T2 alignment, 2026-10-02):
    ///
    /// - **Supply**: `nexus-nat-quality::QualityMonitor` owns one probe
    ///   endpoint per path; every tick it calls `on_stats(&addr, stats)`
    ///   on the shared manager (`rtt_ms` = quinn real RTT, `loss_rate` =
    ///   probe sliding window). A candidate with no stats has unknown score
    ///   (S7) and never participates in selection — so a freshly punched
    ///   direct path does NOT cause a switch until measured (frozen: punch
    ///   only grants candidacy).
    /// - **Candidate registration** happens in
    ///   [`register_nat_relay`](Self::register_nat_relay) /
    ///   [`register_nat_direct`](Self::register_nat_direct); the monitor's
    ///   `add_path` re-registers the same key, which is idempotent
    ///   (`PathManager::add_candidate` keeps `added_at`; the EWMA reset is
    ///   harmless because production calls both back-to-back before any
    ///   stats arrive).
    /// - **Single drainer**: in production the monitor's tick drains
    ///   `poll_event()` and forwards to its `PathEventSink`; the sink (built
    ///   by the composition root, holding `Arc<Mutex<PathLink>>`) delegates
    ///   to [`handle_event`](Self::handle_event). Do NOT call `pump()` when
    ///   a monitor is attached — two drainers would race for events.
    ///   `pump()` remains for contexts without a monitor (unit tests,
    ///   legacy manual driving).
    ///
    /// On `Switched{to, ..}` ([`handle_event`](Self::handle_event)):
    /// - NAT peer (in `nat_conns`): flip the active connection —
    ///   [`PathKind::Direct`] → Direct (if registered), [`PathKind::Turn`] |
    ///   [`PathKind::Mesh`] → Relay. [`PathKind::Proxy`] is ignored (NAT
    ///   never registers proxy candidates).
    /// - Legacy peer (in `conns`): `rebind()` the mapped [`FabricConn`]
    ///   (S27; blocking until the new path is active, CID unchanged).
    ///   Failures are counted and the old connection is kept usable;
    ///   unmapped peers are counted and ignored.
    pub fn pump(&mut self) {
        loop {
            let event = self.manager.lock().unwrap().poll_event();
            match event {
                Some(e) => self.handle_event(e),
                None => break,
            }
        }
    }

    /// Handle one [`PathEvent::Switched`] (shared by [`pump`](Self::pump)
    /// and the production monitor sink). `pub` so the composition root's
    /// `PathEventSink` impl can delegate without reimplementing the
    /// NAT-flip / legacy-rebind policy.
    ///
    /// TEMPORARY (T1, 2026-10-03): `PathEvent::Adopted` (nexus-path D4) is
    /// destructured here only so the workspace compiles; the `to`-side is
    /// handled identically to `Switched`. T3 owns the real Adopted policy
    /// (flip vs rebind) and will refine this on rebase.
    pub fn handle_event(&mut self, event: PathEvent) {
        let to: CandidatePath = match event {
            PathEvent::Switched { to, .. } => to,
            PathEvent::Adopted { to } => to,
        };
        let peer = match self.addr_to_peer.get(&to.remote_addr) {
            Some(peer) => peer.clone(),
            None => {
                self.stats.path_rebind_no_conn += 1;
                return;
            }
        };
        // D1: NAT peer -> flip active connection, never rebind.
        if let Some(conns) = self.nat_conns.get_mut(&peer) {
            match to.kind {
                PathKind::Direct => {
                    if conns.direct.is_some() {
                        conns.active = ActiveConn::Direct;
                        self.stats.path_active_switches += 1;
                    } else {
                        // Defensive: candidate raced ahead of conn handoff.
                        self.stats.path_active_switch_no_direct += 1;
                    }
                }
                PathKind::Turn | PathKind::Mesh => {
                    conns.active = ActiveConn::Relay;
                    self.stats.path_active_switches += 1;
                }
                PathKind::Proxy => {
                    // NAT never registers proxy candidates; ignore.
                }
            }
            return;
        }
        // S27: legacy single-connection peer -> rebind.
        match self.conns.get(&peer) {
            Some(conn) => match conn.rebind() {
                Ok(()) => self.stats.path_rebinds += 1,
                Err(_) => self.stats.path_rebind_errors += 1,
            },
            None => self.stats.path_rebind_no_conn += 1,
        }
    }
}

/// `quic_pair()` needs real UDP loopback: tests probe for it and return
/// early when unavailable (sandbox EPERM); the true verification runs on
/// xc-pc-linux.
#[cfg(test)]
mod tests {
    use super::ActiveConn;
    use super::PathLink;
    use nexus_fabric::{ConnConfig, FabricConn, FabricListener};
    use nexus_path::{CandidatePath, PathConfig, PathKind, PathManager, PathStats, RaceBudget};
    use std::net::SocketAddr;
    use std::time::Duration;

    fn addr(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}").parse().unwrap()
    }

    fn candidate(port: u16) -> CandidatePath {
        CandidatePath {
            kind: PathKind::Direct,
            local_addr: addr(8000),
            remote_addr: addr(port),
            cost: 0.0,
        }
    }

    fn test_config() -> PathConfig {
        PathConfig {
            hysteresis_pct: 0.0,
            switch_hold_ms: 0,
            probe_interval_ms: 60_000,
            ewma_alpha: 1.0,
            max_missed_probes: 1000,
            race_budget: RaceBudget::default(),
        }
    }

    fn stats(rtt_ms: u64) -> PathStats {
        PathStats {
            rtt_ms: Some(rtt_ms),
            loss_rate: Some(0.0),
            ..Default::default()
        }
    }

    /// Direct capability probe: can this host actually send UDP loopback?
    /// The sandbox blocks it at OS level (EPERM on sendto). Tests that need
    /// real QUIC return early (pass-as-skip) when it is unavailable; the
    /// true verification runs on xc-pc-linux.
    fn udp_loopback_available() -> bool {
        use std::net::UdpSocket;
        let a = match UdpSocket::bind("127.0.0.1:0") {
            Ok(s) => s,
            Err(_) => return false,
        };
        let b = match UdpSocket::bind("127.0.0.1:0") {
            Ok(s) => s,
            Err(_) => return false,
        };
        let bp = match b.local_addr() {
            Ok(addr) => addr.port(),
            Err(_) => return false,
        };
        a.send_to(b"probe", format!("127.0.0.1:{bp}")).is_ok()
    }

    /// Real QUIC pair over UDP loopback.
    fn quic_pair() -> Result<(FabricConn, FabricConn), String> {
        let listener = FabricListener::bind(addr(0)).map_err(|e| format!("bind: {e}"))?;
        let server_peer = listener.peer_id();
        let server_addr = listener
            .local_addr()
            .map_err(|e| format!("local_addr: {e}"))?;
        let accept =
            std::thread::spawn(move || listener.accept().map_err(|e| format!("accept: {e}")));
        let conn_a = FabricConn::connect(
            server_peer,
            &ConnConfig {
                addrs: vec![server_addr],
                handshake_timeout: Duration::from_secs(10),
            },
        )
        .map_err(|e| format!("connect: {e}"))?;
        let conn_b = accept
            .join()
            .map_err(|_| "accept thread panicked".to_string())??;
        Ok((conn_a, conn_b))
    }

    /// Two scored candidates in the manager; returns the manager and the
    /// currently active remote addr.
    fn manager_two_paths() -> (PathManager, SocketAddr) {
        let mut pm = PathManager::new(test_config());
        pm.add_candidate(candidate(9001));
        pm.add_candidate(candidate(9002));
        pm.on_stats(&addr(9001), stats(10));
        pm.on_stats(&addr(9002), stats(20));
        while pm.poll_event().is_some() {}
        let active = pm.current_path().unwrap().remote_addr;
        (pm, active)
    }

    #[test]
    fn pump_drives_rebind_on_switch() {
        // S27: Switched -> mapped peer's FabricConn::rebind(), counted.
        if !udp_loopback_available() {
            return; // sandbox: UDP blocked, true verification on xc-pc-linux
        }
        let (conn_a, _conn_b) = quic_pair().expect("real QUIC pair");
        let (pm, active) = manager_two_paths();
        let mut link = PathLink::new(Arc::new(Mutex::new(pm)));
        link.add_conn("b", conn_a);
        link.map_peer_addr("b", addr(9001));
        link.map_peer_addr("b", addr(9002));
        link.manager().lock().unwrap().remove_candidate(&active);
        link.pump();
        assert_eq!(link.stats().path_rebinds, 1);
        assert_eq!(link.stats().path_rebind_errors, 0);
        assert_eq!(link.stats().path_rebind_no_conn, 0);
    }

    #[test]
    fn rebind_failure_keeps_connection() {
        // S27: rebind() failure -> counted, old connection untouched, no panic.
        if !udp_loopback_available() {
            return; // sandbox: UDP blocked, true verification on xc-pc-linux
        }
        let (conn_a, conn_b) = quic_pair().expect("real QUIC pair");
        // Arm the failure path: the peer closes, A's driver reaps the conn
        // (~0.5s), after which cmd_rebind returns Err(Closed).
        // (Local close() alone does not reap: the driver keeps the conn in
        // live; probed 2026-09-30.)
        conn_b.close(0, b"test");
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            if conn_a.rebind().is_err() {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "conn never reaped after peer close"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        let (pm, active) = manager_two_paths();
        let mut link = PathLink::new(Arc::new(Mutex::new(pm)));
        link.add_conn("b", conn_a);
        link.map_peer_addr("b", addr(9001));
        link.map_peer_addr("b", addr(9002));
        link.manager().lock().unwrap().remove_candidate(&active);
        link.pump();
        assert_eq!(link.stats().path_rebinds, 0);
        assert_eq!(link.stats().path_rebind_errors, 1);
    }

    #[test]
    fn unmapped_peer_ignored_and_counted() {
        // S27: Switched for a peer with no conn mapping -> counted, ignored.
        let (pm, active) = manager_two_paths();
        let mut link = PathLink::new(Arc::new(Mutex::new(pm)));
        // Deliberately no add_conn / map_peer_addr.
        link.manager().lock().unwrap().remove_candidate(&active);
        link.pump();
        assert_eq!(link.stats().path_rebind_no_conn, 1);
        assert_eq!(link.stats().path_rebinds, 0);
    }

    // ------------------------------------------------------------------
    // NAT production switching (D1): per-peer multi-connection active
    // selection. RED: these tests target the new PeerConns API, which
    // does not exist yet.
    // ------------------------------------------------------------------

    use nexus_fabric::{ConnShared, Driver};
    use std::sync::{Arc, Mutex};

    /// Real Arc<ConnShared> pair over UDP loopback (Driver-level, bypasses
    /// FabricConn which does not expose its inner Arc).
    fn conn_shared_pair() -> Option<(Arc<ConnShared>, Arc<ConnShared>)> {
        if !udp_loopback_available() {
            return None; // sandbox: UDP blocked, true verification on xc-pc-linux
        }
        let server = Driver::new_server(addr(0)).ok()?;
        let server_peer = server.shared().peer_id?;
        let server_addr = *server.shared().local_addr.lock().unwrap();
        let accept = std::thread::spawn(move || server.accept_conn());
        let client = Driver::new_client().ok()?;
        let client_conn = client
            .connect(server_peer, server_addr, Duration::from_secs(10))
            .ok()?;
        let server_conn = accept.join().ok()?.ok()?;
        Some((client_conn, server_conn))
    }

    /// D1: registering relay + direct creates Turn + Direct candidates;
    /// active starts on Relay.
    #[test]
    fn nat_registers_candidates_and_starts_on_relay() {
        let (relay, direct) = match conn_shared_pair() {
            Some(p) => p,
            None => return,
        };
        let mut link = PathLink::new(Arc::new(Mutex::new(PathManager::new(test_config()))));
        link.register_nat_relay("peer-a", relay, PathKind::Turn, addr(8000), addr(9001));
        assert_eq!(link.nat_active("peer-a"), Some(ActiveConn::Relay));
        // Direct not yet registered: no Direct candidate.
        assert!(link.manager().lock().unwrap().score(&addr(9002)).is_none());
        link.register_nat_direct("peer-a", direct, addr(8000), addr(9002));
        // Both candidates exist; relay still active until stats + switch.
        assert_eq!(link.nat_active("peer-a"), Some(ActiveConn::Relay));
    }

    /// D1: Switched{to: Direct} flips active to Direct (not a rebind).
    #[test]
    fn nat_switch_to_direct_flips_active() {
        let (relay, direct) = match conn_shared_pair() {
            Some(p) => p,
            None => return,
        };
        let mut link = PathLink::new(Arc::new(Mutex::new(PathManager::new(test_config()))));
        link.register_nat_relay("peer-a", relay, PathKind::Turn, addr(8000), addr(9001));
        link.register_nat_direct("peer-a", direct, addr(8000), addr(9002));
        // Direct scores much better than TURN: feed stats and drive the
        // normal event pipeline (pump -> handle_event). The manager emits
        // Switched{to: Direct} during setup; discarding it with a bare
        // poll_event() drain would leave PathLink stuck on Relay.
        link.manager().lock().unwrap().on_stats(
            &addr(9001),
            PathStats {
                rtt_ms: Some(300),
                loss_rate: Some(0.01),
                ..Default::default()
            },
        );
        link.manager().lock().unwrap().on_stats(
            &addr(9002),
            PathStats {
                rtt_ms: Some(50),
                loss_rate: Some(0.0),
                ..Default::default()
            },
        );
        link.pump();
        assert_eq!(link.nat_active("peer-a"), Some(ActiveConn::Direct));
        assert_eq!(link.stats().path_active_switches, 1);
        // Degrading the (already inactive) relay further must not move
        // active away from Direct and must not emit new switch events.
        for _ in 0..5 {
            link.manager().lock().unwrap().on_stats(
                &addr(9001),
                PathStats {
                    rtt_ms: Some(2000),
                    loss_rate: Some(0.5),
                    ..Default::default()
                },
            );
            link.manager().lock().unwrap().on_stats(
                &addr(9002),
                PathStats {
                    rtt_ms: Some(50),
                    loss_rate: Some(0.0),
                    ..Default::default()
                },
            );
        }
        link.pump();
        assert_eq!(link.nat_active("peer-a"), Some(ActiveConn::Direct));
        assert_eq!(link.stats().path_active_switches, 1);
        // Legacy rebind path untouched.
        assert_eq!(link.stats().path_rebinds, 0);
    }

    /// D1: Switched{to: Turn} flips active back to Relay.
    #[test]
    fn nat_switch_back_to_relay() {
        let (relay, direct) = match conn_shared_pair() {
            Some(p) => p,
            None => return,
        };
        let mut link = PathLink::new(Arc::new(Mutex::new(PathManager::new(test_config()))));
        link.register_nat_relay("peer-a", relay, PathKind::Turn, addr(8000), addr(9001));
        link.register_nat_direct("peer-a", direct, addr(8000), addr(9002));
        // Direct active first: feed stats and drive the normal event
        // pipeline (pump -> handle_event), not a bare poll_event() drain.
        link.manager().lock().unwrap().on_stats(
            &addr(9001),
            PathStats {
                rtt_ms: Some(300),
                loss_rate: Some(0.0),
                ..Default::default()
            },
        );
        link.manager().lock().unwrap().on_stats(
            &addr(9002),
            PathStats {
                rtt_ms: Some(50),
                loss_rate: Some(0.0),
                ..Default::default()
            },
        );
        link.pump();
        assert_eq!(link.nat_active("peer-a"), Some(ActiveConn::Direct));
        assert_eq!(link.stats().path_active_switches, 1);
        // Now degrade direct -> back to relay.
        for _ in 0..5 {
            link.manager().lock().unwrap().on_stats(
                &addr(9002),
                PathStats {
                    rtt_ms: Some(2000),
                    loss_rate: Some(0.5),
                    ..Default::default()
                },
            );
            link.manager().lock().unwrap().on_stats(
                &addr(9001),
                PathStats {
                    rtt_ms: Some(300),
                    loss_rate: Some(0.0),
                    ..Default::default()
                },
            );
        }
        link.pump();
        assert_eq!(link.nat_active("peer-a"), Some(ActiveConn::Relay));
        assert_eq!(link.stats().path_active_switches, 2);
    }

    /// D1: Switched to Direct with no direct conn registered -> counted,
    /// active stays on Relay (defensive; should not happen in production).
    #[test]
    fn nat_switch_to_direct_without_conn_stays_on_relay() {
        let (relay, _other) = match conn_shared_pair() {
            Some(p) => p,
            None => return,
        };
        let mut link = PathLink::new(Arc::new(Mutex::new(PathManager::new(test_config()))));
        link.register_nat_relay("peer-a", relay, PathKind::Turn, addr(8000), addr(9001));
        // Manually add a Direct candidate with no direct conn (simulates
        // a race between candidate registration and conn handoff).
        link.manager().lock().unwrap().add_candidate(CandidatePath {
            kind: PathKind::Direct,
            local_addr: addr(8000),
            remote_addr: addr(9002),
            cost: 0.0,
        });
        link.map_peer_addr("peer-a", addr(9002));
        link.manager().lock().unwrap().on_stats(
            &addr(9001),
            PathStats {
                rtt_ms: Some(2000),
                loss_rate: Some(0.5),
                ..Default::default()
            },
        );
        link.manager().lock().unwrap().on_stats(
            &addr(9002),
            PathStats {
                rtt_ms: Some(50),
                loss_rate: Some(0.0),
                ..Default::default()
            },
        );
        link.pump();
        assert_eq!(link.nat_active("peer-a"), Some(ActiveConn::Relay));
        assert_eq!(link.stats().path_active_switch_no_direct, 1);
    }
}
