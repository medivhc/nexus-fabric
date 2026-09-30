//! Path/fabric linkage (S27).
//!
//! `PathLink` owns a [`PathManager`] plus the peer-name → [`FabricConn`]
//! map, and turns [`PathEvent::Switched`] into [`FabricConn::rebind()`]
//! calls. Dependency inversion: `nexus-path` only emits events and stays
//! free of any `nexus-fabric` implementation dependency; the glue lives
//! here in `nexus-projection`.
//!
//! Sync API, zero tokio. `pump()` is synchronous by design: the caller
//! decides which thread drives it (never the downlink hot path — `rebind()`
//! blocks until the new path is active).

use std::collections::HashMap;
use std::net::SocketAddr;

use nexus_fabric::FabricConn;
use nexus_path::{PathEvent, PathManager};

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
}

/// Owns a [`PathManager`] and drives [`FabricConn::rebind()`] on path
/// switches (S27).
pub struct PathLink {
    manager: PathManager,
    conns: HashMap<String, FabricConn>,
    /// Candidate remote addr → peer name, for resolving `Switched.to`.
    addr_to_peer: HashMap<SocketAddr, String>,
    stats: PathLinkStats,
}

impl PathLink {
    /// Create a link around an existing path manager.
    pub fn new(manager: PathManager) -> Self {
        Self {
            manager,
            conns: HashMap::new(),
            addr_to_peer: HashMap::new(),
            stats: PathLinkStats::default(),
        }
    }

    /// Register a peer's fabric connection.
    pub fn add_conn(&mut self, peer: &str, conn: FabricConn) {
        self.conns.insert(peer.to_string(), conn);
    }

    /// Map a candidate's remote address to a peer name, so `Switched.to`
    /// (which carries a [`nexus_path::CandidatePath`]) resolves to a conn.
    pub fn map_peer_addr(&mut self, peer: &str, remote: SocketAddr) {
        self.addr_to_peer.insert(remote, peer.to_string());
    }

    /// Access the owned path manager (to add/remove candidates, feed stats).
    pub fn manager_mut(&mut self) -> &mut PathManager {
        &mut self.manager
    }

    /// Linkage counters (S27).
    pub fn stats(&self) -> &PathLinkStats {
        &self.stats
    }

    /// Drain `poll_event()`; on `Switched{to, ..}` rebind the mapped peer's
    /// connection (S27). Blocking: `rebind()` waits until the new path is
    /// active (CID unchanged). Failures are counted and the old connection
    /// is kept usable; unmapped peers are counted and ignored.
    pub fn pump(&mut self) {
        while let Some(event) = self.manager.poll_event() {
            let PathEvent::Switched { to, .. } = event;
            let peer = match self.addr_to_peer.get(&to.remote_addr) {
                Some(peer) => peer.clone(),
                None => {
                    self.stats.path_rebind_no_conn += 1;
                    continue;
                }
            };
            match self.conns.get(&peer) {
                Some(conn) => match conn.rebind() {
                    Ok(()) => self.stats.path_rebinds += 1,
                    Err(_) => self.stats.path_rebind_errors += 1,
                },
                None => self.stats.path_rebind_no_conn += 1,
            }
        }
    }
}

/// `quic_pair()` needs real UDP loopback: tests probe for it and return
/// early when unavailable (sandbox EPERM); the true verification runs on
/// xc-pc-linux.
#[cfg(test)]
mod tests {
    use super::PathLink;
    use nexus_fabric::{ConnConfig, FabricConn, FabricListener};
    use nexus_path::{CandidatePath, PathConfig, PathKind, PathManager, PathStats};
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
            hysteresis_db: 0.0,
            switch_hold_ms: 0,
            probe_interval_ms: 60_000,
            ewma_alpha: 1.0,
            max_missed_probes: 1000,
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
        let mut link = PathLink::new(pm);
        link.add_conn("b", conn_a);
        link.map_peer_addr("b", addr(9001));
        link.map_peer_addr("b", addr(9002));
        link.manager_mut().remove_candidate(&active);
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
        let (conn_a, _conn_b) = quic_pair().expect("real QUIC pair");
        // Arm the failure path: close, then wait until the driver reaps the
        // connection (cmd_rebind returns Err(Closed) for reaped conns).
        conn_a.close(0, b"test");
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            if conn_a.rebind().is_err() {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "conn never reaped after close"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        let (pm, active) = manager_two_paths();
        let mut link = PathLink::new(pm);
        link.add_conn("b", conn_a);
        link.map_peer_addr("b", addr(9001));
        link.map_peer_addr("b", addr(9002));
        link.manager_mut().remove_candidate(&active);
        link.pump();
        assert_eq!(link.stats().path_rebinds, 0);
        assert_eq!(link.stats().path_rebind_errors, 1);
    }

    #[test]
    fn unmapped_peer_ignored_and_counted() {
        // S27: Switched for a peer with no conn mapping -> counted, ignored.
        let (pm, active) = manager_two_paths();
        let mut link = PathLink::new(pm);
        // Deliberately no add_conn / map_peer_addr.
        link.manager_mut().remove_candidate(&active);
        link.pump();
        assert_eq!(link.stats().path_rebind_no_conn, 1);
        assert_eq!(link.stats().path_rebinds, 0);
    }
}
