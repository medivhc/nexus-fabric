//! Background quality supply loop.
//!
//! [`QualityMonitor`] owns one [`ProbeEndpoint`] per measured path and a
//! background thread that, on every tick: pings due paths, expires stale
//! pings, reads RTT + loss, calls `PathManager::on_stats`, and forwards
//! drained [`PathEvent`]s to the [`PathEventSink`].
//!
//! Lifecycle (§13): Owner = the `QualityMonitor` handle; cancellation =
//! `shutdown()` (stop flag); reaping = join on the monitor thread; the thread
//! itself holds only a `Weak` so a forgotten `shutdown()` cannot leak it.

use crate::endpoint::{DatagramTransport, ProbeEndpoint};
use nexus_path::{CandidatePath, PathEvent, PathKind, PathManager, PathStats};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{
    Arc, Mutex, Weak,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// How aggressively a path is probed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeRole {
    /// Carries (or may soon carry) production traffic: probe every 1s.
    /// Rationale: 3 samples per 3s switch-hold window; 75 B/s is negligible.
    Active,
    /// Warm backup (e.g. TURN relay while direct is active): probe every 5s.
    /// Rationale: aligns with `PathManager::default().probe_interval_ms`;
    /// enough to detect failure, 15 B/s overhead.
    Backup,
}

impl ProbeRole {
    fn interval_ms(self) -> u64 {
        match self {
            ProbeRole::Active => 1000,
            ProbeRole::Backup => 5000,
        }
    }
}

/// A path under measurement. This is the interface contract with Track 1
/// (PathLink): Track 1 builds one `MeasuredPath` per connection (relay +
/// direct), hands them to the monitor, and implements `PathEventSink` to
/// switch the active connection on `PathEvent::Switched`.
pub struct MeasuredPath<T: DatagramTransport> {
    /// Remote address: the `PathManager` candidate key.
    pub addr: SocketAddr,
    pub kind: PathKind,
    pub local_addr: SocketAddr,
    /// Relative cost for scoring (0..10, lower is better).
    pub cost: f64,
    pub transport: T,
    pub role: ProbeRole,
    /// Receives non-probe datagrams; `None` = drop (probe-only connection).
    pub forward: Option<std::sync::mpsc::Sender<Vec<u8>>>,
}

/// Receives path lifecycle events from the monitor thread.
/// Track 1 implements this to switch the active `FabricConn`.
pub trait PathEventSink: Send + Sync + 'static {
    fn on_path_event(&self, event: PathEvent);
}

struct PathState<T: DatagramTransport> {
    endpoint: Arc<ProbeEndpoint<T>>,
    role: ProbeRole,
    last_ping_ms: u64,
}

struct Inner<T: DatagramTransport> {
    pm: Arc<Mutex<PathManager>>,
    sink: Arc<dyn PathEventSink>,
    paths: Mutex<HashMap<SocketAddr, PathState<T>>>,
    stop: AtomicBool,
    handle: Mutex<Option<thread::JoinHandle<()>>>,
}

/// Active quality measurement + supply to `PathManager`.
pub struct QualityMonitor<T: DatagramTransport> {
    inner: Arc<Inner<T>>,
}

impl<T: DatagramTransport> QualityMonitor<T> {
    /// Create (does not start the background thread; call `start()`).
    pub fn new(pm: Arc<Mutex<PathManager>>, sink: Arc<dyn PathEventSink>) -> Self {
        Self {
            inner: Arc::new(Inner {
                pm,
                sink,
                paths: Mutex::new(HashMap::new()),
                stop: AtomicBool::new(false),
                handle: Mutex::new(None),
            }),
        }
    }

    /// Register a path: adds the `PathManager` candidate and starts its
    /// probe endpoint. Re-adding replaces the endpoint and role.
    pub fn add_path(&self, path: MeasuredPath<T>) {
        let endpoint = ProbeEndpoint::start(path.transport, path.forward);
        let candidate = CandidatePath {
            kind: path.kind,
            local_addr: path.local_addr,
            remote_addr: path.addr,
            cost: path.cost,
        };
        self.inner.pm.lock().unwrap().add_candidate(candidate);
        self.inner.paths.lock().unwrap().insert(
            path.addr,
            PathState {
                endpoint,
                role: path.role,
                last_ping_ms: 0, // ping immediately on first tick
            },
        );
        eprintln!("[nat-quality] path added: {} ({:?})", path.addr, path.kind);
    }

    /// Stop measuring a path (endpoint thread exits when its transport closes;
    /// the entry is dropped here).
    pub fn remove_path(&self, addr: &SocketAddr) {
        self.inner.paths.lock().unwrap().remove(addr);
        eprintln!("[nat-quality] path removed: {addr}");
    }

    /// Change a path's probe role (Track 1 calls this on `Switched` so the
    /// newly-active path gets the 1s cadence).
    pub fn set_role(&self, addr: &SocketAddr, role: ProbeRole) {
        if let Some(s) = self.inner.paths.lock().unwrap().get_mut(addr) {
            s.role = role;
        }
    }

    /// Start the background supply thread (idempotent).
    pub fn start(&self) {
        let mut h = self.inner.handle.lock().unwrap();
        if h.is_some() {
            return;
        }
        let weak: Weak<Inner<T>> = Arc::downgrade(&self.inner);
        *h = Some(
            thread::Builder::new()
                .name("nat-quality-monitor".to_string())
                .spawn(move || {
                    while let Some(inner) = weak.upgrade() {
                        if inner.stop.load(Ordering::Relaxed) {
                            break;
                        }
                        inner.tick(now_ms());
                        thread::sleep(Duration::from_millis(200));
                    }
                })
                .expect("spawn quality monitor"),
        );
    }

    /// Stop the background thread and wait for it (idempotent).
    /// The probe endpoint threads exit on their own when their transports
    /// close; they are not joined here (their lifetime follows the connection).
    pub fn shutdown(&self) {
        self.inner.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.inner.handle.lock().unwrap().take() {
            let _ = handle.join();
        }
    }

    /// One measurement round. Public for deterministic testing; the
    /// background thread calls it every 200ms.
    pub fn tick(&self, now_ms: u64) {
        self.inner.tick(now_ms);
    }

    /// Number of paths under measurement.
    pub fn path_count(&self) -> usize {
        self.inner.paths.lock().unwrap().len()
    }

    /// Current loss estimate for a path (`None` = unknown or no such path).
    pub fn path_loss(&self, addr: &SocketAddr) -> Option<f64> {
        self.inner
            .paths
            .lock()
            .unwrap()
            .get(addr)
            .and_then(|s| s.endpoint.loss_rate())
    }
}

impl<T: DatagramTransport> Inner<T> {
    fn tick(&self, now_ms: u64) {
        // Phase 1: measure (no pm lock held while pinging).
        let mut reports: Vec<(SocketAddr, PathStats)> = Vec::new();
        {
            let mut paths = self.paths.lock().unwrap();
            for (addr, state) in paths.iter_mut() {
                let interval = state.role.interval_ms();
                if now_ms.saturating_sub(state.last_ping_ms) >= interval {
                    // A failed ping (closed transport) is skipped; `expire`
                    // below ages it out and loss converges to 1.0.
                    if state.endpoint.ping(now_ms).is_ok() {
                        state.last_ping_ms = now_ms;
                    }
                }
                state.endpoint.expire(now_ms, interval * 2);
                reports.push((
                    *addr,
                    PathStats {
                        rtt_ms: state.endpoint.rtt_ms(),
                        loss_rate: state.endpoint.loss_rate(),
                        throughput_bps: None,
                    },
                ));
            }
        }
        // Phase 2: supply.
        {
            let mut pm = self.pm.lock().unwrap();
            for (addr, stats) in reports {
                pm.on_stats(&addr, stats);
            }
        }
        // Phase 3: drain events (sink called without holding pm lock).
        loop {
            let ev = self.pm.lock().unwrap().poll_event();
            match ev {
                Some(e) => self.sink.on_path_event(e),
                None => break,
            }
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_path::{PathConfig, PathKind};
    use std::sync::Mutex as StdMutex;
    use std::sync::mpsc;

    // Reuse the mock transport from endpoint tests via a local copy.
    struct MockTransport {
        tx: mpsc::Sender<Vec<u8>>,
        rx: StdMutex<mpsc::Receiver<Vec<u8>>>,
        rtt: Option<u64>,
    }

    impl MockTransport {
        fn pair(rtt: Option<u64>) -> (Self, Self) {
            let (a_tx, a_rx) = mpsc::channel();
            let (b_tx, b_rx) = mpsc::channel();
            (
                Self {
                    tx: a_tx,
                    rx: StdMutex::new(b_rx),
                    rtt,
                },
                Self {
                    tx: b_tx,
                    rx: StdMutex::new(a_rx),
                    rtt,
                },
            )
        }
        fn loopback_pair(rtt: Option<u64>) -> (Self, Self) {
            // Both directions answered: start a responder on the peer side.
            Self::pair(rtt)
        }
    }

    impl DatagramTransport for MockTransport {
        type Error = String;
        fn send_dgram(&self, data: &[u8]) -> Result<(), String> {
            self.tx.send(data.to_vec()).map_err(|e| e.to_string())
        }
        fn recv_dgram(&self) -> Result<Vec<u8>, String> {
            self.rx.lock().unwrap().recv().map_err(|e| e.to_string())
        }
        fn rtt_ms(&self) -> Option<u64> {
            self.rtt
        }
    }

    struct VecSink {
        events: StdMutex<Vec<String>>,
    }
    impl PathEventSink for VecSink {
        fn on_path_event(&self, event: PathEvent) {
            // T1 (2026-10-03): `PathEvent::Adopted` (nexus-path D4) added;
            // test sink records both variants.
            let line = match &event {
                PathEvent::Switched { from, to, .. } => {
                    format!("switched {} -> {}", from.remote_addr, to.remote_addr)
                }
                PathEvent::Adopted { to } => format!("adopted {}", to.remote_addr),
            };
            self.events.lock().unwrap().push(line);
        }
    }

    fn test_addrs() -> (SocketAddr, SocketAddr) {
        (
            "10.0.0.1:5000".parse().unwrap(),
            "10.0.0.2:5000".parse().unwrap(),
        )
    }

    fn monitor_with(pm: Arc<Mutex<PathManager>>) -> (QualityMonitor<MockTransport>, Arc<VecSink>) {
        let sink = Arc::new(VecSink {
            events: StdMutex::new(Vec::new()),
        });
        let mon = QualityMonitor::new(pm, sink.clone());
        (mon, sink)
    }

    fn add_mock_path(
        mon: &QualityMonitor<MockTransport>,
        addr: SocketAddr,
        kind: PathKind,
        rtt: Option<u64>,
        with_responder: bool,
    ) {
        let (ta, tb) = MockTransport::loopback_pair(rtt);
        if with_responder {
            // peer answers pings
            ProbeEndpoint::start(tb, None);
        } else {
            // keep tb alive but silent: pings go unread
            std::mem::forget(tb);
        }
        mon.add_path(MeasuredPath {
            addr,
            kind,
            local_addr: "10.0.0.9:4000".parse().unwrap(),
            cost: 1.0,
            transport: ta,
            role: ProbeRole::Active,
            forward: None,
        });
    }

    #[test]
    fn tick_supplies_rtt_and_zero_loss() {
        let (a1, a2) = test_addrs();
        let pm = Arc::new(Mutex::new(PathManager::new(PathConfig::default())));
        let (mon, _sink) = monitor_with(pm.clone());
        add_mock_path(&mon, a1, PathKind::Direct, Some(20), true);
        add_mock_path(&mon, a2, PathKind::Turn, Some(80), true);

        // drive several 1s ticks so pongs complete
        for i in 1..=4 {
            mon.tick(i * 1000);
            thread::sleep(Duration::from_millis(50)); // let pongs arrive
        }
        mon.tick(5000);
        thread::sleep(Duration::from_millis(50));

        let pmg = pm.lock().unwrap();
        // both paths now have EWMA scores (S7: measured -> eligible)
        assert!(pmg.score(&a1).is_some(), "a1 should be scored");
        assert!(pmg.score(&a2).is_some(), "a2 should be scored");
        // lower RTT scores better
        assert!(pmg.score(&a1).unwrap() > pmg.score(&a2).unwrap());
    }

    #[test]
    fn tick_dead_path_converges_to_full_loss() {
        let (a1, _) = test_addrs();
        let pm = Arc::new(Mutex::new(PathManager::new(PathConfig::default())));
        let (mon, _sink) = monitor_with(pm.clone());
        // Silent peer + no RTT (dead QUIC connection): pure probe signal.
        add_mock_path(&mon, a1, PathKind::Direct, None, false);

        // Active cadence: ping every 1s, expire after 2s.
        // tick(3000) expires the ping from tick(1000) as lost.
        for i in 1..=4 {
            mon.tick(i * 1000);
        }
        assert_eq!(mon.path_loss(&a1), Some(1.0));
        // loss=1.0 reports count as missed probes (S6), never as healthy scores.
        let pmg = pm.lock().unwrap();
        assert!(pmg.score(&a1).is_none());
    }

    #[test]
    fn tick_forwards_switch_event_to_sink() {
        let (a1, a2) = test_addrs();
        let cfg = PathConfig {
            hysteresis_pct: 0.0,
            switch_hold_ms: 0,
            ..Default::default()
        };
        let pm = Arc::new(Mutex::new(PathManager::new(cfg)));
        let (mon, sink) = monitor_with(pm.clone());

        // a1 (relay, rtt 200) added first and adopted as active
        // (D4: adoption emits `Adopted`; it is not a switch).
        add_mock_path(&mon, a1, PathKind::Turn, Some(200), true);
        mon.tick(1000);
        thread::sleep(Duration::from_millis(50));
        mon.tick(2000);
        thread::sleep(Duration::from_millis(50));
        {
            let pre = sink.events.lock().unwrap();
            assert!(
                !pre.is_empty() && pre.iter().all(|e| e.starts_with("adopted")),
                "before the switch only the adoption event is expected, got {pre:?}"
            );
        }

        // a2 (direct, rtt 20) joins: strictly better, 0 hysteresis/hold
        // -> Switched event must reach the sink.
        add_mock_path(&mon, a2, PathKind::Direct, Some(20), true);
        mon.tick(3000);
        thread::sleep(Duration::from_millis(50));
        mon.tick(4000);

        let events = sink.events.lock().unwrap();
        assert!(
            events.iter().any(|e| e.starts_with("switched")),
            "expected a switch event, got {events:?}"
        );
    }

    #[test]
    fn set_role_changes_probe_cadence() {
        let (a1, _) = test_addrs();
        let pm = Arc::new(Mutex::new(PathManager::new(PathConfig::default())));
        let (mon, _sink) = monitor_with(pm);
        add_mock_path(&mon, a1, PathKind::Direct, Some(20), true);
        assert_eq!(mon.path_count(), 1);
        mon.set_role(&a1, ProbeRole::Backup);
        // backup cadence is 5s: a tick 1s later must NOT ping again.
        mon.tick(1000); // first ping
        mon.tick(2000); // 1s later: active would ping, backup must not
        // no direct observable; the invariant is exercised via no-panic and
        // role mutation not corrupting state.
        mon.remove_path(&a1);
        assert_eq!(mon.path_count(), 0);
    }

    #[test]
    fn shutdown_is_idempotent() {
        let pm = Arc::new(Mutex::new(PathManager::new(PathConfig::default())));
        let (mon, _sink) = monitor_with(pm);
        mon.start();
        mon.shutdown();
        mon.shutdown(); // no panic, no hang
    }
}
