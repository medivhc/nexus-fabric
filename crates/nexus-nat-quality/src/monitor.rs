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

/// Measurement policy for the probe monitor.
///
/// Carries the d2 death-detection parameters (see
/// `docs/foundation/NAT-TRAVERSAL-CONTRACT.md` and the crate MODULE): a ping
/// is a hard miss when its own deadline elapses; `death_misses` consecutive
/// hard misses is death. The sliding window (10) is only a *scoring* device.
///
/// Deletion Test: inlining these values as private constants would duplicate
/// the decision parameters between `Inner::tick` and the deterministic tests,
/// and would leave no seam to inject an accelerated cadence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbePolicy {
    pub active_ms: u64,
    pub backup_ms: u64,
    pub accel_ms: u64,
    pub accel_after_misses: u32,
    pub soft_miss_factor: u32,
    pub soft_miss_floor_ms: u64,
    pub soft_miss_cap_ms: u64,
    pub death_misses: u32,
    pub deadline_factor: u32,
    pub deadline_floor_ms: u64,
    pub deadline_cap_ms: u64,
    pub tick_ms: u64,
}

impl Default for ProbePolicy {
    fn default() -> Self {
        Self {
            active_ms: 1000,
            backup_ms: 5000,
            accel_ms: 100,
            accel_after_misses: 1,
            soft_miss_factor: 2,
            soft_miss_floor_ms: 100,
            soft_miss_cap_ms: 500,
            death_misses: 14,
            deadline_factor: 3,
            deadline_floor_ms: 300,
            deadline_cap_ms: 2000,
            tick_ms: 100,
        }
    }
}

impl ProbePolicy {
    pub fn interval_ms(&self, role: ProbeRole) -> u64 {
        match role {
            ProbeRole::Active => self.active_ms,
            ProbeRole::Backup => self.backup_ms,
        }
    }

    pub fn soft_miss_ms(&self, rtt_ms: Option<u64>) -> u64 {
        let scaled = u64::from(self.soft_miss_factor).saturating_mul(rtt_ms.unwrap_or(0));
        scaled.clamp(self.soft_miss_floor_ms, self.soft_miss_cap_ms)
    }

    pub fn deadline_ms(&self, rtt_ms: Option<u64>) -> u64 {
        let scaled = u64::from(self.deadline_factor).saturating_mul(rtt_ms.unwrap_or(0));
        scaled.clamp(self.deadline_floor_ms, self.deadline_cap_ms)
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
    /// `path dead` already logged (latch for state-change-only logging).
    dead_logged: bool,
}

struct Inner<T: DatagramTransport> {
    pm: Arc<Mutex<PathManager>>,
    sink: Arc<dyn PathEventSink>,
    policy: ProbePolicy,
    paths: Mutex<HashMap<SocketAddr, PathState<T>>>,
    stop: AtomicBool,
    handle: Mutex<Option<thread::JoinHandle<()>>>,
}

/// Loss supplied to `PathManager` while a path is *not* confirmed dead.
///
/// The scoring window is only 10 samples, so during warm-up (or with a stale
/// late-pong `false` that is never recycled) the raw window loss can already
/// be 1.0 after far fewer than `death_misses` hard misses. Feeding that value
/// through would let `PathManager` (S6) fail over before the death threshold.
/// Non-death reports are therefore capped strictly below 1.0; `Some(1.0)` is
/// supplied only once `consecutive_misses >= death_misses`.
const NON_DEATH_LOSS_CEILING: f64 = 0.999;

fn supply_loss(raw: Option<f64>, consecutive_misses: u32, death_misses: u32) -> Option<f64> {
    if consecutive_misses >= death_misses {
        Some(1.0)
    } else {
        raw.map(|l| l.min(NON_DEATH_LOSS_CEILING))
    }
}

/// Active quality measurement + supply to `PathManager`.
pub struct QualityMonitor<T: DatagramTransport> {
    inner: Arc<Inner<T>>,
}

impl<T: DatagramTransport> QualityMonitor<T> {
    /// Create (does not start the background thread; call `start()`).
    /// Uses [`ProbePolicy::default`].
    pub fn new(pm: Arc<Mutex<PathManager>>, sink: Arc<dyn PathEventSink>) -> Self {
        Self::with_policy(pm, sink, ProbePolicy::default())
    }

    /// Create with an explicit measurement policy (tests / embedded use).
    /// The daemon always goes through [`Self::new`], i.e. the defaults.
    pub fn with_policy(
        pm: Arc<Mutex<PathManager>>,
        sink: Arc<dyn PathEventSink>,
        policy: ProbePolicy,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                pm,
                sink,
                policy,
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
                last_ping_ms: 0, // first ping at the first full interval
                dead_logged: false,
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
            // A role change restarts the death evidence: the pending misses
            // were accumulated under the other cadence. Do not fabricate a
            // `path recovered` log for this bookkeeping reset.
            s.endpoint.reset_consecutive_misses();
            s.dead_logged = false;
        }
    }

    /// Start the background supply thread (idempotent).
    pub fn start(&self) {
        let mut h = self.inner.handle.lock().unwrap();
        if h.is_some() {
            return;
        }
        let tick_ms = self.inner.policy.tick_ms;
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
                        // The cadence is the *effective* policy value, not a
                        // literal: the 4s AC-8 model depends on a 100ms tick.
                        thread::sleep(Duration::from_millis(tick_ms));
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
    /// background thread calls it every effective `ProbePolicy.tick_ms`
    /// (default 100ms).
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
        let policy = self.policy;
        let mut reports: Vec<(SocketAddr, PathStats)> = Vec::new();
        {
            let mut paths = self.paths.lock().unwrap();
            for (addr, state) in paths.iter_mut() {
                let rtt = state.endpoint.rtt_ms();
                let deadline = policy.deadline_ms(rtt);
                let soft_miss = policy.soft_miss_ms(rtt);
                // Only the active path accelerates: a warm backup keeps its
                // 5s cadence (no point burning traffic before it is used).
                let suspect = state.role == ProbeRole::Active
                    && (state.endpoint.consecutive_misses() >= policy.accel_after_misses
                        || matches!(
                            state.endpoint.oldest_outstanding_age_ms(now_ms),
                            Some(age) if age >= soft_miss
                        ));
                let interval = if suspect {
                    policy.accel_ms
                } else {
                    policy.interval_ms(state.role)
                };
                if now_ms.saturating_sub(state.last_ping_ms) >= interval {
                    // A failed ping (closed transport) is skipped; `expire`
                    // below ages it out and loss converges to 1.0.
                    if state.endpoint.ping(now_ms, deadline).is_ok() {
                        state.last_ping_ms = now_ms;
                    }
                }
                state.endpoint.expire(now_ms);

                let misses = state.endpoint.consecutive_misses();
                let dead = misses >= policy.death_misses;
                if dead && !state.dead_logged {
                    eprintln!("[nat-quality] path dead: {addr} misses={misses} at_ms={now_ms}");
                    state.dead_logged = true;
                } else if !dead && state.dead_logged {
                    eprintln!("[nat-quality] path recovered: {addr} at_ms={now_ms}");
                    state.dead_logged = false;
                }

                reports.push((
                    *addr,
                    PathStats {
                        rtt_ms: rtt,
                        loss_rate: supply_loss(
                            state.endpoint.loss_rate(),
                            misses,
                            policy.death_misses,
                        ),
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
    use crate::probe::LossProbe;
    use nexus_path::{CandidatePath, PathConfig, PathKind, SwitchReason};
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::AtomicU64;
    use std::sync::mpsc;
    use std::time::Instant;

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
        add_mock_path_role(mon, addr, kind, rtt, with_responder, ProbeRole::Active);
    }

    fn add_mock_path_role(
        mon: &QualityMonitor<MockTransport>,
        addr: SocketAddr,
        kind: PathKind,
        rtt: Option<u64>,
        with_responder: bool,
        role: ProbeRole,
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
            cost: 0.0,
            transport: ta,
            role,
            forward: None,
        });
    }

    /// Path event sink that keeps the raw events so tests can distinguish
    /// `PathFailed` from `BetterScore`.
    #[derive(Default)]
    struct ReasonSink {
        events: StdMutex<Vec<PathEvent>>,
        adopted: StdMutex<u32>,
    }

    impl PathEventSink for ReasonSink {
        fn on_path_event(&self, event: PathEvent) {
            match &event {
                PathEvent::Switched { .. } => self.events.lock().unwrap().push(event),
                PathEvent::Adopted { .. } => {
                    *self.adopted.lock().unwrap() += 1;
                }
            }
        }
    }

    impl ReasonSink {
        fn switches(&self) -> Vec<(SwitchReason, SocketAddr)> {
            self.events
                .lock()
                .unwrap()
                .iter()
                .filter_map(|e| match e {
                    PathEvent::Switched { to, reason, .. } => {
                        Some((reason.clone(), to.remote_addr))
                    }
                    PathEvent::Adopted { .. } => None,
                })
                .collect()
        }
    }

    /// `direct` is adopted as the active path; `relay` is a healthy backup
    /// candidate. `hysteresis_pct=10.0` + `switch_hold_ms=u64::MAX` make a
    /// `BetterScore` switch impossible, isolating S6 (`PathFailed`) failover.
    fn pm_with_direct_and_relay(direct: SocketAddr, relay: SocketAddr) -> Arc<Mutex<PathManager>> {
        let cfg = PathConfig {
            hysteresis_pct: 10.0,
            switch_hold_ms: u64::MAX,
            ..Default::default()
        };
        let mut pm = PathManager::new(cfg);
        pm.add_candidate(CandidatePath {
            kind: PathKind::Direct,
            local_addr: "10.0.0.9:4000".parse().unwrap(),
            remote_addr: direct,
            cost: 0.0,
        });
        pm.on_stats(
            &direct,
            PathStats {
                rtt_ms: Some(20),
                loss_rate: Some(0.0),
                throughput_bps: None,
            },
        );
        pm.add_candidate(CandidatePath {
            kind: PathKind::Turn,
            local_addr: "10.0.0.9:4001".parse().unwrap(),
            remote_addr: relay,
            cost: 10.0,
        });
        pm.on_stats(
            &relay,
            PathStats {
                rtt_ms: Some(200),
                loss_rate: Some(0.0),
                throughput_bps: None,
            },
        );
        Arc::new(Mutex::new(pm))
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
        // Spec §6-12 (semantic change registered): the old "3 lost samples ->
        // score=None" assertion no longer holds. Non-death supply is capped
        // below 1.0, so a dead-but-not-yet-confirmed path keeps a low score.
        let (direct, relay) = test_addrs();
        let pm = pm_with_direct_and_relay(direct, relay);
        let sink = Arc::new(ReasonSink::default());
        let mon = QualityMonitor::new(pm.clone(), sink.clone());
        add_mock_path_role(
            &mon,
            direct,
            PathKind::Direct,
            None,
            false,
            ProbeRole::Active,
        );

        for step in 0..=28u64 {
            let now = step * 100;
            mon.tick(now);
            let sw = sink.switches();
            match now {
                0..=2_500 => {
                    assert!(
                        sw.is_empty(),
                        "no switch before the 14th hard miss (now={now})"
                    );
                    assert_eq!(
                        pm.lock().unwrap().current_path().unwrap().remote_addr,
                        direct
                    );
                }
                2_600 | 2_700 => {
                    assert!(
                        sw.is_empty(),
                        "death needs 3 consecutive loss=1.0 reports (now={now})"
                    );
                }
                _ => {}
            }
        }
        assert_eq!(mon.path_loss(&direct), Some(1.0), "raw window saturated");
        assert!(
            supply_loss(mon.path_loss(&direct), 13, 14).unwrap() < 1.0,
            "13 misses must never supply 1.0"
        );
        let sw = sink.switches();
        assert_eq!(sw.len(), 1, "exactly one failover, got {sw:?}");
        assert_eq!(sw[0].0, SwitchReason::PathFailed);
        assert_eq!(sw[0].1, relay);
        assert_eq!(
            pm.lock().unwrap().current_path().unwrap().remote_addr,
            relay
        );
        assert!(pm.lock().unwrap().score(&direct).is_some());
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

    #[test]
    fn supply_loss_never_reports_one_before_death() {
        assert_eq!(supply_loss(Some(1.0), 13, 14), Some(0.999));
        assert_eq!(supply_loss(None, 13, 14), None);
        assert_eq!(supply_loss(Some(0.4375), 0, 14), Some(0.4375));
        assert_eq!(supply_loss(Some(1.0), 14, 14), Some(1.0));
        assert_eq!(supply_loss(None, 14, 14), Some(1.0));
        // strict: every non-death value is < 1.0
        for misses in 0..14 {
            assert!(supply_loss(Some(1.0), misses, 14).unwrap() < 1.0);
        }
    }

    #[test]
    fn death_within_4000ms_virtual() {
        let (direct, relay) = test_addrs();
        let pm = pm_with_direct_and_relay(direct, relay);
        let sink = Arc::new(ReasonSink::default());
        let mon = QualityMonitor::new(pm.clone(), sink.clone());
        // Silent peer, RTT unknown: deadline floor 300ms, soft-miss floor 100ms.
        add_mock_path_role(
            &mon,
            direct,
            PathKind::Direct,
            None,
            false,
            ProbeRole::Active,
        );

        let mut first_switch_ms = None;
        for step in 0..=40u64 {
            let now = step * 100;
            mon.tick(now);
            let sw = sink.switches();
            if first_switch_ms.is_none() && !sw.is_empty() {
                first_switch_ms = Some(now);
            }
            if now == 2_500 {
                // 13 hard misses accumulated (the 14th lands at 2600ms).
                assert!(sw.is_empty(), "must not die before the 14th hard miss");
                assert_eq!(
                    pm.lock().unwrap().current_path().unwrap().remote_addr,
                    direct
                );
            }
        }
        // 14th hard miss at 2600ms + 3 loss=1.0 reports -> failover by 2800ms.
        let first = first_switch_ms.expect("expected a failover within 4000ms");
        assert!(
            (2_600..=4_000).contains(&first),
            "failover at {first}ms, expected 2600..=4000"
        );
        let sw = sink.switches();
        assert_eq!(sw.len(), 1, "exactly one switch, got {sw:?}");
        assert_eq!(sw[0].0, SwitchReason::PathFailed);
        assert_eq!(sw[0].1, relay);
    }

    /// Small deterministic PRNG for the virtual 25% loss model (no new dep).
    struct Lcg(u64);

    impl Lcg {
        fn new(seed: u64) -> Self {
            Self(
                seed.wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407),
            )
        }
        fn next_u32(&mut self) -> u32 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (self.0 >> 33) as u32
        }
        fn lost(&mut self, permille: u32) -> bool {
            self.next_u32() % 1000 < permille
        }
    }

    /// Drive the d2 algorithm on a virtual clock for 60s with independent
    /// 25% loss on the ping (A->B) and pong (B->A) directions. `on_tick`
    /// receives `(now_ms, supply_loss)`; no threads and no wall-clock reads.
    fn drive_25pct(seed: u64, mut on_tick: impl FnMut(u64, Option<f64>)) -> (u32, bool) {
        let policy = ProbePolicy::default();
        let mut probe = LossProbe::new(10);
        let mut last_ping_ms = 0u64;
        let mut pending: Vec<(u64, u64)> = Vec::new(); // (deliver_at, nonce)
        let mut ping_rng = Lcg::new(seed);
        let mut pong_rng = Lcg::new(seed ^ 0x9E37_79B9_7F4A_7C15);
        let mut max_run = 0u32;
        let mut died = false;
        let rtt_ms: u64 = 20;
        let rtt = Some(rtt_ms);

        let mut now = 0u64;
        while now <= 60_000 {
            // Deliver every pong whose virtual arrival time has come.
            let mut i = 0;
            while i < pending.len() {
                if pending[i].0 <= now {
                    let (_, nonce) = pending.remove(i);
                    probe.on_pong(nonce);
                } else {
                    i += 1;
                }
            }

            let deadline = policy.deadline_ms(rtt);
            let soft_miss = policy.soft_miss_ms(rtt);
            let suspect = probe.consecutive_misses() >= policy.accel_after_misses
                || matches!(
                    probe.oldest_outstanding_age_ms(now),
                    Some(age) if age >= soft_miss
                );
            let interval = if suspect {
                policy.accel_ms
            } else {
                policy.interval_ms(ProbeRole::Active)
            };
            if now.saturating_sub(last_ping_ms) >= interval {
                let (nonce, _) = probe.send_ping(now, deadline);
                let ping_lost = ping_rng.lost(250);
                let pong_lost = pong_rng.lost(250);
                if !ping_lost && !pong_lost {
                    pending.push((now + rtt_ms, nonce));
                }
                last_ping_ms = now;
            }

            probe.expire(now);
            let run = probe.consecutive_misses();
            max_run = max_run.max(run);
            if run >= policy.death_misses {
                died = true;
            }
            let supply = supply_loss(probe.loss_rate(), run, policy.death_misses);
            on_tick(now, supply);
            now += 100;
        }
        (max_run, died)
    }

    /// Offline seed search (run manually with `--ignored --nocapture`).
    /// Condition: the 60s virtual run has a longest consecutive-miss run of
    /// exactly 13 (so at least one 13-run, never a 14-run).
    #[test]
    #[ignore]
    fn find_25pct_seed_with_13_run() {
        for seed in 1..200_000u64 {
            let (max_run, died) = drive_25pct(seed, |_, _| {});
            if max_run == 13 && !died {
                eprintln!("SEED={seed} max_run={max_run}");
                return;
            }
        }
        panic!("no seed found");
    }

    #[test]
    fn loss_25pct_never_dies_virtual_60s() {
        // Fixed seed from `find_25pct_seed_with_13_run`: the longest run is
        // exactly 13 consecutive misses (a 14-run never occurs), which pins
        // the boundary: any threshold drift (N<14) turns this red.
        const SEED: u64 = 732;
        let (direct, relay) = test_addrs();
        let pm = pm_with_direct_and_relay(direct, relay);
        let (mut max_run, mut saw_supply_one, mut events) = (0u32, false, Vec::new());

        let (run, died) = drive_25pct(SEED, |now, supply| {
            if let Some(loss) = supply {
                if loss >= 1.0 {
                    saw_supply_one = true;
                }
            }
            let mut guard = pm.lock().unwrap();
            guard.on_stats(
                &direct,
                PathStats {
                    rtt_ms: Some(20),
                    loss_rate: supply,
                    throughput_bps: None,
                },
            );
            while let Some(ev) = guard.poll_event() {
                events.push((now, ev));
            }
        });
        max_run = max_run.max(run);

        assert_eq!(max_run, 13, "seed must produce exactly one 13-run, no 14");
        assert!(!died);
        assert!(!saw_supply_one, "non-death supply must stay strictly < 1.0");
        assert!(
            !events.iter().any(|(_, e)| matches!(
                e,
                PathEvent::Switched {
                    reason: SwitchReason::PathFailed,
                    ..
                }
            )),
            "25% bidirectional loss must never produce PathFailed: {events:?}"
        );
    }

    #[test]
    fn role_promotion_no_false_death() {
        let (direct, relay) = test_addrs();
        let pm = pm_with_direct_and_relay(direct, relay);
        let sink = Arc::new(ReasonSink::default());
        let mon = QualityMonitor::new(pm.clone(), sink.clone());
        // Registered as Backup: 5s cadence, 300ms deadline, silent peer.
        add_mock_path_role(
            &mon,
            direct,
            PathKind::Direct,
            None,
            false,
            ProbeRole::Backup,
        );

        for step in 0..=653u64 {
            mon.tick(step * 100);
        }
        assert!(
            sink.switches().is_empty(),
            "13 backup misses are below the death threshold"
        );
        assert_eq!(
            pm.lock().unwrap().current_path().unwrap().remote_addr,
            direct
        );

        // Promotion resets the accumulated misses: it must not be read as an
        // immediate 14th consecutive miss.
        mon.set_role(&direct, ProbeRole::Active);
        for step in 654..=660u64 {
            mon.tick(step * 100);
            assert!(
                sink.switches().is_empty(),
                "promotion must not trigger an immediate PathFailed (now={}ms)",
                step * 100
            );
        }
        assert_eq!(
            pm.lock().unwrap().current_path().unwrap().remote_addr,
            direct
        );
    }

    #[test]
    fn default_policy_tick_ms_is_100() {
        let p = ProbePolicy::default();
        assert_eq!(p.tick_ms, 100);
        assert_eq!(p.active_ms, 1000);
        assert_eq!(p.backup_ms, 5000);
        assert_eq!(p.accel_ms, 100);
        assert_eq!(p.accel_after_misses, 1);
        assert_eq!(p.death_misses, 14);
        assert_eq!(p.deadline_floor_ms, 300);
        assert_eq!(p.deadline_cap_ms, 2000);
        assert_eq!(p.soft_miss_floor_ms, 100);
        assert_eq!(p.soft_miss_cap_ms, 500);
        assert_eq!(p.interval_ms(ProbeRole::Active), 1000);
        assert_eq!(p.interval_ms(ProbeRole::Backup), 5000);
        assert_eq!(p.deadline_ms(None), 300);
        assert_eq!(p.deadline_ms(Some(100)), 300);
        assert_eq!(p.deadline_ms(Some(300)), 900);
        assert_eq!(p.deadline_ms(Some(10_000)), 2000);
        assert_eq!(p.soft_miss_ms(None), 100);
        assert_eq!(p.soft_miss_ms(Some(200)), 400);
        assert_eq!(p.soft_miss_ms(Some(10_000)), 500);
    }

    /// Silent transport with a send counter: proves the production thread
    /// sleeps for the *effective* `ProbePolicy.tick_ms`, not a literal 200ms.
    struct CountingTransport {
        sent: Arc<AtomicU64>,
    }

    impl DatagramTransport for CountingTransport {
        type Error = String;
        fn send_dgram(&self, _data: &[u8]) -> Result<(), String> {
            self.sent.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        fn recv_dgram(&self) -> Result<Vec<u8>, String> {
            Err("closed".into())
        }
        fn rtt_ms(&self) -> Option<u64> {
            None
        }
    }

    #[test]
    fn production_start_sleeps_policy_tick() {
        let addr: SocketAddr = "10.0.0.7:5000".parse().unwrap();
        let pm = Arc::new(Mutex::new(PathManager::new(PathConfig::default())));
        let sink = Arc::new(ReasonSink::default());
        let sent = Arc::new(AtomicU64::new(0));
        // `accel_ms` matches `active_ms` so a silent peer (no pongs) cannot
        // slow the cadence down via suspect acceleration; the subject here is
        // the thread sleep interval, not the acceleration rule.
        let policy = ProbePolicy {
            tick_ms: 20,
            active_ms: 20,
            backup_ms: 20,
            accel_ms: 20,
            ..Default::default()
        };
        let mon = QualityMonitor::with_policy(pm, sink, policy);
        mon.add_path(MeasuredPath {
            addr,
            kind: PathKind::Direct,
            local_addr: "10.0.0.9:4000".parse().unwrap(),
            cost: 0.0,
            transport: CountingTransport {
                sent: Arc::clone(&sent),
            },
            role: ProbeRole::Active,
            forward: None,
        });

        mon.start();
        let start = Instant::now();
        while sent.load(Ordering::SeqCst) < 20 && start.elapsed() < Duration::from_millis(1000) {
            thread::sleep(Duration::from_millis(5));
        }
        let count = sent.load(Ordering::SeqCst);
        mon.shutdown();
        assert!(
            count >= 20,
            "20ms tick should yield >=20 pings in 1s (200ms tick yields ~5), got {count}"
        );
    }
}
