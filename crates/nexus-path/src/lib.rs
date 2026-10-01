//! Path layer: "which path should packets take to reach the peer?"
//!
//! Manages candidate paths (direct → mesh → TURN → proxy), probes them,
//! scores them, and switches the active path with hysteresis. Single active
//! path (S1); racing is for connection setup only (R1), prediction is EWMA
//! layer 1 (R2), no multipath concurrency.
//!
//! Design notes (see `MODULE.md` S1–S9, R1–R6):
//! - Scores are EWMA-smoothed per path; a path with no observations has an
//!   `unknown` score and never participates in selection (S7).
//! - Switching requires the challenger to beat the active path by
//!   `hysteresis_pct` (relative, e.g. 20%) **and** hold that lead for
//!   `switch_hold_ms` (S4), which together give connection stickiness (S5).
//! - A path that misses `max_missed_probes` consecutive probes is declared
//!   failed and replaced immediately, without waiting for hysteresis (S6).
//! - Switching only swaps the UDP socket/address; the session (CID) is owned
//!   by `nexus-fabric`, whose passive migration keeps streams alive (S2).

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

mod ewma;
mod fallback;
mod race;

pub use ewma::Ewma;
pub use fallback::{
    FallbackChain, FallbackConfig, ProxyEndpoint, TurnEndpoint, connect_with_fallback,
};
pub use race::{PathConnector, RaceBudget, RaceOutcome, race_connect};

// ---------------------------------------------------------------------------
// Scoring weights (defaults).
//
// score = W_RTT * f(rtt) + W_LOSS * f(loss) + W_TP * f(throughput) - W_COST * cost
//
// Component functions (higher is better):
// - f(rtt)  = 1000 / (1 + rtt_ms):        10ms -> 90.9, 50ms -> 19.6, 500ms -> 2.0
// - f(loss) = 100 * (1 - loss_rate):      0% -> 100, 50% -> 50, 100% -> 0
// - f(tp)   = 10 * log10(1 + bps / 1e6):  0 -> 0, 1Mbps -> 3.0, 100Mbps -> 20.0
//
// Rationale: RTT and loss dominate interactive quality (1.0 each); throughput
// matters less for P0 and is often unknown (0.5); cost is in ~0..10 abstract
// units and weight 2.0 makes a TURN relay (cost 5) cost 10 points —
// significant but not dominant, so a badly degraded direct path still loses
// to TURN, while at equal quality the cheaper path always wins (S3).
// ---------------------------------------------------------------------------
const W_RTT: f64 = 1.0;
const W_LOSS: f64 = 1.0;
const W_TP: f64 = 0.5;
const W_COST: f64 = 2.0;

/// Kind of candidate path, ordered by preference (cost ascending).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PathKind {
    Direct,
    Mesh,
    Turn,
    Proxy,
}

/// A candidate path to a peer.
#[derive(Debug, Clone)]
pub struct CandidatePath {
    pub kind: PathKind,
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    /// Relative cost (relay bandwidth, cellular billing, etc.). Lower is better.
    /// Expected range ~0..10; enters the score as `W_COST * cost` (S8: explicit).
    pub cost: f64,
}

/// Observed statistics for a path (all optional; unknown = not yet measured).
#[derive(Debug, Clone, Default)]
pub struct PathStats {
    pub rtt_ms: Option<u64>,
    pub loss_rate: Option<f64>,
    pub throughput_bps: Option<u64>,
}

/// Configuration for path selection.
#[derive(Debug, Clone)]
pub struct PathConfig {
    /// Challenger must beat the active path by this relative margin
    /// (e.g. 0.20 = 20% better) to switch (S4, R3).
    /// Valid range: [0, 1]. Negative values are clamped to 0 (any improvement
    /// triggers); values > 1 are allowed but mean "never switch on score".
    pub hysteresis_pct: f64,
    /// New path must hold the lead for this long before switching.
    pub switch_hold_ms: u64,
    /// Interval between active probe rounds on idle paths.
    pub probe_interval_ms: u64,
    /// EWMA smoothing factor for scores (0 < alpha <= 1).
    pub ewma_alpha: f64,
    /// Consecutive missed probes before a path is declared failed.
    pub max_missed_probes: u32,
    /// Budgets for connection racing (R1). Used by `race_connect`, not by
    /// `PathManager` itself (racing is a setup-phase operation).
    pub race_budget: RaceBudget,
}

impl Default for PathConfig {
    fn default() -> Self {
        Self {
            hysteresis_pct: 0.20,
            switch_hold_ms: 3000,
            probe_interval_ms: 5000,
            ewma_alpha: 0.3,
            max_missed_probes: 3,
            race_budget: RaceBudget::default(),
        }
    }
}

/// Reason for a path switch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwitchReason {
    /// An existing candidate's score beat the active path (hysteresis + hold).
    BetterScore,
    /// The active path missed `max_missed_probes` consecutive probes.
    PathFailed,
    /// A newly added candidate beat the active path (hysteresis + hold).
    PathAdded,
}

/// Path lifecycle event.
#[derive(Debug, Clone)]
pub enum PathEvent {
    Switched {
        from: CandidatePath,
        to: CandidatePath,
        reason: SwitchReason,
    },
}

/// Per-candidate runtime state.
struct PathEntry {
    path: CandidatePath,
    /// EWMA-smoothed score (R2). `value() == None` = unknown (no observations yet, S7).
    ewma: Ewma,
    missed_probes: u32,
    added_at: Instant,
}

/// Pending hysteresis hold for a challenger.
struct PendingSwitch {
    candidate: SocketAddr,
    hold_start: Instant,
}

struct State {
    config: PathConfig,
    candidates: HashMap<SocketAddr, PathEntry>,
    /// Remote address of the single active path (S1).
    active: Option<SocketAddr>,
    /// When the current active path was selected; used to tell "newly added"
    /// candidates (reason `PathAdded`) from existing ones (`BetterScore`).
    active_selected_at: Instant,
    pending: Option<PendingSwitch>,
}

struct Inner {
    state: Mutex<State>,
    events: Mutex<VecDeque<PathEvent>>,
    stop: AtomicBool,
}

/// Compute the instantaneous (unsmoothed) score from one stats report.
/// Returns `None` when the report carries no usable data (S7).
fn instant_score(stats: &PathStats, cost: f64) -> Option<f64> {
    let mut total = 0.0;
    let mut any = false;
    if let Some(rtt) = stats.rtt_ms {
        total += W_RTT * (1000.0 / (1.0 + rtt as f64));
        any = true;
    }
    if let Some(loss) = stats.loss_rate {
        let loss = loss.clamp(0.0, 1.0);
        total += W_LOSS * (100.0 * (1.0 - loss));
        any = true;
    }
    if let Some(bps) = stats.throughput_bps {
        total += W_TP * (10.0 * (1.0 + bps as f64 / 1_000_000.0).log10());
        any = true;
    }
    if !any {
        return None;
    }
    // S8: cost is an explicit, visible term — never hidden inside f().
    Some(total - W_COST * cost)
}

/// Pick the highest-scored known candidate, optionally excluding one address.
/// Tie-break: lower cost, then PathKind order. Returns the remote address.
fn best_candidate(state: &State, exclude: Option<&SocketAddr>) -> Option<SocketAddr> {
    state
        .candidates
        .iter()
        .filter(|(addr, e)| e.ewma.value().is_some() && Some(*addr) != exclude)
        .max_by(|a, b| {
            let sa = a.1.ewma.value().unwrap();
            let sb = b.1.ewma.value().unwrap();
            sa.total_cmp(&sb)
                // S3: equal quality -> cheaper path ranks higher.
                .then_with(|| b.1.path.cost.total_cmp(&a.1.path.cost))
                .then_with(|| b.1.path.kind.cmp(&a.1.path.kind))
        })
        .map(|(addr, _)| *addr)
}

impl Inner {
    fn do_switch(
        &self,
        state: &mut State,
        from_addr: SocketAddr,
        to_addr: SocketAddr,
        reason: SwitchReason,
        now: Instant,
    ) {
        let from = state.candidates[&from_addr].path.clone();
        let to = state.candidates[&to_addr].path.clone();
        state.active = Some(to_addr);
        state.active_selected_at = now;
        state.pending = None;
        self.events
            .lock()
            .unwrap()
            .push_back(PathEvent::Switched { from, to, reason });
    }

    /// Immediate failover after the active path failed (S6): no hysteresis,
    /// no hold. If no alternative exists, active becomes `None`.
    fn failover(&self, state: &mut State, failed: SocketAddr, now: Instant) {
        match best_candidate(state, Some(&failed)) {
            Some(best) => self.do_switch(state, failed, best, SwitchReason::PathFailed, now),
            None => {
                state.active = None;
                state.pending = None;
            }
        }
    }

    /// Evaluate whether the active path should be replaced (S4/S5).
    fn evaluate(&self, state: &mut State, now: Instant) {
        let active_addr = match state.active {
            Some(a) => a,
            None => {
                // No active path: adopt the best known one immediately.
                // Not a "switch" (no `from`), so no event is emitted.
                if let Some(best) = best_candidate(state, None) {
                    state.active = Some(best);
                    state.active_selected_at = now;
                }
                state.pending = None;
                return;
            }
        };

        let active_score = match state
            .candidates
            .get(&active_addr)
            .and_then(|e| e.ewma.value())
        {
            Some(s) => s,
            None => {
                // Active path has unknown score; prefer any known path.
                if let Some(best) = best_candidate(state, Some(&active_addr)) {
                    self.do_switch(state, active_addr, best, SwitchReason::BetterScore, now);
                }
                return;
            }
        };

        let challenger = match best_candidate(state, Some(&active_addr)) {
            Some(c) => c,
            None => {
                state.pending = None;
                return;
            }
        };
        let chall_score = state.candidates[&challenger]
            .ewma
            .value()
            .expect("best_candidate only returns scored paths");

        // R3/S4: relative hysteresis. The challenger must beat the active path
        // by `hysteresis_pct` (e.g. 20%). If the active score is not positive,
        // the relative margin is undefined; any strictly better challenger
        // qualifies (the active path is effectively unusable).
        // Clamp negative hysteresis_pct to 0 (defensive; negative would invert).
        let pct = state.config.hysteresis_pct.max(0.0);
        let beats_hysteresis = if active_score > 0.0 {
            (chall_score - active_score) / active_score >= pct
        } else {
            chall_score > active_score
        };

        if beats_hysteresis {
            let hold_start = match &state.pending {
                Some(p) if p.candidate == challenger => p.hold_start,
                _ => {
                    let hs = now;
                    state.pending = Some(PendingSwitch {
                        candidate: challenger,
                        hold_start: hs,
                    });
                    hs
                }
            };
            if now.duration_since(hold_start).as_millis() >= state.config.switch_hold_ms as u128 {
                let reason = if state.candidates[&challenger].added_at >= state.active_selected_at {
                    SwitchReason::PathAdded
                } else {
                    SwitchReason::BetterScore
                };
                self.do_switch(state, active_addr, challenger, reason, now);
            }
        } else {
            // S5: margin not met -> stay pinned, drop any pending hold.
            state.pending = None;
        }
    }
}

/// P0 stub: the hook where UDP heartbeat sends will land (P1).
/// The probe-thread framework (scheduling, ownership, shutdown) is real;
/// no packets are sent yet.
fn send_heartbeat_stub(_local: SocketAddr, _remote: SocketAddr) {
    // P0: stubbed. P1: send UDP ping, await pong, feed results via on_stats.
}

/// Background probe loop. Owned by `PathManager`; stops on `Drop` (join).
fn probe_loop(inner: Arc<Inner>) {
    let mut elapsed = Duration::ZERO;
    let quantum = Duration::from_millis(100);
    loop {
        if inner.stop.load(Ordering::Relaxed) {
            break;
        }
        thread::sleep(quantum);
        if inner.stop.load(Ordering::Relaxed) {
            break;
        }
        elapsed += quantum;
        let interval = inner.state.lock().unwrap().config.probe_interval_ms;
        if elapsed.as_millis() >= interval as u128 {
            elapsed = Duration::ZERO;
            // P0: framework round — invoke the send hook per candidate.
            // Real ping/pong arrives in P1; passive stats drive P0 decisions.
            let remotes: Vec<(SocketAddr, SocketAddr)> = {
                inner
                    .state
                    .lock()
                    .unwrap()
                    .candidates
                    .values()
                    .map(|e| (e.path.local_addr, e.path.remote_addr))
                    .collect()
            };
            for (local, remote) in remotes {
                send_heartbeat_stub(local, remote);
            }
        }
    }
}

/// Manages candidate paths and selects the single active one (S1).
///
/// Sync API, std-only. A background probe thread is spawned on `new()` and
/// joined on `drop()`.
pub struct PathManager {
    inner: Arc<Inner>,
    probe_thread: Option<JoinHandle<()>>,
}

impl PathManager {
    pub fn new(config: PathConfig) -> Self {
        let inner = Arc::new(Inner {
            state: Mutex::new(State {
                config,
                candidates: HashMap::new(),
                active: None,
                active_selected_at: Instant::now(),
                pending: None,
            }),
            events: Mutex::new(VecDeque::new()),
            stop: AtomicBool::new(false),
        });
        let probe_thread = {
            let inner = Arc::clone(&inner);
            Some(thread::spawn(move || probe_loop(inner)))
        };
        Self {
            inner,
            probe_thread,
        }
    }

    /// Add (or replace) a candidate path. A candidate starts with an unknown
    /// score (S7) and never becomes active before its first stats report.
    /// Adding alone never preempts the active path; a new candidate must earn
    /// the switch via scored hysteresis (S4) once stats arrive.
    pub fn add_candidate(&mut self, path: CandidatePath) {
        let mut state = self.inner.state.lock().unwrap();
        let remote = path.remote_addr;
        // Re-adding resets observations, but keeps the original add time so
        // "newness" (PathAdded vs BetterScore) isn't faked by re-announcement.
        let added_at = state
            .candidates
            .get(&remote)
            .map(|e| e.added_at)
            .unwrap_or_else(Instant::now);
        let alpha = state.config.ewma_alpha;
        state.candidates.insert(
            remote,
            PathEntry {
                path,
                ewma: Ewma::new(alpha),
                missed_probes: 0,
                added_at,
            },
        );
    }

    /// Remove a candidate. If it was the active path, the best remaining one
    /// is selected immediately (failover semantics); with no alternative,
    /// the active path becomes `None`.
    ///
    /// S9: removing the active path with a backup available emits
    /// `PathEvent::Switched` (S6's event form, reason `PathFailed`); with no
    /// backup, no event is emitted (nothing to switch to).
    pub fn remove_candidate(&mut self, remote: &SocketAddr) {
        let now = Instant::now();
        let mut state = self.inner.state.lock().unwrap();
        let was_active = state.active == Some(*remote);
        let removed = state.candidates.remove(remote);
        if state
            .pending
            .as_ref()
            .is_some_and(|p| p.candidate == *remote)
        {
            state.pending = None;
        }
        if was_active {
            let new_active = best_candidate(&state, None);
            state.active = new_active;
            state.active_selected_at = now;
            state.pending = None;
            if let (Some(removed), Some(to_addr)) = (removed, new_active) {
                let from = removed.path;
                let to = state.candidates[&to_addr].path.clone();
                self.inner
                    .events
                    .lock()
                    .unwrap()
                    .push_back(PathEvent::Switched {
                        from,
                        to,
                        reason: SwitchReason::PathFailed,
                    });
            }
        }
    }

    /// The currently selected path, if any.
    pub fn current_path(&self) -> Option<CandidatePath> {
        let state = self.inner.state.lock().unwrap();
        state
            .active
            .and_then(|a| state.candidates.get(&a))
            .map(|e| e.path.clone())
    }

    /// Feed observed statistics for a path.
    ///
    /// - A report with `loss_rate >= 1.0` counts as a missed probe (S6).
    /// - Any other report with at least one measurement resets the missed
    ///   counter and updates the EWMA score.
    /// - A report with no measurements at all is ignored (S7).
    /// - Reports for unknown remotes are ignored.
    pub fn on_stats(&mut self, remote: &SocketAddr, stats: PathStats) {
        let now = Instant::now();
        let mut state = self.inner.state.lock().unwrap();

        // Extract config first: `entry` below mutably borrows `state`.
        let max_missed = state.config.max_missed_probes;

        let entry = match state.candidates.get_mut(remote) {
            Some(e) => e,
            None => return,
        };

        let missed = matches!(stats.loss_rate, Some(l) if l >= 1.0);
        if missed {
            entry.missed_probes += 1;
            // No measurement -> EWMA untouched.
        } else {
            let cost = entry.path.cost;
            match instant_score(&stats, cost) {
                Some(instant) => {
                    entry.missed_probes = 0;
                    // R2: feed the instantaneous score into the per-path EWMA.
                    // First observation initializes the smoother (S7: the path
                    // now has data and may be selected).
                    entry.ewma.update(instant);
                }
                None => return, // No usable data; ignore.
            }
        }

        // S6: active path failed -> immediate failover, no hysteresis.
        if state.active == Some(*remote) && state.candidates[remote].missed_probes >= max_missed {
            self.inner.failover(&mut state, *remote, now);
            return;
        }

        self.inner.evaluate(&mut state, now);
    }

    /// Drain the oldest pending path event, if any.
    pub fn poll_event(&self) -> Option<PathEvent> {
        self.inner.events.lock().unwrap().pop_front()
    }

    /// EWMA-smoothed score for a path (higher is better).
    /// `None` = unknown: the path has no observations yet (S7).
    pub fn score(&self, remote: &SocketAddr) -> Option<f64> {
        self.inner
            .state
            .lock()
            .unwrap()
            .candidates
            .get(remote)
            .and_then(|e| e.ewma.value())
    }
}

impl Drop for PathManager {
    fn drop(&mut self) {
        // Owner shutdown: signal the probe thread, then join it.
        self.inner.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.probe_thread.take() {
            // Never panic in Drop; a stuck probe thread must not take down
            // the owner.
            let _ = h.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}").parse().unwrap()
    }

    fn candidate(kind: PathKind, port: u16, cost: f64) -> CandidatePath {
        CandidatePath {
            kind,
            local_addr: addr(8000),
            remote_addr: addr(port),
            cost,
        }
    }

    fn stats(rtt_ms: u64, loss: f64) -> PathStats {
        PathStats {
            rtt_ms: Some(rtt_ms),
            loss_rate: Some(loss),
            throughput_bps: None,
        }
    }

    fn fast_config() -> PathConfig {
        PathConfig {
            hysteresis_pct: 0.01, // 1%: tests want switches to trigger easily
            switch_hold_ms: 50,
            probe_interval_ms: 60_000, // keep the probe thread quiet in tests
            ewma_alpha: 1.0,           // no smoothing unless a test wants it
            max_missed_probes: 3,
            race_budget: RaceBudget::default(),
        }
    }

    #[test]
    fn score_prefers_lower_cost_at_equal_quality() {
        // S3: same rtt/loss, cheaper path scores higher and becomes active.
        let mut pm = PathManager::new(fast_config());
        pm.add_candidate(candidate(PathKind::Direct, 9001, 0.0));
        pm.add_candidate(candidate(PathKind::Turn, 9002, 5.0));
        pm.on_stats(&addr(9001), stats(20, 0.0));
        pm.on_stats(&addr(9002), stats(20, 0.0));
        let s_direct = pm.score(&addr(9001)).unwrap();
        let s_turn = pm.score(&addr(9002)).unwrap();
        assert!(
            s_direct > s_turn,
            "S3 violated: direct {s_direct} should beat turn {s_turn} at equal quality"
        );
        assert_eq!(pm.current_path().unwrap().kind, PathKind::Direct);
    }

    #[test]
    fn unknown_score_does_not_participate() {
        // S7: path with no data has unknown score and is never selected.
        let mut pm = PathManager::new(fast_config());
        pm.add_candidate(candidate(PathKind::Direct, 9001, 0.0));
        pm.add_candidate(candidate(PathKind::Turn, 9002, 5.0));
        assert_eq!(pm.score(&addr(9001)), None);
        assert_eq!(pm.score(&addr(9002)), None);
        assert!(pm.current_path().is_none());
        // Only turn gets data -> turn becomes active even though direct is cheaper.
        pm.on_stats(&addr(9002), stats(50, 0.0));
        assert!(pm.score(&addr(9002)).is_some());
        assert_eq!(pm.score(&addr(9001)), None);
        assert_eq!(pm.current_path().unwrap().kind, PathKind::Turn);
    }

    #[test]
    fn empty_report_is_ignored() {
        let mut pm = PathManager::new(fast_config());
        pm.add_candidate(candidate(PathKind::Direct, 9001, 0.0));
        pm.on_stats(&addr(9001), PathStats::default());
        assert_eq!(pm.score(&addr(9001)), None);
        assert!(pm.current_path().is_none());
    }

    #[test]
    fn ewma_initializes_then_smooths() {
        let mut cfg = fast_config();
        cfg.ewma_alpha = 0.5;
        let mut pm = PathManager::new(cfg);
        pm.add_candidate(candidate(PathKind::Direct, 9001, 0.0));
        // First observation initializes.
        pm.on_stats(&addr(9001), stats(10, 0.0));
        let s1 = pm.score(&addr(9001)).unwrap();
        let instant1 = instant_score(&stats(10, 0.0), 0.0).unwrap();
        assert!(
            (s1 - instant1).abs() < 1e-9,
            "first observation must initialize EWMA"
        );
        // Second observation blends 50/50.
        pm.on_stats(&addr(9001), stats(110, 0.0));
        let s2 = pm.score(&addr(9001)).unwrap();
        let instant2 = instant_score(&stats(110, 0.0), 0.0).unwrap();
        let expected = 0.5 * instant2 + 0.5 * s1;
        assert!(
            (s2 - expected).abs() < 1e-9,
            "EWMA mismatch: got {s2}, want {expected}"
        );
        // Smoothed value lies strictly between the two instants.
        assert!(s2 < s1 && s2 > instant2);
    }

    #[test]
    fn hysteresis_blocks_small_margin() {
        // S4/S5: challenger beating active by less than hysteresis_pct -> no switch.
        let mut pm = PathManager::new(fast_config());
        pm.add_candidate(candidate(PathKind::Direct, 9001, 0.0));
        pm.add_candidate(candidate(PathKind::Mesh, 9003, 0.05)); // -0.1 pts vs direct
        pm.on_stats(&addr(9001), stats(10, 0.0)); // direct active, ~190.9
        assert_eq!(pm.current_path().unwrap().kind, PathKind::Direct);
        // Mesh scores ~190.8: margin 0.1 < hysteresis 1.0.
        for _ in 0..5 {
            pm.on_stats(&addr(9003), stats(10, 0.0));
            pm.on_stats(&addr(9001), stats(10, 0.0));
            thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(
            pm.current_path().unwrap().kind,
            PathKind::Direct,
            "S5 violated: switched on a sub-hysteresis margin"
        );
        assert!(pm.poll_event().is_none());
    }

    #[test]
    fn hysteresis_hold_then_switch() {
        // S4: margin >= hysteresis_pct held for switch_hold_ms -> switch.
        let mut pm = PathManager::new(fast_config()); // hold 50ms, alpha 1.0
        pm.add_candidate(candidate(PathKind::Direct, 9001, 0.0));
        pm.add_candidate(candidate(PathKind::Turn, 9002, 5.0));
        pm.on_stats(&addr(9001), stats(10, 0.0));
        pm.on_stats(&addr(9002), stats(50, 0.0));
        assert_eq!(pm.current_path().unwrap().kind, PathKind::Direct);
        // Degrade direct hard: instant score collapses below turn's.
        for _ in 0..10 {
            pm.on_stats(&addr(9001), stats(2000, 0.5));
            pm.on_stats(&addr(9002), stats(50, 0.0));
            thread::sleep(Duration::from_millis(20));
            if pm.current_path().unwrap().kind == PathKind::Turn {
                break;
            }
        }
        assert_eq!(pm.current_path().unwrap().kind, PathKind::Turn);
        match pm.poll_event() {
            Some(PathEvent::Switched { reason, .. }) => {
                assert!(
                    reason == SwitchReason::BetterScore || reason == SwitchReason::PathAdded,
                    "unexpected reason {reason:?}"
                );
            }
            other => panic!("expected a Switched event, got {other:?}"),
        }
    }

    #[test]
    fn hold_not_elapsed_no_switch_yet() {
        // S4 boundary: margin met but hold time not elapsed -> still pinned.
        let mut cfg = fast_config();
        cfg.switch_hold_ms = 10_000; // long hold
        let mut pm = PathManager::new(cfg);
        pm.add_candidate(candidate(PathKind::Direct, 9001, 0.0));
        pm.add_candidate(candidate(PathKind::Turn, 9002, 5.0));
        pm.on_stats(&addr(9001), stats(10, 0.0));
        pm.on_stats(&addr(9002), stats(50, 0.0));
        pm.on_stats(&addr(9001), stats(2000, 0.5)); // huge margin, hold just started
        pm.on_stats(&addr(9002), stats(50, 0.0));
        assert_eq!(
            pm.current_path().unwrap().kind,
            PathKind::Direct,
            "S4 violated: switched before switch_hold_ms elapsed"
        );
    }

    #[test]
    fn missed_probes_trigger_immediate_failover() {
        // S6: max_missed_probes consecutive 100%-loss reports -> instant switch.
        let mut pm = PathManager::new(fast_config());
        pm.add_candidate(candidate(PathKind::Direct, 9001, 0.0));
        pm.add_candidate(candidate(PathKind::Turn, 9002, 5.0));
        pm.on_stats(&addr(9001), stats(10, 0.0));
        pm.on_stats(&addr(9002), stats(50, 0.0));
        assert_eq!(pm.current_path().unwrap().kind, PathKind::Direct);
        let missed = || PathStats {
            rtt_ms: None,
            loss_rate: Some(1.0),
            throughput_bps: None,
        };
        pm.on_stats(&addr(9001), missed());
        pm.on_stats(&addr(9001), missed());
        assert_eq!(pm.current_path().unwrap().kind, PathKind::Direct); // 2 < 3
        pm.on_stats(&addr(9001), missed()); // 3rd -> failover, no hold wait
        assert_eq!(pm.current_path().unwrap().kind, PathKind::Turn);
        match pm.poll_event() {
            Some(PathEvent::Switched {
                from, to, reason, ..
            }) => {
                assert_eq!(from.kind, PathKind::Direct);
                assert_eq!(to.kind, PathKind::Turn);
                assert_eq!(reason, SwitchReason::PathFailed);
            }
            other => panic!("expected PathFailed switch, got {other:?}"),
        }
    }

    #[test]
    fn single_active_path_among_many() {
        // S1: exactly one active path at any time.
        let mut pm = PathManager::new(fast_config());
        for (i, kind) in [
            PathKind::Direct,
            PathKind::Mesh,
            PathKind::Turn,
            PathKind::Proxy,
        ]
        .iter()
        .enumerate()
        {
            pm.add_candidate(candidate(*kind, 9001 + i as u16, i as f64));
            pm.on_stats(&addr(9001 + i as u16), stats(20 + i as u64 * 10, 0.0));
        }
        assert_eq!(pm.current_path().unwrap().kind, PathKind::Direct);
    }

    #[test]
    fn remove_active_reselects_best_remaining() {
        let mut pm = PathManager::new(fast_config());
        pm.add_candidate(candidate(PathKind::Direct, 9001, 0.0));
        pm.add_candidate(candidate(PathKind::Turn, 9002, 5.0));
        pm.on_stats(&addr(9001), stats(10, 0.0));
        pm.on_stats(&addr(9002), stats(50, 0.0));
        assert_eq!(pm.current_path().unwrap().kind, PathKind::Direct);
        pm.remove_candidate(&addr(9001));
        assert_eq!(pm.current_path().unwrap().kind, PathKind::Turn);
        pm.remove_candidate(&addr(9002));
        assert!(pm.current_path().is_none());
    }

    #[test]
    fn remove_active_emits_switched_event() {
        // S9: removing the active path with a backup available must emit
        // `PathEvent::Switched` (S6's event form).
        let mut pm = PathManager::new(fast_config());
        pm.add_candidate(candidate(PathKind::Direct, 9001, 0.0));
        pm.add_candidate(candidate(PathKind::Turn, 9002, 5.0));
        pm.on_stats(&addr(9001), stats(10, 0.0));
        pm.on_stats(&addr(9002), stats(50, 0.0));
        let active = pm.current_path().unwrap().remote_addr;
        // Drain any events from setup so only remove_candidate's event remains.
        while pm.poll_event().is_some() {}
        pm.remove_candidate(&active);
        match pm.poll_event() {
            Some(PathEvent::Switched { from, to, reason }) => {
                assert_eq!(from.remote_addr, active);
                assert_ne!(to.remote_addr, active);
                assert_eq!(reason, SwitchReason::PathFailed);
            }
            other => panic!("expected Switched after removing active path, got {other:?}"),
        }
    }

    #[test]
    fn remove_last_candidate_emits_no_event() {
        // S9: no backup -> no Switched (nothing to switch to).
        let mut pm = PathManager::new(fast_config());
        pm.add_candidate(candidate(PathKind::Direct, 9001, 0.0));
        pm.on_stats(&addr(9001), stats(10, 0.0));
        while pm.poll_event().is_some() {}
        pm.remove_candidate(&addr(9001));
        assert!(pm.current_path().is_none());
        assert!(pm.poll_event().is_none());
    }

    #[test]
    fn cost_is_explicit_score_term() {
        // S8: cost enters the score as a visible linear term.
        let mut pm = PathManager::new(fast_config());
        pm.add_candidate(candidate(PathKind::Turn, 9002, 2.0));
        pm.add_candidate(candidate(PathKind::Proxy, 9003, 8.0));
        pm.on_stats(&addr(9002), stats(30, 0.0));
        pm.on_stats(&addr(9003), stats(30, 0.0));
        let s_turn = pm.score(&addr(9002)).unwrap();
        let s_proxy = pm.score(&addr(9003)).unwrap();
        let expected = W_COST * (8.0 - 2.0);
        assert!(
            ((s_turn - s_proxy) - expected).abs() < 1e-9,
            "S8: cost must be an explicit linear term"
        );
    }

    #[test]
    fn unknown_remote_report_ignored() {
        let mut pm = PathManager::new(fast_config());
        pm.on_stats(&addr(9999), stats(10, 0.0)); // no such candidate
        assert!(pm.current_path().is_none());
        assert_eq!(pm.score(&addr(9999)), None);
    }
}
