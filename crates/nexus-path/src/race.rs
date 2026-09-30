//! Staggered connection racing (R1, R4, R5).
//!
//! Tries candidate paths in preference order, staggering the starts so the
//! preferred path gets a head start. The first success wins; losers are
//! cancelled cooperatively. Budgets bound the stagger delay, parallelism,
//! and total time.
//!
//! Sync only: `std::thread` + `mpsc`, zero async runtime (R5).
//! `race_connect` blocks until a winner or the total timeout.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crate::CandidatePath;

/// Budgets for a single `race_connect` call (R1).
#[derive(Debug, Clone)]
pub struct RaceBudget {
    /// Head start for the preferred candidate before the next is launched.
    pub stagger_delay_ms: u64,
    /// Maximum concurrent connection attempts.
    pub max_parallel: usize,
    /// Total wall-clock budget; exceeding it fails the race.
    pub total_timeout_ms: u64,
}

impl Default for RaceBudget {
    fn default() -> Self {
        Self {
            stagger_delay_ms: 200,
            max_parallel: 2,
            total_timeout_ms: 5000,
        }
    }
}

/// Something that can attempt a connection over a candidate path.
///
/// The implementor MUST poll `cancel` and return promptly when it is set
/// (R5). `Ok(bytes)` = success, reporting bytes sent during the attempt
/// (used for `wasted_bytes` accounting, R4).
pub trait PathConnector: Send + Sync {
    fn connect(&self, path: &CandidatePath, cancel: &AtomicBool) -> io::Result<u64>;
}

/// Outcome of a successful race (R4).
#[derive(Debug)]
pub struct RaceOutcome {
    /// The winning path (first success).
    pub winner: CandidatePath,
    /// Number of attempts actually launched (`<= max_parallel`).
    pub attempts: u32,
    /// Bytes consumed by non-winning attempts that ran to completion.
    /// Attempts still in flight when the winner was found are cancelled and
    /// NOT counted (their final byte count is unobservable — honest omission).
    pub wasted_bytes: u64,
    /// Wall-clock time from race start to winner.
    pub elapsed_ms: u64,
}

/// Sort key for stagger order: preferred kind first, then lower cost.
fn stagger_order(candidates: &[CandidatePath]) -> Vec<CandidatePath> {
    let mut sorted = candidates.to_vec();
    sorted.sort_by(|a, b| {
        (a.kind, a.cost)
            .partial_cmp(&(b.kind, b.cost))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    sorted
}

// Note: PathKind derives Ord (Direct < Mesh < Turn < Proxy), so tuple
// comparison gives kind-major, cost-minor ordering. NaN cost falls back
// to Equal (stable, no panic).

/// Race to establish connectivity over the candidate paths (R1).
///
/// Candidates are tried in stagger order (see [`stagger_order`]). The first
/// candidate starts immediately; if it hasn't succeeded within
/// `stagger_delay_ms`, the next starts, up to `max_parallel` concurrent
/// attempts. The first `Ok` wins; all other attempts are cancelled via the
/// shared flag and joined. If `total_timeout_ms` elapses with no success,
/// returns `io::ErrorKind::TimedOut`.
///
/// Errors:
/// - `InvalidInput` when `candidates` is empty.
/// - `TimedOut` when the total budget expires.
/// - Otherwise, the last attempt's error (all attempts failed).
pub fn race_connect(
    candidates: &[CandidatePath],
    connector: &dyn PathConnector,
    budget: &RaceBudget,
) -> io::Result<RaceOutcome> {
    if candidates.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "race_connect: no candidates",
        ));
    }

    let ordered = stagger_order(candidates);
    let start = Instant::now();
    let deadline = start + Duration::from_millis(budget.total_timeout_ms);
    let cancel = Arc::new(AtomicBool::new(false));

    // (index, result) channel.
    let (tx, rx) = mpsc::channel::<(usize, io::Result<u64>)>();

    // Scoped threads: they may borrow `connector` and `ordered` from this
    // frame (no 'static required). The scope joins all threads on exit.
    thread::scope(|scope| {
        let mut next_idx = 1usize; // 0 is launched immediately below
        let mut attempts = 0u32;
        let mut running = 0usize; // currently live attempt threads
        let mut last_error: Option<io::Error> = None;
        let mut next_stagger_at;

        // Start the first attempt immediately.
        {
            let tx = tx.clone();
            let cancel = Arc::clone(&cancel);
            let path = ordered[0].clone();
            scope.spawn(move || {
                let res = connector.connect(&path, &cancel);
                // If the race is over, the receiver may be gone; that's fine.
                let _ = tx.send((0, res));
            });
            running += 1;
            attempts += 1;
            next_stagger_at = start + Duration::from_millis(budget.stagger_delay_ms);
        }

        loop {
            let now = Instant::now();
            if now >= deadline {
                break;
            }

            // Stagger: launch next attempt if due and we have capacity.
            if next_idx < ordered.len()
                && running < budget.max_parallel.max(1)
                && now >= next_stagger_at
            {
                let idx = next_idx;
                let tx = tx.clone();
                let cancel = Arc::clone(&cancel);
                let path = ordered[idx].clone();
                scope.spawn(move || {
                    let res = connector.connect(&path, &cancel);
                    let _ = tx.send((idx, res));
                });
                running += 1;
                attempts += 1;
                next_idx += 1;
                next_stagger_at = now + Duration::from_millis(budget.stagger_delay_ms);
            }

            // Wait for the next completion, but no longer than the next deadline.
            let wait_until = next_stagger_at.min(deadline);
            let timeout = wait_until.saturating_duration_since(Instant::now());
            match rx.recv_timeout(timeout) {
                Ok((idx, res)) => {
                    running -= 1;
                    match res {
                        Ok(_bytes) => {
                            // Winner! Cancel the rest; scope will join them.
                            cancel.store(true, Ordering::SeqCst);
                            let mut wasted = 0u64;
                            // Drain any already-completed non-winner results.
                            while let Ok((other_idx, other_res)) = rx.try_recv() {
                                if other_idx != idx {
                                    if let Ok(b) = other_res {
                                        wasted += b;
                                    }
                                }
                            }
                            // Note: attempts still running when we return are
                            // cancelled (via `cancel`) and joined by the scope.
                            // Their byte counts are unobservable -> not in
                            // `wasted_bytes` (R4 honest omission).
                            return Ok(RaceOutcome {
                                winner: ordered[idx].clone(),
                                attempts,
                                wasted_bytes: wasted,
                                elapsed_ms: start.elapsed().as_millis() as u64,
                            });
                        }
                        Err(e) => {
                            last_error = Some(e);
                            // If all launched attempts failed and none remain
                            // to launch, the race is lost.
                            if running == 0 && next_idx >= ordered.len() {
                                break;
                            }
                        }
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    // Loop around: maybe stagger the next attempt.
                    continue;
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    // All senders gone without a result — shouldn't happen,
                    // but treat as failure rather than hang.
                    break;
                }
            }
        }

        // Timeout or all-failed: cancel; scope joins the threads.
        cancel.store(true, Ordering::SeqCst);
        if Instant::now() >= deadline {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "race_connect: total timeout {}ms exceeded",
                    budget.total_timeout_ms
                ),
            ))
        } else {
            Err(last_error.unwrap_or_else(|| io::Error::other("race_connect: all attempts failed")))
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PathKind;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::atomic::AtomicUsize;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    fn path(kind: PathKind, port: u16, cost: f64) -> CandidatePath {
        CandidatePath {
            kind,
            local_addr: addr(1),
            remote_addr: addr(port),
            cost,
        }
    }

    /// Fake connector: sleeps `delay_ms`, then succeeds (unless cancelled).
    struct FakeConnector {
        delay_ms: u64,
        bytes: u64,
        calls: AtomicUsize,
    }

    impl FakeConnector {
        fn new(delay_ms: u64, bytes: u64) -> Self {
            Self {
                delay_ms,
                bytes,
                calls: AtomicUsize::new(0),
            }
        }
    }

    impl PathConnector for FakeConnector {
        fn connect(&self, _path: &CandidatePath, cancel: &AtomicBool) -> io::Result<u64> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let deadline = Instant::now() + Duration::from_millis(self.delay_ms);
            while Instant::now() < deadline {
                if cancel.load(Ordering::SeqCst) {
                    return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
                }
                thread::sleep(Duration::from_millis(5));
            }
            if cancel.load(Ordering::SeqCst) {
                return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
            }
            Ok(self.bytes)
        }
    }

    /// Connector that routes by port: slow port vs everything else (fast).
    struct PortRouter {
        slow_port: u16,
    }

    impl PathConnector for PortRouter {
        fn connect(&self, path: &CandidatePath, cancel: &AtomicBool) -> io::Result<u64> {
            let delay = if path.remote_addr.port() == self.slow_port {
                800
            } else {
                50
            };
            FakeConnector::new(delay, 100).connect(path, cancel)
        }
    }

    #[test]
    fn empty_candidates_rejected() {
        let budget = RaceBudget::default();
        let conn = FakeConnector::new(10, 0);
        let err = race_connect(&[], &conn, &budget).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn stagger_order_prefers_kind_then_cost() {
        let turn_cheap = path(PathKind::Turn, 9002, 1.0);
        let direct_expensive = path(PathKind::Direct, 9001, 9.0);
        let direct_cheap = path(PathKind::Direct, 9003, 0.5);
        let ordered = stagger_order(&[turn_cheap, direct_expensive, direct_cheap]);
        // Direct (kind) before Turn, regardless of cost; then cost ascending.
        assert_eq!(ordered[0].remote_addr.port(), 9003);
        assert_eq!(ordered[1].remote_addr.port(), 9001);
        assert_eq!(ordered[2].remote_addr.port(), 9002);
    }

    #[test]
    fn fast_path_wins_despite_stagger() {
        // Direct is preferred (stagger order) but slow (800ms);
        // Turn starts 200ms later but finishes in 50ms -> Turn wins.
        let candidates = vec![
            path(PathKind::Direct, 9001, 0.0),
            path(PathKind::Turn, 9002, 5.0),
        ];
        let conn = PortRouter { slow_port: 9001 };
        let budget = RaceBudget {
            stagger_delay_ms: 200,
            max_parallel: 2,
            total_timeout_ms: 5000,
        };
        let outcome = race_connect(&candidates, &conn, &budget).unwrap();
        assert_eq!(outcome.winner.kind, PathKind::Turn);
        assert!(outcome.attempts <= 2, "attempts={}", outcome.attempts);
        assert!(outcome.elapsed_ms < 1000, "elapsed={}", outcome.elapsed_ms);
    }

    #[test]
    fn preferred_path_wins_when_fast_enough() {
        // Direct succeeds in 50ms < stagger 200ms -> only 1 attempt.
        let candidates = vec![
            path(PathKind::Direct, 9001, 0.0),
            path(PathKind::Turn, 9002, 5.0),
        ];
        let conn = PortRouter {
            slow_port: 9002, // turn is slow here; direct (9001) is fast
        };
        let budget = RaceBudget::default();
        let outcome = race_connect(&candidates, &conn, &budget).unwrap();
        assert_eq!(outcome.winner.kind, PathKind::Direct);
        assert_eq!(outcome.attempts, 1);
    }

    #[test]
    fn total_timeout_enforced() {
        let candidates = vec![path(PathKind::Direct, 9001, 0.0)];
        let conn = FakeConnector::new(10_000, 0); // hangs
        let budget = RaceBudget {
            stagger_delay_ms: 200,
            max_parallel: 2,
            total_timeout_ms: 300,
        };
        let start = Instant::now();
        let err = race_connect(&candidates, &conn, &budget).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(start.elapsed().as_millis() < 2000);
    }

    #[test]
    fn all_fail_returns_last_error() {
        struct Fail;
        impl PathConnector for Fail {
            fn connect(&self, _: &CandidatePath, _: &AtomicBool) -> io::Result<u64> {
                Err(io::Error::new(io::ErrorKind::ConnectionRefused, "nope"))
            }
        }
        let candidates = vec![path(PathKind::Direct, 9001, 0.0)];
        let err = race_connect(&candidates, &Fail, &RaceBudget::default()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);
    }
}
