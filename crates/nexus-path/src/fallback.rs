//! Fallback chain (F1–F5): Direct → Proxy → Turn.
//!
//! Connects the three isolated transport capabilities — direct QUIC via
//! `nexus-fabric`, SOCKS5 proxy via `nexus-proxy-transport`, TURN relay via
//! `nexus-turn` — into one ordered fallback chain (DESIGN §3.5).
//!
//! This module only makes *decisions* (which tier, in which order, what was
//! skipped). It never builds sockets: the actual dialing is done by the
//! injected [`PathConnector`] (provided by the composition root), and session
//! construction stays with `nexus-fabric` (F2, Non-Responsibilities).
//!
//! Chain order is fixed: Direct → Proxy → Turn (approved decision 3; Mesh is
//! postponed). Tiers without configuration are honestly skipped and counted
//! (F4) — never an error, never retried.
//!
//! Attempt order is the chain order: [`connect_with_fallback`] delegates to
//! [`race_connect`], which (R1, 2026-09-30 requirement-change) attempts
//! candidates in caller-provided order without internal re-sorting.

use std::io;
use std::net::SocketAddr;

use crate::{CandidatePath, PathConnector, PathKind, RaceBudget, RaceOutcome, race_connect};

/// Cost for the direct tier in expanded chains: no relay involved.
const DIRECT_COST: f64 = 0.0;
/// Cost for the TURN tier (established value, cf. existing tests).
const TURN_COST: f64 = 5.0;
/// Cost for the proxy tier. Tier cost order is Direct < Mesh < Turn < Proxy,
/// so proxy sits above TURN.
const PROXY_COST: f64 = 8.0;

/// Number of [`PathKind`] variants; sizes the per-kind counter arrays.
const KIND_COUNT: usize = 4;

/// Index into per-kind counter arrays. Relies on `PathKind`'s declaration
/// order (Direct, Mesh, Turn, Proxy); guarded by `kind_discriminants_stable`.
fn kind_idx(kind: PathKind) -> usize {
    debug_assert!((kind as usize) < KIND_COUNT);
    kind as usize
}

/// Minimal proxy endpoint (F1). Authentication and other proxy options stay in
/// the outbound configuration; the composition root maps `Socks5ProxyConfig`
/// onto this type so `nexus-path` keeps zero new dependencies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyEndpoint {
    /// Address of the proxy server (e.g. SOCKS5 `127.0.0.1:1080`).
    pub server: SocketAddr,
}

/// Minimal TURN endpoint (F1). Credentials stay in the TURN server
/// configuration; the composition root maps it onto this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurnEndpoint {
    /// Address of the TURN server.
    pub server: SocketAddr,
}

/// Which fallback tiers are configured (F1). Tiers without configuration are
/// honestly skipped and counted (F4) — never an error, never retried.
#[derive(Debug, Clone, Default)]
pub struct FallbackConfig {
    pub proxy: Option<ProxyEndpoint>,
    pub turn: Option<TurnEndpoint>,
}

/// An expanded fallback chain: ordered candidates plus F4/F5 bookkeeping.
///
/// Built only via [`FallbackChain::expand`]; the candidate list always starts
/// with Direct (F6: empty config ≡ pure direct).
#[derive(Debug)]
pub struct FallbackChain {
    candidates: Vec<CandidatePath>,
    skipped: Vec<PathKind>,
    skipped_counts: [u64; KIND_COUNT],
    attempts: u64,
    wins: [u64; KIND_COUNT],
    current_tier: Option<PathKind>,
}

impl FallbackChain {
    /// Expand a config into the ordered candidate list Direct → Proxy → Turn.
    ///
    /// `local` is the local bind address; `peer` is the ultimate peer address.
    /// For Proxy/Turn candidates, `remote_addr` is the *relay server* (the
    /// dial target); the injected connector resolves the ultimate peer, which
    /// it captures at construction time.
    pub fn expand(config: &FallbackConfig, local: SocketAddr, peer: SocketAddr) -> Self {
        let mut candidates = Vec::with_capacity(3);
        let mut skipped = Vec::new();
        let mut skipped_counts = [0u64; KIND_COUNT];

        // Direct is always present (F6).
        candidates.push(CandidatePath {
            kind: PathKind::Direct,
            local_addr: local,
            remote_addr: peer,
            cost: DIRECT_COST,
        });

        match &config.proxy {
            Some(ep) => candidates.push(CandidatePath {
                kind: PathKind::Proxy,
                local_addr: local,
                remote_addr: ep.server,
                cost: PROXY_COST,
            }),
            None => {
                skipped.push(PathKind::Proxy);
                skipped_counts[kind_idx(PathKind::Proxy)] += 1;
            }
        }

        match &config.turn {
            Some(ep) => candidates.push(CandidatePath {
                kind: PathKind::Turn,
                local_addr: local,
                remote_addr: ep.server,
                cost: TURN_COST,
            }),
            None => {
                skipped.push(PathKind::Turn);
                skipped_counts[kind_idx(PathKind::Turn)] += 1;
            }
        }

        Self {
            candidates,
            skipped,
            skipped_counts,
            attempts: 0,
            wins: [0u64; KIND_COUNT],
            current_tier: None,
        }
    }

    /// Ordered candidates: Direct → Proxy → Turn (configured tiers only).
    pub fn candidates(&self) -> &[CandidatePath] {
        &self.candidates
    }

    /// Tiers skipped for lack of configuration, in chain order (F4).
    pub fn skipped(&self) -> &[PathKind] {
        &self.skipped
    }

    /// How many times `kind` was skipped during expansion (F4).
    pub fn skipped_count(&self, kind: PathKind) -> u64 {
        self.skipped_counts[kind_idx(kind)]
    }

    /// Number of [`connect_with_fallback`] calls (F5).
    pub fn attempts(&self) -> u64 {
        self.attempts
    }

    /// Number of successful connects won by `kind` (F5).
    pub fn wins(&self, kind: PathKind) -> u64 {
        self.wins[kind_idx(kind)]
    }

    /// Winner of the most recent successful connect (F5). Running switches
    /// are observed via `PathManager`/`PathEvent`, not here.
    pub fn current_tier(&self) -> Option<PathKind> {
        self.current_tier
    }
}

/// Staggered connect over the fallback chain (F2).
///
/// Delegates to [`race_connect`] so stagger order, budget enforcement and
/// cooperative cancellation (R1/R5) apply unchanged; the attempt order is the
/// chain order (R1 requirement-change: caller order is respected). The
/// winning tier is `outcome.winner.kind`. F5 counters are updated on success;
/// a failed race still counts as an attempt but changes no win counters.
///
/// The actual dialing (direct socket / SOCKS5 handshake / TURN allocate) is
/// performed by `connector`, provided by the composition root; this function
/// never builds sockets.
pub fn connect_with_fallback(
    chain: &mut FallbackChain,
    connector: &dyn PathConnector,
    budget: &RaceBudget,
) -> io::Result<RaceOutcome> {
    chain.attempts += 1;
    let outcome = race_connect(chain.candidates(), connector, budget)?;
    chain.wins[kind_idx(outcome.winner.kind)] += 1;
    chain.current_tier = Some(outcome.winner.kind);
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PathConfig, PathEvent, PathManager, PathStats, SwitchReason};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;
    use std::time::Duration;

    fn addr(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}").parse().unwrap()
    }

    fn full_config() -> FallbackConfig {
        FallbackConfig {
            proxy: Some(ProxyEndpoint { server: addr(1080) }),
            turn: Some(TurnEndpoint { server: addr(3478) }),
        }
    }

    fn stats(rtt_ms: u64, loss: f64) -> PathStats {
        PathStats {
            rtt_ms: Some(rtt_ms),
            loss_rate: Some(loss),
            throughput_bps: None,
        }
    }

    #[test]
    fn kind_discriminants_stable() {
        // kind_idx relies on PathKind's declaration order.
        assert_eq!(PathKind::Direct as usize, 0);
        assert_eq!(PathKind::Mesh as usize, 1);
        assert_eq!(PathKind::Turn as usize, 2);
        assert_eq!(PathKind::Proxy as usize, 3);
    }

    #[test]
    fn expand_full_chain_order() {
        // F1: chain order is Direct → Proxy → Turn.
        let chain = FallbackChain::expand(&full_config(), addr(1), addr(9000));
        let kinds: Vec<PathKind> = chain.candidates().iter().map(|c| c.kind).collect();
        assert_eq!(
            kinds,
            vec![PathKind::Direct, PathKind::Proxy, PathKind::Turn]
        );
        assert!(chain.skipped().is_empty());
        // Relay candidates dial the relay server, not the peer (F1).
        assert_eq!(chain.candidates()[0].remote_addr, addr(9000));
        assert_eq!(chain.candidates()[1].remote_addr, addr(1080));
        assert_eq!(chain.candidates()[2].remote_addr, addr(3478));
        // Costs follow the tier cost order (S8).
        assert_eq!(chain.candidates()[0].cost, 0.0);
        assert!(chain.candidates()[1].cost > chain.candidates()[2].cost);
    }

    #[test]
    fn expand_skips_missing_tiers() {
        // F4: tiers without config are skipped and counted, no error.
        let chain = FallbackChain::expand(&FallbackConfig::default(), addr(1), addr(9000));
        let kinds: Vec<PathKind> = chain.candidates().iter().map(|c| c.kind).collect();
        assert_eq!(kinds, vec![PathKind::Direct]);
        assert_eq!(chain.skipped(), &[PathKind::Proxy, PathKind::Turn]);
        assert_eq!(chain.skipped_count(PathKind::Proxy), 1);
        assert_eq!(chain.skipped_count(PathKind::Turn), 1);
        assert_eq!(chain.skipped_count(PathKind::Direct), 0);
        assert_eq!(chain.skipped_count(PathKind::Mesh), 0);
    }

    #[test]
    fn expand_partial_proxy_only() {
        let cfg = FallbackConfig {
            proxy: Some(ProxyEndpoint { server: addr(1080) }),
            turn: None,
        };
        let chain = FallbackChain::expand(&cfg, addr(1), addr(9000));
        let kinds: Vec<PathKind> = chain.candidates().iter().map(|c| c.kind).collect();
        assert_eq!(kinds, vec![PathKind::Direct, PathKind::Proxy]);
        assert_eq!(chain.skipped(), &[PathKind::Turn]);
    }

    #[test]
    fn zero_config_is_pure_direct() {
        // F6: empty config behaves exactly like pure direct (zero regression).
        let chain = FallbackChain::expand(&FallbackConfig::default(), addr(1), addr(9000));
        assert_eq!(chain.candidates().len(), 1);
        let c = &chain.candidates()[0];
        assert_eq!(c.kind, PathKind::Direct);
        assert_eq!(c.cost, 0.0);
        assert_eq!(c.remote_addr, addr(9000));
    }

    /// Fake connector: fails the listed kinds, succeeds instantly otherwise.
    struct FailoverConnector {
        fail_kinds: Vec<PathKind>,
    }

    impl PathConnector for FailoverConnector {
        fn connect(&self, path: &CandidatePath, cancel: &AtomicBool) -> io::Result<u64> {
            if cancel.load(Ordering::SeqCst) {
                return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
            }
            if self.fail_kinds.contains(&path.kind) {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "injected failure",
                ));
            }
            Ok(1200)
        }
    }

    #[test]
    fn connect_falls_back_to_proxy_and_counts() {
        // F2: Direct fails fast; Proxy (next in chain order) wins.
        let mut chain = FallbackChain::expand(&full_config(), addr(1), addr(9000));
        let connector = FailoverConnector {
            fail_kinds: vec![PathKind::Direct],
        };
        let budget = RaceBudget {
            stagger_delay_ms: 10,
            max_parallel: 2,
            total_timeout_ms: 5000,
        };
        let outcome = connect_with_fallback(&mut chain, &connector, &budget).unwrap();
        assert_eq!(outcome.winner.kind, PathKind::Proxy);
        // F5: counters updated.
        assert_eq!(chain.attempts(), 1);
        assert_eq!(chain.wins(PathKind::Proxy), 1);
        assert_eq!(chain.wins(PathKind::Direct), 0);
        assert_eq!(chain.wins(PathKind::Turn), 0);
        assert_eq!(chain.current_tier(), Some(PathKind::Proxy));
    }

    #[test]
    fn connect_all_fail_counts_attempt_not_win() {
        // F2/F5: a failed race counts as an attempt but changes no win counters.
        let mut chain = FallbackChain::expand(&full_config(), addr(1), addr(9000));
        let connector = FailoverConnector {
            fail_kinds: vec![PathKind::Direct, PathKind::Proxy, PathKind::Turn],
        };
        let budget = RaceBudget {
            stagger_delay_ms: 10,
            max_parallel: 2,
            total_timeout_ms: 5000,
        };
        let _ = connect_with_fallback(&mut chain, &connector, &budget).unwrap_err();
        assert_eq!(chain.attempts(), 1);
        assert_eq!(chain.wins(PathKind::Proxy), 0);
        assert_eq!(chain.wins(PathKind::Direct), 0);
        assert_eq!(chain.current_tier(), None);
    }

    #[test]
    fn connect_skipped_chain_races_direct_only() {
        // F4+F2: empty config → single Direct candidate raced alone.
        let mut chain = FallbackChain::expand(&FallbackConfig::default(), addr(1), addr(9000));
        let connector = FailoverConnector { fail_kinds: vec![] };
        let budget = RaceBudget {
            stagger_delay_ms: 10,
            max_parallel: 2,
            total_timeout_ms: 5000,
        };
        let outcome = connect_with_fallback(&mut chain, &connector, &budget).unwrap();
        assert_eq!(outcome.winner.kind, PathKind::Direct);
        assert_eq!(outcome.attempts, 1);
        assert_eq!(chain.current_tier(), Some(PathKind::Direct));
    }

    #[test]
    fn chain_candidates_drive_manager_switch() {
        // F3: chain-expanded candidates plug into PathManager unchanged;
        // S9 switching still fires when direct degrades (regression).
        let chain = FallbackChain::expand(&full_config(), addr(8000), addr(9000));
        let mut pm = PathManager::new(PathConfig {
            hysteresis_pct: 0.01, // 1%: tests want switches to trigger easily
            switch_hold_ms: 50,
            probe_interval_ms: 60_000, // keep the probe thread quiet
            ewma_alpha: 1.0,           // no smoothing
            max_missed_probes: 3,
            race_budget: RaceBudget::default(),
        });
        for c in chain.candidates() {
            pm.add_candidate(c.clone());
        }
        // Candidates are keyed by remote_addr: direct→peer, proxy→proxy server.
        let direct = addr(9000);
        let proxy = addr(1080);
        pm.on_stats(&direct, stats(10, 0.0)); // direct healthy (~190.9)
        pm.on_stats(&proxy, stats(60, 0.0)); // proxy healthy but worse (~100.4)
        while pm.poll_event().is_some() {} // drain PathAdded events
        assert_eq!(pm.current_path().unwrap().kind, PathKind::Direct);
        // Degrade direct hard: proxy must take over via S9 (BetterScore).
        for _ in 0..10 {
            pm.on_stats(&direct, stats(2000, 0.5)); // ~50.5
            pm.on_stats(&proxy, stats(60, 0.0)); // ~100.4
            thread::sleep(Duration::from_millis(20));
            if pm.current_path().unwrap().kind == PathKind::Proxy {
                break;
            }
        }
        assert_eq!(pm.current_path().unwrap().kind, PathKind::Proxy);
        match pm.poll_event() {
            Some(PathEvent::Switched { to, reason, .. }) => {
                assert_eq!(to.kind, PathKind::Proxy);
                assert!(
                    reason == SwitchReason::BetterScore || reason == SwitchReason::PathAdded,
                    "unexpected reason {reason:?}"
                );
            }
            other => panic!("expected a Switched event, got {other:?}"),
        }
    }
}
