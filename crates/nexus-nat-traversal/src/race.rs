//! P5: three-class path race (Track C).
//!
//! After a successful hole punch, the direct P2P path becomes *one candidate
//! among three* (`DirectP2P`, `TurnRelay`, `PeerRelay`). `select_path` applies
//! the frozen hysteresis semantics: a challenger wins only if its score beats
//! the current path by the threshold (20%, or 10% in boost mode) **and** the
//! current path has held for the hold time (3s, or 1s in boost mode).
//! Punch success therefore never implies an automatic switch.

use crate::{RaceClass, ScoredPath};

/// Frozen scoring formula: `score = rtt_ms * (1 + loss * 10)`.
#[must_use]
pub fn path_score(rtt_ms: u64, loss_01: f64) -> f64 {
    rtt_ms as f64 * (1.0 + loss_01 * 10.0)
}

/// Select the winning path class under the frozen hysteresis semantics.
///
/// - `threshold`: 20% normally, 10% when `boost` is true.
/// - `hold`: challenger wins only if `now_ms - current_since_ms >= hold`
///   (3000ms normally, 1000ms in boost mode).
/// - Degenerate: `paths` empty or not containing `current` → the class with
///   the smallest score wins (empty `paths` keeps `current`: no information).
/// - Pure function: the clock is caller-supplied; never reads system time.
#[must_use]
pub fn select_path(
    paths: &[ScoredPath],
    current: RaceClass,
    current_since_ms: u64,
    now_ms: u64,
    boost: bool,
) -> RaceClass {
    // Frozen hysteresis parameters (contract P5).
    let (threshold, hold_ms) = if boost {
        (0.10_f64, 1000_u64)
    } else {
        (0.20_f64, 3000_u64)
    };

    // Degenerate: `paths` empty or not containing `current` → the class with
    // the smallest score wins (empty `paths` keeps `current`: no information).
    let current_score = paths
        .iter()
        .find(|p| p.class == current)
        .map(|p| path_score(p.rtt_ms, p.loss_01));
    let Some(current_score) = current_score else {
        return best_class(paths).unwrap_or(current);
    };

    // Best challenger: smallest score among non-current classes.
    let mut best: Option<(RaceClass, f64)> = None;
    for p in paths {
        if p.class == current {
            continue;
        }
        let score = path_score(p.rtt_ms, p.loss_01);
        if best.is_none_or(|(_, best_score)| score < best_score) {
            best = Some((p.class, score));
        }
    }

    match best {
        Some((class, score))
            if current_score > 0.0
                && (current_score - score) / current_score >= threshold
                && now_ms.saturating_sub(current_since_ms) >= hold_ms =>
        {
            class
        }
        _ => current,
    }
}

/// Class with the smallest score, or `None` for empty input.
fn best_class(paths: &[ScoredPath]) -> Option<RaceClass> {
    paths
        .iter()
        .min_by(|a, b| {
            path_score(a.rtt_ms, a.loss_01)
                .partial_cmp(&path_score(b.rtt_ms, b.loss_01))
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .map(|p| p.class)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scored(class: RaceClass, rtt_ms: u64, loss_01: f64) -> ScoredPath {
        ScoredPath {
            class,
            rtt_ms,
            loss_01,
        }
    }

    /// Contract: a much-better direct path wins once threshold + hold pass.
    #[test]
    fn direct_wins_when_much_better() {
        let paths = vec![
            scored(RaceClass::TurnRelay, 300, 0.01), // score 330
            scored(RaceClass::DirectP2P, 50, 0.0),   // score 50, ~85% better
        ];
        assert_eq!(
            select_path(&paths, RaceClass::TurnRelay, 0, 5000, false),
            RaceClass::DirectP2P
        );
    }

    /// Contract: no switch when the hold time hasn't elapsed, or when the
    /// improvement is below the threshold even after the hold.
    #[test]
    fn no_switch_within_hysteresis() {
        let paths = vec![
            scored(RaceClass::TurnRelay, 300, 0.01), // 330
            scored(RaceClass::DirectP2P, 50, 0.0),   // 50
        ];
        // Hold not satisfied (2000ms < 3000ms).
        assert_eq!(
            select_path(&paths, RaceClass::TurnRelay, 0, 2000, false),
            RaceClass::TurnRelay
        );
        // Hold satisfied but improvement 15% < 20%.
        let close = vec![
            scored(RaceClass::TurnRelay, 200, 0.0),
            scored(RaceClass::DirectP2P, 170, 0.0),
        ];
        assert_eq!(
            select_path(&close, RaceClass::TurnRelay, 0, 9000, false),
            RaceClass::TurnRelay
        );
    }

    /// User-required semantic: a successful punch only makes direct *a
    /// candidate*. Here direct punched but peer-relay scores better, and
    /// direct isn't good enough vs the current peer-relay path — assert we
    /// do NOT switch to direct.
    #[test]
    fn peer_relay_beats_direct() {
        let paths = vec![
            scored(RaceClass::PeerRelay, 60, 0.0), // current, score 60
            scored(RaceClass::DirectP2P, 55, 0.0), // punched, only 8.3% better
            scored(RaceClass::TurnRelay, 300, 0.02),
        ];
        assert_eq!(
            select_path(&paths, RaceClass::PeerRelay, 0, 9000, false),
            RaceClass::PeerRelay
        );
    }

    /// Contract: boost mode uses the tighter 10% threshold and 1s hold.
    /// 15% improvement: not enough normally, enough in boost mode.
    #[test]
    fn boost_tighter_threshold() {
        let paths = vec![
            scored(RaceClass::TurnRelay, 200, 0.0),
            scored(RaceClass::DirectP2P, 170, 0.0), // 15% better
        ];
        assert_eq!(
            select_path(&paths, RaceClass::TurnRelay, 0, 9000, false),
            RaceClass::TurnRelay
        );
        assert_eq!(
            select_path(&paths, RaceClass::TurnRelay, 0, 1500, true),
            RaceClass::DirectP2P
        );
        // Boost mode but hold not satisfied (500ms < 1000ms).
        assert_eq!(
            select_path(&paths, RaceClass::TurnRelay, 1000, 1500, true),
            RaceClass::TurnRelay
        );
    }

    /// Degenerate semantics: empty paths keep current; paths missing the
    /// current class select the smallest score.
    #[test]
    fn degenerate_empty_or_missing_current() {
        assert_eq!(
            select_path(&[], RaceClass::TurnRelay, 0, 9000, false),
            RaceClass::TurnRelay
        );
        let paths = vec![
            scored(RaceClass::DirectP2P, 50, 0.0),
            scored(RaceClass::PeerRelay, 60, 0.0),
        ];
        assert_eq!(
            select_path(&paths, RaceClass::TurnRelay, 0, 9000, false),
            RaceClass::DirectP2P
        );
    }

    /// E4 `product.nat-punch-race` (logical): timeline simulation.
    /// - t=0: only TURN relay, stable.
    /// - t=1000: direct punches successfully (120ms) — good but hold not met.
    /// - t=2000: direct improves (60ms) — hold still not met.
    /// - t=3000: direct jitters (500ms) — must not flap.
    /// - t=4000: direct recovers (60ms), hold met → switch to DirectP2P.
    /// - t=7000: peer-relay improves (40ms), hold met → switch to PeerRelay.
    /// - t=9000: direct recovers again (55ms) but not good enough vs
    ///   peer-relay (40ms) → stays on PeerRelay.
    #[test]
    fn e4_nat_punch_race_timeline() {
        let turn = || scored(RaceClass::TurnRelay, 300, 0.01); // score 330
        let ticks: Vec<(u64, Vec<ScoredPath>, RaceClass)> = vec![
            (0, vec![turn()], RaceClass::TurnRelay),
            (
                1000,
                vec![turn(), scored(RaceClass::DirectP2P, 120, 0.0)],
                RaceClass::TurnRelay,
            ),
            (
                2000,
                vec![turn(), scored(RaceClass::DirectP2P, 60, 0.0)],
                RaceClass::TurnRelay,
            ),
            (
                3000,
                vec![turn(), scored(RaceClass::DirectP2P, 500, 0.0)],
                RaceClass::TurnRelay,
            ),
            (
                4000,
                vec![
                    turn(),
                    scored(RaceClass::DirectP2P, 60, 0.0),
                    scored(RaceClass::PeerRelay, 90, 0.0),
                ],
                RaceClass::DirectP2P,
            ),
            (
                5000,
                vec![
                    turn(),
                    scored(RaceClass::DirectP2P, 60, 0.0),
                    scored(RaceClass::PeerRelay, 90, 0.0),
                ],
                RaceClass::DirectP2P,
            ),
            (
                6000,
                vec![
                    turn(),
                    scored(RaceClass::DirectP2P, 60, 0.0),
                    scored(RaceClass::PeerRelay, 90, 0.0),
                ],
                RaceClass::DirectP2P,
            ),
            (
                7000,
                vec![
                    turn(),
                    scored(RaceClass::DirectP2P, 60, 0.0),
                    scored(RaceClass::PeerRelay, 40, 0.0),
                ],
                RaceClass::PeerRelay,
            ),
            (
                9000,
                vec![
                    turn(),
                    scored(RaceClass::DirectP2P, 55, 0.0),
                    scored(RaceClass::PeerRelay, 40, 0.0),
                ],
                RaceClass::PeerRelay,
            ),
        ];

        let mut current = RaceClass::TurnRelay;
        let mut since_ms = 0u64;
        for (now_ms, paths, expected) in ticks {
            let winner = select_path(&paths, current, since_ms, now_ms, false);
            assert_eq!(
                winner, expected,
                "t={now_ms}ms: expected {expected:?}, got {winner:?} (current={current:?} since t={since_ms}ms)"
            );
            if winner != current {
                current = winner;
                since_ms = now_ms;
            }
        }
        assert_eq!(current, RaceClass::PeerRelay);
    }
}
