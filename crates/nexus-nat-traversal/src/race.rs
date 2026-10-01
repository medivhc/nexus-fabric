//! P5 三类路径竞速选择。
//!
//! **Track C 实现**。本文件为 stub：只给出形状，函数体 `todo!()`。

use std::net::SocketAddr;

use crate::{PeerId, PunchRaceFeed, RaceClass, ScoredPath};

/// 三类路径竞速选择（冻结语义见合同 §P5）。
///
/// challenger 的 score 比 current 好 `>=20%`（boost 10%）**且**
/// 持续占优 `>=3s`（boost 1s）才返回 challenger；否则返回 current。
/// `score = rtt_ms as f64 * (1.0 + loss_01 * 10.0)`（冻结公式）。
pub fn select_path(
    _paths: &[ScoredPath],
    _current: RaceClass,
    _current_since_ms: u64,
    _now_ms: u64,
    _boost: bool,
) -> RaceClass {
    todo!(
        "Track C: direct_wins_when_much_better / no_switch_within_hysteresis / peer_relay_beats_direct / boost_tighter_threshold"
    )
}

/// Track C 实现：向路径层登记 direct 候选的 feed。
#[derive(Debug, Default)]
pub struct ScoringFeed;

impl PunchRaceFeed for ScoringFeed {
    fn report_direct_candidate(
        &self,
        _peer: PeerId,
        _addr: SocketAddr,
        _rtt_ms: u64,
        _loss_01: f64,
    ) {
        todo!("Track C")
    }
}
