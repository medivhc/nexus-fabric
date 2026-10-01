//! Network Boost v1 胶水（S28）。
//!
//! 把 boost 配置（纯数据，来自 `nexus-network` 的 `BoostPathParams`）映射到
//! `nexus-path` 的选路/建连策略：
//!
//! - `path_config_for_boost`：按给定参数构造 `PathConfig`（其余字段取 `Default`）。
//! - `select_best`：EWMA 驱动选路（文档 §12.5）。**只读**：`&PathManager`，
//!   不修改任何状态（single writer 仍在 `nexus-path`）；选 `score()` 最高者，
//!   全 unknown → `None`。不触发切换——切换仍走 `PathManager` + S4/R3
//!   hysteresis + S9 事件。
//! - `boost_connect`：`race_on_connect = true` → `connect_with_fallback`
//!   （staggered 竞速，R1）；`= false` → 按候选顺序依次直连，首个成功即返回。
//!
//! Sync API，零 tokio（与 `nexus-path` 一致）。

use std::io;
use std::sync::atomic::AtomicBool;

use nexus_path::{
    CandidatePath, FallbackChain, PathConfig, PathConnector, PathManager, RaceBudget, RaceOutcome,
    connect_with_fallback,
};

/// EWMA 选路结果（只读观测，不触发切换）。
#[derive(Debug)]
pub struct BoostSelection<'a> {
    /// 分数最高的候选；全 unknown 时为 `None`（此时 `score` 也是 `None`）。
    pub best: Option<&'a CandidatePath>,
    /// 最优分数（EWMA 平滑值，越高越好；`None` = 无样本，S7）。
    pub score: Option<f64>,
    /// 最优分数是否低于调用方给定的劣化阈值（分数非归一化，阈值由调用方定）。
    pub degraded: bool,
}

/// 按 boost 参数构造 `PathConfig`（其余字段取 `Default`）。
///
/// 纯函数；调用方从 `nexus-network` 的 `BoostPathParams` 取
/// `hysteresis_pct` / `switch_hold_ms` 传入（B3）。
pub fn path_config_for_boost(hysteresis_pct: f64, switch_hold_ms: u64) -> PathConfig {
    PathConfig {
        hysteresis_pct,
        switch_hold_ms,
        ..Default::default()
    }
}

/// EWMA 驱动选路：在给定候选中选 `PathManager::score()` 最高者。
///
/// - 只读：`manager: &PathManager`，不修改任何状态；
/// - `candidates` 由调用方持有（`PathManager` 不暴露候选列表）；
/// - 全 unknown → `best = None`；
/// - `degraded = best_score < degrade_threshold`（阈值调用方定）。
pub fn select_best<'a>(
    manager: &PathManager,
    candidates: &'a [CandidatePath],
    degrade_threshold: f64,
) -> BoostSelection<'a> {
    let mut best: Option<&'a CandidatePath> = None;
    let mut best_score: Option<f64> = None;
    for c in candidates {
        match manager.score(&c.remote_addr) {
            Some(s) if best_score.is_none_or(|b| s > b) => {
                best = Some(c);
                best_score = Some(s);
            }
            _ => {}
        }
    }
    let degraded = best_score.is_some_and(|s| s < degrade_threshold);
    BoostSelection {
        best,
        score: best_score,
        degraded,
    }
}

/// Boost 建连分发。
///
/// - `race_on_connect = true` → `connect_with_fallback`（staggered 竞速，R1/R4/R5）；
/// - `= false` → 按候选顺序依次调用 `connector.connect`，首个成功即返回
///   （无 staggering；`cancel` 恒为未置位——单候选失败即试下一个）。
///
/// 实际 dial 由注入的 `PathConnector` 完成（F2 语义不变）；`chain` 的 F5
/// 计数器仅在竞速路径更新（与 `connect_with_fallback` 一致）。
pub fn boost_connect(
    chain: &mut FallbackChain,
    connector: &dyn PathConnector,
    budget: &RaceBudget,
    race_on_connect: bool,
) -> io::Result<RaceOutcome> {
    if race_on_connect {
        return connect_with_fallback(chain, connector, budget);
    }
    let cancel = AtomicBool::new(false);
    let mut last_err: Option<io::Error> = None;
    for (idx, c) in chain.candidates().iter().enumerate() {
        let attempts = idx as u32 + 1;
        match connector.connect(c, &cancel) {
            Ok(_) => {
                return Ok(RaceOutcome {
                    winner: c.clone(),
                    attempts,
                    wasted_bytes: 0,
                    elapsed_ms: 0,
                });
            }
            Err(e) => last_err = Some(e),
        }
    }
    // 顺序直连不统计浪费字节（诚实省略；竞速路径的 R4 语义由 connect_with_fallback 保持）。
    Err(last_err
        .unwrap_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "empty candidate list")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_path::{PathKind, PathStats};
    use std::net::SocketAddr;
    use std::time::Duration;

    fn addr(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}").parse().unwrap()
    }

    fn candidate(kind: PathKind, port: u16) -> CandidatePath {
        CandidatePath {
            kind,
            local_addr: addr(8000),
            remote_addr: addr(port),
            cost: 0.0,
        }
    }

    fn stats(rtt_ms: u64) -> PathStats {
        PathStats {
            rtt_ms: Some(rtt_ms),
            loss_rate: Some(0.0),
            ..Default::default()
        }
    }

    #[test]
    fn path_config_for_boost_applies_params() {
        let cfg = path_config_for_boost(0.10, 1000);
        assert_eq!(cfg.hysteresis_pct, 0.10);
        assert_eq!(cfg.switch_hold_ms, 1000);
        // 其余取 Default。
        assert_eq!(
            cfg.probe_interval_ms,
            PathConfig::default().probe_interval_ms
        );
    }

    #[test]
    fn select_best_picks_highest_ewma_score() {
        let mut pm = PathManager::new(PathConfig {
            hysteresis_pct: 0.0,
            switch_hold_ms: 0,
            probe_interval_ms: 60_000,
            ewma_alpha: 1.0,
            max_missed_probes: 1000,
            race_budget: RaceBudget::default(),
        });
        let good = candidate(PathKind::Direct, 9001);
        let bad = candidate(PathKind::Proxy, 9002);
        pm.add_candidate(good.clone());
        pm.add_candidate(bad.clone());
        // alpha=1.0：单样本即分数。good rtt 20ms 好于 bad rtt 200ms。
        pm.on_stats(&good.remote_addr, stats(20));
        pm.on_stats(&bad.remote_addr, stats(200));
        // 推进一次探测轮次以外的同步：on_stats 直接更新 EWMA，无需等待。
        let arr = [good.clone(), bad.clone()];
        let sel = select_best(&pm, &arr, 1.0);
        assert!(sel.best.is_some());
        assert_eq!(sel.best.unwrap().remote_addr, good.remote_addr);
        assert!(sel.score.is_some());
        assert!(!sel.degraded, "好路径分数应高于阈值 1.0");

        // 阈值抬高 → degraded。
        let sel2 = select_best(&pm, &arr, 1e9);
        assert!(sel2.degraded);
    }

    #[test]
    fn select_best_all_unknown_returns_none() {
        let pm = PathManager::new(PathConfig::default());
        let c = candidate(PathKind::Direct, 9001);
        // 未喂任何 stats → score() 为 None（S7）。
        let arr = [c];
        let sel = select_best(&pm, &arr, 1.0);
        assert!(sel.best.is_none());
        assert!(sel.score.is_none());
        assert!(!sel.degraded);
    }

    #[test]
    fn select_best_does_not_mutate_manager() {
        // 只读性：调用前后 current_path / score 不变。
        let mut pm = PathManager::new(PathConfig {
            hysteresis_pct: 0.0,
            switch_hold_ms: 0,
            probe_interval_ms: 60_000,
            ewma_alpha: 1.0,
            max_missed_probes: 1000,
            race_budget: RaceBudget::default(),
        });
        let c = candidate(PathKind::Direct, 9001);
        pm.add_candidate(c.clone());
        pm.on_stats(&c.remote_addr, stats(20));
        let before = pm.score(&c.remote_addr);
        let arr = [c];
        let _ = select_best(&pm, &arr, 1.0);
        assert_eq!(pm.score(&arr[0].remote_addr), before);
    }

    /// Fake connector：按预设延迟成功。
    struct FakeConnector {
        latency: Duration,
    }

    impl PathConnector for FakeConnector {
        fn connect(&self, _path: &CandidatePath, cancel: &AtomicBool) -> io::Result<u64> {
            let start = std::time::Instant::now();
            while start.elapsed() < self.latency {
                if cancel.load(std::sync::atomic::Ordering::Relaxed) {
                    return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Ok(128)
        }
    }

    struct FailConnector;

    impl PathConnector for FailConnector {
        fn connect(&self, _path: &CandidatePath, _cancel: &AtomicBool) -> io::Result<u64> {
            Err(io::Error::new(io::ErrorKind::ConnectionRefused, "refused"))
        }
    }

    fn test_chain() -> FallbackChain {
        use nexus_path::FallbackConfig;
        FallbackChain::expand(
            &FallbackConfig {
                proxy: None,
                turn: None,
            },
            addr(8000),
            addr(9001),
        )
    }

    #[test]
    fn boost_connect_race_on_uses_racing() {
        // race_on_connect=true → 走 connect_with_fallback（staggered）。
        // 单候选 Direct：直接成功，attempts == 1。
        let mut chain = test_chain();
        let budget = RaceBudget::default();
        let out = boost_connect(
            &mut chain,
            &FakeConnector {
                latency: Duration::from_millis(10),
            },
            &budget,
            true,
        )
        .unwrap();
        assert_eq!(out.winner.kind, PathKind::Direct);
        assert_eq!(out.attempts, 1);
    }

    #[test]
    fn boost_connect_race_off_sequential() {
        // race_on_connect=false → 顺序直连，首个成功即返回。
        let mut chain = test_chain();
        let budget = RaceBudget::default();
        let out = boost_connect(
            &mut chain,
            &FakeConnector {
                latency: Duration::from_millis(10),
            },
            &budget,
            false,
        )
        .unwrap();
        assert_eq!(out.winner.kind, PathKind::Direct);
        assert_eq!(out.attempts, 1);
        assert_eq!(out.wasted_bytes, 0);
    }

    #[test]
    fn boost_connect_race_off_all_fail_returns_err() {
        let mut chain = test_chain();
        let budget = RaceBudget::default();
        let err = boost_connect(&mut chain, &FailConnector, &budget, false).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);
    }
}
