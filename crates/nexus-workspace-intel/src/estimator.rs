//! WorkingSetEstimator（v9 §21）：推断近期高概率数据。
//!
//! 输入（v9 原文）：Snapshot、Profile、Graph、Recent Trace、Task Context、Cache State。
//! 纯函数、确定性、整数分（0..=10000），可重放、可单测。
//!
//! 打分公式（权重冻结，见 `SCORE_*` 常量）：
//! ```text
//! score = 4000 * recency + 2500 * frequency + 2000 * graph + 1000 * profile + 500 * task
//! ```
//! - recency：最近访问距"现在"（轨迹最大时刻）越近分越高，1h 窗口线性衰减；
//! - frequency：访问次数 / 全场最大次数；
//! - graph：指向该路径的边 × 源路径新鲜度，加权求和后归一；
//! - profile：在激活 profile 内；
//! - task：路径命中 TaskContext 前缀
//!
//! 已缓存路径得 0 分（无拉取需求）；同分按路径字典序（确定性）。

use std::collections::HashMap;

use crate::graph::WorkspaceGraph;
use crate::profile::Profile;
use crate::trace::AccessTrace;

/// 新鲜度窗口（秒）：超过此窗口未访问的 recency 归零。
pub const RECENCY_WINDOW_SECS: u64 = 3600;
/// graph 分归一化基数（文档化调参点）。
pub const GRAPH_NORM: f64 = 4.0;

const SCORE_RECENCY: u32 = 4000;
const SCORE_FREQUENCY: u32 = 2500;
const SCORE_GRAPH: u32 = 2000;
const SCORE_PROFILE: u32 = 1000;
const SCORE_TASK: u32 = 500;

/// 任务上下文：当前任务相关的路径前缀（如正在改的模块目录）。
#[derive(Debug, Clone, Default)]
pub struct TaskContext {
    /// 活跃路径前缀。
    pub active_paths: Vec<String>,
}

/// 缓存状态：已在本地的路径 → 字节数。
#[derive(Debug, Clone, Default)]
pub struct CacheState {
    cached: HashMap<String, u64>,
}

impl CacheState {
    /// 标记已缓存。
    pub fn insert(&mut self, path: &str, bytes: u64) {
        self.cached.insert(path.to_string(), bytes);
    }

    /// 是否已缓存。
    #[must_use]
    pub fn contains(&self, path: &str) -> bool {
        self.cached.contains_key(path)
    }

    /// 已缓存字节数。
    #[must_use]
    pub fn bytes(&self, path: &str) -> Option<u64> {
        self.cached.get(path).copied()
    }
}

/// 估计器输入（全部借用，无拷贝、无 I/O）。
#[derive(Debug)]
pub struct EstimatorInput<'a> {
    pub snapshot_paths: &'a [String],
    pub profile: Option<&'a Profile>,
    pub graph: &'a WorkspaceGraph,
    pub trace: &'a AccessTrace,
    pub task_context: &'a TaskContext,
    pub cache: &'a CacheState,
    /// 返回前 N（0 = 全部）。
    pub top_n: usize,
}

/// 打分后的路径。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScoredPath {
    pub path: String,
    /// 0..=10000，越高越可能近期被需要。
    pub score: u32,
    /// 非零分项的可解释记录（DecisionTrace 风格）。
    pub reasons: Vec<String>,
}

/// WorkingSet 估计器（无状态，可复用）。
#[derive(Debug, Default)]
pub struct WorkingSetEstimator;

impl WorkingSetEstimator {
    /// 新估计器。
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// 对快照路径打分并排序（分数降序，同分路径升序）。
    #[must_use]
    pub fn estimate(&self, input: &EstimatorInput<'_>) -> Vec<ScoredPath> {
        let now = input.trace.max_time().unwrap_or(0);
        let max_count = input
            .snapshot_paths
            .iter()
            .map(|p| input.trace.count_for(p))
            .max()
            .unwrap_or(0)
            .max(1);

        let mut out: Vec<ScoredPath> = input
            .snapshot_paths
            .iter()
            .map(|p| self.score_one(p, input, now, max_count))
            .collect();
        out.sort_by(|a, b| b.score.cmp(&a.score).then(a.path.cmp(&b.path)));
        if input.top_n > 0 && out.len() > input.top_n {
            out.truncate(input.top_n);
        }
        out
    }

    fn score_one(
        &self,
        path: &str,
        input: &EstimatorInput<'_>,
        now: u64,
        max_count: u64,
    ) -> ScoredPath {
        let mut reasons = Vec::new();
        // 已缓存：无拉取需求，直接 0 分。
        if input.cache.contains(path) {
            reasons.push("cached:0".to_string());
            return ScoredPath {
                path: path.to_string(),
                score: 0,
                reasons,
            };
        }

        let mut score: u32 = 0;

        // recency
        if let Some(last) = input.trace.last_access(path) {
            let age = now.saturating_sub(last);
            if age < RECENCY_WINDOW_SECS {
                let r = (SCORE_RECENCY as u64 * (RECENCY_WINDOW_SECS - age) / RECENCY_WINDOW_SECS)
                    as u32;
                score += r;
                reasons.push(format!("recency:{r}"));
            }
        }

        // frequency
        let count = input.trace.count_for(path);
        if count > 0 {
            let f = (SCORE_FREQUENCY as u64 * count / max_count) as u32;
            score += f;
            reasons.push(format!("frequency:{f}"));
        }

        // graph：指向本路径的边 × 源新鲜度
        let mut raw = 0.0f64;
        for q in input.snapshot_paths {
            if q == path {
                continue;
            }
            let w = input.graph.edge_weight(q, path);
            if w > 0.0 {
                let freshness = match input.trace.last_access(q) {
                    Some(last) => {
                        let age = now.saturating_sub(last);
                        if age < RECENCY_WINDOW_SECS {
                            (RECENCY_WINDOW_SECS - age) as f64 / RECENCY_WINDOW_SECS as f64
                        } else {
                            0.0
                        }
                    }
                    None => 0.0,
                };
                raw += w * freshness;
            }
        }
        if raw > 0.0 {
            let g = ((SCORE_GRAPH as f64 * raw / GRAPH_NORM).min(SCORE_GRAPH as f64)) as u32;
            score += g;
            reasons.push(format!("graph:{g}"));
        }

        // profile
        if let Some(p) = input.profile {
            if p.contains(path) {
                let w = p.weight.clamp(0.0, 1.0);
                let ps = (SCORE_PROFILE as f64 * w) as u32;
                score += ps;
                reasons.push(format!("profile:{ps}"));
            }
        }

        // task context
        if input
            .task_context
            .active_paths
            .iter()
            .any(|pre| path.starts_with(pre.as_str()))
        {
            score += SCORE_TASK;
            reasons.push(format!("task:{}", SCORE_TASK));
        }

        ScoredPath {
            path: path.to_string(),
            score,
            reasons,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::WorkspaceGraph;
    use crate::profile::Profile;
    use crate::trace::AccessTrace;

    fn fixture() -> (Vec<String>, AccessTrace, WorkspaceGraph) {
        let paths = vec![
            "src/main.rs".to_string(),
            "src/lib.rs".to_string(),
            "README.md".to_string(),
        ];
        let mut t = AccessTrace::new();
        for i in 0..5 {
            t.record("src/main.rs", 100 + i * 10);
        }
        t.record("src/lib.rs", 200);
        t.record("README.md", 10);
        let g = WorkspaceGraph::build(&paths, &t);
        (paths, t, g)
    }

    #[test]
    fn hot_beats_cold() {
        let (paths, trace, graph) = fixture();
        let est = WorkingSetEstimator::new();
        let cache = CacheState::default();
        let ctx = TaskContext::default();
        let ranked = est.estimate(&EstimatorInput {
            snapshot_paths: &paths,
            profile: None,
            graph: &graph,
            trace: &trace,
            task_context: &ctx,
            cache: &cache,
            top_n: 0,
        });
        assert_eq!(ranked[0].path, "src/main.rs");
        assert_eq!(ranked[2].path, "README.md");
        assert!(!ranked[0].reasons.is_empty());
    }

    #[test]
    fn cached_scores_zero() {
        let (paths, trace, graph) = fixture();
        let est = WorkingSetEstimator::new();
        let mut cache = CacheState::default();
        cache.insert("src/main.rs", 100);
        let ctx = TaskContext::default();
        let ranked = est.estimate(&EstimatorInput {
            snapshot_paths: &paths,
            profile: None,
            graph: &graph,
            trace: &trace,
            task_context: &ctx,
            cache: &cache,
            top_n: 0,
        });
        let hot = ranked.iter().find(|s| s.path == "src/main.rs").unwrap();
        assert_eq!(hot.score, 0);
        // 未缓存的 lib 顶上
        assert_eq!(ranked[0].path, "src/lib.rs");
    }

    #[test]
    fn deterministic_tie_break() {
        let est = WorkingSetEstimator::new();
        let paths = vec!["b".to_string(), "a".to_string()];
        let trace = AccessTrace::new();
        let graph = WorkspaceGraph::build(&paths, &trace);
        let cache = CacheState::default();
        let ctx = TaskContext::default();
        let ranked = est.estimate(&EstimatorInput {
            snapshot_paths: &paths,
            profile: None,
            graph: &graph,
            trace: &trace,
            task_context: &ctx,
            cache: &cache,
            top_n: 0,
        });
        // 都 0 分 → 路径升序
        assert_eq!(ranked[0].path, "a");
        assert_eq!(ranked[1].path, "b");
    }

    #[test]
    fn profile_and_task_boost() {
        let (paths, trace, graph) = fixture();
        let est = WorkingSetEstimator::new();
        let cache = CacheState::default();
        let profile = Profile::declare("x", vec!["README.md".into()], 1.0);
        let ctx = TaskContext {
            active_paths: vec!["src/".into()],
        };
        let ranked = est.estimate(&EstimatorInput {
            snapshot_paths: &paths,
            profile: Some(&profile),
            graph: &graph,
            trace: &trace,
            task_context: &ctx,
            cache: &cache,
            top_n: 0,
        });
        let readme = ranked.iter().find(|s| s.path == "README.md").unwrap();
        assert!(readme.reasons.iter().any(|r| r.starts_with("profile:")));
        let main = ranked.iter().find(|s| s.path == "src/main.rs").unwrap();
        assert!(main.reasons.iter().any(|r| r.starts_with("task:")));
    }
}
