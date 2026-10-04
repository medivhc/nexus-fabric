//! PrefetchScheduler（v9 §21）：只决定预取什么、何时、并发和预算。
//!
//! 不选 Provider/Path（那是 Core Planner 的事）。输入是估计器的排序输出，
//! 输出是按优先级贪心装入预算的拉取计划。缺失对象的取回走
//! `ResourceDeliveryRequest` → Planner（见 `delivery` 模块）。

use std::collections::HashMap;

use crate::estimator::{CacheState, ScoredPath};

/// 预取预算（Composition Root 按设备/网络状况给定）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefetchBudget {
    /// 本轮最多拉取字节数。
    pub max_bytes: u64,
    /// 建议并发数（"何时"的执行提示，不强制）。
    pub max_concurrent: u32,
}

/// 单个预取项。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefetchItem {
    pub path: String,
    /// 优先级 = 估计器分数（越高越先）。
    pub priority: u32,
    /// 预估字节数（调用方提供的大小表）。
    pub estimated_bytes: u64,
}

/// 预取计划。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefetchPlan {
    /// 按优先级排序的拉取项。
    pub items: Vec<PrefetchItem>,
    /// 因已缓存跳过的项数。
    pub skipped_cached: usize,
    /// 因预算不足跳过的项数。
    pub skipped_budget: usize,
    /// 建议并发度（min(items, max_concurrent)）。
    pub suggested_concurrency: u32,
}

/// 预取调度器（无状态，可复用）。
#[derive(Debug, Default)]
pub struct PrefetchScheduler;

impl PrefetchScheduler {
    /// 新调度器。
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// 生成预取计划：按分数贪心，能装则装；已缓存的跳过（计数）。
    #[must_use]
    pub fn schedule(
        &self,
        ranked: &[ScoredPath],
        cache: &CacheState,
        sizes: &HashMap<String, u64>,
        budget: &PrefetchBudget,
    ) -> PrefetchPlan {
        let mut items = Vec::new();
        let mut skipped_cached = 0usize;
        let mut skipped_budget = 0usize;
        let mut used: u64 = 0;

        for s in ranked {
            if s.score == 0 {
                continue;
            }
            if cache.contains(&s.path) {
                skipped_cached += 1;
                continue;
            }
            let bytes = sizes.get(&s.path).copied().unwrap_or(0);
            if used + bytes <= budget.max_bytes {
                used += bytes;
                items.push(PrefetchItem {
                    path: s.path.clone(),
                    priority: s.score,
                    estimated_bytes: bytes,
                });
            } else {
                skipped_budget += 1;
            }
        }

        let suggested_concurrency = (items.len() as u32).min(budget.max_concurrent).max(1);
        PrefetchPlan {
            items,
            skipped_cached,
            skipped_budget,
            suggested_concurrency,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::estimator::CacheState;

    fn scored(path: &str, score: u32) -> ScoredPath {
        ScoredPath {
            path: path.into(),
            score,
            reasons: vec![],
        }
    }

    #[test]
    fn greedy_respects_budget_and_cache() {
        let ranked = vec![scored("a", 9000), scored("b", 8000), scored("c", 7000)];
        let mut cache = CacheState::default();
        cache.insert("a", 10);
        let sizes: HashMap<String, u64> = [("a", 10), ("b", 60), ("c", 50)]
            .iter()
            .map(|(k, v)| (k.to_string(), *v))
            .collect();
        let sched = PrefetchScheduler::new();
        let plan = sched.schedule(
            &ranked,
            &cache,
            &sizes,
            &PrefetchBudget {
                max_bytes: 100,
                max_concurrent: 4,
            },
        );
        // a 被缓存排除；b(60) 装入；c(50) 60+50>100 跳过
        assert_eq!(plan.items.len(), 1);
        assert_eq!(plan.items[0].path, "b");
        assert_eq!(plan.skipped_cached, 1);
        assert_eq!(plan.skipped_budget, 1);
        assert_eq!(plan.suggested_concurrency, 1);
    }

    #[test]
    fn zero_score_never_scheduled() {
        let ranked = vec![scored("a", 0)];
        let plan = PrefetchScheduler::new().schedule(
            &ranked,
            &CacheState::default(),
            &HashMap::new(),
            &PrefetchBudget {
                max_bytes: 1000,
                max_concurrent: 2,
            },
        );
        assert!(plan.items.is_empty());
    }
}
