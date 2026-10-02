//! 访问轨迹：观测图（Observed Access Graph）的唯一事实来源。
//!
//! 只记录"何时访问了哪个路径"，不解释原因、不做聚合——聚合是
//! `WorkspaceGraph` / `WorkingSetEstimator` 的职责（v9 §21：trace 是输入）。

use serde::{Deserialize, Serialize};

/// 单次访问事件。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessEvent {
    /// 被访问的 workspace 路径。
    pub path: String,
    /// 访问时刻（unix 秒；调用方提供时钟，保持本 crate 时钟无关）。
    pub at_unix: u64,
}

/// 访问轨迹：按时间追加的事件序列。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AccessTrace {
    events: Vec<AccessEvent>,
}

impl AccessTrace {
    /// 空轨迹。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 记录一次访问（O(1) 追加）。
    pub fn record(&mut self, path: &str, at_unix: u64) {
        self.events.push(AccessEvent {
            path: path.to_string(),
            at_unix,
        });
    }

    /// 全部事件（按记录顺序）。
    #[must_use]
    pub fn events(&self) -> &[AccessEvent] {
        &self.events
    }

    /// 事件数。
    #[must_use]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// 是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// 某时刻之后（含）的事件。
    pub fn recent(&self, since_unix: u64) -> impl Iterator<Item = &AccessEvent> {
        self.events.iter().filter(move |e| e.at_unix >= since_unix)
    }

    /// 轨迹中的最大时刻（`None` = 空轨迹）。估计器用它做"现在"，保证确定性。
    #[must_use]
    pub fn max_time(&self) -> Option<u64> {
        self.events.iter().map(|e| e.at_unix).max()
    }

    /// 某路径的访问次数。
    #[must_use]
    pub fn count_for(&self, path: &str) -> u64 {
        self.events.iter().filter(|e| e.path == path).count() as u64
    }

    /// 某路径的最近访问时刻。
    #[must_use]
    pub fn last_access(&self, path: &str) -> Option<u64> {
        self.events
            .iter()
            .filter(|e| e.path == path)
            .map(|e| e.at_unix)
            .max()
    }

    /// 去重路径集合（按首次出现顺序）。
    #[must_use]
    pub fn distinct_paths(&self) -> Vec<String> {
        let mut seen = std::collections::HashSet::new();
        let mut out = Vec::new();
        for e in &self.events {
            if seen.insert(e.path.clone()) {
                out.push(e.path.clone());
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_and_query() {
        let mut t = AccessTrace::new();
        assert!(t.is_empty());
        t.record("a", 10);
        t.record("b", 20);
        t.record("a", 30);
        assert_eq!(t.len(), 3);
        assert_eq!(t.count_for("a"), 2);
        assert_eq!(t.last_access("a"), Some(30));
        assert_eq!(t.max_time(), Some(30));
        assert_eq!(t.recent(20).count(), 2);
        assert_eq!(t.distinct_paths(), vec!["a".to_string(), "b".to_string()]);
    }
}
