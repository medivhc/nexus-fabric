//! Profile（v9 §21）：典型使用情境。
//!
//! Profile 是"人在某种情境下通常用哪些路径"的声明或从轨迹自动捕获的结果。
//! 它是估计器的加权输入之一，不是权威状态（删了重建）。

use serde::{Deserialize, Serialize};

use crate::trace::AccessTrace;

/// 典型使用情境。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Profile {
    /// 情境名（如 `morning-review`）。
    pub name: String,
    /// 该情境下的典型路径。
    pub paths: Vec<String>,
    /// 权重（>0；多 profile 可并存，估计器按权重加权）。
    pub weight: f64,
}

impl Profile {
    /// 声明式 profile。
    #[must_use]
    pub fn declare(name: &str, paths: Vec<String>, weight: f64) -> Self {
        let mut paths = paths;
        paths.sort();
        paths.dedup();
        Self {
            name: name.to_string(),
            paths,
            weight: weight.max(0.0),
        }
    }

    /// 从轨迹窗口自动捕获：窗口内去重路径即该情境的典型路径。
    #[must_use]
    pub fn capture_from_trace(
        name: &str,
        trace: &AccessTrace,
        since_unix: u64,
        weight: f64,
    ) -> Self {
        let paths: Vec<String> = trace
            .recent(since_unix)
            .map(|e| e.path.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        Self::declare(name, paths, weight)
    }

    /// 路径是否属于该情境。
    #[must_use]
    pub fn contains(&self, path: &str) -> bool {
        self.paths.iter().any(|p| p == path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declare_dedups_and_sorts() {
        let p = Profile::declare("x", vec!["b".into(), "a".into(), "b".into()], 1.0);
        assert_eq!(p.paths, vec!["a".to_string(), "b".to_string()]);
        assert!(p.contains("a"));
        assert!(!p.contains("c"));
    }

    #[test]
    fn capture_from_trace_window() {
        let mut t = AccessTrace::new();
        t.record("a", 10);
        t.record("b", 20);
        t.record("c", 100);
        let p = Profile::capture_from_trace("win", &t, 50, 1.0);
        assert_eq!(p.paths, vec!["c".to_string()]);
    }
}
