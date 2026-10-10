//! WorkspaceGraph（v9 §21）：Static Dependency Graph + Observed Access Graph。
//!
//! - 静态边：manifest 路径的 containment 关系（同目录兄弟文件双向边）。
//!   完全由权威快照路径推导，确定性。
//! - 观测边：访问轨迹的共现（A 访问后 W 秒内访问 B ⇒ A→B 边，权重累积）。
//!
//! 图是估计器的输入之一，不做任何决策。

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::trace::AccessTrace;

/// 共现窗口（秒）：窗口内先后访问视为一次共现。
pub const OBSERVE_WINDOW_SECS: u64 = 60;
/// 静态 containment 边的基准权重。
pub const STATIC_EDGE_WEIGHT: f64 = 0.5;

/// 边的来源。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EdgeKind {
    /// 来自 manifest 路径结构。
    Static,
    /// 来自访问轨迹共现。
    Observed,
}

/// 加权有向边。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Edge {
    pub from: String,
    pub to: String,
    pub weight: f64,
    pub kind: EdgeKind,
}

/// Workspace 访问图。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WorkspaceGraph {
    edges: Vec<Edge>,
    nodes: HashSet<String>,
}

impl WorkspaceGraph {
    /// 空图。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 从快照路径 + 访问轨迹建图（纯函数，确定性）。
    #[must_use]
    pub fn build(snapshot_paths: &[String], trace: &AccessTrace) -> Self {
        let mut g = Self::new();
        for p in snapshot_paths {
            g.nodes.insert(p.clone());
        }
        g.add_static_edges(snapshot_paths);
        g.add_observed_edges(trace);
        g
    }

    /// 从 workspace 只读打开（`&Workspace`），用当前 Head 路径建静态部分。
    pub fn build_from_workspace<S: nexus_storage::ContentStore>(
        ws: &nexus_workspace::Workspace<S>,
        trace: &AccessTrace,
    ) -> Result<Self, nexus_workspace::WorkspaceError> {
        let paths = ws.list_head_paths()?;
        Ok(Self::build(&paths, trace))
    }

    /// 同目录兄弟文件：双向静态边。
    fn add_static_edges(&mut self, paths: &[String]) {
        let mut by_dir: HashMap<String, Vec<String>> = HashMap::new();
        for p in paths {
            let dir = parent_dir(p);
            by_dir.entry(dir).or_default().push(p.clone());
        }
        let mut dirs: Vec<String> = by_dir.keys().cloned().collect();
        dirs.sort();
        for dir in dirs {
            let mut members = by_dir.remove(&dir).unwrap_or_default();
            members.sort();
            for i in 0..members.len() {
                for j in (i + 1)..members.len() {
                    self.add_edge(
                        &members[i],
                        &members[j],
                        STATIC_EDGE_WEIGHT,
                        EdgeKind::Static,
                    );
                    self.add_edge(
                        &members[j],
                        &members[i],
                        STATIC_EDGE_WEIGHT,
                        EdgeKind::Static,
                    );
                }
            }
        }
    }

    /// 轨迹共现：按时间排序，相邻事件在窗口内 ⇒ 前→后边权重 +1。
    fn add_observed_edges(&mut self, trace: &AccessTrace) {
        let mut ev: Vec<_> = trace.events().to_vec();
        ev.sort_by_key(|e| e.at_unix);
        // 累积权重：同一对 (from,to) 只保留一条边，权重累加。
        let mut acc: HashMap<(String, String), f64> = HashMap::new();
        for w in ev.windows(2) {
            let (a, b) = (&w[0], &w[1]);
            if a.path == b.path {
                continue;
            }
            if b.at_unix.saturating_sub(a.at_unix) <= OBSERVE_WINDOW_SECS {
                *acc.entry((a.path.clone(), b.path.clone())).or_insert(0.0) += 1.0;
            }
        }
        let mut keys: Vec<_> = acc.keys().cloned().collect();
        keys.sort();
        for (from, to) in keys {
            let w = acc[&(from.clone(), to.clone())];
            self.add_edge(&from, &to, w, EdgeKind::Observed);
        }
    }

    fn add_edge(&mut self, from: &str, to: &str, weight: f64, kind: EdgeKind) {
        // 同一 (from,to,kind) 合并权重，保持边集规范。
        if let Some(e) = self
            .edges
            .iter_mut()
            .find(|e| e.from == from && e.to == to && e.kind == kind)
        {
            e.weight += weight;
            return;
        }
        self.edges.push(Edge {
            from: from.to_string(),
            to: to.to_string(),
            weight,
            kind,
        });
        self.nodes.insert(from.to_string());
        self.nodes.insert(to.to_string());
    }

    /// 某条边的权重（无边 = 0.0）。
    #[must_use]
    pub fn edge_weight(&self, from: &str, to: &str) -> f64 {
        self.edges
            .iter()
            .filter(|e| e.from == from && e.to == to)
            .map(|e| e.weight)
            .sum()
    }

    /// 从某节点出发的邻居（去重，权重求和），按权重降序。
    #[must_use]
    pub fn neighbors(&self, path: &str) -> Vec<(String, f64)> {
        let mut acc: HashMap<String, f64> = HashMap::new();
        for e in self.edges.iter().filter(|e| e.from == path) {
            *acc.entry(e.to.clone()).or_insert(0.0) += e.weight;
        }
        let mut out: Vec<(String, f64)> = acc.into_iter().collect();
        out.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap().then(a.0.cmp(&b.0)));
        out
    }

    /// 边数。
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// 节点数。
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }
}

fn parent_dir(path: &str) -> String {
    match path.rfind('/') {
        Some(i) => path[..i].to_string(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trace_fixture() -> AccessTrace {
        let mut t = AccessTrace::new();
        t.record("src/main.rs", 100);
        t.record("src/lib.rs", 105); // 共现 main→lib
        t.record("docs/guide.md", 5000); // 超出窗口，无边
        t
    }

    #[test]
    fn static_sibling_edges() {
        let paths = vec![
            "src/main.rs".to_string(),
            "src/lib.rs".to_string(),
            "docs/guide.md".to_string(),
        ];
        let g = WorkspaceGraph::build(&paths, &AccessTrace::new());
        assert_eq!(
            g.edge_weight("src/main.rs", "src/lib.rs"),
            STATIC_EDGE_WEIGHT
        );
        assert_eq!(g.edge_weight("src/main.rs", "docs/guide.md"), 0.0);
    }

    #[test]
    fn observed_cooccurrence_edges() {
        let paths = vec![
            "src/main.rs".to_string(),
            "src/lib.rs".to_string(),
            "docs/guide.md".to_string(),
        ];
        let g = WorkspaceGraph::build(&paths, &trace_fixture());
        // main→lib：静态 0.5 + 观测 1.0
        assert_eq!(g.edge_weight("src/main.rs", "src/lib.rs"), 1.5);
        // guide 超出窗口：只有静态 0（不同目录）= 0
        assert_eq!(g.edge_weight("src/lib.rs", "docs/guide.md"), 0.0);
    }

    #[test]
    fn neighbors_sorted() {
        let paths = vec!["a".to_string(), "b".to_string()];
        let mut t = AccessTrace::new();
        t.record("a", 1);
        t.record("b", 2);
        t.record("a", 3);
        t.record("b", 4);
        let g = WorkspaceGraph::build(&paths, &t);
        let n = g.neighbors("a");
        assert_eq!(n[0].0, "b");
        assert!(n[0].1 >= 2.0);
    }
}
