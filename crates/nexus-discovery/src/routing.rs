//! 基于 LSDB 的选路计算：TopoView → PathComputer → FIB（P5 §12.45）。
//!
//! Portable Core：零 I/O、零第三方依赖。`Fib::compute` 单次 Dijkstra（O(E log V)）
//! 算出全目的地最短路后整体替换 FIB（代际版本号，RCU 风格），不用逐条改。
//!
//! 本期只实现 `ShortestPath`（Dijkstra）；ECMP / K-shortest / Disjoint /
//! Constrained 为后续 feature（只加 `PathComputer` impl，不动 LSDB/FIB/协议）。

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};

use crate::PeerId;
use crate::lsa::Lsdb;

/// 链路代价：`max(latency_ms, 1)`（u64）。
/// 用 LSA 结构化度量中的延迟字段；未来 QoS 算路可用其他字段。
fn link_cost(latency_ms: u32) -> u64 {
    u64::from(latency_ms.max(1))
}

/// LSDB 的只读拓扑视图（图）。
///
/// 链路按通告方向建边（A 通告 B 即有 A→B 边，不要求对称——与链路状态语义一致）。
#[derive(Debug)]
pub struct TopoView<'a> {
    /// node_id.0 → Vec<(neighbor_id.0, cost)>。
    adj: HashMap<&'a str, Vec<(&'a str, u64)>>,
}

impl<'a> TopoView<'a> {
    /// 从 LSDB 构建拓扑视图（O(V+E)）。
    #[must_use]
    pub fn from_lsdb(lsdb: &'a Lsdb) -> Self {
        let mut adj: HashMap<&'a str, Vec<(&'a str, u64)>> = HashMap::new();
        for lsa in lsdb.all() {
            let id = lsa.node_id.0.as_str();
            let edges = adj.entry(id).or_default();
            for nb in &lsa.neighbors {
                edges.push((nb.neighbor.0.as_str(), link_cost(nb.metrics.latency_ms)));
            }
            // 无邻接的节点也占位（保证 node_count 正确）。
            adj.entry(id).or_default();
        }
        Self { adj }
    }

    /// 节点数。
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.adj.len()
    }

    /// 是否包含节点。
    #[must_use]
    pub fn contains(&self, node: &PeerId) -> bool {
        self.adj.contains_key(node.0.as_str())
    }

    /// 全部节点 ID（`compute_all` 默认实现用）。
    pub fn node_ids(&self) -> impl Iterator<Item = &str> {
        self.adj.keys().copied()
    }

    /// 节点的出边（邻居 ID，代价）。
    fn out_edges(&self, node: &str) -> &[(&'a str, u64)] {
        self.adj.get(node).map_or(&[], Vec::as_slice)
    }
}

/// 一条路径（`nodes` 含 src 与 dst）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Path {
    /// 节点序列（含 src/dst）。
    pub nodes: Vec<PeerId>,
    /// 总代价。
    pub cost: u64,
}

/// 算路抽象（未来 ECMP / K-shortest / Disjoint / Constrained 只加新 impl）。
pub trait PathComputer {
    /// 算法名（`"shortest"` / `"ecmp"` / …）。
    fn name(&self) -> &'static str;
    /// 计算 src → dst 路径；不可达 → `None`。
    fn compute(&self, topo: &TopoView, src: &PeerId, dst: &PeerId) -> Option<Path>;
    /// 计算 src → 全目的地的路径（批量；默认实现逐 dst 调用 `compute`）。
    ///
    /// 单源最短路类算法应覆盖为单次运行（O(E log V)），避免 V 倍冗余。
    fn compute_all(&self, topo: &TopoView, src: &PeerId) -> HashMap<PeerId, Path> {
        let mut out = HashMap::new();
        for id in topo.node_ids() {
            let dst = PeerId(id.to_string());
            if let Some(path) = self.compute(topo, src, &dst) {
                out.insert(dst, path);
            }
        }
        out
    }
}

/// Dijkstra 最短路。
#[derive(Debug, Clone, Copy, Default)]
pub struct ShortestPath;

impl ShortestPath {
    /// 创建 Dijkstra 算路器。
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl PathComputer for ShortestPath {
    fn name(&self) -> &'static str {
        "shortest"
    }

    fn compute(&self, topo: &TopoView, src: &PeerId, dst: &PeerId) -> Option<Path> {
        let src_key = src.0.as_str();
        let dst_key = dst.0.as_str();
        if !topo.contains(src) || !topo.contains(dst) {
            return None;
        }
        if src_key == dst_key {
            return Some(Path {
                nodes: vec![src.clone()],
                cost: 0,
            });
        }
        let (dist, prev) = Self::dijkstra(topo, src_key);
        Self::build_path(src, dst_key, &dist, &prev)
    }

    fn compute_all(&self, topo: &TopoView, src: &PeerId) -> HashMap<PeerId, Path> {
        let src_key = src.0.as_str();
        if !topo.contains(src) {
            return HashMap::new();
        }
        let (dist, prev) = Self::dijkstra(topo, src_key);
        let mut out = HashMap::new();
        for id in topo.node_ids() {
            let dst = PeerId(id.to_string());
            if id == src_key {
                out.insert(
                    dst,
                    Path {
                        nodes: vec![src.clone()],
                        cost: 0,
                    },
                );
            } else if let Some(path) = Self::build_path(src, id, &dist, &prev) {
                out.insert(dst, path);
            }
        }
        out
    }
}

impl ShortestPath {
    /// 单源 Dijkstra（O(E log V)），返回（距离表，前驱表）。
    fn dijkstra<'t>(
        topo: &TopoView<'t>,
        src: &'t str,
    ) -> (HashMap<&'t str, u64>, HashMap<&'t str, &'t str>) {
        let mut dist: HashMap<&'t str, u64> = HashMap::new();
        let mut prev: HashMap<&'t str, &'t str> = HashMap::new();
        let mut heap: BinaryHeap<(Reverse<u64>, &'t str)> = BinaryHeap::new();
        dist.insert(src, 0);
        heap.push((Reverse(0), src));

        while let Some((Reverse(d), u)) = heap.pop() {
            if d > *dist.get(u).unwrap_or(&u64::MAX) {
                continue;
            }
            for &(v, w) in topo.out_edges(u) {
                // saturating_add：溢出饱和为 u64::MAX，该值永不入库为更小值，
                // 等价于不可达，不会产生错误的最短路。
                let nd = d.saturating_add(w);
                if nd < *dist.get(v).unwrap_or(&u64::MAX) {
                    dist.insert(v, nd);
                    prev.insert(v, u);
                    heap.push((Reverse(nd), v));
                }
            }
        }
        (dist, prev)
    }

    /// 从前驱表重建 src → dst_key 路径；不可达 → `None`。
    fn build_path(
        src: &PeerId,
        dst_key: &str,
        dist: &HashMap<&str, u64>,
        prev: &HashMap<&str, &str>,
    ) -> Option<Path> {
        let cost = *dist.get(dst_key)?;
        let mut rev: Vec<&str> = vec![dst_key];
        let mut cur = dst_key;
        while cur != src.0.as_str() {
            cur = *prev.get(cur)?;
            rev.push(cur);
        }
        rev.reverse();
        Some(Path {
            nodes: rev.into_iter().map(|s| PeerId(s.to_string())).collect(),
            cost,
        })
    }
}

/// 下一跳（FIB 条目元素；从第一天就是 Vec 形状，本期每 dst 1 条）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NextHop {
    /// 下一跳节点。
    pub peer: PeerId,
    /// 负载分担权重（本期恒为 1）。
    pub weight: u32,
    /// 所属路径标识（本期恒为 0）。
    pub path_id: u32,
}

/// 转发表：`dst vip → Vec<NextHop>`；代际版本号，整体替换。
#[derive(Debug, Clone)]
pub struct Fib {
    generation: u64,
    entries: HashMap<String, Vec<NextHop>>,
}

impl Fib {
    /// 全量重算并整体替换（RCU 风格；调用方持有新旧两代，原子切换）。
    ///
    /// 单次 Dijkstra（O(E log V)）算出全目的地最短路，再逐 dst 取第二跳填 FIB。
    #[must_use]
    pub fn compute<C: PathComputer>(
        lsdb: &Lsdb,
        self_id: &PeerId,
        computer: &C,
        generation: u64,
    ) -> Self {
        let topo = TopoView::from_lsdb(lsdb);
        let paths = computer.compute_all(&topo, self_id);
        let mut entries = HashMap::new();
        for lsa in lsdb.all() {
            if lsa.node_id.0 == self_id.0 {
                continue; // 本端无条目
            }
            if let Some(path) = paths.get(&lsa.node_id) {
                // 最短路的第二跳即下一跳（单节点路径无第二跳，跳过）。
                if let Some(next) = path.nodes.get(1) {
                    entries.insert(
                        lsa.vip.clone(),
                        vec![NextHop {
                            peer: next.clone(),
                            weight: 1,
                            path_id: 0,
                        }],
                    );
                }
            }
        }
        Self {
            generation,
            entries,
        }
    }

    /// 代际版本号。
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// 按目的 VIP 查下一跳（`None` = 不可达/未知）。
    #[must_use]
    pub fn lookup(&self, vip: &str) -> Option<&[NextHop]> {
        self.entries.get(vip).map(Vec::as_slice)
    }

    /// 条目数（不含本端）。
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// 是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lsa::{LinkAdvert, LinkMetrics, Lsa};

    fn peer(id: &str) -> PeerId {
        PeerId(id.to_string())
    }

    fn link(to: &str, latency_ms: u32) -> LinkAdvert {
        LinkAdvert {
            neighbor: peer(to),
            metrics: LinkMetrics {
                latency_ms,
                loss_pct: 0,
                bandwidth_kbps: 100_000,
            },
        }
    }

    fn lsa(id: &str, vip: &str, neighbors: Vec<LinkAdvert>) -> Lsa {
        Lsa {
            node_id: peer(id),
            vip: vip.to_string(),
            incarnation: 1,
            seq: 1,
            capabilities: 0,
            locator: None,
            neighbors,
        }
    }

    /// A-B 10ms，B-D 10ms，A-C 50ms，C-D 10ms，B-C 10ms。
    fn topo_lsdb() -> (Lsdb, PeerId, PeerId, PeerId, PeerId) {
        let (a, b, c, d) = (peer("a"), peer("b"), peer("c"), peer("d"));
        let mut db = Lsdb::new(a.clone());
        db.update_local(lsa("a", "10.0.0.1", vec![link("b", 10), link("c", 50)]));
        db.update(lsa(
            "b",
            "10.0.0.2",
            vec![link("a", 10), link("c", 10), link("d", 10)],
        ));
        db.update(lsa(
            "c",
            "10.0.0.3",
            vec![link("a", 50), link("b", 10), link("d", 10)],
        ));
        db.update(lsa("d", "10.0.0.4", vec![link("b", 10), link("c", 10)]));
        (db, a, b, c, d)
    }

    #[test]
    fn dijkstra_prefers_indirect_shorter_path() {
        let (db, a, b, c, d) = topo_lsdb();
        let topo = TopoView::from_lsdb(&db);
        assert_eq!(topo.node_count(), 4);
        let sp = ShortestPath::new();
        assert_eq!(sp.name(), "shortest");

        // A→C：A-B-C 20ms 优于直连 50ms。
        let p = sp.compute(&topo, &a, &c).unwrap();
        assert_eq!(p.nodes, vec![a.clone(), b.clone(), c.clone()]);
        assert_eq!(p.cost, 20);

        // A→D：A-B-D 20ms。
        let p = sp.compute(&topo, &a, &d).unwrap();
        assert_eq!(p.nodes, vec![a.clone(), b.clone(), d]);
        assert_eq!(p.cost, 20);
    }

    #[test]
    fn dijkstra_unreachable_returns_none() {
        let (db, a, _, _, _) = topo_lsdb();
        let topo = TopoView::from_lsdb(&db);
        let sp = ShortestPath::new();
        assert!(sp.compute(&topo, &a, &peer("ghost")).is_none());
        // 自到自：零代价单节点路径。
        let p = sp.compute(&topo, &a, &a).unwrap();
        assert_eq!(p.nodes, vec![a]);
        assert_eq!(p.cost, 0);
    }

    #[test]
    fn fib_shape_and_generation() {
        let (db, a, b, _, _) = topo_lsdb();
        let sp = ShortestPath::new();
        let fib = Fib::compute(&db, &a, &sp, 7);
        assert_eq!(fib.generation(), 7);
        assert_eq!(fib.len(), 3); // B/C/D（不含本端 A）
        // 每 dst 恰 1 条 NextHop（Vec 形状），A→C/D 经 B。
        for vip in ["10.0.0.2", "10.0.0.3", "10.0.0.4"] {
            let hops = fib.lookup(vip).unwrap();
            assert_eq!(hops.len(), 1);
            assert_eq!(hops[0].peer, b);
            assert_eq!(hops[0].weight, 1);
            assert_eq!(hops[0].path_id, 0);
        }
        assert!(fib.lookup("10.0.0.1").is_none()); // 本端无条目
        assert!(fib.lookup("10.9.9.9").is_none()); // 未知无条目
    }

    #[test]
    fn dijkstra_asymmetric_links() {
        // 非对称通告：a→b 有边，b 不通告 a（单向链路）。
        // 链路状态语义：按通告方向建边，不要求对称。
        let (a, b) = (peer("a"), peer("b"));
        let mut db = Lsdb::new(a.clone());
        db.update_local(lsa("a", "10.0.0.1", vec![link("b", 10)]));
        db.update(lsa("b", "10.0.0.2", vec![])); // b 不通告任何邻居
        let topo = TopoView::from_lsdb(&db);
        let sp = ShortestPath::new();
        // a→b 可达（a 通告了）。
        let p = sp.compute(&topo, &a, &b).unwrap();
        assert_eq!(p.cost, 10);
        // b→a 不可达（b 没通告）。
        assert!(sp.compute(&topo, &b, &a).is_none());
    }

    #[test]
    fn link_cost_minimum_one() {
        assert_eq!(link_cost(0), 1);
        assert_eq!(link_cost(10), 10);
    }
}
