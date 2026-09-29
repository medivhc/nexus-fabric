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

/// 算路抽象（未来 K-shortest / Disjoint / Constrained 只加新 impl）。
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
    /// 计算 src → dst 的全部路径（多路径；默认退化为 `compute` 的单条）。
    ///
    /// ECMP 覆盖为返回所有等代价最短路。
    fn compute_paths(&self, topo: &TopoView, src: &PeerId, dst: &PeerId) -> Vec<Path> {
        self.compute(topo, src, dst).into_iter().collect()
    }
    /// 计算 src → 全目的地的全部路径（批量多路径；默认逐 dst 调用 `compute_paths`）。
    ///
    /// 多路径算法应覆盖为单次运行，避免 V 倍冗余。
    fn compute_all_paths(&self, topo: &TopoView, src: &PeerId) -> HashMap<PeerId, Vec<Path>> {
        let mut out = HashMap::new();
        for id in topo.node_ids() {
            let dst = PeerId(id.to_string());
            let paths = self.compute_paths(topo, src, &dst);
            if !paths.is_empty() {
                out.insert(dst, paths);
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

/// ECMP 等代价多路径：Dijkstra 保留所有等代价前驱，枚举全部等代价最短路。
///
/// 最坏情况：等代价路径数可指数增长（如多层菱形级联）。本实现无上限截断——
/// 调用方（`Fib::compute`）只取去重后的第二跳，不保留全路径；直接调用
/// `compute_paths` 时应评估拓扑规模。百节点常规拓扑无此问题。
#[derive(Debug, Clone, Copy, Default)]
pub struct Ecmp;

impl Ecmp {
    /// 创建 ECMP 算路器。
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// 单源 Dijkstra（保留所有等代价前驱），返回（距离表，前驱表）。
    ///
    /// 链路代价 ≥ 1，故等代价前驱一定在当前节点之前被弹出，前驱表完备。
    fn dijkstra_ecmp<'t>(
        topo: &TopoView<'t>,
        src: &'t str,
    ) -> (HashMap<&'t str, u64>, HashMap<&'t str, Vec<&'t str>>) {
        let mut dist: HashMap<&'t str, u64> = HashMap::new();
        let mut prev: HashMap<&'t str, Vec<&'t str>> = HashMap::new();
        let mut heap: BinaryHeap<(Reverse<u64>, &'t str)> = BinaryHeap::new();
        dist.insert(src, 0);
        heap.push((Reverse(0), src));

        while let Some((Reverse(d), u)) = heap.pop() {
            if d > *dist.get(u).unwrap_or(&u64::MAX) {
                continue;
            }
            for &(v, w) in topo.out_edges(u) {
                let nd = d.saturating_add(w);
                let cur = *dist.get(v).unwrap_or(&u64::MAX);
                if nd < cur {
                    dist.insert(v, nd);
                    prev.insert(v, vec![u]);
                    heap.push((Reverse(nd), v));
                } else if nd == cur {
                    // 等代价：追加前驱（去重；v 尚未弹出，前驱表最终完备）。
                    let entry = prev.entry(v).or_default();
                    if !entry.contains(&u) {
                        entry.push(u);
                    }
                }
            }
        }
        (dist, prev)
    }

    /// 从前驱表枚举 src → dst 的全部最短路（DFS 回溯前驱 DAG）。
    fn enumerate_paths(
        src: &PeerId,
        dst_key: &str,
        dist: &HashMap<&str, u64>,
        prev: &HashMap<&str, Vec<&str>>,
    ) -> Vec<Path> {
        let cost = match dist.get(dst_key) {
            Some(&c) => c,
            None => return Vec::new(),
        };
        // DFS：从 dst 沿前驱回溯到 src，收集全部路径（反转后为 src→dst）。
        fn dfs<'a>(
            cur: &'a str,
            src_key: &str,
            prev: &HashMap<&'a str, Vec<&'a str>>,
            stack: &mut Vec<&'a str>,
            out: &mut Vec<Vec<&'a str>>,
        ) {
            stack.push(cur);
            if cur == src_key {
                out.push(stack.iter().rev().copied().collect());
            } else if let Some(preds) = prev.get(cur) {
                for &p in preds {
                    // 前驱 DAG 无环（代价严格递减），无需 visited。
                    dfs(p, src_key, prev, stack, out);
                }
            }
            stack.pop();
        }
        let mut raw: Vec<Vec<&str>> = Vec::new();
        dfs(dst_key, src.0.as_str(), prev, &mut Vec::new(), &mut raw);
        raw.into_iter()
            .map(|nodes| Path {
                nodes: nodes.into_iter().map(|s| PeerId(s.to_string())).collect(),
                cost,
            })
            .collect()
    }
}

impl PathComputer for Ecmp {
    fn name(&self) -> &'static str {
        "ecmp"
    }

    fn compute(&self, topo: &TopoView, src: &PeerId, dst: &PeerId) -> Option<Path> {
        self.compute_paths(topo, src, dst).into_iter().next()
    }

    fn compute_paths(&self, topo: &TopoView, src: &PeerId, dst: &PeerId) -> Vec<Path> {
        let src_key = src.0.as_str();
        let dst_key = dst.0.as_str();
        if !topo.contains(src) || !topo.contains(dst) {
            return Vec::new();
        }
        if src_key == dst_key {
            return vec![Path {
                nodes: vec![src.clone()],
                cost: 0,
            }];
        }
        let (dist, prev) = Self::dijkstra_ecmp(topo, src_key);
        Self::enumerate_paths(src, dst_key, &dist, &prev)
    }

    fn compute_all_paths(&self, topo: &TopoView, src: &PeerId) -> HashMap<PeerId, Vec<Path>> {
        let src_key = src.0.as_str();
        if !topo.contains(src) {
            return HashMap::new();
        }
        let (dist, prev) = Self::dijkstra_ecmp(topo, src_key);
        let mut out = HashMap::new();
        for id in topo.node_ids() {
            let dst = PeerId(id.to_string());
            let paths = if id == src_key {
                vec![Path {
                    nodes: vec![src.clone()],
                    cost: 0,
                }]
            } else {
                Self::enumerate_paths(src, id, &dist, &prev)
            };
            if !paths.is_empty() {
                out.insert(dst, paths);
            }
        }
        out
    }
}

/// 选路策略（`[routing] strategy` 配置项，§12.48）。
///
/// 枚举本身实现 `PathComputer`（静态分发）：调用方按配置选用策略，
/// 无需 hardcode 具体算法。新增策略 = 新变体 + 委托分支。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingStrategy {
    /// 最短路（Dijkstra；默认，向后兼容）。
    Shortest,
    /// 等代价多路径。
    Ecmp,
}

/// 策略解析错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StrategyParseError {
    /// 未知策略名（保留原字符串）。
    Unknown(String),
}

impl std::fmt::Display for StrategyParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown(s) => write!(f, "unknown routing strategy '{s}'"),
        }
    }
}

impl RoutingStrategy {
    /// 解析配置字符串（大小写不敏感，前后空白忽略）。
    ///
    /// `"shortest"` → `Shortest`，`"ecmp"` → `Ecmp`；其他 → `Err(Unknown)`。
    pub fn parse(s: &str) -> Result<Self, StrategyParseError> {
        match s.trim().to_ascii_lowercase().as_str() {
            "shortest" => Ok(Self::Shortest),
            "ecmp" => Ok(Self::Ecmp),
            _ => Err(StrategyParseError::Unknown(s.to_string())),
        }
    }

    /// 默认策略（`shortest`，向后兼容：既有部署无 `[routing]` 段时行为不变）。
    fn default_strategy() -> Self {
        Self::Shortest
    }
}

impl Default for RoutingStrategy {
    fn default() -> Self {
        Self::default_strategy()
    }
}

impl std::error::Error for StrategyParseError {}

impl PathComputer for RoutingStrategy {
    fn name(&self) -> &'static str {
        match self {
            Self::Shortest => ShortestPath.name(),
            Self::Ecmp => Ecmp.name(),
        }
    }

    fn compute(&self, topo: &TopoView, src: &PeerId, dst: &PeerId) -> Option<Path> {
        match self {
            Self::Shortest => ShortestPath.compute(topo, src, dst),
            Self::Ecmp => Ecmp.compute(topo, src, dst),
        }
    }

    fn compute_all(&self, topo: &TopoView, src: &PeerId) -> HashMap<PeerId, Path> {
        match self {
            Self::Shortest => ShortestPath.compute_all(topo, src),
            Self::Ecmp => Ecmp.compute_all(topo, src),
        }
    }

    fn compute_paths(&self, topo: &TopoView, src: &PeerId, dst: &PeerId) -> Vec<Path> {
        match self {
            Self::Shortest => ShortestPath.compute_paths(topo, src, dst),
            Self::Ecmp => Ecmp.compute_paths(topo, src, dst),
        }
    }

    fn compute_all_paths(&self, topo: &TopoView, src: &PeerId) -> HashMap<PeerId, Vec<Path>> {
        match self {
            Self::Shortest => ShortestPath.compute_all_paths(topo, src),
            Self::Ecmp => Ecmp.compute_all_paths(topo, src),
        }
    }
}

/// 下一跳（FIB 条目元素；从第一天就是 Vec 形状，ECMP 下每 dst 可多条）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NextHop {
    /// 下一跳节点。
    pub peer: PeerId,
    /// 负载分担权重（本期恒为 1）。
    pub weight: u32,
    /// 所属路径标识（本期恒为 0）。
    pub path_id: u32,
}

/// 流标识（5 元组）：按流哈希选择下一跳的输入。
///
/// `protocol` 为 IP 协议号（6=TCP，17=UDP）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    /// 源 IP。
    pub src_ip: std::net::IpAddr,
    /// 目的 IP。
    pub dst_ip: std::net::IpAddr,
    /// 源端口。
    pub src_port: u16,
    /// 目的端口。
    pub dst_port: u16,
    /// IP 协议号。
    pub protocol: u8,
}

impl FlowKey {
    /// FNV-1a 64 流哈希（portable core 手写，零依赖）。
    ///
    /// 输入为 5 元组字段的确定性字节序：IP 按 16 字节展开（IPv4 用
    /// `::ffff:` 映射形式），端口 BE，协议号占单字节。跨平台、跨运行、跨节点
    /// 结果一致——FIB 条目按 peer 排序后，`hash % n` 的索引在各节点相同。
    #[must_use]
    pub fn hash(&self) -> u64 {
        const FNV_OFFSET: u64 = 0xcbf29ce484222325;
        const FNV_PRIME: u64 = 0x100000001b3;
        let mut h = FNV_OFFSET;
        // IP 统一按 16 字节展开：IPv4 用 ::ffff:a.b.c.d 映射形式，保证
        // 同一地址的两种写法哈希一致。
        for ip in [self.src_ip, self.dst_ip] {
            let bytes: [u8; 16] = match ip {
                std::net::IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
                std::net::IpAddr::V6(v6) => v6.octets(),
            };
            for b in bytes {
                h ^= u64::from(b);
                h = h.wrapping_mul(FNV_PRIME);
            }
        }
        for port in [self.src_port, self.dst_port] {
            for b in port.to_be_bytes() {
                h ^= u64::from(b);
                h = h.wrapping_mul(FNV_PRIME);
            }
        }
        h ^= u64::from(self.protocol);
        h = h.wrapping_mul(FNV_PRIME);
        h
    }
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
    /// 单次算路得出全目的地（多）路径，按去重后的第二跳填 `Vec<NextHop>`；
    /// 单路径算法退化为每 dst 1 条（与 §12.45 行为一致）。
    #[must_use]
    pub fn compute<C: PathComputer>(
        lsdb: &Lsdb,
        self_id: &PeerId,
        computer: &C,
        generation: u64,
    ) -> Self {
        let topo = TopoView::from_lsdb(lsdb);
        let all_paths = computer.compute_all_paths(&topo, self_id);
        let mut entries = HashMap::new();
        for lsa in lsdb.all() {
            if lsa.node_id.0 == self_id.0 {
                continue; // 本端无条目
            }
            if let Some(paths) = all_paths.get(&lsa.node_id) {
                // 各路径的第二跳即下一跳，去重（多条等代价路径可能共享第二跳）。
                // 按 peer 排序：FIB 条目内顺序确定，与 HashMap 迭代顺序无关
                //（未来按流哈希选下一跳时，跨节点必须一致，否则 TCP 重排序）。
                let mut seen: Vec<&PeerId> = Vec::new();
                let mut hops: Vec<NextHop> = Vec::new();
                for path in paths.iter() {
                    if let Some(next) = path.nodes.get(1) {
                        if !seen.contains(&next) {
                            seen.push(next);
                            hops.push(NextHop {
                                peer: next.clone(),
                                weight: 1,
                                path_id: 0, // 占位，排序后重分配
                            });
                        }
                    }
                }
                // 按 peer 排序：FIB 条目内顺序确定，与 HashMap 迭代顺序无关
                //（未来按流哈希选下一跳时，跨节点必须一致，否则 TCP 重排序）。
                // 排序后再分配 path_id（0,1,2…），保证跨运行一致。
                hops.sort_by(|a, b| a.peer.0.cmp(&b.peer.0));
                for (idx, hop) in hops.iter_mut().enumerate() {
                    hop.path_id = idx as u32;
                }
                if !hops.is_empty() {
                    entries.insert(lsa.vip.clone(), hops);
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

    /// 按流哈希选择下一跳（§12.47）。
    ///
    /// 同一 `FlowKey` 恒返回同一条（FIB 条目内按 peer 排序，`hash % n`
    /// 索引跨节点一致）；单下一跳直接返回；未知/不可达 VIP → `None`。
    /// 纯函数：零 I/O，不修改 FIB。
    #[must_use]
    pub fn select_next_hop(&self, vip: &str, flow: &FlowKey) -> Option<&NextHop> {
        let hops = self.lookup(vip)?;
        if hops.is_empty() {
            return None;
        }
        if hops.len() == 1 {
            return Some(&hops[0]);
        }
        let idx = (flow.hash() % hops.len() as u64) as usize;
        hops.get(idx)
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

    /// 菱形拓扑：A-B 10ms，B-D 10ms，A-C 10ms，C-D 10ms。
    /// A→D 有两条 20ms 等代价最短路（经 B / 经 C）。
    fn diamond_lsdb() -> (Lsdb, PeerId, PeerId, PeerId, PeerId) {
        let (a, b, c, d) = (peer("a"), peer("b"), peer("c"), peer("d"));
        let mut db = Lsdb::new(a.clone());
        db.update_local(lsa("a", "10.0.0.1", vec![link("b", 10), link("c", 10)]));
        db.update(lsa("b", "10.0.0.2", vec![link("a", 10), link("d", 10)]));
        db.update(lsa("c", "10.0.0.3", vec![link("a", 10), link("d", 10)]));
        db.update(lsa("d", "10.0.0.4", vec![link("b", 10), link("c", 10)]));
        (db, a, b, c, d)
    }

    #[test]
    fn ecmp_finds_all_equal_cost_paths() {
        let (db, a, b, c, d) = diamond_lsdb();
        let topo = TopoView::from_lsdb(&db);
        let ecmp = Ecmp::new();
        assert_eq!(ecmp.name(), "ecmp");

        let paths = ecmp.compute_paths(&topo, &a, &d);
        assert_eq!(paths.len(), 2);
        for p in &paths {
            assert_eq!(p.cost, 20);
            assert_eq!(p.nodes.len(), 3);
        }
        let mut seconds: Vec<String> = paths.iter().map(|p| p.nodes[1].0.clone()).collect();
        seconds.sort();
        assert_eq!(seconds, vec!["b".to_string(), "c".to_string()]);

        // compute() 返回其中一条（兼容单路径语义）。
        let one = ecmp.compute(&topo, &a, &d).unwrap();
        assert_eq!(one.cost, 20);
        // 不可达 → 空。
        assert!(ecmp.compute_paths(&topo, &a, &peer("ghost")).is_empty());
        let _ = (b, c);
    }

    #[test]
    fn ecmp_fib_has_multiple_next_hops() {
        let (db, a, b, c, _) = diamond_lsdb();
        let ecmp = Ecmp::new();
        let fib = Fib::compute(&db, &a, &ecmp, 1);
        // A→D：2 条 NextHop（B 和 C）。
        let hops = fib.lookup("10.0.0.4").unwrap();
        assert_eq!(hops.len(), 2);
        let mut peers: Vec<String> = hops.iter().map(|h| h.peer.0.clone()).collect();
        peers.sort();
        assert_eq!(peers, vec!["b".to_string(), "c".to_string()]);
        // A→B：单条路径，仍为 1 条 NextHop。
        let hops_b = fib.lookup("10.0.0.2").unwrap();
        assert_eq!(hops_b.len(), 1);
        assert_eq!(hops_b[0].peer, b);
        let _ = c;
    }

    #[test]
    fn shortest_path_compute_paths_stays_single() {
        // ShortestPath 经默认 compute_paths 仍为单路径（兼容）。
        let (db, a, _, _, d) = diamond_lsdb();
        let topo = TopoView::from_lsdb(&db);
        let sp = ShortestPath::new();
        let paths = sp.compute_paths(&topo, &a, &d);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].cost, 20);
    }

    #[test]
    fn fib_dedups_shared_second_hop() {
        // 两条等代价路径共享第二跳 B：A-B-D（20）与 A-B-C-D（20）。
        // FIB 去重后应只有 1 条 NextHop（B），而非 2 条。
        let (a, b, c, d) = (peer("a"), peer("b"), peer("c"), peer("d"));
        let mut db = Lsdb::new(a.clone());
        db.update_local(lsa("a", "10.0.0.1", vec![link("b", 10)]));
        db.update(lsa(
            "b",
            "10.0.0.2",
            vec![link("a", 10), link("d", 10), link("c", 5)],
        ));
        db.update(lsa("c", "10.0.0.3", vec![link("b", 5), link("d", 5)]));
        db.update(lsa("d", "10.0.0.4", vec![link("b", 10), link("c", 5)]));

        let topo = TopoView::from_lsdb(&db);
        let ecmp = Ecmp::new();
        // 确认确实有 2 条等代价路径。
        let paths = ecmp.compute_paths(&topo, &a, &d);
        assert_eq!(paths.len(), 2);
        assert!(paths.iter().all(|p| p.cost == 20));
        // 两条路径第二跳都是 B。
        assert!(paths.iter().all(|p| p.nodes[1] == b));

        // FIB 去重：1 条 NextHop。
        let fib = Fib::compute(&db, &a, &ecmp, 1);
        let hops = fib.lookup("10.0.0.4").unwrap();
        assert_eq!(hops.len(), 1);
        assert_eq!(hops[0].peer, b);
        assert_eq!(hops[0].path_id, 0);
        let _ = (c, d);
    }

    fn flow_key(src_port: u16, dst_port: u16) -> FlowKey {
        FlowKey {
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "10.0.0.4".parse().unwrap(),
            src_port,
            dst_port,
            protocol: 6,
        }
    }

    #[test]
    fn flow_hash_is_deterministic() {
        // 同一 FlowKey 多次哈希结果一致；不同字段改变哈希。
        let f = flow_key(1234, 80);
        assert_eq!(f.hash(), f.hash());
        assert_ne!(f.hash(), flow_key(1235, 80).hash());
        assert_ne!(f.hash(), flow_key(1234, 81).hash());
        // protocol 参与哈希：TCP(6) 与 UDP(17) 同 4 元组哈希不同。
        let udp = FlowKey { protocol: 17, ..f };
        assert_ne!(f.hash(), udp.hash());
        // IPv4 与其 IPv6 映射形式哈希一致。
        let mapped = FlowKey {
            src_ip: "::ffff:10.0.0.1".parse().unwrap(),
            ..f
        };
        assert_eq!(f.hash(), mapped.hash());
    }

    #[test]
    fn select_next_hop_same_flow_stable() {
        // 菱形拓扑：A→D 有 2 条下一跳；同一流恒选同一条。
        let (db, a, _, _, _) = diamond_lsdb();
        let fib = Fib::compute(&db, &a, &Ecmp::new(), 1);
        let flow = flow_key(5000, 443);
        let first = fib.select_next_hop("10.0.0.4", &flow).unwrap();
        for _ in 0..50 {
            assert_eq!(fib.select_next_hop("10.0.0.4", &flow).unwrap(), first);
        }
    }

    #[test]
    fn select_next_hop_spreads_flows() {
        // 200 个不同流应分散到两条下一跳（每条 ≥ 25%）。
        let (db, a, _, _, _) = diamond_lsdb();
        let fib = Fib::compute(&db, &a, &Ecmp::new(), 1);
        let hops = fib.lookup("10.0.0.4").unwrap();
        assert_eq!(hops.len(), 2);
        let mut counts = [0u32, 0u32];
        for i in 0..200u16 {
            let hop = fib
                .select_next_hop("10.0.0.4", &flow_key(10000 + i, 80))
                .unwrap();
            let idx = hops.iter().position(|h| h == hop).unwrap();
            counts[idx] += 1;
        }
        assert!(counts[0] >= 50 && counts[1] >= 50, "counts={counts:?}");
    }

    #[test]
    fn select_next_hop_single_and_unknown() {
        // 单下一跳直接返回；未知 VIP → None。
        let (db, a, b, _, _) = diamond_lsdb();
        let fib = Fib::compute(&db, &a, &Ecmp::new(), 1);
        let flow = flow_key(6000, 22);
        let hop = fib.select_next_hop("10.0.0.2", &flow).unwrap();
        assert_eq!(hop.peer, b);
        assert!(fib.select_next_hop("10.9.9.9", &flow).is_none());
        assert!(fib.select_next_hop("10.0.0.1", &flow).is_none()); // 本端无条目
    }

    #[test]
    fn routing_strategy_parse() {
        assert_eq!(RoutingStrategy::parse("ecmp"), Ok(RoutingStrategy::Ecmp));
        assert_eq!(RoutingStrategy::parse("ECMP"), Ok(RoutingStrategy::Ecmp));
        assert_eq!(
            RoutingStrategy::parse(" shortest "),
            Ok(RoutingStrategy::Shortest)
        );
        assert_eq!(
            RoutingStrategy::parse("k-shortest"),
            Err(StrategyParseError::Unknown("k-shortest".to_string()))
        );
        assert!(RoutingStrategy::parse("").is_err());
        // Default 为 Shortest（向后兼容）。
        assert_eq!(RoutingStrategy::default(), RoutingStrategy::Shortest);
    }

    #[test]
    fn routing_strategy_delegates_to_computers() {
        // 策略枚举委托行为与直接使用具体类型一致。
        let (db, a, _, _, d) = diamond_lsdb();
        let topo = TopoView::from_lsdb(&db);

        let via_strategy = RoutingStrategy::Ecmp;
        assert_eq!(via_strategy.name(), "ecmp");
        let paths_s = via_strategy.compute_paths(&topo, &a, &d);
        let paths_e = Ecmp::new().compute_paths(&topo, &a, &d);
        assert_eq!(paths_s.len(), paths_e.len());
        assert_eq!(paths_s.len(), 2);

        let via_shortest = RoutingStrategy::Shortest;
        assert_eq!(via_shortest.name(), "shortest");
        let one_s = via_shortest.compute(&topo, &a, &d).unwrap();
        let one_p = ShortestPath::new().compute(&topo, &a, &d).unwrap();
        assert_eq!(one_s.cost, one_p.cost);

        // Fib::compute 接受策略枚举（PathComputer）。
        let fib = Fib::compute(&db, &a, &via_strategy, 1);
        assert_eq!(fib.lookup("10.0.0.4").unwrap().len(), 2);
    }
}
