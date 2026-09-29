---
id: kshortest-yen-implementation
date: 2026-09-29
module: nexus-discovery
category: implementation-pattern
task_type: feature
---

# K-shortest 路径：Yen 算法实现要点

## 问题/模式描述

ECMP 只给等代价路径。需要主备路径（代价可不同）时，要实现 Yen 的
K-shortest loopless paths 算法。

## 原因分析

- Yen 算法核心是"spur node"枚举：对上一条路径的每个中间节点，
  临时删除成环边/节点后重跑 Dijkstra。
- 需要带排除集的 Dijkstra（`dijkstra_excluding`），而非每次重建拓扑视图。

## 解决方案

- `ShortestPath::dijkstra_excluding(topo, src, excluded_nodes, excluded_edges)`：
  在原 Dijkstra 循环内加两个 `continue` 判断，零额外分配。
- `ShortestPath::build_node_seq`：返回 `Vec<&str>`（不转 PeerId），供 Yen 内部用；
  原 `build_path` 保留（返回 `Path`）。
- Yen 主循环：`result: Vec<Vec<&str>>` 存已选路径；`candidates: BinaryHeap<Reverse<u64>, Vec<&str>>>`；
  每轮对 `result.last()` 的每个 spur 点计算，总路径 = root + spur[1..]；
  去重（`!result.contains`）后取最小。
- `path_cost` 沿拓扑查边代价累加（`saturating_add` 防溢出）。

## 教训/可复用要点

- `HashSet<(&str, &str)>` 存排除边：元组可 Hash，无需自定义类型。
- spur 点不含终点（`0..len-1`），root 含 spur（`0..=spur_idx`），
  删除节点不含 spur（`root[0..spur_idx]`）—— 三个区间易错，写单测覆盖。
- K=1 应退化为单条最短路（与 ShortestPath 一致），单测断言。
