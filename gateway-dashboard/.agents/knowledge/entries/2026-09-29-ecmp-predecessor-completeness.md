---
id: ecmp-review-001
title: ECMP 等代价前驱表完备性证明与路径枚举的两个坑（指数爆炸 / 顺序不确定）
tags: [routing, ecmp, dijkstra, correctness, determinism]
module: nexus-discovery
severity: medium
source: review
date: 2026-09-29
related: ["dijkstra-fib-001", "lsa-codec-alloc-001"]
---

## 问题描述

Review `nexus-discovery::routing::Ecmp`（PRODUCT §12.46）时深入验证了三个点，
结论都是"实现正确但有文档/鲁棒性缺口"，值得后续选路/转发面工作参考：

1. **等代价前驱表是否完备**：Dijkstra 变体在 `nd == cur` 时追加前驱，
   是否可能漏掉"已弹出节点"的前驱？
2. **路径枚举的最坏复杂度**：`enumerate_paths` 递归枚举全部等代价最短路，
   有无上限？
3. **多路径顺序的确定性**：`Ecmp::compute()` 返回"第一条"、FIB 内
   `Vec<NextHop>` 的顺序，跨运行是否一致？

## 原因分析

1. **前驱表完备（已证明正确）**：链路代价 `w ≥ 1`（`link_cost = max(latency_ms, 1)`），
   若 `u` 是 `v` 的等代价前驱则 `dist[u] = dist[v] - w < dist[v]`，
   故 `u` 严格先于 `v` 弹出；执行追加时 `v` 尚未弹出，不会漏。
   `nd < cur` 分支用 `prev.insert(v, vec![u])` 重置，旧距离的前驱被正确丢弃。
   DFS 沿前驱回溯时距离严格递减，前驱图是 DAG，必终止（无需 visited）。

2. **指数爆炸（文档缺口）**：等代价最短路数量可指数增长
   （k 层 × 每层 2 节点 → 2^k 条）。当前实现无上限、无文档说明。
   mesh 规模（数十节点）下无现实问题。

3. **顺序不确定（未来风险）**：`TopoView::from_lsdb` 迭代 `Lsdb::all()`，
   而 `Lsdb.nodes` 是标准 `HashMap<String, Lsa>`（RandomState），
   故邻接表顺序 → 前驱追加顺序 → DFS 枚举顺序 → FIB 内 NextHop 顺序
   均跨运行不确定。当前契约不承诺顺序（E4/单测不依赖顺序），
   但**未来按流哈希转发面**需要各节点对同一 dst 算出相同顺序的 NextHop，
   否则同一流在不同节点哈希到不同下一跳 → TCP 重排序。

## 解决方案

- 本 feature：0 FAIL，Verdict=COMMENTED，3 个 WARN（PRODUCT 方法名笔误、
  顺序不确定性、指数爆炸无文档 + dedup 分支未覆盖），不阻塞进 full。
- 后续转发面：在 FIB 条目内按 `peer` 排序 NextHop，或文档显式声明顺序约束。
- 后续选路：在模块文档中声明路径枚举的最坏情况，或评估只枚举第二跳
  （FIB 实际只需要去重后的第二跳，不需要完整路径）。

## 教训/可复用要点

- Review ECMP/多路径代码时必查三件套：前驱表完备性证明（依赖代价下界）、
  枚举最坏复杂度（有无 cap/文档）、输出顺序确定性（HashMap 迭代是常见源头）。
- `saturating_add` 溢出饱和为 `u64::MAX` 后永不入库为更小值，
  等价于不可达，不会产生错误最短路（与 dijkstra-fib-001 一致）。
- trait 方法数 4 =（单次/批量）×（单路径/多路径），与正交维度匹配时
  不算过度设计；Deletion Test 的标准问法是"删掉它会破坏哪个独立变化维度"。

## 参考

- Review evidence: `.evidence/review-ecmp01/`（review-ecmp01，2026-09-29）
- 代码：`crates/nexus-discovery/src/routing.rs`（`Ecmp::dijkstra_ecmp`、`enumerate_paths`、`Fib::compute`）
- PRODUCT.md §12.46
