---
id: dijkstra-fib-001
title: FIB 构建时不要对每个目的地跑一次 Dijkstra——单源运行已给出全目的地最短路
tags: [routing, dijkstra, complexity, documentation]
module: nexus-discovery
severity: medium
source: review
date: 2026-09-29
related: ["lsa-codec-alloc-001"]
---

## 问题描述

`nexus-discovery::routing::Fib::compute` 对 LSDB 中每个目标节点调用一次完整
Dijkstra（`ShortestPath::compute`），总复杂度 O(V·(V+E) log V)。而单源 Dijkstra
一次运行本来就计算出源点到**所有**可达目的地的最短路（dist/prev 表天然包含全
目的地），逐 dst 循环是 V 倍冗余计算。同时模块文档注释写“Dijkstra 全量重算
（O(n log n)）”，该复杂度只对单次 `compute()` 成立，对 `Fib::compute` 不准确，
会误导容量规划。

## 根因分析

把“算一条路径”的 API（`PathComputer::compute(topo, src, dst) -> Option<Path>`）
直接复用到“算全表”的场景（FIB 需要 self → 所有 dst），没有意识到单源算法的
输出天然就是全表。API 形状（单 dst）与使用场景（全 dst）错位。

## 解决方案

- 短期（已接受）：当前 mesh 规模下冗余计算无现实性能问题，且增量算路已是
  后续 feature，保持逐 dst 循环，但**修正文档的复杂度声明**，写清楚
  `Fib::compute` 的真实复杂度。
- 长期（优化时）：在 `ShortestPath` 内部或新增方法中跑一次 Dijkstra，
  从 dist/prev 表直接提取所有目的地的路径与下一跳；或给 `PathComputer`
  trait 增加批量接口（注意 Deletion Test：批量接口的独立变化维度是“算路算法
  替换”，与单次查询正交，是否值得加视实测瓶颈而定）。

## 预防措施

- Review 选路/算路代码时，检查“单源算法是否被按目标循环调用”；
- 文档中写复杂度时，区分“单次调用复杂度”与“批量场景总复杂度”，后者才是
  调用方关心的；
- 为 FIB 这类全表结构写单测时，顺带断言一次全量构建的耗时量级（小规模下
  可只做 smoke，不断言具体数字）。

## 参考

- Review evidence: `.evidence/review-fib01/`（review-fib01，2026-09-29）
- 代码：`crates/nexus-discovery/src/routing.rs`（`Fib::compute`、`ShortestPath::compute`）
- PRODUCT.md §12.45（冻结边界：增量算路为后续 feature）
