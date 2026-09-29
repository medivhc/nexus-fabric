---
id: disjoint-suurballe-implementation
date: 2026-09-29
module: nexus-discovery
category: implementation-pattern
task_type: feature
---

# Disjoint 不交路径：Suurballe 算法实现要点

## 问题/模式描述

K-shortest 的备用路径可能与主路共享链路，单点故障双路全断。
需要边不交的 2 条路径（总代价最小）。

## 原因分析

- Suurballe 算法标准步骤：Dijkstra → P1 边反向 → 边权变换 →
  Dijkstra 得 P2 → 合并抵消 → 提取 2 条。
- 易错点：漏掉"P1 边反向"会导致 P2 = P1（变换后 P1 边权为 0，
  Dijkstra 会重复选 P1）。

## 解决方案

- `dijkstra_suurballe`：原边（跳过 P1 边）按 `w+dist1[u]-dist1[v]` 松弛；
  P1 反向边（遍历 p1_edges 找终点为 u 的）权按 0 松弛
  （因 P1 为最短路，`dist1[v]=dist1[u]+w`，变换后恰为 0）。
- `combine_disjoint`：边多重集计数，正反边对抵消（`u<v` 去重），
  剩余边建邻接表，DFS 提取 2 条（用后删除）。
- `KShortest::path_cost` 提为 `pub(crate)` 供复用。

## 教训/可复用要点

- Suurballe 的"P1 边反向"是核心，不可省略；否则退化为重复最短路。
- 反向边权的正确性依赖 P1 为最短路（dist1 三角不等式），注释中说明。
- clippy `-D warnings` 下 `&mut` 误用会被拦：`dfs_path` 不修改 adj，
  调用的 `&mut` 是多余的。
