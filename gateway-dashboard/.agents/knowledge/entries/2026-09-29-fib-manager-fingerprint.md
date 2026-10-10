---
id: fib-manager-fingerprint
date: 2026-09-29
module: nexus-discovery
category: implementation-pattern
task_type: feature
---

# FIB 管理器：LSDB 指纹触发按需重算

## 问题/模式描述

FIB 计算（Dijkstra O(E log V)）不应每次无脑重算，也不应由调用方
手写"LSDB 变了没"的判断。需要一个管理器封装变化检测 + 代际管理。

## 原因分析

- LSDB 的 `update()` 返回 `UpdateOutcome`，但调用方可能批量更新多次；
  逐次重算浪费，一次性判断更优。
- 指纹必须覆盖所有影响选路的字段：node_id、incarnation、seq、
  neighbor 列表、latency。任一变化 → 重算。

## 解决方案

- `FibManager<C: PathComputer>`：`new` 初始计算（gen=1）；
  `maybe_recompute` 算指纹，比对，不一致则重算 + gen+1。
- 指纹：FNV-1a 64；LSA 按 node_id 排序、neighbor 按名排序，
  保证与 HashMap 迭代顺序无关；latency 参与（代价变化触发重算）。
- `select()` 委托 `Fib::select_next_hop`，调用方一行完成"选路"。

## 教训/可复用要点

- 单测中 `Lsdb::update` 要求 `(incarnation, seq)` 递增，否则判 stale
  静默丢弃 —— 构造"拓扑变化"测试时必须手动指定 seq=2，
  不能复用 `lsa()` helper（其 seq 恒为 1）。
- 有向拓扑语义：单向建边不可达；测试新节点必须双向建边。
- `maybe_recompute` 内 `self.generation += 1` 后不能直接用
  `self.generation` 调 `Fib::compute`（borrow 冲突），先拷到局部变量。
