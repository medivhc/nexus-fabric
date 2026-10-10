---
id: flow-hash-selection
date: 2026-09-29
module: nexus-discovery
category: implementation-pattern
task_type: feature
---

# 按流哈希选择 FIB 下一跳（FNV-1a 64 + hash % n）

## 问题/模式描述

ECMP（§12.46）让 FIB 的每 dst 条目持有 `Vec<NextHop>`，但没有"某条流走哪一条"
的选择逻辑。若按包轮询或随机选，会导致同一 TCP 流的包走不同路径 → 接收端
重排序/抖动。需要 per-flow 一致的确定性选择。

## 原因分析

- 选择必须满足：同流恒定（stability）、异流分散（spread）、跨节点一致
  （各节点对同一流算出同一索引，否则路径不对称）。
- FIB 条目内已按 peer 排序（§12.46），故 `hash(flow) % n` 的索引天然跨节点一致，
  无需额外协同。

## 解决方案

- `FlowKey`（5 元组）+ 手写 FNV-1a 64（零依赖，portable core）。
- IPv4 统一映射为 IPv6 兼容形式（`::ffff:a.b.c.d`）再哈希，保证同一地址的
  两种写法结果一致。
- `Fib::select_next_hop(vip, flow)`：纯函数；单下一跳短路直接返回（免哈希开销）；
  未知 VIP → `None`。
- E4 验证：同流 100 次恒定；1000 流在 2 条下一跳上 500/500 均分。

## 教训/可复用要点

- 反向流（src/dst 互换）不要求选同一条 —— 各方向独立哈希是对称选路之外的
  简化，契约中显式声明，避免后续误以为是 bug。
- 加权（weight ≠ 1）和一致性哈希最小重映射明确留作后续，不在本期过度设计。
- `cargo fmt` 要在所有修改的 crate 上跑（`cargo fmt -p` 只覆盖单个包），
  否则 harness 的 format 门会挂。
