---
id: classifier-ewma-readonly
date: 2026-10-01
module: nexus-projection
category: architecture-decision
task_type: feature
---

# 统一分类器的 EWMA 只读选路模式

## 问题/模式描述

统一包分类器（`PacketClassifier`）需要在 mesh 命中时选最优路径，但不能破坏
`nexus-path` 的 single-writer 不变量（S7：`PathManager` 是 EWMA 分数的唯一写入者）。

## 解决方案

复用 Boost v1 的 `boost::select_best(manager: &PathManager, ...)`：
- 签名本身就是 `&PathManager`（不可变借用），编译器强制只读；
- 分类器不持有 `PathManager` 的可变引用，不调用 `on_stats`/`add_candidate`；
- 全 unknown 时返回 `None`，分类器回落 `Mesh { path: None }`（不阻塞转发）；
- `degraded` 只打 warn 日志，不自动切 proxy（切路决策权在调用方）。

## 教训/可复用要点

- 跨模块只读观测优先用 `&` 借用 + 现有只读 API，而不是新开 trait；
- "只读不决策"要在契约（MODULE.md）里明确写出，否则后人容易在分类器里加切换逻辑；
- 降级时的行为（warn vs 自动切换）是产品决策，必须在契约里冻结，不能留给实现者臨時决定。
