---
id: conneval-placement-20261002
date: 2026-10-02
module: nexus-connectivity / nexus-planner / nexus-domain
category: architecture-decision
task_type: feature
---

# Connectivity Evaluation（v9 §8.1）的类型安置与 Planner 接入

## 问题/模式描述

v9 §8.1 要求 Connectivity Evaluation 作为规划输入，但 evaluation 函数、
输出 DTO、Planner 消费三者涉及三个 crate（connectivity / domain / planner），
需要决定类型放哪、依赖边怎么加，同时不违反"Planner ≠ Estimator"和
"领域中立"边界。

## 原因分析

- `nexus-connectivity` 的 MODULE 早已把 Evaluation 列为 Responsibility，
  但它的 lib.rs 文档写着"不依赖 nexus-domain"（领域中立）。
- `nexus-planner` 的 allowed deps 是 domain/registry/measurement，
  加 connectivity 依赖会引入 delivery 层边，违反分层。
- `nexus-measurement` 的 MODULE 强调"Measurement ≠ Score"，evaluation 的
  likelihood 判断不是原始测量，放进去会模糊边界。

## 解决方案

- **输出 DTO `ConnectivityEvaluation` 放 `nexus-domain`**：domain 是跨层共享词汇，
  planner 零新增依赖即可消费。
- **纯函数 `evaluate_connectivity` 放 `nexus-connectivity::evaluation`**：
  MODULE 的 Responsibility 早已认领；新增的 domain/measurement 依赖是
  DTO/事实依赖，不是业务逻辑依赖（lib.rs 文档 + MODULE.md 已同步收窄表述）。
- **Planner 接入选改动最小的**：`PlanningSnapshot` 加字段（`new()` 签名不变，
  builder 追加）+ 独立的 `connectivity_gate()` 纯函数（plan_from_snapshot 内部复用，
  example/测试可直接调用拿精确原因）+ `ConsideredCandidate.connectivity`
  让 trace 可见。`filter_candidates` 签名不动。
- 门控语义：只升级 `reason: None` 的候选（不覆盖已有拒绝原因）；
  无评估的候选保持旧行为（未知 ≠ 不可行）。

## 教训/可复用要点

- 跨层 DTO 优先放 domain，避免上游 crate 反向依赖下游。
- "领域中立"的准确含义是"不依赖业务逻辑层"，DTO 词汇依赖是允许的，
  但要在文档里把这条写清楚，否则后人会误以为不能加。
- 纯函数的 Red Evidence 可以是编译失败（BLOCKED）：example 对着规划中的
  API 写，旧实现上直接 E0432/E0599。
