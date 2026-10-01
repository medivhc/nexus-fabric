---
id: frozen-signature-isomorphic-deviation
date: 2026-10-01
module: nexus-projection
category: implementation-pitfall
task_type: feature
---

# 语义同构的签名偏离仍算契约偏离（Review 发现）

## 问题/模式描述

Boost v1 Review（`boostv1rev01`）发现：`crates/nexus-projection/MODULE.md`
S28 冻结签名为 `select_best(...) -> Option<BoostSelection>`（"全 unknown →
返回 None"），实现返回的是裸 `BoostSelection`（None 性由
`best: Option<&CandidatePath>` 字段承载）。两者信息含量完全同构、E4
通过、唯一调用方按实际形状编写——**零行为影响**，但仍被判为
contract-consistency WARN。

## 原因分析

contract-first 纪律下，冻结的 MODULE 签名是 Protected：按冻结签名编写的
调用方（如后续的 `apps/nexus` 组合根）会编译失败。"语义一样"不能替代
"签名一致"，否则冻结契约失去机器可检查的意义。

## 解决方案

二选一，不允许静默偏离：
1. 实现向契约对齐（推荐）：改返回 `Option<BoostSelection>`，约 3 行，
   契约不动；
2. 契约向实现对齐：走 requirement-change 更新 MODULE.md，旧 Evidence
   标记 STALE。

## 教训/可复用要点

- Review 时要把 MODULE.md 的函数签名逐字 diff 实现签名，不能只看
  行为语义；同构 ≠ 一致。
- 写 MODULE 契约时，返回 `Option<T>` 还是"含 Option 字段的 T"要在冻结
  前想清楚——两种形状各有调用方 ergonomics 代价，冻结后改任一边都有
  成本。
