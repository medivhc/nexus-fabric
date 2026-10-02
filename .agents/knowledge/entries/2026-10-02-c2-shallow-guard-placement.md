---
id: c2-shallow-guard-placement
date: 2026-10-02
module: nexus-workspace
category: implementation-pitfall
task_type: feature
---

# Shallow sync 的"本地有提交则拒绝"守卫必须放在 fetch 之前

## 问题/模式描述

C2-P4 shallow sync 要求：本地已有提交时明确报错 `ShallowWithLocalChanges`，
而不是静默丢弃本地数据。最初把守卫放在 merge 阶段（fetch 之后），
导致测试 `shallow_truncates_bfs_at_max_depth` 失败——B 在 fetch 后已有 5 个 commits
（genesis + 拉来的 4 个），守卫误判 B"本地有提交"。

## 原因分析

fetch 本身会给 B 带来 commits，fetch 之后的"本地提交数"包含了刚拉来的远端提交，
无法区分"用户本地提交"和"本次 sync 拉来的"。守卫的语义是"sync 开始前本地是否有数据"，
必须在任何 fetch 发生前检查。

## 解决方案

把守卫移到 `sync_with_remote_opts` 函数开头（exchange_heads 之前）。
merge 阶段的 shallow 分支只处理"全新 workspace 采用远端 heads"的逻辑，不再做守卫。

## 教训/可复用要点

- 前置条件检查（precondition）必须放在产生副作用的操作之前；放在副作用之后，
  检查看到的是被污染的状态。
- "本地数据"的定义是时间敏感的——在 fetch 前快照，不要在 fetch 后推断。
