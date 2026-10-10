---
id: nat-quality-crate-placement
date: 2026-10-02
module: nexus-nat-quality
category: architecture-decision
task_type: feature
---

# 新 crate 选址：MODULE 禁止项优先于任务建议位置

## 问题/模式描述

Track 2 任务建议"在 nexus-nat-wireup（或更合适的位置）"实现质量测量。
`nexus-nat-wireup/MODULE.md` 的 Forbidden Dependencies 明确写着：
"`nexus-path` 的写入式接入（只读登记）"被禁止。而任务要求的
`PathManager::on_stats` 是写入（`&mut self`）。

## 原因分析

MODULE.md 是机器契约，不是建议。任务文本里的"或更合适的位置"正是
为这种情况留的出口。同时 `nexus-path` 是传输无关的（零 `nexus-fabric`
依赖），测量需要的 `FabricConn` 放不进去。

## 解决方案

新建 `nexus-nat-quality` crate（deps: nexus-fabric + nexus-path），并在
`policies/architecture.toml` 声明。lib.rs 头部注释写明选址理由，
MODULE.md 记录决策。

## 教训/可复用要点

- 任务建议位置 vs MODULE 禁止项冲突时，MODULE 赢；选新位置并书面说明理由。
- "X 层内部"（任务约束）指概念层，不一定是同一个 crate。
