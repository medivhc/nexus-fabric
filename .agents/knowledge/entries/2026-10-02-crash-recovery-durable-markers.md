---
id: crash-recovery-durable-markers
date: 2026-10-02
module: nexusd / nexus-session / nexus-connectivity
category: architecture-decision
task_type: feature
---

# Crash Recovery：Durable Marker 优先，Journal 不需要

## 问题/模式描述

v9 §15.2/§15.3 要求 crash recovery。第一反应是上 Journal，但 Session + Connectivity
范围内没有"写一半会丢用户可见状态"的多步事务——所有 durable 写都是单文件原子替换
（temp + fsync + rename），reconcile 幂等，crash 在 reconcile 中间下次启动重跑即可。

## 原因分析

- session 记录：`save()` = load → upsert → 原子写整个文件。单步原子，无中间态。
- link marker：同上。
- reconcile：孤儿分类后逐条回写；crash 在中间 → 已回写的变成终态（下次跳过），
  未处理的下次继续。天然幂等。
- 因此 Journal 是多余抽象（AGENTS.md §12 Deletion Test：删掉它没有破坏任何独立变化维度）。

## 解决方案

- Durable Marker 三件套：`sessions.json` / `links.json` / `run.marker`（`<config-dir>/state/`）。
- 损坏文件不静默丢弃：隔离为 `<name>.corrupt-<ts>` 保留取证，报告 `store_corrupt_quarantined`。
- `Failed` 的 durable 保真度：只保留分类 + 原因字符串，load 重建为 `Internal{message}`。
  这是有意的设计（reconcile 只需要分类），已写进 MODULE.md 和代码文档。

## 教训/可复用要点

- 先问"有没有多步事务"，再决定 Journal vs Marker。Marker 够用就别上 Journal。
- `SessionRecordStore` trait 早就存在（"由 Composition Root 注入实现"），文件实现放 nexusd，
  不进 portable 的 nexus-session——分层按契约走，不用重新发明。
