# Nexus 工程知识库

动态积累的工程经验库：Review 发现的问题、编码踩过的坑、架构决策的来龙去脉，全部沉淀在这里，供后续任务自动检索参考。

## 目录结构

```
.agents/knowledge/
├── README.md          本文件
├── entries/           所有经验条目（每个条目一个 Markdown 文件）
│   ├── 2026-09-19-terminal-outcome-double-write.md
│   ├── 2026-09-20-planner-estimator-circular-dep.md
│   └── ...
└── index.json         自动生成的条目索引（供 Agent 快速检索）
```

## 条目格式

每个条目是一个 Markdown 文件，文件名格式：`YYYY-MM-DD-<slug>.md`

```markdown
---
id: <短id>
title: 一句话标题
tags: [concurrency, session, terminal-outcome]
module: nexus-session
severity: high | medium | low
source: review | debug | incident | architecture-decision
date: 2026-09-19
related: ["<其他条目id>"]
---

## 问题描述

发生了什么？在什么场景下？

## 根因分析

为什么会发生？深层原因是什么？

## 解决方案

怎么修的？关键改动是什么？

## 预防措施

以后怎么避免？Review 时要检查什么？写代码时要注意什么？

## 参考

- 相关 commit / PR / Evidence ID
- 相关 MODULE.md 章节
```

## 什么时候写入

- **Review 发现问题**：Reviewer 在八个维度中发现 FAIL/WARN 时，将有复用价值的问题沉淀为条目
- **Debug 解决坑**：花了时间才定位的 bug，记录根因和解决方案
- **架构决策**：做了一个不直观的架构选择，记录为什么这么选
- **事故复盘**：线上/测试环境出了问题，记录完整链路

## 什么时候读取

- **新任务开始**：Agent 用 `nexus-knowledge` skill 检索与目标模块相关的条目，作为上下文
- **Review 时**：Reviewer 检索相关模块的历史问题，检查本次变更是否重蹈覆辙
- **Debug 时**：先检索知识库有没有类似问题，避免重复定位

## 维护规则

- 条目是**活的**：发现新信息可以追加更新，不要新建重复条目
- 去重：写入前先检索是否已有相似条目，有则更新而非新建
- 索引：`index.json` 由 Agent 在写入后更新，或由 harness 工具自动生成
