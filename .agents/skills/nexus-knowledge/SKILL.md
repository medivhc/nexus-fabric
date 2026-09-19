---
name: nexus-knowledge
description: 在 Nexus 仓库中，当需要检索历史工程经验（Review 发现的问题、编码踩过的坑、架构决策的来龙去脉）时使用；或当 Review 发现了有复用价值的问题、Debug 解决了不直观的 bug、做了不明显的架构选择时，将经验沉淀为知识库条目。知识库位于 .agents/knowledge/，是动态积累的活文件，Agent 在新任务开始、Review、Debug 时自动检索参考，避免重复踩坑。
---

# nexus-knowledge

Nexus 的动态工程知识库：把"踩过的坑、Review 发现的问题、架构决策的理由"沉淀下来，让后续任务自动检索、不再重蹈覆辙。

## 使用场景

### 检索经验（读取侧）

- 新任务开始，要修改某个模块 → 先检索该模块的历史问题和坑
- Review 时 → 检索该模块的历史 Review 问题，检查本次变更是否重蹈覆辙
- Debug 遇到奇怪的 bug → 先检索知识库有没有类似问题
- 做架构决策前 → 检索有没有类似的决策先例和理由

### 沉淀经验（写入侧）

- Review 发现了有复用价值的问题 → 沉淀为条目
- Debug 花了不短时间才定位的 bug → 记录根因和解决方案
- 做了一个不直观的架构选择 → 记录为什么这么选
- 复盘了一次线上/测试环境问题 → 记录完整链路

## 不要使用

- 一次性的、完全没有复用价值的小问题（比如某个拼写错误）
- 只对当前 PR 有意义的临时笔记

## 知识库位置

```text
.agents/knowledge/
├── README.md          说明文档
├── index.json         条目索引（供快速检索）
└── entries/           所有条目（每个条目一个 .md 文件）
```

## 条目格式

文件名：`YYYY-MM-DD-<slug>.md`（slug 用英文小写+连字符）

```markdown
---
id: <短id，8-12字符>
title: 一句话标题
tags: [concurrency, session, terminal-outcome]
module: nexus-session
severity: high | medium | low
source: review | debug | incident | architecture-decision
date: YYYY-MM-DD
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

## 检索方法

1. **按模块检索**：直接 `Grep` `.agents/knowledge/entries/` 下所有文件的 `module:` 字段
2. **按标签检索**：`Grep` `tags:` 字段
3. **按关键词检索**：直接 `Grep` 正文内容
4. **查看索引**：先读 `index.json`，快速浏览所有条目标题和标签

## 写入流程

1. 先检索是否已有相似条目（避免重复）
2. 新建条目文件（按上述格式）
3. 更新 `index.json`：在 `entries` 数组中追加 `{id, title, module, tags, severity, date}`
4. 如果发现已有条目可以补充新信息，直接编辑原条目，不要新建

## 与其他环节的关系

- **Review 环节**：Reviewer 在八个维度中发现 FAIL/WARN 时，判断是否有复用价值 → 有则沉淀为条目
- **Task 环节**：新任务开始时，先检索目标模块的历史经验 → 作为上下文
- **Debug 环节**：先检索知识库 → 有类似问题直接参考解决方案
