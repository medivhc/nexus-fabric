---
id: schedule-contract-whitepaper
date: 2026-09-25
module: nexus-scheduler
category: implementation-pitfall
task_type: feature
---

# 契约阶段产物必须逐项验证落盘（PRODUCT.md §14 曾整段丢失）

## 问题/模式描述

Feature「计划任务与事件驱动」走 Contract-First 时，契约阶段声称已完成的
`PRODUCT.md §14` 在实际工作区文件中**完全不存在**（文件止于 §13.4）：
- 独立 Review 通过 `git show HEAD:PRODUCT.md` + 工作区检索发现 scenario
  requirement `PRODUCT.md#14-schedule` 与 MODULE.md 的 §14.2/14.3/14.4 交叉引用
  全部悬空；
- 根因：本会话对 `PRODUCT.md`（大文件）反复调用 Edit 工具报
  `File has not been read yet`（即使已 Read），前期改用 PowerShell 追加的操作
  未被可靠验证，契约章节在后续环节丢失，而记录中误标为"已写入"。

## 原因分析

1. 大文件修改通道（Edit 工具）不可靠时，换用 PowerShell 追加/替换后**没有立即
   回读验证目标锚点**，把"执行了命令"当成"内容已落盘"。
2. TASK 摘要只记录"声称完成"，没有把锚点字符串（如 `{#14-schedule}`）作为
   可验证断言登记。

## 解决方案

- 修改契约文件后必须回读校验：`Select-String -Path PRODUCT.md -Pattern "<锚点>"`
  或读取目标行号区间，确认标题/小节真实存在；
- scenario 的 `requirement` 锚点、MODULE.md 的 § 引用与 PRODUCT.md 标题锚点
  三者必须字符串级一致（本次补写 §14 时统一为 `{#14-schedule}`）；
- 提交前把「契约文件各锚点存在」加入自检清单。

## 教训/可复用要点

- 任何"已写入/已追加"的声明，之后必须有一条对应的可执行校验（锚点存在、
  行数变化、diff 片段）才算数；
- Review 是发现"契约悬空"的关键防线：场景 requirement 与文档锚点不一致时，
  先怀疑文档没落盘，再怀疑锚点拼写；
- 本机大文件编辑优先走 PowerShell `[IO.File]::AppendAllText` + 单引号 here-string
  锚点 + `.Contains` 断言 + 回读校验的组合，避免 Edit 工具误报与 PowerShell
  双引号转义两重坑。
