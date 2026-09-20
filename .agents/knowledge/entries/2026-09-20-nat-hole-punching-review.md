---
id: nat-review-001
date: 2026-09-20
module: nexus-connectivity
category: implementation-pattern
task_type: feature
---

# NAT 打洞功能 Review 迭代模式

## 问题/模式描述

NAT 打洞功能第 1 轮 Review 发现了 3 个阻塞项：
1. Transaction ID 硬编码（不是随机生成）
2. 缺少 STUN 响应解析的单元测试
3. 没有结构化事件

## 原因分析

- 写代码时只关注"能跑"，没有考虑协议正确性（Transaction ID 应该随机）
- 单元测试只写了最基本的 happy path，没有覆盖解析错误路径
- 忘记了新方法论要求所有关键操作都要有结构化事件

## 解决方案

1. Transaction ID 改为基于时间戳的随机生成
2. 补充 STUN 解析的成功/失败/短包/错误类型等单元测试
3. 新增 NatEvent 枚举（6 种事件类型），StunClient/HolePuncher 都有 events() 访问器

## 教训/可复用要点

1. **写网络协议时，所有字段都要符合规范**：Transaction ID 必须随机，不能硬编码
2. **单元测试要覆盖错误路径**：不能只测 happy path，要测各种错误情况
3. **新功能必须带结构化事件**：这是新方法论的硬性要求，不能忘
4. **Review 迭代是有效的**：第 1 轮 CHANGES_REQUESTED → 第 2 轮 APPROVED，改进了 4 个维度
