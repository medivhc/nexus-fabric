---
id: skill-mining-method
date: 2026-10-06
module: engineering
category: implementation-pattern
task_type: docs
---

# Skill 挖掘五步法（从 Lauren Tan / pstack 播客提炼）

## 问题/模式描述

好的 skill 不是设计出来的，是从真实痛点里"长"出来的。Lauren Tan 的 verification
skill 来自她当"人肉中转站"的痛（在 agent 和 Chrome DevTools 之间转述性能数据），
recall skill 来自每次新开对话都要重讲背景的痛。反面模式：自上而下凭空设计一套
skill 体系——agent 不用，模型一升级就过时。

## 原因分析

- 只有真实发生过的插手才值得固化；想象中的痛点固化成 skill 是浪费。
- 聊天记录是"物化了的真实流程"（the process materialized），比事后回忆可靠。
- 单次偶发错误不值得立规矩；重复出现的模式才值得。

## 解决方案

五步：

1. **记痛点**：每次不得不插手（纠正、重讲背景、当传话筒、手动验证）当时记一笔，
   不要靠事后印象。
2. **翻记录找重复**：定期扫聊天记录 / 任务报告，找重复出现的插手模式。
   偶发 → 放过；重复 → 候选。
3. **分类**：
   - 当"传话筒"（在 agent 和工具 / 数据源之间转述）→ **观察型 skill**：
     给 agent 直接拿真实数据的能力（verification / recall 类）。
     原则："how do I get the agent to answer its own question?
     Not by hallucinating, but actually real data."
   - 反复纠正同一类错误 → **约束型**：能机器化的写成 lint / 类型检查
     （"how do I make it so that the codebase makes this impossible?"）；
     不能机器化的写成 skill 文字。
   - 每个新任务都要重讲的背景 → **上下文型 skill**。
4. **拆分确定性**：把"机械部分"抽成固定脚本 / CLI（agent 直接调），skill 正文
   只留流程和判断标准。Skill 越小越好，只留模型还做不到的部分；模型变强后
   定期删减（"skills get smaller and smaller"，去年要写具体命令，今年只留流程）。
5. **Buffer 再固化**：不要见一个定一条。先让 agent 把实例 append 到 buffer 文档，
   攒一批后看共性、找根因，再固化成规则。固化后验证：这类错误真的消失了吗？
   没有 → 修规则，不骂 agent。

## 教训/可复用要点

- 自下而上：从真实痛点长出来，不自上而下设计 skill 体系。
- 自己的刀：别人的 skill 可以拼着用（pstack × grill me / wayfinder），但最终
  每人 / 每项目一套自己的；"Trust is really about trust in your own tools."
- 落地建议：coordinator 在任务结束时输出"本轮人工插手清单"，
  作为 skill 挖掘的固定输入（可并入 nexus-selfrepair / nexus-task 的收尾步骤）。
  这正是本条目存在的原因：把挖掘方法本身也变成流程。
- 来源：Matt Pocock × Lauren Tan (poteto) 播客
  "LIVE: Poteto (creator of pstack) on shipping 1,000's of PR's a month at SpaceX"，
  2026-10-03，https://www.youtube.com/watch?v=MN9dGgmLyso
