---
id: ws-intel-crate-placement
date: 2026-10-02
module: nexus-workspace-intel
category: architecture-decision
task_type: feature
---

# Workspace Intelligence 独立成 crate（D2=A）

## 问题/模式描述

v9 §21 的 Workspace Intelligence（Graph/Profile/WorkingSet/Prefetch）明确标注
"可丢失并重建"，与权威模型（Commit DAG/HeadSet/Journal）性质正交。
`nexus-workspace/src/lib.rs:15` 也写明"本切片不实现"。

## 原因分析

- 权威 vs 非权威混在一个 crate 里，时间一长必然有人把 estimator 结果
  当正确性依据用（如"预取失败就不 commit"），破坏分层；
- 物理隔离（独立 crate + 独立存储文件）让 Deletion Test 可执行：
  删 crate/删文件，workspace 照转；
- PrefetchScheduler → Planner 的接线需要 planner/registry 类型，
  workspace crate 若直接依赖 planner 会违反"Planner ≠ Estimator"的
  依赖方向（workspace 是被规划的对象，不应知道 planner）。

## 解决方案

- 新 crate `nexus-workspace-intel`，依赖方向只读：
  `intel → {domain, workspace(只读), planner(类型), registry(类型), storage(bound)}`；
- `ResourceDeliveryRequest` DTO 放 `nexus-domain`（跨域契约），`to_snapshot`
  转换放 intel 的 `delivery.rs`；
- 估计器/调度器/建图全是纯函数，"现在"取轨迹最大时刻（不读系统时钟），
  保证确定可重放；
- `IntelStore` 独立 JSON 文件，原子 tmp+rename 写；`delete()` 即 Deletion Test 入口。

## 教训/可复用要点

- "可丢失重建"的内容一律物理隔离，不要只靠注释隔离；
- 估计器类组件的"现在"必须参数化（轨迹最大时刻），否则单测要 mock 时钟。
