---
id: 2026-10-03-n2-p03-planner-thicken
date: 2026-10-03
module: nexus-planner / nexus-domain / nexus-session / apps-nexus
category: architecture-decision
task_type: feature
---

# N2 P0-3：DecisionTrace 加厚、PlanId、plan 双模式的五个选址决定

## 决定 1：trace DTO 从 nexus-planner 迁移到 nexus-domain

D3 要求 Session 记录内嵌 `PlanSnapshot{plan, decision_trace}`，但
`policies/architecture.toml` 中 `nexus-session` 只允许依赖 `nexus-domain`。
给 session 加 planner 依赖是层级倒置（planner 是被调用方，不是被内嵌方），
所以把纯数据 DTO（`RejectReason`/`ScoreComponent`/`ConsideredCandidate`/
`DecisionTrace`/`PlanId`/`MeasurementSnapshot`/`PlanSnapshot`/`plan_id_of`）
移到 domain，求解逻辑留在 planner。`ScoredCandidate`/`FilteredCandidate`
留在 planner（它们包裹 `ProviderRecord`，domain 不能依赖 registry）。
外部调用方只从 planner 导入 `PlanningSnapshot`/`plan_from_snapshot`/
`connectivity_gate`，迁移零破坏。

## 决定 2：MeasurementSnapshot 镜像而非复用 LinkMeasurement

`ConsideredCandidate.measurement` 需要测量值，但 `LinkMeasurement` 在
`nexus-measurement`（domain 零依赖，不可引用）。orphan 规则也禁止在 planner
里为两个外部类型实现 `From`。解法：domain 内定义同构的
`MeasurementSnapshot`（名字即语义："决策时的快照"，不随后续测量更新），
planner 用普通函数 `snapshot_measurement()` 转换填充。

## 决定 3：本地优先是 score 分量，不是排序 hack

白皮书原则 #4 落为 `PlanningSnapshot.local_provider: Option<ProviderId>` +
`LOCALITY_BONUS = 1000` 的 `locality` 打分分量（breakdown 恒记录两项，
`contribution` 之和恒等于总分，单测锁定）。排序键优先级：
已知/未知 RTT > 总分（含加成）> ProviderId 字典序——D3 的"未知严格排最后"
高于本地偏好。`local_provider=None` 时行为与旧版完全一致（既有精确分值
单测 7500/0 未动）。

## 决定 4：`nexus plan` 走进程内命令族，不经过 daemon/ControlCommand

`plan <resource>` 是只读纯计算（resolve＋filter＋score），"不建连"由构造保证
（模块零网络 I/O，只调 `plan_from_snapshot` 纯函数）。按既有模式
（subnet/schedule/node/pair）在 `run()` 里 `args[0]=="plan"` 直接分流到
`nexus::plan_cli`，不新增 `ControlCommand` 变体。`plan explain` 同样改走
进程内（双模式需要；daemon 的 `/localapi/v0/plan/explain` 保留，
`observability_plan_explain` 冻结场景不受影响）。

## 决定 5：静态目录编译内置，诚实标注

P0-3 无真实目录：`plan_cli::DIRECTORY` 编译内置 `dev-svc`/`internet-access`
演示条目，输出标注 `directory: "static-demo"`；未知资源名返回结构化
`NotFound`（exit 0），不伪造。`Registry::candidates()` 按 P0-2 契约只返回
在线候选，会吞掉 `not_present` 的解释价值——P0-3 的静态快照直接由条目构造
`ProviderRecord`（含 `present=false` 条目），P0-4 对接 Registry 时再对齐
Presence 过滤语义。`plan explain sess-*` 在 P0-3 恒查无历史→结构化
`NOT_FOUND`，不回退重算（伪造历史比缺失更坏）。

## 可复用要点

- FNV-1a 64 位作 PlanId：无随机种子，跨运行确定；规范编码用 `len:bytes;`
  拼接消除歧义，浮点永不进入编码。`plan_id_of` 覆盖 plan+trace 全字段
  （测量/评估变化 → Id 变化，这是期望的：Id 标识一次决策）。
- worktree 的 `.githooks` 会掉可执行位：提交前
  `chmod +x .githooks/{pre-commit,commit-msg,pre-push,hook-common.sh}`。
- 真机同步：`rsync --exclude ".git"`（无斜杠）+ `--exclude "target/"`；
  `CARGO_TARGET_DIR=<worktree>/target` 隔离多轨道。
