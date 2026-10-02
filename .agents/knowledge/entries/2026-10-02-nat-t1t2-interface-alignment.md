---
id: nat-t1t2-interface-alignment
date: 2026-10-02
module: nexus-projection
category: architecture-decision
task_type: feature
---

# T1/T2 接口对齐：PathLink 共享 Arc<Mutex<PathManager>>，monitor 为唯一生产 drainer

## 背景

NAT 生产流量切换的三条轨道独立开发后合入时，T1（`PathLink` 选路集成）与
T2（`nexus-nat-quality` 测量）对 `PathManager` 的所有权假设冲突：

- T1：`PathLink` 按值拥有 `PathManager`，`pump()` 同步 drain `poll_event()`；
  stats 由外部调用 `manager_mut().on_stats()` 供给。
- T2：`QualityMonitor::new(pm: Arc<Mutex<PathManager>>, sink)`，后台 tick 做
  ping→expire→`on_stats`→drain `poll_event`→`PathEventSink`。

## 决定

T1 向 T2 对齐（改动小的一侧动）：

1. `PathLink.manager: Arc<Mutex<PathManager>>` —— 与 monitor 共享同一 manager。
   `manager_mut(&mut self) -> &mut PathManager` 改为
   `manager(&self) -> Arc<Mutex<PathManager>>`。
2. 生产环境 monitor 的 tick 是**唯一**的 `poll_event()` drainer；
   `pump()` 保留给无 monitor 的上下文（单测、legacy 手动驱动），文档明确
   "monitor 已挂载时不许调 pump()"，否则双 drainer 抢事件。
3. `pump()` 的事件处理逻辑抽成 `pub handle_event(&mut self, event)`，
   装配层的 `PathEventSink` 实现（持有 `Arc<Mutex<PathLink>>`）直接委托，
   不在 nexus-projection 里重复 NAT-flip / legacy-rebind 策略。
4. `nexus-projection` 不新增对 `nexus-nat-quality` 的依赖——sink 实现放在
   composition root（nexusd），依赖方向保持 measurement→path，无环。
5. 候选双重注册（`register_nat_*` 与 monitor `add_path` 都调
   `add_candidate`）是安全的：`add_candidate` 按 remote key 幂等，保留
   `added_at`；生产装配中两者背靠背调用、中间无 stats，EWMA 重置无害。

## 教训

- 并行轨道约定接口时，只约定"谁调谁"不够，还要约定**所有权**（谁拥有
  PathManager）和**排他性**（谁是唯一的 drainer）。T1/T2 只约定了
  on_stats 调用，漏了这两点，合入时才暴露。
- `&mut self` 方法 + `Arc` 共享天然冲突：需要跨线程共享时，优先把
  `&mut` 逻辑抽成可委托的小方法（`handle_event`），而不是把整个 struct
  改成内部可变。
