---
id: fabric-rebind-failure-arm
date: 2026-09-30
module: nexus-fabric
category: implementation-pitfall
task_type: feature
---

# rebind() 失败路径的测试触发：本端 close() 不 reap，对端 close 才 reap

## 问题/模式描述

Phase 4a 需要测试 `PathLink::pump()` 的 rebind 失败分支
（`path_rebind_errors` 计数、不 panic）。直觉做法：`conn.close()` 后
`rebind()` 应返回 Err。实测：本端 close 后轮询 10 秒，`rebind()` 一直
返回 Ok。

## 原因分析

`driver.rs` 的 `cmd_rebind` 只在连接不在 `live` 表时返回
`Err(FabricError::Closed)`。`close()` 只是排队 QUIC close 帧；driver 的
reap 条件是 `poll_timeout().is_none() && closed.is_some()`。实测发现
本端主动 close 后连接长期不被 reap（quinn-proto 本端关闭语义），而
**对端** close 后约 0.5 秒即 reap（ConnectionLost 到达）。

## 解决方案

测试用对端 close 来武装失败路径：`conn_b.close()` → 轮询
`conn_a.rebind()` 直到返回 Err（带 10 秒超时断言）→ 再跑 pump 断言
`path_rebind_errors == 1`。

## 教训/可复用要点

- fabric 连接的"死亡"判定不对称：本端 close ≠ 立即可观测的死亡。
- 需要确定性触发 Err 时，用对端 close + 轮询 reap，不要依赖本端 close。
- 这是 nexus-fabric 的行为，4a 未改动它；如需"本端 close 后及时 reap"
  则是独立的 fabric 任务。
