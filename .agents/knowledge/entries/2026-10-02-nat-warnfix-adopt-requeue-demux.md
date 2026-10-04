---
id: nat-warnfix-adopt-requeue-demux
date: 2026-10-02
module: nexus-nat-wireup
category: implementation-pitfall
task_type: bugfix
---

# NAT WARN-1/WARN-2：adopt 排空 id 不丢失 + unclaimed 分流契约

## 问题/模式描述

独立 Review（review-nat-prodswitch，COMMENTED）留下 2 个 WARN，都在
`nexus-nat-wireup`：

1. **WARN-1**：`adopt_verified_direct` 从全局 `accept_q` 排空候选直连，
   对非本 peer 的连接判 Rejected 后直接丢弃、不放回。A 并发打洞 B、C
   且两次 tie-break 皆败时，第一次 adopt 可能吞掉 C 的直连。
2. **WARN-2**：`take_unclaimed`（D5 分流出的非 punch 流）无生产消费者。

## 原因分析

WARN-1 的实际洞比 review 描述的多三处——`accept_q` 是 pop-only，
任何被 pop 出但未被 adopt 的 id 都会永久丢失：

1. **Rejected 丢弃**（review 已指出）：`rejected.insert(id)` 后连接被丢，
   不放回队列。
2. **Verified 时直接 return**：同批 `pending` 里还没挑战的候选随
   `return Some(conn)` 被丢弃。
3. **超时退出时 pending 被丢**：`while` 循环结束直接 `return None`，
   retryable 的候选全丢。
4. **隐藏坑**：即使按 review 字面建议"Rejected 放回队尾"，同一 adopt
   的下一轮 drain 里 `pop_front` + `continue` 会把刚放回的 id 再吞掉——
   drain 本身必须改（已拒绝的 id 留在队里，只 defer 到队尾）。

WARN-2：`take_unclaimed` 已经是 `pub`，但 responder_loop 是
`register_relay` 注册的中继连接上**唯一的** stream acceptor；
session 层的 `accept_bi` 只在 examples/`apps/nexus` 用，nexusd 的
`nat_switch.rs` 完全不消费 stream——没有现成的 inbound 路径可接，
硬造消费者会制造双 acceptor 竞速。

## 解决方案

WARN-1（`src/lib.rs`）：
- 新增 `requeue_accept_id(accept_q, accept_cv, id)`：id 放回队尾 + notify。
- 新增 `drain_candidates(...)`：排空时已拒绝/已在 pending 的 id
  defer 回队尾（不 pop 丢弃）；未知/已关闭的 id 照常消费。
- `adopt_verified_direct`：Rejected → 立刻 requeue（本轮 `rejected`
  集合防自旋）；Verified → 把同批未处理的 requeue 后再 return；
  超时退出 → 把 retryable 的 requeue 后再 return None。

WARN-2：
- `take_unclaimed` 保持 `pub`，rustdoc 写全 demux 契约：
  wireup 是注册中继连接的唯一 acceptor；session 层不许调 `accept_bi`；
  非 punch 流经 `take_unclaimed` 交出，字节完好（peek 永不 pop），FIFO。
- D5 路由表抽成纯函数 `route_inbound` + `InboundRoute`
 （Punch/StashUnclaimed/PushBack/Drop），`responder_loop` 改用它，
  路由决策被单测锁定。
- MODULE.md 补 Invariants + Public API。**接线形态 = API+契约**，
  不硬造消费者（后续中继连接器 gap 验收时再实例化）。

## 教训/可复用要点

- pop-only 队列 + 多消费者 = 必须有"放回"语义；review 建议的字面实现
  可能漏掉同一函数内的二次吞没，修的时候要走完 id 的完整生命周期
  （drain → challenge → return/timeout → 下一轮 drain）。
- 沙盒里 `ConnShared`/`StreamShared` 造不出假对象（`ConnState`/
  `StreamState` 未从 fabric 导出，且任务约束只改 wireup），端到端
  pipeline 测试只能去 xc-pc-linux；沙盒里用纯函数抽取 + 队列级测试
  覆盖决策逻辑是诚实的折中。
- "无消费者" 的 WARN 先查调用链再动手：没有现成路径时，API+契约+
  测试就是完整交付，不硬造。
