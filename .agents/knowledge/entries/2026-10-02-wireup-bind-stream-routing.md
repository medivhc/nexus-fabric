---
id: wireup-bind-stream-routing
date: 2026-10-02
module: nexus-nat-wireup
category: implementation-pattern
task_type: feature
---

# Wireup D4/D5：nonce 挑战-应答绑定 + stream 类型前缀路由

## 问题/模式描述

NAT 生产流量切换 Track 3 的两个安全/路由缺口：

1. **D4 身份绑定**：`resolve_accepted_after` 用"最近 accept 的连接"启发式
   adopt 直连，多 peer 并发打洞时会误认（server 侧 `ConnShared.peer`
   恒零值，无 client auth）。
2. **D5 stream 路由**：responder 把中继连接上所有 inbound stream 当
   offer 解，transfer 流会被 `decode_offer` 误杀（stream 已被消费）。

## 解决方案

**D5（帧格式）**：`u8 type | u32 BE len | payload`，`0x01`=punch，
`0x02`=bind。双端同时改（wireup 内部格式，不在冻结 P2 合同内）。

**D5（路由）**：responder 用 `peek_stream_type` 只看首字节、
**不消费**；punch 类型进 `handle_offer`，其余进 `unclaimed` 队列
（转交 handoff，字节完好）；peek 超时则放回队列（不杀慢流），
EOF/错误则丢弃。方案选"转交"而非"放回"：放回同一条流会空转。

**D4（绑定）**：`signaling_nonces: HashMap<PeerId, HashSet<u64>>`
记录每 peer 的信令 nonce（发出+收到）。tie-break 败方在候选直连上
开 BIND 流做挑战-应答：对端须回显一个该 peer 的信令 nonce，
`verify_bind` 做集合交集检查。胜方在 `on_migrated` 起 30s 有界的
bind responder。挑战超时可重试（胜方 responder 可能还没起来），
nonce 对不上则永久拒绝。fail-closed：验不过就留中继。

## 教训/可复用要点

- `accept_q` 是 drain 语义：pop 出的 id 下轮看不到。需要重试的候选
  必须自己 نگه `pending: Vec<Arc<ConnShared>>` 跨轮保留，否则
  Retryable 会丢连接（实现中真实踩到，已修）。
- `StreamShared` 的 `StreamState` 未从 nexus-fabric 导出，单测里造不出
  假 stream；peek/路由的字节完好性靠"peek 永不 pop recv_buf"的不变量
  保证，单测只覆盖纯函数（framing/bind/verify）。
- 挑战-应答不能让挑战方先给 nonce（回显无证明力）；必须是应答方
  主动出示信令知识，挑战方做集合验证。
