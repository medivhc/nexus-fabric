# MODULE.md — nexus-nat-wireup

## Responsibility
生产接线：把 `nexus-nat-traversal` 的 portable 编排（`PunchSession`）接到
真实 `nexus-fabric` driver 上。提供：
- `FabricPunchChannel`：中继连接上的信令通道（`PunchChannel`）。
- `DriverPunchSocket`：同一 punch driver 上的 QUIC 建连扇出（`PunchSocket`）。
- `PunchManager`：responder、去重、tie-break、direct 登记、per-peer registry、
  重打洞调度、prediction 贯通、可观测。
- `SystemPunchClock`：生产时钟注入（`Instant` 基准 + `SystemTime` wall）。

## Non-Responsibilities
- 打洞决策/状态机（`nexus-nat-traversal`）。
- `RelayConnProvider` 的 TURN 生命周期与身份（`nexusd::nat_turn`）；本 crate 只接收
  `on_relay_connected` 的生产喂入。
- QUIC 传输（`nexus-fabric`）。本 crate 只通过 **additive** 接口使用它：
  STUN 事务 tap（`install_stun_tap`/`send_stun_request`/`StunSink`）与
  `FabricConn::shared()`；不改 quinn-proto、不改现有 `on_udp` 的 QUIC 行为。
- 路径层选路（`nexus-path`；本 crate 只做登记=日志+计数）。

## Inputs
- 中继 `Arc<ConnShared>`（已建连，TURN 或直连）。
- punch `Arc<Driver>`（直连 UDP socket，server+client 能力）。
- 本端/对端 `PeerId`、`LocalCandidates`、NAT 类型、STUN 采样。

## Outputs
- `PunchResult::{Migrated{addr}, StayedOnRelay{reason}}`。
- 存活的直连 `Arc<ConnShared>`（tie-break 后唯一，登记在 manager）。
- `PunchPeerStatus`/`TunnelProto`/`RelaySource` 的 per-peer 快照（`status`/`all_status`）。
- 中继连接永不关闭（warm backup，D4）。

## Allowed Dependencies
`nexus-fabric`、`nexus-nat-traversal`、`nexus-connectivity`（path）。
`nexus-turn` 仅 dev（E4）。

## Forbidden Dependencies
第三方新依赖；tokio；`nexus-path` 的写入式接入（只读登记）。
- `nexus-connectivity`（v9 CLI 产品线运行时，frozen；**目标态禁止**）。
  当前残留接缝：①`NatType`，由 P1（迁 `nexus-domain::nat`）清除，
  见 `docs/DOC-AUDIT-2026-10-26-dual-stack.md` 与 `docs/adr/0001-dual-stack-boundary.md`。

> 范围澄清（2026-10-02）：以上禁令约束 `src/` 实现。`examples/e4_prod_switch.rs`
> 作为 E4 验证，为接线完整切换栈（PathLink + QualityMonitor）可依赖
> `nexus-nat-quality` / `nexus-path` / `nexus-projection`（dev-dependencies），
> 实现代码仍不许触碰。

## Invariants
- 打洞包永远从 punch driver 的同一 UDP socket 发出；STUN 样本
  `observed_from == driver.local_addr()`。
- `run()` 的 `Migrated` 语义：直连 QUIC 握手已完成（`Driver::connect`
  返回），不是"包发出去了"。
- **双方都发起**（C-14）：两端 `PunchManager` 都发起打洞；tie-break 确定性：
  PeerId 大者发起的连接保留，小者关闭自己的发起连接。两端独立计算，无需协商。
  不许因 `my_id < peer` 提前 return 等待。
- `DirectConn.addr` = **存活连接实际 remote 地址**（adopt 路径取 `ConnShared.remote_addr`，
  发起路径取 winner target）；不是信令里抄来的地址。
- `PathLink::register_nat_direct` 是唯一真实登记点；`LoggingFeed` 只计数/日志，
  不参与选路（C-13）。
- 中继连接在 Migrated 后不关闭。
- Stream 类型前缀（D5）：wireup 的 stream 帧为 `u8 type | u32 BE len |
  payload`；`0x01`=punch 信令，`0x02`=bind。responder 只 peek 类型，
  非 punch 流一律 stash 到 `unclaimed`（字节完好），永不误解为 offer。
- Nonce 绑定（D4）：tie-break 败方 adopt 直连前，必须在候选连接上做
  挑战-应答——对端须回显一个本 peer 信令交换中的 nonce；
  对不上则丢弃（中继保留）。per-peer nonce 集合，多 peer 并发不误认。
  不动 `nexus-fabric`（server 侧 peer 零值问题由 fabric client auth
  专项解决）。
- 并发 adopt 不丢连接（WARN-1，2026-10-02）：`accept_q` 是 pop-only，
  adopt 排空的候选 id 永不静默丢弃——Rejected 的放回队尾（本轮
  `rejected` 集合防自旋）、Verified 时未处理的放回、超时退出时
  retryable 的放回。drain 时已拒绝的 id 留在队里（defer 回队尾），
  不 pop 丢弃。A 并发打洞 B、C 时，一方的 adopt 不能吞掉另一方的直连。
- Stream 分流契约（D5，WARN-2，2026-10-02）：`register_relay` 后，
  wireup 的 responder_loop 是该中继连接上唯一的 stream acceptor；
  session 层不许对这类连接调 `accept_bi`（会和 responder 在
  `ConnShared.accepted` 上竞速）。非 punch 流按首帧类型进
  `unclaimed` 队列（字节完好，peek 永不 pop），session 层经
  `take_unclaimed` 取走。当前 nexusd 尚未消费，API+契约为接线形态，
  不硬造消费者。

## Side Effects
- 后台线程：connect 扇出（自限时）、responder accept 循环、repunch scheduler
  （tick 1000ms，`Weak<PunchManager>`，manager drop 即退出）。
- 度量：`PunchStats`（尝试/迁移/失败/spray/probe/hint 计数）、`signal_decode_errors_total`、
  `LoggingFeed` 计数。

## Public API
`PunchManager::{new, set_config, set_local, set_samples, register_relay, punch_peer,
repunch, on_reflexive_changed, on_relay_degraded, direct_conn, take_unclaimed,
punch_attempts, status, all_status, set_tunnel_proto, set_relay_source}`、
`punch_peer(driver, my_id, relay_conn, peer, local, remote_nat, config, clock)`、
`FabricPunchChannel::{open, wrap, last_offer_nonce, decode_errors}`、
`PreAnsweredChannel::{new, captured_nonce}`、
`DriverPunchSocket::{new, take_winner, punch_attempts}`、
`FabricPunchChannel`/`DirectConn`/`PunchPeerStatus`/`PunchState`/`TunnelProto`/
`RelaySource`/`RepunchTrigger`、`SeededPredictor`、`LoggingFeed`、`SystemPunchClock`。

## Verification
- 单测/集成：类型前缀 framing 往返、bind 编解码、per-peer nonce 验证、
  tie-break 规则、first-wins、preanswered nonce、prediction 贯通、
  `DirectConn.addr` adopt 取实际 remote、repunch 299/300s 与 5s 合并、
  Symmetric 全禁、registry 聚合与 `signal_decode_errors_total`、
  `await_direct` 全失败归 `TimedOut`、8 个虚拟时间测试之一 `repunch_after_300s`。
- E4（真机）：relay-first / symmetric-spray / unpredictable-fallback，
  经 userspace NAT 模拟器的真实丢包/映射语义；生产流量切换不断流。

## Performance Budget
- spray 扇出 ≤ 2K+1（K≤32）个并发握手；每个自带 handshake timeout。
- await_direct 轮询间隔 20ms。

## Observability
`eprintln!` 前缀 `[wireup]`；`PunchStats` 计数可查。

## Recovery Semantics
- 打洞失败 → `StayedOnRelay`，中继不断。
- 重打洞三触发：periodic（300s + jitter）、reflexive changed、relay degraded
  （3 miss / loss≥0.30×3 / RTT EWMA≥2× 60s-min）；同 peer in-flight ≤1，
  事件触发 5s 内合并，periodic 每 interval ≤1；任一端 Symmetric → 所有自动重打禁用。
- 旧 direct 在新 direct 验证成功前不拆；`repunch` 不重置统计，只累加。
- 悬挂的 connect 线程随各自 handshake timeout 自行结束（≤ punch_timeout）；
  responder bind 30s 上限；STUN pending TTL 2000ms。

## Platform Constraints
std-only，无平台相关代码。
