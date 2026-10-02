# MODULE.md — nexus-nat-wireup

## Responsibility
生产接线：把 `nexus-nat-traversal` 的 portable 编排（`PunchSession`）接到
真实 `nexus-fabric` driver 上。提供：
- `FabricPunchChannel`：中继连接上的信令通道（`PunchChannel`）。
- `DriverPunchSocket`：同一 punch driver 上的 QUIC 建连扇出（`PunchSocket`）。
- `PunchManager`：responder、去重、tie-break、direct 登记。

## Non-Responsibilities
- 打洞决策/状态机（`nexus-nat-traversal`）。
- QUIC 传输（`nexus-fabric`，零改动；仅 additive re-export）。
- 路径层选路（`nexus-path`；本 crate 只做登记=日志+计数）。

## Inputs
- 中继 `Arc<ConnShared>`（已建连，TURN 或直连）。
- punch `Arc<Driver>`（直连 UDP socket，server+client 能力）。
- 本端/对端 `PeerId`、`LocalCandidates`、NAT 类型、STUN 采样。

## Outputs
- `PunchResult::{Migrated{addr}, StayedOnRelay{reason}}`。
- 存活的直连 `Arc<ConnShared>`（tie-break 后唯一，登记在 manager）。
- 中继连接永不关闭（warm backup，D4）。

## Allowed Dependencies
`nexus-fabric`、`nexus-nat-traversal`、`nexus-connectivity`（path）。
`nexus-turn` 仅 dev（E4）。

## Forbidden Dependencies
第三方新依赖；tokio；`nexus-path` 的写入式接入（只读登记）。

## Invariants
- 打洞包永远从 punch driver 的同一 UDP socket 发出。
- `run()` 的 `Migrated` 语义：直连 QUIC 握手已完成（`Driver::connect`
  返回），不是"包发出去了"。
- tie-break 确定性：PeerId 大者发起的连接保留；小者关闭自己的
  发起连接。两端独立计算，无需协商。
- 中继连接在 Migrated 后不关闭。
- Stream 类型前缀（D5）：wireup 的 stream 帧为 `u8 type | u32 BE len |
  payload`；`0x01`=punch 信令，`0x02`=bind。responder 只 peek 类型，
  非 punch 流一律 stash 到 `unclaimed`（字节完好），永不误解为 offer。
- Nonce 绑定（D4）：tie-break 败方 adopt 直连前，必须在候选连接上做
  挑战-应答——对端须回显一个本 peer 信令交换中的 nonce；
  对不上则丢弃（中继保留）。per-peer nonce 集合，多 peer 并发不误认。
  不动 `nexus-fabric`（server 侧 peer 零值问题由 fabric client auth
  专项解决）。

## Side Effects
- 后台线程：connect 扇出（自限时）、responder accept 循环。
- 度量：`PunchStats`（尝试/迁移/失败计数）、drop 计数（E4 sim）。

## Public API
`PunchManager::{new, set_local, register_relay, punch_peer, direct_conn, stats}`、
`punch_peer(driver, my_id, relay_conn, peer, local, remote_nat, config)`、
`FabricPunchChannel::open`、`DriverPunchSocket::{new, take_winner, punch_attempts}`、
`SeededPredictor`、`LoggingFeed`。

## Verification
- 单测：类型前缀 framing 往返、bind 编解码、per-peer nonce 验证、
  tie-break 规则、first-wins、preanswered nonce。
- E4（真机）：relay-first / symmetric-spray / unpredictable-fallback，
  经 userspace NAT 模拟器的真实丢包/映射语义；生产流量切换不断流。

## Performance Budget
- spray 扇出 ≤ 2K+1（K≤32）个并发握手；每个自带 handshake timeout。
- await_direct 轮询间隔 20ms。

## Observability
`eprintln!` 前缀 `[wireup]`；`PunchStats` 计数可查。

## Recovery Semantics
- 打洞失败 → `StayedOnRelay`，中继不断。
- 悬挂的 connect 线程随各自 handshake timeout 自行结束（≤ punch_timeout）。

## Platform Constraints
std-only，无平台相关代码。
