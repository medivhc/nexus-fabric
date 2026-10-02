# MODULE.md — nexus-nat-quality

## Responsibility
NAT 路径的主动质量测量与供给：对指定 `FabricConn` 做 datagram
ping/pong 探针测丢包，复用 `stats().rtt_ms`（quinn 真实 RTT），经由后台
常驻线程把 `PathStats` 供给 `PathManager::on_stats`，并把 `poll_event()`
的切换事件转发给调用方。R3 决议约束：纯 RTT 下 direct 恒胜，违背
"打洞成功≠最优"——loss 测量是必答题，不许降级为只用 RTT。

## Non-Responsibilities
- 打洞编排/状态机（`nexus-nat-traversal`）；接线（`nexus-nat-wireup`）。
- 选路决策本身（`nexus-path::PathManager`）；切换执行（Track 1 的 PathLink）。
- QUIC 传输内部（`nexus-fabric` 零改动；只用公开 `send/recv_datagram` + `stats()`）。

## Inputs
- 被测 `FabricConn`（direct / TURN relay），调用方保证两端都跑了探针 responder。
- `Arc<Mutex<PathManager>>`（调用方创建并持有；本 crate 只调用
  `add_candidate` / `on_stats` / `poll_event`）。
- `Arc<dyn PathEventSink>`（调用方实现，接收 `PathEvent::Switched` 等）。

## Outputs
- 每个被测路径的持续 `PathStats { rtt_ms, loss_rate }`（loss 为滑动窗口丢包率）。
- `PathEventSink::on_path_event` 回调（切换事件）。

## Allowed Dependencies
`nexus-fabric`（`FabricConn`、`ConnStats`）、`nexus-path`
（`PathManager`、`PathStats`、`PathEvent`、`CandidatePath`、`PathKind`）。
std-only，无第三方依赖。

## Forbidden Dependencies
- 第三方新依赖；tokio（std thread 足够）。
- `nexus-fabric` driver/quinn 内部（只用公开 API）。
- 冻结的 P2 信令合同（探针帧是 wireup 层内部帧格式，不进 `signal.rs`）。

## Invariants
- 探针帧格式（25B）：`[8B magic "NXQPROB!"][1B type 0x01=ping/0x02=pong][8B nonce BE][8B sent_ms BE]`。
  非探针 datagram 原样转交（`forward` channel）或按调用方约定丢弃，绝不静默吞掉。
- `loss_rate` 语义：滑动窗口内已完成样本的丢失比例；无完成样本时为 `None`
  （PathManager S7：无测量不参选）；窗口内全丢时为 `Some(1.0)`
  （PathManager S6：记为 missed probe）。
- 探针频率：active 路径 1s，backup（warm）路径 5s（见 Performance Budget）。
- 后台线程有界：`stop` flag + join；随 `QualityMonitor::shutdown` 结束，
  不泄漏（§13：Owner=QualityMonitor，取消=stop flag，回收=join）。

## Side Effects
- 每被测连接 1 个 responder 线程（收 datagram、回 pong）。
- 1 个 monitor 线程（定时 ping、expire、on_stats、drain events）。
- datagram 流量（见 Performance Budget）。

## Public API
`LossProbe::{new, send_ping, on_pong, expire, loss_rate}`、
`probe::{encode_ping, encode_pong, decode}`、`DatagramTransport`、
`ProbeEndpoint::{start, ping, loss_rate, expire}`、
`QualityMonitor::{new, add_path, remove_path, set_role, shutdown}`、
`MeasuredPath`、`ProbeRole::{Active, Backup}`、`PathEventSink`。

## Verification
- 单测（E2）：帧编解码往返/拒识、LossProbe 全丢/全收/部分丢/空窗口/
  未知 nonce、monitor 供给（mock transport + 真实 PathManager）。
- E4（真机，Track 1 联合）：relay→direct 真实切换不断流。

## Performance Budget
- 单探针 ≤ 75B（含 QUIC 开销上确界）；active 1/s → 75 B/s（0.6 kbps）；
  backup 1/5s → 15 B/s。相对生产流量可忽略。
- 滑动窗口 10 样本；ping 超时 2×间隔；monitor tick 200ms。

## Observability
`eprintln!` 前缀 `[nat-quality]`（仅状态变化：add/remove/switch 驱动，
不打 per-ping 日志）；`QualityStats { pings_sent, pongs_recv, timeouts }` 可查。

## Recovery Semantics
- 连接关闭：responder 线程因 `recv_datagram` Err 退出；monitor 跳过失败 ping，
  expire 后 loss→1.0，PathManager 按 S6 做 failover。
- monitor 线程 panic 不传播（join 时忽略，只记日志），不影响调用方。

## Platform Constraints
无（std-only；datagram 经 fabric driver，与平台无关）。
