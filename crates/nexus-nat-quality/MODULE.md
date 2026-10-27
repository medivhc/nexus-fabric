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
- `nexus-connectivity`（v9 CLI 产品线运行时，frozen）。跨栈词汇改用 `nexus-domain` /
  `nexus-proxy-config` / `nexus-session` / `nexus-qos`（P3 落地）。

## Invariants
- 探针帧格式（25B）：`[8B magic "NXQPROB!"][1B type 0x01=ping/0x02=pong][8B nonce BE][8B sent_ms BE]`。
  非探针 datagram 原样转交（`forward` channel）或按调用方约定丢弃，绝不静默吞掉。
- **loss 语义**：评分窗口固定 10 个已完成样本，窗口只用于评分。死亡由
  `consecutive_misses >= 14` 判定；当 `consecutive_misses < 14` 时，供给给
  `PathManager` 的 `loss_rate` 严格 <1.0（上限 0.999）；`Some(1.0)` 只在确认死亡时
  供给，`PathManager` 仍以 3 次连续 1.0 报告触发 S6 failover。`path_loss()` 返回
  原始窗口丢包率（诊断/测试），与供给值语义不同。
- **探针频率/节奏**：active 1s、backup 5s；仅 Active 且在怀疑期加速到 100ms
  （`consecutive_misses>=1` 或 `oldest_outstanding_age>=soft_miss_ms`）；
  per-ping deadline `clamp(3×RTT,300,2000)ms`；monitor tick 100ms
  （`ProbePolicy.tick_ms`；生产线程 sleep 间隔必须取该值）；death_misses=14；
  `soft_miss_ms=clamp(2×RTT,100,500)ms`。
- **死亡/迟到 pong**：每条 ping 携带自己的 deadline；`expire` 只按该 deadline
  过期；迟到 pong 在 `2×该 deadline` 内命中 `recent_expired` 时清零
  `consecutive_misses`；已 push 的窗口 false 不回收。`set_role` 清零连续 miss
  计数（并清除 dead 日志 latch，不伪造 `path recovered`）。
- 后台线程有界：`stop` flag + join；随 `QualityMonitor::shutdown` 结束，
  不泄漏（§13：Owner=QualityMonitor，取消=stop flag，回收=join）。

## Side Effects
- 每被测连接 1 个 responder 线程（收 datagram、回 pong）。
- 1 个 monitor 线程（定时 ping、expire、on_stats、drain events）。
- datagram 流量（见 Performance Budget）。

## Public API
`LossProbe::{new, send_ping(now,deadline), on_pong, expire(now), loss_rate,
consecutive_misses, oldest_outstanding_age_ms}`、
`probe::{encode_ping, encode_pong, decode}`、`DatagramTransport`、
`ProbeEndpoint::{start, ping(now,deadline), expire(now), reset_consecutive_misses,
consecutive_misses, oldest_outstanding_age_ms, loss_rate, rtt_ms}`、
`ProbePolicy`（字段/`Default`/`interval_ms`/`soft_miss_ms`/`deadline_ms`）、
`QualityMonitor::{new, with_policy, add_path, remove_path, set_role, shutdown}`、
`MeasuredPath`、`ProbeRole::{Active, Backup}`、`PathEventSink`。
**不引入** `ProbeEndpoint::start_with_policy`（策略只属于 monitor）。

## Verification
- 单测（E2）：帧编解码往返/拒识、LossProbe 全丢/全收/部分丢/空窗口/
  未知 nonce、per-ping deadline、连续 miss 13/14 边界、迟到 pong 宽限、
  monitor 供给（mock transport + 真实 PathManager）。
- 死亡/时延：`supply_loss` 非死亡期严格 <1.0；虚拟时间
  `death_within_4000ms_virtual`、`loss_25pct_never_dies_virtual_60s`
  （60s、双向独立 25%、固定种子、钉住 13 连丢边界）、
  `role_promotion_no_false_death`、`tick_dead_path_converges_to_full_loss`。
- 生产节拍：`default_policy_tick_ms_is_100` 与
  `production_start_sleeps_policy_tick`（线程 sleep 取有效 `ProbePolicy.tick_ms`）。
- E4（真机，Track 1 联合）：relay→direct 真实切换不断流。

## Performance Budget
- 单探针 ≤ 75B（含 QUIC 开销上确界）；active 1/s → 75 B/s（0.6 kbps）；
  backup 1/5s → 15 B/s。相对生产流量可忽略。
- 窗口 10 个已完成样本（仅评分）；Active 1s / Backup 5s；怀疑期 100ms；
  per-ping deadline `clamp(3×RTT,300,2000)`；tick 100ms；正常双向 ≈50B/s、
  怀疑期 ≈500B/s（持续 ≤~1.5s）。

## Observability
`eprintln!` 前缀 `[nat-quality]`（仅状态变化：add/remove/switch 驱动，
不打 per-ping/per-tick 日志）；`QualityStats { pings_sent, pongs_recv, timeouts }` 可查。
死亡状态变化：
`[nat-quality] path dead: {addr} misses={n} at_ms={now_ms}` /
`[nat-quality] path recovered: {addr} at_ms={now_ms}`。

## Recovery Semantics
- 连接关闭：responder 线程因 `recv_datagram` Err 退出；monitor 跳过失败 ping，
  expire 后 loss→1.0，PathManager 按 S6 做 failover。
- 迟到 pong 在 `2×该 ping 的 deadline` 宽限内命中 `recent_expired` 即清零连续
  miss 计数（已 push 的窗口 false 不回收，评分略保守）。
- role 切换（`set_role`）清零连续 miss 计数并清除 dead 日志 latch。
- `path dead` / `path recovered` 只在状态变化时打印，不刷屏。
- monitor 线程 panic 不传播（join 时忽略，只记日志），不影响调用方。

## Platform Constraints
无（std-only；datagram 经 fabric driver，与平台无关）。
