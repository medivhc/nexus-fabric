# MODULE.md — nexus-nat-traversal

contract: `6052e333abfac88c`（NAT 穿透 v1.1+doc-sync）

## 职责

互联网 NAT 穿透的 portable 编排核心：候选地址模型（P1）、信令 v1/v2 编解码（P2）、
可预测性与有界端口预测（P3）、打洞状态机与单一总预算（P4）、可观测计数（P7）。
本 crate 只做纯编排与编解码，通过注入 trait（`PunchChannel`/`PunchSocket`/
`PunchPredictor`/`PunchClock`）与外部交互。

## 非职责

- 真实 QUIC 建连、迁移与路径验证（`nexus-fabric` driver + 组合根）。
- 三类路径竞速与选路（`nexus-path::PathManager`，P5 SUPERSEDED）。
- STUN/TURN 网络 I/O 与样本采集（`nexusd::nat_stun`/`nat_turn`）。
- 重打洞调度、per-peer registry、LocalAPI/CLI（`nexus-nat-wireup`/`nexusd`）。
- 配置文件解析与校验（`nexusd::config` 的 `PunchSection`）。

## 输入

- `PeerId`、`LocalCandidates`、远端 `NatType`。
- `Vec<PortSample>`：带 `target`/`observed_from`/`at_ms` 的 STUN 端口样本。
- `PunchConfig`：单一总预算、spray/预测/mapping probe 参数。
- `Arc<dyn PunchChannel>`、`Arc<dyn PunchSocket>`、`Arc<dyn PunchPredictor>`、
  `Arc<dyn PunchClock>`。

## 输出

- `PunchResult::{Migrated{addr}, StayedOnRelay{reason}}`（Exactly-One 终态）。
- `PunchPhase` 状态与 `PunchStats` 12 字段计数。
- 编解码帧：`encode_offer/decode_offer`、`encode_answer/decode_answer`（v2）与
  `*_v1`（v1 兼容入口）。

## 依赖

仅 `nexus-connectivity`（`NatType`），std-only；`[dependencies]` 无第三方 crate。
无 I/O、无线程创建、无系统时间（`SystemTime`/`Instant::now`/`thread::sleep` 禁用）。
`portable = true`（`policies/architecture.toml`）。

## 不变量

- **单一总预算**：`deadline = clock.now_ms() + punch_timeout` 在 `run()` 入口起算，
  所有等待共享剩余预算，不得各自重新起算。
- **nonce**：`clock.now_ms()` + 进程内 `AtomicU64` 生成；同一虚拟毫秒内仍唯一；
  nonce 不匹配的 answer 丢弃、状态机不推进。
- **方向与门控**：symmetric–symmetric 零发送；cone→symmetric 无 hint 零发送；
  cone→symmetric 有 hint 只对单一 reflexive IP spray；symmetric→cone **仅当本端
  `assess(own_samples) == Predictable`** 时发 `mapping_probe_count` 个 probe、
  不 spray；本端 `assess != Predictable` 时以 `UnpredictableSymmetric` 零发送
  （不构造 `SendPlan::Probes`）。
- **零发送条件**：`NoCandidates`、`UnpredictableSymmetric`（含“symmetric→cone 且
  本端不可预测”）时不发任何打洞包。
- **exactly-one 终态**：`run()` 只返回一次终态，`Failed` 后不再回到成功态。
- **same-socket**：`srflx_turn` 仅在 `turn_same_socket && cone` 时 authoritative，
  否则只诊断；`ordered()` 不读 `srflx_turn`。
- **编码上限**：候选编码 >16 截断到 16（`debug_assert!`），解码 >16 → `TooMany`；
  版本入口显式不兼容（v2 只收 2、v1 只收 1，其他 → `Version`）。

## 公开 API

- `PunchSession::{new, run, phase, peer, stats, set_local, set_samples}`。
- `PunchConfig`（12 字段）+ `Default` + `validate()`；`PunchConfigError`。
- `PunchClock`、`PunchChannel`、`PunchSocket`、`PunchPredictor`、
  `PunchRaceFeed`（可观测钩子）。
- `LocalCandidates::{has_punchable, ordered, authoritative_srflx}`、`punch_targets`。
- `PredictionHint`、`PredictionPlan`、`DefaultPredictor`、`NoopPredictor`。
- `SIGNAL_VERSION=2`、`MAX_CANDIDATES=16`、`encode_*`/`decode_*`/`*_v1`。
- `PunchStats`、`PunchPhase`、`PunchFailReason`（含 `as_str`）。

## 验证

- 10 个虚拟时间测试（`crates/nexus-nat-traversal/tests/virtual_time.rs` + wireup
  `repunch_after_300s`）：`coord_wait_uses_virtual_time`、`punch_timeout_at_5000ms`、
  `spray_pacing_50ms`、`spray_budget_3s`、`nonce_unique_without_wall_clock`、
  `single_total_budget`、`mapping_probe_count_bounded`、`repunch_after_300s`、
  `unpredictable_symmetric_local_sends_zero`、`assess_called_once_per_run`。
- 错误映射：`SignalError` 8 变体、`PunchConfigError` 2 变体逐条测试。
- grep 门：`rg -n "SystemTime|Instant::now|thread::sleep|std::thread" src` 无命中。
- 编解码往返：v1 逐字节兼容；v2 prediction 逐字段、17→16、>16 → `TooMany`。
- Red Evidence：`G4/G5/G6/G7/G8/G18`（`evidence/red-evidence/`）。

## 性能预算

- 总预算 5s（`punch_timeout`）；协同时间窗 200ms。
- spray 时间盒 3s、间隔 50ms、半径 K≤32（spray 包 ≤33）。
- mapping probe 3 个 × 50ms；本端不可预测时 0 个。
- 虚拟时间套件墙钟 <2s。

## 可观测

`PunchStats` 12 字段：`attempts`/`migrated`/`failed_timeout`/`failed_unpredictable`/
`failed_no_candidates`/`failed_channel_closed`/`spray_sends`/`spray_skipped`/
`mapping_probe_sends`/`prediction_hints_sent`/`prediction_hints_recv`/`last_phase`。
计数字段经 wireup registry 按 peer 聚合为 `*_total`；`last_phase` 覆盖不累加。

## 恢复语义

- 打洞失败 → `StayedOnRelay{reason}`，中继保持；重打由 `nexus-nat-wireup`
  的 scheduler 新建 session（本 crate 不持有后台状态）。
- `set_local`/`set_samples` 供会话复用；symmetric 下所有自动重打由 edge 禁用。

## 平台约束

portable core：std-only、无平台相关代码、无系统调用；`portable = true`。
时间由注入的 `PunchClock` 提供（生产 `SystemPunchClock` 在 wireup）。

## Deletion Test

删除本 crate 后：候选模型、信令编解码、方向门控与有界预测、单一总预算打洞状态机
全部消失；`nexus-nat-wireup` 无法把打洞编排接到 fabric driver，AC-3/4a/4b/5/6/15
的生产路径无实现。没有本 crate 的等价替代（`HolePuncher` 与 `select_path` 已退役且
禁止恢复），故它是必要模块而非包装层。
