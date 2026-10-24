# NAT 穿透打洞冻结合同（Contract-First）

版本：v1.1 FROZEN（2026-10-24）
设计基线：`docs/foundation/NAT-TRAVERSAL-DESIGN.md` v0.1（D1–D6 已拍板）
**Contract hash：`f17a0f178a9e379c`**（本文件去掉本行后 sha256 前 16 hex）
状态：冻结。实现轨道不得修改本文件；只有合同必须变化时停下报告。

## 变更记录（v1.0 → v1.1）

- v1.0 canonical hash `6ab671a04d061b16`；v1.1 canonical hash 见文件头。
  口径不变：去掉 `**Contract hash…**` 行后的 sha256 前 16 hex（v1.0 已实证）。
- 变更动因（spec v1.1 `48c9876cb0d49cf4c8f0affed6a36d65`，based_on `0539169`）：
  1. 候选 provenance 与 TURN 诊断（P1）；
  2. 信令 v2 + 预测提示 + 编码上限 16（P2）；
  3. 样本 provenance 与预测硬化（P3）；
  4. 单一总预算 + 注入时钟 + 方向修正（P4）；
  5. 竞速改为 `PathManager` 唯一实现（P5 SUPERSEDED）；
  6. 旧 `HolePuncher` 已删除（P6）；
  7. `PunchStats` 12 字段 + per-peer registry（P7）；
  8. E4 语义改为「CID 可变、分块不丢块」。
- 旧证据全部 STALE，登记于 `docs/foundation/NAT-TRAVERSAL-STALE.md`；本 run 必须
  gap-first 重跑 Red Evidence（`based_on=0539169`，`contract=<本文件 hash>`）。
- requirement-change 语义：阶段 B 不得修改 A10 冻结的期望值/断言，
  只允许为适配目标签名修改调用点（断言字面不变、diff 入证据）。
  期望本身错误 → 停止实现 → requirement-change → 重写 Red Evidence → 新合同 hash。
  禁止静默修改。

## STALE 清单（v1.0 时代证据，全部不再有效）

1. 旧 P4 签名测试（`PunchSession::new` 无 clock/samples）→ STALE，见 P4 v1.1。
2. 旧 P2「v1/v2 混合容错」测试 → STALE；v1.1 显式不兼容（两个入口各只收一个版本）。
3. 旧 P5 `select_path` 测试/断言 → STALE；P5 SUPERSEDED，实现已删除且禁止恢复。
4. 旧 P6 `#[deprecated]` 测试 → STALE；v1.1 已删除旧 `HolePuncher`，禁止恢复。
5. 旧 E4「CID 不变」断言 → STALE；v1.1 为「CID 可变 + 分块不丢块」。
6. wireup MODULE「fabric 零改动」→ STALE；v1.1 允许 additive STUN tap / `shared()`。
7. design §3/§5/§7 旧措辞 → STALE；按 C-1/C-2/C-23/C-25/C-26 修正。
8. `0539169` 上旧的通过证据（若断言旧行为）→ STALE；本 run 必须 gap-first 重跑。

## 0. 范围与布局

> **历史基线（v1.0 原文，保留供追溯）**：新增 crate `nexus-nat-traversal`
> （std-only portable core，零新依赖，沿用 `nexus-path` 的注入 trait 模式；
> 组合根接线由 coordinator 在合并时做，各轨道不得碰 `driver.rs` / `nexusd`）。
>
> **v1.1 生效口径**：上述「各轨道不得碰 driver.rs / nexusd」是 **v1.0 轨道时代的
> 历史基线**。v1.1 起本 run 承担**组合根接线**：`apps/nexusd`、`crates/nexus-fabric`、
> `crates/nexus-nat-wireup` 的 **additive** 改动由本 run 负责（C-10/C-24）。
> additive = 不改变既有 QUIC/`on_udp` 行为、不新增第二身份源、不删除既有公开 API
> （除非合同明确要求退役）。

```text
crates/nexus-nat-traversal/
  Cargo.toml                  # name/version/edition/license.workspace；[dependencies] 为空
  src/lib.rs                  # PunchSession 状态机 + 注入 traits + PunchConfig + PunchClock
  src/candidate.rs            # PunchCandidate / LocalCandidates / punch_targets
  src/signal.rs               # PunchOffer/PunchAnswer 手写二进制编解码（v1/v2）
  src/predict.rs              # 可预测性检测 + 有界 spray 计划
```

`NatType` 复用 `nexus-connectivity::nat::NatType`（已有，不得重定义）。
`nexus-nat-traversal` 为 `portable=true`（policy 同步，C-11）。
`src/race.rs` 与 `select_path` 已删除（P5 SUPERSEDED），不得恢复。

## P1 候选地址

```rust
pub enum CandidateKind { Host, Srflx, Relay }
pub struct PunchCandidate { pub addr: SocketAddr, pub kind: CandidateKind }
pub struct LocalCandidates {
    pub host: Vec<SocketAddr>,          // 本机各接口地址（可空；永不含 unspecified）
    pub srflx: Option<SocketAddr>,      // authoritative 的公网映射（优先）
    pub srflx_stun: Option<SocketAddr>, // STUN 自测（校验/诊断）
    pub srflx_turn: Option<SocketAddr>, // TURN Allocate 的 XOR-MAPPED（诊断）
    pub nat_type: NatType,
}
impl LocalCandidates {
    pub fn has_punchable(&self) -> bool;
    pub fn ordered(&self) -> Vec<PunchCandidate>;
    pub fn authoritative_srflx(&self) -> Option<SocketAddr>;
}
pub fn punch_targets(cands: &[PunchCandidate]) -> Vec<SocketAddr>;
```

- 至少 1 个候选（srflx 或 host），否则 `PunchFailReason::NoCandidates`。
- 排序：Srflx > Host；Relay 候选不参与打洞（已是中继）。
- `ordered()` 只读 `srflx`/`srflx_stun`/`host`，**不读** `srflx_turn`。
- **same-socket 规则（冻结）**：只有当 TURN allocation 与打洞 socket 是**同一个
  socket**（`turn_same_socket == true`）**且** NAT 类型为 cone 时，才把
  `srflx_turn` 复制到 `srflx`（authoritative）；否则 `srflx_turn` **只作诊断**，
  绝不进入 `ordered()`/`punch_targets()`。

## P2 信令编解码

```rust
pub const SIGNAL_VERSION: u8 = 2;
pub const MAX_CANDIDATES: usize = 16;

pub struct PredictionHint { pub base_port: u16, pub delta: i32, pub samples: u8 }

pub struct PunchOffer {
    pub version: u8,
    pub nonce: u64,
    pub candidates: Vec<PunchCandidate>, // 上限 16
    pub nat_type: NatType,
    pub start_at_ms: u64,
    pub prediction: Option<PredictionHint>,
}
pub struct PunchAnswer {
    pub version: u8,
    pub nonce: u64,
    pub candidates: Vec<PunchCandidate>,
    pub nat_type: NatType,
    pub prediction: Option<PredictionHint>,
}
pub enum SignalError { Version, TooMany, Truncated, BadNatType, BadKind, BadFamily, BadPrediction, TrailingBytes }

pub fn encode_offer(o: &PunchOffer) -> Vec<u8>;              // 只产 version=2
pub fn decode_offer(b: &[u8]) -> Result<PunchOffer, SignalError>; // 只收 version=2，1/3 → Version
pub fn encode_answer(a: &PunchAnswer) -> Vec<u8>;            // 只产 version=2
pub fn decode_answer(b: &[u8]) -> Result<PunchAnswer, SignalError>;
pub fn encode_offer_v1(o: &PunchOffer) -> Vec<u8>;           // v1 布局，prediction 丢弃
pub fn decode_offer_v1(b: &[u8]) -> Result<PunchOffer, SignalError>; // 只收 version=1
pub fn encode_answer_v1(a: &PunchAnswer) -> Vec<u8>;
pub fn decode_answer_v1(b: &[u8]) -> Result<PunchAnswer, SignalError>;
```

- v1 线格式（冻结兼容，逐字节不变）：`version:u8` + `nonce:u64 BE` + `nat_type:u8`
  + `start_at_ms:u64 BE`（answer 无）+ `n:u8` + 每候选 `kind:u8` + `family:u8`
  + ip bytes（v4=4B / v6=16B）+ `port:u16 BE`。
- v2 线格式：在 v1 字段之后追加 `has_prediction:u8`；为 1 时追加
  `base_port:u16 BE` + `delta:i32 BE` + `samples:u8`。`has_prediction` 非 0/1
  → `BadPrediction`；`samples < 3` → `BadPrediction`。
- 版本边界（冻结，显式不兼容）：v2 入口只收 2、v1 入口只收 1；版本 3 或未知
  → `Version`。不做 v1/v2 混合容错。
- 编码 >16 个候选：截断到 16 并 `debug_assert!`（生产不崩塌）；解码 >16 → `TooMany`。
- 往返一致性：`decode(encode(x)) == x`（candidates 顺序不变、prediction 逐字段相等）。

## P3 可预测性检测与预测计划

```rust
pub struct PortSample {
    pub port: u16,
    pub at_ms: u64,
    pub target: SocketAddr,        // 该样本对应的 STUN 服务器地址
    pub observed_from: SocketAddr, // 观测该样本的本地 socket（必须 == punch driver local_addr）
}
pub enum Predictability { Predictable { base_port: u16, delta: i32 }, Unpredictable }
pub struct SprayPlan { pub target_ip: IpAddr, pub ports: Vec<u16> }
pub enum PredictionPlan {
    Spray(SprayPlan),
    MappingProbe { target: SocketAddr, count: u8, interval_ms: u64 },
    None,
}
pub trait PunchPredictor: Send + Sync {
    fn assess(&self, samples: &[PortSample]) -> Predictability;
    fn plan(&self, p: &Predictability, target_ip: IpAddr, k: u8) -> Option<SprayPlan>;
}
pub struct DefaultPredictor;
pub struct NoopPredictor;
```

- 判定规则（冻结）：取最近 `prediction_samples`（3..=8）个样本；丢弃 `port == 0`；
  丢弃年龄 > `max_sample_age`（默认 900s）；`target` 去重后必须 ≥2；
  连续端口差 Δ 全相等且 `abs(Δ) <= max_stable_delta`（默认 8）→
  `Predictable{base_port=最新样本端口, delta=Δ}`；否则 `Unpredictable`。
- same-socket：`observed_from` 必须一致（组合根保证等于 driver `local_addr`）；
  不一致的样本不参与判定。
- `plan` 只对 Predictable 返回 Some；`ports` 以 `base+delta` 为中心向两侧扩展
  K 个，`ports.len() <= 2*K+1`，u16 回绕按 wrapping 处理；端口 0 跳过。
- `PredictionPlan::MappingProbe` 由 `run()` 在「本端 Symmetric、对端 cone」时使用。

## P4 打洞编排状态机

```rust
pub trait PunchClock: Send + Sync {
    fn now_ms(&self) -> u64;                  // 单调时钟（预算/超时/限速）
    fn wall_ms(&self) -> u64;                 // 墙钟（仅 start_at/日志）
    fn sleep_until_ms(&self, deadline_ms: u64);
    fn sleep_ms(&self, ms: u64);
}

pub enum PunchPhase { Idle, OfferSent, Coordinated, Punching, Validating, Migrated, Failed(PunchFailReason) }
pub enum PunchFailReason { Timeout, UnpredictableSymmetric, NoCandidates, ChannelClosed }

pub trait PunchChannel: Send + Sync {
    fn send_offer(&self, offer: &PunchOffer) -> io::Result<()>;
    fn recv_answer(&self, timeout: Duration) -> io::Result<PunchAnswer>; // 超时 → Err(TimedOut)
}
pub trait PunchSocket: Send + Sync {
    fn send_punch(&self, target: SocketAddr, payload: &[u8]) -> io::Result<()>;
    fn await_direct(&self, timeout: Duration) -> io::Result<SocketAddr>;
}

pub struct PunchConfig {
    pub punch_timeout: Duration,          // 默认 5s
    pub coord_skew_ms: u64,               // 默认 200
    pub spray_k: u8,                      // 默认 16，上限 32
    pub spray_interval_ms: u64,           // 默认 50
    pub spray_time_budget: Duration,      // 默认 3s
    pub repunch_interval: Duration,       // 默认 300s
    pub repunch_jitter: Duration,         // 默认 0
    pub prediction_samples: u8,           // 默认 3，范围 3..=8
    pub max_sample_age: Duration,         // 默认 900s
    pub max_stable_delta: u16,            // 默认 8
    pub mapping_probe_count: u8,          // 默认 3
    pub mapping_probe_interval_ms: u64,   // 默认 50
}
impl Default for PunchConfig { fn default() -> Self; }
impl PunchConfig { pub fn validate(&self) -> Result<(), PunchConfigError>; }
pub enum PunchConfigError {
    OutOfRange { field: &'static str, value: i64, min: i64, max: i64 },
    InvalidCombination { field: &'static str, reason: &'static str },
}

pub struct PunchSession { /* peer, local, samples, config, channel, socket, predictor, clock, .. */ }
impl PunchSession {
    pub fn new(peer: PeerId, local: LocalCandidates, remote_nat: NatType,
               samples: Vec<PortSample>, config: PunchConfig,
               channel: Arc<dyn PunchChannel>, socket: Arc<dyn PunchSocket>,
               predictor: Arc<dyn PunchPredictor>, clock: Arc<dyn PunchClock>) -> Self;
    pub fn run(&mut self) -> PunchResult;
    pub fn phase(&self) -> PunchPhase;
    pub fn peer(&self) -> PeerId;
    pub fn stats(&self) -> PunchStats;
    pub fn set_local(&mut self, local: LocalCandidates, samples: Vec<PortSample>);
    pub fn set_samples(&mut self, samples: Vec<PortSample>);
}
```

- 状态转换（冻结）：Idle →(send offer) OfferSent →(answer nonce 匹配)
  Coordinated →(协同等待结束) Punching →(await_direct 成功) Validating
  →(确认) Migrated；任一步超时/失败 → Failed(reason)。
- nonce 不匹配的 answer 必须丢弃（防串扰），状态机不推进。
- **单一总预算（冻结）**：`deadline = clock.now_ms() + punch_timeout` 在 `run()`
  入口起算；`recv_answer`/协同等待/spray 等待/`await_direct` 全部消费同一
  `remaining(deadline)`，不得各自重新起算 5s。
- `send_punch` 的 payload：**production 忽略 payload**，真正打洞包是
  `Driver::connect` 发出的 QUIC Initial；payload 只是测试标记。禁止明文 magic
  协议作为生产握手。
- `Migrated{addr}` 语义：**新直连**握手完成的地址，不是「迁移原连接」；
  组合根负责登记/选路。CID 可变（新连接有新 CID）。
- 方向与门控（冻结，C-21）：
  - 先 `NoCandidates`；
  - Offer 的 `prediction` 由本端 samples + NAT 类型决定；
  - `local==Symmetric && remote==Symmetric` → `UnpredictableSymmetric`（零发送）；
  - `local==cone && remote==Symmetric`：无远端 hint → `UnpredictableSymmetric`
    （零包含 probe）；有 hint → 只对**单一 reflexive IP** spray
    `[base+Δ-K, base+Δ+K]`，50ms 限速，`min(spray_time_budget, remaining)`；
    超时未发目标计 `spray_skipped`；
  - `local==Symmetric && remote==cone`：向对端已知 reflexive 发
    `mapping_probe_count` 个 probe（`mapping_probe_interval_ms`），**不 spray**；
  - 其他：对 `punch_targets` 常规打洞。

## P5 三类路径竞速（SUPERSEDED）

- **本节 SUPERSEDED（2026-10-02 D2）**。`race::select_path` 实现已删除且
  **不得恢复**；`nexus-path::{PathManager, PathLink}` 是唯一竞速实现
  （20% 相对门限 + 3s 保持；boost 10% + 1s）。
- `PunchRaceFeed` 降为**可观测钩子**：打洞成功后只上报候选/计数/日志，
  **不参与选路决策**；`PathLink` 是唯一真实登记点（C-13）。
- `RaceClass` 枚举保留（种类映射到 `nexus-path::PathKind`）。

## P6 旧 HolePuncher 退役

- `nexus-connectivity/src/nat.rs` 的 `HolePuncher::{punch, respond_punch,
  measure_rtt}` **已删除**（2026-10-18），**禁止恢复**；现状代码不得再引用。
- 退役面**不含** tunnel 级 `ph/pa` 协议（OQ-7），其语义保持不动。

## P7 可观测

```rust
pub struct PunchStats {
    pub attempts: u64,
    pub migrated: u64,
    pub failed_timeout: u64,
    pub failed_unpredictable: u64,
    pub failed_no_candidates: u64,
    pub failed_channel_closed: u64,
    pub spray_sends: u64,
    pub spray_skipped: u64,
    pub mapping_probe_sends: u64,
    pub prediction_hints_sent: u64,
    pub prediction_hints_recv: u64,
    pub last_phase: PunchPhase,
}
impl PunchFailReason { pub fn as_str(&self) -> &'static str; }
impl PunchPhase { pub fn as_str(&self) -> &'static str; }
```

- 计数语义：见 spec §14.1（`spray_sends`/`spray_skipped`/`mapping_probe_sends`/
  `prediction_hints_sent`/`prediction_hints_recv` 的产生点写死在 core）。
- per-session 统计经 `PunchSession::stats()` 出口；per-peer 聚合在
  `nexus-nat-wireup::PunchManager` 的 registry 完成（session 结束累加，
  `last_phase` 覆盖不累加）。registry 不是第二套并行全局计数。
- LocalAPI 展示由组合根接（§11.2）。

## E4 场景（冻结）

- `product.nat-punch-relay-first`：netns 双节点，各经 iptables MASQUERADE
  （cone NAT），TURN 中继先建连可用 → 后台打洞 → `Migrated` → 会话层选路到
  新直连；**CID 可变**；「不断流」= 分块不丢块、逻辑会话不重建。
- `product.nat-punch-symmetric`：一端 symmetric（SNAT 顺序分配模拟），
  有界 spray 成功 → `Migrated`。
- `product.nat-punch-unpredictable`：一端 symmetric 随机端口 →
  快速 `StayedOnRelay(UnpredictableSymmetric)`，无 spray 风暴，中继不断流。
- `product.nat-punch-race`：direct RTT 被人工抬高 → **不切换**，流量留在
  peer-relay/TURN（`select_path` 断言已删除，改用 `PathManager` 行为）。
- 双方**都发起**打洞（不再用 PeerId 大小提前 return）；tie-break 由 wireup 收敛。
- 生产触发：`RelayConnProvider` 的 `on_relay_available` → `on_relay_connected`；
  harness 不得直调 `punch_peer`/`on_relay_connected`。

## Red Evidence（各轨道开工前必须）

每个 G 先写测试/场景并在 `0539169` 实现上确认 FAIL（exit != 0），再实现：
`g1_stun_samples_share_punch_socket`、`g2_turn_bound_and_diagnostic`、
`g3_host_candidates_enumerated`、`g4_session_receives_samples_and_clock`、
`g5_no_system_time_in_core`、`g6_single_total_budget`、
`g7_cone_sprays_symmetric_ports`、`g8_signal_v2_prediction_hint_roundtrip`、
`g9_both_sides_initiate`、`g10_repunch_periodic_300s`、`g11_localapi_nat_route`、
`g12_punch_config_defaults`、`g13_relay_provider_triggers_punch`、
`g14_fabric_stun_tap_routes_response`、`g15_all_attempts_fail_is_timeout`、
`g16_peer_status_fields`、`g17_contract_v11_present`、
`g18_encode_candidate_cap_16`。
旧轨道时代的 12 个测试名已 STALE（见 STALE 清单）。

## 诚实边界

- 端口预测只在 Δ 稳定时尝试；随机分配场景明确走 relay。
- 打洞成功率是统计量；E4 证明机制，不承诺百分比。
- spray 行为如实记录（目标单一 IP、时间盒 3s、限速），文档声明 IDS 风险。
- 「不断流」不承诺在途 stream 迁移；打洞产生**新连接**，会话层按块选路。

## 轨道划分（历史基线，v1.1 起不再并行）

> 以下为 v1.0 轨道时代的**历史基线**，供追溯；v1.1 由本 run 统一承担 core、
> wireup、fabric additive tap、nexusd 组合根接线与 E4。

- Track A `feature/nat-punch-core`：crate 骨架 + candidate.rs +
  signal.rs + lib.rs（状态机 + trait 定义 + Noop 实现）+ P7。
- Track B `feature/nat-port-predict`：predict.rs。
- Track C `feature/nat-race`：race.rs（已随 P5 SUPERSEDED 删除）。
- driver/nexusd 接线、合并、综合 E4、独立 Review、full verify：
  v1.1 起由本 run 承担（additive，C-10/C-24）。
