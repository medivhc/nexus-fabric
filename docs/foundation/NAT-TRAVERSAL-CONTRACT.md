# NAT 穿透打洞冻结合同（Contract-First）

版本：v1.0 FROZEN（2026-10-02）
设计基线：`docs/foundation/NAT-TRAVERSAL-DESIGN.md` v0.1（D1–D6 已拍板）
**Contract hash：`6ab671a04d061b16`**（本文件 sha256 前 16 hex）
状态：冻结。实现轨道不得修改本文件；只有合同必须变化时停下报告。

## 0. 范围与布局

新增 crate `nexus-nat-traversal`（std-only portable core，零新依赖，
沿用 `nexus-path` 的注入 trait 模式；组合根接线由 coordinator 在合并时做，
各轨道不得碰 `driver.rs` / `nexusd`）：

```text
crates/nexus-nat-traversal/
  Cargo.toml                  # name/version/edition/license.workspace；[dependencies] 为空
  src/lib.rs                  # PunchSession 状态机 + 注入 traits + PunchConfig
  src/candidate.rs            # PunchCandidate / LocalCandidates
  src/signal.rs               # PunchOffer/PunchAnswer 手写二进制编解码
  src/predict.rs              # 可预测性检测 + 有界 spray 计划（Track B 实现）
  src/race.rs                 # 三类路径竞速选择（Track C 实现）
```

`NatType` 复用 `nexus-connectivity::nat::NatType`（已有，不得重定义）。

## P1 候选地址（Track A）

```rust
pub enum CandidateKind { Host, Srflx, Relay }
pub struct PunchCandidate { pub addr: SocketAddr, pub kind: CandidateKind }
pub struct LocalCandidates {
    pub host: Vec<SocketAddr>,        // 本机各接口地址（可空）
    pub srflx: Option<SocketAddr>,    // TURN Allocate 的 XOR-MAPPED（优先）
    pub srflx_stun: Option<SocketAddr>, // StunClient 自测（校验用，可空）
    pub nat_type: NatType,
}
```

- 至少 1 个候选（srflx 或 host），否则 `PunchFailReason::NoCandidates`。
- 排序：Srflx > Host；Relay 候选不参与打洞（已是中继）。

## P2 信令编解码（Track A）

```rust
pub struct PunchOffer {
    pub version: u8,              // =1，解码时 version != 1 → Err(Version)
    pub nonce: u64,
    pub candidates: Vec<PunchCandidate>, // 上限 16，超限 → Err(TooMany)
    pub nat_type: NatType,        // 发送方自测类型
    pub start_at_ms: u64,         // 发送方建议开打时间（unix ms）
}
pub struct PunchAnswer {
    pub version: u8,              // =1
    pub nonce: u64,               // 必须回显 offer 的 nonce，否则接收方丢弃
    pub candidates: Vec<PunchCandidate>,
    pub nat_type: NatType,
}
pub fn encode_offer(o: &PunchOffer) -> Vec<u8>;
pub fn decode_offer(b: &[u8]) -> Result<PunchOffer, SignalError>;
pub fn encode_answer(a: &PunchAnswer) -> Vec<u8>;
pub fn decode_answer(b: &[u8]) -> Result<PunchAnswer, SignalError>;
```

- 手写编解码：`version:u8` + `nonce:u64 BE` + `nat_type:u8`
  + `start_at_ms:u64 BE` + `n:u8` + 每候选 `kind:u8` + `ip bytes`
  （v4=4B/v6=16B + 1B family tag）+ `port:u16 BE`。
- 往返一致性：`decode(encode(x)) == x`（candidates 顺序不变）。

## P3 可预测性检测（Track B 实现，trait 由 Track A 定义）

```rust
pub struct PortSample { pub port: u16, pub at_ms: u64 }
pub enum Predictability {
    Predictable { base_port: u16, delta: i32 },
    Unpredictable,
}
pub struct SprayPlan { pub target_ip: IpAddr, pub ports: Vec<u16> }
pub trait PunchPredictor: Send + Sync {
    /// 至少 3 个样本；Δ 不稳定 → Unpredictable。
    fn assess(&self, samples: &[PortSample]) -> Predictability;
    /// 有界：ports.len() <= 2*K+1，K = config.spray_k（默认 16，上限 32）。
    fn plan(&self, p: &Predictability, target_ip: IpAddr, k: u8) -> Option<SprayPlan>;
}
```

- 判定规则（冻结）：连续样本两两 Δ 相等 → Predictable{base=last, delta}；
  否则 Unpredictable。样本 <3 → Unpredictable。
- `plan` 只对 Predictable 返回 Some；`ports` 以 `base+delta` 为中心
  向两侧扩展 K 个，u16 回绕按 wrapping 处理。
- Track A 在 lib.rs 中只依赖 `dyn PunchPredictor`，自带
  `NoopPredictor`（恒返回 Unpredictable）用于自身测试。

## P4 打洞编排状态机（Track A）

```rust
pub enum PunchPhase { Idle, OfferSent, Coordinated, Punching, Validating, Migrated, Failed(PunchFailReason) }
pub enum PunchFailReason { Timeout, UnpredictableSymmetric, NoCandidates, ChannelClosed }

pub trait PunchChannel: Send + Sync {
    fn send_offer(&self, offer: &PunchOffer) -> io::Result<()>;
    fn recv_answer(&self, timeout: Duration) -> io::Result<PunchAnswer>; // 超时 → Err(TimedOut)
}
pub trait PunchSocket: Send + Sync {
    /// 从**同一** UDP socket 向目标发打洞负载（QUIC 包由组合根构造，
    /// 此处只规定"同一 socket + 目标地址"语义）。
    fn send_punch(&self, target: SocketAddr, payload: &[u8]) -> io::Result<()>;
    /// 等待对端打洞包/验证完成，超时 → Err(TimedOut)。
    fn await_direct(&self, timeout: Duration) -> io::Result<SocketAddr>;
}

pub struct PunchConfig {
    pub punch_timeout: Duration,   // 默认 5s
    pub coord_skew_ms: u64,        // 默认 200（协同开打时间窗）
    pub spray_k: u8,              // 默认 16，上限 32
    pub spray_interval_ms: u64,    // 默认 50（spray 限速）
    pub repunch_interval: Duration,// 默认 5min
}

pub enum PunchResult {
    Migrated { addr: SocketAddr },                 // 打洞成功，可迁移
    StayedOnRelay { reason: PunchFailReason },     // 留在中继
}

pub struct PunchSession { /* peer: PeerId, phase, .. */ }
impl PunchSession {
    pub fn new(peer: PeerId, local: LocalCandidates, remote_nat: NatType,
               config: PunchConfig,
               channel: Arc<dyn PunchChannel>, socket: Arc<dyn PunchSocket>,
               predictor: Arc<dyn PunchPredictor>) -> Self;
    /// 阻塞执行完整编排：offer → answer → 协同开打 → 等待直连/超时。
    /// 任一端 Symmetric 且 predictor 不可预测 → 直接 StayedOnRelay(UnpredictableSymmetric)。
    pub fn run(&mut self) -> PunchResult;
    pub fn phase(&self) -> PunchPhase;
}
```

- 状态转换（冻结）：Idle →(send offer) OfferSent →(answer nonce 匹配)
  Coordinated →(start_at 到达) Punching →(await_direct 成功) Validating
  →(调用方确认迁移) Migrated；任一步超时/失败 → Failed(reason)。
- nonce 不匹配的 answer 必须丢弃（防串扰），状态机不推进。
- `run` 不直接做 QUIC 迁移：返回 `Migrated{addr}` 由组合根
  驱动 driver 路径迁移（coordinator 合并任务）。

## P5 三类路径竞速（Track C 实现）

```rust
pub enum RaceClass { DirectP2P, TurnRelay, PeerRelay }
pub struct ScoredPath {
    pub class: RaceClass,
    pub rtt_ms: u64,
    pub loss_01: f64,   // 0.0–1.0
}
/// 复用 nexus-path 的 hysteresis 语义：只有 challenger 比 current
/// 好出门限才切换。默认门限 20% + 3s；boost=true 时 10% + 1s。
/// score = rtt_ms as f64 * (1.0 + loss_01 * 10.0)（丢包加权，冻结公式）。
pub fn select_path(paths: &[ScoredPath], current: RaceClass, current_since_ms: u64,
                   now_ms: u64, boost: bool) -> RaceClass;
pub trait PunchRaceFeed: Send + Sync {
    /// 打洞成功后向路径层登记 direct 候选（实现由 Track C 提供，
    /// Track A 只依赖 trait，测试用 NoopFeed）。
    fn report_direct_candidate(&self, peer: PeerId, addr: SocketAddr, rtt_ms: u64, loss_01: f64);
}
```

- 冻结语义：`select_path` 在 challenger 的 score 比 current 好
  `>=20%`（boost 10%）**且** challenger 持续占优 `>=3s`
  （boost 1s）才返回 challenger；否则返回 current。
  （`current_since_ms`/`now_ms` 由调用方提供时钟，pure function 可测。）
- 打洞成功 ≠ 自动切换：direct 只是候选之一（D3）。

## P6 旧 HolePuncher 退役

- `nexus-connectivity/src/nat.rs` 的 `HolePuncher::{punch, respond_punch,
  measure_rtt}` 标记 `#[deprecated(note = "use nexus-nat-traversal")]`，
  本期不删除（避免破坏既有测试），新代码不得调用。

## P7 可观测（各轨道配合，Track A 定义类型）

```rust
pub struct PunchStats {
    pub attempts: u64,
    pub migrated: u64,
    pub failed_timeout: u64,
    pub failed_unpredictable: u64,
    pub last_phase: PunchPhase,
}
```

- `PunchSession::stats()` 返回累计计数；LocalAPI 展示由 coordinator 合并时接。

## E4 场景（冻结）

- `product.nat-punch-relay-first`：netns 双节点，各经 iptables
  MASQUERADE（cone NAT），TURN 中继先建连可用 → 后台打洞 →
  `Migrated` → 全程 TCP 传文件不断流、CID 不变。
- `product.nat-punch-symmetric`：一端 symmetric（SNAT 顺序分配模拟），
  有界 spray 成功 → `Migrated`。
- `product.nat-punch-unpredictable`：一端 symmetric 随机端口 →
  快速 `StayedOnRelay(UnpredictableSymmetric)`，无 spray 风暴，
  中继不断流。
- `product.nat-punch-race`：direct RTT 被人工抬高 → `select_path`
  不切换，流量留在 peer-relay/TURN。

## Red Evidence（各轨道开工前必须）

每个轨道先写测试并在空实现上确认 FAIL（exit != 0），再实现：
- A：`signal_codec_roundtrip`、`nonce_mismatch_drops_answer`、
  `state_machine_happy_path`、`no_candidates_fails`。
- B：`sequential_delta_predictable`、`random_delta_unpredictable`、
  `spray_bounded_by_k`、`too_few_samples_unpredictable`。
- C：`direct_wins_when_much_better`、`no_switch_within_hysteresis`、
  `peer_relay_beats_direct`、`boost_tighter_threshold`。

## 诚实边界

- 端口预测只在 Δ 稳定时尝试；随机分配场景明确走 relay。
- 打洞成功率是统计量；E4 证明机制，不承诺百分比。
- spray 行为如实记录（目标单一 IP、时间盒 3s、限速），文档声明 IDS 风险。

## 轨道划分（防冲突）

- Track A `feature/nat-punch-core`：crate 骨架 + candidate.rs +
  signal.rs + lib.rs（状态机 + 四个 trait 定义 + Noop 实现）+ P7。
- Track B `feature/nat-port-predict`：只写 predict.rs（实现
  `PunchPredictor`），不得改 lib.rs/signal.rs/candidate.rs。
- Track C `feature/nat-race`：只写 race.rs（实现 `select_path` +
  `PunchRaceFeed`），不得改其他文件。
- driver/nexusd 接线、合并、综合 E4、独立 Review、full verify
  由 coordinator 做。
