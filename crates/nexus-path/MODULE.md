# MODULE.md — nexus-path

## Responsibility

路径层：回答"到对端的包，现在走哪条路"。

管理候选路径（直连 → Mesh 转发 → TURN → 代理出口），通过主动探测 +
被动统计给每条路径打分，按分数选择当前最优路径，在路径失效或显著劣化时
切换。切换时通知会话层（`nexus-fabric`）更换 UDP socket，利用其被动迁移
机制保证连接不中断。

## Non-Responsibilities

- 不做 QUIC 传输（`nexus-fabric` 的职责）。
- 不做 NAT 打洞的具体协议（由物理传输层或独立模块提供；路径层只消费"可用地址"）。
- 不做 TURN 协议本身（P0 用 mock/接口；真实互操作后置）。
- 不做多路径并发（S1 单活跃路径不变；竞速仅用于建连期选出首条路径，见 R1）。
- 不做互联网出口的用户规则决策（§11 规则引擎的作用域，见 DESIGN.md §5）。
- 趋势降权（预测第 2 层）、历史模式（第 3 层）后置；不上 ML（见 R2 诚实边界）。
- 已建连路径的抢占式迁移后置（需与 S9 切换联动，单独一期）。

## Inputs

- 候选路径列表：`CandidatePath { kind: Direct | Mesh | Turn | Proxy, local_addr, remote_addr, cost }`
- 被动统计：`PathStats { rtt_ms, loss_rate, throughput_bps }`（来自 `nexus-fabric` 的 `ConnStats` 或探测器）
- 主动探测结果：心跳 ping/pong 的 RTT/丢包
- 配置：`PathConfig { hysteresis_db, switch_hold_ms, probe_interval_ms, ewma_alpha }`

## Outputs

- 当前最优路径：`current_path() -> Option<CandidatePath>`
- 路径切换事件：`PathEvent::Switched { from, to, reason }`
- 路径分数：`score(path) -> f64`（供诊断）

## Allowed Dependencies

- `std` only（零 Tokio，与 `nexus-fabric` 一致）
- `nexus-fabric`（仅用于类型：`PeerId`；不依赖其内部实现）

## Forbidden Dependencies

- `tokio`, `async-std`, 任何 async runtime
- `nexus-discovery`（Mesh 转发复用 FIB，但路径层通过 trait 抽象，不直接依赖；
  具体见 §Deletion Test）
- 平台特有 API（保持 portable core 纯净）

## Invariants

**S1（单活跃路径）**：任意时刻，对单个对端只有一条活跃路径。P0 不做多路径并发。

**S2（切换不丢连接）**：路径切换时，会话层连接（CID）不变。路径层只换
socket，`nexus-fabric` 的被动迁移保证流不中断。

**S3（分数单调性）**：相同网络条件下，成本更低的路径分数不低于成本更高的
（直连 > Mesh > TURN > 代理，同等质量下）。

**S4（hysteresis）**：新路径分数必须优于当前路径 `hysteresis_pct`（相对比例，
默认 0.20 即 20%）且持续 `switch_hold_ms`（默认 3000ms）才切换，防止抖动。
相对门限（非绝对分差），可配置。2026-09-30 requirement-change：将绝对分差
改为相对比例（用户裁决选 A）；`product.fabric-path-basic` 的劣化强度同步
加强（加入丢包）以保留"严重劣化触发切换"意图。

**S5（粘性）**：路径未失效且分数未严重劣化时，不主动切换（连接级 pinning）。

**S6（失效切换）**：活跃路径连续 `max_missed_probes` 次探测无响应，立即切换
到次优路径，不等待 hysteresis。

**S7（诚实分数）**：没有探测数据的路径分数标记为 `unknown`，不参与选优；
不编造分数。

**S8（成本可见）**：每条路径的 `cost`（中继带宽、蜂窝计费等）必须显式建模，
不能隐藏在分数里。

**S9（切换信号）**：`PathEvent::Switched` 是路径切换的唯一对外信号。
路径层只做决策、不触碰会话层连接（保持对 `nexus-fabric` 零实现依赖，
见 Allowed Dependencies）。应用层必须排空 `poll_event()` 并驱动会话层
执行切换；不排空则切换不生效。`remove_candidate` 移除活跃路径时，
若有备选候选，必须发出 `Switched`（S6 的事件形式）。

**R1（staggered 竞速）**：`race_connect(candidates, connector, budget)` 按偏好
排序（`PathKind` 序 then `cost` 升序）依次尝试建连。首候选先发；
`stagger_delay_ms`（默认 200ms）内未成功则启动下一候选（最多
`max_parallel`（默认 2）个并行尝试）。首个成功者胜出，其余协作取消；
`total_timeout_ms`（默认 5000ms）超限返回 `io::ErrorKind::TimedOut`。
空候选列表返回 `InvalidInput`。

**R2（EWMA 实时预测）**：`Ewma` 类型维护 per-path 指数加权移动平均
（`alpha` 可配置，默认 0.3，钳位到 (0, 1]）。`on_stats()` 喂入 RTT/丢包/
吞吐样本，`score()` 返回 EWMA 平滑值；无样本时 `score()` 返回 `None`
（unknown，S7）。预测是打分的输入，不是独立模块（DESIGN §4.6）。
趋势降权（第 2 层）、历史模式（第 3 层）后置，不上 ML。

**R3（hysteresis 相对门限）**：见 S4（2026-09-30 起为相对 20% + 持续 3s，
均可配置）。防抖动；连接级粘性（S5）不变。

**R4（竞速可观测）**：`RaceOutcome` 携带 `attempts: u32`（实际启动的尝试数，
`≤ max_parallel`）与 `wasted_bytes: u64`（非获胜路径上已完成尝试所消耗的
字节数；胜出时刻仍在进行的尝试不计入——无法观测其最终字节数，诚实省略）。

**R5（sync 竞速）**：竞速使用 std 线程（`thread::spawn` + `mpsc`），零 tokio、
零 async runtime。`race_connect` 是阻塞调用。`PathConnector::connect` 必须
协作响应 `cancel: &AtomicBool`（定期检查、及时返回）；胜出/超时后 racer
置位 `cancel` 并 `join` 所有尝试线程。不遵守 cancel 约定的 connector
可能导致 `join` 阻塞——这是 connector 的 bug，不是 racer 的。

**R6（语义守恒）**：S1–S9 不变；`score()` 无样本时返回 `None`（S7）；
`on_stats()` 的 EWMA 更新语义不变；所有既有单测必须通过。新增 API
不得改变既有公共 API 的行为。

## Side Effects

- 后台探测线程（owner：`PathManager`，Drop 时 join）。
- UDP 探测包收发（轻量心跳）。

## Public API

```rust
pub struct PathManager { /* ... */ }
pub struct PathConfig {
    /// Challenger must beat active by this relative margin (e.g. 0.20 = 20%).
    pub hysteresis_pct: f64,       // default 0.20 (was hysteresis_db, absolute)
    pub switch_hold_ms: u64,       // default 3000 (was 2000)
    pub probe_interval_ms: u64,    // default 5000
    pub ewma_alpha: f64,           // default 0.3
    pub max_missed_probes: u32,    // default 3
    pub race_budget: RaceBudget,   // default RaceBudget::default()
}
pub enum PathKind { Direct, Mesh, Turn, Proxy }
pub struct CandidatePath {
    pub kind: PathKind,
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub cost: f64,
}
pub struct PathStats {
    pub rtt_ms: Option<u64>,
    pub loss_rate: Option<f64>,
    pub throughput_bps: Option<u64>,
}
pub enum PathEvent { Switched { from: CandidatePath, to: CandidatePath, reason: SwitchReason } }

// --- Racing (R1/R4/R5) ---
pub struct RaceBudget {
    pub stagger_delay_ms: u64,  // default 200
    pub max_parallel: usize,    // default 2
    pub total_timeout_ms: u64,  // default 5000
}
pub trait PathConnector: Send + Sync {
    /// Attempt connectivity over `path`. Return bytes sent on success.
    /// Must check `cancel` periodically and return promptly when set.
    fn connect(&self, path: &CandidatePath, cancel: &AtomicBool) -> io::Result<u64>;
}
pub struct RaceOutcome {
    pub winner: CandidatePath,
    pub attempts: u32,
    pub wasted_bytes: u64,
    pub elapsed_ms: u64,
}
pub fn race_connect(
    candidates: &[CandidatePath],
    connector: &dyn PathConnector,
    budget: &RaceBudget,
) -> io::Result<RaceOutcome>;

// --- EWMA prediction (R2) ---
pub struct Ewma { /* alpha, value: Option<f64> */ }
impl Ewma {
    pub fn new(alpha: f64) -> Self;
    /// Feed one instantaneous score sample; returns the updated smoothed value.
    pub fn update(&mut self, sample: f64) -> f64;
    /// Current smoothed value; None = no samples yet (S7 unknown).
    pub fn value(&self) -> Option<f64>;
}

impl PathManager {
    pub fn new(config: PathConfig) -> Self;
    pub fn add_candidate(&mut self, path: CandidatePath);
    pub fn remove_candidate(&mut self, remote: &SocketAddr);
    pub fn current_path(&self) -> Option<CandidatePath>;
    pub fn on_stats(&mut self, remote: &SocketAddr, stats: PathStats);
    pub fn poll_event(&self) -> Option<PathEvent>;
    /// EWMA-smoothed score (R2); None = unknown (S7).
    pub fn score(&self, remote: &SocketAddr) -> Option<f64>;
}
```

**Breaking changes (2026-09-30 requirement-change)**:
- `PathConfig::hysteresis_db: f64` (absolute) → `hysteresis_pct: f64` (relative, default 0.20).
- `PathConfig::switch_hold_ms` default 2000 → 3000.
- `PathConfig` gains `race_budget: RaceBudget` field.
- All struct-literal constructions of `PathConfig` must be updated.

## Verification

- E4: `product.fabric-path-basic`（打分选优、hysteresis；2026-09-30 起劣化
  加入 30% 丢包以匹配相对 20% 门限，意图"严重劣化触发切换"不变）
- E4: `product.fabric-path-roam`（路径失效切换不断流）
- E4: `product.path-race`（R1：staggered 竞速选中快路径，`attempts ≤ 2`）
- E4: `product.path-predict-ewma`（R2：RTT 爬升序列分数单调下降）
- 单元测试：分数计算、EWMA、hysteresis 边界、unknown 处理、竞速（fake connector）、
  预算 enforcement、取消语义

## Performance Budget

- 探测包：每路径每 `probe_interval_ms`（默认 5s）1 个心跳，可忽略。
- 打分计算：O(候选路径数)，内存操作，无 I/O。

## Observability

- `score(path)` 可查询（诊断）。
- `PathEvent::Switched` 带原因（`BetterScore` / `PathFailed` / `PathAdded`）。

## Recovery Semantics

- `PathManager` Drop 时停止探测线程（join）。
- 候选路径清空时，`current_path()` 返回 `None`（调用方处理）。

## Platform Constraints

- 纯 std，无平台特有代码。
- 移动端：P0 不实现 radio 感知（远期），但 `probe_interval_ms` 可配置。

## Deletion Test

**问题**：如果删除 `nexus-path` 这个抽象，让 `nexus-fabric` 直接写死"用第一个可用的 socket"，会破坏哪个已存在的独立变化维度？

**回答**：路径选择策略（何时切换、如何打分、hysteresis 参数）与传输机制（QUIC、加密、流）是独立变化的。运营商网络策略调整（如"蜂窝下优先 WiFi"、"TURN 成本上调"）不应要求改动传输层代码。删除该抽象会导致策略变化污染传输层，违反关注点分离。

**反例**：如果未来只有一种路径（纯直连），则该抽象可删除。但 P0 已有四级回退，抽象成立。
