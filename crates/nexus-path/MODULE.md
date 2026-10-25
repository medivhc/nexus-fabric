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
- 不构造任何传输 socket（F2）：直连 socket / SOCKS5 握手 / TURN 分配由组合根
  注入的 `PathConnector` 实现；`nexus-path` 只做决策（选哪级、按什么顺序试）。
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
- 路径收养事件：`PathEvent::Adopted { to }`（此前无活跃路径时收养最优已知候选；
  不是 switch，无 `from`；D4，2026-10-03）
- 路径分数：`score(path) -> f64`（供诊断）

## Allowed Dependencies

- `std` only（零 Tokio，与 `nexus-fabric` 一致）
- `nexus-fabric`（仅用于类型：`PeerId`；不依赖其内部实现）
- 不新增：F1–F6 不引入任何新依赖。代理/TURN 的配置复用发生在组合根
  （outbound 配置 → `ProxyEndpoint`/`TurnEndpoint` 的映射），
  `nexus-path` 不依赖 `nexus-outbound-*`、`nexus-proxy-transport`、
  `nexus-turn` 中任何一个。

## Forbidden Dependencies

- `tokio`, `async-std`, 任何 async runtime
- `nexus-discovery`（Mesh 转发复用 FIB，但路径层通过 trait 抽象，不直接依赖；
  具体见 §Deletion Test）
- 平台特有 API（保持 portable core 纯净）

## Invariants

**S1（单活跃路径）**：任意时刻，对单个对端只有一条活跃路径。P0 不做多路径并发。

**S2（切换不丢连接）**：分区语义，不得混用。

- **非 NAT peer**：同连接 `rebind()` 仅用于这类 peer；路径层只换 socket，
  `nexus-fabric` 的被动迁移保证流不中断（CID 不变）。
- **NAT peer**：direct 与 relay 是**两条不同 CID** 的连接；切换是 `PathLink` 的
  `ActiveConn` 翻转（`register_nat_direct` 登记新直连 → `ActiveConn` 指向它），
  **不调用 `rebind()`**。CID 变化是预期行为；「不断流」的定义是**分块不丢块、
  逻辑会话不重建**，在途 stream 不迁移。

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

**S6 补充（2026-10-03）**：已判失败的路径（`missed_probes >= max_missed_probes`）
在收到新的有效观测（清零 miss 计数）之前不参与选优；`best_candidate` 将其排除，
防止死路径凭陈旧高分被选回造成 flap。

**S7（诚实分数）**：没有探测数据的路径分数标记为 `unknown`，不参与选优；
不编造分数。

**S8（成本可见）**：每条路径的 `cost`（中继带宽、蜂窝计费等）必须显式建模，
不能隐藏在分数里。

**S9（切换信号）**：`PathEvent::Switched` 是路径切换的唯一对外信号。
路径层只做决策、不触碰会话层连接（保持对 `nexus-fabric` 零实现依赖，
见 Allowed Dependencies）。应用层必须排空 `poll_event()` 并驱动会话层
执行切换；不排空则切换不生效。`remove_candidate` 移除活跃路径时，
若有备选候选，必须发出 `Switched`（S6 的事件形式）。

**S9 补充（D4，2026-10-03）**：`active == None` 时收养最优已知候选为活跃路径，
发射 `PathEvent::Adopted { to }`（不是 switch，无 `from`）。`Switched` 仍是
from→to 切换的唯一信号；`Adopted` 覆盖 None→active 的收养。
应用层/pump 必须排空两种事件并驱动会话层执行 rebind/切换；
`PathLink::pump` 对 `Adopted` 的处理由 T3 轨道完成。

**R1（staggered 竞速）**：`race_connect(candidates, connector, budget)` 按**调用方给定
的候选顺序**依次尝试建连（2026-09-30 requirement-change：删除内部 `(PathKind, cost)`
重排；"按什么顺序尝试"是调用方——如 fallback 链 F1——的产品语义，库函数忠实执行，
不替调用方做产品决策）。首候选先发；
`stagger_delay_ms`（默认 200ms）内未成功则启动下一候选（最多
`max_parallel`（默认 2）个并行尝试）。首个成功者胜出，其余协作取消；
`total_timeout_ms`（默认 5000ms）超限返回 `io::ErrorKind::TimedOut`。
空候选列表返回 `InvalidInput`。
变更前行为（已 STALE）：按 `(PathKind, cost)` 排序，Turn 恒在 Proxy 之前；
与批准的 fallback 链顺序（F1：Direct → Proxy → Turn）冲突，故修订。

**R2（EWMA 实时预测）**：`Ewma` 类型维护 per-path 指数加权移动平均
（`alpha` 可配置，默认 0.3，钳位到 (0, 1]）。`on_stats()` 喂入 RTT/丢包/
吞吐样本，`score()` 返回 EWMA 平滑值；无样本时 `score()` 返回 `None`
（unknown，S7）。预测是打分的输入，不是独立模块（DESIGN §4.6）。
趋势降权（第 2 层）、历史模式（第 3 层）后置，不上 ML。

**R3（hysteresis 相对门限）**：见 S4（2026-09-30 起为相对 20% + 持续 3s，
均可配置）。防抖动；连接级粘性（S5）不变。

**R7（NAT 三类竞速唯一实现，D2，2026-10-02）**：`PathManager` 是 NAT
打洞后生产流量切换的唯一竞速实现（`nexus-nat-traversal/src/race.rs`
的 `select_path` 已退役删除）。Kind 映射（冻结）：
`DirectP2P`→`Direct`、`TurnRelay`→`Turn`、`PeerRelay`→`Mesh`。
冻结语义（contract `6ab671a04d061b16`）：20% 相对门限 + 3s 保持；
打洞成功只让 direct 获得参赛资格（S7：无 stats 前不参选）。
回归测试：`nat_peer_relay_beats_direct`、`nat_direct_wins_when_much_better`、
`nat_no_switch_before_hold_elapses`（由 `race.rs` 合同测试改写）。

**R4（竞速可观测）**：`RaceOutcome` 携带 `attempts: u32`（实际启动的尝试数，
`≤ max_parallel`）与 `wasted_bytes: u64`（非获胜路径上已完成尝试所消耗的
字节数；胜出时刻仍在进行的尝试不计入——无法观测其最终字节数，诚实省略）。

**R5（sync 竞速）**：竞速使用 std 线程（`thread::scope` + `mpsc`，scoped threads
允许借用 connector，无需 `'static`），零 tokio、零 async runtime。
`race_connect` 是阻塞调用。`PathConnector::connect` 必须协作响应
`cancel: &AtomicBool`（定期检查、及时返回）；胜出/超时后 racer 置位
`cancel`，scope 保证 join 所有尝试线程。不遵守 cancel 约定的 connector
可能导致 `join` 阻塞——这是 connector 的 bug，不是 racer 的。

**R6（语义守恒）**：S1–S9 不变；`score()` 无样本时返回 `None`（S7）；
`on_stats()` 的 EWMA 更新语义不变；所有既有单测必须通过。新增 API
不得改变既有公共 API 的行为。

**F1（FallbackChain）**：`FallbackConfig { proxy: Option<ProxyEndpoint>, turn: Option<TurnEndpoint> }`；
`ProxyEndpoint { server: SocketAddr }`、`TurnEndpoint { server: SocketAddr }`
为最小可移植端点类型（认证/凭据等留在 outbound 配置里，不进本 crate）。
链顺序固定 Direct → Proxy → Turn；Mesh 本期不参与（后置）。
`FallbackChain::expand(config, local, peer)` 按序展开为 `Vec<CandidatePath>`；
无配置的级别诚实跳过并计数（F4），不报错、不重试。
配置来源：组合根（`nexus-projection::PathLink` 或 app 层）从 outbound 的
`Socks5ProxyConfig` / TURN server 配置映射为端点类型；`nexus-path`
不反向依赖任何 outbound crate（保持 std-only 可移植核心，见 Allowed Dependencies）。

**F2（建连）**：`connect_with_fallback(chain, connector, budget) -> io::Result<RaceOutcome>`；
把链展开为候选列表后复用 `race_connect`（staggered、预算 enforcement、协作取消，
决策①）；胜出级别 = `outcome.winner.kind`（可观测，无需新返回类型）。
实际 dial（直连 socket / SOCKS5 握手 / TURN 分配）由注入的 `PathConnector`
实现（组合根提供）；`nexus-path` 不构造任何 socket（见 Non-Responsibilities）。
设计注：计划草案曾写 `-> (FabricConn, PathKind)`；契约细化为返回
`RaceOutcome`——构造 `FabricConn` 需要依赖 `nexus-fabric` 的实现，
违反本 crate 的可移植边界；已有 `PathLink` 组合先例（`PathManager` +
`FabricConn::rebind()` 由组合根装配）。

**F3（运行中切换）**：不新增切换逻辑。链展开的三级候选（Direct/Proxy/Turn）
作为 `CandidatePath` 接入 `PathManager` 后，复用既有打分 + S4/R3 hysteresis
+ S9 事件；应用层排空 `poll_event()` 并驱动会话层（4a 语义不变）。
回归要求：S9 事件语义零变化；`product.fabric-path-rebind` 必须通过。

**F4（诚实跳过）**：某级无配置 → 该级不进入候选列表，`skipped: Vec<PathKind>`
记录并可计数（`skipped_count(kind) -> u64`）；`connect_with_fallback`
不因跳过而报错；跳过不触发重试、不静默回退到其他语义。

**F5（可观测）**：`FallbackChain` 暴露 `attempts: u64`（建连调用次数）、
`wins(kind) -> u64`（各级胜出计数）、`current_tier: Option<PathKind>`
（最近一次成功建连的胜出级别；运行中切换仍经 `PathManager`/`PathEvent`
观测）。纯 `u64` 字段（std-only，无 metrics 依赖）；热路径无 per-packet 日志。

**F6（不破坏现有语义）**：既有单测全部通过（无修改）；`race_connect`、
`PathManager`、打分语义零改动；`FallbackConfig { proxy: None, turn: None }`
展开为 `[Direct]`，行为 ≡ 纯直连（零回归）。

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
pub enum PathEvent {
    Switched { from: CandidatePath, to: CandidatePath, reason: SwitchReason },
    /// D4 (2026-10-03): emitted when the manager adopts a candidate as the
    /// active path with no previous active path. Not a switch: no `from`.
    Adopted { to: CandidatePath },
}

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

// --- Fallback chain (F1/F2/F4/F5) ---
```rust
pub struct ProxyEndpoint { pub server: SocketAddr }   // minimal; auth stays in outbound config
pub struct TurnEndpoint { pub server: SocketAddr }     // minimal; credentials stay in TURN config
pub struct FallbackConfig {
    pub proxy: Option<ProxyEndpoint>,
    pub turn: Option<TurnEndpoint>,
}
pub struct FallbackChain { /* candidates, skipped, counters */ }
impl FallbackChain {
    /// Expand config into an ordered candidate list: Direct → Proxy → Turn.
    /// Tiers without config are skipped and counted (F4). Direct is always present.
    pub fn expand(config: &FallbackConfig, local: SocketAddr, peer: SocketAddr) -> Self;
    pub fn candidates(&self) -> &[CandidatePath];
    /// Tiers skipped due to missing config, in chain order (F4).
    pub fn skipped(&self) -> &[PathKind];
    pub fn skipped_count(&self, kind: PathKind) -> u64;
    pub fn attempts(&self) -> u64;                 // F5
    pub fn wins(&self, kind: PathKind) -> u64;     // F5
    pub fn current_tier(&self) -> Option<PathKind>; // F5: winner of last successful connect
}

/// Staggered connect over the fallback chain (F2). Expands the chain and
/// delegates to `race_connect`; the winning tier is `outcome.winner.kind`.
/// Updates F5 counters on success. The actual dialing is done by `connector`
/// (provided by the composition root); nexus-path never builds sockets.
pub fn connect_with_fallback(
    chain: &mut FallbackChain,
    connector: &dyn PathConnector,
    budget: &RaceBudget,
) -> io::Result<RaceOutcome>;
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
- E4: `product.path-fallback`（F1–F5：直连被阻断→staggered 经 SOCKS5 代理建连，
  胜出 `proxy` 且 N 字节真实走通；直连阻断用不可路由地址 192.0.2.1 模拟
  防火墙 DROP，不是真实 GFW）
- E4: `product.path-fallback-skip`（F4/F6：无代理·TURN 配置时退化为纯直连，
  跳过计数可观测）
- 单元测试：分数计算、EWMA、hysteresis 边界、unknown 处理、竞速（fake connector）、
  预算 enforcement、取消语义

## Performance Budget

- 探测包：每路径每 `probe_interval_ms`（默认 5s）1 个心跳，可忽略。
- 打分计算：O(候选路径数)，内存操作，无 I/O。

## Observability

- `score(path)` 可查询（诊断）。
- `PathEvent::Switched` 带原因（`BetterScore` / `PathFailed` / `PathAdded`）。
- `FallbackChain` 计数器（F5）：`attempts`、`wins{kind}`、`current_tier`、
  `skipped{kind}`；均为纯 `u64` 字段。

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
