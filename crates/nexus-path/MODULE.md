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
- 不做竞速（Racing）、质量预测、多路径并发（P0 明确不做，见 DESIGN.md §4.4/4.6/4.8）。
- 不做互联网出口的用户规则决策（§11 规则引擎的作用域，见 DESIGN.md §5）。

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

**S4（hysteresis）**：新路径分数必须超过当前路径 `hysteresis_db` 且持续
`switch_hold_ms` 才切换，防止抖动。

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

## Side Effects

- 后台探测线程（owner：`PathManager`，Drop 时 join）。
- UDP 探测包收发（轻量心跳）。

## Public API

```rust
pub struct PathManager { /* ... */ }
pub struct PathConfig {
    pub hysteresis_db: f64,
    pub switch_hold_ms: u64,
    pub probe_interval_ms: u64,
    pub ewma_alpha: f64,
    pub max_missed_probes: u32,
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

impl PathManager {
    pub fn new(config: PathConfig) -> Self;
    pub fn add_candidate(&mut self, path: CandidatePath);
    pub fn remove_candidate(&mut self, remote: &SocketAddr);
    pub fn current_path(&self) -> Option<CandidatePath>;
    pub fn on_stats(&mut self, remote: &SocketAddr, stats: PathStats);
    pub fn poll_event(&self) -> Option<PathEvent>;
}
```

## Verification

- E4: `product.fabric-path-basic`（打分选优、hysteresis）
- E4: `product.fabric-path-roam`（路径失效切换不断流）
- 单元测试：分数计算、EWMA、hysteresis 边界、unknown 处理

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
