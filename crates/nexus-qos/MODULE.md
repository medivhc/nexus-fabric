# nexus-qos Module Contract

## Responsibility

用户态包调度（CAKE-like：per-flow DRR 公平队列 + 三级严格优先级 + per-egress 令牌桶整形）
与令牌桶限流基元。**跨栈共享叶**：v9 CLI 运行时经 `QosController` 消费令牌桶，
N1 `nexusd` 与 `nexus-harness` 直接消费调度器（`cake`）。

定义自 `nexus-connectivity` 下沉（2026-10-28，P3），语义逐字不变。

## Non-Responsibilities

- 不读时钟（`now: Duration` 由调用方注入）、不做 I/O、不接 socket/TUN/tc；
- 不解析配置、不做策略下发、不持久化、不做多路径；
- 不提供 `QosClock` / `MonotonicClock` / `QosConfig` / `PerEndpointStats` / `QosStats` /
  `QosController`（仍属 `nexus-connectivity::qos`）。

## Inputs

- `(FiveTuple, bytes, now: Duration)` → `EnqueueDecision`；
- `(now: Duration)` → `Option<(FlowId, u64)>` / 回收流数；
- `BandwidthLimit` 参数（速率 / burst）。

## Outputs

- `EnqueueDecision`（`Admitted` / `DroppedQueueFull` / `DroppedOversize`）；
- `Option<(FlowId, u64)>`（出队）、`CakeStats` 快照、`usize`（回收流数）；
- `QosError` 类型化错误（`Display` + `std::error::Error`）。

## Public API

### 冻结契约（CAKE-like QoS 调度器：DRR 公平队列 + 整形，scenarios/product/qos_cake.toml）

用户态 CAKE-like 调度器（MVP）：per-flow DRR 公平队列 + 三级严格优先级 +
per-egress 令牌桶整形。纯内存、纯同步；不接真实 TUN/socket（留接入点）；
`qos.rs` 的令牌桶冻结契约保持不动（本模块复用 `BandwidthLimit` / `TokenBucket`）。

- `FiveTuple { src_ip: IpAddr, dst_ip: IpAddr, src_port: u16, dst_port: u16, proto: u8 }`：
  `flow_id() -> FlowId(u64)` 为同进程内确定性哈希（`DefaultHasher`，不持久化）；
  `proto`：6=TCP / 17=UDP / 1=ICMP。
- `Priority { High, Medium, Low }`：`Ord` 为 High < Medium < Low（值越小越优先）。
- `CakeConfig`：
  - 字段：`quantum: u32`（默认 1514）、`flow_timeout: Duration`（默认 60s）、
    `max_queue_packets: usize`（默认 64，单流队列上限）、
    `max_packet_bytes: u64`（默认 65535，超限整包丢弃）、
    `high_priority_ports: Vec<u16>`（默认 `[22, 53, 3389]`）、
    `low_priority_ports: Vec<u16>`（默认空）、
    `rate_limit: Option<BandwidthLimit>`（per-egress 整形；`None` = 不整形）。
  - `validate() -> Result<(), QosError>`：`quantum` ∈ [64, 65536]、
    `flow_timeout` > 0、`max_queue_packets` >= 1、
    `max_packet_bytes` ∈ [1, 16MB]，否则 `QosError::InvalidLimit`；
    high/low 端口交集非空同样拒绝（复用 `InvalidLimit`，message 说明原因，
    不新增错误变体以保持冻结错误面）。
- `CakeScheduler`：
  - `new(&CakeConfig) -> Result<Self, QosError>`（先 `validate`）。
  - `enqueue(&FiveTuple, bytes: u64, now: Duration) -> EnqueueDecision`：
    `Admitted { flow: FlowId, priority: Priority }` /
    `DroppedQueueFull`（该流队列已达 `max_queue_packets`）/
    `DroppedOversize`（`bytes > max_packet_bytes`）；dropped 记入统计。
    新流按端口规则定优先级：`proto == 1`（ICMP）恒 High；源/目的任一端口命中
    high 列表 → High；命中 low 列表 → Low；否则 Medium。流优先级在流生命周期内不变。
  - `dequeue(now: Duration) -> Option<(FlowId, u64)>`：类间严格优先级
    （High 类有 active 流时不看 Medium/Low）；类内 DRR（每流每访问
    `deficit += quantum`，队首包 `len <= deficit` 则发送并 `deficit -= len`；
    单包 > quantum 时 deficit 跨轮累积直到能发）；整形门控：发送前
    `try_consume(len, now)`，令牌不足则**不**出队、**不**扣 deficit、
    **不**跳过找更小的包，直接返回 `None`（调用方稍后重试）；
    每次调用最多出一包。
  - `reap(now: Duration) -> usize`：回收 `now - last_seen >= flow_timeout`
    的流（队内残包计入 dropped），返回回收流数。
  - `flow_count() -> usize` / `snapshot() -> CakeStats`。
  - `CakeStats { packets_enqueued, packets_dequeued, packets_dropped, bytes_dequeued,
    per_priority_dequeued: [u64; 3], flows_current, flows_reaped }`：
    `per_priority_dequeued` 下标按 `High=0, Medium=1, Low=2`。
- 不变量：
  - 同优先级、持续 backlog 的流，出队字节数之差有界（DRR 公平；quantum 相同）；
  - High 类有 backlog 时 Medium/Low 不出包（严格优先级）；
  - 整形开启时，任意 1 秒窗口出队字节 ≤ rate + burst（令牌桶语义）；
  - `dequeue` 返回 `None` 当且仅当：全部 active 为空，或整形令牌不足；
  - 纯内存、纯同步；时钟由调用方 `now: Duration` 显式传入；无 `unsafe`；
    库代码不 panic/unwrap/expect（`new` 失败走 `Result`）。
- `daemon.toml [qos]` 映射（`apps/nexusd` 解析；热加载分类见该 crate 契约）：
  `enabled`（默认 false）、`mesh_upload_mbps` / `proxy_upload_mbps`
  （默认 0 = 不限）、`quantum`（默认 1514）、`high_priority_ports`
  （默认 `"22,53,3389"`）。`enabled = false` 时调度器不实例化（零开销）。

冻结语义：不接真实 TUN/socket；不做多路径；IPv4/IPv6 五元组均支持（`IpAddr`）；
TUN 接入点 = 调用方把包映射为 `(FiveTuple, bytes)` 入队、出队后按 `(FlowId, bytes)`
取回包缓冲（包缓冲所有权在调用方，调度器只处理流 ID 与字节数）。

### 冻结契约（令牌桶基元，scenarios/product/bandwidth_qos.toml）

- `BandwidthLimit { max_bytes_per_sec: u64, burst_size: u64 }`：
  `new(max_bytes_per_sec, burst_size) -> Result<Self, QosError>`（速率必须 > 0、
  burst 必须 >= 1，否则 `QosError::InvalidLimit`）；`rate()` / `burst()` 只读。
- `TokenBucket`：`new(&BandwidthLimit)`（初始满桶 = burst_size）；
  - `refill(now)`：按 `rate` 字节/秒线性补充，封顶 `burst_size`；时间回退不补充；
  - `try_consume(bytes, now) -> bool`：够令牌则扣减并返回 `true`，不够返回 `false`
    （不阻塞、不 sleep）；
  - `remaining_tokens() -> u64`（向下取整）/ `capacity()` / `rate()`。
整形排队、优先级/公平排队、per-flow 分流、真实数据面挂接留 TODO。

冻结语义：纯内存、纯同步、纯函数骨架；不接真实 socket/TUN/内核 tc；不引入 `time` crate，
仅 std（`std::time::Duration`）；无 `unsafe`、库代码不 panic/unwrap/expect。

## Allowed Dependencies

**（空）** —— 只用 `std`；零第三方依赖、零 Nexus 内部依赖。

## Forbidden Dependencies

- 一切 Nexus 内部 crate（含 `nexus-connectivity`）：**叶子不得回指旧栈**，
  这是无环证明的守护条款。
- `engineering/` 下的 Harness/Plugin。
- 未在 `policies/architecture.toml` 声明的 Nexus 内部 crate。
- Portable 模块中的平台专有 Framework/API。
- 叶子身份：本 crate 被两栈依赖**不构成反向边**，判据见
  `docs/adr/0001-dual-stack-boundary.md` §共享叶判据。

## Invariants

- 纯内存、纯同步，不 sleep、不阻塞（`now` 由调用方显式注入）。
- `try_consume` 令牌不足即返回 `false`（不排队等待）。
- 时间回退不补充令牌、不回拨 `last_refill`。
- `validate()` 非法一律 `QosError::InvalidLimit`，**不新增错误变体**（冻结错误面）。
- 整形阻塞时 `dequeue` 回滚 deficit、不出队、不跳过找小包。

## Side Effects

无（纯内存、纯同步；不读写文件、不发包、不分配 OS 资源）。

## Verification

```text
cargo test -p nexus-qos
cargo clippy -p nexus-qos --all-targets -- -D warnings
cargo check -p nexus-qos --target wasm32-wasip1
```

产品级场景：`product.qos-cake`（carrier = `shared-leaf`）、
`product.qos-cake-enabled-path`（生产装配路径，carrier = `n1-fabric`）。

## Performance Budget

未定义性能预算的路径不得宣称"性能完成"。本模块为纯内存调度器，当前无 baseline；
进入数据面热路径前必须在 Contract 中增加 baseline、noise tolerance、warning threshold
与 blocking threshold。

## Observability

`CakeStats` 是结构化快照（`packets_enqueued` / `packets_dequeued` / `packets_dropped` /
`bytes_dequeued` / `per_priority_dequeued` / `flows_current` / `flows_reaped`）；
无自由文本日志、无 per-packet 日志。

## Recovery Semantics

无持久状态（纯内存）：崩溃即丢失队列内容与令牌余额；本 crate 不参与冷启动 reconcile。

## Platform Constraints

portable-core：`wasm32-wasip1` 可编译；无 `unsafe`；不调用任何平台 API。

## Deletion Test

删除 `nexus-qos` 会破坏哪一个**已存在**的独立变化维度：

1. 两栈必须共享同一份令牌桶实现（AC-25 单一实现判据）；
2. 叶子边界是「N1 不得反向依赖 v9 运行时」这一方向性约束**唯一可机械证明的形态**
   （叶子零出边）。

故该抽象不是推测性设计。
