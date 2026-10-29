# nexus-flow-session Module Contract

（2026-10-02 requirement-change 冻结：v9 §10 TUN ingress 链；场景 `product.flow-session-mapping`）

## Responsibility

nexusd TUN 数据面的"流→会话映射"领域：把 TUN 逐包流映射到 §10 资源使用 Session。

- 维护 5 元组流表（`FlowKey`/`FlowEntry`），O(1) 精确匹配；地址为 `IpAddr`（双栈共用一张表，R3 C17）。
- 新流首包：构造 `FlowContext`（origin=PacketCapture）→ 调 Policy → 调 Core Planner → 经 `SessionManager`（Owner）创建 `nexus-session::SessionOwner`。
- 建连异步化：后台线程执行 Establish Connectivity，`process_one()` 永不阻塞；流表项 `Allocating→Active` 经 channel 回填。
- 已建流快路径：后续包直接按绑定 session 转发，不再调 Planner。
- 会话级事件订阅：connectivity established/failed → 触发重 plan（NAT 路径竞速对本层透明）。

## Non-Responsibilities

- 不做逐包分类（`PacketClassifier` 仍在 dataplane，降级为未知流 fallback）。
- 不做 DNS 短路、不做 QoS 整形（保留在逐包快路径，D7）。
- 不直接建连/打洞（Connectivity Establishment 由 domain-runtime/network 层执行）。
- 不持有平台 TUN 句柄（Portable Core 纪律；TUN 句柄在 Composition Root）。
- 不实现 smoltcp TCP 终结语义（那是传输终结层；本层只做"流→会话"映射）。

## FlowKey 双栈与解析（R3 C17）

- `FlowKey { src_ip: IpAddr, dst_ip: IpAddr, src_port, dst_port, proto }`；TCP/UDP 共用。
- `FlowKey::parse(&[u8]) -> Result<FlowKey, FlowParseError>`：v4 固定头 + IHL 偏移；
  v6 固定头 + 扩展头链（`0`/`43`/`60`/`44`，上限 8 个）。**`parse_ipv4` 已删除**
  （原子迁移：dataplane 与 examples 同一 commit 切换）。
- `FlowParseError` 七变体：`Truncated`、`BadVersion(u8)`、`TooManyExtensionHeaders`、
  `UnsupportedExtension(u8)`、`NonFirstFragment`、`UnsupportedTransport(u8)`、
  `BadChecksum`（与 `nexus_projection::ip::IpParseError` 同表；流表不校验校验和，
  `parse` 不返回该变体，保留为契约同源项）。
- v6 非首片/未知扩展头**不建 flow**：调用方按目的地址分类（spec §4.7.3），本层
  只回错误变体，绝不静默插表。
- v4 分片语义保持不变（仍按 L4 偏移解析，不改既有判据）。

## 概念澄清（R3：两层"会话"）

```text
smoltcp 本地 TCP 会话  = 传输终结（TUN 侧 TCP 状态机，本地完成握手）
§10 资源 Session       = 资源使用上下文（FlowContext→Policy→Planner→SessionOwner）
```

映射关系：一个 §10 Session 可绑定一个 smoltcp 终结流（TCP）或一个 UDP 5 元组流；
smoltcp 会话的生命周期从属于 §10 Session（Session 进 Draining/Disposed 时终结本地传输会话）。

## Inputs

- TUN 上行 IPv4/IPv6 包字节（由 dataplane 调用，不持有 TUN）。
- `FlowContext`（本层构造，origin=PacketCapture，destination=5 元组中立表达）。
- Policy/Planner 的同步纯函数调用。
- 后台建连线程的事件回填（channel）。

## Outputs

- `FlowDecision`：{NewSession(session_id), Forward(session_id), Drop(reason), BufferForSession}。
- 结构化 Session 事件（供 dataplane 驱动 smoltcp/RST/转发）。
- 计数器：planner 调用于快路径必须为 0（E4 可证）。

## Allowed Dependencies

- `nexus-domain`（FlowContext/ResourceId/LifecyclePhase）
- `nexus-measurement`（LinkMeasurement 事实测量；Planner 的 measure 闭包签名所需）
- `nexus-policy`（PolicyEngine）
- `nexus-planner`（plan_from_snapshot）
- `nexus-session`（SessionOwner/SessionId/CancelToken）
- `nexus-network`（只读：候选/连接状态查询；**不反向依赖**）

## Forbidden Dependencies

- `nexus-ingress`（ingress 只产 FlowContext；TUN 包的 FlowContext 由本层构造）。
- 平台专有 API（portable=false 但仍禁直调 OS；平台能力经 Composition Root 注入）。
- `engineering/` 下的 Harness/Plugin。
- 未在 `policies/architecture.toml` 声明的 Nexus 内部 crate。
- `nexus-connectivity`（v9 CLI 产品线运行时，frozen）。跨栈词汇改用 `nexus-domain` /
  `nexus-proxy-config` / `nexus-session` / `nexus-qos`（P3 落地）。

## Invariants

- 流表 key = 完整 5 元组（src ip/port, dst ip/port, proto）；不按 destination 聚合（D1）。
- 首个 SYN 只创建一个 Session；重传 SYN 不重复建（幂等 key=FlowKey）。
- SessionManager 是 Owner：建连任务挂 CancellationToken；Exactly-One Outcome（§13/§14）。
- 已建流后续包不调 Planner（hot path 纯洁性）。
- 建连失败 → TCP 发 RST / UDP 丢包；不静默黑洞。
- 空闲超时 → Draining → 会话数回落，无泄漏。
- NAT 路径切换不改变流表项（Identity≠Locator）。

## Side Effects

- 后台建连线程（Owner 拥有，CancellationToken + JoinSet + Reaper）。
- UDP 有界缓冲（32 包/64KB）；TCP 早期数据复用 smoltcp socket buffer。

## Public API

- 默认最小 surface：`private -> pub(crate) -> pub`。
- `FlowKey` / `FlowEntry` / `FlowDecision` / `SessionManager` / `FlowTable` / `UdpBuffer`。

## Verification

```text
cargo check -p nexus-flow-session --all-targets
cargo clippy -p nexus-flow-session --all-targets -- -D warnings
cargo test -p nexus-flow-session
```

产品级：`scenarios/product/flow_session_mapping.toml`（E4）。

## Performance Budget

（R4 基线，2026-10-02，沙盒 shared-CPU；`cargo test -p nexus-flow-session -- --ignored --nocapture perf_baseline`）

| 路径 | baseline (p50/p99) | noise tolerance | warning | blocking |
|---|---|---|---|---|
| 快路径 `on_packet`（已建流查表+Forward） | 831ns / 3395ns | 2x（沙盒噪声大） | p99 > 5µs | p99 > 20µs |
| 首包链（Policy+Planner 同步） | 6.3µs / 28µs | 2x | p99 > 500µs | p99 > 2ms |
| `process_one()` direct 路径现状 | 1833ns / 2223ns（5000 包） | 2x | p99 > 10µs | p99 > 50µs |

- 零 hot-path 分配：快路径不得分配（`process_one()` 现状每包 `to_vec()` 为已知待优化点，不属本层）。
- 未定义性能预算的路径不得宣称"性能完成"。

## Observability

- 结构化事件：`flow.session_created{flow_key, session_id}` / `flow.session_failed{reason}` / `flow.draining{idle_secs}`。
- 关联字段：`session_id` 全链路携带。

## Recovery Semantics

- 本层无持久状态（流表是内存重建）；crash 后冷启动流表为空，新流重新走首包链。
- 与 T4 crash-recovery 的 session durable marker 语义对齐：§10 Session 的 reconcile 走 `nexus-session` 的 `reconcile_session_records`，本层不另建机制。
- 后台建连任务取消语义：Owner drop → CancellationToken → JoinSet reaped（无泄漏）。

## Platform Constraints

- 本 crate `portable = false`（依赖 nexus-network 等 domain-runtime），但仍禁止直调平台 API。
- FUSE/挂载等平台能力与本层无关（C1 正交）。
