# nexus-fabric Module Contract

## Responsibility

QUIC-like session layer for the Nexus foundation (`FabricConn`): reliable
bidirectional streams, unreliable datagrams, E2E encryption (TLS 1.3), and
connections identified by `(PeerId, ConnectionId)` decoupled from the UDP
5-tuple so they survive local address changes (roaming). Sync API; the
quinn-proto driver runs on its own std threads (the repository is tokio-free).

## Non-Responsibilities

- 不做路径选择（直连/TURN/代理出口的决策属路径层）；只消费路径层提供的 UDP 收发能力与候选地址。
- 不做 TUN 投影（属投影层；投影层调用本 crate）。
- 不是 `nexus-session` 的任务执行会话；两者同名异物，禁止混淆。
- 首期不做多路径、0-RTT。

## Inputs

- `PeerId`（ed25519 公钥）+ 候选 `SocketAddr`（路径层提供）。
- 结构化 `ConnConfig`；失败返回类型化 `FabricError`。

## Outputs

- `FabricConn` / `SendStream` / `RecvStream` / datagram / `ConnStats`。
- 结构化 Result；关闭语义显式（graceful close vs abort）。

## Allowed Dependencies

- （无内部 crate；Phase A 骨架）

## Forbidden Dependencies

- `engineering/` 下的 Harness/Plugin。
- 未在 `policies/architecture.toml` 声明的 Nexus 内部 crate。
- `tokio` 及任何 async runtime（仓库 std-only 姿态；quinn-proto 为 sans-IO）。
- Portable 模块中的平台专有 Framework/API。

## Invariants

- S1: E2E 加密（TLS 1.3 via rustls-ring）；中继/TURN 节点只能看到密文。per-hop 链路加密不能替代本条。
- S2: 连接身份 = (PeerId, ConnectionId)，不含 IP/端口。
- S3: 漫游不丢数据：地址变更后未确认数据在新路径重传；流不断、不重不漏。
- S4: 可靠流 = 有序完整交付；`finish` 后对端读到 EOF。
- S5: 数据报 = 尽力而为，可丢失乱序；单包上限 1200 字节（PMTUD 前）。
- S6: 路径迁移需 challenge/response 验证，防地址欺骗。
- S7: 显式关闭语义；关闭后新流拒绝。
- S8: 统计诚实：无样本时标记 unknown，不编造 0。
- S9: UDP 传输抽象：driver 经 `UdpTransport` trait 收发（`recv_from` /
  `send_to` / `set_read_timeout` / `local_addr`），不直接拥有 `UdpSocket`；
  `StdUdpTransport` 为默认实现（行为与之前一致）；`FabricConn::connect` /
  `FabricListener::bind` 保留原签名（默认用 std socket），新增
  `connect_with_transport` / `bind_with_transport` 接受
  `Box<dyn UdpTransport>`（如 `nexus-turn::TurnSocket`）。`nexus-fabric`
  不依赖 `nexus-turn`（依赖倒置：trait 在 fabric，实现在外）。
- S10（驱动连接表回收，2026-10-03 冻结）：reaper 从 `live` /
  `handle_map` 摘除关闭连接时，同步从 `shared.conns` 摘除；关闭连接的
  `accepted` / `dgrams` 缓冲随最后一个 `Arc<ConnShared>` 释放，不永久冻结。
  `accept_conn` 跳过已摘除的 id——死连接不再被 accept 命中。调用方持有的
  `Arc<ConnShared>` 仍可读 `stats()`；"keep shared state for late stats()"
  的旧注释不再适用。
- S11（connect 单一超时预算，2026-10-03 冻结）：`Driver::connect` 的总
  超时为单一 `handshake_timeout` 预算，贯穿"命令应答"与"握手完成"两阶段
  （`deadline = 调用时刻 + handshake_timeout`）。任一阶段超时都清理已创建
  的连接：第二段超时发 `Cmd::Close`（已有）；第一段超时（命令尚未执行）
  置取消标志，迟执行的 `Cmd::Connect` 不得创建孤儿连接（命令携带取消标志，
  执行前检查）。
- FabricConn != nexus-session Session。

## Deletion Test（§12 新抽象论证）

如果删除 `nexus-fabric`、让上层直接依赖 `quinn-proto`：
- 会话语义（S1–S8：E2E 加密、CID 解耦、漫游、统计口径）将散落在各调用方，
  失去单一可冻结的语义契约；
- 路径层与投影层将各自发明连接抽象，破坏 "Identity != Locator" 的统一解释；
- 失去独立的测试替身边界（路径层需要 mock FabricConn 做选路测试）。

独立变化维度：会话语义的演进（0-RTT、多路径）与传输实现（quinn-proto 升级/替换）
是两个维度的变化。故独立 crate 成立。

## Side Effects

- UDP socket 收发；driver 线程（有明确 owner，见 §13 结构化并发要求，实现阶段落实）。
- 无磁盘持久状态（0-RTT 会话票据属远期）。

## Public API

见 `src/lib.rs`：
- `PeerId([u8; 32])`、`ConnectionId(u64)`、`ConnConfig`、`FabricConn`、`FabricListener`
- `SendStream` / `RecvStream`、`ConnStats{rtt_ms, loss_rate, jitter_ms, throughput_bps, active_path, bytes_sent, bytes_recv}`（Option 语义，S8）
- `FabricError{HandshakeFailed, PathUnreachable, Closed(u32), Timeout, Transport}`

冻结语义（`scenarios/product/fabric_conn_basic.toml`、`fabric_conn_roam.toml`）：
- 建连必须完成对端 `PeerId` 认证；认证失败不得建连。
- `fabric-conn-roam`：传输中 rebind 后 CID 不变、载荷哈希一致、应用层可见停顿 < 5000ms（首版宽松）。

## QSEQ：Fabric 层数据报序号（GAP-2 冻结契约）

**Contract hash**：`16df4f6106f0459e5974f180f28521e018324662`

### 背景与诚实边界

多路径 per-packet 模式需要接收端重排缓冲的序号源。任务原目标是"复用 QUIC
真实包号"，但经核查：

1. **quinn-proto 0.11 未暴露包号**：`Connection::spaces[space].next_packet_number`
   为私有字段，无 public API 可读（`vendor/quinn-proto/src/connection/mod.rs`
   第 386–3766 行 public 方法清单中无包号相关项）。不 patch vendor 代码的前提下
   **不可直接获取** —— 此为诚实记录的 blocker，不硬造。
2. **线包号语义不适合重排**：QUIC 有 3 个独立包号空间
   （Initial/Handshake/ApplicationData）；重传分配**新**包号；多个 datagram
   可合并进同一个 QUIC 包。重排缓冲需要的是 *datagram 身份* 序号，而非
   *传输* 序号 —— 线包号是错误的序号空间。

因此定义 **fabric 层数据报序号**：在 `send_datagram` 调用边界（最接近 QUIC
发送路径的应用可见点）按连接单调分配的 `u64` 回绕序号。这不是 QUIC 线包号，
契约中明确区分，不混淆。

### 冻结条款

- **Q1**：`FabricConn` 维护每连接单调递增的 datagram 序号计数器（`u64`，
  `wrapping_add(1)` 回绕），初值为 0。`send_datagram`（非序号版）不分配序号、
  不影响计数器。
- **Q2**（新增 API，纯增量、非破坏）：`send_datagram_seqed(&self, data: &[u8])
  -> Result<u64, FabricError>`：分配序号 `s`（分配后计数器 `wrapping_add(1)`），
  将 `s` 以 8 字节大端序 prepend 到载荷头部后经 QUIC datagram 发送；返回 `s`。
  载荷长度限制：`data.len() <= 1192`（1200 上限减 8 字节序号头），超限返回
  `FabricError::Transport`。
- **Q3**（新增 API，纯增量、非破坏）：`recv_datagram_seqed(&self)
  -> Result<(u64, Vec<u8>), FabricError>`：收到的 datagram 若长度 `< 8`，
  返回 `FabricError::Transport("datagram too short for seq header")`；否则剥离
  前 8 字节大端序为序号 `s`，返回 `(s, 剩余载荷)`。
- **Q4**：序号分配与发送是原子的（同一 `send_datagram_seqed` 调用内完成，
  不存在"取号后发送前"的竞态窗口）。
- **Q5**：`send_datagram` / `recv_datagram`（非序号版）语义零变化；N1 mesh
  现有路径不受影响。
- **Q6**：序号是 per-connection 命名空间；不同连接的序号无可比性。
  接收端必须按连接维护重排缓冲（`nexus-projection::ReorderBuffer` 按连接实例化）。

### 不变量

- 分配的序号在单连接内严格单调递增（模 2^64 回绕意义下）。
- `recv_datagram_seqed` 返回的序号即发送端 `send_datagram_seqed` 返回的序号
  （QUIC datagram 不可靠：允许丢包、允许乱序，不允许篡改/错位）。

## Verification

最低：

```text
cargo check -p nexus-fabric
cargo clippy -p nexus-fabric --all-targets -- -D warnings
```

产品级：`scenarios/product/fabric_conn_basic.toml`、`fabric_conn_roam.toml`（E4）。

## Performance Budget

未定义（实现阶段为 driver loop 与流吞吐定义 baseline/noise/warning/blocking）。

## Observability

`ConnStats` 为稳定结构化字段；关联字段：`connection_id`、`peer_id`、`path_id`
（见 AGENTS.md §22）。Hot path 禁止 per-packet log。

## Recovery Semantics

无持久状态；进程崩溃后连接不恢复（重建）。`close` 尽力发送关闭帧，不保证送达。

## Platform Constraints

- Portable crate 不得直接调用平台 API；UDP socket 经 `std::net`（本 crate 不在 `portable_core` 清单）。
- 平台透明拦截不在本 crate（属 `nexus-platform-*`）。

### N3-6 显式双向 TLS 模式增补

沿用旧 API，新增 opt-in TLS1.3 双向证书身份认证：client pin server PeerId，
server 强制认证证书签名与显式 requester allowlist；认证未完成不得 publish
accepted/应用 stream/datagram。明确 mutual-authenticated peer accessor 区分旧
匿名/占位连接；私钥不进入 Debug/日志。单一握手预算与现有 owner/reaper保留。
细节见 docs/N3-6-LOCALAPI-SECURITY-CONTRACT.md；产品边界
scenarios/product/fabric-mutual-auth.toml。不实现 Task RPC/领域算法。
