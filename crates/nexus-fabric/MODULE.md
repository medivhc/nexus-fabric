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
