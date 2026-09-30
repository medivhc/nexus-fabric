# nexus-proxy-transport — MODULE

## Responsibility

节点间链路的**代理传输**（DESIGN §3.5，P1）：当直连被封时，mesh 流量经
SOCKS5 代理隧道承载 QUIC 会话。本 crate 只做 transport——SOCKS5 握手 →
TCP → 2 字节长度前缀成帧 → 实现 `nexus-fabric::UdpTransport`，QUIC
driver 经 `FabricConn::connect_with_transport` 零改动接入。

## Non-Responsibilities

- 路径选择与 fallback 决策（那是 `nexus-path` 的 `PathManager`；
  `PathKind::Proxy` 候选已存在，但本期**不**做自动触发联动——后置）。
- 代理**出口**（per-flow 规则引擎决策，3b 已做，不碰）。本 crate 是
  per-link 传输，两者不可混淆（见 plan §1）。
- ss/trojan 代理传输、UDP ASSOCIATE（后置）。
- 公网代理互操作（E4 用自研最小 SOCKS5 server）。

## Inputs

- `Socks5ProxyConfig`：代理服务器地址、可选用户名/密码、握手超时。
- CONNECT 目标地址（对端 QUIC 监听地址）。
- 上层 QUIC datagram（已 E2E 加密，代理只看密文）。

## Outputs

- `socks5_connect()`：完成 RFC 1928 握手的已连接 `TcpStream`。
- `ProxyTransport: UdpTransport`：`send_to` 成帧写、`recv_from` 解帧读、
  `local_addr` 返回 TCP 本地地址。
- X6 计数器：`proxy_handshake_ok/err`、`proxy_framed_bytes`。

## Allowed Dependencies

- `std` only（零 Tokio，与 `nexus-fabric` 一致）
- `nexus-fabric`（仅 `UdpTransport` trait；`nexus-fabric` 不反向依赖本 crate，
  延续 4b 的 S9 依赖反转）

## Forbidden Dependencies

- `tokio`, `async-std`, 任何 async runtime
- 任何第三方 crate（首期零新依赖）
- `nexus-path` / `nexus-proxy-config`（本期不做选路联动与共享配置；
  见下文“配置来源说明”）

## Invariants

**X1（QUIC 零改动 / 成帧）**：QUIC datagram 经 2 字节大端长度前缀成帧跑在
TCP 流上；对端解帧还原 datagram。单 datagram ≤ 1200 字节（fabric S5），
超限 `send_to` 返回 `InvalidInput` 错误，**不静默截断**。长度前缀 > 1200
的入帧视为协议违规，`recv_from` 返回错误。`UdpTransport` 是点对点语义：
transport 在构造时绑定唯一的 CONNECT 目标；`send_to(buf, target)` 的
`target` 参数被忽略（TCP 连接即目标，文档化）。

**X2（双重加密语义）**：代理层只做传输 + 混淆（抗识别），不触碰 QUIC
E2E 加密。代理服务器能看到的只是加密后的 QUIC 字节流（fabric S1：
中继看不见内容）。双重加密是故意的，不是浪费。

**X3（层归属）**：本 crate 只做 transport（字节流 → `UdpTransport`）；
选路决策在 `nexus-path`。`PathKind::Proxy` 候选已存在，但本期不实现
`PathManager` 的自动 fallback 触发（联动后置，见诚实边界）。

**X4（协议范围）**：首期只 SOCKS5 CONNECT（RFC 1928），支持无认证与
用户名/密码认证（RFC 1929）。目标地址类型支持 IPv4/IPv6。ss/trojan、
UDP ASSOCIATE 后置。握手失败必须返回类型化错误（`ProxyError`），不静默
回退直连。

**X5（sync）**：全同步 std API，零 tokio。`TcpStream` 用 `Mutex` 包装以满足
`UdpTransport::send_to(&self)` 的共享引用签名；driver 对 transport 是
单线程独占使用，锁竞争可忽略。

**X6（可观测）**：`ProxyTransport::counters()` 返回
`(handshake_ok, handshake_err, framed_bytes)`（`AtomicU64`，Relaxed）。
Hot path 禁止 per-frame log；观测只走计数器。

## Side Effects

- TCP 连接（到 SOCKS5 服务器）。
- 无后台线程（握手与收发全是调用方线程的阻塞调用）。

## Public API

```rust
pub struct Socks5ProxyConfig { pub server: SocketAddr, pub auth: Option<Socks5Auth>, pub connect_timeout: Duration, pub handshake_timeout: Duration }
pub struct Socks5Auth { pub username: String, pub password: String }
pub enum ProxyError { Io(io::Error), NoAcceptableAuth, AuthFailed, ConnectRejected(u8), BadReply(&'static str), FrameTooLarge(u16), FrameOverflow { frame: usize, buf: usize } }
pub const MAX_DATAGRAM: usize = 1200;
pub const FRAME_HEADER_LEN: usize = 2;
pub fn socks5_connect(config: &Socks5ProxyConfig, target: SocketAddr) -> io::Result<TcpStream>;
pub struct ProxyTransport { /* TcpStream + target + counters */ }
impl ProxyTransport {
    pub fn new(stream: TcpStream, target: SocketAddr) -> Self;
    pub fn connect(config: &Socks5ProxyConfig, target: SocketAddr) -> io::Result<Self>;
    pub fn target(&self) -> SocketAddr;
    pub fn counters(&self) -> (u64, u64, u64);
}
impl nexus_fabric::UdpTransport for ProxyTransport { /* recv_from / send_to / set_read_timeout / local_addr */ }
```

API 面最小化：`stream` 字段不暴露；计数器只读。

## Verification

- P-U-1 单测：RFC 1928 握手向量（无认证/用户名密码/拒绝）、成帧 roundtrip、
  超限拒绝（>1200）、截断帧/坏前缀的错误路径。
- P-E-1 E4（`examples/proxy_quic.rs`）：自研最小 SOCKS5 server → A 经代理
  CONNECT 到 B → `connect_with_transport` 建 QUIC → 64KB 回显 →
  断言 `proxy_relayed_bytes > 0`。见 `scenarios/product/proxy_transport.toml`。
- P-V-1 回归：fabric 现有 E4 不受影响（S9 默认路径 `StdUdpTransport` 零行为变化）。

## Performance Budget

- 成帧开销：每 datagram 2 字节头 + 一次 `write_all`；无额外拷贝
  （`send_to` 直接在 TCP 流上写前缀 + 载荷）。
- 握手：一次 TCP 建连 + ≤4 个 RTT（方法协商、可选认证、CONNECT）。
- 本期不设吞吐 benchmark（P1 传输能力，非性能专项）；E4 只断言功能正确。

## Observability

- X6 计数器（见上）。
- 握手失败在 `ProxyError` 中保留 REP/方法字节等上下文，支持
  Retry（换代理）/ Abort（上报）决策。

## Recovery Semantics

- 代理 TCP 断开 → 后续 `send_to`/`recv_from` 返回 `io::Error`
  （连接重置），由上层（路径层/会话重建）决定重连；本 crate 不做
  自动重连（无 Owner 语义，不藏后台任务）。
- 握手超时（`connect_timeout`/`handshake_timeout`）→ 返回超时错误，
  不永久阻塞。

## Platform Constraints

- Linux 首期（E4 只在 xc-pc-linux 真机；沙箱无真实 TCP 到代理？沙箱
  TCP 需 per-destination 审批，E4 只在真机跑）。
- Portable Core 不直接调平台 API：本 crate 只用 `std::net`，可移植。

## 配置来源说明（对 plan 决策③的修正）

Plan 决策③“复用现有 outbound SOCKS5 结构”的前提不成立：实际核查
`nexus-proxy-config` 的 `OutboundKind` 只有
Direct/Relay/Shadowsocks/Vmess/Trojan，**没有 SOCKS5 变体**
（SOCKS5 只存在于 inbound/ingress）。因此本 crate 自带最小
`Socks5ProxyConfig`（server + 可选 auth + 超时），不碰
`nexus-proxy-config`。待 PathManager fallback 联动（后置阶段）时再统
一接入共享出站配置。本修正在此文档化，非静默偏离。
