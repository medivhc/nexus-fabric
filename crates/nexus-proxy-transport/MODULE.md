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
- UDP ASSOCIATE（后置）。
- 公网代理互操作（E4 用自研最小 ss/trojan server）。

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
- `nexus-outbound-shadowsocks`（二期新增：仅复用 `SsStream`/`SsMethod`/
  `encode_request`/`parse_request`/`write_record`/`read_record` 密码学与握手原语；
  不使用 `OutboundAdapter` trait——那是 per-flow egress 语义，本 crate 是
  per-link transport，见 T3）
- `nexus-outbound-trojan`（二期新增：仅复用 `auth_hash`/`encode_request`/
  `parse_request` 握手原语；本期不用 TLS 相关原语，TLS 后置）
- `nexus-proxy-config`（二期新增：仅复用 `OutboundConfig`/`OutboundKind`
  配置**结构**（`TryFrom` 转换）；不引入选路/规则引擎语义，见 T4 配置说明）

## Forbidden Dependencies

- `tokio`, `async-std`, 任何 async runtime
- 新增第三方 crate（本期零新增；`chacha20poly1305`/`hkdf`/`sha2`/
  `rustls`/`ring`/`rcgen` 经 outbound crates 传递复用，已在工作区评审过）
- `nexus-path`（本期不做选路联动；见 X3）

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

**X4（协议范围）**：SOCKS5 CONNECT（RFC 1928），支持无认证与
用户名/密码认证（RFC 1929），目标地址类型支持 IPv4/IPv6；二期新增
shadowsocks（T1）与 trojan 明文握手（T2，TLS 后置）。UDP ASSOCIATE 后置。
握手失败必须返回类型化错误（`ProxyError`），不静默回退直连。

**X5（sync）**：全同步 std API，零 tokio。`TcpStream` 用 `Mutex` 包装以满足
`UdpTransport::send_to(&self)` 的共享引用签名；driver 对 transport 是
单线程独占使用，锁竞争可忽略。

**X6（可观测）**：`ProxyTransport::counters()` 返回
`(handshake_ok, handshake_err, framed_bytes)`（`AtomicU64`，Relaxed）。
Hot path 禁止 per-frame log；观测只走计数器。

## 二期扩展：ss/trojan 代理传输（T1–T6，冻结）

本期把"自由"能力补全到真实抗封锁场景常用的 ss/trojan。X1–X6 继续有效；
T1–T6 是新增冻结不变量。

**T1（ShadowsocksTransport）**：TCP connect → ss 会话握手 → 字节流 →
同样 2 字节成帧 → `impl UdpTransport`；QUIC 层零改动（X1 延续）。
握手复用 `nexus-outbound-shadowsocks` 原语（T3），不重写密码学：
- `SsStream::new(password, method, Role::Client)` 建会话（c2s/s2c 双向 key，
  HKDF 派生，固定计数器 nonce——**无随机 salt**，线格式与公网 ss 不同，
  不宣称互操作，见诚实边界）；
- `write_record(seal(encode_request(target)))` 发目标地址帧；
- 等 `read_record` → `open` 校验服务端回的 `b"ss-proxy-ok"` 确认帧
  （双向密钥自洽即认证；错密码表现为 `DecryptFailed`，不静默回退）。
- 数据面：每 datagram `seal`（12B nonce + ct + 16B tag = 28B 开销）→
  2 字节成帧（T4）。明文 datagram ≤ 1200（X1 延续）；
  线帧上限 `MAX_SEALED_FRAME = 1228`。
- `SsTransport` 结构：`FramedTransport`（T4 共享成帧）+
  `Mutex<SsStream>`（满足 `send_to(&self)` 共享引用；收发不嵌套加锁，
  先 seal/open 再碰 socket）。

**T2（TrojanTransport）**：TCP connect → trojan 握手 → 同样成帧 →
`impl UdpTransport`。握手复用 `nexus-outbound-trojan` 原语：
- 明文写 `encode_request(password, target)`
 （首行 `hex(SHA-224(password))` + CRLF + `0x01` CMD + ATYP/ADDR/PORT + CRLF）；
- **无握手确认帧**（与真实 trojan 协议一致）；**TLS 后置**
  （本期明文 trojan，文档明说；`client_config` 等 TLS 原语本期不用）；
- 认证失败时服务端关闭连接，客户端表现为后续 I/O 错误（无专用错误变体，
  这是协议语义不是缺失）。
- 数据面为明文 2 字节成帧（与 SOCKS5 期一致；QUIC 载荷仍是 E2E 密文，
  X2 对载荷依然成立）。

**T3（密码学不重写）**：AEAD 加解密与握手编解码**只**调用 outbound
crates 的公开原语；本 crate 不准出现 `ChaCha20Poly1305`/`Hkdf`/`Sha224`
的直接调用（`cargo` 依赖图中它们只经 outbound crates 传递）。
`SsMethod` 直接复用 `nexus-outbound-shadowsocks::SsMethod`
（本期冻结 `chacha20-ietf-poly1305`，与 `OutboundConfig` 校验一致）。

**T4（成帧统一 + 配置复用）**：
- 成帧：`framed.rs` 抽出公共 `FramedTransport`（原子 `recv_from` 语义、
  `read_buf`、`FRAME_HEADER_LEN + max_wire` 界，见知识库
  `2026-09-30-proxy-transport-atomic-recv`）；`ProxyTransport` 保持冻结的
  公开 API（`new`/`connect`/`target`/`counters`/`counters_handle` +
  `UdpTransport`），内部委托给 `FramedTransport`，零行为变化。
  `FramedTransport::new(stream, target)` 的 `max_wire` 按传输取
  1200（socks5/trojan）或 1228（ss）。
- 配置：`SsProxyConfig { server: SocketAddr, method: SsMethod, password: String,
  connect_timeout, handshake_timeout }`；
  `TrojanProxyConfig { server: SocketAddr, password: String,
  connect_timeout, handshake_timeout }`；
  两者提供 `TryFrom<&OutboundConfig>`（plan 决策④）：校验
  `kind == Shadowsocks/Trojan`、非空 password、合法 method、
  `locator` 解析为 `SocketAddr`（**必须为 `IP:port`**；域名 locator
  返回 `BadConfig`——域名解析是 egress/选路层职责，transport 不做 DNS）。
  失败为 `ProxyError::BadConfig(String)`（可重试语义：修配置）。

**T5（sync）**：全同步 std，零 tokio。`SsStream`/`encode_request` 均为同步
原语；`Mutex<SsStream>` 只为满足 `send_to(&self)` 签名，driver 单线程
独占使用，锁竞争可忽略（X5 延续）。

**T6（可观测）**：`SsTransport`/`TrojanTransport` 各自持有独立 `Counters`
（与 X6 同构：`(handshake_ok, handshake_err, framed_bytes)`）；
`proxy_handshake_ok{proto}` 的 proto 由传输类型隐含（实例级计数）。
ss 的 `handshake_ok=1` 要求 ack 确认帧校验通过；trojan 的
`handshake_ok=1` 表示请求头已完整写出（无确认帧是协议语义）。

**T7（Trojan over TLS，2026-10-01 冻结）**：在 T2 明文 trojan 之上叠加标准
TLS，兼容真实 trojan 服务器：
- 建连顺序：TCP connect → TLS 握手（rustls 0.23 + ring）→ 在 TLS 隧道内
  写 `encode_request(password, target)`（T2 握手字节不变）→ 2 字节成帧
  （T4，帧在 TLS 内明文，与标准 trojan 一致）；
- `TrojanTlsConfig { server: SocketAddr, password: String, sni: String,
  skip_cert_verify: bool, alpn: Vec<Vec<u8>>, connect_timeout,
  handshake_timeout }`；
  - `sni`：TLS SNI（通常为服务器域名；IP 直连时可用 IP 字符串）；
  - `skip_cert_verify = false`（默认）：用系统根证书校验（rustls
    `with_native_roots`）；`= true`：跳过证书链/主机名校验（仍校验
    握手签名，复用 `nexus-outbound-trojan::client_config_dangerous_skip_verify`），
    仅用于自签/内网节点；
  - `alpn`：下发 ALPN 列表（trojan 标准为 `["h2"]` 或空；可配置）；
- `tls = false` 时回落到 T2 明文模式（`TrojanTransport` 行为零变化）；
- 密码学不重写（T3 延续）：TLS 配置构造只调用
  `nexus-outbound-trojan` 的 `client_config_dangerous_skip_verify` 等公开原语；
- 可观测（T6 延续）：`TlsTrojanTransport` 独立 `Counters`；
  `handshake_ok=1` 表示 TLS 握手 + 请求头写出完成；
- 同步 std（T5 延续）：rustls `Stream` 同步 API，无 tokio。

### T 期诚实边界

- ~~trojan over TLS 后置（本期明文握手+明文成帧，E4 与文档明说）；~~
  T7 已实现 trojan over TLS；T2 明文模式保留用于测试/内网。
  UDP ASSOCIATE 后置。
- ss 会话无随机 salt（复用 `SsStream` 固定计数器 nonce 设计），线格式与
  公网 ss 不兼容；**与公网 ss 服务的互操作未验证，不得宣称**。
  trojan over TLS（T7）与真实 trojan 服务器的互操作需 E4 验证后方可宣称。
- trojan 2 字节长度前缀明文（与 SOCKS5 期一致），载荷 AEAD 仅 ss 有；
  长度隐藏后置。
- E4 只在 xc-pc-linux 真机（Linux）；沙箱 TCP 需 per-destination 审批。

## Side Effects

- TCP 连接（到 SOCKS5 服务器）。
- 无后台线程（握手与收发全是调用方线程的阻塞调用）。

## Public API

```rust
// X 期（冻结，零改动）
pub struct Socks5ProxyConfig { pub server: SocketAddr, pub auth: Option<Socks5Auth>, pub connect_timeout: Duration, pub handshake_timeout: Duration }
pub struct Socks5Auth { pub username: String, pub password: String }
pub enum ProxyError { Io(io::Error), NoAcceptableAuth, AuthFailed, ConnectRejected(u8), BadReply(&'static str), FrameTooLarge(usize), FrameOverflow { frame: usize, buf: usize },
    // T 期新增：
    BadConfig(String),                 // TryFrom<&OutboundConfig> 失败（kind/locator/method/password）
    SsCrypto(nexus_outbound_shadowsocks::OutboundCipherError), // ss 握手/数据面 AEAD 失败
}
pub const MAX_DATAGRAM: usize = 1200;
pub const FRAME_HEADER_LEN: usize = 2;
pub fn socks5_connect(config: &Socks5ProxyConfig, target: SocketAddr) -> Result<TcpStream, ProxyError>;
pub struct ProxyTransport { /* 内部委托 FramedTransport；公开 API 冻结不变 */ }
impl ProxyTransport {
    pub fn new(stream: TcpStream, target: SocketAddr) -> Self;
    pub fn connect(config: &Socks5ProxyConfig, target: SocketAddr) -> Result<Self, ProxyError>;
    pub fn target(&self) -> SocketAddr;
    pub fn counters(&self) -> (u64, u64, u64);
    pub fn counters_handle(&self) -> Counters;
}
impl nexus_fabric::UdpTransport for ProxyTransport { /* recv_from / send_to / set_read_timeout / local_addr */ }

// T 期新增（T4）
pub use nexus_outbound_shadowsocks::SsMethod; // 复用，不重定义
pub struct FramedTransport { /* 共享成帧核心：Mutex<TcpStream> + read_buf + max_wire */ }
impl FramedTransport {
    pub fn new(stream: TcpStream, target: SocketAddr) -> Self; // max_wire = 1200
    pub fn with_max_wire(stream: TcpStream, target: SocketAddr, max_wire: usize) -> Self;
    pub fn target(&self) -> SocketAddr;
    pub fn counters(&self) -> (u64, u64, u64);
    pub fn counters_handle(&self) -> Counters;
}
impl nexus_fabric::UdpTransport for FramedTransport { /* 与 X 期 ProxyTransport 相同的原子成帧语义 */ }
pub const MAX_SEALED_FRAME: usize = 1228; // MAX_DATAGRAM + 28（ss seal 开销）

// T1
pub struct SsProxyConfig { pub server: SocketAddr, pub method: SsMethod, pub password: String, pub connect_timeout: Duration, pub handshake_timeout: Duration }
impl SsProxyConfig {
    pub fn new(server: SocketAddr, method: SsMethod, password: String) -> Self; // 10s 默认超时
}
impl TryFrom<&nexus_proxy_config::OutboundConfig> for SsProxyConfig { type Error = ProxyError; /* T4 */ }
pub fn ss_connect(config: &SsProxyConfig, target: SocketAddr) -> Result<TcpStream, ProxyError>; // 握手后的裸流（SsStream 已消费？见实现注）
pub struct SsTransport { /* FramedTransport + Mutex<SsStream> */ }
impl SsTransport {
    pub fn connect(config: &SsProxyConfig, target: SocketAddr) -> Result<Self, ProxyError>;
    pub fn target(&self) -> SocketAddr;
    pub fn counters(&self) -> (u64, u64, u64);
    pub fn counters_handle(&self) -> Counters;
}
impl nexus_fabric::UdpTransport for SsTransport { /* send_to: seal→成帧；recv_from: 解帧→open */ }

// T2
pub struct TrojanProxyConfig { pub server: SocketAddr, pub password: String, pub connect_timeout: Duration, pub handshake_timeout: Duration }
impl TrojanProxyConfig {
    pub fn new(server: SocketAddr, password: String) -> Self;
}
impl TryFrom<&nexus_proxy_config::OutboundConfig> for TrojanProxyConfig { type Error = ProxyError; /* T4 */ }
pub fn trojan_connect(config: &TrojanProxyConfig, target: SocketAddr) -> Result<TcpStream, ProxyError>;
pub struct TrojanTransport { /* 内部 FramedTransport；明文成帧 */ }
impl TrojanTransport {
    pub fn connect(config: &TrojanProxyConfig, target: SocketAddr) -> Result<Self, ProxyError>;
    pub fn target(&self) -> SocketAddr;
    pub fn counters(&self) -> (u64, u64, u64);
    pub fn counters_handle(&self) -> Counters;
}
impl nexus_fabric::UdpTransport for TrojanTransport { /* 委托 FramedTransport */ }
```

实现注：`ss_connect` 返回的 `TcpStream` 其 ss 会话（`SsStream`）必须由
`SsTransport` 持有（数据面每 datagram 要 seal），因此 `ss_connect` 为
`pub(crate)` 还是 `pub` 待实现阶段按最小 API 面决定；契约只冻结
`SsTransport::connect` 的行为。

API 面最小化：`stream`/`ss` 字段不暴露；计数器只读。

## Verification

- P-U-1 单测：RFC 1928 握手向量（无认证/用户名密码/拒绝）、成帧 roundtrip、
  超限拒绝（>1200）、截断帧/坏前缀的错误路径。
- P-E-1 E4（`examples/proxy_quic.rs`）：自研最小 SOCKS5 server → A 经代理
  CONNECT 到 B → `connect_with_transport` 建 QUIC → 64KB 回显 →
  断言 `proxy_relayed_bytes > 0`。见 `scenarios/product/proxy_transport.toml`。
- P-V-1 回归：fabric 现有 E4 不受影响（S9 默认路径 `StdUdpTransport` 零行为变化）。
- P-U-2 单测（T 期）：`FramedTransport` 成帧 roundtrip/超限/原子 recv
  （与 X 期同语义，`ProxyTransport` 委托后行为不变）；
  `TryFrom<&OutboundConfig>` 转换：合法 ss/trojan 配置、错 kind、
  空 password、非法 method、域名 locator→`BadConfig`；
  ss 握手：错密码 ack 打不开（`SsCrypto(DecryptFailed)`）；
  trojan 请求头写出字节（明文，无确认帧语义）。
- P-E-2 E4（`examples/proxy_ss_quic.rs`，`scenarios/product/proxy_transport_ss.toml`）：
  自研最小 ss server（`read_record`→`open`→`parse_request` 得目标→回
  `seal(b"ss-proxy-ok")`→解密后中继成帧字节到 B）→ A 经 ss 建 QUIC 到 B →
  64KB 回显 → 断言 `proxy_relayed_bytes > 0`（T1/T6）且
  `proxy_saw_plaintext_bytes == 0`（T3/X2：server 只见 AEAD 记录与 QUIC 密文）。
- P-E-3 E4（`examples/proxy_trojan_quic.rs`，`scenarios/product/proxy_transport_trojan.toml`）：
  自研最小 trojan server（读请求头→`parse_request`→`AuthDenied` 则关闭连接→
  明文双向中继到 B）→ A 经 trojan 建 QUIC 到 B → 64KB 回显 →
  断言 `proxy_relayed_bytes > 0` 且 `proxy_saw_plaintext_bytes == 0`
  （T2/T6；明文的是握手头与 2 字节长度前缀，QUIC 载荷仍是密文）。
- P-V-2 回归：P-E-1（SOCKS5）E4 与全部单测在实现后仍 PASS
  （`FramedTransport` 抽取不得改变 `ProxyTransport` 行为）。

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

## 配置来源说明

### SOCKS5（X 期）

Plan 决策③“复用现有 outbound SOCKS5 结构”的前提不成立：实际核查
`nexus-proxy-config` 的 `OutboundKind` 只有
Direct/Relay/Shadowsocks/Vmess/Trojan，**没有 SOCKS5 变体**
（SOCKS5 只存在于 inbound/ingress）。因此本 crate 自带最小
`Socks5ProxyConfig`（server + 可选 auth + 超时），不碰
`nexus-proxy-config`。待 PathManager fallback 联动（后置阶段）时再统
一接入共享出站配置。本修正在此文档化，非静默偏离。

### ss/trojan（T 期，plan 决策④）

`OutboundKind::Shadowsocks`/`Trojan` 真实存在且字段完备
（`locator`/`method`/`password`），因此 `SsProxyConfig`/
`TrojanProxyConfig` 提供 `TryFrom<&OutboundConfig>` 复用其**结构**
（T4）。注意层归属不变（X3）：这是配置结构复用，不是把 per-flow
egress 语义并入 per-link transport；`OutboundAdapter` trait 仍不使用。
