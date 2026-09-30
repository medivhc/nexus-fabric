# MODULE.md — nexus-projection

## Responsibility

投影层 L3 隧道 + 统一路由（DESIGN.md §6.4）：

1. **L3 隧道**：把 TUN 设备抓到的 IP 包封装进 fabric 数据报，对端解封装后
   注入其 TUN 设备。应用无需修改，用标准 socket API。
2. **统一路由**（Phase 3b-1 新增）：每个包经 `Router` 决策为 `RouteTarget`
   （`MeshPeer` / `Egress` / `Drop`），Clash TUN 与 EasyTier TUN 在此融合。
3. **本地出口 NAT**（Phase 3b-1 新增）：`Egress{self}` 的 UDP NAT（含连接跟踪）。

P0 不做：TCP NAT（依赖 L4 中继）、
语义入口（§6.2）、进程 QoS（§6.3）。
3b-2（跨节点 Egress + 跳数防环 + NAT 上限）已完成。
3b-3（域名规则：DNS 嗅探 + 域名→出口映射 + 解析缓存）已完成。
3b-4（真实 UDP Egress：egress 节点真实 socket + 回包反向 NAT）进行中。

## Non-Responsibilities

- 不做用户态 TCP 栈（§6.1 阶段二，远期用 smoltcp）。
- 不做 SOCKS5/HTTP 语义入口（`nexus-ingress` 已有解析器，3b 后续）。
- 不做进程归因/QoS（平台相关，后置）。
- 不做 TUN 设备路由决策的旧模型（`nexus-proxy/tun.rs` 的 `selected_outbound_tag`
  被 `RouteTarget` 取代）。
- 不做 QUIC 传输（`nexus-fabric`）、路径选择（`nexus-path`）。
- 不做跨节点 Egress（3b-2，已完成）。
- 3b-3 做域名规则（DNS 嗅探 + 域名→出口映射 + 解析缓存，已完成）。
- 3b-4 做真实 UDP Egress（egress 节点真实 socket + 回包反向 NAT）。

## Inputs

- TUN 设备读到的原始 IP 包（IPv4/IPv6）。
- 对端发来的 fabric 数据报（载荷为原始 IP 包）。
- `FabricConn`（发送数据报）、`PathManager`（路径切换通知）。
- `Router`（统一路由决策，`routing.rs`）。

## Outputs

- 封装好的 fabric 数据报（载荷 = 1 字节意图位 + 原始 IP 包）。
- 注入本地 TUN 设备的 IP 包。
- 经 NAT 出口的 UDP 包（`Egress{self}`）。
- 统计：`TunStats { packets_in, packets_out, bytes_in, bytes_out }` +
  `RouteStats { mesh_peer, egress_self, egress_remote, dropped }`。

## Allowed Dependencies

- `std` only（零 Tokio）
- `nexus-domain`（`RouteTarget`、`RouteRequest`、`RuleEngine`）
- `nexus-fabric`（`FabricConn::send_datagram` / `recv_datagram` 类型）
- `nexus-path`（`PathManager` 事件类型，仅类型）

## Forbidden Dependencies

- `tokio`, 任何 async runtime
- `nexus-proxy`（旧规则引擎；新决策经 `nexus-domain::RuleEngine` trait）
- 手写平台 TUN FFI（用户决策 2026-09-30：用 `tun-rs` v2 跨平台库，
  不重复造轮子。`TunDevice` trait 保留，`TunRsDevice` 包装 `tun-rs::SyncDevice`）

## Invariants

**S1（包完整）**：TUN → fabric → TUN 全程，IP 包字节级一致（IP 头 + 载荷）。

**S2（意图位开销）**：fabric datagram 载荷 = 1 字节意图位 + 原始 IP 包。
（§6.4 修订：P0 的零开销原则让位于统一路由的最小代价。）

**S3（尽力语义）**：继承 fabric datagram 的尽力语义；丢包不重传、不保证顺序。
（TCP 的可靠性由端到端 TCP 自己保证。）

**S4（双向对称）**：同一 `Projection` 实例同时做封装（出）和解封装（入）；
两个方向独立统计。

**S5（MTU 诚实）**：IP 包超过 fabric datagram 上限时，**丢弃并计数**，
不静默截断、不分片（P0）。`stats.dropped_oversize` 可见。

**S6（设备抽象）**：`TunDevice` trait 隔离 OS 相关；E4 用 `MockTun`
（内存环形缓冲），E5 才用真实设备。核心逻辑不依赖真实 TUN。

**S7（关闭语义）**：`Projection::close()` 停止收发线程，丢弃未发送的包，
不保证投递。

**S8（统计诚实）**：`TunStats` 只计实际读/写成功的包；mock 和真实设备
用同一统计代码。

**S9（路由决策确定性）**：同一 5 元组的包在规则不变时路由决策一致
（`SimpleRuleEngine` 无状态；首包决策可缓存，参考 `tun-dataplane` 的
5 元组缓存模式）。

**S10（虚拟子网优先）**：目的 IP 在虚拟子网内时**不经过规则引擎**，
直接 FIB → `MeshPeer`（fast path）。规则引擎只处理互联网流量。

**S11（NAT 回包正确）**：`Egress{self}` 的 UDP NAT 回包必须能路由回源 TUN，
连接跟踪表 120s 无活动回收，超时后回包丢弃并计数。

**S12（Drop 可见）**：`RouteTarget::Drop` 的包丢弃并计数（`route_dropped`），
不静默消失。

**S13（跳数验证）**：接收侧在处理 egress 意图包之前必须验证跳数
（意图位 bit 2-5）。跳数超过 `max_egress_hops`（默认 2）时丢弃并计数
（`hop_limit_exceeded`），不转发、不入 NAT 表。防止 A→B→A 环路无限转发。

**S14（NAT 表上限）**：`EgressNat` 表项数不超过 `max_entries`（默认 65536）。
满时丢弃最旧表项（LRU）并计数（`evicted`），保证新流不被洪水完全堵死。

**S15（DNS 嗅探无损）**：DNS 查询/响应包的嗅探**不修改包内容**，只提取信息
（查询包的 QNAME、响应包的 A/AAAA 记录）。嗅探失败（非 DNS 载荷、解析错误、
截断包）时按普通包走 IP 规则，**不丢包**、不计数为错误（`dns_sniff_failed`
仅调试计数）。

**S16（域名规则优先）**：`RouteRequest.domain` 为 Some 时，域名规则（后缀/
精确/关键字）**优先于** IP/CIDR/端口规则匹配；域名无命中时回退到 IP 规则。
同一域名在规则不变时决策一致（确定性，类 S9）。

**S17（解析缓存继承）**：DNS 响应中的 A/AAAA 记录写入 `domain → IP` 缓存；
后续发往缓存 IP 的非 DNS 包自动填充 `domain`，继承该域名的路由决策。
缓存项 TTL 上限 300s（取 DNS TTL 与 300s 的较小值），超时失效；缓存上限
4096 项，满时驱逐最旧并计数（`dns_cache_evicted`）。DNS 响应包本身按查询
域名的规则决策（保证查询与响应路径一致）。

**S18（真实 socket 发送）**：egress 节点收到 egress 意图包后，经真实
`UdpSocket` 把 UDP 载荷发往互联网目标（源地址为 egress 节点）。发送失败
计数（`egress_send_failed`），不 panic；NAT 记录已建则保留（重传可达）。
P0 只处理 UDP；TCP 包到达真实 egress 时丢弃并计数（`egress_tcp_dropped`）。

**S19（回包反向 NAT）**：socket 收到的回包必须经 NAT 表反查到源 peer；
无映射的包丢弃并计数（`reply_dropped` 复用 S11），不盲目转发、不猜测目标。
回包经 transport 发回源 peer，意图位为 mesh（非 egress）。

**S20（Socket 生命周期）**：`UdpSocket` 由 egress 模块拥有，随 `Projection`
创建而绑定、随 `close()`/`Drop` 而关闭；接收线程阻塞在 `recv_from`，
关闭时通过 socket 关闭唤醒并 join。线程只持有 Arc clone，不阻止 Drop。

## Side Effects

- TUN 设备读写（`TunDevice::read` / `write`）。
- 后台收发线程（owner：`Projection`，Drop 时 join）。
- fabric datagram 收发（经 `FabricConn`）。

## Public API

```rust
pub trait TunDevice: Send {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize>;
    fn write(&mut self, packet: &[u8]) -> io::Result<usize>;
    fn name(&self) -> &str;
}

/// 数据报传输抽象：按 peer 名发送/接收。实现由组装方注入
/// （`apps/nexus` 用真实 FabricConn，测试用 mock）。
/// Projection 永不直接依赖 nexus-fabric 的连接管理。
pub trait DatagramTransport: Send + Sync {
    fn send_to(&self, peer: &str, data: &[u8]) -> Result<(), TransportError>;
    fn recv(&self) -> Option<(String, Vec<u8>)>;  // (from_peer, data)
}

/// 统一路由决策器：虚拟子网 fast path + 规则引擎。
pub trait Router: Send + Sync {
    fn route(&self, req: &RouteRequest) -> RouteTarget;
}

/// P0 最小规则引擎：IP/CIDR/端口规则。
/// 3b-3 扩展：域名后缀/精确/关键字规则（域名优先于 IP，S16）。
pub struct SimpleRuleEngine { /* ... */ }

/// DNS 嗅探器：从 UDP 包中提取 QNAME（查询）/ A-AAAA 记录（响应）。
/// std-only 最小 wire 解析，无外部依赖（S15）。
pub struct DnsSniffer { /* ... */ }

/// 域名→IP 解析缓存：TTL + 容量上限（S17）。
pub struct DnsCache { /* ... */ }

/// 真实 UDP 出口：拥有一个 `UdpSocket`，把 egress 意图包的 UDP 载荷发往
/// 互联网，并把回包反向 NAT 后交回 transport（S18/S19/S20）。
pub struct RealUdpEgress { /* ... */ }

/// 本地出口 UDP NAT（Egress{self}）。
pub struct EgressNat { /* ... */ }

/// 内存 mock，用于 E4（无权限需求）。
pub struct MockTun { /* 环形缓冲 */ }

pub struct ProjectionConfig {
    pub mtu: usize,  // fabric datagram 上限，默认 1400
}

pub struct TunStats {
    pub packets_in: u64,
    pub packets_out: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub dropped_oversize: u64,
}

pub struct Projection { /* ... */ }

impl Projection {
    /// 创建投影：tun 提供包源/汇，fabric 提供传输。
    /// P0：fabric 以 trait 抽象（MockFabric），不直接依赖 nexus-fabric 具体类型。
    pub fn new(tun: Box<dyn TunDevice>, config: ProjectionConfig) -> Self;
    /// 注入一个要发送的 IP 包（测试/E4 用；正常路径由后台线程从 TUN 读）。
    pub fn send_packet(&mut self, packet: &[u8]) -> Result<(), ProjectionError>;
    /// 取出一个收到的 IP 包（测试/E4 用；正常路径由后台线程写入 TUN）。
    pub fn recv_packet(&mut self) -> Option<Vec<u8>>;
    pub fn stats(&self) -> TunStats;
    pub fn close(self);
}
```

**注**：P0 的 `Projection` 先不绑定真实 `FabricConn`，用内部队列模拟
fabric 传输（E4 验证封装逻辑）；与 fabric 的真实接线是下一步（需要
`FabricConn` 的 datagram API 稳定）。

## Verification

- E4: `product.fabric-projection-basic`（包完整、双向）
- E4: `product.fabric-projection-roam`（路径切换时包不丢——P0 用 mock
  路径事件，验证切换通知处理）
- E4: `product.fabric-egress-basic`（TUN 包 → 规则匹配 → Egress{self} →
  UDP NAT → 回包验证）
- E4: `product.fabric-egress-remote`（TUN 包 → Egress{peer} → 对端 NAT →
  回包，mock peer）
- E4: `product.fabric-egress-domain`（3b-3：DNS 查询嗅探 → 域名规则命中 →
  Egress{peer}；DNS 响应建缓存；后续发往解析 IP 的包继承域名决策；
  域名无命中回退 IP 规则；嗅探失败不丢包）
- E4: `product.fabric-egress-real-udp`（3b-4：A 经 Egress{B} 发 UDP 包 →
  B 经真实 socket 发往本地 echo 服务器 → 回包经 B 的 NAT 反查 →
  transport 发回 A → A 的 TUN 收到回包；无 mock 回包）
- 单元测试：S1 包完整、S5 超大包丢弃计数、S2 意图位开销、S9 路由确定性、
  S10 虚拟子网优先、S11 NAT 回包、S12 Drop 计数、S13 跳数验证、S14 NAT 上限、
  S15 DNS 嗅探无损（坏包/非 DNS 不丢包）、S16 域名优先（域名命中覆盖 IP 规则、
  无命中回退）、S17 解析缓存（响应建缓存、TTL 失效、容量驱逐、后续包继承）、
  S18 真实 socket 发送（发送失败计数不 panic、TCP 丢弃计数）、S19 回包反向
  NAT（无映射丢弃计数）、S20 socket 生命周期（close 关闭并 join 线程）、
  MockTun 集成

## Performance Budget

- 每包一次内存拷贝（TUN → fabric 载荷），无额外分配（复用缓冲）。
- 后台线程：阻塞读 TUN，无忙轮询。

## Observability

- `TunStats` 可查询。
- `dropped_oversize` 单独计数（MTU 问题诊断）。

## Recovery Semantics

- `Projection` Drop 时 join 后台线程。
- `close()` 显式停止；未发送的包丢弃。

## Platform Constraints

- `MockTun` 纯 std，无平台代码。
- 真实 TUN（E5）：用 `tun-rs` v2（sync API，`default-features = false`，
  不启用 `async`/`async_io`）。跨平台：Linux/macOS/Windows/Android/iOS。
  Windows 需 wintun.dll 随二进制分发；iOS/Android 用 `SyncDevice::from_fd`
  接管系统给的 fd。
- 引入 `tun-rs` 时需走依赖评审（license/security/portability），见 AGENTS.md §4。

## Deletion Test

**问题**：如果删除 `nexus-projection`，让应用直接调用 `nexus-fabric`
发 datagram，会破坏哪个独立变化维度？

**回答**：TUN 设备管理（创建、读写、MTU、权限）、统一路由决策
（虚拟子网 vs 规则引擎）、出口 NAT（连接跟踪）与传输机制（QUIC、
加密、路径）是独立变化的。操作系统升级 TUN 行为（如 Windows wintun
换驱动）或规则语法升级（如加域名规则）不应要求改动传输层。
删除该抽象会导致设备细节和路由策略泄漏到传输层。

**反例**：如果永远只有 SOCKS5 语义入口而不用 TUN，则该 crate 可删除。
但 P0 明确要 L3 隧道 + 统一路由，抽象成立。
