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
3b-4（真实 UDP Egress：egress 节点真实 socket + 回包反向 NAT）已完成。
3b-5（TCP Egress：originator smoltcp 终结 + fabric 字节流 + egress TcpStream 中继）进行中。

## Non-Responsibilities

- 不做用户态 TCP 栈（§6.1 阶段二，远期用 smoltcp）。
- 不做 SOCKS5/HTTP 语义入口（`nexus-ingress` 已有解析器，3b 后续）。
- 不做进程归因/QoS（平台相关，后置）。
- 不做 TUN 设备路由决策的旧模型（`nexus-proxy/tun.rs` 的 `selected_outbound_tag`
  被 `RouteTarget` 取代）。
- 不做 QUIC 传输（`nexus-fabric`）、路径选择（`nexus-path`）。
- 不做跨节点 Egress（3b-2，已完成）。
- 3b-3 做域名规则（DNS 嗅探 + 域名→出口映射 + 解析缓存，已完成）。
- 3b-4 做真实 UDP Egress（egress 节点真实 socket + 回包反向 NAT，已完成）。
- 3b-5 做 TCP Egress（originator smoltcp 终结 + fabric 字节流 + egress TcpStream 中继）。

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
- `nexus-ingress`（SOCKS5/HTTP 代理协议状态机；仅解析器，零 I/O）
- `nexus-path`（`PathManager` / `PathEvent`；联动胶水所需，见 S27）

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

**S21（TCP 终结）**：originator 收到路由到 `Egress{peer}` 的 TCP SYN 时，
用 smoltcp 在本地完成三次握手（SYN→SYN-ACK→ACK），应用无感知。
握手完成前应用数据不转发；首包非 SYN（无连接状态的 ACK/数据）丢弃并计数
（`tcp_no_conn_dropped`）。IP 目标在送入 smoltcp 前改写为接口地址，
真实目标记在流表（stream_id → 真实目标）中。

**S22（字节流中继）**：ESTABLISHED 连接的应用字节经 fabric STREAM 意图
数据报（意图值 `0x02`，帧格式：stream_id u32be + flags u8 + 数据；
SYN 帧附带真实目标 ip:port）发往 egress 节点；egress 节点用 `TcpStream`
连接真实目标，双向中继字节。stream_id 全局唯一（AtomicU64），
连接表上限 1024，满时拒绝新 SYN 并计数（`tcp_table_full`）。

**S23（连接生命周期）**：任一端 FIN → 对端对应半关闭/全关闭；
RST/错误 → 对端 RST；smoltcp 侧 socket 关闭 → 发 FIN 帧；
egress 侧 TcpStream EOF/错误 → 发 FIN/RST 帧。半开连接（SYN 已收、
30s 未 ESTABLISHED）回收并计数（`tcp_half_open_expired`）。
`close()` 时关闭所有流并 join 中继线程。

**S24（真实 TUN 设备）**：`TunRsDevice` 实现 `TunDevice` trait，基于
`tun-rs` v2 的 sync API（`default-features = false`，不启用任何 async
feature）。`TunRsDevice::create(name, mtu)` 创建真实 TUN 设备；
`read`/`write`/`name` 语义与 `TunDevice` 一致（read 返回完整 IP 包，
write 写入完整 IP 包）。`MockTun` 保留用于 E4（无特权环境）；
`TunRsDevice` 用于 E5（需 CAP_NET_ADMIN/root）。IP地址分配、路由表、
DNS 配置**不在**本阶段范围（P3.x 后置边界，见 2026-09-29 冻结决策）。
创建失败（无特权）时返回 `io::Error`，调用方可降级为 SKIP。

**S25（语义入口）**：`SemanticIngress::bind(addr)`（std `TcpListener` +
accept 线程，sync，零 tokio）把 SOCKS5/HTTP 显式代理映射为 fabric 流：
- 握手复用 `nexus-ingress` 的 `Socks5Handshake` / HTTP 代理状态机（零
  I/O 纯函数）；首字节嗅探：`0x05` → SOCKS5，否则按 HTTP 请求行解析。
  BIND / UDP ASSOCIATE / plain HTTP absolute-form（非 CONNECT）显式拒绝。
- 握手成功得 `destination`（host:port，host 可为域名或 IP）→ 经
  `UnifiedRouter` 走**同一条**统一决策链（与 TUN 一致）：
  - `Egress{self}` → 本地 `TcpStream::connect`（DIRECT 语义；域名本地解析）；
  - `Egress{peer}` → fabric STREAM 意图 `0x02` 向 peer 发 SYN；
  - `Drop` → SOCKS5 回复 `0x02` / HTTP 回 `403`，计数 `ingress_dropped`。
- SYN 载荷（S22 扩展）：首字节 addr-type（`0x01`=IPv4 后跟 4 字节，
  `0x03`=域名 后跟 1 字节长度 + 域名），最后 2 字节 port（u16be）。
  兼容：载荷长 6 字节时按 3b-5 旧格式（IPv4+port）解析。originator 自 3d
  起统一用 typed 形式。egress 侧收到域名形式 → 解析（走 S17 缓存）→
  `TcpStream` 连接目标 → 复用 S22 中继。域名不在 originator 本地解析
  （避免审查环境 DNS 泄漏/污染）。
- 中继：client socket ⟷ fabric stream（`Egress{peer}`）或 ⟷ 本地
  `TcpStream`（`Egress{self}`）双向字节中继；任一端 EOF/错误 → 关闭对端。
- 握手失败 → 协议错误响应 + 计数 `ingress_handshake_errors`，关闭连接。
- 统计：`ingress_accepted` / `ingress_dropped` /
  `ingress_handshake_errors` / `ingress_egress_local` /
  `ingress_egress_remote`。

**S26（进程归因与 QoS 标记）**：流建立时对本机 socket 做一次进程归因，
结果按流缓存为 `FlowLabels` 随流元数据往下传（标记，不做排队调度）：
- `ProcessAttributor` trait：`attribute(local, remote, proto) -> Attribution`；
  `Attribution { pid: Option<u32>, process_name: Option<String> }`，
  查不到时为 unknown（`None`），不阻塞、不重试。
- Linux 实现（`#[cfg(target_os = "linux")]`，std-only，解析 `/proc`）：
  `/proc/net/tcp` + `/proc/net/udp`（P0 仅 IPv4；tcp6/udp6 后置）→
  按 (local, remote) 五元组找 socket inode → 遍历 `/proc/<pid>/fd/*`
  symlink 找 `socket:[inode]` → 读 `/proc/<pid>/comm` 得进程名。
- Windows 实现（`#[cfg(target_os = "windows")]`，W-PROCATTR，2026-10-01 冻结）：
  `WindowsProcessAttributor`，经 iphlpapi 窄手写 FFI（`GetExtendedTcpTable` /
  `GetExtendedUdpTable`，`TCP_TABLE_OWNER_PID_ALL` / `UDP_TABLE_OWNER_PID`），
  不引入第三方 crate（与 `nexus-platform-windows` 的 wintun/dpapi 手写 extern
  模式一致）。按 (local, remote) 五元组精确匹配找 `dwOwningPid` → 经
  kernel32 Toolhelp32 快照（`CreateToolhelp32Snapshot` / `Process32FirstW` /
  `Process32NextW`）取 exe 文件名。P0 仅 IPv4；IPv6 后置。
  任何失败（表查询失败、五元组无匹配、快照失败、进程已退出）→
  `Attribution::unknown()`，不 panic、不阻塞。归因在流建立时做一次，
  不做 per-packet 归因，不做缓存（与 Linux 实现同复杂度）。
  非 Linux/Windows 用 `NoopAttributor`（恒返回 unknown）；WFP 仍后置。
- `PlatformAttributor`：Linux → `LinuxProcessAttributor`；Windows →
  `WindowsProcessAttributor`；其余 → `NoopAttributor`。
- `QosClass`：`High` / `Normal` / `Low` / `Background`；
  `QosConfig`：进程名精确匹配 → 类（P0；glob/正则后置）；
  无规则命中或 unknown → `Normal`。
- 接入点：TUN 路径 TCP/UDP 流创建时（五元组查本机 socket）、语义入口
  accept 成功时（对端 socket 归因）。归因失败绝不影响流建立。
- 不做：per-packet 归因、按类排队调度（会话层/路径层尚无排队机制，后置）、
  IPv6、Windows WFP（iphlpapi 已覆盖 P0 需求，WFP 仍后置）。

**S27（路径联动）**：`PathLink` 拥有 `PathManager` + peer→`FabricConn`
映射（依赖倒置：nexus-path 只发事件，联动胶水在 projection，见 S9）：
- `pump()`：排空 `poll_event()`；在 `Switched{to, ..}` 时找到对应 peer
  的 `FabricConn` 并调用 `rebind()`（阻塞至新路径生效，CID 不变）。
- `rebind()` 成功 → 计数 `path_rebinds`；失败 → 计数
  `path_rebind_errors`，保持旧连接可用（S2：切换不丢连接——失败时不断开）。
- 无映射的 peer 事件 → 计数 `path_rebind_no_conn` 并忽略（不 panic）。
- E4 必须走生产 `pump()` 路径（教训：`2026-09-30-e4-must-use-production-path`），
  禁止手动调 `rebind()` 冒充联动。

**S28（Boost v1 胶水，2026-10-01 冻结）**：`boost.rs` 是 boost 配置到
`nexus-path` 的组合胶水（依赖倒置：`nexus-network` 只产出纯数据
`BoostPathParams`，本模块完成到 `PathConfig` 的映射与选路/建连策略）：
- `path_config_for_boost(hysteresis_pct, switch_hold_ms) -> PathConfig`：
  用给定参数构造 `PathConfig`（其余字段取 `Default`）。纯函数。
- `select_best(manager: &PathManager, candidates: &[CandidatePath], degrade_threshold: f64) -> Option<BoostSelection>`：
  EWMA 驱动选路（文档 §12.5）。**只读**：`&PathManager`，不修改任何状态
  （single writer 仍在 `nexus-path`，S7 不变）。选 `score()` 最高者；
  全 unknown（`None`）→ 返回 `None`。`BoostSelection { best, score, degraded }`，
  其中 `degraded = score < degrade_threshold`（阈值由调用方定，分数非归一化，
  见 nexus-path 打分公式注释）。
- `boost_connect(chain, connector, budget, race_on_connect) -> io::Result<RaceOutcome>`：
  `race_on_connect = true` → 调 `connect_with_fallback`（staggered 竞速，R1）；
  `= false` → 按候选顺序依次直连（首个成功即返回，无 staggering）。
  实际 dial 由注入的 `PathConnector` 完成（F2 语义不变）。
- 不变量：`select_best` 不触发切换（只读不决策，切换仍走 `PathManager` +
  S4/R3 hysteresis + S9 事件）；`boost_connect` 不改变 `RaceOutcome` 语义（R4）。

**S29（统一包分类器，2026-10-01 冻结）**：`classifier.rs` 是单个 TUN 的唯一包分类入口
（文档 §6/§11.2 数据面位置）。分类顺序：
1. 目的 IP 在 mesh CIDR 内 → `Mesh { path }`（N1；S10 fast path，规则引擎不介入）；
2. 目的 IP 在 fake-IP 池（`198.18.0.0/15`，见 nexus-dns S-unified）→ `Proxy`（送 proxy 规则引擎）；
3. 命中 bypass/白名单规则 → `Direct`（直连）；
4. 其余 → 规则引擎决策（`Proxy` / `Direct` / `Drop`）。
- 非 IPv4 或截断包 → `Drop`（S12 可见性不变）。
- 确定性：同一 5 元组在规则/路径状态不变时分类一致（类 S9）。
- **MVP 说明**：当前实现中第 4 步回落为恒 `Proxy`（完整规则引擎由调用方在外层接入，
  见 `classify` 注释）；`UnifiedRouter`（`routing.rs`）仍是带完整规则引擎的分类器，
  两者后续收敛。

**S30（EWMA 驱动 mesh 选路，2026-10-01 冻结）**：mesh 分类命中时，调用
`boost::select_best(manager, candidates, degrade_threshold)` 选 EWMA 最高分路径
（文档 §12.5）。**只读**：`&PathManager`，不修改任何状态（single writer 仍在
`nexus-path`，S7/S28 不变）。全 unknown → 路径为 `None`（回落默认 mesh 转发，
不阻塞）。`degraded == true` 时打 `warn` 日志（"mesh 路径质量劣化"），不自动切 proxy
（切路决策权在调用方/Boost）。

**S31（FlowContext 生成，2026-10-01 冻结）**：分类后生成统一 `FlowContext`
（`nexus-domain`），供 QoS/调度器使用：
- `origin = FlowOrigin::VirtualPacketInterface`（TUN/VPI 来源）；
- `destination` = 目的 IP 字符串（mesh/fake-ip）或域名（DNS 嗅探命中时）；
- `resource` = 按分类映射（Mesh → mesh resource，Proxy → proxy resource，Direct → direct resource）；
- `profile` = 调用方传入的使用画像（透传，不解析）。
- 纯函数，无副作用；`Drop` 分类不生成 FlowContext（调用方计数丢弃）。
**S32（多路径调度，2026-10-01 冻结）**：`multipath.rs` 是统一数据面的路径
调度胶水（文档 §12.6，独立高级选项，不进 boost 开关）：
- `MultipathStrategy`：`Single`（只用最优 egress，默认，零行为变化）/
  `PerFlow`（按流哈希固定 egress，流内有序）/ `PerPacket`（按包加权轮询）。
- `MultipathConfig { strategy, reorder_buffer }`：纯数据；`strategy` 默认
  `Single`，`reorder_buffer` 默认 64（per-packet 接收端重排上限）。
- `PathScheduler::select(strategy, egresses, flow_id, seq) -> Option<&EgressDescriptor>`：
  - `Single`：返回调用方排序首位的可用 egress（等价当前单路径行为）；
  - `PerFlow`：`flow_id % n`（`flow_id` 为调用方传入的 u64 流标识，通常是
    5 元组哈希；`flow_id_of` 辅助用 FNV-1a 计算），同一 `flow_id` 在 egress
    集合不变时永远选中同一 egress（确定性，流内有序）；
  - `PerPacket`：加权轮询（权重来自 `EgressDescriptor::weight()`，恒 `>= 1`）。
  - `select` 取 `&mut self`（`PerPacket` 的轮询游标是有状态的；`Single`/
    `PerFlow` 分支不修改状态）。
- `ReorderBuffer`（per-packet 接收端）：按 `seq` 缓冲乱序包，按序吐出；
  容量上限 `reorder_buffer`，超限丢弃最小 seq 并计数 `dropped_overflow()`，
  重复 seq 计数 `dropped_duplicate()`；内存有界（`O(reorder_buffer)`）。
- `EgressDescriptor` 字段私有，必须经 `new()` 构造（`weight=0` 钳位到 1）；
  F1 教训：公有字段允许结构体字面量绕过钳位，导致 `PerPacket` 除零 panic。
- 不变量：
  - `Single` 模式与无调度器行为一致（零回归）；
  - `PerFlow` 选择确定性：egress 集合与 `flow_id` 不变时结果不变；
  - 纯内存、纯同步、零真实网络；TUN/QUIC 接入点预留（`EgressKind`
    字段供未来映射到真实 egress）；
  - 不修改 `nexus-path` 的 S1（单活跃路径是路径层的 per-peer 不变量；
    本调度器工作在统一数据面 egress 选择层，是不同层级）。
- Deletion Test：若删除调度器抽象，让调用方手写 `match strategy` 分发，
  则三种策略的切换逻辑与重排缓冲泄漏到每个调用点；策略新增（如
  `PerPacketWeighted`）将要求改动所有调用方。抽象成立。

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

/// TCP 出口终结器：originator 侧用 smoltcp 终结 TCP，字节流经 fabric
/// STREAM 意图转发；egress 侧用 `TcpStream` 中继到真实目标（S21/S22/S23）。
pub struct TcpEgress { /* ... */ }

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
- E4: `product.fabric-egress-tcp`（3b-5：A 的 TUN 收到 TCP SYN →
  smoltcp 本地完成握手 → 应用字节经 STREAM 意图到 B →
  B 经 TcpStream 发往本地 echo 服务器 → 回字节经 STREAM 回 A →
  smoltcp 发到 A 的 TUN；FIN 双向关闭）
- 单元测试：S1 包完整、S5 超大包丢弃计数、S2 意图位开销、S9 路由确定性、
  S10 虚拟子网优先、S11 NAT 回包、S12 Drop 计数、S13 跳数验证、S14 NAT 上限、
  S15 DNS 嗅探无损（坏包/非 DNS 不丢包）、S16 域名优先（域名命中覆盖 IP 规则、
  无命中回退）、S17 解析缓存（响应建缓存、TTL 失效、容量驱逐、后续包继承）、
  S18 真实 socket 发送（发送失败计数不 panic、TCP 丢弃计数）、S19 回包反向
  NAT（无映射丢弃计数）、S20 socket 生命周期（close 关闭并 join 线程）、
  S21 TCP 终结（smoltcp 本地握手、首包非 SYN 丢弃计数）、S22 字节流中继
  （STREAM 意图帧、egress TcpStream 双向中继、表满拒绝计数）、S23 连接
  生命周期（FIN/RST 传播、半开回收、close 清理）、MockTun 集成

## Performance Budget

- 每包一次内存拷贝（TUN → fabric 载荷），无额外分配（复用缓冲）。
- 后台线程：阻塞读 TUN，无忙轮询。

## Observability

- `TunStats` 可查询。
- `dropped_oversize` 单独计数（MTU 问题诊断）。
- S30 degraded warn（`classifier.rs`）：`[classifier] warn: mesh 路径质量劣化
  (score={:?} < threshold={})`，经 `eprintln!` 输出。触发条件：mesh 分类命中且
  EWMA 最优分数低于 `degrade_threshold`。频率：仅 degraded 状态的每次分类时触发
  （非每包；正常路径无输出）。后续可迁移到结构化日志（当前 crate 无 log facade）。

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
