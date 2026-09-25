# nexus-connectivity Module Contract

## Responsibility

提供 Connectivity Evaluation、Link Establishment、NAT Traversal、Hole Punching、Assisted/Relay Fallback 与 Link State。

## Non-Responsibilities

不选择业务 Resource Provider，不拥有 Workspace/Compute 业务策略。

## Inputs

- 仅接受公开类型、DTO、trait、事件或稳定协议对象。
- 输入必须可被结构化验证；不得依赖未声明的全局隐式状态。

## Outputs

- 结构化 Result / Event / DTO。
- 失败必须保留可诊断原因，不以日志文本代替错误类型。

## Allowed Dependencies

- `nexus-delivery`
- `nexus-platform`

## Forbidden Dependencies

- `engineering/` 下的 Harness/Plugin。
- 未在 `policies/architecture.toml` 声明的 Nexus 内部 crate。
- Portable 模块中的平台专有 Framework/API。
- 通过“便利”依赖绕过公开领域边界。

## Invariants

- Evaluation 是低成本规划输入；Establishment 只在 Plan/Session 之后触发。
- 连接失败报告事实，由 Core Planner 决定替代 Plan。
- 双 trait 解耦（W2）：本层消费 `VirtualPacketInterface`（IP 包）与
  `PacketCarrier`（承载帧）两个独立注入 trait，只编排不实现。
- 认证门控（W7）：`send_frame(authenticated=false)` 直接拒绝，且不触碰
  carrier（未认证零发送、不改 Locator）。

## Side Effects

- 仅允许 Responsibility 所需且在架构层中明确归属的副作用。
- 新增副作用前必须更新本契约和 Scenario/Policy（如影响外部行为）。

## Public API

- 默认最小 surface：`private -> pub(crate) -> pub`。
- Public API 变更必须保持结构化、可版本化并有调用方验证。
- 已实现（阶段 B）：
  - `ConnectivityState`：NotAttempted / Establishing / Established{authenticated} / Failed{error}；
  - `EstablishmentRequest`（领域中立：session_tag + locator + 认证门控）；
  - `establish`：确定性纯函数（零 I/O），空 locator → InvalidLocator；`require_authenticated` 未认证 → AuthenticationRequired（W12，绝不进入 Established）；
  - `ConnectivityEvent` 序列（Establishing / Authenticated / Established / Failed）供 Owner 消费；
  - `ConnectivityError` 结构化错误面（delivery 层自持，不依赖领域错误）。
- 已实现（W2/W7 双 trait 编排）：
  - `ConnectivityRuntime`：注入 `Box<dyn VirtualPacketInterface>` +
    `Box<dyn PacketCarrier>`，提供 `bind_local` / `send_frame`（认证门控）/
    `receive_frame` / `read_ip_packet` / `write_ip_packet` / `local_locator`；
  - `ConnectivityError::Io` / `Invalid` 变体：`PlatformError` 结构化映射
    （保留 operation/message，不丢诊断原因）。

### 冻结契约（remote NAT/Relay P0，scenarios/product/remote_nat_relay_fallback_flow.toml）

- `LinkKind { Direct, Relay }`：候选链路类型（v9 §239：Direct 含 LAN/IPv6/Public Endpoint，Relay 为 DERP 类中继）。
- `LinkCandidate { kind, locator, setup_cost_ms }`：领域中立候选链路（激活顺序输入）。
- `trait LinkProbe { fn probe(&self, candidate: &LinkCandidate) -> Result<(), String> }`：
  候选可达性探测，由 Composition Root 以真实 I/O 实现；Connectivity 只做策略编排，零 I/O。
- `LinkActivationEvent { Attempting{kind,locator}, AttemptFailed{kind,locator,reason}, Established{kind,locator} }`：
  激活过程结构化事件（Worker 只发事件）。
- `LinkSelection { kind, locator, events }`：激活结果（选中链路 + 完整事件序列，可重放）。
- `LinkActivator<P: LinkProbe>`：`new(probe)` / `activate(direct: &LinkCandidate, relay: Option<&LinkCandidate>, require_authenticated: bool, authenticated: bool) -> Result<LinkSelection, ConnectivityError>`。
  激活顺序（v9 §243 P0 子集）：Direct 探测成功即选 Direct；Direct 失败且 Relay 可用 -> Relay 回退；
  全部失败 -> `NoLinkAvailable`；认证门控（W12）在**任何探测之前**拦截（未认证零探测、零发送）。
- `ConnectivityError` 新增变体：`NoLinkAvailable { attempted: Vec<LinkKind> }`。

冻结语义：激活失败只报告事实，不替换业务 Provider（由 Core Planner 生成替代 Plan）；
`activate` 是确定性策略编排（探测结果来自注入的 `LinkProbe`，不自行发起网络 I/O）；
NAT/中继场景的物理建连（组合根 transport::connect）发生在激活决策之后。

### 冻结契约（OutboundAdapter 接缝，PRODUCT §11.6）

- `trait OutboundAdapter`：一种真实出站协议实现（Direct / Relay / Shadowsocks）的领域中立接缝：
  - `fn outbound_kind(&self) -> &'static str`（"direct" / "relay" / "shadowsocks"）；
  - `fn tag(&self) -> &str`；
  - `fn handoff(&self, locator: &str) -> Result<OutboundHandoff, ConnectivityError>`（离线交接，零真实网络）。
- `OutboundHandoff { kind, tag, locator }`：离线交接结果 DTO。
- Deletion Test（AGENTS.md §12）成立：Shadowsocks 是首个带真实 AEAD 加解密的出站，与仅做
  可达性探测的 Direct/Relay 构成独立变化维度；DirectAdapter / RelayAdapter 复用既有
  `LinkProbe` 语义，`LinkActivator` / `LinkKind` / `LinkProbe` / `LinkSelection` 既有行为不变。
- trait 保持领域中立、可移植；具体 AEAD 加密实现位于 `nexus-outbound-shadowsocks`（portable=false）。

### 冻结契约（VirtualSubnet 静态路由 P1，PRODUCT §12.5）

- `VirtualSubnetTunnel` 新增 `routes: HashMap<dst_virtual_ip, next_hop_virtual_ip>` 静态路由表。
- 新增 `add_route(dst, next_hop) -> Result<(), ConnectivityError>`：next_hop 必须是已注册 peer，
  否则 `ConnectivityError::Invalid(ROUTE_NEXT_HOP_NOT_PEER)`。
- `send_ip_packet`：dst 非直连 Connected peer 时查 `routes[dst]`，把同一帧（原始 dst 不变）
  发给 next_hop；查不到 → `ConnectivityError::Invalid(NO_ROUTE_TO_DST)`。
- `recv_and_deliver`：dst 非本机时查 `routes[dst]` 重新封装同帧转发给 next_hop，
  计 `TunnelStats.bytes_forwarded`；无 next_hop → `NO_ROUTE_TO_DST`。
- 新增事件 `VirtualSubnetEvent::PacketForwarded { tunnel_id, src, dst, next_hop, bytes }`。
- Deletion Test：MeshCarrier（多对端 carrier 测试替身）是独立变化维度（三节点 E4 必需），
  与 MemoryCarrier（点对点）并存；不引入新 trait，只扩展现成数据面。
- 不做：动态路由、最短路径、跨子网、加密、真实 TUN。

### 冻结契约（VirtualSubnet 链路加密接入 P2，PRODUCT §12.6）

- `VirtualSubnetTunnel` 新增：
  - `enable_encryption(config: EncryptionConfig)`：开启加密模式（默认关闭，
    明文模式与 §12.1-§12.5 语义不变）；`is_encryption_enabled() -> bool`。
  - `begin_handshake(peer_virtual_ip) -> Result<(), ConnectivityError>`：发起方
    生成临时 `KeyPair`，经 carrier 发 `HANDSHAKE_INIT`，暂存本端密钥。
  - `accept_handshake(peer_virtual_ip, &HandshakeMessage) -> Result<(), ConnectivityError>`：
    响应方生成临时 `KeyPair` 并经 `handshake_respond` 派生会话，回
    `HANDSHAKE_RESP`，peer state → Connected。
  - `complete_handshake(peer_virtual_ip, &HandshakeMessage) -> Result<(), ConnectivityError>`：
    发起方用 RESP 公钥经 `derive_directional` 派生会话，peer state → Connected。
- `encryption::KeyPair` 新增 `derive_directional(peer_public, initiator) ->
  Result<DirectionalKeys, EncryptionError>`：纯 ephemeral 分步握手专用
  （initiator 侧在收到对端公钥后完成派生；responder 侧仍走既有
  `handshake_respond`）。
- 数据面（加密模式）：发送 = `encrypt_frame(session.tx, tx_seq, 完整虚拟子网帧)`；
  接收 = 按长度+type 分流握手/数据帧，数据帧以各对端会话 rx 试解密 +
  `ReplayWindow::check_and_accept` 防重放；中间节点用 next_hop 会话重新加密
  转发（虚拟 IP 头内容不变，字节数按 wire 密文长度计）。
- 失败语义：解密失败/无匹配会话/重放拒绝 → 结构化错误（复用 `EncryptionError`
  语义映射 `CRYPTO_ERROR` / `REPLAY_REJECTED`）；未握手 peer 发送 → 沿用
  next_hop not connected。
- Deletion Test：加密模式是虚拟子网数据面的独立变化维度（真实公网流量前提），
  复用 §6 已冻结的 encryption 原语；新增 API 均为 VirtualSubnetTunnel 方法
  + 一个 KeyPair 分步派生方法，无新 trait、无投机抽象。

### 冻结契约（VirtualSubnet NAT 打洞集成 P2.2，PRODUCT §12.9）

- `TunnelState` 新增 `Probing`（打洞中间态）。
- `VirtualSubnetTunnel` 新增：
  - `probe_peer(peer_virtual_ip) -> Result<(), ConnectivityError>`：peer 置
    `Probing`，发 `ProbeStarted` 事件；未注册 peer → `PEER_NOT_FOUND`。
  - `apply_hole_punch(peer_virtual_ip, direct_locator) -> Result<(), ConnectivityError>`：
    打洞成功 → peers locator 动态更新 + state `Connected` + `PeerLocatorUpdated`
    事件；未注册 peer → `PEER_NOT_FOUND`；幂等（可覆盖更新）。
  - `fallback_to_relay(peer_virtual_ip, relay_locator) -> Result<(), ConnectivityError>`：
    打洞失败 → peers locator 切 relay + state `Connected` + `RelayFallback`
    事件；未注册 peer → `PEER_NOT_FOUND`；幂等。
  - `peer_locator(peer_virtual_ip) -> Option<String>`：查询当前 locator。
- 数据面：locator 更新即刻生效（`send_ip_packet` / 转发使用 peers 表当前
  locator）；§12.5 路由、§12.6 加密语义不变。
- 事件：`VirtualSubnetEvent` 新增 `ProbeStarted { peer_id }` /
  `PeerLocatorUpdated { peer_id, new_locator }` /
  `RelayFallback { peer_id, relay_locator }`。
- Deletion Test：打洞集成是虚拟子网数据面的独立变化维度（真实公网场景
  peer locator 动态学习），复用 nat.rs 既有原语语义；新增 API 均为
  VirtualSubnetTunnel 方法 + 一个状态枚举变体，无新 trait、无投机抽象；
  真实 UDP 打洞由 P4.2 tunnel 级打洞状态机挂接（见下节）。

### 冻结契约（tunnel 级双向打洞状态机 P4.2，PRODUCT §12.9.3）

- `HolePunchConfig { max_attempts: u32 = 10, attempt_timeout: Duration = 500ms,
  magic: [u8;4] = b"NXHP" }`（默认总预算 ~5s，与 `HolePuncher::punch` 对齐）。
- `VirtualSubnetTunnel` 新增：
  - `begin_hole_punch(peer_vip, target) -> Result<(), ConnectivityError>`：
    非阻塞发起：peer 置 `Probing` + `HolePunchStarted` 事件 + 记录 pending
    punch { target, attempts: 0 }，经 carrier 发第 1 个 `ph` 帧。
  - `punch_tick(peer_vip) -> Result<(), ConnectivityError>`：重试推进——
    已 Connected / 无 pending → 幂等 Ok；attempts < max → 重发 `ph`；
    attempts == max → `HolePunchFailed` 事件 + 清理：配置 relay 则自动
    `fallback_to_relay` 并 Ok，否则 Err(`HOLE_PUNCH_FAILED`)。
  - `relay_locator(peer_vip) -> Option<String>` / `set_relay_locator(peer_vip,
    locator)`：relay 回退配置。
- 打洞帧协议（与数据帧/握手帧共用同一 PacketCarrier，同一 socket）：
  `ph:<sender_vip>:<magic4>`（请求）/ `pa:<sender_vip>:<magic4>`（确认）；
  sender_vip 为发起方自身虚拟 IP；magic4 = `b"NXHP"` 防误判。
- 接收侧分流（`recv_and_deliver`）：`ph` 帧 → 学习来源（NAT 回程）+
  回 `pa` 到来源（无来源则配置 locator）+ 置 sender Connected（双向可达）；
  `pa` 帧 → 学习来源 + 仅本地发起中（Probing）落账（防伪造成功）→
  `apply_hole_punch` + `HolePunchSucceeded { target }` 事件。
- 事件：`VirtualSubnetEvent` 新增 `HolePunchStarted { peer_vip }` /
  `HolePunchSucceeded { peer_vip, target }` / `HolePunchFailed { peer_vip, reason }`。
- 失败语义：未注册 peer → `PEER_NOT_FOUND`；打洞帧 magic 校验失败 → 丢弃
  （Ok(None)，防数据帧/握手帧误判）；打洞帧不写 VPI、不计数据统计。
- Deletion Test：打洞状态机是隧道连通性建立（直连/relay 路径决策）的独立
  变化维度；复用 carrier 帧流（无新 socket/trait）与 §12.9 落账 API；
  无投机抽象。
- 冻结边界（后续）：多候选并发打洞、NAT 类型驱动路径选择、真实公网跨 NAT
  打洞 E5。

### 冻结契约（VirtualSubnet 协调核心 + 自动 IP 分配 P2.3+P2.4，PRODUCT §12.13）

- 新模块 `coord`（portable：零 I/O、零第三方依赖，可编译 WASI）：
  - `Coordinator`：`announce(now_secs, peer, locator, ttl_secs)` 幂等刷新；
    `heartbeat(now_secs, peer, ttl_secs)` 刷新 TTL（未知 peer →
    `PeerUnknown`）；`peer_list(now_secs)` 返回未过期 (peer, locator, virtual_ip) 三元组（vip
    由分配器补充；vip 未领号 → `PeerUnknown`；注册顺序稳定）；
    `resolve_locator(now_secs, peer)`（过期 → `PeerExpired`）。
    显式 `now_secs` 注入（不用 `Instant`）保证确定性。
  - `VirtualIpAllocator`：`new(cidr)` 校验 IPv4 CIDR；`allocate(now_secs, peer)`
    顺序分配空闲 IP（同 peer 幂等返回原号；耗尽 → `NoAddressAvailable`）；
    `allocate_specific(now_secs, peer, virtual_ip)` 显式保留（占用 →
    `AddressInUse`）；`release(now_secs, peer)` 释放复用。
  - `CoordFrame` 10 变体 + `encode_frame`/`decode_frame`（u8 tag + u16 长度
    前缀字符串 + u64 BE；确定性、可移植）。
  - `peer_id_from_public_key(&[u8;32]) -> String`：FNV-1a 64 确定性哈希
    （标识用途）。
- 接入：loopback TCP 协调端点在 apps/nexus example（Composition Root），
  crate 内零 I/O。
- Deletion Test：协调核心与自动 IP 是虚拟子网控制平面的独立变化维度（真实
  广域扩展前提），复用 PresenceRegistry 语义；无新 trait、无投机抽象。
- 失败语义：全部 `Result + CoordError`（PeerUnknown / PeerExpired /
  AddressInUse / NoAddressAvailable / InvalidCidr / InvalidFrame），无 panic。

### 冻结契约（RelayChannel 中继通道 P0，scenarios/product/relay_fallback.toml）

- `RelayConfig { relay_server, peer_id }`：领域中立中继配置（服务器 locator + 对端 peer 标识）；
  `new(relay_server, peer_id)` / `validate() -> Result<(), ConnectivityError>`（任一字段空 -> `Invalid`）。
- `RelayState { Disconnected, Connecting, Connected, Failed }`：通道状态机；`Display` 输出
  `disconnected` / `connecting` / `connected` / `failed`。
- `RelayStats { bytes_sent, bytes_received, forward_requests }`：单调流量统计（`Default` 归零）。
- `RelayEvent`：`Connecting{relay_server,peer_id}` / `Connected{relay_server,peer_id}` /
  `ConnectFailed{relay_server,peer_id,reason}` / `DataForwarded{peer_id,bytes}` /
  `DataReceived{peer_id,bytes}` / `Closed{peer_id}`（Worker 只发事件）。
- `trait RelayTransport`：`connect(&mut self, &RelayConfig) -> Result<(), String>` /
  `forward(&mut self, peer_id, &[u8]) -> Result<(), String>` /
  `receive(&mut self, peer_id, &mut [u8]) -> Result<usize, String>`；真实 DERP 建连由
  Composition Root / platform 注入，本层零真实网络。
- `RelayChannel`：`new(config, Box<dyn RelayTransport>)`（初始 `Disconnected`、事件为空）；
  - `connect() -> Result<RelayState, ConnectivityError>`：先 `validate`，严格状态机
    `Disconnected -> Connecting(发 Connecting) -> transport.connect()`；成功 `Connected`（发 Connected），
    失败 `Failed`（发 ConnectFailed）并返回 `Io{operation:"relay_connect"}`；
  - `forward(&[u8])` / `receive(&mut [u8])`：仅 `Connected` 允许，否则 `Invalid("relay not connected")`；
    成功后累加 `bytes_sent` / `bytes_received` / `forward_requests` 并发对应数据事件；
  - `close()`：回到 `Disconnected` 并发 `Closed` 事件；
  - `state()` / `stats()` / `events()` / `config()` 只读访问器。
- `MockRelayTransport`：离线确定性回环替身（`new(connect_result)` / `inject_echo(&[u8])` / `sent()`），
  供单测与 E4 产品场景驱动，不发起真实网络。

冻结语义：未 `Connected` 不允许 `forward` / `receive`（门控，未建连零数据面）；`connect` 严格走状态机；
真实中继建连、加密、平台 socket 留 TODO，由 Composition Root / `nexus-platform-*` 完成；
本骨架为可移植纯 std 实现，不新增第三方依赖、不含 `unsafe`。

### 冻结契约（Link Encryption 链路加密 P0，scenarios/product/link_encryption.toml）

- `encryption::KeyPair`：节点长期 X25519 密钥对。
  - `KeyPair::generate() -> Result<KeyPair, EncryptionError>`（内部用 `ring::rand::SystemRandom`，
    不暴露 rng 注入点；长期私钥持久化/序列化留 TODO——ring 0.17 不导出私钥字节）；
  - `public_key_bytes(&self) -> &[u8; 32]`：导出公钥用于握手交换。
  - 握手消费私钥（`agree_ephemeral` move 语义），一个 `KeyPair` 只参与一次握手。
- `encryption::HandshakeMessage { msg_type, public_key }`：自包含固定字节布局
  （type(1) + 公钥(32)），`to_bytes()` / `from_bytes()`。
- `encryption::KeyPair::handshake_initiate(&self, peer_pub) -> Result<(HandshakeMessage, DirectionalKeys), _>`：
  initiator 发起，返回握手 INIT 消息与 initiator 视角的方向密钥。
- `encryption::KeyPair::handshake_respond(&self, &HandshakeMessage) -> Result<(HandshakeMessage, DirectionalKeys), _>`：
  responder 响应，返回握手 RESP 消息与 responder 视角的方向密钥。
- 密钥派生：X25519 ECDH 共享密钥 -> HKDF-SHA256（salt 固定标签，info 字典序双公钥）
  得 32 字节 base；再 HKDF-Expand 两次派生方向子密钥
  （initiator.tx 与 responder.rx 相同，responder.tx 与 initiator.rx 相同），
  避免双向同序号 nonce 复用。
- `encryption::DirectionalKeys { tx: SessionKey, rx: SessionKey }`：
  `tx` 用于加密本端发送帧，`rx` 用于解密对端帧。
- `encryption::SessionKey::from_bytes(&[u8;32])` / `material() -> &[u8;32]`：
  单方向 AEAD 密钥封装（ChaCha20Poly1305）。
- `encrypt_frame(&SessionKey, seq, plaintext) -> Result<Vec<u8>, EncryptionError>` /
  `decrypt_frame(&SessionKey, &[u8]) -> Result<(u64, Vec<u8>), EncryptionError>`：
  wire 布局 `[version(1)|type(1)|seq(8 BE)|nonce(12)|ciphertext|tag(16)]`；
  **整段 22 字节帧头作为 AEAD AAD 认证**，篡改 seq/version/type 必致 tag 失败。
- `ReplayWindow`：64 位序号 + 1024 位滑动位图；
  `check_and_accept(seq)` 对重复/过旧序号返回 `EncryptionError::ReplayRejected{seq}`。
- `EncryptionConfig { algorithm: AeadAlgorithm, key_rotation_after_frames: u64 }`：
  P0 仅 `ChaCha20Poly1305`；rotation 阈值仅记录，轮换逻辑 TODO。
- `EncryptionError`：typed enum（InvalidKey / DecryptionFailed /
  ReplayRejected{seq} / HandshakeFailed / FrameTooShort / UnsupportedVersion /
  UnexpectedFrameType{actual}），Display + std::error::Error。

冻结语义：握手成功前不允许发送业务帧；方向子密钥隔离双向 nonce；
帧头入 AAD 防篡改；接收方先验 tag 再做防重放；
本模块保持 portable、零真实网络（真实传输/握手重传/密钥轮换留 TODO），
仅依赖 ring 0.17（已在依赖树）。

### 冻结契约（Mesh 防火墙规则匹配引擎，scenarios/product/firewall_rules.toml）

- `Protocol { Tcp, Udp, Icmp }`：协议枚举；`as_str()` / `Display` / `FromStr`（小写标签）。
- `FirewallAction { Allow, Deny }`：规则动作；`as_str()` / `Display`。
- `FirewallVerdict { Allow, Deny }`：引擎对一个包的最终判定；`as_str()` / `is_allow()` / `Display`。
- `PortRange { start: u16, end: u16 }`：inclusive 端口范围；
  - `PortRange::new(start, end) -> Result<Self, FirewallError>`：`start > end` 返回 `InvalidRule`；
  - `PortRange::single(p)`：单端口；
  - `contains(u16) -> bool`：inclusive 匹配。
- `FirewallRule { action, src_ip, dst_ip, src_port, dst_port, protocol }`：
  五元组子集；任一 `Option` 为 `None` 表示该维通配。
  - `FirewallRule::new(action, src_ip, dst_ip, src_port, dst_port, protocol) -> Result<Self, FirewallError>`：
    空字符串规范化为 `None`；预校验 IP/CIDR 合法性。
  - `FirewallRule::action_only(action)`：纯动作兜底规则。
  - `src_ip` / `dst_ip` 支持精确 IPv4（`10.0.0.5`）或简化 IPv4 CIDR（`10.0.0.0/24`，按位掩码比较，含非整字节前缀如 `/26`）。
- `FirewallConfig { default_policy: FirewallAction, rules: Vec<FirewallRule> }`：
  `new(default_policy, rules) -> Result<Self, FirewallError>`，构造期校验全部规则。
- `PacketContext { src_ip, dst_ip, src_port, dst_port, protocol }`：进入引擎的包元数据；
  - `PacketContext::transport(src, dst, src_port, dst_port, protocol)`：TCP/UDP 包；
  - `PacketContext::control(src, dst)`：ICMP 包（无端口）。
- `FirewallEngine`：持有已编译规则视图（IP 预解析为内部 `IpEntry`）；
  - `FirewallEngine::new(&FirewallConfig) -> Result<Self, FirewallError>`；
  - `evaluate(&self, &PacketContext) -> FirewallVerdict`：按规则顺序 **first-match-wins**；
    任一已设置维不命中即跳过该规则；全部未命中走 `default_policy`（白名单模式默认 `Deny`）；
  - `rule_count()` / `default_policy()`：只读访问器。
- `dns_query_context(src_ip, dns_server_ip) -> PacketContext`：把 DNS 查询映射成
  `udp/53` 包上下文（演示 DNS 过滤集成点）。
- `FirewallError { InvalidRule { message } }`：类型化错误面，`Display` + `std::error::Error`。

冻结语义：纯内存、纯同步、纯函数骨架；不接真实 socket/TUN/iptables；不支持 IPv6；
真实包抓取、conntrack 状态化规则、规则热加载留 TODO；
本模块保持 portable、零真实网络、无 `unsafe`。
### 冻结契约（带宽控制 / QoS 令牌桶，scenarios/product/bandwidth_qos.toml）

- `BandwidthLimit { max_bytes_per_sec: u64, burst_size: u64 }`：
  `new(max_bytes_per_sec, burst_size) -> Result<Self, QosError>`（速率必须 > 0、
  burst 必须 >= 1，否则 `QosError::InvalidLimit`）；`rate()` / `burst()` 只读。
- `trait QosClock { fn now(&self) -> Duration }`：单调时钟抽象（可注入）；
  `MonotonicClock::new()` 基于 `std::time::Instant`，返回构造点起算的单调时长；
  测试 / E4 用显式 `Duration` 假时钟推进。
- `TokenBucket`：`new(&BandwidthLimit)`（初始满桶 = burst_size）；
  - `refill(now)`：按 `rate` 字节/秒线性补充，封顶 `burst_size`；时间回退不补充；
  - `try_consume(bytes, now) -> bool`：够令牌则扣减并返回 `true`，不够返回 `false`
    （不阻塞、不 sleep）；
  - `remaining_tokens() -> u64`（向下取整）/ `capacity()` / `rate()`。
- `QosConfig { ingress: Option<BandwidthLimit>, egress: Option<BandwidthLimit> }`：
  两方向限制；`None` 表示该方向不限制（恒放行）。
- `PerEndpointStats { up_bytes, down_bytes }`：单连接/节点累计放行字节（Default 归零）。
- `QosStats { bytes_allowed, bytes_dropped, tokens_remaining, endpoints: HashMap<String, PerEndpointStats> }`：
  聚合快照（放行/丢弃字节 + 出站剩余令牌 + 各 tag up/down 累计）。
- `QosController`：持有入站/出站两个令牌桶 + 统计表；
  - `new(&QosConfig)`（两方向桶按 limit 建为满桶）；
  - `try_egress(tag, bytes, now) -> bool` / `try_ingress(tag, bytes, now) -> bool`：
    命中限制返回 `false` 并计 `bytes_dropped`（不计入任何 up/down）；放行计入
    `bytes_allowed` 与该 tag 的 `up_bytes`（egress）/ `down_bytes`（ingress）；
  - `snapshot() -> QosStats` / `egress_tokens_remaining()` / `ingress_tokens_remaining()`。
- `QosError { InvalidLimit { message } }`：类型化错误面，`Display` + `std::error::Error`。

冻结语义：纯内存、纯同步、纯函数骨架；不接真实 socket/TUN/内核 tc；不引入 `time` crate，
仅 std（`std::time::{Duration, Instant}`）；无 `unsafe`、库代码不 panic/unwrap/expect；
整形排队、优先级/公平排队、per-flow 分流、真实数据面挂接留 TODO。

### 冻结契约（身份密钥与 TOFU 自动交换 P4.1，PRODUCT §12.39，scenarios/product/identity_auto_exchange.toml）

- `trait SecretStore { fn read_secret(&self, key) -> Option<Vec<u8>>; fn write_secret(&mut self, key, value) -> Result<(), IdentityError> }`：
  secret 后端抽象（注入），实现 `InMemorySecretStore`（HashMap，测试/内存驱动用）；真实持久化
  由 daemon 装配注入（平台 secure-store，PRODUCT §12.30），本 crate 不直接触盘。
  读失败语义：当前抽象以 `Option` 表示"无记录"（InMemory 后端不失败）；真实后端（如平台
  secure-store 不可用）在 P4.1 冻结边界内并入握手拒绝路径（`IdentityRejected`），由注入层保证。
- `IdentityManager`：`load_or_generate()`（无身份 -> 生成 X25519 static 并持久化，返回是否新生成）、
  `peer_id_of(static_pub) -> String`（SHA-256 前 16 字节 hex = PeerId）、
  `verify_peer(record_key, static_pub) -> Result<IdentityAction>`（TOFU：首学 PeerLearned /
  匹配 PeerVerified / 替换 Err(PeerIdentityChanged)）、`known_peer(key)`、`peer_id()`。
- **TOFU 记录键 = 对端虚拟 IP（VIP）**：同一 VIP 更换 static 公钥即拒绝（防身份顶替），
  与 PRODUCT §12.39 一致；`PeerId` 仅用于事件/显示。
- 握手 wire v2：`HANDSHAKE_INIT/RESP` 各 65B（`type + ephemeral_pub(32) + static_pub(32)`）；
  混合 DH `dh1=DH(init.static, resp.eph)`、`dh2=DH(init.eph, resp.static)`、`dh3=DH(eph_i, eph_r)`，
  按角色对称计算后 `HKDF-SHA256(dh1∥dh2∥dh3, salt=b"nexus-link-encryption-v2")` -> 方向子密钥
  （info 不变）；数据帧 AEAD 布局不变（22B 头作 AAD、1024 位重放窗口）。
- 事件：`IdentityKeyGenerated{tunnel_id}` / `PeerIdentityLearned{tunnel_id, peer_id}` /
  `PeerIdentityRejected{tunnel_id, peer_id}`；身份不匹配时握手路径返回
  `ConnectivityError::IdentityRejected{peer_id}`，错误码 `IDENTITY_CHANGED`。
- 冻结边界：不实现 CA/吊销/轮换、SPKI pinning 界面、双向 NAT 打洞/TURN 真机验证
  （留 P4.2）、多节点自动发现/join（留 P4.3）；身份持久化失败（store 不可用）不降级明文。
## Verification

最低：

```text
cargo check -p nexus-connectivity
cargo clippy -p nexus-connectivity --all-targets -- -D warnings
```

如果该模块影响产品行为，还必须映射 Integration/Scenario Evidence。

## Performance Budget

未定义性能预算的路径不得宣称“性能完成”。进入 hot path 后必须在 Contract 中增加 baseline、noise tolerance、warning threshold 与 blocking threshold。

## Observability

稳定结构化字段优先于自由文本；如涉及 Session/Provider/Path/Workspace，应携带对应 correlation id。

## Recovery Semantics

任何持久状态或长期任务都必须定义 crash 后的 reconcile 行为。无持久状态的纯模块应保持可重建。

## Platform Constraints

平台专有代码只允许存在于 `nexus-platform-*` 或 Composition Root。Portable crate 必须通过相应 portability gate。

### 冻结契约（跨子网路由与出口节点 P2-5，PRODUCT §12.14）

- 新模块 `cidr`（portable：零 I/O、零第三方依赖，可编译 WASI）：
  - `CidrPrefix { network: u32, prefix_len: u8 }`；`parse_cidr` 校验 IPv4 点分 + 前缀
    0..=32（`0.0.0.0/0` 合法）；网络地址主机位必须全零；错误 `CidrError`
    { InvalidFormat / InvalidPrefixLength / NotANetworkAddress }；
  - `cidr_contains` 纯函数；`longest_prefix_match` 返回最长前缀命中（同长取先）。
- `VirtualSubnetTunnel` 增量（§12.5 冻结 API 不变）：
  - `add_prefix_route(cidr_str, next_hop)` / `prefix_routes()`（发送侧前缀路由）；
  - `add_local_prefix(cidr_str)` / `local_prefixes()`（接收侧可达前缀，命中写 VPI）；
  - `mark_egress(virtual_ip)` / `egress_peers()`（出口兜底，顺序取第一个）；
  - 决策顺序：直连 Connected → 精确 routes → 最长前缀 → egress → NoRouteToDst；
  - 新事件变体 `LocalPrefixDelivered { dst, bytes }`（旧变体不变）。
- 不变量：
  - 前缀路由 next_hop 必须是已注册 peer；egress 必须是已注册 peer；
  - 帧头不剥不改（§12.5 保持）；
  - 接收侧：dst==本机 vip 或命中 local_prefixes 才写 VPI，否则转发。
- 边界：`routing.rs`（距离矢量 P1.1）不耦合本模块；协调器广播/出口 NAT/P3。

### 冻结契约（子网 CLI 消费边界 P3.1，PRODUCT §12.28）

- 配置装配（apps/nexus Composition Root）经 `VirtualSubnetConfig::new(cidr, virtual_ip)`
  与 `is_valid_virtual_ip` 校验；cidr 由 `cidr::parse_cidr` 把关。
- `VirtualSubnetTunnel` 装配语义：peers → `add_peer` + `set_peer_state`；
  精确路由 `add_route`；前缀路由 `add_prefix_route`；本地前缀 `add_local_prefix`；
  出口 `mark_egress`；加密 `enable_encryption`（P2-1 §12.7）。
- 不变量：配置校验失败不得进入装配（先校验后装配）；CLI 状态文件不是
  crate 层概念（crate 无 I/O）。

### 冻结契约（真实数据面消费边界 P3.2，PRODUCT §12.29）

- 装配语义扩展：`subnet up --tun` 时 `VirtualSubnetTunnel` 的 VPI 取
  `WintunVpiAdapter`/`TunVpi`、carrier 取 `UdpCarrier`；其余装配不变（§12.16）。
- carrier 契约：`PacketCarrier` 的帧是**封装后线格式**（wire frame），
  `VirtualSubnetTunnel` 不感知 UDP 语义；`UdpCarrier::bind` 解析
  `udp://<host>:<port>` 并绑定，`receive_into` 无数据 Ok(0)。
- 不变量：CLI 装配失败（VPI/carrier 创建）不得落到状态文件写入；mock 与真实
  数据面在 tunnel 层无分支（仅构造期选择）。

### 冻结契约（加密持久化消费边界 P3.3，PRODUCT §12.30）

- `SecureStore`（nexus-platform）语义：`get` 缺失键 → `Ok(None)`；`put` 幂等覆盖；
  平台能力缺失 → `Unavailable`（不 panic、不 fallback 明文）。
- 平台实现职责：Windows `DpapiSecureStore`（DPAPI，绑定用户+机器）；
  Linux `FileSecureStore`（machine-id 派生密钥 + AEAD 文件）。crate 层无
  全局状态；文件格式 `NEXSEC1` 为平台实现内部约定。

### 冻结契约（加密数据面性能边界 P3.6，PRODUCT §12.36）

- `encrypt_frame`/`decrypt_frame`：单帧 O(payload) 时间，不得引入每帧分配
  之外的额外复制；帧往返延迟以 PRODUCT §12.36 预算表为准（baseline 固化）。
- `VirtualSubnetTunnel` 加密模式数据面：`send_ip_packet` → 对端
  `recv_and_deliver` 端到端吞吐/延迟遵循同一预算表；热路径禁止 per-frame
  日志（AGENTS §22）。
- benchmark 语义：进程内闭环（无真实网络），输出 JSON 断言只锁结构不锁
  绝对值（verdict 由预算表计算）；baseline 首测定格入 evidence。


### 冻结契约（TURN 中继分配 RFC5766 P2.5，scenarios/product/turn_relay_allocate.toml）

- 新模块 `nexus-connectivity::turn`（Portable Core：零真实网络、零新增第三方依赖，可编译 WASI；
  复用 `nat.rs` 的 STUN 基础头：magic cookie 0x2112A442 / 12 字节 transaction id / XOR 地址）。
- `TurnClientConfig { server, username, password, realm, nonce, lifetime_secs }`：
  - `new(server, username, password, lifetime_secs)`（realm/nonce 初始空）；
  - `validate() -> Result<(), TurnError>`：`server/username/password` 任一空 -> `Invalid`。
- `TurnAllocationState { Unallocated, Requesting, Allocated{relayed_addr:String, expires_secs:u32},
  Failed{reason:String} }`；`Display` 输出 `unallocated/requesting/allocated/failed`。
- RFC5766 编解码（确定性、可移植，纯 std + 已在依赖树的 `ring`）：
  - TURN 消息类型：Allocate Request 0x003 / Allocate Error Response 0x113 / Refresh 0x006。
  - 属性：REQUESTED-TRANSPORT(0x0019, UDP=17) / XOR-RELAYED-ADDRESS(0x0016) /
    ERROR-CODE(0x0009) / NONCE(0x0015) / REALM(0x0014) / LIFETIME(0x000d) /
    MESSAGE-INTEGRITY(0x0008, HMAC-SHA1) / USERNAME(0x0006)。
  - `build_allocate_request(txid, username, realm, nonce, key: Option<&[u8;16]>) -> Vec<u8>`：
    无凭证时只带 Requested-Transport；带 key 时追加 USERNAME/REALM/NONCE + MESSAGE-INTEGRITY。
  - `parse_allocate_response(buf) -> Result<ParsedTurnMessage, TurnError>`：解析消息类型、
    ERROR-CODE(code,reason)、REALM、NONCE、XOR-RELAYED-ADDRESS。
  - `long_term_key(username, realm, password) -> [u8;16]`：MD5(`username:realm:password`)
    （RFC5389 §10.2，纯 std 小实现，RFC1321 测试向量单测锁定）。
  - `codec_self_test() -> Result<(usize, std::net::SocketAddr), TurnError>`：离线自检
    Allocate Request 构造长度 + 合成成功响应解析 XOR-RELAYED-ADDRESS + MESSAGE-INTEGRITY 往返。
- `trait TurnTransport`：`fn send_recv(&mut self, request: &[u8]) -> Result<Vec<u8>, String>`；
  真实 UDP/TLS 到 TURN 服务器由 Composition Root / `nexus-platform-*` 注入，本层零真实网络。
- `MockTurnTransport`：离线确定性回环——首请求回合成 401（realm="example.org"、
  nonce="abc123"），二次回成功（XOR-RELAYED-ADDRESS=192.0.2.1:54320、LIFETIME=600）；
  `new()` 构造，不发起真实网络。
- `TurnClient { config, state, events }`：
  - `new(config, Box<dyn TurnTransport>)`（初始 `Unallocated`、events 空）；
  - `allocate() -> Result<TurnAllocationState, TurnError>`：严格编排
    `Unallocated -> Requesting`（发无凭证 Allocate）-> 收 401（取 realm/nonce）-> 派生 key
    -> 发带 MESSAGE-INTEGRITY Allocate -> `Allocated`（记录 relayed_addr/expires_secs）；
    任一步失败 -> `Failed{reason}`；二次 Allocate 重复调用直接 `Invalid`；
  - `state()` / `events()` / `relayed_address()` 只读访问器。
- `TurnError` 类型化枚举：`Invalid{message}` / `AllocateFailed{code:u16,reason:String}` /
  `AuthChallengeFailed` / `IntegrityMismatch` / `NoRelayedAddress`；Display + std::error::Error。
- 事件 `TurnEvent { AllocateSent, AuthChallengeReceived{realm,nonce},
  AllocateSuccess{relayed,expires_secs}, AllocateFailed{code,reason} }`（Worker 只发事件）。

冻结语义：
- `allocate` 是确定性策略编排（响应来自注入的 `TurnTransport`，不自行发起网络 I/O）；
  真实 TURN 服务器交互（UDP/TLS socket、ChannelData、ChannelBind、CreatePermission、
  Refresh 定时器）留 P3。
- 未 `Allocated` 不视为可经中继建连；分配失败只报告事实，不替换业务 Provider。
- 本骨架为可移植纯 std 实现，不新增第三方依赖（MD5 纯 std 小实现；HMAC-SHA1 用 `ring` 0.17）、
  不含 `unsafe`。
- Deletion Test 成立：TURN 分配/凭证/生命周期语义是与 DERP 类 `RelayChannel`（DIAL 字节中继）、
  STUN 打洞三个独立变化维度；复用 `nat.rs` STUN 头原语，无新系统级 trait、无投机抽象。
