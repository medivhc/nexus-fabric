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
