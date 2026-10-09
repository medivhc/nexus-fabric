# 《Nexus Bootstrap 自动入网设计》评审报告

> 评审对象：`nexus-bootstrap-design.md`（设计文档，共 13 节）
> 对照源码：`nexus-fabric` 仓库
> 文档自称基线：`bb6201b`；仓库工作树实际 HEAD：`cda5f21`（`git rev-parse HEAD` 核实；差异提交为 proxy 相关 outbound crate，不涉及本设计的核心文件，但行号一律以工作树为准）
> 评审方式：四个分片对照源码逐文件核实行号——线协议与认证 / 服务端与 VIP / 客户端装配与 daemon / 验证与落地，再汇总去重。本报告中所有 `文件:行号` 均实际打开文件核实；【已核实】= 打开文件确认，【推断】= 据已核实代码结构推演、尚未运行验证。
> 只读纪律：评审全程未向被审仓库写入、未改 git、未在其 target 下构建；编译验证在本会话目录的 clone 中完成。

---

## 一、总体结论（TL;DR）

**设计方向成立**：复用现有 UDP 承载、X25519+PSK 会话派生、AEAD 防重放、VIP 分配器的总体路线与现有代码架构相容；`nxb:` 前缀与现有全部帧类型在首字节层面**确定性互斥**（非概率碰撞，见 §二.1）；旧路径可字节级保持不变。

**但有 7 个阻断项必须在动工前解决**，其中多数是"设计对现状的假设与代码不符"：

| # | 阻断项 | 结论 |
|---|---|---|
| S1 | **服务端模块归属违反架构红线** | 设计把 `bootstrap_server.rs` 放 `nexus-connectivity`，但其要调 `nexus-discovery::decode_auto_frame`；仓库在 `crates/nexus-connectivity/src/fib_resolver.rs:4` 明确规定"connectivity 不能依赖 discovery"，两个 crate 当前互不相依。须用 trait 注入（同 FibResolver 模式）或改归属。 |
| S2 | **node_id 未与握手 static 公钥绑定** | `Register{node_id}` 是会话内客户端自报字符串，持全网 PSK 的任何节点都可冒名注册、抢占他人 VIP。`peer_id_from_public_key`（`coord.rs:553`）已存在却未被设计使用。 |
| S3 | **半开会话表无界 DoS** | 设计在未认证的 JoinInit 即预建 ControlSession，而 `sweep_expired` 只清目录、不清待验证会话；UDP 源可伪造，轮换源即可无界堆条目。 |
| S4 | **设计所称"daemon 常驻路径"在代码中不存在** | nexusd 通篇不持有 `VirtualSubnetTunnel`/UDP socket，其常驻循环是 TUN 收包泵（`apps/nexusd/src/main.rs:351`）。真正持有 UDP 隧道的常驻进程只有 CLI `--foreground` → `AutoMeshController`（`apps/nexus/src/mesh.rs:216`）。 |
| S5 | **socket 被隧道私有持有，常驻心跳无发包出口** | `VirtualSubnetTunnel::new` 把 carrier move 进私有字段（`virtual_subnet.rs:443/:466`），无 raw-send 出口；joiner 的一次性借用无法延伸到常驻循环。会话必须收编为隧道字段。 |
| S6 | **一次性 `subnet up` 装配即丢隧道，与 bootstrap 语义矛盾** | `_tunnel` 在 `subnet_cli.rs:348`（`--tun` 路径在 `:643`）立即 drop，join 后无人打洞/心跳。非 foreground + bootstrap 应直接报错。 |
| S7 | **持久身份断链** | `node init` 已把 X25519 seed 落盘（`node_cli.rs:221`），但装配路径用一次性 `KeyPair::generate()`（`subnet_cli.rs:340`）且无回读函数，"客户端默认持久身份"目前不成立。 |

**另需更正设计文档的三处事实性错误**（导致重复劳动或错误接线）：

1. `VirtualIpAllocator::release(now, peer)` **已存在**（`coord.rs:278`，幂等、回 free_pool、已被测试覆盖 `coord.rs:613`）——设计 §9 与 §11 P1 把它列为缺口，应删除该项。
2. 同仓已有带 TTL 过期、注入时钟、已测的 `Coordinator`（`coord.rs:69`，`announce/heartbeat/peer_list/resolve_locator`）——设计 §6.1 要新造 `BootstrapDirectory`+`sweep_expired`，应改为复用（仅需补一个摘除过期条目的小 API）。
3. `allocate_specific`（`coord.rs:252`）**不校验 VIP 是否落在 CIDR**，设计 §5.4 的"先校验 v∈cidr"须服务端自补；且分配池从 `.1` 起跳（`coord.rs:237`），与设计 §8.1 中服务端自身 VIP `.1` 冲突，启动时须先占位。

---

## 二、实现方案（细化到可落地）

### 1. 线协议与帧编解码

#### 1.1 现有收包分流（已核实，`crates/nexus-connectivity/src/virtual_subnet.rs`，`recv_and_deliver` 起于 `:1411`）

| 行号 | 判定 | 失败行为 |
|---|---|---|
| `:1427` | `let data = buffer[..n].to_vec();`（取出去重后的完整数据报） | — |
| `:1430` | NXP1 管线单元探针 `dataplane_pipeline::is_pipeline_unit(&data)`（NXP1 magic 定义于 `dataplane_pipeline.rs:20`，头 6B = magic4+ver+kind） | 前缀不符则原样放行（fall-through） |
| `:1444` | `data.starts_with(b"hs:")` 握手帧 | fall-through |
| `:1472` | `data.starts_with(b"ph:") \|\| data.starts_with(b"pa:")` 打洞帧（打洞 magic 默认 `NXHP`，`:160`） | fall-through |
| `:1477`–`:1492` | 加密模式：遍历 `crypto_sessions` 对**整段 data** 试 `decrypt_frame`；**无任何会话命中即硬错误返回** `CRYPTO_ERROR: no matching session or bad tag`（`:1490`） | **硬错误，不 fall-through** |
| `:1499`–`:1504` | 明文模式：`TunnelFrameHeader::deserialize(&data)`，失败硬错误 `invalid tunnel frame header` | **硬错误** |

**首字节互斥表（已核实）**：

| 帧类 | 首字节 |
|---|---|
| NXP1 管线 | `0x4E`（`N`） |
| `hs:` 握手 | `0x68`（`h`） |
| `ph:`/`pa:` 打洞 | `0x70`（`p`） |
| AEAD 数据帧（`WIRE_VERSION=1`，`encryption.rs:44`） | `0x01` |
| 遗留明文 `src->dst:` 头（`virtual_subnet.rs:391`） | `0x30`–`0x39`（点分十进制数字） |
| **`nxb:` 控制帧** | `0x6E`（`n`） |

六类首字节两两不等，是确定性前缀分类，误判概率为 0（不是哈希碰撞，无需按碰撞概率论证）。

**`nxb:` 分流插入点结论**：插在 `:1427`（data 取出）之后、`:1430`（NXP1 探针）之前。理由：`:1477` 的试解密循环对整段 data 判定 `frame[0] != 0x01` 即全部失败并在 `:1490` 硬错误返回，因此分支必须位于 `:1477` 之前；`:1430/:1444/:1472` 都是前缀 fall-through，故插在 `:1441` 后或 `:1474` 后结构上也能工作，但最早点最稳妥，且控制帧不应进入管线。

#### 1.2 新文件 `crates/nexus-discovery/src/bootstrap_join.rs`（外层帧，与设计 §5.2 一致）

```rust
/// 外层 magic（0x6E 0x78 0x62 0x3A）。
pub const NXB_MAGIC: &[u8; 4] = b"nxb:";

// 外层 tag：必须避开数据面 0x01(WIRE_VERSION/HANDSHAKE_INIT)、
// 0x02(HANDSHAKE_RESP)、0x03(FRAME_DATA)——剥掉 nxb: 后 Secured 密文首字节恒为 0x01。
pub const OUTER_JOIN_INIT:  u8 = 0x10;
pub const OUTER_JOIN_REPLY: u8 = 0x11;
pub const OUTER_ERROR:      u8 = 0x12;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootstrapErrorCode {
    AuthFailed = 1, BadVip = 2, VipConflict = 3,
    NotBootstrap = 4, RateLimited = 5, MalformedFrame = 6,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootstrapJoinFrame {
    JoinInit {
        eph_pub: [u8; 32],
        static_pub: [u8; 32],
        requested_vip: Option<String>, // None = 请服务端分配
        client_nonce: u64,
    },
    JoinReply {
        eph_pub: [u8; 32],
        static_pub: [u8; 32],
        assigned_vip: String,
        lease_secs: u32,
        hb_interval_ms: u32,
        refresh_interval_ms: u32,
        server_nonce: u64,
    },
    Error { code: BootstrapErrorCode, message: String },
}

/// 剥掉 NXB_MAGIC 后的外层判别。
pub enum OuterFrame<'a> {
    Secured(&'a [u8]),                 // 交会话 decrypt_frame + ReplayWindow
    Plain(BootstrapJoinFrame),
}

pub fn encode_join_frame(f: &BootstrapJoinFrame) -> Result<Vec<u8>, DiscoveryError>;
pub fn decode_join_frame(payload: &[u8]) -> Result<BootstrapJoinFrame, DiscoveryError>;

/// Secured 必须用「首字节 == 0x01 且 len >= 22(帧头) + 16(tag)」显式探针判定；
/// 禁止用"未知外层 tag 即当密文"的 fallback（未来扩展 tag 时会误判）。
pub fn split_outer(payload: &[u8]) -> Result<OuterFrame<'_>, DiscoveryError>;
```

**字节规则**（沿用 `auto_discovery.rs` 确定性编码）：帧首 1B tag；公钥固定 32B（`PUBLIC_KEY_LEN=32`，`encryption.rs:53`）；字符串 `u16 BE` 长度前缀 + UTF-8（复用 `nexus-discovery/src/lib.rs:408/:417` 的 `put_str/get_str`，`pub(crate)` 同 crate 直接可用）；`Option<String>` 先 1B presence；整数 `u64 BE`（nonce）、`u32 BE`（lease/间隔）；未知 tag / 截断 / 非法 UTF-8 / trailing bytes 一律 `DiscoveryError::Transport`（对照 `decode_auto_frame` 在 `auto_discovery.rs:302` 的处理）。

#### 1.3 会话密钥、认证时点与 nonce 绑定

- 双方交换 eph/static 公钥后调用（已核实，`encryption.rs:420`）：
  ```rust
  pub fn derive_authed_keys_with_psk(
      my_static: &KeyPair, my_eph: &KeyPair,
      peer_static: &[u8; 32], peer_eph: &[u8; 32],
      initiator: bool, psk: &[u8],
  ) -> Result<DirectionalKeys, EncryptionError>;
  ```
  PSK 拼进 HKDF salt（`b"nexus-link-encryption-v2" ∥ psk`，`encryption.rs:364-368`；info 为排序后的 static 公钥）。返回 `DirectionalKeys { tx, rx }`（`:229`）。
- 控制帧：`encrypt_frame(&keys.tx, seq, plaintext)`（`:466`）；对端 `decrypt_frame(&keys.rx, blob) -> (seq, plain)`（`:492`）+ `ReplayWindow::check_and_accept(seq)`（`:568`，窗口 1024 bitmap，`:538/:63`）。
- **认证时点不对称（须写入设计）**：
  - 服务端：收到客户端首个 AEAD 帧才能判定 PSK 是否一致；PSK 错 → 解密失败 → **静默丢弃**（无法回 `AuthFailed`，因为派生不出可加密该消息的密钥）。
  - 客户端：JoinReply 是明文，客户端同样要等服务端对其 Register 的 AEAD 回包才能判定；PSK 错时表现为**超时**。因此线上 `Error{AuthFailed}` 对 PSK 不符场景是不可达消息；客户端应把"收到 JoinReply 但 RegisterAck 超时"归并为认证失败候选，与"引导不可达"区分打印。
- **握手 nonce 绑定的落地改法**：已核实 `encrypt_frame` 签名仅 `(key, seq, plaintext)`，AAD 硬编码为 22B 帧头（`:478` `Aad::from(&header[..])`，seq/nonce 在明文头内被 AAD 认证，无显式 length 字段）；`derive_authed_keys_with_psk` 不吃 nonce。推荐**不改冻结签名**：把 `client_nonce || server_nonce`（各 8B）作为 AEAD plaintext 前缀，解密后与 JoinInit/JoinReply 阶段按 src 存下的期望值比对。备选（改动面大、不推荐）：新增 `encrypt_frame_with_aad` 变体或给派生函数加 salt 参数——二者都动与已冻结数据面共享的函数，须先过架构评审。
- **首帧无重放保护**：`ReplayWindow` 对首帧直接以该 seq 为基准清零位图（`:569-576`），新会话首帧被无条件接受——这正是 nonce 绑定必须存在的理由。

### 2. 引导服务端（功能 A）

#### 2.1 模块归属：依赖方向结论与推荐方案

已核实的依赖事实：

- `crates/nexus-connectivity/Cargo.toml:11-28` 不依赖 nexus-discovery；`crates/nexus-discovery/Cargo.toml:11-16` 不依赖 nexus-connectivity（双向 grep 无 `use nexus_*`）。
- 红线原文：`crates/nexus-connectivity/src/fib_resolver.rs:4`"而不直接依赖 nexus-discovery（架构边界：connectivity 不能依赖 discovery）"，具体实现由 composition root（apps/nexus）注入。

**推荐方案（与 FibResolver 完全同构）**：服务端纯逻辑（目录、VIP、会话、加解密）放 `nexus-connectivity`，但不直接命名 discovery 的帧类型；在 connectivity 定义帧编解码 trait，由 apps/nexus 组合根用 discovery 的帧实现注入。

```rust
// connectivity 侧：与 discovery 帧解耦的控制消息（仅 bootstrap 所需子集）
pub struct BootstrapPeer { pub node_id: String, pub virtual_ip: String, pub locator: String }

pub enum BootstrapCtrl {
    Register    { node_id: String, virtual_ip: String, locator: String },
    RegisterAck { accepted: bool, ttl_secs: u32 },
    GetPeers    { node_id: String },
    PeerList    { peers: Vec<BootstrapPeer> },
    Heartbeat   { node_id: String, now: u64 },
}

/// 由 apps/nexus 组合根实现：BootstrapCtrl ↔ AutoDiscoveryFrame 字节。
pub trait BootstrapFrameCodec {
    fn encode(&self, f: &BootstrapCtrl) -> Result<Vec<u8>, BootstrapServerError>;
    fn decode(&self, b: &[u8]) -> Result<BootstrapCtrl, BootstrapServerError>;
}
```

> 设计 §6.2 使用了 `RegisterAck`，但现有 `AutoDiscoveryFrame`（`auto_discovery.rs:201`，tag 11–14 在 `:194-197`）只有 Register/GetPeers/PeerList/Heartbeat，**没有 RegisterAck**——这是设计的一个小缺口。组合根的 codec 实现需给内层帧**增量**加一个 tag（如 15 = RegisterAck）；旧节点不参与 bootstrap，增量 tag 不影响旧路径（旧解码器对未知 tag 报 Transport 错误，属预期）。

备选归属：方案 B 把服务端整体放 `nexus-discovery`（新增 discovery→connectivity 依赖边，需架构评审）；方案 C 直接写在 apps/nexus（可单测性最差）。

#### 2.2 在线目录复用 `Coordinator`，不新造 BootstrapDirectory

已核实 `Coordinator`（`coord.rs:69-147`）已具备：`announce(now, peer, locator, ttl)`（幂等 upsert，`:81`）、`heartbeat(now, peer, ttl)`（未知 peer → `PeerUnknown`，`:104`）、`peer_list(now)`（只回未过期条目、注册顺序稳定，`:123`）、`resolve_locator(now, peer)`（区分 `PeerUnknown/PeerExpired`，`:132`）。VIP 不进 Coordinator，由 `VirtualIpAllocator::peer_vip` 补充（`coord.rs:291`）。

**唯一需要补的 API**（Coordinator 目前只在查询时惰性过滤、presences 为私有且无主动摘除，无法驱动 VIP 回收）：

```rust
// 插入点：coord.rs Coordinator impl 内，:147 之后
/// 摘除并返回所有已过期 peer 的名称（供服务端随后 release VIP）。
pub fn prune_expired(&mut self, now_secs: u64) -> Vec<String> {
    let (expired, alive) = self.presences.drain(..)
        .partition(|p: &PresenceEntry| p.expired(now_secs));
    self.presences = alive;
    expired.into_iter().map(|p| p.peer).collect()
}
```

这同时修掉 Coordinator presence vec 只增不减的内存增长问题。

#### 2.3 VIP 权威分配（规则对设计 §5.4 的修正）

已核实分配器行为：`allocate(now, peer)`（`:223`，按 peer 幂等、free_pool FIFO 复用、`.1` 起跳、跳过网络/广播）；`allocate_specific(now, peer, ip)`（`:252`，只 parse IP + 查重，**不校验 CIDR、不排除网络/广播地址**）；`release(now, peer)`（`:278`，已存在，回 free_pool）。

服务端 `handle_join_init` 的分配顺序：

1. `requested_vip = None` → `allocator.allocate(now, &authoritative_node_id)`。
2. `requested_vip = Some(v)`：
   - **先自补 CIDR 校验**（分配器不做）：用 `parse_cidr` 同款判定检查 `v` 在网内且非网络/广播地址，越界 → `BadVip`；可对照 `subnet_cli.rs:214` 对 virtual_ip 的现有校验。
   - `allocate_specific(now, &id, v)`：成功确认；被**别的 node_id** 占用（`AddressInUse`，`:267-269`）→ 回退 `allocate(now, &id)` 另取，JoinReply 返回实际值（软冲突，不报错）。
3. **服务端自身 VIP 占位**：分配池 `.1` 起跳，而设计 §8.1 把服务端配成 `.1`。`BootstrapServer::new` 开放分配前先 `allocate_specific(now, "__bootstrap_self__", &cfg.server_vip)`（建议把自身占位 owner 与普通 node_id 命名空间分开），否则首个客户端拿到 `.1` 与服务端隧道撞号。
4. 客户端一律以 JoinReply.assigned_vip 覆盖本地 `virtual_ip` 与 `derive_vip` 结果（`derive_vip` 在 `coord.rs:572`，FNV1a(static‖nonce)）。

#### 2.4 服务端结构与函数签名

```rust
// crates/nexus-connectivity/src/bootstrap_server.rs
pub struct BootstrapServerConfig {
    pub lease_secs: u32,
    pub hb_interval_ms: u32,
    pub refresh_interval_ms: u32,
    pub server_vip: String,        // 入册第 0 条
    pub server_locator: String,    // 对外可达 locator
    pub max_pending_per_src: usize,// 半开防护，见 S3
}

pub struct BootstrapServer {
    identity: KeyPair,
    psk: Vec<u8>,
    presence: Coordinator,                              // 在线目录（TTL）
    vip: VirtualIpAllocator,                            // VIP 权威
    established: HashMap<String /*src locator*/, ControlSession>,
    pending: HashMap<String /*src locator*/, PendingHandshake>,
    cfg: BootstrapServerConfig,
    codec: Box<dyn BootstrapFrameCodec>,
}

pub struct ControlSession {
    pub keys: DirectionalKeys,
    pub replay: ReplayWindow,
    pub node_id: String,          // = peer_id_from_public_key(握手 static_pub)，非自报
    pub established_at: u64,
}

pub struct PendingHandshake {
    pub eph_pub: [u8; 32],
    pub peer_static: [u8; 32],
    pub client_nonce: u64,
    pub assigned_vip: String,
    pub created_at: u64,
}

pub struct SweepReport { pub expired: Vec<String>, pub released_vips: Vec<String> }

#[derive(Debug)]
pub enum BootstrapServerError {
    AuthFailed, BadVip, VipConflict, Malformed, RateLimited,
    Coord(CoordError), Crypto(EncryptionError),
}

impl BootstrapServer {
    pub fn new(
        identity: KeyPair, psk: Vec<u8>, cfg: BootstrapServerConfig,
        codec: Box<dyn BootstrapFrameCodec>,
        persisted: Option<Vec<(String, String)>>,   // 重启恢复 (node_id, vip)
    ) -> Result<Self, BootstrapServerError>;

    /// src 为 carrier.last_peer_locator() 得到的 locator 字符串（不是 SocketAddr）。
    /// 返回 (回包 dst locator, 字节)；静默丢弃时返回 None。
    pub fn handle_datagram(
        &mut self, src_locator: &str, dgram: &[u8], now: u64,
    ) -> Option<(String, Vec<u8>)>;

    fn handle_join_init(&mut self, src: &str, init: /*解出的字段*/, now: u64)
        -> Result<(String, Vec<u8>), BootstrapServerError>;
    fn handle_secured(&mut self, src: &str, blob: &[u8], now: u64)
        -> Option<(String, Vec<u8>)>;

    /// 固定事务顺序：prune 目录 → 逐 peer release VIP → 返回报告（持久化由挂载层批量触发）。
    pub fn sweep_expired(&mut self, now: u64) -> SweepReport;

    pub fn leases_snapshot(&self) -> Vec<(String, String)>; // 落盘内容
    pub fn upsert_self_entry(&mut self, now: u64);          // 目录第 0 条
}
```

**handle_secured 的关键处理**：

1. 按 src 取已建会话；`decrypt_frame` 失败 / `ReplayWindow` 拒绝 → 静默 `None`（不回明文错误，避免成为 oracle/放大器）。
2. **node_id 权威化（S2 的修法）**：服务端在 JoinInit 已存 `peer_static`；解出 Register 后，用 `peer_id_from_public_key(&peer_static)`（`coord.rs:553`，FNV-1a）算出权威 node_id，**忽略**帧内自报 node_id（或强校验相等，不符按 AuthFailed 处理）。此后目录与 VIP 全部以权威 id 为 key。
3. Register → `presence.announce(now, &id, src_locator, lease)`（locator 用 NAT 源，见 §2.5）→ 回 RegisterAck；GetPeers → `presence.peer_list(now)` 排除自己、逐个补 `allocator.peer_vip` → PeerList；Heartbeat → `presence.heartbeat(now, &id, lease)`。

**sweep 事务顺序（崩溃可收敛）**：`presence.prune_expired(now)` 取回过期 id → 逐个 `vip.release(now, id)`（忽略 `PeerUnknown`）→ 报告。即使在摘除与 release 之间崩溃，VIP 表以持久化文件为准、重启重建，最终收敛。

#### 2.5 locator 策略与 NAT 边界

- **以 NAT 源为准的实现位置**：`PacketCarrier` 不返回 SocketAddr——`receive_into` 后须立即读 `last_peer_locator()`（trait 在 `crates/nexus-platform/src/lib.rs:91`；`UdpCarrier` 实现把源写成 `udp://ip:port` 串，`udp_carrier.rs:103-111`），回包走 `send_to(locator, bytes)`（`:93`）。自报 locator 不进目录，仅可作日志。
- **对称 NAT 下该 locator 不可靠（中风险，须在文档注明语义）**：对称 NAT 中客户端→引导的映射端口与客户端→其它 peer 的映射不同，目录 locator 交给 peer 后直连/打洞仍可能失败。现有兜底链是 `ph:/pa:` 打洞（`virtual_subnet.rs:1171-1257`，源学习在 `:1196`）→ 失败后 `fallback_to_relay`（`:955`），但 relay locator 目前只能手工 `set_relay_locator`（`:998`），无自动 TURN 分配。建议：PeerList 支持多候选 locator/NAT 类型标注；引导把已配置的 relay locator 随 JoinReply/PeerList 一并下发，复用 `punch_tick`（`:1081`）已有的 relay 回退逻辑。
- **引导节点本身位于 NAT 后**：需静态端口映射（`UdpCarrier` 要求显式监听 locator，且拒绝 port 0，`udp_carrier.rs:56`）；发夹 NAT 下 hairpin 可达性需 E5 实测。本期不支持引导自身打洞入网。

#### 2.6 持久化

- **落盘内容**：仅 owner→VIP 分配表（`leases_snapshot`）；在线目录易失、靠心跳重建（与设计 §6.3 一致）。
- **路径**：`<config-dir>/data/bootstrap/vip-leases.json`（`data_dir` 约定见 `apps/nexusd/src/workspace.rs:314-315`）。
- **格式与原子写**：版本化 envelope `{"schema_version":1,"payload_sha256":"...","leases":{...}}`，写 `.tmp` → `sync_all` → `rename` → 目录 fsync（模式参照 `apps/nexusd/src/task_store.rs:336-376`，文件 `0600`、目录 `0700`）。
- **跨平台**：`task_store.rs` 整套为 `#[cfg(target_os = "linux")]`（`:2/:45-53`，非 Linux 返回 UnsupportedCapability），不可直接依赖；Windows/macOS 走 `nexus-platform::SecureStore`（`crates/nexus-platform/src/lib.rs:65-68` 的 get/put）或独立小 store。
- **恢复**：启动读文件，逐条 `allocate_specific(now, node, vip)` 幂等回填；校验和不符/损坏 → 视为空表并告警（VIP 表丢失只导致重分配，不造成不一致，不应拒启）。

#### 2.7 服务端挂载点（与隧道同生命周期）

隧道独占 carrier（`virtual_subnet.rs:422/:443`），服务端不能另持 carrier。方案：隧道持有一个可选 hook，收包时转交、回包由隧道代发：

```rust
/// 服务端/客户端会话共同实现，挂在 VirtualSubnetTunnel 上。
pub trait BootstrapHook {
    /// 入参为已剥掉 nxb: 的 payload + NAT 源 locator + now；
    /// 返回需经同一 socket 发出的回包（dst locator, bytes）。
    fn on_control_datagram(
        &mut self, src: Option<&str>, payload: &[u8], now: u64,
    ) -> Option<(String, Vec<u8>)>;

    /// 每 tick 调用：返回待发数据报与 peer 增删（心跳/刷新/服务端 sweep）。
    fn periodic(
        &mut self, now: u64,
    ) -> BootstrapTick;
}

pub struct BootstrapTick {
    pub datagrams: Vec<(String, Vec<u8>)>,
    pub peers_added: Vec<BootstrapPeer>,
    pub peers_gone: Vec<String>,   // 降级不删
}
```

隧道侧改动（精确位置）：

- 结构体（`:422-462`）与 `crypto_sessions`（`:447`）并列新增字段 `bootstrap: Option<Box<dyn BootstrapHook>>`；新增 `pub fn set_bootstrap_hook(&mut self, h: Option<Box<dyn BootstrapHook>>)`。
- `recv_and_deliver`（`:1411`）：签名增加 `now_secs: u64`（调用方 `mesh.rs:223`、`subnet_cli.rs:728` 一并补传；组合根每 tick 取一次 epoch 秒注入）；在 `:1427` 后插入：
  ```rust
  if let Some(rest) = data.strip_prefix(NXB_MAGIC) {
      if let Some(hook) = self.bootstrap.as_mut() {
          let src = self.carrier.last_peer_locator();
          if let Some((dst, bytes)) = hook.on_control_datagram(src.as_deref(), rest, now_secs) {
              self.carrier.send_to(&dst, &bytes).map_err(/* 同文件 Io 映射风格 */)?;
          }
      }
      return Ok(None);
  }
  ```
- 常驻 tick（`mesh.rs:216-272`）：在 `:248-254` 现有 "2b. WAN Bootstrap" 钩子位置，改为从隧道 hook 取 `periodic(now)`：datagrams 经隧道新增的 `send_raw(locator, bytes)`（薄封装 `carrier.send_to`，仅对 bootstrap 内部开放）发出；`peers_added` 复用 `add_discovered_peer`（`mesh.rs:454`）；`peers_gone` 标记降级。sweep 结果按 §2.6 触发一次持久化。

### 3. 客户端装配（功能 B）

#### 3.1 新文件 `crates/nexus-connectivity/src/bootstrap_joiner.rs`

```rust
pub struct BootstrapSession {
    pub keys: DirectionalKeys,
    pub rx_replay: ReplayWindow,
    pub tx_seq: u64,
    pub server_locator: String,
    pub assigned_vip: String,
    pub lease_secs: u32,
    pub hb_interval_ms: u32,
    pub refresh_interval_ms: u32,
    pub last_hb_at: u64,          // 注入时钟，不用 Instant
    pub last_refresh_at: u64,
}

#[derive(Debug)]
pub enum BootstrapJoinError {
    PskRequired, AuthFailed(String), NotBootstrap, Timeout,
    MalformedFrame(String), BadVip(String), AllBootstrapFailed, Io(String),
}

pub struct BootstrapJoiner<'a> {
    carrier: &'a mut dyn PacketCarrier,
    identity: &'a KeyPair,
    psk: &'a [u8],
    codec: &'a dyn BootstrapFrameCodec,
}

impl<'a> BootstrapJoiner<'a> {
    pub fn new(
        carrier: &'a mut dyn PacketCarrier, identity: &'a KeyPair,
        psk: &'a [u8], codec: &'a dyn BootstrapFrameCodec,
    ) -> Self;

    /// 按 servers 顺序尝试；NotBootstrap/AuthFailed/Timeout 换下一个，其余致命错误直接返回。
    pub fn join(
        &mut self, servers: &[BootstrapConfig], requested_vip: Option<&str>,
        deadline: Duration, now: u64,
    ) -> Result<(BootstrapSession, Vec<BootstrapPeer>), BootstrapJoinError>;

    pub fn send_heartbeat(&mut self, s: &mut BootstrapSession, now: u64)
        -> Result<(), BootstrapJoinError>;
    pub fn refresh_peers(&mut self, s: &mut BootstrapSession, now: u64)
        -> Result<(Vec<BootstrapPeer>, Vec<String>), BootstrapJoinError>;
}
```

要点：交接对象必须是 **`BootstrapSession`（含 tx/rx 密钥与 ReplayWindow）**，而非设计 §7.1 只带 peer/间隔的 `JoinOutcome`——否则常驻心跳与回包解密无密钥。客户端侧 `BootstrapHook` 实现内部持有 `BootstrapSession`，`periodic` 按 hb/refresh 间隔产出 Heartbeat/GetPeers 数据报并处理回包。

#### 3.2 `assemble_with` 逐段改造（锚点已核实，`apps/nexus/src/subnet_cli.rs:534-579`）

现状顺序：取 `s = &config.subnet`（`:539`）→ VIP 防御（`:541`）→ `VirtualSubnetTunnel::new`（`:545`）→ 静态 peers（`:550`）→ routes（`:559`）→ prefix_routes（`:564`）→ local_prefixes（`:569`）→ egress（`:572`）→ encryption（`:575`）。carrier 为 `Box<dyn PacketCarrier>` **按值**入参（`:537`）。

1. **`:539` 后、`:541` 前**插入 bootstrap 分支：
   ```rust
   let (mut bootstrap_hook, bootstrap_peers, effective_vip) = if !s.bootstrap.is_empty() {
       let psk = load_network_psk(s)?                    // :292
           .ok_or_else(|| "PSK_REQUIRED: bootstrap join requires psk".to_string())?;
       let identity = load_node_identity(&config_dir)?;  // 见 3.3
       // carrier 在真实路径已由 assemble_real_tunnel bind（:604/:620）；
       // mock 路径（MeshCarrier）无真 UDP，直接报错而非静默跳过。
       let (sess, peers) = BootstrapJoiner::new(&mut *carrier, &identity, &psk, &codec)
           .join(&s.bootstrap, s.virtual_ip.as_deref(), JOIN_DEADLINE, now)?;
       (Some(ClientBootstrap::new(sess)), peers, sess.assigned_vip.clone())
   } else {
       let vip = s.virtual_ip.as_deref()
           .ok_or_else(|| "VIRTUAL_IP_UNRESOLVED".to_string())?;
       (None, Vec::new(), vip.to_string())
   };
   ```
2. **改 `:541-549`**：VIP 防御与 `VirtualSubnetTunnel::new(VirtualSubnetConfig::new(&s.cidr, &effective_vip), vpi, carrier)` 用 effective_vip。
3. **隧道建成后、`:550` 静态 peers 前**：先装 hook（`tunnel.set_bootstrap_hook(bootstrap_hook)`），再加入 bootstrap peer：
   ```rust
   for p in &bootstrap_peers {
       // 静态已存在的同 VIP 跳过（静态为权威），避免 HashMap insert 覆盖（virtual_subnet.rs:893）
       tunnel.add_peer_if_absent(TunnelPeer::new(&p.virtual_ip, &p.locator))?;
   }
   ```
4. **`:550-577` 顺序不变**，保证旧配置字节级兼容。

#### 3.3 持久身份接通（S7 修法）

`node init` 已把 X25519 seed 写入 `node/identity`（`apps/nexus/src/node_cli.rs:204-240`，字段 `x25519_seed_hex` 在 `:221`），但无回读函数。新增：

```rust
// apps/nexus/src/node_cli.rs（或独立 identity_loader.rs）
pub fn load_node_identity(config_dir: &Path) -> Result<KeyPair, String> {
    // 读 node/identity → 取 x25519_seed_hex（64 hex）→ [u8;32] → KeyPair::from_seed
    // 不存在：首次自动 init（持久化）并提示；禁止在装配路径再用 KeyPair::generate()
}
```

注意区分：`n2_identity.rs:26` 是 **ed25519**（N2 授权），bootstrap 用的是 **X25519** `encryption::KeyPair`（`:127`，`from_seed` 在 `:150`）。启用 bootstrap 后 `subnet_cli.rs:340` 的临时 generate 仅保留给无 bootstrap 的 legacy 路径。

#### 3.4 常驻与一次性路径

- **常驻只有 CLI `--foreground` 一条**：真实路径 `subnet_foreground_real`（`apps/nexus/src/main.rs:614`）→ `AutoMeshController::new(tunnel, 500)`（`:640`）→ `run_with_save`（`:648`，循环在 `mesh.rs:216`）。心跳/刷新按 §2.7 挂 `:248-254` 钩子。
- **nexusd 不承载 bootstrap（S4）**：`run_dataplane`（`apps/nexusd/src/main.rs:351-368`）是 TUN 泵（process_one 在 `:357`、sleep 1ms 在 `:361`），不持有隧道/socket。若产品要求 daemon 常驻 bootstrap，须在 nexusd 组合根新增"隧道+UdpCarrier+控制器"宿主线程，属新增开发而非接线；建议本期只落 CLI foreground 并在文档明确。
- **一次性 `subnet up`（S6 修法）**：`subnet_up` 的 `_tunnel` 在 `:348` drop；`--tun` 路径 `subnet_up_tun` 在 `:643` drop 真实隧道后回调 `:644`。建议检测 `!foreground && !s.bootstrap.is_empty()` → 直接报错 `BOOTSTRAP_REQUIRES_FOREGROUND`。若保留"预拉表写状态"，须给 `SubnetState`（`:142-163`）扩 peer 列表，由下一 foreground 进程经 `mesh.load_state`（`mesh.rs:957`）恢复。
- **tick 收包容量**：主循环每 500ms tick（`mesh.rs:271`），现每 tick 只 `recv_and_deliver` 一次（`:223`）。建议把 socket 排空到 WouldBlock 再 sleep（控制帧/打洞/数据同 socket 排队），E5 压测确认控制帧不被饿死。

#### 3.5 故障转移

- `bootstrap` 数组按序尝试（现有客户端配置结构 `BootstrapConfig{address,name}` 在 `subnet_cli.rs:105-112`，校验在 `:222-245`：非空强制 PSK `:223`、必须 `udp://` `:227`）。
- `NotBootstrap/Timeout` 切换下一个；`AuthFailed` 在"收到 JoinReply 但 RegisterAck 超时"时判定（joiner 是 initiator，自身 PSK 错误要到这一步才暴露），PSK 全网一致前提下快速失败合理。
- 租约期内失联：下个周期改连备用引导重新 join；VIP 按 node_id 幂等（`coord.rs:223-226`），多引导表互不同步是本期已声明限制。

#### 3.6 共存与热加载

- **静态 peers**：`:550-558` 不变；同 VIP 冲突以静态为权威（§3.2 第 3 步）。
- **路由面**：bootstrap peer 只进 `peers`，不自动进 routes/prefix_routes/egress——`validate()`（`:255-279`）已强制 next_hop 必须是静态 peer，bootstrap 节点默认只做直接互通，无路由归属冲突。
- **N1 mesh / proxy(TUN)**：nexusd 的 N1（`assembly.rs`）与 proxy_fwd（`main.rs:336-348`）走独立 TUN dataplane，与 CLI 隧道不共享 socket；同机并跑仅存在 TUN 设备名/MTU 占用问题（nexusd 建 TUN `main.rs:303-316`，CLI 建 TUN `subnet_cli.rs:607/:624`）。
- **热加载**：CLI foreground 不重读配置；nexusd watcher 只轮询 5 个固定文件（`watcher.rs:67-73`，不含 subnet.toml），network.toml 变更判 NeedsRestart（`config.rs:522`）。bootstrap/bootstrap_server 变更天然走重启，文档注明即可。
- **崩溃恢复**：控制会话易失、重启必须重新 join；`mesh.load_state`（`mesh.rs:957`）只恢复 peer locator，二者互补。

### 4. 配置键与校验

```toml
[subnet.bootstrap_server]            # 缺失 = 普通节点
enabled = true
lease_secs = 60                      # 建议 3×hb_interval
hb_interval_ms = 20000
refresh_interval_ms = 60000
```

- 在 `SubnetSection`（`subnet_cli.rs:84` 附近）新增 `#[serde(default)] pub bootstrap_server: Option<BootstrapServerSection>`。
- 该 section 加 `#[serde(deny_unknown_fields)]`（现反序列化默认忽略未知键，`:201-204`，拼错字段不报错）；在 `validate()`（`:209`）尾部追加：lease>0、间隔>0、enabled 为 bool。
- 客户端继续沿用已存在的 `[[subnet.bootstrap]]`（`:84-86/:105-112`），旧校验不变。

### 5. 分阶段落地（对设计 §11 的修正）

| 阶段 | 内容（修正后） | 门禁 |
|---|---|---|
| P1 | `bootstrap_join.rs` 外层帧 + `split_outer` + 单测；`load_node_identity`。**release 已存在（coord.rs:278），从 P1 删除** | `cargo test -p nexus-discovery` 全绿、无 warning |
| P2 | 服务端纯逻辑：Coordinator + allocator + codec trait + 半开防护，内存 carrier 对；PSK fail-closed / VIP 软冲突 / 过期摘除三测 | `cargo test -p nexus-connectivity`；harness `bootstrap-join` PASS |
| P3 | joiner + `assemble_with` 五处接线 + `recv_and_deliver` 分流（含 now 入参）+ mesh `:248` 钩子替换 + 一次性 up 报错 | `cargo test -p nexus` 旧用例不回归 |
| P4 | 真实 UDP 单 socket 分流、服务端角色、VIP 表持久化（loopback） | E5 loopback 手动验收，不进 pre-push |
| P5 | 真机/NAT、多引导故障转移、断电恢复、relay 下发 | E5 真机，记录 evidence |

---

## 三、问题与风险清单（统一编号，已去重）

### 严重

| 编号 | 问题 | 证据 | 建议 |
|---|---|---|---|
| S1 | 服务端放 connectivity 却调 discovery 帧，违反"connectivity 不能依赖 discovery"红线 | `fib_resolver.rs:4`；两 Cargo.toml 互无依赖；`decode_auto_frame` 在 `auto_discovery.rs:302` | §二.2.1 trait 注入（同 `set_fib_resolver`，`virtual_subnet.rs:557`） |
| S2 | node_id 为会话内自报值，未绑定握手 static 公钥；持 PSK 者可冒名/抢 VIP | `coord.rs:553`（peer_id_from_public_key 未被服务端使用）；ControlSession.node_id 客户端可控 | 服务端用 static_pub 派生权威 node_id，忽略/强校验自报值 |
| S3 | 未认证 JoinInit 即预建会话，sweep 只清目录不清半开表；伪造轮换源无界堆条目 | 设计 §6.2"预建 ControlSession"；会话体积对照 `virtual_subnet.rs:77-81` | 每 src 半开上限+LRU、JoinInit 速率限制，或无状态 cookie；pending 设短 TTL |
| S4 | nexusd 不持有隧道/socket，"daemon 常驻"对象不存在 | nexusd grep 无 VirtualSubnetTunnel；`main.rs:351-368` 为 TUN 泵 | 本期常驻只落 CLI foreground；daemon 承载单列新增开发 |
| S5 | carrier 被隧道私有 move，常驻心跳/刷新无发包出口 | `virtual_subnet.rs:443/:466-497`，无 carrier_mut/raw-send | BootstrapHook + 会话收编为隧道字段（§二.2.7） |
| S6 | 一次性 up（含 --tun）装配即 drop，join 后无人建连/心跳 | `subnet_cli.rs:348/:643/:644` | 非 foreground + bootstrap 直接报错 |
| S7 | node init 落了 seed 但装配路径用一次性 generate 且无回读 | `node_cli.rs:221`；`subnet_cli.rs:340` | 新增 `load_node_identity` 并注入装配 |

### 中

| 编号 | 问题 | 证据 | 建议 |
|---|---|---|---|
| M1 | 外层 tag 未定义，若 JoinInit 编 0x01 与 Secured version 字节冲突 | `encryption.rs:44/:50`；设计 §5.2 无 outer tag 规则 | tag 从 0x10 起；Secured 用"首字节 0x01 且 len≥38"探针 |
| M2 | PSK 错时服务端无法加密 AuthFailed，客户端只能超时；Error{AuthFailed} 不可达 | `virtual_subnet.rs:1480`（解密失败）；`encryption.rs:414-419` | 客户端按"Reply 后 Ack 超时"归类认证失败；服务端保持静默 |
| M3 | nonce 绑定无干净落点：AAD 硬编码、salt 不含 nonce | `encryption.rs:478/:417/:420-437` | nonce 入 AEAD plaintext 前缀（不改冻结签名） |
| M4 | allocate_specific 不校验 CIDR/网络地址/广播 | `coord.rs:252-275` | 服务端调前自校验（参照 `subnet_cli.rs:214`） |
| M5 | 池从 .1 起跳，服务端自身 .1 会被首个客户端拿走 | `coord.rs:237`；测试 allocate 返 .1（`:603`） | 启动 allocate_specific 占位自身 VIP |
| M6 | 对称 NAT 下 NAT 源 locator 对 peer 不可达；relay 只能手工配 | `virtual_subnet.rs:1196/:955/:998` | 多候选 locator + 引导下发 relay locator |
| M7 | 设计 handle_datagram 用 SocketAddr，与 carrier 的 locator 字符串模型不符 | `udp_carrier.rs:93/:103-126`；`lib.rs:83-100` | 改用 locator 字符串，src 收包后即读 |
| M8 | sweep 与 release 崩溃中间态未约定 | `coord.rs:278`；设计 §6.2/6.3 无顺序 | 固定 prune→release→持久化，重启以持久化表收敛 |
| M9 | owner 字符串客户端可控可刷量耗尽池；VIP 回收后旧主活跃连接仍路由该地址 | `coord.rs:223-249/:285` | 单域 owner 上限/速率；回收地址设宽限期再入池 |
| M10 | task_store 为 Linux 专用强类型 ledger，不能直接存 VIP 表 | `task_store.rs:2/:45-53` | 借原子写模式，落盘走 SecureStore（`lib.rs:65-68`） |
| M11 | nxb 数据报现落入试解密硬错误/解头失败并被 eprintln 吞掉 | `virtual_subnet.rs:1490/:1500`；`mesh.rs:235` | `:1427` 后插分流，返回 Ok(None) |
| M12 | 非 tun 路径无法 join：UdpCarrier 拒 port 0、MeshCarrier 无真 UDP | `udp_carrier.rs:56-60`；`virtual_subnet.rs:1925-1952` | bootstrap 仅允许真实 carrier，mock 路径显式报错 |
| M13 | BootstrapConfig/BootstrapClient 三处同名（含 mesh.rs:771 HTTP 死代码） | `subnet_cli.rs:105`；`mesh.rs:748-901` | HTTP 版改名/删除；新代码用 BootstrapEndpoint/Session |
| M14 | 每 tick 仅读 1 个数据报，高负载控制帧跨 tick 延迟 | `mesh.rs:223/:271` | tick 内排空 socket；E5 压测 |
| M15 | bootstrap add 与静态 peer 同 VIP 时 HashMap insert 覆盖静态 locator | `virtual_subnet.rs:893/:550` | 静态已存在则跳过，静态为权威 |
| M16 | bootstrap 配置不在 nexusd 热加载白名单，变更只能重启 | `watcher.rs:67-73`；`config.rs:522` | 文档注明，无需改 watcher |
| M17 | 新造 BootstrapDirectory/sweep 与已有 TTL Coordinator 重复 | `coord.rs:69-147/:632-658` | 复用 Coordinator + 补 prune_expired |
| M18 | MeshCarrier recv_buf 为扁平字节流，多帧拼接污染解码 | `virtual_subnet.rs:1944-1952/:1883` | harness 严格 lockstep，或给 carrier 补报文队列 |
| M19 | 本仓无远程 CI；pre-push 仅 verify --fast，harness 场景属 full 不被执行 | `.githooks/pre-push:22`；`policies/quality.toml:18-46` | 确定性断言沉 crates 单测（affected-tests 覆盖） |

### 低

| 编号 | 问题 | 证据 | 建议 |
|---|---|---|---|
| L1 | 场景 toml 的 `non_zero` 断言被解析器静默丢弃 | `engineering/nexus-harness/src/scenario.rs:76-88`；反例 `virtual_subnet_mesh_3node.toml:56` | 用 `equals`/`non_empty`；建议修解析器 |
| L2 | 设计 §5.1 分流表漏列 hs: | `virtual_subnet.rs:1444` | 分流表补 hs: 行 |
| L3 | 文档基线 bb6201b 与实际 HEAD cda5f21 不一致 | `git log` | 实现前约定基线并重核行号 |
| L4 | harness 场景手动 pump、无后台线程，真实轮询无法直接复用 | `run_scenario.rs`（如 `:73/:92`） | harness 只验一次 join/refresh，轮询归 P3/P4 |
| L5 | derive_vip 与服务端权威分配语义重叠，测试易漂移 | `coord.rs:572` 与 `:223` | 测试一律以 assigned_vip 为唯一真相 |
| L6 | 未认证路径放大比约 1.36×（JoinInit≈78B→Reply≈106B），非放大器；PeerList 须先认证 | 设计 §5.2 字段推算 | 保持 Reply 小体积、未认证不发 PeerList |
| L7 | ReplayWindow 首帧无条件接受 | `encryption.rs:568-576` | 依赖 M3 的 nonce 绑定兜底 |
| L8 | NAT rebinding 换 src 即换会话/窗口（半开名额可被这样刷新） | `udp_carrier.rs:109` | 配合 S3 每 src 上限；重连靠 node_id 幂等 |
| L9 | recv 不返回源地址，靠 last_peer_locator 侧信道，拦截顺序错会读错源 | `virtual_subnet.rs:1411`；`udp_carrier.rs:109`；先例 `:1196` | 分支内先读源再决定回包 |
| L10 | 前序所称 `auto_discovery_flow` 测试/"零真实网络"注释在仓库不存在（实为 encryption.rs:4 模块注释） | 全仓 grep；`encryption.rs:4` | 仅澄清 |
| L11 | toml 未知键默认被 serde 忽略 | `subnet_cli.rs:201-204` | 新 server section 加 deny_unknown_fields |
| L12 | 同机 nexusd 与 CLI 都建 TUN 可能抢设备名/MTU | `main.rs:303-316`；`subnet_cli.rs:607/:624` | 二选一或区分 tun_name【推断】 |
| L13 | 设计 JoinOutcome 未带会话密钥，常驻心跳无密钥 | 设计 §7.1；`encryption.rs:492/:568` | 以 BootstrapSession 替代 JoinOutcome |

---

## 四、验证方案

### 1. E4 离线确定性场景（进 harness）

- **分发扩展点（已核实）**：`engineering/nexus-harness/src/run_scenario.rs:9-27` 为手写 match（11 个现有场景，无注册中心）。在 `:20` arm 之后、`:21` `_ =>` 之前加 `"bootstrap-join" => run_bootstrap_join(),`；新函数加在文件末尾（`run_qos_cake` 结束于 `:1768` 之后）。
- **场景骨架要点**（完整伪码见分片 D）：3 个 `MeshCarrier`（定义于 `virtual_subnet.rs:1881`），`connect_peer`（`:1902`）/`recv_handle`（`:1908`）显式连 S<->A、S<->C，A/C 初始零 peer；服务端挂真实 `VirtualIpAllocator::new`（`coord.rs:204`）+ codec；A join 后 C join，断言 C 的 PeerList 含 A；用 join 结果 `add_peer`（`:884`，TunnelPeer::new `:106`）；A→C 发 20B IP 包，按 `run_virtual_subnet_mesh`（`run_scenario.rs:148-284`，收发断言在 `:218-230`）的方式逐跳 `recv_and_deliver` 比对 payload。全程注入 `now`（初始如 1000），无 sleep/SystemTime。
- **lockstep 硬约束（M18）**：MeshCarrier `receive_into` 一次 drain 扁平 buf（`:1944-1952`），多帧握手必须"发一帧→对方 handle→取回复→再发"，否则拼接污染。
- **场景契约**：新增 `engineering/nexus-harness/scenarios/product/bootstrap_join.toml`（仿 `virtual_subnet_mesh_3node.toml`），`evidence_strength = "E4"`，断言只用解析器真实支持的 `equals`/`one_of`/`non_empty`（`scenario.rs:76-88`），**不要写 non_zero**。

### 2. 断言 → 代码位置对照

| 断言 | 取数位置 |
|---|---|
| 新节点 static_peers=0 入网 | 初始 `peers().is_empty()`（`virtual_subnet.rs:1284`） |
| assigned_vip 在 CIDR | allocator 返回值（`coord.rs:223`）/ JoinReply |
| PeerList 含已在线节点 | `Coordinator::peer_list`（`coord.rs:123`），顺序确定 |
| add_peer 数量正确 | `peers().len()`（`:1284`；先例 `run_scenario.rs:241-242`） |
| A→C 数据可达 | `send_ip_packet`（`:1295`）+ `recv_and_deliver`（`:1411`），payload 长度/内容相等（`:218-230`） |
| PSK 错/重放被拒 | 原语层：`decrypt_frame`（`encryption.rs:492`）、`check_and_accept`（`:568`）——只进单测，不进 harness JSON |

### 3. 应新增单测

| 单测 | 归属/插入点 | 断言 |
|---|---|---|
| `bootstrap_join_frame_roundtrip` | 新建 `nexus-discovery/src/bootstrap_join.rs` 末尾 | 三帧往返；未知 tag/截断/trailing → Transport（仿 `auto_discovery.rs:495-558`） |
| `nxb_magic_vs_data_frame_demux` | `virtual_subnet.rs` 测试模块（`:1961`，邻 `:2720`） | nxb 被分流吃掉、不写 VPI；NXP1 仍走管线/解封装，不串路 |
| `psk_mismatch_no_directory_entry` | 服务端新文件测试末尾 | 错 PSK → 不 announce、不回 PeerList，`peer_list(now)` 不含该节点 |
| `vip_soft_conflict_returns_assigned` | 同上 | 申请值被占（`coord.rs:267`）→ 另分配，JoinReply 带实际值 |
| `lease_expiry_prunes_and_releases` | 同上 | 推进 now → prune 摘除、release 回池，同址可被新 peer allocate 复用 |
| `replayed_secured_frame_rejected` | 同上 | 同帧喂两次，第二次 ReplayWindow 拒，目录不重复 touch |
| `all_bootstrap_servers_failed` | `bootstrap_joiner.rs` 末尾 | 全失败 → AllBootstrapFailed，且逐端切换 |

> 密码学原语行为已在 `encryption.rs:759`（wrong key）、`:863`（重放拒绝）、`coord.rs:600-623`（冲突/释放）覆盖，新测只补"服务端编排/策略分支"，不重复测原语。

### 4. CI 增量与门禁现实（M19）

- 本仓无远程 Actions，CI = git hooks：pre-commit 跑 whitespace + `cargo fmt --check`；pre-push（`.githooks/pre-push:22`）跑 `nexus-harness verify --fast`，fast gates 见 `policies/quality.toml:18-28`（含 affected-tests = 改动 crate 的 `cargo test -p`）；product-scenarios 属 full（`:30-46`），pre-push 不跑。
- 推荐：确定性断言全部沉到 crates 单测（pre-push 的 affected-tests 自然覆盖）；harness `bootstrap-join` 留 `verify --full` 与发布前手动：
  ```bash
  cargo test -p nexus-discovery -p nexus-connectivity -p nexus-harness
  cargo run -p nexus-harness -- run bootstrap-join --json
  nexus-harness verify --full
  ```
- E5（loopback/真机）不进 fast，与现有 `coord_join_loopback`（标 E5）一致。

### 5. E5 真实链路

- loopback：1 引导（`[bootstrap_server]`）+ 2 零静态 peer，复用/扩展 `coord_join_loopback_flow`（`apps/nexus/src/lib.rs:7095`，已标 E5，双节点真实 127.0.0.1 闭环；改三节点即可，不必新造）。验证互见、P2P UDP、心跳维持、杀节点后租约到期消失且 VIP 回收。
- 真机：引导放公网 UDP（设计 §12 的 VPS 场景），内网节点零配置入网，验证对称 NAT 下打洞/relay 互通；引导位于 NAT 后的端口映射与发夹场景。
- 如需独立可执行驱动：新增薄壳 example `apps/nexus/examples/bootstrap_join_loopback.rs`（examples 均为薄壳，见 `auto_discovery.rs:13`）+ `nexus::bootstrap_join_loopback_flow()`。

### 6. 编译验证（已在本会话实测通过）

```bash
export PATH="$HOME/.cargo/bin:$PATH"
S=/home/user/Doubao/chats/38445385826129666
git clone /home/user/Doubao/chats/38445294397368066/nexus-fabric "$S/build/wt"
cd "$S/build/wt"
export CARGO_TARGET_DIR="$S/build/target"
cargo check -p nexus-discovery -p nexus-connectivity -p nexus-harness --all-targets  # 基线 50.22s、exit 0
cargo run -p nexus-harness -- run virtual-subnet-mesh --json                        # 已复现 PASS
```

按依赖序 `-p`：nexus-platform → nexus-discovery → nexus-connectivity → nexus-harness → nexus；不要用 `--workspace`（49 个 member）。

---

## 五、代码位置总索引（已核实）

### 帧与发现（nexus-discovery）

| 主题 | 位置 |
|---|---|
| `AutoDiscoveryFrame`（tag 11-14） | `crates/nexus-discovery/src/auto_discovery.rs:201-214`（tag `:194-197`） |
| `encode_auto_frame` / `decode_auto_frame` | `auto_discovery.rs:265` / `:302`（trailing/未知 tag 拒于 `:343`） |
| `BootstrapRegistry`（无 TTL 的原型） | `auto_discovery.rs:55-101`（register `:66`/get_peers `:77`/heartbeat `:89`） |
| `DiscoveredNode` DTO | `auto_discovery.rs:42-51` |
| 测试模块 | `auto_discovery.rs:349` |
| 字符串 u16 BE 编解码 | `crates/nexus-discovery/src/lib.rs:408/:417` |
| 外层帧（待新建） | `crates/nexus-discovery/src/bootstrap_join.rs` |

### 协调与 VIP（nexus-connectivity/coord.rs）

| 主题 | 位置 |
|---|---|
| `Coordinator`（TTL 在线目录） | `crates/nexus-connectivity/src/coord.rs:69-147`（announce `:81`/heartbeat `:104`/peer_list `:123`/resolve_locator `:132`） |
| `VirtualIpAllocator` 结构 | `coord.rs:192-200`（Lease `:151-154`） |
| `new` / CIDR 解析（prefix 2-30、主机位全 0） | `coord.rs:204` / `:163-189` |
| `allocate`（幂等、FIFO 复用、.1 起跳） | `coord.rs:223-249` |
| `allocate_specific`（不校验 CIDR） | `coord.rs:252-275` |
| `release`（**已存在**） | `coord.rs:278-287` |
| `peer_vip` / `len` / `is_empty` | `coord.rs:291` / `:300` / `:306` |
| `peer_id_from_public_key`（FNV-1a） | `coord.rs:553-560` |
| `derive_vip`（FNV-1a static‖nonce） | `coord.rs:572-589` |
| 测试模块（过期 `:632`、冲突/释放 `:600/:613`） | `coord.rs:591` |

### 加密（nexus-connectivity/encryption.rs）

| 主题 | 位置 |
|---|---|
| `KeyPair`（generate/from_seed/public_key_bytes） | `encryption.rs:127`（`:143/:150/:168`） |
| `DirectionalKeys` | `encryption.rs:229-249` |
| HKDF base / PSK salt | `encryption.rs:331` / `:364-368`（info `:361`） |
| `derive_authed_keys_with_psk`（不吃 nonce） | `encryption.rs:420-437` |
| 帧头 22B（ver+type+seq8+nonce12，无 length） | `encryption.rs:61/:454-461` |
| `encrypt_frame`（AAD 硬编码于 `:478`） | `encryption.rs:466` |
| `decrypt_frame`（version/type 校验 `:496/:499`） | `encryption.rs:492` |
| `ReplayWindow`（宽 1024，首帧 `:569`） | `encryption.rs:538`（check_and_accept `:568`） |
| 测试模块（wrong key `:759`、replay `:863`） | `encryption.rs:666` |
| 常量 WIRE_VERSION/FRAME_DATA/REPLAY_WINDOW | `encryption.rs:44/:50/:63` |

### 隧道（nexus-connectivity/virtual_subnet.rs）

| 主题 | 位置 |
|---|---|
| `VirtualSubnetTunnel` 结构（carrier 私有 `:443`、identity `:451`） | `virtual_subnet.rs:422-462`（crypto_sessions `:447`） |
| `new`（carrier move 入） | `virtual_subnet.rs:466-497` |
| `TunnelPeer` / `TunnelPeer::new` | `virtual_subnet.rs:94-114` / `:106-113` |
| `add_peer`（Disconnected 插入、insert 覆盖 `:893`） | `virtual_subnet.rs:884-903` |
| `set_peer_state` | `virtual_subnet.rs:1259` |
| `begin_hole_punch_multi` / `punch_tick` | `virtual_subnet.rs:1033-1073` / `:1081-1120` |
| `fallback_to_relay` / `set_relay_locator` | `virtual_subnet.rs:955` / `:998` |
| 打洞帧处理（学源 `:1196`、回 pa、置 Connected） | `virtual_subnet.rs:1171-1257` |
| `send_ip_packet` / `peers()` / peer_stats | `virtual_subnet.rs:1295` / `:1284` / `:1278` |
| `recv_and_deliver` 与全分流序 | `:1411`；NXP1 `:1430`、hs `:1444`、ph/pa `:1472`、试解密硬错误 `:1477-1492`、明文解头 `:1499-1505`；**nxb 插入点 `:1427 后`** |
| 遗留明文 `src->dst:` 头 | `virtual_subnet.rs:391-396` |
| `MemoryVpi` / connected_pair / MemoryCarrier | `:1686` / `:1779` / `:1749`（send_to 忽略 locator `:1822`） |
| `MeshCarrier`（connect_peer `:1902`/recv_handle `:1908`/路由 `:1931`/扁平 drain `:1944-1952`） | `virtual_subnet.rs:1881-1952` |
| 架构红线注释 | `crates/nexus-connectivity/src/fib_resolver.rs:4`（FibResolver 注入先例 `virtual_subnet.rs:557`） |

### 承载（nexus-platform）

| 主题 | 位置 |
|---|---|
| `PacketCarrier` trait（bind/send_to/receive_into/last_peer_locator） | `crates/nexus-platform/src/lib.rs:83-100`（last_peer `:91`） |
| `SecureStore` trait | `crates/nexus-platform/src/lib.rs:65-68` |
| `UdpCarrier` locator 解析（拒 port 0 `:56`） | `crates/nexus-platform/src/udp_carrier.rs:37-62` |
| bind（set_nonblocking `:79`） | `udp_carrier.rs`（`UdpCarrier::new`） |
| `receive_into`（记 last_peer `:103-111`、WouldBlock→0 `:112`） | `udp_carrier.rs:103-126` |
| NXP1 magic / 6B 头 / is_pipeline_unit | `crates/nexus-connectivity/src/dataplane_pipeline.rs:20/:27/:350` |

### CLI 与 daemon

| 主题 | 位置 |
|---|---|
| `SubnetSection`（bootstrap `:84-86`）/ 客户端 `BootstrapConfig` | `apps/nexus/src/subnet_cli.rs:84-86` / `:105-112` |
| bootstrap 校验（PSK `:223`、udp:// `:227`） | `subnet_cli.rs:222-245` |
| `validate()`（路由 next_hop 校验 `:255-279`） | `subnet_cli.rs:209` |
| `load_network_psk` | `subnet_cli.rs:292-325`（互斥 `:293`、0600 `:310`） |
| `subnet_up`（临时 identity `:340`、`_tunnel` drop `:348`） | `subnet_cli.rs:327-389`；SubnetState `:142-163` |
| `assemble_with` | `subnet_cli.rs:534-579`（carrier `:537`、静态 peers `:550`） |
| `assemble_default_tunnel` | `subnet_cli.rs:583-590` |
| `assemble_real_tunnel`（win/linux，bind 先于 assemble） | `subnet_cli.rs:597-611` / `:614-628` |
| `subnet_up_tun`（隧道即弃 `:643`、回调 `:644`） | `subnet_cli.rs:635-649` / `:652-667` |
| `assemble_real_tunnel_for_daemon` | `subnet_cli.rs:676-684` |
| `subnet_punch` 轮询范式（bind `:711`、recv `:728`、tick `:734`、sleep `:740`） | `subnet_cli.rs:691-786` |
| node 身份写入（seed `:221`） | `apps/nexus/src/node_cli.rs:204-240` |
| ed25519 身份（勿混淆） | `apps/nexus/src/n2_identity.rs:26-74` |
| foreground 分发 / mock 常驻 / 真实常驻 | `apps/nexus/src/main.rs:491` / `:557-603`（`:577/:585`）/ `:614-650`（`:640/:648`） |
| `AutoMeshController` 结构 / `new_with_options(None,None)` | `apps/nexus/src/mesh.rs:122-137` / `:150-152` |
| 常驻循环（recv `:223`、WAN hook `:248-254`、drive_punches `:257`、save `:264`、sleep `:271`） | `apps/nexus/src/mesh.rs:216-278` |
| `add_discovered_peer` / `load_state` | `mesh.rs:454-475` / `:957`（save/load `:924-994`） |
| HTTP 版 `BootstrapConfig`/`BootstrapClient`（死代码） | `mesh.rs:748-757` / `:771-901` |
| app flow：auto_discovery / coord_join_loopback(E5) | `apps/nexus/src/lib.rs:2813` / `:7095` |
| nexusd 主循环（TUN 泵） | `apps/nexusd/src/main.rs:351-368`（TUN 建立 `:303-316`、proxy `:336-348`） |
| nexusd watcher / config NeedsRestart | `apps/nexusd/src/watcher.rs:67-73` / `config.rs:522` |
| nexusd assembly（N1） | `apps/nexusd/src/assembly.rs:1-40` |
| task_store 原子写模式（Linux-only） | `apps/nexusd/src/task_store.rs:336-376`（cfg `:2/:45-53`） |
| data_dir 定位 | `apps/nexusd/src/workspace.rs:314-315` |

### 验证工程

| 主题 | 位置 |
|---|---|
| harness 场景 match | `engineering/nexus-harness/src/run_scenario.rs:9-27`（mesh 场景 `:148-284`；文件末尾 `:1768`） |
| Outcome 类型 / JSON 合并 / 退出码 | `engineering/nexus-harness/src/main.rs:17` / `:35-37` / `:52-56`（--json `:21`） |
| 断言解析（equals/one_of/non_empty） | `engineering/nexus-harness/src/scenario.rs:76-88`（执行 `:393`） |
| 场景 gate | `engineering/nexus-harness/src/commands.rs:291-299` |
| cargo gates（fmt/check/clippy/props/workspace/affected） | `engineering/nexus-harness/src/gates.rs:100/:108/:116/:135/:143/:164` |
| fast/full gate 声明 | `policies/quality.toml:18-28` / `:30-46` |
| pre-commit / pre-push | `.githooks/pre-commit` / `.githooks/pre-push:22` |
| 场景 toml 模板 | `engineering/nexus-harness/scenarios/product/virtual_subnet_mesh_3node.toml`（non_zero 于 `:56`） |
| TURN 零件（未自动接入隧道） | `crates/nexus-turn/src/{client,server,stun}.rs` |

---

*本报告基于 cda5f21 工作树评审；行号随代码演进会漂移，实现前请在约定基线上复核。*
