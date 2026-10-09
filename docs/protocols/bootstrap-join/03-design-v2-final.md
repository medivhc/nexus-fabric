# Nexus Fabric · Bootstrap 自动入网设计（v2 修订版）

> 范围：两个功能——(A) 引导节点服务端；(B) 客户端装配接上 bootstrap。
> 设计原则：复用现有 UDP 承载与加密体系，**不新增任何加密原语、不新增端口、不破坏静态 peers 旧路径**。
> 本文只描述设计，不含最终实现代码；给出 Rust 接口骨架与对接点。
> 行号基准：工作树 **HEAD = `cda5f21`**（v1 自称 `bb6201b`，已更正）。
> 证据标记：**【已核实】** = 对照 `cda5f21` 工作树打开文件确认；**【待验证】** = 据已核实结构推演、需实现或实测时复核。
> 本版（v2）依据评审报告逐条修订 v1；不是重新评审，也不含实现代码。

---

## 0. 相对 v1 的变更摘要 Changelog

v2 逐条落实评审的 7 个阻断项（S1–S7）与 3 处事实更正（C1–C3）。

| 编号 | v1 的问题 / 原说法 | v2 的修订决策 | v2 对应章节 |
|---|---|---|---|
| **S1** | `bootstrap_server.rs` 放在 `nexus-connectivity`，却要调 `nexus-discovery::decode_auto_frame`；违反 `fib_resolver.rs:4`「connectivity 不能依赖 discovery」红线【已核实】 | connectivity 纯逻辑只依赖自有的 `BootstrapCtrl`/`BootstrapPeer`/`BootstrapFrameCodec` trait，不命名 discovery 帧；由 `apps/nexus` 组合根用 discovery 的 `encode/decode_auto_frame` 实现注入（同 `FibResolver` 注入先例） | §5.5、§6.1、§6.5 |
| **S2** | `Register{node_id}` 是会话内客户端自报字符串，持全网 PSK 者可冒名注册、抢占他人 VIP；已存在的 `peer_id_from_public_key`（`coord.rs:553`）未被使用【已核实】 | `PendingHandshake` 存 `peer_static`；服务端解出 Register 后用 `peer_id_from_public_key(&peer_static)` 派生权威 node_id，**忽略**自报值（或强校验相等，不符按 AuthFailed 静默处理）；目录与 VIP 一律以权威 id 为 key | §5.6、§6.2 |
| **S3** | 未认证 JoinInit 即预建 ControlSession，而 sweep 只清目录、不清半开表；UDP 源可伪造轮换，无界堆条目形成 DoS【已核实】 | 新增半开防护：每 src 半开上限 4、全局 pending 上限 1024、每 src JoinInit 速率 10 次/60s、pending TTL 10s 随 periodic 清扫；过载启用无状态 cookie（HMAC），超限回 RateLimited/丢弃 | §5.7、§6.2、§10 |
| **S4** | v1 §7.3 称常驻走「CLI `--foreground` / daemon 模式」；实际 nexusd 通篇不持有 `VirtualSubnetTunnel`/UDP socket，其常驻循环是 TUN 收包泵（`apps/nexusd/src/main.rs:351`）【已核实】 | **foreground 为唯一受支持的 bootstrap 常驻运行方式**；nexusd 本期明确标注不支持 bootstrap，仅给出「新增隧道宿主线程」的改造轮廓并列为后续 | §1、§7.3 |
| **S5** | `VirtualSubnetTunnel::new` 把 carrier move 进私有字段（`virtual_subnet.rs:443/:466`），无 raw-send 出口；joiner 一次性借用无法延伸到常驻循环，心跳/刷新无发包出口【已核实】 | 会话收编为隧道字段：`VirtualSubnetTunnel` 新增 `bootstrap: Option<Box<dyn BootstrapHook>>` + `set_bootstrap_hook` + 内部 `send_raw`；`recv_and_deliver` 增加 `now_secs` 入参 | §6.4、§7.3、§9 |
| **S6** | 一次性 `subnet up`（含 `--tun`）装配即 drop 隧道（`subnet_cli.rs:348` / `:643`），join 后无人打洞/心跳，与 bootstrap 语义矛盾【已核实】 | `subnet_up`(:327)/`subnet_up_tun`(:652) 开头判定 `!foreground && !bootstrap.is_empty()` → 错误码 `BOOTSTRAP_REQUIRES_FOREGROUND`，非零退出并打印受支持方式 | §7.3、§10 |
| **S7** | v1 §5.3 称「客户端默认用持久身份」，但装配路径用一次性 `KeyPair::generate()`（`subnet_cli.rs:340`）；`node init` 已落 seed（`node_cli.rs:221`）却无回读函数【已核实】 | 新增 `load_node_identity(config_dir)` 读 `node/identity` 的 `x25519_seed_hex` → `KeyPair::from_seed`，不存在则自动 init；注入 `assemble_with`；`generate()` 仅保留给无 bootstrap 的 legacy 路径 | §7.2、§9 |
| **C1** | v1 §9/§11 P1 把 `VirtualIpAllocator::release(now, peer)` 列为待补缺口 | **`release` 已存在**（`coord.rs:278`，幂等、回 free_pool、已被 `coord.rs:613` 测试覆盖）【已核实】：从缺口表与 P1 删除，sweep 直接调用 | §6.2、§9、§11 |
| **C2** | v1 §6.1 要新造 `BootstrapDirectory` + `sweep_expired` | 同仓已有带 TTL 过期、注入时钟、已测的 `Coordinator`（`coord.rs:69`）【已核实】：复用它作为在线目录，仅补一个 `prune_expired(now)->Vec<String>`（插入点 `:147` 后） | §6.1、§9 |
| **C3** | v1 §5.4 假设 `allocate_specific` 校验 VIP 落在 CIDR；§8.1 把服务端自身配成 `.1` | `allocate_specific`（`coord.rs:252`）只 parse+查重、**不校验 CIDR/网络/广播**【已核实】；分配池 `.1` 起跳（`coord.rs:237`）【已核实】。服务端调前自补 CIDR 校验（参照 `subnet_cli.rs:214`），启动先 `allocate_specific(now,"__bootstrap_self__",server_vip)` 占位 | §5.4、§6.2 |

---

## 1. 目标与非目标

### 目标
1. 新机器入网只需：一个引导节点 `udp://host:port` + 全网 PSK，**无需静态列出任何 peer**。
2. 引导节点对新节点做 **PSK 认证**、**权威分配/确认 VIP**、返回**当前在线节点列表（VIP + locator）**。
3. 客户端拿到列表后批量 `add_peer_if_absent`，后续建连**完全复用现有直连 → 打洞 → relay** 逻辑。
4. 在线状态靠心跳维持，节点掉线后其条目在 TTL 后自动从注册表清除并回收 VIP。
5. 新节点入网后，后续上线的节点也能被已在线节点**周期性刷新发现**。

### 运行方式约束（据 S4/S6 修订）
- **foreground 为本期唯一受支持的 bootstrap 运行方式**：CLI `--foreground` → `subnet_foreground_real`（`apps/nexus/src/main.rs:614`）→ `AutoMeshController::new(tunnel, 500)`（`:640`）→ `run_with_save`（循环在 `mesh.rs:216`）。【已核实】
- **nexusd 本期不支持 bootstrap**：`run_dataplane`（`apps/nexusd/src/main.rs:351-368`）是 TUN 收包泵（`process_one` `:357`、sleep 1ms `:361`），不持有隧道/UDP socket，无发包出口。【已核实】
- 一次性 `subnet up`（不常驻）+ bootstrap 配置：**直接报错** `BOOTSTRAP_REQUIRES_FOREGROUND`（见 §7.3），不静默半接入网。

### 非目标（本期不做）
- 不做多引导节点之间的注册表同步（引导节点是单点权威；多引导仅作客户端侧故障转移）。
- 不替换 fabric 的 QUIC 传输；bootstrap 控制面走子网 UDP 隧道，不走 QUIC。
- 不做证书/PKI 体系，认证只用对称 PSK（与现有 `network_psk` 语义一致）。
- 不处理跨子网的 VIP 分配（本期限定单一 `[subnet].cidr`）。
- 不做 nexusd 常驻承载 bootstrap（仅给改造轮廓，列为后续）；不做引导节点自身打洞入网。

---

## 2. 现状盘点：可直接复用的零件（行号已按 cda5f21 更正）

| 能力 | 现有实现（位置，cda5f21） | 复用方式 |
|---|---|---|
| 控制帧类型 | `AutoDiscoveryFrame{Register,GetPeers,PeerList,Heartbeat}`（`auto_discovery.rs:201`，tag 11–14 在 `:194-197`）【已核实】 | **不直接扩展**：connectivity 侧另定义解耦子集 `BootstrapCtrl`（§5.5），由组合根 codec 映射；内层 `RegisterAck` 增量加 tag 15 |
| 帧编解码 | `encode_auto_frame` / `decode_auto_frame`（`auto_discovery.rs:265` / `:302`，trailing/未知 tag 拒于 `:343`）【已核实】 | 由组合根 codec 实现 `BootstrapFrameCodec` |
| 在线目录（TTL） | `Coordinator::{announce,heartbeat,peer_list,resolve_locator}`（`coord.rs:69-147`，`:81/:104/:123/:132`）【已核实】 | **直接复用**为服务端在线目录（替换 v1 自造 BootstrapDirectory）；仅补 `prune_expired` |
| VIP 分配器结构 | `VirtualIpAllocator` 结构（`coord.rs:192-200`）、`new`（`:204`）、CIDR 解析（`:163-189`）【已核实】 | 服务端 VIP 权威分配 |
| VIP 分配/确认 | `allocate`（`:223`，按 owner 幂等、free_pool FIFO、`.1` 起跳）/ `allocate_specific`（`:252`，不校验 CIDR）【已核实】 | 见 §5.4；CIDR 由服务端自补校验 |
| VIP 释放 | `release`（`coord.rs:278`，**已存在**，幂等回 free_pool，测试 `:613`）【已核实】 | sweep 直接调用；v1「待补 release」撤销 |
| VIP 查询 | `peer_vip` / `len` / `is_empty`（`coord.rs:291` / `:300` / `:306`）【已核实】 | PeerList 逐条补 VIP |
| 权威 node_id 派生 | `peer_id_from_public_key`（`coord.rs:553`，FNV-1a）【已核实】 | S2：服务端以握手 static 公钥派生权威 node_id |
| 客户端自派生 VIP | `derive_vip(static_pub, cidr, nonce)`（`coord.rs:572`）【已核实】 | 仅作申请建议值；一律以 JoinReply.assigned_vip 为准 |
| PSK 加载/校验 | `load_network_psk`（`subnet_cli.rs:292`，内联/0600 文件、互斥校验 `:293/:310`）【已核实】 | 客户端与服务端共用 |
| PSK 混合握手 | `derive_authed_keys_with_psk`（`encryption.rs:420`）【已核实】 | bootstrap 会话密钥派生（不吃 nonce，见 §5.3） |
| AEAD + 防重放 | `encrypt_frame` / `decrypt_frame` / `ReplayWindow`（`encryption.rs:466`/`:492`/`:538`，check_and_accept `:568`，窗口 1024）【已核实】 | 控制帧加密与重放拦截 |
| 密钥对 | `KeyPair::{generate,from_seed,public_key_bytes}`（`encryption.rs:127`，`:143/:150/:168`）【已核实】 | 节点持久/临时身份；持久身份回读见 §7.2（S7） |
| UDP 承载 | `PacketCarrier` trait（`nexus-platform/src/lib.rs:83-100`，`last_peer_locator` `:91`、`send_to` `:93`）+ `UdpCarrier`（`udp_carrier.rs`）【已核实】 | 控制帧与数据帧共用 socket；src 取 locator 字符串而非 SocketAddr |
| 对端装配 | `VirtualSubnetTunnel::{add_peer(:884),set_peer_state(:1259),begin_hole_punch_multi(:1033)}`【已核实】 | 拉回列表后批量调用；新增 `add_peer_if_absent` 语义见 §7.2 |
| 架构红线/注入先例 | `fib_resolver.rs:4`；FibResolver 注入 `virtual_subnet.rs:557`【已核实】 | S1：同构注入 `BootstrapFrameCodec` |

**结论（沿用 v1 并修正）**：协议帧、VIP 分配、PSK 认证的密码学零件全部存在且被测试覆盖；在线目录 `Coordinator`、VIP `release` 也已存在。真正缺口收敛为四块——
①外层 Join/认证帧 + 编解码（`bootstrap_join.rs`）；②connectivity↔discovery 的 codec trait 注入；③服务端 UDP 事件循环（挂在隧道 hook 上）；④客户端 joiner + `assemble_with` 接线。

---

## 3. 总体方案

- 引导节点是网内一个**普通节点**，额外开启一个可开关的「bootstrap 服务端」角色；它与数据面**共用同一个 UDP socket**（服务端不能另持 carrier，见 §6.4）。
- 复用数据面的「明文公钥握手 + PSK 派生会话密钥」模型：握手包只含 X25519 公钥（无秘密），**认证结果由「首个 AEAD 控制帧能否被对端解密」来证明**——PSK 错误则解密失败。这与现有 PSK 数据面的安全模型逐字一致（`encryption.rs:414-419` 注释）。【已核实】
- 控制帧用 **magic 前缀 `nxb:`** 与 NXP1 数据帧区分，在同一 socket 上分流（首字节确定性互斥，见 §5.1）。
- VIP 由服务端用 `VirtualIpAllocator` **权威分配**；客户端可带申请值，冲突时服务端回传分配值，客户端一律以服务端确认为准。
- node_id 由握手 static 公钥**权威派生**（S2），不信任客户端自报字符串。
- 半开握手做**有界防护**（S3），未认证阶段不回大体积消息、不发 PeerList。

```text
                 ┌────────────────────────────────────────────┐
                 │   引导节点 S（普通节点 + BootstrapHook 挂在隧道上）│
                 │   BootstrapServer                            │
                 │    ├ pending: 半开握手表（有界 + 速率 + TTL）  │
                 │    ├ established: 已认证会话（密钥+ReplayWindow）│
                 │    ├ presence: Coordinator（node→locator/TTL）│
                 │    └ vip: VirtualIpAllocator（权威，持久化）   │
                 └───────▲───────────────────────▲─────────────┘
            nxb: JoinInit/控制帧 │                 │ nxb: JoinInit/控制帧
                  ┌────────────┴───────┐   ┌───────┴────────┐
                  │ 新节点 A            │   │ 新节点 C         │
                  │ ClientBootstrap(hook│   │ ClientBootstrap  │
                  │  持 BootstrapSession)│   │ → 拉回 peers     │
                  └─────────────────────┘   └─────────────────┘
        A、C 各自 add_peer_if_absent(对方) → 现有 直连/打洞/relay 建连
```

---

## 4. 入网时序（v1 §4 修订：体现身份绑定、半开防护、认证时点）

```mermaid
sequenceDiagram
    participant C as 新节点 C（持久 static）
    participant S as 引导节点 S（普通节点+服务端）
    participant P as 已在线 P

    Note over C: load_node_identity 读 x25519 seed（S7）
    Note over S: 启动: 占位 server_vip；载入 vip-leases.json 恢复
    C->>S: nxb:0x10 JoinInit{eph_c, static_c, requested_vip?, client_nonce}
    activate S
    Note over S: 半开防护: 每src/全局上限+JoinInit速率; 超限 RateLimited/丢弃
    Note over S: 建 PendingHandshake(peer_static 入库); 预分配 VIP
    S->>C: nxb:0x11 JoinReply{eph_s, static_s, assigned_vip, lease, 间隔, server_nonce, cookie?}
    deactivate S
    Note over C: derive_authed_keys_with_psk(initiator=true)
    C->>S: nxb:Secured[首字节0x01] AEAD{ client_nonce‖server_nonce ‖ Register{node_id*,vip,locator} }
    activate S
    Note over S: decrypt + ReplayWindow; 比对 nonce 前缀
    Note over S: peer_static→peer_id_from_public_key 派生权威 id
    Note over S: 自报 id 不符 → 静默丢弃（PSK错时无法回 AuthFailed，M2）
    S->>C: AEAD{RegisterAck{accepted, ttl_secs}}
    C->>S: AEAD{GetPeers{权威 node_id}}
    S->>C: AEAD{PeerList{peers（含 S 自身第0条，exclude C）}}
    deactivate S
    Note over C: 对每个 peer add_peer_if_absent
    C->>P: 现有 直连 → 打洞 → relay 建连
    loop 每 hb_interval_ms
        C->>S: AEAD{Heartbeat} 刷新 TTL
    end
    loop 每 refresh_interval_ms
        C->>S: AEAD{GetPeers} 增量发现新上线节点
    end
```

> `node_id*` = 帧内自报值仅作显示/日志；服务端以 `peer_static` 派生值为准（§5.6）。

---

## 5. 线协议设计

### 5.1 复用端口的帧分流

UDP socket 收到数据报后按**首字节确定性互斥**分流（非概率碰撞，误判概率为 0）。现有 `recv_and_deliver` 起于 `virtual_subnet.rs:1411`【已核实】：

| 行号 | 判定 | 失败行为 |
|---|---|---|
| `:1427` | `let data = buffer[..n].to_vec();`（取出去重后的完整数据报） | — |
| **插入点** | **`:1427` 之后、`:1430` 之前：`data.strip_prefix(NXB_MAGIC)` → 交 `BootstrapHook`，处理完 `return Ok(None)`** | 控制帧不进入管线/试解密 |
| `:1430` | NXP1 管线单元探针 `dataplane_pipeline::is_pipeline_unit`（magic `dataplane_pipeline.rs:20`，头 6B） | 前缀不符则 fall-through |
| `:1444` | `data.starts_with(b"hs:")` 握手帧 | fall-through（v1 漏列，已补） |
| `:1472` | `data.starts_with(b"ph:") \|\| b"pa:"` 打洞帧（magic 默认 `NXHP`，`:160`） | fall-through |
| `:1477`–`:1492` | 加密模式：遍历 `crypto_sessions` 对**整段 data** 试 `decrypt_frame`；**无会话命中即硬错误返回** `CRYPTO_ERROR: no matching session or bad tag`（`:1490`） | **硬错误，不 fall-through** |
| `:1499`–`:1504` | 明文模式：`TunnelFrameHeader::deserialize`，失败硬错误 `invalid tunnel frame header` | **硬错误** |

**为什么插在 `:1427` 后、`:1430` 前**：`:1477` 的试解密循环对整段 data 判定 `frame[0] != 0x01` 即全部失败并在 `:1490` **硬错误返回**；明文解头在 `:1499` 同样硬错误。若 nxb 分支落在其后，bootstrap 数据报会被当坏帧硬错误吞掉（M11，`eprintln` 吞错）。因此分支必须位于 `:1477` 之前；`:1430/:1444/:1472` 均为前缀 fall-through，插在其后结构上也能工作，但最早点最稳妥、且控制帧不进管线。

**首字节互斥表（已核实）**：

| 帧类 | 首字节 |
|---|---|
| NXP1 管线（`N`） | `0x4E` |
| `hs:` 握手（`h`） | `0x68` |
| `ph:`/`pa:` 打洞（`p`） | `0x70` |
| AEAD 数据帧（`WIRE_VERSION=1`，`encryption.rs:44`） | `0x01` |
| 遗留明文 `src->dst:` 头（`virtual_subnet.rs:391`，点分十进制数字） | `0x30`–`0x39` |
| **`nxb:` 控制帧（`n`）** | **`0x6E`** |

六类首字节两两不等，是确定性前缀分类。`nxb` = **N**e**x**us **B**ootstrap，外层结构 `b"nxb:" + payload`。

### 5.2 外层帧（新文件 `crates/nexus-discovery/src/bootstrap_join.rs`）

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
    // C -> S，明文（仅 X25519 公钥 + 申请值，无秘密）
    JoinInit {
        eph_pub: [u8; 32],
        static_pub: [u8; 32],
        requested_vip: Option<String>, // None = 请服务端分配
        client_nonce: u64,
    },
    // S -> C，明文
    JoinReply {
        eph_pub: [u8; 32],
        static_pub: [u8; 32],
        assigned_vip: String,          // 服务端权威确认
        lease_secs: u32,                // 注册租约
        hb_interval_ms: u32,
        refresh_interval_ms: u32,
        server_nonce: u64,
    },
    // 服务端错误（见 §5.3：线上 AuthFailed 对 PSK 不符不可达）
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
/// 禁止用「未知外层 tag 即当密文」的 fallback（未来扩展 tag 时会误判，M1）。
pub fn split_outer(payload: &[u8]) -> Result<OuterFrame<'_>, DiscoveryError>;
```

**字节规则**（沿用 `auto_discovery.rs` 确定性编码）：帧首 1B tag；公钥固定 32B（`PUBLIC_KEY_LEN=32`，`encryption.rs:53`）【已核实】；字符串 `u16 BE` 长度前缀 + UTF-8（复用 `nexus-discovery/src/lib.rs:408/:417` 的 `put_str/get_str`）【已核实】；`Option<String>` 先 1B presence；整数 `u64 BE`（nonce）、`u32 BE`（lease/间隔）；未知 tag / 截断 / 非法 UTF-8 / trailing bytes 一律 `DiscoveryError::Transport`（对照 `decode_auto_frame` `auto_discovery.rs:302`）。【已核实】

> 认证后内层 payload = `AEAD(encode_auto_frame(...))`，即 §5.5 的 `BootstrapCtrl` 经 codec 映射后的字节。

### 5.3 会话密钥与认证

- 双方各持持久 `static` 身份（`node init` 生成）。JoinInit/JoinReply 交换临时 `eph` 公钥后调用（`encryption.rs:420`）【已核实】：
  ```rust
  pub fn derive_authed_keys_with_psk(
      my_static: &KeyPair, my_eph: &KeyPair,
      peer_static: &[u8; 32], peer_eph: &[u8; 32],
      initiator: bool, psk: &[u8],
  ) -> Result<DirectionalKeys, EncryptionError>;
  ```
  PSK 拼进 HKDF salt（`b"nexus-link-encryption-v2" ∥ psk`，`encryption.rs:364-368`；info 为排序后的 static 公钥），返回 `DirectionalKeys { tx, rx }`（`:229`）。【已核实】
- 控制帧：`encrypt_frame(&keys.tx, seq, plaintext)`（`:466`）；对端 `decrypt_frame(&keys.rx, blob) -> (seq, plain)`（`:492`）+ `ReplayWindow::check_and_accept(seq)`（`:568`）。
- **认证时点不对称（必须实现，M2）**：
  - 服务端：收到客户端首个 AEAD 帧才能判定 PSK 是否一致；PSK 错 → 解密失败 → **静默丢弃**（无法回 `AuthFailed`，因为派生不出可加密该消息的密钥）。
  - 客户端：JoinReply 是明文，客户端要等服务端对其 Register 的 AEAD 回包（RegisterAck）才能判定；PSK 错时表现为**超时**。
  - 因此线上 `Error{AuthFailed}` 对 PSK 不符场景**不可达**；客户端应把「收到 JoinReply 但 RegisterAck 超时」归并为认证失败候选，与「引导不可达」区分打印。服务端保持静默，避免成为 oracle/放大器。
- **PSK 错 → 不落任何注册条目、不回 PeerList**。
- **nonce 绑定（M3，不改冻结签名）**：已核实 `encrypt_frame` 仅 `(key, seq, plaintext)`，AAD 硬编码为 22B 帧头（`encryption.rs:478`），`derive_authed_keys_with_psk` 不吃 nonce。推荐方案：把 `client_nonce ‖ server_nonce`（各 8B）作为 **AEAD plaintext 前缀**，解密后与 JoinInit/JoinReply 阶段按 src 存下的期望值比对。备选（改动面大、不推荐）：新增 `encrypt_frame_with_aad` 变体或给派生函数加 salt——二者动与数据面共享的冻结函数，须先过架构评审。
- **首帧无重放保护**：`ReplayWindow` 对首帧直接以该 seq 为基准清零位图（`encryption.rs:569-576`）【已核实】——这正是 nonce 前缀绑定必须存在的理由（L7）。

### 5.4 VIP 分配规则（服务端权威，据 C3 修正）

已核实分配器行为：`allocate`（`:223`，按 owner 幂等、free_pool FIFO 复用、`.1` 起跳、跳过网络/广播）；`allocate_specific`（`:252`，**只 parse IP + 查重，不校验 CIDR、不排除网络/广播**）；`release`（`:278`，已存在）。

服务端 `handle_join_init` 的分配顺序：

1. `requested_vip = None` → `allocator.allocate(now, &authoritative_node_id)`。
2. `requested_vip = Some(v)`：
   - **先自补 CIDR 校验**（分配器不做，M4）：用与 `parse_cidr` 同款判定检查 `v` 在网内、且非网络/广播地址；越界 → `BadVip`。可对照 `subnet_cli.rs:214` 对 virtual_ip 的现有校验。【已核实】
   - `allocate_specific(now, &id, v)`：成功确认；被**别的 node_id** 占用（`AddressInUse`，`:267-269`）→ 回退 `allocate(now, &id)` 另取，JoinReply 返回实际值（软冲突，不报错）。
3. **服务端自身 VIP 占位（M5）**：分配池 `.1` 起跳（`:237`），而引导节点对外 VIP 通常就是网内 `.1`。`BootstrapServer::new` **开放分配前**先 `allocate_specific(now, "__bootstrap_self__", &cfg.server_vip)`（占位 owner 与普通 node_id 命名空间分开），否则首个客户端会拿到 `.1` 与服务端隧道撞号。
4. 客户端一律以 `JoinReply.assigned_vip` 覆盖本地 `virtual_ip` 与 `derive_vip`（`coord.rs:572`）结果；测试一律以 assigned_vip 为唯一真相（L5）。
5. **持久化恢复**：启动读 `<config-dir>/data/bootstrap/vip-leases.json`，逐条 `allocate_specific(now, node, vip)` 幂等回填（§6.6）。

### 5.5 【新增·S1】帧编解码 trait 注入

**问题**：`bootstrap_server.rs` 若放 `nexus-connectivity` 却调 `nexus-discovery::decode_auto_frame`，违反 `crates/nexus-connectivity/src/fib_resolver.rs:4` 的红线「connectivity 不能依赖 discovery」（两 crate 当前互不相依，Cargo.toml 已核实）。【已核实】

**决策**：服务端纯逻辑（目录、VIP、会话、加解密）放 `nexus-connectivity`，但不直接命名 discovery 的帧类型；在 connectivity 定义与 discovery 解耦的控制消息子集与编解码 trait，由 `apps/nexus` 组合根用 discovery 帧实现注入——与 `FibResolver`（`virtual_subnet.rs:557`）完全同构。【已核实】

```rust
// ===== crates/nexus-connectivity/src/bootstrap_server.rs（connectivity 侧，不依赖 discovery）=====
/// 与 discovery 帧解耦的 bootstrap 控制消息（仅 bootstrap 所需子集）。
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

**组合根适配结构（apps/nexus）**：
- 新文件建议 `apps/nexus/src/bootstrap_codec.rs`，结构名如 `DiscoveryBootstrapCodec`；【待验证】结构名以实现时仓库约定为准。
- 内部持有（或直接调用）nexus-discovery 的 `encode_auto_frame` / `decode_auto_frame`（`auto_discovery.rs:265`/`:302`），在 `BootstrapCtrl` ↔ `AutoDiscoveryFrame` 之间做映射。
- **内层 `RegisterAck` 需给 `AutoDiscoveryFrame` 增量加 tag 15**：现有帧只有 Register/GetPeers/PeerList/Heartbeat（tag 11–14，`auto_discovery.rs:194-197`），无 RegisterAck。旧节点不参与 bootstrap，增量 tag 不影响旧路径（旧解码器对未知 tag 报 Transport 错误，属预期）。【已核实】

**注入点（文件:行号）**：
- `BootstrapServer::new` **第 4 参数 `codec: Box<dyn BootstrapFrameCodec>`**（签名见 §6.1）。【已核实】
- 隧道侧 `set_bootstrap_hook`（§6.4）：服务端角色的 hook 持有 `BootstrapServer`，客户端角色的 hook 持有 `ClientBootstrap`；二者都经组合根注入同一 `DiscoveryBootstrapCodec`。
- 证据：`fib_resolver.rs:4`（红线）、`virtual_subnet.rs:557`（FibResolver 注入先例）、`main.rs:640`（组合根 `AutoMeshController::new` 处装配）。【已核实】

> 备选归属（方案 B 服务端整体放 discovery、方案 C 写在 apps/nexus）均不推荐：B 需新增 discovery→connectivity 依赖边并过架构评审；C 单测性最差。

### 5.6 【新增·S2】身份与 node_id 绑定

**问题**：`Register{node_id}` 是会话内客户端自报字符串，持全网 PSK 的任何节点都可冒名注册、抢占他人 VIP；`peer_id_from_public_key`（`coord.rs:553`，FNV-1a）已存在却未被服务端使用。【已核实】

**决策**：
- 服务端在 JoinInit 阶段把 `static_pub` 存入 `PendingHandshake.peer_static`（§6.1）。
- `handle_secured` 解出 `BootstrapCtrl::Register` 后，用
  ```rust
  let authoritative_id = peer_id_from_public_key(&pending.peer_static); // coord.rs:553
  ```
  算出权威 node_id；**忽略**帧内自报 `node_id`（或强校验与权威 id 相等，不符按 AuthFailed 处理）。此后目录与 VIP 全部以权威 id 为 key。【已核实】
- 冒名拒绝流程：自报 id ≠ 权威 id → 不 `announce`、不 `peer_vip`，按 §5.3 的静默策略丢弃（服务端在未完成认证前不回明文错误，避免 oracle）。【待验证】是否在已认证会话内对「自报 id 不符」回一个 AEAD `RegisterAck{accepted:false}` 由实现定；fail-closed 底线是不把冒名 id 写入目录。

### 5.7 【新增·S3】半开连接防护

**问题**：v1 在未认证的 JoinInit 即预建会话，而 sweep 只清目录、不清待验证会话；UDP 源可伪造，轮换源即可无界堆条目。【已核实】

**决策（全部参数）**：

| 维度 | 参数 | 处置 |
|---|---|---|
| 每 src 半开上限 | `max_pending_per_src = 4`（进 `BootstrapServerConfig`） | 超限：新 JoinInit 回 `RateLimited` 或直接丢弃 |
| 全局 pending 上限 | `1024`（建议） | 超限：拒绝新 JoinInit（优先淘汰最旧 pending） |
| 每 src JoinInit 速率 | `10 次 / 60s`（滑动窗口） | 超限：`RateLimited`，不建 PendingHandshake |
| pending TTL | `10s`，随 `periodic(now)` 清扫 | 到期未完成首帧 AEAD → 摘 pending、不释放 VIP（VIP 仅在分配后随目录/sweep 回收） |
| 过载无状态 cookie | `token = HMAC(服务端长期密钥, src_locator ‖ time_window)` | 全局 pending 触顶时，JoinReply 改为要求客户端**回显 cookie**；无有效 cookie 的 JoinInit 直接丢弃 |

- 超限一律回 `BootstrapErrorCode::RateLimited`（或静默丢弃，二选一；未认证阶段回包需小体积）。
- 半开表只在**已分配 VIP 之后**才占资源；速率计数在 `handle_join_init` 入口即执行。
- 配合 L8（NAT rebinding 换 src 即换会话/窗口）：重连靠 node_id 幂等拿回同 VIP，不依赖半开名额复用。

---

## 6. 引导节点服务端设计（功能 A，按评审 §二.2 重写）

### 6.1 结构与函数签名

```rust
// crates/nexus-connectivity/src/bootstrap_server.rs
pub struct BootstrapServerConfig {
    pub lease_secs: u32,
    pub hb_interval_ms: u32,
    pub refresh_interval_ms: u32,
    pub server_vip: String,         // 入册第 0 条
    pub server_locator: String,     // 对外可达 locator
    pub max_pending_per_src: usize, // 半开防护，见 §5.7
}

pub struct BootstrapServer {
    identity: KeyPair,
    psk: Vec<u8>,
    presence: Coordinator,                              // 在线目录（TTL）——复用，不再造 BootstrapDirectory
    vip: VirtualIpAllocator,                            // VIP 权威
    established: HashMap<String /*src locator*/, ControlSession>,
    pending: HashMap<String /*src locator*/, PendingHandshake>,
    cfg: BootstrapServerConfig,
    codec: Box<dyn BootstrapFrameCodec>,               // S1 注入
}

pub struct ControlSession {
    pub keys: DirectionalKeys,
    pub replay: ReplayWindow,
    pub node_id: String,       // = peer_id_from_public_key(握手 static_pub)，非自报（S2）
    pub established_at: u64,
}

pub struct PendingHandshake {
    pub eph_pub: [u8; 32],
    pub peer_static: [u8; 32], // S2：权威 node_id 派生来源
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
        codec: Box<dyn BootstrapFrameCodec>,            // S1：第 4 参数
        persisted: Option<Vec<(String, String)>>,       // 重启恢复 (node_id, vip)
    ) -> Result<Self, BootstrapServerError>;

    /// src 为 carrier.last_peer_locator() 得到的 locator 字符串（不是 SocketAddr，M7）。
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

### 6.2 核心处理

`handle_datagram` 流程：
1. `strip_prefix(NXB_MAGIC)` 失败 → 不是我的帧，返回 `None`（交回隧道继续 fall-through；实际分流点已在 `:1427` 后拦截，此处双保险）。
2. `split_outer(payload)`：
   - `Plain(JoinInit)` → `handle_join_init`：先过 S3 速率/半开上限；生成 `eph_s`；按 §5.4 分配/确认 VIP；把 `peer_static`/`client_nonce`/`assigned_vip` 存入 `pending`（按 src locator）；回 `JoinReply`。
   - `Secured(blob)` → `handle_secured`。

`handle_secured` 关键处理：
1. 按 src 取 `established` 会话；`decrypt_frame` 失败 / `ReplayWindow` 拒绝 → 静默 `None`（不回明文错误，避免 oracle/放大器）。
2. 校验 AEAD plaintext 前 16B 的 `client_nonce‖server_nonce` 与该 src 在 Join 阶段存下的期望值一致（§5.3）。
3. **node_id 权威化（S2）**：从 pending/established 取出 `peer_static`，`peer_id_from_public_key` 派生权威 id，忽略/强校验帧内自报 id。
4. `codec.decode(plain)` 解出 `BootstrapCtrl`：
   - `Register` → `presence.announce(now, &id, src_locator, lease)`（locator 用 NAT 源）→ 回 `RegisterAck{accepted:true, ttl_secs}`。
   - `GetPeers` → `presence.peer_list(now)` 排除自己、逐个 `vip.peer_vip` 补 VIP → `PeerList`。
   - `Heartbeat` → `presence.heartbeat(now, &id, lease)`（未知 peer → `PeerUnknown`，可回 Ack 或静默）。

**sweep 事务顺序（崩溃可收敛，M8）**：`presence.prune_expired(now)` 取回过期 id → 逐个 `vip.release(now, id)`（忽略 `PeerUnknown`）→ 报告。即使在摘除与 release 之间崩溃，VIP 表以持久化文件为准、重启重建，最终收敛。

### 6.3 在线目录：复用 Coordinator + 补 prune_expired

已核实 `Coordinator`（`coord.rs:69-147`）已具备 `announce(:81)`/`heartbeat(:104)`/`peer_list(:123)`/`resolve_locator(:132)`，VIP 不进 Coordinator，由 `VirtualIpAllocator::peer_vip`（`:291`）补充。【已核实】

唯一需补的 API（Coordinator 目前只在查询时惰性过滤、`presences` 私有且无主动摘除，无法驱动 VIP 回收）：

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

这同时修掉 Coordinator presence vec 只增不减的内存增长问题。【已核实插入点；实现体以评审 §二.2.2 冻结】

### 6.4 BootstrapHook 挂载（S5）

隧道独占 carrier（`virtual_subnet.rs:422/:443`）【已核实】，服务端不能另持 carrier。方案：隧道持有一个可选 hook，收包转交、回包由隧道代发：

```rust
/// 服务端/客户端会话共同实现，挂在 VirtualSubnetTunnel 上。
pub trait BootstrapHook {
    /// 入参为已剥掉 nxb: 的 payload + NAT 源 locator + now；
    /// 返回需经同一 socket 发出的回包 (dst locator, bytes)。
    fn on_control_datagram(
        &mut self, src: Option<&str>, payload: &[u8], now: u64,
    ) -> Option<(String, Vec<u8>)>;

    /// 每 tick 调用：返回待发数据报与 peer 增删（心跳/刷新/服务端 sweep）。
    fn periodic(&mut self, now: u64) -> BootstrapTick;
}

pub struct BootstrapTick {
    pub datagrams: Vec<(String, Vec<u8>)>,
    pub peers_added: Vec<BootstrapPeer>,
    pub peers_gone: Vec<String>,   // 降级不删
}
```

隧道侧改动（精确位置，均【已核实】）：
- 结构体（`:422-462`）与 `crypto_sessions`（`:447`）并列新增字段 `bootstrap: Option<Box<dyn BootstrapHook>>`；新增 `pub fn set_bootstrap_hook(&mut self, h: Option<Box<dyn BootstrapHook>>)`。
- `recv_and_deliver`（`:1411`）：签名增加 `now_secs: u64`（调用方 `mesh.rs:223`、`subnet_cli.rs:728` 一并补传；组合根每 tick 取一次 epoch 秒注入）；在 `:1427` 后插入：
  ```rust
  if let Some(rest) = data.strip_prefix(NXB_MAGIC) {
      if let Some(hook) = self.bootstrap.as_mut() {
          let src = self.carrier.last_peer_locator();   // 分支内先读源，L9
          if let Some((dst, bytes)) = hook.on_control_datagram(src.as_deref(), rest, now_secs) {
              self.carrier.send_to(&dst, &bytes).map_err(/* 同文件 Io 映射风格 */)?;
          }
      }
      return Ok(None);
  }
  ```
- 隧道新增内部 `send_raw(locator, bytes)`：薄封装 `carrier.send_to`，仅对 bootstrap 内部开放（常驻 tick 发心跳/刷新/sweep 回执）。
- 常驻 tick（`mesh.rs:216-272`）：在 `:248-254` 现有「2b. WAN Bootstrap」钩子位置，改为从隧道 hook 取 `periodic(now)`：`datagrams` 经 `send_raw` 发出；`peers_added` 复用 `add_discovered_peer`（`mesh.rs:454`）；`peers_gone` 标记降级不删。sweep 结果按 §6.6 触发一次持久化。

### 6.5 locator 策略与 NAT 边界

- **以 NAT 源为准**：`PacketCarrier` 不返回 SocketAddr——`receive_into` 后须立即读 `last_peer_locator()`（trait `nexus-platform/src/lib.rs:91`；`UdpCarrier` 把源写成 `udp://ip:port` 串，`udp_carrier.rs:103-111`），回包走 `send_to(locator, bytes)`（`:93`）。【已核实】自报 locator 不进目录，仅可作日志（防伪造/污染）。
- **对称 NAT 下该 locator 不可靠（中风险，须注明语义）**：对称 NAT 中客户端→引导的映射端口与客户端→其它 peer 的映射不同，目录 locator 交给 peer 后直连/打洞仍可能失败。现有兜底链是 `ph:/pa:` 打洞（`virtual_subnet.rs:1171-1257`，源学习 `:1196`）→ 失败后 `fallback_to_relay`（`:955`），但 relay locator 目前只能手工 `set_relay_locator`（`:998`），无自动 TURN 分配。【已核实】建议：PeerList 支持多候选 locator/NAT 类型标注；引导把已配置的 relay locator 随 JoinReply/PeerList 一并下发，复用 `punch_tick`（`:1081`）已有的 relay 回退逻辑。【待验证】
- **引导节点本身位于 NAT 后**：需静态端口映射（`UdpCarrier` 要求显式监听 locator，且拒绝 port 0，`udp_carrier.rs:56`）；发夹 NAT 下 hairpin 可达性需 E5 实测。本期不支持引导自身打洞入网。【已核实；hairpin 待实测】
- **放大比（L6）**：未认证路径 JoinInit≈78B → JoinReply≈106B，放大比约 **1.36×**，非放大器；保持 Reply 小体积，未认证不发 PeerList（PeerList 须先认证）。

### 6.6 持久化

- **落盘内容**：仅 owner→VIP 分配表（`leases_snapshot`）；在线目录易失、靠心跳重建。
- **路径**：`<config-dir>/data/bootstrap/vip-leases.json`（`data_dir` 约定见 `apps/nexusd/src/workspace.rs:314-315`）。【已核实】
- **格式与原子写**：版本化 envelope `{"schema_version":1,"payload_sha256":"...","leases":{...}}`，写 `.tmp` → `sync_all` → `rename` → 目录 fsync（模式参照 `apps/nexusd/src/task_store.rs:336-376`，文件 `0600`、目录 `0700`）。【已核实】
- **跨平台（M10）**：`task_store.rs` 整套为 `#[cfg(target_os="linux")]`（`:2/:45-53`，非 Linux 返回 UnsupportedCapability），不可直接依赖；Windows/macOS 走 `nexus-platform::SecureStore`（`crates/nexus-platform/src/lib.rs:65-68` 的 get/put）或独立小 store。【已核实】
- **恢复**：启动读文件，逐条 `allocate_specific(now, node, vip)` 幂等回填；校验和不符/损坏 → 视为空表并告警（VIP 表丢失只导致重分配，不造成不一致，不应拒启）。

### 6.7 服务端自身入册

- `BootstrapServer::new` 先 `allocate_specific(now, "__bootstrap_self__", &cfg.server_vip)` 占位（§5.4 第 3 步），再开放分配。
- `upsert_self_entry(now)` 把自己（`server_vip` + `server_locator`）作为目录第 0 条；新节点的 PeerList 含它，可直接与引导建连。
- 服务端只做「入网网关 + 目录」，不强制节点间数据流量经过它（P2P 直连/打洞）。

---

## 7. 客户端装配设计（功能 B，按评审 §二.3 重写）

### 7.1 BootstrapSession 与 BootstrapJoiner（完整签名）

```rust
// crates/nexus-connectivity/src/bootstrap_joiner.rs
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
    codec: &'a dyn BootstrapFrameCodec,   // S1 注入
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

**要点（L13）**：交接对象必须是 **`BootstrapSession`（含 tx/rx 密钥与 ReplayWindow）**，而非 v1 只带 peer/间隔的 `JoinOutcome`——否则常驻心跳与回包解密无密钥。客户端侧 `BootstrapHook` 实现（`ClientBootstrap`）内部持有 `BootstrapSession`，`periodic` 按 hb/refresh 间隔产出 Heartbeat/GetPeers 数据报并处理回包。

### 7.2 assemble_with 五处接线（锚点已核实，`subnet_cli.rs:534-579`）

现状顺序：取 `s = &config.subnet`（`:539`）→ VIP 防御（`:541`）→ `VirtualSubnetTunnel::new`（`:545`）→ 静态 peers（`:550`）→ routes（`:559`）→ prefix_routes（`:564`）→ local_prefixes（`:569`）→ egress（`:572`）→ encryption（`:575`）。carrier 为 `Box<dyn PacketCarrier>` 按值入参（`:537`）。【已核实】

| # | 接线点（文件:行号） | 改动 |
|---|---|---|
| 1 | `subnet_cli.rs:539` 后、`:541` 前 | 插入 bootstrap join 分支（见下代码） |
| 2 | `subnet_cli.rs:541–549` | VIP 防御与 `VirtualSubnetTunnel::new(VirtualSubnetConfig::new(&s.cidr, &effective_vip), vpi, carrier)` 改用 `effective_vip` |
| 3 | `subnet_cli.rs:550` 前（隧道建成后、静态 peers 前） | 先 `tunnel.set_bootstrap_hook(...)`，再对 `bootstrap_peers` 逐个 `add_peer_if_absent` |
| 4 | `virtual_subnet.rs:1427` 后 | nxb 分流 + `recv_and_deliver` 加 `now_secs` 入参（§6.4） |
| 5 | `mesh.rs:248–254` | 「WAN Bootstrap」钩子替换为 `hook.periodic(now)`（§6.4） |

接线点 1 代码：
```rust
let (mut bootstrap_hook, bootstrap_peers, effective_vip) = if !s.bootstrap.is_empty() {
    let psk = load_network_psk(s)?                    // :292
        .ok_or_else(|| "PSK_REQUIRED: bootstrap join requires psk".to_string())?;
    let identity = load_node_identity(&config_dir)?;  // §7.4（S7）
    // carrier 在真实路径已由 assemble_real_tunnel bind（:604/:620）；
    // mock 路径（MeshCarrier）无真 UDP，直接报错而非静默跳过（M12）。
    let (sess, peers) = BootstrapJoiner::new(&mut *carrier, &identity, &psk, &codec)
        .join(&s.bootstrap, s.virtual_ip.as_deref(), JOIN_DEADLINE, now)?;
    (Some(ClientBootstrap::new(sess)), peers, sess.assigned_vip.clone())
} else {
    let vip = s.virtual_ip.as_deref()
        .ok_or_else(|| "VIRTUAL_IP_UNRESOLVED".to_string())?;
    (None, Vec::new(), vip.to_string())
};
```

接线点 3 代码：
```rust
tunnel.set_bootstrap_hook(bootstrap_hook);
for p in &bootstrap_peers {
    // 静态已存在的同 VIP 跳过（静态为权威），避免 HashMap insert 覆盖（virtual_subnet.rs:893，M15）
    tunnel.add_peer_if_absent(TunnelPeer::new(&p.virtual_ip, &p.locator))?;
}
```

接线点 4–5 见 §6.4。其余 `:550-577` 顺序不变，保证旧配置字节级兼容。

### 7.3 常驻、心跳与刷新（按 S4 重写）

- **常驻只有 CLI `--foreground` 一条**：`subnet_foreground_real`（`main.rs:614`）→ `AutoMeshController::new(tunnel, 500)`（`:640`）→ `run_with_save`（`:648`，循环在 `mesh.rs:216`）。心跳/刷新经 §6.4 的 `periodic(now)` 挂 `:248-254` 钩子。【已核实】
- **nexusd 不承载 bootstrap（S4）**：`run_dataplane`（`apps/nexusd/src/main.rs:351-368`）是 TUN 泵，不持有隧道/socket。若产品要求 daemon 常驻 bootstrap，**改造轮廓**为：在 nexusd 组合根新增「隧道 + UdpCarrier + AutoMeshController」宿主线程（bind UDP、跑 mesh tick、挂 BootstrapHook），属新增开发而非接线；本期只落 CLI foreground 并在文档明确标注。【待验证】
- **一次性 `subnet up`（S6 修法）**：`subnet_up` 的 `_tunnel` 在 `:348` drop；`--tun` 路径 `subnet_up_tun` 在 `:643` drop 真实隧道后回调 `:644`。在两函数开头（`subnet_cli.rs:327` / `:652`）判定：
  ```rust
  if !foreground && !s.bootstrap.is_empty() {
      // 非零退出；打印"bootstrap 仅支持 nexus subnet up --foreground"
      return Err("BOOTSTRAP_REQUIRES_FOREGROUND".into());
  }
  ```
  不保留「预拉表写状态」半接入网；如未来要支持，须给 `SubnetState`（`:142-163`）扩 peer 列表，由下一 foreground 进程经 `mesh.load_state`（`mesh.rs:957`）恢复。
- **tick 收包容量（M14）**：主循环每 500ms tick（`mesh.rs:271`），现每 tick 只 `recv_and_deliver` 一次（`:223`）。建议把 socket 排空到 WouldBlock 再 sleep（控制帧/打洞/数据同 socket 排队），E5 压测确认控制帧不被饿死。【待验证】
- 引导不可用：客户端标记 `BootstrapStale`，**已建立的 P2P 连接不受影响**；租约期内失联则下个刷新周期改连备用引导重新 join（VIP 按 node_id 幂等，`coord.rs:223-226`）。

### 7.4 持久身份加载（S7）

`node init` 已把 X25519 seed 写入 `node/identity`（`apps/nexus/src/node_cli.rs:204-240`，字段 `x25519_seed_hex` 在 `:221`）【已核实】，但无回读函数。新增：

```rust
// apps/nexus/src/node_cli.rs（或独立 identity_loader.rs）
pub fn load_node_identity(config_dir: &Path) -> Result<KeyPair, String> {
    // 读 node/identity → 取 x25519_seed_hex（64 hex）→ [u8;32] → KeyPair::from_seed（encryption.rs:150）
    // 不存在：首次自动 init（持久化）并提示；禁止在 bootstrap 装配路径再用 KeyPair::generate()
}
```

- `assemble_with` 注入 `load_node_identity(&config_dir)`（接线点 1）。
- 替换 `subnet_cli.rs:340` 的一次性 `KeyPair::generate()`；该 generate **仅保留给无 bootstrap 的 legacy 路径**。【已核实】
- **算法不可混淆**：bootstrap 用的是 **X25519** `encryption::KeyPair`（`:127`，`from_seed` `:150`）；`n2_identity.rs:26` 是 **ed25519**（N2 授权），二者不可互换。【已核实】

### 7.5 故障转移

- `bootstrap` 数组按序尝试（现有 `BootstrapConfig{address,name}` 在 `subnet_cli.rs:105-112`，校验 `:222-245`：非空强制 PSK `:223`、必须 `udp://` `:227`）。【已核实】
- `NotBootstrap/Timeout` 切换下一个；`AuthFailed` 在「收到 JoinReply 但 RegisterAck 超时」时判定（joiner 是 initiator，自身 PSK 错误要到这一步才暴露，§5.3 M2），PSK 全网一致前提下快速失败合理。
- 多引导表互不同步是本期已声明限制（VIP 按 node_id 幂等换引导仍拿回同 VIP）。

### 7.6 共存与热加载

- **静态 peers**：`:550-558` 不变；同 VIP 冲突以静态为权威（接线点 3，`add_peer_if_absent`）。【已核实】
- **路由面**：bootstrap peer 只进 `peers`，不自动进 routes/prefix_routes/egress——`validate()`（`:255-279`）已强制 next_hop 必须是静态 peer，bootstrap 节点默认只做直接互通，无路由归属冲突。【已核实】
- **N1 mesh / proxy(TUN)**：nexusd 的 N1（`assembly.rs`）与 proxy_fwd（`main.rs:336-348`）走独立 TUN dataplane，与 CLI 隧道不共享 socket；同机并跑仅存在 TUN 设备名/MTU 占用问题（二选一或区分 tun_name，L12【待验证】）。
- **热加载（M16）**：CLI foreground 不重读配置；nexusd watcher 只轮询 5 个固定文件（`watcher.rs:67-73`，不含 subnet.toml），network.toml 变更判 NeedsRestart（`config.rs:522`）。bootstrap/bootstrap_server 变更天然走重启，文档注明即可。
- **崩溃恢复**：控制会话易失、重启必须重新 join；`mesh.load_state`（`mesh.rs:957`）只恢复 peer locator，二者互补。
- **命名冲突（M13）**：`BootstrapConfig/BootstrapClient` 三处同名（含 `mesh.rs:771` HTTP 死代码）；新代码用 `BootstrapEndpoint`/`BootstrapSession`，HTTP 版后续改名/删除。【已核实】

---

## 8. 配置变更

### 8.1 引导节点（开启服务端角色）

新增可选表，缺失 = 普通节点（服务端不启用）：
```toml
[subnet]
cidr = "10.144.144.0/24"
virtual_ip = "10.144.144.1"        # 服务端自身 VIP；启动先占位（§5.4 第3步）
encryption = true
network_psk_file = "/etc/nexus/psk.key"   # 复用现有 PSK；服务端与客户端必须一致

[subnet.bootstrap_server]
enabled = true
lease_secs = 60                    # 建议 3×hb_interval
hb_interval_ms = 20000
refresh_interval_ms = 60000
# state 落 <config-dir>/data/bootstrap/vip-leases.json（§6.6）
```

- 在 `SubnetSection`（`subnet_cli.rs:84` 附近）新增 `#[serde(default)] pub bootstrap_server: Option<BootstrapServerSection>`。【已核实】
- 该 section 加 **`#[serde(deny_unknown_fields)]`**（现反序列化默认忽略未知键 `:201-204`，拼错字段不报错，L11）；在 `validate()`（`:209`）尾部追加：`lease_secs > 0`、间隔 `> 0`、`enabled` 为 bool。【已核实】

### 8.2 新节点（客户端，最简）

沿用已存在的 `[[subnet.bootstrap]]`（`:84-86`/`:105-112`），零静态 peer：
```toml
[subnet]
cidr = "10.144.144.0/24"
encryption = true
network_psk_file = "/etc/nexus/psk.key"
# virtual_ip 不填：由服务端分配（填了则作为申请值，软冲突以 JoinReply 为准）

[[subnet.bootstrap]]
address = "udp://bootstrap.example.internal:11010"
name = "bootstrap-1"
# 可再列一个备用引导
```
运行命令不变，但 **bootstrap 仅受 `--foreground` 支持**：
```bash
nexus subnet up --config node.toml --foreground
# 非 foreground + bootstrap → BOOTSTRAP_REQUIRES_FOREGROUND（§7.3）
```

> 校验规则沿用现有：bootstrap 非空则 PSK 必填（`:223`）、地址必须 `udp://`（`:227`）。

---

## 9. 需要小幅补齐的现有能力（v1 §9 修订）

| 项 | 说明 | 插入点（文件:行号） | 状态 |
|---|---|---|---|
| ~~`VirtualIpAllocator::release`~~ | **已存在**（C1），sweep 直接调用 | `coord.rs:278`（测试 `:613`） | **v1 缺口撤销** |
| `Coordinator::prune_expired(now)->Vec<String>` | 摘除过期 peer，驱动 VIP 回收；顺带修 presence 只增不减 | `coord.rs:147` 后 | 新增（§6.3） |
| CIDR 自校验助手 | `allocate_specific` 不校验 CIDR/网络/广播（M4），服务端调前判定 v∈cidr 且非网络/广播 | 参照 `subnet_cli.rs:214` | 新增/复用 |
| 隧道 bootstrap 字段与 hook | `bootstrap: Option<Box<dyn BootstrapHook>>` + `set_bootstrap_hook` + 内部 `send_raw`；`recv_and_deliver` 加 `now_secs` | `virtual_subnet.rs:422-462`、`:1411`（`:1427` 后分流） | 新增（S5，§6.4） |
| 身份回读 | `load_node_identity`：读 `node/identity` 的 x25519_seed_hex → `KeyPair::from_seed` | `node_cli.rs:221`；`encryption.rs:150` | 新增（S7，§7.4） |
| 外层帧 + split_outer | `bootstrap_join.rs` 三帧往返 + 「0x01 且 len≥38」探针 | 新文件 `nexus-discovery/src/bootstrap_join.rs` | 新增（§5.2） |
| 内层 RegisterAck | `AutoDiscoveryFrame` 增量 tag 15 | `auto_discovery.rs:201` 附近 | 新增（S1，§5.5） |

均为局部、向后兼容的增量，不改动已冻结数据面帧的字节布局。

---

## 10. 安全与错误处理矩阵（fail-closed，在 v1 §10 增补）

| 场景 | 行为 |
|---|---|
| 无 PSK 且配置了 bootstrap | 装配前拒绝：`PSK_REQUIRED`（现有，`:223`） |
| PSK 错误 | 首个 AEAD 帧解密失败；服务端**静默丢弃**，客户端表现为 RegisterAck 超时（归并认证失败），**不注册、不返回列表、不建连** |
| 重放旧控制帧 | `ReplayWindow` 拒绝；握手重放由 nonce plaintext 前缀绑定拒绝（§5.3） |
| **冒名 node_id（S2）** | 服务端以 `peer_static` 派生权威 id，忽略/强校验自报值；不符不写目录 |
| **半开 DoS / 速率（S3）** | 每 src 4 条、全局 1024、JoinInit 10 次/60s、pending TTL 10s；超限 RateLimited/丢弃；过载要 cookie |
| **无状态 cookie（S3）** | 全局 pending 触顶后，JoinReply 要求回显 `HMAC(server_key, src‖time_window)`，无 cookie 的 JoinInit 丢弃 |
| **握手 nonce 绑定（M3）** | `client_nonce‖server_nonce` 作 AEAD plaintext 前缀，解密后比对期望；首帧无 ReplayWindow 保护由此兜底 |
| 申请 VIP 不在 CIDR | 服务端自补校验 → `BadVip`，拒绝并回服务端分配值 |
| 申请 VIP 被他人占用 | 软冲突：服务端另分配并在 JoinReply 注明 |
| 对端未开服务端 | 收不到 JoinReply/前缀不符 → `NotBootstrap`，切换备用引导 |
| 全部引导不可达 | `AllBootstrapFailed`，进程非零退出并打印各引导原因 |
| **非 foreground + bootstrap（S6）** | `BOOTSTRAP_REQUIRES_FOREGROUND`，非零退出、打印受支持方式 |
| 伪造 locator | 目录以 NAT 源 locator 为准，忽略自报值 |
| 控制帧格式损坏 | `MalformedFrame`，静默丢弃不回敏感信息 |
| 引导重启 | VIP 表持久化保持稳定；在线目录靠心跳重建；校验和损坏视为空表告警，不拒启 |

---

## 11. 分阶段落地 P1–P5（按评审 §二.5 修正）

| 阶段 | 内容（修正后） | 门禁 |
|---|---|---|
| **P1** | `bootstrap_join.rs` 外层帧 + `split_outer` + 单测；`load_node_identity`。**release 已存在（`coord.rs:278`），从 P1 删除** | `cargo test -p nexus-discovery` 全绿、无 warning |
| **P2** | 服务端纯逻辑：Coordinator + allocator + codec trait + **半开防护**，内存 carrier 对；PSK fail-closed / VIP 软冲突 / 过期摘除**三测** | `cargo test -p nexus-connectivity`；harness `bootstrap-join` PASS |
| **P3** | joiner + `assemble_with` **五处接线**（§7.2）+ `recv_and_deliver` 分流（含 now 入参）+ mesh `:248` hook 替换 + 一次性 up 报错（S6） | `cargo test -p nexus` 旧用例不回归 |
| **P4** | 真实 UDP 单 socket 分流、服务端角色、VIP 表持久化（loopback） | E5 loopback 手动验收，不进 pre-push |
| **P5** | 真机/NAT、多引导故障转移、断电恢复、relay 下发 | E5 真机，记录 evidence |

---

## 12. 验证计划

### 12.1 E4 离线确定性场景（进 harness）

- **分发扩展点（已核实）**：`engineering/nexus-harness/src/run_scenario.rs:9-27` 为手写 match（11 个现有场景，无注册中心）。在 `:20` arm 之后、`:21` `_ =>` 之前加 `"bootstrap-join" => run_bootstrap_join(),`；新函数加在文件末尾（`run_qos_cake` 结束于 `:1768` 之后）。【已核实】
- **场景骨架要点**：3 个 `MeshCarrier`（定义于 `virtual_subnet.rs:1881`），`connect_peer`（`:1902`）/`recv_handle`（`:1908`）显式连 S↔A、S↔C，A/C 初始零 peer；服务端挂真实 `VirtualIpAllocator::new`（`coord.rs:204`）+ codec；A join 后 C join，断言 C 的 PeerList 含 A；用 join 结果 `add_peer`（`:884`，`TunnelPeer::new` `:106`）；A→C 发 20B IP 包，按 `run_virtual_subnet_mesh`（`run_scenario.rs:148-284`，收发断言 `:218-230`）逐跳 `recv_and_deliver` 比对 payload。全程注入 `now`（初始如 1000），无 sleep/SystemTime。【已核实】
- **lockstep 硬约束（M18）**：MeshCarrier `receive_into` 一次 drain 扁平 buf（`:1944-1952`），多帧握手必须「发一帧→对方 handle→取回复→再发」，否则拼接污染。
- **场景契约**：新增 `engineering/nexus-harness/scenarios/product/bootstrap_join.toml`（仿 `virtual_subnet_mesh_3node.toml`），`evidence_strength = "E4"`，断言只用解析器真实支持的 `equals`/`one_of`/`non_empty`（`scenario.rs:76-88`），**不要写 `non_zero`**（L1：`non_zero` 被静默丢弃，反例 `virtual_subnet_mesh_3node.toml:56`）。【已核实】

**断言 → 代码位置对照**：

| 断言 | 取数位置 |
|---|---|
| 新节点 static_peers=0 入网 | 初始 `peers().is_empty()`（`virtual_subnet.rs:1284`） |
| assigned_vip 在 CIDR | allocator 返回值（`coord.rs:223`）/ JoinReply |
| PeerList 含已在线节点 | `Coordinator::peer_list`（`coord.rs:123`），顺序确定 |
| add_peer 数量正确 | `peers().len()`（`:1284`；先例 `run_scenario.rs:241-242`） |
| A→C 数据可达 | `send_ip_packet`（`:1295`）+ `recv_and_deliver`（`:1411`），payload 长度/内容相等（`:218-230`） |
| PSK 错/重放被拒 | 原语层 `decrypt_frame`（`encryption.rs:492`）、`check_and_accept`（`:568`）——只进单测，不进 harness JSON |

### 12.2 应新增单测（7 个，清单与归属）

| 单测 | 归属/插入点 | 断言 |
|---|---|---|
| `bootstrap_join_frame_roundtrip` | 新建 `nexus-discovery/src/bootstrap_join.rs` 末尾 | 三帧往返；未知 tag/截断/trailing → Transport（仿 `auto_discovery.rs:495-558`） |
| `nxb_magic_vs_data_frame_demux` | `virtual_subnet.rs` 测试模块（`:1961`，邻 `:2720`） | nxb 被分流吃掉、不写 VPI；NXP1 仍走管线/解封装，不串路 |
| `psk_mismatch_no_directory_entry` | 服务端新文件测试末尾 | 错 PSK → 不 announce、不回 PeerList，`peer_list(now)` 不含该节点 |
| `vip_soft_conflict_returns_assigned` | 同上 | 申请值被占（`coord.rs:267`）→ 另分配，JoinReply 带实际值 |
| `lease_expiry_prunes_and_releases` | 同上 | 推进 now → prune 摘除、release 回池，同址可被新 peer allocate 复用 |
| `replayed_secured_frame_rejected` | 同上 | 同帧喂两次，第二次 ReplayWindow 拒，目录不重复 touch |
| `all_bootstrap_servers_failed` | `bootstrap_joiner.rs` 末尾 | 全失败 → AllBootstrapFailed，且逐端切换 |

> 密码学原语行为已在 `encryption.rs:759`（wrong key）、`:863`（重放拒绝）、`coord.rs:600-623`（冲突/释放）覆盖，新测只补「服务端编排/策略分支」，不重复测原语。

### 12.3 CI 增量与门禁现实（M19）

- 本仓**无远程 CI**，CI = git hooks：pre-commit 跑 whitespace + `cargo fmt --check`；pre-push（`.githooks/pre-push:22`）跑 `nexus-harness verify --fast`，fast gates 见 `policies/quality.toml:18-28`（含 affected-tests = 改动 crate 的 `cargo test -p`）；product-scenarios 属 full（`:30-46`），pre-push 不跑。【已核实】
- **推荐**：确定性断言全部沉到 crates 单测（pre-push 的 affected-tests 自然覆盖）；harness `bootstrap-join` 留 `verify --full` 与发布前手动：
  ```bash
  cargo test -p nexus-discovery -p nexus-connectivity -p nexus-harness
  cargo run -p nexus-harness -- run bootstrap-join --json
  nexus-harness verify --full
  ```
- E5（loopback/真机）不进 fast，与现有 `coord_join_loopback`（标 E5）一致。

### 12.4 E5 真实链路

- **loopback**：1 引导（`[bootstrap_server]`）+ 2 零静态 peer，**复用/扩展 `coord_join_loopback_flow`**（`apps/nexus/src/lib.rs:7095`，已标 E5，双节点真实 127.0.0.1 闭环；改三节点即可，不必新造）。【已核实】验证互见、P2P UDP、心跳维持、杀节点后租约到期消失且 VIP 回收。
- **真机**：引导放公网 UDP，内网节点零配置入网，验证对称 NAT 下打洞/relay 互通；引导位于 NAT 后的端口映射与发夹场景。
- 如需独立可执行驱动：新增薄壳 example `apps/nexus/examples/bootstrap_join_loopback.rs`（examples 均为薄壳，见 `auto_discovery.rs:13`）+ `nexus::bootstrap_join_loopback_flow()`。
- 单机 loopback 手动验收命令（与 v1 §12 一致，--foreground）：
  ```bash
  nexus subnet up --config server.toml  --foreground
  nexus subnet up --config node-a.toml  --foreground
  nexus subnet up --config node-b.toml  --foreground
  ```

### 12.5 编译验证（可执行命令）

```bash
export PATH="$HOME/.cargo/bin:$PATH"
S=/home/user/Doubao/chats/38445385826129666
cd "$S/build/wt"                       # 会话目录可写 clone（原仓库只读）
export CARGO_TARGET_DIR="$S/build/target"
cargo check -p nexus-discovery -p nexus-connectivity -p nexus-harness --all-targets  # 基线 50.22s、exit 0
cargo run -p nexus-harness -- run virtual-subnet-mesh --json                        # 已复现 PASS
```

按依赖序 `-p`：nexus-platform → nexus-discovery → nexus-connectivity → nexus-harness → nexus；不要用 `--workspace`（49 个 member）。【已核实：基线 `cargo check` 约 50s】

---

## 13. 兼容性与影响面（更新实际改动点清单）

- 旧配置（无 `bootstrap`、无 `bootstrap_server`）路径字节级不变，现有测试与场景全绿：`subnet_cli.rs:550-577` 顺序不动。
- `bootstrap` 与静态 `peers` 可并存：bootstrap 负责发现，静态项为权威（同 VIP 以静态为准，`add_peer_if_absent`）。
- 实际改动点清单：
  - **新增**：`nexus-discovery/src/bootstrap_join.rs`（外层帧）、`nexus-connectivity/src/bootstrap_server.rs`、`nexus-connectivity/src/bootstrap_joiner.rs`、`apps/nexus/src/bootstrap_codec.rs`（codec 适配）、`load_node_identity`。
  - **局部改**：`coord.rs`（+`prune_expired`，`:147` 后）、`virtual_subnet.rs`（+bootstrap 字段/`set_bootstrap_hook`/`send_raw`、`recv_and_deliver` +`now_secs` 与 `:1427` 后分流）、`auto_discovery.rs`（内层 +RegisterAck tag 15）、`subnet_cli.rs`（`assemble_with` 五处接线、`subnet_up`/`subnet_up_tun` 报错、`SubnetSection` +`bootstrap_server`）、`mesh.rs`（`:248-254` hook 替换）。
- 不新增第三方依赖；编解码、密码学、承载全部复用现有实现。
- 行号随代码演进会漂移，实现前请在约定基线 `cda5f21` 上复核；标注【待验证】项需在实现或 E5 实测中确认。
