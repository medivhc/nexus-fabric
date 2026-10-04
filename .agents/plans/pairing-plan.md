# 配对（Pairing）设计计划

> 状态：计划（待实现）
> 任务类型：feature（配对 UX 是新功能；发现机制已有）
> 日期：2026-10-01
> 基线：master `f89b697`

---

## 1. 目标与范围

### 1.1 目标

实现设备间的**信任建立**（pairing）：让用户能安全地将两台设备（如手机和 PC）加入同一个 Nexus 网络，确信没有中间人攻击。

### 1.2 范围

**做**：
- 配对协议（带外认证 + 密钥交换）
- 配对码生成/解析（CLI 可复制粘贴；未来可编码为二维码）
- 配对信息的本地存储（`peers/` 目录）
- CLI 命令：`nexus pair invite/join/list/remove`
- 与现有 `Discovery` trait 的集成（`PairedDiscovery`）

**不做**（本期）：
- Android / iOS 的扫码 UI（Android 暂时不做，用户已确认）
- 二维码生成库（协议支持，CLI 只输出文本码）
- LSA 生产端（复用 A/B 路由层，已有计划）
- 配对后的自动 `network.toml` 回填（见 §4.4 决策：不回填，用 `peers/` 目录）

### 1.3 非目标

- 不替换现有 `Discovery` trait 或其冻结契约（D1–D6）
- 不修改 N1 M1–M7 冻结合同
- 不改动 `apps/nexusd` 的 daemon 主流程

---

## 2. 配对流程设计

### 2.1 角色

- **A（邀请方）**：已运行 Nexus 的设备，生成配对码
- **B（加入方）**：新设备，输入配对码完成配对

### 2.2 流程图

```
  设备 A（邀请方）                    带外通道                    设备 B（加入方）
  ──────────────                    ────────                    ──────────────
  1. nexus pair invite
     ↓
  2. 生成 token (128-bit 随机)
     生成配对码：
       code = "nexus-pair:v1:" +
              base64url(pubkey_A) + ":" +
              base64url(token)
     ↓
  3. 显示配对码                    ─── 用户复制 ───→
     启动配对监听                                              4. nexus pair join <code>
     （等待 B 连接，                                        ↓
      5 分钟超时）                                      5. 解析 code → pubkey_A, token
                                                           发现 A 的地址
                                                           （mDNS / 手动 --addr）
                                                              ↓
                                                           6. 生成临时密钥对？不，
                                                              B 用自己的身份密钥
                                                           7. 连接 A，发送：
                                                              PairRequest {
                                                                peer_id: pubkey_B,
                                                                token: token,
                                                                name: "B's name"
                                                              }
     ←────────── 网络 ───────────
  8. 验证 token：
     - token 匹配且未过期？
     - 是 → 继续；否 → PairReject
     ↓
  9. 生成签名：
       sig = sign(privkey_A, token || pubkey_B)
     发送：
       PairAccept {
         peer_id: pubkey_A,
         name: "A's name",
         signature: sig
       }
     保存 B 的信息到 peers/
     ─────────── 网络 ──────────→
                                                           10. 验证签名：
                                                                verify(pubkey_A, sig,
                                                                  token || pubkey_B)
                                                                - 成功 → 信任 A
                                                                - 失败 → 拒绝，中止
                                                               ↓
                                                           11. 保存 A 的信息到 peers/
                                                               ↓
                                                           12. 显示 "已与 A 配对"
  13. 显示 "已与 B 配对"
```

### 2.3 安全属性

| 威胁 | 缓解措施 |
|------|----------|
| 中间人替换公钥 | 配对码经带外通道传输（用户复制粘贴）；攻击者不知道 token，无法伪造 PairRequest |
| 重放攻击 | token 单次有效，5 分钟过期；A 验证后立即失效 |
| 冒充 A | B 用 code 中的 pubkey_A 验证签名；只有持有 privkey_A 的真 A 能生成有效签名 |
| 暴力破解 token | 128-bit 随机，在线猜测不可行；A 对失败尝试计数，超限锁定 |
| 配对码泄露 | 5 分钟过期；一次性；泄露者仍需网络可达 A 才能使用 |

### 2.4 为什么不用短码（6 位数字）？

- 6 位数字只有 ~20 bit 熵，需在线 rate limiting，复杂度高
- 完整公钥（32 字节）在码中，避免了"短码 + 额外往返取公钥"的交互
- 复制粘贴在 CLI 场景下是可接受的 UX（参考 `gh auth login`、`tailscale up`）
- 未来移动端可将同一码字符串编码为二维码，协议不变

---

## 3. 关键决策

### 决策 1：配对媒介

**决定**：**文本配对码（复制粘贴）为主，mDNS 辅助发现地址**

- 配对码格式：`nexus-pair:v1:<base64url(pubkey_A) >:<base64url(token)>`
  - 示例长度：~90 字符（复制粘贴友好，手动输入不友好——可接受）
- B 发现 A 的网络地址：
  - 优先：mDNS（`_nexus._udp.local`，复用现有 `MdnsDiscovery`）
  - 回退：`--addr <ip:port>` 手动指定
- 未来：同一码字符串可编码为 QR（移动端），协议层无需改动

**拒绝的方案**：
- 纯 mDNS + 6 位短码确认：熵太低，需复杂的防暴力破解；且 mDNS 跨子网不工作
- 手动输入完整公钥：易出错，用户体验差

### 决策 2：信任模型

**决定**：**带外公钥分发 + token 挑战 + ed25519 签名认证**

- 每个节点有 ed25519 身份密钥对（`nexus-fabric::PeerId` 即 32 字节公钥）
- 首次配对时交换：
  - A → B（带外）：`pubkey_A` + `token`（配对码）
  - B → A（网络）：`pubkey_B` + `token`（证明 B 持有配对码）
  - A → B（网络）：`sign(privkey_A, token || pubkey_B)`（证明 A 持有私钥）
- 配对完成后，双方互相信任对方的 `pubkey` 为其身份
- **PeerId 绑定**：`nexus-discovery::PeerId(String)` 与 `nexus-fabric::PeerId([u8;32])` 的映射
  - 配对存储使用 fabric 的 `[u8;32]`（hex 编码为文件名）
  - Discovery 层使用时转换为 `PeerId(hex_string)`
  - 长期：统一为 ed25519 公钥（待架构决策，本期做映射）

**密码学**：`ring` 0.17（workspace 已用，nexus-fabric 在用），ed25519 签名/验证

### 决策 3：配对信息存储

**决定**：配置文件夹下的 `peers/` 子目录 + `identity.toml`

```
<config-dir>/
├── daemon.toml
├── network.toml          # [[peers]] 保留给手动/bootstrap peers
├── proxy.yaml
├── dns.toml
├── identity.toml         # NEW：本节点身份（600 权限）
└── peers/                # NEW：已配对设备（自动管理）
    ├── <hex-pubkey-A>.toml
    └── <hex-pubkey-B>.toml
```

**`identity.toml`**（文件权限 600）：
```toml
# 本节点身份。自动生成，请勿手动编辑。文件权限 600。
peer_id = "a1b2c3..."  # hex，32 字节 ed25519 公钥
# private_key 以 base64url 存于同一文件（600 权限）或平台 secure store（未来）
private_key = "..."
created_at = "2026-10-01T10:00:00Z"
```

**`peers/<hex>.toml`**（文件权限 644，公钥和地址非敏感）：
```toml
# 配对设备信息。由 `nexus pair` 自动管理，请勿手动编辑。
peer_id = "d4e5f6..."  # hex，32 字节 ed25519 公钥
name = "My Laptop"     # 用户备注名（配对时输入）
addresses = ["192.168.1.100:4242"]  # 最后已知地址（发现提示用）
paired_at = "2026-10-01T10:05:00Z"
```

**权限**：
- `identity.toml`：600（owner rw，含私钥）
- `peers/*.toml`：644（公钥+地址非敏感）
- `peers/` 目录：755

**密钥管理演进**：未来可将私钥移入 `nexus-platform` 的 SecureStore；本期文件存储（600）为 MVP。

### 决策 4：`network.toml` 的 `[[peers]]` 是否自动填充？

**决定**：**不自动填充。`peers/` 目录与 `network.toml [[peers]]` 并存，daemon 启动时合并。**

理由：
- `network.toml` 是用户编辑的配置（声明式）；`peers/` 是机器管理的状态。混写会导致用户编辑与机器写入冲突。
- Bootstrap 场景（VPS 作为首个节点）仍需手动 `[[peers]]`；配对场景用 `peers/`。
- Daemon 启动时：`network.toml [[peers]]` ∪ `peers/*.toml`，按 `peer_id` 去重（`peers/` 优先，因其更新）。

```rust
// 伪代码：daemon 启动时的 peer 合并
let mut peers = load_network_toml_peers();  // 手动配置
for f in read_dir(config_dir.join("peers")) {
    let p = load_peer_file(f)?;             // 配对设备
    peers.insert(p.peer_id, p);              // 去重，peers/ 优先
}
```

### 决策 5：与 `Discovery` trait 的集成

**决定**：新增 `PairedDiscovery` 实现 `Discovery` trait；新增 `DiscoverySource::Paired`（最高优先级）。

```rust
// crates/nexus-discovery/src/paired.rs (new)
pub struct PairedDiscovery {
    peers: HashMap<PeerId, Vec<SocketAddr>>,  // 从 peers/ 目录加载
}

impl Discovery for PairedDiscovery {
    fn resolve(&self, peer: &PeerId) -> Vec<SocketAddr> {
        self.peers.get(peer).cloned().unwrap_or_default()
    }
}
```

**优先级**（`DiscoverySource` 新增变体，置于最前）：
```
Paired > Static > Lsa > Mdns
```

理由：Paired 是用户显式信任（走完配对仪式），比手动静态配置更可信（无手误风险）。

**契约影响**（D5）：
- 现有变体 `Static/Lsa/Mdns` 的相对顺序不变（冻结契约不破坏）
- 新增 `Paired` 变体是**加法**，需更新 MODULE.md 的 D5 条款（requirement-change？不，是 feature 的增量，D1–D6 契约本身是"三源发现"，现在变四源——需在 MODULE.md 中记录为 D7）
- `AggregateDiscovery` 需接纳第四源（构造函数变更，非冻结签名？检查：`AggregateDiscovery::new(static_src, lsdb, mdns)` 是 D5 冻结的。新增参数会破坏冻结签名。）

**解决冻结签名冲突**：
- 选项 A：`AggregateDiscovery::new` 加参数（破坏 D5 冻结 ❌）
- 选项 B：新增 `AggregateDiscovery::with_paired(...)` builder 方法（✅ 加法，不破坏）
- 选项 C：`PairedDiscovery` 独立使用，不接入 `AggregateDiscovery`（❌ 失去统一查询）

**选择 B**：保留 `new` 签名，新增 `with_paired(self, paired: PairedDiscovery) -> Self`。

---

## 4. v9 术语映射

| 本设计概念 | v9 术语 | 说明 |
|-----------|---------|------|
| Node（设备） | Node | 拥有 ed25519 身份（PeerId）的设备 |
| 配对（pairing） | （v9 未显式定义，属 Network 搭建） | 带外认证建立 Node 间信任关系 |
| `pubkey` | Identity | ed25519 公钥即节点的 Identity（Identity ≠ Locator） |
| `addresses` | Locator | IP:port 是 Locator，可变；Identity 不变 |
| 配对码 | （带外通道） | 类比 v9 的"信任建立"前置步骤 |
| `peers/` | （Network 配置） | 已信任 Nodes 的 Identity→Locator 映射缓存 |
| PairRequest/Accept | （握手） | 配对握手，非 Connectivity Establishment（配对 ≠ 建连） |

**关键不变量**：
- Pairing ≠ Connectivity Establishment（配对只建信任，不建连）
- Identity（pubkey）≠ Locator（address）：配对绑定的是 Identity，地址可变（漫游时更新）
- Discovery（查地址）≠ Pairing（建信任）：配对是一次性仪式，发现是持续查询

---

## 5. CLI 设计

顶层命令族（类比 `nexus subnet`、`nexus schedule`）：

```bash
# A（邀请方）：生成配对码（5 分钟有效，一次性）
nexus pair invite --dir /etc/nexus/
# 输出：
#   配对码：nexus-pair:v1:AbCdEf...:XyZ...
#   有效期：5 分钟
#   等待加入方连接...

# B（加入方）：输入配对码
nexus pair join "nexus-pair:v1:..." --dir /etc/nexus/ [--addr 192.168.1.100:4242] [--name "My Phone"]
# 输出：
#   正在连接邀请方...
#   验证签名... OK
#   已与 <peer-id-hex> 配对（备注名：My Laptop）

# 列出已配对设备
nexus pair list --dir /etc/nexus/
# 输出：
#   PEER_ID (hex 前 16 字符)...  NAME        PAIRED_AT
#   a1b2c3d4...                  My Laptop   2026-10-01T10:05:00Z

# 移除配对（删除 peers/<hex>.toml）
nexus pair remove <peer-id-prefix> --dir /etc/nexus/
```

**`--dir` 参数**：与 `nexus config` 一致，指定配置文件夹。

**`invite` 的监听**：`nexus pair invite` 启动一个临时 TCP 监听（配对协议端口），等待 B 连接。5 分钟超时或成功后退出。这是一个**前台一次性命令**（非 daemon），符合"nexus 是瘦客户端"原则。

**`join` 的地址发现**：
1. 若 `--addr` 指定，直接用
2. 否则尝试 mDNS 发现（`_nexus._udp.local`，找配对码中 pubkey 对应的实例）
3. 找不到 → 报错提示用 `--addr`

---

## 6. 配对协议（线格式）

### 6.1 配对码

```
nexus-pair:v1:<base64url_nopad(pubkey_A:32)>:<base64url_nopad(token:16)>
```

- `v1`：版本（未来可升级）
- base64url 无填充，URL/QR 安全
- 总长度：`13 + 43 + 1 + 22 = 79` 字符

### 6.2 网络帧

复用 `nexus-discovery` 的帧编码风格（type tag u8 + 字段，u16 BE 长度前缀字符串）：

```
PairRequest (tag=21):
  [21][peer_id:32][token:16][name: u16len+utf8]

PairAccept (tag=22):
  [22][peer_id:32][name: u16len+utf8][signature:64]

PairReject (tag=23):
  [23][reason: u16len+utf8]
```

- tag 选用 21–23（避开 DiscoveryFrame 的 1–4 和 AutoDiscoveryFrame 的 11–14）
- `peer_id`：32 字节定长（ed25519 公钥）
- `token`：16 字节定长（128-bit）
- `signature`：64 字节定长（ed25519）
- 签名内容：`token || peer_id_B`（32+16=48 字节）

### 6.3 传输

- TCP（配对是低频、可靠交付场景，不需要 UDP）
- A 的 `invite` 监听端口：从 mDNS 公告的 service_port 或 `--port` 指定，默认 `18442`
- 帧前加 u32 BE 长度前缀（与 DiscoveryTransport 风格一致，便于复用）

---

## 7. 模块与契约计划（Contract-First）

### 7.1 新模块

`crates/nexus-discovery/src/paired.rs`（或独立 `nexus-pairing` crate？）

**决定**：放在 `nexus-discovery` 内（`paired.rs`），理由：
- 配对结果直接服务于发现（`PairedDiscovery: Discovery`）
- 避免新 crate 的架构评审开销（AGENTS.md §12 Deletion Test：配对协议与发现协议正交？实际上配对是"信任建立"，发现是"地址查询"，是两个维度。但配对结果的消费者只有发现，且配对协议本身简单，独立 crate 的收益不大。）
- 若未来配对协议复杂化（如 PAKE、多设备组），再拆分为独立 crate

### 7.2 MODULE.md 更新

在 `crates/nexus-discovery/MODULE.md` 新增 **D7（配对）** 条款：

- `pub struct PairingCode`：生成/解析/校验
- `pub enum PairingFrame { PairRequest, PairAccept, PairReject }` + 编解码
- `pub struct PairedPeer`：`{ peer_id: [u8;32], name: String, addresses: Vec<SocketAddr>, paired_at: SystemTime }`
- `pub struct PairedDiscovery` + `impl Discovery`
- `pub enum DiscoverySource` 新增 `Paired` 变体（置于首位）
- `AggregateDiscovery::with_paired`（builder 加法）
- 文件存储：`peers/<hex>.toml` 格式（纯函数：`encode_peer_file`/`decode_peer_file`）
- `identity.toml` 格式（纯函数）

### 7.3 Scenario（Red Evidence）

新建 `scenarios/product/pairing.toml`：

```toml
# 配对协议场景：双节点配对流程
# Red Evidence：在未实现时运行，期望 FAIL（命令不存在）
```

场景步骤（harness 可执行）：
1. `nexus pair invite --dir <a-dir>` → 输出配对码（后台运行）
2. 提取配对码
3. `nexus pair join <code> --dir <b-dir> --addr <a-addr>` → 成功
4. 检查 `<a-dir>/peers/` 有 B 的文件
5. 检查 `<b-dir>/peers/` 有 A 的文件
6. `nexus pair list --dir <a-dir>` 显示 B

### 7.4 依赖

- `ring` 0.17（ed25519 签名/验证；workspace 已用，无需新评审）
- 零新增第三方依赖（base64url 手写或复用现有？检查 workspace 是否有 base64 crate）

---

## 8. 安全与边界

### 8.1 诚实边界

- 配对码经**用户**复制粘贴（带外）；若用户通过不安全通道传输（如明文聊天），仍有泄露风险——文档明说
- mDNS 发现的地址**无认证**（D3 已声明）；配对认证靠签名，不靠地址来源
- 本期不做**配对撤销的在线通知**（`pair remove` 只删本地文件，不通知对方；对方下次连接时因无信任记录而拒绝——由会话层保证）

### 8.2 不做

- 长期运行的配对服务（`invite` 是一次性前台命令）
- 配对码的二维码渲染（输出文本，未来移动端做）
- 多设备群组配对（两两配对即可组网，mesh 拓扑经 LSA 扩散）

---

## 9. 实施步骤

### Phase 1（本计划，已完成）
- [x] 输出本计划文档

### Phase 2（Contract-First）
- [ ] 更新 `crates/nexus-discovery/MODULE.md`（D7 条款）
- [ ] 新建 `scenarios/product/pairing.toml`
- [ ] 在旧实现上运行场景 → Red Evidence（FAIL：命令不存在）
- [ ] 冻结契约

### Phase 3（实现）
- [ ] `crates/nexus-discovery/src/paired.rs`：协议 + 编解码 + 文件格式（纯函数，可单测）
- [ ] `ring` ed25519 集成（密钥生成/签名/验证）
- [ ] `PairedDiscovery` + `DiscoverySource::Paired` + `with_paired`
- [ ] `apps/nexus`：`nexus pair invite/join/list/remove` CLI
- [ ] 单测（协议往返、签名验证、文件编解码、token 过期）
- [ ] 集成测试（双节点配对流程，TCP loopback）

### Phase 4（验证）
- [ ] `cargo fmt --check`
- [ ] `cargo clippy -D warnings`
- [ ] `cargo test -p nexus-discovery`
- [ ] 场景验证（harness，如可用）
- [ ] Commit（不 push）

---

## 10. 待确认（给 coordinator / 用户）

1. **CLI 命名**：`nexus pair` vs `nexus network pair`？本计划选 `nexus pair`（顶层命令族，类比 `nexus subnet`）。
2. **私钥存储**：`identity.toml`（600）vs 平台 SecureStore？本计划选文件（MVP），未来迁移。
3. **是否需要用户确认**：配对流程中，A 是否需要手动确认 B 的加入（vs 仅凭 token 自动接受）？本计划选**仅凭 token**（token 即授权；A 生成码时已知晓）。
