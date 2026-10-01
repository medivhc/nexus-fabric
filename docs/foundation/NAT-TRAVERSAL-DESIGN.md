# NAT 穿透打洞设计：Relay-First Punch-Through

版本：v0.1 草案（2026-10-02）
状态：D1–D6 已拍板（2026-10-02），可进合同阶段

## 拍板记录（2026-10-02 用户决策）

- D1 信令：复用中继 FabricConn 控制流
- D2 Symmetric NAT：**做有界端口预测**（用户明确要求，见 §4.3.1）
- D3 成功后：默认竞速切换
- D4 迁移后 TURN 分配：保留 warm backup
- D5 打洞触发：relay 建连后自动后台打洞
- D6 E4：netns + iptables NAT 模拟为基线，真实跨公网为可选加强

## 1. 目标

让两个都在 NAT 后面的节点，先经 TURN 中继**立即**建连（零等待可用），
后台协同打洞；打洞成功后按质量竞速决定**切换**直连，或把直连作为
**多路径**的一条腿。打洞失败则诚实地留在中继上。

非目标（首期不做）：
- TCP 打洞（传输底座是 UDP/QUIC，不需要）。
- IPv6 穿透的特殊处理（有公网 v6 时直连本就走 fallback Direct）。
- 无界端口扫描式预测（见 §4.3.1，只做有界预测）。

## 2. 参考：EasyTier 的做法

EasyTier 的模型（公开文档与行为）：

1. 公共节点 = 注册表 + 中继 + 观察者三合一。节点向公共节点注册，
   公共节点看到并记录每个节点的公网出口（IP:port）与 NAT 类型。
2. 节点间想建连时，经公共节点**交换 peer 信息**（对端公网端点、NAT 类型）。
3. 双方从**同一个 WireGuard UDP socket** 同时向对方公网端点发包打洞；
   对 symmetric NAT 做有限的邻近端口尝试。
4. 打洞成功 → 直连隧道；失败 → 流量经公共节点中继（`easytier-cli`
   里 per-peer 可见 `tunnel_proto`/`nat_type`，p2p 与 relay 动态可见）。

Nexus 的差异：我们不把"等打洞"放在建连关键路径上。
流程反过来——**先中继建连（立即可用），再后台打洞，成功后迁移**。
这与 EasyTier "P2P 失败走 relay" 的终态一致，但首包延迟更优，
且打洞过程对上层完全透明（连接不重建）。

## 3. 总体流程

```text
A ◄──TURN relay──► B          ① 中继建连（现有 4b + fallback，已有）
│                    │
│  relayed FabricConn 控制流
│  PunchOffer{候选地址, NAT类型, nonce}  ② 信令交换（零新机制）
│ ◄────────────────► │
│                    │
│  同一 UDP socket → 对方 reflexive 地址发 QUIC 包
│ ◄ - - - - - - - ► │  ③ 协同打洞（双向同时）
│                    │
│  QUIC path validation 自动完成
│  CID 不变，连接不重建        ④ 路径迁移（复用 S3/S6 被动迁移）
│                    │
│  竞速：direct vs relay
│  20% + 3s hysteresis        ⑤ 切换或多路径（复用 Boost/多路径）
│                    │
└── 打洞超时/失败 → 留在 relay，后台周期重打洞 ──→ ⑥ 回退
```

## 4. 详细设计

### 4.1 候选地址收集（Candidate gathering）

每端收集三类候选，按优先级排序：

1. **Server-reflexive**：TURN `Allocate` 成功响应中的 `XOR-MAPPED-ADDRESS`
   （codec 已支持 `0x0020`，`nexus-turn/src/stun.rs`）。这是零成本的，
   分配中继时天然获得，无需额外 STUN。
2. **STUN 自测**：`StunClient::get_mapping` + `detect_nat_type`（已有）。
   用于校验 reflexive 是否稳定（两次 mapping 对比），并驱动
   `nat_path_decision`（Symmetric → 直接放弃打洞走 Relay）。
3. **Host 本地地址**：本机各接口地址（同子网/同一 NAT 下的直连优化，
   EasyTier 同理）。

### 4.2 信令交换（Signaling）

- **通道**：复用已建立的中继 FabricConn 上的一条控制流（bidirectional）。
  该连接已做 ed25519 PeerId 双向认证 + QUIC 加密，候选地址的真实性
  与机密性天然成立，**不引入新的信令服务器或协议**。
- **消息**：
  - `PunchOffer { nonce: u64, candidates: Vec<Candidate>, nat_type: NatType,
    start_at: Instant }`
  - `PunchAnswer { nonce: u64, candidates: Vec<Candidate>, nat_type: NatType }`
  - `Candidate { addr: SocketAddr, kind: Host|Srflx|Relay }`
- **协同**：双方在 `max(offer.start_at, answer_rx) + Δ(≈200ms)` 同时开打，
  保证双向发包时间窗重叠（打洞要求同时性）。
- 备选（不推荐首期）：经 LSA gossip 交换。LSA 已有 `locator` 字段，
  但 gossip 时效性差，不适合"同时开打"的协同。

### 4.3 打洞执行（Punching）

- **打洞包 = QUIC 包，不是魔术明文**。现有 `HolePuncher::punch`
 （`b"punch-hello"` 明文、阻塞 socket、5 秒超时）是 P4.2 时期的玩具，
  本设计**退役**它，改从 fabric driver 的**同一个 UDP socket**
  向对方候选地址发送 QUIC Initial / PING。
  - 同一 socket 是关键：NAT 映射绑定的是本地 4 元组，换 socket
    映射就变了，打洞白打。
  - QUIC 包自带 AEAD，防 spoof、防注入，无需自定义鉴权。
- **接收侧**：driver 必须把来源未知地址的 UDP 负载喂给
  `quinn-proto` 的 endpoint（而不是按"未知来源"丢弃）。
  quinn 收到来自新地址的合法 QUIC 包会自动发起
  **PATH_CHALLENGE / PATH_RESPONSE** 路径验证——只有真正能收发
  的地址才能通过验证，spoof 的源地址通不过（收不到 challenge）。
- **NAT 类型门控**：`nat_path_decision` 已有；任一端为 Symmetric
  则进入 §4.3.1 有界端口预测流程，预测不可行（端口分配随机）
  时诚实降级走 Relay。

### 4.3.1 有界端口预测（Symmetric NAT）

用户拍板：做，但必须有界。

- **可预测性检测**：向两个不同目标做 STUN binding，得两个
  reflexive 端口 `p1, p2`，算增量 `Δ = p2 - p1`。只有当多次采样
  `Δ` 稳定（如恒为 1 的顺序分配，或小常数）才认为可预测；
  `Δ` 随机 → 直接放弃，走 Relay，不浪费时间。
- **打法**：cone 端已知且稳定，symmetric 端只 spray 预测窗口
  `p_last + Δ ± K`（K 有界，建议 16，可配），同时 symmetric 端
  向 cone 端的已知 reflexive 回打。双向同时，时间盒 3s，限速
  （如每 50ms 一发），只打**对端单一 IP**，不是扫描。
- **诚实边界**：成功率天然低于 cone–cone；E4 必须覆盖
  "顺序分配 symmetric"（iptables SNAT 可模拟）与"随机分配"
  两种场景，后者期望结果是**快速放弃、稳定走 relay**，
  而不是硬打。
- **风险备注**：即使有界，spray 仍可能被对端 IDS 记为可疑；
  行为限定在已认证 peer 的单一 IP + 短时间窗，风险可控，
  但文档中如实声明。

### 4.4 路径迁移（Migration）

- 复用 QUIC 连接迁移：路径验证通过后，把连接的发送路径切到
  直连地址。**CID 不变，连接不重建**，上层零感知。
  driver 已有被动迁移支持（S3/S6，`cmd_rebind` 注释确认 peer 侧
  经路径验证被动迁移）。
- TURN 分配在迁移后**保留为 warm backup**（refresh 保活），
  而不是立即释放——NAT 映射老化/地址变化导致直连断时可秒回中继。
  是否释放由策略配置（默认保留，成本是 TURN 带宽占用为 0，仅保活）。

### 4.5 成功后：切换 vs 多路径

- **默认：竞速后切换**。竞速的候选集合**不只是 direct vs TURN**，
  而是三类（2026-10-02 用户指出：打洞成功 ≠ 最优）：
  1. **direct**：打洞成功的 P2P 直连；
  2. **turn-relay**：TURN 中继（4b）；
  3. **peer-relay**：经其他节点的多跳中继（复用 A/B 层 FIB 转发，
     2026-09-30 已决策：peer 中继复用既有 FIB、不新增机制，
     桌面默认可做中继）。
  三类统一喂给路径层的质量模型（EWMA RTT+丢包）与既有
  hysteresis 门限（默认 20% + 3s；Boost 模式 10% + 1s），
  只有显著更优才切换。也就是说：**打洞成功只意味着 direct
  成为候选，不意味着自动胜出**——经邻居节点更快时，
  direct 照样输给 peer-relay，流量不切过去。
- 这与路径层已有能力对齐：F10 加权选择、PathManager/S9
  本来就在多路径间打分；打洞只是给评分器新增一个候选，
  不重写决策逻辑。
- **可选：多路径**。把胜出的若干条腿（direct + relay）
  同时作为 `nexus-projection/src/multipath.rs` 的腿
  （per-flow / per-packet + QSEQ 重排）。与之前决议一致：
  多路径保持为独立高级选项，不塞进默认切换流程。
- 切换/加腿是**运行时决策**，per-peer 独立，可观测
  （`easytier-cli` 式的 per-peer `tunnel_proto`/`nat_type` 状态建议同步做）。

### 4.6 失败回退与重打洞

- 打洞超时（建议 5s，与现有超时量级一致）→ 留在 relay，
  记录 `punch_failed{peer, reason}` 计数（LocalAPI 可观测）。
- 后台重打洞触发条件：
  - 周期性（建议 5min，可配）；
  - 本端 reflexive 地址变化（TURN refresh 或 STUN 复测发现变化）；
  - relay 路径质量严重劣化（复用 Boost 劣化检测）。
- 任一端 Symmetric NAT → 不重打，直接 relay（避免无意义重试）。

### 4.7 安全

- 候选交换走已认证加密的中继连接：防篡改、防窃听。
- 打洞包为 QUIC AEAD 包：防注入；路径验证防源地址 spoof。
- TURN 侧 `CreatePermission` 只对已认证 peer 的地址授权，
  打洞期间不放宽。
- 不做端口预测 ⇒ 不产生扫描行为，不触发对端 IDS。

## 5. 与现有组件的映射（复用清单）

| 本设计部件 | 现有实现 | 状态 |
|---|---|---|
| 中继建连 | `nexus-turn` TurnClient（4b，E4 3/3）+ `nexus-path` FallbackChain | 已有 |
| NAT 类型探测 | `StunClient::detect_nat_type`，`nat_path_decision` | 已有 |
| XOR-MAPPED 解析 | `nexus-turn/src/stun.rs` codec | 已有（client 需取用） |
| QUIC 路径验证/被动迁移 | quinn-proto + driver S3/S6 | 已有 |
| 质量竞速/hysteresis | `race.rs`，`ewma.rs`，Boost 门限 | 已有 |
| 多路径腿 | `nexus-projection/src/multipath.rs` + QSEQ | 已有 |
| 信令通道 | relayed FabricConn 控制流 | 需新增消息类型 |
| 协同打洞编排 | — | **新增**（核心工作量） |
| 旧 HolePuncher | `nexus-connectivity/src/nat.rs` | **退役** |
| per-peer 状态展示 | LocalAPI | 建议新增 |

## 6. 关键决策（已拍板，2026-10-02）

- **D1** 信令通道：复用中继 FabricConn 控制流（零新机制）。
- **D2** Symmetric NAT：有界端口预测（§4.3.1），不可预测时诚实走 relay。
- **D3** 打洞成功后：默认竞速切换；direct 只是候选之一（§4.5）。
- **D4** TURN 分配在迁移后：保留 warm backup。
- **D5** 打洞触发：relay 建连后自动后台打洞。
- **D6** E4 范围：netns + iptables NAT 模拟为基线（含顺序/随机
  symmetric 两种），真实跨公网为可选加强。

## 7. 验证计划（草图，合同阶段细化）

- E4-1：netns 双节点，A/B 各经 iptables MASQUERADE（cone NAT），
  relay-first 建连可用 → 后台打洞 → direct 建连 → 竞速切换，
  全程 TCP 传文件不断流，CID 不变。
- E4-2：打洞失败场景（对称 NAT 模拟或直接 DROP 打洞包），
  确认 5s 超时后稳定留在 relay，无抖动、无重连风暴。
- E4-3（可选）：多路径模式，直连+relay 双腿同时跑，
  一条腿断后另一条腿不断流。
- Red Evidence：新编排模块在打洞逻辑缺失时对应测试 FAIL。

## 8. 诚实边界

- Symmetric NAT 只做**有界**端口预测；`Δ` 随机时明确走 relay，
  不宣称 symmetric 穿透能力。
- 打洞成功率是统计量，E4 只证明机制正确，不承诺百分比；
  端口预测场景的 E4 期望包含"快速放弃"分支。
- **打洞成功不等于路径最优**：direct 只是竞速候选之一，
  输给 peer-relay/TURN 时不切换（§4.5）。
- 不自研 STUN 服务端：reflexive 采集复用 TURN Allocate 响应
  与现有 `StunClient`（需外部 STUN 服务器地址配置）。
