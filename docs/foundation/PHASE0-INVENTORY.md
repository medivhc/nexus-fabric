# 阶段 0 现状盘点：地基资产清单

| 文档属性 | 内容 |
| --- | --- |
| 日期 | 2026-09-30 |
| 目的 | 把仓库现状资产逐项映射到地基分层（DESIGN.md），标注直接用 / 需改造 / 缺失，输出 P0 开工清单 |
| 方法 | 三个并行只读盘点（投影层 / 会话传输层 / 路径层+Mesh L3），未修改任何代码 |

图例：🟢 直接用 🟡 需改造/接线 🔴 缺失（新建） ⚪ 远期

---

## 1. 投影层（DESIGN §6）——资产最厚的一层

| 能力 | 现状位置 | 状态 | 说明 |
|---|---|---|---|
| SOCKS5/HTTP 状态机 + mixed 嗅探 | `nexus-ingress`（1237 LOC，35 单测） | 🟢 | `Socks5Handshake`/`HttpProxyHandshake`，真实 daemon 冒烟验证过 |
| FlowContext 构造 | `nexus-ingress` | 🟢 | `from_socks5`/`from_http`/`from_virtual_packet_interface` 纯函数 |
| TUN 包解码 | `nexus-ingress::ip_packet` | 🟡 | 仅 IPv4+TCP/UDP，ICMP/IPv6/截断包一律丢弃 |
| 规则引擎 | `nexus-proxy`（1814 LOC，28 单测） | 🟢 | `RuleEngine::route` 纯函数；7 种规则 + selector/urltest/loadbalance/relay 四种策略组 |
| 配置模型 | `nexus-proxy-config`（1874 LOC） | 🟢 | 完整 schema + 校验 + clash 订阅解析；缺口：inbound kind 只有 socks5 |
| DNS 按规则选上游 | `nexus-dns`（905 LOC，16 单测） | 🟢 | `DnsRouter`/`MultiServerDns`；真实传输由注入 Resolver 提供 |
| TUN 建设备/读写帧 | `nexus-platform-linux`（480 LOC） | 🟢 | `/dev/net/tun` + `IFF_TUN`，纯 L3；`tun_dataplane` 真机 PASS |
| 出站 Direct/SS/Trojan | `nexus-outbound-*` + apps 接线 | 🟢 | 数据面已接线；SS/Trojan 无外部互操作证据（诚实边界） |
| 出站 VMess | `nexus-outbound-vmess` | ⚪ | 仅 AEAD roundtrip，用户已定暂不做 |
| 进程归因（/proc→pid） | 无 | 🔴 | 全仓库零代码；DESIGN §6.3 需新建 |
| 用户态 TCP 栈 | 无 | 🔴 | `smoltcp` 未引入，需走 dependency review |
| TUN L4 中继 | 无 | 🔴 | 只有 L3 帧搬运 + per-packet 决策 |
| SOCKS5 UDP ASSOCIATE | `nexus-ingress` 显式拒绝 | 🟡 | UDP 走 TUN 路径，不冲突；UDP 语义入口缺失 |

**注意**：`nexus-proxy` 的 urltest 用的是**离线注入**的 measurement，不是地基 §4 的真实探测/打分——两者不要混淆。

**结论**：约 7000 LOC 可直接用（§11"互联网出口策略"零改造）。真正缺口只有三项：`smoltcp` 引入、进程归因新建、`quinn` 引入。

---

## 2. 会话层（DESIGN §3）——基本缺失

| 地基 §3 需求 | 现状 | 状态 |
|---|---|---|
| 可靠流 | `nexus-transport` 只有 TCP 长度前缀帧流（103 行） | 🔴 需新建 |
| 不可靠数据报 | 无抽象；UDP 散落在 nat/platform/apps | 🔴 需新建 |
| Connection ID | 全仓库零命中 | 🔴 需新建 |
| E2E 加密 | 只有 per-hop 链路加密（见 §5） | 🔴 需会话层 E2E |
| ACK/重传 | 无（只在内核 TCP 里） | 🔴 需新建 |
| 路径迁移 | 全仓库零命中 | 🔴 需新建 |
| 统计 API | `traffic_stats` 纯内存骨架，未 hook 真实计数 | 🟡 需接线 |
| 0-RTT | 零代码 | ⚪ 远期 |
| 身份=公钥 | `nexus-connectivity::identity`：X25519 KeyPair + peer_id | 🟢 可复用 |
| `quinn` 依赖 | Cargo.lock **零依赖** | 🔴 需引入（⚠️ 见 §6 冲突） |

**命名冲突警告**：`nexus-session`（702 行）是 PRODUCT §2 管线的**任务执行会话**（谁发起、在哪执行、结局如何），与地基"网络连接"**同名异物、零重叠**。地基新概念必须另起名（建议 `fabric connection` / `FabricConn`），否则必然混淆。

**结论**：QUIC-like 会话层是地基中**最大的一块新建**。`nexus-transport` 名不副实（MODULE 宣称 Datagram/Multiplexing/Backpressure，实现一条没有）。

---

## 3. 路径层（DESIGN §4）——机制有，决策无

| 地基 §4 能力 | 现状 | 状态 |
|---|---|---|
| 直连（NAT 穿透） | `nat.rs`：真实 STUN Binding + NAT 类型检测 + UDP 打洞，已进 mesh 生产循环 | 🟢（补竞速/打分/切换） |
| Mesh 转发（FIB 多跳） | 选路库完整（§4 另表），但 `set_fib_resolver`/`StrategyWatcher` **生产零调用** | 🟡 接线（小） |
| TURN 中继 | `turn.rs`（919 行）：RFC5766 编解码 + Allocate 状态机完整；**transport 只有 mock**，无真实 UDP 接线、无互操作证据、无数据面 relay | 🟡 补真实传输+数据面 |
| 代理出口 | §11 现有（投影层） | 🟢 |
| 探测 | `LatencyProbe` trait + `ProbeTarget`（portable 零 I/O），**真实探测实现未见生产注入** | 🟡 只有砖块 |
| 打分（EWMA/趋势） | 无 | 🔴 新建（大） |
| 竞速（staggered） | 无；打洞是 per-peer 手动触发 | 🔴 新建 |
| 切换（hysteresis） | 无；`nat_path_decision` 是静态表（Symmetric→Relay） | 🔴 新建 |
| 粘性 | 无 | 🔴 新建 |
| 质量预测 | 无 | 🔴 新建（远期可先启发式） |

**B3 的真相**：`strategy_watcher.rs` 只是"FIB 用哪种选路算法"的热切换，**不是路径选择**，且生产未接线。不要把它当成 §4 的资产。

**结论**：路径层是"机制有、决策无"——数据面砖块齐，**探测/打分/切换/粘性/预测全部新建**，这是仅次于会话层的第二大新建项。

---

## 4. Mesh L3 / 发现（DESIGN §4.1/§8）——库完整，生产未接线

| 能力 | 现状位置 | 状态 | 说明 |
|---|---|---|---|
| 选路算法 | `nexus-discovery::routing`（2364 行） | 🟢 | Dijkstra/ECMP/Yen K-shortest/Suurballe/NodeDisjoint；`SharedFibManager` 原子切换；60+ 单测 |
| FIB | `Fib` + generation 代际 RCU | 🟢 | 库层面完整 |
| LSA 发现 | `lsa.rs`（581 行） | 🟢 | Hello/Welcome + 泛洪 + 版本向量；E4 6/6 |
| **LSA 携带地址** | `Lsa.locator: Option<String>` **已存在** | 🟢 | 注释明写"打洞用"；§8.2 倾向方案的现成载体，只需扩展多地址格式 |
| VirtualSubnet 转发 | `virtual_subnet.rs`（3136 行） | 🟡 | `resolve_next_hop` 五级优先级链；A→B→C 集成测试验证过；生产未接 FIB |
| 打洞状态机 | `virtual_subnet` 内（`ph:`/`pa:` NXHP magic，单 socket 复用） | 🟢 | 与 iroh 的 QUIC-bit 复用思想一致，已在生产循环 |

**结论**：Mesh 转发作为路径层第二候选，**库层面零新建**，缺口只是生产接线（小）。

---

## 5. 加密现状——per-hop 与 E2E 的区分

- **Mesh L3 数据面**：WireGuard 风格 per-hop 加密（X25519 + HKDF-SHA256 + ChaCha20Poly1305，seq 滑动窗口防重放），**真实接入**收发路径。
- **关键缺口**：per-hop = 中继节点解密后再加密，**看得见明文**。这与 §4.7 信任模型"中继节点不可见内容"冲突。
- **结论**：E2E 保密性必须由会话层自己的加密提供——这正是 §3.4"保留传输层加密"的第 1 条理由。per-hop 链路加密保留（防被动窃听），但不能替代会话层 E2E。
- 密钥轮换：TODO（`encryption.rs` 头注释）。

---

## 6. ✅ 决议：quinn-proto 重估通过（2026-09-30，真机实测）

用户决议 #1（`quinn-proto` sans-IO + 自写驱动）已按 AGENTS.md §18 做四项重估，
旧 PRODUCT.md 负面评估（quinn 0.11 默认 features：license FAIL、88 传递包）**已消除**，
原因是旧评估针对默认 features（含 `platform-verifier`、`runtime-tokio`），新方案用
`quinn-proto = { version = "0.11", default-features = false, features = ["rustls", "ring"] }`。

| 评估项 | 方法 | 结果 |
|---|---|---|
| license | cargo-deny + 仓库 `policies/deny.toml`（真机实测） | ✅ PASS：57 个第三方包全过；`r-efi` 的 LGPL 三选一按 OR 语义通过；`wasi` 的 LLVM-exception 已在现有 lockfile 中 |
| supply-chain | `cargo tree`（真机实测） | ✅ 58 包（旧 88 包是默认 features 的锅）；无 tokio、无 boring、无 aws-lc、无 quinn-udp；唯一 C 构建是 `ring` 的 `cc`（已在树内） |
| bans | cargo-deny | ✅ ok；getrandom 0.2.17/0.4.3 双版本 = warn（配置允许） |
| architecture | 依赖分析 | ✅ sans-IO，无运行时要求，不引入 tokio；`rustls 0.23.45` 与仓库现有版本**完全一致**，无重复版本 |
| portability | 推理 | ✅ 旧 FAIL（quinn-udp/socket2 在 wasm32-wasip1）不适用：未引入 quinn-udp；且 transport/connectivity 不在 `harness.toml [portable_core]` 清单内 |
| MSRV | `cargo metadata` | ✅ quinn-proto 0.11.18 声明 rust-version 1.85 = workspace rust-version |
| advisories | cargo-deny | ⏳ RustSec DB 拉取失败（真机网络问题），未完成；留待实现时 harness gate 执行 |

**结论**：`quinn-proto` 可立项。建议 workspace 声明 `quinn-proto = "0.11"`（取最新 patch 0.11.18），
`default-features = false` + `rustls,ring`。`quiche` 维持出局（BoringSSL）。
 scratch 工程：真机 `/tmp/quinn-eval`（一次性，可清理）。

---

## 7. P0 开工清单（按优先级）

| # | 事项 | 性质 | 依赖 |
|---|---|---|---|
| 1 | ~~quinn license/supply-chain/architecture/portability 重估~~ ✅ 已通过（2026-09-30 真机实测，见 §6） | 决策门 | 已关闭 |
| 2 | 会话层新建（可靠流/数据报/CID/E2E/ACK/迁移，基于 quinn-proto + 自写驱动） | 新建（大） | — |
| 3 | 路径决策面新建（探测/打分/切换/粘性；竞速可后置） | 新建（大） | #2（统计 API） |
| 4 | FIB/Watcher 生产接线 | 接线（小） | 无 |
| 5 | TURN 真实传输 + 数据面 + 互操作验证 | 改造（中） | 无 |
| 6 | `smoltcp` 引入（dependency review） | 依赖 | 无，可并行 |
| 7 | 进程归因新建（linux 先行） | 新建（小） | 无，可并行 |
| 8 | `Lsa.locator` 多地址格式扩展 | 改造（小） | 无 |

**命名**：地基连接概念定名 `FabricConn`（避开 `nexus-session` 冲突），在会话层立项时冻结。

**诚实边界**：本盘点是只读调查（E0-E1 级），"可直接用"的结论指代码存在且有测试，不代表已做互操作验证；出站协议（SS/Trojan）无外部互操作证据的状态不变。
