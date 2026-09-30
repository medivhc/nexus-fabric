# N1 Universal Connectivity 实现计划

> Contract hash: `26e4681f1ba902e3e1b3ad13147a07af9ca80b5d`（分支 `feature/n1-connectivity-assemble` @ `a3639d5`）
> 本文档是实现阶段的工作计划。冻结契约（`crates/nexus-network/MODULE.md`）不得修改；
> 如实现中发现契约必须改，走 requirement-change 并先报告（唯一可停点）。
> 依据：v9 规范（技术设计基线）、白皮书 v1.0（产品定义基线）。

## 0. 重要决定清单（评审意见 + 结果）

### D0 [架构/阻塞] `nexus-fabric` rebind 绑定地址从 `127.0.0.1:0` 改为 `0.0.0.0:0`

- 现状：`driver.rs::cmd_rebind` 硬编码 `StdUdpTransport::bind("127.0.0.1:0")`。E4 拓扑是双 netns + veth（10.200.0.0/24），rebind 后的回环 socket 无法到达对端，E4 必败；任何真实部署同理。
- 选项：(a) 改 fabric 为 wildcard 绑定；(b) 不改 fabric，E4 绕开 rebind——但 scenario 冻结要求 `link.rebind_occurred=true`，不可行。
- 评审：选 (a)。这是 bugfix，不是契约变更：冻结语义只是"rebind 不换 CID"，绑定地址是实现细节。4a E4 在回环上验证过，wildcard 在回环上行为一致（内核按路由选源地址），回归风险低。`new_client` 的同类硬编码本次不动（本轨道用 `connect_with_transport` 显式绑定，不依赖它），记为后续项。
- 结果：待实现后跑 fabric 既有 E4（`fabric-conn-roam` 等）确认无回归。

### D1 [架构] 包泵位置与线程模型

- 选项：(a) 包泵在 `nexus-network` 内（计划已定）；(b) 包泵放在 composition root。
- 评审：选 (a)。M1/M2 的包转发是 N1 的核心行为，必须有明确 Owner。线程模型按 AGENTS.md §13：
  `N1Runtime`（Owner）+ `CancellationToken` + JoinSet/Reaper。`VirtualPacketInterface` 方法取 `&mut self`，
  用 `Arc<Mutex<Box<dyn VirtualPacketInterface>>>` 在上行线程（VPI 阻塞读→路由→send_datagram）
  与下行线程（recv_datagram 阻塞→VPI 写）之间共享；每次调用只短暂持锁，无死锁。
- 结果：待实现。

### D2 [架构] 注入 trait 形状（Deletion Test 已通过，契约预批准）

`nexus-network` 新增 portable 模块，**不**依赖 `nexus-fabric`/`nexus-path`/`nexus-discovery`/`nexus-platform-linux`。
定义以下注入 trait（composition root 适配）：

```rust
/// 节点身份：ed25519 公钥 32 字节（对标 fabric PeerId，composition root 转换）。
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct N1PeerId(pub [u8; 32]);

/// 错误：类型化，保留可诊断原因，支持 Retry/Fallback/Abort/Escalate 判定。
pub enum N1Error { Transport(String), PeerUnknown, Closed, Timeout, ... }

/// 单个对端连接（对标 FabricConn 的子集；composition root 为 FabricConn 实现）。
pub trait N1Connection: Send + Sync {
    fn send_datagram(&self, data: &[u8]) -> Result<(), N1Error>;   // ≤1200B，超限返回错误（调用方计数后丢弃）
    fn recv_datagram(&self) -> Result<Vec<u8>, N1Error>;          // 阻塞
    fn open_keepalive(&self) -> Result<N1KeepaliveStream, N1Error>; // 可靠双向流（M2）
    fn rebind(&self) -> Result<(), N1Error>;
    fn connection_id(&self) -> u64;   // CID，用于断言 id_unchanged
    fn peer(&self) -> N1PeerId;
}

/// 建连（对标 FallbackChain + FabricConn::connect_with_transport；composition root 实现）。
pub trait N1Dialer: Send + Sync {
    fn dial(&self, peer: &N1PeerId, addrs: &[SocketAddr]) -> Result<Box<dyn N1Connection>, N1Error>;
}

/// 入向（对标 FabricListener；composition root 实现）。
pub trait N1Listener: Send {
    fn accept(&self) -> Result<(N1PeerId, Box<dyn N1Connection>), N1Error>; // 阻塞
}

/// 发现（对标 AggregateDiscovery；composition root 实现）。
pub trait N1Discovery: Send + Sync {
    fn resolve(&self, peer: &N1PeerId) -> Result<Vec<SocketAddr>, N1Error>;
}

/// 结构化事件上报（Session Runtime 反馈 Planner 的载体；本期 composition root 落盘/日志）。
pub trait N1EventSink: Send + Sync {
    fn emit(&self, event: N1Event);
}
```

- 评审：`N1Connection: Send + Sync` 是必需的（被 pump 双线程 + watcher 共享）。`N1PeerId` 自建而不复用
  fabric `PeerId`，因为 portable core 不能命名 fabric 类型；转换是 composition root 的职责。
  keepalive 流类型 `N1KeepaliveStream` 封装 `(write, read)`，避免暴露 fabric 流类型。
- 结果：待实现（确切签名实现阶段冻结，遵循"最小 surface"）。

### D3 [命名] N1 会话/连接表与 Link 观测器

- 契约 Deletion Test 允许新增，确切名称实现阶段冻结。冻结为：
  - `N1SessionManager`：拥有 `N1PeerId → N1Peer` 表；`dial`（经 `N1Dialer`）、`accept_loop`（经 `N1Listener`）、
    `remove`；是 Connection 生命周期的唯一 Owner。文档必须声明：这是 v9 "Session 中实际建立的传输实例"
    的管理者，**不是**白皮书 Session（某次实际资源使用的上下文）的替代。
  - `N1Peer`：`{ conn: Box<dyn N1Connection>, phase: N1PeerPhase, last_progress: Instant, ... }`，
    phase 遵循 `Allocating/Active/Draining/Disposed`（AGENTS.md §14）。
  - `LinkStateWatcher`：每 peer 一个观测状态；触发器 = keepalive 心跳超时（主）+ `recv_datagram`/
    流错误（辅）。注意：fabric driver 吞掉了 UDP `send_to` 错误（`let _ =`），所以"socket 错误"触发器
    不能依赖 `send_datagram` 返回错误——这是实现时必须遵守的事实，已在 D3 评审中确认。
    触发后执行 `discovery.resolve(peer)` → `conn.rebind()`，并经 `N1EventSink` 上报结构化事件。
- 评审：命名与职责边界清晰，无第二套 Planner，无自主换路（重规划是 Planner 的事，本层只上报）。
- 结果：待实现。

### D4 [E4 架构] 双 netns + veth 对，父进程编排

- scenario 冻结：example 内双节点，各自 `unshare(CLONE_NEWNET)`，先拉起 lo，再建 TUN、配 VPI 子网 IP、加路由。
- 实现方案：example 父进程（root netns）建 veth 对 → fork 子进程 A/B → 子进程 unshare 进新 netns →
  父进程把 veth 端移入子进程 netns（`ip link set <veth> netns <pid>`）→ 子进程内配地址、拉起 lo。
  - Underlay：veth 上 10.200.0.0/24（A=10.200.0.1，B=10.200.0.2→切网后 10.200.0.3）。
  - VPI 子网：TUN 上 10.144.0.0/24（A=10.144.0.1，B=10.144.0.2），MTU 1200（对齐 fabric datagram 1200B 上限）。
  - B 的 underlay socket 显式绑定 10.200.0.2（经 `StdUdpTransport::bind` + `connect_with_transport`），
    使父进程删除该 IP 后故障确定性发生；rebind 后为 wildcard（D0 修复后）。
  - 文件传输：B 在 10.144.0.2:7000 起 TCP server；A 用 TCP client 发确定性文件（2MB 模式字节）；
    传一半时父进程改 B 的 veth IP（`nsenter -t <pidB> -n ip addr del/add`）。
  - 驱动纪律（`e4-must-use-production-path`）：example 只做外部可观察操作；父进程改 IP 是模拟"手机关 WiFi"的外部事件，不是上帝之手。
- 评审：这是满足冻结 scenario 的最小可行拓扑。veth 方案比 `ip netns` 自包含（随进程死亡自动清理）。
- 结果：待实现。

### D5 [范围] M6 CLI 最小诚实范围

- 现状：`apps/nexus` 已有 `connectivity status|candidates|probe|links`，但实现是 demo 桩（硬编码 203.0.113.53 等），与本次无关，不动。
- 决定：新增 `nexus network up --config <toml> [--json]`（前台运行 N1 装配：建 TUN→dial 静态 peers→起 pump，Ctrl-C 退出）
  和 `nexus network status --json`（读配置文件，报告将装配的内容；无 daemon 时诚实标注 `daemon: false`）。
  经 Application API：`nexus-control-api` 新增 `ControlCommand::NetworkUp { config }` / `NetworkStatus`，
  `apps/nexus`（composition root）实现装配逻辑。daemon 化后置（与"daemon 独立关注点可后叠加"一致）。
- 评审：不做 daemon、不做 `network down`（前台进程 Ctrl-C 即停）；`status` 不虚构运行时状态。
- 结果：待实现。

### D6 [语义] 失败事件处置判定

```rust
pub struct N1Event {
    pub peer: N1PeerId,
    pub connection_id: u64,
    pub kind: N1EventKind,          // LinkFailed { reason }, RebindSucceeded, ...
    pub disposition: N1Disposition, // 建议处置
}
pub enum N1Disposition { Retry, Fallback, Abort, Escalate }
```

- 语义：`Retry`=本层可自愈（rebind 后恢复）；`Fallback`=建议上层尝试备用路径（上报 Planner）；
  `Abort`=不可恢复（peer 未知、认证失败类）；`Escalate`=需人工/上层决策。本层只判定+上报，不执行重规划。
- 结果：待实现。

## 1. M1–M7 执行步骤

### 阶段 1：`nexus-network` portable core（M1–M5）

1. `crates/nexus-network/src/n1/mod.rs`：模块骨架 + `N1PeerId` + `N1Error` + 注入 traits（D2）。
2. `session.rs`：`N1SessionManager` + `N1Peer`（D3）；`dial`/`accept_loop`/`remove`；per-peer 单 Connection 不变量的单测。
3. `link.rs`：`LinkStateWatcher` + `N1Event`/`N1Disposition`（D6）；keepalive 心跳协议（8B magic + seq，bidi 流）；
   触发器：心跳超时（可配置，默认 5s）+ 流/datagram 错误；触发后 `resolve → rebind` + 事件上报。
   单测：用测试替身验证超时触发 rebind、事件字段完整。
4. `pump.rs`：`VpiPump`：IPv4 头解析（dst @ bytes 16..20，M1 只处理 IPv4 单播；非 IPv4/组播/超限包丢弃并计数）；
   路由表 = 注入的静态配置 `Vec<(Ipv4Net, N1PeerId)>`（精确匹配 /24 内地址，M3）；
   上行/下行双线程 + `Arc<Mutex<Box<dyn VirtualPacketInterface>>>`（D1）。
5. `config.rs`：`N1Config`（TOML）：`[[peers]] id=<hex> addrs=[...]`，`vpi.routes`，`probe_interval_ms` 等。
6. 单元测试：路由、包解析、状态机、事件。`cargo test -p nexus-network` 全绿。

### 阶段 2：fabric bugfix（D0）+ 回归

7. `crates/nexus-fabric/src/driver.rs::cmd_rebind`：`127.0.0.1:0` → `0.0.0.0:0`，注释说明原因。
   跑 fabric 既有单测 + `fabric-conn-roam` 相关 E4，确认无回归（这是 bugfix 的回归门）。

### 阶段 3：E4 example（M7）

8. `crates/nexus-network/examples/n1_roam.rs`（dev-deps：fabric/path/discovery/platform/platform-linux）：
   composition（适配器实现）+ D4 拓扑 + 文件传输 + JSON 输出
   `{verdict, transfer.hash_match, connection.id_unchanged, link.rebind_occurred, transfer.stalled_within_budget}`。
   反空转：若未发生 rebind 则 verdict=FAIL。
9. xc-pc-linux 真机跑通（netns 需 root；SSH 会话 export RUSTUP_HOME/CARGO_HOME/PATH）。

### 阶段 4：M6 CLI

10. `nexus-control-api`：`ControlCommand::NetworkUp { config: String }` / `NetworkStatus`。
11. `apps/nexus`：`network up --config`（前台装配）+ `network status --json`；`--help` 文案。
12. 手动冒烟：`--help` + `network status --json`（无真机 TUN 时诚实报错，不虚构）。

### 阶段 5：验证

13. `cargo fmt --check` / `cargo check --workspace --all-features` / `clippy -D warnings`。
14. E4 真机重跑（fresh Evidence）。
15. 独立 8 维 Review（≤3 轮，reviewer 独立于实现者）。
16. `verify --fast` 8/8 → `verify --full`；收集 Evidence ID。
17. 完工 push（pre-push hook 已修复可执行位，verify --fast 随 push 跑）。

## 2. 非目标（诚实边界）

- Android Underlay Bypass、其他平台 VPI 装配 E4：后置。
- mDNS 自动发现接线：M3 冻结"首期静态+mDNS"，`N1Discovery` trait 已预留，composition 先接 `StaticDiscovery`，mDNS 接线后置（不违反契约：trait 已存在）。
  - 注：此处需小心——契约 M3 说"mDNS 同子网自动发现"。若 E4/composition 只接静态，是否违反契约？
    契约原文："首期：静态配置（PeerId + 已知 locator）；mDNS 同子网自动发现（MdnsDiscovery，见 nexus-discovery D1–D6）"。
    解读：mDNS 是首期能力。`AggregateDiscovery`（静态>mDNS>LSA）已存在，composition 应直接用 `AggregateDiscovery` 而非裸 `StaticDiscovery`，
    这样 mDNS 能力即得，无需额外工作。决定：composition 用 `AggregateDiscovery::new(static, lsa, mdns)`（查其构造签名）。
- PKI/握手认证、TURN 中断重建、daemon 化：后置（诚实边界已载明）。

## 3. 风险与对策

| 风险 | 对策 |
|---|---|
| QUIC 路径迁移在 IP 变更（非端口变更）时不工作 | 先做最小连通性预实验（单独小 example 验证 rebind+IP 变更），不行则升级为 BLOCKED 报告 |
| 内核 TCP over TUN 在 netns 内行为异常 | os_assemble E4 已验证 TUN 数据面；TCP 是标准内核行为 |
| `nsenter`/`ip` 在 xc-pc-linux 上权限问题 | appen 有 NOPASSWD sudo for `/usr/bin/ip`；以 root 跑 example（agent 是 root） |
| example 双进程复杂度高 | 父进程只做编排（建 veth、改 IP、收 JSON），子进程逻辑独立成函数 |

## 4. 知识条目计划

- `worktree-hooks-not-executable`：已记（Contract 阶段）。
- 待记：fabric rebind 回环绑定问题（D0）、driver 吞 send_to 错误对观测的影响（D3）、veth 双 netns E4 模式（D4）。
