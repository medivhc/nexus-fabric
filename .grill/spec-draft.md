# #7 Flow-session 启用 — Spec 草稿（grill 阶段）

- run: `flow-session`（#7）
- base: master `a656e63`（#3 fabric-over-proxy、#4 NAT switching 已合入）
- 日期: 2026-10-17
- 委托: 用户全权委托，技术决定由 grill 直接定（见 `decisions.md`）

## 1. 目标

让上层（分布式工作空间 / 文件传输 / 后续服务）能通过 QUIC-like 会话层 API
**打开可靠流**、**发送不可靠数据报**；连接身份为 `(PeerId, ConnectionId)`，
与底层 UDP 地址解耦——**底层地址切换（手机关 WiFi 等漫游场景）时不断流、
已确认数据不丢**。

一句话：把 `nexus-fabric::FabricConn` 从"只有 examples/tests 在用"变成
"上层可用的生产 API"，只做**启用/接线**，不做新协议设计。

## 2. 术语澄清（防混淆，先立规矩）

仓库里有三个"会话"，同名异物，本任务只碰第一个：

| 名称 | 位置 | 含义 | 本任务 |
|---|---|---|---|
| 会话层连接 | `nexus-fabric::FabricConn` | QUIC-like：可靠流/不可靠数据报/统计，CID 与地址解耦 | ✅ 对象 |
| 任务执行会话 | `nexus-session::SessionOwner` | Plan 运行生命周期、TerminalOutcome 唯一写入者 | ❌ 无关 |
| 流→资源会话映射 | `nexus-flow-session::SessionManager` | TUN 5 元组流 → §10 资源会话（Policy→Planner→Owner） | ❌ 无关 |

（`nexus-fabric/MODULE.md` 已有"禁止混淆"禁令，此处重申。）

## 3. 现状调查结论（代码实证）

### 3.1 已实现、可直接复用的

| 能力 | 位置 | 证据 |
|---|---|---|
| 可靠双向流 `open_bi`/`accept_bi`，`write`/`finish`/`read`/`read_deadline` | `nexus-fabric/src/lib.rs`, `driver.rs` | S4 有序完整交付；`finish` 后对端读 EOF |
| 不可靠数据报 `send_datagram`/`recv_datagram`/`send_datagram_seqed`/`recv_datagram_seqed` | `nexus-fabric/src/lib.rs` | S5 尽力而为；QSEQ（GAP-2 冻结）提供 fabric 层序号 |
| `ConnectionId` 与 UDP 5 元组解耦（S2） | `driver.rs::NEXT_CONN_ID`（进程级 `AtomicU64`） | 连接身份 = `(PeerId, ConnectionId)` |
| 漫游 `rebind()`（S3/S6） | `driver.rs::cmd_rebind` | client 换 wildcard 新端口→对端 QUIC 被动迁移；`examples/roam.rs` 4 MiB 流哈希一致、应用层停顿 < 5000ms |
| E2E 加密与身份（S1，mTLS） | `cert.rs`, `connect_mtls`/`bind_mtls` | ed25519 PeerId 绑定自签证书 |
| 诚实统计（S8） | `ConnStats`（Option 语义，unknown 不编造） | `stats()` |
| 路径事件 → `rebind()`；NAT 双连接 active 翻转（D1） | `nexus-projection/src/path_link.rs::PathLink` | `Switched`→`rebind()`；relay/direct 两条 QUIC 连接按 PathManager 评分翻转 |
| datagram 传输 + 每 conn pump 线程 | `nexus-projection/src/transport.rs::FabricTransport` | TUN 数据面在用 |
| NAT 打洞信令通道 | `nexus-nat-wireup`（`Driver::connect` + `ConnShared::open_stream`，#4） | 复用打洞 socket，不另建 |
| D5 分流契约 | `nexus-nat-wireup/src/lib.rs:242` | punch 注册的 relay 连接上**禁止**调 `accept_bi`（会与 responder 抢 accept 队列）；非打洞流经 `PunchManager::take_unclaimed()` 取走 |

### 3.2 未接线（本任务要填的坑）

1. **零生产 dial/listen**：`FabricConn::connect`、`FabricListener::bind`/`accept`
   的调用者只有 tests/examples，无生产装配点。
2. **可靠流零生产消费者**：`open_bi`/`accept_bi` 无生产调用。TUN 数据面走自研
   STREAM 帧（`stream_id u32be | flags u8 | payload` over best-effort datagram，
   SYN/FIN/RST 一次性、无重传——可靠性由两端 TCP 栈（smoltcp 本地终结 +
   TcpEgress 重发起）提供，与本任务正交）。
3. **无上层会话注册表**：没有 `PeerId → FabricConn` 的生命周期管理
   （按需拨号、复用、优雅关闭）；`nexus-workspace`/`nexus-delivery` 对 fabric
   零引用。
4. **无入向分发**：没有"远端开流→路由到本地服务 handler"的 API；
   没有"远端数据报→上层服务"的通道。
5. **数据报 intent 类型位 `0b11` 未分配**（`lib.rs`: bit0-1 = 00 mesh / 01 egress /
   10 stream；`0x03` 空闲）——天然的上层服务通道位。

### 3.3 已知限制（P0 不修，文档化 + AC 量化上界）

- `SendStream::write` 无背压（内存缓冲，P0 文档化限制）。
- `connect()` 只用 `ConnConfig.addrs[0]`（P0：无竞速；NAT 场景由 PathLink D1
  双连接机制覆盖）。
- 首期无 0-RTT、多路径。

## 4. 交付物：`nexus-projection::flow_session` 新模块

在 `nexus-projection` 内新增模块（落点决定见 `decisions.md` D1），提供上层
`PeerId` 级会话 API。草案形状（develop 阶段定稿签名）：

```rust
/// 上层会话中心：PeerId → FabricConn 注册表 + 入向分发。
pub struct FlowSessionHub { /* PathLink + listener + 分发表 */ }

impl FlowSessionHub {
    /// 新建：接管一个已 bind 的 listener（后台 accept 线程）与 PathLink。
    pub fn new(listener: FabricListener, link: PathLink, ...) -> Self;

    /// 按需拨号（幂等）：未知 peer 经 PathLink/PathManager 选路建连并注册；
    /// 已知 peer 直接复用。返回是否新建。
    pub fn dial(&self, peer: PeerId, candidates: &[SocketAddr]) -> Result<bool, FlowError>;

    /// 打开到 peer 的可靠双向流（S4 语义）。
    /// 未建连时自动 dial（用上次 candidates；无则 PathUnreachable）。
    pub fn open_stream(&self, peer: PeerId)
        -> Result<(SendStream, RecvStream), FlowError>;

    /// 向 peer 发不可靠数据报（S5 语义；上层服务用 intent kind 0x03，
    /// 见 D4；>1200 字节拒绝）。
    pub fn send_datagram(&self, peer: PeerId, data: &[u8]) -> Result<(), FlowError>;

    /// 注册流服务：远端开流首帧类型字节 → handler。
    /// 类型字节沿用 wireup 首字节约定（D3），与打洞信令共存。
    pub fn register_stream_service(&self, type_byte: u8, h: StreamHandler);

    /// 注册数据报服务：intent kind 0x03 + 服务子 id → handler（D4）。
    pub fn register_datagram_service(&self, svc: u8, h: DatagramHandler);

    /// 连接统计（S8 诚实语义；peer 未知返回 None）。
    pub fn stats(&self, peer: PeerId) -> Option<ConnStats>;

    /// 关闭到 peer 的连接：新 open_stream 拒绝，已有流按 S7 语义结束；
    /// 后台线程退出（AC9 量化）。
    pub fn close_peer(&self, peer: PeerId);
}
```

关键接线规则（实现必须遵守）：

- **R1（D5 契约）**：punch 注册的 relay 连接上**不**起 `accept_bi` 循环；
  其入向流只从 `PunchManager::take_unclaimed()` 取。普通连接起每 conn
  `accept_bi` 循环（沿用 `FabricTransport` pump 线程模式）。
- **R2（漫游）**：地址切换事件走现有 `PathLink::pump()`（`Switched`→`rebind()`；
  NAT 场景 D1 active 翻转）。Hub 不发明新迁移逻辑；`rebind()` 期间的
  `open_stream`/`send_datagram` 按 `FabricError` 语义返回，不静默丢。
- **R3（数据报分流）**：在现有 pump 的 `recv_datagram` 之后、按 intent 首字节
  分流：`0x00/0x01/0x02` 走原 TUN 收件箱（线兼容，不动）；`0x03` 按服务子 id
  分发到上层 handler。单泵单队列，不出现双消费者竞争。
- **R4（拨号）**：`dial` 把 candidates 注册为 `PathManager` 候选，
  用 `FabricConn::connect`（`addrs[0]`，P0）或 `connect_with_transport`
 （TURN/中继场景，S9）；NAT peer 走 `register_nat_relay`/`register_nat_direct`
  双连接路径（复用 #4）。
- **R5（背压）**：`open_stream` 返回的 `SendStream` 沿用无背压语义；
  Hub 文档强制要求调用方分块写入（单次 `write` ≤ 256 KiB，见 AC10）；
  超大单次写入返回 `FlowError::TooLarge`（新错误变体，develop 定）。
- **R6（身份）**：注册表键为 `PeerId`（ed25519）；`String` peer 名只保留在
  projection 边界（配置/展示），不进入新 API。

## 5. 验收标准（AC，可独立验证、量化）

- **AC1 可靠流端到端**：两节点（127.0.0.1 真实 UDP）经 Hub 建连，A
  `open_stream` 发 4 MiB，B 经注册 handler 收完，SHA-256 一致；B `finish`
  后 A 读到 EOF。断言：零 `quinn-proto`/`driver` 直接引用（只用 Hub API）。
- **AC2 数据报往返**：A `send_datagram_seqed` 发 100 包（每包 ≤1192B），B
  `recv_datagram_seqed` 收，序号严格单调递增（Q1/Q4）；乱序注入用
  `ReorderBuffer` 语义验证（沿用 multipath 现有单测口径）。
- **AC3 漫游不断流**：AC1 传输中途调 `rebind()`（模拟地址切换），断言：
  `ConnectionId` 不变、载荷哈希一致、应用层可见停顿 < 5000ms
  （沿用 `fabric_conn_roam` 冻结口径）。
- **AC4 按需拨号复用**：对未知 peer 连续 `open_stream` ×3，底层 `connect`
  只发生 1 次（计数器断言）；`dial` 幂等，再调返回 `Ok(false)`。
- **AC5 流服务分发**：注册 2 个服务（type_byte `0x10`/`0x11`），远端各开
  3 条流，6 条流全部路由到正确 handler，零串扰（per-handler 计数断言）。
- **AC6 D5 回归**：relay 连接经 `PunchManager::register_relay` 注册后，
  Hub 不在其上起 `accept_bi` 循环；打洞流被 responder 消费、普通流经
  `take_unclaimed` 到达正确 handler（单测口径：responder 与 Hub 不抢队列）。
- **AC7 数据报分流兼容**：`INTENT_STREAM(0x02)` 包仍进 TUN 收件箱
  （现有 `FabricTransport` 行为单测全过）；`0x03` 服务包进上层 handler，
  互不干扰。
- **AC8 统计诚实**：建连后 `stats(peer).rtt_ms` 为 `Some`（有样本）；
  未建连 peer 返回 `None`；无样本字段保持 `None`（S8，不编造 0）。
- **AC9 关闭语义**：`close_peer` 后 `open_stream` 返回 `Closed`；
  后台 accept/pump 线程数回到基线（`/proc` 线程计数或命名线程枚举，
  前后差 = 0）；已有流收到对端 close code。
- **AC10 无回归**：`cargo test -p nexus-fabric -p nexus-projection -p nexus-path
  -p nexus-nat-wireup` 全绿；`verify --fast` 受影响测试集全绿。
- **AC11 上界文档化**：单次 `write` > 256 KiB 返回 `TooLarge`；
  Hub 文档写明无背压 + 分块要求（review 抽查文档与实现一致）。

## 6. 范围

**In**：Hub 注册表（dial-on-demand、复用、close）、入向流分发
（`accept_bi` 循环 + `take_unclaimed` D5 集成）、数据报 `0x03` 分流、
`PathLink` 复用（rebind / NAT D1）、单测 + 上层使用示例
（workspace 文件传输如何调用，给出 example）。

**Out**：
- 不动 TUN 数据面线格式（STREAM-over-datagram 保持；其可靠性由两端
  TCP 栈提供，lockstep 升级风险超出"接线"范围）。
- 不做 0-RTT、多路径、路径竞速（`addrs[0]` P0 保持）。
- 不修 `SendStream` 无背压（AC11 文档化上界代替）。
- 不做新协议设计：流类型字节沿用 wireup 首字节约定；数据报用
  `0x03` 空闲 kind 位。

## 7. 风险与缓解

| 风险 | 缓解 |
|---|---|
| `accept_bi` 与 wireup responder 抢队列 | R1：D5 契约进单测（AC6） |
| pump 双消费者竞争 datagram | R3：单泵内按 intent 分流 |
| 无背压导致内存膨胀 | R5/AC11：256 KiB 上界 + 文档 |
| peer 名 String vs PeerId 两套身份 | R6：新 API 只用 PeerId |
| 与 TUN 路径 intent 冲突 | `0x03` 为空闲位；AC7 回归 |
