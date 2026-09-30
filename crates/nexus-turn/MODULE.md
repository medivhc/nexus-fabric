# nexus-turn — MODULE

## Responsibility

RFC 5766 TURN 的最小可用实现（client + 自测用最小 server），为路径层
四级回退（直连 → Mesh → TURN → 代理出口）提供标准中继。`TurnSocket`
实现 `nexus-fabric::UdpTransport`，让 QUIC 会话跑在 TURN 中继上。

## Non-Responsibilities

- 路径选择（那是 `nexus-path` 的 `PathManager`）。
- TURN over TLS / DTLS（后置）。
- 公网 TURN 服务部署（E4 用自研最小 server）。

## Inputs

- TURN server 地址、长效认证用户名/密码（`TurnCredentials`）。
- 经 `TurnSocket` 收发的 UDP 载荷（上层已加密，TURN 只看外层）。

## Outputs

- `TurnClient`：分配（allocate/refresh）、权限（create-permission）、
  通道（channel-bind）。
- `TurnSocket: UdpTransport`：`send_to` 经 ChannelData/Send 中继；
  `recv_from` 返回解封装后的（载荷，真实对端地址）；
  `local_addr` 返回中继分配地址。
- `TurnServer`（最小，仅 E4/自测）：处理 allocate/refresh/
  permission/channel-bind/data 中继。

## Allowed Dependencies

- `std` only（零 Tokio，与 `nexus-fabric` 一致）
- `nexus-fabric`（仅 `UdpTransport` trait；`nexus-fabric` 不反向依赖本 crate）
- `hmac` / `sha1` / `md5`（RFC 5766 长效认证必需；MIT/Apache-2.0；
  引入时走依赖评审，见 AGENTS.md §4）

## Forbidden Dependencies

- `tokio`, `async-std`, 任何 async runtime
- 自研 STUN 之外的 NAT 穿透库（P0 只需 TURN 中继，不做打洞）

## Invariants

**T1（最小子集）**：实现 RFC 5766 的 Allocate / Refresh / CreatePermission /
ChannelBind / ChannelData / Send indication + 长效认证（HMAC-SHA1，
key = MD5(username:realm:password)）。STUN 短期认证、TCP 中继后置。
认证为双向：client 请求带 MI；server 响应（除 401 外）亦带 MI，client
在 `transact()` 校验（RFC 5766 §2.2）。

**T2（中继不解密）**：TURN 只中继 UDP 载荷，不触碰上层加密
（`nexus-fabric` S1：中继节点只能看到密文）。

**T3（权限模型）**：数据只能发往已 `CreatePermission` 的对端；
`ChannelBind` 绑定 channel number → peer；发往未授权目标 → 丢弃并计数
（`turn_unauthorized_dropped`）。Channel number 0x4000–0x7FFF，
与 STUN 消息类型空间不冲突。

**T4（分配生命周期）**：allocation 默认 600s（RFC 5766）；`refresh()`
续租；超时或 Refresh 失败 → 分配失效，后续 `send_to`/`recv_from`
返回错误（`TurnError::AllocationExpired`），不静默黑洞。

**T5（sync）**：全同步 std API，零 tokio。`TurnClient` 操作（allocate 等）
为阻塞调用，由调用方决定线程。

**T6（TurnSocket 语义）**：`send_to(buf, target)` 要求 target 已授权，
经 ChannelData（已绑定）或 Send indication（未绑定但已授权）发出；
`recv_from` 返回 `(载荷, 真实对端 SocketAddr)`（剥离 ChannelData 头或
解析 XOR-PEER-ADDRESS）；`local_addr()` 返回 server 分配的中继地址
（XOR-RELAYED-ADDRESS）。

## Side Effects

- UDP socket（直连 TURN server）。
- 后台线程：`TurnServer` 的主循环线程（Drop 时停止并 join）。
- 注意：`TurnClient` **没有**后台 refresh 保活线程；`refresh()` 需调用方显式
  调用（当前 E4/路径层按需调用）。MODULE 旧文案“可选的 refresh 保活（由调用方
  启停）”指的就是这个显式调用语义，不是后台线程。

### 控制/数据面共享 socket 语义（WARN-4 说明）

- `TurnClient` 的控制面（`transact`）与数据面（`TurnSocket::recv_from`，由
  fabric driver 线程常驻调用）**共享同一个 UDP socket 和同一把锁**。
- `transact` 持锁阻塞 `recv` 期间到达的 ChannelData 会被静默丢弃（QUIC 重传
  恢复，属性能抖动非正确性问题）；反之 driver 持锁 `recv` 时到达的控制面
  响应也会被丢弃（`recv_via_relay` 只处理 ChannelData/Data indication）。
- 设计约束：同一时刻只允许一个控制面事务在途（`transact` 串行化）。若
  refresh 响应恰在 driver 持锁时到达被丢弃，`transact` 会 3s 超时并标记分配
  过期——窗口极窄（需与 driver 的 recv 精确交错），但语义上存在。后续如需
  根治，应在 `transact` 中暂存 ChannelData 而非丢弃。

## Public API

- `TurnCredentials { username, password, realm }`
- `TurnClient::allocate(server, creds) -> io::Result<TurnClient>`
- `TurnClient::create_permission(&self, peer: SocketAddr)`
- `TurnClient::bind_channel(&self, peer: SocketAddr) -> u16`
- `TurnClient::refresh(&self)`, `TurnClient::relayed_addr(&self) -> SocketAddr`
- `TurnSocket::new(client: TurnClient) -> TurnSocket`
- `impl nexus-fabric::UdpTransport for TurnSocket`
- `TurnServer::bind(addr, creds) -> io::Result<TurnServer>`（最小实现，仅测试）

## Verification

- E4 `product.fabric-turn-relay`：双 client 经自研 server 建 QUIC 并传数据。
- 单元测试：STUN 编解码、XOR 地址、长效认证向量（RFC 5766 附录）。

## Performance Budget

- 中继转发：server 侧 per-packet 开销 < 10µs（纯内存拷贝+表查找）。
- Client 侧 ChannelData 头 4 字节（vs Send indication 的 36+ 字节开销）。

## Observability

- 计数：`turn_allocations`, `turn_refreshed`, `turn_unauthorized_dropped`,
  `turn_relayed_bytes`, `turn_allocation_expired`.
- **未计数的静默丢弃**（设计说明，非遗漏）：
  - client 收到未知 channel 的 ChannelData → 丢弃（无计数；对端协议错误，
    QUIC 层无感）。
  - `transact` 收到 txn 不匹配的响应 → 丢弃（单事务在途，不应发生）。
  - server 收到无分配源的 Send indication → 丢弃（无计数；未认证流量）。
  - 上述三处若需可观测性，应加计数器（当前为有意省略，保持最小）。

## 已知偏离与限制（诚实边界）

- **权限粒度**：server 按 RFC 5766 以 IP 为单位记录 permission；client 侧
  `TurnClient` 以 `SocketAddr`（IP:port）为单位做发送前检查（更严格，安全
  方向）。两者语义有差异，但 client 侧只会更保守，不会导致误放行。
- **401 stale-nonce**：`allocate` 收到 401 会自动提取 realm/nonce 重发一次；
  `refresh` 收到 401 则直接标记分配过期（不重试）。自研 server 的 nonce 永不
  变更，故 E4 不触发；对接第三方 TURN server 时若遇 nonce 轮换需调用方重新
  `allocate`。
- **Loopback 限制**：`TurnClient::allocate` 绑定 `127.0.0.1:0`，
  `TurnServer` 的中继 socket 也绑定 `127.0.0.1:0`。作为通用 client API，
  `TurnClient` 目前不支持绑定非 loopback 地址；`TurnServer` 明确仅用于自测
  （见 Non-Responsibilities）。

## Recovery Semantics

- Allocation 过期 → 显式错误，不自动重分配（调用方/路径层决定是否重建路径）。
- Server 重启 → client 下次 Refresh 失败感知，需重新 allocate（S2 切换不丢连接
  由上层重建路径保证，TURN 层只诚实报错）。

## Platform Constraints

- 纯 std + UDP，无平台相关代码。

## Deletion Test

**问题**：如果删除 `nexus-turn`，会破坏哪个独立变化维度？

**回答**：NAT 穿透失败时的标准中继路径。直连、Mesh 转发、代理出口都不需要
TURN 协议；TURN 的分配/权限/通道状态机是独立的协议维度。删除它只会失去
四级回退中的第三级，不影响直连 QUIC 或代理出口。

**反例**：如果永远只有公网直连（无 NAT），则该 crate 可删除。
但 P0 明确要四级回退，抽象成立。
