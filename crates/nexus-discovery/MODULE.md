# nexus-discovery Module Contract

## Responsibility

执行 Bootstrap、Peer Discovery、Endpoint/Candidate Exchange 与 Presence 建立。

## Non-Responsibilities

不承担长期业务数据转发，不决定业务 Provider，不拥有 Session。

## Inputs

- 仅接受公开类型、DTO、trait、事件或稳定协议对象。
- 输入必须可被结构化验证；不得依赖未声明的全局隐式状态。

## Outputs

- 结构化 Result / Event / DTO。
- 失败必须保留可诊断原因，不以日志文本代替错误类型。

## Allowed Dependencies

- `nexus-domain`
- `nexus-registry`
- `nexus-platform`

## Forbidden Dependencies

- `engineering/` 下的 Harness/Plugin。
- 未在 `policies/architecture.toml` 声明的 Nexus 内部 crate。
- Portable 模块中的平台专有 Framework/API。
- 通过“便利”依赖绕过公开领域边界。

## Invariants

- Discovery != Connectivity Establishment。
- Bootstrap 不成为已建立 Session 的长期数据依赖。

## Side Effects

- 仅允许 Responsibility 所需且在架构层中明确归属的副作用。
- 新增副作用前必须更新本契约和 Scenario/Policy（如影响外部行为）。

## Public API

### 冻结契约（remote P0 扩展，scenarios/product/remote_presence_dynamic_flow.toml）

- `pub struct Presence { peer: PeerId, endpoint: SocketAddr, ttl_secs: u64, announced_at: Instant }`
  动态 Presence：提供方主动发布的可达性公告（AGENTS.md §15 冷启动 reconcile 的重新发布 Provider Presence）。
- `pub struct PresenceRegistry { presences: Vec<Presence> }`：进程内动态发现注册中心。
  - `pub fn announce(&mut self, peer: PeerId, endpoint: SocketAddr, ttl_secs: u64) -> Result<(), DiscoveryError>`
    发布/刷新提供方 Presence（幂等：重复 announce 刷新记录）。
  - `pub fn resolve(&self, peer: &PeerId) -> Result<SocketAddr, DiscoveryError>`
    动态解析：Presence 存在且未过期 -> Endpoint；未发布 -> `PeerUnknown`；已过期 -> `PeerExpired`。
  - `pub fn is_announced(&self, peer: &PeerId) -> bool`
- `pub enum DiscoveryError` 新增变体：`PeerExpired(PeerId)`。

冻结语义：`resolve` 只做注册中心查询，不发起网络 I/O、不建立 Connectivity（Discovery != Connectivity Establishment）；TTL 过期后 Peer 不可解析（不得返回过期 Endpoint）；`announce` 幂等刷新。

### 冻结契约（remote P0 扩展，网络发现协议，scenarios/product/remote_presence_network_discovery_flow.toml）

- `pub trait DiscoveryTransport { fn exchange(&mut self, request: &[u8]) -> Result<Vec<u8>, DiscoveryError> }`
  发现协议传输抽象：一次请求-响应往返。不携带发现业务语义；实现由 Composition Root 注入
  （组合根 P0 为 TCP + 长度前缀帧），Discovery 层零 I/O。
- `pub struct PresenceClient { registry: PresenceRegistry }`：请求方侧网络发现客户端（本地缓存已发现公告）。
  - `pub fn discover(&mut self, transport: &mut impl DiscoveryTransport, peer: &PeerId) -> Result<Presence, DiscoveryError>`
    经发现协议拉取远端 Presence：编码 `Discover` 请求帧 -> exchange -> 解码响应；
    `Announce` 则缓存入本地注册中心并返回；`PeerUnknown`/`PeerExpired` 原样返回（不得缓存、不得使用）。
  - `pub fn resolve_local(&self, peer: &PeerId) -> Result<SocketAddr, DiscoveryError>`：查本地缓存（代理 `PresenceRegistry::resolve`）。
- `pub struct PresenceServer`：提供方侧无状态协议处理器。
  - `pub fn handle(&self, registry: &PresenceRegistry, request: &[u8]) -> Vec<u8>`
    解码 `Discover` -> `registry.resolve` -> 编码 `Announce` 或 `PeerUnknown`/`PeerExpired` 响应帧。
- `pub enum DiscoveryFrame { Discover(PeerId), Announce { peer: PeerId, endpoint: SocketAddr, ttl_secs: u64 }, PeerUnknown(PeerId), PeerExpired(PeerId) }`
  `pub fn encode_frame(frame: &DiscoveryFrame) -> Result<Vec<u8>, DiscoveryError>` / `pub fn decode_frame(payload: &[u8]) -> Result<DiscoveryFrame, DiscoveryError>`
  帧格式：type tag (u8) + 字段（字符串为 u16 BE 长度前缀 + UTF-8，endpoint 为地址字符串）。确定性、可移植、无新依赖。
- `pub enum DiscoveryError` 新增变体：`Transport(String)`（发现协议传输失败：发送/接收/解码失败，携带原因）。

冻结语义：`PresenceClient` 不直接持有网络（`DiscoveryTransport` 单请求-响应注入）；
`PresenceServer::handle` 无状态、不发起 I/O、只做 registry 查询与帧编解码；
`Discover` 不建立 Connectivity（Discovery != Connectivity Establishment）；
网络发现只解析 Endpoint，建连仍走后续 Plan/Connectivity 阶段；
过期 Presence 经协议返回 `PeerExpired`，客户端不得使用过期 Endpoint。

### 冻结契约（自动发现扩展，scenarios/product/auto_discovery.toml）

纯同步、内存骨架、无新依赖、无 tokio/async；真实网络传输留 TODO，由 Composition Root 注入。

- `pub struct DiscoveryConfig { pub bootstrap_nodes: Vec<String>, pub node_id: String }`
  自动发现配置（bootstrap_nodes 为引导节点标识串；node_id 为本节点标识）。
- `pub enum DiscoveryState { Idle, Discovering, Connected, Offline }`
  状态机（`#[derive(Debug, Clone, Copy, PartialEq, Eq)]`）；
  `pub fn as_str(self) -> &'static str` 返回 `"idle"/"discovering"/"connected"/"offline"`。
- `pub struct DiscoveredNode { pub node_id: String, pub virtual_ip: String, pub locator: String, pub last_seen: u64 }`
  已发现对等节点（Identity != Locator；last_seen 由调用方注入，便于确定性测试）。
- `pub struct BootstrapRegistry { peers: Vec<DiscoveredNode> }`：引导注册中心（服务端侧，纯内存、无 I/O）。
  - `pub fn new() -> Self`
  - `pub fn register(&mut self, node: DiscoveredNode)`：按 node_id 幂等 upsert，刷新 virtual_ip/locator/last_seen。
  - `pub fn get_peers(&self, exclude: &str) -> Vec<DiscoveredNode>`：排除 self，按 node_id 升序返回以保证确定性。
  - `pub fn heartbeat(&mut self, node_id: &str, now: u64) -> Result<(), DiscoveryError>`：
    刷新 last_seen；未知节点返回 `PeerUnknown(PeerId)`。
  - `pub fn peer_count(&self) -> usize`：注册节点总数（含 self）。
- `pub struct AutoDiscovery { config, state, known_peers }`：自动发现状态机（客户端侧；心跳由 Owner 周期性调用 `heartbeat()` 驱动）。
  - `pub fn new(config: DiscoveryConfig) -> Self`（初始 `Idle`）。
  - `pub fn state(&self) -> DiscoveryState` / `pub fn config(&self) -> &DiscoveryConfig` / `pub fn known_peers(&self) -> &[DiscoveredNode]`。
  - `pub fn register(&mut self, registry: &mut BootstrapRegistry, virtual_ip: &str, locator: &str, now: u64) -> Result<(), DiscoveryError>`
    把本节点 upsert 进 registry；state: `Idle -> Discovering`。
  - `pub fn discover_peers(&mut self, registry: &BootstrapRegistry) -> Result<Vec<DiscoveredNode>, DiscoveryError>`
    拉取 peers 更新 `known_peers`；拉到至少一个 peer 时 state 保持 `Discovering`（建连成功后由调用方 `mark_connected`）。
  - `pub fn heartbeat(&mut self, registry: &mut BootstrapRegistry, now: u64) -> Result<(), DiscoveryError>`：透传 `registry.heartbeat` 错误。
  - `pub fn mark_connected(&mut self)` / `pub fn mark_offline(&mut self)`：状态转移到 `Connected` / `Offline`。
- `pub enum AutoDiscoveryFrame { Register{node_id, virtual_ip, locator}, GetPeers{node_id}, PeerList{peers}, Heartbeat{node_id, now} }`
  `pub fn encode_auto_frame(&AutoDiscoveryFrame) -> Result<Vec<u8>, DiscoveryError>` / `pub fn decode_auto_frame(&[u8]) -> Result<AutoDiscoveryFrame, DiscoveryError>`
  帧格式：type tag (u8) Register=11 / GetPeers=12 / PeerList=13 / Heartbeat=14；
  字符串为 u16 BE 长度前缀 + UTF-8（复用 lib.rs `put_str`/`get_str`）；u64 为大端 8 字节；
  PeerList 节点数量为 u16 BE 前缀，每个节点依次 node_id/virtual_ip/locator 三字符串 + last_seen u64。
  空帧/未知 tag/截断/非法 utf8/越界一律返回 `Transport(String)`。

冻结语义：发现 != 建连——`AutoDiscovery` 只做注册/拉取/心跳，不发起 Connectivity；
建连由 Composition Root 编排；状态机转移为 `Idle -> Discovering -> Connected -> Offline`；
`register`/`heartbeat`/`discover_peers` 均为纯内存操作，无网络 I/O。

### 冻结契约（remote P0，scenarios/product/remote_service_access_flow.toml）

- `pub struct PeerId(pub String)`：提供方节点标识。Identity != Locator：Peer 不携带 Endpoint 本身。
- `pub struct StaticDiscovery { peers: HashMap<PeerId, SocketAddr> }`：静态发现表（发现协议后置）。
  - `pub fn new(peers: impl IntoIterator<Item = (PeerId, SocketAddr)>) -> Self`
  - `pub fn resolve(&self, peer: &PeerId) -> Result<SocketAddr, DiscoveryError>`
- `pub enum DiscoveryError { PeerUnknown(PeerId) }`

冻结语义：`resolve` 只做静态表查询，不发起网络 I/O、不建立 Connectivity（Discovery != Connectivity Establishment）；P0 的 Peer/Endpoint 关系由组合根以静态表注入。

### 常规要求

- 默认最小 surface：`private -> pub(crate) -> pub`。
- Public API 变更必须保持结构化、可版本化并有调用方验证。

## Verification

最低：

```text
cargo check -p nexus-discovery
cargo clippy -p nexus-discovery --all-targets -- -D warnings
```

如果该模块影响产品行为，还必须映射 Integration/Scenario Evidence。

## Performance Budget

未定义性能预算的路径不得宣称“性能完成”。进入 hot path 后必须在 Contract 中增加 baseline、noise tolerance、warning threshold 与 blocking threshold。

### 冻结契约（LSA 发现协议 P5，PRODUCT §12.44，scenarios/product/lsa_discovery.toml）

新模块 `lsa`（portable：零 I/O、零第三方依赖）：Hello/Welcome 入网 + LSA 泛洪 +
LSDB。本期 LSA 只负责发现（`neighbors` 为空）；选路为后续 feature。

- 帧格式：`[version: u8=1][tag: u8][fields...]`；字符串 = `u16 BE` 长度前缀 + UTF-8；
  整数 = BE；`Option<String>` = `u8` 存在位 + 字符串。版本不匹配 / 未知 tag /
  截断 / 尾随字节 → `DiscoveryError::Transport`。
- `pub enum LsaFrame { Hello { node_id, vip, capabilities: u32, incarnation: u64 },
  Welcome { lsas: Vec<Lsa> }, LsaAdvert { lsa: Lsa } }`；
  `pub fn encode_lsa_frame / decode_lsa_frame`（确定性、可移植）。
- `pub struct Lsa { node_id: PeerId, vip: String, incarnation: u64, seq: u64,
  capabilities: u32, locator: Option<String>, neighbors: Vec<LinkAdvert> }`。
- `pub struct Lsdb`：`new(self_id)`；`update(lsa) -> UpdateOutcome`
 （本端 → `SelfIgnored`；新 → `New`；`(incarnation, seq)` 更新 → `Updated`；
  否则 → `Stale`）；`update_local(lsa)`（本端发布）；`get / contains / all / len`。
- `pub struct SeenCache`：`new(capacity)`；`should_flood(node_id, incarnation, seq) -> bool`
 （有界 FIFO 去重，防内存无限增长）。
- Deletion Test：LSA 发现是去中心化拓扑同步的独立变化维度，与 `DiscoveryFrame`
 （presence 查询）正交；无新 trait。

### 冻结契约（Dijkstra 选路 P5，PRODUCT §12.45，scenarios/product/dijkstra_fib.toml）

新模块 `routing`（portable：零 I/O、零第三方依赖）：LSDB → `TopoView` →
`PathComputer` → `FIB`。本项起 LSA 的 `neighbors` 填充真实链路通告
（§12.44 的"neighbors 为空"是发现阶段的临时状态）。

- `pub struct TopoView<'a>`：`from_lsdb(&Lsdb)`（O(V+E)）；链路按通告方向建边，
  不要求对称；`node_count()`、`contains(&PeerId)`。
- `pub struct Path { pub nodes: Vec<PeerId>（含 src/dst）, pub cost: u64 }`。
- `pub trait PathComputer { fn name(&self) -> &'static str; fn compute(&self, topo: &TopoView, src: &PeerId, dst: &PeerId) -> Option<Path>; fn compute_all(&self, topo: &TopoView, src: &PeerId) -> HashMap<PeerId, Path>（默认逐 dst，有批量优化需求的 impl 覆盖）; fn compute_paths(&self, topo: &TopoView, src: &PeerId, dst: &PeerId) -> Vec<Path>（默认退化为单路径）; fn compute_all_paths(&self, topo: &TopoView, src: &PeerId) -> HashMap<PeerId, Vec<Path>>（默认逐 dst） }`；
  本项 `pub struct ShortestPath`（Dijkstra，`name()=="shortest"`，BinaryHeap 最小堆，
  单次运行算全目的地）。
- 链路代价 `max(latency_ms, 1)`（u64）；不可达 → `None`；src==dst → 零代价单节点路径。
- `pub struct NextHop { pub peer: PeerId, pub weight: u32（本期恒 1）, pub path_id: u32（本期恒 0） }`。
- `pub struct Fib`：`compute(lsdb, self_id, computer, generation)` 全量重算整体替换
  （RCU 风格）；`dst vip → Vec<NextHop>`（本期每 dst 1 条）；`generation()`、
  `lookup(vip)`、`len()`；本端无条目。
- Deletion Test：选路是 LSDB 上的独立计算维度（未来 ECMP/K-shortest/Disjoint 只加
  `PathComputer` impl，不动 LSDB/FIB/协议），与泛洪/编解码正交；`PathComputer`
  通过"多算法共享 FIB/TopoView"的独立变化维度。

## Observability

稳定结构化字段优先于自由文本；如涉及 Session/Provider/Path/Workspace，应携带对应 correlation id。

## Recovery Semantics

任何持久状态或长期任务都必须定义 crash 后的 reconcile 行为。无持久状态的纯模块应保持可重建。

## Platform Constraints

平台专有代码只允许存在于 `nexus-platform-*` 或 Composition Root。Portable crate 必须通过相应 portability gate。

### 冻结契约（ECMP 等代价多路径 P5，PRODUCT §12.46，scenarios/product/ecmp.toml）

在 §12.45 的 `routing` 模块上增量：新增 `PathComputer` 实现 `Ecmp`；
`Fib::compute` 改用 `compute_all_paths`，按去重后的第二跳填 `Vec<NextHop>`。
LSA/LSDB/泛洪协议零改动。

- `pub struct Ecmp`：`name()=="ecmp"`；Dijkstra 保留所有等代价前驱
  （链路代价 ≥ 1，前驱表完备），DFS 枚举全部等代价最短路；
  `compute()` 返回其中一条（兼容单路径语义）。
- `Fib` 多下一跳：`NextHop{peer, weight: 恒 1, path_id: 路径序号}`；
  单路径算法下行为与 §12.45 一致（每 dst 1 条）。
- Deletion Test：ECMP 是算路算法的独立变化维度（只加 `PathComputer` impl，
  不动 LSDB/FIB/协议），与 ShortestPath 正交。

### 冻结契约（按流哈希选择下一跳 P5，PRODUCT §12.47，scenarios/product/flow_hash.toml）

在 §12.46 的 `routing` 模块上增量：新增 `FlowKey`（5 元组）与
`Fib::select_next_hop`；LSA/LSDB/泛洪/算路协议零改动。

- `pub struct FlowKey { src_ip: IpAddr, dst_ip: IpAddr, src_port: u16,
  dst_port: u16, protocol: u8 }`：`Clone + Copy + PartialEq + Eq + Hash + Debug`。
- `FlowKey::hash() -> u64`：FNV-1a 64 手写实现（零依赖）；IP 按 16 字节展开
  （IPv4 映射为 IPv6 兼容形式，两种写法哈希一致）；端口 BE；跨平台/跨运行/
  跨节点确定。
- `Fib::select_next_hop(&self, vip: &str, flow: &FlowKey) -> Option<&NextHop>`：
  未知/不可达 → `None`；单下一跳直接返回；多条按 `hash % n` 索引
  （条目内按 peer 排序，索引跨节点一致）；纯函数，零 I/O。
- Deletion Test：流哈希选择是转发面的独立变化维度（ECMP 只决定"有哪些下一跳"，
  本项决定"某流走哪一条"），与算路算法正交；删除后 ECMP 的 `Vec<NextHop>`
  无消费者，转发面无法做 per-flow 一致选路。

### 冻结契约（`[routing] strategy` 配置装配 P5，PRODUCT §12.48，scenarios/product/routing_strategy.toml）

在 §12.47 的 `routing` 模块上增量：新增 `RoutingStrategy` 枚举；
LSA/LSDB/泛洪/算路/FIB 零改动。

- `pub enum RoutingStrategy { Shortest, Ecmp }`：
  `Clone + Copy + PartialEq + Eq + Debug`；`Default` 为 `Shortest`（向后兼容）。
- `RoutingStrategy::parse(s: &str) -> Result<Self, StrategyParseError>`：
  大小写不敏感、前后空白忽略；未知 → `Err(Unknown(s))`。
- `impl PathComputer for RoutingStrategy`：各方法静态委托给对应变体
  （`ShortestPath` / `Ecmp`）；`name()` 与直接使用具体类型一致。
- 配置层（`apps/nexus/src/subnet_cli.rs`）：subnet TOML 新增顶层 `[routing]` 段，
  `strategy` 字段缺省 → `"shortest"`；`SubnetConfig::routing_strategy()` 解析，
  未知值 → `Err("ROUTING_STRATEGY: ...")`（fail-closed）。
- Deletion Test：策略装配是"配置→算法选择"的独立变化维度（之前各调用方
  hardcode 具体 `PathComputer` 类型）；删除后新增策略需改所有调用点，
  违反开闭原则。

### 冻结契约（K-shortest 路径 P5，PRODUCT §12.49，scenarios/product/k_shortest.toml）

在 §12.48 的 `routing` 模块上增量：新增 `PathComputer` 实现 `KShortest`；
LSA/LSDB/泛洪/算路/FIB/策略枚举零改动。

- `pub struct KShortest`：`KShortest::new(k)`（`k>=1`，`k==0` panic）；
  `name()=="k-shortest"`；`k()` 返回 K 值。
- Yen 算法：P1 = Dijkstra；P(k) 经 spur node 枚举（删除成环边/节点后
  Dijkstra 求 spur path）；返回至多 K 条无环路径，按代价升序；
  不可达 → 空 Vec；`compute()` 返回第一条。
- 复杂度 O(K·V·(E log V))；`RoutingStrategy` 暂不集成（K 参数化，待设计）。
- Deletion Test：K-shortest 是"非等代价多路径"的独立变化维度
  （ECMP 只给等代价，K-shortest 给主备）；删除后无备用路径来源。

### 冻结契约（FIB 管理器 P5，PRODUCT §12.50，scenarios/product/fib_manager.toml）

在 §12.49 的 `routing` 模块上增量：新增 `FibManager<C: PathComputer>`；
LSA/LSDB/算路/FIB 零改动。

- `FibManager::new(self_id, computer, lsdb)`：初始计算，generation=1。
- `maybe_recompute(&mut self, lsdb) -> bool`：指纹变化 → 重算 + generation+1
  → `true`；否则无操作 → `false`。
- `fib() -> &Fib`、`generation() -> u64`、
  `select(vip, flow) -> Option<&NextHop>`（委托 `Fib::select_next_hop`）。
- LSDB 指纹：FNV-1a 64 over 排序后的全部 LSA
  `(node_id, incarnation BE, seq BE, neighbor 列表排序, latency)`；
  正确性靠版本向量：`Lsdb::update` 强制 `(incarnation, seq)` 递增，
  任何被应用的更新必 bump 版本 → 指纹变化（未直接哈希的字段经此间接覆盖）。
- Deletion Test：FIB 管理器是"变化检测 + 代际管理"的独立维度
  （之前调用方手写指纹判断或无脑重算）；删除后要么每次全量重算
  （浪费），要么漏掉拓扑变化（错误）。

### 冻结契约（Disjoint 不交路径 P5，PRODUCT §12.51，scenarios/product/disjoint.toml）

在 §12.50 的 `routing` 模块上增量：新增 `PathComputer` 实现 `Disjoint`；
LSA/LSDB/算路/FIB/管理器零改动。

- `pub struct Disjoint`：`Disjoint::new()`；`name()=="disjoint"`。
- Suurballe 算法：Dijkstra 得 dist1 → P1 边反向 → 变换边权
  `w'(u,v)=w+dist1[u]-dist1[v]`（反向边权为 0）上 Dijkstra 得 P2 →
  合并抵消正反边对 → DFS 提取 2 条边不交路径。
- `compute_paths` 返回 0/1/2 条（按代价升序）；边不交指无共享有向边。
- Deletion Test：Disjoint 是"故障隔离"的独立维度（K-shortest 的备用路
  可能共享链路，单点故障双路全断）；删除后无链路级容灾路径来源。
