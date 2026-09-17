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

## Observability

稳定结构化字段优先于自由文本；如涉及 Session/Provider/Path/Workspace，应携带对应 correlation id。

## Recovery Semantics

任何持久状态或长期任务都必须定义 crash 后的 reconcile 行为。无持久状态的纯模块应保持可重建。

## Platform Constraints

平台专有代码只允许存在于 `nexus-platform-*` 或 Composition Root。Portable crate 必须通过相应 portability gate。
