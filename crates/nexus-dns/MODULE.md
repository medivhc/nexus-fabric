# nexus-dns Module Contract

## Responsibility

提供 Resolver、DNS Routing、Cache、Synthetic/Fake-IP 映射、Domain/Flow 关联与 Exit-DNS Binding。

P0 实现边界（`DnsRuntime`）：

- 解析：经注入式 `Resolver` trait 解析 `DnsQuery`（A / AAAA）；
- 缓存：按 `(name, rtype)` 缓存解析结果与 TTL，过期重解析；
- singleflight：同一查询在 TTL 窗口内只触发一次底层解析（重复请求命中缓存）；
- 环路守卫：查询名命中已配置的上游解析器地址集合时返回 `LoopDetected`，不得挂死；
- RDRC 负缓存：解析失败进入负缓存，TTL 内不重试底层解析；
- Exit-DNS Binding：按 `domain -> exit` 规则决策出口，决策结果进入
  `NetworkPlanExtension.exit_dns_binding`（`version = NetworkPlanExtension::VERSION`）。
- 多 server DNS 路由（`DnsRouter` + `MultiServerDns`）：配置多个注入式 `Resolver` server，
  按域名规则首匹配选择本次解析走哪个 server，MATCH 兜底；路由决策可观察。

## Non-Responsibilities

不污染核心 Plan 固定字段；不直接修改平台系统 DNS；不感知 Connectivity/VPI；
不实现真实 DNS 传输协议（UDP/TLS/HTTPS）。“不实现真实传输”仍然成立：`wire`
只做**报文编解码**（无 socket、无 `Instant`、无全局状态）；UDP/TCP socket、
超时/重试/故障转移/并发上限全部在 `nexusd` 服务面（DnsService / 上游引擎）。
本层也不决定 TLS/DoH 等上游形态，`Resolver` 由 Composition Root 注入。

## Inputs

- 仅接受公开类型、DTO、trait、事件或稳定协议对象。
- 输入必须可被结构化验证；不得依赖未声明的全局隐式状态。
- 时间以显式 `now_secs` 参数传入（可测；不依赖平台时钟）。

## Outputs

- 结构化 Result / Event / DTO：`DnsAnswer`、`ExitDnsDecision`、`DnsError`。
- 失败必须保留可诊断原因（`DnsError` 变体），不以日志文本代替错误类型；
  对上层暴露 `NexusError::DnsResolutionFailed` 映射。

## Allowed Dependencies

- `nexus-domain`

## Forbidden Dependencies

- `engineering/` 下的 Harness/Plugin。
- 未在 `policies/architecture.toml` 声明的 Nexus 内部 crate。
- Portable 模块中的平台专有 Framework/API。
- 通过“便利”依赖绕过公开领域边界。
- `nexus-connectivity`（v9 CLI 产品线运行时，frozen）。跨栈词汇改用 `nexus-domain` /
  `nexus-proxy-config` / `nexus-session` / `nexus-qos`（P3 落地）。

## Invariants

- singleflight：同一 `(name, rtype)` 在 TTL 窗口内底层 `Resolver` 至多被调用一次；
  后续请求必须命中缓存。
- 环路守卫：查询名等于任一已配置上游解析器地址 → `DnsError::LoopDetected`；
  环路负测试不得挂死。
- RDRC：被拒绝的查询进入负缓存，负缓存 TTL 内重复查询直接返回
  `DnsError::NegativeCached`，不得重试底层解析。
- `IpPreference` 语义：`V4Only` 只保留 A 记录、`V6Only` 只保留 AAAA 记录、
  `PreferV4` 使 v4 地址排前、`PreferV6` 使 v6 地址排前。
- Exit-DNS Binding：`exit_dns_binding(name)` 返回首个匹配 `domain -> exit` 规则
  的出口；无匹配返回 `None`；决策数据只进入 `NetworkPlanExtension`。
- DNS 多 server 路由：规则表声明顺序首匹配；域名匹配 = 精确或 `.{domain}` 子域；
  无具体命中 -> `default_server`。
- `MultiServerDns::new` 校验所有规则与 `default_server` 引用的 server tag 均存在；
  悬空返回 `DnsError::UnknownServer`。
- 选中 server 后，解析只经该 server 注入的 `Resolver` 完成，不跨 server。
- 多 server 路由为离线确定性决策：`Resolver` 由 Composition Root 注入，本层不发起真实网络。
- 既有单 server `DnsRuntime` 的缓存/环路守卫/RDRC/Exit-DNS Binding 语义不变。
- DNS 特定规划数据进入 NetworkPlanExtension。
- 系统 DNS 修改由 Platform Capability 完成。

## Side Effects

- 仅允许 Responsibility 所需且在架构层中明确归属的副作用（内存缓存写入）。
- 新增副作用前必须更新本契约和 Scenario/Policy（如影响外部行为）。

## Public API

```text
enum IpPreference { V4Only, V6Only, PreferV4, PreferV6 }
enum DnsType { A, Aaaa }
struct DnsQuery { name: String, qtype: DnsType }
struct DnsRecord { name: String, rtype: DnsType, ttl_secs: u64, address: IpAddr }
struct DnsAnswer { name: String, records: Vec<IpAddr>, from_cache: bool }
enum DnsError { ResolutionFailed(String), LoopDetected(String), NegativeCached(String), InvalidQuery(String), UnknownServer(String), NameNotFound(String) }

trait Resolver {
    fn resolve(&mut self, query: &DnsQuery) -> Result<Vec<IpAddr>, DnsError>;
}

struct DnsRuntime { /* resolver: Box<dyn Resolver>, cache, negative_cache, upstream_addrs, exit_rules */ }

impl DnsRuntime {
    fn new(
        resolver: Box<dyn Resolver>,
        cache_ttl_secs: u64,
        upstream_addrs: Vec<String>,
        exit_rules: Vec<(String, String)>,   // (domain, exit)
    ) -> Self;
    fn resolve(&mut self, query: &DnsQuery, preference: IpPreference, now_secs: u64)
        -> Result<DnsAnswer, DnsError>;
    fn resolve_exit_binding(
        &mut self,
        name: &str,
        preference: IpPreference,
        now_secs: u64,
    ) -> Result<ExitDnsDecision, DnsError>;
    fn exit_dns_binding(&self, name: &str) -> Option<String>;
    fn to_plan_extension(&self) -> NetworkPlanExtension;
    fn cache_snapshot(&self) -> Vec<(String, DnsType, bool)>;   // (name, rtype, from_negative)
    fn negative_cache_snapshot(&self) -> Vec<(String, DnsType)>;
}

struct ExitDnsDecision {
    name: String,
    resolved: Vec<IpAddr>,
    from_cache: bool,
    exit: Option<String>,
    preference: IpPreference,
}

// --- DNS 多 server 路由（§11.5）---
// DnsError 新增变体：UnknownServer(String)。
struct DnsRouteRule { domain: String, server: String }
struct DnsServerSelection { server: String, matched_domain: Option<String> }
struct DnsRouter { /* rules: Vec<DnsRouteRule>, default_server: String */ }
impl DnsRouter {
    fn new(rules: Vec<DnsRouteRule>, default_server: String) -> Self;
    fn select(&self, name: &str) -> DnsServerSelection;
}
struct ServerResolved { name: String, server: String, addresses: Vec<IpAddr> }
struct MultiServerDns { /* servers: Vec<(String, Box<dyn Resolver>), router: DnsRouter */ }
impl MultiServerDns {
    fn new(servers: Vec<(String, Box<dyn Resolver>)>, router: DnsRouter)
        -> Result<Self, DnsError>;   // 悬空 server tag -> UnknownServer
    fn select_server(&self, name: &str) -> DnsServerSelection;
    fn resolve(&mut self, name: &str, qtype: DnsType) -> Result<ServerResolved, DnsError>;
}
```

> 实现期修正（契约一致性）：环路与负缓存命中通过 `DnsError::LoopDetected` /
> `DnsError::NegativeCached` 错误路径表达，不再冗余携带于 `ExitDnsDecision`。
> singleflight 语义用 `DnsRuntime::resolver_call_count()` 提供可验证观测：
> 同一 `(name, rtype)` 在 TTL 窗口内底层解析至多一次。

Public API 变更必须保持结构化、可版本化并有调用方验证。

### R3 新增 Public API：`wire` / `mesh`（2026-10-28）

```text
// --- wire：DNS 报文编解码（纯函数，零 I/O、零 Instant、零全局状态）---
enum DnsRcode { NoError, FormErr, ServFail, NxDomain, NotImp, Refused, Other(u8) }
struct DnsQuestion { id: u16, name: String, qtype: u16, rd: bool, edns_udp_size: Option<u16> }
struct WireRecord { rtype: u16, ttl_secs: u32, address: Option<IpAddr> }
struct UpstreamReply { rcode: DnsRcode, truncated: bool, records: Vec<WireRecord>, min_ttl_secs: u32, wire: Vec<u8> }
enum DnsWireError { Truncated, BadHeader, BadName, NoQuestion, BadQuestion, MismatchedQuestion, UnsupportedType(u16) }

fn parse_question(packet: &[u8]) -> Result<DnsQuestion, DnsWireError>;
fn build_query(q: &DnsQuery, id: u16, edns_udp_size: Option<u16>) -> Vec<u8>;
fn parse_response(packet: &[u8], expected: &DnsQuestion) -> Result<UpstreamReply, DnsWireError>;
fn build_answer(query: &[u8], records: &[WireRecord], rcode: DnsRcode) -> Result<Vec<u8>, DnsWireError>;
fn build_error(query: &[u8], rcode: DnsRcode) -> Result<Vec<u8>, DnsWireError>;
fn patch_id(packet: &mut [u8], id: u16) -> Result<(), DnsWireError>;

// --- mesh：静态 Mesh 名表 ---
struct StaticMeshResolver { /* BTreeMap<归一化名, IpAddr> */ }
impl StaticMeshResolver {
    fn new(entries: impl IntoIterator<Item = (String, IpAddr)>) -> Result<Self, DnsError>;
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool;
}
impl MeshNameResolver for StaticMeshResolver { fn resolve_mesh(name: &str) -> Option<IpAddr>; }
```

- `wire` 是**纯编解码层**：12 字节规则、QDCOUNT=1、压缩指针拒绝、TC=1 早返回
  `truncated=true`、上游 question 与请求不符 → `MismatchedQuestion`。socket、
  并发、超时、重试、EDNS 协商策略都在 `nexusd`。
- `build_query` 的冻结签名无 `Result`：非法名（空/超长/非法标签）返回**空
  `Vec`**，调用方必须把空包视为构造失败。
- `mesh` 只做精确匹配（不做后缀/通配）：构造期归一化（小写、去尾点、≤253、
  拒绝空标签）与地址校验；`::1`/`127.0.0.1`/unspecified/multicast/broadcast
  → `InvalidQuery`，link-local（`fe80::`/`169.254.0.0/16`）允许。
  `a.mesh` 与 `b.a.mesh` 是不同名字。


### 冻结契约：DNS IP-CIDR 规则与按 server 缓存隔离（§11.5.1，scenarios/product/dns_ipcidr_rule.toml）

- `enum DnsMatch { Domain(String), IpCidr { network: u32, prefix: u8 } }`；
  `DnsRouteRule { matcher: DnsMatch, server: String }`。域名匹配语义不变。
- `DnsRouter::select(name, client_ip: Option<IpAddr>) -> DnsServerSelection`：
  按声明顺序首匹配；`IpCidr` 规则仅当 `client_ip` 是 IPv4 且 `(ip & mask) == network` 时命中；
  无命中走 `default_server`。`select_server(name)` 等价于 `select(name, None)`。
- IPv4 CIDR 手写解析：`a.b.c.d/p`，p∈0..=32；非法前缀/非法 IP 由 config 层拒绝。
- `MultiServerDns` 缓存键 = `(server_tag, name, qtype)`：不同 server 分表，互不命中；
  命中返回 `from_cache=true` 且不调用该 server 注入的 `Resolver`。
- `MultiServerDns::resolve_with(name, qtype, client_ip)`；`resolve(name, qtype)` 等价
  `resolve_with(name, qtype, None)`。`ServerResolved` 新增 `from_cache: bool`。
- 不变量：跨 server 同名查询不共享缓存；既有单 server `DnsRuntime` 语义与既有 DNS 冻结场景零回归。
- 离线确定性：缓存由 Composition Root 注入的 mock `Resolver` 产生，本层不发起真实网络。

## 统一 DNS（S-unified，2026-10-01 冻结）

### Responsibility（新增）

`nexusd` 的单一 DNS 服务：对 TUN `dns-hijack` 导入的查询做统一分类，按
`mesh 域名 > 代理规则（fake-ip）> 直连上游` 顺序应答。

### 组件

- `DnsUnifiedConfig`：`upstream: Vec<String>`（dns.toml 声明，由 Composition Root
  消费以构造注入的上游 `Resolver`）、`fake_ip_enabled: bool`、
  `fake_ip_network: u32` + `fake_ip_prefix: u8`（默认 `198.18.0.0/15`，构造时
  掩码归一化）、`mesh_suffix: String`（默认 `"mesh"`）、
  `fake_ip_ttl_secs: u64`、`hosts: Vec<(String, IpAddr)>`（自定义 hosts，最高优先级）、
  `ip_preference: IpPreference`（地址族偏好，默认 `PreferV4`；语义见下）。
- `FakeIpPool`：fake-ip 分配池。`allocate(domain, now_secs) -> Ipv4Addr`；
  `lookup(ip) -> Option<String>` 反查域名；`reclaim_expired(now_secs)` 回收
  TTL 过期的映射；同一域名在 TTL 内重复分配返回同一 IP。
- `MeshNameResolver` trait：`resolve_mesh(name) -> Option<IpAddr>`，由
  Composition Root 注入（peer 主机名 → 虚拟网 IP）。
- `ProxyClassifier` trait：`is_proxied(domain) -> bool`，由 Composition Root
  注入（通常包装 `nexus-proxy` 的 `RuleEngine`）。Deletion Test：若删除该
  trait，`nexus-dns` 将被迫直接依赖 `nexus-proxy`（违反 Forbidden
  Dependencies），故抽象成立。
- `UnifiedDns`：`step(query, now_secs) -> Result<ResolveStep, DnsError>`
  （两阶段：本地可判定返回 `Local`，否则返回 `Upstream { class }`）；
  `classify(name) -> DnsClass`（`Hosts | Mesh | FakeIp | Upstream`）；
  `resolve(query, now_secs)` 保留为 `step` + 注入上游的**兼容薄封装**（C11 删除）。

### Invariants（S-unified）

- 分类顺序：`hosts` 精确匹配 > `*.{mesh_suffix}`（含 peer 主机名经
  `MeshNameResolver`）> `ProxyClassifier::is_proxied` 为真 → fake-ip >
  否则上游 `Resolver`。
- Fake-IP 范围：分配的地址必须落在 `fake_ip_range` 内（默认
  `198.18.0.0/15`）；`FakeIpPool::new` 对非规范 CIDR 做掩码归一化；
  `fake_ip_enabled = false` 时代理类域名走上游解析（不分配 fake-ip）。
- 分配确定性：同一 `(domain, qtype=A)` 在 TTL 窗口内重复查询返回同一
  fake-ip，不消耗新地址；AAAA 查询不分配 fake-ip（返回空应答）。
- 反查一致性：`lookup(allocate(d)) == Some(d)`；过期回收后 `lookup` 返回
  `None`，且该 IP 可被重新分配。
- 回收：`reclaim_expired(now)` 只回收 `expires_at <= now` 的条目；未过期
  条目不受影响。
- 上游隔离：mesh/fake-ip/hosts 命中的查询不得调用上游 `Resolver`
  （`resolver_call_count() == 0` 可观测）。
- 时间注入：`now_secs` 由调用方显式传入；不读系统时钟。
- 离线确定性：`MeshNameResolver` / `ProxyClassifier` / 上游 `Resolver`
  均由 Composition Root 注入；本层不发起真实网络、不碰 TUN。

### Public API（新增）

```text
struct DnsUnifiedConfig { upstream, fake_ip_enabled, fake_ip_network, fake_ip_prefix, mesh_suffix, fake_ip_ttl_secs, hosts, ip_preference }
struct FakeIpPool { new(network, prefix, ttl_secs), allocate(domain, now_secs), lookup(ip), reclaim_expired(now_secs), contains(ip), len(), capacity() }
trait MeshNameResolver { resolve_mesh(name) -> Option<IpAddr> }
trait ProxyClassifier { is_proxied(domain) -> bool }
enum DnsClass { Hosts, Mesh, FakeIp, Upstream }  // as_str() 稳定表达
struct UnifiedAnswer { name, class: DnsClass, records: Vec<IpAddr>, from_cache: bool }
enum ResolveStep { Local(UnifiedAnswer), Upstream { class: DnsClass } }
struct UnifiedDns { new(config, mesh, classifier, upstream), step(query, now_secs), resolve(query, now_secs), classify(name),
                    reverse_lookup(ip), reclaim_expired(now_secs),
                    upstream_call_count(), note_upstream_answer(), fake_ip_count(), fake_ip_capacity() }
```

### 两阶段 `step` / `NameNotFound` / `ip_preference`（R3，2026-10-28）

- `step` 只做**本地可判定**部分，不调用上游；`Upstream { class }` 表示调用方
  （`nexusd` 上游引擎）异步取回后再 `note_upstream_answer()` 计数并组装应答。
  `resolve` 仅为过渡薄封装（内部 `step` + `resolve_upstream`），C11 生产接线时删除。
- `DnsError::NameNotFound(name)`：`*.{mesh_suffix}` 命中但静态表无名 →
  **NXDOMAIN**，且**不得**向上游泄露内部名（`upstream_call_count() == 0`）。
  名字存在但无该族记录 → `Local` NODATA（不是错误）。
- 族不符（A 查 v6 / AAAA 查 v4）→ `Local` NODATA；fake-ip 开启时代理类
  AAAA 恒 NODATA 且**不消耗** fake-ip 地址（AC8a）。
- `ip_preference`（D-impl-5）：`V4Only`/`V6Only` 只门控 **Upstream/Mesh/Hosts**
  的查询 qtype（被拦截 → `Local` NODATA）；fake-ip 类的 A 不受影响。
  `PreferV4`/`PreferV6` 在单 qtype 拦截路径上是 **no-op**（本层不做多记录排序，
  不假装有排序效果）。
- **非 A/AAAA qtype 的落点边界（协调员接受的落点上移，语义不变）**：
  `DnsQuery.qtype` 冻结为 `DnsType { A, Aaaa }`，`step` 无法表达 HTTPS(65)/TXT/PTR
  等类型。服务面在调用引擎前用 `wire::DnsQuestion::as_dns_type()` 判定：
  Hosts/Mesh/FakeIp 名上的非 A/AAAA 查询 → NODATA；Upstream 类 → **原样 qtype
  转发**（不缓存），由服务面 C9/C11 短路，`step` 不参与。该边界不放宽冻结签名。


### Verification（新增）

```text
cargo test -p nexus-dns wire
cargo test -p nexus-dns mesh
cargo test -p nexus-dns unified
scenarios/product/dns_unified.toml
```

## Verification

最低：

```text
cargo check -p nexus-dns
cargo clippy -p nexus-dns --all-targets -- -D warnings
cargo test -p nexus-dns
```

产品行为映射（E4）：

```text
scenarios/product/dns_exit_binding.toml
apps/nexus/examples/dns_exit_binding.rs
```

## Performance Budget

未定义性能预算的路径不得宣称“性能完成”。进入 hot path 后必须在 Contract 中
增加 baseline、noise tolerance、warning threshold 与 blocking threshold。

## Observability

稳定结构化字段优先于自由文本；`cache_snapshot()` / `negative_cache_snapshot()`
为 §9 可观察命令（dns status/cache）提供数据出口。

## Recovery Semantics

无持久状态；进程重启后缓存可重建（内存缓存不承诺跨进程存活）。

## Platform Constraints

平台专有代码只允许存在于 `nexus-platform-*` 或 Composition Root。Portable crate
必须通过相应 portability gate。
