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
不实现真实 DNS 传输协议（UDP/TLS/HTTPS），真实传输由后续 `Resolver` 实现提供。

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
enum DnsError { ResolutionFailed(String), LoopDetected(String), NegativeCached(String), InvalidQuery(String) }

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
