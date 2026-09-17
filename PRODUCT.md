# Nexus Product Contract

## 1. 产品定义

Nexus 向用户提供一个统一 Resource Fabric。用户表达“要使用什么资源”和“如何使用”，系统负责发现 Provider、规划 Provider/Placement/Path、建立 Session、激活 Connectivity、执行并持续观测。

产品入口包括：

```text
Devices
Network
Services
Workspaces
Compute
```

这些是产品分类，不是互相割裂的底层系统。

## 2. Network / InternetAccess

Network Resource 必须支持：

- 由 Virtual Packet Interface、SOCKS、HTTP 或 Native API 产生 FlowContext。
- Policy 生成 Intent + Constraint。
- Core Planner 选择 InternetAccess Provider、Placement、Path 与 ExecutionStrategy。
- Session 创建后才执行 Connectivity Establishment。
- DNS 作为 NetworkPlanExtension 管理 Exit-DNS Binding。
- 运行时可观察 Connectivity、DNS、Session、Measurement 与 Replan。

失败必须区分至少：

```text
NO_PROVIDER
CONSTRAINT_UNSATISFIED
CONNECTIVITY_ESTABLISHMENT_FAILED
DNS_RESOLUTION_FAILED
AUTHORIZATION_DENIED
PLATFORM_CAPABILITY_UNAVAILABLE
SESSION_FAILED
```

## 3. Service

Service 是 Resource。

`connect` 建立 Nexus-aware Service Session；`forward` 创建本地 listener 并把本地连接映射到 Service Session。对非 loopback 的监听必须显式授权。

## 4. Workspace

Workspace 是版本化、内容寻址、支持离线分叉的 Data Resource。

权威模型：

```text
WorkspaceId
Commit DAG
Head Set
Namespace / Manifest
Object / Chunk CAS
Replica Set
```

必须满足：

- 离线写允许创建本地 Commit。
- 多端并发写允许形成多个 Head。
- 网络恢复后支持 fast-forward、three-way merge 或显式 Conflict Resolution。
- 不得因为远端 Head 变化丢弃已经成功本地提交的数据。
- 支持 WorkingSet、Profile、WorkspaceGraph 与 Prefetch，但这些不是权威内容。
- 支持 Reachability GC、Storage Quota、Shallow Sync 与 Sparse Replica。
- 无 FUSE/Mount 环境仍可通过 Native API、Materialization 或平台式 Projection 使用。

## 5. Compute

Compute 是 Resource。

执行前固定 Workspace Commit/Snapshot，Planner 综合：

```text
Compute Capability
Queue Delay
Execution Estimate
Workspace Data Locality
WorkingSet Coverage
Missing Bytes
Connectivity Feasibility
Cache Hints
Platform Capability
```

Write-back 必须创建新 Workspace Commit，而不是修改 pinned Snapshot。

## 6. 远程资源访问（Remote Resource Access）

Nexus 允许一个节点作为请求方，通过标准 Intent 访问另一个节点（提供方）上的资源。远程访问复用单节点流水线：

```text
Resolve -> Plan -> Session -> Connectivity -> Execute -> Observe
```

远程资源访问必须满足：

- Discovery 解析提供方 Peer 的 Endpoint；P0 支持静态发现表与动态 Presence 注册（`PresenceRegistry`：announce/resolve + TTL 过期语义）两种模式；动态 Presence 支持网络发现协议（`Discover`/`Announce`/`PeerUnknown`/`PeerExpired` 帧），发现请求-响应经注入的 `DiscoveryTransport` 在节点间传输（组合根 P0 为 TCP + 长度前缀帧）；Presence 注册与网络发现协议解耦——请求方经协议拉取远端公告、本地缓存并按 TTL 刷新，过期公告不得使用。
- 认证门控在业务帧转发前完成：未通过认证的请求在帧流建立后、业务帧前被拒绝，返回 `AUTHORIZATION_DENIED`。
- Transport 提供长度前缀帧协议；P0 冻结为 TCP + u32 大端长度前缀帧。
- 建连失败按逆序幂等回滚（Connectivity -> Session -> Plan 释放），Session 物理排空到 Disposed，TerminalOutcome 由 Owner 唯一提交 `Failed`。
- Connectivity 链路激活按候选顺序执行（v9 §243 P0 子集）：Direct 探测成功即建立直连；Direct 不可达（NAT 场景）时回退 Relay 候选；全部候选不可达返回结构化 `NO_LINK_AVAILABLE`，不替换业务 Provider（由 Core Planner 生成替代 Plan）。P0 的 Relay 为进程内中继转发，中继协议（DERP/自定义）后置。
- Service、InternetAccess、Compute 与 Workspace 是远程访问的首批资源类型；Workspace 远程语义为远程提交（Node A 经闭环向 Node B 的 Workspace 应用 ChangeSet 并取回新 Head）。
- 远程闭环同时以两种形态交付：SDK 组合根函数（apps/nexus）与 daemon 单次执行入口（apps/nexusd `run <resource> --json`）；daemon 对未知资源返回结构化拒绝（`UNKNOWN_RESOURCE`，exit 0 = 请求已被处理）。
- 真实网络交付（real transport）：远端闭环除进程内组合根外，提供真实 TCP 交付形态——提供方 `host` 在真实地址监听并完成**服务端**认证门控（`AUTH` 帧在业务帧前，失败返回 `AUTH_DENIED`）；请求方经静态发现解析真实 Endpoint 后建立真实帧流并执行线上认证；直连不可达时经真实 `relay`（`DIAL` + 字节中继）回退。wire 应用帧（AUTH/AUTH_OK/AUTH_DENIED/CONNECT/READY/ECHO/COMPUTE/RESULT/HTTP/DIAL/RELAY_OK）为应用层协议，传输帧格式仍冻结为 TCP + u32 大端长度前缀。

## 7. Session 语义

Session 使用双轨状态：

```text
LifecyclePhase:
Allocating | Active | Draining | Disposed

TerminalOutcome:
Unfinished | Completed | Failed | Cancelled
```

Completed/Failed/Cancelled 只能提交一次；资源清理可以在 Outcome 确定后继续，最终 LifecyclePhase 到达 Disposed。

## 8. 跨平台产品语义

Nexus 保证 Semantic Portability，而不是强迫所有平台 API 一致。

同一产品能力可以由不同 Platform Capability 实现：

```text
VirtualPacketInterface:
Linux TUN
Windows virtual interface
macOS packet tunnel
Android VPN service
iOS packet tunnel

Workspace Access:
FUSE / filesystem projection
file-provider-style projection
materialized directory/data
native API
```

平台缺少某项能力时，必须返回明确的 Capability Unsupported 或选择文档化降级路径，不能静默改变产品语义。

## 9. 可观察性

关键 Resource/Session 必须可被 CLI/GUI/Agent 观察。

至少提供：

```text
status
plan explain
session watch
connectivity status/candidates/probe/links
dns status/resolve/providers/cache
workspace heads/conflicts/cache
compute jobs
diagnose
platform capabilities
```

## 10. 完成条件

关键用户可见 Capability 原则上至少需要一条 E4 Product Scenario 或 E5 External Observation 证据。

代码存在、单元测试通过、Agent 声称完成、README 标记完成，都不是最终完成判据。

## 11. 代理内核 / Rule-Based Routing Proxy {#11-proxy-kernel}

在既有「远程资源访问闭环」（§6）之外，新增一条独立产品线：规则分流代理内核
（参考 meow-rs / sing-box 机制）。该产品线不修改 §2 Network / InternetAccess 的
既有语义，不污染已冻结的远程闭环 E4 场景。

P0 最小闭环：

```text
SOCKS5 入站（复用 nexus-ingress 状态机）
  -> RuleSet 静态规则表（顺序匹配）
  -> rule_action 动作链（第一动作选定出站 tag）
  -> 策略组（selector 手动 / urltest 按 measurement 自动选优）
  -> Direct / Relay 出站（复用 nexus-connectivity LinkActivator）
  -> 配置层 YAML -> typed structs（Nexus 首个配置入口）
```

### 11.1 用户可观察语义

- 系统从 YAML 配置文件加载入站监听、规则表、策略组与出站定义；解析失败必须
  返回结构化配置错误（`CONFIG_INVALID`），不得静默回退默认。
- SOCKS5 入站复用 `nexus-ingress` 的 `Socks5Handshake` 状态机（RFC 1928/1929）；
  握手完成产出 `FlowContext`（origin=socks5, destination）后进入规则引擎。
- 规则引擎对每个 FlowContext 按声明顺序匹配静态规则表，首条命中即终止
  （first-match）。规则类型 P0 冻结为：
  - `DOMAIN-SUFFIX`：目的域名等于或以 `.` 拼接规则后缀结尾；
  - `DOMAIN`：目的域名精确匹配；
  - `IP-CIDR`：目的为 IP literal 且落在 CIDR 网段内；
  - `MATCH`：兜底规则（必须存在于规则表末尾，匹配一切未命中流量）。
- 每条规则命中后产出 `rule_action` 动作链（有序动作列表）。P0 冻结第一动作
  为 `SELECT_OUTBOUND <tag>`（选定出站或策略组 tag）；动作链为日后 DNS hijack /
  route-options 等后置扩展留口，但 P0 不实现额外动作类型。
- 策略组：
  - `selector`：手动指定候选出站 tag 列表，当前选中项可经 API 切换；切换为
    确定性操作（不发起网络探测）。
  - `urltest`：对候选出站执行 measurement（复用 `nexus-planner` 的 measurement
    选择与 `nexus-connectivity` 的 `LinkProbe`），按离线可复现的确定性数据
    （注入 mock measurement）选择延迟最低候选；P0 禁止真实网络探测。
- 出站：
  - `Direct`：直连，复用 `nexus-connectivity` 的 Direct 链路激活；
  - `Relay`：进程内中继转发，复用 `nexus-connectivity` 的 Relay 链路激活；
    P0 不实现真实加密代理协议栈。
- 每次分流决策必须可观察：命中规则名、规则类型、选定出站 tag、策略组类型、
  动作链首动作。

### 11.4 真实 SOCKS5 数据面（real socks proxy，2026-09-18）

在 §11 P0 决策内核之外，交付真实 SOCKS5 上网数据面全链路：

```text
SOCKS5 入站（Socks5Handshake 状态机，真实字节流）
  -> FlowContext -> 规则路由（§11 纯决策语义，零 I/O）
  -> Session 双轨（Active -> Disposed，TerminalOutcome 唯一提交）
  -> 真实出站连接（代理即出口；域名在此真实 DNS 解析后拨号）
  -> 双向字节中继（客户端 <-> 出站）
```

- 出站激活从 §11 P0 的 mock `LinkActivator` 提升为真实 `std::net::TcpStream`
  拨号（Direct 语义）；不引入加密代理协议（与 §11.2 边界一致）。
- 每次会话必须可观察：握手结果（NO-AUTH 回复）、CONNECT 回复码、命中规则、
  选定出站 tag、Session phase/outcome、双向中继字节数。
- E4 场景：`scenarios/product/daemon_real_socks_proxy_flow.toml`（本地 HTTP 目标
  + 原始 SOCKS5 客户端经代理真实往返 HTTP 200）。

### 11.2 P0 明确不做（不得写进本期 expectation）

以下为 P1+ 展望，本期契约不承诺、不冻结为 expectation：

- 真实加密代理协议栈（Shadowsocks / Vmess / Trojan / Hysteria2）；
- TUN 透明代理 / Virtual Packet Interface 全局拦截；
- Clash 订阅 YAML 在线解析与自动更新；
- LoadBalance / Relay 链式策略组（多跳）；
- DNS 多 server 规则路由（DNS hijack 仅在动作链模型中留口，不在 P0 实现）。

### 11.3 失败语义

```text
CONFIG_INVALID              YAML 解析失败 / 规则表无 MATCH 兜底 / 出站 tag 悬空
NO_MATCH_RULE               规则表缺 MATCH 兜底且流量未命中任何具体规则
OUTBOUND_TAG_UNRESOLVED     动作链选定的出站或策略组 tag 不存在
SELECTOR_EMPTY              selector 策略组候选列表为空
URLTEST_NO_VALID_CANDIDATE  urltest 组所有候选均无有效 measurement
```
