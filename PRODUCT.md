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
- 认证门控在业务帧转发前完成：未通过认证的请求在帧流建立后、业务帧前被拒绝，返回 `AUTHORIZATION_DENIED`；服务端拒绝时随 `AUTH_DENIED` 帧携带原因，客户端必须把认证失败透传为显式认证错误（错误码 `AUTH_DENIED` + 原因），禁止抹成通用建连失败。
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

已就绪命令返回结构化 JSON 快照；领域未就绪命令必须显式返回 `UNSUPPORTED`（禁止静默降级，
PRODUCT §9）。

三命令可观察语义（2026-09-18 冻结）：

- `workspace conflicts`：输出工作区合并冲突快照——构造同 base 双 Head 对同一路径的
  冲突写入，调用三方合并捕获 `MergeConflict`，输出冲突路径集合、Head 集与合并处置。
- `compute jobs`：输出计算作业会话快照——经注入的内存帧通道显式提交作业并取回结果，
  输出各作业的阶段（Active/Closed）与结果。
- `diagnose`：输出子系统健康聚合报告——逐子系统（status/connectivity/dns/workspace/
  plan/session/platform）给出 ready 判定与关键摘要，并输出 overall 结论。

六命令可观察语义（2026-09-18 冻结）：

- `connectivity candidates`：输出链路候选快照——按 LinkKind 构造 direct/relay 候选
  （locator + setup cost），输出候选清单。
- `connectivity probe`：输出候选探测快照——对候选逐个执行 `LinkProbe`（内存注入），
  输出每候选 ok/fail 与激活选择。
- `connectivity links`：输出已建立链路快照——经 `LinkActivator` 激活选择并输出链路
  kind、locator 与激活事件链。
- `dns resolve`：输出解析快照——经 `DnsRuntime` 解析示例域名，输出地址列表、
  TTL 与 Exit-DNS Binding。
- `dns providers`：输出 DNS 提供方快照——上游地址集合、Exit 规则表与服务器路由清单
  （`DnsRouter` 引用服务器）。
- `workspace cache`：输出内容存储缓存快照——对象计数、protected roots 计数与
  GC 保留期语义（mark_roots + sweep_older_than）。

### 9.1 CLI 前端接线与双输出（2026-09-18 冻结）

- `nexus` CLI 前端把全部 17 个 §9 观察命令接线到同一 `observability` 快照
  （与 nexusd 同源，不复制领域逻辑），不再存在"其余命令返回 UNSUPPORTED"的接线缺口；
  领域未就绪命令（如 `connectivity trace`）仍显式返回结构化 `UNSUPPORTED`。
- 全局 `--json` 开关：`--json` 模式把快照 JSON 原样打到 stdout（单行 JSON，stderr 静默）；
  默认模式渲染人读文本视图（JSON 的字段投影，风格对齐 `ControlOutput::to_lines`）。
- exit 语义对齐 nexusd：用法/解析错误（缺参、未知命令）exit 2 并打印 usage；
  业务成功 exit 0；`NexusError` 领域拒绝输出 `verdict=FAIL` 结构化 JSON 且 exit 0
  （请求已被处理，与 `print_json_result` 一致）。

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
  - `GEOIP`：目的 IP 归属地为规则指定国家码（数据由组合根注入的 GEOIP 库展开为
    CIDR 列表，编译期静态匹配，见 §11.11）；
  - `GEOSITE`：目的域名属于规则指定分类集合（数据由组合根注入的分类清单展开为
    域名后缀集，编译期静态匹配，见 §11.11）；
  - `RULE-SET`：引用 rule-providers 定义的规则集（domain / ipcidr / classical
    三种行为，编译期展开为内联匹配器，保持 provider 内声明顺序首匹配，见 §11.11）；
  - `MATCH`：兜底规则（必须存在于规则表末尾，匹配一切未命中流量）。
- IP 类规则（`IP-CIDR` / `GEOIP` / `RULE-SET`(ipcidr)）对未解析的域名流量不命中
  （`FlowContext` 未携带目标 IP）；规则可选 `no_resolve: true`（默认 false）——该标志为
  编译期属性并进入分流决策可观察字段，表示「命中评估不要求先做 DNS 解析」；真实解析差异
  由数据面（§11.4）承接。
- 每条规则命中后产出 `rule_action` 动作链（有序动作列表）。P0 冻结第一动作
  为 `SELECT_OUTBOUND <tag>`（选定出站或策略组 tag）；动作链为日后 DNS hijack /
  route-options 等后置扩展留口，但 P0 不实现额外动作类型。
- 策略组：
  - `selector`：手动指定候选出站 tag 列表，当前选中项可经 API 切换；切换为
    确定性操作（不发起网络探测）。
  - `urltest`：对候选出站执行 measurement（复用 `nexus-planner` 的 measurement
    选择与 `nexus-connectivity` 的 `LinkProbe`），从 `MeasurementSource` 读取
    事实测量并选择延迟最低候选；组合根可注入离线确定性数据
    （`OfflineMeasurements`，E4 可复现）或真实 `LatencyProbe` 测速结果
    （§11.10 节点测速，E5 真机）。
  - `load_balance`：在多候选间按 `round-robin` 均匀分发——组内维护一个确定性游标，
    每次分流决策按 `candidate[cursor % n]` 选出站并推进游标；连续 N 次请求在 n 个候选上
    均匀分布（N>=n 时各候选命中次数差 ≤1）。离线确定性，不探测。
  - `relay`：链式级联——组的候选列表即跳序 `[A, B, ...]`，流量先经 A 再交 B（…）；
    决策结果暴露完整跳序列表 `relay_hops`，最终出口为列表最后一跳。本步为离线确定性决策
    （mock 两跳均被经过），不建真实第二跳连接；真实多跳转发后置。
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

- 真实加密代理协议栈（Vmess / Trojan / Hysteria2；Shadowsocks AEAD 见 §11.6）；
- TUN 透明代理 / Virtual Packet Interface 全局拦截：维持后置。窄 wintun C ABI 绑定
  已在 `nexus-platform-windows/src/wintun.rs` 落地（手写 `LoadLibraryW` 动态加载、
  无第三方 FFI crate、纯符号解析部分已单测），但真实 TUN 会话需管理员权限、随附
  `wintun.dll` 与真实路由表改写，无法在离线确定性 E4 内闭环——须待平台评审通过后
  以 E5 真机观察验收（ARCHITECTURE 明确 Virtual Packet Interface != TUN）；
- Clash 订阅 YAML 在线解析与自动更新；
- LoadBalance / Relay 链式策略组（多跳）；
- DNS hijack 透明拦截（仅在动作链模型中留口，不在本期实现；DNS 多 server 规则路由见 §11.5）。

#### Trojan / Hysteria2 出站依赖评审（实测 scratch，2026-09-18）

在仓库外临时 scratch crate 实测（`cargo add` + `cargo deny` + `cargo check --target
wasm32-wasip1`），结论据真实命令输出，非预判：

- **Trojan（rustls 0.23 + ring，std，不含 platform-verifier）**：CONDITIONAL / 维持后置。
  - architecture：新 adapter crate 应 portable=false、layer=outbound，nexus-proxy 不直接依赖 TLS；可隔离。
  - feature：rustls 客户端 TLS 满足 trojan over TLS；
  - license：25 个传递包，ring/rustls/rustls-webpki 均 MIT/Apache-2.0（在 allowlist）；
    scratch 树无被拒第三方 license（唯一 FAIL 是 scratch 包自身缺 license 字段，非依赖）；
  - security：`cargo deny check advisories` = ok（exit 0）；ring 有公开审计记录；
  - portability：**FAIL（实测）** `cargo check --target wasm32-wasip1` 失败（ring 无 wasm asm）；
    但 adapter 标 portable=false 即可隔离，不污染 portable-core；
  - supply-chain：25 包，rustls/ring 维护活跃。
  - 剩余边界：离线确定性 E4 需 loopback TLS + 自签 CA pinning（可能再引 rcgen 类证书依赖），
    单段闭环工作量偏大，维持后置待专门一段。
- **Hysteria2（quinn 0.11 + rustls/ring）**：FAIL / 维持后置。
  - license：**FAIL（实测）** 默认 quinn 链经 rustls-platform-verifier 拉入
    `webpki-root-certs v1.0.9` = `CDLA-Permissive-2.0`，不在 allowlist（cargo deny licenses exit 4）；
  - security：advisories ok；
  - portability：**FAIL（实测 exit 101）** socket2/quinn-udp 在 wasm32-wasip1 编译失败（无 UDP）；
  - supply-chain：88 个传递包，运行时（quinn-udp + smol）重。
  - 前置条件：需先评审是否把 CDLA-Permissive-2.0 加入 allowlist（策略决策，非本步可擅自放宽），
    且 QUIC/QUIC-UDP 与离线 E4 确定性闭环不匹配——维持后置。

#### Trojan TLS 依赖复审 + 证书方案（rustls+ring+rcgen，实测 scratch，2026-09-18）

针对离线确定性 E4 所需的 loopback TLS + 自签 CA pinning，复审 `rustls 0.23(ring,std)` +
 `rcgen 0.13`（纯 Rust、MIT）组合：

- 传递规模：32 包（无 rustls-platform-verifier / webpki-root-certs），**避免 CDLA**；
- license：`cargo deny check licenses` 无被拒第三方依赖（唯一 exit 4 是 scratch 包自身缺
  license 字段；ring/rustls/rustls-webpki/rcgen 均 MIT/Apache-2.0，在 allowlist）；
- security：`cargo deny check advisories` = ok（exit 0）；
- portability：`cargo check --target wasm32-wasip1` **FAIL（实测 exit 101，ring 需 clang/C asm）**，
  以 `nexus-outbound-trojan` 标 `portable=false` 隔离，不污染 portable-core（11 crate）；
- architecture：`policies/architecture.toml` 已声明 `nexus-outbound-trojan`
  （portable=false / layer=outbound / allowed_internal_deps=[nexus-connectivity]），
  nexus-proxy 不依赖 TLS crate（组合根装配，同 shadowsocks/vmess）；
- supply-chain：rcgen/rustls/ring 维护活跃。

**结论：rcgen 评审通过，采用 rcgen 动态自签测试证书**（不落固定 PEM fixture）。Trojan
六项评审通过，从「CONDITIONAL 后置」转为「进入实现阶段」；hysteria2 维持后置不变。

### 11.5 DNS 多 server 规则路由（multi-server DNS rule routing，2026-09-18）

在既有单 server Exit-DNS Binding 之外，把 DNS 解析推广为「多 server + 按域名规则选择本次
解析走哪个 server」（吸收 sing-box DNS rules）：

```text
配置多个 DNS server（tag + 上游地址）
  -> DNS 规则表（domain 规则，声明顺序首匹配）
  -> 命中规则：本次解析路由到规则指定 server tag
  -> 未命中：MATCH 兜底 -> default_server
  -> 该 server 注入的离线 Resolver 执行解析（P0 不接真实 UDP DNS）
```

- 配置层 YAML 新增可选 `dns:` 段：`servers: [{tag, address}]`、`rules: [{domain, server}]`、
  `default_server`；规则或兜底引用悬空 server tag 返回 `CONFIG_INVALID`。
- 域名规则匹配语义与 Exit-DNS Binding 一致：查询名等于规则 domain 或以 `.{domain}`
  结尾；首条命中即终止，其后规则不再评估。
- 路由决策可观察：本次解析选用的 server tag、命中规则 domain（无具体命中为空，走默认 server）。
- 离线确定性：P0 由 Composition Root 为每个 server 注入内存 mock Resolver；不发起真实网络。
  既有单 server `DnsRuntime`（Exit-DNS Binding、缓存、环路守卫、RDRC 负缓存、观测快照）
  行为保持不变。
- E4 场景：`scenarios/product/dns_rule_server_selection.toml`（两个 server A/B，规则把
  example.internal 指向 A、其余 MATCH 指向 B；离线注入，断言路由与解析结果）。

### 11.5.1 DNS IP-CIDR 规则与按 server 缓存隔离（P1，2026-09-18）

在多 server DNS 路由（§11.5）上扩两件事：

- **IP-CIDR 规则**：`DnsRouteRule` 除域名匹配外新增 IP-CIDR 匹配。请求携带可选的
  客户端/目标 `client_ip`；规则按声明顺序首匹配，域名规则语义不变，IP-CIDR 规则仅在
  `client_ip` 为 IPv4 且落在该前缀时命中，否则落到 `default_server`（MATCH 兜底）。
  本期只支持 IPv4 前缀（`a.b.c.d/p`，p∈0..32），手写确定性解析，不引入 IP 解析第三方依赖。
- **按 server 缓存隔离**：`MultiServerDns` 的解析缓存按 `(server_tag, name, qtype)` 分键，
  不同 server 不共享缓存。向 server A 查过的记录不会让 server B 的同名查询直接命中 A 的缓存——
  跨 server 解析必须经该 server 自己注入的 `Resolver`。这避免跨 server 结果污染。
- 既有单 server `DnsRuntime` 的缓存/环路/RDRC/Exit-DNS Binding 语义与既有三条 DNS
  冻结场景（`dns_exit_binding` / `observability_dns_cache` / `dns_rule_server_selection`）零回归。
- E4 场景：`scenarios/product/dns_ipcidr_rule.toml`。

### 11.6 OutboundAdapter 接缝与 Shadowsocks 出站（AEAD，2026-09-18）

把 `nexus-connectivity` 的出站激活从闭合的 `LinkKind {Direct, Relay}` 枚举推广为显式
`OutboundAdapter` trait：Direct / Relay / Shadowsocks 是三个**真实**出站实现。Deletion Test
（AGENTS.md §12）在此成立——Shadowsocks 是第一个带真实 AEAD 加解密的出站，与仅做可达性
探测的 Direct/Relay 构成独立变化维度（此前仅 Direct/Relay 两个 kind 标签、无第二维行为时，
该 trait 属推测性设计，已在第 1/3 步判停并推迟）。

```text
OutboundAdapter trait（nexus-connectivity，领域中立、可移植）
  -> DirectAdapter / RelayAdapter（复用既有 LinkProbe 可达性语义，行为不变）
  -> ShadowsocksAdapter（nexus-outbound-shadowsocks：AEAD 封装）
  -> Composition Root 按 tag 注册 adapter；规则选定出站 tag -> 取对应 adapter 承接流量
```

- Shadowsocks 出站：配置 `{tag, server, port, method, password}`；本期冻结 method 为
  `chacha20-ietf-poly1305`（纯 Rust AEAD，已实测 wasm32-wasip1 可编译、license/advisory
  通过）；password 经确定性 KDF（HKDF-SHA256，盐=method 标签）派生会话 key。
- 离线确定性：本步不连真实 SS 服务器，E4 场景仅断言「规则把流量导向 shadowsocks adapter」
  且「AEAD encrypt(plaintext) -> decrypt 自洽往返」；不引入真实 TCP/握手帧。
- 新出站 adapter 不削弱既有 Direct/Relay 行为；既有全部产品场景零回归。
- `nexus-outbound-shadowsocks` 为 portable=false（出站/交付层，依赖第三方 crypto），不进入
  `harness.toml [portable_core]` 清单；`OutboundAdapter` trait 本身保持领域中立、可移植。
- E4 场景：`scenarios/product/proxy_shadowsocks_adapter.toml`（配置 shadowsocks 出站，规则指向
  它；断言 selected adapter kind=shadowsocks 且 AEAD 往返一致）。

### 11.7 VMess 出站 adapter（AEAD 记录，P1，2026-09-18）

在同一 `OutboundAdapter` 接缝上新增第四个真实出站实现 VMess。Deletion Test（AGENTS.md §12）
已成立：Direct / Relay / Shadowsocks / VMess 是四个带真实行为的出站维度，新增 VMess 不改动
既有激活/选路路径，仅新增一个 adapter 实现并注册。

- VMess 出站：复用已评审入仓的 RustCrypto `chacha20poly1305` + `sha2`，**零新第三方依赖**；
  UUID（16 字节）经 SHA-256 确定性派生会话 key；本期冻结安全方法为 `chacha20-poly1305`；
  固定计数器 nonce（离线确定性，不调 getrandom）。
- 记录层：`nonce(12B) || ciphertext+tag`，与 Shadowsocks 记录一致的离线 AEAD 自洽往返；
  不追求与真实 vmess server 的线格式逐字节兼容（真实多跳/TLS 传输后置）。
- `nexus-outbound-vmess` 为 portable=false（出站/交付层，依赖第三方 crypto），不进入
  `harness.toml [portable_core]` 清单。
- E4 场景：`scenarios/product/proxy_vmess_adapter.toml`（配置 vmess 出站，规则指向它；
  断言 selected adapter kind=vmess 且 AEAD 往返一致）。

Trojan / Hysteria2 本段不交付：二者分别需要 TLS（rustls）与 QUIC（quinn），会拉入 ring
（C/汇编）与大量传递依赖树，工程量超出单段合理范围且 ring 不可 wasm 移植；评审证据见交付报告。

### 11.8 Clash 订阅节点解析（base64 URI 列表，P1，2026-09-18）

在配置层 `nexus-proxy-config` 增加订阅解析：输入一段 base64 订阅文本 → 解码 → 逐行解析
`scheme://userinfo@host:port#name` 形式的节点 URI → 产出与现有出站模型兼容的 `OutboundConfig` 列表。

- **零新第三方依赖**：手写标准 base64 解码器（标准字母表，支持 `=` 填充；Cargo.lock 无 base64 crate）。
- 本期仅映射 `ss://`（Shadowsocks；userinfo 为 base64 `method:password`）与 `vmess://`
  （VMess；userinfo 为 UUID）两种 URI，复用仓库已有两个 adapter。
- 其它协议行（trojan:// 等）**显式拒绝并记录**进 `rejected`（不致命、不静默吞掉），
  其余合法行照常产出出站；base64 非法字符/长度对齐错误返回 `CONFIG_INVALID`。
- 纯函数、离线确定性：同一份订阅文本永远产出同一 `SubscriptionParse`；不下载订阅、不发网络。
- E4 场景：`scenarios/product/proxy_clash_subscription_parse.toml`（喂含 1 ss + 1 vmess +
  1 未知协议行的固定 base64 订阅；断言解析出 2 个出站、未知协议被记录拒绝、字段正确）。

### 11.9 Trojan 出站 adapter（TLS + SHA-224 请求头，P1，2026-09-18）

在同一 `OutboundAdapter` 接缝上新增第五个真实出站实现 Trojan。Deletion Test（AGENTS.md §12）
已成立：Direct / Relay / Shadowsocks / VMess / Trojan 是五个带真实行为的出站维度；Trojan 是首个
带真实 TLS 握手（rustls 0.23 + ring）的出站，新增它不改动既有激活/选路路径。

- 协议线格式：客户端先完成 TLS 握手（SNI），再在 TLS 内发送请求头
  `hex(SHA-224(password)) | CRLF | ATYP+DST.ADDR+DST.PORT | CRLF`，其后为双向透明字节中继。
- 密码校验：server 端计算并比对首行 `hex(SHA-224(password))`；不匹配即结构化
  `AUTH_DENIED` 拒绝并中止中继（不回明文原因、不泄露密码）。
- TLS 材料：rustls 0.23(ring,std) + rcgen 动态自签测试证书；客户端用自定义
  `CertificateVerifier` 把服务端证书公钥 pin 住（不依赖系统根、不拉 webpki-root-certs，避开 CDLA）。
- 离线确定性：loopback 127.0.0.1 同一进程内起 TLS server + client，rcgen 自签 CA，
  不连公网；server/客户端任务 join 回收（结构化并发，不丢 JoinHandle）。
- 本期冻结边界：不做 WebSocket/gRPC 伪装、不做 UDP、不做多路复用；P0 仅 TCP 透明中继。
- `nexus-outbound-trojan` 为 portable=false（出站/交付层，ring 需 C/asm，wasm 不可编译），
  不进入 `harness.toml [portable_core]` 清单；`OutboundAdapter` trait 本身保持可移植。
- 错误面：`AUTH_DENIED` / `INVALID_HEADER` / `TLS` / `IO`，结构化，不以日志文本代替类型。
- E4 场景：
  - `scenarios/product/proxy_trojan_adapter.toml`（loopback TLS，正确密码，握手通过、请求头送达、payload 往返）；
  - `scenarios/product/proxy_trojan_auth_rejected.toml`（错密码 → server 结构化 `AUTH_DENIED`，无中继）。

#### 11.9.1 真实 TLS 连接参数（skip-cert-verify + ALPN + SNI，2026-09-18）

在离线公钥 pin 模式之外，增加面向真实 trojan 服务器的客户端 TLS 参数（零新依赖，全部用
rustls 0.23 内置 dangerous API 与 ALPN，不引入新 crate）：

- **skip-cert-verify**：`client_config_dangerous_skip_verify(alpn)` 用 rustls
  `danger::ServerCertVerifier` 自定义实现跳过服务端证书链校验（用于自签/内网 trojan 节点）；
  仍保留 TLS 握手签名校验（不把整个握手降级为明文）。错误面保持结构化 `TLS`。
- **ALPN**：`with_alpn_protocols(...)` 下发客户端 ALPN 列表（如 `h2` / `http/1.1`）；
  协商结果可观测（`negotiated_alpn`）。
- **SNI**：由调用方以 `ServerName` 传入（example/E5 层），本 crate 不硬编码域名。
- 离线公钥 pin 模式（§11.9 原有 `client_config`）保持不变，既有两条 E4 零回归。
- E4 场景：`scenarios/product/proxy_trojan_real_tls_params.toml`——loopback 起配置了
  ALPN 列表的 TLS server，客户端用 skip-verify 连接，确定性断言 ALPN 协商命中预期、
  skip 模式握手通过、认证后一段数据往返成功。
- E5（非 E4，不进 scenarios/product/）：`apps/nexus/examples/trojan_real_server.rs`
  为真实节点测试脚手架，CLI/环境变量参数化 `--server/--password/--sni/--target/--alpn/--skip-verify`，
  默认占位、不硬编码任何真实密码。

#### 11.9.2 请求头格式兼容模式（Standard / Singbox，2026-09-18）

不同服务器实现对 trojan 请求头「地址行」前是否带命令字节存在差异：

- **Standard（trojan-gfw 规范，默认）**：`hex(SHA-224(pwd)) | CRLF | ATYP+ADDR+PORT | CRLF`，
  无命令字节。这是 trojan 规范原文，也是本 crate 既有行为，**默认值保持 Standard，不翻转**。
- **Singbox（sing-box 系服务器变体）**：`hex(SHA-224(pwd)) | CRLF | CMD(0x01 CONNECT) | ATYP+ADDR+PORT | CRLF`，
  ATYP 前多一个 `0x01` 命令字节。实测某 sing-box 系机场要求该格式，否则被 fallback 到伪装 nginx
  返回 HTTP 400；带 `0x01` 命令字节才得正常中继。

- **选择机制**：`TrojanHeaderFormat::{Standard, Singbox}`，客户端编码与本地 server 解析成对使用；
  真实节点由配置 / E5 脚手架 `--format` 开关选择。默认 Standard 的理由：trojan-gfw 规范是事实标准，
  翻转默认会要求把既有 3 条冻结 E4 改写为 Singbox（构成 requirement-change），故保持默认并显式切换。
- **失败语义**：格式不匹配时 server 解析出 `INVALID_HEADER`（不会被误判为 `AUTH_DENIED`）；
  密码仍按首行 hash 校验，错误面不变。
- 既有 3 条 trojan E4（adapter / auth-rejected / real-tls-params）继续走 Standard，零回归。
- E4 场景：`scenarios/product/proxy_trojan_header_format.toml`——同一 example 内两条断言：
  (a) Singbox：本地 server 期待命令字节，客户端切 Singbox → 握手+认证+往返 PASS；
  (b) Standard 回归：本地 server 用标准解析器，客户端切 Standard → 往返 PASS。
- E5：`trojan_real_server.rs` 增加 `--format standard|singbox`（默认 standard），供真实节点复测。

#### 11.9.3 Trojan 节点配置项（配置层，2026-09-18）

`nexus-proxy-config` 的 `OutboundKind` 增加 `Trojan`；`OutboundConfig` 在既有 `tag/kind/locator/`
`method/password` 之上增加 trojan 节点字段：

- `password: Option<String>`（trojan 必填，复用既有字段）；
- `alpn: Option<Vec<String>>`（ALPN 协议列表，如 `[h2, http/1.1]`，可空）；
- `skip_cert_verify: Option<bool>`（是否跳过服务端证书链校验，默认 false）；
- `header_format: Option<String>`（`"standard"` | `"singbox"`，缺省即 `"standard"`，§11.9.2）。

校验（`kind: trojan` 时）：
- `password` 必填且非空、`locator` 必填（`host:port`）；缺失 → `CONFIG_INVALID`；
- `header_format` 若给值，必须是 `standard` 或 `singbox`，其它值 → `CONFIG_INVALID`；
- 未给 `header_format` 时按 `standard` 解释（不翻转既有默认）。

真实节点样例（密码一律占位 `CHANGE_ME`，严禁真实凭据入库）：
`examples/configs/trojan_nodes.example.yaml`（日本-TY-3 / 日本-OS-3 两节点，
server 域名/端口/ALPN/udp/skip-cert-verify 可用真实公开值，密码占位）。

E4 场景：`scenarios/product/proxy_trojan_node_config.toml`——喂含两个 trojan 节点（Singbox +
skip-verify + alpn）的 YAML，断言解析出 2 个 `OutboundConfig`、`kind=trojan`、`alpn=[h2,http/1.1]`、
`skip_cert_verify=true`、`header_format=singbox`；再喂一个缺 `password` 的 trojan 节点 → `CONFIG_INVALID`。

### 11.6.1 Shadowsocks 真实 TCP 会话闭环（P1，2026-09-18）

把 Shadowsocks 出站从「离线 AEAD 自洽往返」提升为**真实 TCP 会话闭环**：同一进程内
loopback 127.0.0.1 起 SS server 端 + 客户端，走真实 `std::net::TcpStream`（blocking，
与仓库既有 real-host/relay E4 同一 loopback 形态）+ 真实 AEAD 封装，确定性、离线、可复现。
本步不连公网。

会话语义：

- 方向分离：c2s 与 s2c 使用经 HKDF 不同 info 标签派生的两把独立 key，避免同 key nonce 复用；
  每方向 nonce 自 0 固定计数递增（不调 getrandom）。
- 记录帧：`u32 BE length || AEAD record`，record = `nonce(12B) || ciphertext+tag`。
- 客户端首帧为加密 request header：`[ATYP(1)=1 IPv4 | 3 domain] | addr | port(2 BE)`；
  server 端解密并解析目标地址后，真实 `TcpStream::connect` 到该 loopback 目标并中继双向字节。
- 离线可复现：目标为另一个 loopback echo 端；断言握手成功、目标地址被 server 正确解析、
  一段 payload 往返被正确加解密（client->server 加密、server->echo、echo->server 明文、
  server->client 加密、client 解密比对）。
- 既有离线自洽 E4（`product.proxy-shadowsocks-adapter`）行为不变、不回归。
- E4 场景：`scenarios/product/proxy_shadowsocks_real_tcp.toml`。

### 11.10 节点测速（real node speedtest，2026-09-18）

在 urltest 策略组之外，提供对候选出站的**真实延迟测量**能力：组合根注入
`LatencyProbe`（真实 `std::net::TcpStream::connect_timeout`，非 portable 层），
对配置内候选出站逐一探测目标并产出 `LinkMeasurement` 事实测量；测量结果写入
`MeasurementTable` 并可被 urltest 经 `MeasurementSource` 消费（决策逻辑零改动）。

- 命令：`nexusd proxy speedtest --json` —— 对全部候选出站批量测速，按 RTT
  升序输出结果表。
- 指标：`latency_ms`（±毫秒，未测得为 null）、`status`（`ok` / `timeout` /
  `unreachable` / `dns_failed`）、`probe_kind`（`tcp` / `http204`）、target、时间戳。
  `tcp`：仅建连级 RTT（connect_timeout）。`http204`：TCP 建连后发送单行明文 GET（P0 不做 TLS，target.scheme==https 直接记为 unreachable），
  `GET {path} HTTP/1.1` 等待响应首行 `204 No Content`，计时覆盖建连 +
  请求发送 + 响应首字返回；非 204 响应或读取超时记为 `unreachable`。
- 默认探测目标：`http://www.gstatic.com/generate_204`（Clash 惯例）；目标仅
  http/https、默认公网、超时上限 5s（可配）。
- 安全边界：`tcp` 只做建连级延迟探测；`http204` 只发单行 GET、只读响应首行，
  不做下载吞吐测速（无 throughput 指标）；单节点探测失败以 `status` 记录（非致命），
  不中断批量。
- 确定性策略：E4 场景注入 `OfflineMeasurements`（排序/选择可复现）；
  E5 以 loopback 真实 TCP 服务测真实 `LatencyProbe`（本机确定性闭环）。
- 配置：YAML `proxy:` 下可选 `speedtest: {target, timeout_ms, probe_kind}`；
  缺失走默认值；非法字段返回 `CONFIG_INVALID`。
- E4 场景：`proxy_speedtest.toml`（注入 mock 三候选 tcp，断言排序与 JSON 形态）、
  `proxy_speedtest_loopback.toml`（loopback 真 TCP，断言 latency_ms 有值且低于阈值）、
  `proxy_speedtest_http204.toml`（注入 mock 三候选 http204，断言 probe_kind=http204 与排序）、
  `proxy_speedtest_http204_loopback.toml`（loopback 真 HTTP/204 服务，断言 204 路径 ok）。

### 11.11 GEOIP / GEOSITE / rule-providers（规则数据注入，2026-09-18）

在 §11.1 冻结的静态规则表之外，为规则引擎引入三类**编译期数据注入**的匹配能力：
GEOIP 国家库、GEOSITE 域名分类清单、rule-providers 本地规则集。数据文件由组合根
（apps/nexus）加载后注入决策内核，`nexus-proxy` 保持纯决策零 I/O（匹配数据全部在
编译期展开为静态 `Matcher`）。

- GEOIP：`kind: geoip, match: "<国家码>"`（两字母，如 `CN`）；组合根注入
  `geoip` 库（国家码 → CIDR 列表，自研紧凑二进制 `geoip.nex`，零第三方依赖）；
  编译期把国家码展开为 CIDR 列表（`Matcher::GeoIp`）；国家码不存在于注入库 →
  `CONFIG_INVALID`（不静默降级为不匹配）。
- GEOSITE：`kind: geosite, match: "<分类>"`（如 `cn`）；组合根注入分类清单
  （分类 → 域名后缀列表，纯文本 `geosite/<cat>.txt`，每行一个域名）；编译期展开
  为域名后缀集（`Matcher::GeoSite`，后缀匹配语义与 DOMAIN-SUFFIX 一致）；
  分类不存在 → `CONFIG_INVALID`。
- rule-providers：配置 `rule-providers: { <name>: { behavior: "domain"|"ipcidr"|
  "classical", path: <本地文件> } }`；规则引用 `kind: rule_set, match: "<name>"`；
  编译期把 provider 文件内容展开为内联匹配器（`Matcher::RuleSet`，保持 provider 内
  声明顺序首匹配）：
  - `domain`：每行一个域名（后缀匹配语义同 GEOSITE）；
  - `ipcidr`：每行一个 CIDR（复用 `IpPrefix` 手写解析）；
  - `classical`：每行 `<KIND>,<pattern>`（复用现有全部 RuleKind，无 policy 行，
    action 由引用规则提供）。
  provider 名不存在 / behavior 非法 / path 缺失 → `CONFIG_INVALID`。
- no-resolve：`RuleConfig` 新增可选 `no_resolve: bool`（默认 false）；IP 类规则对
  未解析域名流量不命中的语义不变（`FlowTarget.ip=None` 不匹配），标志为编译期属性并
  进入分流决策可观察字段（真实解析差异由数据面 §11.4 承接）。
- 可观察：分流决策命中规则类型扩展为 `geoip` / `geosite` / `rule_set`，并携带
  国家码 / 分类 / provider 名（`matched_rule` 即规则名，类型字段区分）。
- 离线确定性：注入数据全部为本地文件/内嵌样本，E4 场景可复现；在线拉取与
  真实数据生成工具见 §11.12（2026-09-19 已实现）。
- E4 场景：`proxy_geoip_rule.toml` / `proxy_geosite_rule.toml` /
  `proxy_rule_set.toml` / `proxy_rule_invalid.toml`。


### 11.12 在线规则数据（rule-providers 拉取与数据生成工具，2026-09-19）

§11.11 的注入数据由离线确定性闭环升级为可消费在线规则集：rule-providers 支持
在线 `url` 源（缓存 + 刷新），并落地 `geoip.nex` 二进制格式与生成工具。决策内核
不变——`nexus-proxy` 保持纯决策零 I/O，拉取与格式解析全部发生在数据加载层
（组合根 / 解析器）。

#### A. rule-providers 在线拉取

- 配置：`RuleProviderConfig` 新增可选 `url: Option<String>`（在线源）与
  `refresh_interval_secs: Option<u64>`（刷新间隔，默认 86400，必须 ≥ 1）。
  `path` 语义升级为**本地缓存落盘位置**；仅配置 `path`（无 `url`）时维持纯本地
  加载（§11.11 语义不变）。
- `ProviderFetcher` trait（`nexus-proxy` 定义，纯接口零 I/O）：
  `load(&mut self, cfg: &RuleProviderConfig) -> Result<FetchedProvider, String>`；
  `FetchedProvider { lines: Vec<String>, source: ProviderSource }`；
  `ProviderSource::{Local, Cached, Online}`——命中来源进入可观察输出。
- 组合根实现（apps/nexus）：`FileProviderFetcher`（仅本地，无 url 路径）；
  `CachedHttpProviderFetcher`（有 url 时：本地缓存存在且未过期 → 直接用缓存；
  过期/缺失 → HTTP GET 拉取并写回缓存；拉取失败 → 回退过期缓存并标记
  `Cached`；无任何可用数据 → 结构化失败）。
- 数据流：组合根遍历 `config.rule_providers` → `fetcher.load` → 组装
  `RuleData.providers` → `RuleEngine::with_data`（§11.11 编译期展开不变）。
- 失败语义：在线拉取失败且无可用缓存 → `RULE_PROVIDER_FETCH_FAILED`
  （结构化错误，不静默降级）；其余校验沿用 §11.11。
- 确定性策略：E4 注入 mock fetcher（固定内容，source 可复现）；E5 以本地
  HTTP server 提供 provider 文件驱动真实 `CachedHttpProviderFetcher`
  （离线确定性闭环，不经公网）。
- E4 场景：`proxy_rule_provider_fetch.toml`。

#### B. `geoip.nex` 二进制格式与生成工具

- 格式 v1（小端，无第三方依赖）：`magic "NXGEOIP\0"`（8 字节）+ `u32` 国家数 N
  + N 项依次：`[code: 2 字节 ASCII] + [cidr_count: u32] + cidr_count ×
  [base: u32（IPv4 地址按网络字节序存为小端 u32）] + cidr_count × [prefix: u8]`。
  文件可顺序遍历解析；非法 magic / 截断 / 非法 CIDR → 结构化解析错误。
- 解析器：`nexus-proxy::geoip_nex::parse(&[u8]) -> Result<HashMap<String, Vec<String>>,
  ParseError>`（输出 CIDR 文本，与 `RuleData.geoip` 兼容；纯函数零 I/O）。
- 生成工具：apps/nexus example `geoip_nex_build`：输入 JSON 中间格式
  （`{"CN":["1.0.1.0/24", ...], ...}`）→ 输出 `geoip.nex` 文件；CIDR 非法 → 拒绝
  并指明行。公开数据源适配（GeoLite2 / ip2region 等）为 P1 源插件，不绑定许可。
- 确定性策略：E2 单测（roundtrip / 截断 / 坏 magic）+ E4 场景 roundtrip：
  内存构造 → 解析 → 注入 `RuleData` → 路由断言。
- E4 场景：`geoip_nex_roundtrip.toml`。

### 11.13 `geosite.nex` 二进制格式与生成工具（2026-09-20）

§11.11 的 GEOSITE 注入数据由纯文本 `geosite/<cat>.txt` 升级为可消费的
`geosite.nex` 二进制格式与生成工具——与 §11.12 B（geoip.nex）对称。决策内核
不变——`nexus-proxy` 保持纯决策零 I/O，格式解析全部发生在数据加载层。

- 格式 v1（小端，无第三方依赖）：
  `magic "NXGEOSITE\0"`（10 字节）+ `u32` 分类数 N + N 项依次：
  `[name_len: u32][name: UTF-8 bytes]` + `[domain_count: u32]` +
  `domain_count × [domain_len: u32][domain: UTF-8 bytes]`。
  文件可顺序遍历解析；非法 magic / 截断 / 非 UTF-8 → 结构化解析错误。
- 解析器：`nexus-proxy::geosite_nex::parse(&[u8]) -> Result<HashMap<String,
  Vec<String>>, ParseError>`（输出分类 → 域名列表，与 `RuleData.geosite` 兼容；
  纯函数零 I/O）。
- 生成工具：apps/nexus example `geosite_nex_build`：输入 JSON 中间格式
  （`{"cn":["example.cn", ...], ...}`）→ 输出 `geosite.nex` 文件；分类重复 /
  非字符串域名 → 拒绝并指明条目。
- 确定性策略：E2 单测（roundtrip / 截断 / 坏 magic / 非 UTF-8 / 分类重复）+
  E4 场景 roundtrip：内存构造 → 解析 → 注入 `RuleData.geosite` → 路由断言。
- E4 场景：`geosite_nex_roundtrip.toml`。

### 11.3 失败语义

```text
CONFIG_INVALID              YAML 解析失败 / 规则表无 MATCH 兜底 / 出站 tag 悬空
NO_MATCH_RULE               规则表缺 MATCH 兜底且流量未命中任何具体规则
OUTBOUND_TAG_UNRESOLVED     动作链选定的出站或策略组 tag 不存在
SELECTOR_EMPTY              selector 策略组候选列表为空
URLTEST_NO_VALID_CANDIDATE  urltest 组所有候选均无有效 measurement
DNS_SERVER_UNRESOLVED       DNS 规则或 MATCH 兜底引用的 server tag 未定义
OUTBOUND_ADAPTER_UNAVAILABLE 选定出站 tag 无已注册的 OutboundAdapter 承接
```

## 12. 虚拟子网组网（Virtual Subnet Networking）

在既有远程资源访问闭环（§6）和代理内核（§11）之外，新增第三条产品线：
**虚拟子网组网**（参考 EasyTier / WireGuard 组网模式）。该产品线不修改既有
产品线的语义，不污染已冻结的 E4 场景。

核心概念：

```text
VirtualSubnet: 一个虚拟三层网段，所有成员节点在同一个虚拟 IP CIDR 内。
VirtualIp:    每个节点在虚拟子网中的虚拟 IP（静态分配或由子网分配器分配）。
TunnelPeer:   对端节点的物理端点（locator + 虚拟 IP 映射）。
PacketTunnel: 数据面循环：VPI 读 IP 包 → 封装 → 发给对端；
              对端收到 → 解封装 → 写回 VPI。
```

### 12.1 P0 最小闭环

```text
节点 A：
  创建 VPI 接口，分配虚拟 IP 10.0.0.1/24
  注册 Peer B（虚拟 IP 10.0.0.2，物理 locator 由配置注入）
  启动 PacketTunnel 数据面循环

节点 B：
  创建 VPI 接口，分配虚拟 IP 10.0.0.2/24
  注册 Peer A（虚拟 IP 10.0.0.1，物理 locator 由配置注入）
  启动 PacketTunnel 数据面循环

数据面：
  A 的 VPI 收到目的为 10.0.0.2 的包
    → 封装为隧道帧（源/目虚拟 IP 标记）
    → 通过 PacketCarrier 发给 B 的物理 locator
    → B 的 PacketCarrier 收到帧
    → 解封装提取原始 IP 包
    → 写入 B 的 VPI
    → B 操作系统处理后回包，反向同理
```

### 12.2 用户可观察语义

- 节点启动后声明所属 VirtualSubnet（CIDR + 自身 VirtualIp）。
- 每个 Peer 的隧道状态可观察：Disconnected / Handshaking / Connected / Failed。
- 数据面统计可观察：每 Peer 的上行/下行字节数、丢包数、重传数（P0 只统计计数）。
- 隧道建立失败返回结构化错误（`PEER_UNREACHABLE` / `AUTH_FAILED` / `INVALID_SUBNET`）。

### 12.3 P0 明确不做

- 真实 UDP NAT 打洞（P0 用 Direct / Relay 已有链路激活策略）。
- 多节点网状拓扑自动路由（P0 只支持点对点直连，路由表静态配置）。
- 子网跨子网路由（P0 只支持同一 CIDR 内的节点互通）。
- WireGuard 风格 Noise 协议加密（P0 用 Shadowsocks 风格 AEAD 或明文，加密后置）。
- 自动 IP 分配（P0 静态配置）。
- 真实 TUN 驱动集成（P0 用注入的内存 VPI 做离线确定性 E4，真实驱动是 E5）。

### 12.4 失败语义

```text
INVALID_VIRTUAL_IP          虚拟 IP 不在子网 CIDR 范围内
PEER_NOT_FOUND              目标虚拟 IP 无对应 Peer 注册
TUNNEL_HANDSHAKE_FAILED     隧道握手失败
ENCAPSULATION_ERROR         包封装失败
DECAPSULATION_ERROR         包解封装失败
```
