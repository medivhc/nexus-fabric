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

## 2. Network / InternetAccess {#network}

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

## 4. Workspace {#workspace}

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
  - **Native API 通道**：`NativeApiWorkspaceAccess` 提供结构化读写（`read_file` /
    `write_file` / `list_dir` / `delete`），写入操作暂存于 WorkingSet（内存 HashMap），
    不立即落 Commit；`commit` 时把 WorkingSet 暂存内容与删除集合落成新 Commit，
    Head 前进。读取操作合并 WorkingSet 与当前 Head Manifest 的内容。无文件系统依赖，
    可在 WASM / 嵌入式等无 FS 环境运行。
  - **Materialized Directory 通道**：`MaterializedDirectoryAccess` 把 Workspace 当前
    Head 的全部文件物化到本地临时目录；`read_file` / `write_file` / `list_dir` /
    `delete` 直接操作本地文件系统；`commit` 时扫描本地目录与上次快照的差异，构建
    ChangeSet（新增 / 修改 / 删除）提交回 Workspace，Head 前进并持久化。
  - 两个通道都保持产品语义：Commit DAG / Head Set / Manifest 始终完整；
    `product_semantics_preserved = true`。
  - 错误语义：读取不存在的文件返回 `WorkspaceError::NotFound { path }`；
    删除不存在的路径返回 `WorkspaceError::NotFound { path }`。

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

## 6. 远程资源访问（Remote Resource Access） {#remote}

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
- 链路加密（link encryption，WireGuard 风格，`nexus-connectivity::encryption`）：每个节点持有长期 X25519 密钥对；Direct 与 Relay 通道在建链后、承载业务帧之前必须完成一次握手——握手双方交换公钥并经 X25519 ECDH + HKDF-SHA256 派生一次性 `SessionKey`；**握手成功前不允许发送任何业务帧**，会话密钥每次握手重新派生、不复用长期私钥。数据帧使用 AEAD（ChaCha20Poly1305）加密并携带显式 64 位序号；接收方经滑动窗口做防重放校验，序号过旧或重复一律拒绝，且密文 tag 校验失败即整帧丢弃（不暴露明文）。P0 先交付全内存 mock 骨架与 E4 闭环，真实线上传输、握手重传与密钥周期轮换留 TODO。

## 7. Session 语义 {#session}

Session 使用双轨状态：

```text
LifecyclePhase:
Allocating | Active | Draining | Disposed

TerminalOutcome:
Unfinished | Completed | Failed | Cancelled
```

Completed/Failed/Cancelled 只能提交一次；资源清理可以在 Outcome 确定后继续，最终 LifecyclePhase 到达 Disposed。

## 8. 跨平台产品语义 {#cross-platform}

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

## 9. 可观察性 {#9-observability}

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

### 9.1 CLI 前端接线与双输出（2026-09-18 冻结；2026-09-20 requirement-change：thin-client） {#cli}

- `nexus` CLI 为 **thin-client**：观察命令经 `--addr`（默认 `127.0.0.1:18080`）查询
  `nexusd serve` 的 HTTP LocalAPI，数据只来自 daemon 的 `observability` 快照
  （与 nexusd 同源，CLI 不复制领域逻辑）。
- 已实现 daemon 路由的 7 个命令（`status` / `dns status` / `dns cache` / `session watch` /
  `plan explain` / `connectivity status` / `platform capabilities`）：查询 daemon 快照并原样渲染；
  daemon 未运行 / 连接失败 → 结构化 `DAEMON_UNREACHABLE`（`--json`，exit 0）。
- 暂无 daemon 路由的 10 个命令（`dns resolve` / `dns providers` / `connectivity candidates` /
  `connectivity probe` / `connectivity links` / `workspace heads` / `workspace conflicts` /
  `workspace cache` / `compute jobs` / `diagnose`）：CLI 本地合成显式 `UNSUPPORTED` FAIL JSON
  （与 nexusd 兜底同形），**不回退到进程内 observability**——领域未就绪即显式拒绝，
  禁止静默降级；对应命令在 `nexusd <verb> --json` 进程内路径仍可用。
- `nexus run <resource>` 保持进程内 SDK 路径（LocalAPI 无对应路由）。
- 全局 `--json` 开关：`--json` 模式把 daemon / 本地 JSON 原样打到 stdout（单行 JSON，stderr 静默）；
  默认模式渲染人读文本视图（JSON 的字段投影）。
- exit 语义对齐 nexusd：用法/解析错误（缺参、未知命令）exit 2 并打印 usage；
  业务成功 exit 0；结构化失败（`UNSUPPORTED` / `DAEMON_UNREACHABLE` / 领域拒绝）输出
  `verdict=FAIL` JSON 且 exit 0（请求已被处理）。

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

### 11.2 P0 明确不做（不得写进本期 expectation）

以下为 P1+ 展望，本期契约不承诺、不冻结为 expectation：

- 真实加密代理协议栈（Vmess / Trojan / Hysteria2；Shadowsocks AEAD 见 §11.6）；
- TUN 透明代理 / Virtual Packet Interface 全局拦截：已转 §11.18 落地（portable
  IP 包解析 + 规则路由 + NAT 决策 E4 离线闭环；真实 wintun adapter 开卡与收发为 E5）。
  窄 wintun C ABI 绑定（手写 LoadLibraryW、无第三方 FFI、纯符号解析单测）与
  WintunVpiAdapter 复用 §12.29；真实双向字节中继回写、路由表改写、IPv6、DNS 劫持
  仍为 §11.18 冻结边界（下批）；
- Clash 订阅节点在线拉取与热生效（已移出本冻结清单，本批次交付，见 §11.17）；
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

### 11.5 DNS 多 server 规则路由（multi-server DNS rule routing，2026-09-18） {#11-dns}

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

### 11.5.1 DNS IP-CIDR 规则与按 server 缓存隔离（P1，2026-09-18） {#11-dns-ipcidr}

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

### 11.6 OutboundAdapter 接缝与 Shadowsocks 出站（AEAD，2026-09-18） {#11-outbound-adapter}

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

### 11.6.1 Shadowsocks 真实 TCP 会话闭环（P1，2026-09-18） {#11-shadowsocks-real-tcp}

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

### 11.7 VMess 出站 adapter（AEAD 记录，P1，2026-09-18） {#11-vmess}

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

### 11.8 Clash 订阅节点解析（base64 URI 列表，P1，2026-09-18） {#11-clash-subscription-parse}

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

### 11.9 Trojan 出站 adapter（TLS + SHA-224 请求头，P1，2026-09-18） {#11-trojan}

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

#### 11.9.1 真实 TLS 连接参数（skip-cert-verify + ALPN + SNI，2026-09-18） {#11-trojan-real-tls}

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

#### 11.9.2 请求头格式（Standard = trojan-gfw 官方线上格式，含 CMD 字节；2026-09-25 修订） {#11-trojan-header-format}

> 2026-09-25 requirement-change 修订：真机 E5（2026-09-24，真实机场节点
> hk-1.tr202613.com:465，skip_cert_verify，alpn=[h2,http/1.1]）实证——此前把「Standard」
> 误读为「无命令字节」的规范原文，实际上 trojan-gfw / sing-box / xray 线上服务端统一要求
> **地址行前必须带 `CMD(0x01 CONNECT)` 命令字节**。旧 Standard 缺 CMD 字节时所有 HTTP 出站
> 被目标 nginx 返 400、HTTPS 000；补上 CMD 字节后 google/gstatic generate_204 立即 204。
> 旧 E4 是「自洽闭环」（本地 server 用同逻辑 parse），从未与真实服务端互操作，故掩盖了该缺陷。

标准 trojan 请求头字节布局（**Standard，默认**，与 trojan-gfw 官方线上规范一致）：

```text
hex(SHA-224(password)) | CRLF | CMD(0x01 CONNECT) | ATYP | ADDR | PORT(BE) | CRLF
```

- **Standard（默认）**：含 `CMD(0x01 CONNECT)` 命令字节。这是 trojan-gfw 规范原文，也是
  trojan-gfw / sing-box / xray 服务端实际要求的线上格式。默认值保持 Standard，不翻转。
- **Singbox**：与 Standard **字节完全等价**（同样含 `0x01` CMD 字节），作为既有配置字符串的
  兼容别名保留——历史配置里写过 `header_format: singbox` 的节点无需改动；两者编码/解析输出
  逐字节相同。

- **字节级不变量**：`encode_request_fmt(pwd, target, Standard)` 在 `hex(56B) + CRLF(2B)`
  之后（0-based offset 58）必须紧接 `0x01`（CMD=CONNECT），其后才是 ATYP；即 IPv4 目标时
  offset 58=`0x01`(CMD)、offset 59=`0x01`(ATYP=IPv4)。`encode(Standard) == encode(Singbox)`
  对同一目标恒成立。
- **选择机制**：`TrojanHeaderFormat::{Standard, Singbox}`，客户端编码与本地 server 解析成对使用；
  真实节点由配置 / E5 脚手架 `--format` 开关选择。两变体字节等价，选择不改变线上行为，仅为
  配置兼容。
- **失败语义**：server 按「先 strip 前导 `0x01` CMD 再读 ATYP」解析；命令字节缺失/非法或地址行
  长度不符 → `INVALID_HEADER`（不会被误判为 `AUTH_DENIED`）；密码仍按首行 hash 校验，错误面不变。
- 既有 3 条 trojan E4（adapter / auth-rejected / real-tls-params）继续走 Standard——现在 Standard
  自带 CMD 字节，本地 `parse_request` 同步 strip 它，端到端自洽，零回归。
- E4 场景：`scenarios/product/proxy_trojan_header_format.toml`——同一 example 内：
  (a) 往返：本地 server 与 client 同格式 → 握手+认证+往返 PASS；
  (b) **字节级互操作断言**：`encode(Standard)` 在 hex+CRLF 后紧接 `0x01` CMD 字节，且
  `encode(Standard)` 与 `encode(Singbox)` 逐字节相同（锁定官方线上字节布局，防止再退化为无 CMD）。
- E5：`trojan_real_server.rs` 保留 `--format standard|singbox`（默认 standard），供真实节点复测。

#### 11.9.3 Trojan 节点配置项（配置层，2026-09-18） {#11-trojan-node-config}

`nexus-proxy-config` 的 `OutboundKind` 增加 `Trojan`；`OutboundConfig` 在既有 `tag/kind/locator/`
`method/password` 之上增加 trojan 节点字段：

- `password: Option<String>`（trojan 必填，复用既有字段）；
- `alpn: Option<Vec<String>>`（ALPN 协议列表，如 `[h2, http/1.1]`，可空）；
- `skip_cert_verify: Option<bool>`（是否跳过服务端证书链校验，默认 false）；
- `header_format: Option<String>`（`"standard"` | `"singbox"`，缺省即 `"standard"`，§11.9.2；两值字节等价，仅为配置兼容别名）。

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

### 11.10 节点测速（real node speedtest，2026-09-18） {#11-speedtest}

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

### 11.11 GEOIP / GEOSITE / rule-providers（规则数据注入，2026-09-18） {#11-geoip-geosite-providers}

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


### 11.12 在线规则数据（rule-providers 拉取与数据生成工具，2026-09-19） {#11-rule-providers-online}

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

### 11.13 `geosite.nex` 二进制格式与生成工具（2026-09-20） {#11-geosite-nex}

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

### 11.14 rule-provider TLS 在线拉取（https，2026-09-20） {#11-rule-provider-https}

§11.12 A 的 `CachedHttpProviderFetcher` 仅支持 `http://` 明文；本节升级为支持
`https://`（TLS 1.3，rustls），使真实 Clash 订阅的 https rule-provider 可消费。
决策内核不变——`nexus-proxy` 保持纯决策零 I/O；`ProviderFetcher` trait 与
`ProviderSource::{Local, Cached, Online}` 语义完全不变（TLS 命中仍为 `Online`）。

- 配置：`url` 协议白名单由 `http://` 扩展为 `http:// | https://`；其余校验
  （`refresh_interval_secs ≥ 1` 等）不变。
- 实现（组合根 apps/nexus）：`CachedHttpProviderFetcher` 按 `url` 协议分流——
  `http://` 走既有明文 GET（不变）；`https://` 走 rustls TLS 1.3 客户端 GET，
  默认信任 Mozilla 根（`webpki-roots`），测试/自签场景可注入自定义 root store
  （`with_tls_roots`）。拉取 → 写缓存 → `Online`；缓存新鲜 → `Cached`；拉取失败
  → 回退过期缓存 → `Cached`；无任何可用数据 → 结构化失败（与 §11.12 一致，
  `RULE_PROVIDER_FETCH_FAILED`，不静默降级）。
- 失败语义：TLS 握手失败 / 证书校验失败 / 域名校验失败 → 结构化错误
  （`RULE_PROVIDER_FETCH_FAILED`），不静默降级，不写坏缓存。
- 确定性策略：E5 本地 TLS server（rcgen 自签证书 + rustls server）驱动真实
  `CachedHttpProviderFetcher`（离线确定性闭环，不经公网）；断言 `source=Online`、
  行内容一致、缓存已落盘。
- E5 场景：`proxy_rule_provider_fetch_https.toml`。

### 11.15 公开数据源插件（ip2region TXT → `geoip.nex`，2026-09-20） {#11-public-datasource-plugin}

§11.12 B 标注"公开数据源适配（GeoLite2 / ip2region 等）为 P1 源插件，不绑定许可"。
本节落地首期源插件：**ip2region TXT 文本格式 → `geoip.nex`**（数据文件由用户自行
获取，插件不绑定任何数据源的许可/下载流程）。

- 输入：ip2region 公开 TXT（UTF-8），每行
  `start_ip|end_ip|country|province|city|isp`（竖线分隔，7 列取前 2 列 IP 与第 3 列
  国家）；空行 / `#` 注释行忽略；国家字段为 `0` / `内网IP` / `未分配` 或无法识别的
  文本 → 跳过并计入 `skipped`（可观察，不静默丢弃）。
- 国家映射：内置常用中文国家名 → ISO 3166-1 alpha-2 表（约 60 条，覆盖常见流量
  国家）；映射表是纯数据，随源插件维护。
- 区间转 CIDR：`nexus-proxy::geoip_nex::cidrs_from_range(start, end) -> Vec<(u32, u8)>`
  （贪婪 2^n 拆分，纯函数零 I/O）——输出为 §11.12 B 兼容的 CIDR（base u32 + prefix）。
- 工具：apps/nexus example `geoip_source_ip2region` 双模式：
  - `geoip_source_ip2region <input.txt> <output.nex>`：真实文件模式，stdout
    `ok <categories> <cidrs> <skipped>`；
  - `geoip_source_ip2region --json`：内置确定性样本 → 生成 → 解析回读 → JSON
    （供 E4 场景断言）。
- 确定性策略：E2 单测（`cidrs_from_range` 边界：单 IP / 整段 / 跨 /8 边界 /
  `parse_ipv4` 非法输入）+ E4 场景（内置样本 → 工具 → roundtrip 解析 → 断言
  CN/US 的 CIDR 与 skipped 计数）。
- 明确不做（后续批次）：ip2region xdb 二进制、GeoLite2 mmdb/CSV、数据自动下载。
- E4 场景：`geoip_source_ip2region.toml`。

### 11.16 节点加密出站数据面（node outbound tunnel data plane，2026-09-24） {#11-outbound-tunnel-dataplane}

把 §11.6 / §11.7 / §11.9 的节点 adapter（Shadowsocks / VMess / Trojan）接入 §11.4 的
真实 SOCKS5 数据面：规则路由选定节点型出站时，流量经真实加密隧道出站（对齐 Clash
节点客户端用途，替代其本地代理角色）。

数据面链路：

```text
SOCKS5 入站（Socks5Handshake，§11.4 不变）
  -> FlowContext -> 规则路由（§11.1 纯决策，零改动）
  -> 按 selected_outbound.kind 建立真实出站连接：
       direct      -> TcpStream::connect(destination)（§11.4 现状，零回归）
       shadowsocks -> TcpStream::connect(node.locator)
                      + SsStream(Role::Client) 会话（§11.6.1 复用）
                      + seal(encode_request(destination)) 加密 request header
                      + 双向 record 帧中继（read_record / write_record）
       trojan      -> rustls TLS 握手（SNI=节点域名，ALPN，skip-cert-verify §11.9.1）
                      + trojan 请求头（standard / singbox，§11.9.2）
                      + 双向透明中继
       vmess       -> vmess AEAD 请求头 + 记录中继（§11.7）
  -> 双向字节中继（客户端 <-> 节点隧道）
```

- 配置零新增：复用 `OutboundConfig` 既有字段（kind / locator / method / password /
  alpn / skip_cert_verify / header_format），节点型 kind 的校验沿用 §11.9.3。
- 用户可观察（新增字段；direct 会话不出现或为空）：
  - `routing.outbound_kind`：选定出站的 kind 标签（direct / shadowsocks / trojan / vmess）；
  - `outbound`：`{ kind, node_locator, method?, tls: { sni?, alpn?, skip_cert_verify? },
    header_format? }`（按 kind 可空）。
- 失败语义：节点建连失败 / 协议握手失败 / 隧道中继失败 →
  `ConnectivityEstablishmentFailed { provider: <selected outbound tag> }`，会话级
  结构化 FAIL；服务循环继续 accept 下一会话（逐会话隔离，不中断 daemon）。
- 回归保障：direct 路径与既有 `daemon_real_socks_proxy_flow` 行为零变化。
- 冻结边界（本期不做）：UDP 隧道 / QUIC / 多路复用 / 节点自动切换（selector /
  urltest 已由 §11.1 提供）/ 订阅在线更新（已交付，见 §11.17，本边界不再冻结此项）。
- E4 场景：`scenarios/product/proxy_outbound_shadowsocks_flow.toml`——loopback：
  echo 目标 + 本地 SS server + nexus proxy（配置 outbound=ss-node → 本地 SS server）+
  原始 SOCKS5 客户端经 proxy 访问 echo；断言 SS server 收到加密连接、
  request header 目标送达、payload 经加密隧道往返、`routing.outbound_kind=shadowsocks`。

### 11.17 订阅节点在线更新（subscription online update，requirement-change，2026-09-24） {#11-subscription-update}

§11.2 曾把「Clash 订阅在线解析与自动更新」列为 P0 冻结不做项；本节作为
**requirement-change** 正式交付：nexusd 按可配置间隔从 HTTP(S) 订阅源在线拉取
base64 订阅文本，复用 §11.8 的离线解析（`parse_clash_subscription`）把节点 URI
解析为 `OutboundConfig`，热生效地替换运行时节点列表，无需重启进程。

数据面链路：

```text
SubscriptionSourceConfig（url / interval_secs / user_agent / headers / tls 选项）
  -> 后台拉取器（Owner：CancellationToken + JoinSet + Reaper；禁止丢弃 JoinHandle）
  -> http:// 明文 / https:// rustls GET（复用 §11.12 / §11.14 CachedHttpProviderFetcher 传输层）
  -> parse_clash_subscription（§11.8 纯函数：base64 解码 + ss/vmess 节点映射 + 未知协议显式拒绝）
  -> 合并：本地手写 outbounds 恒定保留；订阅节点集每次成功拉取整体替换上一次订阅节点集；
           同一订阅内按 tag 去重（后出现者覆盖）
  -> HotReloadManager.propose_reload(revision, valid=true)（§12.15 热生效门控，不重启进程）
  -> 结构化可观察事件
```

- **订阅源配置**（`subscriptions:` 段，可选；缺失则无在线订阅，行为与本批前一致）：
  `{ tag, url, interval_secs, user_agent?, headers?: [[k,v]...], tls_skip_cert_verify? }`。
  `url` 协议白名单 `http:// | https://`；`interval_secs >= 1`；非法（空 url / 协议非法 /
  interval=0）返回 `CONFIG_INVALID`。`user_agent` 缺省为 `Nexus-Subscription/1`；
  `headers` 为附加请求头；`tls_skip_cert_verify=true` 时 https 客户端不校验服务端证书
  （自签/私有场景，默认 false 走 Mozilla 根，与 §11.14 一致）。
- **合并语义**：本地手写 `outbounds`（direct / reject 等）**恒定保留、永不被订阅清空**；
  订阅产出的节点集是一个独立可替换集合——每次**成功**拉取整体替换上一次订阅节点集
  （非累积、非追加合并）；同一订阅内 tag 重复时后出现者覆盖先出现者。
  运行时有效节点列表 = 本地手写 outbounds ++ 当前成功订阅节点集。
- **失败回退**：拉取失败（网络错误 / TLS 错误 / 非 200 / base64 非法 / 解析后 0 节点）
  时**保留上一次成功的订阅节点集**，运行时节点列表不变，**不得清空当前节点**；
  本批次回退为进程内保留上一次成功的订阅节点集；跨重启的落盘缓存兜底（§11.12 缓存语义）
  属后续 crash-consistency 工作，不在本期冻结 expectation 内。首次启动即失败且无任何
  历史订阅节点时，运行时节点列表 = 本地手写 outbounds（空订阅集），不致命。
- **热生效**：一次拉取成功并合并后，经 `HotReloadManager.propose_reload(new_revision,
  valid=true)`（§12.15）把新节点集原子生效，**不重启进程**；拉取失败不推进 revision，
  已生效节点列表保持不变。
- **结构化并发**：后台拉取任务有唯一 Owner（`CancellationToken` 请求协作式停止、
  `JoinSet` 收集 worker、`Reaper` 在 Owner drop 时确认回收 worker）；禁止 `tokio::spawn` /
  等价物后丢弃 JoinHandle。worker 只发事件、不直接写 TerminalOutcome。
- **可观察事件**（结构化，带关联字段 `subscription_tag` / `subscription_url`）：
  `{ attempt: u64, ok: bool, node_count_before: usize, node_count_after: usize,
  rejected: u32, latency_ms: u64, error?: string }`；Hot Path 不对每包打日志，
  事件按拉取周期（分钟级）产出。
- **错误面**：配置非法 `CONFIG_INVALID`；单次拉取失败是事件级（`ok=false`）而非进程级
  致命错误，服务循环继续 accept 下一会话；以类型化 `Result` 表达，不以 panic 表示可恢复失败。
- **零回归**：§11.8 `proxy-clash-subscription-parse`、§11.12/§11.14 rule-provider 拉取、
  §12.15 `config_hot_reload` 既有冻结场景行为不变。
- **冻结边界（本期不做）**：订阅 YAML 规则集（仅 base64 URI 列表，§11.8 范围）、
  订阅节点测速自动选路（urltest 已由 §11.1 提供）、多订阅源按 tag 合并冲突策略、
  订阅节点与 selector/urltest 组的自动挂接（仅静态注入 outbounds）、
  https 订阅源拉取接线（E4 以 loopback http 闭环；https 复用 §11.14 rustls 栈为后续接线）。
- E4 场景：`scenarios/product/proxy_subscription_online_update.toml`——本地 loopback
  HTTP 订阅源（可变内容 + 可制造失败）：首次拉取 2 节点 -> 热生效节点数 +2；
  拉取失败 -> 节点数保持不变（回退）；再次拉取 3 节点（含 1 未知协议行）-> 节点数 +3、
  rejected=1；断言 `HotReloadManager` revision 在成功时推进、失败时不推进。
### 11.18 TUN 透明代理入站（TUN transparent proxy inbound，2026-09-24） {#11-tun-transparent-inbound}

把 §11 代理内核的入站从「仅 SOCKS5 显式代理」扩展为「可被 TUN 虚拟网卡透明接管全局
流量」，对齐 Clash TUN 模式语义。与 §12.29（虚拟子网 mesh 隧道线的 PacketTunnel）是
**两条独立数据面**：§12.29 把 VPI 包封装后发给对端节点组网；本节把 VPI 包解出来按
§11 规则表路由到出站（代理上网）。二者复用同一个 `nexus-platform::VirtualPacketInterface`
trait 与 `nexus-platform-windows::WintunVpiAdapter`，但上层编排互不调用。

数据面链路（portable core 部分，离线可确定性闭环）：

```text
wintun 虚拟网卡（nexus-platform-windows::WintunVpiAdapter，§12.29 窄 C ABI 已落地）
  -> VirtualPacketInterface::receive 读原始 IP 包
  -> nexus-ingress::ip_packet 纯函数解析 IPv4 头 + TCP(6)/UDP(17) 传输头 -> TunPacket
       { proto, src_ip:src_port, dst_ip:dst_port }
  -> FlowContext(origin=VirtualPacketInterface, destination="dst_ip:dst_port")
       （复用 ingress::from_virtual_packet_interface，中立零 I/O）
  -> nexus-proxy::ProxyService::route（§11.1 纯决策，零改动）
  -> nexus-proxy::TunNatRouter 按 5 元组缓存分流决策
       （首包决策并建映射；同流后续包命中缓存，不再重跑规则表）
  -> selected_outbound_tag（可观察；出站 adapter 承接见 §11.4/§11.16）
```

- **平台边界（ARCHITECTURE §10/§11）**：wintun 是 Windows 平台能力，只存在于
  `nexus-platform-windows`；portable core（`nexus-ingress` / `nexus-proxy`）只消费注入的
  `nexus-platform::VirtualPacketInterface` trait，不直接调 wintun API。`nexus-ingress` 的
  IP 包解析是纯字节解码（零 I/O、`#![forbid(unsafe_code)]`），不触碰任何平台句柄。
- **解析语义**：仅处理 IPv4 且传输协议为 TCP(6) 或 UDP(17) 的包。版本非 4、IHL 非法、
  长度截断、协议为 ICMP(1)/其他、IPv6 的包一律解析为 `None` 并计入 `dropped` 计数
  （结构化丢弃，不 panic、不写 per-packet 日志）。端口从传输头前 4 字节提取。
- **NAT/连接跟踪**：`TunNatRouter` 以 `(proto, src_ip, src_port, dst_ip, dst_port)` 为键
  缓存 `RoutingDecision`。首包 miss → 走 `ProxyService::route` 并建映射；后续同键包
  hit → 直接复用缓存决策（可观察 `cache_hit=true`，`mappings` 计数不增）。这是 TUN
  per-packet 数据面相对 SOCKS5 per-stream 的独立变化维度，故独立成模块（Deletion Test：
  删除它则每个 IP 包都重跑线性规则表，破坏「同流一次决策」的独立约束）。
- **可观察性**（counter/histogram，禁止 per-packet 日志）：`packets_in` / `bytes_in` /
  `dropped`（无法解析或非 TCP/UDP）/ `mappings`（活跃 5 元组映射数）/ `cache_hits`。
  每条新流首次决策输出 `matched_rule` / `selected_outbound_tag` / `flow_origin`
  （flow_origin=`virtual-packet-interface`）。
- **失败语义**：wintun adapter 创建失败（缺 `wintun.dll` / 无管理员权限 / 驱动未安装）
  → 结构化 `{ verdict:"TUN_ERROR", error:"..." }`（exit 0，不静默回退为 SOCKS5 监听）。
  包解析失败计入 `dropped`，不中断读循环。
- **CLI**：`nexusd proxy --tun [--tun-name <n>] [--config <path>]` 在既有 SOCKS5 监听之外
  追加 TUN 入站；无 `--tun` 时既有 `nexusd proxy --addr` 行为零变化。`--tun` 装配走真实
  `WintunVpiAdapter::create`（E5，需管理员 + 随附 `wintun.dll` 于 nexusd.exe 同目录）。
- **E4 场景**：`scenarios/product/proxy_tun_inbound.toml`——组合根注入 `MemoryVpi`
  （离线确定性替身）：注入一条 IPv4/TCP SYN（dst=10.1.2.3:443，命中 ip_cidr 规则）+
  一条 IPv4/UDP（dst=8.8.8.8:53，落入 MATCH）+ 同 TCP 5 元组第二个包（应 cache_hit）+
  一个截断/ICMP 坏包（计入 dropped）。断言解析、FlowContext origin、命中规则、选定出站、
  NAT 映射数与 cache_hit、计数器。不依赖真实驱动。
- **E5 真机观察**：`cargo run -p nexus --example tun_proxy -- --real [--tun-name <n>]`
  （管理员）→ 真实 `WintunVpiAdapter::create` 成功，输出 `backend`/`mtu`/`driver_version`/
  `capabilities` 与一次非阻塞 `receive`（0 = 无包）。创建失败 → `verdict=TUN_ERROR`。
- **冻结边界（本期不做，下批）**：真实双向 TCP/UDP 字节中继回写 TUN（userspace TCP/IP
  栈 / tun2socks 式连接跟踪与报文改写）、路由表增删（route include/exclude）、IPv6 解析、
  DNS 劫持接入 §11.5 DNS 模块、MTU/MSS 钳制。本期 E4 冻结的是「解析 → 分类 → 规则路由
  → NAT 决策」portable 闭环；真实报文拨号与回写为下批。

### 11.19 HTTP/混合代理入站（HTTP & mixed proxy inbound，2026-09-25） {#11-http-mixed-inbound}

§11.4 的 SOCKS5 入站是唯一显式代理入口，导致系统代理接管（§13 WinINET）后，浏览器 /
PowerShell 等走 HTTP 代理协议（`http://127.0.0.1:7897`）的客户端被立即拒绝（连接被重置）。
Clash Verge 的 7897 是**混合端口**（同一 TCP 端口同时接受 SOCKS5 与 HTTP 代理）。本节把入站
扩展为「混合」语义，使 WinINET 应用流量经 `nexusd system-proxy set` 后真实可用。

数据面链路（与 §11.4 同一出站与中继底座，仅握手段新增 HTTP 分支）：

```text
TCP accept（apps/nexus，非 portable I/O）
  -> 首字节判定：0x05 -> 既有 Socks5Handshake（§11.4，零回归）
                否则 -> nexus-ingress::HttpProxyHandshake（纯函数，零 I/O）
  -> FlowContext（origin=FlowOrigin::Http，复用 ingress::from_http，中立）
  -> 规则路由（§11.1 纯决策，零改动）-> Session 双轨 -> 真实出站 -> 双向字节中继
```

- **混合端口判定**：accept 后读首帧，首字节 `0x05` 走 SOCKS5 状态机；否则走 HTTP 代理
  状态机。两种协议在同一监听端口按首字节分流，互不干扰；同一会话只走其中一条分支。
- **配置**：`inbounds[].kind` 新增 `"mixed"`（同一端口 SOCKS5+HTTP 共存）；保留
  `"socks5"` 既有语义（仅 SOCKS5）。未知 kind 仍被配置层拒绝。`nexusd proxy --addr`
  默认监听行为与既有示例闭环保持兼容（组合根按首字节自动混合，无需新 CLI 标志）。
- **HttpProxyHandshake 语义（portable core，`#![forbid(unsafe_code)]`，零 I/O、零平台 API）**：
  增量 `feed()`，与 `Socks5Handshake` 同构（返回结构化 Step{state, response, flow,
  needs_more, upstream_prefix}）。必须读到请求头结束（`\r\n\r\n`）才进入 `Established`，
  未读完 `needs_more=true`。
  - `CONNECT host:port HTTP/1.1\r\n...\r\n\r\n`：destination=`host:port`，回写
    `HTTP/1.1 200 Connection Established\r\n\r\n`，随后裸中继（隧道语义）。
  - 绝对形式转发 `GET|HEAD|POST ... http://host[:port]/path?query HTTP/1.1\r\n...\r\n\r\n`：
    解析出 destination（缺省端口 80），把请求行改写为 origin-form
    `METHOD /path?query HTTP/1.1` 并随已收到的请求头一并作为 `upstream_prefix` 先写上
    游，再双向中继；握手阶段不回写响应（响应由上游 origin 透传回客户端）。
  - 非 CONNECT 但 target 为 origin-form（`GET /path`，无 scheme）、未知方法、坏请求行
    → 结构化 `HttpProxyError`，回写 `HTTP/1.1 400 Bad Request\r\n\r\n`。
  - 只解析请求行与必要边界，不做完整 HTTP 语义（不解析 body、不做 chunked 重组）。
- **平台边界（ARCHITECTURE §10/§11）**：HTTP 代理协议状态机（请求行/绝对 URL 解析、
  CONNECT 200 响应、origin-form 改写）在 `nexus-ingress`（portable 纯函数）；真实
  `TcpListener` accept / 读写 / 中继在 `apps/nexus`（非 portable）。`nexus-ingress` 不直接
  调 Core Planner / 平台 API / `std::net`。
- **可观察性**：每会话输出 `inbound_kind`（`socks5` / `http`）、HTTP 分支的 method 与
  destination；其余路由 / Session / 字节计数与 §11.4 一致。
- **失败语义**：坏 HTTP 请求行 → 400 响应后关闭会话（结构化错误，不 panic）；握手中途
  客户端断开 → 结构化内部错误，不静默直连。
- **E4 场景**：`scenarios/product/proxy_http_mixed_inbound.toml`——loopback 本地 HTTP
  origin（回 200）+ Nexus 混合入站：(i) 用原始 HTTP 代理客户端（绝对形式 GET）经混合端口
  请求 origin，断言 200；(ii) 同端口再发一个 CONNECT 隧道请求，断言 200 Connection
  Established 后隧道内 GET 200；(iii) 同端口再发 SOCKS5 握手，断言仍通（mixed 共存）。
- **E5 真机观察（本期不冻结，Review WARN 记录即可）**：`nexusd system-proxy set` 后
  WinINET 应用（浏览器 / Invoke-WebRequest）经 7897 真实联网。涉及 registry 修改与停
  clash-verge 复用 7897，验收后必须恢复基线（ProxyEnable=0）并重启 clash-verge。
- **冻结边界（本期不做，下批）**：HTTP 代理认证（Proxy-Authorization）、HTTPS 绝对形式
  （`https://` scheme，本期仅 `http://` 绝对形式 + CONNECT 隧道）、CONNECT 之外的方法
  到上游的完整 body/chunked 处理（本期透传字节）、HTTP/2、端口复用之外的独立 HTTP 监听口。


## 12. 虚拟子网组网（Virtual Subnet Networking） {#12-virtual-subnet-networking}

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


### 12.5 P1 静态路由与三节点转发闭环（2026-09-20）{#12-static-routing}

§12.3 明确"多节点网状拓扑自动路由"为 P0 不做项，但括号注明"路由表静态配置"。
本节冻结 P1 的静态路由最小闭环：三节点链 A—B—C，A 与 C 无直连，B 作为中间转发节点。
不做动态路由发现、不做最短路径计算、不做跨子网；路由表为**显式静态配置**。

```text
节点 A (10.0.0.1)  ──直连──  节点 B (10.0.0.2)  ──直连──  节点 C (10.0.0.3)
       │                                                         │
       └──────── A 不直连 C；A → C 的包必须经 B 转发 ─────────────┘
```

- 路由表（每节点静态配置，非自动发现）：
  - A：`routes = { "10.0.0.3" → "10.0.0.2" }`（C 经 B）
  - B：`routes = {}`（A 和 C 都是直连 peer，无需转发）
  - C：`routes = { "10.0.0.1" → "10.0.0.2" }`（A 经 B，回包对称）
- 转发语义（IP 路由器模型）：
  - `send_ip_packet(dst, packet)`：若 dst 是直连 Connected peer，直发；
    否则查 `routes[dst]` 得 next_hop，把同一隧道帧（src=自己、dst=原始 dst）
    发给 next_hop。帧头 **不剥不改**，保留原始 dst 供中间节点判断。
  - `recv_and_deliver`：解封装后，若 `header.dst_virtual_ip == self.config.virtual_ip`
    → 写 VPI；否则查 `routes[dst]` 得 next_hop，**重新封装同帧**发给 next_hop
    并计 `bytes_forwarded`；若 routes 无 next_hop → 结构化错误 `NO_ROUTE_TO_DST`。
- 新错误码：
  - `NO_ROUTE_TO_DST`：收到一个 dst 非本机且路由表无 next_hop 的帧。
  - `ROUTE_NEXT_HOP_NOT_PEER`：`add_route` 注册的 next_hop 不是已注册 peer。
- 可观察性：
  - `TunnelStats` 新增 `bytes_forwarded: u64`（中间节点累计转发字节）。
  - 新增事件 `VirtualSubnetEvent::PacketForwarded { tunnel_id, src_virtual_ip,
    dst_virtual_ip, next_hop, bytes }`。
- E4 场景：`virtual_subnet_mesh_3node.toml`——A 经 B 转发一个 IP 包到 C：
  断言 C 的 VPI 收到原始 payload、B 的 bytes_forwarded > 0、A 与 C 的 peer 表
  互不可见（A 的 peers 只有 B，C 的 peers 只有 B）。
- 冻结边界（P1 不做）：动态路由协议、最短路径算法、跨子网、加密、真实 TUN。

### 12.6 P1.1 多跳动态路由（距离矢量，2026-09-20）{#12-multihop-routing}

§12.5 在冻结边界中明确"动态路由协议、最短路径算法"为 P1 不做项。
本节作为 **requirement-change** 突破该边界，冻结 P1.1 的最小动态路由闭环：
距离矢量（Distance Vector，Bellman-Ford 简化版），邻居间周期性交换路由通告，
直连不可达时由中间节点转发。本任务为纯内存骨架，真实 UDP/socket 留 TODO。

```text
线性拓扑（4 节点，两端无直连，经 3 跳可达）：
  A (10.0.0.1) -- B (10.0.0.2) -- C (10.0.0.3) -- D (10.0.0.4)
  A 与 D 不直连；A -> D 的包依次经 B、C 转发
```

- 拓扑发现：节点启动时已知直连邻居（add_direct_peer，cost=1）；非直连目标
  完全依靠邻居通告学习，不做链路状态泛洪、不做 SPF。
- 路由数据结构：
  - RouteEntry { destination: String, next_hop: String, cost: u32,
    last_updated_tick: u64 }；
  - RoutingTable { local_virtual_ip, entries: HashMap<dst, RouteEntry> }；
  - 路由通告 RoutingAdvertisement = Vec<(dst_virtual_ip, cost)>（发给邻居的路由视图）。
- 距离矢量合并规则（apply_advertisement(from_peer, adv, now_tick)）：
  - 对 adv 中每条 (dst, cost_via)，候选代价 candidate = cost_via + 1；
  - 跳过 dst == from_peer 的条目（对端自身由 add_direct_peer 直连维护，
    不通过其通告反向再学一条 cost=1 的对等路由）；
  - 本地无该 dst -> 新增 RouteAdded；
  - 本地已有且 next_hop == from_peer -> 刷新 last_updated_tick（同下一跳路由
    保持新鲜；cost 变化时发 RouteUpdated）；
  - 本地已有但 candidate < existing.cost -> 切换下一跳为 from_peer，发 RouteUpdated；
  - 其余情况保持原条目不动。
- 水平分割（Split Horizon，防环路的最小实现）：
  advertise_to(neighbor) 生成发给 neighbor 的通告时，**不包含**
  next_hop == neighbor 的条目——即从 neighbor 学到的路由，不再发回 neighbor。
- 路由超时：expire_stale(now_tick, ticks_to_live) 删除
  now_tick - last_updated_tick > ticks_to_live 的条目，每条发 RouteExpired。
  时间由显式 now_tick: u64 逻辑时钟推进，**不 sleep、不 tokio**。
- 转发语义（MultihopRouter::forward(packet, now_tick)）：
  - 包结构 RoutablePacket { src, dst, ttl: u8, payload }，初始 TTL=64；
  - dst == local_virtual_ip -> DeliverLocal（本地交付）；
  - ttl == 0 -> 错误 TtlExceeded 并发 TtlExceeded 事件（防无限循环）；
  - 查路由表命中 -> ForwardTo { next_hop, ttl: packet.ttl - 1 }，
    并发 PacketForwarded { src, dst, next_hop, ttl } 事件；
  - 未命中 -> 错误 NoRouteToDst。
- 错误码：
  - NoRouteToDst { dst }：路由表无 dst 条目（与 §12.5 语义对齐，本模块独立
    类型化 enum，不复用 ConnectivityError::Invalid 字符串匹配）；
  - TtlExceeded { dst, hops }：TTL 耗尽仍未到目的地；
  - InvalidPacket { message }：包字段非法（空 src/dst 等）；
  - NotADirectPeer { peer }：转发目标不是直连邻居（骨架期由上层校验）。
- 可观察性：
  - RoutingEvent 枚举：RouteAdded{dst,next_hop,cost} /
    RouteUpdated{dst,old_cost,new_cost} / RouteExpired{dst} /
    PacketForwarded{src,dst,next_hop,ttl} / TtlExceeded{dst,hop_count}；
  - MultihopRouter 累积事件，events() / take_events() 供 Owner 状态机消费。
- E4 场景：scenarios/product/multihop_routing.toml（id=product.multihop-routing），
  命令 nexus-harness run multihop-routing --json：
  - 4 节点线性拓扑 A--B--C--D，初始仅直连邻居；
  - 2~3 轮通告后收敛：A 到 D 的 next_hop=B、cost=3；D 到 A 对称；
  - A->D 发一包，逐跳 A->B->C->D，D 本地交付，TTL 从 64 递减到 61；
  - 推进逻辑时钟超过 TTL 后某条非直连路由被 RouteExpired 删除。
- 冻结边界（P1.1 不做）：
  - 真实 UDP 发送/接收、socket、平台 TUN 一律 TODO（纯内存 mock）；
  - <=3 跳以内的简单路由，不做完整 Bellman-Ford 全量迭代计数、不做毒性反转
    （poison reverse）、不做触发更新；
  - 不跨子网、不接加密（复用 §12 既有 encryption 概念，本任务不接入）；
  - 不引入 tokio / 异步任务 / 长期 spawn（显式 tick 推进，纯同步纯函数骨架）。
### 12.7 P2 隧道加密（链路加密接入虚拟子网数据面，2026-09-20）{#12-encryption}

§12.3 冻结"加密后置"；§6 链路加密原语（`nexus-connectivity::encryption`，
PRODUCT §6）已交付。本节把加密**接入虚拟子网数据面**：开启后隧道帧整体
AEAD 加密，每跳独立会话（WireGuard 式链路加密），§12.5 路由语义保持。

- 加密原语复用（不改 wire 布局）：X25519 纯 ephemeral 双公钥握手、
  HKDF-SHA256 方向子密钥（tx/rx）、ChaCha20Poly1305 数据帧（22 字节
  version|type|seq|nonce 头作 AAD）、1024 位滑动防重放窗口。
- 接入 API（`VirtualSubnetTunnel`）：
  - `enable_encryption(config: EncryptionConfig)`：开启加密模式（默认关闭，
    明文模式与 §12.1-§12.5 语义不变）；`is_encryption_enabled() -> bool`。
  - `begin_handshake(peer_virtual_ip)`：发起方生成临时密钥对，经 carrier 发
    `HANDSHAKE_INIT`（33 字节），暂存本端密钥等待响应。
  - `accept_handshake(peer_virtual_ip, msg)`：响应方生成临时密钥对，经
    `handshake_respond` 派生本端会话并回 `HANDSHAKE_RESP`。
  - `complete_handshake(peer_virtual_ip, resp)`：发起方用响应方公钥完成派生
    （新增 `KeyPair::derive_directional(peer_public, initiator)`，分步握手专用）。
  - 握手成功前不发送数据帧（peer state 沿用 Handshaking→Connected；发送仍
    校验 Connected）。
- 数据面语义（加密模式）：
  - 发送：`TunnelFrameHeader.serialize() + payload` 整体作为明文，
    `encrypt_frame(session.tx, tx_seq, inner)` 后经 carrier 发送；tx_seq 递增。
  - 接收：按长度+type 分流握手帧/数据帧；数据帧以**对端会话 rx 依次试解密**
    （tag 失败=错误密钥），成功后再经 `ReplayWindow::check_and_accept` 防重放；
    解密或防重放失败 → 整帧丢弃并返回结构化错误（不暴露明文）。
  - 中间节点转发：解密后 dst≠本机 → 用 next_hop 会话**重新加密**同一明文
    （虚拟 IP 头内容不变，§12.5"帧头不剥不改"语义保持）后转发；计
    `bytes_forwarded` 并发 `PacketForwarded` 事件（字节数按 wire 密文长度）。
- 可观察性：加密模式下各节点 `is_encryption_enabled=true`；peer state 经
  握手推进到 Connected；防重放拒绝计 `dropped`（TunnelStats 复用）。
- 失败语义：无匹配会话解密 / tag 失败 / 重放拒绝 → 结构化错误
  `CRYPTO_ERROR` / `REPLAY_REJECTED`（复用 `EncryptionError` 语义）；
  对未握手 peer 发送数据帧 → 结构化错误（沿用 next_hop not connected）。
- E2 单测：分步握手与既有一步握手派生一致（确定性交叉验证）、双节点
  加密收发 roundtrip、篡改/重放拒绝、明文模式回归。
- E4 场景：`virtual_subnet_encrypted_3node.toml`——A—B—C 链（A 不直连 C），
  全节点加密，A→C 经 B 转发：断言 C 的 VPI 收到原始 payload、B 的
  `bytes_forwarded > 0`、wire 密文不含明文泄漏、重放同一密文被拒、
  各节点 `is_encryption_enabled=true`。
- 冻结边界（P2 不做）：长期身份/公钥持久化（纯 ephemeral 握手）、密钥
  周期轮换逻辑、psk 绑定、真实线上传输（内存 carrier 闭环）。

### 12.8 P2 带宽控制 / QoS（令牌桶限流骨架，2026-09-21）{#12-bandwidth-qos}

§12.1-§12.7 已打通组网 / 转发 / 加密数据面；本节把**出站与入站带宽整形**接入
delivery 层（`nexus-connectivity::qos`）。纯内存、纯同步、可注入时钟骨架。

- 令牌桶（`TokenBucket`）：按 `max_bytes_per_sec` 字节/秒线性 refill，上限
  `burst_size`；初始满桶允许一次性突发 `burst_size` 字节。
  - `refill(now)`：按经过时间补充令牌，封顶 `burst_size`；
  - `try_consume(bytes, now) -> bool`：够令牌则扣减并放行，不够直接拒绝
    （**不阻塞、不 sleep**）；
  - `remaining_tokens() -> u64`：向下取整的剩余令牌（诊断/快照）。
- 可注入时钟（`QosClock` trait）：`fn now(&self) -> Duration`；
  真实实现 `MonotonicClock` 基于 `std::time::Instant`（构造点起算的单调时长）；
  单测 / E4 用显式 `Duration` 假时钟推进，保证确定性。
- 带宽限制（`BandwidthLimit`）：`new(max_bytes_per_sec, burst_size) -> Result<_, QosError>`，
  速率必须 > 0、burst 必须 >= 1，否则 `QosError::InvalidLimit`。
- 配置（`QosConfig { ingress, egress }`）：两方向各自的 `Option<BandwidthLimit>`；
  `None` 表示该方向不限制（恒放行）。
- 控制器（`QosController`）：持有入站/出站两个令牌桶 + 统计表；
  - `try_egress(tag, bytes, now) -> bool` / `try_ingress(tag, bytes, now) -> bool`：
    命中限制返回 `false` 并把字节计入 `bytes_dropped`；放行计入 `bytes_allowed` 与
    该 tag 的 `up_bytes`（egress）/ `down_bytes`（ingress）；
  - `snapshot() -> QosStats`：聚合计数 + `HashMap<tag, PerEndpointStats{up,down}>`。
- 错误面：`QosError::InvalidLimit { message }`，`Display` + `std::error::Error`；
  库代码不用 `panic!` / `unwrap!` / `expect!`。
- 集成语义（演示）：转发路径先过 `QosController` 再过 firewall 判定；被 QoS 拒绝的
  流量计 dropped，不计 allowed、不进入后续过滤。本骨架不改旧模块签名。
- E4 场景：`scenarios/product/bandwidth_qos.toml`（id=`product.bandwidth-qos`），
  命令 `nexus-harness run bandwidth-qos --json`（出站 1000 B/s、burst 1000）：
  - (a) 初始突发 1000 字节放行；
  - (b) 同刻再发 100 字节被拒；
  - (c) 推进时钟 1 秒后令牌恢复，又可发 500 字节；
  - (d) conn-a up=1500、conn-b up=300，两连接统计互不影响；
  - (e) bytes_allowed=1800、bytes_dropped=100（拒绝字节不计入 allowed）。
- 冻结边界（P2 不做）：整形排队（缓冲/平滑）、优先级 / 公平排队、per-flow 哈希分流、
  真实 socket/TUN 挂接、配置热加载与持久化（留 TODO）；不引入 `time` crate，仅 std。

### 12.9 P2.2 NAT 打洞集成（数据面闭环，2026-09-21）{#12-nat-probe}

nat.rs（`nexus-connectivity::nat`：StunClient / HolePuncher / NatType，PRODUCT §connectivity）
已交付且 E4 已绿；§12.1-§12.8 的 peer locator 为**静态配置注入**。本节把打洞接入
虚拟子网数据面：打洞成功 → peer locator **动态学习**（切直连）；失败 → **Relay
回退**（保底路径）。tunnel 侧不持有真实 UDP socket（保持 portable 边界，真实
socket 集成留 P3 产品化）；打洞由外部 HolePuncher 驱动后经隧道 API 落账。

- `TunnelState` 新增 `Probing`（打洞中间态，Disconnected → Probing → Connected /
  Failed 转换）。
- 接入 API（`VirtualSubnetTunnel`）：
  - `probe_peer(peer_virtual_ip) -> Result<(), ConnectivityError>`：peer 置
    `Probing`，发 `ProbeStarted` 事件。
  - `apply_hole_punch(peer_virtual_ip, direct_locator) -> Result<(), ConnectivityError>`：
    打洞成功 → peers locator 更新为直连地址（动态学习）+ state `Connected` +
    `PeerLocatorUpdated` 事件；此后发送走新 locator。
  - `fallback_to_relay(peer_virtual_ip, relay_locator) -> Result<(), ConnectivityError>`：
    打洞失败 → peers locator 切 relay + state `Connected` + `RelayFallback` 事件；
    保底路径。
  - `peer_locator(peer_virtual_ip) -> Option<String>`：查询当前 locator（动态
    学习结果可观察）。
- 数据面语义：locator 更新**即刻生效**（`send_ip_packet` 使用 peers 表当前
  locator）；§12.5 路由 / §12.7 加密语义不变。
- 事件：`VirtualSubnetEvent` 新增 `ProbeStarted { peer_id }` /
  `PeerLocatorUpdated { peer_id, new_locator }` / `RelayFallback { peer_id,
  relay_locator }`（tunnel_id 贯通，与 NatEvent 语义对齐）。
- 失败语义：对未注册 peer 的 probe / apply / fallback → `PEER_NOT_FOUND`；
  已注册 peer 的 apply / fallback 幂等（允许覆盖更新 locator）。
- E2 单测：成功路径（probe → apply → locator 更新 + Connected + 帧走新
  locator）、失败路径（probe → fallback → locator=relay + Connected + 帧走
  relay）、未知 peer 拒绝。
- E4 场景：`virtual_subnet_nat_probe.toml`（id=product.virtual-subnet-nat-probe）——
  双路径：成功（probe → apply_hole_punch("udp://203.0.113.1:5000") → locator
  更新 + Connected + 帧经直连 locator 送达）与失败（probe →
  fallback_to_relay("relay://relay.example:443") → locator=relay + Connected +
  帧经 relay 送达）；断言含 `Probing` 中间态可见。
- 冻结边界（P2.2 不做）：tunnel 内真实 UDP 打洞（HolePuncher 挂接留 P3）、
  打洞重试策略、多候选并发打洞、NAT 类型驱动的路径选择。

#### 12.9.1 E4 场景真实性修正（requirement-change nat01，2026-09-24）

审计发现 product.nat-hole-punching 的 E4 驱动此前硬编码公网映射（203.0.113.42:54321）、NAT 类型（RestrictedCone）与打洞成功（rtt=1ms），与真实打洞之名不符。现修正为诚实边界：E4 冻结期望改为确定性离线编解码自检（RFC5389 Binding Request 构造 + XOR-MAPPED-ADDRESS 解析，nat::codec_self_test），不再冻结伪造的 nat.type==RestrictedCone / hole_punch.success==true；驱动可选地对真实 STUN 服务器（默认 stun.l.google.com:19302）发起 Binding Request，可达时 real_stun=true，否则诚实 real_stun=false（公网映射值环境相关，不入冻结期望）。真实两 peer 跨公网 UDP 打洞与 TUN<->UDP pump Owner 循环仍冻结在 P3；本批以 E5 外部观察（真实 STUN 公网映射、 Windows<->mylinux UdpCarrier 跨主机 RTT）落入 .evidence/nat-real-nat01/。

### 12.9.2 P2.5 TURN 中继分配（RFC 5766，2026-09-25）{#12-turn}

当 STUN 打洞失败（Symmetric NAT / 两端限制型 NAT 后无法直连）时，节点必须能通过配置的
**TURN 服务器**完成中继分配（Allocation），获得一对 relayed transport address 并经其收发，
作为 Direct 打洞失败后的兜底中继路径之一（与既有 DERP 类 `RelayChannel` 并列）。TURN 与
DERP 的区别：TURN 是标准协议（RFC 5766），带显式 Allocate / 长期凭证（RFC 5389 §10.2）/
XOR-RELAYED-ADDRESS / 生命周期；DERP 是进程内字节中继。

- 新模块 `nexus-connectivity::turn`（Portable Core：零真实网络、零新增第三方依赖，可编译 WASI）：
  - TURN 客户端配置 `TurnClientConfig { server, username, password, realm, nonce, lifetime_secs }`；
    `validate()` 拒绝空 `server/username/password`；`realm/nonce` 初始为空（由 401 挑战填充）。
  - 分配状态机 `TurnAllocationState { Unallocated, Requesting,
    Allocated{relayed_addr, expires_secs}, Failed{reason} }`。
  - RFC 5766 编解码（复用 `nat.rs` 的 STUN 基础头：magic cookie / transaction id / XOR 地址）：
    Allocate Request(0x003) / Allocate Error Response(0x113) / Requested-Transport(0x19,UDP=17) /
    XOR-RELAYED-ADDRESS(0x16) / ERROR-CODE(0x9) / NONCE(0x15) / REALM(0x14) / LIFETIME(0xd) /
    MESSAGE-INTEGRITY(0x8, HMAC-SHA1)。
  - 长期凭证 `key = MD5(username:realm:password)`（RFC 5389 §10.2，纯 std 小实现），
    用于计算 MESSAGE-INTEGRITY；HMAC-SHA1 用已在依赖树的 `ring`。
  - 分配编排 `TurnClient::allocate()`：
    1. `Unallocated` -> 发无凭证 Allocate Request；
    2. 收到 401 Unauthenticated -> 提取 realm/nonce，派生 key，重发带 MESSAGE-INTEGRITY 的 Allocate；
    3. 成功 -> 解析 XOR-RELAYED-ADDRESS 得 relayed_addr，状态 `Allocated`；
    4. 任一步失败 -> `Failed{reason}`（保留 ERROR-CODE / 原因）。
  - `trait TurnTransport`（接缝）：`send_recv(&[u8]) -> Result<Vec<u8>, String>`；真实
    UDP/TLS 到 TURN 服务器由 Composition Root / `nexus-platform-*` 注入，本层零真实网络。
  - `MockTurnTransport`：离线确定性回环——首请求回合成 401（含 realm/nonce），二次回成功
    （含 XOR-RELAYED-ADDRESS=192.0.2.1:54320），供单测与 E4 产品场景驱动。
  - `codec_self_test()`：离线构造并解析合成 Allocate 响应 + 计算/校验 MESSAGE-INTEGRITY，零网络。
- 失败语义：结构化 `TurnError`（Invalid / AllocateFailed{code,reason} / AuthChallengeFailed /
  IntegrityMismatch / NoRelayedAddress）；无 panic。
- Deletion Test（AGENTS.md §12）：TURN 分配/凭证/生命周期语义是与 DERP 类 `RelayChannel`
  （DIAL 字节中继）、STUN 打洞三个独立变化维度；复用 `nat.rs` 的 STUN 头原语，不新增系统级
  trait、不投机抽象。
- 冻结边界（P2.5 不做）：真实 UDP/TLS socket 到真实 TURN 服务器、ChannelData 编码、
  ChannelBind、CreatePermission、Refresh 定时器、TURN-over-TLS/TCP、真实中继数据转发 pump、
  多 TURN 服务器选路与配额；这些挂接与产品化留 P3。
- E4 场景：`scenarios/product/turn_relay_allocate.toml`（id=product.turn-relay-allocate）——
  离线确定性：codec 自检（Allocate Request 构造 + XOR-RELAYED-ADDRESS 解析 +
  MESSAGE-INTEGRITY 往返）+ MockTransport 驱动 401 挑战 -> 凭证重发 -> Allocated，
  relayed_addr=192.0.2.1:54320、realm/nonce 非空。真实公网 TURN Allocate 为 E5 外部观察。

### 12.10 P2.3+P2.4 广域协调核心 + 自动 IP 分配（2026-09-21）{#12-coord}

静态 locator 无法扩展（IP 漂移、NAT 后不可预知）。本节交付**协调控制平面核心**与
**虚拟子网自动 IP 分配**：节点经协调器注册（PeerId = X25519 公钥哈希）→ 通告
locator → 领号（自动 IP）→ 拉取对端列表 → 建连。复用 `nexus-discovery`
PresenceRegistry 的"通告/过期"语义扩展到广域（本模块独立实现，零依赖）。

- 新模块 `nexus-connectivity::coord`（Portable Core：零 I/O、零第三方依赖，
  可编译 WASI）：
  - `Coordinator`：`announce(now, peer, locator, ttl_secs)`（幂等刷新）/
    `heartbeat(now, peer, ttl_secs)`（刷新 TTL，未知 peer → `PeerUnknown`）/
    `peer_list(now)` 返回未过期 peer 的**三元组** (peer, locator, virtual_ip)
    （vip 由分配器补充，供节点拉取后 add_peer 建连；vip 未领号 → `PeerUnknown`），
    注册顺序稳定；
    `resolve_locator(now, peer)`（未知/过期 → 结构化错误）。显式 `now_secs`
    注入保证确定性（无 `Instant`）。
  - `VirtualIpAllocator`：`new(cidr)`（校验 IPv4 CIDR）/
    `allocate(now, peer)`（顺序分配空闲 IP；同 peer 重复领号**幂等**返回原号；
    耗尽 → `NoAddressAvailable`）/
    `allocate_specific(now, peer, virtual_ip)`（显式保留；被占用 →
    `AddressInUse`）/
    `release(now, peer)`（释放回池复用）。
  - `CoordFrame`：`Announce{peer,locator,ttl}` / `Heartbeat{peer,ttl}` /
    `PeerListReq` / `PeerListResp{peers}`（三元组 (peer,locator,virtual_ip)）/
    `AllocateReq{peer}` /
    `AllocateResp{peer,virtual_ip}` / `AllocateNack{peer,reason}` /
    `ReleaseReq{peer}` / `UnknownPeer{peer}` / `ExpiredPeer{peer}` ——
    u8 tag + u16 长度前缀字符串 + u64 BE 编解码（与 DiscoveryFrame 同风格，
    确定性、可移植）。
  - `peer_id_from_public_key(&[u8;32]) -> String`：FNV-1a 64 确定性哈希
    （标识用途；安全强度留 P3）。
- 接入（Composition Root / apps/nexus example）：**loopback TCP 协调端点**
  （`127.0.0.1` 随机端口，真实 socket）——节点经 JSON 化输出验证
  注册→领号→拉取→建连→数据面互通全链路（E5）。
- E4 场景：`coord_core.toml`（分配器：分配顺序/幂等重领/显式保留冲突/释放
  复用/耗尽；协调器：announce→peer_list / 过期 / 未知；帧编解码 roundtrip）。
- E5 场景：`coord_join_loopback.toml`（loopback TCP 双节点：announce →
  allocate → peer_list 获得动态 locator+vip → 构建 VirtualSubnetTunnel →
  双向包互通）。
- 冻结边界（P3 再做）：TLS 公网形态（§11.14 rustls 栈挂接）、HTTP/JSON
  协议（本批自定义帧）、心跳周期/租约过期定时器（本批显式 TTL 注入）、
  Planner/Session 深度融合（本批建连直用 VirtualSubnetTunnel）、跨子网
  路由（P2-5）。
### 12.11 P2.3 节点健康检查（探针状态机骨架，2026-09-21）{#12-health-check}

`health_check.rs`（`nexus-connectivity::health_check`）：delivery 层节点健康状态骨架。
纯内存、纯同步、注入逻辑时钟（`now_ms` 由调用方传入，不读真实墙钟）。

- `HealthConfig { probe_interval_ms, timeout_ms, failure_threshold }`：构造校验
  `failure_threshold >= 1`、`probe_interval_ms > 0`，非法返回 `HealthCheckError::InvalidConfig`。
- `HealthState`：`Healthy` / `Degraded` / `Unhealthy`，提供 `as_str()` 与 `Display`。
- `HealthChecker::record_probe(node_id, success, now_ms) -> Result<HealthState, _>`：
  按 node_id 维护连续失败计数。转移规则：连续失败 0 次 → `Healthy`；
  `0 < 连续失败 < failure_threshold` → `Degraded`；`连续失败 >= failure_threshold` →
  `Unhealthy`；任意一次成功立即回到 `Healthy`。新节点首次记录即注册。
- 错误面独立：`HealthCheckError { InvalidConfig, UnknownNode }`，类型化，非 panic。
- E4 场景：`health_check.toml`（id=`product.health-check`）——新节点初始 Healthy、
  连续失败 1/2 次 Degraded、达到 threshold Unhealthy、一次成功恢复 Healthy、
  未记录节点查询返回 UnknownNode。
- 冻结边界（P2.3 不做）：真实定时探测线程、真实网络探活、跨节点状态同步、
  持久化（留 TODO）。

### 12.12 P2.3 节点优先级选择（2026-09-21）{#12-node-priority}

`node_priority.rs`（`nexus-connectivity::node_priority`）：多候选路由的优先级选择骨架。

- `NodePriority { node_id, priority: u8 }`：priority ∈ 0..=100，**越小越优先**；
  越界返回 `PriorityError::InvalidPriority`。
- `RouteCandidate { node_id, priority, latency_ms, bandwidth_mbps }`：单条候选路由。
- `PrioritySelector`：维护 node_id → priority 映射；
  `select_best(&[RouteCandidate]) -> Option<RouteCandidate>`，排序键为
  **(priority 升序, latency_ms 升序, bandwidth_mbps 降序)**，空列表返回 `None`。
- 错误面独立：`PriorityError { InvalidPriority { value }, UnknownNode }`。
- E4 场景：`node_priority.toml`（id=`product.node-priority`）——优先级压倒延迟
  （priority=5 高延迟仍胜 priority=10 低延迟）、同优先级选低延迟、
  同优先级同延迟选高带宽、空候选返回 None、越界优先级被拒。
- 冻结边界（P2.3 不做）：与多跳路由 `routing` 的真实挂接、动态优先级学习（留 TODO）。

### 12.13 P2.3 连接复用池（2026-09-21）{#12-connection-pool}

`connection_pool.rs`（`nexus-connectivity::connection_pool`）：连接复用骨架。

- `PoolConfig { max_idle, max_total, idle_timeout_ms }`：构造校验
  `max_total >= 1`、`max_idle <= max_total`，非法返回 `PoolError::InvalidConfig`。
- `PooledConnection { key, conn_id }`：模拟连接句柄，conn_id 自增。
- `ConnectionPool`：`acquire(key)` 有空闲则复用（取最旧），否则未达 `max_total`
  新建，达上限返回 `PoolError::Exhausted`；`release(conn, now_ms)` 归还为空闲并
  记录时间戳，空闲数超过 `max_idle` 时淘汰最旧；`evict_idle(now_ms)` 淘汰空闲
  超过 `idle_timeout_ms` 的连接；`snapshot()` 暴露 idle/active/total/created_total。
- 引用计数用显式 acquire/release 模拟（不引入 Arc/Drop hook，保持可测试）。
- E4 场景：`connection_pool.toml`（id=`product.connection-pool`）——二次 acquire
  同 key 复用同 conn_id、占满 max_total 后 Exhausted、max_idle 收敛、
  逻辑时钟推进后 evict_idle 回收、非法配置被拒。
- 冻结边界（P2.3 不做）：真实 TCP 连接复用、线程安全 Send/Sync、
  与 relay/nat 数据面挂接（留 TODO）。

### 12.14 P2.3 节点优雅退出（2026-09-21）{#12-graceful-exit}

`graceful_exit.rs`（`nexus-connectivity::graceful_exit`）：节点优雅退出状态机骨架。

- `ExitConfig { grace_period_ms, notify_peers, wait_for_drain }`：构造校验
  `grace_period_ms > 0`，非法返回 `GracefulExitError::InvalidConfig`。
- `ExitState`：`Active / Draining / Exiting / Exited`，各带稳定 `as_str()`。
- `GracefulExit`：`begin_draining(now_ms)` 标记进入 Draining 并记录起始时间；
  `notify_peers(peers)` 在 `notify_peers=true` 时记录已通知对端；
  `advance(active_connections, now_ms)` 推进状态——仍有连接且在宽限期内且
  `wait_for_drain=true` 则停在 Draining，连接排空或宽限期超时则进入 Exiting，
  再推进一次进入终态 Exited。
- E4 场景：`graceful_exit.toml`（id=`product.graceful-exit`）——Active→Draining→
  Exiting→Exited 全链路、未排空仍 Draining、超时强制 Exiting、notify 开关、非法配置被拒。
- 冻结边界（P2.3 不做）：真实网络通知对端、真实 drain 等待、进程信号挂接（留 TODO）。

### 12.15 P2.3 配置热加载（2026-09-21）{#12-config-hot-reload}

`config_hot_reload.rs`（`nexus-connectivity::config_hot_reload`）：配置热加载门控骨架。

- `HotReloadConfig { watch_interval_ms, validate_before_apply }`：构造校验
  `watch_interval_ms > 0`，非法返回 `HotReloadError::InvalidConfig`。
- `ReloadResult`：`Success { applied_revision } / Failed { reason }`，带稳定 `as_str()`。
- `HotReloadManager`：`propose_reload(new_revision, valid)`——`validate_before_apply=true`
  且 `valid=false` 时返回 `Failed` 且已生效 revision 不变；否则把已生效 revision
  推进到 `new_revision` 返回 `Success`；`current_revision()` 暴露当前已生效版本。
- E4 场景：`config_hot_reload.toml`（id=`product.config-hot-reload`）——合法提议推进
  revision、校验开启时非法提议 Failed 且 revision 不变、关闭校验时放宽应用、非法配置被拒。
- 冻结边界（P2.3 不做）：真实文件 watcher 线程、真实配置解析与原子切换（留 TODO）。

### 12.16 P2.3 流量统计汇总（2026-09-21）{#12-traffic-stats}

`traffic_stats.rs`（`nexus-connectivity::traffic_stats`）：按节点流量记账与全量快照骨架。

- `TrafficSummary { total_rx_bytes, total_tx_bytes, active_connections, active_nodes }`：
  快照 DTO，派生 Clone/PartialEq/Debug。
- `StatsCollector`：`record_node_bytes(node, rx, tx)` 饱和累加字节、节点自动注册；
  `record_connection(node, active)` 增减活跃连接数（饱和不回绕）；
  `node_summary(node)` 返回单节点 (rx, tx, active_conns) 或 None；
  `snapshot()` 汇总所有节点字节总数、活跃连接总数与节点数。
- E4 场景：`traffic_stats.toml`（id=`product.traffic-stats`）——字节累加、连接增减、
  未知节点 None、跨节点 snapshot 汇总、上限饱和。
- 冻结边界（P2.3 不做）：真实数据面字节 hook、指标导出到可观测层、周期快照（留 TODO）。

### 12.17 P2.3 节点分组隔离（2026-09-21）{#12-group-isolation}

`group_isolation.rs`（`nexus-connectivity::group_isolation`）：节点分组访问隔离骨架。

- `IsolationMode`：`Full`（按组隔离）/ `None`（全开），带稳定 `as_str()`。
- `GroupConfig { group_name, mode }`：构造校验 `group_name` 非空，空串返回
  `GroupIsolationError::InvalidGroupName`。
- `GroupIsolation`：`define_group(GroupConfig)` 声明组；`assign(node, group)` 把节点划入
  已声明组（未声明组返回 `UnknownGroup`）；`allow_exception(src, dst)` 登记单向跨组放行；
  `check(src, dst) -> AccessDecision`。
- 决策规则（`Full`）：任一节点未分配 -> `Deny`；同组 -> `Allow`；跨组且例外表含
  `(src_group, dst_group)` -> `Allow`；其余跨组 -> `Deny`。`None` 一律 `Allow`。
  例外单向、不自动对称。
- E4 场景：`group_isolation.toml`（id=`product.group-isolation`）--同组 Allow、
  跨组默认 Deny、例外后 Allow、None 全开、未分配 Deny、空组名/未知组拒绝。
- 冻结边界（P2.3 不做）：真实 ACL 下发、规则热更新、与 firewall/node_tags 联动（留 TODO）。

### 12.18 P2.3 带宽分配策略（2026-09-21）{#12-bandwidth-policy}

`bandwidth_policy.rs`（`nexus-connectivity::bandwidth_policy`）：按组/按节点配额分配骨架
（与 `qos` 令牌桶互补，不重复其时钟 refill）。

- `BandwidthPolicy { group_quota_bytes_per_sec, per_node_quota_bytes_per_sec }`：构造校验
  两个 quota 均 > 0，否则 `BandwidthPolicyError::InvalidQuota`。
- `Priority`：`High`/`Normal`/`Low`（`rank()` High=0 最高）；`OverflowStrategy`：
  `Drop`/`Queue`；`AllocationOutcome`：`Granted`/`Dropped`/`Queued`（各带 `bytes` 与 `as_str()`）。
- `PolicyAllocator`：`register_node(node, group, priority)`；`try_allocate(node, bytes, now_second)`
  按逻辑秒 `now_second` 跨秒清零组/节点已用计数。Normal/Low 需组与节点配额都够才 Grant；
  High 只要组内尚有任意配额即放行到组剩余上限（可超节点配额，不做抢占）；配额不足按
  Drop/Queue（Queue 不记账并累计）。未注册节点 -> Dropped。
- E4 场景：`bandwidth_policy.toml`（id=`product.bandwidth-policy`）--配额内 Grant、
  组配额耗尽 Drop、未注册 Drop、Queue 策略 Queued、跨秒重置恢复 Grant。
- 冻结边界（P2.3 不做）：真实排队缓冲/回灌、跨流公平调度、动态抢占、真实单调时钟（留 TODO）。

### 12.19 P2.3 日志级别控制（2026-09-21）{#12-log-level}

`log_level.rs`（`nexus-connectivity::log_level`）：全局/模块级日志级别查询与动态调整骨架。

- `LogLevel`：`Error`/`Warn`/`Info`/`Debug`/`Trace`，带 `as_str()`、`severity()`
  （Error=0...Trace=4），实现 `std::str::FromStr`（大小写不敏感，非法返回
  `LogLevelError::InvalidLevel`）。
- `LogLevelConfig { global, module_overrides }`：`new(global)`、`set_module(module, level)`。
- `LogLevelController`：`effective_level(module)`（覆盖优先、否则全局）；`set_global(level)`；
  `set_module_level(module, level)`；`enabled(module, level)`（level.severity <= 有效级别
  severity 才输出）；`propose(new_config) -> LevelApplyResult`（本骨架简化为总是 Applied
  并整体替换，真实校验留 TODO）。
- E4 场景：`log_level.toml`（id=`product.log-level`）--模块覆盖生效、未覆盖回退全局、
  enabled 阈值判断、set_global/set_module_level 动态调整、字符串解析。
- 冻结边界（P2.3 不做）：真实接 `tracing`/`log` 后端、EnvFilter 热刷新、指标导出（留 TODO）。

### 12.20 P2.3 故障转移（2026-09-21）{#12-failover}

`failover.rs`（`nexus-connectivity::failover`）：主备故障转移 + 自动回切状态机骨架。

- `FailoverConfig { primary_node, standby_nodes, auto_failback }`：`new` 校验
  `primary_node` 非空；`standby_nodes` 不得含空串、不得重复、不得含 `primary_node`，
  否则 `FailoverError::InvalidPrimary` / `InvalidStandby`。
- `FailoverState`：`Primary` / `Standby { node }` / `FailingOver { from, to }` / `Failed`，
  各带 `as_str()`（"primary"/"standby"/"failing-over"/"failed"）与 Display。
- `FailoverManager`：`new(config)` 初始 `state=Primary`、`active=primary_node`；
  `active_node()` / `state()` / `consecutive_failures()` / `last_failure_ms()` 只读暴露。
- `report_failure(node, now_ms)`：累加连续失败与 `last_failure_ms`；失败节点即当前 active
  时按 standby 列表顺序切到下一个尚未失败的备节点（`FailingOver` -> `Standby`，
  同步骨架内直接落 `Standby`）；无可用备节点 -> `Failed`。
- `report_recovery(node, now_ms)`：`auto_failback=true` 且 `node==primary_node` 且当前不在
  Primary -> 切回 Primary 并清零连续失败；否则仅把该节点标记为可用。
- E4 场景：`failover.toml`（id=`product.failover`）--主失败切首备、连续失败退多备、
  无备 -> Failed、auto_failback 回切、不 auto_failback 不回切、构造校验三类拒绝。
- 冻结边界（P2.3 不做）：真实健康探测、真实流量摘除/挂载、跨进程持久化、真实单调时钟
  （`now_ms` 由调用方注入，留 TODO）。

### 12.21 P2.3 节点发现增强（2026-09-21）{#12-discovery-enhanced}

`discovery_enhanced.rs`（`nexus-connectivity::discovery_enhanced`）：多策略节点发现骨架。

- `DiscoveryConfig { interval_ms, timeout_ms, max_peers }`：`new` 校验三者均 > 0，
  否则 `DiscoveryError::InvalidConfig`。
- `DiscoveryStrategy`：`Multicast` / `Bootstrap` / `Manual`，带 `as_str()`，实现
  `std::str::FromStr`（大小写不敏感，非法返回 `DiscoveryError::InvalidStrategy`）。
- `DiscoveredPeer { node_id, endpoint, last_seen_ms }`：可 Clone/PartialEq/Debug。
- `EnhancedDiscovery`：`new(config)` 默认启用全部三种策略；`enable_strategy` /
  `disable_strategy` / `is_strategy_enabled` 控制策略集合。
- `advertise(strategy, node_id, endpoint, now_ms)`：策略未启用 -> 静默忽略（返回
  `Ok(false)`）；`node_id`/`endpoint` 空串 -> `InvalidAdvertise`；同 `node_id` 已存在
  -> upsert 刷新 endpoint 与 `last_seen_ms`；表满且为新节点 -> 按 `last_seen_ms`
  最旧驱逐一条再插入。
- `prune_expired(now_ms) -> usize`：删除 `now_ms - last_seen_ms > timeout_ms` 的邻居；
  `peer_count()` / `peers_snapshot()`（按 node_id 升序确定性输出）/ `get_peer(node_id)`。
- E4 场景：`discovery_enhanced.toml`（id=`product.discovery-enhanced`）--upsert 去重、
  停用策略忽略、超时清理、max_peers 驱逐最旧、FromStr 解析与非法、快照排序。
- 冻结边界（P2.3 不做）：真实组播收发、bootstrap 服务器查询、TLS 握手、节点真实性校验、
  真实单调时钟（`now_ms` 由调用方注入，留 TODO）。

### 12.22 P2.3 智能重试（2026-09-21）{#12-smart-retry}

`smart_retry.rs`（`nexus-connectivity::smart_retry`）：指数退避 + 错误分类 + 熔断骨架。

- `RetryConfig { max_attempts, initial_delay_ms, backoff_factor, failure_threshold,
  circuit_open_ms }`：`new` 校验 `max_attempts>=1`、`initial_delay_ms>0`、
  `backoff_factor>=1`、`failure_threshold>=1`、`circuit_open_ms>0`，否则
  `RetryError::InvalidConfig`。
- `RetryableClass`：`Retryable` / `Fatal`（由调用方对错误分类后传入）。
- `CircuitState`：`Closed` / `Open { opened_at_ms }` / `HalfOpen`，带 `as_str()`。
- `RetryDecision`：`AllowAttempt { attempt, next_delay_ms }` /
  `StopRetry { reason: &'static str }` / `CircuitOpen { retry_after_ms }`，带 `as_str()`。
- `RetryExecutor`：`compute_backoff(attempt)` 按 `initial_delay_ms *
  backoff_factor^(attempt-1)` 计算（attempt 从 1 开始，saturating 并 cap 到
  `u64::MAX/2`）；`decide(attempt, now_ms)` 在熔断未冷却时返回 `CircuitOpen`，
  冷却期过放行一次 `AllowAttempt`（视为 HalfOpen），超过 `max_attempts` 返回 `StopRetry`，
  否则 `AllowAttempt`。
- `record_success(now_ms)`：清零连续失败、熔断回 `Closed`；`record_failure(now_ms, class)`：
  连续失败 +1，达 `failure_threshold` 即 `Open { opened_at_ms }`；Fatal 在本骨架仅记录，
  停止语义由 `decide` 配合 `max_attempts` 体现。
- E4 场景：`smart_retry.toml`（id=`product.smart-retry`）--退避指数序列、超次数 StopRetry、
  达阈值 Open、冷却期内 CircuitOpen、过冷却放行一次、record_success 复位。
- 冻结边界（P2.3 不做）：真实异步调度、jitter 防惊群、半开后真实试探过渡、真实单调时钟
  （`now_ms` 由调用方注入，留 TODO）。

### 12.23 P2-5 跨子网路由与出口节点（2026-09-21）{#12-cross-subnet}

§12.3 明确 P0 不做跨子网，本节随 P2 解冻（designs P2-5 §118-130）。§12.5 静态路由
为精确 `dst → next_hop`；本节扩展为**前缀路由（CIDR + 最长前缀匹配）**与**出口节点
兜底**，同时保持 §12.5 精确路由语义不变（其场景 expectation 为 Protected）。

- `cidr` 模块（`nexus-connectivity::cidr`，portable：零依赖、可 WASI）：
  - `CidrPrefix { network: u32, prefix_len: u8 }`；
  - `parse_cidr("192.168.5.0/24") -> Result<CidrPrefix, CidrError>`：IPv4 点分十进制
    + `/` + 前缀 0..=32（`0.0.0.0/0` = 默认路由合法）；网络地址主机位必须全零
    （`192.168.5.1/24` 拒绝）；格式/范围非法 → `CidrError`
    （`InvalidFormat` / `InvalidPrefixLength` / `NotANetworkAddress`）；
  - `cidr_contains(&CidrPrefix, ip: &str) -> bool`：ip 解析失败返回 false；
  - `longest_prefix_match<'a>(routes: &'a [(CidrPrefix, String)], ip: &str)
    -> Option<&'a String>`：返回包含 ip 且前缀最长的 next_hop；同长度取表内先者
    （稳定）。
- `VirtualSubnetTunnel` 扩展（§12.5 API 不变，纯增量）：
  - `add_prefix_route(cidr_str, next_hop)`：发送侧前缀路由（cidr 非法 / next_hop
    未注册 → 结构化错误）；`prefix_routes() -> Vec<(String, String)>`（注入顺序）；
  - `add_local_prefix(cidr_str)`：**本节点可达前缀**（接收侧投递边界，如办公室网
    `192.168.5.0/24`）；`local_prefixes() -> Vec<String>`；
  - `mark_egress(virtual_ip)`：把已注册 peer 标记为出口节点；`egress_peers() -> Vec<String>`
    （标记顺序）；
  - **发送/转发决策（send_ip_packet 与 recv 转发统一）**：① dst 是直连 Connected
    peer → 直发；② 精确 `routes[dst]`（§12.5）；③ 前缀路由**最长前缀匹配**；
    ④ 出口节点（egress_peers 顺序第一个）；⑤ 皆无 → `NO_ROUTE_TO_DST`。
    帧头不剥不改语义保持（§12.5）；
  - **接收决策**：`header.dst == 本机 vip` **或命中 local_prefixes** → 写 VPI 并推
    `LocalPrefixDelivered { dst, bytes }` 事件；否则按发送决策转发（精确→前缀→出口）。
  - 新增事件变体 `LocalPrefixDelivered`（VirtualSubnetEvent 扩展，旧事件不变）。
- 出口融合边界（与 §11 代理内核）：组网流量在 VPI 域内转发（VirtualSubnetTunnel 负责）；
  **出口节点收到非本虚拟网段帧后如何出公网 = §11 outbound 代理内核职责**，本批只交付
  "投递到出口节点"语义，不实现 NAT/代理挂接。不修改 §11 已冻结场景。
- 子网通告：节点本地 `add_prefix_route` / `add_local_prefix` 即"我可达 <cidr>"的注入面；
  **经协调器（P2-3）广播子网通告留 P3 公网协调器**（本批冻结不做）。
- E4 场景：`cross_subnet.toml`（id=`product.cross-subnet`）——纯函数
  （parse/cidr_contains/longest_prefix 边界与最长前缀选路）+ 数据面
  （前缀命中投递、本地前缀递送、出口兜底、无路由无出口 NoRouteToDst）。
- 冻结边界（P2-5 不做）：协调器广播子网通告、出口 NAT/公网访问实现、前缀路由
  动态学习与过期（全部留 P3 TODO）。
### 12.24 P2.3 Mesh 域名注册与解析（mesh-dns，2026-09-21）{#12-mesh-dns}
Mesh 网络内节点注册域名（`<node>.mesh`），其他节点可跨节点解析到目标
虚拟 IP 与 node_id（纯内存注册表，不接真实 DNS 协议）。

- 注册：节点加入时注册记录 `domain -> {virtual_ip, node_id, ttl_secs}`；
  未注册域名查询返回 NotFound（NXDOMAIN 语义）。
- 解析：跨节点查询按域名精确匹配，返回目标虚拟 IP 与 node_id；
  注册/解析结果均进入结构化快照（可观察）。
- TTL：注册记录带 TTL，由显式逻辑时钟推进，过期后记录清除
  （不 sleep、不 tokio）。
- E4 场景：`scenarios/product/mesh_dns.toml`（id=product.mesh-dns）——
  A/B 各注册域名、B 查询 node-a.mesh 解析到 10.0.0.1 + node-a、
  未注册域名 NotFound、TTL 过期清除。
- 冻结边界（P2.3 不做）：真实 DNS 服务器/协议（UDP 53）、缓存分层、
  与 §11.5 多 server DNS 路由的挂接（留 TODO）。
### 12.25 P2.3 防火墙规则引擎（firewall-rules，2026-09-21）{#12-firewall-rules}
Mesh 网络流量过滤：默认拒绝白名单 + 声明顺序首匹配（first-match-wins）。

- 规则语言（P0 冻结）：
  - `allow <proto> <cidr> <-> <cidr>`：双向网段放行（如 `tcp 10.0.0.0/24` 互访）；
  - `deny <proto>/<port>`：协议+端口封锁（如 `udp/53` 全部 DNS）；
  - `allow <proto>/<port> from <ip>`：单点放行（可被前置 deny 遮蔽）。
- 决策语义：
  - 未命中任何规则 -> 默认策略（default_policy，P0 冻结为 deny）；
  - 命中规则按声明顺序首条生效（first-match-wins），后置规则不覆盖；
  - 转发包（多跳路由场景）按同一规则集评估（§12.5/§12.6 语义不变）。
- 可观察：default_policy、rule_count、每次决策的 verdict（allow/deny）。
- E4 场景：`scenarios/product/firewall_rules.toml`（id=product.firewall-rules）
  ——入站未授权 deny、白名单 allow、转发 allow、CIDR 命中、
  DNS 封锁、first-match-wins 遮蔽（admin 单点放行被前置 deny 覆盖）。
- 冻结边界（P2.3 不做）：真实网卡挂接/iptables/nftables 改写、
  规则热更新、与 QoS（§12.8）/node_tags（§12.27）联动（留 TODO）。
### 12.26 P2.3 自动断线重连（auto-reconnect，2026-09-21）{#12-auto-reconnect}
连接断开后自动重连：指数退避 + 最大重试 + 状态机（显式逻辑时钟注入，
不 sleep、不 tokio）。

- 退避：首次失败后 `next_delay = initial_delay`（factor^0）；
  连续失败指数翻倍（×backoff_factor），封顶 `max_delay_ms`。
- 重试：达 `max_retries` 进入 GiveUp，不再发起新尝试
  （attempt_count 封顶 = max_retries）。
- 恢复：退避中途成功 -> 回到 Connected、重试计数清零、退避重置为 initial。
- 可观察：退避序列、attempt_count、状态机终态（Connected / GiveUp）。
- E4 场景：`scenarios/product/auto_reconnect.toml`（id=product.auto-reconnect）
  ——initial=100ms、翻倍 200/400、封顶 800、3 次后 GiveUp、
  成功恢复重置。
- 冻结边界（P2.3 不做）：真实调度线程、真实网络监听/心跳、
  与 failover（§12.20）联动（留 TODO）。
### 12.27 P2.3 节点标签（node-tags，2026-09-21）{#12-node-tags}
节点打标（key=value）与按标签过滤/路由选择。

- 标签模型：`NodeTag { key, value }`；字符串 `"key=value"` 解析，
  非法格式结构化拒绝。
- 过滤语义：
  - 精确匹配：`key=value` 命中；
  - 多标签 AND：全部标签均命中才返回；
  - key 存在性匹配：仅要求 key 存在（不限值）。
- 路由选择：按标签组合选择下一跳（如 `role=edge` 且 `tier=1`），
  同候选按声明顺序取先者（确定性）。
- E4 场景：`scenarios/product/node_tags.toml`（id=product.node-tags）
  ——5 节点打标、region=us 命中 2、role=db 命中 2、AND 命中 1、
  key 存在命中 5、无匹配 0、next_hop 选择、标签解析。
- 冻结边界（P2.3 不做）：真实路由表挂接、标签动态传播、
  与 discovery/coord（§12.10/§12.21）联动（留 TODO）。
### 12.28 P3.1 子网 CLI 与 TOML 配置（2026-09-21）{#12-subnet-cli}

产品化第一块：用户可用的 `nexus subnet` 命令族 + TOML 配置格式（designs P3 §132-138）。
CLI 走进程内 SDK（同 `run` 路径），状态为本地文件（默认 `~/.nexus/subnet.json`，
`--state <path>` 可覆盖；NEXUS_HOME 影响默认目录）。

- `nexus subnet up --config <path> [--state <path>] [--encrypt-state] [--json]`：读 TOML → 校验 →
  进程内装配 `VirtualSubnetTunnel`（MeshCarrier mock carrier，真实 TUN 留 P3-2）→
  状态写状态文件（`--encrypt-state` 时以加密形式落盘，§12.31）→
  输出 `{ verdict, command:"subnet up", subnet:{ up, tunnel_id,
  virtual_ip, cidr, peer_count, egress_peer_count, prefix_route_count, encryption } }`。
  同 virtual_ip 重复 up → 幂等覆盖（刷新状态文件）。
- `nexus subnet status [--state <path>] [--json]`：读状态文件输出隧道状态；无状态
  → `{ verdict:"DOWN", command:"subnet status", subnet:{ up:false } }`（exit 0）。
- `nexus subnet leave [--state <path>] [--json]`：删除状态文件 →
  `{ verdict, command:"subnet leave", subnet:{ left:true } }`；无状态 → left:false。
- TOML 配置（`[subnet]` 表）：
  - `cidr`（必填，"10.99.0.0/24"，`cidr::parse_cidr` 校验）；
  - `virtual_ip`（必填，须在 cidr 内——`is_valid_virtual_ip`）；
  - `encryption = false`（默认关，P2-1 §12.7 开关）；
  - `[[peers]]`：`virtual_ip` + `locator`（virtual_ip 须在 cidr 内）；
  - `[[routes]]`：`dst` + `next_hop`（§12.5 精确路由）；
  - `[[prefix_routes]]`：`cidr` + `next_hop`（§12.23 前缀路由）；
  - `local_prefixes = ["192.168.5.0/24"]`（§12.23 本地可达前缀）；
  - `egress = ["10.99.0.2"]`（§12.23 出口节点标记）。
- 配置校验错误（cidr 非法 / virtual_ip 不在子网 / peer 不在子网 / 文件缺失 /
  TOML 解析失败）→ `{ verdict:"CONFIG_ERROR", error:"..." }`（exit 0，结构化）。
- E4 场景：`cli_subnet.toml`（id=`product.cli-subnet`，example 进程内全闭环）——
  up（装配字段）/ status（读状态）/ leave（清除）/ up 幂等 / 配置非法四类拒绝 /
  encryption 开关。
- 冻结边界（P3.1 不做）：真实 TUN（P3-2）、nexusd daemon 托管、持续运行
  （CLI 单次命令语义）、订阅配置热重载。

### 12.29 P3.2 真实 TUN 数据面驱动（2026-09-21）{#12-tun-dataplane}
接 P3.1（§12.28 mock carrier 留真实 TUN 到 P3-2 的边界）：把"装配隧道"从
内存 mock 升级为真实系统数据面。三层：

- **真实承载** `UdpCarrier`（nexus-platform，实现 `PacketCarrier`）：标准 UDP
  socket，非阻塞；locator 格式 `udp://<host>:<port>`（bind 解析并绑定、
  send_to 按 locator 发、receive_into 收一帧，无数据 Ok(0)）。
- **真实虚拟网卡**：
  - Windows：复用 `nexus-platform-windows::WintunVpiAdapter`（窄 wintun C ABI
    绑定已落地，§11.2 后 PRODUCT 记录）：加载签名 `wintun.dll`（wintun.net
    分发）→ 创建命名 Layer3 适配器 → 会话读写 IP 帧；需管理员。
  - Linux：新增 `nexus-platform-linux::TunVpi`（`/dev/net/tun` + ioctl，窄 FFI
    unsafe 集中一个模块，仿 wintun.rs 纪律）；读写 IP 帧；需 root/cap_net_admin。
- **CLI 装配**：`nexus subnet up --tun [--tun-name <n>] [--listen <locator>]` 用真实
  `WintunVpiAdapter`/`TunVpi` + `UdpCarrier` 替代 `MemoryVpi` + `MeshCarrier`；
  无 `--tun` 行为不变（§12.28 mock）。装配失败（dll 缺失 / 权限不足 /
  驱动未安装）→ `{ verdict:"TUN_ERROR", error:"..." }`（exit 0 结构化）。
  `--tun` 时本地 UDP 承载默认绑定 `udp://0.0.0.0:0`（OS 分配端口），可用
  `--listen <locator>` 覆盖。
- 冻结边界（P3.2 不做）：路由表/防火墙改写（网络栈管理能力后置，P3.x）、
  DNS 覆写、多适配器管理、隧道持续运行（daemon 托管留 P3.3）。

E4 场景 `tun_dataplane.toml`：UdpCarrier 本地回环收发对齐（E4 可离线闭环）、
`--tun` 装配错误路径（无 dll/无权限 → TUN_ERROR 结构化）、Linux TunVpi
参数校验纯逻辑。真实设备验收走 E5（Windows 真机：wintun.dll 安装 + 适配器
创建 + 帧读写；管理员权限是前置条件）。

### 12.30 P3.3 加密持久化（secure-store）（2026-09-21）{#12-secure-store}

平台级加密持久化（designs P3 §132-138）：把敏感状态/配置以"系统保护"形式落盘，
替代明文。两层：

- **平台实现**（`SecureStore` trait，get/put）：
  - Windows：`nexus-platform-windows::DpapiSecureStore`——DPAPI 窄 FFI
    （CryptProtectData/CryptUnprotectData，仿 wintun.rs unsafe 纪律）；
    绑定当前 Windows 用户 + 机器，无需管理员。
  - Linux：`nexus-platform-linux::FileSecureStore`——密钥派生自
    `/etc/machine-id`（HKDF-SHA256，ring）+ ChaCha20-Poly1305 AEAD 加密文件；
    文件权限 0600。machine-id 缺失 → `Unavailable`（平台能力缺失）。
- **文件格式**：`NEXSEC1` magic + 12 字节 nonce + ciphertext（ring AEAD）。
- **能力声明**：`caps.secure_store`（Windows DPAPI → true；Linux machine-id
  存在 → true）。缺失时调用方走 `Unavailable` 结构化降级。
- 冻结边界（P3.3 不做）：密钥轮换、多用户密钥共享、TEE/HSM。
  CLI/状态文件加密集成（`subnet up --encrypt-state`）→ P3.4（§12.31）。

E4 场景 `secure_store.toml`：DPAPI put/get 往返 + 缺失键 Ok(None)（Windows
真机，无需管理员）+ machine-id 解析纯函数（合法/非法）+ ring AEAD 加解密
往返 + 文件 magic/密文≠明文。Linux 真机文件权限走 E5（WSL/真实 Linux）。

### 12.31 P3.4 CLI 状态文件加密（2026-09-21）{#12-secure-state}

把 §12.28 状态文件从明文升级为平台加密落盘（§12.30 冻结边界中的 P3.4）。

- `nexus subnet up --config <path> [--state <path>] [--encrypt-state]`：`--encrypt-state`
  时状态 JSON 经平台保护加密后写入状态文件（文件路径语义不变，`--state` 仍指向该文件）。
- **加密状态文件格式**（文件首字节格式 magic 识别）：
  - `NEXSEC1`：Linux machine-id 派生密钥（HKDF-SHA256，§12.30）+ ChaCha20-Poly1305
    AEAD 密文（`NEXSEC1 || nonce(12B) || ciphertext || tag`）；
  - `NEXDP1`：Windows DPAPI blob（`NEXDP1 || CryptProtectData(plain)`，绑定当前用户+机器）。
- `nexus subnet status` 自动检测：`NEXSEC1`/`NEXDP1` 前缀 → 解密后解析；否则按明文
  JSON 解析（向后兼容 P3.1 状态文件）。解密失败（密钥变化 / 篡改）→
  `{ verdict:"STORE_ERROR", error:"..." }`（exit 0，结构化，不 panic）。
- 能力缺失（Linux `/etc/machine-id` 不存在或非法）→ `{ verdict:"STORE_ERROR",
  error:"SECURE_STORE_UNAVAILABLE", ... }`，**不 fallback 明文**（§12.30 Unavailable 语义）。
- `nexus subnet leave` 语义不变（删除状态文件）。
- E4 场景：`secure_state.toml`（id=`product.secure-state`，example 进程内闭环）——
  `--encrypt-state` 后状态文件非明文（含格式 magic）、status 读回加密状态字段、
  leave 清除、篡改/解密失败 → STORE_ERROR。Windows 侧走 DPAPI 真机；
  Linux 侧格式/纯逻辑平台无关（真实 `/etc/machine-id` 走 E5）。
- 冻结边界（P3.4 不做）：状态文件迁移（明文→加密自动转换）、密钥轮换
  （§12.30）、多用户密钥共享、加密状态文件备份恢复。

### 12.32 P3.5 nexusd 托管 subnet 常驻（2026-09-21）{#12-subnet-daemon}

nexusd（daemon 组合根）接入 subnet 真实路径：隧道由 daemon 生命周期持有，
为 serve 常驻控制通道铺路。

- `nexusd subnet up --config <path> [--state <path>] [--encrypt-state] [--foreground]`：
  daemon 组合根直接调用 §12.28/§12.31 语义（TOML 校验 → 装配 → 状态文件，
  `--encrypt-state` 加密落盘）。默认一次性执行（与 `nexus subnet up` 行为一致）；
  `--foreground` 时装配后**常驻**：隧道对象由 daemon 进程持有（进程是 owner），
  持续运行直到 leave 信号（状态文件被删除）或 SIGTERM/Ctrl-C → 优雅退出。
- `nexusd subnet status [--state <path>]` / `nexusd subnet leave [--state <path>]`：
  复用 §12.28/§12.31（自动检测加密格式、STORE_ERROR、明文兼容）。
- **隧道生命周期骨架**：daemon 进程内 `SubnetRuntime` 为隧道唯一 Owner
  （AGENTS §13 结构化并发：up 注册、leave 注销、进程退出随 drop 清理）。
  `--foreground` 常驻进程退出码：正常 leave → 0；被信号终止 → 128+signal。
- E4 场景：`subnet_daemon.toml`（example 进程内 spawn `nexusd subnet up --foreground`
  子进程）——up 后状态文件就绪、`nexusd subnet status` 读回字段一致、
  leave（删除状态文件）后子进程退出、退出后 status → DOWN。
- 冻结边界（P3.5 不做）：daemon serve 控制通道（localapi 常驻命令）、
  隧道热重载、多隧道并发管理、崩溃恢复（§15 冷启动对账）。

### 12.33 P2.3 数据压缩（compression，2026-09-21）{#12-compression}

`compression.rs`（`nexus-connectivity::compression`）：链路载荷压缩选路 + 帧头封装 + 压缩率统计骨架。

- `CompressionAlgorithm`：`None` / `Gzip` / `Lz4`，`as_str()` 稳定标签，`tag()`/`from_tag()` 帧头字节往返（0/1/2）。
- `CompressionConfig { algorithm, level(0-9), min_original_bytes(>=1) }`：`new` 校验；
  level>9 或 min_original_bytes<1 -> `CompressionError::InvalidConfig`。
- `CompressionCodec::new(cfg)`：`should_compress(len)` 在 algorithm!=None 且
  `len >= min_original_bytes` 时为真（自适应门控，小报文透传）；
  `encode(data)` 输出 `CompressedBlock { algorithm_tag, original_len, compressed, payload }`，
  `decode(block)` 对称解出原字节（tag 未知 -> `UnknownAlgorithmTag`）。
- `CompressionStats`：saturating 累计 original/compressed/blocks，`ratio() = 1 - compressed/original`。
- 冻结边界（骨架不做）：真实 gzip/lz4 编解码（引入 flate2/lz4 需 dependency 评审，当前身份透传 + 帧头标记）、
  魔数/校验和、压缩字典协商。
- E4 场景：`compression.toml`（id=`product.compression`）--None 不压缩、低于阈值透传、
  高于阈值标记 compressed、统计 blocks/original/ratio、未知 tag 拒绝。

### 12.34 P2.3 分片传输（fragmentation，2026-09-21）{#12-fragmentation}

`fragmentation.rs`（`nexus-connectivity::fragmentation`）：大报文分片 + 重组 + 超时清理 + 缓冲上限骨架。

- `FragmentConfig { max_fragment_size(>=1), max_reassembly_buffer(>=1), reassembly_timeout_ms(>0) }`：`new` 校验。
- `Fragmenter::fragment(data, packet_id)`：按 max_fragment_size 切成有序
  `Fragment { packet_id, index(0..total), total, payload }`；空 data 也产 1 片（total=1）。
- `Reassembler::push(fragment, now_ms)`：按 packet_id 聚合，重复片幂等；
  收齐 -> `Complete { data }` 并释放上下文，否则 `Waiting { received, total }`；
  total 漂移 -> `TotalMismatch`；缓冲超限 -> `ReassemblyBufferExceeded`。
- `Reassembler::gc(now_ms)`：丢弃 `now_ms - inserted_at_ms > reassembly_timeout_ms` 的未完成上下文，
  返回丢弃个数并释放字节。
- 冻结边界（骨架不做）：真实网络收发、重传/选择性 ACK、序列号抗重放。
- E4 场景：`fragmentation.toml`（id=`product.fragmentation`）--200 字节按 64 切 4 片重组 roundtrip、
  空数据单片完成、重复片幂等、total 漂移拒绝、gc 超时回收、缓冲上限拒绝。

### 12.35 P2.3 证书管理（certificate-manager，2026-09-21）{#12-certificate-manager}

`certificate_manager.rs`（`nexus-connectivity::certificate_manager`）：证书加载骨架 + 过期检查 + 自签名识别 + 原子轮换。

- `CertificateConfig { cert_path, key_path, ca_path: Option }`：非空校验，空串 -> `InvalidConfig`。
- `CertificateInfo { subject, serial, not_before_unix, not_after_unix, self_signed }`：
  `new` 校验 `not_before < not_after`。
- `CertificateManager::new(cfg, current, now)`：构造时校验当前证书已生效且未过期
  （`NotYetValid` / `Expired`）。
- `check_expiry(now, warn_before_secs)` -> `ExpiryStatus::Valid` /
  `ExpiringSoon { remaining_secs }`（remaining<=warn）/ `Expired`（错误）。
- `rotate(new_cert, now)`：新证书必须当前有效，原子替换并返回旧证书，`rotations`+1。
- 冻结边界（骨架不做）：真实 PEM 解析/文件 I/O（当前由调用方在内存构造 CertificateInfo）、
  CA 链构建与 SAN 校验、fs 热轮换监听。
- E4 场景：`certificate_manager.toml`（id=`product.certificate-manager`）--
  未生效/过期证书拒绝构造、Valid/ExpiringSoon/Expired 三态分类、rotate 成功换主并记次数、坏新证书拒绝轮换。

### 12.36 P3.6 加密数据面性能基准（performance-benchmark）（2026-09-22）{#12-perf-benchmark}

加密数据面（P2 链路加密后）的性能预算与基准测量（AGENTS §21 性能规范）：
不允许"优化模糊的更快"——先定义预算，再测基线，产出 benchmark Evidence。

- **测量目标**（`apps/nexus/examples/perf_bench.rs`，E4 进程内闭环）：
  - AEAD 帧路径：`encrypt_frame` + `decrypt_frame` 单帧往返延迟（µs）与
    批量吞吐（MB/s，1 KiB payload × N 帧）；
  - 隧道数据面：`VirtualSubnetTunnel` 加密模式 `send_ip_packet` →
    对端 `recv_and_deliver` 进程内端到端吞吐（MB/s）与往返延迟。
- **Performance Budget（本机基准，随 benchmark 输出固化）**：

  | 指标 | baseline（首次实测） | noise tolerance | warning | blocking |
  | --- | --- | --- | --- | --- |
  | AEAD 帧往返延迟（µs/帧，p50） | 实测记录 | ±30% | > 2× baseline | > 5× baseline |
  | AEAD 吞吐（MB/s） | 实测记录 | ±30% | < 0.5× baseline | < 0.2× baseline |
  | 隧道数据面吞吐（MB/s） | 实测记录 | ±30% | < 0.5× baseline | < 0.2× baseline |
  | 隧道数据面往返延迟（µs） | 实测记录 | ±30% | > 2× baseline | > 5× baseline |

  baseline 首测定格并写入 evidence（含 target/toolchain 环境指纹）；后续回归
  按同一指纹比较。本机噪声 > noise tolerance 时只记 WARN 不 FAIL（除非触
  blocking）。
- **Evidence**：benchmark 输出 JSON（verdict + 各指标数值/单位/threshold 判定）
  落 `.evidence/bench-<id>/`；Full verify 不强制含 perf gate（MVP harness 无
  bench gate），性能回归由本场景 E4 + 手动 `cargo run --example perf_bench`
  复核。
- 冻结边界（P3.6 不做）：热路径微优化（仅建基线）、加密算法替换、跨机
  benchmark、harness bench gate 实现（留 P3.7）。

### 12.37 P3.7 harness bench gate（bench-gate，2026-09-22）{#12-bench-gate}

把 P3.6 的加密数据面性能基准接入 Harness 正式门禁（AGENTS §21 性能规范的
机器化执行）：`nexus-harness bench` 运行 `perf_bench` E4 驱动，解析输出
verdict，按 PRODUCT §12.36 预算表判定；`verify --full` 挂载 `bench` gate。

- **bench gate 语义**：
  - 运行 `cargo run -q -p nexus --example perf_bench -- --json`（repo root）；
  - 输出 verdict=PASS → gate PASS（detail 带四指标摘要）；
  - verdict=WARN → gate PASS + detail 注明（WARN 不阻塞，AGENTS §19.1 语义）；
  - verdict=FAIL → gate FAIL（性能回归阻断）；
  - 命令失败 / JSON 解析失败 / 无输出 → gate UNKNOWN（不静默通过）。
- **挂载**：`[verification.full] gates` 增加 `"bench"`；fast 不挂（保持快速）。
- **baseline 语义**：复用 P3.6 固化基线（`.evidence/bench-p3c04/baseline.json`，
  环境指纹一致时比较；缺失时首次运行重建立）。
- 冻结边界（P3.7 不做）：bench 参数化（帧数/载荷/多轮）、跨机远程基准、
  热路径微优化——均不在本项。

### 12.38 P3.8 nexusd daemon 常驻真实 TUN/UDP 数据面（2026-09-24）{#12-daemon-tun-dataplane}

接 §12.32（P3.5 daemon 常驻但使用 mock MemoryVpi+MeshCarrier）与 §12.29（P3.2
CLI 一次性 `--tun` 真实数据面但随进程退出即 drop）：让 daemon 常驻时承载**真实**
组网数据面（wintun/tun 虚拟网卡 + UDP 承载），对齐 easytier 的常驻形态。

- **命令面**：`nexusd subnet up --config <path> [--state <path>] [--encrypt-state]
  [--foreground] [--tun] [--tun-name <n>] [--listen <locator>] [--json]`。
- **数据面选择**：不带 `--tun` 时行为与 §12.32 逐字节一致（MemoryVpi + MeshCarrier
  mock 常驻），`product.subnet-daemon` 期望保持 Protected。`--tun` 是**显式**数据面
  开关，绝不静默切换。
- **`--tun` 必须与 `--foreground` 同用**：单独 `--tun`（无 `--foreground`）→
  结构化错误 `{ verdict:"FAIL", error:{ code:"CONFIG_ERROR",
  message:"--tun requires --foreground" } }`（exit 0）。`--tun` 的语义就是 daemon
  常驻持有真实隧道；一次性 CLI 形态已由 `nexus subnet up --tun`（§12.29）覆盖。
- **真实数据面装配**（复用 §12.29 的共享装配核心，不复制领域逻辑）：
  `UdpCarrier::bind(listen)` → 平台 VPI create（Windows
  `nexus-platform-windows::WintunVpiAdapter::create(tun_name,"Nexus")`；Linux
  `nexus-platform-linux::TunVpi::create(tun_name)`）→ 共享 `assemble_with`（peers
  建连、mark_egress、`encryption=true` 时 `enable_encryption`）。tun_name 默认
  `nexus0`（经 `validate_tun_name` 校验），listen 默认 `udp://0.0.0.0:0`（OS 分配
  端口）。
- **持有与常驻**：隧道对象由 daemon 进程持有（进程为唯一 Owner，AGENTS §13/§14），
  成功后输出 up JSON（额外含 `local_locator` = UDP 实际绑定地址，与 §12.29 CLI
  一致），随后进入与 §12.32 相同的 200ms 轮询循环；leave（状态文件被删除）→
  优雅退出 0，函数返回时 drop 清理 wintun 适配器与 UDP socket。
- **失败语义（不降级）**：UDP bind 失败或 VPI create 失败（wintun.dll 缺失 /
  非管理员 os error 5 / /dev/net/tun 未就绪）→ 返回
  `{ verdict:"TUN_ERROR", command:"subnet up", error:"TUN_ERROR: ..." }`
  （exit 0），**不写状态文件、不进入常驻循环、绝不静默降级回 mock**。
- E4 场景 `daemon_tun_dataplane.toml`（id=`product.daemon-tun-dataplane`，
  example `daemon_tun_daemon --json`，进程内 spawn `nexusd subnet up --foreground
  --tun`）：非管理员环境 → 第一行 stdout 为 TUN_ERROR 结构化、子进程自行退出
  （exit 0）、状态文件未留下；管理员环境 → 第一行为 PASS 且含 `local_locator`、
  删状态文件后优雅退出 0、退出后 status → DOWN。两种环境都断言
  `daemon_tun.verdict_ok / exited_ok / no_state_left` 为 true。
- 冻结边界（P3.8 不做）：路由表/防火墙改写、DNS 覆写、多适配器管理、隧道热重载、
  crash 后冷启动对账（§15）、serve 控制通道下发 TUN 参数；均沿用 §12.29/§12.32
  既有边界。
### 12.39 P4.1 多节点真实互联：身份密钥与自动交换（2026-09-25）{#12-identity-auto-exchange}

接 §12.38（daemon 常驻真实 TUN/UDP 数据面，单机真实）与 §12.7（加密握手为
**纯 ephemeral**、无身份认证，§12.10 注册标识的防伪造留 P3）：让跨机建连具备
**长期身份 + 首次信任自动交换**（TOFU），支撑公网多节点真实互联（P4 目标：
替代 Clash Verge 的组网形态，对齐 easytier/Tailscale 的互联语义）。

- **身份模型**：每个节点持有**长期 X25519 static 身份密钥对**（`IdentityKeyPair`，
  = 节点身份，`PeerId = static 公钥 SHA-256 前 16 字节`，与 §12.10 coord 注册标识
  一致）；首次运行自动生成并经 secure-store（§12.30）加密持久化（`identity` 记录），
  不落明文配置文件。
- **握手 wire 升级（v2，替代 §12.7 纯 ephemeral 布局）**：`HANDSHAKE_INIT` /
  `HANDSHAKE_RESP` 各携带 `ephemeral_pub ∥ static_pub`（发起方/响应方各自身份公钥）。
  会话派生为 WireGuard 式混合 DH：
  `dh1 = DH(static_priv, eph_pub_peer)`，`dh2 = DH(eph_priv, static_pub_peer)`，
  `dh3 = DH(eph_priv, eph_pub_peer)` → `HKDF-SHA256(dh1 ∥ dh2 ∥ dh3)` → 方向子密钥
  （tx/rx）。**同时提供身份认证与前向保密**；§12.7 既有数据帧 AEAD 布局
  （version|type|seq|nonce 头作 AAD、1024 位滑动重放窗口）不变。
- **自动交换（TOFU，首次信任）**：握手完成时，对端 static 公钥写入 peer 身份表
  （secure-store 加密持久化，**键 = 对端虚拟 IP（VIP）**——同一 VIP 更换身份即
  拒绝，防身份顶替）；后续握手必须匹配已存公钥。
  - 对端 static 公钥与已存不一致 → 握手拒绝，事件 `IdentityMismatch`，
    错误码 `IDENTITY_CHANGED`（防身份替换/MITM）；不落新身份。
  - 无已存身份（首次）→ 自动学习并持久化，事件 `PeerIdentityLearned`。
  - 本端无身份密钥 → 自动生成并持久化，事件 `IdentityKeyGenerated`。
- **驱动接入**：`VirtualSubnetTunnel::begin_handshake` / `accept_handshake` 携带
  本端 `IdentityKeyPair`（由 daemon/CLI 装配注入）；握手完成事件序列与 §12.7
  一致（`HandshakeCompleted → SessionEstablished`），既有 `link-encryption` 场景
  期望 Protected。
- **失败语义**：加密未开启 / peer 未注册 → 沿用 §12.7 结构化错误；身份持久化失败
  （secure-store 不可用）→ 握手拒绝 `IDENTITY_STORE_UNAVAILABLE`，不进入无认证
  降级明文（绝不静默降级）。
- E4 场景 `identity_auto_exchange.toml`（id=`product.identity-auto-exchange`，
  example `identity_auto_exchange --json`，双进程真实 UDP 或内存驱动两种形态）：
  断言 `identity_key_generated`、`first_handshake_learned`、`data_frame_decrypted`（数据帧
  往返，实现补充更严格验证）、`second_handshake_verified`、`identity_mismatch_rejected`
  事件与 `verdict=PASS`；断言位置按 toml `events.3/events.4` 对齐。
- 冻结边界（P4.1 不做）：CA/证书吊销与轮换、SPKI pinning 管理界面、双向 NAT
  打洞与 TURN 中继的**真机**验证（原语已交付 §12.9/turn.rs，留 P4.2）、多节点
  自动发现/`join` 命令（留 P4.3）。
## 13. Windows 系统代理接管与常驻自启（system-proxy + autostart，2026-09-24）{#13-system-proxy}

桌面/Windows 场景下，nexusd 作为本地入口把系统 WinINET 代理指向本地数据面，
并提供开机常驻能力。本项只交付 Windows 平台；非 Windows 显式 `Unavailable`，
不静默降级（PRODUCT §8）。

### 13.1 用户可观察语义

nexusd（Windows）提供子命令（均输出单个 JSON 对象，`--json`）：

```text
nexusd system-proxy status --json
    -> 读取 HKCU\...\Internet Settings 的 ProxyEnable / ProxyServer。
nexusd system-proxy set --server 127.0.0.1:7898 --json
    -> 写 ProxyEnable=1 + ProxyServer=<server>，并广播刷新。
nexusd system-proxy clear --json
    -> 写 ProxyEnable=0，广播刷新（保留 ProxyServer 值，与 Clash 行为一致）。
nexusd system-proxy e2e --json
    -> 自清理闭环：snapshot 原值 -> set 127.0.0.1:7898 -> 读回校验
       -> 无条件恢复 snapshot -> 广播刷新 -> 读回校验一致 -> 输出 verdict。
nexusd autostart install --json | remove --json | status --json
    -> 注册/移除/查询“当前用户登录时启动 nexusd”的计划任务。
```

固定语义：

- 注册表位置固定为
  `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`；
  `ProxyEnable` 为 DWORD(0/1)，`ProxyServer` 为 REG_SZ。
- 任何写注册表后必须紧接 `InternetSetOption(INTERNET_OPTION_SETTINGS_CHANGED)`
  与 `InternetSetOption(INTERNET_OPTION_REFRESH)` 广播；否则注册表改了不生效。
- 演示/默认本地端口固定 **7898**；**禁止使用 7897**（Clash Verge 占用）。
- 所有 `system-proxy` 测试场景必须自清理：setup 记录原始 ProxyEnable/ProxyServer，
  teardown 无条件恢复原值并再次广播刷新；测试结束后注册表值与测试前逐位一致。
  禁止把系统代理留在开启状态。

### 13.2 常驻自启方案（冻结：计划任务，非 Windows 服务）

本项冻结为 **当前用户登录触发的计划任务**，不采用 Windows 服务（`sc.exe`）：

- 理由：WinINET 系统代理是 **HKCU 交互用户** 状态；以 SYSTEM 运行的服务操作的是
  `HKU\.DEFAULT`，无法接管当前桌面用户的代理。计划任务在用户会话内运行 nexusd，
  才能正确读写该用户的 HKCU 代理。
- 触发器：当前用户 ONLOGON；运行身份为当前用户（普通权限，无需 UAC 提权）。
- 动作：启动 `nexusd serve --addr 127.0.0.1:7898`。
- 任务名前缀固定 `nexus-`；**临时测试任务名必须带 `nexus-test-` 前缀**，测试后删除，
  用 `Get-ScheduledTask` / `schtasks /query` 确认无残留。
- 安装/移除经 `schtasks.exe`（在 `nexus-platform-windows` 内 spawn，非 portable core）。

### 13.3 架构与失败语义

- 平台特有代码（注册表 FFI、WinINET 通知、schtasks 调用）只允许存在于
  `nexus-platform-windows`；portable core 不直接调 Win32。
- `nexus-platform` 暴露 trait：`SystemProxyController`（snapshot/apply/refresh）与
  `AutostartRegistrar`（install/remove/status）；Windows 实现经组合根装配到 nexusd。
- 非 Windows 平台：nexusd 子命令返回结构化 `Unavailable`（exit 0，请求已处理）。
- 业务失败用 typed `Result`（`PlatformError`），不以 panic 表达可恢复失败。
- 不操作用户 clash-verge 进程/配置；测试端口避开 7897。

### 13.4 E4 映射

- `scenarios/platform/windows_system_proxy.toml`：`nexusd system-proxy e2e --json`
  自清理闭环（HKCU 读写 + InternetSetOption 广播 + 恢复一致性），E4。
- 计划任务真实 create/start/监听 7898/end/delete 周期为部署环境 E5 smoke
  （需在用户会话内运行），不进 harness 反复门禁；其命令构造/前缀/幂等由
  `nexus-platform-windows` 单元测试覆盖。

- 冻结边界（本项不做）：系统代理 PAC / AutoConfigURL、按进程代理（WPAD/
  per-app）、SYSTEM 服务化、全局 `HKLM` 代理、多用户切换会话代理同步。
