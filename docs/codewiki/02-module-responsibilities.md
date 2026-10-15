# 02 · 主要模块职责（Module Responsibilities）

> 依据：各 crate 的 `MODULE.md`（L1 契约）与源码实测。每个 crate 的权威契约是其
> `MODULE.md` 的 Responsibility / Non-Responsibilities / Invariants 字段，本文是聚合导航。
> ⚠️ 标注「骨架/占位」的 crate 表示契约已冻结但实现尚未填充。

## 层次总览

```text
应用层        apps/nexus（CLI） · apps/nexusd（daemon=Composition Root） · apps/nexus-platform-host
领域运行时    nexus-network · nexus-service · nexus-workspace · nexus-compute · nexus-flow-session
规划调度      nexus-planner（唯一 Core Planner） · nexus-scheduler · nexus-measurement
会话与策略    nexus-session · nexus-policy · nexus-auth · nexus-registry · nexus-discovery
代理产品线    nexus-proxy · nexus-proxy-config · nexus-proxy-transport · nexus-outbound-*
入口与 DNS    nexus-ingress · nexus-dns
投递底座      nexus-delivery · nexus-connectivity · nexus-transport · nexus-path · nexus-projection
存储与持久    nexus-storage · nexus-proto · nexus-control-api · nexus-diagnostics
平台能力      nexus-platform · nexus-platform-{linux,windows,macos,android,ios}
独立产品      nexus-web-gateway（零安装浏览器 SSH 网关） · nexus-fabric（仓库自身工具面）
工程平面      engineering/nexus-harness · evidence-schema · verifiers
```

---

## A. 领域核心与身份层

### nexus-domain — 领域模型核心（依赖图零点）
- **职责**：稳定核心领域类型：Resource / Provider / Node / Intent / Constraint / Plan / Session / Measurement、强类型 ID（`ResourceId`/`ProviderId`/`SessionId`/`NodeId`…）、N3 任务模型（`task::*`）与规范 DTO codec。**零 I/O、零依赖**。
- **不负责**：发现、建连、存储、调度、协议解析。
- **关键不变量**：Resource ≠ Provider；Provider ≠ Node；Identity ≠ Locator；Plan 与 Session 分离；Measurement 是事实不是 Score；核心 Plan 领域中立，领域数据只进版本化 `PlanExtension`。
- **规模**：5 文件 ~3762 行（`lib.rs` 1359、`task/mod.rs` 1178）。[MODULE.md](../../crates/nexus-domain/MODULE.md)

### nexus-registry — 注册视图 / Provider 广告 / 控制面帧
- **职责**：Resource/Provider/Node/Presence/Capability/Locator 的可查询注册视图；Provider 广告（发布/查询/TTL/可见性，D2 双层授权 `Discoverability` vs `UsageGrant`）；N2 控制面 5 帧 wire 编解码与已认证控制通道（`ControlChannel`）；本地资源名字表（`LocalNameTable`）；静态 Provider 导入。
- **不负责**：Bootstrap 网络发现、Planner 评分、建 Link。
- **关键不变量**：Registry 保存事实与广告、不保存业务评分；Identity ≠ Locator。
- **规模**：3 文件 ~1945 行（`control_frame.rs` 1081）。[MODULE.md](../../crates/nexus-registry/MODULE.md)

### nexus-auth — 授权 / Principal / 信任
- **职责**：资源授权与类型化权限判定（`GrantTable`：NoSuchGrant→WrongWorkspace→Revoked→Expired→OperationNotGranted→Allow 顺序判定）；PSK 门控（仅 N1 冻结场景）；ed25519 `Principal`；显式 TOFU `TrustStore`（不自动学习）；审计（`AuditRecord`/`AuditSink`）。
- **不负责**：平台 entitlement、Secret Store 实现。
- **关键不变量**：Publication Policy 与 Resource Authorization 分离；授权失败必须结构化可解释；认证门控在业务帧转发之前（W7）。
- **规模**：1 文件 869 行。[MODULE.md](../../crates/nexus-auth/MODULE.md)

### nexus-policy — FlowContext → Intent/Constraint
- **职责**：把 Flow/Resource Context 转换为 Intent + Constraint（`PolicyEngine` 有序规则链、首匹配即终止；`PolicyAction::{AddConstraint, EnrichMetadata, SelectProvider, Reject}`）；四个领域默认引擎（network/service/compute/workspace）。
- **不负责**：选择协议 / Path / 最终 Provider；不做 I/O。
- **关键不变量**：Policy ≠ Path；未知进程/UID 显式 Unknown，不伪造默认值。
- **规模**：1 文件 590 行。[MODULE.md](../../crates/nexus-policy/MODULE.md)

### nexus-plugin — 混淆传输插件
- **职责**：混淆传输插件机制：`ObfuscateTransport` trait + 接口版本硬校验（`OBFUSCATE_API_VERSION=1`）+ 编译期静态注册（`PluginRegistry`）；统一接线点 `dial_with_obfs`（ss/trojan 真实 outbound TCP dial 唯一接线点）；内置 plain / xor 插件。
- **不负责**：路径/选路插件点、vmess 拨号、dlopen 动态加载。
- **关键不变量**（S1–S7）：插件点唯一；版本注册时硬校验；wrap/dial 失败**不自动回退明文**（防降级攻击）；读写方向各自独立变换。
- **规模**：4 文件 ~838 行，零依赖（std only）。[MODULE.md](../../crates/nexus-plugin/MODULE.md)

### nexus-storage — CAS / KV / Journal
- **职责**：内容寻址存储（`ContentStore` + `FsContentStore`/`InMemoryContentStore`）、crash-consistent KV（`FileKvStore`，temp+fsync+rename）、write-ahead journal（`journal_append/replay`，撕裂尾 fail-closed）、可达性 GC（`ReachabilityGc`：roots 保护 + 保留期双条件）、N3 `StrongContentStore`（SHA-256 强校验）。
- **不负责**：Workspace Merge、WorkingSet、远端 Replica 选择。
- **关键不变量**：内容对象按 hash 寻址；关键更新 crash-consistent；portable-core。
- **规模**：4 文件 ~1398 行。[MODULE.md](../../crates/nexus-storage/MODULE.md)

### nexus-measurement — 事实测量
- **职责**：RTT / Loss / Jitter / Throughput 事实测量（`LinkMeasurement`、`MeasurementTable`）、测速目标（`ProbeTarget`）与延迟探测契约（`LatencyProbe`，真实 I/O 由组合根注入）。全整数数值，未知显式 `None`。
- **不负责**：业务权重、Provider 选择（那是 Planner 的事）。
- **关键不变量**：Measurement ≠ Score；未知 ≠ 好（`rtt_sort_key` 未知排最后）。
- **规模**：1 文件 168 行。[MODULE.md](../../crates/nexus-measurement/MODULE.md)

### nexus-diagnostics — 统一诊断 DTO ⚠️ 骨架
- **职责（契约）**：统一诊断 DTO、诊断类别、低成本/深度诊断接口。
- **现状**：`lib.rs` 仅 7 行编译锚点，**契约已立、实现未动**。
- [MODULE.md](../../crates/nexus-diagnostics/MODULE.md)

---

## B. 会话与规划调度层

### nexus-session — 会话生命周期唯一 Owner
- **职责**：Plan 运行生命周期、Replan、结构化并发、双轨状态（LifecyclePhase / TerminalOutcome）；`SessionManager` 是**唯一 Session Owner**（open/attach/close/complete/`sweep_detached`，attach window 300s）；`SessionOwner::commit_outcome` 是 TerminalOutcome 唯一写入入口（commit-once）；durable `SessionRecord` + 冷启动 `reconcile_session_records`（孤儿恰一次提交 Failed）；Portable 取消原语 `CancelToken`/`AbortOnDropHandle`（std 实现，无 tokio）。
- **不负责**：Planner 逻辑、OS API 绑定。
- **关键不变量**：Worker 只发事件，Owner 唯一提交 Outcome；断开 ≠ Failed（attach window 内可重连）。
- **依赖**：仅 `nexus-domain`，零第三方。**规模**：1 文件 2154 行。[MODULE.md](../../crates/nexus-session/MODULE.md)

### nexus-planner — 全系统唯一 Core Planner
- **职责**：Resource + Intent + Constraint → Provider / Placement / Path / ExecutionStrategy，产出领域中立 `Plan` + `DecisionTrace`。求解模型（吸收 kube-scheduler）：`filter_candidates`（硬谓词短路、结构化 `RejectReason`）→ `connectivity_gate`（可行性门控）→ `score_candidates`（归一化加权，分量之和恒等于总分）→ 确定性选优。`plan explain` 双模式（History/Estimate，estimate 展示"估算非承诺"）。
- **不负责**：网络 I/O、建连；不调用领域 Estimator（代价只作为 `ComputePlanExtension` 类型化输入）。
- **关键不变量**：单一 Core Planner；同等输入产生可解释、可重放的确定性决策；本地优先（`LOCALITY_BONUS` 记入 breakdown）。
- **依赖**：domain / registry / measurement，零第三方。**规模**：1 文件 1227 行。[MODULE.md](../../crates/nexus-planner/MODULE.md)

### nexus-scheduler — 计划任务纯逻辑核心
- **职责**：时间表注册/取消/列表/到期触发（`At` 一次性 / `Every` 周期；`tick` 判定到期并经注入 `SubmitFn` 提交 `TaskIntent`）；快照/恢复（`SchedulerSnapshot`）。
- **不负责**：执行路径、持久化、cron、事件触发、工作流 DAG。
- **关键不变量**：单次触发只提交一次（`At`→`Fired` 永不再触发）；提交失败保持 `Scheduled` 下次重试；不承诺 exactly-once（调用方幂等键处理，PRODUCT §14.4）。
- **依赖**：**零内部依赖**，portable-core（须过 WASI 检查），`forbid(unsafe_code)`。**规模**：1 文件 548 行。[MODULE.md](../../crates/nexus-scheduler/MODULE.md)

### nexus-flow-session — TUN 流→会话映射
- **职责**：5 元组流表 O(1) 查找（`FlowTable`/`FlowEntry`/`FlowDecision`）；新流首包走 `run_first_packet_chain`（FlowContext→Policy→Planner→建 Session），建连经 `ConnectivityEstablisher` 注入后台异步回填（`process_one()` 永不阻塞）；已建流快路径转发、不再调 Planner（`planner_calls` 计数器可证）；UDP 有界缓冲（32 包/64KB，`UdpBuffer`）。
- **不负责**：逐包分类/QoS/DNS 短路（留在 dataplane 快路径）、TUN 句柄、smoltcp TCP 终结。
- **关键不变量**：流表 key = 完整 5 元组；建连失败 → TCP RST / UDP 丢包（不静默黑洞）；空闲 → Draining 无泄漏；NAT 路径切换不改流表项（Identity ≠ Locator）。
- **依赖**：domain / policy / planner / session / network(只读) / measurement；禁止依赖 delivery/ingress。**规模**：5 文件 ~1300 行（有量化 Performance Budget）。[MODULE.md](../../crates/nexus-flow-session/MODULE.md)

### nexus-service — Service Resource（remote P0 骨架）
- **职责**：Nexus-aware Service Session（`ServiceSession::connect` 发 `CONNECT` 帧、收 `READY` 进 Active）；注入帧通道 `ServiceTransport`（组合根以 `FrameStream` 适配）。
- **不负责**：Delivery/Transport 重复实现；`forward` 后置（P0 只冻结 connect）。
- **关键不变量**：非 loopback 监听必须显式授权；Session 双轨状态由 nexus-session 管理。
- **依赖**：domain / session。**规模**：1 文件 103 行。[MODULE.md](../../crates/nexus-service/MODULE.md)

### nexus-connectivity — 连接底座策略编排（本层最重）
- **职责**：Connectivity Evaluation（`evaluate_connectivity` 确定性纯函数）→ 建连状态机（`establish`，认证门控 W7：未认证零发送）→ 链路激活（`LinkActivator`：Direct→Relay 回退，失败只报事实不替换 Provider）；虚拟子网数据面（`VirtualSubnetTunnel`：peer 表/路由/egress/加密/打洞）；链路加密（`encryption`：X25519 ECDH + HKDF-SHA256 + ChaCha20Poly1305 + 1024 位重放窗口）；STUN/HolePunch/NAT 类型决策、TURN Allocate（RFC5766）、DERP 类 `RelayChannel`、身份 TOFU（`IdentityManager`）、入网协调（`BootstrapServer`/`Coordinator`/`VirtualIpAllocator`）；以及 firewall/QoS/cake/压缩/分片/连接池/健康检查/故障转移/优雅退出/热加载/流量统计等冻结契约的纯内存骨架。
- **不负责**：业务 Provider 选择、Workspace/Compute 业务策略、真实网络 I/O（全部经注入 trait）。
- **关键不变量**：Evaluation 是规划输入，Establishment 只在 Plan/Session 之后（禁止先建连后规划）；连接失败只报告事实；认证门控零发送。
- **依赖**：platform / domain / measurement + ring、x25519-dalek、flate2、lz4_flex。**规模**：35 文件 ~24.5k 行（`virtual_subnet.rs` 3308 行最大）。[MODULE.md](../../crates/nexus-connectivity/MODULE.md)

### nexus-discovery — 发现 / Presence / 选路 FIB
- **职责**：Bootstrap、Peer Discovery、Endpoint 交换与 Presence（`PresenceRegistry`：announce/resolve + TTL 过期语义，过期不得使用）；网络发现协议帧（Discover/Announce/PeerUnknown/PeerExpired，`DiscoveryTransport` 注入）；四源聚合发现（`AggregateDiscovery`：Paired > Static > Lsa > mDNS）；LSA 泛洪/LSDB（版本向量 `(incarnation, seq)` 强制递增）；选路算法族（Dijkstra/ECMP/K-shortest/Disjoint，`PathComputer` 可插拔于统一 `Fib`）；mDNS（手写 DNS 子集）、带外配对码 + ed25519 信任建立（`PairedDiscovery`）。
- **不负责**：转发长期业务数据、决定业务 Provider、拥有 Session。
- **关键不变量**：Discovery ≠ Connectivity Establishment（只解析 Endpoint）；Identity ≠ Locator；Bootstrap 不成为已建 Session 的长期数据依赖。
- **依赖**：domain / registry / platform + ring(ed25519)。**规模**：8 文件 ~6.5k 行（`routing.rs` 2364 行最大）。[MODULE.md](../../crates/nexus-discovery/MODULE.md)

---

## C. 平台能力层

### nexus-platform — Portable 宿主能力契约（trait 唯一定义点）
- **职责**：定义全部平台 capability trait：`VirtualPacketInterface`（IP 包读写）、`PacketCarrier`/`UdpCarrier`（承载帧，WireGuard conn.Bind 等价物）、`SecureStore`（+ `secure_store` 模块：machine-id 解析、HKDF 派生、NEXSEC1 AEAD 记录）、`ProjectedWorkspace`（workspace-as-filesystem 投影契约）、`TransparentIngressProvider`、`SystemProxyController`/`AutostartRegistrar`（PRODUCT §13）、`Clock`/`RandomSource`。结构化 `PlatformError`（能力缺失显式 `Unavailable`）。
- **不负责**：任何 Linux/Windows/macOS/Android/iOS 具体 API。
- **关键不变量**：抽象必须过 Deletion Test；OS 类型不得泄漏进 portable trait。
- **规模**：4 文件 ~600 行。[MODULE.md](../../crates/nexus-platform/MODULE.md)

### nexus-platform-linux — Linux 适配器（实现最全）
- **职责**：`TunVpi`（MTU 1420）、`FuseWorkspaceFs`（fuser 0.18，写 stage 进 WorkingSet、`commit()` 落盘）、OS 装配事务（`OsAssemble`：快照/rollback/dry-run，失败自动回滚）、netlink 地址/路由（自研 `NlSocket`，无第三方 netlink 库）、`FileSecureStore`（/etc/machine-id 派生）、`file_lease`（N3 flock 原语）、daemon 化、resolv.conf 管理、操作日志 `OpLog`。
- **关键不变量**：只实现 nexus-platform traits；OS 装配默认不开 default-route（防丢 SSH）；apply 幂等。
- **依赖**：仅 `nexus-platform` + fuser。**规模**：13 文件 ~3541 行。[MODULE.md](../../crates/nexus-platform-linux/MODULE.md)

### nexus-platform-windows — Windows 适配器
- **职责**：`WintunVpiAdapter`（wintun.dll 窄 C ABI 动态加载，手写 LoadLibraryW）、`WinInetSystemProxy`（HKCU Internet Settings + InternetSetOption 广播）、`TaskSchedulerAutostart`（schtasks ONLOGON，非 Windows 服务）、`DpapiSecureStore`、netsh/route IP 配置（防注入）。
- **关键不变量**：能力缺失显式 `Unavailable`；`unsafe` 仅限 `wintun.rs`/`wininet_proxy.rs` 两模块并带 Safety Invariant；WinINET 写路径 SETTINGS_CHANGED+REFRESH 成对调用。
- **依赖**：仅 `nexus-platform`，**零第三方**。**规模**：8 文件 ~1787 行。[MODULE.md](../../crates/nexus-platform-windows/MODULE.md)

### nexus-platform-macos / -android / -ios ⚠️ 骨架
- 三者契约冻结、实现未动（`lib.rs` 7 行锚点），只依赖 `nexus-platform`。
- 已冻结的关键不变量：Android **VPN underlay 必须绕过虚拟接口递归**（防自路由回环）；iOS **Extension 可被强杀，正确性不得依赖 graceful shutdown**。

---

## D. 工作区与智能层

### nexus-workspace — Workspace 权威语义核心
- **职责**：Commit DAG + Head Set 权威模型（`Workspace<S: ContentStore>`：init/open/`commit_changes`/`merge_heads`/`resolve_conflict`/`exchange_heads`/`sync_with_remote`/`reconcile_journal`）；内容哈希 CommitId（`commit_id_of`）；持久化 `ConflictObject`；三种访问通道（`NativeApiWorkspaceAccess` / `MaterializedDirectoryAccess` / NativeMount）与确定性选择（`select_access_provider`）；`WorkspaceProjection`（→ `ProjectedWorkspace` 唯一适配点）；`CacheManager`（驱逐只丢副本）；两阶段 GC（`GcScheduler`：plan→tombstone→sweep + Shallow/Sparse + 配额）；N3 `snapshot`（不可变输入快照 + SHA-256 校验）。
- **不负责**：平台 FUSE/File Provider 实现、绕过 Core Planner 选 Replica/Path。
- **关键不变量**：**CommitId = 内容哈希**（标量序列号永不作版本权威）；离线分叉不丢本地提交；**Cache Eviction ≠ CAS GC**（GC 只删"不可达 + 超保留期"对象）；crash 一致性（`journal_pending → commit → commit_pending` 写前日志 + 幂等回放）。
- **依赖**：domain / session / storage / platform。**规模**：5 文件 ~6162 行（`lib.rs` 4047）。[MODULE.md](../../crates/nexus-workspace/MODULE.md)

### nexus-workspace-intel — 访问智能层（非权威、可丢失）
- **职责**：AccessTrace、WorkspaceGraph（静态依赖图 + 观测访问图）、Profile、`WorkingSetEstimator`（0..=10000 确定性打分）、`PrefetchScheduler`（预取规划，不选 Provider/Path）、`IntelStore`（独立 JSON 持久化，与权威状态物理隔离）、`to_snapshot`（→ Core Planner 的 `PlanningSnapshot`）。
- **关键不变量**：可丢失可重建（删 IntelStore 不影响 workspace 正确性）；纯函数确定性（"现在"取轨迹最大时刻，不读系统时钟）；不选路（Planner ≠ Estimator）。
- **依赖**：domain / workspace(只读) / planner / registry / storage；禁止 transport/fabric（零网络 I/O）。**规模**：8 文件 ~1135 行。[MODULE.md](../../crates/nexus-workspace-intel/MODULE.md)

---

## E. 独立产品与工具

### nexus-web-gateway — 零安装浏览器 SSH 网关 ⭐
- **产品**：每台节点内嵌的浏览器接入网关——浏览器打开 HTTPS 页面自动生成临时身份加入 mesh，网页 xterm.js 终端直开节点上的 SSH。真实 SSH 只在节点↔sshd 之间（ssh2/libssh2），浏览器↔节点只传 pty 字节流；凭证只存内存不落盘。多节点 SDP 信令中继（`MeshSignaler`）+ 打洞失败经首触节点 relay。
- **启动**：`cargo run -p nexus-web-gateway --example gateway -- ./gateway.json`（配置样例 `crates/nexus-web-gateway/examples/gateway.example.json`）。
- **关键不变量**：G1 全程 TLS；G3 SSH 协议不出现在浏览器侧；G4 凭证不落盘；G7 /mesh 端点 bearer 鉴权。
- **依赖**：**零 Nexus 内部依赖、零 async runtime**（纯 std 线程）；str0m（WebRTC）、tungstenite、rustls/rcgen、ssh2。**规模**：9 文件 ~3733 行。[MODULE.md](../../crates/nexus-web-gateway/MODULE.md) / [USER_MANUAL.md](../../crates/nexus-web-gateway/USER_MANUAL.md)

---

## F. 代理栈 / 网络数据面

### nexus-proxy-config — 代理配置模型层
- **职责**：YAML → typed structs（`ProxyConfig`：inbounds / rules / groups / outbounds / dns / speedtest / 订阅）+ 结构化校验（`ConfigError{field, reason}` = `CONFIG_INVALID`）；Clash 订阅解析（`parse_clash_subscription`：base64 + ss://vmess:// URI 行）。Nexus 首个配置文件入口。
- **不负责**：规则匹配、选站、I/O、运行时状态。
- **关键不变量**：解析为纯函数（同一 YAML 恒产出同一 ProxyConfig）；规则表必须以 `MATCH` 结尾；悬空 outbound 引用 → `CONFIG_INVALID`；WASI/portable 可检查。
- **依赖**：**零依赖**（手写 YAML/base64 子集解析）。**规模**：1 文件 ~2360 行。[MODULE.md](../../crates/nexus-proxy-config/MODULE.md)

### nexus-proxy — 规则引擎 + 策略组 + 编排
- **职责**：对 `FlowContext`/`FlowTarget` 执行静态规则表顺序首匹配（`RuleEngine::route`，纯函数零 I/O），产出 `rule_action` 动作链 → 策略组解析（`SelectorGroup` 手动 / `UrltestGroup` 按离线 measurement 选 RTT 最低 / load_balance 轮询 / relay 链式跳序）→ `ProxyService::activate_outbound` 委派 `nexus-connectivity::LinkActivator`（Direct→Relay 回退）。含 TUN per-packet 路由（`TunNatRouter`）与 `.nex` 规则数据解析（`geoip_nex` / `geosite_nex`）。
- **不负责**：SOCKS5 状态机、YAML 解析、真实加密协议栈、第二套 Core Planner。
- **关键不变量**：相同输入恒产出同一 RoutingDecision；`MATCH` 必须在表尾；urltest 缺失 measurement 排后不编造分数；规则引擎不调用 Core Planner、不产生第二套系统级 Plan。
- **依赖**：domain / proxy-config / ingress / connectivity / measurement，**零第三方**。**规模**：4 文件 ~2204 行。[MODULE.md](../../crates/nexus-proxy/MODULE.md)

### nexus-proxy-transport — QUIC over 代理隧道（per-link）
- **职责**：mesh 直连被封时把 QUIC 会话经 SOCKS5 / Shadowsocks / Trojan（可 over TLS）代理隧道承载：代理握手 → TCP → 2 字节长度前缀成帧 → 实现 `nexus-fabric::UdpTransport`（`ProxyTransport`），QUIC driver 零改动接入。与 per-flow 的代理出口决策（nexus-proxy）严格区分。
- **关键不变量**（X/T 系列）：单 datagram ≤1200B，超限报错不静默截断；代理层不触碰 QUIC E2E 加密（双重加密）；AEAD/握手只调 outbound crate 公开原语，握手失败不静默回退直连。
- **依赖**：fabric（仅 `UdpTransport` trait，依赖反转）/ outbound-shadowsocks / outbound-trojan / proxy-config + rustls。**零 tokio（全同步 std）**。**规模**：6 文件 ~2270 行 + 4 个 E4 examples。[MODULE.md](../../crates/nexus-proxy-transport/MODULE.md)

### nexus-ingress — 系统级可移植输入组件
- **职责**：portable SOCKS5 状态机（`Socks5Handshake`，RFC 1928/1929）、HTTP CONNECT 状态机（`HttpProxyHandshake`）、TUN IP 包解码（`TunPacket` / `parse_ipv4_packet`）、Flow 分类与中立 `FlowContext` 构造（`from_socks5` / `from_http` / `from_virtual_packet_interface` / `from_native_api`）。
- **不负责**：平台透明拦截（`nexus-platform-*`）、直接调用 Planner、持有 Network Session、认证凭据库。
- **关键不变量**：握手 Established 前不产出 FlowContext；失败返回结构化 `Socks5Error`；状态机只做协议解析（WASI portable）。
- **依赖**：仅 `nexus-domain`，**零第三方**。**规模**：2 文件 ~1228 行。[MODULE.md](../../crates/nexus-ingress/MODULE.md)

### nexus-dns — 解析器 / DNS 路由 / Fake-IP / Exit-DNS
- **职责**：`DnsRuntime`（缓存 + singleflight + 环路守卫 + RDRC 负缓存 + Exit-DNS Binding）；多 server 规则路由（`DnsRouter` / `MultiServerDns`，缓存按 `(server_tag, name, qtype)` 分表隔离）；统一 DNS（`UnifiedDns`：`hosts > mesh > fake-ip > 上游` 顺序分类应答，`FakeIpPool` 默认 198.18.0.0/15）。
- **不负责**：真实 DNS 传输协议（UDP/TLS/HTTPS 由注入的 `Resolver` 实现）。
- **关键不变量**：singleflight 同 key TTL 窗口内底层至多一次；环路守卫 `LoopDetected` 不挂死；时间以显式 `now_secs` 注入不读系统时钟；`lookup(allocate(d)) == Some(d)`。
- **依赖**：仅 `nexus-domain`，**零第三方**。**规模**：2 文件 ~1634 行。[MODULE.md](../../crates/nexus-dns/MODULE.md)

### nexus-network — InternetAccess 域运行时 + N1 装配
- **职责**：网络域运行时（`NetworkTransport`/`NetworkSession`：establish 往返后才 Active，W7 未认证不进业务）；N1 Universal Connectivity 装配（`N1SessionManager` 每对端一个 Connection、`LinkStateWatcher` keepalive→rebind 漫游观测、`VpiPump` IP 包 ↔ fabric datagram、`N1Config` network.toml 解析含 boost 选路参数）。
- **不负责**：拥有 nexus-ingress、把 TUN 当领域核心、自建第二套 Planner。
- **关键不变量**：不编译依赖 nexus-ingress（由 Composition Root 同时装配）；身份 ≠ Locator（rebind 不换 CID）；持续建连失败只报告事实由 Core Planner 重规划；boost 关闭时行为零回归。
- **依赖**：domain / policy / planner / session / dns / platform(VPI trait)。**规模**：7 文件 ~3551 行。[MODULE.md](../../crates/nexus-network/MODULE.md)

### nexus-path — 路径层（选路 / 竞速 / 回退）
- **职责**：回答"到对端的包现在走哪条路"：候选路径管理（直连→Mesh→TURN→代理出口）、主动探测 + 被动统计打分（`Ewma`）、hysteresis 防抖切换（`PathManager`）、staggered 竞速建连（`race_connect`）、Fallback 链（`FallbackChain`）。纯 std 零 tokio，socket 经 `PathConnector` 注入。
- **关键不变量**（S 系列）：S1 单活跃路径（不做多路径并发）；S2 切换只换 socket 不换 CID；S4 hysteresis（新路径须优 20% 且持续 3s）；S7 诚实分数（无测量标 unknown 不参选）；S9 `PathEvent::Switched` 是切换唯一信号（应用必须排空 `poll_event()`）。
- **依赖**：**零依赖**（纯 std）。**规模**：4 文件 ~2034 行 + 6 个 E4 examples。[MODULE.md](../../crates/nexus-path/MODULE.md)

### nexus-projection — L3 隧道 + 统一路由 + 出口数据面（全 workspace 数据面最大）
- **职责**：① L3 隧道（TUN IP 包 ↔ fabric 数据报，`Projection` / `TunDevice` / `TunRsDevice`）；② 统一路由（`Router`/`UnifiedRouter`/`PacketClassifier`：Mesh > fake-ip > bypass > 规则引擎）；③ 出口（`EgressNat` UDP NAT + `RealUdpEgress` 真实 socket + `TcpTerminator` smoltcp TCP 终结中继 + `SemanticIngress` SOCKS5/HTTP 语义入口 + `ProcessAttributor` 进程归因 QoS + `PathScheduler` 多路径调度 + `DnsSniffer` 嗅探）。
- **不负责**：QUIC 传输（nexus-fabric）、路径选择（nexus-path）。
- **关键不变量**（37 条 S 系列）：S1 包完整（TUN→fabric→TUN 字节级一致）；S5 MTU 诚实（超限丢弃计数不截断）；S10 虚拟子网 fast path 优先；S13 跳数防环（`max_egress_hops` 默认 2）；S25–S27 语义入口走同一决策链、归因失败不影响流建立。
- **依赖**：domain / fabric / ingress / path + smoltcp / tun-rs；禁依赖 nexus-proxy 与 tokio。**规模**：13 文件 ~11.4k 行（`lib.rs` 2103、`tcp.rs` 2062）+ 14 examples。[MODULE.md](../../crates/nexus-projection/MODULE.md)

### nexus-compute — 计算执行会话 + N3 Task
- **职责**：Compute Resource 能力/估计输入/执行会话（`ComputeTransport`/`ComputeJobSession`：submit 往返后才 Active）、Workspace Snapshot Pin、Artifact 登记交付、可选 Write-back；N3 提供方 `TaskOwner`（接受/幂等 `AcceptanceLedger`/状态归约）、`RuntimeState`+journal 崩溃恢复（StartIntent 窗口必须核实，未知不 spawn）、请求方 `RequesterMirror`（不写权威 TaskOutcome）。
- **不负责**：修改 pinned Workspace Commit、复制 Workspace/Delivery 实现。
- **关键不变量**：REJECTED 与协议未识别帧是可诊断失败不吞为成功；Write-back 产生新 Commit；TaskOutcome 与 SessionOutcome 分别由原 Owner 恰一次提交；上传中断不能重跑命令。
- **依赖**：domain / session / workspace（注：MODULE.md Allowed 写 delivery，实际 Cargo.toml 为 workspace——契约/实现一处出入）。**规模**：7 文件 ~1933 行。[MODULE.md](../../crates/nexus-compute/MODULE.md)

### nexus-control-api — 前端统一 API 契约（DTO 层）
- **职责**：CLI/GUI/Agent/SDK 的 Application Service 契约与稳定 DTO：`ControlCommand`（PRODUCT §9 命令枚举）/ `ControlOutput` 视图族；N3 线协议（`TaskRequest`/`TaskResponse`/`TaskEnvelope` 六类操作、`TaskApplicationService`、`TaskCallContext`、日志分页 `MAX_PAGE_BYTES=65536`）+ 规范 JSON 编解码（`wire.rs`，schema_version=1）。
- **不负责**：直接访问 OS/CAS/Transport/Connectivity、承载领域算法。
- **关键不变量**：API 返回结构化 DTO、机器接口版本化；principal 来自已认证上下文不可由请求自填；操作 PASS ≠ task.outcome=Completed。
- **依赖**：仅 `nexus-domain`。**规模**：4 文件 ~883 行。[MODULE.md](../../crates/nexus-control-api/MODULE.md)

### nexus-delivery — 共享投递底座 ⚠️ 骨架
- **职责（契约）**：所有远端 Resource Delivery 共用的 Link/Path/Connection、Delivery Request 与绑定抽象。
- **现状**：`lib.rs` 仅 7 行编译锚点，无公开类型。
- **关键不变量**：Delivery 不得反向依赖 `nexus-workspace` / `nexus-compute`。
- [MODULE.md](../../crates/nexus-delivery/MODULE.md)

---

## G. 传输 / NAT 穿透 / 出站协议

### nexus-transport — 帧流传输（冻结契约）
- **职责**：remote P0 冻结的「TCP + u32 大端长度前缀帧」：`connect`/`accept` → `FrameStream`（`send_frame`/`recv_frame` 每次恰好一帧，天然处理半包粘包；`into_raw()` 取回裸流供 relay 透明中继）。
- **关键不变量**：Transport ≠ Connectivity；帧格式与 `TransportError{ConnectFailed, Closed, Protocol}` 三变体为 Protected。
- **依赖**：仅 `nexus-platform`，纯 std。**规模**：1 文件 94 行。[MODULE.md](../../crates/nexus-transport/MODULE.md)

### nexus-fabric — QUIC-like 会话层（E2E 加密 + 漫游）
- **职责**：`FabricConn` 可靠双向流 + 不可靠数据报 + TLS 1.3 E2E 加密；连接身份 `(PeerId, ConnectionId)`（ed25519 公钥 + 连接 ID，与 UDP 五元组解耦支持漫游 `rebind`）；`FabricListener` 服务端；`UdpTransport` trait 依赖倒置（TURN/代理隧道注入）；PeerId-pinning TLS（`PeerPinVerifier`）；QSEQ datagram 序号契约（多路径重排序号源）。同步 API，quinn-proto driver 跑在自有 std 线程（全栈 tokio-free）。
- **关键不变量**（S1–S11）：S1 E2E 加密（中继只见密文）；S2/S3 漫游不丢数据（流不断不重不漏）；S8 统计诚实（无样本标 unknown 不编 0）；S11 单一 handshake_timeout 预算不产生孤儿连接。
- **依赖**：无内部 crate；quinn-proto（vendor patch）、bytes、rcgen、ring。**规模**：5 文件 2780 行。[MODULE.md](../../crates/nexus-fabric/MODULE.md)

### nexus-nat-traversal — 打洞编排核心（portable，无 MODULE.md）
- **职责**：NAT 打洞状态机（`PunchSession`/`PunchPhase`：Idle→OfferSent→Coordinated→Punching→Validating→Migrated/Failed）、信令编解码（`PunchOffer`/`PunchAnswer`）、候选收集（`LocalCandidates`/`punch_targets`）、Symmetric NAT 端口预测（`PunchPredictor`）。冻结合同 `docs/foundation/NAT-TRAVERSAL-CONTRACT.md`。
- **关键不变量**：打洞 socket 必须与 QUIC 连接同 socket（NAT 映射绑定）；协同开打时间窗冻结（punch_timeout 5s / coord_skew 200ms / spray_k≤32）；不可预测 Symmetric → 显式失败不硬打。
- **依赖**：仅 `nexus-connectivity`（复用 `NatType`），std-only。**规模**：4 文件 958 行。

### nexus-nat-wireup — 打洞生产接线层
- **职责**：把 portable 打洞编排接到真实 fabric driver：`FabricPunchChannel`（中继信令通道）、`DriverPunchSocket`（同 socket QUIC 建连扇出）、`PunchManager`（responder/去重/tie-break/direct 登记）。
- **关键不变量**：`Migrated` = 直连 QUIC 握手已完成；tie-break 确定性（PeerId 大者保留连接，两端独立计算）；中继连接 Migrated 后不关闭（warm backup）；nonce 挑战-应答绑定；D5 stream 分流（非 punch 流入 `unclaimed` 队列）。
- **依赖**：fabric / nat-traversal / connectivity。**规模**：4 文件 1568 行。[MODULE.md](../../crates/nexus-nat-wireup/MODULE.md)

### nexus-nat-quality — NAT 路径质量测量
- **职责**：对 `FabricConn` 做 datagram ping/pong 探针测丢包 + 复用 quinn 真实 RTT，后台线程把 `PathStats` 供给 `PathManager::on_stats`（R3：loss 是必答题，纯 RTT 下 direct 恒胜违背"打洞成功≠最优"）。
- **关键不变量**：探针帧 25B 冻结格式（`NXQPROB!`），非探针 datagram 原样转交；无完成样本 `loss_rate=None`（不参选）；后台线程 stop+join 不泄漏。
- **依赖**：fabric / path，std-only。**规模**：4 文件 1043 行。[MODULE.md](../../crates/nexus-nat-quality/MODULE.md)

### nexus-turn — RFC 5766 TURN 最小实现
- **职责**：TURN client（`TurnClient`：allocate/refresh/create_permission/bind_channel）+ `TurnSocket`（实现 fabric `UdpTransport`，QUIC 跑在 TURN 中继上）+ 最小 server（仅 E4 自测）+ STUN 编解码 + 长效认证（HMAC-SHA1）。
- **关键不变量**：T1 最小子集冻结；T2 中继不解密只转发；T3 权限模型（未 CreatePermission 丢弃计数）；T4 分配 600s 过期显式 `AllocationExpired` 不黑洞；全同步 std API。已知限制诚实记录（控制/数据面共享 socket、401 stale-nonce 差异）。
- **依赖**：fabric（仅 `UdpTransport` trait）+ hmac/sha1/md5。**规模**：6 文件 2128 行。[MODULE.md](../../crates/nexus-turn/MODULE.md)

### 出站协议 Adapter（统一 `OutboundAdapter` 接缝，`outbound_kind()` 稳定标签）

| crate | 协议 | 要点 | portable | 规模 |
|---|---|---|---|---|
| [nexus-outbound-shadowsocks](../../crates/nexus-outbound-shadowsocks/MODULE.md) | Shadowsocks AEAD | method 冻结 `chacha20-ietf-poly1305`；HKDF 双向 key；离线确定性 nonce（固定计数器） | 否 | 461 行 |
| [nexus-outbound-vmess](../../crates/nexus-outbound-vmess/MODULE.md) | VMess AEAD | UUID→SHA-256→会话 key；`nonce||ct+tag` 记录层；不宣称逐字节线格式兼容 | 否 | 220 行 |
| [nexus-outbound-trojan](../../crates/nexus-outbound-trojan/MODULE.md) | Trojan (TLS) | rustls + `hex(SHA-224(pwd))` 请求头（trojan-gfw 线格式）；密码不匹配→`AUTH_DENIED` 不泄密；证书 pinning | 否 | 502 行 |
| [nexus-outbound-anytls](../../crates/nexus-outbound-anytls/MODULE.md) | AnyTLS v2 | TLS 上多路复用会话层（clean-room，docs/protocols/anytls.md）；认证帧单次 write；Settings/padding-md5 协商；UDP-over-TCP | 否 | 1662 行 |
| [nexus-outbound-vless](../../crates/nexus-outbound-vless/MODULE.md) | VLESS (+XTLS-Vision) | 请求头字节序逐字节锁定；握手不阻塞读响应；未知 flow/command fail-closed；错误不回显 UUID | **是** | 1786 行 |
| [nexus-outbound-hysteria2](../../crates/nexus-outbound-hysteria2/MODULE.md) | Hysteria2 | QUIC + 最小 HTTP/3 认证（`:status 233`）+ Salamander 混淆 + QPACK 最小子集；自写 sans-IO driver；诚实边界：Huffman/Brutal CC 未实现 | 否 | 3292 行（13 文件，最大 outbound）|

统一不变量：adapter 是开放接缝（新增协议=新增实现，不改选路/激活路径）；离线确定性（E4 可复现）；握手失败不静默回退明文。

### nexus-proto — wire schema 边界 ⚠️ 骨架
- **职责（契约）**：wire/control contract 的 portable schema 边界与代码生成占位。
- **现状**：`lib.rs` 7 行，全 workspace 最小 crate。不变量：Wire schema 必须显式版本化；内部领域类型不得直接等同 wire DTO。[MODULE.md](../../crates/nexus-proto/MODULE.md)

---

## H. 应用层（apps/）

### apps/nexus — CLI（thin-client + SDK 组合根）
- **定位**：用户 CLI 前端，`forbid(unsafe_code)`；参数解析 → `ControlCommand` → 渲染结构化结果。同时是 **SDK Composition Root**（lib.rs）：跨 ingress/policy/planner/session 的装配只能发生在 app 层。
- **四类命令路径**：① daemon LocalAPI thin-client（7 个观察命令；无路由命令本地合成 `UNSUPPORTED`，**禁止回退进程内 observability**）；② N3 thin-client（`task`/`artifact` 命令族，POST /localapi/v1/task）；③ 进程内 SDK 命令族（`subnet`/`schedule`/`proxy`/`speedtest`/`pair`/`node`/`plan`/`use`/`session`/`resource`/`grant`/`provider`/`network`/`run`…）；④ 诚实拒绝（`run <resource> -- <cmd>` → `UNSUPPORTED{feature:"run-with-command"}`，命令执行语义归 N3）。
- **与 daemon 关系**：unix socket `$XDG_RUNTIME_DIR/nexus-localapi.sock`（缺失退私有 tmp 目录再退 TCP loopback）+ bearer token（`~/.config/nexus/localapi.token`，0600）；客户端只发最小 HTTP/1.1、不解析业务语义、不重试。
- **exit 语义**：0 = 业务结果（含 verdict=FAIL / DAEMON_UNREACHABLE），2 = 用法错误。[MODULE.md](../../apps/nexus/MODULE.md)

### apps/nexusd — 守护进程（主 Runtime Composition Root）
- **入口**：`nexusd <config-folder>`（缺配置文件 = 对应子系统不启用；缺 proxy.yaml 且缺 network.toml 拒绝启动）；配置热加载 2s 轮询（`Hot` / `NeedsRestart` 分类）。
- **关键模块**：`assembly.rs`（装配胶水：N1 桥接、mesh CIDR 配置化、关闭顺序）；`dataplane.rs`（统一数据面 D1–D6：单 TUN `nexus0` → DNS 短路 → `PacketClassifier` → CAKE QoS → 多路径/Boost → 转发；含 smoltcp TCP 终结与 ProxyEngine）；`task_executor.rs`（N3 Linux 执行适配器：Docker 隔离、operator 批准镜像、日志分页、orphan 标记）；`recovery.rs`（冷启动 `boot_reconcile`：journal 重放 → session/workspace/task 对账 → orphan 幂等清理 → 发布 Presence → 才接受新任务）；`workspace.rs`（FUSE 挂载 + CAS + 显式 commit + orphan `fusermount -u`）。
- **冻结契约**：daemon 内全系统唯一 SessionManager（`N2_SESSION_MANAGER` OnceLock + 30s sweeper）；`nexusd run <resource> --json`（未知资源→`UNKNOWN_RESOURCE`，exit 0）；SIGTERM/SIGINT 关闭顺序（LocalAPI 停收 → Workspace unmount → dataplane join 1s → N1 shutdown 5s → TUN 关闭 → exit 0）。[MODULE.md](../../apps/nexusd/MODULE.md)

### apps/nexus-platform-host — 平台能力注入锚点
- 极小组合根（58 行）：按 feature 装配 `nexus-platform-*` adapter；唯一子命令 `vpi-capabilities [--json]`（Windows VPI 能力声明，供 E4 机检）。Allowed Dependencies 仅 `nexus-platform`。[MODULE.md](../../apps/nexus-platform-host/MODULE.md)

---

## I. 工程平面（engineering/）

### engineering/nexus-harness — 工程门禁 Harness
- **定位**：Agent/Human/CI 共享的 Project Discovery、Context、Affected Analysis、Command Execution、Policy Evaluation、Evidence Writing、Failure Explanation。不拥有产品真相、不改业务代码。
- **命令**：`status` / `context <target>` / `check` / `test affected` / `verify --fast|--full` / `explain` / `scenario list|run` / `code <verb>`（语义查询，authority 恒 advisory）/ `bench` / `replay`（显式 UNKNOWN）/ `run`。
- **Evidence**：verify 后写 `.evidence/verify-<agent>-<hash>/`（summary/gates/metadata 三件），绑定 9 项 freshness bindings，旧证据 STALE 扫荡 + `latest.json`；schema 见 [engineering/evidence-schema/evidence.schema.json](../../engineering/evidence-schema/evidence.schema.json)。
- **Gate 清单单一真相源**：`policies/quality.toml [verification.fast|full]`（fast 8 gates / full 14 gates）。[MODULE.md](../../engineering/nexus-harness/MODULE.md)

### 其他
- `engineering/evidence-schema/`：Evidence JSON Schema（draft 2020-12，verdict 枚举 PASS/FAIL/STALE/UNKNOWN/BLOCKED，evidence_strength E0–E5）。
- `engineering/verifiers/`：E4 场景外部校验器（Python：n3_artifact_cli / n3_foundation_boundary / n3_operator_grant）。
- `engineering/plugins/`：插件契约（plugin-contract.md）。
