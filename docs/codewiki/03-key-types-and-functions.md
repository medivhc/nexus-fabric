# 03 · 关键类型与函数（Key Types & Functions）

> 按"写代码时最常需要定位"的顺序组织：领域模型 → 会话/规划 → 连接/数据面 → 代理 →
> 传输/出站 → 平台/工作区 → 应用/工程。每个条目给出**一句话作用**与**源码位置**。
> 完整 API 以各 crate `MODULE.md` 的 Public API 节与 `cargo doc` 为准。

## 1. 领域模型（nexus-domain）

文件：[lib.rs](file:///workspace/crates/nexus-domain/src/lib.rs)（1359 行）、[task/mod.rs](file:///workspace/crates/nexus-domain/src/task/mod.rs)（1178 行）

| 符号 | 作用 |
|---|---|
| `ResourceId` / `ProviderId` / `SessionId` / `WorkspaceId` / `NodeId` | 强类型 ID newtype（Identity ≠ Locator） |
| `ResourceRef{workspace, name}` / `ResourceKind` / `ResourceOperation` | 资源命名寻址与操作词汇 |
| `Intent` / `Constraint` / `FlowContext` / `FlowOrigin` | 规划输入 DTO（Ingress → Policy → Planner 的传递载体） |
| `Plan` + `PlanExtension::{Network, Workspace, Compute, Service}` | 领域中立核心 Plan；领域数据只进带 `version` 的类型化扩展 |
| `ConnectivityEvaluation`（`has_feasible_path()`） | 规划期连通性可行性 DTO（`estimated_setup_cost_ms: None` = 无可行路径） |
| `RejectReason` / `ScoreComponent` / `ConsideredCandidate` / `DecisionTrace` | 规划决策轨迹（"为什么没被选"的唯一出口；score 分量之和恒等于总分） |
| `PlanId` / `plan_id_of` / `fnv1a_64_hex` | FNV-1a 确定性 Plan 标识（同输入跨运行恒同 Id） |
| `PlanSnapshot{plan_id, plan, decision_trace}` | 一次规划决策的不透明记录 |
| `LifecyclePhase` / `TerminalOutcome` / `SessionStatus` | 生命周期与业务结果双轨分离 |
| `NexusError` / `FailureDisposition` | 结构化失败枚举（PRODUCT §2 七类 + Unsupported/Internal）+ 处置（Retry/Fallback/Abort/Escalate） |
| `task::{TaskId, ArtifactId, SnapshotId, SubmitTaskRequest, TaskView, TaskExecution, TaskDelivery, TaskOutcome…}` | N3 任务模型（TaskPhase ≠ TaskOutcome；JSON 形状由 `docs/contracts/n3-task-v1.schema.json` 冻结） |
| `codec::CanonicalDto` / `validation::relative_path` | 规范编码（产生 digest）与路径安全校验 |

## 2. 会话与规划

### nexus-session（[lib.rs](file:///workspace/crates/nexus-session/src/lib.rs)，2154 行）

| 符号 | 作用 |
|---|---|
| `SessionOwner::commit_outcome` | **TerminalOutcome 唯一写入入口**（commit-once 守卫） |
| `SessionOwner::transition_phase` | 合法 LifecyclePhase 迁移校验 |
| `SessionEvent`（Started/PhaseChanged/Progress/CancellationRequested/ConnectivityEstablished/Failed/OutcomeCommitted） | Worker 上报事件（Worker 只发事件） |
| `SessionManager`（`open`/`attach`/`close`/`complete`/`note_provider_lost`/`note_revoked`/`sweep_detached`） | 会话生命周期唯一 Owner；attach window 默认 300s |
| `SessionRecord` + `SessionRecordStore` | 轻量 durable marker（存储由 Composition Root 注入） |
| `reconcile_session_records` | 冷启动幂等 reconcile（孤儿恰一次提交 Failed） |
| `CancelToken` / `AbortOnDropHandle` | std 结构化并发原语（Portable，无 tokio） |

### nexus-planner（[lib.rs](file:///workspace/crates/nexus-planner/src/lib.rs)，1227 行）

| 符号 | 作用 |
|---|---|
| `PlanningSnapshot` | 一次规划周期的一致视图 |
| `filter_candidates` | Filter 硬谓词短路 → 结构化 `RejectReason` |
| `connectivity_gate` | 可行性门控纯函数（无可行路径 → `NoFeasibleConnectivityPath`） |
| `score_candidates` | 归一化加权打分（`rtt` + `locality` 分量，`LOCALITY_BONUS` 恒给本地 Provider） |
| `plan_from_snapshot` / `plan` → `Planned{plan, trace}` | K2→K3→确定性选优组装 |
| `ExplainMode` / `classify_explain_arg` / `PlanHistory` / `ExplainedPlan` | `plan explain` 双模式（History/Estimate；查无记录不回退重算） |

### nexus-scheduler（[lib.rs](file:///workspace/crates/nexus-scheduler/src/lib.rs)，548 行）

`Scheduler`（`register`/`cancel`/`list`/`tick`/`snapshot`/`restore`）、`ScheduleSpec::{At, Every}`、`ScheduleEntry`、`TriggerRecord`（失败不静默丢弃）、`SubmitFn`（注入提交回调）。

### nexus-flow-session

- [flow.rs](file:///workspace/crates/nexus-flow-session/src/flow.rs)：`FlowKey`/`FlowEntry`/`FlowTable`（5 元组 O(1)）、`FlowDecision::{NewSession, Forward, Drop, BufferForSession}`、`FlowPhase`
- [manager.rs](file:///workspace/crates/nexus-flow-session/src/manager.rs)：`SessionManager`（流→会话映射 Owner，`planner_calls` 计数器证明快路径不调 Planner）、`ConnectivityEstablisher`（注入 trait）、`EstablishEvent`/`FlowSignal`
- [chain.rs](file:///workspace/crates/nexus-flow-session/src/chain.rs)：`run_first_packet_chain`（首包链纯函数：Policy→Planner→建 Session）
- [buffer.rs](file:///workspace/crates/nexus-flow-session/src/buffer.rs)：`UdpBuffer`（32 包/64KB 有界缓冲）

## 3. 策略 / 授权 / 注册 / 发现

| crate | 关键符号 | 作用 |
|---|---|---|
| nexus-policy [lib.rs](file:///workspace/crates/nexus-policy/src/lib.rs) | `PolicyEngine::evaluate` | 有序规则链首匹配；`PolicyAction::{AddConstraint, EnrichMetadata, SelectProvider, Reject}` |
| nexus-auth [lib.rs](file:///workspace/crates/nexus-auth/src/lib.rs) | `GrantTable::authorize` | 顺序判定 NoSuchGrant→WrongWorkspace→Revoked→Expired→OperationNotGranted→Allow |
| | `PreSharedToken`/`verify_token` | PSK 常量时间门控（仅 N1 场景） |
| | `Principal` / `TrustStore` / `TrustVerdict` | ed25519 主体标识；显式 TOFU（`check` 不自动学习） |
| nexus-registry [advertisement.rs](file:///workspace/crates/nexus-registry/src/advertisement.rs) | `Registry`（`register`/`candidates`/`publish_ad`/`lookup_ads`…） | Provider 事实 + 广告生命周期（TTL 过期拒绝使用） |
| | `ProviderAdvertisement` / `Discoverability` / `UsageGrant` | D2 双层授权（可见 ≠ 可用） |
| | `LocalNameTable` | `ResourceRef` → `ResourceId` 本地解析 |
| [control_frame.rs](file:///workspace/crates/nexus-registry/src/control_frame.rs) | `ControlFrame`（5 种）/ `encode_control_frame` / `ControlChannel` | N2 控制面协议帧与已认证通道 |
| nexus-discovery [lib.rs](file:///workspace/crates/nexus-discovery/src/lib.rs) | `PresenceRegistry`（`announce`/`resolve`） | 动态 Presence + TTL（过期 Endpoint 不得返回） |
| | `Discovery` trait / `StaticDiscovery` / `AggregateDiscovery` | 四源聚合（Paired > Static > Lsa > mDNS） |
| [lsa.rs](file:///workspace/crates/nexus-discovery/src/lsa.rs) | `Lsa` / `Lsdb` / `LsaDiscovery` | LSA 泛洪 + LSDB（`(incarnation, seq)` 版本向量） |
| [routing.rs](file:///workspace/crates/nexus-discovery/src/routing.rs) | `PathComputer`（`ShortestPath`/`Ecmp`/`KShortest`/`Disjoint`）/ `Fib`/`FibManager` | 选路算法族 + RCU 风格 FIB 全量重算 |
| [paired.rs](file:///workspace/crates/nexus-discovery/src/paired.rs) | `PairingCode` / `PairedDiscovery` | 带外配对码 + ed25519 信任建立（配对 ≠ 建连） |

## 4. 连接底座（nexus-connectivity，35 文件 ~24.5k 行）

| 符号 | 位置 | 作用 |
|---|---|---|
| `establish` / `EstablishmentRequest` / `ConnectivityState` | [lib.rs](file:///workspace/crates/nexus-connectivity/src/lib.rs) | 建连纯函数状态机（认证门控 W7：未认证零发送） |
| `ConnectivityRuntime` | lib.rs | 注入 `VirtualPacketInterface` + `PacketCarrier` 双 trait 编排 |
| `LinkActivator` + `LinkProbe`/`LinkKind`/`LinkSelection` | lib.rs | Direct→Relay 回退激活（失败只报事实不替换 Provider） |
| `LinkMarker` + `reconcile_link_markers` | lib.rs | 链路 durable marker 冷启动幂等 reconcile |
| `VirtualSubnetTunnel` | [virtual_subnet.rs](file:///workspace/crates/nexus-connectivity/src/virtual_subnet.rs)（3308 行） | 虚拟子网数据面（peer 表/路由/egress/加密/打洞/管线挂接） |
| `encryption::{KeyPair, DirectionalKeys, encrypt_frame, ReplayWindow}` | [encryption.rs](file:///workspace/crates/nexus-connectivity/src/encryption.rs) | X25519 ECDH + HKDF-SHA256 + ChaCha20Poly1305 + 1024 位重放窗口 |
| `StunClient` / `HolePuncher` / `NatType` / `nat_path_decision` | [nat.rs](file:///workspace/crates/nexus-connectivity/src/nat.rs) | STUN 探测 / 打洞 / NAT 类型驱动路径决策 |
| `TurnClient` + `build_allocate_request` | [turn.rs](file:///workspace/crates/nexus-connectivity/src/turn.rs) | RFC5766 Allocate 编排（401 挑战→MESSAGE-INTEGRITY） |
| `RelayChannel` / `RelayState` | [relay.rs](file:///workspace/crates/nexus-connectivity/src/relay.rs) | DERP 类字节中继状态机 |
| `IdentityManager` / `IdentityAction` | [identity.rs](file:///workspace/crates/nexus-connectivity/src/identity.rs) | 身份密钥 + TOFU 自动交换（公钥更换 → `IdentityRejected`） |
| `evaluation::evaluate_connectivity` | [evaluation.rs](file:///workspace/crates/nexus-connectivity/src/evaluation.rs) | v9 §8.1 确定性纯函数（全整数） |
| `BootstrapServer` / `Coordinator` / `VirtualIpAllocator` | [bootstrap_server.rs](file:///workspace/crates/nexus-connectivity/src/bootstrap_server.rs)、[coord.rs](file:///workspace/crates/nexus-connectivity/src/coord.rs) | 入网协调 + 自动 VIP 分配 |

## 5. 网络域 / 路径 / 数据面

| crate | 关键符号 | 作用 |
|---|---|---|
| nexus-network | `NetworkTransport` / `NetworkSession`（[lib.rs](file:///workspace/crates/nexus-network/src/lib.rs)） | 远程网络会话（establish 往返后才 Active） |
| | `N1SessionManager` / `LinkStateWatcher` / `VpiPump`（`n1/`） | N1 连接表 / keepalive→rebind 漫游 / IP 包泵 |
| nexus-path | `PathManager`（`current_path`/`on_stats`/`poll_event`/`score`）（[lib.rs](file:///workspace/crates/nexus-path/src/lib.rs)） | 候选打分 + hysteresis 切换决策 |
| | `race_connect` / `FallbackChain` / `connect_with_fallback`（[race.rs](file:///workspace/crates/nexus-path/src/race.rs)、[fallback.rs](file:///workspace/crates/nexus-path/src/fallback.rs)） | staggered 竞速建连 / 回退链 |
| | `Ewma`（[ewma.rs](file:///workspace/crates/nexus-path/src/ewma.rs)） | per-path 指数加权移动平均（无样本 = unknown） |
| nexus-projection | `Projection` / `TunDevice` / `TunRsDevice`（[lib.rs](file:///workspace/crates/nexus-projection/src/lib.rs)） | L3 隧道主循环（TUN IP 包 ↔ fabric datagram） |
| | `Router` / `UnifiedRouter` / `PacketClassifier`（[routing.rs](file:///workspace/crates/nexus-projection/src/routing.rs)、[classifier.rs](file:///workspace/crates/nexus-projection/src/classifier.rs)） | 统一包分类（Mesh > fake-ip > bypass > 规则引擎） |
| | `EgressNat` / `RealUdpEgress` / `TcpTerminator` / `TcpRelay`（[egress.rs](file:///workspace/crates/nexus-projection/src/egress.rs)、[tcp.rs](file:///workspace/crates/nexus-projection/src/tcp.rs)） | UDP NAT + 真实出口 + smoltcp TCP 终结中继 |
| | `SemanticIngress`（[semantic.rs](file:///workspace/crates/nexus-projection/src/semantic.rs)） | SOCKS5/HTTP 语义入口映射为 fabric 流 |
| | `PathScheduler` / `ReorderBuffer`（[multipath.rs](file:///workspace/crates/nexus-projection/src/multipath.rs)） | 多路径调度 + RFC1982 回绕感知重排 |
| | `ProcessAttributor` / `QosConfig`（[process.rs](file:///workspace/crates/nexus-projection/src/process.rs)） | 进程归因 + QoS 标记 |
| nexus-dns | `DnsRuntime` / `Resolver`（[lib.rs](file:///workspace/crates/nexus-dns/src/lib.rs)） | 缓存 + singleflight + 环路守卫 + Exit-DNS Binding |
| | `DnsRouter` / `MultiServerDns` | 多 server 规则路由（缓存按 server_tag 分表） |
| | `UnifiedDns` / `FakeIpPool`（[unified.rs](file:///workspace/crates/nexus-dns/src/unified.rs)） | `hosts > mesh > fake-ip > 上游` 统一分类应答 |

## 6. 代理内核

| crate | 关键符号 | 作用 |
|---|---|---|
| nexus-proxy-config | `ProxyConfig` / `parse(yaml)` / `ConfigError`（[lib.rs](file:///workspace/crates/nexus-proxy-config/src/lib.rs)） | YAML → typed structs + 结构化校验（CONFIG_INVALID） |
| | `parse_clash_subscription` | base64 订阅 + ss://vmess:// URI 解析 |
| nexus-proxy | `RuleEngine::route(&FlowTarget) -> RouteOutput`（[lib.rs](file:///workspace/crates/nexus-proxy/src/lib.rs)） | 静态规则表顺序首匹配（纯函数零 I/O） |
| | `ProxyService`（`activate_outbound`） | route → group resolve → LinkActivator 委派 |
| | `SelectorGroup` / `UrltestGroup` / `OfflineMeasurements` | 策略组（手动 / RTT 自动选优） |
| | `TunNatRouter`（[tun.rs](file:///workspace/crates/nexus-proxy/src/tun.rs)） | TUN per-packet 决策 + 5 元组缓存 |
| | `geoip_nex::parse` / `geosite_nex::parse` | `.nex` 规则数据二进制解析 |
| nexus-ingress | `Socks5Handshake` / `HttpProxyHandshake`（[lib.rs](file:///workspace/crates/nexus-ingress/src/lib.rs)） | 协议状态机（`feed()` 增量喂字节） |
| | `from_socks5` / `from_http` / `from_virtual_packet_interface` | 按 FlowOrigin 构造中立 `FlowContext` |
| | `parse_ipv4_packet`（[ip_packet.rs](file:///workspace/crates/nexus-ingress/src/ip_packet.rs)） | IPv4 TCP/UDP 五元组解析（非法一律 None） |
| nexus-proxy-transport | `ProxyTransport`（[framed.rs](file:///workspace/crates/nexus-proxy-transport/src/framed.rs)） | 2 字节长度前缀成帧的 `UdpTransport` 实现 |
| | `socks5_connect` / `SsTransport` / `TrojanTransport` / `TlsTrojanTransport` | 三种代理隧道传输 |

## 7. 传输 / NAT / 出站

| crate | 关键符号 | 作用 |
|---|---|---|
| nexus-transport | `connect` / `accept` / `FrameStream::{send_frame, recv_frame, into_raw}`（[lib.rs](file:///workspace/crates/nexus-transport/src/lib.rs)） | TCP + u32 BE 长度前缀帧（冻结契约） |
| nexus-fabric | `FabricConn`（`connect`/`open_bi`/`accept_bi`/`send(_seqed)_datagram`/`rebind`/`close`）（[lib.rs](file:///workspace/crates/nexus-fabric/src/lib.rs)） | QUIC-like 会话（E2E 加密 + 漫游） |
| | `FabricListener` / `SendStream` / `RecvStream` / `ConnStats` | 监听 / 可靠流 / 诚实统计 |
| | `UdpTransport` trait（[transport.rs](file:///workspace/crates/nexus-fabric/src/transport.rs)） | UDP 依赖倒置接缝（TURN/代理隧道注入） |
| nexus-nat-traversal | `PunchSession` / `PunchPhase` / `PunchOffer`/`PunchAnswer`（[lib.rs](file:///workspace/crates/nexus-nat-traversal/src/lib.rs)） | 打洞状态机 + 信令编解码 |
| nexus-nat-wireup | `PunchManager` / `FabricPunchChannel` / `DriverPunchSocket` / `tie_break_keep_local`（[lib.rs](file:///workspace/crates/nexus-nat-wireup/src/lib.rs)） | 打洞生产接线 + 确定性 tie-break |
| nexus-nat-quality | `QualityMonitor` / `LossProbe`（[monitor.rs](file:///workspace/crates/nexus-nat-quality/src/monitor.rs)） | 路径质量探针（25B 帧格式冻结） |
| nexus-turn | `TurnClient` / `TurnSocket` / `TurnServer`（[client.rs](file:///workspace/crates/nexus-turn/src/client.rs)） | RFC5766 最小实现（`TurnSocket: UdpTransport`） |
| outbound-ss | `ShadowsocksAdapter` / `SsStream`（[lib.rs](file:///workspace/crates/nexus-outbound-shadowsocks/src/lib.rs)） | AEAD 记录层 seal/open |
| outbound-vmess | `VmessAdapter`（[lib.rs](file:///workspace/crates/nexus-outbound-vmess/src/lib.rs)） | VMess AEAD 记录层 |
| outbound-trojan | `TrojanAdapter` / `encode_request` / `auth_hash`（[lib.rs](file:///workspace/crates/nexus-outbound-trojan/src/lib.rs)） | TLS + SHA-224 请求头 |
| outbound-anytls | `AnyTlsAdapter` / `client_handshake` / `encode_frame`（[lib.rs](file:///workspace/crates/nexus-outbound-anytls/src/lib.rs)） | AnyTLS v2 多路复用会话层 |
| outbound-vless | `VlessAdapter` / `VlessConn` / `VisionReader`/`VisionWriter`（[lib.rs](file:///workspace/crates/nexus-outbound-vless/src/lib.rs)） | VLESS 头握手 + XTLS-Vision |
| outbound-hysteria2 | `Hysteria2Client` / `Driver` / `build_auth_request`（[client.rs](file:///workspace/crates/nexus-outbound-hysteria2/src/client.rs)、[driver.rs](file:///workspace/crates/nexus-outbound-hysteria2/src/driver.rs)） | QUIC + HTTP/3 认证 + Salamander 混淆 |
| nexus-plugin | `ObfuscateTransport` / `PluginRegistry` / `dial_with_obfs`（[lib.rs](file:///workspace/crates/nexus-plugin/src/lib.rs)、[dial.rs](file:///workspace/crates/nexus-plugin/src/dial.rs)） | 混淆传输插件接缝（版本硬校验、失败不回退明文） |

## 8. 平台 / 工作区

| crate | 关键符号 | 作用 |
|---|---|---|
| nexus-platform | `VirtualPacketInterface` / `PacketCarrier` / `UdpCarrier`（[lib.rs](file:///workspace/crates/nexus-platform/src/lib.rs)） | 包读写 / 承载帧 capability trait |
| | `SecureStore` + `secure_store::{parse_machine_id, derive_key, encrypt_record}`（[secure_store.rs](file:///workspace/crates/nexus-platform/src/secure_store.rs)） | 平台无关 KV 安全存储核心（NEXSEC1 AEAD 记录） |
| | `ProjectedWorkspace`（[projected.rs](file:///workspace/crates/nexus-platform/src/projected.rs)） | workspace-as-filesystem 投影契约 |
| | `SystemProxyController` / `AutostartRegistrar` / `Clock` / `RandomSource` | 设备能力与基础注入 trait |
| nexus-platform-linux | `TunVpi` / `FuseWorkspaceFs` / `OsAssemble` / `NlSocket` / `file_lease::try_lock_exclusive` | Linux 全套适配器 |
| nexus-platform-windows | `WintunVpiAdapter` / `WinInetSystemProxy` / `TaskSchedulerAutostart` / `DpapiSecureStore` | Windows 适配器（unsafe 仅限两模块） |
| nexus-workspace | `Workspace<S: ContentStore>`（`commit_changes`/`merge_heads`/`resolve_conflict`/`exchange_heads`/`sync_with_remote`/`reconcile_journal`）（[lib.rs](file:///workspace/crates/nexus-workspace/src/lib.rs)） | Commit DAG + Head Set 权威语义 |
| | `commit_id_of` / `HeadSet` / `ConflictObject` | 内容哈希提交 / 多 Head / 持久化冲突 |
| | `WorkspaceAccess` + `NativeApiWorkspaceAccess` / `MaterializedDirectoryAccess` / `select_access_provider` | 三种访问通道与确定性选择 |
| | `CacheManager`（[cache.rs](file:///workspace/crates/nexus-workspace/src/cache.rs)）、`gc::{GcScheduler, GcPlan}`（[gc.rs](file:///workspace/crates/nexus-workspace/src/gc.rs)） | 缓存驱逐（≠ GC）/ 两阶段可达性 GC |
| nexus-workspace-intel | `WorkingSetEstimator` / `PrefetchScheduler` / `IntelStore` / `WorkspaceGraph` | 访问智能（可丢失、确定性、不选路） |
| nexus-storage | `ContentStore` / `FsContentStore` / `FileKvStore` / `journal_append` / `ReachabilityGc` / `StrongContentStore` | CAS / KV / WAL journal / GC / SHA-256 强校验 |

## 9. 计算 / API / 应用 / 工程

| crate | 关键符号 | 作用 |
|---|---|---|
| nexus-compute | `ComputeJobSession` / `TaskOwner<S>` / `AcceptanceLedger` / `RuntimeState` / `RequesterMirror`（[task.rs](file:///workspace/crates/nexus-compute/src/task.rs)、[task_runtime.rs](file:///workspace/crates/nexus-compute/src/task_runtime.rs)） | 计算会话 + N3 TaskOwner/接受台账/运行时归约 |
| nexus-control-api | `ControlCommand` / `ControlOutput` / `ControlService`（[lib.rs](file:///workspace/crates/nexus-control-api/src/lib.rs)） | 前端统一命令与视图 DTO |
| | `TaskRequest`/`TaskResponse`/`TaskApplicationService`（[task.rs](file:///workspace/crates/nexus-control-api/src/task.rs)） | N3 六类操作线协议 |
| nexus-service | `ServiceSession::connect` / `ServiceTransport`（[lib.rs](file:///workspace/crates/nexus-service/src/lib.rs)） | CONNECT→READY 服务会话 |
| apps/nexus | `run()`（[main.rs](file:///workspace/apps/nexus/src/main.rs)）/ `localapi_client`（[localapi_client.rs](file:///workspace/apps/nexus/src/localapi_client.rs)） | CLI 分发 + LocalAPI thin-client |
| apps/nexusd | `assemble_n1`（[assembly.rs](file:///workspace/apps/nexusd/src/assembly.rs)）/ 统一数据面（[dataplane.rs](file:///workspace/apps/nexusd/src/dataplane.rs)）/ `boot_reconcile`（recovery.rs）/ `LinuxTaskExecutor`（[task_executor.rs](file:///workspace/apps/nexusd/src/task_executor.rs)） | Composition Root 装配 / 数据面 / 冷启动对账 / N3 执行 |
| nexus-harness | `dispatch`（[main.rs](file:///workspace/engineering/nexus-harness/src/main.rs)）/ gate 清单执行（[commands.rs](file:///workspace/engineering/nexus-harness/src/commands.rs)）/ `architecture_gate` 等（[gates.rs](file:///workspace/engineering/nexus-harness/src/gates.rs)）/ Evidence 写入（[evidence.rs](file:///workspace/engineering/nexus-harness/src/evidence.rs)）/ 场景执行（[scenario.rs](file:///workspace/engineering/nexus-harness/src/scenario.rs)） | 工程门禁与证据 |

## 10. 跨 crate 高频约定

写代码定位符号时的常见模式：

- **Owner / Worker 分离**：`SessionOwner::commit_outcome`、`TaskOwner`、`QualityMonitor`（stop+join）、`PunchManager`——Worker 只发事件/事件归约，Owner 唯一写终态。
- **注入 trait 接缝**：`ServiceTransport` / `LinkProbe` / `ConnectivityEstablisher` / `DiscoveryTransport` / `SecretStore` / `TurnTransport` / `UdpTransport` / `PathConnector` / `Resolver` / `LatencyProbe` / `SubmitFn`——真实 I/O 一律组合根注入。
- **确定性纯函数**：`RuleEngine::route` / `evaluate_connectivity` / `filter/score_candidates` / `WorkingSetEstimator` / `parse(yaml)`——同输入恒同输出，时间/随机显式注入。
- **诚实语义**：测量无样本 = `None`/unknown（不编 0）；能力缺失 = `Unavailable`/`UNSUPPORTED`（不静默降级）；未实现 = 显式 UNKNOWN。
