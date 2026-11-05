# 03 · 关键类型与函数（Key Types & Functions）

> 按"写代码时最常需要定位"的顺序组织。每个条目给出**一句话作用**与**源码位置**
> （相对仓库根）。所有符号均经源码核实存在（基线 `585e910`）。
> 完整 API 以各 crate `MODULE.md` 的 Public API 节与 `cargo doc` 为准。

## 1. 领域模型（nexus-domain）

文件：[lib.rs](../../crates/nexus-domain/src/lib.rs)（1359 行）、[task/mod.rs](../../crates/nexus-domain/src/task/mod.rs)（1178 行）

| 符号 | 作用 |
|---|---|
| `ResourceId` / `ProviderId` / `SessionId` / `WorkspaceId` / `NodeId` | 强类型 ID newtype（Identity ≠ Locator） |
| `ResourceName` / `ResourceRef{workspace,name}` / `ResourceKind` / `ResourceOperation` | 资源命名寻址（ASCII、≤128）与操作词汇 |
| `FlowContext` / `FlowOrigin::{VirtualPacketInterface,Socks5,Http,NativeApi}` | Ingress 产出的中立流量上下文（不含 Path/Provider 决策） |
| `Intent` / `Constraint` | 规划输入（Policy → Planner 的传递载体） |
| `Plan` + `PlanExtension::{Network,Workspace,Compute,Service}` | 领域中立核心 Plan；领域数据只进带 `version` 的类型化扩展 |
| `ConnectivityEvaluation`（`has_feasible_path()`，VERSION=1） | 规划期连通性可行性 DTO |
| `RejectReason` / `ScoreComponent` / `ConsideredCandidate` / `DecisionTrace` / `MeasurementSnapshot` | 规划决策轨迹（"为什么没被选"的唯一出口） |
| `PlanId` / `fnv1a_64_hex` / `plan_id_of` / `PlanSnapshot` | FNV-1a 确定性 Plan 标识（非密码学） |
| `LifecyclePhase` / `TerminalOutcome` / `SessionStatus` | 生命周期与业务结果双轨分离 |
| `NexusError`（14 变体）/ `FailureDisposition`（`disposition()`） | 结构化失败（PRODUCT §2 七类 + Unsupported/Internal/…）+ 处置映射 |
| `DenyReason` / `AuthorizationDecision` | 授权词汇（`DenyReason::code()` 审计稳定判别名） |
| task::`TaskId`/`ArtifactId`/`SnapshotId`/`SubmitTaskRequest`/`TaskView`/`TaskPhase`/`TaskOutcome`… | N3 任务模型（TaskPhase ≠ TaskOutcome；JSON 形状由 `docs/contracts/n3-task-v1.schema.json` 冻结） |
| `codec::CanonicalDto`（BTreeMap 有序 canonical 编码）/ `validation::{validate_provider_transition, relative_path}` | 规范编码（产生 digest）与状态转移/路径校验 |

## 2. 会话与规划

### nexus-session（[lib.rs](../../crates/nexus-session/src/lib.rs)，2154 行）

| 符号 | 作用 |
|---|---|
| `SessionOwner` / `commit_outcome`（lib.rs:241） | **TerminalOutcome 唯一写入入口**（commit-once 守卫，重复提交 `AlreadyTerminated`） |
| `SessionOwner::transition_phase`（:212） | 合法 LifecyclePhase 迁移（Allocating→Active|Disposed、Active→Draining|Disposed、Draining→Disposed） |
| `record_connectivity_established` / `record_connectivity_failed` / `request_cancellation` | Worker 上报事件（Worker 只发事件，不写 Outcome） |
| `SessionEvent`（7 种）/ `SessionError`（4 变体） | 结构化事件 / 类型化错误（`From<SessionError> for NexusError`） |
| `CancelToken` / `AbortOnDropHandle`（:99/:123） | std 结构化并发原语（Portable，无 tokio） |
| `SessionRecord` / `SessionRecordStore` / `reconcile_session_records`（:485） | durable marker + 冷启动幂等 reconcile（孤儿恰一次提交 Failed） |
| `SessionManager`（:1298，open/attach/close/complete/sweep_detached/note_provider_lost/…） | daemon 内 Session 生命周期**唯一 Owner**；attach window `DEFAULT_ATTACH_WINDOW_SECS=300` |

### nexus-planner（[lib.rs](../../crates/nexus-planner/src/lib.rs)，1227 行）

| 符号 | 作用 |
|---|---|
| `PlanningSnapshot`（`with_connectivity`/`with_local_provider`） | 一次规划周期的一致视图 |
| `filter_candidates`（:202） | 阶段一硬谓词过滤（present→capability→placement → `RejectReason`） |
| `connectivity_gate`（:179） | 可行性门控纯函数（无可行路径 → `NoFeasibleConnectivityPath`） |
| `score_candidates`（:255） | 阶段二评分（rtt 归一化 + `LOCALITY_BONUS=1000`，`breakdown` 之和恒等于总分） |
| `plan_from_snapshot` / `plan`（:334/:457） → `Planned{plan, trace}` | 组装入口（确定性选优） |
| `ExplainMode` / `classify_explain_arg` / `PlanHistory` / `ExplainedPlan` | `plan explain` 双模式（History/Estimate；查无记录不回退重算） |

### nexus-flow-session

- [flow.rs](../../crates/nexus-flow-session/src/flow.rs)：`FlowKey`（5 元组）/`FlowEntry`/`FlowTable`（O(1)）/`FlowDecision::{NewSession,Forward,Drop,BufferForSession}`/`FlowPhase`
- [chain.rs](../../crates/nexus-flow-session/src/chain.rs)：`run_first_packet_chain`（首包链纯函数：Policy→Planner→建 Session，可重放）
- [manager.rs](../../crates/nexus-flow-session/src/manager.rs)：flow 版 `SessionManager`（`planner_calls` 计数器证明快路径不调 Planner）、`ConnectivityEstablisher`（注入 trait）、`EstablishEvent`/`FlowSignal`（TcpReset/TearDown）
- [buffer.rs](../../crates/nexus-flow-session/src/buffer.rs)：`UdpBuffer`（32 包/64KB 有界）

### nexus-scheduler（[lib.rs](../../crates/nexus-scheduler/src/lib.rs)，548 行）

`Scheduler`（register/cancel/list/tick/snapshot/restore）、`ScheduleSpec::{At,Every}`、
`ScheduleState::{Scheduled,Fired,Cancelled}`、`ScheduleEntry`、`TriggerRecord`、
`TaskIntent`、`SubmitFn`（`Box<dyn FnMut(&TaskIntent) -> Result<String, ScheduleError>>`）。

## 3. 策略 / 授权 / 注册 / 发现

| crate · 文件 | 关键符号 | 作用 |
|---|---|---|
| nexus-policy [lib.rs](../../crates/nexus-policy/src/lib.rs) | `PolicyEngine::evaluate` / `PolicyRule` / `PolicyAction::{AddConstraint,EnrichMetadata,SelectProvider,Reject}` | 有序规则链首匹配；trace 支持 explain/replay |
| | `PolicyDecision` / `PolicyResult` / `PolicyTraceEntry` | 展开后的 Intent+Constraint 与完整轨迹 |
| nexus-auth [lib.rs](../../crates/nexus-auth/src/lib.rs) | `GrantTable::authorize` / `AuthOutcome` | 顺序判定 NoSuchGrant→WrongWorkspace→Revoked→Expired→OperationNotGranted→Allow |
| | `PreSharedToken` / `verify_token` | PSK 常量时间门控 |
| | `Principal::from_ed25519_public_key` / `TrustStore` / `TrustVerdict` | 主体派生（`ed25519:<hex(SHA-256(pubkey)[..16])>`）；显式 TOFU |
| | `Grant`（revoked tombstone）/ `AuditRecord` / `AuditSink` | 授权条目 + exactly-once 审计 |
| nexus-registry [lib.rs](../../crates/nexus-registry/src/lib.rs) | `Registry`（register/candidates）/ `ProviderRecord` | 纯内存注册视图（按注册顺序稳定返回） |
| [advertisement.rs](../../crates/nexus-registry/src/advertisement.rs) | `ProviderAdvertisement`（is_expired/is_usable/visible_to）/ `Discoverability` / `UsageGrant` / `UnavailabilityReason` | D2 双层授权（可见 ≠ 可用） |
| | `LocalNameTable` / `StaticProviderEntry::into_advertisement` / `publish_ad`/`lookup_ads`/`purge_expired_ads` | 本地名解析与广告生命周期 |
| [control_frame.rs](../../crates/nexus-registry/src/control_frame.rs) | `ControlFrame`（5 种）/ `encode_control_frame` / `ControlChannel` | N2 控制面协议帧与已认证通道 |
| nexus-discovery [lib.rs](../../crates/nexus-discovery/src/lib.rs) | `Discovery` trait / `StaticDiscovery` / `AggregateDiscovery` / `PresenceRegistry` | 多源聚合发现 + Presence TTL |
| [lsa.rs](../../crates/nexus-discovery/src/lsa.rs) | `Lsa` / `Lsdb` / `LsaDiscovery` | LSA 泛洪（`(incarnation,seq)` 版本向量） |
| [routing.rs](../../crates/nexus-discovery/src/routing.rs) | `PathComputer::{ShortestPath,Ecmp,KShortest,Disjoint}` / `Fib` / `FibManager` | 选路算法族 + RCU 风格 FIB |
| [paired.rs](../../crates/nexus-discovery/src/paired.rs) | `PairingCode` / `PairedDiscovery` / `NodeIdentity` | 带外配对码 + ed25519 信任（配对 ≠ 建连） |

## 4. 连接与传输

### nexus-connectivity（[lib.rs](../../crates/nexus-connectivity/src/lib.rs) 等 35 文件）

| 符号 | 作用 |
|---|---|
| `establish` / `ConnectivityState` / `EstablishmentRequest` / `ConnectivityEvent` | 确定性建连状态机（可重放事件序列） |
| `ConnectivityRuntime`（`bind_local`/`send_frame` 认证门控/`receive_frame`/read/write_ip_packet） | 双 trait 注入编排器（`VirtualPacketInterface` + `PacketCarrier`） |
| `LinkActivator::activate` / `LinkKind` / `LinkCandidate` / `LinkProbe` / `LinkSelection` | Direct→Relay 回退的链路激活（未认证零探测零发送） |
| `LinkMarker` / `LinkMarkerStore` / `reconcile_link_markers` | 链路 durable marker + 冷启动 reconcile |
| `OutboundAdapter` / `OutboundHandoff` | 出站协议领域中立接缝（6 个 outbound crate 实现它） |
| [evaluation.rs](../../crates/nexus-connectivity/src/evaluation.rs)：`evaluate_connectivity` / `EvaluationInput` | v9 §8.1 规划期评估纯函数（全整数） |
| [virtual_subnet.rs](../../crates/nexus-connectivity/src/virtual_subnet.rs)：`VirtualSubnetTunnel` | 虚拟子网数据面（路由/加密/打洞/管线，3101 行最大文件） |
| [coord.rs](../../crates/nexus-connectivity/src/coord.rs)：`Coordinator` / `VirtualIpAllocator` / `derive_vip` / `CoordFrame` | 协调核心 + VIP 分配（显式 `now_secs` 零 I/O） |
| [encryption.rs](../../crates/nexus-connectivity/src/encryption.rs)：`KeyPair`/`SessionKey`/`encrypt_frame`/`decrypt_frame`/`ReplayWindow` | X25519+HKDF+ChaCha20Poly1305 链路加密（1024 位重放窗） |
| [identity.rs](../../crates/nexus-connectivity/src/identity.rs)：`IdentityManager` / `SecretStore` | TOFU 身份（记录键=对端 VIP，换公钥即 `IdentityRejected`） |
| [relay.rs](../../crates/nexus-connectivity/src/relay.rs)：`RelayChannel` / `RelayTransport` | DERP 类中继状态机 |
| [qos.rs](../../crates/nexus-connectivity/src/qos.rs)/[cake.rs](../../crates/nexus-connectivity/src/cake.rs)：`QosController`/`TokenBucket`/`CakeScheduler` | 两级 QoS（限流 + DRR 公平队列） |
| [health_check.rs](../../crates/nexus-connectivity/src/health_check.rs)：`HealthMonitor` | 有 Owner 的探针线程（AtomicBool+Condvar+JoinHandle） |

### nexus-fabric（QUIC-like 会话层）

| 符号 | 作用 |
|---|---|
| `FabricConn`（[lib.rs](../../crates/nexus-fabric/src/lib.rs):87）/ `FabricListener` | 会话句柄（流/datagram/统计）/ 监听 accept（`connect_with_transport`/`bind_with_transport` 注入 UDP） |
| `Driver` / `Cmd` / `ConnShared`（[driver.rs](../../crates/nexus-fabric/src/driver.rs)） | sans-IO quinn-proto 驱动（std 线程，仓库 tokio-free） |
| `UdpTransport` / `StdUdpTransport`（[transport.rs](../../crates/nexus-fabric/src/transport.rs):25/:51） | UDP 收发抽象（turn/proxy-transport 注入实现） |
| `PeerId` / `ConnectionId` | ed25519 公钥身份 / u64 连接号（漫游解耦） |
| `send_datagram_seqed` / `recv_datagram_seqed`（:219/:246） | QSEQ 序号 datagram |
| `FabricIdentity` / `PeerPinVerifier`（[cert.rs](../../crates/nexus-fabric/src/cert.rs)） | 自签 ed25519 证书 / PeerId-pinning TLS 验证 |

### nexus-path（[lib.rs](../../crates/nexus-path/src/lib.rs) 等）

`PathManager`（add_candidate/current_path/on_stats/poll_event/score）、`PathConfig`（hysteresis 20%/3s）、
`PathKind`/`PathEvent`/`SwitchReason`、[ewma.rs](../../crates/nexus-path/src/ewma.rs) `Ewma`、
[race.rs](../../crates/nexus-path/src/race.rs) `race_connect` + `PathConnector`/`RaceBudget`、
[fallback.rs](../../crates/nexus-path/src/fallback.rs) `FallbackChain`/`connect_with_fallback`（Direct→Proxy→Turn）。

### nexus-turn / nexus-nat-\*

- turn：`TurnClient`（[client.rs](../../crates/nexus-turn/src/client.rs)）、`TurnSocket`（[socket.rs](../../crates/nexus-turn/src/socket.rs)，impl `UdpTransport`）、`StunMessage`/`decode`（[stun.rs](../../crates/nexus-turn/src/stun.rs)）、`derive_key`/`verify_integrity`（[auth.rs](../../crates/nexus-turn/src/auth.rs)）
- nat-traversal：`PunchSession`/`PunchResult::{Migrated,StayedOnRelay}`/`PunchChannel`/`PunchSocket`/`PunchConfig`（[lib.rs](../../crates/nexus-nat-traversal/src/lib.rs)）、`PunchOffer`/`encode_offer`（[signal.rs](../../crates/nexus-nat-traversal/src/signal.rs)）、`LocalCandidates`/`punch_targets`（[candidate.rs](../../crates/nexus-nat-traversal/src/candidate.rs)）
- nat-wireup：`PunchManager`/`punch_peer`/`tie_break_keep_local`（[lib.rs](../../crates/nexus-nat-wireup/src/lib.rs)）、`FabricPunchChannel`（[channel.rs](../../crates/nexus-nat-wireup/src/channel.rs)）、`DriverPunchSocket`（[socket.rs](../../crates/nexus-nat-wireup/src/socket.rs)）
- nat-quality：`QualityMonitor`（[monitor.rs](../../crates/nexus-nat-quality/src/monitor.rs)）、`ProbeEndpoint`/`LossProbe`（[endpoint.rs](../../crates/nexus-nat-quality/src/endpoint.rs)/[probe.rs](../../crates/nexus-nat-quality/src/probe.rs)）

### nexus-transport（[lib.rs](../../crates/nexus-transport/src/lib.rs)）

`connect`/`accept` → `FrameStream`（`send_frame`/`recv_frame`/`into_raw`；`u32 BE` 长度前缀冻结）/ `TransportError`。

## 5. 代理栈与数据面

| crate · 文件 | 关键符号 | 作用 |
|---|---|---|
| nexus-ingress [lib.rs](../../crates/nexus-ingress/src/lib.rs) | `Socks5Handshake`（:145）/ `Socks5State`/`Socks5Step` | RFC 1928/1929 增量握手状态机 |
| | `HttpProxyHandshake`（:465） | HTTP CONNECT 状态机 |
| | `from_socks5/from_http/from_virtual_packet_interface/from_native_api` | 构造中立 `FlowContext` |
| [ip_packet.rs](../../crates/nexus-ingress/src/ip_packet.rs) | `TunPacket` / `parse_ipv4_packet` | IPv4 五元组解析（仅 TCP/UDP，其余 None） |
| nexus-proxy [lib.rs](../../crates/nexus-proxy/src/lib.rs) | `RuleEngine::route`（:721）/ `FlowTarget`（:241）/ `RuleData`（:155） | 规则表线性首匹配（纯函数零 I/O） |
| | `ProxyService::route`（:1005）/ `RoutingDecision`（:915） | 编排决策（规则→组→出站 tag→LinkActivator） |
| | `SelectorGroup`（:781）/ `UrltestGroup`（:837） | 策略组（手动 / 离线 measurement 选优） |
| | `TunNatRouter::route_packet` / `TunStats`（[tun.rs](../../crates/nexus-proxy/src/tun.rs)） | TUN per-packet 决策 + 5 元组缓存 |
| nexus-proxy-config [lib.rs](../../crates/nexus-proxy-config/src/lib.rs) | `parse(yaml) -> ProxyConfig`（:730）/ `ConfigError`（:26） | YAML 子集解析 + 结构化校验 |
| | `RuleConfig`/`RuleKind` / `GroupConfig`/`GroupKind` / `OutboundConfig`/`OutboundKind`（9 种） | typed 配置模型 |
| | `parse_clash_subscription`（:1458）/ `RuleProviderConfig` | 订阅与 rule-providers |
| nexus-proxy-transport | `socks5_connect`（[socks5.rs](../../crates/nexus-proxy-transport/src/socks5.rs)）/ `FramedTransport`/`ProxyTransport`（[framed.rs](../../crates/nexus-proxy-transport/src/framed.rs)） | client 侧拨号 + 2B 长度前缀成帧（impl `UdpTransport`） |
| | `SsTransport` / `TrojanTransport` / `TlsTrojanTransport` | ss/trojan 隧道传输 |
| nexus-network [lib.rs](../../crates/nexus-network/src/lib.rs) | `NetworkSession::establish` / `NetworkTransport`（:64） | 远程网络会话（帧通道注入） |
| [n1/session.rs](../../crates/nexus-network/src/n1/session.rs) | `N1SessionManager` / `N1Peer` | 按 PeerId 的连接生命周期 |
| [n1/pump.rs](../../crates/nexus-network/src/n1/pump.rs) | `VpiPump` / `PumpStats` / `Ipv4Net` | TUN↔datagram 包泵 + 静态路由查表 |
| [n1/link.rs](../../crates/nexus-network/src/n1/link.rs) | `LinkStateWatcher` | keepalive 心跳 → 漫游 rebind |
| nexus-dns [lib.rs](../../crates/nexus-dns/src/lib.rs) | `DnsRuntime`（:432）/ `Resolver` trait（:158） | 解析 + 缓存 + Exit-DNS Binding |
| | `DnsRouter`/`MultiServerDns`（:263/:325） | 多 server 路由（域名/IP-CIDR 首匹配） |
| [unified.rs](../../crates/nexus-dns/src/unified.rs) | `UnifiedDns`（:321）/ `FakeIpPool`（:163）/ `MeshNameResolver`/`ProxyClassifier` | 统一分类应答 + fake-ip（198.18.0.0/15） |
| nexus-projection [lib.rs](../../crates/nexus-projection/src/lib.rs) | `Projection`（:677）/ `ProjectionConfig` / `TunDevice`/`MockTun` | L3 隧道主体（1B 意图位 + IP 包） |
| | `encode_intent`/`decode_intent`/`INTENT_MESH/EGRESS/STREAM/SERVICE` | 意图位编解码（bit2-5 跳数） |
| [routing.rs](../../crates/nexus-projection/src/routing.rs) | `UnifiedRouter` / `Router` / `Cidr` | 统一路由（MeshPeer/Egress/Drop） |
| [egress.rs](../../crates/nexus-projection/src/egress.rs) | `SimpleRuleEngine`/`EgressNat`/`RealUdpEgress` | 出口 NAT + 真实 socket |
| [tcp.rs](../../crates/nexus-projection/src/tcp.rs) | `TcpTerminator`/`TcpRelay`/`TcpEgress`/`encode_stream_frame` | smoltcp TCP 终结 + 字节流中继 |
| [dns.rs](../../crates/nexus-projection/src/dns.rs) | `DnsSniffer` / `DnsCache` / `parse_dns_query` | DNS 嗅探（TXID 校验） |
| [semantic.rs](../../crates/nexus-projection/src/semantic.rs) | `SemanticIngress` | SOCKS5/HTTP 显式代理入口（复用 ingress 状态机） |
| [flow_session.rs](../../crates/nexus-projection/src/flow_session.rs) | `FlowSessionHub` / `SendStream`/`RecvStream` | PeerId 级流会话 API |
| nexus-compute [task.rs](../../crates/nexus-compute/src/task.rs) | `TaskOwner`（:166）/ `AcceptanceLedger`/`IdempotencyScope` | N3 提供方接受/状态机唯一写者 |
| [task_runtime.rs](../../crates/nexus-compute/src/task_runtime.rs) | `RuntimeJournal`/`RuntimeEvent`/`RuntimeState` | 持久事件 journal（连续序号 replay 幂等） |
| [task_requester.rs](../../crates/nexus-compute/src/task_requester.rs) | `RequesterMirror`/`RequesterScope` | 请求方只读镜像 |
| [lib.rs](../../crates/nexus-compute/src/lib.rs) | `ComputeJobSession::submit` / `ComputeTransport` | P0 帧往返会话（与 N3 Task 并存不混同） |

## 6. 平台与工作区

| crate · 文件 | 关键符号 | 作用 |
|---|---|---|
| nexus-platform [lib.rs](../../crates/nexus-platform/src/lib.rs) | `PlatformError` / `VirtualPacketInterface` / `PacketCarrier` / `SystemProxyController` / `AutostartRegistrar` | 平台无关 capability traits |
| [secure_store.rs](../../crates/nexus-platform/src/secure_store.rs) | `SecureStore` / `derive_key` / `encrypt_record` | machine-id + HKDF + NEXSEC1 AEAD 记录 |
| [projected.rs](../../crates/nexus-platform/src/projected.rs) | `ProjectedWorkspace` / `ProjectedDirEntry` | workspace-as-filesystem portable 契约 |
| nexus-platform-linux | `TunVpi`（[tun_vpi.rs](../../crates/nexus-platform-linux/src/tun_vpi.rs)）/ `TunFd`/`TUNSETIFF`（[tun.rs](../../crates/nexus-platform-linux/src/tun.rs)） | Linux TUN |
| | `route::{snapshot,apply,rollback}` / `OsAssemble`（[route.rs](../../crates/nexus-platform-linux/src/route.rs)/[assemble.rs](../../crates/nexus-platform-linux/src/assemble.rs)） | 事务性 OS 装配 |
| | `fuse_ws::FuseWorkspaceFs` / `file_lease::try_lock_exclusive` / `directory_publish::publish_directory_no_replace` | FUSE 投影 / flock 租约 / renameat2 原子发布 |
| nexus-platform-windows | `WintunVpiAdapter`（[vpi.rs](../../crates/nexus-platform-windows/src/vpi.rs)）/ `WinInetSystemProxy` / `TaskSchedulerAutostart` / `DpapiSecureStore` / `netcfg::*` | Windows 适配 |
| nexus-workspace [lib.rs](../../crates/nexus-workspace/src/lib.rs) | `WorkspaceCommit` / `commit_id_of` / `conflict_id_of` | **CommitId=内容哈希**提交对象 |
| | `HeadSet` / `HeadAction` / `merge_heads` / `exchange_heads` / `sync_with_remote` | 多 Head 与三方合并/同步 |
| | `Workspace<S: ContentStore>`（init/open/journal_pending/commit_pending/reconcile_journal/…） | Workspace 主体（crash-safe 两段提交） |
| | `ConflictObject`/`ConflictState`/`MergeReport` / `WorkspaceError` | 持久冲突与类型化错误 |
| | `WorkspaceAccess`/`NativeApiWorkspaceAccess`/`MaterializedDirectoryAccess`/`select_access_provider` | 三种访问通道与确定性选择 |
| [gc.rs](../../crates/nexus-workspace/src/gc.rs) | `GcRoots`/`GcConfig`/`GcPlan`/`Tombstone`/`GcScheduler`/`QuotaPolicy`/`InFlightSet` | 可达性 GC（默认保留 14 天） |
| [cache.rs](../../crates/nexus-workspace/src/cache.rs) | `CacheManager`/`CachePin` | 确定性缓存（pin 铁律，不删 CAS 对象） |
| [snapshot.rs](../../crates/nexus-workspace/src/snapshot.rs) | `SnapshotSelection`/`FrozenSnapshot`/`SnapshotLimits` | N3 不可变快照 |
| nexus-workspace-intel | `AccessTrace`/`WorkspaceGraph`/`WorkingSetEstimator`/`PrefetchScheduler`/`IntelStore`/`to_snapshot` | 可丢失访问智能（预取不含 Provider/Path） |
| nexus-web-gateway | `Gateway`/`GatewayConfig`（[gateway.rs](../../crates/nexus-web-gateway/src/gateway.rs)/[config.rs](../../crates/nexus-web-gateway/src/config.rs)）/ `BrowserMessage`/`NodeMessage`（[protocol.rs](../../crates/nexus-web-gateway/src/protocol.rs)） | WebRTC SSH 网关主体 |
| | `MeshSignaler`/`WssMeshSignaler`（[mesh.rs](../../crates/nexus-web-gateway/src/mesh.rs)）/ `run_ssh_client`（[ssh_client.rs](../../crates/nexus-web-gateway/src/ssh_client.rs)） | mesh SDP 中继 / 节点侧 SSH |

## 7. 出站协议（各 crate lib.rs）

| 符号 | crate | 作用 |
|---|---|---|
| `ShadowsocksAdapter` / `SsStream::seal/open` / `encode_request` | outbound-shadowsocks | AEAD 记录层与会话 |
| `VmessAdapter` / `VmessSecurity` | outbound-vmess | AEAD 记录层 |
| `TrojanAdapter` / `auth_hash` / `encode_request_fmt` | outbound-trojan | trojan-gfw 请求头与 TLS |
| `AnyTlsAdapter` / `AnyTlsFrame` / `client_handshake`/`server_handshake` | outbound-anytls | TLS 多路复用会话 |
| `VlessConn` / `VisionWriter`/`VisionReader` / `VlessAdapter` | outbound-vless | XTLS-Vision 状态机 |
| `Hysteria2Client` / `Hysteria2Adapter` / `Driver`（自写 sans-IO QUIC）/ `obfuscate` | outbound-hysteria2 | QUIC+H3 认证+Salamander |

全部经 `nexus_connectivity::OutboundAdapter`（`OutboundHandoff{kind,tag,locator}`）接缝接入。

## 8. 应用与工程

| 符号 | 位置 | 作用 |
|---|---|---|
| `USAGE` 常量 / `main::run` / `parse_command` | [apps/nexus/src/main.rs](../../apps/nexus/src/main.rs) | CLI 全命令表与分发（详见 05） |
| `run_resource`/`run_session`/`run_use`/`run_plan`/`run_node`/`run_pair`/`run_grant`/`run_provider` | `apps/nexus/src/*_cli.rs` | 各命令族入口 |
| `task_cli::run` / `TaskCliCommand` | [task_cli.rs](../../apps/nexus/src/task_cli.rs) | N3 thin front-end（严格版本化请求） |
| `subnet_up`/`subnet_punch`/`write_lease_state` | [subnet_cli.rs](../../apps/nexus/src/subnet_cli.rs) | 虚拟子网命令族 |
| `localapi_client::default_target` / `LocalApiTarget::{Socket,Tcp}` | [localapi_client.rs](../../apps/nexus/src/localapi_client.rs) | thin HTTP 客户端 |
| `internet_access_flow` / `remote_*_flow` / `proxy_serve_once` | [apps/nexus/src/lib.rs](../../apps/nexus/src/lib.rs) | SDK 组合根流程（nexusd 复用） |
| `run_daemon` / `serve_resource` | [apps/nexusd/src/main.rs](../../apps/nexusd/src/main.rs) | daemon 入口 |
| `LoadedConfig` / `parse_daemon_toml` / `classify_change` | [apps/nexusd/src/config.rs](../../apps/nexusd/src/config.rs) | 配置加载/热加载分级 |
| `assemble_n1` / `assemble_n2_session_manager` / `build_dataplane_config` | [apps/nexusd/src/assembly.rs](../../apps/nexusd/src/assembly.rs) | 子系统装配 |
| `Dataplane` / `DataplaneStats` | [apps/nexusd/src/dataplane.rs](../../apps/nexusd/src/dataplane.rs) | 单 TUN 数据面（分类/QoS/DNS 短路） |
| `ControlCommand` / `ControlService::execute` | [nexus-control-api/src/lib.rs](../../crates/nexus-control-api/src/lib.rs) | 前端统一命令面 |
| `TaskRequest`/`TaskApplicationService`（[task.rs](../../crates/nexus-control-api/src/task.rs)）/ `SnapshotRequest`（[snapshot.rs](../../crates/nexus-control-api/src/snapshot.rs)） | nexus-control-api | N3 六类操作 / snapshot staging |
| harness `dispatch`（13 命令）/ `run_gate` / evidence 写入 | [engineering/nexus-harness/src/](../../engineering/nexus-harness/) | 工程验证（详见 05） |
