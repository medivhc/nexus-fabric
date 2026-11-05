# 02 · 主要模块职责（Module Responsibilities）

> 依据：各 crate `MODULE.md`（模块契约，权威）+ 源码实测。规模为 `src/**/*.rs`
> 文件数/行数（commit `585e910`）。**⚠ 标注契约文字与实现已知出入**。
> 成熟度标注：⭐ 实心实现 · ◐ 可用但边界冻结中 · ○ 编译锚点骨架。

## 总览（52 个 workspace 成员）

| 层 | 成员 |
|---|---|
| 领域核心 | nexus-domain · nexus-registry · nexus-auth · nexus-policy · nexus-storage · nexus-measurement · nexus-plugin · nexus-scheduler · nexus-discovery |
| 会话与规划 | nexus-session · nexus-planner · nexus-flow-session · nexus-service · nexus-diagnostics · nexus-control-api |
| 投递底座 | nexus-delivery · nexus-connectivity · nexus-transport · nexus-fabric · nexus-path · nexus-turn · nexus-nat-traversal · nexus-nat-wireup · nexus-nat-quality |
| 代理栈/数据面 | nexus-ingress · nexus-proxy · nexus-proxy-config · nexus-proxy-transport · nexus-network · nexus-dns · nexus-projection · nexus-compute · nexus-outbound-{shadowsocks,vmess,trojan,anytls,vless,hysteria2} |
| 平台 | nexus-platform · nexus-platform-{linux,windows,macos,android,ios} · nexus-workspace · nexus-workspace-intel · nexus-web-gateway · nexus-proto |
| 组装层 | apps/nexus · apps/nexusd · apps/nexus-platform-host |
| 工程 | engineering/nexus-harness |

---

## 1. 领域核心（零 I/O、Portable Core）

### nexus-domain ⭐ — 根基领域模型（5 文件 3762 行）
- **负责**：稳定核心类型与不变量（Resource/Provider/Node/Intent/Constraint/Plan/Session/Measurement）+ N3 Task DTO（`task/` 子模块，1178 行）。[MODULE.md](../../crates/nexus-domain/MODULE.md)
- **不负责**：任何 I/O、平台 API、发现/建连/存储/调度/协议解析。
- **不变量**：Resource≠Provider、Identity≠Locator、Plan/Session 分离、Measurement 是事实非 Score；领域数据只进带 `version` 的 `PlanExtension`，禁止自由字符串混入 Plan。
- **依赖**：零依赖（`[dependencies]` 为空）。**规模**：lib.rs 1359 行、task/mod.rs 1178 行。

### nexus-registry ⭐ — 注册视图与 N2 广告（3 文件 1945 行）
- **负责**：Resource/Provider/Node/Presence/Capacity/Locator 可查询注册视图；Provider 广告生命周期（发布/查询/TTL/双层授权"可见≠可用"）；N2 控制面 5 种帧编解码与已认证通道；`LocalNameTable` 本地名解析。[MODULE.md](../../crates/nexus-registry/MODULE.md)
- **不负责**：Bootstrap 网络发现、Planner 评分、建连。
- **不变量**：只存事实与广告不存评分；Identity≠Locator 禁互相推导；人类可读名不进查询传输；过期广告拒绝使用。
- **依赖**：nexus-domain。纯内存零 I/O 零第三方。

### nexus-auth ⭐ — 授权与主体（1 文件 869 行）
- **负责**：`GrantTable::authorize` 类型化权限判定（NoSuchGrant→WrongWorkspace→Revoked→Expired→OperationNotGranted→Allow 顺序）、`Principal` 派生（`ed25519:<hex(SHA-256(pubkey)[..16])>`）、PSK 常量时间门控、`TrustStore` 显式 TOFU、exactly-once 审计。[MODULE.md](../../crates/nexus-auth/MODULE.md)
- **不变量**：Publication Policy 与 Resource Authorization 分离；授权失败结构化可解释；Principal 只来自握手已验证公钥。
- **依赖**：nexus-domain + `sha2`。无 I/O/无时钟（审计时间由调用方提供）。

### nexus-policy ⭐ — 策略展开（1 文件 590 行）
- **负责**：`PolicyEngine::evaluate` 有序规则链（首匹配终止）把 Flow/Resource Context 展开为 `Intent` + 有序 `Constraint`（`PolicyDecision`），交给唯一 Core Planner 求解；trace 支持 explain/replay。[MODULE.md](../../crates/nexus-policy/MODULE.md)
- **不变量**：Policy≠Path；未知进程/UID 显式 Unknown 不伪造默认值；约束有序确定性。
- **依赖**：nexus-domain。

### nexus-storage ⭐ — CAS/Journal 持久层（4 文件 1398 行）
- **负责**：`ContentStore`（contains/get/put/object_ids）CAS 契约、`object_id_of`（FNV-1a 64 内容寻址）、`FileKvStore` 原子写 + **Journal**（`journal_append/replay/discard_torn_tail`，8MB 上限）、`ReachabilityGc`、`FsContentStore`/`StrongContentStore`。[MODULE.md](../../crates/nexus-storage/MODULE.md)
- **不变量**：内容对象按 hash 寻址；关键更新 crash-consistent；tombstone 两阶段回收后才删对象。
- **依赖**：nexus-domain。

### nexus-measurement ⭐ — 测量事实（1 文件 168 行，最小）
- **负责**：`LinkMeasurement`（rtt/loss 万分比/jitter/throughput/confidence，缺失显式 `None`）、`MeasurementTable`、`ProbeTarget`、`LatencyProbe` 注入 trait。[MODULE.md](../../crates/nexus-measurement/MODULE.md)
- **不变量**：Measurement≠Score；全整数数值；`rtt_sort_key` 显式未知排最后。
- **依赖**：nexus-domain。

### nexus-plugin ⭐ — 混淆传输插件（4 文件 838 行）
- **负责**：`ObfuscateTransport` trait（`wrap` 字节流混淆）+ API 版本硬校验（`OBFUSCATE_API_VERSION=1`）+ 编译期静态注册（`PluginRegistry`/`register_all`）+ 拨号钩子 `dial_with_obfs`。[MODULE.md](../../crates/nexus-plugin/MODULE.md)
- **不变量**：插件点唯一（仅混淆传输）；wrap 失败不自动回退；读写方向独立变换。
- **依赖**：零依赖（std only）。Deletion Test 论证："GFW 升级探测 → 混淆手段必须能热插拔"。

### nexus-scheduler ⭐ — 计划任务纯逻辑（1 文件 548 行）
- **负责**：`Scheduler`（register/cancel/list/tick/snapshot/restore）、`ScheduleSpec::{At,Every}`、触发判定（`tick` 是唯一入口且无 I/O）、`TriggerRecord` 失败不静默丢弃。[MODULE.md](../../crates/nexus-scheduler/MODULE.md)
- **不变量**：单次触发只提交一次；`At` 触发后 `Fired` 永不再触发；失败条目保持 `Scheduled` 下次重试。
- **依赖**：仅 `serde`，**零 nexus-\* 内部依赖**（`allowed_internal_dependencies=[]`）；执行路径由 `SubmitFn` 注入。

### nexus-discovery ⭐ — 发现与路由（8 文件 6468 行）
- **负责**：`Discovery` trait / `StaticDiscovery` / `AggregateDiscovery`（Paired>Static>Lsa>mDNS 四源）、`PresenceRegistry`（TTL 过期不返回）、LSA 泛洪 + `Lsdb`、`PathComputer` 族（`ShortestPath`/`Ecmp`/`KShortest`/`Disjoint`）+ `FibManager`、带外配对（`PairingCode` + ed25519）、mDNS、bootstrap 加入协议。[MODULE.md](../../crates/nexus-discovery/MODULE.md)
- **不变量**：Discovery≠Connectivity Establishment；Bootstrap 不成为已建 Session 的长期数据依赖。
- **依赖**：nexus-domain/registry/platform（声明；**⚠ 源码暂未 `use` 三个内部 crate**，仅 `ring` 用于配对签名）。

---

## 2. 会话与规划

### nexus-session ⭐ — Session 生命周期唯一 Owner（2 文件 2304 行）
- **负责**：`SessionOwner` 状态机（`commit_outcome` 终态唯一写入口、`transition_phase` 合法迁移表）、7 种 `SessionEvent`、`CancelToken`/`AbortOnDropHandle`（std 结构化并发原语）、`SessionRecord`/`SessionRecordStore` durable marker、`reconcile_session_records` 冷启动幂等 reconcile、`SessionManager`（open/attach/close/complete/sweep_detached/note_provider_lost…，attach window 300s）。[MODULE.md](../../crates/nexus-session/MODULE.md)
- **不变量**：Completed/Failed/Cancelled 恰一次提交，`Unfinished` 不可提交；断开≠Failed；Disposed 后禁一切事件；reconcile 不重写已有 outcome，真孤儿恰一次提交 `Failed`。
- **依赖**：nexus-domain。纯 std；两个跨 crate 并发竞态测试 target。

### nexus-planner ⭐ — 唯一系统级 Core Planner（1 文件 1227 行）
- **负责**：`plan_from_snapshot` 两阶段求解（`filter_candidates` 硬谓词短路 → `connectivity_gate` 可行性门控 → `score_candidates` 归一化打分）→ `Planned{plan, trace}`；`ExplainMode` 双模式（History/Estimate，估算必标"非承诺"）。[MODULE.md](../../crates/nexus-planner/MODULE.md)
- **不变量**：全系统唯一 Core Planner；`breakdown` 分量之和恒等于总分；确定性 tie-break（已知 RTT 先→总分降序→ProviderId 字典序）；本地 Provider `LOCALITY_BONUS=1000`；`RejectReason` 是"为什么没被选"唯一出口。
- **依赖**：nexus-domain/registry/measurement。纯计算零 I/O，可编译 WASI。

### nexus-flow-session ⭐ — TUN 流→会话映射（5 文件 1300 行）
- **负责**：`FlowTable`（5 元组 O(1)）、`run_first_packet_chain`（首包链纯函数：Policy→Planner→建 Session）、flow 版 `SessionManager`（后台建连 + `FlowSignal` RST/TearDown 回填、Drop Reaper）、`UdpBuffer`（32 包/64KB 有界缓冲）。[MODULE.md](../../crates/nexus-flow-session/MODULE.md)
- **不变量**：已建流不调 Planner（`planner_calls` 计数器可证）；`process_one()` 永不阻塞；建连失败发 RST 不静默黑洞；NAT 换路不改流表项。
- **依赖**：domain/measurement/policy/planner/session/network（只读）。快路径 p99 预算 5µs 警戒/20µs 阻塞已冻结。

### nexus-service ◐ — Service 会话骨架（1 文件 103 行）
- **负责**：`ServiceSession::connect`（发 CONNECT 收 READY 后 Active）+ `ServiceTransport` 注入 trait。[MODULE.md](../../crates/nexus-service/MODULE.md)
- **不变量**：connect≠forward（P0 只冻结 connect）；外部监听须显式授权。
- **依赖**：domain/session（session 声明未用；delivery 未引）。

### nexus-diagnostics ○ — 诊断契约锚点（1 文件 7 行）
- **负责**：契约上定义统一诊断 DTO/类别（unknown/unreachable/unauthorized/no-valid-plan/crash-recovery）；**当前无任何 pub 符号**，`Diagnose` 命令实现组装层。[MODULE.md](../../crates/nexus-diagnostics/MODULE.md)
- **依赖**：nexus-domain。

### nexus-control-api ⭐ — Application Service DTO（6 文件 5742 行）
- **负责**：前端统一命令面 `ControlCommand`（Status/PlanExplain/SessionWatch/Connectivity*/Dns*/Workspace*/ComputeJobs/Diagnose/…）+ `ControlOutput` DTO；N3 六类任务操作 `TaskRequest`（Submit/Get/ReadLogs/Cancel/ListArtifacts/GetArtifact，`schema_version==1` 硬校验）；N3-12 `SnapshotRequest` staging（Staged≠task acceptance）。[MODULE.md](../../crates/nexus-control-api/MODULE.md)
- **不变量**：principal 来自已认证上下文不能自填；操作 PASS 不表示 task.outcome=Completed；分页/容量上限校验。
- **依赖**：nexus-domain（proto 允许未引）。含 4330 行契约测试（tests/snapshot_contract.rs）。

### nexus-connectivity ⭐ — 连接底座（35 文件 22965 行，最重 crate 之一）
- **负责**：确定性建连状态机（`establish`/`ConnectivityState`）、`LinkActivator` Direct→Relay 回退、`evaluate_connectivity` 规划期评估、`LinkMarker` reconcile、`OutboundAdapter` 出站接缝、**虚拟子网数据面**（`VirtualSubnetTunnel`/`Coordinator`/`VirtualIpAllocator`/X25519+ChaCha20Poly105 加密/`ReplayWindow`）、DERP 类 `RelayChannel`、QoS 双件（`TokenBucket`+`CakeScheduler`）、`FirewallEngine`、`HealthMonitor`、bootstrap 服务端/入网。[MODULE.md](../../crates/nexus-connectivity/MODULE.md)
- **不变量**：Evaluation 是规划输入、Establishment 只在 Plan/Session 后（Plan before Connectivity）；认证门控 fail-closed（未认证零探测零发送）；sans-IO 全注入（`PacketCarrier`/`VirtualPacketInterface`/`LinkProbe`）；诚实 recovery（`reconcile_link_markers` 不假装链路活着）。
- **依赖**：platform/domain/measurement（delivery 允许未用）+ `ring`/`x25519-dalek`/`flate2`/`lz4_flex`。全同步无 tokio。**⚠ 命名注意**：`PathConnector`/`UdpTransport`/QUIC driver 不在本 crate（见 nexus-path / nexus-fabric）。

---

## 3. 投递底座与传输

### nexus-delivery ○ — 共享底座锚点（1 文件 7 行）
- **负责**：契约上定义 Link/Path/Connection、Delivery Request 与绑定抽象；**当前零 API**，编译锚点。[MODULE.md](../../crates/nexus-delivery/MODULE.md)
- **不变量**：不反向依赖 workspace/compute（实际无任何业务代码）。**依赖**：nexus-domain。

### nexus-fabric ⭐ — QUIC-like 会话层（5 文件 2864 行 + tests/examples 1709）
- **负责**：`FabricConn`/`FabricListener`（可靠流 + 不可靠 datagram + TLS 1.3 E2E）、`(PeerId, ConnectionId)` 连接身份（与 UDP 五元组解耦，漫游不断流）、`Driver`（sans-IO quinn-proto 直驱，std 线程）、`UdpTransport` trait 依赖倒置（`TurnSocket`/`ProxyTransport` 可注入）、`FabricIdentity`/`PeerPinVerifier`、QSEQ 序号 datagram。[MODULE.md](../../crates/nexus-fabric/MODULE.md)
- **不变量**：S1 E2E 加密（中继只见密文）；S3 漫游不丢数据 + challenge/response 防欺骗；S8 统计诚实（无样本不编 0）；S11 connect 单一超时预算。
- **依赖**：零 nexus-\*；`quinn-proto`（**vendor 补丁 quinn#2658** 漫游 loss-detection 修复）+ bytes/rcgen/ring。

### nexus-path ⭐ — 路径层（4 文件 2034 行）
- **负责**：`PathManager`（候选管理+EWMA 打分+hysteresis 切换+`PathEvent`）、四级回退 `FallbackChain`（Direct→Proxy→Turn）、`race_connect` staggered 竞速（`PathConnector` 注入）。[MODULE.md](../../crates/nexus-path/MODULE.md)
- **不变量**：S1 单活跃路径、S2 切换只换 socket 不丢连接（CID 不变）；S4 hysteresis 优于当前 20% 且持续 3s；S7 无探测数据=unknown 不编分数；不构造任何传输 socket。
- **依赖**：**零依赖**。

### nexus-turn ⭐ — TURN 中继（6 文件 2128 行）
- **负责**：RFC 5766 最小实现（Allocate/Refresh/CreatePermission/ChannelBind/ChannelData、长效认证 HMAC-SHA1）、`TurnSocket` 实现 `fabric::UdpTransport`（QUIC over RELAY）、最小 `TurnServer`（自测用）。[MODULE.md](../../crates/nexus-turn/MODULE.md)
- **不变量**：T2 中继不解密；T3 只发往已授权对端（未授权丢弃计数）；T4 分配 600s 过期显式报错不静默黑洞。
- **依赖**：nexus-fabric（仅 trait）+ hmac/sha1/md5。

### nexus-nat-traversal ⭐ — 打洞编排核心（4 文件 958 行）
- **负责**：`PunchSession` 打洞状态机（终态恰一次：`Migrated{addr}` | `StayedOnRelay{reason}`）、P2 信令编解码、候选收集/端口预测（SprayPlan）。**注意：唯一无 MODULE.md 的 crate**，契约在 `docs/foundation/NAT-TRAVERSAL-CONTRACT.md`。
- **不变量**：`PunchSocket` 必须是 QUIC 连接同一 UDP socket；冻结配置默认值（5s 超时/200ms 协调偏差/spray_k 16）。
- **依赖**：nexus-connectivity（复用 `NatType`）。

### nexus-nat-wireup ⭐ — 打洞生产接线（4 文件 1568 行）
- **负责**：`PunchManager`（responder/去重/tie-break/direct 登记）、`FabricPunchChannel`（中继流信令）、`DriverPunchSocket`（QUIC 建连扇出）、D4 nonce 挑战-应答、D5 流类型前缀 framing。[MODULE.md](../../crates/nexus-nat-wireup/MODULE.md)
- **不变量**：`Migrated` 语义=直连 QUIC 握手已完成；tie-break 确定性（PeerId 大者保留）；中继连接 Migrated 后不关闭（warm backup）。
- **依赖**：fabric/nat-traversal/connectivity（turn 仅 dev）。

### nexus-nat-quality ⭐ — 路径质量测量（4 文件 1043 行）
- **负责**：`QualityMonitor` 常驻线程（探针 ping active 1s/backup 5s）、`LossProbe` 滑动窗口丢包（无样本=None 不参选）、25B 探针帧编解码、切换事件转发给 `PathManager::on_stats`。[MODULE.md](../../crates/nexus-nat-quality/MODULE.md)
- **不变量**：loss 测量是必答题不许只用 RTT；非探针 datagram 不静默吞。
- **依赖**：fabric/path，std-only。

### nexus-transport ◐ — 帧流抽象（1 文件 94 行）
- **负责**：`FrameStream`（`u32 BE` 长度前缀帧，冻结）、`connect`/`accept`、`into_raw` 取回 TcpStream 供 relay 中继。[MODULE.md](../../crates/nexus-transport/MODULE.md)
- **不变量**：Transport≠Connectivity；帧协议与错误变体冻结（Protected）。
- **依赖**：platform（delivery 声明未用）。

### nexus-proto ○ — wire schema 锚点（1 文件 7 行）
- **负责**：wire/control contract 的 portable schema 边界与代码生成占位接口；**零类型零消费者**。[MODULE.md](../../crates/nexus-proto/MODULE.md)
- **不变量**：wire schema 显式版本化；内部领域类型不得直接等同 wire DTO。

### 出站协议族（6 crate，全部 tokio-free、离线确定性、`OutboundAdapter` 接缝）

| crate | 协议 | 关键机制 | src 行数 |
|---|---|---|---|
| [nexus-outbound-shadowsocks](../../crates/nexus-outbound-shadowsocks/MODULE.md) | Shadowsocks | chacha20-ietf-poly1305 AEAD 记录层、HKDF 双 key、`SsStream` 会话 | 461 |
| [nexus-outbound-vmess](../../crates/nexus-outbound-vmess/MODULE.md) | VMess | AEAD 记录层（UUID→SHA-256 派生 key）；不承诺线格式逐字节兼容 | 220 |
| [nexus-outbound-trojan](../../crates/nexus-outbound-trojan/MODULE.md) | Trojan | trojan-gfw 官方请求头 `hex(SHA-224(pwd))`、Standard/Singbox 双格式、rustls | 502 |
| [nexus-outbound-anytls](../../crates/nexus-outbound-anytls/MODULE.md) | AnyTLS v2 | TLS 上会话多路复用、Settings/padding-md5、UDP-over-TCP | 1662 |
| [nexus-outbound-vless](../../crates/nexus-outbound-vless/MODULE.md) | VLESS | XTLS-Vision 状态机、fail-closed flow/command、错误不回显 UUID | 1786 |
| [nexus-outbound-hysteria2](../../crates/nexus-outbound-hysteria2/MODULE.md) | Hysteria2 | QUIC+最小 H3 认证（`:status 233`）+ Salamander 混淆 + 自写 sans-IO driver | 3292 |

全部实现 `nexus_connectivity::OutboundAdapter`；全部 `#![forbid(unsafe_code)]`。
**⚠** shadowsocks/trojan 的 Cargo 声明了 `nexus-plugin` 但源码未用。

---

## 4. 代理栈与数据面

### nexus-ingress ⭐ — 系统级输入组件（2 文件 1228 行）
- **负责**：`Socks5Handshake`（RFC 1928/1929 吸收式 enum 状态机）、`HttpProxyHandshake`（CONNECT）、`parse_ipv4_packet`/`TunPacket`（TUN IPv4 五元组解码）、`FlowContext` 构造（`from_socks5/from_http/from_virtual_packet_interface/from_native_api`）。[MODULE.md](../../crates/nexus-ingress/MODULE.md)
- **不变量**：Established 前不产出 FlowContext；只做协议解析不持凭据库（授权归上层）；不调 Planner、不含平台透明拦截。
- **依赖**：nexus-domain。

### nexus-proxy ⭐ — 规则分流内核（4 文件 2204 行）
- **负责**：`RuleEngine::route`（静态规则表线性首匹配，纯函数零 I/O）、`ProxyService::route` 编排（规则→策略组→出站 tag→委派 `LinkActivator`）、策略组（`selector`/`urltest`/`load_balance`/`relay`）、NXGEOIP/NXGEOSITE 解析、`TunNatRouter` TUN per-packet 决策。[MODULE.md](../../crates/nexus-proxy/MODULE.md)
- **不变量**：`rule_action` 首动作必须 `SELECT_OUTBOUND <tag>`；MATCH 规则必须表尾；urltest 按离线 measurement 选 RTT 最低（同分 tag 字典序）；出站激活只报告事实不替换 tag；**不产生第二套系统级 Plan**。
- **依赖**：domain/proxy-config/ingress/connectivity/measurement（policy/planner 声明未用）。

### nexus-proxy-config ⭐ — 配置模型层（1 文件 2360 行）
- **负责**：`parse(yaml)` → `ProxyConfig` typed structs（inbounds/rules/groups/outbounds/dns/speedtest/订阅）+ 结构化校验（悬空引用 → `CONFIG_INVALID{field,reason}`）；`parse_clash_subscription`（ss://vmess:// 映射，其余显式 `rejected`）。[MODULE.md](../../crates/nexus-proxy-config/MODULE.md)
- **不变量**：解析纯函数零 I/O；规则表必须以 MATCH 结尾；WASI 可检查（不碰文件系统）。
- **依赖**：**零依赖**（内置最小 YAML 子集解析器）。**⚠** `OutboundKind` 实际 9 种（direct/relay/ss/vmess/trojan/socks5/anytls/vless/hysteria2），MODULE.md 只列 5 种。

### nexus-proxy-transport ⭐ — per-link 代理传输（6 文件 2297 行）
- **负责**：SOCKS5/ss/trojan 握手 → TCP → 2 字节长度前缀成帧 → 实现 `fabric::UdpTransport`（QUIC 经代理隧道零改动接入）。[MODULE.md](../../crates/nexus-proxy-transport/MODULE.md)
- **不变量**：X1 单 datagram ≤1200B 超限报错不截断；X2 代理层只见 QUIC 密文；T3 密码学只调 outbound-\* 公开原语不重写；全 std 零 tokio。
- **依赖**：fabric（仅 trait）/outbound-shadowsocks/outbound-trojan/proxy-config + rustls。**⚠** ss 线格式与公网 ss 不兼容，未验证互操作不得宣称。

### nexus-network ⭐ — Network Domain Runtime + N1 装配（7 文件 3551 行）
- **负责**：`NetworkSession::establish` 远程网络会话；N1 mesh（`N1SessionManager` 按 PeerId 管连接、`VpiPump` TUN↔datagram 包泵、`LinkStateWatcher` keepalive 漫游 rebind、`[boost]` 配置）。[MODULE.md](../../crates/nexus-network/MODULE.md)
- **不变量**：**不编译依赖 nexus-ingress（核心禁边）**；M2 IP 包走 fabric unreliable datagram；M3/M4 Identity≠Locator（rebind 不换 CID）；M5 漫游失败只报告事实由 Planner 决定替代 Plan。
- **依赖**：domain/policy/planner/session/dns/platform（delivery 允许未用；fabric/path/discovery 经注入 trait）。

### nexus-dns ⭐ — DNS 统一子系统（2 文件 1634 行）
- **负责**：`DnsRuntime`（解析+缓存+Exit-DNS Binding）、`DnsRouter` 多 server 路由、`UnifiedDns` 统一分类（hosts > mesh 后缀 > fake-ip > 上游）、`FakeIpPool`（198.18.0.0/15，TTL 内同域名同 IP）。[MODULE.md](../../crates/nexus-dns/MODULE.md)
- **不变量**：singleflight（同 name+rtype TTL 内底层解析至多一次）；环路守卫 `LoopDetected`；负缓存；时间显式 `now_secs` 注入。
- **依赖**：nexus-domain。`ProxyClassifier`/`MeshNameResolver`/`Resolver` 全注入（Deletion Test：不直依赖 nexus-proxy）。

### nexus-projection ⭐ — L3 隧道 + 统一路由（14 文件 12536 行，数据面最大）
- **负责**：`Projection`（TUN IP 包 ↔ fabric datagram，载荷=1B 意图位+IP 包）、`UnifiedRouter`、出口 NAT + 真实 socket egress、smoltcp TCP 终结（`TcpTerminator`/`TcpRelay`）、`DnsSniffer`、`SemanticIngress`（SOCKS5/HTTP 显式代理）、多路径调度（`PathScheduler`/`ReorderBuffer`）、`FlowSessionHub`、`TunRsDevice` 真实 TUN、进程归因/QoS 标记。[MODULE.md](../../crates/nexus-projection/MODULE.md)
- **不变量**：IP 包字节级一致、超 MTU 丢弃计数不截断；跳数验证防环路；域名规则优先 IP 规则；DNS 响应 TXID 校验；域名不在 originator 本地解析（防 DNS 泄漏）；S27b NAT 多连接永不 rebind。
- **依赖**：domain/fabric/ingress/nat-wireup/path + smoltcp/tun-rs。禁依赖 nexus-proxy 与 tokio（已核实均无）。**⚠** nat-wireup 未列入 MODULE.md Allowed（policies 已声明）。

### nexus-compute ⭐ — N3 提供方 TaskOwner（7 文件 1933 行）
- **负责**：`TaskOwner`（接受/幂等/状态机唯一写者）、`AcceptanceLedger`（原子接受镜像 + 幂等索引）、`RuntimeJournal`（连续序号事件、replay 幂等）、`RequesterMirror`（请求方只读镜像）、`ComputeJobSession`（P0 帧往返，与 N3 Task 并存不混同）。[MODULE.md](../../crates/nexus-compute/MODULE.md)
- **不变量**：execution adapter 只供事实不赋 TaskOutcome；`StartIntent` 崩溃窗口必须核实（未知不 spawn）；上传中断不能重跑命令；幂等 key 过期固定于首次接受时刻。
- **依赖**：domain/session/workspace（delivery 允许未用）。

---

## 5. 平台、工作区与独立产品

### nexus-platform ⭐ — capability traits（4 文件 600 行）
- **负责**：`VirtualPacketInterface`/`PacketCarrier`/`SecureStore`（NEXSEC1 AEAD 记录）/`SystemProxyController`/`AutostartRegistrar`/`ProjectedWorkspace`/`UdpCarrier` 等平台无关 trait + 结构化 `PlatformError`。[MODULE.md](../../crates/nexus-platform/MODULE.md)
- **不变量**：平台专有类型不得泄漏进 portable trait；能力缺失走 `Unavailable` 显式不静默降级。
- **依赖**：零 nexus-\*（仅 `ring`）。

### nexus-platform-linux ⭐ — Linux 适配（15 文件 4044 行）
- **负责**：`TunVpi`（/dev/net/tun + TUNSETIFF 窄 FFI）、netlink 地址/路由、`OsAssemble` 事务装配（快照→apply→失败自动 rollback）、FUSE workspace 投影（`fuse_ws`，fuser 0.18）、`file_lease` flock 租约、`directory_publish`（renameat2 原子无覆盖）、`FileSecureStore`（machine-id）。[MODULE.md](../../crates/nexus-platform-linux/MODULE.md)
- **不变量**：O1–O6 装配纪律（默认不开 default-route、`--dry-run` 零 netlink 写、幂等）；生产依赖仅 nexus-platform（workspace/storage 仅 dev）。
- **依赖**：nexus-platform + fuser。

### nexus-platform-windows ⭐ — Windows 适配（8 文件 1787 行）
- **负责**：`WintunVpiAdapter`（运行时加载 wintun.dll 窄 ABI）、`WinInetSystemProxy`、`TaskSchedulerAutostart`、`DpapiSecureStore`、`netcfg`（netsh/route）。[MODULE.md](../../crates/nexus-platform-windows/MODULE.md)
- **不变量**：unsafe 仅限两处窄 FFI 各带 Safety Invariant；WinINET 写路径成对 broadcast；自启任务名前缀 `nexus-` 幂等。
- **依赖**：仅 nexus-platform。

### nexus-platform-{macos,android,ios} ○ — 骨架（各 1 文件 7 行）
- 契约已写（macOS 系统托管网络/文件投影；Android VPN Service+underlay bypass；iOS Packet Tunnel Extension+可强杀语义），**src 仅编译锚点、无 pub 符号**，业务 API 待实现。[macOS](../../crates/nexus-platform-macos/MODULE.md) / [Android](../../crates/nexus-platform-android/MODULE.md) / [iOS](../../crates/nexus-platform-ios/MODULE.md)

### nexus-workspace ⭐ — Commit DAG / CAS / GC（6 文件 6970 行）
- **负责**：`WorkspaceCommit`（**CommitId=内容哈希**，全节点确定性一致）、`HeadSet`（多 Head）、`Workspace<S: ContentStore>`（journal 两段提交/`reconcile_journal`/`merge_heads` 三方合并/`resolve_conflict`/`exchange_heads`/`sync_with_remote`）、`ConflictObject` 持久冲突、GC 机制（`GcRoots`/`plan_gc`/`apply_tombstones`/`sweep`，默认保留 14 天）、`CacheManager`（pin 铁律）、`FrozenSnapshot`（N3 快照）。[MODULE.md](../../crates/nexus-workspace/MODULE.md)
- **不变量**：标量序列号永不作版本权威（DurableState v2）；Head 交换校验 `id==hash(content)`；离线分叉不丢本地提交；GC 只删"不可达+超保留期"；Cache Eviction ≠ CAS GC。
- **依赖**：domain/session/storage/platform（delivery 允许未用）。

### nexus-workspace-intel ⭐ — 访问智能层（8 文件 1135 行）
- **负责**：`AccessTrace`/`WorkspaceGraph`/`WorkingSetEstimator`/`PrefetchScheduler`/`IntelStore`——可丢失重建的非权威访问智能（预取计划不含 Provider/Path，取回必须经 Core Planner）。[MODULE.md](../../crates/nexus-workspace-intel/MODULE.md)
- **不变量**：删 IntelStore 不影响 workspace 正确性；纯函数确定性；对 workspace 只读。
- **依赖**：domain/workspace(只读)/planner/registry/storage。

### nexus-web-gateway ⭐ — 浏览器 SSH 网关（9 文件 3811 行 + tests 2043）
- **负责**：每节点 Web 接入点（HTTPS 静态页 + WSS 信令 + str0m WebRTC DataChannel + ssh2 真实 SSH 客户端），mesh SDP 中继（`MeshSignaler` 接缝）。[MODULE.md](../../crates/nexus-web-gateway/MODULE.md) / [USER_MANUAL.md](../../crates/nexus-web-gateway/USER_MANUAL.md)
- **不变量**：G1 全程 TLS；G3 SSH 协议只发生在节点↔sshd；G4 凭证只存内存；G10 证书 0700/0600 原子写。
- **依赖**：**零 Nexus 内部依赖、零 async runtime**（str0m/tungstenite/rustls/ssh2 同步线程模型）。

---

## 6. 组装层（apps/）

### apps/nexus ⭐ — CLI 瘦客户端 + SDK 组合根（src 43 文件 ~3.7 万行）
- **负责**：CLI 参数解析/渲染（完整命令表见 [05](05-running-and-development.md)）、thin-client（LocalAPI，daemon 不可达输出 `DAEMON_UNREACHABLE` exit 0）、进程内 SDK 命令族（network/subnet/schedule/proxy/system-proxy/pair/node…）、Composition Root 纵切装配（`internet_access_flow`/`remote_*_flow` 等，nexusd 复用）。
- **不变量**：app 不承载可复用领域逻辑；无路由命令本地合成显式 `UNSUPPORTED` 不静默降级；`use` 拒绝 `-- <cmd>`（N3 语义走 task）。
- **⚠**：MODULE.md Allowed 仅 control-api，但作为组合根 Cargo 实际装配 30+ nexus crate（Cargo.toml 有注释豁免说明）。模块清单：`*_cli.rs`（resource/session/use/plan/node/pair/task/subnet/grant/provider/schedule/snapshot）、`localapi_client`、`observability`、`network`、`mesh`、N2/N3 持久层等。

### apps/nexusd ⭐ — daemon / 主 Runtime 组合根（src 68 文件 ~3.9 万行）
- **负责**：`nexusd <config-folder>` 入口（配置热加载 2s、校验失败拒绝应用不 crash）、LocalAPI（bearer token 常量时间比较 fail-closed、unix socket/TCP）、数据面装配（单 TUN `nexus0`、分类器 Mesh/Proxy/Direct/Drop、DNS 短路、CAKE QoS）、N2 唯一 `SessionManager` + sweeper、N3 任务执行/容量/制品/恢复、NAT 打洞/TURN/中继切换、workspace FUSE 挂载。
- **配置族**（缺失=不启用）：`daemon.toml`（LocalAPI/tun/qos/turn）/ `network.toml`（N1 mesh）/ `proxy.yaml`（Clash 风格出口）/ `dns.toml` / `workspace.toml`。
- **不变量**：daemon 只装配不复制领域逻辑；单 TUN 所有权；N1/DNS 装配失败计数降级、仅 TUN 失败致命；结构化并发全线程有 Owner。

### apps/nexus-platform-host ◐ — 平台宿主（1 文件 58 行）
- **负责**：按 feature 装配 platform-\* adapter，唯一命令 `vpi-capabilities [--json]`（静态声明，供 E4 机检）。零第三方依赖。

---

## 7. 工程平面

### engineering/nexus-harness ⭐ — 工程验证入口
- **负责**：Project Discovery / Context（含语义锚点）/ Affected Analysis / 13 个 CLI 命令 / Policy Evaluation / Evidence 写入 / 失败解释 / Code Intelligence（8 个只读语义查询 + MCP 薄适配 + provider daemon）。
- **不变量**：`--json` 必含 `schema_version/command/verdict/message`；Agent claim 不产生最终 PASS；gate 失败显式 FAIL/BLOCKED/UNKNOWN 不静默降级；指纹取不到报哨兵值不当确定取值；code 查询 `authority` 恒 advisory。
- 细节见 [05](05-running-and-development.md) 与 [MODULE.md](../../engineering/nexus-harness/MODULE.md)。
