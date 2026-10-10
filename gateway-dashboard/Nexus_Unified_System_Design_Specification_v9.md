# Nexus 统一系统设计规范 v9

**文档状态：Final Design Baseline**
**文档性质：产品运行时、跨平台能力、分布式 Workspace、Agent-Native 工程验证与 Rust 工程治理统一规范**
**适用范围：Nexus Resource Fabric、Discovery、Planner、Session Runtime、Connectivity、Transport、Ingress、DNS、Workspace、Compute、Platform Runtime、CLI/API、Engineering Harness、Verification、Evidence 与 CI**

## 1. 系统定义

Nexus 是一个面向个人设备、服务器、云环境、沙箱与外部基础设施的统一资源运行时。系统将网络访问能力、服务、Workspace、计算能力与设备能力组织为动态 Resource Fabric，并使用统一的 Resource、Intent、Plan、Session 与 Measurement 模型完成发现、规划、执行、交付、观测与恢复。Nexus 的最高层执行闭环固定为：

```text
Resource + Intent
        ↓
Resolve Candidate Providers
        ↓
Plan Placement + Path
        ↓
Create Session
        ↓
Establish Connectivity
        ↓
Execute
        ↓
Observe + Adapt
```

规划阶段只能执行低成本 Resolution、Connectivity Evaluation、历史 Measurement 查询与领域估计；NAT Traversal、Hole Punching、Relay 激活等高成本 Connectivity Establishment 必须在 Plan 收敛并创建 Session 后针对选中的 Path 执行。Network、Service、Workspace 与 Compute 都映射到这一闭环；TUN、Packet Tunnel、Proxy、Relay、Filesystem Projection、FUSE、Remote Executor、Cache、Multipath 等均属于执行机制，不构成新的顶层领域模型。

Nexus 同时包含两个正交平面：

```text
Product / Runtime Plane
  Nexus 如何正确运行

Engineering / Verification Plane
  人与 Agent 如何可靠理解、修改、验证和恢复 Nexus 工程状态
```

Engineering Harness 不进入生产运行时领域模型，也不成为产品真相来源。

## 2. 核心领域模型与边界

稳定核心对象统一为：

```text
Resource
Provider
Node
Intent
Constraint
Plan
Session
Measurement
```

`Resource` 表示可使用的能力或对象；`Provider` 表示提供 Resource 的主体；`Node` 是具有稳定 Identity、动态 Presence 与 Capability 的 Provider；`Intent` 表示使用目标；`Constraint` 表示硬条件；`Plan` 表示 Provider、Placement、Path 与 Execution Strategy 的执行决策；`Session` 表示 Plan 的运行实例；`Measurement` 表示事实观测。

以下边界属于架构不变量：

```text
Resource ≠ Provider
Provider ≠ Node
Node ≠ IP
Identity ≠ Locator
Plan ≠ Session
Measurement ≠ Score
Policy ≠ Path
Connectivity Evaluation ≠ Connectivity Establishment
Connectivity ≠ Transport
Portable Ingress ≠ Platform Interception
Virtual Packet Interface ≠ TUN
Workspace ≠ Filesystem
Workspace ≠ Mount
WorkspaceGraph ≠ CAS
Profile ≠ Snapshot
Prefetch ≠ Sync
Planner ≠ Estimator
Planner ≠ Scheduler
TerminalOutcome ≠ LifecyclePhase
Portable Core ≠ Platform Runtime
Product Capability ≠ Platform Capability
```

## 3. 调用方向与编译依赖约定

规范中严格区分运行时调用流与 Cargo 编译依赖。符号定义如下：

```text
A ==> B
运行时 A 调用、驱动或提交工作给 B

A --> B
编译期 A 依赖 B 的公开类型、trait 或 API
箭头始终指向被依赖方
```

典型运行时调用流：

```text
Ingress / User Request
  ==> Application Service / SessionManager
  ==> Policy + Core Planner
  ==> Session Runtime
  ==> Domain Runtime
  ==> Delivery Infrastructure
  ==> Platform Capability
  ==> OS / Framework
```

运行时调用流不等于 Cargo 依赖图，所有实现必须遵守 Dependency Inversion。

## 4. 完整 Cargo 依赖基线

核心依赖关系固定如下；未列出的依赖默认禁止，新增依赖必须通过架构 Policy 审核：

```text
# Core types
nexus-registry      --> nexus-domain
nexus-policy        --> nexus-domain
nexus-auth          --> nexus-domain
nexus-measurement   --> nexus-domain
nexus-session       --> nexus-domain
nexus-storage       --> nexus-domain

# Discovery / registry
nexus-discovery     --> nexus-domain
nexus-discovery     --> nexus-registry
nexus-discovery     --> nexus-platform

# Planner
nexus-planner       --> nexus-domain
nexus-planner       --> nexus-registry
nexus-planner       --> nexus-measurement

# Delivery
nexus-delivery      --> nexus-domain
nexus-connectivity  --> nexus-delivery
nexus-connectivity  --> nexus-platform
nexus-transport     --> nexus-delivery
nexus-transport     --> nexus-platform

# Portable ingress / network domain
nexus-ingress       --> nexus-domain
nexus-dns           --> nexus-domain
nexus-network       --> nexus-domain
nexus-network       --> nexus-policy
nexus-network       --> nexus-planner
nexus-network       --> nexus-session
nexus-network       --> nexus-delivery
nexus-network       --> nexus-dns

# Other domains
nexus-service       --> nexus-domain
nexus-service       --> nexus-session
nexus-service       --> nexus-delivery

nexus-workspace     --> nexus-domain
nexus-workspace     --> nexus-session
nexus-workspace     --> nexus-delivery
nexus-workspace     --> nexus-storage

nexus-compute       --> nexus-domain
nexus-compute       --> nexus-session
nexus-compute       --> nexus-delivery
nexus-compute       --> nexus-workspace

# Wire/control contract
nexus-proto         --> prost / tonic only
nexus-control-api   --> nexus-domain
nexus-control-api   --> nexus-proto

# Platform
nexus-platform-<os> --> nexus-platform

# Frontends
CLI / GUI / Agent Client / SDK --> nexus-control-api

# Composition Root
nexusd / platform host --> domain runtimes
nexusd / platform host --> ingress adapters
nexusd / platform host --> platform adapters
```

禁止的关键反向依赖：

```text
nexus-domain       -X-> nexus-platform-*
Portable Core      -X-> OS Framework
nexus-delivery     -X-> nexus-workspace / nexus-compute
nexus-network      -X-> nexus-ingress
production crates  -X-> Engineering Harness
platform adapters  -X-> higher-level domain runtimes
```

`nexus-network` 不拥有或编译依赖 `nexus-ingress`；二者由 Composition Root 同时装配。

## 5. Portable Core、Composition Root 与 Deletion Test

Portable Core 中禁止直接调用具体 OS Framework。Clock、Random、Secure Store、Packet Interface、Transparent Interception、Filesystem Projection、Process Attribution、Background Lifecycle 等宿主能力都通过 portable trait 注入。平台实现只存在于 `nexus-platform-*`，Composition Root 负责把这些实现与 Domain Runtime 组装。

每新增一个 trait、adapter 或 indirection layer，必须通过 Deletion Test：如果删除该抽象并直接依赖当前实现，会破坏哪个已经存在的独立变化维度？允许理由包括多个真实平台实现、隔离不可移植依赖、安全边界、生命周期边界、稳定测试替身或必须保持依赖方向；“未来也许会有第二个实现”本身不足以增加抽象。

## 6. Resource Fabric、Discovery 与 Bootstrap

Resource Fabric 是统一逻辑资源空间，产品层可以展示为 Devices、Network、Services、Workspaces 与 Compute，但底层仍使用统一 Resource/Provider 模型。Discovery 负责 Identity、Presence、Capability、Resource Metadata、Provider Advertisement 与 Locator；Bootstrap/Rendezvous 只负责初始发现、候选交换与 Presence 建立，不承担长期业务数据转发。Provider Advertisement 至少包含 ProviderId、可选 NodeId、ResourceId、Capability Set、Locator Set、Region、Availability 与静态属性，高频动态状态进入 Measurement 或 Provider State。

## 7. 唯一 Core Planner 与 DomainExtension

全系统只有一个系统级 `Planner`，负责决定：

```text
Provider
Placement
Path
Execution Strategy
```

Planner 输入包含 Resource、Intent、Constraint、Candidate Providers、Capabilities、Measurements、Connectivity Feasibility、Platform Capabilities、Domain Planning Inputs 与 Current Runtime State。领域内部可以拥有 Estimator、Evaluator、Scheduler，但不能生成第二套系统级 Plan。

核心 Plan 保持领域中立：

```text
Plan
├─ PlanId
├─ ResourceId
├─ ProviderId
├─ Placement
├─ Path
├─ ExecutionStrategy
└─ DomainExtension
```

`DomainExtension` 必须版本化且类型安全，可包含 NetworkPlanExtension、WorkspacePlanExtension、ComputePlanExtension 与 ServicePlanExtension。DNS Binding、Workspace Snapshot、Sandbox Spec 等领域特有信息不得污染核心 Plan 固定字段。Planner 同时生成结构化 DecisionTrace，记录候选生成、过滤原因、Measurement、Connectivity Feasibility、Score Breakdown、Dominance Decision 与最终选择。

## 8. Connectivity Evaluation 与 Connectivity Establishment

### 8.1 Connectivity Evaluation

Connectivity Evaluation 是规划输入，不正式建立业务 Link。它根据 Known Locators、LAN/IPv6 Hints、NAT Observation、历史成功率、Recent RTT/Loss、Relay Availability、Existing Links 与 Platform Network Capability 输出 DirectLikely、PunchingLikely、RelayAvailable、ExistingLinkAvailable、EstimatedSetupCost 与 Confidence。

### 8.2 Connectivity Establishment

Session 创建后，才针对 Plan 中选中的目标执行 Link 激活：Reuse Existing Link、LAN Direct、IPv6 Direct、Public Endpoint Direct、NAT Traversal、Hole Punching、Assisted Connectivity 或 Relay Fallback。建立失败后，Connectivity 只报告失败事实，不自行替换业务 Provider；Session Runtime 把事实反馈给 Core Planner，再生成替代 Plan。

## 9. Delivery Infrastructure

Delivery Infrastructure 是 InternetAccess、Service、Workspace 与 Compute 共享的交付底座：

```text
Delivery Infrastructure
├─ Connectivity
│  ├─ Evaluation
│  ├─ Establishment
│  └─ Link State
├─ Transport
│  ├─ Stream
│  ├─ Datagram
│  ├─ Multiplexing
│  ├─ Backpressure
│  └─ Flow Control
└─ Delivery Session Binding
```

`Link` 表示已经可以使用的一段逻辑通信能力；`Path` 表示 Planner 选择的逻辑交付路径；`Connection` 表示 Session 中实际建立的传输实例。Planner 可以规划尚未激活的逻辑 Link，执行阶段由 Connectivity 激活。Transport 不负责业务 Provider 选择。

## 10. Ingress 的系统级驱动角色

Ingress 是系统级输入管道，而不是 `nexus-network` 的私有子件。Composition Root 同时装配 Ingress 与 Network Runtime；Ingress 只负责把外部流量转换为中立 `FlowContext`，然后提交给 Application Layer 的 `SessionManager`：

```text
Platform Interception / SOCKS / HTTP / Virtual Packet Source
                    ↓
             Portable Ingress
                    ↓
               FlowContext
                    ↓
          SessionManager / Application Service
                    ↓
                 Policy
                    ↓
              Core Planner
                    ↓
          Create Network Session
                    ↓
            nexus-network Runtime
```

`nexus-ingress` 不直接调用 Planner，不创建 Session，也不依赖 `nexus-network`。`nexus-network` 同样不依赖 `nexus-ingress`。二者只通过 `FlowContext`、Application API 与 Session 生命周期发生运行时协作。

## 11. Portable Ingress 与 Platform Interception

`nexus-ingress` 必须是 Portable Crate，只实现 SOCKS5/HTTP 协议状态机、portable TCP/UDP dispatch semantics、Packet Stream Decoder、Flow Classification 与 FlowContext Construction。它不直接创建 OS Socket，不读取 `SO_ORIGINAL_DST`、TPROXY metadata、Windows 驱动重定向信息或 Apple 平台专有对象。

OS 绑定的流量拦截进入 `nexus-platform-*`，通过 `TransparentIngressProvider`、`VirtualPacketInterface`、`PacketSource`、`ByteStream`、`DatagramFlow` 等 portable trait 把流量注入 `nexus-ingress`。因此 `nexus-ingress` 必须通过 WASI 或等价非桌面宿主目标的 Portable Core 检查。

## 12. Virtual Packet Interface 与跨平台网络入口

统一抽象为 `VirtualPacketInterface`，而不是把 Linux TUN 作为跨平台模型。平台映射包括 LinuxTunAdapter、WindowsPacketAdapter、MacOSPacketTunnelAdapter、AndroidVpnServiceAdapter 与 IOSPacketTunnelAdapter。Android 还必须提供 Underlay Bypass，防止 Nexus 底层 Socket 再次进入自身 VPN；iOS/macOS 允许 Runtime 由系统 Extension 承载，不能假设独立 daemon + root helper。

从 Core 看，跨平台统一点是 Packet Semantics：

```text
Packet Source
  ↓
FlowContext
  ↓
Policy
  ↓
Planner
  ↓
Session
```

## 13. Policy、DNS 与 InternetAccess

Policy 根据 FlowContext、Resource Context、业务状态、设备状态和用户配置生成 Intent + Constraint；规则不直接绑定底层协议。Process/Application Attribution 是可选 Platform Capability，未知字段必须显式表示 Unknown/None。

DNS 是 Network Domain Extension，包含 Resolver、DNS Routing、Cache、Synthetic/Fake-IP Mapping、Domain↔Flow Correlation、IPv4/IPv6 Preference 与 Exit-DNS Binding。DNS 特有信息通过 NetworkPlanExtension 表达。

InternetAccess 是标准 Resource。传统代理概念映射为：Inbound→Ingress，Rules→Policy，Outbound→InternetAccess/Transport Provider，Selector→Core Planner，URL Test→Measurement，Fallback→Session Runtime + Replan，Detour→Path Composition，Multi-exit→Candidate Providers，Proxy Chain→Bounded Path Composition。

## 14. Session 双轨状态与 Exactly-One Outcome

Session 使用双轨状态模型：

```rust
enum LifecyclePhase {
    Allocating,
    Active,
    Draining,
    Disposed,
}

enum TerminalOutcome {
    Unfinished,
    Completed(SessionResult),
    Failed(DomainError),
    Cancelled(CancellationReason),
}
```

`TerminalOutcome` 一旦从 Unfinished 提交为 Completed/Failed/Cancelled，终身不可改变；资源仍可在 Outcome 确定后继续进入 Draining，最后到达 Disposed。Exactly-One Terminal Outcome 只约束业务结果，不与资源处置生命周期混合。

## 15. Structured Concurrency 与 Shutdown

任何长期异步任务都必须有 Owner、CancellationToken、JoinSet/Reaper 与终态归属。禁止无 Owner 的 fire-and-forget、丢弃 JoinHandle、Worker 直接写 TerminalOutcome、多个 boolean 表示生命周期、取消后不等待 cleanup 或重复提交 Outcome。AbortOnDropHandle 用于所有权失效保护，CancellationToken 用于 cooperative cancellation，JoinSet/Reaper 用于确认任务真正退出并消费 normal/error/panic。

### 15.1 Graceful Shutdown

平台允许正常退出时：Stop accepting new work → cancel → grace period → abort remaining → JoinSet reap → flush logs/metadata/journals → persist final status → release platform resources → Disposed。

### 15.2 Ungraceful Kill

正确性不能依赖 Graceful Shutdown。OOM、SIGKILL、Extension termination、设备掉电都可能在任意点中断内存状态机，因此关键状态使用轻量 Durable Marker / Journal 持久化。

### 15.3 Reconciliation on Boot

Runtime 在接受新工作前必须：打开 durable state → replay/validate journals → reconcile Session records → reconcile Workspace Heads → reconcile Compute Jobs → 释放或重建 orphan OS resources → 发布新的 Provider Presence。所有 cleanup 必须幂等。

## 16. Platform Runtime 与 Capability Model

Core 不假设一定存在 TUN、Mount、root helper、长期 daemon、任意端口监听、进程归属或全局 Route/DNS 修改能力。平台层统一提供 Packet Interface、Transparent Interception、Filesystem Projection、Secure Store、Local IPC、Background Runtime、Process Attribution 与 PrivilegedOperationProvider。背景模式至少支持 PersistentDaemon、ForegroundService、ExtensionHosted、OpportunisticBackground 与 AppBound。

平台差异由 PlatformCapabilities 表达，产品语义保持一致。跨平台目标是 Semantic Portability，而不是底层 API Uniformity。

## 17. Workspace 权威模型

Workspace 是标准持久化 Data Resource。权威层只包含：

```text
Workspace
├─ WorkspaceId
├─ Commit DAG
├─ Head Set
├─ Namespace / Manifest
├─ Object / Chunk CAS
└─ Replica Set
```

单标量 Generation 不作为唯一版本权威。每个 WorkspaceCommit 使用内容哈希作为 CommitId，包含 Parent CommitIds、RootManifestId、Author/NodeId、Logical Metadata 与可选 Merge Metadata。多端离线修改允许产生多个 Head，任何已成功本地提交的 Commit 都不得因为远端 Head 已变化而被丢弃。

## 18. Workspace Fork、Merge 与 Conflict

网络恢复后交换 Head Set 并判断 Same Head、Fast-forward 或 Diverged。Diverged 时从 Common Ancestor 执行 Three-way Merge 或显式 Resolution，生成新的 Merge Commit。可自动合并的典型情况包括不同路径独立修改、目录项无冲突增加与结构化元数据合并；无法自动合并时产生持久化 Conflict Object，包含 Base、Local、Remote 与 Resolution State。Conflict 是 Workspace 状态的一部分，不是临时 UI 状态。

## 19. Workspace Crash-Consistency

本地写入使用 Write-Ahead Journal：Begin Journal → Write Objects/Chunks → Create Commit Object → fsync durable metadata → atomic update Local Head Set → Mark Journal Committed。冷启动时根据 journal 与 commit/head 实际状态执行 finalize、replay head update 或只丢弃 incomplete staging，禁止因进程强杀导致已经成功落盘的用户数据静默丢失。

## 20. Workspace DAG Compaction、Shallow Sync 与 CAS GC

不可变 Commit DAG 与 CAS 必须具有受控生命周期，不能无限追加。Workspace 存储管理分为“权威版本保留”和“本地物理副本保留”两个层次；本地节点可以删除可从其他 Replica 重新获取的数据，但不能破坏全局 Durability Policy。

GC 使用 Reachability 分析。以下对象及其传递闭包属于 Protected Roots：

```text
Current Head Set
Explicitly Retained Snapshots / Commits
Unmerged Branch Heads
Conflict Objects and their Base/Local/Remote commits
Active Compute Snapshot Pins
Pending Workspace Write-back
Explicit Legal / User Holds
Replica Durability-required roots
Recent tombstones within retention window
```

不再从任何 Protected Root 可达的 Object/Chunk 成为 GC Candidate，但必须经过安全保留期后才能删除。默认保留期由 Policy 控制，移动端可以采用例如 14 天的短保留窗口，持久存储节点可以更长。GC 过程必须先生成候选集合与 Tombstone/Deletion Intent，再根据本地 Replica Policy、安全窗口和并发引用检查执行物理删除；任何 active pin、in-flight fetch、pending replication 或 recovery journal 都会阻止删除。

系统同时支持：

```text
Shallow Metadata Sync
  只同步最近 N 次 Commit / 指定 ancestry frontier

Sparse Replica
  只持有指定路径、Profile、WorkingSet 或显式 Pin 对应的数据

On-demand Deepening
  需要历史 ancestor 或缺失对象时再增量拉取

Pack / Metadata Compaction
  合并小对象索引、压缩历史元数据表示，但不改变 CommitId 语义

Storage Quota / Pressure Policy
  soft limit 触发后台 GC
  hard pressure 触发主动 cache eviction、shallowing 和预取暂停
```

Shallow Sync 只是本地 Replica 策略，不改变全局 DAG 的逻辑历史。删除本地 CAS 对象前必须确认它不是本节点承担的唯一 Durability Replica。

## 21. Workspace Intelligence：Graph、Profile、WorkingSet 与 Prefetch

Workspace Intelligence 可丢失并重建，包含 WorkspaceGraph、Profiles、AccessTrace、Cache State 与 Derived WorkingSet。WorkspaceGraph = Static Dependency Graph + Observed Access Graph；Profile 表示典型使用情境；WorkingSet Estimator 根据 Snapshot、Profile、Graph、Recent Trace、Task Context 与 Cache State 推断近期高概率数据；Prefetch Scheduler 只决定预取什么、何时预取、并发和资源预算，不选择 Provider 与 Path。

任何缺失 Object/Chunk 都转换为标准 Resource Delivery Request，再进入 Core Planner：

```text
Missing Object / Chunk
      ↓
Resource Delivery Request
      ↓
Core Planner
      ↓
Provider + Path
      ↓
Session
      ↓
Delivery Infrastructure
```

## 22. Workspace Cache 与 Projection

CacheManager 综合 Recency、Frequency、Size、Refetch Cost、WorkingSet Probability、Profile Membership、Dependency Importance、Graph Centrality、Active Session Pin 与 Compute Snapshot Pin。Dirty Journal、Unique Persistent Replica Data、Active Compute Snapshot、Pending Artifact、Unreplicated Commit、Conflict Resolution State 与 Explicit Pin 不得被普通 Cache 淘汰。

Workspace Projection 属于访问适配层，不属于权威模型。统一访问方式包括 Native Workspace API、File API、Object/Chunk API、Filesystem Projection、File-provider-style Projection 与 Materialized Directory。Linux FUSE、Windows/macOS Filesystem Adapter 与移动端 File/Document Provider 只把平台文件语义映射到 Workspace Runtime，不拥有 Replica Selection、Path Planning、Cache Policy 或 Commit 语义。

## 23. Compute 与 Workspace 协同

Compute 是标准 Resource。Compute Provider 向 Planner 提供 Capability Constraints、Execution Cost Estimate、Queue Delay、Workspace Data Locality、WorkingSet Coverage、Missing Bytes Estimate、Cache Hints 与 Platform Execution Capability。执行前 Workspace 固定为不可变 `WorkspaceId + CommitId + RootManifestId`。Write-back 生成新的 Workspace Commit，不修改原 Snapshot。Planner 优化的是任务整体完成时间与 Intent Utility，而不是孤立 CPU 或网络指标。

## 24. Application API 与 CLI

Application API 统一暴露 SystemService、NodeService、ResourceService、PlanningService、SessionService、NetworkService、ConnectivityService、DnsService、ServiceAccessService、WorkspaceService、ComputeService、PolicyService、PermissionService、PlatformService、ConfigService 与 DiagnosticsService。

正式 CLI：

```text
nexus
├── status
├── daemon
├── node
├── resource
├── use
├── plan
├── network
├── connectivity
├── dns
├── service
├── workspace
├── compute
├── session
├── policy
├── platform
├── diagnose
├── permission
└── config
```

Connectivity 与 DNS 是第一公民诊断入口；例如 `nexus connectivity status/candidates/probe/links` 和 `nexus dns status/resolve/providers/cache`。CLI、GUI、Agent Client 与 SDK 只通过 Application API 工作，不直接访问 SQLite、CAS、Planner 内部状态或平台特权 API。

## 25. Agent-Native Engineering Plane

Engineering Plane 将 Agent 视为上下文有限、概率性、会话可能中断的工程参与者。目标是把 Task 转换为受约束、可验证、可恢复的工程过程：

```text
Task
  ↓
Agent
  ↓
Engineering Harness
  ↓
Project Contract / Policies / Tests / Scenarios / Observability
  ↓
Evidence
  ↓
Verdict
```

核心原则为 Repository as API、Correctness by Construction、Machine-Readable First、Evidence Before Completion、Fast Feedback First、Context Locality、Determinism by Default 与 Harness Must Stay Thin。Harness 不拥有业务真相，不重新实现 Cargo/Git/Test/Tracing/Benchmark，也不进入 production crate 依赖图。

## 26. 统一仓库目录契约

跨 crate 的契约真相入口统一放在仓库根目录；`engineering/` 只放工程工具实现，禁止同时维护两套 policies/scenarios 路径：

```text
Nexus/
├── README.md
├── PRODUCT.md
├── ARCHITECTURE.md
├── DEVELOPMENT.md
├── Cargo.toml
├── Cargo.lock
├── harness.toml
│
├── policies/
│   ├── architecture.toml
│   ├── dependencies.toml
│   └── quality.toml
│
├── scenarios/
│   ├── product/
│   ├── regression/
│   └── platform/
│
├── .evidence/
├── crates/
│   └── <crate>/
│       ├── Cargo.toml
│       ├── MODULE.md
│       └── src/
│
├── tests/
├── benches/
├── fuzz/
└── engineering/
    ├── nexus-harness/
    ├── plugins/
    └── evidence-schema/
```

`harness.toml`、`policies/`、`scenarios/` 与 `.evidence/` 的位置是稳定 Project Contract，不允许在其他目录出现同名权威入口。

## 27. Project Contract 与 Module Contract

文档职责固定为：README 负责入口与导航；PRODUCT 描述外部可观察能力和失败语义；ARCHITECTURE 描述系统边界与依赖；DEVELOPMENT 描述开发与验证入口；每个核心 crate 的 MODULE.md 描述局部 Responsibility、Non-Responsibilities、Inputs、Outputs、Allowed/Forbidden Dependencies、Invariants、Side Effects、Public API、Verification、Performance Budget、Observability、Recovery Semantics 与 Platform Constraints。

文本契约不能替代机器门禁；关键边界必须同步存在于 Cargo 依赖、policies 与 CI 中。

## 28. Engineering Harness 与稳定命令

Harness 只负责 Project Discovery、Context Building、Affected Analysis、Command Execution、Policy Evaluation、Evidence Writing、Failure Explanation 与 Replay Coordination。稳定命令至少包括：

```text
nexus-harness status
nexus-harness context <target>
nexus-harness check
nexus-harness test affected
nexus-harness verify --fast
nexus-harness verify --full
nexus-harness explain
nexus-harness bench
nexus-harness replay
```

所有命令支持机器可读 `--json`，并维护版本化 JSON Schema（`schema_version`）。Agent 不应解析 ANSI、自由文本长日志或不稳定表格。

## 29. Context Locality 与 Affected Analysis

Agent 标准工程循环固定为 Task → status → context → read minimal contracts/API/tests → modify → check → test affected → fix → verify → Evidence。Context Builder 聚合模块职责、依赖边界、相关文件、核心 invariants、tests/scenarios、最近失败 Evidence、Git diff 与可写/只读/protected paths，默认不读整个仓库。

Affected Analysis 使用 changed files → owning modules/crates → reverse dependency graph → mapped tests/scenarios → affected verification set。优先复用 Cargo metadata 与显式 mapping，不在核心路径中构造脆弱的全程序猜测式静态分析。

## 30. Verification、Evidence 与 Verdict

真正的完成路径固定为：Product Requirement → Observable Behavior → Verification → Evidence → Verdict。统一 Verdict 为 PASS、FAIL、STALE、UNKNOWN、BLOCKED。Agent 只能提交 Candidate Completion，最终 PASS 必须由 Harness Verification 基于独立 Evidence 产生。

Evidence 持久化在 `.evidence/verify-<id>/`，至少绑定 source revision、working tree digest/dirty state、configuration digest、feature set、target platform/target triple、toolchain version、harness schema version 与 platform capability digest；任一影响结论的输入变化都会让旧 Evidence 自动变为 STALE。

Evidence 强度分级：E0 Assertion/Existence、E1 Static Check、E2 Unit/Local Behavior、E3 Integration、E4 Product Scenario、E5 Independent External Observation。关键用户可见 Capability 原则上至少需要一条 E4 或更高等级 Evidence。

## 31. Feature 的 Contract-First / Spec-Freeze 协议

不可自证原则通过“两阶段契约先行”解决，而不是简单要求不同的人或不同 Agent 身份。对于全新 Feature，必须先冻结验证契约，再进入实现阶段。

### 31.1 Contract Phase

在业务实现之前产生独立的 Contract Revision，至少包含 PRODUCT/MODULE 契约增量、Scenario 定义、可观察输出与失败条件。Harness 必须在“实现尚未存在”的基线上运行该 Scenario，并记录预期的 `FAIL` 或 `BLOCKED` 作为 **Red Evidence**。Contract Revision 的 Scenario 内容、关键 expectation、schema 与 requirement mapping 被计算哈希并写入 `contract.lock` 或 Evidence metadata。

要求：

```text
Scenario 必须在实现前存在
Scenario 必须在旧实现上失败或明确 blocked
Scenario 的断言来自冻结后的 Product Contract
Contract Revision 与 Implementation Revision 必须可区分
```

### 31.2 Implementation Phase

进入实现阶段后，已冻结的 PRODUCT expectation、MODULE invariant 和 Scenario expectation 自动提升为 Protected Paths / Protected Fragments。实现 Agent 可以修改业务代码、非受保护的辅助测试和内部实现，但不能修改被冻结的 Scenario 预期值来使测试通过。

如果实现阶段确实发现 Contract 有误，必须显式进入 `requirement-change` 流程：关闭当前 Implementation Phase → 修改 Contract → 重新获得 Red Evidence → 生成新的 Contract Hash → 使此前实现 Evidence 失效 → 再重新进入 Implementation Phase。

### 31.3 单 Agent 条件下的独立性

“独立”定义为 **验证标准在实现之前冻结、验证执行器与实现代码路径分离、Evidence 可重放**，而不是强制必须由两个不同模型身份完成。因此在无人类介入时，同一个 Agent 可以先执行 Contract Author 角色，再执行 Implementation Worker 角色，但 Harness 必须：

```text
在 Contract Phase 后清晰冻结 acceptance artifacts
Implementation Phase 禁止写 protected expectations
最终 Scenario 由独立 runner/verifier 执行
最终 Verdict 由 Harness 生成而非 Agent 文本声明
```

对于高风险 Capability，可以进一步要求 Contract Author 与 Implementation Worker 使用独立 Agent Session、不同模型上下文或第二 Verifier，但这属于增强等级，不是最低正确性前提。

## 32. Protected Paths 与任务类型

Harness 支持 Writable Paths、Readable Paths 与 Protected Paths。任务类型至少包括 feature、bugfix、refactor、test、docs、performance、dependency 与 requirement-change。典型策略：refactor 不允许改产品 Scenario expectation；bugfix 应增加 Regression Evidence；performance 必须执行 Performance Budget Gate；只有 requirement-change 可以合法修改冻结的 Product/Scenario expectation。越界修改必须产生显式 FAIL，不允许静默降级。

## 33. Observability、Replay 与 Performance Contract

Event/Log、Trace/Span、Metric 构成 Evidence 基础设施。稳定关联字段至少包括 request_id、session_id、node_id、provider_id、connection_id、path_id、task_id、workspace_id、commit_id，结构化字段视为 API。Hot Path 默认禁止 per-packet/per-frame 高级别日志，高频观测优先使用 counter、histogram、sampling 与 aggregation。

Planner、Connectivity、Session State Machine 与 Workspace Recovery 必须逐步支持 record → replay，使偶发运行错误转化为 deterministic input。性能要求必须进入 Product/Module Contract 与 Evidence，定义 baseline、noise tolerance、warning threshold 与 blocking threshold。

## 34. Rust 工程基线

根 workspace 统一管理 edition、MSRV、dependency 与 release profile。Release 默认采用明确的 LTO/strip 策略；成员 crate 继承 workspace 配置。Feature 只表达真实能力边界，default feature set 尽量最小，第三方依赖优先 `default-features = false`。公共 API 默认遵循 private → pub(crate) → pub；核心领域错误使用类型化 error；库代码不得用 panic 表达正常业务失败；unsafe 必须集中到最小模块、写明 Safety Invariant，并建立专项 test/fuzz。

依赖供应链使用 advisory/license/source policy，推荐 `cargo deny`。新增依赖必须回答所属架构层、是否污染 Portable Core、是否引入 OS-specific transitive dependency、是否影响 WASI portability 与是否存在更小替代。

## 35. CI 与架构门禁

CI 和 Local Harness 必须调用同一组 Gate 定义：

```text
fmt
static architecture checks
clippy -D warnings
default tests
no-default-features
each-feature
supported feature matrix
all-features where valid
WASI portable-core checks
platform-specific checks
integration/scenario/regression
selected fuzz / concurrency
performance budgets
```

CI 同时承担 Compilation Test、Behavior Test、Dependency Boundary Test、Architecture Test 与 Portability Test。`nexus-domain`、`nexus-policy`、`nexus-planner`、`nexus-ingress`、Workspace core 等 portable crate 必须通过 WASI 或等价非桌面宿主检查。常用工具优先复用 cargo fmt/check/clippy/nextest/llvm-cov/deny/hack/fuzz、proptest、loom 与 tracing，Harness 不重写这些工具。

## 36. Rust 工程目录

生产与工程验证平面目录严格分离：

```text
apps/
  nexus/
  nexusd/
  nexus-platform-host/

crates/
  nexus-domain/
  nexus-control-api/
  nexus-registry/
  nexus-discovery/
  nexus-connectivity/
  nexus-ingress/
  nexus-dns/
  nexus-policy/
  nexus-auth/
  nexus-planner/
  nexus-session/
  nexus-measurement/
  nexus-delivery/
  nexus-transport/
  nexus-network/
  nexus-service/
  nexus-workspace/
  nexus-compute/
  nexus-storage/
  nexus-platform/
  nexus-platform-linux/
  nexus-platform-windows/
  nexus-platform-macos/
  nexus-platform-android/
  nexus-platform-ios/
  nexus-diagnostics/
  nexus-proto/

engineering/
  nexus-harness/
  plugins/
  evidence-schema/
```

根目录的 `policies/`、`scenarios/`、`.evidence/` 与 `harness.toml` 不属于 `engineering/` 子目录；它们是仓库级 Project Contract 和运行产生的 Evidence 入口。Production apps/crates 不得依赖 `engineering/`。

## 37. Diagnostics 与可观察性

Diagnostics 必须覆盖 Runtime Host、Identity、Registry、Discovery、Connectivity Evaluation/Establishment、Transport、Virtual Packet Interface、Portable Ingress、Platform Interception、DNS、Policy、Planner、Session Lifecycle/Outcome、Crash Recovery、Platform Capability、Workspace Commit DAG/Head Set/Conflicts/GC、WorkspaceGraph/Profile/WorkingSet/Prefetch、Filesystem Projection、Compute Job、Privileged Runtime 与 Engineering Evidence Freshness。默认低成本，`--deep` 才执行主动 Probe、完整性扫描或高成本验证。

## 38. 验收原则

Capability 完成必须同时满足 Product Complete 与 Engineering Complete：外部可观察行为满足 Product Contract，且当前 revision 拥有 fresh、足够强、独立可重放的 Evidence。不能仅以“代码存在”“cargo test 通过”“Agent 说完成”“README 标记完成”或 Coverage 数字高来宣告完成。

最低要求包括：可被用户或 Agent 发现、可调用、运行状态可观察、失败原因可解释、可正确取消、TerminalOutcome 唯一、Crash 后可恢复或明确失败、目标平台可验证；架构级能力还必须证明 Portable Core 未污染、Deletion Test 通过、Feature 组合可构建、WASI 检查通过、`-D warnings` 通过、Crash Recovery 测试通过、Workspace Fork/Merge/GC 测试通过。

## 39. 实现阶段

### 39.1 Cross-Cutting：Agent-Native Engineering Baseline

优先建立 Project Contract、MODULE.md、harness.toml、policies、scenarios、status/context/check/test/verify/explain、revision-bound Evidence Store 与 Affected Analysis。Harness 初期坚持 Local / Single-Agent First，不提前引入远端调度、多 Agent 共识或第二套 Build System。

### 39.2 Phase 1：Portable Core + Network + Crash-Consistent Runtime

完成 Portable Core、Platform Capability Traits、Composition Root、Registry/Discovery、Core Planner、Session 双轨状态、Structured Concurrency、Crash Recovery、Virtual Packet Interface、Portable Ingress、Platform Interception、Connectivity Evaluation/Establishment、Transport、Policy、DNS、InternetAccess、Connectivity/DNS CLI 与 CI Architecture Gates。

### 39.3 Phase 2：Distributed Workspace

完成 Workspace Commit DAG、Head Set、Offline Commit、Fork Detection、Three-way Merge、Conflict Object、Write-Ahead Journal、Crash Recovery、Reachability GC、Shallow/Sparse Replica、Storage Quota、WorkspaceGraph、Profile、WorkingSet Estimator、Prefetch Scheduler、Materialization 与 Filesystem Projection。

### 39.4 Phase 3：Compute + Agent Loop

完成 Immutable Workspace Commit Pin、Compute Estimates、Core Planning、Remote Executor、Structured Job Runtime、Streaming Logs、Execution Cache、Artifact、Optional Workspace Commit 与 Agent-facing structured API。

## 40. 最终设计结论

Nexus 的稳定核心由 Resource、Provider、Intent、Constraint、Plan、Session 与 Measurement 构成；全系统只有一个 Core Planner；Connectivity 与 Transport 是所有远端业务域共享的 Delivery Infrastructure；Platform Runtime 把统一语义映射到底层 OS 能力；Workspace 使用不可变 Commit DAG + Head Set 支持离线分叉、合并、Crash Recovery、Shallow/Sparse Replica 与安全 CAS GC；Ingress 是系统级 Driver，通过 SessionManager 提交 FlowContext，而不是 `nexus-network` 的私有子件。

Agent-Native Engineering Plane 与生产 Runtime 正交。仓库根目录是稳定 Project Contract：`harness.toml`、`policies/`、`scenarios/` 与 `.evidence/` 的位置唯一；`engineering/` 只存放 Harness/Plugin/Schema 工具实现。新 Feature 使用 Contract-First / Spec-Freeze 两阶段流程，先形成在旧实现上失败的 Red Evidence 并冻结 Scenario，再进入 Implementation Phase；最终 PASS 只能由独立 Runner/Harness 基于 fresh Evidence 产生，从而解决“Agent 既写实现又写 Scenario”的不可自证死锁。

整个系统最终统一为：

```text
Portable Core
    ↓
Resource + Intent
    ↓
Resolve Candidate Providers
    ↓
Core Planner
    ↓
Create Session
    ↓
Connectivity Establishment
    ↓
Delivery / Domain Execution
    ↓
Platform Capability
    ↓
Observe + Adapt
    ↓
Persist / Recover

Engineering Plane:
Task
    ↓
Frozen Contract
    ↓
Minimal Context
    ↓
Implementation
    ↓
Affected Verification
    ↓
Independent Scenario Verification
    ↓
Revision-bound Evidence
    ↓
Verdict
```

本规范作为 Nexus 产品运行时、跨平台网络入口、内网穿透、规则代理、分布式 Workspace、Filesystem Projection、Compute 调度、Agent-Native 工程系统、Verification/Evidence、Crash Recovery、存储治理与 Rust 工程质量的统一最终设计基线。
