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

- Discovery 解析提供方 Peer 的 Endpoint；P0 支持静态发现表与动态 Presence 注册（`PresenceRegistry`：announce/resolve + TTL 过期语义）两种模式；发现协议的网络传输后置。
- 认证门控在业务帧转发前完成：未通过认证的请求在帧流建立后、业务帧前被拒绝，返回 `AUTHORIZATION_DENIED`。
- Transport 提供长度前缀帧协议；P0 冻结为 TCP + u32 大端长度前缀帧。
- 建连失败按逆序幂等回滚（Connectivity -> Session -> Plan 释放），Session 物理排空到 Disposed，TerminalOutcome 由 Owner 唯一提交 `Failed`。
- Connectivity 链路激活按候选顺序执行（v9 §243 P0 子集）：Direct 探测成功即建立直连；Direct 不可达（NAT 场景）时回退 Relay 候选；全部候选不可达返回结构化 `NO_LINK_AVAILABLE`，不替换业务 Provider（由 Core Planner 生成替代 Plan）。P0 的 Relay 为进程内中继转发，中继协议（DERP/自定义）后置。
- Service、InternetAccess、Compute 与 Workspace 是远程访问的首批资源类型；Workspace 远程语义为远程提交（Node A 经闭环向 Node B 的 Workspace 应用 ChangeSet 并取回新 Head）。
- 远程闭环同时以两种形态交付：SDK 组合根函数（apps/nexus）与 daemon 单次执行入口（apps/nexusd `run <resource> --json`）；daemon 对未知资源返回结构化拒绝（`UNKNOWN_RESOURCE`，exit 0 = 请求已被处理）。

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
