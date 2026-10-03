# Nexus Architecture Contract

## 1. 核心领域

稳定核心：

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

核心边界：

```text
Resource != Provider
Provider != Node
Identity != Locator
Plan != Session
Measurement != Score
Policy != Path
Connectivity Evaluation != Connectivity Establishment
Connectivity != Transport
Portable Ingress != Platform Interception
Virtual Packet Interface != TUN
Workspace != Filesystem
WorkspaceGraph != CAS
Planner != Estimator
Planner != Scheduler
TerminalOutcome != LifecyclePhase
Portable Core != Platform Runtime
```

## 2. 运行时调用流

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

Ingress 是系统级 Driver。`nexus-ingress` 只生成中立 FlowContext，并提交给 SessionManager/Application Layer；它不直接调用 Planner，也不是 `nexus-network` 的私有子件。

### 2.1 TUN Ingress 接入 {#tun-ingress}

（2026-10-02 requirement-change 冻结；场景 `product.flow-session-mapping`）

nexusd 的 TUN 数据面经 `nexus-flow-session`（Application 层新 crate）接入上链：

```text
TUN packet
  ==> FlowTable (5-tuple key; DNS 短路/QoS 仍在逐包快路径)
  ==> 新流首包：FlowContext(origin=PacketCapture) → Policy → Core Planner
  ==> SessionManager (Owner) 创建 Session → 后台线程异步 Establish Connectivity
  ==> 会话 Active 后：流表项绑定 session，快路径转发（不再调 Planner）
```

- `nexus-flow-session` 依赖方向：`{nexus-domain, nexus-policy, nexus-planner, nexus-session, nexus-network}`；`nexus-network` 不得反向依赖它（ARCHITECTURE §3 禁止边）。
- `process_one()` 永不阻塞：Policy/Planner 是同步纯函数可在包线程调，建连异步经 channel 回填流表项 `Allocating→Active`。
- smoltcp 本地 TCP 会话（传输终结）与 §10 资源 Session（资源使用上下文）是两层"会话"，MODULE 必须写清映射关系。

## 3. 编译依赖

`A --> B` 表示 A 在编译期依赖 B。

```text
nexus-registry      --> nexus-domain
nexus-policy        --> nexus-domain
nexus-auth          --> nexus-domain
nexus-measurement   --> nexus-domain
nexus-session       --> nexus-domain
nexus-storage       --> nexus-domain
nexus-diagnostics   --> nexus-domain

nexus-discovery     --> nexus-domain / nexus-registry / nexus-platform

nexus-planner       --> nexus-domain / nexus-registry / nexus-measurement

nexus-delivery      --> nexus-domain
nexus-connectivity  --> nexus-delivery / nexus-platform
nexus-transport     --> nexus-delivery / nexus-platform

nexus-ingress       --> nexus-domain
nexus-dns           --> nexus-domain

nexus-network       --> nexus-domain / nexus-policy / nexus-planner
                     / nexus-session / nexus-delivery / nexus-dns

nexus-service       --> nexus-domain / nexus-session / nexus-delivery
nexus-workspace     --> nexus-domain / nexus-session / nexus-delivery / nexus-storage
nexus-compute       --> nexus-domain / nexus-session / nexus-delivery / nexus-workspace

nexus-control-api   --> nexus-domain / nexus-proto
nexus-platform-<os> --> nexus-platform
```

禁止：

```text
nexus-network     -X-> nexus-ingress
nexus-domain      -X-> nexus-platform-*
nexus-delivery    -X-> nexus-workspace / nexus-compute
production crates -X-> engineering harness
platform adapters -X-> higher-level domain runtimes
```

## 4. Portable Core

Portable Core 不直接调用 OS Framework。Clock、Random、SecureStore、VirtualPacketInterface、TransparentIngress、FilesystemProjection、Lifecycle、Attribution 等由 `nexus-platform` trait 表达，由 `nexus-platform-*` 实现。

每个新 abstraction 必须通过 Deletion Test：

> 删除该抽象并直接依赖当前实现，会破坏哪个已经存在的独立变化维度？

“未来也许会有第二个实现”本身不是新增 trait 的充分理由。

## 5. Planner 与 Plan

全系统只有一个 Core Planner，负责：

```text
Provider
Placement
Path
ExecutionStrategy
```

领域特有信息进入类型化、版本化的 DomainExtension：

```text
NetworkPlanExtension
WorkspacePlanExtension
ComputePlanExtension
ServicePlanExtension
```

Planner 生成 DecisionTrace，记录候选、拒绝原因、Measurement、Connectivity Feasibility、评分与最终选择。

## 6. Connectivity / Delivery

规划前只做 Connectivity Evaluation；Plan + Session 创建后才做 Establishment。

Delivery Infrastructure 被 Network/Service/Workspace/Compute 共享：

```text
Connectivity
Transport
Delivery Session Binding
```

## 7. Session 与结构化并发

所有异步任务必须有 Owner、Cancellation、Join/Reap 与终态归属。

```text
CancellationToken = 请求停止
AbortOnDropHandle = 所有权失效保护
JoinSet + Reaper   = 确认退出并消费结果
```

Worker 只能发送事件。Owner State Machine 是 TerminalOutcome 唯一写入者。

## 8. Workspace

Workspace 权威版本使用不可变 Commit DAG + Head Set。

```text
Base Commit + ChangeSet
        ↓
Immutable Commit
        ↓
Local Head Set

Divergence:
Common Ancestor + Local + Remote
        ↓
Three-way Merge / Explicit Resolution
        ↓
Merge Commit
```

CAS GC 只删除不再从 protected roots 可达并且超过安全保留期的对象。移动/受限节点默认允许 Shallow Sync 与 Sparse Replica。

## 9. Crash Consistency

Graceful Shutdown 不是正确性的前提。

关键状态使用最小 durable journal/marker。冷启动必须先 Reconciliation：

```text
replay journals
reconcile session records
reconcile workspace heads
reconcile jobs/artifacts
release/recreate orphan OS resources
publish fresh presence
accept new work
```

## 10. Agent-Native Engineering Plane

工程平面与 production runtime 正交：

```text
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

Harness 不拥有业务真相、不重写 Cargo/Git/Test/Tracing/Benchmark，也不被 production crate 依赖。

## 11. 代理内核产品线（Rule-Based Routing Proxy）

代理内核是独立于 PRODUCT §6 远程资源访问闭环（Remote Resource Access）的第二条产品线，其驱动链与既有
Ingress -> Application Service -> Policy -> Core Planner -> Session Runtime ->
Network Runtime 平行但不合并：

```text
SOCKS5 Ingress（nexus-ingress Socks5Handshake）
  -> FlowContext
  -> nexus-proxy RuleEngine（静态规则表顺序匹配）
  -> rule_action 动作链（首动作 SELECT_OUTBOUND tag）
  -> nexus-proxy GroupRegistry（selector / urltest）
  -> nexus-connectivity LinkActivator（Direct / Relay）
```

衔接约束：

- `nexus-proxy` 复用 `nexus-ingress` 的 `FlowContext` 与 `Socks5Handshake`，
  但不修改 ingress 的协议状态机语义。
- 规则引擎是领域局部组件，**不是**系统级 Core Planner；它不产生第二套系统级
  Plan，也不修改 `NetworkPlanExtension`。规则动作链属于 `nexus-proxy` 内部的
  typed extension，不污染领域中立的 `Plan` 模型。
- 出站激活委派 `nexus-connectivity::LinkActivator`（Direct -> Relay 回退），
  与远程资源访问闭环共享同一 Delivery Infrastructure。
- `nexus-proxy-config` 是 Nexus 首个配置文件入口（YAML -> typed structs），
  位于 portable-core 层，不依赖运行时 crate。
- Portable Core 不引入平台 API：SOCKS5 监听 socket、LinkProbe 的真实 I/O 由
  Composition Root / `nexus-platform-*` 注入。
- `nexus-proxy` 不反向依赖 `nexus-network` / `nexus-service` / `nexus-workspace`
  / `nexus-compute`；代理内核产品线与远程资源访问闭环共享底座但不互相调用业务逻辑。

## 12. N3 Task / Snapshot / Artifact（契约阶段）

N3 是 Compute/Workspace 的类型化领域扩展；`Task != Session != Connection`。
稳定核心 Plan 固定字段不增加 Task、Sandbox 或 Artifact 信息；使用版本化
ComputePlanExtension/WorkspacePlanExtension，不产生第二个系统级 Planner。

- `nexus-domain`：N3 标识符及跨模块版本化 DTO、纯状态词汇；零 I/O。
- `nexus-compute`：TaskOwner、接受/幂等语义、执行结局与交付、Artifact 登记；
  提供方是权威，请求方是经事件序号恢复的只读镜像。
- `nexus-workspace`：固定输入、清单、SHA-256 校验、Snapshot protected roots。
- `nexus-storage`：注入的 durable record/journal 与版本化 SHA-256 内容命名空间；
  不解释 TaskOutcome，不迁移既有 FNV CAS。
- `nexus-session`：保持现有 SessionManager 唯一 Session Owner；不拥有 Task，
  不把 Session 的孤儿 Failed 传播为尚未核实的 Task 失败。
- `nexus-control-api`：Submit/Get/ReadLogs/Cancel/ListArtifacts/GetArtifact 的
  Application Service DTO；不依赖 compute/workspace/storage 实现。
- `nexusd`：装配唯一 SessionManager 和提供方 TaskOwner，注入存储、认证传输、
  Linux 执行适配器、日志 drain、取消/Join/Reap；执行平台能力在平台层或组合根实现。
- `nexus`：CLI 参数/渲染，任务操作访问 daemon，不另持 TaskOwner。

本阶段仅冻结上述归属，不新增 crate、Cargo/Policy 依赖边或预先新增 trait。
Compute 不直接依赖 storage/platform/network；持久记录、进程执行、认证通道通过
组合根注入，未来新增 abstraction 必须通过 Deletion Test。
提供方 durable StartIntent/执行句柄用于核实崩溃窗口，未知时不自动再 spawn。
TaskOutcome 与 Session TerminalOutcome 分别恰一次提交，不要求两侧共识。
细节与冻结范围见 `docs/N3-MODEL-CONTRACT.md`；产品入口见 PRODUCT §17。
