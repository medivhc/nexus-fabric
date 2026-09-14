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
