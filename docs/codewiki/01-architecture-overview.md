# 01 · 项目整体架构（Architecture Overview）

> 依据：[ARCHITECTURE.md](../../ARCHITECTURE.md)（架构契约，权威）、
> [PRODUCT.md](../../PRODUCT.md)（产品契约）、[README.md](../../README.md)、
> [docs/PROJECT-STATUS.md](../PROJECT-STATUS.md)、[Nexus_Unified_System_Design_Specification_v9.md](../../Nexus_Unified_System_Design_Specification_v9.md)（设计基线）。

## 1. Nexus 是什么

Nexus 是一个**统一的个人动态资源运行时（Resource Fabric）**，外加与之配套的
**Agent-Native Engineering System**（工程平面）。它把网络访问、Service、Workspace、
Compute 与设备能力统一建模为 `Resource`，完成资源使用的主链路是：

```text
Resource + Intent
        ↓
Resolve Candidate Providers
        ↓
Core Planner（全系统唯一）
        ↓
Create Session
        ↓
Establish Connectivity      ← Plan before Connectivity
        ↓
Execute
        ↓
Observe + Adapt
        ↓
Persist / Recover
```

仓库同时把"如何可靠地开发 Nexus"作为正式工程契约：Agent、Human、CI 共享同一套
Repository Contract、Harness、Policy、Scenario 与 Evidence（见 [05](05-running-and-development.md)）。

## 2. 核心领域与边界（ARCHITECTURE §1）

稳定核心词汇：`Resource / Provider / Node / Intent / Constraint / Plan / Session / Measurement`。

核心边界（不可在非架构变更任务中破坏）：

```text
Resource != Provider              Provider != Node
Identity != Locator               Plan != Session
Measurement != Score              Policy != Path
Connectivity Evaluation != Connectivity Establishment
Connectivity != Transport         Portable Ingress != Platform Interception
Virtual Packet Interface != TUN   Workspace != Filesystem
WorkspaceGraph != CAS             Planner != Estimator
Planner != Scheduler              TerminalOutcome != LifecyclePhase
Portable Core != Platform Runtime
```

Session 双轨语义是贯穿全系统的不变量：`LifecyclePhase`（Allocating→Active→Draining→Disposed，
资源释放状态）与 `TerminalOutcome`（Unfinished/Completed/Failed/Cancelled，业务结果）分离；
**终态恰好一次提交**，由 Owner 状态机唯一写入。

## 3. 运行时调用流（ARCHITECTURE §2）

```text
Ingress / User Request
  ==> Application Service / SessionManager
  ==> Policy + Core Planner
  ==> Session Runtime
  ==> Domain Runtime
  ==> Delivery Infrastructure（Connectivity / Transport，共享底座）
  ==> Platform Capability（nexus-platform trait）
  ==> OS / Framework
```

`nexus-ingress` 是系统级 Driver：只生成中立 `FlowContext` 提交给 SessionManager，
**不直接调用 Planner**，也不是 `nexus-network` 的私有子件。

### 3.1 TUN Ingress 接入（§2.1，2026-10-02 冻结）

nexusd 的 TUN 数据面经 `nexus-flow-session` 接入上链：

```text
TUN packet
  ==> FlowTable（5 元组；DNS 短路/QoS 仍在逐包快路径）
  ==> 新流首包：FlowContext(origin=PacketCapture) → Policy → Core Planner
  ==> SessionManager 创建 Session → 后台线程异步 Establish Connectivity
  ==> 会话 Active 后：流表项绑定 session，快路径转发（不再调 Planner）
```

`process_one()` 永不阻塞；建连异步经 channel 回填流表项 `Allocating→Active`。

### 3.2 代理内核产品线（§11，Rule-Based Routing Proxy）

与远程资源访问闭环**平行但不合并**的第二条产品线：

```text
SOCKS5 Ingress（nexus-ingress Socks5Handshake）
  → FlowContext
  → nexus-proxy RuleEngine（静态规则表顺序匹配）
  → rule_action 动作链（首动作 SELECT_OUTBOUND tag）
  → nexus-proxy GroupRegistry（selector / urltest / load_balance / relay）
  → nexus-connectivity LinkActivator（Direct → Relay 回退）
```

规则引擎是领域局部组件，**不产生第二套系统级 Plan**；出站激活共享同一 Delivery
Infrastructure；`nexus-proxy` 不反向依赖 network/service/workspace/compute。

## 4. 分层架构（自底向上）

```text
┌─ 领域核心（零 I/O、纯类型、Portable Core）────────────────────┐
│ nexus-domain（根基层）registry · policy · auth · storage ·    │
│ measurement · scheduler · plugin（零依赖叶子）                 │
└──────────────────────────────────────────────────────────────┘
┌─ 会话与规划 ─────────────────────────────────────────────────┐
│ nexus-session（TerminalOutcome 唯一 Owner）· nexus-planner    │
│ （唯一 Core Planner）· nexus-flow-session（流→会话映射）       │
│ nexus-service · nexus-diagnostics · nexus-control-api         │
└──────────────────────────────────────────────────────────────┘
┌─ 投递底座（共享，不反向依赖业务域）──────────────────────────┐
│ nexus-delivery · nexus-connectivity（2.3 万行，建连/打洞/     │
│ 中继/QoS/虚拟子网数据面）· nexus-transport · nexus-fabric     │
│ （QUIC-like 会话层）· nexus-path（四级回退选路）· nexus-turn   │
└──────────────────────────────────────────────────────────────┘
┌─ 代理栈与数据面 ─────────────────────────────────────────────┐
│ nexus-ingress（SOCKS5/HTTP 状态机 + TUN 解码）· nexus-proxy   │
│ nexus-proxy-config（YAML→typed）· nexus-proxy-transport       │
│ nexus-network（N1 装配）· nexus-dns · nexus-projection        │
│ （L3 隧道/统一路由，1.25 万行）· nexus-compute · outbound-*   │
└──────────────────────────────────────────────────────────────┘
┌─ 平台适配（Portable Core 不碰的平台 API 全在这）─────────────┐
│ nexus-platform（capability traits）→ platform-{linux,windows, │
│ macos,android,ios}（后三者为 7 行骨架）                        │
└──────────────────────────────────────────────────────────────┘
┌─ 组装层（Composition Root，唯一允许纵切装配）────────────────┐
│ apps/nexus（CLI 瘦客户端 + SDK 组合根）· apps/nexusd（daemon）│
│ apps/nexus-platform-host（平台宿主）                          │
└──────────────────────────────────────────────────────────────┘
┌─ 工程平面（与 production 正交）──────────────────────────────┐
│ engineering/nexus-harness + evidence-schema · policies/ ·     │
│ scenarios/（314 条 E4）· .githooks/ · .agents/skills/         │
└──────────────────────────────────────────────────────────────┘
```

依赖方向只能自底向上（完整编译依赖图与禁止边见 [04](04-dependencies.md)）。

## 5. 产品线全景（PRODUCT.md 17 节）

| 产品线 | PRODUCT 节 | 核心能力 | 主要实现 |
|---|---|---|---|
| N1 Universal Connectivity | §2 | QUIC-like 会话层、路径四级回退、NAT 穿透、VPI 单播互通 | fabric / path / nat-* / turn / network |
| N2 Universal Resource Access | §16 | 发现→规划→授权→访问→撤销闭环 `nexus use` | registry / discovery / auth / planner / session |
| N3 Distributed Workspace | §17 | Task / Snapshot / Artifact（模型与契约阶段） | compute / workspace / control-api |
| Service / Workspace / Compute | §3–§5 | 三类领域资源语义 | service / workspace / compute |
| 代理内核（Rule-Based Routing） | §11 | SOCKS5 真实数据面、规则分流、策略组、测速 | proxy / proxy-config / outbound-* |
| 虚拟子网组网 | §12 | VIP 分配、加密数据面、打洞、跨子网出口 | connectivity::virtual_subnet / subnet_cli |
| 系统代理与自启 | §13 | system-proxy / autostart | platform-windows / platform-linux |
| 计划任务 | §14 | `schedule at|every` 时间表触发 | scheduler / schedule_cli |
| 持久化与恢复 | §15 | journal / marker / 冷启动 reconcile | storage / session::reconcile / workspace::gc |
| Web Gateway | —（独立手册） | 零安装浏览器网页 SSH 终端（WebRTC） | nexus-web-gateway |

成熟度光谱（据 [docs/product/](../product/) 实证与各 MODULE.md）：N1 已 Final PASS
（PROJECT-STATUS，2026-10-04 真机 22 gate 全绿）；N2 主链路可用；N3 处于"模型与契约"
阶段（task submit 的完整执行接线尚未装配，CLI 诚实标注）。

## 6. 关键架构机制速览

- **单一 Core Planner**：`nexus-planner::plan_from_snapshot` 是唯一系统级规划入口；
  领域数据只进类型化版本化 `PlanExtension::{Network,Workspace,Compute,Service}`。
  代理规则引擎、Estimator、Scheduler 都是领域局部组件，不得产生第二套系统级 Plan。
- **Plan before Connectivity**：规划期只做低成本 `ConnectivityEvaluation`（可行性门控）；
  建连（Establishment）在 Plan + Session 创建之后触发。
- **Exactly-One Terminal Outcome**：`SessionOwner::commit_outcome` 唯一写入口 +
  `SessionManager` 唯一 Owner + `reconcile_session_records` 冷启动恰一次补提交。
  Worker 只发 `SessionEvent`；断开 ≠ Failed（attach window 300s 内可重连）。
- **结构化并发**：全仓库 **tokio-free**（std thread + sans-IO）。`CancelToken` /
  `AbortOnDropHandle`（nexus-session）+ `JoinHandle` + Drop Reaper（flow-session）+
  `HealthMonitor`（connectivity）；禁止 fire-and-forget（policies/quality.toml）。
- **Crash Consistency**：durable journal/marker（`FileKvStore::journal_*`、
  `SessionRecord`、`LinkMarker`、`AcceptanceLedger`/`RuntimeJournal`）；
  冷启动先 reconcile 再接受新工作，全部幂等。
- **Workspace 不变量**：权威版本 = 不可变 Commit DAG + Head Set（CommitId 是内容哈希，
  全节点确定性一致）；离线分叉不丢本地提交，冲突落持久 `ConflictObject`；
  GC 只删"protected roots 不可达 + 超安全保留期"对象（Cache Eviction ≠ CAS GC）。
- **Portable Core**：平台能力经 `nexus-platform` trait 注入，由 Composition Root 装配；
  portable crate 过 WASI gate（`harness.toml [portable_core]`，12 个 crate）。
- **诚实语义**：无测量标 `unknown` 不编 0；能力缺失显式 `Unsupported`/`Unavailable`；
  未实现显式 UNKNOWN（如 harness `replay` 命令）；N2 拒绝 N3 语义而非静默降级。

## 7. 仓库结构

```text
Nexus/
├── PRODUCT.md ARCHITECTURE.md DEVELOPMENT.md AGENTS.md   契约层
├── harness.toml policies/ scenarios/ FILE_MANIFEST.md    机器约束层
├── crates/          48 个 crate（5 层架构实现）
├── apps/            nexus（CLI+组合根）· nexusd（daemon）· nexus-platform-host
├── engineering/     nexus-harness · evidence-schema · e2e · verifiers
├── tests/ benches/ fuzz/ examples/ scripts/ configs/     辅助层
├── vendor/quinn-proto/   QUIC 补丁（quinn#2658 漫游修复）
├── docs/            设计/契约/审计/product 实证/USER_MANUAL
└── .githooks/ .agents/    机器门禁与 Agent Skills / 知识库
```

规模基线（commit `585e910`）：workspace 成员 52 个（48 crate + 3 app + harness）；
`*.rs` 源文件 590 个、约 25.1 万行。最重的实现：`apps/nexusd`（src 68 文件 ~3.9 万行）、
`apps/nexus`（src 43 文件 ~3.7 万行）、`nexus-projection`（14 文件 1.25 万行）、
`nexus-connectivity`（35 文件 2.3 万行）。

## 8. Agent-Native 工程闭环（ARCHITECTURE §10）

```text
Task → Frozen Contract → Minimal Context → Implementation
  → Affected Verification → Independent Scenario Verification
  → Revision-bound Evidence → Verdict（仅 Harness 可产生）
```

Contract-First / Spec-Freeze：新 Feature 先改契约 + scenarios 并取得 Red Evidence，
冻结 expectation 后才进实现；实现不得静默修改期望。细节见
[05-running-and-development.md](05-running-and-development.md)。
