# 01 · 项目整体架构（Architecture Overview）

> 依据：[README.md](../../README.md)、[ARCHITECTURE.md](../../ARCHITECTURE.md)、
> [PRODUCT.md](../../PRODUCT.md)、[Cargo.toml](../../Cargo.toml)。
> 冲突时以契约为准。

## 1. 项目定位

**Nexus** 是一个统一的**个人动态资源运行时（Resource Fabric）**，外加一套与之配套的
**Agent-Native Engineering System**（把"如何可靠地开发 Nexus"本身写成机器可执行的仓库契约）。

产品把网络访问、Service、Workspace、Compute 与设备能力统一建模为 **Resource**，用户表达
"要使用什么资源"和"如何使用"，系统负责：

```text
Resource + Intent
        ↓
Resolve Candidate Providers      （发现候选提供方）
        ↓
Core Planner                     （规划 Provider / Placement / Path / ExecutionStrategy）
        ↓
Create Session                   （创建会话）
        ↓
Establish Connectivity           （建连，规划后才建连）
        ↓
Execute                          （执行）
        ↓
Observe + Adapt                  （观测 + 重规划反馈闭环）
        ↓
Persist / Recover                （持久化 / 崩溃恢复）
```

两个平面**正交**：

| 平面 | 内容 | 入口 |
|---|---|---|
| **Production Runtime** | 资源运行时本体（40+ crate + daemon + CLI） | `crates/`、`apps/` |
| **Agent-Native Engineering** | 契约、门禁、场景验证、Evidence | `engineering/`、`harness.toml`、`policies/`、`scenarios/`、`.githooks/` |

Harness 不拥有业务真相、不被 production crate 依赖（[ARCHITECTURE §10](../../ARCHITECTURE.md)）。

## 2. 核心领域模型

稳定核心（[ARCHITECTURE §1](../../ARCHITECTURE.md)）：

```text
Resource · Provider · Node · Intent · Constraint · Plan · Session · Measurement
```

核心边界（领域不变量，违反即架构红线）：

```text
Resource   != Provider        Identity    != Locator
Provider   != Node            Plan        != Session
Measurement != Score          Policy      != Path
Connectivity Evaluation != Connectivity Establishment
Connectivity != Transport     Portable Ingress != Platform Interception
Virtual Packet Interface != TUN            Workspace != Filesystem
WorkspaceGraph != CAS         Planner     != Estimator / Scheduler
TerminalOutcome != LifecyclePhase          Portable Core != Platform Runtime
```

Session 双轨状态（[PRODUCT §7](../../PRODUCT.md)）：

```text
LifecyclePhase : Allocating | Active | Draining | Disposed
TerminalOutcome: Unfinished | Completed | Failed | Cancelled
```

`Completed/Failed/Cancelled` 恰好提交一次，由 Owner State Machine 唯一写入；
Worker 只发事件。

## 3. 运行时分层与调用流

```text
Ingress / User Request
  ==> Application Service / SessionManager
  ==> Policy + Core Planner
  ==> Session Runtime
  ==> Domain Runtime            （Network / Service / Workspace / Compute）
  ==> Delivery Infrastructure   （Connectivity + Transport + Delivery Session Binding）
  ==> Platform Capability       （nexus-platform trait，由 nexus-platform-<os> 实现）
  ==> OS / Framework
```

规则要点：

- **Ingress 是系统级 Driver**：`nexus-ingress` 只产生中立 `FlowContext` 并上交
  Application 层，不直接调用 Planner，也不是 `nexus-network` 的私有子件。
- **Plan before Connectivity**：规划前只做 Connectivity *Evaluation*；
  Plan + Session 创建之后才做 Connectivity *Establishment*。
- **单一 Core Planner**：全系统只有一个系统级 Planner；领域局部组件只能是
  Estimator / Evaluator / Scheduler，不得产生第二套系统级 Plan。
  领域信息进类型化、版本化的 `NetworkPlanExtension` / `WorkspacePlanExtension` /
  `ComputePlanExtension` / `ServicePlanExtension`。
- **Portable Core 不碰平台 API**：Clock、Random、SecureStore、VirtualPacketInterface、
  TransparentIngress、FilesystemProjection、Lifecycle 等由 `nexus-platform` trait 表达，
  平台实现集中在 `nexus-platform-*`，由 Composition Root（`apps/nexusd`）装配。
- **Delivery 共享底座**：Network / Service / Workspace / Compute 都经 Delivery
  Infrastructure 使用远端资源；Delivery 不得反向依赖业务域。

### 3.1 TUN 数据面会话链（PRODUCT §2.1）

```text
TUN packet → FlowTable(5-tuple) → 新流首包: FlowContext(origin=PacketCapture)
             → Policy → Core Planner → SessionManager 创建 Session
             → 后台异步 Establish Connectivity → 会话 Active 后绑定流表项、快路径转发
```

`process_one()` 永不阻塞；DNS 短路与 QoS 整形留在逐包快路径。

## 4. 产品线全景

`PRODUCT.md`（约 2600 行、15 章）冻结的产品线：

| 产品线 | PRODUCT 章节 | 一句话 |
|---|---|---|
| 设备能力 Devices | §1.1 | VirtualPacketInterface / SecureStore / SystemProxyController / AutostartRegistrar，经 capability adapter 注入 |
| Network / InternetAccess | §2 | FlowContext → Policy → Planner → Session → Connectivity，7 类结构化失败语义 |
| Service | §3 | `connect` / `forward`，非 loopback 监听需显式授权 |
| Workspace | §4 | 内容哈希 Commit DAG + Head Set + CAS，离线分叉、三方合并、Conflict Object 持久化 |
| Compute | §5 | 执行前固定 Snapshot；Write-back 必须产生新 Commit |
| 远程资源访问 | §6 | 跨节点闭环：发现 → 认证门控 → 帧协议（TCP + u32 长度前缀）→ 链路加密（X25519 ECDH + HKDF + ChaCha20Poly1305）|
| Session 语义 | §7 | 双轨状态（见 §2 上文） |
| 跨平台语义 | §8 | Semantic Portability；能力缺失必须显式 `Unavailable` / 文档化降级 |
| 可观察性 | §9 | status / plan explain / session watch / connectivity / dns / workspace / compute jobs / diagnose；thin-client CLI 经 LocalAPI 查 daemon |
| 代理内核 | §11 | Rule-Based Routing Proxy：SOCKS5/HTTP/TUN 入站 → 规则表（DOMAIN/IP-CIDR/GEOIP/GEOSITE/RULE-SET/MATCH）→ 策略组（selector/urltest/load_balance/relay）→ 出站（Shadowsocks/VMess/Trojan/…） |
| 虚拟子网组网 | §12 | TUN/UDP 数据面、静态/动态路由（Dijkstra+FIB）、隧道加密、QoS、NAT 打洞、TURN 中继、健康检查、故障转移等 P0–P5 能力族 |
| Windows 系统代理 | §13 | WinINET 系统代理接管 + 计划任务常驻自启 |
| 计划任务 | §14 | Scheduled Task Submission，幂等与恢复 |
| 持久化与恢复 | §15 | Cold-Start Reconciliation：先对账再接受新工作 |

完成条件（§10）：关键用户可见 Capability 需 **E4 产品场景** 或 **E5 外部观测** 证据；
代码存在 / 单测通过 / Agent 声称完成都不算数。

## 5. 仓库结构地图

```text
/
├── PRODUCT.md / ARCHITECTURE.md / DEVELOPMENT.md / AGENTS.md   ← L1/L2 契约
├── harness.toml / policies/ / scenarios/                       ← 机器门禁与 E4 场景
├── apps/
│   ├── nexus/                 CLI（thin-client，198 个 .rs，含 examples/ E4 场景驱动）
│   ├── nexusd/                守护进程 = Composition Root（装配一切）
│   └── nexus-platform-host/   平台宿主入口
├── crates/                    40+ 领域/平台 crate（每个带 MODULE.md 契约）
├── engineering/
│   ├── nexus-harness/         工程门禁 CLI（status/context/check/test/verify/explain/code）
│   ├── evidence-schema/       Evidence JSON Schema
│   ├── verifiers/             Python E4 校验器
│   └── plugins/               插件契约
├── scenarios/product|platform|engineering|regression/          ← E4 场景契约（唯一权威）
├── tests/concurrency|integration|regression/                   ← 跨 crate 测试
├── fuzz/                      fuzz target（policy_planner_no_panic）
├── docs/                      设计文档、N3 契约、协议文档
├── vendor/quinn-proto/        QUIC 补丁（quinn#2658 修复）
└── .githooks/ .agents/        机器门禁与项目级 Agent Skills
```

规模基线：workspace 成员 52 个（48 crate + 3 app + harness），`*.rs` 源文件约 555 个；
最大的 crate 是 `apps/nexus`（198）与 `apps/nexusd`（66），核心库中
`nexus-connectivity`（36）与 `nexus-projection`（27）最重。

## 6. Agent-Native 工程闭环

```text
Task → 契约（PRODUCT/MODULE/scenarios）→ Red Evidence → Spec-Freeze（Contract Hash）
     → Implementation → 受影响范围验证 → 独立 Review → Evidence → Verdict
```

- **Contract-First**：新 feature / 需求变化必须先冻结 Scenario expectation（Protected），
  实现只能让场景变绿，禁止改 expected value 迎合实现。
- **不可自证**：Agent 只能声明 `Candidate Completion`；`PASS | FAIL | STALE | UNKNOWN | BLOCKED`
  最终 Verdict 只能由 Harness/Verifier 产生。
- **Evidence 强度**：E0 存在 → E1 静态 → E2 单测 → E3 集成 → E4 产品场景 → E5 外部观测。
- **Evidence Freshness**：绑定 source revision、working tree digest、配置摘要、feature set、
  target triple、toolchain、契约哈希；输入变化即 STALE。

细节见 [05-running-and-development.md](05-running-and-development.md)。

## 7. 两条驱动链（并行产品线，共享底座）

**远程资源访问闭环**（主链）：

```text
Ingress → Application Service / SessionManager → Policy → Core Planner
       → Session Runtime → Network Runtime → Delivery → Platform Capability
```

**代理内核链**（PRODUCT §11 / ARCHITECTURE §11，平行不合并）：

```text
SOCKS5/HTTP/TUN Ingress（nexus-ingress 状态机）
  → FlowContext → nexus-proxy RuleEngine（first-match 静态规则表）
  → rule_action 动作链（首动作 SELECT_OUTBOUND tag）
  → GroupRegistry（selector / urltest / load_balance / relay）
  → nexus-connectivity LinkActivator（Direct → Relay 回退）
```

衔接约束：代理规则引擎是**领域局部组件**，不是第二套 Core Planner；不修改
`NetworkPlanExtension`；`nexus-proxy` 不反向依赖 network/service/workspace/compute。
