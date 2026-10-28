# ADR 0001 — 双栈划界：v9 CLI 运行时 frozen，N1 为唯一演进面

- date: 2026-10-26
- status: accepted
- decision-owner: 主会话
- supersedes: ARCHITECTURE.md §6 原文的适用范围（"Delivery Infrastructure 被 Network/Service/Workspace/Compute 共享"）

## 背景

系统内同时存在两套建连运行时：

1. `nexus-connectivity`（及消费它的 `apps/nexus` 命令面、`nexus-proxy`）；
2. N1 投递面（`nexus-fabric` / `nexus-path` / `nexus-nat-*` / `nexus-projection` /
   `nexus-network` / `nexus-dns` / `nexus-turn` / `nexus-ingress` / `nexus-flow-session` /
   `nexus-outbound-*`），由 `apps/nexusd` 装配。

两者长期并行，旧栈被新栈 crate 当作"共享底座"引用，形成了 4 处实质接缝
（① `NatType`/`StunMapping`、② `OutboundAdapter`/`OutboundHandoff`、③ CAKE/令牌桶、
④ `LinkMarker` 系列），使得"新栈演进"不断被旧栈的词汇与持久化格式绑住。

方案对比（B vs C）：

- **B（迁移/退役旧栈）**：把 CLI 命令面整体迁到 N1 后删除 `nexus-connectivity`。
  否决，因为：
  1. CLI 仍有真实用户面（`subnet` / `mesh` / `proxy` / `connectivity`），迁移期两栈必须
     同时可运行，迁移成本与回归面远大于收益；
  2. 旧栈的虚拟子网 / bootstrap / relay / FIB / mesh DNS 能力在 N1 尚无等价实现，
     强行迁移等于重写产品线；
  3. 一次性大迁移会把"边界治理"与"功能迁移"耦合在同一个不可验证的变更里。
- **C（划界 + 接缝清零）**：把旧栈定性为 frozen 的 v9 CLI 产品线运行时，把 4 处接缝
  逐个下沉到跨栈共享叶（`nexus-domain` / `nexus-proxy-config` / `nexus-session` /
  `nexus-qos`），使 N1 对旧栈的直接依赖边归零。采纳。

## 决策

### 两栈定义

- **v9 CLI 产品线运行时（frozen）** = `nexus-connectivity` + `apps/nexus` 的
  `subnet` / `mesh` / `proxy` / `connectivity` 命令面 + `nexus-proxy`。
  只接受带 Red Evidence 的缺陷 / 安全 / 崩溃一致性修复（判据 F1–F7，见
  `crates/nexus-connectivity/MODULE.md` 的 `Lifecycle` 节）。
- **N1 投递面（唯一演进面）** = `nexus-fabric`（QUIC 驱动）、`nexus-path`（路径选择）、
  `nexus-nat-traversal` / `nexus-nat-wireup` / `nexus-nat-quality`、`nexus-projection`、
  `nexus-network`、`nexus-dns`、`nexus-turn`、`nexus-ingress`、`nexus-flow-session`、
  `nexus-outbound-*`，由 `apps/nexusd` 装配。新能力、新协议字段、新 pub API 只在这一面演进。

### frozen 纪律（浓缩）

- 允许：缺陷修复（带 Red Evidence）、安全修复、崩溃一致性修复、不改语义的依赖安全升级。
- 禁止：新功能、新模块、新 pub API、新协议 / 线格式 / 持久化字段、任何新的入边、
  以"修复"为名修改冻结场景 expectation 或降低门禁强度。

### 判据口径

- **直接依赖边必须为 0**：口径 = `cargo metadata --no-deps` 的 **normal 直接边**
  （`kind == null`）。传递残差（`nexusd → nexus → nexus-connectivity` 等）单独登记，
  不参与本判据。
- 机器判据由 `policies/architecture.toml` 的 `[dual_stack]` 承载（P5 落地）；在此之前
  以 `policies/architecture.toml` 的 allowed 列表 + 独立 Review 人工核对。

## 4 接缝处置表

| # | 接缝 | 现址 | 目标归属 | 期 | 状态 |
|---|---|---|---|---|---|
| ① | `NatType` / `StunMapping` | `nexus-connectivity::nat` | `nexus-domain::nat` | P1 | 已迁（`nexus-connectivity` 以 `pub use` 保旧路径） |
| ② | `OutboundAdapter` / `OutboundHandoff` | `nexus-connectivity` | `nexus-proxy-config::outbound_seam` | P2 | **已落地**（2026-10-28）：条件生效已解除，见 run dual-stack-convergence P2 与 MSR-dualstack-p2-gate-verified-20261028 |
| ③ | CAKE + 令牌桶 | `nexus-connectivity::{cake,qos,bandwidth_policy}` | 新叶子 crate `nexus-qos` | P3 | planned（进入条件：P1/P1′ 已合入 master） |
| ④ | `LinkMarker` / `LinkMarkerStore` / `LinkReconcileReport` / `reconcile_link_markers` | `nexus-connectivity` | `nexus-session::link_marker` | P1′ | 已迁（`links.json` 字节格式不变） |

## 共享叶判据

**叶子被两栈依赖不是反向边**。判据：该 crate 只承载词汇 / DTO / durable record

- 不含 I/O、不含建连逻辑、不依赖任何运行时 crate；
- 被两栈同时依赖时，两栈之间不因此产生调用关系；
- 先例：`ConnectivityEvaluation` 已在 `nexus-domain`；`OutboundKind` 已在
  `nexus-proxy-config`。

**叶子清单**：

| 叶子 | 承载 |
|---|---|
| `nexus-domain` | NAT 词汇（`nat::NatType` / `StunMapping`）、`ConnectivityEvaluation` DTO、核心领域类型 |
| `nexus-proxy-config` | 出站身份 / 交接词汇（`OutboundKind`；② 的目标落点） |
| `nexus-session` | durable record（`SessionRecord`、`link_marker::*`） |
| `nexus-qos` | 包调度与令牌桶（P3 落地） |

## 被取代的旧口径清单

| 旧口径 | 位置 | 处置 |
|---|---|---|
| "Delivery Infrastructure 被 Network/Service/Workspace/Compute 共享" | `ARCHITECTURE.md` §6 原文 | 改写为双栈划界（P0） |
| "与远程资源访问闭环共享同一 Delivery Infrastructure" | `ARCHITECTURE.md` §11（`:254`） | 改为"共享 `LinkActivator`（v9 运行时）"（P0） |
| "代理内核产品线与远程资源访问闭环共享底座但不互相调用业务逻辑" | `ARCHITECTURE.md` §11（`:260`） | 改为"共享的仅为跨栈共享叶"（P0） |
| "Connectivity 与 Transport 是共享底座" | `AGENTS.md` §9 | 改为双栈定义（P0） |
| "Connectivity/Transport 是共享 Delivery Infrastructure" | `crates/nexus-network/MODULE.md`（旧 `:173`） | 改为分层词 + 双栈口径（P0） |
| "本 crate 是 delivery 层共享底座"（`lib.rs` 头部 + 22 个模块头） | `crates/nexus-connectivity/src/**` | 改为 "v9 CLI 产品线运行时（frozen）"（P0） |
| "本 crate 是 … 不为其他产品线提供共享基础层" | `crates/nexus-connectivity/MODULE.md` | 改写 Responsibility / Non-Responsibilities 并新增 `Lifecycle`（P0） |
| `HolePuncher::punch` 记为 `#[deprecated]` | `docs/DOC-AUDIT-2026-10-06.md:89` | **过时**：该 API 已于 2026-10-18 删除；10-06 快照不改写，按过时登记于 `docs/DOC-AUDIT-2026-10-26-dual-stack.md` |

## Exceptions 表

任何对 F1（能力面）/ F6（线格式）的放宽解释都必须在此登记，并满足：依赖边类例外须在
`policies/architecture.toml [[dual_stack.allow]]` 有条目（`reason` + `review_by`）；
提交正文带 `review: <evidence-id>` 与 `requirement-change: <hash>`。

| 日期 | 文件 | 变更摘要 | Red Evidence id | owner | reviewer | review_by |
|---|---|---|---|---|---|---|
| — | — | （暂无例外） | — | — | — | — |

## 后果 / 风险

- **传递残差（登记，不判）**：`nexusd → nexus → nexus-connectivity`（`nexusd` 直接依赖
  `nexus`，而 `nexus` 是 v9 命令面本体）；P2 未落地前 `nexusd → nexus-outbound-* →
  nexus-connectivity` 亦为传递路径。二者都不属于"直接边"判据。
- **`nexus-qos` 未落地**：ADR 中 ③ 与"共享叶清单"里 `nexus-qos` 条目为 `planned`；
  在 P3 落地前不得引用其 API。
- **P1′ 的 breaking 变更**：`LinkMarker` / `LinkMarkerStore` / `LinkReconcileReport` /
  `reconcile_link_markers` 4 个公开项从 `nexus-connectivity` **删除**（不是保留别名）。
  这与 P1（`NatType` / `StunMapping` 以 `pub use` 保旧路径）的不对称是**有意**的：
  connectivity 内部不再持久化链路状态，保留别名会让"旧栈仍拥有链路持久化"的
  误解继续存在；而 NAT 词汇是两栈都要用的纯词汇，保留别名零风险。
