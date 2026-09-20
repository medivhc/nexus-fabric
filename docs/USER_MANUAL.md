# Nexus 用户手册

> 版本：基于 master
>
> `9f5dc8e`
>
> （2026-09-20 校验）
> 校验证据：
>
> `nexus-harness verify --full`
>
>  →
>
> **21 门禁全 PASS，0 fail**
>
> （evidence
>
> `verify-c909d8536eb6`
>
> ）

本手册只收录**有完整实现逻辑、用户可达**的功能。每个功能均附代码级校验：可机检场景（E4/E3）在 `verify --full` 中 PASS、可执行驱动（example / CLI 命令）与来源代码路径。



***

## 1. 产品概览

Nexus 向用户提供一个统一 **Resource Fabric**：用户表达 "要使用什么资源、如何使用"，系统负责发现 Provider、规划 Provider/Placement/Path、建立 Session、激活 Connectivity、执行并持续观测（PRODUCT §1）。

五大产品分类：**Devices / Network / Services / Workspaces / Compute**。

所有资源使用遵守统一时序（ARCHITECTURE §6）：



```
Resolve Candidate Providers

 → Plan Placement + Path

 → Create Session

 → Establish Connectivity

 → Execute
```

核心不变量（由场景机检强制）：



* **Plan 与 Session 必须先于建连**（`plan_before_connectivity`）。

* **TerminalOutcome 恰一次提交**：Completed / Failed / Cancelled 只能由 Owner 提交一次，Worker 只发事件。

* **失败逆序幂等回滚**：终态确定后 Draining → Disposed，重复回滚被拒绝且状态不变。

* **认证门控**：未认证的链路 / 帧绝不进入业务处理。

## 2. 快速开始

### 2.1 环境要求


| 项                  | 要求                                 |
| ------------------ | ---------------------------------- |
| Rust               | stable 1.95.0（`rustc` / `cargo`）   |
| 目标平台               | x86\_64-pc-windows-msvc（本手册校验环境）   |
| nightly（仅 fuzz 门禁） | `rustup toolchain install nightly` |

### 2.2 构建


```
cargo build --workspace
```

### 2.3 三个入口


| 二进制                   | 角色                    | 命令示例                                          |
| --------------------- | --------------------- | --------------------------------------------- |
| `nexusd`              | 桌面 / 服务端 Runtime 组合根  | `nexusd run internet-access --json`           |
| `nexus`               | 控制面 CLI 前端（bootstrap） | `nexus status`                                |
| `nexus-platform-host` | 平台宿主（能力声明）            | `nexus-platform-host vpi-capabilities --json` |

> 说明：
>
> `nexus`
>
>  CLI 当前为 bootstrap 状态 —— 命令解析完整，但除
>
> `status`
>
>  外领域执行返回结构化
>
> `Unsupported`
>
> （PRODUCT §7 禁止静默降级）。可执行功能请使用
>
> `nexusd`
>
>  或 SDK 组合根函数。

## 3. 功能总览

以下 32 项功能均已通过代码级校验（场景 PASS + 驱动可运行）。括号内为场景 ID 与期望条数。


| #  | 功能                           | 场景（E4/E3）                                            | 用户入口                                          |
| -- | ---------------------------- | ---------------------------------------------------- | --------------------------------------------- |
| 1  | InternetAccess 端到端访问         | `product.internet-access-flow` (11)                  | example / SDK                                 |
| 2  | 建连失败逆序回滚                     | `product.connectivity-failure-rollback` (7)          | example / SDK                                 |
| 3  | VPI/PacketCarrier 双 trait 解耦 | `product.connectivity-carrier-split` (6)             | example                                       |
| 4  | SOCKS5 有状态握手                 | `product.socks5-handshake` (6)                       | example                                       |
| 5  | DNS 子系统与 Exit-DNS Binding    | `product.dns-exit-binding` (8)                       | example                                       |
| 6  | Service 资源生命周期               | `product.resource-session-lifecycle` (9)             | example / SDK                                 |
| 7  | daemon 运行远程服务闭环              | `product.daemon-run-remote-service-flow` (20)        | `nexusd run service --json`                   |
| 8  | 远程 Service 访问                | `product.remote-service-access-flow` (20)            | example / SDK                                 |
| 9  | 远程 Internet 出口               | `product.remote-internet-access-flow` (21)           | example / SDK / `nexusd run internet-access`  |
| 10 | 远程建连失败回滚                     | `product.remote-connectivity-failure-rollback` (12)  | example                                       |
| 11 | 远程认证门控拒绝                     | `product.remote-network-auth-rejected-rollback` (12) | example                                       |
| 12 | 远程计算作业                       | `product.remote-compute-job-flow` (22)               | example / SDK / `nexusd run compute`          |
| 13 | 远程计算拒绝回滚                     | `product.remote-compute-rejected-rollback` (12)      | example                                       |
| 14 | 远程 Workspace 提交              | `product.remote-workspace-commit-flow` (20)          | example                                       |
| 15 | 远程 Workspace 拒绝回滚            | `product.remote-workspace-rejected-rollback` (15)    | example                                       |
| 16 | 动态 Presence 发现               | `product.remote-presence-dynamic-flow` (21)          | example                                       |
| 17 | Presence 过期回滚                | `product.remote-presence-expired-rollback` (7)       | example                                       |
| 18 | NAT/Relay 链路回退               | `product.remote-nat-relay-fallback-flow` (23)        | example                                       |
| 19 | Relay 不可用回滚                  | `product.remote-relay-unavailable-rollback` (13)     | example                                       |
| 20 | Workspace 离线三方合并             | `product.workspace-offline-merge` (4)                | example / SDK                                 |
| 21 | 崩溃恢复（冷启动 Reconciliation）     | `regression.crash-recovery` (4)                      | example / SDK                                 |
| 22 | 终态恰一次提交                      | `regression.session-outcome-exactly-once` (2)        | example / SDK                                 |
| 23 | 未知资源结构化拒绝                    | `product.daemon-rejects-unknown-resource` (4)        | `nexusd run <unknown> --json`                 |
| 24 | Observability 总览             | `product.observability-status` (4)                   | `nexusd status --json`                        |
| 25 | Observability: plan explain  | `product.observability-plan-explain` (4)             | `nexusd plan explain --json`                  |
| 26 | Observability: session watch | `product.observability-session-watch` (4)            | `nexusd session watch --json`                 |
| 27 | Observability: dns cache     | `product.observability-dns-cache` (3)                | `nexusd dns cache --json`                     |
| 28 | 未就绪命令显式 UNSUPPORTED          | `product.observability-unsupported` (3)              | `nexusd workspace heads --json`               |
| 29 | Windows VPI 能力声明（wintun）     | `platform.virtual-packet-interface` (10)             | `nexus-platform-host vpi-capabilities --json` |
| 30 | 虚拟子网隧道（Virtual Subnet）      | `product.virtual-subnet-tunnel` (7)                  | example / SDK                                 |
| 31 | NAT 打洞（STUN + UDP 打洞）       | （单元测试覆盖，待 E4 场景完善）                     | SDK / example                                 |
| 32 | 独立 Review + 动态知识库          | （工程方法论，非用户功能）                           | `.agents/skills/` + `.agents/knowledge/`    |



***

## 4. 功能手册（按域）

### 4.1 网络 / Internet Access

#### 4.1.1 InternetAccess 端到端访问



* **能力**：运行一次 InternetAccess 端到端纵切 ——Ingress 构造中立 FlowContext → SessionManager/Policy 生成 Intent+Constraint → Core Planner 选择 Provider/Placement/Path → 创建 Session → 建连 → 执行。纯内存、确定性（相同入参产生相同报告，可重放）。

* **用户用法**：


  * example：`cargo run --quiet -p nexus --example internet_access_flow -- --json`

  * SDK：`nexus::internet_access_flow(destination: &str, profile: &str) -> Result<Value, NexusError>`（`apps/nexus/src/lib.rs:84`）

* **代码级校验**：


  * 场景 `product.internet-access-flow`（E4，11 条期望）→ PASS

  * 驱动：`apps/nexus/examples/internet_access_flow.rs`；SDK 实现 `apps/nexus/src/lib.rs`

  * 门禁：product-scenarios；集成测试 `apps/nexus/tests/internet_access_flow.rs`

#### 4.1.2 建连失败逆序回滚



* **能力**：Connectivity 建连失败时验证两条产品不变量 ——(1) 先规划后建连；(2) W12 认证门控：未认证链路绝不 Established，失败事件结构化上报；(3) Worker 只发事件，Owner 唯一提交 `Failed`；(4) 终态后 Draining → Disposed，重复回滚幂等（被拒绝、状态不变）。

* **用户用法**：


  * example：`cargo run --quiet -p nexus --example connectivity_failure_rollback -- --json`

  * SDK：`nexus::connectivity_failure_rollback(destination: &str, profile: &str)`（`apps/nexus/src/lib.rs:329`）

* **代码级校验**：场景 `product.connectivity-failure-rollback`（7 期望）→ PASS；驱动 `apps/nexus/examples/connectivity_failure_rollback.rs`；集成测试 `apps/nexus/tests/connectivity_failure_rollback.rs`

#### 4.1.3 VPI / PacketCarrier 双 trait 解耦



* **能力**：Connectivity 层通过两个 trait 注入编排 ——VPI（IP 包语义）与 PacketCarrier（承载帧语义）分离，认证门控在链路层生效。是 wintun 后端与未来多平台后端的统一抽象边界。

* **用户用法**：`cargo run --quiet -p nexus --example connectivity_carrier_split -- --json`

* **代码级校验**：场景 `product.connectivity-carrier-split`（6 期望）→ PASS；驱动 `apps/nexus/examples/connectivity_carrier_split.rs`

#### 4.1.4 SOCKS5 有状态握手



* **能力**：SOCKS5 状态机：分步喂字节推进 Greeting → Method → Request → Established；失败路径结构化上报（不把协议错误改写成 "预期行为"）。

* **用户用法**：`cargo run --quiet -p nexus --example socks5_handshake -- --json`

* **代码级校验**：场景 `product.socks5-handshake`（6 期望）→ PASS；驱动 `apps/nexus/examples/socks5_handshake.rs`

#### 4.1.5 DNS 子系统与 Exit-DNS Binding



* **能力**：DNS 解析 → 缓存 → 环路守卫 → RDRC 负缓存 → Exit-DNS Binding 作为 NetworkPlanExtension 进入 Plan。可观测 DNS 状态 / 缓存 / Provider。

* **用户用法**：


  * example：`cargo run --quiet -p nexus --example dns_exit_binding -- --json`

  * 观察：`nexusd dns status --json` / `nexusd dns cache --json`

* **代码级校验**：场景 `product.dns-exit-binding`（8 期望）→ PASS；驱动 `apps/nexus/examples/dns_exit_binding.rs`

#### 4.1.6 虚拟子网隧道（Virtual Subnet）



* **能力**：节点间虚拟 IP 互通隧道，支持双节点点对点虚拟 IP 收发，结构化事件输出支持 replay / 调试。

* **用户用法**：


  * example：`cargo run --quiet -p nexus --example virtual_subnet_tunnel -- --json`

  * SDK：`nexus_connectivity::virtual_subnet::VirtualSubnetTunnel`

* **代码级校验**：场景 `product.virtual-subnet-tunnel`（7 期望）→ PASS；驱动 `crates/nexus-connectivity/src/virtual_subnet.rs`；单元测试 7 项

#### 4.1.7 NAT 打洞（STUN + UDP 打洞）



* **能力**：STUN 协议获取公网映射 + NAT 类型检测 + UDP 打洞建连。支持结构化事件输出。

* **用户用法**：


  * SDK：`nexus_connectivity::nat::StunClient` / `nexus_connectivity::nat::HolePuncher`

* **代码级校验**：单元测试 7 项（STUN 请求构造、响应解析、随机 Transaction ID 等）；待 E4 场景完善

### 4.2 Service

#### 4.2.1 Service 资源生命周期



* **能力**：Service 资源完整生命周期，验证两条产品不变量：(1) Resolve → Plan → Session → Connectivity → Execute 顺序（Plan/Session 先于建连）；(2) Exactly-One Terminal Outcome：Owner 只提交一次终态、重复提交被拒、终态后 cleanup 推进到 Disposed。

* **用户用法**：


  * example：`cargo run --quiet -p nexus --example service_session_lifecycle -- --json`

  * SDK：`nexus::service_session_lifecycle(resource: &str, profile: &str)`（`apps/nexus/src/lib.rs:192`）

* **代码级校验**：场景 `product.resource-session-lifecycle`（9 期望）→ PASS；集成测试 `apps/nexus/tests/service_session_lifecycle.rs`

#### 4.2.2 daemon 运行远程服务闭环



* **能力**：`nexusd` 单次执行入口装配 SDK 远程服务闭环，输出附加 daemon 入口元数据（`daemon.entry` / `daemon.resource`）。

* **用户用法**：`cargo run --quiet -p nexusd -- run service --json`

* **代码级校验**：场景 `product.daemon-run-remote-service-flow`（20 期望）→ PASS；实现 `apps/nexusd/src/main.rs`（`run_resource` + `enrich`）

### 4.3 远程资源访问（Node A ↔ Node B）

> 共同机制：进程内双节点模拟 ——Node B 在回环端口监听并提供服务 / 出口 / 计算 / Workspace；Node A 经 Discovery → Plan → Session → Connectivity → Auth → 资源访问的真实 TCP 长度前缀帧流闭环。链路激活支持 Direct 探测与 Relay 中继两跳。

#### 4.3.1 远程 Service 访问



* **能力**：Node A 经静态发现 / 规划 / 会话 / 建连 / Token 门控 / Transport 访问 Node B 的 Service 资源（CONNECT → READY 握手）。

* **用户用法**：example `cargo run --quiet -p nexus --example remote_service_access_flow -- --json`；SDK `nexus::remote_service_access_flow()`（`apps/nexus/src/lib.rs:617`）

* **代码级校验**：场景 `product.remote-service-access-flow`（20 期望）→ PASS

#### 4.3.2 远程 Internet 出口



* **能力**：Node A 经远程闭环访问 Node B 的 InternetAccess 出口，HTTP 请求 / 响应帧往返成功。

* **用户用法**：example `cargo run --quiet -p nexus --example remote_internet_access_flow -- --json`；SDK `nexus::remote_internet_access_flow()`；`nexusd run internet-access --json`

* **代码级校验**：场景 `product.remote-internet-access-flow`（21 期望）→ PASS

#### 4.3.3 远程建连失败回滚



* **能力**：Discovery 已解析 Node B 但建连失败 → 按逆序幂等回滚到 Disposed，Owner 唯一提交 Failed。

* **用户用法**：example `cargo run --quiet -p nexus --example remote_connectivity_failure_rollback -- --json`

* **代码级校验**：场景 `product.remote-connectivity-failure-rollback`（12 期望）→ PASS

#### 4.3.4 远程认证门控拒绝



* **能力**：远程网络会话令牌不匹配时认证门控拒绝（W7：未认证帧不进入业务处理），逆序幂等回滚。

* **用户用法**：example `cargo run --quiet -p nexus --example remote_network_auth_rejected_rollback -- --json`

* **代码级校验**：场景 `product.remote-network-auth-rejected-rollback`（12 期望）→ PASS

#### 4.3.5 远程计算作业



* **能力**：Node A 向 Node B 提交计算作业并取回结果帧（提交 / 结果往返）。

* **用户用法**：example `cargo run --quiet -p nexus --example remote_compute_job_flow -- --json`；SDK `nexus::remote_compute_job_flow()`；`nexusd run compute --json`

* **代码级校验**：场景 `product.remote-compute-job-flow`（22 期望）→ PASS

#### 4.3.6 远程计算拒绝回滚



* **能力**：计算作业被提供方拒绝（REJECTED 帧）→ 逆序幂等回滚。

* **用户用法**：example `cargo run --quiet -p nexus --example remote_compute_rejected_rollback -- --json`

* **代码级校验**：场景 `product.remote-compute-rejected-rollback`（12 期望）→ PASS

#### 4.3.7 远程 Workspace 提交



* **能力**：Node A 经远程闭环向 Node B 的 Workspace 远程提交并取回新 Head（OK:HEAD 往返）。

* **用户用法**：example `cargo run --quiet -p nexus --example remote_workspace_commit_flow -- --json`

* **代码级校验**：场景 `product.remote-workspace-commit-flow`（20 期望）→ PASS

#### 4.3.8 远程 Workspace 拒绝回滚



* **能力**：远程提交被提供方拒绝（REJECTED 帧）→ 逆序幂等回滚。

* **用户用法**：example `cargo run --quiet -p nexus --example remote_workspace_rejected_rollback -- --json`

* **代码级校验**：场景 `product.remote-workspace-rejected-rollback`（15 期望）→ PASS

#### 4.3.9 动态 Presence 发现



* **能力**：Node B 发布动态 Presence，Node A 经动态发现解析（Discovery → Endpoint）后完成远程闭环。

* **用户用法**：example `cargo run --quiet -p nexus --example remote_presence_dynamic_flow -- --json`

* **代码级校验**：场景 `product.remote-presence-dynamic-flow`（21 期望）→ PASS

#### 4.3.10 Presence 过期回滚



* **能力**：Node B 的 Presence 过期（PeerExpired/PeerUnknown）后 Node A 动态解析失败并回滚，不进入 Plan/Session。

* **用户用法**：example `cargo run --quiet -p nexus --example remote_presence_expired_rollback -- --json`

* **代码级校验**：场景 `product.remote-presence-expired-rollback`（7 期望）→ PASS

#### 4.3.11 NAT/Relay 链路回退



* **能力**：Node B 位于 NAT 后：Direct 候选探测失败（NAT 不可达）时回退 Relay 中继（A → R → B 两跳）完成远程闭环。

* **用户用法**：example `cargo run --quiet -p nexus --example remote_nat_relay_fallback_flow -- --json`

* **代码级校验**：场景 `product.remote-nat-relay-fallback-flow`（23 期望）→ PASS

#### 4.3.12 Relay 不可用回滚



* **能力**：Direct 与 Relay 均不可达时，Link Activation 结构化失败并回滚。

* **用户用法**：example `cargo run --quiet -p nexus --example remote_relay_unavailable_rollback -- --json`

* **代码级校验**：场景 `product.remote-relay-unavailable-rollback`（13 期望）→ PASS

### 4.4 Workspace（本地）

#### 4.4.1 离线提交三方合并



* **能力**：Workspace 多端离线写允许产生多个 Head；重新联网后 fast-forward /three-way merge / 显式冲突解决；已成功提交的本地数据不因远端 Head 前进而丢失。

* **用户用法**：


  * example：`cargo run --quiet -p nexus-workspace --example workspace_offline_merge -- --json`

  * SDK（`crates/nexus-workspace/src/lib.rs`）：`Workspace::init / open(id, store, &state_root) / commit_changes / merge_heads / heads / state_root / into_store`

* **代码级校验**：场景 `product.workspace-offline-merge`（4 期望）→ PASS；驱动 `crates/nexus-workspace/examples/workspace_offline_merge.rs`；workspace 单元测试 12 项

#### 4.4.2 崩溃恢复（冷启动 Reconciliation）



* **能力**：进程强杀后冷启动必须先 Reconciliation 再接受新工作：加载持久状态 → 重放 / 验证 journal（确认或 redo）→ 孤儿会话分类（Active+Unfinished 恰一次提交 Failed→Disposed）→ 接受新任务；所有 reconcile 幂等。

* **用户用法**：


  * example：`cargo run --quiet -p nexus-workspace --example crash_recovery -- --json`

  * SDK：`Workspace::open` + `reconcile_journal`（返回 `JournalReconcileReport{confirmed, redone, total}`）；`nexus_session::reconcile_session_records(store, &mut session, process_alive)`（返回 `SessionReconcileReport`）

* **代码级校验**：场景 `regression.crash-recovery`（E3，4 期望：reconciliation\_started → workspace\_journal\_reconciled → orphan\_session\_classified → accept\_new\_work）→ PASS；驱动 `crates/nexus-workspace/examples/crash_recovery.rs`；session/workspace 单元测试 25 项

### 4.5 Session

#### 4.5.1 终态恰一次提交



* **能力**：取消、成功、断链三种竞争源轮换 10,000 轮，TerminalOutcome（Completed/Failed/Cancelled）每轮恰一次提交且生命周期到达 Disposed；Worker 只发事件、Owner 是唯一 Outcome Writer。

* **用户用法**：


  * example：`cargo run --quiet -p nexus-session --example session_outcome_exactly_once -- --json`

  * SDK（`crates/nexus-session/src/lib.rs`）：`SessionOwner::new / transition_phase / commit_outcome / request_cancellation / id / phase / committed_outcome / status / events`；`CancelToken`、`AbortOnDropHandle`

* **代码级校验**：场景 `regression.session-outcome-exactly-once`（E3，2 期望）→ PASS；驱动 `crates/nexus-session/examples/session_outcome_exactly_once.rs`；并发测试 `tests/concurrency/session_outcome_race.rs`（2 concurrency tests PASS）

### 4.6 Daemon

#### 4.6.1 未知资源结构化拒绝



* **能力**：`nexusd run <unknown> --json` 返回结构化拒绝 `UNKNOWN_RESOURCE`（exit 0 = 请求已被处理，拒绝也是处理结果），禁止静默忽略。

* **用户用法**：`cargo run --quiet -p nexusd -- run frobnicate --json`

* **代码级校验**：场景 `product.daemon-rejects-unknown-resource`（4 期望）→ PASS

### 4.7 Observability（§9）

> 全部通过
>
> `nexusd <verb> ... --json`
>
>  输出结构化 JSON；未就绪领域命令显式
>
> `UNSUPPORTED`
>
> （exit 0），禁止静默降级。



| 命令                              | 能力                                    | 场景                                        |
| ------------------------------- | ------------------------------------- | ----------------------------------------- |
| `nexusd status --json`          | 总览：DNS 快照 + 建连链路 + 规划决策 + 平台能力        | `product.observability-status` (4)        |
| `nexusd plan explain --json`    | Plan + DecisionTrace 结构化拒绝原因          | `product.observability-plan-explain` (4)  |
| `nexusd session watch --json`   | Session 双轨状态（phase/outcome/committed） | `product.observability-session-watch` (4) |
| `nexusd dns cache --json`       | DNS 正 / 负缓存快照                         | `product.observability-dns-cache` (3)     |
| `nexusd workspace heads --json` | 领域未就绪 → 显式 UNSUPPORTED                | `product.observability-unsupported` (3)   |

SDK 层：`nexus::observability::{status, dns_status, dns_cache, session_watch, connectivity_status, plan_explain, platform_capabilities}`（`apps/nexus/src/observability.rs`）。

### 4.8 平台

#### 4.8.1 Windows VPI 能力声明（wintun）



* **能力**：平台宿主声明 Windows Virtual Packet Interface 能力：wintun 窄 FFI 后端、portable consumer（nexus-ingress）、Packet Semantics（MTU 1420、packet ingress/egress、wintun native API）。

* **用户用法**：`cargo run --quiet -p nexus-platform-host --features platform-windows -- vpi-capabilities --json`

* **代码级校验**：场景 `platform.virtual-packet-interface`（10 期望）→ PASS；实现 `apps/nexus-platform-host`（`vpi-capabilities` 命令）

### 4.9 工程方法论

#### 4.9.1 独立 Review 量化闭环



* **能力**：Fast Verify 通过后必须执行独立 Review，八个维度量化检查（契约一致性 / 边界覆盖 / API 面控制 / 依赖边界 / 错误处理 / 测试质量 / 复杂度控制 / 可观测性），Verdict = CHANGES_REQUESTED 时迭代修正，最多 3 轮。

* **位置**：`.agents/skills/nexus-review/SKILL.md`

* **证据**：`.evidence/review-<id>/summary.json`（含 review_round、dimension_changes 等字段）

#### 4.9.2 动态知识库



* **能力**：持续沉淀踩坑、模式、教训，避免重复犯错。任务开始前检索相关历史经验。

* **位置**：`.agents/knowledge/`（entries/ 目录 + index.json）

* **条目格式**：YAML frontmatter + Markdown 正文（问题/原因/解决方案/教训）



***

## 5. 验证体系（如何复现校验）

### 5.1 验证链


```
nexus-harness check          # 4 门禁：whitespace/format/check/clippy

nexus-harness test affected  # 受影响测试

nexus-harness verify --fast  # 8 门禁

nexus-harness verify --full  # 21 门禁（预备交付前）
```

### 5.2 21 门禁清单（verify --full）

whitespace、format、check、clippy、architecture-policy、dependency-governance（cargo-deny）、affected-tests、selected-properties、workspace-tests、integration（3 targets）、product-scenarios（product/engineering/platform 三目录）、regression、architecture-policy、dependency-governance、coverage-summary、selected-fuzz、selected-concurrency、performance-budgets、platform-checks、feature-matrix（72 member×feature 检查）、portable-core（11 crate 编译 wasm32-wasip1）。

### 5.3 场景求值机制

每个可机检场景的 `[when].command` 运行后，runner 对 stdout 的**单个 JSON 对象**按点路径求值 `[[expect]] field=... equals/one_of/non_empty`（支持嵌套与数组路径，如 `events.0`、`capabilities.packet_ingress`）。命令输出必须是纯 JSON 单对象。静态场景（无 command）求值为 UNKNOWN。

### 5.4 证据绑定与新鲜度

每次验证的证据绑定 `source_revision / working_tree_digest / dirty_state / configuration_digest / contract_hash / toolchain_version / target_triple` 等。任意影响结论的输入变化后，旧证据自动 STALE，必须重跑验证绑定新 revision。**Agent 只能声明 Candidate Completion，最终 PASS 由 Harness 产生。**



***

## 6. 已知限制与未实现功能


| 项                                            | 状态        | 说明                                                                                                        |
| -------------------------------------------- | --------- | --------------------------------------------------------------------------------------------------------- |
| Workspace Projection（无 Mount 平台使用 Workspace） | 场景已冻结、未实现 | `platform.workspace-projection-fallback` 静态 UNKNOWN（MaterializedDirectory 访问提供者未实现）                       |
| `nexus` CLI 领域执行                             | bootstrap | 命令解析完整，除 `status` 外返回结构化 Unsupported；可执行入口走 `nexusd`                                                      |
| 传输层 crate                                    | stub      | `nexus-delivery`、`nexus-diagnostics`、`nexus-proto`、`nexus-platform-{linux,macos,android,ios}` 为 12–16 行骨架 |
| fuzz 门禁                                      | 需 nightly | `cargo +nightly fuzz check`（stable 下 libfuzzer -Z 选项失败）                                                   |
| NAT 打洞 E4 场景                               | 待完善      | 单元测试覆盖，待补充产品级 E4 场景                                                                              |
| 磁盘注意                                         | 本机        | 构建产物优先放 D:（C:/E: 高水位告警）                                                                                   |
