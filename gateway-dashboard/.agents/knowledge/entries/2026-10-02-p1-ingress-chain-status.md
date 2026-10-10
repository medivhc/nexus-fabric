# v9 §10 全链路装配现状（2026-10-02，Phase 1 收尾 Track 3）

## 链路现状图

v9 §10 规定的链路：

```text
Platform Interception / SOCKS / HTTP / Virtual Packet Source
        ↓
Portable Ingress (nexus-ingress)
        ↓
FlowContext (nexus-domain)
        ↓
SessionManager / Application Service
        ↓
Policy (nexus-policy) → Intent + Constraint
        ↓
Core Planner (nexus-planner) → Plan + DecisionTrace
        ↓
Create Network Session (nexus-session: SessionOwner)
        ↓
nexus-network Runtime + Connectivity Establishment
```

### 现状：两条世界线

**A. `apps/nexus`（CLI `nexus use <resource>`）——链路完整，已 E4**

`apps/nexus/src/lib.rs` 的 `remote_*_flow()` 函数族实现全链：

```text
StaticDiscovery → nexus_ingress::from_native_api() → FlowContext
  → PolicyEngine::default_network().evaluate() → Intent + Constraint
  → Registry + PlanningSnapshot → nexus_planner::plan_from_snapshot() → Plan + DecisionTrace
  → SessionOwner::new() → Active
  → nexus_transport::connect() (真实 TCP) → Connectivity Establishment
  → nexus_auth 预共享 Token
  → nexus_network::NetworkSession::establish() → 真实请求/响应帧
  → commit_outcome(Completed) → Draining → Disposed
```

- E4 场景 `scenarios/product/remote_internet_access_flow.toml`（E4，冻结期望）：
  `cargo run -p nexus --example remote_internet_access_flow`，
  断言 events 顺序 remote_provider_resolved → plan_selected → session_created
  → connectivity_established → …，verdict=PASS。
- 同族还有 service / compute / workspace 的 remote flow（`nexus use service|compute|workspace`）。

**B. `apps/nexusd`（生产 daemon）——链路缺失**

`nexusd <config-dir>` 的实际装配（`main.rs::run_daemon`）：

```text
TUN (nexus-projection) → dataplane::Dataplane::process_one() → N1MeshBridge / ProxyEngine
```

- `dataplane.rs` 零引用 policy/planner/session（grep 确认）。
- `Cargo.toml` 声明了 `nexus-ingress` 依赖，但 `src/` 零引用（dead dep）。
- 零引用 `nexus_policy` / `nexus_planner` / `nexus_session`。
- 即：生产 daemon 的主流量路径（TUN 包）**完全绕过** §10 链——无 FlowContext、无 Policy、
  无 Planner、无 Session。

### 断点清单

| # | 断点 | 性质 | 处置 |
|---|------|------|------|
| 1 | nexusd TUN 数据面不走 §10 链 | 领域缺口 | 记录，不扩 scope（见下） |
| 2 | apps/nexus 链用硬编码 Registry + MeasurementTable（非真实 Discovery/Measurement） | 领域缺口 | 记录 |
| 3 | nexusd 对 nexus-ingress 的 dead 依赖 | 小清理 | 可顺手删（本 track 不做，提 follow-up） |

### 为什么断点 1 不是"补胶水"能解决的

v9 §1：规划是 per-Session 的，不是 per-packet 的。TUN 数据面是逐包转发的，
把 Policy→Planner→Session 硬塞进 `process_one()` 在架构上是错的。
正确形态需要：流分类（5 元组 → FlowContext）→ SessionManager 查已建 Session →
无则走 Policy→Planner→建连 → 包按 Session 的已建路径转发。
这是"流→会话映射"的领域设计，不是装配胶水，需独立立项（requirement-change 级）。

### E4 证据（本 track 新跑）

- `product.remote-internet-access-flow` 在 `track-p1-chain`（master 9c2769c）沙盒重跑：
  **21/21 冻结期望 PASS**（verdict=PASS；events 顺序 remote_provider_resolved →
  plan_selected → session_created → connectivity_established →
  network_session_established → remote_access_completed；plan.provider_id=node-b；
  session Disposed/Completed 且 commit_count=1；network 200；architecture 不变量成立）。
- 该场景用真实 TCP loopback（127.0.0.1），沙盒可跑；UDP EPERM 不影响。

### 本 track 的改动（glue/可观测性）

- `apps/nexus/src/lib.rs::remote_internet_access_flow`：JSON 报告新增 `trace` 字段
  （DecisionTrace：considered + selected），与本地 `internet_access_flow` 同形。
  纯加法可观测性，**未改任何冻结期望**（scenarios/ 零 diff）。
- 链路其他段（ingress/policy/planner/session/network/connectivity）均未动。
