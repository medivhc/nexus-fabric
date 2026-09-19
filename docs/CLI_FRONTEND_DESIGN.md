# nexus CLI 前端功能设计

> 状态：设计稿（未实现）
> 基线：master `23d504b`；依据代码 `apps/nexus/src/main.rs`、`apps/nexus/src/observability.rs`、`crates/nexus-control-api/src/lib.rs`、`apps/nexusd/src/main.rs`

---

## 1. 背景与目标

### 1.1 现状（代码事实）

| 层 | 现状 |
| -- | -- |
| `nexus-control-api` | 定义 **17 个 `ControlCommand`**（status / plan explain / session watch / connectivity×4 / dns×4 / workspace×3 / compute jobs / diagnose / platform capabilities）+ `ControlOutput` DTO + `ControlService` trait（`lib.rs:26-146`） |
| `apps/nexus/src/observability.rs` | **已实现 18 个命令函数**（JSON 快照）：status、plan_explain、session_watch、connectivity_status/candidates/probe/links、dns_status/resolve/providers/cache、workspace_heads/conflicts/cache、compute_jobs、diagnose、platform_capabilities、unsupported_command |
| `apps/nexusd`（daemon） | **只路由 7 个**观察命令（status / dns status / dns cache / session watch / connectivity status / plan explain / platform capabilities）；其余落到 fallback → `UNSUPPORTED`（`main.rs:50-66`） |
| `nexus`（CLI 前端） | **bootstrap**：17 个命令全部解析正确，但 `BootstrapControlService` 除 `status` 返回固定文本外全部返回 `NexusError::Unsupported`（`main.rs:96-127`） |

### 1.2 目标

把 `nexus` CLI 从 bootstrap 升级为**真实可执行的控制面前端**：

1. 17 个 `ControlCommand` 全部接线到已实现的 observability 能力，消除"命令听懂了但不会做"的落差；
2. 输出双模式：人读文本（`to_lines`）+ 机器读 JSON（`--json`，与场景求值、nexusd 语义一致）；
3. 遵循 PRODUCT §7/§9：未就绪命令显式 `UNSUPPORTED`，禁止静默降级；
4. 不复制领域逻辑：CLI 只做"解析 → 装配 → 渲染"，执行全部委托 `observability` / SDK 组合根。

---

## 2. 设计原则

- **单一执行来源**：`observability.rs` 是唯一执行后端（nexus CLI 与 nexusd 共用），CLI 不重复实现任何领域行为。
- **契约一致**：所有输出字段与场景期望保持同源；新增命令先冻结场景再实现（Contract-First）。
- **机器可读优先**：`--json` 输出与 `nexusd` 相同结构（`verdict` 字段 + 命令数据），可直接被 harness 场景求值。
- **文本为视图**：人读输出是 JSON 的渲染视图，不携带额外语义。
- **向后兼容**：现有 `ControlService` trait 与 `ControlCommand`/`ControlOutput` DTO 保持稳定；只替换实现（`BootstrapControlService` → 真实服务），不扩 DTO 形状。

---

## 3. 命令功能规格

### 3.1 命令映射总表（17 → 18 函数，全覆盖）

| # | CLI 命令 | ControlCommand | 执行后端（observability） | 当前可达 | 场景证据（已有/待建） |
| -- | -- | -- | -- | -- | -- |
| 1 | `nexus status` | Status | `status()` | nexus CLI / nexusd | `product.observability-status` (PASS) |
| 2 | `nexus plan explain <resource>` | PlanExplain | `plan_explain()` | nexusd | `product.observability-plan-explain` (PASS) |
| 3 | `nexus session watch <session-id>` | SessionWatch | `session_watch()` | nexusd | `product.observability-session-watch` (PASS) |
| 4 | `nexus connectivity status` | ConnectivityStatus | `connectivity_status()` | nexusd | `product.observability-connectivity-status`（待建） |
| 5 | `nexus connectivity candidates` | ConnectivityCandidates | `connectivity_candidates()` | 均未接线 | 待建 |
| 6 | `nexus connectivity probe <target>` | ConnectivityProbe | `connectivity_probe()` | 均未接线 | 待建 |
| 7 | `nexus connectivity links` | ConnectivityLinks | `connectivity_links()` | 均未接线 | 待建 |
| 8 | `nexus dns status` | DnsStatus | `dns_status()` | nexusd | `product.observability-dns-status`（待建） |
| 9 | `nexus dns resolve <name>` | DnsResolve | `dns_resolve()` | 均未接线 | 待建 |
| 10 | `nexus dns providers` | DnsProviders | `dns_providers()` | 均未接线 | 待建 |
| 11 | `nexus dns cache` | DnsCache | `dns_cache()` | nexusd | `product.observability-dns-cache` (PASS) |
| 12 | `nexus workspace heads <ws>` | WorkspaceHeads | `workspace_heads()` | 均未接线 | 待建 |
| 13 | `nexus workspace conflicts <ws>` | WorkspaceConflicts | `workspace_conflicts()` | 均未接线 | 待建 |
| 14 | `nexus workspace cache <ws>` | WorkspaceCache | `workspace_cache()` | 均未接线 | 待建 |
| 15 | `nexus compute jobs` | ComputeJobs | `compute_jobs()` | 均未接线 | 待建 |
| 16 | `nexus diagnose` | Diagnose | `diagnose()` | 均未接线 | 待建 |
| 17 | `nexus platform capabilities` | PlatformCapabilities | `platform_capabilities()` | nexusd | `product.observability-platform-capabilities`（待建） |

> **结论**：observability 模块已覆盖全部 17 个命令，**无需新增领域实现**。设计核心是"接线 + 渲染"，不是"造功能"。

### 3.2 命令行为语义

每个命令的执行管线：

```text
nexus <command> [args] [--json]
  → parse_command → ControlCommand
  → ControlServiceImpl.execute(command)
      → observability::<fn>()  → serde_json::Value
  → 渲染：
      --json   → 原样输出 Value（结构化，机器可读）
      默认     → to_lines() 文本视图（人读）
```

- 命令**参数当前不参与执行**（observability 函数为无参确定性快照，用演示数据）；`<resource>/<session>/<workspace>/<name>/<target>` 由 `parse_command` 校验存在性（缺失报用法错误 exit 2），值本身在 P0 透传忽略、P1 参数化后消费（见 §5.2）。
- 所有命令输出顶层含 `"verdict": "PASS"`；执行失败返回 `NexusError` 结构化错误（见 §4.3）。

### 3.3 命令分组（面向用户）

| 组 | 命令 | 用途 |
| -- | -- | -- |
| 总览 | `status`、`diagnose` | 一键健康总览 / 分子系统健康报告 |
| 规划 | `plan explain <resource>` | 查看 Plan 决策与拒绝原因 |
| 会话 | `session watch <id>` | 观察 Session 双轨状态 |
| 连接 | `connectivity status\|candidates\|probe <t>\|links` | 建连状态 / 候选 / 探测 / 活动链路 |
| DNS | `dns status\|resolve <n>\|providers\|cache` | DNS 状态 / 解析 / 上游 / 缓存 |
| Workspace | `workspace heads\|conflicts\|cache <ws>` | Head Set / 冲突 / 缓存与 GC |
| 计算 | `compute jobs` | 作业快照 |
| 平台 | `platform capabilities` | 能力与适配器清单 |

---

## 4. 架构设计

### 4.1 控制流

```text
apps/nexus/src/main.rs（不变：参数解析）
  │  ControlCommand
  ▼
apps/nexus/src/control_service.rs（新增）     ← ControlServiceImpl（真实实现）
  │  按命令分发 → observability::<fn>()
  ▼
serde_json::Value
  ├─ --json → println!("{value}")             ← 机器读
  └─ 默认   → 渲染为文本行（JSON 字段 → 行）    ← 人读
```

- 新增 `apps/nexus/src/control_service.rs`：实现 `ControlService` trait 的真实服务，内部把 `ControlCommand` 映射到 `observability` 函数，JSON 转 `ControlOutput`（文本视图）或直接透传（`--json`）。
- `main.rs` 的 `BootstrapControlService` 替换为 `ControlServiceImpl`；`status` 的 bootstrap 占位文本由真实 `observability::status()` 替代。
- **不触碰**：`nexus-control-api`（DTO/trait 稳定）、`apps/nexusd`（保持 7 命令路由，作为独立运行时入口；其未路由命令的接线属 P1 可选）。

### 4.2 渲染规则

**`--json`**：输出 `observability` 返回的原始 `Value`（顶层 `verdict` + 命令字段）。错误同样 JSON 化：`{"verdict":"FAIL","error":{"code":"...","message":"..."}}`。

**默认文本视图**：为每个命令定义固定渲染函数（如 `render_plan_explain(&PlanView)`），字段对齐 `ControlOutput::to_lines()` 现有风格。文本视图只是 JSON 的投影，二者字段一一对应。

### 4.3 错误语义与 exit code

| 情形 | 默认模式 | `--json` 模式 | exit |
| -- | -- | -- | -- |
| 成功 | 文本行 | JSON（verdict=PASS） | 0 |
| 领域错误（如 Unsupported） | `error: <结构化信息>` | JSON（verdict=FAIL） | 0（请求已被处理，与 nexusd 一致） |
| 用法/解析错误（缺参数、未知命令） | 错误 + usage | 错误 + usage | 2 |

> 语义对齐 nexusd：**结构化输出即处理结果**，领域拒绝不算进程失败；只有"根本没听懂"才算用法错误。

### 4.4 新增命令（P2 可选扩展，不改变 §3 契约）

| 命令 | 后端 | 说明 |
| -- | -- | -- |
| `nexus run <service\|internet-access\|compute> [--json]` | SDK 远程闭环函数（同 nexusd `run`） | 单次执行入口 |
| `nexus demo <flow>` | `apps/nexus/examples/*.rs` 对应流程 | 运行演示闭环（等价 example） |

---

## 5. 验证设计（Contract-First）

### 5.1 场景现状与冲突

现有 `product.observability-unsupported` 场景用 `nexusd workspace heads --json` 验证"未就绪 → UNSUPPORTED"（PASS）。**若把 workspace heads 接线，该场景期望失效** → 必须 requirement-change：改用仍保持未实现的命令验证 UNSUPPORTED 语义（候选：`connectivity trace`——observability 注释中明确"当前未就绪示例：connectivity trace"）。

### 5.2 实施阶段与验证路径

**P0：接线（本设计的主体）**
- 变更：新增 `control_service.rs`；`main.rs` 换真实服务；默认文本渲染。
- 场景（先 Red 后绿，feature 类型，Contract-First）：
  - 新增 12 个机检场景，command 为 `nexus <cmd> [args] --json`（或 `nexusd` 对应命令），expect 断言 verdict=PASS + 关键字段（复用 observability 输出结构）：
    - `product.observability-connectivity-status/candidates/probe/links`
    - `product.observability-dns-status/resolve/providers`
    - `product.observability-workspace-heads/conflicts/cache`
    - `product.observability-compute-jobs`、`product.observability-diagnose`、`product.observability-platform-capabilities`
  - 旧实现（bootstrap）跑这些 command → FAIL（Unsupported）→ Red Evidence → 冻结 hash。
- 验证链：`cargo fmt --all` → `harness check` → `test affected` → `verify --fast` → `verify --full`。

**P1：参数化（可选）**
- `observability` 命令函数接受参数（`dns_resolve(name)`、`workspace_heads(ws)` 等），CLI 把用户参数传入；场景断言参数影响输出。
- 属 requirement-change 风险点：函数签名变化影响所有调用方（nexusd/场景），需先 re-freeze 相关场景。

**P2：扩展命令**（§4.4），独立场景。

### 5.3 单元测试

- `control_service` 映射测试：17 个 `ControlCommand` → 对应函数调用正确、`ControlOutput` 形状正确；
- `parse_command` 已覆盖（保留现有 tests）；
- 渲染测试：`--json` 透传、文本视图与 JSON 字段一致。

---

## 6. 边界与不做的事

- **不做**：不复制领域逻辑到 CLI；不修改 `nexus-control-api` 的 DTO/trait 形状；不接真实网络/磁盘（observability 为确定性内存快照，与现有场景一致）。
- **不做**：不改 `apps/nexusd` 现有 7 命令路由（除非 P1 需要对齐）；不引入第三方 CLI 框架（clap 等）——现有手写解析已覆盖且受测试保护。
- **不做**：`diagnose` 之外的诊断扩展（nexus-diagnostics 仍为 stub；`diagnose()` 基于现有子系统聚合，不新增底层）。
- **不破坏**：`observability-unsupported` 场景的 UNSUPPORTED 验证语义（换命令续测，见 §5.1）。

---

## 7. 交付清单（实施时）

```text
新增  apps/nexus/src/control_service.rs         真实 ControlService 实现 + 文本渲染
修改  apps/nexus/src/main.rs                    换用 ControlServiceImpl；--json 全局开关
修改  apps/nexus/src/lib.rs                     导出 control_service 模块（SDK 可用）
新增  scenarios/product/observability-*.toml   12 个接线场景（Contract-First）
修改  scenarios/product/observability_unsupported.toml  换 UNSUPPORTED 验证命令（requirement-change）
测试  apps/nexus/src/control_service.rs 内单测   映射/渲染/错误语义
证据  verify-<id>（P0 后 21 门禁全绿 + 新场景 PASS）
```
