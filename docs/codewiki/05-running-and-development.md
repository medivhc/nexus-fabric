# 05 · 运行方式与开发流程（Running & Development）

> 依据：[README.md](../../README.md)、[DEVELOPMENT.md](../../DEVELOPMENT.md)、
> [AGENTS.md](../../AGENTS.md)、[harness.toml](../../harness.toml)、
> `apps/*/MODULE.md`、[engineering/nexus-harness/MODULE.md](../../engineering/nexus-harness/MODULE.md)。
> 本文是导航性派生文档；命令语义以契约为准。

## 1. 构建

Rust workspace（[Cargo.toml](../../Cargo.toml)，52 个成员：48 个 `crates/*` + 3 个 `apps/*` + `engineering/nexus-harness`）。
workspace 统一 edition、MSRV、profile（[DEVELOPMENT.md §5](../../DEVELOPMENT.md)）。

```sh
cargo build --workspace            # 全量构建
cargo build -p nexus               # 只构建 CLI 瘦客户端
cargo build -p nexusd              # 只构建 daemon
cargo check --workspace --all-targets   # Fast Gate 中的 check 项
```

产出三个可执行文件：

| 二进制 | crate | 角色 |
|---|---|---|
| `nexus` | [apps/nexus](../../apps/nexus/MODULE.md) | 控制面 CLI 瘦客户端（部分命令为进程内 SDK 直跑） |
| `nexusd` | [apps/nexusd](../../apps/nexusd/MODULE.md) | 常驻 daemon（LocalAPI 服务端 + 各子系统装配） |
| `nexus-platform-host` | [apps/nexus-platform-host](../../apps/nexus-platform-host/MODULE.md) | 平台宿主装配入口 |

## 2. 运行 Nexus（产品运行时）

### 2.1 daemon：`nexusd <config-folder>`

```sh
nexusd /etc/nexus/
```

唯一参数是配置文件夹，**缺失 = 不启用**（[apps/nexusd/src/main.rs](../../apps/nexusd/src/main.rs)）：

| 文件 | 作用 | 缺失时 |
|---|---|---|
| `daemon.toml` | LocalAPI 地址、PID、日志、`[tun]` / `[network.turn]` / `[qos]` 小节 | 全部默认值 |
| `network.toml` | N1 mesh 组网 | 不启用 mesh |
| `proxy.yaml` | Clash 风格代理数据面 | 不启用代理 |
| `dns.toml` | DNS 子系统 | 不启用 DNS |
| `workspace.toml` | Workspace FUSE 挂载（无 `/dev/fuse` 时显式禁用并提示） | 不启用 Workspace |

配置支持热加载；监听端口、TUN 设备名、LocalAPI 地址变更 → `NeedsRestart`（[config.rs](../../apps/nexusd/src/config.rs)）。
内部/历史入口 `nexusd serve`（仅 LocalAPI）保留兼容。

### 2.2 CLI：`nexus [--json] [--addr <ip:port>] <command>`

瘦客户端经 LocalAPI 与 daemon 通信（默认 unix socket
`$XDG_RUNTIME_DIR/nexus-localapi.sock`，共享 bearer token 在
`~/.config/nexus/localapi.token`，0600；`--addr` 切 TCP loopback）。
完整命令族见 [apps/nexus/src/main.rs](../../apps/nexus/src/main.rs) 的 `USAGE`，摘要：

```text
观察类（需 daemon 在跑）：
  status / plan <resource> / plan explain <resource|session-id>
  use <resource>                      N2 资源访问入口（resolve→plan→authorize→establish）
  session list|watch <id>|close <id>
  resource list|show/publish/revoke
  connectivity status|candidates|probe <target>|links
  dns status|resolve <name>|providers|cache
  workspace heads|conflicts|cache|commit <workspace>
  task submit/show/cancel/logs/artifacts / task-provider grant ...
  compute jobs / diagnose / platform capabilities

进程内 SDK 直跑（不经 daemon）：
  run <resource>          远程资源访问（`run -- <cmd>` 为 N3 语义，N2 诚实拒绝）
  network up|status       N1 装配前台运行（建 TUN→dial→包泵，Ctrl-C 退出）
  subnet up|status|leave|punch        虚拟子网（PRODUCT §12.28）
  schedule at|every|list|cancel|tick   计划任务（PRODUCT §14）
  proxy [--addr] [--config] [--tun] / speedtest / bufferbloat-test / run|host|relay
  system-proxy <status|set|clear|e2e> / autostart <install|remove|status>
  pair invite|join|list|remove --dir <config-dir>
  node init / node trust --provider <id> --pubkey <hex>
```

Exit 语义（对齐 `nexusd`）：

```text
0   业务结果（含 verdict=FAIL / DAEMON_UNREACHABLE，请求已被处理）
2   用法/解析错误
```

`--json` 原样打印机器可读 JSON（stderr 静默）；默认渲染人读文本（JSON 字段投影）。

## 3. 工程运行方式：nexus-harness

`engineering/nexus-harness` 是仓库的工程入口（最小命令壳，固定命令与 JSON schema；
命令声明见 [harness.toml `[commands]`](../../harness.toml)）。机器模式统一 `--json`。

```sh
nexus-harness status               # 仓库/工程状态
nexus-harness context <target>     # 最小必要上下文（模块职责/边界/API/相关测试/可写路径）
nexus-harness check                # 快速静态检查
nexus-harness test affected        # 受影响测试集（Cargo metadata + 显式 mapping，见 §7）
nexus-harness verify --fast        # Fast Gate（推送前门禁）
nexus-harness verify --full        # Full Gate（Candidate Completion 前）
nexus-harness explain [--json]     # 失败归因（Implementation / Contract / Environment / Unsupported）
nexus-harness bench                # 性能预算门禁
nexus-harness replay               # record → replay 排障
nexus-harness code <verb>          # 只读语义查询（symbol/definition/references/implementations/
                                   #   callers/callees/hover/diagnostics；advisory，不拥有最终 PASS）
```

## 4. 测试与验证

### 4.1 Fast / Full Gate（[DEVELOPMENT.md §6](../../DEVELOPMENT.md)）

```text
Fast：format → check → clippy -D warnings → architecture delta → dependency delta
      → affected tests → selected properties

Full：workspace tests → integration → product scenarios → regression
      → architecture policy → dependency governance → coverage summary
      → selected fuzz/concurrency → performance budgets → platform checks
      → feature matrix → portable-core checks
```

禁止通过削弱 gate 解决失败（[AGENTS.md §19](../../AGENTS.md)）。
注意口径：`verify --fast` 在 `cargo-deny` 缺失时把 `dependency-governance` 记 UNKNOWN
而可能 overall PASS——引用 PASS 必须写明工具在场与否（[DEVELOPMENT.md §11.1](../../DEVELOPMENT.md)）。

### 4.2 测试分层

| 层 | 位置 | 强度 |
|---|---|---|
| 单元/局部行为 | 各 crate `src` 内 `#[cfg(test)]` + `tests/` | E2 |
| 跨 crate 集成/并发 | [tests/](../../tests/README.md)（cancellation、shutdown、outcome race、crash recovery） | E3 |
| 产品级 Scenario | [scenarios/](../../scenarios/)（`product/` / `regression/` / `platform/` / `engineering/`，约 250+ toml） | E4 |

关键用户可见 Capability 至少需要 **E4**（`harness.toml [evidence] minimum_user_visible_strength`）。

### 4.3 Evidence

`.evidence/verify-<id>/`（多 Agent 下 `verify-<agent>-<hash>`）绑定：source revision、
working tree digest、dirty state、configuration digest、feature set、target triple、
toolchain、harness schema version、platform capability digest、contract hash。
任何影响结论的输入变化 → 旧 Evidence **STALE**，不得作为完成证明。
Verdict ∈ `PASS | FAIL | STALE | UNKNOWN | BLOCKED`，最终 Verdict 只能由 Harness/Verifier 产生；
Agent 只能声明 **Candidate Completion**。

## 5. 标准开发循环（Contract-First）

```text
Task → nexus-harness status → nexus-harness context <target>
  → 读最小 Product / Module Contract / Tests → 修改
  → nexus-harness check → nexus-harness test affected → 修复
  → nexus-harness verify --fast
  → 独立 Review（§6）
  → Candidate Completion → nexus-harness verify --full → Evidence + Verdict
```

新 Feature / 需求变化必须分两阶段：

1. **Contract Phase**：改 `PRODUCT.md` / `MODULE.md` → 新增/修改 `scenarios/` →
   在旧实现上跑出 FAIL/BLOCKED **Red Evidence** → 冻结 expectation，生成 Contract Hash。
2. **Implementation Phase**：冻结 expectation 进入 Protected（`scenarios/**/expectations`、
   `PRODUCT.md#frozen`、`crates/**/MODULE.md#frozen-invariants`）；实现只能让 Scenario 变绿，
   不得改 expected value；契约有误则退出实现、走 `requirement-change` 重建 Red Evidence。

任务类型（commit subject 的 `<type>` 必须取自其一）：
`feature | bugfix | refactor | test | docs | performance | dependency | requirement-change`。
`refactor` 的 Scenario expectation 默认不可改；`requirement-change` 是唯一允许主动改冻结期望的类型
（改后旧 Evidence 自动 STALE）。

## 6. 独立 Review（[AGENTS.md §19.1](../../AGENTS.md)）

fast verify 通过后、full verify 之前，由**独立于实现的执行者**做八维度审查
（契约一致性 / 边界覆盖 / API 面控制 / 依赖边界 / 错误处理质量 / 测试质量 / 复杂度控制 / 可观测性）。
Verdict：`APPROVED`（可进 full verify）/ `COMMENTED`（记录在案）/
`CHANGES_REQUESTED`（修完重走 fast verify + 再评审，默认上限 3 轮）/ `BLOCKED`（契约冲突）。
产物：`.evidence/review-<scope>-<agent>-r<n>/summary.json` + `findings.md`，须引用上一轮 ID 并记录维度变化。

## 7. 受影响分析与 Code Intelligence

Affected Analysis：`changed files → owning crates → reverse dependencies → mapped tests/scenarios →
affected verification set`（Cargo metadata + 显式 mapping，不做全程序猜测）。
`nexus-harness code callers/callees` 的语义调用图只是增量信号，不是影响集的真相来源；
结果带 snapshot（source_revision + working_tree_digest），工作树变了返回 `SNAPSHOT_STALE`；
provider 不可用返回 `BLOCKED` 而非空结果。Code Intelligence 只属 `engineering/`，
生产 crate 不得依赖 rust-analyzer/LSP，`code` 无任何写能力。

## 8. Git 门禁（.githooks）

安装：`git config core.hooksPath .githooks`（或 `.githooks/install.sh` / `install.ps1`）。
机器可读声明见 [harness.toml `[hooks]`](../../harness.toml)：

```text
pre-commit   whitespace 检查；暂存含 .rs 时 cargo fmt --check；受保护路径变更告警
commit-msg   subject 必须为 <type>(<scope>): <summary>；受保护路径变更正文必须携带
             contract: <hash> 或 requirement-change: <hash>（marker 正则见 harness.toml）
pre-push     nexus-harness verify --fast 不得 FAIL/BLOCKED；STALE Evidence 阻止推送；
             推送区间修改受保护契约路径必须带 contract marker
```

受保护路径：`PRODUCT.md`、`ARCHITECTURE.md`、`policies/`、`scenarios/`、`harness.toml`、`**/MODULE.md`。
`--no-verify` 可绕过但不产生任何证据，仍不得声明 Final PASS。

## 9. 分支、提交与推送

Trunk-Based（[AGENTS.md §30](../../AGENTS.md)）：`master` 唯一长期分支；
任务分支 `task/<run-id>-<slug>`，经 PR 由 coordinator 串行 squash-merge，合并后删除分支。
**禁止直推 `master`**（当前以 pre-push 门禁 + mirror pre-receive 代替 GitHub branch protection）。

推送前固定执行 `./nexus-sync.sh` / `nexus-sync.ps1`：

```sh
git fetch origin
git rebase origin/master        # 线性历史，冲突在此显式解决
nexus-harness verify --fast     # 在最新 base 上生成绑定当前 revision 的证据
git push origin $(git branch --show-current)   # 只推任务分支
```

## 10. 多 Agent 并行（摘要）

- `export NEXUS_AGENT=<name>`（`[A-Za-z0-9_-]`，≤32，并发不撞名）：
  证据目录 `verify-<agent>-*` / `review-<scope>-<agent>-r<n>`，STALE 标记只作用于同 agent。
- 推荐 worktree 模式：每 Agent 一个 worktree + 独立分支 + 独立 `CARGO_TARGET_DIR` + 独立 PAT；
  汇合点只有 `nexus-sync`。
- crate 归属域划分见 [AGENTS.md §29.1](../../AGENTS.md)（默认分工建议，非权限约束）。

## 11. 项目级 Agent Skills 与知识库

- [.agents/skills/](../../.agents/skills/README.md)：`nexus-task`、`nexus-contract-first`、
  `nexus-evidence`、`nexus-review`、`nexus-knowledge`、`nexus-multiagent`、`nexus-selfrepair`、
  `nexus-test-review`（索引见 `harness.toml [skills]`）。任务开始时按匹配读取对应 `SKILL.md`。
- [.agents/knowledge/](../../.agents/knowledge/)：踩坑/模式/决策条目（§19.2），任务前检索、踩坑后写入。

## 12. 已知环境注意事项（结论口径）

来自 [DEVELOPMENT.md §11.1](../../DEVELOPMENT.md)，**在把门禁结果当结论前必须知道**：

- 作为**结论**的门禁（`cargo test -p nexus-harness`、`verify --fast --json`、Contract Hash）
  应在 Linux 主机或 `core.autocrlf=false` 的工作树跑；WSL 用户态只可用于开发试跑。
- `* text=auto` 会让 checkout 文件变 CRLF，导致按工作树字节计算的 `contract_hash` /
  `configuration_digest` 与仓库 LF 内容不一致；契约身份应按已提交 blob 计算的口径修正
  尚属待办（门禁契约变更，需独立走 Contract-First）。
- Windows 上 `echo` fixture 场景与部分 harness 单测为环境假红，与产品代码无关。
- `verify --fast` 在 `cargo-deny` 缺失时依赖治理记 UNKNOWN，PASS 不代表该 gate 真跑过。

## 13. 常见任务速查

| 我想… | 用 |
|---|---|
| 了解某个 crate 负责什么 | `nexus-harness context <crate>` 或读 `crates/<crate>/MODULE.md` |
| 看仓库整体状态 | `nexus-harness status --json` |
| 改代码后自查 | `nexus-harness check` → `test affected` → `verify --fast` |
| 定位符号/调用关系 | `nexus-harness code symbol|definition|references|callers` |
| 加新 Feature | 先 Contract Phase（改契约 + scenarios + Red Evidence），再实现（§5） |
| 排查 gate 失败 | `nexus-harness explain --json`，先归因再改（[AGENTS.md §24](../../AGENTS.md)） |
| 提交/推送 | commit subject 带任务类型；受保护路径带 `contract:` marker；`nexus-sync` |
