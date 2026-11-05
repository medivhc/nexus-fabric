# 05 · 运行方式与开发流程（Running & Development）

> 依据：[README.md](../../README.md)、[DEVELOPMENT.md](../../DEVELOPMENT.md)、
> [AGENTS.md](../../AGENTS.md)、[harness.toml](../../harness.toml)、[DEV-ENV.md](../../DEV-ENV.md)、
> `apps/*/MODULE.md`、[engineering/nexus-harness/MODULE.md](../../engineering/nexus-harness/MODULE.md)。
> 本文是导航性派生文档；命令语义以契约为准。

## 1. 构建

Rust workspace（[Cargo.toml](../../Cargo.toml)，52 个成员：48 `crates/*` + 3 `apps/*` + `engineering/nexus-harness`）。
workspace 统一 edition 2024 / rust-version 1.85 / profile（[DEV-ENV.md](../../DEV-ENV.md) 是工具链版本唯一真值：
stable 1.98.1 / nightly 1.100.0-nightly / cargo-deny 0.20.2 / cargo-llvm-cov 0.9.1 / wasm32-wasip1 target）。

```sh
cargo build --workspace                 # 全量构建
cargo build -p nexus                    # CLI 瘦客户端
cargo build -p nexusd                   # daemon
cargo check --workspace --all-targets   # Fast Gate 的 check 项
```

产出三个可执行文件：

| 二进制 | crate | 角色 |
|---|---|---|
| `nexus` | [apps/nexus](../../apps/nexus/MODULE.md) | 控制面 CLI 瘦客户端 + SDK 组合根 |
| `nexusd` | [apps/nexusd](../../apps/nexusd/MODULE.md) | 常驻 daemon（LocalAPI + 数据面装配） |
| `nexus-platform-host` | [apps/nexus-platform-host](../../apps/nexus-platform-host/MODULE.md) | 平台宿主（`vpi-capabilities`） |

## 2. 运行 Nexus（产品运行时）

### 2.1 daemon：`nexusd <config-folder>`

```sh
nexusd /etc/nexus/
```

唯一参数是配置文件夹，**缺失 = 不启用**（[main.rs](../../apps/nexusd/src/main.rs)）：

| 文件 | 作用 | 缺失/变更语义 |
|---|---|---|
| `daemon.toml` | LocalAPI 地址、PID、日志 + `[tun]`（mtu ∈[1280,9000]）+ `[qos]`（CAKE-like）+ `[network.turn]`（TURN+STUN）+ `[network.proxy]` | 全默认；`localapi_addr`/`[qos]`/`[tun]`/`[network.turn]` 变更 → NeedsRestart |
| `network.toml` | N1 mesh（含 `[vpi.routes]`、`[boost]`） | 不启用 mesh；变更 → NeedsRestart |
| `proxy.yaml` | Clash 风格代理（TUN 出站经代理） | 不启用；变更 → **Hot 热加载** |
| `dns.toml` | 统一 DNS（`DnsUnifiedConfig`） | 不启用；变更 → Hot |
| `workspace.toml` | `[[workspace]]` → FUSE 挂载（Linux） | 不启用（无 /dev/fuse 显式禁用） |

配置 2 秒内热生效、校验失败拒绝应用不 crash；缺 proxy.yaml 且缺 network.toml → 拒绝启动（exit 1）。
兼容入口：`nexusd serve`（仅 LocalAPI）、`nexusd task-provider ...`。

LocalAPI：bearer token（`~/.config/nexus/localapi.token`，0600，常量时间比较 fail-closed）；
默认 unix socket `$XDG_RUNTIME_DIR/nexus-localapi.sock`，`--addr` 切 TCP loopback。
GET 路由 `/localapi/v0/{status,dataplane/stats,dns/*,session/watch,n2/session/*,plan/explain,connectivity/status,platform/capabilities,workspace/*}`；
POST `/localapi/v1/{task,snapshot}`（N3）。

### 2.2 CLI：`nexus [--json] [--addr <ip:port>] <command>`

瘦客户端经 LocalAPI 与 daemon 通信；**观察命令**需先起 `nexusd`；daemon 不可达输出
`DAEMON_UNREACHABLE` FAIL JSON（exit 0）。exit 语义：0=业务结果（含 FAIL）、2=用法错误。
完整命令族（[main.rs](../../apps/nexus/src/main.rs) `USAGE` 常量）：

```text
观察类（需 daemon）：
  status / plan <resource> / plan explain <resource|session-id>
  use <resource>                      N2 四步闭环（resolve→plan→authorize→establish）
  session list|watch <id>|close <id> / resource list|show|publish|revoke
  connectivity status|candidates|probe <target>|links
  dns status|resolve <name>|providers|cache
  workspace heads|conflicts|cache|commit <workspace>
  snapshot freeze|upload|status|cancel  N3-12 离线冻结与认证 staging
  task submit|show|cancel|logs|artifacts / artifact get
  task-provider grant list|add|revoke  本地 Use 授权运维
  compute jobs / diagnose / platform capabilities

进程内 SDK 直跑（不经 daemon）：
  run <resource>       远程资源访问（`run -- <cmd>` 为 N3 语义，N2 诚实拒绝）
  network up|status    N1 装配前台运行（建 TUN→dial→包泵，Ctrl-C 退出）
  subnet up|status|leave|punch        虚拟子网（PRODUCT §12）
  schedule at|every|list|cancel|tick   计划任务（PRODUCT §14）
  proxy [--addr] [--config] [--tun] / speedtest / bufferbloat-test / run|host|relay
  system-proxy <status|set|clear|e2e> / autostart <install|remove|status>
  pair invite|join|list|remove --dir <config-dir>
  node init / node trust --provider <id> --pubkey <hex>
```

## 3. 工程运行方式：nexus-harness

`engineering/nexus-harness` 是工程入口（固定命令与 JSON schema；声明见
[harness.toml `[commands]`](../../harness.toml)）。机器模式统一 `--json`。
**实际命令面 13 个**（AGENTS.md §3 摘要仅列 7 个，以实现为准）：

| 命令 | 语义 |
|---|---|
| `status` | 仓库状态 + 最新 Evidence 新鲜度（含 STALE） |
| `context <target>` | 模块契约要点 + 映射 tests/scenarios + 语义锚点 |
| `check` | 本地静态门禁（format/check/clippy/whitespace） |
| `test affected` | 变更影响集测试（Cargo metadata + 显式 mapping） |
| `verify --fast / --full` | 按 `policies/quality.toml` gate 执行并写 Evidence |
| `explain` | 解释最近一次 gate 失败 |
| `bench` | 跑 `perf_bench` example 按性能预算判 verdict（**已实现**） |
| `replay` | **仍为 UNKNOWN**（MVP 未实现，显式报告不静默 PASS） |
| `scenario list / run <name>` | 场景包机器接口（[CONTRACT-scenario-pack.md](../../CONTRACT-scenario-pack.md) 冻结） |
| `run <flow>` | 12 个 E4 产品流驱动（virtual-subnet/mesh/nat-hole-punching/…） |
| `code <verb>` | 8 个只读语义查询（symbol/definition/references/implementations/callers/callees/hover/diagnostics） |
| `mcp serve / selftest` | MCP stdio 薄适配（8 个只读工具，零写能力） |
| `daemon start/stop/status/selftest` | provider daemon（code intelligence 后端） |

**⚠ 文档-实现漂移**：harness MODULE.md 顶部命令表仍写 `bench` 为 "UNKNOWN（MVP 未实现）"，
但实现（`gates::bench_gate`）、quality.toml full gate 与 `scenarios/engineering/bench_gate_verdicts.toml`
均已就位——引用时以实现+场景为准；`replay` 的 UNKNOWN 是真。

## 4. 测试与验证

### 4.1 Fast / Full Gate（[policies/quality.toml](../../policies/quality.toml)）

```text
Fast（8 gates）：format · check · clippy -D warnings · architecture-delta ·
  dependency-delta · resource-type-neutrality · affected-tests · selected-properties

Full（14 gates）：workspace-tests · integration · product-scenarios · regression ·
  architecture-policy · dependency-governance · coverage-summary · selected-fuzz ·
  selected-concurrency · performance-budgets · bench · platform-checks ·
  feature-matrix · portable-core
```

禁止通过削弱 gate 解决失败。Fast 后必须过**独立 Review**（§5）才进 Full。
口径注意：`verify --fast` 在 `cargo-deny` 缺失时 `dependency-governance` 记 UNKNOWN
而可能 overall PASS——引用 PASS 必须写明工具在场与否（[DEVELOPMENT.md §11.1](../../DEVELOPMENT.md)）。

### 4.2 测试分层

| 层 | 位置 | 强度 |
|---|---|---|
| 单元/局部行为 | 各 crate `src` 内 `#[cfg(test)]` + `tests/` | E2 |
| 跨 crate 集成/并发 | [tests/](../../tests/)（cancellation、shutdown、outcome race、crash recovery） | E3 |
| 产品级 Scenario | [scenarios/](../../scenarios/)：**314 个场景 .toml**（product 275 / engineering 29 / platform 8 / regression 2；`fixtures/` 另有 1 个夹具配置不计） | E4 |

关键用户可见 Capability 至少 **E4**（`harness.toml [evidence] minimum_user_visible_strength`）。

### 4.3 Evidence

`.evidence/verify-<agent>-<hash>/`（多 Agent 命名空间见 §8）绑定：source revision、
working tree digest、dirty state（三态，git 问不到写 `null` 不写 false）、configuration digest、
feature set、target triple、toolchain、harness schema version、platform capability digest、
contract hash。Schema 见 [engineering/evidence-schema/evidence.schema.json](../../engineering/evidence-schema/evidence.schema.json)。
任何影响结论的输入变化 → 旧 Evidence **STALE**（落 `"verdict":"STALE"` 墓碑供 pre-push 检出）。
Verdict ∈ `PASS | FAIL | STALE | UNKNOWN | BLOCKED`，最终 Verdict 只能由 Harness/Verifier 产生；
Agent 只能声明 **Candidate Completion**。

## 5. 标准开发循环与 Contract-First

```text
Task → nexus-harness status → nexus-harness context <target>
  → 读最小 Product / Module Contract / Tests → 修改
  → nexus-harness check → nexus-harness test affected → 修复
  → nexus-harness verify --fast → 独立 Review → Candidate Completion
  → nexus-harness verify --full → Evidence + Verdict
```

新 Feature / 需求变化分两阶段（[DEVELOPMENT.md §2](../../DEVELOPMENT.md)）：

1. **Contract Phase**：改 `PRODUCT.md`/`MODULE.md` → 新增/修改 `scenarios/` →
   在旧实现上跑出 FAIL/BLOCKED **Red Evidence** → 冻结 expectation + Contract Hash。
2. **Implementation Phase**：冻结 expectation 为 Protected（`scenarios/**/expectations`、
   `PRODUCT.md#frozen`、`crates/**/MODULE.md#frozen-invariants`）；实现只能让 Scenario 变绿，
   不得改 expected value；契约有误退出实现走 `requirement-change` 重建 Red Evidence。

任务类型（commit subject `<type>` 必须取自其一）：
`feature | bugfix | refactor | test | docs | performance | dependency | requirement-change`。

### 独立 Review（[AGENTS.md §19.1](../../AGENTS.md)）

fast verify 通过后、full verify 前，由**独立于实现的执行者**做八维度审查
（契约一致性/边界覆盖/API 面控制/依赖边界/错误处理/测试质量/复杂度控制/可观测性）。
Verdict：`APPROVED`（进 full）/ `COMMENTED`（记录）/ `CHANGES_REQUESTED`（修完重走，
默认上限 3 轮）/ `BLOCKED`（契约冲突）。产物 `.evidence/review-<scope>-<agent>-r<n>/`
（summary.json + findings.md），须引用上一轮 ID 并记录维度变化。

## 6. Code Intelligence（`nexus-harness code`）

语义查询优先于 grep（[DEVELOPMENT.md §9.1](../../DEVELOPMENT.md)）：LLM 提问、确定性程序分析
给事实。纪律：verdict 恒 `advisory`（最终 PASS 由 cargo + Harness 决定）；结果带 `snapshot`
（source_revision + working_tree_digest），工作树变了返回 `SNAPSHOT_STALE` 不得当事实；
provider 不可用返回 `BLOCKED` 不冒充"无引用"；结果超预算显式 `budget.truncated`；
**只读**（写能力 server 侧拒绝并计数）；只属 `engineering/`，生产 crate 不得依赖 LSP。
`code callers/callees` 只是受影响分析的增量信号，影响集仍由 Cargo metadata + 显式映射决定。

## 7. Git 门禁（.githooks）

安装：`git config core.hooksPath .githooks`（或 [.githooks/install.sh](../../.githooks/install.sh) / `install.ps1`）。
机器可读声明见 [harness.toml `[hooks]`](../../harness.toml)：

```text
pre-commit   whitespace 检查；暂存含 .rs 时 cargo fmt --check；受保护路径变更告警；
             crates/*.rs 变更要求 .evidence/review-* 的 summary.json
             verdict ∈ {APPROVED, COMMENTED}（Review Evidence 门禁）
commit-msg   subject 必须 <type>(<scope>): <summary>；拒绝占位摘要（wip/tmp/done…）；
             受保护路径变更正文必须携带 contract: <hash> 或 requirement-change: <hash>
pre-push     HEAD 含 .rs 变更时跑 nexus-harness verify --fast --json（FAIL/BLOCKED/UNKNOWN 全拦）；
             .evidence STALE 墓碑阻止推送；推送区间改受保护路径须带 contract marker；
             改 crates/*.rs 同样要求 Review Evidence
```

受保护路径：`PRODUCT.md | ARCHITECTURE.md | policies/ | scenarios/ | harness.toml | **/MODULE.md | DEV-ENV.md`。
`--no-verify` 可绕过但不产生证据，仍不得声明 Final PASS。
（`verify`/STALE/Review 检查在无 Rust 变更时跳过；多 Agent 下按 `NEXUS_AGENT` 限域。）

## 8. 分支、提交与推送

Trunk-Based（[AGENTS.md §30](../../AGENTS.md)）：`master` 唯一长期分支；任务分支
`task/<run-id>-<slug>`，经 PR 由 coordinator 串行 squash-merge，合并后删分支。
**禁止直推 `master`**（当前以 pre-push 门禁 + mirror pre-receive 代替 GitHub branch protection）。
提交规范见 [CONTRIBUTING.md](../../CONTRIBUTING.md)（subject ≤100 字符、祈使语气）。

推送前固定执行 [nexus-sync.sh](../../nexus-sync.sh) / `nexus-sync.ps1`：

```sh
git fetch origin
git rebase origin/master        # 线性历史，冲突在此显式解决
nexus-harness verify --fast     # 在最新 base 上生成绑定当前 revision 的证据
git push origin $(git branch --show-current)   # 只推任务分支
```

多 Agent 并行：`export NEXUS_AGENT=<name>`（证据目录 `verify-<agent>-*` /
`review-<scope>-<agent>-r<n>`，STALE 只作用于同 agent）；推荐每 Agent 一个 worktree +
独立 `CARGO_TARGET_DIR`（详见 AGENTS.md §29.5）。

## 9. 项目级 Agent Skills 与知识库

- [.agents/skills/](../../.agents/skills/README.md)（8 个）：`nexus-task`（标准开发循环）、
  `nexus-contract-first`、`nexus-review`（独立评审）、`nexus-knowledge`、`nexus-evidence`、
  `nexus-multiagent`、`nexus-test-review`、`nexus-selfrepair`（有界自修复 ≤3 轮）。
- [.agents/knowledge/](../../.agents/knowledge/)：103 个经验条目（踩坑/模式/决策），
  任务前检索、踩坑后写入（注意 `index.json` 索引落后于实际条目数）。

## 10. 已知环境注意事项（结论口径）

来自 [DEVELOPMENT.md §11.1](../../DEVELOPMENT.md) 与 AGENTS.md，**引用门禁结果前必须知道**：

- 作为**结论**的门禁（`cargo test -p nexus-harness`、`verify --fast --json`、Contract Hash）
  应在 Linux 主机（xc-pc-linux）或 `core.autocrlf=false` 工作树跑；Windows CRLF 会让
  `contract_hash`/部分 harness 单测假红；WSL 用户态只可开发试跑。
- 契约身份按已提交 blob 计算的口径修正仍是待办（门禁契约变更需独立 Contract-First）。
- 沙箱 UDP 被禁时 `verify --full` 只能在真机跑；Windows 上 `echo` fixture 场景为环境假红。
- `verify --fast` 在 cargo-deny 缺失时依赖治理记 UNKNOWN，PASS 不代表该 gate 真跑过。

## 11. 常见任务速查

| 我想… | 用 |
|---|---|
| 了解某个 crate 负责什么 | `nexus-harness context <crate>` 或读 `crates/<crate>/MODULE.md`（亦见 [02](02-module-responsibilities.md)） |
| 看仓库整体状态 | `nexus-harness status --json` |
| 改代码后自查 | `nexus-harness check` → `test affected` → `verify --fast` → 独立 Review |
| 定位符号/调用关系 | `nexus-harness code symbol\|definition\|references\|callers`（亦见 [03](03-key-types-and-functions.md)） |
| 核对能否加某依赖 | 先查 [04](04-dependencies.md) 与 `policies/architecture.toml` 闭集 |
| 加新 Feature | 先 Contract Phase（改契约 + scenarios + Red Evidence），再实现 |
| 排查 gate 失败 | `nexus-harness explain --json`，先归因（Implementation/Contract/Environment/Unsupported）再改 |
| 跑产品场景 | `nexus-harness scenario run <name> --json`（314 条清单 `scenario list`） |
| 提交/推送 | subject 带任务类型；受保护路径带 `contract:` marker；`nexus-sync` |
