# nexus-harness Module Contract

## Responsibility

提供 Agent/Human/CI 共享的 Project Discovery、Context、Affected Analysis、Command Execution、Policy Evaluation、Evidence Writing、Failure Explanation 与 Replay Coordination。

CLI 命令契约（与 `harness.toml [commands]` 一致）：

```text
status            仓库状态 + 最新 Evidence 新鲜度（含 STALE 语义）
context <target>  目标模块契约要点与映射的 tests/scenarios
check             本地静态门禁（format/check/clippy/whitespace）
test affected     变更影响集测试
verify --fast     快速门禁 + 写入 Evidence
verify --full     全量门禁 + 写入 Evidence
explain           解释最近一次 gate 失败
bench             UNKNOWN（MVP 未实现，显式报告）
replay            UNKNOWN（MVP 未实现，显式报告）
code <verb>       语义代码查询（只读；见下方 Code Intelligence Contract）
```

## Code Intelligence Contract

CLI 形态（`--json` 输出沿用核心四字段 + 扩展字段）：

```text
nexus-harness code symbol <name> [options]
nexus-harness code definition <location-or-symbol> [options]
nexus-harness code references <location-or-symbol> [options]
nexus-harness code implementations <location-or-symbol> [options]
nexus-harness code callers <location-or-symbol> [options]
nexus-harness code callees <location-or-symbol> [options]
nexus-harness code hover <location> [options]
nexus-harness code diagnostics [target] [options]
```

`location` 为 `<path>:<line>:<column>`，**行列均为 1-based**（内部按 LSP 0-based
转换）；`<symbol>` 形态经 `workspace/symbol` 解析，若同名匹配多于一个则
返回 `FAIL` + `error.code = QUERY_INVALID` 并列出候选，不做静默挑选。

options（全部可选，缺省即预算默认值）：

```text
--workspace <path>            查询根（相对仓库根解析）；缺省为仓库根
--max-results <n>             缺省 20
--max-snippet-lines <n>       缺省 8
--max-result-bytes <n>        缺省 65536
--timeout-secs <n>            单请求超时，缺省 20
--ready-timeout-secs <n>      provider 就绪等待上限，缺省 90
--provider-binary <name|path> 覆盖 language server 可执行文件（仅用于失败路径验证）
```

扩展字段（`code` 各命令统一；**字段可得性**按下述规则，不装作永远齐全）：

- `command` / `authority` / `error`（失败时）永远存在。
- `snapshot` 一旦完成仓库发现就存在（含 verb 不认识、参数非法等 provider 启动前的失败）；不在 git 仓库内时以 `WORKSPACE_UNRESOLVED` 上报。
- `budget` 在 options 解析成功后存在；`provider` 只在 language server 被解析到之后存在。
- `results` / `count` 恒存在，失败时为 `[]` / `0`——失败**绝不**表现为"空结果 + PASS"。

```text
results            语言中立结果数组（symbol/kind/kind_id/qualified_name/path/in_scope/range/snippet）
count              截断前的完整命中数
budget             {max_results,max_snippet_lines,max_result_bytes,workspace_scope,truncated}
continuation       截断时 {refinement_hint}（未截断则省略）
provider           {kind,binary,version,ready,restart_count,restart_reason,
                      duration_ms,write_requests_refused,server_requests_unhandled,
                      dropped_notifications}
                   kind 是适配器标识，binary 是实际解析到的可执行文件（两者可对照
                   发现错配）；三类计数彼此分离，"未识别请求"不得污染写拒绝计数
snapshot           {source_revision,working_tree_digest,target_triple,toolchain_version,workspace_root}
authority          恒为 "advisory"：Code Intelligence 不拥有最终 PASS
error              失败时 {code,reason}
```

`kind` 是 provider 声明的 LSP `SymbolKind` 对应字符串，`kind_id` 是该数值原文
（0 = provider 未给出）。两者都给是因为 rust-analyzer 对 trait/impl 方法有时
上报 `property`(6) 或 `variable`(12) 而非 `method`(5)：只给字符串会误导 Agent，
而 harness 不擅自纠正 language server 的语义声明，交由调用方判断。

错误码（提案 §12 冻结）：

```text
PROVIDER_UNAVAILABLE WORKSPACE_UNRESOLVED INITIALIZATION_FAILED QUERY_INVALID
SYMBOL_NOT_FOUND RESULT_TRUNCATED TIMEOUT PROVIDER_CRASHED SNAPSHOT_STALE UNSUPPORTED
```

码表使用现状（如实记录，避免"目录里有、实现里没有"）：

- `RESULT_TRUNCATED` 是**契约预留**：首期截断通过 `budget.truncated = true` +
  `continuation.refinement_hint` 表达，不作为终态码，因此当前无构造点。
- 其余九码均有构造点；`TIMEOUT` 同时承载"请求超时"与"就绪预算耗尽导致空结果
  不可信"两种情形（后者在 `reason` 里写明），以便调用方区分"重启无望"
  （`INITIALIZATION_FAILED`）与"加大预算可救"（`TIMEOUT`）。
- 结果条目的 `in_scope` 表达作用域：查询**目标**越出 `--workspace` 直接
  `QUERY_INVALID`；**结果**越界（例如 callee 落到标准库源码）不删除、只标
  `in_scope = false`，因为删掉就等于静默丢弃（提案 §5 禁止）。

## Non-Responsibilities

不拥有产品真相；不重写 Cargo/Git/Test/Tracing/Benchmark；不被 production crate 依赖；不直接修改业务代码；不生成或修改 `scenarios/`、`policies/` 契约内容（只执行与验证）。

## Inputs

- 仅接受公开类型、DTO、trait、事件或稳定协议对象。
- 输入必须可被结构化验证；不得依赖未声明的全局隐式状态。
- 机器模式输入输出必须是版本化 JSON。

## Outputs

- 结构化 Result / Event / DTO。
- 失败必须保留可诊断原因，不以日志文本代替错误类型。
- `--json` 输出必须包含 `schema_version` / `command` / `verdict` / `message` 四个核心字段，可按命令扩展附加字段。

## Allowed Dependencies

- 第三方（均 `default-features = false`，只开所需 feature）：
  - `serde_json`（feature `std`）：结构化 JSON 输出与 Evidence 读写；
  - `toml`（feature `parse`）：解析 `harness.toml` 与 `policies/*.toml`。
- 外部进程（只读/执行，不解析 ANSI 输出）：`git`（revision、tree digest、hash-object 计算摘要）、`cargo`（fmt/check/clippy/test）、`rustc`（toolchain/target 信息）、`rust-analyzer`（Code Intelligence 只读语义查询；经手写 JSON-RPC framing 通信，不使用第三方 LSP 库）。
- 摘要计算复用 `git hash-object`，避免引入密码学依赖（git 是 harness 的硬前置）。
- `rust-analyzer` 可执行文件解析顺序：`NEXUS_RUST_ANALYZER` → `PATH` → 无；三者皆失败即返回 `BLOCKED` + `PROVIDER_UNAVAILABLE`，不得伪造空结果。

## Forbidden Dependencies

- 无 Nexus 内部依赖。
- `engineering/` 下的 Harness/Plugin。
- 未在 `policies/architecture.toml` 声明的 Nexus 内部 crate。
- Portable 模块中的平台专有 Framework/API。
- 通过“便利”依赖绕过公开领域边界。

## Invariants

- 机器模式输出必须是版本化 JSON。
- Agent claim 不能产生最终 PASS。
- Gate 失败必须显式 FAIL/BLOCKED/UNKNOWN，不能静默降级。
- Local Harness 与 CI 使用同一 Gate 定义（`policies/quality.toml`）。
- Evidence 必须绑定 revision / working-tree / config / feature / target / toolchain / platform，并写入 `.evidence/verify-<id>/`。
- verdict 语义：`PASS / FAIL / STALE / UNKNOWN / BLOCKED`；STALE 证据必须以 `"verdict":"STALE"` 形式落盘，供 `.githooks/pre-push` 检出。
- 未实现的 gate（bench/replay/coverage 等）必须显式记录 UNKNOWN，不得以 PASS 掩盖。
- Code Intelligence 只读不变量：客户端只允许发送白名单内的 LSP 方法（`workspace/symbol`、`textDocument/{documentSymbol,hover,definition,typeDefinition,implementation,references,prepareCallHierarchy,diagnostic}`（`typeDefinition` 为白名单预留，首期无 CLI verb 调用点：提案 §4 的 Agent-facing 列表本身不含 type-definition，故不视为未兑现，但不得假装已经暴露给 Agent）、`callHierarchy/{incomingCalls,outgoingCalls}`）；`rename`、`workspace/applyEdit`、`codeAction` 自动应用、`workspace/willSaveWaitUntil`、格式化写入、任意 `workspace/executeCommand` 一律拒绝并返回 `UNSUPPORTED`。
- provider 子进程 command/args 不接受模型或调用方拼接的任意 shell 参数（`--provider-binary` 只接受单个可执行文件名或路径，按 `split_whitespace` 之前的整串传入，不经 shell）。
- `request()` 在返回匹配响应**之前**必须先 `pump_server_requests()` 一次：language server 会阻塞等待其对 server→client 请求的应答，悬置请求既会卡住 provider，也会让 `write_requests_refused` 在观测时刻还没入账（计数失真等于把拒绝能力藏起来）。
- 只读边界是**可端到端验证的**：`LspSession` 的传输端点被抽象（`child: Option<Child>` + `stdin: Box<dyn Write + Send>`），生产路径只由 `spawn()` 填入真实子进程；`#[cfg(test)] LspSession::for_tests()` 用内存流接一个假 server，走的是与真进程完全相同的 `dispatch_stream` 分流与应答逻辑。修改任何写能力拒绝路径必须让 `code_intel::lsp::tests::adversarial_server_pushed_apply_edit_is_refused_and_never_written` 保持绿色（该测试断言目标文件**不存在**）。
- `code` 结果必须绑定 `snapshot`（source_revision + working_tree_digest + target + toolchain + workspace root）；查询完成前后 digest 不一致时返回 `SNAPSHOT_STALE`。
- 命中超过预算时必须 `budget.truncated = true` 并给出 `continuation.refinement_hint`；禁止静默丢弃结果后宣称完整。字节预算与条数预算同等生效：单条结果自身超过 `max_result_bytes` 时保留它但仍置 `truncated = true`。
- Code Intelligence 的时间语义属契约面（不是实现细节）：rust-analyzer 的 workspace 加载是多阶段的，就绪只认"`\$/progress` begin/end 收敛且静默 ≥ 1.5s"（`Completed`）。**只有 `Completed` 允许把空结果当作答案**；server 从不上报进度的静默、以及预算耗尽，两者下的空结果一律 `BLOCKED` + `error.code = TIMEOUT`、`provider.ready = false`。把"还没索引完"说成"确实没有引用"即提案 §12 禁止的伪 PASS。didOpen 后另有 15s 空结果重试窗口（文件级分析需要时间）。
- provider 的构建副作用：rust-analyzer 在 didOpen 后默认跑 flycheck（`cargo check`）；其产物经 `CARGO_TARGET_DIR=<temp>/nexus-code-intel-<workspace 哈希>` 重定向到**仓库外**，被查 workspace 内不留构建产物。不改业务源码，但确有磁盘写入，故在此披露。
- 数值型选项（`--max-results` / `--max-snippet-lines` / `--max-result-bytes` / `--timeout-secs` / `--ready-timeout-secs`）必须 ≥ 1，0 属退化输入 → `QUERY_INVALID`。
- `provider.kind` 是适配器标识、`provider.binary` 是实际解析到的可执行文件，两者分开以便发现错配；`write_requests_refused`（applyEdit/executeCommand 拒绝）与 `server_requests_unhandled`（未识别请求）、`dropped_notifications`（缓冲溢出丢弃）三个计数彼此独立，不得合并。
- `code` 永远不产出最终 PASS：`authority` 恒为 `"advisory"`，correctness 仍由 `cargo check/clippy/test` 与 verify Evidence 决定。

## Side Effects

- 允许：写入 `.evidence/verify-<id>/`（Evidence）；运行只读验证命令（cargo/git）；输出状态；为 Code Intelligence 启动长期本地子进程 `rust-analyzer`（工作目录限制在仓库/worktree 内，每请求有 timeout/cancellation，stdout 有单帧 64MiB + 单会话累计 256MiB 上限、stderr 有 64KiB 环形上限（超限即按崩溃处理，不静默截断后继续）；crash 最多重启一次且必须记入 `provider.restart_count` 与 `provider.restart_reason`，命令结束时发送 `shutdown`/`exit`）。
- 禁止：修改业务代码；修改 `scenarios/` 或 `policies/` 内容；执行网络操作；修改 git index/HEAD。
- 新增副作用前必须更新本契约和 Scenario/Policy（如影响外部行为）。

## Public API

- CLI 命令与 `--json` 输出为本模块 Public API，保持版本化与向后兼容。
- 默认最小 surface：`private -> pub(crate) -> pub`。

## Verification

最低：

```text
cargo check -p nexus-harness
cargo clippy -p nexus-harness --all-targets -- -D warnings
cargo test -p nexus-harness
nexus-harness verify --fast --json   # 自举验证
```

场景（E4，机器可执行）：`scenarios/engineering/harness_verify_fast_evidence.toml`、`scenarios/engineering/harness_status_verdicts.toml`。

Code Intelligence 场景（E4，冻结于 2026-10-10 契约阶段，夹具为
`engineering/nexus-harness/fixtures/code-intel`）：
`code_intelligence_symbol.toml`、`code_intelligence_implementations.toml`、
`code_intelligence_definition.toml`、`code_intelligence_callers.toml`、
`code_intelligence_hover.toml`、`code_intelligence_diagnostics_advisory.toml`、
`code_intelligence_budget_truncation.toml`、`code_intelligence_provider_unavailable.toml`、
`code_intelligence_write_method_denied.toml`、`code_intelligence_callees.toml`、
`code_intelligence_scope_violation.toml`、`code_intelligence_read_only_counters.toml`、
`code_intelligence_budget_count.toml`。

### Gate 实现状态（2026-09-15）

`verify --full` 按 `policies/quality.toml [verification.full]` 声明执行；gate 语义统一为：**有可验证内容则真实执行，工具缺失或无可验证内容则显式 UNKNOWN 并给出原因，不静默 PASS**。

- 真实执行：workspace-tests / product-scenarios / regression / architecture-policy / dependency-governance（cargo-deny 0.20：`cargo deny --config policies/deny.toml check advisories licenses bans sources`，缺失则 UNKNOWN）/ coverage-summary（cargo-llvm-cov）/ platform-checks（portable-core 平台依赖静态扫描）/ feature-matrix（每成员 `--no-default-features` + `--all-features`）/ portable-core（`cargo check --target wasm32-wasip1`）。
- 条件执行（无内容/无工具时 UNKNOWN）：integration（成员 tests/*.rs 存在时逐个运行）/ selected-fuzz（cargo-fuzz + fuzz targets）/ selected-concurrency（tests/concurrency 有测试时运行）/ performance-budgets（quality.toml `[performance]` 定义 baseline+blocking 后判定）。
- 单元测试：`cargo test -p nexus-harness`（100 个 = 既有 56 + Code Intelligence 44；覆盖 scenario 求值、evidence 新鲜度/STALE、digest 确定性、workspace 成员解析、dependency-governance gate 语义，以及 JSON-RPC framing、只读白名单、URI 往返、DTO 形状与预算截断、progress 收敛判定、provider 参数校验、**假 server 主动推 `workspace/applyEdit` 的端到端拒绝**）。
  - Windows 宿主已知 4 个与本模块能力无关的预存在失败：3 个 scenario 测试把 `sh`/`echo` 当 shell 内建使用（Windows 下按可执行文件解析），1 个 `gates` 的 §12.58 contract-hash 测试受 `text=auto` 的 CRLF 检出影响；两者均非 Code Intelligence 引入。

## Performance Budget

`verify --fast` 应单次运行可在合理时间内完成并报告；未定义严格预算前不得宣称“性能完成”。进入 hot path 后必须补充 baseline / noise tolerance / warning / blocking 阈值。

## Observability

稳定结构化字段优先于自由文本；机器模式输出含 `schema_version` 与 `verdict`；失败保留 gate 名、命令与退出码。

## Recovery Semantics

Evidence 写入必须幂等：同一 `(revision, configuration_digest)` 重复 verify 覆盖同一 verify id，不产生孤儿状态；verify 中断不得破坏已有 `.evidence/`。

## Platform Constraints

平台专有代码只允许存在于 `nexus-platform-*` 或 Composition Root。本模块只依赖 git/cargo/rustc 标准工具链；不作为 portable crate（位于 `engineering/`，非 `[portable_core]` 列表成员）。
