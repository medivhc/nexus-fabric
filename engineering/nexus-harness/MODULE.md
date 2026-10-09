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

扩展字段（`code` 全部命令统一）：

```text
results            语言中立结果数组（symbol/kind/kind_id/qualified_name/path/range/snippet）
count              截断前的完整命中数
budget             {max_results,max_snippet_lines,max_result_bytes,workspace_scope,truncated}
continuation       截断时 {refinement_hint}（未截断则省略）
provider           {kind,version,ready,restart_count,duration_ms}
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
- Code Intelligence 只读不变量：客户端只允许发送白名单内的 LSP 方法（`workspace/symbol`、`textDocument/{documentSymbol,hover,definition,typeDefinition,implementation,references,prepareCallHierarchy,diagnostic}`、`callHierarchy/{incomingCalls,outgoingCalls}`）；`rename`、`workspace/applyEdit`、`codeAction` 自动应用、`workspace/willSaveWaitUntil`、格式化写入、任意 `workspace/executeCommand` 一律拒绝并返回 `UNSUPPORTED`。
- provider 子进程 command/args 不接受模型或调用方拼接的任意 shell 参数（`--provider-binary` 只接受单个可执行文件名或路径，按 `split_whitespace` 之前的整串传入，不经 shell）。
- `code` 结果必须绑定 `snapshot`（source_revision + working_tree_digest + target + toolchain + workspace root）；查询完成前后 digest 不一致时返回 `SNAPSHOT_STALE`。
- 命中超过预算时必须 `budget.truncated = true` 并给出 `continuation.refinement_hint`；禁止静默丢弃结果后宣称完整。
- `code` 永远不产出最终 PASS：`authority` 恒为 `"advisory"`，correctness 仍由 `cargo check/clippy/test` 与 verify Evidence 决定。

## Side Effects

- 允许：写入 `.evidence/verify-<id>/`（Evidence）；运行只读验证命令（cargo/git）；输出状态；为 Code Intelligence 启动长期本地子进程 `rust-analyzer`（工作目录限制在仓库/worktree 内，每请求有 timeout/cancellation，stdout/stderr 有大小上限，crash 最多重启一次且必须记入 `provider.restart_count`，命令结束时发送 `shutdown`/`exit`）。
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
`code_intelligence_write_method_denied.toml`。

### Gate 实现状态（2026-09-15）

`verify --full` 按 `policies/quality.toml [verification.full]` 声明执行；gate 语义统一为：**有可验证内容则真实执行，工具缺失或无可验证内容则显式 UNKNOWN 并给出原因，不静默 PASS**。

- 真实执行：workspace-tests / product-scenarios / regression / architecture-policy / dependency-governance（cargo-deny 0.20：`cargo deny --config policies/deny.toml check advisories licenses bans sources`，缺失则 UNKNOWN）/ coverage-summary（cargo-llvm-cov）/ platform-checks（portable-core 平台依赖静态扫描）/ feature-matrix（每成员 `--no-default-features` + `--all-features`）/ portable-core（`cargo check --target wasm32-wasip1`）。
- 条件执行（无内容/无工具时 UNKNOWN）：integration（成员 tests/*.rs 存在时逐个运行）/ selected-fuzz（cargo-fuzz + fuzz targets）/ selected-concurrency（tests/concurrency 有测试时运行）/ performance-budgets（quality.toml `[performance]` 定义 baseline+blocking 后判定）。
- 单元测试：`cargo test -p nexus-harness`（98 个 = 既有 56 + Code Intelligence 42；覆盖 scenario 求值、evidence 新鲜度/STALE、digest 确定性、workspace 成员解析、dependency-governance gate 语义，以及 JSON-RPC framing、只读白名单、URI 往返、DTO 形状与预算截断、progress 收敛判定、provider 参数校验）。
  - Windows 宿主已知 4 个与本模块能力无关的预存在失败：3 个 scenario 测试把 `sh`/`echo` 当 shell 内建使用（Windows 下按可执行文件解析），1 个 `gates` 的 §12.58 contract-hash 测试受 `text=auto` 的 CRLF 检出影响；两者均非 Code Intelligence 引入。

## Performance Budget

`verify --fast` 应单次运行可在合理时间内完成并报告；未定义严格预算前不得宣称“性能完成”。进入 hot path 后必须补充 baseline / noise tolerance / warning / blocking 阈值。

## Observability

稳定结构化字段优先于自由文本；机器模式输出含 `schema_version` 与 `verdict`；失败保留 gate 名、命令与退出码。

## Recovery Semantics

Evidence 写入必须幂等：同一 `(revision, configuration_digest)` 重复 verify 覆盖同一 verify id，不产生孤儿状态；verify 中断不得破坏已有 `.evidence/`。

## Platform Constraints

平台专有代码只允许存在于 `nexus-platform-*` 或 Composition Root。本模块只依赖 git/cargo/rustc 标准工具链；不作为 portable crate（位于 `engineering/`，非 `[portable_core]` 列表成员）。
