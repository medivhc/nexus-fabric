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
- 外部进程（只读/执行，不解析 ANSI 输出）：`git`（revision、tree digest、hash-object 计算摘要）、`cargo`（fmt/check/clippy/test）、`rustc`（toolchain/target 信息）。
- 摘要计算复用 `git hash-object`，避免引入密码学依赖（git 是 harness 的硬前置）。

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

## Side Effects

- 允许：写入 `.evidence/verify-<id>/`（Evidence）；运行只读验证命令（cargo/git）；输出状态。
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

### Gate 实现状态（2026-09-15）

`verify --full` 按 `policies/quality.toml [verification.full]` 声明执行；gate 语义统一为：**有可验证内容则真实执行，工具缺失或无可验证内容则显式 UNKNOWN 并给出原因，不静默 PASS**。

- 真实执行：workspace-tests / product-scenarios / regression / architecture-policy / dependency-governance / coverage-summary（cargo-llvm-cov）/ platform-checks（portable-core 平台依赖静态扫描）/ feature-matrix（每成员 `--no-default-features` + `--all-features`）/ portable-core（`cargo check --target wasm32-wasip1`）。
- 条件执行（无内容/无工具时 UNKNOWN）：integration（成员 tests/*.rs 存在时逐个运行）/ selected-fuzz（cargo-fuzz + fuzz targets）/ selected-concurrency（tests/concurrency 有测试时运行）/ performance-budgets（quality.toml `[performance]` 定义 baseline+blocking 后判定）。
- 单元测试：`cargo test -p nexus-harness`（11 个，覆盖 scenario 求值、evidence 新鲜度/STALE、digest 确定性、workspace 成员解析）。

## Performance Budget

`verify --fast` 应单次运行可在合理时间内完成并报告；未定义严格预算前不得宣称“性能完成”。进入 hot path 后必须补充 baseline / noise tolerance / warning / blocking 阈值。

## Observability

稳定结构化字段优先于自由文本；机器模式输出含 `schema_version` 与 `verdict`；失败保留 gate 名、命令与退出码。

## Recovery Semantics

Evidence 写入必须幂等：同一 `(revision, configuration_digest)` 重复 verify 覆盖同一 verify id，不产生孤儿状态；verify 中断不得破坏已有 `.evidence/`。

## Platform Constraints

平台专有代码只允许存在于 `nexus-platform-*` 或 Composition Root。本模块只依赖 git/cargo/rustc 标准工具链；不作为 portable crate（位于 `engineering/`，非 `[portable_core]` 列表成员）。
