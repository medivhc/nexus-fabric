# Nexus Development Contract

## 1. 标准开发循环

```text
Task
 ↓
nexus-harness status
 ↓
nexus-harness context <target>
 ↓
读取最小 Product / Module Contract / Tests
 ↓
修改
 ↓
nexus-harness check
 ↓
nexus-harness test affected
 ↓
修复
 ↓
nexus-harness verify --fast
 ↓
Candidate Completion
 ↓
nexus-harness verify --full
 ↓
Evidence + Verdict
```

## 2. Contract-First / Spec-Freeze

新 Feature 必须分成两个阶段。

Contract Phase：

1. 修改 PRODUCT/MODULE Contract。
2. 新增或修改 `scenarios/`。
3. 在旧实现上运行 Scenario，得到 FAIL/BLOCKED Red Evidence。
4. 冻结 Scenario expectation / requirement mapping / schema，生成 Contract Hash。

Implementation Phase：

1. 已冻结 expectation 进入 Protected Paths/Fragments。
2. 实现代码只能使冻结 Scenario 通过，不能静默修改 expectation。
3. Contract 有误时必须退出 Implementation Phase，进入 `requirement-change`，重新产生 Red Evidence 和 Contract Hash。
4. 最终 PASS 由 Harness/Verifier 生成，而不是 Agent 文本声明。

## 3. 任务类型

```text
feature
bugfix
refactor
test
docs
performance
dependency
requirement-change
```

规则：

- `refactor`：Product Scenario expectation 默认不可修改。
- `bugfix`：应新增 Regression Evidence。
- `performance`：必须执行 Performance Budget Gate。
- `requirement-change`：允许改变已冻结 Product/Scenario expectation，但旧 Evidence 自动 STALE。

## 4. MODULE.md

核心 crate 必须维护局部契约：

```text
Responsibility
Non-Responsibilities
Inputs
Outputs
Allowed Dependencies
Forbidden Dependencies
Invariants
Side Effects
Public API
Verification
Performance Budget
Observability
Recovery Semantics
Platform Constraints
```

文本契约不替代机器门禁；Cargo、Policy 与 CI 必须共同约束。

## 5. Rust 工程纪律

- workspace 统一 edition、MSRV、profile。
- 第三方依赖默认 `default-features = false`，只开启实际需要能力。
- `cargo fmt --check`。
- `cargo clippy --all-targets -- -D warnings`。
- default / no-default / each-feature / supported feature matrix。
- Portable Core 做 WASI 或等价非桌面宿主检查。
- 公共 API 默认 `private -> pub(crate) -> pub`。
- 正常业务错误使用类型化 Result，不使用 panic。
- `unsafe` 必须最小化、写明 Safety Invariant 并有专项测试/fuzz。

## 6. Fast / Full Verification

Fast：

```text
format
check
clippy
architecture delta
dependency delta
affected tests
selected local properties
```

Full：

```text
workspace tests
integration
product scenarios
regression
architecture policy
dependency governance
coverage summary
selected fuzz/concurrency
performance budgets
platform checks
feature matrix
portable-core checks
```

## 7. Evidence

`.evidence/verify-<id>/` 绑定：

```text
source_revision
working_tree_digest
dirty_state
configuration_digest
feature_set
target_triple
toolchain_version
harness_schema_version
platform_capability_digest
```

任何影响结论的输入变化，旧 Evidence 必须变为 STALE。

## 8. Evidence 强度

```text
E0 Assertion / Existence
E1 Static Check
E2 Unit / Local Behavior
E3 Integration
E4 Product Scenario
E5 Independent External Observation
```

关键用户可见 Capability 原则上需要 E4 或更高证据。

## 9. Context Locality

Agent 默认读取顺序：

```text
Task
→ Product Contract
→ Module Contract
→ Public API
→ Relevant Tests/Scenarios
→ Relevant Implementation
```

不要默认读取整个仓库。

## 10. Affected Analysis

```text
changed files
→ owning crates/modules
→ reverse dependencies
→ mapped tests/scenarios
→ affected verification set
```

MVP 优先 Cargo metadata + 显式 mapping，不构造脆弱的全程序猜测式分析。

## 11. 本地验证入口

本合同包中的 `engineering/nexus-harness` 是最小命令壳，用于固定命令与 JSON schema；生产级 Harness 可以逐步替换其内部实现，但命令与 Evidence 语义应保持兼容。

## 12. 机器门禁与项目级 Skills

- **Git Hooks**：`.githooks/`（pre-commit / commit-msg / pre-push）把任务类型、受保护路径、Contract Hash、Evidence 新鲜度变成提交/推送前的硬检查。安装：`git config core.hooksPath .githooks`（或 `.githooks/install.ps1` / `install.sh`）。配置声明见 `harness.toml [hooks]`。
- **项目级 Agent Skills**：`.agents/skills/` 提供 `nexus-task`、`nexus-contract-first`、`nexus-evidence` 三个技能，封装标准开发循环、契约先行与证据报告。任务开始时按匹配读取对应 `SKILL.md`。
- 修改 `.githooks/` 或 `.agents/skills/` 属于 `docs` / `refactor` 类维护变更，仍须通过标准验证流程。
