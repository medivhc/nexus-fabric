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

### 9.1 语义查询优先于 grep（Code Intelligence 工作流）

`engineering/` 提供只读的语义查询入口 `nexus-harness code <verb>`（verb：
`symbol | definition | references | implementations | callers | callees | hover |
diagnostics`）。代码理解任务的标准链路因此从"读很多文件再猜类型"变为：

```text
Task
→ nexus-harness context <target>
→ code symbol / definition          锚定真实声明，而不是同名文本
→ references / implementations      拿到写入点与 trait 的实际 impl
→ callers / callees on demand       按需一层展开，不做全量调用图
→ read only selected spans          只读被命中的行区间
→ implementation
→ cargo/compiler verification       check / clippy / test 仍是 correctness gate
→ Evidence
→ Verdict
```

纪律（细节契约见 `engineering/nexus-harness/MODULE.md` 的 Code Intelligence 段）：

- 分工：**LLM 负责提出问题、形成假设、综合结果；确定性程序分析负责提供代码事实。**
  能用 `code` 得到的事实，不要靠 `rg` 猜。
- `code` 的 verdict 是 **advisory**（输出里的 `authority` 字段），不拥有最终 PASS；
  最终结论仍由 `cargo check/clippy/test` 与 Harness Evidence/Verdict 决定。
- 结果必须带 `snapshot`（`source_revision` + `working_tree_digest` + provider/版本）；
  查询期间工作树变了就返回 `SNAPSHOT_STALE`，此时该结果不得作为事实使用。
- 结果集超预算时显式 `budget.truncated=true` 并给 `continuation.refinement_hint`；
  provider 不可用返回 `BLOCKED`，**不得**返回空结果冒充"没有引用"。
- 该能力只属于 `engineering/`：生产 crate 不得依赖 rust-analyzer/LSP/MCP，
  `code` 也没有任何写能力（rename / workspace edit / code action / `executeCommand`
  不进入 API，server 侧请求一律拒绝并计数）。

## 10. Affected Analysis

```text
changed files
→ owning crates/modules
→ reverse dependencies
→ mapped tests/scenarios
→ affected verification set
```

MVP 优先 Cargo metadata + 显式 mapping，不构造脆弱的全程序猜测式分析。

`code callers/callees` 的语义调用图只是**增量信号**，不是 Affected Analysis 的真相
来源：影响集仍由 Cargo metadata + 显式映射决定。语义结果用来回答"这个符号被谁写
过"，不用来回答"该跑哪些测试"。

## 11. 本地验证入口

本合同包中的 `engineering/nexus-harness` 是最小命令壳，用于固定命令与 JSON schema；生产级 Harness 可以逐步替换其内部实现，但命令与 Evidence 语义应保持兼容。

### 11.1 Windows 工作树的已知限制（2026-10-10 实测）

以下限制来自本仓库 Harness 自身对 POSIX 约定的依赖，**不是** Code Intelligence 引入的；
在 Windows 上跑门禁前要先知道，否则会把环境问题误读成代码问题：

- `git config core.autocrlf=true` 的检出会让 `PRODUCT.md`、`policies/*.toml`、
  `scenarios/**/*.toml` 在工作树里变成 CRLF。`gates.rs` 的 §12.58 复现测试和
  `Repo::contract_hash()` / `configuration_digest()` 都按**工作树字节**做哈希，因此在
  Windows 上算出的值与仓库内容（LF）不一致：`product_section16_contract_hash_is_reproducible`
  在 Windows FAIL、在 Linux/WSL PASS；跨平台生成的 Evidence 目录名也不能直接比对。
- 更严重的是**同一提交、同一主机**也可能得到不同的哈希：`.gitattributes` 是
  `* text=auto`，只有经 git checkout 落地的文件会被转成 CRLF，由工具直接写入的
  新文件保持 LF。于是 `contract_hash` 取决于"这个文件是 checkout 来的还是写出来的"
  这一瞬态属性。因此**契约身份必须按已提交 tree 的 blob（仓库内容为 LF）计算**，
  复现方法（2026-10-27 起，见 `engineering/nexus-harness/MODULE.md` Invariants 中的
  `contract_hash` 条）：输入集为 `harness.toml [protection].root_contract_paths` 下的全部
  git 可见文件与全仓 `**/MODULE.md`（`git ls-files -z -co --exclude-standard`），按路径
  字节序排序；每个文件拼 `<path>\0<字节长度>\0<内容>`（工作树缺失的已跟踪文件记为
  `<path>\0-\0`），整体喂给 `git hash-object --stdin`。此前的值（只覆盖
  `scenarios/*/*.toml`，如 `8ba9fea` = `cea5547a…`、`d4138b7` = `f13e96c6…`）与新口径不可比。
  覆盖面扩大到 `*.md` 契约后，CRLF 工作树字节的问题影响更多文件，下面的待办仍未关闭。
- `scenario.rs` 用 `Command::new(program)` 直接执行命令首词，`echo` 在 Windows 上是
  cmd 内建而不是 PE 可执行文件，因此 3 个以 `echo` 为 fixture 的场景单测
  （`run_single_pass_report`、`run_single_expect_failure_signature`、
  `run_parallel_keeps_order_and_verdicts`）在 Windows FAIL、在 Linux/WSL PASS。
  2026-10-10 复测补正机制描述：本机装了 Git for Windows，`D:\Program Files\Git\usr\bin\echo.exe`
  确实存在，`node child_process.spawnSync("echo", ['{"verdict":"PASS"}'])` 能拿到正确输出；
  但 harness 的管道形态（`Stdio::piped()` + 读线程）下 stdout 读回来是空的，报告落在
  `failed_step=parse`、`detail=output not JSON (EOF while parsing a value at line 2 column 0)`。
  结论不变（Windows 假红、Linux 绿、与本模块无关），但根因是"MSYS echo 在重定向管道下的
  输出没有按预期到达"，不是"命令解析不到可执行文件"。
- `gates::tests::product_section16_contract_hash_is_reproducible`（PRODUCT.md 冻结边界防篡改）
  在 Windows 工作树里必然假红：`.gitattributes` 的 `* text=auto` 把 checkout 变成 CRLF，
  而文档里存的 sha256 是按 LF blob 算的，同一 commit 在 Linux 上绿、在 Windows 上红
  （实测 rev `54010f8`：Windows FAIL，xc-pc-linux PASS）。已修：该测试读入后先
  `replace("\r\n", "\n")` 再算，并新增 `product_freeze_hash_is_line_ending_independent`
  锁定"同一内容两种行尾 → 同一个 hash"，同时断言不归一化时二者确实不同（否则测试没意义）。
  **口径边界要说清**：这条修改只作用于该防篡改测试，`Repo::contract_hash()`、
  `configuration_digest()`、`working_tree_digest()` 仍然按工作树字节计算，也就是说上面
  那条"契约身份必须按已提交 blob 计算"的待办**没有被关闭**，它仍属门禁契约变更，
  需要独立走 Contract-First 周期。
- `env::tests::digests_deterministic_and_sha1_length` 曾在 Linux 上偶发红（100 个里
  1 个失败，复跑与 `--test-threads=1` 全绿）。根因：`Repo::working_tree_digest()` 走
  `git write-tree`，与并发跑的其它测试争 `.git/index.lock` 时失败并**静默降级**成
  `tree-unknown`，于是"两次取值不相等"。已修：`Repo::git()` 只对锁竞争类错误重试
  （4 次、25/50/75ms 退避），并把该测试从"两次相等"加强为"两次相等**且**不是
  `*-unknown` 哨兵值"，避免"都没取到"被当成"取到了同一个值"。

处置：需要作为**结论**的门禁（`cargo test -p nexus-harness`、`verify --fast --json`、
Contract Hash）在**项目的 Linux 主机（`xc-pc-linux`）**或 `core.autocrlf=false` 的工作树里跑。
本机 WSL2 Ubuntu 用户态（同物理机、从 Windows 工作副本 fetch、由工具改过 resolv.conf 与
`~/.cargo/config.toml`）**只可用于开发试跑，不作为结论来源**（2026-10-10 所有者指示）。
另外一条同样重要的口径：`verify --fast` 在 `cargo-deny` 缺失时把 `dependency-governance`
记成 UNKNOWN 因而可能"overall PASS"，这种 PASS 不代表依赖治理真跑过 —— 装上工具后同一
分支会 FAIL。引用 PASS 时必须同时写明工具在场与否。修正哈希口径（按提交内容而非工作树字节
归一化行尾）属于门禁契约变更，需要独立走 Contract-First 周期，不在本条目里顺带改。


## 12. 机器门禁与项目级 Skills

- **Git Hooks**：`.githooks/`（pre-commit / commit-msg / pre-push）把任务类型、受保护路径、Contract Hash、Evidence 新鲜度变成提交/推送前的硬检查。安装：`git config core.hooksPath .githooks`（或 `.githooks/install.ps1` / `install.sh`）。配置声明见 `harness.toml [hooks]`。
- **项目级 Agent Skills**：`.agents/skills/` 提供 `nexus-task`、`nexus-contract-first`、`nexus-evidence` 三个技能，封装标准开发循环、契约先行与证据报告。任务开始时按匹配读取对应 `SKILL.md`。
- 修改 `.githooks/` 或 `.agents/skills/` 属于 `docs` / `refactor` 类维护变更，仍须通过标准验证流程。
