# Proposal: Agent Semantic Code Intelligence

> Status: Proposal
>
> Scope: Agent-Native Engineering Plane only
>
> Initial language backend: Rust / `rust-analyzer`

## 1. Problem

Nexus 已经把 **Context Locality** 作为工程契约：Agent 应从 Task、Product/Module Contract、Public API、Tests/Scenarios 逐步收敛到 Relevant Implementation，而不是默认读取整个仓库。

当前 `nexus-harness context <target>` 已经能提供模块契约和 tests/scenarios 映射，但当 Agent 进入实现代码后，仍然容易退化为：

```text
rg / grep
→ 打开若干文件
→ 根据文本猜测 trait/impl/type/call path
→ 再打开更多文件
```

对 Rust 而言，这种方式在 trait dispatch、泛型、宏、associated type、re-export、method resolution 等场景中既浪费上下文，也容易产生错误推断。

因此需要给 Engineering Plane 增加一个**确定性的语义代码查询层**：让 Agent 查询编译器/LSP 已知的代码事实，而不是让 LLM 自己从大量文本中重建这些事实。

目标不是“让 Agent 读取更多代码”，而是进一步贯彻：

```text
Repository as API
+ Minimal Context
+ Structured Evidence
```

## 2. Decision

在 `nexus-harness` 的 Engineering Plane 中引入统一的 **Code Intelligence API**；首个 provider 使用 `rust-analyzer`，通过 LSP 获取 Rust 语义信息。

Agent 不直接依赖 LSP 协议，也不直接依赖 `rust-analyzer` 的原始 JSON-RPC schema。Harness 对上暴露稳定、版本化、语言中立的查询 DTO，对下通过 provider adapter 连接不同语言工具。

推荐结构：

```text
Agent / Human / Coordinator
          │
          │ versioned JSON
          ▼
┌──────────────────────────────┐
│        nexus-harness         │
│                              │
│ context <target>             │
│ code <query>                 │
└──────────────┬───────────────┘
               │
       Code Intelligence API
               │
      ┌────────┴─────────┐
      │                  │
      ▼                  ▼
Semantic Provider   Compiler Provider
rust-analyzer       cargo / rustc JSON
      │                  │
      ▼                  ▼
def/ref/impl/type    diagnostics/check
call hierarchy       clippy/test
```

生产 crate 不依赖该能力；它属于 `engineering/`，不得进入 Nexus runtime、Portable Core 或产品依赖图。

## 3. Why not expose raw LSP directly

直接把完整 LSP/MCP 工具集暴露给 Agent 看似简单，但会产生三个问题：

1. Agent 与具体 server/protocol 耦合；未来接入 clangd、gopls、pyright 时上层提示词与工具调用需要变化。
2. LSP 返回结果没有 Nexus 的 context budget、revision binding、结构化 failure semantics。
3. LSP 同时包含 rename、code action、workspace edit 等写能力；Engineering Plane 的查询路径不应因为便利而获得隐式修改权限。

因此边界应为：

```text
Agent Contract != LSP Contract
```

LSP 是 provider protocol，不是 Agent-facing domain API。

## 4. Agent-facing API

建议新增：

```text
nexus-harness code symbol <query> --json
nexus-harness code definition <location-or-symbol> --json
nexus-harness code references <location-or-symbol> --json
nexus-harness code implementations <location-or-symbol> --json
nexus-harness code callers <location-or-symbol> --json
nexus-harness code callees <location-or-symbol> --json
nexus-harness code hover <location> --json
nexus-harness code diagnostics [target] --json
```

其中 `context <target>` 仍然是 Agent 的首选入口；Code Intelligence 是进入 Relevant Implementation 后的按需下钻能力。未来 `context` 可以在不改变上层工作流的前提下，选择性引用 semantic results。

所有机器输出继续遵循 Harness 现有约束，至少包含：

```json
{
  "schema_version": "1",
  "command": "code.references",
  "verdict": "PASS",
  "message": "3 references",
  "snapshot": {
    "source_revision": "...",
    "working_tree_digest": "..."
  },
  "provider": {
    "kind": "rust-analyzer",
    "version": "..."
  },
  "results": []
}
```

单个 result 使用语言中立位置模型：

```json
{
  "symbol": "...",
  "kind": "method",
  "qualified_name": "...",
  "path": "crates/.../src/lib.rs",
  "range": {
    "start": { "line": 10, "column": 4 },
    "end": { "line": 16, "column": 5 }
  },
  "snippet": "..."
}
```

不要把 rust-analyzer 的内部 symbol ID 或 LSP-specific DTO 作为长期 Public API。

## 5. Context budget

语义查询的价值之一是减少 token，而不是制造另一种“大结果集”。因此每个查询必须支持并默认施加 budget：

```text
max_results
max_snippet_lines
max_result_bytes
workspace_scope
```

当结果被截断时必须显式返回：

```text
truncated = true
continuation / refinement_hint
```

禁止静默丢弃结果后仍让 Agent 误以为结果完整。

推荐默认行为：

- definition / hover：只返回目标位置附近的最小必要 span；
- references：优先返回位置和 symbol metadata，不默认展开完整函数；
- callers/callees：返回一层关系，Agent 明确请求后再继续展开；
- diagnostics：结构化错误，不向 Agent 倾倒完整 ANSI build log。

## 6. Rust provider

MVP 使用 `rust-analyzer`，Harness 负责其生命周期：

```text
resolve workspace root
→ spawn rust-analyzer
→ initialize / initialized
→ open/query documents as required
→ bounded semantic requests
→ cancel on timeout
→ restart on crash
→ shutdown
```

首期只启用只读语义能力：

```text
workspace/symbol
tree/document symbols
textDocument/hover
textDocument/definition
textDocument/typeDefinition
textDocument/implementation
textDocument/references
textDocument/prepareCallHierarchy
callHierarchy/incomingCalls
callHierarchy/outgoingCalls
publishDiagnostics / pull diagnostics where supported
```

MVP 明确不启用：

```text
rename
workspace edit
code action auto-apply
format/write operations
arbitrary executeCommand
```

所有 server command、args、environment 必须来自仓库配置或固定实现；不得允许模型把任意 shell 参数透传给 language server launcher。

## 7. Compiler truth remains separate

LSP 提供的是高价值语义查询，但不能替代编译和验证。

Rust 的 correctness 路径继续使用：

```text
cargo check --workspace --all-targets
cargo clippy ...
cargo test ...
```

并优先消费 `--message-format=json` 的结构化 compiler messages。

职责分离：

```text
rust-analyzer
    “这个 symbol/type/impl/call relation 是什么？”

cargo/rustc
    “当前 revision 在指定 target/features 下是否成立？”

Harness/Verifier
    “这些结果是否足以产生当前 Evidence/Verdict？”
```

Code Intelligence 查询本身最多属于 E0/E1 辅助事实，不能因为 LSP 没有 diagnostics 就产生 Final PASS。

## 8. Relationship to Affected Analysis

现有开发契约明确规定 Affected Analysis 的 MVP 优先：

```text
Cargo metadata + explicit mapping
```

这一原则保持不变。

Semantic references/call hierarchy 可以作为后续的**增量信号**：

```text
changed files
→ owning modules
→ Cargo reverse dependencies / explicit mapping
→ optional semantic relation enrichment
→ affected tests/scenarios
```

禁止把 rust-analyzer 的调用图直接升级成全程序影响分析的唯一真相；宏、cfg、动态 dispatch、feature matrix 与平台差异都可能使单一语义快照不完整。

## 9. Plugin boundary

建议把具体工具适配实现为 Harness plugin/provider，而不是把 rust-analyzer 逻辑散落在 command handler 中。

新增 plugin category：

```text
code-intelligence
```

其 contract 延续现有 Harness Plugin 原则：

```text
structured input
versioned structured output
explicit failure propagation
duration + provider metadata
no protected-contract mutation
```

建议内部 trait 形态：

```rust
trait CodeIntelligenceProvider {
    fn symbols(&self, query: SymbolQuery) -> Result<SymbolResult, CodeIntelError>;
    fn definition(&self, query: LocationQuery) -> Result<LocationResult, CodeIntelError>;
    fn references(&self, query: LocationQuery) -> Result<LocationsResult, CodeIntelError>;
    fn implementations(&self, query: LocationQuery) -> Result<LocationsResult, CodeIntelError>;
    fn callers(&self, query: LocationQuery) -> Result<RelationsResult, CodeIntelError>;
    fn callees(&self, query: LocationQuery) -> Result<RelationsResult, CodeIntelError>;
    fn hover(&self, query: LocationQuery) -> Result<HoverResult, CodeIntelError>;
    fn diagnostics(&self, query: DiagnosticQuery) -> Result<DiagnosticsResult, CodeIntelError>;
}
```

这里的签名只是设计方向；实施前应按现有 harness code style 再冻结具体 API。

## 10. MCP integration

如果 OpenCode、Claude Code 或其他 Agent runtime 希望通过 MCP 使用该能力，推荐增加薄适配：

```text
MCP Tool
   ↓
Nexus Code Intelligence API
   ↓
Provider
   ↓
rust-analyzer
```

而不是：

```text
Agent → raw MCP-LSP bridge → rust-analyzer
```

这样 MCP 只是 transport adapter；同一套语义能力仍可由 CLI、CI、Coordinator 或未来其他 Agent protocol 使用。

可以使用现有通用 LSP→MCP bridge 做 spike，但不建议把它作为长期的 Nexus engineering contract。

## 11. Optional persistent index

SCIP 等 repository-wide semantic index 有价值，但不进入 MVP。

后续只有在出现以下证据时再增加：

- rust-analyzer cold start 成为明确瓶颈；
- 大仓库跨 session 查询需要持久化索引；
- Coordinator 需要跨 revision 做 symbol/reference diff；
- 离线/远程 Agent 无法持续运行 language server。

如果引入 SCIP，它应作为另一个 Code Intelligence Provider/Cache，而不是第二套 Agent API。

## 12. Failure semantics

Code Intelligence 必须遵守 Nexus 的显式失败原则。

建议错误至少区分：

```text
PROVIDER_UNAVAILABLE
WORKSPACE_UNRESOLVED
INITIALIZATION_FAILED
QUERY_INVALID
SYMBOL_NOT_FOUND
RESULT_TRUNCATED
TIMEOUT
PROVIDER_CRASHED
SNAPSHOT_STALE
UNSUPPORTED
```

工具不存在、server 启动失败或查询不支持时，不得退化为伪 PASS；应返回 `BLOCKED` / `UNKNOWN` / `FAIL` 中与 Harness 语义一致的结果以及结构化原因。

## 13. Snapshot and staleness

语义结果必须绑定至少：

```text
source_revision
working_tree_digest
provider/version
workspace configuration
feature/target context where applicable
```

如果文件在查询完成后发生变化，调用方不能把旧位置当作当前事实。

这与 Evidence 的 STALE 原则一致：代码理解结果也必须知道“它描述的是哪个工作树”。

## 14. Security and resource control

Language server 是本地长期子进程，应有明确资源边界：

- 工作目录必须被限制在 repository/worktree；
- command/args 不接受模型自由输入；
- 每个 request 有 timeout/cancellation；
- stdout/stderr 有大小上限；
- server crash 可重启但必须记录；
- 查询结果有大小上限；
- 默认只读；
- 不允许通过 LSP `executeCommand` 获得任意命令执行能力。

## 15. Suggested implementation phases

### Phase 0 — Spike

目标：验证 `rust-analyzer` 对 Nexus workspace 的稳定性和查询质量，不改变公开契约。

验证：

- workspace initialization；
- trait method definition/implementation；
- references；
- incoming/outgoing call hierarchy；
- diagnostics；
- cold/warm latency；
- 大结果集截断行为。

### Phase 1 — Rust read-only provider

冻结版本化 Code Intelligence DTO，并实现：

```text
symbol
definition
references
implementations
hover
callers/callees
diagnostics
```

增加 deterministic fixture workspace，覆盖 trait、多 impl、generic、re-export、cfg 的典型边界。

### Phase 2 — Harness integration

把 API 接入：

```text
nexus-harness code ... --json
```

并允许 `context <target>` 使用 bounded semantic facts 增强 Relevant Implementation 定位。

### Phase 3 — Agent adapters

根据真实使用方增加 MCP adapter；OpenCode/Claude/其他 Agent 都使用同一个 Nexus schema。

### Phase 4 — Generalization only when justified

根据实际项目需要再接：

```text
clangd
gopls
pyright/typescript language server
SCIP cache/index
```

先证明 Rust 路径有价值，再抽象多语言，不提前建立空泛框架。

## 16. Acceptance criteria

MVP 可进入 Candidate Completion 前至少满足：

1. Agent 能从一个 Rust method 位置准确得到 definition、references 和 implementations；
2. trait method + 多 impl fixture 有确定性测试；
3. callers/callees 至少能支持一层按需展开；
4. diagnostics 使用结构化 DTO，不要求解析终端自由文本；
5. 所有结果都绑定当前 revision/working-tree snapshot；
6. 结果集超预算时显式标记 truncated；
7. rust-analyzer 不可用时返回明确 BLOCKED/UNKNOWN，而不是伪造空结果；
8. provider 无写业务代码能力；
9. production crates 不增加 rust-analyzer/LSP/MCP 依赖；
10. `cargo check/clippy/test` 与 Harness Evidence/Verdict 仍是 correctness gate，Code Intelligence 不拥有最终 PASS；
11. `cargo test -p nexus-harness` 与 `nexus-harness verify --fast --json` 通过并产生符合现有规则的 Evidence。

## 17. Expected Agent workflow

完成后，一个代码理解任务应从：

```text
Task
→ nexus-harness context <target>
→ rg/read many files
→ infer types and implementations
→ more reads
```

变为：

```text
Task
→ nexus-harness context <target>
→ code symbol / definition
→ references / implementations
→ callers / callees on demand
→ read only selected spans
→ implementation
→ cargo/compiler verification
→ Evidence
→ Verdict
```

核心变化是：

> LLM 负责提出问题、形成假设和综合结果；确定性的程序分析工具负责提供代码事实。

这使 Semantic Code Intelligence 成为 **Minimal Context** 的实现机制之一，而不是新的业务子系统。
