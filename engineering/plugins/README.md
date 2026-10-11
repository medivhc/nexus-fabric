# Harness Plugins

Harness Plugin 只适配已有工具，不重写工具本身。

预期插件类别：

```text
cargo
git
architecture-policy
dependency-governance
test-runner
coverage
fuzz
concurrency
benchmark
observability-replay
platform-build
code-intelligence
```

Plugin contract：

1. 输入必须结构化。
2. 输出必须包含 `schema_version`、status/verdict、duration、artifacts。
3. 执行失败必须显式传播。
4. Plugin 不得把工具错误吞掉后返回 PASS。
5. Plugin 不得直接修改受保护的 Product/Scenario expectation。

## `code-intelligence` 类别的当前形态（2026-10-10）

提案 `docs/SEMANTIC-CODE-INTELLIGENCE-PROPOSAL.md` §9 要求：工具适配实现为 Harness
plugin/provider，不把 rust-analyzer 逻辑散落在 command handler 中，并新增 plugin
category `code-intelligence`。首期落地的取舍如下：

- **trait 边界已经按 §9 建立**：`CodeIntelligenceProvider`
  （`engineering/nexus-harness/src/code_intel/provider.rs`）是唯一的 provider 抽象，
  rust-analyzer 的细节全部关在 `code_intel/rust_analyzer.rs` 里，
  `code_intel/mod.rs` 只做 CLI/预算/envelope，不碰 LSP 语义。
- **但没有独立 plugin crate，也没有执行器注册条目**。原因：提案 §2 的硬约束是
  "生产 crate 不依赖该能力，它属于 `engineering/`"，而本仓库目前**没有** plugin
  执行器注册表（`nexus-harness` 的门禁是 `gates.rs` 里按名字硬编码分发的，
  例如 `"architecture-policy" => gates::architecture_gate(..)`），为 `code` 单独造
  一个 crate 只会多出一条跨 crate 的契约面，收益为零。

所以本类别是**已声明、未注册**：类别名进入上面的预期列表，`plugin-contract.md`
里没有对应的执行器条目。Phase 3（MCP adapter）时再决定是否抽成独立 plugin crate。

字段映射（内嵌实现的 `nexus-harness code <verb> --json` 输出 → plugin contract
要求的最小输出）：

| Plugin contract 字段 | 当前 `code` 输出中的对应字段 | 说明 |
|---|---|---|
| `schema_version` | `schema_version` | 由 `nexus-harness/src/main.rs` 统一注入的数字 `1`，`code_intel` 自身不写版本号 |
| `plugin` | `command` | 值为 `code <verb>`（如 `code definition`）；没有独立的 plugin 名 |
| `status` | `verdict` | 只取 `PASS / FAIL / BLOCKED`；`SNAPSHOT_STALE` 映射为 `BLOCKED` 而不是 `STALE`，与本文上方"STALE 属 Evidence Freshness 层"一致 |
| `duration_ms` | `provider.duration_ms` | 从解析 binary 起算，含 initialize 与就绪等待 |
| `artifacts` | `results[]` + `snapshot` | 语义结果与 `source_revision`/`working_tree_digest`/`target`/`toolchain`/`workspace_root` 绑定，等价于证据工件 |
| `diagnostics` | `error.code` + `error.reason` + `budget` + `continuation` | 失败用冻结的 10 个错误码结构化表达；截断与下一步提示走预算字段，不塞进日志文本 |

差异点（抽成 plugin 时必须解决，现在先记录不隐瞒）：`provider` 里的
`ready` / `restart_count` / `restart_reason` / `write_requests_refused` /
`dropped_notifications` 是**进程内**计数与状态，一次性执行的 plugin 模型无法表达；
"provider 不可用返回 BLOCKED 而不是 FAIL"也需要 plugin 契约显式区分
"工具不可用"与"工具报错"。
