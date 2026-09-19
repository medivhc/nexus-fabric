---
name: nexus-evidence
description: 当需要在 Nexus 仓库生成、解读或报告验证证据时使用（运行 nexus-harness verify、判断证据强度与新鲜度、输出 Candidate Completion 报告、分析 gate 失败）。包含 E0–E5 证据强度、绑定字段与 STALE 规则、verdict 语义、以及完成报告模板。Agent 只能声明 Candidate Completion，最终 PASS 必须来自 Harness/Verifier。
---

# nexus-evidence

Nexus 的证据体系：什么是证据、证据如何失效、Agent 能声明什么、不能声明什么。

## 使用场景

- 运行 `nexus-harness verify --fast` / `verify --full` 后解读 verdict 与 Evidence。
- 判断某条证据是否 fresh（绑定字段是否与当前工程状态一致）。
- 输出 Candidate Completion 报告。
- gate 失败时判断失败类型（Implementation Failure / Contract Conflict / Environment Failure / Unsupported Capability）。

## 证据强度

```text
E0  Assertion / 文件存在 / 符号存在
E1  静态检查（fmt / clippy / cargo check）
E2  单元测试 / 局部行为测试
E3  集成测试
E4  产品级 Scenario
E5  独立外部观察
```

关键用户可见 Capability 原则上至少需要 **E4**（或更强的 E5）证据。以下任何一项都不能单独代表完成：代码已存在、cargo check 通过、unit test 通过、README 写着 completed、coverage 很高、Agent 说已经完成。

## Evidence 绑定与新鲜度

`.evidence/verify-<id>/` 必须绑定：

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
contract_hash
```

任意影响结论的输入发生变化（改代码、改配置、改 feature、切 toolchain 等）：

```text
旧 Evidence → STALE
```

禁止把 STALE Evidence 当作当前完成证明。`.githooks/pre-push` 会扫描 `.evidence` 中的 STALE verdict 并阻止推送。

## Verdict 语义

```text
PASS      由 Harness/Verifier 产生的最新证据
FAIL      验证失败，需要修复
STALE     绑定输入已变化，结论不再成立
UNKNOWN   gate 未实现或无法判定（骨架状态）
BLOCKED   存在契约冲突 / 环境缺失 / 无法产生 fresh Evidence
```

Agent 最多提交：

```text
Candidate Completion
```

Agent 不得声明：

```text
Final PASS
```

## 失败处理

gate 失败时先回答：什么失败？为什么失败？期望 vs 实际？涉及哪个模块？哪些文件最相关？Evidence 是否 fresh？属于哪类失败？优先使用：

```text
nexus-harness explain --json
```

禁止：连续修改多个无关位置期望测试“碰巧变绿”；通过削弱 gate 解决失败。

## 输入

- 任务上下文（任务类型、修改范围）。
- `nexus-harness` 各命令的 JSON 输出。
- 需要判断的新旧 Evidence 记录。

## 输出形式：完成报告

```text
任务类型：
修改模块：
修改契约：
修改实现：
新增/修改 Tests / Scenarios：
Fast Verification：
Review Evidence ID / Path：
Review Verdict：APPROVED / CHANGES_REQUESTED / COMMENTED / BLOCKED
Reviewer：<独立执行者标识>
Full Verification：
Evidence ID / Path：
Evidence Freshness：
剩余风险 / Blocker：
Candidate Completion：yes / no
Final Verdict：仅 Harness 可决定
```

没有 Review Evidence 时，不能提交 Candidate Completion（纯文档/格式调整且不改变行为的变更可降级）。

如果 Full Verification 没有产生适当且 fresh 的 Evidence，不要写 `done` / `complete` / `finished`。
