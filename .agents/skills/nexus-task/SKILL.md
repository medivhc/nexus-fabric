---
name: nexus-task
description: 在 Nexus 仓库内执行一次端到端工程任务时使用（修改 crates/apps/engineering 代码、文档、配置或验证流程）。接到任务后按本技能完成：任务类型判定 → 最小上下文获取（优先 nexus-harness context）→ 契约先行（feature/requirement-change 转 nexus-contract-first）→ 实现 → 标准验证（nexus-harness check → test affected → verify --fast → verify --full）→ Candidate Completion 报告。不适用于仓库外通用问答、与 Nexus 无关的创作或分析任务。
---

# nexus-task

在 Nexus 仓库执行一次完整工程任务的标准流程，把 AGENTS.md 的工作循环变成可重复执行步骤。

## 使用场景

- 接到针对 Nexus 仓库的任务（新功能、bug、重构、补测试、文档、性能、依赖变更、需求变化）。
- 需要在仓库中修改 `crates/`、`apps/`、`engineering/`、`policies/`、`scenarios/` 或顶层契约文档。
- 需要判断任务类型、确定验证范围、输出完成报告。

## 不要使用

- 与仓库无关的通用问答、闲聊、创作任务。
- 仅阅读/解释仓库内容而不做修改（直接按 AGENTS.md 回答即可，不必走完整流程）。

## 核心流程

1. **判定任务类型**：在修改任何文件前确定任务类型，只能是以下八类之一：

   ```text
   feature | bugfix | refactor | test | docs | performance | dependency | requirement-change
   ```

   - 需要改变已冻结 Product/Scenario 期望 → `requirement-change`（不是 feature）。
   - 只补测试、不改变产品行为 → `test`。
   - 涉及新依赖 → `dependency`，必须过六项评审（architecture/feature/license/security/portability/supply-chain）。

2. **获取最小上下文**（仓库即 API，不要默认读整个仓库）：

   ```text
   nexus-harness status --json
   nexus-harness context <target> --json
   ```

   默认读取顺序：PRODUCT.md → ARCHITECTURE.md → 相关 crates/<crate>/MODULE.md → Public API → 相关 Tests/Scenarios → 相关实现。
   README、代码注释、旧测试输出、过期 benchmark 不能高于正式契约和最新 Evidence。

   **同时检索知识库**：读取 `nexus-knowledge` 技能，检索与目标模块相关的历史经验条目，了解有哪些已知的坑和注意事项。

3. **feature / requirement-change 必须走契约先行**：读取 `nexus-contract-first` 技能，完成契约阶段并拿到 Red Evidence 和 Contract Hash 后再进入实现。

3.5. **TDD 测试用例评审**：测试用例写完后、实现开始前，必须经过独立的测试用例评审。读取 `nexus-test-review` 技能，由独立评审者（不同人、不同 session，子代理盲评）检查测试用例本身。

   - Verdict=APPROVED → 测试用例冻结，进入第 4 步实现。
   - Verdict=CHANGES_REQUESTED → 打回重写测试用例，不进入实现。

   测试用例评审是 TDD 流程的门禁，不是可选项。没有走过测试用例评审的实现，第 6 步独立 Review 时直接打回。

4. **实现**：

   - 遵守对应 crate 的 MODULE.md 契约与 `policies/architecture.toml` 依赖边界。
   - Rust 纪律：`private → pub(crate) → pub`；类型化 Result 而非 panic；`unsafe` 最小化并写明 Safety Invariant。
   - 结构化并发：每个长期任务必须有 Owner（CancellationToken + JoinSet + Reaper），禁止丢弃 JoinHandle。
   - TerminalOutcome（Completed/Failed/Cancelled）只允许 Owner State Machine 提交一次；Worker 只发 Event。
   - 有持久状态的关键路径必须有 journal / write-ahead marker 与幂等 reconcile。
   - Workspace 纪律：不 reset/checkout/revert/删除与任务无关的用户修改；不确定文件归属时报告歧义，不猜测。

5. **标准验证**（修改后立即运行，按此顺序）：

   ```text
   nexus-harness check
   nexus-harness test affected
   nexus-harness verify --fast
   ```

   禁止通过削弱 gate（删测试、改 expected value、降低 timeout、skip 失败 Scenario）来解决失败。

6. **独立 Review（量化迭代）**：verify --fast 通过后，进入独立 Review 环节。读取 `nexus-review` 技能，由独立于实现的执行者完成八个维度的审查，输出 Review Evidence 到 `.evidence/review-<id>/`。

   Review 是量化迭代过程，不是一次性检查：

   ```text
   第 1 轮 Review
     ├─ APPROVED / COMMENTED → 进入 Full Verify
     └─ CHANGES_REQUESTED → 修正 FAIL 维度 → 重新 fast verify → 第 2 轮 Review
           ├─ APPROVED / COMMENTED → 进入 Full Verify
           └─ CHANGES_REQUESTED → 修正 → 重新 fast verify → 第 3 轮 Review
                 └─ 仍 CHANGES_REQUESTED → 升级 BLOCKED，人工介入
   ```

   每一轮 Review 都必须：
   - 引用上一轮的 Review Evidence ID
   - 记录维度变化（哪些 FAIL→PASS，哪些退步了）
   - 最多迭代 3 轮，超过则升级 BLOCKED

   禁止实现 Agent 自行 Review 自己刚写的变更。

7. **Full Verification**：Review 通过后运行：

   ```text
   nexus-harness verify --full
   ```

8. **失败处理**：gate 失败时先判断失败类型（Implementation Failure / Contract Conflict / Environment Failure / Unsupported Capability），使用 `nexus-harness explain --json`，不要连续修改无关位置碰运气。

9. **输出 Candidate Completion 报告**：格式见 `nexus-evidence` 技能。报告不是 Final PASS——最终 PASS 必须由 Harness/Verifier 产生。

## 关键规则

- 遇到以下情况必须停止实现并报告 BLOCKED/UNKNOWN：契约与 Scenario 冲突；必须修改冻结期望才能实现；新依赖产生未批准架构边；Portable Core 被迫直接调用平台 API；唯一通过方式是删除独立验证；无法产生 fresh Evidence；Workspace 修改可能删除仍可达数据；并发设计无法确定 Outcome 唯一 Owner；新持久状态没有 Crash Recovery 语义。
- 受保护路径（`PRODUCT.md`、`ARCHITECTURE.md`、`policies/`、`scenarios/`、`harness.toml`、`crates/**/MODULE.md`）的修改受 `.githooks` 与 `nexus-contract-first` 双重约束。

## 输入

- 任务描述（issue / 用户需求）。
- 可选：相关文件路径、报错日志、Scenario 名称。

## 输出形式

- 完成报告（见 `nexus-evidence` 的模板），包含：任务类型、修改模块、修改契约、修改实现、新增/修改 Tests/Scenarios、Fast/Full Verification 结果、Evidence ID/Path、Evidence Freshness、剩余风险/Blocker、Candidate Completion: yes/no。
