---
name: nexus-review
description: 在 Nexus 仓库中，当实现 Agent 完成代码修改并通过 verify --fast 之后、提交 Candidate Completion 之前，执行独立代码审查。由独立于实现 Agent 的执行者（另一个 Agent 会话或人工）完成，覆盖契约一致性、边界覆盖、API 面控制、依赖边界、错误处理、测试质量、复杂度控制、可观测性八个维度，输出 Review Evidence 到 .evidence/review-<id>/。禁止实现 Agent 自行 Review 自己的变更；Review Verdict = CHANGES_REQUESTED 时必须修改后重新 Review，不得直接进入 verify --full。Review 是量化迭代过程，每一轮都要对比上一轮的维度变化。
---

# nexus-review

Nexus 的独立 Review 环节：自动化验证回答"代码对不对"，独立 Review 回答"代码好不好、全不全、有没有踩坑"。

## 使用场景

- 实现 Agent 完成了代码修改，`nexus-harness verify --fast` 通过。
- 需要提交 Candidate Completion 之前。
- 变更涉及核心领域、并发、持久化、架构边界等高风险区域。

## 不要使用

- 实现 Agent 自己 Review 自己刚写的变更（违反独立性原则）。
- 纯文档 / 注释 / 格式调整且不改变任何行为的变更（可降级为 COMMENTED 快速过）。
- 只读分析、不涉及代码修改的任务。

## 独立性规则

- Review 执行者必须独立于实现执行者。
- 同一个 Agent 会话中刚写完代码，不能紧接着自己写 Review 报告。
- Review 报告的 `reviewer` 字段必须填写独立执行者标识（Agent 会话 ID 或人工姓名）。

## 八个检查维度

### 1. 契约一致性（contract-consistency）

- 实现是否严格遵循对应 `crates/<crate>/MODULE.md` 的 Invariants 和边界？
- 是否有任何地方违反了 MODULE.md 的 Non-Responsibilities 声明？
- Scenario expectation 是否被静默修改以迎合实现？
- PRODUCT.md / ARCHITECTURE.md 中声明的语义是否被正确实现？

### 2. 边界覆盖（edge-coverage）

- 错误路径是否完整覆盖？（每一个 `Err` 分支都有对应的处理或测试）
- 状态转换是否完备？（状态机的每一条边都有对应的行为）
- 资源释放是否正确？（句柄 / 内存 / 网络连接 / 文件描述符在错误路径下也能释放）
- 并发场景是否考虑到？（共享状态的锁顺序、竞态条件、消息丢失）
- 极端输入是否处理？（空输入、超大输入、零值、最大值、非法格式）

### 3. API 面控制（api-surface-minimization）

- 是否有不该暴露为 `pub` 的类型 / 函数 / 常量？
- 是否把 `pub(crate)` 偷偷提升成了 `pub`？
- Public API 的文档是否完整？
- 是否新增了不必要的公共 trait / 抽象？

### 4. 依赖边界（dependency-boundary）

- 是否引入了 `policies/architecture.toml` 未声明的内部依赖？
- 是否违反了层级约束（portable-core → platform、domain → delivery 等方向）？
- 是否新增了第三方依赖？如果是，是否经过了六项评审？

### 5. 错误处理质量（error-handling-quality）

- 正常业务失败是否用类型化 `Result` 而不是 `panic!` / `unwrap()` / `expect()`？
- 错误类型是否保留了足够的上下文支持 Retry / Fallback / Abort / Ignore / Escalate？
- 是否有不当的错误吞掉（`let _ = ...` 无理由丢弃错误）？
- 是否有不当的错误信息泄露（把内部细节暴露给用户可见层）？

### 6. 测试质量（test-quality）

- 测试是否真实验证了行为，而不是只测 happy path？
- 是否有脆弱的断言（依赖时间 / 随机数 / 系统状态）？
- 新增的测试是否覆盖了本次变更引入的新代码路径？
- 是否有"为了覆盖率而写"的无意义测试？

### 7. 复杂度控制（complexity-control）

- 是否有过度设计？（抽象层级比实际需求多）
- 新增的 trait / 接口是否过了 Deletion Test？（删掉它会破坏哪个独立变化维度？）
- 函数 / 模块是否过大？职责是否单一？
- 是否有重复代码可以提取？

### 8. 可观测性（observability）

- 关键路径是否有结构化事件 / 日志？
- 是否有必要的关联字段（request_id / session_id / node_id / connection_id 等）？
- 热路径是否有无节制的 per-packet / per-frame 日志？
- 遇到非确定性问题时，是否有足够的记录支持 replay / 调试？

## Verdict 语义（量化）

每个维度的状态为 PASS / WARN / FAIL，最终 Verdict 由最差维度决定：

```text
APPROVED           0 个 FAIL，0 个 WARN（或只有非阻塞建议），可以进入 verify --full
CHANGES_REQUESTED  ≥ 1 个 FAIL，必须修改后重新走 fast verify + 再次独立 Review
COMMENTED          0 个 FAIL，≥ 1 个 WARN，有建议但不阻塞，记录在案即可
BLOCKED            发现契约冲突，需要切换到 requirement-change 流程
```

## 迭代闭环（必须显式记录）

Review 不是一次性的，必须形成"检查 → 修正 → 再检查"的迭代循环：

```text
第 1 轮 Review
  ↓
CHANGES_REQUESTED → 记录 FAIL 维度 + 阻塞项
  ↓
修正代码
  ↓
重新 fast verify
  ↓
第 2 轮 Review（独立于第 1 轮的执行者）
  ↓
对比第 1 轮：哪些 FAIL 变成了 PASS？哪些维度退步了？
  ↓
... 直到 Verdict = APPROVED 或 COMMENTED
```

每一轮 Review 都必须：
- 引用上一轮的 Review Evidence ID
- 记录本轮与上一轮的维度变化（哪些从 FAIL→PASS，哪些新增了 FAIL）
- 迭代次数有上限（默认 3 轮，超过则升级为 BLOCKED，需要人工介入）

## 输出：Review Evidence

Review 完成后，在 `.evidence/review-<id>/` 下生成：

```text
summary.json      Review verdict + 维度结果 + 阻塞项 + 建议 + 上一轮对比
findings.md       详细的 Review 意见（可读形式）
```

### summary.json 结构

```json
{
  "schema_version": 1,
  "review_id": "<12字符短id>",
  "review_round": 1,
  "previous_review_id": null,
  "verdict": "APPROVED | CHANGES_REQUESTED | COMMENTED | BLOCKED",
  "reviewer": "<独立执行者标识>",
  "source_revision": "<git commit sha>",
  "working_tree_digest": "<与 verify evidence 相同>",
  "contract_hash": "<与 verify evidence 相同>",
  "scope": {
    "task_type": "<feature | bugfix | refactor | ...>",
    "task_summary": "<一句话描述本次变更>",
    "changed_crates": ["<受影响的 crate 列表>"],
    "changed_files": 0
  },
  "dimensions": [
    {
      "name": "contract-consistency",
      "status": "PASS | WARN | FAIL",
      "findings": ["..."],
      "recommendation": "..."
    }
  ],
  "dimension_changes": {
    "edge-coverage": "FAIL → PASS",
    "test-quality": "WARN → PASS"
  },
  "blocking_issues": ["<阻塞进入 full verification 的问题列表>"],
  "blocking_issues_fixed": ["<已修复的阻塞项>"],
  "blocking_issues_remaining": ["<剩余阻塞项>"],
  "non_blocking_suggestions": ["<不阻塞但建议改进的问题列表>"]
}
```

## 输入

- 本次变更的 diff（`git diff HEAD` 或暂存区 diff）。
- 相关 crate 的 MODULE.md。
- 相关的 Scenario 文件。
- `nexus-harness context <target>` 的输出。
- 实现 Agent 的 Candidate Completion 报告草稿。
- 上一轮 Review 的 summary.json（如果不是第 1 轮）。

## 问题沉淀

Review 中发现的有复用价值的问题，需要沉淀到知识库：

1. 判断该问题是否有复用价值（不是只针对本次变更的一次性问题）
2. 读取 `nexus-knowledge` 技能
3. 先检索知识库是否已有相似条目
4. 有则更新，无则新建条目，记录问题描述、根因、解决方案、预防措施

## 与其他环节的关系

- **前置**：`nexus-harness verify --fast` 必须已通过。
- **后续**：Review Verdict = APPROVED 后，才能运行 `nexus-harness verify --full`。
- **迭代**：CHANGES_REQUESTED → 修正 → 重新 fast verify → 再次独立 Review（最多 3 轮）。
- **关联**：Review Evidence 的 `source_revision` / `working_tree_digest` / `contract_hash` 必须与同期的 verify Evidence 绑定一致。
- **沉淀**：有复用价值的问题 → 写入 `.agents/knowledge/` 知识库。
