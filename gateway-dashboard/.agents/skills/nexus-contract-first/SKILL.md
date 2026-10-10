---
name: nexus-contract-first
description: 当 Nexus 任务涉及新用户可见能力、需求变化，或需要修改已冻结的 Product/Scenario 期望（feature 与 requirement-change 任务类型）时使用。执行契约阶段（修改 PRODUCT/MODULE 契约 → 新增/修改 scenarios → 在旧实现上运行得到 FAIL/BLOCKED Red Evidence → 冻结期望与 Contract Hash）与实现阶段（只允许业务代码使冻结 Scenario 变绿）。若实现被迫改变冻结契约，必须停止并报告 Contract Conflict，不得静默解除保护。
---

# nexus-contract-first

Nexus 的 Contract-First / Spec-Freeze 制度：Agent 不能自己写实现、自己改验证标准、自己宣布完成。

## 使用场景

- 新用户可见 feature 或需求变化（任务类型为 `feature` / `requirement-change`）。
- 需要新增或修改 `scenarios/` 下的产品场景契约。
- 需要修改 `PRODUCT.md`、`ARCHITECTURE.md`、`policies/` 或 `crates/**/MODULE.md` 中的契约语义。

## 不要使用

- `bugfix` / `refactor` / `test` / `docs` / `performance` / `dependency` 任务（它们默认保持已冻结期望不变）。
- 只读分析或解释，不修改契约。

## 阶段 A：契约阶段

按顺序完成：

1. 修改相关 `PRODUCT.md` / `MODULE.md`（描述新能力与失败语义）。
2. 新增或修改 `scenarios/` 下的场景（E4 产品级契约）。
3. **在旧实现上执行 Scenario**，必须得到明确的：

   ```text
   FAIL
   或
   BLOCKED
   ```

   这就是 Red Evidence——没有 Red Evidence 不得进入实现阶段。
4. 冻结：Scenario expectation、requirement mapping、用户可观察语义、相关模块不变量。
5. 生成 **Contract Hash**（或等价 revision marker），记录到 commit message：

   ```text
   contract: <hash>
   ```

## 阶段 B：实现阶段

契约冻结后：

- 冻结的 Scenario expectation 自动成为 Protected（`.githooks` 的 pre-commit/commit-msg/pre-push 会机器化此约束）。
- 实现 Agent 只能修改业务代码使冻结 Scenario 通过。
- **禁止**为了让实现变绿而修改 expected value、删除失败测试、降低 timeout/threshold、把失败 Scenario 改成 skip、把产品错误改写成“预期行为”。
- 允许：新增测试、新增 Regression Test、补充边界案例、增加更严格验证。

## Contract Conflict（停止条件）

如果实现看起来必须改变 Protected Contract 才能完成：

```text
停止实现
→ 报告 Contract Conflict
→ 切换到 requirement-change 任务类型
→ 重新建立 Red Evidence 和新的 Contract Hash
```

不得自行解除保护，不得静默把旧 Evidence 当作有效。

## 输入

- 任务描述与目标行为。
- 相关 PRODUCT.md / MODULE.md / scenarios 文件路径。
- 当前实现状态（旧实现是否可运行）。

## 输出形式

- Red Evidence（FAIL/BLOCKED 的 Scenario 运行记录，路径/ID）。
- Contract Hash。
- 冻结清单（哪些 expectation / invariant 进入 Protected）。
- 实现阶段结束时的 Candidate Completion 报告（见 `nexus-evidence`）。
