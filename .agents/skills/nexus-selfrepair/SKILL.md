---
name: nexus-selfrepair
description: 执行者在验证失败后进入的有界自修复循环：跑场景 → 读失败签名 → 定位 → 在本 worktree 修 → 重跑。硬边界：最多 3 轮、每轮必须换修复策略、同一 failure_signature 第二次出现立即停止并结构化升级给协调者；禁止修改 scenarios/ 下任何 expectation 与断言（防"教会测试撒谎"）；禁止推 master、禁止 --no-verify。循环终点是"验证变绿 → 走 nexus-review 独立评审"，循环本身永远不合并。另含 buffer 模式（攒坏模式、攒够再看共性）与 sampling 信号（多 agent 同一签名 → 修环境不修单个 agent）。适用于验证失败后的无人值守修复；不适用于契约冲突、环境失败（见"不要使用"）。
---

# nexus-selfrepair

把"agent 自己跑验证、自己读失败、自己修、修不好就升级"的闭环写成固定程序。
目标：不再需要人当"人肉中转站"——agent 看日志、agent 定位、agent 修、agent 重跑，
人只处理循环升级上来的结构化报告。

思想来源：Lauren Tan（pstack）——"把反复纠正的地方写成规矩"；
"把确定性部分抽出来变成代码，只把需要判断的部分留给 agent"。

## 使用场景

- `nexus-harness scenario run <name>` 或 `verify --fast/--full` 返回 FAIL，失败被判定为
  **Implementation Failure**（实现 bug，非契约冲突、非环境失败）。
- 执行者在自己的 worktree 里，需要无人值守地修到验证变绿，再交给独立评审。

## 不要使用

- 失败分类是 **Contract Conflict**（AGENTS.md §25：必须改 Protected Contract 才能过）
  → 停止实现，报告 Contract Conflict，走 `nexus-contract-first`。
- 失败分类是 **Environment Failure**（沙盒 UDP EPERM、真机资源不足等）
  → 不进修复循环。记录到 buffer（见"buffer 模式"），报告给协调者。
- 失败分类是 **Unsupported Capability** → 停止，报告。
- 修复需要改 `scenarios/` 的 expectation / 断言才能变绿 → 这不是修，这是"教会测试撒谎"。
  按 §7 视为 Contract Conflict，停止并升级。

## 前提：失败签名接口（消费，不生产）

本 skill 只**消费** Track A（场景包）生产的失败签名，不定义、不修改其字段。
跨轨冻结接口：

```json
{
  "scenario": "<场景名>",
  "verdict": "PASS | FAIL | BLOCKED",
  "evidence_id": "<evidence id>",
  "failure_signature": {
    "failed_step": "<失败步骤名>",
    "assertion": "<失败断言描述>",
    "key_log_lines": ["<关键日志行>", "..."]
  },
  "duration_ms": 12345
}
```

取签名的唯一入口：

```text
nexus-harness scenario run <name> --json
```

## 循环算法

每轮严格按以下六步执行，不许跳步：

```
1. RUN      nexus-harness scenario run <name> --json   → 拿到 verdict + failure_signature
2. PARSE    提取 failed_step / assertion / key_log_lines；与上一轮签名做精确比对
3. DIAGNOSE 按 AGENTS.md §24 先定位再改：
             什么失败？为什么失败？期望是什么？实际是什么？
             涉及哪个模块？哪些文件最可能相关？Evidence 是否 fresh？
             判定失败分类（Implementation / Contract / Environment / Unsupported）
4. FIX      只改实现代码（本 worktree 内）；
             禁止连续修改多个无关位置；禁止"希望测试碰巧变绿"
5. RERUN    回到第 1 步
6. DECIDE   按"硬边界"决定：继续下一轮 / 停止并升级 / 变绿走评审
```

**每轮必须换修复策略。** 第 1 轮修 A 假设失败，第 2 轮必须基于新的定位证据换 B 策略，
禁止用同一策略重试（"再跑一次看看"不算策略）。

## 硬边界（违反任何一条即停止）

1. **最多 3 轮**。第 3 轮仍未变绿 → 停止，按 `stop_reason=max_rounds` 升级。
2. **同一 failure_signature 出现第二次 → 立即停止**，按 `stop_reason=same_signature_twice` 升级。
   签名比对字段：`failed_step` + `assertion`（`key_log_lines` 只作辅助证据，不参与判等）。
3. **禁止修改 `scenarios/` 下任何 expectation 与断言**（AGENTS.md §7）。
   允许：新增回归测试、补充边界案例、增加更严格的验证。
   禁止：删失败测试、改 expected value 迎合实现、降 timeout/threshold、把失败改成 skip。
4. **禁止修改已冻结契约**（`PRODUCT.md`、`ARCHITECTURE.md`、`policies/`、`crates/**/MODULE.md`）。
   如定位结论是"必须改契约才能过" → 这是 Contract Conflict，停止并升级。
5. **禁止推 master**，只推自己的分支；**禁止 `--no-verify`** 或任何等价绕过。
6. 只在本 worktree 内修改；不得到协调者明确指令，不碰其他轨道的文件。

## 升级报告（结构化，给协调者）

停止时必须输出以下 JSON（打印到 stdout 并写入 `.evidence/selfrepair-<loop-id>/escalation.json`）：

```json
{
  "loop_id": "selfrepair-<NEXUS_AGENT>-<yyyymmdd-hhmm>",
  "scenario": "<场景名>",
  "verdict": "FAIL",
  "evidence_id": "<最后一次运行的 evidence id>",
  "failure_signature": { "failed_step": "...", "assertion": "...", "key_log_lines": ["..."] },
  "rounds": [
    {
      "round": 1,
      "diagnosis": "<定位结论：什么失败、为什么>",
      "strategy": "<本轮修复策略>",
      "changed_files": ["<文件>"],
      "result": "FAIL",
      "result_signature": { "failed_step": "...", "assertion": "..." }
    }
  ],
  "stop_reason": "same_signature_twice | max_rounds | contract_conflict | environment_failure",
  "recommended_next": "<给协调者的建议：换人看 / 改契约 / 修环境 / 加场景>"
}
```

`rounds[].strategy` 必须每轮不同——这是给协调者判断"agent 是不是在原地打转"的证据。

## 终点语义

- 验证变绿 → **走 `nexus-review` 独立评审**。循环的输出是"可评审的候选"，不是"可合并的代码"。
- 循环本身**永远不直接合并、不推 master**。用户铁律（2026-10-05）：
  "以后都需要独立 review 然后修复"——自修复循环只是把"实现 → 评审"之间的返工自动化了，
  不改变"实现 ≠ 评审"的铁律。
- 评审 verdict 为 CHANGES_REQUESTED → 打回后**可以**再进一轮自修复循环（loop_id 新开，
  rounds 计数重置，但升级报告必须引用上一轮的 loop_id 供追溯）。

## buffer 模式（攒坏模式，不立即修）

来自播客的实用技巧：verifier 发现**疑似坏模式 / 重复出现的失败**时，先只记录、不立即修。
攒够数量或固定周期，由协调者看共性，再沉淀为 lint 规则或 skill 条目。

触发条件（满足任一）：
- 同一 failure_signature 在**不同场景**或**不同 agent** 出现 ≥ 2 次；
- 失败看起来是"写法问题"而非"逻辑 bug"（如：每次都在同一个断言风格上跌倒）；
- agent 修了 3 轮没修好，但签名稳定、可复现——这是"模式"的信号，不是"偶发"的信号。

记录位置（固定文档，append-only，agent 不许改历史条目）：

```text
.agents/knowledge/entries/<yyyy-mm-dd>-selfrepair-buffer.md
```

每条记录格式：

```markdown
## <yyyy-mm-dd hh:mm> <NEXUS_AGENT>
- signature: <failed_step> / <assertion>
- scenario: <场景名>  evidence: <evidence_id>
- 观察: <一句话：为什么觉得这是模式而非偶发>
```

消费：协调者定期（如每周）通读 buffer，找共性（"these are all the same thing"），
决定沉淀为 lint 规则 / skill 条目 / 契约修订。**"看见森林"的是协调者，不是单个 agent。**
buffer 里的条目 agent 不许自行"认领修复"——修模式是环境工作，走 sampling 信号流程。

## sampling 信号（多 agent 同一签名 → 修环境）

如果 buffer 或升级报告显示：**多个 agent 在走同一条捷径 / 栽在同一个失败签名上**，
修的不是某个 agent 的代码，而是环境：

```
修 skill（nexus-selfrepair / nexus-task 的某条规则写得不清楚）
修约束（加一条 lint 规则 / 收紧类型，让这种错写不出来）
修场景（断言本身有歧义 → 走 nexus-contract-first 修场景，见"不要使用"）
```

判断标准：偶发（单个 agent、单次）→ 走自修复循环；成模式（多 agent / 多次）
→ 升级为环境问题，由协调者决策。**永远不要对着单个 agent 的偶发错误加全局规则**
（规则膨胀和"钝刀"一样伤效率）。

## 与其他技能的关系

- `nexus-task`：端到端任务流程；验证失败且判定为 Implementation Failure 时，转入本 skill 的循环。
- `nexus-evidence`：evidence 的生成、解读与新鲜度判断；本 skill 的 RUN 步依赖它。
- `nexus-review`：循环的唯一合法出口。验证变绿后必须走独立评审。
- `nexus-contract-first`：循环中撞上 Contract Conflict 时的出口。
- `nexus-multiagent`：执行者在多 agent 并行中的自修复行为规范（有界升级、NEXUS_AGENT 命名）。
- `nexus-knowledge`：buffer 模式的记录位置与消费约定（§19.2 动态知识库）。

## 维护约定

- 本 skill 不得与 AGENTS.md、`policies/`、`harness.toml` 的机器约束矛盾。
- 失败签名接口由 Track A（场景包）生产；字段名冻结，**本 skill 只消费，不得改字段名**。
  如接口需要变更，走 `nexus-contract-first`，由两轨协调者共同确认。
