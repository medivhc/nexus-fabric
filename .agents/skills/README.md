# Nexus 项目级 Agent Skills

仓库自带的一组 Agent 技能，把 AGENTS.md 的工程制度封装成可加载、可执行的工作流。任何在 Nexus 仓库内工作的 Agent，在动手前先按任务匹配读取对应 `SKILL.md`。

| 技能 | 触发场景 | 覆盖 AGENTS.md |
|---|---|---|
| `nexus-task` | 在仓库内执行一次端到端工程任务（改代码/文档/配置/验证流程） | §1–§4, §9, §13–§18, §23, §26 |
| `nexus-contract-first` | 新能力或需求变化，需要改已冻结的 Product/Scenario 期望（feature / requirement-change） | §5–§7, §25 |
| `nexus-review` | 实现完成、fast verify 通过后，提交 Candidate Completion 前的独立代码审查 | §6 不可自证原则 |
| `nexus-knowledge` | 检索历史工程经验（坑、Review 问题、架构决策），或沉淀新经验到知识库 | §27 决策原则 |
| `nexus-evidence` | 生成/解读/报告验证证据，判断新鲜度，输出完成报告 | §6, §20, §24, §26 |
| `nexus-multiagent` | 多个 Agent（不同 Harness/Model）并行向同一仓库贡献代码时的编排：角色分工、评审配对、模型差异的任务分配 | §29（编排层补充，机器化约定以 §29 为准） |
| `nexus-test-review` | TDD 测试用例独立评审：测试写完后、实现开始前的门禁，检查覆盖度/有效性/独立性/边界/可读性 |
| `nexus-selfrepair` | 执行者验证失败后的有界自修复循环：跑场景 → 读失败签名 → 定位 → 修 → 重跑（最多 3 轮，同一签名二次出现即结构化升级）；含 buffer 模式与 sampling 信号 | §24, §25, §19.1 |

## 加载方式

直接 `Read` 对应目录下的 `SKILL.md`（技能本体是自包含的单文件，无外部资源依赖）。

## 与其他机制的配合

- **机器门禁**：`.githooks/`（pre-commit / commit-msg / pre-push）把 §4/§5/§7/§19/§20 的关键约束变成提交与推送前的硬检查；本目录的技能是“怎么做”，hooks 是“做不到就拦”。
- **机器配置**：`harness.toml` 的 `[hooks]` 与 `[skills]` 段声明两套机制的项目级配置（任务类型表、受保护路径、Contract marker、技能索引）。
- **验证入口**：所有验证统一走 `nexus-harness`（`status` / `context` / `check` / `test affected` / `verify --fast` / `verify --full` / `explain`）。

## 维护约定

- 新增技能：在本目录新建 `<skill>/SKILL.md`（frontmatter 含 `name`、`description`），更新本索引与 `harness.toml` 的 `[skills] entries`，并同步 `FILE_MANIFEST.md`。
- 修改技能内容不得与 AGENTS.md、`policies/`、`harness.toml` 的机器约束矛盾。
