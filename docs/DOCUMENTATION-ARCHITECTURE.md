# Nexus 文档架构设计（Documentation Architecture）

> 状态：设计稿（design），2026-10-06
> 目标：让文档体系从"写完就烂"变成"烂了会被发现、被标出、被处理"。
> 核心原则：**机制 > 自觉**。凡是能靠机器保证的，不靠人记住；凡是靠人维护的，必须有过期标记、归属和清理节奏。

---

## 1. 四层定义与归属表

| 层 | 内容 | 位置 | 保鲜方式 | Owner |
|---|---|---|---|---|
| **L1 契约层**（机器强制的真相来源） | `PRODUCT.md`（产品语义）、`ARCHITECTURE.md`（架构不变量）、各 crate `MODULE.md`、`scenarios/`（产品级期望）、`policies/`（架构/依赖/质量门禁） | 仓库根 / `crates/*/MODULE.md` / `scenarios/` / `policies/` | 每一句可验证的声明都有对应机器检查（harness gate / CI / pre-push hook）；代码违背文档 → 门禁直接拦 | 各模块 owner（见 AGENTS.md §29.1 归属表） |
| **L2 操作层**（怎么做事） | `AGENTS.md`（工程制度）、`DEVELOPMENT.md`（开发流程）、`.agents/skills/*/SKILL.md`（可执行工作流） | 仓库根 / `.agents/skills/` | 文档中的每条命令都在 CI 或日常工作中被执行；失效即被踩坑即被修 | 工具链 skill 的维护者（身份值按 AGENTS.md §29.2 规则自定；注：§29.1 的 `agent-e` 归属"平台与基础设施"，并非工具链域，此处不引用该身份值） |
| **L3 决策层**（为什么这样，只追加不修改） | ADR（架构决策记录）、`.agents/knowledge/entries/`（踩坑/模式/决策条目） | `docs/adr/`（新建）、`.agents/knowledge/`（已有） | append-only：旧条目永不改写，只能被新条目标记取代；天然不过时 | 决策提出者；知识库条目按现有 §19.2 触发点写入 |
| **L4 导航层**（怎么找到东西） | README 索引、`FILE_MANIFEST.md`、skill 索引（`.agents/skills/README.md`）、knowledge `index.json` | 各目录 | **全部生成，不手写**（见 §4） | 生成器脚本（CI 拥有） |

**分层判定规则**：拿不准一份文档属哪层时，看它的"腐烂方式"——会被代码证伪的是 L1，会被工具链证伪的是 L2，记录历史的是 L3，靠枚举文件的是 L4。

---

## 2. 保鲜元数据（Frontmatter）格式

所有 L1/L2 手写文档必须在文件头携带以下 frontmatter。没有 frontmatter 的文档视为"未纳入保鲜体系"，doc audit 时优先处理。

```yaml
---
doc-id: nexus-doc-architecture        # 全仓库唯一，kebab-case
layer: L1                            # L1 / L2（L3/L4 不用此格式，见 §3）
owner: agent-c                        # 负责人身份值（沿用 §29.2 NEXUS_AGENT 命名空间）
last-verified: 2026-10-06            # 上次人工确认"内容仍准确"的日期
verified-against: b9ae124            # 确认时所在的 commit（短 hash）
status: current                       # current / stale / deprecated
---
```

字段语义：

- `last-verified` 不是"最后修改日期"，而是"最后一次有人对照现实检查过"的日期。改了错别字不算验证。
- `verified-against` 绑定检查时的代码状态。STALE 判定同时看时间和版本（见 §5）。
- `status: deprecated` 表示"已知过时、待删除或待重写"，doc audit 前不清零。

---

## 3. 各层保鲜机制（谁来做、何时触发、输出什么）

### L1 契约层：机器检查是正文，文字是注释

| 机制 | 触发 | 执行者 | 输出 |
|---|---|---|---|
| 门禁绑定 | 每次 push（pre-push hook） | harness | 契约声明 vs 代码行为不一致 → FAIL，禁止推送 |
| 受保护路径 | 修改 `PRODUCT.md` / `ARCHITECTURE.md` / `policies/` / `scenarios/` / `MODULE.md` | commit-msg hook | 必须携带 `contract: <hash>` 或 `requirement-change: <hash>`，否则拒收 |
| 人工复核 | 每季度 doc audit（见 §6） | owner | 更新 `last-verified` / `verified-against`，或标 `deprecated` |

**硬规则**：L1 文档中任何"可被机器验证"的陈述（如"某模块禁止依赖 X"、"某场景期望输出 Y"），必须在 `policies/` 或 `scenarios/` 或测试中有对应检查。纯文字描述、无机器背书的 L1 陈述，降级为 L2 处理。

### L2 操作层：用进废退 + 失效即修

| 机制 | 触发 | 执行者 | 输出 |
|---|---|---|---|
| Skill 自检 | 每周 CI 定时任务 | CI | 逐条执行 `.agents/skills/*/SKILL.md` 中的命令片段（` ```sh verify ` 标记的代码块），失败则开 doc debt 工单 |
| AGENTS.md 章节校验 | 每次修改 AGENTS.md | pre-commit hook | 引用的 `§X` 章节号必须存在；引用的文件路径必须存在 |
| 人工复核 | 每季度 doc audit | owner | 同 L1 |

**硬规则**：SKILL.md 中的操作步骤必须写成可被 CI 逐条执行的代码块（` ```sh verify ` 标记），而不是散文。散文描述步骤的 skill 视为未完成。

### L3 决策层：append-only

- **ADR**：新建 `docs/adr/` 目录，文件命名 `NNNN-<slug>.md`（编号递增）。每条 ADR 包含：日期、背景、决策、备选、后果。**永不编辑已发布的 ADR**；决策变更时写新 ADR，在旧 ADR 头部加 `superseded-by: NNNN` 标记（加标记是唯一允许的修改）。
- **知识库**：沿用现有 §19.2（`.agents/knowledge/`），条目格式不变。新增一条规则：条目 `category` 增加 `decision` 取值，用于记录"为什么没选另一条路"。
- L3 不设 STALE——历史记录不会"过期"，只会被取代。`superseded-by` 链就是它的保鲜机制。

### L4 导航层：生成器

| 产物 | 生成器 | 触发 | 输出 |
|---|---|---|---|
| `FILE_MANIFEST.md` | `engineering/docgen/manifest.py`（新建） | pre-commit（有文件增删时） | 文件路径 + 用途（用途从各文件 frontmatter `doc-id` 聚合，手写用途列禁止） |
| `.agents/skills/README.md` 索引表 | `engineering/docgen/skills-index.py`（新建） | pre-commit（skill 增删时） | 从各 `SKILL.md` frontmatter 的 `name`/`description` 生成 |
| `.agents/knowledge/index.json` | 已有（需补生成脚本） | pre-commit（entry 增删时） | 从 entries frontmatter 生成 |
| API 文档 | rustdoc | CI | `cargo doc` 产物，不入库 |

**硬规则**：L4 文件顶部必须带 `<!-- GENERATED, DO NOT EDIT. Source: <生成器路径> -->` 标记。pre-commit 发现手改生成文件 → 拒绝提交并提示重新生成。

---

## 4. STALE 扫描规则

CI 每周定时任务 `doc-freshness`（与现有 `verify --fast` 定时任务并列），扫描所有带 frontmatter 的 L1/L2 文档：

```
STALE 当且仅当满足任一条件：
  1. today - last-verified > 90 天
  2. verified-against 指向的 commit 在 master 历史中已不可达
    （被 rebase 丢弃）或早于 500 个 commit
  3. status == deprecated

输出：doc debt 清单（doc-id、owner、stale 原因、过期天数），
      按 owner 分组，发到用户可见的固定位置（见 §7）。
```

**注意**：STALE 是"待复核"标记，不是"错误"标记。owner 在 doc audit 或日常工作中复核后，更新 `last-verified`/`verified-against` 即可清零。连续两个季度 STALE 未处理的文档，自动进入删除候选（见 §6）。

STALE 扫描**不阻塞 push**（与 STALE evidence 门禁不同——证据关乎"能不能说完成了"，文档 STALE 关乎"待办事项"，阻塞会逼出 `--no-verify` 式的绕过）。

---

## 5. Doc-code 联动门禁

| 检查 | 位置 | 触发 | 行为 |
|---|---|---|---|
| Public API 变更未更新 MODULE.md | pre-commit | 暂存区 `.rs` 文件的 `pub` 项增删（`cargo public-api` diff 或 rustdoc JSON diff） | 警告（warning，不阻断）：提示 owner 检查对应 `MODULE.md` 的 Public API / Verification 章节 |
| Skill 命令失效 | CI 每周 | 见 §3 L2 | 失败 → doc debt 工单 |
| 生成文件被手改 | pre-commit | L4 文件在暂存区且无生成器标记更新 | 拒绝提交，提示重新生成 |
| AGENTS.md 引用失效 | pre-commit | AGENTS.md 在暂存区 | 章节号/文件路径引用检查，失败则拒绝 |

**工具链说明**：上表提到 `cargo public-api`，但该工具当前不在工具链中。引入它需按 AGENTS.md §18 走依赖评审（architecture / license / security / portability / supply-chain），列为 P2 前置任务；在评审通过之前，API diff 默认用 rustdoc JSON diff 实现。

**为什么 API 检查只是 warning**：误报率高（如内部重构触 pub(crate)）。先 warning 跑一个季度，误报率 <5% 再升级为阻断。门禁升级本身记一条 ADR。

---

## 6. Doc Audit 流程（每季度）

| 步骤 | 执行者 | 输入 | 输出 |
|---|---|---|---|
| 1. 拉清单 | 协调者 agent | STALE 扫描结果 + 全量 frontmatter | 待审文档列表（按 owner 分组） |
| 2. 逐份判定 | 各 owner | 文档 + 当前代码/现实 | 三选一：`current`（更新验证字段）/ `deprecated`（写明原因）/ `delete`（直接删） |
| 3. 处理 deprecated | owner | 原因 | 要么重写（回到 current），要么删除；不允许第三个季度仍为 deprecated |
| 4. 汇总报告 | 协调者 | 各 owner 结果 | 本季度 doc 健康度：current 占比、删除数、新增 ADR 数 |

**删除标准**：同时满足"连续两季度 STALE"和"owner 无法在 1 小时内确认其准确性"的文档，直接删除。**错误的文档比没有文档更糟**——缺了自然有人按需重写，重写时带 fresh 的 frontmatter。

**时间盒**：单个 owner 的 audit 工作量不超过半天。超了说明文档太多，先删再审。

---

## 7. Doc Debt 可视化

- STALE 扫描输出一份机器可读的 `doc-debt.json`（doc-id、owner、stale 原因、过期天数），存 `.evidence/doc-debt/`（本地，不入库；格式沿用 §20 的 evidence 绑定思想：带生成时间和 source revision）。
- 人类可读摘要并入现有的 Nexus Feature 看板刷新节奏（每 3 天）：只有"新增 STALE 文档"或"文档被删除"时才通知用户，无变化静默。
- Doc debt 不设"清零 KPI"——目标是"没有不知道自己过时的文档"，不是"零 STALE"。

---

## 8. 从现状迁移路线图

现状：大部分文档无 frontmatter、无 owner、部分已确认过时（如需求变更前的设计文档）。分四阶段迁移，不停工、不搞大跃进：

### P0：清点（1-2 天，单 agent）

- 扫描全仓库 `*.md`，输出清单：路径、是否有 frontmatter、最后修改时间、疑似所属层。
- 标记"已确认过时"的文档（需求变更前的设计稿），移入 `docs/archive/<日期>/`（参照 evidence-archive 惯例：归档不删除，ID 可引用）。
- 输出：`docs/DOC-AUDIT-BASELINE.md`（一次性基线，之后不再维护）。

### P1：立规矩（2-3 天）

- 新建 `docs/adr/`，写第一条 ADR：`0001-doc-architecture.md`（本文的决策记录）。
- 给所有 L1/L2 现存文档补 frontmatter（`last-verified` 填补写当天的实际检查日期——**不许批量填当天糊弄**，没检查过的填 `status: stale`）。
- 新建生成器脚本 `engineering/docgen/`（manifest + skills-index），L4 文件加生成标记，接 pre-commit。
- 现存 6 个 skill 的 `sh verify` 代码块 retrofit：按 §3 L2 硬规则，把操作步骤改写为 ` ```sh verify ` 标记的可执行代码块（散文描述步骤视为未完成）。预估工作量 0.5–1 天。

### P2：接门禁（3-5 天）

- pre-commit：生成文件手改拦截、AGENTS.md 引用检查、API 变更 warning（前置：`cargo public-api` 引入需先过 §18 依赖评审，未通过前用 rustdoc JSON diff，见 §5 工具链说明）。
- CI：每周 `doc-freshness` STALE 扫描 + skill 命令自检。
- `.evidence/doc-debt/` 输出 + 看板通知接线。

### P3：跑起来（第一个季度）

- 按 §6 跑第一次正式 doc audit。
- 按 §5 的约定评估 API 检查误报率，决定是否升级为阻断。
- 复盘：哪些机制没触发过、哪些是噪音，记 ADR 调整。

**P0-P2 期间新文档**：直接按新规范写（带 frontmatter），不参与迁移。

---

## 9. 与现有机制的衔接点

| 现有机制 | 衔接方式 |
|---|---|
| AGENTS.md §20 Evidence Freshness | STALE 思想复用；但文档 STALE **不阻塞 push**（证据 STALE 阻塞，二者分开） |
| AGENTS.md §19.2 动态知识库 | 即 L3 的一半；补充 `decision` 分类 + ADR 目录 |
| AGENTS.md §29 多 Agent 协作 | owner 身份值沿用 `NEXUS_AGENT` 命名空间；doc audit 任务分配走 §29 的 worktree 隔离 |
| `nexus-review` skill | L1/L2 文档的季度复核可复用 review 的"独立执行者"思想：owner 自查 + 交叉抽查 |
| `nexus-multiagent` skill | doc audit 的多 owner 并行即多 agent 协作场景，直接套用 |
| `.githooks/` | 新增检查进现有 pre-commit，不另起 hook 框架 |
| STALE evidence 归档惯例 | `docs/archive/` 沿用 `evidence-archive/` 的"归档不删除"惯例 |

---

## 10. 非目标

- 不做文档站点/主题化渲染（当前阶段不需要）。
- 不做全文搜索（仓库内 grep 足够）。
- 不强制文档覆盖率指标（"每个函数都要有文档注释"是腐烂加速器）。
- 不追溯重写历史文档——P0 只归档不清算。
