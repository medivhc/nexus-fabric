# AGENTS.md

> 适用范围：Nexus 仓库中的所有编码 Agent。
> 方法论：Agent-Native Engineering System。
> 核心原则：
>
> **仓库即 API；Agent 必须通过显式契约、机器约束、快速反馈、独立验证和持久化证据来工作。**



***

## 1. 使命

你的任务不是 “写出看起来正确的代码”，而是交付一个同时满足以下条件的变更：



* 与产品契约和架构契约一致；

* 只影响预期模块与允许的依赖边界；

* 可以被机器验证；

* 当用户可见行为发生变化时，可以从产品边界观察和验证；

* 在会话中断、进程崩溃或 Agent 切换后可以恢复上下文；

* 有与当前 revision、工作区状态和配置绑定的最新 Evidence 支撑。

编码 Agent 可以提出方案并实现代码，但**不能自行认证最终完成**。

统一工程闭环：



```
任务

&#x20; ↓

项目契约

&#x20; ↓

最小必要上下文

&#x20; ↓

实现

&#x20; ↓

受影响范围验证

&#x20; ↓

独立验证

&#x20; ↓

Evidence

&#x20; ↓

Verdict
```

Agent 最多只能提交：



```
Candidate Completion
```

最终完成必须由 Harness / Verifier 产生。



***

## 2. 真相来源

理解项目时，不要首先从实现代码猜行为，而应优先读取仓库中的正式契约。

默认读取顺序：



```
任务 / 用户显式需求

&#x20; ↓

PRODUCT.md

&#x20; ↓

ARCHITECTURE.md

&#x20; ↓

相关 crates/\<crate>/MODULE.md

&#x20; ↓

相关 Public API

&#x20; ↓

相关 Tests / Scenarios

&#x20; ↓

Implementation
```

同时根据需要查看：



* `DEVELOPMENT.md`：开发流程、验证方式、Evidence 规则；

* `harness.toml`：机器可读工程配置；

* `policies/`：架构、依赖、质量门禁；

* `scenarios/`：产品级 E4 场景契约；

* `.evidence/`：历史验证状态与最新 Evidence；

* `engineering/`：Harness 和工程工具实现。

以下内容不能高于正式契约和最新 Evidence：



* README 中的非规范性描述；

* 代码注释；

* Agent 历史对话；

* 旧测试输出；

* 过期 benchmark；

* 未绑定当前 revision 的 “测试通过” 记录。



***

## 3. 仓库即 API

不要默认从 “阅读整个仓库” 开始。

优先使用稳定工程入口：



```
nexus-harness status

nexus-harness context \<target>

nexus-harness check

nexus-harness test affected

nexus-harness verify --fast

nexus-harness verify --full

nexus-harness explain
```

如果工具支持机器模式，优先使用：



```
\--json
```

不要在存在结构化接口时依赖解析：



* ANSI 彩色终端；

* 不稳定表格；

* 自由文本长日志；

* 易变化的人类可读输出。

Agent 获取上下文时应只获取当前任务所需信息：



```
模块职责

边界与不变量

Public API

Allowed / Forbidden Dependencies

相关 Tests / Scenarios

最近相关失败

可写路径

Protected Paths
```

目标不是 “给 Agent 更多文本”，而是**降低理解成本和无关上下文**。



***

## 4. 任务分类

在修改任何文件前，先确定任务类型：



```
feature

bugfix

refactor

test

docs

performance

dependency

requirement-change
```

不同任务类型拥有不同的允许变更范围和验证要求。

### feature

必须遵循：



```
Contract-First

→ Red Evidence

→ Spec-Freeze

→ Implementation
```

不能先写实现再补契约。

### bugfix

默认保持产品契约和 Scenario expectation 不变。

应尽可能增加最小 Regression Test / Regression Scenario。

### refactor

产品外部行为默认不得变化。

现有 Product Scenario expectation 视为 Protected。

### test

测试不能被用于静默重新定义产品行为。

如果产品预期本身要变化，任务类型必须切换为：



```
requirement-change
```

### docs

文档不能与当前机器约束、架构 Policy、实际产品行为矛盾。

### performance

必须定义明确 Performance Budget，并生成 benchmark Evidence。

### dependency

新增或修改依赖必须通过：



```
architecture review

feature review

license review

security review

portability review

supply-chain review
```

### requirement-change

这是正常情况下唯一允许主动修改已冻结 Product / Scenario expectation 的任务类型。

一旦需求变化：



```
旧 Evidence → STALE
```



***

## 5. Contract-First / Spec-Freeze

对于新的用户可见 Feature 或需求变化，不允许直接进入业务代码实现。

### 阶段 A：契约阶段

依次完成：



1. 修改相关 `PRODUCT.md` / `MODULE.md`；

2. 新增或修改 `scenarios/`；

3. 在旧实现上执行 Scenario；

4. 得到明确的：



```
FAIL

或

BLOCKED
```

作为 Red Evidence；

5\. 冻结：



* Scenario expectation；

* requirement mapping；

* 用户可观察语义；

* 相关模块不变量；

1. 生成 Contract Hash 或等价 revision marker。

### 阶段 B：实现阶段

契约冻结后：



* 冻结的 Scenario expectation 自动成为 Protected；

* 实现 Agent 只能修改业务代码使 Scenario 通过；

* 禁止为了让实现变绿而修改 expected value；

* 如果发现契约本身错误，必须停止 Implementation；

* 切换到：



```
requirement-change
```

重新建立 Red Evidence 和新的 Contract Hash。

这是 Nexus 中解决 “Agent 自己写实现、自己改验证标准、自己宣布完成” 的核心制度。



***

## 6. 不可自证原则

Agent 可以声明：



```
Candidate Completion
```

Agent 不得声明：



```
Final PASS
```

最终 PASS 必须来自 Harness / Verifier 产生的最新 Evidence。

以下任何一项都不能单独代表 “完成”：



```
代码已经存在

cargo check 通过

unit test 通过

README 写着 completed

coverage 很高

Agent 说已经完成
```

Evidence 强度统一定义为：



```
E0  断言 / 文件存在 / 符号存在

E1  静态检查

E2  单元测试 / 局部行为测试

E3  集成测试

E4  产品级 Scenario

E5  独立外部观察
```

关键用户可见 Capability 原则上至少需要：



```
E4
```

或者更强的 E5 Evidence。



***

## 7. Protected Paths 与测试完整性

以下路径默认视为高信号契约：



```
PRODUCT.md

ARCHITECTURE.md

policies/

scenarios/

crates/\*\*/MODULE.md

DEV-ENV.md
```

Implementation Phase 中：



* 冻结 Scenario expectation 为 Protected；

* 冻结 Module Invariant 为 Protected；

* 实现 Agent 不得静默修改这些标准。

允许：



* 新增测试；

* 新增 Regression Test；

* 补充边界案例；

* 增加更严格验证。

禁止：



* 删除失败测试以使 CI 通过；

* 修改 expected value 迎合当前实现；

* 降低 timeout /threshold 语义以隐藏失败；

* 把失败 Scenario 改成 skip；

* 把产品错误改写成 “预期行为”。

如果实现看起来必须改变 Protected Contract 才能完成：



```
停止实现

→ 报告 Contract Conflict
```

不能自行解除保护。



***

## 8. 模块契约

每个核心 crate 都应维护：



```
MODULE.md
```

修改模块前必须先读取其 MODULE Contract。

标准字段：



```
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

文本契约不能代替硬门禁。

真正边界应同时存在于：



```
Cargo dependency graph

policies/

CI

tests

scenarios
```

新增依赖时：



1. 判断是否违反层级；

2. 判断是否需要更新 `policies/architecture.toml`；

3. 判断 MODULE / ARCHITECTURE 是否需要同步修改；

4. 运行 dependency + architecture gate。



***

## 9. 核心架构不变量

除非当前任务明确是架构变更，否则不得破坏以下约束。

### 核心领域



```
Resource != Provider

Provider != Node

Identity != Locator

Plan != Session

Measurement != Score

Policy != Path

Planner != Estimator

Planner != Scheduler

TerminalOutcome != LifecyclePhase

Portable Core != Platform Runtime
```

### 规划与建连时序

必须保持：



```
Resolve Candidate Providers

&#x20; ↓

Plan Placement + Path

&#x20; ↓

Create Session

&#x20; ↓

Establish Connectivity

&#x20; ↓

Execute
```

禁止：



```
先对所有候选打洞 / 建连

再决定 Plan
```

### Core Planner

全系统只有一个系统级 Core Planner。

领域局部组件可以是：



```
Estimator

Evaluator

Scheduler
```

但不能产生第二套系统级 Plan。

### Plan

Core `Plan` 必须保持领域中立。

领域特定数据只能进入类型化、版本化的：



```
NetworkPlanExtension

WorkspacePlanExtension

ComputePlanExtension

ServicePlanExtension
```

### Delivery Infrastructure

Connectivity 与 Transport 是共享底座：



```
Network

Service

Workspace

Compute
```

都通过 Delivery Infrastructure 使用远端资源。

禁止让 Delivery 反向依赖：



```
Workspace

Compute

Service business logic
```



***

## 10. Ingress 的所有权

`nexus-ingress` 是系统级、可移植的输入组件。

它可以负责：



```
SOCKS5 protocol state machine

HTTP Proxy protocol state machine

Packet / Stream decode

Flow classification

FlowContext construction
```

它不能：



* 直接调用 Core Planner；

* 成为 `nexus-network` 的私有子模块；

* 直接持有平台特有透明拦截实现；

* 直接调用 Linux / Windows /macOS/ Android /iOS 的专有拦截 API。

正确驱动链：



```
Ingress

&#x20; ↓

Application Service / SessionManager

&#x20; ↓

Policy

&#x20; ↓

Core Planner

&#x20; ↓

Session Runtime

&#x20; ↓

Network Runtime
```

平台透明拦截必须放在：



```
nexus-platform-\*
```

通过 capability adapter 注入。



***

## 11. Portable Core 与平台代码

Portable Core 不允许直接调用平台 API。

平台能力通过 trait 注入，由 Composition Root 装配。

平台相关实现集中在：



```
nexus-platform

nexus-platform-linux

nexus-platform-windows

nexus-platform-macos

nexus-platform-android

nexus-platform-ios

platform composition roots
```

Portable Core 中禁止直接依赖：



```
Linux-only API

Win32

Android framework API

Apple NetworkExtension API

平台 mount API

平台 secure-store API
```

Portable crate 必须继续通过配置好的：



```
WASI

或等价非桌面宿主 portability gate
```



***

## 12. 新抽象必须通过 Deletion Test

新增 trait /interface/adapter 前必须回答：

> 如果删除这个抽象，直接依赖当前实现，会破坏哪个已经存在的独立变化维度？

合理理由包括：



```
多个真实平台实现

可移植性边界

安全边界

生命周期边界

有独立价值的测试替身

依赖反转

可独立替换 Provider / Adapter
```

以下理由不充分：



```
以后可能会用

感觉更优雅

所有 struct 都应该有 trait

为了架构看起来完整
```

默认倾向：



```
更少但真实的抽象
```

而不是推测性设计。



***

## 13. 结构化并发

不允许创建没有 Owner 的长期异步任务。

任何长期任务必须能回答：



```
谁创建？

谁拥有？

谁取消？

谁回收？

谁记录结果？
```

推荐模型：



```
Owner

&#x20;├─ CancellationToken

&#x20;├─ JoinSet

&#x20;│   ├─ Worker

&#x20;│   ├─ Worker

&#x20;│   └─ Worker

&#x20;└─ Reaper
```

语义：



```
CancellationToken

\= 请求协作式停止

AbortOnDropHandle

\= Owner 消失时防止任务泄漏

JoinSet + Reaper

\= 确认任务真正结束并消费结果
```

禁止：



```
tokio::spawn(...)

然后丢弃长期任务 JoinHandle
```



***

## 14. Exactly-One Terminal Outcome

必须把 “业务结果” 和 “资源释放状态” 分开。



```
LifecyclePhase:

Allocating

Active

Draining

Disposed

TerminalOutcome:

Unfinished

Completed

Failed

Cancelled
```

规则：



* `Completed / Failed / Cancelled` 最多只能提交一次；

* Worker 不允许直接修改 TerminalOutcome；

* Worker 只发送 Event；

* Owner State Machine 是唯一 Outcome Writer；

* Outcome 确定后仍可继续执行 cleanup；

* 资源物理生命周期最终进入：



```
Disposed
```

禁止用多个互相松散的 bool 表示生命周期。



***

## 15. Crash Consistency

不能假设 Graceful Shutdown 一定执行。

系统必须能够面对：



```
panic

process crash

SIGKILL

OOM kill

mobile OS termination

device restart

power loss
```

有持久状态的关键路径必须使用必要的：



```
journal

write-ahead marker

durable metadata
```

冷启动必须先执行 Reconciliation，再接受新任务。

典型顺序：



```
加载 durable state

&#x20; ↓

重放 / 验证 journal

&#x20; ↓

reconcile session

&#x20; ↓

reconcile workspace heads

&#x20; ↓

reconcile compute jobs / artifacts

&#x20; ↓

清理或重建 orphan OS resources

&#x20; ↓

重新发布 Provider Presence

&#x20; ↓

accept new work
```

所有 cleanup /reconciliation 必须幂等。



***

## 16. Workspace 不变量

Workspace 权威数据：



```
WorkspaceId

Commit DAG

Head Set

Namespace / Manifest

Object / Chunk CAS

Replica Set
```

禁止重新退回到：



```
一个可变整数 Generation
```

作为唯一版本真相。

离线写：



```
Base Commit

&#x20; \+

ChangeSet

&#x20; ↓

Immutable Local Commit

&#x20; ↓

Local Head Set
```

多个节点离线修改时允许产生多个 Head。

重新联网后：



```
Common Ancestor

&#x20;\+ Local Head

&#x20;\+ Remote Head

&#x20; ↓

Fast-forward

或

Three-way Merge

或

Explicit Conflict Resolution

&#x20; ↓

Merge Commit
```

已经成功提交的本地数据不能因为远端 Head 前进而被静默丢弃。



***

## 17. Workspace 存储纪律

不可变 CAS 不意味着本地无限保留。

GC Protected Roots 包括：



```
当前有效 Heads

显式保留 Snapshot

未合并 / Conflict 分支

Active Compute Snapshot

Pending Artifact

Explicit Pin

Durability Required Roots
```

只有：



```
不可达对象

\+

超过安全保留期
```

才允许进入 GC。

受限平台需要支持：



```
Storage Quota

Shallow Sync

Sparse Replica

WorkingSet Materialization

Background Compaction

Reachability GC
```

注意：



```
Cache Eviction != CAS GC
```

CacheManager 不能删除仍然具有权威可达性的对象。



***

## 18. Rust 质量规范

### API Surface

优先级：



```
private

→ pub(crate)

→ pub
```

公共 API 越小，Agent 可误用状态空间越小。

### Error

正常业务失败使用：



```
Result

typed error enum
```

不要用 panic 表示可恢复业务失败。

Error 应保留足够信息支持：



```
Retry

Fallback

Abort

Ignore

Escalate
```

### Unsafe

`unsafe` 必须：



* 集中到最小模块；

* 显式写 Safety Invariant；

* 有专项测试；

* 适合时增加 fuzz /property test；

* 不把 unsafe responsibility 无必要地传播到上层。

### Dependency

第三方依赖优先：



```
default-features = false
```

只开启实际需要 feature。

新增依赖时至少检查：



```
架构层级

OS-specific transitive dependency

WASI / portability

license

security advisory

feature expansion

更小替代方案
```



***

## 19. 标准验证流程

修改后首先运行：



```
nexus-harness check

nexus-harness test affected

nexus-harness verify --fast
```

Fast Verify 通过后，必须执行**独立 Review**（详见 §19.1）：

- 由独立于实现的执行者完成八个维度的审查
- 输出 Review Evidence 到 `.evidence/review-<id>/`
- Verdict = APPROVED / COMMENTED 后才能进入 Full Verify
- Verdict = CHANGES_REQUESTED 时必须修改后重新走 fast verify + Review

准备 Candidate Completion 前运行：



```
nexus-harness verify --full
```

Fast Gate 目标：



```
format

check

clippy -D warnings

architecture delta

dependency delta

affected tests

selected properties
```

Full Gate 至少覆盖：



```
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

禁止通过削弱 gate 来解决失败。



***

## 19.1 独立 Review（Independent Review）

自动化验证回答"代码对不对"，独立 Review 回答"代码好不好、全不全、有没有踩坑"。

### 独立性规则

- Review 执行者必须独立于实现执行者。
- 同一个 Agent 会话中刚写完代码，不能紧接着自己写 Review 报告。
- Review 报告的 `reviewer` 字段必须填写独立执行者标识（Agent 会话 ID 或人工姓名）。

### 八个检查维度

```
1. 契约一致性（contract-consistency）
   - 实现是否严格遵循 MODULE.md 的 Invariants 和边界
   - Scenario expectation 是否被静默修改以迎合实现

2. 边界覆盖（edge-coverage）
   - 错误路径是否完整覆盖
   - 状态转换是否完备
   - 资源释放是否正确

3. API 面控制（api-surface-minimization）
   - 是否有不该暴露为 pub 的类型 / 函数
   - 是否把 pub(crate) 偷偷提升成了 pub

4. 依赖边界（dependency-boundary）
   - 是否引入了 policies/architecture.toml 未声明的内部依赖
   - 是否违反了层级约束

5. 错误处理质量（error-handling-quality）
   - 正常业务失败是否用类型化 Result 而不是 panic / unwrap
   - 错误类型是否保留足够上下文

6. 测试质量（test-quality）
   - 测试是否真实验证了行为，而不是只测 happy path
   - 新增的测试是否覆盖了本次变更引入的新代码路径

7. 复杂度控制（complexity-control）
   - 是否有过度设计
   - 新增的 trait / 接口是否过了 Deletion Test

8. 可观测性（observability）
   - 关键路径是否有结构化事件 / 日志
   - 是否有必要的关联字段
```

### Verdict 语义（量化）

每个维度的状态为 PASS / WARN / FAIL，最终 Verdict 由最差维度决定：

```
APPROVED           0 个 FAIL，0 个 WARN（或只有非阻塞建议），可以进入 verify --full
CHANGES_REQUESTED  ≥ 1 个 FAIL，必须修改后重新走 fast verify + 再次独立 Review
COMMENTED          0 个 FAIL，≥ 1 个 WARN，有建议但不阻塞，记录在案即可
BLOCKED            发现契约冲突，需要切换到 requirement-change 流程
```

### 迭代闭环（必须显式记录）

Review 不是一次性的，必须形成"检查 → 修正 → 再检查"的迭代循环：

```
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

### 输出：Review Evidence

Review 完成后，在 `.evidence/review-<id>/` 下生成：

```
summary.json      Review verdict + 维度结果 + 阻塞项 + 建议 + 上一轮对比
findings.md       详细的 Review 意见（可读形式）
```

summary.json 必须包含：

```json
{
  "review_round": 2,
  "previous_review_id": "review-vsub01",
  "dimension_changes": {
    "edge-coverage": "FAIL → PASS",
    "test-quality": "WARN → PASS",
    "observability": "WARN → WARN"
  },
  "dimensions": [
    { "name": "edge-coverage", "status": "PASS", "findings": [...] }
  ],
  "blocking_issues_fixed": ["..."],
  "blocking_issues_remaining": []
}
```



***

## 19.2 动态知识库（Dynamic Knowledge Base）

每个项目都应该有一个持续积累的知识库，把踩坑、模式、教训沉淀下来，避免重复犯错。

### 位置

```
.agents/knowledge/
├── README.md         说明文档
├── index.json        条目索引（按 id / module / category 索引）
└── entries/          条目存放
    └── YYYY-MM-DD-<slug>.md
```

### 写入触发点

- Review 发现问题并修复后
- 实现过程中踩坑并解决后
- 完成一个重要 feature 后
- 发现可复用的实现模式后

### 读取触发点

- 任务开始前（检索是否有相关历史经验）
- 遇到类似问题时
- Review 时（对照历史踩坑清单）

### 条目格式

```markdown
---
id: <short-id>
date: YYYY-MM-DD
module: <crate-name>
category: implementation-pitfall | implementation-pattern | architecture-decision
task_type: feature | bugfix | refactor | ...
---

# 标题

## 问题/模式描述

## 原因分析

## 解决方案

## 教训/可复用要点
```



***

## 20. Evidence Freshness

Evidence 必须绑定当前工程状态。

至少包含：



```
source revision

working tree digest

dirty state

configuration digest

feature set

target triple

toolchain version

harness schema version

platform capability digest

contract hash
```

任意会影响结论的输入发生变化：



```
旧 Evidence → STALE
```

禁止把 STALE Evidence 当作当前完成证明。



***

## 21. 性能规范

不要优化模糊的 “更快”。

关键路径必须定义：



```
baseline

noise tolerance

warning threshold

blocking threshold
```

优化优先级：



```
算法

→ 架构

→ 减少 I/O / syscall

→ batching

→ allocation / copy

→ lock contention

→ cache locality

→ micro-optimization
```

Performance Task 没有 benchmark Evidence 时不能宣告完成。



***

## 22. Observability 与 Replay

结构化可观测字段属于工程接口。

优先使用：



```
Event / Log

Trace / Span

Metric
```

常用关联字段：



```
request\_id

session\_id

node\_id

provider\_id

connection\_id

path\_id

task\_id

workspace\_id

commit\_id
```

Hot Path 默认禁止无节制：



```
per-packet log

per-frame log
```

高频观测应优先：



```
counter

histogram

sampling

aggregation
```

遇到 Planner / Connectivity / Session / Recovery 的非确定性问题时，优先：



```
record

→ replay
```

不要持续靠猜测性修改碰运气。



***

## 23. Working Tree 纪律

不得破坏与当前任务无关的用户工作。

大范围修改前：



1. 查看当前 revision；

2. 查看 dirty state；

3. 确定哪些改动在当前任务之前已存在；

4. 不要 reset /checkout/revert /delete 与任务无关的修改；

5. 不要顺手格式化整个仓库；

6. 不要无必要更新 lockfile；

7. 不要随意覆盖历史 Evidence。

如果无法判断文件归属：



```
报告歧义
```

不要猜测。



***

## 24. 失败处理

Gate 失败时，不要直接对日志进行随机修改。

先判断：



```
什么失败？

为什么失败？

期望是什么？

实际是什么？

涉及哪个模块？

哪些文件最可能相关？

Evidence 是否 fresh？

这是：

&#x20; Implementation Failure？

&#x20; Contract Conflict？

&#x20; Environment Failure？

&#x20; Unsupported Capability？
```

工具可用时优先：



```
nexus-harness explain --json
```

禁止：



```
连续修改多个无关位置

希望测试“碰巧变绿”
```



***

## 25. Stop Conditions

遇到以下情况必须停止实现并报告：



* Product Contract 与 Scenario 冲突；

* `MODULE.md` 与机器 Architecture Policy 冲突；

* 必须修改 Frozen Expectation 才能实现；

* 新依赖会产生未批准的架构边；

* Portable Core 被迫直接调用平台 API；

* 唯一通过方式是删除或削弱独立验证；

* 环境缺失导致无法产生 fresh Evidence；

* 用户可见 Feature 没有合理产品级验证路径；

* Workspace 修改可能删除仍可达或未合并的数据；

* 并发设计无法确定 TerminalOutcome 唯一 Owner；

* 新持久状态没有 Crash Recovery 语义。

这时应返回：



```
BLOCKED

或

UNKNOWN
```

而不是虚构 PASS。



***

## 26. 任务完成报告

编码任务结束时，用简洁格式报告：



```
任务类型：

修改模块：

修改契约：

修改实现：

新增/修改 Tests / Scenarios：

Fast Verification：

Full Verification：

Evidence ID / Path：

Evidence Freshness：

剩余风险 / Blocker：

Candidate Completion：yes / no

Final Verdict：仅 Harness 可决定
```

如果 Full Verification 没有产生适当且 fresh 的 Evidence，不要写：



```
done

complete

finished
```



***

## 27. 默认决策原则

当存在多个合理实现时，优先选择能够降低以下成本或提高以下能力的方案：



```
理解成本

约束强度

反馈速度

验证独立性

状态恢复能力

Evidence 质量
```

但不能通过增加不必要 abstraction 或第二套工程系统来实现。

最终目标不是：

> 让 Agent 足够强大，从而可以无视项目结构。

而是：

> 让仓库结构、契约、验证和证据系统足够清晰，使一个上下文有限、概率性的 Agent 仍然能够反复交付可信的工程结果。



***

## 28. Hooks 与 Skills（项目级机制）

把上述文本契约机器化的两套项目级机制：

### Git Hooks（机器强制门禁）

位于 `.githooks/`（激活：`git config core.hooksPath .githooks`，或运行 `.githooks/install.ps1` / `install.sh`）：



```
pre-commit  → whitespace 检查；暂存含 .rs 时 cargo fmt --check；受保护路径变更告警

commit-msg  → subject 必须为 \<type>(\<scope>): \<summary>，type ∈ 任务类型表；

&#x20;             受保护路径变更必须在正文携带 contract: \<hash> 或 requirement-change: \<hash>

pre-push    → nexus-harness verify --fast 不得 FAIL/BLOCKED；STALE Evidence 阻止推送；

&#x20;             推送区间修改受保护契约路径必须带 contract marker
```



* `--no-verify` 可绕过，但绕过不产生任何证据，仍不得声明 Final PASS。

* 门禁的机器可读声明见 `harness.toml [hooks]`；本地与 CI 使用同一 Gate 定义。

### 项目级 Agent Skills

位于 `.agents/skills/`（任务开始时按匹配读取对应 `SKILL.md`）。
完整索引见 `harness.toml [skills]` 与 `.agents/skills/README.md`。

## 29. 多 Agent 协作约定（Multi-Agent Collaboration）

多个 Agent（豆包会话、CI、远端流程）并行修改同一仓库时的冲突治理。核心：
**域隔离降冲突概率，命名空间消除证据互踩，rebase 让冲突只在同步时刻暴露一次。**

> 本节的 ownership 表、身份值、同步节奏均为**默认分工建议，不是权限约束**。
> 机器门禁（§28）不检查"谁改了什么域"；单 Agent 场景可完全忽略本节，
> 多 Agent 并发的价值在于减少 rebase 冲突，而非限制改动。

### 29.1 crate 归属（ownership）

为降低并行冲突概率的默认分工建议：每个 Agent 建议固定负责一个（或多个）域，
避免并行任务触碰同一 crate 的文件；`apps/nexus/src/lib.rs` 与 `MODULE.md` 类共享
文件视为高冲突区，改动前先同步。**跨域改动无需申请**，只需留意同步节奏（29.3）。
owner 列给出推荐的身份值（见 29.2），未分配 Agent 的 crate 先归入其依赖关系
最近域的 owner，并在表中补记。

| 归属域（推荐身份值） | 路径 | 说明 |
|---|---|---|
| 身份与领域（`agent-a`） | `crates/nexus-auth/`、`nexus-registry/`、`nexus-domain/`、`nexus-discovery/`、`nexus-policy/`、`nexus-plugin/`、`nexus-storage/` | 授权/目录/领域模型/发现/策略/插件/持久层 |
| 会话与调度（`agent-b`） | `crates/nexus-session/`、`nexus-planner/`、`nexus-flow-session/`、`nexus-scheduler/`、`nexus-service/`、`nexus-diagnostics/`、`nexus-connectivity/` | 会话/规划/流会话/调度/服务/诊断/连接管理 |
| 代理栈（`agent-c`） | `crates/nexus-proxy/`、`nexus-proxy-config/`、`nexus-proxy-transport/`、`nexus-network/`、`nexus-path/`、`nexus-ingress/`、`nexus-dns/`、`nexus-delivery/`、`nexus-projection/`、`nexus-compute/`、`nexus-control-api/`、`nexus-measurement/` | 代理/配置/路由/入口/解析/投递/投影/计算/控制面 |
| 传输与穿透（`agent-d`） | `crates/nexus-transport/`、`nexus-nat-traversal/`、`nexus-nat-wireup/`、`nexus-nat-quality/`、`nexus-turn/`、`nexus-outbound-shadowsocks/`、`nexus-outbound-trojan/`、`nexus-outbound-vmess/`、`nexus-proto/` | 传输/内网穿透/中继/出站协议/Proto |
| 平台与基础设施（`agent-e`） | `crates/nexus-platform/`、`nexus-platform-android/`、`nexus-platform-ios/`、`nexus-platform-linux/`、`nexus-platform-macos/`、`nexus-platform-windows/`、`nexus-workspace/`、`nexus-workspace-intel/`、`nexus-fabric/` | 平台适配/工作区/仓储自身 |
| 组装层（`agent-c`） | `apps/nexus/`、`apps/nexusd/`、`apps/nexus-platform-host/` | CLI/daemon/平台宿主：改动最易冲突，先同步再改 |
| 工具链 | `engineering/`、`.githooks/`、`.agents/` | harness/hooks/skills（低冲突） |
| 共享 | `scenarios/`、`policies/`、`*.MODULE.md`、`PRODUCT.md` | 契约文件：冻结先行，改动走 requirement-change + contract marker（§7） |

### 29.2 Evidence 命名空间（NEXUS_AGENT）

- 身份值**可任意设置**（`[A-Za-z0-9_-]`，≤32 字符），不必须来自 29.1 表；
  表的推荐值只是省得想名字。唯一硬约束是**并发时不撞名**（同一时间一个值只
  被一个运行中的 Agent 使用；撞名会导致证据目录互相覆盖）。
- 长期协作的 Agent 建议固定一个身份值用到底（可取自表，也可自定后登记入表）；
  临时并发 Agent 建议用唯一可识别的名字（如 `agent-review-r2`）。
- 换域不换身份；换身份的唯一理由是撞名或弃用。
- 每个 Agent 设置环境变量 `NEXUS_AGENT=<name>`（`[A-Za-z0-9_-]`，≤32 字符）。
- verify 证据目录：`verify-<agent>-<hash>`；review 证据目录：
  `review-<scope>-<agent>-r<n>`。
- harness 的 STALE 标记只作用于**同 agent** 的证据；跨 agent 证据互不干扰
  （Agent B 的 verify 不会把 Agent A 的证据标 STALE）。
- hooks（pre-commit/pre-push）的 STALE 扫描与 Review 检查按当前 `NEXUS_AGENT`
  限定范围；未设置时兼容单 Agent / CI（扫描全部）。
- 未设置 `NEXUS_AGENT` 视为单 Agent 模式（行为与历史一致）。

### 29.3 同步与推送（nexus-sync）

每个 Agent push 前固定执行（脚本 `./nexus-sync.sh` / `nexus-sync.ps1`）：

```
git fetch origin
git rebase origin/master      # 线性历史；冲突在此显式解决（§17：FF/3-way/显式冲突，已提交数据不静默丢弃）
nexus-harness verify --fast   # 在最新 base 上生成绑定当前 revision 的证据
git push origin $(git branch --show-current)   # 只推自己的任务分支，禁止直推 master（§30）
```

规则：
- 统一用 rebase 而非 merge（线性历史，冲突一次解决）。
- 冲突解决是显式协议，不是自动丢弃；rebase 中断时禁止 `--abort` 以外的破坏性操作。
- 小步单主题提交；一个逻辑变更一个 commit，避免长分支。
- master 只经 Pull Request 由 coordinator 合并（§30）；任何 Agent 不得 `git push origin master`，分支保护会在机械层面拒绝。
- 契约文件（29.1 共享列）改动必须携带 contract marker 并由 owner 评审后合入。

### 29.4 CI 建议

master 启用 branch protection：required status check（CI 跑 `verify --fast`）、
linear history（禁 merge commit）、require up-to-date。CI 的 evidence 由远端生成，
本地证据不再成为推送阻塞；本地 `NEXUS_AGENT` 用于区分各 Agent 的证据命名空间。

### 29.5 沙箱并行工作区建议（worktree 模式）

多个 Agent 在同一沙箱机器上并行开发同一仓库时的推荐布局：**每个 Agent 一个
独立 worktree + 独立分支**，文件系统级隔离，编辑/构建/测试互不阻塞
（共享同一 `.git` 对象库，磁盘只存一份历史）：

```
cd nexus-fabric
git worktree add -b feat/a-registry ../ws-a     # Agent A：只碰 29.1 表中自己的域
git worktree add -b feat/b-session  ../ws-b     # Agent B
git worktree add -b feat/c-proxy    ../ws-c     # Agent C
```

每个 worktree 的启动配方（四步）：

| 项 | 做法 | 效果 |
|---|---|---|
| 目录 | 自己的 worktree（`ws-a` / `ws-b` / …） | 并行编辑不冲突 |
| 身份 | `export NEXUS_AGENT=<唯一值>`（推荐取 29.1 表值，也可自定） | 证据写入 `verify-<agent>-*`，互不覆盖、互不误标 STALE |
| 构建 | `export CARGO_TARGET_DIR=$PWD/target`（每 worktree 独立） | 并行 cargo 无锁等待、不挤同一磁盘 |
| 凭证 | 每 Agent 独立 PAT，`git -c url."https://oauth2:<token>@github.com/".insteadOf=...` 单命令注入，用后即删 | remote 永不落盘凭据，token 泄露不牵连他人 |

节奏：并行开发期间各 Agent 互不相见，唯一汇合点即各自 push 前的
`nexus-sync`（29.3）；ownership 域隔离使 rebase 大概率无事发生，
冲突只在同步时刻暴露并显式解决。

已知缺口（需另行约定，尚未机器化）：
- 跨沙箱 Review 证据不互通：`.evidence/` 为 gitignore 的本地目录，独立 Review
  （§19.1）的产物只存在于评审方沙箱，提交方 push 时看不到。建议约定评审结论以
  marker 形式进 commit 正文（如 `review: <id>`）并由 hook 校验，或由 CI 存档评审产物。
- branch protection 因私有库 + 非 Pro 账号暂无法开启，见 §30.3 现状说明。
***

## 30. 分支与合并工作流（Trunk-Based，GitHub）

`master` 是唯一长期分支，必须始终保持可构建、可验证。所有变更走短命任务分支 +
Pull Request 合并；直推 `master` 是违规行为（目标：GitHub 分支保护，见 §30.3）。

### 30.1 分支

- `master`：唯一长期分支，受分支保护（§30.3）。
- 任务分支：`task/<run-id>-<slug>`（沿用 `feature/`、`bugfix/`、`docs/` 前缀亦可），
  一个 pipeline run 对应一个分支，生命周期 = 任务周期，合并后删除。
- 禁止长期并存的 `develop` / `release` 分支；发版用 tag 打在 `master` 上。

### 30.2 合并流程（coordinator 专属）

```
Agent：任务分支上完成实现 → 独立评审 → 修复 → 复验（§19 / §19.1）
  → push 任务分支（§29.3）
  ↓
Coordinator：开 PR（描述自动填：任务原文、spec/contract hash、评审 verdict、evidence 链接）
  ↓
门禁：PR 已 rebase 到最新 master；verify --fast 在最新 base 上为 PASS（pre-push 门禁同样适用）
  ↓
Coordinator：squash merge → 删除任务分支（仓库已开 delete_branch_on_merge）
```

- 一次只合并一个 PR，串行化；冲突在合并时刻显式解决（§17 / §29.3）。
- squash merge：一个任务在 `master` 上为一个 commit，回滚是一条 `git revert`。
- PR **不需要人工评审**：pipeline 内的独立评审（不同模型/会话，§19.1）即评审，
  PR 是机械门禁与审计容器。用户日常不看 PR，看 coordinator 报告与 evidence。

### 30.3 分支保护（`master`）

目标态（GitHub 分支保护）：
- Require a pull request before merging：禁止一切直推（含 admin）。
- Require linear history：rebase / squash 合并，禁 merge commit。
- 暂不开 required status checks：`verify --fast` 跑在真机（xc-pc-linux /
  NU-SH-1217），不在 GitHub Actions；远期 coordinator 可在真机验证通过后经 API
  回写 check-run，届时再开。
- 禁止 force push 与分支删除。

现状（2026-10-08）：仓库为私有库、账号未绑支付（非 Pro），GitHub 拒绝为私有库
开启分支保护（"Upgrade to GitHub Pro or make this repository public"）。在升级或
公开之前，以下机制代替执行：
- pre-push 门禁（§28）：verify --fast、STALE 扫描、contract marker、Review Evidence，
  任何一项不过都推不出去；
- mirror 侧 pre-receive 钩子：拒绝一切对 `refs/heads/master` 的直接推送；
- coordinator 经 GitHub API 串行 squash-merge PR，一次一个；
- 仓库已开 `delete_branch_on_merge`，合并后任务分支自动删除。
直推 `master` 无论是否成功都是违规。

### 30.4 例外

生产事故等必须绕行时：仍走 PR 流程，标题加 `emergency:` 前缀，事后 24h 内补齐
evidence；"禁止 `--no-verify`、禁止削弱门禁"的铁律不变——门禁失败就修，不绕行。

***

## 31. 云端 Agent 开发指引（Cloud Agent Development Guide）

多个云端 agent（Trae / Copilot / opencode 等）并行开发同一仓库时的环境一致性方案。

核心问题：各沙箱环境不一致（工具链/系统库/性能），无 Docker 权限，导致验证结果不可信、
Evidence 不可比。

### 31.1 环境一致性三层方案

> **版本单一来源**：Rust 工具链版本的唯一真值是 `DEV-ENV.md` §"Rust 工具链"
> （stable **1.98.1** / nightly 1.100.0-nightly / rustup 1.29.1）。
> `rust-toolchain.toml` 是它的机器可读镜像。本机 Windows cargo 1.95.0 仅作兜底，
> agent 沙箱跑 `cargo check` 时 rustup 会自动按 `rust-toolchain.toml` 切换到 1.98.1，
> 无需手动干预。详见 §31.7。

```
Layer 1: 远程统一开发机（xc-pc-linux）
  - 所有云端 agent 通过 SSH 在同一台远程机上工作
  - 解决：工具链、系统库、性能一致性
  - 脚本：scripts/remote-dev-setup.sh
  - 补充入口：.devcontainer/devcontainer.json（Codespaces / dev container）

Layer 2: CI 标准化验证（GitHub Actions）
  - 所有 PR 在 ubuntu-latest runner 上跑 verify --fast
  - 解决：验证基线一致、Evidence 可比
  - 配置：.github/workflows/ci-verify.yml

Layer 3: 工具链版本锁定（rust-toolchain.toml）
  - 所有 agent 强制使用相同 Rust 版本（1.98.1）
  - 解决：编译/验证结果跨平台可比
  - 配置：rust-toolchain.toml
```

### 31.2 远程开发机工作流

云端 agent 不在本地沙箱工作，而是 SSH 到 xc-pc-linux：

```bash
# 一键配置远程开发环境
./scripts/remote-dev-setup.sh --agent-name trae-18 --crate nexus-auth

# 后续所有操作在远程机上执行
ssh xc-pc-linux 'cd /work/nexus-dev/worktrees/trae-18 && \
  export NEXUS_AGENT=trae-18 && \
  export CARGO_TARGET_DIR=/work/nexus-dev/worktrees/trae-18/target && \
  export RUSTUP_HOME=/work/nexus-dev/.rustup && \
  export CARGO_HOME=/work/nexus-dev/.cargo && \
  export PATH=${CARGO_HOME}/bin:${PATH} && \
  nexus-harness verify --fast'
```

环境变量模板（每个 agent 必须设置）：

```bash
export NEXUS_AGENT=<agent-name>          # 证据命名空间（§29.2）
export CARGO_TARGET_DIR=$PWD/target     # 独立构建目录（防并发锁冲突）
export RUSTUP_HOME=/work/nexus-dev/.rustup
export CARGO_HOME=/work/nexus-dev/.cargo
export PATH=${CARGO_HOME}/bin:${PATH}
```

### 31.3 推送前分级本地预检（Push-Time Local Precheck）

云端 agent 在推送前**必须**先做轻量本地预检，避免把编译错误直接推到 CI
浪费 5-15 分钟反馈周期。使用脚本 `scripts/agent-local-check.sh`：

```bash
# 基本预检（L1 check + L2 clippy + fmt）——所有推送前必须通过
./scripts/agent-local-check.sh <crate>

# 涉及 FFI / 平台代码时追加 L3 build（捕获链接错误）
./scripts/agent-local-check.sh <crate> --full
```

| 级别 | 命令 | 捕获内容 | 适用 |
|---|---|---|---|
| L1 | `cargo check -p <crate> --all-targets` | 语法/import/类型/借用（80% 编译错误） | 所有推送 |
| L2 | `cargo clippy -p <crate> --all-targets -- -D warnings` | 潜在 bug + 项目 lint | 所有推送 |
| fmt | `cargo fmt -p <crate> -- --check` | 格式 | 所有推送 |
| L3 | `cargo build -p <crate> --all-targets` | 链接错误（FFI/静态库） | 涉及 FFI/平台代码 |

若沙箱没有 Rust 工具链，无法本地预检，**直接推送后依赖 CI quick-check 兜底**（见 §31.4）。

> **小空间沙箱（<1GB）替代方案**：若沙箱剩余空间不足以跑 `cargo check`，
> 改用 `scripts/agent-zero-deps-check.sh` 做零依赖契约预检（Cargo.toml 语法、
> protected/forbidden paths、secrets-pattern 扫描）——它不下载依赖、不编译，
> 但**不能**捕获编译错误，编译正确性仍由 CI quick-check 作为第二道门兜底。
> 详见 §31.9 L1。

### 31.4 CI 验证门禁

所有 PR 必须通过 `ci-verify.yml`：

1. **quick-check job**（前置快速门，2-3 分钟）：
   - 只检查 PR 改动的 crate，运行 `cargo check -p <crate> --all-targets`
   - 失败时 PR comment 立即反馈，agent 无需等待全量 verify
2. **verify-fast job**（全量门禁，quick-check 通过后才运行）：
   - 环境：ubuntu-latest + rust-toolchain.toml 锁定的工具链
   - 运行 `nexus-harness verify --fast`
   - 产出：`.evidence/` 上传为 artifact（保留 7 天）
   - PR comment 自动附验证结果和 Evidence 下载链接

### 31.5 分支命名约定

```
云端 agent:  agent/remote/<agent-name>   (如 agent/remote/trae-18)
本地 agent:  task/<run-id>-<slug>          (如 task/001-add-auth)
CI 触发:     ci/<workflow>/<run-number>
```

### 31.6 验证分层

| 层 | 环境 | 跑什么 | 说明 |
|---|---|---|---|
| 本地预检 | agent 沙箱 | `agent-local-check.sh`（check/clippy/fmt） | 推送前自检，可选 |
| CI quick-check | ubuntu-latest | `cargo check` 受影响 crate | 编译错误快速反馈（2-3min） |
| CI verify-fast | ubuntu-latest | `nexus-harness verify --fast` | PR 合并门禁，Evidence 可比 |
| 真机 | xc-pc-linux / NU-SH-1217 | `verify --full` | 沙盒 UDP 被禁的场景 |

### 31.7 版本单一来源（Source of Truth）

所有 agent 必须以 **DEV-ENV.md** 为 Rust 工具链版本的唯一真值；`rust-toolchain.toml`
是它的机器可读镜像，agent 沙箱由 rustup 自动按 channel 安装。

| 来源 | 用途 | 谁可写 |
|---|---|---|
| `DEV-ENV.md` §"Rust 工具链" | **版本唯一真值**（stable 1.98.1 / nightly 1.100.0 / rustup 1.29.1） | maintainer（受保护路径） |
| `rust-toolchain.toml` | 机器可读镜像（channel / components / targets） | 任何人（改版本需同步 DEV-ENV.md） |
| `Cargo.toml` `[workspace.package]` | edition / rust-version / license | 任何人 |
| `binary_context`（运行时） | 沙箱实际可用的 python/node 版本 | 系统（只读） |

**版本漂移防护**：任何工具链 bump 必须先更新 `DEV-ENV.md`，再改
`rust-toolchain.toml`，最后在 CI 上跑一次 verify --fast 确认。
agent 沙箱若 cargo 版本与真值不符，rustup 会自动切换到 `rust-toolchain.toml`
指定的 channel（1.98.1），无需手动干预。

### 31.8 Agent 侧 allow / deny Matrix

| 操作 | 允许 | 说明 |
|---|---|---|
| 读取仓库任意文件 | ✅ allow | 含 AGENTS.md / policies / scenarios |
| 修改 `crates/`、`apps/`、`engineering/` | ✅ allow | 普通代码改动 |
| 修改 `scripts/*.sh` | ✅ allow | agent 辅助脚本 |
| 修改 `.github/workflows/*.yml` | ⚠️ require-review | CI 配置需 maintainer 评审 |
| 修改 `policies/`、`scenarios/`、`harness.toml`、`PRODUCT.md`、`ARCHITECTURE.md`、`*/MODULE.md` | ❌ deny（除非带 contract/requirement-change marker） | 受保护路径（AGENTS.md §7） |
| 修改 `DEV-ENV.md` | ⚠️ require-review | §31.7 版本唯一真值，仅 maintainer 可写（受保护路径 §7） |
| 修改 `AGENTS.md` | ⚠️ require-review | 受保护路径（AGENTS.md §7） |
| 新增 `target/`、`.evidence/` 内容 | ❌ deny | 构建产物 / Evidence，由 `.gitignore` 拦截 |
| 提交密钥 / token / 私钥 | ❌ deny | secrets-pattern 扫描拦截 |
| 推送非 `agent/remote/<name>` 分支 | ⚠️ require-review | 见 §31.5 分支命名 |

### 31.9 Known Limitations & Fallback（送拖车）

以下为已知限制，agent 遇到时按 fallback 处理，不阻塞推送：

| # | 限制 | Fallback |
|---|---|---|
| L1 | 沙箱无 Rust 工具链 / 空间 <1GB | 跳过 `agent-local-check.sh`，改用 `scripts/agent-zero-deps-check.sh` 做契约预检，编译正确性由 CI quick-check 兜底 |
| L2 | 沙箱无 SSH 到 xc-pc-linux | 跳过远程开发机工作流，直接在本地沙箱改代码 + 推送，依赖 CI verify-fast 统一验证 |
| L3 | 沙箱 UDP 被禁（无法跑真机 P2P 场景） | `verify --full` 只能在 xc-pc-linux / NU-SH-1217 上跑；沙箱只跑 `verify --fast` |
| L4 | CI runner 与本地环境可能有 system lib 差异 | CI 安装 `libssl-dev / pkg-config / clang / llvm / libdbus-1-dev / libxcb1-dev` 对齐；首次 CI 若失败，按 PR comment 摘录修复 |
| L5 | `agent-local-check.sh` 与 CI quick-check 可能 diverge | 两者都用 `cargo check -p <crate> --all-targets`，工具链同为 1.98.1；差异只在 system lib，CI 为权威 |
| L6 | shellcheck 未在沙箱安装 | 脚本语法自检用 `bash -n`；CI 建议加 `shellcheck scripts/*.sh` 作为 pre-step（backlog） |
| L7 | `agent-zero-deps-check.sh` 不能 catch 编译错误 | intentional：它只做 zero-dependency gate；编译正确性由 CI quick-check 作为第二道门 |
| L8 | 版本漂移（DEV-ENV.md 未及时更新） | risk-based：每次 toolchain bump 必须先更新 DEV-ENV.md（§31.7 SSOT discipline） |

### 31.10 清理

任务完成后清理远程 worktree（幂等：worktree 不存在时 `git worktree remove`
与 `git branch -D` 均为 no-op，不会报错）：

```bash
ssh xc-pc-linux 'cd /work/nexus-dev/nexus && \
  git worktree remove /work/nexus-dev/worktrees/<agent-name> 2>/dev/null || true && \
  git branch -D agent/remote/<agent-name> 2>/dev/null || true'
```

> 也可直接运行 `scripts/remote-dev-setup.sh`（不带参数会报错 exit 2），
> 它在创建 worktree 前会先清理同名残留（见脚本内 `trap ... EXIT`）。
