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

### Verdict 语义

```
APPROVED           所有维度 PASS 或只有非阻塞建议，可以进入 verify --full
CHANGES_REQUESTED  存在至少一个 FAIL 维度，必须修改后重新 Review
COMMENTED          有建议但不阻塞，记录在案即可
BLOCKED            发现契约冲突，需要切换到 requirement-change 流程
```

### 输出：Review Evidence

Review 完成后，在 `.evidence/review-<id>/` 下生成：

```
summary.json      Review verdict + 维度结果 + 阻塞项 + 建议
findings.md       详细的 Review 意见（可读形式）
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

位于 `.agents/skills/`（任务开始时按匹配读取对应 `SKILL.md`）：



```
nexus-task            仓库内端到端工程任务流程（类型判定 → 上下文 → 契约先行 → 实现 → 验证 → 报告）

nexus-contract-first  契约阶段 / 实现阶段 / Red Evidence / Contract Hash / Contract Conflict

nexus-evidence        证据强度 E0–E5、绑定与 STALE 规则、Candidate Completion 报告模板
```

技能索引见 `harness.toml [skills]` 与 `.agents/skills/README.md`。