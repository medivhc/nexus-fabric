# Code Intelligence —— Phase 2/3/4 工作计划（提案 §15 剩余阶段）

基线：`fix/windows-cfg-portability` @`df2049c`（PR #12 head）。执行分支：`feature/code-intel-phase-234`，
工作树 `D:\next\ci-p24`（**不用** `D:\next\nexus-fabric` —— 那棵树被 `fix/apps-windows-cfg` 的 staged 改动占着）。
权威验证宿主仍是 `xc-pc-linux`；Windows 只作冒烟与负向验证。状态口径同 AGENTS.md：
**Candidate Completion ≠ 完成**，最终结论由 `nexus-review` + 所有者持有。

## 0. 现状与证据（不是猜测，都是实测）

Phase 0/1 与提案 §16 十一条已交付：16 个 E4 场景在 xc-pc-linux 全 PASS、
`cargo test -p nexus-harness` 117/0、`verify --fast` overall PASS 9/9 无 UNKNOWN
（Evidence `verify-qoder-xc-da41a40845f1` @`54010f8`、`verify-qoder-xc-2432533a7ccc` @`1e6b2b3`）。

本轮为 Phase 2-4 新测的证据：

- **冷启动是真瓶颈**（§11 的第一条触发条件成立）：扫 N3 时 `symbol Task` 在 47-crate 真实
  workspace 上 `duration_ms=90535` 且 `ready=false`；`references` 给到 `--ready-timeout-secs 300`
  仍 `ready=false`（`ms=301950`）；同一轮里 `symbol` 类查询 31s 才收敛。每次 CLI 调用都新起一个
  rust-analyzer，索引从头来。
- **多语言没有需求**（§15「先证明 Rust 路径有价值，再抽象多语言，不提前建立空泛框架」）：
  仓库内 C/C++ = 0 文件、Go = 0、TypeScript = 0；Python 1456 行且全是 stdlib 脚本；
  手写 JS 只有 `crates/nexus-web-gateway/static/app.js` 一个 767 行文件，无 package.json/tsconfig。
  宿主工具：Windows 无 pyright/pylsp/gopls/clangd；Linux 有 clangd 10 但**无 C/C++ 可查**，
  Python 是 3.8.10（而 `engineering/verifiers/*.py` 用 `tomllib`，需 ≥3.11）。
- **`context` 目前完全没有实现定位能力**：`commands.rs:108` 只返回 `module_contract` /
  `headings` / `mapped_scenarios`（后者是拿目标名做 `text.contains` 的文本匹配），
  没有 snapshot 绑定、没有 budget、没有 truncated，也没有 "Relevant Implementation"。
  并且 `context` **没有任何 E4 场景或单测钉住**（`scenarios/engineering/` 里一条都没有），
  所以扩展它是加字段而不是改冻结期望——但仍要走契约先行，把新承诺写成场景。

## Phase 2 —— `context` 消费有界语义事实

目标（提案 §15 Phase 2 未完成的那半句）：`nexus-harness context <target>` 在**不改变 Agent 工作流**
的前提下，附加一组有界的 Relevant Implementation 语义锚点。

1. 契约先行：在 `engineering/nexus-harness/MODULE.md` 写清 `context` 的新字段与**可得性规则**
   （`semantic_anchors` 只在 provider 可用时出现；provider 不可用时 `context` 仍是 PASS 但必须带
   `semantic_status` 说明"这次没有语义证据"——绝不允许把"查不到"写成"没有实现"）。
   新增字段设计：`semantic_anchors: [{symbol,kind,kind_id,qualified_name,path,range,in_scope}]`（复用
   `ResultItem` 形状，不另造 DTO）、`semantic_budget {max_results,truncated}`、`semantic_status`
   （`ok` | `unavailable` | `invalid_scope` | `timeout` | `stale`）。
2. 新 E4 场景（先 Red 后实现）：
   - `code_intelligence_context_anchors.toml`：对 `context` 的 fixture 模块查询，钉
     `command`/`verdict`/`authority=advisory`/`snapshot.source_revision` 非空/`semantic_anchors` 非空/
     `semantic_anchors.0.in_scope==true`/`semantic_budget.truncated` 存在。
   - `code_intelligence_context_no_fake_semantics.toml`：把 provider 指到不存在的二进制
     （`--provider-binary`），断言 `semantic_status=="unavailable"` 且 `verdict` 仍是 PASS
     （契约降级而非伪失败）——这条钉住"context 不会因为语义层挂了就说谎"。
3. 实现方式：给 `code_intel` 加一个**库层入口**（不是让 `context` 自己拼 CLI argv）：
   `code_intel::query(verb, request) -> Envelope` 之类的内部函数，`run()` 与 `context` 共用它；
   `context` 侧只允许 `symbol` + `implementations` 两个低宽度查询，预算默认远小于 `code`
   （`max_results` 默认 8），并把语义查询的耗时并入输出（复用 `ProviderMeta`）。
   保持既有约束：`authority` 恒 `advisory`、containment 用归一化判定、digest 哨兵值视为不可用。
4. 验收：新场景在 xc-pc-linux 上 PASS；`cargo test -p nexus-harness` 全绿（Linux）；
   既有 16 场景不回归；`context` 的**旧字段语义不变**（只加不改）。

## Phase 3 —— MCP 薄适配（transport only）

目标（§10）：`Agent → MCP → Nexus Code Intelligence API → provider`，而不是 `Agent → raw LSP bridge`。

1. 依赖口径：`MODULE.md` 的 Allowed Dependencies 是闭集（`serde_json`/`toml`/外部二进制），
   且 `policies/dependencies.toml` 有 `review_new_direct_dependencies = true` ⇒
   **不引入 `rmcp` 等第三方 crate**，手写 MCP stdio 帧。好消息：`code_intel/lsp.rs` 已有
   `Content-Length` + `Content-Type` 的 JSON-RPC 分帧实现，MCP stdio 用同一套帧格式，可复用其
   读写循环（`encode_frame`/`read_frame`/有界缓冲/溢出计数），只补**服务端方向**的循环。
2. 新 verb：`nexus-harness mcp serve`（main.rs 派发加一条 arm；BLOCKED 兜底不变）。
   实现协议面：`initialize`（声明 capabilities：tools only，无 completion/no write）、
   `notifications/initialized`、`tools/list`、`tools/call`、`shutdown`；
   tool 名与 Nexus schema 一致：`code.symbol` / `code.definition` / `code.references` /
   `code.implementations` / `code.callers` / `code.callees` / `code.hover` / `code.diagnostics`，
   入参映射到现有 `Verb` + `SourceLocation` + `Budget`，返回值就是 §4 的那套语言中立 DTO
   （**不暴露** rust-analyzer 内部 symbol id）。
3. 安全边界（§14 必须在 MCP 侧同样成立）：
   - server→client 请求（`workspace/applyEdit`、`workspace/executeCommand`）一律拒绝并计数
     （复用 `ProviderMeta::absorb` 的三桶计数）；
   - 客户端传来的 tool 参数不得包含任意可执行路径；`--provider-binary` 之类只在 serve 启动时
     由仓库配置决定，**不接受运行期注入**（这是提案 §6 那句"不得允许模型把任意 shell 参数
     透传给 language server launcher"在 MCP 上的落点）；
   - stdio 单帧与会话总字节上限沿用 `lsp.rs` 的既有上限常量，超限即断会话并给结构化原因；
   - `mcp serve` 不写 Evidence、不拥有 PASS：每条 `tools/call` 响应里 `authority` 恒 `advisory`。
4. 测试分层（诚实标注强度）：
   - E2 单测：内存 transport 驱动完整握手 + `tools/list` + 一次 `tools/call`，断言帧格式、
     协议版本号、写请求拒绝计数、超限断会话原因串；
   - E4 场景 `code_intelligence_mcp_loopback.toml`：新增 `nexus-harness mcp selftest --json`，
     它用 `current_exe()` 把**自己**作为子进程拉起 `mcp serve`，通过真实管道跑一遍握手 + 一次
     `code.symbol` 查询 + 一次 `workspace/applyEdit` 越界请求，返回 PASS/FAIL 与计数；
     场景钉住这个 envelope。这样 E4 不需要外部 MCP 客户端在场（两宿主都没有），
     且**必须**在 MODULE.md 里写明："第三方 MCP 客户端真实互操作本轮未验证"。
5. 依赖宿主工具的问题：`mcp selftest` 会二次 spawn 自己并触发 rust-analyzer 冷启动（Linux 上
   约 30-90s），所以 selftest 默认只跑到 `tools/list` + 一次**夹具 workspace** 的小查询，
   避免把 47-crate 索引拖进场景。

## Phase 4 —— 泛化：只做有证据的那一件（用户已定：会话复用缓存）

按 §11，持久索引/缓存"只在出现证据时再增加"，且"应作为另一个 Provider/Cache，
而不是第二套 Agent API"。证据已具备（见 §0）。因此 Phase 4 交付三件：

1. **跨命令会话复用缓存**（核心）
   - 目标：把冷启动从"每条命令一次"降为"每个 workspace+revision 一次"。
   - 做法（保守、可关）：在**仓库外**的私有缓存目录（`${env:NEXUS_CACHE_DIR|/tmp}` 下按
     仓库根 hash 分目录）写一个 session 记录：`{pid, socket 或 stdio 句柄不行 ⇒ 用本地 unix socket
     /named pipe 代价大}`。**先评估最省事的可行方案**：进程间共享一个活的 rust-analyzer 需要
     传输通道，跨 CLI 调用保持子进程 stdio 不可行（exec 后管道丢失）⇒ 实际可落的是
     "把会话作为后台子进程 + 本地 unix socket（Windows 用 named pipe）"。这是一次真实的工程扩张，
     必须按契约先行处理：先在 MODULE.md 的 Side Effects 里加"允许在仓库外创建 socket/监听与
     会话文件"，再加 E4/E2 场景证明 1) 第二条命令复用同一 provider（`provider.duration_ms` 显著下降、
     `provider.restart_count==0` 且 `session_reused==true`），2) revision/working_tree 变化后旧会话**失效**，
     3) 缓存目录在工作树外且不污染 git status，4) 崩溃/残留进程可被下次调用回收，
     5) `--no-session` 能退回一次性行为（默认值先取 **opt-in**：`--session reuse`；
     只有当 E4 证明稳定后才考虑改默认）。
   - 若评估结论是"这套 IPC 复杂度不值"，**诚实降级**为：只复用**同一次 `mcp serve` 进程内**的
     会话（MCP 长驻天然把冷启动摊薄到一次），并在文档里把"跨命令缓存"记为已测量、暂缓。
     这个决定由 Phase 4 的 spike 结果驱动，不预先承诺。
2. **判断台账**（§15 Phase 4 的另一半，也是"完成"的一部分）：把 clangd / gopls / pyright-TS / SCIP
   逐项写成"做/不做 + 实测依据"，落进本文档 §0 与本模块 MODULE.md 的 Non-Responsibilities。
   结论按现有测量：clangd 不做（0 C/C++ 文件；Linux 装了也用不上）、gopls 不做（0 Go）、
   pyright/TS 不做（0 TS、无 package.json；且引入需网络安装，用户明确不授权）、
   SCIP 索引不做（先做会话复用；若复用后冷启动仍不足再单独立项）。
3. **provider 选择 seam 的文档化**（不写空框架代码）：在 MODULE.md 里把"如何新增一个语言 provider"
   写成清单（`Verb`/`SourceLocation`/`CodeIntelligenceProvider`/`resolve_binary`/DTO 复用/场景模板），
   使将来接 Python 时不需要重构。零实现 ⇒ 零空泛框架。

## 执行与验证约定（每阶段都要走一遍）

- Contract-First：先 MODULE.md + 新场景 + **Red Evidence**（新场景在实现前必须真的跑失败），
  再实现，再 Green；Protected 路径（`*/MODULE.md`、`scenarios/`、`policies/`、`harness.toml`）
  提交带 `contract: <hash>` marker，手工调 `.githooks/pre-commit` 与 `commit-msg`（hooks 未安装）。
- 每阶段收尾：`cargo fmt --all -- --check`、`cargo clippy -p nexus-harness --all-targets -D warnings`、
  `cargo test -p nexus-harness`（Windows 允许那 3 条 master 自带的 POSIX-`echo` 假红，须写明）、
  然后 **bundle → xc-pc-linux** 跑 `xc-verify.sh`（fast 9 门 + 全部 E4 场景 + 越界形态）。
- 场景数会从 16 增长（Phase 2 至少 +2，Phase 3 至少 +1，Phase 4 视 spike 结论），
  `FILE_MANIFEST.md` 行数与 `MODULE.md` 的场景清单同步更新。
- 独立 Review：§19.1 上限 3 轮是**每个评审对象**的额度。本轮新增的 MCP/会话复用属新评审对象，
  完成实现与 Evidence 后另发一轮独立 Review（用户要求子代理用 qwen3.8-flash，Agent 工具无
  `model` 参数 ⇒ 案卷记 `model=unknown`，用独立会话执行）。
- 子代理分工：契约与文档由主会话写（避免与代码并行改同一文件）；
  实现按阶段派给子代理，每个子代理只碰指定文件集，主会话跑门禁并逐条核对 diff 后才提交。

## 里程碑与判据

| 里程碑 | 完成判据 |
| --- | --- |
| M1 Phase 2 | 2 个新 E4 在 Linux PASS；`context` 输出带 `semantic_anchors`/`semantic_status`；旧字段不变；16 个既有场景不回归 |
| M2 Phase 3 | `mcp serve` 握手 + `tools/list` + `tools/call` 通过 E2；`mcp selftest` E4 在 Linux PASS；写请求拒绝计数可见；文档写明"第三方客户端未验证" |
| M3 Phase 4 | 会话复用 spike 有结论；若做 ⇒ E4 证明复用生效 + 失效正确 + `--no-session` 可退；若不做 ⇒ 记录降级理由；判断台账落地；MODULE.md 增补 provider 清单 |
| M4 收尾 | Linux 上 `verify --fast` overall PASS、全部 E4（含新增）PASS、`cargo test -p nexus-harness` 全绿；FILE_MANIFEST/MODULE/证据同步；推送 stacked 分支并开 PR |

## 附录 A：Phase 4 判断台账（逐项做/不做 + 实测依据）

测量时间 2026-10-11，宿主 Windows（rust-analyzer 1.95.0 / node v24.14.1 / 无 python）与
`xc-pc-linux`（rust-analyzer 1.98.1 / Python 3.8.10 / clangd 10.0.0 / node v10.19.0）。
仓库面积统计排除 `.git`、`target/`、`node_modules`、`.evidence/`。

| 候选（提案 §15 Phase 4 列表） | 决定 | 依据 |
| --- | --- | --- |
| `clangd` | **不做** | 仓库内 `.c/.h/.cpp` = **0 文件**，无 `build.rs`、无 `bindgen`/`cc` 依赖。Linux 上 clangd 10 在场也无物可查。接它只会得到一个没有使用者的 provider |
| `gopls` | **不做** | `.go` = **0 文件**。 |
| `pyright` / `pylsp` | **不做** | 提供方缺席：两宿主都没有 pyright/pylsp；装上需要网络安装（npm/pip），所有者已明确"都不装，按现状交付"。且 Python 侧只有 1456 行 stdlib 脚本、无类型工具配置，语义查询的收益面很小 |
| `typescript-language-server` | **不做** | `.ts/.tsx` = **0 文件**；手写 JS 只有 `crates/nexus-web-gateway/static/app.js` 一个 767 行文件，无 `package.json`/`tsconfig.json`/构建器 |
| 多语言 provider seam（代码层抽象） | **不做实现，只做清单** | 上面四项都不做 ⇒ seam 没有第二个使用者，写了就是 §15 禁止的"空泛框架"。改为在 MODULE.md 写"接下一个语言 provider 需要动哪几处"的清单，成本是文档、收益是将来不重构 |
| 跨命令会话复用缓存 | **先 spike，由数字决定** | 触发条件（§11 第一条）已由实测满足：真实 47-crate workspace 上 `symbol Task` `duration_ms=90535` 且 `ready=false`；`references` 给 `--ready-timeout-secs 300` 仍不收敛；`symbol` 类在缓存热的情况下 31s 收敛。spike 载体是 `mcp selftest --with-query` 的两次查询（`query_first_ms` / `query_second_ms` / 相对判据 `second×4 < first`），数字必须来自 xc-pc-linux |

spike 与实现结论（2026-10-11 回填）：

- **复用发生前**（Red）：`mcp selftest --with-query` 两次查询 first=18352ms / second=17817ms，
  比值判据 `second*4 < first` 不成立 ⇒ 同一个 serve 进程内也没有复用，根因是 `run()`
  每次调用都新建 provider。Red Evidence：`scenario-9e6b63057174`（宿主 Windows/RA 1.95.0）。
- **实现进程内复用之后**（Green）：first=18029ms / second=486ms（**37 倍**），
  结构层 `query_first_session_reused=false / session_queries=1`、
  `query_second_session_reused=true / session_queries=2`、`session_invalidated_reason=""`。
  Green Evidence：`scenario-61696a369a4c`（19 条期望全过，宿主 Windows/RA 1.95.0；
  结论级复跑待 xc-pc-linux）。
- **落法决定**：只做**同一进程内**的 provider 会话复用（`mcp serve` 持有），
  **不做**跨进程缓存/后台 daemon/socket/索引落盘。理由：后者要新增一套隐藏的服务生命周期
  与写副作用（谁启动、谁回收、崩溃后谁清），而当前唯一有证据的成本是
  "一个长驻适配器里每次查询重新索引一遍"，进程内复用已经把它消掉；跨命令缓存的判据
  （`provider.session_reused`）留在输出里，将来若真出现"Agent 每条命令都要冷启动"的
  实测证据，再按 §11 单独立项。**这一条不是"没时间做"，是证据只支撑到这一步。**
- 判据口径：复用与否用**结构事实**（`session_reused` / `session_queries` /
  `session_invalidated_reason`）判定，时延只作旁证。原因是我第一版把
  `second*4 < first` 写成了判据 —— 那是把宿主负载写进契约，属于会造成脆弱红的做法，
  已在 MODULE.md 与本文件里改成结构判据。

## 阶段 4 收尾状态（2026-10-11）

提案 §15 Phase 4 的目标在本区间按**已授权的口径**走完：多语言 provider 与跨进程缓存
不在范围内（前者：仓库内 0 个 C/C++/Go/TS 源文件、两个宿主都没有对应 language server，
且所有者明确"都不装，按现状交付"；后者：§11 只在出现证据时再加，而当前证据只支撑到
进程内复用）。剩下有证据的一件事 —— 同一进程内重复查询重复付冷启动 —— 已消掉并有
结构判据。

独立 Review（round 1，对象 `df2049c..aba6de2`）判 `CHANGES_REQUESTED`，2 阻塞 /
5 非阻塞 + 4 条 minor，已全部处置（B1/G1/A1/A2/A3/G2 修，H1 与 4 条 minor 逐条表态、
其中 1 条**不能改**因为会破坏既有契约的字段可得性），修复复跑记在
`.agents/green-evidence-code-intelligence.txt` §M。
审查者是独立执行者但 `model=unbound`，且在 Windows 只做静态阅读没跑 cargo —— 它的
verdict 不能当门禁结论，本轮修复后的数字全部由实现侧复跑补齐（fmt/clippy/test/selftest/21 场景）。

仍未验证（诚实边界，别在被问到时说成已完成）：
- 第三方 MCP 客户端互操作（两个宿主都没有真实客户端）；
- `verify --full` 对本区间无结论（宿主余量 27G < 实测需要的 30G+）；
- 跨进程/跨命令的会话成本（判据 `provider.session_reused` 已可见，数据未取）；
- 多语言 provider 的真实表现（未装，未测，不做任何声称）。

