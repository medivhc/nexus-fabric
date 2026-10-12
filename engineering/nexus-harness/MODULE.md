# nexus-harness Module Contract

## Responsibility

提供 Agent/Human/CI 共享的 Project Discovery、Context、Affected Analysis、Command Execution、Policy Evaluation、Evidence Writing、Failure Explanation 与 Replay Coordination。

CLI 命令契约（与 `harness.toml [commands]` 一致）：

```text
status            仓库状态 + 最新 Evidence 新鲜度（含 STALE 语义）
context <target>  目标模块契约要点与映射的 tests/scenarios
check             本地静态门禁（format/check/clippy/whitespace）
test affected     变更影响集测试
verify --fast     快速门禁 + 写入 Evidence
verify --full     全量门禁 + 写入 Evidence
explain           解释最近一次 gate 失败
bench             UNKNOWN（MVP 未实现，显式报告）
replay            UNKNOWN（MVP 未实现，显式报告）
code <verb>       语义代码查询（只读；见下方 Code Intelligence Contract）
```

## Code Intelligence Contract

CLI 形态（`--json` 输出沿用核心四字段 + 扩展字段）：

```text
nexus-harness code symbol <name> [options]
nexus-harness code definition <location-or-symbol> [options]
nexus-harness code references <location-or-symbol> [options]
nexus-harness code implementations <location-or-symbol> [options]
nexus-harness code callers <location-or-symbol> [options]
nexus-harness code callees <location-or-symbol> [options]
nexus-harness code hover <location> [options]
nexus-harness code diagnostics [target] [options]
```

`location` 为 `<path>:<line>:<column>`，**行列均为 1-based**（内部按 LSP 0-based
转换）；`<symbol>` 形态经 `workspace/symbol` 解析，若同名匹配多于一个则
返回 `FAIL` + `error.code = QUERY_INVALID` 并列出候选，不做静默挑选。

options（全部可选，缺省即预算默认值）：

```text
--workspace <path>            查询根（相对仓库根解析）；缺省为仓库根
--max-results <n>             缺省 20
--max-snippet-lines <n>       缺省 8
--max-result-bytes <n>        缺省 65536
--timeout-secs <n>            单请求超时，缺省 20
--ready-timeout-secs <n>      provider 就绪等待上限，缺省 90
--provider-binary <name|path> 覆盖 language server 可执行文件（仅用于失败路径验证）
```

扩展字段（`code` 各命令统一；**字段可得性**按下述规则，不装作永远齐全）：

- `command` / `authority` / `error`（失败时）永远存在。
- `snapshot` 一旦完成仓库发现就存在（含 verb 不认识、参数非法等 provider 启动前的失败）；不在 git 仓库内时以 `WORKSPACE_UNRESOLVED` 上报。
- `snapshot.workspace_root` **只在作用域校验通过后出现**。早期失败（verb 缺失/不认识、参数非法、作用域被拒）里 `snapshot` 存在但没有这个字段——不用 `"."` 之类的占位值表示"还没确定"，那会让消费方把"未确定作用域"读成"作用域就是仓库根"（round 3 待办 4）。
- `budget` 在 options 解析成功后存在；`provider` 只在 language server 被解析到之后存在。
- `results` / `count` 恒存在，失败时为 `[]` / `0`——失败**绝不**表现为"空结果 + PASS"。

```text
results            语言中立结果数组（symbol/kind/kind_id/qualified_name/path/in_scope/range/snippet）
count              截断前的完整命中数
budget             {max_results,max_snippet_lines,max_result_bytes,workspace_scope,truncated}
continuation       截断时 {refinement_hint}（未截断则省略）
provider           {kind,binary,version,ready,restart_count,restart_reason,
                      duration_ms,write_requests_refused,server_requests_unhandled,
                      dropped_notifications,session_reused,session_queries,
                      session_invalidated_reason}
snapshot           {source_revision,working_tree_digest,target_triple,toolchain_version,
                      workspace_root}
                   workspace_root 仅在作用域校验通过后出现（见上方字段可得性规则）
authority          恒为 "advisory"：Code Intelligence 不拥有最终 PASS
error              失败时 {code,reason}
```

`kind` 是 provider 声明的 LSP `SymbolKind` 对应字符串，`kind_id` 是该数值原文
（0 = provider 未给出）。两者都给是因为 rust-analyzer 对 trait/impl 方法有时
上报 `property`(6) 或 `variable`(12) 而非 `method`(5)：只给字符串会误导 Agent，
而 harness 不擅自纠正 language server 的语义声明，交由调用方判断。

错误码（提案 §12 冻结）：

```text
PROVIDER_UNAVAILABLE WORKSPACE_UNRESOLVED INITIALIZATION_FAILED QUERY_INVALID
SYMBOL_NOT_FOUND RESULT_TRUNCATED TIMEOUT PROVIDER_CRASHED SNAPSHOT_STALE UNSUPPORTED
```

码表使用现状（如实记录，避免"目录里有、实现里没有"）：

- `RESULT_TRUNCATED` 是**契约预留**：首期截断通过 `budget.truncated = true` +
  `continuation.refinement_hint` 表达，不作为终态码，因此当前无构造点。
- 其余九码均有构造点；`TIMEOUT` 同时承载"请求超时"与"就绪预算耗尽导致空结果
  不可信"两种情形（后者在 `reason` 里写明），以便调用方区分"重启无望"
  （`INITIALIZATION_FAILED`）与"加大预算可救"（`TIMEOUT`）。
- 结果条目的 `in_scope` 表达作用域：查询**目标**越出 `--workspace` 直接
  `QUERY_INVALID`；**结果**越界（例如 callee 落到标准库源码）不删除、只标
  `in_scope = false`，因为删掉就等于静默丢弃（提案 §5 禁止）。
- 作用域判定是**归一化后**的（`env::path_is_within_resolved`：两侧先 `canonicalize`
  再按组件比较），不是字符串前缀。理由：`fixtures/../../../../x` 这类路径词法上仍以
  声明的作用域为前缀，实际却指向作用域之外甚至仓库之外（独立 Review round 2 的
  B-R2-1）。归一化同时覆盖 `.`/`..` 组件、符号链接与 Windows junction、盘符大小写；
  任一侧 canonicalize 失败一律判"不在范围内"（fail-closed），绝不当作通过。
  `in_scope` 用同一判定，仅当 server 报出的路径尚未落盘（虚拟文档/生成代码）才退回词法比较。

### 诊断条目字段映射（`code diagnostics`，提案 §16.4）

诊断不是符号，但必须复用同一套条目形状，所以字段是**映射**而不是同名：

| LSP Diagnostic | 输出字段 | 语义 |
|---|---|---|
| `code` | `symbol` | 诊断码（数字按字符串输出）；没有 code 时为空串 |
| 固定 `"diagnostic"` | `kind` | 条目类型 |
| 固定 `0` | `kind_id` | 诊断没有符号类别（0 = provider 未给出） |
| `severity` | `qualified_name` | 经 `diagnostic_severity` 映射为 `error/warning/info/hint` |
| 诊断所属文件 | `path` | 相对仓库根；与 `code` 请求的目标文件一致 |
| 同一目标文件 | `in_scope` | 用与符号条目相同的归一化判定（不再硬编码 true：pull 结果里可能带 sysroot/依赖 crate 的诊断） |
| `range`（0-based） | `range`（1-based） | 与其他 verb 同一转换规则 |
| `message` | `snippet` | 自由文本只进 `snippet`，判定不依赖解析它 |

条目形状由 `engineering.code-intelligence-diagnostics-item-shape`（E4）锁定：夹具里
`fixtures/code-intel/src/diagnostic_probe.rs` 刻意留**一处**类型错误，场景断言
`results.0` 的映射后形状（`kind == "diagnostic"`、`kind_id == 0`、`qualified_name`
即 severity 且必须是 `error`、`in_scope == true`、`path` 指向该文件、`symbol`/`snippet`
非空）。只断言**契约保证的结构**，不钉 provider 版本的自由文本——RA 1.95 与 1.98 的
message 措辞不同，钉文案等于把版本耦合写进契约。诊断条目的**数量**同样不钉：
它随 RA 的分析面变化，钉数量会制造与语义无关的脆弱红。

## Context Semantic Anchoring（提案 §15 Phase 2）

`context <target>` 在原有三项输出（`module_contract` / `headings` / `mapped_scenarios`，**语义不变、
只增不改**）之外，附加一组**有界**语义锚点，让 Agent 从模块契约直接落到"实现在哪"，
不必退回 `rg` + 猜类型（提案 §1）。

`mapped_scenarios` 的口径必须说准：它是**子串启发式**（场景正文里出现 target 名就算命中），
所以它的条数**不是**"该模块的场景总数"，也不能与 `MODULE.md` 里声明的场景清单数互相验证
（例：`context engineering/nexus-harness` 报 20 而清单是 21，因为握手场景正文不含目标路径串）。
把它当总数用会得出"有一个场景漏登记"的假结论（独立 Review round 2 的 N7）。

新增字段（`context` 的 `--json` 输出）：

```text
semantic_status   ok | no_candidates | not_found | unavailable | timeout | stale
                    | unsupported_scope | invalid_query
semantic_anchors  复用 code 的 ResultItem 形状（symbol/kind/kind_id/qualified_name/
                    path/in_scope/range/snippet），不另造 DTO
semantic_budget   {max_results, truncated, candidate_queries, candidate_spans,
                    workspace_scope}
semantic_reason   非 ok 时 {code, reason}，code 取自下方错误码
snapshot          与 code 同一套 Bindings（source_revision/working_tree_digest/…）
authority         恒为 "advisory"
```

不变量（这些是本节的承诺，不是实现细节）：

1. **语义层永远不改变 `context` 自己的 verdict。** 目标目录存在 ⇒ PASS；不存在 ⇒ BLOCKED。
   语义查不到就写 `semantic_status`，绝不把"没查到"升级成"没有实现"，也不把"查到了"
   当成 correctness（提案 §7/§12）。
2. **候选符号只从模块契约里取**：解析 `<target>/MODULE.md` 中**成对反引号包裹**的整段
   标识符（首字母大写、长度 ≥3、只含 ASCII 字母数字与 `_`），按出现顺序去重，
   **最多 3 个候选**；按顺序尝试，**首个产出锚点的候选即停止**（每次尝试都要一次 language
   server 冷启动，实测 18–30s，三次串行会把 `context` 拖成分钟级），
   `semantic_budget.candidate_queries` 记实际尝试数（1–3）。
   聚合上限 `max_results = 8`；不猜名字、不扫源码找符号、不做全仓索引。
   - **整段必须是标识符**：一格里写多个名字（`Foo, Bar`）整格作废，刻意不做"取词首"——
     词首截断会把 `Cargo.toml` 变成 `Cargo`、把 `Context-Builder` 变成 `Context`，而截断片段
     完全可能命中**另一个**符号、把 Agent 领到错的地方，那比漏收更糟。
   - 漏收必须可见：`semantic_budget.candidate_spans` 报"契约里一共看到几个 code span"，
     与 `candidate_queries` 对照就能分辨"契约没写"与"写了但不合命名规则"（提案 §5 禁止静默丢弃）。
3. **只在 cargo workspace root 上跑语义层**（目标目录里存在带 `[workspace]` 的 `Cargo.toml`）。
   原因必须写清：rust-analyzer 从 workspace root 启动才能限定加载面；从根 workspace 的成员
   目录启动会把 47 个 crate 全灌进索引，实测冷启动 30–90s 且 `ready` 常常不收敛，
   有界预算兜不住。此时 `semantic_status = "unsupported_scope"`，`semantic_reason` 里指向
   `code symbol`（一次性小查询）与 Phase 4 的会话复用缓存。
4. **未收敛即降级，不冒充结论**：provider 侧判定"索引未收敛 ⇒ 空结果不可信"的既有规则
   （`PROVIDER_UNAVAILABLE` / `TIMEOUT` / `SYMBOL_NOT_FOUND`）原样映射到 `semantic_status`，
   错误码不新造。
5. 作用域与 containment 判定与 `code` 共用同一套归一化实现（`path_is_within_resolved`，
   fail-closed）；工作树指纹取不到（`tree-unknown`/`dirty-unknown`）时
   `semantic_status = "stale"` 且**不发起** provider 调用。
6. `context` 接受 `--provider-binary <path>`，仅用于让"provider 不可用"这条路径可被 E4 确定性地
   演练；它不改变其它字段语义，也不接受任何写能力参数（提案 §6：不得把任意 shell 参数
   透传给 language server launcher）。

## MCP Adapter（提案 §15 Phase 3、§10）

`nexus-harness mcp serve [--provider-binary <path>]` /
`nexus-harness mcp selftest [--with-query]` 是一个**薄 transport 适配层**：把 MCP 的
`tools/list` / `tools/call` 映射到同一套 `code <verb>` 能力，让外部 Agent runtime 用的仍然是
Nexus 的中立 schema，而不是 LSP 原文（提案 §3 的 `Agent Contract != LSP Contract`）。

```text
Agent ──MCP(stdio JSON-RPC)──▶ nexus-harness mcp serve ──▶ code_intel::run ──▶ rust-analyzer
```

握手与方法：

- 实现 `initialize`（回 `protocolVersion` / `serverInfo` / `capabilities = { tools: {} }`，
  **不声明** `workspace`、`completion`、`logging` 等能力）、`notifications/initialized`
  （以及任何 `notifications/*`：接收、不响应、不影响状态）、`tools/list`、`tools/call`、
  `shutdown`。未实现的合法方法返回 JSON-RPC `-32601`，参数不合形态返回 `-32602`，
  未知 method 返回 `-32601` —— 协议层错误用 JSON-RPC error object 表达，
  **不**伪装成 Nexus 的 `verdict`；而语义层失败仍以 `content[0].text` 里的 Nexus envelope
  原样返回（保持 §12 的错误码与 `authority = "advisory"`）。
- 暴露 8 个工具，名字与 CLI 一一对应：`code.symbol` / `code.definition` / `code.references` /
  `code.implementations` / `code.callers` / `code.callees` / `code.hover` / `code.diagnostics`。
  **不暴露任何写能力工具**（rename / format / applyEdit / executeCommand 一律不在
  `tools/list` 里）。被按名请求时分两层拒绝，两层各说各的话：协议层回 JSON-RPC
  `-32602`，其 `message` **以 `UNSUPPORTED: ` 开头**（即 Nexus 冻结错误码字面量），
  让客户端能按前缀断言"撞了白名单"而不必匹配自然语言全文；两层不混用，
  也绝不返回空结果或把写请求降级成一次无意义查询。白名单判定发生在命名约定判定
  **之前**——`workspace/applyEdit` 这类不带 `code.` 前缀的名字也必须走同一条
  `UNSUPPORTED` 拒绝，不能落进"未知工具"文案（那等于把越权说成拼写问题，客户端可以换个
  拼法重试）。selftest 逐个试完负向清单上的**全部** 6 个名字，不抽查一个。
- 工具入参只接受 `target` / `workspace` / `max_results` / `max_snippet_lines` /
  `max_result_bytes` / `timeout_secs` / `ready_timeout_secs`。**不接受** `provider_binary`
  之类的启动期参数：把可执行路径放进 tool 参数就等于让模型给 language server launcher
  注入 argv，提案 §6 明令禁止。provider 二进制的**唯一**入口是启动期：
  `mcp serve --provider-binary <path>`，解析顺序与 `code` 完全同一函数
  （`--provider-binary` 覆盖 → `NEXUS_RUST_ANALYZER` → `PATH`；
  指定了但不存在 ⇒ `PROVIDER_UNAVAILABLE`，不回退到 PATH —— 静默回退会把"我以为换了
  server"变成"其实没换"）。`serve` 的**未知启动参数一律 `BLOCKED`**，不静默丢弃：
  被文档承诺过的开关失效必须看得见（独立 Review round 2 的 N1 就是文档承诺了这个 flag
  而 `dispatch` 把 `args` 整个丢掉，实测给不存在的路径与不给完全同形、exit 0）。
- **通道划分（传输层正确性，不是风格问题）**：`mcp serve` 的 **stdout 只承载 MCP 帧**
  （`Content-Length` 分帧的 JSON-RPC），进程退出时的 CLI envelope（`verdict` / `message` /
  `command` / `schema_version` / `authority` / `handled_requests` / `snapshot`）走 **stderr**；
  退出码仍由 verdict 决定（`PASS`/`UNKNOWN` ⇒ 0，`FAIL` ⇒ 1，`BLOCKED` ⇒ 2）。
  理由：stdout 对 MCP 而言**就是协议通道**，往它上面追加一段裸 JSON，严格客户端会把会话结尾
  读成畸形帧。这条在 round 2 之前是破的（实测 `printf '' | mcp serve --json` 的 stdout 是
  194 字节裸 JSON），修前 Red 见 `.agents/red-evidence-mcp-round2.txt`。
- `serve` 的**每条**退出路径都带 `authority = "advisory"`、`handled_requests` 与 `snapshot`。
  `handled_requests` = 本会话已回复的请求条数；notification 按定义不产生回复，**不计入**。
  它是 PASS/UNKNOWN 的**判据本身**（`> 0` ⇒ PASS，`= 0` ⇒ UNKNOWN），所以必须出现在输出里、
  也必须被契约定义 —— 一个决定 verdict 的量只活在代码里，等于把判定藏起来。
  `snapshot` 的存在理由与 `context` 相同：declined/退出的结果也要说清绑在哪棵树上。
- `selftest` 用 `current_exe()` 把**自己**作为子进程拉起 `mcp serve`，通过真实管道跑
  `initialize → notifications/initialized → tools/list → tools/call`，
  默认不触发 provider 冷启动（第三条 `tools/call` 用**故意非法**的参数，验证协议层与
  参数校验的失败形状）；`--with-query` 时额外跑**两次**夹具 workspace 上的真实查询
  （作用域限定在 3 个源文件内，冷启动面确定）。`selftest` **只认 `--with-query`**，
  未知参数在启动任何子进程之前就 `BLOCKED`（与 `serve` 同一规则；要换 provider 用
  `NEXUS_RUST_ANALYZER` 或 `mcp serve --provider-binary`，selftest 不自造旁路入口）。
- `selftest` 里"notification 不产生回复"必须是**序列证明**而不是"写成功了就算过"：
  发完 notification 紧接着发一条带 id 的请求，断言下一条响应就是那个 id ——
  证明中间没有多出帧。只断言 `write_frame(..).is_ok()` 是在测管道写通不写通，
  与被声称的性质无关（round 2 的 N4a）。
- `selftest` 还单独探测 `serve` 的**退出形状**（不依赖 language server，默认路径即跑）：
  客户端一条请求都没发就挂断 ⇒ `eof_verdict = "UNKNOWN"`（既不是崩溃也不是 PASS，
  零请求不能伪装成"处理过了"）；发来畸形帧 ⇒ `malformed_frame_verdict = "FAIL"`；
  处理过至少一条请求后正常挂断 ⇒ `pass_verdict = "PASS"` 且 `handled_requests = 1`。
  第三条探针同时断言 **stdout 可按帧完整消费且没有多余字节**（帧数与已回复请求数一致）——
  这是通道划分的回归保护：round 1 修好的那条 PASS 分支此前只能靠人工 `printf` 看见，
  因为退出 envelope 混在同一个 stdout 里让"取最后一行 JSON"的探针解析不出来。
  这些值是 serve 的对外契约的一部分，由握手场景直接断言。
- `selftest` 还端到端证明 **`--provider-binary` 真的生效**（`provider_override_honored`）：
  它另起一个 `mcp serve --provider-binary <与自身同目录的不存在路径>`，跑一次真实
  `tools/call`，断言**三件事**同时成立 —— 错误码是 `PROVIDER_UNAVAILABLE`（不是"悄悄用了
  PATH 上的 server 然后成功"）、失败原因点名 `--provider-binary`、**且原因里带上我传进去的
  那条路径**。第三条是 round 3 的 N-A2 补的：rust-analyzer 缺失时的兜底文案本身就写着
  `--provider-binary` 字样，只断言前两条在**没有可解析 RA 的宿主**上会"flag 根本没兑现也报绿"。
  所以这条探针在没有 RA 的宿主上会如实变红 —— 它测的是 flag 有没有被兑现，不是环境好不好。
  选不存在的路径而不是真 server，是为了在任何宿主都 fail fast 且不受负载影响
  （`resolve_binary` 在 spawn 之前就失败）。threading 另有一条直接单测
  （`tools_call_threads_startup_provider_override`），不依赖任何子进程。
- `selftest` 的 `--json` 输出字段（缺任何一个都算契约破坏，字段名即对外承诺；
  BLOCKED/declined 路径同样带 `authority` + `snapshot`，与 `code`/`serve` 同形 ——
  round 3 的 N-A1 补的不一致）：
  `verdict` / `message` / `authority` / `protocol_version` / `initialized_ok` / `tools_count` /
  `notification_no_reply` / `write_tools_exposed` / `unknown_method_rejected` /
  `bad_arguments_rejected` / `write_call_rejected` / `eof_verdict` /
  `malformed_frame_verdict` / `pass_verdict` / `pass_handled_requests` / `stdout_frames_ok` /
  `provider_override_honored` / `probe_count` / `query_skipped` / `probes[]` / `duration_ms` /
  `snapshot`，加了 `--with-query` 才有 `query_*` 一族。
  `probe_count` 把探针条数变成**机器可核**的量（默认路径 11、`--with-query` 14，
  由握手与 real-query 两条场景分别钉住）—— 以前这个数只活在散文里，§N 把 8 记成 11
  正是这么发生的（round 2 的 N3）。
- `--with-query` 顺带产出 Phase 4 的判定数据：`query_first_ms` / `query_second_ms` 是**旁证**，
  判据本身是结构事实 —— `query_warm_reused = provider.session_reused && session_queries >= 2`
  （场景 `mcp_real_query` 直接钉 `query_first_session_reused=false`/`queries=1` 与
  `query_second_session_reused=true`/`queries=2`）。**为什么不用时延比值**：我第一版写的判据是
  `second × 4 < first`，那是把宿主负载写进契约，只会造出与语义无关的脆弱红；
  绝对毫秒数同样不钉。跨命令（进程之间）的会话复用是否要做，由 `provider.session_reused`
  这个可见判据将来是否出现新的实测证据来决定（见「Provider Session Reuse」）。

诚实边界（必须照此声明，不许含糊）：

- 本适配器的**协议合规性只由 selftest + E4 场景证明**，即"我们的 server 与我们的 client
  在真实 stdio 管道上互操作正确"。**第三方 MCP 客户端**（OpenCode / Claude Code 等）
  在本仓库两个宿主上都不存在，因此与真实客户端的互操作**未经验证**，不得声称已通过。
  口径要说准：未验证的是"真实客户端的行为"，**不是**"我们自己知道的正确性"——
  退出 envelope 混进 stdout 这类**已知**偏差在 round 2 被抓出并已修（见上方通道划分 +
  `pass_verdict`/stdout 纯净探针），不能再把它说成"未知风险"。
- `mcp serve` 不写 Evidence、不拥有最终 PASS：每条工具结果的 `authority` 恒 `advisory`；
  correctness 仍归 `cargo check/clippy/test`（提案 §7）。
- 零新依赖：JSON-RPC 帧沿用 `code_intel/lsp.rs` 的 `Content-Length` 分帧实现
  （MCP stdio 与 LSP 同帧格式），不引入 `rmcp` 等第三方 crate
  ——Allowed Dependencies 是闭集，加依赖要走独立的 requirement-change 周期。
- 资源边界沿用 `code`：单帧与会话字节上限、stderr 环形上限、每请求 timeout、
  notification 有界缓冲与丢弃计数；超限即断会话并给结构化原因，不静默截断后继续。

## Provider Session Reuse（提案 §15 Phase 4、§11）

证据先行：§11 把持久索引/缓存列为"出现证据才做"。证据已实测拿到——在 47-crate 的真实
workspace 上 `symbol Task` 冷启动 `duration_ms=90535` 且 `provider.ready=false`；
`mcp selftest --with-query` 的两次查询是 18352ms / 17817ms，**同一个 serve 进程内也没有复用**
（`run()` 每次都新建一个 provider）。因此本模块只做一件有证据支撑的泛化：
**同一进程内**复用 provider 会话。

契约：

- **复用键** = 解析后的 provider 二进制 + `--workspace` 根 + provider 版本 +
  **会话建立时的 `working_tree_digest`**。四项任一不同 ⇒ 不复用。
- **指纹不一致就重建，不冒充新鲜。** 工作树在会话建立之后变过，索引描述的已经不是当前树；
  此时宁可付一次冷启动，也不给一份"看起来新鲜"的结果。重建原因写进
  `provider.session_invalidated_reason`（`digest_changed` / `workspace_changed` /
  `provider_restarted` / `binary_changed`），`session_reused` 记 `false`。
  这条优先于"要快"。
- 复用生效时 `provider.session_reused = true`、`provider.session_queries >= 2`；
  `ready`、`dropped_notifications`、`write_requests_refused` 等计数继续按**整个会话**累计
  （与既有"跨重启计数合并"规则同源，不因复用而重置）。
- **每条结果仍做查询前后 digest 对比**，`SNAPSHOT_STALE` 的判定不因复用放宽；
  `duration_ms` 仍然是**本次查询**的耗时（不是会话累计），否则 Agent 会把会话成本误读成查询成本。
- **CLI 路径的跨命令复用要显式开启**（所有者 2026-10-12 决定，见下方「Provider Daemon & Result Cache」）：
  默认仍然是一次调用一个进程 —— `daemon` 未运行时查询照旧走进程内会话并报
  `session_source="in-process"`；**CLI 永不自动拉起 daemon**，这条优先级高于"体验顺畅"。
  `mcp serve` 依旧是自带会话的调用方，退出时必须关闭 provider，不留孤儿进程。
- 曾经的"明确不做：跨进程缓存、后台 daemon、socket/端口、把索引落盘"已由实测证据解除否决，
  但**理由不作废** —— 作废的是"隐藏生命周期"这个风险，做法是给生命周期加可见护栏
  （显式 start/stop/status、租约文件、idle TTL、输出里必带 `daemon.session_source` 与
  `daemon.running`）。仍然不做：SCIP/repository-wide 落盘索引、把索引或缓存写进仓库、
  非回环绑定、TLS/认证体系、任何新外部依赖、第二套 Agent-facing API。证据与决定记在
  `.agents/provider-daemon-and-result-cache-plan.md`。

## Provider Daemon & Result Cache（提案 §11、§15 Phase 4；所有者 2026-10-12 授权）

触发证据（不是"以后可能有用"）：真仓库 47 crates 上 `symbol Task` `duration_ms=90535` 且
`provider.ready=false`；`references` 给 `--ready-timeout-secs 300` 仍不收敛；夹具 workspace 每次
冷启动 15–40s。§Q 的 69ms 只证明**同一进程内**已复用，跨命令仍从零开始。

```text
nexus-harness code <verb> ──(daemon 在跑且握手成功)──▶ daemon(127.0.0.1:<临时端口>)
                                        │                    └─ 会话池：每 workspace 一个 rust-analyzer
                                        └─(没在跑)──▶ 进程内冷启动，session_source="in-process"
```

- **只做回环**：`TcpListener` 绑 `127.0.0.1:0`。绝不绑非回环地址、不做 TLS、不做端口发现服务。
  选 TCP 而不是 unix socket / named pipe 的理由要说清：两宿主同一实现 ⇒ Windows 冒烟宿主能跑
  完整的 daemon E4，不需要 `cfg(unix)` 分叉留下一条"Linux 才测过"的路径。
- **线协议是实现细节**：沿用 `code_intel/lsp.rs` 的 `Content-Length` 分帧（含 header/body 上限），
  消息面只接受 Nexus 级查询（verb + target + workspace + 预算），服务端仍走同一套
  verb 白名单、作用域 containment 与只读不变量。**不暴露 raw LSP**，也不新增 Agent-facing API
  （提案 §11 的约束：cache/provider 是另一个 Provider，不是第二套契约）。
- **租约与存活判定**：`std::env::temp_dir()/nexus-code-intel-daemon-<fnv>/lease.json`
  记 `{pid, port, token, started_at, last_heartbeat, idle_secs, workspace_key, version}`；
  daemon 定期刷新 `last_heartbeat`。存活与否**用端口握手判定，不用 `kill(pid,0)`**（那需要 libc，
  违反零新依赖）。daemon 崩溃留下的残留租约 ⇒ `status` 报 `stale_lease=true`，
  `stop` 只删文件、**不去 kill 一个无法验证的 pid**。
- **token 是误用防护，不是安全边界**（必须照此声明）：租约在按用户隔离的 temp 目录里，
  而同用户下的任何进程本来就能直接运行 `nexus-harness code` —— daemon 经内部协议能做的事
  **不多于** CLI 本来能做的事，因此拿到 token 不构成提权；token 的作用只是拒绝误连与
  让 `stop`/`status` 认对对象。Windows 上无法用 std 收紧 ACL，这一点不粉饰。
- **生命周期**：`daemon start|stop|status|selftest [--workspace <root>] [--idle-secs N]
  [--max-workspaces N]`，默认 `idle_secs=900`、`max_workspaces=2`（LRU 驱逐即关闭该会话的
  RA 子进程）。`start` 幂等（已活着 ⇒ `PASS` + `already_running=true`，不起第二个）；
  `stop` 对不存在的 daemon 报 `UNKNOWN` + 原因（不假装停成功）；所有退出路径回收 provider，
  `selftest` 断言 `sessions_after_stop=0`。空闲到点自行退出并删租约。
- `code` / `context` 支持 **`--no-daemon`** 与 **`--no-cache`**：前者完全不问 daemon
  （必然 `session_source="in-process"`，给 CI 一个不受环境里是否有人手起过 daemon 影响的确定口径），
  后者不读也不写结果缓存（`cache.disabled=true`）。默认值都是"允许"。
- **两层"缓存"不得混为一谈**：
  ① *会话层*（daemon）真正省掉冷启动，复用键沿用四项（provider 二进制 + workspace 根 +
     provider 版本 + **会话建立时的 `working_tree_digest`**），指纹变了就重建并记
     `provider.session_invalidated_reason` —— "宁可付冷启动也不冒充新鲜"的优先级不变；
  ② *结果层*（落盘）键 =`(working_tree_digest, workspace 根, verb, target, provider 版本, 预算)`，
     **仅当当前工作树指纹与键一致**才允许命中；查询前后各取一次 digest 的检查不因缓存放宽；
     条目数与字节有上限、超限即不写且计数可见；**不得包含源码原文**。
     命中时 `cache.key_digest` 必须等于当次 `snapshot.working_tree_digest` ——
     把这个等式做成字段与断言，使"拿旧指纹的结果冒充新结果"在输出里就看得见。
     结果层的收益**未经实测**（它省重复查询不省索引），所以验收只钉结构正确性，时延只作旁证。
- **字段与可得性**（缺字段即契约破坏，`null`/`0` 不得冒充"有但不知道"）：

  ```text
  daemon   {running, session_source: "daemon"|"in-process", lease_path, port, pid,
            idle_secs, already_running, stale_lease, daemon_unavailable,
            provider_sessions, provider_session_capacity}
  cache    {tier: "miss"|"memory"|"disk", key_digest, entries, bytes, disabled}
  ```
  `running=false` 时 `port`/`pid`/`lease_path` **不出现**；`daemon_unavailable` 只在
  本想用 daemon 却失败时出现，并带结构化原因（此时查询照常完成，不得 hang 在超时上，
  也不得把回落说成 PASS 之外的任何结论）。默认值也是契约：`idle_secs=900`、
  `max_workspaces=2`，即使没有 daemon，`daemon status` 也要把这两个默认值报出来
  （否则"默认值都是允许"这句话没有任何机器对应物）。
- **`daemon selftest` 的作用域与隔离**（缺了就不可复现，故属契约）：
  ① 必须显式给 `--workspace`，**没有缺省作用域**（不写就是环境依赖）；
  ② 必须在**私有租约/缓存命名空间**里跑 —— 不得读写开发者真实在跑的 daemon 的
     `lease.json`/cache 目录，也不得让环境里的 daemon 改变探针结果；
  ③ 需要"无 daemon"前提的探针（`default_path_*`、`stop_absent_*`）必须自己确认起始状态，
     不靠执行顺序碰运气；
  ④ 空闲自退出用**注入的小 `--idle-secs`** 观测，默认 900s 大于场景 600s 超时，天然不可测；
  ⑤ 全程只在自己的 temp scratch workspace 里跑，结束时 `git status --porcelain` 仍为 0 行。
- **`daemon selftest --json` 的字段清单**（`probe_count` 必须等于本清单条数；场景侧对每条钉**值**
  而不是笼统的"探针都过了"。字段名即对外承诺，改名要同步改场景 —— 之前
  `sessions_after_stop` / `provider_sessions_after_stop` 两处漂移就是这么来的）：

  ```text
  start_verdict                        "PASS"        daemon start 的 verdict
  status_running_after_start           true          start 后 status 报 running=true
  start_idempotent_same_port           true          第二次 start 观察到同一个 port（不起第二个）
  already_running                      true          第二次 start 的契约字段
  default_path_session_source          "in-process"  不带任何 flag 的普通查询：会话来源
  default_path_lease_absent            true          同一查询跑完后租约目录仍未出现 ⇒ 没被自动拉起
  second_process_session_source        "daemon"      第二个 CLI 进程走 daemon
  reuse_queries_total                  2             daemon 侧累计查询数（跨两个进程）
  reuse_provider_sessions              1             复用观测点的会话数：是 1 不是 2
  stale_lease_detected                 true          租约指向没人听的端口 ⇒ status 报 stale_lease=true
  stale_fallback_verdict               "PASS"        残留租约下查询照常完成（不 hang、不谎报）
  stale_fallback_session_source        "in-process"  回落确实是进程内会话
  wrong_token_rejected                 true          token 不符的连接被拒（误用防护，见上文口径）
  idle_self_exit_observed              true         --idle-secs 注入后到点自行退出
  lease_removed_on_idle                true          自退出也删自己写的租约
  stop_absent_verdict                  "UNKNOWN"     stop 一个不存在的 daemon ⇒ 不是 PASS 也不是 FAIL
  sessions_after_stop                  0             stop 后 daemon 侧会话数为 0（无孤儿 RA）
  lru_provider_sessions_at_capacity    1            --max-workspaces 1 下查两个 workspace，会话数仍是 1
  digest_invalidation_reason           "digest_changed"  工作树变更后重建的原因值
  cache_second_run_tier                "disk"        结果层必须**真的命中过**（同指纹二次相同查询）
  cache_hit_key_digest_bound           true          命中那次 cache.key_digest == snapshot.working_tree_digest
  cache_default_enabled                true          默认路径 cache.disabled=false
  cache_disableable                    true          --no-cache ⇒ disabled=true 且 tier="miss" 且查询仍 PASS
  cache_bounded_and_source_free        true          条目/字节不超过契约上限，且缓存内容不含源码原文
  wire_refuses_non_whitelist           true          内部协议收到白名单外 verb ⇒ 拒绝且不改状态
  commands_surface_lists_daemon        true          兜底 BLOCKED 消息里的命令清单必须含 daemon
  unknown_flag_blocked                 true          未知启动参数 BLOCKED（不接受"参数被忽略"）
  defaults_idle_secs                   900           契约默认值
  defaults_max_workspaces              2             契约默认值
  dirty_after_lifecycle                0             整个生命周期结束后工作树未被写入
  ```
  `probe_count = 30`。"不得 hang" 不用时间上界钉死（那是把宿主负载写进契约）：真卡住时
  场景会以 `failed_step="run"`（超时）暴露，而不是被某条脆弱的毫秒断言误判。
  部分探针（`second_process_*`、`cache_second_run_tier`、`stale_fallback_verdict`）要求宿主
  有可解析的 rust-analyzer；在没有 RA 的宿主上它们**如实变红**，这是性质而非环境噪声
  —— 与 `provider_override_honored` 同一口径。

## Non-Responsibilities

不拥有产品真相；不重写 Cargo/Git/Test/Tracing/Benchmark；不被 production crate 依赖；不直接修改业务代码；不生成或修改 `scenarios/`、`policies/` 契约内容（只执行与验证）。

## Inputs

- 仅接受公开类型、DTO、trait、事件或稳定协议对象。
- 输入必须可被结构化验证；不得依赖未声明的全局隐式状态。
- 机器模式输入输出必须是版本化 JSON。

## Outputs

- 结构化 Result / Event / DTO。
- 失败必须保留可诊断原因，不以日志文本代替错误类型。
- `--json` 输出必须包含 `schema_version` / `command` / `verdict` / `message` 四个核心字段，可按命令扩展附加字段。

## Allowed Dependencies

- 第三方（均 `default-features = false`，只开所需 feature）：
  - `serde_json`（feature `std`）：结构化 JSON 输出与 Evidence 读写；
  - `toml`（feature `parse`）：解析 `harness.toml` 与 `policies/*.toml`。
- 外部进程（只读/执行，不解析 ANSI 输出）：`git`（revision、tree digest、hash-object 计算摘要）、`cargo`（fmt/check/clippy/test）、`rustc`（toolchain/target 信息）、`rust-analyzer`（Code Intelligence 只读语义查询；经手写 JSON-RPC framing 通信，不使用第三方 LSP 库）。
- 摘要计算复用 `git hash-object`，避免引入密码学依赖（git 是 harness 的硬前置）。
- `rust-analyzer` 可执行文件解析顺序：`NEXUS_RUST_ANALYZER` → `PATH` → 无；三者皆失败即返回 `BLOCKED` + `PROVIDER_UNAVAILABLE`，不得伪造空结果。

## Forbidden Dependencies

- 无 Nexus 内部依赖。
- `engineering/` 下的 Harness/Plugin。
- 未在 `policies/architecture.toml` 声明的 Nexus 内部 crate。
- Portable 模块中的平台专有 Framework/API。
- 通过“便利”依赖绕过公开领域边界。

## Invariants

- 机器模式输出必须是版本化 JSON。
- Agent claim 不能产生最终 PASS。
- Gate 失败必须显式 FAIL/BLOCKED/UNKNOWN，不能静默降级。
- Local Harness 与 CI 使用同一 Gate 定义（`policies/quality.toml`）。
- Evidence 必须绑定 revision / working-tree / config / feature / target / toolchain / platform，并写入 `.evidence/verify-<id>/`。
- `dirty_state` 是**三态**：`true`/`false` 是 git 给出的事实，`null` 表示"问不到 git"（`Repo::dirty_state() -> Option<bool>`）。git 查询失败时绝不写 `false`——那会把"无法证明"变成一条正面事实，而 verify 的 freshness 判定正好消费这个字段（独立 Review round 2 记的 fail-open 缺口）。同一失败路径下 `working_tree_digest` 取哨兵值（`tree-unknown`/`dirty-unknown`），按上一条规则不得当作确定取值。
- verdict 语义：`PASS / FAIL / STALE / UNKNOWN / BLOCKED`；STALE 证据必须以 `"verdict":"STALE"` 形式落盘，供 `.githooks/pre-push` 检出。
- 未实现的 gate（bench/replay/coverage 等）必须显式记录 UNKNOWN，不得以 PASS 掩盖。
- git 调用失败只在**锁竞争**时重试（`.git/index.lock` 类消息，最多 4 次、25/50/75ms 退避），其它错误原样上报，不得吞掉真故障。digest 的降级哨兵值（`tree-unknown` / `dirty-unknown` / `*-unknown` / 空串）代表"没取到"，**不得**被当成一次确定的取值：`env::tests::digests_deterministic_and_sha1_length` 同时断言"两次相等"与"不是哨兵值"。
- Code Intelligence 只读不变量：客户端只允许发送白名单内的 LSP 方法（`workspace/symbol`、`textDocument/{documentSymbol,hover,definition,typeDefinition,implementation,references,prepareCallHierarchy,diagnostic}`（`typeDefinition` 为白名单预留，首期无 CLI verb 调用点：提案 §4 的 Agent-facing 列表本身不含 type-definition，故不视为未兑现，但不得假装已经暴露给 Agent）、`callHierarchy/{incomingCalls,outgoingCalls}`）；`rename`、`workspace/applyEdit`、`codeAction` 自动应用、`workspace/willSaveWaitUntil`、格式化写入、任意 `workspace/executeCommand` 一律拒绝并返回 `UNSUPPORTED`。
- provider 子进程 command/args 不接受模型或调用方拼接的任意 shell 参数（`--provider-binary` 只接受单个可执行文件名或路径，按 `split_whitespace` 之前的整串传入，不经 shell）。
- **边界校验必须发生在 spawn 之前**，且顺序是：workspace 根存在 → workspace 根归一化后仍在仓库内 → 查询目标归一化后仍在 workspace 内。三者任一失败都不得起 language server（envelope 里不出现 `provider` 字段）。round 2 的实测反例是越界的 `--workspace` 被词法判定放行、子进程真的带着仓库外的 cwd 起来了。
- `code` 永远不产出最终 PASS：`authority` 恒为 `"advisory"`，correctness 仍由 `cargo check/clippy/test` 与 verify Evidence 决定。
- `request()` 在返回匹配响应**之前**必须先 `pump_server_requests()` 一次：language server 会阻塞等待其对 server→client 请求的应答，悬置请求既会卡住 provider，也会让 `write_requests_refused` 在观测时刻还没入账（计数失真等于把拒绝能力藏起来）。
- 只读边界是**可端到端验证的**：`LspSession` 的传输端点被抽象（`child: Option<Child>` + `stdin: Box<dyn Write + Send>`），生产路径只由 `spawn()` 填入真实子进程；`#[cfg(test)] LspSession::for_tests()` 用内存流接一个假 server，走的是与真进程完全相同的 `dispatch_stream` 分流与应答逻辑。修改任何写能力拒绝路径必须让 `code_intel::lsp::tests::adversarial_server_pushed_apply_edit_is_refused_and_never_written` 保持绿色（该测试断言目标文件**不存在**）。
- `code` 结果必须绑定 `snapshot`（source_revision + working_tree_digest + target + toolchain + workspace root）；查询完成前后 digest 不一致时返回 `SNAPSHOT_STALE`。
- 取不到可信指纹时**不许**当成"没变化"：`Repo::working_tree_digest()` 在 git 调用失败时降级为哨兵值（`tree-unknown` / `dirty-unknown`），并发场景下 `git write-tree` 会因 `.git/index.lock` 竞争走到该分支。`code` 在查询前后任一侧拿到哨兵值（或空串）即 `BLOCKED` + `WORKSPACE_UNRESOLVED`，绝不返回 PASS（提案 §12/§13）。
- 命中超过预算时必须 `budget.truncated = true` 并给出 `continuation.refinement_hint`；禁止静默丢弃结果后宣称完整。字节预算与条数预算同等生效：单条结果自身超过 `max_result_bytes` 时保留它但仍置 `truncated = true`。
- Code Intelligence 的时间语义属契约面（不是实现细节）：rust-analyzer 的 workspace 加载是多阶段的，就绪只认"`\$/progress` begin/end 收敛且静默 ≥ 1.5s"（`Completed`）。**只有 `Completed` 允许把空结果当作答案**；server 从不上报进度的静默、以及预算耗尽，两者下的空结果一律 `BLOCKED` + `error.code = TIMEOUT`、`provider.ready = false`。把"还没索引完"说成"确实没有引用"即提案 §12 禁止的伪 PASS。didOpen 后另有 15s 空结果重试窗口（文件级分析需要时间）。
- provider 的构建副作用：rust-analyzer 在 didOpen 后默认跑 flycheck（`cargo check`）；其产物经 `CARGO_TARGET_DIR=<temp>/nexus-code-intel-<workspace 哈希>` 重定向到**仓库外**，被查 workspace 内不留构建产物。不改业务源码，但确有磁盘写入，故在此披露。
- 数值型选项（`--max-results` / `--max-snippet-lines` / `--max-result-bytes` / `--timeout-secs` / `--ready-timeout-secs`）必须 ≥ 1，0 属退化输入 → `QUERY_INVALID`。
- `provider.kind` 是适配器标识、`provider.binary` 是实际解析到的可执行文件，两者分开以便发现错配；`write_requests_refused`（applyEdit/executeCommand 拒绝）与 `server_requests_unhandled`（未识别请求）、`dropped_notifications`（缓冲溢出丢弃）三个计数彼此独立，不得合并。三者都按**整个 `code` 调用的累计值**上报：崩溃重启会换新会话，旧会话的计数在替换前先累加进 `provider`，否则"重启前拒绝过 N 次写请求"会随进程一起消失——计数失真等于把拒绝能力藏起来。
- `code` 永远不产出最终 PASS：`authority` 恒为 `"advisory"`，correctness 仍由 `cargo check/clippy/test` 与 verify Evidence 决定。

## Side Effects

- 允许：写入 `.evidence/verify-<id>/`（Evidence）；运行只读验证命令（cargo/git）；输出状态；为 Code Intelligence 启动长期本地子进程 `rust-analyzer`（工作目录限制在仓库/worktree 内，每请求有 timeout/cancellation，stdout 有单帧 64MiB + 单会话累计 256MiB 上限、stderr 有 64KiB 环形上限（超限即按崩溃处理，不静默截断后继续）；crash 最多重启一次且必须记入 `provider.restart_count` 与 `provider.restart_reason`，命令结束时发送 `shutdown`/`exit`）。
- 禁止：修改业务代码；修改 `scenarios/` 或 `policies/` 内容；执行网络操作；修改 git index/HEAD。
- 新增副作用前必须更新本契约和 Scenario/Policy（如影响外部行为）。
- **daemon 与缓存的写副作用（2026-10-12 新增，全部在仓库工作树之外）**：
  ① 只监听 `127.0.0.1` 的临时端口 —— 不做跨机、不做发现服务、不开放非回环接口；
  ② `temp_dir()/nexus-code-intel-daemon-<fnv>/lease.json`（租约，daemon 自己刷新与删除）；
  ③ `temp_dir()/nexus-code-intel-daemon-<fnv>/cache/`（digest 键控的结果缓存，有上限，
  不含源码原文，可用 `--no-cache`/`cache.disabled` 关掉）。
  **仓库内不得出现 daemon/缓存文件**（`dirty_after=0` 与"仓库内无残留"是验收项，
  与 flycheck scratch 同一口径）；`daemon stop` 与 idle 到期都必须删掉自己写的文件。
- 容量口径（照实说明，别把近似值当精确值）：上述 256MiB 量的是**读线程再序列化后累计的近似线上字节**（`serde_json::to_string` 后的长度），不是进程 RSS，也不是 `serde_json::Value` 的堆占用——后者通常是线上字节的好几倍，所以 256MiB 并不等于"最多用 256MiB 内存"。把口径做精确的前提是 `read_frame` 直接返回本帧消耗的字节数（round 3 待办 8），在此之前调小上限只是换一个同样含糊的数；因此本轮**不动数值**，只把口径写进契约，并把"降上限到 32–64MiB"留作带测量的独立契约周期（属契约数值变更，会影响超大 workspace 的可用性）。

## Public API

- CLI 命令与 `--json` 输出为本模块 Public API，保持版本化与向后兼容。
- 命令面：`status` / `context` / `check` / `test` / `verify` / `explain` / `bench` / `replay` /
  `scenario` / `run` / `code <8 个只读 verb>` / `mcp serve|selftest` /
  **`daemon start|stop|status|selftest`**（2026-10-12 新增，见「Provider Daemon & Result Cache」）。
  未知命令与未知参数一律 `BLOCKED`，不静默忽略、不"当成一次查询试一下"。
- 默认最小 surface：`private -> pub(crate) -> pub`。

## Verification

最低：

```text
cargo check -p nexus-harness
cargo clippy -p nexus-harness --all-targets -- -D warnings
cargo test -p nexus-harness
nexus-harness verify --fast --json   # 自举验证
```

场景（E4，机器可执行）：`scenarios/engineering/harness_verify_fast_evidence.toml`、`scenarios/engineering/harness_status_verdicts.toml`。

Code Intelligence 场景（E4，冻结于 2026-10-10 契约阶段，夹具为
`engineering/nexus-harness/fixtures/code-intel`）：
`code_intelligence_symbol.toml`、`code_intelligence_implementations.toml`、
`code_intelligence_definition.toml`、`code_intelligence_callers.toml`、
`code_intelligence_hover.toml`、`code_intelligence_diagnostics_advisory.toml`、
`code_intelligence_budget_truncation.toml`、`code_intelligence_provider_unavailable.toml`、
`code_intelligence_write_method_denied.toml`、`code_intelligence_callees.toml`、
`code_intelligence_scope_violation.toml`、`code_intelligence_read_only_counters.toml`、
`code_intelligence_budget_count.toml`、`code_intelligence_scope_escape.toml`（目标用 `..` 逃出
`--workspace`）、`code_intelligence_workspace_escape.toml`（`--workspace` 根逃出仓库，必须在 spawn 之前被拒）、
`code_intelligence_diagnostics_item_shape.toml`（诊断条目映射后的形状，round 3 待办 3；夹具
`fixtures/code-intel/src/diagnostic_probe.rs` 刻意留一处类型错误，只钉结构不钉文案与条数）。
`code_intelligence_context_anchors.toml`（Phase 2：`context` 的语义锚点有界、绑定 snapshot、
候选来自模块契约）、`code_intelligence_context_no_fake_semantics.toml`（Phase 2：provider
不可用时 `context` 的 verdict 不变且**不伪造锚点**）、
`code_intelligence_context_scope_guard.toml`（Phase 2：成员目录上报 `unsupported_scope`
且一次 provider 都不起）、`code_intelligence_mcp_handshake.toml`（Phase 3：MCP 只暴露 8 个
只读工具，未知方法/非法参数/写能力调用都被拒，并覆盖 **EOF 的两种形状** —— 客户端一条请求
都没发就挂断 ⇒ `UNKNOWN`，畸形/半帧 ⇒ `FAIL`）、
`code_intelligence_mcp_real_query.toml`（Phase 3/4：`tools/call` 走真实查询并返回 CLI 那套
中立 DTO，且第二次查询必须复用同一 provider 会话）。
`code_intelligence_daemon_lifecycle.toml`（daemon 的显式生命周期、跨命令复用与两层缓存：
**逐条钉本文件 selftest 字段清单的值**（36 条期望，`probe_count = 30`），并显式传 `--workspace`
—— 契约规定 selftest 没有缺省作用域，缺省即环境依赖。覆盖 start 幂等、默认路径不自动 spawn
（`default_path_session_source` + `default_path_lease_absent` 两枚值断言，而非用 `--no-daemon`
同义反复）、残留租约回落不谎报、错误 token 被拒、注入小 idle 后自退出并删租约、
stop 打不存在的 daemon ⇒ `UNKNOWN`、stop 后 `sessions_after_stop=0`、LRU 到容量仍只 1 个会话、
digest 变更 ⇒ `digest_invalidation_reason="digest_changed"`、结果层**真的命中过**
（`cache_second_run_tier="disk"`）、缓存有界且不含源码原文、线协议不越白名单、
命令清单含 `daemon`、生命周期全程 `dirty_after_lifecycle=0`）、
`code_intelligence_daemon_explicit_only.toml`（`--no-daemon` 下 `session_source="in-process"`，
证明 CLI 不自动 spawn，且该口径不受环境里是否有人手起过 daemon 影响）、
`code_intelligence_cache_disabled.toml`（`--no-cache` ⇒ `cache.disabled=true` 且 `tier="miss"`，
键绑定字段仍可见）、`code_intelligence_daemon_command_surface.toml`（未知 daemon 子命令 `BLOCKED`
且 declined 输出照样带 `authority`/`daemon.running`）、`code_intelligence_daemon_unknown_flag.toml`（daemon 的未知启动参数 `BLOCKED` —— 本模块两次栽在"参数被接受但不生效"上，daemon 一次新增三个参数，同一漂移最可能复发的地方就是它；参数被真实兑现由 selftest 的 `defaults_*`/`idle_self_exit_observed` 值探针钉）。共 **26** 个。

### Review 结论与待办承载体（2026-10-10）

独立 Review 三轮走完（AGENTS.md §19.1 上限）：round 1/2 = `CHANGES_REQUESTED`（阻塞项已逐条修复），
round 3 对被验 rev `3088dfe` 判 **`COMMENTED`（0 FAIL、0 阻塞、12 条非阻塞待办）**，案卷
`.evidence/review-qoder-independent-3088dfe/`。12 条待办的承载体是
`.agents/code-intelligence-followups.md`（逐条带 `文件:行` 与验收动作），本模块不另开散文清单 ——
round 2 的教训就是"待办只写在提交说明里，下一轮没有承载体"。其中第 3、4、7、9、10 条属契约面变更，
必须各自走独立 Contract-First 周期（新的 Red Evidence → 冻结 → 实现），不得与本模块的既有契约混改。

### Gate 实现状态（2026-09-15）

`verify --full` 按 `policies/quality.toml [verification.full]` 声明执行；gate 语义统一为：**有可验证内容则真实执行，工具缺失或无可验证内容则显式 UNKNOWN 并给出原因，不静默 PASS**。

- 真实执行：workspace-tests / product-scenarios / regression / architecture-policy / dependency-governance（cargo-deny 0.20：`cargo deny --config policies/deny.toml check advisories licenses bans sources`，缺失则 UNKNOWN）/ coverage-summary（cargo-llvm-cov）/ platform-checks（portable-core 平台依赖静态扫描）/ feature-matrix（每成员 `--no-default-features` + `--all-features`）/ portable-core（`cargo check --target wasm32-wasip1`）。
- 条件执行（无内容/无工具时 UNKNOWN）：integration（成员 tests/*.rs 存在时逐个运行）/ selected-fuzz（cargo-fuzz + fuzz targets）/ selected-concurrency（tests/concurrency 有测试时运行）/ performance-budgets（quality.toml `[performance]` 定义 baseline+blocking 后判定）。
- 单元测试：`cargo test -p nexus-harness`（Windows/1.95.0 上**本轮实测 137 个 = 134 passed + 3 failed**；
  Linux 只多 1 条 —— 差额是 `#[cfg(unix)]` 的真实符号链接越界回归在该宿主才编译，
  xc-pc-linux/1.98.1 在 rev `bdf2f767` **实测 138 passed / 0 failed**（§Q，不是从 Windows 推的）；
  **117/116 是 round 2 之前的陈旧声明，本区间把测试数从 117 一路推到 137 却没同步这行，
  已由独立 Review 的 N2/N-A4 抓出并在此更正**。那 3 条失败是 master 自带、依赖 POSIX `echo` 的
  `scenario::tests::run_single_*`/`run_parallel_*` 在本宿主假红，见 DEVELOPMENT.md §11.1；
  覆盖 scenario 求值、evidence 新鲜度/STALE、digest 确定性与锁竞争判定、containment 的归一化比较
  （含 `#[cfg(unix)]` 真实符号链接形态）、workspace 成员解析、dependency-governance gate 语义、
  affected 分析在 git 失败时上抛而非交空集，以及 JSON-RPC framing、只读白名单、URI 往返、
  DTO 形状与预算截断、progress 收敛判定、provider 参数校验、
  **假 server 主动推 `workspace/applyEdit` 的端到端拒绝**、
  **notification 溢出经读线程入账并出现在 `provider.dropped_notifications`**、
  **工作树指纹哨兵值不得当作新鲜**、**`..` 不能逃出 `--workspace` 或仓库**、
  **早期失败不得用 `"."` 冒充 `workspace_root`**、会话体积上限边界、跨重启计数合并、
  **serve 的三条退出形状（零请求 EOF ⇒ UNKNOWN / 畸形 ⇒ FAIL / 处理过 ⇒ PASS 且 stdout 只有帧）**、
  **负向清单上 6 个越权名逐个被结构化拒绝**、`serve` **启动参数面（只认 `--provider-binary`，
  未知参数报错而非静默丢弃）**）。
  - Windows 宿主已知 **3** 个与本模块能力无关的预存在失败：3 个 scenario 测试把 `sh`/`echo`
    当 shell 内建使用（Windows 下按可执行文件解析，管道形态读回空 stdout ⇒ `failed_step=parse`）。
    此前这里写"4 个"，第 4 条是 `gates` 的 §12.58 contract-hash 测试受 `* text=auto` 的 CRLF 检出影响 ——
    **独立 Review round 2 在本 worktree 实测它是过的**，因为该失败只在完成 CRLF 检出的宿主上出现
    （条件性由 §11.1 自己解释）。按实测改成 3，并把条件写清，不再虚报一个不存在的红。

## Performance Budget

`verify --fast` 应单次运行可在合理时间内完成并报告；未定义严格预算前不得宣称“性能完成”。进入 hot path 后必须补充 baseline / noise tolerance / warning / blocking 阈值。

## Observability

稳定结构化字段优先于自由文本；机器模式输出含 `schema_version` 与 `verdict`；失败保留 gate 名、命令与退出码。

## Recovery Semantics

Evidence 写入必须幂等：同一 `(revision, configuration_digest)` 重复 verify 覆盖同一 verify id，不产生孤儿状态；verify 中断不得破坏已有 `.evidence/`。

## Platform Constraints

平台专有代码只允许存在于 `nexus-platform-*` 或 Composition Root。本模块只依赖 git/cargo/rustc 标准工具链；不作为 portable crate（位于 `engineering/`，非 `[portable_core]` 列表成员）。
