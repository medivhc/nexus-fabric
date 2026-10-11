# Code Intelligence —— 独立 Review 后续待办与处置（round 3 判 `COMMENTED`，0 阻塞）

来源案卷：`.evidence/review-qoder-independent-3088dfe/`（审查者 `qoder-independent-session-828e3f6b`，
第 3 轮 = AGENTS.md §19.1 的上限轮，不再有第 4 轮）。
被验 revision：`3088dfe`（代码在 `95dc9ca`）；当时的结论级 Linux 证据 `verify-qoder-xc-c9bc84e20690`。

> 本文件的作用是把待办**落到有承载体的地方**（round 2 我犯的错就是只写在提交说明里，
> 下一轮没有承载体）。逐条都带 `文件:行` 或明确的验收动作。
> 2026-10-10 处置记录见每条末尾的 `【处置】`；文末"合并前置"段已去重（此前同一段被写了两遍）。

## 优先四条

1. **`gates.rs` affected 分析的 git 失败 fail-open** —— `git diff --name-only HEAD` 与
   `porcelain()` 双双 `unwrap_or_default()` ⇒ git 失败时变更集为空 ⇒ `affected-tests` 门输出
   "no affected crates changed" 并 **PASS**。
   验收：改用 `porcelain_result()`，git 失败时门输出 `UNKNOWN` 并写明原因；补失败注入测试。
   【处置：已做，提交 `c02030b`】`changed_member_names` 返回 `Result`，门侧
   `Gate::unknown("affected-tests", …)`；`Repo::porcelain()` 一并删除（零调用方 + 它是
   "把失败读成空输出"的默认值入口）。两条回归：
   `affected_analysis_surfaces_git_failure_instead_of_empty_change_set`（纯谓词层）与
   `affected_gate_is_unknown_when_git_fails`（门层，断言 verdict=UNKNOWN 且 detail 含 git）。
   失败注入没有新机制：`Repo { root: <temp 非仓库目录> }` 就是真的 git 失败源，测试先断言
   该前提成立，环境异常时明确报错而非静默跳过。
   注意 `path_is_within`（词法）在归属判定处**保留**：`git diff HEAD` 会列已删除路径，
   canonicalize 必然失败，改归一化判定会把删除的 crate 漏出 affected —— 那是另一种 fail-open。

2. **`env.rs` `dirty_state()` 的 `None` 分支零测试** —— 结构性修复（`Option<bool>` +
   序列化 `null`）已由审查者核对调用点，但没有回归保护。
   验收：断言 `dirty_state() == None` 时 `Bindings` 不产出 `false`。
   【处置：已做，提交 `c02030b`】`dirty_state_none_serializes_as_null_not_false`（null 与
   false 不是同一个绑定）+ `bindings_from_non_repo_root_keep_dirty_state_unknown`
   （真实失败路径驱动 `Bindings::current`，顺带断言工作树指纹带 `unknown` 哨兵）。

3. **诊断条目形状补一条 E4** —— deterministic 夹具里没有任何会产生诊断的文件 ⇒ 提案 §16.4
   的结构化承诺只有代码 + 单测为证。
   验收：夹具内加稳定产生诊断的源文件；属**契约扩展**，必须先跑全部场景回归再冻结期望。
   【处置：已做，提交 `54010f8`】新场景 `code_intelligence_diagnostics_item_shape.toml` +
   夹具 `fixtures/code-intel/src/diagnostic_probe.rs`（一处返回类型与表达式类型不一致）。
   顺序是先写契约与场景跑 **Red**（`scenario-edf5bdf1d4b8`：夹具还不存在 ⇒ `verdict` 期望
   落空 + `QUERY_INVALID`），再加夹具转 Green。断言只钉**映射后的结构**
   （`kind`/`kind_id`/`qualified_name=error`/`in_scope`/`path`/`snippet` 非空/`range` 存在），
   **不钉** provider 自由文本、**不钉**条数 —— RA 版本之间两者都会变，钉它们得到脆弱红。
   夹具约束（只能挂在 `lib.rs` 末尾、不得引用被冻结锚点引用的符号）写进了文件头注释。
   回归：Windows/RA 1.95 与 xc-pc-linux/RA 1.98 上 16 个场景全 PASS（Linux 侧
   `scenario-qoder-xc-90ff2c8263b8`）。

4. **`snapshot.workspace_root` 取消双含义** —— 早期失败写 `"."`，成功路径写真实 scope。
   【处置：已做，提交 `f11d9a7`】早期失败**省略**该字段，MODULE.md 的字段可得性规则与
   snapshot 字段表都写明"只在作用域校验通过后出现"；两条回归（workspace-escape 追加断言 +
   新增 `early_failures_never_claim_a_workspace_root`，verdict 按错误码表逐个钉：
   `QUERY_INVALID`→FAIL、`UNSUPPORTED`→BLOCKED）。两处既有场景期望都在成功路径上，
   没有动冻结期望。

## 其余八条

5. **symlink 越界形态跨宿主固化** —— 此前只有 xc-pc-linux 手工实测，Windows 侧无特权建链接。
   【处置：已做，提交 `c02030b`】`#[cfg(unix)]` 的 E2 回归
   `resolved_containment_blocks_symlink_escape_that_lexical_allows`：temp 目录里
   `std::os::unix::fs::symlink` 构造"workspace 内链接指向 workspace 外真实文件"，
   断言归一化拒绝、词法放过（否则测试没覆盖缺陷本身）、同目录内普通文件仍放行。
   Windows 上该测试不参与编译（117 个 vs 116 个的差额就是它）。

6. **notification 溢出缺端到端断言** —— `push_notification` 有单元测试，但没有"假 server
   连发 >256 条 ⇒ 入账并出现在 envelope"的证据。
   【处置：已做，提交 `c02030b`】`overflowing_server_notifications_are_counted_through_the_read_path`：
   经 `dispatch_stream` 真实分流路径灌 `NOTIFICATION_CAP + 5` 条 publishDiagnostics，
   断言响应仍正确返回、`dropped_notifications() == 5`，再经 `ProviderMeta::absorb` 出现在
   `provider.dropped_notifications` 上，并断言三条计数互不污染。

7. **容量口径写进 MODULE.md**（256MiB 是"再序列化后的近似线上字节"，`serde_json::Value`
   堆占用通常数倍于此；审查者建议降到 32–64MiB）。
   【处置：口径已写进 Side Effects（提交 `f11d9a7`）；**数值未动**】理由：口径精确化的前提是
   待办 8（`read_frame` 返回本帧消耗字节），在那之前调小上限只是换一个同样含糊的数；
   且属契约数值变更、影响超大 workspace 可用性，要带测量单独走一轮。
   **仍开放**：降上限到 32–64MiB 的决定本身。

8. **`read_frame` 返回消耗字节数**，去掉 `dispatch_stream` 为统计体积重复
   `serde_json::to_string` 的热路径（动签名 + 8 处测试调用点）。与 7 同源。
   【处置：未做】本轮没碰：它是纯内部重构但会改掉会话体积的度量口径，必须和 7 的数值决定
   一起做，否则"精确测量"落进一个仍按旧近似值写成的契约里。

9. **崩溃/超时路径附带 stderr 尾部** —— `stderr_tail` 目前唯一调用点是 initialize 失败。
   【处置：未做】需要先定两件事：截断长度、以及它是否进 `provider` 字段（进就是契约扩展）。
   属独立契约周期。

10. **`policies/quality.toml` 机器化声明"权威门禁宿主"** —— 现在只在 `DEVELOPMENT.md` §11.1
    散文里。【处置：仍未做，且刻意不在本分支做】Protected 路径 + 改 gate 语义，
    需要独立 Contract-First + 新 Red Evidence。本条即"机器可见待办"的承载体。

11. **PR 合并顺序必须钉住** —— 产品域 clippy 改写先合，特性分支再同步掉那几笔。
    【处置：已关闭】PR #10 已由所有者合入 master（`0e751fb`），特性分支随后 merge 掉它
    （merge commit `356f0f8`，无冲突，`git diff b30e16b HEAD` 对 harness 为空 ⇒ 两边内容
    一致，产品域权威来源回到 master）。特性分支历史里那三笔同名提交（`cebf397`/`78cc36a`/
    `3d2c986`）仍在，这是 merge 而非 rebase 的代价：本分支的 Evidence 绑定 rev 链条不能作废重算，
    保留历史比"看起来干净"更重要。
    该分支的独立自证数字保留在案卷里：`verify-qoder-xc-7c926d27ccaa` @`179a435`，
    workspace clippy exit 0、`cargo test -p nexus --lib` 192/0/2、`cargo test -p nexus-harness`
    56/0（master 基线，证明不依赖 Code Intelligence 也全绿）。

12. **Windows 侧两项结构性障碍**（`nexus-platform-linux` 无条件依赖 `fuser`；
    `apps/nexus/examples/discovery_mdns.rs` 用 Unix-only `std::os::fd`）⇒ `verify --fast`
    在 Windows 结构性不可能通过，Windows 只能作冒烟宿主。
    【处置：未做，不属本模块】标准解法（`cfg(target_os = "linux")` 门控 /
    `[[example]] required-features`）属产品域与平台域，需要另开任务。
    本轮另发现两条同类**Windows 假红**（都不是本模块引入，已写进 `DEVELOPMENT.md` §11.1）：
    master 自带的 3 个依赖 POSIX `echo` 的 scenario 单测；PRODUCT.md 冻结边界防篡改测试
    因 `* text=auto` 的 CRLF checkout 假红 —— 后者本轮已在测试内按 LF 规范化修掉，
    并补了"行尾无关"的锁定测试。

## 仍未满足的流程项

- **模型绑定**：用户要求独立 Review 用 `qwen3.8-flash`，可用的独立执行者不接受 `model` 参数，
  故 round 1–3 与 Phase 2/3/4 的 round 1 案卷一律记 `model=unbound`；会话独立性成立（非实现会话），
  模型口径不成立 —— 这一点在被问到时不能说成"已按 qwen3.8-flash 审过"。
- **Phase 2/3/4 的 round 1 已修完并双宿主复跑，round 2 待审**（AGENTS.md §19.1 上限 3 轮）：
  审查对象从 `aba6de2` 变成 `3c3bb97e`，2 条阻塞与 6 条非阻塞的处置需要另一个独立执行者
  复核，不能由实现侧自证为"已关闭"。
- `verify --full`：round 3 判 `COMMENTED` 后按 `nexus-review` 语义可进入。本轮在 rev `54010f8`
  上启动后**因磁盘余量不足主动中止**（`/work` 8.3G ⇒ SIGTERM，`verify-full-exit=143`，
  没有写出 Evidence），细节与善后见 `.agents/green-evidence-code-intelligence.txt` §J。
  上一次完整 `--full` 结论仍绑在已作废的 `3088dfe`，因此**当前没有对本 rev 有效的 --full 结论**。
- 动态对照（纯 master 的 product 场景逐条 verdict）同样未做，本轮改为静态等价论证
  （`scenarios/product/` 零差异 + apps 侧 6 文件差异全部 cfg 门控到非 Linux 分支）。
  脚本 `/work/xc-master-control.sh` 已就位，待宿主有 ≥40G 余量或改用独立 clone 时跑。
- 冷启动成本：每个场景都新起一个 rust-analyzer（Windows 实测单次冷启动 17–33s），
  连续跑时前一个的 flycheck 还在夹具 workspace 里，后一个的索引/就绪判定会被打断 ——
  本轮 Windows 串行跑 16 个场景时 `symbol` 就出现过一次假红（单跑即 PASS，
  `scenario-105171ccc9f9`）。这是提案 §15 Phase 4"持久索引 / 跨命令会话复用"要解决的问题，
  不是本轮改动引入的语义回归。

## 合并前置（三条已关闭，第四条降级为静态论证）

推送 PR #10 时发现 `origin/master` 从本分支基点 `8ba9fea` 前进 45 个提交到 `66b6b78`
（含 `apps/nexus/src/{lib.rs,main.rs,subnet_cli.rs,mesh.rs,node_cli.rs}`、
`engineering/nexus-harness/{Cargo.toml,src/run_scenario.rs}`、`policies/{architecture.toml,dependencies.toml}`、
新增 `scenarios/product/bootstrap_join.toml`）。当时记的四条前置：

1. 产品域 PR 需 rebase 后重跑 —— 已完成，PR #10 合入 master（`0e751fb`）。
2. 特性分支必须同步 master —— 已完成：先 rebase 到 `a95a989`（45 提交那一跳），再 merge
   `0e751fb` ⇒ 当前 rev `54010f8`；`engineering/nexus-harness/Cargo.toml` 与 `policies/*`
   两处双方都改的地方没有冲突。
3. 现有 Evidence（绑定 `3088dfe`）对新 rev 一律作废 —— 已重跑：`verify --fast --json`
   overall PASS、9/9 门 PASS、`cargo test -p nexus-harness` 117/0、16/16 E4 场景 PASS，
   Evidence `verify-qoder-xc-da41a40845f1`（contract `3652314f9c21`、tree `3187fff368d0`）。
4. 纯 master 的 `verify --full` 对照 —— **仍未做成，本轮降级为静态等价论证**。
   要证明的是"product 的红与本模块无关"，而整轮 --full 的 coverage/wasm/clippy 与这个问题
   无关且会吃掉十几 G；改为对照同一组 `scenarios/product/*.toml` 的逐条 verdict
   （脚本 `/work/xc-master-control.sh` 已就位），但为 master 重建 workspace 的磁盘与时间
   成本在本轮不可用，中止 --full 后余量也只够跑一次特性分支复跑。
   本轮实际拿到的是静态论证：`git diff origin/master...HEAD -- scenarios/product/` 为空，
   apps 侧 6 个文件（+43/−7）的差异全部是给 import/item 加 `cfg(unix)` /
   `cfg(target_os = "linux")` / `cfg_attr(not(linux), allow(dead_code))`，Linux 分支内容与
   master 一致 ⇒ 权威宿主上产品可见行为等价。口径限制也要记着：这不是同一命令在 master 上
   的实测对照，也不是 product-scenarios 的门包装（门包装还做 pack 归属与 UNKNOWN 映射）。

## Phase 2/3/4 独立 Review round 1（对象 `df2049c..aba6de2`）修复台账

案卷：`.evidence/review-qoder-independent-p234-r1/`（`review.md` 是审查者原文，`summary.json` 带
逐维度 verdict）。审查者是**独立于实现会话**的执行者，但两点必须记着：
①模型没能绑定（Agent 工具无 `model` 参数），口径记 `model=unbound`；
②它在 Windows 上**只做静态阅读**，没跑 cargo —— 所以它的 verdict 不能当门禁结论，
它自己也把"所有门禁结果 / E4 运行时 PASS / 第三方 MCP 客户端互操作"列进了 could-NOT-verify。
本轮修复后的复跑数字见 `.agents/green-evidence-code-intelligence.txt` §M（Windows 冒烟宿主）
与 §N（xc-pc-linux 结论级：`verify --fast` 9/9 门 PASS、`nexus-harness` 单测 133/0、
21/21 场景 PASS、`mcp selftest` 11/11 probes、Phase 4 复用 16128ms→69ms）。

verdict `CHANGES_REQUESTED`：4 个 CHANGES_REQUESTED 维度（A/B/G/H）、4 个 PASS（C/D/E/F）、
2 条阻塞（B1、G1）、4 条非阻塞（A1/A2/A3/G2）+ 1 组 minor（H1 与 E1/F/G 四条）。

1. **B1（阻塞，已修）** —— `lsp::read_frame` 把**所有**协议失败（含正常 EOF）都映射成
   `PROVIDER_CRASHED`，`serve` 的 FAIL 分支因此吃掉一切，PASS 分支变成**不可达死代码**，
   而注释"客户端关管道 = 正常退出"是假的：干净挂断与崩溃/畸形帧同形。
   【处置】`lsp.rs` 拆出 `FrameIn::{Message, CleanEof, Failed}` 与 `read_frame_result`
   （`read_frame` 原语义保留给 LSP 客户端侧，不改变 provider 失败的判法）；
   `serve` 与 `spawn_reader` 改用新入口。**偏离审查者的修法**：它建议 EOF 一律路由到 PASS，
   我改成 `handled > 0 ? PASS : UNKNOWN` —— 一条请求都没处理就报 PASS，等于把
   "什么都没验证"说成"验证过了"，与 §12 的 verdict 语义冲突。
   新增 `serve_exit_shape` 一次性子进程探测并挂进 selftest 第 8 步（默认路径即跑，不需要
   language server），因为**此前没有任何测试直接跑过 `serve`**，这正是 B1 能藏住的原因。
   实测：`verdict=PASS | eof_verdict=UNKNOWN | malformed_frame_verdict=FAIL`，
   probes `clean_eof_is_not_reported_as_crash=true`、`malformed_frame_is_failure=true`。

2. **G1（阻塞，已修）** —— 已冻结的 `MODULE.md` 场景清单只列了 4 条新场景并写"共 **20** 个"，
   而 `code_intelligence_context_scope_guard.toml` 就在同一区间落地 ⇒ 真实是 **21**。
   契约文件少报了自己的验证集。【处置】补 scope_guard 行、计数改 21。

3. **A1（非阻塞，已修）** —— `status_for_error` 会产出 `semantic_status = "invalid_query"`
   （候选符号歧义 ⇒ `code` 回 `QUERY_INVALID`），而契约枚举里没有这个值。
   【处置】`MODULE.md` 枚举补 `invalid_query`。

4. **A2（非阻塞 → 修出真缺陷）** —— 审查者指出 `MODULE.md` 写"按名请求写能力返回结构化
   `UNSUPPORTED`"，实现只回 JSON-RPC `-32602`，且 selftest 只断言 `error.is_some()`。
   把文案断言加严（要求 `-32602` **且** message 以 `UNSUPPORTED` 开头）之后 selftest 立刻变红：
   `build_argv` 把 `strip_prefix("code.")` 放在白名单判定**之前**，于是
   `workspace/applyEdit` / `workspace/executeCommand` / `textDocument/rename` 这 3 个不带
   `code.` 前缀的负向名落进"未知工具"文案 —— 把**越权**说成了"你没这个名字"，
   客户端可以换个拼法继续试。
   【处置】白名单门前移（命名约定判定留在其后，作为"白名单被改坏"的兜底），
   所有拒绝统一 `UNSUPPORTED: ` 前缀并区分"写能力工具"与"不在只读白名单"；
   selftest 第 6 步改为**逐个试完负向清单上的全部 6 个名字**（只抽一个，其余 5 个是 free-ride）；
   单测 `forbidden_tool_names_are_refused_not_executed` 从"只断言有 error"升级为断言
   `code` + 前缀，并补了带/不带 `code.` 前缀两类陌生名。
   值得留一句教训：**"断言只做到 error 存在"等于没断言 message** —— 契约写的是形状，
   测试就要钉形状。

5. **A3（非阻塞，已修）** —— `semantic_budget` 的字段形状块漏了 `candidate_spans`
   （`commands.rs` 在发、同文件的不变量文字在要求）。【处置】字段表补上。

6. **G2（非阻塞，已修）** —— `FILE_MANIFEST.md` 的 changelog 写"新增 4 个场景 / 16 增至 20 /
   178→184"，而表内实为 5 行、头部是 185（声明总数与行数本身是一致的，只有叙述陈旧）。
   【处置】改为 5 场景 / 16→21 / 178→185。

7. **H1（非阻塞，不改，记理由）** —— `status_for_error` 为 context 路径重复编码了一遍
   `code` 的错误→结论映射。这是契约里明写的口径（context 的 `semantic_status` 词表与
   CLI verdict 不同源），消重复就得动 `code` 的冻结错误映射表 —— 收益是 DRY，代价是
   动已冻结语义，本轮不做。漂移风险由 `mod.rs` 的显式 match 分支 + `invalid_query`
   单测（A1 补齐后枚举与实现同形）压住。

8. **E1/F/G minor 四条（不改，逐条记理由）**
   - `anchors` 在作用域门**之前**调 `Bindings::current`（git），`context <成员目录>` 即使
     declined 也付一次 git 调用。**不改，而且不能改**：`context_scope_guard` 场景要求
     declined 结果仍带 `snapshot.source_revision`（非空），把 git 调用挪到门后就丢绑定。
     已在 `anchors()` 里把这段顺序理由写成注释，防止下一轮把它当"优化点"删掉。
   - anchors 的 happy-path / 复用循环 / "首个命中即停"没有单测，只有 E4（依赖真 RA）。
     本轮不加：需要造假 provider 才能测，属独立一小块工作。
   - 会话重建失败时旧 provider 活到 `serve` 退出。可接受：作用域只在同一进程内，
     `ProviderSession` 的 `Drop` 保证退出即回收，不留孤儿。
   - MCP 的预算参数没有上限校验 —— 与 CLI `code` 同口径（上限由上下文预算与截断可见性兜），
     不是本区间新引入的差别。

## Phase 2/3/4 独立 Review round 2（对象 `aba6de2..a3af128`）发现与处置

案卷 `.evidence/review-qoder-independent-p234-r2/`。verdict **`COMMENTED`，0 阻塞**：
round 1 的 B1/G1/A1/A2/A3/G2 全部 **CLOSED**，H1 与 4 条 minor 的"不改"处置被接受
（E1 那条审查者还去 `scope_guard.toml:58-60` 与 `commands.rs:189` 核了一遍，确认"declined 也必须
带非空 `snapshot.source_revision`"是真的，所以顺序不能挪）。与 round 1 不同的是这次它**跑了命令**
（fmt/clippy/test/selftest + 十条直接喂字节流的 `mcp serve` 探测），所以结论有载体。
模型口径仍旧：**`model=unbound`**。

新增 7 条非阻塞，处置如下（修前实测在 `.agents/red-evidence-mcp-round2.txt`）：

- **N5（已修）stdout 被裸 JSON 污染** —— `main.rs` 对所有命令一律 `println!`，而 `mcp serve` 的
  stdout **就是协议通道**：干净 EOF 时 stdout 是 194 字节裸 JSON；处理过请求后裸 envelope 直接
  粘在最后一帧尾部、中间没有分隔。修：只有 `mcp serve` 的退出 envelope 改打 stderr
  （human 与 `--json` 两种形态都改，退出码仍由 verdict 决定），stdout 恢复为纯帧通道，
  并在 selftest 里断言"stdout 可按帧完整消费且无多余字节"。
- **N4b（已修）PASS 分支此前不可探针** —— round 1 修好的 `handled > 0 ⇒ PASS` 只能靠人工
  `printf` 观察，因为旧探针"取最后一行 JSON"在 N5 那种粘连下解析不出来。修后新增
  `handled_request_exit_is_pass_and_stdout_is_pure` 探针（喂一帧 `initialize` 再关管道 ⇒
  `PASS` + `handled_requests=1` + 恰好 1 帧纯净 stdout）。
- **N4a（已修）notification 探针自我实现** —— 原来 `ok = write_frame(..).is_ok()` 测的是管道写通，
  与被声称的"不产生回复"无关。改成**序列证明**：notification 之后紧发的 `id=2` 请求，
  其响应必须是管道里的下一条帧（`response.id == 2`），不吃超时也不靠"没读到东西"。
- **N6（已修）`serve` 的退出 envelope 没有 `snapshot`** —— 新增的 `UNKNOWN` 恰好就是 declined 形态，
  按 doctrine declined 要说自己绑在哪棵树上。四条退出路径统一带
  `authority + handled_requests + snapshot`（`serve_exit_fields`），并加单测钉住字段存在性。
- **S1（自查发现，已修）`handled_requests` 从没写进契约** —— 它偏偏就是 PASS/UNKNOWN 的判据本身。
  "一个决定 verdict 的量只活在代码里"属于本模块最不该有的形态，已在 MODULE.md 定义
  （已回复请求数；notification 不计）。
- **N1（已修）`--provider-binary` 在 `mcp serve` 上静默失效** —— 契约承诺了它，`dispatch` 却把
  `args` 整个丢掉，实测给 `/definitely/not/ra` 与不给了完全同形、exit 0。修：`serve(args)` 解析
  `--provider-binary`（空格与 `=` 两种形式，空值拒绝），线程化进 `run_with_session` 的同一 argv 通道
  （于是解析顺序与"指定了但不存在 ⇒ `PROVIDER_UNAVAILABLE`、不回退 PATH"一并生效）；
  **未知启动参数一律 BLOCKED**，不再静默。新增端到端探针 `provider_override_honored`：
  另起一个带不存在路径的 serve，跑真实 `tools/call`，断言错误码是 `PROVIDER_UNAVAILABLE`
  **且**原因文字点名 `--provider-binary`（两件事同时成立才算过 —— 单看错误码无法排除
  "悄悄用了 PATH 上的 server 之后又失败"）。
- **N2（已修）MODULE.md 的单测数陈旧** —— 还写着 Linux 117 / Windows 116，而本区间自己把测试数
  从 117 推到了 134（Windows 实测 131 passed + 3 failed；Linux 多 1 条 `cfg(unix)` ⇒ 135）。
  同一段还漏了 serve 退出形状、6 名越权拒绝、启动参数面三类新覆盖。
  顺带更正另一处虚报：原文说 Windows 有 **4** 个预存在失败，第 4 条（§12.58 contract-hash 测试）
  在本 worktree 实测**是过的** —— 它只在完成 CRLF 检出的宿主上红，条件由 §11.1 自己解释。
  按实测改成 3 并写明条件。
- **N3（已修，我自己写错的台账）** —— `.agents/green-evidence-code-intelligence.txt` §N 把 Linux
  第 6b 步的默认 `mcp selftest` 记成 "11/11 probes"，实测输出是 **8/8**；11/11 是另一次
  `--with-query` 的数。把没跑过的探针算进结论正是提案禁止的那类错误。勘误见 §N 末尾与 §O。
- **N7（已修）** —— `mcp.rs` 模块文档还说分帧复用 `read_frame`（实际入站读用
  `read_frame_result`，provider 侧才用 `read_frame`）；`mapped_scenarios` 是子串启发式，
  它的条数不是场景总数（`context engineering/nexus-harness` 报 20 而清单 21，因为握手场景
  正文不含目标路径串）—— 已在 MODULE.md 写清口径，防止被当成"有场景漏登记"的假结论。

本轮学到、值得留着继续生效的三条口径：
① **契约承诺的开关必须端到端证明**，"参数被接受"不等于"参数生效"，而"exit 0 且输出没变"
   是最坏失效形状（看起来成功）；
② **传输通道的纯度属于正确性**：一个 CLI 顺手 `println!` 到 stdout，就能让协议服务端
   在会话结尾发出客户端读不进去的字节；
③ **决定 verdict 的量必须出现在输出里并被契约定义**（`handled_requests` 就是这一轮的例子）。

### 本轮新登记的两条后续项（有承载体，不靠记忆）

- **场景证据 id 的覆盖行为**：`evidence.rs:218-231` 的 `scenario_run_id` 种子是
  `source_revision + scenario_id + configuration_digest + contract_hash`，**不含工作树指纹**。
  于是同一 rev 上脏树的两次运行算出同一个 id，后一次直接覆盖前一次的
  `.evidence/scenario-*/summary.json`（本轮实测：`callees` 的 FAIL 与 PASS 都是
  `scenario-8eed2a7b113c`，磁盘上只剩 PASS）。
  影响面：**在同一 rev 上做 Red→Green 时，`.evidence/` 留不下 Red** ——
  本模块一直把 verdict/输出逐条抄进 `.agents/*evidence*.txt`，正是因为这个覆盖，不是巧合。
  修法二选一，都要另走契约周期（它改的是 Evidence 语义，属 harness 的对外承诺）：
  ① 把 `working_tree_digest` 加进种子（Red/Green 自然分家，代价是同一棵脏树上的重复运行
  不再复用同一条记录）；② 保持 id 稳定但**追加** `runs[]` 历史而不是覆盖 summary
  （可读性更好，代价是记录格式变更）。本轮不动，理由：不属于 Phase 4 目标，且需要
  先定义"同一条场景记录"到底代表一次运行还是一个 revision 的结论 —— 那是另一个契约问题。
- **E4 批次期间不得并发构建**：批量场景跑的是真实 rust-analyzer，flycheck 走
  `CARGO_TARGET_DIR` 指定的 scratch；此时执行 `cargo build` 会争 target 目录锁，
  让某条场景拿到 `BLOCKED`（本轮 `callees` 就这样假红过一次，单跑即 PASS）。
  已写进 §O 的过程事实；下次接手先确认没有构建在跑再开批次。



