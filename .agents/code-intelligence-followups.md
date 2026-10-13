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
  **round 3 把这条判据说重了**：RA 缺失时的兜底文案里本身就含 `--provider-binary` 字样
  （`provider.rs` 的"找不到 rust-analyzer：…或设置 NEXUS_RUST_ANALYZER / --provider-binary"），
  所以只断言那两条，在**没有可解析 RA 的宿主**上把 threading 整段删掉也照样绿 ——
  审查者用受控 PATH 复现了这个假绿。现改为三条：码 + flag 名 + **原因里带上我传进去的那条路径**，
  并补一条不依赖子进程的直接单测 `tools_call_threads_startup_provider_override`。
  副作用要说清：这条探针在没有 RA 的宿主上会**如实变红**，那是它该测的东西。
- **N2（已修）MODULE.md 的单测数陈旧** —— 还写着 Linux 117 / Windows 116，而本区间自己把测试数
  从 117 推到了 **135**（rev `52184e9`/`c453a0b` 时点 Windows 实测 132 passed + 3 failed；
  Linux 多 1 条 `cfg(unix)` ⇒ 136）。round 3 整改又加了 2 条测试，`c453a0b` 之后是 **137**
  （134 passed + 3 failed，Windows；Linux 待 §Q 实测），所以这里的原则改为：
  **凡引用条数就带 rev**，不写"现在的总数"。
  本文件此前把它记成 134/131/135，是 round 3 的 N-A4 抓出来的第三次同类漂移 ——
  同一 commit 修了 `MODULE.md` 与 §O 却没扫到这里。正确值以 `MODULE.md` 与 §O/§P 实测为准。
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

## 独立 Review round 3（末轮，对象 `a3af128..c453a0b`）发现与处置

案卷 `.evidence/review-qoder-independent-p234-r3/`。verdict **`COMMENTED`、0 阻塞、无新回归**，
round 2 的 N1-N7 + S1 **全部 CLOSED**（这次审查者跑了 29 条命令并先重建了二进制）。
它同时给出一个我必须接住的判断：**我自己那两次自我更正（§N 11/11→8/8、§O 134→135）
不是偶然，是系统性弱点** —— 数字是从一次终端输出抄下来的、没有随存工件，
更正靠记忆传播而不是靠检索（135 那次修了两个文件、漏了两个）。
这是 §19.1 的第 3 轮 = **上限轮**，所以以下 N-A1..N-A6 属整改项，**不再有第 4 轮复核**，
完成与否由所有者判定。

- **N-A2（已修，且是本轮最有价值的一条）** —— 我上一轮写的 `provider_override_honored`
  判据可以假绿：它要求 `PROVIDER_UNAVAILABLE` + 原因含 `--provider-binary`，
  而 rust-analyzer 缺失时 `provider.rs:209` 的**兜底文案本身就写着这个 flag 名**
  （"…或设置 NEXUS_RUST_ANALYZER / --provider-binary"）。审查者在 RA 不可解析的受控 PATH 下
  复现了等价状态：把 threading 整段删掉，谓词照样为真。
  我先前写在代码注释与待办里的"两条同时成立就排除了悄悄用 PATH 上的 server"是**过度声称**。
  修法：判据抽成纯函数 `override_proof_honored(code, reason, bogus_path)`，第三条要求
  **原因里带上调用方实际传入的那条路径**；另加单测
  `override_predicate_rejects_the_rust_analyzer_missing_fallback`，直接拿兜底文案真身当输入，
  在**没有 RA、没有子进程**的环境下把这条假绿证伪（我用受控 PATH 试过端到端复现，
  但那种环境同时切掉了 git，导致失败发生在 `WORKSPACE_UNRESOLVED` 而非 provider 解析，
  所以最终采用可确定性复现的纯函数单测，而不是一个"大概能复现"的环境实验）。
  再加 `tools_call_threads_startup_provider_override`：以前所有 `handle_request` 单测都传 `&None`，
  threading 本身没有任何直接覆盖。
  代价说清：这条探针在**没有 RA 的宿主上会如实变红** —— 它测的是 flag 有没有兑现，不是环境好不好。
- **N-A1（已修）** —— `selftest` 的 BLOCKED 路径只回 4 个核心键，而同一轮我在 MODULE.md
  新写了"字段缺任何一个都算契约破坏"。`code`/`serve` 的 declined 都带 `authority`+`snapshot`，
  规矩不能只对它们生效 ⇒ 三条 declined 路径改用 `decline_fields()`。
  顺带修一处潜在阻塞：selftest 的子进程 stderr 是 piped 却从不排空，而 N5 之后 envelope
  正好写在 stderr 上 ⇒ 改 `Stdio::null()`（要看 envelope 的是 `serve_exit_shape`，它自己收全）。
- **N-A3（已修）** —— `frames == handled` 只在 PASS 分支比对；零请求与畸形分支上冒出一条
  **格式合法**的幽灵帧仍然会绿，而幽灵帧正是"把 envelope 当帧发出去"的形态 ⇒ 三条分支全比。
- **N-A4（已修）** —— 135/136 的更正没扫到本文件（`52184e9` 加的段落仍写 134/131/135），
  于是两个文件对同一个数各执一词。已按审查者要求的勘误协议 `git grep` 一遍旧值并逐处表态，
  同时把口径改成"**引用条数必须带 rev**"（round 3 整改又加 2 条测试 ⇒ Windows 现在是 137，
  Linux 待 §Q 实测，不在契约里预填）。
- **N-A5（已修）** —— §O 记的 stderr `682 字节` 其实是在**脏树**上取的（clean 是 683，
  Linux 三元组换算是 685 = §P 的数），而那一行没带任何条件限定 —— 恰好是它上面一条
  刚立下的"数字必须带宿主与测量时点"规则的违反者。已就地补全条件。
- **N-A6（已修）** —— 第 9 步 gate 在 `failure.is_none()` 上，前面一失败它就"没跑"，
  但输出里记的是 `false` ⇒ "没跑"与"跑了没过"在消费方看来同形。改成不 gate（它不需要 RA、
  几十毫秒），并把探针条数变成机器可核字段 `probe_count`（握手场景钉 11、real-query 钉 14）——
  §N 那次记错条数正是因为这个数只活在散文里。

审查者提的"下一轮该怎么记数"我按可行性接了这些：判据尽量做成**纯函数 + 单测**（能在无 RA、
无子进程、无网络的环境下证伪），条数变成**输出字段**由场景钉住，引用数字必须带 rev，
勘误时 `git grep` 旧值并列出故意保留的历史值。没接的一条：**每个结论数字都要有随存工件**
——场景证据的确定性 id 会覆盖前一次记录（本文件上面登记的那条后续项），所以工件化要等
那个 id 语义先定清楚，否则会写出"看起来有工件、其实每次都被覆盖"的假安全感。

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
### 后续项：一条语法错误的场景文件会**无声消失**（harness 自身的 fail-open）

- 现象与载体：2026-10-12 写 `code_intelligence_daemon_unknown_flag.toml` 时 `title` 里嵌了裸
  双引号 ⇒ TOML 非法；`scenario run <id>` 报 `unknown scenario id`（`failed_step="lookup"`，
  `scenario-b349976b96b7`）。根因在 `scenario.rs:52-53`（`read_to_string(..).ok()?` +
  `toml::from_str(..).ok()?`）与 `scenario.rs:168-189`（`load_all` 对 `None` 直接跳过）。
- 为什么这是 fail-open：解析失败不产生任何 verdict、不减少任何门禁的绿度，
  只让 pack 少一条场景。实测 `gates.rs` 里没有"声明条数 == 加载条数"的校验。
  最坏情形不是"我的测试没跑"，而是**别人删坏/改坏一条场景后，门禁照绿**。
- 修法（都要另走契约周期，因为改的是 Evidence/门禁语义）：
  ① `load_all` 返回 `(scenarios, load_errors)`，`scenario run` 对已知文件名的 id 缺失时
     把解析错误原文带进 `failure_signature`（现在只有 `unknown scenario id`）；
  ② 场景 pack 的门（或 `MODULE.md` 声明的场景数）加一条"清单条数 == 实际加载条数"的
     机器核对，少一条即 `UNKNOWN`/`FAIL` 并列出文件名；
  ③ 顺手把 `lookup` 与 `expect` 的区分写进 `DEVELOPMENT.md`（本模块已两次靠它辨认真红灯）。
- 本轮不动它：属 harness 通用能力，与本特性无耦合；混在 daemon 提交里会让两件事都难审。

## daemon 实现落地时新学到的三条（2026-10-13，Windows 冒烟宿主）

### F-新1：daemon 在跑会锁住可执行文件，`cargo build` / `cargo run` 直接失败

- 实测症状：`cargo build -q -p nexus-harness` 报
  `error: failed to remove file D:\next\ci-p24\target\debug\nexus-harness.exe  拒绝访问。(os error 5)`；
  另有一个 `cargo run -p nexus-harness -- verify --fast`（00:44 起）因为同样的锁**卡了 6 分钟没结束**。
- 机理：Windows 给运行中的映像加文件锁。daemon 与 harness 是同一个 exe ⇒ 只要有一个 daemon 活着，
  这个 exe 就编不动。Linux 上没有这件事（可覆盖已打开的 inode）。
- 为什么不是"实现细节"而是流程：**冒烟宿主的整个验证顺序被它约束**。跑 `daemon selftest` 期间不能构建；
  构建前必须 `daemon stop`（或等 idle 到期）。这与既有的"跑 E4 批次期间不许并发构建"是同族约束，
  但成因不同：那条是 target 目录锁，这条是映像锁。
- 建议的承载体（要另走契约周期，因为它改 `status` 的对外可得性）：
  `daemon status` 增加一个 `exe_locked_by_daemon` 观测（比较租约里的 pid 与自身可执行文件路径是否同一镜像），
  让"你现在编不动是因为你自己起了 daemon"成为可见事实而不是 os error 5 的谜。本轮**不动它**，先登记。

### F-新2：`Stdio::null()` 在 Windows 上会把调用方的管道句柄漏给 daemon —— 已实现侧修复

- 实测症状：`nexus-harness daemon start --json | cat` **不返回**（40s 超时被杀），但 envelope 已经打出来了；
  同一命令把 stdout 重定向到文件则 464ms 返回。第二个观测：node 的 `execFileSync` 调 `daemon start`
  永久挂住，而 daemon 本身健康（内部 ping 正常应答）。
- 机理：daemon 继承了父进程那个**可继承的管道写端**。读端要等所有写端关闭才见 EOF ⇒
  只要 daemon 活着，任何"用管道读子进程输出"的调用方都会挂住 —— 场景求值器正是这么读的。
  这不是性能问题：**它会让 daemon 的 E4 场景永久挂住而不是变红**，正是本模块最坏的那种失效形状。
- **更正（上一条写错了）**：我写完就登记了"修法（本轮已做）"，但**实测证伪了它**。三种写法逐个测：
  ① 三句柄全 `Stdio::null()` ⇒ 挂 40s；② stdout/stderr 给 `serve.log`、stdin 仍 null ⇒ daemon
  因目录不存在起不来（`create_dir_all` 补上后继续）；③ stdin/stdout/stderr **全部**给显式文件句柄
  ⇒ 仍然挂满 25s 超时（rc=124），而同一命令 stdout 重定向到文件时 400ms 返回。
  结论：这是 Windows 的**可继承句柄传播**，`std::process::Command` 的 stdio 写法决定不了它；
  要挡它需要 Win32 handle list（`PROC_THREAD_ATTRIBUTE_HANDLE_LIST`），而本 crate 顶部
  `#![forbid(unsafe_code)]` 且零新依赖 ⇒ 这条路按现约束走不通。
- 因此本轮的处理是"写明口径 + 不假装修好"：MODULE.md 的 daemon 一节新增一条 Windows 已知效应，
  并指明消费方要么把 daemon 的输出重定向到文件，要么走 harness 已有的
  `run_command_with_timeouts`（有界读，回归测试 `run_command_orphaned_grandchild_holding_pipe_returns`），
  所以 daemon 的 E4 场景是"多花一次读超时"而不是"永久挂住"。`serve.log`/`stdin.devnull` 保留，
  理由改成"崩溃有证据"，不再是"修管道"。
- 留作下一个契约周期的候选（都是契约面变更，不混进本轮）：
  ① 允许 `daemon start --no-spawn` 只写启动意图、由调用方自己后台化，从而彻底不产生孙进程；
  ② 或把"daemon 必须脱离父进程句柄表"列为引依赖的例外，由所有者裁决。

### F-新3：`sessions_after_stop = 0` 的可观测边界要说清

- 机制是 `ProviderSession::Drop` 关掉 RA 子进程，selftest 报的 0 是 daemon **在退出路径上自己数出来的**。
  "曾经有会话"由 `stop_reply.sessions_before_stop` 同时带出，避免只报 0 的自证。
- 取不到的是**外部**证据：不用 libc 就没法可移植地问"pid N 还活着吗"（契约明确禁止 `kill(pid,0)`，
  因为那要引依赖）。Windows 上可以 `tasklist /FI "PID eq N"`、Linux 上可以 `stat /proc/N`，
  但那是两宿主两套实现 —— 与本特性"两宿主同一实现好冒烟"的决定相冲。
- 所以这条的性质是"结构事实 + Drop 语义"，不是"进程表里查无此 pid"。要后者就得另开一个
  带 cfg 分叉的契约周期；登记为待办，不混进本轮。

### F-新4：selftest 的 23 枚字段，**值**层面只有一个承载体

- 现状：`daemon_selftest_field_list_matches_contract` 解析 MODULE.md 的清单代码块，与实际发出的
  键集合**逐名**对齐（多一名少一名都红）。但它不比对每行的**值**列。
- 现实后果（本轮实测）：我把 `cache_default_enabled` 的语义读反，发的是 `cache.disabled=false`
  而不是契约的"默认允许=true"；selftest 自己全绿，是 `code_intelligence_daemon_lifecycle`
  把 `equals = true` 钉住才红的。也就是说：**名字有双重承载体，值只有场景一重**。
- 建议的承载体（属契约面 + 测试面变更，另开周期）：把那枚单测升级成同时比对
  `(名字, 契约声明的值)` 与 `(名字, 探针期望的值)`，期望值从 inline 的 `json!(...)` 抽成
  一张 `const EXPECTED: [(&str, Value); 23]` 表 —— 表与清单不符即红，不需要跑冷启动。

### F-新5：xc-pc-linux 上有两个"看起来是新构建"的旧二进制（§R 第一次整批作废的真实原因）

- 症状：§R 首跑里 4 条 daemon/cache 场景在 ~100ms 内 FAIL、`daemon selftest` 直接 `BLOCKED`
  （`supported commands: … code` —— 那句里根本没有 `daemon`）。看着像"Linux 上实现没生效"。
- 真相是**宿主环境陷阱**，两条同时成立：
  ① 远端 shell 里 `CARGO_TARGET_DIR=/work/nexus-dev/target` ⇒ `cargo build` 的新产物落在那儿，
     而我的脚本执行的是仓库内**残留**的 `/work/nexus-ci/target/debug/nexus-harness`（mtime 10-12 19:31）；
  ② `PATH` 上还有一个 10-12 00:58 的 `cargo install` 版（`/work/nexus-dev/.cargo/bin/nexus-harness`）。
  同一份源码、三个不同世代的二进制同时存在，`cargo test` 报 150 passed 与 stale 二进制互不矛盾，
  所以**光看 exit code 发现不了**。
- 处理：§R 重跑一律用 `CARGO_TARGET_DIR` 下的新鲜路径，并在案卷里显式记 `ls -la $BIN` 的 mtime；
  首跑的那批 FAIL 结论**不作数**，也不拿它当"Linux 回归"。已按 `nexus-review` 案卷硬要求写清宿主与工具链。
- 后果之一（正好落在既有待办上）：重跑用同一场景 id 得到 PASS，而场景 evidence_id 是确定性的 ⇒
  它**原地覆盖**了 stale 二进制的 FAIL 记录（`scenario-05ee009a7979` 先 FAIL 后 PASS）。
  "先落盘再复跑"这条老规矩在这轮救了一次场：不落盘就没人知道那条 FAIL 发生过。
- 建议的承载体（属 harness/门禁面，另开周期）：`scenario run` 与 `status` 的输出里带上
  **被执行二进制的路径与 mtime**（现在只有 `source_revision`/`working_tree_digest`，它们描述仓库，
  不描述跑的是哪个构建）。缺这一项，"新代码的结论"与"旧构建的结论"在案卷里长得一模一样。

## daemon/缓存 独立 Review round 2（对象 `f075157`，案卷 `.evidence/review-qoder-independent-daemon-r2/`）

B-1 已由审查者实测判 **CLOSED**（真生命周期链 + 四组假监听端反证）。本轮 1 条阻塞 + 6 条非阻塞，
逐条处置如下；实测数字在 `.agents/green-evidence-code-intelligence.txt` §V。

- **B-2（阻塞，已修）**：整改时我在 MODULE.md 写的"CLI 拿不到应答时报 `-1`"是**单一分支**的现时态
  宣称，而实现（和同批新单测）在"根本没连上"这一支是**不发该字段** ⇒ 两处承载体无共同解。
  修法按审查者要求只动契约文本，不动实现/语义/场景：把取值写成两支（① 连上但没应答 ⇒ `-1`+UNKNOWN；
  ② 没连上 ⇒ 字段缺席+UNKNOWN），并写清"发 0 与发 -1 在这里都不是证据"。
  教训与盲评 r4 同一条：**散文里的现时态行为描述必须与分支图同构**，写一支等于给另一支承诺了没有的东西。
- **N-r2-1（已修）**：stop 分支已在回帧前 `drain_pool`，外层第二次 drain 是对空池做的 ⇒
  我新加的 `sessions_before_exit` 与 `daemon serve` 自报的 `provider_sessions` 双双恒 0，
  B-1 换来的可证伪性在这两个字段上被我自己抵消了。修法：`Conn::Stop` 从单元变成带 `Drain`
  （回收观测只有**一个**出处），删掉 `sessions_before_exit`（无承载体就不许有字段），
  `serve` 的退出 envelope 改用带出的那份 ⇒ `provider_sessions` 在 stop 路径上可以是真非 0。
- **N-r2-2（已修）**：实测 `status` 对一个"连得上但不答话"的监听者 **25s 未返回**（exit 124），
  根因是握手/探活与查询共用 `CLIENT_READ_TIMEOUT=900s`；同时 `start` 对"没答话"的租约拒绝覆盖，
  于是僵住的 daemon 既等不起也清不掉。修法：拆出 `PROBE_READ_TIMEOUT`（长超时只在 `query`/`stop`
  这两档打开）+ 契约级逃生口 `--takeover`（显式授权放弃旧租约，**仍不 kill pid**）。
  两档预算的载体是单测 `silent_daemon_probe_returns_within_the_probe_budget`（夹具：accept 后
  永不回帧的监听者；断言**时长**而不是文案，合并预算的实现会先让它红）。
- **N-r2-3（已修，方向本来安全）**：`stop_in` 里"等租约消失"的 10s 轮询在负载宿主上是瞬时假红源。
  两点处置：① 上限提到 30s 并把数值写进 reason 文案（`租约已删=?，等待上限 30s`），红的时候能自证
  是"没等到"还是"daemon 报了未退出"；② **不**因为超时就去替 daemon 删租约 —— 猜着删就是把
  "可能仍在收尾"的活 daemon 变成找不到主人的孤儿。
- **N-r2-4（已修）**：plan 的取代指针用"下文 69 行/82 行"自指，而我插入的 12 行把它们推到了 81/94
  —— 行号锚点在**被自己锚定的文件**里必然漂移。改成节名锚点（§4「两层"缓存"必须分开定义」/
  §5「输出字段」）。通则：**指向会被本文件改动影响的行号 = 承诺一个自己维护不了的量**。
- **N-r2-5（已修，且升级为记法要求）**：§U 只写了 rev 与 mtime 级信息，没落被执行二进制的 md5，
  于是"冻结副本 + 核 md5"停在建议层（正是 F-新5 那条宿主陷阱的成因）。§V 起：Windows 与 Linux 的
  运行记录都必须带**同一次**跑的二进制路径 + md5 + mtime，缺一项则该条结论按"未固定被测物"处理。
- **N-r2-6（注释与事实不符，已改注释，不改行为）**：`drain_pool` 的注释写"问不到（Err）算仍活着"，
  而代码用 `matches!(…, Some(false))`：`close_with_report` 是三档 —— `Some(true)` 操作系统确认已退、
  `Some(false)` 仍活着**或最后一次 `try_wait` 问不到**（`lsp.rs` 的 `reaped` 只认 `Ok(Some(_))`，
  "问不到"落在这档）、`None` 是这个条目根本没有会话可回收（从未开过或已被 `Drop` 收过）⇒ 不算泄漏。
  同时如实写覆盖面：观测只到**直接持有的子进程**，rust-analyzer 自己再 spawn 的后代不在 std 能
  枚举的范围（要 libc）⇒ `sessions_after_stop=0` 说的是"我们那批句柄都退了"。这条与
  **F-新3 同源**，F-新3 说的边界就是它。

### round 1 遗留五条在本轮一并销项

- **N-3（已更正记录，数据未改）**：§T 把两个 `daemon selftest` 的 `duration_ms`（330.7s / 268.9s）
  与一条**场景**的端到端耗时（172.5s，含 29 条期望比对）写成"同一份码三次"，因此 1.9 倍散布是
  我算错量纲得到的。已在 §T 就地更正：selftest 自身的散布是 1.23 倍，命令超时余量按上界 330.7s
  算仍是 ~1.8x（结论方向没变，数字的来源变了）。
- **N-4（已修）**：`FILE_MANIFEST.md` 里 `..._daemon_explicit_only.toml` 的描述漏了 `--no-cache`
  —— 该场景现在两个 flag 都给（MODULE.md「`--no-daemon`/`--no-cache`」一条写明了理由），
  描述与命令行不一致会让下一个读清单的人以为只给一个。探针数目（23）上一轮已改。
- **N-6（已修，改的是契约措辞）**：MODULE.md 原写"命中条件：`cache.key_digest` 等于本次
  `snapshot.working_tree_digest`"，而 miss 路径上这个等式**同样成立**（key_digest 就是本次键里
  的那个 digest）⇒ 等式是必要条件，不是命中证据。现改为两层：命中证据只有 `cache.tier="disk"`，
  并如实写明 `--no-cache` 也发 `"miss"`、靠 `cache.disabled=true` 区分（这条由
  `code_intelligence_cache_disabled` 钉）。**教训：把"键没串"写成"命中了"就是给假绿开一门。**
- **N-7（按设计保留，作口径备忘）**：求值器没有"字段缺席"与"字段对字段"比较算子，所以
  等式/缺席类性质只能活在点名单测里。这是 harness 的限制（与 F-新4、§后续项那条 fail-open 同域），
  不在本周期改门禁面；MODULE.md 已就地披露"由点名单测承载"。
- **N-9（已修，注释）**：`mod.rs` 说 target 分量是"argv 去掉两个策略 flag"，实际 `--json` 也不在
  分量里 —— 但那是 `main.rs` 在分发前剥掉的，不是这里滤的。注释补齐第三个来源，并保留
  "宁可多算一项而 miss"的原则句。

## daemon/缓存 独立 Review round 3（末轮，对象 `9fae434`，案卷 `.evidence/review-qoder-independent-daemon-r3/`）

verdict `CHANGES_REQUESTED`：1 阻塞（B-3）+ 11 非阻塞。**这是本对象的末轮**（AGENTS.md §19.1
的 3 轮上限），所以下面的整改**没有第 4 轮独立复核**，完成判定归所有者。实测数字与被测物身份在
`.agents/green-evidence-code-intelligence.txt` §X。

- **B-3（阻塞，已修，只动契约文本）**：r2 整改留下的那半句。契约说"连上了但没拿到应答 ⇒ -1"，
  而实现的判据是**握手有没有拿到 `ready` 帧**；评审用四个形状实测（ready 后 EOF ⇒ -1；连上但不答话 /
  答 refused / 被拒 ⇒ 字段缺席），同一段话对两支各说一半 ⇒ 无共同解。契约重写成"① 握手成功后
  没应答或帧里没这个量 ⇒ -1；② 握手没成功（含被拒、不答话、不合格帧、版本不符）⇒ 字段缺席"，
  并给 ① 补上承载体。
  **通则（与前两轮同一条教训连起来）：写行为分支必须按**实现的判据**分，不能按"语义上相邻的两端"分；
  上一轮我漏了"连上但不答话"到底属于哪一支，这一轮把"连上"这个词整个换掉。**
- **N-r3-5 / N-r3-6（已修，有前后对照）**：`--takeover` 换代后旧实例仍无条件心跳写租约、退出时
  照删租约 + purge 共享缓存 ⇒ 实测能让"还在监听的 daemon"变成"没人起过"，并清掉跨命令缓存资产。
  改成按 token 判归属（`lease_is_ours`），心跳与清理都跳过别人的租约；两宿主各跑一次两真 daemon
  交接实验确认（§X）。
- **N-r3-4（已修）**：`--takeover` 只钉了"怎么解析"，没钉"生效与否"——删掉 `|| takeover` 曾让
  152 单测 + 26 场景全绿。判定抽成 `may_replace_unanswered_lease` 并钉四格真值表；调用点绕开它
  就会因未使用项被 `-D warnings` 拦下。**边界写在 §X：这钉住判定，不端到端钉住换活 daemon 的租约。**
- **N-r3-3（已修）**：契约 ① 原先**在仓内没有任何承载体**。新增
  `stop_after_a_ready_frame_reports_minus_one`（夹具：先答 ready，再在 stop 上关连接）。
  记下一条实现期教训：**给"应答缺失"造夹具时，形状选错会从"秒级红"变成"挂 15 分钟"** ——
  stop 档读预算 900s，"永不回帧"那种形状不能用作单测前提。
- **N-r3-2 / N-r3-8 / N-r3-11（已修）**：负数不再被说成"帧里没有"；预算测试改工作线程 + 60s 有界
  等待（"不设超时"从挂住变成红）；MODULE.md 给 §W 加了 provenance。
- **N-r3-1 / N-r3-9（明确不修，只声明）**：前者要改 `daemon.provider_sessions` 的 DTO 形状
  （15 处构造点 + 词表），后者要改错误码词表 ⇒ 都是契约面，按本模块既有规矩各自走独立
  Contract-First 周期，不在末轮整改里顺手改。契约里已禁止把 `provider_sessions=0` 读成"池子为空"。
- **N-r3-7（不写成已修）**：`daemon serve` 的 `provider_sessions` 已改为取自带出的观测，
  但"它可以是真的非 0"仍无承载体：需要造一个"有序关闭后仍活着"的子进程，两宿主都造不出
  （评审也造不出）。与 **F-新3** 同源，别在下一轮又被登记成"漏做"——它是**做不出观测**，不是没做。
- **N-r3-10（含对我自己的更正）**：`core.hooksPath` 未设 ⇒ commit-msg 分类法在本地无机器承载体
  （装 hooks 归所有者）。更重要的是：**§V 的更正本身写错了**，合法 type 是 `bugfix`，不是我说的
  `bug`。已在 §X 更正，`76cb129` 起 subject 用 `bugfix` 并在提交前跑通两个 hook。
  另新增一条口径：**并行档多红不是固定现象**（本轮并行与串行同为 152+3），MODULE.md 里那句写死的
  已改掉 —— 又是"把一次观测的偶然值当常量"的老毛病。

### 本轮沉淀的通则（会复发的）

1. **"连上/没连上"这类日常语言在协议代码里几乎总是分错支**：判据要写成实现真正检查的那个量
   （这里是"有没有 `ready` 帧"），否则契约与实现各覆盖一半、合起来无共同解。B-2 与 B-3 是同一
   句话的两半，各花一轮才收敛。
2. **权限类逃生口（takeover）必须连带声明"放弃之后旧主还剩什么义务"**：不写归属，就会被放弃者
   在退出时把接手者的状态清掉 —— 这不是理论风险，是实测到的。
3. **把判定抽成私有函数 + `-D warnings` 的 dead_code** 是低成本拿到"承载体的牙齿"的办法：
   调用点绕开它，构建就红。

### 推送前自查：一笔我自己造成的 Protected 路径 marker 缺口

`f075157`（§U 台账提交）改了 `engineering/nexus-harness/MODULE.md` —— 那是 AGENTS.md §7 的
Protected 路径 —— 而提交正文**没有** `contract:` marker。内容只是把"Linux 对应值待 §U 复跑实测"
换成实测数字，契约语义没变，但按路径规则这是机械违规，记在这里而不是等评审来抓。

顺带一条机制观察（比这条违规本身更值得留）：**`pre-push` 的 marker 检查是按整个 range 判
"区间内是否存在任一 marker"**，所以它天然拦不住"某一笔缺 marker"这种缺口；要抓只能逐笔
`git show --name-only` 对正文核。这与 G4 同源：`.githooks` 未安装，本机没有机器门禁，
"我以为 hook 会拦"是不成立的。

处置：它与三笔不合规 subject 当时都在**未推送**区间，按"不重写历史"不原地改。
**2026-10-13 推送后更新**：分支已推到 `origin/feature/code-intel-phase-234`（tip `697e9a1`），
所以修正它们现在意味着**改写已发布历史 + force-push** —— 技术代价低（无 PR、无协作、hooks 未装），
但性质变了，仍归所有者决定，我没有做。已登记进 `docs/CODE-INTELLIGENCE-KNOWN-ISSUES.md` 的 G4/G4b。
