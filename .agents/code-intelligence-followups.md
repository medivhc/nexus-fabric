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
  故三轮案卷均记 `model=unknown`；会话独立性成立（非实现会话）。
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
