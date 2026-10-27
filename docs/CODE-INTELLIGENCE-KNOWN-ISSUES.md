---
doc-id: code-intelligence-known-issues
layer: L2
owner: coordinator
last-verified: 2026-10-13
verified-against: 76cb129
status: current
---

# Code Intelligence 已知问题清单

> **这份文档是什么**：登记 Code Intelligence（`code`/`context`/`mcp`/`daemon` + LSP provider）
> 当前**已知的问题、限制与没做到的部分**。每条给根因、影响面、现有护栏、承载体，开放项还写明
> "下一步需要什么证据"。
>
> **它不是什么**：它**不是契约** —— 与 `engineering/nexus-harness/MODULE.md` 冲突时一律以 MODULE.md
> 为准；它也不是变更日志 —— 已修完的过程与逐条处置在 `.agents/code-intelligence-followups.md`，
> 实测数字与被测物身份在 `.agents/green-evidence-code-intelligence.txt` 的 §T–§X。
>
> **口径**：凡"实测"都带宿主与工具链；没有证据的地方直接写**未验证**，不写"应该没问题"。
> 引用本清单时，F 组的条目**不得**当作已通过。
>
> 本清单的引用一律用**节名 / 案卷目录 / 提交 sha**，不用 `文件:行号` —— 行号会被自己的编辑推移
> （独立评审 round 2 的 N-r2-4 就是栽在这里）。

---

## 0. 一览

| 组 | 主题 | 条数 | 现状 |
|---|---|---|---|
| A | 契约面待办（须另开 Contract-First 周期） | 6 | 全部开放，本分支刻意不动 |
| B | 平台/宿主结构性障碍（不属本模块） | 4 | 开放 3，已缓解 1 |
| C | 可观测性边界（已如实写进契约） | 6 | 开放 4，已修 2 |
| D | 记录与流程陷阱（踩过之后改成了口径） | 7 | 已入口径，非代码缺陷 |
| E | harness 自身的 fail-open | 2 | 开放（属 harness 域） |
| F | 未验证 | 6 | 开放 |
| G | 治理与评审状态（含 G4b marker 缺口、G5 的 squash 误判更正） | 8 | 开放 |

---

## A. 契约面待办（每条都要新的 Red Evidence → 冻结 → 实现，不与既有契约混改）

- **A1 结果预算的数值口径**。`MODULE.md`「Side Effects」的会话上限是**单帧 64MiB / 单会话累计 256MiB**，
  而它量的是"读线程再序列化后累计的近似线上字节"（`serde_json::to_string` 的长度），
  **不是**进程 RSS，也不是 `Value` 的堆占用（后者通常是线上字节的好几倍）。
  影响面：256MiB 不等于"最多用 256MiB 内存"；调小上限（评审建议 32–64MiB）会直接影响超大
  workspace 的可用性。现有护栏：口径已写进契约、超限即停读并如实报错（不静默截断后继续）。
  下一步：带测量的独立契约周期。**（原始待办 7，未做数值变更）**
- **A2 `read_frame` 不返回本帧消耗字节**。`dispatch_stream` 为了统计体积只能重复 `to_string`，
  既是热路径也是 A1 口径含糊的根因。改它要动签名与测试调用点。**（原始待办 8，未做）**
- **A3 崩溃/超时路径不带 stderr 尾部**。目前只有 initialize 失败会附 `stderr_tail`。
  要先定两件事：截断长度、以及它是否进 `provider` 字段（进就是契约扩展）。**（原始待办 9，未做）**
- **A4 "权威门禁宿主"只在散文里**。Linux 是唯一结论宿主、Windows 只作冒烟宿主这件事写在
  `DEVELOPMENT.md` §11.1，没有机器化声明。落进 `policies/quality.toml` 属 Protected 路径 +
  改 gate 语义，需独立周期。**（原始待办 10，仍未做，且刻意不在本分支做）**
- **A5 `daemon.provider_sessions` 的 `0` 有两种出处**：① 有 pong 会话计数或 `stopped` 帧 ⇒ 观测；
  ② 无任何出处（没连上、没答话、declined）⇒ 恒发 `0`，含义是"本次没问到"。
  影响面：把 ②读成"池子为空"就是说谎。现有护栏：`MODULE.md`「Provider Daemon & Result Cache」
  已禁止这种读法。下一步：改成"无出处即缺席"要动 DTO 形状（15 处构造点 + 字段词表）⇒ 独立周期。
  **（独立评审 round 3 的 N-r3-1；只声明，未修）**
- **A6 诊断码借用**。daemon 握手超时/沉默在 `daemon_unavailable` 里显示为
  `PROVIDER_CRASHED`（"daemon 响应不合规(PROVIDER_CRASHED): header read failed…"），
  读起来像 provider 崩了。现有护栏：文案保留真实出处。下一步：错误码词表是契约面，独立周期。
  **（round 3 的 N-r3-9，未改）**

---

## B. 平台与宿主的结构性障碍

- **B1 Windows 跑不了 `verify --fast`** ⇒ Windows 只能是冒烟宿主。根因两处都不在本模块：
  `nexus-platform-linux` 无条件依赖 `fuser`；`apps/nexus/examples/discovery_mdns.rs` 用
  Unix-only `std::os::fd`。标准解法（`cfg(target_os="linux")` 门控 / `[[example]] required-features`）
  属产品域与平台域。**（原始待办 12，未做）**
- **B2 master 自带 3 条依赖 POSIX `echo` 的 scenario 单测在 Windows 假红**
  （`scenario::tests::run_single_*` / `run_parallel_*`）。机制已更正过一次：`echo.exe` 能 spawn，
  但 harness 的管道形态读回空 stdout ⇒ `failed_step=parse`。护栏：`DEVELOPMENT.md` §11.1 披露，
  台账每次实测都把"152+3 的那 3 条"点名列出，不混进本模块的失败里。
- **B3 daemon 在跑会锁住可执行文件**（Windows）：`cargo build` / `cargo run` 直接 os error 5。
  这是**顺序约束**不是缺陷：跑构建前先 `daemon stop` 或确认无 `daemon serve` 残留。
- **B4 daemon 继承调用方可继承的 stdout 管道句柄**（Windows）：等 EOF 的管道消费会挂到 daemon
  退出为止。`Stdio::null()` 与三种写法实测都漏；修它要 Win32 handle list，被
  `#![forbid(unsafe_code)]` 与零依赖挡住 ⇒ **不修，改声明**。
  护栏与证据：契约写明消费口径（重定向到文件，或走 harness 的有界读）；§V/§X 有同一步骤
  在管道 stdio 下 240s（脚本超时）vs 文件 stdio 下 20.3s 的对照 ⇒ **给 daemon 相关命令计时
  必须以文件 stdio 为准**。

---

## C. 可观测性边界（契约已照实写，别在引用时扩大它）

- **C1 `sessions_after_stop` 只覆盖直接持有的子进程**。rust-analyzer 自己再 spawn 的后代不在
  std 能枚举的范围（要 libc）。所以 `=0` 说的是"我们那批句柄都退了"，
  **不是**"这台机器上没有 rust-analyzer 在跑"。
- **C2 "回收观测可以是真非 0"没有承载体**。该值现在是 `try_wait` 的观测（不是常量），
  但要让它红一次需要造一个"有序关闭后仍活着"的子进程，两宿主都造不出（独立评审也造不出）。
  ⇒ 这是**做不出观测**，不是没做；别在下一轮被登记成待办漏项。**（round 3 的 N-r3-7）**
- **C3 `--takeover` 的端到端路径没有门禁**。单测钉的是判定真值表
  （`only_refusal_or_takeover_may_replace_an_unanswered_lease`），端到端只有两宿主的活体实验记录。
  求值器也没有能钉它的算子。
- **C4 "字段缺席"与"字段对字段"这类性质只能活在单测**：场景求值器只有
  `equals`/`one_of`/`non_empty` 三种算子。护栏：`MODULE.md`「点名单测」名单（名字即契约）。
  **（round 1 的 N-7，按设计保留为口径备忘）**
- **C5 selftest 的 23 枚字段，名字有双重承载体、值只有一重**：
  `daemon_selftest_field_list_matches_contract` 只做键集合逐名对齐，不比对每行的值；值由场景钉。
  我曾把 `cache_default_enabled` 语义写反而 selftest 全绿，就是场景把它红的。
  下一步：把期望值抽成 `const EXPECTED: [(&str, Value); 23]` 与清单同表比对（契约面 + 测试面，另开周期）。
- **（已修，列在此处是为了标明边界）租约归属**：`--takeover` 换代后旧实例原先仍会每 2s 写回
  `lease.json`，并在退出时删租约 + purge 共享结果缓存 ⇒ 实测能让"还在监听的 daemon"变成
  "没人起过"，并把跨命令缓存清掉。现在按 token 判归属（`lease_is_ours`），心跳与清理都跳过
  别人的租约；两宿主各跑一次"两个真 daemon 交接"活体实验做**前后对照**（见 §X）。
  仍未声明干净的残留风险：被放弃的旧 daemon 若其实还活着，它仍在监听但**不可发现**，
  清理它属操作者责任（没有可移植手段区分"繁忙"与"已死"）。

---

## D. 记录与流程陷阱（踩过之后已改成口径，不是代码缺陷）

- **D1 跨宿主对账**：同一 rev 的**干净树**上，两宿主的 `working_tree_digest` **相同**，
  而 `contract_hash` **必然不同**（它按工作树字节算，Windows 是 CRLF）。脏树上两者都分叉。
  ⇒ 引用任何 Evidence 的哈希时必须带宿主；改这几个哈希函数会作废全部既有 Evidence（须另走
  Contract-First）。
- **D2 被测物必须固定到"一次跑"**：xc-pc-linux 上曾同时存在三个不同世代的 `nexus-harness`
  （仓库内 target 残留、`CARGO_TARGET_DIR` 新产物、`cargo install` 旧版），
  `cargo test` 全绿与"跑的是旧二进制"互不矛盾。现行口径：运行记录必须带被执行二进制的
  路径 + md5 + mtime，缺一项则该条结论按"未固定被测物"处理（§W 起强制执行）。
- **D3 场景 evidence_id 是确定性的、种子不含工作树指纹** ⇒ 同一 rev 上脏树复跑会**原地覆盖**
  前一条记录。Red→Green 时必须把 verdict/输出抄进 `.agents/*evidence*.txt`，别指望 `.evidence/` 留着。
- **D4 跑 E4 批次期间不许并发 `cargo build`**：场景起真实 rust-analyzer，flycheck 与构建争同一个
  target 目录锁，会把某条场景假红成 BLOCKED。
- **D5 负载宿主上 E4 可假红**：§V 里 `diagnostics-advisory` 因 `textDocument/diagnostic` 20s 超时
  得 UNKNOWN（`provider.ready=true`，是取诊断这一步超时，不是没就绪）。**冷启动/宿主预热的前置
  条件仍未登记**（写进契约就是把宿主负载写进契约，所以只做旁证）。处置原则不变：不降超时、
  不改断言，如实登记；同一 rev 在 Linux 上新鲜跑通。
- **D6 "并行比串行多红 2 条"不是固定现象**：总数 150 时实测过 `145+5`，本轮并行与串行同为
  `152+3` ⇒ 那是负载相关的间歇现象，别当常量引用（§X 已更正 MODULE.md 里写死的句子）。
- **D7 跨宿主脚本的工具链假设**：远端 `node` 是 v10.19.0，没有 `fs.rmSync` ⇒ 一整块观测没跑起来；
  另外 `pgrep -f 'nexus-harness daemon serve'` 会把承载它的 shell 自己算进去（空转时报 2）。
  口径：观测缺失要写进台账（"第一版没跑起来"），宿主工具链版本必须实测。

---

## E. harness 自身的 fail-open（与本特性无关，但会被它坑到）

- **E1 场景加载错误的门禁传播已修复（2026-10-27）**：此前 `load_all` 只打印错误并返回合法子集，
  `run_gate` 因而可能把写坏的场景遗漏为整组 PASS。现在门禁保留并汇总文件读取、TOML、版本、
  必填字段和目录读取错误，在执行场景前返回带路径的 FAIL；真正无场景时依 MODULE 返回 UNKNOWN。
  `scenario list` / `scenario run` 的目录查询兼容入口仍返回合法子集并打印诊断，未知 ID 的
  `failed_step="lookup"` 与实际断言失败的 `expect` 继续区分；没有扩展其结构化加载错误接口。
  回归与边界见 `scenario_load_tests.rs` 和知识条目 `2026-10-27-harness-scenario-load-errors.md`。
- **E2 输出里没有"跑的是哪个构建"**：`scenario run` / `status` 只报 `source_revision` 与
  `working_tree_digest`（描述仓库），不报被执行二进制的路径与 mtime ⇒ "新代码的结论"与
  "旧构建的结论"在案卷里长得一模一样（D2 的机器缺口）。

---

## F. 未验证（引用时不得当作已通过）

- **F1 第三方 MCP 客户端互操作**：只验证了自己的 `mcp serve/selftest` 与帧协议形状。
- **F2 多 language server provider / SCIP**：仓库里 C/C++/Go/TS 源文件为 0、两宿主都没有对应
  language server，所有者裁决"都不装，按现状交付" ⇒ 对本模块在其它语言上的表现**不做任何声称**。
- **F3 本区间 `verify --full` 无结论**：Linux `/work` 实测只剩 23G，而 --full 需要 ≥45G；
  上一轮从 22G 跑到 coverage 阶段掉到 8.3G 只能主动 SIGTERM（exit 143，没写出 Evidence）。
  宁可留"无 --full 结论"，不交一份会自毁的门禁。
- **F4 §W/§X 的 Linux 数字未被独立案卷复现**：round 3 的评审宿主没有 ssh 通道，已在案卷与
  MODULE.md 里标为"被审方一手实跑，独立案卷未复现"。强度按这个引用。
- **F5 纯 master 的 product 场景动态对照未做**：只有静态等价论证
  （`git diff origin/master...HEAD -- scenarios/product/` 为空 + apps 侧差异全被 cfg 门控到非 Linux 分支）。
- **F6 结果缓存的收益未实测**：验收只钉结构（命中形状、失效计数、上限），时延只作旁证。

---

## G. 治理与评审状态

- **G1 daemon/结果缓存对象的独立代码 Review 3 轮已用尽**（AGENTS.md §19.1）：
  r1 B-1（常量冒充观测）→ r2 B-2（契约只写一支而实现有两支）→ r3 B-3（分界用词"连上/没连上"，
  而实现判据是"有没有 `ready` 帧"）三条阻塞都已整改，案卷
  `.evidence/review-qoder-independent-daemon-r{1,2,3}/`。
  **⇒ 末轮整改（`76cb129`）没有第 4 轮独立复核，完成判定归评审者/所有者。**
- **G2 `nexus-test-review` 盲评 r1–r4 均判 `CHANGES_REQUESTED` 后被所有者按上限止评**
  （案卷 `.evidence/test-review-branch-feature-code-intel-phase-234-2026-10-12{,-r2,-r3,-r4}/`）
  ⇒ r4 之后的契约补记与实现没有第 5 轮独立背书。
- **G3 案卷一律记 `model=unbound`**：可用的独立执行者不暴露 `model` 参数，会话独立性成立、
  模型绑定口径**不成立**，被问到时不能说成"已按指定模型审过"。
- **G4 `.githooks` 未安装**（`core.hooksPath` 未设，装它属所有者决定）⇒ `commit-msg` 的 type
  分类法在本地没有机器承载体，提交靠手工调用 hook。本分支历史上三笔 subject 不合规
  （`0a42240 feat`、`f1575b5 fix`、`4b61987 fix`；正确值是 `feature`/`bugfix`/`bugfix`，
  注意 **`bug` 不是合法 type**——我 §V 的更正本身写错过一次，§X 再更正）。
  **状态更新（2026-10-13 推送后）**：这三笔已随 `feature/code-intel-phase-234` 推到
  `origin`，所以修正它们不再是"本地 rebase"而是**改写已发布历史 + force-push**。
  该分支目前没有 PR、没有他人协作、`.githooks` 也未安装，技术上 force-push 代价低；
  但这属"改写已发布历史"的破坏性动作 ⇒ 归所有者决定，我没有做。
  现行口径（`97ecbe5` 起执行）：消息文本先过 `pre-commit` 与 `commit-msg`，两个都 exit 0
  才 `git commit -F`。
- **G4b 保护路径的 marker 有一笔历史缺口**：`f075157`（§U 台账提交）改了
  `engineering/nexus-harness/MODULE.md`（属 AGENTS.md §7 的 Protected 路径）但正文**没有
  `contract:` marker** —— 内容只是把"Linux 对应值待 §U 复跑实测"换成实测数字，契约语义未变，
  但按路径规则这是机械违规。`pre-push` 的 marker 检查是**按整个 range** 判"有没有任一 marker"，
  所以它不会拦住这种单笔缺口；发现方式是逐笔核 `git show --name-only` 对正文 marker。
  修法与 G4 同：**这一笔也已经在 `origin` 上**（推送之后不再是本地可改范围），是否补 marker
  （改写已发布历史 + force-push）归所有者决定。
- **G5 本分支与 master 的关系（这条我先前判错过，已更正）**：我原先写"基座是**尚未合并**的
  PR #12（head `df2049c`）"，依据是 `git merge-base --is-ancestor df2049c origin/master` 返回否。
  **那是错的判断方法**：AGENTS.md §30.2 规定 coordinator 用 **squash-merge**，被压缩的分支上
  那些 commit 永远不会成为 master 的祖先，所以祖先测试对 squash 天然假阴性。
  真值来自 GitHub API：PR #12 `merged=true`，`merged_at=2026-10-11T03:24:31Z`
  （26 commits / 46 files 被压成一笔）。本分支后来又 `merge` 过 `origin/master@634771e`，
  所以 `merge-base(master, HEAD) = 634771e` ⇒ **PR 的可见 diff 只有本轮新工作**
  （实测 29 文件 +9805/−94，不含 #12 的 apps/nexus 与 env.rs/gates.rs 内容）。
  仍开放的部分只剩一件：master 在本分支合并点之后又前进了 4 笔 doc/skill 提交
  （`81b1029`/`534861a`/`edc2c5f`/`d3ae689`，与本模块代码无重叠，只有 `FILE_MANIFEST.md`
  可能小冲突）⇒ 是否先把它们同步进来再合本 PR，归所有者定。
  **口径教训记下来**：在这条流水线上判断"某个 PR 合了没有"只能看 PR 元数据，不能看 commit 祖先。

---

## 来源

- 契约：`engineering/nexus-harness/MODULE.md`「Provider Daemon & Result Cache」「命中形状」
  「点名单测」「Side Effects」「租约归属」。
- 实测台账：`.agents/green-evidence-code-intelligence.txt` §T–§X（含每轮的被测二进制 md5/mtime）。
- 逐条处置：`.agents/code-intelligence-followups.md`（Phase 2/3/4 三轮 + daemon 三轮 + F-新1..5）。
- 评审案卷：`.evidence/review-qoder-independent-daemon-r{1,2,3}/`、
  `.evidence/review-qoder-independent-p234-r{1,2,3}/`、
  `.evidence/test-review-branch-feature-code-intel-phase-234-2026-10-12{,-r2,-r3,-r4}/`（均被 gitignore）。
- Linux 原始日志：`xc-pc-linux:/work/xc-v-linux.log`（§W）与 `:/work/xc-x-linux.log`（§X）。

**下次必须重核本清单的触发条件**：改动 `daemon.rs`/`cache.rs`/`lsp.rs` 的回收或选路逻辑；
改动 `contract_hash`/`working_tree_digest` 口径；换门禁宿主；`policies/quality.toml` 落 A4；
或任何一条 A/C/E 组被独立周期实现之后。
