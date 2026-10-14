# r14 独立评审（第二次派单）·逐条取证

## 0. 宿主、工具链、出处（硬要求）

- 实际模型标识（运行时给什么写什么）：**qfmodel**。
- Windows 侧：Git Bash，git 2.46.0.windows.1，node v24.14.1。**没有在 Windows 编译本 crate**（ssh2 cfg 门，仓库知识在册），Windows 侧零编译证据。
- Linux 侧：`ssh appen@10.144.144.4`（真机 xc-pc-linux，非 WSL），rustc/cargo 1.98.1，git 2.25.1，host python3。**WSL 全程未用作任何门禁结论来源。**
- 我怎么执行 cargo：`cd /work/r14-audit && CARGO_TARGET_DIR=/work/r14-target PATH=/work/nexus-dev/.cargo/bin:$PATH cargo test -p nexus-web-gateway --lib` 及探针 `cargo run -q -p nexus-web-gateway --example gateway_file_contract -- --case config --json`（取输出最后一行 JSON）。
- **这不是我自己从零建的树**：`/work/r14-audit`（HEAD `66edcc4`，工作树进树时 clean）与 `/work/r14-target` 编译产物是 r14 第一次派单（中断者）留下的，我直接复用。中断者留下的唯一文件 `summary.provisional-attempt1-interrupted.json` 三条 finding 全 pending、引用的 review.md/findings.json 不存在——**我一个字没引用它作为证据**。
- 树号对齐：变异表口径 = `0dbc1d2`，我的树 = `66edcc4`。`git diff --stat 0dbc1d2..66edcc4 -- crates scenarios` 只动 `requirements.toml`（+文档），**config.rs / file_service.rs / 探针代码零改动**；且 18 条配方锚点在该树上 `count==1` 全部预检通过（锚点存在即代码逐字节相等的强证）。⇒ 复跑与该表可比。
- 被评对象：`294c4d3`、`0dbc1d2`、`66edcc4`；`m0-verify` = `8b6b0d0`（实测 `git rev-parse m0-verify`）。

## Q1 两种红法不等价——作者说对了（实测）

① 两格确无自翻对象。代码证：`crates/nexus-web-gateway/examples/gateway_file_contract.rs:1565-1570`——`absent_disabled` 与 `disabled_no_engine` 的取值都在两处 `map_err(...)?`（legacy 解析、`file_engine()`）之后、`f.insert` 之前；任一早退 ⇒ 两格连插入都没发生。`dispatch()` 第 122/125 行：`gateway_config(&mut fields)?` 出错则 `verdict=PASS` 永不写入；main 第 92-101 行错误分支输出 `verdict:"FAIL"` 且 **`case` 字段照写**（来自 argv）⇒ `case` 在任何杀伤下都不翻。

实测（我在 /work/r14-audit 复跑，非引用 mm10.log）：
- **MC06**（`config.rs:494` `if !self.files.enabled {` → `&& false`）：`cargo test --lib` 红 1 = `config::tests::absent_files_section_is_disabled`；探针 config `flips=1（仅 verdict PASS→FAIL）missing=21`；auth-throttle 0 翻。
- **MC11**（去掉 `files` 字段的 `#[serde(default)]`）：同形状——红 1（同名单测）、探针 flips=1(verdict)、missing=21。
- 回写后 `git status` = 0，baseline/MC99 均 84 passed、23 条 0 翻 0 缺席。
⇒ **那两格确实"来不及翻"**，不是作者猜的；只有整体 FAIL 这一种红法，成立。

② 整体 FAIL 够不够支撑现时态句？我判**够（以现在这个措辞）**：
- MODULE.md G12（`crates/nexus-web-gateway/MODULE.md:99-105`）与 PRODUCT.md §18.4（`PRODUCT.md:3384-3391`）两句都已写成**带边界**："file_engine() 是从配置起引擎的唯一入口"后紧跟"只约束从配置构造这条路：FileEngine::new 本身仍是 pub"；"拒启动成立在构造缝上，Gateway::start 还没消费"。
- "关断时结构性没有引擎"在 **单测层有指名杀伤**（MC06 红 `absent_files_section_is_disabled`——该测试直接断言 `file_engine()` 返回 `None`），场景层只有整体 FAIL 并不使该句无承载。
- 两处文档都明写"不写成全覆盖"并把"两格只有整体 FAIL"记入措辞（MODULE.md:133-136）。
⇒ 不构成 WARN/FAIL。探针"早退改记录 false 再续"的处方**我同意且已在案卷中被登记为下一轮必答**（`.agents/green-evidence-gateway-file-service-m1.txt` 覆盖率节尾"要不要把探针这两处的早退改成…是下一轮的必答问题"），本轮不需要我再抢答。

## Q2 覆盖率与变异表可复算性

① 我自己的解析（node，逐行吃 `FLIP` 行，非实现者脚本产物之外的口径；期望名单来自我直接数的 `scenarios/product/gateway_file_config.toml` 23 条 `field =`）：
- 被至少一条配方以"翻自己那一格"打过 = **20 个名字 = 19 条实质期望 + verdict**；从未翻的 3 个 = `case`、`absent_section_is_disabled`、`disabled_yields_no_engine`。
- **作者写的 19 对。** 分法自洽：verdict 的翻转只发生在早退形状（MC05/06/11/12 全部 flips=1 且 missing=21），它是"整体响"不是"指名杀伤"，从 19 里单列出去是诚实的；`case` 是 argv 回显（见上代码证），排除正确。

② 复跑 4 条 + 新配方 1 条（全部我自己在 66edcc4 树上跑）：
| 配方 | 我的实测 | 案卷表（口径 0dbc1d2）| 对上？ |
|---|---|---|---|
| MC07 删缝里 `self.validate()?` | 2 红 + 3 翻（invalid_table/blank_token/blank_alias_yields_no_engine）| 同 | ✓ |
| MC18 打开根失败静默丢根 | 1 红 + 1 翻 `missing_root_path_rejected` | 计数行 "1 1/0"（无名，见 W-2）| ✓ |
| MC06 | 1 红 + verdict 翻 + 21 缺席 | 同 | ✓ |
| MC11 | 1 红 + verdict 翻 + 21 缺席 | 同 | ✓ |
| **NEW20（我设计）** config.rs:252 `idle_timeout_secs > MAX_FILE_WINDOW_SECS` 加 `&& false` | **84 全绿、探针 0 翻 0 缺席** | 表内无此配方 | 新发现，见 W-1 |

NEW20 选点理由：案卷表 18 条只钉了 lockout 的 24h 上界（MC02 配置层、MC13 引擎层），`over_24h_window_is_rejected_in_both_layers` 单测只把 `lockout_window_secs` 拨过界——**配置层 idle 上界是这张表打不到的宣称**（MODULE.md:160-163"两个时长…不得越过 24h…两层各写一次"）。它**不翻**：删掉后行为仍被引擎层委托（`file_service.rs:222`）挡住，只换错误标签，且全仓没有任何单测/期望以名字钉它 ⇒ 该句挂在 MODULE.md:139"（除注明外逐条都有单测把它跑红，且夹具只违反自己那一条）"的射程内却没有红——报 W-1。
（透明记录：NEW20 第一次跑因我本地 bash 转义把 `&&` 写成 `\&\&`，编译错误作废；修后重跑才是上表数据。）

③ 三句现时态核（只读码，不跑）：
- `FileEngine::new` 仍 pub：`file_service.rs:1409` `pub fn new(`，且探针作为 example（crate 外）直接调用并编译通过 ⇒ `lib.rs` 公开 `file_service` 的边界句**真**。
- "Gateway::start 仍不消费 file_engine()"：全仓 `file_engine()` 调用点 = config.rs 单测（565/668/679/703/732/743）+ 探针，gateway/start 侧 0 处 ⇒ 文档"还没消费"句**真**，无"现时态宣称而承载体不存在"。
- "19 条的可复算来源在案卷里是否真的存在"：**只能算半存在**，报 W-2（下面给出处方）。

## W-1（WARN）配置层 idle 24h 上界零可红对象
- 位置：`crates/nexus-web-gateway/src/config.rs:252`；措辞出处：`crates/nexus-web-gateway/MODULE.md:139`（"除注明外逐条都有单测把它跑红"）与 160-163（"两层各写一次"对 idle 那半没有红可指）。
- 复现：在 `/work/r14-audit` 给该行条件追加 ` && false`，跑 `cargo test -p nexus-web-gateway --lib`（84 passed, 0 failed）+ 探针 `--case config --json`（flips=0, missing=0）。
- 处方（给下一轮任选其一）：给 `over_24h_window_is_rejected_in_both_layers` 或新单测补一段"把 `files.idle_timeout_secs = MAX_FILE_WINDOW_SECS + 1`、断言错误串含 `files.idle_timeout_secs`"；或在 MODULE.md:160-163 那句给 idle 上界加"注明"（它靠委托兜底、无独立红）。

## W-2（WARN）"翻转名单记在案卷《第十二片再续》"两处对不上
- 位置：`crates/nexus-web-gateway/MODULE.md:133`；案卷实际节名 `crates/../.agents/green-evidence-gateway-file-service-m1.txt:1602`（"第十二片续"）、`:1693`（覆盖率节）。`git grep -l 再续` 全仓只命中 MODULE.md ⇒ **被引用的案卷标题不存在**。
- 名单展开度：带名字的翻转明细块止于 MC14；**MC15–MC18 四行只有"红数 翻转/缺席"计数（1720-1723），无名**。原始 FLIP 名在 `/work/mm10.log`（实现者 Linux 机路径，`.agents:1699` 自己也承认脚本在 `/work/mm10.py`——均未入库）。
- 后果：第三方只靠案卷**不能**重算出 19——他能看到"23 条、未翻 3 个名字"的减法，但减法前提本身要靠未入库的 log 验证（我入库外复算成立是因为我能 ssh 到那台机吃他的 log + 自己复跑 5 条）。
- 处方：①把 MODULE.md:133 的引用改成实际节名（或给覆盖率节加锚题《第十二片再续》）；②把 MC15–18 四行补上翻转字段名；③把 mm10.py 与本表口径的 mm10.log（或其内容哈希）落到 `.agents/` 或 `.evidence/`，否则"可达提交"闭环只到配方、不到数据。

## NOTE
- N-1：Q1 判定"作者说对"；两格确无自翻对象（MC06/MC11 均实测）；两句现时态描述因带边界 + 单测层指名红而成立；不写"全覆盖"是对的；探针改造已挂下一轮，本轮无需加码。
- N-2：出处坦白——复用中断者的树与 target；我自己烧掉过一次无效 NEW20 跑（转义 bug）；结束后 audit 树 `git status` = 0。
- N-3：r13 四条 WARN 闭环复核：W-1 已闭（MC07 复跑 3 翻含两条新对象）；W-2 已闭（边界句与 `FileEngine::new` pub 实测一致）；W-3 已闭（表与本人都只用逐字段 diff，不用退码）；W-4 已闭（口径换成可达提交 0dbc1d2，我在 66edcc4 复跑 4 条全对上，锚点预检证代码等同）。

## 未跑成 / 不构成证据
- MC01–MC05、MC08–MC10、MC12–MC17 共 13 条我未复跑（预算内只复跑 4+1），它们的红数/翻转我采信的是"案卷明细 × 我自己的 mm10.log 解析"两路一致，非全亲手。
- 场景 harness（E4 逐条对账）、workspace 级其它门：未跑，不外推。
- 中断者（attempt-1）的三条 pending finding：未用作任何结论。

verdict：**COMMENTED**（0 FAIL / 2 WARN / 3 NOTE）。
