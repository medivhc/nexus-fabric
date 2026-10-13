# review-gateway-file-r10 — findings（第 10 轮独立评审）

树锚：`8a67e85`（复验树）。评审宿主：Windows 纸面复核 + **xc-pc-linux 实测**。
Linux 树：`/work/r10-verify-clone`（评审者自有克隆：`git clone /work/m0-verify` + checkout 8a67e85；
跑完 `git status` 归零；未触碰 `/work/m0-verify`、`/work/nexus-dev/target`；
`CARGO_TARGET_DIR=/work/r10-review-target`、`CARGO_INCREMENTAL=0`、rustc/cargo 1.98.1 x86_64-unknown-linux-gnu）。
不采信实现方提交说明与案卷自述作为依据；凡引用其数字处均给出评审方自己的复现方式。

## 0. 实测底账（本轮全部为评审方亲跑）

| 声明 | 评审方实测 | 结论 |
|---|---|---|
| 69 条 lib 单测全绿 | `cargo test -q -p nexus-web-gateway --lib` ⇒ `69 passed; 0 failed` | 复现 |
| clippy --all-targets 零诊断 | exit 0、无输出 | 复现 |
| 9 场景 102 期望全 PASS（auth-throttle 25） | 逐条 `nexus-harness scenario run` ⇒ 25+7+10+6+16+9+15+5+9，全 "all N expectations held" | 复现 |
| contract_hash 4f28580b… | Windows 上按 env.rs:188-216 独立复算（LF 归一，303 文件/425483 B）⇒ `4f28580bd3c9bd568e62863be1976755044d4fd2`；不归一 = 3d3dc88f… | 复现 |
| working_tree_digest 7e8c4fc7…、dirty=false | 评审克隆上 verify --fast 输出的 bindings 逐字相同 | 复现 |
| M10b ⇒ 10 红 + 10 翻转 | 见 §4 | 复现（名单逐条一致） |
| P8 ⇒ 1 红 + 1 翻转 | 见 §4 | 复现 |
| P7 ⇒ 1 红 + 1 翻转 | 见 §4 | 复现 |
| F ⇒ 编不过（G15 称同树实测，案卷称 F 未复跑） | 评审方在 8a67e85 复跑：`error: method `token_eq` is never used`，lib 与 lib test 双双失败 | 内容成立，provenance 文档互相打架（NOTE-2） |
| verify --fast 门事故（首跑 FAIL selected-properties） | 评审方同树首跑**同样 FAIL**（同一门、exit 101、测试名再次丢失），3 次复跑 PASS；直接 `cargo test -p nexus-harness` 10 次全绿（117/次） | 事故为**活的、可复现的 flake**（WARN-2） |

## 1. 三张声明的绑定纪律 —— 成立

`git diff --name-status 8a67e85` ⇒ 仅 4 个 M：案卷(+114)、FILE_MANIFEST(+7/-2)、
MODULE.md(1 行)、file_service.rs(2 行)。file_service.rs 的两处 hunk（:953-954）逐行核对
**全部在 `//` 注释内**（旧锚 ada41e4/24 条 → 8a67e85/25 条），MODULE 同一句锚定；
PRODUCT/requirements/scenarios/**examples** 字节与 8a67e85 相同。
⇒ 「脏差只有锚定句、案卷、FILE_MANIFEST」为真，**非 FAIL**。
数字侧：声明 208 = awk `^\| ` 209 减表头 ✓；#[test] 44+15+6+2+2=69 ✓；[[expect]] auth-throttle 25 ✓。

## 2. r9 六条 WARN 的闭合审计

- **W-1 空地址/前提登记**：闭（带尾巴）。`authenticate` :1671-1677 空 source 进门即拒
  （record AUTH_DENIED 审计行、不调 is_locked/token_eq/record_failure），e11 探针 :976-991
  钉「比较计数不增 + 两张源表不长 + 码 AUTH_DENIED」；P8 实测证明守卫是唯一门。
  G16 :341-350 把 source 的**四个用途**（配额/额度/源锁/归属）登记在同一条前提下；
  close_session doc :1778-1781、PRODUCT :3340-3343、REQ-010 同步。
  尾巴：处方里的「带端口两种表示」单测仍无（NOTE-4）。
- **W-2 源锁表门禁**：闭，且这次是代码追契约。`arm_source` :1014-1024 是 source_locks 全仓
  唯一 insert 点（grep :786 初始化/:860 retain/:1022 插入），:1018 `len >= max_buckets`
  满则升级全局窗口 ⇒ 「四张表各自 ≤ max_throttle_buckets」逐张复验成立
  （buckets :907、locked :961、source_failures :986、source_locks :1018）。
  观测面：单测 :3933 + 探针 :1018 都有 `<= max` 断言；期望 `unknown_source_locked_on_first_failure_when_ledger_full`
  实测钉升级分支（P7 1+1）。「源限额绝不升级为全体 fail-closed」加限定语后（MODULE :270/279-280、
  PRODUCT :3331「地址表还有位置时」、REQ-010）与代码逐字一致。
- **W-3 PRODUCT 互斥陈述**：闭。:3325-3327 改写成带括注的历史判断，:3338 过去时。
- **W-4 close_session doc 旧理由**：闭。:1760-1766 三段历史、旧口径明确标推翻。
- **W-5 射程与理由不对称**：闭（登记路线）。succeed doc :1126「只这一支」、
  close_session doc :1775-1777、G16 :351-354、PRODUCT :3339、REQ-010 一致写明
  abort_upload/remove/rename/commit_upload 同型面保留到 M2。
- **W-6 变异计数三处不一**：闭。定稿 10/10 且评审方独立复现（§4）；8/4、8/5、9/9 留痕不抹
  （G15 :297-300）。
- r9 NOTE 侧：N-1 闭（:3167-3174 轮转地址，但案卷时序错置，NOTE-1）；N-2 闭（两个新 E4 对象
  实测有效）；**N-3 只闭一半（→ WARN-1）**；N-4..N-9 闭（N-5 的「同形性只管返回值与审计行」
  与 :1769-1774 逐字对上；N-7 的 61/63/66 全部带树限定或换当前值；N-9 知识条目删「六处」计数）。

## 3. WARN-1（新）：时钟边界分支——状态口径没跟上返回值口径，注释却宣布已修

位置：`crates/nexus-web-gateway/src/file_service.rs:994-1001`、`:1005-1008`、对照 `:960-967`、`:1014-1017`。

r9 R9-N-3 的原方是「先算 until、**拿到才**删账本行；两支 None 与 pair 同口径」。本轮落了返回值半：
`arm_source` None ⇒ `return true`（:1015-1017），与 pair 的「本次仍按锁定处理」同形——这点成立。
没落状态半：:998-999
```rust
let armed = self.arm_source(skey, now);
self.source_failures.remove(&skey);
```
`remove` 无条件执行。None 时 arm_source 不落锁、不升全局、返回恒真的 `true`，随后账本行照删
⇒ 该地址终态 = 无锁 + 无账本 = 白送一份全新额度（之后每条失败都真做令牌比较，直至再攒满
max_failures_per_source）。pair 侧 None（:960 Some 才写锁）保留 :929 刚写的超限桶行，
下一条失败**当场**再按锁定处理——两侧在 None 分支**仍不同口径**。
:995-997 的注释却把重排（先算锁后删行）宣称为对「等于白送一次额度重置」的修复；重排对 None
分支的改变只有返回值。:1005-1008 的「rather than falling back to go ahead and compare tokens」
对该分支同样不成立（下一条就 fallback）。
可达性复核与 r9 一致：需 now+lockout 与 now+3600s 双双越 Instant 上界，validate :214-227 已封
24h ⇒ 实践不可达；故判 WARN 的依据是**把没做完的写成做完了**（散文诚实），不是运行时杀伤力。
复现：静态读 :998-999（remove 不在任何条件内）+ :1015-1017（None 只 return true）对照 :960。
时钟不可注入，实测触发不了（这正是 G15 未证事项自己登记的那条）。
修法：让 arm_source 回报「锁是否落地」（返回 Option<Instant> 或 bool 之外的标志），
`if landed { remove }`；或把两处注释改准并把该不对称登记进未证事项。

## 4. 变异实测（评审方在 8a67e85 亲跑）

- **M10b**（:1678 预检 `&& false`）⇒ `59 passed; 10 failed`。红名单与案卷声明**逐条一致**：
  lockout_refuses_even_the_correct_token_and_stays_bounded / lockout_rearms_after_expiry_and_flood_arms_are_not_exempt /
  lockout_requires_failures_inside_one_window / expired_locks_are_reclaimed_… / session_teardown_touches_no_throttle_state /
  throttle_fails_closed_when_the_table_is_full / per_source_budget_locks_the_address_not_the_whole_node /
  unknown_address_is_locked_when_the_source_ledger_is_full / authenticate_compares_tokens_only_when_not_short_circuited /
  source_lock_table_full_escalates_instead_of_growing_forever。
  `idle_recycle_clears_no_throttle_state` 与 `empty_transport_address_is_refused_before_the_throttle` 不红
  ——后者「守卫在预检之前、两支互不影响」的案卷说法实测为真。
  期望翻转 10 条（baseline-vs-mutant JSON 逐字段 diff）：locked_after_attempts 6→0、
  correct_token_bypasses_lockout false→true、throttle_full_fail_closed、product_engine_fails_closed_when_flooded、
  lock_survives_session_teardown、code_after_teardown THROTTLED→ACCEPTED、single_address_cannot_fill_the_table、
  throttle_per_source_budget_scoped_to_address、token_comparisons_short_circuit_when_locked、
  unknown_source_locked_on_first_failure_when_ledger_full。
- **P8**（:1671 守卫 `&& false`）⇒ 1 红（empty_transport_address…）+ 1 翻转（empty_source… true→false）。
  推导复核：去掉守卫后 authenticate("nolist","",TOKEN) 一路通到底 ⇒ ACCEPTED 且创建会话，
  合成式第一格即假；新 P8 对象**有杀伤力**。
- **P7**（:1018 门禁 `&& false`）⇒ 1 红（source_lock_table_full_escalates…）+ 1 翻转（unknown_source_locked…）。
- **F**（:1686 换成 `!=`）⇒ `error: method `token_eq` is never used`；check --all-targets（含 test profile）
  双双编不过。
- 未复跑：P1/P2/P3/P4/P5/P6/E/N5/N6/M9（案卷对其中四支已自报未复跑，诚实；P1 的 3+3 缺树限定，NOTE-3）。

## 5. WARN-2：selected-properties 门 flake 被评审方独立复现；同 bindings 覆写再次销毁取证

位置：`engineering/nexus-harness/src/evidence.rs:128-131,146-162`（目录 `verify-<id>` 按 bindings 定名、
write_json 无条件覆写）；事故记录 `.agents/green-evidence-gateway-file-service-m1.txt:995-1006`。

评审方实测：`cargo run -q -p nexus-harness -- verify --fast --json` 在 8a67e85 干净克隆上
**首跑 FAIL**（唯一失败门 selected-properties = `cargo test -p nexus-harness` exit 101），
随后 3 次复跑全 PASS；直接 `cargo test -p nexus-harness` 共 10 次全绿（117 passed/次，
含一次与 `cargo build --all-targets` 并发的负载样本，仍绿）。
两次事故（实现方 1 次 + 评审方 1 次）的共同点：都发生在**冷 target 目录、门内先现编译**的首跑；
失败测试名**都没捕获**——门的 detail 截到编译行 + `error: test failed` 为止，而评审方的 FAIL
gates.json 又被自己的 PASS 复跑按同一 bindings id `1f1eeff0a910` **原地覆写**
（目录 mtime 11:14、文件 mtime 11:16，与实现方案卷描述的机制一字不差）。
定性：实现方处置**诚实**（未声称 9 门全 PASS、事故单列、覆写自登记为 harness 缺陷），
本片结论**不需降级**——本片依赖的 constituent 门全部被评审方单独复跑为绿（§0）。
但该缺陷应从「顺带登记」升格为链上 WARN：机验封印所依赖的门在这台宿主上以约 1/4 的
首跑样本率间歇失败，且取证面**结构性丢失**，两次不同操作者各损失一次诊断。
修法（harness 侧）：verify 目录加 run-seq/时间戳或先归档再写；detail 至少保留 `failures:` 名单段。
复现命令见 §0 末行。

## 6. NOTE 汇总（各条带位置）

1. 案卷 :977 「R9-N-1……本轮之前已按轮转地址改掉」时序错置——轮转地址（10.7.x.y）是
   8a67e85 才有的（`git show 1c0f0a9:…/file_service.rs` :3124 仍是单地址 10.0.0.9；
   新注释自署 r9 R9-N-1）。改动真实、判据被救回（现在断言 `== max` 的两侧夹逼），只欠时态。
2. G15 :288-293「在同一棵树上手跑实测的三件事」含 F，案卷 :991-993 又把 F 列入「本轮未复跑」
   ——两份契约文档 provenance 互相打架；内容由评审方代跑证实（§4），补个树限定即可。
3. 案卷 P1 行「RED 3 + 3 翻转」未标树；P1 的注入面在 arm_source 落地后已经移动，引用需小心。
4. r9 W-1 处方尾巴的「带端口两种表示」测试仍缺；退化路径（auth 一处表示、close 另一处 ⇒
   合法所有者只能等 idle_timeout）现在只有散文钉，无机验对象。配方在 r9 summary
   `not_machine_verifiable_this_round` 第 4 条。
5. 两支表满升级（:961-962 与 :1018-1020）共用可覆盖的 `global_locked_until` 单槽；
   覆盖方向恒为延长（until 恒为各自 now + w，后写 now 更大），非缺陷，登记备查。

## 7. 数字与算式复点（全部可由旁边夹具参数推出）

默认参数（file_service.rs :153-165）：max_throttle_buckets=1024、lockout_after=5、
lockout_window=60 s、max_failures_per_source=40。
- 83.1% = 60/(60+1029/84.4)，分子 1029 = 1024+5 ✓（MODULE :240-244）。
- 85.33/s = 1024×5/60 ✓；68.33/s = 1025×4/60 ✓（+1 的理由 :252-253 自洽）；17.07/s = 1024/60 ✓。
- 0.67/s = 40/60 ✓；128 = 5120/40（精确）✓；26 = ⌈1029/40⌉ ✓，且 MODULE/PRODUCT 现在两个数都写。
- G12 交叉界与 validate :239-260 逐条对上（含 `< lockout_after` 拒、`> max×lockout_after` 拒）。

## 8. 判定

0 FAIL / 2 WARN / 5 NOTE ⇒ **COMMENTED，可合并**。
r9 六条 WARN：5 条真闭（其中 W-1 留一条无主测试尾巴），1 条（W-2 修复派生的 N-3 侧）半闭
新立 WARN-1。实现方本轮所有可机验声明被评审方在 Linux 同树逐项复现——这是本链十轮以来
第一次「自报数字与评审实测零分歧」。两条 WARN 都不触判定方向：WARN-1 是注释过报一处
实践不可达分支的修复完成度；WARN-2 是 harness 证据链的活缺陷，被本评审方以第二次独立
事故实证。
