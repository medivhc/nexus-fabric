# 独立评审案卷 —— 网关文件服务，第 8 轮（r8）

**被评审对象**：`crates/nexus-web-gateway` 认证节流器第九片的一次**语义翻转**
（`Throttle::forget` → `forget_failures`，只清失败计数、不再清已武装的锁）、随之新增的 2 条单测 /
1 个引擎访问器 / 5 条冻结期望，以及 MODULE G15、PRODUCT §18.2、requirements.toml REQ-010 三处
散文的同步；外加实现方对 r7 撰写者 R7-N-10 的公开否决、对 R7-W-4 的公开更正，以及它自报的
第 8 条（自己把 r7 §3.2 的不变式改假）。

**宿主 / 工具链（本评审）**：Windows 11 x64 + Git Bash，**纯静态阅读**。
`nexus-web-gateway` 依赖 ssh2 0.9.6（`userauth_pubkey_memory` 受
`cfg(any(unix, vendored-openssl, openssl-on-win32))` 门控）且本机无 cl.exe/nasm ⇒ **未跑任何**
单测 / clippy / harness / 场景。实现方在 xc-pc-linux 报的 63 passed / clippy 零诊断 /
95 条期望全 PASS / `verify --fast` 9 门 = `verify-0ffee5f17190` 一律**未复现**，也不当替代证明。
r7 那台仓外 std-only 复算台本轮**没用**：它建模的是 `forget` 两行都删的旧语义，对第九片已失配。
本轮判据 = 读码 + 按夹具算数 + grep/awk/git 实测。标记：`[读]``[算]``[核]`。

**Verdict：COMMENTED —— 0 FAIL / 3 WARN / 7 NOTE，可合并。**
翻转方向严格更安全且没有换来判定缺陷；三条 WARN 全是散文与可红对象：G15 新写的两条算式
复算不出它旁边的数值（R8-W-1）、翻转只关了一半的洞（R8-W-2）、窄路径论证给错了界且锁表上界
零观测面（R8-W-3）。**我自己判错的也留痕**：§2(2) 我起初把 R8-N-1 写成『翻转理由不成立』，
重推第 4 轮才确认它在共享传输地址的前提下成立——所以最后落的是措辞精度问题而不是 FAIL，
推理过程写在 §2(2) 与 §2(4)。

---

## 0. 绑定与取证（全部 `[核]`）

- 分支 `feature/gateway-file-service-contracts`，HEAD `175e115`（= 本轮 `source_revision`；
  r7 填的 `af953af` 落后两提交，即 R7-AUDIT-5，本轮起改绑真实基线）。工作树 10 M + 1 ??。
- **`git diff 3e8600b -- crates/nexus-web-gateway/src …/examples MODULE.md requirements.toml
  scenarios PRODUCT.md` 为空**，全树差异只剩 `.agents/green-evidence…txt`（+8/-5）
  ⇒ 实现方那句『之后的落地只在 .agents/、FILE_MANIFEST.md、.agents/knowledge/**』**成立**。
  本链此前反复抓『自报数字与树不自洽』，这一项本批**没抓到**。
- 三棵树 `4d6223a` → `6bf7691` → `3e8600b` 逐行 diff：第一跳到第二跳是 G15 + `record_failure`
  注释改口径 + 两条正面断言，第二跳到第三跳只有 MODULE:179 一行与 file_service:866 两行
  （零红数字改成实测口径）⇒ 两句自述**为真**；三棵树的 `scenarios/` 字节相同 ⇒
  『contract_hash 一直是 750cbe0b…』**成立**。
- **关键取证**（`[核]`）：`4d6223a` 的 G15 与注释里还写着『那支经 `authenticate` 不可达
  （不变式 `locked.len() ≤ buckets.len() ≤ max_buckets` 且行与锁同生同死）』，而**同一棵树已经
  落地了只删行不删锁的 `forget_failures`** ⇒ 这条『证明』在它自己跑绿全部门禁的树上就已失效，
  由本批第三棵树改掉。实现方在第九片第 8 条公开登记了这件事，与 diff 逐行吻合。这条自抓是
  本链第一次，我不重复计为待办。
- `contract_hash` **本评审独立复现** = `750cbe0b70dc7fb9e6f7b97a09aa902dee48acef`：按
  `env.rs:187-216`（子目录名排序 / 文件名排序 / `scenarios/{d}/{n}\n` + 原文 / `\n===\n` 连接 /
  `git hash-object --stdin` 的 blob sha1）。**行尾归一方式声明**：Windows 脏树先做
  `\r\n → \n` ⇒ 422343 字节 ⇒ 复现一致；**不归一** ⇒ 436124 字节 ⇒ `ad717763…`，
  再次确认本批新增的那条 CRLF 知识条目。

---

## 1. 问题 A —— 语义翻转有没有换来新问题

### A(1) 还有没有路径能清掉一个已武装的锁 `[读]+[核]`

**没有，只有 `decay`。** `grep -n locked src/file_service.rs` 全仓四处：`:784`（`decay` 的
`retain(|_, until| *until > now)`）、`:807`（`is_locked` 读）、`:873`（上界判断）、`:876`（写）。
`succeed:884` 与 `forget_failures:958` 都只做 `buckets.remove`。`succeed` 会不会**间接**清？
不会：它唯一的调用点是 `authenticate:1465`，而 `:1438` 的 `is_locked` 预检在令牌比较**之前**
短路 ⇒ 锁定中根本走不到 `succeed` `[读]`。`forget_failures` 不碰 `global_locked_until` ⇒
表满/溢出那条 fail-closed 大路第三方与自伤都拆不掉 `[读]`。
`Throttle::default()`（`lockout=0`）仍按 r4 R4-N-5 携带，`FileEngine::new` 先 `validate()`
（`:181` 拒零窗口），所以它只在单测里可达 `[读]`，本批未触碰。

### A(2) 契约里有没有哪句还承诺『拆会话即清状态』 `[读]+[核]`

三处逐一核过，**全部同步，无残留**：
- MODULE G15:197-202『显式 `close_session` 只清该 (主体,源) 的**失败计数**，**不清**已武装的
  锁定——窗口必须服完』+ 闲置回收什么都不清 + 点名了两条钉住它的单测 `[核]`
- PRODUCT §18.2:3321-3323『**拆会话不是解锁路径**』同口径 `[核]`
- requirements.toml:89 REQ-010『显式 close_session 只清该对的失败计数、已武装的锁必须服完，
  闲置回收什么都不清』——r7 R7-W-5/R7-AUDIT-2 点名的『随会话回收清零』那句歧义**已消失**，
  且『会话+源』改成了『主体+源』`[核]`
- G15:166『锁定窗口内正确口令也不得绕过』：r7 判『真但不全面（close_session 能抹掉窗口）』，
  **本批之后这句的后半注记可以撤销** `[读]`
- G16:252『三处释放缺一不可…会话拆除（close/闲置回收…）』——查过，它讲的是 **budget** 释放，
  `:1524` 与 `:1556` 两边都调 `release_session` ⇒ 与新节流语义**不打架** `[读]`；G21 只谈
  `idle_timeout` 与审计出口，无节流承诺 `[读]`。
- `close_session` 的 doc（`:1512-1515`）仍说『`source` 不是参数是有意的…peer 无法抹掉
  somebody else 的 lockout』——字面仍真（它现在连自己的都抹不掉），但理由的承重已经变了，
  登记在 R8-N-7 的正面确认里，不单列。

### A(3) 两个上界各自怎么成立 + 『窄路径可达』论证是否严密 `[算]+[读]`

**两个上界各自成立**，我分别重推：
- `buckets.len() ≤ max_buckets`：仍由 `:824` 的写入门禁（新行只在 `len < max` 或键已在册时产生）
  ⇒ 物理行 ≤ 1024，与回收无关。**成立，未受本批影响** `[算]`。
- `locked.len() ≤ max_buckets`：由 `:873` 那句 `if self.locked.len() >= self.max_buckets`
  自己——只有它不成立才 `insert` ⇒ 锁表不可能越过 max。**成立** `[算]`。注释把这两句写成
  『两个上界各自独立成立（别把它们当同一个）』是**本轮该做对的区分**，做对了。
- `locked.len() ≤ buckets.len()`（r7 §3.2）**确实失效**：见证就是新单测自己——
  `:3346` 断言 `throttle_failures()==0` 而 `:3351` 断言 `throttle_locked()==true` 同时成立，
  即『带活锁而无行』`[读]`。实现方在注释、G15、案卷三处都改了这个口径，没有留下第二处
  现在为假的『证明』`[核]`。

**『窄路径可达』的两条腿，一条稳、一条错：**
1. 无令牌者到不了——**结论对，证明少一句**。要走到 `:873` 必须『某行的第 `lockout_after` 条
   失败』且『锁表已满』。行满时新键一律在 `:824` 被截走 ⇒ 只有**在册行**能走到 `:847`；
   在册行若要提供 1024 条活锁，就必须 1024 行**全部带活锁**，此后任何新键都撞 `:824`。
   这中间依赖一条未写出的前提：**行与锁的死亡条件逐字等价**（`:784` 用 `until > now`、
   `:786`+`:693` 用 `now - last >= window`、`:803` 同 `:784`；锁定期 `:1438` 短路 ⇒ 行不再刷新），
   所以孤锁**只**来自 `forget_failures`。补上这句，『让行消失只能靠 close_session』才是证明
   而不是断言 `[算]`。
2. 有令牌者的上界是 `max_sessions`——**不成立**：`close_session:1517` 会 `remove` 会话、
   `next_session` 单调自增（`:1255`，从 1 起）⇒ 同一段会话额度可以**顺序**复用去拆 N 个不同
   身份的对，孤锁个数不受并发会话数约束。真正的界是『一个 `lockout_window` 内造得出多少条
   活锁』= 需要 `max_buckets × (1 + lockout_after)` 次认证落在同一窗口内；默认参数
   `1024×6/60 s = 102.4 次/秒`，**高于**同一份 G15 代价 (3) 自己算的 85.33 次/秒聚合上界
   ⇒ 默认参数下那支经 `authenticate` 其实**仍然到不了**。也就是说：本批从『结构不可达』
   降级成『窄路径可达』，方向上是**保守过头**（更安全），但它给的**理由是错的**，
   而且读者会误以为 `max_throttle_buckets` 很小的配置下天花板还是 `max_sessions`
   （小表夹具里 8×6=48 次认证就够）`[算]`。
3. 本批之后 :873 那句成了**锁表唯一的内存防线**，而它**零可红对象**：没有任何读侧能观测
   锁表大小（访问器只有 `throttle_buckets/failure_count/global/globally_locked` 和新增的
   `throttle_locked(principal, source)`，没有 `locked.len()`），实现方自报的 E（关掉那支 ⇒
   63 单测全绿、18 条期望字段无一翻转）我按夹具逐条重推**为真**（没有任何断言触及锁表上界
   语义；`expired_locks` 断言的是 `!globally_locked`，去掉那支同样成立）⇒ G15 标题那句
   『计数与表项**有界**』对锁表这一半没有机器对象；E 之下 `locked` 可长到约
   `85.33/s × 60 s = 5120` 行（≈250 KB 量级，粗估不是实测）`[算]`。⇒ R8-W-3。

### A(4) 改名之后的调用点 `[核]`

`grep -rn forget`（src + examples + MODULE）：唯一**调用点** = `file_service.rs:1528`。
审计路径（`:1529` 成功行 / `:1535` 未知会话 NOT_FOUND 行）、预算释放（`:1524` close、
`:1556` sweep_idle）、`sweep_idle:1554-1559` 都不经过节流器 ⇒ **无漏改**。
`examples` 里剩下的 `after_forget` 只是局部变量名。全仓其余 `forget` 命中都是 `std::mem::forget`
（其它 crate）。`:565` 的探针注释已改成『Session teardown clears the **bucket**』，口径对 `[核]`。

---

## 2. 问题 B —— 杀伤力独立复算（未抄实现方的红/绿）

夹具与红点都给到 `文件:行`。逐条按代码重推，**结论：红/绿全部与实现方一致；
两处它说错或说少**（N2 的红点数、N6 的机制与预测数字）。

| 变异 | 我重推的红 | 与实现方是否一致 |
|---|---|---|
| N1 close 也删锁 | RED `session_teardown_…`：先 `:3351`（`throttle_locked` 变 false）再 `:3359`（ACCEPTED）；`:3346` 在 N1 下**仍真**（删行那半还在）。探针 `lock_survives_session_teardown=false`、`code_after_teardown=ACCEPTED`、`throttle_pair_concatenation_is_separate=false`（合成式第三项 `examples:728`） | 一致 ✓（它的『因为合成式里有确实锁过那一项』我核为真） |
| N2 `forget_failures` 掏空 | RED 同一条测试，但**第一个红点是 `:3322`**（(a) 段第二条失败把桶推到 `lockout_after=2` ⇒ THROTTLED ≠ AUTH_DENIED），`:3346` 随后也红（failures 残留 2）。探针三字段不变 ✓（e7 的 (a) 段没有『关会话后再失败』那一跳） | **它说少了**：不是只靠 `throttle_failures()==0` 那半 |
| N3 `sweep_idle` 也清 | RED `idle_recycle_…:3397`（只推进到 count=1 ⇒ AUTH_DENIED） | 一致 ✓ |
| N4 丢两段长度前缀 | RED 单测 `:3221-3224`（`is_locked("a","bc")` 变 true）+ `throttle_pair_concatenation_is_separate=false`（`:727` concat_other=THROTTLED）；其余 5 条节流测试与另外 17 条期望不变（`("ab","bc")` 那对不写前缀也不撞，`:3225-3227` 的自评仍然诚实） | 一致 ✓ |
| N5 摘要丢 source | RED 单测 `:2882` + `other_source_still_admitted=false`；`e5` 两条合成式与 `victim_code_after_forged_prefix` 不变（两条 principal 本就不同）；`throttle_full_fail_closed` 不变 | 一致 ✓（这条柱子确实是本批新补的，R7-N-5 闭合） |
| N6 桶不衰减 | RED **3 条**单测：`lockout_rearms…`（`:3041` 附近 6 条断言）、`lockout_requires_failures_inside_one_window`（第 3 轮第一条撞阈值）、**以及 `expired_locks_are_reclaimed…`（`:3270`+`:3282`）**；契约 `throttle_sustainable_failure_budget=false`（20/28）+ `throttle_flood_self_heals_after_quiet_window=false`（`healed` 项：新失败走溢出 ⇒ `buckets()==0≠1`）；`throttle_entries_bounded` 与 `flood_armed_before_quiet_window` 不变 | 一致 ✓（3 条对；这第三条正是 r7 实测补上而第八片案卷漏记的那一条） |
| E 关掉锁表满升级那支 | 63 单测全绿 + 18 条期望字段无一翻转 ✓ —— 但代价是锁表内存上界失去唯一防线且没有任何对象能红 | 数字一致，**后果它没写**（R8-W-3 第 3 点） |
| F `constant_time_eq` → `!=` | 63 全绿 ✓，且函数语义等价 ⇒ 『无断言约束 authenticate 真用常数时间比较』在当前树仍成立；`:4467` 那条测试只测函数本身不测调用点 | 一致 ✓ 且已登记在未清偿清单 |

**N6 的 20/28 我自己推了一遍**（`[算]`，夹具 `rows=8`、`lockout_after=3`、窗口 100 ms、
每轮全程新身份、轮间睡 150 ms）：round 0 建满 8 行 ⇒ 16 条 AUTH_DENIED；round 1 起新身份
**拿不到行**（`:824` 表满且键不在册）⇒ 走溢出：`global=1`、`global=2` 两条仍 AUTH_DENIED，
第 3 条 `global >= 3` 武装 ⇒ 该轮余下 14 条 THROTTLED；**全局计数自己的衰减在 N6 下没坏** ⇒
每个静置窗口后 `global` 归零，下一轮再白送 2 条 ⇒ `denied = 16+2+2 = 20`、`throttled = 28`
（总数守恒 48）。⇒ 实现方自报的 **20/28 复现成功**，r7 §2.1 推的『约 16』错了 4，错因是没算
那 2×2 次白送。**但实现方自己给出的机制是错的**：`examples:735-736` 写『计数粘住 ⇒ 从第 2 轮起
每行的第一条就把桶推到阈值 ⇒ AUTH_DENIED 掉到约 16』——身份每轮都换，没有『每行』可粘；
武装来自**溢出计数**而不是单行阈值；而它抄的『约 16』与案卷第九片自报的 20 不同源。
场景注释 `gateway_file_auth_throttle.toml:104-108` 同型（『计数粘住』）。⇒ R8-N-2。

---

## 3. 问题 C —— 数字自洽（全部 `[核]`，方法披露）

| 声称 | 我实测 | 结论 |
|---|---|---|
| 95 条期望 / auth-throttle 18 | `grep -c -F '[[expect]]'` 逐文件 = 18/7/10/6/16/9/15/5/9 = **95** | ✓ |
| 63 单测 | `#[test]` = file_service 38 + config 15 + protocol 6 + cert 2 + gateway 2 = **63**（`tests/gateway_e2e.rs` 另有 21，不属 `--lib`，口径正确） | ✓ |
| FILE_MANIFEST 204 | 头部声明 204；`awk '/^\| /{n++}'` = **205** 减表头 1 = 204；:43 的注释链自己写了这条配方 | ✓ |
| 第八片说 61/90、第九片说 63/95 | 在 `1ab58b1` 上 `git show` 逐文件求和 = **61** 单测 / **90** 期望（auth-throttle 13）；在 `3e8600b` 与工作树上 = **63** / **95** | **两组各自与自己描述的树自洽**，不是矛盾 ✓；本批公开更正（90→95、61→63）如实 |
| 三棵树场景字节相同 ⇒ contract_hash 一直是 750cbe0b | `git diff <tree> -- scenarios` 对三棵树**全空**；我 LF 归一后自行复算 = `750cbe0b…` | ✓ |
| `git diff 3e8600b -- src/ examples/ scenarios/ MODULE PRODUCT requirements` 为空 | 逐路径跑，**空**（只有 CRLF warning） | ✓ 那句自报成立 |
| 未冻结观测字段 | 探针 emit 28 个、场景引用 18 个 ⇒ 12 个未冻结（r7 时 9 个，新增 `concat_other_code`、`pool_denials_observed`、`pool_lockouts_observed`）；`state_cleared_after_close` 仍未冻结 | R3-N-4 欠账 +3，但三个新字段都已被各自的合成式冻结 ⇒ 口径债不是缺陷（R8-N-5） |
| 案卷里残留的旧数字 | `file_service.rs:840` 仍写 61 条单测（当前树 63）；`:3291` 与场景注释引『61 单测 + 90 期望』未加『当时的』限定（`:954` 加了） | R8-N-4 |

---

## 4. 问题 D —— 时间夹具（e8：8 行 × 每行 `lockout_after-1` 条 × 3 轮、静置 150 ms、窗口 100 ms）

**(1) 假红还是假绿？——只有假绿，没有假红。** 三条独立理由 `[读]+[算]`：
(a) 24 个身份互不相同、每个恰 2 条失败，个体阈值 3 **按定义到不了**，机器多慢都不影响；
(b) `thread::sleep` 只有**下界**语义（150 ms 只会超调不会欠调）⇒ 静置侧的 1.5× 余量不是
概率而是保证；(c) 运行越慢 ⇒ `decay` 越早丢掉旧行 ⇒ 表越不可能满 ⇒ 越不可能走溢出武装。
⇒ 现实现在这条期望上**恒绿**，它不会因慢 CI 变红。
风险在另一侧：N6 要红，需要 3 条注入落在同一个 100 ms 窗口内（即每条 <33 ms）；按本仓知识条目
记的 llvm-cov 放大约 20×（µs 级 ⇒ 几十 µs）远够不到，但**真够不到的东西不该被写成『余量薄』**。
⇒ 若真发生病态停顿（每条约 >33 ms），红的是**杀伤力**（变异逃逸），而这条期望是 R7-W-1 唯一的
可红对象 ⇒ 逃逸是静默的。哪一侧掩盖哪一侧：**假绿不会被任何假红掩盖，因为它根本不红**；
反过来 `e6` 的 `flood_armed_before_quiet_window` 才是真正的假红侧（现实现要在 100 ms 内注满
6 条才武装），而它被**单独冻结**正是为了区分『从未武装』与『武装过又自愈』（r7 R7-N-4 已核，
本批也按那条改了口径 ✓）。

**(2) 登记够不够？——登记到位，方向判反，判 NOTE 不判 WARN。**
`.agents/knowledge/entries/2026-09-30-coverage-run-flaky-timing-test.md` 的『新实例』段确实列了
三处（`lockout_rearms` 300 ms / `lockout_requires` 200 ms / e6+e8 探针），并写进 G15 未证事项
（MODULE:229-233）⇒ R7-N-11 的登记诉求**闭合** ✓。但它最后那句『llvm-cov 约放大 20×，届时
1.5× 余量的那处最可能先**假红**』对 e8 是**方向错**的（见 (1)）。判 NOTE 的理由：这条判错
不改变任何行为、不改契约承诺，且改法就是一句话；不判 WARN 的理由：登记面已完整、
读者据它做决定的场景是『别把本机跑绿当证据』，那句在两个方向上都成立。

**(3) 有没有等价杀伤力的非墙钟配方？——有，但只有注入时钟那一条干净。**
配方 A（推荐，需改 API）：把 `now` 做成参数（`record_failure(principal, source, now)`、
`decay(now)` 已有、读侧四访问器与 `is_locked` 同样加 `now`），夹具变成**纯计数**：
t=0 灌 `rows × (lockout_after-1)` 条 ⇒ 断言 recorded == 该值且未武装；虚拟推进 1.5 个窗口，
重复 3 轮 ⇒ 现实现 48/0，N6 下同一份虚拟推进**确定性**给出 20/28 ⇒ 红。零睡眠、零抖动，
且把 R7-N-11 与本项一次结掉（`sweep_idle(now)` 已经是这个形态，成本只在 `Throttle` 六个
`Instant::now()`）。
配方 B（不碰 API）：把窗口缩到比一轮注入的自然工作量还短（例如 10 µs），让『跨过窗口』
由代码本身完成——原理上可行且能省掉 sleep，但它用一个更短、没量过的窗口换掉一个更长、
可标注的窗口，可复核性更差，**不推荐**。
配方 C（纯计数、杀伤力不等价）：不测额度池而只测『行满 ⇒ 溢出武装』与『溢出计数按窗口归零』
这两条已在 `throttle_fails_closed_when_the_table_is_full` 与 `lockout_rearms…` 里有的东西——
它杀不了 N6 的额度侧，所以不构成等价。

---

## 5. 问题 E —— G15 新登记的算术逐条复算 `[算]+[核]`

| 契约句 | 我的复算 | 判定 |
|---|---|---|
| `1024×5/60 s ≈ 85.33 次/秒` | 5120/60 = 85.333 | ✓ 真 |
| `(1024×4+4)/60 ≈ 68.33` | 4100/60 = 68.333 | ✓ 数值真 |
| G15 写的避开锁定式 `max_throttle_buckets × (lockout_after-1)` | 1024×4/60 = **68.267** | ✗ **式子与旁边的 68.33 不同源**（缺 `+4` 那一项，即 `(max_buckets+1)×(lockout_after-1)`） |
| `1024×1/60 s ≈ 17.07` | 1024/60 = 17.067 | ✓ 真 |
| 占空比 `w/(w + max_throttle_buckets·lockout_after/注入率)` 用 84.4 ⇒ ≈83% | 60/(60+5120/84.4) = **49.73%**；83% 来自 r7 §2.3 的 60/(60+(1024+5)/84.4) = **83.11%** | ✗ **表达式抄错**（分子应是**武装成本** `max_buckets + lockout_after`，不是它们的积），PRODUCT:3330 指它取值 ⇒ 一处错污染两份契约 |
| 『这是可复算表达式，不是实测』『那是算术而不是实测』 | 两处都明写了 | ✓ 不误读为实测，r7 R7-AUDIT-4 的要求做到了 |
| PRODUCT:3312『V1 是零节流：**实测** 84.4 次认证/秒』 | 84.4 仍是 V1 时代实测、当前引擎从未重测；现在它同时被当『零节流吞吐』与『攻击者注入率』两用（后者隐含单个客户端吃满整节点吞吐，是乐观假设） | 残余：句子里『实测』两字仍会被读成**本引擎实测**；建议式子旁加半句『注入率取 PRODUCT 的 V1 吞吐上界』 |

另外两处正面确认：代价 (3) 明写『节流器**没有**把 84.4 压下去，它管的是单身份被猜速率与内存，
整节点认证成本属连接层限流与 RSS 计量（未闭环）』——r7 R7-W-1 要登记的那半**已登记** ✓；
涓流口径按 R7-AUDIT-4 改写为『每满一个窗口只滴一条者不被锁死；严格小于一个窗口的涓流仍会
跨窗口累积到阈值（`stale` 用 `>=`）』——与我独立重推一致 ✓。

---

## 6. 问题 F —— r7 三条 WARN 与三条降级 NOTE 的清偿

| 条目 | 判定 | 依据（详见 summary 的 `r7_disposition_audit`） |
|---|---|---|
| R7-W-1 聚合代价登记 + 可红对象 | **verified_with_new_defect** | G15 代价 (3) + PRODUCT 双登 + 新增 e8 可红对象（我重推 48/0 与 20/28 ⇒ 非空转）；新缺陷 = R8-W-1 两条式子 |
| R7-W-2 `forget` 零杀伤力 + 注释不实 | **verified** | 三条子判据全闭：N1 实测红新单测；`(asserted by the probe)` 已删并改为明写观测不到；两侧柱子（close 清计数 / sweep_idle 不清）都有测。改名无漏改（A4） |
| R7-W-4 对被删方案的假描述 | **verified** | MODULE:158-163 改成『标签字节数其实是被封住的…不是从无界变有界』，`.agents` 第八片原句旁就地标注不抹历史；与 `file_service.rs:744-754` 同口径 |
| R7-W-3 → R7-AUDIT-1 | **partly** | 口径改了（谎报那半闭合）+ 自抓写进契约；但 r7 修法要的『锁表占满才能升级』正向测试**没做**，且本批之后该支的正向覆盖更少而不是更多（E 我复核为零红），锁表上界还新失去观测面（R8-W-3） |
| R7-W-5 → R7-AUDIT-2 | **verified** | REQ-010:89 整段重写，四个缺口逐一补上；三处散文与代码逐字对齐；『只能靠人核』的边界实现方自己也写了，本评审就是那次人核 |
| R7-W-7 → R7-AUDIT-3 | **verified** | G15 代价 (4) 把归因残余（256 B 截断 + 近似类）写进契约，并明写『不允许只写在案卷自述里』；未证事项三条也落了 |
| R7-N-1/-3/-4/-7 | **partly** | -3/-4/-7 全做；-1 只做了一半（`:840` 的 61 现在应随树到 63） |
| R7-N-5/-6 契约面柱子 | **verified** | `other_source_still_admitted`、`throttle_pair_concatenation_is_separate` 均冻结，我重推 N5/N4 各打得中它们 |
| R7-N-12 复算台进仓 | **partly** | 拆会话那侧仓内有两条 #[test]（含孤锁正面断言）；可达性那侧仍只有自报数字，且 r7 复算台对新语义已失配 |
| **实现方对 R7-N-10 的否决** | **成立**（本评审独立复核） | `harness.toml:65-67` 落在 `[protection]`；无 `requirements.rs`；`gates.rs:675` 附近是 `coverage_gate`；`required_artifact_kinds` 全仓零命中；`product-scenarios` 门真实存在（`commands.rs:291-297`、`scenario.rs:201-216` 逐条求值、`:568`/`:572-576` 两条报法）⇒ 95 条全 PASS 是机器核过的。订正两点：『git grep ReviewRun 全仓零命中』在当前树上被否决文本自己命中 2 处（`.agents:637/639`），且 `.evidence/**` 未跟踪 ⇒ 建议改口径为『harness 的配置与代码里没有 ReviewRun 语义』（R8-N-6） |
| **R7-W-2 修法分歧**（补测试 vs 改语义） | **实现方方向对、理由不准** | 钉住现状 = 把一条可被第三方破坏的锁定完整性固化成承诺；翻掉 = 关掉可达的一半并顺带做出 r7 要的两侧柱子。但保留的清计数在同一前提下给出同一条预算（R8-W-2），而它给的因果『无限猜测预算』对无令牌者自己并不成立（R8-N-1）。分歧**没有被抹平**：三处留痕（第八片原句旁的更正、第九片第 1 条明写『评审者建议补两条单测，我判断现状本身是扇门』、第九片开头并列撰写者 6W/12N 与签发者 3W/16N、FILE_MANIFEST:258 的登记注）✓ |

---

## 7. 发现明细

### WARN

**R8-W-1（G15 两条算式复算不出自己旁边的数）** `MODULE.md:206-207`、`MODULE.md:212-216`、
`PRODUCT.md:3330`。占空比应写 `w/(w + (max_throttle_buckets + lockout_after)/注入率)`（83.11%），
现式给 49.73%；避开锁定那支应写 `(max_throttle_buckets + 1)×(lockout_after-1)/lockout_window`
（68.33），现式给 68.27。85.33 与 17.07 为真。两处都明写了是算术不是实测（这点做对了），
所以不是『把算术说成实测』，是**表达式与数值不同源**——r7 R7-W-1 订正 1 抓过的同一类错误被
抄进了契约。改两行字。

**R8-W-2（翻转只关了一半的洞）** `file_service.rs:944-946`（『清计数是无害且有意义的』）、
`MODULE.md:197-202`、`PRODUCT.md:3321-3323`、`requirements.toml:89`。锁定由**计数**达到阈值而
武装，`forget_failures` 仍清计数、仍经同一个无归属检查的 `close_session` 可达 ⇒ 同一条链
（会话号可猜 + 攻击者的失败记在与某个合法会话相同的 (主体,源) 上，需要同一传输地址可被多主体
共享，即 R7-N-9 登记的 source 前提）现在只需每 4 次猜密关一次会话，就把计数按定义钉在阈值之下
⇒ 锁**永远不武装**，比旧语义的『解锁』更省事。不判 FAIL 的三条理由：本批严格更安全；该前提
已在 R7-N-9 登记为未证事项；`FileEngine::close_session` 今天**没有任何 wire 调用者**
（`src/gateway.rs:1215` 的 `close_session_id` 是 DataChannel 会话，与引擎无关，`[核]`）。
修法三选一（详见 summary）：把 `forget_failures` 一并挂到 M2 归属检查之后 / 在 G15 代价里补
这条残余与它的前提 / 把理由改准（R8-N-1）。

**R8-W-3（窄路径的界给错 + 锁表上界零可红对象）** `file_service.rs:861-871`、
`MODULE.md:176-184`。`max_sessions` 不是孤锁的上界（close 释放会话槽，额度可顺序复用）；
真正的界是『一个窗口内造得出的活锁数』，默认参数需要 102.4 次认证/秒 > 代价 (3) 自算的
85.33 ⇒ 默认参数下那支其实仍到不了（本批的降级方向保守，界写错）。并且 L ≤ B 失效之后
`:873` 成了锁表唯一内存防线，而它没有任何读侧观测/期望（E 自报零红我复核为真）⇒ G15
『计数与表项有界』这一句对锁表那一半没有机器对象。补 `Throttle::lock_count()` +
`FileEngine::throttle_locks()` + 一条 `throttle_locks_bounded` 期望即可闭合。

### NOTE

- **R8-N-1** 翻转理由的因果说重一层（『无限猜测预算』需要共享 source 前提），r7 §4.1/§4.2 的
  因果说轻一层（『必须已持有正确令牌 ⇒ 不构成越权』漏掉了第三方拆别人会话这条更严重的读法）；
  行为无需回退，措辞要改。本评审自己的错判过程写在开头，留痕。
- **R8-N-2** N6 的机制与预测数字：武装来自**溢出计数**而不是单行阈值；每轮白送 2 条
  AUTH_DENIED ⇒ 20/28（实现方自报值，我复现）；`examples:735-736` 与场景注释仍写『约 16 /
  计数粘住』，与案卷自报的 20 不同源。
- **R8-N-3** 时间夹具方向判反：e8 对现实现**不可能假红**（三条理由，§4(1)），风险在杀伤力侧；
  『最可能先假红』那句该归 e6 的 `armed_before`。等价配方 = 注入时钟（配方 A）。
- **R8-N-4** 数字滚动残留：`:840` 的 61 应随树到 63；`:3291` 与场景注释的『61 单测 + 90 期望』
  需要『第八片树上』限定（`:954` 已经有了）；正面确认 `:866` 与 MODULE:179 已改成实测口径。
- **R8-N-5** 未冻结观测字段 9 → 12（新增 3 个都被合成式冻结，`state_cleared_after_close`
  零杀伤力也已在 doc 写清）⇒ 口径债。
- **R8-N-6** 对 R7-N-10 的否决成立，但『git grep ReviewRun 全仓零命中』现在被否决文本自己
  打脸（`.agents:637/639` 是跟踪文件），且 `.evidence/**` 未随分支跟踪；建议改口径。
- **R8-N-7** 正面登记：G16:252 的 close/闲置回收并列属**预算**释放面，与新语义不打架；
  `next_session` 从 **1** 起（r7 §4.1 写『从 0 起』是笔误，不影响可猜性判断）；`succeed` 唯一
  调用点在 `is_locked` 预检之后 ⇒ 锁定中不可能被间接触发。

---

## 8. 本轮**没有**重审的部分（为什么不重复审）

预算/在途/终端优先、路径解析/symlink/TOCTOU、`.part` 命名、审计环结构与 256 B 截断、
`validate()` 语料、`lock_until` 的 `checked_add` 兜底、准入检查（`max_sessions`/
`max_browser_sessions`）：本批未改，`[核]` `git diff 175e115 -- src/file_service.rs` 的 hunk
全部落在 `Throttle`（683-961）、`FileLimits.max_throttle_buckets` 文档、
`FileEngine::throttle_locked`、`close_session` 注释与 `mod tests` 的节流区。
`Throttle::default()`（r4 R4-N-5）与 `constant_time_eq` 调用点无断言（r1 起携带）仍按原登记
结转，本批未触碰、也未被改得更危险。

## 9. 签发结论

**COMMENTED，0 FAIL / 3 WARN / 7 NOTE，本批可合入。** 判定方向没有被本批改坏：fail-closed
仍可达且有 4 条独立柱子、正确令牌在个体锁与全局窗口内都被拒、两个上界各自成立、翻转没有开
新的解锁路径、改名没有漏改调用点、三处契约散文与代码逐字对齐、r7 的 3 条 WARN 清偿为
2 verified + 1 verified_with_new_defect、3 条降级 NOTE 清偿为 2 verified + 1 partly、
实现方对 R7-N-10 的否决经我独立复核维持。三条 WARN 都是改文字或加一条观测面的量级，
不构成阻塞；`non_blocking_followups` 按序随本批落地提交或下一片走。
第 8 轮 > AGENTS.md:1585 的 3 轮上限：r4/r5/r6 已三次向 owner 报备，本轮延续该状态；
r7 的两条待裁决项 owner 已裁决并落地，本轮新增一条需 owner 定方向的产品取舍（R8-W-2）。
