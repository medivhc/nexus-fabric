# 独立评审 r4 — 网关文件服务（`feature/gateway-file-service-contracts`，tip af953af + 未提交工作树）

**VERDICT: CHANGES_REQUESTED** — r3 的两条 FAIL（R3-NEW-1 终端发送失败丢弃挤占清单、R3-NEW-2 已在册主体永久锁不住）**在本树里都已真正修好**，我逐条读码 + 用状态机复算件独立复现过（见 §一）。R3-W-1/W-3/W-4 也修了，G12 那句"逐条都有单测把它跑红"这次**确实成立**（8 条规则逐个推演过杀伤力）。阻塞点换成了同族的另一处：本批新加的 `FileLimits.lockout_window` 字段**没有进 `validate()` 的"任一上限不得为 0"清单**，取 `Duration::ZERO` 时 G15 的锁定被静默关闭（复算件：200 次错令牌 200 次全部进入比较，默认值下只有 5 次），而契约写的是"配置不自洽即拒启动"。另有 **7 条 WARN 集中在"修复无可杀死的测试 + 案卷声称的测试不存在"**这一类：r3 R3-NEW-2 唯一被引用的证据 `lockout_rearms_after_expiry_and_flood_arms_are_not_exempt` **在旧（有缺陷）代码下同样全绿**；R3-W-1 与 R2-W-11 两条处置声称的断言在仓里找不到；G21"单测逐个动词断言"仍对 12 个动词中的 6 个为假。

---

## 〇、评审宿主、工具链与"未编译验证"声明

- 评审者：独立代码评审 agent（**非实现方**，只读复核）。宿主 **Windows (win32)**；本机 PATH 上有 rustc/cargo 1.95.0（`/d/rust/.cargo/bin`），但**本 crate 在本机不可编译**：`ssh2 0.9.6` 的 `userauth_pubkey_memory` 由 `cfg(any(unix, vendored-openssl, openssl-on-win32))` 门控，且无 cl.exe/nasm。**我没有编译本 crate，没有跑过 `cargo test`/`clippy`/`verify`，实现方的 55 单测 / 零诊断 / 9-9 场景 86 期望 / contract_hash `8f510129…` 我一个都没复现，也不把它们当我在任何一处结论的证据。**
- 运行时自报的模型标签：`qfmodel`（按 harness 给出的标签如实登记，不代表我对底层模型的身份主张）。
- 允许的例外（已按 brief 执行并清理）：临时目录里写了 **4 份 std-only 复算件**（`Throttle`/`SendBudget` 状态机的逐字复刻，把 `Instant` 换成逻辑时钟以消掉睡眠抖动；**不含任何 IO，不含产品代码依赖**），用于裁定三件事：① r3 两条 FAIL 的新旧对照，② 新单测的杀伤力，③ `lockout_window = 0` 的后果。**临时目录已删除**。复算件不是本 crate 的测试，不构成"已编译"。
- 本机静态交叉核验（已做）：`grep -c '^\[\[expect\]\]'` 九份场景 = **86**，逐文件 6/10/9/5/9/9/16/7/15，与 EV:318/323 自述一致；`grep -c '#\[test\]'` 同 crate src = **55**（file_service 30 + config 15 + protocol 6 + cert 2 + gateway 2），与"55 passed"与"本片新增 2 条"自洽；九份场景冻结的每一个字段名都能在探针里找到对应 `f.insert`（无引用已改名/不存在的字段）；`FILE_MANIFEST.md` 表格 `awk '/^\| /'` = 195 行（减表头 1）= 声明值 **194** ✓ 自洽。
- 被复评内容 = af953af 之上的**未提交工作树**（10 个改动文件）。评审侧内容指纹（我自己按 `path + git hash-object` 排序后取 sha1，**不是 git tree**）：`953e8ab343ef851d47c9dc3acbca5791fba43020`；其中 `file_service.rs` blob `6a997c7a49cad45f2ec821cfb7f4145c5a7096b6`、探针 blob `0963f2491ed4ef4bc7e7fd7bded8fe989fc05770`。
- 缩写：`FS`=crates/nexus-web-gateway/src/file_service.rs，`PR`=crates/nexus-web-gateway/examples/gateway_file_contract.rs，`MO`=crates/nexus-web-gateway/MODULE.md，`CF`=crates/nexus-web-gateway/src/config.rs，`PD`=PRODUCT.md，`EV`=.agents/green-evidence-gateway-file-service-m1.txt，`SC`=scenarios/product。

---

## 一、r3 处置逐条核验（读码 + 复算件判定，不是读注释判定）

| r3 项 | 处置声称 | 本评审判定 | 依据 |
|---|---|---|---|
| R3-NEW-1 | fixed | **FIXED** | 见 (1) |
| R3-NEW-2 | fixed | **代码 FIXED，证据无效**（→ R4-W-1） | 见 (2) |
| R2-W-11 | partly-fixed-and-declared | **FIXED（声明口径）+ 新增半边无可杀死测试**（→ R4-W-3） | 见 (3) |
| R3-NEW-3 | fixed | **(a) FIXED（真杀伤力）**；**(b) PARTLY**（→ R4-W-4） | 见 (4) |
| R3-W-1 | fixed | **代码 FIXED，声称的证据不存在**（→ R4-W-2） | 见 (5) |
| R3-W-2 | 并入 R3-NEW-2 处置 | **PARTLY**（1 条/window ⇒ 5 条/window；未写进契约，→ R4-W-6） | 见 (2) |
| R3-W-3 | fixed | **FIXED** | 见 (6) |
| R3-W-4 | fixed | **FIXED（有杀伤力）** | `SendBudget::settle_file` 严格只看队头（FS:877-892），FS:2600-2621 断"会话 2 不得插队/部分 settle 退 0/连续整条退 40"；把实现换回"扫全队列"，FS:2605 与 FS:2613 必红 ⇒ 真闸门 |
| R3-W-5 | = R2-W-11 | 见 (3) | |
| R3-W-6 | fixed | **PARTLY**：探针头例外段在位（PR:10-14）、G12 `files.enabled` 改为契约声明（MO:99-101 + PD:3341-3344）；**PD:3316"全局 RSS…都有配额表"仍与 MO:180 冲突**（→ R4-W-7） | |
| R3-N-1 | accepted-as-defense | **准确**：MO:123 仍写"提交路径同样必须过 require_writable + require_local_io 两道门"，两道门在位（FS:1774-1775）但结构上不可拒（等值检查 FS:1764 在前），属纵深防御，与处置一致 | |
| R3-N-2 | documented | **FIXED**：MO:131-133 写明为何复用 `OUTSIDE_ROOT` | |
| R3-N-3 | documented | **FIXED**：MO:127-130 + PD:3348-3350 登记两处残余窗口 | |
| R3-N-4 | registered-as-debt | **准确**：探针 emit 的 56 个不同字段里 **29 个**未被任何场景冻结（r3 记的 46 已因本批加严下降）；登记在 `open_debt_after_this_batch` ✓ | |
| R3-N-5 | documented | **FIXED**：MO:175-177 写明 `source` 必须是不可被对端影响的 transport address，M2 必须核 | |
| R3-N-8 | fixed | **该项在 r3 案卷的 findings 里不存在**（r3 的 NOTE 编号止于 R3-N-5；`disposition_by_implementer.items` 自己造了这条 ID，r3 summary.json:336），代码注释 FS:756 又引用"评审 r3 N-8"⇒ 证据 ID 卫生问题（R4-N-7）。改名本身（`terminal_delivered`→`terminal_accepted`，FS:757）是对的 | |

### (1) R3-NEW-1 —— 通过，且这次带真测试

`push_terminal` 改返回 `(Vec<(u64,usize)>, FileResult<()>)`（FS:799），**三条出口都交回清单**：`bytes > limit` 时清单为空（FS:801-815，不挤 = 不白赔），挤完仍放不下时把真实挤掉的清单随 `Err` 一起回（FS:820-830），成功时照旧（FS:831-833）。`FileEngine::send_terminal` **先按清单回冲再看结果**（FS:1046-1052），不再有 `?` 提前返回。复算件按 r3 的原始复现跑（limit=128、`send_terminal(64)` + 8×`push_file(8)` + `send_terminal(70)`）：旧写法 `inflight=64 / budget_for_session=0 / 不变量=false`，新写法 `0 / 0 / true`，`file_drops=8` ⇒ **r3 复算件的那条背离已闭合**。新单测 FS:2632-2688 三段都有杀伤力（删掉 FS:826-829 的回传 ⇒ FS:2647/2681 红；删掉 FS:801-815 的前置判定 ⇒ FS:2656-2658 红）。
残留：r3 整改第 1 条还要"一个探针字段"，**没加**——`SC quota:56` 仍冻 `ssh_messages_dropped = 0`，即探针面依然只测成功的终端发送（登记为 R4-N-8，单测已覆盖实质，故不阻塞）。

### (2) R3-NEW-2 —— 代码三处都改对了；但它唯一的"证据"杀不掉任何一条

改对的三处：① `is_locked` 的全局窗口对**所有**主体生效（FS:665-677，"不在 buckets 就豁免"那句已删）；② `record_failure` 开头 `decay(now)`（FS:680-682 + FS:655-663）回收到期锁，`locked` 因此不会再被死锁占满，达到阈值的在册主体走 FS:694-701 重新上锁；③ 全局窗口过期时 `global` 归零（FS:657-661）。复算件按 r3 的攻击序列（把 `buckets` 与 `locked` 都灌满 → 等锁过期 → 在册主体拿正确口令）：旧变体 **96 次里 56 次进入令牌比较、56 次开出会话**，新变体 **0 次** ⇒ r3 立案的"填满之后正确令牌照样通过"这条判据**在新代码上不再成立**。表也确有界：复算件持续灌 40 轮，`buckets ≤ 16(cap)`、`locked ≤ 16(cap)`、`global` 被窗口归零封顶在 5。`succeed()` 只在 `is_locked` 预检（FS:1150）与令牌比对通过之后调用（FS:1177），锁定期内清不掉桶 ✓。`lockout_window` 确实接线：`Throttle::new(..., limits.lockout_window)`（FS:982-986），不是硬编码 60 s ✓。
**不成立的是"这条修复有测试保护"**：见 R4-W-1。

### (3) R2-W-11 —— 声明口径合格；新增的 `list` 过账半边无测试

G16 已改成按"谁知道序列化长度"划分（MO:162-168：引擎**必须**过账 `read_page` 页字节与 `list` 的 `ack_bytes`；逐片 ack 与 `stat`/`mkdir`/`remove`/`rename`/`commit` 回包由 wire 层在 M2 逐动词接上，"否则 G16 每条出站文件类消息过账只对 read/list 成立"），PD:3351-3353 同步。这正是 r3 整改第 3 条给的两个选项之一，且**显式登记进了处置清单** ⇒ 该项结案。
新落的 `list` 过账（FS:1359，按 FS:1316-1347 已累计的 `ack_bytes` 计费，不是编数字）**在全仓找不到一条断言**：单测里 `list` 出现在 FS:2333/2400/2935/2940/3027/3029，没有一处看 `budget()`/`inflight_*`；探针 `list_pagination`（PR:97-124）不读预算，`quota_backpressure` 不调 `list`。**删掉 FS:1359 ⇒ 55 条单测与 9 条场景全绿**（R4-W-3）。

### (4) R3-NEW-3 —— G12 这次真兑现了；G21 没有

G12"（逐条都有单测把它跑红）"（MO:103）：`every_validate_rule_has_a_red_test`（FS:3383-3478）改成语料化的 8 条规则 + **断言错误消息里的规则名**，我逐条做了"删掉这条规则还红不红"的推演：8 条夹具各自只违反一条（`max_entries_per_page:0` / `browser=8>sessions=4` / `chunk 256>buffered 128` / `chunk 64>inflight 32` / `ack 256>buffered 128` / `ack 100<124` / `inflight 256>buffered 128` / `handles 2<sessions 8`），删掉对应规则后其余规则**都不会短路**（关键字互不为子串），`validate()` 返回 `Ok` ⇒ `expect_err` panic ⇒ 必红。r3 点名的 `handles < sessions` 夹具这次把 `chunk_bytes/inflight` 保持在默认（64 ≤ 128），不再借到别人的红 ⇒ **(a) 结案**。反向边界（FS:3464-3477，`ack == 信封+条目` 必须放行）有效，但它是**用同两个常量喂自己**（改常量不会红）⇒ R4-N-6 之外的算术自证只到"不等号方向"为止。
G21"单测逐个动词断言'恰好一行 + action 对 + 码对 + principal 非空'"（MO:208）：`abort_upload`（FS:3090-3100）、`ack_staged` 拒绝（FS:3101-3105）、`idle_recycle`（FS:2975-2978）这三条本批新加的断言**确有杀伤力**。但 MO:205-206 列的 12 个动词里仍有 **6 个的"恰好一行"没人断言**（见 R4-W-4）。

### (5) R3-W-1 —— 代码对了，处置里的证据句是空的

`charge_file` 现在两条早退都回滚：`checked_add` 的 `None` 分支先 `unpush_file` 再回 `OVERFLOW`（FS:1111-1117），`CAPACITY` 分支同样回滚（FS:1118-1128），`push_file` 自己失败时 `?` 走掉（FS:1107）无状态可回滚 ✓。但处置清单写的证据"**单测断言每次拒绝之后 inflight_matches_budget 仍成立**"在仓里**不存在**：全文件 `inflight_matches_budget` 只出现在 FS:1081/1082/2686/2788/2792/2795，分别在"失败的终端发送"与"挤占/ack"之后，**没有任何一条跟在 `CAPACITY`/`OVERFLOW` 过账拒绝之后**。我把最接近的 `per_session_inflight_ceiling_is_enforced_by_the_engine`（FS:2799-2827）按"删掉 FS:1120 的 `unpush_file`"重算了一遍：残留条目被后面的 `settle_file(s,16)` 一并冲掉，`inflight_bytes==0`（FS:2824）与 `read_page` 成功（FS:2825）**都仍然成立** ⇒ 该测试杀不掉这条修复（R4-W-2）。

### (6) R3-W-3 —— 通过

EV:318 本批"86 条"、EV:323-324 的更正（"上一片 77"、加严 9 = auth 7→9 + quota 11→16 + sftp 13→15）与我逐文件 `grep -c` 的结果完全一致；第四片 EV:249 的自述也已就地改为 86 而非覆盖历史。77 = 6+10+9+5+9+7+11+7+13 ✓，86 = 6+10+9+5+9+9+16+7+15 ✓。这条是静态可复核的算术，结案。

---

## 二、brief 指定七项的逐项验证

### 1. SendBudget 释放对称性（每一次消息离开 `file_queue` 是否都动 `inflight_bytes`）

`inflight_bytes` 的**全部**写入点是 4 处：初始化 0（FS:1214）、过账 `= next`（FS:1129-1131）、挤占回冲（FS:1047-1051）、ack 回冲（FS:1064-1069）。`file_queue` 的全部变更点是 6 处：`push_back`（FS:847）、`pop_back`（FS:855）、`pop_front`（FS:865 挤占 / FS:887 settle）、`retain`（FS:899 release_session）。逐条配对核验：

- `settle_file`：FS:887 出队 ⇔ FS:1067 回冲**实际释放的字节** ✓（FS:2793-2795 断 `inflight==0` 且不变量成立）。
- `release_session`（经 `close_session` FS:1235 与 `sweep_idle` FS:1257）：FS:899 移除该会话全部条目，会话对象连同 `inflight_bytes` 一起消失，事后 `inflight_bytes(missing)=0 == file_buffered_for(missing)=0` ⇒ 不变量成立 ✓（FS:3196-3237 两条路径都断 `budget().buffered()==0`）。
- `unpush_file`（`charge_file` 回滚）：移除的是**从未记入 `inflight`** 的那条（回冲发生在 FS:1129 之前）⇒ 两侧对称 ✓。
- `push_terminal` 成功与失败：见 §一(1) ✓。
- brief 点名的其他路径：`abort_upload`/`discard_stream`（FS:1860-1866、1870-1884）**不动预算**——流不占预算（`stage_chunk` FS:1592-1700 全程不过 `charge_file`）⇒ 无泄漏；逐片 ack/回包的字节在 M1 不进预算，是声明过的 wire 义务（MO:162-168）而非泄漏。`open_upload` 被拒不涉及过账（FS:1495-1568 无 `charge_file`）✓。闲置回收流（FS:1245-1253）只删 `.part` 与清 `streams`，随后 FS:1257 释放 ✓。`charge_file` 在"会话额度恰好等于上限"时放行（`next > ceiling` 严格大于，FS:1118）✓ 与 `ceil` 语义一致，不产生"扣了不记"的中间态。
- **残余**：`release_session` 的返回值（释放了多少字节）在两处调用点都被丢弃（FS:1235、FS:1257）。今天没有下游消费者，不构成缺陷，但"会话拆除释放了多少"因此不可观测（R4-N-2 之外的观测面缺口，NOTE）。
- `read_page` 在**释放句柄之后**才过账（FS:1467 → FS:1469）：过账失败时句柄已归还、页不返回（FS:1469 的 `?` 使 FS:1470-1475 不执行）⇒ 顺序正确，且 `every_verb` 的 `read/OK` 与 `engine_read_page_is_charged…` 都覆盖了成功侧。
- 被拒的 `list` 不会在任何地方返回一页（FS:1359 在构造 `ListPage` 之前）✓；`mkdir` 成功后回包被拒的情形不存在（`mkdir` 不过账），其审计行按 `outcome` 落（FS:1886-1893）✓ 无错记。

### 2. 节流锁定/解锁覆盖面

见 §一(2)。补充三条判据：
- **没有主体能永久锁不住** ✓：`record_failure` 先 `decay` 再判 `locked.len() >= max_buckets`，而 `locked` 的键必来自 `buckets`（只有 FS:699 写 `locked`，且 FS:692 的 entry 路径要求该键在 `buckets` 内），所以"桶在册 + 自身锁已过期"时 `locked.len() ≤ max_buckets-1` 必然成立 ⇒ 走 FS:699 写真锁。复算件 B 变体给出 0 次放行 = 实证。
- **到期不能被用来在"已入桶"的主体上无限猜** ✓：每个窗口每 (主体,源) 只多 1 次比较（FS:2711-2730 的夹具行为 + 复算件 E：20 个窗口里 `AUTH_DENIED` 只出现在第一窗口的阈值之前）。
- **两张表有界** ✓（复算件 D：`buckets`、`locked` 均恰好封顶在 cap，`global` 被归零封顶在 lockout_after）。
- **WARN（R4-W-6）**：`buckets` **自身永不衰减**（只有 `succeed` FS:706-709 与 `forget` FS:728-732 会删，两者都要求一次成功认证/一次会话拆除）⇒ 一旦伪造量把 1024 个桶位占满，"溢出人群"就成了永久人口，此后每窗口只需 `lockout_after`（默认 5）条伪造失败即可无限续期全局窗口。复算件 F：每 tick 1 条失败时，未在册的合法主体 **1872/2000 = 94% 的时间被拒**，而攻击者只需在窗口失效瞬间补 5 条 ⇒ 实际接近永久。PRODUCT:3313-3315 写的是"有时限的全局窗口…到期自行解除"，MO:149-153 还停留在"此后**未在册**的主体即使令牌正确也被拒"——两句都没覆盖"续期是无界的"这件事。r3 R3-W-2 给的两个出路（衰减/固定窗口 **或** 把续期口径写进 G15）本批只做了"窗口过期时归零 `global`"这一步（把成本从 1 条/window 提到 5 条/window），既没做桶衰减也没写契约。
- 另记一条 NOTE：`close_session` 的 `forget`（FS:1236）会清掉该 (principal, source) 的**在途锁定**；今天不可被无令牌者利用（要开 session 必须先过一次成功认证，而那次成功已清桶），但它与 `sweep_idle` 不清理形成不对称（FS:1255-1260 不调 `forget`）⇒ 见 R4-N-4。

### 3. 准入与身份

`authenticate` 的顺序：锁定预检 FS:1150 → 常数时间令牌 FS:1154 → `succeed` FS:1177 → 全局 `max_sessions` FS:1181-1190 → 单 peer `max_browser_sessions` FS:1191-1205（按 `s.source == source` 数）→ **才** `sessions.insert` FS:1206-1219 ⇒ 准入确在插入之前 ✓。`FileSession` 自记 `source`（FS:610）✓；`close_session(&mut self, session)` 不收调用方 source（FS:1228）✓，`throttle.forget` 用会话自己那对（FS:1236）✓。逐动词找剩下的"调用方身份决定安全状态"：所有动词只收 `session: u64`，principal 一律由 `record` 从会话解析（FS:2103-2112，空串才回落到会话）；流定位一律 `self.session(s)?.streams.get(id)`（FS:1613-1617 / 1707-1710 / 1757-1763 / 1871-1875），`stream_id` 服务端签发且不回收（FS:1528-1529）；`commit` 的 root 参数已与流的 root 等值绑定（FS:1764-1772）⇒ **无第二处**（与 r3 §二(4) 结论一致，本批未新增信任点）。剩下两条是前提而非缺陷：`source`/`principal` 本身来自 wire 层（MO:175-177 已写前提），`send_file_message(session, bytes)` 的 `bytes` 由调用方给（MO:162-168 已写义务）。

### 4. 契约句真伪

- MO:103 G12"逐条都有单测把它跑红"→ **真**（§一(4)）。
- MO:111"任一上限不得为 0"→ **假**（R4-NEW-1，见 §三）。
- MO:189/G21 MO:208"单测逐个动词断言"→ **对 6/12 个动作为假**（R4-W-4）。
- MO:204"漏记在结构上不可发生"→ **对 `close_session` 为假**（FS:1229 的 `if let Some` 使未知 id 零行；`stage_chunk`/`ack_staged` 的行 root 为空，R4-W-4/W-5）。
- PR:5-8"每一个字段都取自可观测引擎行为"+ PR:10-14 例外段 → **真**（例外显式点名 `capability-negotiation` 的 7 条与 `decide_channel` PR:902-924，PD:3337-3344 同口径）。
- `FILE_MANIFEST.md:5` 声明 194 → **与自己表格自洽**（195 行减表头）；但按本批新惯例应随分支携带的 r3/r4 案卷**未登记**，且 `git ls-files .evidence` 显示连 r1/r2 四份文件都还没 `git add -f`（R4-N-9）。
- PD §18.4（PD:3334-3361）列的未证事项：目录改名窗口 ✓、`hard_link`→`unlink` 与 `remove_tree` 部分删除 ✓、出站预算只覆盖页/列表 ✓、SCTP 对称性 / TURN / Windows 身份键 ✓ —— 四条都与代码对得上；**漏列**：全局 RSS 上界（PD:3316 反而声称"有配额表"，与 MO:180"未验"冲突，R4-W-7）、`LIST_ACK_ENVELOPE_BYTES=72 / ENTRY_ACK_OVERHEAD=52` 是对尚不存在的 M2 编码的估算（只在 FS:914-921 注释里声明，契约面没写）、`sync_all` 的耐久性未做崩溃实验（MO:188-190 写了，PD 没写）。

### 5. 期望条数算术

`grep -c '^\[\[expect\]\]'`：auth 9、capability 7、download 10、list 6、quota 16、sandbox 9、sftp 15、no-replace 5、resume 9 ⇒ **86**。九份文件里 `[[` 开头的表共 86 个且全是 `[[expect]]`（无 `[[expect.*]]` 变体）。EV:318"86"、EV:323 的分解"86 = 6+10+9+5+9+9+16+7+15"、EV:324"相对 77 加严 9"全部与实测一致；第四片 EV:249 已就地改正。**无 mismatch**（R3-W-3 结案）。

### 6. 新引入的东西（逐项）

`push_terminal` 签名 ✓（§一(1)）；`settle_file` 队头 ✓；`charge_file` 双侧回滚 ✓（但无测试，R4-W-2）；`Throttle::decay`/无豁免/`global_locked_until` ✓ 代码对、测试空（R4-W-1）；`FileLimits.lockout_window` 字段**没进零值清单**（R4-NEW-1）；默认 `max_inflight 128 KiB` 与 `max_buffered 128 KiB` 同量级并由 FS:218-224 交叉校验 ✓（但 `SC quota:8` 的 `[given] max_inflight_bytes_per_session = 1048576` 仍与实际夹具/默认脱节，r2 N-5 已登记）；ack 下限 `>= 72+52` ✓ 真被 FS:201-212 拒（`max_ack_bytes=100` case）；`HandleRegistry` HashSet 去重 ✓ 无回归（FS:3366-3380 直测上限）；`list` 过 `ack_bytes` ✓ 逻辑对但无测试（R4-W-3）；`list` 只用 `symlink_metadata`（FS:1342-1345）✓；`read_page` 0 字节显式拒（FS:1399-1409）✓；`rename` 文件走 `hard_link`+`unlink`（FS:2030-2048）✓ 但判目录用了跟随链接的 `std::fs::metadata`（FS:2027）与 `dst.exists()`（FS:2020）（R4-N-3）；`commit` root 绑定 + 两道门 ✓；`abort_upload`/`ack_staged`/`close_session` 审计包装 ✓（覆盖面见 R4-W-4/W-5）；`part_path` 错误码 `AlreadyExists ⇒ OUTPUT_EXISTS`、其余 ⇒ `CAPACITY`（FS:1536-1547）——**方向对但无测试**（nonce 不可预置，W-12 同一欠账；且"其余一律 CAPACITY"仍把权限/配额类失败归因成容量，属已登记的词表欠账）；`CF` 的 `MAX_TERMINALS_CEILING=64`（CF:15-20、262-271）+ 单测（CF:348-357）✓ 有杀伤力（删上界 ⇒ 第一条断言红；把上界配歪 ⇒ 第二条红），仓内无 `max_terminals > 64` 的配置（`gateway.example.json:31` = 5，e2e = 5/1）⇒ 不会把既有配置拒掉。
另外两条"新形状"值得记：`SendBudget::push_file` 的 `self.buffered() + bytes`（FS:840）与 `drain_file_reserve` 的 `self.limit - self.buffered()`（FS:863）是**未 checked 的算术**，而 `bytes` 来自公开的 `send_file_message`（FS:1088）⇒ 与 G20"一律 checked_*"的字面口径不符：`bytes = usize::MAX` 时先在 FS:840 panic（debug/测试构建），根本走不到 FS:1113 那条新加的 `checked_add` 回滚（R4-W-8）；`FileSession.recycled` 只写不读（FS:1247 写、FS:1255-1259 随即 `remove`）⇒ 死状态（R4-N-1）；`Throttle` 仍 `derive(Default)`（FS:620）而 `Default` 会带出 `max_buckets=0/lockout_after=0/lockout=0` 的危险实例，全仓只有 `new` 用它 ⇒ 建议删 derive（R4-N-5）。

### 7. 测试杀伤力

见 §四表。一句话结论：本批 2 条新单测里**一条有真杀伤力（terminal 回冲），一条零杀伤力（throttle）**；3 处声称"修好"的东西（`charge_file` 回滚、`list` 过账、G21 逐动词）没有可红的断言。

---

## 三、新缺陷（FAIL/WARN/NOTE）

**R4-NEW-1（FAIL）`validate()` 的"任一上限不得为 0"漏掉本批新增的 `lockout_window`，取 0 时 G15 锁定被静默关闭（fail-open）。**
FS:155-164 的零值清单覆盖 9 个数值字段，**不含** `lockout_window`（FS:120/145，本批新增）、`idle_timeout`（FS:114）、`max_upload_bytes`、`max_rehash_bytes_per_stream`。`Throttle` 直接从 `limits.lockout_window` 拿值（FS:982-986），`record_failure` 写的是 `locked.insert(key, now + self.lockout)`（FS:699）；`lockout = 0` 时该项立刻"过期"，`is_locked` 的 `*until > now`（FS:669）恒假，而全局窗口只在 `locked` 满时才立（FS:696-698）⇒ **每一次错误令牌都完整走到 FS:1154 的令牌比较**，锁定只剩"把返回码写成 THROTTLED"的装饰作用。复算件：`lockout_after=5` 下连喂 200 次错令牌——默认 60 s 时进入比较 **5 次**，`lockout_window=0` 时 **200 次**（且第 6 次起返回码仍是 THROTTLED，错误码与真实原因不符，正是 r2 N-3/r3 NEW-2 反复立案的那一族）。`idle_timeout = 0` 同理：FS:1246 的 `> timeout` 对任何先前时刻成立 ⇒ 每个会话立刻被回收。契约侧 MO:111"任一上限不得为 0"与 FS:167 的自述"a zero ceiling silently disables its gate"在此为假；`every_validate_rule_has_a_red_test` 的 8 条夹具也不含这两个字段（FS:3388-3451）。今天没有配置面能填入这个值（`files` 尚未接进 `GatewayConfig`），但 `FileLimits` 与 `FileEngine::new` 都是公开 API，M2 一接配置就变成"启动即 fail-open"。修法（≤5 行）：把 `self.lockout_window.is_zero() || self.idle_timeout.is_zero() || self.max_upload_bytes == 0 || self.max_rehash_bytes_per_stream == 0` 加进 FS:155-164，并在 `every_validate_rule_has_a_red_test` 加第 9 条夹具（`lockout_window: Duration::ZERO`）——MO:111 那句于是自动变真。

**R4-W-1（WARN）r3 R3-NEW-2 唯一被引用的测试在旧（有缺陷）代码下同样全绿；其核心断言的夹具主语根本不在 `buckets` 里。**
`lockout_rearms_after_expiry_and_flood_arms_are_not_exempt`（FS:2691-2755）。复算件按 `lockout_window=40ms / lockout_after=2 / max_buckets=8` 逐条复现：把 `is_locked` 换回"豁免在册主体"、把 `decay` 换成空函数、把 `global` 归零换成"只增不减"——**六条断言全部仍然成立（failing asserts = []）**。原因可指名：① FS:2711-2730 的"过期后再犯必须重新锁上"在 `locked.len()==1 < 8` 时旧实现也会重新 `insert`，回收与否不可区分；② FS:2739 的主语 `"in-table-but-not-locked"` **从未在这个引擎上失败过一次**，因此不在 `buckets`（复算件打印 `buckets(in-table)=false`），旧写法的全局窗口对它照样生效 ⇒ FS:2742-2743 那句"全局窗口对**所有**主体生效，已在册的不得豁免"断言的是一个不在册的主体，**对该修复零杀伤力**；真正能区分的是 `flood0`（在 `buckets`、未被锁、窗口已立），复算件给出"旧=放行 / 新=拒绝"，而测试没用它。③ FS:2745-2753 的"窗口自行过期 + 迟到用户可进来"在旧代码（`global` 只增不减）下同样成立——要杀 R3-W-2 必须在**过期之后再喂 `lockout_after-1` 条溢出失败并断言 `!throttle_globally_locked()`**，测试没有这一步。探针同理：`throttle_full_fail_closed`（PR:537-543）与 `product_engine_fails_closed_when_flooded`（PR:590-593）用的都是 `brand-new`/`fresh-after-flood`，都不在 `buckets`。⇒ 结论：代码是对的（复算件 B 实证），但**这条修复没有回归保护，而 r3 summary.json 的处置把它当证据登记了**，下一片任何一次改歪 `is_locked`/`decay` 都不会红。修法：把 FS:2739 的主语换成真实在册主体（`flood0` 或"p0"，即"在 buckets 且不在 locked"），并补"窗口过期后再喂 4 条 ⇒ 仍未全局锁定；第 5 条 ⇒ 锁定"。

**R4-W-2（WARN）R3-W-1 的处置证据（"单测断言每次拒绝之后 inflight_matches_budget 仍成立"）不存在；该回滚无可杀它的测试。** 依据见 §一(5)：`inflight_matches_budget` 的四个断言点（FS:2686/2788/2792/2795）都不在过账拒绝之后，而 FS:2799-2827 在删掉回滚后仍全绿。修法：在 `per_session_inflight_ceiling_is_enforced_by_the_engine` 的 `CAPACITY` 之后加 `assert!(e.inflight_matches_budget(s))`（旧写法下为假：`inflight 16 / budget 24`），并在探针 quota 案加一个同名观测。

**R4-W-3（WARN）本批新加的 `list` 过账（FS:1359）在单测与探针两侧都没有观测。** 见 §一(3)。修法：给 `list_pagination`（PR:97-124）或 `quota_backpressure` 加一个 `list_charged_to_shared_budget` = `budget().file_buffered_for(s) == inflight_bytes(s) && 首list后 budget>0`，冻进 `SC list-pagination`；再加一条"预算满时 `list` 回 QUEUE_FULL 且不返回页"。

**R4-W-4（WARN）G21 的"单测逐个动词断言"仍对 MO:205-206 列出的 12 个动词中的 6 个为假。** 现覆盖：`authenticate`(拒)/`read`(3)/`list`(2)/`mkdir`(2)/`rename`(3)/`stage_chunk`(拒)/`commit`(拒)/`ack_staged`(拒)/`stat`(拒)/`remove`(拒)/`abort_upload`(成)/`idle_recycle`(成)/`close_session`(成，仅 action)。缺的 6 个分两级：**存在性没人钉（删掉 record 全库不红）= 成功侧的 `stat`（FS:2062）、`commit`（FS:1740）、`remove`（FS:1929）、`open_upload`（FS:1489）与 `close_session(未知 id)` 零行（FS:1229-1238）**；**四件套形状没套用（存在性有人钉，但记两行/记错 action/记空 principal 无人管）= `authenticate` 成功（FS:3016-3017 只断 `result_code`）与 `close_session` 成功（FS:3323-3327 只断 action）**。逐条变异推演：删掉 FS:2062（`stat` OK 的 `record`）⇒ 全绿（FS:3137 的 8242 次循环用的是 `missing.bin`，走拒绝分支）；删 FS:1740（`commit` OK）⇒ 全绿；删 FS:1929（`remove` OK）⇒ 全绿；FS:3070 对 `open_upload` 成功只比 `action`，而它上一行（FS:3063-3068）正是一条 `open_upload` 拒绝 ⇒ 删掉 FS:1489 的 `record` 该断言照样成立（**恒真断言**）；`close_session` 未知 id 时 FS:1229 的 `if let Some` 使整段零行 ⇒ MO:204"漏记在结构上不可发生"仍不严格成立。修法：把这 6 个成功/未知-id 情形纳入同一个 `audited!` 形状（一次调用 + 行数 +1 + 码 + principal），或把 MO:208 改成"逐个动词（除…成功路径…）"并登记欠账——**这两条路 r3 已经给过一次（整改第 5 条），本批只做了 12 条里的 3 条。**

**R4-W-5（WARN）审计行的 `root` 字段对 4 个动词恒为空，与 MO:202 的承诺不符。** `stage_chunk` 拒绝（FS:1587）、`ack_staged` 拒绝（FS:1715）、`abort_upload` 未知流（FS:1881）、`authenticate`（FS:1151/1156-1167）都传 `""`；而 `stage_chunk`/`ack_staged` 的多数拒绝发生在**流已定位之后**（FS:1614-1617 已 `get` 到流，INTEGRITY/CAPACITY 都在其后），流自己正记着 root（FS:582），`abort_upload` 本批也正是这么改的（FS:1875）⇒ 同一个信息在包装层可得却只填了一处。这是 r2 W-5 被 r3 记为"未清偿另一半"、处置清单里没有对应项的那条（整改第 6 条）。

**R4-W-6（WARN）全局窗口实际可被无界续期，而两份契约都把它写成"有时限/到期自行解除"。** 见 §二(2) 第三条与复算件 F（94% 拒止，攻击成本 5 条/窗口，因 `buckets` 永不衰减）。与 r3 R3-W-2 同一项，判定 **PARTLY**：本批把续期成本从 1 条提到 `lockout_after` 条，既没给桶加衰减/驱逐，也没把"可无限续期"写进 MO:149-153 或 PD:3313-3315。这正是 AGENTS"不允许偷偷把取舍换成另一种"要求显式登记的那类。

**R4-W-7（WARN）PD:3316 仍把"全局 RSS"列入"都有配额表"，与 MO:180"全局 RSS 上界仍未验"直接冲突；§18.4 也没登记它。** 全仓 `grep -i rss` 只有 FS:2092 的注释与两份文档（无任何计量/上限实现）。这是 r3 R3-W-6 的第三半边，处置清单里 R3-W-6 声称"PRODUCT §18.4 同步写清这一点"，实际只写了 `files.enabled`。

**R4-W-8（WARN）G20 的"一律 `checked_*`"在预算路径上有两个未检查的算式，并使本批新加的 `OVERFLOW` 回滚在 debug/测试构建里不可达。** `push_file` 的 `self.buffered() + bytes`（FS:840）与 `drain_file_reserve` 的 `bytes.saturating_sub(self.limit - self.buffered())` 里的 `limit - buffered()`（FS:863）都是裸算式，`bytes` 来自公开的 `send_file_message`（FS:1088）。`current + bytes` 要溢出必使 `buffered + bytes` 同时溢出（`inflight ≤ buffered`），因此 FS:1111-1117 的 `checked_add` 分支**永远在 FS:840 之后**：测试构建里先 panic，release 构建里先回绕。修法：`bytes.checked_add(self.buffered())` 后按 `QUEUE_FULL` 拒，`limit.saturating_sub(buffered())`；并把"FS:1113 这条回滚在何种输入下可达"如实写进注释或删掉（现在是不可达且无断言的分支，属 brief 点名的"unreachable-but-asserted"形状）。

**NOTE（10 条，逐条）**
R4-N-1 `FileSession.recycled` 写于 FS:1247、随即在 FS:1256 随会话一起删除，无任何读取者 ⇒ G21 的"回收"状态不可查询（只有 `sweep_idle` 的返回 id 列表）。
R4-N-2 `budget.release_session()` 的返回值（归还字节数）在 FS:1235 与 FS:1257 两处都被丢弃 ⇒ "拆除归还了多少"不可观测，`session_teardown_releases_the_shared_budget`（FS:3196-3237）只能间接断言 `buffered()==0`。
R4-N-3 `rename_inner` 用 `std::fs::metadata(&src)`（FS:2027，**跟随符号链接**）判目录、`dst.exists()`（FS:2020）、`open_upload_inner` 的 `abs.exists()`（FS:1522）同族；本文件的既定方法是 `symlink_metadata`（FS:1338-1341 的 W-2 注释就是这条理由）。影响被 FS:2018 的 `reverify` 与提交时 FS:1822 的 `resolve` 夹住（链接目标最终仍会被拒），但"src 在 reverify 之后被换链 ⇒ 用 `rename(2)` 移动链接本体"落进 root 内是可能的；`remove_tree` 用的是 `symlink_metadata`（FS:1981）⇒ 同一文件里两种口径。
R4-N-4 `sweep_idle`（FS:1255-1260）不 `throttle.forget`，`close_session`（FS:1236）却会清掉该 (principal, source) 的在途锁定；不对称，今天不可被无令牌者利用，但值得在 G15 写一句"回收不清节流状态"。
R4-N-5 `Throttle` 的 `derive(Default)`（FS:620）能造出 `max_buckets=0/lockout_after=0` 的实例（全仓只用 `new`，FS:982）；建议删 derive 或改为 `debug_assert`。
R4-N-6 `every_validate_rule_has_a_red_test` 的反向夹具（FS:3464-3477）与 ack 下限（FS:201-203）共用 `LIST_ACK_ENVELOPE_BYTES/ENTRY_ACK_OVERHEAD_BYTES` 两个常量 ⇒ 这条"边界必须放行"杀不掉不等号方向之外的任何东西，也**杀不掉 72/52 本身估错**（那两个数描述的是尚不存在的 M2 编码，FS:914-921 已声明，但契约面没登记）。
R4-N-7 处置清单里的 `R3-N-8`（r3 summary.json:336）在 r3 的 findings/`findings[]` 中没有对应条目（NOTE 编号止于 R3-N-5），FS:756 的代码注释又引用"评审 r3 N-8"⇒ 引用不存在的评审 ID，后续读者无法回溯。
R4-N-8 探针仍无"失败的终端发送"观测，`SC quota:56` 还冻 `ssh_messages_dropped = 0`（r3 整改第 1 条点名过；实质由 FS:2632-2688 覆盖，故降为 NOTE）；另有 29 个 emit 未被冻结的字段（R3-N-4，已登记欠账）。
R4-N-9 `FILE_MANIFEST.md:5` 的 194 与自身表格自洽，但按 CF:31-44 新立的"案卷随分支携带"惯例，r3/r4 四份文件未登记；且 `git ls-files .evidence` 显示 r1/r2 四份**尚未真正 `git add -f`**（`.gitignore:3` 仍排除）⇒ 落地提交时计数须改为 198，否则声明与仓内不一致。
R4-N-10 `ack_staged`（FS:1705-1718）不 `touch(session)`，而其余动词都刷 `last_activity`；只轮询 ack 的客户端会被闲置回收。另：`SC quota:8` 的 `[given] max_inflight_bytes_per_session = 1048576` 与新默认（FS:140，128 KiB）/探针夹具（PR:607，128）仍脱节（r2 N-5 已登记）。

---

## 四、测试杀伤力表（本批新增/改动的测试，逐条"改坏什么还绿"）

| 测试 | 位置 | 杀伤力 | 依据（变异推演） |
|---|---|---|---|
| `failed_terminal_send_still_hands_back_the_evicted_list` | FS:2632-2688 | **有（3 处）** | 回退成 `FileResult<Vec<_>>` ⇒ FS:2647/2681 红；删 FS:801-815 前置判定 ⇒ FS:2656-2658 红（复算件 C：inflight 64 vs 0） |
| `lockout_rearms_after_expiry_and_flood_arms_are_not_exempt` | FS:2691-2755 | **无** | 复算件 A：三个缺陷变体（豁免 / 无 decay / global 不归零）下六条断言全绿；FS:2739 主语不在 `buckets`（R4-W-1） |
| `terminal_class_has_priority_over_file_class`（本批加了 settle 断言） | FS:2576-2630 | **有** | 回退"扫全队列" ⇒ FS:2602/2605/2613 红；按条记账退化 ⇒ FS:2591/2595 红 |
| `every_validate_rule_has_a_red_test`（重写为关键字断言） | FS:3383-3478 | **有（8/8）** | 逐条删规则后其余不短路，`expect_err` panic；反向边界断言有效但自喂常量（R4-N-6） |
| `idle_sweep_uses_the_refreshed_field`（本批加 `idle_recycle` 行） | FS:2973-2978 | **有** | 删 FS:1258 的 `record` ⇒ action/code/principal 三条全红 |
| `every_verb_is_audited_including_refusals`（本批加 `abort_upload`/`ack_staged`） | FS:3090-3105 | **部分有** | `abort_upload`/`ack_staged` 红（删 FS:1878/1881/1715 的 `record` 即红）；但 `stat`/`commit`/`remove`/`open_upload` 的**成功行**、`close_session(未知 id)` 删了全绿（R4-W-4）；FS:3070 是恒真断言 |
| `engine_read_page_is_charged_to_the_shared_budget` | FS:2758-2797 | **有** | 断 `inflight_bytes==0` + `inflight_matches_budget` 三连（FS:2787/2788/2792/2795）；r2 点名的错误等式已改对 |
| `session_teardown_releases_the_shared_budget` | FS:3196-3237 | **有** | close 与 sweep 两处各断 `budget().buffered()==0` |
| `per_session_inflight_ceiling_is_enforced_by_the_engine` | FS:2799-2827 | **有（对上限），无（对回滚）** | 见 R4-W-2 |
| `throttle_fails_closed_when_the_table_is_full` | FS:3240-3276 | **有（未在册人群）** | 仍不含"在册主体 + 全局窗口"的组合（R4-W-1 同一缺口） |
| `handle_registry_ceiling_is_reachable` | FS:3366-3380 | **有** | 删 FS:549-557 的 CAPACITY 分支即红；FS:2918 `peak <= 1` 仍恒真但 MO:178-179 如实声明 |
| `rename_a_file_is_non_overwriting_and_leaves_one_name` | FS:3332-3363 | **有** | 回退成 `rename(2)` ⇒ FS:3347 的 EXISTS 与 FS:3350-3351 的原字节断言红 |
| `zero_byte_page_request_is_refused_not_stalling` | FS:3480-3497 | **有** | 删 FS:1399 的 `max_bytes == 0` ⇒ FS:3491 红 |
| `oversized_max_terminals_rejected`（CF:348-357） | CF | **有** | 删上界 ⇒ 第一条断言红；上界配歪 ⇒ 第二条红 |
| `commit_cannot_be_redirected_to_another_root` | FS:3146-3194 | **有** | 含"只读根 0 条目"与"拒后仍可发布"两半 |
| 声称存在但不存在的断言 | 处置清单 R3-W-1 | — | "每次拒绝之后 inflight_matches_budget" 无对应代码行（R4-W-2） |

---

## 五、本宿主/本树不可机器验证（评审只能目视或无法判定）

1. 实现方全部实测数字：55 单测 / clippy 零诊断 / 9-9 场景 86 期望 / `verify --fast` 9 门 / contract_hash `8f510129…`（对内容树 `e32967d3…`）。**未复现。** 只有三条我能静态对上：`#[test]` 计数 = 55、`[[expect]]` 计数 = 86、清单 194 = 表行数-1。
2. `constant_time_eq`（FS:2219-2228）的不提前返回性质与"认证路径真的用它"（FS:1154 换成 `==` 全库仍绿；FS:3527-3536 已如实登记为目视项）。
3. 残余 TOCTOU：`resolve`/`reverify`/`reverify_parent`/`reverify_ancestor`（FS:374-445、2137-2177）在单线程测试里与前置检查不可区分；`rename` 的 `hard_link`→`remove_file` 窗口、`remove_tree` 的部分删除、`create_new` 与父目录换链——MO:127-130、PD:3348-3350 已登记为未证。
4. Windows 面：`\\?\` 前缀比较（FS:297-303）、大小写不敏感、目录符号链接特权、`hard_link` 在 FAT/exFAT 失败（会把 W-3 的原子路径退化为 `CAPACITY`，而 §18.3 的 B 级口径以此为前提）、FS:3505-3510 的非 unix skip。**本机不可编译，未执行。**
5. SCTP 真实语义：`bufferedAmount` 与 `set_sctp_max_buffered_amount` 对称性、"消息不可部分发送"这一整个 settle/drain 模型的前提、终端类零丢失在真实 pty 路径（`send_terminal` 全仓除 FS/PR 无调用点，wire 层尚不存在）。
6. `72`/`52` 两个 ack 成本是对**尚未存在**的 M2 编码的估算（FS:914-921）；M2 换编码必须重测 `validate()` 的 ack 下限与 `list` 的字节截断。
7. 耐久性：`sync_all()` 真在发布前落盘（FS:1791-1793）需崩溃/掉电实验；逐片 `flush()` 是空操作属 std 事实。
8. 全局 RSS 上界与 `/proc/self/fd`：std 下无计量（MO:180），本批未改。
9. panic-free-by-construction：除 R4-W-8 两处外，我把非测试算术点（FS:837-901、1316-1359、1413-1469、1610-1700、1776-1808）都看过，未发现**外部可控输入**可达的新 panic；fuzz（PD:3320-3321 语义）未执行。
10. 我复算件裁定的是**状态机与算术**，不是并发/时序/IO；`buckets`/`locked` 的实测上限只在复刻件里成立（真实 `Instant` 与 40 ms 窗口的测试仍受宿主调度影响，见 FS:2720/2745 的 sleep 与 2737 的断言间距）。

---

## 六、合并决定

**CHANGES_REQUESTED（1 FAIL / 8 WARN / 10 NOTE）。** 阻塞项，按序：

1. **R4-NEW-1**：`lockout_window`（及 `idle_timeout`/两个 u64 上限）进 `validate()` 的零值清单 + 第 9 条红测试。≤5 行，两句契约话（MO:111、FS:167）随之变真。
2. **R4-W-1 + R4-W-2 + R4-W-3**：给本批三条修复各配一条**真会红**的断言——`is_locked` 无豁免（用真实在册主体做主语，并断"过期后再喂 4 条不锁、第 5 条锁"）、`charge_file` 回滚（拒绝之后 `inflight_matches_budget`）、`list` 过账（`list` 之后预算与额度同步）。r3 的两条 FAIL 是代码回归，本轮的同类问题是**证据回归**：一处修复的回归保护为零，一处处置登记了仓里不存在的断言。
3. **R4-W-4 + R4-W-5**：G21 的两句话要么兑现（把 `stat`/`commit`/`remove`/`open_upload`/`authenticate`/`close_session` 成功行与未知 id 行纳入同一断言形状；`stage_chunk`/`ack_staged` 的行补 root），要么把句子改成带例外的口径并登记欠账。FS:3070 的恒真断言应改掉。
4. **R4-W-6 + R4-W-7**：桶衰减/固定窗口二选一，或把"窗口可被 `lockout_after` 条/窗口的伪造失败无限续期"写进 MO:149-153 与 PD:3313-3315；PD:3316 的"全局 RSS 有配额表"与 MO:180 对齐（这是 r3 整改第 5 条明确列过的两句，本批处置只做了其中一半）。
5. **合入清单**：落地提交时按 FILE_MANIFEST 的新惯例 `git add -f` 携带 r1-r4 案卷并把 194 更正为 198（R4-N-9）。

**AGENTS.md 的第 3 轮升级条款已被触发**：本分支的评审迭代已连续 4 轮未收敛（r1/r2/r3 均 CHANGES_REQUESTED）。r1→r2→r3 收敛趋势明确（FAIL 6→5→2），本轮 FAIL 降到 1 且**没有再出现"自己修出来的行为回归"**——剩下的 1 条是新增字段没进已有的零值门，其余全部是测试/契约真伪与可用性取舍登记。按规则我**不自行判定"可以合"**：R4-W-6（合法新用户在默认配置下可被永久拒于认证之外）是"内存有界 vs 可用性"的**产品取舍**，应由 owner 裁决（选 A：给桶加衰减；或选 B：接受并在 G15/§18.2 落字）。除此之外，第 1-3、5 条是纯工程件，实现方一轮内可清偿；清偿后本评审可给 APPROVED/COMMENTED。
