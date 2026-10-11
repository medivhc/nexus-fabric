# 独立评审 r3 — 网关文件服务（`feature/gateway-file-service-contracts`，af953af + 未提交工作树）

**VERDICT: CHANGES_REQUESTED** — r2 的 5 条 FAIL 里 **NEW-1 / NEW-4 真已修复**，**NEW-5 的数值分歧由实现方胜**（本评审复算后判 r2 推算有误，见 §二），**NEW-2 与 NEW-3 只修了一半，而且残留的正是它们各自被立案的那一条**：终端发送失败时挤掉的消息不回冲会话额度（in-flight 与预算永久背离），以及 `locked` 表满之后已在册主体**永久锁不住**。12 条 WARN 中 W-1/2/3/4/10 已修，W-5/6/8 部分修（且新落的 G12/G21 两句"逐条都有单测""逐个动词断言"仍为假），**W-11 在处置清单里整条缺失**。另：本片自报的期望条数与自己刚写的表格不自洽（80 vs 86）。

---

## 一、评审宿主、工具链与"未编译验证"声明

- Reviewer：独立评审 agent（非实现方），model `qfmodel`（运行时自报值），宿主 **Windows**；工作树 `E:/nexus-fabric-m0`，`git log -1` = `af953af`，工作树有 10 个未提交改动文件。
- **本轮为纯静态评审。我没有、也不能在本机编译这个 crate**：`ssh2 0.9.6` 的 `user_unxth_pubkey_memory` 由 `cfg(any(unix, vendored-openssl, openssl-on_win32))` 门控，本机无 cl.exe/nasm，`cargo test/clippy` 一次都没跑过。**凡"跑出来是多少"的结论都不出自本评审。**
- 允许的例外：为把算术钉死，我在临时目录写了一份 **std-only 复算件**（把 `SendBudget`/`charge_file`/`send_terminal` 的算术逐字抄出来跑，不含任何 IO），输出四条（见 §三 R3-NEW-1、§二 NEW-5、R3-W-7），**临时目录已删除**。这是复算件不是产品代码测试，不构成"已编译本 crate"。
- 静态交叉核验（本机可做，已做）：`grep -c '^\[\[expect\]\]'` 九条场景 = **86**；探针 emit 字段集合 ⊇ 场景冻结字段集合（**无一条冻结字段引用了探针不再 emit 的名字**，即 `final_send_squeezed_messages` 已同步改名）。
- 实现方在 xc-pc-linux（rustc/cargo 1.98.1）对内容树 `2da0dae385cdb25f94737ed212f3d41ac9196ebd` 自报：53 单测全绿、clippy 零诊断、9/9 场景 80 条期望、`verify --fast` 9 门、contract_hash `8f5101…`。**本评审未复现其中任何一个数字**；`--lib` 单测条数我按 `#[test]` 计数交叉过：`file_service.rs` 28 + 同 crate 其余 25 = **53**，与自报一致（仅此一条能静态对上）。

文件缩写：`FS`=crates/nexus-web-gateway/src/file_service.rs，`PR`=crates/nexus-web-gateway/examples/gateway_file_contract.rs，`MO`=crates/nexus-web-gateway/MODULE.md，`CF`=crates/nexus-web-gateway/src/config.rs，`SC`=scenarios/product，`PD`=PRODUCT.md，`EV`=.agents/green-evidence-gateway-file-service-m1.txt。

---

## 二、r2 逐条处置核验（读码判定，不是读注释判定）

| r2 项 | 处置声称 | 本评审判定 | 依据 |
|---|---|---|---|
| R2-NEW-1 | fixed | **FIXED** | 见 (1) |
| R2-NEW-2 | fixed | **PARTLY（残留 = FAIL R3-NEW-1）** | 见 (2) |
| R2-NEW-3 | fixed | **PARTLY（残留 = FAIL R3-NEW-2）** | 见 (3) |
| R2-NEW-4 | fixed | **FIXED** | 见 (4) |
| R2-NEW-5 | disputed（值）/ accepted（形） | **数值争议判实现方胜；形态改进采纳；该项结案** | 见 (5) |
| W-1 | fixed | **FIXED** | `#[derive(Debug, Clone, PartialEq, Eq)]` 回到 FS:875，`AuditRecord`(FS:876-883) 五字段齐；FS:3074-3091 断言 clone/`==`/`{:?}`（缺 derive 就编译不过 ⇒ 防复发是真闸门） |
| W-2 | fixed | **FIXED** | FS:1279-1294 只用 `next.path().symlink_metadata()`，`is_dir/size` 取自链接自身，链接项 `size=0`；全文件已无 `next.metadata()`（FS:1370 是已打开 `File` 的 len，语义正确）。悬空链接不再让整页 NOT_FOUND、root 外目录不再当 oracle；注释与代码一致 |
| W-3 | files fixed / dirs declared | **FIXED(文件)+DECLARED(目录)，声明三处一致** | FS:1956-1974 文件走 `hard_link`+`remove_file`，`AlreadyExists`→`OUTPUT_EXISTS`，unlink 失败先删新名再回 `CAPACITY`（不留两个名字，见 R3-N-3 的残余窗口）；目录分支 FS:1976-1980 显式声明 + MO:119-122 + PD:3340-3342。测试 FS:3094-3125 断到两侧字节，有杀伤力 |
| W-4 | fixed | **FIXED** | FS:1336-1346 `max_bytes == 0` 显式 `PAGE_TOO_LARGE`；测试 FS:3211-3228；探针 PR:738-748 + SC quota:70 冻 `zero_byte_page_refused=true` |
| W-5 | fixed | **PARTLY** | 三个动词确有行（见 (6)），但 root 字段/未知会话/ack 面仍未清偿，且 MO:189 的新断言为假 |
| W-6 | partly-fixed | **判定与实现方一致** | `refuses_link` 现在必 `SYMLINK_ESCAPE`（PR:920-928），删掉 resolve 的链接检查后 `list_rejects_escaping_symlink` 必红（read_dir 打文件链接 → `NOT_FOUND`）；`locked_after_attempts` 改为观测（PR:475-496，我复算=6，与 SC auth:32 冻结值一致；off-by-one 会红）；`post_open_reverify_used` 三码混收未改（PR:314-319）——实现方如实登记为 remaining，**接受** |
| W-7 | open | **准确（不是躲）** | `decide_channel` 仍在探针里（PR:896-918），`CF` 确无 `files` 字段（grep 全量：`CF` 里 `files` 只出现在 `tls.files`），MO:99 仍写 "`files.enabled` 缺省 false"。判为诚实欠账；但 PR:3-8 的总述未加例外（R3-N-2） |
| W-8 | fixed | **PARTLY** | 见 (7)：5 条新覆盖里 4 条有杀伤力，`max_read_handles ≥ max_sessions` 那条**红的是别的规则** ⇒ MO:101"逐条都有单测把它跑红"仍为假（R3-NEW-3 之外最该同批修的一句散文） |
| W-9 | declared+direct test | **FIXED(顺带修出的缺陷是真的)** | 我对质了 `git show af953af`：旧 `open: HashMap<(u64,String), usize>` + `*entry.or_insert(0) += 1` + `live()` 求和 ⇒ 同一路径第二次 acquire 报 2 个活句柄，与自身文档矛盾（实现方的说法成立）。新产品路径唯一调用点是 `read_page` 的配对 acquire/release（FS:1354/1404），无第二处依赖引用计数语义；`HandleRegistry::release` 由"减一"改成 `HashSet::remove`（FS:559-561）在配对使用下等价，**无回归**。FS:3127-3142 直测上限（删掉 FS:544 的 CAPACITY 分支必红）；FS:2703 `peak <= 1` 那句仍是恒真但已在 FS:3129-3132 与 MO:161-163 写明是结构不可达，诚实 |
| W-10 | fixed | **FIXED** | PD:3280-3284 改"已连续暂存"+durability 后移+实际临时物名 `.<目标名>.nexus-part-<16hex>`（与 FS:2117-2142 的 `.` + name + `nexus-part-` + 16 hex 逐字节一致）；PD:3335-3341 的 Red Evidence 口径改写；PD:3314 的"全局 RSS 有配额表"仍绝对（R3-N-4） |
| W-11 | **disposition 清单里没有这一条** | **OPEN（未被处置）** | 见 (8) |
| W-12 | open | **准确（不是躲）** | FS:3231-3255 仍直接测 `std::fs::OpenOptions::create_new`，把 FS:1471 的 `create_new(true)` 改成 `create(true)` 它照样绿；仍 `if !cfg!(unix) { return; }`（FS:3236-3241）；nonce 确实不可注入（FS:2117-2127 取 SystemTime+pid+stream）。实现方给的理由（不可预置确切 `.part` 名）读码成立 ⇒ 判诚实欠账，不判谎报 |

### (1) R2-NEW-1 —— 通过

- `UploadStream.root` 在位（FS:570-577，注释即引 r2 NEW-1），`open_upload_inner` 写入 `root.to_string()`（FS:1480）。
- `commit_upload_inner` 的顺序：`touch` → 取流记录的 root（FS:1683-1689）→ **不一致即 `OUTSIDE_ROOT` 返回（FS:1690-1698）** → `self.root(root)?` → `require_writable()`（FS:1700）→ `require_local_io()`（FS:1701）。r2 要求的 (a)(b) 两条都在。
- **拒绝不吃流**（r2 明查项）：FS:1690-1698 的返回在 `discard_stream`（FS:1744/1751/1757/1775）与任何 `hard_link`/`remove_file` **之前**，只读检查、零 IO。测试 FS:2909-2956 与探针 PR:421-439 都验了"换 root 被拒 → 回原 root 仍能发布"，SC sftp:84-89 冻 `commit_root_redirect_code=OUTSIDE_ROOT`、`commit_after_refusal_recovers=true`。
- **别的地方还信不信调用方给的 root**：逐动词查了流的定位——`stage_chunk`(FS:1539-1543)、`ack_staged`(FS:1633-1636)、`abort_upload`(FS:1797-1801)、`commit`(FS:1684-1687/1703-1706) 一律 `self.session(session)` → `s.streams.get(stream)`，`streams` 是**每会话**的 `BTreeMap`（FS:607），所以跨会话流 id 得到 `NOT_FOUND`，**打不到别人的流**；`next_stream` 全局自增但不复用号。`.part` 路径只从流自己的 `part_path` 取（FS:1762/1789）。结论：无残留信任点。
- NOTE：等值检查成立后，`require_writable`/`require_local_io` 在结构上不可能再拒（流的 root 必然来自一次已过这两道门的 `open_upload`，FS:1441），所以这两道门目前只是纵深防御、**无测试能区分它们的存在**（R3-N-1）。

### (2) R2-NEW-2 —— 部分修复，残留即该条本体（→ R3-NEW-1）

已到位并核过的：`file_queue: VecDeque<(u64, usize)>`（FS:729）、`file_buffered_for`（FS:753-759）、`push_terminal` 返回挤掉清单且 `file_drops += evicted.len()`（FS:771-777）、引擎逐条回冲 `inflight_bytes`（FS:993-1001）、`settle_file` 按会话+只整条+报实际字节（FS:829-843）、`release_session`（FS:848-852）由 `close_session`（FS:1176）与 `sweep_idle`（FS:1198）两处调用、`charge_file` 对未知会话直接 `NOT_FOUND`（FS:1051 + `session()` FS:1211-1215）、`inflight_matches_budget` 自证（FS:1029-1031）、r2 点名冻错的那条断言已改为 `inflight_bytes(s)==0`（FS:2572）。逐条释放路径静态检查（brief 指定的四处）：**流 abort** —— 流从不占预算（`stage_chunk` 不过 `charge_file`）⇒ 无泄漏；**audit 轮转** —— 只动 `audit`/`audit_dropped`（FS:2039-2042）⇒ 无泄漏；**`settle_file` 多给字节** —— `remaining` 只按实际出队的整条扣，返回真值，会话侧 `saturating_sub` ⇒ 无负账、无虚报。

**不成立的是"每一次挤占都回冲"**——见 R3-NEW-1。

### (3) R2-NEW-3 —— 方向对、可观测对、取舍已声明；但锁定仍可被已在册主体永久绕过（→ R3-NEW-2）

到位的：溢出计数达阈值升级为全局窗口（FS:663-667）、`locked` 自身满时也升级而不是无界增长（FS:673-675）、`is_locked` 对**不在 `buckets`** 的主体 fail-closed（FS:645-657）、`global` 终于可观测（FS:695-702，`throttle_overflow`/`throttle_globally_locked` FS:976-983）、测试 FS:3001-3038 + 探针 PR:499-538（小表夹具）与 PR:565-587（**产品尺寸**夹具 1024 桶）双观测，SC auth:48-56 冻两条 true。**可用性取舍确实写在 MO:140-144**（"合法新用户也会被拒"），并且把探针里"淹没之后再开新会话"那一步**移到淹没之前**且注释写明顺序有意（PR:552-554）+ EV:274-277 公开登记这条"修复自己造成的合法红"——这不是偷偷换语义，**接受**。

残留见 R3-NEW-2：全局窗口对"已在 `buckets` 里的主体"故意不生效（FS:654），而 `locked` 的到期项**永不删除**（只有 `forget` 会删，FS:706-710，而它要求一次成功认证）⇒ `locked` 单调长满后，已在册主体每次撞阈值都只走 FS:673-675 那条"升级全局窗口"的分支，而它被 FS:654 豁免 ⇒ **该主体此后永远锁不住**。可达性：默认尺寸 1024 桶 × `lockout_after=5` = 5120 次错口令；本仓自己的小夹具（8×3）24 次即到。且 `record_failure` 此时仍返回 `true`，`authenticate` 因此回 `THROTTLED` 而**下一次调用照样比令牌**——错误码与真实原因不符（r2 N-3 同类）。

### (4) R2-NEW-4 —— 通过

`authenticate` 的顺序是：锁定预检（FS:1091）→ 令牌（FS:1095）→ `succeed`（FS:1118）→ **全局 `max_sessions`（FS:1122）→ 单 peer `max_browser_sessions`（FS:1132-1146，按 `s.source == source` 数）** → 才 `sessions.insert`（FS:1147-1160）：**准入检查确在插入之前**。容量释放：`close_session` `sessions.remove`（FS:1170）、`sweep_idle` 第二遍 `remove`（FS:1197）；测试 FS:3066-3069 断"关掉三个之后能再开"。`FileSession.source` 落账（FS:597-605），`close_session(&mut self, session)` **不再收调用方 source**（FS:1165-1169，r2 N-8 一并清偿），`throttle.forget` 用会话自己的 `(principal, source)`（FS:1177）。其余身份入口逐一看过：所有动词只收 `session: u64`，principal 一律由 `record` 从会话解析（FS:2020-2038），**没有第二处接受调用方身份**。探针 PR:716-736 冻 `session_admission_capped=true`（`accepted == max_browser_sessions` 且码为 CAPACITY，两处都断到具体值）。

一处未声明的信任前提（NOTE R3-N-5）：`max_browser_sessions` 的 key 是 wire 层送来的 `source` 字符串，若那个值将来可被对端影响，单 peer 配额就能靠换 `source` 拼散；G15/G16 都没写这个前提。

### (5) R2-NEW-5 —— **争议判实现方胜**，形态改进采纳，结案

r2 的推算前提是"100 条 4 字节终端消息会把队列挤空"。这句**错**：`settle_terminal(4)` 紧跟着每次成功的 `send_terminal(4)`，第一次挤掉一条 8 字节页之后 `buffered()` 回到 120，而 FS:774 的守卫是 `buffered() + bytes > limit` ⇒ `120 + 4 = 124 ≤ 128`，**整个循环只挤 1 条**；随后整预算发送时队列里还剩 15 条。我的 std-only 复算件逐字实现 FS:771-825 + FS:993-1001 + FS:1004-1006，跑出旧布局：`queued=16, loop_evicted=1, delivered=100, failed=0, squeezed_here=15, terminal_ok=true, pending=0` ⇒ **旧断言 `16==16 && 15>1 && pending==0` 为 true**，EV:205-206 记的 16/15/true 与 r2 所评的代码自洽；r2 由此推论"9/9=77 与本树不自洽"是**误报**，特此更正。

不论谁赢，brief 要判的第二问也成立：**新写法确实让证据不再依赖读者自行推演**。PR:670-698 用一台**全新引擎**灌满（`while eb.send_file_message(sb, 8).is_ok()`，>64 直接 Err）→ 记 `drops_before` → 一次 `send_terminal(limit)` → `squeezed == queued` 且 `pending == 0` 且 `terminal_ok`；SC quota:66 另冻 `messages_queued_before_final_send = 16`。复算件同布局跑出 `queued=16, drops_before=1, squeezed=16, terminal_ok=true, pending=0`、`inflight_released_on_squeeze=true`。这条判据的算术闭合、被冻结值锚定，**结案**（实现方"值不接受、形接受"的处置成立）。

### (6) W-5 的另一半

`abort_upload` 有包装并落一行（FS:1796-1809，成功行用流自己记的 `(root, rel)`，未知流落 `NOT_FOUND` 行）；`close_session` 落一行（FS:1178）；`ack_staged` 的**拒绝**落行（FS:1631-1644）；内部清理改走不记账的 `discard_stream`（FS:1786-1792），`commit` 的拒绝因此**恰好一行**（包装层 FS:1666-1668 是唯一 `record`），我逐条点了 `commit_upload_inner` 的 8 个 return 点，没有第二处记账 ⇒ "一次 commit 拒绝记两行"确已避免。未清偿：`stage_chunk`/`ack_staged` 的行 root 仍传 `""`（FS:1513/1641），**而流现在正记着 root**（FS:577）；`close_session(未知 id)` 整段在 `if let Some` 里 ⇒ 零行（FS:1169-1179），MO:185"漏记在结构上不可发生"仍不严格成立；客户端的 ack（`settle_file` FS:1012）释放预算**完全不记账**。

### (7) W-8 缺杀伤力的那一条

`every_validate_rule_has_a_red_test`（FS:3144-3209）的 5 个 case 全部只断 `unwrap_err().code == CONFIG`，而 `validate()` 是**顺序短路**：case "handles < sessions"（FS:3172-3181：`max_sessions:8, max_read_handles:2, inflight:1024`，`chunk_bytes` 仍是默认 64 KiB）在 FS:179 的 `chunk_bytes > max_inflight_bytes_per_session` 上就先红了。我把 FS:222-227 那段删掉再静态求值这个 case：仍红（同一处 chunk>inflight 短路）⇒ **这条 case 对 `max_read_handles ≥ max_sessions` 零杀伤力**，MO:101 那句"逐条都有单测把它跑红"依旧为假。其余 4 个 case 我逐个做了"删掉对应规则"的推演：都会落到 `Ok` ⇒ `unwrap_err()` panic ⇒ 真会红。反向边界断言（FS:3197-3208，`ack == 信封+条目` 必须放行）有效。修法一行：该 case 把 `chunk_bytes` 压到 ≤ inflight。

### (8) W-11 无处置

`disposition_by_implementer.items` 有 16 条（R2-NEW-1..5 + W-1..6/8/9/10 + W-7/12 的 open），**独缺 W-11**，`accepted_debt_from_notes` 里也没有。读码确认原状未动：引擎内部只有 `read_page` 过账（FS:1406），`list` 页（FS:1242-1303）、`stat`/`mkdir`/`remove`/`rename`/`commit` 的回包、逐片 ack 都不经过 `charge_file`；MO:153-155 把这件事改写成"序列化长度只有调用方知道，由 wire 层经 `send_file_message` 过账"——设计立场可以接受（且 r2 提的"未知会话也能过账"子条已修），但 **G16"每条出站文件类消息出门前过账"在产品侧仍是靠一个不存在的 wire 层自觉**，而这条既没登记为已修也没登记为欠账。判 **OPEN（漏登记）**，不判谎报（因为 MO 的措辞确实改了）。

---

## 三、新缺陷

**R3-NEW-1（FAIL）终端发送被拒时，已经挤掉的消息不回冲会话额度 —— r2 NEW-2 同一条的残留路径。**
`SendBudget::push_terminal`（FS:771-786）在第一个 `if` 里 `drain_file_reserve` 把消息**弹出队列**并 `file_drops += evicted.len()`；若弹完仍放不下（`terminal_buffered + bytes > limit`），FS:778-782 **直接 `return Err`，`evicted` 随返回值一起被丢掉**。唯一消费这个返回值的是 `FileEngine::send_terminal`（FS:993-1001），它用 `push_terminal(bytes)?` 的 `?`，所以**失败时那条回冲循环根本没跑**。后果：被挤掉的整条消息已从预算出队（`file_buffered_for(s)` 少 N 字节），但它自己会话的 `inflight_bytes` 一分不减 ⇒ **G16 写死的自证不变量 `inflight_bytes == budget.file_buffered_for(session)` 永久背离**（FS:1029-1031），且和 r2 NEW-2 第 1 点一样**没有任何 API 能冲回来**（`settle_file` 只会去队列里找已经不存在的条目）。复算件：`limit=128`，`send_terminal(64)` + 8×`send_file_message(8)`，再 `send_terminal(70)` ⇒ `err=true, terminal_drops=1, file_drops=8, inflight=64, file_buffered_for=0, matches=false`。
可达性：`send_terminal` 是公开 API、pty 字节的正门；不是理论路径。**测试面零覆盖**：现有全部 `send_terminal` 调用都成功（探针甚至把 `ssh_messages_dropped == 0` 冻成期望，SC quota:52-54 ⇒ 这条分支按构造永不被执行）。
修法：`push_terminal` 失败前把 `evicted` 一并返回（`Err` 携带清单，或先回冲再报错），或 FS:778-782 之前不弹（改为先算可挤字节再挤）；并加一条"终端发送被拒 ⇒ 会话额度与预算仍相等"的单测 + 一个探针字段。

**R3-NEW-2（FAIL）`locked` 表的到期项从不删除，表满后已在册主体永久锁不住 —— r2 NEW-3 的 fail-open 换到了另一群人身上。**
三处读码合起来：① `is_locked` 的全局窗口分支只对**不在 `buckets`** 的主体生效（FS:653-655）；② `record_failure` 在 `locked.len() >= max_buckets` 时**只设全局窗口，不写该 key**（FS:673-675），并且返回 `true`；③ 到期项**无人清理**——`locked` 只在 `forget`（FS:706-710）里删，而 `forget` 只在 `close_session` 里对**成功认证过**的会话调用（FS:1177），`succeed` 不删 `locked`（FS:684-687），`is_locked` 读到过期项也只是返回 false、不顺手移除（FS:647-649）。
攻击序列（全部用错口令，无需令牌）：把 `buckets` 与 `locked` 都灌到 `max_buckets`（默认 1024×5=5120 次；本仓小夹具 8×3=24 次）→ 等 60 s（`Duration::from_secs(60)` 写死在 FS:933-937，不可配）→ 这批 principal 的 `locked` 项过期，`is_locked` 回 false；此后它们每次撞阈值都落进 ② 的分支，而 ① 把它们豁免 ⇒ **从此不限速、不计窗，正确令牌照样 `Ok(session)`**（FS:1091→1095）。这与 r2 NEW-3 立案的判据（"填满之后正确令牌仍然通过"）是同一条，只是人群从"未在册"换成"已在册且曾被封"。
可观测性也帮不上：`throttle_overflow`/`throttle_globally_locked` 看得见全局窗口，看不见"某个已在册主体的锁定被静默丢弃"；`record_failure` 返回 `true` 让 `authenticate` 回 `THROTTLED`，而下一轮照样比令牌（错误码误导原因）。
修法：`is_locked` 顺手回收到期项（或 `locked` 只存未过期项），并把 ② 改成"驱逐一个到期/最旧的 `locked` 项后写真 `locked`"，而不是升级为对当事人无效的窗口；补一条"填满 `locked` 之后，过期再犯仍被拒"的单测（当前 `throttle_fails_closed_when_the_table_is_full` FS:3001-3038 只验未在册那一群）。

**R3-NEW-3（WARN）G12 的"逐条都有单测把它跑红"仍为一条假话** —— 见 §二(7)。同批应改的是 MO:189"单测逐个动词断言…"：`abort_upload` 在测试里是**裸调用**（FS:2867，没走 `audited!`），`ack_staged`/`idle_recycle` 的行无人断言（`idle_sweep_uses_the_refreshed_field` FS:2731-2759 只断返回的 id），`open_upload` 成功与 `authenticate` 成功仍只断 `back().action`（FS:2848-2849/2795-2796）。删掉 `abort_upload` 的 `record`（FS:1804）**全库不红**——而这正是 W-5 本批新加的记账。

**R3-W-1（WARN）`charge_file` 的回滚只覆盖 CAPACITY 一条早退路径。** FS:1055 先 `push_file`，FS:1056-1058 才 `checked_add`；OVERFLOW 那条 `?` **没有** `unpush_file`（只有 FS:1059-1068 的 CAPACITY 分支回滚）⇒ 造出一条"占共享预算、不占会话额度"的条目，`inflight_matches_budget` 反向背离且无释放路径。当前不可被对端触发（`bytes` 由 wire 层给的序列化长度），但它是 r2 NEW-2 第 3 点的同族形状，一行改：把 `checked_add` 提到 `push_file` 之前。

**R3-W-2（WARN）`Throttle::global` 只增不减，全局窗口因此是"一次性升级、永久待命"。** FS:663-667 里 `global` 从不清零，窗口一过期，**下一次溢出失败（`global` 仍 ≥ 阈值）立刻再设 `global_locked_until`** ⇒ 一次洪水之后，攻击者每 60 s 喂一条伪造失败就能让所有未在册主体无限期认证失败。MO:140-144 声明了"窗口内合法新用户也被拒"，没声明"窗口可被一条失败无限续期"。建议给 `global` 加衰减/固定窗口，或把续期口径写进 G15。

**R3-W-3（WARN）自报期望条数与自己刚写的表格互相不自洽。** EV:249 "E4 场景 9/9 PASS = **80** 条 expectation（上一片 73，本片加严 7）"，而 EV:250-254 的表格（6+10+9+5+9+9+16+7+15）与九份 `[[expect]]` 实测都是 **86**；"上一片 73"也错了一层——第三片自报的总数是 77（EV:180）。r2 上一轮的案头数字（77）我是逐文件数过才写的；这一轮的实现方**有了正确方法却没有用它**。AGENTS 的口径是"自述数字必须能由仓内文件复核"，这条现在复核不过（见 §六）。

**R3-W-4（WARN）`settle_file` 可以越过同会话的队头消息释放后面的消息。** FS:833-840 是"扫全队列，凡本会话且 `≤ remaining` 就释放"，于是 `[(s,12),(s,10)]` 上 `settle_file(s,10)` 释放第二条（复算件：`freed=10, queue=[(1,12)]`）。SCTP 消息按序到达，队头没冲掉时后面的消息不可能已送达 ⇒ 这是"为仍在缓冲里的字节退还预算"，与 FS:721-722/827-828 自己写的"整条 FIFO"矛盾（不致命：真实 `bufferedAmount` 还会兜一层，但账面上少报在途）。修法：遇第一条不匹配即停（对同会话）。

**R3-W-5（WARN）W-11 无处置**（§二(8)）。

**R3-W-6（WARN）探针/文档仍有两处"绝对话说绝对了"**：PR:3-8"每一个字段都取自可观测引擎行为"对 capability-negotiation 的 7 条期望不成立（W-7 已 open，但这句话没改）；MO:99 把 `files.enabled` 缺省 false 写成 enforced 不变量，而配置里根本没有这个字段。PD:3314 的"全局 RSS 有配额表"同样绝对（MO:161-163 已如实说"未验"，两份文档口径不一致）。

---

## 四、测试质量：哪些断言仍然没有杀伤力

**本批确实新增杀伤力的**（逐条做过"删掉被测物会不会红"的推演）：`terminal_class_has_priority_over_file_class`（FS:2501-2540，我逐步复算：10 条 10 字节 + 1 条被拒 + 挤 5 条 ⇒ `file_drops==6`、`evicted.len()==5`、`release_session==40`，每个数字都是真约束；旧实现给 2 ⇒ 红）；`engine_read_page_is_charged_to_the_shared_budget`（FS:2542-2582，把 r2 点名的错误等式改成 `inflight==0` 并断 `inflight_matches_budget`）；`session_teardown_releases_the_shared_budget`（FS:2958-2999，close 与 sweep 两处各断 `budget().buffered()==0`）；`commit_cannot_be_redirected_to_another_root`（FS:2909-2956，含"只读根里 0 个条目"与"拒绝后仍可发布"两半）；`session_quotas_are_admission_checks`（FS:3040-3071，两道配额+释放复用）；`throttle_fails_closed_when_the_table_is_full`（FS:3001-3038，但只覆盖未在册人群，见 R3-NEW-2）；`handle_registry_ceiling_is_reachable`（FS:3127-3142）；`rename_a_file_is_non_overwriting_and_leaves_one_name`（FS:3094-3125）；`audit_records_are_snapshottable`（FS:3073-3091，缺 derive 编译不过）；`zero_byte_page_request_is_refused_not_stalling`；`every_validate_rule_has_a_red_test` 的 4/5 个 case；`throttle_full_fail_closed`/`product_engine_fails_closed_when_flooded`/`teardown_releases_budget`/`messages_queued_before_final_send=16` 这几条新冻期望（回归必红）。

**仍然没有杀伤力 / 无覆盖（逐条，附"改坏什么还绿"）**
1. **失败的终端发送 + 非空文件队列**（R3-NEW-1）——全库零覆盖；探针把 `ssh_messages_dropped == 0` 冻成期望，等于**把这条分支排除在测试面之外**。
2. `locked` 表满后的再犯（R3-NEW-2）——`throttle_fails_closed_when_the_table_is_full` 只验未在册主体；无任何断言覆盖 FS:673-675 的分支。
3. `abort_upload`/`ack_staged`/`idle_recycle` 的审计行（FS:1804/1641/1199）——删掉 `record` 全绿（FS:2867 是裸调用）。
4. `commit_upload_inner` 的 `require_writable`/`require_local_io`（FS:1700-1701）——等值检查在前使它们不可达，删掉任一全绿（R3-N-1）。
5. `max_read_handles ≥ max_sessions`（FS:222-227）——见 §二(7)。
6. `every_verb_is_audited_including_refusals` 里 `open_upload`/`authenticate` 的成功路径仍不是"恰好一行"（FS:2795-2796、2848-2849）；`stat`/`remove` 成功路径无宏断言。
7. 没有任何断言约束 `authenticate` 真用 `constant_time_eq`（FS:1095 换成 `==` 全库仍绿；FS:3257-3267 的诚实声明已在位，属目视项）。
8. `post_open_reverify_used` 三码混收（PR:314-319，实现方已登记 remaining）；`refuses_link` 的另一半已修。
9. 探针 emit 但未被任何场景冻结的字段仍有 46 个（含 `read_page_overflow_code`、`settle_releases_budget_and_inflight`、`inconsistent_limits_rejected`、`interim_codes`、`state_cleared_after_close`、`committed_path`、`second_page_next_offset`、`final_terminal_send_ok`、`pending_messages_after_final_send`）——即 r2 **N-4**，而 `accepted_debt_from_notes` 只登记了 N-1/2/3/5/6/7/8（EV:299 也写"7 条"），**N-4 既不修也不登记**（brief 问"open 是否准确"：这条不准）。
10. 新默认 `max_inflight_bytes_per_session = 128 KiB`（FS:136）与 SC quota:8 `[given] max_inflight_bytes_per_session = 1048576` 仍脱节（r2 N-5，登记为欠账，可接受但读场景的人会拿错数）。

---

## 五、非机器可验、仅评审目视（本树与本宿主都验不了）

1. 时序面：`constant_time_eq` 不提前返回（FS:2144-2154 目视正确；循环长度泄漏 `max(len)`，令牌是配置常量 ⇒ 可接受），以及"认证路径真的调它"。
2. 残余 TOCTOU：父目录在 `resolve` 与 `create_new`/`hard_link`/`hard_link`-发布之间被换成链接。`reverify_parent`/`reverify_ancestor`（FS:2063-2103）与 `reverify`（FS:426-440）在单线程测试里与 `resolve` 不可区分；`SandboxRoot::reverify` 仍返回恒 `Ok(true)` 的 bool（N-1 欠账）。`rename` 文件路径的 `hard_link`→`remove_file(src)` 之间，另一个本地写者把 `src` 换成新 inode，则"改名"复制的是旧内容——单进程无法观测。
3. Windows：`\\?\` 前缀比较（FS:292-302）、大小写不敏感使逐字节比较判非规范（FS:302）、目录符号链接特权、`CREATE_NEW` 对 reparse point、`hard_link` 在 FAT/exFAT 上失败（那会让 W-3 的文件原子路径退化成 `CAPACITY`——**本机无法验证，PD:3323-3327 的 B 级口径以此为前提**）、FS:3236-3241 的 Windows skip。§18.3 B 级仍只站在"(dev,ino) 不可得"这一层。
4. SCTP 真实语义：`bufferedAmount`/`set_sctp_max_buffered_amount` 对称性、"消息不可部分发送"（整个 settle/drain 模型的前提）、终端类零丢失在真实 pty 路径上（`send_terminal` 全仓除 FS/PR 无调用点，wire 层还不存在）。
5. `LIST_ACK_ENVELOPE_BYTES=72 / ENTRY_ACK_OVERHEAD_BYTES=52`（FS:871-872）是对**尚未存在**的 M2 编码的估算；`validate()` 的 ack 下限（FS:196-207）和 `list` 的字节截断（FS:1273-1278）都建立在它上面，M2 换编码必须重测（FS:866-870 已声明）。
6. 耐久性：`sync_all()` 真在发布前落盘（FS:1717-1719）需崩溃/掉电实验；逐片 `flush()` 是空操作是 std 事实。
7. 全局 RSS 上界（PD:3314 列进"都有配额表"）：std 下无计量、无实现。
8. panic-free-by-construction：我目视过非测试代码的算术点——`release_session` 的 `before - file_buffered()`（FS:851，retain 后必 ≤）在 `file_buffered()` 的 `.sum()` 溢出时会连带失守（只有 wire 层给出荒谬 `bytes` 才触发，属可信输入）；`drain_file_reserve` 的 `limit - buffered()`（FS:815）靠 `buffered ≤ limit` 不变量，该不变量在 R3-W-1/OVERFLOW 泄漏路径下可能被破坏后引发下溢。未发现**外部可控输入**可达的 panic；fuzz（PD:3319-3320）未执行。

---

## 六、合并前必须处理（按阻塞序）

1. **R3-NEW-1**：`push_terminal` 失败路径不得丢弃 `evicted`；补"终端被拒 ⇒ 会话额度与预算仍相等"的单测 + 一个探针字段，并且**不要再把 `ssh_messages_dropped == 0` 当覆盖**（它使这条分支按构造不可达）。
2. **R3-NEW-2**：`locked` 到期项回收（或只存未过期项），把 FS:673-675 改成"写真锁定（必要时驱逐一个）"，并补一条"填满 `locked` 后过期再犯仍被拒"的测试；`record_failure` 在此情形不得返回 `true` 让 `authenticate` 谎报 THROTTLED。
3. **W-11 的处置**：要么在引擎内给 `list`/回包/ack 过账，要么把 G16"每条出站文件类消息出门前过账"改成"引擎只对页过账，其余由 wire 层负责（M2 待接线）"，并在 disposition 清单里显式登记——不能留在"12 条 WARN 有 11 条处置"的状态。
4. **证据算术自洽（R3-W-3）**：用 `grep -c '^\[\[expect\]\]'` 由仓内文件复核总数（当前 **86**）并更正 EV:249 的 80/73/+7；把这条复核写进自报口径。
5. **文档话说太满的四句**：MO:101（`max_read_handles ≥ max_sessions` 仍无红测试，§二(7) 一行改 case 即可兑现）、MO:189（`abort_upload`/`ack_staged`/`idle_recycle` 要么进 `audited!` 要么把句子改成"逐动词（除…）"）、PR:3-8（capability-negotiation 例外）、MO:99 的 `files.enabled` 与 PD:3314 的全局 RSS 与 MO:161-163 对齐。
6. **小账**：`stage_chunk`/`ack_staged` 审计行补 root（流已记着它，FS:577）；`close_session(未知 id)` 也要留一行；`charge_file` 的 `checked_add` 提到 `push_file` 之前；`settle_file` 遇同会话第一条不匹配即停；`accepted_debt` 补登记 r2 **N-4**（46 个 emit 未冻字段）与 W-5 的 root 半边。
7. **合入清单**：`.evidence/review-gateway-file-r3/` 两份案卷需按 FILE_MANIFEST 本批新惯例 `git add -f` 携带，并把清单计数（当前 194）随之更正——本评审按约束未代做。
8. r1/r2 的 **F4/F3/F5(代码侧)/G21 记账模式**、r2 W-1/2/3/4/10 的修复与 r2 NEW-1/NEW-4 的接线，本评审复核通过，不再重 litigate；W-7/W-12 的 open 判定准确。

**门禁提示**：EV:300-301 说本分支 pre-commit 第 4 关只认最新 review 目录的 verdict——本目录 verdict 为 **CHANGES_REQUESTED**，故第四片按自己的门禁不应合入；上面 1-2 两条是同级缺陷（都是 r2 原条的残留路径），不建议用"改期望"或"再挪一次探针顺序"绕过。
