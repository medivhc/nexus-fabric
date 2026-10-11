# 独立评审 r2 — 网关文件服务（`feature/gateway-file-service-contracts`，af953af + 未提交工作树）

**VERDICT: CHANGES_REQUESTED** — 6 条 r1 FAIL 中 **F4 / F5 / F3 真已修复**，**F2 的模型已修但它的机器化断言在当前树里算不出 true**，**F1 只接了一半（记账无释放路径）**，并新增 3 条与 r1 同级的缺陷（提交动词绕过权限门、节流表满即 fail-open、会话数无上限）。另：报告数字与本树不自洽。
Reviewer: independent review agent, model `qfmodel` (QoderCN), host Windows（无法编译：`ssh2` cfg 门），**static read only**。所有实测数字（44 单测 / clippy / 9/9=77 / `verify --fast` / contract_hash c534121…）由实现方在 xc-pc-linux 产出，**本评审未复现、也不试图复现**。

引用格式 `file:line`，均为绝对路径下的行号。文件缩写：`FS`=crates/nexus-web-gateway/src/file_service.rs，`PR`=crates/nexus-web-gateway/examples/gateway_file_contract.rs，`MO`=crates/nexus-web-gateway/MODULE.md，`CF`=crates/nexus-web-gateway/src/config.rs，`SC`=scenarios/product，`PD`=PRODUCT.md，`EV`=.agents/green-evidence-gateway-file-service-m1.txt。

---

## 一、r1 六条 FAIL 的逐条复核

### F4（路径截断）— **已修复，未发现残留越界路径**

- `resolve` 对 `NotFound` 改为 `continue`：FS:390-397。缺失分量之后仍逐段 `push`，不再截断。
- 未校验的 `r.canonical.join(rel)` 兜底已全部消失：全文件仅剩测试里**故意的** naive 差分 FS:2118。逐动词核过：`read_page` FS:1212、`list` FS:1115、`stat` FS:1782、`open_upload` FS:1318、`mkdir` FS:1642、`remove` FS:1685、`rename` FS:1756-1757、`commit` FS:1582 全部只用 `resolve` 的返回值。
- 每个动词对"缺失中间层"的后果都验了：`open_upload`/`commit`/`rename` 走 `reverify_parent`（FS:1879-1887，`parent().canonicalize()` 对不存在的路径必回 `NOT_FOUND`）⇒ 静默接受不可能；`mkdir` 走 `reverify_ancestor`（FS:1847-1874，从目标往上找到**最深存在祖先**才判 `ensure_within`）⇒ 仍能一次建出整条链。`remove`/`stat` 的 `symlink_metadata` 直接 `NOT_FOUND`。
- **`reverify_ancestor` 是否削弱符号链接保证：没有。** 它比对的最深存在祖先必然已被 `resolve` 逐段 `lstat` 过（缺失段不可能是链接），且它对找到的祖先额外做了 `is_symlink` 判定 FS:1852-1857 —— 比 `reverify_parent`（只 `canonicalize`+`ensure_within`，不查链接）还强一档。`ensure_within` 用 `Path::starts_with`（按分量），`/root` 不会匹配 `/rootother` FS:412-421。`..`/绝对/`Prefix`（含 `\\?\`、`C:`）一律 `OUTSIDE_ROOT` FS:377-385。`rel=""`/`"."` ⇒ 目标=root ⇒ `reverify_parent` 取到文件系统根 ⇒ `OUTSIDE_ROOT`，拒。
- Windows `\\?\`：`open` 只在**比较**时剥前缀 FS:292-302，存下来的 `canonical` 保留前缀，`resolve`/`reverify*` 全程同形，`ensure_within` 两侧一致。遗留问题见 N-7（测试用不带前缀的 `dir.join()` 比对 `resolve` 输出，Windows 上必不等；Windows 大小写使逐字节比较把 `c:\…` 判为非规范 —— 方向是 fail-closed，可接受）。
- 残余竞态（resolve 与 create 之间父目录被换成链接）确实**声明**了：FS:1894-1900、MO:112-117、PD:3339。

### F1（发送预算从未接线）— **部分修复（FAIL，见 NEW-2）**

接线的**存在性**成立：`FileEngine` 自持 `budget` FS:829/878；`read_page` 出门前过账 FS:1269；`charge_file` FS:948-975、`send_file_message` FS:940-942、`send_terminal` FS:910-912、`settle_file` FS:922-927、`settle_terminal` FS:915-917、`inflight_bytes` FS:930-935；探针里已无 `SendBudget` 构造（全仓 `SendBudget` 只出现在 FS）。`unpush_file` 回滚**正确**：只在 `back()==Some(bytes)` 时弹 FS:748-752，而 `charge_file` 是紧接着 `push_file` 调它 FS:952/961，且 `bytes==0` 在两侧都提前返回 FS:732/949 —— 不会弹错、不会重复弹。

**不成立的是"不漏"**：
1. **被挤掉的消息永不回冲会话额度。** `drain_file_reserve` 只弹 `file_queue` FS:756-769，`SendBudget` 没有会话归属信息（FS:680-690），所以 `push_terminal` 挤掉页时（FS:719）该会话的 `inflight_bytes` 一分不减。单测把这份错账冻成了期望：FS:2335-2341 两条 64 字节页都被挤掉后仍断言 `inflight_bytes(s)==64`。该会话此后只能靠"ack 一份自己从未收到的页"恢复 ⇒ 永久 `CAPACITY`。
2. **会话拆除不冲共享预算。** `close_session` FS:1037-1044 与 `sweep_idle` FS:1047-1066 把 `FileSession`（连同 `inflight_bytes`）整个丢掉，但从不调 `budget.settle_file` ⇒ `file_queue` 里那些条目的字节**永久**占着 128 KiB 预算。攻击面只要一个合法令牌：认证→`read_page` 两页→关会话/闲置，两轮即把**全节点**文件类发送预算钉死，之后任何会话的 `read_page` 永远 `QUEUE_FULL`，且无任何 API 能清（`settle_file` 需要知道每条消息的序列化长度，而引擎没告诉调用方）。这正是 r1 F1 的同一类缺陷（预算在、释放不在）。
3. **绕过面：只有 `read_page` 过账。** `list`（FS:1105-1168）、`stat`、`commit`、`mkdir/remove/rename` 的结果都不碰预算；MO:138-140 的口径是"**每条**出站文件类消息过账"。当前只有 wire 层自觉调 `send_file_message` 才成立，引擎结构上不强制 —— 而 wire 层还不存在（全仓只有 FS/PR/lib.rs 引用 `FileEngine`）。另外 `send_file_message` 对不存在的 session 会**只进共享预算、不进会话额度**（FS:954/971 都在 `if let Some` 里），又是一个无结算路径的入口。

### F2（丢弃计数）— **模型已修，其机器化断言在本树算不出 true（FAIL）**

模型本身诚实，三条都核过：队列是 `VecDeque<usize>` 每条消息一项 FS:685；`drain_file_reserve` 整条 FIFO 弹、按**条数**计 FS:756-769（`usize::from(freed>0)` 已无）；`settle_file` 只在 `front <= remaining` 时弹 ⇒ **不可能部分冲刷** FS:772-782；`invariant buffered ≤ limit` 成立，故 `self.limit - self.buffered()` FS:757 不会下溢。单测 FS:2285-2309 有真实杀伤力（旧实现给 2，新断言要 6）。

**但 E4 那一条不能成立。** `PR:576-591`：
- `file_accepted`=16（`send_file_message(s,8)` 在 buffered=128 处 `QUEUE_FULL`，`file_drops`=1）；
- 随后 100× `send_terminal(4)`+`settle_terminal(4)`（PR:562-568），每次 `drain_file_reserve(4)` 的 `need=4-0=4`，弹**一条** 8 字节消息 ⇒ 第 16 次迭代队列已空，`file_drops`=17；
- 于是 PR:577 的整预算终端发送 `send_terminal(128)`：`buffered()=0`，`0+128>128` 为假 ⇒ **一条都不挤**，`squeezed_here`（PR:578）=**0**；
- `squeeze_accounting_is_per_message` = `16==16 && 0>1 && pending==0` = **false**（PR:585-591）。
而 `SC/gateway_file_quota_backpressure.toml:42-44` 冻结的是 `equals = true`。EV:205-206 记录的 `final_send_squeezed_messages=15` 在这段代码里**取不到任何值**（`file_messages_squeezed_out=16` 反倒与我的推算一致，说明推算路径对）。⇒ 要么本树场景红，要么 EV 第三片的数字不是这棵树跑出来的。两种情形都必须由实现方**重跑并如实更正**；在澄清之前，"F2 已机器化"这条不能算过。EV:206 的解释（"另加一次整预算终端发送才把队列清空"）与代码不符：队列在前面的循环里就已经清空了。

### F3（`mutation_capability_of_sftp_backend` 常量回读）— **已修复**

把 `BackendKind::Sftp::allows_mutation()` 翻成 `true` 后，三条独立变红：`mutation_capability_of_sftp_backend`→true（PR:404-407，SC sftp:63-65）、`refusal_code`→`NOT_FOUND`（PR:381-385，SC sftp:40-42）、`sftp_refusal_gate`→`"OTHER"`（PR:412-418 要求消息含 `non-overwriting`；翻转后 `require_writable` FS:443-454 放行，`open_upload_inner` FS:1319 的 `reverify_parent` 对本地不存在的 `/home/user/files` 回 `NOT_FOUND`，消息里没有那两个字）。注意 `open_upload` **不**调 `require_local_io`，所以实现方"下一道 `require_local_io` 仍然回 UNSUPPORTED"的说法（PR:408-411、EV:212-214）不成立 —— 真正让它变红的是 `reverify_parent`/`refusal_code`，结论仍成立但理由要改。脆弱点：`sftp_refusal_gate` 靠错误消息子串判定（N-6）。`sftp_list_supported`（PR:398-401）单独看杀不掉删 `require_local_io` 的变异（远端路径 read_dir 失败仍是 `is_ok()==false`），但单测 FS:2042-2049 断言了码，故覆盖存在。

### F5（`.part` 创建 TOCTOU）— **代码与文档已修，测试不咬产品路径（W-12）**

`create_new(true)` 在位 FS:1331-1336；POSIX 下 `O_CREAT|O_EXCL` 遇符号链接回 `ELOOP/EEXIST` 而不跟随，Windows `CREATE_NEW` 对 reparse point 同样失败，声明与残余窗口写进 FS:1894-1900、MO:112-117、PD:3327/3339。两点不满：(a) 新测试 FS:2671-2695 直接测 `std::fs::OpenOptions`，**不经 `open_upload`**，把 `create_new(true)` 改成 `create(true)` 它照样绿；(b) 它在 Windows 上直接 `return`（FS:2676-2681），而它锁的正是 §18.3 B 级口径里那句"`create_new` 等价物"的平台前提。附带：预置链接被拒时报的是 `CAPACITY_UNAVAILABLE`（FS:1336）而不是 `SYMLINK_ESCAPE`，审计行也跟着记成容量问题（N-3）。

### G21（审计/记录）— **包装层方向对了，但仍有零记录动词、principal/root 不全，且 `AuditRecord` 的 derive 被写进注释里丢了（W-1 / W-5）**

七个动词确有唯一出口（`read_page`/`list`/`stat`/`mkdir`/`remove`/`rename`/`open_upload`/`commit` 的 `*_inner`+包装：FS:1090-1103、1176-1190、1280-1293、1506-1525、1626-1633、1660-1673、1742-1750、1768-1776），逐片成功只在 `Err` 记 FS:1365-1378，`record` 是 `VecDeque` 环 + `audit_dropped` FS:1804-1835/823-824/890-894，容量 8192 FS:793。**零记录**：`abort_upload`（FS:1618-1624，客户端可发起、且**删除已暂存字节**的破坏性动词）、`ack_staged`（FS:1492-1499）、`close_session`（FS:1037-1044）。MO:160 说"审计行由动作的统一出口落账，漏记在结构上不可发生" —— 包装模式没覆盖这三个入口，所以该句当前为假。**两条记录**：未发现（`*_inner` 内无 `record` 调用，已 grep 全量 FS:993-1773 核对）。principal 真实：调用点传空串时从会话解析 FS:1813-1822，`sweep_idle` 用 `s.principal` FS:1062，`authenticate` 显式传 FS:993/998/1033 ⇒ 除"session 不存在"（无从归因）外都能归因。root 字段：`stage_chunk`(FS:1375)、`authenticate`(FS:993 等)、`idle_recycle`(FS:1062) 都传 `""`，其中 `stage_chunk` 的 root 本可从流推出（流的 root 没被记录，见 NEW-1 / W-5）⇒ G21 五字段中 root 在这三个动作上缺失。

### 其他声称的修复

| 声称 | 结论 | 依据 |
|---|---|---|
| `validate` 新增 `max_ack_bytes ≥ 信封+条目` 下限 | 代码在位（FS:196-207），**零测试覆盖** | 无任何测试/探针把 ack 预算压到 <124；MO:101 声称"逐条都有单测把它跑红"为假（W-8） |
| `×64` 魔数换成 `inflight ≤ buffered`，默认 1 MiB→128 KiB | **已修** | FS:210-219、FS:136；单测 FS:2001-2006 能跑红；`SC/gateway_file_quota_backpressure.toml:8` 的 `[given] max_inflight_bytes_per_session=1048576` 已与代码默认值脱节（散文侧漂移，N-5） |
| `list` 按序列化字节截断 | 代码在位 FS:1136-1141，**零测试** | 名字长度/预算截断路径无单测、无场景；两个成本常数 FS:801-802 从未被断言 |
| 恰好 `cap` 条不再谎报 truncated | **已修**（逐循环推演：第 cap 条入列后 `rd.next()` 回 `None` ⇒ `break`，`truncated` 保持 false，FS:1124-1161），**零测试** | 单测 FS:2469-2491 用 5 条/cap=2，测不到这条修复 |
| `commit_upload` 发布前 `sync_all()` | 代码在位 FS:1551-1553；逐片 `flush()` 是空操作的说明在 FS:574-578、MO G18 | PD:3280 仍对用户承诺"已连续**落盘**"，与本批修复口径矛盾（WARN-10） |
| `max_rehash_bytes_per_stream` 不再门控增量摘要 | **已修且有杀伤力** | FS:1431-1435 顺序字节无条件进摘要；预算只管重放回读 FS:1451-1466；`digest_complete` 现在恒为 `hashed_bytes >= staged` FS:1554；单测 FS:2167-2203（48>16 仍能带摘要发布，第 3 次回读 `CAPACITY`）能杀掉旧行为 |
| `config.rs` 上界 `MAX_TERMINALS_CEILING=64` | **已修，测试质量合格** | CF:19/269-273；CF:348-357 同时断言 `+1` 被拒**且上界本身可用**（有边界杀伤力，不是装饰） |

---

## 二、新增缺陷

**NEW-1（FAIL）`commit_upload` 不检查 root 可写/后端，且流不绑定授权 root ⇒ 可读根与 SFTP 根都能被发布。**
`FS:1527-1536`：`commit_upload_inner` 只做 `touch`+`self.root(root)`，**没有** `require_writable()` 也没有 `require_local_io()`（全量核对：`require_writable` 只出现在 FS:1304/1638/1684/1755，`require_local_io` 只在 FS:1114/1211/1781）。而 `UploadStream` 不记 root（FS:570-589 字段里没有 root），所以 `commit_upload(session, root, stream, _)` 的 `root` 是调用方**当场任意指定**的。后果两条：
1. 客户端在**可写根**上传，然后以 `root = 只读根` 提交 ⇒ 文件落进配置为 `read_only` 的导出目录（`resolve`/`reverify_parent` 都放行，`hard_link` FS:1596 只在 OS 层受权限约束，而 `read_only` 是**应用层**开关，OS 不会拒）。违反 MO G13/PD:3292"仅在 root 可写时提供写"。
2. 客户端以 `root = SFTP 根` 提交 ⇒ 远端 POSIX 路径被丢给**本地**解析并 `hard_link`。`/home/user/files` 在节点本地存在时（很常见）会直接写出一个本地文件，正是 G14/PD:3305-3308 立此存照要防的"把远端路径交给本地解析器"；不存在的才回 `NOT_FOUND`。
测试面：`FS:2030-2039` 与 `PR:377-397` 都只测 `open_upload/mkdir/remove/rename`，**从未用另一个 root 去 commit** ⇒ 无一条断言能变红。这条与 r1 F3/F4 同级：契约承诺的门在动词接线处漏了。

**NEW-2（FAIL）预算/额度释放模型不完整** — 见 F1 三点（`FS:756-769`/`719`、`FS:1037-1044`/`1047-1066` 无 settle、`FS:954/971` 对未知 session 只进共享预算）。这不是理论问题：`PR:617-623` 自己把 `inflight_bytes(s)==budget().file_buffered()` 当成"释放正确"的判据，而 `FS:2335-2341` 已经演示了任何一次挤占都会让这个等式两边永久背离。修法必须给 `SendBudget` 加会话归属（或让引擎在拆除/挤占时按已知长度冲回），否则 G16 MO:138-140 的"对端 ack 才同时释放两者"在有淘汰/有断线的真实路径上不成立。

**NEW-3（FAIL）节流表满即 fail-open，锁定门被伪造量绕过。**
`FS:638-651`：表满时新键只累加私有 `global`，返回 `global >= lockout_after`，但**从不写 `self.locked`**；`is_locked` 只读 `locked` FS:629-635。`authenticate` FS:992-996 的顺序是"先查 `is_locked`，未锁则照样比对令牌"。于是攻击者只要先把表填满（1024 个不同 principal，每个一次错口令即可，`PR:472-474` 就是这段），此后**任意新 principal/新源**的失败只影响错误码字符串，令牌比对持续进行 ⇒ 锁定窗口对溢出人群完全不存在，正确令牌仍然 `Ok(session)`。MO:131-132 同时承诺"两层键节流**并锁定**"与"表项有界"，代码用前者换后者且未声明；`global` 连访问器都没有（`Throttle::buckets()` FS:658-660 只回 `len`），所以探针 `throttle_entries_bounded`（`PR:476-479`）只验了内存有界，验不出锁定已失效。fail-closed 的正解是表满时对新桶直接拒绝（或 LRU 驱逐并写 `locked`），并把 `global` 暴露成可观测计数。

**NEW-4（FAIL）并发会话数没有任何上限。**
`authenticate` FS:1020-1032 无条件 `self.sessions.insert(...)`；`max_sessions`/`max_browser_sessions` 全生命周期只出现在 `validate()` 的交叉比较里（FS:98/100/130/131/153/154/165/222），**从不参与准入**。MO:134-136 与 PD:3312 都把"并发会话数"列为有配额表的上界。持有令牌的一个浏览器即可无限量开会话（每会话可再开无限流、每流一个 `.part` 文件），闲置清扫只限**寿命**不限**数量**（FS:1047-1066）。`authenticate` 已经拿到 `source`，按 source 计数就能实现 `max_browser_sessions`。

**NEW-5（FAIL）F2 的机器化断言在本树算不出 true，与冻结期望和自报证据互相矛盾。**
详见第一节 F2：`PR:576-591` 静态求值得 `squeezed_here = 0` ⇒ `squeeze_accounting_is_per_message = false`，而 `SC/gateway_file_quota_backpressure.toml:42-44` 冻结 `equals = true`，`EV:205-206` 记录的是 `final_send_squeezed_messages = 15`（该表达式在本文代码上取不到 15）。⇒ "9/9 场景 = 77 条期望 PASS"与这棵树不自洽。这是**证据级** FAIL：F2 的模型改对了，但它声称的机器化闸门当前是红的（或数字来自另一棵树），必须重跑并按 AGENTS.md 的口径如实更正，不允许"改期望"。

**W-1（WARN）`AuditRecord` 的 `#[derive(Debug, Clone, PartialEq, Eq)]` 被写进了 `///` 文档注释里，四个 derive 全部静默消失。**
`FS:804`：`/// One audit line (G21): refusals are recorded too.#[derive(Debug, Clone, PartialEq, Eq)]` —— `#[derive]` 落在注释文本内，因此 `FS:805` 的 `pub struct AuditRecord` **没有** `Debug/Clone/PartialEq/Eq`。今天能编译，只是因为现有测试只读字段（`FS:2542/2558`），没有 `{:?}`/`==`/`clone()`。后果：公开的审计记录类型不能被 wire 层快照（`Clone`）或断言（`PartialEq`），而 `FileEngine::audit()` 返回的 `&VecDeque<AuditRecord>`（FS:886-888）无法被 M2 异步日志取走。这是本批 G21 重构引入的静默 API 回归，也侧面说明该文件改完后没有被通读。一行修复。

**W-2（WARN）`list` 跟随符号链接，且与自己的注释矛盾。**
`FS:1142-1144` 用 `next.metadata()`（跟随链接），`FS:1145-1148` 才用 `symlink_metadata`。三个后果：(a) 一个**悬空**链接就让 `metadata()` 报错 ⇒ 整个目录页以 `NOT_FOUND` 失败（本地用户放一个坏链接即可让该目录不可浏览，并让审计留下一条假阴性拒绝）；(b) `is_dir` 取自**链接目标**（可能在 root 外，FS:1157）⇒ 一个 root 外目录的存在性被当 oracle 回给客户端（`size` 已经对链接置 0，FS:1158，说明作者本意是不泄漏）；(c) `FS:1150-1152` 的注释"never traversed"当前为假。修法：只用 `link`（`symlink_metadata`）填 `is_dir/size`。

**W-3（WARN）`rename` 的"不覆盖"是 check-then-act，POSIX 下可被并发覆盖，且未声明。**
`FS:1760-1763` 先 `dst.exists()` 再 `std::fs::rename`。`rename(2)` 语义是**静默替换**目标，所以两个会话之间（或会话与本地写者之间）的窗口里目标出现 ⇒ 原字节被覆盖，违反 MO:118"目标已存在 ⇒ `OUTPUT_EXISTS` 且原字节一字未动"。对比：`commit` 用了原子的 `hard_link`（FS:1594-1596）并显式讨论了这个区别，`rename` 处一句都没写。std-only 下目录改名拿不到无覆盖原语（`hard_link` 对目录失败），所以要么实现"文件走 hard_link+unlink、目录显式声明窗口"，要么把窗口写进 G13/G14 与 §18.4。

**W-4（WARN）`read_page` 的 `max_bytes=0` 破坏 `next_offset` 单调。**
`FS:1240-1248/1263-1275`：`want=0` ⇒ 空页、`next_offset == offset`、`eof=false`（只要 offset<len）。MO:142 要求 `next_offset` 单调。`validate()` 只保证 `chunk_bytes != 0` FS:150，没保证请求 `>0`。

**W-5（WARN）G21 仍有零记录动词，root 字段在三个动作上为空。** 见第一节 G21 段：`abort_upload` FS:1618-1624（客户端可发起、删除已暂存字节）、`ack_staged` FS:1492-1499、`close_session` FS:1037-1044 均无包装层；`stage_chunk`/`authenticate`/`idle_recycle` 的 root 传 `""`（FS:1375/993/1062）。MO:160 的"漏记在结构上不可发生"当前为假。

**W-6（WARN）探针四条字段无杀伤力（名称强于断言）。** `refuses_link` 只判 `is_err()`（PR:763-765）⇒ `list_rejects_escaping_symlink`/`write_rejects_escaping_symlink`（PR:260-275，SC sandbox:22-32 冻为 true）在删掉 `resolve` 符号链接检查后仍绿；`post_open_reverify_used` 三码混收（PR:313-319）删掉 `FS:1589` 仍绿；`locked_after_attempts` 是 `lockout_after+1` 的常量回读（PR:455-457）。详见第三节 1、2 条。

**W-7（WARN）`capability-negotiation` 整案自证：G19 在产品侧没有任何代码。** `decide_channel` 定义在探针里（PR:739-761），`CF` 的 `GatewayConfig` 无 `files` 字段（未知字段被 serde 静默丢弃），所以该场景的 8 条期望与产品代码零耦合 —— 与 r1 F1"证明的是模型不是产品路径"同类。MO:99 的"`files.enabled` 缺省 false"、G12 的"配置不自洽即拒启动"在 `config.rs` 里都不存在。

**W-8（WARN）`validate()` 五条新/改交叉约束零测试覆盖，MO:101 的"逐条都有单测把它跑红"为假。** 见第三节第 7 条（FS:179-184、187-192、196-207、222-227、150-164）。本批声称的"ack 下限"修复完全无覆盖。

**W-9（WARN）读句柄配额结构不可达，G16 的句柄防线是意外成立。** `acquire`/`release` 在一次同步调用内配对（FS:1217/1267 及全部错误路径），`live()` 恒 0、`peak()` 恒 1 ⇒ FS:538-547 的 `CAPACITY` 分支、`max_read_handles` 配置、单测 FS:2463-2465、探针 `peak_read_handles_within_budget`（PR:673-681，SC quota:59-62）全部是恒真式。M2 改流式读时这道墙会同步消失。

**W-10（WARN）PRODUCT.md 三处口径已被本批修复作废。** PD:3280 仍承诺 ack = "已连续**落盘**"（MODULE.md G18 本批已改为"已连续暂存"，两份权威文档互斥）；PD:3282 仍写临时物名 `.nexus-part.*`（实际是 `.<name>.nexus-part-<hex>`，FS:1912-1924）；PD:3333 仍写"本节的场景当前状态是 **Red Evidence**"，与本批"9/9 绿"的自述矛盾。

**W-11（WARN）预算只覆盖 `read_page`，G16"每条出站文件类消息过账"结构上不成立。** `list` 页、`commit`/`stat`/`mkdir` 的回包、逐片 ack 都不经过 `charge_file`；引擎也允许对不存在的 session 过账（FS:954/971 的 `if let Some`），产生无归属、无释放路径的预算条目。见第一节 F1 第 3 点。

**W-12（WARN）`part_creation_refuses_a_preplanted_symlink` 不经过引擎。** FS:2671-2695 直接测 `std::fs::OpenOptions::create_new`，把 `FS:1334` 的 `create_new(true)` 改成 `create(true)` 该测试仍绿；且它在 Windows 上直接 `return`（FS:2676-2681），而 PD:3327 的 B 级口径正是靠"`create_new` 等价物"这句平台前提撑着。建议：加一条以固定 nonce（需要把 nonce 生成抽成可注入）或直接以已存在同名文件驱动 `open_upload` 的引擎级测试，并在 EV 里写明 Windows 未验。

### NOTE（信息性，不阻塞）

- **N-1** `SandboxRoot::reverify` 返回 `FileResult<bool>` 且成功分支恒 `Ok(true)`（FS:426-440），调用方只 match `Err`（FS:1229）⇒ 那个 bool 是死值；MO:116 / PD:3303 的"TOCTOU **快照类型化**"在代码里没有对应类型（没有 pre-op 快照，只有事后重解析）。
- **N-2** FS:1657-1659 的注释引用了一个不存在的函数 `remove_all_in_root`（实际是 `remove_tree` FS:1712）。
- **N-3** FS:1331-1336：预置 `.part` 名字/链接的拒绝被报为 `CAPACITY_UNAVAILABLE`，审计行同样记容量码；`SYMLINK_ESCAPE`/`EXISTS` 才是可归因的码。
- **N-4** 探针 emit 但场景未冻的字段（其中两条是本批 F1/F2 的证据）：`read_page_overflow_code` PR:614、`settle_releases_budget_and_inflight` PR:617-623、`inconsistent_limits_rejected` PR:527-530、`interim_codes` PR:453、`state_cleared_after_close` PR:487-490、`file_messages_squeezed_out`/`final_send_squeezed_messages` PR:581/583、`committed_path` PR:200、`second_page_next_offset` PR:109。回归不会红。
- **N-5** `SC/gateway_file_quota_backpressure.toml:8` 的 `[given] max_inflight_bytes_per_session = 1048576` 与本批把默认值改成 128 KiB 的决定已脱节（散文侧漂移，不影响判定）。
- **N-6** `sftp_refusal_gate`（PR:412-418）与 `FS:443-454` 的措辞子串耦合：改写错误消息会把它变成 `OTHER` 而变红（失败方向安全，但很脆，且不是错误码级别的判定）。
- **N-7** Windows 路径形状：`resolve` 返回 `\\?\` 前缀形而 `SandboxRoot::open` 接受无前缀拼写，测试 FS:2384-2389 拿 `dir.join(...)`（无前缀）比对 ⇒ Windows 上必不等；Windows 大小写不敏感使 FS:302 的逐字节比较把 `c:\Uploads` 判为非规范（fail-closed 方向，但 B 级平台会误拒）。
- **N-8** `close_session(sid, source)` 用调用方给的 source 去 `throttle.forget`（FS:1042）⇒ 会话没记住自己的 source，清理是否命中取决于调用方传对；`SendBudget::terminal_delivered` 在**接受**时自增而非实际送达（FS:727），字段名与语义不符。



---

## 三、测试质量评估

**有真实杀伤力的重写**
- `every_verb_is_audited_including_refusals`（FS:2523-2668）：`audited!` 宏 FS:2532-2548 断言"恰好一行 + action + 码 + principal 非空"。删掉任一个包装层的 `record` ⇒ `len != before+1` **必红**；同一动词记两行 ⇒ 也必红。r1 的"删 record 仍绿"这条**已清偿**。环有界与溢出可观测也真在断言（FS:2660-2666，`AUDIT_CAPACITY` 直接引用常量，不是抄数）。
- `constant_time_eq_distinguishes_lengths_and_prefixes`（FS:2697-2707）：四条断言能杀"只比前缀"/"只比首字节"/"只比 min(len)"三类变异；对"逐字节提前 return"它**明确声明杀不掉**并把它登记为评审目视项（FS:2703-2706）—— 这是诚实口径，不是回避。仍是装饰的部分：没有任何断言约束 `authenticate` 真的用 `constant_time_eq`（FS:996 换成 `==` 后全库仍绿）。
- F4 两条（FS:2376-2403、FS:2405-2436）：前者断言 `resolve("a/b/c")` 的**全路径**并额外测"缺失之后已存在分量仍查链接"（`a/escape/deep` ⇒ SYMLINK_ESCAPE）；后者断言 `NOT_FOUND` + `a/` 根本没被创建 + 无 `.` 开头残留 + `mkdir a/b` 后同路径可发布。旧实现两条都必红。
- 预算三条（FS:2311-2374）：`QUEUE_FULL`、终端优先的 6 条计数、`settle_file(4)` 不部分冲刷、宽裕预算下单独把 per-session 上限跑红 —— 都有杀伤力。**但 FS:2341 把 NEW-2 的错误等式冻成了期望**（两条页已被挤掉仍记 64 在途），这条断言现在锁住的是缺陷。
- `rehash_budget_…`（FS:2167-2203）、`oversized_max_terminals_rejected`（CF:348-357）、`sftp_backend_…`（FS:2016-2065）：码与路径都断到具体值，能杀。

**仍是装饰 / 杀不掉明显变异的断言（逐条）**
1. `refuses_link` 只看 `is_err()`（PR:763-765），被用于 `list_rejects_escaping_symlink`/`write_rejects_escaping_symlink`（PR:260-275）。把 `resolve` 的符号链接检查删掉后：`list("escape")` 走 `read_dir(链接→文件)` 失败、`mkdir("escape")` 走 `create_dir_all` 失败 ⇒ 两个字段**仍然 true**。SC sandbox:22-32 把它们冻成 `equals=true`，于是这两条 E4 断言对 G13 无保护力。（`read`/`remove` 两条能杀，因为删检查后会 `Ok`。）
2. `post_open_reverify_used` 接受三种码（PR:313-319）：删掉 `commit` 里的 `reverify_parent`（FS:1589）后，`resolve("sub/x.bin")` 在 `sub` 已变链接时回 SYMLINK_ESCAPE ⇒ **字段仍 true**。字段名承诺"用到了打开后复核"，实际证明的是 `resolve`。同理 `SandboxRoot::reverify`（FS:426-440，`read_page` FS:1229 的事后复核）在当前单测+探针里**没有任何一条**能区分它与 `resolve` 的前置检查（进程内没有并发换链），且它返回恒 `true` 的 `bool`、Ok 值无人消费（FS:1229 只 match `Err`）—— MO:116/PD:3303 的"TOCTOU **快照类型化**"在代码里没有对应类型。
3. `FS:2610-2611` 用裸调用+只看 `action` 覆盖 `open_upload` 成功路径（不是"恰好一行"），`commit`/`remove`/`stat` 只断言了**拒绝**码，`stat` 成功、`remove` 成功、`list` 成功只有 list 一条走宏。把 `record` 的 Ok 分支删掉只会红 list 一项。
4. `part_creation_refuses_a_preplanted_symlink` 不碰引擎（FS:2671-2695），见 F5。
5. `every_verb_is_audited_…` 里 `e.abort_upload(s, id)`（FS:2629）是**裸调用**，宏没用它 ⇒ 测试名"every verb"与 NEW-4/`ack_staged`/`close_session` 的零记录并存。
6. 句柄断言是恒真式：`read_page` 在返回前必 `release`（FS:1267，全部错误路径也 release），所以 `live()` 恒 0、`peak()` 恒 1；单测自己承认（FS:2465 `peak <= 1`），探针的 `peak_read_handles_within_budget`（PR:673-681，SC quota:59-62）与 `max_read_handles` 配额 FS:538-547 的 `CAPACITY` 分支**在结构上不可达**。G16"同一流的分片不得各自新开句柄"当前是靠"读是同步的"意外成立，不是靠注册表；M2 改成流式读时这条防线会同时失效，需要重新接线（记入第四节）。
7. `validate()` 八条被 MO:101 承诺"逐条都有单测把它跑红"，实测只有 3 条有测试：`chunk ≤ buffered`（FS:1996-2000）、`browser ≤ sessions`（FS:2007-2011）、`inflight ≤ buffered`（FS:2001-2006）。**无测试**：`chunk ≤ inflight`（FS:179-184）、`max_ack ≤ buffered`（FS:187-192）、`max_ack ≥ 信封+条目`（FS:196-207，本批新增的修复）、`read_handles ≥ sessions`（FS:222-227）、"任一上限不得为 0"（FS:150-164）。删掉这五条任一，44 条单测与 9 条场景全绿。
8. list 的两条修复（字节截断、恰好 cap 不谎报）零覆盖，见上表；`LIST_ACK_ENVELOPE_BYTES`/`ENTRY_ACK_OVERHEAD_BYTES`（FS:801-802）从未被任何断言与真实序列化输出对表，而 FS:796-800 的注释恰恰说这两个数取自"探针实际 JSON 形状" —— 探针里没有这段 JSON。
9. 探针 emit 但场景未冻的关键字段：`read_page_overflow_code`（PR:614）、`settle_releases_budget_and_inflight`（PR:617-623）、`inconsistent_limits_rejected`（PR:527-530）、`interim_codes`（PR:453）、`state_cleared_after_close`（PR:487-490）、`file_messages_squeezed_out`/`final_send_squeezed_messages`（PR:581/583）、`second_page_next_offset`（PR:109）、`committed_path`（PR:200）。EV:207-209 引为 F1 证据的后两条**不在 77 条期望里**，回归了也不会红。
10. `capability_negotiation` 整个案例测的是探针自己写的 `decide_channel`（PR:739-761），产品侧不存在这段逻辑：`CF` 的 `GatewayConfig` 根本没有 `files` 字段（`SC/gateway_file_capability_negotiation.toml` 的 8 条期望因此与产品代码零耦合，改坏 `config.rs`/未来的 wire 都不会让它红）。这是 r1 F1"证明的是模型不是产品路径"的同类残留，而 `PR:3-8` 的总述"每一个字段都取自可观测引擎行为"对这条与 `mutation_capability_of_sftp_backend`/`locked_after_attempts`（PR:455-457，是 `lockout_after+1` 的常量回读）不成立。

---

## 四、非机器可验、仅评审目视（本树与本平台都验不了）

1. **常数时间的时序面**：`constant_time_eq` 的"不提前返回"只能靠目视（FS:1929-1938 实现正确；循环长度泄漏 `max(len)`，令牌长度是配置常量，可接受）。测试自己也这么声明（FS:2703-2706）。
2. **残余 TOCTOU 窗口的真实大小**：父目录在 `resolve` 与 `create_new`/`hard_link` 之间被换成链接，进程内无并发换链就无法观测；PD:3339 已把它列为"不得当作已证"的第③点。`reverify_parent` 的事前/事后两次检查在单线程测试里与 `resolve` 无法区分（见三.2）。
3. **`\\?\` 前缀、Windows 大小写与 UNC root**：本主机不能编译（`ssh2` cfg 门），`FS:292-302` 的剥前缀比较、`FS:2104-2105` 的 `symlink_file` 路径、`FS:2676-2681` 的 Windows 跳过都未被执行过；§18.3 B 级口径目前仍只站在"(`dev`,`ino`) 不可得"这一层（EV:228-231 自己标为待核）。
4. **SCTP 真实语义**：`bufferedAmount` 与 `set_sctp_max_buffered_amount` 的对称性（PD:3336-3338 ①）、"消息不可部分发送"这条 F2 模型的物理前提，本层拿不到；`LIST_ACK_ENVELOPE_BYTES=72/ENTRY=52` 是对**尚未存在**的 M2 编码的估算（FS:795-802）。
5. **耐久性**：`sync_all()` 是否真在 publish 前落盘（FS:1551）需要崩溃/掉电实验；逐片 `flush()` 是空操作是 std 事实，不是测试事实。
6. **终端类零丢失**：`send_terminal` 只活在模型里，`gateway.rs`/`ssh_client.rs` 没有任何调用点（全仓 `FileEngine` 引用只有 FS/PR/lib.rs），所以 MO:140"终端（pty）字节流优先且零丢失"在真实 pty 路径上未接线。
7. **全局 RSS 上界**（MO:136 列在"都有上界"里）：std 下无计量，代码里无任何实现或声明。
8. **panic-free-by-construction**：我逐处目视了非测试代码的潜在 panic 点（FS:1913 `&d[..8]`、FS:757 `limit - buffered`、FS:1249 `saturating_sub`、FS:1263、`vec![0u8; want]` 受 chunk 上限封顶），未发现可达 panic；但 `FS:538-547` 之类"结构上不可达"的分支同样意味着**没被跑过**，fuzz（PD:3317-3318）未执行。

---

## 五、必须在合并前处理（按阻塞序）

1. NEW-1 `commit_upload` 补 `require_writable`/`require_local_io`，并把 root 记进 `UploadStream` 后强制"提交 root == 打开 root"，配一条用只读根与 SFTP 根提交的单测 + 一条 E4 字段。
2. NEW-2 给预算加会话归属并在"挤占/拆除/未知 session"三处释放；改掉 `FS:2341` 冻住的错误等式；补一条"挤占后 `inflight == file_buffered`"的断言。
3. NEW-5 F2 机器化：`squeeze_accounting_is_per_message` 在当前代码下为 false 而场景期望 true —— 先确定这棵树到底跑没跑过，重跑并如实更正 EV:205-206；若结论是"场景红"，则本批 F2 视为未交付。
4. NEW-3 节流表满改 fail-closed（拒绝新桶或 LRU+写 `locked`），并把 `global` 暴露成可观测计数，加一条"填满后正确口令仍被拒"的测试。
5. NEW-4 `authenticate` 实现 `max_sessions`/`max_browser_sessions` 准入，或把 G16/§18.2 的措辞改口为"未实现"。
6. W-1 `FS:804` 把 `#[derive(Debug, Clone, PartialEq, Eq)]` 从 `///` 注释里救出来（本批审计重构引入的静默回归；也侧面说明这批改完没有被完整读过/编译过）。
7. W-2 `list` 改回 `symlink_metadata` 取值；W-3 `rename` 无覆盖要么补原子路径要么写明窗口；W-12 `part_creation…` 改成经 `open_upload` 验引擎路径。W-8（`validate` 五条无测试）、W-7（capability 案自证）、W-10（PD 三处口径过时）属"契约文本/覆盖收口"，同批处理。
8. 契约文档三处收口：MO:101"逐条都有单测把它跑红"（当前假，7 条里只有 3 条）、MO:138-140"每条出站文件类消息过账"（当前只有 read 页）、PD:3280"已连续落盘"与 PD:3333"本节的场景当前状态是 Red Evidence"（均已过时）；`PR:3-8` 的"每个字段都取自引擎可观测行为"需为 `capability-negotiation` 例外让路。
