# Review: gateway file engine + E4 probe (round 1)

## 1. 评审者宿主与工具链
- OS/build: Windows 11 (win32) Git Bash. `git version 2.46.0.windows.1`；`rustc 1.89.0 (…)`（本机 rustc，见下）。
- 被评审树: worktree `E:\nexus-fabric-m0`, 分支 `feature/gateway-file-service-contracts`, tip `af953af`; 代码提交 `93d1dd7` + `8fa559c`（`git rev-parse` 核对：`93d1dd7=93d1dd79bc…`, `8fa559c=8fa559c733…`）。
- 取证手段：
  1. 逐行读源码/契约（`file_service.rs` 1977 行、`gateway_file_contract.rs`、9 条 `scenarios/product/gateway_file_*.toml`、`MODULE.md` G12–G21、`requirements.toml` REQ-005..013、`PRODUCT.md` §18、`config.rs`、两个 N3 文档、`.githooks/*`、`.gitignore`、`.evidence/*`）。
  2. **实测复现 item 7**：直接跑 `pre-commit` 第 4 关的选取片段（真实 `.evidence`+真实 git，只读）。
  3. **编译执行的 std-only 复算探针**（临时目录，已清理）复现 `SendBudget`+`FileLimits::validate` 算术（items 3/4）与 `resolve` 循环（item 2/F4）。
- **未经编译验证声明**：`nexus-web-gateway` 本机不能编（`ssh2 0.9.6::userauth_pubkey_memory` 被 `cfg(any(unix,vendored-openssl,openssl-on-win32))` 门控，无 cl.exe/nasm）——见记忆 `nexus-web-gateway-verification-host`。故：item 7、以及 F2/F4/W1 的算术/路径结论有**本机编译运行**证据；其余对引擎行为的判定为**源码静态推理**（高置信但未过 crate 编译）。`#![forbid(unsafe_code)]` 已核（lib.rs:15）。

## 2. 总体 verdict
**CHANGES_REQUESTED**（AGENTS.md §19.1：≥1 FAIL）。核心问题：E4 的配额/背压面把**一个没接进数据流的玩具模型**当成产品行为在证明；多个自证字段只读回引擎自己的声明；`resolve` 的 `NotFound=>break` 会把多段新路径**截断**。

## 3. 七项逐项判定表

| # | 项 | 结论 | 关键证据 `file:line` |
|---|---|---|---|
| 1 | 自证字段 | **FAIL**（见 F3 + W6/W7）；部分可判定 | `post_open_reverify_used` 可判定(真实拒绝) `gateway_file_contract.rs:316-321`；`correct_token_bypasses_lockout` 可判定 `:450-454`；`throttle_entries_bounded` 半判定(只读 buckets) `:467-470`+`file_service.rs:627-629`；`peak_read_handles_within_budget` 进程内计数器非 OS fd `:573-576`+`file_service.rs:496/539`；`file_drops_reported` **FAIL**(玩具+事件≠消息) `:538`；`mutation_capability_of_sftp_backend` **FAIL**(纯枚举回读) `:406-409` |
| 2 | G13 沙箱闭死 | **读路径基本闭死；写/.part 有未证窗口 + resolve 截断 FAIL** | `resolve` `file_service.rs:348-386`；`reverify` canonicalize 兜底 `:402-416`；commit `reverify_parent` `:1297-1303`；**F4** break 截断 `:369-372`（实测）；**F5** open 期 .part TOCTOU `:1087→1103` |
| 3 | SendBudget 建模诚实 | **FAIL**（F1 未接线 + F2 计数失真） | `drain_file_reserve` `file_service.rs:690-697`；`FileEngine` 无 SendBudget 字段 `:716-726`；`inflight_bytes` 从未被读写 `:565/:841` |
| 4 | validate 交叉约束 | **WARN/FAIL 缺项**（W1/W2） | `validate` `:142-208`（x64 因子）；`max_terminals` 无上界 `config.rs:73/14/255`；FileLimits 未由 GatewayConfig 构造 |
| 5 | 续传/不覆盖 vs N3-4/N3-9 | **WARN + F4** | `stage_chunk` 前缀语义 `:1161-1226`（对齐 N3-4:58）；无 fsync `:1182-1184` vs N3-4:62；integrity 可选 `:1256/1284`；rehash 预算→CAPACITY `:1267-1290`；`hard_link` 不覆盖 `:1306-1322`（对齐 N3-4:62-63） |
| 6 | 单证伪力 | **WARN/FAIL**（W6，4 条装饰/弱证伪） | `every_verb_is_audited…` `:1957`；`constant_time_eq…` `:1971`；`allows_mutation` 断言 `:1632-1633`；`terminal_class…` `:1859` |
| 7 | 门禁缺陷 | **FAIL**（已实测复现） | `pre-commit:48-87`、`pre-push:104-145`、`.gitignore:3`；实测选中 `review-g11-ice-fix-qoder-r1`（COMMENTED, source_revision `0576cb7`≠`93d1dd7`）放行 `crates/*.rs` |

### 逐条要点

**Item 1（自证字段）**
- `mutation_capability_of_sftp_backend` = `BackendKind::Sftp.allows_mutation()` = `matches!(self,Self::Local)`（`file_service.rs:228-231`）。它把枚举定义回读成 JSON，改坏枚举时实现与断言一起变，**永不红** → FAIL。真正的可观测替代**已在同一探针里**（`sftp_upload/mkdir/remove/rename/list_supported` + `refusal_code` 均驱动引擎返回 `UNSUPPORTED_CAPABILITY`，`:379-403`）。修法：删该布尔或改绑 `/api/config.files` 能力面观测。
- `file_drops_reported`/`ssh_messages_dropped`：探针直接 `SendBudget::new(...)`（`:519`），而 `FileEngine` 根本不含 SendBudget（`:716-726`）、`read_page/list/stage_chunk` 也不推任何预算 → 这组字段证明的是**离线的模型**，不是产品数据路径。FAIL（并入 F1）。
- `peak_read_handles_within_budget`：`self.handles.peak/live`（`:496/:539`）是引擎自维护计数，同步读会随真实 File 开闭，能被 `offsets_are_checked` 的 `live==0` 反向证伪（`:1897`），故**非纯自述**，但它测的是注册表逻辑数，不是 OS 句柄——G16 的 DoS 本尊（~1022 fd）没被观测。判 WARN，替代：下载期间读 `/proc/self/fd` 目录项计数（Linux A 级）做差分。
- `post_open_reverify_used`（`:316-321`）：确由真实 commit 失败码导出（换链后 commit 报 OUTSIDE_ROOT，走 `reverify_parent` 的 canonicalize），**可判定**。NOTE：字段名越权（resolve 也可能先拦）；且只覆盖 commit 期换目录，未覆盖 open 期（见 F5）。
- `correct_token_bypasses_lockout`（`:450-454`）/`throttle_entries_bounded`（`:467-470`）：行为/状态可观测；`throttle_entries_bounded` 只读 `buckets.len()`，不读 `locked` 表也不读 RSS（见 W7）。

**Item 2（沙箱）**
- 读路径：逐分量 `symlink_metadata`（`:367-381`）+ 打开后 `reverify` 用 `canonicalize` 兜底（`:411-414`）——中间目录被换成指向外部的符号链接时，`symlink_metadata(abs)` 会跟随该目录链接、但最终段非链接而放过，**随后 canonicalize 落到 root 外→OUTSIDE_ROOT**（`:414`）。链条成立，探针 `sandbox-symlink` 有差分（`naive_resolver_would_escape` `:326-330`）。判定：基本闭死。
- **F4（FAIL）**：`resolve` 遇 `NotFound` 直接 `break`（`:369-372`），**后续 Normal 段不再拼**，返回路径停在第一个缺失段。编译探针实测 `resolve("a/b/c")`（`a` 不存在）→ `…/a`。`open_upload` 取的是 `Ok(截断路径)` 分支（`:1076`，不走 NOT_FOUND 兜底），于是多段新目录的上传把 `.part` 建到 `…/.a.nexus-part…`、commit 又 `resolve` 成 `…/a` 并以 `hard_link` 发布成 **`a`**（不是 `a/b/c`）且不报错。违反 N3-4:16/N3-9:9「绝对 output 固定 / 分页不得替换任意字段」(G18/§18.1)。复现：`open_upload("a/b/c", …)` 且 `a` 不存在。修法：NotFound 时**继续拼剩余段**（只跳过对不存在段的链接检查），或显式返回可区分错误让调用方 `canonical.join(rel)`。
- **F5（写/.part 残余窗口）**：`open_upload` 先 `reverify_parent(abs)`（`:1087`）再 `create_new(part)`（`:1103-1108`）——std-only 无 `O_NOFOLLOW`，若这中间父目录被换成指向外部的符号链接，`create_new` 跟随链接把 `.part` 写到 root 外（字节短暂落到外部，commit 失败后 `abort_upload` 又会经符号链接把它从外部删掉，`:1334`）。同窗口存在于 `commit` 的 `reverify_parent→hard_link`（`:1298→1306`，`hard_link` 目标存在即失败可缓解但不消除创建窗口）。当前**既未防御也未在探针/文档标注为可接受残余**。判 FAIL：要么在 Linux(A 级) 用 `O_NOFOLLOW`/`openat`+handle 身份真正闭合，要么按 §18.3 的 B 级口径把它**明写为已声明残余风险**并加一条 open 期差分探针（现在只测了 commit 期）。
- `remove_tree` 中途换链：每个 child 先 `r.resolve(child_rel)`（`:1415`）再 `symlink_metadata`（`:1416`）判链接→SYMLINK_ESCAPE，递归用 root 内已核实路径，read_dir 只列不删。判定：中途换链**不能**绕过（每层重解析），探针 `remove_recursive_stays_in_root` 有效（`:292-304`）。

**Item 3（SendBudget）**
- `drain_file_reserve` 返回 `usize::from(freed>0)`（`:696`）= 每次挤占事件记 1，不管挤掉几条消息。编译探针复现：`limit=100`，10×push_file(10) 满仓后 1×push_terminal(40) 挤掉 4 条 10B 消息 → `file_drops` 只加 **1**（真实应为 4）。可复算失败输入即此序列 → **误导性值确认（F2）**。
- 更根本：SendBudget 未接入 FileEngine（`:716-726`），`inflight_bytes`（`:565/:841`）声明后从不增减 → 引擎实际**零发送侧背压**，G16/§18.2「超预算回 QUEUE_FULL/CAPACITY 并显式计数丢弃」在产品路径**未实现**（F1）。真实拥塞序列下 `file_drops_reported`/`ssh_messages_dropped` 会给出「模型自洽、产品未落地」的误导绿灯。

**Item 4（validate 缺项）**
- 已做的不等式：零值、`browser≤sessions`、`chunk≤buffered`、`chunk≤inflight`、`ack≤buffered`、`sessions×inflight≤buffered×64`、`read_handles≥sessions`（`:143-207`）。
- **缺 G12 点名项**：`chunk_bytes × max_sessions × 在途页数` 里「在途页数」无独立上界（只有 `inflight_bytes_per_session`，且运行时不用）。`×64` 因子放大：编译探针复现——默认 `sessions=4,inflight=1MiB,buffered=128KiB` → worst=4MiB ≤ 阈值 8MiB **放行**，但对 SCTP 预算真实超配 **32×**；边界组 B `sessions=4,inflight=2MiB` → worst=8MiB=阈值 **恰好放行**，超配 **64×**。这正是「配置自洽但组合超预算且拒启动不了」的口子。
- **缺 ack×entries 交叉项**：`max_ack_bytes` 只对上 `buffered`，从不校验 `max_entries_per_page × 最大条目名` ≤ `max_ack_bytes`（`:180`）。可配 `max_entries_per_page=100000, max_ack_bytes=32KiB` 放行 → G17「单条 ack 不得大到头阻塞控制通道」在配置层不设防。
- **缺聚合上传预算**：`max_upload_bytes × max_sessions`（`.part` 磁盘/RSS）无式；`validate` 也不在任何启动路径被调（引擎未接 GatewayConfig）。
- `max_terminals`：`config.rs:73`，默认 5（`:14`），`validate` **只有 `==0` 下界**（`:255-259`），无上界；且终端 fd/RSS 与 `FileLimits` 在**两个不同结构体**里，从未进同一预算式——§18.2「全局 RSS… 公式与 FileLimits 交叉校验」对终端面未兑现（W2）。

**Item 5（vs N3-4/N3-9）**
- 对齐良好：`stage_chunk` 连续前缀 append（`:1161-1194`）、重复页逐字节比对（`:1206-1218`）、跳跃/部分重叠拒绝且不重写前缀（`:1197-1226`）——对齐 N3-4:58。`commit_upload` 先核 declared_len（`:1256`）再 `hard_link`（目标存在→EXISTS 不覆盖，`:1306-1322`），拒绝时 `abort_upload` 清 `.part`（`:1319`）——对齐 N3-4:62-63/G14。`.part` 命名 `.{name}.nexus-part-<hash>`（`:1530-1555`），熵用 pid+纳秒+stream（非栈地址），对齐 §18.1。
- **差量**：① N3-4:57-59/N3-9:16 的「**部分字节摘要/prefix_sha256**」续传机制**未实现**——引擎只有一个封顶 `max_rehash_bytes_per_stream` 的增量 hasher，从不产出/比对前缀摘要（`:1186-1190`）。② 无 fsync：`stage_chunk` 只 `.flush()`（`:1182-1184`），而 §18.1/G18 承诺「已连续**落盘**」，N3-4:62 明确「写页后 fsync」→ 耐久性越权（W3）。③ 完整性**可选**：`expected_sha256=None` 且 `declared_len=None` 时 commit 零校验直接发布（`:1256/1284`），G18「完整 SHA-256 与长度校验通过后才发布」只在调用方自愿时成立（W4）。④ `max_rehash_bytes_per_stream` 用尽 → 带摘要的 commit 返 CAPACITY（`:1284-1290`）：这是 fail-closed（**不**发布未核字节，符合 §18.2「拒什么」），但把「哈希 DoS 上限」误当成「校验门」，使 >64MiB 默认预算的产物**永远无法带摘要发布**——能力悬崖；N3-4 的正解是客户端流式 prefix-SHA 核验、服务端不做它算不完的全量重哈希。

**Item 6（单测证伪力）**——见 W6。

**Item 7（门禁）**——实测复现见 §4 G1。

## 4. FAIL 清单（阻塞）

- **F1 配额/背压是离线玩具**：`SendBudget`+`FileSession.inflight_bytes` 从不接入 `FileEngine`（`file_service.rs:716-726` 无预算字段、`:565/:841` inflight 不用；`gateway_file_contract.rs:519` 直接手搓 SendBudget）。→ `quota_backpressure` 整案、以及 `file_drops_reported/ssh_messages_*` 证明的是模型不是产品；G16/§18.2/REQ-011 在产品路径未实现。修法：把 SendBudget 作为 `FileEngine` 字段，`read_page/list/stage_chunk/ack` 经它 push/settle，探针改为**驱动引擎**并读引擎内计数。
- **F2 drain 计数失真**：`file_service.rs:690-697` `usize::from(freed>0)` 把「挤掉 N 条消息」记成 1（探针复算：4→1）。修法：SendBudget 需持**消息队列**（每条带字节），drain 时按真实被逐出的消息条数累加 `file_drops`；补一条「1 终端挤 ≥2 文件 → 断言 file_drops==被挤条数」的单测。
- **F3 `mutation_capability_of_sftp_backend` 纯自述**：`gateway_file_contract.rs:406-409` 回读枚举谓词（`file_service.rs:228-231`）。修法：删该字段，靠同案已有的行为型 `sftp_*_supported`/`refusal_code`（`:379-403`）作证据；或绑 `/api/config.files` 能力面。
- **F4 `resolve` NotFound→break 截断路径**：`file_service.rs:369-372`（本机编译探针实测 `a/b/c→a`）。经 `open_upload`（`:1076`）与 `commit_upload`（`:1297`）导致多段新目录上传**发布到错误前缀路径且不报错**，违反 N3-4/N3-9 output 固定。修法：NotFound 不 `break` 整循环，改为「跳过对不存在段的链接检查、继续拼剩余段」。
- **F5 写/.part 创建期 TOCTOU 未防未声明**：`file_service.rs:1087→1103`、`:1298→1306`，std-only 无 `O_NOFOLLOW`。修法：Linux(A 级) 用 `O_NOFOLLOW`/`openat`+handle 身份闭合；若接受残余，须按 §18.3 明写 + 加一条 **open 期换目录差分探针**（现仅测 commit 期 `:309-321`）。
- **G1 门禁可用无关旧案卷放行**（item 7）：实测——`pre-commit` 第 4 关以 `ls .evidence/review-* | sort | tail -1` 选中 `review-g11-ice-fix-qoder-r1`，只 `sed` 抽 `"verdict"`，得 `COMMENTED` 即放行 `crates/nexus-web-gateway/src/file_service.rs` 的改动；该案卷 `source_revision=0576cb7…`，与被评审码 `93d1dd7/8fa559c` **毫不相干**，且 `pre-commit:48-87`/`pre-push:104-145` **从不读**该案卷里已存在的 `source_revision/working_tree_digest/contract_hash`（`.evidence/review-g11-ice-fix-qoder-r1/summary.json:8-10`）。复现命令：对真实树跑第 4 关选取片段（已跑，输出 `GATE DECISION: PASS`）。修法（最小）：①案卷必须绑定并校验——`git merge-base --is-ancestor "$source_revision" HEAD` 且重算工作树摘要与 `working_tree_digest` 一致，否则 BLOCK；`scope.changed_crates`/`contract_hash` 须覆盖本次 `crates/*.rs`（现「一个 agent 的评审不满足另一个」只是 `:51-53` 注释，选取是 `sort|tail -1`，非 scope 感知）。②`/.evidence` 被 `.gitignore:3` 排除→新案卷不随分支走、跨宿主不可核（`git check-ignore` 实测 `.evidence/review-gateway-file-*/summary.json` IGNORED；`red-n2-p0-0`/`review-g11` 靠 `git add -f` 强制跟踪才在场，见 `git ls-files .evidence/` + commit `6757ffa`）。处理：把 `.evidence/review-*/summary.json`（+findings）从 ignore 中**放行子路径**使其可携，或落地 AGENTS.md:2203 建议——commit 正文写 `review: <id>` + 绑定哈希、hook 校验、CI 存档案卷。

## 5. WARN 清单
- **W1 validate 缺交叉项**（`file_service.rs:142-208`）：无「在途页数」独立上界；`×64` 因子使最坏在途超配 32–64× 仍放行（探针复算）；无 `entries×name≤ack` 项（G17 头阻塞配置不设防）；无 `max_upload_bytes×sessions` 聚合项。
- **W2 预算未贯通/终端无上界**：`max_terminals` 仅 `==0` 下界（`config.rs:255`），终端 fd/RSS 与 FileLimits 分处两结构、从不入同一预算式；`FileLimits` 也未由 `GatewayConfig` 构造（引擎只 `lib.rs:20` 声明模块，`gateway.rs/config.rs` 不用），故 §18.2「拒启动」目前无产品启动路径承载。
- **W3 无 fsync**：`stage_chunk` 仅 `.flush()`（`:1182-1184`），却 ack「已连续落盘」；N3-4:62 要求写页后 fsync（`std::fs::File::flush` 非 `sync_all`）。
- **W4 完整性可选**：`commit_upload` 无 `expected_sha256`/`declared_len` 即零校验发布（`:1256/1284`），G18「校验通过才发布」不强制。
- **W5 rehash 预算当校验门**：`digest_complete=hashed>=staged` 对大流恒假 → 带摘要 commit 返 CAPACITY（`:1267-1290`），大产物不可摘要发布；N3-4 的 prefix-SHA 流式续传未实现。
- **W6 装饰/弱证伪单测**：`every_verb_is_audited_including_refusals`（`:1957`）——从 list/read/remove/open_upload/commit 删 `record()` 仍**绿**（只断言 3 个码在场）；变异判据：每动词至少断言一条**拒绝码留痕**。`constant_time_eq_distinguishes_lengths_and_prefixes`（`:1971`）——把 `constant_time_eq` 改成 `a==b`（早退非恒时）仍**绿**，测不到 G15 恒时性；判据：注入定长输入比对耗时/或断言无早退分支。`sftp` 案 `assert!(!Sftp.allows_mutation())`（`:1632-1633`）定义回读。`terminal_class_has_priority`（`:1859`）证不了 F2 的计数失真。
- **W7 throttle 有界只观测 buckets**：`file_service.rs:627`+探针 `:467-470` 不看 `locked` 表/RSS；`record_failure` 超 `max_buckets` 后并入单一 `global`（`:609-612`），对伪造新 principal 触发 THROTTLED 却**从不真正插入 `locked`**（`is_locked` 恒假）→ 锁定有效性随伪造量静默降级，而「有界」断言仍绿。
- **W8 mkdir 嵌套实际不可用（fail-closed，非漏洞）**：`mkdir` 用 `canonical.join(rel)` 后 `reverify_parent`（`:1347-1348`），而 `reverify_parent` 要求父目录**已存在可 canonicalize**（`:1515-1522`）→ 对新 2+ 级路径恒 NOT_FOUND。安全上保守，功能上「建目录」承诺（§18.1）受限。单测 `symlink_…_on_every_verb` 名为 every_verb 却漏 mkdir/rename。

## 6. NOTE 清单
- **N1** 单测实际 **13** 条（`file_service.rs:1605/1627/1680/1708/1741/1779/1826/1859/1872/1903/1927/1957/1971`），非 `MODULE.md:109` 自述的「12 条」、亦非评审简报的 12。实现方自述计数不可采信。
- **N2** `gateway_file_contract.rs:3` 头注释「eight cases」已过期——`dispatch` 有 9 个 `--case` 分支（`:50-60`），与 9 条场景/`af953af` 的「9/9」一致。
- **N3** item 7 与 F2/F4/W1 有本机**编译运行**证据（std-only 探针，已清理，未入库）；其余引擎行为判定为静态读码（未过 crate 编译，原因见 §1）。
- **N4** 探针 `capability_negotiation`（`:596-659`）把 G19 规则写成探针内**私有纯函数** `decide_channel`，与真实 `/api/config` 处理（本 crate 尚无 files 接线）无关——该案的「PASS」证明的是探针本地逻辑，非网关行为；与 F1 同源（M2 前未接线）。

## 7. 要合入 master 必须先清掉（可执行）
1. **F1**：把 SendBudget/`inflight_bytes` 接进 `FileEngine` 数据路径，探针改驱动引擎；G16/§18.2/REQ-011 落地。
2. **F2**：SendBudget 持消息队列、按真实被逐出条数计 `file_drops`；补「1 终端挤 N 文件 ⇒ file_drops==N」判据。
3. **F3**：删 `mutation_capability_of_sftp_backend` 自证布尔（及其单测回读），保留行为型断言。
4. **F4**：修 `resolve` 的 `NotFound=>break` 截断（继续拼剩余段）；加多段新目录上传探针。
5. **F5**：写/.part 创建窗口——Linux 用 `O_NOFOLLOW`/`openat` 闭合，或明写为可接受残余并加 open 期差分探针。
6. **G1**：门禁绑定并校验 `source_revision`（`--is-ancestor`）+`working_tree_digest`+`scope`；放行 `.evidence/review-*/summary.json` 出 `.gitignore` 或按 AGENTS.md:2203 用 commit marker + CI 存档。
7. **W1/W6**：至少补「ack×entries 头阻塞」「在途页数」两项交叉校验；把 `every_verb_is_audited`、`constant_time_eq` 两条改成能真正证伪（删审计/改早退必须红）。

（W2–W5/W7/W8 可与 M2/M3 同批；但 §18.2/REQ-011 声称已实现的启动 fail-closed 与配额面在 W2/F1 未清前不得对外声明为「已对齐」。）
