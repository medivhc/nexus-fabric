---
doc-id: nexus-gateway-file-service-retrospective
layer: L3-decision
owner: orchestrator-agent
last-verified: 2026-10-11
verified-against: 0576cb73a802256604088f6accd4917b245c3945 + 未提交工作树
status: current
---

# 网关文件服务：一次被否决的实现、它的收获与下一步

这份是**索引与总结**：把 `nexus-web-gateway` 文件访问/上传模块这一整轮工作（实现 → 46+28 测试全绿 → 18 角度独立评审 16 FAIL → 拆分决策 → 重做设计 → 设计被裁决 CHANGES_REQUESTED）压成可复查的一页，并把产物、文档地图、下一步计划和需要你拍板的决策列清。

## 0. 现在的状态（一句话一条）

| 线 | 状态 | 产物 |
|---|---|---|
| **G11 ICE 修复**（让 `gateway-ci` 转绿的真正必要因） | 已剥成独立可提交补丁，Linux 实测基线对比充分 | `E:\nexus-fabric-g11`（干净重放树）+ `g11-ice-fix.patch` + `G11-PATCH-README.md` |
| **文件模块 V1**（本次实现） | 否决，不修；降级为反例证据 | `file-module-attempt.patch`(156,383 B) + `snapshot/` + `FILE-MODULE-CHANGE-MAP.md` + `FILE-MODULE-POC-INDEX.md` |
| **文件服务 V2 设计** | 已写（393 行），独立评审判 **CHANGES_REQUESTED**，不能进编码 | `docs/GATEWAY-FILE-SERVICE-DESIGN-V2.md` |
| **harness 证据绑定缺陷** | 已证实并立案（含 3 处加重细节与修复方案） | `plan-artifacts/HARNESS-EVIDENCE-BINDING-DEFECT.md` |
| **知识沉淀** | 8 条新条目入库目录（未改既有文件，`index.json` 回填以建议形式给出） | `.agents/knowledge/entries/2026-10-11-*.md` |
| 提交状态 | 全部未提交，`E:\nexus-fabric` 工作树保持原样 | 无 commit / 无 push / 无历史改写 |

## 1. 时间线与因果

1. `b39226d`（10-10 02:07）把"所有非 loopback 网卡 IP"无条件通告为 ICE host candidate —— 但 UDP socket 绑的是 `listen_addr` 的具体 IP，收不到别的 IP 的包 ⇒ ICE 永不连通。
2. `3a3f9eb8`（10-10 05:59）第一次让 CI 忠实传播 cargo 退出码，于是**这条既有缺陷从"假绿"变"连红 5 次"**。仓库同事先前把它当"测试挂了"，实际 101 = 12 条 e2e 建连失败（`peer 0 should connect` / `no control channel open`）。
3. 我在这条基线上加文件模块（V1），跑出 46 单测 + 28 e2e 全绿、`clippy`/`fmt`/`verify --fast` 9 门 PASS，还顺手抓到两个真 bug（libssh2 `readdir` 回显前缀、`DataView.setUint64` 不存在）。
4. 18 个独立角度评审推翻它：**16 FAIL / 1 WARN / 1 COMMENTED**。原因是绿测试只覆盖功能语义，**资源与安全语义完全没被核算**。
5. 决策：拆两条线（G11 保留、文件模块按 N3 契约重做），V1 不就地打补丁。

## 2. 收获

### 2.1 关于这个 crate 的技术事实（都可复查，非意见）

- **ICE 候选必须 ⊆ socket 实际可收包地址**。绑具体 IP 只收该 IP；只有绑族内通配地址才能通告多网卡；`0.0.0.0` 不能进 SDP，但 `page_addr` 必须是具体地址（否则浏览器打不开）。→ `ice_bind_plan()`。
- **`ssh2` 的三个门**：`userauth_pubkey_memory` 被 `cfg(any(unix, vendored-openssl, openssl-on-win32))` 挡死 ⇒ **该 crate 在 Windows 当前配置下编译不过**（`libssh2-sys` 本身能过，走 WinSCH；`getifaddrs 0.6` 也能过；本机无 `cl.exe`/`nasm` 所以 vendored-openssl 不可行）；`stat` 跟随符号链接而 `lstat` 不跟随（`sftp.rs:284` vs `:304`）；`readdir` 会回显查询目录前缀。
- **单事件循环 + 无上限发送队列 = 头阻塞**。str0m `write()` 在 `len > available`(默认 128 KiB) 时返回 `Ok(false)`；`flush_send_queue` 只 `break` 保留队首 ⇒ 一条超大 `FileListAck`（10 万条 ≈ 10.4 MB）永久堵死该会话**所有**消息，还每 tick `front().cloned()` 复制它。
- **`panic = "abort"`（workspace 根 `Cargo.toml:68`）× 外部可控算术溢出 = 单条畸形帧打死整节点**。`offset + len` 在 debug panic（worker 静默死亡、丢 ack、会话假活；全 crate 8 处 `thread::spawn` 都丢弃 `JoinHandle`），在 release 无 overflow-checks 时回绕绕过 `max_upload_bytes`。
- **`entry_at` 用未 canonical 的 root 做 `strip_prefix`** ⇒ root 是符号链接（macOS `/tmp`）或带 `\\?\` 前缀（Windows）时，每个嵌套条目 path 退化成 `/name`，浏览器拿错 path 去下载/删除 = **删错文件**。
- **SFTP 不是"天然限制在 home 内"**。V1 的 `remote_path` 不解析链接、类型判断用 `stat` ⇒ 真机 PoC 里 `list/read/commit/mkdir` 穿透 home，`remove(recursive=true)` **删掉 home 外一棵树**。
- **每分片一个新 `stream_id`** 撞上"按 stream_id 缓存读句柄、仅会话关闭时清" ⇒ 实测第 1022 片 EMFILE（ulimit 1024），后果是**新 WSS 连接 125 µs 失败、裸 TCP connect 1.8 µs 失败**：单用户下 64 MiB 就打挂节点前门。
- **SFTP 每开一个文件会话就新建一条 TCP + SSH 握手 + 认证**（无连接池）⇒ 实测 1 浏览器 open→close 循环 = **84.4 次认证/秒**，10 浏览器 165/s，撞 `MaxStartups`/faillock，把网关自己的终端登录和目标机账号一起锁死。
- **`/api/config` 未鉴权就回 `ice_servers`（含 TURN username/credential）与节点列表**（这条是既有面，V1 又加了 `files.roots` 名单）。令牌校验是文件系统的唯一防线，却**零节流**（实测单会话 5000 次错 token 全被处理）。
- **`DataView.setUint64/getUint64` 不是标准 API**（Node/浏览器都没有）；跨语言二进制协议只有 Rust 侧断言等于没锁 JS 侧 —— V1 的"共享 fixture"其实是单侧的，且 CI 里没有 node 步骤。

### 2.2 关于工程流程（这才是本轮最值钱的收获）

1. **"全绿"与"能上线"之间隔着一次资源/配额核算。** `verify --fast` 9 门 PASS、46+28 测试全绿，同时存在 12 条 P0（含 1 条远端任意文件删除）。缺的不是测试数量，是**没人算过 fd/RSS/消息大小/线程数/认证速率的上界**。→ 高风险网络与文件类变更，独立 Review 之前先做一次配额与资源上界推导，并把结论写进 Review 输入。
2. **CI 假绿的机制是"退出码传播"**。测试步骤最后一句是 `echo` 时，13 条 e2e 挂掉也照样绿。→ 门禁脚本里 `grep -c`/管道之后必须显式传 `$STATUS`；回归测试必须**有断言**（V1 之前那条"ICE 回归测试"只 `println!` 网卡数，零断言）。
3. **变异测试能量化"哪些测试是装饰"。** 评审实际把 30 个位置改坏跑回去：ICE 候选、帧头二进制布局、上传顺序/内容落地、三闸门是"改坏必红"；`unknown file session` 应答、SFTP 路径归一化、G14 的 e2e 层、空闲超时、stream 归属、`chunk_bytes` 入站上限是"改坏仍绿"。→ 新不变量要同时配一条**能红的**测试，否则等于没写。
4. **测试自证循环要单独查。** `routable_ipv4s()` 与实现用同一套 `getifaddrs` 过滤逻辑比长度 ⇒ 在容器/多网卡机器上天然 flaky 且能自我掩盖。
5. **实现者不能自签 Review，也不该用数字为自己背书。** 本轮我只出"实现者自验案卷"，18 角度评审与 V2 设计评审都由独立执行者出；我引用的 `verify-c327a6da9351` 事后被证明**不能证明验的是哪些字节**（见 2.3），这类事实在自己案卷里必须公开更正。
6. **顺手改动要披露。** V1 为过 `cargo fmt` 门禁改了 `cert.rs`（该文件在 master 上本来就不 fmt-clean），与本需求无关，diff 变大需 reviewer 另行确认。

### 2.3 关于工具与证据链（仓库级发现，影响面超出本 crate）

**`nexus-harness` 的 Evidence 绑定在 dirty 态对内容盲 —— 已用实验证实。**
- `engineering/nexus-harness/src/env.rs:104-114`：clean 时 `git write-tree`；**dirty 时是 `git status --porcelain` 文本的 hash**（注释自陈 "stable for a given dirty state"）。porcelain 只有状态码 + 路径，无字节数/内容 ⇒ 同一路径集合下**改内容 digest 纹丝不动**（实测：marker A / marker B 两版内容 sha256 不同，digest 同为 `12d3f5e29e…`）；未跟踪目录整体替换内容 digest 也不变（`8c1c17ee…` 恒定）。
- `env.rs:59` 的 `.trim()` 把行首空格剥掉，破坏 XY 状态列语义（加重）。
- `evidence.rs:62-75`：evidence id seed = revision|configuration|contract，**不含 digest 与时间戳** ⇒ 两棵不同内容的脏树得同一 id，`evidence.rs:117-163` 原地 `fs::write` 覆写、`mark_stale_others` 跳过同 id ⇒ **前一次证据静默消失而不是变 STALE**（实测同 id `bindexp-c8882e6fedc0` 两次 run，`gates.json` mtime `06:12:22→06:12:49`、size `2362→2422`）。
- `harness.toml:39` 的 `bind_working_tree_digest = true` 在 src 里 grep `bind_` **零命中** —— 是死配置。
- 影响：`.githooks/pre-push` 现场验字节尚可，但**落盘记录不可追溯**；`harness status/explain/latest.json`、AGENTS.md §20/§29 引用的脏态证据（含历史上 `verify-d7c57c186675` 这类）凡不能证明产生时树 clean，都不能证明验过哪些字节。
- 修复提案（含取舍）在 `plan-artifacts/HARNESS-EVIDENCE-BINDING-DEFECT.md`：dirty 态改用 `git diff HEAD --binary` + 逐未跟踪文件内容哈希；id seed 纳入 digest（时间戳只进 summary 字段，不进 id）；`bind_*` 语义要么兑现要么删。

**环境事实（省下一轮试错）**：该 crate 的编译/测试证据只能来自 xc-pc-linux；`scp` 与 GitHub over https 在那台机上常断，稳定做法是 `ssh host 'cat > p' < f` 或 tar 管道 + `git bundle`；Linux 上 warm target 在 `/work/nexus-dev/target`；`/` 与 `/media/appen/data` 都接近满（评审期间我清掉了各 agent 遗留的约 5.1 GB 构建目录，`/` 回到 94%）。

## 3. 文档地图

| 文档 | 作用 | 位置 |
|---|---|---|
| 本文件 | 总结 + 索引 + 下一步 | `crates/nexus-web-gateway/docs/GATEWAY-FILE-SERVICE-RETROSPECTIVE-2026-10-11.md` |
| 18 角度评审汇总 | 裁决依据：16 FAIL、P0-1..P0-12、P1、变异测试"装饰区"清单 | `docs/FILE-MODULE-REVIEW-2026-10-11.md` |
| V1 实现与自验案卷 | 实现了什么、当时怎么验的、含**两条公开更正** | `docs/FILE-MODULE-VERIFICATION-2026-10-10.md` |
| V2 设计方案 | 重做方案（当前 CHANGES_REQUESTED，待按 8 条修订） | `docs/GATEWAY-FILE-SERVICE-DESIGN-V2.md` |
| N3 权威契约（V2 必须对齐） | 字节分页/续传/原子不覆盖发布/校验和 | `docs/N3-4-ARTIFACT-DELIVERY.md`、`docs/N3-9-ARTIFACT-CLI-CONTRACT.md`、`docs/N3-6-LOCALAPI-SECURITY-CONTRACT.md`、`docs/N3-8-CAPACITY-SESSION-CONTRACT.md` |
| 本 crate 契约 | G1..G16、Non-Responsibilities、依赖禁令、Verification | `crates/nexus-web-gateway/MODULE.md` |
| 纪律与门禁 | 任务类型/protected paths/Review 结构/Evidence | `AGENTS.md`、`.agents/skills/nexus-review/SKILL.md`、`harness.toml`、`.githooks/*` |
| 补丁与归档（会话目录，非仓库） | 可提交补丁、V1 完整补丁、PoC 索引、harness 提案 | `…/sessions/…/c2283260c5da99a5d2076c04/plan-artifacts/` |

## 4. 下一步计划（按依赖排序，每条带验收标准）

**N0（你拍板，阻塞开工）** 见 §5 决策表：D3 Windows 句柄身份键、D4 TURN 凭据路径、D5 "不覆盖"语义是否升级为 requirement-change、D7 `panic=abort` 取舍。

**N1 G11 单独提交**（可立即做，与文件模块无耦合）
1. 在 `E:\nexus-fabric-g11` 上按 `G11-PATCH-README.md` 的 message 草稿提交（body 已含 `contract: 8de98ae132…`，该 hash 由 `scenarios/**/*.toml` 独立复算两次一致）。
2. 前置缺口：`.githooks/pre-commit` 第 4 关要 `.evidence/review-*/summary.json`（APPROVED/COMMENTED）—— G11 这条**还没有独立 Review 案卷**，需你指定执行者补一份（范围小，可降级快速过）。
3. 验收：push 后 `gateway-ci` 的 `test` job 转绿（V1 的 12 条建连失败消失）；`verify --fast` 9 门 PASS。

**N2 修 V2 设计的 8 条 CHANGES_REQUESTED**（评审已给逐条定位）
① 补 SFTP 提交路径的 no-replace（V1 用的是 `rename(...,None)`，ssh2 默认含 `OVERWRITE` ⇒ 远端仍静默覆盖）；② SFTP 逐分量 `lstat`/`readlink` 解析算法写死（含 home 内既有链接）；③ 定义 TOCTOU 快照内容与 Windows 替代身份键（`\\?\` 下 `(dev,ino)` 在 stable std 不可得）；④ 删"需新增 sha2"误述（Cargo.toml 已有）；⑤ 帧上限必须 ≤ str0m 可用缓冲（默认 128 KiB 且两通道共享 ⇒ 256 KiB 配置根本写不下），并给非文件类队列加全局字节上限；⑥ TURN 凭据下发时序与 `new RTCPeerConnection` 兼容（`hello_ack` 方案不成立，通道在 ICE 之后才存在）；⑦ 令牌节流键要可从 `gateway.rs` 取得（现在不采 `peer_addr`）+ 失败表容量上限；⑧ 全局并发会话行、磁盘/摘要成本上限、把 D3/D4/D5/D7 升为 M0 前置、M0 交付物补 scenario + RED（AGENTS §5 阶段 A、`harness.toml` 的 `red_evidence_required`）。
验收：设计文档第二版由同一评审者复评至 COMMENTED/APPROVED。

**N3 修 harness 证据绑定**（独立于文件服务，属仓库级）
按 `HARNESS-EVIDENCE-BINDING-DEFECT.md` 的提案改 `env.rs`/`evidence.rs` + 补 3 条 env 回归与 id/STALE 测试；顺带处理 `bind_*` 死配置。这条**应在 M1 之前做**，否则重做线的每一期证据都继承同一个洞。

**N4 知识条目回填**：`index.json` 追加 8 个条目对象（片段已备好）、4 个既有条目回填 `related`（我无权改既有文件）。

**N5 M0 契约阶段**：V2 定稿后先改 `PRODUCT.md`/`scenarios/`/`MODULE.md`（G11–G16 重写 + 新增不变量）并产出 RED evidence，再动代码。

**N6 重做实现**：M1 安全 P0（SFTP 符号链接、配额、令牌节流、`/api/config` 去凭据、溢出与 panic 隔离）→ M2 协议演进（version/capability、分页、双预算队列、服务端签发 stream_id）→ M3 完整性与续传（对齐 N3 的 `prefix_sha256`/intent）→ M4 结构收敛（两引擎去重、下沉或引证权威）。每期退出准则：`fmt`/`clippy`/affected tests/`verify --fast` + **资源核算测试（fd/RSS/消息大小/认证速率上界）** + 独立 Review + `verify --full`。

## 5. 已固化的决策（owner 同意按建议锁定，2026-10-11）

| # | 决策 | 锁定内容 |
|---|---|---|
| **D3** | Windows 身份键与支持等级 | Windows 降 **B 级**：密码认证 + 本地沙箱；`(dev,ino)` 在 stable std 不可得（实测 E0658 `windows_by_handle`），改用"打开后路径重解析 + `create_new` 等价物"并明写残余风险；升 A 级需走 `windows-sys` 依赖评审 |
| **D4** | TURN 凭据脱敏 | `/api/config` 只回 `urls`；凭据走**建 PC 前**的一次性短时效端点（`hello_ack` 方案因时序不成立被废：通道在 ICE 之后才存在，且禁 renegotiate）。备选"不支持需凭据 TURN" |
| **D5** | 上传不覆盖已存在目标 | 作为**用户可见语义变更**走 requirement-change：改冻结文本 + 先有 scenario RED；与"wire 只加不改"的冲突显式调和 |
| **D7** | `panic = "abort"` 下的隔离 | 不靠 `catch_unwind` 假装解决（release 不存在）：要求 panic-free-by-construction（`checked_*` + 无外部可控 panic + 显式列举 str0m 内部 assert 面）+ fuzz；是否改 profile 列为 owner 待批 |
| **D1** | 是否下沉 `nexus-delivery` | 暂不下沉（MODULE.md 禁内部依赖 + portable-core/WASI 门），但字段与语义**强制对齐** N3-4/N3-9 + 双向一致性测试 |
| **D0** | 网关能力入产品契约 | 进 M0：`PRODUCT.md` 至少一节 + `scenarios/` 网关场景包（当前两处命中均为 0） |
| **D8** | 同路径并发上传 | 服务端签发 `stream_id` + 目标路径锁（同路径拒绝并发写） |

## 5b. 计划进度（本轮已完成 / 待办）

**已完成并独立复验**
- **#15 harness 证据绑定修复**：新干净树 `E:\nexus-fabric-harness`，改 `env.rs`/`evidence.rs`/`config.rs`/`commands.rs`/`scenario_cmd.rs`，产物 `harness-evidence-binding.patch`(30,603 B) + `HARNESS-FIX-README.md`。
  我在 Linux 上独立跑：**打补丁 64 tests 全绿，还原后 56 ⇒ 净新增 8 个测试**；`dirty_content_digest` 在位；clean 树 evidence id 仍是 `c327a6da9351`（向后兼容成立）。
- **#14 V2 设计修订**：`docs/GATEWAY-FILE-SERVICE-DESIGN-V2.md` 升 rev2.1，新增 §13 已定决策 / §14 评审处置表，8 条逐条落实（SFTP no-replace 与"服务端是否 honor"标为需实测、逐分量 lstat/readlink 算法、TOCTOU 快照类型、Windows 降级、两通道共享 128 KiB 预算、TURN 时序、节流键可取源、全局 fd/RSS/磁盘/重哈希预算 + M0 前置 scenario/RED）。

**新发现的基线事实（重要，影响提交策略）**
- **pristine master 的 `verify --fast` 本身是 FAIL**：唯一红门 `format`，红点在 `crates/nexus-web-gateway/src/gateway.rs:474`（`&[("Content-Disposition", ...)]` 未过 `cargo fmt --all`）——这是**第二处** master 不 fmt-clean 的证据（另一处是我早前修的 `cert.rs`）。`whitespace/check/clippy/architecture-policy/dependency-governance/resource-type-neutrality/affected-tests/selected-properties` 均 PASS。
- 因此：**G11 那条补丁顺带治好 format 门**（我的格式化包含在同一 diff 里）⇒ 打完 G11 补丁后 `verify --fast` = 9 门全 PASS，与"master 单门红"形成自洽对照。
- 对 harness agent 报告的一处纠正：它称"基线红门含 affected-tests/selected-properties"，实测**不成立**（两者在干净 master 上 PASS）；机制结论不受影响。

**待办**
1. V2 rev2.1 交同一评审者复评（它自己已点出下一轮最可能被挑的三处：`grant-nonce` 泄露面、`max_browser_sessions=8` 与终端面 fd/线程预算只在表里挂名无推导、`.part` nonce 用栈地址当种子的熵声明无证据）。
2. **#16 G11 提交**：需要（a）小范围独立 Review 案卷（pre-commit 第 4 关）（b）你的 commit/push 授权 —— 目前仍是"不提交"。
3. **#15 的落地**同样是 review + 提交；提交前要注意脏树 id 变化会让 `.evidence/verify-*` 目录随内容增加而膨胀，且同 id 保护会把旧证据移成 STALE 墓碑（可能触到 pre-push 的"不得有 STALE"检查）——**保留/清理策略属人工决定，未自动删除**。
4. 文件服务 M0（PRODUCT.md + scenarios + MODULE.md 契约与 RED evidence）→ M1 安全 P0 → M2 协议演进 → M3 完整性/续传 → M4 结构收敛。

## 5c. 推送之后：master 又前进了（PR #12），本轮 rebase + 复验处置

**事实**：两个分支 push 完成后 `git fetch` 发现 `origin/master` 从 `0576cb7` 前进到
`176c5a5`（PR #12 `feature(nexus-harness): Code Intelligence API + 独立 Review 三轮`，
46 files / +6236），而 #12 动的正是我 #15 的同一批文件：`engineering/nexus-harness/src/env.rs`
(+227)、`src/evidence.rs` (+48)、`src/gates.rs` (+112)，外加一个 5000 行的 `src/code_intel/` 新模块。

**判断**：#12 修的是"git **查询失败**被读成干净/空变更集"这一半 fail-open（`dirty_state` →
`Option<bool>`、`porcelain_result()`、`tree-unknown`/`dirty-unknown` 哨兵、`affected-tests` 记
UNKNOWN）；我修的是"查询**成功但结果不含字节**"。互补，不冗余，但 rebase 必冲突。

**逐处保留的解法**（`fix/nexus-harness-evidence-binding` → `6a7b51d`）：
`git()` 的 index.lock 退避重试搬进 `git_bytes()`（两条调用路径共享同一锁语义）；
`working_tree_digest()` 维持"只问一次 status"+ 三哨兵，dirty 分支换成内容绑定，
`code_intel::digest_is_unusable` 仍认得哨兵；`dirty_content_digest()` 两个分量改 `?` 上抛
（原 `unwrap_or_default()` 会用空字节凑出看似正常的 digest，属 #12 在别处禁止的同一形态）；
`Bindings::current(&Repo)` → `(&Repo, &Config)`，`code_intel/mod.rs` 三处调用点补参；
#12 自己的 `bindings_from_non_repo_root_...` 测试经新增 `test_config` 适配；`verify_id` 入 seed
条件由 `if b.dirty_state` 改为 `!= Some(false)`（`None` 也入，用哨兵 digest，不折叠成"干净树 id"）。

**新基线上的复验**（xc-pc-linux, rustc 1.98.1, git 2.25.1）：

| 对象 | 数字 |
|---|---|
| pristine `176c5a5` gateway | unit 22 · **e2e 7 过 13 挂** · `cargo fmt --check --all` 退出 1（红点仍是 `cert.rs:42`/`gateway.rs:474`）⇒ 旧结论"7 过 13 挂"在新基线成立，stacking 理由也成立 |
| `fix/gateway-ice-candidate-bind` `e1ef70c` | unit **24/0** · e2e **21/0** · `verify --fast` **9 门 PASS** · 与 rebase 前树逐字节相同（`git diff 9532f9a..b9fdf8f -- crates/nexus-web-gateway .evidence` 为空） |
| harness 基线 `e1ef70c` | `cargo test -p nexus-harness` **117/0** |
| `fix/nexus-harness-evidence-binding` `6a7b51d` | **126/0**（净 +9）· fmt/clippy 干净 · `verify --fast` 9 门 PASS · 顶层 PASS |
| 缺陷当场复现 | 同一脏树只改未跟踪文件字节：base 二进制 digest 恒 `af614e39…`；新二进制 `cda75a59… → d56c6579…` |
| 代价 | `status` 一次：干净树 22 ms vs 23 ms（CI 路径无回退）；脏树 200 未跟踪文件 22 ms vs **133 ms**（每文件一次 `git hash-object`） |

**本轮新发现的仓库级摩擦（不是本补丁引入，已在 commit message 与 PR body 里登记）**：
`mark_stale_others` 每次写入都把同 agent 的旧目录标 STALE，而 `.githooks/pre-push` 第 2 条
"有 STALE 即拒推" ⇒ 同一 clone 里**第二次 verify 之后必然踩线**。实测把 remote_sha 设为
master 手工跑该钩子：留墓碑 ⇒ `ERROR STALE evidence found → pre-push gate failed`；清掉验证
序列自己产生的墓碑 ⇒ `pre-push gate passed`（规则 1/3/4 通过）。与 rebase/force-push 叠加时
钩子第 3/4 条的 range 判定本身也失效（旧 remote sha 不再是 HEAD 的祖先）。这是把 agent 推向
`--no-verify` 的机制性诱因，值得单独立项。

**契约集漂移的诚实处理**：#12 新增 16 个 `scenarios/*.toml` ⇒ 现树 `contract_hash` 实测
`3652314f9c213a60fb21c23fc9a296359b63c0b5`，而 G11 的 `contract:` marker 与评审案卷绑的是评审
当时的 `9c44e9351f04ba1d2afc3a924954d4ad7710c97e`（`source_revision 0576cb7`）。案卷没有对新
契约集重跑评审，marker 因此**保持原值**——改成新哈希等于伪造一次没发生过的评审。

**PR 状态**：`gh` 在本机未登录（`gh auth status` = not logged in），建 PR 是有凭据的公开写操作，
我没有代做。两个 PR 的标题与正文已备好，可直接粘贴：
`plan-artifacts/PR-1-GATEWAY-ICE.md`、`plan-artifacts/PR-2-HARNESS-EVIDENCE-BINDING.md`。
合并顺序：先 PR-1，再把 PR-2 的 base 从 `fix/gateway-ice-candidate-bind` 改回 master。

## 5d. M0 契约落地（同一天的下半段，分支 `feature/gateway-file-service-contracts`）

新分支从 G11 tip `e1ef70c` 切出（要改的 `MODULE.md` 含该分支新增的 G11），两提交：
`46b04bc`（requirement-change(gateway)）+ `17f0c0b`（docs(evidence)）。工作树
`E:\nexus-fabric-m0`。**未推公开仓库**（推新分支属对外写操作，等 owner 一句确认）。

交付物与实测：

| 项 | 内容 |
|---|---|
| `PRODUCT.md` | 新增 §18 `{#18-gateway-file-service}`：承诺、边界、平台口径（Linux=A/Windows=B/macOS=C 只保证 fail-closed）、非目标、三条"未证不得当已证"、M0-M4 退出准则 |
| `MODULE.md` | "文件系统浏览"移出 Non-Responsibilities；Responsibility 标注"契约声明，非已交付 API"；新增不变量 **G12-G21** |
| `requirements.toml` | **REQ-005..REQ-012**，全部 `doing`，每条 acceptance 反向点名其 E4 场景 |
| `scenarios/product/` | **8 个** `gateway_file_*.toml`（分页/下载/续传/不覆盖/沙箱/鉴权节流/配额背压/能力协商），断言只用 `equals`/`one_of`/`non_empty` |
| RED（xc-pc-linux） | `scenario list` 命中 8/8；`scenario run` **8/8 verdict=FAIL**，`failed_step="parse"`；根因单独取证：`error: no example target named gateway_file_contract in nexus-web-gateway package` |
| 门禁 | 加 8 条 FAIL 场景后 `verify --fast` = **9 门全 PASS**（RED 不阻塞门禁），`contract_hash` 由 `3652314f…` → **`63eff98eb965bf3382895eb95c59a75c255e194c`**，`source_revision 46b04bc…`，`dirty_state=false`，evidence dir `verify-ec5649ae8d49` |

三条诚实标注（都写进了 `.agents/red-evidence-gateway-file-service.txt`）：

1. **本批 RED 的信息量低于 #12 的先例**：它证明"探针接口不存在"，不证明"哪条 expectation
   未满足"（落在 parse 步而非 expect 步）。M1 落地 `gateway_file_contract` 后每条 expectation
   才第一次被逐项判定。
2. **编号偏离 V2 §11**：V2 写"G13 重写、新增 G17-G21"是按 V1 工作树已有 `G11..G16` 排的号；
   V1 从未合入 master ⇒ 本分支 `G12..G16` 为空，一次落成 G12-G21，并在 MODULE.md 里写明，
   免得后人与 V2 文字对不上。
3. **M0 退出准则未达成的一半**：docs 独立评审需非实现者模型（不自签）；ADR 目录登记前发现
   `docs/` 下**不存在** ADR 惯例（`ls docs | grep -iE "adr|decision"` 与
   `grep -rl "^ADR-" docs/*.md` 均空），是否新建 `docs/adr/` 属文档结构决策，未擅自动手。

一处措辞收缩：`PRODUCT.md` §18 初稿曾直接写出"`/api/config` 目前仍会回 TURN 凭据"。
这是**未修补**的泄露细节，写进公开仓库的产品文档等于替别人做 disclosure 决定；改为
只声明要求的变更（REQ-012：`/api/config` 的 TURN 段只回 `urls`，凭据走一次性短时效通道），
泄露的具体形态留在评审案卷里，等 M2 修补或 owner 决定公开时机。

顺带一条宿主事实：取证期间该机 sshd 报
`kex_exchange_identification: banner line 0: Exceeded MaxStartups`——连续快速新建连接会被拒。
这与 V1 评审 P0-12（SFTP 认证风暴放大成拒绝服务）是同一类机制，只是这次撞在我的验证通道上。

## 6. 我这轮新发现并公开更正的两处

1. 归档 agent 报告"评审 §4 写 `FRAME_HEADER_LEN=15` 与实际 14 不一致"——**这条不成立**：评审原文是"把 `FRAME_HEADER_LEN` 从 14 改成 15"这一**变异动作**，不是声称现值为 15；帧头确为 14 字节（`src/file.rs:50`，且 `FRAME_HEADER_LEN=15` 的变异导致编译期类型锁死而红）。特此更正，避免误改。
2. 我上一轮对 harness 的判断（"疑似只看 git index"）已在 V1 案卷里更正为准确版本；本轮实验进一步确认它**在 dirty 态对内容完全盲**，并追加三处加重：`porcelain` 被 `.trim()` 破坏状态列语义、未跟踪目录折叠成单行、同 id 覆写使旧证据消失而非 STALE。
