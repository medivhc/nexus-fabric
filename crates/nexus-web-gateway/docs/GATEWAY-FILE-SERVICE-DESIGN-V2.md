# nexus-web-gateway 文件服务 · V2 设计方案

> 状态：设计稿 **rev2.1**（design），2026-10-11 · 任务类型：**requirement-change（契约阶段）**，不含实现代码。
> rev2.1 = 针对第一轮独立评审 CHANGES_REQUESTED 的 8 条必改项 + 2 条顺带项的修订，
> 逐条处置见 **§14 评审意见处置表**；owner 已固化的决策见 **§13 已定决策**（原 §12 中 D0/D1/D2/D3/D4/D5/D7/D8
> 不再作为开放问题）。append-only 纪律（下方引文）自**批准编号入 `docs/adr/` 之日起**生效；
> 本稿尚未获批准、尚未编号，属可修订案卷。
> 形态：本文件属 **L3 决策层**（`docs/DOCUMENTATION-ARCHITECTURE.md:15`）。该体系 §2 的 YAML 保鲜
> frontmatter **仅适用于 L1/L2**（"L3/L4 不用此格式，见 §3"，`DOCUMENTATION-ARCHITECTURE.md:24`）；
> L3 用 ADR 形态（日期、背景、决策、备选、后果）且 **append-only、只被取代不修改**
> （`DOCUMENTATION-ARCHITECTURE.md:67-71`）。上一版案卷自造 `layer: L3-decision` / `created:` 字段
> 正是元评审 FAIL 项（`FILE-MODULE-REVIEW-2026-10-11.md:40`，角度 18），本卷按规矩纠正。
> 正式 ADR 由 owner 在本设计批准后提取编号入 `docs/adr/`（目录尚未建立，登记随 M0 一并做，已定决策 D0 见 §13）；
> 本卷是候选 ADR 的母稿。
>
> 裁决依据：18 角度独立评审 16 FAIL（`FILE-MODULE-REVIEW-2026-10-11.md`，下称【评审】）、
> rev2.1 修订依据 = 第一轮 CHANGES_REQUESTED 必改 8 条 + 顺带 2 条（逐条处置见 §14），
> 与实现者案卷含两条公开更正（`FILE-MODULE-VERIFICATION-2026-10-10.md:89-96`，下称【案卷】）。
> 权威契约锚：`docs/N3-4-ARTIFACT-DELIVERY.md:54-66`、`docs/N3-9-ARTIFACT-CLI-CONTRACT.md:9-12`、
> `docs/N3-6-LOCALAPI-SECURITY-CONTRACT.md`、`docs/N3-8-CAPACITY-SESSION-CONTRACT.md:11`、
> `PRODUCT.md:3186/3220/3244-3246`、`ARCHITECTURE.md:41-50/89-90/107-115/117-125`、
> `crates/nexus-web-gateway/MODULE.md`（G1..G16）、`AGENTS.md` §4/§5/§7/§13-§15/§19.1、`harness.toml`。

## 0. 决策记录总览（ADR 候选，§1–§12 各为一条）

| # | 决策 | 一句话 |
|---|---|---|
| A1 | 权威关系选 **(b)∪(a)**：网关自有 wire，字段同名同义引用 N3-4/N3-9 + 双向一致性测试；**不**下沉 nexus-delivery | §1 |
| A2 | 句柄/流模型：**服务端签发 stream_id**、按已解析目标缓存句柄、显式 close_stream、字节+数量双上限 | §2 |
| A3 | ack/背压：列表分页 `entry_offset/next_offset/eof`、单消息 64 KiB 硬上限、分优先级有界队列 | §3 |
| A4 | 健壮性：`checked_*` 全域 + panic-free-by-construction（release `panic=abort` 下 unwind 防线**不存在**，改 profile 与否属 owner 待批，见 §13-D7） | §4 |
| A5 | 安全：SFTP 逐分量 lstat/readlink deny-by-default、`.part` 服务端命名 + EXCL、TOCTOU 快照类型化（本地 (dev,ino)/Windows 降级/SFTP 元数据）、会话级+全局令牌节流、`/api/config` 去凭据 + 建 PC 前短时效凭据端点、SFTP 复用+熔断、SFTP 提交显式 no-replace flags | §5 |
| A6 | 配额：全局浏览器会话/fd/RSS/磁盘/摘要重算预算全清单 + `validate()` 交叉闭合公式 | §6 |
| A7 | 兼容：`version` 协商 + capability 门控建通道 + 帧头保留位 + FileTarget **显式 kind 校验**（非反序列化失败） | §7 |
| A8 | 可观测：composition root 装 subscriber；生命周期/拒绝 INFO；每帧 0 日志、5 s 汇总 | §8 |
| A9 | 平台矩阵：Windows=密码认证+本地沙箱（**B 级**，§13-D3），macOS=全量，`\\?\`/mode=0 写进契约 | §9 |
| A10 | 测试：资源核算测试 + 变异必红清单 + CI 真跑的 JS↔Rust golden fixture + hermetic 化 + SFTP no-replace 一致性探针 | §10 |
| A11 | 分期 M0–M4 与回滚：wire 只加不改、无超前 stub、每期独立可 revert；M0 补 scenario+RED 前置 | §11 |
| A12 | 待决策仅剩 D6；D0-D5/D7/D8 已固化 | §12/§13 |

---

## 1. 权威关系（A1）——三选一论证与选定

**问题**：N3 已冻结"字节分页 + 断点续传 + 内容校验 + 原子发布"的权威语义
（N3-4:54-66：私有暂存目录、跨进程 receiver lease、写页 fsync 后原子保存 `offset/prefix_sha256`、
完整 SHA-256+长度后存 Publishing intent、同文件系统 `hard_link` 原子不覆盖发布；
N3-9:9-12：`offset/max_bytes/next_offset/eof` 分页、每页 64 KiB、Artifact 上限 80 MiB）。
V1 网关文件面字段名同构而保证更弱、零内容校验、互不引证（【评审】P1-语义分裂 :121-125），
且仓库并存第三种帧格式（`apps/nexusd/src/sync_transport.rs:6-7`：`u8 type|u32 BE len|payload`，
`MAX_FRAME=64 KiB` 同 :37）。

**备选与论证**：

- (a) 网关纯接入、字节面完全复用 Artifact 语义。语义上正确（读=已授权字节页、
  写=prefix_sha256 续传 + SHA/长度后 intent），但 Artifact 的**持久 authority 侧**（catalog、
  receiver lease、intent journal，N3-4:30-42）绑定 daemon Task 语义；浏览器不是 LocalAPI 客户端
  （N3-6:24 单一路由 `POST /localapi/v1/task`），网关 std-only 无 async（MODULE.md:63）。
  整体复用被 N3-9:8 的平台门（仅 Linux 接收器）进一步卡死。
- (b) 网关自有 wire，但**字段同名同义显式引证 N3-4/N3-9** + 双向一致性测试。
- (c) 下沉 `nexus-delivery`（现为 8 行 stub，`crates/nexus-delivery/src/lib.rs:1-8`）。三条硬约束
  反对现在做：① `ARCHITECTURE.md:89-90` 规定 `nexus-delivery --> nexus-domain` 且 :107-115 禁反向依赖
  Workspace/Compute 业务；② `harness.toml:72-87` 把 nexus-delivery 列入 portable core
  （WASI 门），塞进 str0m/ssh2/std::fs 即违宪；③ 网关 MODULE.md:66-71 禁止依赖任何 Nexus 内部 crate。
  下沉是 Delivery Infrastructure 装配完成后的动作，不是文件模块 V2 的前置。

**选定：(b)，并把 (a) 的四条语义逐条搬进网关自有协议**：
① 分页字段改名对齐 `entry_offset/next_offset/eof`（§3；N3-9:9-12 的 offset/next_offset/eof 同名）；
② 上传续传携带 `prefix_sha256`，服务端只对逐字节一致的重放页回执（N3-4:57-59、
`apps/nexus/src/artifact_download.rs:136-145` 的"完全重复旧页必须逐字节匹配、跳跃/部分重叠拒绝"）；
③ `write_end` 升级为 **expected_size + expected_sha256 校验通过后才发 intent、再发布**（N3-4:62-63）；
④ 发布=原子不覆盖，**两条提交路径都要闭死**：
(a) 本地：提交用 `std::fs::hard_link(part, target)`，目标已存在 → `OUTPUT_EXISTS`
（N3-4:63-64、`PRODUCT.md:3220`"默认拒绝覆盖文件，SHA-256 校验后原子发布"、
artifact_download.rs:190-192）。V1 的 `fs::rename`（`src/file.rs:602`）**会静默覆盖**既有目标，
与自身 `rename` 操作的拒覆盖语义（file.rs:650-651）分叉——废除。
(b) **SFTP（rev2.1 补，评审必改①）**：V1 提交走 `sftp.rename(part, final, None)`
（`src/file.rs:906-911`），ssh2 0.9.6 的 `rename` 在 `flags=None` 时**默认取全部
RenameFlags**，其中含 `OVERWRITE`（`ssh2-0.9.6/src/sftp.rs:407-409`；位定义 :135-146：
`OVERWRITE=:139 / ATOMIC=:142 / NATIVE=:145`；其 doc :405 明言 "If no flags are specified
then all flags are used"）⇒ 只修 (a) 则远端仍会静默覆盖，④ 的"不覆盖"承诺半边落空。
V2 规定：SFTP 提交**必须显式传 `Some(RenameFlags::ATOMIC | RenameFlags::NATIVE)`（不含
OVERWRITE）**，并叠加三道工程防线：
(i) 提交前 `lstat(final)` 已存在 ⇒ 直接 `OUTPUT_EXISTS` 拒绝（best-effort 预检，存在竞态窗口）；
(ii) rename 目标侧父链逐分量过 §5 符号链接解析算法（本节第 2 条修订）；
(iii) **服务端 honor 与否是未知数，不得写成已证事实**：SFTP v3 协议对 rename-to-existing
的行为属"implementation-defined"，libssh2 的 flags 是否经 `posix-rename@openssh.com`
扩展送达并被 OpenSSH portable sftp-server 尊重，**需实测**。实测方法（M1 门槛、CI 本地
sshd，逐步记录进案卷）：主机上放 `A.txt`（内容 AAA）与 `B.txt`（内容 BBB），探针程序调
`sftp.rename(A, B, Some(ATOMIC|NATIVE))`；判定：返回 Err 且 B 内容仍 BBB、A 仍在 ⇒
no-replace 成立；B 变 AAA 且 A 消失 ⇒ 静默覆盖（不 conform，对照组：flags=None 应必现覆盖）。
覆盖被测版本串（`ssh -V` + sftp-server 路径，至少 OpenSSH 8.9/9.x/当前发布版各一次）。
实测不 conform 的部署：SFTP 提交语义降级为"预检 + 尽力而为"，写进 G14 修订文本与运维
手册（启用前跑探针），**不伪称协议级保证**。`docs/N3-4:63-64` 的 hard_link 模型在远端
不可用（ssh2 未暴露 `hardlink@openssh.com`），此为与 N3-4 的声明差量之一。

**代价**：字段"同名同义"仍是两套码；一致性靠测试而非类型系统保证（缓解：§10 golden fixture 与
artifact_download 行为表逐条对照的语义测试）。依赖事实纠正（rev2.1，评审必改④前半）：本卷旧文
"新增 `sha2` 依赖"**过时且错误**——`sha2 = 0.10` 已在依赖表中（`crates/nexus-web-gateway/Cargo.toml:29-30`，
REQ-001 引入，现用于 `/cert` 指纹 `src/cert.rs:42-49`），摘要/续传**零新增依赖**；并同步
ssh2/SFTP 能力面评审条目（【评审】:126-128）。V2 潜在新增依赖仅两处、均属条件项：
`hmac`（仅 D4 短时效 TURN 凭据实装时，§5/§13-D4）、`windows-sys`（仅未来 Windows 升 A 级时，
§9/§13-D3）；两者许可证均 MIT/Apache-2.0 在 allowlist（`policies/dependencies.toml:14-23`），
但须过 `require_architecture_layer_review`/`require_os_transitive_dependency_review`（同文件 :11-13）。

## 2. 句柄与流模型（A2）——含 fd/RSS 上界推导

**V1 病灶**：浏览器自选 stream_id 且每分片自增（`static/app.js:124,1196,1259`）；后端按
stream_id 缓存读句柄（`src/file.rs:497-515,814-831`）、认领表 `file_streams` 按 stream_id 插
（`src/gateway.rs:1836`），只在会话释放时清（file.rs:656-662/998-1004）⇒ 2 GiB/64 KiB = 32 768
次 `File::open`，实测第 1022 片 EMFILE 并锁死节点前门（【评审】P0-2 :52-58）。

**V2 模型**：

- **stream_id 由服务端签发**。浏览器命令 `file_read{session_id, req_id, path, offset, len}` /
  `file_write_begin{…}` 不带浏览器自选 id；节点为每个打开的目标分配 `stream_id: u32` 并在
  ack 中回显（`FILE_WRITE_BEGIN_ACK{stream_id, received}`）。浏览器无法伪造/抢占他人流
  （V1 的跨会话 stream 抢占属【评审】:154 装饰区）。**同路径并发写互斥（§13-D8）**：服务端对
  每个已解析 canonical 目标持活动上传锁，锁未释放时后到的 `file_write_begin` 即拒
  （`TARGET_LOCKED`）——提交时 no-replace 只防最后一步覆盖，防不了两路 `.part` 交错抢同一目标。
- **读句柄按"已解析目标"缓存**：`HashMap<TargetKey, ReadHandle>`，`TargetKey` 按平台分档
  （rev2.1，评审必改④，细节见 §9/§13-D3）：local·Unix/macOS = `(dev, ino)`（std 稳定
  API `std::os::unix::fs::MetadataExt`）；local·Windows = **casefold 后的 canonical path 串**
  （std 拿不到卷号+文件索引：`volume_serial_number`/`file_index` 至今 gated by unstable
  feature `windows_by_handle`，本机 rustc 1.95.0 编译探针实测 `error[E0658]`，tracking issue
  rust-lang/rust#63010；workspace MSRV `rust-version = 1.85`，根 `Cargo.toml:61`，更不可用）——
  句柄去重仅在"同路径未被换出"前提下成立，残余风险登记 §9；sftp = 规范化远端路径 +
  lstat 元数据快照。同文件多 offset 读复用句柄；LRU 上限
  `max_read_handles = 8 / 文件会话`，超限逐出**最旧且非当前请求**句柄（逐出=Drop=关 fd，无需浏览器配合）。
- **显式 `close_stream{stream_id}`**（`FileCommand::CloseStream`）：释放读句柄或中止上传态并从
  `file_streams` 认领表删除条目；读侧 EOF（final 标志）自动回收；每流独立空闲 60 s 回收。
- **每文件会话限额**（字节+数量，均入 `FileLimits`，`src/config.rs:133-156` 扩展）：
  `max_read_handles=8`、`max_upload_streams=2`、`max_buffered_bytes_per_stream=1 MiB`（=16 片，
  64 KiB 默认分片，config.rs:102）、`max_buffered_bytes_per_session=4 MiB`、
  每会话发送排队 `max_queued_bytes=4 MiB`（§3）。
- **超限的确定性错误**：新增类型化错误码（wire 字段 `error.code`，见 §3）——
  `QUOTA_HANDLES`、`QUOTA_STREAMS`、`QUOTA_SESSIONS`、`BUFFERED_LIMIT`（仅拒**本片**，
  已 ack 前缀不动，浏览器按 ack 的 `received` 停发等待排空）、`FD_EXHAUSTED`（retryable）、
  `PATH_RACE`（§5 快照复核不符）、`TARGET_LOCKED`（§13-D8：同 canonical 目标已有活动
  上传流时后到者拒，retryable）、`RESUME_DENIED`（§6 rehash 预算耗尽）。
  一律"显式失败、不静默丢弃"（G16，MODULE.md:113-115）。

**上界推导（真实数字；rev2.1 按评审必改⑧把"浏览器会话数"从隐含常数改为显式全局配额）**：

- fd：单浏览器会话最坏 = WSS(1) + 文件会话 4（config.rs:149，**per-session**，代码实证
  `sess.file_sessions.len() >= cfg.max_sessions` gateway.rs:1892；终端同理
  `sess.ssh_bridges.len() >= cfg.ssh.max_terminals` gateway.rs:1537）×（读句柄 8 + 上传
  part ≤2 + SFTP TCP socket 1 + 事件通知管道 2）≤ 4×13+1 = **53 fd**。此数**只有在网关
  全局并发浏览器会话上限下才闭合**：新增 `files.max_browser_sessions = 8`（§6；旧文把
  `max_file_sessions_total=32` 当全局闸是错觉——32 只是 8×4 的派生值，浏览器会话本体此前
  无上限）。全局文件面 fd ≤ 8×53 = **424**，加终端/监听/UDP 基线，对 Linux 默认
  `ulimit -n 1024`（【评审】:8 实验宿主同值）留 ≥512 余量——**8 个浏览器即打满预算，
  这是自述数字的诚实推论，§6 validate() 交叉约束把它固化为启动校验**。网关自维护
  **登记式 fd 计数**（open/close 唯一入口），预算耗尽先拒后开——不新增 libc 依赖，读不到
  rlimit 就把 `files.fd_budget` 当配置事实（默认 512），文档写明残余。
- RSS：worker 线程栈 2 MiB（Rust std 默认）+ 单次读缓冲 ≤ chunk_bytes（默认 64 KiB、硬上限
  256 KiB，config.rs:105，与 §3 SCTP 预算联动钳制）+ 排队字节 ≤4 MiB + 乱序缓冲 ≤4 MiB +
  ssh2 会话缓冲 ≈0.5 MiB ⇒ **每文件会话默认 ≤ ~11 MiB**；全局 ≤ 8×4×11 ≈ **352 MiB**
  文件面增量。**但 352 MiB 只在默认值成立**：§6 允许 per-stream 4→16 MiB、
  per-session 缓冲/排队各到 16 MiB，最坏单文件会话 ~37 MiB ⇒ 32 会话 >1 GiB。V2 因此
  新增 `files.rss_budget_mib = 512`（§6），`validate()` fail-closed 校验
  `max_browser_sessions × max_sessions × worst_case(每会话各上限) ≤ rss_budget_mib`，
  上限组合超预算即拒启动——不允许"默认安全、配置即爆"。2 GiB 下载对服务端
  RSS 的影响 = 每会话预算常数（拉取式、逐片，V1 的 `Upload.buffered` 无界问题
  file.rs:1109-1116/1416-1419 由字节配额封死；【评审】P0-5 :73-74 实测 1 GiB 路径不存在）。
- 磁盘（rev2.1 补，旧文整个缺失）：暂存 = `max_upload_streams × max_upload_bytes` 最坏
  2×2 GiB/文件会话，全局最坏 64 GiB——不可接受。新增 `files.max_staging_bytes_total = 8 GiB`
  （§6）：`file_write_begin` 声明 expected_size 时**预留**配额（全局 AtomicU64 加减，终态释放），
  超限 ⇒ `QUOTA_STORAGE`（retryable）。std-only 无法跨平台查剩余磁盘（无 libc，statvfs/
  GetDiskFreeSpaceEx 均不可用）⇒ 真实 ENOSPC 以写失败 errno 上抛计入 `write_ack.error`，
  "配额账本≠磁盘实况"作残余风险登记。
- 浏览器侧 2 GiB 全量驻内存（【评审】:38 前端角度）：下载改为流式写 `File System Access API`
  `createWritable()`，不可用时回退分片 Blob 顺序拼接，任何时刻驻留 ≤ 64 片（4 MiB）。

## 3. ack 与背压（A3）

**目录列表分页**（修【评审】P0-3 :60-64）：
`file_list{session_id, req_id, path, entry_offset, max_entries}` →
`file_list_ack{session_id, req_id, path, entries, next_offset, eof, error}`。
字段名对齐 N3-9:9-12 的 `offset/max_bytes/next_offset/eof`（此处按条目序号而非字节，语义同构：
`next_offset` = 下一页起点条目号，`eof` = 已到尾）。`max_entries` 默认 256、服务端钳到 1024；
**单消息序列化硬上限 64 KiB**（=N3-9:10 每页 64 KiB 同值；亦低于 Chrome 单条 DataChannel
文本消息实测上限，【评审】:61"＞2520 条即超"）：超限时按已装入的条目截页并回 `next_offset`，
绝不产生超限消息。排序在节点固定（file.rs:337-341），页间不保证快照一致——文档化为
"允许并发修改的弱一致枚举"，浏览器按 `entry_offset` 幂等合并。

**SCTP 发送预算事实（rev2.1 必改⑤，显式写进设计）**：str0m 0.24.1 的发送预算默认
`DEFAULT_MAX_BUFFERED_AMOUNT = 128 KiB`，注释明言"**across all streams**"
（`str0m-0.24.1/src/sctp/mod.rs:28-32`）；`available()` 把**同一 association 全部 open
stream 的 buffered_amount 求和**后从这**一个** `max_buffered_amount` 里扣
（同文件 :601-618）⇒ 信令通道与文件通道（G15：同一个 SDP 里两条 SCTP stream，
MODULE.md:111-112 禁 renegotiate）**共享同一份发送预算**。而 `files.chunk_bytes` 允许配到
256 KiB（`src/config.rs:105`）：一旦协商出 256 KiB 级帧（256 KiB+14 > 128 KiB），该帧在
服务端**永远写不下**——旧文"永久性头阻塞在协议层不可能"据此**不成立**，撤销。

**控制通道不可送达时的降级（修订版）**：
V1 病灶：`flush_send_queue` 对 `Ok(false)` 只 break 且保留队首并每 tick 克隆整条 10 MB 消息
（`src/gateway.rs:1159-1174`）。V2：
1. **帧尺寸 ≤ 可用预算是"无永久头阻塞"的前提，须由配置校验保证**：新增
   `files.sctp_send_budget_bytes`（默认 4 MiB），Rtc 构建时经既有 API
   `RtcConfig::set_sctp_max_buffered_amount` 下发（`str0m-0.24.1/src/config.rs:700`，默认
   装配 :896、应用 :lib.rs:1263）；`validate()` fail-closed 校验
   `sctp_send_budget_bytes ≥ 2×(chunk_bytes+14)×在途上限 16 + 信令余量 256 KiB`
   （默认 64 KiB 片：2×78 KiB×16+256 KiB ≈ 2.75 MiB ≤ 4 MiB ✓；256 KiB 片则须 ≥8.5 MiB，
   不满足即拒启动——`chunk_bytes` 与预算不再互不知情）。浏览器侧 SCTP 发送预算的对称上限
   （Chrome 实现值）**需实测**（§10），实测前上传方向在途按 16 帧×(chunk+14) 钳制。
2. `send_queue` 拆为**两类预算**：终端/信令类（`max_signaling_queue_bytes` 默认 1 MiB，
   新全局上限，rev2.1 补——旧文"不限"是把 DoS 面转嫁给 SCTP 预算）与文件元数据类
   （≤256 KiB）。文件类队满 ⇒ 拒收新的入站文件命令（`QUEUE_FULL`, retryable=true）、
   丢弃**最旧**文件类消息并记 INFO 汇总计数；信令类**不静默丢弃**（G9 语义保持），
   其队列超 1 MiB 且宽限 30 s 内排空失败 ⇒ 判定对端失联/路径拥塞，**显式关闭该浏览器会话**
   （`SESSION_BACKPRESSURE_CLOSED`，随会话回收释放全部资源）——把"永不丢"的无限堆积换成
   有界降级路径。
3. 浏览器侧按 `req_id`+超时重发（拉取式语义使丢包天然可恢复，§7）。

**二进制帧长度上限与 `chunk_bytes` 双向协商**：
浏览器在 `file_open` 携带 `max_inbound_chunk_bytes`（浏览器能收的最大帧）；服务端取
`min(files.chunk_bytes, max_inbound_chunk_bytes, 预算允许值)`——预算允许值 = 满足上文
校验式 `budget ≥ 2×(chunk+14)×16 + 256 KiB` 的最大 chunk（rev2.1：三方取小，256 KiB
配置上限在预算不足时**不得**进入协商；病灶 config.rs:105 与 128 KiB 默认预算的矛盾由
`validate()` 与协商双重封死）。生效值在 `file_open_ack.chunk_bytes`（现字段：
`src/protocol.rs:239-247`，
现填充：gateway.rs:2234）中回显并附 `max_frame_bytes = 协商值 + 14`。**入站**超上限帧 ⇒ 立即
拒绝该流（`write_ack{error: FRAME_TOO_LARGE}`）并丢弃缓冲；V1 入站 chunk 上限是装饰区
（【评审】:154），列入 §10 变异必红清单。帧头 `kind|stream_id(4)|offset(8)|flags(1)` 14 字节
（file.rs:49-50）保持，offset 有效域钳 `[0, 2^53-1]`（JS 双 32 位拼 64 位精度上限；
N3-8:11 "Checked arithmetic is bounded by 2^53-1" 同款纪律），越界即 `OFFSET_INVALID`。

**浏览器 `bufferedAmount` 使用**（写入侧契约）：上传在途未 ack 帧 ≤16（1 MiB），且
`channel.bufferedAmount > 512 KiB` 时暂停喂帧，回落后再续；下载（读请求）在途 ≤8 片、
`bufferedAmount` 同样门控服务端反压提示。此规则写入 §10 的 JS 契约测试。

**请求级 `req_id`**（修【评审】P0-8 :90-93）：所有文件控制消息携带浏览器自增 `req_id`，
所有 ack 回显；前端 waiter 以 `(type, req_id)` 精确匹配，废除广播 resolve
（`app.js:896 pumpFileWaiters`）。P0-7 的 waiter 卡死同批修：`resetFileSession`
（app.js:979）与通道 onclose/`reconnect()` 路径必须**全量 reject** 挂起 promise，`fileBusy`
在 `finally` 中必然复位。

## 4. 健壮性（A4）

- **算术**：文件面所有 `offset + len` 一律 `checked_add`（病灶：`src/file.rs:1387`；
  连带 1404/1432/1440 的推进）。统一走 `fn checked_end(offset: u64, len: usize) ->
  Result<u64, FileError>`；配套 clippy `arithmetic_side_effects = "deny"` 作用于
  `file.rs`/`gateway.rs` 模块级，把纪律机器化。
- **worker 生命周期**：8 处 `thread::spawn`（gateway.rs:503,507,522,997,1256,1575,1674,1919）
  全部改为：保存 `JoinHandle` 入 `FileBridge`，事件循环检测 `is_finished()`
  ⇒ 向该浏览器会话投 `FileClosed{reason:"worker_panic", code:"WORKER_PANIC"}` 并
  清理其句柄/流/缓冲（对应 AGENTS.md §13 结构化并发：有 Owner、有回收；§14 恰一次终态）。
  debug/test 构建额外把线程体包 `catch_unwind(AssertUnwindSafe(run_file_worker))` 以拿到
  结构化错误——**rev2.1 明确：这不是发布版的防线**（见下），不得据此声称 panic 已被"隔离"。
- **`panic = "abort"` 下的诚实结论（§13-D7 已固化）**：workspace release profile 设
  `panic = "abort"`（根 `Cargo.toml:68`）。因此 **catch_unwind 防线只存在于 debug/test/CI；
  发布版任一 worker panic = 整个节点进程 SIGABRT**（实测 exit 134，【评审】P0-4 :69）。
  暴露面 = "任何一条畸形帧触发 panic ⇒ 杀死该节点全部终端/文件/信令会话"。V2 的对策不是
  假装 unwind 有效，而是把 **panic-free-by-construction 升为设计要求**：
  ① 外部输入路径上禁止 `unwrap/expect`（decode_frame 现存两处 `expect("checked length")`
  file.rs:132-133 可保留——先判长度后取，列入审计清单）；所有切片索引/换算走
  `checked_*`/`get(..)` 风格 totality；
  ② 帧解码/配额判定/分页裁剪全部写成 totality 风格的纯函数并以 fuzz（`fuzz/` 已有目录）
  覆盖 `decode_frame + stage_chunk`；fuzz 面扩到 `Rtc::handle_input` 的外部可控输入
  （畸形 STUN/DTLS/SCTP/SDP）——**str0m 内部残余 assert/unwrap 面不受我方代码控制**，
  fuzz 发现即列附录并上游报改，未决前该输入路径 M1 不放行；
  ③ debug 构建的 overflow-panic + catch_unwind 测试作为"发布前红"探针。
  **是否把网关宿主二进制 profile 改为 `panic="unwind"`（用体积换隔离）= owner 待批项**，
  本设计不预设答案、不以 ①-③ 冒充该问题的解决（§13-D7 残余子项）。

## 5. 安全模型（A5）

- **SFTP 符号链接策略：逐分量解析算法**（修 P0-1；rev2.1 必改②——旧文"全面改 lstat"不可
  实现：SFTP 无本地路径遍历原语，服务端在远端解析整条路径，客户端只对**每一分量**独立
  lstat 才能阻断跟随。算法，`root`=home，`rel` 已按 G13 规范化为分量序列 `c1..cn`）：
  1. 游标 `cur = root`。对每个前缀 `p = c1..ci`（i=1..n）：`sftp.lstat(p)`
     （`ssh2-0.9.6/src/sftp.rs:304`；FileStat.permissions 判 S_IFLNK/S_IFDIR/S_IFREG）。
  2. lstat 失败且 i<n（分量尚不存在，创建场景）⇒ 后续分量必然也不存在，停止遍历，进入
     "新建路径"分支；lstat 成功且为 **dir** ⇒ `cur = p` 继续；为 **regular** 且 i<n ⇒
     `NOT_A_DIRECTORY` 拒绝；为 **symlink** ⇒ `sftp.readlink(p)`（`sftp.rs:357`）取原始目标
     仅作审计日志，随即 **`SYMLINK_DENIED` 拒绝**。
     **策略二选一的选定与理由**：备选"允许指向 home 内的链接、逐分量重新校验"被否——
     链接目标可能绝对、可能指向另一台机器的挂载视图，客户端要判定"目标在 home 内"必须对
     目标路径**再跑一遍同一算法**且需递归+环检测；`realpath`（`sftp.rs:361-363`）由**服务端**
     解析、不产生可复核的中间分量，等价于把信任重新交还给要防御的对象。故取
     **deny-by-default 唯一实现值**；`files.sftp_symlink_policy` 仅 `deny`，预留 `report`
     命名空间不实现（Deletion Test，AGENTS.md §12）。
  3. 终分量 `cn`：lstat 存在且为 regular ⇒ 读/覆盖拒绝路径按 §1④ no-replace；为 dir ⇒
     目录操作；**为 symlink ⇒ `SYMLINK_DENIED`**——封掉"home 内**已存在**的链接、终分量
     被 open 跟走"的洞（SFTP open 由服务端解析链接、协议无 O_NOFOLLOW 位；写新建场景由
     `CREATE|EXCLUSIVE` 兜底：目标名已存在即失败，链接也是"已存在"；读场景由本步 lstat
     拒绝，lstat→open 竞态窗口归入下文 TOCTOU 残余）。不存在 ⇒ 新建分支，要求父目录
     （i=n-1 前缀）已确认为 dir。
  4. **`rename` 双侧同样过这套**：src 按 1-3 全量解析；dst 解析到父目录分量（dst 终分量
     lstat 存在 ⇒ `OUTPUT_EXISTS` 预检拒绝，不存在 ⇒ 只校验父链）。`list` 可展示
     `kind:"symlink"`（protocol.rs:113 已有该 kind）但绝不进入。递归 `remove` 改为
     **自底向上 + 每子项 lstat**，遇 symlink 只 `unlink` 链接本身。
  `read/write/mkdir/remove/rename/commit` 仅接受 **regular file 与 dir**，
  symlink/fifo/device ⇒ `SYMLINK_DENIED`（不跟随、不报错降级）。同步修订 MODULE.md G13
  的"SFTP 靠服务端 CWD 约束"伪声明（MODULE.md:103-106；【评审】:50 判 false）。
- **`.part` 不可预测名 + 目录权限**（修 P0-10，【评审】:101-109）：暂存名由**服务端**生成：
  `.nexus-part.<h>`，`h = hex(SHA-256(nonce ‖ stream_id ‖ target_path)[0..16])`；
  `nonce` 在 `file_open_ack` 下发、进程启动时随机化（种子=SystemTime/栈地址/Pid 混合哈希，
  定位是**反预测**而非反共租户——真正边界是下一条）。打开一律 `create_new`
  （本地 `OpenOptions::create(true).truncate(false).create_new(true)`；SFTP
  `CREATE|EXCLUSIVE`）：名字已存在 ⇒ `PART_EXISTS` 拒绝（杜绝 V1 对同名符号链接的截断跟随，
  file.rs:563-567）。本地 root **启动校验**：POSIX 下 root 属主=网关账户且 group/other
  无写位，否则 fail-closed 拒用该 root（错误 `ROOT_INSECURE`），`files.allow_world_writable_roots`
  显式豁免才允许。SFTP 侧同样拒绝把 `.nexus-part.*` 作为任何操作可见名（防止抢占他人暂存）。
- **TOCTOU 缓解三段式（rev2.1 必改③：先补"比对基准"，再谈比对）**：旧文的裂缝在于
  `resolve_within` 现在只返回 `PathBuf`（`src/file.rs:203-217`），"打开后比对 (dev,ino)"
  没有快照可当基准。V2 把签名改为返回 **`Target { path: PathBuf, anchor: PathId,
  final_id: Option<PathId> }`**：
  · `PathId`（本地·Unix/macOS）= 稳定 std `std::os::unix::fs::MetadataExt` 的
  `(dev: u64, ino: u64)`：`anchor` = 最深已存在祖先的 lstat(dev,ino)，`final_id` =
  终分量已存在时的 lstat(dev,ino)（新建文件为 None）；
  · `PathId`（本地·Windows）= **casefold canonical path 字符串**——std 稳定面拿不到
  (dev,ino)（见 §2/§9 与 §13-D3 的 B 级降级），比对退化为"打开后对句柄路径重解析
  canonicalize == 快照串"；
  · `PathId`（SFTP）= lstat 元组 `(size, mode, uid, gid, mtime, atime)`——ssh2 的 FileStat
  不暴露远端 inode/fileid（`hardlink@openssh.com`/`positional` 类扩展未接入），这是**弱基准**，
  同大小同 mtime 的替换可骗过，残余风险显式登记（SFTP 后端的真实边界是远端账号自身）。
  **比对时机**：(a) 打开既有文件：open 返回 fd 后立即 `fstat`（本地 `File::metadata()`；
  SFTP `File::stat()`），fd 的 `PathId == final_id` 比终分量身份；fd 无"父目录句柄"可读，
  故 anchor 复核 = 对 `path.parent()` 重新 canonicalize+lstat 与快照比对（父链被换 inode
  而终分量 (dev,ino) 不变的情形由这一步兜住）；(b) 新建（create_new 成功）：对句柄 fstat
  得新 `PathId` 写回缓存 + 父链 anchor
  复核同上；(c) rename/commit 前：对 src/dst 各重跑一次 resolve-with-snapshot 并比对旧快照。
  **不符** ⇒ 关闭、重试一次（重新 resolve 取新快照）；仍不符 ⇒ `PATH_RACE` 拒绝（新增类型化
  错误码，入 §2 错误清单）。②打开最终分量时 unix 加 `custom_flags(O_NOFOLLOW)`（Linux
  `0x20000`、macOS `0x100`，平台常量表见 §9；先例 artifact_download.rs:277 用
  `0x20000|0x800`），Windows 无等价位 ⇒ `create_new` + §5-root 权限要求 + 本条降级方案；
  复核先例：receiver-lease artifact_download.rs:258-263。中间目录组件竞态作为**已声明
  残余风险**写入 G13 修订文本（前提：root 及链上目录非他方可写，由启动校验保证）。
- **令牌失败节流与最小熵（修 P0-6 局部，【评审】:79-83；rev2.1 必改⑦：节流键换成真实
  可得的标识）**：旧文键 `(源 IP, rtc 会话)` **不可实现**——`src/gateway.rs` 全库不采
  `peer_addr`（grep 零命中，WSS/TLS accept 丢弃了对端地址），str0m 侧 `remote_addrs` 是
  `Rtc` 私有字段（`str0m-0.24.1/src/lib.rs:916`）不可读。V2 键改为两层、均有界：
  ① **会话级**：失败计数器直接挂在 `Session` 结构体字段上（10 次失败/60 s 滑动窗口 ⇒
  锁定该会话 `file_open` 300 s）——**不存在全局映射表**，生命周期随会话回收，条目数
  被 `max_browser_sessions`（§6）封顶，节流表本身不可能成为新 DoS 面；
  ② **全局桶**：跨会话累计失败（AtomicU64 计数 + 窗口切换，O(1) 状态）超 100 次/60 s ⇒
  对**所有** file_open 注入指数退避延迟（100 ms 起、上限 2 s）并 INFO 告警——弥补
  "攻击者可无限新建会话"时会话级键的空白。IP 维度**不做**；若未来确需，先给 WSS accept
  加 `TcpStream::peer_addr()` 采集（小改造，属 requirement 变更，不在 V2 范围）。
  `validate()` 新增 `files.auth_token` 长度 ≥24 且非常量前缀（熵下限 fail-closed）；
  锁定与失败计数各为 INFO 审计事件；比较保持常量时间（gateway.rs:1887 现状保留；同规
  N3-6:32）。
- **`/api/config` 整改 + TURN 凭据时序自洽**（修 P0-6 局部，G1 既有面；rev2.1 必改⑥）：
  现端点未鉴权即回 `ice_servers`（含 TURN username/credential，`src/config.rs:34-41`；
  `gateway.rs:599-619`，ice_servers 在 :604）与节点拓扑。**旧 V2 案（凭据随 `hello_ack`
  经已建立的控制通道下发，gateway.rs:2425-2431/:2429）不成立，撤销**：浏览器在
  `new RTCPeerConnection({iceServers})` **构造时**就要拿到全部 ICE 服务器
  （`static/app.js:285`；`app.js:321-325` 的 init() 先 fetch `/api/config` 再建 PC 可证时序），
  而控制通道在 ICE 成功 + DTLS + SCTP 之后才存在，`hello_ack` 更晚；且网关禁 renegotiate、
  数据通道与首通道必须同一 SDP（MODULE.md:111-112）⇒ 事后补凭据既来不及也无法重建 PC，
  该方案**不可能工作**。V2 改为（§13-D4 已固化）：
  ① `GET /api/config` 收缩为
  `{node_id, node_name, page_addr, ice:{urls[]}, files:{enabled, version, capabilities[]}}`
  ——ICE **只回 URL，username/credential 字段不进入序列化结构**（类型级封死，测试断言响应体
  不含 `credential` 子串，§10）；`files` 子对象保留为 §7 capability 门控的唯一发现面（回滚
  判据④依赖它，§11）；节点拓扑（`node_list`）不再整包外泄。
  ② 需凭据 TURN 时，页面在建 PC **之前**追加一次 `POST /api/turn-credentials`（同一 HTTPS
  端口，与 fetch /api/config 同批 await，满足 ①-PC 构造的时序）：部署侧 coturn
  `use-auth-secret`，网关按 HMAC-SHA1(secret, `unix-exp:tag`) 派生时效 ≤1 h 的一次性
  username/credential 返回；长期凭据永不出配置边界。请求须携带 WSS 握手时服务端签发的
  连接级随机 `grant-nonce`（绑定"活着的 WSS 连接"，无 nonce ⇒ 403），全局令牌桶限
  5 次/分、突发 10——授权性核算与 §5 节流同一"会话级+全局桶"纪律，无新表。诚实代价：
  HMAC 时效凭据在 TTL 内**可被截获者重放**（coturn 语义如此，"一次性"仅在"每 nonce 只发
  一份 + 短 TTL"意义上成立；严格单次需服务端已用集合，V2 不做并登记残余）；需新增
  `hmac` crate 依赖（sha1 已在依赖表 Cargo.toml:28；§1 依赖治理）。
  ③ 二选一的另一半：若 owner 认为端点复杂度不可接受，则**明确"不支持需凭据的 TURN"**——
  `/api/config` 仅回 `stun:` URL，需 TURN 的部署直接失败并给出显式错误文案（不静默降级
  成无 TURN 直连）；代价 = NAT 严格对称场景不可达，M3 前由 D4 已批的 ② 方案默认，③ 为
  备选收缩位。
- **SFTP 连接复用与全局限流**（修【评审】角度 9：84 次握手/秒可触发目标 sshd faillock）：
  复用键 `(rtc 会话, ssh.target, SHA-256(认证材料指纹))`，每浏览器会话 SFTP 连接 ≤2、
  空闲 TTL=`files.idle_timeout_secs` 内跨文件会话共享（键不同绝不共享，G4 凭据不落盘不变，
  MODULE.md:81-83）；全局令牌桶 `2 次握手/秒` + 并发 `8`；对同一 target 连续 5 次失败
  ⇒ 60 s **熔断**（`TARGET_BACKOFF`, retryable=true）。G3 不变量重述：文件字节仍只在
  浏览器↔节点间走 DataChannel，SSH/SFTP 协议只在节点↔sshd（MODULE.md:78-80）。

## 6. 配额体系（A6）

对齐 `SshConfig.max_terminals` 的纪律：默认值 + `validate()` fail-closed（0 即拒启动，
config.rs:357-361 模式）。完整清单（`files.*` 新字段除注明外均属 V2 新增）：

| 维度 | 键 | 默认 | 校验 |
|---|---|---|---|
| **全局并发浏览器会话** | `max_browser_sessions`（新，rev2.1 必改⑧：fd/RSS 推导此前把浏览器数当隐含常数） | 8 | ≥1；§2 推导仅在此闸下成立 |
| 浏览器会话并发文件会话 | `max_sessions`（config.rs:149 已有，**per-session**，gateway.rs:1892 实证） | 4 | ≥1 |
| 全网关文件会话 | `max_sessions_total`（新，派生值 8×4，启动校验两者积一致，不一致 fail-closed） | 32 | ≥1 |
| 每文件会话读句柄 | `max_read_handles`（新） | 8 | ≥1 |
| 每文件会话上传流 | `max_upload_streams`（新） | 2 | ≥1 |
| 每上传流乱序缓冲 | `max_buffered_bytes_per_stream`（新） | 1 MiB | ≤4 MiB |
| 每会话乱序缓冲 | `max_buffered_bytes_per_session`（新） | 4 MiB | ≤16 MiB |
| 每会话出帧排队字节 | `max_queued_bytes`（新，文件通道） | 4 MiB | ≤16 MiB |
| 信令/终端出队全局上限 | `max_signaling_queue_bytes`（新，§3） | 1 MiB | ≥256 KiB；超限走会话关闭降级 |
| 控制消息文件类预算 | `max_control_queue_bytes`（新） | 256 KiB | ≤1 MiB |
| SCTP 发送预算（全通道共享） | `sctp_send_budget_bytes`（新，§3；`set_sctp_max_buffered_amount` 下发） | 4 MiB | ≥ 2×(chunk+14)×16+256 KiB |
| 单条 JSON 消息 | 协议硬上限 | 64 KiB | 不可配 |
| 上传总量（每文件会话） | `max_upload_bytes`（config.rs:151 已有） | 2 GiB | 语义改：连续前缀+缓冲之和 |
| **全局暂存磁盘配额** | `max_staging_bytes_total`（新，§2 磁盘维度，write_begin 预留/终态释放） | 8 GiB | ≥ max_upload_bytes |
| **全局 fd 预算** | `fd_budget`（新，§2 登记式计数） | 512 | ≥ max_browser_sessions×53 |
| **全局 RSS 预算** | `rss_budget_mib`（新，§2 公式） | 512 | ≥ max_browser_sessions×max_sessions×最坏每会话 |
| **每流摘要重算预算** | `max_rehash_bytes_per_stream`（新，防 CPU DoS，见下） | 16 MiB | ≤256 MiB |
| 上传全量流式摘要 | （每字节恰一次哈希，O(n)） | — | 受 max_upload_bytes 约束 |
| 提交/续传全文件摘要重算 | `max_digest_bytes`（新） | 80 MiB | 对齐 N3-4:39/N3-9:10；语义见下"矛盾闭合" |
| 列表页条目 | `max_list_entries_per_page`（新） | 256 | 受消息上限再钳 |
| 空闲回收 | `idle_timeout_secs`（config.rs:155 已有） | 300 | ≥1；语义改（下） |
| 每流空闲回收 | `stream_idle_secs`（新） | 60 | ≥1 |
| SFTP 握手令牌桶 | `sftp_handshake_rate`（新） | 2/s | ≥1 |
| SFTP 并发握手 | `max_sftp_handshakes`（新） | 8 | ≥1 |
| 令牌失败窗口 | `auth_fail_limit/window/lockout`（新） | 10/60 s/300 s | 另加全局桶 100/60 s（§5） |

**配额闭合（rev2.1，评审必改⑧ + 顺带项）**：

- **交叉校验 fail-closed**：`validate()` 不再只查单值下限，还查上表三条全局预算公式
  （fd/RSS/SCTP）与各 per-session 上限的**乘积闭合**——旧文"352 MiB"只在默认值成立，
  而表内允许 16 MiB×2 ⇒ 32 会话 >1 GiB；旧文 fd 416 只在"32 文件会话且浏览器数≤8"成立
  而浏览器数无闸。现在把浏览器闸（8）写进表、把乘积校验写进 `validate()`，配置组合打爆
  预算即拒绝启动（同 `max_terminals` 的 0 即拒启动纪律，config.rs:357-361 模式）。
- **80 MiB vs 2 GiB 矛盾闭合**（顺带项①）：`max_digest_bytes=80 MiB`（N3-4:39/N3-9:10 的
  Artifact 上限）与保留的 `max_upload_bytes=2 GiB` 字面冲突。V2 澄清两维度：80 MiB 是
  "**可整体重算/暂存全文件摘要**"的预算上限（用于：断点重开的 prefix 校验、提交时摘要
  复核），不是上传载荷上限；2 GiB 上传靠**流式增量哈希**（每字节恰一次 sha256 update，
  O(n)），**不**为每页重算前缀。二者并存成立，文档与类型注释同步改写。
- **摘要计算成本上限（CPU DoS 封死）**：N3-9 的逐页 `prefix_sha256` 校验若朴素实现
  （每页对"从头到页尾"重算）是**平方级**成本——搬到 2 GiB 上传，攻击者单帧重放即可迫使
  服务端哈希 ~2 GiB（评审 N3-9 角度自认）。V2 规定：增量状态机 `Hasher` 只随**新接受
  字节** update；重放页只允许对"重放区间 ∩ 已接受前缀"做**区间哈希**，其总开销由
  `max_rehash_bytes_per_stream=16 MiB` 封顶，超预算 ⇒ `RESUME_DENIED`（retryable，浏览器
  须整文件重传而非继续续传）——攻击者可迫使的重算量与上传总大小解耦。
- **全局并发会话上限**即表中 `max_browser_sessions=8`：WSS accept 处计数，超限
  `QUOTA_SESSIONS` 显式拒（G16）；终端面 `max_terminals=5` 同为 per-session
  （gateway.rs:1537 实证），全局 40 终端的 fd/线程预算在 M0 场景契约里一并核算。

**真实 idle 语义**（修 P0-5 第二病灶，gateway.rs:1810/1851 被任意命令刷新 + 【评审】:76 实测
idle=3 s 下 `file_stat` 滴灌 15 s 零回收）：`last_activity` 只在**改变会话资源占用**的命令
（开流/传输/提交）上刷新；只读探针（`file_stat`/分页 list 读）不再无限续命；同时
`max_sessions` 与 `max_sessions_total` 的字节配额合计核算使"滴灌保活"无资源可占。

## 7. 兼容与演进（A7）

- **版本与能力协商**：`file_open{version: 2, token, target, max_inbound_chunk_bytes}`；
  `file_open_ack{version, kind, chunk_bytes, capabilities: ["pagination","req_id",
  "server_streams","sha_verify","resume"|"…"…]}`。节点在 `/api/config.files` 暴露
  `enabled + version + capabilities[]`（gateway.rs:608-615 现结构上扩展）。
  版本不匹配 ⇒ `UNSUPPORTED_VERSION` 显式拒绝，不做暗中降级。
- **混版本安全**（修 P0-9，【评审】:95-99）：页面**仅在**目标节点
  `/api/config.files.enabled && version≥2 && capabilities ∋ "server_streams"` 时才在 SDP 里
  创建 `nexus.file` 通道（病灶：app.js:821 无条件建通道；而旧节点
  `ChannelOpen(_,_)` 后开者赢 ⇒ 终端与节点列表整体失联）。旧页面→新节点：新节点保留
  现行的 label 优先 + 无名首通道兜底（gateway.rs:1196-1205 已实现，列为契约不得回退）。
- **帧头演进**：14 字节布局冻结（file.rs:49-50；帧头字节布局是【评审】:150 的硬约束区）。
  `flags` 字节现仅 bit0 有义（`FRAME_FLAG_FINAL`，file.rs:53），bit1-7 **必须为 0**，
  收到置位 ⇒ `FRAME_FLAGS` 拒绝——这是未来扩展位的安全占法。`kind` 空间 0x01/0x81
  （file.rs:45-47），其余 kind 拒绝（decode_frame 已做，file.rs:128-131；补变异测试）。
- **`FileTarget` 演进（rev2.1 顺带项②纠错）**：serde internally-tagged 枚举
  （protocol.rs:94-104）的"反序列化失败即拒"是 **Rust 中心论**——页面是 JS
  `JSON.parse`，未知 `kind` 根本不会抛异常，旧浏览器会**静默吞下**新变体然后带着无法理解的
  目标继续走。V2 拒逻辑改为**双侧显式校验**：① 浏览器把已知 `kind` 当白名单（代码常量表），
  `/api/config` 里未知 kind 的 root/目标一律不呈现并提示"请升级页面"；发送前再查一次白名单；
  ② 服务端只在会话 `file_open` 声明的 `client_capabilities` 包含对应变体标签（如
  `target_peer`）时才接受该变体命令，未声明 ⇒ `UNSUPPORTED_CAPABILITY` 显式拒绝——新变体
  （如未来 `Peer{peer_id, root}` 跨网关文件中继）的"旧浏览器不受影响"由此保证，不靠反序列化
  失败。中继本身仍是 MODULE.md:29-30 声明的 Non-Responsibility，接缝为 `MeshSignaler`；
  V2 不做，但配额与安全模型（令牌按持有会话校验）保证未来变体可沿用同一 worker 模型而不改
  帧格式。

## 8. 可观测性（A8）（修 P1【评审】:131-134）

- **接线**：库不装 subscriber；入口 `examples/gateway.rs` 与未来宿主在
  composition root 安装 `tracing-subscriber`（EnvFilter，默认 INFO）——这是
  【评审】"INFO 下 0 行"的直接整改；subscriber 作为 examples 的 dev-dependency 走
  依赖登记。
- **结构化字段**：`node_id, rtc_session, file_session, stream, backend(sftp|local),
  target_hash, path(仅非热路径,截断 256 B), offset, len, code`。会话生命周期
  （ChannelOpen/Close、file_open 接受/拒绝、配额拒绝、锁定、提交、digest 验证、回收）
  = INFO；错误路径 = WARN；**每帧 0 日志**。
- **周期汇总**：每文件会话 `AtomicU64` 计数（frames_in/out、bytes_in/out、缓冲高水位、
  句柄数、丢弃数），事件循环每 5 s 对**有增量**的会话发一条 INFO 汇总——AGENTS.md §22
  "高频观测优先 counter/aggregation" 的落地。
- **审计最小集**（对齐 N3-6:49"拒绝持久审计"思想，网关侧为进程日志+计数，无 journal）：
  令牌失败与锁定（会话 ID + 全局桶计数；**无源地址**——§5 必改⑦，本节点不采 peer_addr）、
  越权/符号链接/路径竞态拒绝、`remove/rename/提交`成功、
  配额触顶、worker panic。案卷纪律：以上每条都必须有测试产生日志行（§10），
  防止"Observability 声明与现实冲突"复发。

## 9. 平台矩阵（A9）——支持口径是契约，不是注释

> **rev2.1 必改④ 事实纠错**：旧版本表把 Windows 标为"A 级契约保证"，并以
> `(dev,ino)` 式文件身份键（卷号+文件索引）作为该承诺的一部分。**实测不成立**：本机
> rustc 1.95.0（`rustc --version` 核验）编译探针直报
> `error[E0658]: use of unstable library feature 'windows_by_handle'`——
> `std::os::windows::fs::MetadataExt::file_index/volume_serial_number` 仍为 unstable
> （tracking rust-lang/rust#63010），且 workspace MSRV `rust-version = 1.85`
> （根 `Cargo.toml:61`）使其在约束内**永久不可用**。稳定 std 在 Windows 拿不到任何
> 文件级身份键 ⇒ 句柄缓存/TOCTOU 打开后复核（§2/§5）在 Windows 退化为"canonical path
> 串重解析"。按 §13-D3 固化：**Windows 支持等级 = B 级**。

| 能力 | Linux | macOS | Windows（B 级） |
|---|---|---|---|
| SFTP 密码认证 | 契约保证 | 契约保证 | 契约保证 |
| SFTP 私钥认证 | 契约保证 | 契约保证 | **不支持**：ssh2 `userauth_pubkey_memory` 带 cfg 门（案卷:85），调用点须 cfg 门控并回显 `UNSUPPORTED_PLATFORM`（修【评审】角度 11"Windows 编译失败"——现在是整个 crate 编不过） |
| 本地沙箱读 | ✓（A 级：身份键 (dev,ino) + O_NOFOLLOW） | ✓（同左） | **B 级**：可用，但身份复核仅 canonical path 串（无 (dev,ino)、无 O_NOFOLLOW）——reparse point 替换竞态为声明残余 |
| 本地沙箱写/原子发布 | `hard_link` | `hard_link` | `hard_link`（NTFS 同卷支持；跨卷/网络卷失败 ⇒ `COMMIT_LINK_UNSUPPORTED`，不自动降级为可覆盖 rename）+ `create_new` 独占建暂存 |
| `O_NOFOLLOW` | `0x20000` | `0x100` | 无此位；靠 `create_new` + root ACL 要求 + 文档化残余 |
| 文件身份键 `(dev,ino)` 等价物 | `std::os::unix::fs::MetadataExt` | 同左 | **不可得**（见上实测）；替代 = 打开后路径重解析 + `create_new` 等价物（§13-D3） |
| `FileEntry.mode` | 真实权限位 | 真实权限位 | 恒 0 = "未知"（file.rs:450-453 现状**写成契约**：protocol.rs:119 doc 言明 0 为未知，浏览器不得据此授权 UI） |
| 证据基线 | CI/真机全量 | 编译+单测 | 编译+单测（key-auth 用例 cfg skip；B 级残余测试见 §10） |

**依赖策略（若未来要升 Windows A 级）**：唯一现实路径是引入 `windows-sys`
（`GetFileInformationByHandleEx/FileIdInfo`，MIT/Apache-2.0，在许可证 allowlist
`policies/dependencies.toml:14-23`，且 workspace `Cargo.lock` 已含传递依赖 windows-sys
0.52/0.61），以 `[target.'cfg(windows)'.dependencies]` 挂接并过
`require_architecture_layer_review`/`require_os_transitive_dependency_review`（:11-13）。
本 crate 现状（`crates/nexus-web-gateway/Cargo.toml:12-40`）无任何 Windows 专属依赖；
V2 **不引入**，列 M4 后复评。

**P0-12 根治**（【评审】:113-118）：`LocalSandbox::new` 存 **canonical root**（现在存原始
path，file.rs:372-378）；条目回显用存下的 canonical root `strip_prefix`（file.rs:397-407），
Windows 再套 `strip_verbatim_prefix`（`\\?\` 前缀还原为常规盘符路径再渲染 `/`-相对）。
canonicalize 失败 ⇒ 会话打开即 `ROOT_UNAVAILABLE` 拒绝，而非每条目退化。macOS
`/tmp→/private/tmp` 与 Windows `\\?\` 各一条回归测试（§10）。
支持等级终值已由 owner 在 D3 拍板（§13）：**Windows = B 级，上表即 B 级契约文本**。

## 10. 测试策略（A10）

- **资源核算测试**（新增，直接封【评审】角度 5 的四项单会话打挂）：
  ① fd 登记计数器：128 MiB 文件 64 KiB 分片全程下载，断言峰值句柄 ≤ `max_read_handles`；
  Linux 用 `/proc/self/fd` 目录实测交叉验证（test-only cfg(unix)）；
  ② RSS：`/proc/self/statm` 前后差 < §6 配额表推出的每会话预算（测试宿主 ulimit 记录进案卷）；
  ③ 消息大小 property test：10 万条目目录 + 恶意长文件名，**每条**序列化 ack ≤64 KiB；
  ④ 队列：灌满文件类预算，断言 ssh 消息零丢失、文件类显式 `QUEUE_FULL`。
- **变异可杀性清单**（"改坏必须红"逐条列名，终结【评审】§4 装饰区）：
  `sftp.stat→lstat` 反转红（真 sshd symlink PoC：list/read/write/remove 各一条）；
  `checked_add→+` 红（`offset=2^64-1` 溢出用例）；入站 `chunk_bytes` 超限红；
  `create_new→create` 红（预置同名 `.part` 链接）；`O_NOFOLLOW` 移除红（TOCTOU 夹具）；
  `req_id` 错配红（并发 mkdir/remove 交错）；分页 `next_offset` 不单调红；
  capability 门控移除红（JS 契约测试）；`hard_link→rename` 红（目标已存在场景）；
  `prefix_sha256` 跳过红（乱序重放改字节）；idle 刷新语义放宽红（file_stat 滴灌仍回收）；
  令牌锁定移除红；`/api/config` 出现 `credential` 子串红；SFTP 握手限流移除红
  （本地 sshd `MaxStartups` 见证）；**rev2.1 新增**：SFTP 提交 `rename(Some(ATOMIC|NATIVE))
  →None` 红（真 sshd 预置不同内容同名目标，None 必现静默覆盖即红，§1④b）；逐分量解析
  循环 `lstat→stat` 反转红（home 内预置指向 home 外文件的链接）；`rehash 预算` 放宽红
  （恶意乱序重放 2 GiB 声明大小，服务端累计哈希 ≤ `max_rehash_bytes_per_stream` 断言）；
  `validate()` 乘积交叉约束红（16 MiB×32 会话组合拒启动，§6）；节流表有界性红
  （伪造海量会话，断言计数器随 Session 回收清零、全局桶 O(1)，§5⑦）；
  **SFTP no-replace 一致性探针**（§1④b 实测方法入 CI 本地 sshd，输出按 `ssh -V` 版本串
  归档案卷；OpenSSH 各版本是否 honor 无 OVERWRITE flags 属"需实测"项，探针结论进 G14
  修订文本）；**浏览器侧 SCTP 发送预算实测**（Chrome `bufferedAmount` 上限与
  `set_sctp_max_buffered_amount` 对称性，§3①，同样先实测后声称）。未知 file session/stream 显式错误补测试
  （现 8 处零覆盖，【评审】:144-146）。SFTP e2e 的 rename/递归 remove 必须**事后 list 复核**
  （修【案卷】:63-66 降级表述；夹具改为固定远端子目录并在断言后清空，根除残留累积）。
- **JS↔Rust 双侧帧契约，CI 真跑**：单一 golden 文件
  `crates/nexus-web-gateway/tests/fixtures/frame-golden.bin`（含 §7 flags/kind 负例），
  Rust 测试逐字节读它；`node tools/frame-contract.test.mjs` 同样读它断言编解码等价，
  **写进 gateway-ci workflow 的显式步骤并把运行日志存 evidence**——【评审】:172-173
  "CI 会变绿零远端证据"的教训：每期完成判据含一次真实 push 触发的 CI 绿，不接受本地复述。
- **非 hermetic 消除**：删除"候选集合==可路由网卡集合"的自证循环（tests/gateway_e2e.rs 的
  `routable_ipv4s()` 与实现同逻辑，【案卷】§4.2 假测试教训）；改为 `ice_bind_plan()`
  纯函数单测（输入伪造网卡表/绑定地址，断言输出候选集——G11 契约的机器化）；
  测试零外部 STUN、零真实网卡假设（全 loopback）；固定 `sleep` 一律换成事件等待 +
  上限超时（超时报 TEST_TIMEOUT 而非静默继续）；`idle_timeout_secs: 600` 写死导致
  file 空闲路径零覆盖（【评审】:154）——超时测试用 1-3 s 配置并断言回收事件。

## 11. 分期与回滚（A11）

| 期 | 内容 | 阻塞上线? | 交付物 | 退出准则 |
|---|---|---|---|---|
| M0 | **契约前置（rev2.1 扩容，D0/D2 已固化）**：MODULE.md 修订（G13 重写、新增 G17 分页/G18 配额/G19 能力协商/G20 完整性/G21 审计）；REQ-005..009 改口径 + **REQ-006"不覆盖"按 requirement-change 走冻结文本修订并先行落 scenario RED**（D5，§13）；**`PRODUCT.md` 网关能力锚点 + `scenarios/` 场景契约新建**（当前两文件网关命中数实测为 0）；ADR 目录与编号登记（D0）；依赖登记**纠错**：sha2 已存在（Cargo.toml:29-30，无需新增），条件新增仅 `hmac`（D4）与 fuzz 目标；SCTP 预算公式与 §6 交叉校验入配置契约；SFTP no-replace 探针方案入验收 | 是 | 契约 diff + contract hash + **scenario 文件 + RED 证据**（`harness.toml:46-48` `contract_first.red_evidence_required = true`；AGENTS.md 阶段 A :343/:351"先改 scenarios 再实现"） | docs 独立评审 + `verify --fast`（protected paths：`harness.toml:110-118`）+ **RED 证据齐备（无 RED 不进 M1）** |
| M1 | 安全/可用性 P0 收口，**零新 wire 语义**（仅加 `req_id`）：P0-1/2/4/5/6/7/8/10/12 全项 + worker JoinHandle 监控 + §5 逐分量解析/快照类型化/节流两层键 + 变异可红测试同批；panic 面 fuzz（含 str0m 输入面）先于放行 | 是 | 代码+测试+`.evidence/review-gateway-file-r<n>` | check→affected→`verify --fast`→**独立** Review（§19.1 八维，非实现者）→`verify --full` |
| M2 | 协议演进：分页、服务端签发 stream、capability 门控建通道（P0-9）、版本协商、`/api/config` 收缩（只回 urls） | 是 | 同上 | 同 M1；额外：混版本 e2e（新页×旧节点、旧页×新节点）、`/api/config` 凭据子串扫描红 |
| M3 | 完整性与续传：sha2 流式摘要（零新依赖）、prefix 区间哈希 + rehash 预算、不覆盖发布（本地 hard_link + SFTP 显式 flags，探针结论达标后才声称）、REQ-006 口径（D5 已批）、TURN 短时效凭据端点（D4 已批；若 owner 收缩则改走 §5③"不支持需凭据 TURN"） | 否（可后置） | 同上 | 同 M1 + N3-9 语义一致性测试全绿 + no-replace 探针归档 |
| M4 | 结构收敛：双引擎读循环合并、跨引擎语义统一（mkdir/flush/part，【评审】:132-137）、SFTP 连接池、nexus-delivery 复评（D1 结论：不下沉，仅复评）、windows-sys 升 A 级复评（§9 依赖策略） | 否 | refactor 类，外部行为不变 | 同 M1 |

顺序纪律：每期都走 `nexus-harness check → test affected → verify --fast → 独立 Review →
verify --full`（AGENTS.md §19/§19.1），Review 超 3 轮不收敛升级人工（AGENTS.md §19.1 迭代上限）。

**回滚**：① 运行时 kill-switch：`files.enabled=false`（默认值，config.rs:135，G12 fail-closed
语义不变）；② wire 只加不改 ⇒ 新节点回滚旧二进制后，页面 capability 检查失败自动退化为
无文件模式（`/api/config.files` 缺字段 = 旧版 = 不建通道，§7）；③ 每期 = 一条任务分支
squash-merge（AGENTS.md §30.2），放弃 = 单条 `git revert`；④ **无半成品 wire**：任何消息
字段只随实现它的里程碑落地，M3 砍掉则 `file_digest/expected_sha256` 等定义**不预先存在**；
⑤ 服务器端唯一持久物 `.nexus-part.*`：root 打开时清扫（超过 `max(mtime)` 24 h 即删），
放弃功能不留下无法解释的远端残留（对照【案卷】:66 残留累积教训；N3-4:66"回收需显式
生命周期策略"同样成立）。

## 12. 待决策清单（A12）——rev2.1 收缩后仅存开放项

原 D0–D8 中 D0/D1/D2/D3/D4/D5/D7/D8 已由 owner 固化为决策（见 §13，不再是开放问题），
本表只保留仍未拍的项：

| # | 问题 | 本设计默认倾向 |
|---|---|---|
| D6 | `files.auth_token` 是否并入 REQ-003 访问认证统一设计（G12 的立论前提"REQ-003 未落地"，MODULE.md:99-102；REQ-003 口径问题见【案卷】§7.3） | 并入，但 M1 不等待——令牌+节流先行 |

（D7 的**残余子项**仍待批——"是否把网关宿主 profile 改 `panic=unwind`"，主体已固化见 §13-D7；
`grant-nonce` 端点的限速参数量级（5/min）属运维调参，不列为契约决策。）

## 13. 已定决策（owner 已固化，2026-10-11）

以下不是开放问题；实现与后续评审**不得**把它们重新翻出，只能按条目执行或在有新增证据时
走 requirement-change 重开。

| # | 已定内容 | 落到 |
|---|---|---|
| D0 | 网关文件面能力进 `PRODUCT.md` + `scenarios/`，作为 **M0 交付物**（原 D2"是否进"并此关闭；ADR 目录登记同批） | §11-M0 |
| D1 | **不下沉** `nexus-delivery`：MODULE.md:66-71 禁内部 crate 依赖 + harness.toml:72-87 portable-core/WASI 门双重硬阻；但网关字段与语义**强制对齐** `docs/N3-4-ARTIFACT-DELIVERY.md:54-66` 与 `docs/N3-9-ARTIFACT-CLI-CONTRACT.md:9-12`，并加**双向一致性测试**（网关↔N3 各跑对方行为表） | §1/§10/§11-M4 |
| D3 | **Windows 支持等级 = B 级**：仅密码认证 + 本地沙箱；`(dev,ino)` 类身份键在 Windows **不可得**（rustc 1.95.0 实测 `windows_by_handle` unstable + MSRV 1.85，§9）——用"打开后路径重解析 + `create_new` 等价物"替代，残余风险（reparse 替换竞态、句柄缓存同路径假设）**明写**，不再声称 A 级契约保证 | §2/§5/§9 |
| D4 | **`/api/config` 的 ICE 部分只回 `urls`**（`files:{enabled,version,capabilities}` 子对象保留作 §7 门控/§11 回滚判据）；TURN 凭据走**建 PC 前**的一次性短时效端点 `POST /api/turn-credentials`（grant-nonce 门 + 全局令牌桶 + HMAC TTL≤1 h）；备选收缩位 ="不支持需凭据的 TURN"（代价：对称 NAT 不可达、显式失败）。两者皆满足"PC 构造时需要 iceServers"的时序（app.js:285/321-325），**hello_ack 方案已废**（§5⑥） | §5/§11-M2/M3 |
| D5 | **"上传不覆盖已存在目标"按用户可见语义变更处理**：走 requirement-change——改 REQ-006/PRODUCT.md:3220 冻结文本 + **先有 scenario RED** 才动实现；与"wire 只加不改"的调和：wire 层只是把 `write_end` 的既有 ack 错误码空间填上 `OUTPUT_EXISTS`（字段只加），语义收紧发生在**服务端行为与契约文本**层，不改任何既有字段含义 ⇒ 不违"只加不改"；旧页面在新节点上得到的是显式错误而非静默行为漂移 | §1/§11-M0 |
| D7 | **不靠 `catch_unwind` 假装解决问题**：release profile 为 `panic = "abort"`（根 Cargo.toml:68），设计上要求 **panic-free-by-construction**（`checked_*`、外部可控路径无 unwrap/expect、显式列举 str0m 内部仍可能 assert 的面并 fuzz 到其输入边界）；**是否改 profile 属 owner 待批子项，不得含糊**（§4） | §4/§10 |
| D8 | **同路径并发写**：服务端签发 stream_id（§2）+ **目标路径锁**——同一 canonical 目标已有活动上传流时，后到的 `file_write_begin` 直接拒绝（`TARGET_LOCKED`, retryable），不再"只靠提交时 no-replace 兜底"（旧 D8 倾向作废：no-replace 只防最后一步覆盖，防不了两路交错写两个 `.part` 抢同一目标的资源与语义混乱） | §2/§5 |

## 14. 评审意见处置表（rev2.1，第一轮 CHANGES_REQUESTED）

| # | 评审必改项 | 处置 | 改到 | 残余风险 |
|---|---|---|---|---|
| 1 | SFTP 提交漏 no-replace（`rename(...,None)` 默认含 OVERWRITE） | 采纳：④拆 (a)本地/(b)SFTP，显式 `Some(ATOMIC\|NATIVE)`（不带 OVERWRITE）+ 预检 lstat + **服务端是否 honor 标"需实测"**并给出探针实测方法（版本矩阵入案卷） | §1-④b、§10、§11-M3 | OpenSSH 各版本行为未知；实测不 conform 时 SFTP 不覆盖仅"尽力而为"；libssh2 flags 是否经扩展送达服务端未证 |
| 2 | SFTP 符号链接策略不可实现 | 采纳：写成逐分量 lstat/readlink 算法（含"二选一"选定=deny 与理由、home 内已存在链接/终分量放行洞、rename 双侧同检） | §5 第 1 条 | lstat→open 竞态窗口（SFTP 无 NOFOLLOW 位）；远端账号本身即威胁主体时算法失效（边界声明） |
| 3 | TOCTOU"比对 (dev,ino)"缺基准 | 采纳：定义快照类型 `Target{path,anchor,final_id}`，PathId 分平台（unix=(dev,ino) 稳定 std；Windows=canonical 串，指向 D3；SFTP=元数据弱基准），三种比对时机与 `PATH_RACE` 错误码 | §5 第 3 条、§2 TargetKey | 中间目录竞态仍为声明残余；SFTP 弱基准可被同元数据替换骗过 |
| 4 | Windows 身份键不成立 + sha2 依赖描述过时 | 采纳：Windows 全面降 **B 级**（rustc 1.95.0 编译探针 E0658 实证 + MSRV 1.85），§9 表与措辞全部改 B 级并给出未来升 A 的 `windows-sys` 路径与依赖策略；§1"新增 sha2"更正为**已在依赖表**（Cargo.toml:29-30，cert.rs:42-49 在用） | §9、§2、§1 代价段、§13-D3 | B 级下 Windows 句柄缓存/复核仅路径串；`windows-sys` 方案未经评审引入前不可用 |
| 5 | 帧上限 vs 128 KiB 共享 SCTP 预算 | 采纳：把"两通道共享单一预算"事实写进设计（str0m sctp/mod.rs:28-32,601-618 实证）；新增 `sctp_send_budget_bytes` + `set_sctp_max_buffered_amount`（config.rs:700）+ `validate()` 乘积校验 + 三方取小协商；信令队列也加全局上限与"超宽限显式关会话"降级；撤销"永久头阻塞不可能"的无条件断言，改为带前提结论 | §3、§6 表 | 浏览器侧 SCTP 发送预算对称上限**需实测**；预算调大对弱网排队时延的影响未量化 |
| 6 | TURN 凭据经 hello_ack 与时序冲突 | 采纳：撤销 hello_ack 方案；D4 固化为"config 只回 urls + 建 PC 前一次性短时效端点（grant-nonce 门、全局限流）"，备选"不支持需凭据 TURN"及其代价写明（app.js:285/321-325、MODULE.md:111-112 实证） | §5 第 5 条、§13-D4 | HMAC 时效凭据 TTL 内可截获重放（coturn 语义）；新增 `hmac` 依赖待依赖评审 |
| 7 | 节流键含不可得的源 IP | 采纳：换"Session 内嵌计数器（无全局表，随会话回收）+ 全局 O(1) 桶退避"两层；peer_addr 不采（grep 实证）、remote_addrs 私有（str0m lib.rs:916 实证）写明；§8 审计字段同步去掉"源地址" | §5 第 4 条、§8 | 无限新建会话的攻击由全局桶延迟缓解、非消除；跨会话慢速爆破仍可低成本试探（每连接一次会话配额） |
| 8 | 配额未闭合 + M0 前置缺失 | 采纳：新增 `max_browser_sessions=8`（fd 推导显式化：8×53=424≤512）、`rss_budget_mib`/`fd_budget`/`max_staging_bytes_total`（磁盘维度旧文全缺）/`max_rehash_bytes_per_stream`（平方级重算→区间哈希+预算封顶，解耦 2 GiB）；`validate()` 乘积交叉 fail-closed；D3/D4/D5/D7 升为 M0 前置，M0 交付物补 scenario+RED（harness.toml:46-48 实证；scenarios/、PRODUCT.md 网关命中 0 实测），退出准则"无 RED 不进 M1" | §2、§6、§11-M0、§13 | 磁盘账本≠磁盘实况（std-only 无 statvfs）；40 终端全局 fd/线程预算仅登记待 M0 场景核算 |
| 顺① | 80 MiB vs 2 GiB 自相矛盾 | 采纳：两维度拆分（全文件重算预算 vs 载荷上限 + 流式 O(n) 增量哈希），写入 §6"矛盾闭合" | §6 | >80 MiB 文件断点重开的校验强度降级（区间+增量，非全量重算复核） |
| 顺② | "旧浏览器反序列化失败即拒"系 Rust 中心论 | 采纳：改为双侧显式 kind 白名单 + `client_capabilities` 门控，点明 JSON.parse 对未知 kind 不抛 | §7 末条 | 白名单滞后的旧页面升级依赖人工；capability 谎报由服务端命令面拒绝兜底 |

## 附：P0/P1 → 章节追溯

P0-1→§5/§9/§10；P0-2→§2；P0-3→§3；P0-4→§4；P0-5→§2/§6；P0-6→§5；P0-7/8→§3；
P0-9→§7；P0-10→§5；P0-11→§1/§5/§13-D5；P0-12→§9；P1 语义分裂→§1；依赖治理→§1/§10；
可观测→§8；重复分叉→§11-M4；SFTP durable 谎称→§2/§10（flush 错误必须上抛计入
`write_ack.error`，本地每 append flush、SFTP 提交前强制 flush 并核对远端 size）；
IPv6 候选→§10（bind plan 纯函数化，G11 契约不变）；产品锚点→§11-M0/§13-D0；
案卷过度声称→§10/§11（远端 CI 证据入退出准则）；frontmatter 不合规→本卷头部。
rev2.1 必改①→§1-④b/§10；②→§5 逐分量算法；③→§5 快照类型/§2；④→§9/§2/§1 代价段；
⑤→§3 预算段/§6；⑥→§5 config 段/§13-D4；⑦→§5 节流段/§8；⑧→§2/§6/§11-M0/§13；
顺①→§6 矛盾闭合；顺②→§7 FileTarget 段。
