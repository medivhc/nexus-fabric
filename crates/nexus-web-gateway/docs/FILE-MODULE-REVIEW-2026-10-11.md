---
doc-id: nexus-gateway-file-module-review
layer: L3-decision
owner: review-orchestrator-agent
created: 2026-10-11
reviewed-against: 0576cb73a802256604088f6accd4917b245c3945 + 未提交工作树改动
review-executors: 18 个独立 Agent 会话（一角度一个，互不通信；模型绑定由用户在 Qoder 应用侧设置，编排者无法自证所用模型）
review-hosts: 读码 Windows 10/11（rustc/cargo 1.95.0, Git Bash MINGW64, git 2.46.0.windows.1）；实验 xc-pc-linux（Linux 5.15.0-139-generic Ubuntu 20.04, rustc/cargo 1.98.1, OpenSSH_8.2p1 internal-sftp, ulimit -n 1024, nproc 20）
status: current
verdict: 不适用 —— 本文是发现汇总，不是 .evidence Review 案卷，不能用于满足 .githooks/pre-commit
---

# nexus-web-gateway 文件模块 · 18 角度独立评审汇总

**结论先说**：18 个角度里 **16 FAIL、1 WARN、1 COMMENTED**，没有一个角度给 APPROVED/PASS。
按本次变更直接引入的可利用问题算，**这份实现不能上线，也不该提交**。下面每条都给了
`文件:行号` 与取证方式；标 **[自验]** 的是我（编排者）亲自读码/查依赖源码复核过的。

## 1. 角度状态

| # | 角度 | 状态 | 一句话结论 |
|---|---|---|---|
| 1 | 契约一致性 | FAIL | REQ-006 续传是空头承诺；符号链接 root 破坏 path 回显；G12 与 REQ-003 互相矛盾 |
| 2 | 产品归属 | FAIL | 与 N3-4/N3-9 的 Artifact 交付契约语义分裂，且零内容校验；PRODUCT.md/scenarios 无锚点 |
| 3 | 帧协议/stream 语义 | FAIL | 读句柄与认领表无界；乱序重叠缓冲可致永久不可提交；SFTP ack 声称 durable 实未 flush |
| 4 | 并发与线程 | FAIL | worker 零 panic 隔离 + 发布版 `panic=abort` ⇒ 单条畸形帧可全节点 SIGABRT；UDP 每轮只收 1 包 |
| 5 | 资源与内存 | FAIL | 4 项单会话即可打挂节点：fd 耗尽、buffered RSS 1 GiB、发送队列无界、大目录死锁控制通道 |
| 6 | 错误语义 | FAIL | `offset+len` 溢出绕过上限并污染状态；前端 waiter 不 reject ⇒ 面板永久卡死 |
| 7 | 威胁模型 | FAIL | 令牌爆破零节流；`/api/config` 未鉴权泄露 TURN 凭据与 root 名单；审计零记录 |
| 8 | 路径沙箱绕过 | FAIL | **SFTP 后端完全不认符号链接（可删 home 外整棵树）**；`.part` 名可预测；TOCTOU 已实测逃逸 |
| 9 | DoS 与配额 | FAIL | SFTP 每会话新建握手 ⇒ 84 次认证/秒可锁死目标账号 faillock；全局配额缺失 |
| 10 | 测试强度 | FAIL | 变异测试证实 6 类"改坏不红"装饰区（含 G13-SFTP、G14-e2e、G9 应答）；JS 侧无契约测试 |
| 11 | 可移植性 | FAIL | Windows 编译失败；Windows/macOS 下嵌套条目 path 系统性退化；"不依赖平台专用 API"不实 |
| 12 | 复杂度与重复 | FAIL | 两引擎读循环逐字节重复；part 命名/mkdir/flush 跨引擎语义分叉 |
| 13 | 依赖边界与治理 | FAIL | ssh2 能力面从 pty 扩到 SFTP+std::fs，`policies/dependencies.toml` 无评审条目，且现有门禁抓不到 |
| 14 | 协议演进与兼容 | WARN | 配置向后兼容 OK；混版本（新页面+旧节点）会整体失效是高危；帧头无版本位 |
| 15 | 可观测性 | FAIL | `file.rs` 1936 行 0 日志；运行入口不装 subscriber ⇒ 默认与 INFO 配置下全哑 |
| 16 | 前端实现 | FAIL | fd 泄漏、waiter 卡死、ack 错配、2 GiB 下载全量驻内存、Files 按钮连错节点 |
| 17 | 证据链 | COMMENTED | 5/7 条数字逐字节复现一致；但 harness 证据绑定对内容无效、"CI 会变绿"零远端证据 |
| 18 | 案卷元评审 | FAIL | 我的案卷存在过度声称（SFTP e2e 只断言 ack）、风险清单漏 3 项、frontmatter 不合体系 |

## 2. 阻塞项（P0，必须先修，按危害排序）

**P0-1 SFTP 后端符号链接逃逸（最高危）** [自验]
`src/file.rs:733-740` 的 `remote_path` 只做 `normalize_rel`，从不解析链接；`:938-941`/`:969` 判目录用 `sftp.stat`
（libssh2 `LIBSSH2_SFTP_STAT` 跟随符号链接），而 ssh2 0.9.6 明明提供 `lstat`（`sftp.rs:304`）。
真机 PoC（评审 #8，root=远端 home）：`list("/link")` 列出 home 外目录、`read_at` 读到外部内容、
`part_open+commit` 在 home 外写出文件、`mkdir` 在 home 外建目录、`remove(...,recursive=true)` **删掉 home 外整棵树**。
→ MODULE.md 的 G13"符号链接也出不去"与"SFTP 靠服务端 CWD 约束"两句 are false。修法：SFTP 侧一律 `lstat` +
拒绝非 regular/dir，或明确把 SFTP 的沙箱责任写进契约并取消"逃逸不可能"的措辞。

**P0-2 下载分片泄漏 fd，单会话打挂整个节点** [自验，4 个角度交叉命中]
`app.js:1196` 每个分片 `fileStreamSeq++` 用新 stream_id；`src/file.rs:497-515` 以 stream_id 为键缓存
`File::open` 句柄，只在会话 `release()` 时清；`src/gateway.rs:1836` 每片再往 `file_streams` 插一条。
实测（#5 probe1 / #9 T3B）：**第 1022 片 EMFILE**（ulimit 1024），此后同节点 `file_list` 报 os error 24、
新浏览器 WSS 连接 125 µs 失败、裸 TCP connect 1.8 µs 失败 ⇒ **一个令牌用户下载 63.8 MiB 就锁死节点前门**。
SFTP 侧本地 fd 不涨，但每片在远端 sshd 新开一个 SFTP handle/远端 fd。修法：path 相同即复用句柄 +
`close_stream` 显式释放 + 每会话句柄/条目上限。

**P0-3 大目录一次 list 让控制通道永久死锁** [自验读码 + #5 #6/#9]
`FileListAck` 无分页、无大小上限（10 万条目 ≈ 10.4 MB JSON）；`flush_send_queue`
（`src/gateway.rs:1159-1186`）对 `Ok(false)` 只 `break` 且保留队首 ⇒ 超出 str0m 128 KiB 可用缓冲的消息
**永远发不出去并头阻塞其后所有终端/信令消息**，同时每 tick `front().cloned()` 复制 10 MB（实测 RSS +182.8 MB / 10 次）。
>2520 条即超 Chrome 单消息上限。修法：entries 分页 + ack 字节上限 + 不可送达时丢弃并回 error。

**P0-4 `offset + len` 溢出：绕过配额、崩 worker、发布版全进程 abort** [真跑 #4 #6]
`src/file.rs:1387`。debug/test 构建 `attempt to add with overflow` panic ⇒ worker 静默死亡、
**丢 ack、不发 Closed、`file_sessions` 假活**（全 crate `thread::spawn` 8 处均丢弃 `JoinHandle`，无 `catch_unwind`）；
release 无 overflow-checks ⇒ 回绕成小值**通过 `max_upload_bytes` 检查**。且 `Cargo.toml` 的 `panic = "abort"`
使任一 worker panic 变成**整网关进程 SIGABRT**（#4 EXP2c 实测 exit 134）。修法：`checked_add` + 帧长上限 +
spawn 时 `catch_unwind`/JoinHandle ⇒ 投 `FileClosed`。

**P0-5 缓冲与保活无上限：单会话 RSS 1 GiB，滴灌永久持有** [真跑 #5 #9]
`max_upload_bytes` 校验的是本片 end 偏移而非"连续前缀 + buffered 总量"（`src/file.rs:1387-1388`，
`config.rs:150` 文档写的是 per file session，实现是 per stream）；实测 8 条流灌乱序片 ⇒ **RSS +1028 MiB**。
`last_activity` 被任意命令/回执刷新（`gateway.rs:1810/1851/2364`）⇒ idle=3 s 下每 1.5 s 一次 `file_stat`
**15 s 内 0 次回收**，会话与内存永久保留。

**P0-6 令牌防线零节流 + 未鉴权信息面** [真跑 #7]
`gateway.rs:1887` 是文件系统唯一防线，实测单会话 **5000 次错 token 全被处理、无锁定**（~74/s，可多会话并发）；
`validate()` 对 token 无最小长度/熵要求。`/api/config` 未鉴权即回 `ice_servers`（含 **TURN username/credential**，
`config.rs:34-41`，属既有泄露面）以及我这次新增的 `files.roots` 名单与网格拓扑。`/mesh` 在默认 `InMemory` 下
无 token 也返回 101（既有）。修法：失败计数/退避 + token 熵下限 + `/api/config` 剔除凭据类字段。

**P0-7 前端 waiter 不 reject ⇒ 面板永久卡死** [node 复现 #6 #16]
`app.js:981` `resetFileSession` 只 `clearTimeout`，promise 永不 settle ⇒ `fileUploadSelected` 的 `finally`
不执行、`fileBusy` 永久 true、`fileOpen()` 卡在 `await fileCloseSession()`；通道 onclose / `file_closed` /
`reconnect()`（`app.js:462-499` 完全没重置文件态）都会进这条路径，用户只能刷新页面。

**P0-8 前端 ack 广播错配** [node 复现 #16]
`pumpFileWaiters`（`app.js:897-909`）遍历并 resolve **所有**匹配 waiter，而 `fileSimpleOp` 谓词只匹配
`type`+`op`（`app.js:1344`），mkdir/rename/remove 不受 `fileBusy` 保护 ⇒ A 的失败 ack 被当成 B 的结果，
B 自己的 ack 随后被静默丢弃。协议缺一个请求级 id。

**P0-9 混版本会让整个页面失效** [源码级 #14]
`app.js:385-387` 无条件在首个 SDP 里建 `nexus.file` 通道，而**旧节点**是
`Event::ChannelOpen(cid, _) => sess.channel = Some(cid)`（后开者赢、不看 label）⇒ 新页面 + 旧节点时
所有 `NodeMessage` 被送进文件通道，终端与节点列表整体失联。回滚或灰度共存即触发。修法：按 `/api/config`
的 `enabled` 才建通道，同时旧节点侧按 label 兜底。

**P0-10 `.part` 名字可预测且绕过 resolve；TOCTOU 逃逸** [真跑 #8]
`src/file.rs:563` 的 `.{stream_id}.{name}.nexus-part` 由浏览器自选的 stream_id 决定，
`part_open` 直接 `OpenOptions` 跟随已存在的同名符号链接 ⇒ 预置链接可把外部文件截断/写入（运维把 root
配在共享/构建目录时可达）。另：resolve 是快照校验，真正 create/open 由内核二次解析，无 `openat`/`O_NOFOLLOW`，
并发实验里**前 100 次 mkdir 内 2 次逃逸**。

**P0-11 REQ-006「断线重连续传」不成立** [真跑 #1，#16 亦指出]
`part_open` 用 `truncate(true)`/`OpenFlags::TRUNCATE`（`file.rs:567/871`），重连必新建会话
（`gateway.rs` 拒 re-offer）⇒ 实测同名 `.part` 从 10 字节被截成 0，节点已回执的前缀被销毁。
现有 `file_local_upload_round_trip_with_resume` 只在**同一会话内**重放，从未跨会话。
案卷与 `requirements.toml` 的 acceptance 都必须降级或改实现。

**P0-12 路径回显退化导致读/删错对象** [真跑 #1 #8 #11，三方独立] [自验]
`src/file.rs:378` 存的是**未 canonical** 的 root，`:399` 用 `strip_prefix(&self.root)`，
而 `resolve()` 返回 canonical 路径 ⇒ root 本身是符号链接（macOS `/tmp→/private/tmp`）或 Windows
（canonicalize 带 `\\?\` 前缀）时每个嵌套条目退化成了 `/{name}`：`list("/sub")` 回显 `/b.bin`，
浏览器拿着错 path 去下载/删除 ⇒ **删到别的文件**。修法：`LocalSandbox::new` 里就把 root 规范化存下来。

## 3. P1（非安全但阻塞"可提交"）

- **语义分裂**（#2）：N3 已定义"字节分页 + 续传 + 原子发布"的权威契约——
  `docs/N3-4-ARTIFACT-DELIVERY.md:54-66`（`offset`/`prefix_sha256` 续传、SHA-256/长度后 intent、hard_link 不覆盖发布）、
  `docs/N3-9-ARTIFACT-CLI-CONTRACT.md:9-12`（`offset/max_bytes/next_offset/eof`，每页 64 KiB）。
  我的 `file.rs`/`protocol.rs` 里 **sha256/checksum/digest 命中数 0**，字段名同构而保证更弱，且互不引证；
  仓库里还有第三种帧格式（`apps/nexusd/src/sync_transport.rs:8`）。需要决定谁是权威。
- **依赖治理**（#13）：`policies/dependencies.toml` 里 `grep ssh2/SFTP` = 0 命中，而 `[security]
  review_feature_expansion = true`；本次把 ssh2 从 pty 扩到 SFTP 子系统 + `std::fs` 读写，属未经评审的
  能力面扩大。`cargo tree` 显示 Linux 上 `ssh2 → libssh2-sys → openssl-sys`。现有 9 门 harness **捕获不到这条**。
- **可观测性**（#15）：`file.rs` 全量 0 个 tracing 调用；19 处 `tracing::` 里 15 处是 `debug!`；
  `examples/gateway.rs` 不装 subscriber ⇒ 真跑一次完整故障序列（错 token→未知 root→空洞拒→下载→close）
  INFO 下 **0 行**，TRACE 下 3054 行里本模块只占 1 行。会话生命周期（ChannelOpen/Close/ICE）零日志，
  与 MODULE.md 的 Observability 声明直接冲突。
- **重复与跨引擎语义分叉**（#12）：两个 `read_at` 的缓冲读循环**逐字节相同**（`file.rs:522-539` vs `842-859`）；
  part 命名（本地带 stream_id/隐藏、SFTP 不带/可见）、mkdir（`create_dir_all` vs 单层且存在即错）、
  flush（本地每 append 落盘、SFTP 只在 commit）三处分叉 = 行为随目标类型漂移，属实现缺陷而非风格问题。
- **SFTP ack 声称 durable 实则未 flush**（#3 F3）：`file.rs:889-897` 无 flush，`:904` 用 `let _ = flush()` 吞错。
  协议帧内无长度/CRC，无法自检。
- **IPv6/候选质量**（#11）：`routable_iface_ips` 不看 `IFF_UP`，实测放行 15+ 条**无 scope-id 的 fe80**
  （docker/veth/tun）进 SDP；`::` 通配时 IPv4-only 浏览器拿不到任何候选，dual-stack 语义未证。
- **产品/文档层缺锚点**（#2 #18）：`PRODUCT.md`/`scenarios/` 里 gateway 命中 0，本次却把"文件系统浏览"
  升为 crate 级 Responsibility；`docs/DOCUMENTATION-ARCHITECTURE.md` 规定 L3 用 ADR 形态且不用该 frontmatter
  字段（我的案卷 `layer: L3-decision`、`created:` 均不合规）。
- **案卷过度声称**（#10 #18）：SFTP e2e 的 `rename`/`remove` 只断言 `ok:true` 不再 list 复核
  （`tests/gateway_e2e.rs:2052-2069`）⇒ 递归删除若变 no-op 仍绿，且 `sftp_work_dir()` 每次换名会让远端残留静默累积；
  "未知 file session 显式报错"有实现无测试（8 处 `UNKNOWN_FILE_SESSION` 零覆盖）；
  `wildcard_bound_gateway_...` 用与实现同逻辑的 `routable_ipv4s()` 比长度 = 循环论证。

## 4. 被证实为"改坏不红"的装饰区（#10 变异测试）

硬约束（改了就红）：ICE 候选一致性（M09 让 22 条红）、帧头二进制布局（含 `FRAME_HEADER_LEN=15` 直接编译失败）、
上传顺序/乱序排空/内容落地、三闸门（未启用/错令牌/会话数）、`..` 拒绝（单测与 e2e 各守一道）。
装饰区（改了仍绿）：`unknown upload stream` / `unknown file session` 应答、SFTP `remote_path` 绕过
`normalize_rel`（**G13 在 SFTP 侧零测试**）、G14 的 e2e 层、空洞检查的 e2e 层、重放容错的 e2e 层、
file 空闲超时（所有测试写死 `idle_timeout_secs: 600`）、跨会话 stream_id 抢占、`chunk_bytes` 入站上限、
`upload.path != path` 校验、SFTP `./..` 过滤。llvm-cov：`file.rs` 1231 行未覆盖 116，未覆盖处集中在
安全/错误路径（`part_abort`、SFTP remove 非递归分支、后端连接失败分支、SESSION_UNAVAILABLE 应答）。

## 5. 我（实现者/编排者）对自己先前结论的公开更正

1. **"harness `working_tree_digest` 疑似只看 git index"** → 不准确。源码
   `engineering/nexus-harness/src/env.rs` 的 `working_tree_digest` 写着 clean 时用 `git write-tree`、
   **dirty 时用 `git status --porcelain` 文本的 hash**（注释自称 "stable for a given dirty state"），
   即 **dirty 态下对文件内容完全盲**；且 `evidence.rs:62-70` 的 evidence id =
   hash(revision|config|contract)，不含 digest/时间戳 ⇒ 可被另一棵内容不同的树以同一 id 覆写。
   因此我案卷 §2 引用的 `verify-c327a6da9351` **不能证明任何具体字节被验证过**（评审 #17 实测数据：
   改动 `app.js` 内容后 digest 不变，`git add` 后才变）。
2. **"真实 sshd SFTP e2e 覆盖改名/递归删除/关闭会话"** → 过度声称。该用例对 rename/remove 只断言
   `FileOpAck{ok:true}`，无服务端效果复核；"未知 file session 显式报错"有实现无测试。
   我的案卷 §2/§3 需要按 §3 上文降级表述。

数字本身（46 单测 / 28 e2e / fmt / clippy / verify --fast 9 门 PASS）被 #17 在另一台副本上**逐字节复现一致**，
这部分不用改；但"CI 会变绿"确实**没有任何远端证据**（改动未提交，`gateway-ci` 只在 push master 触发，
master HEAD run 仍是 failure），且看板 artifact 断链今天实测仍在。

## 6. 建议修复顺序

1. 安全类先收口：P0-1（SFTP `lstat` + 拒绝符号链接 + 改写 G13 措辞）、P0-6（令牌节流 + `/api/config` 去凭据）、
   P0-10（`.part` 用随机名 + resolve 后再校验/或用 `O_NOFOLLOW` 等价手段）、P0-12（root 存 canonical）。
2. 可用性类：P0-2（句柄按 path 复用 + 显式 close + 上限）、P0-3（分页 + ack 字节上限 + 不可送达时降级）、
   P0-4（`checked_add` + `catch_unwind`/JoinHandle）、P0-5（buffered 字节上限 + 每会话流数上限 + 真实 idle 语义）、
   P0-7/P0-8（waiter 全量 reject；给简单操作加请求 id）。
3. 混版本：P0-9（按能力建通道）；P0-11（要么实现跨会话续传、要么把 acceptance 改成"同会话内续传"）。
4. 结构性：先与 N3-4/N3-9 定权威（含校验和），再决定网关文件面是复用 Artifact 语义还是登记为架构豁免；
   两引擎重复与跨引擎语义分叉一起收；补 subscriber 与会话级 INFO；把 ssh2/SFTP 能力面写进
   `policies/dependencies.toml` 评审条目。
5. 契约与案卷：修 §5 两条更正、frontmatter 归入 ADR 体系、补 §3 列的漏项；REQ 状态按实际（`doing`）保留。

## 7. 交付与独立性说明

- 18 个评审会话均为一次性独立执行者，只领一个角度，彼此不可见；都遵守了"不得写入 `E:\nexus-fabric`
  与 `/work/gateway-file-module`"（#1/#14 曾把探针写进 Linux 共享副本，我已清理并恢复 `tests/` 与
  `tools/` 文件模式；同时删除它们遗留的 `/tmp` 与 `/media/appen/data/rev*-target` 共约 5.1 GB）。
- **本文不是 `.evidence/review-*` 案卷**：`nexus-review` 要求 reviewer 是独立于实现者的执行者，而我同时是
  实现者兼编排者，因此我只做归并与自验，**不签发 verdict**。要进 `verify --full`/提交，仍需由你指定的
  独立执行者按 `SKILL.md` 的 summary.json 结构出案卷。
- 模型口径：子智能体模型由你在应用侧绑定，我在 CLI 侧无法读取或证明其模型名；若需按你既有习惯在案卷里
  点名评审模型（形如 `Independent review (<model>)`），需要你从应用侧确认实际使用的模型。
