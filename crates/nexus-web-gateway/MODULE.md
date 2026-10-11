# nexus-web-gateway — Module Contract

## Responsibility

浏览器零安装接入 Nexus 网格的 Web 接入点（每节点内嵌）：

- HTTPS 服务：静态页面（xterm.js 终端）+ `/api/config` + `/cert`（本地 CA 下载）+ WSS 信令端点 `/ws`。
- 节点侧 WebRTC 端点（str0m，sans-IO）：接受浏览器 SDP offer，建立
  RTCPeerConnection + DataChannel（控制通道）。
- 经控制通道下发 mesh 节点列表（PeerId、候选地址、服务目录）与 ICE 服务器配置。
- SDP 信令中继：浏览器对其他节点的 offer 经已建连 mesh 转发（`MeshSignaler` trait），
  不依赖外部信令服务。
- 网页 SSH 终端：浏览器 DataChannel → 目标节点 → **节点侧真实 SSH 客户端（ssh2/libssh2）**
  → 本地 sshd。浏览器表单里的账号密码/私钥经安全通道传给节点，在节点侧完成 SSH
  握手与认证，不落盘。浏览器 ↔ 节点之间只传终端字节流（pty 层），SSH 协议只发生在
  节点 ↔ sshd 之间。
- 网关文件服务（契约先行，`PRODUCT.md#18-gateway-file-service`）：在显式配置的 root 沙箱内
  提供浏览/下载/上传/建目录/改名/删除，经独立二进制 DataChannel 承载。**本节是契约声明，
  不是已交付 API**：实现按 M1-M4 分期落地，`requirements.toml` 的 REQ-005..REQ-013 保持
  `doing`，在此之前不存在对外可调用面。

## Non-Responsibilities

- 不做 SSH 服务器；SSH 协议只发生在节点 ↔ sshd（浏览器不解析 SSH 协议）。
- 不做浏览器能力暴露（摄像头/传感器）、HTTP 服务代理（Phase 2）。
  文件系统浏览已从此条移出（2026-10-11）：它现在是 §18 的产品职责，边界见 G12-G21。
- 不做持久身份与验证（MVP 用临时身份，节点默认接受）。
- 不做 TURN 服务器本身（TURN 是标准外部服务器；节点仅把配置下发给浏览器）。
- 不实现 Nexus fabric FIB 信令后端（`MeshSignaler` 是接缝；fabric 后端后续接入）。

## Inputs

- `GatewayConfig`：监听地址、节点 PeerId/名称、mesh 节点列表、ICE 服务器、
  TLS 材料（自动生成本地 CA 或文件）、SSH 目标（含空闲超时）、mesh 信令后端
  （`Wss` 模式含本地 `/mesh` 端点 bearer token 与对端 peer 列表）。
- 浏览器经 WSS 的 SDP offer / 经 DataChannel 的控制消息（JSON）。
- 其他网关经 mesh 转发来的 SDP offer。

## Outputs

- HTTPS 页面与静态资源、`/api/config`。
- WSS 信令 answer。
- DataChannel 控制消息（节点列表、中继 answer、SSH 数据）。
- SSH 终端到本地 sshd 的 TCP 字节流。

## Allowed Dependencies

- `str0m`（sans-IO WebRTC；`rust-crypto` feature，纯 Rust）
- `tungstenite`（同步 WebSocket，`handshake` feature）
- `rustls` / `rcgen`（TLS 1.3 + 本地 CA 自签证书）
- `serde` / `serde_json`（协议与配置）
- `sha1` / `base64`（RFC 6455 WebSocket 握手）
- `ssh2` / `libssh2-sys`（节点侧真实 SSH 客户端；仅 `std` 同步线程模型）
- `getifaddrs`（枚举本机网卡地址：`listen_addr` 未指定时导出可通告的 host candidate
  集合与 `page_addr`；UDP socket 绑族内通配地址而非某个网卡 IP，见 G11）
- 仅 `std` 线程模型，零 async runtime（与仓库 std-only 姿态一致）。

## Forbidden Dependencies

- `tokio`、`async-std`、任何 async runtime。
- Nexus 内部 crate（本 crate 是独立接入模块；fabric FIB 经 `MeshSignaler` trait
  注入，不直接依赖 `nexus-fabric`）。
- 真实密钥/证书材料硬编码（证书经 `cert_dir` 落盘，密钥/凭证不写日志）。

## Invariants

**G1（全程 TLS）**：所有浏览器可见路径均为 HTTPS/WSS，无纯 HTTP。
**G2（临时身份）**：浏览器身份是内存中的临时 ed25519/随机 ID，节点侧默认接受，
不持久化、不验证。
**G3（节点侧真实 SSH 客户端）**：节点与目标 sshd 之间运行完整 SSH 协议握手与认证
（ssh2/libssh2）；浏览器 DataChannel/mesh 只承载终端字节流（pty 层），不解析 SSH
应用层内容。SSH 协议绝不出现在浏览器 ↔ 节点之间。
**G4（凭证不落盘）**：页面提交的密码/私钥只保存在内存 session 中，用于节点侧 SSH
认证，关闭即丢弃，不写盘、不做浏览器端存储。
**G5（最小 API 面）**：对外只暴露 `Gateway::start` / `GatewayConfig` /
协议消息类型；内部 `Session`/事件循环为 private。
**G6（类型化错误）**：业务失败返回 `GatewayError`，不用 panic。
**G7（mesh 端点鉴权）**：`/mesh` WSS 端点要求 `Authorization: Bearer <token>`，
本地 token 由 `MeshConfig::Wss.token` 配置；缺失/错误返回 401。
**G8（空闲终端回收）**：SSH bridge 超过 `SshConfig.idle_timeout_secs` 空闲即断开，
事件循环周期性扫描并下发 `ssh_close`。
**G9（不静默丢弃终端数据）**：网关收到未知 session 的 `ssh_data` 时必须回 `ssh_close`
或明确错误，绝不静默吞掉。
**G10（证书持久化）**：自签证书按节点落盘（`cert_dir`，默认 `$XDG_CACHE_HOME/nexus-web-gateway/<node_id>`），
重启指纹不变；`/cert` 提供 PEM 下载。
**G11（候选/收包一致）**：SDP 通告的 ICE host candidate 必须是共享 UDP socket
**实际能收到包**的地址。绑定具体 IP 的 socket 只收该目的地址的包，因此
`listen_addr` 为具体 IP（含 `127.0.0.1`）时只能通告该 IP；`listen_addr` 为未指定地址时
绑定族内通配地址，此时才可通告全部可路由网卡 IP（多网卡：LAN + mesh）。
通告 socket 收不到的候选会让 ICE 静默超时（曾导致网关所有 DataChannel 测试与 CI 红）。

### 文件服务不变量（G12-G21，契约先行；编号说明见下）

> 编号偏离：V2 设计（`docs/GATEWAY-FILE-SERVICE-DESIGN-V2.md` §11）写的"G13 重写、
> 新增 G17-G21"是按 V1 工作树里 `G11..G16` 已存在来排号的；V1 那批实现**从未合入 master**，
> 因此本分支上 `G12..G16` 是空的。这里一次性把文件面的不变量落成 `G12..G21`，
> 语义与 V2 §2-§9 一一对应，后续期次不再重排号。

**G12（文件面默认关闭，配置不自洽即拒启动）**：`files.enabled` 缺省 `false`
（**契约声明**：`config.rs` 尚无 `files` 字段，把它接进 `GatewayConfig::validate`
与 kill-switch 属 M1 剩余项，当前 enforced 的是引擎侧的 `FileLimits::validate`）；
`FileLimits` 的交叉约束任一校验不过 ⇒ **拒绝启动**，绝不"半启用"或静默放宽
（fail-closed）。当前 enforced 的交叉约束（除注明外逐条都有单测把它跑红，
且夹具只违反自己那一条）：
`chunk_bytes ≤ max_buffered_amount`（否则一页永远发不出去）、
`chunk_bytes ≤ max_inflight_bytes_per_session`、
`max_ack_bytes ≤ max_buffered_amount`（V1 的超大 ack 头阻塞就是这条缺失；加了下一条
之后它已被 `ack ≤ inflight ≤ buffered` 蕴含，作为先写的检查保留是纵深防御——
**它没有、也不可能有"只违反它"的夹具**，所以不列入"逐条有红测试"）、
`max_ack_bytes ≤ max_inflight_bytes_per_session`（`list` 按 ack 字节过账，一条完整
ack 放不进会话额度就意味着每次 list 都当场 CAPACITY——评审 r5 R5-W-3 的配对约束）、
`max_ack_bytes ≥ list 信封 + 一个条目`（否则每个 list 页都截断成 0 条目且"没报错"；
这条只是**必要不充分**——长文件名仍可能塞不进，所以运行期还有一条：0 条目且仍有
剩余时 `list` 必须回 `PAGE_TOO_LARGE`，绝不返回 `next_offset == offset` 的空页）、
`max_inflight_bytes_per_session ≤ max_buffered_amount`（in-flight 与共享预算由同一事件
释放，高于预算的上限是够不到的死配置——取代了旧的 `×64` 魔数）、
`max_browser_sessions ≤ max_sessions`、`max_read_handles ≥ max_sessions`、
任一数值上限不得为 0，**两个时长同样不得为 0**（`lockout_window = 0` 会让每次锁定
写入即过期、`idle_timeout = 0` 会让会话刚建即回收——评审 r4 R4-NEW-1），
且时长不得越过 24 h（它们参与 `Instant` 加法，病态大值不是"更宽松"而是把锁死推到
时钟边界之外——评审 r5 R5-W-2；数值型上限没有这种后果，仍只封低边）。
root 非空且不重复、`read_only` 组合同样校验。
**G13（root 是唯一授权面，逐分量解析 + 打开后重核实）**：root 必须是 `canonicalize`
后的真实路径（非规范 root 在 Windows/macOS 上会回显错误路径并使越界检查失效）；
自 root 起对每一段做 `lstat`/`readlink`，任一段是符号链接即拒绝；**解析不得因某段
缺失而提前停止**——缺失分量按字面继续拼接（否则 `a/b/c` 被截断成 `a`，上传会发布到
错误前缀且不报错），"不存在"由具体动作决定其后果：`mkdir` 允许一次建出整条缺失链
（校验最深存在祖先在 root 内且非链接），`open_upload`/发布则要求父目录**必须已存在**
否则 `NOT_FOUND`；**打开之后**重新解析核实最终路径仍在 root 内（TOCTOU 快照类型化，
不允许"解析一次即相信"）；改名/删除的目标同样受此约束，删除**不递归**出 root。
**流绑死在打开它的 root 上**：`UploadStream` 记录打开时的 root，提交时传入的 root 参数
必须与之一致，否则 `OUTSIDE_ROOT`——否则"在可写根上传、换个 root 提交"就能落进
`read_only` 根，或把 SFTP 根的远端路径丢给本地解析器 `hard_link`（评审 r2 NEW-1）。
提交路径同样必须过 `require_writable` + `require_local_io` 两道门。
**改名**：文件走 `hard_link`+`unlink`，与发布同族，目标存在即失败且原字节一字未动；
目录在 std 下拿不到原子无覆盖原语（`hard_link` 对目录失败），只能前置 `exists` 检查，
并发窗口仍可能被 `rename(2)` 静默替换——这个窗口是**声明过的残余**（§18.4），不是已证安全。
文件路径自身也有残余：`hard_link(src,dst)` 与 `remove_file(src)` 之间本地写者若把 `src`
换成新 inode，复制的是旧内容（单进程内不可观测）；`remove_tree` 遇符号链接即拒，但
**它之前删掉的兄弟项不回滚**，一次被拒的递归删除可能留下"部分删除"状态，调用方不得
假设原子性（评审 r3 N-3，登记进未证事项）。
提交 root 与流的 root 不一致时复用 `OUTSIDE_ROOT`：授权面只有 root 一个，换 root 提交
本质是越出流被授权的那棵树，而不是容量或完整性问题；不另开新码是把码表守住的理由
（评审 r3 N-2 的取舍）。
**G14（不覆盖；SFTP 后端结构性不支持写）**：目标已存在 ⇒ `OUTPUT_EXISTS` 且原字节一字未动；
**发布被拒时不得留 `.part` 残留**（实测：E4 场景抓到过一处残留，而当时 12 条单测全绿；
条数随实现增长，当前计数只以 `.agents/green-evidence-gateway-file-service-m1.txt`
的实测行为准，本文不再自我报告数量）。
本地引擎用同文件系统 `hard_link`（目标存在即失败）原子发布。SFTP 根**不提供
上传/改名/删除**：`ssh2 0.9.6` 依赖的 libssh2 通告并把 SFTP 钳在 v3
（`include/libssh2_sftp.h:51`），rename 的 flags 仅在 `sftp->version >= 5` 入包
（`src/sftp.c:2833-2834`，全树无赋值）⇒ `Some(ATOMIC|NATIVE)` 与 `None` 包体逐字节相同；
可用原语是 `SSH_FXP_POSIX_RENAME`（`libssh2_sftp_posix_rename_ex`），该 crate 未绑定。
所以这里的口径是"拒绝写"，不是"携带标志"，也不是"等服务端实测"（owner 2026-10-11 选定）。
在 SFTP 传输真正实现之前，其读面同样返回 `UNSUPPORTED_CAPABILITY`——把远端路径交给本地
解析器只会得到误导性的 `NOT_FOUND`。
**G15（文件凭证不落盘，失败计数有界）**：文件通道使用独立于页面登录的配置令牌，
比较必须常数时间；认证失败按（主体 + 源）**两层键**节流并锁定，计数与表项**有界**
（不得随伪造会话线性增长）；键的两半同样按 `IDENTITY_LABEL_MAX_BYTES` 裁长度，
否则"表项有界"只是**项数**有界而不是内存有界（未认证者能送任意长的主体名/源串，
评审 r5 R5-W-4）。裁剪带来的**键碰撞**必须说清楚（评审 r6 NOTE-4）：只有"前
`IDENTITY_LABEL_MAX_BYTES` 字节相同**且总长相同**"的两个身份才会落进同一个桶，
所以它不会削弱锁定方向（碰撞只会让窗口更早武装，仍 fail-closed），但**给了新攻击面**：
伪造者只要让自己的身份与受害者前缀 + 总长一致，就能用自己的 5 条失败替受害者招来
一次锁定。接受该代价的理由与 R4-W-6 同源（内存上界 vs 归因精度），登记为待 owner
裁决项，不伪装成"无副作用的裁剪"；
锁定窗口内正确口令也不得绕过；沿用 G4 的"凭证不落盘"。
**表满时必须 fail-closed**：溢出人群没有自己的桶，因此累计失败达到阈值时升级为
一个**全局锁定窗口**（`throttle_overflow`/`throttle_globally_locked` 可观测），
窗口期内**所有**主体即使令牌正确也被拒——包括已经把表填满的那批在册主体
（评审 r3 R3-NEW-2：旧写法只约束"不在 buckets 里"的主体，等于让填表者永久豁免）。
窗口到期时锁表与溢出计数一起回收（`decay`），所以一次洪水不会永久待命：
重新武装需要**再攒满 `lockout_after` 条**溢出失败。显式声明的代价：这段时间合法
新用户也会被拒——它是"内存有界"与"锁定不失效"之间的取舍，选后者并写在这里，
不允许用"只累加一个私有计数器、继续比令牌"的方式偷偷换成前者（评审 r2 NEW-3）。
**仍未闭环的可用性口径（评审 r4 R4-W-6，待 owner 裁决）**：`buckets` 自身不做时间
衰减（只有成功认证或会话拆除会删桶），所以伪造量占满 1024 个桶位之后，攻击者每
窗口只需 `lockout_after`（默认 5）条伪造失败即可无限续期全局窗口，实测在该节奏下
未在册的合法主体约 94% 的时间被拒。要么给桶加时间衰减（等价于"窗口内不失败就恢复"），
要么在 PRODUCT 里把"合法用户可被无限期拒服务"写成明示的可接受代价；本批**只把现象
登记进契约与未证清单，不静默改变语义**。
**G16（句柄、队列与终端优先）**：`stream_id` 由**服务端签发**，同一流的多个分片
不得各自新开读句柄（V1 反面教训：约 1022 片后句柄耗尽导致整节点 DoS）；读句柄峰值、
并发会话数、单会话在途字节、`.part` 声明大小、重放页回读字节都有上界；
**会话配额是准入检查**：`authenticate` 在全局 `max_sessions` 与单 peer
`max_browser_sessions` 达到上限时直接 `CAPACITY_UNAVAILABLE` 拒（只在 `validate()`
里两两比较等于没有上界，评审 r2 NEW-4），释放的额度必须可复用。
超预算回 `QUEUE_FULL`/`CAPACITY_UNAVAILABLE` 并**按消息条数显式计数**被拒绝或被挤掉的
文件类消息（记"发生过一次挤占"等于没记：一条大消息与清空整条队列在账上必须可区分），
终端（pty）字节流优先且零丢失。共享发送预算与单会话在途计数由**引擎自己持有**，
过账责任按"谁知道序列化长度"划分（评审 r2 W-11 的处置，不做"引擎已经管全部"的
口头声明）：引擎算得出长度的**必须**由引擎过账——`read_page` 的页字节、`list` 的
`ack_bytes`（截断逻辑本就累计了这个数）；引擎算不出长度的（逐片 ack、`stat`/
`mkdir`/`remove`/`rename`/`commit` 的回包）由 wire 层用真实长度调
`send_file_message` 过账，引擎不替它编数字。**M2 建通道时必须逐动词接上**，
否则"G16 每条出站文件类消息过账"只对 read/list 成立。
三处释放缺一不可：对端 ack、被终端字节挤掉（回冲**它自己会话**的额度，
**包括终端发送最终失败的那条路径**——挤占已经发生，清单丢了额度就永久悬空，
评审 r3 R3-NEW-1）、会话拆除（close/闲置回收，否则一次断线就把全节点预算永久钉死，
评审 r2 NEW-2）。未知会话不得过账——无归属的条目没有释放路径；过账后的任何早退
都必须回滚（r3 R3-W-1）。`settle_file` 只看队头，不得越过未落地的消息提前退额度
（r3 R3-W-4）。`inflight_bytes == budget.file_buffered_for(session)` 是引擎自证的不变量。
per-peer 配额以 `source` 为键，前提是 **wire 层送来的 `source` 不可被对端影响**
（应为 DTLS 绑定的 transport address）；若该字符串可被对端拼散，配额就成了纸面约束
（评审 r3 N-5，M2 接线时必须核）。
诚实边界：M1 的读是同步的（一次调用内 acquire+release），所以 `max_read_handles`
在产品路径上当前**打不满**，防线由"读不落驻留"意外成立；注册表本身另有直接单测。
OS 句柄层面（`/proc/self/fd`）与全局 RSS 上界仍未验（M1 剩余项）。
wire/探针都不得另搓一份预算来"演示"背压（那样证明的是模型，不是产品路径）。
**G17（分页与截断必须显式）**：列表条目数与单条 ack 字节数都有服务端硬上限；
超限返回 `TRUNCATED` + `next_offset`，`next_offset` 必须单调；**绝不**把截断结果标记为
完整列表，也不允许单条 ack 大到能头阻塞控制通道。两个推论：请求 `max_bytes = 0`
必须显式拒（否则返回 `next_offset == offset` 的空页，客户端永远停在同一页，
评审 r2 W-4）；目录恰好等于 `max_entries_per_page` 条时不得谎报截断（旧实现在
第 cap 条入列后又走一次"满则断"分支，把看完的目录标成未看完）。
**G18（拉式续传与前缀完整性）**：读取是拉式的；上传 ack 只承认**已连续暂存**的字节数
（不是"收到某片"，也**不是**"已落盘"——逐片 `flush()` 在 std 上是空操作，耐久性只在
提交前一次 `sync_all()` 之后才成立）；完全重复的旧页必须逐字节匹配才接受；跳跃或部分
重叠的页拒绝，**不重写已承认前缀**；完整 SHA-256 与长度校验通过后才提交发布；字段语义与
`docs/N3-4-ARTIFACT-DELIVERY.md`、`docs/N3-9-ARTIFACT-CLI-CONTRACT.md` 对齐（分页不得替换
固定身份的任意字段）。
**G19（能力协商与混版本）**：页面在建文件通道前先读 `/api/config.files`；
字段缺失＝旧版网关 ⇒ 退化为"无文件模式"（不报错、不卡连接）；版本不认识时**不静默**
建通道；wire 只加不改，回滚旧二进制后新字段自然缺省。
**G20（外部可控量的算术与崩溃面）**：`offset + len`、页长、声明大小一律 `checked_*`
并显式拒绝溢出；本 crate release 下 `panic = "abort"`，**不靠 `catch_unwind` 假装隔离**，
要求 panic-free-by-construction，并对 str0m/帧解码输入面做 fuzz。
**G21（空闲回收与可判定审计）**：文件会话按配置 `idle_timeout_secs` 空闲回收，
且任何"活动刷新"必须刷新被检查的那个时间戳（V1 反面教训：刷新打在错字段上 ⇒
超时形同不存在）；每次文件操作留下可判定审计记录（主体、root、动作、目标相对路径、
结果码），**拒绝也要记**，成功也要记（旧实现只记拒绝，"谁读了哪个文件"查不出来）；
审计行由动作的统一出口落账，不散在各 `return` 前，所以"漏记"在结构上不可发生。
落账出口覆盖 `authenticate`/`read`/`list`/`stat`/`open_upload`/`commit`/`mkdir`/
`remove`/`rename`/`abort_upload`/`ack_staged`/`close_session`/`idle_recycle`，其中
`abort_upload`（客户端可发起、删掉已暂存字节）与 `close_session` 过去**一行都不记**
（评审 r2 W-5）；`stage_chunk`/`ack_staged` 的拒绝行 root 取自流本身，过去写死空串
（评审 r6 WARN-1）——**唯一合法的 root 空格**是"流/会话根本不存在"的拒绝，那时没有
root 可归因，宁留空也不编一个；单测逐个动词断言"恰好一行 + action 对 + 码对 +
principal 非空"（饱和环上只能按尾部内容断言，不断言行数增长）。
例外：逐片上传的**成功**页与逐片 `ack_staged` 的成功不写审计行（一次 2 GiB 上传
会灌满环并冲掉有意义记录），其可归因性由"连续前缀 ack + 提交行"承担，二者的**拒绝**仍记。**审计环本身字节有界**：行数封顶
`AUDIT_CAPACITY`，且每个由调用方控制的字段（principal/root/rel）裁到
`AUDIT_FIELD_MAX_BYTES` 并留下 `[+NB]` 截断标记——只说"行数有界"是不成立的，因为
`principal` 在令牌校验之前就被写下、`rel` 由调用方给，未认证者本可以把每行撑大
（评审 r5 R5-W-4）。溢出丢最旧一条并
累加 `audit_dropped`——无上限的审计日志就是一条用拒绝请求把节点内存打满的路径。

## Side Effects

- TCP/HTTPS 监听线程、每连接线程、事件循环线程、SSH bridge 读线程。
- UDP socket（WebRTC 媒体/ICE 流量，所有 session 共享）。

## Public API

- `GatewayConfig`（JSON 加载 + 校验）、`MeshNodeInfo`、`IceServer`、`SshConfig`、`TlsConfig`
- `Gateway::start(cfg) -> Result<GatewayHandle, GatewayError>`
- `GatewayHandle::local_addr` / `GatewayHandle::page_addr`（浏览器实际访问地址；
  `listen_addr` 为 `0.0.0.0` 时 `page_addr` 是派生的可路由 IP）
- `SdpPayload`（str0m SDP ↔ JSON 转换）
- `BrowserMessage` / `NodeMessage`（DataChannel 协议）
- `cert::generate_identity` / `cert::server_config`
- `http::read_request` / `websocket_accept_key` / `lookup_asset`
- `mesh::MeshSignaler` / `InMemoryMeshSignaler` / `WssMeshSignaler`

## Verification

- 单元测试：协议消息 roundtrip、SDP payload 转换、配置校验负路径
  （空 node_id / 空或重复 node_list / 空 ICE urls / TLS 文件空路径 /
  mesh WSS 空 token 或空 peer 字段）、证书持久化（重启指纹不变）、
  **G11 绑定与候选集合关系（具体 IP 只通告自己、未指定地址绑通配且不通告 0.0.0.0）**。
- 集成测试（`tests/gateway_e2e.rs`）：
  - HTTPS 页面、`/api/config` 与 `/cert` 可访问（rustls 客户端 pin 本地 CA）。
  - WSS 信令：浏览器-like str0m 客户端经 WSS 交换 SDP，建立 DataChannel。
  - **ICE 候选真连通**：`127.0.0.1` 绑定的网关必须通告且仅通告 loopback 候选，
    并真的连上（G11 回归）；未指定地址绑定时候选等于可路由网卡集合。
  - 双节点：经 in-memory mesh 中继，与第二个节点建立 DataChannel。
  - WSS mesh：两个独立 gateway 经 `/mesh` bearer-token 中继 SDP 并建连；
    错误 token 返回 401。
  - SSH 终端：DataChannel → 节点侧真实 SSH 客户端（ssh2）→ **真实 sshd 子进程**
    （OpenSSH，loopback 高端口，key 认证）→ 命令回显；空闲超时后终端被关闭。
  - 中继 SSH：经 WSS mesh 在两个 gateway 间中继终端，目标节点跑真实 SSH 客户端。
  - 负路径：无节点列表/空 node_id 配置被拒；SSH target 拒绝连接返回错误；
    未知 session 的 `ssh_data` 返回 `ssh_close`；re-offer 被拒（返回错误而非假 answer）。

## Performance Budget

- 控制消息：单条 DataChannel 消息处理 < 1ms（无锁队列 + 单事件循环线程）。
- SSH 数据：纯内存拷贝转发（TCP ↔ DataChannel），无额外拷贝（每 chunk 一次 base64）。

## Observability

- `tracing` 日志：连接错误、协议错误、mesh 错误。
- Session 生命周期：channel open/close、ICE 状态变化。

## Platform Constraints

- 本地引擎纯 Rust + std，**不使用 libc/`unsafe`**（crate 级 `forbid(unsafe_code)`）。代价是
  拿不到 `O_NOFOLLOW` 和跨平台稳定的句柄身份键，因此 G13 以"逐分量 `symlink_metadata` +
  打开后重解析"实现，其残余竞态窗口是**已知限制**，不是没列出来的依赖。
- 支持等级按平台分述（`PRODUCT.md` §18.3）：Linux = A（全量 + 真 sshd e2e 证据）、
  Windows = B（本地沙箱 + 密码认证）、macOS = C（不承诺，只保证 fail-closed 拒启动）。
  此处原有"不依赖平台专用 API"一句与上面的分级互斥，已删；若为提升 Windows 等级引入
  `windows-sys`/`libc`，属依赖治理评审项（D3）。