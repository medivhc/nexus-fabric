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
`lockout_after ≤ max_failures_per_source ≤ max_throttle_buckets × lockout_after`
（低了就没有任何身份能先被锁、等于把两层键塌成一层；高于上界则"表满 → 全局窗口"这条
大路永远先到，限额成了死配置——两条都有只违反自己的夹具。副作用是**缩小节流表的小
夹具必须同时缩小这道额度**，否则拒启动，这不是 bug 而是要逼着夹具想清楚自己测哪道门）、
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
**G15（文件凭证不落盘，失败计数有界且按窗口衰减）**：文件通道使用独立于页面登录的配置令牌，
比较必须常数时间；认证失败按（主体 + 源）**两层键**节流并锁定，计数与表项**有界**
（不得随伪造会话线性增长）。键是身份的 **SHA-256 摘要**（定长 32 字节），不是
裁剪后的标签。裁决理由要写准（评审 r7 R7-W-4 纠正了我第一版的说法）：旧写法把两半各裁到
固定长度，**标签字节数其实是被封住的**（裁剪点 + `…[+NB]` 标记），所以它不是"从无界变有界"；
摘要键的真实收益是（a）每行从"两个按裁剪点定长的 `String`"变成一个 32 字节数组（常数级内存收益，
r5 R5-W-4 的诉求由**定长**满足而不是由"从不有界变有界"满足），(b) 消除**定向锁定**面——旧键下
"前 128 字节与受害者相同且总长也相同"的伪造身份会落进受害者的桶，攻击者用自己的
`lockout_after` 条失败就能替一个从未出错的合法主体招来一次锁定（评审 r6 NOTE-4）；现在
共用一个桶需要 SHA-256 碰撞，而不是"前缀 + 长度可控"。两半在哈希前都写**长度前缀**，
否则 `("ab","c")` 与 `("a","bc")` 是同一段拼接，碰撞对同时掌握两半的攻击者是免费的。
锁定窗口内正确口令也不得绕过；沿用 G4 的"凭证不落盘"。
**表满时必须 fail-closed**：溢出人群没有自己的桶，因此溢出累计达到阈值时升级为
一个**全局锁定窗口**（`throttle_overflow`/`throttle_globally_locked` 可观测），
窗口期内**所有**主体即使令牌正确也被拒——包括已经把表填满的那批在册主体
（评审 r3 R3-NEW-2：旧写法只约束"不在 buckets 里"的主体，等于让填表者永久豁免）。
实际生效的升级机制**只有溢出计数这一条**：`record_failure` 里"锁表满也升级为全局窗口"
那支是纵深防御，经 `authenticate` 不可达。证明要三句才成立（r8 R8-W-3 指出我上一版
漏了第一句，于是"不可达"从证明退化成断言）：(a) 行与锁的**死亡条件逐字等价**
（锁判 `until > now` 且 `until = arm + w`，行判 `now - last >= w` 即作废，武装那次
两者写的是同一个 `now`；锁定期内 `authenticate` 先短路，行和锁都不再被刷新）；
(b) 行只有两个消失途径——`decay`（按 (a) 与锁同时死）与 `succeed`（它只在没有活锁时
才可达），**会话拆除不再是途径**（见下面"会话拆除"那段）；(c) 新行只在
`buckets.len() >= max_buckets` 不成立时才产生。由 (a)(b) 得 `locked.len() ≤ buckets.len()`
（每条活锁对应一行活行），由 (c) 得 `buckets.len() ≤ max_buckets`；所以
`locked.len() == max_buckets` 要求所有在册行都带活锁，而那时任何新身份都先撞 (c)
走溢出分支，到不了那支。r7 §3.2 证的是同一件事，但我第八片曾把"行可以只被删一半"
写进实现，那会让 `locked.len() ≤ buckets.len()` 当场失效——第九片把拆除清状态整个
去掉之后这条不变式重新成立。观测面补齐：`throttle_locks()`（锁表存活项数）与
`throttle_buckets()` 一起让"表项有界"对**锁表那一半**也有可红对象（此前全仓不可读）。
实测覆盖（本批 D 轮复验；树号与全量 bindings 只记在案卷《M1 第十一片》的 D 轮一节，契约里
不写 sha，免得这一行自己改动就把它声称的那棵树弄没了）：关掉那支 ⇒ 73 单测全绿、auth-throttle 的 27 条期望字段无一翻转（这与上面的
不可达性一致，不是"测试没覆盖到"）；把过期锁回收改成恒真 ⇒ 只有
`expired_locks_are_reclaimed_instead_of_escalating_to_the_global_window` 红（评审 r7
R7-W-3 改判 NOTE）。把两支并列写成"两道 fail-closed 机制"就是谎报。
**桶与溢出计数都随窗口衰减**：每次写入前 `decay` 回收过期的锁、过期的桶与过期的
溢出计数，一条身份静置满一个窗口就不再背失败，伪造量占住的桶位自己腾出来。**衰减有四条腿，
本批给每条都配了对象**（此前 `source_failures` 与 `source_locks` 那两条腿是零可红面——
本轮把衰减族变异全量重跑才测出来，且**两条对偶测试的第一版自己也没杀伤力**：`M18` 在
70 条那棵树上全绿、`M17` 连错两版（71 条与 72 条那两棵都全绿，都是"最后一条失败之后又睡
过整整一个窗口"这同一个错），修到迭代之间才睡之后各自红 1 条）：
桶衰减 = `lockout_requires_failures_inside_one_window` + `throttle_sustainable_failure_budget`，
两层键锁回收 = `expired_locks_are_reclaimed_instead_of_escalating_to_the_global_window`，
源账本衰减 = `source_ledger_budget_forgives_failures_from_older_windows`（慢滴不攒额度），
源锁回收 = `expired_source_locks_are_reclaimed_instead_of_escalating_to_the_global_window`
（不回收会把个体源锁偷偷升级成全局窗口，与 `locked` 那一半同形）。这四条腿的**内存**上界
与**门槛**语义是两件事：前者由写侧回收保证、后者由这四条钉，别互相背书。同一个
`lockout_window` 既是锁定持续的时间、也是失败被遗忘的周期（一物两用是有意选择：
两个独立时钟只会让配置自相矛盾，也让 `validate()` 的交叉约束成倍增长）。于是
维持 fail-closed 窗口需要攻击者**持续**注入新身份——停止注入后一个窗口内自愈，
重新武装必须**再攒满** `lockout_after` 条溢出失败（评审 r4 R4-W-6 的 owner 裁决：
实现衰减，而不是把"合法用户可被无限期拒服务"写成可接受代价；r3 R3-W-2 是同一条
性质在全局窗口上的特例）。`throttle_buckets`/`throttle_overflow`/`throttle_failures`/
`throttle_locks`
报的是读侧按窗口过滤后的**存活**值；**物理行数有界来自 `record_failure` 的准入行门禁**
（新行只在 `len < max_buckets` 时才产生），与回收无关——回收决定的是行会不会死，
两者不是一回事、也不互相背书（评审 r7 §3.2/§3.3）。
**会话拆除不碰节流状态（r7 R7-W-2 → r8 R8-W-2，本条改了两轮才定）**：
`close_session` 与 `sweep_idle` 都**不**清该 (主体,源) 的锁定，也**不**清它的失败计数；
节流状态只由两处清理——成功认证（`succeed`）与窗口衰减（`decay`）。理由链条要写全，
因为它不是一步想到的：
(a) 最早的 `forget()` 连锁一起删 ⇒ 会话拆除即解锁；r7 实测把那个函数删空
**谁都不红**（r7 在第八片那棵树上实测：当时 61 单测 + 90 条期望全绿），而它的注释写着"asserted by the probe"——
探针那条 `state_cleared_after_close` 跑在成功认证之后，成功早已由 `succeed` 清过桶，
探针观测不到它。
(b) 第九片第一版改成"只清计数、锁必须服完"。r8 指出这只关了一半：锁是由**计数**达到
阈值才武装的，而清计数走的还是同一扇没有归属检查的门——会话号顺序自增、M2 接线之前
`close_session(session)` 不校验调用方是不是会话所有者 ⇒ 一个能猜整数的第三方每
`lockout_after - 1` 次替被冒用的身份关一次会话，就能把计数按定义钉在阈值之下，
锁**永远武装不了**，比解锁更省事。
(c) 于是本批先把拆除清状态整个去掉（`succeed` 已经覆盖被删函数唯一的正当收益——
回来的合法主体不该背着旧账——所以删它不损失正向语义），再把 (b) 那扇门本身关上：
**`close_session(session, source)` 现在要求出示与会话相同的传输地址**，地址不符即
`NOT_FOUND` 且**什么都不发生**——会话还在、别人的 `.part` 暂存文件还在、发送预算没被
释放（归属检查之前，只猜到一个自增整数就能终止别人的上传，这是比"清计数"大得多的
破坏面）。拒绝与"id 不存在"在返回值与审计行上**逐字同形**，所以这条入口不做会话
存在性的 oracle；实现上这要求"先落审计行、再把会话放回原位"，因为 `record` 在
principal 留空时会回查会话补上归属——顺序反了就变成泄露主体名的 oracle，本批的测试
正是这样把自己的实现抓红的（`closing_another_peers_session_is_refused_and_leaves_it_intact`）。
两侧各有单测：`session_teardown_touches_no_throttle_state`、
`idle_recycle_clears_no_throttle_state`；契约面柱子：
`foreign_close_refused_and_session_survives`。
**残余（不是"已闭环"）**：源地址是**传输地址而不是凭证**。同一 NAT/同一出口下能看见
彼此地址的调用方仍互相可判，真正的凭证化要等 M2 的 wire 层给每条会话发 capability。
（`src/gateway.rs` 里的 `close_session_id` 是 DataChannel 的会话，与 `FileEngine` 无关，
所以这条入口今天还没有 wire 调用者——那也意味着上述检查目前只有引擎与探针层面的效力。）
**显式声明的代价（五条，一条比一条贵）**：
(1) 全局窗口期内迟到的合法主体同样被拒——"内存有界"与"锁定不失效"之间选后者，
不允许偷偷换成"只累加一个私有计数器、继续比令牌"的 fail-open（评审 r2 NEW-3）。
按洪水节奏的拒止占空比可复算为
`w / (w + (max_throttle_buckets + lockout_after) / 注入率)`——分子是**武装一次的成本**
（灌满 `max_buckets` 行 + `lockout_after` 条溢出失败），不是它们的积；用 PRODUCT 自己
引用的 84.4 次/秒折算 = 60/(60 + 1029/84.4) ≈ **83.1%**（r7 §2.3；这是**可复算表达式**，
不是实测。r8 R8-W-1 抓到我上一版把分子写成 `max_buckets·lockout_after`，那个式子算出来
是 49.7%，与它自己旁边写的 83% 不同源）。
(2) 每身份的锁定门槛从"累计 `lockout_after` 条失败"变成"**同一个窗口内** `lockout_after`
条"，所以**每满一个窗口只滴一条**者不会被锁死；但严格小于一个窗口的涓流仍会跨窗口
累积到阈值（`stale` 用 `>=`，评审 r7 R7-AUDIT-4），本条不是"慢滴免死金牌"。
(3) **聚合侧代价（r7 R7-W-1，本批补登记）**：桶位从一次性消耗品变成每窗口可续的额度池，
于是"整台引擎每窗口可记录的失败数"上界是
`max_throttle_buckets × lockout_after`（默认参数 1024×5/60 s ≈ **85.33 次/秒**；
避开锁定的策略是 `(max_throttle_buckets + 1) × (lockout_after - 1) / lockout_window`
= 1025×4/60 ≈ **68.33 次/秒**（那一轮多出来的一个身份用不掉一整份额度，所以是 +1 而非
`max_buckets`；写成 `1024×4/60` 只有 68.27，r8 R8-W-1 抓到的是这种"式子算不出旁边的数"）；
旧语义同口径是 1024×1/60 s ≈
17.07 次/秒）。这个数**与 PRODUCT 引用的"V1 零节流：实测 84.4 次认证/秒"同量级**，
必须明说：节流器保护的是"单个身份被猜的速率"和"内存"，它**不是**认证 QPS 的上界，
衰减把可记录额度提高了 `lockout_after` 倍。聚合 QPS/成本的那道闸门属于 M2 的连接层
限流与 RSS 计量，仍未闭环。额度侧（不是墙上速率）在产品路径上有可红对象：期望
`throttle_sustainable_failure_budget`。
**但这条聚合上界本批之后不再能被单个地址触及**：`max_failures_per_source`（默认 40）
锁的是**地址本身**，一个源每窗口最多贡献 `max_failures_per_source` 条失败
（40/60 s ≈ 0.67 次/秒，比"衰减之后、限额之前"的 5120 条/窗口小 128 倍）；要重新触及
上面那条聚合上界，攻击者必须在**同一个窗口内**准备
`ceil(max_throttle_buckets × lockout_after / max_failures_per_source)` = **128 个不同源地址**
（5120/40，精确值）。但**武装全局窗口不需要那么多**：那道大路要的是
`max_throttle_buckets + lockout_after` 条溢出失败 = 1029 条，而每个地址最多贡献 40 条，
所以 `ceil(1029/40)` = **26 个地址**就够了；注入总条数没变，变的是必须同时握有的
地址数。这两个数都要写出来——只写 128 会让人读成"表满那条大路被关上了"，而它仍然
只要求一个低速率的多地址注入者（评审 r9 R9-N-8）。
两道门在**表还有位置时**必须可区分：源限额锁的是地址本身，不升级为全体 fail-closed，
所以契约面有两根柱子——`throttle_per_source_budget_scoped_to_address`（小夹具：6 条花完
额度 ⇒ 只有 1 道源锁、第 6 条报 THROTTLED、同地址的新主体被拒、别的地址照常放行）与
`single_address_cannot_fill_the_table`（产品尺寸引擎：一个地址灌 2048 条失败也只留下
40 行，实测 `solo_rows_after_flood = 40`，且 `throttle_globally_locked()` 仍为 false）。
`max_failures_per_source` 的内存口径：**四张表各自 ≤ `max_throttle_buckets`**（两层键的
行、两层键的锁、源账本、源锁），键都是定长摘要。源锁表也有自己的门禁（评审 r9
R9-W-2：它原先没有，于是"账本满 ⇒ 陌生地址第一条失败就锁"变成**每 1 次请求换 1 条
表项**的内存放大路径，恰是最便宜的注入）——源锁表满时与两层键同一条大路一致：
升级为全局窗口。所以"源限额绝不升级为全体 fail-closed"这句的准确形式是"**在源锁表
还有位置时**不升级"，两条大路谁先满谁先全局。两支升级（`locked` 满与 `source_locks` 满）
写的都是**同一个** `global_locked_until` 槽、且直写不取 max——这不是缺陷：所有 `until` 都等于
各自 `now + lockout_window`，后写的 `now` 必然不早于先写的，所以覆盖只会延长不会缩短
（评审 r10 R10-N-5；登记在此是因为这张表本批才有了第二条全局升级路径，后来的读者需要知道
两支共用一个可覆盖的 Option 槽且覆盖方向安全）。断言面：
`unknown_source_locked_on_first_failure_when_ledger_full`（账本满 ⇒ 陌生地址第一条就被锁）
与 `throttle_source_locks() <= max_throttle_buckets`。
(4) **归因残余（r7 R7-W-7）**：节流表里只剩摘要，"谁被锁了"只能靠审计环，而审计把
principal 裁到 `AUDIT_FIELD_MAX_BYTES`——两条 principal 若前 256 字节相同且总长相同，
在审计里渲染成同一串，它们的摘要却是两个桶。长身份面上归因精度只剩"前 256 字节 + 长度"
这一近似类，反向也成立（看着同一条的两行可能来自两个桶）。
这条取舍登记在契约面，不允许只写在案卷自述里。
(5) **比较只有一个入口，且短路可验证（r10 自查 + r9 复核后改写，更早那版是过度声明）**：
`authenticate` 的令牌比较全部经过 `FileEngine::token_eq`，计数也就挂在那一处。
三件事的分层结论（**provenance 各自标明，r10 R10-N-2 抓到过这里两份文档打过架**）：
删掉计数（P6）⇒ 单测与期望 `token_comparisons_short_circuit_when_locked` 红；删掉锁定
预检（M10b）⇒ 在本批 D 轮复验树上是 **12 条单测红 + 12 条冻结期望翻转**——这两支由实现方
在复验树上手跑（8a67e85 那一次是 10/10、加漂移单测后 11/11、再加 pair 侧数量对象后 12/12；
每多一条都是因为新测试同样依赖"锁定先于比较"）。
**绕开** `token_eq` 直接比较（F）实现方本轮**未**复跑，由评审 r10 在同一棵复验树上代跑
证实：在这套 `[workspace.lints.rust] warnings = "deny"` 下 `token_eq` 成为 dead-code，
**编译不过**（实测 `error: method `token_eq` is never used`，且 `cargo check
--all-targets` 连 test profile 一起红），所以"多一个比较点"是构建期挡住的、不是靠测试
（清单与逐条推导见 `.evidence/review-gateway-file-r9/findings.md` §3 与案卷第十一片的
D 轮变异表）。
这里要留一条诚实的痕迹：M10b 那个数字在本链出现过**六个**值——8 红/4 翻转（第十片正文）、
8 红/5 翻转（同片变异表）、r9 静态重推 9/9、8a67e85 实测 10/10（r10 独立复现）、
c5d0918 实测 11/11、最终 D 轮树 b9ebbe4 实测 12/12。`idle_recycle_clears_no_throttle_state` 一直是唯一不红的既有锁定测试，
它的 THROTTLED 来自 `record_failure` 的武装返回值而非预检；9 → 10 的差集按名字逐条对过
（对法：在 r9 读的那棵树里把它给的九个行号逐个回推到 fn 名），是为 R9-W-2 新增的那条源锁表
门禁单测，而空地址那条在 M10b 下**不红**（守卫在预检之前）。按本链既定口径**以实测为准**，
旧值保留在这里而不是抹掉。
仍然**没有**被挡住的那一半要说清：把 `token_eq` **内部**的 `constant_time_eq` 换成
`!=`（长度相关的比较）不会让任何测试红——时序侧信道只能由 `constant_time_eq` 自身的
单测（区分长度/前缀）加评审目视负责，计数与入口唯一性都不背书这一点。
**未证事项**：`lockout_window` 只校验"非 0"与"≤24h"，**没有下界**——把它配成毫秒级
会同时缩短锁定和放宽涓流门槛（一物两用的直接后果）；`max_failures_per_source` 同样
只校验非 0 与两条交叉界，没有"相对 QPS 的下界"概念，因为它管的是爆炸半径不是速率；
principal/source 的长度在进入摘要前不设上界（任意长身份 ⇒ O(len) 摘要成本，r7 R7-N-8）；
身份按字节精确比较，不做 NFC/大小写归一，同一自然人可造任意多桶（r7 R7-N-9，
与代价 (3) 同向；本批的源限额把"一个自然人"这一类收敛到地址粒度，但没有解决
"同一地址下多个自然人"的反向问题）；`Throttle` 内部全部时间读取硬编码
`Instant::now()`，时钟不可注入，因此本契约的时间夹具依赖真实墙钟
（`sweep_idle(now)` 已示范可注入形态，登记为 M1 剩余项；flaky 面见
`.agents/knowledge`）。本批不新增这些规则，也不谎称它们有测；它们随 `files` 配置接线
一起在真实配置面上处理。
**G16（句柄、队列与终端优先）**：`stream_id` 由**服务端签发**，同一流的多个分片
不得各自新开读句柄（V1 反面教训：约 1022 片后句柄耗尽导致整节点 DoS）；读句柄峰值、
并发会话数、单会话在途字节、`.part` 声明大小、重放页回读字节都有上界；
**会话配额是准入检查**：`authenticate` 在全局 `max_sessions` 与单 peer
`max_browser_sessions` 达到上限时直接 `CAPACITY_UNAVAILABLE` 拒（只在 `validate()`
里两两比较等于没有上界，评审 r2 NEW-4），释放的额度必须可复用。
**会话终止也要验归属**：`close_session(session, source)` 必须出示与该会话相同的传输
地址，否则 `NOT_FOUND` 且**什么都不发生**——会话不被终止、别人的 `.part` 暂存文件不
被删、其发送预算不被释放、节流状态不被清（评审 r8 R8-W-2 追到的根因面：会话号顺序自增，
没有这一步时"猜一个整数"就能打断别人的上传）。未知 id 与不属于自己的 id 在返回值与
审计行上逐字同形，不做会话存在性的 oracle；残余是地址不是凭证，凭证化等 M2。
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
`source` 这个键本批之后同时被**五件事**依赖（评审 r11 R11-W-2：早先三份文档各数各的——代码
doc 与探针注释数成三处、本节数成四件事、案卷又换了一份名单，全都少算了同一摘要键里的另一半；
r12 R12-W-1 接着指出"另一半"的后果只钉住了机制、没钉住数量，于是补了
`same_principal_with_two_address_spellings_doubles_the_pair_threshold` 与同名冻结期望）：
per-peer 会话配额、单源失败额度、源锁、`close_session` 的归属证明，以及 `(主体,源)` **摘要键的
源那一半**——最后这一处最容易漏：表示漂移不只把额度按字符串分账，它同样让**单个身份**在两种
写法下拿到两个桶，于是 pair 侧的 `lockout_after` 门槛被翻倍。它们共享同一条前提，也必须一起登记：**wire 层送来的
`source` 不可被对端影响**（应为 DTLS 绑定的 transport address），且**同一条会话在
认证与终止两处必须是同一个字符串**——引擎既不解析也不归一化地址（不剥端口、不处理
IPv6 方括号与 `%zone`），所以两种表示（带端口/不带、大小写、zone 差异）会让合法
所有者关不掉自己的会话，只能等 `idle_timeout`；**这两种退化现在各有机验对象**（评审
r10 R10-N-4：原先这整段是零对象的散文）——单测
`address_representation_drift_arms_two_independent_source_locks` 钉归属那一格，冻结期望
`address_representation_drift_splits_the_source_budget` 钉"一种写法一份额度"那一格。它们钉的是
**后果**，不是给归一化背书：谁将来做了归一化，这两条会红，本段必须同步改；反过来，如果 `source` 里含临时端口且
每连接都变，那么"单源额度"与"源锁"就被逐连接豁免，G15 代价 (3) 里那两个地址数
（128 / 26）会退化成"128 / 26 个字符串"。空 `source` 在 `authenticate` 就被拒
（它不能当归属凭证，见 `FileEngine::authenticate` 的注释）。这条前提早先只为配额
登记过（评审 r3 N-5），现在**五处**共用它（r11 R11-W-2 把这里从"四处"改成五处：漏的是
`(主体,源)` 摘要键的源那一半），M2 接线时必须逐处核。
**归属证明的射程**：目前只有 `close_session` 有；`abort_upload`（删已暂存字节）、
`remove`/`rename`/`commit_upload` 等按 id 动的动词仍不做归属检查，同一类"猜到自增整数
即可破坏他人数据"的面保留到 M2 发 capability —— 不许把 G15/G16 里那句"拆会话不再
清状态"读成这条面已经整体关闭。
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