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
  不是已交付 API**：实现按 M1-M4 分期落地，`requirements.toml` 的 REQ-005..REQ-011 保持
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

**G12（文件面默认关闭，配置不自洽即拒启动）**：`files.enabled` 缺省 `false`；
`FileLimits` 与 SCTP 发送预算的交叉约束（`chunk_bytes × max_sessions × 在途页数` 不得
突破声明的每会话/全局预算）、root 非空且不重复、`read_only` 组合等任一校验不过 ⇒
**拒绝启动**，绝不"半启用"或静默放宽（fail-closed）。
**G13（root 是唯一授权面，逐分量解析 + 打开后重核实）**：root 必须是 `canonicalize`
后的真实路径（非规范 root 在 Windows/macOS 上会回显错误路径并使越界检查失效）；
自 root 起对每一段做 `lstat`/`readlink`，任一段是符号链接即拒绝；**打开之后**重新解析
核实最终路径仍在 root 内（TOCTOU 快照类型化，不允许"解析一次即相信"）；改名/删除的
目标同样受此约束，删除**不递归**出 root。
**G14（上传不覆盖已存在目标）**：目标已存在 ⇒ `OUTPUT_EXISTS` 且原字节一字未动；
本地引擎用同文件系统 `hard_link` 原子发布；SFTP 引擎显式携带 no-replace 语义，
但**"远端 sftp-server 是否 honor 该标志"在 OpenSSH 各版本上属未实测项**，
探针结论达标之前不得声称跨进程对手也不会覆盖；拒绝路径不留 `.nexus-part.*` 残留。
**G15（文件凭证不落盘，失败计数有界）**：文件通道使用独立于页面登录的配置令牌，
比较必须常数时间；认证失败按（会话 + 源）**两层键**节流并锁定，计数与表项**有界**
（不得随伪造会话线性增长）；锁定窗口内正确口令也不得绕过；沿用 G4 的"凭证不落盘"。
**G16（句柄、队列与终端优先）**：`stream_id` 由**服务端签发**，同一流的多个分片
不得各自新开读句柄（V1 反面教训：约 1022 片后句柄耗尽导致整节点 DoS）；读句柄峰值、
并发会话数、单会话在途字节、全局 RSS、`.part` 声明大小、累计重哈希字节都有上界；
超预算回 `QUEUE_FULL`/`CAPACITY_UNAVAILABLE` 并**显式计数**丢弃的文件类消息，
终端（pty）字节流优先且零丢失。
**G17（分页与截断必须显式）**：列表条目数与单条 ack 字节数都有服务端硬上限；
超限返回 `TRUNCATED` + `next_offset`，`next_offset` 必须单调；**绝不**把截断结果标记为
完整列表，也不允许单条 ack 大到能头阻塞控制通道。
**G18（拉式续传与前缀完整性）**：读取是拉式的；上传 ack 只承认**已连续落盘**的字节数
（不是"收到某片"）；完全重复的旧页必须逐字节匹配才接受；跳跃或部分重叠的页拒绝，
**不重写已承认前缀**；完整 SHA-256 与长度校验通过后才提交发布；字段语义与
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
结果码），**拒绝也要记**。

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

- Linux/macOS/Windows 均可（纯 Rust + std）。
- 不依赖平台专用 API。