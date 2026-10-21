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
- 文件访问与上传（REQ-005..REQ-008）：同一节点侧 SSH 客户端跑 **SFTP 子系统**，
  对目标主机的文件系统做浏览/stat/下载/上传/建目录/删除/改名；另可选暴露
  **节点本地目录**（`files.roots`，默认不启用）。元数据走控制通道 JSON，
  **文件字节走独立的二进制 DataChannel（label `nexus.file`）**，读为浏览器拉取、
  写为节点确认连续字节，二者都可从任意 offset 续传。
- `/api/config` 额外暴露文件能力（是否启用、分块大小、本地 root 名单），
  页面据此决定可选项；令牌永不下发。

## Non-Responsibilities

- 不做 SSH 服务器；SSH/SFTP 协议只发生在节点 ↔ sshd（浏览器不解析这些协议）。
- 不做浏览器能力暴露（摄像头/传感器）、HTTP 服务代理（Phase 2）。
- 不做跨网关的**文件中继**：文件会话在持有该浏览器控制通道的节点上执行
  （SFTP 目标仍是任意 sshd）；`MeshSignaler` 是接缝，后续可接。
- 不做持久身份与验证（MVP 用临时身份，节点默认接受）。
- 不做 TURN 服务器本身（TURN 是标准外部服务器；节点仅把配置下发给浏览器）。
- 不实现 Nexus fabric FIB 信令后端（`MeshSignaler` 是接缝；fabric 后端后续接入）。
- 文件模块不做符号链接跟随到 root 外的能力，也不提供 POSIX 属主/chmod 语义。

## Inputs

- `GatewayConfig`：监听地址、节点 PeerId/名称、mesh 节点列表、ICE 服务器、
  TLS 材料（自动生成本地 CA 或文件）、SSH 目标（含空闲超时）、mesh 信令后端
  （`Wss` 模式含本地 `/mesh` 端点 bearer token 与对端 peer 列表）、
  `FileConfig`（文件模块开关、bearer token、本地 root 白名单、分块/会话/大小/空闲限制）。
- 浏览器经 WSS 的 SDP offer / 经 DataChannel 的控制消息（JSON）与文件分块（二进制）。
- 其他网关经 mesh 转发来的 SDP offer。

## Outputs

- HTTPS 页面与静态资源、`/api/config`（含文件能力）。
- WSS 信令 answer。
- DataChannel 控制消息（节点列表、中继 answer、SSH 数据、文件元数据应答）。
- 二进制 DataChannel（`nexus.file`）上的文件分块帧。
- SSH 终端 / SFTP 到本地 sshd 与远端文件系统的 TCP 字节流。

## Allowed Dependencies

- `str0m`（sans-IO WebRTC；`rust-crypto` feature，纯 Rust）
- `tungstenite`（同步 WebSocket，`handshake` feature）
- `rustls` / `rcgen`（TLS 1.3 + 本地 CA 自签证书）
- `serde` / `serde_json`（协议与配置）
- `sha1` / `base64`（RFC 6455 WebSocket 握手）
- `ssh2` / `libssh2-sys`（节点侧真实 SSH 客户端；仅 `std` 同步线程模型）
- `getifaddrs`（枚举本机网卡地址；`listen_addr` 为 `0.0.0.0` 时派生可路由的
  WebRTC UDP 地址，避免 SDP 只带 loopback 候选导致真实浏览器连不上）
- 仅 `std` 线程模型，零 async runtime（与仓库 std-only 姿态一致）。
- SFTP 复用已声明的 `ssh2`（libssh2 的 SFTP 子系统），**不新增依赖**；帧头编解码只用 `std` 切片操作。

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
**G12（文件默认关闭 + fail-closed）**：`files.enabled=false` 时任何 `file_open` 被拒；
启用时必须配置非空 `files.auth_token`（`validate()` 直接拒绝无 token 的启用配置），
每个 `file_open` 都要通过 bearer token 校验（常时序比较）。原因：G2 下浏览器身份
不可验证，REQ-003 访问认证尚未落地，把文件系统暴露成无鉴权面不可接受。
**G13（路径沙箱）**：文件路径一律 `/` 分隔、相对会话 root；`.`/空段丢弃，
出现 `..`、`\` 或 NUL 直接拒绝；解析时对 root 与最近存在的祖先做 canonicalize，
结果必须仍在 canonical root 内（符号链接不得把会话带出 root）。
SFTP 会话的 root 是远端账号的 home（由服务端 CWD 约束）。
**G14（上传原子提交）**：上传写入同目录的 `.part` 暂存文件，节点只按**连续**前缀落盘并
以连续字节数回执；`file_write_end` 存在空洞即失败，成功后 rename 到位，
中止/失败/会话释放都清理暂存文件，绝不留下半截目标文件。
**G15（文件字节只走二进制通道）**：文件分块只走 `nexus.file` 二进制 DataChannel
（帧头 kind/stream_id/offset/flags），控制通道只承载小 JSON 消息；
二进制通道与首条通道在**同一个 SDP**里协商（网关不支持 renegotiate）。
**G16（显式失败，不静默丢弃）**：未知文件会话、未知 stream、错误 token、越权路径、
超限上传都必须回明确应答（`file_open_ack`/`file_op_ack`/`file_write_ack`/`file_list_ack`
带 error），空闲超过 `files.idle_timeout_secs` 回收并回 `file_closed`。

## Side Effects

- TCP/HTTPS 监听线程、每连接线程、事件循环线程、SSH bridge 读线程、
  每个文件会话一个 worker 线程（SFTP 会另开一条到 sshd 的 TCP 连接与会话）。
- UDP socket（WebRTC 媒体/ICE 流量，所有 session 与所有通道共享）。
- 节点本地文件系统的读/写（仅在 `files.roots` 白名单内，且写受 `read_only` 约束）。

## Public API

- `GatewayConfig`（JSON 加载 + 校验）、`MeshNodeInfo`、`IceServer`、`SshConfig`、`TlsConfig`、
  `FileConfig`、`FileRoot`
- `Gateway::start(cfg) -> Result<GatewayHandle, GatewayError>`
- `GatewayHandle::local_addr` / `GatewayHandle::page_addr`（浏览器实际访问地址；
  `listen_addr` 为 `0.0.0.0` 时 `page_addr` 是派生的可路由 IP）
- `SdpPayload`（str0m SDP ↔ JSON 转换）
- `BrowserMessage` / `NodeMessage`（控制通道协议，含 `file_*` 消息）、
  `FileTarget` / `FileEntry`
- `file::*`：`FILE_CHANNEL_LABEL`、`FRAME_READ_CHUNK`/`FRAME_WRITE_CHUNK`、
  `FRAME_HEADER_LEN`、`encode_frame`/`decode_frame`、`normalize_rel`/`render_rel`、
  `FileBackend` trait、`LocalSandbox`、`SftpBackend`、`FileCommand`/`FileReply`、
  `run_file_worker`
- `cert::generate_identity` / `cert::server_config`
- `http::read_request` / `websocket_accept_key` / `lookup_asset`
- `mesh::MeshSignaler` / `InMemoryMeshSignaler` / `WssMeshSignaler`

## Verification

- 单元测试：协议消息 roundtrip（含 `file_*` 与 wire 格式锁定）、SDP payload 转换、
  配置校验负路径（空 node_id / 空或重复 node_list / 空 ICE urls / TLS 文件空路径 /
  mesh WSS 空 token 或空 peer 字段 / **文件模块启用但无 token / 分块超限 /
  root 路径非绝对或重名**）、证书持久化（重启指纹不变）、
  **G11 绑定与候选集合关系（具体 IP 只通告自己、未指定地址绑通配且不通告 0.0.0.0）**。
- 文件引擎单元测试：帧编解码 roundtrip 与短帧/未知 kind 拒绝、
  `normalize_rel` 规则（`..`/`\`/NUL）、本地沙箱 list/stat/read（含 EOF 与越界）、
  `..` 与符号链接逃逸拒绝、只读 root 拒绝所有写操作、
  上传原子提交与暂存文件清理、乱序分块按连续前缀排空、重放容忍、
  超限与空洞提交拒绝、`base_name` 处理 libssh2 readdir 回显前缀。
- 集成测试（`tests/gateway_e2e.rs`）：
  - HTTPS 页面、`/api/config`（含文件能力）与 `/cert` 可访问（rustls 客户端 pin 本地 CA）。
  - WSS 信令：浏览器-like str0m 客户端经 WSS 交换 SDP，建立 DataChannel。
  - **ICE 候选真连通**：`127.0.0.1` 绑定的网关必须通告且仅通告 loopback 候选，
    并真的连上（G11 回归）；未指定地址绑定时候选等于可路由网卡集合。
  - 双节点：经 in-memory mesh 中继，与第二个节点建立 DataChannel。
  - WSS mesh：两个独立 gateway 经 `/mesh` bearer-token 中继 SDP 并建连；
    错误 token 返回 401。
  - SSH 终端：DataChannel → 节点侧真实 SSH 客户端（ssh2）→ **真实 sshd 子进程**
    （OpenSSH，loopback 高端口，key 认证）→ 命令回显；空闲超时后终端被关闭。
  - 中继 SSH：经 WSS mesh 在两个 gateway 间中继终端，目标节点跑真实 SSH 客户端。
  - **文件模块**：模块关闭/令牌错误 → 显式拒绝；本地 root 会话经
    **二进制通道**完成 list/stat/分块下载（含 offset 续读与 final 标志）；
    上传含乱序分块、重放、`write_end` 提交后磁盘内容与无暂存残留；
    会话数上限拒绝；`..` 越权在通道上被拒；
    **SFTP 对真实 sshd（`internal-sftp`）完成 mkdir/上传/列表/分块下载/改名/递归删除/关闭**。
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