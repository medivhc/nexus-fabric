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

## Non-Responsibilities

- 不做 SSH 服务器；SSH 协议只发生在节点 ↔ sshd（浏览器不解析 SSH 协议）。
- 不做浏览器能力暴露（摄像头/传感器）、文件系统浏览、HTTP 服务代理（Phase 2）。
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
- `getifaddrs`（枚举本机网卡地址；`listen_addr` 为 `0.0.0.0` 时派生可路由的
  WebRTC UDP 地址，避免 SDP 只带 loopback 候选导致真实浏览器连不上）
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
重启指纹不变；`/cert` 提供 PEM 下载。证书目录权限 `0700`、私钥 `key.pem` 权限 `0600`（Unix），
写盘为临时文件 + 原子 rename；加载旧版本落盘的身份时收紧过宽权限；损坏身份重生成必须有 warn 日志。
ICE host candidate 必须始终包含 UDP 套接字的**实际绑定地址**（接口枚举候选之外的强制项，
去重）：绑在具体 IP（含 loopback）上的套接字不会收到发往其他网卡 IP 的数据报。

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
  mesh WSS 空 token 或空 peer 字段）、证书持久化（重启指纹不变）。
- 集成测试（`tests/gateway_e2e.rs`）：
  - HTTPS 页面、`/api/config` 与 `/cert` 可访问（rustls 客户端 pin 本地 CA）。
  - WSS 信令：浏览器-like str0m 客户端经 WSS 交换 SDP，建立 DataChannel；
    answer SDP 断言包含 UDP 套接字实际绑定地址的 host candidate（H1 回归）。
  - 双节点：经 in-memory mesh 中继，与第二个节点建立 DataChannel。
  - WSS mesh：两个独立 gateway 经 `/mesh` bearer-token 中继 SDP 并建连；
    错误 token 返回 401。
  - SSH 终端：DataChannel → 节点侧真实 SSH 客户端（ssh2）→ **真实 sshd 子进程**
    （OpenSSH，loopback 高端口，key 认证）→ 命令回显；空闲超时后终端被关闭。
    环境门禁：宿主缺少 `sshd`/`ssh-keygen` 时这些用例显式 skip（打印原因），
    不计为产品失败；fixture 在 root（容器）下自适应 `PermitRootLogin yes`。
  - 中继 SSH：经 WSS mesh 在两个 gateway 间中继终端，目标节点跑真实 SSH 客户端。
  - worker 连接回收用例依赖 `ss`；宿主缺 `ss` 时显式 skip（不得假通过）。
  - 负路径：无节点列表/空 node_id 配置被拒；SSH target 拒绝连接返回错误；
    未知 session 的 `ssh_data` 返回 `ssh_close`；re-offer 被拒（返回错误而非假 answer）。
  - 所有消息等待必须有 deadline（缺消息 = 带超时报错的失败，不得无限挂起）。

## Performance Budget

- 控制消息：单条 DataChannel 消息处理 < 1ms（无锁队列 + 单事件循环线程）。
- SSH 数据：纯内存拷贝转发（TCP ↔ DataChannel），无额外拷贝（每 chunk 一次 base64）。

## Observability

- `tracing` 日志：连接错误、协议错误、mesh 错误。
- Session 生命周期：channel open/close、ICE 状态变化。

## Platform Constraints

- Linux/macOS/Windows 均可（纯 Rust + std）。
- 不依赖平台专用 API。