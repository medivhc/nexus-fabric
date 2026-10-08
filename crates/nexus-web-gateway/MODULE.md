# nexus-web-gateway — Module Contract

## Responsibility

浏览器零安装接入 Nexus 网格的 Web 接入点（每节点内嵌）：

- HTTPS 服务：静态页面（xterm.js 终端）+ `/api/config` + WSS 信令端点 `/ws`。
- 节点侧 WebRTC 端点（str0m，sans-IO）：接受浏览器 SDP offer，建立
  RTCPeerConnection + DataChannel（控制通道）。
- 经控制通道下发 mesh 节点列表（PeerId、候选地址、服务目录）与 ICE 服务器配置。
- SDP 信令中继：浏览器对其他节点的 offer 经已建连 mesh 转发（`MeshSignaler` trait），
  不依赖外部信令服务。
- 网页 SSH 终端：浏览器 DataChannel → 目标节点 → 本地 sshd（TCP 转发）。

## Non-Responsibilities

- 不做真实 SSH 客户端/服务器协议（节点只做 TCP 字节转发；SSH 认证由页面侧
  SSH 客户端或后续阶段的节点侧 SSH 客户端完成）。
- 不做浏览器能力暴露（摄像头/传感器）、文件系统浏览、HTTP 服务代理（Phase 2）。
- 不做持久身份与验证（MVP 用临时身份，节点默认接受）。
- 不做 TURN 服务器本身（TURN 是标准外部服务器；节点仅把占位符配置下发给浏览器）。
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
- 仅 `std` 线程模型，零 async runtime（与仓库 std-only 姿态一致）。

## Forbidden Dependencies

- `tokio`、`async-std`、任何 async runtime。
- Nexus 内部 crate（本 crate 是独立接入模块；fabric FIB 经 `MeshSignaler` trait
  注入，不直接依赖 `nexus-fabric`）。
- 真实密钥/证书材料硬编码。

## Invariants

**G1（全程 TLS）**：所有浏览器可见路径均为 HTTPS/WSS，无纯 HTTP。
**G2（临时身份）**：浏览器身份是内存中的临时 ed25519/随机 ID，节点侧默认接受，
不持久化、不验证。
**G3（中继不解密）**：SSH 终端是纯 TCP 字节转发，节点不解析 SSH 应用层内容。
**G4（凭证不落盘）**：页面提交的密码/私钥只保存在内存 session 中，关闭即丢弃，
不写盘、不做浏览器端存储。
**G5（最小 API 面）**：对外只暴露 `Gateway::start` / `GatewayConfig` /
协议消息类型；内部 `Session`/事件循环为 private。
**G6（类型化错误）**：业务失败返回 `GatewayError`，不用 panic。
**G7（mesh 端点鉴权）**：`/mesh` WSS 端点要求 `Authorization: Bearer <token>`，
本地 token 由 `MeshConfig::Wss.token` 配置；缺失/错误返回 401。
**G8（空闲终端回收）**：SSH bridge 超过 `SshConfig.idle_timeout_secs` 空闲即断开，
事件循环周期性扫描并下发 `ssh_close`。

## Side Effects

- TCP/HTTPS 监听线程、每连接线程、事件循环线程、SSH bridge 读线程。
- UDP socket（WebRTC 媒体/ICE 流量，所有 session 共享）。

## Public API

- `GatewayConfig`（JSON 加载 + 校验）、`MeshNodeInfo`、`IceServer`、`SshConfig`、`TlsConfig`
- `Gateway::start(cfg) -> Result<GatewayHandle, GatewayError>`
- `GatewayHandle::local_addr`
- `SdpPayload`（str0m SDP ↔ JSON 转换）
- `BrowserMessage` / `NodeMessage`（DataChannel 协议）
- `cert::generate_identity` / `cert::server_config`
- `http::read_request` / `websocket_accept_key` / `lookup_asset`
- `mesh::MeshSignaler` / `InMemoryMeshSignaler` / `WssMeshSignaler`

## Verification

- 单元测试：协议消息 roundtrip、SDP payload 转换、配置校验负路径
  （空 node_id / 空或重复 node_list / 空 ICE urls / TLS 文件空路径 /
  mesh WSS 空 token 或空 peer 字段）。
- 集成测试（`tests/gateway_e2e.rs`）：
  - HTTPS 页面与 `/api/config` 可访问（rustls 客户端 pin 本地 CA）。
  - WSS 信令：浏览器-like str0m 客户端经 WSS 交换 SDP，建立 DataChannel。
  - 双节点：经 in-memory mesh 中继，与第二个节点建立 DataChannel。
  - WSS mesh：两个独立 gateway 经 `/mesh` bearer-token 中继 SDP 并建连；
    错误 token 返回 401。
  - SSH 终端：DataChannel → mock sshd（TCP）→ 回显，认证 prologue 生效；
    空闲超时后终端被关闭。
  - 负路径：无节点列表/空 node_id 配置被拒；SSH target 拒绝连接返回错误。

## Performance Budget

- 控制消息：单条 DataChannel 消息处理 < 1ms（无锁队列 + 单事件循环线程）。
- SSH 数据：纯内存拷贝转发（TCP ↔ DataChannel），无额外拷贝（每 chunk 一次 base64）。

## Observability

- `tracing` 日志：连接错误、协议错误、mesh 错误。
- Session 生命周期：channel open/close、ICE 状态变化。

## Platform Constraints

- Linux/macOS/Windows 均可（纯 Rust + std）。
- 不依赖平台专用 API。