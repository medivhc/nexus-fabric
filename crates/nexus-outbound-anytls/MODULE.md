# nexus-outbound-anytls

> 出站层 crate（`layer = "outbound"`, `portable = false`）。
> 协议语义：`docs/protocols/anytls.md`（clean-room 实现）。

## Responsibility

实现 `nexus_proxy_config::outbound_seam::OutboundAdapter` 的 **AnyTLS** 出站实现：
在一条 TLS 连接（rustls 0.23 + ring）上承载 AnyTLS v2 会话层多路复用。

提供：
- 认证帧编解码：`SHA256(password)(32) + u16BE(padding0_len) + padding0`，拼成一个
  buffer **一次 `write`** 发出（§5 坑 #1：官方单次 `ReadOnceFrom` 读认证，分开写
  会导致对端读 padding 长度时 EOF）；
- 7 字节会话帧头编解码（`cmd + stream_id(u32 BE) + data_len(u16 BE)`）与命令表
  0~10（未知命令按 `cmdWaste` 处理）；
- Settings 文本（`v=2` / `client=<name>` / `padding-md5=<hex>`）的构造与解析，
  以及 `ServerSettings` / `UpdatePaddingScheme` 的 client/server 两端处理；
- 默认 padding scheme（§4.1 `stop=8` 文本）的数据结构（`PaddingScheme` /
  `PacketPaddingPolicy` / `PaddingSegment`）与 `padding-md5`（MD5 小写 hex）计算；
- SOCKS5 地址编码/解码（首个 PSH 的目标地址；含 IPv4/IPv6/Domain）；
- client 侧：建 session（认证→Settings→等 ServerSettings）、开 stream
 （SYN→PSH(地址)→等 SYNACK）、关 stream（FIN）；
- server 侧最小实现（测试用）：一次读认证、校验 SHA256、Settings 前收到 SYN
  则先发 Alert 再拒绝 session、比对 `padding-md5`（不一致下发 UpdatePaddingScheme）、
  `v>=2` 回 ServerSettings；
- UDP-over-TCP（sing-box v2）：魔法地址 `sp.v2.udp-over-tcp.arpa:0`、
  eager Connect 载荷（`0x01 + SOCKS5地址`，在 SYNACK 等待之前写出以规避死锁）、
  `u16 BE` 长度前缀分包；
- rcgen 动态自签证书 + rustls 客户端证书 pinning / 服务端配置构造（离线 loopback E4）；
- 结构化错误 `AnyTlsError`（不以日志文本代替类型；认证失败不泄露密码/hash）。

## Non-Responsibilities

- 不实现 padding 的**写路径**（按 scheme 对 TLS 写包做分包/填充是 session 运行时的
  职责，本 crate 只提供 scheme 数据结构与 md5 协商）；
- 不实现 session 复用池 / 空闲回收 / 心跳定时器（§4.2 的运行时策略，由上层装配）；
- 不做 TUN/透明网卡、不做 WebSocket/gRPC 伪装；
- 不做系统根证书校验（客户端固定 pin 服务端公钥）；
- `nexus-proxy` / 选路 / 策略组不依赖本 crate（组合根装配）；
- 不做第二套系统级 Plan。

## Inputs

- 配置：`tag`、服务端 `locator`、`password`、客户端标识（Settings `client=` 字段，
  默认 `nexus-anytls/0.1.0`）；
- 运行时：已建立的 TLS 字节流（`Read + Write`，如 rustls `StreamOwned`）。

## Outputs

- `OutboundAdapter::handoff` → `OutboundHandoff { kind = "anytls", tag, locator }`；
  错误类型为 `OutboundHandoffError`（当前无生产者，见 proxy-config MODULE）；
- 认证/帧/Settings/地址字节流；结构化错误。

## Allowed Dependencies

- `nexus-proxy-config`（出站身份/交接词汇 `outbound_seam::OutboundAdapter`）；
- 已评审入仓第三方：`rustls 0.23(ring,std)`、`rcgen 0.13`、`sha2 0.10`、
  `md5 0.7`（仅 `padding-md5` 指纹计算，非安全用途；版本已在 Cargo.lock 锁定，
  license 已 allowlisted）。

## Forbidden Dependencies

- `nexus-proxy` / 选路 / 策略组 / 系统根证书（webpki-root-certs 类 CDLA 包）；
- tokio / 异步运行时（与仓库 loopback blocking+thread 模式一致）；
- 任何 wasm 不可移植但未隔离的依赖。
- `nexus-connectivity`（v9 CLI 产品线运行时，frozen；**目标态禁止**）。
  接缝 ② 已于 2026-10-28（P2）清除：出站身份/交接词汇定义于 `nexus-proxy-config`，
  本 crate 对 `nexus-connectivity` 的直接边为 0
  （见 `docs/DOC-AUDIT-2026-10-26-dual-stack.md` 与 `docs/adr/0001-dual-stack-boundary.md`）。

## Invariants

- `outbound_kind() == "anytls"`（稳定标签）；
- 密码 hash 不匹配 → `AuthDenied`，且**不在失败消息中泄露密码或其 hash**；
- 认证 32+2+padding0 必须拼成一个 buffer 一次 `write`（TLS record 对齐）；
- Settings 帧（cmd=4, stream 0）是每个新 session 的第一帧；server 在收到它之前
  收到 SYN 必须发 Alert 并拒绝 session；
- `padding-md5` 口径：`DEFAULT_PADDING_SCHEME` 常量文本原始字节的 MD5（无末尾换行）；
  client/server 握手均用同一口径；
- TLS 客户端只接受被 pin 的服务端证书；
- 离线确定性：同一份 password+目标永远产生同一认证/帧字节；不连公网；
- server/client 会话线程必须 join 回收（结构化并发）；
- UoT eager 载荷必须在 SYNACK 等待**之前**写出（死锁规避）。

## Side Effects

- 打开 loopback TCP 监听/连接；生成内存内自签证书；不写盘、不读系统证书库。

## Verification

- crate 内单测：认证帧 roundtrip / 错密码 → `AuthDenied`、7 字节帧头 roundtrip
  （全部 11 个命令值 + 未知值→Waste）、Settings roundtrip、padding-md5 确定性、
  SOCKS5 地址 roundtrip、UoT 编解码、loopback TLS client↔server 最小握手
  （成功/错密码/md5 不一致→UpdatePaddingScheme）、stream 开/关帧序列、
  SYN 先于 Settings → Alert+拒绝、UoT eager 载荷顺序。

## Portability

`portable = false`：ring 需要 C/asm（同 trojan）；
本 crate 不进 `harness.toml [portable_core]`，不污染 portable-core 门禁。

## Unsafe

本 crate 自身 `#![forbid(unsafe_code)]`；ring 内部 unsafe 属第三方，不在本 crate 扩散。

## Public API

- 认证：`auth_digest` / `encode_auth` / `send_auth`（一次写）/ `parse_auth` /
  `recv_auth`（server 一次读）；
- 帧：`AnyTlsCommand::{from_u8, as_u8}` / `AnyTlsFrame` / `encode_frame` /
  `decode_frame_bytes` / `read_frame` / `write_frame`；
- Settings：`Settings` / `encode_settings` / `encode_server_settings` /
  `parse_settings`；
- Padding：`DEFAULT_PADDING_SCHEME` / `PaddingScheme` / `PacketPaddingPolicy` /
  `PaddingSegment` / `parse_padding_scheme` / `default_padding_scheme` /
  `padding_md5_hex`；
- 地址：`AnyTlsTarget` / `encode_socks5_addr` / `decode_socks5_addr`；
- UoT：`UOT_MAGIC_DOMAIN` / `UOT_MAGIC_PORT` / `uot_magic_target` /
  `encode_uot_connect` / `encode_uot_datagram` / `decode_uot_datagrams`；
- 会话：`ClientHandshake` / `client_handshake` / `client_open_stream` /
  `client_open_stream_with_payload` / `client_open_uot_stream` /
  `server_handshake`（server 最小实现）；
- TLS：`LoopbackIdentity` / `generate_loopback_identity` / `server_config` /
  `client_config`；
- 错误：`AnyTlsError`；adapter：`AnyTlsAdapter`（`outbound_kind() == "anytls"`）。

## 与文档有出入 / 未确认处

- `padding-md5` 的 md5 输入口径：文档只说"padding scheme 原始字节"；本实现取
  `DEFAULT_PADDING_SCHEME` 常量文本的原始字节（无末尾换行）。与对端协商时双方
  必须口径一致；本 crate client/server 侧一致。
- `UpdatePaddingScheme` 之后：文档未明确当前 session 是否继续；本实现下发新
  scheme 后若 `v>=2` 仍回 `ServerSettings`（session 可用，client 按文档为后续
  session 切换 scheme）。
- UoT 包内分片细节未确认：只实现已确认的 `u16 BE` 长度前缀分包，相关函数注释
  标 `// 未确认：`。
- server 最小实现对握手阶段的 `HeartRequest/HeartResponse` 等非预期帧直接以
  `UnexpectedCommand` 拒绝（fail-closed），而非忽略；完整 server 由后续工作实现。
