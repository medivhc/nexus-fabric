# nexus-outbound-hysteria2

> 出站层 crate（`layer = "outbound"`, `portable = false`）。
> 协议语义：`docs/protocols/hysteria2.md`（clean-room 实现）。

## Responsibility

实现 `nexus_connectivity::OutboundAdapter` 的 **Hysteria2** 出站实现：
QUIC（RFC 9000）+ 不可靠数据报扩展（RFC 9221）上的 TCP/UDP 代理。

提供：

- QUIC 建连（`client.rs` + `driver.rs`）：SNI（`sni` 为空则用 server host）、
  ALPN `h3`、**禁用 QUIC bit greasing**、DATAGRAM 收发、流接收窗口 8MB /
  连接接收窗口 20MB / 最大空闲超时 30s / 最大并发双向+单向流各 1024、
  10s keep-alive（ack-eliciting）；证书校验三选一（`tls.rs`）：
  `pin-sha256`（叶子 DER 的 SHA-256，**替代**链校验+主机名校验，mihomo
  行为，允许自签名）/ `insecure`（仍校验 TLS 握手签名）/ 系统根证书
  （`rustls-native-certs`）；
- 最小 HTTP/3 认证（`auth.rs` + `qpack.rs`，文档 §2.1/§3.1/§5 坑 #1）：
  单向控制流（stream 2）发空 SETTINGS `[0x00, 0x04, 0x00]`（QPACK 动态表
  保持禁用）；stream 0 发 HEADERS 帧（`0x01` + varint 长度 + QPACK 块），
  7 个头（`:method/:scheme/:authority/:path` + `hysteria-auth` /
  `hysteria-cc-rx` / `hysteria-padding`，全小写线格式，字面量永不索引编码）；
  响应校验 `:status == 233`（其他一律认证失败断开），解析 `hysteria-udp`
  与 `hysteria-cc-rx`；拒绝 DATA 先于 HEADERS、拒绝 QPACK 动态表引用；
- `TCPRequest` / `TCPResponse` 帧编解码（`frames.rs`，varint `0x401`、地址文本
  `host:port`、padding）；fast-open 语义（请求发出后不等响应即返回，
  **读侧始终先剥离 `TCPResponse`**）；
- `UDPMessage` 编解码（`frames.rs`；`session u32BE | packet u16BE | frag_id |
  frag_count | varint 地址长 | 地址文本 | 载荷`）；UDP session id 本地从 0
  递增分配，无显式关闭；超上限的包直接丢弃（`DatagramTooLarge`，不分片）；
- Salamander 混淆（`obfs.rs`）：`salt(8) + (payload XOR BLAKE2b-256(key||salt))`
  的加/解，发生在 QUIC 包之下的 driver 收发处；`obfs = "gecko"` 配置即拒绝；
- QPACK 静态表（RFC 9204 Appendix A 全表，`qpack.rs`）：解码支持静态表索引
  引用与静态表名引用；字符串（值以及 §4.5.4 的字面量名）支持 Huffman（`H` 位）
  解码（RFC 7541 附录 B 码表，含 EOS/padding 校验），编码侧恒 `H`=0；
- 最小 sans-IO QUIC 驱动（`driver.rs`，同步阻塞 API）：UDP 收发、定时器、
  端点事件路由、stream 读写原语（`write_all` / `read_exact` / `read_some` /
  `read_varint`）、DATAGRAM 收发；client 与测试用 server 共用；
- 测试用最小 server（`test_server.rs`，**仅测试**）：rcgen 自签证书、
  密码校验、`:status: 233` 响应、TCP 回显、UDP 回显；另有按目标地址选择的
  TCP 测试模式：`SINK_TARGET`（吸收长度前缀的上行并回实收字节数）与 crate
  内的 banner / 关闭前数据 / 无响应 FIN / 拒绝四种；
- 结构化错误 `Hysteria2Error`（不以日志文本代替类型；`Display`/ `Debug`
  绝不回显密码；`Hysteria2Target` 的 `Debug` 对密码脱敏）。

## QUIC 选型结论（`Driver` vs `quinn-proto` 直接）

**直接使用 `quinn-proto` 0.11（workspace 已有 `[patch.crates-io]` 的 vendor
版本），不复用 `nexus-fabric` 的 `Driver`。** 原因：

- `Driver::connect` 硬编码 `server_name = "nexus-fabric"`（SNI 不可配）；
- 客户端 TLS 是 Nexus 自有的 PeerId-pinned ed25519 verifier，不支持
  `pin-sha256` / `insecure` / 系统根证书三选一；
- `ConnConfig` 只有 `addrs` + `handshake_timeout`，无 ALPN / 窗口 / 空闲超时 /
  DATAGRAM 缓冲 / greasing 等传输旋钮；
- 其 TLS 身份模型（PeerId 绑定自签证书）与 Hysteria2 的服务器证书模型不兼容。

`quinn-proto` 的 sans-IO `Endpoint`（`Endpoint::new` 不持有 socket，
`poll_transmit` / `handle` / `poll_timeout` 由调用方驱动）满足全部需求，
且 `EndpointConfig::grease_quic_bit(false)` 直接支持禁用 greasing——
无需引入 `quiche` 新依赖。

## Non-Responsibilities

- **Brutal CC** 固定速率拥塞控制：只收发 `Hysteria-CC-RX` 协商字段
  （`0`=无限制 / `"auto"`=用 CC 自适应 / 具体数值），拥塞算法用
  quinn-proto 默认（Cubic，`TransportConfig` 默认值）；
- **端口跳跃**（`ports` / `hop-interval` 定时轮换 + 源地址归一化）：列为后续；
- **完整 HTTP/3 连接**：只做认证所需的最小子集（SETTINGS 空帧 + 一次
  QPACK HEADERS）；server 的 SETTINGS / QPACK 动态表 / 其他 H3 帧不处理；
- **server 侧产品实现**：只有测试用最小 server；
- UDP 分片重组（超上限直接丢弃）、session 复用池 / 心跳定时器 /
  断线重连（由上层装配）；
- `nexus-proxy` / 选路 / 策略组不依赖本 crate（组合根装配）；
- 不做第二套系统级 Plan。

## 与文档的出入 / 未确认点

- `:authority` 头的值按文档取字面量 `"hysteria"`（非 server host）；
  头字段名在线上用全小写（HTTP/3 要求），文档表格的大小写为逻辑名；
- `Hysteria-Padding` 随机串：文档只给 256~2048 字节 `[a-zA-Z0-9]` 范围，
  具体长度分布未规定——本实现用系统 RNG 在该区间均匀取值；
- `TCPRequest` 的 padding 长度文档未规定——本实现取 16 字节随机；
- 认证响应缺 `hysteria-cc-rx` 时视为 `Auto`（// 未确认：文档未明确缺省语义，
  按最接近的 "auto" 处理）；缺 `hysteria-udp` 时视为非法响应（文档 §3.1
  要求至少包含该头）；
- DATAGRAM 收发缓冲：文档"收发队列各 1024"指包数，quinn-proto 以字节计，
  按 1350 字节/包折算为 `1024*1350` 字节；
- QPACK 字符串解码支持 Huffman（`H` 位，RFC 7541 附录 B，见 crate 私有
  `huffman` 模块）；本端编码恒 `H`=0，不实现 Huffman 编码；
- quinn-proto 默认拥塞控制为 Cubic（`TransportConfig` 默认值，源码确认）；
- `TCPResponse`（fast-open 读侧剥离）上限 64 KiB（状态 + 消息 + padding）：
  文档未规定上限，超出视为非法帧，防止按对端声明的长度无界缓冲；响应帧按
  字节累积到完整才解码，读超时保留已读部分，帧后同批到达的载荷优先返回
  （2026-10-27，interop T2 修复）；
- driver 每次 `pump` 不阻塞地处理 socket 中已到达的包（每次至多 64 个），
  零等待读也能收包；读侧在看到对端关闭后再读一次，同一次 `pump` 收到的
  数据与关闭不会丢数据（2026-10-27）；
- // 未确认：`max_datagram_frame_size` 的对端通告值未经真实 server 验证，
  loopback 测试中 client/server 均为本实现。

## Inputs

- 配置：`tag`、服务端 `server`/`port`、认证 `password`、`sni`（可选）、
  证书校验模式（`pin-sha256` / `insecure` / 系统根）、`cc_rx_bps`
  （`Hysteria-CC-RX`）、`obfs`（`none` / `salamander` + `obfs-password`）、
  `fast-open`（默认 true）、`udp`（默认 true）、`handshake_timeout`；
- 运行时：`Hysteria2Adapter::connect()` 自行建 UDP socket 并完成 QUIC 握手与认证
  （阻塞）。

## Outputs

- `OutboundAdapter::handoff` → `OutboundHandoff { kind = "hysteria2", tag, locator }`；
- `Hysteria2Client`：`open_tcp` / `stream_read` / `stream_write` /
  `stream_finish`、`alloc_udp_session` / `send_udp` / `recv_udp`；
- 认证/帧/地址字节流；结构化错误。

## Allowed Dependencies

- `nexus-connectivity`（OutboundAdapter 接缝）；
- 已评审入仓第三方：`quinn-proto 0.11`（vendor patch，`rustls`+`ring`
  features；与 `nexus-fabric` 同源）、`rustls 0.23`（`ring`+`std`）、
  `rustls-native-certs 0.8`（系统根证书）、`ring 0.17`（系统 RNG +
  握手签名校验）、`rcgen 0.13`（测试用自签证书）、`sha2 0.10`
  （`pin-sha256` 计算）、`blake2 0.10`（Salamander `BLAKE2b-256`）、
  `bytes 1`（quinn-proto sans-IO buffer 类型）。
