# nexus-outbound-hysteria2

> 出站层 crate（`layer = "outbound"`）。clean-room 实现，不拷贝任何既有代码。
> 协议语义：`docs/protocols/hysteria2.md`；官方规范：https://github.com/apernet/hysteria/blob/master/PROTOCOL.md

## Responsibility

实现 `nexus_connectivity::OutboundAdapter` 的 **Hysteria2** 出站实现：
基于 QUIC（RFC 9000）+ DATAGRAM（RFC 9221）的 TCP/UDP 代理协议。

提供：

- QUIC varint 编解码（RFC 9000 §16）：`encode_varint` / `decode_varint`；
- TCP 中继帧：`TcpRequest`（`0x401 | varint地址长 | 地址文本 | varint pad长 | pad`）
  与 `TcpResponse`（`status(1) | varint消息长 | 消息 | varint pad长 | pad`）编解码；
- UDP 中继帧：`UdpMessage`（`session_id u32BE | packet_id u16BE | frag_id | frag_count |
  varint地址长 | 地址文本 | 载荷`）编解码；
- 最小 QPACK 编码器（literal field line，不用动态表）：`qpack_encode_headers`；
- HTTP/3 认证：空 SETTINGS 帧构造（控制流 stream 2）、HEADERS 帧构造（stream 0，
  `:method/:scheme/:authority/:path` + `Hysteria-Auth` + `Hysteria-CC-RX` +
  `Hysteria-Padding`）、响应解析（`:status == 233`、`Hysteria-UDP`、`Hysteria-CC-RX`）；
- QUIC 传输配置：`build_quic_client_config` 生成 quinn-proto `ClientConfig`
 （ALPN `h3`、禁用 grease、启用 DATAGRAM、流/连接窗口、空闲超时）；
- 配置门禁：`Hysteria2Config::validate`（必填项、端口范围、obfs 门禁、
  hop ports 解析、hop-interval 钳制）；
- 结构化错误 `Hysteria2Error`（不以日志文本代替类型；错误展示绝不回显 password）。

## Non-Responsibilities

- **Salamander 混淆的完整实现**：线格式（`salt(8) | payload XOR BLAKE2b-256(key||salt)`）
  已在文档中定义，`Salamander` 结构提供接口占位；BLAKE2b 需新增第三方依赖，
  按依赖政策需走评审，本 crate v1 不引入，配置中启用时返回
  `Hysteria2Error::SalamanderNotImplemented`（fail-closed）；
- **端口跳跃运行时**：`HopPorts::parse` 解析端口集合，`hop_interval` 钳制；
  实际的定时轮换与源地址归一化由上层 driver 完成；
- **Brutal CC**：`rx_bps` 只放进 `Hysteria-CC-RX` 请求头，不实现固定速率发送；
  拥塞控制用 quinn-proto 默认；
- **完整 QUIC I/O driver**（UDP socket + 事件循环 + 保活）：由上层装配；
  本 crate 提供传输参数与协议帧，`quinn-proto` 为 sans-IO；
- session 复用池 / 断线重连 / 选路 / 策略组（由上层装配）；
- `nexus-proxy` / 选路 / 策略组不依赖本 crate（组合根装配）。

## Inputs

- 配置：`tag`、服务端 `server`/`port`、`password`（`Hysteria-Auth`）、`sni`、
  `skip_cert_verify`、`pin_sha256`、`up_mbps`/`down_mbps`、`obfs`（`salamander`
  占位）、`obfs_password`、`ports`（跳跃端口集合）、`hop_interval`、
  `fast_open`、`udp` 开关；
- 运行时：quinn-proto `Endpoint`（由上层 driver 提供）。

## Outputs

- `OutboundAdapter::handoff` → `OutboundHandoff { kind = "hysteria2", tag, locator }`；
- 协议帧字节流；结构化错误。

## Allowed Dependencies

- `nexus-connectivity`（OutboundAdapter 接缝）；
- `quinn-proto` 0.11（与 nexus-fabric 同版本，workspace patch 生效）；
- `bytes`（quinn-proto sans-IO API）；
- `rustls` 0.23（TLS 客户端配置）；
- 标准库。

## Forbidden Dependencies

- `quiche` / 其他 QUIC 栈（统一用 quinn-proto）；
- tokio / 异步运行时；
- `nexus-proxy` / 选路 / 策略组。

## Invariants

- `outbound_kind() == "hysteria2"`（稳定标签）；
- QUIC varint 编码遵循 RFC 9000 §16（首字节高 2 位定长度）；
- TCPRequest 地址为**文本** `host:port`（区别于 SOCKS5/VLESS 二进制地址）；
- 认证响应 `:status` 必须为 233，否则 fail-closed；
- `obfs: gecko` 直接拒绝（仅 salamander 占位）；
- 错误展示绝不回显 password / obfs_password；
- 离线确定性：同一份配置+输入永远产生同一字节流；不连公网。

## Side Effects

- 无。纯离线编解码；单测不打开 socket、不连公网。

## Verification

- crate 内单测：varint 编解码（1/2/4/8 字节边界）、TCPRequest/TCPResponse
  roundtrip、UDPMessage roundtrip（含分片字段）、QPACK 编码（伪头顺序、
  literal 不索引）、SETTINGS 帧字节、认证请求头构造（字段齐全）、认证响应
  解析（233 通过、非 233 拒绝、Hysteria-UDP 解析、CC-RX 解析）、配置校验
  （必填项缺失、端口越界、gecko 拒绝、hop ports 解析、hop-interval 钳制）、
  adapter kind/tag/handoff。

## Portability

纯 Rust，无 C/asm 依赖（quinn-proto 的 ring 为 Rust 汇编混合，已在 nexus-fabric 验证）。

## Unsafe

本 crate `#![forbid(unsafe_code)]`。
