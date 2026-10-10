# nexus-outbound-vless

> 出站层 crate（`layer = "outbound"`, `portable = true`）。
> 协议语义：`docs/protocols/vless.md`（clean-room 实现）。

## Responsibility

实现 `nexus_connectivity::OutboundAdapter` 的 **VLESS** 出站实现：
在一条已建立的字节流上完成 VLESS 请求/响应头握手，支持基础 VLESS 与
XTLS-Vision padding 封装。

提供：

- 请求头编解码：`version(1)=0x00 | uuid(16) | addon_len(1) | addon |
  command(1) | port(2 BE) | addr_type(1) | address(变长)`——**port 在
  addr_type 之前**（VMess/VLESS 惯例，`encode_request`/`decode_request`
  对称实现，单测锁定字节顺序）；
- UUID 文本（`xxxxxxxx-xxxx-...`，连字符位置严格校验；或 32 hex 纯文本，
  大小写不敏感）↔ 16 字节二进制；
- Addon 手写 protobuf：`flow=""` → 空；`flow="xtls-rprx-vision"` →
  `[0x0A, 0x10] + "xtls-rprx-vision"`；未知 flow 直接拒绝（不静默降级）；
- 命令 0x01 TCP / 0x02 UDP / 0x03 Mux（Mux 只做帧头编解码，复用逻辑不做）；
- **响应头惰性读**：`VlessConn` 握手只写请求头，响应头
  `[version(1) | addon_len(1)] + addon` 在第一次 `read` 时才消费
  （server 先拨号目标，目标先说话的协议在握手时阻塞读响应会死锁）；
- UDP-over-TCP：`u16 BE` 长度前缀分包，双向同格式（无 per-datagram 源地址）；
- XTLS-Vision padding 帧编解码：首帧 21 字节头（含 UUID）/ 后续帧 5 字节头，
  命令 0x00 CONTINUE / 0x01 END / 0x02 DIRECT；
- Vision 写方向状态机 `VisionWriter`：初始 padding → 检测内层 TLS
  ClientHello（`0x16`）标记 `seen_tls` → 出现 Application Data（`0x17 0x03`）
  后发 END（含剩余数据）转透传；direct 模式发 DIRECT（写侧裸 TCP 直通，
  读侧仍走 TLS）；首个写块即非 TLS → 直接 END，不做多余填充；
- Vision 读侧解码器 `VisionReader`：对称解包，还原明文，END/DIRECT 后透传；
- 配置门禁：`flow=xtls-rprx-vision` 要求 `tls=true`（无加密传输时拒绝启用）；
- 结构化错误 `VlessError`（不以日志文本代替类型；错误展示绝不回显 UUID）。

## Non-Responsibilities

- **VLESS-Encryption 后量子**（ML-KEM-768，文档 §3.4）：复杂度高且上游自称
  未独立复核，不在本 crate 实现；
- **传输链**（TCP/TLS/WS/gRPC/H2/HTTPUpgrade/XHTTP/REALITY）：通用传输层，
  是 `nexus-proxy-transport` 的职责，本 crate 只消费"已建立的字节流"；
- **Mux.Cool 完整实现**：`command=0x03` 只做帧头编解码（请求本身即信令，
  不带地址），mux 复用/子流调度不做；
- ServerHello 过滤器（`TLS_FILTER_PACKETS`）：文档标未确认的上游细节，不实现；
- `xtls-rprx-vision-udp443` 变体：线格式差异未确认，不实现；
- session 复用池 / 心跳 / 选路 / 策略组（由上层装配）；
- `nexus-proxy` / 选路 / 策略组不依赖本 crate（组合根装配）；
- 不做第二套系统级 Plan。

## Inputs

- 配置：`tag`、服务端 `locator`、用户 `uuid`、`flow`（`""` /
  `xtls-rprx-vision`）、`tls` 开关、`vision_direct` 开关；
- 运行时：已建立的字节流（`Read + Write`，如 TCP 直连或 TLS 流）。

## Outputs

- `OutboundAdapter::handoff` → `OutboundHandoff { kind = "vless", tag, locator }`；
- 请求/响应头、Vision 帧、UDP 数据报字节流；结构化错误。

## Allowed Dependencies

- `nexus-connectivity`（OutboundAdapter 接缝）；
- 标准库（`std::io`、`std::net`、`std::time`）；无第三方依赖。

## Forbidden Dependencies

- `nexus-proxy` / 选路 / 策略组；
- tokio / 异步运行时（与仓库 loopback blocking+thread 模式一致）；
- 任何 wasm 不可移植但未隔离的依赖。

## Invariants

- `outbound_kind() == "vless"`（稳定标签）；
- 请求头字节顺序恒为 `command | port(BE) | addr_type | address`
  （port 在 addr_type 之前；单测逐字节锁定）；
- `VlessConn::handshake` 只写请求头、绝不阻塞读响应；响应头在第一次
  `read` 时惰性消费；
- 未知 flow / 未知 command / 未知 Vision 命令一律 fail-closed（拒绝，不降级）；
- 错误展示绝不回显 UUID 或其文本；
- Vision padding 随机源为内部 xorshift64（测试固定种子确定性；生产用时间种子）；
- 离线确定性：同一份 uuid+目标+种子永远产生同一请求头/帧字节；不连公网。

## Side Effects

- 单测打开 loopback TCP 监听/连接（127.0.0.1）；不写盘、不连公网。

## Verification

- crate 内单测：请求头 roundtrip（IPv4/域名/IPv6/UDP/Mux）+ port-before-addr_type
  逐字节顺序锁定、UUID 文本↔二进制（含非法输入）、Addon 编码（空/vision）、
  响应头 roundtrip + 惰性消费不丢字节、Vision 帧 roundtrip（首帧/后续帧/
  END/DIRECT/UUID 不匹配/未知命令）、Vision 写状态机（ClientHello→AppData→END、
  direct→DIRECT、非 TLS 首块直接 END、END 后透传）、padding 长度策略区间、
  UDP 分包 roundtrip + 截断拒绝、loopback client↔server 最小握手
  （client 握手后不等响应直接写载荷，证明无死锁）、配置门禁
  （Vision 无 TLS 拒绝）、adapter kind/tag/handoff。

## Portability

`portable = true`：纯 Rust + 标准库，无 C/asm 依赖。

## Unsafe

本 crate `#![forbid(unsafe_code)]`。

## Public API

- 常量：`VLESS_VERSION` / `FLOW_XTLS_RPRX_VISION` / `VISION_FIRST_HEADER_LEN` /
  `VISION_HEADER_LEN`；
- UUID：`VlessUuid::{from_bytes, as_bytes, parse, to_text}`；
- Flow/Addon：`VlessFlow::{parse, as_str, addon_bytes}`；
- 地址/命令：`VlessTarget` / `VlessCommand::{from_u8, as_u8}`；
- 请求头：`VlessRequest` / `encode_request` / `decode_request`；
- 响应头：`VlessResponse` / `encode_response` / `read_response`（惰性读）；
- 连接：`VlessConn::{new, handshake, response_pending, into_inner}`（`Read` 惰性
  消费响应头，`Write` 透传）；
- UDP：`encode_udp_datagram` / `read_udp_datagram` / `decode_udp_datagrams`；
- Vision：`VisionCommand::{from_u8, as_u8}` / `encode_vision_frame` /
  `VisionReader::{new, read_frame, is_ended}` / `VisionWriter::{new,
  with_time_seed, write_chunk, phase, seen_tls}` / `VisionWritePhase`；
- 配置/adapter：`VlessConfig::{validate}` / `VlessAdapter::{new, from_config,
  locator, uuid, flow}`（`outbound_kind() == "vless"`）；
- 错误：`VlessError`。

## 与文档有出入 / 未确认处

- Mux 信令头（`command=0x03`）：文档 §3.2 只说"不带地址"；本实现编码到
  command 为止，**完全省略 port/address 字段**。Xray 上游是否确为此布局
  未逐字节复核，注释标 `// 未确认：`。
- `xtls-rprx-vision-udp443`：文档标未确认线格式差异，不实现，
  `VlessFlow::parse` 直接拒绝。
- Vision padding 随机源：文档只给长度策略（`rand%500+900-len` /
  `rand%256`），未规定随机源；本实现用内部 xorshift64（非密钥材料，
  仅 padding 抖动）。
- Vision ClientHello/AppData 检测为启发式扫描（按文档"record type 0x16 且含
  ClientHello"/"`0x17 0x03`"字面实现）；误判只影响 padding 有无，
  不影响正确性（END 后透传）。
- ServerHello 过滤器（`TLS_FILTER_PACKETS=8`）：文档标未确认上游细节，不实现。
