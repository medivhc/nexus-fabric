# 协议可用性状态（AVAILABILITY）

本页汇总各协议当前的可用性结论，数据来源为 [MATRIX.md](interop/MATRIX.md) 的互操作验证结果。

注：`USABLE` 指 TCP 产品路径；产品 SOCKS5 UDP ASSOCIATE 五协议均未实现，`UdpEcho` 为 crate 级证据、不代表产品入口可用。

## VLESS

- **验证状态（verdict）**：`VERIFIED`（命中规则 8）
- **覆盖范围（scope）**：`PROTOCOL_SUBSET`
- **是否可用（claim）**：`USABLE`
- **root_cause_class**：`NONE`
- **根因/限制摘要**：阻断已消除——产品装配 eager read 由惰性响应头读取修复（commit `43ca7ac`）、跨协议 T2 由 transport 批量写修复（commit `60e6029`），H/T1/T2/L/R 全 PASS。限制：Vision 结论为 crate 级证据、产品 splice 未实现（scope 因此为 `PROTOCOL_SUBSET`）。

## AnyTLS

- **验证状态（verdict）**：`VERIFIED`（命中规则 8）
- **覆盖范围（scope）**：`FULL`
- **是否可用（claim）**：`USABLE`
- **root_cause_class**：`NONE`
- **根因/限制摘要**：阻断已消除——唯一阻塞的跨协议 T2（transport 批量写缺陷）已由 `PendingWrite` 接线修复（commit `60e6029`），全部 required 格 PASS。

## Hysteria2

- **验证状态（verdict）**：`BROKEN`（命中规则 2）
- **覆盖范围（scope）**：`PROTOCOL_SUBSET`
- **是否可用（claim）**：`NOT_USABLE`
- **root_cause_class**：`E_NEXUS_CODEC`
- **根因/限制摘要**：认证响应 QPACK Huffman 编解码错误，共 8 格阻塞（均为 `E_NEXUS_CODEC`）；属单协议可解（编解码一处），修复后本 run schema 上限为 `VERIFIED / FULL`。

## Trojan

- **验证状态（verdict）**：`BROKEN`（命中规则 1）
- **覆盖范围（scope）**：`TCP_ONLY`
- **是否可用（claim）**：`NOT_USABLE`
- **root_cause_class**：`E_NEXUS_FRAMING`
- **根因/限制摘要**：fallback 静默接受（fail-open 安全语义问题）+ 产品 UDP 未实现；本 run `UdpEcho` 固定 `NOT_IMPLEMENTED`，即使其余修复完成上限仍为 `PARTIAL / TCP_ONLY / USABLE_WITH_GAPS`。

## Shadowsocks

- **验证状态（verdict）**：`BROKEN`（命中规则 2）
- **覆盖范围（scope）**：`TCP_ONLY`
- **是否可用（claim）**：`NOT_USABLE`
- **root_cause_class**：`E_NEXUS_HANDSHAKE_WIRE`
- **根因/限制摘要**：协议线格式 / SIP004 AEAD 实现错误（需协议重写）+ 产品 UDP 未实现；本 run `UdpEcho` 固定 `NOT_IMPLEMENTED`，修复后上限仍为 `PARTIAL / TCP_ONLY / USABLE_WITH_GAPS`。
