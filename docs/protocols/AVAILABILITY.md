# 协议可用性状态（AVAILABILITY）

本页汇总各协议当前的可用性结论，数据来源为 [MATRIX.md](interop/MATRIX.md) 的互操作验证结果。

## VLESS

- **验证状态（verdict）**：`BROKEN`（命中规则 2）
- **覆盖范围（scope）**：`PROTOCOL_SUBSET`
- **是否可用（claim）**：`NOT_USABLE`
- **root_cause_class**：`E_NEXUS_HANDSHAKE_WIRE`
- **根因/限制摘要**：产品装配（eager read）bug + 跨协议 T2，依赖 transport 才能完全解决；VlessVision 结论为 crate 级证据、产品 splice 未实现。

## AnyTLS

- **验证状态（verdict）**：`BROKEN`（命中规则 2）
- **覆盖范围（scope）**：`PROTOCOL_SUBSET`
- **是否可用（claim）**：`NOT_USABLE`
- **root_cause_class**：`E_NEXUS_TRANSPORT`
- **根因/限制摘要**：只差跨协议 T2（transport 批量写缺陷，单点可解，修复后本 run schema 上限为 `VERIFIED / FULL`）。

## Hysteria2

- **验证状态（verdict）**：`BROKEN`（命中规则 2）
- **覆盖范围（scope）**：`PROTOCOL_SUBSET`
- **是否可用（claim）**：`NOT_USABLE`
- **root_cause_class**：`E_NEXUS_CODEC`
- **根因/限制摘要**：认证响应 QPACK Huffman 编解码错误 + 跨协议 T2，共 8 格阻塞，单协议不可独立解决。

## Trojan

- **验证状态（verdict）**：`BROKEN`（命中规则 1）
- **覆盖范围（scope）**：`TCP_ONLY`
- **是否可用（claim）**：`NOT_USABLE`
- **root_cause_class**：`E_NEXUS_FRAMING`
- **根因/限制摘要**：fallback 静默接受（fail-open 安全语义问题）+ 共性 T2；且本 run `UdpEcho` 固定 `NOT_IMPLEMENTED`，即使修复完成上限仍为 `PARTIAL / TCP_ONLY / USABLE_WITH_GAPS`。

## Shadowsocks

- **验证状态（verdict）**：`BROKEN`（命中规则 2）
- **覆盖范围（scope）**：`TCP_ONLY`
- **是否可用（claim）**：`NOT_USABLE`
- **root_cause_class**：`E_NEXUS_HANDSHAKE_WIRE`
- **根因/限制摘要**：协议线格式 / SIP004 AEAD 实现错误（需协议重写）+ 共性 T2；本 run `UdpEcho` 固定 `NOT_IMPLEMENTED`，修复后上限仍为 `PARTIAL / TCP_ONLY / USABLE_WITH_GAPS`。
