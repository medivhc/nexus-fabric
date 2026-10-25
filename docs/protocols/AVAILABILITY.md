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
- **root_cause_class**：`E_TIMEOUT_HANG`
- **根因/限制摘要**：认证响应 QPACK Huffman 编解码错误；代表根因类为 `E_TIMEOUT_HANG`，剩余阻塞格为 `Default/TcpThroughput(FAIL,E_TIMEOUT_HANG)`，其余格 PASS。属单协议可解（编解码一处），修复后本 run schema 上限为 `VERIFIED / FULL`。

## Trojan

- **验证状态（verdict）**：`PARTIAL`（命中规则 6）
- **覆盖范围（scope）**：`TCP_ONLY`
- **是否可用（claim）**：`USABLE_WITH_GAPS`
- **root_cause_class**：`E_NEXUS_NOT_IMPLEMENTED`
- **根因/限制摘要**：fallback 主路径已 fail-closed（success 前零字节投递）；残余为 success 之后到达的 fallback（承诺边界 R-1/R-2）与产品 UDP 未实现。`missing_cells` 仅 `UdpEcho(NOT_IMPLEMENTED)`，本 run 上限为 `PARTIAL / TCP_ONLY / USABLE_WITH_GAPS`。

## Shadowsocks

- **验证状态（verdict）**：`PARTIAL`（命中规则 6）
- **覆盖范围（scope）**：`TCP_ONLY`
- **是否可用（claim）**：`USABLE_WITH_GAPS`
- **root_cause_class**：`E_NEXUS_NOT_IMPLEMENTED`
- **根因/限制摘要**：SIP004 线格式已由 `fixes-2` 修复（H/T1/T2/L/R 全 PASS）；剩余仅产品 UDP 未实现。`missing_cells` 仅 `UdpEcho(NOT_IMPLEMENTED)`，本 run 上限为 `PARTIAL / TCP_ONLY / USABLE_WITH_GAPS`。
