# 协议可用性状态（AVAILABILITY）

本页汇总各协议当前的可用性结论，数据来源为 [MATRIX.md](interop/MATRIX.md) 的互操作验证结果。

注：`USABLE` 指协议级互操作（TCP 产品路径 + 产品级 UDP）；产品 SOCKS5 UDP ASSOCIATE 已落地，VLESS（`flow=None`）/AnyTLS 有产品级 `UdpEcho` 证据；Trojan/Shadowsocks/Hysteria2 产品级 UDP 未实现（`UdpEcho` = `NOT_IMPLEMENTED`，fail-closed 丢弃、不直连）。

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

- **验证状态（verdict）**：`PARTIAL`（命中规则 6）
- **覆盖范围（scope）**：`PROTOCOL_SUBSET`
- **是否可用（claim）**：`USABLE_WITH_GAPS`
- **root_cause_class**：`E_NEXUS_NOT_IMPLEMENTED`
- **根因/限制摘要**：TCP 产品路径结论不变（逐格 PASS 仍在）；变化的是证据作用域——产品级 `UdpEcho` 未实现（`NOT_IMPLEMENTED`，fail-closed 丢弃、不直连），按 spec E1 规则 6 回落 `PARTIAL / PROTOCOL_SUBSET / USABLE_WITH_GAPS`（裁决 `MSR-fixes6-decision-package-20261029` D-1）；crate 级 UDP 仍 PASS（`UdpEchoCrate`），QUIC 出站传输不受影响。历史阻断均已消除——认证响应 QPACK Huffman 编解码已由 `fixes-3` 修复；Salamander 变体已由 `fixes-4` 独立验证 PASS；`Default/TcpThroughput` 大流量挂死已由 `fixes-7` pump 修复（官格四跑 PASS，median 103–106 MB/s，构建含修复且 probe 二进制 sha256 一致）。该格唯一 FAIL 证据 `T193403Z` 采自不含 pump 修复的构建（并行采集时序倒置），已按裁决 `MSR-fixes7-hy2-flip-ruling-20261028` 在证据根记 superseded 弃用（见 MATRIX 附录 E）。范围限制：端口跳跃/Brutal/gecko/分片不在本 run 范围，结论仅对 sing-box 1.13.16 参照配置成立。证据构建注记：T2 证据构建（`e8363bc`/`4b4de30`，基底 `c04b409` + pump 修复）早于 `fixes-4`/`fixes-5` 合入，合并树在此之外另含该两 run 的变更；逐格构建绑定见 MATRIX 附录 D。

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
