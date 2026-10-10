---
id: 2026-09-22-perf-bench
date: 2026-09-22
module: nexus-connectivity / apps-nexus
category: implementation-pitfall | implementation-pattern
task_type: feature
---

# P3.6 加密数据面性能基准：坑与模式

## 问题 1：Windows UDP bind os error 10013（WSAEACCES）

- 现象：`UdpCarrier::bind("udp://127.0.0.1:53011/53211")` 抛 10013，但 52001 可用。
- 原因：Hyper-V/WSL2（本机跑 WSL2 + docker-desktop）在动态端口排除段内，系统拒绝 bind。
- 排查：`netsh int ipv4 show excludedportrange protocol=udp` 查看保留段（本机 49252-50359 一带大量排除）。
- 教训：Windows 上 E4/测试固定 UDP 端口先用该命令挑段，或直接复用过已验证端口（52001/52002）。

## 问题 2：TunnelFrameHeader::deserialize 整体 UTF-8 校验

- 现象：`VirtualSubnetTunnel` 加密数据面收发，载荷用 `0xAB` 填充时报
  `invalid tunnel frame header`（解密成功但 deserialize 失败）。
- 原因：`deserialize` 先 `std::str::from_utf8(data)`（整段），二进制载荷不是合法 UTF-8 → None。
- 教训：走隧道数据面（明文/加密均如此）的 benchmark/测试载荷用 ASCII（如 `b'A'`），
  二进制载荷需求应走 VPI 层或先修 deserialize（现状为 P0 简化协议）。

## 模式：隧道进程内握手驱动

```rust
tunnel_a.begin_handshake("10.99.0.2")?;      // A 发 hs:INIT
tunnel_b.recv_and_deliver(&mut buf)?;        // B 自动 accept（发 hs:RESP）
tunnel_a.recv_and_deliver(&mut buf)?;        // A 自动 complete → 双方 Connected
```
`recv_and_deliver` 以 `hs:` 前缀自动分流握手帧（accept/complete），返回 Ok(None)；
数据帧解密后按各 peer session 试解密 + ReplayWindow 校验。

## 模式：性能基准（AGENTS §21 合规）

- 预算表三件套：baseline（首测固化入 evidence，含 target/toolchain 指纹）、
  noise/warning/blocking 相对阈值、绝对下限（防灾难退化，避免 CI 噪声 flaky）。
- verdict 由被测程序按预算表自评 + 全量原始指标输出（可人工复核）；
  harness 场景断言只锁结构（verdict 枚举 + 字段 non_empty），不锁绝对值。
- harness 场景断言仅支持 Equals/OneOf/NonEmpty（engineering/nexus-harness/src/scenario.rs），
  无 numeric type 断言；`performance-budgets` gate 检查 budgets 字段齐全。

## 本机基线（debug build，x86_64-windows，2026-09-22）

| 指标 | 值 |
| --- | --- |
| AEAD 帧往返 | ~3.1-3.6 µs/帧（1 KiB） |
| AEAD 吞吐 | 636-1014 MB/s（ChaCha20-Poly1305） |
| 隧道吞吐（UDP 回环+加密） | 61-83 MB/s |
| 隧道往返 | 9.6-11.6 µs |
