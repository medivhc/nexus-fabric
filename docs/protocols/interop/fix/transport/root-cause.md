# 产品数据面批量传输在 WouldBlock 上误判为致命错误 — 根因报告（S27）

- 影响：五协议的 `TcpThroughput`（32 MiB × 3 双向）全部失败；16 MiB 及以下可过，≥32 MiB 稳定复现
- 归类：`E_NEXUS_TRANSPORT`（Nexus 族）。不是协议线格式问题，也不是参照端行为问题
- 证据：`evidence/{anytls,trojan,vless}/default/tcp-throughput/*`、`fix/transport/wouldblock-smoking-gun.txt`

## 现象
- probe 侧读到 ~21–31 MiB（不足 32 MiB）后 EOF/connection reset；产品 proxy JSON 仍能返回（路由正确）。
- 目标端 sink 已写满 32 MiB（target_stats），sing-box 日志无错误、仍在等（未主动关闭）。
- 16 MiB × 3 双向通过；28 MiB 单次通过；32 MiB 单次/多次均失败（跨 AnyTLS/Trojan/VLESS）。

## 直接证据（临时插桩，已回退）
在 AnyTLS pump 的 client 写失败分支打出：
```
[DEBUG-anytls] client write err Os { code: 11, kind: WouldBlock, message: "Resource temporarily unavailable" } up=34586660 down=27917990 pending=0 frame=65535
```
即 `client.write_all()` 在**非阻塞 client socket** 上返回 `WouldBlock`，pump 把它当致命错误，
`c_open=false; tls_open=false` → 连接关闭，probe 看到 EOF。

## 根因（first wrong place）
`apps/nexus/src/lib.rs:5471-5479`（AnyTLS）等各协议 arm 在进入中继前执行
`client.set_nonblocking(true)`，随后在 pump 中直接 `client.write_all(...)`：
- `std::io::Write::write_all` 在非阻塞 socket 上遇到 EAGAIN/WouldBlock 时返回 Err，
  且**不保留已写进度**；
- 各 pump 的 `Err(_)` 分支一律 `c_open=false; tls_open=false`。
同样模式见 Trojan（`:5212-5220`）、VLESS TLS/明文（`:5758-5790`, `:5780-5800`）、Hy2（`:5848` 附近），
以及 node 方向 `node.write_all`（rustls 缓冲的 WouldBlock 同样被当致命）。
小载荷（≤socket 缓冲余量）不会触发；32 MiB 级别传输必然在某个 8–64 KiB 写上遇到 WouldBlock。

## 影响面
- 所有产品出站协议的**批量 TCP 传输**（吞吐格），不是单协议线格式问题。
- H/T1（64 KiB）/L/R/F 不受影响；UDP crate 路径不受影响。

## 修复方案（路径 B：数据面非阻塞写状态机）
1. 通用 `PendingWrite`（保留未写尾部，WouldBlock 时下一轮续写，读侧暂停形成背压）；
2. 在 4 个 arm（Trojan/AnyTLS/VLESS×2/Hy2）的 client↔node 两个方向接入；
3. 单测：Mock nonblocking writer 模拟 EAGAIN，断言不丢字节、不早退；
4. 复验：五协议 T2 + T1/L/R 回归。

## 量化估算
- 通用状态机 ~80 行；4 个 arm 接线 ~15 行/处 = 60；单测 ~100；合计 **~240–260 行**，
  但需要同时改 4 条协议数据面并逐条回归（含 Hy2 QUIC stream 写路径），验证成本高于行数。
- 风险：任何一处置错都会引入新的半关闭/丢字节问题；属于**跨协议数据面变更**，
  超出“单协议局部 bug”的 fix 支线边界。
- 结论：`UPGRADE`（见交卷）。本 run 按证据定格：required T2 FAIL + Nexus 族 → 规则 2 `BROKEN`
  （即使某些协议其余格全 PASS）。

## 终局状态更正

- 本文写于终局重跑之前：正文“五协议的 TcpThroughput 全部失败”混同了不同主因，需按终局证据区分。
- VLESS 基线 T2（`PIV-vless-default-tcp-throughput-20261024T172313Z-001`）= FAIL + `E_NEXUS_FRAMING`，主因是 VLESS 响应头 eager read 死锁（见 `fix/vless/root-cause.md`）；WouldBlock 传输缺陷是在 VLESS fix 分支复验 T2 时才被分离出来的第二缺陷（fix 分支 T2 仍 FAIL，`E_NEXUS_TRANSPORT`）。
- Hy2 T2（`PIV-hysteria2-default-tcp-throughput-20261024T173044Z-001`）= FAIL + `E_NEXUS_CODEC`，认证响应解码先失败，未进入批量传输路径。
- AnyTLS/Trojan 终局 T2 = FAIL + `E_NEXUS_TRANSPORT`（本文主题）。
- 终局取值以 `docs/protocols/interop/MATRIX.md` 各协议 `Default/TcpThroughput` 行为准；构建来源见 MATRIX 附录 D。
