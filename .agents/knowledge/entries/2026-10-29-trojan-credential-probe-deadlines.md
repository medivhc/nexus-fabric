---
id: trojan-credential-probe-deadlines
date: 2026-10-29
module: apps/nexusd
category: implementation-pitfall
task_type: feature
---

# Trojan 凭据探测：按截止时刻驱动 rustls，测试要走完三次握手

## 问题/模式描述

nexusd 的 Trojan 凭据探测（PRODUCT §11.9.5）要求单次探测 ≤ 13 s（建连 5 s + TLS/写 5 s +
读 3 s），并在「下行字节 / 零字节关闭 / 沉默」之间精确判定。实现与测试中踩到三处：

1. `StreamOwned::read` / `complete_io` 内部可能多次读 socket（TLS 1.3 的 NewSessionTicket
   在握手后到达），每次都等满 socket 超时，总时长可超过预期窗口。
2. 单测直接向 `ProxyEngine::handle_packet` 注入一个 SYN，拨号从不发生：终结器在三次握手
   完成（ACK）后才发出 `TcpEvent::Syn`，且包必须带正确的 IPv4 / TCP 校验和。
3. 测试评审预期「端口关闭 → tcp_connect、严格校验失败 → tls_handshake」，但既有 Trojan 拨号
   （`trojan_tls_connect`）把两者都映射为 `io`。
4. （代码评审 r1 B1，fail-open）同一次 `read_tls` 读到「fallback 的 404 记录 + 一个坏记录」时，
   `process_new_packets` 报错，直接判 inconclusive 会丢掉已解密的 404，拨号照常进行。

## 原因分析

1. socket 读超时是「每次调用」的，不是「整个阶段」的。
2. `nexus-projection` 的 `TcpTerminator` 用 smoltcp 状态机，`Established` 之后才上报 Syn。
3. proxy-transport 在 `write_all` 里隐式握手，所有 I/O 错误都落成 `ProxyError::Io`。
4. rustls 的 `process_new_packets` 按顺序处理一次读入的全部记录：坏记录之前的完整记录已经
   解密进明文缓冲，随后才因坏记录返回错误——错误不代表「没有收到数据」。

## 解决方案

1. 手动驱动 `ClientConnection`：`write_tls` / `read_tls` + `process_new_packets`，每次 socket
   调用前把超时设为「截止时刻 − 现在」；读窗口内只认 `reader().read` 返回的应用数据为下行
   字节（`WouldBlock` 继续、`UnexpectedEof` / `Ok(0)` / reset 为关闭）。
2. 测试按 SYN → 取 SYN-ACK 序号 → ACK 走完握手，再观察拨号。
3. 不改既有拨号的错误映射；改为断言「探测开 / 关时拨号失败原因完全相同」——这才是契约
   （inconclusive 照常拨号）真正约束的不变量。
4. `process_new_packets` 出错后先 `reader().read`：已解密的明文照样判 rejected。回归测试让
   节点在一次写里发出 404 记录 + AEAD 必败的 application_data 记录。

## 教训/可复用要点

- 有总时长上限的阶段，用截止时刻驱动 rustls，而不是依赖 socket 超时。
- 单-flight 闸门加 drop guard：探测方 unwind 时清 `in_flight` 并唤醒等待者，否则闸门永久卡死。
- 断言某个新机制「不改变」既有行为时，用开 / 关对照，而不是硬编码既有行为的具体值。
- 安全判定里，任何「错误 → 放行」分支都要先确认错误之前没有已到达的证据（字节）被丢弃。
