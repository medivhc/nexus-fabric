---
id: turn-e4-premature-drop
date: 2026-09-30
module: nexus-turn
category: implementation-pitfall
task_type: feature
---

# E4 调试：B 侧过早 drop 连接导致 echo 数据丢失（非 TURN 协议 bug）

## 问题/模式描述

`product.fabric-turn-relay` E4 在 64KB 回显时稳定失败（`echo read: timeout`），
但小包（≤16KB）全过。初步怀疑 TURN 中继丢包，实测 TURN-only 高速收发也丢包，
一度误判为 server 缓冲区问题。

## 原因分析

真正根因与 TURN 协议无关，是 **example 的生命周期 bug**：

- `SendStream::write()` 只是把数据拷进 app buffer（无背压，P0 已知），由
  driver 线程的 `pump_stream` 搬进 QUIC。
- E4 的 B 线程在 `send.finish()` 后**立即返回**，drop `FabricConn` → drop
  `Driver` → driver 线程 shutdown。
- 此时 32KB echo 大部分还在 app buffer 里，driver 没来得及 pump，数据丢失；
  A 侧 `echo read` 超时。A 收到约 10KB（driver 在 shutdown 前 pump 的量），
  之后硬停滞——不是慢，是 driver 已死。
- 小包能过是因为数据量小，driver 在 app 线程退出前已 pump 完（竞态恰好赢）。
- 加 instrumentation“修复”了它，纯粹是时序扰动改变了竞态结果（heisenbug）。

对比：`basic.rs` 的 B 线程在 echo 后还要收 100 个 datagram，曾意外地保持
连接存活。2026-10-20 补充：若这些 datagram 已缓存，接收循环可立即结束，
仍不能证明反方向 echo/FIN 已交付。应显式保留 listener/connection owner，
直到客户端读完完整回显与 EOF，并在客户端失败时也消费 server JoinHandle。
早期建连失败还需要有界 accept，避免持有 owner 后永远等不到 server join。

## 解决方案

E4 的 B 线程在 `send.finish()` 后**等待 A 确认**（mpsc channel 显式握手），
A 收完回显、断言通过后才 signal B 退出。此时才允许 drop 连接。

## 教训/可复用要点

1. **“小包过、大包挂 + 硬停滞（非变慢）”首先怀疑生命周期/竞态**，而不是
   丢包。丢包只会导致变慢（QUIC 会重传），硬停滞意味着某条线程死了或
   连接关了。
2. `bytes_sent=0` 但对端收到了数据 → stats 是 stale 的 → driver 已死。
   这是“driver 被过早 shutdown”的强信号。
3. instrumentation 改变结果时，不要庆祝“修好了”，要意识到是 heisenbug，
   继续找竞态。
4. 无背压的 `send.write()` + 立即 drop 连接是固定踩坑模式：任何 E4/example
   在 `finish()` 后必须显式保持连接存活，直到对端确认。
