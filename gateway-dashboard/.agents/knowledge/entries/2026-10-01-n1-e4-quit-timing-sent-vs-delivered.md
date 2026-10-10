---
id: n1-e4-quit-timing-sent-vs-delivered
date: 2026-10-01
module: nexus-network
category: implementation-pitfall
task_type: bugfix
---

# E4 harness：SENT ≠ 送达；QUIT 必须等 B 的 BYE

## 问题

`n1_roam.rs` 父进程在收到 A 的 `SENT` 后立即给 A、B 发 `QUIT`。
`SENT` 只表示 A 把 2MB 写入了**本地 TCP socket**，不代表 B 收到。
A 收到 QUIT 后调用 `pump.shutdown()` → `close_all()` 关闭 QUIC 连接，
导致在飞的 TCP 重传包丢失，B 永远收不满 2MB，E4 卡死在
`timeout waiting for BYE from B`。

## 关键误诊教训

这个时序 bug 曾被误诊为 "fabric driver 在 rebind 后收割 QUIC 连接"
（driver 连接生命周期 bug）。`[quinn-lost] reason=b"n1 shutdown"` 日志
看起来像 driver 主动杀连接，实际是 A 在收到过早 QUIT 后的**正常关闭**，
driver 收割已关闭连接是正确行为。

**教训：看到连接消失，先查关闭发起方（谁调了 close/shutdown），
再怀疑 driver/transport 层。** 日志里的 reason 字段是第一线索，
不要跳过它直接怀疑底层。

## 修复

```rust
// 关键时序：必须等 B 收完（BYE from B）再给 A 发 QUIT。
let sent = a.read_line("SENT from A")?;
b.write_line("QUIT")?;
let bye_b = b.read_line("BYE from B")?;  // B 确认收完 2MB
a.write_line("QUIT")?;                    // 再让 A 关闭
let bye_a = a.read_line("BYE from A")?;
```

## 可复用要点

- 任何"发送完成"信号（如 SENT、write 返回）只表示数据进入本地协议栈，
  不等于对端收到。E4 的终止时序必须以**接收方确认**为准。
- 调试"连接莫名消失"时，按顺序查：① 应用层是否主动 close/shutdown；
  ② 对端是否 close；③ 才是 transport/driver 的收割/GC 逻辑。
