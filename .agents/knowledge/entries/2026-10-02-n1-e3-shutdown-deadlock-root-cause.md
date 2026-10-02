---
id: n1-e3-shutdown-deadlock-root-cause
date: 2026-10-02
module: nexus-network
category: implementation-pitfall
task_type: bugfix
---

# E-3：N1SessionManager::remove() shutdown 死锁根因

## 问题描述

`N1SessionManager::remove(peer)` / `shutdown()` 在 watcher 线程阻塞于
`open_keepalive()` 时永久 hang。E4 曾为规避此死锁用 `process::exit(0)`，
导致生产 graceful shutdown 路径无覆盖（review E-3）。

## 原因分析

循环等待（join/close deadlock），不是锁顺序问题：

```text
主线程：w.shutdown() → stop=true → join(watcher 线程) → 等 watcher 退出
watcher 线程：阻塞在 conn.open_keepalive()（可靠流 open，阻塞 I/O）
              → 只有 conn.close() 能让它返回 Err(Closed)
conn.close()：排在 join 之后，还没执行
```

- `stop` 原子标志救不了：线程卡在阻塞 I/O 里，根本不轮询 flag。
- 此前怀疑的 `peers` 锁是误诊（已证伪）：真正的等待环是
  **join → watcher → open_keepalive → close → join**。
- watcher 自己的退出路径末尾也会调 `conn.close()`（打断 responder 的
  accept），但主循环卡在 `open_keepalive()` 时根本到不了退出路径。

修复（`crates/nexus-network/src/n1/session.rs::remove`）：先 `p.conn.close()`
打断阻塞（`open_keepalive` 返回 `Err(Closed)` → watcher 走退出路径），
再 `w.shutdown()` join。顺序约束已写进 `remove()` 的 doc comment。

## 解决方案

1. `remove()`：`conn.close()` → `watcher.shutdown()`（close 先行）。
2. 回归测试 `remove_wakes_watcher_blocked_in_open_keepalive`：
   `HangingKeepaliveConn` 替身忠实复现"open_keepalive 阻塞直到 close"语义；
   `entered` 原子标志保证 watcher 已进入阻塞点才调 remove（确定性，
   不靠 sleep 猜时序）；watchdog 把 hang 翻译成 10s 失败而非卡死整个
   test 二进制。Red 验证：旧顺序下 10.06s 失败，新顺序 0.07s 通过。

## 教训/可复用要点

- **阻塞 I/O + join 是经典死锁对**：任何"先 join 再释放阻塞条件"的顺序都是错的。
  取消路径必须是：先打断阻塞（close/shutdown fd），再 join。
- trait 契约是最好的防线：`N1Connection::close` 的文档已写明
  "阻塞中的 recv_datagram / accept_keepalive / keepalive 读必须随之返回 Closed"
  ——实现 `remove()` 时若对照此契约，死锁本可避免。
- `stop` 标志只能取消"轮询式"循环，取消不了"阻塞式"调用；设计取消路径时
  先问"线程此刻可能卡在哪"，再决定先调什么。
- E4 用 `process::exit(0)` 绕过生产路径 = 用 sketch 掩盖 bug（见
  `2026-09-30-e4-must-use-production-path.md`）；E-3 修复后 n1_roam.rs 已恢复
  对 shutdown 路径的覆盖。
