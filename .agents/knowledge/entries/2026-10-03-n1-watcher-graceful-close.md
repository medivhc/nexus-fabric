---
id: n1-watcher-graceful-close-001
date: 2026-10-03
module: nexus-network
category: implementation-pitfall
task_type: bugfix
---

# Watcher 必须区分"对端优雅关闭"与"链路故障"

## 问题/模式描述

`N1SessionManager::remove()`（E-3 shutdown 死锁修复）先调 `conn.close()` 再 join watcher。
`conn.close()` 发 QUIC application CONNECTION_CLOSE（code 0, `"n1 shutdown"`）。
对端的 keepalive pinger 读失败，watcher 误报 `LinkFailed "keepalive stream error"`，
进而 `discovery returned no locators` → 300s 全局超时（B2 在 2026-10-02 真机复现 3/3）。

## 原因分析

错误链逐层丢失"优雅关闭"信息：

```
quinn: ApplicationClosed{error_code: 0}
  → fabric map_close_reason → FabricError::Closed(0)      // 码还在
  → apps/nexus map_fabric_err → N1Error::Closed           // 码被丢掉！
  → pinger_loop: Err(_) => break                          // 错误被丢掉！
  → ping_watch: done → recover("keepalive stream error")  // 误报
```

两处信息丢失：`map_fabric_err` 把 `Closed(code)` 的码丢掉；`pinger_loop` 把
终止错误直接丢弃，只发 `()` 信号。

## 解决方案

1. 新增 `N1Error::PeerClosed(u32)` 变体，保留 application close 码；
   `map_fabric_err` 里 `FabricError::Closed(code)` → `N1Error::PeerClosed(code)`。
2. `pinger_loop` 经 channel 透出终止错误（`Sender<N1Error>`）。
3. `ping_watch` 收到 `PeerClosed(0)` 时静默退出，不上报 LinkFailed、不触发 rebind；
   其他错误仍走 `recover("keepalive stream error")`。
4. `watch()` 的 `open_keepalive` 失败分支与 pump 的收包循环同样识别 `PeerClosed(_)`，
   对端优雅关闭时干净退出而非按瞬时错误自旋。

注意：`FabricError::Closed(0)` 也覆盖 `LocallyClosed` 与"连接不在表内"两种情况。
在 watcher 上下文里本地关闭恒有 stop 标志位保护，把它们当优雅关闭静默退出
同样正确（都不该误报 LinkFailed）。真正的传输故障（`Transport`/`Timeout`）
不受影响，仍触发恢复。

E-3 的顺序（先 `conn.close()` 再 join watcher）未动，回归测试
`remove_wakes_watcher_blocked_in_open_keepalive` 通过。

## 教训/可复用要点

- 错误枚举的变体是信息通道：`Closed` 这种"一元化"错误会吞掉调用方做决策
  所需的关键区分度。加变体时问一句"调用方需要区分吗"。
- 跨层错误映射（fabric → N1 → watcher）每层都要检查信息是否丢失，
  尤其是"码/原因"这类结构化字段。
- `Err(_) => break` 这种丢弃错误的写法，在观测器/恢复决策路径上是 bug 温床；
  恢复决策必须基于 typed error，不能基于"出错了"这个布尔值。
