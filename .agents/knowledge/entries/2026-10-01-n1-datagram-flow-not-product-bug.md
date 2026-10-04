---
id: n1-datagram-flow-diag
date: 2026-10-01
module: nexus-fabric
category: implementation-pitfall
task_type: bugfix
---

# N1 E4: Datagram 流停止不是产品 bug，是 harness 子进程 B 死亡

## 问题描述

E4 `product.n1-connectivity-roam` 通过率 17%（1/6）。失败模式一致：
Rebind 成功 → migration burst 触发 → 此后无传输进展 → 300s 超时。
初步怀疑是 pump 在 QUIC migration 成功后停止转发 datagram。

## 原因分析

在 `driver.rs::pump_one` 加 TEMP-DIAG（已清理）证实：

- `quic.datagrams().send()` 返回 `Ok`（ok=1, blocked=0, dropped=0），**无静默丢弃**
- `poll_transmit` 正常产生包（n_tx=1）
- `dgram_tx_q` 被正常排空

**产品代码（driver/pump/QUIC）工作正常。**

真因：harness 子进程 B 在 migration trigger burst 后**静默死亡**（变 zombie），
死在 `n1_roam.rs:720` 的 `println!("ROAMED")` 处（stdout 管道）。
B 死后 A 收不到 ACK，TCP  stall，测试超时。

- B 的 `child_main` 未返回（无 Ok/Err），直接消失，无 panic 信息
- 父进程 hanging 在 `b.read_line("ROAMED from B")`
- 1 次 PASS 是 TEMP-DIAG 日志改变时序，偶然避开

## 解决方案

未找到。尝试过将 `println!("ROAMED")` 换成忽略错误的 `write_all`，
B 依然死亡（已 revert）。需 harness 专家深入查 stdout 管道断裂原因。

## 教训/可复用要点

1. **先证伪再定罪**：不要假设"datagram 流停止"就是产品 bug。用 TEMP-DIAG
   在 driver 层打点，确认 `send()` 返回值，区分"产品不发" vs "harness 死了"。
2. **Zombie 进程是关键信号**：`ps` 看到 `<defunct>` 说明子进程已退出，
   父进程未 reap。结合"父进程 hanging"，可定位是 harness 协调 bug。
3. **TEMP-DIAG 交错输出**：多线程的 eprintln! 会交错，用 `cat -v` 或
   按行过滤，不要被 garbled 输出误导。
4. **`println!` 会 panic**：stdout 管道断裂时 `println!` panic。若需健壮，
   用 `writeln!` 并处理 Result。但本案例中换了也依然死，说明问题更深。
