---
id: harness-scenario-pipe-eof-hang
title: harness 跑场景用 Command::output() 会被孤儿子进程持有 pipe 卡成永挂
tags: [harness, concurrency, pipe, e4, timeout]
module: nexus-harness
severity: high
source: incident
date: 2026-10-02
related: ["2026-10-01-n1-e4-quit-timing-sent-vs-delivered"]
---

# harness 场景命令必须有界执行：孤儿 pipe 持有者致 output() 永挂

## 问题描述

`nexus-harness verify --full` 在 `product-scenarios` gate 卡死 40+ 分钟，
进程 CPU 时间为 0（纯等待）。两次排查发现两个独立 hang 点：

1. `apps/nexus` 的 `bufferbloat_test_loopback_no_bloat` 单测：`saturate_worker`
   用阻塞 socket `write_all` 无写超时，对端不读时永久阻塞，`join` 永挂。
   → 修：`set_write_timeout(5s)`。
2. `product.n1-connectivity-roam` E4：`n1_roam` 的 parent 进程被自己的 300s
   看门狗杀死后变成僵尸，孤儿 child A 继承了 stderr pipe 写端；
   harness 的 `run_command` 用 `Command::output()`，其内部读 pipe 到 EOF
   永不到 → harness 永挂。

## 原因分析

`Command::output()` 的语义是：spawn → 读 stdout/stderr 到 EOF → wait。
只要**任一**进程（包括已孤儿化的孙进程）持有 pipe 写端，EOF 就不会到来。
E4 场景常用 parent/child 结构且 child 用 `stderr(Stdio::inherit())`，
parent 意外死亡时极易触发。

注意 `try_wait()` 本身不受影响——僵尸子进程可被正常回收；
卡死的是 output() 内部的 pipe 抽干，不是 wait。

## 解决方案

`engineering/nexus-harness/src/scenario.rs::run_command` 改写为：

- spawn + 读线程（stdout/stderr 各一）并发抽干 pipe；
- 主线程 `try_wait()` 轮询，直接子进程 600s 未退出则 kill 并判 FAIL；
- 输出收集只按 drain timeout（10s）有限等待，不依赖 EOF；
- 超时/孤儿场景下取已读到的部分输出，永不阻塞。

回归测试（`scenario::tests`）：

- `run_command_times_out_instead_of_hanging`：`sleep 30` + 2s 超时必须有界返回。
- `run_command_orphaned_grandchild_holding_pipe_returns`：
  `sh -c 'sleep 60 &'`（sh 立退、sleep 60 孙进程持有 stdout pipe）必须在
  15s 内返回；旧实现会在此卡满 60s。

## 教训/可复用要点

- 任何"跑外部命令并读输出"的代码，默认都要有超时；`Command::output()`
  在有孙进程的场景下是危险 API。
- 读 pipe 到 EOF 与等进程退出是两个独立的完成条件，必须分别设界。
- E4 场景的 parent/child pipe 继承关系要在设计时画出来：谁持有谁的写端、
  谁死后谁还拿着，hang 点一目了然。
- 排查"0 CPU 的慢"先看 wchan：futex/pipe_read/anone_pipe_read 直接定位等待点。
