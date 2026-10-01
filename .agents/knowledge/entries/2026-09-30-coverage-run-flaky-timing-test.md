---
id: coverage-run-flaky-timing-test
date: 2026-09-30
module: nexus-projection
category: environment-pitfall
task_type: verify
---

# llvm-cov 插桩运行会放大时序敏感测试的 flakiness

## 问题/模式描述

`verify --full`（revision `42f3e9b`，evidence `b20ee5c51e3b`）中
`coverage-summary` gate 判 UNKNOWN：其 llvm-cov 插桩运行里
`nexus-projection` 的 `path_link::tests::rebind_failure_keeps_connection`
失败（"conn never reaped after peer close"，102 passed / 1 failed）。

## 原因分析

- 该测试本身是时序敏感的（reap 是异步的）：单独跑 3/3 通过，
  但耗时在 0.43s / 2.64s / 9.80s 之间剧烈波动。
- llvm-cov 插桩拖慢执行，把本来就紧的时序窗口压垮 → 在覆盖率运行里挂掉，
  在普通 `cargo test` 里稳定通过。
- 与被测功能改动零代码交集（`path_link.rs` 未引用 `race_connect` /
  `FallbackChain`），可排除回归。

## 解决方案

- 判定为已知 flaky（时序敏感 + 插桩放大），非本次改动回归：
  `coverage-summary` 保持 UNKNOWN 不阻塞，整体 verdict 仍为 PASS。
- 读 full verify 结果时区分：gate UNKNOWN ≠ FAIL；看 detail 里是"未实现"
  还是"运行失败"，运行失败再看是确定性失败还是时序 flaky。

## 教训/可复用要点

- 覆盖率/插桩运行是 flaky 测试的放大器：一个在普通 CI 稳定通过的测试，
  可能在 coverage gate 里偶发挂掉。先看失败测试的耗时方差和代码交集，
  再决定是修测试还是记 flaky。
- 同一模式此前出现过：os-assemble 阶段 `nexus-projection` 102/103 flaky，
  单独重跑 103/103。时序敏感测试 + 高负载/插桩 = 经典组合。

## 参考

- `.evidence/verify-b20ee5c51e3b/`（`coverage-summary: UNKNOWN`）
- `crates/nexus-projection/src/path_link.rs`（`rebind_failure_keeps_connection`）
