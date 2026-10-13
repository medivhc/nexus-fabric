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

## 新实例（2026-10-13，评审 r7 R7-N-11 登记）

`crates/nexus-web-gateway` 的节流语义有 **三处依赖真实墙钟**的夹具，全部登记为已知
flaky 面，改动它们时不要用"我这台机器跑绿了"当证据：

- 单测 `lockout_rearms_after_expiry_and_flood_arms_are_not_exempt`：窗口 300 ms，两次
  `sleep(window * 2)`。窗口取 300 ms 而不是 40 ms 是有意的：**武装侧**要求一整轮注入
  落在同一个窗口内，窗口越小越容易被调度抖动打断（40 ms 版在 Linux 上就是靠运气跑的）。
- 单测 `lockout_requires_failures_inside_one_window`：窗口 200 ms，`sleep(window + window/2)`。
- 探针 `auth-throttle` 的 e6/e8 夹具：窗口 100 ms 静置 400 ms（4× 余量），以及
  8 行 × 3 轮、轮间静置 150 ms（1.5× 余量，最薄的一处）。

`Throttle` 内部**每一个**时间读取都直接调 `Instant::now()`（这里故意不写数量：写死计数
的散文会随着增删读点变成谎话，评审 r9 R9-N-9 就是抓的这一条），**时钟不可注入**，而 `FileEngine::sweep_idle(now)`
已经示范了可注入形态——把时钟注入做进 `Throttle` 是这三处夹具脱开墙钟的唯一办法，
本批未做，记在 MODULE G15 的未证事项里。llvm-cov 插桩运行按本条目上面的实测先例
约放大 20×，会把静置侧的余量吃掉——**但插桩放大的是"跑得更慢"，而 sleep 只有下界
语义，所以放大带来的是假红风险（多睡不等于少睡）**。评审 r8 反过来核出另一件事：
e8 那个 1.5× 余量的夹具**不可能假红**（每身份恰好 `lockout_after-1` 条失败，慢只会
让衰减更早发生，而衰减本来就是期望的方向），它的真实风险在**变异逃逸**侧——即
"判据在这台机器上恰好不需要吃满余数就能成立"，所以这条夹具的余量大小不是它的效力
证明，效力只能靠变异实测（N6 实测 20/28 就是这么来的）。我上一版把方向说成"最可能
先假红"，已被 r8 判为说反，此处按复核结果改写。
