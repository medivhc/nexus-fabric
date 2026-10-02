---
id: harness-stderr-must-not-pollute-scenario-json
title: harness 场景判定只看 stdout——stderr 拼入判定文本会导致 eprintln! 日志破坏 JSON 解析
tags: [harness, scenario, stdout, stderr, json, misdiagnosis]
module: nexus-harness
severity: medium
source: debug
date: 2026-10-02
related: []
task_type: bugfix
---

# harness 场景判定只看 stdout

## 问题/模式描述

2026-10-02 真机 full verify 把 `product.composition-root` 和
`product.workspace-sync-authz` 判为 FAIL，detail 为
`output not JSON (trailing characters at line 2 column 1)`，
stdout 第 2 行出现了 `[nexusd] N1 bridge assembled: 1 routes` /
`[sync] rejected non-member peer ... (authz)` 这样的日志行。
执行员据此诊断为"产品侧 stdout 污染"，决定"修产品侧"。

实际复查发现产品侧**从没错过**：这两行自引入起就是 `eprintln!`
（`apps/nexusd/src/assembly.rs`、`apps/nexusd/src/sync_transport.rs`），
机器 JSON 一直走 stdout。真正的 bug 在 harness：
`run_command_with_timeouts`（b2abdbe 引入，修孤儿孙进程持有 pipe 致
`output()` 永挂）把 stderr 拼进了判定文本：

```rust
let text = format!("{}{}", stdout, stderr);  // 错误：stderr 不该参与判定
```

`run_gate` 对整段文本做 `serde_json::from_str`，于是任何 stderr 日志行
都破坏 JSON 解析。

## 原因分析

- 修 pipe 挂起问题时，为了"不丢信息"把 stderr 并入了返回文本，
  但该文本的唯一消费者是场景 JSON 判定（`run_gate` 第 312 行），
  语义上它必须是纯 stdout。
- 产品侧的 stdout/stderr 分离约定（JSON 走 stdout，日志走 stderr）
  被 harness 侧的合并破坏了——验证工具违反了它自己要强制的约定。

## 解决方案

`engineering/nexus-harness/src/scenario.rs`：
stderr 照常抽干（避免 pipe 背压阻塞子进程）但丢弃，判定文本只含 stdout。
加回归测试 `run_command_ignores_stderr_for_scenario_json`
（stdout 打 JSON + stderr 打日志，断言判定文本 == 纯 stdout）。

```rust
Ok((false, _)) => {}  // 抽干但不参与判定
let text = String::from_utf8_lossy(&stdout).into_owned();
```

## 教训/可复用要点

1. 报"stdout 污染"时先看证据里的原始字节到底从哪个 fd 来，
   不要直接认定产品侧；`eprintln!`/`println!` 一 grep 即知。
2. 验证工具自身的输出处理逻辑也是 bug 来源——修 A 问题时引入的
   B 回归（b2abdbe 修挂起引入合并），要有回归测试锁住。
3. 机器判定口径必须文档化：场景命令的机器可读输出 == 纯 stdout JSON。
