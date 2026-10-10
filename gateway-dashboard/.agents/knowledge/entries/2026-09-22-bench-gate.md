---
id: 2026-09-22-bench-gate
date: 2026-09-22
module: engineering/nexus-harness
category: implementation-pattern | architecture-decision
task_type: feature
---

# P3.7 harness bench gate：性能预算机器化执行

## 问题/模式

MVP harness 的 `bench` 命令返回 UNKNOWN（"not implemented"），P3.6 的加密数据面
性能基准只能手动 `cargo run --example perf_bench` 复核。P3.7 将其接入正式门禁。

## 方案（AGENTS §21 机器化）

- `gates::bench_gate`：`cargo run -q -p nexus --example perf_bench -- --json`
  （repo root）→ 取 stdout 最后一行 JSON → 按预算 verdict 映射：
  PASS→PASS / WARN→PASS+note（不阻塞）/ FAIL→FAIL / 运行或解析失败→UNKNOWN
  （"not silently passed"）。
- 解析层抽为纯函数 `bench_verdict_gate(text)`，单测覆盖 5 分支
  （PASS/WARN/FAIL/无 JSON/坏 JSON）。
- `commands::bench()` 提供独立 `nexus-harness bench [--json]`；
  `[verification.full] gates` 增加 `"bench"`（fast 不挂，保持快速）；
  full verify 现为 22 gates。

## 教训/可复用要点

1. **`Value::pointer` 接收 `&str` 路径**（如 `/aead/throughput_mbps`），
   不是 `&[&str]` 切片——闭包签名写错会 E0308。
2. **gate 语义映射**：WARN 不阻塞（AGENTS §19.1），映射为 PASS+detail 注明；
   只有 FAIL 阻断、UNKNOWN 提示（不静默）。这与 scenario 断言
   （verdict∈枚举 + 字段非空）解耦：绝对值判定留在 example 内，gate 只搬 verdict。
3. **quality.toml 是 gates 单一真相源**（config.declared_gates），新增 gate =
   声明 + commands.rs match 两处同步；漏一处会走 unimplemented→UNKNOWN。

## 验证

- `nexus-harness bench --json` → verdict=PASS（aead ~989 MB/s / tunnel ~80 MB/s）
- 单测 `bench_verdict_gate_maps_budget_verdicts` 全绿
- fast 8 gates / full 22 gates 全 PASS（verify-5f6171306bd7，contract 438d3a8b…）
