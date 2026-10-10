---
id: boost-v1-contract-first
date: 2026-10-01
module: nexus-network, nexus-projection
category: implementation-pattern
task_type: feature
---

# Boost v1 的 Contract-First 落点：配置层与胶水层的依赖边界划分

## 问题/模式描述

Network Boost v1 需要把 `network.toml [boost]` 配置映射到 `nexus-path` 的
`PathConfig`（hysteresis/switch_hold），但 `nexus-network` 的
`policies/architecture.toml` 允许依赖列表中**没有** `nexus-path`
（仅 dev-dependencies 有）。直接加生产依赖需要改架构 policy，超出本期范围。

## 解决方案

三层划分，各守边界：

1. **`nexus-network`**（配置层）：`BoostConfig` + `[boost]` 解析/校验 +
   `path_params() -> BoostPathParams`。`BoostPathParams` 是纯数据 struct
   （`hysteresis_pct: f64`、`switch_hold_ms: u64`、`race_on_connect: bool`），
   零 `nexus-path` 类型，policy 无需改动。
2. **`nexus-projection`**（胶水层，已有 `nexus-path` 生产依赖）：
   `boost.rs` 提供 `path_config_for_boost()`、`select_best()`（`&PathManager`
   只读）、`boost_connect()`（竞速分发）。函数取原始标量参数，不依赖
   `nexus-network` 类型。
3. **组合根**（example/app）：把 `BoostPathParams` 的字段拆开传入胶水函数。

## 教训/可复用要点

- 配置 struct 跨越依赖边界时，用"纯数据中转 struct + 调用方拆字段"代替
  加依赖边；policy 变更是重操作，能避则避。
- `select_best` 的 `candidates: &[CandidatePath]` 由调用方持有——
  `PathManager` 不暴露候选列表，胶水层不要为此去改 `nexus-path` 的 API。
- 测试中 `select_best(&pm, &[c], ...)` 会触发 E0716（临时数组借用）；
  必须先 `let arr = [c];` 再传 `&arr`。
