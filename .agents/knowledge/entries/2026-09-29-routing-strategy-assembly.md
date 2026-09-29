---
id: routing-strategy-assembly
date: 2026-09-29
module: nexus-discovery
category: implementation-pattern
task_type: feature
---

# `[routing] strategy` 配置装配：策略枚举直接实现 PathComputer

## 问题/模式描述

`ShortestPath` 与 `Ecmp` 是两个独立类型，各调用方 hardcode 具体类型。
新增策略或切换策略需要改所有调用点。需要配置驱动的装配。

## 原因分析

- Rust 中"返回两种不同类型之一"的工厂函数需要 `Box<dyn Trait>`（堆分配）
  或枚举包装。portable core 倾向零分配。
- 策略枚举本身实现 `PathComputer`（各方法 match 委托）是最简方案：
  无新 trait、无 Box、无包装类型，调用方只认 `RoutingStrategy`。

## 解决方案

- `pub enum RoutingStrategy { Shortest, Ecmp }` + `impl PathComputer for RoutingStrategy`
  （5 个方法全部委托，含 `compute_all`/`compute_all_paths` 的批量优化版本，
  避免退化为默认实现的逐 dst 调用）。
- `parse()` 大小写不敏感+trim；`Default` 为 `Shortest`（向后兼容）。
- 配置层：`SubnetConfig` 加 `#[serde(default)] routing: RoutingSection`；
  `routing_strategy()` 返回 `Result<_, String>`，未知值 fail-closed。
- 注意：`SubnetConfig.subnet` 无 `#[serde(default)]`，纯 `[routing]` 的 TOML
  解析会失败 —— E4 测试必须带最小 `[subnet]` 段。

## 教训/可复用要点

- 枚举实现 trait 做静态分发时，**必须覆盖所有有默认实现的方法**
  （`compute_all` 等），否则委托会丢失被委托类型的批量优化。
- `#[serde(default)]` 只加在新增字段上，既有必填字段不动，保证向后兼容。
