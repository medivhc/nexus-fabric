---
id: enum-discriminant-index
date: 2026-09-30
module: nexus-path
category: implementation-pitfall
task_type: feature
---

# Review：用 enum 判别值强转做数组索引是潜伏 panic（`kind as usize` 模式）

## 问题/模式描述

`crates/nexus-path/src/fallback.rs` 用 `PathKind` 的判别值给 per-kind 计数器数组
做索引：

```rust
const KIND_COUNT: usize = 4;
fn kind_idx(kind: PathKind) -> usize {
    debug_assert!((kind as usize) < KIND_COUNT);
    kind as usize   // 依赖 Direct=0, Mesh=1, Turn=2, Proxy=3 的隐式顺序
}
```

配套测试 `kind_discriminants_stable` 只断言了**现有** 4 个 variant 的顺序，
没有 guard variant 数量。将来给 `PathKind` 加第 5 个 variant 时：代码编译通过，
`debug_assert` 在 release 被编译掉，数组索引越界 → 运行时 panic。

## 原因分析

- `as usize` 强转不产生任何编译期约束：enum 加 variant 是"静默成功"的变更，
  而数组大小 `KIND_COUNT` 和索引函数不会被编译器提醒更新。
- 测试只能 guard"已知的现在"，guard 不了"未知的将来"；顺序稳定 ≠ 数量稳定。
- `debug_assert` 只在 debug 生效，恰好是"开发时没事、线上炸"的经典形状。

## 解决方案

用 **exhaustive match** 代替强转，让编译器做守卫：

```rust
fn kind_idx(kind: PathKind) -> usize {
    match kind {
        PathKind::Direct => 0,
        PathKind::Mesh => 1,
        PathKind::Turn => 2,
        PathKind::Proxy => 3,
    }
}
```

加 variant 时 match 不再 exhaustive → 编译错误定位到此处，作者被迫同步更新
`KIND_COUNT` 与计数器数组。保留 `kind_discriminants_stable` 测试作为文档亦可，
但不再是唯一的防线。

## 教训/可复用要点

- Review 时看到 `SomeEnum as usize` 做数组/位图索引，直接问：
  "加一个 variant 会发生什么？是编译错误还是运行时 panic？"
- 更一般的原则：**把"将来一定会被违反的隐式约定"变成编译期错误**，
  而不是测试或 debug_assert。match 穷尽性是 Rust 里最廉价的防线。
- 同一模式也适用于 `#[repr(u8)]` + 手工映射的场景：只要索引含义依赖
  variant 集合的完整性，就用 exhaustive match 守。

## 参考

- Review evidence `9ef6600405f4`（路径 fallback 联动，第 1 轮，COMPLEXITY WARN）
- `crates/nexus-path/src/fallback.rs`（`kind_idx` / `KIND_COUNT`）
