---
id: unwrap-or-eager-001
title: Option::unwrap_or 的参数是立即求值的——回退表达式含下溢/副作用时必须用 unwrap_or_else
tags: [rust-pitfall, option, eager-evaluation]
module: nexus-discovery
severity: high
source: debug
date: 2026-09-30
related: ["lsa-codec-alloc-001"]
---

## 问题描述

`crates/nexus-discovery/src/mdns.rs` 的 `decode_name` 在处理 DNS 压缩指针的
单测（`decode_name_handles_compression`）中 panic：`attempt to subtract with
overflow`，位置在函数尾的 `*pos += consumed.unwrap_or(p - *pos)`。

## 根因分析

`Option::unwrap_or` 的参数是**立即求值**的（eager），不是惰性的。即使
`consumed` 为 `Some(2)`，表达式 `p - *pos` 仍会被先求值。DNS 压缩指针跳转后，
`p`（跳转目标，如 0）小于 `*pos`（原流位置，如 24），`p - *pos` 在 debug
构建下直接 panic（release 下回绕出错误值）。

这是 Rust 新手/老手都易犯的错：`unwrap_or` 看起来像"默认值"，但它的参数
不是闭包。凡是回退表达式含有**可能 panic 的运算**（减法下溢、除零、索引）
或**副作用/开销**（分配、I/O），都不能用 `unwrap_or`。

## 解决方案

```rust
// 错：p - *pos 总是被求值，指针跳转后下溢 panic。
*pos += consumed.unwrap_or(p - *pos);
// 对：闭包惰性求值，只有 None 时才计算。
*pos += consumed.unwrap_or_else(|| p - *pos);
```

同理适用于 `ok_or`（立即求值）vs `ok_or_else`（惰性）。

## 预防措施

- Review 看到 `unwrap_or(` / `ok_or(` 时，检查参数是否为纯字面量/常量；
  凡含运算，一律要求 `unwrap_or_else` / `ok_or_else`。
- clippy 的 `or_fun_call` lint 覆盖的是"函数调用"情形，但**算术表达式**
  不会被 lint 捕获，需人工注意。

## 参考

- commit：feature/discovery `54192f7`（E4 驱动提交，含此修复）
- 相关：`lsa-codec-alloc-001`（同为解码器边界算术坑）
