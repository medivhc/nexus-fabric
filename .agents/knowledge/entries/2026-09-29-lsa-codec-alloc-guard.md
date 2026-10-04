---
id: lsa-codec-alloc-001
date: 2026-09-29
module: nexus-discovery
category: implementation-pattern
task_type: feature
---

# 解码不可信长度前缀时用 `Vec::with_capacity(n.min(CAP))` 防过度分配

## 问题/模式描述

二进制协议解码时，对端可发送任意 `u16` 长度前缀（如 `n = 65535`）。
若直接 `Vec::with_capacity(n)`，恶意/损坏帧可触发 64KB+ 的瞬时堆分配
（放大攻击面；`n` 个元素的逐个解码仍会因截断检查失败，但内存已分配）。

LSA 解码（`crates/nexus-discovery/src/lsa.rs`，`get_lsa` / `decode_lsa_frame`）
采用：
```rust
let n = get_u16(buf, pos)? as usize;
let mut neighbors = Vec::with_capacity(n.min(64));
for _ in 0..n {
    neighbors.push(decode_one(...)?); // 逐个解码，截断即 Err
}
```

## 原因分析

- `with_capacity` 只影响初始分配，不影响 `push` 语义——`n.min(64)` **不是截断**，
  解码循环仍跑满 `n` 次，数据无丢失。
- 攻击者能控制的只是初始分配上限（64 个元素的槽位），而非解码出的数据量；
  真实数据量仍由后续 bounds 检查（`frame truncated`）把关。
- Review 时曾误判为"静默丢数据"，实测确认是容量提示。命名上 `min(CAP)`
  易引起误解，注释应写明"仅容量提示，非截断"。

## 解决方案

- 不可信长度前缀 → `Vec::with_capacity(n.min(SANE_CAP))` + 逐个解码 + bounds 检查。
- CAP 取典型值的数倍（如邻居数 64、Welcome 快照 256），兼顾正常性能与抗放大。

## 教训/可复用要点

- 任何解码 `u16/u32` 长度前缀后 `with_capacity(n)` 的地方都应套 `min(CAP)`。
- Review 看到 `n.min(...)` 先确认是 capacity hint 还是真截断（看循环上界）。
- 建议在代码注释写明 `// capacity hint only, not truncation` 避免后人误改。
