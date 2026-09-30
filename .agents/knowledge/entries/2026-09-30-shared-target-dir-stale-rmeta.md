---
id: shared-target-dir-stale-rmeta
date: 2026-09-30
module: engineering
category: implementation-pitfall
task_type: feature
---

# 共享 CARGO_TARGET_DIR 跨 worktree 导致陈旧 rmeta 幻影编译错误

## 问题描述

2026-09-30，`feature/path-fallback` 在 xc-pc-linux 的独立 worktree
（`/tmp/nexus-path-fallback`）工作，但 `CARGO_TARGET_DIR` 指向多 worktree
共享的 `/work/nexus-dev/target`。`verify --fast` 连续两次报出**幻影编译错误**：

1. `no FallbackChain in the root`（E0432）——而 `cargo build` 刚成功过；
   `touch crates/nexus-path/src/lib.rs` 强制重建后消失。
2. `missing fields obfs and obfs_key in initializer of
   nexus_proxy_config::OutboundConfig`（E0063）——本 worktree 的
   `OutboundConfig` 根本没有这两个字段（是另一个并行轨道 plugin-dial
   在它的源码里加的）；`touch` 对应 crate 的 `lib.rs` 后消失。

两次都是代码无问题，`touch` 后 `cargo check` 通过。

## 根因分析

共享 target 目录里有其他 worktree 构建留下的 `.rmeta`；cargo 的指纹
（mtime based）在多 worktree 高频交叉构建下失效，复用了不属于本
worktree 源码的旧 metadata。表现就是编译器"看到"了别的 worktree 的
类型定义（phantom types）。

## 解决方案

每个 worktree 用**独立**的 `CARGO_TARGET_DIR`
（如 `/tmp/nexus-path-fallback-target`），彻底隔离。代价是一次全量重建
（慢），但正确性优先。切换后果然 `verify --fast` 8/8 PASS。

## 预防措施

- 并行轨道每个 worktree 配独立 target dir；不要为了省磁盘/省时间共享。
- 看到"不可能"的编译错误（源码里没有的东西被编译器看到），先怀疑
  stale rmeta：`touch` 相关 `lib.rs` 强制重建验证。
- AGENTS.md 的 worktree 隔离条款应同时覆盖 target dir。

## 参考

- Branch: feature/path-fallback @ 2706e8f
- Evidence: verify --fast 8/8 PASS (dedicated target dir)
