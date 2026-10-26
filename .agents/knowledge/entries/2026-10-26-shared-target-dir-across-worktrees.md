---
id: shared-target-worktree
date: 2026-10-26
module: engineering
category: implementation-pitfall
task_type: test
---

# 多个 worktree 共用 CARGO_TARGET_DIR 会互相覆盖构建产物

## 问题描述

主工作树（分支 A，含新函数 `outbound_warnings`）与评审子代理的临时 worktree（旧
revision `1e0f970`）共用 `/home/user/nexus-fabric/target`。随后在主树干净提交上重跑
E4 场景得到假 FAIL：嵌套 `cargo run -p nexus` 报 `cannot find function
outbound_warnings in crate nexus_proxy_config`，而主树源码里该函数存在。

## 原因分析

cargo 对 path 依赖按**相对工作区根**的路径计算 metadata hash（为可复现构建），
不同 worktree 中同名 crate 落到同一产物文件；新鲜度又按 mtime 判断。旧树后编译的
rlib 比主树源文件新，cargo 便认为主树产物「已是最新」而不重编。

## 解决方案

- 每个 worktree 独立 `CARGO_TARGET_DIR=<worktree>/target`（AGENTS.md §29.5 已要求）。
- 已被污染时：`cargo clean -p <受影响 crate...>` 后重建，并把共享期间产生的
  verify / scenario Evidence 视为可疑，在干净构建上重新生成。

## 教训

- 给子代理派发「在临时 worktree 里跑测试」时，提示词必须写明独立 target 目录，
  不要为省编译时间指向主树 target。
- 场景驱动丢弃子进程 stderr 会把编译失败伪装成「exited without output」；排查时先
  手动跑嵌套命令看 stderr。
