---
id: arch-cleanup-dead-code-2026-10-03
date: 2026-10-03
module: workspace
category: architecture-decision
task_type: refactor
---

# 架构清理：删除确认死代码（module_summary / NEXUS_*_MODULE / 空依赖边）

## 问题/模式描述

2026-10-02 opencode 整库架构分析 + 死代码深挖（`~/workspace/reports/nexus-deadcode-verify-2026-10-02.md`）
确认三类可安全删除的死代码：
1. 23 个 `pub const fn module_summary()` 定义（零调用）
2. 24 个 `pub const NEXUS_*_MODULE` 常量（零引用；报告写 23，实为 23 lib.rs + `nexus-connectivity/src/coord.rs` 的 `NEXUS_COORD_MODULE`）
3. 8 条空 Cargo 依赖边：`control-api→proto`、`nexusd→diagnostics`、`{network,service,transport,connectivity,compute,workspace}→delivery`

## 原因分析

- `module_summary()` / `NEXUS_*_MODULE` 是早期"模块标记"约定，但从未有消费方（MODULE.md 也未记录该约定）。
  若未来需要模块摘要，应由 MODULE.md 单一来源生成，而非在 Rust 代码里复制样板。
- 空依赖边：占位 crate（proto/diagnostics/delivery）本身是**有意保留**的契约槽位
  （MODULE.md 骨架 + architecture.toml / harness.toml 背书），但 8 个依赖方声明了依赖却零代码引用，
  导致 Cargo 依赖图与代码引用长期不一致。删边不删 crate。

## 解决方案

- 用脚本精确删除（item + 紧贴的 `///` doc 与 `#[attr]`），32 文件、217 行纯删除。
- 删前对每类做全 workspace 二次 grep 确认零引用（防报告过时）。
- `policies/architecture.toml` 的 `allowed_internal_dependencies` 是"允许"而非"必须"，
  删 Cargo 边不违反策略，无需同步改 policy。
- **未动**：两套 TurnClient（去留另议）、API/错误类型风格问题（非死代码）、
  平台占位 crate（macos/android/ios）、`NEXUS_HOME` 环境变量（与常量无关）。

## 教训/可复用要点

- 批量删除脚本的 end-pattern 必须用 `re.search` 语义而非 `re.match`（行首锚定）——
  第一版脚本把 `nexus-session/src/lib.rs` 整文件 894 行吃掉了，回退重写才修好。
  删后务必 `git diff --stat` 看删除行数是否合理（209 行 vs 7903 行一眼可辨）。
- workspace 级 `cargo check --all-targets` 即编译了全部 tests/examples，
  对纯删除类 refactor 是最强的正确性证明（编译器保证无引用）。
- 沙盒 `cargo test --workspace` 的 UDP-EPERM 失败是已知环境噪音，
  判读时以干净基线 worktree 对照（AGENTS.md 已有条目）。
