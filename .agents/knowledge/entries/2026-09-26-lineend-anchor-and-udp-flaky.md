---
id: ps-lineend-001
title: 仓库 .rs 文件行尾不统一 + harness full 下 UDP 测试竞态 flaky
tags: [powershell, line-ending, anchor-replace, flaky-test, harness]
module: apps/nexus
severity: medium
source: debug
date: 2026-09-26
related: []
---

## 问题描述

两个独立坑，同一天（schedule CLI 接入任务）踩到：

1. **仓库 .rs 文件行尾不统一**：`apps/nexus/src/lib.rs` 为纯 LF、`apps/nexus/src/main.rs` 与
   `apps/nexusd/src/main.rs` 为纯 CRLF、`apps/nexus/src/schedule_cli.rs` 与 `mesh.rs` 为纯 LF。
   用 PowerShell 做锚点文本替换时，here-string 的 CRLF 假设会让 `([regex]::Matches($t,
   [regex]::Escape($old))).Count` 返回 0，抛 "anchor count=0"（文件未被修改，安全但浪费轮次）。

2. **harness verify --full 下 subnet_punch_cli 集成测试偶发 FAIL**：`punch_empty_targets_errors` /
   `punch_encrypted_state_preserved` / `punch_failure_persists_state_for_status` 三个用例在
   full verify 中 FAIL，但 `cargo test -p nexus --test subnet_punch_cli` 单独/串行/压力跑
   3 次均 9/9 全过。full verify 重跑即 PASS（22/22）。

## 根因分析

1. git 工作树中 .rs 文件行尾由各自历史写入方式决定（Write 工具 vs PowerShell vs rustfmt
   对已有文件），没有统一约定；Edit 工具对"未整文件读取"的大文件报 not read，逼出
   PowerShell 锚点替换路径，而 here-string 行尾默认跟随脚本传递方式（CRLF）。

2. 测试代码自曝竞态：`subnet_punch_cli.rs` 注释「pick_port 有 drop 竞态窗口，并行测试会
   端口冲突」，port_lock 只串行化了 2 个持锁用例；`punch_empty_targets_errors` 等 3 个用例
   不持锁，在 harness full 的重负载上下文（cargo test --workspace 并行全仓测试紧随其后）
   下 UDP ephemeral 端口瞬时冲突，`subnet_punch` 内部 bind 失败 → 断言
   `starts_with(HOLE_PUNCH_EMPTY_TARGETS)` 等不成立。是环境/时序偶发，非逻辑错误。

## 解决方案

1. 锚点替换统一套路：先读字节探测文件行尾（CRLF/LF 计数），把文件全文与 here-string 都
   归一化为 LF 做 Replace，写回时按原行尾还原（LF 文件直接写，CRLF 文件
   `-replace "\n", "\r\n"`），全程用 `[IO.File]::WriteAllText($p, $t, (New-Object
   System.Text.UTF8Encoding $false))`（无 BOM）。每次替换仍保留唯一性校验
   `count -eq 1`，替换后 Select-String 回读锚点。

2. full verify 首个 FAIL 先区分失败类别再动手：对疑似竞态的测试（自曝端口/时序依赖），
   先在同样状态下单独/串行复跑 N 次（本项目 3 次），再模拟 harness gate 序列
   （workspace-tests → integration），仍不复现则重跑 full。不要一 FAIL 就改测试或改代码。
   最终以重跑 full 的 fresh PASS 证据为准（本次 22/22），并把竞态观察记录在案。

## 预防措施

- 任何 PowerShell 文本替换前先探测目标文件行尾，锚点按实际行尾归一化；不在假设上写脚本。
- Review/验证遇到 full FAIL 时，先做失败类别判定（Implementation / Contract / Environment /
  Unsupported），Environment/竞态类先复现后重跑，禁止为迎合而削弱 gate。
- 新增会 bind 真实端口/UDP 的集成测试时，沿用并扩展 port_lock 串行化，或改用
  SO_REUSEADDR 语义避免 ephemeral 竞态。

## 参考

- commit 14b47ee（schedule CLI 接入）
- `.evidence/verify-4ce69aac9494`（full 22/22 PASS）
- `apps/nexus/tests/subnet_punch_cli.rs`（port_lock / pick_port 注释）
