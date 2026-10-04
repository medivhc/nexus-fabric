---
id: cli-unify-scenario-requirement-change-pattern
title: CLI 统一后 stale 场景走 requirement-change 的重写模式（thin-client 现实为准）
tags: [requirement-change, scenario, cli-unify, thin-client, UNSUPPORTED]
module: scenarios
severity: medium
source: requirement-change
date: 2026-10-02
related: []
task_type: requirement-change
---

# CLI 统一后 stale 场景的 requirement-change 重写模式

## 背景

2026-10-01 CLI 统一（01e5114）把 `nexus` 变成 thin-client：`nexusd` 退化为纯
daemon（`usage: nexusd <config-folder>`），旧 `nexusd <cmd> --json` 的进程内演示
入口全部删除。14 个场景的冻结期望与新 CLI 真实行为冲突，用户 2026-10-02 批准
走 requirement-change 重写（分支 `requirement-change/stale-14-scenarios`）。

## 新 CLI 现实（真机实测，2026-10-02）

- `nexus run frobnicate|workspace --json` →
  `{"verdict":"FAIL","error":{"code":"UNSUPPORTED","message":"unsupported feature: run <r>"}}`
  （exit 0；注意 run 系列没有 `error.command` 字段，只有 `error.message`）
- `nexus run service --json` → thin wrapper 调进程内 SDK，
  `{"verdict":"PASS","run":{"resource":"service","outcome":"Completed",`
  `"connectivity":{"status":"Connected"},"session_id":"sess-<随机hex>"}}`
- 无 LocalAPI 路由的观察命令 →
  `{"verdict":"FAIL","error":{"code":"UNSUPPORTED","command":"<cmd>"}}`
  （与 2026-09-20 冻结的 `cli_*.toml` 同形）
- 部分命令需位置参数，否则 exit 2 + usage 文本（非 JSON）：
  `connectivity probe <target>`、`workspace cache|conflicts|heads <workspace>`
- 解析器未知的子命令（如 `connectivity trace`）→ exit 2 + usage 文本

## 重写模式

1. `[when]` 从 `cargo run --quiet -p nexusd -- <cmd> --json` 改为
   `cargo run --quiet -p nexus -- <cmd> --json`（+ 必需的位置参数）。
2. 期望改为新行为的精确断言（verdict + error.code + error.command/message），
   不放水成恒真。
3. 每个文件保留 requirement-change 注释（原因 + 日期 2026-10-02）。
4. contract hash（`git hash-object` over sorted `scenarios/**/*.toml`，
   见 `env.rs::contract_hash`）写入 commit message 的 `requirement-change: <hash>`。

## 教训

- **harness 能力缺口**：`ExpectKind` 只有 Equals/OneOf/NonEmpty，且场景 runner
  要求 stdout 为 JSON、丢弃 exit 码——exit 2 + usage 文本的新行为无法表达为 E4。
  遇到此类行为，只能在 `[given]` 里如实记录 + 报告注明，不要硬凑 JSON 断言。
- `nexus run service` 的 `session_id` 每次随机，只断言 `non_empty`。
- 重写前先在真机实测每个命令的真实输出，不要凭 `cli_*.toml` 脑补字段
  （如 run 系列就没有 `error.command`）。
