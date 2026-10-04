# cargo-deny 基线归因决策记录（fix/deny-baseline）

日期：2026-09-30｜执行：Muse（子代理）｜用户授权：书面理由逐条记录

## 归因方法

- 干净 worktree @ `4c1b86f`（基座），不污染任何 feature 分支工作区。
- cargo-deny 0.20.2（官方预编译 musl 二进制，sha256 校验通过）。
- advisory DB：现场从 github.com/rustsec/advisory-db 全新 clone（1284 条公告），
  在线跑 + `--offline`（gate 实际命令）双验证。
- gate 实际命令：`cargo deny --offline --config policies/deny.toml check advisories licenses bans sources`

## 逐类结果

| 类别 | 基座 4c1b86f | feature/turn-relay @68d178e | feature/plugin-obfs @b211120 |
|---|---|---|---|
| advisories | 0 errors | 0 errors | 0 errors |
| licenses | ok | **1 error：nexus-turn 未声明 license** | **1 error：nexus-plugin 未声明 license** |
| bans | ok | ok | ok |
| sources | ok | ok | ok |

## 决策表

| # | 类别 | 对象 | 决策 | 书面理由 |
|---|---|---|---|---|
| 1 | advisories | 全工作区 182 crates | **无需例外**（`ignore = []` 保持） | 1284 条最新公告下零命中。rustls 0.23.45 / quinn-proto 0.11.18 等传递依赖当前无 advisory。 |
| 2 | licenses | nexus-turn 0.1.0 | **修复（非例外）**：补 `license.workspace = true`，commit `a438ce6` → `feature/turn-relay` | 真实缺失：contract 阶段新建 crate 时漏了 license 字段。仓库约定 `license.workspace = true`（MIT OR Apache-2.0），与其他 crate 一致。纯元数据补齐，无行为/API 变化。 |
| 3 | licenses | nexus-plugin 0.1.0 | **修复（非例外）**：补 `license.workspace = true`，commit `922001b` → `feature/plugin-obfs` | 同上，真实缺失。 |
| 4 | bans | 全工作区 | **无需动作** | `multiple-versions`/`wildcards` 均为 warn 级（策略如此），零 deny。 |
| 5 | sources | 全工作区 | **无需动作** | 全部 crates.io，无 git/未知 registry。 |

## 关于"219 个 errors"的前报告——诚实说明

此前 full verify 报告称基座 `4c1b86f` 上 `cargo deny` 报 219 errors（rustls/windows-sys/paste
系）。本次在干净 worktree + 全新 DB 下**无法复现**：基座在线/`--offline` 均为全绿。

可能解释（按可能性排序）：
1. 当时真机缓存的 advisory DB 处于某种中间/损坏状态（gate 用 `--offline` 读缓存 DB）；
2. 当时工作区处于脏状态（另有分支 checkout 中途切换，`Cargo.lock` 非基座版本）；
3. 报告归因有误。

**结论**：以本次可复现的干净归因为准。deny.toml **零例外、零 allowlist 膨胀**——
任务要求的"不许为了过 gate 而批量 allowlist"自然满足，因为没有任何 advisory 需要忽略。

## 安全债（必须明确列出）

- **无"真实可达但没修"的 advisory**：本次归因下 advisory 类零命中，不存在此类债。
- **"不可达所以忽略"类例外**：零条。`[advisories] ignore = []` 保持为空。
- **未来复核点**：advisory DB 随时间漂移是已知属性。本次全绿只代表 2026-09-30 的 DB
  状态；`unused-ignored-advisory = "warn"` 已配置，若将来加 ignore 条目，失效时会自动告警。

## 验证

- `cargo deny --offline --config policies/deny.toml check advisories licenses bans sources`
  在三个树状态下均为 `advisories ok, bans ok, licenses ok, sources ok`（exit 0）。
- license 修复已分别推送到 `feature/turn-relay`（a438ce6）与 `feature/plugin-obfs`（922001b）。
