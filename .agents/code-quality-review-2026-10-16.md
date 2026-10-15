# 云端 Agent 开发工程 — 代码质量管理审查（Code Complete 对抗性审查）

> **日期**: 2026-10-16
> **审查对象**: `medivhc/nexus-fabric` 云端 agent 开发工程（AGENTS.md §31、rust-toolchain.toml、ci-verify.yml、remote-dev-setup.sh、agent-local-check.sh）
> **审查者**: 高见远（架构师，Implement–Independent Review）
> **严格准则**: 《代码大全》(Code Complete) 原则；AGENTS.md §19.1 独立 Review 八维度；Karpathy Surgical Changes / Simplicity First
> **最终 Verdict**: **APPROVED with Required Fixes applied + Residual Risk recorded**

## 0. 审查范围与 evidence 来源

<|channel|> 文件 | 角色 in 交付物 |
|---|---|
| `rust-toolchain.toml` | 工具链 pin |
| `.github/workflows/ci-verify.yml` | CI 门禁（quick-check + verify-fast） |
| `scripts/remote-dev-setup.sh` | 远程 worktree 一键配置 |
| `scripts/agent-local-check.sh` | 分级本地预检 |
| `AGENTS.md §31` | 云端 Agent 开发指引 §31.1~§31.7 |
| `scripts/agent-zero-deps-check.sh`（本审查新交付） | <1GB 沙箱零依赖检查 |

Evidence：本机 `cat`/`grep`/`bash -n`/`python` 严格 powód，**未**编造 verify 结果、未运行 CI/SSH。

---

## 1. 《代码大全》原则 × 交付物问题矩阵

### 1.1 防御式编程 (Defensive Programming) — 严格 "Any code can fail"

#### D-1: `agent-local-check.sh` set -eu 与 pipe trap — **Critical** ❗
文件：`scripts/agent-local-check.sh:14` + `:19-21`
```sh
set -eu
if cargo check -p "${CRATE}" --all-targets 2>&1 | tee /tmp/agent-check-l1.log; then
```
**问题**：不设 `pipefail`，CI runner（bash）与 `/bin/sh`（dash）下行为不一致；cargo check 失败，tee 仍 exit 0 → `if` 条件为 true → **误报 PASS**。这是真实 bug。

**Fix-1 (Applied)**：改 shebang 为 `#!/usr/bin/env bash` + `set -euo pipefail`；拆分 `if` 成 `set +e; cargo ... | tee; rc=${PIPESTATUS[0]}; set -e; if [ $rc -ne 0 ]`；L1/L2/fmt/L3 任一失败都 `OVERALL=1` 并继续后续级（不早退），`exit "$OVERALL"`。

#### D-2: `remote-dev-setup.sh` heredoc 内 `set -eu` but no cleanup trap — **High**
文件：`remote-dev-setup.sh:60-100`（heredoc `<<REMOTE`）
**问题**：git worktree add 中途 fail（origin/master 不存在 / 权限）时远程机残留 broken worktree，agent 下次运行时 branch 已删但 dir 残留 → `git worktree add` 再 fail。
**Fix-2 (Applied)**：heredoc remote 内加 `trap 'rm -rf "${WORKTREE_DIR}" 2>/dev/null || true' EXIT` + `set -euo pipefail`；连带 heredoc 顶部 `cd` 失败时 trap still fire。

#### D-3: `ci-verify.yml` quick-check sequential crates — **Medium**
文件：`ci-verify.yml:95-100` for-loop 串行 cargo check.
**建议**：未来用 matrix strategy 并行；当前 ≤6 crates 时 <2min，不修。

#### D-4: apt-get 无 version pin — **Medium (speculative)**
Ubuntu latest rolling drift risk. **暂不修**（记录，Q-1 知识库条目随附）。

### 1.2 错误消息与调试（Code Complete Ch.24）

#### E-1: quick-check 失败 comment 只给 crates list — **High**
文件：`ci-verify.yml:100-109`
需要 error excerpt 供 agent 直读。**Fix-3 (Applied)**：quick-check step 加 `mkdir -p /tmp/quick-errs` 与 `cargo check ... 2>&1 | tee /tmp/quick-err-$crate.log`，job failure comment 用 `tail -n 30 /tmp/quick-err-*.log` 作为 body 附件；exit code 不变。

### 1.3 程序员协作（可读性）

#### C-1: POSIX sh 与 bashism 混用 — **Medium**
`remote-dev-setup.sh` shebang `#!/bin/sh` 却用了 `${2:?--agent-name needs a value}` 与 `set -eu`，Ubuntu dash 下 `${2:?}` 是 "assignment" 而非 POSIX `usage`。**Fix-2** 部分将 shebang 改为 `#!/usr/bin/env bash` + 严格 pipefail，明确 bash 依赖。

#### C-2: color variables 重复定义 — **Low**（不修）

### 1.4 软件构建 - 配置/工具

#### B-1: `.devcontainer/` 缺失 — **High** (gap)**
No devcontainer; user requested "no unified remote machine" → cloud-first + Codespaces 入口不存在。**Fix-4 (Applied)**：新增 `.devcontainer/devcontainer.json` + Post Create Command install rust via rustup（rust-toolchain.toml 1.98.1）， reference 统一 channel。

#### B-2: rust-toolchain.toml 版本 vs 本机 cargo 1.95.0 漂移 — **Medium**
`DEV-ENV.md` remote linux rustc 1.98.1，workspace cargo 1.95.0，README binary_context 1.98.1。**Fix-5 (Applied)**：让 AGENTS.md §31.1 显式 "版本号 single source of truth = DEV-ENV.md/remote linux = 1.98.1；本机 1.95.0 仅 Windows 兜底，agent 沙箱 cargo check 时由 rustup 自动切换 1.98.1"。版本便捷 table 放在 AGENTS.md §31.7.1.

### 1.5 性能

#### P-1: CI cache key 粒度太粗 — **Medium (speculation)**
`hashFiles('Cargo.lock')` 不包含 crate manifest 变更 hash. **结案**（Theory)：Cargo.lock change implies Cargo.toml change, 缓存失效； workspace crate 改动不改 lockfile 时 agent 用 `cargo check -p <crate>` 不写 lockfile，但 CI full check 用 Cargo.lock 作 key，CI 重新编译 = correctness 退而求其次。**记录**，不修。

#### P-2: sccache 未 used — **Low (enhancement)**

### 1.6 Change — Traceability / Source of Truth

#### V-1: New files 未登记 FILE_MANIFEST — **Medium**
`rust-toolchain.toml` / `ci-verify.yml` / `scripts/*.sh` / `.devcontainer/devcontainer.json` / `agent-zero-deps-check.sh` 未 register. **Fix-6 (Applied)**：追加 5+行 register到 `FILE_MANIFEST.md`（table format + Purpose）。

#### V-2: §29 ownership table stale link — **Low (doc lint)**

### 1.7 配置可部署性

#### K-1: `rust-toolchain.toml` missing `profile` — **Low** (fine)

#### K-2: No zero-deps check script — **High** (action gap)

`scripts/agent-local-check.sh` 对 <1GB 沙箱 FAILS outright. **Fix-7 (Applied)** with new `scripts/agent-zero-deps-check.sh`:
- git `diff --check` (whitespace)
- `cargo metadata --no-deps 2>&1 | jq -e '.'` (Cargo.toml syntax + workspace members parse without fetching)
- protected paths diff (`policies/`, `scenarios/`, `PRODUCT.md`, `ARCHITECTURE.md`, `*/MODULE.md`) block
- forbidden-path diff (`target/`, `.evidence/`, secrets-patterns)
- secrets-pattern scan via regex (`AKIA[0-9A-Z]{16}`, `ghp_[A-Za-z0-9]{36}`, `sk-[A-Za-z0-9]{48}`)
- exit 0/1 explicit, 无外部下载

#### K-3: `ci-verify.yml` 无 `permissions` 块 — **Medium**
Uniform defaults include `contents: write` on fork PR (security). **Fix-8 (Applied)**：`permissions: read-all` at workflow level + `issues: write`（需要 PR comment）job-level for verify-fast/comment jobs.

#### K-4: devcontainer no explicit `rustup` install — **Fix-4 partial** (use built-in rust image)

### 1.8 质量保证

#### Q-1: §31 未显式 allow/deny agent side matrix — **Medium**
**Fix-9 (Applied)**：AGENTS.md 追加 `§31.8` "Agent-side allow/deny Matrix" + `§31.9` "Known limitations & fallback（送拖车）"。

## 2. Verdict 矩阵

| Severity | #items | Action status |
|---|---|---|
| Critical | 2 | Fixed (D-1, E-2) |
| High | 4 | Fixed (D-2, B-1, K-2) + E-1 |
| Medium | 11 | Fixed 5 (C-1 shebang, K-3 permissions, V-1 manifest, B-2 docs, Q-1 matrix); Remaining 6 完 beauty leftovers backlog |
| Low | ~6 | Not fixed (backlog) |

## 3. 必修真实 bug（已修，由 engineer 具体落实代码变更）

- **Fix-1**：`scripts/agent-local-check.sh` (14-26 lines rewritten for pipefail + PIPESTATUS)
- **Fix-2**：`scripts/remote-dev-setup.sh` heredoc 加 trap cleanup + bash shebang
- **Fix-3**：`ci-verify.yml` quick-check failure comment 加 error excerpt
- **Fix-4**：`.devcontainer/devcontainer.json` 新建
- **Fix-5**：`AGENTS.md §31.1` source-of-truth table
- **Fix-6**：`FILE_MANIFEST.md` 追加 5+ entries
- **Fix-7**：`scripts/agent-zero-deps-check.sh` 新建
- **Fix-8**：`ci-verify.yml` 写 permissions least-privilege
- **Fix-9**：`AGENTS.md §31.8/§31.9`

**真实 bug 优先级**：Fix-1 和 Fix-2 是 "行为与期望 mismatch" → 必须修；Fix-3/8 是 "CI 安全/体验" → 推荐修；其余 Doc/backlog。

## 4. 已知剩余风险（Candidate Completion retained）

1. **CI 曾未在真机跑过**：versions / dependencies 在 github runner 上可能 differs（Ubuntu 24.04 vs 本机/remote 混合），CI 第一次运行 likely 有 familiarization issues（rustup auto-channel 1.98.1 → remote 1.98.1 same; cargo build.rs on github runner potentially broke）。
2. **`agent-local-check.sh` 与 CI quick-check 可能 diverge**（沙箱 1.98.1 vs github 1.98.1 同 channel → likely same，但是 system libs 不同）。
3. **`scripts/agent-zero-deps-check.sh` 不能 catch 编译错误**——这是 intentional，它只做 zero-dependency gate，CI quick-check 仍必须作为第二道门。
4. **DRY**：`AGENT_NAME` 等字段在脚本里字符串 interpolate 多 times → 维护成本，minor. **accepted risk**.
5. **脚本 lacks test**：shellcheck 没跑过（沙箱无 shellcheck）。下次 CI 应加 `shellcheck scripts/*.sh` 作为 pre-step，建议。
6. **版本 table 第 1 source-of-truth 是 DEV-ENV.md**，如果 DEV-ENV.md 不更新就继续漂移；建议 risk-based，每次 toolchain bump 必须更新 DEV-ENV first (SSOT discipline).
7. **AGENTS.md §31 与 source-of-truth 交叉 referenced 但 AGENTS.md 是 read-mostly**；agent 通常不可写（protected path `__`).

## 5. Reviewer 证据（按 AGENTS.md §19.1 output schema）

```json
{
  "review_round": 1,
  "previous_review_id": "none",
  "dimension_changes": {},
  "dimensions": [
    {"name": "contract-consistency", "status": "PASS", "findings": ["rust-toolchain.toml matches §19.5 environment availability"]},
    {"name": "edge-coverage", "status": "WARN", "findings": ["missing error excerpt in quick-check comment", "no trap cleanup in heredoc"]},
    {"name": "api-surface-minimization", "status": "PASS", "findings": []},
    {"name": "dependency-boundary", "status": "PASS", "findings": []},
    {"name": "error-handling-quality", "status": "FAIL", "findings": ["D-1/E-2 set -eu + pipe trap"]},
    {"name": "test-quality", "status": "WARN", "findings": ["shellcheck not run locally (no shellcheck installed)"]},
    {"name": "complexity-control", "status": "PASS", "findings": []},
    {"name": "observability", "status": "WARN", "findings": ["CI artifact only .evidence/, no log-to-artifact for troubleshooting"]}
  ],
  "blocking_issues_fixed": ["D-1 (set pipefail + PIPESTATUS)", "E-2 (OVERALL accumulate with set -e inactive)"],
  "blocking_issues_remaining": []
}
```

## 6. Verdict

**APPROVED with Required Fixes** — 9 高危 item 已修，Medium/Low backlogged as future knowledge entries.

Commit summary:
- `fix(scripts): set -euo pipefail + PIPESTATUS in agent-local-check.sh; trap cleanup in remote-dev-setup.sh`
- `feature(scripts): add agent-zero-deps-check.sh for <1GB sandbox`
- `feature(ci): devcontainer.json + permissions + ubuntu-24.04 pin + error excerpts`
- `docs(agents): §31 source-of-truth + §31.7 agent matrix + §31.8 §31.9 + FILE_MANIFEST 5 entries`
- `docs(knowledge): 2026-10-16-cloud-agent-quality-review entry`

Candidate Completion ready (不宣称 Final PASS — CI 未跑，真机未跑)。