# Nexus Git Hooks（机器强制门禁）

将 AGENTS.md 的文本契约转化为提交/推送前的机器门禁。激活方式：

```text
Windows（PowerShell）：powershell -ExecutionPolicy Bypass -File .githooks/install.ps1
POSIX：               ./.githooks/install.sh
安装范围：            当前 worktree（extensions.worktreeConfig + core.hooksPath）
```

## 门禁与 AGENTS.md 的对应

| Hook | 检查内容 | 对应契约 |
|---|---|---|
| `pre-commit` | 暂存区 whitespace 错误；暂存含 `.rs` 时运行 `cargo fmt --check`（workspace 存在且 cargo 可用）；受保护契约路径变更告警 | §7 Protected Paths；§19 标准验证流程 |
| `commit-msg` | subject 必须为 `<type>(<scope>): <summary>`，type ∈ 任务类型表；受保护路径变更必须在正文携带 `contract: <hash>` 或 `requirement-change: <hash>` | §4 任务类型；§5 Contract-First / Contract Hash |
| `pre-push` | 当前 worktree `cargo run -p nexus-harness -- verify --fast` 必须返回 PASS；`.evidence` 中 STALE 证据阻止推送；推送区间修改受保护契约路径必须带 contract marker | §19/§20 Evidence 新鲜度；§7 受保护路径 |

共享配置与常量：`hook-common.sh`（任务类型、受保护路径模式、Contract marker 模式）。
门禁配置的机器可读声明：`harness.toml` 的 `[hooks]` 段。

## 行为语义

- **受保护路径**（`PRODUCT.md`、`ARCHITECTURE.md`、`policies/`、`scenarios/`、`harness.toml`、`*/MODULE.md`）的静默修改被阻止：`commit-msg`/`pre-push` 要求显式 Contract Hash marker。这是 §7“实现 Agent 不得静默修改受保护标准”的机器化。
- **任务类型**严格采用 AGENTS.md §4 的八类，不扩展不替换。
- **`--no-verify` 绕过**：允许，但绕过本身不产生任何证据；按 §6 不可自证原则，绕过 gate 的变更仍不得声明 Final PASS，必须由 Harness/Verifier 产生 Evidence。
- **Harness 执行**：通过 Cargo 运行当前 worktree 的源码；构建、执行失败，或 Fast 未返回 PASS，均阻塞。PATH 上的旧 Harness 不被选用。
- Cargo 子进程清除 `git rev-parse --local-env-vars` 列出的变量；hook 自己保留 Git index/HEAD，以支持 alternate index。调用者的配置、token、runtime、PATH 和显式自定义 target 保持原值；linked worktree 继承主仓库默认 target 时重定向到当前 worktree/target。
- 安装仅设置当前 worktree 的 hooksPath，不覆盖共享/主仓库的 hooksPath。启用 worktreeConfig 前若存在共享 core.worktree 或 core.bare=true，拒绝自动迁移并提示 git help worktree。
- 运行 Cargo 会写构建缓存，Fast 会写 Evidence；不修改业务源码、Git index/HEAD，也不激活全局环境。
- `python3 .githooks/tests/test_hooks.py` 是假工具单元夹具，不代表实际 Fast 通过。实际门禁应另行执行并保存 Evidence。
