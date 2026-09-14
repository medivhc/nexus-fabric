# Nexus Git Hooks（机器强制门禁）

将 AGENTS.md 的文本契约转化为提交/推送前的机器门禁。激活方式：

```text
Windows（PowerShell）：powershell -ExecutionPolicy Bypass -File .githooks/install.ps1
POSIX：               ./.githooks/install.sh
等价：                git config core.hooksPath .githooks
```

## 门禁与 AGENTS.md 的对应

| Hook | 检查内容 | 对应契约 |
|---|---|---|
| `pre-commit` | 暂存区 whitespace 错误；暂存含 `.rs` 时运行 `cargo fmt --check`（workspace 存在且 cargo 可用）；受保护契约路径变更告警 | §7 Protected Paths；§19 标准验证流程 |
| `commit-msg` | subject 必须为 `<type>(<scope>): <summary>`，type ∈ 任务类型表；受保护路径变更必须在正文携带 `contract: <hash>` 或 `requirement-change: <hash>` | §4 任务类型；§5 Contract-First / Contract Hash |
| `pre-push` | `nexus-harness verify --fast` 不得为 FAIL/BLOCKED；`.evidence` 中 STALE 证据阻止推送；推送区间修改受保护契约路径必须带 contract marker | §19/§20 Evidence 新鲜度；§7 受保护路径 |

共享配置与常量：`hook-common.sh`（任务类型、受保护路径模式、Contract marker 模式）。
门禁配置的机器可读声明：`harness.toml` 的 `[hooks]` 段。

## 行为语义

- **受保护路径**（`PRODUCT.md`、`ARCHITECTURE.md`、`policies/`、`scenarios/`、`harness.toml`、`*/MODULE.md`）的静默修改被阻止：`commit-msg`/`pre-push` 要求显式 Contract Hash marker。这是 §7“实现 Agent 不得静默修改受保护标准”的机器化。
- **任务类型**严格采用 AGENTS.md §4 的八类，不扩展不替换。
- **`--no-verify` 绕过**：允许，但绕过本身不产生任何证据；按 §6 不可自证原则，绕过 gate 的变更仍不得声明 Final PASS，必须由 Harness/Verifier 产生 Evidence。
- **harness 缺席时**（未安装 / 骨架实现返回 UNKNOWN），hook 记录警告但不阻塞；一旦 harness 就绪并返回 FAIL/BLOCKED，立即阻塞。
- 每个 hook 均幂等、无副作用（只读 + 退出码），可在 CI 中按同一语义复用（§3 MODULE.md：Local Harness 与 CI 使用同一 Gate 定义）。
