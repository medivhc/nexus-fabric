# Nexus

Nexus 是一个统一的个人动态资源运行时（Resource Fabric）以及与之配套的 Agent-Native Engineering System。

它把网络访问、Service、Workspace、Compute 与设备能力统一建模为 Resource，并通过：

```text
Resource + Intent
        ↓
Resolve Candidate Providers
        ↓
Core Planner
        ↓
Create Session
        ↓
Establish Connectivity
        ↓
Execute
        ↓
Observe + Adapt
        ↓
Persist / Recover
```

完成资源使用。

本仓库同时把“如何可靠地开发 Nexus”作为正式工程契约。Agent、Human 与 CI 共享同一套 Repository Contract、Harness、Policy、Scenario 与 Evidence。

## 入口

- [PRODUCT.md](PRODUCT.md)：用户可观察能力与失败语义。
- [ARCHITECTURE.md](ARCHITECTURE.md)：核心模型、依赖方向与不变量。
- [DEVELOPMENT.md](DEVELOPMENT.md)：开发、Contract-First、验证与 Evidence 工作流。
- [docs/PROJECT-STATUS.md](docs/PROJECT-STATUS.md)：项目当前状态（N1/N2/N3 进展、诚实边界）。
- [docs/protocols/interop/MATRIX.md](docs/protocols/interop/MATRIX.md)：出站代理协议互操作证据总表（当前五协议均 `BROKEN / NOT_USABLE`）；修复路线见 [NEXT-STEPS.md](docs/protocols/interop/NEXT-STEPS.md)。
- [docs/DEVELOPMENT-PROCESS.md](docs/DEVELOPMENT-PROCESS.md)：实际开发流程（worktree 纪律、真机验证、独立评审、模型横评）。
- [harness.toml](harness.toml)：机器可读的工程入口。
- [policies/](policies/)：架构、依赖与质量门禁。
- [scenarios/](scenarios/)：产品级 E4 场景契约。
- `crates/<crate>/MODULE.md`：局部模块契约。
- `crates/nexus-web-gateway/USER_MANUAL.md`：Nexus Web Gateway（零安装浏览器网页 SSH 终端）用户手册。
- `.evidence/`：与 revision/config/feature/target 绑定的验证证据。
- [.githooks/](.githooks/README.md)：提交/推送前的机器门禁（pre-commit / commit-msg / pre-push）。
- [.agents/skills/](.agents/skills/README.md)：项目级 Agent Skills（nexus-task / nexus-contract-first / nexus-evidence）。

## 关键原则

```text
Repository as API
Portable Core
Single Core Planner
Plan before Connectivity Establishment
Structured Concurrency
Exactly-One Terminal Outcome
Crash Consistency
Workspace Commit DAG
Semantic Portability
Evidence Before Completion
Contract First / Spec Freeze
```

## 工程完成定义

Agent 只能提交 Candidate Completion。

真正的完成必须同时满足：

```text
Product Complete
  产品可观察行为满足 PRODUCT / Scenario Contract

Engineering Complete
  当前 revision 拥有 fresh、足够强、可重放的 Evidence
```

最终 Verdict 只能由 Harness/Verifier 产生：

```text
PASS | FAIL | STALE | UNKNOWN | BLOCKED
```

## 当前目录的性质

此包是 Nexus 的“统一仓库目录契约与可编译骨架定义”，重点是固定目录、模块责任、依赖边界、Scenario、Policy 与 Harness 协议。业务实现可以逐步填充，但不能绕过这些契约。
