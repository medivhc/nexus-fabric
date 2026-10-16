# E2E 测试系统契约

> PEE stage-200 产物。单一评分源：`references/rubric.md`（阶段 200 阈值 80）。

## 1. 系统边界

```
┌─────────────────────────────────────────────────────────┐
│                    E2E 测试系统                          │
│                                                         │
│  驱动源   policies/quality.toml（声明 gates）            │
│  入口     nexus-harness verify --full                    │
│  场景层   scenarios/<subdir>/*.toml                     │
│  证据层   .evidence/ + engineering/evidence-schema/      │
│  报告层   .pee/runs/<run-id>/logs/ + reports/          │
└─────────────────────────────────────────────────────────┘
```

## 2. 场景契约（Scenario Contract）

每个场景是 `scenarios/<subdir>/<name>.toml`，字段：

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `schema_version` | int | 是 | 固定 1 |
| `id` | string | 是 | 全局唯一，`<subdir>.<name>` |
| `title` | string | 否 | 人类可读描述 |
| `evidence_strength` | string | 否 | E1–E5 |
| `requirement` | string | 否 | 指向 PRODUCT.md 锚点 |
| `[given]` | table | 是 | 环境声明 |
| `[given].fixture` | string[] | 否 | E4 夹具命令，按序执行，任一失败→FAIL |
| `[when].command` | string | 是 | 被测命令；缺省→静态契约（UNKNOWN） |
| `[[expect]]` | array | 是 | 断言：`equals` / `one_of` / `non_empty` |

## 3. 分层证据模型

| 层 | 强度 | 说明 | 谁产出 |
|----|------|------|--------|
| E1 | 单元断言 | `cargo test` | Executor |
| E2 | 集成断言 | `cargo test -p <pkg> --test <name>` | Executor |
| E3 | 沙箱场景 | `nexus-harness verify --full` 的 product-scenarios gate | Executor |
| E4 | 真机/隔离环境 | scenario + fixture，离线可复现 | Executor |
| E5 | 外部观察 | 真实公网/真实设备，冻结在 P3 | 人工/外部 |

## 4. 契约一致性规则

1. `scenarios/` 是受保护路径（AGENTS.md §7），修改需 `contract:` 或 `requirement-change:` marker。
2. Scenario expectation 不得为迎合实现而静默修改。
3. `verify --full` 的 `product-scenarios` gate 并行跑全部 product/engineering/platform 场景。
4. 未实现的 gate 记 UNKNOWN，不静默跳过。
5. 场景文件必须声明 `schema_version = 1`（缺省或非 1 时 `load_all` 拒绝加载并打印诊断，不静默丢弃）。

## 4b. 判定值枚举（verdicts）

来自 `harness.toml [evidence].verdicts`，契约侧显式声明：

| 判定值 | 含义 | 门控行为 |
|--------|------|----------|
| `PASS` | 全部 expect 通过 | 不阻塞 |
| `FAIL` | expect 失败 / 夹具失败 / 命令非 0 | 门禁 FAIL |
| `UNKNOWN` | 平台不匹配 / 静态契约无 `[when].command` / gate 未实现 | 记录但不阻塞 |
| `BLOCKED` | 场景未找到 / 用法错误 / n3 contract-first 未实现 | 门禁 FAIL |
| `STALE` | 证据与当前 revision 不匹配 | 推送被阻断（`harness.toml [hooks.verify]`） |

## 5. 接口契约（E2E 系统对外）

### 5.1 主入口

| 项 | 内容 |
|----|------|
| 命令 | `nexus-harness verify [--fast\|--full]` |
| 输入 | `policies/quality.toml` 声明的 gates |
| 输出 | JSON evidence（`engineering/evidence-schema/evidence.schema.json`） |
| 契约哈希 | 受保护路径变更时由 `contract:` marker 携带 |
| 版本 | 由 `AGENTS.md §31.7` 单一真值确定（`rust-toolchain.toml` 为机器可读镜像） |

### 5.2 同级命令接口（`commands.rs`）

| 命令 | 用途 | 判定值 |
|------|------|--------|
| `status` | 工作区状态摘要 | PASS |
| `context <target>` | 最小上下文（契约→实现） | PASS |
| `check` | 受影响 crate 的 `cargo check --all-targets` | PASS/FAIL |
| `test affected` | 受影响 crate 的测试 | PASS/FAIL |
| `verify --fast` | 快速门禁（format/check/clippy/affected-tests） | PASS/FAIL |
| `verify --full` | 全量门禁（+workspace-tests/integration/product-scenarios/regression） | PASS/FAIL |
| `explain <anchor>` | 解释 PRODUCT.md 锚点的实现位置 | PASS |
| `bench` | 基准测试 | PASS/FAIL |
| `replay <id>` | 回放历史 evidence | UNKNOWN（未实现） |

### 5.3 场景子命令（`scenario_cmd.rs`）

| 命令 | 用途 | 判定值 |
|------|------|--------|
| `scenario list` | 列出全部场景（id/subdir/summary/requires） | PASS |
| `scenario run <id>` | 单场景执行，输出失败签名 | PASS/FAIL/UNKNOWN/BLOCKED |

## 6. 示例（可直接使用）

### 6.1 场景 TOML（最小可运行）

```toml
schema_version = 1
id = "product.echo-json"
title = "E2E 最小场景：echo 输出 JSON 并校验"
evidence_strength = "E3"
requirement = "PRODUCT.md#00-echo"

[given]
fixture = ["echo ready"]

[when]
command = "echo '{\"verdict\":\"PASS\",\"n\":1}'"

[[expect]]
field = "verdict"
equals = "PASS"

[[expect]]
field = "n"
equals = 1
```

### 6.2 evidence JSON（`engineering/evidence-schema/evidence.schema.json` 子集）

```json
{
  "schema_version": "1",
  "verification_id": "product.echo-json",
  "verdict": "PASS",
  "source_revision": "abc123def456",
  "working_tree_digest": "sha256:...",
  "configuration_digest": "sha256:...",
  "feature_set": ["001-e2e-contract-schema"],
  "target_triple": "x86_64-unknown-linux-gnu",
  "toolchain_version": "1.98.1",
  "checks": [
    {"id": "echo-json.expect.verdict", "status": "PASS", "duration_ms": 12}
  ]
}
```

## 7. 阈值

| 阶段 | 阈值 | 说明 |
|------|------|------|
| 200 | 80 | 契约完整性 |
| 310 | 70（通过率须 100%） | 单元测试 |
| 500 | 100 | 数据层 |
| 600/610 | 90 | 前端 |
| 700 | 90 | 联调 |