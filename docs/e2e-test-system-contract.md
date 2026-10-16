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
| `schema_version` | int | 是 | 固定 1，非 1 时拒绝加载（`scenario.rs:62`） |
| `id` | string | 是 | 全局唯一，`<subdir>.<name>` |
| `title` | string | 否 | 人类可读描述，缺省空串 |
| `requires_root` | bool | 否 | 顶层字段（不在 `[given]` 内），缺省 false；true→`real-device` |
| `evidence_strength` | string | 否 | E1–E5；缺省/非法时由 `evidence_strength()` 推导或 fail-safe 降 E1 |
| `[given].platform` | string | 否 | 平台声明（如 `windows`/`linux`） |
| `[given].fixture` | string[] | 否 | E4 夹具命令，按序执行，任一失败→FAIL |
| `[when].command` | string | 否 | 被测命令；缺省→静态契约（UNKNOWN） |
| `[[expect]]` | array | 否 | 断言：`equals` / `one_of` / `non_empty`；缺省→仅命令 smoke |
| `requirement` | string | 否 | 文档标注（指向 PRODUCT.md 锚点），**parser 不解析**，仅供人类阅读 |

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

**场景失败步骤枚举**（`ScenarioRunReport.failed_step`，`scenario.rs`）：

| 值 | 含义 |
|----|------|
| `""` | 未失败 |
| `fixture` | `[given].fixture` 某条命令非 0 |
| `command` | 主命令 spawn 失败 / 超时 / 非 0 |
| `expect` | 某条 `[[expect]]` 断言不成立 |
| `parse` | 命令 stdout 非合法 JSON |
| `lookup` | `scenario run <id>` 未找到该 id |

**evidence 校验的 BLOCKED 路径**：`verify` 回读刚落盘的 evidence，核对
`evidence.schema.json` 的 10 个 required 字段全部被真实填充；残缺即返回
`BLOCKED`（fail-closed，宁堵一次验证也不放行绑定不全的证据——STALE 判定
依赖这些绑定字段）。

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
| `check` | workspace 级 `cargo check --workspace --all-targets`（`gates.rs:254`） | PASS/FAIL |
| `test affected` | 受影响 crate 的测试 | PASS/FAIL |
| `verify --fast` | 快速门禁（format/check/clippy/affected-tests） | PASS/FAIL |
| `verify --full` | 全量门禁（+workspace-tests/integration/product-scenarios/regression） | PASS/FAIL |
| `explain` | 解释**最新一次 evidence 的 gates 判定**（无参数；非 PRODUCT.md 锚点查询，`commands.rs:383`） | PASS |
| `bench` | 基准测试 | PASS/FAIL |
| `replay <id>` | 回放历史 evidence | UNKNOWN（未实现） |

### 5.3 场景子命令（`scenario_cmd.rs`）

| 命令 | 用途 | 判定值 |
|------|------|--------|
| `scenario list` | 列出全部场景（输出字段：`name`/`subdir`/`summary`/`requires`，`scenario_cmd.rs:51`） | PASS |
| `scenario run <id>` | 单场景执行，输出失败签名 | PASS/FAIL/UNKNOWN/BLOCKED |

## 6. 示例（可直接使用）

### 6.1 场景 TOML（最小可运行）

> 注意：`[when].command` 由 `split_whitespace()` 切分后**直接 exec，不经 shell**
> （`scenario.rs:374-383`），因此**不支持 shell 引号/重定向/管道**。输出 JSON
> 用 `printf %s <json>`，不要用 `echo '<json>'`（单引号会被当字面字符输出，
> 导致 JSON parse FAIL）。需要复杂逻辑时写临时脚本再调 `sh <script>`。

```toml
schema_version = 1
id = "product.echo-json"
title = "E2E 最小场景：printf 输出 JSON 并校验"
evidence_strength = "E3"

[given]
fixture = ["printf %s ready"]

[when]
command = "printf %s {\"verdict\":\"PASS\",\"n\":1}"

[[expect]]
field = "verdict"
equals = "PASS"

[[expect]]
field = "n"
equals = 1
```

### 6.2 evidence JSON

> 对应 `engineering/evidence-schema/evidence.schema.json`：`schema_version`
> 是 `const: 1` 的**整型**（不是字符串）；`checks[]` 每项必填 `id` + `status`，
> 可选 `duration_ms` / `artifact` / `message`；顶层 `additionalProperties: false`。

```json
{
  "schema_version": 1,
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