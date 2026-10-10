# CONTRACT: Scenario Pack（场景包机器接口）

- Track：Track A（agent-pack）
- Base：73db945
- 任务类型：feature（Contract-First：契约阶段）
- 目标：把 `scenarios/` 下的产品/回归场景变成 agent 可直接调用的固定程序。
  agent 不再手写检查脚本，只调用固定命令、读机器可读结果。
- Red Evidence：`red-evidence/scenario-list-old.json`、
  `red-evidence/scenario-run-old.json`（旧实现上 `scenario` 命令组不存在，
  返回 `BLOCKED` "supported commands: ..."——无单场景机器可调用接口，
  无稳定失败签名）。

## 冻结的机器接口（字段名不可更改）

### 1. `nexus-harness scenario list --json`

```json
{"schema_version":1,"scenarios":[{"name":"product.cli-subnet","subdir":"product","summary":"...","requires":"sandbox|real-device"}]}
```

字段推导规则（冻结）：

- `name`：场景 toml 的 `id` 字段（如 `product.cli-subnet`）。
- `subdir`：`product | regression | platform | engineering`（toml 所在子目录）。
- `summary`：toml 的 `title` 字段原文。
- `requires`：启发式 v1（toml 不可改，故为推导值，未来可用 `requires` 字段精确化，
  那将是 requirement-change）：
  - 顶层 `requires_root = true` → `"real-device"`；
  - 文件 stem 或 id 含 `realnet` / `real_net` → `"real-device"`；
  - 其余 → `"sandbox"`。
- 无 `[when].command` 的静态契约场景同样列出（agent 可见但不可执行；
  `scenario run` 对其返回 `BLOCKED`）。

### 2. `nexus-harness scenario run <name> --json`

```json
{"schema_version":1,"command":"scenario run","scenario":"product.cli-subnet",
 "verdict":"PASS|FAIL|BLOCKED","evidence_id":"scenario-agent-pack-a1b2c3d4e5f6",
 "failure_signature":{"failed_step":"fixture|command|expect|parse|lookup",
 "assertion":"up.up_ok","key_log_lines":["..."]},"duration_ms":1234}
```

语义（冻结）：

- `scenario`：请求的场景 id（原样回显）。
- `verdict`：
  - `PASS`：全部 `[[expect]]` 成立；
  - `FAIL`：fixture 失败 / 命令超时或 spawn 失败 / 输出非 JSON / 任一 expect 不成立；
  - `BLOCKED`：场景 id 不存在（`failed_step="lookup"`），或静态契约无
    `[when].command` 不可执行，或证据写入失败。
- `failure_signature.failed_step` 枚举（冻结）：
  - `"fixture"`：`[given].fixture` 任一命令 exit 非 0；
    `assertion` = 失败的 fixture 命令原文；
  - `"command"`：场景命令 spawn 失败或超时；
    `assertion` = `"spawn_failed"` 或 `"timed_out"`；
  - `"expect"`：`[[expect]]` 不成立；
    `assertion` = 失败的 expect `field` path；
  - `"parse"`：命令输出不是合法 JSON；
    `assertion` = `""`；
  - `"lookup"`：场景不存在或不可执行；
    `assertion` = `""`。
- `failure_signature.key_log_lines`：与失败相关的最后 10 行日志
  （fixture 失败取 stderr 尾部；命令失败取 stdout+stderr 尾部；expect 失败取
  被判定的 JSON 输出尾部）。`PASS` 时为空数组。
- `duration_ms`：单场景执行的墙钟毫秒数（含 fixture）。
- `evidence_id`：`scenario-<agent>-<12hex>`，
  `hash(revision | scenario_id | bindings)` 前 12 hex；
  证据目录 `.evidence/scenario-<id>/summary.json`
  （`schema_version`/`command="scenario run"`/`scenario`/`verdict`/
  `failure_signature`/`duration_ms`/`bindings`）。
  场景证据**不**参与 STALE 扫荡、不写 `latest.json`（verify 门禁证据不受影响）。

## 实现约束（冻结）

- 复用 `scenario::run_gate` 的执行语义（fixture 顺序执行、有界超时、
  场景级 `NEXUS_CONFIG_DIR` 隔离、n3 contract-first 的 UNKNOWN 特例保持不变）。
- 不修改 `scenarios/product|regression|platform` 下任何 toml 的 expectation
  （Protected，AGENTS.md §7）。
- 不新增/删除场景文件；只新增 harness 命令。
- 错误用类型化 `Result`，不用 panic（AGENTS.md §18）。
- 新增 pub API 保持最小（`pub(crate)` 优先）。

## 冻结清单

- 上述两个 JSON 接口的全部字段名与枚举值；
- `requires` 启发式 v1 推导规则；
- `evidence_id` 命名与目录规则；
- Red Evidence（旧实现 BLOCKED 输出）。

## Contract Hash

哈希算法：**sha256，取 hex 前 16 位**。
（实现前由协调者/实现者计算本文件哈希并记入 commit message `contract: <hash>`）
