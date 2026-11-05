---
doc-id: nexus-test-case-execution
layer: L2
owner: agent-c
last-verified: 2026-10-23
verified-against: 585e910
status: current
---

# 测试用例执行子系统：当前实现总结

本文总结 `engineering/nexus-harness` 中测试用例执行（场景执行）的当前实现。它是一份代码推导的参考文档，不替代 `engineering/nexus-harness/MODULE.md`、`docs/e2e-test-system-contract.md` 或 `CONTRACT-scenario-pack.md`。事实以代码为准，行号以当前 revision 为准。

## 1. 系统组成

测试执行分两层：

- 通用场景引擎，位于 `scenario.rs` 与 `scenario_cmd.rs`。它加载 `scenarios/**/*.toml`，执行命令，求值断言，输出 JSON 判定。
- 硬编码运行器，位于 `run_scenario.rs`。它是 `nexus-harness run <name>` 的进程内 E4 测试。

两层会组合。部分场景 TOML 把 `nexus-harness run <name> --json` 作为 `[when].command`，由通用引擎以子进程方式调用硬编码运行器。

## 2. 数据模型

核心结构在 `scenario.rs`：

- `Scenario`：id、subdir、title、requires_root、file_stem、platform、fixtures、command、expects、evidence_strength。
- `ScenarioExpect`：path（即 TOML 的 `field`）与 `ExpectKind`。
- `ExpectKind`：`Equals(Value)`、`OneOf(Vec<Value>)`、`NonEmpty`、`Absent`。
- `ScenarioRunReport`：verdict、failed_step、assertion、key_log_lines、duration_ms、detail。
- `ScenarioResult`：门禁聚合用的旧格式，含 id、verdict、detail。
- `ExpectFailure`：path 与 actual，用于断言失败的结构化输出。

TOML 解析规则（`load_file`）：

- `schema_version` 必须等于整数 1。缺失、等于 2 或字符串 "1" 都会返回错误。
- `id` 必填字符串。
- `title` 缺省空串。
- `requires_root` 缺省 false。
- `evidence_strength` 可选，E1 到 E5。
- `[given].platform` 可选字符串。
- `[given].fixture` 是字符串数组。非字符串项被忽略。
- `[when].command` 可选字符串。
- `[[expect]]` 每项 `field` 必填，且只能有 `equals`、`one_of`、`non_empty`、`absent` 之一。
- `requirement` 字段不被解析，只作人类可读锚点。

## 3. 场景加载

`load_all(scenarios_dir, subdirs)` 按调用方给的子目录列表扫描 `scenarios/<subdir>/*.toml`。文件按名字排序。子目录不存在时静默跳过。

扫描范围：

- `scenario list` 使用 `SCAN_SUBDIRS`，包含 product、regression、platform、engineering。
- `verify --full` 的 product-scenarios 门使用 product、engineering、platform。
- `verify --full` 的 regression 门使用 regression。

无效场景（schema_version 错误、TOML 解析失败）打印 stderr 并跳过。它们不会直接使门禁失败。这一点在第 9 节说明。

分类器：

- `scenario_requires(s)` 返回 "real-device" 或 "sandbox"。`requires_root` 为真，或 id 或 file_stem 含 realnet / real_net 时返回 "real-device"。
- `evidence_strength(s)` 显式声明 E1 到 E5 时原样返回。非法声明降级为 E1。
- `derive_evidence_strength(s)` 在缺省时推导：real-device 到 E4，有 fixture 到 E4，有 command 到 E3，静态契约到 E1。

## 4. CLI 命令面

信封与退出码在 `main.rs`：

- 输出 JSON 信封，顶层字段为 `schema_version`、`command`、`verdict`、`message`，再加命令特有字段。
- 退出码：FAIL 为 1，BLOCKED 为 2，其余为 0。

`nexus-harness scenario list`：

- 输出 `scenarios` 数组，每项 `name`、`subdir`、`summary`、`requires`。
- 除非 `setup()` 失败返回 BLOCKED，否则恒为 PASS。

`nexus-harness scenario run <id>`：

- 查找场景并执行。输出 `command`、`scenario`、`verdict`、`evidence_id`、`failure_signature`、`duration_ms`。
- verdict 映射：PASS 到 PASS，FAIL 到 FAIL，其余（含 UNKNOWN）到 BLOCKED。
- 未知 id 返回 BLOCKED，`failed_step` 为 "lookup"。

## 5. 执行引擎

`run_single_inner` 的执行顺序：

1. 平台门。`[given].platform` 与当前平台不匹配时返回 UNKNOWN，`failed_step` 为 "lookup"。
2. 静态契约。没有 `[when].command` 时返回 UNKNOWN，`failed_step` 为 "lookup"。
3. 隔离目录。创建 `std::env::temp_dir()/nexus-scenario-<id>-<pid>`，并设置 `NEXUS_CONFIG_DIR`。
4. Fixture。按序执行 `[given].fixture` 命令。任一非零退出即 FAIL，`failed_step` 为 "fixture"，`assertion` 是失败的命令文本。
5. 主命令。以 600 秒超时执行 `[when].command`，10 秒排水。
6. JSON 解析。只解析 stdout。非 JSON 返回 FAIL，`failed_step` 为 "parse"。
7. 断言求值。逐条执行 `[[expect]]`。全部通过返回 PASS。失败返回 FAIL，`failed_step` 为 "expect"，`assertion` 是字段路径。

命令执行细节（`run_checked_with_timeouts`）：

- 不经过 shell。命令用 `split_whitespace()` 切分后直接 exec。
- 程序名是 `nexus-harness` 时替换为 `current_exe()`。
- stdout 与 stderr 由两个读线程排水。这避免孤儿孙进程持有管道写端时主线程挂死。
- 轮询间隔 100 毫秒。
- 超时后 kill 子进程。
- stderr 只保留最后 8 行，且不参与 JSON 判定。

并行执行：

- `parallel_jobs()` 优先读 `NEXUS_HARNESS_JOBS` 环境变量，否则用 CPU 数，限制在 1 到 16。
- `run_parallel` 用共享队列调度，结果按声明顺序回填。worker panic 时该场景返回 FAIL，`failed_step` 为 "harness"。

## 6. 门禁与验证流程

`nexus-harness verify` 在 `commands.rs`：

- `--fast` 与 `--full` 二选一。其它用法返回 BLOCKED。
- 先跑 `whitespace` 门（硬编码），再按 `policies/quality.toml` 声明的门列表路由。
- 聚合规则：任一 FAIL 则整体 FAIL。UNKNOWN 只计数不阻塞。没有 FAIL 则 PASS。
- 写证据后回读校验。10 个 schema 必填字段任一残缺则返回 BLOCKED。

fast 门（8 个）：format、check、clippy、architecture-delta、dependency-delta、resource-type-neutrality、affected-tests、selected-properties。

full 门（14 个）：workspace-tests、integration、product-scenarios、regression、architecture-policy、dependency-governance、coverage-summary、selected-fuzz、selected-concurrency、performance-budgets、bench、platform-checks、feature-matrix、portable-core。

场景门由 `run_gate` 聚合：

- product-scenarios 跑 product、engineering、platform。
- regression 跑 regression。
- 任一场景 FAIL 则门 FAIL。没有场景文件时返回 PASS，detail 为 "no scenario files declared"。

## 7. 证据

场景证据（`scenario run`）：

- id 为 `scenario-<agent>-<hash12>` 或 `scenario-<hash12>`。
- seed 是 revision、scenario_id、configuration_digest、contract_hash 的组合哈希前 12 位。
- 写入 `.evidence/scenario-<id>/summary.json` 与 `metadata.json`。
- 不参与 STALE 扫荡，不写 `latest.json`，不影响 verify 门禁证据。

验证证据（`verify`）：

- id 为 `verify-<agent>-<hash12>` 或 `verify-<hash12>`。
- 写入 `summary.json`、`gates.json`、`metadata.json`、`latest.json`。
- summary 包含 bindings 十个字段：source_revision、working_tree_digest、dirty_state、configuration_digest、feature_set、target_triple、toolchain_version、harness_schema_version、platform_capability_digest、contract_hash。
- 同 id 不同绑定时，旧证据被重命名为 `verify-<id>-stale-*` 并标记 STALE。
- 同 agent 作用域内绑定不同的其它证据会被标记 STALE。
- `latest.json` 供 `status` 判断新鲜度。

`NEXUS_AGENT` 环境变量（净化后 1 到 32 个 `[A-Za-z0-9_-]` 字符）决定证据命名空间。不同 agent 的证据互不影响。

## 8. 硬编码运行器（run_scenario.rs）

`nexus-harness run <name>` 支持 12 个子命令：

- virtual-subnet-tunnel
- virtual-subnet-mesh
- nat-hole-punching
- multihop-routing
- mesh-dns
- dns-unified
- multipath
- firewall-rules
- bandwidth-qos
- qos-cake
- auto-reconnect
- bootstrap-join

每个运行器在进程内构建拓扑，执行确定性逻辑，用 Rust 布尔不变量判定 PASS 或 FAIL。它们不解析 JSON、不写证据、没有墙钟超时（只用假时钟）。未知子命令返回 BLOCKED。

`run_scenario.rs` 没有单元测试。这些运行器通过场景 TOML 间接覆盖，例如 `scenarios/product/auto_reconnect.toml`。

## 9. 当前实现边界

以下行为是当前实现的真实边界，不是缺陷描述，也不是契约承诺：

- `scenario list` 恒为 PASS。子目录缺失或文件无效只打印 stderr，不使命令失败。
- 无效场景被跳过，不计数为门禁失败。`load_rejects_invalid_schema_version` 测试断言的是空场景集，而不是门 FAIL。
- `scenario run` 把 UNKNOWN 映射为 BLOCKED。`run_gate` 保留 UNKNOWN，只有 FAIL 使门失败。所以静态契约不会让 verify 门失败，但 `scenario run` 对它们返回退出码 2。
- `run_scenario.rs` 的 bootstrap-join 会启动后台 pump 线程。注释说明它随进程结束，不优雅停机。该线程的 JoinHandle 被忽略。
- `replay` 命令硬编码返回 UNKNOWN。
- `performance-budgets` 门只检查 `policies/quality.toml` 的 `[performance]` 键是否存在，不实测阈值。
- 依赖外部工具的 full 门（coverage、fuzz、concurrency、bench、portable-core）在工具缺失时返回 UNKNOWN，而不是静默 PASS。

## 10. 相关文件

- `engineering/nexus-harness/src/scenario.rs`
- `engineering/nexus-harness/src/scenario_cmd.rs`
- `engineering/nexus-harness/src/run_scenario.rs`
- `engineering/nexus-harness/src/gates.rs`
- `engineering/nexus-harness/src/commands.rs`
- `engineering/nexus-harness/src/evidence.rs`
- `engineering/nexus-harness/src/env.rs`
- `engineering/nexus-harness/src/config.rs`
- `engineering/nexus-harness/src/main.rs`
- `policies/quality.toml`
- `harness.toml`
- `engineering/evidence-schema/evidence.schema.json`

## 11. 关联文档

- `engineering/nexus-harness/MODULE.md`：模块契约。
- `docs/e2e-test-system-contract.md`：E2E 测试系统契约。
- `CONTRACT-scenario-pack.md`：场景包机器接口契约。
- `docs/source-audit/05-core-platform-harness.md`：源码逆向审计。