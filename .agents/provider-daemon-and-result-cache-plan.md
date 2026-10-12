# Provider Daemon 与结果缓存 —— 设计与实施计划（所有者 2026-10-12 授权）

## 0. 授权范围与触发证据

所有者 2026-10-12 决定实现三件事：**跨进程/跨命令会话复用（daemon）**、**结果缓存（digest 键控，落盘在仓库外）**、
**后台 daemon 的显式生命周期（start/stop/status + idle TTL）**；并明确**不装 SCIP**（选项原话：
"daemon + 结果缓存，不装 SCIP"、"显式 start/stop/status + idle TTL"）。

提案 §11 的触发条件已满足，不是"以后可能有用"：
- rust-analyzer 冷启动是**实测瓶颈**：真仓库（47 crates）上 `symbol Task` `duration_ms=90535` 且
  `provider.ready=false`；`references` 给 `--ready-timeout-secs 300` 仍不收敛；
  夹具 workspace 上每次冷启动 15–40s（`mcp selftest --with-query` 实测 first=15591/17593ms）。
- 每次 CLI 调用都新建一个 provider 进程 ⇒ 跨命令场景（Agent 连续下钻）反复付同一笔钱。
  §Q 的 69ms 只证明**同一进程内**已复用；跨命令仍是从零开始。

同时接受提案 §11 的两条约束：
- **不新增第二套 Agent API**：Agent-facing 面只有 `nexus-harness code <verb>` 与 MCP 的 8 个只读 verb；
  daemon 的内部线协议是实现细节，不是对外契约，不暴露 raw LSP。
- SCIP/repository-wide 索引**不做**（要装外部索引器，且会引入谁都没验证过的覆盖率）。

## 1. 现在的"明确不做"要改成什么

`MODULE.md` 的「Provider Session Reuse」现在写着"明确不做：跨进程缓存、后台 daemon、socket/端口、
索引落盘，理由是不引入隐藏生命周期"。**本轮不是推翻理由，而是给理由加上护栏**：
隐藏生命周期的风险来自"谁都不知道进程在不在、谁把它停掉"，显式 `start/stop/status` + 租约文件 +
idle TTL + 可见的 `session_source` 字段正是把这件事变可见的做法。旧条目改写成"做，但按 §2–§6 的约束做"，
并把新增写副作用登记进 `FILE_MANIFEST` 的 Side Effects。

## 2. 传输与绑定（零新依赖）

- `std::net::TcpListener` 绑 **`127.0.0.1:0`**（回环 + 临时端口）。两宿主同一实现 ⇒ Windows 冒烟宿主
  也能跑完整 E4，不需要 `cfg(unix)` 分叉；**绝不绑非回环地址**，不做 TLS、不做认证体系。
- 线协议沿用 `code_intel/lsp.rs` 的 `Content-Length` 分帧实现（同一套 header/body 上限与结构化失败原因）；
  再写一个编解码器等于复制一份安全边界（round 2/3 的同类教训）。
- 租约/缓存目录：`std::env::temp_dir()/nexus-code-intel-daemon-<fnv>`，命名沿用现有
  `scratch_dir_for` 的 FNV 做法，**一律在仓库工作树之外**（`dirty_after=0` 是门禁项，不能被新功能破坏）。
- 租约文件 `lease.json`：`{pid, port, token, started_at, last_heartbeat, idle_secs, workspace_key, version}`。
  token 是**误用防护不是安全边界**，必须照此声明：文件在按用户隔离的 temp 目录里，
  而同用户下的任何进程本来就能直接跑 `nexus-harness code` —— daemon 通过内部协议能做的事
  **不多于** CLI 本来能做的事（服务端仍走同一套 verb 白名单 + 作用域 containment + 只读不变量），
  所以拿到 token 不构成提权。这一句必须写进契约，别把"看起来成功"的防护当成边界。
- **存活判定不用 pid 信号**：`kill(pid,0)` 需要 libc ⇒ 违反零新依赖。判据改为"租约里的端口能不能握手"，
  外加 `last_heartbeat` 年龄。daemon 崩溃后租约是残留文件，`status` 报 `stale_lease`，
  `stop` 只清理文件、**不去 kill 一个无法验证的 pid**。

## 3. 生命周期（显式，不自动拉起）

- 命令：`nexus-harness daemon start|stop|status|selftest [--workspace <root>] [--idle-secs N] [--max-workspaces N]`。
  默认 `idle_secs=900`、`max_workspaces=2`（超出按 LRU 关会话并**关闭其 RA 子进程**）。
- **CLI 永不自动 spawn**。查询时若无可用 daemon ⇒ 进程内冷启动并如实报
  `daemon.running=false` + `session_source="in-process"`。这条是"不隐藏生命周期"的核心。
- `start` 幂等：已有活 daemon ⇒ `PASS` + `already_running=true`，不起第二个。
- `stop` 幂等：无 daemon ⇒ `UNKNOWN` + 原因（不是 FAIL，也没假装停成功）。
- 退出路径都要回收 RA 子进程（沿用 `ProviderSession` 的 `Drop` 语义），`selftest` 里断言
  `provider_sessions_after_stop == 0`（**契约名已统一为 `sessions_after_stop`**，见
  `MODULE.md` 的 selftest 字段清单；两处漂移是独立盲评抓出来的，别再写回旧名）。
- 崩溃：daemon 死后 `status`/查询都会探到，行为回落到 in-process，且输出带
  `daemon_unavailable` 的结构化原因；**不会**让查询 hang 在超时上。

## 4. 两层"缓存"必须分开定义

- **会话层（daemon）**：真正省掉冷启动的是**常驻的 rust-analyzer 进程**，不是任何落盘文件。
  复用键沿用现有四项：解析后的 provider 二进制 + workspace 根 + provider 版本 +
  **会话建立时的 `working_tree_digest`**；指纹变化 ⇒ 重建并把原因写进
  `provider.session_invalidated_reason`。这条"宁可付冷启动也不冒充新鲜"的优先级不变。
- **结果层（落盘）**：`digest` 键控的查询结果缓存，键 =
  `(working_tree_digest, workspace 根, verb, target, provider 版本, 预算参数)`。
  只有**当前工作树指纹与键里的一致**才允许命中；每查询前后各取一次 digest 的现有检查**不因缓存放宽**。
  缓存内容受预算约束（条目数 + 字节上限 + 超限即不写并计数可见），且**不得包含源码原文**。
  命中时 `cache.tier="disk"` 且 `cache.key_digest` 必须等于 `snapshot.working_tree_digest` ——
  写成契约字段，让"拿旧指纹的结果冒充新结果"这种错法在输出里就看得见。
- 明示边界：结果层缓存的**收益未经实测**（它省的是重复查询，不是索引成本）。本轮落它，
  但验收只钉结构正确性（键绑定、命中条件、越界不命中），时延只作旁证 ——
  和 §Q 里把复用倍率降级成旁证是同一条口径。

## 5. 输出字段（契约要写可得性）

```text
daemon   {running, session_source: "daemon"|"in-process", lease_path, port, pid,
          idle_secs, already_running, stale_lease, daemon_unavailable,
          provider_sessions, provider_session_capacity}
cache    {tier: "miss"|"memory"|"disk", key_digest, entries, bytes, disabled}
provider 现有字段不变（session_reused/session_queries/session_invalidated_reason 继续有效）
```
- `daemon.running=false` 时 `port`/`pid`/`lease_path` **不出现**（不得用 `null` 或 `0` 冒充"有但不知道"）。
- 两者都属 `authority="advisory"` 的 Code Intelligence 输出，不拥有最终 PASS。

## 6. 明确不做

SCIP/repository-wide 落盘索引、多机或远程 daemon、非回环绑定、TLS 或 token 当安全边界、
自动拉起、环境变量悄悄启用、把索引或缓存写进仓库、第二套 Agent-facing API、任何新外部依赖。

## 7. 实施顺序（契约先行）

1. `MODULE.md` 新章「Provider Daemon & Result Cache」+ Public API/字段可得性 + Side Effects +
   改掉旧的"明确不做"条目；`FILE_MANIFEST` 登记新文件与写副作用。
2. 新 E4 场景（4 条）+ 跑 **Red Evidence**（`daemon` 命令不存在 ⇒ 结构化 BLOCKED/UNKNOWN）。
3. 冻结契约（记 contract hash），再实现 `code_intel/daemon.rs` + `code_intel/cache.rs` + CLI 接线。
4. 单测（纯函数优先：租约解析/握手帧/键构造/失效判定都不要网络与 RA）+ `daemon selftest` 探针；
   Windows 全套门禁 + 25 条 E4。
5. thin bundle → xc-pc-linux 结论级复跑（fmt/workspace clippy/单测/`verify --fast`/全场景），数字记 §R。
6. 独立 Review（新对象 ⇒ 3 轮预算重新起算）；`model=unbound` 照旧如实记。

## 8. 验收判据（可证伪，不靠形容词）

- 两个**不同进程**各跑一次 `code symbol`：第二条 `session_source="daemon"`、
  `status.provider_sessions=1`（不是 2），且 `daemon selftest` 的 `reuse_probe=true`。
- `daemon stop` 之后 `status.running=false` 且 `selftest` 报 `sessions_after_stop=0`。
- 未 start 时查询仍 `PASS`/照常失败，`session_source="in-process"` —— 证明没被自动拉起。
- digest 不一致 ⇒ `cache.tier="miss"` 且绝不说成 `disk`；`key_digest` 恒等于当次
  `snapshot.working_tree_digest`。
- 工作树在会话建立后被改动 ⇒ `session_invalidated_reason="digest_changed"`，结果不冒充新鲜。
- `dirty_after=0` 与"仓库内无 daemon 文件"仍然成立（租约/缓存全在 temp）。
- daemon 崩溃/租约残留 ⇒ `stale_lease=true`，查询自动回落 in-process，无 hang、无假 PASS。
