# Contract：C2 workspace sync over fabric transport

- Contract hash：`d8890ffb4510befb`（6 个场景 toml 全集 git hash-object 前 16 位）
- Red Evidence：`.evidence/red-evidence-c2-sync/RED.md`（6/6 BLOCKED）
- 冻结日期：2026-10-02
- 基座：0785939（W3 合并后本地 master）
- requirement-change 2026-10-02（Review F2）：`workspace_sync_basic.toml` 的
  `sync.fetched_commits` 1→2（genesis 按 author 区分，fresh peer 需拉取对端 genesis）。
  旧 hash `9aceea8ef2359341` 作废。

## 冻结的场景

| 场景 | 驱动命令 |
|---|---|
| product.workspace-sync-basic | `cargo run -q -p nexusd --example workspace_sync_e4 -- --scenario basic --json` |
| product.workspace-sync-over-race-path | `... --scenario race-path --json` |
| product.workspace-sync-authz | `... --scenario authz --json` |
| product.workspace-sync-conflict-converge | `... --scenario conflict-converge --json` |
| product.workspace-sync-resume | `... --scenario resume --json` |
| product.workspace-sync-shallow-sparse | `... --scenario shallow-sparse --json` |

## 冻结的语义（D1–D7）

- D1：fabric QUIC bi-stream 承载，复用 `NatSwitching::active_conn(peer)`，不另建连接；回迁点：`nexus-delivery` 建好后只换"取连接"一处（记在 `sync_transport.rs` 注释）
- D2：`WorkspaceTransport` trait 不变；fabric 适配器在 nexusd（Composition Root）；`nexus-workspace` 不新增 fabric 依赖
- D3：`STREAM_TYPE_WORKSPACE_SYNC = 0x03`；被动端按 type 路由到 `serve_sync`
- D4：`serve_sync` 前置成员授权（静态列表 v1；未授权 → 明确拒绝帧；零数据泄露；审计日志）；P2 完成前不做真机联调
- D5：OBJECT-DATA 去 hex → `OBJECT-CHUNK:{id}:{offset}:{total}\n<bytes>` + `OBJECT-END:{id}`；WANT 按需分批
- D6：非原子、幂等、可续（fetch 每批 persist；merge 逐个 persist）
- D7：先 resolve 者赢；conflict-state 交换帧；禁止双端各解各的

## 实现顺序

P1 传输适配 → P2 授权 → P3 大对象分块/续传 → P4 shallow/sparse → P5 冲突收敛
