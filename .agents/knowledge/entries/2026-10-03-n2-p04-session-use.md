---
id: n2-p04-session-use
date: 2026-10-03
module: nexus-session, nexus (apps)
category: implementation-pattern
task_type: feature
---

# N2 P0-4：SessionManager + nexus use 四步闭环

## 问题/模式描述

N2 P0-4 在 `crates/nexus-session` 实现 `SessionManager`（Owner 模型，D1），
在 `apps/nexus` 实现 `nexus use <name>` 四步闭环
（resolve → plan → authorize → establish，D4），并修正终态语义
（断开 ≠ Failed，D7）。

## 关键设计决策

### SessionManager 在组合根，不进 nexus-session 的依赖边界之外

`SessionManager` 持有 `Box<dyn SessionRecordStore>`（持久化 trait），
但四步闭环编排（resolve→plan→authorize→establish）**放在 `apps/nexus`
（组合根），不进 `nexus-session`**。原因：`policies/architecture.toml`
规定 `nexus-session` 只能依赖 `nexus-domain`；闭环需要 planner、
registry、auth grant 表——这些依赖只能在组合根层组合。

### KvSessionRecordStore 用 Arc<FileKvStore> 而非借用

`SessionManager` 的 `Box<dyn SessionRecordStore>` 隐含 `'static` bound；
`KvSessionRecordStore<'a>` 借用 `&FileKvStore` 进不了 Box。
解法：`N2Store` 内部持 `Arc<FileKvStore>`，子存储（sessions/audit_sink）
返回 owned 值。教训：设计持久层句柄时，若最终要装入 trait object，
从一开始就用 `Arc` 共享，别用借用。

### plan_id 稳定 = D3 确定性免费验证

`nexus use dev-svc` 产出的 `plan_id`（`fc4a6ffd`）与
`nexus plan dev-svc` 预览的 `plan_id` 完全一致——同一输入同一 plan，
D3 确定性在真机输出上直接可验证，无需额外测试。

### D2 例外：AUTH_GRANT/AUTH_REVOKE 的 ResourceRef

契约张力裁决：**契约文本补例外，不改帧为 ResourceId**。
D2"人类可读名不出传输层"约束的是**寻址/查询路径**
（`ResourceQuery` 只带不透明 `ResourceId`，测试锁定）；
`AuthGrant`/`AuthRevoke` 是**提供方→请求方**的授权状态公告，
`ResourceRef` 是提供方命名空间内的 grant 表键（人类可运维），
请求方只做本地关联、不做地址解析。
文档在 `control_frame.rs`（`GrantAnnouncement`）+ `nexus-registry/MODULE.md`，
测试 `auth_revoke_carries_provider_namespaced_ref_exception` 锁定边界。

### Unfinished vs Failed（D7）

`note_client_detached`（attach window 内）→ 保持 Active/Unfinished；
`note_provider_lost` → Failed；`close`/`note_revoked` → Cancelled。
`TerminalOutcome` 唯一写入者仍是 `SessionManager`（经 `SessionOwner::commit_outcome`）。

## 可复用要点

- `save_names` 是全量覆盖语义——publish 时先 `load_names` 合并再写回。
- 名字表条目持久化 kind（`NameEntry.kind: Option<ResourceKind>`），
  解码时 `None` 默认 Service（向后兼容）。
- `nexus resource publish` 需要 `nexus node init` 先行（provider 身份）；
  未 init 时返回结构化 `NO_IDENTITY`，不静默失败。
- daemon 的 SessionManager 装配在 `nexusd::assembly::assemble_n2_session_manager`
  （§15 顺序：load → journal replay → reconcile → 持有实例）；
  存储打不开时降级为 None，不阻塞 daemon 启动（P0-4 无 daemon 侧建 Session 流量）。
