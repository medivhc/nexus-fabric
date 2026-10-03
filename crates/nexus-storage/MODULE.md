# nexus-storage Module Contract

## Responsibility

提供 CAS/Object/Chunk 持久化、原子元数据更新、Journal 与本地存储预算基础能力。

## Non-Responsibilities

不决定 Workspace Merge、WorkingSet 或远端 Replica 选择。

## Inputs

- 仅接受公开类型、DTO、trait、事件或稳定协议对象。
- 输入必须可被结构化验证；不得依赖未声明的全局隐式状态。

## Outputs

- 结构化 Result / Event / DTO。
- 失败必须保留可诊断原因，不以日志文本代替错误类型。

## Allowed Dependencies

- `nexus-domain`

## Forbidden Dependencies

- `engineering/` 下的 Harness/Plugin。
- 未在 `policies/architecture.toml` 声明的 Nexus 内部 crate。
- Portable 模块中的平台专有 Framework/API。
- 通过“便利”依赖绕过公开领域边界。

## Invariants

- 内容对象按 hash 寻址。
- 关键更新必须 crash-consistent。

## Side Effects

- 仅允许 Responsibility 所需且在架构层中明确归属的副作用。
- 新增副作用前必须更新本契约和 Scenario/Policy（如影响外部行为）。

## Public API

- 默认最小 surface：`private -> pub(crate) -> pub`。
- Public API 变更必须保持结构化、可版本化并有调用方验证。
- 本骨架只提供最小编译锚点；业务 API 在实现阶段增量添加。
- `FsContentStore`（C1，`fs.rs`）：落盘 CAS（`<dir>/<object-id>` 扁平布局；
  temp+fsync+rename 原子写，crash-consistent）；`stored_at` 取文件 mtime，
  供 `ReachabilityGc::sweep_older_than` 保留期使用；`delete_object` 语义与
  `InMemoryContentStore` 一致（两阶段 GC 由调用方保证）。
- `FileKvStore`（N2 P0-1，`kv.rs`，**新增；不碰 ContentStore/FNV-1a**）：
  小体量键值状态的 crash-consistent 持久化（节点身份、grant 表快照、审计日志）。
  `put` 原子写（tmp `create_new` + write + fsync(file) + rename + fsync(dir)，
  照抄 `fs.rs::atomic_write` 模式）；键文件名转义（`[A-Za-z0-9._-]` 原样、
  其余 `%XX`，防目录穿越）；`journal_append` write-ahead（`[len:u32 LE][payload]`
  + fsync，返回单调 seq）/`journal_replay`（boot 重放；尾部撕裂 → fail-closed
  `TornJournalTail`，需 `journal_discard_torn_tail` 显式丢弃）/`journal_truncate`。
  本 crate 保持 portable-core（仅 std）：目录权限收紧由调用方在平台侧做。

## Verification

### N3 持久与内容契约增补（待实现）

Task/幂等索引/pin intent 的 atomic publish 或 journal 事务由组合根通过存储适配器实现；
只有持久提交后才能 ack accepted。保留现有 torn-tail fail-closed 语义。
N3 Snapshot/Artifact 使用版本化 SHA-256 命名空间/映射，验证内容摘要和长度后发布，
不同 SHA-256 内容不能因既有 FNV ID 相同而覆盖。旧 CAS/Commit 格式保持不变。
TaskOutcome 与 pin 生命周期决策分别归 Compute/Workspace，storage 不反向依赖它们。
规范：`docs/N3-MODEL-CONTRACT.md` §3/4/6；场景 `n3-idempotency`、
`n3-artifact-resume`、`n3-gc-roots`、`n3-crash-reconcile`。

最低：

```text
cargo check -p nexus-storage
cargo clippy -p nexus-storage --all-targets -- -D warnings
```

如果该模块影响产品行为，还必须映射 Integration/Scenario Evidence。

## Performance Budget

未定义性能预算的路径不得宣称“性能完成”。进入 hot path 后必须在 Contract 中增加 baseline、noise tolerance、warning threshold 与 blocking threshold。

## Observability

稳定结构化字段优先于自由文本；如涉及 Session/Provider/Path/Workspace，应携带对应 correlation id。

## Recovery Semantics

任何持久状态或长期任务都必须定义 crash 后的 reconcile 行为。无持久状态的纯模块应保持可重建。

## Platform Constraints

平台专有代码只允许存在于 `nexus-platform-*` 或 Composition Root。Portable crate 必须通过相应 portability gate。
