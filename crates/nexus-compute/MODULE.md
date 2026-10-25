# nexus-compute Module Contract

## Responsibility

实现 Compute Resource 的能力描述、估计输入、执行会话、Workspace Snapshot Pin、Artifact 与可选 Write-back。

## Non-Responsibilities

不修改 pinned Workspace Commit；不复制 Workspace/Delivery 实现。

## Inputs

- 仅接受公开类型、DTO、trait、事件或稳定协议对象。
- 输入必须可被结构化验证；不得依赖未声明的全局隐式状态。

## Outputs

- 结构化 Result / Event / DTO。
- 失败必须保留可诊断原因，不以日志文本代替错误类型。

## Allowed Dependencies

- `nexus-domain`
- `nexus-session`
- `nexus-workspace`

## Forbidden Dependencies

- `engineering/` 下的 Harness/Plugin。
- 未在 `policies/architecture.toml` 声明的 Nexus 内部 crate。
- Portable 模块中的平台专有 Framework/API。
- 通过“便利”依赖绕过公开领域边界。

## Invariants

- Compute 优化任务总完成时间与 Intent Utility。
- Write-back 产生新 Workspace Commit。

## Side Effects

- 仅允许 Responsibility 所需且在架构层中明确归属的副作用。
- 新增副作用前必须更新本契约和 Scenario/Policy（如影响外部行为）。

## Public API

### 冻结契约（remote P0 扩展，scenarios/product/remote_compute_job_flow.toml）

- `pub trait ComputeTransport`：注入的帧通道，避免 compute -> transport 依赖边（架构允许依赖仅 domain/session/delivery/workspace）；由组合根以 `transport::FrameStream` 适配装配。
  - `pub fn send_frame(&mut self, payload: &[u8]) -> Result<(), ComputeError>`
  - `pub fn recv_frame(&mut self) -> Result<Vec<u8>, ComputeError>`
- `pub struct ComputeJobSession`：远程计算作业会话（PRODUCT §2/§6）。
  - `pub fn submit(transport: Box<dyn ComputeTransport>, job: &[u8]) -> Result<Self, ComputeError>`
    在已认证帧通道上提交作业帧并接收结果帧；响应 `OK:<result>` 提取结果后进入 Active，`REJECTED` 视为提供方拒绝。
  - `pub fn phase(&self) -> ComputePhase`
  - `pub fn result(&self) -> Option<&str>`
- `pub enum ComputePhase { Submitting, Active, Closed }`
- `pub enum ComputeError { Transport, Rejected, Closed, Protocol }`

冻结语义：作业必须显式提交（submit 完成往返后才 Active）；提供方拒绝（REJECTED）与协议未识别帧（Protocol）是可诊断失败，不得吞为成功。

### 常规要求

- 默认最小 surface：`private -> pub(crate) -> pub`。
- Public API 变更必须保持结构化、可版本化并有调用方验证。

## Verification

### N3 契约增补（待实现）

负责提供方 TaskOwner、单次执行接受/幂等/状态约束、Artifact 登记与交付语义；
请求方镜像不写权威 TaskOutcome。一个 Task 可关联多个 Session，仍只有一个真实命令启动。
Outcome、execution、delivery、取消请求及观察新鲜度分别记录；上传中断不能重跑命令。
accepted 前持久发布 Task/幂等 key/pin intent；StartIntent 崩溃窗口必须核实，未知不 spawn。
输入快照委托 Workspace；存储与受隔离进程/传输由组合根注入，不新增 storage/platform 依赖。
旧 ComputeJobSession/OK 帧往返不代表 N3 Task；保持其冻结行为。
规范：PRODUCT §17、`docs/N3-MODEL-CONTRACT.md`、N3 JSON schema。
验收：`scenarios/product/n3-*.toml`，未来 verifier 为 nexusd 的 `n3_task_e4` example，
必须编排真实产品边界，禁止合成成功结果。

最低：

```text
cargo check -p nexus-compute
cargo clippy -p nexus-compute --all-targets -- -D warnings
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

### N3-8 Session 关联事件

TaskOwner 支持 SessionAttached 事件，合法 ID、去重和连续序号由纯归约验证；接受初始 session_ids 仍为空。可信组合根在关联前核实权限、实际容量及原 SessionManager 的持久 Plan。TaskOutcome 与 SessionOutcome 分别由原 Owner 提交，不从 Session 孤儿 Failed 推断 Task 失败。详见 docs/N3-8-CAPACITY-SESSION-CONTRACT.md。
