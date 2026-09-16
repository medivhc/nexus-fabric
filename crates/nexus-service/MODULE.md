# nexus-service Module Contract

## Responsibility

实现 Service Resource 的解析、授权后的连接、connect/forward 与服务会话行为。

## Non-Responsibilities

不重复实现 Delivery/Transport。

## Inputs

- 仅接受公开类型、DTO、trait、事件或稳定协议对象。
- 输入必须可被结构化验证；不得依赖未声明的全局隐式状态。

## Outputs

- 结构化 Result / Event / DTO。
- 失败必须保留可诊断原因，不以日志文本代替错误类型。

## Allowed Dependencies

- `nexus-domain`
- `nexus-session`
- `nexus-delivery`

## Forbidden Dependencies

- `engineering/` 下的 Harness/Plugin。
- 未在 `policies/architecture.toml` 声明的 Nexus 内部 crate。
- Portable 模块中的平台专有 Framework/API。
- 通过“便利”依赖绕过公开领域边界。

## Invariants

- connect != forward。
- 外部监听必须显式授权。

## Side Effects

- 仅允许 Responsibility 所需且在架构层中明确归属的副作用。
- 新增副作用前必须更新本契约和 Scenario/Policy（如影响外部行为）。

## Public API

### 冻结契约（remote P0，scenarios/product/remote_service_access_flow.toml）

- `pub trait ServiceTransport`：注入的帧通道，避免 service -> transport 依赖边（架构允许依赖仅 domain/session/delivery）；由组合根以 transport::FrameStream 适配装配。
  - `pub fn send_frame(&mut self, payload: &[u8]) -> Result<(), ServiceError>`
  - `pub fn recv_frame(&mut self) -> Result<Vec<u8>, ServiceError>`
- `pub struct ServiceSession`：Nexus-aware Service Session（PRODUCT §3 connect 语义）。
  - `pub fn connect(transport: Box<dyn ServiceTransport>) -> Result<Self, ServiceError>`
  - `pub fn phase(&self) -> ServicePhase`
- `pub enum ServicePhase { Connecting, Active, Closed }`
- `pub enum ServiceError { Transport, Unauthorized, Closed }`

冻结语义：connect != forward（P0 只冻结 connect；forward 后置）；外部监听必须显式授权（`ServicePlanExtension.loopback_authorization_required`）。

### 常规要求

- 默认最小 surface：`private -> pub(crate) -> pub`。
- Public API 变更必须保持结构化、可版本化并有调用方验证。

## Verification

最低：

```text
cargo check -p nexus-service
cargo clippy -p nexus-service --all-targets -- -D warnings
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
