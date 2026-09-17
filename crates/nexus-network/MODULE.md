# nexus-network Module Contract

## Responsibility

实现 InternetAccess Network Domain Runtime，消费 Policy/Plan/Session/Delivery/DNS 结果执行网络会话。

## Non-Responsibilities

不拥有 nexus-ingress；不把透明代理或 TUN 当成领域核心。

## Inputs

- 仅接受公开类型、DTO、trait、事件或稳定协议对象。
- 输入必须可被结构化验证；不得依赖未声明的全局隐式状态。

## Outputs

- 结构化 Result / Event / DTO。
- 失败必须保留可诊断原因，不以日志文本代替错误类型。

## Allowed Dependencies

- `nexus-domain`
- `nexus-policy`
- `nexus-planner`
- `nexus-session`
- `nexus-delivery`
- `nexus-dns`

## Forbidden Dependencies

- `engineering/` 下的 Harness/Plugin。
- 未在 `policies/architecture.toml` 声明的 Nexus 内部 crate。
- Portable 模块中的平台专有 Framework/API。
- 通过“便利”依赖绕过公开领域边界。

## Invariants

- nexus-network 不编译依赖 nexus-ingress。
- Ingress 与 Network Runtime 由 Composition Root 同时装配。

## Side Effects

- 仅允许 Responsibility 所需且在架构层中明确归属的副作用。
- 新增副作用前必须更新本契约和 Scenario/Policy（如影响外部行为）。

## Public API

### 冻结契约（remote P0 扩展，scenarios/product/remote_internet_access_flow.toml）

- `pub trait NetworkTransport`：注入的帧通道，避免 network -> transport 依赖边（架构允许依赖仅 domain/policy/planner/session/delivery/dns）；由组合根以 `transport::FrameStream` 适配装配。
  - `pub fn send_frame(&mut self, payload: &[u8]) -> Result<(), NetworkError>`
  - `pub fn recv_frame(&mut self) -> Result<Vec<u8>, NetworkError>`
- `pub struct NetworkSession`：InternetAccess 远程网络会话（PRODUCT §2/§6）。
  - `pub fn establish(transport: Box<dyn NetworkTransport>, request: &[u8]) -> Result<Self, NetworkError>`
    在已认证的帧通道上发送请求帧并接收响应帧；成功提取 HTTP 状态码后进入 Active。
  - `pub fn phase(&self) -> NetworkPhase`
  - `pub fn response_status(&self) -> Option<&str>`
- `pub enum NetworkPhase { Connecting, Active, Closed }`
- `pub enum NetworkError { Transport, Unauthorized, Closed }`

冻结语义：网络会话必须显式建立（establish 完成请求/响应往返后才 Active）；未通过认证的请求不得进入业务处理（W7）。

### 常规要求

- 默认最小 surface：`private -> pub(crate) -> pub`。
- Public API 变更必须保持结构化、可版本化并有调用方验证。

## Verification

最低：

```text
cargo check -p nexus-network
cargo clippy -p nexus-network --all-targets -- -D warnings
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
