# nexus-auth Module Contract

## Responsibility

定义 Resource Authorization、Principal 与类型化权限判定。

## Non-Responsibilities

不负责平台 entitlement，不负责 Secret Store 实现。

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

- Publication Policy 与 Resource Authorization 分离。
- 授权失败必须结构化、可解释。

## Side Effects

- 仅允许 Responsibility 所需且在架构层中明确归属的副作用。
- 新增副作用前必须更新本契约和 Scenario/Policy（如影响外部行为）。

## Public API

### 冻结契约（remote P0，scenarios/product/remote_service_access_flow.toml）

- `pub struct PreSharedToken(pub String)`：预共享令牌（P0 门控；完整握手后置）。
- `pub struct Principal(pub String)`：认证通过后的主体标识。
- `pub fn verify_token(token: &PreSharedToken, expected: &PreSharedToken) -> Result<Principal, AuthError>`
  使用常量时间比较；失败结构化返回。
- `pub enum AuthError { Unauthorized }`

> 范围声明（N2 P0-1，D6）：`verify_token` 仅服务于冻结的 N1 remote-host
> 场景（`daemon-real-host-*`）；**N2 资源授权路径拒绝 PSK**，
> 只接受握手派生的 `Principal`。

### N2 P0-1（D6，PRODUCT §16.5）：ed25519 双向身份＋本地 grant 表

- `Principal::from_ed25519_public_key(&[u8; 32]) -> Principal`：
  `ed25519:<hex(SHA-256(pubkey)[..16])>`（与 `IdentityManager::peer_id_of` 同构）；
  调用方必须传入握手已验证的公钥，不接受请求方自称。
- `pub struct Grant { resource: ResourceRef, principal: Principal, operations: Vec<ResourceOperation>, not_after: Option<u64>, revoked: bool }`
- `pub struct GrantTable`：`upsert` / `revoke`（tombstone）/
  `authorize(&AuthRequest, now_unix, &mut dyn AuditSink) -> AuthorizationDecision`。
  判定顺序：NoSuchGrant → WrongWorkspace → Revoked → Expired → OperationNotGranted → Allow；
  每次判定 exactly-once 写审计记录。
- `pub struct AuthRequest { workspace, resource, principal, operation }`；
  `pub struct AuditRecord { at_unix, workspace, resource, principal, operation, decision }`；
  `pub trait AuditSink { fn record(&mut self, record: AuditRecord) }`（`VecAuditSink` 为测试实现；
  daemon 落盘实现在 P0-4 经 `FileKvStore::journal_append`）。
- `pub struct TrustStore` / `pub enum TrustVerdict{Trusted, UnknownFirstSeen, IdentityChanged}`：
  显式 TOFU——`check` 永不自动学习，未知节点返回 `UnknownFirstSeen` 由调用方
  提示用户确认后再 `trust`（与 N1 `IdentityManager::verify_peer` 的静默 TOFU 区分）。
- 结构化拒绝：`nexus-domain::{DenyReason, AuthorizationDecision}`。
- 本模块保持 portable、无 I/O（WASI check 覆盖）；持久化由组合根负责。

冻结语义：认证门控发生在业务帧转发之前（W7：未认证帧不得进入业务处理）；本模块纯校验、无 I/O、保持 portable（WASI check 覆盖）。

### 常规要求

- 默认最小 surface：`private -> pub(crate) -> pub`。
- Public API 变更必须保持结构化、可版本化并有调用方验证。

## Verification

最低：

```text
cargo check -p nexus-auth
cargo clippy -p nexus-auth --all-targets -- -D warnings
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
