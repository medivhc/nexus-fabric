# nexus-registry Module Contract

## Responsibility

维护 Resource、Provider、Node、Presence、Capability 与 Locator 的可查询注册视图。

N2 P0-2 增补：
- Provider 广告（`ProviderAdvertisement`）的发布 / 查询 / TTL / 可见性
  （D2 契约三件套：双层授权字段 `discoverable_by` vs `use_grants`、
  三种不可用原因 `UnavailabilityReason`、过期广告拒绝 `AdvertisementExpired`）；
- N2 控制面 5 种帧（`ControlFrame`：RESOURCE_ANNOUNCE / RESOURCE_QUERY /
  AUTH_GRANT / AUTH_REVOKE / LEASE_RENEW）的 wire 编解码（显式 u8 类型前缀，
  不靠首字节猜）与已认证通道（`ControlChannel`；认证走既有门控，
  本模块不另起第二套认证路径）；
- 本地资源名字表（`LocalNameTable`：`ResourceRef{workspace, name}` 本地解析为
  不透明 `ResourceId`；名字不进广告传输）；
- 静态 Provider 配置导入（`StaticProviderEntry` → 广告；P0 static 先行，
  mDNS/LSA 的 Provider 广播是 P0 红线，不做）。

## Non-Responsibilities

不执行 Bootstrap 网络发现，不负责 Planner 评分，不建立 Link。

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

- Registry 保存事实与广告，不保存业务评分。
- Node Identity 与 Locator 分离。

## Side Effects

- 仅允许 Responsibility 所需且在架构层中明确归属的副作用。
- 新增副作用前必须更新本契约和 Scenario/Policy（如影响外部行为）。

## Public API

- 默认最小 surface：`private -> pub(crate) -> pub`。
- Public API 变更必须保持结构化、可版本化并有调用方验证。
- 本骨架只提供最小编译锚点；业务 API 在实现阶段增量添加。

N2 P0-2 增补（`contract: e02ef53829a39d4cada00266afa46ee87f6539364185b177888a43a4a2c9949f`）：
- `advertisement`：`ProviderAdvertisement`（v9 §6 最小字段集＋D2 三件套）、
  `Discoverability::{Public, Restricted}`、`UsageGrant`、
  `UnavailabilityReason::{ProviderOffline, HealthDegraded, NotAcceptingWork}`
  （`as_str()` 拼写与 `n2-provider-offline` 冻结期望一致）、
  `RegistryError::AdvertisementExpired`、`LocalNameTable`、
  `StaticProviderEntry`；
- `Registry` 新增：`publish_ad`（过期拒绝）/ `withdraw_ad` /
  `lookup_ads` / `lookup_visible_ads` / `purge_expired_ads` /
  `advertisement_count` / `import_static`；
- `control_frame`：`ControlFrame`（5 种）、`GrantAnnouncement`、
  `encode_control_frame` / `decode_control_frame`（u8 显式类型前缀）、
  `FrameCodecError`（类型化）、`ControlTransport`（组合根以
  `nexus_transport::FrameStream` 适配）、`AuthenticatedPeer`、
  `ControlChannel::established`（构造即要求已认证对端）、`ChannelError`。

N2 P0-4 增补（契约张力裁决：AUTH_GRANT/AUTH_REVOKE 的 `ResourceRef`）：
- 决议：**契约文本补例外**（不改帧为 `ResourceId`）。
- D2"人类可读名不出传输层"约束的是**寻址/查询路径**（请求方不得把人类可读名
  当地址发送；`ResourceQuery` 只带不透明 `ResourceId`，`human_readable_name_never_goes_on_wire`
  测试锁定）。`AuthGrant`/`AuthRevoke` 是**提供方→请求方**的授权状态公告，
  其 `ResourceRef` 为提供方命名空间内的 grant 表键（人类可运维），非地址解析键；
  请求方只做本地关联（经广告通道已持有的 `ResourceId` 映射），不做地址解析。
- 否决"改用 `ResourceId`"的理由：提供方 grant 表本就以 `ResourceRef` 为键，
  强行换 Id 需提供方维护其没有的反向映射，且割裂人类可运维的 grant 管理与线上传告。
- 详见 `control_frame.rs` 中 `GrantAnnouncement` 的 D2 例外文档。

## Verification

最低：

```text
cargo check -p nexus-registry
cargo clippy -p nexus-registry --all-targets -- -D warnings
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
