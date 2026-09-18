# nexus-connectivity Module Contract

## Responsibility

提供 Connectivity Evaluation、Link Establishment、NAT Traversal、Hole Punching、Assisted/Relay Fallback 与 Link State。

## Non-Responsibilities

不选择业务 Resource Provider，不拥有 Workspace/Compute 业务策略。

## Inputs

- 仅接受公开类型、DTO、trait、事件或稳定协议对象。
- 输入必须可被结构化验证；不得依赖未声明的全局隐式状态。

## Outputs

- 结构化 Result / Event / DTO。
- 失败必须保留可诊断原因，不以日志文本代替错误类型。

## Allowed Dependencies

- `nexus-delivery`
- `nexus-platform`

## Forbidden Dependencies

- `engineering/` 下的 Harness/Plugin。
- 未在 `policies/architecture.toml` 声明的 Nexus 内部 crate。
- Portable 模块中的平台专有 Framework/API。
- 通过“便利”依赖绕过公开领域边界。

## Invariants

- Evaluation 是低成本规划输入；Establishment 只在 Plan/Session 之后触发。
- 连接失败报告事实，由 Core Planner 决定替代 Plan。
- 双 trait 解耦（W2）：本层消费 `VirtualPacketInterface`（IP 包）与
  `PacketCarrier`（承载帧）两个独立注入 trait，只编排不实现。
- 认证门控（W7）：`send_frame(authenticated=false)` 直接拒绝，且不触碰
  carrier（未认证零发送、不改 Locator）。

## Side Effects

- 仅允许 Responsibility 所需且在架构层中明确归属的副作用。
- 新增副作用前必须更新本契约和 Scenario/Policy（如影响外部行为）。

## Public API

- 默认最小 surface：`private -> pub(crate) -> pub`。
- Public API 变更必须保持结构化、可版本化并有调用方验证。
- 已实现（阶段 B）：
  - `ConnectivityState`：NotAttempted / Establishing / Established{authenticated} / Failed{error}；
  - `EstablishmentRequest`（领域中立：session_tag + locator + 认证门控）；
  - `establish`：确定性纯函数（零 I/O），空 locator → InvalidLocator；`require_authenticated` 未认证 → AuthenticationRequired（W12，绝不进入 Established）；
  - `ConnectivityEvent` 序列（Establishing / Authenticated / Established / Failed）供 Owner 消费；
  - `ConnectivityError` 结构化错误面（delivery 层自持，不依赖领域错误）。
- 已实现（W2/W7 双 trait 编排）：
  - `ConnectivityRuntime`：注入 `Box<dyn VirtualPacketInterface>` +
    `Box<dyn PacketCarrier>`，提供 `bind_local` / `send_frame`（认证门控）/
    `receive_frame` / `read_ip_packet` / `write_ip_packet` / `local_locator`；
  - `ConnectivityError::Io` / `Invalid` 变体：`PlatformError` 结构化映射
    （保留 operation/message，不丢诊断原因）。

### 冻结契约（remote NAT/Relay P0，scenarios/product/remote_nat_relay_fallback_flow.toml）

- `LinkKind { Direct, Relay }`：候选链路类型（v9 §239：Direct 含 LAN/IPv6/Public Endpoint，Relay 为 DERP 类中继）。
- `LinkCandidate { kind, locator, setup_cost_ms }`：领域中立候选链路（激活顺序输入）。
- `trait LinkProbe { fn probe(&self, candidate: &LinkCandidate) -> Result<(), String> }`：
  候选可达性探测，由 Composition Root 以真实 I/O 实现；Connectivity 只做策略编排，零 I/O。
- `LinkActivationEvent { Attempting{kind,locator}, AttemptFailed{kind,locator,reason}, Established{kind,locator} }`：
  激活过程结构化事件（Worker 只发事件）。
- `LinkSelection { kind, locator, events }`：激活结果（选中链路 + 完整事件序列，可重放）。
- `LinkActivator<P: LinkProbe>`：`new(probe)` / `activate(direct: &LinkCandidate, relay: Option<&LinkCandidate>, require_authenticated: bool, authenticated: bool) -> Result<LinkSelection, ConnectivityError>`。
  激活顺序（v9 §243 P0 子集）：Direct 探测成功即选 Direct；Direct 失败且 Relay 可用 -> Relay 回退；
  全部失败 -> `NoLinkAvailable`；认证门控（W12）在**任何探测之前**拦截（未认证零探测、零发送）。
- `ConnectivityError` 新增变体：`NoLinkAvailable { attempted: Vec<LinkKind> }`。

冻结语义：激活失败只报告事实，不替换业务 Provider（由 Core Planner 生成替代 Plan）；
`activate` 是确定性策略编排（探测结果来自注入的 `LinkProbe`，不自行发起网络 I/O）；
NAT/中继场景的物理建连（组合根 transport::connect）发生在激活决策之后。

### 冻结契约（OutboundAdapter 接缝，PRODUCT §11.6）

- `trait OutboundAdapter`：一种真实出站协议实现（Direct / Relay / Shadowsocks）的领域中立接缝：
  - `fn outbound_kind(&self) -> &'static str`（"direct" / "relay" / "shadowsocks"）；
  - `fn tag(&self) -> &str`；
  - `fn handoff(&self, locator: &str) -> Result<OutboundHandoff, ConnectivityError>`（离线交接，零真实网络）。
- `OutboundHandoff { kind, tag, locator }`：离线交接结果 DTO。
- Deletion Test（AGENTS.md §12）成立：Shadowsocks 是首个带真实 AEAD 加解密的出站，与仅做
  可达性探测的 Direct/Relay 构成独立变化维度；DirectAdapter / RelayAdapter 复用既有
  `LinkProbe` 语义，`LinkActivator` / `LinkKind` / `LinkProbe` / `LinkSelection` 既有行为不变。
- trait 保持领域中立、可移植；具体 AEAD 加密实现位于 `nexus-outbound-shadowsocks`（portable=false）。

## Verification

最低：

```text
cargo check -p nexus-connectivity
cargo clippy -p nexus-connectivity --all-targets -- -D warnings
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
