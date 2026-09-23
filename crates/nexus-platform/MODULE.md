# nexus-platform Module Contract

## Responsibility

定义 Portable Host Capability Traits：Packet Interface、Transparent Interception、Filesystem Projection、Secure Store、Lifecycle、Clock、Random、Attribution 等。

## Non-Responsibilities

不包含 Linux/Windows/macOS/Android/iOS 具体 API。

## Inputs

- 仅接受公开类型、DTO、trait、事件或稳定协议对象。
- 输入必须可被结构化验证；不得依赖未声明的全局隐式状态。

## Outputs

- 结构化 Result / Event / DTO。
- 失败必须保留可诊断原因，不以日志文本代替错误类型。

## Allowed Dependencies

- 无 Nexus 内部依赖。
- 第三方：`ring`（HKDF-SHA256 + ChaCha20-Poly1305，SecureStore 平台无关核心，
  PRODUCT §12.30；license Apache-2.0 AND ISC 在 allowlist，dependency review
  见 `policies/dependencies.toml`）。

## Forbidden Dependencies

- `engineering/` 下的 Harness/Plugin。
- 未在 `policies/architecture.toml` 声明的 Nexus 内部 crate。
- Portable 模块中的平台专有 Framework/API。
- 通过“便利”依赖绕过公开领域边界。

## Invariants

- 平台抽象必须通过 Deletion Test。
- 具体 OS 类型不得泄漏到 portable trait。

## Side Effects

- 仅允许 Responsibility 所需且在架构层中明确归属的副作用。
- 新增副作用前必须更新本契约和 Scenario/Policy（如影响外部行为）。

## Public API

- 默认最小 surface：`private -> pub(crate) -> pub`。
- Public API 变更必须保持结构化、可版本化并有调用方验证。
- 本骨架只提供最小编译锚点；业务 API 在实现阶段增量添加。

已实现（revision f8c7113+）：

- `PlatformError` 结构化平台错误：`Unavailable`（对应 PRODUCT §7 显式 Capability Unsupported）、`Io`、`NotFound`、`Invalid`；全部能力 trait 的错误从 `String` 迁移为 `PlatformError`。
- `VirtualPacketInterface`：IP 包读/写（`receive`/`send`），不含加密与建连。
- `PacketCarrier`（WireGuard `conn.Bind` 等价物）：承载传输封装帧的
  `bind`/`send_to`/`receive_into`/`local_locator`，与 VPI 解耦；加密打洞
  编排在 `nexus-connectivity` 层消费（吸收点 W2）。
- `secure_store`（PRODUCT §12.30）：machine-id 解析（32 hex → 16 字节）、
  HKDF-SHA256 密钥派生、NEXSEC1 AEAD 记录（`magic || nonce || ct || tag`）
  加解密——平台无关纯逻辑，DPAPI / machine-id 文件后端在 `nexus-platform-*`。
- `SystemProxyController`（PRODUCT §13）：snapshot/apply/refresh 当前用户的
  系统代理（WinINET）状态；具体注册表/WinINET 通知在 `nexus-platform-windows`。
- `AutostartRegistrar`（PRODUCT §13）：install/remove/status 当前用户登录自启
  条目；具体计划任务操作在 `nexus-platform-windows`。

## Verification

最低：

```text
cargo check -p nexus-platform
cargo clippy -p nexus-platform --all-targets -- -D warnings
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
