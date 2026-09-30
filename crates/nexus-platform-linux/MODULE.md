# nexus-platform-linux Module Contract

## Responsibility

实现 Linux 平台 Capability Adapter，包括 TUN、透明拦截、Mount/Filesystem、Service/Privilege 等宿主桥接。

## Non-Responsibilities

不依赖 higher-level domain runtime，不包含业务策略。

## Inputs

- 仅接受公开类型、DTO、trait、事件或稳定协议对象。
- 输入必须可被结构化验证；不得依赖未声明的全局隐式状态。

## Outputs

- 结构化 Result / Event / DTO。
- 失败必须保留可诊断原因，不以日志文本代替错误类型。

## Allowed Dependencies

- `nexus-platform`

## Forbidden Dependencies

- `engineering/` 下的 Harness/Plugin。
- 未在 `policies/architecture.toml` 声明的 Nexus 内部 crate。
- Portable 模块中的平台专有 Framework/API。
- 通过“便利”依赖绕过公开领域边界。

## Invariants

- 只实现 nexus-platform capability traits。

### OS 装配不变量（O1–O6，feature/os-assemble）

- **O1（事务性）**：`apply()` 前必须拍快照（地址+路由）；任一步失败 →
  自动 `rollback()` 到快照；`rollback()` 本身失败 → 返回类型化错误并告警，
  不静默吞掉。
- **O2（退出清理）**：正常退出 / 收到 SIGTERM / SIGINT →
  清理本进程创建的地址和路由；`Drop` 不足以保证（kill -9），文档明确说明
  kill -9 无法清理。
- **O3（SSH 保护）**：默认不开 default-route；开启 default-route 必须显式
  双标志 `--default-route --yes-i-know`，且文档警告丢 SSH 风险。
- **O4（干跑）**：`--dry-run` 下零 netlink 写操作，只输出计划。
- **O5（幂等）**：重复 `apply()` 不产生重复路由/地址（先查已存在）。
- **O6（可观测）**：操作日志（`os_assemble.log`）+ 计数器。

## Side Effects

- 仅允许 Responsibility 所需且在架构层中明确归属的副作用。
- 新增副作用前必须更新本契约和 Scenario/Policy（如影响外部行为）。

## Public API

- 默认最小 surface：`private -> pub(crate) -> pub`。
- Public API 变更必须保持结构化、可版本化并有调用方验证。
- 本骨架只提供最小编译锚点；业务 API 在实现阶段增量添加。

## Verification

最低：

```text
cargo check -p nexus-platform-linux
cargo clippy -p nexus-platform-linux --all-targets -- -D warnings
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
