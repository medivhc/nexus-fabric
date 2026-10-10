# nexus-control-api Module Contract

## Responsibility

定义 CLI/GUI/Agent Client/SDK 使用的 Application Service 契约与稳定 DTO。

## Non-Responsibilities

不直接访问 OS、数据库、CAS、Transport、Connectivity 或平台专有 API；不承载领域算法。

## Inputs

- 仅接受公开类型、DTO、trait、事件或稳定协议对象。
- 输入必须可被结构化验证；不得依赖未声明的全局隐式状态。

## Outputs

- 结构化 Result / Event / DTO。
- 失败必须保留可诊断原因，不以日志文本代替错误类型。

## Allowed Dependencies

- `nexus-domain`
- `nexus-proto`

## Forbidden Dependencies

- `engineering/` 下的 Harness/Plugin。
- 未在 `policies/architecture.toml` 声明的 Nexus 内部 crate。
- Portable 模块中的平台专有 Framework/API。
- 通过“便利”依赖绕过公开领域边界。

## Invariants

- API 返回结构化 DTO；机器接口必须版本化。
- Application API 是前端统一入口。

## Side Effects

- 仅允许 Responsibility 所需且在架构层中明确归属的副作用。
- 新增副作用前必须更新本契约和 Scenario/Policy（如影响外部行为）。

## Public API

- 默认最小 surface：`private -> pub(crate) -> pub`。
- Public API 变更必须保持结构化、可版本化并有调用方验证。
- 本骨架只提供最小编译锚点；业务 API 在实现阶段增量添加。

已实现（revision f8c7113+）：

- `ControlCommand`：PRODUCT §8 可观察性命令（status / plan explain / session watch / connectivity / dns / workspace / compute jobs / diagnose / platform capabilities）。
- `ControlOutput` 与各 View DTO（StatusView/PlanView/SessionView/LinesView），`to_lines()` 供终端渲染。
- `ControlService` trait：前端统一入口；重导出 `NexusError`/`ResourceId`/`SessionId` 供只依赖本 crate 的前端使用。

## Verification

### N3 Application Service 契约增补（待实现）

版本化操作为 SubmitTask / GetTask / ReadTaskLogs / CancelTask / ListTaskArtifacts /
GetArtifact；统一返回 task/logs/artifact DTO 或结构化 error，不承载 TaskOwner 算法。
SubmitTaskRequest JSON 形状见 `docs/contracts/n3-task-v1.schema.json`。
principal 来自已认证调用上下文，不能由请求 DTO 自填；查询和产物获取分别鉴权。
操作 PASS 仅指正确处理请求，不表示 task.outcome=Completed；取消待确认明确输出。
TaskView.cancel_request 为来源显式的请求方 durable intent 视图；provider cancellation
只来自提供方事件，未送达取消不能改写权威状态。嵌套 DTO 继承顶层 schema_version。
任务 CLI/API 同源，LocalAPI 路由在实现批次另补契约，旧 ControlCommand 不在此删除。
规范及场景：PRODUCT §17、`docs/N3-MODEL-CONTRACT.md`、`n3-*.toml`。

最低：

```text
cargo check -p nexus-control-api
cargo clippy -p nexus-control-api --all-targets -- -D warnings
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

### N3-6 LocalAPI 协议增补

TaskRequest/TaskEnvelope 作为 POST /localapi/v1/task 的 schema1 线协议；认证 context
由 daemon token/本地身份/配置作用域构造，不反序列化任意主体。HTTP framing、
容量、错误与相关性按 docs/N3-6-LOCALAPI-SECURITY-CONTRACT.md 冻结；本 crate
仍无 OS/Transport/存储副作用，六类 DTO 不变。
