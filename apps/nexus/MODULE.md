# nexus Module Contract

## Responsibility

用户 CLI 前端，仅负责参数解析、调用 nexus-control-api 与渲染结构化结果。

## Non-Responsibilities

不承载可复用核心领域逻辑；可复用逻辑必须下沉到对应 crate。

## Inputs

- 仅接受公开类型、DTO、trait、事件或稳定协议对象。
- 输入必须可被结构化验证；不得依赖未声明的全局隐式状态。

## Outputs

- 结构化 Result / Event / DTO。
- 失败必须保留可诊断原因，不以日志文本代替错误类型。

## Allowed Dependencies

- `nexus-control-api`

## Forbidden Dependencies

- `engineering/` 下的 Harness/Plugin。
- 未在 `policies/architecture.toml` 声明的 Nexus 内部 crate。
- Portable 模块中的平台专有 Framework/API。
- 通过“便利”依赖绕过公开领域边界。

## Invariants

- 该 app 只承担前端或 Composition Root 角色。
- 不得让 production crate 反向依赖 app。

## Side Effects

- 仅允许 Responsibility 所需且在架构层中明确归属的副作用。
- 新增副作用前必须更新本契约和 Scenario/Policy（如影响外部行为）。

## Public API

- 默认最小 surface：`private -> pub(crate) -> pub`。
- Public API 变更必须保持结构化、可版本化并有调用方验证。
- 本骨架只提供最小编译锚点；业务 API 在实现阶段增量添加。

已实现（骨架声明 revision f8c7113+；observability v1 落地于 2909f69 之后）：

- §9 可观察性命令（PRODUCT.md#9-observability，`observability` 模块，结构化 JSON 快照）：
  - 可用命令：`status` / `plan explain` / `session watch` / `connectivity status` /
    `dns status` / `dns cache` / `workspace heads` / `workspace conflicts` /
    `compute jobs` / `diagnose` / `platform capabilities`。
  - dns 命令挂 `nexus-dns` `DnsRuntime` snapshot API（缓存/负缓存/调用计数/Exit-DNS Binding）。
  - plan explain 挂 `nexus-planner` DecisionTrace（结构化拒绝原因 label）。
  - workspace heads/conflicts 挂 `nexus-workspace` DAG（Head Set 分叉 / 三方合并冲突快照）。
  - compute jobs 挂 `nexus-compute` ComputeJobSession（内存帧通道提交，Active/Closed 阶段快照）。
  - diagnose 聚合各子系统快照输出健康报告（逐项 ready + overall）。
  - 领域未就绪命令（connectivity probe 等）返回
    `NexusError::Unsupported`（PRODUCT §9 禁止静默降级）。
- 远程闭环组合根（PRODUCT §6）：`remote_*_flow` 系列
  （service/internet-access/compute/workspace/presence），供 nexusd 复用。
- 真实网络切片（real transport，PRODUCT §6）：`remote_host_serve_once`（单连接）/
  `remote_host_serve_loop`（持续服务循环）/ `relay_serve_once` / `remote_real_flow` /
  `remote_real_flow_with_relay` / `error_code` ——
  真实 TCP 帧流 + 服务端 `AUTH` 门控（业务帧前，失败回 `AUTH_DENIED:<reason>`，客户端透传
  为 `AuthorizationDenied`，禁止抹成通用建连失败）+ `DIAL` 字节中继回退；
  host 侧支持 service（ECHO 往返）/ internet-access（真实 HTTP GET）/ compute（表达式求值）。
- 真实 SOCKS5 代理数据面（PRODUCT §11.4）：`proxy_serve_once` /
  `DEFAULT_PROXY_CONFIG` —— 握手（Socks5Handshake）→ 规则路由（nexus-proxy）
  → Session 双轨 → 真实出站连接 → 双向字节中继。
- 本地主链路切片：`internet_access_flow` / `service_session_lifecycle` /
  `connectivity_failure_rollback`。

## Verification

最低：

```text
cargo check -p nexus
cargo clippy -p nexus --all-targets -- -D warnings
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
