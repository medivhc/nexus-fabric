# nexusd Module Contract

## Responsibility

桌面/服务端主 Runtime Composition Root，装配 Domain Runtimes、Ingress、Registry/Discovery 与平台抽象。

## Non-Responsibilities

不承载可复用核心领域逻辑；可复用逻辑必须下沉到对应 crate。

## Inputs

- 仅接受公开类型、DTO、trait、事件或稳定协议对象。
- 输入必须可被结构化验证；不得依赖未声明的全局隐式状态。

## Outputs

- 结构化 Result / Event / DTO。
- 失败必须保留可诊断原因，不以日志文本代替错误类型。

## Allowed Dependencies

- `nexus`（apps/nexus SDK 组合根：daemon 复用其远程闭环流程，不复制领域逻辑）
- `nexus-control-api`
- `nexus-registry`
- `nexus-discovery`
- `nexus-ingress`
- `nexus-network`
- `nexus-service`
- `nexus-workspace`
- `nexus-compute`
- `nexus-diagnostics`
- `nexus-platform`

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

### 冻结契约（daemon 形态，scenarios/product/daemon_run_remote_service_flow.toml）

- 单次执行入口：`nexusd run <resource> --json`，路由到 SDK 组合根远程闭环（`service` / `internet-access` / `compute`），stdout 输出单个 JSON 对象。
- 未知资源：输出 `{"verdict":"REJECTED","error":{"code":"UNKNOWN_RESOURCE","resource":"<name>"}}`，exit 0（表示请求已被 daemon 处理，拒绝也是处理结果；无效 CLI 用法仍 exit 非 0）。
- daemon 不复制领域逻辑：全部闭环复用 `nexus` SDK 组合根函数；本 app 只承担 CLI 解析与装配。

### 真实网络入口（real transport，PRODUCT §6，2026-09-18）

- `nexusd host <service|internet-access|compute> --addr <ip:port> --token <t>`：
  提供方在真实地址**持续监听**（服务循环，逐连接独立认证 + 业务闭环），
  服务端完成 `AUTH` 门控（业务帧前），随后执行业务
  （service ECHO 往返 / internet-access 真实 HTTP GET / compute 表达式求值）。
  认证拒绝输出 `AUTH_DENIED` 结果后继续服务，不退出。
- `nexusd relay --addr <ip:port>`：`DIAL <target>` 帧 + 双向字节中继（真实 TCP 代理）。
- `nexusd run <resource> --endpoint <ip:port> [--relay <ip:port>] --token <t> --json`：
  请求方经静态发现解析真实 Endpoint 建立真实帧流并执行线上认证；直连失败回退 relay。
- `nexusd proxy --addr <ip:port> [--config <path>]`：真实 SOCKS5 数据面入口
  （PRODUCT §11.4）——监听后逐会话完成握手 → 规则路由 → Session → 真实出站
  → 字节中继；每会话输出一条结构化 JSON。
- 语义：host/relay 只做装配与真实 I/O，闭环事件与认证语义全部复用 `nexus` SDK。

### §9 可观察性子命令（scenarios/product/observability_*.toml）

- `nexusd status --json` / `dns status --json` / `dns cache --json` /
  `dns resolve --json` / `dns providers --json` /
  `session watch --json` / `connectivity status --json` /
  `connectivity candidates --json` / `connectivity probe --json` / `connectivity links --json` /
  `plan explain --json` /
  `workspace heads --json` / `workspace conflicts --json` / `workspace cache --json` /
  `compute jobs --json` /
  `diagnose --json` / `platform capabilities --json`：路由到 SDK `observability` 模块，
  stdout 输出单个 JSON。
- 领域未就绪子命令（connectivity trace 等）：
  输出 `{"verdict":"FAIL","error":{"code":"UNSUPPORTED","command":"<name>"}}`，exit 0。
- 无效 CLI 用法仍 exit 非 0。

### 常规要求

- 默认最小 surface：`private -> pub(crate) -> pub`。
- Public API 变更必须保持结构化、可版本化并有调用方验证。

## Verification

最低：

```text
cargo check -p nexusd
cargo clippy -p nexusd --all-targets -- -D warnings
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
