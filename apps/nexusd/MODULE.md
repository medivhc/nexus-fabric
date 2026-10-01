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
- `nexus-projection`（统一数据面：TUN/分类器/多路径/Boost）
- `nexus-connectivity`（统一数据面：CAKE-like QoS）
- `nexus-dns`（统一数据面：UnifiedDns）
- `nexus-path`（统一数据面：PathManager/EWMA 选路，Boost 联动）

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
- `nexusd proxy speedtest --json`：节点测速批量结果表（PRODUCT §11.10）。
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

### `daemon.toml [qos]` 小节（CAKE-like QoS，scenarios/product/qos_cake.toml (e)）

- 字段（全部可选）：`enabled`（默认 false；别名 `enable` 亦接受）、
  `mesh_upload_mbps` / `proxy_upload_mbps`（整数 Mbps，0=不限，默认 0；
  负数按 0 处理，即不限）、
  `quantum`（整数，需在 [64, 65536] 内，默认 1514，非法则拒绝加载）、
  `high_priority_ports`（逗号分隔字符串 `"22,53,3389"` 或整数数组，
  默认 `[22, 53, 3389]`）。
- 映射：`mesh_upload_mbps` ×1e6/8 → mesh egress 整形字节/秒（`None`=不限）；
  proxy 同理。`enabled=false` 时调度器不实例化（零开销）。
- 热加载：`[qos]` 任一字段变化 → `NeedsRestart`（子系统启停/重配）；
  无变化时沿用既有分类。

### 统一数据面装配（D1-D6，scenarios/product/dataplane_unified.toml，2026-10-01 冻结）

- **D1（TUN 所有权）**：`nexusd <config-folder>` 启动数据面时，创建并持有单个 TUN
  设备（Linux: `tun-rs`，设备名 `nexus0`，MTU 1500）。TUN 是唯一包入口；
  不存在"Clash TUN 与 Mesh TUN 抢设备"（设计文档 §6）。
- **D2（分类管线）**：从 TUN 读取的每个 IPv4 包 → `PacketClassifier::classify()`：
  - `Mesh{..}` → N1 转发（`network.toml` 未配置则计数 `mesh_dropped_no_n1`）；
  - `Proxy` → proxy 转发（`proxy.yaml` 未配置则计数 `proxy_dropped_no_proxy`）；
  - `Direct` → 直连（MVP 计数 `direct_forwarded`，实际经系统路由）；
  - `Drop` → 计数 `dropped`。
- **D3（DNS 拦截）**：UDP 目的端口 53 的包短路分类器 → `UnifiedDns::resolve()` →
  构造 DNS 响应写回 TUN（`dns_answered` 计数；响应包源端口 53）。
- **D4（QoS）**：`[qos].enabled=true` 时，分类后、转发前经过 `CakeScheduler`：
  `enqueue()` 拒绝则计数 `qos_dropped`；`enabled=false` 时零开销直通
  （`qos_bypassed=true` 可观测）。
- **D5（多路径）**：`[multipath].strategy` 非 `Single` 时，`PathScheduler::select()`
  选择 egress；MVP 默认 `Single` 直通。
- **D6（Boost）**：`[boost].enabled=true` 时，分类器构造传入 `PathManager`，
  mesh 分类启用 EWMA 只读选路（S30）；禁用时 `candidates=[]`。
- 可观测：`DataplaneStats { mesh_forwarded, proxy_forwarded, direct_forwarded,
  dropped, dns_answered, qos_dropped }`，经 LocalAPI `/localapi/v0/dataplane/stats` 暴露。
- 不变量：单 TUN（D1）；分类器是唯一分类入口（S29）；DNS 不泄露 mesh 内名
  （nexus-dns S-unified）；QoS 禁用时零开销（D4）。

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
