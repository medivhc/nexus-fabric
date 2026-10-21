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
    `connectivity candidates` / `connectivity probe` / `connectivity links` /
    `dns status` / `dns cache` / `dns resolve` / `dns providers` /
    `workspace heads` / `workspace conflicts` / `workspace cache` /
    `compute jobs` / `diagnose` / `platform capabilities`。
  - dns 命令挂 `nexus-dns` `DnsRuntime` snapshot API（缓存/负缓存/调用计数/Exit-DNS Binding）。
  - plan explain 挂 `nexus-planner` DecisionTrace（结构化拒绝原因 label）。
  - workspace heads/conflicts 挂 `nexus-workspace` DAG（Head Set 分叉 / 三方合并冲突快照）。
  - compute jobs 挂 `nexus-compute` ComputeJobSession（内存帧通道提交，Active/Closed 阶段快照）。
  - diagnose 聚合各子系统快照输出健康报告（逐项 ready + overall）。
  - 领域未就绪命令（connectivity trace 等）返回
    `NexusError::Unsupported`（PRODUCT §9 禁止静默降级）。
  - CLI 前端（apps/nexus/src/main.rs + control_service.rs + localapi_client.rs）：thin-client，
    观察命令经 HTTP LocalAPI 查询 `nexusd serve`（`--addr` 默认 `127.0.0.1:18080`）；7 个命令有
    daemon 路由（status / dns status / dns cache / session watch / plan explain /
    connectivity status / platform capabilities），查询 daemon 快照原样渲染，daemon 不可达 →
    结构化 `DAEMON_UNREACHABLE`；暂无路由命令（dns resolve/providers、connectivity
    candidates/probe/links、workspace heads/conflicts/cache、compute jobs、diagnose）本地合成
    显式 `UNSUPPORTED` FAIL JSON，不回退进程内 observability（PRODUCT §9 禁止静默降级）；
    `nexus run <resource>` 保持进程内 SDK 路径；全局 `--json` 双输出（JSON 原样 / 人读文本投影）；
    exit 语义对齐 nexusd（用法错误 exit 2，业务成功 exit 0，领域拒绝 verdict=FAIL 且 exit 0）。
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
- 真实节点测速（PRODUCT §11.10）：TcpLatencyProbe（std::net connect_timeout，非 portable）
  + Http204LatencyProbe（connect 后发单行 GET、等响应首行 204，非 portable）
  + proxy_speedtest_with(probe, candidates, timeout, target_label, probe_kind)（批量测速、RTT 排序 JSON 输出）；结果可经 MeasurementSource 喂 urltest。
- 计划任务 CLI（PRODUCT §14）：`schedule_cli` 模块（组合根）——`nexus schedule
  at|every|list|cancel|tick` 五个用户可观察操作；注册表持久化到
  `~/.nexus/schedule.json`（`--state` 可覆盖；`SchedulerSnapshot` 落盘/重载，
  PRODUCT §14.2 / §14.4，损坏快照显式 `STATE_ERROR` 不静默丢弃）；业务错误输出
  `INVALID_SCHEDULE` / `SCHEDULE_NOT_FOUND` / `SUBMIT_FAILED` 结构化 JSON（exit 0，
  PRODUCT §14.3）；用法错误 exit 2（对齐本 CLI exit 语义）；触发回调生成 task id，
  不实现执行路径（P0 冻结边界）。单进程假设：并发 `nexus schedule` 调用各自
  load-modify-save，不提供 lost-update 保护（P0 边界，多进程调度为 P1+）。
- 本地主链路切片：`internet_access_flow` / `service_session_lifecycle` /
  `connectivity_failure_rollback`。

## Verification

### N3 CLI 契约增补（待实现）

新增 task submit --request / show / logs / cancel / artifacts、artifact get。
参数与 JSON envelope 见 `docs/N3-MODEL-CONTRACT.md` §7；操作经 daemon 的统一
Application Service，不在 CLI 创建 TaskOwner 或直接 spawn 工作负载。
用法 exit 2、结构化业务响应 exit 0，工作结果从 TaskOutcome 读取。
artifact get 默认拒绝覆盖，下载完整性验证后原子发布。
现有 run-with-command 的 UNSUPPORTED 场景保持有效；便捷 run 接线单独 requirement-change。
验收：`scenarios/product/n3-submit.toml` 及未来 n3_task_e4 产品编排。

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

### N3-6 CLI 与授权组装增补

N3 CLI 使用 POST /localapi/v1/task 获取真实 TaskEnvelope；不可达显式拒绝，
不回退演示路径。下载 receiver 未装配时不触碰 output，legacy run 契约保留。
本组装层授权 facade 复用真实 N2 当前 Use grant/持久 audit，按接受 resource/
workspace 检查，不依赖 default Workspace；错配/审计失败拒绝。协议、容量、
错误映射、FIFO/相关性边界见 docs/N3-6-LOCALAPI-SECURITY-CONTRACT.md。

### N3-9 Artifact CLI 接收器

按 docs/N3-9-ARTIFACT-CLI-CONTRACT.md 装配 Linux ArtifactDownload 与私有 IO；先远端 probe，再 durable offset/完整 record 校验，额外当前授权 EOF 后完整 SHA/no-replace 发布。Linux offline 返回 ProviderUnreachable，output/凭证不创建；未启用服务及其他平台 Unsupported。保持 forbid(unsafe_code)，文件锁使用已有 Linux platform 依赖的安全非阻塞 helper。受保护 crash/prefix/lease/inode/no-replace 语义与测试保留，不创建 TaskOwner、不新增 wire DTO/依赖。

### N3-10 提供方范围 Use grant 运维

按 docs/N3-10-OPERATOR-GRANT-CONTRACT.md 分派本地 task-provider grant；配置路径必须显式，不使用环境/default Workspace/daemon目标代替。严格核实既存 scope、私有 N2 身份和真实 grant 编码；list 不创建或清理文件，add/revoke 只改变单个 Use-only grant。专用 Linux lease/审计与原子 IO 由组合根拥有，保持 forbid(unsafe_code)；不创建 Task/Session/identity、无 outbox 或新增依赖。业务失败按 schema1 显式报告 phase/可能已生效，用法错误 exit2。冻结状态未知时拒绝 mutation，读列表仍可取证。

### N3-12 Snapshot CLI 与只读输入适配

按 docs/N3-12-SNAPSHOT-STAGING-CONTRACT.md §1/2/3/8，新增 snapshot freeze/upload/status/cancel。freeze 从显式私有 config 的正规 Workspace anchor/CAS bounded read，仅写新 bundle，no-replace helper 归属 Linux platform；upload 验证完整原 bundle后按原key/已确认offset续传，status/cancel只调用本机认证API。纯语法/非本机target拒绝先于IO，forbid(unsafe_code)、无 TaskOwner/新依赖/远端明文token。
