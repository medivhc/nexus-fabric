---
doc-id: n3-recovery-function-summary
layer: L2
owner: coordinator
last-verified: 2026-10-20
verified-against: 1beb960
status: current
---

# N3 功能与代码恢复总结

核实日期：2026-10-20（Asia/Shanghai）。本文依据正式契约、可读源码和机器记录说明能力边界，不改写历史 PROJECT-STATUS。发布基线为远端 master `5d70709`，发布分支为 `feat/n3-restored-code-20261020`；实际推送状态以远端引用为准。

现有代码已具备 Task/Snapshot/Artifact 的持久基础、Linux 隔离执行适配器、本机 Task 查询与取消、Linux Artifact 断点下载、scoped Use 授权运维，以及恢复的 N3-11 提供方初始化/检查与 managed daemon 启动。它们尚未构成用户从 CLI 提交新任务、上传固定输入并经远端提供方执行的完整链路：当前生产 `Submit` 分支仍明确拒绝。N3-12 正在取证恢复，不能认定已集成；N3-13/14 未验收，Full 与 Windows→Linux E5 暂停。

## 1. 如何理解能力边界

| 层次 | 当前已有能力 | 当前边界 |
|---|---|---|
| 库与提供方内部适配器 | 严格 DTO/规范摘要、持久接受与幂等、固定 Commit Snapshot、运行 journal、Linux Engine 执行/冷核实、产物登记、容量与已有 Session 绑定、请求方只读镜像/取消 outbox | 内部 Rust 调用需要真实认证、授权、输入与容量前置；存在库 API 不表示 CLI 已接通 |
| daemon LocalAPI | `POST /localapi/v1/task`；真实既有 Task 的 Get、ReadLogs、Cancel、ListArtifacts、GetArtifact；逐次当前 Use 检查 | Linux 提供方、显式 `task-api.toml` 与真实 authority；Submit 校验/授权后仍返回 `UNSUPPORTED_CAPABILITY` |
| CLI | `task show/logs/cancel/artifacts`；Linux `artifact get`；本机 grant 运维；`nexusd task-provider init/check` | CLI 为 daemon 薄客户端；`task submit` 可解析请求并收到真实拒绝，不启动工作负载 |
| 远端执行产品闭环 | Fabric 显式 mTLS 安全基础；Linux 内部执行适配器可以核实真实 Engine 执行 | 尚无已验收的跨节点 Task RPC、输入上传与提交装配；未完成真实 Windows→Linux 两机验收 |

正式依据：[PRODUCT §17](../PRODUCT.md)、[ARCHITECTURE §12](../ARCHITECTURE.md)、[N3 模型契约](N3-MODEL-CONTRACT.md)。实际边界：[LocalTaskService](../apps/nexusd/src/task_service.rs)、[ProviderService 的 Submit 拒绝分支](../apps/nexusd/src/task_service_provider.rs)、[CLI 解析和下载](../apps/nexus/src/task_cli.rs)。

Task、资源 Session 与连接各有所有者。TaskOwner 独占 TaskOutcome 写入，原 SessionManager 独占 Session 生命周期；连接丢失、Session 回收、请求受理或取消 ack 均不能替代已核实的 Task 执行结局。查询 envelope 的 `verdict=PASS` 表示该次查询处理成功，不代表 Task 已完成。

## 2. N3-1 至 N3-10 已有功能

下表的“已有”指当前可定位的实现与正式范围；各批历史文档中的验证描述保持其原 revision 语境，不合并为当前一次全量 PASS。

| 批次 | 功能与行为 | 入口及限制 | 正式范围与主要源码 |
|---|---|---|---|
| N3-1 | v1 Task/Snapshot/Artifact 标识、DTO、结构与状态校验；精确整数的规范 JSON/SHA-256；原子持久接受；按 Workspace、认证主体、Provider、key 的幂等；同键重放保留原 Task/TTL，冲突拒绝 | 库与 Linux 持久化适配器；不自行认证主体、创建 Session 或启动命令。损坏 authority 保留并拒绝，不能清空重建 | [实现说明](N3-1-IMPLEMENTATION.md)；[domain task](../crates/nexus-domain/src/task/mod.rs)、[codec](../crates/nexus-domain/src/task/codec.rs)、[TaskOwner](../crates/nexus-compute/src/task.rs)、[接受存储](../apps/nexusd/src/task_store.rs) |
| N3-2 | 从明确唯一 Commit 固定 Snapshot；显式 include/exclude 与 executable 集合进入摘要；独立 SHA-256 内容空间；清单/字节/路径核实；接受记录驱动持久 input pin；保护根与两阶段 GC；Linux 私有输入物化 | 库与提供方内部适配器；不扫描可变 Head/工作目录，不默认递归上传；物化不是隔离执行。旧 FNV ID 不作为完整性认证 | [实现说明](N3-2-IMPLEMENTATION.md)；[Snapshot](../crates/nexus-workspace/src/snapshot.rs)、[StrongContentStore](../crates/nexus-storage/src/strong.rs)、[Snapshot 存储](../apps/nexusd/src/snapshot_store.rs) |
| N3-3 | 持久 Prepare/StartIntent/Started/Exited 等运行 journal；单调事件、恰一次终态；Docker Engine 固定原 container/exec 身份；隔离执行、持续排空的有界日志、真实退出码；全子树停止/reap 后确认取消或超时 | Linux 提供方内部 executor；仅本地 Docker socket、不可变镜像与精确隔离/配额。能力不足拒绝，不退回裸主机；未知启动窗口不重跑 | [运行基础](N3-3-RUNTIME-FOUNDATION.md)、[Linux executor](N3-3-LINUX-EXECUTOR.md)；[运行归约](../crates/nexus-compute/src/task_runtime.rs)、[journal](../apps/nexusd/src/task_runtime_store.rs)、[executor](../apps/nexusd/src/task_executor.rs)、[执行路径](../apps/nexusd/src/task_executor_run.rs)、[日志](../apps/nexusd/src/task_executor_logs.rs) |
| N3-4 | 自然退出、全子树 reap、日志 seal 后登记真实输出与日志；持久 ArtifactId、来源/环境/授权范围、SHA-256/长度；required 缺失与非允许退出码有真实失败结果；断点接收器验证完整内容后原子无覆盖发布 | 提供方内部登记与本地接收库；“交付”指已登记并可授权获取，不要求某请求方已下载。登记/补传不重执行命令；尚无完整 Artifact GC/终态 pin 释放 | [交付说明](N3-4-ARTIFACT-DELIVERY.md)；[归约](../crates/nexus-compute/src/task_artifact.rs)、[提供方登记](../apps/nexusd/src/task_artifacts.rs)、[catalog](../apps/nexusd/src/task_artifacts_catalog.rs)、[接收器](../apps/nexus/src/artifact_download.rs) |
| N3-5 | 六类版本化 Task 操作与 Application Service DTO；严格 CLI 解析；请求方只读 provider 镜像、单调更新与持久取消 outbox；冷启动按原 Engine 身份核实，不重新创建/启动 exec | 基础能力；本地取消意图不伪造 provider Requested/Confirmed；ack 不等于停止；未知保持 PendingVerification，不延长原 timeout | [阶段计划与边界](N3-5-PARALLEL-PLAN.md)；[控制 API](../crates/nexus-control-api/src/task.rs)、[CLI](../apps/nexus/src/task_cli.rs)、[镜像/outbox](../crates/nexus-compute/src/task_requester.rs)、[请求方存储](../apps/nexusd/src/task_requester_store.rs)、[原执行冷核实](../apps/nexusd/src/task_executor_recovery.rs) |
| N3-6 | 正式 LocalAPI v1 的严格 HTTP framing、token 认证、有限大小/超时、schema1 envelope；装配真实既有任务查询、日志、取消和产物分页；每次核实真实当前 Use；Fabric 增加显式 TLS1.3 双向证书认证与 allowlist | 本地 TCP 仅 loopback，Unix socket 私有；认证先于 body 读取/服务调用。跨节点 Task 业务未接通，不能用 N2 明文 admission 替代安全通道 | [LocalAPI/安全契约](N3-6-LOCALAPI-SECURITY-CONTRACT.md)；[HTTP](../apps/nexusd/src/task_http.rs)、[服务](../apps/nexusd/src/task_service_provider.rs)、[客户端](../apps/nexus/src/task_localapi.rs)、[真实授权](../apps/nexus/src/task_authorization.rs)、[Fabric 认证](../crates/nexus-fabric/src/cert.rs) |
| N3-7 | linked worktree Git hooks 的根目录/环境隔离；真实 CLI/daemon 预构建；Cargo metadata 发现实际 test target；工程失败保留可诊断证据；既有测试配置隔离与同进程冷身份初始化修复 | 工程稳定性改进，不新增 Task 产品能力。Fast 中“无受影响测试”不能代替实际 E3/E4；不宣称已解决跨进程同时身份初始化 | [工程范围](N3-7-ENGINEERING-PLAN.md)；[hook 公共逻辑](../.githooks/hook-common.sh)、[场景驱动](../engineering/nexus-harness/src/run_scenario.rs)、[测试发现/执行](../engineering/nexus-harness/src/gates.rs)、[身份实现](../apps/nexus/src/n2_identity.rs) |
| N3-8 | 明确 CPU/内存/PID/可写存储/后端字节/slots 预算与固定 reserve、executor overhead；接受 envelope v2 同事务保存 Task/幂等/input pin/容量预留；活固定 inode owner lease、epoch 与恢复 Ready；可信内部接口绑定已存在且有真实 Plan 的原 Session；确认取消后由原 Manager 清理 | 配置预算不是宿主空闲量测或普适 OOM/ENOSPC 保证。未知执行保留占用并阻止新启动/GC；reap 仅释放运行容量，保留后端字节。无新 wire 操作，Submit 仍拒绝 | [容量/Session 契约](N3-8-CAPACITY-SESSION-CONTRACT.md)；[容量](../apps/nexusd/src/task_capacity.rs)、[恢复](../apps/nexusd/src/task_capacity_recovery.rs)、[Session 绑定](../apps/nexusd/src/task_sessions.rs)、[内部 prepare 入口](../apps/nexusd/src/task_service.rs) |
| N3-9 | Linux `nexus artifact get` 通过真实分页 LocalAPI 下载；先取得已授权 Published record 再做 output IO；逐页绑定完整 record；durable offset 续传；完成前另取当前授权的空 EOF 页；SHA-256/长度核实后 hard-link 无覆盖发布 | 每页最多64 KiB、Artifact 限额沿用80 MiB；并发 lease 忙可重试；失败保留前缀，不重置损坏接收器；非 Linux 明确 Unsupported。每页前缀重读/hash 可有平方级成本，未作性能完成承诺 | [下载契约](N3-9-ARTIFACT-CLI-CONTRACT.md)；[CLI 下载链](../apps/nexus/src/task_cli.rs)、[接收器](../apps/nexus/src/artifact_download.rs)、[专用 IO](../apps/nexus/src/artifact_download_fs.rs)、[Linux file lease](../crates/nexus-platform-linux/src/file_lease.rs) |
| N3-10 | 本机 scoped `task-provider grant add/revoke/list`；从显式根既存两字段配置确定 scope；复用真实 N2 Use grant 与既存身份；list 只读；mutation 先持久 intent、原子更新 grant、再持久 applied，保留校验链 | Linux 本机命令；不生成身份或接管 default Workspace。拒绝修改 Manage/mixed 记录；损坏/torn/dangling 审计保留现场，不猜测补做授权。旧 generic writer 不共用新锁；无跨节点授权通知 | [运维契约](N3-10-OPERATOR-GRANT-CONTRACT.md)；[CLI](../apps/nexus/src/task_provider_grant.rs)、[Linux 实现](../apps/nexus/src/task_provider_grant/linux.rs)、[审计](../apps/nexus/src/task_provider_grant/audit.rs) |

后续批次是增量：N3-6/N3-8 原文中的“完整下载未装配”描述其当时状态，Linux 完整下载已由 N3-9 接通；它们关于 Submit、输入传输、远端 Task 与 E5 的限制仍保留。

## 3. N3-11：正式 init、check 与 managed startup

入口由 `nexusd` 组合根持有：

```text
nexusd task-provider init --config <absolute-private-root> --provider <id> --workspace <id> --capacity <absolute-policy-json> [--json]
nexusd task-provider check --config <absolute-private-root> [--json]
nexusd <config-folder>
```

这些命令的具体规则以[冻结契约](N3-11-PROVIDER-INIT-CONTRACT.md)为准；实现入口为[参数/输出](../apps/nexusd/src/task_provider_command.rs)、[初始化/验证](../apps/nexusd/src/task_provider_init.rs)、[安全 IO](../apps/nexusd/src/task_provider_init_io.rs)、[正常 daemon 接线](../apps/nexusd/src/main.rs)。

### init 的行为

- 所有必填参数、重复/未知选项、路径和标识在宿主 IO 前校验；显式绝对路径不允许 `..`，不使用环境/default 节点根。用法错误 exit2；业务结果为单个 schema1 JSON、exit0，必须看 `verdict/error`。
- 首次根必须已存在、真实0700、祖先无 symlink。只允许运维者事先提供一个有效且明确 `[tun] enabled=false` 的 `daemon.toml`；也允许不带它做离线初始化，但正常 N3-only 启动仍要求明确 no-TUN 配置。
- 建立真实 N2 Ed25519 身份、原 `data/n3/tasks` 容量 authority，并最后发布恰含 provider/workspace 的 `task-api.toml`。Provider ID 与认证 principal 不混同；Workspace 是固定 scope，不伪造 Commit/Snapshot。
- 不创建 grant、资源广告、Task、Session、输入、Artifact 或 LocalAPI token；不运行 daemon、Engine qualification 或 capacity owner recovery。初始化后 epoch0/Pending 不等于活 Ready。
- policy 严格使用现有 total/fixed/overhead 结构；有界读取并拒绝非整数、未知字段、不合法预算、链接/特殊文件/不安全权限。摘要来自规范 DTO 字节，不是 JSON 排版。预算由运维显式分配，不自动探测主机空闲或发明默认预算。
- 固定 inode 非阻塞 init lease、校验和 journal 和完成 receipt 绑定 scope、policy、根/锁/原身份 inode 与原字节摘要；原 capacity-owner inode 写入 managed-required sentinel。原容量账本仍是唯一容量真相。
- 只恢复精确可证明的原持久检查点，包括原 staged 身份、身份发布、容量初始化及 scope publication。authority 丢失、坏校验和、inode 替换、未知/矛盾状态明确拒绝；不换身份、不重建空池、不自动猜测回滚。
- completed 且同 scope、同 canonical policy 的重复 init 在启动前、活 daemon 期间及冷启动后均为 `changed=false`，保留原身份、账本、epoch、reservations。旧 unmanaged 根不能隐式 enrollment；scope/policy 改变拒绝。

### check 的行为

check 仅验证已经 completed 的 managed provider，直接有界读取原文件并核实全部 binding/authority links；不调用会初始化/写入的 storage open、不创建 init lock/token/身份、不清 tmp、不做 reconciliation、不取得 Ready-owner lease。为一致性观察可锁住既存 acceptance inode，忙或观察变化明确返回可重试失败。

成功中的 `initialized=true` 只证明初始化绑定完整；不证明 owner 存活、Engine 合格、容量 Ready 或 Submit 可用。pristine、pending、缺 marker、损坏及 authority loss 均失败；失败保留原文件。恢复边界与零写入断言可从[正式契约](N3-11-PROVIDER-INIT-CONTRACT.md)、[实现](../apps/nexusd/src/task_provider_init.rs)、[真实命令回归](../apps/nexusd/tests/task_provider_init.rs)追溯。

### managed startup 的行为

正常 config-folder、`serve` 兼容入口与 Task loader 在身份 ensure、reconciliation 和 token 创建前验证 managed anchors。journal、receipt、init lock 或原 owner sentinel 任一尚存，就不能因其他 marker 缺失而降级成 legacy；pending/损坏根不得进入 READY。全部 anchors/authority 一并抹除后的外部识别不在本地证明承诺内。

完整核实的 managed provider 可作为正常 daemon 的有效独立 subsystem，无需虚构 proxy/network/workspace 配置；普通空根仍拒绝。N3-only 启动必须有显式 no-TUN `daemon.toml`。配置根为实际 N2/Task 所有权根，环境 decoy 不应重定向它；相对 config-folder 先锚定为绝对路径，同时保留 symlink/`..` 的安全检查。正常 daemon 继续用原唯一 SessionManager 和容量 owner 恢复，不由 init/check 获得 Ready。READY 行仍须结合真实 LocalAPI TaskService 观察理解。

Linux 限制：init/check 的合法参数在非 Linux 平台于 IO 前返回 `UNSUPPORTED_CAPABILITY`；Linux executor 仍依赖受支持本地 Docker Engine、固定不可变镜像及其隔离资格。本批初始化不要求运行 Engine，也不证明后续执行资格。不承诺 Windows 提供方或 Windows Artifact 接收器。

## 4. Fabric owner 与 datagram 修复

本次恢复包含正式 `product.fabric-conn-basic` 示例的协调修复。`SendStream::write/finish` 只将回显字节与 FIN 排队，不能视为对端已经收齐；示例保留独立 server listener owner，直到 client 收到完整回显/EOF 且 server worker 被 join 后才释放。所有 client `Result` 路径都消费 server JoinHandle，同时保留 client/server 双侧错误；失败不能留下 detached worker。

datagram 观察按已有 S5 尽力而为契约：示例发送100个200B数据报，接收循环至多检查100次，首次观察合法200B数据报即可满足“至少收到一个”；无需等待全部100个，从而不会在已有合法观察后又因下一次 timeout/close 抹掉该事实。一个都未收到的 timeout/close 仍失败；错误长度不计有效接收。修复不把 QUIC datagram 变为可靠传输，也不修改 stream finish/Drop API、认证语义或冻结场景期望。

正式依据：[Fabric MODULE S4/S5/S10/S11](../crates/nexus-fabric/MODULE.md)、[basic 冻结场景](../scenarios/product/fabric_conn_basic.toml)。实际修复：[basic example](../crates/nexus-fabric/examples/basic.rs)；验证边界：[owner regression](../crates/nexus-fabric/examples/basic/owner_tests.rs)、[datagram regression](../crates/nexus-fabric/examples/basic/datagram_tests.rs)。mTLS/原 driver owner 与 reaper 的实现另见[driver](../crates/nexus-fabric/src/driver.rs)；该基础安全能力不等于远端 Task RPC 已集成。

## 5. 本轮验证与恢复边界

本轮集成代码在最新 master 上通过 Check 4/4、受影响测试、Fast 9/9；真实二进制回归为 init 23 + relative-startup 4，Fabric owner/datagram 回归18，全部45项通过、0忽略。`product.n3-11-provider-init` 的12项期望与 `product.fabric-conn-basic` 的6项期望均通过。首轮 Check 的格式/rustdoc 失败保留在本地证据中，修复后重新执行；没有修改冻结期望、增补 skip 或绕过 hooks。

可持久核对的[机器验证摘要](recovery/2026-10-20/verification.json)及同目录 Check/Affected/Fast/E4 JSON，绑定于 `1beb960` 的已测试工作树 SHA-256 `0992a086c45d3a71b7ffab025704831a850b60a7dffa6e0409c0cb6e1a361d38`；这是添加本文及源码归档之前的集成代码验证，不冒充最终提交的全量验收。发布时仍须在最终提交上运行正常 Fast/推送门禁。完整 Full 与 Windows→Linux E5 按原决定暂停；本轮不声明 Candidate Completion 或 Final PASS。

恢复范围必须区分：

- 活跃构建中恢复的是远端已提交的 N3-11 `37e0cff`，保留最新 master 的 runtime、flow-session、NAT 更新和 Fabric 修复；它不是已丢失的10月19日未提交工作树。
- 27项历史清单中有15项文件逐字节匹配10月17日哈希，包括完整 N3-12 冻结契约、DTO实现、staging入口/测试入口和场景。另保留40个完整中间代码候选，均未证明等于最后版本。
- 仍缺12项清单文件，外加完整 backend/CLI/freeze 的最终来源证明、部分测试、10月19日 N3-11 lease 与 N3-12 TTL/expiry 修复；27项清单本身也不是全部源码清单。不能宣称所有代码已恢复。
- 尚未集成的源码以 `.txt` 形式存于[恢复归档](recovery/2026-10-20/README.md)，每份都有原路径、大小、SHA-256与来源标识；不参与编译、测试或场景发现。归档不是可安装的 N3-12，实现与冻结测试必须恢复完整并重新审查后才能装配。

## 6. 里程碑与下一步优先级

| 里程碑 | 当前定位 | 下一完成条件 |
|---|---|---|
| N3-1..4 | 模型、固定输入、运行、日志与产物持久基础存在 | 保持 authority、唯一 owner、完整性及不重执行不变量 |
| N3-5..10 | 本机协议、查询/取消、容量/Session 基础、Linux 下载、grant 运维存在 | 不把有限 E4 扩大为完整 Submit 或远端计算验收 |
| N3-11 + Fabric 修复恢复 | 代码已恢复到当前交付线；有上述独立 revision 的历史验证 | 适用门禁已通过；独立审查与最终提交后的 Fast/推送状态以交付记录为准 |
| N3-12 | 15项精确历史文件及40个中间候选已归档，未完整集成 | 恢复完整来源、原冻结契约/摘要、核心 staging/上传/恢复文件与证据；先核实边界再集成 |
| N3-13 | 未验收 | 保密双向认证通道中绑定真实 peer/grant/输入/容量及唯一 SessionManager；装配 Submit 与真实执行；闭合完整 N3 E4 verifier |
| N3-14 | 未验收；Windows E5 暂停 | 真实 Windows requester→Linux provider 双机，记录平台/Engine digest、固定输入、日志/退出码、产物摘要和恢复观察 |

优先级：

1. 保留本轮 N3-11/Fabric 已恢复代码、来源清单和验证；正常审查/提交后推送新 feat 分支。不得以当前有限门禁替代完整 N3 验收。
2. N3-12 先完成来源与完整性取证。原方案涉及固定 Commit Snapshot staging、独立接受前预算、durable receipt、分片上传/断点恢复、manifest/blob 校验与 GC roots；这些目前是待核实范围，不列为已交付能力。
3. 在 N3-12 可信基础上推进 N3-13 的实际安全提交与执行装配，保留 Submit 旧拒绝直到新契约与真实产品路径具备证据；不借 principal 字符串、明文 N2 或放宽 LocalAPI 地址绕过身份安全。
4. 恢复 Full 与 N3-14 两机 E5 前，核实受支持 Engine/镜像/隔离能力和真实 Windows 测试条件；现阶段保留暂停与未验收状态。

路线图依据：[N3-11..14 执行计划](N3-11-14-EXECUTION-PLAN.md)。其中“当前进度”是2026-10-11的历史快照；本文仅增补恢复交付视角，不回写旧快照，也不把恢复中的文件数量或设计描述当作完整功能验收。
