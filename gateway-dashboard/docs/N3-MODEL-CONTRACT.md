# N3 首期模型与契约

日期：2026-10-03。任务类型：feature / Contract-First 阶段 A。
产品依据：白皮书 v1.0 §4.7、§8–11、§16.2、§17.1；技术依据：v9 §23。
规范入口：PRODUCT.md §17、ARCHITECTURE.md §12、相关 MODULE.md。
本文定义待实现行为，不能作为 N3 已可用或兼容的证明。

## 1. 首期范围与进入条件

目标：Windows 用户或 Agent 向指定可信 Linux Compute Provider 提交固定项目输入，
在已核实的环境内执行构建或测试，按任务 ID 查询日志、退出码和可下载产物。
先用 Linux 请求方验证同一协议，再用真实 Windows→Linux 验收平台语义。

首期每个 Task 最多启动一次命令；不自动重新执行、不自动换 Provider。
输入同步、连接恢复、日志续读、产物补传可以在原 Task 内重试。
多 Provider 优化、GPU、共享执行缓存、调度触发、可写远端挂载、自动源码 write-back 后置。
发布入口、Android VPN、VMess 继续按现有范围处理。

提供方身份必须经双向认证的保密通道核实，Use grant、Workspace 和数据范围均在执行侧检查。
N2 当前独立 TCP challenge-response 不能直接承载 N3 命令、凭据或输入；
N2 安全收口和获准传输装配是运行验收的前置，不是本次文档阶段已交付的能力。
不新增 crate、Cargo 依赖、Planner 或架构依赖边。

## 2. 对象归属与关系

| 对象 | 权威内容 | 模块与 Owner |
|---|---|---|
| Task | 接受的执行契约、事件序号、执行结局、交付状态、唯一终态 | nexus-compute 的提供方 TaskOwner；nexusd 装配 |
| Snapshot | 不可变输入选择、Commit/Manifest 引用、文件清单与 SHA-256 | nexus-workspace；持久 root 由存储适配器维护 |
| Artifact | 来源 Task/Snapshot/环境、内容摘要、权限、位置、保留期 | nexus-compute 登记语义；存储及传输由组合根注入 |
| Session | 一次资源使用、PlanSnapshot、路径与连接生命周期 | 现有唯一 SessionManager；保持 N2 契约 |
| TaskId / SnapshotId / ArtifactId | 版本化跨模块引用及 DTO | nexus-domain 的 N3 类型区；无 I/O |

Task 可以关联多个先后发生的资源 Session；Session 关闭不决定 Task 终态。
Plan 不拥有 Task，Task 引用 Session 内的历史 PlanSnapshot；不增加第二个系统级 Planner。
TaskOwner 只写 TaskOutcome；SessionManager 只写 Session 的 TerminalOutcome。
请求方保存提供方事件的只读镜像，不与提供方争夺权威，也不要求分布式共识。
没有可靠提供方记录时，镜像只能显示“状态待核实”。
请求方可另存本地主动操作的 durable intent/outbox；它不属于提供方事件镜像，
只能以显式的 cancel_request 字段呈现，不能改写权威 cancellation/phase/outcome。

## 3. 接受的执行契约

结构 schema：`docs/contracts/n3-task-v1.schema.json` 的 SubmitTaskRequest。
所有持久/线上的 N3 DTO 均有 schema_version=1；未知版本拒绝，不降级解读。
顶层 SubmitTaskRequest/TaskView/ArtifactRecord/SnapshotRef 各带版本；
AcceptedContract、TaskError、Execution/Delivery/Cancellation/CancelRequestIntent 等
嵌套对象继承所在顶层的版本，不能脱离该版本信封独立解读。
schema 根为 SubmitTaskRequest，`$defs` 还定义 SnapshotRef、AcceptedContract、TaskView、
TaskExecution/Delivery/Cancellation、TaskError 和 ArtifactRecord。
schema 检查结构与部分状态组合；摘要计算、同 Workspace、输出路径唯一、文件系统名称安全、
授权和容量等语义必须由 Application Service 校验，不能以 schema 通过代替这些检查。
`n3-submit.example.json` 是结构示例，Commit/Manifest/Provider 与全零镜像摘要均未解析，
不能作为真实提交夹具；运行 verifier 必须从实际注册、冻结输入和环境查询生成请求。

请求必须包含：workspace、resource、provider、input_snapshot、command（argv 数组）、
cwd（Snapshot 内相对目录）、environment、limits、outputs、success_exit_codes、
idempotency_key 和 idempotency_ttl_seconds。
首期幂等 TTL 为 1–86400 秒，ID/key 最多 256 字符；command 至多 1024 项、
每项至多 32768 字符且无 NUL，argv[0] 非空，空后续参数允许。
principal 从已认证通道派生，禁止调用方自填；首期无其他 Provider 回退。
Submit 需要资源的有效 Use grant；show/logs/cancel/artifacts/get 还必须与接受记录的
authenticated_principal 和 Workspace 一致，并通过当前提供方授权检查。
首期不提供代他人操作、公开分享或隐式管理员绕过；拒绝操作均留审计。
command 不经过隐式 shell。环境引用必须解析到不可变镜像摘要，并在执行侧核实
OS、architecture、digest、隔离模式和资源限制；名称/标签不是环境固定证据。
首期隔离模式为 container，网络为 none；所需工具链/依赖在固定镜像或 Snapshot 中准备。
平台不支持所需隔离或配额时返回 UNSUPPORTED_CAPABILITY，禁止退回裸主机执行。

limits 是硬上限：timeout_seconds、cpu_millis（1000=一核配额）、memory_bytes、
storage_bytes、log_bytes；提供方可以拒绝但不能悄悄降低/提高已接受数值。
开始前预留实际容量并重新核实授权，验证输入完整后才允许启动进程。
accepted 响应只承诺任务已持久接受，包含 TaskId、provider 和 request_digest；
不承诺已开跑。任何持久化失败都不能返回 accepted=true。

accepted_contract 保存规范化 request（其中包含 snapshot）、解析后的环境证明、
authenticated_principal、capacity_reservation_id、接受/幂等过期时间。
contract_digest = SHA-256(canonical accepted_contract)。
accepted_contract.request 即规范化 SubmitTaskRequest，environment_evidence 为实际环境证明；
prepare_deadline_unix/delivery_deadline_unix 在此一并保存并回传，不能事后静默延长。
接受时必须验证 prepare_deadline > accepted_at 且 delivery_deadline > prepare_deadline；
输入声明的 Workspace 必须等于 request.workspace，outputs.path 去重且不能覆盖保留日志位置。
TaskId 是提供方生成的不透明唯一 ID，不能由请求方的 SessionId 充当。

### 幂等与接受的原子性

作用域为 `(workspace, authenticated_principal, provider, idempotency_key)`。
request_digest 覆盖除幂等键和幂等 TTL 之外的全部请求字段；任何默认值先显式补齐。
同一作用域、未过期键、相同 digest 返回同一个 TaskId；不同 digest 返回
IDEMPOTENCY_CONFLICT。并发重复提交最多接受一个 Task，不仅是串行去重。
TTL 从首次持久接受时开始；重复提交不续期。响应包含 expires_at_unix。
到期后同键可新建 Task；客户端对响应丢失的重试必须在有效期内查询/重交，
过期后不得把同键当作避免重复执行的保证。
键、Task 契约和输入 pin 的 durable intent 必须一次原子发布或 journal 事务提交；
在此之前不能 ack。准备阶段的容量预留可恢复且幂等释放。

## 4. Snapshot 与完整性

SnapshotRef 包含 workspace、commit_id、root_manifest_id、snapshot_id、manifest_sha256、
selection_digest、file_count、total_bytes。Commit 必须唯一指定，不以可变 Head 作为输入。
项目中的未提交内容先按明确输入选择创建不可变 Commit；不覆盖原 Head 或丢弃本地修改。
输入预览返回相同 SnapshotRef、文件清单及字节数；接受后不再重新扫描当前工作目录。

N3 manifest_v1 是按 UTF-8 path 字节排序的文件数组，每项包含
`{path, sha256, size_bytes, executable}`；仅普通文件，空目录不传输。
path 为相对、UTF-8、以 `/` 分隔的规范路径；拒绝绝对路径、`.`/`..` 分量、
NUL、重复路径、目标文件系统名称碰撞、符号链接、设备文件及目录逃逸。
cwd 只能是由该清单形成的目录或 `.`。
include/exclude 规则及版本以 selection_digest 固定；密钥/凭据通过单独授权注入，
不因默认遍历而进入输入。本期不提供凭据注入功能。

规范 JSON 编码：对象键按 UTF-8 字节排序，无空白，保留数组顺序；
有效 Unicode 标量直接 UTF-8 编码，不自动归一化，拒绝孤立 surrogate 和重复对象键。
字符串只做以下转义：quote 为 `\"`、backslash 为 `\\`；U+0008/0009/000A/000C/000D
分别用 `\b`/`\t`/`\n`/`\f`/`\r`；其余 U+0000–001F 用小写 hex `\u00xx`。
slash `/` 不转义，其余字符（含 U+2028/2029、非 ASCII）不做 `\u` 转义。
数值必须无损解析为整数：禁止小数/指数/NaN；规范字节用最短十进制，无 `+` 或前导零，
负零编码为 `0`。所有 DTO 的非负数值上限为 9007199254740991（2^53−1），
不得经浮点舍入再做摘要。true/false/null 使用 JSON 的小写字面值。
独立已知字节/摘要向量见 `docs/contracts/n3-canonical-vectors.json`；
任何 Rust/Windows/Agent 实现均须匹配向量，不能仅由同一编码器互相比较。
manifest_sha256 是上述 manifest_v1 编码的 SHA-256；snapshot_id 为 `sha256:` +
SnapshotRef 其余全部字段规范编码的 SHA-256。内容摘要格式为 `sha256:<64 lowercase hex>`。
SHA-256 是安全完整性边界；既有 FNV CommitId/ObjectId 仅做旧模型定位，不能代替它。
SHA-256 由已认证的执行契约绑定；仅给字节附一个攻击方可改的摘要不构成认证。
N3 内容使用版本化 SHA-256 命名空间/映射；不能用 FNV 地址覆盖或混淆不同 SHA-256 内容。
既有 CAS/Commit 格式本期不迁移，新增命名空间需后续 storage 契约实现。

缺失对象 → INPUT_UNAVAILABLE；SHA-256/长度不符 → INPUT_INTEGRITY_FAILED，
均在执行前拒绝，command_start_count=0。输入在目标端核实后才进入 Running。
接受 Task 时持久保护快照、待登记产物和未交付输出；启动先重建 roots 后再运行 GC。
最终交付/确认取消后可释放 Task pin，但显式保留快照、冲突分支和其他存活引用仍受保护。

## 5. 生命周期、结果与观察

TaskPhase：Waiting → Preparing → Running → Finalizing → Finished。
等待时允许取消/拒绝，准备失败不进入 Running；已启动进程必须先退出并 reap 才 Finished。
phase 不表达成功，TaskOutcome 为 Unfinished / Completed / Failed / Cancelled，
由提供方 TaskOwner 恰一次持久提交；Finished 必须伴随已确认终态。
PendingVerification 是查询视图的 observation 字段，不是可覆盖终态的业务状态。

| 情况 | execution | delivery | TaskOutcome / 用户视图 |
|---|---|---|---|
| 接受/准备/运行 | NotStarted / Running | Pending | Unfinished |
| 退出码满足契约、全部必需结果已可访问 | Exited | Complete | Completed / Succeeded |
| 非允许退出码，结果已登记 | Exited（保留真实 exit_code） | Complete | Failed(WorkloadExit) / Failed |
| 命令退出，但上传暂时失败 | Exited | Pending（retryable error） | Unfinished / Finalizing |
| 必需产物确定缺失 | Exited | Failed | Failed(ArtifactMissing) |
| 已确认取消且进程已 reap，或确认从未启动 | Stopped / NotStarted | NotRequired | Cancelled |
| 超时停止且已 reap | Stopped(reason=Timeout) | NotRequired | Failed(Timeout) |
| 连接丢失或执行端结局未知 | 保留最后已确认值 | 保留最后已确认值 | observation=PendingVerification，禁止推测终态 |

success_exit_codes 默认 [0]，提交时显式化；非零退出码可作为完整交付的测试结果，
result_confirmed=true 与 workload_succeeded=false 分开记录。
delivery Complete 指日志已登记且所有 required 输出已验证、登记、可以授权获取；
outputs 为空也必须能按 TaskId 读取日志和真实退出码。
TaskView 含 task_id、accepted_contract、contract_digest、phase、outcome、
error、execution、delivery、cancellation、cancel_request、observation、last_event_seq、
session_ids、artifact_ids。除 cancel_request 和 observation 外这些状态来自提供方事件。
真实退出码仅在 Exited 时存在；信号停止记录 signal/reason，不伪造 exit_code=0。

### 取消、超时与竞态

提供方 durable 接受 cancel 后记 Requested，执行侧确认从未开跑或已停止/reap 后才 Confirmed。
提供方 TaskCancellation.state 仅由提供方事件更新，不能由请求方伪造 Requested。
不可达时，请求方 daemon 先持久保存 `(TaskId, principal, provider)` 作用域的取消 outbox；
保存成功才回 CancelPending，TaskView.cancel_request 为
`{origin:RequesterIntent, state:Queued, requested_at_unix, reason, error:null}`。
这时权威 cancellation 保持最后确认值（如 None），outcome 保持 Unfinished，
observation=PendingVerification。写入失败返回 PERSISTENCE_FAILED，不能假称已排队。
同任务的重复 cancel 共用该 intent、幂等恢复。冷启动恢复 outbox 后重连送达，
收到提供方 durable 接受后 state=Acknowledged；拒绝则 Rejected 并保留结构化 error。
未收到 ack 时重传 cancel 不重传任务提交，不产生第二个 TaskOutcome writer。
最终停止由权威 cancellation=Confirmed 证明；outbox 只能确认送达，不能证明停止。
提供方原生视图没有本地请求时 cancel_request.state=None，origin 仍显式为 RequesterIntent。
已确认自然退出先于取消生效时权威 cancellation 返回 TooLate，
继续按真实退出和产物契约整理结果；不能用取消覆盖已确认 Completed/Failed。
撤销执行权限触发同一停止路径，原因 Revoked；不允许继续开始新的进程或数据传输。
日志/结果查询仍单独受查询权限检查，撤销执行权不等于公开历史数据。
timeout_seconds 从执行端确认启动计时，由本地单调时钟执行；重连不重置预算。
准备/交付另设提供方接受时明示的 prepare_deadline_unix/delivery_deadline_unix；
准备逾期确认未启动后 Failed(PrepareDeadlineExceeded)，交付逾期保留已确认执行结果并
Failed(DeliveryDeadlineExceeded)。未知执行状态不能仅因墙钟逾期而宣布停止。
Owner 管理进程/工作目录/取消/Join/Reap；进程子树全部停止才确认取消，清理幂等。

## 6. 日志、Artifact 与恢复

日志以 `(task_id, stream, offset)` 定位，stdout/stderr 独立字节 offset，分页返回
next_offset、eof、truncated；达到 log_bytes 时明确标记截断，仍持续 drain，不能阻塞进程。
重连可重复读同一 offset；不承诺两个流之间有全序。

outputs 是明确相对文件路径及 required 标志，不使用未定义 glob 语义。
ArtifactRecord 至少含 artifact_id、task_id、snapshot_id、environment_digest、
producer_node、workspace、owner_principal、path、size_bytes、content_sha256、
storage_ref、created_at_unix、retain_until_unix、publication_state。
输出收集与输入相同的路径/链接防逃逸规则；不存在必需文件明确失败。
storage_ref 不是访问凭证；每次获取仍验证 Workspace、主体与授权。
单个文件校验、持久保存、登记完成后才 Published；部分上传保持 Pending。
补传不触发命令重执行。跨 Workspace/越权读取拒绝并审计。
达到保留期并且没有 active Task、pending delivery、显式保留或其他 root 才允许回收。

接受 → StartIntent durable → 启动执行适配器 → Started durable →
ExitConfirmed durable → Published/交付确认 durable → TaskOutcome durable。
StartIntent 与 OS spawn 不是原子操作：崩溃窗口一律待核实，用任务标签/持久执行句柄
向执行适配器核实原进程；无法核实不得自动 spawn 第二次。
明确确认执行记录及进程已丢失后可 Failed(ExecutionLost)，未知时保留待核实。
进程身份必须防 PID 复用（持久运行句柄/启动身份），不能仅凭 PID 判断。
冷启动先恢复 Task/幂等索引/pins/输出暂存，再允许新任务和 GC。
提供方事件单调 event_seq；镜像去重并拒绝回退，终态事件不可覆盖。
崩溃后结果镜像不能把现有 N2 孤儿 Session 的 Failed 推导成 Task 失败。
资源和 journal 的撕裂/损坏返回 STATE_CORRUPT，保留取证；不清空记录重建假成功。

## 7. CLI 与结构化 API

新增 `nexus task submit --request <json-file> --json`，只读 `task show <id>`、
`task logs <id> --stream stdout|stderr --offset <n>`，`task cancel <id>`，
`task artifacts <id>`，`artifact get <id> --output <path>`。
所有任务操作走 daemon 的统一 Application Service，CLI 不直接持有领域 TaskOwner。
artifact get 默认拒绝覆盖现有文件；临时下载、SHA-256 验证后原子发布。
跨节点 Submit/Get/ReadLogs/Cancel/ListArtifacts/GetArtifact 是版本化消息，
由现有 Delivery 适配，不把 HTTP/TCP/容器类型传入 portable DTO。
LocalAPI 路由规范在实现该批次前补契约，不假装已有端点。

Envelope：schema_version=1、verdict=PASS|FAIL；成功时是 task/artifact/logs，
失败时 error 至少有 code、retryable、task_id（若已接受）、reason。
PASS 表示请求已正确处理，例如 show 可返回 Failed Task，cancel 可返回 CancelPending；
必须读取 task.outcome 判断工作结果。CLI 保持现有用法 exit 2、业务 envelope exit 0。
权限类 AUTH_DENIED、不可达 PROVIDER_UNREACHABLE、版本 UNSUPPORTED_VERSION，
以及 INPUT_* / ENVIRONMENT_MISMATCH / CAPACITY_UNAVAILABLE / IDEMPOTENCY_CONFLICT /
ARTIFACT_* / STATE_CORRUPT 均结构化保留；不把错误文本当判别名。

当前 `run ... -- <command>` 的 N2 UNSUPPORTED 冻结期望保持有效；N3 本期使用
task submit 独立入口。后续若接通白皮书 run 便捷语法，必须单独 requirement-change，
不可在实现时悄悄改旧 Scenario。本期 `schedule` 不接 TaskOwner。

## 8. 验收场景与证据边界

`scenarios/product/n3-*.toml` 共 22 条，覆盖提交、输入不变/损坏、环境不匹配、幂等/冲突/过期、
非零退出、断线恢复、取消待确认/竞态、超时、产物补传/缺失/损坏、越权、路径逃逸、
日志配额、GC roots、接受原子性和崩溃恢复。
全部场景声明未来 verifier，由它编排真实 CLI/Application Service；旧 CLI 的独立入口探测
另存 Red Evidence，不冒充已运行的提交 E4。多步骤场景声明未来
`apps/nexusd/examples/n3_task_e4.rs`，该 verifier 在本阶段尚不存在。
未来 verifier 只编排真实 CLI/Application Service/文件/受隔离进程，不能合成领域成功值。
必须记录请求、返回、日志、运行标签、产物字节及摘要对应的独立观察，
用于解释各字段；`command_start_count` 必须来源执行适配器/OS 的真实启动记录。
不得为了返回 summary 临时搭建第二个 Task 状态机。

多步场景用实际不同进程的请求方/Provider，在本机验证 E4 产品行为；
不能把两个进程误称双机或 Windows 兼容证据。Windows→Linux E5 单独验收，
须记录两机 node_id/OS/locator、实际环境 digest、Snapshot 和获取的产物摘要。
全套 E4/E5 变绿、安全前置和 fresh Full Evidence 满足前不得宣称 N3 可用。
契约阶段缺少 verifier 时 BLOCKED 是明确 Red，不能记为产品测试 PASS。

## 9. 实现分批与冻结

1. N3-1：domain DTO/纯状态约束、accepted record/幂等持久化；不 spawn。
2. N3-2：Workspace Snapshot、SHA-256 命名空间、输入核实、durable pin。
3. N3-3：受隔离 Linux executor、环境/配额校验、日志、真实退出与取消。
4. N3-4：Artifact 登记/授权获取、断点补传、交付语义。
5. N3-5：CLI/API 装配、StartIntent 崩溃核实、真实 Windows→Linux E5。

本文件、PRODUCT §17、ARCHITECTURE §12、N3 MODULE 增补、JSON schema 及
n3-* Scenario expectation 在 Red 后按 `.evidence/red-n3-model-v1/freeze.json`
列出的 SHA-256 文件清单冻结。标记存于 Evidence，避免自引用 hash。
后续只修改实现和新增更严格测试；需求变化重新 Contract-First。
