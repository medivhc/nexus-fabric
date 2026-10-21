# N3-13 远端固定输入 Task 接线契约草案

状态：**DRAFT / 未冻结 / 未实施 / 未运行 RED**。日期：2026-10-19。
本文件是供协调者与独立契约/测试评审使用的提案，不替代 PRODUCT、MODULE、旧 wire 或冻结 Scenario。
写作基底为 `a97cfc0b63766a585d0194cebf5568be3092f92a`，叠加 N3-12 候选源码摘要
`6d05c24d5badf97166cb0ebd45ff44d0cf41f9b9b0f72ef96ded1454dbfba485`；
该依赖的最终独立 Review/Full 尚未验收。基线采纳记录在 `.evidence/n313-contract18/baseline-adoption.json`。
本文所有“应/必须”描述拟冻结行为，不能解释为当前能力已存在。
本轮回应独立报告 `.evidence/n313-contract-consistency19/` 的 CC19-01–08；该报告不是验收。
D1/D2/D4/D4b 的已选骨架标为 **coordinator-selected candidate, pending formal freeze**；
该标签只指显式私有remote配置/单active固定key binding、单连接单请求HTTP1.1路径且不远传token、
多Staged消歧与保留原Staged/charge的copy交接。本轮补充的Host/status/deadline/配置生命周期细节仍是
待协调者复审的建议；其余精确缺口标为 **UNRESOLVED / 冻结阻塞**，本轮不转为已冻结或实现可用。

## 1. 来源、范围与不可改动的边界

真相顺序：用户任务 → PRODUCT §17 → ARCHITECTURE §2/3/12 → 相关 MODULE/Public API → 正式契约/Scenario → 实现。
主要依据为 `docs/N3-MODEL-CONTRACT.md` §§1–8、N3-6 §§2–6、N3-8、N3-12 §§2–5 与
`docs/N3-11-14-EXECUTION-PLAN.md`。readiness 分析只作为索引，本文已逐项回读这些依据及实际接口。

本批拟实现 Linux 请求方 daemon 到指定 Linux provider 的保密、双向认证 Snapshot 与 Task 操作，
完成 Staged → 原权威接受 → 接受后准备 → 真实 Plan/Session → 原 executor → 日志/Artifact 恢复。
CLI 仍只访问本机 daemon 的统一 Application Service；不在 CLI 创建 TaskOwner、持有 provider 私钥或执行 workload。

保持以下冻结边界：

- TaskRequest 恰为 Submit/Get/ReadLogs/Cancel/ListArtifacts/GetArtifact；schema1 原字段、摘要与响应相关性不变。
- SnapshotRequest 恰为 Begin/PutChunk/Get/Seal/Cancel；原 schema1 UploadState 与 durable-prefix 规则不变。
- LocalAPI 的 numeric loopback/私有 Unix socket、token、HTTP framing 与现有业务错误不放宽；不把 token 发给远端。
- N2 明文准入不承载命令、输入或日志；不改 `run ... -- <command>` 的 UNSUPPORTED 期望。
- 原 Core Planner、daemon 唯一 SessionManager、TaskOwner、capacity-owner、executor owner/reaper 各保持唯一所有权。
- Delivery/Fabric 不依赖 Compute/Workspace；业务 codec、可信 context 与存储装配放在组合根。无预设新 crate/依赖/trait。
- 完整原 22 条 N3 Scenario 期望受保护；有限基础 E4 不替代全套。Windows→Linux E5 单列 N3-14。

正式冻结前仍需按 contract-first 更新适用 PRODUCT/MODULE/新增场景，在旧真实 binary 上取得 FAIL/BLOCKED RED，
使可编译 RED 测试通过独立盲评，再记录冻结清单/hash。本草案不跨越这些门禁。

## 2. 当前可复用接口与已核实缺口

| 边界 | 真实入口/事实 | 本批必须补齐 |
|---|---|---|
| 保密认证 | Fabric `connect_mtls`、`bind_mtls`、`mutually_authenticated_peer`；`FabricIdentity::from_ed25519_seed` | 复用固定 N2 身份；逻辑 provider→expected key；可信 context 装配 |
| 授权 | `Principal::from_ed25519_public_key`、`authorize_use`/`authorize_contract`；SnapshotService 接受 TaskCallContext | 每操作当前 Use/owner/scope 与拒绝审计，不能调用本地主体 wrapper 冒充远端 |
| 有界传输 | Fabric SendStream.write 扩展 send_buf，driver 持续扩展 recv_buf；命令队列也须审计 | 端到端收发/握手/连接/command 队列与解码内存真正有界；业务长度检查不足 |
| 接受 | `TaskOwner::accept_verified`、`FileTaskAcceptanceStore::transact_with_boundary` 与 capacity envelope v2 | 有预算的 staging→strong CAS 交接与恢复；原事务接受 Task/key/pin/reservation |
| 准备 | 现 Submit 授权后 Unsupported；`TaskSessionBridge::bind_existing` 只绑定实际已有 Session | 请求方原 Planner/Manager 持有资源 Session；现同 root bridge 的远端双端映射仍 UNRESOLVED |
| 执行 | `LinuxTaskExecutor::run/reconcile` 有 owner.lock、StartIntent、真实环境与 start 复检 | 正式 approved-image 配置与真实 Engine qualification；生产 open 当前是空 allowlist |
| 请求方 | RequesterMirror/FileTaskRequesterStore 与 ArtifactDownload 已存在 | 远端代理、持久镜像/取消 outbox/分页恢复；不合成 provider 终态 |
| 完整验证 | 原 22 场景引用 `apps/nexusd/examples/n3_task_e4.rs`，当前文件不存在 | 真正 verifier 编排两进程/CLI/Engine/文件与全部既有断言 |

## 3. 运维、路由与实际 CLI（提案 D1）

**coordinator-selected candidate, pending formal freeze**：不扩展只有 provider/workspace 两字段的
`task-api.toml`，新增显式 opt-in 私有
`<config-root>/task-remote.toml`，由正常 daemon 装配，缺失时维持当前本机行为与能力拒绝。
文件上限 64KiB、固定 schema_version=1、拒绝重复/未知字段；Linux 权限/所有者/nofollow/single-link
与已有私有配置规则一致。provider listener 与 requester bindings 是不同角色，不自动同时开启。
字段候选如下；准确序列化语法及验证仍须正式冻结。首期配置在 daemon 启动时读取，不支持热重载：

```toml
# provider 角色示意；不是已支持的配置
schema_version = 1
[listener]
bind = "192.0.2.20:7443" # 显式 numeric UDP locator
requester_public_keys = ["<64 lowercase hex raw Ed25519 public key>"]
approved_images = ["sha256:<64 lowercase hex immutable image ID>"]

# requester 角色在其自己的 root 中使用；同一例不表示同时启用
[[providers]]
provider = "prov-linux-build"
workspace = "ws-build"
endpoint = "192.0.2.20:7443"
peer_public_key = "<64 lowercase hex expected provider public key>"
```

provider scope 来自既存 N3-11 binding/task-api，listener 不再声明另一个身份或任意 authority root。
双方只读既存私有 N2 身份并导入 Fabric；缺失/不一致/权限不安全必须拒绝，不能生成新 key 使原 grant 漂移。
CLI 不通过参数提供 seed/principal。原 grant add 可对 requester 公钥派生的 principal 显式授予 Use；
握手 allowlist 只允许接入，不产生 resource Use。没有静默 TOFU、key rotation 或 provider fallback。

首期每 requester root 只允许一个 active provider/workspace binding，绑定完整 provider key，
不从旧不透明 ID 推导 provider/workspace。Submit/Begin 必须匹配该 binding；有 mirror/UploadId/Artifact
索引时必须同时匹配原 scope/key；缺镜像的旧 ID 查询只能发往该唯一已配置 binding，由 provider 按原
owner/scope 校验，不能广播、枚举别的 provider、借 provider 本地主体代发，或因 mirror 缺失推断未接受。
首次 Submit ACK 丢失仍由原 request/key/TTL 重交恢复，不能以 TaskId 猜接受记录。
配置缺失/禁用时维持原本机入口；已经记录为 remote 的 ID/intent 不回退本机 authority。
重启禁用 remote 时保留 mirror/outbox/key binding，不发 remote RPC，明确能力拒绝并保持待核实；
不能清空 outbox、取消 Task 或释放 pin。存在未结清 remote 记录时，变更 provider/workspace/key 明确拒绝，
不自动重绑、TOFU 或 key rotation；旧记录的迁移/安全清退流程仍 UNRESOLVED，不以禁用绕过。
本机 legacy 操作沿原认证入口；启用 remote 时既有 local ID 与 remote ID 的冲突处理/迁移需 D1 精确冻结，
未定义时拒绝歧义，不能靠探测本机与远端两处 authority 选一个。

现有用户命令保持：

```text
nexus snapshot freeze WS --config ABS_ROOT --commit COMMIT --include PATH --output ABS_NEW_BUNDLE --json
nexus snapshot upload --bundle ABS_BUNDLE --provider PROVIDER --resource RESOURCE --key UPLOAD_KEY --json
nexus snapshot status UPLOAD_ID --json
nexus task submit --request ABS_REQUEST_JSON --json
nexus task show TASK_ID --json
nexus task logs TASK_ID --stream stdout --offset N --json
nexus task cancel TASK_ID --json
nexus task artifacts TASK_ID --json
nexus artifact get ARTIFACT_ID --output ABS_NEW_FILE --json
```

这些是现有语法的目标接线，不声称目前 remote 功能存在。`--addr`/`--socket` 仍指定本机 daemon；
remote locator 只能由 daemon 的显式 provider binding 选择，不解释 `--addr REMOTE` 为远端直连。
源 bundle 仍按原 N3-12 在所有 upload 成功出口重新验证，包括 Begin 已 Staged/Seal ACK 等快捷路径。
正式操作顺序为既存真实 Workspace/Commit → freeze → provider init/staging-init/实际资源注册与 grant →
双方显式 key 配置 → daemon preflight/recovery → upload/Seal → submit → show/logs/artifacts/get。
N3-11 init 与授 grant 不等于注册了可规划资源；缺真实资源保持明确拒绝。
双方 bootstrap 只读各自 root 既有 N2 身份；可用资源的真实注册命令、Advertisement/ResourceId/name
与 Planner 参数仍见 D6 UNRESOLVED，以上顺序不是已可执行的完整 runbook。

## 4. 可信认证与 wire（提案 D2）

双方先完成 Fabric TLS1.3 mTLS。client 必须 pin 配置中与逻辑 provider 绑定的完整 32-byte key；
provider 必须验证 requester CertificateVerify 且命中显式 key allowlist（空列表拒绝全部）。
两端 `mutually_authenticated_peer()` 必须为 Some，raw key 必须匹配；旧 `peer()`/占位身份不是证明。
0-RTT 与认证前应用数据禁止。IP/port 是 locator，不是 Principal。

provider 的唯一可信 context 路径为：

```text
completed mTLS accessor(raw requester key)
  → Principal::from_ed25519_public_key(raw key)
  → TaskCallContext::from_authenticated(principal, configured workspace)
  → TaskApplicationService/SnapshotService
```

该 constructor 本身只校验字符串，不认证；安全证据来自其调用者掌握已认证连接，不来自公有函数名。
请求/header/配置里任意 principal 字符串均不得替代此链。远端不调用 `execute_local` 使用 provider 自身主体。
Submit 的 provider/workspace/resource 与 scope、已有记录的 owner、SnapshotRef 全部复核；GetArtifact
回溯原 accepted contract。Begin/Put/Get/Seal/Cancel 同样每次检查 owner/scope/当前 Use。
每次操作与实际 spawn 前从原 N2 grant authority 重读当前到期/撤销状态；每次拒绝写真实原因审计，
审计失败返回 PERSISTENCE_FAILED，不能成功或伪造 grantdeny。
这只保护操作准入；运行中 grant 到期/撤销还必须走 §8 的独立发现 → durable Revoked → stop/reap 路径，
即使 requester 不再发 RPC 也必须生效，不能以 spawn 前或下一次 RPC 检查替代。

**coordinator-selected candidate, pending formal freeze**：mTLS Fabric 单条可靠双向 stream 内
使用有界 HTTP/1.1 JSON framing，
路径为 **`POST /n3/v1/task` / `POST /n3/v1/snapshot`**（和 LocalAPI 监听入口分开），
body/response 直接为原 schema1 DTO/envelope。没有新 Task operation、principal、UploadId Submit 字段或 output path。
一连接一 stream、一 stream 一请求，响应后关闭；不用 datagram 发送业务。Host 候选固定 `n3.v1`，
只作 framing 校验，不作身份/DNS来源；任何 Authorization header 均拒绝，不把 LocalAPI token 传远端。
已识别 task/snapshot 路由使用各自原 schema1 envelope：framing/Host/DTO 错误 HTTP400+INVALID_REQUEST（未知schema仍为UNSUPPORTED_VERSION），
长度/已识别有界配额超限 HTTP413+CAPACITY_UNAVAILABLE，错 method HTTP405+INVALID_REQUEST；
正常业务处理含 Use/owner 拒绝为 HTTP200，不能把业务 AUTH_DENIED 改成 LocalAPI token 的 HTTP401。
无认证连接、无可安全识别路由、来不及在剩余预算发送完整 frame 或无连接名额时直接关闭，
不伪造 Task/Upload envelope，也不等待剩余 body。原 LocalAPI HTTP401/token/路径行为保持原契约。
此 Host/status/close 表同为 D2 候选，须正式冻结；mTLS失败无业务 envelope。
Task 接纳文本规则保持原行为；Snapshot 仍要求原 canonical bytes 完全相等。
禁止 Transfer-Encoding、重复关键 header、query/编码路径别名、pipeline/尾随第二请求、截断与长度冲突。
16KiB header/1MiB request/2MiB response 在任何长度对应分配前检查，认证完成前不读业务 body。
原 `nexus_transport::FrameStream` 绑定明文 TcpStream 且按 u32 长度分配，不能直接用来声称此适配已完成。

## 5. 字节、并发、内存与 deadline（提案 D3）

复用现 N3 adapter 上限：manifest≤65,536 bytes；files≤1,024；snapshot logical bytes≤67,108,864；
chunk/page raw bytes≤65,536；所有计数/加法 checked 且≤2^53−1。
N3 wire 上限是 adapter admission 限制，不把更小能力包装为任意合法大 DTO 都可执行。

| controlled resource | 拟定硬上限/行为 |
|---|---|
| pending handshake + live connection | provider 共8，requester 共8；名额在分配状态前取得，第9个拒绝/关闭，无等待队列 |
| stream/inflight request | 每连接整个lifetime仅1条bidi/1请求，共8；额外bidi/uni/datagram拒绝；无等待中的完整请求body |
| app send/recv FIFO | 每方向每连接64KiB；driver 与 app 共享额度，收到未消费字节不得继续 drain QUIC |
| QUIC send/reassembly windows | 每连接各≤256KiB；crypto/握手缓存亦有独立硬限；不能只限制 app FIFO |
| driver commands/accepted queue | command≤32、accepted≤8；Pump coalesce；满时显式背压/拒绝，不能 unbounded mpsc |
| 业务分配 | 单请求raw≤1MiB、响应raw≤2MiB；解码 DTO/node/string/副本需有可核算 ceiling |
| gateway controlled heap | 候选总 ceiling=128MiB，含上表、encoder/parser、连接/握手/队列元数据；不含 engine workload与原authority缓存 |
| connection clocks | 单一 handshake预算10s；认证后header/body/响应合计30s绝对deadline，不随小段进度重置 |
| close/worker ownership | daemon持有listener/connection/worker/reaper；关闭/取消唤醒阻塞读写，join上限5s，剩余未知资源明确报告 |

send 满时只接受可容纳的前缀或可重试阻塞，不能复制完整待发 body 到另一个未计费队列；
recv 满时停止读 QUIC并依赖流控，不能“读完再拒绝”。超长声明、慢读方、永不EOF、洪泛新流、
无效握手都必须在上述上限内回收。业务请求断线取消的是 RPC观察，不自动取消或重执行已接受 Task。
prepare/执行/交付分别沿原 accepted deadlines/timeout，不因RPC30s延长或缩短。

**D3 UNRESOLVED / 冻结阻塞**：当前 Fabric API 没有这些背压保证。上表 provider 8/requester 8
尚未定义同进程双角色共享还是相加，不能据此认定部署总额度。必须冻结在任何连接/握手状态分配前取得
许可的真实边界、每类分配上限和 allocation/counter 证据：lossless parse tree 的 depth/node/string 总量、
DTO/encoder/clone 副本、拒绝前状态、QUIC crypto/reassembly/send/packet、driver command payload、
等待中的线程/队列与 timer，审计所有 VecDeque/mpsc 后再确定最小 additive API。
128MiB 仅是待逐项复算的 gateway controlled heap 候选，不是进程 RSS、整个 daemon/requester 内存承诺；
排除项 engine workload/原 authority 缓存不能偷偷计为零，D8 mirror/outbox/日志缓存另有未决预算。
已封存独立只读审计 `.evidence/n313-bounded-transport-audit19/summary.json`（SHA-256
`212ac754bf2eec62dec34992234654db5ad61c0454e3bb764cecc4eff9fd59e8`）的结论是
E1_STATIC_ONLY / D3_UNRESOLVED / BLOCKED_FOR_FREEZE；不是实现批准或验收。它指出即使限制live连接，
accepted queue的stale IDs、已完成stream的lifetime map仍需回收；现有public Sender/可变低层state
不能静默换型以绕过兼容审查。read_deadline缓冲数据快路径、server握手绝对时限、UDP drain/command调度公平性、
取消/Drop唤醒与有界join也尚未证明。QUIC窗口/crypto乱序区间不等于TLS/packet metadata总heap硬限；
authority来源的RPC clone/编码仍属gateway增量内存，不因原缓存排除而免计。
冻结要求逐项 byte accounting 与真实压力测试；不能实现时保持 listener disabled/BLOCKED。
不得为此改变旧 Fabric 流无损/S4及既有调用的冻结预期；需要行为不兼容时显式 Contract Conflict。

## 6. SnapshotRef 选择与兼容的 staging 交接（提案 D4）

Submit schema1 无 UploadId。新接受之前在原 acceptance lock 内先检查 scoped key：
同一未过期 request_digest 返回原 TaskId/contract/TTL，**不要求原 upload 仍存在、不再导入、不增加任何预算**；
不同 digest 精确 IDEMPOTENCY_CONFLICT；replay 仍须当前 Use/owner/scope，不放过撤权。
TTL到期按原契约允许新 Task，不用同 key 承诺永久去重。

新接受按 `(authenticated principal, provider, workspace, resource, full canonical SnapshotRef)`
查找本 owner 的 Staged records，不能只比 snapshot_id，也不能借其他主体的等内容跳过 reservation。
候选0个→INPUT_UNAVAILABLE；恰1个→选原 UploadId；>1个→INPUT_UNAVAILABLE、reason明确 ambiguous staged input，
不挑“最新”、不返回 foreign UploadId；owner须显式Cancel多余上传再重试。Receiving/Cancelling/Cancelled不合格。
选定后持锁重新验证原 binding/manifest/所有blob SHA、cwd与路径限制；损坏返回 INPUT_INTEGRITY_FAILED 或 STATE_CORRUPT，
不能自动refreeze/修复、不能把本机路径当输入。此保守消歧方案是 **coordinator-selected candidate, pending formal freeze（D4）**。

**D4b coordinator-selected candidate, pending formal freeze：copy handoff，保留原 Staged。** 导入strong CAS与accepted pin成功后，原 upload
仍保持Staged、原字节、原UploadCharge；owner可以之后调用既有snapshot Cancel，物理删除/fsync后才返还staging charge。
取消已选upload与accept并发时按锁序线性化：cancel先取得staging并完成则accept无输入；accept先持有两锁完成则
accepted pin保护独立strong内容，之后Cancel只清staging，不取消Task、不删除accepted输入。
不增加Consumed状态、不把成功传输伪装成Cancelled、不把Staged变成无字节/零charge视图。

这里故意不自动释放staging。原N3-12明确要求“AcceptedContract/input pin durable后才release”，
但未授权改变旧state/view/Cancel行为。自动transfer/release若为本批必须项，标记 **Contract Conflict D4b**：
另起requirement-change补充新版本state/view及迁移、重新RED/hash；或设计既有owner显式Cancel的独立客户端步骤，
不能由provider冒充用户发送Cancel。不能静默给Submit增加UploadId。

## 7. 锁序、预算与逐phase恢复（提案 D5）

交接严格 `acceptance.lock → staging.lock`，释放反序。不得持staging反调会再取acceptance的stage_snapshot/release_preview。
授权/audit callbacks在这两锁外；锁内只复核已观察的 scope/binding/输入，不声称存在 grant authority generation。
N3-10 只保证原子读取完整 grant 前/后版本；旧 generic writer 不共享其 mutation lock，没有统一 generation
或跨旧 writer 事务隔离。观察点是双锁外一次真实 current Use 读取及审计；实际 spawn 前再次读取。
读取失败/不一致拒绝新接受或启动，不使用缓存 Allow。该模型存在接受观察后撤权的窗口，不能宣称
accept 与撤权线性隔离；已接受 Task 仍受 §8 运行中发现/停止约束。
**CC19-07 / D5 UNRESOLVED**：精确重核实边界、所有 grant writer 的一致性语义与验收观察尚未冻结，
不能用未定义 generation 弥补。SessionManager/bridge locks、Engine IO与网络回复不在交接双锁内执行；
完整全局锁图必须列明 acceptance/staging、grant/audit、bridge cleanup、Manager、Task runtime 与 GC，
包括现 bridge 持 Manager 回调 TaskOwner 的边，避免反向环。流式输入校验/导入在持锁期有既定64MiB上限和owner，不能开无owner任务。

预算必须并存，不抵扣：

1. 原staging账本继续按N3-12 GlobalCharge+UploadCharge收费，直到原Cancel物理清理完成。
2. 新task按原capacity policy.demand完整预留：包括backend `3*input + 2*80MiB archive + 2*storage + 2*logs + 2*metadata + overhead`，
   runtime与memory/PID/slots亦不变；full snapshot logical size用于收费，不用跨owner dedup免除。
3. 导入中尚未accepted的strong文件/临时副本、handoff journal原+tmp与目录也要预留，不能写完才算或借未提交task reservation。

候选最小方案：固定最多一个交接事务（原acceptance lock串行）；独立retained初始化receipt绑定原root/identity/policy，
私有checksummed handoff record≤64KiB，原+唯一替换tmp≤128KiB，整个metadata布局≤1MiB。
import payload allowance候选 `2*sum(A(unique blob bytes)) + 2*A(manifest bytes) + 1MiB`，A沿N3-12的4096roundup。
必须在原capacity authority内先durably reserve该pending allowance；accepted时原子转换为原task demand，
不能与同一task导入成本重复释放，也不能把配置中的fixed reserve无解释再消费一遍。
**D5 UNRESOLVED / 冻结阻塞**：精确authority schema/计费映射、固定允许文件集合、future serialized ceiling、
pending reserve→accepted demand 的单事务转换和旧pool显式兼容策略尚未定案。即使单列 import 预算，
也必须从属唯一已配置 capacity authority，不能成为第二个可独立变化的容量账本。
应审计原task demand的已有副本/metadata覆盖后才选私有版本化envelope；H1/H2 的每个强CAS digest
还须证明临时/共享文件归属及其reservation与pin关系，不能把同digest的其他Task/owner文件当自有副本清理。D5未冻结之前不可写入生产数据；既有pool绝不静默upgrade/reprovision/改policy。
没有空间/序列化cap余量在写payload前CAPACITY_UNAVAILABLE；write/fsync/rename/ENOSPC真实失败PERSISTENCE_FAILED。

| phase / durable boundary | 崩溃恢复必须观察的事实与后续动作 |
|---|---|
| H0 尚未有intent/reserve | 零新Task/key/pin/strong副本；原Staged/charge不变 |
| H1 pending allowance+intent已durable | intent绑定原scope/key/request_digest/UploadId/SnapshotRef/预算及原inode；仅原事务可继续或已证实清理后返还pending allowance |
| H2 strong copy部分/已完整，接受未提交 | owned temp/每digest/长度/inode验证；流式补同字节或删除已证明owned临时副本；原Staged不删除；不能把临时文件认成接受成功 |
| H3 Task/key/input pin/capacity单事务durable | durable原接受账本为唯一承诺；重试返回同Task，pin立即是GC root；journal缺最终marker也不得回滚Task或重收reservation |
| H4 ACK前/后断线、journal收尾 | 仅清已证明owned tmp与pending转换记录；保留accepted后台disk charge；staging按§6继续原状态 |
| H5 owner显式Cancel staging中断 | 原N3-12 Cancelling recovery，已accepted pin完全独立；确认删除fsync后才归还upload charge |

恢复先验证原receipt/ledger/checksum/inodes与pending allowance，再恢复handoff/accepted roots、Session绑定、StartIntent/Engine、
Artifact/Requester记录，最后才Ready/新接受/GC。preflight必须覆盖新handoff标记；缺失/损坏保留取证STATE_CORRUPT，
不能重建空authority或“未知就删”。现N3-12staging恢复在token/READY前执行；新增次序不得让它越过未恢复accepted roots的GC。
cancel/GC与独立进程accept重试也遵守固定锁与原epoch/live owner检查。

## 8. 接受后真实准备、Session与单次执行（提案 D6）

新Submit在接受前验证当前授权、唯一Staged输入、固定环境实际证据、硬限/能力与可接受的具体capacity；
环境不匹配返回ENVIRONMENT_MISMATCH，不支持隔离/精确配额返回UNSUPPORTED_CAPABILITY，command_start_count=0。
接受事务只承诺Waiting、TaskId、原contract digest/expiry/deadlines与初始空session_ids；不在Get或accept事务创建Session。
ACK丢失可能表示已接受，客户端仅按原key/TTL重交；不能新key自动重试。

正式 N2 所有权必须按两端区分（PRODUCT §16.5 D1/D3、nexus-session MODULE）：

| 步骤/事实 | 权威端与约束 |
|---|---|
| resolve → policy/Core Planner placement/path | requester daemon 的原目录/Planner，绑定其真实 root/identity 与指定 provider/resource；不能先对所有候选建连 |
| 创建/持久资源 Session | requester daemon 唯一原 SessionManager；`open(resource, provider, PlanSnapshot{plan, decision_trace})`，Plan 只内嵌该 Session，不独立持久化为第二权威 |
| Plan 后资源 Establishment | 只按该真实 Plan/Session；provider 仅 admission+lease，不为 requester 的资源使用另建领域 Session |
| provider 接受与执行 | provider root 的原 TaskOwner/capacity/executor owner；不拥有 requester Session 的终态写权限 |
| SessionAttached/恢复 | 必须证明真实 Session 与 Task/contract/principal/provider/resource/root 的关联；SessionOutcome 与 TaskOutcome 仍独立 |

§4 前置 mTLS 连接只承载受限 RPC 控制/输入传输，不是资源 Session，不证明上述资源 Establishment 已完成，
不能将 FabricConn ID、上传成功或 mTLS 握手当作 canonical Plan/Session 证据；两层装配如何一致仍属下列 D6 阻塞。

**D6 UNRESOLVED / 冻结阻塞**：现有 `prepare_with_existing_session` / `TaskSessionBridge::bind_existing`
只核验同 root、同注入 Manager 内实际已有 Active/Unfinished Session、canonical Plan/trace 与 N2 names；
它不能证明另一个 requester daemon/root 的远端 Session。当前没有从这些接口得到合法双端映射，
不得让 provider prepare worker 调其本地 Manager.open 替 requester 建资源 Session，也不能把同root测试
当远端证明。冻结前必须给出：双方实际注册/name/advertisement/ResourceId 与 Planner 调用参数；
requester Manager/root 的真实 Session 与 provider Task/admission/lease 的可核实关联和已有API调用链；
跨文件/跨端恢复关联键及重连/cleanup各自owner；无新wire字段前如何携带并验证所需事实。
如当前API无法表达，先提最小正式契约变更，不能宣称现接口已可直接装配。

provider daemon 持有 prepare worker，来源是原 durable accepted 记录而非 socket 寿命；
其 intent 只能记录 Task/contract、选定资源、请求方身份与原 Session 内嵌 PlanSnapshot 的事实引用/恢复进度，
不能另存可独立演进的权威 Plan。Session 已 durable 而关联未 durable 时，只有证明上述关联后才能补接或
由 requester 原 Manager 幂等关闭并持久补偿；不能盲目再 create。关联/执行未知为 PendingVerification，
保留reservation，不进入executor。确定未启动的准备失败/逾期才由原TaskOwner按原PrepareDeadline规则提交。

executor仍自行验证live capacity/RuntimeHeld、当前Use callback、环境与完整输入，且使用原owner.lock。
原顺序StartIntent durable → 原执行身份/Engine create/start → Started durable → ExitConfirmed →
日志/required Artifact Published并交付确认 → 原TaskOwner唯一终态。Session失败/Disposed不决定TaskOutcome。
StartIntent/spawn/Started任一窗口崩溃必须按原task label、执行句柄/启动身份重附着核实；
Engine404、PID、断线、lease消失均不独自证明未执行/reap，不自动第二次spawn，不延长timeout。
取消先Requested，全部子孙停止并reap后才Confirmed/Cancelled；自然退出先到则TooLate，不覆盖真实exit/终态。

运行中执行权到期/撤销的发现由 **provider daemon 的原 executor owner** 持有监督任务负责，
它随 accepted/运行记录恢复，以原 accepted principal/workspace/resource 从真实 N2 grant authority 独立重读，
不依赖 RPC、客户端在线、grant通知或 requester outbox。到期/撤销发现后由执行owner向原TaskOwner发送事件，
经原TaskOwner持久记录 cancellation Requested(reason=Revoked)，禁止新进程及新的受该执行授权控制的数据传输，
唤醒原取消路径停止进程子树；Join/Reaper 核实所有子孙已停止后才 durable Confirmed/Cancelled。
这是原owner持有执行权威后的内部撤权事件，不能再要求已撤销的Use返回Allow才允许停止；远端Cancel仍走原鉴权入口。
没有运行句柄时也要证明 never-started/无执行authority，不能以无句柄判停止。日志/结果查询继续单独鉴权。
记录写入/授权读取失败不许可继续开始新工作；执行owner保守停止并保留故障事实，不能假报已持久请求或
停止确认。已确认自然退出先于撤权生效仍按原TooLate与真实结果整理，不覆盖既有唯一终态。
冷启动先恢复 Revoked intent/原执行身份并 stop/reap；执行状态、持久记录或 reap 证据未知则
PendingVerification、reservation继续持有、禁止二次spawn，墙钟到期/Engine404不替代停止证明。
RPC AUTH_DENIED及其拒绝审计与这个 owner 停止事实分开；审计失败不能变成继续执行的许可。
**CC19-01 UNRESOLVED / 冻结阻塞**：监督检查的最大延迟、到期时钟/倒退边界、grant读取失败后的
停止与持久补记次序、监督任务/队列预算及跨进程写者观察验证尚须精确冻结，不能只补一句轮询便视为完成。
运行capacity只凭既有proof释放，backenddisk继续收费；Session关闭仍必须由真实requester Manager持久处理，
当前同root bridge cleanup intent 不足以证明远端关闭，属于 D6。

## 9. approved image与真实资格（提案 D7）

普通ProviderService当前以空approved_images打开executor，真实运行会拒绝；这是当前限制。
拟配置仅接受运维显式不可变sha256 image ID集合，空集合拒绝全部，不自动pull/tag resolve或替换image。
接收前和spawn前都验证当前image实际OS/architecture/ID、container+network=none、请求limits可精确表示。
allowlist文件不等于Engine qualified；Docker可连接、固定BusyBox在场或普通测试通过也不等于qualification。

资格证据必须由真实Engine执行核实并绑定Engine/kernel/cgroup/seccomp/image ID/配置：
CPU CFS、memory+swap、PID256、page精确tmpfs/storage与上限64MiB、只读root、非特权UID、cap-drop、
no-new-privileges、seccomp、network=none、无image volumes逃逸；工具链/准备utilities确实存在；
真实日志drain/截断、正常与非零退出、required产物、timeout/cancel子孙stop+reap、StartIntent冷恢复。
每个负例需有同环境合法正控，精确拒绝不能被“image不在allowlist”更早遮蔽。
无法资格化则新接受明确能力拒绝，原22场景相应BLOCKED/UNKNOWN保持，不删expect/skip/降低硬限。
qualification缓存/有效期与capability变更失效策略须D7决议；缓存不能跳过executor现有实际复检。

## 10. 请求方恢复、日志和Artifact（提案 D8）

请求方daemon复用FileTaskRequesterStore/RequesterMirror，scope绑定已pin provider key对应逻辑provider、
本地真实principal与workspace；镜像只接收digest合法、scope匹配、event_seq单调的原provider view。
错TaskId/ArtifactId/stream/offset、旧seq回退、不同contract/环境/输出record拒绝，不能覆盖已持久终态。
连接丢失只设置PendingVerification，既不重Submit也不推断Failed/Cancelled。
首次Submit ACK丢失时，客户端须保留原request/key/有效期并同key重交；不把“还无镜像”解释为未接受。

远端不可达Cancel先将本地intent/outbox fsync再显示cancel_request=Queued/CancelPending；
它不伪造provider cancellation=Requested。重连转发原Cancel，provider持久ACK/拒绝后再结算outbox；
断线重发幂等。查询不可达返回PROVIDER_UNREACHABLE，若呈现cached view必须明确原观察状态。
**D8 UNRESOLVED / 冻结阻塞**：mirror/outbox/日志缓存的最大条目、单记录与总序列化ceiling、
允许文件/tmp集合、memory预算、保留/清退策略及启动预留尚无本批硬限。须定义首次 ACK 丢失时原request/key
的 durable 预算，满额在写前拒绝，不能为腾空间删除未结清intent或把网络有界当整个requester有界。

日志按stream独立offset与64KiB页续读，偏移不重置，无stdout/stderr全序承诺；
provider到log_bytes标记truncated仍持续drain，不能因慢读方阻塞workload。
Artifact下载复用原接收器：先当前授权Published完整record，再打开output/resume，逐页校验原record与offset，
结束后额外当前授权空EOF，完整SHA/长度验证，私有同父临时file/目录fsync/no-replace原子发布。
失败保留原durable prefix，锁忙可重试；不把storage_ref当授权、不覆盖既有文件、不把补传当再执行。
取回Artifact的权限撤销/磁盘满/崩溃不修改provider真实exit；delivery按原TaskOwner事实决定。
Linux接收器先接线；Windows路径/ACL/no-replace平台适配仍属于N3-14。

原 `n3-gc-roots` 还冻结了 `pins_released_after_finalization=true`，而当前N3-8只释放已证实的runtime容量、
保留backenddisk。完整N3不能用“保留全部accepted input永远不GC”代替该期望。
拟由原TaskOwner在每Task真实finalization条件满足后持久记录幂等release事实，只释放该Task自己的input pin。
Completed、Failed（含无required输出/ArtifactMissing）和已证实never-started或已reap的Cancelled都需独立条件，
不能笼统要求每个终态都有实际不存在的 required Artifact；未知执行或pending交付不提前release。
历史AcceptedContract/幂等记录继续可查；boot必须识别每Task已release事实，不能从历史accepted列表无条件复活pin。
显式retain、其他Task、共享digest引用、pending Artifact/delivery等root继续保护。
pin release、tombstone/保留期、物理删除/fsync证明和backend disk返费是四个独立边界；GC沿既有两phase，
sweep前重查可达性和适用保留期，不能把未来回收计成已释放disk，也不能为了删除pin删Task/幂等记录。
**D9 UNRESOLVED / 冻结阻塞**：逐终态/交付组合的release资格与新durable release schema、现有“所有accepted
Task皆root”catalog/ledger的兼容/迁移、适用GC保留期（不可静默绕过workspace既有14天默认）、共享digest归属/
计费和物理清理proof、quota转换及冷恢复顺序均未定。未补齐时完整gc-roots保持BLOCKED，不永久pin代替、不改expect。

## 11. 错误语义与拒绝的可观察性

保持原TaskErrorCode与schema1 envelope；不新增错误字符串充当枚举。业务envelope CLI exit0、用法exit2。
pre-accept error.task_id=null；若已接受必须保留原TaskId并允许同key查询恢复，不能假报“肯定没写入”。

| 条件 | 错误/状态与允许副作用 |
|---|---|
| 错provider pin/未认证/非allowlist | 握手拒绝，零业务dispatch/authority mutation；不向未知对端泄漏Task/Upload |
| 已认证但foreign owner/scope、无/过期/撤销Use | AUTH_DENIED；拒绝审计持久；拒绝RPC自身不改业务authority/泄露输入输出；独立撤权owner仍须按§8停止 |
| framing/未知字段/关联错误 | INVALID_REQUEST；未知schema为UNSUPPORTED_VERSION；零业务mutation |
| frame/队列/预算超限 | CAPACITY_UNAVAILABLE；无新Task，保持已durable reservation，不无界排队 |
| 无唯一Staged/输入不可用 | INPUT_UNAVAILABLE；完整性损坏INPUT_INTEGRITY_FAILED；不创建替代输入 |
| 非批准/实际环境不符 | ENVIRONMENT_MISMATCH；不支持隔离/硬限UNSUPPORTED_CAPABILITY；零command start |
| 同key不同digest | IDEMPOTENCY_CONFLICT；原Task/key/TTL/pin/capacity不变 |
| write/fsync/rename/audit失败 | PERSISTENCE_FAILED；记录phase/可能已提交，不假ACK；保留恢复intent |
| 权威缺失/损坏/不一致 | STATE_CORRUPT；取证保留，不重建、执行或GC |
| 连接/IO deadline | PROVIDER_UNREACHABLE、retryable=true；Task状态未知待核实，不变终态 |

D2候选错误映射：本端可证的错provider key/认证拒绝为AUTH_DENIED；无可核实原因的close/timeout或连接失败为
PROVIDER_UNREACHABLE，不把不明握手close谎称对端allowlist拒绝，不泄漏对方allowlist。无完整frame则不解析业务成功。
D2/D8候选deadline组合：原LocalAPI客户端/Artifact每页 **5秒端到端总预算不变**；remote 10秒handshake/
30秒认证后IO是远端连接的上限，代理实际使用 `min(原请求剩余预算, remote相应剩余上限)`，不另起30秒绕过5秒。
上游断线/预算到期只能停止该RPC观察与IO，不取消provider已接受Task；接受是否发生靠原key/TTL恢复。
prepare/delivery/执行timeout独立沿原accepted契约，不因分页/RPC重置。跨本机代理传递/量测剩余预算的准确接口和
压力观察仍须正式冻结（CC19-08），不能用“remote30秒”静默放宽旧预算。
事件保留provider/task/upload/request/contract/epoch/phase/已认证key指纹关联；不记录seed/token/输入正文。

## 12. 验证、RED/TDD拆分与Evidence等级

本草案阶段没有运行测试、构建、网络或Engine，未生成RED、Contract Hash、Test Review或PASS。
详细requirements→tests映射及逐决策状态在ignored `.evidence/n313-contract18/`，不作为冻结证据。
后续可执行分片及依赖顺序：

1. C0：N3-12候选依赖验收/锁定源码摘要；D1–D9定案，正式契约/场景更新。保持旧22场景与本机边界。
2. T0：旧binary正式CLI/daemon RED；完整verifier缺失记BLOCKED；编译可运行Stub下RED测试，由独立子代理盲评后freeze。
3. T1：最小mTLS/可信context与有界Fabric。两真实进程正控及错pin/匿名/allowlist/Use/owner/撤权；网络压力严格计量。
4. T2：有预算copy handoff+原acceptance。独立进程并发replay/conflict、丢ACK、Cancel/GC以及H0–H5每个write/fsync/kill窗口。
5. T3：接受后原注册/Planner/SessionManager/bridge、StartIntent执行与真实qualification；原终态/cancel/reap/容量释放。
6. T4：RequesterMirror/outbox/log/ArtifactDownload远端恢复；冷重启、撤权、坏record/hash、ENOSPC与no-replace。
7. T5：真实 `apps/nexusd/examples/n3_task_e4.rs` 支持所有原22 case；check→affected→Fast→独立八维Review修复→适用Full。
8. T6/N3-14：获授权Windows requester与Linux provider两台真实机器独立E5；当前没有这些机器/locator/凭据输入，保持BLOCKED。

每个拒绝用例先建立同一业务phase的合法正控，再只变一个条件，精确断言错误code、到达phase、零额外start/接受/预算或输出改变。
不得以is_err、前置unsupported、空allowlist、缺输入或错误HTTP版本遮蔽要测的授权/完整性分支。
每个持久phase在intent前、fsync后、rename后、ACK前kill；包括半写/ENOSPC/原lock inode替换、ledger/receipt丢失，
且独立进程冷恢复验证原TaskId/UploadId/offset/pin/capacity，不能通过测试fixture直接写provider权威记录造绿。
验证程序只编排真实CLI/Application Service/Engine/文件；start_count从实际Engine/OS启动记录取证，不能合成第二Task状态机。

Evidence分级：文档/符号E0；静态门禁E1；纯codec/状态/预算E2；真实持久adapter与故障恢复E3；
两独立Linux请求方/provider进程、真实mTLS+CLI+qualified Engine全生命周期为E4；真实Windows→Linux跨机独立观察为E5。
E4不等于E5；未运行/缺能力不记PASS。全22场景必须逐条报告，缺verifier/环境不适用不能被局部新E4遮盖。
Evidence绑定revision+dirty/source摘要、二进制hash、toolchain、两端配置/公钥（无secret）、Engine/kernel/image ID、
原Snapshot/manifest/blob/取回Artifact摘要、实际日志/退出/运行标签、故障phase、observer原始输出和要求映射。
独立Review者不能是实现/测试作者；Fast/Review/Full任一步未完成只报告Candidate/Blocked，不自行Final PASS。

## 13. 冻结前必须解决的决策

| ID | 必须决议的契约点 | 当前提案/风险 |
|---|---|---|
| D1 | 私有remote配置、真实注册、ID寻址与生命周期 | coordinator-selected candidate, pending formal freeze：显式task-remote.toml、每root单active固定key binding、不热重载；local/remote旧ID冲突与迁移、真实注册仍UNRESOLVED |
| D2 | mTLS framing/status/握手错误/deadline组合 | coordinator-selected candidate, pending formal freeze：单连接单请求有界HTTP1.1/n3/v1，原envelope、不远传token；§4/11具体映射及5秒不放宽仍待正式冻结 |
| D3 | Fabric bounds API、角色聚合、QUIC/command/crypto/parser完整计量 | UNRESOLVED：接口/逐类上界与pressure观察不足，128MiB只为controlled heap候选，不是RSS/全daemon界限 |
| D4 | SnapshotRef多upload消歧 | coordinator-selected candidate, pending formal freeze：仅恰1个Staged；多匹配INPUT_UNAVAILABLE明确ambiguous，owner显式Cancel多余 |
| D4b | copy交接和原upload生命周期 | coordinator-selected candidate, pending formal freeze：copy保留原Staged/字节/charge，owner显式Cancel；无Consumed/zerocharge/Submit UploadId |
| D5 | 唯一budget、pending→accepted事务、schema/迁移/归属/全局锁图及授权观察 | UNRESOLVED：§7公式未证明精确映射，无统一grant generation/跨旧writer隔离；不得第二容量账本/静默借fixed reserve或升级旧pool |
| D6 | 双端注册/Planner/请求方Manager、provider admission+lease与远端Session关联 | UNRESOLVED：现同root bridge不证明远端Session；不得provider另建资源Session/独立Plan权威；未定前不进入executor |
| D7 | approved_images配置、实际Engine资格矩阵/失效、接收前环境证据 | 当前生产allowlist空；socket/image存在不证明资格 |
| D8 | mirror/outbox/日志缓存的条目/序列化/文件/内存/持久预算与保留 | UNRESOLVED：含丢首次ACK的request/key预留，满额写前拒绝；不得删除待核实intent腾空间 |
| D9 | 各终态finalization/release schema、boot/GC保留期/共享digest/返费proof | UNRESOLVED：不要求不存在的required Artifact，不复活released pin；保留其他root，物理删除确认前不返还disk |
| CC19-01 | 运行中grant到期/撤销发现与原owner停止路径 | §8补owner→durable Revoked→子树stop/reap→未知保守恢复；检查延迟/失败补记/时钟与预算仍UNRESOLVED |

这些均未正式冻结；候选选择不再交由实现者任意更换，UNRESOLVED缺口仍是冻结阻塞项。契约Conflict必须另走requirement-change/新RED/hash；
不靠改旧schema、旧场景或降低安全/配额预期解除阻塞。
