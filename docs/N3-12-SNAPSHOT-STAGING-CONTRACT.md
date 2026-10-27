# N3-12 Snapshot freezing and bounded staging contract

状态：契约阶段，待真实 RED、测试盲评及 hash 冻结；生产实现尚未开始。核实基线 `37e0cff`（PR #18 的 N3-11 本地 Candidate），日期 2026-10-12。本文与 PRODUCT §17.9、相关 MODULE、新 E4 场景共同冻结；不改变已有六类 TaskRequest。

## 1. 本批交付与实际入口

本批把明确 Workspace Commit 的选定输入冻结为本地 bundle，经已认证的本机 LocalAPI 上传到提供方私有 staging，并在中断后保留原 UploadId、SnapshotRef、已确认字节与预算。Staged 不表示 Task Accepted、容量 Ready、已创建 Session 或 Engine qualified。本批不执行命令、不发布 Artifact、不提供远端明文上传。

现有正规 Workspace 持久入口确实存在：`workspace.toml` 的 `[[workspace]]`，daemon 派生的 `data/cas/`、`data/workspaces/<id>/state_root`，以及 `Workspace::open` / `freeze_snapshot`。`WorkspaceManager::start` 目前同时负责 open-or-create 与 FUSE mount；新 freeze 不能调用这一入口，不能因缺 anchor 自动创建 Workspace，也不能扫描挂载目录、WorkingSet 或自动选择 Head。

正式入口：

```text
nexus snapshot freeze <workspace> --config ABS_CONFIG --commit COMMIT_ID
  --include PATH [--include PATH ...] [--exclude PATH ...]
  [--executable PATH ...] --output ABS_NEW_BUNDLE [--json]
nexusd task-provider staging-init --config ABS_CONFIG --budget ABS_POLICY [--json]
nexus snapshot upload --bundle ABS_BUNDLE --provider PROVIDER --resource RESOURCE --key UPLOAD_KEY
  [--addr LOOPBACK_IP:PORT | --socket ABS_SOCKET] [--json]
nexus snapshot status UPLOAD_ID [--addr ... | --socket ...] [--json]
nexus snapshot cancel UPLOAD_ID [--addr ... | --socket ...] [--json]
```

Freeze 离线只读既有配置、anchor 与 CAS；源配置根要求私有，既有 Workspace 目录/对象可为 0755/0644，但不可 group/other write；不 chmod 或迁移源。`--config` 在此命令显式必需，因为当前 CLI 没有统一 Workspace 存储定位参数。用户选择 Workspace/Commit/selection，不选择内部 CAS 路径或 state_root。读取一致的既有 state_root 后，只能选其 DAG 中存在的指定 Commit；anchor 后续前进不能改变本次输入，旧 Commit 缺失须 `INPUT_UNAVAILABLE`，不能退回 Head。既有 anchor 的 write+rename 没有 fsync；本批不扩大其 power-loss 保证，不从 CAS 枚举猜测未锚定 Commit，不修补源 anchor。源 workspace.toml 读取上限 65,536 bytes，anchor 上限 256 bytes，durable state 与 legacy manifest 每个对象读取上限 8MiB；source content 单对象上限 64MiB。state_root 所定位 durable state bytes 必须重新核实 legacy FNV locator，不能只信 Workspace::open 的解析；anchor 名与 state key 均采用原正规格式。只读 adapter 在分配/解析前 bounded read，超限返回 `CAPACITY_UNAVAILABLE`（只是本命令的 adapter 限制，不改变原 Workspace 格式契约）。源配置/CAS/anchor 零写入；输出采用私有同父临时目录、内容校验、文件/目录 fsync、Linux renameat2(RENAME_NOREPLACE) no-replace 发布；安全 helper 归属 nexus-platform-linux，平台不支持时明确 UNSUPPORTED_CAPABILITY。安全 helper 入口为 `nexus_platform_linux::directory_publish::publish_directory_no_replace(&Path,&Path) -> io::Result<()>`；适用于 file/dir，调用方承担父目录验证与 fsync，原目标包括空目录/symlink 都不可覆盖。输出已存在返回 `OUTPUT_EXISTS`。不增加 Workspace 创建/import 功能。

`staging-init` 是显式本地运维操作，只允许已完成 N3-11 的提供方；不修改原 execution capacity policy、receipt、任务 ledger schema 或 init receipt。重复已完成的相同预算与绑定返回 `changed:false`；冲突与已初始化权威丢失失败关闭。namespace 外 retained `snapshot-staging-required-v1.json` 先 durable 写 Pending intent、最后 durable 标记 Complete（校验和与原 root/identity/scope/policy/namespace/lease inode 绑定），防止整个 namespace 丢失降级为未配置。首次初始化中断且尚未 Complete 时保存取证并拒绝启动/自动重建；本批不提供 pending init reset。若外 retained marker 与全部 staging state 一同被删除，不能声称区分“从未 provision”。不得在 status/upload 或正常查询中顺便 provision 预算。

本批 Linux 请求方及 Linux 提供方。合法非 Linux 调用在任何 IO 前 `UNSUPPORTED_CAPABILITY`；Windows 请求方属于 N3-14。语法未知/重复/缺参、非法相对路径、`..`、非本机 target：exit2 或已冻结 N3 本机地址拒绝语义，必须在凭据读取、连接、输出创建前拒绝。`--include`/`--exclude`/`--executable` 是可重复集合选项，重复相同值拒绝。

## 2. Bundle 与输入完整性

既有 Sha256Digest 的 wire 字符串必须是 `sha256:` 加 64 位小写 hex；bundle blob basename 仅使用其 64 位 hex 部分，不能把裸 hex 当作 DTO digest。输出目录为正式可搬运的 immutable bundle：`bundle-v1.json`、`manifest-v1.json`、`blobs/<64位小写sha256hex>`。Bundle metadata 恰好 `{schema_version:1, snapshot:SnapshotRef}`；manifest 内容为既有 `SnapshotFile[]` 的 canonical JSON，不再发明不同的 manifest。每个 blob 按唯一 digest 存一次；同 digest 不同 size 拒绝；空文件仍须验证 SHA-256(empty)，可以零字节 blob 表示。Bundle 不包含凭据、principal、授权、provider 容量或 TaskId。

SnapshotRef 与 manifest 的 digest、sorted unique path、file/directory collision、file_count、total_bytes、selection_digest、executable、case-sensitive UTF-8 路径完全沿用 `nexus-workspace::snapshot` / `nexus-domain::task`。Legacy Workspace 的 FNV ObjectId 只用于定位；freeze 核实 legacy object id 后重新 SHA-256 每个实际字节。Upload 不能把传入 CommitId 当作已验证 DAG 来源；它验证 self-consistent SnapshotRef/manifest/blob，Commit provenance 来自真实 freeze，不能声称远端已验证原 DAG。

V1 adapter 硬限：canonical manifest UTF-8 ≤ 65,536 bytes、files ≤ 1,024、SnapshotRef.total_bytes ≤ 67,108,864、单 chunk ≤ 65,536；计数和加法全部 checked 且 ≤ 2^53-1。manifest 声明超限在 reservation/write 前拒绝。读取源 blob 前核实单 blob 声明上限，流式 SHA-256；禁止先无界 `read_to_end` 再判断。现有 `Workspace::freeze_snapshot` 会积累所有 selected 内容，CLI 不能把它原样当成已满足内存边界：实现需增加 bounded freeze 路径/只读 adapter，保持既有 freeze 语义和 ABI 可用。Portable 新接口为 `SnapshotLimits { max_files: u64, max_total_bytes: u64, max_manifest_bytes: usize }` 与 `Workspace::freeze_snapshot_bounded(commit, selection, target, hash, limits) -> Result<FrozenSnapshot, TaskError>`；limits 由调用方提供，CLI 传本批固定 1024 files/64MiB/64KiB 限值。先核实完整选择/计数/逻辑总量/canonical manifest bounds，再调用 target.put；单次 source get 分配前 bound 归 app adapter。合法排除全部已匹配文件产生 empty selection 时，portable 可用 max_files=0/max_total_bytes=0，但 metadata 限值仍须容纳 canonical `[]`；不存在 include 不变为静默空选。

输出和 upload 读取拒绝 symlink、hardlink、FIFO/device、错误文件名、额外 blob、缺 blob、非 canonical metadata/manifest；逐文件 descriptor 与路径 inode 绑定、private regular 文件，目录不得被 request 路径替代。Bundle bytes 被外部修改时不得隐式修补/re-freeze；返回 `INPUT_INTEGRITY_FAILED`。输出目录内允许的文件集合必须固定，临时命名不从客户端路径派生。

## 3. Portable wire 与认证

新增独立 `nexus-control-api::snapshot` 模块；仅依赖既有 nexus-domain/nexus-proto，不依赖 nexus-workspace、存储、网络或 OS。复用既有 SnapshotRef、Sha256Digest、TaskError 与 CanonicalDto，新增独立 UploadId、SnapshotRequest / UploadView / SnapshotEnvelope。原六类 TaskRequest、TaskEnvelope 与 `/localapi/v1/task` 不增加变体。

请求为 strict canonical DTO，顶层均包含 `schema_version:1`、`operation`（wire 字符串恰好 `Begin`/`PutChunk`/`Get`/`Seal`/`Cancel`），恰好以下 operation 字段；未知字段、duplicate key、float/exponent/non-exact integer、未知版本拒绝。数组 bytes 复用当前 `Vec<u8>` canonical 表达（整数 0..255），不增加编码依赖。

| operation | 额外字段 | 语义 |
|---|---|---|
| Begin | provider, workspace, resource, upload_key, snapshot, manifest_json | manifest_json 是 bounded canonical manifest 字符串；由 daemon workspace adapter 解析、验证，不让 control-api 引入 Workspace 类型 |
| PutChunk | upload_id, blob_sha256, offset, bytes, chunk_sha256 | 仅所声明 blob，offset/length/hash 受限，确认连续 durable prefix |
| Get | upload_id | 返回当前 authoritative staging view，不创建文件或预算 |
| Seal | upload_id | 再核实所有完整 blob 与 manifest；原子变成 Staged；重复返回原 view |
| Cancel | upload_id | durable cleanup intent → 物理删除/fsync → 返还预算 → Cancelled；重复幂等 |

UploadId 与 upload_key 使用既有 ID 字符/长度规则；UploadId 由提供方生成安全名称而非请求自填；生成 basename 恰好符合 ASCII `[A-Za-z0-9_-]{1,256}`（普通 UploadId 解析仍沿用 TaskId Unicode 规则）；查询传入 ID 仅用于查索引，禁止直接拼接任意 ID 到路径（既有 ID 验证允许一般 Unicode/斜杠，不能冒充文件名校验）。Begin 的幂等索引键为 `(authenticated_principal, provider, workspace, resource, upload_key)`；值绑定 SnapshotRef 和 canonical manifest digest。相同键/内容返回原 UploadId 和进度；改变任一绑定内容 `IDEMPOTENCY_CONFLICT`。不同 principal 即使选择相同 key/digest，不能看到、续传或删除别人的 upload。

Response view 恰好 `{schema_version, upload_id, provider, workspace, resource, snapshot, state, reserved_bytes, blobs}`；blobs 按 digest 升序，各项 `{sha256,size_bytes,durable_offset}`。`Cancelled` view 的 blobs 为 `[]`、reserved_bytes 为 0；其他状态返回原声明集合。不包含 request-supplied principal。成功 envelope `{schema_version:1,verdict:"PASS",upload:view}`；失败 `{schema_version:1,verdict:"FAIL",error:TaskError,upload_id:null|id}`；不得复用 TaskEnvelope 并伪造 TaskId。本地 freeze / staging-init 有自己的 command envelope；freeze PASS 输出 SnapshotRef、bundle path，staging-init PASS 输出 binding/policy digest/changed，不输出 seed/token。

唯一新增路由 `POST /localapi/v1/snapshot`，沿用既有 N3 framing、16KiB header、1MiB request、2MiB response、总 IO deadline、connection-close、token authority inode/bytes 绑定及禁止 Transfer-Encoding/重复 Content-Length/pipeline 等规则；不足/过大 body 不进入 service。Chunk 数组最坏约 262,145 bytes，manifest string 最坏转义仍受 1MiB 限制。Snapshot 路由的 JSON body 字节必须与 lossless parse 后的 canonical_bytes 完全一致，拒绝额外空白、不同字段顺序与非 canonical 转义；原 Task 路由的 JSON 文本接纳规则不变。DTO 严格验证与 response correlation 必须独立测试。

TCP 只允许 numeric loopback，Unix socket 沿用既有真实本机 token 认证。Daemon 从其 N3-11 固定 N2 identity 与 task-api scope 构造 authenticated context，不能从 Begin principal/header 获得身份。每次 Begin/PutChunk/Get/Seal/Cancel 都复核配置 provider/workspace、实际当前 `(workspace, resource, principal, Use)` grant 及 upload owner；Get/Cancel 从原记录取得 resource，不能由调用方替换。无记录与 foreign scope 返回不泄漏记录的拒绝。授权审计失败视为 `PERSISTENCE_FAILED`，不给成功响应；授权 callbacks 不得在 staging flock 内调用。

不改当前 N3 token 认证模型，也不把 token 发到远端。N2 明文 Admission 不能充当 payload 保密/双向认证。N3-13 必须先实现并验证保密双向认证 peer context，再接远端 upload/Submit。

## 4. 独立预算与 exact charging

新 namespace `data/n3/snapshot-staging-v1/`，独立 immutable budget policy、外 retained 初始化绑定 receipt、固定 inode flock lease 和单一权威 checksummed ledger。upload receipt 是 ledger 内的 versioned record，不再另存可变副本。Policy 恰好 `{schema_version:1,max_reserved_bytes,max_active_uploads}`；两个预算值是正 exact integer，max_active_uploads ≤ 8。由原 N3-11 root/inode、provider/workspace、N2 principal/identity fingerprint 绑定，初始化 sentinel/receipt/ledger 任一部分缺失不得重新 provision。强权限、nofollow、single-link、固定锁 inode、atomic replace + fsync 与 N3-11 采用同等 Linux adapter 边界。

预算为**明确算法的 accounted staging bytes**，不是通用 RAM/实际文件系统分配/ENOSPC 保证。不更改任务 capacity policy 的 disk 字段，也不把接受前 upload 计成 execution reservation。设 `A(x)=4096*ceil(x/4096)`，`A(0)=0`；M 为 canonical manifest 长度，U 为不同 blob digest 数，B_i 为每个 unique blob 的声明长度，K=65,536，R=524,288（每条 active upload record 含唯一 blob offsets、固定 hash/binding 与至多一个 chunk intent；实际 canonical 序列化也必须 ≤ R）。所有乘加 checked。

```text
GlobalCharge = 16,777,216
UploadCharge = 2*sum(A(B_i)) + 2*A(M) + 2*A(R) + A(K)
               + 4096*(U + 6)
Admission: GlobalCharge + sum(reserved UploadCharge) + new UploadCharge
           <= policy.max_reserved_bytes
           AND active reservation count + 1 <= policy.max_active_uploads
```

2×blob 提前覆盖发布/恢复时最坏另一完整副本；2×manifest/record 是保守预收 envelope，单权威 ledger 下 record 不另写文件；chunk scratch 和目录/file bookkeeping 固定计费。最大 global ledger 每份 4MiB、最多 1,024 条索引/tombstone、同时最多原 ledger 与一个替换临时 ledger；policy/外 retained receipt/锁等剩余 global metadata 必须维持在 GlobalCharge 的其余 8MiB 下，写前检查实际序列化长度和固定允许文件集合。目录数/receipt 文件数不得随 chunks 增长，无 append-only 永久 chunk 日志，不允许无限遗留 tmp。

单权威 ledger 由 immutable policy/scope/root binding + records 构成；每 active record 的 canonical 上限 R，所有 records 共同 ledger 上限 4MiB，1024 条是数量上限而非保证容纳 1024 个长 binding。Begin 在任何写入前为新记录计算并保留 future serialization ceiling：保留实际 bindings/SnapshotRef/digests，所有数值用 MAX_INTEGER 位宽，采用最长 state 与最大一个 chunk intent/目录和文件 inode bindings；全表 future ceilings + envelope/header ≤ 4MiB。ceiling 随持久记录保存且状态转换不增大，只有 expired tombstone 删除才返还此 metadata allowance。表满可早拒，不能在接受后因 offset/state 增长无法提交。原/唯一 replacement 的固定 `.ledger-v1.tmp` 也受 4MiB cap；残留 canonical 完整 tmp 若 checksum、generation 与原 ledger 的唯一 next transition 可核实则恢复，否则保留并 STATE_CORRUPT，不清理未知文件。所有事务以这份 ledger 提交，消除独立 ledger/receipt 同步双写。无法在此 envelope 内实现的文件布局须在契约冻结前修改公式，不能实现后静默放宽。真实 fsync/write/ENOSPC 失败返回 `PERSISTENCE_FAILED`，保留已 durable reservation 与恢复 intent；不用 `statvfs` 冒充可靠 admission。空 manifest/blob 按 metadata 与 directory cost 仍收费；dedup 只在同一 upload 内减 blob payload，不能凭其他 owner blob 免 reservation 或越权引用。

GlobalCharge provision 时已占用，因此 policy.max_reserved_bytes 必须 ≥ GlobalCharge。达到 global serialized cap 即 `CAPACITY_UNAVAILABLE`，不得分配后才检查。Cancelled tombstone 保留 86,400 秒（提供方 clock），仍计入 global metadata，期间相同 Begin key 返回原 Cancelled；活动/未清理/完成 Staged 无自动 expiry。仅 expired Cancelled 在 boot 或下一次合法变更请求时可移除索引；Get 零 staging 文件变更/cleanup；认证审计写入原审计 namespace 仍允许且必需。时钟倒退不提前清理；全表满时可拒绝，不能删活记录。TTL 后同 key 允许新 upload，不能承诺永久幂等索引。

## 5. 状态、durable prefix 与恢复

| 状态 | budget | blob offsets | 可用操作 / 合法转换 |
|---|---|---|---|
| Receiving | 原 UploadCharge | 每 blob 0..size 连续已确认 prefix | PutChunk、Get、Seal(仅全完整)、Cancel；→ Staged / Cancelling |
| Staged | 原 UploadCharge | 所有 offset==size，全 SHA 与 manifest 已验证 | Get、重复 Seal、相同 Begin、Cancel；→ Cancelling |
| Cancelling | 原 UploadCharge | 不再接收/Seal；原 bindings 不变 | Get/Cancel 显示或继续 cleanup；→ Cancelled |
| Cancelled | 0 | blobs=[]；binding/terminal tombstone 不变 | Get/重复 Cancel/相同 Begin；不复活 |

Internal BeginIntent / ChunkIntent / SealIntent / CleanupIntent 都是有单一 owner 的 durable transaction 元数据，不独立伪造公网成功态。Begin 先保存 reservation+原 manifest/bindings 再创建 payload；回复只在 ledger/tree 相互一致且 fsync 完成后。只有租约持有者改变状态，同一 upload 的 chunks 串行；没有 unowned background task。

PutChunk 要求 length>0、offset==durable_offset、offset+length≤size、独立 chunk_sha256 匹配。合法重试仅在 `[offset,offset+length)` 全部属于已确认 prefix 且现有 bytes 完全相等时幂等返回当前 view；跨越已确认/未确认边界、future/gap、改变旧 bytes 都拒绝，不能 truncate 原 prefix。空 blob 在 Begin/Seal 明确核实 empty hash，不用空 PutChunk 表示进度。

每次写先 durable 保存 `{blob,old_offset,next_offset,chunk_sha256,scratch_state}` intent，写唯一固定命名 scratch，核实整 chunk/hash 并 fsync，再 durable 标记 `ScratchReady`，此后才允许把 scratch 的原字节追加到 blob；fsync blob 后 atomic fsync ledger 提交 next_offset，并保留 `CommittedCleanup` intent（原chunk范围/hash不变）；随后删除 scratch、fsync，再 durable 清 intent，最后回复。冷恢复先重算原 durable prefix hash：`ScratchReady` 前目标只能恰好停在 old_offset，可清理证明归属的未完成 scratch并保留 old_offset；`ScratchReady` 后必须核实完整 scratch，目标尾部只能是其一致前缀，可在原 intent 范围内补完相同字节并提交原 next_offset，不能回退或改写 old_offset 之前的字节。`CommittedCleanup` 恢复核实已完成 blob/原 chunk，仅清 owned scratch再 durable 清 intent；无 pending intent 的额外尾部、old prefix 缺字节/被改、无法证明归属的文件、内部 record/bindings 不一致均 `STATE_CORRUPT`，预算不返还。ledger record 每 blob 保存 SHA-256(prefix)，每次提交覆盖更新；pending chunk 有独立 hash；不通过 reset/truncate 猜测恢复。

**每请求校验时机（requirement-change，2026-10-27）**：
- 入口校验（所有请求）：每个 Begin/PutChunk/Get/Seal/Cancel 在租约内、任何 ledger/目录/payload 状态改变之前，对全部 record 的已确认 prefix 做完整流式 SHA-256 校验，不一致即 `STATE_CORRUPT`，且该请求不改变任何状态。
- 不重复全量重读（PutChunk、Get）：除入口校验外，同一请求不得再读取已确认 prefix 的字节。随后的 durable 检查点（chunk 追加前的 record 复核、ledger 提交前的复核）只复核 inode/类型/权限/长度等绑定与 intent 一致性；本次提交写入 ledger 的新 SHA-256(prefix) 由入口校验得到的同一摘要状态（`nexus::n3_acceptance::Sha256Stream`，可克隆的流式 SHA-256）续算本 chunk 已追加且经回读核实的字节得到。单次 PutChunk 读取的 blob payload 字节 ≤ 全部已确认 prefix + 1 个 chunk（追加回读核实）。Begin、Seal、Cancel 每个 upload 各发生有限次，保留现有额外完整校验，不受此条约束。
- 豁免：入口时存在 pending intent（崩溃遗留）而在请求内完成的恢复，以及 ledger TEMP 恢复发布路径（`ledger::load` 发布前的 `validate_all`），沿用冷恢复的完整校验，不计入上条。
- 冷启动 open/恢复的完整重算与 Seal 的整 blob 流式重算不变。
- 后果（明确接受）：入口校验之后、同一请求进行中对已确认 prefix 的篡改，推迟到下一个请求入口、Seal 或冷启动时失败关闭（`STATE_CORRUPT`），绝不进入 Staged；若在下一个请求前被恢复原样，提交的 prefix 摘要仍对应原字节，上传可正常继续。
- 复杂度：单次 PutChunk 流式哈希约 1×已确认 prefix（原实现约 4×），整次上传仍为 O(size²/chunk)；彻底消除需改 ledger 格式，另立 requirement-change。

Seal 流式再 SHA-256 每个完整 blob，校验 manifest digest/SnapshotRef；intent fsync 后发布 Staged record，回复前 ledger fsync。与已有 `FileSnapshotStore` strong CAS/catalog 隔离：本批 Staged 是 owned staging root，不调用当前无预算的 `stage_snapshot` / `release_preview`。即使同 SnapshotId，多 owner 上传互不授权、互不清除。

Cancel 先 durable Cancelling，再删除仅本 UploadId namespace 中已验证 owned payload/scratch，目录 fsync 确认删除，最后持久写零预算 Cancelled tombstone。删除失败/进程死后保持 charge；未能证明 physical deletion 不能先返还预算。授权撤销时上传/Seal/Get/Cancel 拒绝，不改变原 staging；运维显式重新授予 grant 后才能继续/取消，不偷偷以 GC 绕开 owner。normal/serve 在原 managed provider preflight 后、identity ensure/boot reconciliation/token publication 之前打开并恢复所有 staging；listener 的 token authority 核实完成后才能发 READY。任一损坏权威不得创建新空 ledger 或把该 upload 判完成。

N3-13 后续接线必须采用 `acceptance lock → staging lock` 固定顺序，原 AcceptedContract 与 input pin durable 后才能删除/release staging；读取 Staged 不能替代 accepted pin。未 accepted 的 staging 不进入现有 Task GC catalog；现有 strong CAS GC 也不能扫描/删 staging namespace。本批增加桥接需求说明，不提前修改 TaskSubmit wire 或执行流程。

## 6. 可操作流程与 Evidence

常见流程：用户已存在正规持久 Workspace → `nexus workspace commit WS` 显式提交并取得 CommitId → 正式 freeze 该 Commit → 运维 N3-11 init、staging-init 与已有 `nexus task-provider grant add --config ROOT --resource compute-local --self` → 启动正常 no-TUN daemon → 本机 upload → status 验证 Staged → cancel 验证 budget 物理清理后归零。Freeze 无需 daemon/FUSE 正在运行，但需要此前真实存在的 Workspace。资源名是现有 grant 作用域，不能把 `resource publish` / directory可见性当 Allow。

上传 CLI 的 --provider 是显式必需 ID，不能从 token 文件位置、default config、N2 directory 或 bundle 猜测；workspace 固定来自原 bundle 的 SnapshotRef。上传 CLI 默认遍历 Begin 所返回 offset、按 blob digest 升序续传；使用相同 `--key` 重试就能恢复原 UploadId，用户不用手工管理 offsets。网络/daemon中断保留 bundle 与提供方原状态；重试重新验证同一 bundle，不重新选择 Commit/Head。最终 JSON包含原 SnapshotRef/UploadId/进度/预算/状态，不把 `PASS` 文案写成执行完成。

新增 frozen E4 `product.n3-12-snapshot-staging`：旧真实 nexus 对 `snapshot freeze` 或 `snapshot upload` 正式命令拒绝/exit2 得明确 FAIL RED，记录 binary hash/revision/dirty/config。observer 不通过 SDK seed、test-only provider identity、预写 staging/capacity/receipt 或改 expected 造 GREEN。源 Workspace 使用 checked-in、已真实导出且带 SHA 清单的 immutable Workspace fixture（只有 requester 源 CAS/anchor/config，不含提供方 state），由正式 freeze 读取；若选择真实 FUSE commit 作为主场景则其缺平台能力为 UNKNOWN，不能让 N3-12 mandatory upload E4 依赖不可用 FUSE。E3 可以直接以现有正规 Workspace APIs 构造 Commit 验证 freeze adapter；不能称该 E3 为产品 E4。

| 验证 | 必须独立观察的断言 |
|---|---|
| 正常 binary E4 | 固定旧 Commit 的字节，与更新 Head/WorkingSet/decoy 无关；正规 freeze→真实 grant→正常 daemon→chunk upload→Staged；无 Task/Session/Engine/Artifact 创建 |
| repeat/restart | 相同 key 同 UploadId，已确认 bytes/inodes 未替换；SIGKILL 后冷恢复同 offset/SnapshotRef/reservation；补剩余 chunk 与 Seal |
| scope/auth E3+E4 | 无 grant、expired/revoked、foreign principal/scope/resource 每次拒绝；篡改DTO principal/非本机target/token inode 不写 payload；审计错误不给 PASS |
| integrity E3 | 非 canonical/重复字段/路径碰撞、digest/size/total/manifest不符、zero blob、重复同digest异size、extra/symlink/hardlink、prefix篡改/缺权威，全失败关闭 |
| budgets E3+有限 E4 | exact formula 边界、checked overflow、empty 与1024files/64MiB/64KiB限、最多8reservation、ledger/tombstone cap、跨 owner dedup不逃费、取消删除故障不返费 |
| durable cutpoints E3 | Begin每次fsync、chunk intent/payload/receipt、Seal、cleanup删除/ledger 各前后 crash；可证明恢复与不可证明 STATE_CORRUPT；不会重置预算/原输入 |
| compatibility | 原 TaskRequest六类wire、N3-11 init/check、旧task/capacity/runtime/artifact/snapshot测试与Portable gate；新 staging 不改旧 receipt、无新增crate/dependency |

冻结前至少产出：PRODUCT/MODULE映射、独立 scenario expectation / observer、旧实现真实 RED、字段 schema 与 contract hash。实现后 Check/affected/Fast、独立八维 review、适用 Full/E4；真实 Windows→Linux E5 保留 N3-14。Engine 无触发的独立观察使用 Linux strace/ptrace：初始 daemon exec 为 positive control，操作期间没有额外 exec/connect，并同步比较原 runtime/Artifact/Task 持久状态和实际 Session 列表。该工具是有限 E4 的测试能力前置，不是产品依赖；缺能力不 skip 或假 PASS，不声称 Engine qualification。fresh Evidence 绑定 revision、dirty内容、工具链、binary hash 与 fixture配置；本草案不能作为完成证据。

## 7. 冻结材料与适配器边界

- 源 fixture 由当前真实 Workspace::init 与 NativeApiWorkspaceAccess::write_file/commit 导出旧/new Commit；仅 requester config/anchor/CAS，另存 generation provenance/SHA 清单。observer 将其复制为 private source，不写任何 provider authority；选 old Commit，对 new Head/WorkingSet/物理 decoy 不读取。fixture 生成工具不参与 provider GREEN。
- 最坏合法 ID 为 256 Unicode scalar，canonical escaping 最坏每 ID 1538 bytes；每 active record 1024 blob 的宽松上界含 manifest 约 440KiB，小于 R，但每次写仍执行真实 serialized cap。计算证据来自独立预算探针，不能替代生产断言。
- staging 固定允许集合：namespace 根 `policy-v1.json`、`staging.lock`、`ledger-v1.json`、至多一个 `.ledger-v1.tmp`、`uploads/`；uploads 下只有提供方生成的安全 UploadId namespace；每 upload 内 `manifest-v1.json`、`blobs/`、至多一个 `chunk.tmp`。blob basename 是 64 位小写 digest；内部原子 publication scratch 文件最多一个并受同一 intent/budget 绑定。禁止未知文件/目录。Cancelled 只保留 ledger tombstone，物理 upload namespace 已删除。
- Get 零 staging 写入；变更操作与 boot 在原固定 inode staging.lock 上独占串行化。normal service 不永久占该 flock，以允许运维重复 staging-init 只读核实。
- Current Use authorization 与 audit 在进入 staging lease 之前完成；后端固定 scope 与原 principal、upload owner 都再校验；不会在 ledger lock 内调用外部授权 callback。
- HTTP 已辨明 `/localapi/v1/snapshot` 后使用独立 SnapshotEnvelope；无法辨认的畸形 request-head 维持原 framing 拒绝，不伪造 upload。完整 snapshot JSON body 的拒绝均为 typed schema1 error。

## 8. 冻结 Rust API 与相关性

`nexus-control-api::snapshot`：

```rust
UploadId::new(String) -> Result<UploadId, TaskError>; // existing TaskId grammar
UploadId::as_str(&self) -> &str;
UploadState::{Receiving, Staged, Cancelling, Cancelled};
UploadBlob { sha256: Sha256Digest, size_bytes: u64, durable_offset: u64 }
UploadView { schema_version: u64, upload_id: UploadId, provider: String,
  workspace: String, resource: String, snapshot: SnapshotRef, state: UploadState,
  reserved_bytes: u64, blobs: Vec<UploadBlob> }
SnapshotRequest::{Begin { provider: String, workspace: String, resource: String,
  upload_key: String, snapshot: Box<SnapshotRef>, manifest_json: String },
  PutChunk { upload_id: UploadId, blob_sha256: Sha256Digest, offset: u64,
    bytes: Vec<u8>, chunk_sha256: Sha256Digest }, Get { upload_id: UploadId },
  Seal { upload_id: UploadId }, Cancel { upload_id: UploadId }}
SnapshotEnvelope::{Upload(UploadView), Error { error: TaskError, upload_id: Option<UploadId> }}
trait SnapshotService: Send + Sync {
  fn execute(&self, context: &task::TaskCallContext, request: SnapshotRequest)
    -> Result<UploadView, TaskError>;
}
```

Request/View 的 validate、CanonicalDto 和 Envelope::validate_for(&SnapshotRequest) 是独立可验证纯 API。blob 集合 sorted unique、offset≤size、unique count≤file_count、sum(unique sizes)≤total_bytes；同 digest 多文件不要求 unique sum 等于 total。非 Cancelled 时 file_count>0 必须至少一个 blob；file_count==0 要求 total_bytes==0 且 blobs=[]。PutChunk offset+length checked≤MAX_INTEGER，实际 declared size 与 chunk hash 由 daemon 验证。Cancelled 为空集合/零 charge；其他 state charge 正 exact integer；Staged 的全部 offsets==size。scope/workspace须与 SnapshotRef 一致。这些 DTO 不解析 manifest、计算 hash、访问 IO 或授予权限，真实验证在 adapter。

成功 Begin envelope 必须完整匹配请求 provider/workspace/resource/SnapshotRef；其余必须匹配 UploadId。Seal 成功只能 Staged，Cancel 成功只能 Cancelled；PutChunk 成功只能 Receiving/Staged，必须包含请求 digest 且 durable_offset 覆盖原请求 range；允许重试返回更大当前进度。错误中的 UploadId 若存在必须与原请求相关；Begin 错误没有调用方自填 UploadId。CLI 不接受无关记录作为 PASS。

Freeze PASS `{schema_version:1,verdict:"PASS",command:"snapshot freeze",snapshot:SnapshotRef,bundle_path:absolute_string}`；FAIL 同 schema/verdict/command 与 typed error。Staging-init PASS `{schema_version:1,verdict:"PASS",command:"task-provider staging-init",scope:{provider,workspace},principal,policy_digest,changed}`；FAIL 同 schema/verdict/command/error 与 phase、mutation_may_have_applied。处理失败 exit0；纯参数用法失败 exit2。

## 9. Provider adapter 与 TDD 可观测边界

Linux `nexusd::snapshot_staging` 对 daemon 组合根提供 `initialize(config: &Path, budget: &Path) -> Result<StagingStatus, task_provider_init::InitFailure>`，以及 `FileSnapshotStaging::open(config: &Path) -> Result<Option<FileSnapshotStaging>, TaskError>`。StagingStatus 字段为 provider/workspace/principal/policy_digest:String、changed:bool。未配置 marker/namespace 均不存在时 open 返回 None；任何一项残留就检查原 Complete binding，不用缺失→空 ledger 回退。FileSnapshotStaging 实现 §8 SnapshotService；额外 `execute_local(SnapshotRequest) -> SnapshotEnvelope` 只从其已核实原 N2 identity/scope 构造 context，不 ensure 身份。

测试使用正规 N3-11 init 与真实持久 grant API 构造 E3 状态；不同 trusted authenticated context 属于 E3，不能称远端认证。私有 `cfg(test)` 故障钩子可在真实 durable IO 前后返回 PersistenceFailed/模拟进程死亡，以对所有已命名 cutpoints 重开原文件观察；钩子不进入产品 build、wire 或环境变量，作用域限定当前实例，不共享全局 fault 状态。初始化测试可调用私有 `cfg(test) initialize_with_test_fault(config,budget,cutpoint)`，fault由该次调用持有；初始化 Pending 中断必须保留取证/拒绝 reset，Complete 后重试才可 changed=false。TTL 测试使用实例私有 cfg(test) clock，不依赖真实 sleep。必须至少覆盖 init Pending/Complete、Begin reservation/manifest、chunk Intent/ScratchReady/blob append/CommittedCleanup/clear、Seal intent/Staged、Cancel intent/delete/release、atomic ledger replacement；先记录 RED 并盲评测试，再实现。这些测试不能直接构造假的 accepted provider/staging authority 来替代正规初始化。
