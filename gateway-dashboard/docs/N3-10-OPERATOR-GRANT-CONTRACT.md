# N3-10 本地提供方 scoped Use grant 运维契约

本批类型 feature。新增生产本机运维入口，使非 default Workspace 的既有 N3 Artifact 可以由真实 CLI 撤权/恢复；不修改 Task schema1、六个 Task wire 操作、旧 generic grant 行为或原完整 N3 场景预期。

## 1. 命令、范围与身份

- `nexus [--json] task-provider grant list --config <dir> [--resource <name>]`
- `nexus [--json] task-provider grant add --config <dir> --resource <name> (--self|--principal <p>) [--not-after <unix>]`
- `nexus [--json] task-provider grant revoke --config <dir> --resource <name> (--self|--principal <p>)`

config 为显式绝对既存路径，不允许相对路径或 `..`，不使用环境/default 节点目录。本机操作不接受显式全局 --addr/--socket。未知/重复选项、缺值、冲突主体、list 带主体或期限、revoke 带期限为用法错误 exit2，任何 IO 前拒绝。仅 Linux 支持，其他平台在宿主 IO 前明确 Unsupported。

config 与 n2 必须为既存真实 0700 目录。固定 `task-api.toml` 为单链接 regular，无 symlink/group/world 写权限（0700 根内允许0600/0644），不超过16KiB，恰有字符串 provider/workspace 两字段，按既有 TaskId 校验。它固定本机 provider/workspace；resource 用既有 ResourceName 校验，直接组成 ResourceRef，不要求 mutable NameEntry 或 DEFAULT_WORKSPACE resolve。目录可见不产生授权。

--principal 为 `ed25519:` 后32个小写 hex；--self 从同根既存 `n2/auth-identity` 派生实际公钥与 principal，严格核实版本、seed、公钥及精确字段。mutation 的审计 actor 总是该实际既存身份；目标 principal 不是 actor 认证证据。身份文件 regular/0600/单链接、最多16KiB，拒绝 FIFO/symlink/错公钥；绝不 ensure/generate 身份。list 不读身份。

not-after 仅 add 允许，精确非负十进制整数不超过 2^53-1；允许过去时间，由既有当前 Use 判定拒绝访问。不接受负数、小数、指数、溢出或非法值并降级成永久授权。

## 2. 真实 grant 与读取

读取/写入既有 N2 grant key/filename 与 JSON 格式，daemon 继续使用真实 N2 GrantTable；不私建影子表。文件名与 workspace/name/principal 内容精确关联，严格字段、操作和整数校验，单记录最多16KiB、文件regular/单链接、无group/world写权限（兼容0700父目录内原N2的0600/0644文件；新写一律0600）、NOFOLLOW/NONBLOCK。grant key 必须能编码为合法单文件名，长度超出宿主255字节上限明确拒绝。list 范围最多4096条、响应最多2MiB，超限明确失败而不截断；仅枚举当前 Workspace，按resource/principal稳定排序。

list 可显示实际 Use/Manage/mixed 操作、期限和撤销状态用于取证，但不写 grant/audit、创建 lock/身份/目录、清理 tmp，也不调用带副作用的 N2Store/FileKvStore open。scope/文件/记录错误明确失败，保留原内容。

add/revoke 的既存目标必须 operations 恰为 `[use]`；Manage、mixed、空、重复操作均拒绝，原字节保持。add 创建或明确替换 Use-only 的期限并恢复 revoked=false；不影响其他主体/resource/Workspace。重复相同 add 为 changed=false，不重新序列化原记录。revoke 保留 Use-only 记录及期限，设置 tombstone；已撤销为 changed=false。不存在 revoke 为 changed=false、revoked=false、grant=null，不合成记录或身份。

## 3. 并发、持久审计和失败

新 mutation 持有同根固定 `task-provider-grants.lock`（0600/单链接/固定inode），使用现有 safe Linux nonblocking file lease；忙返回 retryable CAPACITY_UNAVAILABLE，不等待其他进程生命期。lock/根/文件替换拒绝。旧 generic grant/其他直接写者不共用该锁，本地运维须协调；不宣称跨旧命令事务隔离。daemon 原子读取 grant，看见更新前或后完整记录。

只有实际 changed mutation 追加专用 `n2/task-provider-grant-audit-v1.jsonl`：先 intent fsync，随后同目录 private temp/create-new 写 grant、fsync、原子 rename 和目录 fsync，最后 applied fsync。0600、单链接 regular、上限8MiB；不自动截断/轮换/删除。NOFOLLOW/NONBLOCK，现有父目录及固定 inode 在临界区重核实。权限/损坏/超限不能被当作空日志。

每行 exact 字段：schema_version=1、mutation_id、phase(intent/applied)、operation(add/revoke)、scope(provider/workspace)、resource、principal(target)、actor、changed(true)、before_sha256(null/原字节sha256)、after_sha256(预期新字节sha256)、at_unix、previous_sha256、record_sha256。mutation_id 唯一；intent/applied 的目标、actor、摘要与changed一致。record_sha256 为去除自身字段后规范JSON UTF-8字节SHA-256，previous指上一条record hash（首条null）。配对完整、链完整才能继续 mutation。

每次 mutation 验证既存审计；坏checksum/JSON/链、torn尾、dangling intent 明确 STATE_CORRUPT，保留未知状态，不回滚、补造applied、清空或重新执行授权。list 不依赖audit可用，允许读取真实 grant 取证。无变更请求不追加audit，但不得绕过既存损坏/未知审计阻断；可能首次创建自己的lease。后续显式修复工具独立规划。

审计前失败不修改 grant。rename/目录sync/applied之后的错误可能已经改变授权；结构化失败必须给 phase 与 mutation_may_have_applied（保守true），不能打印PASS或声称失败零写入。临时文件不成为权威，不自动清除他人文件。无 N2 AUTH_GRANT/REVOKE outbox，不宣称通知跨节点主体。用户仍从真实 daemon 的下一次请求观察 current Use，已发布 Artifact 文件在撤权/过期时保持。

## 4. 输出与证据

结构化业务结果 exit0、用法错误 exit2。成功 schema_version=1、verdict=PASS、command=`task-provider grant <op>`、scope={provider,workspace}；list 有 grants 数组，每项 resource/principal/operations(lowercase)/not_after/revoked；mutation 有 operation、changed、grant（同形或不存在revoke的null）。业务FAIL含 error(code/reason/retryable)、phase、mutation_may_have_applied。人读与 --json 输出同形，不打印secret seed/公钥记录。

有限E4 `product.n3-10-operator-grant` 使用原合格现有 Engine/TaskOwner 真实产物和正常 daemon/CLI：初始SDK仅准备原authority；所有后续 list/revoke/add由生产CLI执行。核实原真实Completed/Confirmed/exit0、scoped列表、撤权与过期下载拒绝、两次恢复、原文件inode/SHA保持、4次mutation的intent/applied校验链、daemon/thread回收和本次已停止label-bound容器清理。旧B56实际CLI拒绝运维命令，建立RED后冻结本契约、场景与观察器。

实际binary E3另覆盖参数零IO、scope隔离、TTL边界、缺失/错身份、配置/目录/FIFO/symlink/hardlink边界、Manage/mixed保留、list零写入/清理、忙/换inode、审计满/损坏/torn/dangling与发布错误可能已生效。保持 Rust1.85 MSRV，无新crate/deps/unsafe。

本批不创建新Provider authority、preaccept staging预算或输入协议，不证明 Submit、Snapshot import、跨节点计算或外部Windows→Linux E5。之后再独立做fresh provisioning、独立staging份额/receipt和上传恢复。
