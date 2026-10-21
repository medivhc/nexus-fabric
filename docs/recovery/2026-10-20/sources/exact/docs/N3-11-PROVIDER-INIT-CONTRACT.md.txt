# N3-11 正式提供方初始化与只读检查契约

本批类型 requirement-change：新增 Linux 本机运维入口，并使核实完成的 managed N3 提供方可独立通过正常 config-folder daemon 启动。状态：契约冻结；旧真实 nexusd 的正式 init 返回用法错误 exit2，本批场景产生 FAIL Red Evidence。冻结摘要与旧 binary/source binding 保存在 `.evidence/n3-11/`，Contract Hash 记入本批契约提交。基线为 origin/master d50d8fe。

## 1. 范围与入口

- `nexusd task-provider init --config <absolute-existing-private-root> --provider <id> --workspace <id> --capacity <absolute-policy-json> [--json]`
- `nexusd task-provider check --config <absolute-existing-private-root> [--json]`

入口由 nexusd Composition Root 所有，在普通 config-folder 分派之前识别；不得让 nexus 反向依赖 nexusd，不添加 crate、依赖边、wire operation 或 portable trait。既有 nexus task-provider grant 运维行为不变。

所有参数在宿主 IO 前解析和纯校验。必填项缺失、未知或重复选项、缺值、init/check 不适用选项、重复 --json、--addr/--socket、相对路径或 .. 为用法错误 exit2；不隐式使用环境/default 节点根。provider/workspace 使用既有 TaskId 纯校验，合法斜杠字符不作为宿主路径，不额外改窄原 ID 语法。config 与 capacity 路径均须显式绝对且无 ..。本批只支持 Linux；其他平台合法参数后在 IO 前返回 UnsupportedCapability。

首次 init 的 config 必须已存在且为真实0700目录，全部祖先为真实目录、无 symlink。除运维者提供的单个 `daemon.toml` 外不得含既存条目；该配置须是现有 daemon 可接受的配置，且明确 `[tun] enabled=false`，不自动生成假 network/proxy/workspace 配置。无 daemon.toml 的首次 init 可以完成离线初始化，正常启动仍须运维者明确配置 no-TUN。初始化自己的 lease/marker 不作为用户已有内容，创建后必须在同一已核实根内重查新出现的其他条目。坏配置或非法 policy 在新 authority 发布前拒绝。

初始化建立同根 n2 身份、data/n3/tasks 与既有容量 authority，并最后发布 `task-api.toml`。该文件继续恰含字符串 provider/workspace 两字段，新写0600。Workspace 只是固定配置作用域，不调用 Workspace::init，不制造 Commit/Snapshot。provider ID 与真实 N2 Ed25519 principal 独立。没有 grants、names、advertisements、Tasks、Sessions、Engine、输入/产物内容或 LocalAPI token 创建；不运行 daemon、Engine 验证、SessionManager 或 capacity-owner recovery。

## 2. Policy 与唯一容量权威

capacity 输入为最多16KiB、单链接 regular、无 symlink、无 group/world 写权限的 JSON 文件；使用 NOFOLLOW/NONBLOCK 有界读取，拒绝 FIFO/hardlink/损坏 UTF-8、重复字段及读取中的 inode/内容变化。精确结构为既有 ProviderCapacityPolicy 的 `total`、`fixed`、`overhead`，不接受未知或缺失字段、浮点、指数或非整数：

- total/fixed 恰含 cpu_millis、memory_bytes、pids、runtime_storage_bytes、backend_disk_bytes、slots；
- overhead 恰含 cpu_millis、memory_bytes、pids、backend_disk_bytes；
- 每一 allocation、reserve 和 overhead 为正且不超过2^53-1，fixed 各维度不超过 total，遵循既有 validate 和 checked arithmetic。

policy_digest 为既有 CanonicalDto 规范字节的 SHA-256，而非输入 JSON 的排版摘要。预算是显式运维分配，不是主机空闲量测，也不承诺普适 OOM/ENOSPC 防护；没有静默默认预算、自动改配或 staging 份额。

继续由 `FileTaskAcceptanceStore::provision_capacity` 建立既有 acceptance envelope v2、runtime receipt、capacity receipt 与固定 owner inode。初始化元数据仅证明本批所有权和恢复范围，不保存第二套 mutable capacity、reservation 或 Task 真相。initial epoch0/Pending 不是活 Ready；只有原 daemon 恢复 owner 能决定 Ready。

## 3. 固定身份、journal 与恢复

本批 managed 元数据位于 config 根：`task-provider-init.lock` 为固定 inode 非阻塞 lease，`task-provider-init-v1.json` 为持久初始化 journal，`task-provider-initialized-v1.json` 为完成 binding receipt。三者0600、regular、单链接，拒绝替换。journal/receipt各不超过16KiB、使用严格 versioned JSON 与 canonical checksum，不含 secret seed。它们绑定同一初始化ID、scope、canonical policy_digest、config 根 device/inode、初始化 lease device/inode、身份 principal/完整原字节 SHA-256/原文件 device/inode以及阶段；完成receipt与journal的全部固定事实须精确一致。阶段及每个字段的合法组合须明确检查，不能用几个独立 bool 推断恢复。

首次 init 写入并 fsync durable intent 后才发布 authority；目录逐级0700创建并同步父目录。身份生成与发布由本机组合根拥有，使用真实既有 N2 record 格式及 key filename 编码，核实 version/created_at/seed/public key 的精确字段、实际派生公钥和 principal。private staged identity 保留完整原字节以支持已证明的中断窗口，0600、单链接且独立于 N2 `.tmp-*` 自动清理；其名字/binding 由原 intent 约束，不日志输出或复制 seed 到公共 journal。

可恢复的耐久检查点覆盖 intent、原 staged 身份、原已发布身份、空容量初始化以及 scope publication。文件与目录同步错误不吞掉。既有 authority 仅按既有 fresh-empty provisioning 规则补全，参数必须与同一个 intent 完全一致，身份只发布原 staged 字节；最后在核实全部原 binding、scope 和真实容量后原子发布完成receipt并完成journal。两者之间的耐久中断按同一已证明intent恢复，矛盾记录拒绝。完成之前正常 daemon 拒绝本批 managed root。

在原 `data/n3/tasks/capacity-owner.lock` 的同一固定inode中写入精确managed-required sentinel `n3-provider-init-v1-required\n`，同步原文件及目录后才允许完成初始化。它仅标明本批managed要求，不替代原owner binding、lease、epoch或capacity receipt。现有容量代码不得截断/改写该inode内容；不修改既有acceptance/runtime/artifact/capacity receipt字节格式。旧unmanaged owner lock为空仍兼容。完成receipt保存原owner inode binding，校验同时要求其sentinel完整。

对未完成 state，只有精确、完整、可证明的原检查点才继续。torn/坏 checksum/非法状态组合、原 intent/staged 身份矛盾、已发布身份消失、required capacity authority 消失、根或锁 inode 变化均 STATE_CORRUPT 并保留文件；不重新生成身份，不重建空 pool，不猜测 rollback/applied，不清理他人 tmp 或重做未知状态。任意损坏/authority loss 不在中断自动恢复承诺内。

lease 使用已有 Linux safe nonblocking flock helper，忙为 retryable CAPACITY_UNAVAILABLE。同新入口的独立进程串行化，旧 generic N2/direct writer 仍由节点所有者协调，不声称跨旧 writer 事务隔离。使用 Rust1.85可用能力，无新 unsafe。

## 4. 完成后幂等与只读检查

相同 scope 和 canonical policy 的 completed init，在首次启动前、daemon 运行中、停止或冷启动后均返回 changed=false。它核实一致的journal/完成receipt、原managed binding、原真实身份、现存两字段 scope、原 owner inode与真实 authority，并保留当前 ledger/runtime/容量 epoch/reservations；不能再次调用 fresh provisioning、begin recovery、取得 Ready-owner lease或重置状态。

scope/policy 变化拒绝，既存旧 root 没有本批 marker/完成 binding 时不允许 enrollment，即使为空也不接管。completed marker、身份、receipt、ledger 或 owner 缺失/损坏不能被视为 fresh；相同字节但原身份/根/锁 inode 已变仍拒绝。daemon 合法改变 capacity epoch、Ready及 reservations 后不要求完整 envelope 等于初始化字节；比较其不变 policy/scope/binding，并验证全部现有 authority links。

check 只成功于 completed 且完整核实的 managed provider。它直接有界读取并验证已有文件；不得调用 N2Store/FileKvStore/Task store/Snapshot/Artifact 的带写入 open/initialize，也不创建或取得init mutation lease、不产生日志审计、token或身份、不清 tmp、不执行 reconciliation。允许对既存原acceptance固定inode使用非阻塞锁以取得一致性读取，但不得创建/替换该文件、写入authority或取得capacity-owner Ready lease。忙或观察中发生变化可明确retryable失败。原文件字节、inode、权限、链接数与条目清单保持。它可与活 daemon 共存，验证原 owner inode，但不借持久 Ready 字段宣称 owner 存活或可接收 Task。

pristine、pending、缺 marker、损坏或 authority loss 的 check 显式 FAIL；没有把它们改造成空的已初始化状态。`initialized=true` 仅表示本批初始化 binding 已核实，绝不等同 runtime Ready、Engine qualification 或完整 Submit 能力。

所有读取/发布/幂等返回边界核实原 FD、路径 dev/ino、类型、nlink、权限及必要原字节，root 与 ancestor 保持原 real-directory binding。private 子目录为0700，新 authority 文件0600；既有 scope文件兼容其原0600/0644规则。对坏权限不自动 chmod/rewrite。当容量写者正在原 acceptance 临界区改变 authority 时，读取不能认证混合快照；应取得真实一致性观察或明确 retryable失败，不能修改 epoch或持久 state以便验证。

## 5. 正常 daemon 与兼容入口

正常 `nexusd <config-folder>` 在任何身份 ensure、N2 assembly、boot reconciliation 或新 token创建前核实本批 managed marker。`serve` 兼容入口及 Task loader 同样检查该 marker；pending/损坏 managed root拒绝，不 READY、不先生成替代身份。任一init journal、完成receipt、init lock或原capacity owner sentinel仍在时，该root仍为managed；缺失其同伴记录明确拒绝，不能降级为legacy。只删除顶层markers但保留原owner sentinel仍须拒绝。真正没有本批初始化证据的历史unmanaged入口保持原行为，不隐式迁移。该检测以尚存耐久anchor为界；不声称能区分全部anchors/authority被一并抹除后伪装的legacy目录，该情况没有外部权威证据。

完整核实的 managed provider 作为正常 config-folder 的有效 subsystem，允许它没有 proxy.yaml/network.toml/workspace.toml。这是对旧 T3 的增量 requirement-change：普通空根仍拒绝，存在一个未核实 task-api.toml不算 subsystem。N3-only启动需要显式有效 no-TUN daemon.toml；不启用主机网络接口，也不合成占位资源。

完成 init不取得 Ready；正常 daemon继续经原唯一 SessionManager、容量 owner 与原 executor/snapshot恢复形成 Ready，身份/初始化binding保持。READY行不证明 TaskService可用，E4还须通过真实 LocalAPI查询观察现有 TaskService的既有 unknown accepted TaskId拒绝。恢复异常不能开放新接受或执行。

## 6. 输出和失败

所有业务结果输出单个 schema_version=1 JSON，exit0；用法错误exit2。--json与人读路径输出同形；不输出 identity record、seed、staged内容或token。成功例：

```json
{"schema_version":1,"verdict":"PASS","command":"task-provider init","scope":{"provider":"provider-a","workspace":"workspace-a"},"principal":"ed25519:0123456789abcdef0123456789abcdef","changed":true}
```

```json
{"schema_version":1,"verdict":"PASS","command":"task-provider check","scope":{"provider":"provider-a","workspace":"workspace-a"},"principal":"ed25519:0123456789abcdef0123456789abcdef","initialized":true,"policy_digest":"sha256:<64 lowercase hex>"}
```

FAIL含 command、error={code,reason,retryable}、phase、mutation_may_have_applied。code沿用既有 TaskErrorCode；scope/policy冲突、损坏/未知/丢失managed authority为 STATE_CORRUPT；非法输入policy为 INVALID_REQUEST；IO为 PERSISTENCE_FAILED；忙为CAPACITY_UNAVAILABLE；其他平台为UNSUPPORTED_CAPABILITY。无变更check和completed验证错误 mutation_may_have_applied=false；init发布后的IO失败保守true并注明phase，不以FAIL声称零写入。未核实的信息不伪造为成功scope/principal或initialized=true。

## 7. 验证与保护范围

新增有限 E4 `product.n3-11-provider-init`，由正常正式 init/check CLI建立新 provider，无SDK seed、fake identity、Engine或手写Task/容量authority。观察正式init、check零写入、重复init原authority保持、正常no-TUN daemon/真实TaskService、独立环境decoy不变、唯一Manager、退出回收、post-boot幂等、scope/policy修改拒绝、损坏和required authority loss拒绝及启动前阻断。观测器自身破坏负例fixture须标明，不污染正常主体。

真实binary E3覆盖参数零IO、policy shape/整数边界、权限/FIFO/symlink/hardlink、跨进程忙/替换inode、身份公钥不符、legacy不能enroll、qualified耐久窗口SIGKILL恢复、pending/corrupt检查及daemon拒绝、发布错误可能已生效。check与幂等证明使用字节/SHA、inode/mode/nlink及条目清单，避免把合法daemon epoch变化当作reset；不打印身份内容。

旧binary执行本批场景产生明确FAIL作为RED后，冻结本契约、PRODUCT/MODULE增补、场景requirement/expectations与observer摘要，再进入实现。Check→affected→Fast→独立八维Review→Full；原完整N3场景、旧授权/下载场景与现有失败保持保护。该批只交付初始化与有限边界，不开放Submit、输入上传、跨节点Task RPC、staging预算、Windows或完整N3 E5。
