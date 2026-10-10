# N3-2：Snapshot 与持久输入保护

范围：落实已冻结模型 §4 的 Workspace Snapshot、SHA-256 v1 内容空间、输入核实和接受记录驱动的持久 pin。没有修改 37 个冻结契约文件；没有新 crate、依赖或旧 CAS/Commit 格式迁移。真实任务路由、授权服务、跨机输入传输、隔离命令执行与 Artifact 状态由后续阶段装配。本批不能证明 N3 产品可用。

## 实现入口

- `nexus-workspace::snapshot`：从显式唯一 Commit 生成 `FrozenSnapshot`，输出 SnapshotRef、规范文件清单和总字节数；从不读取可变 Head 或扫描本地工作目录。Legacy Manifest 只表示普通文件内容，不承载 symlink、设备或空目录。
- `SnapshotSelection`：v1 精确文件/目录前缀规则；include 必须明确且非空，`.` 是显式全选，exclude 优先。规则、版本、匹配语义和显式 executable 文件集合进入 selection_digest。没有默认递归上传或凭据注入。调用方应明确选中构建输入，并先通过已有 Workspace commit API 提交所选未提交内容。
- `nexus-storage::strong`：与 FNV locator 分离的 `StrongContentStore` 读写边界和纯 SHA-256/长度核实；SHA-256 注入沿用 N3-1 组合根实现。接口无删除方法，删除需恢复 domain roots。
- `nexusd::snapshot_store::FileSnapshotStore`：Linux Provider 的私有持久内容/根索引/GC/输入物化适配器。与 `FileTaskAcceptanceStore` 使用同一根目录、固定 inode flock 和锁内重读，序列化接受、内容发布、预览保留、GC 和物化。

内容布局为 `<provider-root>/content-sha256-v1/<64 lowercase hex>`，不使用 FNV 地址。manifest_v1 本身也存入此空间，按冻结 SnapshotRef 的 manifest_sha256 读取；旧 Commit/ObjectId 仅定位创建快照时的旧数据，不能用于目标端完整性认证。目标端必须使用已认证接受契约绑定的 SnapshotRef；单纯接收攻击方提供的字节及摘要不构成身份认证。

## 状态与持久化

`snapshot-roots-v1.json` 是带规范 payload SHA-256 的原子镜像，保存 staged preview、独立 explicit retain 和两阶段 GC tombstone。初始空根索引在内容目录创建前严格发布；已初始化目录缺失根索引是 STATE_CORRUPT，不能清空重建。写入失败不报告成功，错误或崩溃后只读最后一次完整发布；损坏原文件保留。

接受存储每次首次打开先持久发布空 acceptance 镜像，再原子发布初始化 receipt，完成同步后才返回可用句柄。已有 N3-1 有效镜像只补 receipt，不重写或变更格式。初始化后镜像丢失返回 STATE_CORRUPT；既有句柄的 read/transact/GC 也直接拒绝 missing image，不回退为空 ledger。receipt 损坏同样 fail closed。

新对象和根索引均使用 create_new 临时文件 → write → fsync(file) → rename → 严格 fsync(directory)，不吞同步失败。重试复用已存在对象前重新验证全部字节并同步文件/目录，不把存在视作首次发布已持久。N3-1 已有的父目录链同步继续保留；子目录每次打开同步本身与父目录。

实际 Task roots 直接从接受镜像中每个 `AcceptedTask.input_pin_intent` 重建，不依赖幂等索引当前值或 TTL。到期键复用后旧任务仍保护原快照；release_preview 只释放预览，不解除 Task 或 explicit root。GC 在锁内先加载完整接受记录及根索引、核实所有受保护 manifest/文件，再持久发布 tombstone，过保留期后删除；新 root 会撤销旧 tombstone。恢复失败/缺失输入会阻止 GC，不能丢弃不完整 roots 继续删数据。

stage/retain/prepare 在发布新的保护根时，同一根索引事务撤销涉及 manifest/文件的旧删除意图。因此即使新根在下一次 GC 前被释放，再次不可达也从新 tombstone 起计完整保留期，不复用更早时间。

所有 N3 输入已经复制进强摘要空间，旧 FNV GC 不会操作该目录，故不需要改变旧 Workspace DAG、GC 持久格式或把 pin 混入既有用户 retain 集合。Task 输入 pin 当前保守保留；释放需后续 N3-3 的权威持久终态，不凭请求或键过期释放。Pending Artifact/Delivery 的实际持久状态和相应 roots 接入归后续产物阶段；不能据此声称 `n3-gc-roots` 全场景通过。

## 目标端物化

先验证 Snapshot 身份、manifest digest、规范 UTF-8 路径排序、重复/文件目录名称冲突、数量/长度总计和每个文件 SHA-256；cwd 必须为清单形成的目录或 `.`。本期目标为 Linux case-sensitive 名称，无 Unicode 自动归一化，不承诺 Windows 目标端名称规则。

全部字节核实完成后，在私有 Provider root 下独占新建 0700 输入目录；路径不由请求选择根目录。中间目录须为真实私有目录，文件用 create_new、O_NOFOLLOW 和非阻塞打开，拒绝链接和特殊文件；数据文件 0600，显式 executable 文件 0700。物化返回 `PreparedSnapshot` 只代表已核实私有输入，不代表容器隔离、真实 command_start 或 Task 状态推进。失败的私有树不返回成功；未提交临时文件和失败物化树清理治理留后续生命周期阶段。

## 验证与证据

新增测试用真实 Workspace Commit、ring SHA-256、磁盘 root 索引和独立标准 SHA-256(`abc`) 向量，覆盖固定输入、规范 manifest 字节、选择/CWD、路径冲突、损坏/缺失、权限/链接/FIFO、到期键复用、冷启动与独立保留、两阶段 GC/复活、并发句柄与进程、发布错误和子进程异常退出。ignored helper 由父测试显式运行，不是跳过能力验证。

测试和 Harness 输出、逐文件绑定、冻结摘要核对、独立 Review、Full 结果存于 `.evidence/n3-2/` 与 `.evidence/review-n3-2-*/`。现有 22 条 N3 E4 场景仍依赖未来真实 verifier，禁止用本批 E2/E3 基础测试替代。

R1 指出接受镜像 missing fallback 和 root 复活未立即撤销 tombstone；4 个独立回归先在旧实现上复现 FAIL，再修正为 PASS。补充首次空镜像丢失、旧镜像 receipt 迁移和损坏 receipt 回归。R2 与 Full 的最终结论以 Evidence 为准。
