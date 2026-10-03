# N3-1：模型与持久接受基础

范围：冻结契约的实现阶段第一批。N3 用户命令、真实输入同步、任务执行、Artifact 交付和跨机验收仍待后续批次；本批不能作为 N3 可用的证明。

## 实现入口

- `nexus-domain::task`：v1 Task/Snapshot/Artifact DTO、强摘要引用、结构与纯状态校验；不修改 Core Plan。
- `nexus-domain::task::codec`：精确整数的规范 JSON 值和编码接口。SHA-256 函数由组合根提供。
- `nexus-compute::task::TaskOwner`：`accept_verified`、内部接受记录查询、作用域幂等、首个 TTL 和冲突处理；不创建 Session、不启动命令。
- `nexus::n3_acceptance`：基于已有 serde/ring/getrandom 的严格 JSON 解码、SHA-256 和随机 TaskId。
- `nexusd::task_store::FileTaskAcceptanceStore`：Linux Provider 的锁与持久化适配器。

`AcceptanceContext` 是已认证、已授权的 Application Service 上下文。调用方必须检查 Use grant、Workspace/输入范围、环境证明与实际容量；本批没有接入这些服务，也不允许把请求里的字符串当成身份验证。重复请求仍需当前授权。首次接受时环境证明必须与请求一致，截止时间及容量预留 ID 固化在记录内。

## 持久化与恢复

同一个 `acceptance-v1.json` 保存 TaskView、输入 pin **意图**和完整作用域索引；pin 的真实存储装配归 N3-2。索引以 `(workspace, authenticated_principal, provider, key)` 作用域区分，TTL 到期复用键不删除历史 Task/pin。

每次事务打开固定 `acceptance.lock` inode，以 Linux `flock` 串行化独立句柄/进程；在锁内重新读取，不依赖进程内缓存。锁文件永不删改或替换。进程退出后 OS 释放锁。Linux FFI 位于 daemon 组合根，安全边界仅为一个持有的 fd；保持 CLI 和 portable crates 的 `forbid(unsafe_code)`。

发布顺序：临时文件 `create_new` → 写入完整镜像及 SHA-256 → fsync(file) → 同目录 rename → fsync(directory)。任何持久化失败均不返回接受成功。rename 后若 fsync 失败，提交可能已经可见；同作用域重试通过重读与目录同步得到原 Task，不能盲目生成新的执行。

每次打开存储目录均同步所有已存在父目录（含 AlreadyExists/失败重试），再进入可接受状态；传入根目录的父目录必须已存在，根目录必须为私有真实目录（0700），新建镜像和锁文件为 0600。重启读取已发布镜像，忽略未提交临时文件。格式、摘要、引用、作用域或状态损坏返回 STATE_CORRUPT 并保留原文件，不清空重建。此适配器仅支持 Linux Provider，其他平台返回 UNSUPPORTED_CAPABILITY。

这是低吞吐接受基础：每次事务读取/验证并原子写整个镜像，历史记录不会自动回收。后续增加规模与保留治理时必须保留同样的原子发布和恢复语义；目前没有容量、性能或长期运行完成声明。

## 验证边界

- 4 个独立冻结字节/摘要向量，拒绝重复键、孤立 surrogate、小数/指数、未知字段、非法版本、越界整数和不安全路径。
- 320 个 phase/outcome/execution/delivery 组合及额外事实、取消意图、非零退出、单调事件/终态保护测试。
- 首次接受、冷重启、重放不续期、冲突、精确到期、主体/Provider/Workspace 作用域、保存失败和损坏镜像测试。
- 12 个独立 store 句柄并发去重；8 个独立进程提交；在 write/file-sync/rename/directory-sync 后异常退出并重新恢复。
- 子进程 fixture 标记 ignored，只由对应父测试以 `--ignored --exact` 显式启动（发布崩溃、初始化崩溃、并发提交）；它不是能力跳过或独立 PASS。

上述为 E2/E3 基础证据，不是 E4 用户任务执行。冻结的 22 条 N3 产品场景仍等待真实 verifier 与后续 N3-2..5，不修改其期望。

最新工程验证、逐文件摘要与独立 Review 放在 `.evidence/n3-1/` 和 `.evidence/review-n3-1-*/`。`PROJECT-STATUS` 保留阶段 A 的冻结快照，本批实际进度与限制以本文和新 Evidence 为准。正式冻结清单仍为 `.evidence/red-n3-model-v1/freeze.json`。

## 独立 Review 修正

R1 发现并已修正：每次 open 都同步父目录链，不把 AlreadyExists 当持久化证明；确认 Timeout 停止只能提交 Failed/Timeout，取消停止事实必须与确认原因一致。新增父同步失败重试、并发初始化、创建者异常退出，以及 Timeout/取消竞态的回归。结论仍等待 R2 与 Full Evidence。
