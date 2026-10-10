# N3-4 首批：持久 Artifact 与交付适配器

本批从 N3-3 提交 `f56d56b7fdc73a8fb50dd7e233bb384f66a90c30` 开始，分支为 `n3-4`。
37 个冻结契约文件不变，无新 crate、Cargo 依赖或协议路由。
Portable Compute 只负责登记事实校验与 TaskOwner 的唯一交付/终态归约；Linux 文件、
锁、授权服务回调和下载落盘位于 nexusd 组合根。

## 提供方登记与终态

`FileTaskArtifacts::publish` 只消费已经确认自然退出、全子树 reap、日志 seal 的执行证据。
它核对 Task/contract/Engine 句柄、退出码、冻结工作树归档、指定输出暂存和两条日志。
暂存文件必须与归档的真实普通文件字节一致；所有父路径禁止链接。不会再次启动命令。

登记 intent 持久保存 ArtifactId、来源 Task/Snapshot、环境摘要、Provider、Workspace、
接受主体、路径、SHA-256/长度、保留时间及 Pending 状态。ArtifactId 由 Task/路径/内容摘要固定。
内容经验证进入独立 SHA-256 命名空间、fsync 并发布后，再把目录记录写为 Published。
两条日志同样进入有摘要的内容空间并以 TaskId/stream 可读，包含截断事实。
每次 Catalog 更新在发布前校验契约、已登记内容和容量界限。

只有日志和全部 required 输出已持久登记并存在授权获取路径，TaskOwner 才归约 DeliveryReady。
允许的真实退出码 → Complete/Completed；非允许码 → Complete/Failed(WorkloadExit)，
保留真实 exit_code。required 文件缺失或链接不可用 → Failed(ArtifactMissing)。
optional 缺失允许不登记，outputs=[] 仍必须登记两条日志。
可重试上传/持久保存失败保持 Finalizing/Unfinished/Pending，可带结构化 retryable error。
补传恢复相同 ArtifactId 和原始执行事实；交付 deadline 到期不能变成 Completed。

这是提供方“已登记、可授权获取”的交付语义，不以某个请求方已下载全部字节为必要条件。
客户端坏下载不覆盖提供方已确认的执行结果，也不能发布损坏文件。

## 持久 authority 与恢复

接受/运行 journal/Artifact 更新/Snapshot GC 共用既有稳定接受 flock。
Catalog envelope 校验和绑定 Task/contract，Runtime DeliveryReady/ArtifactsMissing 必须与
持久 Catalog 一致；仅伪造 Published 标志或调用领域事件不能绕过文件适配器的核实。
新 authority receipt 在 Catalog/初始化 receipt durable 后升级；不会改写不可变接受记录。
失去 Catalog、receipt、内容，或发生撕裂、公开权限/链接时保留现场并拒绝打开/新工作/GC。
已有 Artifact 目录不能被当成旧版本的空状态初始化。

Catalog 元数据最多 8 MiB；单文件及本批日志发布合计最多 80 MiB，实际工作区限额仍由
N3-3 的硬隔离限制。容量不支持时返回结构化错误，不写出不可重新加载的超限 Catalog。
本批没有 Artifact 删除接口或回收器，显式保留全部内容与 Task pin；未声称完成保留期 GC
和终态 pin 释放。完整服务启动顺序及原执行冷接管继续由 N3-5 装配。

## 每次读取的授权

`list`、`get` 和已登记 `logs` 接受由认证服务提供的 principal/Workspace 上下文，先匹配
不可变接受主体和 Workspace，再调用必需的当前 grant 检查；不缓存一次授权为永久许可。
回调在存储锁外运行，可以重入服务方法。返回页之前重新读取/核实目录与实际内容摘要。
storage_ref 只作为提供方内部内容定位，不是凭证。拒绝经既有 FileKvStore journal 持久审计。

这证明适配器的强制检查边界；测试回调不是已交付的身份认证/grant 服务。
没有开放 CLI/API、跨节点版本化消息或安全传输，也不据此宣称 E4。

## 请求方本地断点下载

`ArtifactDownload` 接收已授权的字节页，不自行拉取或相信 storage_ref。
每个目标使用私有目录、稳定跨进程 receiver lease、校验和进度与部分字节摘要。
写页后 fsync，再原子保存 offset/prefix 摘要；完全重复的旧页必须逐字节匹配，
跳跃或部分重叠拒绝。重开只接受一致的原 Artifact/目标/进度，不清空损坏数据重下。
目录已存在但进度丢失、receiver lock 丢失/换 inode、硬链接或公开权限均拒绝。

完整 SHA-256 与长度校验后保存 Publishing intent，再以同文件系统 hard_link 原子、
不覆盖地发布目标。目标已存在（含链接）返回 OUTPUT_EXISTS；坏字节返回
ARTIFACT_INTEGRITY_FAILED。崩溃在 link 前后由同 inode + 完整摘要核实后恢复确认，
不会用相同内容的另一份文件冒充本次发布。Published 的目标丢失属于损坏，不自动重建。
接收目录、部分文件及发布 receipt 保留，回收需后续显式生命周期策略。

## 验证与边界

局部测试包括真实 SIGKILL 在 5 个提供方登记窗口、3 个下载发布窗口中恢复。
容器测试在 N3-3 的 11 个真实场景上增加 4 个 Artifact 场景，核实真实输出的登记/
分页/断点接收/摘要、不重执行、真实非零码、必需文件缺失/链接及当前授权拒绝。
既有 runtime/acceptance/Snapshot 回归、标准 Harness、WASI 与独立审查的证据保存于
`.evidence/n3-4/`。默认 suite 忽略依赖外部 Engine 的新测试，显式真实测试结果独立保存。
冻结 `n3_task_e4` verifier 仍缺产品入口/真实服务装配；不把本批 E2/E3 当作 N3 E4/E5。

独立审查还暴露了既有 Snapshot 并发测试的跨秒夹具问题：每个线程创建不同 Commit，
却断言同一 SnapshotId。修正为共享同一已冻结 Workspace/Commit，保持原有摘要与 GC
断言；没有修改 Snapshot/Commit 身份语义或冻结场景期望。首次失败与第二轮审查证据保留。
