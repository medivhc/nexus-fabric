# N3-3 首批：持久运行状态基础

本批继续冻结的 N3 v1 契约，不修改 37 个模型/Scenario 文件。N3-2 已提交为
`15abd4fc058d16937019d56ec58117f470246ba2`；本批位于 `n3-3` 分支。
这是 N3-3 的运行状态与持久恢复基础，不代表隔离 executor、日志或 N3 产品入口已交付。

## 所有权与状态

`nexus-compute::task::TaskOwner` 同时负责接受和事件归约；没有第二个 Outcome Writer、
Planner 或 SessionManager。接受镜像仍保存不可变 Waiting 记录，运行 journal 单独绑定
TaskId 和 contract_digest。回放从该接受记录开始，严格执行事件归约及 domain 状态约束，
不允许上传任意 TaskView 或指定 Completed 来跳过真实交付。

- Prepare → StartIntent → Started → Exited；自然退出保留真实 exit_code 和成功码分类，
  进入 Finalizing / Pending / Unfinished，`outputs=[]` 也不会提前完成。
- StartIntent 先持久保存非 PID 的执行身份，视图置为 PendingVerification。
  首次写入返回 `applied=true`；相同事件重放返回 false，不能据此再次 spawn。
  未知启动窗口不能由墙钟、准备失败或第二个 StartIntent 覆盖。
- Cancel 在没有 StartIntent 时可以确认从未启动；已有意图时保持 Requested，
  直到 adapter 证实 NeverStarted 或完整子树停止且已 reap。
- 运行取消/Revoked 的 stop_reason 必须匹配请求；已确认自然退出转为 TooLate，
  仍等待交付。Timeout 仅在 adapter 确认停止与 reap 后归约为 Failed / Timeout。
- prepare_deadline 只在明确未启动时生效；delivery_deadline 需要已确认自然退出，
  不改变真实退出事实。ObservationLost 不改 Outcome 或已确认执行结果。

事件序号必须连续；相同序号/内容可重放，冲突或跳号拒绝。终态不接受新的执行事件；
允许观察状态变化和自然退出后的 TooLate，不能替换已确定终态。
底层事务也检查历史只能追加、返回视图与重放一致、不同 Task 不复用执行句柄。
一笔事务只能追加一个事件或完全不变；`applied` 必须与实际追加一致，不允许回调伪造。

`RuntimeAction` 是 Provider 内部已核实事实接口，**不是**请求方可填写的协议。
真实 Application Service 必须从当前授权/容量/已校验输入派生启动前置，
执行 adapter 必须给出防身份复用的 Started/Exit/Stop 证据。单元测试输入不是 OS 执行证据。

## 持久化与升级

Linux 组合根在接受目录增加 `task-runtime-v1.json` 校验和镜像与初始化 receipt。
接受、运行更新、Snapshot root/GC 使用同一稳定 inode flock。锁内重读并验证全部 journal，
然后 create_new(0600) 临时文件 → write → fsync(file) → rename → fsync(directory)。
目录同步失败仍返回错误，可能已经提交；重读重放不能授予重复启动。

首次打开合法 N3-2 根时先持久发布空 runtime 镜像和 receipt，再原子升级既有
`acceptance-initialized-v1` 内容，写入 `runtime-v1-required` 标记。接受镜像字节不变。
升级根即使同时丢失两个 runtime 文件也返回 STATE_CORRUPT，不重建空历史。
已有 journal 校验和、版本、Task/contract 绑定、顺序、状态或权限损坏均保留证据并拒绝。
任一 runtime authority 文件幸存也证明已有接受库；即使接受镜像及其 receipt 同时丢失，
恢复也在任何写入前拒绝，不能先发布空接受库再回放日志。
临时孤儿不代替 authority；特殊文件、符号链接和公开权限的 runtime authority 被拒绝。

每次打开、接受/读取、运行更新及 GC 锁入口先回放 runtime；恢复失败阻止新工作和 GC。
接受事务在回调后再次验证 ledger/runtime 绑定，旧接受记录不得删除或替换。
新接受只能追加一个记录，返回记录须与镜像和当前 scoped index 一致；replayed=true 的事务不能改变镜像，
不能以一份合法但丢失旧 Task 的空 ledger 破坏运行日志或 pin。
Snapshot pin 仍保守保留全部接受 Task，包括本批可产生的终态；本批不释放 Task pin，
避免尚未装配的 Artifact/交付恢复遗漏 root。只有后续完整交付/保留期 authority 才能释放。

## 验证边界与后续

新增状态/持久化测试覆盖真子进程的四个崩溃边界和八进程启动竞态。
同时检查真实文件重开、接受镜像不变、事件冲突、未知执行、终态保护、腐坏和迁移。
它们是 E2/E3 基础证据，不冒充 N3 E4。

环境资格探测使用 Docker 本地 socket、解析后的不可变 busybox 镜像 ID，
只读根、network=none、CPU/内存配置和 1 MiB tmpfs；超额写入实际返回 ENOSPC。
配置观察不等于 CPU/内存压力验证；资格探测没有连接 TaskOwner，不是正式 executor。
执行日志在 `.evidence/n3-3/`，探测容器已回收。

下一批接入受隔离 Linux executor：固定镜像/硬配额核实、执行句柄与任务绑定、
从确认启动开始的单调超时、stdout/stderr 有界持久分页及持续排空、整个子树取消/回收。
N3-4 接入 Artifact 登记/授权获取和 delivery 确认；N3-5 装配安全产品入口及实际执行核实。
本批不能证明外部授权、进程实际停止、日志已登记或镜像任务成功，也不新增产品路由。
冻结的 `n3_task_e4` verifier 仍未实现，全套 N3 可用性和 Final PASS 仍待完整 E4/E5。
