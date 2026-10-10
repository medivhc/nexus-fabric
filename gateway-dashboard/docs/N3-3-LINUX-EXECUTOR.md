# N3-3 第二批：Linux 隔离执行适配器

本批在未提交的运行 journal 基础上继续开发；分支仍为 `n3-3`，HEAD 为 N3-2 的
`15abd4fc058d16937019d56ec58117f470246ba2`。冻结的 37 个 N3 契约文件不变，
没有新增 crate、Cargo 依赖、Planner、SessionManager 或用户协议入口。

## 运行边界

`nexusd::task_executor::LinuxTaskExecutor` 是组合根的 Linux 平台适配器。
TaskOwner 仍是唯一 Task 结果写入者；适配器只提交核实后的 Started、Exited、Stopped 等事件。
它不是 CLI/API Application Service。`run` 的必需回调由该服务重新检查当前执行权限及
实际容量预留，不能以 accepted principal 或 reservation_id 存在代替这些检查。
`cancel` / `logs` 同样要求调用服务先执行当前主体、Workspace 和 grant 检查。
当前测试使用受控的提供方内部调用，不构成安全传输或真实授权的 E4 证明。

执行侧只连接 `/var/run/docker.sock` 的 Engine API v1.45；不使用 CLI context、远程
Docker endpoint、客户端代理默认值，也不拉取/解析可变镜像标签。必须由提供方操作员
批准不可变 image content ID，并实际检查 OS、architecture、digest、memory/swap/CFS/
seccomp 支持。镜像需提供固定的 sleep/cp/tar/ps/kill 工具。镜像自带可写 volumes 被拒绝。
不支持所需隔离、精确配额或工具时明确失败，不执行裸主机工作负载。

容器使用 UID/GID 65534、无 capabilities、no-new-privileges、只读根、network=none、
私有 PID/cgroup namespace、IPC=none、无 Docker 日志驱动（避免旁路无界日志）。
CPU quota、memory 和 memory+swap 与接受值严格一致；`/work` 是指定容量的 tmpfs。
存储值必须是 4096 的倍数且不超过本适配器支持的 64 MiB，memory 不小于 Docker 的
6 MiB，CPU 配额不少于 Engine 的 10 millicores；不满足则拒绝，不暗中舍入/改配额。PID 上限另设 256。
任务内可写工作区的硬存储配额与 Provider 后端的输入、持久日志/输出暂存分别管理；
真实容量回调必须同时预留后端开销，本批没有装配容量调度器。

Snapshot 在准备、传递、容器工作区中三次核实 SHA-256、长度及执行位。
传递子树只供该容器只读挂载；宿主的 Provider/执行父目录保持 0700。
已接受的不可变输入记录与初始私有 materialization 不改变。
准备进程与用户命令使用不同 Engine exec ID；用户 argv 直接交给 exec API，不隐式经过 shell。

## 持久启动与资源所有权

唯一用户 exec ID 与 container ID 在启动前进入 StartIntent，且仅首次 applied=true 可以启动。
容器按 TaskId 的 SHA-256 命名，并带 TaskId/contract_digest 标签。运行句柄使用 Engine
身份，不依赖可能复用的 PID。存在历史意图、执行目录或不明确持久化结果时禁止重跑。

核实用户 exec 的真实 PID/Running/ExitCode 后记录 Started；保存 boot_id 与确认时的
单调时钟值。当前调用用本地单调计时，取消/超时先持久 stop intent，再停止整个容器
PID namespace，确认 Engine Running=false/Pid=0/Dead=false 且用户 exec 已退出后
才记录 Stopped。停止原因和信号独立保存，不伪造成功退出码。
自然退出使用 Engine 实际退出状态与 success_exit_codes，保持 Finalizing/Pending/Unfinished。
即使 outputs 为空，也不提前宣告交付完成或 Completed。

自然退出后清理其剩余同 UID 子进程并核实没有活跃后代，再从真实 tmpfs 导出工作树。
工作树归档和明确输出先 fsync 到受保护的私有暂存，然后停止/reap namespace。
归档逐项检查 checksum、UTF-8、相对路径、重复成员、普通文件和所有父目录，
不将归档名称直接交给宿主提取器。链接或缺失输出只记 Unavailable，留给 Artifact 阶段处理；
本批不登记 Artifact、释放 Task pin、开放下载或确认 delivery。

日志读取线程由同步执行调用持有，在 scope 结束前 shutdown/join；不遗弃长期线程。
错误路径停止容器但不推测 Task 终态；无法确认的事实保持 PendingVerification。
停止后的 Engine 记录及私有暂存保留，供后续核实/交付；测试仅删除各自的容器。

## 有界日志与冷打开

`executions-v1/<sha256(task_id)>` 包含独立 stdout/stderr 文件、绑定 Task/contract/配额的
校验和进度、稳定日志锁/owner lease/start gate，以及 Engine/start/exit/stop/reap 证明。
追加按 write → fsync(file) → 原子发布进度 → fsync(directory)，歧义/撕裂不清空重建。
stdout/stderr 合计最多保留 log_bytes；超量标记 truncated，读取线程仍持续 drain。
按流/字节 offset 分页（每页 1–65536 字节），可重复读同一 offset；没有跨流全序。
只有确认完整流 EOF、子树 reap 与持久 seal 后才返回最终 eof=true。

owner lease 是跨进程稳定 flock。冷打开不把释放的 lease 当成进程退出证据；孤儿
运行记录变为 PendingVerification。没有核实旧 Kernel/日志 authority 前，禁止新增执行。
不会自动产生新的执行 ID 或重新启动旧命令。实际冷恢复接管、原始超时预算核实和服务
启动准入的完整装配属于 N3-5；本批提供保守阻断和持久证据，不冒充自动恢复完成。

## 验证

真实容器套件需要本地 Engine、已批准的不可变 busybox 镜像；默认 workspace 测试不
依赖外部 daemon，所以这些新测试显式执行，未修改任何已有 Scenario/测试期望：

```sh
source /workspace/.nexus-env/activate.sh
NEXUS_N3_TEST_IMAGE_ID=<实际 image content ID> cargo test --locked -p nexusd \
  task_executor::tests::container_ -- --ignored --nocapture --test-threads=1
```

覆盖真实退出/固定输入/暂存输出、字面 argv、两个日志流的超量持续排空/重复分页、
取消确认、单调超时、内核 ENOSPC/CPU throttling/OOM、只读根/非 root、链接与缺失输出，
以及真实 SIGKILL 执行 owner 后保留原执行并阻断新工作。
局部测试覆盖日志绑定/撕裂/权限/链接及二进制 frame/tar 解析边界。
命令、原始结果、源码摘要、独立审查及 Full 结果保存在 `.evidence/n3-3-executor/`。
这些是 E2/E3 证据；冻结的 `n3_task_e4`、安全产品入口、Artifact 交付和 Windows→Linux E5
仍未实现，不据此宣称完整 N3 可用。
