---
id: n3-requester-recovery-boundaries
date: 2026-10-04
module: nexus-compute / apps/nexusd / apps/nexus
category: implementation-pitfall
task_type: feature
---

# Provider 作用域、原执行 owner lease 与 CLI 文件边界

## 问题与根因

TaskId 是提供方生成的不透明标识，不能把请求方缓存的单字段 TaskId 当成跨 Provider
唯一索引。两个可信提供方可以选择相同字符串；第二个镜像会错误地撞到第一个的主体
检查，导致合法任务被拒绝。冷恢复中，只比较已打开 fd 与当前 owner.lock 路径也不足：
另一个进程从已重建的同名文件首次打开时，没有旧 inode 身份可比较。

## 修正

Requester authority 以 `(provider, TaskId)` 区分，每次操作仍核对接受 principal 与
Workspace；同作用域接受合同不能改变。outbox ack/reject 必须匹配实际响应的 TaskId。
请求方只修改 cancel_request 与 observation overlay，既有 provider cancellation、
execution/outcome 保持原样；收到 terminal 不能抹掉尚未确认送达的取消意图。

新执行日志持久绑定 owner.lock 的 device/inode，获取租约与活 owner 核对固定 fd、
当前路径和 receipt。kernel u64 身份用字符串保存，避免经过 DTO 整数上限或浮点舍入。
旧日志缺 receipt 时不自动绑定当前文件或迁移，owner claim 明确拒绝；已保存字节仍可读。

原 Engine 身份、Task/contract 与退出/reap/seal 证据核实后才恢复确认事实。
未知 Running 保持 PendingVerification；404 不等于 ExecutionLost，不重新启动任务，
不伪造 timeout 或重置单调预算。恢复 User/Revoked 停止必须核实原 namespace 全子树
已停/reap，不把丢失的日志尾部假装为 EOF。

## 回归与复用

- 两个 Provider 的同 TaskId 各自排队、确认、重启与查询，旧单键版本明确红灯。
- 跨 Task ack/reject、作用域错配不改变旧镜像。
- 原 owner 活着时替换/删除 lock，第二 owner 与原 owner 都拒绝继续 claim。
- 真实 owner SIGKILL、退出 outbox 与 stop outbox 窗口保留原命令身份，实际启动次数不增加。

完整服务认证、旧 receipt 迁移、原 timeout/日志重新附着和 E4/E5 是后续装配，
这些局部回归不能替代其产品验收。证据：`.evidence/n3-5/`，计划 `docs/N3-5-PARALLEL-PLAN.md`。

## CLI 非普通文件不能先阻塞打开

独立审查 `n35parrev001` 发现，先 `File::open` 再判断 `metadata().is_file()`
会在无 writer 的 FIFO 上阻塞，因而无法返回结构化 InvalidRequest。
打开前的类型检查能拒绝已知 FIFO，但路径可被替换，单独 precheck 仍有竞态。
安全策略需要非阻塞打开及已打开 fd 的类型复查；不支持该保证的平台应明确拒绝，
不能把阻塞风险隐藏在普通文件校验之后。普通文件读取仍需保留大小上限。

负例应运行真实 CLI，设置明确截止时间并在失败时 kill/reap 子进程；超时是红灯，
不能作为正常拒绝。保留原 FIFO 红灯证据，修复后刷新 Fast 并由另一位执行者复审。
