# N3-5 后续计划与第一批并行开发

基线：`3e7b391b99c837af2437e00b2b56423512bd9d2b`，已同步远端 master。
任务类型：feature。沿用冻结 N3 模型、schema、22 个产品 Scenario 与模块契约，
第一批不更改其期望，不新增 crate、依赖或架构边。
当前已有持久接受、Snapshot/pins、隔离执行与 Artifact 登记/本地接收适配器。
这些 E2/E3 证据尚未交付跨节点产品服务；N3 全套 E4/E5 未通过。

## 第一批：三个独立 worktree 并行实现

| 轨道 | 分支与目录 | 负责范围 | 必须守住的边界 |
|---|---|---|---|
| A：统一 API/CLI 基础 | `n3-5/api-cli`，`/workspace/ws-n3-5-api` | control-api 的六类版本化 Task 操作与统一 Service、严格 CLI 解析及诚实未装配响应 | principal 不来自请求 DTO；CLI 不持有 TaskOwner、不 spawn；本批不新增未定义的 HTTP 路由 |
| B：请求方恢复状态 | `n3-5/requester`，`/workspace/ws-n3-5-requester` | 只读 provider 镜像、单调事件校验、持久取消 outbox 与恢复 | 本地意图只写 cancel_request；ack 仅证明送达，不证明停止；不覆盖 provider 终态 |
| C：原执行冷核实 | `n3-5/recovery`，`/workspace/ws-n3-5-recovery` | 依据原 Engine 身份及 owner lease 核实/保守停止恢复，防止命令重执行 | 未知保持 PendingVerification；不凭 PID/墙钟定终态；不延长原 timeout 预算 |
| 集成与审查 | `n3-5/integration`，`/workspace/ws-n3-5-integration` | 接口协调、补丁集成、回归、独立审查、最终 Harness 与证据 | master 保持不变；不把缺服务的局部测试冒充 E4/E5 |

三轨只依赖基线已有的领域 DTO 与持久 authority。A 的 Service 是协议边界，B/C 不等待
尚未交付的 A 传输；集成统一处理 lib.rs 导出，避免共享注册文件互踩。
开发结果保留在独立工作区，以原始补丁、精确源码 SHA 和测试记录交付给集成者。
本次未要求自动提交、推送或同步 master，集成完成后保持可审阅的改动。

每个 worktree 独立 `CARGO_TARGET_DIR`、`NEXUS_AGENT`、LocalAPI token、runtime 与
`.evidence/n3-5/`；使用 Rust 1.98.1。为控制 7 GiB 可用磁盘，构建 debug=0、
incremental=0、每轨 jobs=2。不共享其他 worktree 的 rmeta 或 Cargo target。
Docker 是共享系统资源：只有轨道 C 使用固定现有 image content ID，清理仅限自己的
测试容器；禁止全局 prune、pull、改 tag 或重启 daemon。

## 第二批：服务装配与安全前置

1. 明确 LocalAPI 路由/方法/body/认证上下文契约，再建立旧版本 red 与冻结记录。
2. 装配 daemon 的统一 Task Application Service，把接受、Snapshot、Executor、
   Artifact 与 requester outbox 接起来；启动先恢复 authority 和 roots，再允许新工作/GC。
3. 接入真实当前 Use grant、接受主体/Workspace 检查、环境核实与实际容量预留，
   拒绝操作持久审计；撤权走同一确认停止/reap 路径。
4. 装配双向认证且保密的既有获准传输。N2 独立 TCP challenge-response 不承载
   N3 命令/输入；没有安全通道就拒绝跨节点任务，不能降级成明文 TCP。
5. 将 CLI 接入真实 daemon 服务，输出版本化 task/logs/artifact/error；实现安全的
   分页获取、本地摘要校验与原子不覆盖发布，保留业务 exit 0、用法 exit 2。

已找到可复用的服务入口：`nexus::n2_store::N2Store` 提供 `load_grant_table` 与
`audit_sink`，`n2_admission` 目前按认证公钥派生主体后校验 grant。装配时须改为
请求所属 Workspace，不能沿用 N2 admission 中固定 default Workspace 的便利假设。
现有 `nexus-fabric` 提供 TLS 1.3 与服务器证书公钥 pin，但 client 配置为
`with_no_client_auth`；这不单独证明 N3 双向认证。下一批需明确已验证请求方身份如何
绑定到保密通道，并审查原始 Task 数据传输之前的认证门禁，不能只因使用 QUIC 就放行。

API/CLI、授权服务与安全传输必须共同就绪，才能运行完整跨进程产品路径。
不以真实容器的局部运行代替这一装配，也不把 Task 状态机复制到 verifier。

## 第三批：产品验收与生命周期

- 补 `n3_task_e4` 编排真实独立 requester/provider 进程，记录实际启动次数、日志、
  标签、原始产物与摘要；逐一闭合冻结 22 个 N3 Scenario。
- 覆盖断连、取消/撤权、超时、StartIntent 崩溃窗口、outbox 重启、补传与查询授权。
- 明确保留期、active/pending/显式 root 与恢复次序，再实现 Artifact 回收及终态 pin 释放；
  不能因终态或过期就删除仍可达数据。
- 在真实 Windows requester 与 Linux provider 两机运行 E5，记录 node_id/OS/locator、
  实际 image digest、Snapshot 与下载摘要。本机双进程不称跨平台证据。
- 完成 fresh Full；既有网络失败与 UNKNOWN 独立记录，不削弱期望以获取 PASS。

## 第一批验证与交付条件

每轨先局部 check/clippy 与有意义的错误、并发、持久化回归；B 验证真实跨进程
竞争及 SIGKILL，C 验证真实 Engine 原句柄与无二次执行。默认 ignored 不算通过。
集成依次执行 check、affected、Fast、独立八维 review、Full；审查最多三轮。
保留红灯、首次失败、精确源码/冻结文件 SHA 与分别归档的 Fast/Full 原始结果。

独立 Review 或局部测试通过仅证明本批范围。公开任务服务、安全前置及 E4/E5 未完成时，
Candidate Completion 不代表 N3 可用，更不能声明 Final PASS。
