# N3-6：本地提供方服务与双向 TLS 前置契约

任务类型：feature；基线 `9e5086d63f2ac2f7a2475664b2afe2834a38f591`。
本批增补 LocalAPI 与 opt-in Fabric mTLS，不改变已冻结 N3 模型、schema、22 个
N3 场景及既有 v0 LocalAPI、匿名 Fabric 调用的期望。本契约不是 N3 全部可用的证明。

## 1. 交付范围

Linux daemon 从真实接受记录、runtime、日志、Artifact catalog 与原 Engine 提供
GetTask / ReadTaskLogs / CancelTask / ListTaskArtifacts / GetArtifact。
所有操作逐次检查接受主体、Workspace、提供方及当前 Use grant，拒绝必须持久审计。
SubmitTask 不调用接受：真实容量预留、唯一 SessionManager、完整输入传输尚未装配，
认证/校验后显式 UNSUPPORTED_CAPABILITY；不得伪造 reservation/session/接受/终态。
CLI 接入 task show/logs/cancel/artifacts 与 submit 的真实服务响应。
CLI artifact get 尚未装配 daemon receiver，显式 UNSUPPORTED_CAPABILITY，
不创建、覆盖、修改输出，不把读取一个 Artifact page 声称为完整下载。

跨节点 Task RPC、Snapshot 上传、容量/Session 装配、撤权自动停止、原 timeout 预算
重新附着、Artifact GC/终态 pin 释放与 Windows→Linux E5 属后续批次。
Fabric mTLS 是经真实进程验证的安全基础，本批不因此放行跨节点 Task 业务数据。

## 2. LocalAPI v1 协议

- 单一路由：`POST /localapi/v1/task`；不允许 query string 或编码路径别名。
- Body 为现有 schema_version=1 的 TaskRequest.to_value()，响应为 TaskEnvelope。
  六类 operation 及嵌套 DTO 沿用已冻结 codec；拒绝重复 JSON key、浮点、未知字段/版本。
- Header 上限 16 KiB；请求 Body 上限 1 MiB；响应 Body 上限 2 MiB；单页至多
  65536 原始字节。精确单个 Content-Length、Content-Type: application/json；
  重复 Authorization/Content-Length、Transfer-Encoding、冲突长度与截断拒绝。
  不支持 chunked/pipelining；一次连接处理一个请求，Connection: close。
- 认证先于读取/解码 Body 或调用 Service。Authorization: Bearer 来自既有私有
  token 文件，常量时间比较；不接受任意 principal/header/body 充当认证身份。
- 请求 framing/DTO 错误 HTTP 400 + INVALID_REQUEST；超限 HTTP 413 +
  CAPACITY_UNAVAILABLE；缺失/错 token HTTP 401 + AUTH_DENIED；本路由错 method
  HTTP 405 + INVALID_REQUEST。成功处理业务请求（含业务拒绝）HTTP 200。
  所有本路由错误均为 schema1 TaskEnvelope，不复用 v0 的无版本错误格式。
- Read/Write socket 超时有界；header/body 读取有总预算，防 slowloris 持续占有
  单线程控制面；拒绝后关闭连接，不等待攻击者发送剩余 Body。
- v0 GET 路由的既有业务行为保留。N3 TCP listener 仅允许 loopback，非 loopback
  请求 N3 路由拒绝；Unix socket 用私有权限，不把 LocalAPI token 经明文远程 TCP 发出。

## 3. 启用、身份与恢复

`<config-dir>/task-api.toml` 可选启用；文件缺失时 v1 路由返回能力不足。
配置仅有 `provider` 和 `workspace` 两个必需字符串，拒绝未知字段/非法标识。
提供方 authority 根固定 `<config-dir>/data/n3/tasks`，不能由请求提供本地路径。
配置无 authenticated_principal：本地 token 认证成功后，以本节点持久 N2 ed25519
公钥派生 principal；配置 Workspace 是作用域选择，不代表授权已通过。

启动先验证接受/runtime/Artifact authority 与 roots，核实原 owner/Engine 后暴露
可用服务；未知保留 PendingVerification，不重执行、不延长 timeout、不凭 PID
或墙钟确认终态。损坏、初始化后的 authority 丢失不能自动重建为空，也不能每次
查询新建目录来掩盖损坏。服务缺配置、boot 失败或平台不支持明确返回错误。
不创建第二个 SessionManager，不用 unsafe 强制 Send。

授权使用 AcceptedContract.request 的 resource/workspace，和请求已认证 context
及已配置 provider 比对；GetArtifact 必须回溯其 Task 的相同合同。
每次从真实 N2 持久表加载当前 Use grant（含到期/撤销），审计落盘失败则拒绝。
主体/作用域错配即使 grant 会 Allow 也拒绝，并记录真实错配原因；不伪造 grantdeny。
不把 storage_ref 当授权、不把目录可见当 Use grant。

Cancel 返回原 owner 提交的真实 provider view。ack 或请求受理不等于停止确认，
自然退出 TooLate 不改写结果；重复调用不能重复 spawn 或覆盖既有终态。
未启动任务无日志时只在 NotStarted/no-handle/无既有日志 authority 已核实后返回
empty/eof=false；不得吞掉启动后日志丢失/损坏错误。Artifact 分页沿用已登记记录
与摘要/EOF/范围约束，不枚举任意主机路径。

## 4. CLI 绑定与错误

N3 命令走真实 LocalAPI，不 silent fallback 到演示数据或 run_unavailable。
TaskRequest 不携带本地 output 路径、调用主体或存储授权；Get/Cancel 等响应操作、
TaskId、ArtifactId、stream、offset 必须与请求关联，错误 task_id 若出现也必须匹配。
JSON 输出直接为严格 TaskEnvelope；业务拒绝 exit 0，用法错误 exit 2。
本地 daemon connect/IO timeout：PROVIDER_UNREACHABLE，retryable=true，reason明确
为 local daemon；HTTP401：AUTH_DENIED，retryable=false；非法服务响应/关联错配：
INVALID_REQUEST，retryable=false；容量超限 CAPACITY_UNAVAILABLE，retryable=false。
沿用已有 TaskErrorCode，不修改冻结 domain schema。禁止把网络失败改成任务失败。
既有 FIFO 非阻塞请求读取、大小限制与 legacy run-with-command 拒绝必须保留。

## 5. Fabric opt-in mTLS

新增显式双向 TLS 1.3 模式，保持旧 connect/bind API 的兼容行为。
身份来自 Ed25519 私钥/证书，支持既有依赖构造身份并得到 PeerId；私钥不得通过
Debug/日志/握手报错输出，不自动学习未知节点或忽略错误 pin。
客户端 pin 服务端 PeerId 并提供自身证书；服务端强制证书、验证 CertificateVerify
签名并按显式 PeerId allowlist 允许请求方。空 allowlist 拒绝所有请求方。
验证失败/匿名客户端不进入 accepted 队列，不可取得应用 stream/datagram；
只有双方握手完成、两侧已验证真实公钥才能暴露明确的 mutual-authenticated peer。
旧连接中的占位 PeerId 或单向 server pin 不能通过该 accessor 冒充双向认证。
0-RTT/认证前 Task 数据不允许；握手超时沿用单一预算及 owner/reaper，关闭后无孤儿。
本批不增加 Task RPC frame/Ready 协议、不导出 N2 私钥给 CLI、不降级为明文 TCP。

## 6. 独立验证

新增产品边界 Scenario `product.n3-localapi-v1-boundary`：真实 daemon 进程验证
未认证/非法版本/截断/超限/disabled-service，且不产生接受记录；本场景只证明
协议与能力门禁，不能替代完整任务生命周期的 22 个 E4。
新增 `product.fabric-mutual-auth`：真实独立进程的 TLS 1.3 连接/流往返，证明两侧
已认证公钥匹配；错误 server pin、无证书、非 allowlist 身份均拒绝，未认证应用
数据交付次数为零。不是跨 OS/两真机 E5。
Service 回归覆盖真实持久 authority、当前 grant/撤销/审计失败、主体作用域、
真实取消/自然退出、冷恢复与损坏；CLI 覆盖真实 daemon、关联校验与离线错误。
按 check→affected→Fast→独立八维 review→Full 执行；冻结后不改这些期望。
