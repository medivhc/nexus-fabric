# N3-6 第二批：本地 Task 服务与双向 TLS 前置

前一批已在 `n3-5/integration` 提交为 `9e5086d`，没有 push 或同步 master。
本批基于该 commit，类型 feature；先补 LocalAPI/Fabric 契约、保留旧 verifier
缺失红灯与旧真实 HTTP 拒绝，再冻结后开发。规范：
`docs/N3-6-LOCALAPI-SECURITY-CONTRACT.md`；原 22 个 N3 场景及 schema 不变。

| 轨道 | 分支 / worktree | 所有权与可交付范围 |
|---|---|---|
| A Service | n3-6/service / /workspace/ws-n3-6-service | apps/nexusd Task Service/HTTP/配置/main，apps/nexus 授权 facade；真实当前 Use grant 与拒绝审计，本地持久事实查询和取消 |
| B mTLS | n3-6/transport / /workspace/ws-n3-6-transport | nexus-fabric opt-in 双向 TLS/证书身份/认证前应用门禁；真实独立进程 E4；不实现 Task RPC 或修改领域算法 |
| C CLI | n3-6/cli / /workspace/ws-n3-6-cli | apps/nexus task CLI/严格有界 LocalAPI client/main；真实 daemon 响应与关联性，离线明确错误，保留 FIFO/legacy 边界 |
| 集成 | n3-6/integration / /workspace/ws-n3-6-integration | 契约/红灯/冻结、共享 lib.rs 导出协调、产品边界场景、证据与独立 review |

各 worktree 独立 target、NEXUS_AGENT、token/config/runtime 与 evidence；debug=0，
incremental=0，jobs=2，Rust1.98.1。已删除完成批次的生成缓存，保留其源代码、分支、
所有原 patch 与证据；不动原 master target。Docker 只用已有固定镜像，不 pull/prune。

实现不得改冻结文件；source/patch SHA 交付，集成核对后复制所有权范围。
两处 apps/nexus lib.rs 注册可能重叠，由 root 集成；不为共享问题新增 crate/依赖。
新增 E4 仅证明 LocalAPI 版本/鉴权/能力门禁与 mTLS 安全前置，不替代完整 Task E4。
真实 Submit 仍需 capacity reservation、唯一 SessionManager、Snapshot 上传协议和
安全远程 RPC；CLI 完整下载仍需将既有 daemon receiver 正式组装到前端请求链。
这些不满足时明确 UnsupportedCapability，不设置假 accepted/session 或伪完成下载。

验证依次 check→affected→Fast→独立八维 Review（最多3轮）→Full；原生场景统计
包含 product/platform/engineering/regression，不从单个 product gate 推总数。
前一批 Full 的 N2 前置资源缺失及网络 rebind/reap 失败单独记录，不删改旧场景。
本批仍不自动提交新改动、推送或修改 master；用户当前“提交”已针对上一批完成。
