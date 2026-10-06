# N3-9：真实 Artifact CLI 下载（requirement-change）

本批将 Linux `nexus artifact get <id> --output <path>` 从未装配接收器的拒绝接通到已有本地提供方分页服务。完整 Submit、输入传输、跨节点身份/保密传输、Windows 下载和完整 N3 E4/E5 仍在后续批次；不变更六个 TaskRequest 操作、schema_version=1 或 TaskOutcome。既有 N3-8 无 task-api.toml 的能力拒绝场景保持有效。

## 1. 可观察行为与协议

- CLI 先经现有真实 LocalAPI 客户端请求 GetArtifact(offset=0,max_bytes=65536)，连接后读取 daemon 创建的私有 token，不创建 token。无法连接返回 PROVIDER_UNREACHABLE；缺失/坏 token 返回 AUTH_DENIED；未启用 Task 服务返回 UNSUPPORTED_CAPABILITY。首次成功 Published record 之前不检查、创建、打开或修改 output/接收器目录。
- 仅 Linux 支持接收器；其他平台在本地输出 IO 前明确 UNSUPPORTED_CAPABILITY。保持 Rust 1.85 MSRV 和 `nexus` 的 forbid(unsafe_code)，不使用较新标准库文件锁。
- 接收器固定完整 ArtifactRecord 与绝对 output；分页不能替换 task/workspace/provider/snapshot/环境/摘要/大小/storage_ref/发布状态/保留期等任意字段。现有严格 DTO、Artifact ID、请求 offset、页长度、next_offset、EOF 相关性校验继续有效；空非 EOF 或无进展页拒绝。
- 新下载可消费 probe 第一页；续传仍先 probe0，随后从持久 offset 读取，不重写旧前缀。每页上限 64 KiB、整个 Artifact 上限沿用 80 MiB。每次请求使用现有 5 秒 IO 预算；无隐式重试、无限等待或重新执行任务。
- 已完整 partial、零字节、已发布本地重放同样额外真实请求 offset=size 的空 EOF 页，核实当前 Use 和相同完整 record 后才 finish。本批保证逐页及最后 EOF 的当前授权检查；不宣称远端授权撤销与本地 hard-link 原子发布之间存在分布式原子事务。
- 成功返回既有 TaskEnvelope::Success(TaskResponse::Artifact)，最后页 offset=next_offset=size、bytes=[]、eof=true，schema_version=1、verdict=PASS。文件输出为完整原始字节，包含二进制数据；成功不在 JSON 中重新输出整个文件。结构化业务失败 exit0，用法错误 exit2；--force 等未声明选项仍拒绝。

## 2. 持久化、并发和无覆盖

复用 N3-4 接收器 progress-v1/checksum、private 0700 目录与 0600 文件、O_NOFOLLOW/O_NONBLOCK、前缀 SHA/长度检查、lease inode、Publishing intent、fsync 与 hard-link no-replace。同一 output 的并发 lease 使用非阻塞 flock；锁忙返回可重试 CAPACITY_UNAVAILABLE，不等待另一个 CLI 的生命期。接收器损坏、丢失或绑定变化不得重置/删除后重传。

授权拒绝、断连、记录变化、非法页、摘要失败不发布新 output，保留可核实的持久 prefix。已有无本接收器发布证明的 output 返回 OUTPUT_EXISTS；竞争输出不覆盖。已发布重放仅认可同 inode 和有效持久发布证明；撤权时失败且保留原文件。崩溃后的三个发布窗口（intent/link/destination sync）与既有接收器 SIGKILL 验证保持。

接收器及专用私有 IO 位于 `nexus` 组合根，`nexusd::artifact_download` 保留兼容 re-export。Linux 平台层只提供安全 `file_lease::try_lock_exclusive(&File)->io::Result<()>`，封装已有 flock unsafe 站点；生命周期由调用方持有 File 决定，WouldBlock 显式返回。该具体宿主 primitive 无业务策略、无新 portable trait/依赖边，不向 portable core 泄漏 OS API。

## 3. 冻结验证与范围

新增有限 E4 `product.n3-9-artifact-cli`：已存在合格固定 Engine 真实执行、TaskOwner 产生真实结果、Artifact 发布后，启动正常 daemon 读取原 authority，真实 CLI 下载超过一页的产物；独立 observer 检查原字节/SHA、最终空 EOF envelope、无覆盖、当前撤权拒绝、授权恢复后的同 inode 重放及进程回收。验证 driver 仅 example/engineering，不增加 production fixture API、不伪造 Completed/engine/exit/reap。

旧 master CLI 对同一有效提供方/真实 Artifact 执行上述场景，必须产生 FAIL/BLOCKED RED，保留原输出、二进制摘要、环境/源码与契约绑定后冻结。本批不改旧 22 个完整 N3 场景的期望或缺失 verifier 状态。

E3 真实 loopback HTTP 测试另覆盖多页二进制、连接中断后 durable offset、全 record 改变、最后 EOF 撤权、零字节、完整 partial、发布重放、坏字节/非法页、probe 失败零 output IO、offline 无凭证 IO及已有输出。旧 missing receiver 测试按本 requirement-change 显式迁移：Linux absent daemon 为 PROVIDER_UNREACHABLE，输出/凭证仍零修改，非 Linux 保持 UNSUPPORTED_CAPABILITY。

不宣称性能完成：现有每页前缀读取/hash 的总成本可为平方级，限额保持原值。本批局部 E4 不证明完整 Submit、输入入口、跨节点或 Windows→Linux E5。
