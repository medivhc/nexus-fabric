---
id: n3-authorized-download-progress
date: 2026-10-05
module: apps/nexus / apps/nexusd / nexus-platform-linux
category: implementation-pattern
task_type: requirement-change
---

# 接收器复用要保留当前授权、原发布证明和宿主边界

## 问题与原因

已下载字节、完整 partial 或原 Published receipt 只证明本地内容/发布身份，不能证明当前 Use grant。分页客户端既有相关性只覆盖 Artifact ID 和窗口，其他 record 字段也属于绑定身份。将接收器从 daemon 复用到 CLI 时，原 flock unsafe 与 CLI forbid(unsafe_code) 冲突；std File 锁接口的稳定版本晚于 Rust 1.85。

## 方案与复用要点

- 先实际 probe，成功取得 Published record 后才打开本地接收器；保持连接后才读私有 token，offline 不创建凭证或 output。
- 固定完整 ArtifactRecord，续传使用 receiver durable offset；每页相同 record，最后额外获取 offset=size 的空 EOF 页。零字节、完整 partial 和已发布重放都执行当前授权检查。
- 授权 EOF 与本地原子发布分属不同节点/系统；记录它们之间的非原子区间，不声称撤权和 hard-link 发布有分布式原子性。
- 复用 checksum progress、原 inode、SHA/长度和 Publishing intent；坏页/断连保留 prefix，损坏或丢失 authority 保留取证。原目录/lock 不能被当作全新接收器。
- 将原 flock unsafe 站点移到既有 Linux adapter 的最小安全 primitive，使用非阻塞锁，WouldBlock 映射可重试容量错误；持有 File 的生命周期保持 lease。接收器专用 IO 留组合根私有，不扩大 provider authority API 或增加 portable trait。

## 真实验证夹具

提供方 cold boot 会核实原 Snapshot/Engine/exit/reap authority。只有 cfg(test) 的假输出夹具不足以启动正常服务；使用现有真实 Engine/TaskOwner 执行并发布，再让普通 daemon/CLI 获取已有产物。种子通过原 LocalTaskService 持有真实 capacity-owner Ready lease，不新增 production fixture API。

普通 daemon 首条 stdout 可以是 boot-reconcile JSON，随后才 READY。observer 在总 deadline 内循环等待 READY，保留 stdout/stderr、seed 和各 CLI JSON；启动观察失败与“真实有效 Artifact 下载失败”的 RED 分开记录。固定容器只在原 Task/contract labels、Stopped/Pid0 校验后由 observer 清理。

## 参考

- docs/N3-9-ARTIFACT-CLI-CONTRACT.md
- .evidence/n3-9/spec-freeze.json 与 red-artifact-cli.json
- engineering/verifiers/n3_artifact_cli.py
