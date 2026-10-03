---
id: n3-accept-atomic
date: 2026-10-03
module: nexus-domain / nexus-compute / apps/nexus / apps/nexusd
category: implementation-pattern
task_type: feature
---

# 幂等接受须原子保存 Task、作用域索引和 pin 意图

## 问题/模式描述

仅在内存中去重，或者分次写 Task、幂等 key 和输入保护信息，会在并发提交或接受后崩溃时产生重复 Task、丢失 pin，甚至假称已接受。存储 rename 成功后目录同步失败时，返回错误也不证明没有提交。

## 原因分析

接受需要 durable acknowledgment；进程内 mutex 无法串行化不同进程，临时文件同步也不能替代目录同步。现有 FileKvStore 的 put 会忽略目录同步错误，不能单凭该行为认证更严格的 N3 接受语义。

## 解决方案

compute 管理领域接受事务，组合根注入原子存储：固定 inode flock、锁内重新读取、Task/index/pin 同镜像、fsync(file)、rename、严格 fsync(directory)。rename 后出错视为 ambiguous commit，按原作用域 key 重读和重试；不缓存假成功，也不触发命令启动。损坏镜像保留取证并 STATE_CORRUPT。

## 教训/可复用要点

- 作用域包含 Workspace、已认证主体、Provider、key；TTL 从首次接受起计，不因重试续期。
- 锁文件不能删除重建，否则独立进程可能锁住不同 inode。
- requester cancel outbox 与 provider cancellation/TaskOutcome 必须分开；意图不是停止证据。
- JSON 摘要要匹配独立字节向量；禁止重复 key、浮点舍入或 serializer 默认转义导致多种摘要。
- 针对文件同步、rename、目录同步分别注入错误，并用真正子进程异常退出验证恢复。

## 参考

- docs/N3-MODEL-CONTRACT.md
- docs/N3-1-IMPLEMENTATION.md
- .evidence/review-n3-model-v1-r2/

## N3-1 独立 Review 修正

R1 发现 create(root) 成功者之外的 AlreadyExists/失败重试可能跳过父目录同步：另一个进程 ack 之前不能依赖最初创建者已完成 fsync。每次成功 open 均同步 canonical root 的所有已存在祖先目录，覆盖创建者崩溃/父同步错误和并发初始化。

Stopped/Timeout 是确认的执行事实，Cancelled/其他 generic failure 不能覆盖它；终态必须为 Failed/Timeout。取消正例必须使用真实取消原因，不能让组合矩阵复用 Timeout fixture 认错为对。

来源：.evidence/review-n3-1-r1/ 的 N3-1-R1-01、N3-1-R1-02。
