---
id: n3-expiry-err
date: 2026-10-19
module: apps/nexusd
category: implementation-pitfall
task_type: bugfix
tags: [expiry, recovery, error-handling, test-review]
---

# 正常过期清理后重新判断请求目标是否存在

Snapshot 变更先校验原 owner/current Use 并完成审计，再在 lease 内校验权威状态。
随后合法 TTL 清理可能移除本次请求的 Cancelled 记录。直接把旧 UploadId 交给
要求记录存在的恢复器，会把正常清理误报为 STATE_CORRUPT。

在清理后、恢复前重新检查目标是否存在；已移除则返回与缺失记录相同的
AUTH_DENIED。保留清理前的完整损坏校验，不能把真正的坏前缀、缺失 payload
或坏 ledger 改为授权拒绝。当前 Use 审计仍在 staging lease 外完成；本路径不
需要为同一次已审计授权再调用一个 lease 内的拒绝审计。

契约允许到期清理时，测试不能强制每次变更或 boot 都立刻删除。通过 Get 的
零写入观察区分保留与移除，再分别断言原 Cancelled 行为或缺失拒绝。两条路径
都检查活动上传的内容、durable prefix、状态和 charge；审计故障控制使用从未
创建的 ID，避免暗中依赖清理策略。

本组独立用例 R2 APPROVED，旧实现三种 mutator 分类 RED、四项控制 PASS；
最小修复后七项全 PASS。局部回归不替代当前组合的 Fast、代码审查和 Full。

参考：N3-12 契约 §3/5/8、独立聚合 Review R1 的 TTL finding，以及
`.evidence/test-review-branch-task-n312-expiry19-2026-10-19/r2/`。
