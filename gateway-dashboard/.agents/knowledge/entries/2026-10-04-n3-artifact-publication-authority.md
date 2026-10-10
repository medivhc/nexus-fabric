---
id: n3-artifact-publication-authority
module: nexus-compute / apps/nexusd
tags: [artifact, crash-recovery, delivery, authorization]
severity: high
source: debug
date: 2026-10-04
related: [n3-runtime-start-authority, n3-snapshot-roots]
---

# 交付 authority 丢失不能被解释为新下载或旧版本迁移

Published 需要已验证真实内容、durable Catalog 和当前授权获取路径，不能仅把 DTO 标志改绿。
TaskOwner 的交付事件必须与 Catalog 一致，命令退出与交付完成分别记录；补传永不 spawn。
输出要核对已 reap/封存的真实工作树和暂存字节，日志即使 outputs=[] 也须登记。

在准备登记的 Task 上，同时删除 Artifact image/receipt 和接受升级 receipt 后，旧初始化
逻辑可能把剩余内容目录误认成尚未使用的旧版本。内容目录证明已有状态，须在任何创建
之前拒绝；新接受、读取和 GC 都需要恢复完整 authority。损坏不清空重建。

下载进度和部分文件同时丢失时，目标私有目录/稳定 receiver lock 仍证明已有 authority。
不能按 offset=0 重新初始化。下载 lease 的 inode 也属于身份；文件丢失后创建新 lock 会
绕过已有 owner，需要拒绝，活 owner 操作前也核对当前 inode。三项红灯回归已保留。

下载发布使用 durable Publishing intent + no-replace hard_link + 目录同步。
崩溃后只有原 partial 的同 inode 目标及完整 SHA-256 才可确认本次发布；已有不同 inode
即便相同字节也不能被当作己方产物。进度与发布 receipt 不得早于实际持久化确认。

参考：docs/N3-4-ARTIFACT-DELIVERY.md；.evidence/n3-4/；真实 SIGKILL 的 5+3 个窗口。

审查中的既有 Snapshot 并发夹具首次 24 PASS /1 FAIL，单独重跑 PASS。
Commit ID 按契约包含真实创建秒；在线程中重新创建 Workspace/Commit 后跨秒产生不同
SnapshotId 是正确行为。相同身份的并发/GC 测试必须共享同一固定 Workspace/Commit，
保留摘要相等和 GC 断言，不能删时间字段或只用一次重跑来覆盖失败。
