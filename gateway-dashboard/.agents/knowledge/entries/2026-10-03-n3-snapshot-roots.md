---
id: n3-snapshot-roots
date: 2026-10-03
module: nexus-workspace / nexus-storage / apps/nexusd
category: implementation-pattern
task_type: feature
---

# 强内容空间的根恢复须与任务接受串行化

## 问题/模式描述

把 FNV ObjectId 当完整性摘要，或在恢复接受记录之前扫描内容删除，会导致冻结输入被覆盖或接受成功后失去 pin。根索引缺失也不能被解释为空集合。

## 解决方案

N3 v1 用独立 SHA-256 内容空间，manifest 与文件全读校验；Workspace 从唯一 Commit 和明确选择生成描述。组合根的内容、根索引、GC 和任务接受共享固定 inode flock；GC 根据全部 AcceptedTask 重建 roots，不使用会到期/被替换的幂等 key 作为保留真相。

初始空根索引先持久发布，再创建内容目录；已初始化内容目录丢失根索引直接 STATE_CORRUPT。未完成首次目录同步的既有内容在重试时重新同步。释放预览不解除已接受 Task 或显式 root。两阶段 GC 在 sweep 前锁内重验所有 root，恢复不完整则停止删除。

R1 找到两个缺口：接受镜像的 missing→空 ledger 回退同样会丢根，故首次空接受镜像和初始化 receipt 必须在开放句柄前持久化；已有有效镜像迁移只补 receipt。根复活后不能只等 GC 看见它才撤销删除意图：stage/retain/prepare 发布保护与撤销 manifest/文件 tombstone 在同一索引事务内完成，防止下一次 GC 前先释放新根而复用旧保留期。

## 预防措施

- 检查创建者与 AlreadyExists 重试，不把存在当成 fsync 完成证明。
- 接受与 GC 须锁同一个稳定 inode；不要复制 pin 到独立未绑定的内存缓存。
- 接受记录保留历史 Task；幂等过期不等于任务终态，更不等于可以 GC。
- 私有物化树每次新建；不在调用方指定的既有目录跟随 symlink 写入。
- 用独立进程的异常退出/并发、独立摘要向量和缺失根索引回归验证。

## 参考

- docs/N3-MODEL-CONTRACT.md §4
- docs/N3-2-IMPLEMENTATION.md
- .evidence/n3-2/
