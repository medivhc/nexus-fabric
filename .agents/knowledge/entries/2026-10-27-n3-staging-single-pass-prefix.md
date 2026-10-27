---
id: n3-single-pass-prefix
date: 2026-10-27
module: apps/nexusd
category: implementation-pattern
task_type: requirement-change
---

# N3-12 每请求只校验一次已确认 prefix，并续算提交摘要

## 问题/模式描述
staging 每个请求在入口 validate_all、chunk 追加前复核、提交前 hash_prefix 共约 4 次重读已确认 prefix，整次上传 O(size²)；32 MiB release 基准 28.7 s。

## 原因分析
每个 durable 检查点都复用了冷恢复的完整校验；提交摘要从磁盘重算而非续算。

## 解决方案
- 入口完整流式校验记录 `Verified{inode, offset, Sha256Stream}`；同请求后续复核只查绑定/长度/intent（`validate_record_trusting`）。
- 提交摘要 = 入口状态 clone + 本请求追加并回读核实的 bytes；仅当 entry offset == c.old、inode 一致且整 chunk 在本请求追加时续算，否则完整重算（请求内恢复改变 offset 的情况必须走回退）。
- 契约门禁计字节不计时间：cfg(test) 读取层按文件角色计 hash/read 字节。
- 结果：32 MiB 13.7–13.9 s（3 次），debug 压力测试 524 s → 433 s（剩余主要是每次编辑全量重写 ledger）。

## 教训/可复用要点
- 每请求字节预算必须显式列出幂等重试比较路径（读 + 回读 = 2×length），否则契约与实现冲突（review r1 B1）。
- “先恢复再写”同请求路径要有专门测试：去掉 offset 过滤器的变异体否则存活（review r1 B2）。
- harness contract hash 只覆盖 scenarios/，修改 MODULE.md/docs 不改变 marker 值。
