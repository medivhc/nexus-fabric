---
id: n3-prefix-rehash
date: 2026-10-26
module: apps/nexusd
category: implementation-pitfall
task_type: performance
---

# Snapshot staging 每次请求重哈希全部已确认 blob 前缀（上传 O(n²)）

## 问题描述

`snapshot_staging::tests::pressure::ledger_table_future_metadata_is_bounded_and_expired_tombstones_free_capacity`
在 debug 构建下单独运行超过 20 分钟，`verify --fast` 的 affected-tests 被它拖住。
gdb 采样（2026-10-26）：填表循环结束后（count=71），测试后半段以 64 KiB 分块上传
64 MiB，栈顶长期停在 `pread64(count=65536)` + `ring sha256_block_data_order`。

## 原因分析

`FileSnapshotStaging::execute`（`backend.rs`）每个请求都调用
`recovery::validate_all`，它对**每条记录的每个 blob** 执行
`f.hash_prefix(b.offset)`（`recovery.rs` 的 blob 循环），从头重读并重算已确认前缀。
上传 S 字节、分块 C 时共有 S/C 次请求，第 k 次重哈希 k·C 字节：

- 64 MiB / 64 KiB：约 1024 次请求，累计重哈希约 32 GiB；
- 其它 upload 的每次 Get/PutChunk 也重哈希所有 active upload 的前缀
  （≤8 reservation，每请求最多约 512 MiB）。

次要成本：`Directory::check` 对每次打开沿祖先链逐层 `statx`；`ledger::save` 每次
对整表做 canonical 序列化 + checksum（与 `n3-ledger-cost` 条目同源）。

## 解决方案（未实施，需决策）

这是 N3-12「prefix 篡改失败关闭」的实现方式，改动属于安全/性能取舍：

1. 增量：ledger 持久化每 blob 的 SHA-256 中间状态或分块哈希链，请求时只校验
   新增区间 + inode/size/ctime 绑定；冷启动 reconcile 时全量重哈希。
2. 或：请求路径只做元数据绑定校验，全量前缀重哈希仅在 `open`/恢复与 `Seal` 时执行。

任一方案都须先按 AGENTS.md §21 定义 baseline/阈值、建立未插桩基准，并评估
N3-12 篡改检测语义是否仍满足；不能删校验或缩小测试规模换速度。

## 教训

- 「每次请求全量校验」在数据量随请求线性增长时就是 O(n²)；契约写「篡改失败关闭」
  不等于「每次请求全量重哈希」，设计时要明确校验发生在哪个时刻。
- 慢测试先 gdb 采样定位，不要先怀疑死锁或环境。
