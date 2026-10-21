---
id: n3-ledger-cost
module: apps/nexusd
date: 2026-10-21
source: review
tags: [staging, ledger, performance, evidence]
---

# 保留取消索引后的全表验证成本

独立代码审查 n312rec20r1a 指出：非 Begin 请求在授权前及持有租约时分别读取和验证整个 ledger，validate_all 再逐条检查文件树；每次 durable edit 又校验并序列化全表。Cancelled tombstone 增多时，这些重复工作累积。

审查截点的真实51项二进制E3仍在满表用例，插桩运行已超过28分钟。这是运维和测试成本的观察，不能当作未插桩性能基准，也不能据此声称违反尚未定义的延迟阈值；完整E3必须等真实退出，不能以局部成功、中断或改小数据规模代替。本轮最终51项通过、0 skip，插桩总耗时3199.795秒；结果见docs/recovery/2026-10-21/verification.json。

后续先建立0/128/512/1024条记录的未插桩基准，再定位重复decode、validation和目录检查。优化须保持checksummed ledger、完整异常检查、原inode绑定、audit-before-lease及冻结测试期望；不能通过删校验或缩小满表测试换取通过。

参考：apps/nexusd/src/snapshot_staging/backend.rs、ledger.rs、recovery.rs；apps/nexusd/tests/n3_snapshot_staging_binary.py 的 test_cancelled_tombstone_table_is_bounded_and_never_silently_reuses_live_key；.evidence/review-n312-recovery-n311-restore20-r1/。
