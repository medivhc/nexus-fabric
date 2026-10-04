---
id: n3-runtime-start-authority
date: 2026-10-04
module: nexus-compute / apps/nexusd
category: implementation-pattern
task_type: feature
---

# 不可变接受与追加运行历史分别持久化，重放不授权再次启动

## 问题/模式描述

N3-1 接受 ledger 强制保存初始 Waiting；直接修改该记录会破坏接受摘要和历史 pin。
只记当前运行视图又无法验证事件回退，StartIntent 与 OS spawn 的崩溃窗口可能被误当未启动。
升级后同时丢失新 journal 和 receipt，如果仍按旧根迁移，会静默重置运行历史。

## 解决方案

原 TaskOwner 从绑定 TaskId/contract_digest 的追加事件归约视图。StartIntent 先 durable，
重放返回 applied=false；未知保留 PendingVerification，不自动重跑，也不由墙钟定终态。
自然退出只进入 Finalizing/Pending，交付确认之前不 Completed；取消确认需要从未启动
或 adapter 的完整子树停止/reap 事实。

组合根 runtime image 与接受/GC 共用稳定 flock。新镜像和 receipt 先完整同步，
再升级既有接受初始化 receipt 的 runtime-required 标记；接受镜像字节保持不变。
升级根丢失新 authority 文件拒绝恢复，而不是再次按旧根初始化。读取/接受/GC 先回放全部
journal，腐坏、跨 Task 句柄复用、序号冲突或错误状态直接阻断，保留取证。

## 教训/可复用要点

- 任意需要执行事实的事件只由受信 adapter 派生，不能把请求方填写的事件作为停止证据。
- 不把 PendingVerification 当成 Failed，也不把真实 exit 与交付成功合并。
- 原子 rename 后失败可能已经提交；重试可确认事件，但不能恢复首次 spawn 的授权。
- 新持久格式迁移必须留下既有 authority 可见的升级标记，区分合法首次迁移与状态丢失。
- 用独立进程异常退出和竞争检查唯一启动意图；单元事件不算真实 workload 执行证明。

## N3-3 首批 R1 审查修正

R1-01 独立重现 low-level 事务不追加事件却连续返回 applied=true。存储层须校验
applied 与真正追加一致，单笔只允许一个事件；不能仅校验返回 TaskView 正确。
R1-02 独立重现接受镜像/receipt 丢失、runtime 空镜像/receipt 幸存时静默重建空库；
runtime 非空则先写空接受镜像后才报错。新 authority 也必须加入旧接受初始化的已存在
证据判断，在任何空镜像发布前失败。回归既检查返回 STATE_CORRUPT，也检查缺失路径
仍缺失、幸存字节未改写，避免“最后失败了”掩盖前置写入。

R2-01 又独立重现低层接受回调清空已绑定运行历史的接受记录，写盘返回成功后，
下一次读取才因 runtime 失去关联报错。接受事务必须保留所有旧记录原样不变，
回调后重新验证完整 ledger 和 runtime 绑定，在任何写入前失败；即使没有 runtime
事件，旧接受/幂等/pin 事实也不能被删除。返回 acknowledgment 也必须匹配真实记录：
一项新接受或完全不变的历史 replay，不能确认不存在的 Task 或错误的新旧标志。

## 参考

- docs/N3-MODEL-CONTRACT.md §5–6
- docs/N3-3-RUNTIME-FOUNDATION.md
- .evidence/n3-3/
