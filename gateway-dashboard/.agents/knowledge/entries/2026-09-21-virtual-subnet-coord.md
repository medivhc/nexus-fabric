---
id: virtual-subnet-coord
date: 2026-09-21
module: nexus-connectivity / apps/nexus
category: implementation-pattern
task_type: feature
---

# 协调核心批次（P2.3+P2.4）：peer_list 三元组 + E5 loopback 全链路

## 问题/模式描述
- 协调器 peer_list 最初契约只有 (peer, locator)；节点拉取后缺对端 vip，无法 add_peer 建连 → requirement-change 改为三元组 (peer, locator, virtual_ip)，Coordinator::peer_list 保持两元组（crate 最小 API），vip 由组合根用 VirtualIpAllocator::peer_vip 补充。
- 无响应帧协议：Announce/Heartbeat/Release 服务端不回帧，客户端若用"请求-读响应" helper 会阻塞到 EOF → 需 send-only helper（写后即关）。

## 原因分析
- 契约在实现阶段暴露缺口（E5 数据面闭环需要对端 vip），是正当 requirement-change 而非改期望迎合实现。
- TCP 帧协议必须显式区分"有响应帧"与"无响应帧"两类请求。

## 解决方案
- PRODUCT/MODULE/CoordFrame 同步三元组；E5 场景补 a_learned_peer_b_vip / b_learned_peer_a_vip 断言；client_request（读）与 client_send（不读）双 helper。
- E5 用真实 loopback TCP（u32 BE 长度前缀 + CoordFrame），双节点 announce→allocate→peer_list→MeshCarrier 建连→双向包互通。

## 教训/可复用要点
- lib.rs 相邻追加 flow 的 git merge 冲突会互相缠绕（两个冲突块夹同一个函数体）→ 用 `git show master:file` + `git show HEAD:file` 程序化合并（master 版 + 提取 HEAD 的 flow 追加），比手工删标记安全。
- 小节撞号（master 并行批次也用 §12.10）→ 本侧重编号 §12.13，MODULE/scenarios 内部引用同步。
- master 存量场景可能从未跑过 Full（并行批次合入时只 fast）→ 本批次 Full 暴露 node-tags 场景 command 引用不存在的 `nexus-harness run` 子命令，属存量缺陷，单独修。
- 文件行尾：新文件 coord.rs 用 LF；既有 lib.rs/PRODUCT 是 CRLF+BOM（PowerShell 用 ReadAllText/WriteAllText UTF8Encoding($false) 保 BOM）；git 会报 LF→CRLF warning 但不阻断。