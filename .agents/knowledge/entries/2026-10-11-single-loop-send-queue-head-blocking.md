---
id: send-queue-hol-block-001
title: 单事件循环 + 无上限发送队列：一条超过通道可用缓冲的消息会永久头阻塞其后所有消息
tags: [event-loop, backpressure, datachannel, head-of-line-blocking, str0m, pagination]
module: nexus-web-gateway
severity: high
source: review
date: 2026-10-11
related: ["tcp-egress-review-fixes", "ice-candidate-bind-set-001"]
---

## 问题描述

网关是**单事件循环**架构：所有会话（终端、信令、文件元数据）共用一条发送队列，
`flush_send_queue`（`src/gateway.rs:1159-1186`）每 tick 从队首往外写。

新增的 `FileListAck` 没有分页也没有大小上限：10 万条目 ≈ **10.4 MB JSON**。评审实测（角度 5/6/9）：
这条消息永远发不出去，并且把它身后**所有终端与信令消息一起堵死**；同时每 tick 用
`front().cloned()` 复制整条 10 MB 消息，10 次观测 RSS **+182.8 MB**。另有一条独立天花板：
>2520 条目录项就超 Chrome 单条 DataChannel 文本消息上限。

## 根因分析

str0m 的 `channel.write()` 在 `buf.len() > available`（通道可用缓冲 **128 KiB**）时返回
`Ok(false)`，语义是"暂时写不下"。V1 的处理是 `break` 并**把队首原样留着**——这个策略只对
"稍后会腾出空间"的消息成立。若某条消息**永远大于**可用缓冲，它就永远满足不了"腾得下"的条件：

1. 队首永久不可送达 ⇒ 队列语义从"公平 FIFO"退化为"一条坏消息独占通道"；
2. 保留即重试 ⇒ 每 tick 全量克隆超大消息 ⇒ 内存被复制流量放大。

根因不是"背压没做好"，而是**协议允许构造出不可送达的消息**，而队列没有"不可送达"这个终态。

## 解决方案

V2 设计（`GATEWAY-FILE-SERVICE-DESIGN-V2.md` §3）把三层一起做掉：

- **构造性上限**：目录列表分页 `entry_offset / max_entries` → `next_offset / eof`（字段名对齐
  N3-9 的分页语义），`max_entries` 默认 256、服务端再钳 1024；**单条 JSON 消息硬上限 64 KiB**
  （不可配），超限就按已装入的条目截页并回 `next_offset`，绝不产出超限消息。每条 ≤64 KiB ⇒
  通道只要腾出 64 KiB 就能写出，**永久性头阻塞在协议层不可能**。
- **双预算队列**：终端/信令类与文件元数据类分开设预算（文件类 ≤256 KiB）。文件类队满 ⇒
  拒收新的入站文件命令（`QUEUE_FULL`, retryable=true）、丢弃**最旧**的文件类消息并记 INFO 计数；
  **永远不丢** ssh/signaling 消息。
- **不可送达即降级**：发送失败/超预算时丢弃并回显 error，而不是原地无限重试。
- 浏览器侧按 `req_id` + 超时重发（拉取式语义使丢包天然可恢复）。

## 预防措施

- Review 单事件循环 + 共享发送队列时必问三条：**① 协议能否构造出一条大于通道可用缓冲的消息？
  ② 队列对"写不下"有没有终态（丢弃/降级/报错），还是只有重试？③ 队列保留的巨型元素会不会被反复克隆？**
- 任何"一次请求返回整个集合"的接口（目录列表、批量 ack、状态快照）默认要分页 + 字节上限；
  分页字段名与语义优先对齐仓库里已有的权威契约（此处是 N3-4/N3-9），不要再发明一套。
- 弱一致分页要写进文档（页间不保证快照一致，客户端按 offset 幂等合并），否则会被当成事务读。
- 分优先级预算时，把"哪一类绝对不丢"写成不变量并配测试（V2 的资源核算测试④：灌满文件类预算，
  断言 ssh 消息零丢失、文件类显式 `QUEUE_FULL`）。

## 参考

- `crates/nexus-web-gateway/docs/FILE-MODULE-REVIEW-2026-10-11.md` P0-3（:60-64）
- `crates/nexus-web-gateway/docs/GATEWAY-FILE-SERVICE-DESIGN-V2.md` §3、§10
- `src/gateway.rs:1159-1186`（病灶）、`static/app.js`（Chrome 消息上限侧约束）
