---
id: os-assemble-netlink-decision
title: OS 装配 netlink 选型：手写窄 netlink，不引入 neli/rtnetlink
tags: [netlink, dependency-review, linux]
module: nexus-platform-linux
severity: medium
source: architecture-decision
date: 2026-09-30
related: ["tun-rs-device-impl"]
---

## 问题描述

P3.x OS 装配需要 netlink 操作（配 IP、加/删路由、快照查询）。
候选：① `rtnetlink` ② `neli` ③ 手写窄 netlink（仿 tun.rs）。

## 决策

选 ③ 手写窄 netlink，新建 `netlink.rs` 模块，零新第三方依赖。

## 原因分析

1. **rtnetlink 出局**：tokio async；仓库 std-only、无 tokio（tun-rs 条目已确认），
   引入 tokio 是架构级倒退。
2. **neli 可用但太重**：BSD-3-Clause、pure Rust、有 sync API（`router::synchronous::NlRouter`），
   license 没问题；但会引入 libc + serde + neli-proc-macros（syn/quote）整棵树，
   而本 crate 当前只有 1 个依赖（nexus-platform）。
3. **需求有界**：只需要 RTM_NEWADDR / RTM_GETADDR / RTM_NEWROUTE / RTM_DELROUTE /
   RTM_GETROUTE 五个操作，消息构造/解析约 300 行可控。
4. **一致性**：tun.rs 已确立"手写 extern C 窄绑定，不引入第三方 FFI crate"的纪律；
   netlink 同属 Linux UAPI 窄接口，同一纪律适用。

## 解决方案

- `netlink.rs`：unsafe 集中一处（socket/sendmsg/recvmsg + 消息帧），显式 Safety Invariant；
  消息构造/属性编码为纯函数，可单测。
- 对齐 tun.rs：`#![deny(unsafe_op_in_unsafe_fn)]`，模块外不扩散 unsafe。
- 零新依赖 → 无需改 policies/architecture.toml。

## 预防措施

- netlink 属性对齐（RTA_ALIGNTO=4）和多部分消息（NLM_F_DUMP + NLMSG_DONE）
  是手写最易错处，必须有单测覆盖往返编解码。
- Review 时重点查：seq/pid 匹配、NLMSG_ERROR 处理、EAGAIN 重试。
