---
id: datachannel-label-routing-001
title: 新增第二条 DataChannel 会打死旧功能——旧节点忽略 ChannelOpen 的 label，"后开者赢"
tags: [webrtc, datachannel, version-skew, capability-negotiation, routing]
module: nexus-web-gateway
severity: high
source: review
date: 2026-10-11
related: ["ice-candidate-bind-set-001", "wireup-bind-stream-routing"]
---

## 问题描述

给 `nexus-web-gateway` 加文件能力时，前端在**首个 SDP 里无条件创建**第二条 DataChannel
（label `nexus.file`，`static/app.js:385-387`）。旧节点的通道处理是：

```rust
Event::ChannelOpen(cid, _) => sess.channel = Some(cid)   // label 被丢掉，后开者赢
```

于是"**新页面 + 旧节点**"这一组合下，`sess.channel` 被文件通道覆盖，**所有 `NodeMessage`
（终端输出、节点列表、信令）被送进二进制文件通道** ⇒ 终端与节点列表整体失联。灰度共存或
回滚页面即触发，属 P0（评审角度 14 判 WARN，但危害是整站失效）。

同一处代码的旧形态还有两个坑：原实现把 `ChannelOpen` 的 label 丢弃、并且**直接丢弃所有 binary
帧**，所以任何二进制子通道进来就没有归宿。

## 根因分析

三层叠加：

1. **接收端没有按 label 路由**，把"通道"当单例存储 ⇒ 通道数量从 1 变 2 时，语义直接错乱；
2. **发起端不查对端能力**，无条件建通道 ⇒ 把不兼容窗口从"不可能"变成"每次都触发"；
3. **协议没有版本位/能力声明**，两端无法在建立前发现不兼容，只能靠部署顺序假设（"节点一定比页面新"）。

这不是"文件功能没做好"，而是**在共享信令面上做增量演进的通用陷阱**：任何"多发一条通道/多一种
流类型"的改动，都必须在旧对端的解释规则下自证安全。

## 解决方案

- 接收端按 label 管通道（本次把 `Session` 从单通道改为 label 键控，并保留"按 label 优先 +
  无名首通道兜底"，`src/gateway.rs:1196-1205`，V2 把这条列为**不得回退的契约**）。
- 发起端**能力门控**：页面仅在 `/api/config.files` 报
  `enabled && version >= 2 && capabilities ∋ "server_streams"` 时才在 SDP 里建文件通道；
  `/api/config.files` 缺字段 = 旧版 = 不建通道（这同时给回滚留了自动降级路径）。
- 显式版本协商：`file_open{version}` / `file_open_ack{version, capabilities[]}`，
  版本不匹配 ⇒ `UNSUPPORTED_VERSION` 显式拒绝，**不做暗中降级**。
- 帧头演进留安全位：14 字节头冻结，`flags` 现只用 bit0，bit1-7 必须为 0，收到置位即
  `FRAME_FLAGS` 拒绝；`kind` 未分配值直接拒绝。

## 预防措施

- Review 到"新增一条通道 / 新增一种流类型"时，第一件事是查**旧对端如何解释它**：
  搜 `ChannelOpen`/`accept`/首字节分派处是否忽略 label/type；凡是"单例变量存通道"的写法，
  新增通道就是破坏性变更。
- 规则：**新通道必须按能力门控创建；老代码必须按 label（或类型前缀）兜底路由**。
  两者成对出现才算完成演进设计。
- 混版本要真测：V2 把"新页 × 旧节点、旧页 × 新节点"两条 e2e 列为里程碑 M2 的退出准则；
  只测同版本等于没测。
- 与 NAT 侧的同类经验（`wireup-bind-stream-routing`：stream 首字节 type 前缀 + 不 peek 消费）
  一致——**分发键要显式存在于协议里**，不能靠"到达顺序"或"最近一个"。
- 回滚设计里把"能力字段缺失 = 旧版本 = 不启用新面"做成默认，比做配置开关更可靠。

## 参考

- `crates/nexus-web-gateway/docs/FILE-MODULE-REVIEW-2026-10-11.md` P0-9（:95-99）、角度 14
- `crates/nexus-web-gateway/docs/GATEWAY-FILE-SERVICE-DESIGN-V2.md` §7（A7）、§11 M2
- `crates/nexus-web-gateway/docs/FILE-MODULE-VERIFICATION-2026-10-10.md` §1（通道分发改造）
