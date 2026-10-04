# 2026-09-30: TCP 成帧 transport 的 `recv_from` 必须是原子的

## 背景
`nexus-proxy-transport` 的 `ProxyTransport` 把 QUIC datagram 用 2 字节长度前缀成帧跑在 TCP 上（X1）。
E4（QUIC over SOCKS5 proxy）在握手阶段卡住，日志显示 `recv_from` 读到垃圾帧长度
（`49664`/`50688`/`51712` 等随机值）。

## 根因
不是代理损坏数据，也不是帧逻辑错误——最小复现（纯成帧无 QUIC）一次通过。

真正原因是 **`read_exact` 与 driver 短超时的交互**：
- fabric driver 的事件循环用 `set_read_timeout`（可低至 1ms）循环调用 `recv_from`，
  超时就 `break` 继续 pump。
- 我的 `recv_from` 用 `read_exact(2字节头)` + `read_exact(payload)`。
  当超时发生在"头已读、payload 未到"的窗口，`read_exact` 返回 `TimedOut`，
  但 **2 字节头已经被消费**。下一次 `recv_from` 把 payload 字节当成帧头解析，
  流永久失步，后续全是垃圾长度。

## 修复
`ProxyTransport` 加内部 `read_buf: Vec<u8>`：
- `recv_from` 先从 `read_buf` 尝试解析完整帧；不够就从 socket 读一块 append 进去再试。
- socket 读超时/出错时直接返回错误，**`read_buf` 原样不动**，下次调用从帧边界恢复。
- `FrameOverflow`（caller buffer 装不下）时也要先 drain 掉该帧再报错，否则同样失步。

## 症状识别
- 帧长度是随机大数（如 `0xC200`=49664），且第一个垃圾字节恰好是上一包 QUIC payload
  的首字节（如 `0xC6`/`0xCA`，QUIC long header）→ 高度怀疑是"头被消费、payload 被当成头"。
- 最小化隔离（去掉 QUIC，只测成帧+中继）能快速区分是帧逻辑 bug 还是 I/O 语义 bug。

## 规则
**任何在流式传输（TCP）上做 datagram 成帧的 `recv_from`，面对带超时的调用者时，
必须是原子的：要么返回完整 datagram，要么返回超时且不消费任何字节。**
`read_exact` 直接怼 socket 在超时场景下是错的。
