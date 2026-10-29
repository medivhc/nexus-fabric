---
id: udp-proxy-stream-pitfalls
date: 2026-10-29
module: apps/nexusd
category: implementation-pitfall
task_type: feature
---

# UDP 代理流（VLESS / AnyTLS）：「打开」不等于「被接受」，入队不等于转发

## 问题/模式描述

nexusd 经 VLESS / AnyTLS 承载 UDP（PRODUCT §11.18.1），代码评审 r1 找到三处问题：

1. VLESS 的 `open_udp` 只建连并写请求头（不等响应），节点拒绝（UUID 错误 / 不支持 UDP）时
   直接断开。流表把它当成普通的对端关闭：不打 `udp_stream_open_failed`、没有 1 s 重试间隔，
   每个数据报都新开一条 TCP / TLS 连接（实测 500 ms 内 95 条）。
2. 单线程 worker 只在两次 20 ms 读超时之间写；再加上建流后也套用「64 个未写出」的上限，
   健康流上一次 100 个数据报的突发会丢 36 个，上行平均多约 9 ms。
3. dataplane 在 `handle_packet` 返回 true（已入队）时就计 `proxy_forwarded`；入队后因建流
   失败丢弃的数据报同时计入转发与丢弃，违反「只计真实转发」。

## 原因分析

- 协议握手是否完成要看节点的确认（VLESS 响应头、AnyTLS SynAck），而不是本地写成功。
- 「建流队列上限」是为建流期间设计的；建流之后的约束是内存背压，不是数据报个数。
- 同步发送（SOCKS5 / SS）与异步代理流对「转发」的时点不同，一个 bool 表达不了。

## 解决方案

1. `UdpStream::established()`（VLESS = 已读到响应头）；流在确认前结束 → 按建流失败处理
   （`cause=protocol_handshake`、日志、1 s 间隔、计数）。
2. 建流期间 64 个数据报；建流之后改为 1 MiB 未写出字节的背压。worker 有流量时 2 ms 读超时、
   空闲时 20 ms。
3. `UdpForwarder::handle_packet` 返回 `UdpSend { Written, Queued, Dropped }`；只有 `Written`
   当场计转发，代理流的写出经 `ProxyPollResult.udp_forwarded` 在写出后计入。

## 教训/可复用要点

- 「连接已建立」与「对端已接受」分开建模；未被接受就结束的流走失败路径（日志 + 退避），
  否则每个包都会触发一次重连。
- 契约里为某个阶段定的上限，不要顺手套到另一个阶段；另一个阶段需要的是别的约束。
- 计数点放在副作用真正发生的地方；异步路径要把「已发生」回传给计数方。
- （工具链）变异测试恢复文件时要刷新 mtime：用 `shutil.move` / 保留时间戳的方式把备份挪回去，
  文件 mtime 早于变异版本的构建，cargo 判定「已是最新」，二进制里仍是最后一个变异体——本次
  因此在全量测试里看到两个看似与负载有关、实则每次必现的假失败。恢复后 `touch`（或 `os.utime`）再构建。
