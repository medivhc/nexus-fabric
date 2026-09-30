---
id: tcp-egress-review-fixes
date: 2026-09-30
module: nexus-projection
category: implementation-pitfall
task_type: bugfix
---

# TCP Egress Review 修复：F1/W1/W2

第 1 轮独立 Review（CHANGES_REQUESTED）发现的 1 FAIL + 2 WARN 的修复记录。

## F1：stream_id 按 (peer, stream_id) 分发

**问题**：`TcpTerminator` 的 stream_id 是每实例 `AtomicU32` 从 1 自增；
`handle_stream_datagram` 只用 `lookup_id(id).is_some()` 判断 originator。
任一节点同时做 originator 和 egress 时两侧计数器都从 1 开始，确定性碰撞：
A 发给 B relay 的 stream 1 DATA 会被灌入 B 自己向 C 发起的 smoltcp 连接。

**修复**：零线格式改动。
- `TcpTerminator::peer_for(stream_id) -> Option<String>`（TermConn 已存 peer）。
- `TcpEgress::is_originator_frame(id, from_peer)`：`peer_for(id) == Some(from_peer)`。
- relay 表键从 `u32` 改为 `(peer, stream_id)`——同 id 来自不同 originator 也要共存。
- lib.rs 两处分发（downlink + `peer=="self"` loopback）都改用 `is_originator_frame`。

**教训**：E4 曾因此挂掉——根因是 MockTransport 全都叫 `"local"`，
而路由 peer 叫 `"B"`，from_peer 对不上。生产 FabricConn 的 from_peer 是真实
PeerId，会与路由一致；mock 必须保真。给 `MockTransport` 加了 `set_name`
（interior mutability），example 里 `set_name("A")/("B")`。

## W1：fabric→smoltcp 背压静默丢字节

**问题**：`handle_fabric_data` 里 `send_slice` 写不满（16KB 发送缓冲满）时
`break` 丢弃剩余字节；egress 已从真实 TcpStream 消费 → 永久丢失。

**修复**：`TermConn.pending: Vec<u8>` 保留未写入字节；`flush_pending(key)`
在 `handle_fabric_data` 和每次 `poll()` 重试；新增计数
`TcpTermStats.send_buffer_full`。回归测试 64KB→16KB 缓冲验证
delivered == 65536 精确无丢失。

**教训**：写测试时 ACK 必须累计（`ack = srv_seq+1+delivered`），否则 window
耗尽后 drain 停滞，看起来像"不收敛"。

## W2：downlink 线程阻塞 connect/write

**问题**：`TcpRelay::handle_frame` 在 downlink 线程上做阻塞
`connect_timeout(5s)` 和临时切阻塞的 `write_all`——慢速目标卡住全节点
入站处理。

**修复**：
- SYN 只做校验+入队，connect 在一次性 worker 线程跑（`connect_timeout`），
  结果经 mpsc channel 在 `poll()`（已有 10ms 线程）里收割入表。
- connect 在途中的 DATA/FIN 缓存在 `PendingSyn{first_data, fin_pending}`
 （64KB cap，超限 RST）。
- DATA 走非阻塞 `write` 循环；WouldBlock 余量进 `write_pending`
 （256KB cap），在 `poll()` 里刷；真错误才 RST。
- RST 在 connect 在途中到达 → `cancelled` 集，worker 的迟到结果直接丢弃。

**教训**：`TcpStream::write(&[])` 不能做 connect 完成探测（Linux 上
len=0 直接返回 Ok(0)，不等 connect 完成）——不要用空写探测，
用 channel 回传是正道。
