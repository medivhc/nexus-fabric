---
id: proxy-transport-ss-e4-pitfalls
date: 2026-09-30
module: nexus-proxy-transport
category: implementation-pitfall
task_type: feature
---

# ss/trojan E4 的两个坑：握手/数据面成帧混用、server teardown 拖死 join

## 背景

`nexus-proxy-transport` 二期：ss 的握手复用 outbound crate 的 `write_record`/
`read_record`（u32 BE 长度），数据面走共享的 2 字节成帧（T4）。E4 自研 ss
server 终结 AEAD 会话并中继。

## 坑 1：握手帧和数据帧是两种成帧，server 必须同时会说

症状：`SsTransport::connect`（握手）成功，A→B 方向 server 成功
`read_record→open→forward`（日志可见 1228B sealed → 1200B 明文），但
`A QUIC connect: timeout`——B 永远不回包。

根因：中继把 `open` 出来的**裸 QUIC datagram**直接 `write_all` 给了 B，
B 的 `FramedTransport` 把 QUIC 头前 2 字节当长度解析，全是垃圾帧。
握手用 u32 记录帧、数据面用 2 字节帧，server 在两个域用了同一种读法。

修复：S 作为会话终结点，中继时给 S↔B 腿**重新加帧**
（`u16(plain.len()) || plain`）；B→A 方向同理（读 2 字节帧→seal→写
`u16 || sealed`）。教训：**当一条 TCP 连接上叠了两套成帧（握手一套、
数据一套），中继/终结点的每一处读写都要明确自己在说哪一套**；QUIC
connect timeout + 单向通，是"对端在解析垃圾帧长度"的典型症状
（见 `2026-09-30-proxy-transport-atomic-recv` 的症状识别）。

## 坑 2：E4 server 的 relay 线程超时会拖死 server_thread.join()

症状：E4 本来 2s 能跑完，实测 30s+；`handshake_err` 出现几百到几千的
非确定性计数（0/115/961/1022/3848），但 verdict 依然 PASS。

根因链：
- B 关闭后，S 的 t2 退出，但 t1 还 parked 在 `read_sealed` 的 30s 读超时里；
- `server_thread.join()` 等 t1 → 进程 30s 不退出；
- 这 30s 里 A 的 QUIC driver 还活着继续 poll `recv_from`；
- t1 超时退出 → 最后一个 fd 关闭 → FIN 到 A → driver 对 EOF 紧循环空转，
  每个 EOF 都计一次 `handshake_err`（`Ok(0)` 分支）。

修复（E4 harness 层，不碰传输语义）：
1. 任一中继方向结束即 `shutdown(Both)` 整个 session，
   用 `JoinHandle::is_finished()` 轮询 + 50ms sleep 触发 teardown，
   不让线程 parked 在 30s 超时里；
2. A 在 echo 收完、join 完 B 线程后**显式 `drop(conn)` 停 driver**，
   再 `join` server 线程——否则 driver 在 server teardown 的 FIN 到达时
   还在 poll，EOF 空转污染计数器。

规则：**E4 的 server teardown 必须是 prompt 的**；`server_thread.join()`
绝不能依赖 relay 线程的读超时自然退出。以及：`handshake_err` 这类计数器
在 teardown  race 下天然有噪声，scenario 只断言 verdict/roundtrip/
relayed/saw_plaintext，不把 teardown 噪声写进冻结期望。
