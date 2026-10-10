---
id: vsub-p1-001
date: 2026-09-19
module: nexus-connectivity
category: implementation-pattern
task_type: feature
---

# P1 双向包往返实现要点

## 问题：P0 只验证了单向发送，没有验证真正的双向通道

P0 阶段用的 MemoryCarrier 是独立缓冲区，两个节点的 carrier 之间没有真正连接，所以只能验证 A 发送成功（bytes_sent > 0），不能验证 B 真的收到了。

## 解决：用 Arc<Mutex<Vec<u8>>> 共享缓冲区

关键设计：
- A 的 send_buf 和 B 的 recv_buf 是**同一个 Arc<Mutex<Vec<u8>>>**
- B 的 send_buf 和 A 的 recv_buf 是**同一个 Arc<Mutex<Vec<u8>>>**
- 这样 A 调用 send_to() 写入 send_buf，B 调用 receive_into() 就能直接从共享的 recv_buf 读到

```rust
pub fn connected_pair() -> (Self, Self) {
    let a_send = Arc::new(Mutex::new(Vec::new()));
    let b_send = Arc::new(Mutex::new(Vec::new()));

    let a = Self {
        send_buf: a_send.clone(),
        recv_buf: b_send.clone(),  // A 收 = B 发
        ...
    };
    let b = Self {
        send_buf: b_send.clone(),
        recv_buf: a_send.clone(),  // B 收 = A 发
        ...
    };
    (a, b)
}
```

## 验证步骤

1. A 发送包 → A.send_ip_packet() 写入共享缓冲区
2. B 接收包 → B.recv_and_deliver() 从共享缓冲区读取并解封装
3. B 回包 → B.send_ip_packet() 写入另一个共享缓冲区
4. A 接收回包 → A.recv_and_deliver() 读取并解封装
5. 验证双方 bytes_sent 和 bytes_received 都 > 0

## 教训

- **测试替身要"足够真实"**：内存模拟的 VPI/Carrier 不能只是"能跑通"，要能验证真正的数据流方向。
- **共享状态用 Arc 而不是手动复制**：P0 的 connect_to() 是一次性复制，不是实时连接，这种"假连接"会导致测试覆盖不到真正的数据流。
- **Scenario expect 要跟着实现走**：P0 时 bytes_received=0 是对的（没实现接收），P1 实现了双向后就要改成 non_empty。
