---
id: virtual-subnet-static-routing
date: 2026-09-20
module: nexus-connectivity
category: implementation-pattern
task_type: feature
---

# VirtualSubnet 静态路由与三节点转发（P1 §12.5）

## 问题/模式描述

VirtualSubnetTunnel 原本只支持点对点直连：`send_ip_packet(dst)` 直接查 peers 表。
要支持三节点 A—B—C（A 与 C 不直连，B 转发），需要静态路由表 + 中间节点转发逻辑。

## 原因分析

P0 点对点模型假设每个 peer 都有直连 locator。网状拓扑下，源节点不知道远端节点的
物理 locator，必须配置 next_hop。

## 解决方案

1. `routes: HashMap<dst_virtual_ip, next_hop_virtual_ip>` 静态路由表
2. `send_ip_packet`：dst 是直连 peer → 直发；否则查 routes → next_hop → 发给 next_hop
3. `recv_and_deliver`：dst == 自己 → 写 VPI；dst != 自己 → 先查直连 peer（中间节点本身就是最终目的的邻居），再查 routes → 转发原帧
4. `MeshCarrier`：多对端 carrier 测试替身（`MemoryCarrier` 只支持点对点）

## 教训/可复用要点

- **转发时帧头不改**：隧道帧的 src/dst 始终是原始虚拟 IP，中间节点只改物理下一跳
  （对应 IP 路由器的"改二层不改三层"）。
- **直连优先于路由表**：中间节点 B 收到 dst=C 的帧时，C 是 B 的直连 peer，不需要
  查 routes 表——先查 peers 再查 routes，避免 routes 配置冗余。
- **harness scenario JSON 嵌套**：expect 的 `field = "node_a.bytes_sent_to_b"` 是
  嵌套路径查找，extra 里必须把字段放到 `node_a` 的 JSON 对象里，不能作为顶层 key
  `"node_a.bytes_sent_to_b"`（否则报 `<missing>`）。
- **MeshCarrier vs MemoryCarrier**：三节点 E4 需要多对端 carrier（B 的 send_buf 同时
  发给 A 和 C），`MemoryCarrier::connected_pair()` 不够用。新增 `MeshCarrier` 按
  `peer_locator` 路由到不同对端的 recv_buf，不要硬改 MemoryCarrier 破坏现有测试。
