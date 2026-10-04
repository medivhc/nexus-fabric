---
id: fabric-active-path-semantics
date: 2026-09-30
module: nexus-fabric
category: implementation-pitfall
task_type: feature
---

# ConnStats.active_path 是本端 local addr，不是远端

## 问题/模式描述

Phase 4a 的 E4 需要验证"对端观测到源端口变化"（QUIC 真实迁移）。
最初在 B 侧轮询 `conn_b.stats().active_path`，期望看到 A 的新源端口，
10 秒超时从未变化，导致 E4 FAIL。

## 原因分析

读 `crates/nexus-fabric/src/driver.rs` 的 `update_stats`：

```rust
st.active_path = Some(*self.shared.local_addr.lock().unwrap());
```

`active_path` 是 endpoint **自己**的 local UDP 地址。B 侧的该值是 B 的
监听地址，A 迁移时永远不会变。A 侧在 `cmd_rebind` 中同步更新为新
socket 地址（`self.shared.local_addr = addr` + `update_stats`），所以
观测点必须在 A 侧。

## 解决方案

E4 改为观测 A 侧：`conn_a.stats().active_path.port()` 在 rebind 前后
变化（A 的新源端口 = 对端看到的 remote 端口变化）。配合"全部字节回
显"（迁移后 B 仍能收包）共同证明真实迁移，非纯逻辑切换。

## 教训/可复用要点

- 不要从字段名猜语义（"active path"听起来像远端路径），读 driver 源码确认。
- E4 的观测面选择必须先验证该面真的会动，否则 E4 FAIL 会误导排查方向。
