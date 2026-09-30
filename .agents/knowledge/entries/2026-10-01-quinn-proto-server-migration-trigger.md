---
id: quinn-proto-server-migration-trigger
date: 2026-10-01
module: nexus-fabric
category: implementation-pitfall
task_type: bugfix
---

# quinn-proto 服务端被动迁移的触发条件与 N1 E4 排障

## 问题/模式描述

N1 E4（`product.n1-connectivity-roam`）中，B（fabric Client）切换 underlay IP 并 rebind 后，
A（fabric Server）收到了 B 从新地址发来的包，但始终不触发 QUIC 被动迁移，导致 A→B 数据面 stall，
E4 在 `BYE from B` 超时失败。

4a E4（`product.fabric-conn-roam`，loopback 端口迁移）工作正常。

## 原因分析

1. **quinn-proto 0.11 的服务端迁移触发点**在 `connection/mod.rs::on_packet_authenticated`：
   ```rust
   if remote != self.path.remote
       && !is_probing_packet
       && number == self.spaces[SpaceId::Data].rx_packet
   ```
   另有一处前置丢弃在 `handle_event`：
   ```rust
   if remote != self.path.remote && !self.side.remote_may_migrate() {
       trace!("discarding packet from unrecognized peer {}", remote);
       return;
   }
   ```
   `remote_may_migrate()` 对 Server 取 `server_config.migration`（默认 true），Client 恒 false。

2. **诊断确认**：A 的 UDP socket 确实收到了 B 新地址（10.200.0.3:new_port）的包，
   但 A 的 quinn-proto 从未执行 `migrate()`（在 vendor 代码中加 eprintln 无输出）。
   包在 endpoint→connection 路径上被静默丢弃，具体丢弃点未定位（疑似 CID 路由或包号校验）。

3. **F-EDGE-1 的教训**：`cmd_rebind` 原实现因未先关闭旧 socket（无 SO_REUSEADDR），
   `bind(orig)` 恒 EADDRINUSE，端口保留分支是死代码，Client 恒落到 `0.0.0.0:0`。
   修复时若简单改为“先关旧 socket 再 bind(orig)”，IP 未变场景下 rebind 成 no-op
   （同地址重绑），对端永不迁移——4a E4 回归。正确做法：Client 直接 `0.0.0.0:0`
   保证地址变化；Server 才保留原地址。

4. **F-EDGE-2 的教训**：`local_address_changed()` 只影响本端路径状态，
   不能帮助对端迁移；旧代码刻意不调用（debug_assert 风险），不应无条件加回。

## 解决方案

- Client rebind：先关闭旧 socket，再 `bind(0.0.0.0:0)`，保证新地址不同。
- Server rebind：先关闭旧 socket，再 `bind(orig)`，保留 well-known 端口；失败则报错。
- 移除无条件的 `local_address_changed()` 调用。
- N1 E4 的迁移 stall 仍未解决（BLOCKED），需进一步定位 quinn-proto 内部丢弃点。

## 教训/可复用要点

- rebind 的“保留端口”优化必须保证新地址与旧地址不同，否则迁移无从触发。
- 调试 QUIC 迁移时，直接在 vendor 代码加 eprintln 比外层推测高效。
- cargo 在 path 依赖 mtime 未更新时可能跳过重建，`touch` 源码强制刷新。
- 共享 target 目录（`/work/nexus-dev/target`）多 worktree 共用时，注意二进制新鲜度。
