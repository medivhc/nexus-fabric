---
id: linux-migration-pitfall-001
date: 2026-09-29
module: apps/nexus, engineering/nexus-harness
category: implementation-pitfall
task_type: bugfix
---

# TCP 流双向复制 EOF 死锁与跨平台 Scenario 门禁判定

## 问题描述

1. **执行挂起（为何这么慢）**：在 Linux 宿主上运行 `nexus-harness verify --full` 时，整个进程挂起在 `product.daemon-real-socks-proxy-flow` 场景超过 1 小时，无任何超时退出。
2. **场景失败（跨平台断言不匹配）**：在 Linux 宿主上执行 `product.secure-store` 与 `platform.windows-system-proxy` 时，由于 Windows 专有 API（DPAPI、WinINET 注册表）无法在 Linux 原生调用，导致场景门禁判为 FAIL。

## 原因分析

1. **半双工 TCP 转发缺少双方 Shutdown**：
   在 `apps/nexus/src/lib.rs:pump_bytes` 中，双向转发采用独立的复制线程。当客户端完成发送触发 EOF 时，之前代码仅退出本地读取循环，未对对端调用 `shutdown(Shutdown::Both)`。同时测试例 `real_socks_proxy_flow.rs` 期望的 HTTP 响应体长度判断存在错误（`response.len() > 200`，而 mock 响应仅 62 字节），导致客户端循环永不退出，主线程 `proxy.join()` 陷入无限等待死锁。
2. **Scenario 调度器缺少宿主平台条件判定**：
   `windows_system_proxy.toml` 与 `virtual_packet_interface.toml` 在 `[given]` 中显式声明了 `platform = "windows"`。但 `nexus-harness/src/scenario.rs` 加载 scenario 时未提取 `given.platform`，在非 Windows（Linux）环境下盲目调用包含 Win32 专有特性的命令，导致预期断言失败。

## 解决方案

1. **双向显式 Shutdown**：
   在 `pump_bytes` 发生任何 EOF 或错误退出时，显式调用 `dst.shutdown(Shutdown::Both)` 与 `src.shutdown(Shutdown::Both)`，确保单向断开能立即唤醒并终止反向等待线程。
2. **解析校验逻辑健全化**：
   修复 `real_socks_proxy_flow.rs` 响应体截断判定，在接收到完整 HTTP 200 响应后立即退出循环并显式主动关闭客户端套接字。
3. **平台条件化 Scenario 调度**：
   在 `nexus-harness/src/scenario.rs` 中解析 `given.platform`；若场景指定的平台与当前执行宿主系统（Windows / Linux / macOS）不符，记录为 `UNKNOWN (platform contract: <required> required, host is <current>)` 而非判定为 `FAIL`，使非宿主专属的平台场景不会阻断核心产品场景门禁。

## 教训与可复用要点

- **异步 / 线程 TCP 转发纪律**：任何流式中继协议在感知到一方 EOF 时，必须严格执行双向连接的终止通告（`Shutdown::Both`），杜绝半关闭悬挂。
- **跨平台契约严格区分平台专有与可移植**：测试场景必须在 `[given]` 明确环境约束；Harness 必须尊重平台前置条件，避免在不同 OS 迁移时发生误报。
