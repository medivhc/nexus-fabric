# Daemon Root 所有权基线清单（#1 运行时所有权归一，AC6）

> 范围：`nexusd` 的 `run_daemon`（`apps/nexusd/src/main.rs:622`）装配的 7 个根。
> 每项均可凭文末 grep 模式复现（S4）。行号以 `github/master@ebdf11d` 为准，
> 以符号为准。

## 1. 七根装配表

| # | 根 | 所有者/位置 | 线程 | 关键资源 |
|---|---|---|---|---|
| ① | Dataplane | `run_daemon`（:752） | `nexusd-dataplane`（:756） | TUN 设备（`TunRsDevice::create`，:323；`tun_enabled()` 为 false 时跳过，no-tun 模式） |
| ② | N1 mesh | `run_daemon`（:731） | —（dial 在 `assembly::assemble_n1` 装配的 `N1MeshBridge` 内部，无独立线程名） | `network.toml` 存在即启用；装配失败 → 降级（只计数不发包），dataplane 照常跑 |
| ③ | NatSwitchRuntime | `run_daemon`（:409 结构定义，:867 启动） | `nexusd-nat-switch`（:485，worker）+ `nat-quality-monitor`（`monitor.rs`:146，200ms 轮询） | 独立 `Driver::new_server("0.0.0.0:0")`（:858）+ `TurnManager` 的 TURN UDP socket（`nat_turn.rs`）+ `StunProber` 的 STUN UDP socket（`UdpStunTransport`）；见诚实声明 A |
| ④ | LocalAPI | `run_daemon`（:778） | `nexusd-localapi`（:780） | `serve_localapi`（:1059）；就绪后 5s 超时即判失败 |
| ⑤ | N2 会话 | `run_daemon`（:118） | `n2-session-sweeper`（:71） | `assembly::assemble_n2_session_manager` + sweeper 线程 |
| ⑥ | 配置 watcher | `run_daemon`（:872） | `nexusd-cfg-watch`（`watcher.rs`:60） | `watcher::spawn`；主线程持有 channel，single-writer |
| ⑦ | Workspace FUSE | `run_daemon`（:807，Linux only） | `WorkspaceManager::start` 内（C1） | `workspace.toml` 存在即挂载；挂载失败 → fail-fast 拒绝启动 |

## 2. 诚实声明

- **A. `NatSwitchRuntime` 的独立 socket 是 D5 接线前的临时状态。**
  `main.rs:858` 的 `Driver::new_server("0.0.0.0:0")` 独立于 N1 mesh 的 fabric
  driver 存在，是因为 `NatSwitching::on_relay_connected` 的生产喂入（D5）
  需要更深的 mesh/fabric 集成（`main.rs:406` 注释）；D5 落地后该独立
  driver 应被收敛，不应视为长期架构。
- **B. `QualityMonitor` 当前空转（零注册路径）。**
  `monitor.rs:153` 的 200ms 轮询线程已启动（`NatSwitching::new` →
  `sw.monitor.start()`，`nat_switch.rs:134`），但因 `on_relay_connected`
  待 D5 喂入，尚无路径注册到 `PathManager`，探针无实际目标。
  这是 D5 前的已知状态，不是 bug。

## 3. 复现用 grep 模式（S4）

```bash
# 线程名
grep -rn '\.name("nexusd-dataplane"\|\.name("n2-session-sweeper"\|\.name("nexusd-localapi"\|\.name("nexusd-nat-switch"\|\.name("nexusd-cfg-watch"\|\.name("nat-quality-monitor"' apps/nexusd/src/main.rs apps/nexusd/src/watcher.rs crates/nexus-nat-quality/src/monitor.rs
# bind 点
grep -rn '"0\.0\.0\.0:0"' apps/nexusd/src/main.rs            # NatSwitchRuntime 独立 driver
grep -rn '"127\.0\.0\.1:0"' apps/nexusd/src/nat_turn.rs crates/nexus-turn/src/client.rs crates/nexus-turn/src/server.rs  # TURN/STUN UDP socket
# TUN 设备创建点
grep -rn 'TunRsDevice::create' apps/nexusd/src/main.rs
# 装配入口
grep -n 'fn run_daemon\|assemble_n1\|assemble_n2_session_manager\|fn serve_localapi\|watcher::spawn' apps/nexusd/src/main.rs
```
