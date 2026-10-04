# Windows TUN 详细设计

> 状态：**设计**（2026-10-01）。基于真机验证（tun-rs v2.8 可用，wintun.dll 已存在）。
> 遵循 v9 VirtualPacketInterface 原则 + §13 Composition Root。

## 1. 三种运行模式

| 模式 | 配置 | TUN | 说明 |
|------|------|-----|------|
| 纯代理 | 只有 `proxy.yaml` | 可选 | 对标 Clash，可 TUN 透明或显式 SOCKS |
| 纯组网 | 只有 `network.toml` | 可选 | 对标 EasyTier no-tun，N1 mesh 节点 |
| 统一 | 两个都有 | 必需 | TUN 透明代理 + N1 mesh |

**`tun_enabled` 配置**（`daemon.toml`）：
```toml
[tun]
enabled = true          # false = no-tun 模式
name = "nexus"          # 设备名，避开 "Mihomo"
mtu = 1500
```

- `enabled = false` 时：不建 TUN，N1/proxy 子系统照常跑（显式代理/中继节点）
- 缺 `proxy.yaml` 且缺 `network.toml` 时：daemon 拒绝启动（无意义）

## 2. TUN 为默认路由时的包流

```
TUN (默认路由 0.0.0.0/0)
  ↓ 所有包
[分类器]
  ├─ Mesh (10.200.0.0/24) → smoltcp 终结 TCP → N1 QUIC → 对端
  ├─ Proxy (规则命中) → smoltcp 终结 TCP → Trojan/SS → 代理服务器
  ├─ Direct (bypass) → 写回 TUN → OS 直接发出
  └─ DNS (UDP 53) → UnifiedDns → 写回 TUN
```

**关键**：TUN 做默认路由时，不需要加 mesh 的特定路由（默认路由已覆盖）。

## 3. 防回环排除

代理服务器的 IP **必须**排除，否则 proxy 流量回环进 TUN 死循环：

```
# 伪代码：启动时
for proxy_server in proxy_servers:
    add_route(proxy_server.ip/32, via=physical_gateway, metric=1)
    # metric 比 TUN 的默认路由更优先
```

- Linux：`ip route add <proxy_ip>/32 via <gateway>`
- Windows：`route add <proxy_ip> mask 255.255.255.255 <gateway> metric 1`

## 4. smoltcp 终结（TCP 必需）

**为什么需要**：
- TUN 给的是 IP 包，但代理/mesh 要的是数据流
- 必须在用户态终结 TCP（smoltcp），拿到 stream，再经代理/mesh 发出
- UDP 不用，直接转发 datagram

**数据流**：
```
TUN → IP 包 → smoltcp (TCP 终结) → stream
  ├─ mesh → N1 QUIC stream → 对端 smoltcp → IP 包 → 对端 TUN
  └─ proxy → Trojan/SS 连接 → 代理服务器
```

**Windows 和 Linux 一样**，都是 smoltcp，与平台无关。

## 5. IP 配置

| 平台 | 命令 |
|------|------|
| Linux | `ip addr add 10.200.0.5/24 dev nexus` |
| Windows | `netsh interface ip set address "nexus" static 10.200.0.5 255.255.255.0` |

- IP 从 N1 mesh 网段分配（`network.toml` 配置）
- 纯代理模式时：用 link-local 或任意私有 IP（仅需 TUN 能收包）

## 6. DNS 处理（无需 WFP）

**核心洞察**：所有包都走 TUN，DNS（UDP 53）自动被分类器拦截，无需平台防火墙。

```
TUN → 分类器看到 UDP dport=53 → UnifiedDns 解析 → 响应包写回 TUN
```

- Linux：不需要 iptables
- Windows：不需要 WFP
- 纯 portable 逻辑，写一次全平台通用

## 7. 与 Mihomo 共存

| 项 | 做法 |
|----|------|
| 设备名 | `nexus` vs `Mihomo`，不冲突 |
| 路由 metric | 我们的默认路由 metric 设高（如 100），Mihomo 优先；或反之，按用户选择 |
| 同时运行 | 允许，但用户需明确哪个是主出口（避免双重代理） |

**建议**：测试时先停 Mihomo，验证通过后再测共存。

## 8. 诚实边界

- smoltcp 的 TCP 终结在 Linux 已验证（3b-5），Windows 未验证
- Windows 的 `netsh`/`route add` 需要管理员权限（已确认 xiangcui 是管理员）
- 非管理员用户创建 TUN 未验证
- 双 TUN 同时做默认路由时的行为未测试（建议先停 Mihomo）
