# Nexus Daemon 架构设计

> 状态：**已实现**（2026-10-01，master `6ea9559`）
> 任务类型：feature（用户愿景）
> 基线：v9 统一系统设计规范（技术基线）+ 白皮书 v1.0（产品基线）

---

## 1. 架构总览

```
┌─────────────────────────────────────────────────────────────┐
│  nexusd <config-folder>          # 唯一 daemon 入口         │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  ConfigDir 加载 → 子系统装配 → LocalAPI → Watcher     │  │
│  │  （2s 轮询热加载）                                    │  │
│  └──────────────────────────────────────────────────────┘  │
│                          ▲                                 │
│                          │ 配置文件夹（真相来源）            │
│  ┌──────────┴──────────┐ ┌┴──────────────┐ ┌─────────────┐ │
│  │ daemon.toml         │ │ network.toml  │ │ proxy.yaml  │ │
│  │ (LocalAPI 地址)     │ │ (N1 mesh)     │ │ (Clash 风格)│ │
│  └─────────────────────┘ └───────────────┘ └─────────────┘ │
│  ┌─────────────┐                                            │
│  │ dns.toml    │                                            │
│  │ (DNS 规则)  │                                            │
│  └─────────────┘                                            │
└─────────────────────────────────────────────────────────────┘
                          ▲
                          │ nexus（瘦客户端）
                          │
    ┌─────────────────────┼─────────────────────┐
    │ nexus config get/set/list --dir <dir>     │  改配置（写文件）
    │ nexus status                              │  查状态（LocalAPI）
    │ nexus proxy ...                           │  客户端命令
    └───────────────────────────────────────────┘
```

**核心原则**（用户愿景，2026-10-01）：

> `nexusd` 启动，参数只有一个：配置文件夹。然后所有的命令通过 `nexus`，
> 配置是热生效的。`nexus` 只负责改配置、看状态。

- **单一真相来源**：配置文件夹是所有持久化状态的唯一来源。
- **职责分离**：`nexusd` 是数据面（常驻 daemon）；`nexus` 是控制面（瘦客户端）。
- **热生效**：配置变更 2 秒内生效，无需重启 daemon（部分变更除外，见 §3）。

---

## 2. 配置文件夹结构

路径：任意目录，如 `/etc/nexus/`。

| 文件 | 格式 | 子系统 | 缺失时行为 |
|------|------|--------|-----------|
| `daemon.toml` | TOML | daemon 自身 | 使用默认值（LocalAPI `127.0.0.1:18080`） |
| `network.toml` | TOML | N1 mesh 网络 | 不启用 mesh |
| `proxy.yaml` | YAML | Clash 风格代理 | 不启用 proxy（沿用现有 YAML 格式，免迁移） |
| `dns.toml` | TOML | DNS | 不启用自定义 DNS |

**优雅降级**：任一文件缺失 = 对应子系统不启用，daemon 正常启动其他子系统。

**三个 "proxy" 的语义区分**（#1 命名澄清；键名不动，与 `config.rs` 模块文档同步）：

| 配置项 | 语义 | 管辖 |
|--------|------|------|
| `daemon.toml [network.proxy]` | **N1 建连经代理** | dial 时的代理 tier（#3 fabric-over-proxy） |
| `proxy.yaml` | **TUN 出站经代理** | 互联网出口策略（Clash 风格） |
| `daemon.toml [network.turn]` | **TURN+STUN** | NAT switching（与代理无关） |

注：`nexus proxy` CLI 子命令（§4.3）是第三个含义的 "proxy"——本轮仅记录，不处理。

### 2.1 `daemon.toml`（可选）

```toml
# LocalAPI 监听地址（nexus status 等命令连接用）
localapi_addr = "127.0.0.1:18080"
```

全部字段可选，有默认值。

---

## 3. 热加载分级

Watcher 每 2 秒轮询（标准库实现，零新依赖；沙盒无网络时 `notify` crate 不可用）。

检测到文件变更 → 重载 → 校验 → 分类 → 应用/拒绝。

| 变更类型 | 行为 | 说明 |
|----------|------|------|
| `proxy.yaml` / `dns.toml` 内容变更 | **热生效** | 规则、记录类纯数据，直接应用 |
| `network.toml` 内容变更 | **热生效** | peer 列表等；端口类变更由 N1 侧自行决定 |
| `daemon.toml` 的 `localapi_addr` 变更 | **需重启** | 记 warning，提示重启 daemon，不自动重启 |
| 任一文件新增/删除 | **需重启** | 子系统启停需重新装配，记 warning |
| 任一文件校验失败 | **拒绝** | 沿用旧配置，记 error 日志，**进程不 crash** |

**校验失败处理**（关键）：
- 新配置解析/校验失败 → 拒绝应用
- 保留旧配置继续运行
- 记 `ERROR` 日志（含文件名和错误原因）
- 进程不退出、不 crash
- 更新 watcher 基准，避免重复刷屏

**原子写入**：`nexus config set` 使用临时文件 + `rename`，避免 watcher 读到半截文件。

---

## 4. 瘦客户端命令

### 4.1 `nexus config`（配置文件管理）

本地文件操作，不经过 daemon；daemon 侧通过 watcher 热加载。

```bash
# 查看配置文件内容（stdout）
nexus config get --dir /etc/nexus/ proxy.yaml

# 从 stdin 写入配置文件（原子写入）
cat new-proxy.yaml | nexus config set --dir /etc/nexus/ proxy.yaml

# 列出已知配置文件及存在性
nexus config list --dir /etc/nexus/
```

已知文件名：`daemon.toml` / `network.toml` / `proxy.yaml` / `dns.toml`。

### 4.2 `nexus status`（状态查询）

经 LocalAPI（HTTP）查询 daemon 快照。

```bash
nexus status
nexus status --json
```

### 4.3 `nexus proxy`（代理客户端命令）

从 `nexusd` 迁移而来（CLI 统一，2026-10-01）：

```bash
nexus proxy --help                    # 用法（修复了原 nexusd proxy --help hang 的 bug）
nexus proxy [--addr <ip:port>]        # one-shot SOCKS5 测试
nexus proxy run|host|relay ...        # 数据面组合根
```

**语义**：`nexus proxy` 保持 one-shot，不做 daemon 化。如需长期运行，使用 `nexusd <config-folder>`。

### 4.4 其他

- `nexus system-proxy`：系统代理控制（进程内 SDK）
- `nexus autostart`：开机自启（进程内 SDK）
- `nexus network up/status`：N1 装配（进程内，M6）

---

## 5. Daemon 启动流程

```
1. nexusd /etc/nexus/
   ↓
2. ConfigDir::new() 校验路径存在且为目录
   ↓
3. config::load() 加载四文件（校验失败 → JSON FAIL 退出）
   ↓
4. log_enabled_subsystems() 报告启用的子系统
   ↓
5. LocalAPI 后台线程启动（daemon.toml 的 localapi_addr）
   ↓
6. watcher::spawn() 启动配置监听线程
   ↓
7. 主事件循环：
   - 接收 ReloadEvent::Applied → 日志 "config hot-reloaded: [...]"
   - 接收 ReloadEvent::NeedsRestart → warning 日志
   - 接收 ReloadEvent::Rejected → error 日志，沿用旧配置
   ↓
8. 输出 {"verdict":"READY",...}，进入常驻
```

**退出码**：
- `0`：正常（READY 后常驻，Ctrl-C 退出）
- `1`：配置加载失败（JSON FAIL 输出）
- `2`：用法错误

---

## 6. 设计决策记录

### 6.1 为什么用配置文件夹 + 热加载，而不是 Tailscale 模式？

| 维度 | Tailscale（`tailscale up --flag`） | 本设计（config folder + 热加载） |
|------|-----------------------------------|----------------------------------|
| 配置存储 | daemon 内部状态，用户不直接碰 | 配置文件夹（文件），用户可直接编辑 |
| 配置变更 | 重跑 `tailscale up` / `tailscale set` | 改文件，2 秒内热生效 |
| 适用场景 | 配置项少（authkey、hostname 等） | 配置复杂（Clash 规则集、代理组、DNS） |
| 可脚本化 | CLI flag | 文件（可版本控制、模板生成） |

**选择理由**：Nexus 融合 Clash，Clash 用户习惯直接改 YAML；代理规则集、DNS 规则等复杂配置用文件比 CLI flag 好维护。

### 6.2 为什么用轮询而不是 inotify？

- 沙盒无网络，无法下载 `notify` crate。
- 2 秒延迟对配置热加载可接受。
- 零新依赖，符合 AGENTS.md §18 依赖最小化原则。
- 后续可替换为 `notify`（接口已隔离在 `watcher.rs`）。

### 6.3 为什么保留 `nexusd serve`？

历史兼容：`serve` 是旧的 LocalAPI 入口。保留作内部实现，用户入口为 `<config-folder>`。未来可移除。

---

## 7. 诚实边界

- **当前实现**：daemon 负责配置加载/校验/热加载 + LocalAPI。各子系统（mesh/proxy/dns）的实际长驻运行时装配为后续工作；当前 `status` 如实报告"已配置/未配置"，不虚构"运行中"。
- **`nexus status` 的 LocalAPI 端到端**：daemon 侧线程已启动，但 `nexus` 客户端的 status 命令走旧 ControlCommand 路径，需后续对齐（2026-10-01 已知）。
- **热加载的 N1 侧**：`network.toml` 变更时，端口类变更由 N1 侧自行决定是否需重启；当前仅保证 peer 列表类纯数据热生效。

---

## 8. 相关代码

| 模块 | 路径 | 职责 |
|------|------|------|
| daemon 入口 | `apps/nexusd/src/main.rs` | CLI 解析、装配、事件循环 |
| 配置管理 | `apps/nexusd/src/config.rs` | ConfigDir、LoadedConfig、校验、分级 |
| 热加载 | `apps/nexusd/src/watcher.rs` | 2s 轮询、ReloadEvent、mpsc 通信 |
| 瘦客户端 | `apps/nexus/src/main.rs` (`run_config`) | config get/set/list |

**并发模型**（AGENTS.md §13）：watcher 线程由 daemon 主线程拥有；通过 `mpsc::Sender<ReloadEvent>` 向主线程报告，不直接改共享状态；主线程是唯一的配置应用者（single writer）。

---

## 10. DNS 统一设计

> 状态：**设计**（2026-10-01，用户要求统一）。未实现。

### 10.1 问题

三套 DNS 各管各的：
- **Clash DNS**：fake-ip 模式、劫持 53 端口、按规则分流上游
- **Mesh**：peer 主机名、mesh 域名需要解析到虚拟网 IP
- **系统 DNS**：被 TUN 劫持后，查询不知道给谁

### 10.2 统一架构

`nexusd` 只起**一个** DNS 服务器（`0.0.0.0:53`），TUN 的 `dns-hijack` 把所有 53 端口流量导入：

```
应用 DNS 查询
    ↓ (TUN dns-hijack: any:53)
nexusd DNS (0.0.0.0:53)
    ↓ 查询分类器
    ├── mesh 域名 → Mesh 解析器 → 真实 mesh IP
    │   (如 *.mesh、peer 主机名 → 10.144.144.x)
    │
    ├── 命中代理规则 → Fake-IP 池 → 返回 fake-ip
    │   (198.18.0.0/15，Clash 兼容范围)
    │   后续到 fake-ip 的 TCP/UDP 被 TUN 捕获 → 走 proxy 规则引擎
    │
    └── 直连/bypass → 上游 DNS（系统配置或 dns.toml 指定）
```

### 10.3 关键设计点

| 项目 | 设计 |
|------|------|
| Fake-IP 池 | `198.18.0.0/15`（RFC 2544 benchmarking，与 Clash 兼容） |
| Mesh 域名后缀 | `.mesh`（如 `xc-pc-linux.mesh` → `10.x.x.x`）；可配置 |
| 查询分类顺序 | mesh 域名 > 代理规则（fake-ip）> 直连上游 |
| 缓存 | 按查询类型分别缓存；fake-ip 映射表常驻内存（随 daemon 生命周期） |
| `dns.toml` | 上游 DNS、fake-ip 开关、mesh 后缀、自定义 hosts |

### 10.4 与 TUN 的配合

- TUN 的 `dns-hijack: any:53` 确保所有 DNS 查询进入我们的服务器，不泄露
- Fake-IP 返回后，应用发起的 TCP 连接目标是 fake-ip，被 TUN 捕获
- TUN 的包分类器识别 fake-ip → 送入 proxy 规则引擎（见 §6）
- Mesh 域名返回真实 IP，TUN 分类器识别 mesh 网段 → 送入 N1

---

## 11. 用户态 QoS 设计（CAKE-like）

> 状态：**设计**（2026-10-01，用户想法）。未实现。
> 目标：在用户态实现类似 Linux CAKE qdisc 的公平队列 + 流量整形。

### 11.1 为什么用户态

- **跨平台**：Windows/macOS 没有 CAKE；用户态一套代码全平台跑
- **与分类器集成**：QoS 决策需要应用层信息（proxy 规则、mesh 优先级），内核 qdisc 拿不到
- **可观测**：每流统计天然可导出给 `nexus status`

### 11.2 在数据面的位置

```
TUN 捕获
    ↓
[包分类器] (§6: mesh / proxy / bypass)
    ↓
[QoS 层：本节] ← 按 egress 分实例
    ├── mesh egress 实例（整形 mesh 上行）
    └── proxy egress 实例（整形代理上行）
    ↓
转发（N1 / proxy 规则引擎）
```

每个 egress 一个独立实例，避免 mesh 和 proxy 互相抢带宽。

### 11.3 核心组件

#### 流识别
- **5 元组** → flow ID：`hash(src_ip, dst_ip, src_port, dst_port, proto)`
- 流表：`HashMap<FlowId, FlowState>`（分片锁或 lock-free，防热点）
- 流超时：60s 无包则回收（避免内存泄漏）

#### 优先级分级（类 CAKE diffserv）
| 优先级 | DSCP 对标 | 典型流量 | 识别方式 |
|--------|-----------|----------|----------|
| 高 | CS6/EF | SSH、DNS、ICMP、游戏 | 端口/协议规则，可配置 |
| 中 | 默认 | 网页、API | 默认 |
| 低 | CS1 | 下载、备份 | 端口/规则，可配置 |

#### 公平队列（DRR，Deficit Round Robin）
- 每个流一个队列 + `deficit` 计数器
- 调度轮询：`deficit += quantum`；包大小 ≤ deficit 则发送，`deficit -= 包大小`
- `quantum` 默认 1514（以太网 MTU），可配置
- 保证：大象流不饿死老鼠流（CAKE 的核心公平性）

#### 整形（Token Bucket）
- 每个优先级一个 token bucket，或全局一个
- 速率可配置（如 `upload_mbps: 100`）
- 高精度定时器：Linux `timerfd` / Windows `CreateTimerQueueTimer`，精度目标 <1ms

### 11.4 用户态挑战与对策

| 挑战 | 对策 |
|------|------|
| 定时器精度 | 平台相关高精度定时器；整形允许 ±1ms 抖动 |
| per-packet 开销 | 流表分片；热路径避免分配；batch dequeue |
| CPU 占用 | 空闲时 park 线程；backpressure 传导（队列满则 drop，TCP 自适应） |
| 与 async 集成 | QoS 层跑独立线程（OS thread），与 tokio 运行时通过 channel 通信，避免阻塞 |

### 11.5 配置（`daemon.toml` 扩展）

```toml
[qos]
enable = true
# 上行整形（Mbps，0 = 不限速）
mesh_upload_mbps = 100
proxy_upload_mbps = 200
# DRR quantum（字节）
quantum = 1514
# 高优先级端口（逗号分隔）
high_priority_ports = "22,53,3389"
```

### 11.6 诚实边界

- 本设计未实现、无测试、无性能数据
- 用户态 QoS 的 CPU 开销 vs 内核 qdisc 尚未量化
- Windows 高精度定时器行为需实测

---

## 12. Network Boost 与高级选项

> 状态：**设计**（2026-10-01）。竞速/预测代码已存在（`crates/nexus-path/`，已合入 master）；
> boost 开关集成、多路径调度器为新设计，未实现。

### 12.1 设计原则

**Boost 开关 v1** 只放开销小、普遍受益的：
- **预测（EWMA）**：持续跟踪路径质量，劣化时主动切换
- **竞速**：建连时并行拨号选最快，降低首包延迟
- **激进切路**：boost 模式下更低的 hysteresis 门限

**独立高级选项**（不进 boost 开关）：
- **QoS**（§11）：只有链路拥塞时有用，空闲时是纯开销
- **多路径**（§12.4）：复杂度最高，瓶颈在代理服务器端时无效

> 原因：用户开了 boost 没感觉会觉得是假的。QoS/多路径效果看场景，单独开关更诚实。

### 12.2 现有能力（已合入 master）

| 模块 | 文件 | 能力 |
|------|------|------|
| 竞速 | `crates/nexus-path/src/race.rs` | staggered racing，`race_connect`，budget + 协作取消 |
| 质量预测 | `crates/nexus-path/src/ewma.rs` | per-path EWMA，20% 相对 hysteresis + 3s 保持 |
| 路径回退 | `crates/nexus-path/src/fallback.rs` | Direct → Proxy → Turn，`FallbackChain` |

### 12.3 Boost 开关配置

```toml
# network.toml
[boost]
enabled = true
# 激进切路：boost 模式下的 hysteresis（默认 20% → 10%）
hysteresis_pct = 0.10
# 保持时间（默认 3s → 1s）
switch_hold_ms = 1000
# 建连时是否竞速
race_on_connect = true
```

### 12.4 在统一数据面中的位置

```
                    ┌─ 竞速/预测（建连时，control plane）─┐
                    │  race_connect 选最优路径             │
                    │  EWMA 跟踪路径质量                   │
                    └──────────────────┬──────────────────┘
                                       ↓ 建连完成
TUN 捕获 → [包分类器] → [QoS: DRR+整形] → [路径调度器] → 转发
              §6       §11（独立开关）    §12.6（独立开关）
                                       ↓
                              N1 / Proxy egress
```

**分工**：
- **竞速/预测**（boost）：连接建立时选路。`race_connect` 并发拨多条路径，EWMA 持续打分。
- **QoS**（§11，独立开关）：连接建立后，包调度时做流间公平。
- **路径调度器**（多路径，独立开关）：在 QoS 之下，按包或按流选择 egress 路径。

### 12.5 EWMA 驱动统一分类器

EWMA 的 per-path 分数可输入包分类器（§6），实现动态调整：

```
分类器决策（伪代码）：
  if dst in mesh_subnet:
      path = ewma_best(mesh_paths)      # 选 EWMA 最优的 mesh 路径
      if path.score < threshold:
          log::warn!("mesh 路径质量劣化，考虑 proxy")
          # 可选：按规则溢出到 proxy
      forward(mesh, path)
  else if proxy_rule.match(dst):
      forward(proxy)
  else:
      forward(bypass)
```

- hysteresis（boost 模式 10% + 1s）防止路径乒乓
- 分类器只读 EWMA 分数，不修改（single writer 仍在 `nexus-path`）

### 12.6 多路径扩展设计（独立高级选项）

**目标**：单流可同时用多条路径（如 mesh 直连 + proxy 并发），提升吞吐/可靠性。

**架构**：在 QoS 层之下加路径调度器，每个 egress 独立 QoS 实例：

```
                    ┌─ QoS 实例 A (mesh直连) ─┐
[QoS: DRR] → [路径调度器]─┼─ QoS 实例 B (proxy) ──┤→ 转发
                    └─ QoS 实例 C (TURN) ───┘
```

**调度策略**（可配置）：
| 策略 | 描述 | 适用 |
|------|------|------|
| `single` | 只用最优路径（默认，当前行为） | 低延迟优先 |
| `per-flow` | 按流哈希固定路径（流内有序） | 通用 |
| `per-packet` | 按包轮询/加权（需接收端重排） | 吞吐优先，需对端支持 |

**接收端重排**（per-packet 模式）：
- 包头加 sequence number（复用 QUIC 的包号机制，避免新协议）
- 接收端按序重组，乱序包缓冲（上限可配置，防内存爆炸）

**配置**（`network.toml`）：
```toml
[multipath]
# 调度策略：single | per-flow | per-packet
strategy = "single"
# per-packet 模式的重排缓冲上限（包数）
reorder_buffer = 64
```

### 12.7 诚实边界

- 竞速/预测代码已实现并合入，但**尚未与统一 daemon 的分类器集成**（§12.5 为设计）
- 多路径调度器未实现；per-packet 模式的接收端重排未设计细节
- EWMA 参数（20%/3s）来自路径层场景，mesh 场景下的最优值需实测
- boost 的激进参数（10%/1s）为初值，需真机调优

---

## 13. Composition Root 详细设计

> 状态：**设计**（2026-10-01）。遵循 v9 §4-5 的 Composition Root 原则，
> 补全 v9 未规定的具体行为：生命周期、线程模型、失败降级、配置校验。

### 13.1 v9 约束（已满足，无需重设计）

| v9 要求 | 现状 |
|---------|------|
| Root = `nexusd`，组装 domain runtimes + ingress + platform | ✅ `apps/nexusd` 是组装点 |
| `nexus-network` 不依赖 `nexus-ingress` | ✅ 无此依赖边 |
| Portable Core 不直调 OS API，trait 注入 | ✅ 平台能力经 trait |
| Deletion Test | ✅ 新抽象均通过 |

### 13.2 子系统清单与所有权

```
nexusd (Composition Root)
├── ConfigLoader（配置目录 → LoadedConfig）
├── Dataplane（TUN + 分类器 + DNS + QoS）
│   └── 持有：TunDevice, PacketClassifier, UnifiedDns, CakeScheduler
├── N1MeshBridge（N1 会话 + 路由）
│   └── 持有：N1SessionManager（独立线程）
├── ProxyEngine（代理出站）
└── LocalAPI（状态查询）
```

**所有权规则**：
- Root 拥有所有子系统；子系统之间不直接持有对方
- Dataplane 经 `N1Sender` trait 用 N1（依赖反转，不拥有）
- N1 的 session 线程由 `N1MeshBridge` 拥有，Root 只发 shutdown 信号

### 13.3 启动顺序

```
1. 加载配置（ConfigLoader）
   ↓ 失败 → 退出（exit 1，打日志）
2. 校验配置（见 §13.6）
   ↓ 失败 → 退出（exit 1）
3. 创建 TUN
   ↓ 失败 → 退出（TUN 是数据面根基，无降级）
4. 创建 Dataplane（分类器/DNS/QoS）
5. 创建 N1MeshBridge（如果 network.toml 有 N1 配置）
   ↓ 失败 → 降级：dataplane 照常跑，Mesh 包计数丢弃（mesh_dropped_no_n1）
6. 创建 ProxyEngine（如果 proxy.yaml 存在）
   ↓ 失败 → 降级：Proxy 包计数丢弃
7. 启动 LocalAPI
8. 进入主循环（信号处理 + 热加载轮询）
```

**原则**：TUN 失败是致命的（无 TUN 无数据面）；N1/Proxy 失败是可降级的（对应分类计数，不影响其他路径）。

### 13.4 关闭顺序（反向）

```
1. 收到 SIGTERM/SIGINT
2. 停 LocalAPI（不再接受新查询）
3. 停 Dataplane（不再从 TUN 读包）
   - 等待 in-flight 包处理完（最多 1s，超时强制停）
4. 发 shutdown 给 N1MeshBridge
   - 等待 session 线程退出（最多 5s）
5. 发 shutdown 给 ProxyEngine
6. 关闭 TUN
7. 退出（exit 0）
```

**原则**：反向关闭；每个子系统有超时，超时后强制继续（不无限等）。

### 13.5 线程模型

| 线程 | 职责 | 关闭方式 |
|------|------|----------|
| main | 信号 + 热加载轮询 + 协调关闭 | 自然退出 |
| dataplane | TUN 读包 → 分类 → QoS → 转发 | `shutdown()` + join（1s 超时） |
| n1-session | N1 peer 连接、QUIC 收发 | `shutdown()` + join（5s 超时） |
| n1-downlink | N1 收包 → 写回 TUN（后置） | 同上 |
| localapi | HTTP 状态查询 | 先停（无 join 需求） |

**规则**：
- 跨线程只经 `Arc<Mutex<>>` 共享状态（stats）或 channel 发包
- 不允许 dataplane 线程直接调用 N1 的阻塞 API（经 `N1Sender` trait，内部非阻塞）

### 13.6 配置校验

**启动时校验**（失败则退出）：
- mesh CIDR 必须合法；与 bypass CIDR 重叠 → **警告**（不退出，mesh 优先）
- `daemon.toml [qos]` 的 quantum 范围 [64, 65536]，非法 → 退出
- `dns.toml` 缺失 → 用默认（不退出）；格式错误 → 退出

**热加载时**（`nexus config set`）：
| 配置项 | 变更行为 |
|--------|----------|
| mesh CIDR | `NeedsRestart`（正在飞的包路由会乱） |
| bypass 规则 | 热生效（`Applied`） |
| DNS 上游 | 热生效（新查询用新的） |
| QoS 速率 | 热生效 |
| Boost 开关 | 热生效 |

### 13.7 诚实边界

- N1 下行线程（`inject_from_n1` 的生产者）尚未实现
- `network.toml` → `N1SessionManager` 的完整装配未做（`set_n1_sender` 接口已留）
- 关闭超时的具体值（1s/5s）为初值，需实测调优

---

## 14. 验证状态

- **单测**：`cargo test -p nexusd` 10/10 通过（含热加载 Applied/Rejected/NeedsRestart 三路径）
- **功能验证**（2026-10-01）：启动、改文件热加载、坏 YAML 拒绝且进程存活、`nexus config` 三命令，全部通过
- **静态检查**：`cargo fmt --check` 通过；`cargo clippy -D warnings` 通过
- **Candidate Completion**：yes
- **Final PASS**：需 Harness `verify --fast` / `verify --full` 判定（未执行）
