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

## 9. 验证状态

- **单测**：`cargo test -p nexusd` 10/10 通过（含热加载 Applied/Rejected/NeedsRestart 三路径）
- **功能验证**（2026-10-01）：启动、改文件热加载、坏 YAML 拒绝且进程存活、`nexus config` 三命令，全部通过
- **静态检查**：`cargo fmt --check` 通过；`cargo clippy -D warnings` 通过
- **Candidate Completion**：yes
- **Final PASS**：需 Harness `verify --fast` / `verify --full` 判定（未执行）
