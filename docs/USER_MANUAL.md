# Nexus 用户手册

> 版本：基于 master `67a75ff`（2026-10-04 按代码实际实现对齐更新）
> 本次更新性质：**docs**（依据 `apps/nexus/src/main.rs`、各 `*_cli.rs`、`localapi_client.rs`、
> `observability.rs` 与 `nexusd/src/main.rs` 的实际命令面重写 CLI / N2 / N3 / network / config 章节；
> **不改变任何产品行为**，场景期望与 PRODUCT 契约未动）。
> 旧声明（基于 `b6c2a41`、evidence `verify-4ce69aac9494`、22/22 PASS）已随 revision 前进而 **STALE**：
> 本手册不再复用该证据，条目均附代码路径与 E4/E3 场景来源，可在目标 revision 上用
> `nexus-harness verify --full` 重新生成证据复现校验（Final PASS 只由 Harness 产生）。
> 2026-10-04：补齐此前缺席或误归属的命令面 —— N2 资源访问（`nexus plan|use|session|resource|grant|provider|node|pair`，
> PRODUCT §16）、N3 任务（`nexus task|artifact`，PRODUCT §17）、`nexus network up|status`、
> `nexus config get|set|list`、`nexus proxy bufferbloat-test`；修正此前误记为 `nexusd <verb>` 的观察命令
> （现归 `nexus` CLI 名下，`nexusd` 仅保留 `<config-folder>` 与 `serve`）；修正默认 LocalAPI 传输目标
> （**unix socket 优先**，非固定 TCP `127.0.0.1:18080`）。
> 2026-10-05：一次"只看本手册执行用户命令"的可用性走查后修订 —— 修正 §2.3 daemon 二进制名
> （`nexus`→`nexusd`）、补齐**退出码三档语义（0/1/2）**、§4.7 观察表补必填参数、
> §4.9.2 示例资源名（`net`→`dev-svc`）；并把走查发现的实现缺陷/帮助缺口如实登记进 §6.1
> （`proxy --addr` 失效、`nexusd --help` 缺 `serve`、`vpi-capabilities` 需 feature 等），
> **不把产品缺陷曲解为预期行为**。详见 §6.5。

本手册只收录**有完整实现逻辑、用户可达**的功能。每个功能均附代码级校验：可机检场景（E4/E3）在 `verify --full` 中 PASS、可执行驱动（example / CLI 命令 / 集成测试）与来源代码路径。



***

## 1. 产品概览

Nexus 向用户提供一个统一 **Resource Fabric**：用户表达 "要使用什么资源、如何使用"，系统负责发现 Provider、规划 Provider/Placement/Path、建立 Session、激活 Connectivity、执行并持续观测（PRODUCT §1）。

五大产品分类：**Devices / Network / Services / Workspaces / Compute**。

所有资源使用遵守统一时序（ARCHITECTURE §6）：



```
Resolve Candidate Providers

&#x20;→ Plan Placement + Path

&#x20;→ Create Session

&#x20;→ Establish Connectivity

&#x20;→ Execute
```

核心不变量（由场景机检强制）：



* **Plan 与 Session 必须先于建连**（`plan_before_connectivity`）。

* **TerminalOutcome 恰一次提交**：Completed / Failed / Cancelled 只能由 Owner 提交一次，Worker 只发事件。

* **失败逆序幂等回滚**：终态确定后 Draining → Disposed，重复回滚被拒绝且状态不变。

* **认证门控**：未认证的链路 / 帧绝不进入业务处理。

## 2. 快速开始

### 2.1 环境要求



| 项                  | 要求                                 |
| ------------------ | ---------------------------------- |
| Rust               | 工作区 `edition = "2024"`、`rust-version = "1.85"`（见 `Cargo.toml`）；CI/沙箱实测 stable 1.92 |
| 目标平台               | Linux / Windows / macOS（平台专有功能仅在对应平台构建；本手册在 Linux 校验）              |
| nightly（仅 fuzz 门禁） | `rustup toolchain install nightly`（`cargo +nightly fuzz check`）      |
| 其它验证工具             | `cargo-deny`、`cargo-llvm-cov`、`wasm32-wasip1` target（`verify --full` 的相应门禁） |

### 2.2 构建



```
cargo build --workspace
```

### 2.3 入口与运行模式



| 二进制                   | 角色                             | 命令示例                                          |
| --------------------- | ------------------------------ | --------------------------------------------- |
| `nexus`               | 用户控制面 CLI：thin-client 观察命令 + 进程内命令族 | `nexus status --json` / `nexus use dev-svc` / `nexus subnet up --config c.toml` |
| `nexusd`             | 常驻 daemon：配置目录入口 + HTTP LocalAPI 提供方 | `nexusd serve` / `nexusd <config-folder>`     |
| `nexus-platform-host` | 平台宿主（能力声明）                     | `nexus-platform-host vpi-capabilities --json`（需 `--features platform-windows`，否则仅 stub，见 §4.8.1） |

三种使用形态（详见 §4.9）：



* **thin-client 观察命令**：`nexus` 经 `nexusd serve` 的 HTTP LocalAPI 查询 daemon 快照。`localapi_client` 的**路由表定义 8 条**（静态 5：`status` / `dns status` / `dns cache` / `connectivity status` / `platform capabilities`；动态 3：`workspace commit <ws>` / `session watch <id>` / `plan explain <res>`）。**注意**：`nexus plan` 与 `nexus session` 在 `main.rs` 分发时先被 N2 进程内模块接管、不经 daemon，故 CLI 实际经 daemon 的为 **5 静态 + `workspace commit`**；daemon 侧 `/session/watch`、`/plan/explain` 端点仍存在（由 `nexusd` 侧驱动/`localapi_probe` 使用）。daemon 未运行 → 结构化 `DAEMON_UNREACHABLE`（exit 0）。另有 **10 个观察命令无路由**（`dns resolve|providers`、`connectivity candidates|probe|links`、`workspace heads|conflicts|cache`、`compute jobs`、`diagnose`），CLI 本地合成显式 `UNSUPPORTED`（PRODUCT §9 禁止静默降级）。

* **进程内命令族（不经 daemon）**：`nexus plan|use|session|resource|grant|node|pair|network|subnet|schedule|system-proxy|autostart|config|run` 与 `nexus proxy ...` 直接装配 SDK 组合根执行，输出结构化 JSON。**退出码不是恒 0**：N2 进程内命令按 `verdict` 决定（`verdict=FAIL` → exit 1，如 `NOT_FOUND` / `AUTH_DENIED` / `ALREADY_TERMINATED`），`run` 则无论成败恒 exit 0；完整三档语义见 §4.9.2。

* **daemon 任务链（N3）**：`nexus task ...` 为 `nexusd` /localapi/v1/task 的 thin-client（POST）；`nexus artifact get` 当前诚实返回 `UNSUPPORTED_CAPABILITY`（未装配下载适配器）。

传输目标：`nexus` / `nexusd serve` 默认 **unix socket 优先**（`$XDG_RUNTIME_DIR/nexus-localapi.sock`，否则 `temp_dir()/nexus-<uid>/nexus-localapi.sock`，0700；均不可用才回退 TCP `127.0.0.1:18080`）；`--addr <ip:port>` 可显式切 TCP loopback，`--socket <path>` 指定 socket 路径（Windows 构建下 `--socket` 不可用）。

**两种 daemon 形态的默认传输不同**：`nexusd serve`（无参）默认 unix socket（同上）；而 `nexusd <config-folder>` 的 LocalAPI 地址取自配置目录内 `daemon.toml` 的 `localapi_addr`，**默认 TCP `127.0.0.1:18080`**（见 `apps/nexusd/src/config.rs`）。由于 `nexus` CLI 默认仍走 unix socket，若只用 `nexusd <config-folder>` 起服务，需 `nexus --addr 127.0.0.1:18080 status --json` 才能命中。

**帮助缺口**：`nexusd --help` / `nexusd -h` 仅打印 `nexusd <config-folder>` 用法（不含 `serve`，exit 2）；且 `nexusd serve --help` **不显示帮助，会直接启动 daemon**（见 §6.1）。

## 3. 功能总览

### 3.1 命令面总览（按 `nexus` CLI 实际分发，2026-10-05 复核）

下表为 `apps/nexus/src/main.rs` 分发逻辑中**实际可达**的全部命令。全局选项 `--json` / `--addr <ip:port>` / `--socket <path>` 在分发前统一剥离（`--json` 任意位置；`--addr`/`--socket` 亦为全局剥离，**这会与 `proxy` 子命令自己的 `--addr` 冲突，见 §6.1**）；**退出码三档语义见 §4.9.2**。

| 命令族 | 语法 | 路由/实现 | 产出 |
| --- | --- | --- | --- |
| 观察（thin-client） | `status`；`dns status\|cache`；`connectivity status`；`platform capabilities` | daemon 静态路由（5） | daemon JSON 原样渲染 |
| 观察（thin-client，带参） | `workspace commit <ws>` | daemon 动态路由（CLI 实际使用） | daemon JSON |
| （路由表另有） | `session watch <id>`；`plan explain <res>` | `localapi_client` 动态路由条目，但 CLI 先由 N2 模块接管（不经 daemon） | 见 N2 行 |
| 观察（无路由） | `dns resolve\|providers`；`connectivity candidates\|probe\|links`；`workspace heads\|conflicts\|cache`；`compute jobs`；`diagnose` | 本地合成 `UNSUPPORTED`（10） | `{verdict:"FAIL",error:{code:"UNSUPPORTED",command}}` |
| N2 资源访问（PRODUCT §16） | `plan <res>`；`plan explain <res\|session-id>`；`use <res>` | 进程内（N2 存储） | 规划预览 / 四步闭环 |
| N2 会话 | `session list`；`session watch <id>`；`session close <id>` | 进程内 N2 存储（`session watch` 即此语义；daemon `/session/watch` 路由条目由 daemon 侧使用） | 会话视图 / 关闭为 `Cancelled` |
| N2 资源目录 | `resource list`；`resource show <name>`；`resource publish --name <n> --kind <k> [--locator <l>...]`；`resource revoke <name>`；`resource export <name> [--file <p>]`；`resource import [--file <p>]` | 进程内 | 发布/撤销/导入导出 |
| N2 授权 | `grant add --resource <r> (--principal <p>\|--self) --op <Use\|Manage> [--not-after <n>]`；`grant revoke\|del --resource <r> --principal <p>`；`grant list [--resource <r>]` | 进程内（outbox 广播） | grant 表变更 |
| N2 身份/信任 | `node init [--force]`；`node trust --provider <id> --pubkey <hex>` | 进程内（本地文件） | NodeId / TOFU 信任 |
| N2 提供方 | `provider serve --bind <addr:port> [--once]` | 常驻准入服务 | 一条 `PASS` JSON（含 control 地址）+ 服务日志 |
| 设备配对（D7，§4.9.4） | `pair invite\|join\|list\|remove --dir <config-dir> [...]` | 进程内（本地文件 + 前台 TCP） | 纯文本（无 JSON） |
| N3 任务（PRODUCT §17） | `task submit --request <file>`；`task show\|cancel\|artifacts <id>`；`task logs <id> --stream <stdout\|stderr> --offset <n>` | thin-client（POST `/localapi/v1/task`） | 版本化任务 envelope |
| N3 产物 | `artifact get <id> --output <path>` | 未装配 → `UNSUPPORTED_CAPABILITY`（不写输出） | FAIL envelope |
| N1 装配 | `network up --config <toml>`；`network status [--config <toml>]` | 进程内 Composition Root（仅 Linux） | 建 TUN→dial→包泵 / 诚实状态 |
| 虚拟子网（PRODUCT §12） | `subnet up\|status\|leave\|punch` | 进程内 SDK | 隧道状态 / 打洞结果 |
| 计划任务（PRODUCT §14） | `schedule at\|every\|list\|cancel\|tick` | 进程内 SDK | 注册表 JSON |
| 代理数据面（PRODUCT §11） | `proxy [--addr <ip:port>] [--config <path>] [--tun] [--tun-name <n>]`；`proxy speedtest`；`proxy bufferbloat-test --proxy <ip:port> [--duration <s>] [--threshold <ms>]`；`proxy run\|host\|relay ...` | 进程内（自 `nexusd` 迁移） | SOCKS5 会话 JSON / READY |
| 平台控制（PRODUCT §13） | `system-proxy status\|set\|clear\|e2e`；`autostart install\|remove\|status` | 进程内 SDK（Windows；非 Windows 返回 `UNSUPPORTED`） | JSON |
| 配置文件夹 | `config get\|set\|list --dir <config-dir> [file]` | 本地文件（原子写） | 内容 / `PASS` |
| 资源执行 | `run <resource>`；`run <resource> -- <cmd...>` | 进程内 SDK；后者诚实拒绝 `UNSUPPORTED{feature:"run-with-command",layer:"N3"}` | 运行结果 / FAIL |

`nexusd` 侧仅保留两种形态：`nexusd <config-folder>`（配置目录入口）与 `nexusd serve [--addr <ip:port>] [--socket <path>]`（LocalAPI 提供方）；此前的 `nexusd run/host/relay/proxy/system-proxy/autostart/subnet/schedule` 均已迁移至 `nexus` CLI。

### 3.2 功能—场景对照表

以下 50 项功能均已通过代码级校验（场景 / 集成测试 PASS + 驱动可运行）。括号内为场景 ID 与期望条数；历史遗留限制与本次修复记录见 §6。45–50 为 2026-09-26 实测落地项（schedule CLI 有 E4 场景；其余为 E5 实测 + example 驱动）。



| #  | 功能                                                      | 场景（E4/E3）                                                                                                                                                                                   | 用户入口                                                        |
| -- | ------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------- |
| 1  | InternetAccess 端到端访问                                    | `product.internet-access-flow` (11)                                                                                                                                                         | example / SDK                                               |
| 2  | 建连失败逆序回滚                                                | `product.connectivity-failure-rollback` (7)                                                                                                                                                 | example / SDK                                               |
| 3  | VPI/PacketCarrier 双 trait 解耦                            | `product.connectivity-carrier-split` (6)                                                                                                                                                    | example                                                     |
| 4  | SOCKS5 有状态握手                                            | `product.socks5-handshake` (6)                                                                                                                                                              | example                                                     |
| 5  | DNS 子系统与 Exit-DNS Binding                               | `product.dns-exit-binding` (8)                                                                                                                                                              | example                                                     |
| 6  | DNS 多 server 规则路由 + IP-CIDR                             | `product.dns-rule-server-selection` (5) / `product.dns-ipcidr-rule` (5)                                                                                                                     | example                                                     |
| 7  | Service 资源生命周期                                          | `product.resource-session-lifecycle` (9)                                                                                                                                                    | example / SDK                                               |
| 8  | daemon 运行远程服务闭环                                         | `product.daemon-run-remote-service-flow` (20)                                                                                                                                               | `nexus proxy run service --json`                                 |
| 9  | 远程 Service 访问                                           | `product.remote-service-access-flow` (20)                                                                                                                                                   | example / SDK                                               |
| 10 | 远程 Internet 出口                                          | `product.remote-internet-access-flow` (21)                                                                                                                                                  | example / SDK / `nexus proxy run internet-access`                |
| 11 | 远程建连失败回滚                                                | `product.remote-connectivity-failure-rollback` (12)                                                                                                                                         | example                                                     |
| 12 | 远程认证门控拒绝                                                | `product.remote-network-auth-rejected-rollback` (12)                                                                                                                                        | example                                                     |
| 13 | 远程计算作业                                                  | `product.remote-compute-job-flow` (22)                                                                                                                                                      | example / SDK / `nexus proxy run compute`                        |
| 14 | 远程计算拒绝回滚                                                | `product.remote-compute-rejected-rollback` (12)                                                                                                                                             | example                                                     |
| 15 | 远程 Workspace 提交                                         | `product.remote-workspace-commit-flow` (20)                                                                                                                                                 | example                                                     |
| 16 | 远程 Workspace 拒绝回滚                                       | `product.remote-workspace-rejected-rollback` (15)                                                                                                                                           | example                                                     |
| 17 | 动态 Presence 发现                                          | `product.remote-presence-dynamic-flow` (21)                                                                                                                                                 | example                                                     |
| 18 | Presence 过期回滚                                           | `product.remote-presence-expired-rollback` (7)                                                                                                                                              | example                                                     |
| 19 | Presence 网络发现与未知回滚                                      | `product.remote-presence-network-discovery-flow` (25) / `product.remote-presence-network-unknown-rollback` (9)                                                                              | example                                                     |
| 20 | NAT/Relay 链路回退                                          | `product.remote-nat-relay-fallback-flow` (23)                                                                                                                                               | example                                                     |
| 21 | Relay 不可用回滚                                             | `product.remote-relay-unavailable-rollback` (13)                                                                                                                                            | example                                                     |
| 22 | Workspace 离线三方合并                                        | `product.workspace-offline-merge` (4)                                                                                                                                                       | example / SDK                                               |
| 23 | 崩溃恢复（冷启动 Reconciliation）                                | `regression.crash-recovery` (4)                                                                                                                                                             | example / SDK                                               |
| 24 | 终态恰一次提交                                                 | `regression.session-outcome-exactly-once` (2)                                                                                                                                               | example / SDK                                               |
| 25 | 未知资源结构化拒绝                                               | `product.daemon-rejects-unknown-resource` (3)                                                                                                                                               | `nexus run <unknown> --json`（FAIL / `UNSUPPORTED`）             |
| 26 | Observability 总览                                        | `product.observability-status` (4)                                                                                                                                                          | `nexus status --json`（daemon 路由）                            |
| 27 | Observability: plan explain                             | `product.observability-plan-explain` (4)                                                                                                                                                    | `nexus plan explain <res> --json`（N2 进程内；daemon `/plan/explain` 端点并存） |
| 28 | Observability: session watch                            | `product.observability-session-watch` (4)                                                                                                                                                   | `nexus session watch <id> --json`（N2 进程内；daemon `/session/watch` 端点并存） |
| 29 | Observability: dns cache                                | `product.observability-dns-cache` (3)                                                                                                                                                       | `nexus dns cache --json`（daemon 路由）                         |
| 30 | Observability: 完整命令集                                    | `observability-{dns-resolve,dns-providers,connectivity-candidates,connectivity-probe,connectivity-links,workspace-heads,workspace-conflicts,workspace-cache,compute-jobs,diagnose}`（见 §4.7） | `nexus <verb> --json`（有 daemon 路由者走 daemon，其余本地 `UNSUPPORTED`） |
| 31 | 未就绪命令显式 UNSUPPORTED                                     | `product.observability-unsupported` (3)                                                                                                                                                     | `nexus diagnose --json`（无路由 → 本地 `UNSUPPORTED`）             |
| 32 | Windows VPI 能力声明（wintun）                                | `platform.virtual-packet-interface` (10)                                                                                                                                                    | `nexus-platform-host vpi-capabilities --json`               |
| 33 | 虚拟子网隧道（Virtual Subnet）                                  | `product.virtual-subnet-tunnel` (7)                                                                                                                                                         | example / SDK                                               |
| 34 | 三节点虚拟子网静态路由（mesh）                                       | `product.virtual-subnet-mesh-3node` (10)                                                                                                                                                    | `nexus-harness run virtual-subnet-mesh --json` / SDK        |
| 35 | NAT 打洞（STUN + UDP 打洞）                                   | `nat-hole-punching`（harness 驱动；product TOML 已随 AC2 退役）                                                                                                                                                       | `nexus-harness run nat-hole-punching --json` / SDK |
| 36 | Proxy 节点测速（tcp /http204）                                | `proxy-speedtest` (8) / `proxy-speedtest-loopback` (6) / `proxy-speedtest-http204` (8) / `proxy-speedtest-http204-bad-status` (5) / `proxy-speedtest-http204-loopback` (6)                  | `nexus proxy speedtest --json` / example                   |
| 37 | Proxy 规则路由内核                                            | `proxy-*` 场景族（见 §4.1.10）                                                                                                                                                                    | `nexus proxy --addr <ip:port> [--config <path>]` / example |
| 38 | 出站适配器（SS / VMess / Trojan）                              | `proxy-*-adapter` 等 8 场景（见 §4.1.10）                                                                                                                                                         | example                                                     |
| 39 | 规则数据注入（geoip.nex/geosite.nex/rule-providers / Clash 订阅） | `geoip-nex-roundtrip` (8) / `geosite-nex-roundtrip` (8) / `proxy-rule-provider-fetch` (11) / `proxy-clash-subscription-parse` (9)                                                           | example / 配置                                                |
| 40 | Workspace Projection 访问通道                               | `platform.workspace-projection-fallback` (4) / `platform.workspace-projection-channels` (16)                                                                                                | example / SDK                                               |
| 41 | nexusd serve 常驻 daemon（HTTP LocalAPI）                   | 集成测试 E3（`apps/nexusd/tests/serve_localapi_e2e.rs`，4 用例）                                                                                                                                     | `nexusd serve --addr <ip:port>`                             |
| 42 | nexus CLI thin-client + run                             | `product.cli-run-command` (5)                                                                                                                                                               | `nexus run service --json` / `nexus status --json`          |
| 43 | 真实节点数据面（host / relay / SOCKS5）                          | `daemon-real-host-flow` (9) / `daemon-real-relay-flow` (9) / `daemon-real-socks-proxy-flow` (11) / `daemon-real-host-auth-denied` (5)                                                       | `nexus proxy host\|relay\|proxy --addr <ip:port>`            |
| 44 | 独立 Review + 动态知识库                                       | （工程方法论，非用户功能）                                                                                                                                                                               | `.agents/skills/` + `.agents/knowledge/`                    |
| 45 | 计划任务 CLI（PRODUCT §14）                                 | `product.schedule-cli` (10) / `product.schedule-cli-reachable` (1)                                                                                                                                        | `nexus schedule at\|every\|list\|cancel\|tick`            |
| 46 | nexus CLI 虚拟子网命令族                                        | `product.virtual-subnet-tunnel` (7) / `product.virtual-subnet-mesh-3node` (10)（进程内 SDK 入口）                                                                                                           | `nexus subnet up\|status\|leave\|punch`                  |
| 47 | 前台常驻 subnet（`--foreground`）                               | 实测 E5（PRODUCT §12.32 / §12.38；`--tun` 建议与 `--foreground` 同用）                                                                                                                              | `nexus subnet up\|status\|leave [--config] [--foreground] [--tun]` |
| 48 | TUN / TPROXY 透明入站数据面（daemon）                          | E4 场景（`product.tun-production-chain` 等 8 个）+ E5 netns S1–S10 已验收（Linux TPROXY；IPv4-only；S2 UDP 回包源端口项按 spec 冲突裁决挂起；PRODUCT §11.18）                                                                                        | `nexusd <config-dir>`（`proxy.yaml` 的 `inbounds[kind=tun\|tproxy]`） |
| 49 | 系统代理控制（WinInet）                                          | 实测 E5（PRODUCT §8 / §13；`e2e` 自清理闭环）                                                                                                                                                | `nexus system-proxy status\|set\|clear\|e2e`          |
| 50 | 开机自启注册（Task Scheduler ONLOGON）                             | 实测 E5（PRODUCT §13.2）                                                                                                                                                                          | `nexus autostart install\|remove\|status`              |
| 51 | Windows TUN 设备打开 smoke（非数据面）                          | 一次性设备打开验证；需管理员 + wintun.dll 与 exe 同目录；不参与 daemon 数据面                                                                                                                           | `nexus proxy --tun`                                      |



***

## 4. 功能手册（按域）

### 4.1 网络 / Internet Access

#### 4.1.1 InternetAccess 端到端访问



* **能力**：运行一次 InternetAccess 端到端纵切 ——Ingress 构造中立 FlowContext → SessionManager/Policy 生成 Intent+Constraint → Core Planner 选择 Provider/Placement/Path → 创建 Session → 建连 → 执行。纯内存、确定性（相同入参产生相同报告，可重放）。

* **用户用法**：


  * example：`cargo run --quiet -p nexus --example internet_access_flow -- --json`

  * SDK：`nexus::internet_access_flow(destination: &str, profile: &str) -> Result<Value, NexusError>`（`apps/nexus/src/lib.rs:89`）

* **代码级校验**：


  * 场景 `product.internet-access-flow`（E4，11 条期望）→ PASS

  * 驱动：`apps/nexus/examples/internet_access_flow.rs`；SDK 实现 `apps/nexus/src/lib.rs`

  * 门禁：product-scenarios；集成测试 `apps/nexus/tests/internet_access_flow.rs`

#### 4.1.2 建连失败逆序回滚



* **能力**：Connectivity 建连失败时验证两条产品不变量 ——(1) 先规划后建连；(2) W12 认证门控：未认证链路绝不 Established，失败事件结构化上报；(3) Worker 只发事件，Owner 唯一提交 `Failed`；(4) 终态后 Draining → Disposed，重复回滚幂等（被拒绝、状态不变）。

* **用户用法**：


  * example：`cargo run --quiet -p nexus --example connectivity_failure_rollback -- --json`

  * SDK：`nexus::connectivity_failure_rollback(destination: &str, profile: &str)`（`apps/nexus/src/lib.rs:334`）

* **代码级校验**：场景 `product.connectivity-failure-rollback`（7 期望）→ PASS；驱动 `apps/nexus/examples/connectivity_failure_rollback.rs`；集成测试 `apps/nexus/tests/connectivity_failure_rollback.rs`

#### 4.1.3 VPI / PacketCarrier 双 trait 解耦



* **能力**：Connectivity 层通过两个 trait 注入编排 ——VPI（IP 包语义）与 PacketCarrier（承载帧语义）分离，认证门控在链路层生效。是 wintun 后端与未来多平台后端的统一抽象边界。

* **用户用法**：`cargo run --quiet -p nexus --example connectivity_carrier_split -- --json`

* **代码级校验**：场景 `product.connectivity-carrier-split`（6 期望）→ PASS；驱动 `apps/nexus/examples/connectivity_carrier_split.rs`

#### 4.1.4 SOCKS5 有状态握手



* **能力**：SOCKS5 状态机：分步喂字节推进 Greeting → Method → Request → Established；失败路径结构化上报（不把协议错误改写成 "预期行为"）。

* **用户用法**：`cargo run --quiet -p nexus --example socks5_handshake -- --json`

* **代码级校验**：场景 `product.socks5-handshake`（6 期望）→ PASS；驱动 `apps/nexus/examples/socks5_handshake.rs`

#### 4.1.5 DNS 子系统与 Exit-DNS Binding



* **能力**：DNS 解析 → 缓存 → 环路守卫 → RDRC 负缓存 → Exit-DNS Binding 作为 NetworkPlanExtension 进入 Plan。可观测 DNS 状态 / 缓存 / Provider。

* **用户用法**：


  * example：`cargo run --quiet -p nexus --example dns_exit_binding -- --json`

  * 观察：`nexusd dns status --json` / `nexusd dns cache --json`

* **代码级校验**：场景 `product.dns-exit-binding`（8 期望）→ PASS；驱动 `apps/nexus/examples/dns_exit_binding.rs`

* **扩展（多 server 规则路由）**：多 DNS server + 按域名规则选择解析 server（未命中 MATCH 兜底）；IP-CIDR 规则与按 `(server_tag, name, qtype)` 分键的缓存隔离。场景 `product.dns-rule-server-selection`（5 期望）与 `product.dns-ipcidr-rule`（5 期望）→ PASS；驱动 `apps/nexus/examples/dns_rule_server_selection.rs`、`apps/nexus/examples/dns_ipcidr_rule.rs`（PRODUCT §11.5 / §11.5.1）。

#### 4.1.6 虚拟子网隧道（Virtual Subnet，双节点 P0）



* **能力**：节点间虚拟 IP 互通隧道，支持双节点点对点虚拟 IP 收发，结构化事件输出支持 replay / 调试。

* **用户用法**：


  * example：`cargo run --quiet -p nexus --example virtual_subnet_tunnel -- --json`

  * SDK：`nexus_connectivity::virtual_subnet::VirtualSubnetTunnel`

* **代码级校验**：场景 `product.virtual-subnet-tunnel`（7 期望）→ PASS；驱动 `crates/nexus-connectivity/src/virtual_subnet.rs`；单元测试 7 项

#### 4.1.7 三节点虚拟子网静态路由（mesh，P1 §12.5）



* **能力**：三节点链 A—B—C，A 与 C 无直连，B 作为中间节点按**显式静态路由表**转发。`send_ip_packet`：dst 是直连 Connected peer → 直发；否则查 `routes[dst]` 得 next\_hop，同一隧道帧（src/dst 原始虚拟 IP 不剥不改）发给 next\_hop。`recv_and_deliver`：dst 非本机 → 查路由重新封装转发并计 `TunnelStats.bytes_forwarded`；无 next\_hop → `NO_ROUTE_TO_DST`。`add_route` 的 next\_hop 非已注册 peer → `ROUTE_NEXT_HOP_NOT_PEER`。新增事件 `PacketForwarded { tunnel_id, src, dst, next_hop, bytes }`。不做：动态路由、最短路径、跨子网、加密、真实 TUN。

* **用户用法**：


  * harness：`nexus-harness run virtual-subnet-mesh --json`（场景驱动）

  * SDK：`VirtualSubnetTunnel::add_route(dst, next_hop) -> Result<(), ConnectivityError>`、`peer_stats(vip).bytes_forwarded`（`crates/nexus-connectivity/src/virtual_subnet.rs`）

* **代码级校验**：场景 `product.virtual-subnet-mesh-3node`（9 期望）→ PASS；`MeshCarrier` 多对端测试替身；单元测试含三节点转发与错误路径

#### 4.1.8 NAT 打洞（STUN + UDP 打洞）



* **能力**：STUN 协议获取公网映射 + NAT 类型检测 + UDP 打洞建连。支持结构化事件输出。

* **用户用法**：


  * harness：`nexus-harness run nat-hole-punching --json`（离线确定性编解码自检，输出 PASS/FAIL JSON；真实跨主机打洞 P3 deferred）

  * SDK：`nexus_connectivity::nat::{NatEvent, NatType, StunMapping}`（canonical codec：`nexus_turn::stun`；`StunClient`/`HolePuncher` 已随 #1 退役）

* **代码级校验**：`nexus-harness run nat-hole-punching` → PASS（2026-10-18：RFC5389 Binding Request 构造 + XOR-MAPPED-ADDRESS 解析确定性自检）；单元测试 `cargo test -p nexusd nat_stun` 12/12。真实 STUN 服务器集成测试待完善。

#### 4.1.9 Proxy 节点测速（tcp /http204，§11.10）



* **能力**：对候选出站批量测速并按 RTT 升序输出。两种探测：


  * `tcp`（默认）：仅建连级延迟（connect\_timeout）。

  * `http204`：TCP 建连后发送单行明文 `GET {path} HTTP/1.1`，等待响应首行 `204 No Content`，计时覆盖建连 + 请求发送 + 响应首字返回；非 204 响应 / 读取超时 / `https` target 记为 `unreachable`（P0 不做 TLS）。

  * 指标：`latency_ms`（未测得 null）、`status`（`ok`/`timeout`/`unreachable`/`dns_failed`）、`probe_kind`、`target`。默认目标 `http://www.gstatic.com/generate_204`，超时上限 5s（可配）。单节点失败非致命，不中断批量。

* **用户用法**：


  * daemon：`nexus proxy speedtest --json`（loopback 自检，tcp）

  * example：`cargo run --quiet -p nexus --example proxy_speedtest -- --json`（tcp 离线 mock）、`proxy_speedtest_loopback`（tcp 真 TCP）、`proxy_speedtest_http204`（http204 离线 mock）、`proxy_speedtest_http204_loopback`（http204 真 HTTP/204 服务）、`proxy_speedtest_http204_bad_status`（500 → unreachable）

  * SDK：`nexus::proxy_speedtest_with(probe, candidates, timeout, target_label, probe_kind)`（`apps/nexus/src/lib.rs:4206`）、`Http204LatencyProbe`（`apps/nexus/src/lib.rs:4137`）

  * 配置：YAML `proxy.speedtest: {target, timeout_ms, probe_kind}`（`tcp`|`http204`，其他 → `CONFIG_INVALID`，nexus-proxy-config 已解析校验）

* **代码级校验**：场景 `proxy-speedtest` (8) / `proxy-speedtest-loopback` (6) / `proxy-speedtest-http204` (8) / `proxy-speedtest-http204-bad-status` (5) / `proxy-speedtest-http204-loopback` (6) → 全部 PASS

#### 4.1.10 Proxy 规则路由内核与出站适配器（§11）



* **能力**：规则路由代理内核 ——Clash 风格配置解析（订阅节点解析）、规则匹配（DOMAIN / GEOSITE / GEOIP / IP-CIDR / MATCH / 端口）、规则集与 rule-providers（含在线 URL 拉取）、分组策略（selector /url-test/load-balance /relay）。真实数据面：`nexus proxy --addr <ip:port> [--config <path>]` 提供真实 SOCKS5 监听，逐会话完成握手 → 规则路由 → Session → 真实出站 → 双向字节中继。

* **出站适配器**：Shadowsocks（真实 TCP 会话）、VMess（线格式）、Trojan（TLS + 认证 + Standard/Singbox 头格式 + SNI/ALPN/skip-verify 参数）。适配器经 `OutboundAdapter` trait 注入（MODULE.md 冻结契约）。

> **互操作状态注记**：上述是代码级适配器能力，不代表已通过参照实现互操作。
> 互操作状态以 [出站协议互操作证据总表](protocols/interop/MATRIX.md) 为准：VLESS、AnyTLS
> 为 `VERIFIED / USABLE`；Shadowsocks 为 `PARTIAL / TCP_ONLY / USABLE_WITH_GAPS`
> （SIP004 互操作已通、产品 UDP 未实现、nexusd TUN 路径不在覆盖内）；
> Hysteria2、Trojan 为 `BROKEN / NOT_USABLE`。
> 五协议均可在配置面选择但无「实验性/未验证」标注。

* **用户用法**：


  * 数据面：`nexus proxy --addr 127.0.0.1:1080 --config <path>`

  * example：`proxy_default_match` / `proxy_rule_set` / `proxy_geoip_rule` / `proxy_geosite_rule` / `proxy_ipcidr_rule` / `proxy_selector_group` / `proxy_urltest_group` / `proxy_loadbalance_group` / `proxy_relay_group` / `proxy_socks5_domain_rule` / `proxy_rule_invalid` / `proxy_shadowsocks_adapter` / `proxy_shadowsocks_real_tcp` / `proxy_vmess_adapter` / `proxy_trojan_adapter`（含 `--scenario rejected` 反例）/ `proxy_clash_subscription_parse` / `proxy_rule_provider_fetch`

* **代码级校验**：`proxy-*` 场景族全部 PASS（default-match 6 /rule-set 8 /geoip-rule 6 /geosite-rule 5 /ipcidr-rule-match 6 /selector 6 /urltest 5 /loadbalance 6 /relay-group 5 /socks5-domain-rule-forward 6 /rule-invalid 4 /shadowsocks-adapter 6 /shadowsocks-real-tcp 5 /vmess-adapter 6 /trojan-adapter 6 /trojan-auth-rejected 6 /trojan-header-format 4 /trojan-node-config 7 /trojan-real-tls-params 6 /clash-subscription-parse 9 /rule-provider-fetch 11）

> **互操作状态注记**：上述 `proxy-*` 是代码级/自洽校验，不等于对参照实现的互操作。
> 互操作结论以 [出站协议互操作证据总表](protocols/interop/MATRIX.md) 为准：VLESS、AnyTLS
> 为 `VERIFIED / USABLE`；Shadowsocks 为 `PARTIAL / TCP_ONLY / USABLE_WITH_GAPS`
> （产品 UDP 未实现、nexusd TUN 路径不在覆盖内）；Hysteria2、Trojan 为 `BROKEN / NOT_USABLE`。

#### 4.1.11 规则数据注入（geoip.nex/geosite.nex）



* **能力**：`geoip.nex` / `geosite.nex` 二进制规则数据格式 + 生成器 + 往返校验，供 GEOIP / GEOSITE 规则匹配与 rule-providers 在线拉取使用。

* **用户用法**：`cargo run --quiet -p nexus --example geoip_nex_roundtrip -- --json`、`geosite_nex_roundtrip`；工具 `geoip.nex`（`crates/nexus-proxy-config` 相关实现）。

* **代码级校验**：`product.geoip-nex-roundtrip` (8) / `product.geosite-nex-roundtrip` (8) → PASS

### 4.2 Service

#### 4.2.1 Service 资源生命周期



* **能力**：Service 资源完整生命周期，验证两条产品不变量：(1) Resolve → Plan → Session → Connectivity → Execute 顺序（Plan/Session 先于建连）；(2) Exactly-One Terminal Outcome：Owner 只提交一次终态、重复提交被拒、终态后 cleanup 推进到 Disposed。

* **用户用法**：


  * example：`cargo run --quiet -p nexus --example service_session_lifecycle -- --json`

  * SDK：`nexus::service_session_lifecycle(resource: &str, profile: &str)`（`apps/nexus/src/lib.rs:197`）

* **代码级校验**：场景 `product.resource-session-lifecycle`（9 期望）→ PASS；集成测试 `apps/nexus/tests/service_session_lifecycle.rs`

#### 4.2.2 daemon 运行远程服务闭环



* **能力**：`nexusd` 单次执行入口装配 SDK 远程服务闭环，输出附加 daemon 入口元数据（`daemon.entry` / `daemon.resource`）。

* **用户用法**：`cargo run --quiet -p nexusd -- run service --json`

* **代码级校验**：场景 `product.daemon-run-remote-service-flow`（20 期望）→ PASS；实现 `apps/nexusd/src/main.rs`（`run_resource` + `enrich`）

### 4.3 远程资源访问（Node A ↔ Node B）

> 共同机制：进程内双节点模拟 ——Node B 在回环端口监听并提供服务 / 出口 / 计算 / Workspace；Node A 经 Discovery → Plan → Session → Connectivity → Auth → 资源访问的真实 TCP 长度前缀帧流闭环。链路激活支持 Direct 探测与 Relay 中继两跳。

#### 4.3.1 远程 Service 访问



* **能力**：Node A 经静态发现 / 规划 / 会话 / 建连 / Token 门控 / Transport 访问 Node B 的 Service 资源（CONNECT → READY 握手）。

* **用户用法**：example `cargo run --quiet -p nexus --example remote_service_access_flow -- --json`；SDK `nexus::remote_service_access_flow()`（`apps/nexus/src/lib.rs:624`）

* **代码级校验**：场景 `product.remote-service-access-flow`（20 期望）→ PASS

#### 4.3.2 远程 Internet 出口



* **能力**：Node A 经远程闭环访问 Node B 的 InternetAccess 出口，HTTP 请求 / 响应帧往返成功。

* **用户用法**：example `cargo run --quiet -p nexus --example remote_internet_access_flow -- --json`；SDK `nexus::remote_internet_access_flow()`（`apps/nexus/src/lib.rs:949`）；`nexus proxy run internet-access --json`

* **代码级校验**：场景 `product.remote-internet-access-flow`（21 期望）→ PASS

#### 4.3.3 远程建连失败回滚



* **能力**：Discovery 已解析 Node B 但建连失败 → 按逆序幂等回滚到 Disposed，Owner 唯一提交 Failed。

* **用户用法**：example `cargo run --quiet -p nexus --example remote_connectivity_failure_rollback -- --json`

* **代码级校验**：场景 `product.remote-connectivity-failure-rollback`（12 期望）→ PASS

#### 4.3.4 远程认证门控拒绝



* **能力**：远程网络会话令牌不匹配时认证门控拒绝（W7：未认证帧不进入业务处理），逆序幂等回滚。

* **用户用法**：example `cargo run --quiet -p nexus --example remote_network_auth_rejected_rollback -- --json`

* **代码级校验**：场景 `product.remote-network-auth-rejected-rollback`（12 期望）→ PASS

#### 4.3.5 远程计算作业



* **能力**：Node A 向 Node B 提交计算作业并取回结果帧（提交 / 结果往返）。

* **用户用法**：example `cargo run --quiet -p nexus --example remote_compute_job_flow -- --json`；SDK `nexus::remote_compute_job_flow()`（`apps/nexus/src/lib.rs:1289`）；`nexus proxy run compute --json`

* **代码级校验**：场景 `product.remote-compute-job-flow`（22 期望）→ PASS

#### 4.3.6 远程计算拒绝回滚



* **能力**：计算作业被提供方拒绝（REJECTED 帧）→ 逆序幂等回滚。

* **用户用法**：example `cargo run --quiet -p nexus --example remote_compute_rejected_rollback -- --json`

* **代码级校验**：场景 `product.remote-compute-rejected-rollback`（12 期望）→ PASS

#### 4.3.7 远程 Workspace 提交



* **能力**：Node A 经远程闭环向 Node B 的 Workspace 远程提交并取回新 Head（OK:HEAD 往返）。

* **用户用法**：example `cargo run --quiet -p nexus --example remote_workspace_commit_flow -- --json`；SDK `nexus::remote_workspace_commit_flow()`（`apps/nexus/src/lib.rs:1655`）

* **代码级校验**：场景 `product.remote-workspace-commit-flow`（20 期望）→ PASS

#### 4.3.8 远程 Workspace 拒绝回滚



* **能力**：远程提交被提供方拒绝（REJECTED 帧）→ 逆序幂等回滚。

* **用户用法**：example `cargo run --quiet -p nexus --example remote_workspace_rejected_rollback -- --json`

* **代码级校验**：场景 `product.remote-workspace-rejected-rollback`（15 期望）→ PASS

#### 4.3.9 动态 Presence 发现



* **能力**：Node B 发布动态 Presence，Node A 经动态发现解析（Discovery → Endpoint）后完成远程闭环。

* **用户用法**：example `cargo run --quiet -p nexus --example remote_presence_dynamic_flow -- --json`

* **代码级校验**：场景 `product.remote-presence-dynamic-flow`（21 期望）→ PASS

#### 4.3.10 Presence 过期回滚



* **能力**：Node B 的 Presence 过期（PeerExpired/PeerUnknown）后 Node A 动态解析失败并回滚，不进入 Plan/Session。

* **用户用法**：example `cargo run --quiet -p nexus --example remote_presence_expired_rollback -- --json`

* **代码级校验**：场景 `product.remote-presence-expired-rollback`（7 期望）→ PASS

#### 4.3.11 Presence 网络发现与未知回滚



* **能力**：Presence 网络级发现闭环（多节点发现 → Endpoint 解析 → 远程访问）与未知 Peer 结构化拒绝回滚。

* **用户用法**：example `cargo run --quiet -p nexus --example remote_presence_network_discovery_flow -- --json` / `remote_presence_network_unknown_rollback -- --json`

* **代码级校验**：场景 `product.remote-presence-network-discovery-flow`（25 期望）→ PASS；`product.remote-presence-network-unknown-rollback`（9 期望）→ PASS

#### 4.3.12 NAT/Relay 链路回退



* **能力**：Node B 位于 NAT 后：Direct 候选探测失败（NAT 不可达）时回退 Relay 中继（A → R → B 两跳）完成远程闭环。

* **用户用法**：example `cargo run --quiet -p nexus --example remote_nat_relay_fallback_flow -- --json`

* **代码级校验**：场景 `product.remote-nat-relay-fallback-flow`（23 期望）→ PASS

#### 4.3.13 Relay 不可用回滚



* **能力**：Direct 与 Relay 均不可达时，Link Activation 结构化失败并回滚。

* **用户用法**：example `cargo run --quiet -p nexus --example remote_relay_unavailable_rollback -- --json`

* **代码级校验**：场景 `product.remote-relay-unavailable-rollback`（13 期望）→ PASS

### 4.4 Workspace（本地）

#### 4.4.1 离线提交三方合并



* **能力**：Workspace 多端离线写允许产生多个 Head；重新联网后 fast-forward /three-way merge / 显式冲突解决；已成功提交的本地数据不因远端 Head 前进而丢失。

* **用户用法**：


  * example：`cargo run --quiet -p nexus-workspace --example workspace_offline_merge -- --json`

  * SDK（`crates/nexus-workspace/src/lib.rs`）：`Workspace::init / open(id, store, &state_root) / commit_changes / merge_heads / heads / state_root / into_store`

* **代码级校验**：场景 `product.workspace-offline-merge`（4 期望）→ PASS；驱动 `crates/nexus-workspace/examples/workspace_offline_merge.rs`；workspace 单元测试 12 项

#### 4.4.2 崩溃恢复（冷启动 Reconciliation）



* **能力**：进程强杀后冷启动必须先 Reconciliation 再接受新工作：加载持久状态 → 重放 / 验证 journal（确认或 redo）→ 孤儿会话分类（Active+Unfinished 恰一次提交 Failed→Disposed）→ 接受新任务；所有 reconcile 幂等。

* **用户用法**：


  * example：`cargo run --quiet -p nexus-workspace --example crash_recovery -- --json`

  * SDK：`Workspace::open` + `reconcile_journal`（返回 `JournalReconcileReport{confirmed, redone, total}`）；`nexus_session::reconcile_session_records(store, &mut session, process_alive)`（返回 `SessionReconcileReport`）

* **代码级校验**：场景 `regression.crash-recovery`（E3，4 期望：reconciliation\_started → workspace\_journal\_reconciled → orphan\_session\_classified → accept\_new\_work）→ PASS；驱动 `crates/nexus-workspace/examples/crash_recovery.rs`；session/workspace 单元测试 25 项

#### 4.4.3 Workspace Projection 访问通道（§4 / §9）



* **能力**：无 FUSE/Mount 平台也能使用 Workspace —— 统一 `WorkspaceAccess` trait（`read_file / write_file / list_dir / delete / commit / head / provider_type`）+ 三通道选择（`select_access_provider`）：NativeMountDirectory（平台原生挂载，优先）→ MaterializedDirectory（物化目录投影）→ NativeApi（纯结构化 API，**总可用兜底**）。访问通道只改变 "怎么访问"，不改变权威模型（Commit DAG / Head Set / Manifest 仍完整）。

* **用户用法**：


  * example：`cargo run --quiet -p nexus-workspace --example workspace_projection_fallback -- --json`（默认 given：native\_mount=false, materialization=true）

  * SDK：`nexus_workspace::{WorkspaceAccess, NativeApiWorkspaceAccess, select_access_provider}`（`crates/nexus-workspace/src/lib.rs`）

* **代码级校验**：场景 `platform.workspace-projection-fallback`（4 期望：选中 `MaterializedDirectory` + 产品语义保持）→ PASS；`platform.workspace-projection-channels`（16 期望：NativeApi 读写/commit/恢复/NotFound + Materialized 物化/读写/回写）→ PASS（2026-09-20，feature/workspace-projection-api 合并）

* **已知边界**：NativeApi 通道已实现 WorkingSet 合并语义（read 合并 Head Manifest、write/delete 落 WorkingSet、commit 落新 Commit、list_dir 单层 + 合成父目录项、路径越界拒绝 `PathTraversal` / 缺失文件 `NotFound`）；MaterializedDirectory 已实现 Head Manifest 物化到本地目录 + 差异回写；NativeMountDirectory 真实目录挂载仍为 API 声明待落地（见 §6.1）。

### 4.5 Session

#### 4.5.1 终态恰一次提交



* **能力**：取消、成功、断链三种竞争源轮换 10,000 轮，TerminalOutcome（Completed/Failed/Cancelled）每轮恰一次提交且生命周期到达 Disposed；Worker 只发事件、Owner 是唯一 Outcome Writer。

* **用户用法**：


  * example：`cargo run --quiet -p nexus-session --example session_outcome_exactly_once -- --json`

  * SDK（`crates/nexus-session/src/lib.rs`）：`SessionOwner::new / transition_phase / commit_outcome / request_cancellation / id / phase / committed_outcome / status / events`；`CancelToken`、`AbortOnDropHandle`

* **代码级校验**：场景 `regression.session-outcome-exactly-once`（E3，2 期望）→ PASS；驱动 `crates/nexus-session/examples/session_outcome_exactly_once.rs`；并发测试 `tests/concurrency/session_outcome_race.rs`（2 concurrency tests PASS）

### 4.6 Daemon

#### 4.6.1 未知资源结构化拒绝



* **能力**：`nexus run <unknown> --json` 返回结构化拒绝 `{verdict:"FAIL", error.code:"UNSUPPORTED"}`（exit 0 = 请求已被处理，拒绝也是处理结果），禁止静默忽略。

* **用户用法**：`nexus run frobnicate --json`

* **代码级校验**：场景 `product.daemon-rejects-unknown-resource`（3 期望）→ PASS

#### 4.6.2 nexusd serve：常驻 daemon（HTTP LocalAPI）



* **能力**：`nexusd serve` 常驻监听，提供最小 HTTP LocalAPI；`nexus` CLI 经裸 GET 查询。输出 `READY` JSON 报告实际监听地址。

* **用户用法**：


  * `nexusd serve`（默认 **unix socket 优先**：`$XDG_RUNTIME_DIR/nexus-localapi.sock`，否则 `temp_dir()/nexus-<uid>/nexus-localapi.sock`；均不可用才回退 TCP `127.0.0.1:18080`）

  * `nexusd serve --addr <ip:port>`（显式 TCP loopback）

  * `nexusd serve --socket <path>`（指定 Unix domain socket；**Windows 为 named pipe，当前 UNSUPPORTED**，报错提示改用 `--addr`）

  * 静态路由（GET）：`/localapi/v0/{status, dns/status, dns/cache, connectivity/status, platform/capabilities}`；动态路由：`/localapi/v0/session/watch?session=<id>`、`/localapi/v0/plan/explain?resource=<res>`、`/localapi/v0/workspace/commit/<ws>`；daemon 另提供 `/localapi/v0/{dataplane/stats, n2/session/list, n2/session/attach, workspace/mounts}`（无对应 CLI ControlCommand）

  * 配合 CLI：`nexusd serve` → `nexus status --json`（CLI 默认同一 unix socket；跨机/显式 TCP 用 `nexus --addr <ip:port> status --json`）

* **代码级校验**：集成测试 E3 `apps/nexusd/tests/serve_localapi_e2e.rs`（4 用例：status /dns cache /plan explain 路由 200 + 未知路由 404 `NOT_FOUND`；子进程 READY 轮询 + Drop guard 回收）；integration 门禁 PASS

#### 4.6.3 真实节点数据面（host /relay/ SOCKS5 proxy）



* **能力**：真实网络入口 ——`nexus proxy host <resource> --addr <ip:port> [--token <t>]` 提供方持续监听（每连接 AUTH 门控 + 业务闭环）；`nexus proxy relay --addr <ip:port>` DIAL + 双向字节中继；`nexus proxy --addr <ip:port> [--config <path>]` 真实 SOCKS5 数据面（握手 → 规则路由 → Session → 真实出站 → 字节中继）。

* **用户用法**：`nexus proxy host service --addr 127.0.0.1:8787 --token <t>`；`nexus proxy relay --addr 127.0.0.1:8788`；`nexus proxy --addr 127.0.0.1:1080`

* **已知缺陷（`--addr` 失效）**：`nexus proxy [host|relay] --addr <ip:port>` 的 `--addr` **当前不生效**——全局选项剥离器（`main.rs::extract_remote_target`）在分发前把 `--addr` 当作 thin-client 目标吞掉，子命令收不到，实际监听**默认端口**（SOCKS5 `1080`、host `8787`；`ss` 实测确认）。上面的示例恰用默认端口，故看似正常；换成别的端口即可复现（监听仍在默认端口）。**不在文档层改写成"预期行为"，已在 §6.1 登记为待修缺陷**；当前规避：只能用默认端口（`proxy` 的 `--config` / `--token` / `--tun` 不受影响）。

* **代码级校验**：`product.daemon-real-host-flow` (9) / `daemon-real-host-auth-denied` (5) / `daemon-real-relay-flow` (9) / `daemon-real-socks-proxy-flow` (11) → 全部 PASS；错误 token 透传 `AUTH_DENIED`，host 为持续服务循环

### 4.7 Observability（§9）

观察命令统一由 **`nexus` CLI** 提供（`nexusd` 自身仅 `<config-folder>` 与 `serve` 两种形态）。有 daemon 路由者由 daemon 返回 JSON；无路由者 CLI 本地合成显式 `UNSUPPORTED`（exit 0），禁止静默降级。



| 命令                                      | 能力                                                         | 场景                                                  |
| --------------------------------------- | ---------------------------------------------------------- | --------------------------------------------------- |
| `nexus status --json`                  | 总览：DNS 快照 + 建连链路 + 规划决策 + 平台能力                             | `product.observability-status` (4)                  |
| `nexus dns status --json`              | DNS 运行时状态（缓存 / 调用计数 / Exit-DNS Binding）                    | 由 `dns-exit-binding` + status 覆盖                    |
| `nexus dns cache --json`               | DNS 正 / 负缓存快照                                              | `product.observability-dns-cache` (3)               |
| `nexus dns resolve <name> --json`      | 解析 [example.com](https://example.com) 输出地址 / TTL / Binding | `product.observability-dns-resolve` (6)             |
| `nexus dns providers --json`           | DNS Provider 列表                                            | `product.observability-dns-providers` (5)           |
| `nexus session watch <id> --json`      | Session 双轨状态（phase/outcome/committed）                      | `product.observability-session-watch` (4)           |
| `nexus connectivity status --json`     | 建连状态                                                       | 由 `status` 覆盖                                       |
| `nexus connectivity candidates --json` | 候选 Provider                                                | `product.observability-connectivity-candidates` (5) |
| `nexus connectivity probe <target> --json` | 目标可达性探测                                                | `product.observability-connectivity-probe` (6)      |
| `nexus connectivity links --json`      | 活动链路                                                       | `product.observability-connectivity-links` (6)      |
| `nexus plan explain <res\|session-id> --json` | Plan + DecisionTrace 结构化拒绝原因（N2 进程内；见 §4.9.3）            | `product.observability-plan-explain` (4)            |
| `nexus platform capabilities --json`   | 平台能力清单                                                     | 由 `status` + `platform.virtual-packet-interface` 覆盖 |
| `nexus workspace heads <ws> --json`    | Head Set 快照（离线分叉可观察）                                       | `product.observability-workspace-heads` (6)         |
| `nexus workspace conflicts <ws> --json` | 未合并冲突                                                      | `product.observability-workspace-conflicts` (6)     |
| `nexus workspace cache <ws> --json`    | 缓存状态 / 保护保留                                                | `product.observability-workspace-cache` (6)         |
| `nexus compute jobs --json`            | 作业阶段 / 结果快照                                                | `product.observability-compute-jobs` (7)            |
| `nexus diagnose --json`                | 统一诊断                                                       | `product.observability-diagnose` (5)                |
| `nexus workspace commit <ws> --json`   | 提交 Workspace 暂存变更（daemon 动态路由）                              | 由 `nexusd` Workspace 挂载契约覆盖（C1/D1–D9）                 |

SDK 层：`nexus::observability::{status, dns_status, dns_cache, dns_resolve, dns_providers, session_watch, connectivity_status, connectivity_candidates, connectivity_probe, connectivity_links, plan_explain, platform_capabilities, workspace_heads, workspace_conflicts, workspace_cache, compute_jobs, diagnose}`（`apps/nexus/src/observability.rs`）。

> **必填参数**：上表中带 `<name>` / `<target>` / `<id>` / `<res>` / `<ws>` 的命令，位置参数不可省略——逐字照抄不带参的写法会得到 `error: missing argument`（exit 2）。例如 `nexus dns resolve --json`、`nexus connectivity probe --json`、`nexus session watch --json`、`nexus workspace heads --json` 均缺参失败；须写 `nexus dns resolve example.com --json` 等。

**进程级状态单例**：`nexusd` 的 DNS 运行时为进程级单例（`OnceLock<RwLock<DnsRuntime>>`）。同一进程内多次 `dns status` / `dns cache` 共享同一缓存与调用计数（第二次同名解析 `from_cache=true`）；`nexusd serve` 常驻时，每个 LocalAPI 请求看到同一份累积状态，而非全新快照。

**CLI thin-client 路由**：`localapi_client` 路由表定义 **8 条** —— 静态 5：`status` / `dns status` / `dns cache` / `connectivity status` / `platform capabilities`；动态 3：`workspace commit <ws>` / `session watch <id>` / `plan explain <res>`。但 `main.rs` 分发中 `nexus plan` / `nexus session` 先被 N2 进程内模块接管，**CLI 实际经 daemon 的为 5 静态 + `workspace commit`**；`/session/watch`、`/plan/explain` 端点由 daemon 侧（`localapi_probe` / observability 场景）使用。其余 10 个命令本地合成显式 `UNSUPPORTED`（9 个 `cli-*` 场景 + `product.observability-unsupported`（经 `nexus diagnose`）冻结该契约，2026-09-20 requirement-change）；daemon 未启动 → `DAEMON_UNREACHABLE`（均 exit 0）。

### 4.8 平台

#### 4.8.1 Windows VPI 能力声明（wintun）



* **能力**：平台宿主声明 Windows Virtual Packet Interface 能力：wintun 窄 FFI 后端、portable consumer（nexus-ingress）、Packet Semantics（MTU 1420、packet ingress/egress、wintun native API）。

* **用户用法**：`cargo run --quiet -p nexus-platform-host --features platform-windows -- vpi-capabilities --json`

* **诚实边界**：必须带 `--features platform-windows`；**不带该 feature 的构建（默认，如 §2.3 的示例）只打印 stub 文本 `nexus-platform-host: repository-contract bootstrap`，不输出任何能力 JSON**。

* **代码级校验**：场景 `platform.virtual-packet-interface`（10 期望）→ PASS；实现 `apps/nexus-platform-host`（`vpi-capabilities` 命令）

### 4.9 CLI 前端（thin-client）

#### 4.9.1 nexus run：远程资源访问



* **能力**：`nexus run <resource>` 走进程内 SDK 路径执行远程资源访问（LocalAPI 无对应路由），输出 `run.resource / session_id / connectivity.status / outcome`。

* **用户用法**：`cargo run --quiet -p nexus -- run service --json`（支持 `service` / `compute` / `internet-access`；未知资源 → 结构化 `Unsupported`）

* **代码级校验**：场景 `product.cli-run-command`（5 期望：verdict=PASS、run.resource=service、session\_id 非空、connectivity=Connected、outcome=Completed）→ PASS

#### 4.9.2 nexus 观察命令（thin-client 查询）



* **能力**：观察命令的参数解析（`--json` 任意位置；`--addr <ip:port>` / `--socket <path>`，默认 **unix socket 优先**）；路由表 **8 条**（静态 5 + 动态 3；CLI 实际经 daemon 为 5 静态 + `workspace commit`，`plan` / `session` 先被 N2 进程内模块接管），向 `nexusd serve` 发裸 HTTP GET 并原样渲染 daemon JSON（`--json` 机器可读 / 默认人读投影）；**10 个**无路由命令本地合成 `UNSUPPORTED`；连接失败输出 `DAEMON_UNREACHABLE` FAIL JSON。

* **退出码三档（`apps/nexus/src/main.rs` / `verdict_exit_code`，实测）**：
  * `0` —— 请求已被处理（含 `verdict=FAIL`）：走 daemon 的命令（daemon 返回 FAIL 或 `DAEMON_UNREACHABLE`）、本地合成 `UNSUPPORTED` 的无路由命令、`run <resource>`（无论成败）均为 0。
  * `1` —— **N2 进程内命令的业务失败**：输出 `verdict=FAIL` 且按 `verdict_exit_code` 返回 1，例如 `plan explain <不存在>`→`NOT_FOUND`、`session watch <不存在>`→`NOT_FOUND`、`session close <已终态>`→`ALREADY_TERMINATED`、`use`（无授权）→`AUTH_DENIED`。
  * `2` —— 用法 / 解析错误（缺参、未知命令、`--socket` 在本构建不可用）。
  * **注意**：`run` 是例外——其 FAIL 仍为 exit 0（`main.rs` 的 `Run` 分支恒 0）；而 `plan`/`use`/`session`/`resource`/`grant`/`config` 的 FAIL 为 exit 1。脚本消费时不能只按"0 vs 非 0"判定，须读 `verdict`。

* **用户用法**：先 `nexusd serve`，再 `nexus status --json` / `nexus plan explain dev-svc --json` / `nexus dns cache --json`（`dev-svc` / `internet-access` 为内建 registry 中存在的资源；不存在的资源名如 `net` → `NOT_FOUND`，exit 1）；显式 TCP 目标用 `nexus --addr 127.0.0.1:18080 status --json`。

* **代码级校验**：CLI 单元测试（解析 / 剥离 / exit 语义）+ 集成测试 `apps/nexusd/tests/serve_localapi_e2e.rs`；9 个 `cli-*` 场景（E4）冻结 thin-client 契约：无路由命令必须本地合成 `verdict=FAIL, error.code=UNSUPPORTED, error.command=<命令名>`（2026-09-20 requirement-change，见 §6.2 修复记录）

#### 4.9.3 N2 资源访问命令族（PRODUCT §16）

* **能力**：`nexus` 内置 N2 通用资源访问命令面（进程内 N2 存储，不经 daemon）：
  * `plan <resource>`：只读规划预览（resolve + filter + score，不建连）；`plan explain <resource|session-id>` 双模式（历史 DecisionTrace / 估算非承诺标注，查无历史 → `NOT_FOUND`，拒绝伪造）。
  * `use <resource>`：四步闭环 resolve→plan→authorize→establish；`--json` = Strict 信任策略、交互 = TOFU Prompt；租约 TTL 3600s；`-- <cmd>` 诚实拒绝 `UNSUPPORTED{feature:"use-with-command",layer:"N3"}`。
  * `session list|watch <id>|close <id>`：list/watch 读同一持久化记录；close 主动关闭 → `Cancelled`（cancel_reason=`UserClosed`）。
  * `resource list|show|publish|revoke|export|import`：publish = 建广告（locator 需含非 `n2adm://` 数据面端点）+ 本机自授 Use + 清 tombstone；revoke = 按 grantee 排 `AUTH_REVOKE` + withdraw 广告 + tombstone + 撤 grant。
  * `grant add|revoke|del|list`：`--self` 用 ed25519 principal；revoke = tombstone（`DenyReason::Revoked`）、del = 物理删除；变更经 outbox 广播 `AUTH_GRANT` / `AUTH_REVOKE`。
  * `node init [--force]`：生成 X25519 传输身份，NodeId = `SHA-256(静态公钥)` 前 16 字节（无注册中心，幂等，`--force` 轮换）；`node trust --provider <id> --pubkey <hex>`：显式 TOFU 信任提供方 ed25519 身份。
  * `provider serve --bind <addr:port> [--once]`：提供方常驻准入服务（每 Session 执行 grant 判定 + 审计 + 租约落盘）；启动时向 stdout 打印一条 `{"verdict":"PASS","command":"provider serve","provider":{"control":...}}`，此后持续服务。`--once` = **处理一条连接后退出**（不是"启动后立即退出"）；不带 `--once` 则一直常驻，需 Ctrl-C 结束。
  * `pair invite|join|list|remove --dir <dir>`：带外配对码 + ed25519 签名握手（`PAIR_PORT=18443`，超时 300s；纯文本输出）。

* **N2 状态存储位置**：`plan` / `use` / `session` / `resource` / `grant` / `node` 等进程内命令的状态写入**节点根目录**，由 `node_cli::node_dir()` 决定：`$NEXUS_CONFIG_DIR` → `$XDG_CONFIG_HOME/nexus` → `~/.config/nexus`（即这些命令**没有** `--dir` 参数；隔离/清理 N2 状态需设 `NEXUS_CONFIG_DIR`）。`pair` / `config` 自带 `--dir`，与之无关。

* **代码级校验**：E4 场景 `product.n2-plan-preview` (5) / `product.n2-use-loop` (6；fixture：`node init` → `resource publish` → `grant add --self`) / `product.n2-resource-list` (2) / `product.n2-resource-show` (4) / `product.n2-resource-publish` (3) / `product.n2-resource-revoke` (3) / `product.n2-grant-deny-audit` (4；FAIL / `AUTH_DENIED` / `NoSuchGrant` / `audit_written=true`) / `product.n2-provider-offline` (4，E5) / `product.pairing` (7) → PASS；实现 `apps/nexus/src/{plan_cli,use_cli,session_cli,resource_cli,grant_cli,provider_cli,node_cli,pair_cli}.rs`。

#### 4.9.4 N3 任务命令族（PRODUCT §17）

* **能力**：`nexus task submit --request <file>` 经 daemon `POST /localapi/v1/task`（要求 loopback/私有 socket + Bearer + Content-Type；请求文件 ≤ 1 MiB）；`task show|cancel|artifacts <id>`；`task logs <id> --stream <stdout|stderr> --offset <n>`。输出为版本化任务 envelope（`schema_version:1`，FAIL 带 `error.code` / `task_id` / `retryable` / `reason`）。

* **诚实边界**：daemon 端 `LocalTaskService` 依赖 `task-api.toml` 装配出的 provider，缺失时返回 `UNSUPPORTED_CAPABILITY`（本地 Task 服务默认未启用）；`nexus artifact get <id> --output <path>` 当前直接返回 `UNSUPPORTED_CAPABILITY`（下载适配器未装配），**从不创建或覆盖输出文件**。

* **代码级校验**：`apps/nexus/src/task_cli/tests.rs`（语法/边界/能力诚实性）；N3 场景见 `scenarios/product/n3-*.toml`。

#### 4.9.5 N1 装配、配置与平台控制

* **`nexus network up --config <toml>`**：仅 Linux，前台建 TUN → `ip` 配 addr/mtu/up/route → dial 静态 peers → 起 `VpiPump`（按 Enter 或 Ctrl-C 退出）。**退出码区分**：缺 `--config` / 配置解析失败 → exit 2；建 TUN 失败（缺 `CAP_NET_ADMIN`）或**无 peer 连接** → exit 1；成功装配 → exit 0。**`network status [--config <toml>]`**：诚实报告 `daemon:false` / `assembled_by_this_process:false`；带 `--config` 且可读时给出 `would_assemble`，文件不可读时置 `config_error` 但**仍 exit 0**。
* **`nexus config get|set|list --dir <config-dir> [file]`**：本地文件操作（已知文件 `daemon.toml` / `network.toml` / `proxy.yaml` / `dns.toml`）；`set` 从 stdin 读并**原子写**（临时文件 + rename），避免 daemon watcher 读到半截。
* **`nexus system-proxy status|set|clear|e2e`** / **`nexus autostart install|remove|status`**：Windows 平台控制（PRODUCT §13；固定端口 7898；`e2e` 自清理闭环）；非 Windows 返回结构化 `UNSUPPORTED`。
* **`nexus proxy bufferbloat-test --proxy <ip:port> [--duration <s>] [--threshold <ms>]`**：空载基准 vs 打满负载延迟对比，定位拥塞段（PRODUCT §11）。

* **代码级校验**：`apps/nexus/src/network.rs`、`main.rs`（`run_config` + bufferbloat 内联测试）；`scenarios/product/subnet_daemon.toml`、`scenarios/platform/windows_system_proxy.toml`。

### 4.10 工程方法论

#### 4.10.1 独立 Review 量化闭环



* **能力**：Fast Verify 通过后必须执行独立 Review，八个维度量化检查（契约一致性 / 边界覆盖 / API 面控制 / 依赖边界 / 错误处理 / 测试质量 / 复杂度控制 / 可观测性），Verdict = CHANGES\_REQUESTED 时迭代修正，最多 3 轮。

* **位置**：`.agents/skills/nexus-review/SKILL.md`

* **证据**：`.evidence/review-<id>/summary.json`（含 review\_round、dimension\_changes 等字段）

#### 4.10.2 动态知识库



* **能力**：持续沉淀踩坑、模式、教训，避免重复犯错。任务开始前检索相关历史经验。

* **位置**：`.agents/knowledge/`（entries/ 目录 + index.json）

* **条目格式**：YAML frontmatter + Markdown 正文（问题 / 原因 / 解决方案 / 教训）



***

## 5. 验证体系（如何复现校验）

### 5.1 验证链



```
nexus-harness check          # 4 门禁：whitespace/format/check/clippy

nexus-harness test affected  # 受影响测试

nexus-harness verify --fast  # 9 门禁（whitespace + policies/quality.toml [verification.fast] 声明的 8 项）

nexus-harness verify --full  # 23 门禁（fast 9 项 + [verification.full] 声明的 14 项）
```

### 5.2 23 门禁清单（verify --full）

whitespace、format、check、clippy、architecture-policy（fast 侧 delta）、dependency-governance（cargo-deny）、resource-type-neutrality、affected-tests、selected-properties、workspace-tests、integration（`tests/*.rs` 目标，含 nexusd serve e2e）、product-scenarios（product/engineering/platform 三目录）、regression、architecture-policy、dependency-governance、coverage-summary（cargo-llvm-cov）、selected-fuzz（`cargo +nightly fuzz check`）、selected-concurrency、performance-budgets、bench（perf_bench）、platform-checks、feature-matrix（50 members × 2 flag ≈ 100 检查）、portable-core（12 crate 编译 wasm32-wasip1）。

> 工具缺失的门禁记 **UNKNOWN**（不静默 PASS）：`cargo-deny` / `cargo-llvm-cov` / `cargo-fuzz` / `wasm32-wasip1` target 未安装时对应门禁为 UNKNOWN，需先补齐工具链（见 §2.1）。

### 5.3 场景求值机制

每个可机检场景的 `[when].command` 运行后，runner 对 stdout 的**单个 JSON 对象**按点路径求值 `[[expect]] field=... equals/one_of/non_empty`（支持嵌套与数组路径，如 `events.0`、`capabilities.packet_ingress`）。命令输出必须是纯 JSON 单对象。静态场景（无 command）求值为 UNKNOWN；**不被 loader 支持的期望类型（如&#x20;**`not_equals`**&#x20;/&#x20;**`greater_than`**&#x20;/&#x20;**`non_zero`**）与非法 TOML 会被静默丢弃或跳过**（见 §6.2）。

### 5.4 证据绑定与新鲜度

每次验证的证据绑定 `source_revision / working_tree_digest / dirty_state / configuration_digest / contract_hash / toolchain_version / target_triple` 等。任意影响结论的输入变化后，旧证据自动 STALE，必须重跑验证绑定新 revision。**Agent 只能声明 Candidate Completion，最终 PASS 由 Harness 产生。**



***

## 6. 已知限制、未实现功能与当前阻塞

### 6.1 限制表



| 项                                       | 状态          | 说明                                                                                                                                   |
| --------------------------------------- | ----------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| Workspace Projection 通道（NativeApi + MaterializedDirectory） | 已实现 | 三通道选择 + NativeApi WorkingSet 读写/commit + MaterializedDirectory 物化目录均已落地（E4 `platform.workspace-projection-channels` 16 期望 PASS，2026-09-20）；NativeMountDirectory 真实目录挂载仍为 API 声明待落地 |
| nexus CLI 观察命令                          | thin-client | 路由表 **8 条**（静态 5 + 动态 3；CLI 实际经 daemon 为 5 静态 + `workspace commit`，`plan`/`session` 先被 N2 模块接管）；默认 **unix socket 优先**（TCP `127.0.0.1:18080` 为回退/显式）；其余 10 命令本地显式 UNSUPPORTED；`--socket` 在 Windows 构建不可用 |
| nexus CLI 退出码                            | 三档          | `0` 已处理（含 daemon FAIL / 本地 UNSUPPORTED / `run`）；`1` N2 进程内 `verdict=FAIL`（NOT_FOUND / AUTH_DENIED / ALREADY_TERMINATED）；`2` 用法错误。**不要只按 0/非 0 判定，须读 `verdict`**（见 §4.9.2） |
| `nexus proxy [host\|relay] --addr`         | **待修缺陷**   | `--addr` 被全局选项剥离器在分发前吞掉，子命令收不到，实际监听默认端口（SOCKS5 1080 / host 8787）；手册与 CLI 自带帮助均承诺该 flag 生效。规避：只能用默认端口（见 §4.6.3） |
| `nexusd --help` / `nexusd serve --help`    | 帮助缺口       | `nexusd --help` 只列 `nexusd <config-folder>`，**不含 `serve`**（exit 2）；`nexusd serve --help` **不显示帮助、会直接启动 daemon** |
| `nexus-platform-host vpi-capabilities`     | 需 feature   | 仅在 `--features platform-windows` 构建下输出能力 JSON；默认构建只打印 stub 文本（见 §4.8.1） |
| `nexus subnet status` 的 verdict           | 含 `DOWN`    | 无隧道/状态文件缺失或损坏时返回 `verdict:"DOWN"`（并非 PASS/FAIL 二分）；脚本须容忍 `DOWN` / `STORE_ERROR` / `TUN_ERROR` |
| `nexus plan explain` 人读输出               | 双重输出       | 非 `--json` 时先打印字段投影，**随后又打印整段原始 JSON**，与其他命令"纯投影"不一致（不影响 `--json` 机器消费） |
| N2 状态目录                                 | 无 `--dir`   | `plan`/`use`/`session`/`resource`/`grant`/`node` 状态固定在 `$NEXUS_CONFIG_DIR` → `$XDG_CONFIG_HOME/nexus` → `~/.config/nexus`；隔离用 `NEXUS_CONFIG_DIR`（见 §4.9.3） |
| N3 本地 Task 服务                            | 默认未启用       | daemon `LocalTaskService` 需 `task-api.toml` 装配出的 provider；缺失时 `nexus task submit` 返回 `UNSUPPORTED_CAPABILITY`                        |
| N3 artifact 下载                            | 未装配         | `nexus artifact get` 直接返回 `UNSUPPORTED_CAPABILITY`，**从不创建或覆盖输出文件**                                                                     |
| nexusd serve `--socket`（Windows）        | UNSUPPORTED | named-pipe transport 未实现（std 无 named-pipe server，平台专有 I/O 应收敛到 nexus-platform-windows）；用 `--addr` TCP loopback                       |
| http204 probe 与 https                   | 不支持         | P0 仅明文 HTTP；`target.scheme == https` 直接记为 `unreachable`（不做 TLS）                                                                      |
| 传输层 crate                               | stub        | `nexus-platform-{linux,macos,android,ios}` 为骨架（`nexus-delivery`、`nexus-diagnostics`、`nexus-proto` 已于 2026-10-26 删除）                            |
| fuzz 门禁                                 | 需 nightly   | `cargo +nightly fuzz check`（stable 下 libfuzzer -Z 选项失败）                                                                              |
| NAT 打洞真实 STUN 集成测试                      | 待完善         | 单元测试 + example 已覆盖，真实 STUN 服务器集成测试待补充                                                                                                |
| 磁盘注意                                    | 本机          | 构建产物优先放 D:（C:/E: 高水位告警）                                                                                                              |

### 6.2 修复记录（2026-09-20：requirement-change + bugfix，HEAD 6ff5fb1 校验发现）

1. **product-scenarios 门禁 FAIL（9 个 `cli-*` 场景）→ 已修复（requirement-change）**：
   `cli-compute-jobs` / `cli-connectivity-candidates|links|probe` / `cli-diagnose` /
   `cli-dns-providers|resolve` / `cli-workspace-cache|conflicts` 的旧冻结期望要求
   `nexus <cmd> --json` 返回 PASS 数据；thin-client 化后这些命令无 LocalAPI 路由，CLI 按
   PRODUCT §9「禁止静默降级」本地合成 `UNSUPPORTED`（FAIL）。定性为 requirement-change：
   PRODUCT §9.1、`apps/nexus/MODULE.md`、`docs/CLI_FRONTEND_DESIGN.md` 同步为 thin-client
   模型，9 个场景期望改写为 `verdict=FAIL + error.code=UNSUPPORTED + error.command=<命令名>`
   （与 `localapi_client::command_name` 输出一致），Red Evidence 为
   `verify-e003ba88e02b`（20/21）。修复后 `verify --full` 21/21 全 PASS（见头部证据）。

2. `scenarios/product/nat_hole_punching.toml` **非法 TOML → 已修复（bugfix，语义不变）**：
   原 `[[expect]]` 使用 `not_equals = null`（`null` 非法 TOML 值）与 loader 不支持的
   `not_equals` / `greater_than` 类型，`load_file` 返回 None，场景从未进入门禁求值。
   已改为 loader 支持的 `non_empty = true`（mapping 非空 / RTT 非空），语义等价；
   场景现正常加载并 PASS。

3. **旧手册验证声明已 STALE → 已回写**：旧版头部声称 "基于 9f5dc8e / 21 门禁全 PASS
   （evidence verify-c909d8536eb6）"，而该证据绑定 `4539d3f4`（非 9f5dc8e），且 HEAD 已推进
   24 个提交。本次已按修复后 HEAD 重新校验并如实记录（见头部证据 ID）。

### 6.3 修复记录（2026-09-26：feature + bugfix，HEAD b6c2a41 校验发现）

1. **`nexus schedule` CLI 完全不可达 → 已修复（feature，Contract-First）**：PRODUCT §14 契约
   已冻结（`schedule at|every|list|cancel|tick` 五操作 + 三错误名），但旧实现 `nexus schedule`
   报 `unknown command`（exit 2）、E4 example 不存在（exit 101）。本次按契约先行落地：
   新增 `apps/nexus/src/schedule_cli.rs`（组合根：注册表持久化 `~/.nexus/schedule.json`，
   `--state` 可覆盖；snapshot/restore 崩溃重载，损坏快照显式 `STATE_ERROR` 不静默丢弃）、
   `apps/nexus/src/main.rs` 接线（`run_schedule`：at/every/list/cancel/tick；用法错误 exit 2，
   业务错误输出 `INVALID_SCHEDULE` / `SCHEDULE_NOT_FOUND` / `SUBMIT_FAILED` JSON exit 0）、
   E4 驱动 `apps/nexus/examples/schedule_cli_flow.rs`。新场景
   `product.schedule-cli`（10 期望）/ `product.schedule-cli-reachable`（1 期望）；
   Red Evidence `.evidence/red-schedcli-20260926/`（旧实现双 FAIL）。实现中发现并修正
   1 处错误契约期望（`list.after_cancel` 1→2，依据 PRODUCT §14.1「列出全部条目」）。

2. **`nexusd` 帮助未列已实现命令、用法错误 exit 不一致 → 已修复（bugfix）**：
   `nexusd --help`（兜底 usage）未列 subnet / system-proxy / autostart / proxy speedtest
   （实测均可用）；5 处用户可达的用法错误路径从 `ExitCode::FAILURE`（1）统一为 2
   （main 兜底未知命令、`subnet` 缺子命令 / `up` 缺 `--config` / 未知子命令、
   `host` 缺 resource），与 nexus CLI 的 exit 语义对齐（0=业务已处理，2=用法错误）；
   system-proxy / autostart 的未知子命令输出 JSON FAIL（exit 0，属业务结果）保持不变。

3. **手册基线落后 HEAD 一周 → 已回写**：旧手册声明基于 0a819ed（2026-09-20，
   evidence verify-25a825fea486），而 09-21 后落地功能（schedule CLI、subnet CLI、
   TUN 数据面、身份自动交换、订阅在线更新等示例面）均未收录，按手册自述规则旧证据
   已 STALE。本次已按当前 HEAD（b6c2a41）重新校验并如实记录：§3 功能清单 44→50，
   并补充「已实现但未纳入 E4 校验的示例面」清单（见下）。

**已实现但未纳入 E4 校验的示例面（E0–E3 级，example 可运行，待补 E4 场景）**：
`identity_auto_exchange`（身份自动交换）、`proxy_subscription_online_update`（订阅在线更新）、
`turn_relay_allocate`（TURN relay 分配）、`secure_store`（安全存储）、`subnet_daemon` /
`subnet_punch_cli`（daemon 托管 / 打洞 CLI 驱动）、`tun_dataplane` / `tun_proxy`
（TUN 数据面 example）。

**剩余限制（非阻塞）**：NAT 打洞为 example 级 E4（确定性 STUN mock + 打洞），真实 STUN 服务器
集成测试待完善；`cli-*` 场景的产品行为由“直接返回数据”收缩为“显式 UNSUPPORTED”，属
thin-client 架构下的契约收敛（进程内观察快照仍由 SDK `nexus::observability` 提供，CLI 仅 8 条命令有 daemon 路由）。

### 6.4 更新记录（2026-10-04：docs，按代码实际实现对齐）

本次为**纯文档更新（docs）**，不改变任何产品行为、场景期望或 PRODUCT 契约；依据
`apps/nexus/src/main.rs` 与各 `*_cli.rs`、`localapi_client.rs`、`nexusd/src/main.rs` 的实际分发逻辑：

1. **命令面补齐**：新增 §3.1 命令面总览、§4.9.3（N2：`plan/use/session/resource/grant/provider/node/pair`）、
   §4.9.4（N3：`task/artifact`）、§4.9.5（`network` / `config` / `system-proxy` / `autostart` / `proxy bufferbloat-test`）。
2. **命令归属修正**：观察命令此前误记为 `nexusd <verb>`，实际由 `nexus` CLI 提供；`nexusd` 现仅保留
   `<config-folder>` 与 `serve`。§3.2 表、§4.6、§4.7 已更正。
3. **默认传输修正**：LocalAPI 默认由固定 TCP `127.0.0.1:18080` 改为 **unix socket 优先**
   （`$XDG_RUNTIME_DIR/nexus-localapi.sock` 等；均不可用才回退 TCP）。
4. **门禁计数修正**：`verify --fast` 9 门禁、`verify --full` 23 门禁（此前记 8 / 21）；
   portable-core 12 crate（此前 11）；feature-matrix 50 members（≈100 检查）。
5. **诚实边界补录（§6.1）**：N3 本地 Task 服务默认未启用（需 `task-api.toml` 装配 provider）、
   `nexus artifact get` 未装配（返回 `UNSUPPORTED_CAPABILITY`，不写输出）。

> 本手册此前的验证证据声明已随 revision 前进而过期（见头部）；功能条目可用
> `nexus-harness verify --full` 在目标 revision 重新生成证据复现校验，Final PASS 只由 Harness 产生。

### 6.5 更新记录（2026-10-05：docs，手册可用性走查后的准确性修订）

本次同样为**纯文档更新（docs）**，不改变任何产品行为、场景期望或 PRODUCT 契约。修订来自一次
"只看本手册、逐条执行用户命令"的走查（Linux 沙箱，二进制 `target/debug/{nexus,nexusd,nexus-platform-host}`），
共执行约 72 条命令；命中差异后按"文档对齐实际行为、缺陷如实登记不曲解"原则修订：

1. **二进制名笔误**：§2.3 daemon 行此前写作 `nexus` / `nexus serve`，实为 **`nexusd` / `nexusd serve`**
   （`nexus serve` 实测 `unknown command`，exit 2）；§3.2 #41 用户入口列的 `nexus serve --addr` 同步修正为 `nexusd serve --addr`。
2. **退出码三档语义**：此前只写 `0 / 2`，漏了 **`1`（N2 进程内 `verdict=FAIL`）**；
   新增 §4.9.2 三档说明与 §6.1 汇总行。实测：`plan explain net` / `session watch <不存在>` /
   `use`（无授权）→ exit 1；daemon 路由与本地 `UNSUPPORTED` → exit 0。
3. **§4.7 观察表补必填参数**：`dns resolve <name>` / `connectivity probe <target>` /
   `session watch <id>` / `workspace heads <ws>` 等此前漏 `<...>`，逐字照抄会 `missing argument`（exit 2）。
4. **示例资源名**：§4.9.2 的 `nexus plan explain net` 中 `net` 不在内建 registry（`NOT_FOUND`，exit 1），
   改为 `dev-svc` / `internet-access`。
5. **默认传输澄清**：补记 `nexusd <config-folder>` 默认走 `daemon.toml` 的 TCP `127.0.0.1:18080`，
   与 `nexusd serve` 的 unix socket 默认不同；以及 `nexusd --help` 不含 `serve`、`nexusd serve --help` 会直接启动 daemon。
6. **诚实边界补录（§6.1）**：`nexus proxy [host|relay] --addr` 失效（全局选项剥离，待修 bugfix）、
   `vpi-capabilities` 需 `--features platform-windows`（否则 stub）、`subnet status` 会返回 `verdict:"DOWN"`、
   `plan explain` 人读双重输出、N2 状态目录无 `--dir`。
7. **`provider serve` 输出修正**：此前记"无 JSON"，实为启动打印一条 `PASS` JSON；并补 `--once` = 处理一条连接后退出。

> 走查中未重跑 `nexus-harness verify --full`，因此本手册**不新增、不复用任何完成证据**；
> 上述条目均可用对应 CLI 在目标 revision 直接复现。Final PASS 只由 Harness 产生。