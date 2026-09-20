# Nexus 用户手册

> 版本：基于 master
> `0a819ed`
> （2026-09-20 校验；工作区含未提交无关文件，dirty_state=true）
> 校验证据：
> `nexus-harness verify --full`
> →
> **21/21 门禁 PASS，0 FAIL，0 unknown**
> （evidence
> `verify-25a825fea486`
> ，绑定 0a819ed /dirty，contract_hash b7eb77d4…）
> 2026-09-20：NAT 场景 TOML 修复 + 9 个 `cli-*` 场景 thin-client 契约（requirement-change）
> 后 product-scenarios 转绿；随后 **Workspace Projection 通道落地**（NativeApi WorkingSet +
> MaterializedDirectory 物化目录，E4 场景 `platform.workspace-projection-channels` 16 期望）
> 已合并（0a819ed）。修复/落地记录见 §6.2。
> 本手册所列每个功能的可机检场景（E4/E3）在本次校验中均 PASS。

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
| Rust               | stable 1.95.0（`rustc` / `cargo`）   |
| 目标平台               | x86\_64-pc-windows-msvc（本手册校验环境）   |
| nightly（仅 fuzz 门禁） | `rustup toolchain install nightly` |

### 2.2 构建



```
cargo build --workspace
```

### 2.3 入口与运行模式



| 二进制                   | 角色                             | 命令示例                                          |
| --------------------- | ------------------------------ | --------------------------------------------- |
| `nexusd`              | 进程内组合根（run /host/relay /proxy） | `nexusd run internet-access --json`           |
| `nexusd serve`        | 常驻 daemon：HTTP LocalAPI 提供方    | `nexusd serve --addr 127.0.0.1:18080`         |
| `nexus`               | 控制面 CLI 前端（thin-client）        | `nexus status --json`                         |
| `nexus-platform-host` | 平台宿主（能力声明）                     | `nexus-platform-host vpi-capabilities --json` |

两种使用形态：



* **进程内闭环**：`nexusd run/host/relay/proxy` 直接装配 SDK 组合根执行，输出结构化 JSON（exit 0 = 请求已被处理，拒绝也是处理结果）。

* **常驻 daemon + 瘦客户端**：先启动 `nexusd serve --addr <ip:port>`（HTTP LocalAPI，默认监听 `127.0.0.1:0` 随机端口），再由 `nexus` CLI 经 `--addr`（默认 `127.0.0.1:18080`）查询。**CLI 的 7 个观察命令依赖 daemon**：daemon 未运行时返回结构化 `DAEMON_UNREACHABLE`（exit 0）；其余 10 个观察命令无 LocalAPI 路由，CLI 本地合成显式 `UNSUPPORTED`（PRODUCT §9 禁止静默降级，不回落进程内 observability）。

## 3. 功能总览

以下 44 项功能均已通过代码级校验（场景 / 集成测试 PASS + 驱动可运行）。括号内为场景 ID 与期望条数；历史遗留限制与本次修复记录见 §6。



| #  | 功能                                                      | 场景（E4/E3）                                                                                                                                                                                   | 用户入口                                                        |
| -- | ------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------- |
| 1  | InternetAccess 端到端访问                                    | `product.internet-access-flow` (11)                                                                                                                                                         | example / SDK                                               |
| 2  | 建连失败逆序回滚                                                | `product.connectivity-failure-rollback` (7)                                                                                                                                                 | example / SDK                                               |
| 3  | VPI/PacketCarrier 双 trait 解耦                            | `product.connectivity-carrier-split` (6)                                                                                                                                                    | example                                                     |
| 4  | SOCKS5 有状态握手                                            | `product.socks5-handshake` (6)                                                                                                                                                              | example                                                     |
| 5  | DNS 子系统与 Exit-DNS Binding                               | `product.dns-exit-binding` (8)                                                                                                                                                              | example                                                     |
| 6  | DNS 多 server 规则路由 + IP-CIDR                             | `product.dns-rule-server-selection` (5) / `product.dns-ipcidr-rule` (5)                                                                                                                     | example                                                     |
| 7  | Service 资源生命周期                                          | `product.resource-session-lifecycle` (9)                                                                                                                                                    | example / SDK                                               |
| 8  | daemon 运行远程服务闭环                                         | `product.daemon-run-remote-service-flow` (20)                                                                                                                                               | `nexusd run service --json`                                 |
| 9  | 远程 Service 访问                                           | `product.remote-service-access-flow` (20)                                                                                                                                                   | example / SDK                                               |
| 10 | 远程 Internet 出口                                          | `product.remote-internet-access-flow` (21)                                                                                                                                                  | example / SDK / `nexusd run internet-access`                |
| 11 | 远程建连失败回滚                                                | `product.remote-connectivity-failure-rollback` (12)                                                                                                                                         | example                                                     |
| 12 | 远程认证门控拒绝                                                | `product.remote-network-auth-rejected-rollback` (12)                                                                                                                                        | example                                                     |
| 13 | 远程计算作业                                                  | `product.remote-compute-job-flow` (22)                                                                                                                                                      | example / SDK / `nexusd run compute`                        |
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
| 25 | 未知资源结构化拒绝                                               | `product.daemon-rejects-unknown-resource` (4)                                                                                                                                               | `nexusd run <unknown> --json`                               |
| 26 | Observability 总览                                        | `product.observability-status` (4)                                                                                                                                                          | `nexusd status --json`                                      |
| 27 | Observability: plan explain                             | `product.observability-plan-explain` (4)                                                                                                                                                    | `nexusd plan explain --json`                                |
| 28 | Observability: session watch                            | `product.observability-session-watch` (4)                                                                                                                                                   | `nexusd session watch --json`                               |
| 29 | Observability: dns cache                                | `product.observability-dns-cache` (3)                                                                                                                                                       | `nexusd dns cache --json`                                   |
| 30 | Observability: 完整命令集                                    | `observability-{dns-resolve,dns-providers,connectivity-candidates,connectivity-probe,connectivity-links,workspace-heads,workspace-conflicts,workspace-cache,compute-jobs,diagnose}`（见 §4.7） | `nexusd <verb> --json`                                      |
| 31 | 未就绪命令显式 UNSUPPORTED                                     | `product.observability-unsupported` (3)                                                                                                                                                     | `nexusd connectivity trace --json`                          |
| 32 | Windows VPI 能力声明（wintun）                                | `platform.virtual-packet-interface` (10)                                                                                                                                                    | `nexus-platform-host vpi-capabilities --json`               |
| 33 | 虚拟子网隧道（Virtual Subnet）                                  | `product.virtual-subnet-tunnel` (7)                                                                                                                                                         | example / SDK                                               |
| 34 | 三节点虚拟子网静态路由（mesh）                                       | `product.virtual-subnet-mesh-3node` (9)                                                                                                                                                     | harness run / SDK                                           |
| 35 | NAT 打洞（STUN + UDP 打洞）                                   | `product.nat-hole-punching` (6)                                                                                                                                                       | example / SDK                                               |
| 36 | Proxy 节点测速（tcp /http204）                                | `proxy-speedtest` (8) / `proxy-speedtest-loopback` (6) / `proxy-speedtest-http204` (8) / `proxy-speedtest-http204-bad-status` (5) / `proxy-speedtest-http204-loopback` (6)                  | `nexusd proxy speedtest --json` / example                   |
| 37 | Proxy 规则路由内核                                            | `proxy-*` 场景族（见 §4.1.10）                                                                                                                                                                    | `nexusd proxy --addr <ip:port> [--config <path>]` / example |
| 38 | 出站适配器（SS / VMess / Trojan）                              | `proxy-*-adapter` 等 8 场景（见 §4.1.10）                                                                                                                                                         | example                                                     |
| 39 | 规则数据注入（geoip.nex/geosite.nex/rule-providers / Clash 订阅） | `geoip-nex-roundtrip` (8) / `geosite-nex-roundtrip` (8) / `proxy-rule-provider-fetch` (11) / `proxy-clash-subscription-parse` (9)                                                           | example / 配置                                                |
| 40 | Workspace Projection 访问通道                               | `platform.workspace-projection-fallback` (4) / `platform.workspace-projection-channels` (16)                                                                                                | example / SDK                                               |
| 41 | nexusd serve 常驻 daemon（HTTP LocalAPI）                   | 集成测试 E3（`apps/nexusd/tests/serve_localapi_e2e.rs`，4 用例）                                                                                                                                     | `nexusd serve --addr <ip:port>`                             |
| 42 | nexus CLI thin-client + run                             | `product.cli-run-command` (5)                                                                                                                                                               | `nexus run service --json` / `nexus status --json`          |
| 43 | 真实节点数据面（host /relay/ SOCKS5）                            | `daemon-real-host-flow` (9) / `daemon-real-relay-flow` (9) / `daemon-real-socks-proxy-flow` (11) / `daemon-real-host-auth-denied` (5)                                                       | \`nexusd host                                               |
| 44 | 独立 Review + 动态知识库                                       | （工程方法论，非用户功能）                                                                                                                                                                               | `.agents/skills/` + `.agents/knowledge/`                    |



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


  * example：`cargo run --quiet -p nexus --example nat_hole_punching -- --json`（可运行，输出 PASS JSON）

  * SDK：`nexus_connectivity::nat::StunClient` / `nexus_connectivity::nat::HolePuncher`

* **代码级校验**：场景 `product.nat-hole-punching`（6 期望：verdict PASS、local/public mapping 非空、NAT 类型 RestrictedCone、打洞成功、RTT 非空）→ PASS（2026-09-20 修复非法 TOML 后进入门禁求值）；驱动 example 可运行；单元测试 7 项。真实 STUN 服务器集成测试待完善。

#### 4.1.9 Proxy 节点测速（tcp /http204，§11.10）



* **能力**：对候选出站批量测速并按 RTT 升序输出。两种探测：


  * `tcp`（默认）：仅建连级延迟（connect\_timeout）。

  * `http204`：TCP 建连后发送单行明文 `GET {path} HTTP/1.1`，等待响应首行 `204 No Content`，计时覆盖建连 + 请求发送 + 响应首字返回；非 204 响应 / 读取超时 / `https` target 记为 `unreachable`（P0 不做 TLS）。

  * 指标：`latency_ms`（未测得 null）、`status`（`ok`/`timeout`/`unreachable`/`dns_failed`）、`probe_kind`、`target`。默认目标 `http://www.gstatic.com/generate_204`，超时上限 5s（可配）。单节点失败非致命，不中断批量。

* **用户用法**：


  * daemon：`nexusd proxy speedtest --json`（loopback 自检，tcp）

  * example：`cargo run --quiet -p nexus --example proxy_speedtest -- --json`（tcp 离线 mock）、`proxy_speedtest_loopback`（tcp 真 TCP）、`proxy_speedtest_http204`（http204 离线 mock）、`proxy_speedtest_http204_loopback`（http204 真 HTTP/204 服务）、`proxy_speedtest_http204_bad_status`（500 → unreachable）

  * SDK：`nexus::proxy_speedtest_with(probe, candidates, timeout, target_label, probe_kind)`（`apps/nexus/src/lib.rs:4206`）、`Http204LatencyProbe`（`apps/nexus/src/lib.rs:4137`）

  * 配置：YAML `proxy.speedtest: {target, timeout_ms, probe_kind}`（`tcp`|`http204`，其他 → `CONFIG_INVALID`，nexus-proxy-config 已解析校验）

* **代码级校验**：场景 `proxy-speedtest` (8) / `proxy-speedtest-loopback` (6) / `proxy-speedtest-http204` (8) / `proxy-speedtest-http204-bad-status` (5) / `proxy-speedtest-http204-loopback` (6) → 全部 PASS

#### 4.1.10 Proxy 规则路由内核与出站适配器（§11）



* **能力**：规则路由代理内核 ——Clash 风格配置解析（订阅节点解析）、规则匹配（DOMAIN / GEOSITE / GEOIP / IP-CIDR / MATCH / 端口）、规则集与 rule-providers（含在线 URL 拉取）、分组策略（selector /url-test/load-balance /relay）。真实数据面：`nexusd proxy --addr <ip:port> [--config <path>]` 提供真实 SOCKS5 监听，逐会话完成握手 → 规则路由 → Session → 真实出站 → 双向字节中继。

* **出站适配器**：Shadowsocks（真实 TCP 会话）、VMess（线格式）、Trojan（TLS + 认证 + Standard/Singbox 头格式 + SNI/ALPN/skip-verify 参数）。适配器经 `OutboundAdapter` trait 注入（MODULE.md 冻结契约）。

* **用户用法**：


  * 数据面：`nexusd proxy --addr 127.0.0.1:1080 --config <path>`

  * example：`proxy_default_match` / `proxy_rule_set` / `proxy_geoip_rule` / `proxy_geosite_rule` / `proxy_ipcidr_rule` / `proxy_selector_group` / `proxy_urltest_group` / `proxy_loadbalance_group` / `proxy_relay_group` / `proxy_socks5_domain_rule` / `proxy_rule_invalid` / `proxy_shadowsocks_adapter` / `proxy_shadowsocks_real_tcp` / `proxy_vmess_adapter` / `proxy_trojan_adapter`（含 `--scenario rejected` 反例）/ `proxy_clash_subscription_parse` / `proxy_rule_provider_fetch`

* **代码级校验**：`proxy-*` 场景族全部 PASS（default-match 6 /rule-set 8 /geoip-rule 6 /geosite-rule 5 /ipcidr-rule-match 6 /selector 6 /urltest 5 /loadbalance 6 /relay-group 5 /socks5-domain-rule-forward 6 /rule-invalid 4 /shadowsocks-adapter 6 /shadowsocks-real-tcp 5 /vmess-adapter 6 /trojan-adapter 6 /trojan-auth-rejected 6 /trojan-header-format 4 /trojan-node-config 7 /trojan-real-tls-params 6 /clash-subscription-parse 9 /rule-provider-fetch 11）

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

* **用户用法**：example `cargo run --quiet -p nexus --example remote_internet_access_flow -- --json`；SDK `nexus::remote_internet_access_flow()`（`apps/nexus/src/lib.rs:949`）；`nexusd run internet-access --json`

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

* **用户用法**：example `cargo run --quiet -p nexus --example remote_compute_job_flow -- --json`；SDK `nexus::remote_compute_job_flow()`（`apps/nexus/src/lib.rs:1289`）；`nexusd run compute --json`

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



* **能力**：`nexusd run <unknown> --json` 返回结构化拒绝 `UNKNOWN_RESOURCE`（exit 0 = 请求已被处理，拒绝也是处理结果），禁止静默忽略。

* **用户用法**：`cargo run --quiet -p nexusd -- run frobnicate --json`

* **代码级校验**：场景 `product.daemon-rejects-unknown-resource`（4 期望）→ PASS

#### 4.6.2 nexusd serve：常驻 daemon（HTTP LocalAPI）



* **能力**：`nexusd serve` 常驻监听，提供最小 HTTP LocalAPI；`nexus` CLI 经 TCP 裸 GET 查询。输出 `READY` JSON 报告实际监听地址。

* **用户用法**：


  * `nexusd serve --addr <ip:port>`（TCP loopback；默认 `127.0.0.1:0` 随机端口）

  * `nexusd serve --socket <path>`（Unix domain socket；**Windows 为 named pipe，当前 UNSUPPORTED**，报错提示改用 `--addr` TCP loopback）

  * 路由（GET）：`/localapi/v0/{status, dns/status, dns/cache, session/watch, plan/explain, connectivity/status, platform/capabilities}`

  * 配合 CLI：`nexusd serve --addr 127.0.0.1:18080`（CLI 默认目标）→ `nexus status --json`

* **代码级校验**：集成测试 E3 `apps/nexusd/tests/serve_localapi_e2e.rs`（4 用例：status /dns cache /plan explain 路由 200 + 未知路由 404 `NOT_FOUND`；子进程 READY 轮询 + Drop guard 回收）；integration 门禁 PASS

#### 4.6.3 真实节点数据面（host /relay/ SOCKS5 proxy）



* **能力**：真实网络入口 ——`nexusd host <resource> --addr <ip:port> [--token <t>]` 提供方持续监听（每连接 AUTH 门控 + 业务闭环）；`nexusd relay --addr <ip:port>` DIAL + 双向字节中继；`nexusd proxy --addr <ip:port> [--config <path>]` 真实 SOCKS5 数据面（握手 → 规则路由 → Session → 真实出站 → 字节中继）。

* **用户用法**：`nexusd host service --addr 127.0.0.1:8787 --token <t>`；`nexusd relay --addr 127.0.0.1:8788`；`nexusd proxy --addr 127.0.0.1:1080`

* **代码级校验**：`product.daemon-real-host-flow` (9) / `daemon-real-host-auth-denied` (5) / `daemon-real-relay-flow` (9) / `daemon-real-socks-proxy-flow` (11) → 全部 PASS；错误 token 透传 `AUTH_DENIED`，host 为持续服务循环

### 4.7 Observability（§9）

全部通过 `nexusd <verb> ... --json` 输出结构化 JSON；未就绪领域命令显式 `UNSUPPORTED`（exit 0），禁止静默降级。



| 命令                                      | 能力                                                         | 场景                                                  |
| --------------------------------------- | ---------------------------------------------------------- | --------------------------------------------------- |
| `nexusd status --json`                  | 总览：DNS 快照 + 建连链路 + 规划决策 + 平台能力                             | `product.observability-status` (4)                  |
| `nexusd dns status --json`              | DNS 运行时状态（缓存 / 调用计数 / Exit-DNS Binding）                    | 由 `dns-exit-binding` + status 覆盖                    |
| `nexusd dns cache --json`               | DNS 正 / 负缓存快照                                              | `product.observability-dns-cache` (3)               |
| `nexusd dns resolve --json`             | 解析 [example.com](https://example.com) 输出地址 / TTL / Binding | `product.observability-dns-resolve` (6)             |
| `nexusd dns providers --json`           | DNS Provider 列表                                            | `product.observability-dns-providers` (5)           |
| `nexusd session watch --json`           | Session 双轨状态（phase/outcome/committed）                      | `product.observability-session-watch` (4)           |
| `nexusd connectivity status --json`     | 建连状态                                                       | 由 `status` 覆盖                                       |
| `nexusd connectivity candidates --json` | 候选 Provider                                                | `product.observability-connectivity-candidates` (5) |
| `nexusd connectivity probe --json`      | 目标可达性探测                                                    | `product.observability-connectivity-probe` (6)      |
| `nexusd connectivity links --json`      | 活动链路                                                       | `product.observability-connectivity-links` (6)      |
| `nexusd plan explain --json`            | Plan + DecisionTrace 结构化拒绝原因                               | `product.observability-plan-explain` (4)            |
| `nexusd platform capabilities --json`   | 平台能力清单                                                     | 由 `status` + `platform.virtual-packet-interface` 覆盖 |
| `nexusd workspace heads --json`         | Head Set 快照（离线分叉可观察）                                       | `product.observability-workspace-heads` (6)         |
| `nexusd workspace conflicts --json`     | 未合并冲突                                                      | `product.observability-workspace-conflicts` (6)     |
| `nexusd workspace cache --json`         | 缓存状态 / 保护保留                                                | `product.observability-workspace-cache` (6)         |
| `nexusd compute jobs --json`            | 作业阶段 / 结果快照                                                | `product.observability-compute-jobs` (7)            |
| `nexusd diagnose --json`                | 统一诊断                                                       | `product.observability-diagnose` (5)                |
| `nexusd connectivity trace --json`      | 领域未就绪 → 显式 UNSUPPORTED                                     | `product.observability-unsupported` (3)             |

SDK 层：`nexus::observability::{status, dns_status, dns_cache, dns_resolve, dns_providers, session_watch, connectivity_status, connectivity_candidates, connectivity_probe, connectivity_links, plan_explain, platform_capabilities, workspace_heads, workspace_conflicts, workspace_cache, compute_jobs, diagnose}`（`apps/nexus/src/observability.rs`）。

**进程级状态单例**：`nexusd` 的 DNS 运行时为进程级单例（`OnceLock<RwLock<DnsRuntime>>`）。同一进程内多次 `dns status` / `dns cache` 共享同一缓存与调用计数（第二次同名解析 `from_cache=true`）；`nexusd serve` 常驻时，每个 LocalAPI 请求看到同一份累积状态，而非全新快照。

**CLI thin-client 路由**：`nexus` 仅 7 个命令有 daemon 路由（status /dns status /dns cache /session watch /plan explain /connectivity status /platform capabilities）；其余 10 个命令本地合成显式 `UNSUPPORTED`（9 个 `cli-*` 场景冻结该契约，2026-09-20 requirement-change）；daemon 未启动 → `DAEMON_UNREACHABLE`（均 exit 0）。

### 4.8 平台

#### 4.8.1 Windows VPI 能力声明（wintun）



* **能力**：平台宿主声明 Windows Virtual Packet Interface 能力：wintun 窄 FFI 后端、portable consumer（nexus-ingress）、Packet Semantics（MTU 1420、packet ingress/egress、wintun native API）。

* **用户用法**：`cargo run --quiet -p nexus-platform-host --features platform-windows -- vpi-capabilities --json`

* **代码级校验**：场景 `platform.virtual-packet-interface`（10 期望）→ PASS；实现 `apps/nexus-platform-host`（`vpi-capabilities` 命令）

### 4.9 CLI 前端（thin-client）

#### 4.9.1 nexus run：远程资源访问



* **能力**：`nexus run <resource>` 走进程内 SDK 路径执行远程资源访问（LocalAPI 无对应路由），输出 `run.resource / session_id / connectivity.status / outcome`。

* **用户用法**：`cargo run --quiet -p nexus -- run service --json`（支持 `service` / `compute` / `internet-access`；未知资源 → 结构化 `Unsupported`）

* **代码级校验**：场景 `product.cli-run-command`（5 期望：verdict=PASS、run.resource=service、session\_id 非空、connectivity=Connected、outcome=Completed）→ PASS

#### 4.9.2 nexus 观察命令（thin-client 查询）



* **能力**：17 个观察命令的参数解析（`--json` 任意位置、`--addr <ip:port>` 默认 `127.0.0.1:18080`）；7 个有 daemon 路由的命令向 `nexusd serve` 发裸 HTTP GET 并原样渲染 daemon JSON（`--json` 机器可读 / 默认人读投影）；无路由命令本地合成 `UNSUPPORTED`；连接失败输出 `DAEMON_UNREACHABLE` FAIL JSON。exit 语义：0 = 业务结果（含 FAIL），2 = 用法 / 解析错误。

* **用户用法**：先 `nexusd serve --addr 127.0.0.1:18080`，再 `nexus status --json` / `nexus plan explain net --json` / `nexus dns cache --json`

* **代码级校验**：CLI 单元测试（解析 / 剥离 /exit 语义）+ 集成测试 `apps/nexusd/tests/serve_localapi_e2e.rs`；9 个 `cli-*` 场景（E4）冻结 thin-client 契约：无路由命令必须本地合成 `verdict=FAIL, error.code=UNSUPPORTED, error.command=<命令名>`（2026-09-20 requirement-change，见 §6.2 修复记录）

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

nexus-harness verify --fast  # 8 门禁

nexus-harness verify --full  # 21 门禁（预备交付前）
```

### 5.2 21 门禁清单（verify --full）

whitespace、format、check、clippy、architecture-policy、dependency-governance（cargo-deny）、affected-tests、selected-properties、workspace-tests、integration（4 targets，含 nexusd serve e2e）、product-scenarios（product/engineering/platform 三目录）、regression、architecture-policy、dependency-governance、coverage-summary、selected-fuzz、selected-concurrency、performance-budgets、platform-checks、feature-matrix（72 member×feature 检查）、portable-core（11 crate 编译 wasm32-wasip1）。

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
| nexus CLI 观察命令                          | thin-client | 7 命令需先启动 `nexusd serve`（默认目标 127.0.0.1:18080）；其余 10 命令显式 UNSUPPORTED；`--socket` CLI 端未落地                                             |
| nexusd serve `--socket`（Windows）        | UNSUPPORTED | named-pipe transport 未实现（std 无 named-pipe server，平台专有 I/O 应收敛到 nexus-platform-windows）；用 `--addr` TCP loopback                       |
| http204 probe 与 https                   | 不支持         | P0 仅明文 HTTP；`target.scheme == https` 直接记为 `unreachable`（不做 TLS）                                                                      |
| 传输层 crate                               | stub        | `nexus-delivery`、`nexus-diagnostics`、`nexus-proto`、`nexus-platform-{linux,macos,android,ios}` 为 12–16 行骨架                            |
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

**剩余限制（非阻塞）**：NAT 打洞为 example 级 E4（确定性 STUN mock + 打洞），真实 STUN 服务器
集成测试待完善；`cli-*` 场景的产品行为由“直接返回数据”收缩为“显式 UNSUPPORTED”，属
thin-client 架构下的契约收敛（进程内数据面仍由 `nexusd <verb> --json` 提供）。