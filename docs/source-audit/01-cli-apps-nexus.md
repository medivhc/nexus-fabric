# Shard A：apps/nexus（CLI 片区）源码逆向状态文档

> 本文仅依据仓库 e6ccf8b 的源代码与机器配置（.rs/Cargo.toml/*.toml）撰写，未采信任何叙述性文档；结论行号均可复核。

## 1. 片区范围与行数总表

- 仓库：`/home/user/Doubao/chats/38445294397368066/nexus-fabric`，HEAD e6ccf8b，工作区干净。
- 本片区 = workspace 成员 `apps/nexus`（一个巨型单体 crate，2026 edition，`#![forbid(unsafe_code)]`）。
- 实测规模：`find src tests examples -name '*.rs' | xargs wc -l` = **49,184 行**（含 tests/ 集成测试与 examples/）。
- 测试属性实测：`rg "#\[test\]|#\[tokio::test\]" src tests | wc -l` = **277 个**（其中 src 内单元测试约 220 个，tests/ 集成测试约 57 个）。
- 占位宏实测：`unimplemented!`/`todo!` = **0 处**；`unreachable!` = 3 处（`src/task_cli.rs:408`、`src/n2_admission.rs:159`、`src/lib.rs:4615`，均为分支不可达兜底）。

### 1.1 关键文件行数（wc -l 实测）

| 文件 | 行数 | 文件 | 行数 |
|---|---|---|---|
| src/lib.rs | 11,841 | src/main.rs | 1,908 |
| src/n2_store.rs | 1,921 | src/n2_admission.rs | 1,687 |
| src/mesh.rs | 1,094 | src/observability.rs | 1,020 |
| src/resource_cli.rs | 1,114 | src/use_cli.rs | 865 |
| src/localapi_client.rs | 780 | src/subnet_cli.rs | 807 |
| src/grant_cli.rs | 698 | src/pair_cli.rs | 632 |
| src/n2_directory.rs | 630 | src/network.rs | 509 |
| src/session_cli.rs | 506 | src/plan_cli.rs | 487 |
| src/task_localapi.rs | 383 | src/schedule_cli.rs | 362 |
| src/artifact_download.rs | 370 | src/node_cli.rs | 326 |
| src/task_cli.rs | 413 | src/control_service.rs | 278 |
| src/subscription_updater.rs | 290 | src/strategy_watcher.rs | 535 |
| src/provider_fetcher.rs | 199 | src/geoip_sources.rs | 192 |
| src/task_authorization.rs | 172 | src/task_provider_grant.rs | 175 |
| src/n3_acceptance.rs | 137 | src/n2_identity.rs | 229 |
| src/provider_cli.rs | 67 | | |

## 2. 实际职责（从代码推断）

`apps/nexus` 不是单一"CLI 可执行文件"，而是**一个既出二进制、又被 daemon（apps/nexusd）复用的组合根 crate**。从代码可证的三层职责：

1. **瘦客户端命令面**（`main.rs`）：解析 argv → 分派到各 `*_cli` 模块；观察类命令优先经 `localapi_client.rs` 把裸 HTTP GET 转发给 `nexusd serve` 的 LocalAPI。
2. **N2 资源访问本地闭环**（`use_cli.rs`/`grant_cli.rs`/`resource_cli.rs`/`n2_*.rs`）：在 CLI 进程内直接读写 `~/.config/nexus/` 下的本地状态（会话、授权表、广告、目录、准入租约），并通过独立 TCP 端口与对端做 ed25519 双向握手。
3. **daemon 进程内复用的快照/装配函数**（`observability.rs`/`subnet_cli.rs`/`mesh.rs`/`network.rs`/`strategy_watcher.rs`/`subscription_updater.rs`）：这些函数被 `nexusd serve` 按 HTTP 请求调用，apps/nexus 自身进程内大多不可达。

### 2.1 main.rs（1,908 行，已分段全部读完）— 真实命令面

文件头注释（`main.rs:1-15`）自称瘦客户端模式。`run()`（`main.rs:197-356`）的实际分发主干：

| 命令 | 入口（行号） | 实现形态 |
|---|---|---|
| `task-provider grant add\|revoke\|list` | `task_provider_grant::run`（`main.rs:212`） | 本地文件操作，仅 Linux |
| `task submit\|show\|cancel\|logs\|artifacts` / `artifact get` | `task_cli::run`（`main.rs:231`） | 瘦客户端 → daemon HTTP |
| `run <res> -- <cmd>` | `run_with_command_rejected`（`main.rs:248,381-398`） | **硬编码拒绝** UNSUPPORTED run-with-command |
| `run <res>`（无 `--`） | `ControlServiceImpl::snapshot`（`main.rs:320-333`） | 进程内纵切 `lib.rs::run_resource` |
| `subnet up\|status\|leave\|punch` | `run_subnet`（`main.rs:253,440-610`） | 本地装配 + 状态文件 |
| `schedule at\|every\|list\|cancel\|tick` | `run_schedule`（`main.rs:257,713-812`） | 注册表文件 `~/.nexus/schedule.json` |
| `proxy run\|host\|relay\|speedtest\|bufferbloat-test` | `run_proxy`（`main.rs:261,1350-1448`） | 真实 SOCKS5 数据面 |
| `system-proxy status\|set\|clear\|e2e` | `dispatch_system_proxy`（`main.rs:265,1453-1557`） | **仅 Windows**；非 Windows 硬编码 UNSUPPORTED（`main.rs:1561-1567`） |
| `autostart install\|remove\|status` | `dispatch_autostart`（`main.rs:269,1570-1626`） | **仅 Windows**；非 Windows 硬编码 UNSUPPORTED（`main.rs:1629-1635`） |
| `config get\|set\|list` | `run_config`（`main.rs:273,1232-1345`） | 本地 TOML 文件 |
| `pair invite\|join\|list\|remove` | `pair_cli::run_pair`（`main.rs:277`） | 真实 TCP 握手 |
| `node init\|trust` | `node_cli::run_node`（`main.rs:281`） | 本地身份密钥 |
| `plan [explain]` | `plan_cli::run_plan`（`main.rs:285`） | 本地只读预览 |
| `use <name>` | `use_cli::run_use`（`main.rs:289`） | N2 四步闭环 |
| `session list\|watch\|close\|seed` | `session_cli::run_session`（`main.rs:294`） | 进程内读 N2 存储 |
| `resource list\|show\|publish\|revoke\|export\|import` | `resource_cli::run_resource`（`main.rs:298`） | 本地广告/授权表 |
| `grant add\|revoke\|del\|list` | `grant_cli::run_grant`（`main.rs:302`） | 本地授权表 |
| `provider serve --bind [--once]` | `provider_cli::run_provider`（`main.rs:306`） | n2_admission 长驻 TCP |
| `status / dns * / connectivity * / workspace * / compute jobs / diagnose / platform capabilities` | `parse_command`（`main.rs:310,830-918`）→ `route_for`/`route_for_dynamic` → `query_daemon`（`main.rs:345-355`） | daemon HTTP 转发；无路由 → 本地合成 UNSUPPORTED |
| `network up --config / network status` | `nexus::network::dispatch`（`main.rs:336-341`） | **仅 Linux**；非 Linux 硬编码 Err（`network.rs:303-308`） |

main.rs 自带测试 24 个（`main.rs:1636` 起）：parse_command 解析、全局 flag 剥离、exit code、schedule 参数校验、bufferbloat loopback 集成（`main.rs:1872` 起）。

### 2.2 与 daemon（apps/nexusd）及 LocalAPI 的真实交互通道（以代码为准）

代码里存在**两条独立通道**，均非"进程内 SDK 调用 daemon"：

1. **观察命令通道（GET）**：`localapi_client.rs:399 http_get` —— 裸 HTTP/1.1 GET over unix socket（默认 `$XDG_RUNTIME_DIR/nexus-localapi.sock`，`localapi_client.rs:54`）或 TCP `127.0.0.1:18080`（`localapi_client.rs:27`，`--addr` 显式）。`Authorization: Bearer <token>`，token 文件 `~/.config/nexus/localapi.token`（0600，32 随机字节 hex，`localapi_client.rs:160-211`）。
2. **N3 任务通道（POST）**：`task_localapi.rs:35 execute` —— `POST /localapi/v1/task` over TCP loopback（强校验非 loopback 拒，`task_localapi.rs:52-58`）或 unix socket（socket2 非阻塞 connect，`task_localapi.rs:79-87`）。严格 HTTP/1.1 解析（16KiB header 上限、Content-Length 白名单 2MiB、拒 Transfer-Encoding，`task_localapi.rs:200-292`），响应校验状态码白名单 200/400/401/405/413（`task_localapi.rs:248`）+ 操作相关性（task_id/digest/page offset，`task_localapi.rs:315-380`）。

**无路由命令本地合成 UNSUPPORTED**：`connectivity candidates/probe/links`、`dns resolve/providers`、`workspace heads/conflicts/cache`、`compute jobs`、`diagnose`（`localapi_client.rs:254-263`）。这与 `main.rs:6-13` 注释自称"7 个观察命令有 daemon 路由"基本一致，但**漏了 `workspace commit` 动态路由**（`localapi_client.rs:305-308`）。

### 2.3 状态存储实际持久化什么（n2_store.rs，1,921 行）

状态根 = `node_cli::node_dir()`（`node_cli.rs:32`）：`$NEXUS_CONFIG_DIR` → `$XDG_CONFIG_HOME/nexus` → `~/.config/nexus`。其下 `n2/` 目录用 FileKvStore（tmp + fsync + rename 原子写）持久化：

- `n2/session/<id>`：会话记录（含完整 `PlanSnapshot` JSON，D3，`n2_store.rs:612,657-659`）
- `n2/grant/<ws>/<name>/<principal>`：授权表（tombstone revoke，终态 CAS，`n2_store.rs:575-604`）
- `n2/ad/<provider>/<resource>`：资源广告
- `n2/names`/`n2/revoked_names`：名字表/tombstone
- `n2/trusted_peers`：TrustStore（TOFU）
- `n2/lease/<session>`：准入租约（TTL 3600s）
- `n2/outbox/<seq:020>`：控制帧出站队列（AUTH_REVOKE/AUTH_GRANT）
- `n2/auth-identity`：ed25519 授权身份密钥对（0600）

**outbox 的真实消费方**：`n2_admission.rs:259-308`（serve_forever 的 `handle_admission` 内 pending_announcements 按 principal 过滤 → write_response_flushing 写成功后 outbox_delete，at-least-once）。`n2_store.rs:14-15` 注释自称"P0-5 真跨机时实际发送"——该出站泵在 `n2_admission.rs` 已真实装配，注释描述与代码一致。

### 2.4 n2_* / n3_* 系列实际能力

- **n2_admission.rs（1,687 行）= implemented**：真实跨机准入协议。独立 TCP 流（`n2-admission-v1`，u32 BE 长度前缀 + JSON，不复用 D8 控制帧）。B 侧 `serve_forever`（`:696`）：并发 accept（上限 64，`:66`）、10s 超时。v2 双向握手（`:351`）：B→A hello(challenge_b+pubkey_b) → A 签 → B 验签派生 principal（D6 不接受自称）→ B 本地 grant 判定 → B 签 challenge_a 随 verdict 返回 → A 验签 + TrustStore（Trusted/IdentityChanged 拒/UnknownFirstSeen 按 TOFU）。14 个测试全部 loopback 真实 TCP。
- **n2_directory.rs（630 行）= implemented**：registry-backed 目录，静态种子 3 资源（`dev-svc`/`internet-access`/`restricted-svc`）叠加持久化广告，tombstone 过滤；OFFLINE_MARK_TTL=300s（`:46`）。7 个测试。
- **n2_identity.rs（229 行）= implemented**：ed25519 密钥对生命周期，存 `n2/auth-identity`，双重检查锁。3 个测试（含 16 线程冷启动）。
- **n3_acceptance.rs（137 行）= implemented 但纯适配层**：文件头自称（`:1-2`）"No CLI/API route, transport or executor is installed." 实际 = SHA-256（ring）、TaskId 生成、严格 JSON 解析（拒重复键/浮点数/指数）、DTO 解码。**"n3_acceptance 实际验收什么"：什么都不验收**——它只是组合根的 JSON/codec 适配函数集合，没有验收流程。

### 2.5 lib.rs（11,841 行，已分段全部读完）— 真实内部结构

**性质判定**：11,841 行中约 10,000 行是 **40+ 个 `pub fn` 产品场景纵切驱动**，被 `main.rs` 的 `proxy_run_resource`（`main.rs:1098-1117`）按资源名分派调用。分两类：

1. **E4 内存闭环纵切**（纯内存、无真实建连）：`internet_access_flow`（`:133`）、`service_session_lifecycle`（`:241`）、`connectivity_failure_rollback`（`:378`）、`presence`/`auto_discovery`/`relay_fallback`/`turn_relay`/`link_encryption`/`identity_auto_exchange`/`cross_subnet`/`tun_proxy_flow`/`routing_*` 等约 30 个。
2. **E5 loopback 真实 TCP 纵切**：`remote_service_access_flow`（`:667`）、`remote_connectivity_failure_rollback`（`:833`）、`remote_internet_access_flow`（`:992`）、`remote_network_auth_rejected_rollback`（`:1171`）、`remote_compute_job_flow`（`:1339`）、`remote_workspace_commit_flow`（`:1705`）、`remote_presence_*`（`:2152-2378`）、`remote_nat_relay_fallback_flow`（`:2385`）、`remote_client_flow`（`:3398`）、`relay_serve_once`（`:4259`）。帧协议：`AUTH:<token>/CONNECT/ECHO/COMPUTE/HTTP/DIAL`（`:3558-3567`）。

**真实数据面**：`proxy_serve_once`（`:4684-5856`）是真实 SOCKS5/HTTP 混合握手 → `ProxyService` 路由 → 出站 kind 分支：
- 已实现：Direct（`:4825`）、Shadowsocks（`:4862`）、Trojan（`:5012`）、Anytls（`:5256`）、Vless（`:5540`）、Hysteria2（`:5741`，quinn-proto QUIC）
- **硬编码 Err deferred**：Relay（`:5237`）、Vmess（`:5244`，注释自称缺请求头编码器/帧格式/会话密钥派生）、Socks5 outbound（`:5250`，注释自称 "use nexusd ProxyEngine (P1-P5)"）

### 2.6 observability.rs（1,020 行）— 硬编码演示快照

**关键事实**：全部 17 个观察命令进程内快照函数返回硬编码/内存演示数据：
- `DemoResolver`：example.com → 2606:2800:220:1:... + 93.184.216.34（`:41-46`），其他域名失败
- `session_watch`：硬编码 sess-1/sess-2/sess-3（`:202-214`）
- `connectivity_status`：硬编码 203.0.113.53:51820（`:272-283`）
- `plan_explain`：硬编码 p1/p2 ProviderRecord，只认识 internet-access（`:311/:320-338`）
- `platform_capabilities`：纯硬编码字符串数组（`:391-411`）
- `workspace_heads/conflicts/cache`：InMemoryContentStore 每次现构造（`:441/:522/:873`）
- `compute_jobs`：InMemoryComputeTransport 硬编码 "OK:42"（`:622`）

**可达性**：apps/nexus CLI 进程内**不可达**这些函数（main.rs:345-355 观察命令优先 daemon 转发；`ControlServiceImpl::snapshot` 仅 Run 用，`main.rs:320-333`）。它们被 daemon（apps/nexusd）进程内调用（`observability.rs:66-67` 注释自称），但返回演示数据。**即：CLI 瘦客户端拿到的"观察数据" = daemon 内存里的硬编码快照，不是真实运行状态。**

## 3. 依赖关系（以 apps/nexus/Cargo.toml 为准）

- workspace 内依赖（约 24 个）：nexus-control-api（命令 DTO/ControlCommand）、nexus-domain、nexus-ingress、nexus-proxy(-config)、nexus-policy、nexus-registry、nexus-measurement、nexus-planner、nexus-scheduler、nexus-session、nexus-connectivity（cidr/coord/encryption/virtual_subnet/reconnect）、nexus-discovery、nexus-transport、nexus-auth、nexus-service、nexus-network、nexus-fabric、nexus-path、nexus-compute、nexus-workspace(-intel)、nexus-dns、nexus-outbound-{shadowsocks,vmess,trojan,anytls,vless,hysteria2}、nexus-plugin、nexus-storage、nexus-platform(-linux/-windows)。
- 关键第三方：quinn-proto 0.11（Hysteria2 QUIC）、rustls 0.23（Trojan/Vless TLS、provider_fetcher）、serde/serde_json、getrandom（LocalAPI bearer token）、ring（ed25519 身份/SHA-256）、toml 0.8（配置）、socket2（mDNS/LocalAPI 非阻塞 connect）。

## 4. 实现度判定汇总（四档）

| 判定 | 模块/命令 | 证据（行号） |
|---|---|---|
| **implemented** | use_cli（N2 四步闭环）、grant_cli、resource_cli、node_cli、plan_cli（只读）、session_cli、provider_cli、pair_cli（除 mDNS）、schedule_cli、subnet_cli（含 --tun/punch）、n2_admission、n2_store、n2_directory、n2_identity、n3_acceptance（适配层）、task_cli（thin client）、task_localapi、task_provider_grant（仅 Linux）、task_authorization、control_service、localapi_client、network.rs（仅 Linux）、subscription_updater、strategy_watcher、provider_fetcher、geoip_sources、artifact_download（仅 Linux）、mesh（Phase1） | 各文件行号见上文 |
| **partial** | lib.rs 纵切（内存/loopback 模拟，非真实多机）、proxy 出站（relay/vmess/socks5 deferred）、system-proxy/autostart（仅 Windows）、observability（硬编码演示数据）、network up（仅 Linux）、pair join（--addr 必填，mDNS 未实现） | `lib.rs:5237/5244/5250`；`main.rs:1561-1567,1629-1635`；`pair_cli.rs:391` |
| **stub** | `run <res> -- <cmd>`（诚实拒绝）、`task_cli::run_unavailable`（仅测试调用）、schedule 触发回调（只生成 task id 不执行）、observability 进程内快照（main 不可达） | `main.rs:381-398`；`task_cli.rs:384`；`schedule_cli.rs:107-109` |
| **dead** | `parse_command` 的 session 分支（`main.rs:845-850`）——main.rs:294 已截走全部 session* | `main.rs:294` vs `main.rs:845-850` |

## 5. 片区跨 crate 调用主干

- argv → `main.rs::run` → 各 `*_cli::run` → 进程内 `n2_store::N2Store` 读写（use/grant/resource/session/plan）。
- 观察命令 → `localapi_client::http_get` → daemon HTTP（unix socket/TCP loopback）。
- N3 任务 → `task_cli::run` → `task_localapi::execute` → daemon HTTP POST `/localapi/v1/task`。
- 准入跨机 → `use_cli::use_remote` → `n2_admission::admit_session`（独立 TCP）↔ B 侧 `n2_admission::serve_forever`。
- `ControlServiceImpl::snapshot`（`control_service.rs:27`）→ `observability::*`（daemon 进程内）。
- lib.rs 纵切 → `FrameStreamAdapter`（`lib.rs:539-600`）实现 nexus_service/network/compute/workspace 四个 Transport trait（依赖注入装配点）。

## 6. 片区小结

**真实能力**：N2 资源访问闭环（解析→规划→授权→建立→会话/租约持久化）是本片区最完整的真实代码，含真实跨机 ed25519 双向握手准入。CLI↔daemon 的两条 HTTP 通道（GET 观察 / POST 任务）协议严格、鉴权完整（Bearer token + loopback 限制）。SOCKS5 代理数据面已支持 6 种出站协议。

**最大缺口**：
1. **观察命令无真实数据源**——observability 全部硬编码演示数据，CLI 拿到的 status/dns/connectivity 等不是真实运行状态。
2. **3 种 proxy 出站（relay/vmess/socks5）硬编码 Err deferred**。
3. **schedule 触发不执行**——tick 只生成 task id，命令永不运行。
4. **平台分裂**：system-proxy/autostart 仅 Windows，network up/artifact download/task-provider grant 仅 Linux。
