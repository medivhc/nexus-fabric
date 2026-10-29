# nexusd Module Contract

## Responsibility

桌面/服务端主 Runtime Composition Root，装配 Domain Runtimes、Ingress、Registry/Discovery 与平台抽象。

## Non-Responsibilities

不承载可复用核心领域逻辑；可复用逻辑必须下沉到对应 crate。

## Inputs

- 仅接受公开类型、DTO、trait、事件或稳定协议对象。
- 输入必须可被结构化验证；不得依赖未声明的全局隐式状态。

## Outputs

- 结构化 Result / Event / DTO。
- 失败必须保留可诊断原因，不以日志文本代替错误类型。

## Allowed Dependencies

- `nexus`（apps/nexus SDK 组合根：daemon 复用其远程闭环流程，不复制领域逻辑）
- `nexus-control-api`
- `nexus-registry`
- `nexus-discovery`
- `nexus-ingress`
- `nexus-network`
- `nexus-service`
- `nexus-workspace`
- `nexus-compute`
- `nexus-platform`
- `nexus-projection`（统一数据面：TUN/分类器/多路径/Boost）
- `nexus-qos`（跨栈共享叶：CAKE-like QoS 调度与令牌桶；`cake` / `bucket`）
- `nexus-dns`（统一数据面：UnifiedDns）
- `nexus-path`（统一数据面：PathManager/EWMA 选路，Boost 联动）
- `signal-hook`（R4：Unix SIGTERM/SIGINT 优雅关闭；MIT/Apache-2.0；`default-features = false`）

## Forbidden Dependencies

- `engineering/` 下的 Harness/Plugin。
- 未在 `policies/architecture.toml` 声明的 Nexus 内部 crate。
- Portable 模块中的平台专有 Framework/API。
- 通过“便利”依赖绕过公开领域边界。
- `nexus-connectivity`（v9 CLI 产品线运行时，frozen）：
  接缝 ①（NAT 词汇）/ ②（出站交接词汇）/ ③（CAKE）/ ④（LinkMarker）
  **均已清零**，本 crate 无任何直接依赖边与源码引用，且**无反向依赖例外**
  （不设临时放行、不设 allow 条目）；跨栈共享词汇见
  `nexus-domain` / `nexus-proxy-config` / `nexus-qos` / `nexus-session`。
  见 `docs/DOC-AUDIT-2026-10-26-dual-stack.md` 与 `docs/adr/0001-dual-stack-boundary.md`。

## Invariants

- 该 app 只承担前端或 Composition Root 角色。
- 不得让 production crate 反向依赖 app。
- S49 文档一致性 grep 明确排除 `docs/recovery/`：该目录是 SHA-256 manifest
  固定的取证归档（`docs/recovery/2026-10-20/canonical-export-manifest.json`），
  历史快照包含旧符号是预期事实；改写快照会破坏 manifest 校验。门禁实现在
  `scripts/doc-consistency-check.sh`，只扫描 `PRODUCT.md`、`docs/`、`crates/`、
  `scenarios/` 中的活文档。

## Side Effects

- 仅允许 Responsibility 所需且在架构层中明确归属的副作用。
- 新增副作用前必须更新本契约和 Scenario/Policy（如影响外部行为）。

## Public API

### 冻结契约（daemon 形态，scenarios/product/daemon_run_remote_service_flow.toml）

- 单次执行入口：`nexusd run <resource> --json`，路由到 SDK 组合根远程闭环（`service` / `internet-access` / `compute`），stdout 输出单个 JSON 对象。
- 未知资源：输出 `{"verdict":"REJECTED","error":{"code":"UNKNOWN_RESOURCE","resource":"<name>"}}`，exit 0（表示请求已被 daemon 处理，拒绝也是处理结果；无效 CLI 用法仍 exit 非 0）。
- daemon 不复制领域逻辑：全部闭环复用 `nexus` SDK 组合根函数；本 app 只承担 CLI 解析与装配。

### 真实网络入口（real transport，PRODUCT §6，2026-09-18）

- `nexusd host <service|internet-access|compute> --addr <ip:port> --token <t>`：
  提供方在真实地址**持续监听**（服务循环，逐连接独立认证 + 业务闭环），
  服务端完成 `AUTH` 门控（业务帧前），随后执行业务
  （service ECHO 往返 / internet-access 真实 HTTP GET / compute 表达式求值）。
  认证拒绝输出 `AUTH_DENIED` 结果后继续服务，不退出。
- `nexusd relay --addr <ip:port>`：`DIAL <target>` 帧 + 双向字节中继（真实 TCP 代理）。
- `nexusd run <resource> --endpoint <ip:port> [--relay <ip:port>] --token <t> --json`：
  请求方经静态发现解析真实 Endpoint 建立真实帧流并执行线上认证；直连失败回退 relay。
- `nexusd proxy --addr <ip:port> [--config <path>]`：真实 SOCKS5 数据面入口
  （PRODUCT §11.4）——监听后逐会话完成握手 → 规则路由 → Session → 真实出站
  → 字节中继；每会话输出一条结构化 JSON。
- `nexusd proxy speedtest --json`：节点测速批量结果表（PRODUCT §11.10）。
- 语义：host/relay 只做装配与真实 I/O，闭环事件与认证语义全部复用 `nexus` SDK。

### §9 可观察性子命令（scenarios/product/observability_*.toml）

- `nexusd status --json` / `dns status --json` / `dns cache --json` /
  `dns resolve --json` / `dns providers --json` /
  `session watch --json` / `connectivity status --json` /
  `connectivity candidates --json` / `connectivity probe --json` / `connectivity links --json` /
  `plan explain --json` /
  `workspace heads --json` / `workspace conflicts --json` / `workspace cache --json` /
  `compute jobs --json` /
  `diagnose --json` / `platform capabilities --json`：路由到 SDK `observability` 模块，
  stdout 输出单个 JSON。
- 领域未就绪子命令（connectivity trace 等）：
  输出 `{"verdict":"FAIL","error":{"code":"UNSUPPORTED","command":"<name>"}}`，exit 0。
- 无效 CLI 用法仍 exit 非 0。

### `daemon.toml [qos]` 小节（CAKE-like QoS，scenarios/product/qos_cake.toml (e)）

- 字段（全部可选）：`enabled`（默认 false；别名 `enable` 亦接受）、
  `mesh_upload_mbps` / `proxy_upload_mbps`（整数 Mbps，0=不限，默认 0；
  负数按 0 处理，即不限）、
  `quantum`（整数，需在 [64, 65536] 内，默认 1514，非法则拒绝加载）、
  `high_priority_ports`（逗号分隔字符串 `"22,53,3389"` 或整数数组，
  默认 `[22, 53, 3389]`）。
- 映射：`mesh_upload_mbps` ×1e6/8 → mesh egress 整形字节/秒（`None`=不限）；
  proxy 同理。`enabled=false` 时调度器不实例化（零开销）。
- 热加载：`[qos]` 任一字段变化 → `NeedsRestart`（子系统启停/重配）；
  无变化时沿用既有分类。

### 统一数据面装配（D1-D6，scenarios/product/dataplane_unified.toml，2026-10-01 冻结）

- **D1（TUN 所有权）**：`nexusd <config-folder>` 启动数据面时，创建并持有单个 TUN
  设备（Linux: `tun-rs`，设备名 `nexus0`，MTU 1500）。TUN 是唯一包入口；
  不存在"Clash TUN 与 Mesh TUN 抢设备"（设计文档 §6）。
- **D2（分类管线）**：从 TUN 读取的每个 IPv4 包 → `PacketClassifier::classify()`：
  - `Mesh{..}` → N1 转发（`network.toml` 未配置则计数 `mesh_dropped_no_n1`）；
  - `Proxy` → 未配置/无可用出口 → SYN 直接回 RST（`craft_rst`，不进终结器、不回
    SYN-ACK）+ 计数 `proxy_dropped_no_proxy`（D2=C）；tag 可拨号 → proxy 转发；
  - `Direct` → 直连（MVP 计数 `direct_forwarded`，实际经系统路由）；
  - `Drop` → 计数 `dropped`。
- **D3（DNS 拦截）**：UDP/53 的 IPv4 包短路分类器，提交给单 owner DNS 线程（见「DNS
  服务面」）：`UnifiedDns::step()` 本地命中（Hosts/Mesh/FakeIp）→ 线程内构造响应；
  `Upstream` → 非阻塞上游引擎；响应经有界 channel 回数据面并写回 TUN（`dns_answered`
  计数；响应包源端口 53）。**两条入口、一条引擎**：TUN 与 TPROXY UDP/53 提交同一 DNS
  线程，回程按 `DnsReply` 的 sink 判别（TUN 写设备 / `TransparentOutput::UdpReply` 走
  tproxy 回程，Q-3/D-impl-2）。目的为 v6 的 53 本 run 不拦截（D-impl-7：0x86DD 全部
  落 `ipv6.*` 计数，不静默）。
- **D4（QoS）**：`[qos].enabled=true` 时，分类后、转发前经过 `CakeScheduler`：
  `enqueue()` 拒绝则计数 `qos_dropped`；`enabled=false` 时零开销直通
  （`qos_bypassed=true` 可观测）。
- **D5（多路径）**：`[multipath].strategy` 非 `Single` 时，`PathScheduler::select()`
  选择 egress；MVP 默认 `Single` 直通。
- **D6（Boost）**：`[boost].enabled=true` 时，分类器构造传入 `PathManager`，
  mesh 分类启用 EWMA 只读选路（S30）；禁用时 `candidates=[]`。
- 可观测：`DataplaneStats { mesh_forwarded, proxy_forwarded, direct_forwarded,
  dropped, dns_answered, qos_dropped }`，经 LocalAPI `/localapi/v0/dataplane/stats` 暴露。
- 不变量：单 TUN（D1）；分类器是唯一分类入口（S29）；DNS 不泄露 mesh 内名
  （nexus-dns S-unified）；QoS 禁用时零开销（D4）。

### IPv6 数据面 slice 1（R3 C18/C19：计数 / 分类 / 能力表 / Mesh 原始转发）

- **入口分派**：`0x86DD` 包在 DNS 拦截与所有 v4 路径**之前**进入专用分支；
  不变量：**任何 0x86DD 包都落在一个 `ipv6.*` 计数上，绝不只增通用 `dropped`**
  （AC10，S-V6-A 合并点起生效）。
- **分类单一出口**：v6 与 v4 共用 `PacketClassifier`（经 `classify_with_cache`）；
  v6 在委托规则引擎**之前**短路（D-impl-1）：`mesh_cidrs6` 命中 → `Mesh`，
  `bypass_cidrs6` 命中 → `Direct`，其余 → `Proxy{outbound:"proxy"}`。禁止第二套
  v6 判定（D-impl-10）。v6 不建 flow 会话（终结双栈归 S-V6-B）。
- **解析口径**（spec §4.7.3）：扩展头链支持 `0`/`43`/`60`/`44`；`44` 不重组
  （Fragment 头存在 → `ipv6.fragments`，仍按目的地址分类）；ESP/AH 不解析 L4、
  按目的地址分类；>8 个扩展头或长度越界 → `ipv6.dropped_extension`（fail-closed）；
  固定头/L4 截断 → `ipv6.dropped_truncated`。入站 v6 包**不校验** L4 校验和
  （TUN 可能携带 CHECKSUM_PARTIAL）；我们构造的 v6 响应必须写完整校验和。
- **多播**：`ff00::/8` → `ipv6.multicast`，只计数、不进分类转发（classifier 对
  多播不特判，契约由单测钉住）。
- **路径结果**：Mesh → N1 原始转发（`send_to_mesh(IpAddr::V6, bytes)`，
  `ipv6.mesh_forwarded`）；无 v6 路由 / 无 sender → `ipv6.mesh_no_route` 且既有
  `mesh_dropped_no_n1` 同步 +1。Direct → 只计数（`ipv6.classified_direct` +
  `direct_forwarded`；本 run 无 v6 direct egress，与 v4 一样"计数可见"，不静默）。
  Proxy → 阻断（Q4 已裁定，不是缺口）：`ipv6.classified_proxy` +
  `ipv6.proxy_dropped` + 限流日志，不调用 ProxyEngine、不计 `proxy_dropped_no_proxy`。
- **v6 DNS 不拦截**（D-impl-7）：`is_dns_query`/`is_dns_tcp_query` 保持 v4-only；
  v6/53 落 Proxy → `ipv6.proxy_dropped` 可见，不是静默丢弃。
- **计数归属**（D-impl-10）：`ipv6.packets` 对所有 0x86DD +1；其余字段每个维度
  只加一个语义分量——传输层 `udp`/`tcp`、分类 `classified_*`、路径结果
  `mesh_forwarded`/`mesh_no_route`/`proxy_dropped`、标志位
  `fragments`/`multicast`/`dropped_*`。
- **能力表**：`ipv6_paths` 是静态表（启动时由 `[[vpi.routes6]]` 与编译特性决定，
  不随包变化）：`mesh = supported|unsupported`、`direct = supported`、
  `proxy_tcp = supported`（合并门 RC-r3-f3-proxytcp-20261028 对齐 C21 接线事实；CAC-1 实测）、`proxy_udp = blocked`、`tun_address = unassigned`、`nat = unsupported`；
  经 `/localapi/v0/dataplane/stats` 的 `ipv6_paths` 暴露，并与 `ingress_ip_family`
  派生自同一张表（v6 mesh 路由在位 → `dual-stack`，否则 `ipv4`；N-8：禁止硬编码
  `ipv4` 与能力表矛盾）。
- **日志**（60 s / `(event, 判别字段)` 一条）：`ipv6_proxy_unsupported proto=<n>`、
  `ipv6_fragment_dropped path=proxy`、`ipv6_ext_unsupported hdr=<n>`；计数不随限流丢失。
- **不在本 slice**：v6 TCP 终结（S-V6-B）、v6 代理出口、v6 NAT/打洞、TUN v6 地址
  分配（Q7）、v6 QoS 归因（`unknown → Normal`）。这些是显式取舍，状态表可见。

### DNS 服务面（R3，C5–C11；引擎契约见 `crates/nexus-dns/MODULE.md`）

- **线程归属**：单一 DNS 线程（`nexusd-dns`）唯一持有 `UnifiedDns`、`FakeIpPool`、
  `UpstreamEngine`、上游 socket 与缓存，无锁；dataplane 线程不持有 resolver。
  `DnsService::start` 在 TUN 创建成功后调用；thread spawn 失败 → 数据面不启动
  （不构造 `Dataplane`），状态 `service="failed"`，杜绝“dns_enabled 但无服务”的隐藏
  Stub。no-tun 模式不启动 DNS 服务，`dns.enabled=false`、`service="disabled"`（SU-2）。
- **队列/节奏**：dataplane→DNS 请求队列 256、DNS→dataplane 回包队列 256、TCP 回退
  上限 32（`tcp_worker_queue`；当前实现为单查询在 `poll` 内联执行并受 R1 等待约束，
  未单独起 worker 线程）、空闲 tick 5 ms、fake-ip 回收扫描 60 s、关闭 join 2 s。
- **关闭语义**：数据面循环退出 → drop 请求发送端 → DNS 线程处理在途查询（≤2 s）→
  join；超时记日志后继续，不 hang；结束后状态 `service="failed"`。
- **上游**：明文 UDP/53（可带端口），≤8 台、声明序去重；`degraded`（连续失败 ≥3）
  排在健康服务器之后；`TC=1` 可回退 TCP（实际等待 = min(`tcp_timeout_ms`, 剩余预算)，
  剩余 ≤0 立即放弃并故障转移）；RCODE 失败、畸形响应、错源/错 txid/错 question 一律
  不得误用。状态显式 `plaintext=true`（明文暴露面不隐藏）。
- **状态面**：`/localapi/v0/dns/status` 返回 `dns` 对象：`enabled`、`service`、
  `source="dataplane"`、`config_generation`（启动 = 1）、
  `classes{hosts,mesh,proxy_classifier,upstream}`、
  `proxy_policy{unmatched,unevaluable,rules,unevaluable_rules,default_proxied}`、
  `upstream{state,plaintext,servers[],last_error}`、计数器（含 `classify_unevaluable`）、
  `fake_ip{enabled,allocated,capacity,exhausted}`。进程级 `OnceLock` 只承载 LocalAPI
  读口（第一个实例优先，D-impl-9）；example/E4 直接读 `DnsServiceHandle.status`。
- **`dns_answered` 语义（修正）**：DNS 拦截产生的响应成功写入 TUN 的次数，含所有
  rcode/class；TCP/53 的 RST 也计入；写失败另计 `dns_reply_write_failed`。等式：
  `dns_answered = dns_noerror + dns_nodata + dns_nxdomain + dns_servfail + dns_refused
  + dns_formerr + dns_tcp_refused`。
- **日志**：统一 `[nexusd] dns` 前缀；每 `(event, reason)` 每 60 s ≤1 条；不记录用户
  查询的域名（只记长度/类型/计数）。

### N1 组网接入（W1-W4，scenarios/product/n1_wireup.toml，2026-10-01 冻结）

- **W1（N1 发送）**：`Classification::Mesh{..}` 且 `n1_configured=true` 时，
  dataplane 调用 N1 发送接口真发（不再仅计数）：
  - 发送成功 → `mesh_forwarded += 1`；
  - 发送失败（无路由/无连接/超限）→ `mesh_dropped_no_n1 += 1`（D2 可观测性不变）。
- **W2（N1 接收）**：N1 对端发来的包经下行路径写回 TUN（`tun_written += 1`）；
  写 TUN 失败 → 计数丢弃（不 panic）。
- **W3（接口边界）**：`nexus-network` 新增 `N1MeshBridge`（`n1/bridge.rs`）：
  - 持有 `N1SessionManager`（连接表）+ `Ipv4Route` 路由表（复用 pump.rs 逻辑）；
  - `send_to_mesh(dst: IpAddr, packet: &[u8]) -> Result<(), N1Error>`（IPv4/IPv6，
    v6 路由来自 `[[vpi.routes6]]`）；
  - **不修改** M1-M7 冻结行为（`VpiPump`、`N1SessionManager` 核心逻辑不动）。
- **W4（配置）**：`network.toml` 的 N1 配置（peer 列表、mesh CIDR）经
  `DataplaneConfig` 传给 dataplane；未配置 N1 时保持 D2 计数行为。
- 不变量：单 TUN（D1）；分类器唯一入口（S29）；N1 发送失败不阻塞其他分类
  （Proxy/Direct 照常）；`mesh_dropped_no_n1` 语义不变（无 N1 或发送失败都计数）。

### `[tun]` no-tun 模式（T1-T4，2026-10-01 冻结）

- **T1（`[tun]` 配置）**：`daemon.toml` 的 `[tun]` 小节（全部可选，有默认值）：
  - `enabled`（bool，默认 `true`）：`false` = no-tun 模式，不创建 TUN；
  - `name`（string，默认 `"nexus"`）：TUN 设备名（Linux），避开 `"Mihomo"` 等；
  - `mtu`（整数，默认 1500，合法范围 [1280, 9000]，非法则拒绝加载）。
- **T2（no-tun 行为）**：`[tun].enabled=false` 时：
  - 跳过 TUN 创建，不启动 dataplane 线程（记日志 `"[nexusd] tun disabled; dataplane not started"`）；
  - N1/proxy 子系统照常（由 `network.toml` / `proxy.yaml` 存在性决定，与 TUN 无关）；
  - LocalAPI 照常服务；stats 标注 `tun_enabled=false`。
- **T3（空配置拒绝）**：缺 `proxy.yaml` **且**缺 `network.toml` 时，daemon 拒绝启动
  （exit 1，stderr 说明 `"no subsystem configured: need proxy.yaml and/or network.toml"`）。
  有任一文件即启动（纯代理 / 纯组网 / 统一三模式，见 `docs/WINDOWS_TUN_DESIGN.md` §1）。
- **T4（热加载分类）**：`[tun]` 任一字段变化 → `NeedsRestart`（TUN 设备启停需重建）。
- 不变量：`enabled=true` 时行为与 D1 完全一致（零回归）；no-tun 时不创建任何
  TUN 设备（`tun0`/系统 TUN 不受影响）；空配置拒绝先于 TUN 创建（快速失败）。

### `daemon.toml [network.discovery]` 与 relay 地址簿（peer 发现/订阅，2026-10-27）

- **键表（全部可选；缺失 = 默认值）**：

| 键 | 类型 | 默认 | 校验/说明 |
|---|---|---|---|
| `enabled` | bool | `true` | 总开关；`false` = pump 与 feed 都不启动 |
| `mdns` | bool | `true` | 只停/启 mDNS pump |
| `lsa` | bool | `true` | 只停/启 LSA gossip pump |
| `feed` | bool | `true` | 订阅/触发开关 |
| `gossip_port` | u16 | `19010` | `1..=65535` 且 ≠ 5353；静态 peer 的 LSA 目标端口按此替换（所有节点需一致，spec §9 R-6） |
| `advertise_ip` | string | `""`（自动） | 空 = 自动选择；否则必须是 IPv4 字面量。**多网卡主机应显式配置**，自动选择会优先取“最小的私有 IPv4”（常见为 docker `172.17.0.1`） |
| `lsa_refresh_sec` | u64 | `30` | `5..=300` |
| `lsa_stale_sec` | u64 | `90` | `max(60, 2×lsa_refresh_sec)..=3600` |
| `book_poll_ms` | u64 | `5000` | `1000..=60000`；relay 地址簿轮询间隔 |
| `trigger_max_failures` | u32 | `3` | `1..=10`；连续触发失败达到该值后 park |

- **`[network.turn].relay_book_dir`**：`string`（目录），缺省 `None`。配置 = 共享目录
  `DirRelayAddressBook`（每节点 `<self64>.addr`，read-all，目录不存在自动创建 `0700`）；
  缺省 = 兼容的 per-self 临时文件 `$TMP/nexus-relay-<self64>.toml`；空字符串 =
  `daemon.toml` 解析错误（CONFIG，启动失败）。
- **可见性（操作者必须能判断“为什么不触发”）**：
  - 启动打印 `[discovery] advertise_ip=<ip|none> source=<config|auto> gossip_port=<p>
    mdns=<enabled|disabled> lsa=<enabled|disabled> lsa_locator=<udp://ip:port|none>
    feed=<enabled|disabled>`；
  - 启动打印 `[nat-relay] book mode=<shared-dir|per-self> path=<…>`；
  - `GET /localapi/v0/connectivity/nat` 的 `peer_source` 块包含
    `book_entries`、`subscribed_peers_without_book_addr`、`trigger_parked_max_failures`、
    `trigger_parked_capacity`，可直接区分“book 里没有对端地址”与“触发失败被 park”。
  - 无可用 IPv4（自动选择为空）时 mDNS 不启动：冻结 WARN
    `[discovery-mdns] WARN: no advertise IPv4; mdns disabled` +
    `discovery.last_error="advertise-ip-unavailable"`；此时 LSA locator 为空
    （摘要 `lsa_locator=none`），身份级发现仍可接收。
- **park 语义**：`trigger_parked_max_failures` 的 peer 只有 **book 地址变化**或
  **源集合变化**（订阅来源增减）才重开；`trigger_parked_capacity` 在单槽释放后自动重开。
  `trigger_capacity_parked_total` 仍只累计 capacity 次数。
- **`last_error`**：成功后**不清空**（spec §4.12.1 明文）；用 `book_last_success_ms`
  判断当前是否新鲜，不要把旧的 `book-reload-failed` 当成仍在失败。
- **诚实边界（spec §9 R-1/R-2/R-3，必须在任何对外说明中复述）**：
  - **R-1 跨主机 D5 仍依赖共享存储**：book 渠道是 **INTERIM**，要求节点间共享文件系统，
    不是通用生产分发；无共享目录时跨主机 D5 不点火（AC3 记 `BLOCKED(environment)`）。
  - **R-2 通告端点语义**：LSA locator / mDNS SRV 只表示**发现/gossip 端点**
    （`advertise_ip:gossip_port`），不是 N1 拨号端点；**本 run 不交付零配置 N1 数据面**，
    不得宣称“零配置组网已可传数据”。
  - **R-3 单 relay 容量**：一个 TURN allocation 只安全服务 **1 个 peer**；多 peer
    relay 属后续工作。
- 不变量：`[network.discovery]` 任一键变化 → `NeedsRestart`（pump/feed 生命周期需重建）。

### Composition Root 接线（R1-R5，scenarios/product/composition_root.toml，2026-10-01 冻结）

- **R1（N1 桥接线）**：`network.toml` 存在时，Composition Root 按 §13.3 步骤 5
  装配 N1：
  - `N1Config::parse_toml` 解析失败 → 记 error 日志，降级（不调
    `set_n1_sender`，dataplane 照常跑，Mesh 包计数 `mesh_dropped_no_n1`）；
  - 解析成功 → 经 `nexus::network::build_session_manager` 构造
    `N1SessionManager`，由 `vpi.routes` 构造 `N1MeshBridge`，各 peer
    `dial()` 尽力而为（单 peer 失败记 warn，不中断）；
  - 成功后调 `dataplane.set_n1_sender(bridge)`；`n1_bridge_ready()` 为 true
    当且仅当 sender 已注入。
  - 不变量：M1-M7 冻结行为不动（只新增装配胶水）；N1 失败不影响
    Proxy/Direct 分类（W1 不变量延续）。
- **R2（mesh CIDR 配置化）**：`DataplaneConfig.mesh_cidrs` 不再硬编码
  `10.0.0.0/8`，而是取自 `network.toml [vpi.routes]` 的 subnet 列表
 （`"A.B.C.D/N"` 字符串）；`network.toml` 缺失 → 空列表；
  解析失败 → 空列表 + warn（降级，不阻断 dataplane）；
  与 bypass CIDR 重叠 → 启动时 warn 日志，mesh 优先（分类器 S29 顺序不变）。
- **R3（dns.toml 严格 schema）**：DNS 子系统实际启用时解析为 `DnsFileConfig`
  （`unified` + `mesh_hosts` + `proxy` + `upstream`）：
  - 所有键必须在 `[dns]` 下；未知键、根级键 → 启动失败 `CONFIG`（exit 1，
    `{"code":"CONFIG"}`，消息含键名）；
  - 19 键（类型/默认/范围见 spec §4.6.1）：`upstream`（必填、≤8、去重保序）、
    `fake_ip_enabled`、`fake_ip_range`（前缀 ≤30）、`mesh_suffix`、`fake_ip_ttl_secs`、
    `hosts`、`ip_preference`、`unmatched`、`unevaluable`、`attempt_timeout_ms`、
    `attempts_per_server`、`total_budget_ms`、`edns_udp_size`、`tcp_fallback`、
    `tcp_timeout_ms`、`cache_max_entries`、`cache_max_ttl_secs`、`negative_ttl_secs`、
    `max_inflight`；
  - `[dns.mesh.hosts]`：mesh 名源（SU-3：loopback 拒绝、link-local 接受；地址必须落在
    `[[vpi.routes]]` 或 `[[vpi.routes6]]`；有 mesh 表但无对应网段 → `CONFIG` 失败）；
  - `unmatched=proxied` 必须有可用出站（判定 = `outbound_manifest::select_index`，
    F1），否则 `CONFIG` 失败；
  - `[tun].enabled=false` 时 DNS 子系统整体禁用：`dns.toml` 不解析、不校验、不建线程，
    其非法内容不影响启动结论（SU-2）；
  - `dns.toml` 缺失 = DNS 禁用：`enabled=false`、`service="disabled"`、不拦截 53。
  - 落点：`config::parse_dns_toml(text, network_toml, has_usable_outbound)`（三参数：
    mesh 网段归属 + 可用出站上下文）+ `assembly::build_dataplane_config`；旧的宽松
    解析已在 C11 原子迁移中删除。
- **R4（关闭顺序）**：Unix SIGTERM/SIGINT → 按 §13.4 反向关闭：
  LocalAPI 停收新查询 → **Workspace unmount（C1/D7）** → dataplane 线程停
  （join 1s 超时）→ `N1SessionManager::shutdown()`（join 5s 超时）→ TUN 随
  dataplane 线程退出关闭 → exit 0；任一步超时 → warn 日志后强制继续，不无限等。
  （ProxyEngine 尚无独立运行时，步骤为 no-op，记 info。）
- **R5（热加载分类）**：`network.toml` 内容变更 → `NeedsRestart`
  （mesh CIDR 属重启类，§13.6）；`dns.toml` 内容变更 → `NeedsRestart`
  （DNS 服务持有 socket 与缓存；固定日志原文
  `[nexusd] WARN: config change requires restart: dns.toml (dns service owns sockets/cache)`）；
  `dns.toml` 增删 → `NeedsRestart`（子系统启停）；
  `workspace.toml` 内容变更/增删 → `NeedsRestart`（挂载集合变化需重新装配，C1/D1）；
  `proxy.yaml` **内容变更 → `NeedsRestart`**（engine 只在启动构造，Q-7=B），
  并发布 stale 面（`outbound.stale=true` + active/file tag/kind/sha1）。
- 不变量：TUN 失败仍致命；N1/DNS 失败可降级；**Proxy 失败分层**：`proxy.yaml`
  解析失败、rule engine 构建失败、以及首个 wired 出站非法（`SelectedInvalid`，
  含域名不可解析）一律启动失败（stderr JSON + exit 1）；**仅**『无任何可用代理
  出站』（`NoUsableOutbound`）降级为『无 proxy engine』，Proxy 流按 D2 回 RST
  并计数。关闭必达 exit（不 hang）；`mesh_dropped_no_n1` 语义不变。

### TCP 终结接线（S1-S11，engineering/e2e/test-plans/tcp_termination_wireup.toml，2026-10-01 冻结）

- **S1（终结范围）**：IPv4 + proto 6 的包，且 `PacketClassifier` 分类为
  `Mesh{..}` 或 `Proxy` 时，进入 smoltcp 终结
  （`nexus_projection::tcp::TcpTerminator::handle_uplink(packet, peer)`），
  不再走 D2/W1 的 raw-datagram 路径。`peer` 参数：Mesh 取分类 `path` 的
  socket addr 字符串（`None` 时用目的 IP 字符串）；Proxy 用 `"proxy"`。
- **S2（TUN 回写）**：`handle_uplink` 返回的 TUN 包（SYN-ACK/ACK/重传）全部
  写回 TUN；`tun_written += n`；单包写失败 → `dropped += 1`
  （不 panic，不中断后续包）。
- **S3（事件轮询）**：`process_one()` 处理完 TCP 包后调用
  `terminator.poll()` 收获 `TcpEvent`，按 S4–S7 分发。非 TCP 包不触发
  poll（零回归）。
- **S4（Syn 事件）**：`TcpEvent::Syn{stream_id, dst, peer}`：
  - dataplane 记录 `stream_id → (orig_dst: SocketAddrV4, proxy: bool)`；
  - Mesh：`encode_stream_frame(stream_id, STREAM_SYN,
    &encode_syn_payload(dst_ip_str, dst_port))` 经
    `N1Sender::send_to_mesh(orig_dst_ip, frame)` 发送；成功 →
    `mesh_tcp_frames += 1`，失败 → `mesh_dropped_no_n1 += 1`（W1 语义复用）；
  - Proxy：`proxy_tcp_streams += 1`（proxy 传输接线 = GAP-1，本契约只计数）；
  - 两类都计 `tcp_handshakes += 1`。
- **S5（Data 事件）**：`TcpEvent::Data{stream_id, peer, bytes}`：
  - Mesh：STREAM DATA 帧经 N1 发送；成功 →
    `mesh_tcp_frames += 1; mesh_tcp_bytes += bytes.len()`，失败 →
    `mesh_dropped_no_n1 += 1`；
  - Proxy：`proxy_tcp_bytes += bytes.len()`。
- **S6（Closed 事件）**：`TcpEvent::Closed{stream_id, peer, reset}`：
  - Mesh：STREAM FIN（`reset=false`）或 RST（`reset=true`）帧经 N1 发送；
    失败 → `mesh_dropped_no_n1 += 1`；
  - Proxy：删除流记录，无额外计数（S4 已计）；
  - 两类都删除 `stream_id` 记录（防泄漏）。
- **S7（TunPacket 事件）**：写回 TUN（同 S2 计数规则）。
- **S8（非 TCP 零回归）**：UDP/ICMP/非 IPv4 → 现有 D2/D3/W1 路径；
  `Direct`/`Drop` 分类的 TCP → 现有计数路径，永不进终结器。
- **S9（下行 STREAM 帧）**：新增
  `Dataplane::inject_stream_frame_from_n1(peer: &str, frame: &[u8])`：
  `decode_stream_frame` →
  `terminator.handle_originator_frame(stream_id, flags, payload)` →
  产生的 TUN 包写回 TUN（S2 规则）。`inject_from_n1` 的 raw 语义不变。
- **S10（可观测）**：`DataplaneStats` 新增 `tcp_handshakes`、
  `mesh_tcp_frames`、`mesh_tcp_bytes`、`proxy_tcp_streams`、
  `proxy_tcp_bytes: u64`；新增
  `Dataplane::tcp_term_stats() -> TcpTermStats`。LocalAPI stats 自动包含新字段。
- **S11（性能基线）**：实测并记录（无硬门限，供回归对比）：
  (1) `TcpTerminator` 单流吞吐（Mbps）；
  (2) dataplane TCP 包处理速率（pps）。
  记录于 `.evidence/`。
- 不变量：Direct 分类永不进终结器（S8）；终结器内部按 nexus-projection
  S21–S23 语义（表满/半开超时）处理，dataplane 不新增丢弃路径；
  跨平台同一套代码（TUN 经 `Box<dyn TunDevice>`，VirtualPacketInterface
  抽象）；UDP 分片/重组后置。
- 诚实边界：Proxy 方向只计数到 `proxy_tcp_*`（传输接线 = GAP-1）；
  Mesh 方向 STREAM 帧经 N1 datagram 承载；egress 侧 `TcpRelay` **已接线**
  （dataplane 持有 relay，`n1_egress_poll` 每轮驱动，计数见
  `/localapi/v0/n1/stats` 的 `egress.*`）。计数口径：`egress.connect_ok` 只计
  本地 socket 已产出证据的连接（静默连接少计、不多计）；`egress.bytes_to_local`
  计 DATA 载荷进入 relay 写路径的字节（正常缓冲下等于写入本地 socket）。
- **已知失败 / 待诊断**：2026-10-29 公网 [R] 窗口 10 MiB relay 传输在
  145,400 字节（1.39%）处中断，SHA-256 不一致；两端应用均未报错
  （发送端 `send` 成功、接收端干净 EOF `reset=false`），根因未定性，且
  按 spec §12.3 **不是** `FAIL(loss)`（接收端收到发送端几乎全部帧，发送端
  `fallback_errors` +8,339）。诊断 follow-up：
  `n1-mid-stream-send-failure-diagnosis`。本能力状态按 **preview** 记录，
  不得据此宣称 N1 可用；用户文档的诚实边界见 `docs/USER_MANUAL.md` §4.1.14。

### 常规要求

- 默认最小 surface：`private -> pub(crate) -> pub`。
- Public API 变更必须保持结构化、可版本化并有调用方验证。

### NAT chunk 消费（P0）

生产 TUN 的 Mesh TCP DATA 帧经 `NatPathProvider::send_chunk` 消费 NAT 层选定的 active conn：direct 活跃且发送门开启时每 chunk 新开一条 bi-stream（`WORKSPACE_SYNC` 帧，payload 为 `KIND=0x01 || STREAM_FRAME`），否则走既有 N1 fallback 并发送**原始 STREAM_FRAME**（不带 KIND）。SYN/FIN/RST 仍走 N1，不计入 chunk。

- 句柄：组合根创建 `NatHandleSlot` 并在 dataplane 线程启动前注入；NAT runtime 起来后 `slot.set`。slot 为空 = 全部 fallback（`runtime="disabled"`），不是错误。
- 门：`DIRECT_ACCEPT_QUIET_MS=30000`（接收）、`DIRECT_SEND_GUARD_MS=32000`（发送）；两端共享同一个单调 `PunchClock`，判据是 `PunchState::Succeeded` + `last_success_ms` 差值。不使用 `direct_conn_id`。
- 接收端：只 accept active 为 `Direct` 的 conn；读到一帧后继续 drain 到 EOF 并关闭己方发送方向（quinn 双半释放后才补发 `MAX_STREAMS`）；帧读失败只关闭发送方向。队列满丢该 chunk，不阻塞 accept。
- 状态面：只读路由 `GET /localapi/v0/nat/chunks`（新文件 `nat_chunk_stats.rs` 构建 JSON）；`/localapi/v0/connectivity/nat` 与 `/localapi/v0/dataplane/stats` 的既有字段零改动。计数字段用 `direct_attempts` 语义：只表示发送尝试，不表示送达。
- **ERRATA-2（spec 批准的修正，用户可见行为变化）**：direct chunk 路径下 terminator
  **不认识**的流不再静默丢弃，改为交 egress relay（以前直接丢）。这是 additive 修正、
  不是回归，但确实改变了 P0 direct 路径对未知流的用户可见行为——排障/公告时按
  「未知流改走 relay」表述，不要沿用旧的「丢弃」口径。
- 诚实边界：本段不引入 seq/ack/重排/重试，不声称 chunk 级顺序、送达或“不中断”；跨 conn 不迁移在途 stream；fabric driver 的流条目在 conn 关闭前不回收（既有 L-1）。

## Verification

### N3 装配契约增补（待实现）

装配 Compute TaskOwner、唯一 SessionManager、Snapshot/Artifact 存储与认证传输，
以及具硬配额/隔离的 Linux executor；平台不支持时显式拒绝，不退回裸主机。
所有任务进程/子树、日志 drain、取消、Join/Reap 和清理均有 Owner。
冷启动先对账 Task/幂等/pins/执行标签，再接受任务和运行 GC；未知 StartIntent 不再 spawn。
请求方 daemon 持久管理 cancel intent/outbox，确认落盘后才显示 Queued/CancelPending；
恢复后幂等转发，视图中与提供方 cancellation/TaskOutcome 明确分离，不写权威终态。
API/日志视图来自真实领域记录，不能从现有演示 ComputeJobSession 合成 N3 完成。
未来 `examples/n3_task_e4.rs` 是独立产品边界 verifier，不建立另一套业务状态机，
case 与断言由 `scenarios/product/n3-*.toml` 冻结，规范见 PRODUCT §17 与 N3 模型契约。

最低：

```text
cargo check -p nexusd
cargo clippy -p nexusd --all-targets -- -D warnings
```

如果该模块影响产品行为，还必须映射 Integration/Scenario Evidence。

### Proxy 生产转发（P1-P5，scenarios/product/proxy_fwd.toml，2026-10-01 冻结）

- **P1（TCP 转发）**：`Classification::Proxy` 的 TCP 包 → `ProxyEngine`：
  - 经 `TcpTerminator`（smoltcp）在用户态终结：SYN → SYN-ACK → ACK；
  - 握手完成（`TcpEvent::Syn{stream_id, dst}`）→ worker 线程经代理协议
    dial 目标（ss / trojan / socks5，P3 选路）；
  - dial 成功 → `proxy_forwarded += 1`，启动中继线程双向泵字节
    （proxy→`handle_fabric_data`→TUN；TUN→proxy stream）；
  - dial 失败 → `handle_fabric_rst(stream_id)`，`proxy_dropped_no_proxy += 1`；
  - 对端关闭 → `handle_fabric_fin/rst`；本地关闭 → 关 proxy 连接。
- **P2（UDP 转发）**：`Classification::Proxy` 的 UDP 包 → `ProxyEngine`：
  - 解析 IP/UDP 头 → `dialer.udp_capability()` 分派 → `UdpMode` 承载：
    SOCKS5 = `Socks5Associate`；SS = `ShadowsocksAead`（仍由 `ss_std::SsUdp` 承载，
    删除门归 fixes-6）；VLESS/AnyTLS = `Unsupported{NotWired}`；Trojan（恒 TLS）=
    `Unsupported{TlsVariantNotSupported}`；
  - 回包经后台线程解包 → 重构 IP/UDP 包 → 写回 TUN（`tun_written += 1`）；
  - `Unsupported` → 丢包 + `udp_send_failed`/`udp_unsupported*` 计数 +
    每 `(kind,tag)` 首次与每 10 s 一条限频日志，**绝不直连**；
  - 发送失败 → `proxy_dropped_no_proxy += 1`。
- **P3（出站选择，Q-4=A 多出站 + strict-first）**：`OutboundRegistry::build` 按
  `outbound_manifest::select_index`（文件顺序首个 proxy+wired，**唯一定义**）遍历：
  - 全部 wired 出站（socks5/shadowsocks/trojan/vless/anytls）建 dialer 入表，
    **按规则 tag 选路**（不是只选一个）；
  - direct/relay → `skipped(NotProxyKind)`；vmess/hysteria2 → `skipped(ProtocolNotWired)`
    且进 `unsupported` 槽（运行期结构化错误）；
  - 首个 wired 配置非法 → `SelectedInvalid`（**硬失败，不跳到下一个**）；
    非首个 wired 配置非法 → `Invalid` 槽（启动 warn + 运行期 `InvalidOutbound`）；
  - 无任何 proxy+wired → `NoUsableOutbound` → 无 engine（D1 降级）；
  - `OutboundKind` 集合不变（`Socks5` 为既有 additive）。
- **P4（失败语义）**：任何 dial/中继失败 → 计数丢弃，不 panic、不崩
  dataplane 线程；`proxy_dropped_no_proxy` 语义扩展为"无可用代理或转发失败"。
  - **D2=C 无出口 RST**：无 engine 或 tag 不可用（`UnknownOutbound` /
    `UnsupportedOutboundKind` / `InvalidOutbound`）→ **TCP SYN 当场回 RST**
    （唯一发射点 `emit_proxy_egress_rst`；不进终结器、不回 SYN-ACK、
    `stream_id=-`），每包恰好计一次 `proxy_dropped_no_proxy`（tag 不可用另加
    `dropped++`）；UDP 维持丢包 + 计数（无 RST 语义）。
  - **两态去重**：flow_mgr 开且无 engine 时，SYN 已发的 RST 记入
    `proxy_egress_rst_pending`；`FlowSignal::TcpReset` 命中只做会话回收
    + 既有 `dropped++`，不再发第二个 RST。
- **P5（资源边界）**：TCP 最大连接数复用 `TcpTerminator::MAX_TCP_CONNS`；
  UDP 流表上限 1024，60s 无活动回收；worker 线程 per-dial 创建、
  完成后退出（有界）；关闭时 join 超时 1s（R4 延续）。
- **P6（Trojan 凭据探测，PRODUCT §11.9.5，2026-10-28）**：每个 wired trojan 出站的
  dialer 持有一份探测状态（registry 拥有，每个新 registry 从空状态开始，不持久化——崩溃后
  重新探测，无需 Recovery）。`dial_tcp` 在无有效结果时先探测：探测在发起拨号的 worker 线程内
  同步执行（不新建长期任务，不阻塞 dataplane `tick()`），同出站的并发拨号等同一结果
  （single-flight，等待上限 = 单次探测上限 13 s：建连 5 s + TLS/写请求 5 s + 读 3 s）；`rejected` → `dial_tcp` 返回既有 `ProtocolHandshake(AuthRejected{Trojan})`，
  不连接节点，走 P4 的 dial 失败语义（RST + `tcp_dials_failed`）；有效期 `passed` 10 min /
  `rejected` 60 s / `inconclusive` 不缓存且两次探测间隔 ≥ 10 s，均从探测结束时刻按单调时钟计
  （实现以 `Instant` 参数注入时间，便于单测边界）。
  `credential_probe: false` 时 dialer 行为与 P6 之前完全相同。每次探测结束一条 stderr 行
  （不含密码）。统计面不新增字段。
- 不变量：单 TUN（D1）；分类器唯一入口（S29）；TUN 所有权仍在 dataplane
  （engine 只返回待写包，不直接写 TUN）；`proxy_forwarded` 仅在真实转发
  发生时计数（不再是纯分类计数）。
- **统计面（D3=A，15 个恒定字段）**：`tcp_streams`（Syn 数）/ `tcp_dials_ok` /
  `tcp_dials_failed` / `tcp_dial_buffer_dropped_bytes` / `tcp_dial_buffer_overflow_resets` /
  `udp_sent` / `udp_send_failed` + `tcp_streams_ok`（dial 成功进 relay）/
  `tcp_bytes_up` / `tcp_bytes_down` / `udp_unsupported` / `udp_unsupported_vless` /
  `udp_unsupported_anytls` / `udp_unsupported_other` / `udp_unsupported_log_suppressed`。
  **不存在** `tcp_flows_rejected` / `tcp_dials_throttled`（不引入上限，不是 0 值字段）。
  - **同步点唯一**：`Dataplane::poll_proxy_engine()` 每 tick 一次（`saturating_sub` delta）；
    Proxy 分类分支不再同步（避免同 tick 两次 delta）。
  - 字段语义写死：`proxy_tcp_streams` = 握手流数（Syn）；`proxy_tcp_streams_ok` =
    dial 成功流数；`proxy_tcp_bytes` **自本版本起为真实上行字节**（旧值恒 0，修死计数）；
    `proxy_tcp_bytes_down` 为下行；`proxy_dropped_no_proxy` 聚合「无出口」与「dial 失败」，
    同一事件只加一次。

### Workspace 生产接线（C1/D1-D9，scenarios/product/daemon_workspace_mount.toml，2026-10-02 冻结）

- **D1（配置）**：config dir 新增 `workspace.toml`，`[[workspace]]` 数组
  （`id`/`mountpoint?`/`author?`/`auto_commit_secs?`）；缺失文件 = workspace
  子系统不启用。内容变更/增删 → `NeedsRestart`。
- **D2（挂载点）**：显式 `mountpoint` 优先；缺省 `<data-dir>/mounts/<id>`；
  `data-dir` 派生为 `<config-dir>/data`（v1 不可配）。
- **D3（持久化）**：各 workspace 共享 `FsContentStore`（`<data-dir>/cas/`）；
  `InMemoryContentStore` 只留测试。
- **D4（state_root 锚）**：`<data-dir>/workspaces/<id>/state_root` 原子写；
  启动时 `open` 用；每次 commit 后更新。
- **D5（提交语义）**：不自动提交；`nexus workspace commit <id>` 经 LocalAPI
  `GET /localapi/v0/workspace/commit/<id>`；可选定时自动提交（默认关）。
  unmount/shutdown 时 WorkingSet 脏 → warn，**不静默提交**。
  R3：未 commit 的 WorkingSet 数据 daemon 重启即丢——写进挂载点 ≠ 持久化，
  只有 commit 后的数据才 crash-safe。
- **D6（orphan 清理）**：`boot_reconcile` 的 orphan OS resources 步骤对
  `workspace.toml` 的挂载点做幂等 `fusermount -u` 清理（busy 则 `-uz`），
  结果记入 reconcile 报告 `orphan_mounts_cleaned`（F1 收敛，2026-10-02）；
  `WorkspaceManager::start` 保留同样的幂等清理作兜底（自保护，双重清理无害）。
- **D7（关闭顺序）**：LocalAPI → Workspace unmount → Dataplane → N1 → TUN。
- **D8（降级）**：无 `/dev/fuse` → warn + workspace 子系统不启用，不静默 fallback。
- **D9（依赖边）**：nexusd（Composition Root）→ `nexus-platform-linux`；
  `nexus-platform-linux` 不反向依赖 `nexus-workspace`（只消费 portable
  `ProjectedWorkspace` trait）。
- **LocalAPI**：`GET /localapi/v0/workspace/mounts`（状态快照）；
  `GET /localapi/v0/workspace/commit/<id>`（显式提交）。
- 不变量：`ProjectedWorkspace::state_root()`（默认 `None` 的加法）是 daemon
  更新锚文件的唯一通道；FUSE 脏追踪（`has_uncommitted_changes`）只用于
  warn，不触发提交。

## Performance Budget

未定义性能预算的路径不得宣称“性能完成”。进入 hot path 后必须在 Contract 中增加 baseline、noise tolerance、warning threshold 与 blocking threshold。

- **N3-12 staging PutChunk 校验预算**（requirement-change 2026-10-27，见 N3-12 §5「每请求校验时机」）：
  - 机器门禁（确定性，计字节不计时间，读取层按文件角色计数）：单次 PutChunk 对 blob payload 的 `hash_prefix` 字节恰等于本请求入口时全部已确认 prefix 之和（入口完整校验不得删除、不得重复），且全部 blob payload 读取字节 ≤ 该和 + 1 个 chunk（全部落在已确认 prefix 内的幂等重试：≤ 该和 + 2×重试长度）；Get 读取恰等于该和。续算机制为 `nexus::n3_acceptance::Sha256Stream`。单测 `snapshot_staging::tests::verification_budget::*`（含请求进行中篡改的推迟失败关闭、入口校验先于任何状态改变）。
  - 时延基准（非门禁）：`snapshot_staging::tests::baseline::put_chunk_cost_by_upload_size`（`--release --ignored`）。baseline：2026-10-26 master，sandbox 无争用，32 MiB 上传 28.7 s；noise tolerance ±25%；warning：同条件 32 MiB > 15 s；blocking：> 30 s。

## Observability

稳定结构化字段优先于自由文本；如涉及 Session/Provider/Path/Workspace，应携带对应 correlation id。

## Recovery Semantics

任何持久状态或长期任务都必须定义 crash 后的 reconcile 行为。无持久状态的纯模块应保持可重建。

## Platform Constraints

平台专有代码只允许存在于 `nexus-platform-*` 或 Composition Root。Portable crate 必须通过相应 portability gate。

### N3-6 本地提供方 Task Service 增补

可选 task-api.toml 的 provider/workspace 配置启用真实 Get/ReadLogs/Cancel/
ListArtifacts/GetArtifact；authority 根固定 config-dir/data/n3/tasks。token
认证后由本地 N2 身份派生调用主体，启动先核实 authority/原 owner/Engine。
Submit 未具真实容量、唯一 SessionManager 和完整传输时拒绝，不构造占位接受。
协议及权限、错误、恢复、审计和 localhost 边界见
docs/N3-6-LOCALAPI-SECURITY-CONTRACT.md；不能把本批局部服务称为完整 N3。

### N3-8 容量与 Session 不变量

遵循 docs/N3-8-CAPACITY-SESSION-CONTRACT.md：私有接受 envelope v2 原子绑定预算/Task/key/pin；显式空根初始化，receipt 禁止降级重建。活 capacity-owner lease + fresh reconcile epoch 决定 Ready；Prepare/StartIntent/GC 在原 acceptance.lock 内重查。未知执行保留容量，真实 reap 只释放 runtime，disk charge 保留。明确 daemon config root 注入同一个 SharedSessionManager；可信内部绑定核实主体、Use、容量、实际 Session/持久 Plan，确认取消先 durable intent 再 Manager close/重载补偿。平台实现留在组合根，公网 Submit/完整下载能力不扩大。

### N3-9 接收器复用

本地 GetArtifact 继续原有逐页当前 Use、accepted scope、审计与真实内容校验。ArtifactDownload 迁到 nexus 组合根，原 nexusd::artifact_download 路径兼容 re-export；provider 私有 artifact authority IO 不扩大 public surface。验证 example 通过真实现有 Engine/TaskOwner 产生并发布产物，随后由正常 daemon 冷启动复核，禁止 production fixture API 或伪造终态。范围见 docs/N3-9-ARTIFACT-CLI-CONTRACT.md；Submit 仍明确拒绝。

### N3-11 正式提供方初始化与检查（契约草案）

按docs/N3-11-PROVIDER-INIT-CONTRACT.md新增本机task-provider init/check，先于config-folder参数分派。init仅fresh显式既存私有根，从原N2身份record和FileTaskAcceptanceStore::provision_capacity建立原authority，不添加反向app依赖、第二套capacity owner或wire操作。journal及固定inode lease绑定原root、scope、canonical policy和原identity；qualified中断仅恢复原字节，缺失/损坏authority拒绝重建。完成后相同init启动前后changed=false，不reprovision或推进epoch；check直接核实既有文件且零写入，不调用会初始化/清理的storage open。

managed marker在身份ensure、N2 assembly、reconciliation和token创建前核实，pending/corrupt不READY；compatibility serve及Task loader同样检查，legacy unmanaged保持原行为。核实完成managed provider是正常config-folder合法subsystem，N3-only需要运维者明确no-TUN；原普通空根拒绝不变，不生成占位proxy/network。初始Pending不是活Ready，daemon仍经原owner恢复；不创建grant/name/ad/Task/Session/Engine/token或开放Submit/上传。仅Linux、Rust1.85，无新deps/crate/unsafe；输出schema1与phase/mutation_may_have_applied，具体权限、inode、恢复和有限E4见草案。实现须等待实际RED及冻结摘要。

### N3-12 显式暂存预算与 durable upload owner

按 docs/N3-12-SNAPSHOT-STAGING-CONTRACT.md，新增 task-provider staging-init 与独立 /localapi/v1/snapshot 路由。固定原身份/root/scope，namespace外保留初始化marker；single authoritative ledger记录reservation/owner/key/manifest/durableprefix/transactionintent，预算和serialization cap在任何payload前保证。当前Use/audit先于staging lease；confirmed prefix不得重置，Cancel物理清理fsync后返还charge。normal/serve在identity ensure/启动写入/token/READY前恢复，损坏拒绝READY。原任务capacity/receipt/GC catalog/wire不变，Staged不是Task接受，不装配执行/远端认证。
