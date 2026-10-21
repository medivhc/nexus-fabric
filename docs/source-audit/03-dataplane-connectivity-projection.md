# 03 · 数据面与连接片区审计（Shard C：connectivity / projection / network / path / dns / ingress）

> 本文仅依据仓库 e6ccf8b 的源代码与机器配置（.rs/Cargo.toml/*.toml）撰写，未采信任何叙述性文档；结论行号均可复核。

## 0. 片区范围与行数总表

本片区为"连接与数据面膜"，共 6 个 workspace 成员，src 实测行数（`find .../src -name '*.rs' | xargs wc -l`）与 `#[test]`/`#[tokio::test]` 实测数（`rg -c`）：

| crate | src 行数 | #[test] 数 | 在片区中的角色 |
|---|---:|---:|---|
| crates/nexus-connectivity | 21,262 | 397 | 隧道/加密/打洞/中继/包调度的 delivery 层底座（含大量纯逻辑骨架） |
| crates/nexus-projection | 11,397 | 163 | L3 TUN↔fabric 隧道核心 + SOCKS5/HTTP 显式入站 |
| crates/nexus-network | 3,551 | 36 | N1 Universal Connectivity 装配 portable core（VPI↔mesh 转发泵） |
| crates/nexus-path | 2,034 | 40 | 选路打分/切换/竞速决策（零 socket） |
| crates/nexus-dns | 1,634 | 33 | 纯内存 DNS 分类/缓存/路由（注入式 Resolver） |
| crates/nexus-ingress | 1,228 | 35 | SOCKS5/HTTP 代理握手状态机 + IPv4 包解析（纯函数） |
| **合计** | **41,106** | **704** | |

> 注：用户给的 projection 行数 14,364 含 `examples/`；本审计以 `src/` 为准（11,397 行）。connectivity 的 21,262 与用户口径一致。

---

## 1. crates/nexus-ingress（1,228 行 src：lib.rs 1,030 + ip_packet.rs 198）

### 实际职责（从代码推断）
一个**零 I/O 的协议解码库**。它"入站"但并不监听 socket：只提供 SOCKS5/HTTP 代理握手的**增量状态机**（`feed` 纯函数推进）与 IPv4 包头解析，把字节流解析成 `FlowContext`，真正的 TCP 监听由 `nexus-projection/src/semantic.rs` 完成。

### 关键类型 / pub API / 入口
- `Socks5Handshake`（`crates/nexus-ingress/src/lib.rs:145`）：状态机 `Greeting→MethodSelected→UserPassAuth→Established`；`feed(&mut self, data: &[u8])` 返回当前状态+待发响应（lib.rs:180 起）。仅支持 CONNECT(0x01)；BIND/UDP ASSOCIATE 显式拒绝，REP=0x07（lib.rs:240-244）。ATYP 支持 IPv4(1)/域名(3)/IPv6(4)；RFC1929 user/pass 仅校验帧格式，不做授权（lib.rs:216 注释自认）。
- `HttpProxyHandshake`（lib.rs:465）：CONNECT 回 `200` 后裸中继；绝对形式 GET/POST 改写为 origin-form 作 `upstream_prefix`（lib.rs:580-583）；拒绝 origin-form 请求行与 `https://` scheme（lib.rs:538, 661）。
- `parse_ipv4_packet`（`crates/nexus-ingress/src/ip_packet.rs:60`）：纯函数，仅 IPv4 + TCP/UDP；不校验校验和、不重组分片、不解 ICMP、不支持 IPv6（ip_packet.rs:58 注释）。
- `FlowContext` 构造器：`from_socks5`(lib.rs:37)、`from_http`(lib.rs:43)、`from_virtual_packet_interface`(lib.rs:49)、`from_native_api`(lib.rs:55)。

### 依赖
workspace 内：仅 `nexus-domain`（`FlowContext`/`FlowOrigin`/`ResourceId`）。无第三方依赖。

### 实现度判定：`implemented`
证据：状态机逻辑真实且被 `nexus-projection/src/semantic.rs:20` `use nexus_ingress::{HttpProxyHandshake, HttpProxyState, Socks5Handshake, Socks5State}` 真实调用（`do_socks5` semantic.rs:235、`do_http` semantic.rs:288 驱动握手循环）。本 crate 自身不开 socket 是设计使然（纯函数解码），非空转。

### stub / TODO / 空转清单
- 无 `unimplemented!`/`todo!`。`UnsupportedCommand`/`UnsupportedAddressType`/`UnsupportedScheme` 是协议层显式拒绝（返回 REP=0x07/405），非占位。
- 握手注释自认"user/pass 仅校验帧格式不授权"（lib.rs:216）——这是 P0 简化，非错误。

### 测试
35 个 `#[test]`（全在 `src/lib.rs` 与 `src/ip_packet.rs` 末尾 `mod tests`）。实测覆盖：握手各状态分支、BIND/UDP-ASSOCIATE 拒绝、域名/IPv6 ATYP、HTTP CONNECT 200 与 405、IPv4 包截断/IPv6/ICMP 拒析、FlowContext 构造。均为内存字节喂入测试，无真实 socket。

---

## 2. crates/nexus-dns（1,634 行 src：lib.rs 903 + unified.rs 731）

### 实际职责（从代码推断）
一个**纯内存 DNS 分类/缓存/路由库**，本身**不做真实 DNS 传输**。它定义注入式 `Resolver` trait，所有真实 UDP/TLS/HTTPS DNS 收发均由 Composition Root 注入；本层只负责"先查 hosts/mesh/fake-ip，未命中才上游"的分类逻辑与正/负缓存。

### 关键类型 / pub API / 入口
- `Resolver` trait（`crates/nexus-dns/src/lib.rs:158`）：注入式 trait；lib.rs 注释明确"P0 由测试与 E4 场景注入内存 mock"（lib.rs:152-153）。
- `DnsRuntime`（lib.rs:432）：正缓存 + RDRC 负缓存 + 环路守卫 + Exit-DNS Binding；`resolve`(lib.rs:479)、`resolve_exit_binding`(lib.rs:539)、`to_plan_extension`(lib.rs:577)。
- `MultiServerDns`（lib.rs:325）：多 server 路由，`DnsRouter`(lib.rs:263) 规则首匹配，按 (server,name,qtype) 隔离缓存。
- `UnifiedDns`（`crates/nexus-dns/src/unified.rs:321`）：单一查询分类器，顺序 hosts > mesh > fake-ip > upstream（`classify` unified.rs:359、`resolve` unified.rs:387）。
- `FakeIpPool`（unified.rs:163）：198.18.0.0/15 顺序分配，by_domain/by_ip 双向映射，TTL 回收。
- 注入 trait：`MeshNameResolver`(unified.rs:97)、`ProxyClassifier`(unified.rs:107)。

### 依赖
workspace 内：仅 `nexus-domain`（`NetworkPlanExtension`）。无第三方。无任何 socket/tokio。

### 实现度判定：`implemented`（但"真实解析"能力刻意不在本 crate）
证据：分类/缓存/路由逻辑真实且自洽。本 crate **不是**硬编码返回——它真的按分类顺序查询并缓存；但它**不接真实 DNS 服务器**，`Resolver` 由外部注入（lib.rs:158）。注释 unified.rs:8-9、lib.rs:324 明确"不发起真实网络"。判定为 implemented：作为分类/缓存库真实可用；"真实 DNS 解析"是注入点的职责，源码中无法确认线上注入的是哪个 Resolver 实现。

### stub / TODO / 空转清单
- 无 `unimplemented!`/`todo!`。本 crate 不发包是设计（注入式），不算空转。

### 测试
33 个 `#[test]`。覆盖：正/负缓存命中与过期、环路守卫、fake-ip 分配回收、多 server 路由隔离、hosts/mesh 短路、exit binding。均为内存断言，`now_secs` 由测试注入。

---

## 3. crates/nexus-path（2,034 行 src：lib.rs 1,105 + ewma.rs 110 + fallback.rs 420 + race.rs 399）

### 实际职责（从代码推断）
一个**纯选路决策/调度库**，自身**零 socket、零网络**（std-only，用 std::thread 而非 tokio）。它根据外部喂入的路径统计，用 EWMA 打分做迟滞切换；并提供 Direct→Proxy→Turn 的候选展开与 scoped-thread 竞速拨号（拨号本身经注入 trait）。

### 关键类型 / pub API / 入口
- `PathManager`（`crates/nexus-path/src/lib.rs:392`）：候选路径 Direct/Mesh/Turn/Proxy；打分 `instant_score`(lib.rs:178) = `W_RTT*1000/(1+rtt) + W_LOSS*100*(1-loss) + W_TP*10*log10(1+Mbps) - W_COST*cost`；迟滞 `hysteresis_pct` 默认 0.20 + `switch_hold_ms` 默认 3000（lib.rs:106-117）；外部喂统计入口 `on_stats`(lib.rs:508)。
- **空转点**：`send_heartbeat_stub`（lib.rs:349-351）函数体为空；注释 "P0: stubbed. P1: send UDP ping"。`probe_loop`(lib.rs:354) 真起 std::thread，每 100ms 循环、按 `probe_interval_ms` 遍历候选调用 `send_heartbeat_stub`——**但不发任何包**。
- `race_connect`（`crates/nexus-path/src/race.rs:80`）：真 scoped thread 竞速，但实际拨号由注入 trait `PathConnector::connect`(race.rs:46) 完成；本 crate 不开 socket。
- `FallbackChain::expand`（`crates/nexus-path/src/fallback.rs:97`）：固定 Direct→Proxy→Turn。

### 依赖
`Cargo.toml` 内 `[dependencies]` 为空——零 workspace 依赖、零第三方。

### 实现度判定：`partial`
证据：打分/迟滞/切换/竞速逻辑真实，且被 `crates/nexus-projection/src/path_link.rs:25,667`（`use nexus_path::{...}`）真实调用并在 `handle_event`(path_link.rs:265) 触发 `FabricConn::rebind()`。缺口：**主动探测（发包测 RTT/loss）是空函数**（lib.rs:349），路径测量完全依赖外部 `on_stats` 喂入，本 crate 自己不产生任何测量数据。

### stub / TODO / 空转清单
- `crates/nexus-path/src/lib.rs:349`：`fn send_heartbeat_stub(_local, _remote) {}` —— 空函数体，probe 线程调用它但不发包。

### 测试
40 个 `#[test]`。覆盖：迟滞阈值、hold 窗口、missed-failover 行为、NAT 冻结合约、`PathEvent::Adopted` vs `Switched`、reannounce 保留观测。均为喂入统计的内存决策测试。

---

## 4. crates/nexus-network（3,551 行 src：lib.rs 181 + n1/{mod 286, config 807, pump 835, link 719, session 500, bridge 223}）

### 实际职责（从代码推断）
N1 Universal Connectivity 的**装配 portable core**：把"已注入的连接/监听/发现/VPI"编排成 VPI↔mesh datagram 转发 + keepalive 观测 + 连接表。自身不开 socket/不发 QUIC，所有 I/O 经注入 trait。

### 关键类型 / pub API / 入口
- 注入 trait（`crates/nexus-network/src/n1/mod.rs`）：`N1Connection`(mod.rs:129)、`N1Dialer`(mod.rs:191)、`N1Listener`(mod.rs:198)、`N1Discovery`(mod.rs:204)、`N1EventSink`(mod.rs:211)；`N1PeerId`(mod.rs:30, ed25519 32B hex)、`N1Error`(mod.rs:91)、`N1Event`/Kind/Disposition(mod.rs:218-256)。
- `VpiPump`（`crates/nexus-network/src/n1/pump.rs:199`）：真线程包泵——`uplink_loop`(pump.rs:330) 从注入的 `VirtualPacketInterface` 读 IPv4 → 最长前缀路由 `route`(pump.rs:228) → `conn.send_datagram`；`downlink_worker`(pump.rs:443) `recv_datagram` → `vpi.send`。带 supervisor 线程 + panic hook + poison 恢复。`DATAGRAM_CAP=1200`。
- `LinkStateWatcher`（`crates/nexus-network/src/n1/link.rs:81`）：真线程——`pinger_loop`(link.rs:329) 发 16B `N1KALIVE`+seq ping 读 pong；`responder_loop`(link.rs:357) accept 回 pong；心跳超时(link.rs:224) → `recover`(link.rs:247) `discovery.resolve` → `conn.rebind()`，指数退避 3s/6s/12s/上限 30s。
- `N1SessionManager`（`crates/nexus-network/src/n1/session.rs:55`）：per-peer 单连接表，`dial`(session.rs:82)/`insert_accepted`(session.rs:98)/`accept_loop`(session.rs:128)/`remove`(session.rs:172，先 close 再 watcher.shutdown 解死锁)。
- `N1MeshBridge`（`crates/nexus-network/src/n1/bridge.rs:34`）：send_to_mesh 最长前缀路由 + `connection_for` + `send_datagram`，薄胶水。
- `lib.rs`：`NetworkSession`(lib.rs:85 establish) 经注入 `NetworkTransport` 发请求帧收响应帧提取 HTTP 状态码——薄壳。
- `n1/config.rs`：手写 TOML 子集解析器 `N1Config::parse_toml`(config.rs:135)，fail-fast 未知键报错；`BoostConfig`(config.rs:78)。

### 依赖
workspace 内：`nexus-dns`、`nexus-platform`（提供 `VirtualPacketInterface`/`PacketCarrier` 等 trait）及其他；`Cargo.toml` 还声明依赖 nexus-path/nexus-nat-wireup/nexus-nat-quality/apps 等。

### 实现度判定：`implemented`
证据：pump/watcher/session 逻辑真实且被生产装配——`apps/nexusd/src/assembly.rs:87` `assemble_n1` 真构造 `N1MeshBridge`；`apps/nexus/src/network.rs` 为 `N1Connection`/`N1Dialer`/`N1Discovery` 写真实适配（包 `FabricConn`）。物理 socket 层在本 crate 之外是注入式设计。

### stub / TODO / 空转清单
- 无 `unimplemented!`/`todo!`。
- 弱测试点（非生产空转）：`n1/bridge.rs` 测试（bridge.rs:161-201）只内联重算路由，未真构造 bridge——注释 bridge.rs:157-159 自认"we can't easily construct a real N1SessionManager without dialer/discovery"。

### 测试
36 个 `#[test]`。覆盖：最长前缀路由匹配、keepalive 状态迁移、连接表 insert/remove、TOML 解析 fail-fast、discovery→rebind 退避计数。注入 mock trait 测试。

---

## 5. crates/nexus-projection（11,397 行 src；最大应用核心）

### 实际职责（从代码推断）
**L3 TUN↔fabric 隧道核心**。"投影"= 把 OS 网络栈的 IPv4 包投影到 fabric 的 per-peer datagram 抽象：从真实 TUN 读 IP 包 → 分类到 MeshPeer/Egress/Drop → 加 1 字节 intent 帧头发给 peer；收 peer datagram → 按 intent 分发回 TUN 或本机 egress。同时承载 SOCKS5/HTTP CONNECT 显式入站与 TCP/UDP 本机 egress。

### 关键类型 / pub API / 入口
- `Projection`（`crates/nexus-projection/src/lib.rs:669`）：起 4 个真线程 `uplink_loop`/`downlink_loop`/`egress_recv_loop`/`tcp_poll_loop`。Uplink 读 TUN → classify → 加 intent → `transport.send_to`；Downlink 读 `transport.recv` → 按 intent 分发。配置 `ProjectionConfig`(lib.rs:173)。
- `FabricTransport`（`crates/nexus-projection/src/transport.rs:133`）：真包 `nexus-fabric` 的 `FabricConn`，在真线程上泵 `recv_datagram`。
- `UnifiedRouter`（`crates/nexus-projection/src/routing.rs:154`）：虚拟子网前缀 fast path → domain 规则 → `SimpleRuleEngine` CIDR 首匹配。
- `RealUdpEgress`（`crates/nexus-projection/src/egress.rs:546`）：每流一个真 `std::net::UdpSocket`，真 `send_to`/`recv_from`；NAT 表按 translated 5-tuple 反查重建 IP 回包。
- `TcpTerminator`（`crates/nexus-projection/src/tcp.rs:492`）：originator 侧用 **smoltcp** 在用户态本地终结 TCP（本地握手→把字节流变 STREAM intent 帧）。
- `TcpRelay`（tcp.rs:1002）：egress 侧用真 `std::net::TcpStream` connect + 中继；connect 跑在 worker 线程不阻塞 downlink。
- `SemanticIngress`（`crates/nexus-projection/src/semantic.rs:115`）：真 `TcpListener::bind`(semantic.rs:126) 监听本地 SOCKS5/HTTP CONNECT，accept 线程 + per-conn worker 线程；握手用 nexus-ingress 纯状态机；路由走同一 `Router` 决策链。
- 其他：`dns.rs` 真 DNS wire sniffer + 缓存；`process.rs` Linux /proc 解析 + Windows iphlpapi FFI 真实进程归属；`multipath.rs` 纯内存调度 + 重排；`path_link.rs` 真把 `PathEvent::Switched` 转 `FabricConn::rebind()`。

### 依赖
workspace 内：`nexus-ingress`、`nexus-path`、`nexus-fabric`、`nexus-domain`。第三方：`smoltcp`（TCP 终结）、`tun-rs`（真实 TUN 设备，见 `tun_rs_device.rs`）。

### 实现度判定：`implemented`
证据：TUN/socket/smoltcp 全是真的。被 `apps/nexusd/src/assembly.rs`、`apps/nexusd/src/workspace.rs:416`、`crates/nexus-nat-wireup`、`engineering/nexus-harness` 装配。4 个背景线程真循环干活。

### stub / TODO / 空转清单
- `crates/nexus-projection/src/lib.rs:1162`：`on_path_event` 只 `self.path_switches.fetch_add(1)`，注释 "Future: trigger FabricConn rebind / path migration here"。但实际 rebind 已在 `path_link.rs:265 handle_event` 里做，故此处仅计数观测，非关键路径空转。
- 2 处 `unreachable!()`（lib.rs:803、lib.rs:1313）——防御性，注释标注不可达。

### 测试
163 个 `#[test]`。大量真 loopback TCP/UDP 集成测试：`real_egress_reply_reverse_nat`(egress.rs:1158) 用真 UdpSocket 回环；`relay_connects_and_relays`(tcp.rs:1576) 起真 TcpListener 回显；`semantic_ingress_bind_and_close`(semantic.rs:965) 真 bind+accept。部分真网络测试在 sandbox 跳过（注释 egress.rs:1066-1068 说明 EPERM）。

---

## 6. crates/nexus-connectivity（21,262 行 src，34 个文件；片区最大）

### 实际职责（从代码推断）
delivery 层共享底座。**绝大多数是 portable 纯逻辑骨架**（状态机/决策/编解码/密码学/包算法），自身不开 socket；物理 I/O 经注入 trait（`PacketCarrier`/`VirtualPacketInterface`/`TurnTransport`/`RelayTransport`/`LinkProbe`）由 apps/nexus Composition Root 注入。但其中隧道编排、密码学、STUN/UDP 打洞、TURN 编解码、数据面管线是真材实料并被驱动。

### 关键类型 / pub API / 入口（真材实料部分）
- `VirtualSubnetTunnel`（`crates/nexus-connectivity/src/virtual_subnet.rs:422`）：真隧道编排。`read_vpi_and_route`(virtual_subnet.rs:1601) 读 VPI → `send_ip_packet`(virtual_subnet.rs:1295) 解析下一跳 → 加 `TunnelFrameHeader` → 管线/加密 → `carrier.send_to`；`recv_and_deliver`(virtual_subnet.rs:1411) 从 carrier 收 → 反解/解密 → 写 VPI 或转发。打洞状态机 `begin_hole_punch_multi`(virtual_subnet.rs:1033)/`punch_tick`(virtual_subnet.rs:1081)/`handle_hole_punch_frame`(virtual_subnet.rs:1171)；握手 `begin_handshake`(virtual_subnet.rs:700)/`accept_handshake`(virtual_subnet.rs:738)/`complete_handshake`(virtual_subnet.rs:824)。
- `encryption.rs`：真密码学——X25519(`x25519-dalek`) ECDH、HKDF-SHA256、ChaCha20Poly1305(`ring`) AEAD、滑动窗口防重放；WireGuard 式三 DH 握手 `derive_authed_keys`；`encrypt_frame`/`decrypt_frame`(encryption.rs)。
- `nat.rs`：真 UDP socket——`StunClient::get_mapping`(nat.rs:131) `UdpSocket::bind`(nat.rs:122) + `send_to`/`recv_from`(nat.rs:143,147) 做 STUN Binding；`HolePuncher::punch`(nat.rs:223) 真发 hello/ack/ping。
- `turn.rs`：真 RFC5766/5389 STUN/TURN wire 编解码 + HMAC-SHA1 `MESSAGE-INTEGRITY`；`TurnTransport` trait(turn.rs) 注入，`MockTurnTransport` 离线回环。
- `dataplane_pipeline.rs`：真把 firewall→qos→compression→fragmentation 串成每包 `NXP1` 管线（发送序 firewall→qos→compress→frag，接收序反向）。
- `coord.rs`：真 `Coordinator` 心跳注册表 + `VirtualIpAllocator` CIDR 顺序分配。
- `lib.rs`：`establish`(lib.rs:309) 纯函数建连评估；`ConnectivityRuntime`(lib.rs:381) 双 trait 注入门控（未认证 `send_frame` 直接拒、不碰 carrier，lib.rs:417-421）；`LinkActivator`(lib.rs:555) 委托注入 `LinkProbe`。

### 纯决策骨架（注释自标"真实网络集成留 TODO"，不 spawn 不 socket）
`relay.rs`、`connection_pool.rs`、`health_check.rs`、`node_priority.rs`、`failover.rs`、`smart_retry.rs`、`reconnect.rs`、`graceful_exit.rs`、`discovery_enhanced.rs`、`group_isolation.rs`、`bandwidth_policy.rs`、`log_level.rs`、`config_hot_reload.rs`、`node_tags.rs`、`mesh_dns.rs`、`traffic_stats.rs`、`certificate_manager.rs`、`compression.rs`。这些是正确的状态机/决策引擎，但真实 socket/持久化/调度接线留 TODO。`routing.rs` 头部 `#![allow(deprecated)]`（§12.57 退役模块）。

### 依赖
workspace 内：`nexus-platform`、`nexus-domain`、`nexus-measurement`。第三方：`ring`/`x25519-dalek`（密码学）、压缩库等。

### 实现度判定：`partial`
证据：核心隧道/加密/STUN/TURN 编解码真实且被 `apps/nexus/src/mesh.rs:run_with_save`(mesh.rs:200 附近) 真循环驱动（每 tick `tunnel.recv_and_deliver` + `drive_punches`）。缺口：约 1/3 模块是纯决策骨架，真实 socket/持久化/调度未接线（各文件头部 TODO 清单）；本 crate 自身无 tokio task。

### stub / TODO / 空转清单
- 无 `unimplemented!`/`todo!`/`unreachable!`。
- 大量模块头部自标 TODO（见上"纯决策骨架"清单），属"逻辑在、I/O 未接"。
- `fib_resolver.rs:85`：`NullFibResolver` 空实现恒返回 None（测试用/禁用 FIB）。
- `encryption.rs:649`：发送多少帧后轮换会话密钥——P0 仅记录阈值，轮换逻辑 TODO。

### 测试
397 个 `#[test]`（全片区最多）。覆盖：加解密往返/防重放/篡改 AAD、握手三 DH 派生、STUN 编解码、TURN 401 挑战回环、隧道转发/前缀路由/打洞状态机、firewall 首匹配、QoS 令牌桶、CAKE DRR、分片重组。注入 mock VPI/Carrier 为主，nat.rs 用真 loopback UDP。

---

## 7. 片区内跨 crate 调用主干

按 rg 全仓验证：

1. **projection → fabric**：`FabricTransport`(transport.rs:133) 包 `nexus_fabric::FabricConn`，真泵 `recv_datagram`。
2. **projection → path**：`PathLink`(path_link.rs:25 `use nexus_path::{...}`) 在 `handle_event`(path_link.rs:265) 把 `PathEvent::Switched` 转 `FabricConn::rebind()`。
3. **projection → ingress**：`SemanticIngress`(semantic.rs:20) `use nexus_ingress::{Socks5Handshake, HttpProxyHandshake}` 复用其握手状态机。
4. **network → platform**：`VpiPump`/`N1SessionManager` 被 `apps/nexusd/src/assembly.rs:87 assemble_n1` 装配；`apps/nexus/src/network.rs` 为 N1 trait 写真实适配。
5. **connectivity → platform**：`VirtualSubnetTunnel` 被 `apps/nexus/src/mesh.rs:124,545` 持有并由 `run_with_save` 真循环驱动；nat.rs 真 UDP；encryption 真密码学。
6. **dns**：纯内存分类，`Resolver` trait(lib.rs:158) 注入，无反向依赖。
7. **ingress**：纯函数，被 projection/semantic 调用。

### 与片区外（proxy/daemon/CLI）的真实接线点
- `apps/nexusd/src/assembly.rs:87`：装配 N1（network）；`apps/nexusd/src/workspace.rs:416`：`WorkspaceProjection::new`（projection）。
- `apps/nexus/src/mesh.rs:124,545,run_with_save`：connectivity 隧道主循环。
- `apps/nexus/src/subnet_cli.rs:538,583,602,619,680`：TOML→VirtualSubnetTunnel 装配。
- 片区外调用方（rg 验证存在，非 dead）：`crates/nexus-nat-wireup`、`engineering/nexus-harness/src/run_scenario.rs:41,174`。

---

## 8. 片区小结

**真实能力**：这是一套相当完整的 L3 数据面——真实 TUN（tun-rs）、真实 UDP/TCP egress（projection）、用户态 TCP 终结（smoltcp）、真密码学（X25519+ChaCha20Poly1305）、真 STUN/UDP 打洞、真 TURN wire 编解码、真实 SOCKS5/HTTP CONNECT 入站、VPI↔mesh 转发泵。跨 crate 调用主干清晰且被 nexusd/nexus CLI 真实装配，非 demo。

**最大缺口**：
1. **主动路径测量空转**：`nexus-path` 的 probe 线程调用空函数 `send_heartbeat_stub`(lib.rs:349)，自己不发包测 RTT/loss，统计全靠外部喂——选路决策的输入源在本仓内未闭环。
2. **connectivity 约 1/3 模块是纯决策骨架**：relay/connection_pool/health_check/failover/smart_retry/reconnect 等逻辑正确但真实 socket/持久化/调度未接线（头部 TODO）。
3. **dns 不做真实解析**：`Resolver` 是注入 trait，本仓内看不到线上注入的真实 DNS server 实现（源码中无法确认注入点的具体实现）。
4. **network/connectivity 的物理 socket 层全部在本 crate 之外**：本片区 crate 多为 portable core，真实 UDP/QUIC socket 在 nexus-platform-* 与 apps/nexus 内（超出本片区范围）。
