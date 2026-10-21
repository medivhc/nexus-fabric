# 06 · Nexus-Fabric 实现状态矩阵总表（51 个 workspace 成员）

> 本文仅依据仓库 e6ccf8b 的源代码与机器配置（.rs/Cargo.toml/*.toml）撰写，未采信任何叙述性文档；结论行号均可复核。
>
> 成员口径：根 `Cargo.toml` `[workspace] members` 共 **51 个** = 3 apps + 47 crates + engineering/nexus-harness，本表逐一列齐、零遗漏。
> 行数口径：`find <member> -name '*.rs' | xargs wc -l`（含该成员 examples/、tests/）。
> 实现度：`implemented` / `partial` / `stub` / `dead`，定义见 AUDIT-SPEC 第 3 节；证据为分片审计回验后的 `文件:行号`。

## 0. 总览计数

| 实现度 | 数量 | 成员 |
|---|---|---|
| implemented | 36 | 见下表 |
| partial | 8 | apps/nexus、apps/nexusd、connectivity、path、transport、outbound-{shadowsocks,trojan,vmess} |
| stub | 6 | apps/nexus-platform-host、diagnostics、delivery、platform-{macos,android,ios} |
| dead | 1 | nexus-proto |

## 1. 三个 apps

| 成员 | 行数 | 实际职责（一句话） | 实现度 | 关键缺口 | 关键证据 |
|---|---:|---|---|---|---|
| apps/nexus | 49,184 | 组合根 crate（既出 CLI 二进制，又被 nexusd 复用）：瘦客户端命令面 + N2 资源访问本地闭环 + daemon 复用的快照/装配函数 | **partial** | observability 17 个观察快照全为硬编码演示数据；proxy 出站 relay/vmess/socks5 硬编码 Err；schedule 触发只生成 task id 不执行；system-proxy/autostart 仅 Windows，network up/artifact 下载/task-provider grant 仅 Linux | apps/nexus/src/main.rs:231,345-355；lib.rs:5237,5244,5250；observability.rs:41-46,391 |
| apps/nexusd | 28,877 | daemon 组合根：TUN 数据面线程、手写 HTTP/1.1 LocalAPI、（Linux）FUSE workspace、N2 session sweeper、boot reconcile | **partial** | N3 Submit 硬编码 Unsupported；executor.run 生产无调用方；镜像白名单空、容量账本未 provision；DNS upstream/mesh resolver 为 stub；flow-session/sync-transport/nat-switch/requester-store 生产 dead；hot-reload 只打日志 | apps/nexusd/src/main.rs:756,599；task_service_provider.rs:229,87；dataplane.rs:1428-1451 |
| apps/nexus-platform-host | 58 | 薄壳二进制：Windows feature 下打印静态 VPI 能力 JSON，否则打印 bootstrap 字符串 | **stub** | 无 daemon/监听/装配；linux/macos/android/ios feature 无代码分支 | apps/nexus-platform-host/src/main.rs:24,30 |

## 2. 47 个 crates

| 成员 | 行数 | 实际职责（一句话） | 实现度 | 关键缺口 | 关键证据 |
|---|---:|---|---|---|---|
| nexus-domain | 3,762 | 全仓纯核心模型：标识/Intent/Constraint/Plan/错误处置 + 版本化 N3 Task DTO 与 digest（零依赖，约 25 个 crate 依赖它） | implemented | 无 | src/lib.rs:282,497,906；task/mod.rs:339 |
| nexus-auth | 869 | 纯授权判定：PSK 校验、Grant 表 6 步判定、ed25519 派生 Principal、TOFU 信任库、审计 sink | implemented | 审计 sink 由外部注入，crate 无 I/O | src/lib.rs:63,262,347 |
| nexus-registry | 1,945 | 内存 Provider 视图 + 广告/本地名表 + 5 种 N2 控制帧 wire 编解码与认证通道 | implemented | 纯内存，持久化在外部 | src/lib.rs:64；control_frame.rs:78,489 |
| nexus-discovery | 5,963 | mesh 发现与路由：mDNS/LSA/配对纯状态机 + SPF/ECMP/K-最短/不相交路径 + FIB | implemented | 零 I/O，真实 socket 在组合根 | mdns.rs:28；routing.rs:130,304,446,1192 |
| nexus-policy | 590 | 动作链策略引擎：profile_eq/destination_prefix 匹配→AddConstraint/Enrich/Select/Reject | implemented | 匹配维度仅 2 维（无端口/协议/IP 段/进程） | src/lib.rs:262,300 |
| nexus-plugin | 981 | 混淆传输插件点：ObfuscateTransport trait + 静态注册表 + plain/xor 内置 | implemented | 仅同步 std::net::TcpStream 包装 | src/lib.rs:66；registry.rs:18；builtin.rs:67 |
| nexus-storage | 1,398 | 本地文件持久化：FileKvStore 原子写 + 崩溃恢复 journal + CAS ContentStore | implemented | 仅本地 fs | kv.rs:84,292,358；fs.rs:20 |
| nexus-session | 2,304 | 会话状态机：phase 转移、终态一次提交、取消令牌、崩溃 reconcile、Manager | implemented | 无 | src/lib.rs:155,485,1298 |
| nexus-planner | 1,227 | Core Planner：能力过滤→连通门→RTT/局部性打分→产出 Plan | implemented | execution_strategy 恒 "direct"、extension 恒 Network（compute/service/workspace 无差异化规划） | src/lib.rs:202,255,334,439 |
| nexus-flow-session | 1,300 | 逐流编排：policy.evaluate→planner.plan→注入 ConnectivityEstablisher | implemented | 建连由外部 trait 注入 | manager.rs:23,68；chain.rs:71 |
| nexus-scheduler | 548 | 内存定时器：register/cancel/tick/snapshot/restore（BTreeMap） | implemented | 快照落盘在 apps/nexus schedule_cli | src/lib.rs（接线见 schedule_cli.rs:13,69） |
| nexus-service | 103 | Service 帧握手契约：发 CONNECT 等 READY | implemented | `Connecting` 为死变体、无 close；0 自测 | src/lib.rs:20,83,92 |
| nexus-control-api | 883 | 前端统一控制面契约：22 命令枚举 + DTO + ControlService trait + N3 wire | implemented | 纯契约，实现 control_service.rs | src/lib.rs:17,104,148 |
| nexus-measurement | 168 | 链路测量纯 DTO：RTT/loss/jitter + MeasurementTable + LatencyProbe trait | implemented | crate 内零 I/O，探针在 apps（lib.rs:5874,5911） | src/lib.rs（全） |
| nexus-fabric | 3,722 | 基于 quinn-proto（patched）sans-IO 的 QUIC/mTLS 会话层：可靠流/数据报/PeerId pinning（**非顶层聚合**，是底层传输） | implemented | 无（依赖 patched vendor quinn-proto） | lib.rs:86,323；driver.rs:1341；cert_strict.rs |
| nexus-connectivity | 21,262 | delivery 层底座：真隧道编排/真密码学/真 STUN UDP/打洞 + 约 1/3 纯决策骨架 | **partial** | 约 1/3 模块（relay/connection_pool/health_check/failover/smart_retry/reconnect 等）真实 socket/持久化/调度未接线；密钥轮换 TODO | virtual_subnet.rs:422；encryption.rs；nat.rs:131；lib.rs:309 |
| nexus-path | 3,215 | 选路打分/迟滞/竞速决策（零 socket，std-only） | **partial** | 主动探测 `send_heartbeat_stub` 为空函数，probe 线程不发包，统计全靠外部 on_stats 喂入 | lib.rs:349,392；race.rs:80 |
| nexus-transport | 94 | 同步 TCP u32BE 长度前缀 FrameStream | **partial** | doc 自称的 Datagram/Mux/Reuse/Backpressure 均不存在 | src/lib.rs:3,42-91 |
| nexus-outbound-shadowsocks | 461 | SS AEAD 记录帧 + SOCKS 地址编解码原语（chacha20-ietf-poly1305） | **partial** | 无 connect/relay，从不持有 TcpStream，纯原语库 | src/lib.rs:279,355,368 |
| nexus-outbound-trojan | 502 | Trojan 请求行编解码 + rustls 配置原语 | **partial** | `TrojanAdapter::new` 丢弃密码（:241）；无转发循环 | src/lib.rs:127,241,356 |
| nexus-outbound-vmess | 220 | 单帧 chacha20poly1305 AEAD 自洽原语 | **partial** | 无 VMess 请求头/建连/转发 | src/lib.rs:134,152,163 |
| nexus-outbound-vless | 2,060 | 完整 VLESS：握手头/UDP-over-TCP/XTLS-Vision 读写状态机 | implemented | adapter handoff 离线，真实建连在组合根 | src/lib.rs:365,667,882,1067 |
| nexus-outbound-anytls | 1,795 | AnyTLS 多路复用 client/server 握手与会话协议 | implemented | adapter handoff 离线 | src/lib.rs:755,903,959 |
| nexus-outbound-hysteria2 | 3,292 | 真 QUIC（quinn-proto）+ H3 最小认证 + TCP/UDP 数据面 + Salamander 混淆 | implemented | Brutal CC（用 Cubic）、端口跳跃、UDP 分片、完整 H3 未实现 | client.rs:56；auth.rs:95,143；obfs.rs |
| nexus-projection | 14,364 | L3 TUN↔fabric 隧道核心：真 TUN + UDP/TCP egress + smoltcp TCP 终结 + SOCKS5/HTTP 显式入站 | implemented | on_path_event 仅计数（rebind 在 path_link）；examples 约 2,967 行 | lib.rs:669；transport.rs:133；semantic.rs:115；tcp.rs:492 |
| nexus-network | 5,974 | N1 装配 portable core：VPI↔mesh 转发泵 + keepalive 观测 + per-peer 连接表 | implemented | 物理 socket 在 crate 外（注入式） | n1/pump.rs:199；n1/link.rs:81；assembly.rs:87 |
| nexus-dns | 1,634 | 纯内存 DNS 分类/缓存/路由（hosts>mesh>fake-ip>upstream） | implemented | 不做真实 DNS 传输，Resolver 为注入 trait，线上真实 server 实现源码中无法确认 | lib.rs:158,432；unified.rs:321 |
| nexus-ingress | 1,228 | SOCKS5/HTTP 握手增量状态机 + IPv4 包解析（零 I/O） | implemented | 不开 socket（设计使然）；user/pass 仅校验帧格式 | lib.rs:145,465；ip_packet.rs:60 |
| nexus-proxy | 2,204 | 纯决策内核：规则引擎 + 策略组（Selector/Urltest/LoadBalance/Relay）+ tag 解析 | implemented | 零网络 I/O，不监听不转发；出站激活委派注入 LinkActivator | src/lib.rs:634,1005,1072 |
| nexus-proxy-config | 2,360 | 手写 YAML 解析 + 9 变体 OutboundKind + 富 OutboundConfig + clash 订阅解析（零第三方依赖） | implemented | HTTP 订阅拉取在组合根 | src/lib.rs:309,730,1458 |
| nexus-proxy-transport | 3,541 | SOCKS5/SS/Trojan/TrojanTLS 真握手 + u16BE 帧层（生产 nexusd 拨号层） | implemented | 仅 4 种握手 | src/lib.rs:63；framed.rs:63 |
| nexus-nat-traversal | 1,678 | 打洞状态机 + 信令编解码 + 有界端口预测 | implemented | 无真实 STUN 客户端，PortSample 由组合根注入 | lib.rs:350；predict.rs:37；signal.rs |
| nexus-nat-wireup | 3,854 | 生产接线 PunchManager：中继 bi-stream 信令 + 同 socket QUIC fan-out + tie-break | implemented | LoggingFeed 只计数，PathManager 深度集成自述 follow-up | lib.rs:129；channel.rs；socket.rs |
| nexus-nat-quality | 1,043 | 25B probe 帧 + 滑动窗口丢包 + QualityMonitor 喂 PathManager | implemented | RTT 取 quinn stats，loss 靠 probe（stats().loss_rate 未填充不用） | probe.rs；monitor.rs:82；lib.rs:28 |
| nexus-turn | 2,274 | 真 RFC5766 TURN client/server：Allocate/Permission/Channel/Refresh + 长效认证 | implemented | **仅 examples/自测接线，生产 nat_switch 未 import** | client.rs:104；server.rs；stun.rs |
| nexus-compute | 1,933 | N3 纯域层：accepted task 状态机、runtime 事件重放、requester 镜像、artifact 校验 | implemented | 无 OS 调用（纯契约层） | task.rs:181；task_runtime.rs:123 |
| nexus-workspace | 7,550 | CAS 工作区引擎：init/open/commit/merge/conflict/sync/snapshot/gc/cache + FUSE 适配 | implemented | WorkspaceTransport 的 fabric 生产适配（sync_transport）无调用方 | lib.rs:1435,1658,1837,2559 |
| nexus-workspace-intel | 1,135 | 非权威访问智能层：trace→graph→working-set 估计→prefetch | implemented | **nexusd 不依赖，仅 apps/nexus CLI 使用**（daemon 片区内 orphan） | lib.rs:25-40；apps/nexus/Cargo.toml:36 |
| nexus-platform | 600 | 8 个 portable trait（Clock/Random/SecureStore/VPI/Carrier/Ingress/SystemProxy/Autostart）+ UdpCarrier/ring 加密 | implemented | 纯 trait + 两个可移植实现 | src/lib.rs:57-145；udp_carrier.rs；secure_store.rs |
| nexus-platform-linux | 3,907 | 真实 Linux 适配：/dev/net/tun FFI、rtnetlink FFI、fuser FUSE、内置 DNS | implemented | 仅 Linux；测试多为报文构造纯函数 | tun.rs:153；netlink.rs:732；fuse_ws.rs:895 |
| nexus-platform-windows | 1,787 | 真实 Win32 适配：wintun.dll/crypt32/wininet 动态加载、schtasks、netcfg | implemented | 仅 Windows；capabilities 为 const fn 静态值 | wintun.rs:264；dpapi.rs:302；autostart.rs:158 |
| nexus-platform-macos | 7 | 空模块（文档 + forbid unsafe） | **stub** | 无任何代码；host feature 无实现分支 | src/lib.rs:1-7 |
| nexus-platform-android | 7 | 空模块（文档 + forbid unsafe） | **stub** | 同上 | src/lib.rs:1-7 |
| nexus-platform-ios | 7 | 空模块（文档 + forbid unsafe） | **stub** | 同上 | src/lib.rs:1-7 |
| nexus-diagnostics | 7 | 空模块（文档 + forbid unsafe） | **stub** | 无代码、无调用方 | src/lib.rs:1-7 |
| nexus-delivery | 7 | 空模块（文档 + forbid unsafe） | **stub** | 无代码、无调用方；但被列入 harness portable_core 门禁 | src/lib.rs:1-7；harness.toml:83 |
| nexus-proto | 7 | 空文件（doc 自称 wire schema 边界与代码生成占位，实际零 pub item） | **dead** | 全仓零 Cargo 依赖、零源码引用 | src/lib.rs:1-7 |

## 3. engineering

| 成员 | 行数 | 实际职责（一句话） | 实现度 | 关键缺口 | 关键证据 |
|---|---:|---|---|---|---|
| engineering/nexus-harness | 6,445 | 工程门禁 CLI：cargo/git gate 矩阵 + 277 场景子进程执行器 + evidence 落盘 | implemented | replay 未实现（UNKNOWN）；performance_budgets 只校验 toml 键不实测 | main.rs:60-84；gates.rs:226,811；scenario.rs:488 |

## 4. 「机器配置声明但代码未落地」总清单

按"声明位置 → 代码事实"汇总（分片 B、E 为主）：

1. **harness `replay` 命令**：`harness.toml:28` 声明；nexus-harness `main.rs:71-76` 显式返回 UNKNOWN。
2. **性能预算门禁**：`policies/quality.toml:74-98` 声明 4 路径 × 4 档 ns 阈值；`gates.rs:811 performance_budgets_gate` 只校验 `[performance]` 键存在，不实测、不比对（quality.toml:72 自承待 benchmark 校准）。
3. **platform-host 四个平台 feature**：`apps/nexus-platform-host/Cargo.toml:14-17` 声明 platform-linux/macos/android/ios optional features；`main.rs` 仅 windows 分支有代码，其余选中只打印 bootstrap。
4. **异 schema 静态场景**：`scenarios/product/tcp_termination_wireup.toml` 用 `[scenario]`/`[[steps]]` 写法，与 harness `load_file`（只认顶层 id + `[when].command`）不兼容，不被加载（277 场景中唯一孤儿；其余 276 个可执行）。
5. **harness [hooks]**：`harness.toml:89-126` 声明 pre-commit/commit-msg/pre-push 与 contract hash marker；由 `.githooks/*.sh` 执行，nexus-harness 二进制无 hooks 子命令。
6. **N3 provider 冷启动**：`task-api.toml` 决定启用，但 `task_service_provider.rs:55-79` 强制 `data/`、`data/n3/` 已存在且私有、`FileTaskAcceptanceStore::open_existing`（:77-78 注释自承 cannot provision），新建配置无法冷启动 provider，除非外部预建目录树。
7. **配置热加载**：`watcher.rs:12-13` 注释宣称 proxy.yaml/dns.toml/network.toml 变更"热生效"；`main.rs:599-601` 收到 Applied 仅 eprintln，不回注运行中子系统（需重启）。
8. **N3 Submit 表面契约**：HTTP `POST /localapi/v1/task`（task_http.rs:201）与 `execute` 的 Submit 分支呈现可提交表面，`task_service_provider.rs:229` 恒返回 UnsupportedCapability。
9. **flow sessions**：`dataplane.rs:253 enable_flow_sessions` 定义齐全，生产无调用（仅内部 :268 与测试）。
10. **workspace fabric 同步**：`sync_transport.rs` 完整实现 WorkspaceTransport(type 0x03) 与授权，生产无 `FabricSyncTransport::open/from_shared` 调用方。
11. **NAT 生产切换**：`nat_switch.rs:19-22` 自承 main.rs 不实例化；全仓无 `NatSwitching::new` 调用方。
12. **富协议生产路由**：vless/anytls/hysteria2/vmess 在 nexusd `proxy_fwd.rs:93-98` 一律映射 None（仅 SS/Trojan/Socks5 可拨号）；6 个 OutboundAdapter 生产零实例化，仅 examples。
13. **requester 侧镜像/outbox**：`task_requester_store.rs` 生产无调用方（仅 re-export + 测试）。
