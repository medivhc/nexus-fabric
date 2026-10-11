# 05 · 核心域 / 平台适配 / harness 源码逆向审计（Shard E）

> 本文仅依据仓库 e6ccf8b 的源代码与机器配置（.rs/Cargo.toml/*.toml）撰写，未采信任何叙述性文档；结论行号均可复核。

## 片区范围与行数总表

本片区覆盖 24 个 workspace 成员，合计约 38,537 行 .rs：

- 核心域（17）：nexus-auth、nexus-registry、nexus-domain、nexus-discovery、nexus-policy、nexus-plugin、nexus-storage、nexus-session、nexus-planner、nexus-flow-session、nexus-scheduler、nexus-service、nexus-diagnostics、nexus-control-api、nexus-measurement、nexus-fabric、nexus-delivery
- 平台适配（6）：nexus-platform、nexus-platform-linux、nexus-platform-windows、nexus-platform-macos、nexus-platform-android、nexus-platform-ios
- 工程门禁（1）：engineering/nexus-harness

逐成员行数、职责、实现度见 `fragments/06-E.md` 矩阵。

---

## 一、核心域 crate

### nexus-domain（3,762 行，零第三方依赖）
- **实际职责**：全仓唯一的纯核心模型与 N3 任务 DTO 层。定义标识、意图、约束、Plan、错误处置、路由规则 trait，以及版本化的 Submit/Accept/Execution/Delivery/Cancellation/Artifact 契约与 digest 校验。
- **关键类型/入口**：`ResourceId/ProviderId/SessionId/WorkspaceId/NodeId`（src/lib.rs:19-53）；`Intent{profile}`（:282）；`FlowContext`（:314）；`PlanExtension{Network,Workspace,Compute,Service}`（:332）；`Plan`（:497）；`NexusError` 14 变体 + `disposition{Retry,Fallback,Abort,Escalate}`（:906-963）；trait `RuleEngine{decide}`（:1069）；`task/mod.rs`：`SubmitTaskRequest`（:339）、`AcceptedContract`（:503）、`TaskDelivery`（:691）、digest 校验（:1128）。
- **依赖**：自身零依赖；被约 25 个 crate 依赖。
- **实现度**：implemented。20 单测。
- **stub/空转**：无。

### nexus-auth（869 行）
- **实际职责**：纯授权判定库。PSK 常量时间校验、ed25519 公钥派生 Principal、Grant 表 6 步判定、TOFU 信任库（永不静默学习）、审计 sink。
- **关键入口**：`verify_token`（:63）；`Principal::from_ed25519_public_key`（:109）；`GrantTable.authorize`（:262，NoSuchGrant/WrongWorkspace/Revoked/Expired/OperationNotGranted/Allow，Manage 蕴含 Use :322）；`TrustStore`（:347）。
- **依赖**：nexus-domain + sha2。被 apps/nexus、nexus-registry 引用。
- **实现度**：implemented。约 18 单测。
- **stub/空转**：无。

### nexus-registry（1,945 行）
- **实际职责**：内存 Provider 视图 + 资源广告/本地名解析 + 5 种 N2 控制帧的 wire 编解码与认证通道。
- **关键入口**：`Registry{records,ads}`（lib.rs:64）；`ProviderAdvertisement`（advertisement.rs:111）；`LocalNameTable`（:389）；`ControlFrame{ResourceAnnounce,ResourceQuery,AuthGrant,AuthRevoke,LeaseRenew}`（control_frame.rs:78）；wire 编解码（:489/:535）；trait `ControlTransport`（:594）。
- **依赖**：nexus-domain。被 planner/flow-session/discovery/workspace-intel/apps 使用。
- **实现度**：implemented。21 单测。
- **stub/空转**：无。

### nexus-discovery（5,963 行）
- **实际职责**：mesh 发现与路由引擎。mDNS/DNS-SD、LSA、ed25519 配对均为纯状态机/编解码；routing 模块实现 SPF/ECMP/K-最短/节点不相交路径与 FIB 转发表。真实 socket 装配在组合根。
- **关键入口**：trait `Discovery`（lib.rs:104）；`PresenceRegistry`（:261）；`DiscoveryFrame` 编解码（:386/:464）；`mdns.rs:28 MDNS_ADDR=224.0.0.251:5353`；`routing.rs:130 ShortestPath`、`:304 Ecmp`、`:446 KShortest`、`:841 NodeDisjoint`、`:1192 FIB{lookup,select_next_hop}`、`:1322 FibManager`。
- **依赖**：nexus-domain/registry/platform + ring。被 network/connectivity/nexusd/apps 使用。
- **实现度**：implemented。95 单测。
- **stub/空转**：零 I/O 是设计边界（mdns.rs:239 注释自述），非造假。

### nexus-policy（590 行）
- **实际职责**：动作链策略引擎。按 profile_eq/destination_prefix 匹配，输出 AddConstraint/EnrichMetadata/SelectProvider/Reject，首匹配终止。
- **关键入口**：`PolicyEngine{rules}`；`evaluate`（:262）；`default_network/service/compute/workspace`。
- **依赖**：nexus-domain。被 flow-session/network/apps/nexusd 使用。
- **实现度**：implemented。10 单测。
- **缺口**：匹配维度仅 2 维（无端口/协议/IP 段/进程）。

### nexus-plugin（981 行，edition 2021）
- **实际职责**：混淆传输插件点。trait + 编译期静态注册表 + plain/xor 内置包装，把已建 TcpStream 包成混淆字节流。
- **关键入口**：trait `ObfuscateTransport{wrap}`（lib.rs:66）；`PluginRegistry{register,get,wrap}`（registry.rs:18）；`XorTransport`（builtin.rs:67）。
- **依赖**：零。被 apps/nexus、outbound-shadowsocks/trojan 使用。
- **实现度**：implemented。16 单测。

### nexus-storage（1,398 行）
- **实际职责**：本地文件持久化。FileKvStore 原子写 + 崩溃恢复 journal（append/replay/discard_torn_tail/truncate）+ CAS ContentStore。
- **关键入口**：`FileKvStore{put,get,delete,list,journal_append,journal_replay}`（kv.rs:84-451）；`FsContentStore`（fs.rs:20）；trait `StrongContentStore`（strong.rs:8）。
- **依赖**：nexus-domain。被 workspace/workspace-intel/nexusd/apps 使用。
- **实现度**：implemented。23 单测。

### nexus-session（2,304 行）
- **实际职责**：会话状态机。phase 转移、终态一次提交、取消令牌、崩溃 reconcile、Manager（含 attach 窗口、detached sweep、provider lost 通知）。
- **关键入口**：`SessionOwner`（lib.rs:155）；`reconcile_session_records`（:485）；`SessionManager`（:1298）。
- **依赖**：nexus-domain。被 nexusd/workspace/compute/network 使用。
- **实现度**：implemented。46 单测 + 根 tests/concurrency。
- **stub**：唯一 `unreachable!`（:577）有调用方守卫。

### nexus-planner（1,227 行）
- **实际职责**：Core Planner。能力硬过滤 → 连通性门 → RTT 归一化 + 局部性 bonus 打分（字典序 tie-break）→ 组装 Plan。
- **关键入口**：`filter_candidates`（:202）；`score_candidates`（:255）；`plan_from_snapshot` 四阶段（:334）。
- **依赖**：nexus-domain/registry/measurement。被 flow-session/chain.rs:71、workspace-intel/nexusd/network 使用。
- **实现度**：implemented。29 单测。
- **硬编码**：`:439 execution_strategy` 恒 `"direct"`；`:440 extension` 恒 `PlanExtension::Network`（注释 :98-99 已如实声明）。

### nexus-flow-session（1,300 行）
- **实际职责**：逐流编排。把 policy.evaluate → planner.plan_from_snapshot 串成链，建连由注入的 `ConnectivityEstablisher` trait 承接。
- **关键入口**：trait `ConnectivityEstablisher`（manager.rs:23）；`SessionManager{on_packet,pump,drain_signals,sweep_idle}`（:68）；chain.rs:71。
- **依赖**：domain/measurement/policy/planner/session/network。仅 nexusd 依赖。
- **实现度**：implemented。18 单测。

### nexus-scheduler（548 行）
- **实际职责**：内存定时器调度器。register/cancel/list/tick/snapshot/restore，BTreeMap 存储。
- **关键入口**：全 lib.rs；真实接线 apps/nexus/src/schedule_cli.rs:13（快照落盘 :69）。
- **实现度**：implemented。6 单测。

### nexus-service（103 行）
- **实际职责**：Service 帧握手契约。在已认证帧通道发 CONNECT、等 READY。
- **关键入口**：`ServicePhase{Connecting,Active,Closed}`（:18）；`connect`（:83）；trait `ServiceTransport`。
- **依赖**：domain。真实接线 apps/nexus/src/lib.rs:543 实现 trait、:759/2248/2555/3225/3488 调 connect。
- **实现度**：implemented（极小）。0 自测。
- **死变体**：`:20 Connecting` 从不构造（connect 直返 Active :92）。

### nexus-control-api（883 行）
- **实际职责**：前端统一控制面契约。22 个控制命令枚举 + 结构化输出 DTO + `ControlService{execute}` trait + N3 task wire。
- **关键入口**：`ControlCommand`（lib.rs:17）；`ControlOutput`（:104）；trait `ControlService`（:148）。
- **依赖**：domain。apps/nexus/src/control_service.rs 实现 trait。
- **实现度**：implemented（纯契约）。12 单测。

### nexus-measurement（168 行）
- **实际职责**：链路测量纯 DTO。RTT/loss/jitter/throughput（全 Option）+ MeasurementTable + LatencyProbe trait。
- **关键入口**：全 lib.rs；真实探针 apps/nexus/src/lib.rs:5874 TcpLatencyProbe、:5911 Http204LatencyProbe。
- **实现度**：implemented。3 单测。

### nexus-fabric（3,722 行）—— QUIC/mTLS 会话层，非顶层聚合
- **实际职责**：基于 quinn-proto（patched）sans-IO 的 QUIC-like 会话层。可靠流 open_bi/accept_bi、不可靠数据报、E2E 加密、地址解耦、PeerId pinning mTLS。是全仓底层传输，被 turn/proxy-transport/projection/nat-wireup/nat-quality/network 依赖。
- **关键入口**：`FabricConn{connect,connect_mtls,open_bi,send_datagram,rebind,close}`（lib.rs:86）；`FabricListener{bind,bind_mtls,accept}`（:323）；`cert.rs` rcgen 自签 ed25519 证书绑定 PeerId；`cert_strict.rs` PeerId-pinning verifier；`driver.rs`（1,341）quinn-proto 事件驱动；`transport.rs` UdpTransport trait。
- **依赖**：quinn-proto 0.11 / bytes / rcgen / ring。
- **实现度**：implemented。21 src 测试 + 8 集成测试（tests/mutual_auth.rs、s10_s11.rs）。

### nexus-diagnostics（7 行）/ nexus-delivery（7 行）
- **实际职责**：空模块。src/lib.rs 仅模块文档 + `#![forbid(unsafe_code)]`，无任何类型/函数。
- **依赖**：diagnostics 零依赖方；delivery 零依赖方（但 harness.toml:83 把它列入 portable_core 门禁）。
- **实现度**：stub。0 测试。

---

## 二、平台适配层

### nexus-platform（600 行）
- **实际职责**：portable 抽象 trait 集合 + 两个可移植实现。trait：Clock/RandomSource/SecureStore/VirtualPacketInterface/PacketCarrier/TransparentIngressProvider/SystemProxyController/AutostartRegistrar（lib.rs:57-145）。
- **可移植实现**：`UdpCarrier`（udp_carrier.rs，真实 std::net::UdpSocket）；`secure_store.rs`（ring HKDF-SHA256 + ChaCha20-Poly1305）；`projected.rs` ProjectedWorkspace trait。
- **实现度**：implemented。7 单测。

### nexus-platform-linux（3,907 行）
- **实际职责**：真实 Linux 系统适配。手写 FFI 操作 /dev/net/tun（tun.rs，TUNSETIFF）、rtnetlink（netlink.rs，socket/bind/RTM_NEWADDR/ROUTE）、fuser FUSE ws、内置 DNS、daemon、事务性 OsAssemble。
- **实现度**：implemented。约 38 测试（多为报文构造纯函数）。全 src 无 unimplemented!/todo!；不 forbid(unsafe_code)（合法 unsafe FFI）。
- **接线**：apps/nexus、nexusd、nexus-network。

### nexus-platform-windows（1,787 行）
- **实际职责**：真实 Win32 适配。动态加载 wintun.dll（wintun.rs）、crypt32 CryptProtectData（dpapi.rs）、wininet InternetSetOption（wininet_proxy.rs）、schtasks.exe 自启（autostart.rs）、netcfg。
- **实现度**：implemented。33 测试。
- **静态声明**：`WintunVpiAdapter::capabilities/backend/mtu` 为 `pub const fn`（vpi.rs），非运行时探测。

### nexus-platform-macos / android / ios（各 7 行）
- **实际职责**：空模块。仅文档 + forbid(unsafe_code)。
- **实现度**：stub。仅 platform-host optional dep；host main.rs 无对应 feature 代码分支。

### 平台分发机制
- `apps/nexus` 硬依赖 linux+windows，代码内 `#[cfg(target_os=...)]` 分发。
- `apps/nexus-platform-host` 把 5 个平台都声明为 optional features，但 main.rs 仅 windows 有 `vpi-capabilities` 分支；linux/macos/android/ios 四个 feature 选中后无任何代码（只打印 "repository-contract bootstrap"）。

---

## 三、engineering/nexus-harness（6,445 行）

- **实际职责**：工程门禁 CLI。把 policies/quality.toml 声明的 gate 名单分发到真实 cargo/git 调用；把 scenarios/**/*.toml 变成子进程执行的 E4 场景；证据落盘到 .evidence/。
- **命令**（main.rs:60-84）：status/context/check/test/verify/explain/run/scenario/bench 真实；**replay 显式未实现→UNKNOWN**（:71-76）。
- **gate 真实性**（gates.rs）：whitespace/format/check/clippy/affected-tests/integration/feature_matrix/portable_core 真调 cargo/git；architecture/dependency/platform_checks/resource_kind_neutrality 真读 toml+扫源码；coverage/fuzz/concurrency/bench 真跑外部工具（缺工具→UNKNOWN，不静默 PASS）。quality.toml 声明的 8 fast + 14 full gate 名全部有映射。
- **partial**：`performance_budgets_gate`（:811）只校验 quality.toml `[performance]` 键存在，不实测不比对阈值。
- **场景**：277 个 toml，276 个有 `[when].command` 可执行（独立 NEXUS_CONFIG_DIR、600s 超时、并行、JSON equals/one_of/non_empty 断言）；1 个静态孤儿（tcp_termination_wireup.toml 异 schema）。
- **hooks**：harness.toml [hooks] 由 .githooks/*.sh 执行，二进制无 hooks 子命令。
- **实现度**：implemented。56 自测。

---

## 四、片区内跨 crate 调用主干

- `nexus-domain` 是根，被几乎所有核心 crate 依赖。
- 决策链：`nexus-flow-session/chain.rs:71` 调 `nexus-policy.evaluate` → `nexus-planner.plan_from_snapshot` → 注入的 `ConnectivityEstablisher`。
- 会话生命周期：`nexus-flow-session` 经 `nexus-session` 的 SessionOwner/Manager 管理 phase/outcome；崩溃时 `reconcile_session_records` 恢复。
- 传输底座：`nexus-fabric`（QUIC/mTLS）被 `nexus-turn`/`nexus-proxy-transport`/`nexus-nat-wireup`/`nexus-network` 复用；`nexus-discovery` 的 FIB 为 network 提供下一跳。
- 平台抽象：`nexus-platform` trait 由 `nexus-platform-linux`/`-windows` 真实实现，经 `apps/nexus`、`nexusd`、`nexus-platform-host` 接线；macos/android/ios 空壳。
- 门禁：`nexus-harness` 依赖 nexus-connectivity/dns/projection 跑部分 gate，并读取 policies/quality.toml + harness.toml + scenarios/。

## 五、片区小结：真实能力与最大缺口

**真实能力**：核心 portable 域（domain/auth/policy/session/planner/storage/control-api）是一套高密度、有单测支撑的纯逻辑模型；Linux 与 Windows 两个平台适配器接的是真实 OS API（TUN/netlink/FUSE、wintun/DPAPI/wininet/schtasks）；fabric 是真实 QUIC/mTLS 会话层；harness 是真实可执行的门禁与场景执行器（未实现项一律记 UNKNOWN，不静默 PASS）。

**最大缺口**：
1. **三平台空壳**：macos/android/ios 仅有 7 行空模块，platform-host 对应 feature 无实现分支——跨平台分发在非 Linux/Windows 上不落地。
2. **性能预算空转**：quality.toml 声明的 4 路径 ns 阈值无实测门禁，performance_budgets_gate 只查 toml 键。
3. **replay 命令与 TCP 终结场景**：replay 未实现；tcp_termination_wireup real_device 场景用异 schema 未被 harness 加载。
4. **planner 维度固定**：execution_strategy 恒 direct、extension 恒 Network，compute/service/workspace 资源无差异化规划。
5. **平台层真实行为覆盖靠真机**：单元测试集中在纯函数，OS 副作用路径未在本审计中实跑验证。

---

## 附：非成员目录（仅读机器制品）

- **engineering/evidence-schema/evidence.schema.json**：JSON Schema draft 2020-12，定义证据信封（required: schema_version/verification_id/verdict/source_revision/working_tree_digest/configuration_digest/feature_set/target_triple/toolchain_version/checks；verdict 5 值枚举；checks[] 含 id/status/duration_ms/artifact/message；additionalProperties false）。
- **engineering/verifiers/*.py**（3 个真实 E2E 探针）：`n3_foundation_boundary.py` 起真 nexusd 校验 config root/token 边界；`n3_artifact_cli.py` 经 docker.sock 用固定镜像 seed + 跑真实 Artifact CLI；`n3_operator_grant.py` 测 operator Use grant 下真实执行与投递（revoked/expired 拒绝、audit、清理）。
- **engineering/plugins/**：目录存在，仅含 plugin-contract.md、README.md 两个 .md；按只读红线未读取。
