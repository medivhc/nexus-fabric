# Nexus 产品文档（按源代码函数体实证，HEAD ced3b7a）

> 本文**只依据仓库当前 HEAD 的源代码与机器配置撰写**（HEAD = `ced3b7a9ed801f38ee816135700889978ff0e0b6`，工作区干净；含 web-gateway、bootstrap-join、code-intel 三个新组件），未采信任何叙述性文档（.md）；所有功能描述均来自函数体实际逻辑（实际发什么网络包、写什么文件、返回什么值），不来自函数名、注释或测试名；每条关键结论带 `文件:行号` 可复核。
>
> 证据分级：**可用** = 函数体有真实逻辑且有测试实际走到该路径；**已实现未验证** = 代码存在但无测试走到；**不可用/占位** = 函数体硬编码 Err/固定数据。

---

## 1. 这个产品实际是什么

### 1.1 一句话
Nexus 是一个**自托管的虚拟组网与授权访问系统**：多台机器上跑同一个 Rust 程序（`nexus` CLI / `nexusd` 守护进程），节点之间通过 ed25519 身份互相认证、按"资源+主体+操作"表授权，在虚拟子网（TUN）里建立点对点隧道，并能按 Clash 风格配置把出站流量代理到 Shadowsocks/Trojan 等出口。附带一套本地持久化的"任务账本"（N3）和一个尚未接入守护进程的浏览器 Web 终端网关（web-gateway）。

### 1.2 它实际解决的问题（从代码行为归纳）
1. **跨机器资源访问的身份与授权**：每个节点生成自己的 ed25519 长期身份（`apps/nexus/src/n2_identity.rs:78,91-92`），资源提供方（provider）在每次建立会话时与请求方做双向挑战-应答握手并查授权表（`apps/nexus/src/n2_admission.rs:351,597,800,896`），拒绝任何"自称"的身份。
2. **虚拟组网**：在真实 TUN 设备（Linux `/dev/net/tun`、Windows wintun）上构成虚拟子网，节点间打洞后交换虚拟 IP（`apps/nexus/src/subnet_cli.rs:1167,1185`；`crates/nexus-discovery/src/bootstrap_join.rs:181-216`）。
3. **代理出口**：本机 SOCKS5 入口按规则引擎选择出站（Shadowsocks/Trojan/SOCKS5 拨号，`apps/nexusd/src/proxy_fwd.rs:69-91`）。
4. **（半成品）本地任务执行面**：任务的接受/持久化/日志/产物读取是真的（`apps/nexusd/src/task_service_provider.rs:233-316`），但"提交并真实执行"被硬编码拒绝。

### 1.3 关键事实边界（不要误解）
- 准入握手信道是**裸 TCP JSON，无加密、无前向保密**（`n2_admission.rs:20-21` 模块头与 :811 connect 函数体印证）；双向签名只证明"对方持有私钥"，不加密业务流。
- 守护进程的**可观测接口几乎全部返回硬编码演示数据**（见 §4.3），不反映真实运行状态。
- 任务**提交执行**当前不可用（`task_service_provider.rs:229` 恒 `Err(UnsupportedCapability)`）。
- web-gateway 是**独立 example 进程，未嵌入任何守护进程**（`crates/nexus-web-gateway/examples/gateway.rs:13`；全仓除其自身外零调用方）。

## 2. 两个二进制的实际角色与职责边界

### 2.1 `nexus`（CLI，apps/nexus）
从入口 `run(args)`（`apps/nexus/src/main.rs:200`）的实际分派看，它有**三重身份**：
1. **瘦客户端**：`task`/`status`/`dns status`/`session watch` 等命令把请求做成 HTTP/1.1 POST/GET 发到本机守护进程（`apps/nexus/src/task_localapi.rs:175-200`、`localapi_client.rs:146-158`），Bearer token 鉴权。
2. **本地状态机客户端**：`use`/`grant`/`resource`/`session`/`node`/`pair`/`plan` 直接读写本机 N2Store 文件目录并直接发起跨机准入握手（不经过 daemon）。
3. **数据面/代理组合根**：`subnet up --tun`、`network up`、`proxy`、`provider serve` 在这里直接创建 TUN/socket/监听。

边界：它是 lib crate 又是二进制——`nexusd` 反过来 `use nexus::...` 复用它的 observability 快照、装配函数与 task DTO（`apps/nexusd/src/main.rs:756`）。

### 2.2 `nexusd`（守护进程，apps/nexusd）
从 `main.rs:257` 入口的实际装配看：
- `nexusd <config-folder>` 加载 daemon.toml/network.toml/proxy.yaml/dns.toml/workspace.toml（:286-296 usage），boot reconcile 后装配 N2 session manager（`assembly.rs:220`）、可选 TUN 数据面线程（:514）、HTTP LocalAPI 线程（:541）、Linux FUSE workspace（:565）、配置 watcher（:599）。
- **对外只有一个手写 HTTP/1.1 LocalAPI**（默认 127.0.0.1:18080 或 unix socket），共 **13 个路由**（12 个 v0 GET + 1 个 v1 POST），无其它网络服务。
- 它不直接做准入服务（准入由 `nexus provider serve` 起的独立进程完成），也不跑已提交任务的执行。

边界：v0 路由里除 dataplane/stats、n2/session/*、workspace/* 外全部返回演示数据；v1 task 路由在非 Linux 或缺 task-api.toml 时整体不可用。

## 3. 组件实际分工与调用关系

### 3.1 分层（从各 Cargo.toml 内部依赖与函数体调用归纳）
| 层 | crate | 实际职责（函数体证据） |
|---|---|---|
| 核心模型 | nexus-domain | 全仓唯一无内部依赖的纯模型 crate：Principal/Resource/Plan/Task DTO（被约 25 个 crate 依赖） |
| 安全原语 | nexus-auth | GrantTable.authorize 判定链（`src/lib.rs:286`）、TOFU TrustStore（:358）、常量时间 PSK 比较（:63，N1 冻结路径） |
| 身份与准入 | apps/nexus n2_identity/n2_admission | ed25519 密钥 0600 落盘；跨机挑战-应答握手（TCP JSON） |
| 传输底座 | nexus-fabric | 基于 patched quinn-proto 的 QUIC/mTLS 会话（PeerId pin 校验，`cert.rs:287`）——注意：运行时 mesh/subnet **不用它**，见 §5.3 |
| 隧道与数据面 | nexus-connectivity → nexus-projection → nexus-network | VirtualSubnet 隧道（`connectivity/virtual_subnet.rs:422`）；TUN+UDP/TCP egress+smoltcp 终结（`projection/lib.rs:669`）；VPI 转发泵（`network/n1/pump.rs:199`） |
| 代理 | nexus-proxy / proxy-config / proxy-transport + 6 个 outbound crate | 决策内核（零网络 I/O）；手写 YAML 解析；SOCKS5/SS/Trojan 真握手拨号；vless/anytls/hysteria2 协议栈存在但生产未路由 |
| NAT | nat-traversal / nat-wireup / nat-quality / turn | 打洞状态机、PunchManager、probe 喂 PathManager；TURN 栈仅 examples 接线 |
| 任务账本 | nexus-compute（纯域状态机）→ nexusd task_*（文件持久层） | accepted 任务 journal 回放；Submit 恒拒 |
| 内容工作区 | nexus-workspace（CAS 引擎）→ nexusd workspace.rs（FUSE 挂载） | commit/merge/sync/conflict |
| 平台适配 | nexus-platform{,-linux,-windows,-macos,-android,-ios} | Linux/windows 真 FFI；macos/android/ios 为 7 行空模块 |
| 工程门禁 | engineering/nexus-harness | cargo/git gate + 276 个场景子进程执行器；新增 code_intel 只读 LSP 查询子系统 |
| 浏览器网关 | nexus-web-gateway | 自签 HTTPS/WSS 静态页 + SSH 终端桥；example 进程，未接入 |

### 3.2 两条独立传输路径（重要）
代码里存在**两套互不相通的传输构造**：
- **N2 路径（运行时实际用的）**：`nexus provider serve` → n2_admission 裸 TCP JSON 握手 → 明文/隧道 endpoint → `nexus_connectivity::VirtualSubnetTunnel`（`apps/nexus/src/mesh.rs:27`）。
- **fabric 路径（仅 examples/测试走到）**：`nexus-fabric` 的 QUIC mTLS + PeerId pinning 实现得很完整（`cert.rs:455,374,396`），但 apps 生产代码没有调用 `new_mtls_server`/`build_mtls_*`（仅 `crates/nexus-fabric/examples/mutual_auth_e4.rs`）——**标注为"已实现未验证"**。

## 4. 真实能力清单与边界

### 4.1 可用（有真实逻辑 + 测试实际走到）
| 能力 | 代码证据 | 测试证据（读函数体） |
|---|---|---|
| ed25519 节点身份生成/持久化/并发幂等 | n2_identity.rs:78,91-92,108-115 | 16 线程 barrier 并发 ensure 返回同一身份（:181,210） |
| 双向挑战-应答准入 + grant 判定 + 租约落盘 + 审计 | n2_admission.rs:351-548,800-917 | admit_roundtrip_with_grant(:1201)、deny_without_grant_writes_audit(:1248)、tampered_signature_is_rejected(:1474) |
| TrustStore：首见不自动信任、KeyChange 拒绝、Strict 拒未信任 | auth/lib.rs:358；n2_admission:896-924 | untrusted_provider_is_rejected(:1516)、identity_changed_is_rejected(:1546) |
| Grant 判定固定链（NoSuchGrant→WrongWorkspace→Revoked→Expired→OperationNotGranted，Manage 蕴含 Use） | auth/lib.rs:286-329 | authorize 纯函数单测族 |
| LocalAPI bearer token：32 随机字节/0600/常量时间比较/loopback 强制 | localapi_client.rs:198-213；nexusd main.rs:1208-1231；task_localapi.rs:45-60 | create_and_reload_stable(:693)；tests:83 断言出站 Bearer header |
| 节点 pair（invite/join）配对码握手 | pair_cli.rs:178,263,303,429,475 | pair_cli.rs 内 roundtrip 测试族 |
| 子网上线（mock carrier 只写状态；--tun 真 TUN） | subnet_cli.rs:527-613,1167,1185 | tun 名校验、状态加密往返、punch 事件单测 |
| NAT 打洞真实 UDP 收发（subnet punch） | subnet_cli.rs:1223-1330 | punch 事件单测 |
| bootstrap-join 字节编解码（nxb: magic + JoinInit/Reply/Error 帧） | discovery/bootstrap_join.rs:181-221；bootstrap_codec.rs:47-82 | ctrl_roundtrip_maps_both_directions(:215)、join_init_reply_and_error_roundtrip(:250) |
| 代理决策内核 + 配置解析 + SOCKS5/SS/Trojan 拨号 | proxy/*.rs；proxy-transport/*.rs；proxy_fwd.rs:69-91 | 47/40/35 个 crate 内测试族 |
| vless/anytls/hysteria2 协议栈（loopback 集成测试） | outbound-vless:882、anytls:959、hysteria2 client.rs:56 | 各 crate loopback echo 测试 |
| N3 任务查询面（Get/Cancel/ReadLogs/ListArtifacts/GetArtifact 读真实持久化） | task_service_provider.rs:233-316 | task_service_tests.rs:228 断言 Submit 被拒且 acceptance 文件未改 |
| Web 网关静态页/WSS 信令/SSH 终端（example 进程） | gateway.rs:314,354,397-427；ssh_client.rs:42-100 | tests/gateway_e2e.rs:128,190,280,327（真 TestSshd 端到端 echo） |
| fabric PeerId pinning（防扩展内嵌伪造） | fabric/cert.rs:287,255-257；cert_strict.rs:60 | admitted_certificate_requires_its_actual_signature(:483)、embedded_extensions 不替换 SPKI(:530) |

### 4.2 已实现但未接线 / 未验证
- vless/anytls/hysteria2/vmess 协议栈：nexusd `proxy_fwd.rs:93-98` 把这四个变体映射为 `None`（不拨号）；6 个 OutboundAdapter 仅 examples 实例化。
- TURN 栈（`crates/nexus-turn`）：仅 wireup/examples 引用，生产 nat_switch 未 import。
- nexus-fabric QUIC mTLS 服务端模式：仅 examples/测试走到，apps 生产装配不可达。
- 路径主动探测：`nexus-path/src/lib.rs:349 send_heartbeat_stub` 是空函数。
- web-gateway：example 进程；mesh WSS 真 TLS 中继路径无 e2e 覆盖（测试默认用进程内 InMemoryMeshSignaler）。
- `TrustPolicy::Prompt` 交互 TOFU 答 y 持久化：无 tty 测试走到。

### 4.3 不能做什么（硬边界）
- **不能真正执行提交的任务**：Submit 恒拒（`task_service_provider.rs:229`）；任务执行面当前只是"已 accepted 任务的只读回放/查询面"。
- **不能从守护进程观察到真实运行状态**：v0 可观测端点返回硬编码演示数据——DNS 只认 example.com 并恒返回 `93.184.216.34`（`observability.rs:38-50,109`）、session watch 每次新建 sess-1/2/3 假会话（:201）、connectivity 硬编码连 `203.0.113.53:51820`（:271）、plan 硬编码 p1/p2（:309）、platform capabilities 是字面量数组（:391）。
- **不能在 Windows/macOS 上用 N3 task API**：`TokenAuthority.valid()` 在非 unix 恒 false（`task_http.rs:321-325`）；LocalTaskService 非 Linux 直接 Unsupported（task_service.rs:81-85）。
- **不能在非 Windows 上改系统代理/开机自启**（`main.rs:1619,1687` 恒 UNSUPPORTED）；不能在非 Linux 上跑 `network up` 与 `task-provider grant`。
- **macOS/Android/iOS 平台不落地**：三个平台 crate 各 7 行空模块（`src/lib.rs:1-7`）。
- **准入信道不加密**：N2 握手跑在裸 TCP JSON 上，业务流保密性取决于 endpoint 自身（明文 TCP 或后续代理出站配置）。

## 5. 安全模型实际怎么工作

### 5.1 身份
- 每节点首次使用时生成 ed25519 密钥对（32 随机字节 seed），落盘 `<node_dir>/n2/auth-identity`，0600 权限（`n2_identity.rs:91,108-115`）。
- Principal = `ed25519:` + hex(SHA256(pubkey)[..16])（`nexus-auth/src/lib.rs:94`），**只由握手验证过的公钥派生，拒绝自称**。
- N3 路径额外收紧：读身份文件要求 O_NOFOLLOW、0600、nlink==1、非 symlink、dev/ino 绑定（`task_authorization.rs:138-175`）。

### 5.2 N2 双向握手（裸 TCP JSON）
provider 端 `handle_admission`（`n2_admission.rs:351`）：发 challenge_b+自己公钥 → 验请求方对 challenge_b 的签名（:600）→ 反查资源广告（:428）→ 查 grant 表（:481）→ 写租约/回 B 自己对 challenge_a 的签名（:516）。请求方 `admit_session`（:800）：验 B 签名 + 防混淆检查（响应公钥必须等于 hello 公钥，:856）→ 过 TrustStore。**信道无加密、无前向保密**。

### 5.3 信任决策
- TrustStore 首次见 = UnknownFirstSeen（不自动学习，auth:358）；Strict 直接拒，Prompt 仅 tty 才问 `[y/N]`（n2_admission:937-951，非 tty 直接拒）；KeyChange 直接拒。
- Grant 判定每次建会话执行，顺序固定（§4.1），Allow/Deny 都 exactly-once 写审计。

### 5.4 LocalAPI 凭据
- Bearer token = 32 随机字节 hex（64 字符），0600 文件；服务端常量时间比较（`main.rs:1224`、`task_http.rs:97`）；客户端只把 token 发往 loopback（`task_localapi.rs:45-60`）；N3 还要求服务端确认监听在 loopback 且 token 文件 inode/权限绑定有效。

### 5.5 TLS 验证实际行为（含所有"跳过校验"位置）
| 位置 | 实际行为 | 信任假设 |
|---|---|---|
| fabric PeerPinVerifier（`cert.rs:287`） | 从证书抽 ed25519 SPKI，**必须等于预期 PeerId**；strict 路径拒绝非标准 DER/扩展内嵌 SPKI | 强：身份绑定证书，防伪造 |
| web-gateway mesh WSS client（`crates/nexus-web-gateway/src/mesh.rs:224-234`） | `PermissiveVerifier::verify_server_cert` 函数体直接 `Ok(assertion())`——**接受任意证书，不验链/主机名/CA/有效期** | **弱**：节点间唯一保护是 Bearer token；作者自承 MVP placeholder。SSH 侧同样不验 host key（ssh_client.rs:60-100 无 hostkey 回调） |
| outbound-trojan skip（`crates/nexus-outbound-trojan/src/lib.rs:359`） | `SkipCertVerify` 直接 Ok；仅当配置 `skip-cert-verify` 时启用 | 配置显式选择才放宽 |
| hysteria2（`crates/nexus-outbound-hysteria2/src/tls.rs:59`） | `Insecure` pin=None 无条件接受任意证书；`PinSha256` 只 pin 叶子 DER 哈希 | 配置显式选择 |
| nexusd proxy_fwd（`apps/nexusd/src/proxy_fwd.rs:79-89`） | trojan 未配 skip/alpn 时走**明文** Trojan；TLS 校验完全由 proxy.yaml 驱动 | 生产出口默认明文 |
| fabric P0 server（`cert.rs:469`） | `with_single_cert`，**无 client cert verifier**——服务端接受任意 client；client 侧仍 pin server | mTLS 实际是单向 |

**总体安全定位**：身份认证（ed25519 双向签名 + TOFU + 授权表）是真实且经测试覆盖的；但**准入信道不加密、web-gateway 节点间 WSS 不验证书、代理出口默认明文**是三个明确的信任边界，部署时必须知道。
