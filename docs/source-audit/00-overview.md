# 00 · Nexus-Fabric 项目实际状态总览（纯源码逆向）

> 本文仅依据仓库 e6ccf8b 的源代码与机器配置（.rs/Cargo.toml/*.toml）撰写，未采信任何叙述性文档；结论行号均可复核。
>
> 本文是自包含总览：读者无需阅读仓库内任何 .md 即可理解项目实际状态。逐 crate 明细见 01–05，状态矩阵见 06，注释错误见 07，复核过程见 08。

---

## 1. 一句话结论

**nexus-fabric 是一个用 Rust workspace 组织的"虚拟组网 + 代理 + 本地内容工作区"系统，核心 L3 数据面（真实 TUN、真实密码学、QUIC/mTLS 会话、SOCKS5/HTTP 入站）与 N2 授权/准入闭环是真实落地的；但它当前更像一个"可演示、可查询、可装配"的工程骨架而非可投产产品——N3 任务"提交并真实执行"端到端不通，所有状态观察命令返回硬编码演示数据，5 个 crate 与 3 个平台适配是空壳，多个已实现子系统在生产二进制中没有接线。**

审计基线：HEAD `e6ccf8b`，工作区干净；528 个 .rs 文件、200,336 行；51 个 workspace 成员（3 apps + 47 crates + engineering/nexus-harness）；全仓约 2,103 个测试属性。

## 2. 这是什么系统（从代码推断，而非名字/文档）

从源码行为看，系统由三块相对独立的能力拼成：

1. **N1/N2 虚拟组网与授权面**：在真实 TUN 设备（Linux /dev/net/tun、Windows wintun）与注入式 packet carrier 之上，做虚拟子网、隧道编排、X25519/ChaCha20Poly1305 加密、节点身份（ed25519）、跨机双向握手准入（`n2_admission.rs`）、Grant 授权表与会话持久化（`n2_store.rs`）。
2. **代理与出站协议面**：Clash 风格的纯决策代理内核（规则引擎 + 策略组，`nexus-proxy`）、手写 YAML/订阅配置解析（`nexus-proxy-config`）、SOCKS5/SS/Trojan 真实拨号层（`nexus-proxy-transport`），以及六个出站协议实现（Shadowsocks/Trojan/VMess/VLESS/AnyTLS/Hysteria2）与 NAT 打洞三件套。
3. **N3 durable 任务与内容工作区**：版本化、可持久化的任务账本（acceptance ledger、runtime journal、logs、artifacts、capacity）、真实 Docker Engine API 执行客户端，以及 CAS 内容寻址工作区（commit/merge/conflict/sync）与 Linux FUSE 挂载。

代码中大量出现 N1/N2/N3、P0–P5、E4/E5、§xx 等阶段/文档编号；按审计口径，这些**只代表注释自称的规划阶段**，功能是否存在一律以代码为准。

## 3. 三个二进制：真实入口与命令面

workspace 产出三个二进制（默认 src/main.rs，无显式 [[bin]] 改写）；apps/nexus 与 apps/nexusd 同时产出 lib（互相复用）。

### 3.1 `nexus`（apps/nexus，49,184 行）— 主 CLI / 组合根
- 入口 `apps/nexus/src/main.rs:197 run()`，手写 argv 分派（非 clap），无子命令时打印 USAGE。
- 真实命令面（均回源到 handler 核实）：
  - **N2 闭环（真实）**：`use <name>`（resolve→plan→authorize→establish 四步）、`grant add|revoke|del|list`、`resource list|show|publish|revoke|export|import`、`node init|trust`、`session list|watch|close|seed`、`plan [explain]`、`provider serve`、`pair invite|join|list|remove`（mDNS 未实现，--addr 必填）。
  - **子网/组网**：`subnet up|status|leave|punch`（`--tun` 为真实 TUN）、`network up|status`（**仅 Linux**）、`mesh` 相关装配。
  - **代理**：`proxy run|host|relay|speedtest|bufferbloat-test`（真实 SOCKS5 数据面）；`system-proxy *`、`autostart *`（**仅 Windows**）。
  - **N3 瘦客户端（真实发 HTTP，但 daemon Submit 拒绝）**：`task submit|show|cancel|logs|artifacts`、`artifact get`（下载仅 Linux 完整）。
  - **观察类（转发 daemon，最终拿到硬编码演示数据）**：`status`、`dns status|resolve|providers|cache`、`connectivity *`、`workspace heads|conflicts|cache|commit`、`compute jobs`、`diagnose`、`platform capabilities`。
  - **诚实拒绝**：`run <res> -- <cmd>` 恒返回 UNSUPPORTED run-with-command。

### 3.2 `nexusd`（apps/nexusd，28,877 行）— 守护进程
- 入口 `apps/nexusd/src/main.rs:257`：两种形态——`nexusd <config-folder>`（新入口，run_daemon，:386）与 `nexusd serve [--addr|--socket]`（历史/兼容，:848）。
- run_daemon 真实启动：加载配置（daemon.toml/network.toml/proxy.yaml/dns.toml/workspace.toml）→ boot reconcile → N2 session manager + sweeper → T3 门禁（proxy/network/workspace 三者皆无则 exit 1，main.rs:465-473）→ 装配 N1 → TUN 数据面线程（:514）→ LocalAPI 线程（:541）→（Linux）FUSE workspace + 配置 watcher。
- **对外只暴露一个手写 HTTP/1.1 LocalAPI**（默认 127.0.0.1:18080，config.rs:131-133；Bearer token，常量时间比较）：
  - v0 GET：status、dataplane/stats、dns/status|cache、session/watch、n2/session/*、plan/explain、connectivity/status、platform/capabilities、workspace/mounts|commit（main.rs:1148-1196）——全部转调 `nexus::observability::*`（硬编码演示数据）。
  - v1：唯一路由 `POST /localapi/v1/task`（task_http.rs:201，三重鉴权）；Get/Cancel/ReadLogs/ListArtifacts/GetArtifact 真实，**Submit 硬编码 Unsupported**（task_service_provider.rs:229）。

### 3.3 `nexus-platform-host`（apps/nexus-platform-host，58 行）— 占位薄壳
- 仅在 `--features platform-windows` 时 `vpi-capabilities` 打印静态 VPI 能力 JSON；其余 feature（linux/macos/android/ios）无代码分支，default 仅打印 "repository-contract bootstrap"（main.rs:24）。判定 **stub**。

## 4. Workspace 拓扑（51 成员，分层；完整矩阵见 06）

按依赖方向自底向上（内部依赖边从各 Cargo.toml 实测）：

| 层 | 成员（真实职责一句话） |
|---|---|
| 基础（零内部依赖） | **domain** 全仓核心模型+N3 DTO；**path** 选路打分/竞速；**platform** 8 个 portable trait；**plugin** 混淆插件点；**proto**（dead 空壳）；**proxy-config** 代理配置模型；**scheduler** 内存定时器 |
| 基础工具 | auth 授权判定；registry 资源视图+控制帧；storage 文件持久化；measurement 测量 DTO；policy 动作链引擎；control-api 控制面契约；transport TCP 帧流（partial） |
| 连接/数据面 | connectivity 隧道/加密/STUN 底座（partial）；dns 分类缓存（注入式）；ingress 握手状态机；fabric QUIC/mTLS 会话层 |
| 数据面核心 | projection TUN↔fabric 隧道+egress+smoltcp；network N1 装配泵 |
| 代理/出站 | proxy 决策内核；proxy-transport 真实拨号；outbound-vless/anytls/hysteria2（implemented）、outbound-ss/trojan/vmess（partial 原语） |
| NAT | nat-traversal 打洞状态机；nat-wireup QUIC 打洞接线；nat-quality 探测；turn TURN 栈（仅 examples 接线） |
| 任务/工作区 | compute N3 纯域层；workspace CAS 引擎；workspace-intel 访问智能层（仅 CLI 用） |
| 平台适配 | platform-linux（/dev/net/tun+rtnetlink+FUSE）、platform-windows（wintun/DPAPI/wininet/schtasks）implemented；platform-macos/android/ios 空壳 stub；diagnostics、delivery 空壳 stub |
| 工程门禁 | nexus-harness gate 矩阵 + 277 场景执行器 |
| 组合根 | apps/nexus（partial）、apps/nexusd（partial）、apps/nexus-platform-host（stub） |

## 5. 跨 crate 调用关系主干

```
                        nexus-domain（纯模型，被约 25 个 crate 依赖）
                                     │
   授权/资源：auth ├ registry ├ policy ├ planner ├ storage ├ scheduler ├ measurement
                                     │
   传输底座：nexus-fabric（QUIC/mTLS，quinn-proto sans-IO）
        ├ projection（FabricTransport 包 FabricConn；4 线程真循环；真 TUN/smoltcp/egress）
        ├ proxy-transport（SOCKS5/SS/Trojan 真握手 + u16BE 帧）
        ├ nat-wireup（PunchManager：bi-stream 信令 + 同 socket QUIC 打洞）
        ├ nat-quality（probe/QualityMonitor 喂 path）；turn（TURN 栈，仅 examples）
        └ network（VpiPump/LinkWatcher，装配 N1）
   connectivity（隧道/加密/STUN，被 mesh.rs 真循环驱动；约 1/3 骨架 partial）
        └ 6 个 outbound 协议 crate（→connectivity；ss/trojan 还→plugin）

   nexusd（组合根）
     ├ assembly → assemble_n1(network)、build_dataplane_config、load token
     ├ dataplane（TUN 包分类/QoS；DNS 注入的是 Stub resolver）
     │     └ set_proxy_engine → proxy_fwd.ProxyEngine（仅 SS/Trojan/Socks5 拨号）
     ├ LocalAPI：v1 task_http → LocalTaskService → ProviderService（持久化层）
     └ workspace.rs → nexus-workspace CAS + FUSE
   nexus CLI
     ├ 本地 N2：各 *_cli → n2_store / n2_admission（独立 TCP 跨机准入）
     ├ 观察命令 → localapi_client（HTTP GET unix-socket/loopback）
     └ N3 → task_cli → task_localapi（HTTP POST /localapi/v1/task）
   nexus-harness → gates（真 cargo/git）+ scenarios（276 个子进程场景）；依赖 connectivity/dns/projection
```

## 6. 真实能力清单（代码可证，非文档声称）

**确实可用（有真实逻辑 + 真实调用路径）：**
1. N2 资源访问四步闭环与本地持久化（会话/授权/广告/租约/审计），含真实跨机 ed25519 双向握手准入（n2_admission，14 个 loopback 测试）。
2. 真实 L3 数据面：TUN 收发、UDP/TCP egress、smoltcp 用户态 TCP 终结、SOCKS5/HTTP CONNECT 显式入站（projection，被 nexusd 装配）。
3. 真实密码学：X25519 ECDH、HKDF、ChaCha20Poly1305、防重放（connectivity/encryption）；真实 QUIC/mTLS 会话（fabric，patched quinn-proto）。
4. 代理纯决策内核与手写 YAML/订阅解析；SOCKS5/SS/Trojan 真实拨号转发（nexusd proxy_fwd，生产已 set_proxy_engine）。
5. NAT 打洞：状态机、信令、端口预测、同 socket QUIC fan-out、质量探测（traversal/wireup/quality）。
6. N3 durable 持久化工程（原子写、flock、dev/ino 绑定、崩溃重放）与真实 Docker Engine API 客户端；CAS 工作区与 Linux FUSE 挂载。
7. 工程门禁：真实 cargo/git gate；276 个场景以子进程隔离 + 超时 + JSON 断言执行；未实现项显式 UNKNOWN，不静默 PASS。

**不可用 / 未闭环（高信号缺口）：**
1. N3 "提交并真跑"端到端不通（三重：Submit stub、executor.run 生产无调用、镜像白名单空 + 容量未 provision）。
2. 观察面 17 个命令返回硬编码演示数据（example.com 固定解析、固定 session/IP、"OK:42" 等），不是真实运行状态。
3. vless/anytls/hysteria2/vmess 协议栈虽 implemented，nexusd 生产 dial（proxy_fwd.rs:93-98）不路由；6 个 OutboundAdapter 生产零实例化。
4. 主动路径测量空转（path send_heartbeat_stub 空函数）；DNS 真实上游 resolver 是 stub；配置热加载只打日志。
5. 5 个空壳 crate（diagnostics、delivery、platform-macos/android/ios）；macOS/Android/iOS 平台不落地。
6. flow-session、workspace fabric sync、nat-switch、requester-store 在生产 dead；harness replay 未实现、性能预算门禁空转。

## 7. 构建与运行方式（从 Cargo.toml / main.rs 事实）

- 构建：Rust **edition 2024**、rust-version 1.85；工具链 cargo/rustc 1.99（需 `export PATH="$HOME/.cargo/bin:$PATH"`）。release profile：thin LTO、strip symbols、codegen-units 1、**panic=abort**；workspace lint `warnings = "deny"`。
- 依赖补丁：`[patch.crates-io] quinn-proto = { path = "vendor/quinn-proto" }`（根 Cargo.toml 注释自陈为修复上游 quinn#2658）。
- 构建产物：`cargo build --release` 产出 nexus、nexusd、nexus-platform-host；apps/nexus、apps/nexusd 同时是 lib。
- 运行：
  - daemon：`nexusd <config-folder>`（配置夹内 daemon.toml/network.toml/proxy.yaml/dns.toml/workspace.toml 缺失即不启用对应能力）；兼容 `nexusd serve --addr|--socket`。
  - CLI：`nexus <command>`；观察命令经 unix socket（`$XDG_RUNTIME_DIR/nexus-localapi.sock`）或 TCP 127.0.0.1:18080 访问 daemon，Bearer token 文件 0600。
  - 独立 fuzz：`fuzz/` 是独立 cargo-fuzz workspace（非根成员，需 nightly）。
- 工程门禁入口：`nexus-harness status|check|verify [--fast|--full]|run|scenario|…`（replay 未实现）。

## 8. 整体完成度判断

| 维度 | 判断 | 依据 |
|---|---|---|
| 核心数据面（TUN/加密/隧道/入站） | **基本落地** | projection/fabric/connectivity 真实逻辑 + 生产装配 + 约 700 数据面测试 |
| N2 授权/准入 | **落地最完整** | use/grant/resource + n2_admission/n2_store 真实闭环 |
| 代理决策/配置 | **落地**（转发面部分） | proxy/proxy-config implemented；生产仅 3 类出站可拨号 |
| N3 durable 任务 | **只读回放面，执行面不通** | Submit stub + run 不可达 + 白名单/容量空 |
| 可观测性 | **未落地（演示数据）** | observability 全硬编码 |
| 跨平台（mac/iOS/Android） | **未落地** | 3 个 7 行空壳 + host 无分支 |
| 工程门禁 | **落地且诚实** | harness 真跑 cargo/git + 276 场景，未实现显式 UNKNOWN |

**总体：约 7 成"骨架与核心路径"已建成，但"端到端产品闭环"尚未打通。** 51 个成员中 implemented 36、partial 8、stub 6、dead 1（计数与明细见 06）。

## 9. 最大风险（按影响排序）

1. **可观测性失真**：所有状态/诊断输出是硬编码演示数据，运维与用户据其判断会得到与真实系统无关的结论——这是最危险的"看起来在工作"。
2. **N3 执行闭环断裂**：任务可被持久化/查询/取消，但永远无法提交并真实执行；Docker 客户端虽真，但生产不可达、白名单与容量为空。
3. **已实现能力未接线**：vless/anytls/hysteria2/vmess、TURN、flow-session、workspace sync、nat-switch 等"实现但生产 dead"，代码量造成的能力错觉强。
4. **跨平台缺口**：非 Linux/Windows 全部空壳，平台分发在 macOS/移动端不成立。
5. **决策输入未闭环**：路径主动探测空转、DNS 上游 stub、热加载空转——选路/解析/配置等关键决策的真实数据输入在仓内缺失。

## 10. 文档导航（本审计交付物）

| 文件 | 内容 |
|---|---|
| 00-overview.md | 本文件，自包含总览 |
| 01-cli-apps-nexus.md | apps/nexus 逐文件实际状态 |
| 02-daemon-n3-durable.md | nexusd + compute/workspace(-intel)/platform-host |
| 03-dataplane-connectivity-projection.md | connectivity/projection/network/path/dns/ingress |
| 04-proxy-outbound-nat.md | proxy、6 出站、NAT、TURN、transport/proto |
| 05-core-platform-harness.md | 核心域、平台适配、harness、非成员制品 |
| 06-implementation-status.md | 51 成员状态矩阵 + 声明未落地总清单 |
| 07-comment-errors.md | 注释错误清单（high 2 / medium 9 / low 9，剔除误报 1） |
| 08-verification-log.md | 两层复核记录与仍无法确认项 |
