# Shard D · 代理 / 出站协议 / NAT 穿透 源码状态审计

> **口径声明（逐字遵循 AUDIT-SPEC 5.1）**：本结论仅以源码为事实来源。仓库中所有 `.md` 叙述性文档均被用户声明为错误，不作为依据；每个判定均带 `文件:行号` 证据；实现度按四档（implemented / partial / stub / dead）；注释不符按五要素定位；遵守只读红线（未修改任何 crate 源码，仅在本审计目录落盘）。
>
> 审计对象 HEAD：`e6ccf8b`。片区 15 个 workspace 成员，约 25,385 行 `.rs`。

## 0. 结论速览（15 成员实现度判定）

| crate | 行数 | 判定 | 一句证据 |
|---|---:|---|---|
| nexus-proto | 7 | **dead** | 整文件仅 `#![forbid(unsafe_code)]` + doc，零 pub item（`src/lib.rs:1-7`），全仓零引用 |
| nexus-transport | 94 | **partial** | 仅实现同步 TCP u32BE 长度前缀 `FrameStream`（`src/lib.rs:42-91`），doc 自称的 Datagram/Mux/Reuse/Backpressure 不存在 |
| nexus-outbound-vmess | 220 | **partial** | 仅单帧 chacha20poly1305 自洽（`src/lib.rs:134/152`），无 VMess 请求头编解码、无建连/转发 |
| nexus-outbound-shadowsocks | 461 | **partial** | AEAD 记录帧 + SOCKS 地址编解码完整（`:279 SsStream`），但无 `connect`/relay 循环，纯原语库 |
| nexus-outbound-trojan | 502 | **partial** | Trojan 请求行编解码 + rustls 配置原语（`:127/356`），`TrojanAdapter::new` 丢弃密码（`:241`），无转发 |
| nexus-outbound-vless | 2,060 | **implemented** | 完整握手头/ UDP-over-TCP/XTLS-Vision 读写状态机（`:365/:667/:882`），35 测试含 loopback TCP/TLS/vision 集成 |
| nexus-outbound-anytls | 1,795 | **implemented** | 多路复用会话 client/server 握手完整（`:755/:903`），24 测试含真实 loopback TLS 往返 |
| nexus-outbound-hysteria2 | 3,292 | **implemented** | quinn-proto 真 QUIC + H3 最小认证 + TCP/UDP 数据面（`client.rs:56`），50 测试含 loopback echo |
| nexus-proxy | 2,204 | **implemented** | 规则引擎 + 策略组 + 出站 tag 解析纯决策内核（`src/lib.rs:634/939`），零网络 I/O，47 测试 |
| nexus-proxy-config | 2,360 | **implemented** | 手写 YAML 解析 + 9 变体 OutboundKind 配置模型 + base64 订阅解析（`:309/:730/:1458`），零第三方依赖，34 测试 |
| nexus-proxy-transport | 3,541 | **implemented** | SOCKS5/SS/Trojan/TrojanTLS 真握手 + u16BE 帧层 over `Mutex<TcpStream>`（`framed.rs:63`），40 测试 |
| nexus-nat-traversal | 1,678 | **implemented** | 打洞状态机 + 信令编解码 + 有界端口预测（`lib.rs:350`、`predict.rs:37`），STUN 样本由组合根注入，8 测试 |
| nexus-nat-wireup | 3,854 | **implemented** | 生产接线 PunchManager：bi-stream 信令 + 同 socket QUIC fan-out 打洞 + tie-break（`lib.rs:129`），14 测试 |
| nexus-nat-quality | 1,043 | **implemented** | 25B probe 帧 + 滑动窗口丢包估计 + QualityMonitor 后台喂 PathManager（`probe.rs`、`monitor.rs:82`），19 测试 |
| nexus-turn | 2,274 | **implemented** | 真 RFC5766 TURN client/server：Allocate/Permission/Channel/Refresh + 长效认证（`client.rs:104`），18 测试；但仅 examples/自测接线 |

**测试总数**：301 个 `#[test]`/`#[tokio::test]`（逐 crate 统计见片段 D-1~D-6）。

## 1. 出站协议逐个定性

### 1.1 小行数 crate 逐行结论
- **vmess（220）**：读完。`VmessAdapter::new`（`:95`）SHA256(UUID)→32B key；`encrypt`（`:134`）用自增计数器拼 12B nonce 做单帧 AEAD，`decrypt`（`:152`）用帧内 nonce。**没有 VMess 协议头**（版本/指令/端口/地址字段全缺），`handoff`（`:163`）只返回 DTO。三测试全是自加密自解密。→ **partial**。
- **shadowsocks（461）**：读完。是六个出站里最"厚"的原语库——`SsTarget`、`encode_request/parse_request`（`:225/248`）、双 key `SsStream`（`:279`）、u32BE record（`:355/368`）。但它从不持有 `TcpStream`，不拨号、不 relay。→ **partial（原语完整，数据面未接线）**。
- **trojan（502）**：读完。`auth_hash=hex(SHA224(pwd))`（`:95`），请求行 `hash\r\n\x01ATYP\r\n\r\n`（`:127`）；TLS 侧提供 rcgen 自签、`SkipCertVerify`、dangerous skip-verify 客户端配置。`TrojanAdapter::new(tag,locator,_password)`（`:241`）显式丢弃密码。→ **partial**。

### 1.2 大行出站 crate
- **vless（2,060）**：协议层真实落地——UUID/flow/target/command 全编解码，握手请求/响应、UDP-over-TCP 分包、XTLS-Vision 的 `VisionReader/VisionWriter` 状态机与 XorShift 填充 PRNG。`VlessAdapter::handoff` 离线（`:1067`），注释明确"真实建连/传输链装配由 Composition Root 完成"（`:1007-1008`）。集成测试用 loopback mock server 真跑 TCP+TLS 回显。→ **implemented（协议库）**。
- **anytls（1,795）**：7 字节帧头、认证帧、Settings 协商、padding scheme（md5）、UoT、client/server 双向握手状态机；测试含多个真实 loopback TLS server/client 握手。→ **implemented（协议库）**。
- **hysteria2（3,292）**：唯一自带真实 QUIC 传输栈的出站。`Driver` 用 quinn-proto sans-IO + 自写 UDP pump（`driver.rs`），H3 最小 SETTINGS/认证流校验 `:status==233`，Salamander BLAKE2b 混淆在 UDP 包层，TCP/UDP 代理数据面齐全。注释自述未实现：Brutal CC（用 Cubic）、端口跳跃、UDP 大包分片、完整 H3。→ **implemented（生产可用度最高的出站）**。

## 2. nexus-proxy / config / transport 真实职责与接线

- **nexus-proxy 不是代理转发主体**。它是纯决策内核：`RuleEngine`（`lib.rs:634`）对 `FlowTarget` 线性首匹配；`SelectorGroup`/`UrltestGroup`/`LoadBalance`/`Relay` 四种策略组；`ProxyService::route`（`:1005`）产出 `RoutingDecision`；`activate_outbound`（`:1072`）把选定 tag 委派给注入的 `LinkActivator<P:LinkProbe>`。它**不监听本地端口、不读写 socket**；历史上的 per-packet 五元组缓存已迁移到 `nexus-projection::transparent::decision::FlowDecisionCache`（TUN/TPROXY 共用）。
- **出站激活委派边界**（`:1090-1100`）：Direct/Relay 才进 `LinkActivator`；Shadowsocks/Vmess/Trojan/Anytls/Vless/Hysteria2/Socks5 的 relay candidate 一律 `None`，注释称"由对应 nexus-outbound-* adapter 在 Composition Root 承接"。
- **proxy-config**：手写 YAML 子集 AST 解析器（零第三方依赖），`OutboundKind` 9 变体（`:309`），`OutboundConfig` 富字段（method/password/alpn/uuid/flow/tls/sni/ports/up/down/obfs_password…），并带 clash 订阅 base64 解析与订阅运行时状态机（`:1458/:1596`，真正 HTTP 拉取在组合根 `:1488`）。
- **proxy-transport**：per-link 隧道层，把 QUIC datagram 经"TCP 代理握手 + u16BE 帧"承载，实现 `nexus_fabric::UdpTransport`。四种真握手（SOCKS5 RFC1928/1929、SS 复用 outbound-shadowsocks 的 `SsStream`、Trojan 明文、Trojan-TLS rustls）。这是生产 nexusd 真正拨号的层（`apps/nexusd/src/tcp_relay.rs:209-233`）。

### 2.1 关键接线真相（生产转发面缺口）
`apps/nexusd/src/proxy_fwd.rs:55-100` `dial_config_from_outbound`：
- 仅 **Shadowsocks(chacha20) / Trojan / TrojanTls / Socks5** 产出 `ProxyDialConfig`；
- **Direct / Relay / Vmess / Anytls / Vless / Hysteria2 一律返回 None**（`:93-98`），导致 `ProxyEngine::new`（`:116`）返回 None、该 proxy 分类不转发。

即：**vmess / vless / anytls / hysteria2 四个协议栈虽然 implemented，但在 nexusd 生产转发面未被路由到**；六个 `OutboundAdapter` 实现（vmess:163/trojan:259/vless:1067/ss:161/hy2:54/anytls:1017）在 `apps/*/src` 生产源码零实例化，仅存在于 `apps/nexus/examples/`。

## 3. NAT 三件套 + TURN

- **nexus-nat-traversal**：打洞编排状态机（offer→answer nonce 匹配→协同开打 spray→await_direct）。**它不含 STUN 客户端**——`PortSample` 由组合根注入（`lib.rs:159-161` 注释明说），`PunchChannel`/`PunchSocket` 是注入 trait。端口预测器 `DefaultPredictor`（`predict.rs:37`）基于"连续 Δ 相等"判定可预测并生成 ±K spray 窗口。
- **nexus-nat-wireup**：把编排接到真实 `nexus-fabric::Driver`——`FabricPunchChannel`（中继 bi-stream 上跑 P2 codec）、`DriverPunchSocket`（同 UDP socket 后台 `Driver::connect` fan-out，Initial 包即打洞）、`PunchManager`（responder 循环/去重/PeerId tie-break/nonce 绑定挑战防冒充/非 punch 流 stash）。`LoggingFeed` 注释自述"Real PathManager integration is a follow-up"（`lib.rs:82`）。生产 `apps/nexusd/src/nat_switch.rs:30-33` 真实接线。
- **nexus-nat-quality**：25B probe ping/pong 帧、滑动窗口丢包估计、`QualityMonitor` 后台循环把 RTT（取 quinn `stats().rtt_ms`）与丢包喂 `PathManager`；注释明确不用 `stats().loss_rate`（从未填充，`lib.rs:28-29`）。
- **nexus-turn**：**是真 TURN 协议栈不是壳**——STUN 编解码、MD5/HMAC-SHA1 长效认证、Allocate(401 重发)/Permission/ChannelBind/Refresh、`TurnSocket: UdpTransport`、最小 TURN server。但接线范围仅限 **nexus-nat-wireup/examples 与自测**；生产 `nat_switch.rs` 未 import，`src/` 零 `use nexus_turn`。

### 3.1 nexus-transport(94) 与 nexus-proto(7) 真实内容
- `nexus-proto`：空 crate（7 行），全仓无任何 Cargo.toml 依赖、无源码引用 → **dead**。
- `nexus-transport`：同步 TCP 长度前缀 `FrameStream`（`send_frame`/`recv_frame`/`connect`/`accept`），仅 apps/nexus 依赖；doc 夸大了能力集。

## 4. dead / 凭据 / 空转发排查
- **dead**：nexus-proto（空壳零引用）。
- **声明未落地（接线缺口）**：vmess/vless/anytls/hysteria2 在 nexusd 生产 dial 路径未接线（§2.1）；nexus-turn 仅 examples 接线。
- **硬编码凭据/服务器**：无。命中字面量（`"p"`、`"trojan-secret"`、`"s3cr3t"`、`10.0.0.0/8`、`8.8.8.8`）全部位于 `#[cfg(test)]` 或 `examples/`。
- **空转发**：无；shutdown D 源码无 `todo!`/`unimplemented!` 生产桩，"Unsupported" 均为正当类型化错误（IPv6 目标本期不支持、未知 obfs/flow）。

## 5. 注释与代码不符
- **HIGH 级数量：0**。
- **MEDIUM 级：1**
  - `nexus-proxy-transport/src/lib.rs:43-48`：注释称"`OutboundKind` has no `Socks5` variant; SOCKS5 there is inbound/ingress only"——事实 `nexus-proxy-config/src/lib.rs:321` 已有 `OutboundKind::Socks5` 且生产 `proxy_fwd.rs:91` 已接线。陈旧/位置错误。
- **LOW 级：3**
  - `nexus-proto/src/lib.rs:3`：自称"portable schema 边界与代码生成占位接口"，实际空文件零 item。
  - `nexus-transport/src/lib.rs:3`：自称覆盖 Stream/Datagram/Mux/Reuse/Backpressure，实际仅 FrameStream。
  - `nexus-outbound-trojan/src/lib.rs:241`：`TrojanAdapter::new` 形参 `_password` 被丢弃却无注释说明，调用方契约不清。

## 6. 仍无法确认 / 待上层分片或组合根确认
1. **真实端到端转发是否跑通**：本 shard 只到"出站协议库 + proxy-transport 拨号 + 决策内核"；真正把 `FlowContext→选定出站→建连→字节 relay` 串起来的 Composition Root 在 `apps/nexus`（非本 shard），其是否实例化 vless/anytls/hy2 adapter 未在本审计范围核验（生产 nexusd 路径已确认不接线）。
2. **STUN 采样的真实采集点**：traversal 声明由组合根注入 `PortSample`，注入方（driver/discovery 某 crate）不在本 shard，样本真实性无法在此验证。
3. **nexus-proto 是否为占位待建**：空壳可能是计划中未开工的 schema crate，非废弃；仅从本仓源码无法区分"有意空壳"与"遗漏"。
4. **hysteria2 Brutal CC / 端口跳跃**：注释自述未实现，但是否在 driver 上层以其他方式补偿，超出本 shard。

---
*支撑证据：`fragments/06-D.md`（出站协议+proxy 接线）、`fragments/07-D.md`（NAT+TURN）、`fragments/08-D.md`（dead/凭据/注释错误）。*
