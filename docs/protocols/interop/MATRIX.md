# 出站协议互操作证据总表（MATRIX）

> 本文件由 `scripts/interop/recompute-verdicts.py` 从证据机械生成；人工零编辑。
> 修复顺序、依赖与复验口径见人工维护的 [NEXT-STEPS.md](NEXT-STEPS.md)。

- run `protocol-interop-fixes-3`；baseline `29a299eeba58be2411c95e5e7baf0d64a0a0339e`；spec frozen v1.1（sha256 `67fb4bcb119b2bf2fd12d64533462489a75f37fcc41df6a66c2a86e6e7fa82b8`）；test window `2026-10-24T17:30:56Z .. 2026-10-25T11:15:26Z`。
- 参照实现：sing-box 1.13.16（sha256 `8da901e7b6eb0d2f6f6e701f19d5f78af235d038ae078b37a70739db5895d262`）；Xray 26.10.21（sha256 `a27e3f95ab6ce270956d0cecd32eda4686a811afc71c64a6a734a3dede14883e`）。
- archive（主机归档路径）：`/work/interop-run/protocol-interop-fixes-3/archive/protocol-interop-fixes-3-20261025T112538Z.tar.zst`。

## 先读：范围 / 结论 / 图例

- **覆盖**：5 个出站代理协议（VLESS、AnyTLS、Hysteria2、Trojan、Shadowsocks）共 46 个证据格。TCP 成功型格走产品 SOCKS5 出口路径；`UdpEcho` 与 VLESS Vision 部分格为 crate 直调（`CrateDirect`），不代表产品入口可用。
- **不覆盖**：VMess（本轮暂缓）、direct/relay/socks5 出站、TUN/VPN、Android 统一 VPN 入口、UI/诊断呈现。
- **本表不回答**：直连/中继回退是否可用（属 N1 整体结论）；也不把「产品级 UDP 未实现」扩大成「Hy2 的 QUIC 出站传输不可用」（见产品级 UDP 节）。
- **结论 1**：本次复算：`VERIFIED` 2 个（Vless、Anytls），`PARTIAL` 0 个，`BROKEN` 3 个（Hysteria2、Trojan、Shadowsocks）；当前可宣称可用（`VERIFIED`）的协议为 Vless、Anytls。
- **结论 1 限定**：`USABLE` 指 TCP 产品路径；产品 SOCKS5 UDP ASSOCIATE 五协议均未实现，`UdpEcho` 为 crate 级证据、不代表产品入口可用。
- **结论 2**：剩余阻断分属协议编解码、协议线格式与产品安全语义/产品能力缺口；本 run 已消除产品装配（VLESS eager read）与跨协议传输（T2）两类阻断。`root_cause_class` 只是规则代表类，不是完整根因。
- **结论 3**：未达 `VERIFIED` 的协议及本次复算代表根因：Hysteria2 `BROKEN / E_TIMEOUT_HANG`；Trojan `BROKEN / E_NEXUS_FRAMING`；Shadowsocks `BROKEN / E_NEXUS_HANDSHAKE_WIRE`。
- **结论 4**：Trojan/SS 当前仍受 fallback 安全语义/线格式与产品 UDP 缺口阻断；即使其余修复完成，本 run `UdpEcho` 固定 `NOT_IMPLEMENTED`，上限仍为 `PARTIAL / TCP_ONLY / USABLE_WITH_GAPS`（spec E1 规则 6/R11）。
- **结论 5**：五协议当前均可在产品配置面选择，且无「实验性/未验证」标注；配置面标注已裁决批准，待 protocol-config-surface-labeling run 落地（本 run 不改产品代码）。
- **优先级 1（P4，DONE）**：Hysteria2 QPACK Huffman 解码——RFC 7541 Huffman 解码接入两个字面量消费点；Default H/T1/L/R/U/BC/BX 由 E_NEXUS_CODEC 转 PASS，QpackDiag 解码成功并记录认证字段；T2 仍 FAIL/E_TIMEOUT_HANG（吞吐路径，非 codec）；证据：commit `fbc5db3`；commit `da86d3a`；commit `f692f2d`；prediction-check。
- **优先级 2（P4b，待办）**：Hysteria2 T2 吞吐路径——32 MiB 上传在认证后挂死（8 MiB 通过、16 MiB 挂死）；按 spec §3.2 定性为 transport/流控路径问题，另行根因，不在本 run 修。
- **优先级 3（P5，待办）**：Hysteria2 Salamander（fixes-4）——本 run 不跑 Salamander 任何格；Salamander/H 保持基线 FAIL/E_NEXUS_CODEC 证据。
- **字段**：`verdict` = `VERIFIED`（规则 8，全 required PASS）/ `PARTIAL`（规则 3–7/9，非阻断缺口）/ `BROKEN`（规则 1/2，阻断性 Nexus 失败）；`scope` = `PROTOCOL_SUBSET` / `FULL` / `TCP_ONLY`；`claim` = `USABLE` / `USABLE_WITH_GAPS` / `NOT_USABLE` / `NOT_CLAIMED`；`carrier` = `ProductSocks5`（产品 SOCKS5 出口路径）/ `CrateDirect`（crate 直调，非产品入口）。
- **规则 1**：失败格（BadCredential/BadConfig）判 FAIL 且表现为有效 echo/静默成功（`E_NEXUS_FRAMING`）或挂死（`E_TIMEOUT_HANG`）→ `BROKEN`。
- **规则 2**：任一 required 格 FAIL 且 class 属 `E_NEXUS_*` / `E_TIMEOUT_HANG` → `BROKEN`。
- **错误类**：`E_NEXUS_*` = Nexus 侧失败（握手/线格式、认证编码、帧/静默成功、传输、UDP、编解码、未实现），判 FAIL；`E_TIMEOUT_HANG` = 挂死/超时，判 FAIL；`E_EXPECTED_*` = 预期认证/配置拒绝，负向格判 PASS；`E_REF_*` / `E_NETWORK_ENV` / `E_TOOL_BUG` / `E_EVIDENCE_GAP` = 参照端/环境/证据缺口，判 BLOCKED（`E_REF_LIMITATION` 判 FAIL，须带 `ref_source`/`ref_version`）。
- **Xray**：26.10.21 仅用于 VLESS Vision 争议裁决，本轮未触发；五协议结论全部来自 sing-box 1.13.16 参照。
- **测试广度**：上述结论仅对 sing-box 1.13.16 参照配置成立；Xray 26.10.21 本轮未触发作裁决；其他服务端实现/传输组合（含 REALITY、ws/grpc）未测。

## ⚠ 安全警示：Trojan fallback fail-open

- **触发条件**：Trojan 密码错误、服务端被劫持，或服务端配置了 fallback（本 run 参照端 fallback → HTTP 404）。
- **用户所见**：SOCKS5 CONNECT 已回 success，服务端 fallback 的 HTTP 响应被当作隧道数据交给应用（404 页面内容），用户误以为代理成功。
- **白皮书映射**：违背 §6.2「路径失效时按配置阻断或回退，并向用户显示实际行为」与 §16.1 N1「失败与恢复可观察」。
- **当前临时缓解（仅文档层）**：把含 fallback 的 Trojan 出站视为实验性/不安全；产品负责人决定是否默认禁用。本 run 不改产品代码。
- **完整修复成本**：延迟 SOCKS5 success 至上游就绪或等价 fail-closed 方案，>400 行 / >2 人日，触及 `proxy_serve_once` 全部出站路径，应另立 run。
- **证据**：`TrojanFallback/BadCredential`（FAIL，`E_NEXUS_FRAMING`），根因见 [fix/trojan/root-cause.md](fix/trojan/root-cause.md)。

## 协议 verdict（按 spec E1 复算）

| 协议 | verdict | scope | claim | root_cause_class | missing_cells | 命中规则 |
|---|---|---|---|---|---|---|
| Vless | VERIFIED | PROTOCOL_SUBSET | USABLE | NONE | NONE | 8 |
| Anytls | VERIFIED | FULL | USABLE | NONE | NONE | 8 |
| Hysteria2 | BROKEN | PROTOCOL_SUBSET | NOT_USABLE | E_TIMEOUT_HANG | TcpThroughput(FAIL,E_TIMEOUT_HANG), Handshake[Hy2Salamander](FAIL,E_NEXUS_CODEC) | 2 |
| Trojan | BROKEN | TCP_ONLY | NOT_USABLE | E_NEXUS_FRAMING | UdpEcho(NOT_IMPLEMENTED,E_NEXUS_NOT_IMPLEMENTED), BadCredential[TrojanFallback](FAIL,E_NEXUS_FRAMING) | 1 |
| Shadowsocks | BROKEN | TCP_ONLY | NOT_USABLE | E_NEXUS_HANDSHAKE_WIRE | Handshake(FAIL,E_NEXUS_HANDSHAKE_WIRE), TcpSmall(FAIL,E_NEXUS_FRAMING), TcpThroughput(FAIL,E_NEXUS_FRAMING), LongLived(FAIL,E_NEXUS_FRAMING), Reconnect(FAIL,E_NEXUS_FRAMING), UdpEcho(NOT_IMPLEMENTED,E_NEXUS_NOT_IMPLEMENTED) | 2 |

## 阻塞层、归属与修复后上限

`root_cause_class` 是 E1 首个命中规则所取的**代表类**，不是完整根因；下表按 fix 根因文档给出直接阻塞层与归属，不改变上表 verdict。

| 协议 | 直接阻塞层 | 归属 | 剩余阻塞格（相对可用） | 单协议可解？ | 修复后本 run schema 上限 |
|---|---|---|---|---|---|
| Vless | 无（本 run 已修复，证据见「fix 支线与复验」） | — | 无 | — | `VERIFIED / PROTOCOL_SUBSET`（Vision 仅 crate 级，产品 splice 未实现） |
| Anytls | 无（本 run 已修复，证据见「fix 支线与复验」） | — | 无 | — | `VERIFIED / FULL` |
| Hysteria2 | 认证响应 QPACK Huffman | 协议编解码实现错误 | TcpThroughput(FAIL,E_TIMEOUT_HANG), Handshake[Hy2Salamander](FAIL,E_NEXUS_CODEC) | 是（编解码一处） | `VERIFIED / FULL` |
| Trojan | fallback 静默接受 + 产品 UDP 未实现 | 产品安全语义 + 产品 UDP 能力缺口 | UdpEcho(NOT_IMPLEMENTED,E_NEXUS_NOT_IMPLEMENTED), BadCredential[TrojanFallback](FAIL,E_NEXUS_FRAMING) | 否，依赖产品 UDP / fallback 架构 | 本 run 最高 `PARTIAL / TCP_ONLY / USABLE_WITH_GAPS`（U 未实现，规则 6） |
| Shadowsocks | 线格式/SIP004 AEAD + 产品 UDP 未实现 | 协议实现错误 + 产品 UDP 能力缺口 | Handshake(FAIL,E_NEXUS_HANDSHAKE_WIRE), TcpSmall(FAIL,E_NEXUS_FRAMING), TcpThroughput(FAIL,E_NEXUS_FRAMING), LongLived(FAIL,E_NEXUS_FRAMING), Reconnect(FAIL,E_NEXUS_FRAMING), UdpEcho(NOT_IMPLEMENTED,E_NEXUS_NOT_IMPLEMENTED) | 否，依赖产品 UDP | 本 run 最高 `PARTIAL / TCP_ONLY / USABLE_WITH_GAPS`（U 未实现，规则 6） |

**参照端生态**：本轮未发现参照端生态缺陷——sing-box 1.13.16 的行为符合规范；Xray 26.10.21 仅用于 Vision 争议裁决，本轮未触发。五协议 verdict 均无 `E_REF_*` 根因。

## Vless

> **verdict=VERIFIED / claim=USABLE**（scope=PROTOCOL_SUBSET，root_cause_class=NONE）
>
> 本节任一 PASS 不改变协议 verdict；单格 PASS 只在所列 carrier/scope 下成立。
> VlessVision 行为 crate 级证据，产品 Vision splice 未实现。

| Cell | 状态 | carrier | scope | evidence_id | class | 关键数字 | 证据路径 | notes |
|---|---|---|---|---|---|---|---|---|
| Default/Handshake | PASS | ProductSocks5 | ProductPath | PIV-vless-default-handshake-20261024T214820Z-001 | NONE | up=1B down=1B | evidence/vless/default/handshake/PIV-vless-default-handshake-20261024T214820Z-001/probe.json | proxy_json routing.outbound_kind=vless outbound.kind=vless; target_stats={"tcp_bytes_down":2,"tcp_bytes_up":2,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} … |
| Default/TcpSmall | PASS | ProductSocks5 | ProductPath | PIV-vless-default-tcp-small-20261024T214824Z-001 | NONE | up=65536B down=65536B | evidence/vless/default/tcp-small/PIV-vless-default-tcp-small-20261024T214824Z-001/probe.json | proxy_json routing.outbound_kind=vless outbound.kind=vless; target_stats={"tcp_bytes_down":65537,"tcp_bytes_up":65537,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} … |
| Default/TcpThroughput | PASS | ProductSocks5 | ProductPath | PIV-vless-default-tcp-throughput-20261024T214827Z-001 | NONE | median=1388514117B/s samples=3 | evidence/vless/default/tcp-throughput/PIV-vless-default-tcp-throughput-20261024T214827Z-001/probe.json | proxy_json routing.outbound_kind=vless outbound.kind=vless; target_stats={"tcp_bytes_down":101716128,"tcp_bytes_up":101712896,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} … |
| Default/LongLived | PASS | ProductSocks5 | ProductPath | PIV-vless-default-long-lived-20261024T214832Z-001 | NONE | heartbeats=12 | evidence/vless/default/long-lived/PIV-vless-default-long-lived-20261024T214832Z-001/probe.json | proxy_json routing.outbound_kind=vless outbound.kind=vless; target_stats={"tcp_bytes_down":13,"tcp_bytes_up":13,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} … |
| Default/Reconnect | PASS | ProductSocks5 | ProductPath | PIV-vless-default-reconnect-20261024T215026Z-001 | NONE | reconnects=3 | evidence/vless/default/reconnect/PIV-vless-default-reconnect-20261024T215026Z-001/probe.json | proxy_json routing.outbound_kind=vless outbound.kind=vless; target_stats={"tcp_bytes_down":4,"tcp_bytes_up":4,"tcp_connections":4,"udp_bytes":0,"udp_datagrams":0} … |
| Default/UdpEcho | PASS | CrateDirect | ProtocolWire | PIV-vless-default-udp-echo-20261024T215033Z-001 | NONE | udp 1000/1000 corrupt=0 | evidence/vless/default/udp-echo/PIV-vless-default-udp-echo-20261024T215033Z-001/probe.json | udp_seq_and_hash_ok; target_stats={"tcp_bytes_down":0,"tcp_bytes_up":0,"tcp_connections":0,"udp_bytes":512064,"udp_datagrams":1001} …; crate 级，产品入口不可用 |
| Default/BadCredential | PASS | ProductSocks5 | ProductPath | PIV-vless-default-bad-credential-20261024T215038Z-001 | E_EXPECTED_AUTH_REJECT | up=0B down=0B | evidence/vless/default/bad-credential/PIV-vless-default-bad-credential-20261024T215038Z-001/probe.json | proxy_json routing.outbound_kind=vless outbound.kind=vless; workload_error=eof; classification=E_EXPECTED_AUTH_REJECT; reference closed the session on the negative case …; 限定：正向路径不通时本格仅证明无静默成功，不独立证明认证拒绝语义 |
| Default/BadConfig | PASS | ProductSocks5 | ProductPath | PIV-vless-default-bad-config-20261024T215041Z-001 | E_EXPECTED_CONFIG_REJECT | up=0B down=0B | evidence/vless/default/bad-config/PIV-vless-default-bad-config-20261024T215041Z-001/probe.json | proxy_json routing.outbound_kind=vless outbound.kind=vless; workload_error=eof; classification=E_EXPECTED_CONFIG_REJECT; reference closed the session on the negative case …; 限定：正向路径不通时本格仅证明无静默成功，不独立证明认证拒绝语义 |
| VlessVision/Handshake | PASS | CrateDirect | ProtocolWire | PIV-vless-vless-vision-handshake-20261024T215044Z-001 | NONE | up=1B down=1B | evidence/vless/vless-vision/handshake/PIV-vless-vless-vision-handshake-20261024T215044Z-001/probe.json | vision_commands=["continue"]; target_stats={"tcp_bytes_down":2,"tcp_bytes_up":2,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} …; crate 级，产品 splice 未实现 |
| VlessVision/TcpSmall | PASS | CrateDirect | ProtocolWire | PIV-vless-vless-vision-tcp-small-20261024T215048Z-001 | NONE | up=65536B down=65536B | evidence/vless/vless-vision/tcp-small/PIV-vless-vless-vision-tcp-small-20261024T215048Z-001/probe.json | vision_commands=["continue", "continue", "end"]; target_stats={"tcp_bytes_down":65537,"tcp_bytes_up":65537,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} …; crate 级，产品 splice 未实现 |

## Anytls

> **verdict=VERIFIED / claim=USABLE**（scope=FULL，root_cause_class=NONE）
>
> 本节任一 PASS 不改变协议 verdict；单格 PASS 只在所列 carrier/scope 下成立。
> PaddingDiag 为诊断格，不参与 verdict。
> AnyTLS：session 池/心跳定时器/padding 写路径未单独验。

| Cell | 状态 | carrier | scope | evidence_id | class | 关键数字 | 证据路径 | notes |
|---|---|---|---|---|---|---|---|---|
| Default/Handshake | PASS | ProductSocks5 | ProductPath | PIV-anytls-default-handshake-20261024T213337Z-001 | NONE | up=1B down=1B | evidence/anytls/default/handshake/PIV-anytls-default-handshake-20261024T213337Z-001/probe.json | proxy_json routing.outbound_kind=anytls outbound.kind=anytls; target_stats={"tcp_bytes_down":2,"tcp_bytes_up":2,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} … |
| Default/TcpSmall | PASS | ProductSocks5 | ProductPath | PIV-anytls-default-tcp-small-20261024T213340Z-001 | NONE | up=65536B down=65536B | evidence/anytls/default/tcp-small/PIV-anytls-default-tcp-small-20261024T213340Z-001/probe.json | proxy_json routing.outbound_kind=anytls outbound.kind=anytls; target_stats={"tcp_bytes_down":65537,"tcp_bytes_up":65537,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} … |
| Default/TcpThroughput | PASS | ProductSocks5 | ProductPath | PIV-anytls-default-tcp-throughput-20261024T213344Z-001 | NONE | median=341779977B/s samples=3 | evidence/anytls/default/tcp-throughput/PIV-anytls-default-tcp-throughput-20261024T213344Z-001/probe.json | proxy_json routing.outbound_kind=anytls outbound.kind=anytls; target_stats={"tcp_bytes_down":101716128,"tcp_bytes_up":101712896,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} … |
| Default/LongLived | PASS | ProductSocks5 | ProductPath | PIV-anytls-default-long-lived-20261024T213353Z-001 | NONE | heartbeats=12 | evidence/anytls/default/long-lived/PIV-anytls-default-long-lived-20261024T213353Z-001/probe.json | proxy_json routing.outbound_kind=anytls outbound.kind=anytls; target_stats={"tcp_bytes_down":13,"tcp_bytes_up":13,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} … |
| Default/Reconnect | PASS | ProductSocks5 | ProductPath | PIV-anytls-default-reconnect-20261024T213546Z-001 | NONE | reconnects=3 | evidence/anytls/default/reconnect/PIV-anytls-default-reconnect-20261024T213546Z-001/probe.json | proxy_json routing.outbound_kind=anytls outbound.kind=anytls; target_stats={"tcp_bytes_down":4,"tcp_bytes_up":4,"tcp_connections":4,"udp_bytes":0,"udp_datagrams":0} … |
| Default/PaddingDiag | PASS | ProductSocks5 | ProductPath | PIV-anytls-default-padding-diag-20261024T213601Z-001 | NONE | up=0B down=0B | evidence/anytls/default/padding-diag/PIV-anytls-default-padding-diag-20261024T213601Z-001/probe.json | proxy_json routing.outbound_kind=anytls outbound.kind=anytls; serversettings_inferred; target_stats={"tcp_bytes_down":1,"tcp_bytes_up":1,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} …; 诊断格，不参与 verdict |
| Default/UdpEcho | PASS | CrateDirect | ProtocolWire | PIV-anytls-default-udp-echo-20261024T213554Z-001 | NONE | udp 1000/1000 corrupt=0 | evidence/anytls/default/udp-echo/PIV-anytls-default-udp-echo-20261024T213554Z-001/probe.json | udp_seq_and_hash_ok; target_stats={"tcp_bytes_down":0,"tcp_bytes_up":0,"tcp_connections":0,"udp_bytes":512064,"udp_datagrams":1001} …; crate 级，产品入口不可用 |
| Default/BadCredential | PASS | ProductSocks5 | ProductPath | PIV-anytls-default-bad-credential-20261024T213558Z-001 | E_EXPECTED_AUTH_REJECT | up=0B down=0B | evidence/anytls/default/bad-credential/PIV-anytls-default-bad-credential-20261024T213558Z-001/probe.json | proxy_error=ConnectivityEstablishmentFailed { provider: ProviderId("ref"), reason: "anytls session handshake failed: anytls io error" }; workload_error=read: Connection reset by peer (os error 104) … |
| AnyTlsCustomPadding/BadConfig | PASS | ProductSocks5 | ProductPath | PIV-anytls-anytls-custom-padding-bad-config-20261024T213605Z-001 | E_EXPECTED_CONFIG_REJECT | up=0B down=0B | evidence/anytls/anytls-custom-padding/bad-config/PIV-anytls-anytls-custom-padding-bad-config-20261024T213605Z-001/probe.json | proxy_error=ConnectivityEstablishmentFailed { provider: ProviderId("ref"), reason: "anytls session handshake failed: anytls server requested padding scheme update" } … |

## Hysteria2

> **verdict=BROKEN / claim=NOT_USABLE**（scope=PROTOCOL_SUBSET，root_cause_class=E_TIMEOUT_HANG）
>
> 本节任一 PASS 不改变协议 verdict；单格 PASS 只在所列 carrier/scope 下成立。
> QpackDiag 为诊断格，不参与 verdict。

| Cell | 状态 | carrier | scope | evidence_id | class | 关键数字 | 证据路径 | notes |
|---|---|---|---|---|---|---|---|---|
| Default/TcpSmall | PASS | ProductSocks5 | ProductPath | PIV-hysteria2-default-tcp-small-20261025T111158Z-001 | NONE | up=65536B down=65536B | evidence/hysteria2/default/tcp-small/PIV-hysteria2-default-tcp-small-20261025T111158Z-001/probe.json | proxy_json routing.outbound_kind=hysteria2 outbound.kind=hysteria2; target_stats={"tcp_bytes_down":65537,"tcp_bytes_up":65537,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} … |
| Default/TcpThroughput | FAIL | ProductSocks5 | ProductPath | PIV-hysteria2-default-tcp-throughput-20261025T111159Z-001 | E_TIMEOUT_HANG | median=0B/s samples=0 | evidence/hysteria2/default/tcp-throughput/PIV-hysteria2-default-tcp-throughput-20261025T111159Z-001/probe.json |  |
| Default/LongLived | PASS | ProductSocks5 | ProductPath | PIV-hysteria2-default-long-lived-20261025T111322Z-001 | NONE | heartbeats=12 | evidence/hysteria2/default/long-lived/PIV-hysteria2-default-long-lived-20261025T111322Z-001/probe.json | proxy_json routing.outbound_kind=hysteria2 outbound.kind=hysteria2; target_stats={"tcp_bytes_down":13,"tcp_bytes_up":13,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} … |
| Default/Reconnect | PASS | ProductSocks5 | ProductPath | PIV-hysteria2-default-reconnect-20261025T111514Z-001 | NONE | reconnects=3 | evidence/hysteria2/default/reconnect/PIV-hysteria2-default-reconnect-20261025T111514Z-001/probe.json | proxy_json routing.outbound_kind=hysteria2 outbound.kind=hysteria2; target_stats={"tcp_bytes_down":4,"tcp_bytes_up":4,"tcp_connections":4,"udp_bytes":0,"udp_datagrams":0} … |
| Default/Handshake | PASS | ProductSocks5 | ProductPath | PIV-hysteria2-default-handshake-20261025T111155Z-001 | NONE | up=1B down=1B | evidence/hysteria2/default/handshake/PIV-hysteria2-default-handshake-20261025T111155Z-001/probe.json | proxy_json routing.outbound_kind=hysteria2 outbound.kind=hysteria2; target_stats={"tcp_bytes_down":2,"tcp_bytes_up":2,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} … |
| Hy2Salamander/Handshake | FAIL | ProductSocks5 | ProductPath | PIV-hysteria2-hy2-salamander-handshake-20261024T173056Z-001 | E_NEXUS_CODEC | up=0B down=0B | evidence/hysteria2/hy2-salamander/handshake/PIV-hysteria2-hy2-salamander-handshake-20261024T173056Z-001/probe.json | proxy_error=ConnectivityEstablishmentFailed { provider: ProviderId("ref"), reason: "hysteria2 connect/auth 127.0.0.1:26104 failed: hysteria2 invalid frame" } … |
| Default/QpackDiag | PASS | CrateDirect | ProtocolWire | PIV-hysteria2-default-qpack-diag-20261025T111153Z-001 | NONE | up=0B down=0B | evidence/hysteria2/default/qpack-diag/PIV-hysteria2-default-qpack-diag-20261025T111153Z-001/probe.json | qpack_diag_not_triggered=handshake_ok; hy2_error=null; hy2_auth_status=233; hy2_auth_status_source=connect_ok_after_decode_auth_response; hy2_udp_enabled=true; hy2_cc_rx=auto …; 诊断格，不参与 verdict |
| Default/UdpEcho | PASS | CrateDirect | ProtocolWire | PIV-hysteria2-default-udp-echo-20261025T111520Z-001 | NONE | udp 1000/1000 corrupt=0 | evidence/hysteria2/default/udp-echo/PIV-hysteria2-default-udp-echo-20261025T111520Z-001/probe.json | udp_seq_and_hash_ok; target_stats={"tcp_bytes_down":0,"tcp_bytes_up":0,"tcp_connections":0,"udp_bytes":512064,"udp_datagrams":1001} … |
| Default/BadCredential | PASS | ProductSocks5 | ProductPath | PIV-hysteria2-default-bad-credential-20261025T111524Z-001 | E_EXPECTED_AUTH_REJECT | up=0B down=0B | evidence/hysteria2/default/bad-credential/PIV-hysteria2-default-bad-credential-20261025T111524Z-001/probe.json | proxy_error=ConnectivityEstablishmentFailed { provider: ProviderId("ref"), reason: "hysteria2 connect/auth 127.0.0.1:26103 failed: hysteria2 authentication failed" } …; 限定：正向路径被 CODEC 阻断时本格 PASS 仅证明无静默成功，不独立证明配置拒绝语义 |
| Default/BadConfig | PASS | ProductSocks5 | ProductPath | PIV-hysteria2-default-bad-config-20261025T111526Z-001 | E_EXPECTED_CONFIG_REJECT | up=0B down=0B | evidence/hysteria2/default/bad-config/PIV-hysteria2-default-bad-config-20261025T111526Z-001/probe.json | proxy_error=ConnectivityEstablishmentFailed { provider: ProviderId("ref"), reason: "hysteria2 connect/auth 127.0.0.1:26104 failed: hysteria2 timed out" }; workload_error=read: Connection reset by peer (os error 104) …; 限定：正向路径被 CODEC 阻断时本格 PASS 仅证明无静默成功，不独立证明配置拒绝语义 |

## Trojan

> **verdict=BROKEN / claim=NOT_USABLE**（scope=TCP_ONLY，root_cause_class=E_NEXUS_FRAMING）
>
> 本节任一 PASS 不改变协议 verdict；单格 PASS 只在所列 carrier/scope 下成立。

| Cell | 状态 | carrier | scope | evidence_id | class | 关键数字 | 证据路径 | notes |
|---|---|---|---|---|---|---|---|---|
| Default/Handshake | PASS | ProductSocks5 | ProductPath | PIV-trojan-default-handshake-20261024T173155Z-001 | NONE | up=1B down=1B | evidence/trojan/default/handshake/PIV-trojan-default-handshake-20261024T173155Z-001/probe.json | proxy_json routing.outbound_kind=trojan outbound.kind=trojan; target_stats={"tcp_bytes_down":2,"tcp_bytes_up":2,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} … |
| Default/TcpSmall | PASS | ProductSocks5 | ProductPath | PIV-trojan-default-tcp-small-20261024T213725Z-001 | NONE | up=65536B down=65536B | evidence/trojan/default/tcp-small/PIV-trojan-default-tcp-small-20261024T213725Z-001/probe.json | proxy_json routing.outbound_kind=trojan outbound.kind=trojan; target_stats={"tcp_bytes_down":65537,"tcp_bytes_up":65537,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} … |
| Default/TcpThroughput | PASS | ProductSocks5 | ProductPath | PIV-trojan-default-tcp-throughput-20261024T213728Z-001 | NONE | median=1383539707B/s samples=3 | evidence/trojan/default/tcp-throughput/PIV-trojan-default-tcp-throughput-20261024T213728Z-001/probe.json | proxy_json routing.outbound_kind=trojan outbound.kind=trojan; target_stats={"tcp_bytes_down":101716128,"tcp_bytes_up":101712896,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} … |
| Default/LongLived | PASS | ProductSocks5 | ProductPath | PIV-trojan-default-long-lived-20261024T213734Z-001 | NONE | heartbeats=12 | evidence/trojan/default/long-lived/PIV-trojan-default-long-lived-20261024T213734Z-001/probe.json | proxy_json routing.outbound_kind=trojan outbound.kind=trojan; target_stats={"tcp_bytes_down":13,"tcp_bytes_up":13,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} … |
| Default/Reconnect | PASS | ProductSocks5 | ProductPath | PIV-trojan-default-reconnect-20261024T213927Z-001 | NONE | reconnects=3 | evidence/trojan/default/reconnect/PIV-trojan-default-reconnect-20261024T213927Z-001/probe.json | proxy_json routing.outbound_kind=trojan outbound.kind=trojan; target_stats={"tcp_bytes_down":4,"tcp_bytes_up":4,"tcp_connections":4,"udp_bytes":0,"udp_datagrams":0} … |
| Default/UdpEcho | NOT_IMPLEMENTED | CrateDirect | ProtocolWire | PIV-trojan-default-udp-echo-20261024T174223Z-001 | E_NEXUS_NOT_IMPLEMENTED | udp 0/0 corrupt=0 | evidence/trojan/default/udp-echo/PIV-trojan-default-udp-echo-20261024T174223Z-001/probe.json | Trojan UDP 路径未实现（产品入口 + 出站均无） |
| Default/BadCredential | PASS | ProductSocks5 | ProductPath | PIV-trojan-default-bad-credential-20261024T191756Z-001 | E_EXPECTED_AUTH_REJECT | up=0B down=0B | evidence/trojan/default/bad-credential/PIV-trojan-default-bad-credential-20261024T191756Z-001/probe.json | proxy_json routing.outbound_kind=trojan outbound.kind=trojan; workload_error=read: Resource temporarily unavailable (os error 11); classification=E_EXPECTED_AUTH_REJECT … |
| TrojanFallback/BadCredential | FAIL | ProductSocks5 | ProductPath | PIV-trojan-trojan-fallback-bad-credential-20261024T191808Z-001 | E_NEXUS_FRAMING | up=0B down=0B | evidence/trojan/trojan-fallback/bad-credential/PIV-trojan-trojan-fallback-bad-credential-20261024T191808Z-001/probe.json | proxy_json routing.outbound_kind=trojan outbound.kind=trojan; negative case returned non-echo bytes; silently surfaced as tunnel payload; fallback response was relayed as tunnel data … |
| Default/BadConfig | NOT_APPLICABLE | CrateDirect | ProtocolWire | PIV-trojan-default-bad-config-20261024T173215Z-001 | NONE | up=0B down=0B | evidence/trojan/default/bad-config/PIV-trojan-default-bad-config-20261024T173215Z-001/probe.json | Trojan BadConfig 在 Nexus 出站配置面不可表达 |

## Shadowsocks

> **verdict=BROKEN / claim=NOT_USABLE**（scope=TCP_ONLY，root_cause_class=E_NEXUS_HANDSHAKE_WIRE）
>
> 本节任一 PASS 不改变协议 verdict；单格 PASS 只在所列 carrier/scope 下成立。

| Cell | 状态 | carrier | scope | evidence_id | class | 关键数字 | 证据路径 | notes |
|---|---|---|---|---|---|---|---|---|
| Default/Handshake | FAIL | ProductSocks5 | ProductPath | PIV-shadowsocks-default-handshake-20261024T173553Z-001 | E_NEXUS_HANDSHAKE_WIRE | up=0B down=0B | evidence/shadowsocks/default/handshake/PIV-shadowsocks-default-handshake-20261024T173553Z-001/probe.json | proxy_json routing.outbound_kind=shadowsocks outbound.kind=shadowsocks; workload_error=tunnel read: Resource temporarily unavailable (os error 11) … |
| Default/TcpSmall | FAIL | ProductSocks5 | ProductPath | PIV-shadowsocks-default-tcp-small-20261024T213934Z-001 | E_NEXUS_FRAMING | up=0B down=0B | evidence/shadowsocks/default/tcp-small/PIV-shadowsocks-default-tcp-small-20261024T213934Z-001/probe.json | proxy_json routing.outbound_kind=shadowsocks outbound.kind=shadowsocks; workload_error=tunnel read: Connection reset by peer (os error 104) … |
| Default/TcpThroughput | FAIL | ProductSocks5 | ProductPath | PIV-shadowsocks-default-tcp-throughput-20261024T213938Z-001 | E_NEXUS_FRAMING | median=0B/s samples=0 | evidence/shadowsocks/default/tcp-throughput/PIV-shadowsocks-default-tcp-throughput-20261024T213938Z-001/probe.json | proxy_json routing.outbound_kind=shadowsocks outbound.kind=shadowsocks; workload_error=sink digest read: Connection reset by peer (os error 104) … |
| Default/LongLived | FAIL | ProductSocks5 | ProductPath | PIV-shadowsocks-default-long-lived-20261024T213941Z-001 | E_NEXUS_FRAMING | heartbeats=0 | evidence/shadowsocks/default/long-lived/PIV-shadowsocks-default-long-lived-20261024T213941Z-001/probe.json | proxy_json routing.outbound_kind=shadowsocks outbound.kind=shadowsocks; workload_error=heartbeat 0: tunnel read: Resource temporarily unavailable (os error 11) … |
| Default/Reconnect | FAIL | ProductSocks5 | ProductPath | PIV-shadowsocks-default-reconnect-20261024T214145Z-001 | E_NEXUS_FRAMING | reconnects=0 | evidence/shadowsocks/default/reconnect/PIV-shadowsocks-default-reconnect-20261024T214145Z-001/probe.json | proxy_json routing.outbound_kind=shadowsocks outbound.kind=shadowsocks; workload_error=cycle 0: tunnel read: Resource temporarily unavailable (os error 11) … |
| Default/UdpEcho | NOT_IMPLEMENTED | CrateDirect | ProtocolWire | PIV-shadowsocks-default-udp-echo-20261024T174224Z-001 | E_NEXUS_NOT_IMPLEMENTED | udp 0/0 corrupt=0 | evidence/shadowsocks/default/udp-echo/PIV-shadowsocks-default-udp-echo-20261024T174224Z-001/probe.json | Shadowsocks UDP 路径未实现（产品入口 + 出站均无） |
| Default/BadCredential | PASS | ProductSocks5 | ProductPath | PIV-shadowsocks-default-bad-credential-20261024T191810Z-001 | E_EXPECTED_AUTH_REJECT | up=0B down=0B | evidence/shadowsocks/default/bad-credential/PIV-shadowsocks-default-bad-credential-20261024T191810Z-001/probe.json | proxy_json routing.outbound_kind=shadowsocks outbound.kind=shadowsocks; workload_error=read: Resource temporarily unavailable (os error 11); classification=E_EXPECTED_AUTH_REJECT …; 限定：正向路径不通时本格仅证明无静默成功，不独立证明认证拒绝语义 |
| Default/BadConfig | PASS | ProductSocks5 | ProductPath | PIV-shadowsocks-default-bad-config-20261024T191823Z-001 | E_EXPECTED_CONFIG_REJECT | up=0B down=0B | evidence/shadowsocks/default/bad-config/PIV-shadowsocks-default-bad-config-20261024T191823Z-001/probe.json | proxy_json routing.outbound_kind=shadowsocks outbound.kind=shadowsocks; workload_error=read: Resource temporarily unavailable (os error 11); classification=E_EXPECTED_CONFIG_REJECT …; 限定：正向路径不通时本格仅证明无静默成功，不独立证明认证拒绝语义 |

## 产品级 UDP（不参与协议 verdict）

产品 SOCKS5 入口 `crates/nexus-ingress/src/lib.rs:232-241` 拒绝 BND/UDP ASSOCIATE；Trojan/SS 出站也没有 UDP 帧路径。因此产品级 UDP 按能力缺口记录，不进入五协议 verdict；crate 级 UDP 结论见各协议 `UdpEcho` 行。

**区分**：本项指产品 SOCKS5 UDP relay 入口/出站帧路径缺失，不等于所有 UDP/QUIC 路径不可用——Hy2 出站到代理服务器仍走 QUIC/UDP 传输，其失败点是认证响应编解码（`E_NEXUS_CODEC`），不是 UDP 传输本身。

## 产品能力缺口

- 产品级 UDP：未实现（上节）。
- Vision：产品路径只编码 addon，不实现 splice；本 run 的 Vision 结论来自 crate 直调。
- Hysteria2：端口跳跃/Brutal/gecko/分片不在范围。
- AnyTLS：session 池/心跳定时器/padding 写路径不单独验。
- Trojan fallback fail-open（安全语义）：错凭据/被劫持/服务端 fallback 时，SOCKS5 仍回 success，fallback 的 HTTP 内容被当隧道数据。
- 代理失败可观察性：上述场景下产品不显示实际行为，不满足白皮书 §6.2/§16.1。

## fix 支线与复验

本 run 产生 verdict 翻转的修复条目（来源：run-meta）：

- **RFC 7541 Huffman 解码 + 两接入点**（commit `da86d3a`）：认证响应 HEADERS 的 Huffman 名字/值可解码，Hy2 Default 认证不再 InvalidFrame；协议级三元组仍 BROKEN（T2 与 Salamander 格未过）（prediction-check；evidence/env/hy2-auth-headers.md）

根因文档位于仓库 `docs/protocols/interop/fix/`；本 run 证据根为 `/work/interop-run/protocol-interop-fixes-3`，上表 cell 证据路径均相对该目录。

## 附录 A：配置索引

| 文件 | sha256 |
|---|---|
| evidence/ref-config/anytls-custom-padding.json | 3699b9d48f4e8e8c94bd9e79c08550727f43b67cc8824e09c5e326d596b3ba6b |
| evidence/ref-config/anytls.json | 33bef598995522c4c706634454aad9d45cec3ad0684424e997802d3d4078847d |
| evidence/ref-config/hysteria2-plain.json | ca771fa1ce5175147379caa20866e1a2aa5a805b072dcfccbef651af61f4f623 |
| evidence/ref-config/hysteria2-salamander.json | b989656c719515f0a6025eb42cf5fc4caa9737395c0f034c31cf62f716cac9bb |
| evidence/ref-config/shadowsocks-aes256gcm.json | 64cf70a4e1572dc8cad6fa89e6994b7b4b104c64208ee28c3d5c396e3630a181 |
| evidence/ref-config/shadowsocks.json | 32696b19db71af481f15ac8be5301955621998d3664cd3af4a35f3f4c582b82d |
| evidence/ref-config/trojan-fallback.json | e8070abc016e858f688f6ea3da2f0f09c790a2f12ff7bfddeca07620f97d27f6 |
| evidence/ref-config/trojan.json | 363e493c976254a23c4a49685b1b439b618f4c8661d1d68a91853bd03037e5b9 |
| evidence/ref-config/vless-basic-flow-mismatch.json | b6abb7bb5308b0e38e7bb0c96174e79ff5093cf211c72d58ee2923235dbf2bfa |
| evidence/ref-config/vless-basic.json | 7fe4a7d0eb9ddacbbb34babe6eb2de43e5e698171ba0d6632ed99c951ace21fb |
| evidence/ref-config/vless-vision.json | a637aa292aa6536c754b20edeaab4f4d31b6634fcc1246c0a96ee8f529af5635 |
| evidence/ref-config/xray-vless-basic.json | 0e85c1a8d67fa41aa96978b70c53655986f5b5ee31faed76c933c2cc9be3ccca |
| evidence/ref-config/xray-vless-vision.json | df9c2ceb8a12d94bf8a832547e9674994fa02d6304e6b88fabef490849e860a9 |

## 附录 B：证据清单

| evidence_id | verdict | carrier | scope | 路径 |
|---|---|---|---|---|
| PIV-anytls-anytls-custom-padding-bad-config-20261024T213605Z-001 | PASS | ProductSocks5 | ProductPath | evidence/anytls/anytls-custom-padding/bad-config/PIV-anytls-anytls-custom-padding-bad-config-20261024T213605Z-001/probe.json |
| PIV-anytls-default-bad-credential-20261024T213558Z-001 | PASS | ProductSocks5 | ProductPath | evidence/anytls/default/bad-credential/PIV-anytls-default-bad-credential-20261024T213558Z-001/probe.json |
| PIV-anytls-default-handshake-20261024T213337Z-001 | PASS | ProductSocks5 | ProductPath | evidence/anytls/default/handshake/PIV-anytls-default-handshake-20261024T213337Z-001/probe.json |
| PIV-anytls-default-long-lived-20261024T213353Z-001 | PASS | ProductSocks5 | ProductPath | evidence/anytls/default/long-lived/PIV-anytls-default-long-lived-20261024T213353Z-001/probe.json |
| PIV-anytls-default-padding-diag-20261024T213601Z-001 | PASS | ProductSocks5 | ProductPath | evidence/anytls/default/padding-diag/PIV-anytls-default-padding-diag-20261024T213601Z-001/probe.json |
| PIV-anytls-default-reconnect-20261024T213546Z-001 | PASS | ProductSocks5 | ProductPath | evidence/anytls/default/reconnect/PIV-anytls-default-reconnect-20261024T213546Z-001/probe.json |
| PIV-anytls-default-tcp-small-20261024T213340Z-001 | PASS | ProductSocks5 | ProductPath | evidence/anytls/default/tcp-small/PIV-anytls-default-tcp-small-20261024T213340Z-001/probe.json |
| PIV-anytls-default-tcp-throughput-20261024T213344Z-001 | PASS | ProductSocks5 | ProductPath | evidence/anytls/default/tcp-throughput/PIV-anytls-default-tcp-throughput-20261024T213344Z-001/probe.json |
| PIV-anytls-default-udp-echo-20261024T213554Z-001 | PASS | CrateDirect | ProtocolWire | evidence/anytls/default/udp-echo/PIV-anytls-default-udp-echo-20261024T213554Z-001/probe.json |
| PIV-hysteria2-default-bad-config-20261025T111526Z-001 | PASS | ProductSocks5 | ProductPath | evidence/hysteria2/default/bad-config/PIV-hysteria2-default-bad-config-20261025T111526Z-001/probe.json |
| PIV-hysteria2-default-bad-credential-20261025T111524Z-001 | PASS | ProductSocks5 | ProductPath | evidence/hysteria2/default/bad-credential/PIV-hysteria2-default-bad-credential-20261025T111524Z-001/probe.json |
| PIV-hysteria2-default-handshake-20261025T111155Z-001 | PASS | ProductSocks5 | ProductPath | evidence/hysteria2/default/handshake/PIV-hysteria2-default-handshake-20261025T111155Z-001/probe.json |
| PIV-hysteria2-default-long-lived-20261025T111322Z-001 | PASS | ProductSocks5 | ProductPath | evidence/hysteria2/default/long-lived/PIV-hysteria2-default-long-lived-20261025T111322Z-001/probe.json |
| PIV-hysteria2-default-qpack-diag-20261025T111153Z-001 | PASS | CrateDirect | ProtocolWire | evidence/hysteria2/default/qpack-diag/PIV-hysteria2-default-qpack-diag-20261025T111153Z-001/probe.json |
| PIV-hysteria2-default-reconnect-20261025T111514Z-001 | PASS | ProductSocks5 | ProductPath | evidence/hysteria2/default/reconnect/PIV-hysteria2-default-reconnect-20261025T111514Z-001/probe.json |
| PIV-hysteria2-default-tcp-small-20261025T111158Z-001 | PASS | ProductSocks5 | ProductPath | evidence/hysteria2/default/tcp-small/PIV-hysteria2-default-tcp-small-20261025T111158Z-001/probe.json |
| PIV-hysteria2-default-tcp-throughput-20261025T111159Z-001 | FAIL | ProductSocks5 | ProductPath | evidence/hysteria2/default/tcp-throughput/PIV-hysteria2-default-tcp-throughput-20261025T111159Z-001/probe.json |
| PIV-hysteria2-default-udp-echo-20261025T111520Z-001 | PASS | CrateDirect | ProtocolWire | evidence/hysteria2/default/udp-echo/PIV-hysteria2-default-udp-echo-20261025T111520Z-001/probe.json |
| PIV-hysteria2-hy2-salamander-handshake-20261024T173056Z-001 | FAIL | ProductSocks5 | ProductPath | evidence/hysteria2/hy2-salamander/handshake/PIV-hysteria2-hy2-salamander-handshake-20261024T173056Z-001/probe.json |
| PIV-shadowsocks-default-bad-config-20261024T191823Z-001 | PASS | ProductSocks5 | ProductPath | evidence/shadowsocks/default/bad-config/PIV-shadowsocks-default-bad-config-20261024T191823Z-001/probe.json |
| PIV-shadowsocks-default-bad-credential-20261024T191810Z-001 | PASS | ProductSocks5 | ProductPath | evidence/shadowsocks/default/bad-credential/PIV-shadowsocks-default-bad-credential-20261024T191810Z-001/probe.json |
| PIV-shadowsocks-default-handshake-20261024T173553Z-001 | FAIL | ProductSocks5 | ProductPath | evidence/shadowsocks/default/handshake/PIV-shadowsocks-default-handshake-20261024T173553Z-001/probe.json |
| PIV-shadowsocks-default-long-lived-20261024T213941Z-001 | FAIL | ProductSocks5 | ProductPath | evidence/shadowsocks/default/long-lived/PIV-shadowsocks-default-long-lived-20261024T213941Z-001/probe.json |
| PIV-shadowsocks-default-reconnect-20261024T214145Z-001 | FAIL | ProductSocks5 | ProductPath | evidence/shadowsocks/default/reconnect/PIV-shadowsocks-default-reconnect-20261024T214145Z-001/probe.json |
| PIV-shadowsocks-default-tcp-small-20261024T213934Z-001 | FAIL | ProductSocks5 | ProductPath | evidence/shadowsocks/default/tcp-small/PIV-shadowsocks-default-tcp-small-20261024T213934Z-001/probe.json |
| PIV-shadowsocks-default-tcp-throughput-20261024T213938Z-001 | FAIL | ProductSocks5 | ProductPath | evidence/shadowsocks/default/tcp-throughput/PIV-shadowsocks-default-tcp-throughput-20261024T213938Z-001/probe.json |
| PIV-shadowsocks-default-udp-echo-20261024T174224Z-001 | NOT_IMPLEMENTED | CrateDirect | ProtocolWire | evidence/shadowsocks/default/udp-echo/PIV-shadowsocks-default-udp-echo-20261024T174224Z-001/probe.json |
| PIV-trojan-default-bad-config-20261024T173215Z-001 | NOT_APPLICABLE | CrateDirect | ProtocolWire | evidence/trojan/default/bad-config/PIV-trojan-default-bad-config-20261024T173215Z-001/probe.json |
| PIV-trojan-default-bad-credential-20261024T191756Z-001 | PASS | ProductSocks5 | ProductPath | evidence/trojan/default/bad-credential/PIV-trojan-default-bad-credential-20261024T191756Z-001/probe.json |
| PIV-trojan-default-handshake-20261024T173155Z-001 | PASS | ProductSocks5 | ProductPath | evidence/trojan/default/handshake/PIV-trojan-default-handshake-20261024T173155Z-001/probe.json |
| PIV-trojan-default-long-lived-20261024T213734Z-001 | PASS | ProductSocks5 | ProductPath | evidence/trojan/default/long-lived/PIV-trojan-default-long-lived-20261024T213734Z-001/probe.json |
| PIV-trojan-default-reconnect-20261024T213927Z-001 | PASS | ProductSocks5 | ProductPath | evidence/trojan/default/reconnect/PIV-trojan-default-reconnect-20261024T213927Z-001/probe.json |
| PIV-trojan-default-tcp-small-20261024T213725Z-001 | PASS | ProductSocks5 | ProductPath | evidence/trojan/default/tcp-small/PIV-trojan-default-tcp-small-20261024T213725Z-001/probe.json |
| PIV-trojan-default-tcp-throughput-20261024T213728Z-001 | PASS | ProductSocks5 | ProductPath | evidence/trojan/default/tcp-throughput/PIV-trojan-default-tcp-throughput-20261024T213728Z-001/probe.json |
| PIV-trojan-default-udp-echo-20261024T174223Z-001 | NOT_IMPLEMENTED | CrateDirect | ProtocolWire | evidence/trojan/default/udp-echo/PIV-trojan-default-udp-echo-20261024T174223Z-001/probe.json |
| PIV-trojan-trojan-fallback-bad-credential-20261024T191808Z-001 | FAIL | ProductSocks5 | ProductPath | evidence/trojan/trojan-fallback/bad-credential/PIV-trojan-trojan-fallback-bad-credential-20261024T191808Z-001/probe.json |
| PIV-vless-default-bad-config-20261024T215041Z-001 | PASS | ProductSocks5 | ProductPath | evidence/vless/default/bad-config/PIV-vless-default-bad-config-20261024T215041Z-001/probe.json |
| PIV-vless-default-bad-credential-20261024T215038Z-001 | PASS | ProductSocks5 | ProductPath | evidence/vless/default/bad-credential/PIV-vless-default-bad-credential-20261024T215038Z-001/probe.json |
| PIV-vless-default-handshake-20261024T214820Z-001 | PASS | ProductSocks5 | ProductPath | evidence/vless/default/handshake/PIV-vless-default-handshake-20261024T214820Z-001/probe.json |
| PIV-vless-default-long-lived-20261024T214832Z-001 | PASS | ProductSocks5 | ProductPath | evidence/vless/default/long-lived/PIV-vless-default-long-lived-20261024T214832Z-001/probe.json |
| PIV-vless-default-reconnect-20261024T215026Z-001 | PASS | ProductSocks5 | ProductPath | evidence/vless/default/reconnect/PIV-vless-default-reconnect-20261024T215026Z-001/probe.json |
| PIV-vless-default-tcp-small-20261024T214824Z-001 | PASS | ProductSocks5 | ProductPath | evidence/vless/default/tcp-small/PIV-vless-default-tcp-small-20261024T214824Z-001/probe.json |
| PIV-vless-default-tcp-throughput-20261024T214827Z-001 | PASS | ProductSocks5 | ProductPath | evidence/vless/default/tcp-throughput/PIV-vless-default-tcp-throughput-20261024T214827Z-001/probe.json |
| PIV-vless-default-udp-echo-20261024T215033Z-001 | PASS | CrateDirect | ProtocolWire | evidence/vless/default/udp-echo/PIV-vless-default-udp-echo-20261024T215033Z-001/probe.json |
| PIV-vless-vless-vision-handshake-20261024T215044Z-001 | PASS | CrateDirect | ProtocolWire | evidence/vless/vless-vision/handshake/PIV-vless-vless-vision-handshake-20261024T215044Z-001/probe.json |
| PIV-vless-vless-vision-tcp-small-20261024T215048Z-001 | PASS | CrateDirect | ProtocolWire | evidence/vless/vless-vision/tcp-small/PIV-vless-vless-vision-tcp-small-20261024T215048Z-001/probe.json |

## 附录 C：命令与端口

```bash
scripts/interop/run-matrix.sh --protocol <p> --variant <v> --cell <c> \
  --run-dir /work/interop-run/protocol-interop-fixes-3 \
  --probe-bin $CARGO_TARGET_DIR/debug/examples/protocol_interop_probe \
  --ref-bin $RUN_DIR/ref/sing-box-1.13.16-linux-amd64-musl/sing-box
python3 scripts/interop/recompute-verdicts.py --run-dir /work/interop-run/protocol-interop-fixes-3 \
  --run-meta /work/interop-run/protocol-interop-fixes-3/analysis/run-meta.json \
  --matrix docs/protocols/interop/MATRIX.md --check
```

- 参照端口：vless 26100/26101、anytls 26102、hysteria2 26103/26104、
  trojan 26105/26115、shadowsocks 26106、xray 26108/26109。
- 目标端口：26200 echo / 26201 sink+source / 26202 udp / 26203 http fallback。
- 抓包：dumpcap -P（pcap），T2 用 `-a filesize:102400` 封顶 100 MiB。

## 附录 D：终局 T2 证据构建来源

| 协议 | evidence_id | nexus.commit | cargo_target_dir | binary_sha256 |
|---|---|---|---|---|
| Vless | PIV-vless-default-tcp-throughput-20261024T214827Z-001 | 43ca7ac42b6b67d26498d7aeeeecc28199a02e13 | /work/wt-protocol-interop-fixes-1/target | 7cbff04742d322f0866d1375fca23a89f001e2f22fcdd1bac5a24f4376279e96 |
| Anytls | PIV-anytls-default-tcp-throughput-20261024T213344Z-001 | 60e6029e4977c47bf624cbc62f107ea02fe16da3 | /work/wt-protocol-interop-fixes-1/target | b6c5a37ad1c64edd50a304d32ad76514c2b705f8185f0f883bcf4d2dbaa29c01 |
| Hysteria2 | PIV-hysteria2-default-tcp-throughput-20261025T111159Z-001 | f692f2d3123bc0e367b0af91eb64871365391e23 | /work/wt-protocol-interop-fixes-3/target | MISSING |
| Trojan | PIV-trojan-default-tcp-throughput-20261024T213728Z-001 | 60e6029e4977c47bf624cbc62f107ea02fe16da3 | /work/wt-protocol-interop-fixes-1/target | b6c5a37ad1c64edd50a304d32ad76514c2b705f8185f0f883bcf4d2dbaa29c01 |
| Shadowsocks | PIV-shadowsocks-default-tcp-throughput-20261024T213938Z-001 | 60e6029e4977c47bf624cbc62f107ea02fe16da3 | /work/wt-protocol-interop-fixes-1/target | b6c5a37ad1c64edd50a304d32ad76514c2b705f8185f0f883bcf4d2dbaa29c01 |

上表逐格给出各 T2 证据绑定的构建提交、目标目录与二进制哈希；按证据 `nexus.commit` 派生：`43ca7ac42b6b67d26498d7aeeeecc28199a02e13`（Vless）；`60e6029e4977c47bf624cbc62f107ea02fe16da3`（Anytls、Trojan、Shadowsocks）；`f692f2d3123bc0e367b0af91eb64871365391e23`（Hysteria2）。
构建均来自证据记录的本 worktree `cargo_target_dir`，不再引用前序 run 的 fix worktree。

## 附录 E：被替代运行

| evidence_id | 原结论 | 替代者 | 弃用理由 |
|---|---|---|---|
| PIV-anytls-default-tcp-throughput-20261024T173000Z-001 | PASS | PIV-anytls-default-tcp-throughput-20261024T175443Z-001 | 0981421（T2 证据鲁棒性修复）后重跑否决：早期 PASS 系 EOF/超时被当作成功；修复后 174434Z/175443Z 稳定 FAIL（E_NEXUS_TRANSPORT，WouldBlock 传输缺陷） |
| PIV-trojan-default-tcp-throughput-20261024T173200Z-001 | PASS | PIV-trojan-default-tcp-throughput-20261024T175446Z-001 | 0981421（T2 证据鲁棒性修复）后重跑否决：早期 PASS 系 EOF/超时被当作成功；修复后 174437Z/175446Z 稳定 FAIL（E_NEXUS_TRANSPORT，WouldBlock 传输缺陷） |
| PIV-hysteria2-default-bad-credential-20261024T173046Z-001 | PASS | PIV-hysteria2-default-bad-credential-20261024T191742Z-001 | 85a6bb8（负向诚实性修复）后重跑否决：早期把客户端解码失败当参照端拒绝；修复后 probe=Blocked + E_NEXUS_CODEC，按 D1 映射 FAIL（R-01 判卷机修复后再次重跑结论一致） |

复算的选择规则是同格取最新 evidence_id；被替代运行仍保留在证据树与 `analysis/progress.tsv`，不覆盖历史结论。
