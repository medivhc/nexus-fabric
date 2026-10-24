# 出站协议互操作证据总表（MATRIX）

> 本文件由 `scripts/interop/recompute-verdicts.py` 从证据机械生成；人工零编辑。
> 修复顺序、依赖与复验口径见人工维护的 [NEXT-STEPS.md](NEXT-STEPS.md)。

- run `protocol-interop-verification`；baseline `0539169e8195944fcd183e7831e5d5ac746f3f40`；spec frozen v1.1（sha256 `23c7e4e797ee9edbf0eb645bfc20a7c97cfacb30e1a67bd8fee77ccbc527de4f`）；test window `2026-10-24T17:22:49Z .. 2026-10-24T19:18:23Z`。
- 参照实现：sing-box 1.13.16（sha256 `9ff0345fde4157a6bdab45a615668d41ccc93f6d0f361108042a48b8a49a9baa`）；Xray 26.10.21（sha256 `0eec3ed4163c273d8c8bf821f7d219e257921cf584aa3fb970715e458e631978`）。
- archive（主机归档路径）：`/work/interop-run/protocol-interop-verification/archive/protocol-interop-verification-20261024T184740Z.tar.zst`, `/work/interop-run/protocol-interop-verification/archive/protocol-interop-verification-20261024T185026Z.tar.zst`。

## 先读：范围 / 结论 / 图例

- **覆盖**：5 个出站代理协议（VLESS、AnyTLS、Hysteria2、Trojan、Shadowsocks）共 46 个证据格。TCP 成功型格走产品 SOCKS5 出口路径；`UdpEcho` 与 VLESS Vision 部分格为 crate 直调（`CrateDirect`），不代表产品入口可用。
- **不覆盖**：VMess（本轮暂缓）、direct/relay/socks5 出站、TUN/VPN、Android 统一 VPN 入口、UI/诊断呈现。
- **本表不回答**：直连/中继回退是否可用（属 N1 整体结论）；也不把「产品级 UDP 未实现」扩大成「Hy2 的 QUIC 出站传输不可用」（见产品级 UDP 节）。
- **结论 1**：五协议全部 `BROKEN / NOT_USABLE`，当前无任何协议可宣称可用。
- **结论 2**：阻断分属产品装配、跨协议传输、协议编解码、协议线格式与产品安全语义；`root_cause_class` 只是规则代表类，不是完整根因。
- **结论 3**：AnyTLS 只差跨协议 T2；VLESS 是产品装配 bug；SS 是协议重写；Hy2 是 QPACK 编解码；Trojan 是安全语义 + 共性 T2。
- **结论 4**：即使修复完成，Trojan/SS 因本 run `UdpEcho` 固定 `NOT_IMPLEMENTED`，上限仍为 `PARTIAL / TCP_ONLY / USABLE_WITH_GAPS`（spec E1 规则 6/R11）。
- **结论 5**：五协议当前均可在产品配置面选择，且无「实验性/未验证」标注；是否继续暴露由产品负责人决定（本 run 不改产品代码）。
- **优先级**：① P0 安全止血（文档/配置面，0 代码）先公开并限制 Trojan fallback；② P1 transport 批量写（唯一一格修多协议，预期 AnyTLS 首先可用）；③ P2 VLESS fix 合入复验 → Hy2 QPACK Huffman → SS SIP004 AEAD → Trojan fallback 完整语义（依赖/成本/复验口径见 [NEXT-STEPS.md](NEXT-STEPS.md)）。
- **字段**：`verdict` = `VERIFIED`（规则 8，全 required PASS）/ `PARTIAL`（规则 3–7/9，非阻断缺口）/ `BROKEN`（规则 1/2，阻断性 Nexus 失败）；`scope` = `PROTOCOL_SUBSET` / `FULL` / `TCP_ONLY`；`claim` = `USABLE` / `USABLE_WITH_GAPS` / `NOT_USABLE` / `NOT_CLAIMED`；`carrier` = `ProductSocks5`（产品 SOCKS5 出口路径）/ `CrateDirect`（crate 直调，非产品入口）。
- **规则 1**：失败格（BadCredential/BadConfig）判 FAIL 且表现为有效 echo/静默成功（`E_NEXUS_FRAMING`）或挂死（`E_TIMEOUT_HANG`）→ `BROKEN`。
- **规则 2**：任一 required 格 FAIL 且 class 属 `E_NEXUS_*` / `E_TIMEOUT_HANG` → `BROKEN`。
- **错误类**：`E_NEXUS_*` = Nexus 侧失败（握手/线格式、认证编码、帧/静默成功、传输、UDP、编解码、未实现），判 FAIL；`E_TIMEOUT_HANG` = 挂死/超时，判 FAIL；`E_EXPECTED_*` = 预期认证/配置拒绝，负向格判 PASS；`E_REF_*` / `E_NETWORK_ENV` / `E_TOOL_BUG` / `E_EVIDENCE_GAP` = 参照端/环境/证据缺口，判 BLOCKED（`E_REF_LIMITATION` 判 FAIL，须带 `ref_source`/`ref_version`）。
- **Xray**：26.10.21 仅用于 VLESS Vision 争议裁决，本轮未触发；五协议结论全部来自 sing-box 1.13.16 参照。

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
| Vless | BROKEN | PROTOCOL_SUBSET | NOT_USABLE | E_NEXUS_HANDSHAKE_WIRE | Handshake(FAIL,E_NEXUS_HANDSHAKE_WIRE), TcpSmall(FAIL,E_NEXUS_FRAMING), TcpThroughput(FAIL,E_NEXUS_FRAMING), LongLived(FAIL,E_NEXUS_FRAMING), Reconnect(FAIL,E_NEXUS_FRAMING) | 2 |
| Anytls | BROKEN | PROTOCOL_SUBSET | NOT_USABLE | E_NEXUS_TRANSPORT | TcpThroughput(FAIL,E_NEXUS_TRANSPORT) | 2 |
| Hysteria2 | BROKEN | PROTOCOL_SUBSET | NOT_USABLE | E_NEXUS_CODEC | TcpSmall(FAIL,E_NEXUS_CODEC), TcpThroughput(FAIL,E_NEXUS_CODEC), LongLived(FAIL,E_NEXUS_CODEC), Reconnect(FAIL,E_NEXUS_CODEC), Handshake(FAIL,E_NEXUS_CODEC), Handshake[Hy2Salamander](FAIL,E_NEXUS_CODEC), UdpEcho(FAIL,E_NEXUS_CODEC), BadCredential(FAIL,E_NEXUS_CODEC) | 2 |
| Trojan | BROKEN | TCP_ONLY | NOT_USABLE | E_NEXUS_FRAMING | TcpThroughput(FAIL,E_NEXUS_TRANSPORT), UdpEcho(NOT_IMPLEMENTED,E_NEXUS_NOT_IMPLEMENTED), BadCredential[TrojanFallback](FAIL,E_NEXUS_FRAMING) | 1 |
| Shadowsocks | BROKEN | TCP_ONLY | NOT_USABLE | E_NEXUS_HANDSHAKE_WIRE | Handshake(FAIL,E_NEXUS_HANDSHAKE_WIRE), TcpSmall(FAIL,E_NEXUS_FRAMING), TcpThroughput(FAIL,E_NEXUS_FRAMING), LongLived(FAIL,E_NEXUS_FRAMING), Reconnect(FAIL,E_NEXUS_FRAMING), UdpEcho(NOT_IMPLEMENTED,E_NEXUS_NOT_IMPLEMENTED) | 2 |

## 阻塞层、归属与修复后上限

`root_cause_class` 是 E1 首个命中规则所取的**代表类**，不是完整根因；下表按 fix 根因文档给出直接阻塞层与归属，不改变上表 verdict。

| 协议 | 直接阻塞层 | 归属 | 剩余阻塞格（相对可用） | 单协议可解？ | 修复后本 run schema 上限 |
|---|---|---|---|---|---|
| VLESS | 产品装配（eager read）+ 跨协议 T2 | 产品装配 bug + 跨协议数据面共性缺陷 | H/T1/L/R 由 fix 解决；T2 需 transport | 否，依赖 transport | `VERIFIED / PROTOCOL_SUBSET`（Vision 仅 crate 级，产品 splice 未实现） |
| AnyTLS | 跨协议 T2 | 跨协议数据面共性缺陷 | 仅 T2 | 是（transport 一处） | `VERIFIED / FULL` |
| Hysteria2 | 认证响应 QPACK Huffman + T2 | 协议编解码实现错误 + 跨协议数据面共性缺陷 | Handshake/Handshake[Hy2Salamander]/TcpSmall/TcpThroughput/LongLived/Reconnect/UdpEcho/BadCredential 共 8 格 | 否，依赖 transport | `VERIFIED / FULL` |
| Trojan | fallback 静默接受 + T2 | 产品安全语义 + 跨协议数据面共性缺陷 | fallback + T2；U 固定未实现 | 否，依赖 transport + fallback 架构 | 本 run 最高 `PARTIAL / TCP_ONLY / USABLE_WITH_GAPS`（U 未实现，规则 6） |
| Shadowsocks | 线格式/SIP004 AEAD + T2 | 协议实现错误 + 跨协议数据面共性缺陷 | H/T1/T2/L/R；U 固定未实现 | 否，依赖 transport | 本 run 最高 `PARTIAL / TCP_ONLY / USABLE_WITH_GAPS`（U 未实现，规则 6） |

**参照端生态**：本轮未发现参照端生态缺陷——sing-box 1.13.16 的行为符合规范；Xray 26.10.21 仅用于 Vision 争议裁决，本轮未触发。五协议 verdict 均无 `E_REF_*` 根因。

## Vless

> **verdict=BROKEN / claim=NOT_USABLE**（scope=PROTOCOL_SUBSET，root_cause_class=E_NEXUS_HANDSHAKE_WIRE）
>
> 本节任一 PASS 不改变协议 verdict；单格 PASS 只在所列 carrier/scope 下成立。
> VlessVision 行为 crate 级证据，产品 Vision splice 未实现。

| Cell | 状态 | carrier | scope | evidence_id | class | 关键数字 | 证据路径 | notes |
|---|---|---|---|---|---|---|---|---|
| Default/Handshake | FAIL | ProductSocks5 | ProductPath | PIV-vless-default-handshake-20261024T172249Z-001 | E_NEXUS_HANDSHAKE_WIRE | up=0B down=0B | evidence/vless/default/handshake/PIV-vless-default-handshake-20261024T172249Z-001/probe.json | proxy_error=ConnectivityEstablishmentFailed { provider: ProviderId("ref"), reason: "vless response read failed: vless io error" }; workload_error=tunnel read: Connection reset by peer (os error 104) … |
| Default/TcpSmall | FAIL | ProductSocks5 | ProductPath | PIV-vless-default-tcp-small-20261024T172301Z-001 | E_NEXUS_FRAMING | up=0B down=0B | evidence/vless/default/tcp-small/PIV-vless-default-tcp-small-20261024T172301Z-001/probe.json | proxy_error=ConnectivityEstablishmentFailed { provider: ProviderId("ref"), reason: "vless response read failed: vless io error" }; workload_error=tunnel read: Connection reset by peer (os error 104) … |
| Default/TcpThroughput | FAIL | ProductSocks5 | ProductPath | PIV-vless-default-tcp-throughput-20261024T172313Z-001 | E_NEXUS_FRAMING | median=0B/s samples=0 | evidence/vless/default/tcp-throughput/PIV-vless-default-tcp-throughput-20261024T172313Z-001/probe.json | proxy_error=ConnectivityEstablishmentFailed { provider: ProviderId("ref"), reason: "vless response read failed: vless io error" }; workload_error=sink digest read: Connection reset by peer (os error 104) … |
| Default/LongLived | FAIL | ProductSocks5 | ProductPath | PIV-vless-default-long-lived-20261024T172328Z-001 | E_NEXUS_FRAMING | heartbeats=0 | evidence/vless/default/long-lived/PIV-vless-default-long-lived-20261024T172328Z-001/probe.json | proxy_error=ConnectivityEstablishmentFailed { provider: ProviderId("ref"), reason: "vless response read failed: vless io error" }; workload_error=heartbeat 0: tunnel read: Connection reset by peer (os error 104) … |
| Default/Reconnect | FAIL | ProductSocks5 | ProductPath | PIV-vless-default-reconnect-20261024T172339Z-001 | E_NEXUS_FRAMING | reconnects=0 | evidence/vless/default/reconnect/PIV-vless-default-reconnect-20261024T172339Z-001/probe.json | workload_error=cycle 0: tunnel read: Resource temporarily unavailable (os error 11); workload_error=cycle 0: proxy ConnectivityEstablishmentFailed { provider: ProviderId("ref") … |
| Default/UdpEcho | PASS | CrateDirect | ProtocolWire | PIV-vless-default-udp-echo-20261024T174211Z-001 | NONE | udp 1000/1000 corrupt=0 | evidence/vless/default/udp-echo/PIV-vless-default-udp-echo-20261024T174211Z-001/probe.json | udp_seq_and_hash_ok; target_stats={"tcp_bytes_down":0,"tcp_bytes_up":0,"tcp_connections":0,"udp_bytes":512064,"udp_datagrams":1001} … |
| Default/BadCredential | PASS | ProductSocks5 | ProductPath | PIV-vless-default-bad-credential-20261024T191726Z-001 | E_EXPECTED_AUTH_REJECT | up=0B down=0B | evidence/vless/default/bad-credential/PIV-vless-default-bad-credential-20261024T191726Z-001/probe.json | proxy_error=ConnectivityEstablishmentFailed { provider: ProviderId("ref"), reason: "vless response read failed: vless io error" }; workload_error=read: Connection reset by peer (os error 104) …; 限定：正向路径不通时本格仅证明无静默成功，不独立证明认证拒绝语义 |
| Default/BadConfig | PASS | ProductSocks5 | ProductPath | PIV-vless-default-bad-config-20261024T191736Z-001 | E_EXPECTED_CONFIG_REJECT | up=0B down=0B | evidence/vless/default/bad-config/PIV-vless-default-bad-config-20261024T191736Z-001/probe.json | proxy_error=ConnectivityEstablishmentFailed { provider: ProviderId("ref"), reason: "vless response read failed: vless io error" }; workload_error=read: Connection reset by peer (os error 104) …; 限定：正向路径不通时本格仅证明无静默成功，不独立证明认证拒绝语义 |
| VlessVision/Handshake | PASS | CrateDirect | ProtocolWire | PIV-vless-vless-vision-handshake-20261024T172418Z-001 | NONE | up=1B down=1B | evidence/vless/vless-vision/handshake/PIV-vless-vless-vision-handshake-20261024T172418Z-001/probe.json | vision_commands=["continue"]; target_stats={"tcp_bytes_down":2,"tcp_bytes_up":2,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} …; crate 级，产品 splice 未实现 |
| VlessVision/TcpSmall | PASS | CrateDirect | ProtocolWire | PIV-vless-vless-vision-tcp-small-20261024T172419Z-001 | NONE | up=65536B down=65536B | evidence/vless/vless-vision/tcp-small/PIV-vless-vless-vision-tcp-small-20261024T172419Z-001/probe.json | vision_commands=["continue", "continue", "end"]; target_stats={"tcp_bytes_down":65537,"tcp_bytes_up":65537,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} …; crate 级，产品 splice 未实现 |

## Anytls

> **verdict=BROKEN / claim=NOT_USABLE**（scope=PROTOCOL_SUBSET，root_cause_class=E_NEXUS_TRANSPORT）
>
> 本节任一 PASS 不改变协议 verdict；单格 PASS 只在所列 carrier/scope 下成立。
> PaddingDiag 为诊断格，不参与 verdict。

| Cell | 状态 | carrier | scope | evidence_id | class | 关键数字 | 证据路径 | notes |
|---|---|---|---|---|---|---|---|---|
| Default/Handshake | PASS | ProductSocks5 | ProductPath | PIV-anytls-default-handshake-20261024T172529Z-001 | NONE | up=1B down=1B | evidence/anytls/default/handshake/PIV-anytls-default-handshake-20261024T172529Z-001/probe.json | proxy_json routing.outbound_kind=anytls outbound.kind=anytls; target_stats={"tcp_bytes_down":2,"tcp_bytes_up":2,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} … |
| Default/TcpSmall | PASS | ProductSocks5 | ProductPath | PIV-anytls-default-tcp-small-20261024T172534Z-001 | NONE | up=65536B down=65536B | evidence/anytls/default/tcp-small/PIV-anytls-default-tcp-small-20261024T172534Z-001/probe.json | proxy_json routing.outbound_kind=anytls outbound.kind=anytls; target_stats={"tcp_bytes_down":65537,"tcp_bytes_up":65537,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} … |
| Default/TcpThroughput | FAIL | ProductSocks5 | ProductPath | PIV-anytls-default-tcp-throughput-20261024T175443Z-001 | E_NEXUS_TRANSPORT | median=0B/s samples=0 | evidence/anytls/default/tcp-throughput/PIV-anytls-default-tcp-throughput-20261024T175443Z-001/probe.json | proxy_json routing.outbound_kind=anytls outbound.kind=anytls; workload_error=source eof after 30200403 / 33554432 bytes … |
| Default/LongLived | PASS | ProductSocks5 | ProductPath | PIV-anytls-default-long-lived-20261024T172542Z-001 | NONE | heartbeats=12 | evidence/anytls/default/long-lived/PIV-anytls-default-long-lived-20261024T172542Z-001/probe.json | proxy_json routing.outbound_kind=anytls outbound.kind=anytls; target_stats={"tcp_bytes_down":13,"tcp_bytes_up":13,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} … |
| Default/Reconnect | PASS | ProductSocks5 | ProductPath | PIV-anytls-default-reconnect-20261024T172736Z-001 | NONE | reconnects=3 | evidence/anytls/default/reconnect/PIV-anytls-default-reconnect-20261024T172736Z-001/probe.json | proxy_json routing.outbound_kind=anytls outbound.kind=anytls; target_stats={"tcp_bytes_down":4,"tcp_bytes_up":4,"tcp_connections":4,"udp_bytes":0,"udp_datagrams":0} … |
| Default/PaddingDiag | PASS | ProductSocks5 | ProductPath | PIV-anytls-default-padding-diag-20261024T174336Z-001 | NONE | up=0B down=0B | evidence/anytls/default/padding-diag/PIV-anytls-default-padding-diag-20261024T174336Z-001/probe.json | proxy_json routing.outbound_kind=anytls outbound.kind=anytls; serversettings_inferred; target_stats={"tcp_bytes_down":1,"tcp_bytes_up":1,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} …; 诊断格，不参与 verdict |
| Default/UdpEcho | PASS | CrateDirect | ProtocolWire | PIV-anytls-default-udp-echo-20261024T174215Z-001 | NONE | udp 1000/1000 corrupt=0 | evidence/anytls/default/udp-echo/PIV-anytls-default-udp-echo-20261024T174215Z-001/probe.json | udp_seq_and_hash_ok; target_stats={"tcp_bytes_down":0,"tcp_bytes_up":0,"tcp_connections":0,"udp_bytes":512064,"udp_datagrams":1001} … |
| Default/BadCredential | PASS | ProductSocks5 | ProductPath | PIV-anytls-default-bad-credential-20261024T191738Z-001 | E_EXPECTED_AUTH_REJECT | up=0B down=0B | evidence/anytls/default/bad-credential/PIV-anytls-default-bad-credential-20261024T191738Z-001/probe.json | proxy_error=ConnectivityEstablishmentFailed { provider: ProviderId("ref"), reason: "anytls session handshake failed: anytls io error" }; workload_error=read: Connection reset by peer (os error 104) … |
| AnyTlsCustomPadding/BadConfig | PASS | ProductSocks5 | ProductPath | PIV-anytls-anytls-custom-padding-bad-config-20261024T191740Z-001 | E_EXPECTED_CONFIG_REJECT | up=0B down=0B | evidence/anytls/anytls-custom-padding/bad-config/PIV-anytls-anytls-custom-padding-bad-config-20261024T191740Z-001/probe.json | proxy_error=ConnectivityEstablishmentFailed { provider: ProviderId("ref"), reason: "anytls session handshake failed: anytls server requested padding scheme update" } … |

## Hysteria2

> **verdict=BROKEN / claim=NOT_USABLE**（scope=PROTOCOL_SUBSET，root_cause_class=E_NEXUS_CODEC）
>
> 本节任一 PASS 不改变协议 verdict；单格 PASS 只在所列 carrier/scope 下成立。
> QpackDiag 为诊断格，不参与 verdict。

| Cell | 状态 | carrier | scope | evidence_id | class | 关键数字 | 证据路径 | notes |
|---|---|---|---|---|---|---|---|---|
| Default/TcpSmall | FAIL | ProductSocks5 | ProductPath | PIV-hysteria2-default-tcp-small-20261024T173041Z-001 | E_NEXUS_CODEC | up=0B down=0B | evidence/hysteria2/default/tcp-small/PIV-hysteria2-default-tcp-small-20261024T173041Z-001/probe.json | proxy_error=ConnectivityEstablishmentFailed { provider: ProviderId("ref"), reason: "hysteria2 connect/auth 127.0.0.1:26103 failed: hysteria2 invalid frame" } … |
| Default/TcpThroughput | FAIL | ProductSocks5 | ProductPath | PIV-hysteria2-default-tcp-throughput-20261024T173044Z-001 | E_NEXUS_CODEC | median=0B/s samples=0 | evidence/hysteria2/default/tcp-throughput/PIV-hysteria2-default-tcp-throughput-20261024T173044Z-001/probe.json | proxy_error=ConnectivityEstablishmentFailed { provider: ProviderId("ref"), reason: "hysteria2 connect/auth 127.0.0.1:26103 failed: hysteria2 invalid frame" }; workload_error=Broken pipe (os error 32) … |
| Default/LongLived | FAIL | ProductSocks5 | ProductPath | PIV-hysteria2-default-long-lived-20261024T173048Z-001 | E_NEXUS_CODEC | heartbeats=0 | evidence/hysteria2/default/long-lived/PIV-hysteria2-default-long-lived-20261024T173048Z-001/probe.json | proxy_error=ConnectivityEstablishmentFailed { provider: ProviderId("ref"), reason: "hysteria2 connect/auth 127.0.0.1:26103 failed: hysteria2 invalid frame" } … |
| Default/Reconnect | FAIL | ProductSocks5 | ProductPath | PIV-hysteria2-default-reconnect-20261024T173050Z-001 | E_NEXUS_CODEC | reconnects=0 | evidence/hysteria2/default/reconnect/PIV-hysteria2-default-reconnect-20261024T173050Z-001/probe.json | workload_error=cycle 0: tunnel read: Connection reset by peer (os error 104); workload_error=cycle 0: proxy ConnectivityEstablishmentFailed { provider: ProviderId("ref") … |
| Default/Handshake | FAIL | ProductSocks5 | ProductPath | PIV-hysteria2-default-handshake-20261024T173039Z-001 | E_NEXUS_CODEC | up=0B down=0B | evidence/hysteria2/default/handshake/PIV-hysteria2-default-handshake-20261024T173039Z-001/probe.json | proxy_error=ConnectivityEstablishmentFailed { provider: ProviderId("ref"), reason: "hysteria2 connect/auth 127.0.0.1:26103 failed: hysteria2 invalid frame" } … |
| Hy2Salamander/Handshake | FAIL | ProductSocks5 | ProductPath | PIV-hysteria2-hy2-salamander-handshake-20261024T173056Z-001 | E_NEXUS_CODEC | up=0B down=0B | evidence/hysteria2/hy2-salamander/handshake/PIV-hysteria2-hy2-salamander-handshake-20261024T173056Z-001/probe.json | proxy_error=ConnectivityEstablishmentFailed { provider: ProviderId("ref"), reason: "hysteria2 connect/auth 127.0.0.1:26104 failed: hysteria2 invalid frame" } … |
| Default/QpackDiag | PASS | CrateDirect | ProtocolWire | PIV-hysteria2-default-qpack-diag-20261024T174317Z-001 | E_NEXUS_CODEC | up=0B down=0B | evidence/hysteria2/default/qpack-diag/PIV-hysteria2-default-qpack-diag-20261024T174317Z-001/probe.json | hy2_error=hysteria2 invalid frame; target_stats={"tcp_bytes_down":1,"tcp_bytes_up":1,"tcp_connections":1,"udp_bytes":0,"udp_datagrams":0} …; 诊断格，不参与 verdict |
| Default/UdpEcho | FAIL | CrateDirect | ProtocolWire | PIV-hysteria2-default-udp-echo-20261024T174221Z-001 | E_NEXUS_CODEC | udp 0/0 corrupt=0 | evidence/hysteria2/default/udp-echo/PIV-hysteria2-default-udp-echo-20261024T174221Z-001/probe.json | target_stats={"tcp_bytes_down":0,"tcp_bytes_up":0,"tcp_connections":0,"udp_bytes":64,"udp_datagrams":1}; pcap_stats=utc=2026-10-24T17:42:23Z;packets=12;size_bytes=7731;capinfos_ok=yes;first_packet=1;sha256=6d9429e4490493 … |
| Default/BadCredential | FAIL | ProductSocks5 | ProductPath | PIV-hysteria2-default-bad-credential-20261024T191742Z-001 | E_NEXUS_CODEC | up=0B down=0B | evidence/hysteria2/default/bad-credential/PIV-hysteria2-default-bad-credential-20261024T191742Z-001/probe.json | proxy_error=ConnectivityEstablishmentFailed { provider: ProviderId("ref"), reason: "hysteria2 connect/auth 127.0.0.1:26103 failed: hysteria2 invalid frame" } … |
| Default/BadConfig | PASS | ProductSocks5 | ProductPath | PIV-hysteria2-default-bad-config-20261024T191744Z-001 | E_EXPECTED_CONFIG_REJECT | up=0B down=0B | evidence/hysteria2/default/bad-config/PIV-hysteria2-default-bad-config-20261024T191744Z-001/probe.json | proxy_error=ConnectivityEstablishmentFailed { provider: ProviderId("ref"), reason: "hysteria2 connect/auth 127.0.0.1:26104 failed: hysteria2 timed out" }; workload_error=read: Connection reset by peer (os error 104) …; 限定：正向路径被 CODEC 阻断时本格 PASS 仅证明无静默成功，不独立证明配置拒绝语义 |

## Trojan

> **verdict=BROKEN / claim=NOT_USABLE**（scope=TCP_ONLY，root_cause_class=E_NEXUS_FRAMING）
>
> 本节任一 PASS 不改变协议 verdict；单格 PASS 只在所列 carrier/scope 下成立。

| Cell | 状态 | carrier | scope | evidence_id | class | 关键数字 | 证据路径 | notes |
|---|---|---|---|---|---|---|---|---|
| Default/Handshake | PASS | ProductSocks5 | ProductPath | PIV-trojan-default-handshake-20261024T173155Z-001 | NONE | up=1B down=1B | evidence/trojan/default/handshake/PIV-trojan-default-handshake-20261024T173155Z-001/probe.json | proxy_json routing.outbound_kind=trojan outbound.kind=trojan; target_stats={"tcp_bytes_down":2,"tcp_bytes_up":2,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} … |
| Default/TcpSmall | PASS | ProductSocks5 | ProductPath | PIV-trojan-default-tcp-small-20261024T173157Z-001 | NONE | up=65536B down=65536B | evidence/trojan/default/tcp-small/PIV-trojan-default-tcp-small-20261024T173157Z-001/probe.json | proxy_json routing.outbound_kind=trojan outbound.kind=trojan; target_stats={"tcp_bytes_down":65537,"tcp_bytes_up":65537,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} … |
| Default/TcpThroughput | FAIL | ProductSocks5 | ProductPath | PIV-trojan-default-tcp-throughput-20261024T175446Z-001 | E_NEXUS_TRANSPORT | median=0B/s samples=0 | evidence/trojan/default/tcp-throughput/PIV-trojan-default-tcp-throughput-20261024T175446Z-001/probe.json | proxy_json routing.outbound_kind=trojan outbound.kind=trojan; workload_error=source eof after 21669618 / 33554432 bytes … |
| Default/LongLived | PASS | ProductSocks5 | ProductPath | PIV-trojan-default-long-lived-20261024T173219Z-001 | NONE | heartbeats=12 | evidence/trojan/default/long-lived/PIV-trojan-default-long-lived-20261024T173219Z-001/probe.json | proxy_json routing.outbound_kind=trojan outbound.kind=trojan; target_stats={"tcp_bytes_down":13,"tcp_bytes_up":13,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} … |
| Default/Reconnect | PASS | ProductSocks5 | ProductPath | PIV-trojan-default-reconnect-20261024T173416Z-001 | NONE | reconnects=3 | evidence/trojan/default/reconnect/PIV-trojan-default-reconnect-20261024T173416Z-001/probe.json | proxy_json routing.outbound_kind=trojan outbound.kind=trojan; target_stats={"tcp_bytes_down":4,"tcp_bytes_up":4,"tcp_connections":4,"udp_bytes":0,"udp_datagrams":0} … |
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
| Default/TcpSmall | FAIL | ProductSocks5 | ProductPath | PIV-shadowsocks-default-tcp-small-20261024T173656Z-001 | E_NEXUS_FRAMING | up=0B down=0B | evidence/shadowsocks/default/tcp-small/PIV-shadowsocks-default-tcp-small-20261024T173656Z-001/probe.json | proxy_json routing.outbound_kind=shadowsocks outbound.kind=shadowsocks; workload_error=tunnel read: Connection reset by peer (os error 104) … |
| Default/TcpThroughput | FAIL | ProductSocks5 | ProductPath | PIV-shadowsocks-default-tcp-throughput-20261024T173659Z-001 | E_NEXUS_FRAMING | median=0B/s samples=0 | evidence/shadowsocks/default/tcp-throughput/PIV-shadowsocks-default-tcp-throughput-20261024T173659Z-001/probe.json | proxy_json routing.outbound_kind=shadowsocks outbound.kind=shadowsocks; workload_error=sink digest read: Connection reset by peer (os error 104) … |
| Default/LongLived | FAIL | ProductSocks5 | ProductPath | PIV-shadowsocks-default-long-lived-20261024T173726Z-001 | E_NEXUS_FRAMING | heartbeats=0 | evidence/shadowsocks/default/long-lived/PIV-shadowsocks-default-long-lived-20261024T173726Z-001/probe.json | proxy_json routing.outbound_kind=shadowsocks outbound.kind=shadowsocks; workload_error=heartbeat 0: tunnel read: Resource temporarily unavailable (os error 11) … |
| Default/Reconnect | FAIL | ProductSocks5 | ProductPath | PIV-shadowsocks-default-reconnect-20261024T173929Z-001 | E_NEXUS_FRAMING | reconnects=0 | evidence/shadowsocks/default/reconnect/PIV-shadowsocks-default-reconnect-20261024T173929Z-001/probe.json | proxy_json routing.outbound_kind=shadowsocks outbound.kind=shadowsocks; workload_error=cycle 0: tunnel read: Resource temporarily unavailable (os error 11) … |
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

- [`docs/protocols/interop/fix/hysteria2/root-cause.md`](fix/hysteria2/root-cause.md)：Hysteria2 认证响应解码失败 — 根因报告（S27）
- [`docs/protocols/interop/fix/shadowsocks/root-cause.md`](fix/shadowsocks/root-cause.md)：Shadowsocks 线格式不兼容 — 根因报告（S27）
- [`docs/protocols/interop/fix/transport/root-cause.md`](fix/transport/root-cause.md)：产品数据面批量传输在 WouldBlock 上误判为致命错误 — 根因报告（S27）
- [`docs/protocols/interop/fix/trojan/root-cause.md`](fix/trojan/root-cause.md)：Trojan fallback 静默成功 — 根因报告（S27 / B-6）
- [`docs/protocols/interop/fix/vless/root-cause.md`](fix/vless/root-cause.md)：VLESS 产品路径握手死锁 — 根因报告（S27）

根因文档内的 `evidence/...` 路径相对主机证据根 `$RUN_DIR=/work/interop-run/protocol-interop-verification`（非仓库内路径）；仓库内可打开的是根因文档本身。spec 原文不在仓库，规则 1/2 的判定摘要见顶部「先读」。

| fix 支线复验（vless lazy response）| 状态 | evidence_id |
|---|---|---|
| Handshake | PASS | PIV-vless-default-handshake-20261024T174904Z-001 |
| Handshake | PASS | PIV-vless-default-handshake-20261024T175114Z-001 |
| LongLived | PASS | PIV-vless-default-long-lived-20261024T174909Z-001 |
| LongLived | PASS | PIV-vless-default-long-lived-20261024T175118Z-001 |
| Reconnect | PASS | PIV-vless-default-reconnect-20261024T175101Z-001 |
| Reconnect | PASS | PIV-vless-default-reconnect-20261024T175311Z-001 |
| TcpSmall | PASS | PIV-vless-default-tcp-small-20261024T174907Z-001 |
| TcpSmall | PASS | PIV-vless-default-tcp-small-20261024T175116Z-001 |
| TcpThroughput | FAIL | PIV-vless-default-tcp-throughput-20261024T175335Z-001 |
| TcpThroughput | FAIL | PIV-vless-default-tcp-throughput-20261024T175439Z-001 |

复验基于 fix 分支 `fix/protocol-interop-vless-lazy-response`；review 与 re-verify 已完成（R-01 PASS）。合入与 verdict 更新待 fix 流程另行裁决；即使合入，T2 仍受 transport 阻塞——上表 verdict 只用 verify 分支基线证据。

## 附录 A：配置索引

| 文件 | sha256 |
|---|---|
| evidence/ref-config/anytls-custom-padding.json | 53ff76068f4f366cb76d151045be4cce140b8801c9d481368449feaf2ad2ce17 |
| evidence/ref-config/anytls.json | 4b39f714e38b7b83580274ca76bfd53ad1a4c5b9177531a22c12f9af7c291b7f |
| evidence/ref-config/hysteria2-plain.json | 3d39fbbed36630414ff32aa65afea87c0635ac09008844ba4b21c1e5e893c24e |
| evidence/ref-config/hysteria2-salamander.json | c8fbec2e76cc259ce21c457f435e90e5f3914f2b5f1df82bcaeee55c6e4751e2 |
| evidence/ref-config/shadowsocks-aes256gcm.json | 80a68051442ac2a5b812e2d0f03298b5db87c4a69d9ece83296af89dc386ce08 |
| evidence/ref-config/shadowsocks.json | 2c5bc8415e4a4ef3650f12df05ea608f77df2d5597a9741ba8264c99db9884f1 |
| evidence/ref-config/trojan-fallback.json | faac89bdd587e5c39083fc73d8f64c2d4b1574d23977864f68a4e481e6417b6d |
| evidence/ref-config/trojan.json | 6aea2b1607f022434ede78e0dd700f6644acfbff10591906070631968fbcfb26 |
| evidence/ref-config/vless-basic-flow-mismatch.json | 0165eda05634bfc1ad68517da4a11330afded70d867e9954724644a220370c23 |
| evidence/ref-config/vless-basic.json | bae9885c1a0fcd6a959397eea07197dea8ed0c932412b034dac76000ce455a13 |
| evidence/ref-config/vless-vision.json | efc92e4461c9bad5813b1959500b31fabdaa61072335e52e1f76acb747229a78 |
| evidence/ref-config/xray-vless-basic.json | f6bbc3a5e513eb07e5e20cab9dcad2650dc0b5a620beb50cb0e7ae54c4c85f3f |
| evidence/ref-config/xray-vless-vision.json | ae5ea283976e3add48fe2b3249da6520228394ebb3beb47061be0aff45e9c299 |

## 附录 B：证据清单

| evidence_id | verdict | carrier | scope | 路径 |
|---|---|---|---|---|
| PIV-anytls-anytls-custom-padding-bad-config-20261024T191740Z-001 | PASS | ProductSocks5 | ProductPath | evidence/anytls/anytls-custom-padding/bad-config/PIV-anytls-anytls-custom-padding-bad-config-20261024T191740Z-001/probe.json |
| PIV-anytls-default-bad-credential-20261024T191738Z-001 | PASS | ProductSocks5 | ProductPath | evidence/anytls/default/bad-credential/PIV-anytls-default-bad-credential-20261024T191738Z-001/probe.json |
| PIV-anytls-default-handshake-20261024T172529Z-001 | PASS | ProductSocks5 | ProductPath | evidence/anytls/default/handshake/PIV-anytls-default-handshake-20261024T172529Z-001/probe.json |
| PIV-anytls-default-long-lived-20261024T172542Z-001 | PASS | ProductSocks5 | ProductPath | evidence/anytls/default/long-lived/PIV-anytls-default-long-lived-20261024T172542Z-001/probe.json |
| PIV-anytls-default-padding-diag-20261024T174336Z-001 | PASS | ProductSocks5 | ProductPath | evidence/anytls/default/padding-diag/PIV-anytls-default-padding-diag-20261024T174336Z-001/probe.json |
| PIV-anytls-default-reconnect-20261024T172736Z-001 | PASS | ProductSocks5 | ProductPath | evidence/anytls/default/reconnect/PIV-anytls-default-reconnect-20261024T172736Z-001/probe.json |
| PIV-anytls-default-tcp-small-20261024T172534Z-001 | PASS | ProductSocks5 | ProductPath | evidence/anytls/default/tcp-small/PIV-anytls-default-tcp-small-20261024T172534Z-001/probe.json |
| PIV-anytls-default-tcp-throughput-20261024T175443Z-001 | FAIL | ProductSocks5 | ProductPath | evidence/anytls/default/tcp-throughput/PIV-anytls-default-tcp-throughput-20261024T175443Z-001/probe.json |
| PIV-anytls-default-udp-echo-20261024T174215Z-001 | PASS | CrateDirect | ProtocolWire | evidence/anytls/default/udp-echo/PIV-anytls-default-udp-echo-20261024T174215Z-001/probe.json |
| PIV-hysteria2-default-bad-config-20261024T191744Z-001 | PASS | ProductSocks5 | ProductPath | evidence/hysteria2/default/bad-config/PIV-hysteria2-default-bad-config-20261024T191744Z-001/probe.json |
| PIV-hysteria2-default-bad-credential-20261024T191742Z-001 | FAIL | ProductSocks5 | ProductPath | evidence/hysteria2/default/bad-credential/PIV-hysteria2-default-bad-credential-20261024T191742Z-001/probe.json |
| PIV-hysteria2-default-handshake-20261024T173039Z-001 | FAIL | ProductSocks5 | ProductPath | evidence/hysteria2/default/handshake/PIV-hysteria2-default-handshake-20261024T173039Z-001/probe.json |
| PIV-hysteria2-default-long-lived-20261024T173048Z-001 | FAIL | ProductSocks5 | ProductPath | evidence/hysteria2/default/long-lived/PIV-hysteria2-default-long-lived-20261024T173048Z-001/probe.json |
| PIV-hysteria2-default-qpack-diag-20261024T174317Z-001 | PASS | CrateDirect | ProtocolWire | evidence/hysteria2/default/qpack-diag/PIV-hysteria2-default-qpack-diag-20261024T174317Z-001/probe.json |
| PIV-hysteria2-default-reconnect-20261024T173050Z-001 | FAIL | ProductSocks5 | ProductPath | evidence/hysteria2/default/reconnect/PIV-hysteria2-default-reconnect-20261024T173050Z-001/probe.json |
| PIV-hysteria2-default-tcp-small-20261024T173041Z-001 | FAIL | ProductSocks5 | ProductPath | evidence/hysteria2/default/tcp-small/PIV-hysteria2-default-tcp-small-20261024T173041Z-001/probe.json |
| PIV-hysteria2-default-tcp-throughput-20261024T173044Z-001 | FAIL | ProductSocks5 | ProductPath | evidence/hysteria2/default/tcp-throughput/PIV-hysteria2-default-tcp-throughput-20261024T173044Z-001/probe.json |
| PIV-hysteria2-default-udp-echo-20261024T174221Z-001 | FAIL | CrateDirect | ProtocolWire | evidence/hysteria2/default/udp-echo/PIV-hysteria2-default-udp-echo-20261024T174221Z-001/probe.json |
| PIV-hysteria2-hy2-salamander-handshake-20261024T173056Z-001 | FAIL | ProductSocks5 | ProductPath | evidence/hysteria2/hy2-salamander/handshake/PIV-hysteria2-hy2-salamander-handshake-20261024T173056Z-001/probe.json |
| PIV-shadowsocks-default-bad-config-20261024T191823Z-001 | PASS | ProductSocks5 | ProductPath | evidence/shadowsocks/default/bad-config/PIV-shadowsocks-default-bad-config-20261024T191823Z-001/probe.json |
| PIV-shadowsocks-default-bad-credential-20261024T191810Z-001 | PASS | ProductSocks5 | ProductPath | evidence/shadowsocks/default/bad-credential/PIV-shadowsocks-default-bad-credential-20261024T191810Z-001/probe.json |
| PIV-shadowsocks-default-handshake-20261024T173553Z-001 | FAIL | ProductSocks5 | ProductPath | evidence/shadowsocks/default/handshake/PIV-shadowsocks-default-handshake-20261024T173553Z-001/probe.json |
| PIV-shadowsocks-default-long-lived-20261024T173726Z-001 | FAIL | ProductSocks5 | ProductPath | evidence/shadowsocks/default/long-lived/PIV-shadowsocks-default-long-lived-20261024T173726Z-001/probe.json |
| PIV-shadowsocks-default-reconnect-20261024T173929Z-001 | FAIL | ProductSocks5 | ProductPath | evidence/shadowsocks/default/reconnect/PIV-shadowsocks-default-reconnect-20261024T173929Z-001/probe.json |
| PIV-shadowsocks-default-tcp-small-20261024T173656Z-001 | FAIL | ProductSocks5 | ProductPath | evidence/shadowsocks/default/tcp-small/PIV-shadowsocks-default-tcp-small-20261024T173656Z-001/probe.json |
| PIV-shadowsocks-default-tcp-throughput-20261024T173659Z-001 | FAIL | ProductSocks5 | ProductPath | evidence/shadowsocks/default/tcp-throughput/PIV-shadowsocks-default-tcp-throughput-20261024T173659Z-001/probe.json |
| PIV-shadowsocks-default-udp-echo-20261024T174224Z-001 | NOT_IMPLEMENTED | CrateDirect | ProtocolWire | evidence/shadowsocks/default/udp-echo/PIV-shadowsocks-default-udp-echo-20261024T174224Z-001/probe.json |
| PIV-trojan-default-bad-config-20261024T173215Z-001 | NOT_APPLICABLE | CrateDirect | ProtocolWire | evidence/trojan/default/bad-config/PIV-trojan-default-bad-config-20261024T173215Z-001/probe.json |
| PIV-trojan-default-bad-credential-20261024T191756Z-001 | PASS | ProductSocks5 | ProductPath | evidence/trojan/default/bad-credential/PIV-trojan-default-bad-credential-20261024T191756Z-001/probe.json |
| PIV-trojan-default-handshake-20261024T173155Z-001 | PASS | ProductSocks5 | ProductPath | evidence/trojan/default/handshake/PIV-trojan-default-handshake-20261024T173155Z-001/probe.json |
| PIV-trojan-default-long-lived-20261024T173219Z-001 | PASS | ProductSocks5 | ProductPath | evidence/trojan/default/long-lived/PIV-trojan-default-long-lived-20261024T173219Z-001/probe.json |
| PIV-trojan-default-reconnect-20261024T173416Z-001 | PASS | ProductSocks5 | ProductPath | evidence/trojan/default/reconnect/PIV-trojan-default-reconnect-20261024T173416Z-001/probe.json |
| PIV-trojan-default-tcp-small-20261024T173157Z-001 | PASS | ProductSocks5 | ProductPath | evidence/trojan/default/tcp-small/PIV-trojan-default-tcp-small-20261024T173157Z-001/probe.json |
| PIV-trojan-default-tcp-throughput-20261024T175446Z-001 | FAIL | ProductSocks5 | ProductPath | evidence/trojan/default/tcp-throughput/PIV-trojan-default-tcp-throughput-20261024T175446Z-001/probe.json |
| PIV-trojan-default-udp-echo-20261024T174223Z-001 | NOT_IMPLEMENTED | CrateDirect | ProtocolWire | evidence/trojan/default/udp-echo/PIV-trojan-default-udp-echo-20261024T174223Z-001/probe.json |
| PIV-trojan-trojan-fallback-bad-credential-20261024T191808Z-001 | FAIL | ProductSocks5 | ProductPath | evidence/trojan/trojan-fallback/bad-credential/PIV-trojan-trojan-fallback-bad-credential-20261024T191808Z-001/probe.json |
| PIV-vless-default-bad-config-20261024T191736Z-001 | PASS | ProductSocks5 | ProductPath | evidence/vless/default/bad-config/PIV-vless-default-bad-config-20261024T191736Z-001/probe.json |
| PIV-vless-default-bad-credential-20261024T191726Z-001 | PASS | ProductSocks5 | ProductPath | evidence/vless/default/bad-credential/PIV-vless-default-bad-credential-20261024T191726Z-001/probe.json |
| PIV-vless-default-handshake-20261024T172249Z-001 | FAIL | ProductSocks5 | ProductPath | evidence/vless/default/handshake/PIV-vless-default-handshake-20261024T172249Z-001/probe.json |
| PIV-vless-default-long-lived-20261024T172328Z-001 | FAIL | ProductSocks5 | ProductPath | evidence/vless/default/long-lived/PIV-vless-default-long-lived-20261024T172328Z-001/probe.json |
| PIV-vless-default-reconnect-20261024T172339Z-001 | FAIL | ProductSocks5 | ProductPath | evidence/vless/default/reconnect/PIV-vless-default-reconnect-20261024T172339Z-001/probe.json |
| PIV-vless-default-tcp-small-20261024T172301Z-001 | FAIL | ProductSocks5 | ProductPath | evidence/vless/default/tcp-small/PIV-vless-default-tcp-small-20261024T172301Z-001/probe.json |
| PIV-vless-default-tcp-throughput-20261024T172313Z-001 | FAIL | ProductSocks5 | ProductPath | evidence/vless/default/tcp-throughput/PIV-vless-default-tcp-throughput-20261024T172313Z-001/probe.json |
| PIV-vless-default-udp-echo-20261024T174211Z-001 | PASS | CrateDirect | ProtocolWire | evidence/vless/default/udp-echo/PIV-vless-default-udp-echo-20261024T174211Z-001/probe.json |
| PIV-vless-vless-vision-handshake-20261024T172418Z-001 | PASS | CrateDirect | ProtocolWire | evidence/vless/vless-vision/handshake/PIV-vless-vless-vision-handshake-20261024T172418Z-001/probe.json |
| PIV-vless-vless-vision-tcp-small-20261024T172419Z-001 | PASS | CrateDirect | ProtocolWire | evidence/vless/vless-vision/tcp-small/PIV-vless-vless-vision-tcp-small-20261024T172419Z-001/probe.json |

## 附录 C：命令与端口

```bash
scripts/interop/run-matrix.sh --protocol <p> --variant <v> --cell <c> \
  --run-dir /work/interop-run/protocol-interop-verification \
  --probe-bin $CARGO_TARGET_DIR/debug/examples/protocol_interop_probe \
  --ref-bin $RUN_DIR/ref/sing-box-1.13.16-linux-amd64-musl/sing-box
python3 scripts/interop/recompute-verdicts.py --run-dir $RUN_DIR \
  --matrix docs/protocols/interop/MATRIX.md --check
```

- 参照端口：vless 26100/26101、anytls 26102、hysteria2 26103/26104、
  trojan 26105/26115、shadowsocks 26106、xray 26108/26109。
- 目标端口：26200 echo / 26201 sink+source / 26202 udp / 26203 http fallback。
- 抓包：dumpcap -P（pcap），T2 用 `-a filesize:102400` 封顶 100 MiB。

## 附录 D：终局 T2 证据构建来源

| 协议 | evidence_id | nexus.commit | cargo_target_dir | binary_sha256 |
|---|---|---|---|---|
| Vless | PIV-vless-default-tcp-throughput-20261024T172313Z-001 | 878318c1cd03b45885b54bc7ce51e89da437ecc4 | /work/wt-protocol-interop/target-interop | 634fe5047f2cf0d56a27c7b0d952bd60a9752f2798f9139e1b2535e4807e57e0 |
| Anytls | PIV-anytls-default-tcp-throughput-20261024T175443Z-001 | b7acb321dd080a86667c06c7993532dce3d793f2 | /work/wt-interop-fix-vless/target | 3ae316d8592c68876d440f2480f5a05c56b1a633efaaf10419e79a764f236755 |
| Hysteria2 | PIV-hysteria2-default-tcp-throughput-20261024T173044Z-001 | 0e66bdfdfe97b67db46d7b81547268d2864c0bdd | /work/wt-protocol-interop/target-interop | 4c021c27d18e9e1bc35493de1b04ad81929b392c40ff64648cba1d932e14a744 |
| Trojan | PIV-trojan-default-tcp-throughput-20261024T175446Z-001 | b7acb321dd080a86667c06c7993532dce3d793f2 | /work/wt-interop-fix-vless/target | 3ae316d8592c68876d440f2480f5a05c56b1a633efaaf10419e79a764f236755 |
| Shadowsocks | PIV-shadowsocks-default-tcp-throughput-20261024T173659Z-001 | 0e66bdfdfe97b67db46d7b81547268d2864c0bdd | /work/wt-protocol-interop/target-interop | 4c021c27d18e9e1bc35493de1b04ad81929b392c40ff64648cba1d932e14a744 |

AnyTLS/Trojan 终局 T2 由 fix 分支 `b7acb32` 的 fix worktree 构建（fix 仅改 VLESS 响应头泵，产品 `apps/nexus/src/lib.rs` 本表基线未被改动）；同格 FAIL 另有主 worktree 构建记录。

## 附录 E：被替代运行

| evidence_id | 原结论 | 替代者 | 弃用理由 |
|---|---|---|---|
| PIV-anytls-default-tcp-throughput-20261024T173000Z-001 | PASS | PIV-anytls-default-tcp-throughput-20261024T175443Z-001 | 0981421（T2 证据鲁棒性修复）后重跑否决：早期 PASS 系 EOF/超时被当作成功；修复后 174434Z/175443Z 稳定 FAIL（E_NEXUS_TRANSPORT，WouldBlock 传输缺陷） |
| PIV-trojan-default-tcp-throughput-20261024T173200Z-001 | PASS | PIV-trojan-default-tcp-throughput-20261024T175446Z-001 | 0981421（T2 证据鲁棒性修复）后重跑否决：早期 PASS 系 EOF/超时被当作成功；修复后 174437Z/175446Z 稳定 FAIL（E_NEXUS_TRANSPORT，WouldBlock 传输缺陷） |
| PIV-hysteria2-default-bad-credential-20261024T173046Z-001 | PASS | PIV-hysteria2-default-bad-credential-20261024T191742Z-001 | 85a6bb8（负向诚实性修复）后重跑否决：早期把客户端解码失败当参照端拒绝；修复后 probe=Blocked + E_NEXUS_CODEC，按 D1 映射 FAIL（R-01 判卷机修复后再次重跑结论一致） |

复算的选择规则是同格取最新 evidence_id；被替代运行仍保留在证据树与 `analysis/progress.tsv`，不覆盖历史结论。
