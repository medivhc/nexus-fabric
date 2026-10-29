# 出站协议互操作证据总表（MATRIX）

> 本文件由 `scripts/interop/recompute-verdicts.py` 从证据机械生成；人工零编辑。
> 修复顺序、依赖与复验口径见人工维护的 [NEXT-STEPS.md](NEXT-STEPS.md)。

- run `protocol-interop-fixes-6`；baseline `e1bb2770074b533bbe6ddba7dd37f5a1426d312f`；spec frozen fixes-6 frozen v1.0（sha256 `ebb8ba3eb7164753dba4838ba08b58ca7eada7b7fa0ec2bcec6141716cad6cbe`）；test window `2026-10-25T18:22:40Z .. 2026-10-28T15:19:44Z`。
- 参照实现：sing-box 1.13.16（sha256 `8da901e7b6eb0d2f6f6e701f19d5f78af235d038ae078b37a70739db5895d262`）；Xray 26.10.21（sha256 `MISSING`）。
- archive（主机归档路径）：（S30 归档后追加）。
- 注记：`docs/protocols/interop/notes/trojan-fallback.md`（sha256 `0c49d2f5ea7e7c121731b212fc5f652be17cde97d11d7a8972195e9c27f7a339`）；本节由 `recompute-verdicts.py --notes` 注入，禁止手工编辑 MATRIX。

## 先读：范围 / 结论 / 图例

- **覆盖**：5 个出站代理协议（VLESS、AnyTLS、Hysteria2、Trojan、Shadowsocks）共 52 个证据格。TCP 成功型格走产品 SOCKS5 出口路径；`UdpEcho` 为产品级（`ProductSocks5`/`ProductPath`），`UdpEchoCrate` 为 crate 级诊断格（`CrateDirect`/`ProtocolWire`）；VLESS Vision 部分格为 crate 直调。
- **不覆盖**：VMess（本轮暂缓）、direct/relay/socks5 出站、TUN/VPN、Android 统一 VPN 入口、UI/诊断呈现。
- **本表不回答**：直连/中继回退是否可用（属 N1 整体结论）；也不把「产品级 UDP 能力缺口」扩大成「Hy2 的 QUIC 出站传输不可用」（见产品级 UDP 节）。
- **结论 1**：本次复算：`VERIFIED` 2 个（Vless、Anytls），`PARTIAL` 3 个（Hysteria2、Trojan、Shadowsocks），`BROKEN` 0 个；当前**无缺口**可宣称可用（`VERIFIED / USABLE`）的协议为 Vless、Anytls；另有 3 个 `USABLE_WITH_GAPS`（Hysteria2、Trojan、Shadowsocks）。
- **结论 1 限定**：`USABLE` 指协议级互操作：TCP 产品路径 + 产品级 UDP（`UdpEcho` 行）。产品 SOCKS5 UDP ASSOCIATE 已有产品级证据支撑：Vless、Anytls；其余协议产品级 UDP 仍为 `NOT_IMPLEMENTED` 或未通过（Hysteria2、Trojan、Shadowsocks），见「产品级 UDP」节。
- **结论 2**：剩余阻断分属产品能力缺口（Trojan/Shadowsocks/Hysteria2 出站 UDP 未接线）与产品安全语义（Trojan fallback 的窗口外残余）。本 run 把 UdpEcho 证据面按 Q10 重锚到产品级：VLESS/AnyTLS 由新鲜产品级证据支撑 PASS；Hy2 的 crate 级 UDP 虽 PASS，但产品级 UdpEcho 为 NOT_IMPLEMENTED，按 spec E1 规则 6 回落 `PARTIAL / PROTOCOL_SUBSET / USABLE_WITH_GAPS`（不是代码回归，是证据锚点变化）。 Hysteria2 的口径需三句话讲清：(1) Hy2 的 TCP 产品路径结论不变（逐格 PASS 仍在）；(2) 变化的是证据作用域：产品级 `UdpEcho` 未实现，按 spec E1 规则 6 记 `PARTIAL`；(3) crate 级 UDP 仍 PASS（`UdpEchoCrate`），QUIC 出站传输不受影响。
- **结论 3**：未达 `VERIFIED` 的协议及本次复算代表根因：Hysteria2 `PARTIAL / E_NEXUS_NOT_IMPLEMENTED`；Trojan `PARTIAL / E_NEXUS_NOT_IMPLEMENTED`；Shadowsocks `PARTIAL / E_NEXUS_NOT_IMPLEMENTED`。
- **结论 4**：Trojan/Shadowsocks 的 UDP 缺口仍在产品出站侧（crate 无标准 UDP 帧 API；SIP004 线格式已由 fixes-2 修复）；Hy2 同样为产品出站未接线。三者上限均为 `PARTIAL / USABLE_WITH_GAPS`（spec E1 规则 6）。Trojan fallback fail-open 主路径已由 fixes-5 关闭（success 前零字节投递），剩余为 success 之后到达的 fallback（R-1/R-2 承诺边界）。
- **结论 5**：五协议仍可在产品配置面选择且无「实验性/未验证」标注；配置面标注（P0b）仍待 protocol-config-surface-labeling run 落地（本 run 不改配置面）。本 run 只翻转产品 SOCKS5 的 UDP 能力面：TUN 表面仍为 `PRODUCT_UDP_NOT_IMPLEMENTED`（Q2/R-1，两表面不同步）。
- **优先级 1（C1，DONE）**：ingress SOCKS5 UDP ASSOCIATE 命令/地址/数据报编解码——DONE（commit 1e4762cc）；证据：cargo test -p nexus-ingress；cargo check -p nexus-ingress --target wasm32-wasip1。
- **优先级 2（C2，DONE）**：出站 UDP 抽象与 VLESS/AnyTLS 会话——DONE（commit 2ac45f49）：Supported(VlessOverTcp)/Supported(AnytlsUot)；Trojan/SS/Hy2 取 NotWired；证据：apps/nexus/src/udp_outbound.rs；cargo test -p nexus --lib。
- **优先级 3（C3，DONE）**：UDP 关联管理器（flow 表/源校验/限速/队列）——DONE（commit 2bf72bba）；证据：apps/nexus/src/udp_association.rs；cargo test -p nexus --lib。
- **优先级 4（C4，DONE）**：proxy_serve_once 接入 UDP ASSOCIATE 与 fail-closed——DONE（commit e8f3fe78）：产品入口 + 能力翻转同 commit；证据：apps/nexus/src/lib.rs；cargo test -p nexus --lib。
- **优先级 5（C5，DONE）**：证据面契约：UdpEcho 产品化 + UdpEchoCrate diag——DONE（commit 3e132e87）；证据：scripts/interop/cell-matrix.json；scripts/interop/recompute-verdicts.py。
- **优先级 6（C6，DONE）**：产品 UDP E4 入口与 crate 证据执行——DONE（commit e1bb2770）：proxy_udp_associate 6 case 全 PASS；证据：apps/nexus/examples/proxy_udp_associate.rs；apps/nexus/examples/interop/product.rs。
- **优先级 7（P7，待办）**：产品级 UDP（Trojan/SS/Hy2 出站）——VLESS（flow=None）/AnyTLS（UoT）已产品级可用并有新鲜 UdpEcho 证据；Trojan/Shadowsocks/Hysteria2 出站仍无 UDP 帧 API，产品级 UdpEcho = NOT_IMPLEMENTED（fail-closed，不直连）。
- **字段**：`verdict` = `VERIFIED`（规则 8，全 required PASS）/ `PARTIAL`（规则 3–7/9，非阻断缺口）/ `BROKEN`（规则 1/2，阻断性 Nexus 失败）；`scope` = `PROTOCOL_SUBSET` / `FULL` / `TCP_ONLY`；`claim` = `USABLE` / `USABLE_WITH_GAPS` / `NOT_USABLE` / `NOT_CLAIMED`；`carrier` = `ProductSocks5`（产品 SOCKS5 出口路径）/ `CrateDirect`（crate 直调，非产品入口）。
- **规则 1**：失败格（BadCredential/BadConfig）判 FAIL 且表现为有效 echo/静默成功（`E_NEXUS_FRAMING`）或挂死（`E_TIMEOUT_HANG`）→ `BROKEN`。
- **规则 2**：任一 required 格 FAIL 且 class 属 `E_NEXUS_*` / `E_TIMEOUT_HANG` → `BROKEN`。
- **错误类**：`E_NEXUS_*` = Nexus 侧失败（握手/线格式、认证编码、帧/静默成功、传输、UDP、编解码、未实现），判 FAIL；`E_TIMEOUT_HANG` = 挂死/超时，判 FAIL；`E_EXPECTED_*` = 预期认证/配置拒绝，负向格判 PASS；`E_REF_*` / `E_NETWORK_ENV` / `E_TOOL_BUG` / `E_EVIDENCE_GAP` = 参照端/环境/证据缺口，判 BLOCKED（`E_REF_LIMITATION` 判 FAIL，须带 `ref_source`/`ref_version`）。
- **Xray**：26.10.21 仅用于 VLESS Vision 争议裁决，本轮未触发；五协议结论全部来自 sing-box 1.13.16 参照。
- **测试广度**：上述结论仅对 sing-box 1.13.16 参照配置成立；Xray 26.10.21 本轮未触发作裁决；其他服务端实现/传输组合（含 REALITY、ws/grpc）未测。

## Trojan 注记（机器注入自 `docs/protocols/interop/notes/trojan-fallback.md`）

<!-- notes_sha256=0c49d2f5ea7e7c121731b212fc5f652be17cde97d11d7a8972195e9c27f7a339 -->

# Trojan fallback fail-closed — 修复注记（protocol-interop-fixes-5）

> 本文件是本 run 的 MATRIX Trojan 注记**正本**，随仓库 check-in；只经
> `recompute-verdicts.py --notes docs/protocols/interop/notes/trojan-fallback.md`
> 注入生成产物。人工直接编辑 `MATRIX.md` 视为违反契约（spec AC-14.3）。

## 结论与承诺边界

- 已交付：**CONNECT 应答暂存 + Trojan 就绪窗口 + 首包分类 + 失败应答**。当节点实际
  拒绝了本次连接（密码错误、服务端 fallback、首包前关闭）时，客户端在任何隧道载荷之前
  看到失败：SOCKS5 `REP != 0`（节点端口拒绝时 `0x05`，其余 `0x01`）、HTTP
  `502 Bad Gateway`；失败后 500ms 内 EOF，隧道字节 = 0。
- 承诺边界（不写成已关闭全部残余）：本 run 只保证「**在 success 之前到达的 fallback
  首包零字节投递**」。success 之后才到达的 fallback 首包不可判定（Trojan 无响应头、
  无认证回执的协议上限），公开登记为残余（R-1/R-2）。
- verdict 上限：`PARTIAL / TCP_ONLY / USABLE_WITH_GAPS`（`UdpEcho` 仍
  `NOT_IMPLEMENTED`，归 fixes-6）。不写成 `VERIFIED`。
- 线缆面：客户端→服务端的字节流、Trojan 请求头、TLS 记录划分与基线一致；不注入任何
  探测/占位/心跳字节；失败只在本地 SOCKS5/HTTP 应答层可观察（不 flush `close_notify`、
  不写额外 TLS alert）。

## 残余风险（登记 ≠ 关闭）

| # | 残余 | 用户可见后果 | 去向 |
|---|---|---|---|
| R-1 | fallback 响应慢于 `W`（>1 RTT + 50ms，或 >600ms 自适应上限；显式覆盖过小时同理） | success 已写出，窗口外到达的 fallback 内容仍可能被当作隧道数据 | 本注记（承诺边界） |
| R-2 | fallback 等客户端先发载荷后才响应 | 零载荷判据失效，同上 | 本注记（承诺边界） |
| R-3 | `signature` 模式下的非 HTTP fallback | 显式安全降级的已知漏报 | 本注记 + PRODUCT §11.9.3 |
| R-4 | 客户端在 success 前 pipelined 载荷（`seed` 非空） | 守卫不适用（扣压又违反上行零扣压） | 本注记 |
| R-5 | `nexusd` TUN / `ProxyEngine` 路径 | 该入口的「成功」由 smoltcp SYN-ACK 伪造，仍 fail-open | `NEXT-STEPS.md`（单独立项） |
| R-6 | HTTP 绝对形式转发（non-CONNECT） | 不回本地成功应答，fallback 的 404 仍作为 origin 响应出现 | `NEXT-STEPS.md` |
| R-7 | 服务端被完全劫持并伪装成真实目标 | 超出协议可判定范围（需端到端认证/证书钉扎） | 威胁模型边界 |

## §12 已接受的行为变更

`Default/BadCredential`（无 fallback 的坏凭据）本地形态：

| 项 | 变更前 | 变更后 |
|---|---|---|
| SOCKS5 CONNECT 应答 | `REP=0x00` 已写出，随后隧道 EOF | **应答阶段 `REP=0x01`**（success 未写出） |
| 客户端可见 | 「隧道建立成功后又 EOF」 | 「代理连接被拒绝」 |
| MATRIX 判定 | PASS | **PASS（不变）** |
| 错误分类 | `E_EXPECTED_AUTH_REJECT` | **`E_EXPECTED_AUTH_REJECT`（不变）** |
| 线缆字节（client→node） | 基线 | 与基线逐字节一致 |

理由：鉴权拒绝在 CONNECT 应答阶段暴露比「先报成功再 EOF」更诚实。回滚必须走
requirement-change 改 spec 与 MATRIX 期望，不得在实现里静默分支回退。

## 严格模式误杀面（M-1~M-8）与 signature 逃生口

`fallback_guard: strict`（默认）只放行端口绑定的 server-first greeting 白名单
（22 `SSH-`、21/25/587 `220`、110 `+OK`、143 `* OK`、5900 `RFB `）。下面的**合法**
server-first 目标会被判为「非白名单首包」而拒绝：

| # | 合法 server-first 目标 | strict（默认） | signature |
|---|---|---|---|
| M-1 | MySQL 3306 二进制握手 | 拒绝 | 放行 |
| M-2 | SSH on 非规范端口（如 2222） | 拒绝 | 放行 |
| M-3 | telnet IAC（首字节 `0xFF`） | 拒绝 | 放行 |
| M-4 | 自定义 banner（任意端口） | 拒绝 | 放行 |
| M-5 | SMTP 非 `220` 应答（554/421 等，端口 25/587） | 拒绝 | 放行 |
| M-6 | VNC/FTP/POP3/IMAP on 非规范端口 | 拒绝 | 放行 |
| M-7 | 白名单前缀被 TCP 分片且 50ms 内未补齐 | 拒绝 | 放行 |
| M-8 | 白名单端口但首包被中间盒改写为非典型 banner | 拒绝 | 放行 |

`fallback_guard: signature` 是**明确标注的安全降级（官方逃生口）**：只拒绝 `HTTP/`
状态行，其余一律放行。切换即接受**非 HTTP fallback 全部漏报**的代价（R-3）；
不存在 `off`/完全关闭的官方开关。AC-8 的确定性枚举（白名单 7 端口 × Handshake/
TcpSmall 100% PASS、M-1~M-8 在 strict 下 100% 拒绝、signature 下 100% 放行）见
`/work/interop-run/fixes5/analysis/ac8-whitelist.json`。

## 证据（本 run）

- 基线二进制（AC-2/AC-3/AC-6/AC-9 的对照臂）：`a30147a` 同机重建，
  `nexus` sha256 `2f5ad75e9f56a57b81482f691e22e6d4a0c29bf9adfddf06ad4954ec81978791`，
  probe sha256 `74c9fcac7e30fdb3370b6b7fcf91b0c6368d102ef86afa71af58e5524d346ac5`
  （登记于 `/work/interop-run/fixes5/analysis/baseline-binaries.json`）。
- 候选 probe 二进制（interop 全格所用）：sha256
  `b51a52726cd22320c447687cae6ab1a3b6b0fa4d854926199dc81d7986f3ed66`。
- AC-3（上行零扣压，3 轮 × 200）：`/work/interop-run/fixes5/analysis/ac3-pipelined.json`
  （逐轮 p99 与反转量；判据 p99 ≤ 5ms）。
- AC-6（失败的服务端可见差异，35 配对样本）：
  `/work/interop-run/fixes5/analysis/ac6-wire.json` +
  `ac6-baseline.pcap` / `ac6-candidate.pcap`（头记录后新增 client→node 字节 = 0、
  TLS alert = 0、客户端关闭时刻差中位 5.0ms / 最大 11.1ms、节点侧关闭差 ≤0.02ms）。
- AC-9（窗口校准，sing-box 1.13.16 trojan-fallback）：
  `/work/interop-run/fixes5/analysis/ac9-calibration.json`（114 完整流，p99 = 0.276ms，
  要求 ≥ 20.8ms，实际 `W = 50ms`）+ `ac9.pcap`。
- AC-1/AC-11 本地 E4：`analysis/ac1-local-fallback.json`、`analysis/ac11-mixed-inbound.json`。
- AC-2 T2：`/work/interop-run/fixes5/analysis/t2/t2-accounting.json`（两臂各 3 轮，
  逐格 evidence id 见该文件）。
- interop 全格证据：`/work/interop-run/fixes5/evidence/`（`analysis/verdicts.json` 为
  复算结果；`TrojanFallback/BadCredential` 的 probe.json + pcap 在同一目录树内）。

## 复算与校验

```bash
python3 scripts/interop/recompute-verdicts.py \
  --run-dir /work/interop-run/fixes5 \
  --run-meta /work/interop-run/fixes5/analysis/run-meta.json \
  --notes docs/protocols/interop/notes/trojan-fallback.md \
  --matrix docs/protocols/interop/MATRIX.md
python3 scripts/interop/recompute-verdicts.py ... --check   # 零漂移（含注记一致性）
```

## 协议 verdict（按 spec E1 复算）

| 协议 | verdict | scope | claim | root_cause_class | missing_cells | 命中规则 |
|---|---|---|---|---|---|---|
| Vless | VERIFIED | PROTOCOL_SUBSET | USABLE | NONE | NONE | 8 |
| Anytls | VERIFIED | FULL | USABLE | NONE | NONE | 8 |
| Hysteria2 | PARTIAL | PROTOCOL_SUBSET | USABLE_WITH_GAPS | E_NEXUS_NOT_IMPLEMENTED | UdpEcho(NOT_IMPLEMENTED,E_NEXUS_NOT_IMPLEMENTED) | 6 |
| Trojan | PARTIAL | TCP_ONLY | USABLE_WITH_GAPS | E_NEXUS_NOT_IMPLEMENTED | UdpEcho(NOT_IMPLEMENTED,E_NEXUS_NOT_IMPLEMENTED) | 6 |
| Shadowsocks | PARTIAL | TCP_ONLY | USABLE_WITH_GAPS | E_NEXUS_NOT_IMPLEMENTED | UdpEcho(NOT_IMPLEMENTED,E_NEXUS_NOT_IMPLEMENTED) | 6 |

## 阻塞层、归属与修复后上限

`root_cause_class` 是 E1 首个命中规则所取的**代表类**，不是完整根因；下表按 fix 根因文档给出直接阻塞层与归属，不改变上表 verdict。

| 协议 | 直接阻塞层 | 归属 | 剩余阻塞格（相对可用） | 单协议可解？ | 修复后本 run schema 上限 |
|---|---|---|---|---|---|
| Vless | 无（本 run 已修复，证据见「fix 支线与复验」） | — | 无 | — | `VERIFIED / PROTOCOL_SUBSET`（Vision 仅 crate 级，产品 splice 未实现） |
| Anytls | 无（本 run 已修复，证据见「fix 支线与复验」） | — | 无 | — | `VERIFIED / FULL` |
| Hysteria2 | 产品级 UDP 未接线（crate 级 UdpEcho 已 PASS） | 产品 UDP 能力缺口（本 run 只接线 VLESS/AnyTLS） | UdpEcho(NOT_IMPLEMENTED,E_NEXUS_NOT_IMPLEMENTED) | 否，依赖后续 run 接线 Hy2 出站 UDP | 本 run 最高 `PARTIAL / PROTOCOL_SUBSET / USABLE_WITH_GAPS`（产品 UdpEcho NOT_IMPLEMENTED，规则 6） |
| Trojan | 产品级 UDP 未接线（fallback fail-open 主路径已由 fixes-5 关闭） | 产品 UDP 能力缺口（crate 无 UDP 帧 API，R-3 取 NotWired） | UdpEcho(NOT_IMPLEMENTED,E_NEXUS_NOT_IMPLEMENTED) | 否，依赖后续 run 接线 Trojan 出站 UDP | 本 run 最高 `PARTIAL / TCP_ONLY / USABLE_WITH_GAPS`（产品 UdpEcho NOT_IMPLEMENTED，规则 6） |
| Shadowsocks | 产品级 UDP 未接线（SIP004 线格式已由 fixes-2 修复） | 产品 UDP 能力缺口（crate 无标准 UDP API） | UdpEcho(NOT_IMPLEMENTED,E_NEXUS_NOT_IMPLEMENTED) | 否，依赖后续 run 接线 SS 出站 UDP | 本 run 最高 `PARTIAL / TCP_ONLY / USABLE_WITH_GAPS`（产品 UdpEcho NOT_IMPLEMENTED，规则 6） |

**参照端生态**：本轮未发现参照端生态缺陷——sing-box 1.13.16 的行为符合规范；Xray 26.10.21 仅用于 Vision 争议裁决，本轮未触发。五协议 verdict 均无 `E_REF_*` 根因。

## Vless

> **verdict=VERIFIED / claim=USABLE**（scope=PROTOCOL_SUBSET，root_cause_class=NONE）
>
> 本节任一 PASS 不改变协议 verdict；单格 PASS 只在所列 carrier/scope 下成立。
> VlessVision 行为 crate 级证据，产品 Vision splice 未实现。

| Cell | 状态 | carrier | scope | evidence_id | class | 关键数字 | 证据路径 | notes |
|---|---|---|---|---|---|---|---|---|
| Default/Handshake | PASS | ProductSocks5 | ProductPath | PIV-vless-default-handshake-20261028T151326Z-001 | NONE | up=1B down=1B | evidence/vless/default/handshake/PIV-vless-default-handshake-20261028T151326Z-001/probe.json | proxy_json routing.outbound_kind=vless outbound.kind=vless; target_stats={"tcp_bytes_down":2,"tcp_bytes_up":2,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} … |
| Default/TcpSmall | PASS | ProductSocks5 | ProductPath | PIV-vless-default-tcp-small-20261028T151333Z-001 | NONE | up=65536B down=65536B | evidence/vless/default/tcp-small/PIV-vless-default-tcp-small-20261028T151333Z-001/probe.json | proxy_json routing.outbound_kind=vless outbound.kind=vless; target_stats={"tcp_bytes_down":65537,"tcp_bytes_up":65537,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} … |
| Default/TcpThroughput | PASS | ProductSocks5 | ProductPath | PIV-vless-default-tcp-throughput-20261028T151340Z-001 | NONE | median=1328403824B/s samples=3 | evidence/vless/default/tcp-throughput/PIV-vless-default-tcp-throughput-20261028T151340Z-001/probe.json | proxy_json routing.outbound_kind=vless outbound.kind=vless; target_stats={"tcp_bytes_down":101716128,"tcp_bytes_up":101712896,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} … |
| Default/LongLived | PASS | ProductSocks5 | ProductPath | PIV-vless-default-long-lived-20261028T151346Z-001 | NONE | heartbeats=12 | evidence/vless/default/long-lived/PIV-vless-default-long-lived-20261028T151346Z-001/probe.json | proxy_json routing.outbound_kind=vless outbound.kind=vless; target_stats={"tcp_bytes_down":13,"tcp_bytes_up":13,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} … |
| Default/Reconnect | PASS | ProductSocks5 | ProductPath | PIV-vless-default-reconnect-20261028T151539Z-001 | NONE | reconnects=3 | evidence/vless/default/reconnect/PIV-vless-default-reconnect-20261028T151539Z-001/probe.json | proxy_json routing.outbound_kind=vless outbound.kind=vless; target_stats={"tcp_bytes_down":4,"tcp_bytes_up":4,"tcp_connections":4,"udp_bytes":0,"udp_datagrams":0} … |
| Default/UdpEcho | PASS | ProductSocks5 | ProductPath | PIV-vless-default-udp-echo-20261028T151815Z-001 | NONE | udp 1000/1000 corrupt=0 | evidence/vless/default/udp-echo/PIV-vless-default-udp-echo-20261028T151815Z-001/probe.json | bnd=127.0.0.1:56769; proxy_json verdict=PASS routing.flows[0].outbound_kind=vless udp.datagrams_in=1000 udp.datagrams_out=1000 udp.send_failed=0; udp sent=1000 received=1000 corrupt=0; udp_seq_and_hash_ok …; 产品级（ProductSocks5） |
| Default/UdpEchoCrate | PASS | CrateDirect | ProtocolWire | PIV-vless-default-udp-echo-crate-20261028T151822Z-001 | NONE | up=512000B down=512000B | evidence/vless/default/udp-echo-crate/PIV-vless-default-udp-echo-crate-20261028T151822Z-001/probe.json | udp_seq_and_hash_ok; target_stats={"tcp_bytes_down":0,"tcp_bytes_up":0,"tcp_connections":0,"udp_bytes":512064,"udp_datagrams":1001} …; 诊断格，不参与 verdict |
| Default/BadCredential | PASS | ProductSocks5 | ProductPath | PIV-vless-default-bad-credential-20261028T151547Z-001 | E_EXPECTED_AUTH_REJECT | up=0B down=0B | evidence/vless/default/bad-credential/PIV-vless-default-bad-credential-20261028T151547Z-001/probe.json | proxy_json routing.outbound_kind=vless outbound.kind=vless; workload_error=eof; classification=E_EXPECTED_AUTH_REJECT; reference closed the session on the negative case …; 限定：正向路径不通时本格仅证明无静默成功，不独立证明认证拒绝语义 |
| Default/BadConfig | PASS | ProductSocks5 | ProductPath | PIV-vless-default-bad-config-20261028T151944Z-001 | E_EXPECTED_CONFIG_REJECT | up=0B down=0B | evidence/vless/default/bad-config/PIV-vless-default-bad-config-20261028T151944Z-001/probe.json | proxy_json routing.outbound_kind=vless outbound.kind=vless; workload_error=eof; classification=E_EXPECTED_CONFIG_REJECT; reference closed the session on the negative case …; 限定：正向路径不通时本格仅证明无静默成功，不独立证明认证拒绝语义 |
| VlessVision/Handshake | PASS | CrateDirect | ProtocolWire | PIV-vless-vless-vision-handshake-20261025T193038Z-001 | NONE | up=1B down=1B | evidence/vless/vless-vision/handshake/PIV-vless-vless-vision-handshake-20261025T193038Z-001/probe.json | vision_commands=["continue"]; target_stats={"tcp_bytes_down":2,"tcp_bytes_up":2,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} …; crate 级，产品 splice 未实现 |
| VlessVision/TcpSmall | PASS | CrateDirect | ProtocolWire | PIV-vless-vless-vision-tcp-small-20261025T193041Z-001 | NONE | up=65536B down=65536B | evidence/vless/vless-vision/tcp-small/PIV-vless-vless-vision-tcp-small-20261025T193041Z-001/probe.json | vision_commands=["continue", "continue", "end"]; target_stats={"tcp_bytes_down":65537,"tcp_bytes_up":65537,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} …; crate 级，产品 splice 未实现 |

## Anytls

> **verdict=VERIFIED / claim=USABLE**（scope=FULL，root_cause_class=NONE）
>
> 本节任一 PASS 不改变协议 verdict；单格 PASS 只在所列 carrier/scope 下成立。
> PaddingDiag 为诊断格，不参与 verdict。
> AnyTLS：session 池/心跳定时器/padding 写路径未单独验。

| Cell | 状态 | carrier | scope | evidence_id | class | 关键数字 | 证据路径 | notes |
|---|---|---|---|---|---|---|---|---|
| Default/Handshake | PASS | ProductSocks5 | ProductPath | PIV-anytls-default-handshake-20261028T151554Z-001 | NONE | up=1B down=1B | evidence/anytls/default/handshake/PIV-anytls-default-handshake-20261028T151554Z-001/probe.json | proxy_json routing.outbound_kind=anytls outbound.kind=anytls; target_stats={"tcp_bytes_down":2,"tcp_bytes_up":2,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} … |
| Default/TcpSmall | PASS | ProductSocks5 | ProductPath | PIV-anytls-default-tcp-small-20261028T151557Z-001 | NONE | up=65536B down=65536B | evidence/anytls/default/tcp-small/PIV-anytls-default-tcp-small-20261028T151557Z-001/probe.json | proxy_json routing.outbound_kind=anytls outbound.kind=anytls; target_stats={"tcp_bytes_down":65537,"tcp_bytes_up":65537,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} … |
| Default/TcpThroughput | PASS | ProductSocks5 | ProductPath | PIV-anytls-default-tcp-throughput-20261028T151600Z-001 | NONE | median=369453205B/s samples=3 | evidence/anytls/default/tcp-throughput/PIV-anytls-default-tcp-throughput-20261028T151600Z-001/probe.json | proxy_json routing.outbound_kind=anytls outbound.kind=anytls; target_stats={"tcp_bytes_down":101716128,"tcp_bytes_up":101712896,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} … |
| Default/LongLived | PASS | ProductSocks5 | ProductPath | PIV-anytls-default-long-lived-20261028T151608Z-001 | NONE | heartbeats=12 | evidence/anytls/default/long-lived/PIV-anytls-default-long-lived-20261028T151608Z-001/probe.json | proxy_json routing.outbound_kind=anytls outbound.kind=anytls; target_stats={"tcp_bytes_down":13,"tcp_bytes_up":13,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} … |
| Default/Reconnect | PASS | ProductSocks5 | ProductPath | PIV-anytls-default-reconnect-20261028T151801Z-001 | NONE | reconnects=3 | evidence/anytls/default/reconnect/PIV-anytls-default-reconnect-20261028T151801Z-001/probe.json | proxy_json routing.outbound_kind=anytls outbound.kind=anytls; target_stats={"tcp_bytes_down":4,"tcp_bytes_up":4,"tcp_connections":4,"udp_bytes":0,"udp_datagrams":0} … |
| Default/PaddingDiag | PASS | ProductSocks5 | ProductPath | PIV-anytls-default-padding-diag-20261025T193313Z-001 | NONE | up=0B down=0B | evidence/anytls/default/padding-diag/PIV-anytls-default-padding-diag-20261025T193313Z-001/probe.json | proxy_json routing.outbound_kind=anytls outbound.kind=anytls; serversettings_inferred; target_stats={"tcp_bytes_down":1,"tcp_bytes_up":1,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} …; 诊断格，不参与 verdict |
| Default/UdpEcho | PASS | ProductSocks5 | ProductPath | PIV-anytls-default-udp-echo-20261028T151826Z-001 | NONE | udp 1000/1000 corrupt=0 | evidence/anytls/default/udp-echo/PIV-anytls-default-udp-echo-20261028T151826Z-001/probe.json | bnd=127.0.0.1:42078; proxy_json verdict=PASS routing.flows[0].outbound_kind=anytls udp.datagrams_in=1000 udp.datagrams_out=1000 udp.send_failed=0; udp sent=1000 received=1000 corrupt=0; udp_seq_and_hash_ok …; 产品级（ProductSocks5） |
| Default/UdpEchoCrate | PASS | CrateDirect | ProtocolWire | PIV-anytls-default-udp-echo-crate-20261028T151833Z-001 | NONE | up=512000B down=512000B | evidence/anytls/default/udp-echo-crate/PIV-anytls-default-udp-echo-crate-20261028T151833Z-001/probe.json | udp_seq_and_hash_ok; target_stats={"tcp_bytes_down":0,"tcp_bytes_up":0,"tcp_connections":0,"udp_bytes":512064,"udp_datagrams":1001} …; 诊断格，不参与 verdict |
| Default/BadCredential | PASS | ProductSocks5 | ProductPath | PIV-anytls-default-bad-credential-20261028T151808Z-001 | E_EXPECTED_AUTH_REJECT | up=0B down=0B | evidence/anytls/default/bad-credential/PIV-anytls-default-bad-credential-20261028T151808Z-001/probe.json | proxy_error=ConnectivityEstablishmentFailed { provider: ProviderId("ref"), reason: "anytls session handshake failed: anytls io error" }; workload_error=read: Connection reset by peer (os error 104) … |
| AnyTlsCustomPadding/BadConfig | PASS | ProductSocks5 | ProductPath | PIV-anytls-anytls-custom-padding-bad-config-20261028T151811Z-001 | E_EXPECTED_CONFIG_REJECT | up=0B down=0B | evidence/anytls/anytls-custom-padding/bad-config/PIV-anytls-anytls-custom-padding-bad-config-20261028T151811Z-001/probe.json | proxy_error=ConnectivityEstablishmentFailed { provider: ProviderId("ref"), reason: "anytls session handshake failed: anytls server requested padding scheme update" } … |

## Hysteria2

> **verdict=PARTIAL / claim=USABLE_WITH_GAPS**（scope=PROTOCOL_SUBSET，root_cause_class=E_NEXUS_NOT_IMPLEMENTED）
>
> 本节任一 PASS 不改变协议 verdict；单格 PASS 只在所列 carrier/scope 下成立。
> QpackDiag 为诊断格，不参与 verdict。

| Cell | 状态 | carrier | scope | evidence_id | class | 关键数字 | 证据路径 | notes |
|---|---|---|---|---|---|---|---|---|
| Default/TcpSmall | PASS | ProductSocks5 | ProductPath | PIV-hysteria2-default-tcp-small-20261025T193400Z-001 | NONE | up=65536B down=65536B | evidence/hysteria2/default/tcp-small/PIV-hysteria2-default-tcp-small-20261025T193400Z-001/probe.json | proxy_json routing.outbound_kind=hysteria2 outbound.kind=hysteria2; target_stats={"tcp_bytes_down":65537,"tcp_bytes_up":65537,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} … |
| Default/TcpThroughput | PASS | ProductSocks5 | ProductPath | PIV-hysteria2-default-tcp-throughput-20261025T182240Z-001 | NONE | median=104614006B/s samples=3 | evidence/hysteria2/default/tcp-throughput/PIV-hysteria2-default-tcp-throughput-20261025T182240Z-001/probe.json | proxy_json routing.outbound_kind=hysteria2 outbound.kind=hysteria2; target_stats={"tcp_bytes_down":101716128,"tcp_bytes_up":101712896,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} … |
| Default/LongLived | PASS | ProductSocks5 | ProductPath | PIV-hysteria2-default-long-lived-20261025T193528Z-001 | NONE | heartbeats=12 | evidence/hysteria2/default/long-lived/PIV-hysteria2-default-long-lived-20261025T193528Z-001/probe.json | proxy_json routing.outbound_kind=hysteria2 outbound.kind=hysteria2; target_stats={"tcp_bytes_down":13,"tcp_bytes_up":13,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} … |
| Default/Reconnect | PASS | ProductSocks5 | ProductPath | PIV-hysteria2-default-reconnect-20261025T193745Z-001 | NONE | reconnects=3 | evidence/hysteria2/default/reconnect/PIV-hysteria2-default-reconnect-20261025T193745Z-001/probe.json | proxy_json routing.outbound_kind=hysteria2 outbound.kind=hysteria2; target_stats={"tcp_bytes_down":4,"tcp_bytes_up":4,"tcp_connections":4,"udp_bytes":0,"udp_datagrams":0} … |
| Default/Handshake | PASS | ProductSocks5 | ProductPath | PIV-hysteria2-default-handshake-20261025T193753Z-001 | NONE | up=1B down=1B | evidence/hysteria2/default/handshake/PIV-hysteria2-default-handshake-20261025T193753Z-001/probe.json | proxy_json routing.outbound_kind=hysteria2 outbound.kind=hysteria2; target_stats={"tcp_bytes_down":2,"tcp_bytes_up":2,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} … |
| Hy2Salamander/Handshake | PASS | ProductSocks5 | ProductPath | PIV-hysteria2-hy2-salamander-handshake-20261025T193758Z-001 | NONE | up=1B down=1B | evidence/hysteria2/hy2-salamander/handshake/PIV-hysteria2-hy2-salamander-handshake-20261025T193758Z-001/probe.json | proxy_json routing.outbound_kind=hysteria2 outbound.kind=hysteria2; target_stats={"tcp_bytes_down":2,"tcp_bytes_up":2,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} … |
| Hy2Salamander/TcpSmall | PASS | ProductSocks5 | ProductPath | PIV-hysteria2-hy2-salamander-tcp-small-20261025T182802Z-001 | NONE | up=65536B down=65536B | evidence/hysteria2/hy2-salamander/tcp-small/PIV-hysteria2-hy2-salamander-tcp-small-20261025T182802Z-001/probe.json | proxy_json routing.outbound_kind=hysteria2 outbound.kind=hysteria2; target_stats={"tcp_bytes_down":65537,"tcp_bytes_up":65537,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} … |
| Default/QpackDiag | PASS | CrateDirect | ProtocolWire | PIV-hysteria2-default-qpack-diag-20261025T193804Z-001 | NONE | up=0B down=0B | evidence/hysteria2/default/qpack-diag/PIV-hysteria2-default-qpack-diag-20261025T193804Z-001/probe.json | qpack_diag_not_triggered=handshake_ok; hy2_error=null; hy2_auth_status=233; hy2_auth_status_source=connect_ok_after_decode_auth_response; hy2_udp_enabled=true; hy2_cc_rx=auto …; 诊断格，不参与 verdict |
| Default/UdpEcho | NOT_IMPLEMENTED | ProductSocks5 | ProductPath | PIV-hysteria2-default-udp-echo-20261028T151837Z-001 | E_NEXUS_NOT_IMPLEMENTED | udp 0/0 corrupt=0 | evidence/hysteria2/default/udp-echo/PIV-hysteria2-default-udp-echo-20261028T151837Z-001/probe.json | bnd=127.0.0.1:35755; proxy_json udp.unsupported_hysteria2=1 udp.sent=0 udp.dropped_unsupported=1; fail_closed=no_direct_no_reply; target_udp_baseline=1 target_udp_delta=0 …; 产品级（ProductSocks5） |
| Default/UdpEchoCrate | PASS | CrateDirect | ProtocolWire | PIV-hysteria2-default-udp-echo-crate-20261028T151841Z-001 | NONE | up=512000B down=512000B | evidence/hysteria2/default/udp-echo-crate/PIV-hysteria2-default-udp-echo-crate-20261028T151841Z-001/probe.json | udp_seq_and_hash_ok; target_stats={"tcp_bytes_down":0,"tcp_bytes_up":0,"tcp_connections":0,"udp_bytes":512064,"udp_datagrams":1001} …; 诊断格，不参与 verdict |
| Default/BadCredential | PASS | ProductSocks5 | ProductPath | PIV-hysteria2-default-bad-credential-20261025T193814Z-001 | E_EXPECTED_AUTH_REJECT | up=0B down=0B | evidence/hysteria2/default/bad-credential/PIV-hysteria2-default-bad-credential-20261025T193814Z-001/probe.json | proxy_error=ConnectivityEstablishmentFailed { provider: ProviderId("ref"), reason: "hysteria2 connect/auth 127.0.0.1:26103 failed: hysteria2 authentication failed" } …; 限定：正向路径被 CODEC 阻断时本格 PASS 仅证明无静默成功，不独立证明配置拒绝语义 |
| Default/BadConfig | PASS | ProductSocks5 | ProductPath | PIV-hysteria2-default-bad-config-20261025T193818Z-001 | E_EXPECTED_CONFIG_REJECT | up=0B down=0B | evidence/hysteria2/default/bad-config/PIV-hysteria2-default-bad-config-20261025T193818Z-001/probe.json | proxy_error=ConnectivityEstablishmentFailed { provider: ProviderId("ref"), reason: "hysteria2 connect/auth 127.0.0.1:26104 failed: hysteria2 timed out" }; workload_error=read: Connection reset by peer (os error 104) …; 限定：正向路径被 CODEC 阻断时本格 PASS 仅证明无静默成功，不独立证明配置拒绝语义 |

## Trojan

> **verdict=PARTIAL / claim=USABLE_WITH_GAPS**（scope=TCP_ONLY，root_cause_class=E_NEXUS_NOT_IMPLEMENTED）
>
> 本节任一 PASS 不改变协议 verdict；单格 PASS 只在所列 carrier/scope 下成立。

| Cell | 状态 | carrier | scope | evidence_id | class | 关键数字 | 证据路径 | notes |
|---|---|---|---|---|---|---|---|---|
| Default/Handshake | PASS | ProductSocks5 | ProductPath | PIV-trojan-default-handshake-20261025T193833Z-001 | NONE | up=1B down=1B | evidence/trojan/default/handshake/PIV-trojan-default-handshake-20261025T193833Z-001/probe.json | proxy_json routing.outbound_kind=trojan outbound.kind=trojan; target_stats={"tcp_bytes_down":2,"tcp_bytes_up":2,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} … |
| Default/TcpSmall | PASS | ProductSocks5 | ProductPath | PIV-trojan-default-tcp-small-20261025T193838Z-001 | NONE | up=65536B down=65536B | evidence/trojan/default/tcp-small/PIV-trojan-default-tcp-small-20261025T193838Z-001/probe.json | proxy_json routing.outbound_kind=trojan outbound.kind=trojan; target_stats={"tcp_bytes_down":65537,"tcp_bytes_up":65537,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} … |
| Default/TcpThroughput | PASS | ProductSocks5 | ProductPath | PIV-trojan-default-tcp-throughput-20261025T195102Z-001 | NONE | median=1368476078B/s samples=3 | evidence/trojan/default/tcp-throughput/PIV-trojan-default-tcp-throughput-20261025T195102Z-001/probe.json | proxy_json routing.outbound_kind=trojan outbound.kind=trojan; target_stats={"tcp_bytes_down":101716128,"tcp_bytes_up":101712896,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} … |
| Default/LongLived | PASS | ProductSocks5 | ProductPath | PIV-trojan-default-long-lived-20261025T193849Z-001 | NONE | heartbeats=12 | evidence/trojan/default/long-lived/PIV-trojan-default-long-lived-20261025T193849Z-001/probe.json | proxy_json routing.outbound_kind=trojan outbound.kind=trojan; target_stats={"tcp_bytes_down":13,"tcp_bytes_up":13,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} … |
| Default/Reconnect | PASS | ProductSocks5 | ProductPath | PIV-trojan-default-reconnect-20261025T194043Z-001 | NONE | reconnects=3 | evidence/trojan/default/reconnect/PIV-trojan-default-reconnect-20261025T194043Z-001/probe.json | proxy_json routing.outbound_kind=trojan outbound.kind=trojan; target_stats={"tcp_bytes_down":4,"tcp_bytes_up":4,"tcp_connections":4,"udp_bytes":0,"udp_datagrams":0} … |
| Default/UdpEcho | NOT_IMPLEMENTED | ProductSocks5 | ProductPath | PIV-trojan-default-udp-echo-20261028T151845Z-001 | E_NEXUS_NOT_IMPLEMENTED | udp 0/0 corrupt=0 | evidence/trojan/default/udp-echo/PIV-trojan-default-udp-echo-20261028T151845Z-001/probe.json | bnd=127.0.0.1:44098; proxy_json udp.unsupported_trojan=1 udp.sent=0 udp.dropped_unsupported=1; fail_closed=no_direct_no_reply; target_udp_baseline=1 target_udp_delta=0 …; 产品级（ProductSocks5） |
| Default/UdpEchoCrate | NOT_IMPLEMENTED | CrateDirect | ProtocolWire | PIV-trojan-default-udp-echo-crate-20261028T151848Z-001 | E_NEXUS_NOT_IMPLEMENTED | up=0B down=0B | evidence/trojan/default/udp-echo-crate/PIV-trojan-default-udp-echo-crate-20261028T151848Z-001/probe.json | Trojan UDP 路径未实现（crate 直调无 UDP 帧 API；产品入口见 UdpEcho 行）; 诊断格，不参与 verdict |
| Default/BadCredential | PASS | ProductSocks5 | ProductPath | PIV-trojan-default-bad-credential-20261025T194052Z-001 | E_EXPECTED_AUTH_REJECT | up=0B down=0B | evidence/trojan/default/bad-credential/PIV-trojan-default-bad-credential-20261025T194052Z-001/probe.json | proxy_error=ConnectivityEstablishmentFailed { provider: ProviderId("ref"), reason: "tunnel closed before ready: waited_ms=11 first_bytes_hex= dest_port=26200" }; socks5_rep=1; tunnel_bytes_to_client=0 … |
| TrojanFallback/BadCredential | PASS | ProductSocks5 | ProductPath | PIV-trojan-trojan-fallback-bad-credential-20261025T194055Z-001 | E_EXPECTED_AUTH_REJECT | up=0B down=0B | evidence/trojan/trojan-fallback/bad-credential/PIV-trojan-trojan-fallback-bad-credential-20261025T194055Z-001/probe.json | proxy_error=ConnectivityEstablishmentFailed { provider: ProviderId("ref"), reason: "trojan fallback signature detected: waited_ms=6 first_bytes_hex=485454502f312e3120343034204e6f74 dest_port=26200" }; socks5_rep=1 … |
| Default/BadConfig | NOT_APPLICABLE | CrateDirect | ProtocolWire | PIV-trojan-default-bad-config-20261025T194057Z-001 | NONE | up=0B down=0B | evidence/trojan/default/bad-config/PIV-trojan-default-bad-config-20261025T194057Z-001/probe.json | Trojan BadConfig 在 Nexus 出站配置面不可表达 |

## Shadowsocks

> **verdict=PARTIAL / claim=USABLE_WITH_GAPS**（scope=TCP_ONLY，root_cause_class=E_NEXUS_NOT_IMPLEMENTED）
>
> 本节任一 PASS 不改变协议 verdict；单格 PASS 只在所列 carrier/scope 下成立。

| Cell | 状态 | carrier | scope | evidence_id | class | 关键数字 | 证据路径 | notes |
|---|---|---|---|---|---|---|---|---|
| Default/Handshake | PASS | ProductSocks5 | ProductPath | PIV-shadowsocks-default-handshake-20261025T194100Z-001 | NONE | up=1B down=1B | evidence/shadowsocks/default/handshake/PIV-shadowsocks-default-handshake-20261025T194100Z-001/probe.json | proxy_json routing.outbound_kind=shadowsocks outbound.kind=shadowsocks; target_stats={"tcp_bytes_down":2,"tcp_bytes_up":2,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} … |
| Default/TcpSmall | PASS | ProductSocks5 | ProductPath | PIV-shadowsocks-default-tcp-small-20261025T194104Z-001 | NONE | up=65536B down=65536B | evidence/shadowsocks/default/tcp-small/PIV-shadowsocks-default-tcp-small-20261025T194104Z-001/probe.json | proxy_json routing.outbound_kind=shadowsocks outbound.kind=shadowsocks; target_stats={"tcp_bytes_down":65537,"tcp_bytes_up":65537,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} … |
| Default/TcpThroughput | PASS | ProductSocks5 | ProductPath | PIV-shadowsocks-default-tcp-throughput-20261025T194107Z-001 | NONE | median=56883702B/s samples=3 | evidence/shadowsocks/default/tcp-throughput/PIV-shadowsocks-default-tcp-throughput-20261025T194107Z-001/probe.json | proxy_json routing.outbound_kind=shadowsocks outbound.kind=shadowsocks; target_stats={"tcp_bytes_down":101716128,"tcp_bytes_up":101712896,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} … |
| Default/LongLived | PASS | ProductSocks5 | ProductPath | PIV-shadowsocks-default-long-lived-20261025T194141Z-001 | NONE | heartbeats=12 | evidence/shadowsocks/default/long-lived/PIV-shadowsocks-default-long-lived-20261025T194141Z-001/probe.json | proxy_json routing.outbound_kind=shadowsocks outbound.kind=shadowsocks; target_stats={"tcp_bytes_down":13,"tcp_bytes_up":13,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} … |
| Default/Reconnect | PASS | ProductSocks5 | ProductPath | PIV-shadowsocks-default-reconnect-20261025T194338Z-001 | NONE | reconnects=3 | evidence/shadowsocks/default/reconnect/PIV-shadowsocks-default-reconnect-20261025T194338Z-001/probe.json | proxy_json routing.outbound_kind=shadowsocks outbound.kind=shadowsocks; target_stats={"tcp_bytes_down":4,"tcp_bytes_up":4,"tcp_connections":4,"udp_bytes":0,"udp_datagrams":0} … |
| Default/UdpEcho | NOT_IMPLEMENTED | ProductSocks5 | ProductPath | PIV-shadowsocks-default-udp-echo-20261028T151850Z-001 | E_NEXUS_NOT_IMPLEMENTED | udp 0/0 corrupt=0 | evidence/shadowsocks/default/udp-echo/PIV-shadowsocks-default-udp-echo-20261028T151850Z-001/probe.json | bnd=127.0.0.1:51734; proxy_json udp.unsupported_shadowsocks=1 udp.sent=0 udp.dropped_unsupported=1; fail_closed=no_direct_no_reply; target_udp_baseline=1 target_udp_delta=0 …; 产品级（ProductSocks5） |
| Default/UdpEchoCrate | NOT_IMPLEMENTED | CrateDirect | ProtocolWire | PIV-shadowsocks-default-udp-echo-crate-20261028T151853Z-001 | E_NEXUS_NOT_IMPLEMENTED | up=0B down=0B | evidence/shadowsocks/default/udp-echo-crate/PIV-shadowsocks-default-udp-echo-crate-20261028T151853Z-001/probe.json | Shadowsocks UDP 路径未实现（crate 直调无 UDP 帧 API；产品入口见 UdpEcho 行）; 诊断格，不参与 verdict |
| Default/BadCredential | PASS | ProductSocks5 | ProductPath | PIV-shadowsocks-default-bad-credential-20261025T194352Z-001 | E_EXPECTED_AUTH_REJECT | up=0B down=0B | evidence/shadowsocks/default/bad-credential/PIV-shadowsocks-default-bad-credential-20261025T194352Z-001/probe.json | proxy_json routing.outbound_kind=shadowsocks outbound.kind=shadowsocks; workload_error=eof; classification=E_EXPECTED_AUTH_REJECT; reference closed the session on the negative case …; 限定：正向路径不通时本格仅证明无静默成功，不独立证明认证拒绝语义 |
| Default/BadConfig | PASS | ProductSocks5 | ProductPath | PIV-shadowsocks-default-bad-config-20261025T194359Z-001 | E_EXPECTED_CONFIG_REJECT | up=0B down=0B | evidence/shadowsocks/default/bad-config/PIV-shadowsocks-default-bad-config-20261025T194359Z-001/probe.json | proxy_json routing.outbound_kind=shadowsocks outbound.kind=shadowsocks; workload_error=eof; classification=E_EXPECTED_CONFIG_REJECT; reference closed the session on the negative case …; 限定：正向路径不通时本格仅证明无静默成功，不独立证明认证拒绝语义 |

## 产品级 UDP（不参与协议 verdict）

产品 SOCKS5 UDP ASSOCIATE 入口与出站帧路径按协议分别取证：`UdpEcho` 为产品级 required 格，`UdpEchoCrate` 为 crate 级诊断格（不参与 verdict）。已可用（产品级 `UdpEcho` PASS）：Vless、Anytls；仍为 `NOT_IMPLEMENTED`/未通过：Hysteria2、Trojan、Shadowsocks（出站无 UDP 帧路径，按 fail-closed 丢弃，不直连）。

**区分**：本项指产品 SOCKS5 UDP relay 入口/出站帧路径，不等于所有 UDP/QUIC 路径不可用——Hy2 出站到代理服务器仍走 QUIC/UDP 传输。

## 产品能力缺口

- 产品级 UDP：Trojan/Shadowsocks/Hysteria2 出站未接线（VLESS flow=None / AnyTLS UoT 已可用，见上节）。
- Vision：产品路径只编码 addon，不实现 splice；本 run 的 Vision 结论来自 crate 直调。
- Hysteria2：端口跳跃/Brutal/gecko/分片不在范围。
- AnyTLS：session 池/心跳定时器/padding 写路径不单独验。
- Trojan：success **之后**才到达的 fallback 首包不可判定（R-1/R-2 承诺边界，见 notes/trojan-fallback.md）；signature 模式的非 HTTP fallback 漏报（R-3）。
- nexusd TUN / ProxyEngine 路径的 fallback fail-open 与 UDP 能力不在本 run 覆盖内（R-5/Q2）。
- R-7：main.rs 串行 accept 模型下 UDP 关联单进程有效并发 = 1（`MAX_UDP_ASSOCIATIONS=128` 不可达）。

## fix 支线与复验

本 run 产生 verdict 翻转的修复条目（来源：run-meta）：

- **产品级 UDP（VLESS flow=None / AnyTLS UoT）**（commit `e8f3fe78`）：UdpEcho 证据面从 crate 级改为产品级（ProductSocks5/ProductPath）；VLESS/AnyTLS 产品 UDP 1000/1000 往返 PASS（evidence/vless/default/udp-echo/；evidence/anytls/default/udp-echo/）
- **crate 级 UDP 证据分离（UdpEchoCrate diag）**（commit `3e132e87`）：保留 crate 级证据为 diag 格（不参与 verdict）：VLESS/AnyTLS/Hy2 crate PASS，Trojan/SS NOT_IMPLEMENTED（evidence/*/default/udp-echo-crate/）

根因文档位于仓库 `docs/protocols/interop/fix/`；本 run 证据根为 `/home/appen/pipeline-runs/protocol-interop-fixes-6/evidence-run`，上表 cell 证据路径均相对该目录。

## 附录 A：配置索引

| 文件 | sha256 |
|---|---|
| evidence/ref-config/anytls-custom-padding.json | 7ff455595bf998535a8284d1d369610ac6b90b74db2888380c0358f039ece797 |
| evidence/ref-config/anytls.json | 83373be4b02d291a82439442bccf201a4501a0957b86085649d26c68511affa4 |
| evidence/ref-config/hysteria2-plain.json | 557666fafafbc9cb776e2aa854b9e29b8dfd9fd7191b8d5770dc29e5259baf12 |
| evidence/ref-config/hysteria2-salamander.json | 29d962f97dbc9e57558413ce04bae231ef22355c313ad5cd657dc2cdd2b5c18c |
| evidence/ref-config/shadowsocks-aes256gcm.json | db4df2bbd2a99d9b97397a5eb717deaedb081f70bf172f7019f4c146bda14d7d |
| evidence/ref-config/shadowsocks.json | 6a631d9202fdcdada55bda79cf1baa2b9f4dd85bf63d6e20a408fa4a15eb6d7b |
| evidence/ref-config/trojan-fallback.json | 8f44cd7b8702b60d1e4155efab9bd60228cf76ccf146b517ed8b908f050ff66a |
| evidence/ref-config/trojan.json | 34e3dfecf3f5822104d486cbf9819fa9ebfa1fb3eac0f102074c8b7c2377acef |
| evidence/ref-config/vless-basic-flow-mismatch.json | e0adaa990beba711264dc00ebed373f93db03f8fe0548453109a6385495a0973 |
| evidence/ref-config/vless-basic.json | d0979a17cccabb5dc7ba4835dc453f6f15b0f908bb6c9c28872eb4a32307811b |
| evidence/ref-config/vless-vision.json | e0a83dad9c49a294f89ea8499523b5c4eedb019c9931d73da6020168ef964c7e |
| evidence/ref-config/xray-vless-basic.json | 7e422870dac4bace1c8c05711848a8e0faeb67458a6dacb4be019ea35c54afa3 |
| evidence/ref-config/xray-vless-vision.json | 5593cbb711db4ed12964b67fd6ce56d90c46509a6375ba2f5664eff52951ca38 |

## 附录 B：证据清单

| evidence_id | verdict | carrier | scope | 路径 |
|---|---|---|---|---|
| PIV-anytls-anytls-custom-padding-bad-config-20261028T151811Z-001 | PASS | ProductSocks5 | ProductPath | evidence/anytls/anytls-custom-padding/bad-config/PIV-anytls-anytls-custom-padding-bad-config-20261028T151811Z-001/probe.json |
| PIV-anytls-default-bad-credential-20261028T151808Z-001 | PASS | ProductSocks5 | ProductPath | evidence/anytls/default/bad-credential/PIV-anytls-default-bad-credential-20261028T151808Z-001/probe.json |
| PIV-anytls-default-handshake-20261028T151554Z-001 | PASS | ProductSocks5 | ProductPath | evidence/anytls/default/handshake/PIV-anytls-default-handshake-20261028T151554Z-001/probe.json |
| PIV-anytls-default-long-lived-20261028T151608Z-001 | PASS | ProductSocks5 | ProductPath | evidence/anytls/default/long-lived/PIV-anytls-default-long-lived-20261028T151608Z-001/probe.json |
| PIV-anytls-default-padding-diag-20261025T193313Z-001 | PASS | ProductSocks5 | ProductPath | evidence/anytls/default/padding-diag/PIV-anytls-default-padding-diag-20261025T193313Z-001/probe.json |
| PIV-anytls-default-reconnect-20261028T151801Z-001 | PASS | ProductSocks5 | ProductPath | evidence/anytls/default/reconnect/PIV-anytls-default-reconnect-20261028T151801Z-001/probe.json |
| PIV-anytls-default-tcp-small-20261028T151557Z-001 | PASS | ProductSocks5 | ProductPath | evidence/anytls/default/tcp-small/PIV-anytls-default-tcp-small-20261028T151557Z-001/probe.json |
| PIV-anytls-default-tcp-throughput-20261028T151600Z-001 | PASS | ProductSocks5 | ProductPath | evidence/anytls/default/tcp-throughput/PIV-anytls-default-tcp-throughput-20261028T151600Z-001/probe.json |
| PIV-anytls-default-udp-echo-20261028T151826Z-001 | PASS | ProductSocks5 | ProductPath | evidence/anytls/default/udp-echo/PIV-anytls-default-udp-echo-20261028T151826Z-001/probe.json |
| PIV-anytls-default-udp-echo-crate-20261028T151833Z-001 | PASS | CrateDirect | ProtocolWire | evidence/anytls/default/udp-echo-crate/PIV-anytls-default-udp-echo-crate-20261028T151833Z-001/probe.json |
| PIV-hysteria2-default-bad-config-20261025T193818Z-001 | PASS | ProductSocks5 | ProductPath | evidence/hysteria2/default/bad-config/PIV-hysteria2-default-bad-config-20261025T193818Z-001/probe.json |
| PIV-hysteria2-default-bad-credential-20261025T193814Z-001 | PASS | ProductSocks5 | ProductPath | evidence/hysteria2/default/bad-credential/PIV-hysteria2-default-bad-credential-20261025T193814Z-001/probe.json |
| PIV-hysteria2-default-handshake-20261025T193753Z-001 | PASS | ProductSocks5 | ProductPath | evidence/hysteria2/default/handshake/PIV-hysteria2-default-handshake-20261025T193753Z-001/probe.json |
| PIV-hysteria2-default-long-lived-20261025T193528Z-001 | PASS | ProductSocks5 | ProductPath | evidence/hysteria2/default/long-lived/PIV-hysteria2-default-long-lived-20261025T193528Z-001/probe.json |
| PIV-hysteria2-default-qpack-diag-20261025T193804Z-001 | PASS | CrateDirect | ProtocolWire | evidence/hysteria2/default/qpack-diag/PIV-hysteria2-default-qpack-diag-20261025T193804Z-001/probe.json |
| PIV-hysteria2-default-reconnect-20261025T193745Z-001 | PASS | ProductSocks5 | ProductPath | evidence/hysteria2/default/reconnect/PIV-hysteria2-default-reconnect-20261025T193745Z-001/probe.json |
| PIV-hysteria2-default-tcp-small-20261025T193400Z-001 | PASS | ProductSocks5 | ProductPath | evidence/hysteria2/default/tcp-small/PIV-hysteria2-default-tcp-small-20261025T193400Z-001/probe.json |
| PIV-hysteria2-default-tcp-throughput-20261025T182240Z-001 | PASS | ProductSocks5 | ProductPath | evidence/hysteria2/default/tcp-throughput/PIV-hysteria2-default-tcp-throughput-20261025T182240Z-001/probe.json |
| PIV-hysteria2-default-udp-echo-20261028T151837Z-001 | NOT_IMPLEMENTED | ProductSocks5 | ProductPath | evidence/hysteria2/default/udp-echo/PIV-hysteria2-default-udp-echo-20261028T151837Z-001/probe.json |
| PIV-hysteria2-default-udp-echo-crate-20261028T151841Z-001 | PASS | CrateDirect | ProtocolWire | evidence/hysteria2/default/udp-echo-crate/PIV-hysteria2-default-udp-echo-crate-20261028T151841Z-001/probe.json |
| PIV-hysteria2-hy2-salamander-handshake-20261025T193758Z-001 | PASS | ProductSocks5 | ProductPath | evidence/hysteria2/hy2-salamander/handshake/PIV-hysteria2-hy2-salamander-handshake-20261025T193758Z-001/probe.json |
| PIV-hysteria2-hy2-salamander-tcp-small-20261025T182802Z-001 | PASS | ProductSocks5 | ProductPath | evidence/hysteria2/hy2-salamander/tcp-small/PIV-hysteria2-hy2-salamander-tcp-small-20261025T182802Z-001/probe.json |
| PIV-shadowsocks-default-bad-config-20261025T194359Z-001 | PASS | ProductSocks5 | ProductPath | evidence/shadowsocks/default/bad-config/PIV-shadowsocks-default-bad-config-20261025T194359Z-001/probe.json |
| PIV-shadowsocks-default-bad-credential-20261025T194352Z-001 | PASS | ProductSocks5 | ProductPath | evidence/shadowsocks/default/bad-credential/PIV-shadowsocks-default-bad-credential-20261025T194352Z-001/probe.json |
| PIV-shadowsocks-default-handshake-20261025T194100Z-001 | PASS | ProductSocks5 | ProductPath | evidence/shadowsocks/default/handshake/PIV-shadowsocks-default-handshake-20261025T194100Z-001/probe.json |
| PIV-shadowsocks-default-long-lived-20261025T194141Z-001 | PASS | ProductSocks5 | ProductPath | evidence/shadowsocks/default/long-lived/PIV-shadowsocks-default-long-lived-20261025T194141Z-001/probe.json |
| PIV-shadowsocks-default-reconnect-20261025T194338Z-001 | PASS | ProductSocks5 | ProductPath | evidence/shadowsocks/default/reconnect/PIV-shadowsocks-default-reconnect-20261025T194338Z-001/probe.json |
| PIV-shadowsocks-default-tcp-small-20261025T194104Z-001 | PASS | ProductSocks5 | ProductPath | evidence/shadowsocks/default/tcp-small/PIV-shadowsocks-default-tcp-small-20261025T194104Z-001/probe.json |
| PIV-shadowsocks-default-tcp-throughput-20261025T194107Z-001 | PASS | ProductSocks5 | ProductPath | evidence/shadowsocks/default/tcp-throughput/PIV-shadowsocks-default-tcp-throughput-20261025T194107Z-001/probe.json |
| PIV-shadowsocks-default-udp-echo-20261028T151850Z-001 | NOT_IMPLEMENTED | ProductSocks5 | ProductPath | evidence/shadowsocks/default/udp-echo/PIV-shadowsocks-default-udp-echo-20261028T151850Z-001/probe.json |
| PIV-shadowsocks-default-udp-echo-crate-20261028T151853Z-001 | NOT_IMPLEMENTED | CrateDirect | ProtocolWire | evidence/shadowsocks/default/udp-echo-crate/PIV-shadowsocks-default-udp-echo-crate-20261028T151853Z-001/probe.json |
| PIV-trojan-default-bad-config-20261025T194057Z-001 | NOT_APPLICABLE | CrateDirect | ProtocolWire | evidence/trojan/default/bad-config/PIV-trojan-default-bad-config-20261025T194057Z-001/probe.json |
| PIV-trojan-default-bad-credential-20261025T194052Z-001 | PASS | ProductSocks5 | ProductPath | evidence/trojan/default/bad-credential/PIV-trojan-default-bad-credential-20261025T194052Z-001/probe.json |
| PIV-trojan-default-handshake-20261025T193833Z-001 | PASS | ProductSocks5 | ProductPath | evidence/trojan/default/handshake/PIV-trojan-default-handshake-20261025T193833Z-001/probe.json |
| PIV-trojan-default-long-lived-20261025T193849Z-001 | PASS | ProductSocks5 | ProductPath | evidence/trojan/default/long-lived/PIV-trojan-default-long-lived-20261025T193849Z-001/probe.json |
| PIV-trojan-default-reconnect-20261025T194043Z-001 | PASS | ProductSocks5 | ProductPath | evidence/trojan/default/reconnect/PIV-trojan-default-reconnect-20261025T194043Z-001/probe.json |
| PIV-trojan-default-tcp-small-20261025T193838Z-001 | PASS | ProductSocks5 | ProductPath | evidence/trojan/default/tcp-small/PIV-trojan-default-tcp-small-20261025T193838Z-001/probe.json |
| PIV-trojan-default-tcp-throughput-20261025T195102Z-001 | PASS | ProductSocks5 | ProductPath | evidence/trojan/default/tcp-throughput/PIV-trojan-default-tcp-throughput-20261025T195102Z-001/probe.json |
| PIV-trojan-default-udp-echo-20261028T151845Z-001 | NOT_IMPLEMENTED | ProductSocks5 | ProductPath | evidence/trojan/default/udp-echo/PIV-trojan-default-udp-echo-20261028T151845Z-001/probe.json |
| PIV-trojan-default-udp-echo-crate-20261028T151848Z-001 | NOT_IMPLEMENTED | CrateDirect | ProtocolWire | evidence/trojan/default/udp-echo-crate/PIV-trojan-default-udp-echo-crate-20261028T151848Z-001/probe.json |
| PIV-trojan-trojan-fallback-bad-credential-20261025T194055Z-001 | PASS | ProductSocks5 | ProductPath | evidence/trojan/trojan-fallback/bad-credential/PIV-trojan-trojan-fallback-bad-credential-20261025T194055Z-001/probe.json |
| PIV-vless-default-bad-config-20261028T151944Z-001 | PASS | ProductSocks5 | ProductPath | evidence/vless/default/bad-config/PIV-vless-default-bad-config-20261028T151944Z-001/probe.json |
| PIV-vless-default-bad-credential-20261028T151547Z-001 | PASS | ProductSocks5 | ProductPath | evidence/vless/default/bad-credential/PIV-vless-default-bad-credential-20261028T151547Z-001/probe.json |
| PIV-vless-default-handshake-20261028T151326Z-001 | PASS | ProductSocks5 | ProductPath | evidence/vless/default/handshake/PIV-vless-default-handshake-20261028T151326Z-001/probe.json |
| PIV-vless-default-long-lived-20261028T151346Z-001 | PASS | ProductSocks5 | ProductPath | evidence/vless/default/long-lived/PIV-vless-default-long-lived-20261028T151346Z-001/probe.json |
| PIV-vless-default-reconnect-20261028T151539Z-001 | PASS | ProductSocks5 | ProductPath | evidence/vless/default/reconnect/PIV-vless-default-reconnect-20261028T151539Z-001/probe.json |
| PIV-vless-default-tcp-small-20261028T151333Z-001 | PASS | ProductSocks5 | ProductPath | evidence/vless/default/tcp-small/PIV-vless-default-tcp-small-20261028T151333Z-001/probe.json |
| PIV-vless-default-tcp-throughput-20261028T151340Z-001 | PASS | ProductSocks5 | ProductPath | evidence/vless/default/tcp-throughput/PIV-vless-default-tcp-throughput-20261028T151340Z-001/probe.json |
| PIV-vless-default-udp-echo-20261028T151815Z-001 | PASS | ProductSocks5 | ProductPath | evidence/vless/default/udp-echo/PIV-vless-default-udp-echo-20261028T151815Z-001/probe.json |
| PIV-vless-default-udp-echo-crate-20261028T151822Z-001 | PASS | CrateDirect | ProtocolWire | evidence/vless/default/udp-echo-crate/PIV-vless-default-udp-echo-crate-20261028T151822Z-001/probe.json |
| PIV-vless-vless-vision-handshake-20261025T193038Z-001 | PASS | CrateDirect | ProtocolWire | evidence/vless/vless-vision/handshake/PIV-vless-vless-vision-handshake-20261025T193038Z-001/probe.json |
| PIV-vless-vless-vision-tcp-small-20261025T193041Z-001 | PASS | CrateDirect | ProtocolWire | evidence/vless/vless-vision/tcp-small/PIV-vless-vless-vision-tcp-small-20261025T193041Z-001/probe.json |

## 附录 C：命令与端口

```bash
scripts/interop/run-matrix.sh --protocol <p> --variant <v> --cell <c> \
  --run-dir /home/appen/pipeline-runs/protocol-interop-fixes-6/evidence-run \
  --probe-bin $CARGO_TARGET_DIR/debug/examples/protocol_interop_probe \
  --ref-bin $RUN_DIR/ref/sing-box-1.13.16-linux-amd64-musl/sing-box
python3 scripts/interop/recompute-verdicts.py --run-dir /home/appen/pipeline-runs/protocol-interop-fixes-6/evidence-run \
  --run-meta /home/appen/pipeline-runs/protocol-interop-fixes-6/evidence-run/analysis/run-meta.json \
  --matrix docs/protocols/interop/MATRIX.md --check
```

- 参照端口：vless 26100/26101、anytls 26102、hysteria2 26103/26104、
  trojan 26105/26115、shadowsocks 26106、xray 26108/26109。
- 目标端口：26200 echo / 26201 sink+source / 26202 udp / 26203 http fallback。
- 抓包：dumpcap -P（pcap），T2 用 `-a filesize:102400` 封顶 100 MiB。

## 附录 D：终局 T2 证据构建来源

| 协议 | evidence_id | nexus.commit | cargo_target_dir | binary_sha256 |
|---|---|---|---|---|
| Vless | PIV-vless-default-tcp-throughput-20261028T151340Z-001 | e1bb2770074b533bbe6ddba7dd37f5a1426d312f | /work/wt-fixes6-p1-dev/target | a789b2fc53e325d92ef73184268581b656f85785d1055dc52e362e17dfda903e |
| Anytls | PIV-anytls-default-tcp-throughput-20261028T151600Z-001 | e1bb2770074b533bbe6ddba7dd37f5a1426d312f | /work/wt-fixes6-p1-dev/target | a789b2fc53e325d92ef73184268581b656f85785d1055dc52e362e17dfda903e |
| Hysteria2 | PIV-hysteria2-default-tcp-throughput-20261025T182240Z-001 | 4b4de3059baa975dc82955735ef81759402b5ca8 | /work/wt-protocol-interop-fixes-7/target | 139dd86868c55744b0218833a6714a67b36c84d225d3902abf4da7a07275b960 |
| Trojan | PIV-trojan-default-tcp-throughput-20261025T195102Z-001 | 779595540c4310aa3b61ffd9c8986f7c6e1013ef | /work/nexus-dev/target | b51a52726cd22320c447687cae6ab1a3b6b0fa4d854926199dc81d7986f3ed66 |
| Shadowsocks | PIV-shadowsocks-default-tcp-throughput-20261025T194107Z-001 | 087b0dd29b1d327317b507d431c429552d367e51 | /work/wt-protocol-interop-fixes-5/target | b51a52726cd22320c447687cae6ab1a3b6b0fa4d854926199dc81d7986f3ed66 |

上表逐格给出各 T2 证据绑定的构建提交、目标目录与二进制哈希；按证据 `nexus.commit` 派生：`087b0dd29b1d327317b507d431c429552d367e51`（Shadowsocks）；`4b4de3059baa975dc82955735ef81759402b5ca8`（Hysteria2）；`779595540c4310aa3b61ffd9c8986f7c6e1013ef`（Trojan）；`e1bb2770074b533bbe6ddba7dd37f5a1426d312f`（Vless、Anytls）。
构建均来自证据记录的本 worktree `cargo_target_dir`，不再引用前序 run 的 fix worktree。

## 附录 E：被替代运行

| evidence_id | 原结论 | 替代者 | 弃用理由 |
|---|---|---|---|
| PIV-hysteria2-default-tcp-throughput-20261025T193403Z-001 | Fail | PIV-hysteria2-default-tcp-throughput-20261025T182240Z-001 | 构建 commit 087b0dd2 不含 pump 修复 13f9a9b（祖先证明：git merge-base --is-ancestor 13f9a9b 087b0dd2 -> exit 1，非祖先；13f9a9b 为 4b4de30 祖先 -> exit 0），对修复后代码不具证据资格。该证据系 fixes-5 期并行全量采集（cargo_target_dir 指向 wt-protocol-interop-fixes-5），probe exit 124 / E_TIMEOUT_HANG；其 evidence_id 时间（19:34Z）晚于 fixes-7 官格 PASS 证据（18:22Z）纯系并行采集顺序造成的时序倒置，recompute「同格取最新 id」规则在此失效。被 fixes-7 官格证据取代：develop 两跑 T173819Z（median 105,148,476 B/s）/ T173857Z（105,869,317 B/s，构建 e8363bc）与 re-verify 两跑 T182208Z（103,110,744 B/s）/ T182240Z（104,614,006 B/s，构建 4b4de30）共四跑 PASS，probe binary sha256 同为 139dd86868c5…。裁决 MSR-fixes7-hy2-flip-ruling-20261028 裁决一（装配 B）。 |
| PIV-hysteria2-default-tcp-throughput-20261025T193405Z-001 | 无（仅 selfcheck.json，非 verdict 证据） | PIV-hysteria2-default-tcp-throughput-20261025T182240Z-001 | 与 T193403Z 同批（同格、同次并行采集，+2s）的 selfcheck 伴随工件目录，无 probe.json、无独立 verdict；随 T193403Z 一并自组合根副本移出，理由同上条。原件保留于原始证据树。 |
| PIV-vless-default-bad-config-20261028T151550Z-001 | Blocked | PIV-vless-default-bad-config-20261028T151944Z-001 | dumpcap 捕获窗口未抓到参照端流量（pcap packets=0 → finalize 按 AC-12.2.3/plan §8.1 规则 4 机械降级为 BLOCKED/E_EVIDENCE_GAP），语义判定本身为 E_EXPECTED_CONFIG_REJECT PASS。同批其余 23 格均抓到 pcap（13–5938 包），判定为采集侧偶发缺口；按纪律只复跑一次并照录两次结果，两次运行目录均保留在证据树。复跑证据：packets=14，verdict=Pass。 |

复算的选择规则是同格取最新 evidence_id；被替代运行仍保留在证据树与 `analysis/progress.tsv`，不覆盖历史结论。
