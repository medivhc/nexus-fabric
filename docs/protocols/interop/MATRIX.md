# 出站协议互操作证据总表（MATRIX）

> 本文件由 `scripts/interop/recompute-verdicts.py` 从证据机械生成；人工零编辑。
> 修复顺序、依赖与复验口径见人工维护的 [NEXT-STEPS.md](NEXT-STEPS.md)。

- run `protocol-interop-fixes-5`；baseline `a30147a7b98c9a84a46332c6613cf161280234b2`；spec frozen fixes-5 frozen (requirement-change)（sha256 `a955bd9ab227c23c2772fc6932ab909f2e65de114cb39bb1e2650866334e7718`）；test window `2026-10-25T18:28:02Z .. 2026-10-25T19:51:02Z`。
- 参照实现：sing-box 1.13.16（sha256 `8da901e7b6eb0d2f6f6e701f19d5f78af235d038ae078b37a70739db5895d262`）；Xray 26.10.21（sha256 `MISSING`）。
- archive（主机归档路径）：（S30 归档后追加）。
- 注记：`docs/protocols/interop/notes/trojan-fallback.md`（sha256 `0c49d2f5ea7e7c121731b212fc5f652be17cde97d11d7a8972195e9c27f7a339`）；本节由 `recompute-verdicts.py --notes` 注入，禁止手工编辑 MATRIX。

## 先读：范围 / 结论 / 图例

- **覆盖**：5 个出站代理协议（VLESS、AnyTLS、Hysteria2、Trojan、Shadowsocks）共 47 个证据格。TCP 成功型格走产品 SOCKS5 出口路径；`UdpEcho` 与 VLESS Vision 部分格为 crate 直调（`CrateDirect`），不代表产品入口可用。
- **不覆盖**：VMess（本轮暂缓）、direct/relay/socks5 出站、TUN/VPN、Android 统一 VPN 入口、UI/诊断呈现。
- **本表不回答**：直连/中继回退是否可用（属 N1 整体结论）；也不把「产品级 UDP 未实现」扩大成「Hy2 的 QUIC 出站传输不可用」（见产品级 UDP 节）。
- **结论 1**：本次复算：`VERIFIED` 2 个（Vless、Anytls），`PARTIAL` 2 个（Trojan、Shadowsocks），`BROKEN` 1 个（Hysteria2）；当前**无缺口**可宣称可用（`VERIFIED / USABLE`）的协议为 Vless、Anytls；另有 2 个 `USABLE_WITH_GAPS`（Trojan、Shadowsocks）。
- **结论 1 限定**：`USABLE` 指 TCP 产品路径；产品 SOCKS5 UDP ASSOCIATE 五协议均未实现，`UdpEcho` 为 crate 级证据、不代表产品入口可用。
- **结论 2**：剩余阻断分属产品安全语义（Trojan fallback 的窗口外残余）、协议编解码（Hy2）、跨协议传输与产品能力缺口（五协议产品级 UDP）。本 run 已消除 Trojan fallback 的 fail-open 主路径（success 前零字节投递），`root_cause_class` 只是规则代表类，不是完整根因。
- **结论 3**：未达 `VERIFIED` 的协议及本次复算代表根因：Hysteria2 `BROKEN / E_TIMEOUT_HANG`；Trojan `PARTIAL / E_NEXUS_NOT_IMPLEMENTED`；Shadowsocks `PARTIAL / E_NEXUS_NOT_IMPLEMENTED`。
- **结论 4**：Trojan 的 fallback fail-open 主路径已由本 run 关闭（success 前零字节投递），剩余为 success 之后到达的 fallback（R-1/R-2 承诺边界）与产品 UDP 未实现；Shadowsocks 剩余为产品 UDP 缺口（SIP004 线格式已由 fixes-2 修复）。两者上限均为 `PARTIAL / TCP_ONLY / USABLE_WITH_GAPS`（spec E1 规则 6/R11）。
- **结论 5**：五协议当前均可在产品配置面选择，且无「实验性/未验证」标注；配置面标注（P0b）仍待 protocol-config-surface-labeling run 落地。本 run 只新增 trojan 专属的 `fallback_guard` / `ready_window_ms` 两个字段与 CONNECT 应答时序/失败语义。
- **优先级 1（AC-1，DONE）**：TrojanFallback/BadCredential：success 前失败、零隧道字节、参照端 fallback 访问可证——PASS（本地 E4 + interop 参照格）；证据：analysis/ac1-local-fallback.json；evidence/trojan/trojan-fallback/bad-credential/（见 analysis/verdicts.json）；analysis/ac6-wire.json。
- **优先级 2（R-1，待办）**：fallback 响应慢于 W（>600ms 上限 / 显式覆盖过小）——success 已写出，窗口外 fallback 内容仍可能被视为隧道数据；承诺边界外，见 notes/trojan-fallback.md。
- **优先级 3（R-2，待办）**：fallback 等客户端先发载荷才响应——零载荷判据失效；承诺边界外。
- **优先级 4（T2，DONE）**：Trojan/Default/TcpThroughput 中位数 ≥ 基线 90%（两臂各 ≥3 轮）——见 analysis/t2/t2-accounting.json；证据：analysis/t2/t2-accounting.json。
- **优先级 5（AC-3，DONE）**：上行零扣压：pipelined CONNECT+载荷 3 轮 × 200——PASS（轮轮 p99 ≤ 5ms；无系统性扣压）；证据：analysis/ac3-pipelined.json。
- **优先级 6（R-3，待办）**：signature 模式下的非 HTTP fallback——显式安全降级的已知漏报面。
- **优先级 7（R-4，待办）**：客户端在 success 前 pipelined 载荷（seed 非空）——守卫不适用（扣压又违反上行零扣压）。
- **优先级 8（R-5，待办）**：nexusd TUN / ProxyEngine 路径——成功由 smoltcp SYN-ACK 伪造，本 run 不覆盖，按单独立项排期。
- **优先级 9（AC-6，DONE）**：失败只在本地可观察：无新增 client→node 字节、无 TLS alert、服务端可见时序差 ≤200ms——PASS（35 配对样本；client 关闭时刻差中位 5.0ms / 最大 11.1ms；节点侧关闭差 ≤0.02ms；新增字节 0；alert 0）；证据：analysis/ac6-wire.json；analysis/ac6-baseline.pcap；analysis/ac6-candidate.pcap。
- **优先级 10（R-6，待办）**：HTTP 绝对形式转发（non-CONNECT）——不回本地成功应答，fallback 的 404 仍会作为 origin 响应出现。
- **优先级 11（P7，待办）**：产品级 UDP（fixes-6）——Trojan/SS 的 UdpEcho 仍 NOT_IMPLEMENTED，verdict 上限因此保持 PARTIAL / TCP_ONLY / USABLE_WITH_GAPS。
- **优先级 12（R-7，待办）**：服务端被完全劫持并伪装成真实目标——超出协议可判定范围（需端到端认证/证书钉扎）。
- **优先级 13（AC-8，DONE）**：严格模式默认且判定确定：白名单 7 端口 × 2 工作负载 + M-1~M-8 拒绝面 + signature 逃生口——PASS（14/14 白名单、8/8 strict 拒绝、8/8 signature 放行；unshare -Urn 低端口权限可用）；证据：analysis/ac8-whitelist.json。
- **优先级 14（AC-9，DONE）**：窗口校准：W ≥ 3×p99 + 20ms（sing-box fallback 实测）——PASS（114 完整流样本，p99 = 0.276ms，要求 ≥20.8ms，实际 W=50ms，无需抬高下限）；证据：analysis/ac9-calibration.json；analysis/ac9.pcap。
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
| Hysteria2 | BROKEN | PROTOCOL_SUBSET | NOT_USABLE | E_TIMEOUT_HANG | TcpThroughput(FAIL,E_TIMEOUT_HANG) | 2 |
| Trojan | PARTIAL | TCP_ONLY | USABLE_WITH_GAPS | E_NEXUS_NOT_IMPLEMENTED | UdpEcho(NOT_IMPLEMENTED,E_NEXUS_NOT_IMPLEMENTED) | 6 |
| Shadowsocks | PARTIAL | TCP_ONLY | USABLE_WITH_GAPS | E_NEXUS_NOT_IMPLEMENTED | UdpEcho(NOT_IMPLEMENTED,E_NEXUS_NOT_IMPLEMENTED) | 6 |

## 阻塞层、归属与修复后上限

`root_cause_class` 是 E1 首个命中规则所取的**代表类**，不是完整根因；下表按 fix 根因文档给出直接阻塞层与归属，不改变上表 verdict。

| 协议 | 直接阻塞层 | 归属 | 剩余阻塞格（相对可用） | 单协议可解？ | 修复后本 run schema 上限 |
|---|---|---|---|---|---|
| Vless | 无（本 run 已修复，证据见「fix 支线与复验」） | — | 无 | — | `VERIFIED / PROTOCOL_SUBSET`（Vision 仅 crate 级，产品 splice 未实现） |
| Anytls | 无（本 run 已修复，证据见「fix 支线与复验」） | — | 无 | — | `VERIFIED / FULL` |
| Hysteria2 | 认证响应 QPACK Huffman | 协议编解码实现错误 | TcpThroughput(FAIL,E_TIMEOUT_HANG) | 是（编解码一处） | `VERIFIED / FULL` |
| Trojan | 产品 UDP 未实现（fallback fail-open 已由 fixes-5 关闭主路径） | 产品 UDP 能力缺口（fixes-6） | UdpEcho(NOT_IMPLEMENTED,E_NEXUS_NOT_IMPLEMENTED) | 否，依赖 fixes-6 | 本 run 最高 `PARTIAL / TCP_ONLY / USABLE_WITH_GAPS`（U 未实现，规则 6） |
| Shadowsocks | 产品 UDP 未实现（SIP004 线格式已由 fixes-2 修复） | 产品 UDP 能力缺口（fixes-6） | UdpEcho(NOT_IMPLEMENTED,E_NEXUS_NOT_IMPLEMENTED) | 否，依赖产品 UDP | 本 run 最高 `PARTIAL / TCP_ONLY / USABLE_WITH_GAPS`（U 未实现，规则 6） |

**参照端生态**：本轮未发现参照端生态缺陷——sing-box 1.13.16 的行为符合规范；Xray 26.10.21 仅用于 Vision 争议裁决，本轮未触发。五协议 verdict 均无 `E_REF_*` 根因。

## Vless

> **verdict=VERIFIED / claim=USABLE**（scope=PROTOCOL_SUBSET，root_cause_class=NONE）
>
> 本节任一 PASS 不改变协议 verdict；单格 PASS 只在所列 carrier/scope 下成立。
> VlessVision 行为 crate 级证据，产品 Vision splice 未实现。

| Cell | 状态 | carrier | scope | evidence_id | class | 关键数字 | 证据路径 | notes |
|---|---|---|---|---|---|---|---|---|
| Default/Handshake | PASS | ProductSocks5 | ProductPath | PIV-vless-default-handshake-20261025T192805Z-001 | NONE | up=1B down=1B | evidence/vless/default/handshake/PIV-vless-default-handshake-20261025T192805Z-001/probe.json | proxy_json routing.outbound_kind=vless outbound.kind=vless; target_stats={"tcp_bytes_down":2,"tcp_bytes_up":2,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} … |
| Default/TcpSmall | PASS | ProductSocks5 | ProductPath | PIV-vless-default-tcp-small-20261025T192811Z-001 | NONE | up=65536B down=65536B | evidence/vless/default/tcp-small/PIV-vless-default-tcp-small-20261025T192811Z-001/probe.json | proxy_json routing.outbound_kind=vless outbound.kind=vless; target_stats={"tcp_bytes_down":65537,"tcp_bytes_up":65537,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} … |
| Default/TcpThroughput | PASS | ProductSocks5 | ProductPath | PIV-vless-default-tcp-throughput-20261025T192814Z-001 | NONE | median=1362581225B/s samples=3 | evidence/vless/default/tcp-throughput/PIV-vless-default-tcp-throughput-20261025T192814Z-001/probe.json | proxy_json routing.outbound_kind=vless outbound.kind=vless; target_stats={"tcp_bytes_down":101716128,"tcp_bytes_up":101712896,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} … |
| Default/LongLived | PASS | ProductSocks5 | ProductPath | PIV-vless-default-long-lived-20261025T192821Z-001 | NONE | heartbeats=12 | evidence/vless/default/long-lived/PIV-vless-default-long-lived-20261025T192821Z-001/probe.json | proxy_json routing.outbound_kind=vless outbound.kind=vless; target_stats={"tcp_bytes_down":13,"tcp_bytes_up":13,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} … |
| Default/Reconnect | PASS | ProductSocks5 | ProductPath | PIV-vless-default-reconnect-20261025T193015Z-001 | NONE | reconnects=3 | evidence/vless/default/reconnect/PIV-vless-default-reconnect-20261025T193015Z-001/probe.json | proxy_json routing.outbound_kind=vless outbound.kind=vless; target_stats={"tcp_bytes_down":4,"tcp_bytes_up":4,"tcp_connections":4,"udp_bytes":0,"udp_datagrams":0} … |
| Default/UdpEcho | PASS | CrateDirect | ProtocolWire | PIV-vless-default-udp-echo-20261025T193023Z-001 | NONE | udp 1000/1000 corrupt=0 | evidence/vless/default/udp-echo/PIV-vless-default-udp-echo-20261025T193023Z-001/probe.json | udp_seq_and_hash_ok; target_stats={"tcp_bytes_down":0,"tcp_bytes_up":0,"tcp_connections":0,"udp_bytes":512064,"udp_datagrams":1001} …; crate 级，产品入口不可用 |
| Default/BadCredential | PASS | ProductSocks5 | ProductPath | PIV-vless-default-bad-credential-20261025T193028Z-001 | E_EXPECTED_AUTH_REJECT | up=0B down=0B | evidence/vless/default/bad-credential/PIV-vless-default-bad-credential-20261025T193028Z-001/probe.json | proxy_json routing.outbound_kind=vless outbound.kind=vless; workload_error=eof; classification=E_EXPECTED_AUTH_REJECT; reference closed the session on the negative case …; 限定：正向路径不通时本格仅证明无静默成功，不独立证明认证拒绝语义 |
| Default/BadConfig | PASS | ProductSocks5 | ProductPath | PIV-vless-default-bad-config-20261025T193033Z-001 | E_EXPECTED_CONFIG_REJECT | up=0B down=0B | evidence/vless/default/bad-config/PIV-vless-default-bad-config-20261025T193033Z-001/probe.json | proxy_json routing.outbound_kind=vless outbound.kind=vless; workload_error=eof; classification=E_EXPECTED_CONFIG_REJECT; reference closed the session on the negative case …; 限定：正向路径不通时本格仅证明无静默成功，不独立证明认证拒绝语义 |
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
| Default/Handshake | PASS | ProductSocks5 | ProductPath | PIV-anytls-default-handshake-20261025T193045Z-001 | NONE | up=1B down=1B | evidence/anytls/default/handshake/PIV-anytls-default-handshake-20261025T193045Z-001/probe.json | proxy_json routing.outbound_kind=anytls outbound.kind=anytls; target_stats={"tcp_bytes_down":2,"tcp_bytes_up":2,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} … |
| Default/TcpSmall | PASS | ProductSocks5 | ProductPath | PIV-anytls-default-tcp-small-20261025T193048Z-001 | NONE | up=65536B down=65536B | evidence/anytls/default/tcp-small/PIV-anytls-default-tcp-small-20261025T193048Z-001/probe.json | proxy_json routing.outbound_kind=anytls outbound.kind=anytls; target_stats={"tcp_bytes_down":65537,"tcp_bytes_up":65537,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} … |
| Default/TcpThroughput | PASS | ProductSocks5 | ProductPath | PIV-anytls-default-tcp-throughput-20261025T193052Z-001 | NONE | median=354962096B/s samples=3 | evidence/anytls/default/tcp-throughput/PIV-anytls-default-tcp-throughput-20261025T193052Z-001/probe.json | proxy_json routing.outbound_kind=anytls outbound.kind=anytls; target_stats={"tcp_bytes_down":101716128,"tcp_bytes_up":101712896,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} … |
| Default/LongLived | PASS | ProductSocks5 | ProductPath | PIV-anytls-default-long-lived-20261025T193101Z-001 | NONE | heartbeats=12 | evidence/anytls/default/long-lived/PIV-anytls-default-long-lived-20261025T193101Z-001/probe.json | proxy_json routing.outbound_kind=anytls outbound.kind=anytls; target_stats={"tcp_bytes_down":13,"tcp_bytes_up":13,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} … |
| Default/Reconnect | PASS | ProductSocks5 | ProductPath | PIV-anytls-default-reconnect-20261025T193303Z-001 | NONE | reconnects=3 | evidence/anytls/default/reconnect/PIV-anytls-default-reconnect-20261025T193303Z-001/probe.json | proxy_json routing.outbound_kind=anytls outbound.kind=anytls; target_stats={"tcp_bytes_down":4,"tcp_bytes_up":4,"tcp_connections":4,"udp_bytes":0,"udp_datagrams":0} … |
| Default/PaddingDiag | PASS | ProductSocks5 | ProductPath | PIV-anytls-default-padding-diag-20261025T193313Z-001 | NONE | up=0B down=0B | evidence/anytls/default/padding-diag/PIV-anytls-default-padding-diag-20261025T193313Z-001/probe.json | proxy_json routing.outbound_kind=anytls outbound.kind=anytls; serversettings_inferred; target_stats={"tcp_bytes_down":1,"tcp_bytes_up":1,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} …; 诊断格，不参与 verdict |
| Default/UdpEcho | PASS | CrateDirect | ProtocolWire | PIV-anytls-default-udp-echo-20261025T193320Z-001 | NONE | udp 1000/1000 corrupt=0 | evidence/anytls/default/udp-echo/PIV-anytls-default-udp-echo-20261025T193320Z-001/probe.json | udp_seq_and_hash_ok; target_stats={"tcp_bytes_down":0,"tcp_bytes_up":0,"tcp_connections":0,"udp_bytes":512064,"udp_datagrams":1001} …; crate 级，产品入口不可用 |
| Default/BadCredential | PASS | ProductSocks5 | ProductPath | PIV-anytls-default-bad-credential-20261025T193327Z-001 | E_EXPECTED_AUTH_REJECT | up=0B down=0B | evidence/anytls/default/bad-credential/PIV-anytls-default-bad-credential-20261025T193327Z-001/probe.json | proxy_error=ConnectivityEstablishmentFailed { provider: ProviderId("ref"), reason: "anytls session handshake failed: anytls io error" }; workload_error=read: Connection reset by peer (os error 104) … |
| AnyTlsCustomPadding/BadConfig | PASS | ProductSocks5 | ProductPath | PIV-anytls-anytls-custom-padding-bad-config-20261025T193351Z-001 | E_EXPECTED_CONFIG_REJECT | up=0B down=0B | evidence/anytls/anytls-custom-padding/bad-config/PIV-anytls-anytls-custom-padding-bad-config-20261025T193351Z-001/probe.json | proxy_error=ConnectivityEstablishmentFailed { provider: ProviderId("ref"), reason: "anytls session handshake failed: anytls server requested padding scheme update" } … |

## Hysteria2

> **verdict=BROKEN / claim=NOT_USABLE**（scope=PROTOCOL_SUBSET，root_cause_class=E_TIMEOUT_HANG）
>
> 本节任一 PASS 不改变协议 verdict；单格 PASS 只在所列 carrier/scope 下成立。
> QpackDiag 为诊断格，不参与 verdict。

| Cell | 状态 | carrier | scope | evidence_id | class | 关键数字 | 证据路径 | notes |
|---|---|---|---|---|---|---|---|---|
| Default/TcpSmall | PASS | ProductSocks5 | ProductPath | PIV-hysteria2-default-tcp-small-20261025T193400Z-001 | NONE | up=65536B down=65536B | evidence/hysteria2/default/tcp-small/PIV-hysteria2-default-tcp-small-20261025T193400Z-001/probe.json | proxy_json routing.outbound_kind=hysteria2 outbound.kind=hysteria2; target_stats={"tcp_bytes_down":65537,"tcp_bytes_up":65537,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} … |
| Default/TcpThroughput | FAIL | ProductSocks5 | ProductPath | PIV-hysteria2-default-tcp-throughput-20261025T193403Z-001 | E_TIMEOUT_HANG | median=0B/s samples=0 | evidence/hysteria2/default/tcp-throughput/PIV-hysteria2-default-tcp-throughput-20261025T193403Z-001/probe.json |  |
| Default/LongLived | PASS | ProductSocks5 | ProductPath | PIV-hysteria2-default-long-lived-20261025T193528Z-001 | NONE | heartbeats=12 | evidence/hysteria2/default/long-lived/PIV-hysteria2-default-long-lived-20261025T193528Z-001/probe.json | proxy_json routing.outbound_kind=hysteria2 outbound.kind=hysteria2; target_stats={"tcp_bytes_down":13,"tcp_bytes_up":13,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} … |
| Default/Reconnect | PASS | ProductSocks5 | ProductPath | PIV-hysteria2-default-reconnect-20261025T193745Z-001 | NONE | reconnects=3 | evidence/hysteria2/default/reconnect/PIV-hysteria2-default-reconnect-20261025T193745Z-001/probe.json | proxy_json routing.outbound_kind=hysteria2 outbound.kind=hysteria2; target_stats={"tcp_bytes_down":4,"tcp_bytes_up":4,"tcp_connections":4,"udp_bytes":0,"udp_datagrams":0} … |
| Default/Handshake | PASS | ProductSocks5 | ProductPath | PIV-hysteria2-default-handshake-20261025T193753Z-001 | NONE | up=1B down=1B | evidence/hysteria2/default/handshake/PIV-hysteria2-default-handshake-20261025T193753Z-001/probe.json | proxy_json routing.outbound_kind=hysteria2 outbound.kind=hysteria2; target_stats={"tcp_bytes_down":2,"tcp_bytes_up":2,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} … |
| Hy2Salamander/Handshake | PASS | ProductSocks5 | ProductPath | PIV-hysteria2-hy2-salamander-handshake-20261025T193758Z-001 | NONE | up=1B down=1B | evidence/hysteria2/hy2-salamander/handshake/PIV-hysteria2-hy2-salamander-handshake-20261025T193758Z-001/probe.json | proxy_json routing.outbound_kind=hysteria2 outbound.kind=hysteria2; target_stats={"tcp_bytes_down":2,"tcp_bytes_up":2,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} … |
| Hy2Salamander/TcpSmall | PASS | ProductSocks5 | ProductPath | PIV-hysteria2-hy2-salamander-tcp-small-20261025T182802Z-001 | NONE | up=65536B down=65536B | evidence/hysteria2/hy2-salamander/tcp-small/PIV-hysteria2-hy2-salamander-tcp-small-20261025T182802Z-001/probe.json | proxy_json routing.outbound_kind=hysteria2 outbound.kind=hysteria2; target_stats={"tcp_bytes_down":65537,"tcp_bytes_up":65537,"tcp_connections":2,"udp_bytes":0,"udp_datagrams":0} … |
| Default/QpackDiag | PASS | CrateDirect | ProtocolWire | PIV-hysteria2-default-qpack-diag-20261025T193804Z-001 | NONE | up=0B down=0B | evidence/hysteria2/default/qpack-diag/PIV-hysteria2-default-qpack-diag-20261025T193804Z-001/probe.json | qpack_diag_not_triggered=handshake_ok; hy2_error=null; hy2_auth_status=233; hy2_auth_status_source=connect_ok_after_decode_auth_response; hy2_udp_enabled=true; hy2_cc_rx=auto …; 诊断格，不参与 verdict |
| Default/UdpEcho | PASS | CrateDirect | ProtocolWire | PIV-hysteria2-default-udp-echo-20261025T193809Z-001 | NONE | udp 1000/1000 corrupt=0 | evidence/hysteria2/default/udp-echo/PIV-hysteria2-default-udp-echo-20261025T193809Z-001/probe.json | udp_seq_and_hash_ok; target_stats={"tcp_bytes_down":0,"tcp_bytes_up":0,"tcp_connections":0,"udp_bytes":512064,"udp_datagrams":1001} … |
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
| Default/UdpEcho | NOT_IMPLEMENTED | CrateDirect | ProtocolWire | PIV-trojan-default-udp-echo-20261025T194049Z-001 | E_NEXUS_NOT_IMPLEMENTED | udp 0/0 corrupt=0 | evidence/trojan/default/udp-echo/PIV-trojan-default-udp-echo-20261025T194049Z-001/probe.json | Trojan UDP 路径未实现（产品入口 + 出站均无） |
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
| Default/UdpEcho | NOT_IMPLEMENTED | CrateDirect | ProtocolWire | PIV-shadowsocks-default-udp-echo-20261025T194346Z-001 | E_NEXUS_NOT_IMPLEMENTED | udp 0/0 corrupt=0 | evidence/shadowsocks/default/udp-echo/PIV-shadowsocks-default-udp-echo-20261025T194346Z-001/probe.json | Shadowsocks UDP 路径未实现（产品入口 + 出站均无） |
| Default/BadCredential | PASS | ProductSocks5 | ProductPath | PIV-shadowsocks-default-bad-credential-20261025T194352Z-001 | E_EXPECTED_AUTH_REJECT | up=0B down=0B | evidence/shadowsocks/default/bad-credential/PIV-shadowsocks-default-bad-credential-20261025T194352Z-001/probe.json | proxy_json routing.outbound_kind=shadowsocks outbound.kind=shadowsocks; workload_error=eof; classification=E_EXPECTED_AUTH_REJECT; reference closed the session on the negative case …; 限定：正向路径不通时本格仅证明无静默成功，不独立证明认证拒绝语义 |
| Default/BadConfig | PASS | ProductSocks5 | ProductPath | PIV-shadowsocks-default-bad-config-20261025T194359Z-001 | E_EXPECTED_CONFIG_REJECT | up=0B down=0B | evidence/shadowsocks/default/bad-config/PIV-shadowsocks-default-bad-config-20261025T194359Z-001/probe.json | proxy_json routing.outbound_kind=shadowsocks outbound.kind=shadowsocks; workload_error=eof; classification=E_EXPECTED_CONFIG_REJECT; reference closed the session on the negative case …; 限定：正向路径不通时本格仅证明无静默成功，不独立证明认证拒绝语义 |

## 产品级 UDP（不参与协议 verdict）

产品 SOCKS5 入口 `crates/nexus-ingress/src/lib.rs:232-241` 拒绝 BND/UDP ASSOCIATE；Trojan/SS 出站也没有 UDP 帧路径。因此产品级 UDP 按能力缺口记录，不进入五协议 verdict；crate 级 UDP 结论见各协议 `UdpEcho` 行。

**区分**：本项指产品 SOCKS5 UDP relay 入口/出站帧路径缺失，不等于所有 UDP/QUIC 路径不可用——Hy2 出站到代理服务器仍走 QUIC/UDP 传输，其失败点是认证响应编解码（`E_NEXUS_CODEC`），不是 UDP 传输本身。

## 产品能力缺口

- 产品级 UDP：未实现（上节）。
- Vision：产品路径只编码 addon，不实现 splice；本 run 的 Vision 结论来自 crate 直调。
- Hysteria2：端口跳跃/Brutal/gecko/分片不在范围。
- AnyTLS：session 池/心跳定时器/padding 写路径不单独验。
- Trojan：success **之后**才到达的 fallback 首包不可判定（R-1/R-2 承诺边界，见 notes/trojan-fallback.md）；signature 模式的非 HTTP fallback 漏报（R-3）。
- nexusd TUN / ProxyEngine 路径的 fail-open 不在本 run 覆盖内（R-5）。

## fix 支线与复验

本 run 产生 verdict 翻转的修复条目（来源：run-meta）：

- **Trojan fallback fail-closed（CONNECT 应答暂存 + 就绪窗口 + 首包分类 + 失败应答）**（commit `12cbf81`）：TrojanFallback/BadCredential 由 FAIL/E_NEXUS_FRAMING 转为 PASS（REP≠0 + 零隧道字节 + pcap 证明 fallback 被访问）；Trojan Default 全格保持 PASS；上限仍为 PARTIAL / TCP_ONLY / USABLE_WITH_GAPS（evidence/trojan/trojan-fallback/bad-credential/（见 analysis/verdicts.json）；analysis/ac1-local-fallback.json；analysis/ac6-wire.json；analysis/ac9-calibration.json）

根因文档位于仓库 `docs/protocols/interop/fix/`；本 run 证据根为 `/work/interop-run/merge-fixes4-20261028`，上表 cell 证据路径均相对该目录。

## 附录 A：配置索引

| 文件 | sha256 |
|---|---|
| evidence/ref-config/anytls-custom-padding.json | 49cb09a1968c0d9474783143211d4cdd99213ab8abcf84ce906a38328810ccda |
| evidence/ref-config/anytls.json | a3595a3d96315a4b44fb24cf8592d57238c0e1f8d3bb66234fc2e95b58ae44f4 |
| evidence/ref-config/hysteria2-plain.json | 8ec6e903c28d2e506f8eebaba71a5b99dd69faf0c3977004eb6899994f2746e2 |
| evidence/ref-config/hysteria2-salamander.json | 48fc29090a367033651b3035939c11e08e773164f6a2bff7ec911c1867945239 |
| evidence/ref-config/shadowsocks-aes256gcm.json | b11aa07c7076f23e6a8146ab23af91b11e817ba04178ffa7a4d9929f6caded4c |
| evidence/ref-config/shadowsocks.json | 26f7ca2a50977fc736f5e717ce6fb8d4030f2a44f780885bb0649875f2718361 |
| evidence/ref-config/trojan-fallback.json | 3c773c80a87811ea4a22a23afd7189faf4fc216fdc3b4bccad8f35f3b099de0f |
| evidence/ref-config/trojan.json | 0791a37ad1e65eff6465ed47d48776808cdeb6e0a8ae3d270d1f615645255b2d |
| evidence/ref-config/vless-basic-flow-mismatch.json | 5ce7bc75961c47452d90e32f8fc39d13a202d23cd857304e86f4ee766a1a40bf |
| evidence/ref-config/vless-basic.json | 09247f957de6b365227951d4d4c0d217d15bc2f1b8b03ac7a581f77beabaf49e |
| evidence/ref-config/vless-vision.json | e475ca5b0864e1eb9e515a0884355d2e30c49d7173017e465fdda16daaf45563 |
| evidence/ref-config/xray-vless-basic.json | e6bd8ef10a995cf0a3e88b46d52ad0fb4b04b96b787e99c670f7b8e302e49e17 |
| evidence/ref-config/xray-vless-vision.json | f6eee916fbd74ec3a80500ea6114b1a244a4e559e55db3048047c4cbf3d87dc7 |

## 附录 B：证据清单

| evidence_id | verdict | carrier | scope | 路径 |
|---|---|---|---|---|
| PIV-anytls-anytls-custom-padding-bad-config-20261025T193351Z-001 | PASS | ProductSocks5 | ProductPath | evidence/anytls/anytls-custom-padding/bad-config/PIV-anytls-anytls-custom-padding-bad-config-20261025T193351Z-001/probe.json |
| PIV-anytls-default-bad-credential-20261025T193327Z-001 | PASS | ProductSocks5 | ProductPath | evidence/anytls/default/bad-credential/PIV-anytls-default-bad-credential-20261025T193327Z-001/probe.json |
| PIV-anytls-default-handshake-20261025T193045Z-001 | PASS | ProductSocks5 | ProductPath | evidence/anytls/default/handshake/PIV-anytls-default-handshake-20261025T193045Z-001/probe.json |
| PIV-anytls-default-long-lived-20261025T193101Z-001 | PASS | ProductSocks5 | ProductPath | evidence/anytls/default/long-lived/PIV-anytls-default-long-lived-20261025T193101Z-001/probe.json |
| PIV-anytls-default-padding-diag-20261025T193313Z-001 | PASS | ProductSocks5 | ProductPath | evidence/anytls/default/padding-diag/PIV-anytls-default-padding-diag-20261025T193313Z-001/probe.json |
| PIV-anytls-default-reconnect-20261025T193303Z-001 | PASS | ProductSocks5 | ProductPath | evidence/anytls/default/reconnect/PIV-anytls-default-reconnect-20261025T193303Z-001/probe.json |
| PIV-anytls-default-tcp-small-20261025T193048Z-001 | PASS | ProductSocks5 | ProductPath | evidence/anytls/default/tcp-small/PIV-anytls-default-tcp-small-20261025T193048Z-001/probe.json |
| PIV-anytls-default-tcp-throughput-20261025T193052Z-001 | PASS | ProductSocks5 | ProductPath | evidence/anytls/default/tcp-throughput/PIV-anytls-default-tcp-throughput-20261025T193052Z-001/probe.json |
| PIV-anytls-default-udp-echo-20261025T193320Z-001 | PASS | CrateDirect | ProtocolWire | evidence/anytls/default/udp-echo/PIV-anytls-default-udp-echo-20261025T193320Z-001/probe.json |
| PIV-hysteria2-default-bad-config-20261025T193818Z-001 | PASS | ProductSocks5 | ProductPath | evidence/hysteria2/default/bad-config/PIV-hysteria2-default-bad-config-20261025T193818Z-001/probe.json |
| PIV-hysteria2-default-bad-credential-20261025T193814Z-001 | PASS | ProductSocks5 | ProductPath | evidence/hysteria2/default/bad-credential/PIV-hysteria2-default-bad-credential-20261025T193814Z-001/probe.json |
| PIV-hysteria2-default-handshake-20261025T193753Z-001 | PASS | ProductSocks5 | ProductPath | evidence/hysteria2/default/handshake/PIV-hysteria2-default-handshake-20261025T193753Z-001/probe.json |
| PIV-hysteria2-default-long-lived-20261025T193528Z-001 | PASS | ProductSocks5 | ProductPath | evidence/hysteria2/default/long-lived/PIV-hysteria2-default-long-lived-20261025T193528Z-001/probe.json |
| PIV-hysteria2-default-qpack-diag-20261025T193804Z-001 | PASS | CrateDirect | ProtocolWire | evidence/hysteria2/default/qpack-diag/PIV-hysteria2-default-qpack-diag-20261025T193804Z-001/probe.json |
| PIV-hysteria2-default-reconnect-20261025T193745Z-001 | PASS | ProductSocks5 | ProductPath | evidence/hysteria2/default/reconnect/PIV-hysteria2-default-reconnect-20261025T193745Z-001/probe.json |
| PIV-hysteria2-default-tcp-small-20261025T193400Z-001 | PASS | ProductSocks5 | ProductPath | evidence/hysteria2/default/tcp-small/PIV-hysteria2-default-tcp-small-20261025T193400Z-001/probe.json |
| PIV-hysteria2-default-tcp-throughput-20261025T193403Z-001 | FAIL | ProductSocks5 | ProductPath | evidence/hysteria2/default/tcp-throughput/PIV-hysteria2-default-tcp-throughput-20261025T193403Z-001/probe.json |
| PIV-hysteria2-default-udp-echo-20261025T193809Z-001 | PASS | CrateDirect | ProtocolWire | evidence/hysteria2/default/udp-echo/PIV-hysteria2-default-udp-echo-20261025T193809Z-001/probe.json |
| PIV-hysteria2-hy2-salamander-handshake-20261025T193758Z-001 | PASS | ProductSocks5 | ProductPath | evidence/hysteria2/hy2-salamander/handshake/PIV-hysteria2-hy2-salamander-handshake-20261025T193758Z-001/probe.json |
| PIV-hysteria2-hy2-salamander-tcp-small-20261025T182802Z-001 | PASS | ProductSocks5 | ProductPath | evidence/hysteria2/hy2-salamander/tcp-small/PIV-hysteria2-hy2-salamander-tcp-small-20261025T182802Z-001/probe.json |
| PIV-shadowsocks-default-bad-config-20261025T194359Z-001 | PASS | ProductSocks5 | ProductPath | evidence/shadowsocks/default/bad-config/PIV-shadowsocks-default-bad-config-20261025T194359Z-001/probe.json |
| PIV-shadowsocks-default-bad-credential-20261025T194352Z-001 | PASS | ProductSocks5 | ProductPath | evidence/shadowsocks/default/bad-credential/PIV-shadowsocks-default-bad-credential-20261025T194352Z-001/probe.json |
| PIV-shadowsocks-default-handshake-20261025T194100Z-001 | PASS | ProductSocks5 | ProductPath | evidence/shadowsocks/default/handshake/PIV-shadowsocks-default-handshake-20261025T194100Z-001/probe.json |
| PIV-shadowsocks-default-long-lived-20261025T194141Z-001 | PASS | ProductSocks5 | ProductPath | evidence/shadowsocks/default/long-lived/PIV-shadowsocks-default-long-lived-20261025T194141Z-001/probe.json |
| PIV-shadowsocks-default-reconnect-20261025T194338Z-001 | PASS | ProductSocks5 | ProductPath | evidence/shadowsocks/default/reconnect/PIV-shadowsocks-default-reconnect-20261025T194338Z-001/probe.json |
| PIV-shadowsocks-default-tcp-small-20261025T194104Z-001 | PASS | ProductSocks5 | ProductPath | evidence/shadowsocks/default/tcp-small/PIV-shadowsocks-default-tcp-small-20261025T194104Z-001/probe.json |
| PIV-shadowsocks-default-tcp-throughput-20261025T194107Z-001 | PASS | ProductSocks5 | ProductPath | evidence/shadowsocks/default/tcp-throughput/PIV-shadowsocks-default-tcp-throughput-20261025T194107Z-001/probe.json |
| PIV-shadowsocks-default-udp-echo-20261025T194346Z-001 | NOT_IMPLEMENTED | CrateDirect | ProtocolWire | evidence/shadowsocks/default/udp-echo/PIV-shadowsocks-default-udp-echo-20261025T194346Z-001/probe.json |
| PIV-trojan-default-bad-config-20261025T194057Z-001 | NOT_APPLICABLE | CrateDirect | ProtocolWire | evidence/trojan/default/bad-config/PIV-trojan-default-bad-config-20261025T194057Z-001/probe.json |
| PIV-trojan-default-bad-credential-20261025T194052Z-001 | PASS | ProductSocks5 | ProductPath | evidence/trojan/default/bad-credential/PIV-trojan-default-bad-credential-20261025T194052Z-001/probe.json |
| PIV-trojan-default-handshake-20261025T193833Z-001 | PASS | ProductSocks5 | ProductPath | evidence/trojan/default/handshake/PIV-trojan-default-handshake-20261025T193833Z-001/probe.json |
| PIV-trojan-default-long-lived-20261025T193849Z-001 | PASS | ProductSocks5 | ProductPath | evidence/trojan/default/long-lived/PIV-trojan-default-long-lived-20261025T193849Z-001/probe.json |
| PIV-trojan-default-reconnect-20261025T194043Z-001 | PASS | ProductSocks5 | ProductPath | evidence/trojan/default/reconnect/PIV-trojan-default-reconnect-20261025T194043Z-001/probe.json |
| PIV-trojan-default-tcp-small-20261025T193838Z-001 | PASS | ProductSocks5 | ProductPath | evidence/trojan/default/tcp-small/PIV-trojan-default-tcp-small-20261025T193838Z-001/probe.json |
| PIV-trojan-default-tcp-throughput-20261025T195102Z-001 | PASS | ProductSocks5 | ProductPath | evidence/trojan/default/tcp-throughput/PIV-trojan-default-tcp-throughput-20261025T195102Z-001/probe.json |
| PIV-trojan-default-udp-echo-20261025T194049Z-001 | NOT_IMPLEMENTED | CrateDirect | ProtocolWire | evidence/trojan/default/udp-echo/PIV-trojan-default-udp-echo-20261025T194049Z-001/probe.json |
| PIV-trojan-trojan-fallback-bad-credential-20261025T194055Z-001 | PASS | ProductSocks5 | ProductPath | evidence/trojan/trojan-fallback/bad-credential/PIV-trojan-trojan-fallback-bad-credential-20261025T194055Z-001/probe.json |
| PIV-vless-default-bad-config-20261025T193033Z-001 | PASS | ProductSocks5 | ProductPath | evidence/vless/default/bad-config/PIV-vless-default-bad-config-20261025T193033Z-001/probe.json |
| PIV-vless-default-bad-credential-20261025T193028Z-001 | PASS | ProductSocks5 | ProductPath | evidence/vless/default/bad-credential/PIV-vless-default-bad-credential-20261025T193028Z-001/probe.json |
| PIV-vless-default-handshake-20261025T192805Z-001 | PASS | ProductSocks5 | ProductPath | evidence/vless/default/handshake/PIV-vless-default-handshake-20261025T192805Z-001/probe.json |
| PIV-vless-default-long-lived-20261025T192821Z-001 | PASS | ProductSocks5 | ProductPath | evidence/vless/default/long-lived/PIV-vless-default-long-lived-20261025T192821Z-001/probe.json |
| PIV-vless-default-reconnect-20261025T193015Z-001 | PASS | ProductSocks5 | ProductPath | evidence/vless/default/reconnect/PIV-vless-default-reconnect-20261025T193015Z-001/probe.json |
| PIV-vless-default-tcp-small-20261025T192811Z-001 | PASS | ProductSocks5 | ProductPath | evidence/vless/default/tcp-small/PIV-vless-default-tcp-small-20261025T192811Z-001/probe.json |
| PIV-vless-default-tcp-throughput-20261025T192814Z-001 | PASS | ProductSocks5 | ProductPath | evidence/vless/default/tcp-throughput/PIV-vless-default-tcp-throughput-20261025T192814Z-001/probe.json |
| PIV-vless-default-udp-echo-20261025T193023Z-001 | PASS | CrateDirect | ProtocolWire | evidence/vless/default/udp-echo/PIV-vless-default-udp-echo-20261025T193023Z-001/probe.json |
| PIV-vless-vless-vision-handshake-20261025T193038Z-001 | PASS | CrateDirect | ProtocolWire | evidence/vless/vless-vision/handshake/PIV-vless-vless-vision-handshake-20261025T193038Z-001/probe.json |
| PIV-vless-vless-vision-tcp-small-20261025T193041Z-001 | PASS | CrateDirect | ProtocolWire | evidence/vless/vless-vision/tcp-small/PIV-vless-vless-vision-tcp-small-20261025T193041Z-001/probe.json |

## 附录 C：命令与端口

```bash
scripts/interop/run-matrix.sh --protocol <p> --variant <v> --cell <c> \
  --run-dir /work/interop-run/merge-fixes4-20261028 \
  --probe-bin $CARGO_TARGET_DIR/debug/examples/protocol_interop_probe \
  --ref-bin $RUN_DIR/ref/sing-box-1.13.16-linux-amd64-musl/sing-box
python3 scripts/interop/recompute-verdicts.py --run-dir /work/interop-run/merge-fixes4-20261028 \
  --run-meta /work/interop-run/merge-fixes4-20261028/analysis/run-meta.json \
  --matrix docs/protocols/interop/MATRIX.md --check
```

- 参照端口：vless 26100/26101、anytls 26102、hysteria2 26103/26104、
  trojan 26105/26115、shadowsocks 26106、xray 26108/26109。
- 目标端口：26200 echo / 26201 sink+source / 26202 udp / 26203 http fallback。
- 抓包：dumpcap -P（pcap），T2 用 `-a filesize:102400` 封顶 100 MiB。

## 附录 D：终局 T2 证据构建来源

| 协议 | evidence_id | nexus.commit | cargo_target_dir | binary_sha256 |
|---|---|---|---|---|
| Vless | PIV-vless-default-tcp-throughput-20261025T192814Z-001 | 087b0dd29b1d327317b507d431c429552d367e51 | /work/wt-protocol-interop-fixes-5/target | b51a52726cd22320c447687cae6ab1a3b6b0fa4d854926199dc81d7986f3ed66 |
| Anytls | PIV-anytls-default-tcp-throughput-20261025T193052Z-001 | 087b0dd29b1d327317b507d431c429552d367e51 | /work/wt-protocol-interop-fixes-5/target | b51a52726cd22320c447687cae6ab1a3b6b0fa4d854926199dc81d7986f3ed66 |
| Hysteria2 | PIV-hysteria2-default-tcp-throughput-20261025T193403Z-001 | 087b0dd29b1d327317b507d431c429552d367e51 | /work/wt-protocol-interop-fixes-5/target | MISSING |
| Trojan | PIV-trojan-default-tcp-throughput-20261025T195102Z-001 | 779595540c4310aa3b61ffd9c8986f7c6e1013ef | /work/nexus-dev/target | b51a52726cd22320c447687cae6ab1a3b6b0fa4d854926199dc81d7986f3ed66 |
| Shadowsocks | PIV-shadowsocks-default-tcp-throughput-20261025T194107Z-001 | 087b0dd29b1d327317b507d431c429552d367e51 | /work/wt-protocol-interop-fixes-5/target | b51a52726cd22320c447687cae6ab1a3b6b0fa4d854926199dc81d7986f3ed66 |

上表逐格给出各 T2 证据绑定的构建提交、目标目录与二进制哈希；按证据 `nexus.commit` 派生：`087b0dd29b1d327317b507d431c429552d367e51`（Vless、Anytls、Hysteria2、Shadowsocks）；`779595540c4310aa3b61ffd9c8986f7c6e1013ef`（Trojan）。
构建均来自证据记录的本 worktree `cargo_target_dir`，不再引用前序 run 的 fix worktree。
