# prediction-check — protocol-interop-fixes-1

预测冻结来源：`~/pipeline-runs/protocol-interop-fixes-1/spec.md` §0.5（v1.2）。预测不因实测修改；实际值按 step 时间窗取该轮最新证据 + classification 覆盖。

## 步骤 2 — transport 后复跑（25 格）

| protocol | variant | cell | step | predicted | actual verdict | actual class | match? | evidence_id | evidence path | note |
|---|---|---|---|---|---|---|---|---|---|---|
| Anytls | Default | Handshake | 2 | PASS - | PASS | - | yes | PIV-anytls-default-handshake-20261024T213337Z-001 | evidence/anytls/default/handshake/PIV-anytls-default-handshake-20261024T213337Z-001 | - |
| Anytls | Default | TcpSmall | 2 | PASS - | PASS | - | yes | PIV-anytls-default-tcp-small-20261024T213340Z-001 | evidence/anytls/default/tcp-small/PIV-anytls-default-tcp-small-20261024T213340Z-001 | - |
| Anytls | Default | TcpThroughput | 2 | PASS - | PASS | - | yes | PIV-anytls-default-tcp-throughput-20261024T213344Z-001 | evidence/anytls/default/tcp-throughput/PIV-anytls-default-tcp-throughput-20261024T213344Z-001 | T2 3 样本中位数见 probe.json metrics |
| Anytls | Default | LongLived | 2 | PASS - | PASS | - | yes | PIV-anytls-default-long-lived-20261024T213353Z-001 | evidence/anytls/default/long-lived/PIV-anytls-default-long-lived-20261024T213353Z-001 | - |
| Anytls | Default | Reconnect | 2 | PASS - | PASS | - | yes | PIV-anytls-default-reconnect-20261024T213546Z-001 | evidence/anytls/default/reconnect/PIV-anytls-default-reconnect-20261024T213546Z-001 | - |
| Anytls | Default | UdpEcho | 2 | PASS - | PASS | - | yes | PIV-anytls-default-udp-echo-20261024T213554Z-001 | evidence/anytls/default/udp-echo/PIV-anytls-default-udp-echo-20261024T213554Z-001 | - |
| Anytls | Default | BadCredential | 2 | PASS - | PASS | - | yes | PIV-anytls-default-bad-credential-20261024T213558Z-001 | evidence/anytls/default/bad-credential/PIV-anytls-default-bad-credential-20261024T213558Z-001 | - |
| Anytls | AnyTlsCustomPadding | BadConfig | 2 | PASS - | PASS | - | yes | PIV-anytls-anytls-custom-padding-bad-config-20261024T213605Z-001 | evidence/anytls/anytls-custom-padding/bad-config/PIV-anytls-anytls-custom-padding-bad-config-20261024T213605Z-001 | - |
| Anytls | Default | PaddingDiag | 2 | PASS - | PASS | - | yes | PIV-anytls-default-padding-diag-20261024T213601Z-001 | evidence/anytls/default/padding-diag/PIV-anytls-default-padding-diag-20261024T213601Z-001 | diag，不入 verdict 分母 |
| Vless | Default | TcpSmall | 2 | FAIL E_NEXUS_FRAMING | FAIL | E_NEXUS_FRAMING | yes | PIV-vless-default-tcp-small-20261024T213608Z-001 | evidence/vless/default/tcp-small/PIV-vless-default-tcp-small-20261024T213608Z-001 | - |
| Vless | Default | TcpThroughput | 2 | FAIL E_NEXUS_FRAMING | FAIL | E_NEXUS_FRAMING | yes | PIV-vless-default-tcp-throughput-20261024T213621Z-001 | evidence/vless/default/tcp-throughput/PIV-vless-default-tcp-throughput-20261024T213621Z-001 | - |
| Vless | Default | LongLived | 2 | FAIL E_NEXUS_FRAMING | FAIL | E_NEXUS_FRAMING | yes | PIV-vless-default-long-lived-20261024T213635Z-001 | evidence/vless/default/long-lived/PIV-vless-default-long-lived-20261024T213635Z-001 | - |
| Vless | Default | Reconnect | 2 | FAIL E_NEXUS_FRAMING | FAIL | E_NEXUS_FRAMING | yes | PIV-vless-default-reconnect-20261024T213648Z-001 | evidence/vless/default/reconnect/PIV-vless-default-reconnect-20261024T213648Z-001 | - |
| Trojan | Default | TcpSmall | 2 | PASS - | PASS | - | yes | PIV-trojan-default-tcp-small-20261024T213725Z-001 | evidence/trojan/default/tcp-small/PIV-trojan-default-tcp-small-20261024T213725Z-001 | - |
| Trojan | Default | TcpThroughput | 2 | PASS - | PASS | - | yes | PIV-trojan-default-tcp-throughput-20261024T213728Z-001 | evidence/trojan/default/tcp-throughput/PIV-trojan-default-tcp-throughput-20261024T213728Z-001 | T2 3 样本中位数见 probe.json metrics |
| Trojan | Default | LongLived | 2 | PASS - | PASS | - | yes | PIV-trojan-default-long-lived-20261024T213734Z-001 | evidence/trojan/default/long-lived/PIV-trojan-default-long-lived-20261024T213734Z-001 | - |
| Trojan | Default | Reconnect | 2 | PASS - | PASS | - | yes | PIV-trojan-default-reconnect-20261024T213927Z-001 | evidence/trojan/default/reconnect/PIV-trojan-default-reconnect-20261024T213927Z-001 | - |
| Shadowsocks | Default | TcpSmall | 2 | FAIL E_NEXUS_FRAMING | FAIL | E_NEXUS_FRAMING | yes | PIV-shadowsocks-default-tcp-small-20261024T213934Z-001 | evidence/shadowsocks/default/tcp-small/PIV-shadowsocks-default-tcp-small-20261024T213934Z-001 | - |
| Shadowsocks | Default | TcpThroughput | 2 | FAIL E_NEXUS_FRAMING | FAIL | E_NEXUS_FRAMING | yes | PIV-shadowsocks-default-tcp-throughput-20261024T213938Z-001 | evidence/shadowsocks/default/tcp-throughput/PIV-shadowsocks-default-tcp-throughput-20261024T213938Z-001 | - |
| Shadowsocks | Default | LongLived | 2 | FAIL E_NEXUS_FRAMING | FAIL | E_NEXUS_FRAMING | yes | PIV-shadowsocks-default-long-lived-20261024T213941Z-001 | evidence/shadowsocks/default/long-lived/PIV-shadowsocks-default-long-lived-20261024T213941Z-001 | - |
| Shadowsocks | Default | Reconnect | 2 | FAIL E_NEXUS_FRAMING | FAIL | E_NEXUS_FRAMING | yes | PIV-shadowsocks-default-reconnect-20261024T214145Z-001 | evidence/shadowsocks/default/reconnect/PIV-shadowsocks-default-reconnect-20261024T214145Z-001 | - |
| Hysteria2 | Default | TcpSmall | 2 | FAIL E_NEXUS_CODEC | FAIL | E_NEXUS_CODEC | yes | PIV-hysteria2-default-tcp-small-20261024T214223Z-001 | evidence/hysteria2/default/tcp-small/PIV-hysteria2-default-tcp-small-20261024T214223Z-001 | probe 原始 error.class=E_NEXUS_FRAMING；按 fix/hysteria2/root-cause.md （QPACK Huffman H=1 → InvalidFrame，认证解码阶段）覆盖为 E_NEXUS_CODEC，实证为同一失败 |
| Hysteria2 | Default | TcpThroughput | 2 | FAIL E_NEXUS_CODEC | FAIL | E_NEXUS_CODEC | yes | PIV-hysteria2-default-tcp-throughput-20261024T214226Z-001 | evidence/hysteria2/default/tcp-throughput/PIV-hysteria2-default-tcp-throughput-20261024T214226Z-001 | probe 原始 error.class=E_NEXUS_FRAMING；按 fix/hysteria2/root-cause.md （QPACK Huffman H=1 → InvalidFrame，认证解码阶段）覆盖为 E_NEXUS_CODEC，实证为同一失败 |
| Hysteria2 | Default | LongLived | 2 | FAIL E_NEXUS_CODEC | FAIL | E_NEXUS_CODEC | yes | PIV-hysteria2-default-long-lived-20261024T214229Z-001 | evidence/hysteria2/default/long-lived/PIV-hysteria2-default-long-lived-20261024T214229Z-001 | probe 原始 error.class=E_NEXUS_FRAMING；按 fix/hysteria2/root-cause.md （QPACK Huffman H=1 → InvalidFrame，认证解码阶段）覆盖为 E_NEXUS_CODEC，实证为同一失败 |
| Hysteria2 | Default | Reconnect | 2 | FAIL E_NEXUS_CODEC | FAIL | E_NEXUS_CODEC | yes | PIV-hysteria2-default-reconnect-20261024T214232Z-001 | evidence/hysteria2/default/reconnect/PIV-hysteria2-default-reconnect-20261024T214232Z-001 | probe 原始 error.class=E_NEXUS_FRAMING；按 fix/hysteria2/root-cause.md （QPACK Huffman H=1 → InvalidFrame，认证解码阶段）覆盖为 E_NEXUS_CODEC，实证为同一失败 |

step2 预测吻合：25/25

## 步骤 3 — VLESS 惰性响应头合入后复验（10 格）

| protocol | variant | cell | step | predicted | actual verdict | actual class | match? | evidence_id | evidence path | note |
|---|---|---|---|---|---|---|---|---|---|---|
| Vless | Default | Handshake | 3 | PASS - | PASS | - | yes | PIV-vless-default-handshake-20261024T214820Z-001 | evidence/vless/default/handshake/PIV-vless-default-handshake-20261024T214820Z-001 | - |
| Vless | Default | TcpSmall | 3 | PASS - | PASS | - | yes | PIV-vless-default-tcp-small-20261024T214824Z-001 | evidence/vless/default/tcp-small/PIV-vless-default-tcp-small-20261024T214824Z-001 | - |
| Vless | Default | TcpThroughput | 3 | PASS - | PASS | - | yes | PIV-vless-default-tcp-throughput-20261024T214827Z-001 | evidence/vless/default/tcp-throughput/PIV-vless-default-tcp-throughput-20261024T214827Z-001 | T2 3 样本中位数见 probe.json metrics |
| Vless | Default | LongLived | 3 | PASS - | PASS | - | yes | PIV-vless-default-long-lived-20261024T214832Z-001 | evidence/vless/default/long-lived/PIV-vless-default-long-lived-20261024T214832Z-001 | - |
| Vless | Default | Reconnect | 3 | PASS - | PASS | - | yes | PIV-vless-default-reconnect-20261024T215026Z-001 | evidence/vless/default/reconnect/PIV-vless-default-reconnect-20261024T215026Z-001 | - |
| Vless | Default | UdpEcho | 3 | PASS - | PASS | - | yes | PIV-vless-default-udp-echo-20261024T215033Z-001 | evidence/vless/default/udp-echo/PIV-vless-default-udp-echo-20261024T215033Z-001 | - |
| Vless | Default | BadCredential | 3 | PASS - | PASS | - | yes | PIV-vless-default-bad-credential-20261024T215038Z-001 | evidence/vless/default/bad-credential/PIV-vless-default-bad-credential-20261024T215038Z-001 | - |
| Vless | Default | BadConfig | 3 | PASS - | PASS | - | yes | PIV-vless-default-bad-config-20261024T215041Z-001 | evidence/vless/default/bad-config/PIV-vless-default-bad-config-20261024T215041Z-001 | - |
| Vless | VlessVision | Handshake | 3 | PASS - | PASS | - | yes | PIV-vless-vless-vision-handshake-20261024T215044Z-001 | evidence/vless/vless-vision/handshake/PIV-vless-vless-vision-handshake-20261024T215044Z-001 | - |
| Vless | VlessVision | TcpSmall | 3 | PASS - | PASS | - | yes | PIV-vless-vless-vision-tcp-small-20261024T215048Z-001 | evidence/vless/vless-vision/tcp-small/PIV-vless-vless-vision-tcp-small-20261024T215048Z-001 | - |

step3 预测吻合：10/10
