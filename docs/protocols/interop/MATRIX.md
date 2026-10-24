# 出站协议互操作证据总表（MATRIX）

> 本文件由 `scripts/interop/recompute-verdicts.py` 从证据机械生成；人工零编辑。

| 项 | 值 |
|---|---|
| run | protocol-interop-verification |
| baseline | 0539169e8195944fcd183e7831e5d5ac746f3f40 |
| spec | frozen v1.1（sha256 23c7e4e797ee9edbf0eb645bfc20a7c97cfacb30e1a67bd8fee77ccbc527de4f） |
| sing-box | 1.13.16（9ff0345fde4157a6bdab45a615668d41ccc93f6d0f361108042a48b8a49a9baa  sing-box-1.13.16-linux-amd64-musl.tar.gz） |
| Xray | 26.10.21（0eec3ed4163c273d8c8bf821f7d219e257921cf584aa3fb970715e458e631978  Xray-linux-64.zip） |
| test window | 2026-10-24T17:16:12Z .. 2026-10-24T17:16:12Z |
| archive | （S30 归档后追加） |

## 协议 verdict（按 spec E1 复算）

| 协议 | verdict | scope | claim | root_cause_class | missing_cells | 命中规则 |
|---|---|---|---|---|---|---|
| Vless | BROKEN | PROTOCOL_SUBSET | NOT_USABLE | E_NEXUS_HANDSHAKE_WIRE | Handshake(FAIL,E_NEXUS_HANDSHAKE_WIRE) | 2 |
| Anytls | NOT_RUN | — | NOT_CLAIMED | — | — | allow-partial |
| Hysteria2 | NOT_RUN | — | NOT_CLAIMED | — | — | allow-partial |
| Trojan | NOT_RUN | — | NOT_CLAIMED | — | — | allow-partial |
| Shadowsocks | NOT_RUN | — | NOT_CLAIMED | — | — | allow-partial |

## Vless

| Cell | 状态 | carrier | scope | evidence_id | 关键数字/错误 | 证据路径 | notes |
|---|---|---|---|---|---|---|---|
| Default/Handshake | FAIL | ProductSocks5 | ProductPath | PIV-vless-default-handshake-20261024T171612Z-001 | up=0B down=0B E_NEXUS_HANDSHAKE_WIRE | evidence/vless/default/handshake/PIV-vless-default-handshake-20261024T171612Z-001/probe.json | proxy_error=ConnectivityEstablishmentFailed { provider: ProviderId("ref"), reason: "vless response read failed: vless io error" }; workload_error=tunnel read: Connection reset by peer (os error 104); proxy JSON unavailab |
| Default/TcpSmall | MISSING | — | — | — | 缺格 | — | E_EVIDENCE_GAP |
| Default/TcpThroughput | MISSING | — | — | — | 缺格 | — | E_EVIDENCE_GAP |
| Default/LongLived | MISSING | — | — | — | 缺格 | — | E_EVIDENCE_GAP |
| Default/Reconnect | MISSING | — | — | — | 缺格 | — | E_EVIDENCE_GAP |
| Default/UdpEcho | MISSING | — | — | — | 缺格 | — | E_EVIDENCE_GAP |
| Default/BadCredential | MISSING | — | — | — | 缺格 | — | E_EVIDENCE_GAP |
| Default/BadConfig | MISSING | — | — | — | 缺格 | — | E_EVIDENCE_GAP |
| VlessVision/Handshake | MISSING | — | — | — | 缺格 | — | E_EVIDENCE_GAP |
| VlessVision/TcpSmall | MISSING | — | — | — | 缺格 | — | E_EVIDENCE_GAP |

## Anytls

| Cell | 状态 | carrier | scope | evidence_id | 关键数字/错误 | 证据路径 | notes |
|---|---|---|---|---|---|---|---|
| Default/Handshake | MISSING | — | — | — | 缺格 | — | E_EVIDENCE_GAP |
| Default/TcpSmall | MISSING | — | — | — | 缺格 | — | E_EVIDENCE_GAP |
| Default/TcpThroughput | MISSING | — | — | — | 缺格 | — | E_EVIDENCE_GAP |
| Default/LongLived | MISSING | — | — | — | 缺格 | — | E_EVIDENCE_GAP |
| Default/Reconnect | MISSING | — | — | — | 缺格 | — | E_EVIDENCE_GAP |
| Default/PaddingDiag | MISSING | — | — | — | 缺格 | — | E_EVIDENCE_GAP |
| Default/UdpEcho | MISSING | — | — | — | 缺格 | — | E_EVIDENCE_GAP |
| Default/BadCredential | MISSING | — | — | — | 缺格 | — | E_EVIDENCE_GAP |
| AnyTlsCustomPadding/BadConfig | MISSING | — | — | — | 缺格 | — | E_EVIDENCE_GAP |

## Hysteria2

| Cell | 状态 | carrier | scope | evidence_id | 关键数字/错误 | 证据路径 | notes |
|---|---|---|---|---|---|---|---|
| Default/TcpSmall | MISSING | — | — | — | 缺格 | — | E_EVIDENCE_GAP |
| Default/TcpThroughput | MISSING | — | — | — | 缺格 | — | E_EVIDENCE_GAP |
| Default/LongLived | MISSING | — | — | — | 缺格 | — | E_EVIDENCE_GAP |
| Default/Reconnect | MISSING | — | — | — | 缺格 | — | E_EVIDENCE_GAP |
| Default/Handshake | MISSING | — | — | — | 缺格 | — | E_EVIDENCE_GAP |
| Hy2Salamander/Handshake | MISSING | — | — | — | 缺格 | — | E_EVIDENCE_GAP |
| Default/QpackDiag | MISSING | — | — | — | 缺格 | — | E_EVIDENCE_GAP |
| Default/UdpEcho | MISSING | — | — | — | 缺格 | — | E_EVIDENCE_GAP |
| Default/BadCredential | MISSING | — | — | — | 缺格 | — | E_EVIDENCE_GAP |
| Default/BadConfig | MISSING | — | — | — | 缺格 | — | E_EVIDENCE_GAP |

## Trojan

| Cell | 状态 | carrier | scope | evidence_id | 关键数字/错误 | 证据路径 | notes |
|---|---|---|---|---|---|---|---|
| Default/Handshake | MISSING | — | — | — | 缺格 | — | E_EVIDENCE_GAP |
| Default/TcpSmall | MISSING | — | — | — | 缺格 | — | E_EVIDENCE_GAP |
| Default/TcpThroughput | MISSING | — | — | — | 缺格 | — | E_EVIDENCE_GAP |
| Default/LongLived | MISSING | — | — | — | 缺格 | — | E_EVIDENCE_GAP |
| Default/Reconnect | MISSING | — | — | — | 缺格 | — | E_EVIDENCE_GAP |
| Default/UdpEcho | MISSING | — | — | — | 缺格 | — | E_EVIDENCE_GAP |
| Default/BadCredential | MISSING | — | — | — | 缺格 | — | E_EVIDENCE_GAP |
| TrojanFallback/BadCredential | MISSING | — | — | — | 缺格 | — | E_EVIDENCE_GAP |
| Default/BadConfig | MISSING | — | — | — | 缺格 | — | E_EVIDENCE_GAP |

## Shadowsocks

| Cell | 状态 | carrier | scope | evidence_id | 关键数字/错误 | 证据路径 | notes |
|---|---|---|---|---|---|---|---|
| Default/Handshake | MISSING | — | — | — | 缺格 | — | E_EVIDENCE_GAP |
| Default/TcpSmall | MISSING | — | — | — | 缺格 | — | E_EVIDENCE_GAP |
| Default/TcpThroughput | MISSING | — | — | — | 缺格 | — | E_EVIDENCE_GAP |
| Default/LongLived | MISSING | — | — | — | 缺格 | — | E_EVIDENCE_GAP |
| Default/Reconnect | MISSING | — | — | — | 缺格 | — | E_EVIDENCE_GAP |
| Default/UdpEcho | MISSING | — | — | — | 缺格 | — | E_EVIDENCE_GAP |
| Default/BadCredential | MISSING | — | — | — | 缺格 | — | E_EVIDENCE_GAP |
| Default/BadConfig | MISSING | — | — | — | 缺格 | — | E_EVIDENCE_GAP |

## 产品级 UDP（不参与协议 verdict）

产品 SOCKS5 入口 `crates/nexus-ingress/src/lib.rs:232-241` 拒绝 BND/UDP ASSOCIATE；Trojan/SS 出站也没有 UDP 帧路径。因此产品级 UDP 按能力缺口记录，不进入五协议 verdict；crate 级 UDP 结论见各协议 `UdpEcho` 行。

## 产品能力缺口

- 产品级 UDP：未实现（上节）。
- Vision：产品路径只编码 addon，不实现 splice；本 run 的 Vision 结论来自 crate 直调。
- Hysteria2：端口跳跃/Brutal/gecko/分片不在范围。
- AnyTLS：session 池/心跳定时器/padding 写路径不单独验。

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
| PIV-vless-default-handshake-20261024T171612Z-001 | FAIL | ProductSocks5 | ProductPath | evidence/vless/default/handshake/PIV-vless-default-handshake-20261024T171612Z-001/probe.json |

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
