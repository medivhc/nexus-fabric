# Hysteria2 认证响应解码失败 — 根因报告（S27）

- 协议/格：Hysteria2 Default（plain）与 Hy2Salamander；Handshake/TcpSmall/TcpThroughput/LongLived/Reconnect/UdpEcho 全失败
- 证据：`evidence/hysteria2/default/handshake/PIV-hysteria2-default-handshake-20261024T173039Z-001/probe.json`（错误 `hysteria2 invalid frame`）；`analysis/qpack/source-refs.md`（源码判定）
- 参照：sing-box 1.13.16（sha256 9ff0345f…）；sing-quic d83826c306d7；quic-go v0.59.0-sing-box-mod.4；qpack v0.6.0

## 现象
产品 SOCKS5 → Hy2 出站（QUIC/TLS）到 sing-box。`Hysteria2Client::connect` 在读取认证 HEADERS
响应时返回 `Hysteria2Error::InvalidFrame`，产品错误 `hysteria2 connect/auth ... failed: hysteria2 invalid frame`。
plain 与 salamander 一致；错密码（F1）与 obfs 不匹配（F2）按预期被拒绝并 PASS。

## 根因
`crates/nexus-outbound-hysteria2/src/qpack.rs` 的 QPACK 子集**不实现 Huffman（H 位）**：
`decode_string`（约 `:150-160`）遇到 `H=1` 直接 `InvalidFrame`。
服务端（sing-box 1.13.16 → sing-quic → quic-go http3）用 `qpack.Encoder` 编码认证响应：
- `:status: 233` 走“静态名引用 + 字面值”，值 Huffman；
- `hysteria-udp` / `hysteria-cc-rx` / `hysteria-padding` 名字不在静态表，名字与值均 Huffman。
源码文件/行号见 `analysis/qpack/source-refs.md`（B-3：未使用 keylog，采用固定版本源码判定）。

## 影响面
- 所有 Hy2 产品路径与 crate UDP 路径（认证阶段即失败）。
- 负向格（F1/F2）不受影响（认证被拒，不进入响应解码分支）。

## 修复路径（路径 B：QPACK 能力补齐）
按 RFC 7541 附录 B 增加 Huffman 解码表与 `decode_string` 的 H=1 分支。

## 量化估算
- 静态 Huffman 表（257 项）+ 解码器 + 单测：约 **300–400 行**，1–1.5 人日。
- 关键风险：Huffman 表与 RFC 逐项对齐；需要与 qpack v0.6.0 编码结果做金样往返。
- 结论：**在硬门上限附近**（≤400 行 / ≤2 人日）。本 run 先定性并升级，不在 verify 分支改协议 crate
  （B-3 明确禁止为诊断改协议 crate；修复需独立 fix 分支 + 独立 review）。

## 终局状态更正

- 本文写于终局重跑之前：正文中“错密码（F1）与 obfs 不匹配（F2）按预期被拒绝并 PASS”已过时。
- 终局 F1（`PIV-hysteria2-default-bad-credential-20261024T180645Z-001`）= **FAIL**：85a6bb8 之后 probe 不再把客户端解码失败当参照端拒绝，probe 记录 `Blocked + E_NEXUS_CODEC`，复算按 D1 映射为 FAIL（推导见 `analysis/classification/PIV-hysteria2-default-bad-credential-20261024T180645Z-001.json`）。
- F2（BadConfig，`PIV-hysteria2-default-bad-config-20261024T173059Z-001`）= PASS。
- 终局取值以 `docs/protocols/interop/MATRIX.md` 的 `Hysteria2` 节 `Default/BadCredential`、`Default/BadConfig` 行为准。
