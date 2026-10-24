# 互操作修复路线（NEXT-STEPS）

> 本文件为人工维护，不属于 `scripts/interop/recompute-verdicts.py` 的生成产物。
> 证据与 verdict 正本仍以 [MATRIX.md](MATRIX.md) 为准；本文件只排修复顺序、依赖与复验口径，
> **不改变任何技术 verdict**。

## 0. 当前状态

- 五协议（VLESS、AnyTLS、Hysteria2、Trojan、Shadowsocks）全部 `BROKEN / NOT_USABLE`。
- 本轮未发现参照端生态缺陷；sing-box 1.13.16 行为符合规范，Xray 26.10.21 仅用于 Vision 争议裁决且未触发。
- Trojan/SS 即使全部修完，本 run 的 `UdpEcho` 固定 `NOT_IMPLEMENTED`，上限仍是
  `PARTIAL / TCP_ONLY / USABLE_WITH_GAPS`（spec E1 规则 6/R11）。不要用「修完就 VERIFIED」做产品承诺。
- VLESS fix（`fix/protocol-interop-vless-lazy-response`）已实现并完成专项复验（R-01 PASS）；
  合入与 verdict 更新待 fix 流程另行裁决。即使合入，T2 仍受 transport 阻塞。

## 1. 顺序、依赖与验收

| 顺序 | 动作 | 依赖 | 预期产品结果（需按 fix 流程复验，非本环节改判） | 成本/风险 | 复验口径 |
|---|---|---|---|---|---|
| **P0** | **安全止血（文档/配置面，0 代码）**：把 Trojan fallback 静默成功列为最高级已知风险；MATRIX 顶部警示；含 fallback 的 Trojan 配置加实验性标注/警示，或由产品负责人决定默认禁用 | 无 | 用户不会在「以为在走代理」时静默收到 404 内容；满足白皮书 §6.2「显示实际行为」的最低要求 | 极低；是否改配置面文案由产品负责人拍板 | 文档评审通过；配置说明含 fallback 风险；不改 verdict |
| **P1** | **跨协议 transport 批量写**：`PendingWrite` + 4 个 arm（Trojan/AnyTLS/VLESS×2/Hy2）接入，背压语义，逐协议回归 | 无（其它修复的共同前置） | 预期 AnyTLS 首先达到可用（只差这一格）；为 VLESS/Trojan/Hy2 的 T2 解锁；唯一能「一格修多协议」的杠杆 | ~240–260 行；跨协议回归是最大风险，验证成本高于行数 | 五协议 T2 重跑 + T1/L/R 回归；AnyTLS 达到 `VERIFIED` 才可改其 verdict |
| **P2** | **VLESS fix 合入 + 复验**：合入 `fix/protocol-interop-vless-lazy-response`（~100 行），与 transport 修复一起复验 H/T1/T2/L/R | P1（T2 仍会被它挡住） | VLESS 预期成为首个 `VERIFIED / PROTOCOL_SUBSET`（Vision 仍是 crate 级，产品 splice 未实现） | 低；fix 已实现并专项复验，风险主要在合入流程 | H/T1/T2/L/R 全 PASS；T2 不再出现 `E_NEXUS_FRAMING`/`E_NEXUS_TRANSPORT` |
| **P3** | **Hy2 QPACK Huffman**：RFC 7541 附录 B 码表 + 解码 + 金样测试 | P1（认证过后还有 T2） | Hy2 预期达到 `VERIFIED / FULL`；否则至少认证/握手/小流量可通 | ~300–400 行，1–1.5 人日；Huffman 表逐项对齐风险 | 认证响应解码成功；H/Hy2Salamander/T1/L/R/U/F1 逐格重跑；T2 过 transport 后复验 |
| **P4** | **SS SIP004 AEAD**：salt + `EVP_BytesToKey`（MD5）+ HKDF-SHA1 + LE nonce + 标准分块 | P1 | SS 可到 `PARTIAL / TCP_ONLY / USABLE_WITH_GAPS`（U 仍未实现，本 run schema 到不了 VERIFIED） | ~250–350 行，1.5–2 人日；会波及 loopback 测试的自洽格式 | 与 sing-box 参照端互操作 H/T1/T2/L/R 通过；U 仍记 `NOT_IMPLEMENTED` |
| **P5** | **Trojan fallback 完整语义**：延迟 SOCKS5 success 至上游就绪，或等价 fail-closed 方案 | P1；产品架构决策 | Trojan 可到 `PARTIAL / TCP_ONLY / USABLE_WITH_GAPS`（U 未实现）；若产品 UDP 补齐，才可能更高 | >400 行 / >2 人日；触及 `proxy_serve_once` 全部出站路径，应另立 run | 错凭据/fallback 场景下不再把 404 内容当隧道数据；失败对用户可观察 |
| **并行** | **产品决策**：五协议在配置面标注「实验性/未验证」，对外不宣称支持；优先让 AnyTLS/VLESS 达到首个可用 | 无 | 避免用户按 USER_MANUAL/配置面误以为可用；把「验证结论」转成「产品承诺边界」 | 文档/文案层；若下架配置面则需产品决策 | MATRIX、USER_MANUAL、配置说明三处口径一致 |

## 2. 顺序理由（与文档枚举顺序的差异）

1. Trojan fallback 是**安全语义**问题，不是「功能没做完」；止血是 0 代码，不应排在工程项之后。
2. VLESS fix 已完工并经过专项核验，唯一缺的是 transport，故应在 transport 后立即合入复验。
3. 工程关键路径仍是 **transport 第一**：它是唯一「一格修多协议」的杠杆，也是 VLESS/Trojan/Hy2 T2 的共同前置。
4. Trojan/SS 的「可达上限」必须提前告知：本 run 的 U 格固定 `NOT_IMPLEMENTED`，二者最高
   `PARTIAL / USABLE_WITH_GAPS`。

## 3. 回归面

- transport 改动横跨 4 个协议 arm 的两个方向；任何一处置错都会引入新的半关闭/丢字节问题。
- Hy2 的 T2 走 QUIC stream 写路径，与 TCP arm 的回归方式不同。
- SS 改线格式会波及 loopback 测试使用的自洽格式，需要同时迁移测试或保留旧格式仅用于测试。
- 每次修复后都必须重跑 `recompute-verdicts.py --check`，确保生成物与证据、`analysis/verdicts.json` 零漂移。
