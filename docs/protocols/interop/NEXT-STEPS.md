# 互操作修复路线（NEXT-STEPS）

> 本文件为人工维护，不属于 `scripts/interop/recompute-verdicts.py` 的生成产物。
> 证据与 verdict 正本仍以 [MATRIX.md](MATRIX.md) 为准；本文件只排修复顺序、依赖与复验口径，
> **不改变任何技术 verdict**。

## 0. 当前状态

- 2 个协议 `VERIFIED`：VLESS（`PROTOCOL_SUBSET / USABLE`）、AnyTLS（`FULL / USABLE`）；
  1 个协议 `PARTIAL / TCP_ONLY / USABLE_WITH_GAPS`：Shadowsocks（`fixes-2`，本 run：
  SIP004 互操作已通，仅剩产品 UDP 缺口）；2 个协议 `BROKEN / NOT_USABLE`：Hysteria2、Trojan。
  上述 SS 结论是**矩阵口径**（crate + SOCKS5 产品路径）：**nexusd TUN 路径不在覆盖内**，
  不得读作「生产 SS 已修好」。逐格判定、`missing_cells` 与命中规则见 [MATRIX.md](MATRIX.md) 的「协议 verdict」表。
- 本 run 已完成两项翻转修复：跨协议 transport 批量写（commit `60e6029`）与 VLESS 惰性响应头
  读取（commit `43ca7ac`）。修复前后预测与逐格证据见
  [prediction-check.md](prediction-check.md)（步骤 2 `25/25`、步骤 3 `10/10`）。
- 本轮未发现参照端生态缺陷；sing-box 1.13.16 行为符合规范，Xray 26.10.21 仅用于 Vision
  争议裁决且未触发。
- 结论广度：仅对 sing-box 1.13.16 参照配置成立；其他服务端实现/传输组合（含 REALITY、
  ws/grpc）未测。
- `USABLE` 指 TCP 产品路径；产品 SOCKS5 UDP ASSOCIATE 五协议均未实现，`UdpEcho` 为 crate
  级证据、不代表产品入口可用。
- Trojan/SS 即使其余修复全部完成，本 run 的 `UdpEcho` 固定 `NOT_IMPLEMENTED`，上限仍是
  `PARTIAL / TCP_ONLY / USABLE_WITH_GAPS`（spec E1 规则 6/R11）。
  **不要用「修完就 VERIFIED」做产品承诺。**
- 配置面标注（BROKEN 两协议（Hysteria2、Trojan）「未验证/不可用」、含 fallback 的 Trojan 警示）已裁决批准，
  待 `protocol-config-surface-labeling` run 落地；本轮不改产品代码。

## 1. 顺序、依赖与验收

| 顺序 | 动作 | 依赖 | 状态 / 结果 | 成本/风险 | 复验口径 |
|---|---|---|---|---|---|
| **P0a** | **安全止血·文档警示**：公开 Trojan fallback fail-open，MATRIX 顶部警示与白皮书映射 | 无 | **DONE**（见 [MATRIX.md](MATRIX.md) 安全警示节） | 极低；纯文档 | 文档评审通过；不改 verdict |
| **P0b** | **安全止血·配置面标注**：BROKEN 两协议（Hysteria2、Trojan）加「未验证/不可用」标注；含 fallback 的 Trojan 加警示或默认禁用 | 产品负责人裁决 | **已裁决批准，待 `protocol-config-surface-labeling` run 落地**（本轮不改产品代码） | 低；文案/配置层 | 该 run 落地后核对配置面、USER_MANUAL 与 MATRIX 口径一致 |
| **P1** | **跨协议 transport 批量写**：`PendingWrite` + Trojan/AnyTLS/VLESS×2/Hy2 四个 arm 接入 | 无 | **DONE**（commit `60e6029`）：AnyTLS 由 T2 单格阻塞转为 `VERIFIED / FULL`；VLESS/Trojan/Hy2 的 T2 解锁 | 已完成；跨协议回归已由 prediction-check 步骤 2 覆盖 | prediction-check 步骤 2（`25/25`）；五协议 T2 + T1/L/R 回归 |
| **P2** | **VLESS fix 合入 + 复验**：合入惰性响应头修复，与 transport 修复一起复验 H/T1/T2/L/R | P1 | **DONE**（commit `43ca7ac`）：VLESS 转为 `VERIFIED / PROTOCOL_SUBSET`；Vision 仍为 crate 级，产品 splice 未实现 | 已完成；风险主要在合入流程，现已关闭 | prediction-check 步骤 3（`10/10`）；H/T1/T2/L/R 全 PASS |
| **P3** | **SS SIP004 AEAD**：salt + `EVP_BytesToKey`（MD5）+ HKDF-SHA1 + LE nonce + 标准分块（`fixes-2`，用户第一优先） | 无 | **DONE**（`fixes-2`，commit `ebc652e`）：SS crate 与 SOCKS5 产品路径达 SIP004 互操作，矩阵 verdict `PARTIAL / TCP_ONLY / USABLE_WITH_GAPS`（7 格新证据全 PASS + 独立 KAT）。nexusd TUN 路径不在覆盖内，不表述为「生产 SS 已修好」 | 已完成；U 仍未实现，故本 run schema 到不了 VERIFIED | 与 sing-box 参照端互操作 H/T1/T2/L/R 通过；U 仍记 `NOT_IMPLEMENTED` |
| **P4** | **Hy2 QPACK Huffman**：RFC 7541 附录 B 码表 + 解码 + 金样测试（`fixes-3`） | 无 | 待办：预期 Hy2 达到 `VERIFIED / FULL`；否则至少认证/握手/小流量可通 | ~300–400 行，1–1.5 人日；Huffman 表逐项对齐风险 | 认证响应解码成功；H/Hy2Salamander/T1/L/R/U/F1 逐格重跑；T2 复验 |
| **P5** | **Hy2 Salamander**：在 QPACK Huffman 修复后单独验证 Salamander 变体（`fixes-4`） | P4 | 待办：Salamander 变体仍需独立证据，不复用 plain 结论 | 中；依赖 P4 的编解码修复 | Salamander 认证/握手/数据传输逐格重跑 |
| **P6** | **Trojan fallback 完整语义**：延迟 SOCKS5 success 至上游就绪，或等价 fail-closed 方案（`fixes-5`） | P0b；产品架构决策 | 待办：Trojan 最高 `PARTIAL / TCP_ONLY / USABLE_WITH_GAPS`（U 未实现）；不许诺修完即 VERIFIED | >400 行 / >2 人日；触及 `proxy_serve_once` 全部出站路径，应另立 run | 错凭据/fallback 场景下不再把 404 内容当隧道数据；失败对用户可观察 |
| **P7** | **产品级 UDP**：补齐 SOCKS5 UDP ASSOCIATE 与各协议出站 UDP 帧路径（`fixes-6`） | 产品决策 | 待办：补齐前五协议均不可经产品使用 UDP | 跨入口与出站的大项，需单独立项 | SOCKS5 UDP ASSOCIATE 成功；各协议 crate 级与产品级 UDP 证据分离记录 |

## 2. 顺序理由

1. **P0 拆成文档与配置面两行**：文档警示已在本 run 落地；配置面标注的裁决已批准，但实施属
   独立 run，不能再用「待产品负责人决定」掩盖其已到期状态。
2. **P1/P2 已完成**：transport 是唯一「一格修多协议」的杠杆，VLESS 惰性响应头紧随其后合入；
   两项合并产生本 run 的 VLESS/AnyTLS 翻转，证据见 prediction-check 步骤 2/3。
3. **SS 第一优先**：`fixes-2` 已立项且是用户当前第一优先；SS 修复后最高仍是
   `PARTIAL / TCP_ONLY / USABLE_WITH_GAPS`，不得承诺 VERIFIED。
4. **Hy2 先 QPACK Huffman 后 Salamander**：plain 路径的认证解码是 Salamander 变体的前置；
   `fixes-3` / `fixes-4` 分别验收，避免用一个修复的结论覆盖另一个变体。
5. **Trojan fallback 排在其后**：这是安全语义与架构改动（P6 / `fixes-5`），不是简单编解码修复；
   产品 UDP（P7 / `fixes-6`）补齐前，Trojan/SS 的 `UdpEcho` 仍是 `NOT_IMPLEMENTED`。
6. **上限口径不变**：Trojan/SS 本 run schema 最高 `PARTIAL / TCP_ONLY / USABLE_WITH_GAPS`；
   任何「修完即 VERIFIED」的说法都超出现有证据与 E1 规则。

## 3. 回归面

- transport 改动横跨 4 个协议 arm 的两个方向；任何一处置错都会引入新的半关闭/丢字节问题。
  本 run 已通过 prediction-check 步骤 2 覆盖，后续改动仍需重跑相关协议 T2 + T1/L/R。
- Hy2 的 T2 走 QUIC stream 写路径，与 TCP arm 的回归方式不同；QPACK Huffman 与 Salamander
  需要分别验证。
- SS 改线格式会波及 loopback 测试使用的自洽格式，需要同时迁移测试或保留旧格式仅用于测试。
- 每次修复后都必须重跑 `recompute-verdicts.py --check`，确保生成物与证据、`analysis/verdicts.json`
  零漂移。

## 4. 已立项存根

| run | 范围 | 前置 |
|---|---|---|
| `protocol-config-surface-labeling` | 配置面标注/暴露裁决落地（P0b） | 无 |
| `fixes-2` | SS SIP004 AEAD（P3） | 无 |
| `fixes-3` | Hy2 QPACK Huffman（P4） | 无 |
| `fixes-4` | Hy2 Salamander（P5） | `fixes-3` |
| `fixes-5` | Trojan fallback 完整语义（P6） | `protocol-config-surface-labeling` / 产品架构决策 |
| `fixes-6` | 产品级 UDP（P7） | 产品决策 |
