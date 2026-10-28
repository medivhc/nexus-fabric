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
