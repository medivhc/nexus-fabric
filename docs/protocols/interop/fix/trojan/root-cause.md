# Trojan fallback 静默成功 — 根因报告（S27 / B-6）

- 协议/格：Trojan `trojan-fallback` + `BadCredential`（F1-fallback）
- 证据：`evidence/trojan/trojan-fallback/bad-credential/PIV-trojan-trojan-fallback-20261024T173217Z-001/`
- 参照：sing-box 1.13.16，`trojan-fallback`（listen 26115，fallback → 127.0.0.1:26203 HTTP 404）

## 现象
错密码时 sing-box 按 fallback 配置把连接转给 HTTP 404 服务；产品把 404 响应体当隧道数据
回给 SOCKS5 客户端（SOCKS5 CONNECT 已回 success），probe 收到非 echo 字节。
probe 判 `FAIL` + `E_NEXUS_FRAMING`（D1 无“客户端不识别 fallback/静默接受非 echo 响应”专类，取最近类）。

## 根因
产品 Trojan 数据面无“认证失败/非隧道响应”识别：TLS 建连 + 请求头写出后即进入双向字节中继，
不校验服务端首字节是否为合法隧道载荷（Trojan 协议本身无响应头；认证失败由服务端 fallback 表现为任意 HTTP 响应）。
正确行为应是 fail-closed（无法区分真实目标数据与 fallback 响应时，至少不能把非目标 echo 当成功）。

## 影响面
- 仅 Trojan 认证失败场景的语义（安全边界）：客户端得到“成功”连接并收到 404 字节。
- 正常认证路径 H/T1/T2/L/R 全部 PASS，不受影响。

## 修复方案（候选，路径 B）
在 Trojan 出站首个下行字节处引入“目标协议契约”不可行（Trojan 无握手确认）；可选：
1) 文档/契约层面把该行为登记为已知限制（不改代码）；或
2) 产品在 SOCKS5 CONNECT 前不做上游就绪判定（当前架构），改为延迟回 success 直到目标首包。
两者都涉及产品语义/架构，超出本 run “局部 bug”范围。

## 量化估算（已被 fixes-5 实测结论取代）
- 方案 2 涉及 proxy_serve_once 握手时序与所有出站路径：>400 行 / >2 人日 → **不满足硬门**。
- 本 run 结论：按 spec E1 规则 1 判 Trojan BROKEN；修复升级 coordinator 决策。

## 修复结论（protocol-interop-fixes-5，2026-10-26，requirement-change）

方案 2 已实现（`fixes-5`）：**CONNECT 应答暂存 + Trojan 就绪窗口 + 首包分类 + 失败应答**。

- `DeferredConnectReply` 把 `Established` 步的 success 从握手循环里暂存出来；非 trojan
  出站仍在既有逻辑点写出（字节/时机不变），trojan 出站在 TLS 握手 + 请求头 + seed 全部
  flush 之后才决定写 success 还是失败应答。
- 窗口 `W = clamp(节点建连耗时 + 50ms, 50ms, 600ms)`（或 `ready_window_ms` 覆盖
  `min(n,5000)`）：客户端先载荷 → 载荷先写节点再回 success（零扣压）；白名单 greeting
  首包 → 放行；静默到期 → 放行；HTTP 状态行 / 非白名单首包 / 首包前 EOF → 失败应答
  （SOCKS5 `REP≠0` / HTTP 502）+ 有界 drain + FIN，不写额外 TLS 记录。
- 规模：机制 ~300 行（app 行为代码 + `trojan_guard`）+ 验证 ~300 行（probe 失败格 +
  E4 场景/example）；另计配置面 60–80、单测 120、文档 40–90。

**承诺边界（不得写成已关闭全部残余）**：

| # | 残余 | 后果 |
|---|---|---|
| R-1 | fallback 响应慢于 `W`（>1 RTT + 50ms，或 >600ms 上限；显式覆盖过小同理） | success 已写出，窗口外的 fallback 内容仍可能被当隧道数据 |
| R-2 | fallback 等客户端先发载荷才响应 | 零载荷判据失效，同上 |
| R-3 | `signature` 模式下的非 HTTP fallback | 该模式是显式安全降级，漏报属已知代价 |
| R-4 | 客户端在 success 前 pipelined 载荷（seed 非空） | 守卫不适用（扣压又违反上行零扣压） |
| R-5 | `nexusd` TUN / `ProxyEngine` 路径 | 该入口的成功由 smoltcp SYN-ACK 伪造，本 run 不覆盖 |
| R-6 | HTTP 绝对形式转发（non-CONNECT） | 不回本地成功应答，fallback 的 404 仍会作为 origin 响应出现 |
| R-7 | 服务端被完全劫持并伪装成真实目标 | 超出协议可判定范围（需端到端认证/证书钉扎） |

**已接受的行为变更**：无 fallback 的坏凭据由「先 success 再 EOF」变为「CONNECT 应答阶段
`REP≠0`」；MATRIX 判定与 `E_EXPECTED_AUTH_REJECT` 分类不变。误杀面 M-1~M-8 与
`signature` 逃生口代价见 PRODUCT §11.9.3 / USER_MANUAL §4.1.10 / MATRIX 的 Trojan 注记。

## 终局状态更正

- 本文写于终局重跑之前：正文中“正常认证路径 H/T1/T2/L/R 全部 PASS”已过时。
- 终局 T2（`PIV-trojan-default-tcp-throughput-20261024T175446Z-001`）= **FAIL** + `E_NEXUS_TRANSPORT`（WouldBlock 批量写缺陷）；H/T1/L/R = PASS；F1-fallback = FAIL + `E_NEXUS_FRAMING`（本文主题）。
- 正文证据路径漏了 `-bad-credential` 段，正确路径为 `evidence/trojan/trojan-fallback/bad-credential/PIV-trojan-trojan-fallback-bad-credential-20261024T173217Z-001/`。
- 终局取值以 `docs/protocols/interop/MATRIX.md` 的 `Trojan` 节 `Default/TcpThroughput`、`TrojanFallback/BadCredential` 行为准。
