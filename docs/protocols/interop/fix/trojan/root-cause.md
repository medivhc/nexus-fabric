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

## 量化估算
- 方案 2 涉及 proxy_serve_once 握手时序与所有出站路径：>400 行 / >2 人日 → **不满足硬门**。
- 本 run 结论：按 spec E1 规则 1 判 Trojan BROKEN；修复升级 coordinator 决策。

## 终局状态更正

- 本文写于终局重跑之前：正文中“正常认证路径 H/T1/T2/L/R 全部 PASS”已过时。
- 终局 T2（`PIV-trojan-default-tcp-throughput-20261024T175446Z-001`）= **FAIL** + `E_NEXUS_TRANSPORT`（WouldBlock 批量写缺陷）；H/T1/L/R = PASS；F1-fallback = FAIL + `E_NEXUS_FRAMING`（本文主题）。
- 正文证据路径漏了 `-bad-credential` 段，正确路径为 `evidence/trojan/trojan-fallback/bad-credential/PIV-trojan-trojan-fallback-bad-credential-20261024T173217Z-001/`。
- 终局取值以 `docs/protocols/interop/MATRIX.md` 的 `Trojan` 节 `Default/TcpThroughput`、`TrojanFallback/BadCredential` 行为准。
