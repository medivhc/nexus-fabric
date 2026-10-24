# VLESS 产品路径握手死锁 — 根因报告（S27）

- 协议/格：VLESS Default；Handshake / TcpSmall / TcpThroughput / LongLived / Reconnect 全失败
- 证据：`evidence/vless/default/handshake/PIV-vless-default-handshake-20261024T172249Z-001/`（pcap + probe.json + ref log）
- 参照：sing-box 1.13.16（sha256 9ff0345f…；config `vless-basic` sha256 见 evidence/ref-config）

## 现象
产品 SOCKS5 入站 → VLESS 出站（TLS）到 sing-box。probe 的 SOCKS5 客户端先完成 CONNECT 应答，
再发送载荷（普通客户端行为）。probe 侧表现为：
- `proxy_error=ConnectivityEstablishmentFailed{ reason="vless response read failed: vless io error" }`
- 客户端 tunneling 读 `Connection reset by peer`
- 全部 5 个 TCP 成功型格 FAIL；F1（错 UUID）/F2（flow 不匹配）正常拒绝；UDP 与 Vision（crate 直调）PASS。

## 抓包时序（pcap 14 包，filter `port 26100`）
- t=0：client → ref 完整 TLS 握手 + VLESS 请求头 + 1 字节载荷（Application Data）。
- t≈0：ref 已接受请求并拨号到目标（sing-box log `outbound connection to 127.0.0.1:26200`）。
- t=0 到 t≈10.08s：**ref 未向 client 发送任何 Application Data**。
- t≈10.08s：client 因 10s 读超时发出 FIN，随后 ref 才发送 24 字节 Application Data。
- target 计数（probe 的同进程目标端）：selfcheck 连接 1 字节；**产品连接 0 字节**——载荷从未经产品上行。

## 根因（first wrong place）
`apps/nexus/src/lib.rs:4482-4515` `vless_handshake_stream` 在把控制权交给中继泵之前**同步阻塞**
调用 `nexus_outbound_vless::read_response(inner)`（`:4509`）。此时：
1. 产品 pump 尚未启动（`:5747` / `:5773` 调用点之后才 pump），client 后续载荷无法写入 node；
2. sing-box 的 VLESS 响应头并非连接建立即发，而是随目标首批数据一起下发；
3. 目标端要收到载荷才回显 → 形成闭环等待，10s 读超时后断开。

协议 crate 的 `VlessConn` 本就实现“响应头惰性读”（第一次 read 才消费），产品绕过了该纪律。

## 与规范差异
`docs/protocols/vless.md` §2.1 的惰性读纪律（crate `VlessConn` 已编码）。产品在装配层重新引入
eager read，属于产品装配缺陷，不是参照端行为问题，也不是 crate 缺陷。

## 影响面
- 所有 VLESS TCP 产品路径（普通 SOCKS5 客户端不 pipeline 首包时必挂）；H/T1/T2/L/R。
- 负向格（F1/F2）不受影响（服务端直接关闭，响应头读取很快 EOF）。
- VLESS UDP / Vision（crate 直调）不受影响。
- 不涉及产品配置面/新入口。

## 修复方案（路径 A：局部装配 bug）
不在 `vless_handshake_stream` 读响应头；在 `vless_pump_stream` 的 node→client 方向加一个
“跳过 VLESS 响应头”的状态机（`version(1) + addon_len(1) + addon`，通常 2 字节），跳过后按原样中继。
TLS 与明文两条路径共用同一泵，一处修复覆盖两路。

## 量化估算
- 代码：`vless_handshake_stream` 删 10 行；`vless_pump_stream` 新增 ~30 行状态机；单测 ~60 行。
- 合计约 **100 行 / 0.5 人日**，低于本 run 硬门（≤400 行且 ≤2 人日）。
