---
id: proxy-outbound-dataplane
date: 2026-09-24
module: apps/nexus
category: implementation-pattern
task_type: feature
---

# 节点加密出站数据面（proxy_serve_once 按 outbound.kind 分流）

## 问题/模式描述

nexusd proxy 数据面出口原为直连 TcpStream（§11.4）。要让节点型出站（shadowsocks /
trojan / vmess）真实走加密隧道，需在 SOCKS5 会话闭环里按 selected outbound 的 kind
分流建立隧道，并新增可观察字段（routing.outbound_kind / outbound）。

## 关键实现要点

- 在 proxy_serve_once 第 4 步查 config.outbounds 定位 selected outbound，match kind：
  - direct → 原直连逻辑原样（零回归）
  - shadowsocks → connect locator → SsStream(Role::Client) → seal(encode_request(SsTarget))
    写加密 request header → 双向 record 帧中继
  - trojan / vmess / relay → 本期未冻结 E4，结构化 ConnectivityEstablishmentFailed
    （不静默直连）
- SS 双向中继用**两个独立 SsStream 实例**（TX 线程只 seal、RX 线程只 open；RX 用帧内
  nonce，不依赖本地计数器，跨实例安全）。主流程先写 request header（TX counter 已 +1），
  再把 TX 实例 move 进 client→node 线程。
- EOF（UnexpectedEof）是 SS 中继的正常结束信号；`loop + match read_record` 会触发
  clippy while_let_loop，直接写 `while let Ok(frame) = read_record(...)`。
- OutboundKind 枚举有 Direct/Relay/Shadowsocks/Vmess/Trojan 五个变体，match 必须全盖。

## 踩坑

- Edit/Read 工具对超大数据文件（PRODUCT.md 113KB、lib.rs 6.9K 行）反复报
  "File has not been read yet"——改用 PowerShell 脚本（[IO.File]::ReadAllText +
  Replace + WriteAllText UTF8 无 BOM）做精确锚点替换，可靠。
- PRODUCT.md 是 CRLF/LF 混合换行：字符串锚点含换行会失配，用行号定位或纯文本锚点
  （不含换行符）最稳。
- cargo run 启动的 example 进程卡住时会锁住 exe 导致 LNK1104；先
  Stop-Process 再重编译。
- 旧实现下 SS server 永不收到连接：非阻塞 accept + 轮询超时让场景能正常退出并输出
  FAIL（否则 join 永久阻塞）。
