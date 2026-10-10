# AnyTLS 协议语义文档

> 参考实现：meow-rs（`crates/meow-anytls/`，Rust，anytls-go 的 clean-room 重写）+ 官方协议文档。
> 协议版本：v2（当前）。官方参考实现：[anytls-go](https://github.com/anytls/anytls-go)。

## 1. 协议概述

AnyTLS 是一个基于 TLS 的轻量代理协议，设计目标是解决 "TLS-in-TLS" 嵌套握手指纹问题。它在一条 TLS 连接上承载**会话层多路复用**：多个代理 Stream 复用同一个 TLS Session，每个 Stream 独立开关；通过可配置的 **padding scheme** 对 TLS 包做分包/填充，改变流量特征；心跳机制检测并恢复卡住的隧道。

协议本身**不包含 TLS 参数**（SNI、证书校验、fingerprint 等由外层传输配置决定）。认证极其简单：`SHA256(password)`。

## 2. 握手流程

### 2.1 Session 建立（client 视角）

1. TCP 连接到服务器。
2. 完成 TLS 握手（SNI 等由外层配置提供）。
3. **一次写**发送认证请求（必须合并为一次 `write`，见 §5 坑）：
   - `SHA256(password)`：32 字节
   - `padding0_length`：u16 大端
   - `padding0`：`padding0_length` 字节随机/零填充
4. 发送 **Settings** 帧（cmd=4, stream_id=0），data 为 UTF-8 文本 `key=value\n`：
   - `v=2`（协议版本号）
   - `client=anytls-rs/0.1.0`（实现名，第三方应填真实名）
   - `padding-md5=` 当前 padding scheme 原始字节的 MD5（小写 hex）
5. 等待服务器响应：
   - 若 `padding-md5` 与服务器不一致 → 服务器发 **UpdatePaddingScheme**（cmd=6），data 为服务器的 padding scheme 原始文本；客户端必须切换到该 scheme（作用于该 Client 的后续所有 session）。
   - 若上报 `v >= 2` → 服务器立即发 **ServerSettings**（cmd=10），data 为 `v=2`。
6. Session 进入事件循环。双方可用 **HeartRequest**（cmd=8）/ **HeartResponse**（cmd=9）做 keep-alive。

### 2.2 Session 建立（server 视角）

1. Accept TCP → TLS accept。
2. 从 TLS 连接**一次性读**出认证数据：校验 32 字节 `SHA256(password)`（失败则关闭连接，或 fallback 到 HTTP 服务）；完整读出 padding0 并丢弃。
3. 创建 server session，进入帧循环。
4. 收到客户端 **Settings** 后：比对 `padding-md5`，不一致则下发 **UpdatePaddingScheme**；`v>=2` 则回 **ServerSettings**。
5. **关键规则**：若在收到 `cmdSettings` 之前收到 `cmdSYN`，必须拒绝该 session（可先发 **Alert** cmd=5 说明原因再关闭）。

### 2.3 Stream 打开（代理一条 TCP 连接）

1. Client 发送 **SYN**（cmd=1），stream_id 在 session 内单调递增。
2. Client 发送 **PSH**（cmd=2）首包，data 为 SOCKS5 格式目标地址（`ATYP + 地址 + port(u16 BE)`），紧接着可发用户数据。
3. Server 拨号目标成功后发送 **SYNACK**（cmd=7，v2 特性）：无 data = 成功；带 data = 错误信息，client 必须关闭该 stream。（服务器若架构上无法回报出站状态，也允许收到 SYN 即回 SYNACK。）
4. 之后双方用 **PSH** 传数据，**FIN**（cmd=3）关闭 stream（收到 FIN 后关闭本地 stream 即可，不必回 FIN；session 关闭时不必发 FIN）。
5. 代理中继完成后 server 只关 Stream、**不关 Session**（session 回到空闲池复用）。

### 2.4 UDP（UDP-over-TCP）

UDP 走 sing-box 的 **udp-over-tcp v2** 协议：
1. Client 向魔法域名 `sp.v2.udp-over-tcp.arpa:0` 开一条普通 stream（同 2.3 流程）。
2. 在 SYNACK 等待**之前**先写 eager payload（否则与 sing-box inbound 死锁：server 等 request 才报 SYNACK，client 等 SYNACK 才写 request）。
3. Eager payload（Connect 格式）：`isConnect(1字节=0x01) + SOCKS5地址`。
4. 之后每个 UDP 包在 stream 上编码为：`长度(u16 BE) + 包内容`。

## 3. 帧格式

### 3.1 认证请求（TLS 握手后，client→server，一次性）

| 字段 | 长度 | 含义 |
|---|---|---|
| `sha256(password)` | 32 字节 | 密码的 SHA-256（UTF-8 字节原文） |
| `padding0 length` | 2 字节 | 大端 u16，padding0 的长度 |
| `padding0` | 可变 | 按 padding scheme 第 0 包策略生成的填充，建议填 0 |

认证总开销 34 字节 + padding0。

### 3.2 会话层帧（双向）

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     command   |                  stream_id (BE u32)             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| stream_id cont|          data length (BE u16)   |               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               +
|                          data (可变)                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| 字段 | 长度 | 含义 |
|---|---|---|
| `command` | 1 字节 | 命令类型（见下表） |
| `stream_id` | 4 字节 | 大端 u32；控制帧（Settings/心跳等）用 0 |
| `data length` | 2 字节 | 大端 u16，data 长度（单帧最大 65535） |
| `data` | 可变 | 命令负载 |

Header 共 7 字节。

### 3.3 命令表

| 值 | 名称 | 方向 | 说明 |
|---|---|---|---|
| 0 | `cmdWaste` | 双向 | 填充；收到后完整读出 data 并静默丢弃 |
| 1 | `cmdSYN` | C→S | 打开新 stream |
| 2 | `cmdPSH` | 双向 | 承载 stream 数据；首个 PSH 的 data 以 SOCKS5 地址开头 |
| 3 | `cmdFIN` | 双向 | 关闭 stream（EOF 标记） |
| 4 | `cmdSettings` | C→S | 客户端设置（`v/client/padding-md5`）；**每个新 session 必须立即发送** |
| 5 | `cmdAlert` | S→C | 服务器警告文本；双方随后关闭 session |
| 6 | `cmdUpdatePaddingScheme` | S→C | 下发新 padding scheme（原始 scheme 文本） |
| 7 | `cmdSYNACK` | S→C | v2+；stream 打开确认，无 data=成功，带 data=错误文本 |
| 8 | `cmdHeartRequest` | 双向 | keep-alive 请求 |
| 9 | `cmdHeartResponse` | 双向 | keep-alive 响应 |
| 10 | `cmdServerSettings` | S→C | v2+；服务器设置（`v=2`） |

除上述说明外，命令不应携带 data。未知命令值建议按 `cmdWaste` 处理（meow-rs 行为）。

### 3.4 Settings 文本格式

UTF-8，`key=value`，行与行之间 `\n` 分隔。client→server：`v`、`client`、`padding-md5`；server→client：`v`。

## 4. 关键参数与默认值

### 4.1 Padding scheme（默认）

```
stop=8
0=30-30
1=100-400
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
3=9-9,500-1000
4=500-1000
5=500-1000
6=500-1000
7=500-1000
```

语义：
- `stop=N`：只对第 0~N-1 个 TLS 写包做 padding/分包，之后的包直接发送。
- `k=min-max[,c,...]`：第 k 个包的目标尺寸（**TLS PlainText 尺寸**，不计 TLS 加密开销）策略；`c` 是"检查点"——若上一个分包发完后用户数据已无剩余，则直接返回、不再发后续填充包。
- 第 0 包 = 认证包（不支持分包，padding0 与 sha256 一起发送）。
- 包计数器以 **Write TLS 的次数**为准；包 1 应包含 `cmdSettings` + 首个 stream 的 `cmdSYN + cmdPSH(目标地址)`；包 2 通常是用户的第一个数据包（如 TLS ClientHello）。
- 若 stop 之前的某个包没有对应策略，直接发送。
- 服务器下发的 scheme 只作用于连接到该服务器的 Client；客户端首个 session 用默认 scheme，收到 `cmdUpdatePaddingScheme` 后新建 session 必须用新 scheme。

### 4.2 复用策略（协议要求）

- 客户端**必须**实现 session 复用：新建 stream 前先找空闲 session，取 `Seq` 最大的；没有才建新 session（Seq 在 Client 内单调递增）。
- Stream 中继完毕关闭后，若 session 事件循环无错误，将 session 放回空闲池并记录空闲起始时间。
- 定期检查（如 30s），关闭持续空闲超限（如 60s）的 session。
- meow-rs 的 SYNACK 超时：默认 30 秒。

### 4.3 其他参数

| 参数 | 含义 | 默认（meow-rs/官方） |
|---|---|---|
| `password` | 认证密码（必填） | — |
| `idle-session-check-interval` | 空闲检查间隔 | 30s |
| `idle-session-timeout` | 空闲 session 回收阈值 | 30s（官方文档示例为 60s） |
| `min-idle-session` | 最少保留的空闲 session 数 | 0 |

## 5. meow-rs 实现中的注意点

1. **认证必须一次写完**（`util/auth.rs::send_authentication`）：参考服务器（anytls-go/sing-anytls）用单次 `ReadOnceFrom` 读认证数据；rustls 的一次 `write_all` = 一个 TLS record。若分三次写（hash / len / padding），服务器单次读只拿到第一个 32 字节 record，读 padding 长度时 EOF，报 `EOF: read padding length: fallback disabled` 并在 SYNACK 前断开。meow-rs 把 32+2+padding 拼成一个 buffer 一次 `write_all`。这是与官方实现对接时最容易踩的坑。
2. **Settings 先缓冲**：`Session::start_client` 先把 Settings 帧写入内部缓冲（`buffering=true`），等第一个 stream 的 SYN+PSH(地址) 到达后一起刷出——对应官方"包 1 应包含 cmdSettings 和首个 Stream 的 cmdSYN+cmdPSH"。`disable_buffering()` 在写目标地址前调用。
3. **Session 池**（`client/session_pool.rs`）：复用"最新空闲"（Seq 最大）session；`create_stream` 拿不到健康 session 时建新 session；心跳保活防止 NAT 超时回收。
4. **SYNACK 看门狗**：`open_proxy_stream` 用 `OpeningStreamGuard` + 30s 超时等 SYNACK，超时/错误则关闭 stream，防止 v1 语义下隧道卡住无限等待。
5. **UoT 死锁规避**（`client.rs::create_proxy_stream_with_payload`）：对 `sp.v2.udp-over-tcp.arpa` 先写 eager payload 再等 SYNACK；普通 TCP stream 不需要。
6. **Server 侧 SYN 先于 Settings 必须拒绝**：协议要求，meow-rs server 在 session 层实现。
7. **Alert 即关**：收到 cmdAlert 读出文本记日志后关闭整个 session（不只是 stream）。
8. 未知命令按 Waste 丢弃——对协议扩展友好，但注意这也可能掩盖对端 bug。

## 6. 参考来源

- meow-rs 代码：
  - `crates/meow-anytls/src/util/auth.rs` — 认证帧编解码 + 单次写注释
  - `crates/meow-anytls/src/protocol/frame.rs` — 帧头 7 字节、命令表
  - `crates/meow-anytls/src/protocol/codec.rs` — 编解码（大端序）
  - `crates/meow-anytls/src/session/session.rs` — Settings/ServerSettings/UpdatePaddingScheme/心跳处理、padding 写路径
  - `crates/meow-anytls/src/client/client.rs` — 建流、SYNACK 等待、eager payload
  - `crates/meow-anytls/src/client/udp_client.rs` — UDP-over-TCP（magic addr、Connect 格式、u16 长度前缀分包）
  - `crates/meow-anytls/src/server/server.rs`、`server/handler.rs` — 服务端握手、SYNACK 发送条件
  - `crates/meow-anytls/src/padding/factory.rs` — 默认 padding scheme、md5 协商
  - `crates/meow-proxy/src/anytls_adapter.rs` — 出站适配（TLS 由外部 `TlsConnect` 注入）
- 官方文档：
  - https://github.com/ssrlive/anytls-rs/blob/HEAD/docs/protocol.md（权威协议说明，中文；描述 anytls-go 行为）
  - https://github.com/anytls/anytls-go（参考实现，`docs/protocol.md`）
  - sing-box udp-over-tcp v2：https://sing-box.sagernet.org/configuration/transport/udp-over-tcp/（meow-rs 注释引用；UoT 包内分片细节未在 meow-rs 展开——**未确认**，实现时需对照 sing-box 文档）
