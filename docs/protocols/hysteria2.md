# Hysteria2 协议语义文档

> 参考实现：meow-rs `crates/meow-proxy/src/hysteria2/`（Rust，基于 `quiche` + BoringSSL 的 clean-room 实现）。
> 官方协议规范：https://github.com/apernet/hysteria/blob/master/PROTOCOL.md ；用户文档：https://v2.hysteria.network/

## 1. 协议概述

Hysteria2 是基于 **QUIC（RFC 9000）+ 不可靠数据报扩展（RFC 9221）** 的 TCP/UDP 代理协议。设计上对未认证的探测者表现为一个普通 **HTTP/3 Web 服务器**（认证走一条 HTTP/3 `POST /auth` 请求）；认证通过后，同一 QUIC 连接转为代理连接：**TCP 走双向 QUIC stream，UDP 走 QUIC DATAGRAM**。多路复用天然由 QUIC 提供。

特色机制：
- **拥塞控制协商**：认证时双方交换 `Hysteria-CC-RX`（最大接收速率），可指定固定发包速率（Brutal CC），或 `"auto"`/0 回退到 BBR/Cubic 类算法。
- **Salamander 混淆**：可选的整包 XOR 混淆层（`BLAKE2b-256(key||salt)`）。
- **端口跳跃**：客户端按 `hop-interval` 轮换目标端口。

meow-rs 用 `quiche`（BoringSSL）实现 QUIC，HTTP/3 认证只手写最小子集（SETTINGS + QPACK 编码请求头，不跑完整 H3 连接）。

## 2. 握手流程

### 2.1 连接建立（client 视角）

1. UDP socket 绑定（v4/v6 通配地址），解析服务器地址（支持域名、多 A/AAAA 轮询）。
2. 发起 QUIC 握手：SNI = `servername`（为空则用 server host）；ALPN = `h3`；**禁用 QUIC bit greasing**；启用 DATAGRAM（收发队列各 1024）；流接收窗口 8MB、连接窗口 20MB；最大空闲超时 30s；最大并发双向/单向流各 1024。
3. 证书校验三选一：`pin-sha256`（DER 的 SHA-256，叶子 pin，替代链校验）/ `insecure`（不校验）/ 系统根证书链校验。
4. QUIC 建连后（`is_established`），在 stream 0 上发 HTTP/3 认证：
   - 先在**单向控制流（stream 2）**上发 `SETTINGS`：`[0x00, 0x04, 0x00]`（stream type 0 + SETTINGS帧 + 长度0；空 SETTINGS，QPACK 动态表保持禁用）。
   - 在 **stream 0** 上发 HEADERS 帧（`0x01` + varint长度 + QPACK 编码块）：
     ```
     :method: POST
     :scheme: https
     :authority: hysteria
     :path: /auth
     Hysteria-Auth: <password>
     Hysteria-CC-RX: <rx_bps>        # 客户端最大接收速率(bytes/s)，0=未知
     Hysteria-Padding: <随机串>      # 256~2048字节[a-zA-Z0-9]，仅混淆，双方应忽略
     ```
     （官方 spec 写 `:host: hysteria`；HTTP/3 线上用 `:authority`，meow-rs 发 `:authority: hysteria`。）
   - 读回响应 HEADERS，校验 `:status == 233`（`233 HyOK`）；其他状态一律视为认证失败并断开。
   - 读 `Hysteria-UDP: true/false` 决定是否启用 UDP（false 时 UDP 请求直接报错）。
   - `Hysteria-CC-RX` 响应值语义：`0`=无限制；`"auto"`=server 不提供，client 必须用拥塞控制算法自适应。
5. 认证成功后，该 QUIC 连接即为代理连接；之后所有代理走**裸 QUIC stream/datagram**，不再用 H3。
6. 保活：每 10s 发 QUIC ack-eliciting 包（`send_ack_eliciting`）。

### 2.2 TCP 代理（每条连接一条双向 stream）

1. Client 开新双向 stream（client 起始 stream id=0 为 auth 用，代理 stream 从 **4** 开始、步进 4）。
2. 首帧发送 **TCPRequest**（可携带首个数据 payload 做 fast-open）：
   ```
   [varint] 0x401 (TCPRequest ID)
   [varint] 地址长度
   [bytes]  地址字符串 "host:port"（文本形式！）
   [varint] padding长度
   [bytes]  随机padding
   ```
3. Server 回 **TCPResponse**：
   ```
   [uint8]  status (0x00=OK, 0x01=Error)
   [varint] 消息长度
   [bytes]  消息字符串
   [varint] padding长度
   [bytes]  随机padding
   ```
4. status=0 → 该 stream 成为透明转发通道，直到任一侧关闭；status=1 → server 关闭该 QUIC stream（消息为错误文本）。
5. `fast-open=true`（meow-rs 默认）时，client 在**发出请求帧后**不等响应即认为连接可用（写缓冲排空即 signal connected）；`false` 则等 TCPResponse 的 OK 才返回。读侧**始终**先剥离 TCPResponse 再向上传 payload。

### 2.3 UDP 代理（QUIC DATAGRAM）

1. 每个 UDP session 分配一个本地唯一的 **Session ID**（u32，meow-rs 从 0 递增）。
2. 每个 UDP 包封装为 **UDPMessage**，经 QUIC unreliable datagram 双向发送：
   ```
   [uint32] Session ID      (大端)
   [uint16] Packet ID       (大端)
   [uint8]  Fragment ID
   [uint8]  Fragment Count
   [varint] 地址长度
   [bytes]  地址字符串 "host:port"
   [bytes]  载荷
   ```
3. 分片：超 QUIC 最大 datagram 的包必须分片或丢弃；分片共享同一 Packet ID，Fragment ID 从 0 起；收齐所有分片才处理，丢一片则整包丢弃；不分片时 Fragment Count=1（此时 Packet/Frag ID 无意义）。
4. **无显式关闭**：server 按不活跃超时回收 Session ID 对应的端口；client 发往已回收 session 的包会被 server 当作新 session 处理。
5. server 不支持 UDP 时应静默丢弃收到的 UDPMessage（client 侧 meow-rs 在认证阶段已知 `Hysteria-UDP: false` 则直接拒绝）。

### 2.4 Salamander 混淆（如配置）

每个 UDP 数据报（整个 QUIC 包）封装为：
```
[8字节] 随机 salt
[bytes] payload XOR BLAKE2b-256(password || salt) 的循环密钥流
```
即 `payload[i] ^= hash[i % 32]`。收包时按前 8 字节取 salt 重算密钥流解开；非法包丢弃。注意：这是**整包**变换，发生在 QUIC 包之下（meow-rs 在 driver 收发 datagram 处做）。

### 2.5 端口跳跃（如配置 `ports`）

- `ports` 格式：逗号分隔的端口/端口段，如 `"10000-20000,30000"`（meow-rs `HopPorts::parse`）。
- 客户端按 `hop-interval`（默认 30s，最小 5s）在集合中随机轮换发包目标端口；server 回包可能来自任一 hop 端口，client 把源地址归一化回 canonical server 地址再交给 quiche。

## 3. 帧格式

### 3.1 认证（HTTP/3，stream 0 / 控制流 2）

请求（QPACK 编码的 HEADERS 帧）见 §2.1。响应 HEADERS 至少包含：

| 伪头/头 | 值 |
|---|---|
| `:status` | `233`（成功）；其他=失败断开 |
| `Hysteria-UDP` | `true`/`false` |
| `Hysteria-CC-RX` | 数字或 `"auto"`（可选） |
| `Hysteria-Padding` | 随机串（可选，应忽略） |

### 3.2 TCPRequest / TCPResponse

见 §2.2。注意地址是**文本** `host:port`（区别于 SOCKS5/VLESS 的二进制地址），长度前缀为 QUIC varint。

QUIC varint 编码（RFC 9000 §16）：首字节高 2 位决定长度——`00`=1字节(0~63)，`01`=2字节(64~16383)，`10`=4字节，`11`=8字节；大端。

### 3.3 UDPMessage

见 §2.3。`Session ID(u32 BE) | Packet ID(u16 BE) | Frag ID(1) | Frag Count(1) | varint地址长 | 地址文本 | 载荷`。最大 UDP 载荷 meow-rs 限制约 4096 字节（`MAX_UDP_SIZE`）。

## 4. 关键参数与默认值

| 参数（mihomo 风格） | 含义 | 默认（meow-rs） |
|---|---|---|
| `server` / `port` | 服务器地址/QUIC 端口 | 必填 |
| `password` / `auth` | `Hysteria-Auth` 凭证字符串 | 必填 |
| `sni`/`servername` | QUIC TLS SNI；为空用 server host | server |
| `skip-cert-verify` | 跳过证书校验 | false |
| `pin-sha256` / `fingerprint` | 叶子证书 DER 的 SHA-256 pin（meow-rs 中 pin 优先于 insecure） | 未设置 |
| `alpn` | 固定 `h3`（meow-rs 校验并拒绝其他值） | `h3` |
| `up` / `down` | 带宽（Mbps→内部转 bytes/s）；`down`→`Hysteria-CC-RX` 请求头 | 0（未知/不限） |
| `obfs` | `salamander`（`gecko` 明确不支持，配置即报错） | 不启用 |
| `obfs-password` | Salamander 预共享 key | obfs 启用时必填 |
| `ports` | 跳跃端口集合（如 `10000-20000`） | 不启用 |
| `hop-interval` | 跳跃间隔 | 30s（最小钳制 5s） |
| `fast-open` | TCP 请求发出后不等响应即返回 | true |
| `udp` | 是否启用 UDP（与 server 协商结果取交集） | true |

拥塞控制语义（官方）：
- client 发 `Hysteria-CC-RX: 0` → 不知道自己速率，server 必须用拥塞控制算法（BBR/Cubic）调节发向 client 的速率。
- server 回 `0` → 无限制，client 可任意速率发送。
- server 回 `"auto"` → 不提供数值，client 必须用拥塞控制算法自适应。

## 5. meow-rs 实现中的注意点

1. **最小 HTTP/3**：`auth.rs` 不跑完整 H3 连接——只发空 SETTINGS + 一次 QPACK HEADERS，用 quiche 的 qpack codec；注释解释了原因：完整 H3 会宣告 `SETTINGS_H3_DATAGRAM`，导致 quic-go/quiche 的 H3 接收器"偷走"本该走裸 datagram 的 UDP 包。**不要**换成高级 H3 API。
2. **响应只认 233 + Hysteria-UDP**：`decode_response` 严格校验帧类型（拒绝 DATA 先于 HEADERS、拒绝 QPACK 动态表引用、拒绝控制流上的 SETTINGS）；多余的未知扩展帧允许跳过。官方要求失败时 server 伪装成普通 Web 服务器——client 侧只看状态码。
3. **Pin 语义与官方 CLI 不同**：meow-rs 中配置了 pin 即**替代**链校验+主机名校验（mihomo 行为，允许自签名）；官方 hysteria CLI 的 pin 是**额外**的叶子检查，`insecure` 独立控制链校验。实现/联调时注意这个差异。
4. **无 Brutal CC**：meow-rs 把 `rx_bps` 只放进 `Hysteria-CC-RX` 请求头，**不实现** Brutal 固定速率发送；拥塞控制用 quiche 默认。quiche 默认 CC 算法本文**未确认**（疑似 CUBIC），如需 Brutal 语义需另行实现。
5. **Greasing 禁用**：`quic.grease(false)`——hysteria2 明确禁用 QUIC bit greasing（官方行为）。
6. **Stream id 分配**：0=auth，代理 bidi stream 从 4 起、步进 4（client-initiated bidi stream 编号规则）。
7. **读侧 TCPResponse 剥离**：driver 在把 payload 交给上层前先用 `parse_tcp_response` 消费 `status+msg+pad`；fast-open 下 connected 信号在"请求帧排空"时即发，但**读侧仍要等**响应剥离完成——`expect_response` 标志保证。
8. **UDP session 本地管理**：`RegisterUdp` 分配 session id；无显式关闭帧，drop 时 `UnregisterUdp` 仅清本地状态。
9. **Gecko 不支持**：`obfs: gecko`（握手分片混淆）在 Rust 后端明确拒绝，只有 salamander。
10. **端口跳跃的源归一化**：`normalize_source` 把 hop 端口回包的源地址改回 canonical 地址，否则 quiche 认不出是同一连接的包。

## 6. 参考来源

- meow-rs 代码：
  - `crates/meow-proxy/src/hysteria2/proto.rs` — TCPRequest/TCPResponse/UDPMessage 编解码、QUIC varint
  - `crates/meow-proxy/src/hysteria2/auth.rs` — 最小 HTTP/3 认证（SETTINGS/QPACK/233 校验）
  - `crates/meow-proxy/src/hysteria2/tls.rs` — quiche 配置（ALPN h3、窗口、DATAGRAM、证书 pin/insecure/链校验）
  - `crates/meow-proxy/src/hysteria2/driver.rs` — 事件循环、stream/datagram 调度、保活、fast-open
  - `crates/meow-proxy/src/hysteria2/obfs.rs` — Salamander（BLAKE2b XOR）与端口跳跃
  - `crates/meow-proxy/src/hysteria2/tcp.rs` / `udp.rs` — TCP/UDP 数据面
  - `crates/meow-proxy/src/hysteria2/client.rs` — `ReconnectableClient`（断线重连）
  - `crates/meow-config/src/proxy_parser.rs::parse_hysteria2` — 参数解析与门禁
- 官方文档：
  - https://github.com/apernet/hysteria/blob/master/PROTOCOL.md（权威协议规范：认证/TCP/UDP/拥塞控制/Salamander）
  - https://v2.hysteria.network/（用户文档）
