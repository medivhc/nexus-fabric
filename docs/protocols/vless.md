# VLESS 协议语义文档

> 参考实现：meow-rs `crates/meow-proxy/src/vless/`（Rust，Xray-core `transport/vless/encoding.go` 的忠实移植）。
> 官方协议说明：https://xtls.github.io/en/development/protocols/vless.html ；VLESS 配置/XHTTP：https://xtls.github.io/en/config/outbounds/vless.html

## 1. 协议概述

VLESS（VLESS + XTLS）是 Xray-core 的轻量无状态传输协议：无握手加密、无内置完整性，**身份只靠 16 字节 UUID**，安全完全依赖外层传输（TLS/REALITY）。它只做一件事——在已建立的传输流上用极简的请求/响应头把"代理到哪里"告诉服务器，然后透传字节流。

meow-rs 实现覆盖：
- 基础 VLESS（TCP/UDP/Mux.Cool 信令）
- **XTLS-Vision**（`flow=xtls-rprx-vision`）：内层 TLS 感知的 padding 封装 + splice 直传
- **VLESS-Encryption**（后量子，`encryption: mlkem768x25519...`）：ML-KEM-768 + X25519 混合密钥交换的 1-RTT/0-RTT 记录层
- 传输链：TCP / TLS / WS / gRPC / H2 / HTTPUpgrade / XHTTP，REALITY 可作为 TLS 层变体

## 2. 握手流程

### 2.1 基础 VLESS（client 视角）

1. 按配置建立传输链：`TCP → [TLS] → [WS/gRPC/H2/HTTPUpgrade/XHTTP] → 字节流`。
   - 若配置了 **VLESS-Encryption**，先在传输流上完成其 1-RTT（或 0-RTT）握手（见 §3.4），之后 VLESS 头跑在加密记录层之上。
2. **立即发送请求头**（无需等待任何 server 首包）：
   ```
   version(1) | uuid(16) | addon_len(1) | addon(addon_len) |
   command(1) | port(2, BE) | addr_type(1) | address(变长)
   ```
   （注意：**port 在 addr_type 之前**，这是 VMess/VLESS 惯例。）
3. 若 `flow=xtls-rprx-vision`，之后所有读写经过 Vision padding 封装（见 §3.3）；否则直接透传。
4. **惰性读响应头**：不在握手时等，而是第一次 `read` 时消费开头的 2 字节 `[version(1) | addon_len(1)]` + N 字节 addon（通常全 0，直接丢弃）。**不要**在写请求头后立刻阻塞读响应——server 要先拨号目标，目标先说话的协议会死锁。

### 2.2 请求头字段

| 字段 | 长度 | 含义 |
|---|---|---|
| `version` | 1 字节 | 固定 `0x00` |
| `uuid` | 16 字节 | 用户 UUID 的二进制形式（非文本） |
| `addon_len` | 1 字节 | addon 字节长度 |
| `addon` | `addon_len` 字节 | protobuf 编码的 Addons；`flow=""` 时长度为 0、无内容 |
| `command` | 1 字节 | `0x01`=TCP，`0x02`=UDP，`0x03`=Mux.Cool（`CommandMux`，无地址，目标由 mux 帧承载） |
| `port` | 2 字节 | 大端，目标端口（**在 addr_type 之前**） |
| `addr_type` | 1 字节 | `0x01`=IPv4，`0x02`=域名，`0x03`=IPv6 |
| `address` | 变长 | IPv4=4字节；IPv6=16字节；域名=`len(1字节)+内容`（最长 255 字节） |

Addon 编码（无 prost，手写）：`flow="xtls-rprx-vision"` 时 `addon_len=18`，内容为 `[0x0A, 0x10] + "xtls-rprx-vision"`（0x0A=protobuf field 1/wire-type 2，0x10=varint 16=字符串长度）。`flow=""` 时 `addon_len=0`。

### 2.3 响应头字段

| 字段 | 长度 | 含义 |
|---|---|---|
| `version` | 1 字节 | 回显请求 version（`0x00`） |
| `addon_len` | 1 字节 | 通常为 0 |
| `addon` | `addon_len` 字节 | 读出并丢弃 |

### 2.4 UDP-over-TCP（VLESS UDP）

- 请求头 `command=0x02`，地址为 DNS/目标地址。
- 此后流上每个 UDP 包独立成帧：`长度(u16 BE) + 包内容`，双向同格式。
- 没有 per-datagram 源地址字段（不像 SOCKS5 UDP 头）。

### 2.5 XTLS-Vision 流程

Vision 只适用于 **TCP + TLS/REALITY**（meow-rs 配置门禁：无加密传输时拒绝启用；UDP 不走 Vision）。

Client 写方向状态机（`vless/vision.rs`）：
1. 初始 `write_padding=true`。每个上层写块包成 padding 帧（见 §3.3）。
2. 检测到内层 **TLS ClientHello**（TLS record type `0x16` 且含 ClientHello）后标记 `write_seen_tls`。
3. 当出现内层 **TLS Application Data**（`0x17 0x03 ...`）且已见过 ClientHello → 发送 `COMMAND_PADDING_END(0x01)` 帧（含剩余数据），之后**写方向停止 padding**；若开启 direct 模式则发 `COMMAND_PADDING_DIRECT(0x02)`，写侧切为裸 TCP 直通（读侧仍走 TLS， verified 对 sing-box 与 Xray）。
4. 若**始终没见到 TLS 握手**（非 TLS 内层流量）→ 直接 `COMMAND_PADDING_END`，不做多余填充。

读方向对称解包：先读 21 字节头（含 UUID，仅首帧），后续帧头 5 字节（无 UUID），按 `command/content_len/padding_len` 剥离 padding，还原明文；`END` 后进入透传。

## 3. 帧格式

### 3.1 Vision padding 帧

```
首帧:  uuid(16) | command(1) | content_len(2 BE) | padding_len(2 BE) | content | padding(0填充)
后续帧: command(1) | content_len(2 BE) | padding_len(2 BE) | content | padding(0填充)
```

| 值 | 命令 | 含义 |
|---|---|---|
| `0x00` | `COMMAND_PADDING_CONTINUE` | 继续 padding |
| `0x01` | `COMMAND_PADDING_END` | 结束 padding，后续透传 |
| `0x02` | `COMMAND_PADDING_DIRECT` | 结束 padding 且写侧切裸 TCP 直通（splice） |

padding 长度策略（meow-rs）：`content.len() < 900` 时随机填充——见过 TLS 则补到约 900~1400（`rand%500 + 900 - len`），否则 `rand%256`；`>=900` 则不填充。

读侧还有 ServerHello 过滤器（`TLS_FILTER_PACKETS=8`，识别 TLS1.3 ServerHello 的 `supported_versions` 扩展 `0x002b` 与密码套件 `0x1301~0x1304`）——**未确认**其在官方 Xray 中的对应细节，meow-rs 自有实现。

### 3.2 Mux 信令（`command=0x03`）

- sing-mux：VLESS 请求目标为保留地址 `sp.mux.sing-box.arpa:444`，之后跟 mux 请求头；server 须为 sing-box/mihomo。
- muxcool（Xray `CommandMux`）：VLESS 请求本身即信令，不带地址；server 须为 Xray/sing-box。
- meow-rs 中 mux 为可选 feature，细节以 `mux` 模块为准。

### 3.3 VLESS-Encryption 记录层（后量子）

配置字符串形如 `encryption: mlkem768x25519plus.native.0.<base64-key>...`（`parse_client_encryption` 解析；`""/"none"`=不启用）。多 key 可组成 relay 链（`a.b.KEY1.KEY2...`），野外一般单 key。

**1-RTT 握手**（client→server，然后 server→client）：

Client Hello（分片、间隔写入，抗 DPI 流量整形）：
```
iv(16随机) | relays(每key一段) |
nfs_aead.seal(encode_length(pfs_key_exchange_len - 18)) |
nfs_aead.seal(pfs_public_key = ML-KEM-768 ek(1184) || X25519 pub(32)) |
nfs_aead.seal(encode_length(padding_len - 18)) |
nfs_aead.seal(padding_body)
```
- `relays`：对每个 NFS key——X25519 key 做 ECDH（放己方临时公钥 32B），ML-KEM key 做 encapsulate（放 ciphertext，ML-KEM-768 为 1088 字节）；`xor_mode>0` 时用 `AES-256-CTR(nfs_key, iv)` 加密每段；多 key 时后段再用前一段的 keystream 二次加密（"relay" 链）。
- `nfs_aead`：以 `iv` 为 nonce 上下文、`nfs_key`（最后一段的共享密钥）为 key 的 AEAD；`encode_length`=2 字节大端长度。

Server 回复：
```
nfs_aead.seal(server_pfs_pub = ML-KEM-768 ct(1088) || X25519 pub(32) || tag(16))
peer_aead.seal(ticket(32))            # ticket 前 2 字节为有效期秒数(0-RTT 用)
peer_aead.seal(encode_length(peer_padding_len))
```
- client 用 ML-KEM dk 解封得 `mlkem_shared`，与 X25519 ECDH 结果拼接成 64 字节 `pfs_key`；`united_key = pfs_key || nfs_key` 为数据阶段密钥。
- ticket 若有效（`seconds>0`）则缓存 `(pfs_key, ticket, expire)` 供 0-RTT。

**0-RTT**（有未过期 ticket 时）：`iv | relays | seal(len=32) | seal(ticket)` 一次写出，直接进入数据阶段；server 拒收则丢弃缓存、下次回退 1-RTT。

**数据阶段记录**（双向）：
```
[5字节伪TLS头: 0x17 0x03 0x03 | len(2 BE)=密文+16] [AEAD密封体(明文+16字节tag)]
```
- 伪 TLS Application Data 记录头同时作为 AEAD 的 AAD。
- nonce 耗尽时以 `header||sealed` 为新上下文 rekey（`Aead::new(&ctx, ...)`）。
- `xor_mode=2`（`random`）时再用 `AES-256-CTR(united_key, iv)` 把每条记录的 5 字节头 XOR 掉，使帧边界不可分辨。
- 三种 XorMode：`native`(0) / `xorpub`(1) / `random`(2)。

**未确认**：meow-rs 自称与上游 Go 实现逐字节兼容（含 nonce 调度、BLAKE3 KDF 上下文），但本文未逐字节复核 Xray `transport/vless/encryption` 源码；`seed`/`padding` 配置字符串的完整语法以 Xray 文档为准。

## 4. 关键参数与默认值

| 参数（mihomo/sing-box 风格） | 含义 | 默认/约束 |
|---|---|---|
| `uuid` | 用户身份，16 字节二进制上线路 | 必填 |
| `flow` | `""` 或 `xtls-rprx-vision`（旧 `xtls-rprx-direct` 等已废弃，meow-rs 拒绝） | `""` |
| `tls` | 是否启用 TLS | false（Vision 要求 true；meow-rs 无 TLS+Vision 直接报错） |
| `servername`/`sni` | TLS SNI；为空则用 server 地址 | server |
| `skip-cert-verify` | 跳过证书校验 | false |
| `fingerprint`/`client-fingerprint` | uTLS 指纹（如 chrome） | 未设置 |
| `reality-*` | REALITY 参数（`pbk`/`sid`/`spx` 等） | 未设置 |
| `network` | `tcp`/`ws`/`grpc`/`h2`/`httpupgrade`/`xhttp` | `tcp` |
| `ws-opts.path` / `headers.Host` | WS 路径与 Host 头 | `/` / server |
| `grpc-opts.grpc-service-name` | gRPC 服务名 | `GunService` |
| `encryption` | VLESS-Encryption 配置串（后量子） | 不启用 |
| `alpn` | TLS ALPN（按 network 给默认值） | — |
| `ech-opts` | ECH（DNS 预解析注入 base64 config） | 未启用 |

REALITY 客户端（meow-rs 自研，`meow-transport/reality_tls.rs`）：`session_id = AES-256-GCM(authKey)(ver\|ts\|shortId)`，`authKey = HKDF-SHA256(X25519(临时, pbk), salt=clientRandom[:20], "REALITY")`，nonce 取 `clientRandom[20:]`，AAD 为整个 ClientHello（shortId 清零）；握手后用 `HMAC-SHA512(authKey, ed25519叶子公钥) == 证书签名` 做服务器认证，失败则关闭。

## 5. meow-rs 实现中的注意点

1. **响应头惰性读**（`vless/conn.rs::VlessConn`）：`response_pending` 在首次 `poll_read` 才消费 2+N 字节。握手函数只管"请求头已发出"就返回——这是为了兼容目标先说话的协议；若改成握手时阻塞读响应，会对这类目标死锁。
2. **port 在 addr_type 之前**：`header.rs` 顶部用 NOTE 强调，人读文档时容易写反；`encode_request` 按 Xray `EncodeRequestHeader` 顺序实现。
3. **Vision 要求加密传输**：配置层硬门禁（无 TLS 的 Vision 直接返回错误），因为无外层 TLS 时 splice 无意义且用户无保护；Vision+UDP 会警告（Vision 只定义了 TCP 语义，UDP 走普通 VLESS）。
4. **Vision DIRECT 的不对称性**：`COMMAND_PADDING_DIRECT` 后**写侧**切裸 TCP 直通、`读侧`仍走 TLS（经与 sing-box/Xray 实测验证）。实现直通前检查传输是否支持 raw passthrough，不支持则报错。
5. **VLESS-Encryption 在 VLESS 头之下**：分层顺序是 `TCP → 传输链(TLS/WS/…) → [Encryption握手] → VLESS头 → 载荷`。不要把它和 TLS 搞混——它是 Xray 的"后量子"层，`encryption` 字段的 key 用 `./xray mlkem768` 生成。
6. **未知 flow 直接拒绝**：上游 mihomo 会静默忽略未知 flow（可能导致安全降级），meow-rs 按 ADR-0002 Class A 直接报错。`xtls-rprx-vision-udp443` 变体 meow-rs 未实现——**未确认**其线格式差异，实现前需查 Xray 文档。
7. **Mux 两套线协议**：sing-mux（保留地址 + mux 请求头）vs muxcool（CommandMux 0x03 本体即信令），server 要求不同，`with_mux` 按 `MuxOptions.protocol` 选择。
8. **gRPC authority**：按 mihomo 行为用 `servername`（为空才回退到 dial host），因为有些前端按 `:authority` 路由。

## 6. 参考来源

- meow-rs 代码：
  - `crates/meow-proxy/src/vless/header.rs` — 请求/响应头编码（含 port-before-addr_type 注释）
  - `crates/meow-proxy/src/vless/conn.rs` — `VlessConn`（惰性响应头）、`VlessPacketConn`（UDP `u16 BE` 分帧）
  - `crates/meow-proxy/src/vless/vision.rs` — Vision padding 帧、读写状态机、DIRECT 语义
  - `crates/meow-proxy/src/vless/encryption/{mod,client,aead,factory}.rs` — 后量子 Encryption（1-RTT/0-RTT/记录层）
  - `crates/meow-proxy/src/vless_adapter.rs` — 出站适配、传输链装配
  - `crates/meow-config/src/proxy_parser.rs` — vless 配置解析（network/tls/reality/flow 门禁）
  - `crates/meow-transport/{tls,ws,grpc,h2,httpupgrade,xhttp,reality_tls}.rs` — 各传输层
- 官方文档：
  - https://xtls.github.io/en/development/protocols/vless.html（VLESS 线格式）
  - https://xtls.github.io/en/config/outbounds/vless.html（含 `flow`、`encryption`/`padding`/`seed` 后量子参数说明）
  - Xray-core `proxy/vless` / `transport/vless/encryption` 源码（meow-rs 注释中引用的上游实现）
