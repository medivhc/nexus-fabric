# nexus-outbound-shadowsocks Module Contract

## Responsibility

Shadowsocks AEAD 出站 adapter（PRODUCT §11.6）：实现 `nexus-connectivity::OutboundAdapter`，
对出站字节流做 AEAD 封装/解封装。本期冻结 method 为 `chacha20-ietf-poly1305`（RustCrypto
纯 Rust 实现，已实测 wasm32-wasip1 可编译）。

## Non-Responsibilities

- 不实现真实 TCP 建连 / SS 会话握手帧（本期离线确定性，E4 仅做 AEAD 自洽往返）；
- 不选择 Provider、不持有 Plan/Session；
- 不引入 TUN / vmess / trojan / 订阅。

## Inputs

- 配置：`{ tag, server, port, method, password }`（由 nexus-proxy-config 类型化后注入）。
- 明文字节流（Composition Root / example 注入）。

## Outputs

- `OutboundHandoff`（kind="shadowsocks"）；
- `encrypt(plaintext) -> Vec<u8>` / `decrypt(&[u8]) -> Result<Vec<u8>, OutboundCipherError>`。

## Allowed Dependencies

- `nexus-connectivity`
- RustCrypto 系：`chacha20poly1305`、`hkdf`、`sha2`（license MIT OR Apache-2.0，
  cargo-deny advisories/licenses/bans/sources 已评审通过）。

## Forbidden Dependencies

- `engineering/`、`nexus-proxy` / `nexus-network` 等领域业务 crate（出站 adapter 不反向依赖编排层）。
- 平台专有 / C / FFI 实现（纯 Rust）。
- 未在 `policies/architecture.toml` 声明的内部 crate。

## Invariants

- `encrypt` 输出 = nonce(12B) || ciphertext+tag；`decrypt` 严格逆操作，自洽往返 `decrypt(encrypt(x)) == x`。
- key 由 password 经 HKDF-SHA256（盐=method 标签）确定性派生；同一 password+method 恒得同一 key。
- 离线确定性：nonce 用固定计数器（小端 12B）递增，不调用 getrandom；相同输入恒得相同输出。
- 本 crate `portable=false`（出站/交付层，依赖第三方 crypto）；不加入 `harness.toml [portable_core]`。
- 自身零 `unsafe`（crypto crate 内部除外）。

## Side Effects

- 仅内存加解密；无网络 I/O、无持久状态。

## Public API

```text
enum SsMethod { Chacha20IetfPoly1305 }   // as_str() -> "chacha20-ietf-poly1305"
struct ShadowsocksAdapter { /* tag, method, key, locator */ }
impl ShadowsocksAdapter {
    fn new(tag, locator, method, password) -> Result<Self, OutboundCipherError>;
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, OutboundCipherError>;
    fn decrypt(&mut self, frame: &[u8]) -> Result<Vec<u8>, OutboundCipherError>;
}
impl nexus_connectivity::OutboundAdapter for ShadowsocksAdapter { ... }
enum OutboundCipherError { KeyDerivation, InvalidFrame, DecryptFailed }
```

### 冻结契约：真实 TCP 会话（§11.6.1，scenarios/product/proxy_shadowsocks_real_tcp.toml）

在保留既有离线 `ShadowsocksAdapter::encrypt/decrypt` 自洽 API 不变的前提下新增会话层：

- `enum Role { Client, Server }`；`struct SsStream`：持 c2s / s2c 两把独立 key（HKDF info
  分别为 `b"ss-c2s"` / `b"ss-s2c"`，盐=method），TX 方向 nonce 自 0 固定计数递增。
- `SsStream::new(password, method, role)`：Client TX=c2s/RX=s2c；Server 相反。
- `seal(plaintext) -> nonce(12B)||ct+tag`；`open(frame) -> plaintext`（用 RX key，帧内 nonce）。
- `enum SsTarget { Ipv4([u8;4],u16), Domain(String,u16) }`；`encode_request(&SsTarget)->Vec<u8>`
  （ATYP=1 IPv4 / =3 domain）、`parse_request(&[u8])->Result<SsTarget>`。
- 记录帧 I/O：`write_record(&mut TcpStream, &[u8])` / `read_record(&mut TcpStream)`
  （`u32 BE length` 前缀），纯 std，零新依赖。
- 不变量：同一方向 nonce 不重复；c2s/s2c key 互不派生混淆；request header 长度/ATYP 非法
  返回 `InvalidFrame`；AEAD 校验失败返回 `DecryptFailed`。
- 离线 loopback：目标为另一 loopback echo 端；server 解析目标后真实 `TcpStream::connect` 并中继。
- 结构化并发：server/echo 用 `std::thread::spawn`，调用方 `join()` 回收，不丢 JoinHandle。
- 既有 `ShadowsocksAdapter` 自洽 E4 行为不变。

## Verification

最低：

```text
cargo check -p nexus-outbound-shadowsocks
cargo clippy -p nexus-outbound-shadowsocks --all-targets -- -D warnings
```

产品行为映射（E4）：

```text
scenarios/product/proxy_shadowsocks_adapter.toml
apps/nexus/examples/proxy_shadowsocks_adapter.rs
```

## Performance Budget

未定义性能预算的路径不得宣称"性能完成"。

## Observability

稳定结构化字段：method 标签、tag；不加每包自由文本日志。

## Recovery Semantics

无持久状态；进程重启后用同一配置重建。

## Platform Constraints

`portable=false`；平台专有代码仅在 Composition Root。
