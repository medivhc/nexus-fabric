# nexus-outbound-shadowsocks Module Contract

## Responsibility

Shadowsocks 出站 crate。对外提供两套**线格式互不相同**的 API，边界必须分清：

- **SIP004 TCP AEAD 流（`SsStream`）**：标准 shadowsocks AEAD 线格式，
  `salt(32) || chunk*`，`chunk = AEAD(len 2B BE) || AEAD(payload)`，
  AEAD = `chacha20-ietf-poly1305`，AAD 恒为空。这是 `apps/nexus` SOCKS5 产品出口
  （ProductSocks5 carrier）与 `nexus-proxy-transport` 使用的线格式。
- **离线自洽 adapter（`ShadowsocksAdapter`）**：`nexus_proxy_config::outbound_seam::OutboundAdapter`
  面，key 由 HKDF-SHA256（盐=method 标签）派生，帧 `nonce(12B) || ct+tag`。
  **非 SIP004、无互操作证据、不在产品矩阵路径上**；线格式迁移另立 follow-up
  （spec §1.7）。本 crate 不声明它与真实 shadowsocks 服务器可互通。

method 冻结为 `chacha20-ietf-poly1305`（RustCrypto 纯 Rust 实现，wasm32-wasip1 可编译）。

## Non-Responsibilities

- **不覆盖 nexusd TUN 路径**：`apps/nexusd/src/proxy_fwd/ss_std.rs` 是另一套独立实现，
  本 crate 的改动不改变其行为；TUN 路径 SS 可用性须另行验证（spec §0.6）。
- 不实现 SS UDP / UDP relay（产品级 UDP 属后续 run）；`UdpEcho` 维持 NOT_IMPLEMENTED。
- 不实现加分 method（含 `aes-256-gcm`）；method 集合仅 `chacha20-ietf-poly1305`。
- 不实现 `ShadowsocksAdapter` 的 SIP004 线格式（仅文档诚实，spec §1.7）。
- 不选择 Provider、不持有 Plan/Session；不引入 TUN / vmess / trojan / 订阅。
- 生产代码不得调用 `with_tx_salt`（仅供确定性测试/金样）。

## Inputs

- 配置：`{ tag, locator, method, password }`（由 nexus-proxy-config 类型化后注入）。
- 明文/线字节（`seal` / `open` 双向流式调用）。
- 生产 TX salt 由 `ring::rand::SystemRandom` 惰性生成；测试通过 `with_tx_salt` 注入。

## Outputs

- `SsStream::seal(plaintext) -> Vec<u8>`（线字节增量，首非空调用含 32B salt）；
- `SsStream::open(data) -> Vec<u8>`（当前可解出的明文，可为空）；
- `ShadowsocksAdapter`：`OutboundHandoff`、`encrypt` / `decrypt`（离线自洽）；
  错误类型为 `OutboundHandoffError`（当前无生产者，见 proxy-config MODULE）；
- `OutboundCipherError { KeyDerivation, InvalidFrame, DecryptFailed }`。

## Allowed Dependencies

- `nexus-proxy-config`、`nexus-plugin`（既有内部边）。
- RustCrypto 系：`chacha20poly1305`、`hkdf`、`sha2`（**仅 `ShadowsocksAdapter` 使用**）、
  `sha1`（HKDF-SHA1 内层 hash）、`md5`（EVP_BytesToKey）。
- `ring`（`SystemRandom`，生产 salt 唯一来源；default features 关闭，仅
  `alloc` + `dev_urandom_fallback`）。
- 以上第三方均已在 `policies/dependencies.toml` 有 `[[dependency_reviews.direct]]` 记录，
  版本已由 `Cargo.lock` 固定（不引入新包）。

## Forbidden Dependencies

- `engineering/`、`nexus-proxy` / `nexus-network` 等领域业务 crate（出站 crate 不反向依赖编排层）。
- 平台专有拦截 API / TUN / FFI 实现（`ring` 的 cc 构建除外，已评审）。
- 未在 `policies/architecture.toml` 声明的内部 crate。
- `nexus-connectivity`（v9 CLI 产品线运行时，frozen；**目标态禁止**）。
  接缝 ② 已于 2026-10-28（P2）清除：出站身份/交接词汇定义于 `nexus-proxy-config`，
  本 crate 对 `nexus-connectivity` 的直接边为 0
  （见 `docs/DOC-AUDIT-2026-10-26-dual-stack.md` 与 `docs/adr/0001-dual-stack-boundary.md`）。

## Invariants

SIP004 线格式（`SsStream`）：

- 口令 → master key：`EVP_BytesToKey`（MD5、**无 salt、1 次迭代**），取前 32B。
- master key → 方向 subkey：HKDF-SHA1，`salt` = 本方向 32B salt，`info = "ss-subkey"`。
  不存在预共享 c2s/s2c key；`Role` 保留在签名中但**不影响派生**（SIP004 双向对称）。
- 线格式：`salt(32) || chunk*`；`chunk = AEAD(len 2B BE) || AEAD(payload)`；AAD 恒空。
- len 合法域 `1..=0x3FFF`；`0` 或 `>0x3FFF` → `InvalidFrame`（流 poisoned）。
- nonce：12B 小端计数器，不上线；TX 每加密一个 chunk（len/payload 各一次）+1，
  RX 每**成功**解密一个 chunk +1；初值 0。
- salt：首次非空 `seal` 才生成/发射；空 `seal` 返回空且不触发 salt；同一流不重复发射 salt。
- 解码缓冲上限：每次 `open` 返回 Ok 后保留的未解字节 ≤ 16449B（32 salt + 单 chunk 最大线长 16417）。
- poisoned：`open` 任一错误后流进入 poisoned，后续 `open` 返回同一变体，不重同步。
- `with_tx_salt` 仅测试使用；生产路径用 `new`（随机 salt）。

离线 adapter（`ShadowsocksAdapter`，行为未变）：

- `encrypt` 输出 = `nonce(12B) || ciphertext+tag`；`decrypt` 严格逆操作。
- key 由 password 经 HKDF-SHA256（盐=method 标签）确定性派生；固定计数器 nonce，
  不调 getrandom（离线确定性）。

通用：

- 本 crate `portable=false`（出站/交付层，依赖第三方 crypto）；不加入
  `harness.toml [portable_core]`。
- 自身零 `unsafe`（crypto crate 内部除外）。
- `write_record` / `read_record` 为 legacy Nexus 记录帧（u32 BE 前缀），
  **非 SIP004**；SS 产品路径禁止使用。

## Side Effects

- 仅内存加解密 + `SystemRandom` 读取 OS CSPRNG；无网络 I/O、无持久状态。

## Public API

```text
enum SsMethod { Chacha20IetfPoly1305 }   // as_str() -> "chacha20-ietf-poly1305"
enum Role { Client, Server }             // 保留；SIP004 下无派生差异
enum SsTarget { Ipv4([u8;4], u16), Domain(String, u16) }
fn encode_request(&SsTarget) -> Vec<u8>
fn parse_request(&[u8]) -> Result<SsTarget, OutboundCipherError>

struct SsStream { /* SIP004 流式会话 */ }
impl SsStream {
    fn new(password: &str, method: SsMethod, role: Role) -> Result<Self, OutboundCipherError>;
    fn with_tx_salt(password: &str, method: SsMethod, role: Role, tx_salt: [u8;32])
        -> Result<Self, OutboundCipherError>;      // 仅测试/金样
    fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, OutboundCipherError>;
    fn open(&mut self, data: &[u8]) -> Result<Vec<u8>, OutboundCipherError>;
}

struct ShadowsocksAdapter { /* 离线自洽；非 SIP004、无互操作证据 */ }
impl ShadowsocksAdapter {
    fn new(tag, locator, method, password) -> Result<Self, OutboundCipherError>;
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, OutboundCipherError>;
    fn decrypt(&mut self, frame: &[u8]) -> Result<Vec<u8>, OutboundCipherError>;
}
impl nexus_proxy_config::outbound_seam::OutboundAdapter for ShadowsocksAdapter { ... }

fn write_record<W: Write + ?Sized>(&mut W, &[u8]) -> io::Result<()>;   // legacy，非 SIP004
fn read_record<R: Read + ?Sized>(&mut R) -> io::Result<Vec<u8>>;       // legacy，非 SIP004
enum OutboundCipherError { KeyDerivation, InvalidFrame, DecryptFailed }
```

### 冻结契约：SIP004 真实 TCP 会话

- request header：首个 payload chunk 的明文必须以 `encode_request` 输出（`ATYP|addr|port`）开头，
  且 header 不得跨 chunk；SIP004 其余 chunk 可任意分块。
- 流式解码：salt 未满 32B 不产出、不报错；len/payload 未收齐不出该 chunk 明文；
  字节可任意切分到达。
- 错误语义：AEAD 校验失败 `DecryptFailed`；非法 len `InvalidFrame`；派生失败 `KeyDerivation`。
  对端 EOF 时缓冲内有半个 chunk **不是** crate 错误（由 io 层以连接关闭呈现）。
- 产品行为：调用方（`apps/nexus` SS arm）在 `open` Err 时 fail-closed 关连接，
  不重试、不降级直连、不静默吞字节。
- 既有 `ShadowsocksAdapter` 自洽行为与其测试保持不变。

## Verification

最低：

```text
cargo test -p nexus-outbound-shadowsocks
cargo clippy -p nexus-outbound-shadowsocks --all-targets -- -D warnings
python3 crates/nexus-outbound-shadowsocks/tests/kat/generate_kat.py --check
```

KAT（独立来源，禁止由待测实现自产）：

```text
tests/sip004_kat.rs        KAT-3/KAT-4 全流金样 + 6 类负向
tests/fixtures/*.bin       Python cryptography 生成（sha256 见 tests/kat/README.md）
src/lib.rs (tests)         KAT-1 EVP_BytesToKey、KAT-2 HKDF-SHA1、chunk 边界
```

产品行为映射（E4）：

```text
scenarios/product/proxy_shadowsocks_adapter.toml
scenarios/product/proxy_shadowsocks_real_tcp.toml
apps/nexus/examples/proxy_shadowsocks_adapter.rs
apps/nexus/examples/proxy_shadowsocks_real_tcp.rs
```

## Performance Budget

未定义性能预算的路径不得宣称"性能完成"。

## Observability

稳定结构化字段：method 标签、tag；不加每包自由文本日志。

## Recovery Semantics

无持久状态；进程重启后用同一配置重建。`open` 失败后流 poisoned，不重同步
（SIP004 无重同步机制），由上层关闭连接重建会话。

## Platform Constraints

`portable=false`；平台专有代码仅在 Composition Root。生产 salt 依赖 OS CSPRNG
（`ring::rand::SystemRandom`）。
