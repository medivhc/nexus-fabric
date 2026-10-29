# nexus-outbound-vmess

VMess AEAD 出站 adapter（PRODUCT.md §11.7）：实现
`nexus_proxy_config::outbound_seam::OutboundAdapter`，在与 Shadowsocks 同一接缝上新增第四个真实出站。

## Responsibility

- 把出站字节流用 VMess AEAD 记录层封装/解封装（`nonce(12B) || ciphertext+tag`）。
- 作为 `OutboundAdapter` 的一个真实实现注册（`outbound_kind() = "vmess"`）。

## Non-Responsibilities

- 不做真实 vmess 协议线格式逐字节兼容（真实多跳 / TLS 传输后置）。
- 不调用系统级 Core Planner；不产生第二套系统级 Plan。
- 不发起真实网络连接；E4 仅离线 AEAD 自洽往返。

## Inputs

- `tag`、`locator`（host:port）、VMess security method、UUID（用作 key 材料）。

## Outputs

- `VmessAdapter`（实现 `OutboundAdapter`）；`encrypt`/`decrypt` 记录帧；结构化错误
  `VmessCipherError`。
- `OutboundAdapter::handoff` 的错误类型为 `OutboundHandoffError`（当前无生产者，见
  proxy-config MODULE）。

## Allowed Dependencies

- `nexus-proxy-config`（`OutboundAdapter` / `OutboundHandoff` / `OutboundHandoffError`）。
- 已评审入仓的 `chacha20poly1305` / `sha2`（RustCrypto，纯 Rust）。

## Forbidden Dependencies

- 平台 API、其它 outbound crate、registry/planner。
- `nexus-connectivity`（v9 CLI 产品线运行时，frozen；**目标态禁止**）。
  接缝 ② 已于 2026-10-28（P2）清除：出站身份/交接词汇定义于 `nexus-proxy-config`，
  本 crate 对 `nexus-connectivity` 的直接边为 0
  （见 `docs/DOC-AUDIT-2026-10-26-dual-stack.md` 与 `docs/adr/0001-dual-stack-boundary.md`）。

## Invariants

- UUID 经 SHA-256 确定性派生 32 字节会话 key；固定计数器 nonce，不调 getrandom（离线确定性）。
- 加密帧 = `nonce(12B) || ciphertext+tag`；解密用帧内 nonce。
- `VmessAdapter` 是开放接缝（新增协议 = 新增一个 adapter 实现，不改既有选路/激活路径）。

## Deletion Test（AGENTS.md §12）

成立：Direct / Relay / Shadowsocks / VMess 是四个带真实行为的出站维度。删掉本 adapter 而
继续硬编码 direct/relay/shadowsocks，会丢失「新协议作为独立出站实现」这一已存在的变化维度
（新增 vmess 不改动既有激活/选路路径，仅新增一个实现并注册）。

## Side Effects

- 无网络副作用（离线；不连真实 server）。

## Public API

- `VmessSecurity::Chacha20Poly1305`（`as_str` / `parse`）。
- `VmessAdapter::new(tag, locator, security, uuid)` / `encrypt` / `decrypt` / `handoff`。

## Verification

```text
cargo check -p nexus-outbound-vmess
cargo clippy -p nexus-outbound-vmess --all-targets -- -D warnings
```

产品行为映射 E4：`scenarios/product/proxy_vmess_adapter.toml`。

## Platform Constraints

portable=false：依赖第三方 crypto（RustCrypto），不进入 `harness.toml [portable_core]`。
零 `unsafe`。
