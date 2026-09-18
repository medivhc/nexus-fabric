# nexus-outbound-trojan

> 出站层 crate（`layer = "outbound"`, `portable = false`）。
> 对应 PRODUCT §11.9。

## Responsibility

实现 `nexus_connectivity::OutboundAdapter` 的第五个真实出站实现 **Trojan**：
在既有 TCP 字节流之上叠加 TLS（rustls 0.23 + ring）与 trojan 请求头
（`hex(SHA-224(password)) | CRLF | ATYP+ADDR+PORT | CRLF`），其后双向透明中继。

提供：
- 请求头编码/解码与密码 SHA-224 校验（纯函数，可单测）；
- rcgen 动态自签证书生成 + rustls 客户端证书 pinning / 服务端配置构造；
- 面向真实节点的客户端 TLS 参数：skip-cert-verify（danger API）+ ALPN 下发；
- 离线 loopback E4 所需的 TLS 会话原语（不连公网）；
- 请求头格式兼容：Standard（trojan-gfw，无命令字节，默认）与 Singbox（ATYP 前带 0x01 CONNECT）。

## Non-Responsibilities

- 不实现 TUN/透明网卡、不做 UDP、不做 WebSocket/gRPC 伪装、不做多路复用；
- 不做系统根证书校验（客户端固定 pin 服务端公钥）；
- `nexus-proxy` / 选路 / 策略组不依赖本 crate（组合根装配，同 shadowsocks/vmess）；
- 不做第二套系统级 Plan。

## Inputs

- 配置：`tag`、服务端 `locator`、`password`、SNI；
- 运行时：loopback `std::net::TcpStream` + rustls TLS stream。

## Outputs

- `OutboundAdapter::handoff` → `OutboundHandoff { kind = "trojan", tag, locator }`；
- 请求头字节流；结构化错误。

## Allowed Dependencies

- `nexus-connectivity`（OutboundAdapter 接缝）；
- 已评审入仓第三方：`rustls 0.23(ring,std)`、`rcgen 0.13`、`sha2 0.10`。

## Forbidden Dependencies

- `nexus-proxy` / 选路 / 策略组 / 系统根证书（webpki-root-certs 类 CDLA 包）；
- tokio / 异步运行时（与仓库 loopback blocking+thread 模式一致）；
- 任何 wasm 不可移植但未隔离的依赖。

## Invariants

- `outbound_kind() == "trojan"`（稳定标签）；
- 密码首行不匹配 → `AUTH_DENIED`，且**不在失败消息中泄露密码或其 hash 前缀**；
- TLS 客户端只接受被 pin 的服务端证书（`CertificateVerifier` 自定义）；
- 离线确定性：同一份 password+目标永远产生同一请求头字节；不连公网；
- server/client 会话线程必须 join 回收（结构化并发）。
- skip-cert-verify 仅跳过证书链/主机名校验，**仍执行 TLS 握手签名校验**；ALPN 协商结果可观测；
- SNI 由调用方以 `ServerName` 传入，本 crate 不硬编码域名、不硬编码真实密码。
- 请求头**默认 Standard**（trojan-gfw 规范）；客户端编码与本地 server 解析按同一 `TrojanHeaderFormat` 配对；
  格式不匹配 → `INVALID_HEADER`（不被误判为 `AUTH_DENIED`）。

## Side Effects

- 打开 loopback TCP 监听/连接；生成内存内自签证书；不写盘、不读系统证书库。

## Verification

- crate 内单测：请求头编解码往返、错密码 → `AUTH_DENIED`、kind/tag 稳定；
- E4：`scenarios/product/proxy_trojan_adapter.toml`、`proxy_trojan_auth_rejected.toml`、
  `proxy_trojan_real_tls_params.toml`（skip-verify + ALPN 协商 + 往返）、
  `proxy_trojan_header_format.toml`（Singbox 命令字节格式 + Standard 回归）。

## Portability

`portable = false`：ring 需要 C/asm，`cargo check --target wasm32-wasip1` 实测失败；
本 crate 不进 `harness.toml [portable_core]`，不污染 portable-core 门禁。

## Unsafe

本 crate 自身 `#![forbid(unsafe_code)]`；ring 内部 unsafe 属第三方，不在本 crate 扩散。

## Public API（新增，§11.9.1）

- `client_config_dangerous_skip_verify(alpn: &[&[u8]]) -> Result<ClientConfig, TrojanError>`：
  用 rustls `danger::ServerCertVerifier` 自定义实现跳过服务端证书校验，并下发 ALPN 列表；
  握手签名仍校验。零新依赖（rustls 0.23 内置）。
- `ServerName` 由调用方传入（SNI 不硬编码）。

## Public API（新增，§11.9.2）

- `TrojanHeaderFormat::{Standard, Singbox}`：请求头格式选择。Standard=trojan-gfw（无命令字节，默认）；
  Singbox=ATYP 前带 `0x01` CONNECT 命令字节（sing-box 系服务器变体）。
- `encode_request_fmt(password, target, fmt)` / `parse_request_fmt(password, buf, fmt)`：
  按格式编解码；`encode_request` / `parse_request` 保留为 Standard 默认，既有调用零回归。
