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
- 离线 loopback E4 所需的 TLS 会话原语（不连公网）。

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

## Side Effects

- 打开 loopback TCP 监听/连接；生成内存内自签证书；不写盘、不读系统证书库。

## Verification

- crate 内单测：请求头编解码往返、错密码 → `AUTH_DENIED`、kind/tag 稳定；
- E4：`scenarios/product/proxy_trojan_adapter.toml`、`proxy_trojan_auth_rejected.toml`。

## Portability

`portable = false`：ring 需要 C/asm，`cargo check --target wasm32-wasip1` 实测失败；
本 crate 不进 `harness.toml [portable_core]`，不污染 portable-core 门禁。

## Unsafe

本 crate 自身 `#![forbid(unsafe_code)]`；ring 内部 unsafe 属第三方，不在本 crate 扩散。
