# nexus-ingress Module Contract

## Responsibility

提供 portable SOCKS5/HTTP 代理协议状态机、Packet/Stream 解码、Flow Classification 与 FlowContext 构造。
其中 Packet 解码（§11.18 TUN 透明入站）：把 wintun/VPI 读到的原始 IPv4 包纯函数解析为
`TunPacket`（proto + 四元组地址端口），供上层构造中立 `FlowContext`。

## Non-Responsibilities

不创建 OS 专有透明代理，不直接调用 Planner，不拥有 Network Session。

## Inputs

- 仅接受公开类型、DTO、trait、事件或稳定协议对象。
- 输入必须可被结构化验证；不得依赖未声明的全局隐式状态。

## Outputs

- 结构化 Result / Event / DTO。
- 失败必须保留可诊断原因，不以日志文本代替错误类型。

## Allowed Dependencies

- `nexus-domain`

## Forbidden Dependencies

- `engineering/` 下的 Harness/Plugin。
- 未在 `policies/architecture.toml` 声明的 Nexus 内部 crate。
- Portable 模块中的平台专有 Framework/API。
- 通过“便利”依赖绕过公开领域边界。
- `nexus-connectivity`（v9 CLI 产品线运行时，frozen）。跨栈词汇改用 `nexus-domain` /
  `nexus-proxy-config` / `nexus-session` / `nexus-qos`（P3 落地）。

## Invariants

- Ingress 是系统级 Driver 输入源，但通过 SessionManager/Application Layer 提交流量上下文。
- Transparent interception 位于 nexus-platform-*。
- 该 crate 必须保持 WASI/portable 可检查。
- SOCKS5 握手为有状态 enum 状态机（sing-box 吸收）：握手完成（Established）前
  不产出 `FlowContext`；失败路径必须返回结构化 `Socks5Error` 并进入 `Failed`。
- 状态机只做协议解析（RFC 1928/1929 帧格式），不持有认证凭据库；RFC 1929
  凭据格式合法即回成功，授权策略由上层决定。

## Side Effects

- 仅允许 Responsibility 所需且在架构层中明确归属的副作用。
- 新增副作用前必须更新本契约和 Scenario/Policy（如影响外部行为）。

## Public API

- 默认最小 surface：`private -> pub(crate) -> pub`。
- Public API 变更必须保持结构化、可版本化并有调用方验证。
- 已实现（骨架）：
  - `classify` + `from_socks5` / `from_http` / `from_virtual_packet_interface` /
    `from_native_api`：按 `FlowOrigin` 构造中立 `FlowContext`（纯函数，零 I/O）。
- 已实现（§11.18 TUN IP 包解码，纯函数零 I/O，portable）：
  - `ip_packet::TunPacket { protocol: u8, src_ip: [u8;4], dst_ip: [u8;4],
    src_port: u16, dst_port: u16 }`：解析后的 IPv4 传输五元组；
  - `ip_packet::parse_ipv4_packet(&[u8]) -> Option<TunPacket>`：仅接受 IPv4 且传输层为
    TCP(6)/UDP(17)；版本非 4、IHL 非法、截断、ICMP/其他协议、IPv6 一律返回 `None`
    （调用方计入 dropped，本模块不持有计数、不日志）；
  - `TunPacket::destination(&self) -> String`：`"dst_ip:dst_port"`，直接喂给
    `from_virtual_packet_interface` 构造 `FlowContext`。
- 已实现（SOCKS5 有状态握手状态机，sing-box 吸收）：
  - `Socks5Handshake`：`new()` / `state()` / `feed(&mut self, bytes) -> Socks5Step` /
    `command()` / `take_data()`（Established 后的数据面字节）；
  - `Socks5State`：Greeting / MethodSelected / UserPassAuth / Established / Failed；
  - `Socks5Step { state, response, flow, needs_more }`：需发送的响应字节 +
    握手完成时的 `FlowContext`（origin=Socks5, destination="host:port"）；
  - `Socks5Error`：BadVersion / BadMethodCount / NoAcceptableMethod / BadAuthVersion /
    AuthFailed / BadRequestVersion / UnsupportedCommand / UnsupportedAddressType /
    InvalidAddress（结构化，非文本日志）。
  - 支持 CONNECT（ATYP IPv4/域名/IPv6）与 UDP ASSOCIATE（CMD=0x03）；BIND/未知命令
    显式返回 command-not-supported（REP=0x07）。
- 已实现（SOCKS5 UDP ASSOCIATE 协议面，纯函数零 I/O，portable）：
  - `Socks5Address { Ipv4, Domain, Ipv6 }`：ATYP 三型 + `port()` /
    `to_destination_string()` / `is_unspecified()`；用数组/String 表示，
    不依赖 `std::net` socket。
  - `Socks5Command { Connect, UdpAssociate { client_endpoint } }`：
    握手 `Established` 后经 `Socks5Handshake::command()` 读取（`Socks5Step` 字段不变）。
  - `encode_udp_associate_reply(&Socks5Address)` / `encode_command_reply(rep, &Socks5Address)`：
    构造 BND 应答。**硬约定**：UDP ASSOCIATE 时 `Socks5Step.response` 为空
    （状态机不知道实际 bind 地址），调用方必须先 bind UDP socket，再用
    `encode_udp_associate_reply` 发送真实 BND。
  - `Socks5UdpDatagram { fragment, address, payload }` + `decode_udp_datagram` /
    `encode_udp_datagram`：RSV=0 校验、ATYP 三型、单包上限 65507；FRAG != 0 只保留
    字段由上层策略丢弃（本模块不做重组）。
  - `Socks5UdpError`：TooShort / BadReserved / UnsupportedAddressType /
    InvalidAddress / DatagramTooLarge（结构化）。

## Verification

最低：

```text
cargo check -p nexus-ingress
cargo clippy -p nexus-ingress --all-targets -- -D warnings
```

如果该模块影响产品行为，还必须映射 Integration/Scenario Evidence。

## Performance Budget

未定义性能预算的路径不得宣称“性能完成”。进入 hot path 后必须在 Contract 中增加 baseline、noise tolerance、warning threshold 与 blocking threshold。

## Observability

稳定结构化字段优先于自由文本；如涉及 Session/Provider/Path/Workspace，应携带对应 correlation id。

## Recovery Semantics

任何持久状态或长期任务都必须定义 crash 后的 reconcile 行为。无持久状态的纯模块应保持可重建。

## Platform Constraints

平台专有代码只允许存在于 `nexus-platform-*` 或 Composition Root。Portable crate 必须通过相应 portability gate。
