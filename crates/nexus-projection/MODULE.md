# MODULE.md — nexus-projection

## Responsibility

投影层 L3 隧道：把 TUN 设备抓到的 IP 包封装进 fabric 数据报，对端解封装后
注入其 TUN 设备。应用无需修改，用标准 socket API，地基在底下传输。

P0 只做 L3 隧道（DESIGN.md §6.1 阶段一）。语义入口（§6.2）和进程 QoS（§6.3）
是后续 phase。

## Non-Responsibilities

- 不做用户态 TCP 栈（§6.1 阶段二，远期用 smoltcp）。
- 不做 SOCKS5/HTTP 语义入口（`nexus-ingress` 已有解析器，3b 集成）。
- 不做进程归因/QoS（平台相关，后置）。
- 不做 TUN 设备路由决策（`nexus-proxy/tun.rs` 的职责）。
- 不做 QUIC 传输（`nexus-fabric`）、路径选择（`nexus-path`）。

## Inputs

- TUN 设备读到的原始 IP 包（IPv4/IPv6）。
- 对端发来的 fabric 数据报（载荷为原始 IP 包）。
- `FabricConn`（发送数据报）、`PathManager`（路径切换通知）。

## Outputs

- 封装好的 fabric 数据报（载荷 = 原始 IP 包，无额外头部）。
- 注入本地 TUN 设备的 IP 包。
- 统计：`TunStats { packets_in, packets_out, bytes_in, bytes_out }`。

## Allowed Dependencies

- `std` only（零 Tokio）
- `nexus-fabric`（`FabricConn::send_datagram` / `recv_datagram` 类型）
- `nexus-path`（`PathManager` 事件类型，仅类型）

## Forbidden Dependencies

- `tokio`, 任何 async runtime
- `nexus-proxy`（路由决策是另一维度；投影只做搬运）
- 平台 TUN FFI（`TunDevice` trait 抽象；Linux 实现在 crate 内 `os::linux` 模块，
  narrow unsafe，仿 `tun-dataplane` 纪律）

## Invariants

**S1（包完整）**：TUN → fabric → TUN 全程，IP 包字节级一致（IP 头 + 载荷）。

**S2（无额外头部）**：P0 封装零开销——fabric datagram 载荷就是原始 IP 包，
不加投影层头部。（未来需要元数据时再加版本化头部。）

**S3（尽力语义）**：继承 fabric datagram 的尽力语义；丢包不重传、不保证顺序。
（TCP 的可靠性由端到端 TCP 自己保证。）

**S4（双向对称）**：同一 `Projection` 实例同时做封装（出）和解封装（入）；
两个方向独立统计。

**S5（MTU 诚实）**：IP 包超过 fabric datagram 上限时，**丢弃并计数**，
不静默截断、不分片（P0）。`stats.dropped_oversize` 可见。

**S6（设备抽象）**：`TunDevice` trait 隔离 OS 相关；E4 用 `MockTun`
（内存环形缓冲），E5 才用真实设备。核心逻辑不依赖真实 TUN。

**S7（关闭语义）**：`Projection::close()` 停止收发线程，丢弃未发送的包，
不保证投递。

**S8（统计诚实）**：`TunStats` 只计实际读/写成功的包；mock 和真实设备
用同一统计代码。

## Side Effects

- TUN 设备读写（`TunDevice::read` / `write`）。
- 后台收发线程（owner：`Projection`，Drop 时 join）。
- fabric datagram 收发（经 `FabricConn`）。

## Public API

```rust
pub trait TunDevice: Send {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize>;
    fn write(&mut self, packet: &[u8]) -> io::Result<usize>;
    fn name(&self) -> &str;
}

/// 内存 mock，用于 E4（无权限需求）。
pub struct MockTun { /* 环形缓冲 */ }

pub struct ProjectionConfig {
    pub mtu: usize,  // fabric datagram 上限，默认 1400
}

pub struct TunStats {
    pub packets_in: u64,
    pub packets_out: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub dropped_oversize: u64,
}

pub struct Projection { /* ... */ }

impl Projection {
    /// 创建投影：tun 提供包源/汇，fabric 提供传输。
    /// P0：fabric 以 trait 抽象（MockFabric），不直接依赖 nexus-fabric 具体类型。
    pub fn new(tun: Box<dyn TunDevice>, config: ProjectionConfig) -> Self;
    /// 注入一个要发送的 IP 包（测试/E4 用；正常路径由后台线程从 TUN 读）。
    pub fn send_packet(&mut self, packet: &[u8]) -> Result<(), ProjectionError>;
    /// 取出一个收到的 IP 包（测试/E4 用；正常路径由后台线程写入 TUN）。
    pub fn recv_packet(&mut self) -> Option<Vec<u8>>;
    pub fn stats(&self) -> TunStats;
    pub fn close(self);
}
```

**注**：P0 的 `Projection` 先不绑定真实 `FabricConn`，用内部队列模拟
fabric 传输（E4 验证封装逻辑）；与 fabric 的真实接线是下一步（需要
`FabricConn` 的 datagram API 稳定）。

## Verification

- E4: `product.fabric-projection-basic`（包完整、双向）
- E4: `product.fabric-projection-roam`（路径切换时包不丢——P0 用 mock
  路径事件，验证切换通知处理）
- 单元测试：S1 包完整、S5 超大包丢弃计数、S6 mock/真实同一统计

## Performance Budget

- 每包一次内存拷贝（TUN → fabric 载荷），无额外分配（复用缓冲）。
- 后台线程：阻塞读 TUN，无忙轮询。

## Observability

- `TunStats` 可查询。
- `dropped_oversize` 单独计数（MTU 问题诊断）。

## Recovery Semantics

- `Projection` Drop 时 join 后台线程。
- `close()` 显式停止；未发送的包丢弃。

## Platform Constraints

- `MockTun` 纯 std，无平台代码。
- 真实 TUN（Linux `/dev/net/tun`）在 `os::linux` 模块，narrow unsafe；
  P0 可以只给 trait + MockTun，真实实现后置（E5）。

## Deletion Test

**问题**：如果删除 `nexus-projection`，让应用直接调用 `nexus-fabric`
发 datagram，会破坏哪个独立变化维度？

**回答**：TUN 设备管理（创建、读写、MTU、权限）与传输机制（QUIC、
加密、路径）是独立变化的。操作系统升级 TUN 行为（如 Windows wintun
换驱动）不应要求改动传输层。删除该抽象会导致设备细节泄漏到传输层。

**反例**：如果永远只有 SOCKS5 语义入口而不用 TUN，则该 crate 可删除。
但 P0 明确要 L3 隧道，抽象成立。
