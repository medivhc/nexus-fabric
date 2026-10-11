//! 语义查询夹具：trait + 多 impl + 泛型分派 + 调用链。
//!
//! 本文件的**行号与列号是冻结契约的一部分**（E4 Scenario 以
//! `src/transport.rs:<line>:<col>` 形式引用），改动必须重走契约阶段。

/// 出口能力：一个 trait，三个实现（用于 `textDocument/implementation` 计数）。
pub trait Egress {
    /// 发送一帧。冻结位置：本行的 `send` 标识符即 Scenario 锚点。
    fn send(&self, payload: &[u8]) -> Result<usize, &'static str>;

    /// 稳定标识，用于 `callers` / `callees` 一层展开。
    fn name(&self) -> &'static str;
}

pub struct TcpEgress {
    pub peer: String,
}

impl Egress for TcpEgress {
    fn send(&self, payload: &[u8]) -> Result<usize, &'static str> {
        Ok(payload.len())
    }

    fn name(&self) -> &'static str {
        "tcp"
    }
}

pub struct UdpEgress {
    pub peer: String,
}

impl Egress for UdpEgress {
    fn send(&self, payload: &[u8]) -> Result<usize, &'static str> {
        Ok(payload.len())
    }

    fn name(&self) -> &'static str {
        "udp"
    }
}

pub struct RelayEgress {
    pub hop: Box<dyn Egress>,
}

impl Egress for RelayEgress {
    fn send(&self, payload: &[u8]) -> Result<usize, &'static str> {
        self.hop.send(payload)
    }

    fn name(&self) -> &'static str {
        "relay"
    }
}

/// 泛型静态分派：`dispatch` 是 `Egress::send` 的调用者（callers 锚点）。
pub fn dispatch<E: Egress>(egress: &E, payload: &[u8]) -> Result<usize, &'static str> {
    let _label = egress.name();
    egress.send(payload)
}

/// 动态分派：`dispatch_dyn` 同样调用 `Egress::send`。
pub fn dispatch_dyn(egress: &dyn Egress, payload: &[u8]) -> Result<usize, &'static str> {
    egress.send(payload)
}
