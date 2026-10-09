//! Code Intelligence 夹具 crate root。
//!
//! 覆盖提案 §15 Phase 1 要求的最小确定性边界：trait、多 impl、泛型、
//! re-export、cfg。零外部依赖，保证 rust-analyzer 冷启动结果可重现。

mod transport;

/// re-export：验证 Agent 经公开路径查询时 `definition` 能穿透到真实声明处。
pub use transport::{Egress, RelayEgress, TcpEgress, UdpEgress};

/// 就绪探针：`nexus-harness code` 的 provider 在响应查询前等待该 symbol 可见，
/// 以此判定 rust-analyzer 已完成 workspace 加载（不依赖 RA 私有的状态字符串）。
pub const PROBE_READY: &str = "CodeIntelFixtureProbe";

/// 结构体方法：hover / definition 的单点锚。
pub struct Scheduler {
    /// 每次调用的最大重试次数。
    pub retries: u32,
}

impl Scheduler {
    /// 冻结锚点：本行的 `tick` 用于 `code definition` 与 `code callers`。
    pub fn tick(&self, egress: &dyn Egress, payload: &[u8]) -> Result<usize, &'static str> {
        let mut sent = 0usize;
        for _ in 0..self.retries {
            sent = transport::dispatch_dyn(egress, payload)?;
            if sent > 0 {
                break;
            }
        }
        Ok(sent)
    }
}

/// 泛型入口：验证 `typeDefinition` / generic 参数的 resolution。
pub fn run_static<E: Egress>(egress: &E, payload: &[u8]) -> usize {
    transport::dispatch(egress, payload).unwrap_or(0)
}

/// cfg 边界：非 Linux 平台上该函数仍存在（返回 Unsupported），
/// 使 `code references` 的结果集在不同平台上仍为确定值。
pub fn platform_send(egress: &TcpEgress, payload: &[u8]) -> &'static str {
    #[cfg(target_os = "linux")]
    {
        let _ = (egress, payload);
        "linux"
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (egress, payload);
        "unsupported"
    }
}

#[cfg(test)]
mod tests {
    use super::{Egress, Scheduler, TcpEgress, UdpEgress, platform_send, run_static};

    #[test]
    fn fixture_impls_are_deterministic() {
        assert_eq!(TcpEgress { peer: String::new() }.name(), "tcp");
        assert_eq!(UdpEgress { peer: String::new() }.name(), "udp");
    }

    #[test]
    fn fixture_call_chain_compiles() {
        let egress = TcpEgress {
            peer: "127.0.0.1:0".to_string(),
        };
        assert_eq!(run_static(&egress, b"abc"), 3);
        assert_eq!(platform_send(&egress, b"abc").len() > 0, true);
        let sched = Scheduler { retries: 2 };
        assert_eq!(sched.tick(&egress, b"x").unwrap_or(0), 1);
    }
}
