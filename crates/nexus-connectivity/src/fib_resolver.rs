//! FIB 解析器抽象（§12.56）。
//!
//! 转发面（`virtual_subnet`）通过 `FibResolver` trait 查询 FIB，
//! 而不直接依赖 `nexus-discovery`（架构边界：connectivity 不能依赖 discovery）。
//! 具体的 FIB 实现（如基于 discovery LSDB 的）在 composition root（`apps/nexus`）提供。

use std::sync::Arc;

/// 精简流标识（§12.56）：用于 FIB 加权选择的流哈希输入。
///
/// 与 `nexus-discovery::routing::FlowKey` 语义一致（5 元组），
/// 但独立定义以避免跨 crate 依赖。仅支持 IPv4。
///
/// 注意：不提供 `hash()` 方法。实际的流哈希选择由 discovery 侧
/// `Fib::select_next_hop` 完成（见 `apps/nexus::DiscoveryFibResolver`），
/// 避免两套哈希实现分叉（§12.47 跨节点一致性）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKeyView {
    /// 源 IPv4（网络字节序 u32）。
    pub src_ip: u32,
    /// 目的 IPv4（网络字节序 u32）。
    pub dst_ip: u32,
    /// 源端口（TCP/UDP；其他协议为 0）。
    pub src_port: u16,
    /// 目的端口（TCP/UDP；其他协议为 0）。
    pub dst_port: u16,
    /// IP 协议号（如 6=TCP，17=UDP，1=ICMP）。
    pub protocol: u8,
}

impl FlowKeyView {
    /// 从 IPv4 包解析流标识。
    ///
    /// 返回 `None` 的情况：包太短、非 IPv4、IP 头选项过长。
    /// TCP/UDP 端口解析失败时端口为 0（仍可用 IP + 协议做流哈希）。
    #[must_use]
    pub fn parse_ipv4(packet: &[u8]) -> Option<Self> {
        if packet.len() < 20 {
            return None;
        }
        // Version + IHL。
        let version_ihl = packet[0];
        if version_ihl >> 4 != 4 {
            return None; // 非 IPv4
        }
        let ihl = (version_ihl & 0x0F) as usize;
        if ihl < 5 || packet.len() < ihl * 4 {
            return None;
        }
        let protocol = packet[9];
        let src_ip = u32::from_be_bytes(packet[12..16].try_into().ok()?);
        let dst_ip = u32::from_be_bytes(packet[16..20].try_into().ok()?);

        let header_len = ihl * 4;
        let (src_port, dst_port) = match protocol {
            // TCP/UDP：端口在传输头前 4 字节；包太短时端口回退为 0。
            6 | 17 if packet.len() >= header_len + 4 => (
                u16::from_be_bytes(packet[header_len..header_len + 2].try_into().ok()?),
                u16::from_be_bytes(packet[header_len + 2..header_len + 4].try_into().ok()?),
            ),
            _ => (0, 0),
        };
        Some(Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
        })
    }
}

/// FIB 解析器（§12.56）：转发面查询 FIB 的抽象。
///
/// 实现方（如 `apps/nexus` 的 `DiscoveryFibResolver`）持有
/// `SharedFibManager` + `PeerId→VIP` 映射，按流哈希选择下一跳。
pub trait FibResolver: Send + Sync {
    /// 查询 dst VIP 的下一跳 VIP。
    ///
    /// - `Some(vip)`：FIB 命中，返回下一跳的 VIP（调用方保证其为已注册 peer）。
    /// - `None`：FIB 无条目，调用方回退到静态路由等原有逻辑。
    fn resolve(&self, dst_vip: &str, flow: &FlowKeyView) -> Option<String>;
}

/// 空实现（测试用）：恒返回 None（即禁用 FIB，回退原有逻辑）。
#[derive(Debug, Clone, Copy, Default)]
pub struct NoFib;

impl FibResolver for NoFib {
    fn resolve(&self, _dst_vip: &str, _flow: &FlowKeyView) -> Option<String> {
        None
    }
}

/// 共享的 FIB 解析器（`Arc<dyn FibResolver>` 别名）。
pub type SharedFibResolver = Arc<dyn FibResolver>;

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_packet(protocol: u8, src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16) -> Vec<u8> {
        let mut p = vec![0u8; 24];
        p[0] = 0x45; // IPv4, IHL=5
        p[9] = protocol;
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        p[20..22].copy_from_slice(&sport.to_be_bytes());
        p[22..24].copy_from_slice(&dport.to_be_bytes());
        p
    }

    #[test]
    fn parse_tcp_packet() {
        let pkt = ipv4_packet(6, [10, 0, 0, 1], 12345, [10, 0, 0, 2], 80);
        let fk = FlowKeyView::parse_ipv4(&pkt).unwrap();
        assert_eq!(fk.src_ip, 0x0A000001);
        assert_eq!(fk.dst_ip, 0x0A000002);
        assert_eq!(fk.src_port, 12345);
        assert_eq!(fk.dst_port, 80);
        assert_eq!(fk.protocol, 6);
    }

    #[test]
    fn parse_udp_packet() {
        let pkt = ipv4_packet(17, [192, 168, 1, 1], 53, [192, 168, 1, 2], 5353);
        let fk = FlowKeyView::parse_ipv4(&pkt).unwrap();
        assert_eq!(fk.protocol, 17);
        assert_eq!(fk.src_port, 53);
    }

    #[test]
    fn parse_icmp_no_ports() {
        let pkt = ipv4_packet(1, [10, 0, 0, 1], 0, [10, 0, 0, 2], 0);
        let fk = FlowKeyView::parse_ipv4(&pkt).unwrap();
        assert_eq!(fk.protocol, 1);
        assert_eq!(fk.src_port, 0);
        assert_eq!(fk.dst_port, 0);
    }

    #[test]
    fn parse_rejects_non_ipv4() {
        // IPv6 版本号。
        let mut pkt = ipv4_packet(6, [10, 0, 0, 1], 1, [10, 0, 0, 2], 80);
        pkt[0] = 0x60;
        assert!(FlowKeyView::parse_ipv4(&pkt).is_none());
    }

    #[test]
    fn parse_rejects_short() {
        assert!(FlowKeyView::parse_ipv4(&[0u8; 10]).is_none());
    }

    #[test]
    fn parse_with_ip_options() {
        // IHL=6（24 字节头，4 字节选项）：端口偏移应跳过选项。
        let mut pkt = vec![0u8; 28];
        pkt[0] = 0x46; // IPv4, IHL=6
        pkt[9] = 6; // TCP
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt[16..20].copy_from_slice(&[10, 0, 0, 2]);
        // 选项 4 字节（20..24），端口在 24..28。
        pkt[24..26].copy_from_slice(&8080u16.to_be_bytes());
        pkt[26..28].copy_from_slice(&80u16.to_be_bytes());
        let fk = FlowKeyView::parse_ipv4(&pkt).unwrap();
        assert_eq!(fk.src_port, 8080);
        assert_eq!(fk.dst_port, 80);
    }

    #[test]
    fn parse_truncated_transport_ports_fallback() {
        // TCP 但包在传输头处截断：端口回退为 0，仍返回 Some。
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0x45;
        pkt[9] = 6; // TCP
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt[16..20].copy_from_slice(&[10, 0, 0, 2]);
        let fk = FlowKeyView::parse_ipv4(&pkt).unwrap();
        assert_eq!(fk.src_port, 0);
        assert_eq!(fk.dst_port, 0);
        assert_eq!(fk.protocol, 6);
    }

    #[test]
    fn no_fib_returns_none() {
        let r = NoFib;
        let fk = FlowKeyView {
            src_ip: 1,
            dst_ip: 2,
            src_port: 3,
            dst_port: 4,
            protocol: 6,
        };
        assert!(r.resolve("10.0.0.2", &fk).is_none());
    }
}
