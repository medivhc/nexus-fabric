//! §11.17 TUN 透明入站：原始 IPv4 包的纯函数解码。
//!
//! 本模块零 I/O、零 unsafe（继承 `#![forbid(unsafe_code)]`），只做字节校验与字段提取，
//! 不持有计数、不打日志。它把 wintun/VPI 读到的 IP 帧解析为中立 `TunPacket`，
//! 上层据此构造 `FlowContext`。无法解析或非目标协议的包返回 `None`，由调用方计数丢弃。

/// IPv4 协议号（TCP）。
pub const PROTO_TCP: u8 = 6;
/// IPv4 协议号（UDP）。
pub const PROTO_UDP: u8 = 17;

/// 最小 IPv4 头长度（无选项）。
const MIN_IPV4_HEADER: usize = 20;

/// 解析后的 IPv4 传输五元组（§11.17）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TunPacket {
    /// IP 层协议号（仅 TCP=6 / UDP=17）。
    pub protocol: u8,
    /// 源 IPv4 地址（网络序 4 字节）。
    pub src_ip: [u8; 4],
    /// 目的 IPv4 地址（网络序 4 字节）。
    pub dst_ip: [u8; 4],
    /// 源端口（主机序）。
    pub src_port: u16,
    /// 目的端口（主机序）。
    pub dst_port: u16,
}

impl TunPacket {
    /// 中立分流目的地 `"dst_ip:dst_port"`，直接喂给
    /// `from_virtual_packet_interface` 构造 `FlowContext`。
    #[must_use]
    pub fn destination(&self) -> String {
        format!(
            "{}.{}.{}.{}:{}",
            self.dst_ip[0], self.dst_ip[1], self.dst_ip[2], self.dst_ip[3], self.dst_port
        )
    }

    /// NAT/连接跟踪键：`(protocol, src_ip, src_port, dst_ip, dst_port)`。
    #[must_use]
    pub fn flow_key(&self) -> (u8, [u8; 4], u16, [u8; 4], u16) {
        (
            self.protocol,
            self.src_ip,
            self.src_port,
            self.dst_ip,
            self.dst_port,
        )
    }
}

/// 解析一个原始 IPv4 包。
///
/// 仅接受 IPv4 且传输层为 TCP(6) / UDP(17)。以下情况返回 `None`（调用方计入 dropped）：
/// 长度不足、IP 版本号非 4、IHL 非法（<5 或超过包长）、传输协议非 TCP/UDP、
/// 传输端口字段被截断。不校验 IP 头校验和、不重组分片、不解 ICMP/IPv6。
#[must_use]
pub fn parse_ipv4_packet(data: &[u8]) -> Option<TunPacket> {
    if data.len() < MIN_IPV4_HEADER {
        return None;
    }
    let version = data[0] >> 4;
    if version != 4 {
        return None;
    }
    let ihl = (data[0] & 0x0f) as usize;
    if ihl < 5 {
        return None;
    }
    let header_len = ihl * 4;
    if header_len > data.len() {
        return None;
    }
    let protocol = data[9];
    if protocol != PROTO_TCP && protocol != PROTO_UDP {
        return None;
    }
    // 传输层端口至少占 4 字节（TCP/UDP 头前 4 字节同为 src/dst port）。
    if data.len() < header_len + 4 {
        return None;
    }
    let mut src_ip = [0u8; 4];
    src_ip.copy_from_slice(&data[12..16]);
    let mut dst_ip = [0u8; 4];
    dst_ip.copy_from_slice(&data[16..20]);
    let src_port = u16::from_be_bytes([data[header_len], data[header_len + 1]]);
    let dst_port = u16::from_be_bytes([data[header_len + 2], data[header_len + 3]]);
    Some(TunPacket {
        protocol,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一个合法 IPv4/TCP 包（含可变 IHL/协议/端口）。
    fn ipv4_packet(
        protocol: u8,
        ihl_words: u8,
        src: [u8; 4],
        dst: [u8; 4],
        sport: u16,
        dport: u16,
    ) -> Vec<u8> {
        let header_len = ihl_words as usize * 4;
        let mut pkt = vec![0u8; header_len + 8];
        pkt[0] = (4u8 << 4) | ihl_words;
        pkt[8] = 64; // TTL
        pkt[9] = protocol;
        pkt[12..16].copy_from_slice(&src);
        pkt[16..20].copy_from_slice(&dst);
        pkt[header_len..header_len + 2].copy_from_slice(&sport.to_be_bytes());
        pkt[header_len + 2..header_len + 4].copy_from_slice(&dport.to_be_bytes());
        pkt
    }

    #[test]
    fn parses_tcp_syn() {
        let p = ipv4_packet(PROTO_TCP, 5, [192, 168, 1, 5], [10, 1, 2, 3], 12345, 443);
        let out = parse_ipv4_packet(&p).expect("tcp packet parses");
        assert_eq!(out.protocol, PROTO_TCP);
        assert_eq!(out.src_ip, [192, 168, 1, 5]);
        assert_eq!(out.dst_ip, [10, 1, 2, 3]);
        assert_eq!(out.src_port, 12345);
        assert_eq!(out.dst_port, 443);
        assert_eq!(out.destination(), "10.1.2.3:443");
    }

    #[test]
    fn parses_udp_dns() {
        let p = ipv4_packet(PROTO_UDP, 5, [192, 168, 1, 5], [8, 8, 8, 8], 53000, 53);
        let out = parse_ipv4_packet(&p).expect("udp packet parses");
        assert_eq!(out.protocol, PROTO_UDP);
        assert_eq!(out.destination(), "8.8.8.8:53");
    }

    #[test]
    fn ihl_with_options_offsets_ports() {
        // IHL=6（24 字节头）：端口应在偏移 24 而非 20。
        let p = ipv4_packet(PROTO_TCP, 6, [1, 1, 1, 1], [2, 2, 2, 2], 1000, 80);
        let out = parse_ipv4_packet(&p).expect("parses with options");
        assert_eq!(out.src_port, 1000);
        assert_eq!(out.dst_port, 80);
    }

    #[test]
    fn rejects_short_packets() {
        assert!(parse_ipv4_packet(&[]).is_none());
        assert!(parse_ipv4_packet(&[0x45, 0, 0, 0]).is_none());
    }

    #[test]
    fn rejects_non_ipv4() {
        // version = 6。
        let mut p = ipv4_packet(PROTO_TCP, 5, [1, 1, 1, 1], [2, 2, 2, 2], 1, 2);
        p[0] = (6u8 << 4) | 5;
        assert!(parse_ipv4_packet(&p).is_none());
    }

    #[test]
    fn rejects_bad_ihl() {
        // IHL=4 (<5)。
        let mut p = ipv4_packet(PROTO_TCP, 5, [1, 1, 1, 1], [2, 2, 2, 2], 1, 2);
        p[0] = (4u8 << 4) | 4;
        assert!(parse_ipv4_packet(&p).is_none());
    }

    #[test]
    fn rejects_icmp_and_other_protocols() {
        let p = ipv4_packet(1, 5, [1, 1, 1, 1], [2, 2, 2, 2], 0, 0); // ICMP
        assert!(parse_ipv4_packet(&p).is_none());
        let p = ipv4_packet(47, 5, [1, 1, 1, 1], [2, 2, 2, 2], 0, 0); // GRE
        assert!(parse_ipv4_packet(&p).is_none());
    }

    #[test]
    fn rejects_truncated_transport_ports() {
        // IPv4 头完整但传输端口被截断。
        let p = ipv4_packet(PROTO_TCP, 5, [1, 1, 1, 1], [2, 2, 2, 2], 1, 2);
        assert!(parse_ipv4_packet(&p[..22]).is_none());
    }

    #[test]
    fn flow_key_distinguishes_flows() {
        let a = ipv4_packet(PROTO_TCP, 5, [192, 168, 1, 5], [10, 1, 2, 3], 12345, 443);
        let b = ipv4_packet(PROTO_UDP, 5, [192, 168, 1, 5], [8, 8, 8, 8], 53000, 53);
        let ka = parse_ipv4_packet(&a).unwrap().flow_key();
        let kb = parse_ipv4_packet(&b).unwrap().flow_key();
        assert_ne!(ka, kb);
    }
}
