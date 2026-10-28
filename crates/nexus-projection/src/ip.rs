//! 双栈 IP 报文解析与构造（R3 WP-V6-A / C15）。
//!
//! 纯函数模块：零 I/O、零时间、零全局状态。生产数据面（`apps/nexusd`）用它
//! 解析 v6 固定头/扩展头链，并构造 DNS 响应与 TCP RST。
//!
//! 口径（spec §4.7.3 / §5.6）：
//! - 版本 6、固定头 40B；目的地址恒来自固定头（分类不需要 L4）；
//! - 扩展头链支持 `0`（Hop-by-Hop）、`43`（Routing）、`60`（Destination
//!   Options）、`44`（Fragment）；`44` **不重组**（`NonFirstFragment` 交给调用方
//!   按目的地址分类）；
//! - ESP(50)/AH(51) 无法安全定位 L4 → [`IpParseError::UnsupportedExtension`]；
//! - 超过 8 个扩展头 → [`IpParseError::TooManyExtensionHeaders`]（fail-closed）；
//! - **入站包不校验 L4 校验和**（TUN 可能携带 CHECKSUM_PARTIAL）；我们自己构造
//!   的 v6 包必须写完整校验和（单测自校验 == 0）。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// IP 版本。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpVersion {
    /// IPv4。
    V4,
    /// IPv6。
    V6,
}

/// 地址/报文解析错误（AC15：可判别变体；与 `flow::FlowParseError` 同表）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpParseError {
    /// 短于固定头，或扩展头/载荷越界。
    Truncated,
    /// 版本字段非 4/6。
    BadVersion(u8),
    /// 扩展头链超过 8 个。
    TooManyExtensionHeaders,
    /// ESP/AH 等无法安全定位 L4 的扩展头（值为 next header）。
    UnsupportedExtension(u8),
    /// 非首片（不重组；调用方按目的地址分类）。
    NonFirstFragment,
    /// 非 TCP/UDP 传输协议（不建 flow；调用方按目的地址分类）。
    UnsupportedTransport(u8),
    /// 内部构造的包自校验失败（仅构造路径/测试使用）。
    BadChecksum,
    /// 源/目的地址族不一致（构造路径）。
    AddressFamilyMismatch,
}

/// 解析后的 IP 报文视图（借用入参，零拷贝）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpPacketView<'a> {
    /// 版本。
    pub version: IpVersion,
    /// 源地址。
    pub src: IpAddr,
    /// 目的地址。
    pub dst: IpAddr,
    /// 传输层协议号（v4 头 `protocol` / v6 链尾 `next header`）。
    pub protocol: u8,
    /// L4 起始偏移（v4 = IHL；v6 = 固定头 + 扩展头链）。
    pub l4_offset: usize,
    /// L4 及之后字节。
    pub payload: &'a [u8],
    /// v6 链中出现过 Fragment 头（`44`）；调用方据此计 `ipv6.fragments`。
    ///
    /// v4 恒为 false（v4 分片仍走既有 `direct_dropped_unsupported` 语义）。
    pub has_fragment_header: bool,
}

/// 解析后的 UDP 视图。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpView<'a> {
    /// 源（含端口）。
    pub src: SocketAddr,
    /// 目的（含端口）。
    pub dst: SocketAddr,
    /// UDP 载荷。
    pub payload: &'a [u8],
}

/// 支持的 v6 扩展头（链式头部，长度在 byte 1，单位 8 字节）。
fn is_chain_extension(next_header: u8) -> bool {
    matches!(next_header, 0 | 43 | 60)
}

/// 解析 IP 报文（v4/v6）为 [`IpPacketView`]。
///
/// # Errors
/// 见 [`IpParseError`]。`NonFirstFragment` / `UnsupportedExtension` /
/// `UnsupportedTransport` 都由调用方按"不解析 L4、按目的地址分类"处理，
/// 不是静默丢弃。
pub fn parse_ip_packet(packet: &[u8]) -> Result<IpPacketView<'_>, IpParseError> {
    let version = packet
        .first()
        .map(|b| b >> 4)
        .ok_or(IpParseError::Truncated)?;
    match version {
        4 => parse_v4(packet),
        6 => parse_v6(packet),
        other => Err(IpParseError::BadVersion(other)),
    }
}

fn parse_v4(packet: &[u8]) -> Result<IpPacketView<'_>, IpParseError> {
    if packet.len() < 20 {
        return Err(IpParseError::Truncated);
    }
    let ihl = usize::from(packet[0] & 0x0f) * 4;
    if ihl < 20 || packet.len() < ihl {
        return Err(IpParseError::Truncated);
    }
    let src = IpAddr::V4(Ipv4Addr::new(
        packet[12], packet[13], packet[14], packet[15],
    ));
    let dst = IpAddr::V4(Ipv4Addr::new(
        packet[16], packet[17], packet[18], packet[19],
    ));
    Ok(IpPacketView {
        version: IpVersion::V4,
        src,
        dst,
        protocol: packet[9],
        l4_offset: ihl,
        payload: &packet[ihl..],
        has_fragment_header: false,
    })
}

fn parse_v6(packet: &[u8]) -> Result<IpPacketView<'_>, IpParseError> {
    if packet.len() < 40 {
        return Err(IpParseError::Truncated);
    }
    let mut src_octets = [0u8; 16];
    src_octets.copy_from_slice(&packet[8..24]);
    let mut dst_octets = [0u8; 16];
    dst_octets.copy_from_slice(&packet[24..40]);
    let src = IpAddr::V6(Ipv6Addr::from(src_octets));
    let dst = IpAddr::V6(Ipv6Addr::from(dst_octets));

    let mut next_header = packet[6];
    let mut offset = 40usize;
    let mut extensions = 0usize;
    let mut has_fragment_header = false;

    loop {
        if is_chain_extension(next_header) {
            extensions += 1;
            if extensions > MAX_EXTENSION_HEADERS {
                return Err(IpParseError::TooManyExtensionHeaders);
            }
            if packet.len() < offset + 2 {
                return Err(IpParseError::Truncated);
            }
            let ext_len = (usize::from(packet[offset + 1]) + 1) * 8;
            if packet.len() < offset + ext_len {
                return Err(IpParseError::Truncated);
            }
            next_header = packet[offset];
            offset += ext_len;
            continue;
        }
        match next_header {
            // Fragment：不重组。非首片无 L4 头，交给调用方按目的地址分类。
            44 => {
                extensions += 1;
                if extensions > MAX_EXTENSION_HEADERS {
                    return Err(IpParseError::TooManyExtensionHeaders);
                }
                if packet.len() < offset + 8 {
                    return Err(IpParseError::Truncated);
                }
                has_fragment_header = true;
                let fragment_field = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
                let fragment_offset = fragment_field >> 3;
                next_header = packet[offset];
                offset += 8;
                if fragment_offset != 0 {
                    return Err(IpParseError::NonFirstFragment);
                }
                continue;
            }
            // ESP / AH：长度语义不同且载荷加密，无法安全定位 L4。
            50 | 51 => return Err(IpParseError::UnsupportedExtension(next_header)),
            _ => break,
        }
    }

    Ok(IpPacketView {
        version: IpVersion::V6,
        src,
        dst,
        protocol: next_header,
        l4_offset: offset,
        payload: &packet[offset..],
        has_fragment_header,
    })
}

/// 扩展头链上限（spec §4.7.3：超过 8 个 → `dropped_extension`）。
const MAX_EXTENSION_HEADERS: usize = 8;

/// 只取目的地址（v4/v6），不解析扩展头链之外的内容。
///
/// # Errors
/// 同 [`parse_ip_packet`]。
pub fn parse_ip_dst(packet: &[u8]) -> Result<IpAddr, IpParseError> {
    // 目的地址恒在固定头内：v4 16..20，v6 24..40。
    match packet.first().map(|b| b >> 4) {
        None => Err(IpParseError::Truncated),
        Some(4) => {
            if packet.len() < 20 {
                return Err(IpParseError::Truncated);
            }
            Ok(IpAddr::V4(Ipv4Addr::new(
                packet[16], packet[17], packet[18], packet[19],
            )))
        }
        Some(6) => {
            if packet.len() < 40 {
                return Err(IpParseError::Truncated);
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&packet[24..40]);
            Ok(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        Some(other) => Err(IpParseError::BadVersion(other)),
    }
}

/// 解析 UDP 报文（v4/v6）。
///
/// # Errors
/// - 非 UDP（`UnsupportedTransport`）；
/// - 头/载荷越界（`Truncated`）；
/// - 扩展头问题（同 [`parse_ip_packet`]）。
pub fn parse_udp(packet: &[u8]) -> Result<UdpView<'_>, IpParseError> {
    let view = parse_ip_packet(packet)?;
    if view.protocol != 17 {
        return Err(IpParseError::UnsupportedTransport(view.protocol));
    }
    let l4 = view.payload;
    if l4.len() < 8 {
        return Err(IpParseError::Truncated);
    }
    let src_port = u16::from_be_bytes([l4[0], l4[1]]);
    let dst_port = u16::from_be_bytes([l4[2], l4[3]]);
    let udp_len = usize::from(u16::from_be_bytes([l4[4], l4[5]]));
    if udp_len < 8 || l4.len() < udp_len {
        return Err(IpParseError::Truncated);
    }
    Ok(UdpView {
        src: SocketAddr::new(view.src, src_port),
        dst: SocketAddr::new(view.dst, dst_port),
        payload: &l4[8..udp_len],
    })
}

/// 构造 IPv4/IPv6 UDP 包（完整校验和；源/目的族必须一致）。
///
/// # Errors
/// - `src`/`dst` 族不一致 → [`IpParseError::AddressFamilyMismatch`]；
/// - 载荷超出单包上限（65507）→ [`IpParseError::Truncated`]。
pub fn build_udp_packet(
    src: SocketAddr,
    dst: SocketAddr,
    payload: &[u8],
) -> Result<Vec<u8>, IpParseError> {
    if src.is_ipv4() != dst.is_ipv4() {
        return Err(IpParseError::AddressFamilyMismatch);
    }
    let udp_len = 8usize
        .checked_add(payload.len())
        .filter(|len| *len <= 65_535)
        .ok_or(IpParseError::Truncated)?;

    match (src, dst) {
        (SocketAddr::V4(src), SocketAddr::V4(dst)) => {
            let total_len = 20 + udp_len;
            if total_len > 65_535 {
                return Err(IpParseError::Truncated);
            }
            let mut segment = vec![0u8; udp_len];
            segment[0..2].copy_from_slice(&src.port().to_be_bytes());
            segment[2..4].copy_from_slice(&dst.port().to_be_bytes());
            segment[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
            segment[8..].copy_from_slice(payload);
            let mut checksum = tcp_udp_checksum_v4(*src.ip(), *dst.ip(), 17, &segment);
            if checksum == 0 {
                // RFC 768：校验和为 0 表示"未计算"，必须改写为 0xFFFF。
                checksum = 0xFFFF;
            }
            segment[6..8].copy_from_slice(&checksum.to_be_bytes());

            let mut packet = vec![0u8; total_len];
            packet[0] = 0x45;
            packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
            packet[8] = 64; // TTL
            packet[9] = 17; // UDP
            packet[12..16].copy_from_slice(&src.ip().octets());
            packet[16..20].copy_from_slice(&dst.ip().octets());
            let header_checksum = ipv4_checksum(&packet[..20]);
            packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());
            packet[20..].copy_from_slice(&segment);
            Ok(packet)
        }
        (SocketAddr::V6(src), SocketAddr::V6(dst)) => {
            let mut segment = vec![0u8; udp_len];
            segment[0..2].copy_from_slice(&src.port().to_be_bytes());
            segment[2..4].copy_from_slice(&dst.port().to_be_bytes());
            segment[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
            segment[8..].copy_from_slice(payload);
            let mut checksum = tcp_udp_checksum_v6(*src.ip(), *dst.ip(), 17, &segment);
            if checksum == 0 {
                // RFC 2460：v6 UDP 校验和必填，计算值为 0 时发送 0xFFFF。
                checksum = 0xFFFF;
            }
            segment[6..8].copy_from_slice(&checksum.to_be_bytes());

            let mut packet = vec![0u8; 40 + udp_len];
            packet[0] = 0x60;
            packet[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
            packet[6] = 17; // UDP
            packet[7] = 64; // hop limit
            packet[8..24].copy_from_slice(&src.ip().octets());
            packet[24..40].copy_from_slice(&dst.ip().octets());
            packet[40..].copy_from_slice(&segment);
            Ok(packet)
        }
        _ => Err(IpParseError::AddressFamilyMismatch),
    }
}

/// 构造回给查询方的 TCP RST（v4/v6）。
///
/// 交换源/目的，`RST|ACK`，窗口 0；IPv4 重算头校验和，两族都重算 TCP
/// 校验和（v6 用伪头）。非 TCP 报文 → [`IpParseError::UnsupportedTransport`]。
///
/// # Errors
/// 解析失败（见 [`IpParseError`]）或非 TCP。
pub fn build_tcp_reset(query: &[u8]) -> Result<Vec<u8>, IpParseError> {
    let view = parse_ip_packet(query)?;
    if view.protocol != 6 {
        return Err(IpParseError::UnsupportedTransport(view.protocol));
    }
    let l4 = view.payload;
    if l4.len() < 20 {
        return Err(IpParseError::Truncated);
    }
    let src_port = u16::from_be_bytes([l4[0], l4[1]]);
    let dst_port = u16::from_be_bytes([l4[2], l4[3]]);
    let seq = u32::from_be_bytes([l4[4], l4[5], l4[6], l4[7]]);
    let ack = u32::from_be_bytes([l4[8], l4[9], l4[10], l4[11]]);
    let flags = l4[13];
    // ACK 置位 → 回包的 seq = 对端 ack；否则 seq = 0 且 ack = 对端 seq+1。
    let (out_seq, out_ack) = if flags & 0x10 != 0 {
        (ack, 0)
    } else {
        (0, seq.wrapping_add(1))
    };

    let mut segment = vec![0u8; 20];
    segment[0..2].copy_from_slice(&dst_port.to_be_bytes());
    segment[2..4].copy_from_slice(&src_port.to_be_bytes());
    segment[4..8].copy_from_slice(&out_seq.to_be_bytes());
    segment[8..12].copy_from_slice(&out_ack.to_be_bytes());
    segment[12] = 5 << 4; // data offset 5，无选项
    segment[13] = 0x14; // RST | ACK
    // window=0，urgent=0。

    match view.version {
        IpVersion::V4 => {
            let src = match view.dst {
                IpAddr::V4(ip) => ip,
                IpAddr::V6(_) => return Err(IpParseError::BadVersion(6)),
            };
            let dst = match view.src {
                IpAddr::V4(ip) => ip,
                IpAddr::V6(_) => return Err(IpParseError::BadVersion(4)),
            };
            let checksum = tcp_udp_checksum_v4(src, dst, 6, &segment);
            segment[16..18].copy_from_slice(&checksum.to_be_bytes());

            let total_len = 20 + segment.len();
            let mut packet = vec![0u8; total_len];
            packet[0] = 0x45;
            packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
            packet[8] = 64;
            packet[9] = 6;
            packet[12..16].copy_from_slice(&src.octets());
            packet[16..20].copy_from_slice(&dst.octets());
            let header_checksum = ipv4_checksum(&packet[..20]);
            packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());
            packet[20..].copy_from_slice(&segment);
            Ok(packet)
        }
        IpVersion::V6 => {
            let src = match view.dst {
                IpAddr::V6(ip) => ip,
                IpAddr::V4(_) => return Err(IpParseError::BadVersion(4)),
            };
            let dst = match view.src {
                IpAddr::V6(ip) => ip,
                IpAddr::V4(_) => return Err(IpParseError::BadVersion(6)),
            };
            let checksum = tcp_udp_checksum_v6(src, dst, 6, &segment);
            segment[16..18].copy_from_slice(&checksum.to_be_bytes());

            let mut packet = vec![0u8; 40 + segment.len()];
            packet[0] = 0x60;
            packet[4..6].copy_from_slice(&(segment.len() as u16).to_be_bytes());
            packet[6] = 6; // TCP
            packet[7] = 64;
            packet[8..24].copy_from_slice(&src.octets());
            packet[24..40].copy_from_slice(&dst.octets());
            packet[40..].copy_from_slice(&segment);
            Ok(packet)
        }
    }
}

/// IPv4 头校验和（RFC 1071）。
#[must_use]
pub fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = header.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let Some(&last) = chunks.remainder().first() {
        sum += u32::from(last) << 8;
    }
    fold_checksum(sum)
}

/// v4 TCP/UDP 校验和（伪头：src/dst/zero/proto/len）。
#[must_use]
pub fn tcp_udp_checksum_v4(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, segment: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + segment.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0);
    pseudo.push(proto);
    pseudo.extend_from_slice(&(segment.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(segment);
    checksum_bytes(&pseudo)
}

/// v6 TCP/UDP 校验和（伪头：src/dst/len/zero×3/next header）。
#[must_use]
pub fn tcp_udp_checksum_v6(src: Ipv6Addr, dst: Ipv6Addr, proto: u8, segment: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(40 + segment.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(&(segment.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0]);
    pseudo.push(proto);
    pseudo.extend_from_slice(segment);
    checksum_bytes(&pseudo)
}

/// 对任意字节序列求 RFC 1071 校验和。
fn checksum_bytes(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let Some(&last) = chunks.remainder().first() {
        sum += u32::from(last) << 8;
    }
    fold_checksum(sum)
}

fn fold_checksum(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v6_udp_packet(dst: Ipv6Addr, proto: u8, payload: &[u8]) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let mut pkt = vec![0u8; 40 + udp_len];
        pkt[0] = 0x60;
        pkt[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
        pkt[6] = proto;
        pkt[7] = 64;
        pkt[8..24].copy_from_slice(&Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1).octets());
        pkt[24..40].copy_from_slice(&dst.octets());
        pkt[40..42].copy_from_slice(&4321u16.to_be_bytes());
        pkt[42..44].copy_from_slice(&53u16.to_be_bytes());
        pkt[44..46].copy_from_slice(&(udp_len as u16).to_be_bytes());
        pkt[48..].copy_from_slice(payload);
        pkt
    }

    #[test]
    fn parse_v4_fixed_header() {
        let mut pkt = vec![0u8; 24];
        pkt[0] = 0x45;
        pkt[9] = 17;
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt[16..20].copy_from_slice(&[10, 1, 2, 3]);
        let view = parse_ip_packet(&pkt).unwrap();
        assert_eq!(view.version, IpVersion::V4);
        assert_eq!(view.src, "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(view.dst, "10.1.2.3".parse::<IpAddr>().unwrap());
        assert_eq!(view.protocol, 17);
        assert_eq!(view.l4_offset, 20);
        assert_eq!(view.payload.len(), 4);
        assert!(!view.has_fragment_header);
        assert_eq!(
            parse_ip_dst(&pkt).unwrap(),
            "10.1.2.3".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn parse_v6_fixed_header_and_udp() {
        let dst = "fd00:144::6".parse::<Ipv6Addr>().unwrap();
        let pkt = v6_udp_packet(dst, 17, b"hi");
        let view = parse_ip_packet(&pkt).unwrap();
        assert_eq!(view.version, IpVersion::V6);
        assert_eq!(view.dst, IpAddr::V6(dst));
        assert_eq!(view.protocol, 17);
        assert_eq!(view.l4_offset, 40);
        assert!(!view.has_fragment_header);
        let udp = parse_udp(&pkt).unwrap();
        assert_eq!(udp.dst.port(), 53);
        assert_eq!(udp.payload, b"hi");
    }

    #[test]
    fn parse_errors_are_typed() {
        assert_eq!(parse_ip_packet(&[]), Err(IpParseError::Truncated));
        assert_eq!(parse_ip_packet(&[0x60, 0, 0]), Err(IpParseError::Truncated));
        assert_eq!(
            parse_ip_packet(&[0x50; 40]),
            Err(IpParseError::BadVersion(5))
        );
        // 非 TCP/UDP：不建 flow（调用方按目的分类）。
        let icmp = v6_udp_packet("fd00:144::6".parse().unwrap(), 58, b"");
        let view = parse_ip_packet(&icmp).unwrap();
        assert_eq!(view.protocol, 58);
        assert_eq!(
            parse_udp(&icmp).unwrap_err(),
            IpParseError::UnsupportedTransport(58)
        );
    }

    #[test]
    fn parse_v6_extension_chain() {
        // 40B 固定头 + 8B Hop-by-Hop（next=43）+ 8B Routing（next=60）
        // + 8B DestOpts（next=17）→ UDP。
        let mut pkt = vec![0u8; 40 + 8 + 8 + 8 + 8];
        pkt[0] = 0x60;
        pkt[4..6].copy_from_slice(&32u16.to_be_bytes());
        pkt[6] = 0; // Hop-by-Hop
        pkt[7] = 64;
        pkt[24..40].copy_from_slice(&"fd00:144::6".parse::<Ipv6Addr>().unwrap().octets());
        pkt[40] = 43; // next = Routing
        pkt[41] = 0; // len = 8
        pkt[48] = 60; // next = DestOpts
        pkt[49] = 0;
        pkt[56] = 17; // next = UDP
        pkt[57] = 0;
        pkt[64..66].copy_from_slice(&9999u16.to_be_bytes());
        pkt[66..68].copy_from_slice(&53u16.to_be_bytes());
        pkt[68..70].copy_from_slice(&8u16.to_be_bytes());
        let view = parse_ip_packet(&pkt).unwrap();
        assert_eq!(view.protocol, 17);
        assert_eq!(view.l4_offset, 64);
        assert!(!view.has_fragment_header);
    }

    #[test]
    fn parse_v6_fragment_header() {
        let mut pkt = vec![0u8; 40 + 8 + 8];
        pkt[0] = 0x60;
        pkt[4..6].copy_from_slice(&16u16.to_be_bytes());
        pkt[6] = 44; // Fragment
        pkt[7] = 64;
        pkt[24..40].copy_from_slice(&"fd00:144::6".parse::<Ipv6Addr>().unwrap().octets());
        pkt[40] = 17; // next = UDP
        pkt[41] = 0;
        // 首片：offset=0, M=1。
        pkt[42..44].copy_from_slice(&1u16.to_be_bytes());
        let view = parse_ip_packet(&pkt).unwrap();
        assert!(view.has_fragment_header);
        assert_eq!(view.protocol, 17);
        assert_eq!(view.l4_offset, 48);

        // 非首片：offset=1（字段 0x0008）→ NonFirstFragment。
        pkt[42..44].copy_from_slice(&8u16.to_be_bytes());
        assert_eq!(parse_ip_packet(&pkt), Err(IpParseError::NonFirstFragment));
    }

    #[test]
    fn parse_v6_too_many_extension_headers() {
        // 9 个 Hop-by-Hop 头（每个 8B）→ TooManyExtensionHeaders。
        let mut pkt = vec![0u8; 40 + 9 * 8];
        pkt[0] = 0x60;
        pkt[4..6].copy_from_slice(&(9 * 8u16).to_be_bytes());
        pkt[6] = 0;
        pkt[7] = 64;
        for i in 0..9 {
            let off = 40 + i * 8;
            pkt[off] = if i == 8 { 17 } else { 0 };
            pkt[off + 1] = 0;
        }
        assert_eq!(
            parse_ip_packet(&pkt),
            Err(IpParseError::TooManyExtensionHeaders)
        );
    }

    #[test]
    fn parse_v6_esp_ah_unsupported() {
        for hdr in [50u8, 51u8] {
            let mut pkt = vec![0u8; 48];
            pkt[0] = 0x60;
            pkt[4..6].copy_from_slice(&8u16.to_be_bytes());
            pkt[6] = hdr;
            pkt[7] = 64;
            assert_eq!(
                parse_ip_packet(&pkt),
                Err(IpParseError::UnsupportedExtension(hdr))
            );
        }
    }

    #[test]
    fn build_udp_v4_checksum_is_valid() {
        let src = "10.0.0.1:53".parse::<SocketAddr>().unwrap();
        let dst = "10.0.0.2:4321".parse::<SocketAddr>().unwrap();
        let pkt = build_udp_packet(src, dst, b"answer").unwrap();
        assert_eq!(pkt[0], 0x45);
        // IP 头校验和自校验 == 0。
        assert_eq!(ipv4_checksum(&pkt[..20]), 0);
        let (IpAddr::V4(s), IpAddr::V4(d)) = (src.ip(), dst.ip()) else {
            unreachable!()
        };
        let segment = &pkt[20..];
        let mut zeroed = segment.to_vec();
        zeroed[6..8].copy_from_slice(&[0, 0]);
        let expected = tcp_udp_checksum_v4(s, d, 17, &zeroed);
        assert_ne!(expected, 0);
        assert_eq!(&segment[6..8], &expected.to_be_bytes());
        // 对含校验和的 segment 求值 == 0（自校验）。
        assert_eq!(tcp_udp_checksum_v4(s, d, 17, segment), 0);
    }

    #[test]
    fn build_udp_v6_checksum_is_valid() {
        let src = "[fd00::1]:53".parse::<SocketAddr>().unwrap();
        let dst = "[2001:db8::20]:4321".parse::<SocketAddr>().unwrap();
        let pkt = build_udp_packet(src, dst, b"answer").unwrap();
        assert_eq!(pkt[0], 0x60);
        assert_eq!(pkt[6], 17);
        let (IpAddr::V6(s), IpAddr::V6(d)) = (src.ip(), dst.ip()) else {
            unreachable!()
        };
        // 自校验：把 UDP 校验和字段清零后重新计算 == 报文中的值，
        // 且对整个 segment（含校验和）求值 == 0。
        let segment = &pkt[40..];
        let mut zeroed = segment.to_vec();
        zeroed[6..8].copy_from_slice(&[0, 0]);
        let expected = tcp_udp_checksum_v6(s, d, 17, &zeroed);
        assert_eq!(&segment[6..8], &expected.to_be_bytes());
        assert_eq!(tcp_udp_checksum_v6(s, d, 17, segment), 0);
    }

    #[test]
    fn build_udp_family_mismatch() {
        let src = "10.0.0.1:53".parse::<SocketAddr>().unwrap();
        let dst = "[fd00::1]:4321".parse::<SocketAddr>().unwrap();
        assert_eq!(
            build_udp_packet(src, dst, b"x"),
            Err(IpParseError::AddressFamilyMismatch)
        );
    }

    fn tcp_syn_v4() -> Vec<u8> {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&40u16.to_be_bytes());
        pkt[8] = 64;
        pkt[9] = 6;
        pkt[12..16].copy_from_slice(&[10, 0, 0, 2]);
        pkt[16..20].copy_from_slice(&[10, 1, 2, 3]);
        pkt[20..22].copy_from_slice(&40000u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&443u16.to_be_bytes());
        pkt[24..28].copy_from_slice(&1000u32.to_be_bytes());
        pkt[32] = 5 << 4;
        pkt[33] = 0x02; // SYN
        pkt
    }

    fn tcp_syn_v6() -> Vec<u8> {
        let mut pkt = vec![0u8; 60];
        pkt[0] = 0x60;
        pkt[4..6].copy_from_slice(&20u16.to_be_bytes());
        pkt[6] = 6;
        pkt[7] = 64;
        pkt[8..24].copy_from_slice(&"fd00:144::6".parse::<Ipv6Addr>().unwrap().octets());
        pkt[24..40].copy_from_slice(&"2001:db8::20".parse::<Ipv6Addr>().unwrap().octets());
        pkt[40..42].copy_from_slice(&40000u16.to_be_bytes());
        pkt[42..44].copy_from_slice(&443u16.to_be_bytes());
        pkt[44..48].copy_from_slice(&1000u32.to_be_bytes());
        pkt[52] = 5 << 4;
        pkt[53] = 0x02; // SYN
        pkt
    }

    #[test]
    fn build_tcp_reset_v4() {
        let query = tcp_syn_v4();
        let rst = build_tcp_reset(&query).unwrap();
        assert_eq!(rst[0], 0x45);
        assert_eq!(rst[9], 6);
        // 源/目的交换。
        assert_eq!(&rst[12..16], &[10, 1, 2, 3]);
        assert_eq!(&rst[16..20], &[10, 0, 0, 2]);
        // 端口交换 + RST|ACK。
        assert_eq!(u16::from_be_bytes([rst[20], rst[21]]), 443);
        assert_eq!(u16::from_be_bytes([rst[22], rst[23]]), 40000);
        assert_eq!(rst[33], 0x14);
        // ACK = 对端 seq + 1。
        assert_eq!(
            u32::from_be_bytes([rst[28], rst[29], rst[30], rst[31]]),
            1001
        );
        assert_eq!(ipv4_checksum(&rst[..20]), 0);
        let mut zeroed = rst[20..].to_vec();
        zeroed[16..18].copy_from_slice(&[0, 0]);
        let expected = tcp_udp_checksum_v4(
            Ipv4Addr::new(10, 1, 2, 3),
            Ipv4Addr::new(10, 0, 0, 2),
            6,
            &zeroed,
        );
        assert_eq!(&rst[36..38], &expected.to_be_bytes());
        assert_eq!(
            tcp_udp_checksum_v4(
                Ipv4Addr::new(10, 1, 2, 3),
                Ipv4Addr::new(10, 0, 0, 2),
                6,
                &rst[20..]
            ),
            0
        );
    }

    #[test]
    fn build_tcp_reset_v6() {
        let query = tcp_syn_v6();
        let rst = build_tcp_reset(&query).unwrap();
        assert_eq!(rst[0], 0x60);
        assert_eq!(rst[6], 6);
        let src = "2001:db8::20".parse::<Ipv6Addr>().unwrap();
        let dst = "fd00:144::6".parse::<Ipv6Addr>().unwrap();
        assert_eq!(&rst[8..24], &src.octets());
        assert_eq!(&rst[24..40], &dst.octets());
        assert_eq!(u16::from_be_bytes([rst[40], rst[41]]), 443);
        assert_eq!(rst[53], 0x14);
        assert_eq!(
            tcp_udp_checksum_v6(src, dst, 6, &rst[40..]),
            0,
            "v6 RST checksum must self-verify as 0"
        );
    }

    #[test]
    fn build_tcp_reset_rejects_non_tcp() {
        let pkt = v6_udp_packet("fd00:144::6".parse().unwrap(), 17, b"");
        assert_eq!(
            build_tcp_reset(&pkt),
            Err(IpParseError::UnsupportedTransport(17))
        );
    }
}
