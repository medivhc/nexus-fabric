//! sockaddr / ancillary cmsg 的安全解析（spec §9.3 / §12.2 AC-G8-02）。
//!
//! 这些函数只处理字节切片，不接触裸指针；真正的 `recvmsg` / `sendto`
//! 在 `tcp.rs` / `udp.rs` 的 unsafe 块中，并逐条写明 Safety Invariant。

use std::net::{Ipv4Addr, SocketAddrV4};

use nexus_platform::TransparentIngressError;

/// `cmsghdr` 头长度（Linux 64-bit：`cmsg_len` usize + level + type）。
fn cmsg_header_len() -> usize {
    std::mem::size_of::<usize>() + 2 * std::mem::size_of::<libc::c_int>()
}

/// `CMSG_ALIGN` 等价对齐。
fn cmsg_align(len: usize) -> usize {
    let align = std::mem::size_of::<usize>();
    (len + align - 1) & !(align - 1)
}

/// 一条 ancillary 消息（已拷贝出数据，脱离原始控制缓冲区）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AncillaryMessage {
    /// cmsg level（如 `IPPROTO_IP`）。
    pub level: i32,
    /// cmsg type（如 `IP_ORIGDSTADDR`）。
    pub ty: i32,
    /// 数据区。
    pub data: Vec<u8>,
}

/// 解析 `recvmsg` 控制缓冲区。
///
/// # Errors
///
/// 长度/对齐异常 → `AncillaryParseFailed`；空缓冲区返回空列表。
pub fn parse_cmsgs(buf: &[u8]) -> Result<Vec<AncillaryMessage>, TransparentIngressError> {
    let header = cmsg_header_len();
    if !buf.is_empty() && buf.len() < header {
        return Err(TransparentIngressError::AncillaryParseFailed {
            detail: format!("control buffer {} shorter than cmsg header", buf.len()),
        });
    }
    let mut out = Vec::new();
    let mut offset = 0usize;
    while offset + header <= buf.len() {
        let raw_len = &buf[offset..offset + std::mem::size_of::<usize>()];
        let mut len_bytes = [0u8; std::mem::size_of::<usize>()];
        len_bytes.copy_from_slice(raw_len);
        let cmsg_len = usize::from_ne_bytes(len_bytes);
        if cmsg_len < header {
            return Err(TransparentIngressError::AncillaryParseFailed {
                detail: format!("cmsg_len {cmsg_len} smaller than header {header}"),
            });
        }
        if offset + cmsg_len > buf.len() {
            return Err(TransparentIngressError::AncillaryParseFailed {
                detail: format!(
                    "cmsg_len {cmsg_len} exceeds control buffer {}",
                    buf.len() - offset
                ),
            });
        }
        let level = read_i32(&buf[offset + std::mem::size_of::<usize>()..])?;
        let ty = read_i32(&buf[offset + std::mem::size_of::<usize>() + 4..])?;
        let data = buf[offset + header..offset + cmsg_len].to_vec();
        out.push(AncillaryMessage { level, ty, data });
        let advance = cmsg_align(cmsg_len);
        if advance == 0 {
            break;
        }
        offset += advance;
    }
    Ok(out)
}

fn read_i32(bytes: &[u8]) -> Result<i32, TransparentIngressError> {
    if bytes.len() < 4 {
        return Err(TransparentIngressError::AncillaryParseFailed {
            detail: "truncated cmsg header".to_string(),
        });
    }
    let mut raw = [0u8; 4];
    raw.copy_from_slice(&bytes[..4]);
    Ok(i32::from_ne_bytes(raw))
}

/// 从 ancillary 消息中取 `IP_ORIGDSTADDR`（缺失返回 `None`）。
///
/// # Errors
///
/// cmsg 数据不足 16 字节或地址族非法。
pub fn find_orig_dst(
    messages: &[AncillaryMessage],
) -> Result<Option<SocketAddrV4>, TransparentIngressError> {
    for msg in messages {
        if msg.level == libc::IPPROTO_IP && msg.ty == super::IP_ORIGDSTADDR {
            return sockaddr_in_to_v4(&msg.data).map(Some);
        }
    }
    Ok(None)
}

/// 把 `sockaddr_in` 字节解析为 IPv4 地址。
///
/// # Errors
///
/// 长度不足 → `AncillaryParseFailed`；族非 `AF_INET` → `UnsupportedFamily`；
/// 端口 0 → `OrigDstInvalid`。
pub fn sockaddr_in_to_v4(bytes: &[u8]) -> Result<SocketAddrV4, TransparentIngressError> {
    if bytes.len() < 8 {
        return Err(TransparentIngressError::AncillaryParseFailed {
            detail: format!("sockaddr_in truncated: {} bytes", bytes.len()),
        });
    }
    let family = u16::from_ne_bytes([bytes[0], bytes[1]]);
    if family != libc::AF_INET as u16 {
        return Err(TransparentIngressError::UnsupportedFamily { family });
    }
    let port = u16::from_be_bytes([bytes[2], bytes[3]]);
    if port == 0 {
        return Err(TransparentIngressError::OrigDstInvalid {
            raw: format!("port=0 family={family}"),
        });
    }
    let ip = Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);
    Ok(SocketAddrV4::new(ip, port))
}

/// 构造 `sockaddr_in` 供 `bind` / `sendto` 使用。
pub(crate) fn to_sockaddr_in(addr: SocketAddrV4) -> libc::sockaddr_in {
    // SAFETY: sockaddr_in is plain-old-data; zeroing is a valid initial value.
    let mut out: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    out.sin_family = libc::AF_INET as libc::sa_family_t;
    out.sin_port = addr.port().to_be();
    out.sin_addr.s_addr = u32::from_ne_bytes(addr.ip().octets());
    out
}

/// 从 `sockaddr_in` 指针读取地址（调用方保证指针有效且已填充）。
///
/// # Safety
///
/// `addr` 必须指向一个已初始化、长度至少 `size_of::<sockaddr_in>()` 的
/// `sockaddr_in`。
pub(crate) unsafe fn from_sockaddr_in(addr: *const libc::sockaddr_in) -> SocketAddrV4 {
    // SAFETY: caller guarantees `addr` points to a valid, initialized
    // sockaddr_in that outlives this borrow.
    let value = unsafe { &*addr };
    let octets = value.sin_addr.s_addr.to_ne_bytes();
    SocketAddrV4::new(Ipv4Addr::from(octets), u16::from_be(value.sin_port))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sockaddr_bytes(ip: [u8; 4], port: u16) -> Vec<u8> {
        let mut bytes = vec![0u8; 16];
        bytes[0..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
        bytes[2..4].copy_from_slice(&port.to_be_bytes());
        bytes[4..8].copy_from_slice(&ip);
        bytes
    }

    #[test]
    fn tproxy_sockaddr_parses_family_port_and_ip() {
        let addr = sockaddr_in_to_v4(&sockaddr_bytes([10, 200, 2, 2], 8080)).unwrap();
        assert_eq!(addr, SocketAddrV4::new(Ipv4Addr::new(10, 200, 2, 2), 8080));
    }

    #[test]
    fn tproxy_sockaddr_rejects_short_and_wrong_family() {
        let err = sockaddr_in_to_v4(&[0u8; 4]).unwrap_err();
        assert!(matches!(
            err,
            TransparentIngressError::AncillaryParseFailed { .. }
        ));
        let mut bytes = sockaddr_bytes([1, 2, 3, 4], 80);
        bytes[0..2].copy_from_slice(&(libc::AF_INET6 as u16).to_ne_bytes());
        let err = sockaddr_in_to_v4(&bytes).unwrap_err();
        assert!(matches!(
            err,
            TransparentIngressError::UnsupportedFamily { .. }
        ));
    }

    #[test]
    fn tproxy_sockaddr_rejects_zero_port() {
        let err = sockaddr_in_to_v4(&sockaddr_bytes([1, 2, 3, 4], 0)).unwrap_err();
        assert!(matches!(
            err,
            TransparentIngressError::OrigDstInvalid { .. }
        ));
    }

    fn cmsg(level: i32, ty: i32, data: &[u8]) -> Vec<u8> {
        let header = cmsg_header_len();
        let len = header + data.len();
        let padded = cmsg_align(len);
        let mut out = vec![0u8; padded];
        out[0..std::mem::size_of::<usize>()].copy_from_slice(&len.to_ne_bytes());
        out[std::mem::size_of::<usize>()..std::mem::size_of::<usize>() + 4]
            .copy_from_slice(&level.to_ne_bytes());
        out[std::mem::size_of::<usize>() + 4..header].copy_from_slice(&ty.to_ne_bytes());
        out[header..len].copy_from_slice(data);
        out
    }

    #[test]
    fn tproxy_cmsg_empty_buffer_and_missing_orig_dst() {
        assert!(parse_cmsgs(&[]).unwrap().is_empty());
        assert_eq!(find_orig_dst(&[]).unwrap(), None);
    }

    #[test]
    fn tproxy_cmsg_parses_single_orig_dst() {
        let bytes = cmsg(
            libc::IPPROTO_IP,
            super::super::IP_ORIGDSTADDR,
            &sockaddr_bytes([10, 200, 2, 2], 53),
        );
        let messages = parse_cmsgs(&bytes).unwrap();
        assert_eq!(messages.len(), 1);
        let dst = find_orig_dst(&messages).unwrap().unwrap();
        assert_eq!(dst, SocketAddrV4::new(Ipv4Addr::new(10, 200, 2, 2), 53));
    }

    #[test]
    fn tproxy_cmsg_parses_multiple_and_ignores_unknown() {
        let mut bytes = cmsg(libc::IPPROTO_IP, 9999, &[1, 2, 3, 4]);
        bytes.extend(cmsg(
            libc::IPPROTO_IP,
            super::super::IP_ORIGDSTADDR,
            &sockaddr_bytes([192, 0, 2, 1], 9000),
        ));
        let messages = parse_cmsgs(&bytes).unwrap();
        assert_eq!(messages.len(), 2);
        let dst = find_orig_dst(&messages).unwrap().unwrap();
        assert_eq!(dst.port(), 9000);
    }

    #[test]
    fn tproxy_cmsg_rejects_short_and_bad_length() {
        let bytes = cmsg(
            libc::IPPROTO_IP,
            super::super::IP_ORIGDSTADDR,
            &sockaddr_bytes([1, 2, 3, 4], 80),
        );
        let err = parse_cmsgs(&bytes[..6]).unwrap_err();
        assert!(matches!(
            err,
            TransparentIngressError::AncillaryParseFailed { .. }
        ));
        let mut bad = bytes;
        bad[0..std::mem::size_of::<usize>()].copy_from_slice(&1usize.to_ne_bytes());
        let err = parse_cmsgs(&bad).unwrap_err();
        assert!(matches!(
            err,
            TransparentIngressError::AncillaryParseFailed { .. }
        ));
    }
}
