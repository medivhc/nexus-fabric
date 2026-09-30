//! STUN 消息编解码（RFC 5389 头 + RFC 5766 属性/消息类型）。
//!
//! 只实现 4b 最小子集所需的消息与属性。ChannelData（§11）走独立的
//! 4 字节头，不经过 STUN 解析。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};

/// STUN magic cookie (RFC 5389 §6).
pub const MAGIC_COOKIE: u32 = 0x2112_A442;
/// STUN 头长度。
pub const HEADER_LEN: usize = 20;

// ---- 消息方法（12 bit） ----
pub const METHOD_ALLOCATE: u16 = 0x003;
pub const METHOD_REFRESH: u16 = 0x004;
pub const METHOD_CREATE_PERMISSION: u16 = 0x008;
pub const METHOD_CHANNEL_BIND: u16 = 0x009;
pub const METHOD_SEND: u16 = 0x006;
pub const METHOD_DATA: u16 = 0x007;

// ---- 类（2 bit） ----
pub const CLASS_REQUEST: u8 = 0b00;
pub const CLASS_INDICATION: u8 = 0b01;
pub const CLASS_SUCCESS: u8 = 0b10;
pub const CLASS_FAILURE: u8 = 0b11;

// ---- 常用消息类型 ----
pub const ALLOCATE_REQUEST: u16 = msg_type(METHOD_ALLOCATE, CLASS_REQUEST);
pub const ALLOCATE_SUCCESS: u16 = msg_type(METHOD_ALLOCATE, CLASS_SUCCESS);
pub const ALLOCATE_FAILURE: u16 = msg_type(METHOD_ALLOCATE, CLASS_FAILURE);
pub const REFRESH_REQUEST: u16 = msg_type(METHOD_REFRESH, CLASS_REQUEST);
pub const REFRESH_SUCCESS: u16 = msg_type(METHOD_REFRESH, CLASS_SUCCESS);
pub const REFRESH_FAILURE: u16 = msg_type(METHOD_REFRESH, CLASS_FAILURE);
pub const CREATE_PERMISSION_REQUEST: u16 = msg_type(METHOD_CREATE_PERMISSION, CLASS_REQUEST);
pub const CREATE_PERMISSION_SUCCESS: u16 = msg_type(METHOD_CREATE_PERMISSION, CLASS_SUCCESS);
pub const CREATE_PERMISSION_FAILURE: u16 = msg_type(METHOD_CREATE_PERMISSION, CLASS_FAILURE);
pub const CHANNEL_BIND_REQUEST: u16 = msg_type(METHOD_CHANNEL_BIND, CLASS_REQUEST);
pub const CHANNEL_BIND_SUCCESS: u16 = msg_type(METHOD_CHANNEL_BIND, CLASS_SUCCESS);
pub const CHANNEL_BIND_FAILURE: u16 = msg_type(METHOD_CHANNEL_BIND, CLASS_FAILURE);
pub const SEND_INDICATION: u16 = msg_type(METHOD_SEND, CLASS_INDICATION);
pub const DATA_INDICATION: u16 = msg_type(METHOD_DATA, CLASS_INDICATION);

// ---- 属性类型 ----
pub const ATTR_USERNAME: u16 = 0x0006;
pub const ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;
pub const ATTR_ERROR_CODE: u16 = 0x0009;
pub const ATTR_XOR_PEER_ADDRESS: u16 = 0x0012;
pub const ATTR_DATA: u16 = 0x0013;
pub const ATTR_REALM: u16 = 0x0014;
pub const ATTR_NONCE: u16 = 0x0015;
pub const ATTR_XOR_RELAYED_ADDRESS: u16 = 0x0016;
pub const ATTR_REQUESTED_TRANSPORT: u16 = 0x0019;
pub const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
pub const ATTR_CHANNEL_NUMBER: u16 = 0x000C;
pub const ATTR_LIFETIME: u16 = 0x000D;

/// 由 12-bit 方法 + 2-bit 类合成 16-bit 消息类型（RFC 5389 §6）。
pub const fn msg_type(method: u16, class: u8) -> u16 {
    let m = method & 0x0fff;
    let c = (class & 0x03) as u16;
    ((m & 0x0f80) << 2) | ((m & 0x0070) << 1) | (m & 0x000f) | ((c & 0x02) << 7) | ((c & 0x01) << 4)
}

/// 从消息类型解出（方法，类）。
pub fn split_type(t: u16) -> (u16, u8) {
    // 方法位：u16 bit13..9（M11..M7）、bit7..5（M6..M4）、bit3..0（M3..M0）；
    // 注意 bit8（C1）与 bit4（C0）是类位，必须排除。
    let m = ((t & 0x3e00) >> 2) | ((t & 0x00e0) >> 1) | (t & 0x000f);
    let c = (((t & 0x0100) >> 7) | ((t & 0x0010) >> 4)) as u8;
    (m, c)
}

/// Channel number 有效范围（RFC 5766 §11）：0x4000–0x7FFF，
/// 与 STUN 消息类型空间（首两 bit 为 0）不冲突。
pub fn valid_channel(n: u16) -> bool {
    (0x4000..=0x7FFF).contains(&n)
}

/// 判断数据报是否为 ChannelData（首两字节 0x4000–0x7FFF）。
pub fn is_channel_data(buf: &[u8]) -> bool {
    buf.len() >= 4 && (u16::from_be_bytes([buf[0], buf[1]]) & 0xC000) == 0x4000
}

/// 判断数据报是否为 STUN 消息（首两 bit 为 0 且长度 ≥ 20）。
pub fn is_stun_message(buf: &[u8]) -> bool {
    buf.len() >= HEADER_LEN && (buf[0] & 0xC0) == 0x00
}

/// 解析 ChannelData：返回（channel number，载荷）。
pub fn parse_channel_data(buf: &[u8]) -> Option<(u16, &[u8])> {
    if !is_channel_data(buf) {
        return None;
    }
    let channel = u16::from_be_bytes([buf[0], buf[1]]);
    let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    if buf.len() < 4 + len {
        return None;
    }
    Some((channel, &buf[4..4 + len]))
}

/// 编码 ChannelData（4 字节头 + 载荷，无 padding）。
pub fn encode_channel_data(channel: u16, payload: &[u8], out: &mut Vec<u8>) {
    debug_assert!(valid_channel(channel));
    out.extend_from_slice(&channel.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
}

/// 生成 transaction ID（进程内计数器 + 时间混合；E4 自测足够唯一）。
pub fn new_transaction_id() -> [u8; 12] {
    static CTR: AtomicU64 = AtomicU64::new(0);
    let c = CTR.fetch_add(1, Ordering::Relaxed);
    // xorshift64* 混合计数器与纳秒时间
    let mut x = c.wrapping_add(0x9E37_79B9_7F4A_7C15)
        ^ std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x1234_5678);
    let mut out = [0u8; 12];
    for chunk in out.chunks_mut(4) {
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        let v = x.wrapping_mul(0x2545_F491_4F6C_DD1D);
        chunk.copy_from_slice(&((v >> 32) as u32).to_be_bytes());
    }
    out[..4].copy_from_slice(&(c as u32).to_be_bytes());
    out
}

/// STUN 属性（仅最小子集）。
#[derive(Debug, Clone, PartialEq)]
pub enum Attribute {
    Username(Vec<u8>),
    /// 编码时填 20 字节零，由 [`encode_with_integrity`] 计算后回填。
    MessageIntegrity([u8; 20]),
    Realm(Vec<u8>),
    Nonce(Vec<u8>),
    XorMappedAddress(SocketAddr),
    XorRelayedAddress(SocketAddr),
    XorPeerAddress(SocketAddr),
    Lifetime(u32),
    /// 协议号（17 = UDP）。
    RequestedTransport(u8),
    ChannelNumber(u16),
    Data(Vec<u8>),
    ErrorCode(u8, u8, Vec<u8>),
    /// 未知属性：解码保留，编码原样写回。
    Unknown(u16, Vec<u8>),
}

impl Attribute {
    pub(crate) fn attr_type(&self) -> u16 {
        match self {
            Attribute::Username(_) => ATTR_USERNAME,
            Attribute::MessageIntegrity(_) => ATTR_MESSAGE_INTEGRITY,
            Attribute::Realm(_) => ATTR_REALM,
            Attribute::Nonce(_) => ATTR_NONCE,
            Attribute::XorMappedAddress(_) => ATTR_XOR_MAPPED_ADDRESS,
            Attribute::XorRelayedAddress(_) => ATTR_XOR_RELAYED_ADDRESS,
            Attribute::XorPeerAddress(_) => ATTR_XOR_PEER_ADDRESS,
            Attribute::Lifetime(_) => ATTR_LIFETIME,
            Attribute::RequestedTransport(_) => ATTR_REQUESTED_TRANSPORT,
            Attribute::ChannelNumber(_) => ATTR_CHANNEL_NUMBER,
            Attribute::Data(_) => ATTR_DATA,
            Attribute::ErrorCode(_, _, _) => ATTR_ERROR_CODE,
            Attribute::Unknown(t, _) => *t,
        }
    }

    fn encode_value(&self, txn: &[u8; 12], out: &mut Vec<u8>) {
        match self {
            Attribute::Username(v)
            | Attribute::Realm(v)
            | Attribute::Nonce(v)
            | Attribute::Data(v)
            | Attribute::ErrorCode(_, _, v) => {
                if let Attribute::ErrorCode(class, number, _) = self {
                    out.extend_from_slice(&[0, 0, *class, *number]);
                }
                out.extend_from_slice(v);
            }
            Attribute::MessageIntegrity(tag) => out.extend_from_slice(tag),
            Attribute::XorMappedAddress(a) => encode_xor_addr(a, txn, out),
            Attribute::XorRelayedAddress(a) => encode_xor_addr(a, txn, out),
            Attribute::XorPeerAddress(a) => encode_xor_addr(a, txn, out),
            Attribute::Lifetime(secs) => out.extend_from_slice(&secs.to_be_bytes()),
            Attribute::RequestedTransport(proto) => out.extend_from_slice(&[*proto, 0, 0, 0]),
            Attribute::ChannelNumber(n) => {
                out.extend_from_slice(&n.to_be_bytes());
                out.extend_from_slice(&[0, 0]);
            }
            Attribute::Unknown(_, v) => out.extend_from_slice(v),
        }
    }
}

/// XOR 编码地址属性值（RFC 5389 §15.2 / RFC 5766 §14.5）。
fn encode_xor_addr(addr: &SocketAddr, txn: &[u8; 12], out: &mut Vec<u8>) {
    out.push(0x00);
    match addr.ip() {
        IpAddr::V4(v4) => {
            out.push(0x01);
            out.extend_from_slice(&((addr.port() ^ (MAGIC_COOKIE >> 16) as u16).to_be_bytes()));
            let xored = u32::from_be_bytes(v4.octets()) ^ MAGIC_COOKIE;
            out.extend_from_slice(&xored.to_be_bytes());
        }
        IpAddr::V6(v6) => {
            out.push(0x02);
            out.extend_from_slice(&((addr.port() ^ (MAGIC_COOKIE >> 16) as u16).to_be_bytes()));
            let mut mask = [0u8; 16];
            mask[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
            mask[4..].copy_from_slice(txn);
            for (i, b) in v6.octets().iter().enumerate() {
                out.push(b ^ mask[i]);
            }
        }
    }
}

/// XOR 解码地址属性值。
fn decode_xor_addr(value: &[u8], txn: &[u8; 12]) -> Option<SocketAddr> {
    if value.len() < 4 || value[0] != 0x00 {
        return None;
    }
    let port = u16::from_be_bytes([value[2], value[3]]) ^ (MAGIC_COOKIE >> 16) as u16;
    match value[1] {
        0x01 if value.len() >= 8 => {
            let raw = u32::from_be_bytes([value[4], value[5], value[6], value[7]]) ^ MAGIC_COOKIE;
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(raw)), port))
        }
        0x02 if value.len() >= 20 => {
            let mut mask = [0u8; 16];
            mask[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
            mask[4..].copy_from_slice(txn);
            let mut octets = [0u8; 16];
            for (i, o) in octets.iter_mut().enumerate() {
                *o = value[4 + i] ^ mask[i];
            }
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        _ => None,
    }
}

/// STUN 消息（builder 风格）。
#[derive(Debug, Clone)]
pub struct StunMessage {
    pub msg_type: u16,
    pub txn: [u8; 12],
    pub attrs: Vec<Attribute>,
}

impl StunMessage {
    pub fn new(msg_type: u16) -> Self {
        Self {
            msg_type,
            txn: new_transaction_id(),
            attrs: Vec::new(),
        }
    }

    pub fn attr(mut self, a: Attribute) -> Self {
        self.attrs.push(a);
        self
    }

    pub fn get(&self, t: u16) -> Option<&Attribute> {
        self.attrs.iter().find(|a| a.attr_type() == t)
    }

    /// 编码（不带 MESSAGE-INTEGRITY 计算；MI 属性按原样写入）。
    pub fn encode(&self) -> Vec<u8> {
        let mut body = Vec::new();
        for a in &self.attrs {
            let mut value = Vec::new();
            a.encode_value(&self.txn, &mut value);
            body.extend_from_slice(&a.attr_type().to_be_bytes());
            body.extend_from_slice(&(value.len() as u16).to_be_bytes());
            body.extend_from_slice(&value);
            // 4 字节对齐 padding
            let pad = (4 - value.len() % 4) % 4;
            body.extend(std::iter::repeat_n(0u8, pad));
        }
        let mut out = Vec::with_capacity(HEADER_LEN + body.len());
        out.extend_from_slice(&self.msg_type.to_be_bytes());
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        out.extend_from_slice(&self.txn);
        out.extend_from_slice(&body);
        out
    }
}

/// 解码后的消息（含 MI 值在原始字节中的偏移，供 server 验证用）。
#[derive(Debug)]
pub struct DecodedMessage {
    pub msg_type: u16,
    pub txn: [u8; 12],
    pub attrs: Vec<Attribute>,
    /// MESSAGE-INTEGRITY 属性值在原始数据报中的字节偏移（无则为 None）。
    pub mi_value_offset: Option<usize>,
    /// 本次解码消费的字节数（头声明长度）。
    pub consumed: usize,
}

impl DecodedMessage {
    pub fn get(&self, t: u16) -> Option<&Attribute> {
        self.attrs.iter().find(|a| a.attr_type() == t)
    }
}

#[derive(Debug)]
pub enum DecodeError {
    TooShort,
    BadMagic,
    Truncated,
}

/// 解码一个 STUN 消息（`buf` 需以 STUN 头开头）。
pub fn decode(buf: &[u8]) -> Result<DecodedMessage, DecodeError> {
    if buf.len() < HEADER_LEN {
        return Err(DecodeError::TooShort);
    }
    if (buf[0] & 0xC0) != 0x00 {
        return Err(DecodeError::TooShort);
    }
    let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
    let msg_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    if u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]) != MAGIC_COOKIE {
        return Err(DecodeError::BadMagic);
    }
    if buf.len() < HEADER_LEN + msg_len {
        return Err(DecodeError::Truncated);
    }
    let mut txn = [0u8; 12];
    txn.copy_from_slice(&buf[8..20]);

    let mut attrs = Vec::new();
    let mut mi_value_offset = None;
    let mut off = HEADER_LEN;
    let end = HEADER_LEN + msg_len;
    while off + 4 <= end {
        let at = u16::from_be_bytes([buf[off], buf[off + 1]]);
        let len = u16::from_be_bytes([buf[off + 2], buf[off + 3]]) as usize;
        let vstart = off + 4;
        let vend = vstart + len;
        if vend > end {
            return Err(DecodeError::Truncated);
        }
        let value = &buf[vstart..vend];
        let attr = match at {
            ATTR_USERNAME => Attribute::Username(value.to_vec()),
            ATTR_REALM => Attribute::Realm(value.to_vec()),
            ATTR_NONCE => Attribute::Nonce(value.to_vec()),
            ATTR_DATA => Attribute::Data(value.to_vec()),
            ATTR_MESSAGE_INTEGRITY if len == 20 => {
                let mut tag = [0u8; 20];
                tag.copy_from_slice(value);
                mi_value_offset = Some(vstart);
                Attribute::MessageIntegrity(tag)
            }
            ATTR_XOR_MAPPED_ADDRESS => match decode_xor_addr(value, &txn) {
                Some(a) => Attribute::XorMappedAddress(a),
                None => Attribute::Unknown(at, value.to_vec()),
            },
            ATTR_XOR_RELAYED_ADDRESS => match decode_xor_addr(value, &txn) {
                Some(a) => Attribute::XorRelayedAddress(a),
                None => Attribute::Unknown(at, value.to_vec()),
            },
            ATTR_XOR_PEER_ADDRESS => match decode_xor_addr(value, &txn) {
                Some(a) => Attribute::XorPeerAddress(a),
                None => Attribute::Unknown(at, value.to_vec()),
            },
            ATTR_LIFETIME if len == 4 => {
                Attribute::Lifetime(u32::from_be_bytes([value[0], value[1], value[2], value[3]]))
            }
            ATTR_REQUESTED_TRANSPORT if len == 4 => Attribute::RequestedTransport(value[0]),
            ATTR_CHANNEL_NUMBER if len == 4 => {
                Attribute::ChannelNumber(u16::from_be_bytes([value[0], value[1]]))
            }
            ATTR_ERROR_CODE if len >= 4 => {
                Attribute::ErrorCode(value[2], value[3], value[4..].to_vec())
            }
            _ => Attribute::Unknown(at, value.to_vec()),
        };
        attrs.push(attr);
        off = vend + (4 - len % 4) % 4;
    }

    Ok(DecodedMessage {
        msg_type,
        txn,
        attrs,
        mi_value_offset,
        consumed: end,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msg_type_encode_decode_vectors() {
        // RFC 5766 已知类型值
        assert_eq!(ALLOCATE_REQUEST, 0x0003);
        assert_eq!(ALLOCATE_SUCCESS, 0x0103);
        assert_eq!(REFRESH_REQUEST, 0x0004);
        assert_eq!(CREATE_PERMISSION_REQUEST, 0x0008);
        assert_eq!(CHANNEL_BIND_REQUEST, 0x0009);
        assert_eq!(SEND_INDICATION, 0x0016);
        assert_eq!(DATA_INDICATION, 0x0017);
        // split_type 往返
        for (m, c) in [(0x003u16, 0u8), (0x004, 2), (0x009, 3), (0x007, 1)] {
            assert_eq!(split_type(msg_type(m, c)), (m, c));
        }
    }

    #[test]
    fn encode_decode_allocate_request() {
        let msg = StunMessage::new(ALLOCATE_REQUEST)
            .attr(Attribute::RequestedTransport(17))
            .attr(Attribute::Username(b"nexus".to_vec()))
            .attr(Attribute::Realm(b"nexus".to_vec()))
            .attr(Attribute::Nonce(b"nonce123".to_vec()))
            .attr(Attribute::MessageIntegrity([0u8; 20]));
        let bytes = msg.encode();
        assert!(is_stun_message(&bytes));
        assert!(!is_channel_data(&bytes));
        let d = decode(&bytes).unwrap();
        assert_eq!(d.msg_type, ALLOCATE_REQUEST);
        assert_eq!(d.txn, msg.txn);
        assert_eq!(d.attrs.len(), 5);
        assert!(matches!(
            d.get(ATTR_REQUESTED_TRANSPORT),
            Some(Attribute::RequestedTransport(17))
        ));
        assert!(d.mi_value_offset.is_some());
    }

    #[test]
    fn xor_mapped_address_roundtrip() {
        for addr in [
            SocketAddr::from(([192, 0, 2, 1], 32853)),
            SocketAddr::from(([127, 0, 0, 1], 3478)),
        ] {
            let msg = StunMessage::new(ALLOCATE_SUCCESS)
                .attr(Attribute::XorRelayedAddress(addr))
                .attr(Attribute::XorMappedAddress(addr));
            let d = decode(&msg.encode()).unwrap();
            assert_eq!(
                d.get(ATTR_XOR_RELAYED_ADDRESS),
                Some(&Attribute::XorRelayedAddress(addr))
            );
            assert_eq!(
                d.get(ATTR_XOR_MAPPED_ADDRESS),
                Some(&Attribute::XorMappedAddress(addr))
            );
        }
    }

    #[test]
    fn xor_v6_address_roundtrip() {
        let addr = SocketAddr::from(([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1], 12345));
        let msg = StunMessage::new(ALLOCATE_SUCCESS).attr(Attribute::XorPeerAddress(addr));
        let d = decode(&msg.encode()).unwrap();
        assert_eq!(
            d.get(ATTR_XOR_PEER_ADDRESS),
            Some(&Attribute::XorPeerAddress(addr))
        );
    }

    #[test]
    fn channel_data_encode_parse() {
        let mut buf = Vec::new();
        encode_channel_data(0x4000, b"payload", &mut buf);
        assert!(is_channel_data(&buf));
        assert!(!is_stun_message(&buf));
        let (ch, data) = parse_channel_data(&buf).unwrap();
        assert_eq!(ch, 0x4000);
        assert_eq!(data, b"payload");
        // STUN 头不会被误判为 ChannelData
        let stun = StunMessage::new(ALLOCATE_REQUEST).encode();
        assert!(!is_channel_data(&stun));
        assert!(parse_channel_data(&stun).is_none());
    }

    #[test]
    fn channel_number_range() {
        assert!(valid_channel(0x4000));
        assert!(valid_channel(0x7FFF));
        assert!(!valid_channel(0x3FFF));
        assert!(!valid_channel(0x8000));
    }

    #[test]
    fn error_code_roundtrip() {
        let msg = StunMessage::new(ALLOCATE_FAILURE).attr(Attribute::ErrorCode(
            4,
            1,
            b"Unauthorized".to_vec(),
        ));
        let d = decode(&msg.encode()).unwrap();
        assert!(matches!(
            d.get(ATTR_ERROR_CODE),
            Some(Attribute::ErrorCode(4, 1, r)) if r == b"Unauthorized"
        ));
    }

    #[test]
    fn decode_rejects_bad_magic() {
        let mut bytes = StunMessage::new(ALLOCATE_REQUEST).encode();
        bytes[4] ^= 0xFF;
        assert!(matches!(decode(&bytes), Err(DecodeError::BadMagic)));
    }

    #[test]
    fn lifetime_attr_roundtrip() {
        let msg = StunMessage::new(REFRESH_SUCCESS).attr(Attribute::Lifetime(600));
        let d = decode(&msg.encode()).unwrap();
        assert_eq!(d.get(ATTR_LIFETIME), Some(&Attribute::Lifetime(600)));
    }
}
