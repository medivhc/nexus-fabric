//! Hysteria2 代理帧编解码（文档 §2.2/§2.3/§3.2/§3.3）。
//!
//! - TCP 走双向 QUIC stream：首帧 `TCPRequest`（可携带首个数据 payload 做
//!   fast-open），server 回 `TCPResponse`，之后 stream 为透明转发通道。
//! - UDP 走 QUIC DATAGRAM：每个包封装为 `UDPMessage`。
//!
//! 地址一律为**文本** `host:port`（区别于 SOCKS5/VLESS 的二进制地址），
//! 长度前缀为 QUIC varint。

use super::Hysteria2Error;
use super::varint;

/// TCPRequest 帧 ID（varint）。
pub const TCP_REQUEST_ID: u64 = 0x401;

/// TCPResponse 状态：OK。
pub const TCP_STATUS_OK: u8 = 0x00;
/// TCPResponse 状态：Error。
pub const TCP_STATUS_ERROR: u8 = 0x01;

/// 单个 UDP 数据报载荷上限（文档 §3.3：meow-rs `MAX_UDP_SIZE` 约 4096 字节）。
pub const MAX_UDP_PAYLOAD: usize = 4096;

/// TCP 建连请求（client → server，位于代理 stream 首部）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpRequest {
    /// 目标地址文本 `host:port`。
    pub target: String,
}

impl TcpRequest {
    /// 编码请求帧：`[varint 0x401][varint 地址长][地址][varint padding长][padding]`。
    /// `padding` 为调用方提供的随机填充；帧之后可直接跟 fast-open 首包数据。
    #[must_use]
    pub fn encode(target: &str, padding: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        varint::encode(TCP_REQUEST_ID, &mut out);
        varint::encode(target.len() as u64, &mut out);
        out.extend_from_slice(target.as_bytes());
        varint::encode(padding.len() as u64, &mut out);
        out.extend_from_slice(padding);
        out
    }

    /// 解码请求帧，返回 `(请求, 消费字节数)`；帧之后剩余的字节为可选的
    /// fast-open 首包数据，由调用方继续处理。
    ///
    /// # Errors
    ///
    /// 帧 ID 不是 `0x401`、截断、地址非 UTF-8 → [`Hysteria2Error::InvalidFrame`]。
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), Hysteria2Error> {
        let (id, mut pos) = varint::decode(buf)?;
        if id != TCP_REQUEST_ID {
            return Err(Hysteria2Error::InvalidFrame);
        }
        let (addr_len, n) = varint::decode(&buf[pos..])?;
        pos += n;
        let addr_len = usize::try_from(addr_len).map_err(|_| Hysteria2Error::InvalidFrame)?;
        let addr_bytes = buf
            .get(pos..pos + addr_len)
            .ok_or(Hysteria2Error::InvalidFrame)?;
        pos += addr_len;
        let target =
            String::from_utf8(addr_bytes.to_vec()).map_err(|_| Hysteria2Error::InvalidFrame)?;
        let (pad_len, n) = varint::decode(&buf[pos..])?;
        pos += n;
        let pad_len = usize::try_from(pad_len).map_err(|_| Hysteria2Error::InvalidFrame)?;
        if buf.len() < pos + pad_len {
            return Err(Hysteria2Error::InvalidFrame);
        }
        pos += pad_len;
        Ok((Self { target }, pos))
    }
}

/// TCP 建连响应（server → client，位于代理 stream 首部）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpResponse {
    /// `true` = OK（0x00），`false` = Error（0x01）。
    pub ok: bool,
    /// server 返回的消息文本（OK 时通常为空）。
    pub message: String,
}

impl TcpResponse {
    /// 编码响应帧：`[u8 status][varint 消息长][消息][varint padding长][padding]`。
    #[must_use]
    pub fn encode(ok: bool, message: &str, padding: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(if ok { TCP_STATUS_OK } else { TCP_STATUS_ERROR });
        varint::encode(message.len() as u64, &mut out);
        out.extend_from_slice(message.as_bytes());
        varint::encode(padding.len() as u64, &mut out);
        out.extend_from_slice(padding);
        out
    }

    /// 解码响应帧，返回 `(响应, 消费字节数)`；之后剩余字节为代理载荷。
    ///
    /// # Errors
    ///
    /// 状态字节非法、截断、消息非 UTF-8 → [`Hysteria2Error::InvalidFrame`]。
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), Hysteria2Error> {
        let status = *buf.first().ok_or(Hysteria2Error::InvalidFrame)?;
        let ok = match status {
            TCP_STATUS_OK => true,
            TCP_STATUS_ERROR => false,
            _ => return Err(Hysteria2Error::InvalidFrame),
        };
        let mut pos = 1;
        let (msg_len, n) = varint::decode(&buf[pos..])?;
        pos += n;
        let msg_len = usize::try_from(msg_len).map_err(|_| Hysteria2Error::InvalidFrame)?;
        let msg_bytes = buf
            .get(pos..pos + msg_len)
            .ok_or(Hysteria2Error::InvalidFrame)?;
        pos += msg_len;
        let message =
            String::from_utf8(msg_bytes.to_vec()).map_err(|_| Hysteria2Error::InvalidFrame)?;
        let (pad_len, n) = varint::decode(&buf[pos..])?;
        pos += n;
        let pad_len = usize::try_from(pad_len).map_err(|_| Hysteria2Error::InvalidFrame)?;
        if buf.len() < pos + pad_len {
            return Err(Hysteria2Error::InvalidFrame);
        }
        pos += pad_len;
        Ok((Self { ok, message }, pos))
    }
}

/// UDP 代理消息（经 QUIC DATAGRAM 双向传输）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpMessage {
    /// Session ID（u32 大端；client 本地从 0 递增分配）。
    pub session_id: u32,
    /// Packet ID（u16 大端；分片共享同一 ID，不分片时无意义）。
    pub packet_id: u16,
    /// Fragment ID（从 0 起）。
    pub frag_id: u8,
    /// Fragment Count（不分片时为 1）。
    pub frag_count: u8,
    /// 目标地址文本 `host:port`。
    pub target: String,
    /// 载荷。
    pub payload: Vec<u8>,
}

impl UdpMessage {
    /// 编码：`[u32BE session][u16BE packet][u8 frag_id][u8 frag_count]
    /// [varint 地址长][地址][载荷]`。
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + self.target.len() + self.payload.len() + 4);
        out.extend_from_slice(&self.session_id.to_be_bytes());
        out.extend_from_slice(&self.packet_id.to_be_bytes());
        out.push(self.frag_id);
        out.push(self.frag_count);
        varint::encode(self.target.len() as u64, &mut out);
        out.extend_from_slice(self.target.as_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// 解码 UDPMessage。
    ///
    /// # Errors
    ///
    /// 截断、地址非 UTF-8 → [`Hysteria2Error::InvalidFrame`]。
    pub fn decode(buf: &[u8]) -> Result<Self, Hysteria2Error> {
        if buf.len() < 8 {
            return Err(Hysteria2Error::InvalidFrame);
        }
        let session_id = u32::from_be_bytes(buf[0..4].try_into().unwrap());
        let packet_id = u16::from_be_bytes(buf[4..6].try_into().unwrap());
        let frag_id = buf[6];
        let frag_count = buf[7];
        let mut pos = 8;
        let (addr_len, n) = varint::decode(&buf[pos..])?;
        pos += n;
        let addr_len = usize::try_from(addr_len).map_err(|_| Hysteria2Error::InvalidFrame)?;
        let addr_bytes = buf
            .get(pos..pos + addr_len)
            .ok_or(Hysteria2Error::InvalidFrame)?;
        pos += addr_len;
        let target =
            String::from_utf8(addr_bytes.to_vec()).map_err(|_| Hysteria2Error::InvalidFrame)?;
        let payload = buf[pos..].to_vec();
        Ok(Self {
            session_id,
            packet_id,
            frag_id,
            frag_count,
            target,
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_request_roundtrip_with_fast_open_payload() {
        let padding = [0xABu8; 16];
        let mut wire = TcpRequest::encode("example.com:443", &padding);
        // fast-open 首包数据直接跟在帧后面。
        wire.extend_from_slice(b"hello-fast-open");
        let (req, consumed) = TcpRequest::decode(&wire).unwrap();
        assert_eq!(req.target, "example.com:443");
        assert_eq!(&wire[consumed..], b"hello-fast-open");
    }

    #[test]
    fn tcp_request_wrong_id_rejected() {
        let mut bad = Vec::new();
        varint::encode(0x402, &mut bad); // 不是 0x401
        assert_eq!(TcpRequest::decode(&bad), Err(Hysteria2Error::InvalidFrame));
    }

    #[test]
    fn tcp_request_truncated_rejected() {
        let wire = TcpRequest::encode("example.com:443", &[0u8; 8]);
        for cut in [1, 3, 10, wire.len() - 1] {
            assert_eq!(
                TcpRequest::decode(&wire[..cut]),
                Err(Hysteria2Error::InvalidFrame),
                "cut at {cut} must fail"
            );
        }
    }

    #[test]
    fn tcp_response_roundtrip() {
        // OK 响应（含 padding），后跟代理载荷。
        let mut wire = TcpResponse::encode(true, "", &[0xCDu8; 8]);
        wire.extend_from_slice(b"proxy-payload");
        let (resp, consumed) = TcpResponse::decode(&wire).unwrap();
        assert!(resp.ok);
        assert_eq!(resp.message, "");
        assert_eq!(&wire[consumed..], b"proxy-payload");

        // Error 响应携带错误文本。
        let wire = TcpResponse::encode(false, "dial tcp: connection refused", &[]);
        let (resp, consumed) = TcpResponse::decode(&wire).unwrap();
        assert!(!resp.ok);
        assert_eq!(resp.message, "dial tcp: connection refused");
        assert_eq!(consumed, wire.len());
    }

    #[test]
    fn tcp_response_bad_status_rejected() {
        assert_eq!(
            TcpResponse::decode(&[0x02, 0x00, 0x00]),
            Err(Hysteria2Error::InvalidFrame)
        );
        assert_eq!(TcpResponse::decode(&[]), Err(Hysteria2Error::InvalidFrame));
    }

    #[test]
    fn udp_message_roundtrip() {
        let msg = UdpMessage {
            session_id: 0x0102_0304,
            packet_id: 0x0506,
            frag_id: 2,
            frag_count: 5,
            target: "8.8.8.8:53".to_string(),
            payload: b"\x12\x34\x01\x00".to_vec(),
        };
        let wire = msg.encode();
        // 头部字节序：u32BE session, u16BE packet, frag_id, frag_count。
        assert_eq!(
            &wire[..8],
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x02, 0x05]
        );
        let back = UdpMessage::decode(&wire).unwrap();
        assert_eq!(back, msg);
    }

    #[test]
    fn udp_message_empty_payload_and_domain_target() {
        let msg = UdpMessage {
            session_id: 7,
            packet_id: 0,
            frag_id: 0,
            frag_count: 1,
            target: "dns.example.net:853".to_string(),
            payload: Vec::new(),
        };
        let back = UdpMessage::decode(&msg.encode()).unwrap();
        assert_eq!(back, msg);
    }

    #[test]
    fn udp_message_truncated_rejected() {
        assert_eq!(
            UdpMessage::decode(&[0x01, 0x02, 0x03]),
            Err(Hysteria2Error::InvalidFrame)
        );
        let msg = UdpMessage {
            session_id: 1,
            packet_id: 2,
            frag_id: 0,
            frag_count: 1,
            target: "a:1".to_string(),
            payload: b"data".to_vec(),
        };
        let wire = msg.encode();
        // 从地址区中间截断（wire = 8 头 + 1 地址长 + 3 地址 + 4 载荷 = 16 字节，
        // 取前 10 字节则地址不完整）。
        assert_eq!(
            UdpMessage::decode(&wire[..wire.len() - 6]),
            Err(Hysteria2Error::InvalidFrame)
        );
    }
}
