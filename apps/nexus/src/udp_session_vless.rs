//! VLESS over TCP 的 UDP 会话（spec §4.1；`apps/nexus` 内部）。
//!
//! 线格式由 `nexus-outbound-vless` 提供（`u16BE len + payload`，无 per-datagram
//! 源地址）；本模块负责：TCP/TLS 连接、`command=Udp` 请求头、惰性响应头消费，
//! 以及 100ms 读轮询下「超时/WouldBlock 不算错误」的增量组帧。

use std::net::SocketAddr;

use nexus_outbound_vless::{
    VlessCommand, VlessError, VlessFlow, VlessRequest, VlessTarget, VlessUuid,
};
use nexus_proxy_config::OutboundKind;

use super::udp_outbound::{
    TargetAddr, UdpHandshakeFailure, UdpOutboundError, UdpSession, UdpStream, connect_tcp,
    map_handshake_write, map_send_error, read_into, set_poll_timeouts,
    set_protocol_handshake_timeouts, tls_client_config, tls_connect,
};

const KIND: OutboundKind = OutboundKind::Vless;

/// VLESS UDP 出站配置（一个出站配置一份）。
pub(crate) struct VlessUdpConfig {
    pub(crate) server: SocketAddr,
    pub(crate) sni: String,
    pub(crate) uuid: VlessUuid,
    pub(crate) flow: VlessFlow,
    pub(crate) use_tls: bool,
    pub(crate) skip_cert_verify: bool,
}

/// 为一个目标建立 VLESS UDP 会话（一个目标一条连接）。
pub(crate) fn open_vless_session(
    config: &VlessUdpConfig,
    target: &TargetAddr,
) -> Result<Box<dyn UdpSession>, UdpOutboundError> {
    // Phase 1 仅 flow=None；Vision+UDP 线格式未确认（fail-closed，不建连）。
    if config.flow != VlessFlow::None {
        return Err(UdpOutboundError::Unsupported {
            kind: KIND,
            reason: nexus_proxy_config::UdpUnsupportedReason::NotWired,
        });
    }

    let socket = connect_tcp(KIND, config.server)?;
    let handle = socket.try_clone().map_err(|error| UdpOutboundError::Io {
        kind: KIND,
        io: error.kind(),
    })?;
    let mut stream: Box<dyn UdpStream> = if config.use_tls {
        let tls_config = tls_client_config(KIND, config.skip_cert_verify)?;
        tls_connect(KIND, socket, &config.sni, tls_config)?
    } else {
        Box::new(socket)
    };

    // §5.2：协议握手阶段（请求头 + 惰性响应头）显式 10s 上限。
    set_protocol_handshake_timeouts(&handle, KIND)?;
    let request = VlessRequest {
        uuid: config.uuid,
        flow: config.flow,
        command: VlessCommand::Udp,
        port: target.port(),
        target: Some(vless_target(target)),
    };
    let request_bytes = nexus_outbound_vless::encode_request(&request)
        .map_err(|error| map_vless_handshake_error(error, OutboundKind::Vless))?;
    stream
        .write_all(&request_bytes)
        .map_err(|error| map_handshake_write(KIND, error))?;

    set_poll_timeouts(&handle, KIND)?;
    Ok(Box::new(VlessUdpSession {
        stream,
        target: target.clone(),
        header: ResponseHeader::new(),
        buf: Vec::new(),
        closed: false,
    }))
}

/// 惰性消费响应头 `[version(1) | addon_len(1) | addon]`。
struct ResponseHeader {
    state: HeaderState,
}

enum HeaderState {
    Prefix,
    Addon(usize),
    Done,
}

impl ResponseHeader {
    fn new() -> Self {
        Self {
            state: HeaderState::Prefix,
        }
    }

    fn is_done(&self) -> bool {
        matches!(self.state, HeaderState::Done)
    }

    /// 从缓冲尽量消费；返回是否已消费完（未完成不视为错误）。
    fn consume(&mut self, buf: &mut Vec<u8>) -> Result<bool, UdpOutboundError> {
        loop {
            match self.state {
                HeaderState::Prefix => {
                    if buf.len() < 2 {
                        return Ok(false);
                    }
                    let version = buf[0];
                    let addon_len = usize::from(buf[1]);
                    buf.drain(..2);
                    if version != 0x00 {
                        return Err(UdpOutboundError::Handshake {
                            kind: KIND,
                            failure: UdpHandshakeFailure::ResponseInvalid,
                        });
                    }
                    self.state = HeaderState::Addon(addon_len);
                }
                HeaderState::Addon(len) => {
                    if buf.len() < len {
                        return Ok(false);
                    }
                    buf.drain(..len);
                    self.state = HeaderState::Done;
                }
                HeaderState::Done => return Ok(true),
            }
        }
    }
}

/// VLESS UDP 会话（per-target）。
struct VlessUdpSession {
    stream: Box<dyn UdpStream>,
    target: TargetAddr,
    header: ResponseHeader,
    buf: Vec<u8>,
    closed: bool,
}

impl UdpSession for VlessUdpSession {
    fn send(&mut self, target: &TargetAddr, payload: &[u8]) -> Result<(), UdpOutboundError> {
        if self.closed {
            return Err(UdpOutboundError::Closed { kind: KIND });
        }
        if target != &self.target {
            return Err(UdpOutboundError::Config {
                kind: KIND,
                detail: "per-target session target mismatch",
            });
        }
        let frame = encode_udp_datagram(payload)?;
        self.stream
            .write_all(&frame)
            .map_err(|error| map_send_error(KIND, error))
    }

    fn try_recv(&mut self) -> Result<Option<(TargetAddr, Vec<u8>)>, UdpOutboundError> {
        if self.closed {
            return Err(UdpOutboundError::Closed { kind: KIND });
        }
        loop {
            if !self.header.is_done() {
                self.header.consume(&mut self.buf)?;
            }
            if self.header.is_done() {
                if let Some(payload) = take_len_prefixed(&mut self.buf) {
                    return Ok(Some((self.target.clone(), payload)));
                }
            }
            if !read_into(&mut *self.stream, &mut self.buf, KIND)? {
                return Ok(None);
            }
        }
    }

    fn close(&mut self) {
        self.closed = true;
    }
}

/// 编码一个 UDP 数据报（`u16BE len + payload`）。
pub(crate) fn encode_udp_datagram(payload: &[u8]) -> Result<Vec<u8>, UdpOutboundError> {
    nexus_outbound_vless::encode_udp_datagram(payload).map_err(|error| match error {
        VlessError::DatagramTooLarge { len } => UdpOutboundError::DatagramTooLarge {
            kind: KIND,
            len,
            limit: u16::MAX as usize,
        },
        _ => UdpOutboundError::Handshake {
            kind: KIND,
            failure: UdpHandshakeFailure::InvalidFrame,
        },
    })
}

/// 从流上读一个 UDP 数据报；无完整帧（含 100ms 超时）→ `Ok(None)`，EOF → `Closed`。
// spec §4.1 冻结 API；产品路径用增量组帧（`take_len_prefixed`），本函数当前仅单测调用。
#[allow(dead_code)]
pub(crate) fn read_udp_datagram(
    stream: &mut dyn UdpStream,
    buf: &mut Vec<u8>,
) -> Result<Option<Vec<u8>>, UdpOutboundError> {
    loop {
        if let Some(payload) = take_len_prefixed(buf) {
            return Ok(Some(payload));
        }
        if !read_into(stream, buf, KIND)? {
            return Ok(None);
        }
    }
}

/// 把一段完整字节切分成 UDP 数据报序列（尾部不完整 → `Truncated`）。
// spec §4.1 冻结 API；产品路径用增量组帧，本函数当前仅单测调用。
#[allow(dead_code)]
pub(crate) fn decode_udp_datagrams(buf: &[u8]) -> Result<Vec<Vec<u8>>, UdpOutboundError> {
    nexus_outbound_vless::decode_udp_datagrams(buf).map_err(|_| UdpOutboundError::Handshake {
        kind: KIND,
        failure: UdpHandshakeFailure::Truncated,
    })
}

/// 从缓冲取一个完整 `u16BE len + payload`；不足一帧 → None（保留剩余字节）。
fn take_len_prefixed(buf: &mut Vec<u8>) -> Option<Vec<u8>> {
    if buf.len() < 2 {
        return None;
    }
    let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    if buf.len() < 2 + len {
        return None;
    }
    buf.drain(..2);
    Some(buf.drain(..len).collect())
}

fn vless_target(target: &TargetAddr) -> VlessTarget {
    match target {
        TargetAddr::Ip(SocketAddr::V4(v4)) => VlessTarget::Ipv4(*v4.ip()),
        TargetAddr::Ip(SocketAddr::V6(v6)) => VlessTarget::Ipv6(*v6.ip()),
        TargetAddr::Domain { host, .. } => VlessTarget::Domain(host.clone()),
    }
}

fn map_vless_handshake_error(error: VlessError, kind: OutboundKind) -> UdpOutboundError {
    match error {
        VlessError::DatagramTooLarge { len } => UdpOutboundError::DatagramTooLarge {
            kind,
            len,
            limit: u16::MAX as usize,
        },
        VlessError::TruncatedDatagram => UdpOutboundError::Handshake {
            kind,
            failure: UdpHandshakeFailure::Truncated,
        },
        VlessError::Io => UdpOutboundError::Io {
            kind,
            io: std::io::ErrorKind::Other,
        },
        _ => UdpOutboundError::Handshake {
            kind,
            failure: UdpHandshakeFailure::InvalidFrame,
        },
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::io::{Cursor, Read};

    #[test]
    fn udp_datagram_encoding_roundtrip() {
        let frame = encode_udp_datagram(b"hello").expect("encode");
        assert_eq!(frame, vec![0x00, 0x05, b'h', b'e', b'l', b'l', b'o']);
        assert_eq!(
            decode_udp_datagrams(&frame).expect("decode"),
            vec![b"hello".to_vec()]
        );
    }

    #[test]
    fn oversize_payload_rejected_before_send() {
        let payload = vec![0u8; 65536];
        assert_eq!(
            encode_udp_datagram(&payload),
            Err(UdpOutboundError::DatagramTooLarge {
                kind: KIND,
                len: 65536,
                limit: 65535,
            })
        );
    }

    #[test]
    fn truncated_stream_is_reported() {
        // 声明 4 字节但只有 2 字节。
        assert_eq!(
            decode_udp_datagrams(&[0x00, 0x04, b'a', b'b']),
            Err(UdpOutboundError::Handshake {
                kind: KIND,
                failure: UdpHandshakeFailure::Truncated,
            })
        );
    }

    #[test]
    fn response_header_is_consumed_lazily() {
        let mut header = ResponseHeader::new();
        let mut buf = vec![0x00, 0x02, 0xAA, 0xBB, 0x00, 0x03, b'x', b'y', b'z'];
        // 首次消费：头完整，剩余数据报未动。
        assert!(header.consume(&mut buf).expect("consume"));
        assert!(header.is_done());
        assert_eq!(buf, vec![0x00, 0x03, b'x', b'y', b'z']);
        assert_eq!(take_len_prefixed(&mut buf), Some(vec![b'x', b'y', b'z']));

        // 分段到达：先只有 1 字节，再补齐。
        let mut header = ResponseHeader::new();
        let mut buf = vec![0x00];
        assert!(!header.consume(&mut buf).expect("partial"));
        assert!(!header.is_done());
        buf.extend_from_slice(&[0x01, 0xCC]);
        assert!(header.consume(&mut buf).expect("complete"));
        assert!(header.is_done());
        assert!(buf.is_empty());
    }

    #[test]
    fn bad_response_version_is_handshake_failure() {
        let mut header = ResponseHeader::new();
        let mut buf = vec![0x01, 0x00];
        assert_eq!(
            header.consume(&mut buf),
            Err(UdpOutboundError::Handshake {
                kind: KIND,
                failure: UdpHandshakeFailure::ResponseInvalid,
            })
        );
    }

    #[test]
    fn read_udp_datagram_keeps_partial_bytes() {
        // 两条数据报：第二条只到达一半时返回 None，补齐后返回。
        struct Chunky {
            chunks: Vec<Vec<u8>>,
        }
        impl Read for Chunky {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.chunks.is_empty() {
                    return Ok(0);
                }
                let chunk = self.chunks.remove(0);
                buf[..chunk.len()].copy_from_slice(&chunk);
                Ok(chunk.len())
            }
        }
        impl std::io::Write for Chunky {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                Ok(buf.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut stream = Box::new(Chunky {
            chunks: vec![vec![0x00, 0x03, b'a', b'b'], vec![b'c', 0x00, 0x01]],
        });
        let mut buf = Vec::new();
        assert_eq!(
            read_udp_datagram(&mut *stream, &mut buf).expect("first"),
            Some(b"abc".to_vec())
        );
        // 缓冲里只剩半帧，随后 EOF → Closed（不是 None）。
        assert_eq!(
            read_udp_datagram(&mut *stream, &mut buf),
            Err(UdpOutboundError::Closed { kind: KIND })
        );

        // Cursor 完整性快速校验（1 帧 + EOF）。
        let mut cursor = Cursor::new(vec![0x00, 0x02, b'o', b'k']);
        let mut buf = Vec::new();
        assert_eq!(
            read_udp_datagram(&mut cursor, &mut buf).expect("cursor"),
            Some(b"ok".to_vec())
        );
        assert_eq!(
            read_udp_datagram(&mut cursor, &mut buf),
            Err(UdpOutboundError::Closed { kind: KIND })
        );
    }
}
