//! AnyTLS UoT（UDP over TCP）会话（spec §4.2；`apps/nexus` 内部）。
//!
//! 一个目标一条 TLS session + 一条魔法 UoT stream；数据报用 `u16BE len + payload`
//! 前缀，包在 PSH 帧里。100ms 读轮询下只做增量组帧，超时/WouldBlock 不算错误。

use std::net::SocketAddr;

use nexus_outbound_anytls::{
    AnyTlsCommand, AnyTlsError, AnyTlsFrame, AnyTlsTarget, CLIENT_IDENT, ClientHandshake,
    DEFAULT_PADDING_SCHEME, client_handshake, client_open_uot_stream as crate_open_uot_stream,
    decode_frame_bytes, decode_uot_datagrams as crate_decode_uot_datagrams, encode_frame,
    encode_uot_datagram as crate_encode_uot_datagram, padding_md5_hex,
};
use nexus_proxy_config::OutboundKind;

use super::udp_outbound::{
    TargetAddr, UdpHandshakeFailure, UdpOutboundError, UdpSession, UdpStream, connect_tcp,
    map_send_error, read_into, set_poll_timeouts, set_protocol_handshake_timeouts,
    tls_client_config, tls_connect,
};

const KIND: OutboundKind = OutboundKind::Anytls;
/// AnyTLS 帧头长度（cmd 1 + stream_id 4 + len 2）。
const FRAME_HEADER_LEN: usize = 7;

/// AnyTLS UDP 出站配置（一个出站配置一份）。
pub(crate) struct AnytlsUdpConfig {
    pub(crate) server: SocketAddr,
    pub(crate) sni: String,
    pub(crate) password: String,
    pub(crate) skip_cert_verify: bool,
}

/// 为一个目标建立 AnyTLS UoT 会话。
pub(crate) fn open_anytls_session(
    config: &AnytlsUdpConfig,
    target: &TargetAddr,
) -> Result<Box<dyn UdpSession>, UdpOutboundError> {
    let socket = connect_tcp(KIND, config.server)?;
    let handle = socket.try_clone().map_err(|error| UdpOutboundError::Io {
        kind: KIND,
        io: error.kind(),
    })?;
    // AnyTLS 始终 TLS（与 TCP 路径一致）。
    let tls_config = tls_client_config(KIND, config.skip_cert_verify)?;
    let mut stream = tls_connect(KIND, socket, &config.sni, tls_config)?;

    // §5.2：协议握手阶段（session + UoT stream）显式 10s 上限。
    set_protocol_handshake_timeouts(&handle, KIND)?;
    let padding_md5 = padding_md5_hex(DEFAULT_PADDING_SCHEME);
    let mut handshake =
        client_handshake(&mut stream, &config.password, 0, CLIENT_IDENT, &padding_md5)
            .map_err(map_anytls_handshake_error)?;
    let stream_id = client_open_uot_stream(&mut stream, &mut handshake, target)?;

    set_poll_timeouts(&handle, KIND)?;
    Ok(Box::new(AnytlsUdpSession {
        stream,
        stream_id,
        target: target.clone(),
        buf: Vec::new(),
        uot: Vec::new(),
        closed: false,
    }))
}

/// 开一条 UoT stream（目标编码进 eager Connect 载荷）。
pub(crate) fn client_open_uot_stream(
    stream: &mut Box<dyn UdpStream>,
    handshake: &mut ClientHandshake,
    target: &TargetAddr,
) -> Result<u32, UdpOutboundError> {
    crate_open_uot_stream(stream, handshake, &anytls_target(target))
        .map_err(map_anytls_handshake_error)
}

/// 编码一个 UoT 数据包（`u16BE len + payload`）。
pub(crate) fn encode_uot_datagram(payload: &[u8]) -> Result<Vec<u8>, UdpOutboundError> {
    crate_encode_uot_datagram(payload).map_err(|_| UdpOutboundError::DatagramTooLarge {
        kind: KIND,
        len: payload.len(),
        limit: u16::MAX as usize,
    })
}

/// 按 `u16BE` 长度前缀切分完整缓冲（尾部不完整 → `InvalidFrame`）。
// spec §4.2 冻结 API；产品路径用增量组帧（`take_uot_datagram`），本函数当前仅单测调用。
#[allow(dead_code)]
pub(crate) fn decode_uot_datagrams(buf: &[u8]) -> Result<Vec<Vec<u8>>, UdpOutboundError> {
    crate_decode_uot_datagrams(buf).map_err(|_| UdpOutboundError::Handshake {
        kind: KIND,
        failure: UdpHandshakeFailure::InvalidFrame,
    })
}

/// AnyTLS UoT 会话（per-target）。
struct AnytlsUdpSession {
    stream: Box<dyn UdpStream>,
    stream_id: u32,
    target: TargetAddr,
    /// 未成帧的字节。
    buf: Vec<u8>,
    /// 已从 PSH 帧取出、尚未切分成 UoT 数据报的字节。
    uot: Vec<u8>,
    closed: bool,
}

impl UdpSession for AnytlsUdpSession {
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
        let datagram = encode_uot_datagram(payload)?;
        let frame = encode_frame(AnyTlsCommand::Psh, self.stream_id, &datagram).map_err(|_| {
            // 帧数据区上限 u16；UoT 前缀 2 字节占用后 payload 上限 65533。
            UdpOutboundError::DatagramTooLarge {
                kind: KIND,
                len: datagram.len(),
                limit: u16::MAX as usize,
            }
        })?;
        self.stream
            .write_all(&frame)
            .map_err(|error| map_send_error(KIND, error))
    }

    fn try_recv(&mut self) -> Result<Option<(TargetAddr, Vec<u8>)>, UdpOutboundError> {
        if self.closed {
            return Err(UdpOutboundError::Closed { kind: KIND });
        }
        loop {
            if let Some(payload) = take_uot_datagram(&mut self.uot) {
                return Ok(Some((self.target.clone(), payload)));
            }
            if let Some(frame) = take_frame(&mut self.buf) {
                match frame.cmd {
                    AnyTlsCommand::Psh if frame.stream_id == self.stream_id => {
                        self.uot.extend_from_slice(&frame.data);
                        continue;
                    }
                    AnyTlsCommand::Fin if frame.stream_id == self.stream_id => {
                        self.closed = true;
                        return Err(UdpOutboundError::Closed { kind: KIND });
                    }
                    AnyTlsCommand::HeartRequest => {
                        let heartbeat = encode_frame(AnyTlsCommand::HeartResponse, 0, &[])
                            .map_err(|_| UdpOutboundError::Handshake {
                                kind: KIND,
                                failure: UdpHandshakeFailure::Internal,
                            })?;
                        self.stream
                            .write_all(&heartbeat)
                            .map_err(|error| map_send_error(KIND, error))?;
                        continue;
                    }
                    AnyTlsCommand::Alert => {
                        let reason = crate::redact::sanitize(&String::from_utf8_lossy(&frame.data));
                        return Err(UdpOutboundError::Handshake {
                            kind: KIND,
                            failure: UdpHandshakeFailure::StreamRejected { reason },
                        });
                    }
                    // Waste / 心跳响应 / 其他 stream 的帧：忽略。
                    _ => continue,
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

/// 从缓冲取一个完整 UoT 数据报；不足一个 → None（保留剩余字节）。
fn take_uot_datagram(buf: &mut Vec<u8>) -> Option<Vec<u8>> {
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

/// 从缓冲取一个完整 AnyTLS 帧；不足一帧 → None（保留剩余字节）。
fn take_frame(buf: &mut Vec<u8>) -> Option<AnyTlsFrame> {
    if buf.len() < FRAME_HEADER_LEN {
        return None;
    }
    let data_len = u16::from_be_bytes([buf[5], buf[6]]) as usize;
    if buf.len() < FRAME_HEADER_LEN + data_len {
        return None;
    }
    // 头已确认完整，decode 不会失败；失败时按「无帧」处理，避免无限循环。
    decode_frame_bytes(buf).ok().map(|(frame, consumed)| {
        buf.drain(..consumed);
        frame
    })
}

fn anytls_target(target: &TargetAddr) -> AnyTlsTarget {
    match target {
        TargetAddr::Ip(SocketAddr::V4(v4)) => AnyTlsTarget::Ipv4(v4.ip().octets(), v4.port()),
        TargetAddr::Ip(SocketAddr::V6(v6)) => AnyTlsTarget::Ipv6(v6.ip().octets(), v6.port()),
        TargetAddr::Domain { host, port } => AnyTlsTarget::Domain(host.clone(), *port),
    }
}

fn map_anytls_handshake_error(error: AnyTlsError) -> UdpOutboundError {
    let failure = match error {
        AnyTlsError::AuthDenied => UdpHandshakeFailure::AuthRejected,
        AnyTlsError::InvalidFrame | AnyTlsError::InvalidAddress => {
            UdpHandshakeFailure::InvalidFrame
        }
        AnyTlsError::InvalidSettings => UdpHandshakeFailure::ResponseInvalid,
        AnyTlsError::InvalidPaddingScheme { .. } | AnyTlsError::PaddingSchemeUpdated { .. } => {
            UdpHandshakeFailure::ResponseInvalid
        }
        AnyTlsError::UnexpectedCommand { .. } => UdpHandshakeFailure::UnexpectedFrame,
        AnyTlsError::StreamRejected { reason, .. } => UdpHandshakeFailure::StreamRejected {
            reason: crate::redact::sanitize(&reason),
        },
        AnyTlsError::Tls => {
            return UdpOutboundError::Tls {
                kind: KIND,
                failure: super::udp_outbound::UdpTlsFailure::Handshake,
            };
        }
        AnyTlsError::Io => {
            return UdpOutboundError::Io {
                kind: KIND,
                io: std::io::ErrorKind::Other,
            };
        }
    };
    UdpOutboundError::Handshake {
        kind: KIND,
        failure,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn uot_datagram_encoding_roundtrip() {
        let encoded = encode_uot_datagram(b"ping").expect("encode");
        assert_eq!(encoded, vec![0x00, 0x04, b'p', b'i', b'n', b'g']);
        assert_eq!(
            decode_uot_datagrams(&encoded).expect("decode"),
            vec![b"ping".to_vec()]
        );
    }

    #[test]
    fn oversize_uot_payload_rejected() {
        let payload = vec![0u8; 65536];
        assert_eq!(
            encode_uot_datagram(&payload),
            Err(UdpOutboundError::DatagramTooLarge {
                kind: KIND,
                len: 65536,
                limit: 65535,
            })
        );
    }

    #[test]
    fn uot_incremental_split_keeps_partial_bytes() {
        let mut buf = vec![0x00, 0x02, b'a', b'b', 0x00, 0x03, b'c'];
        assert_eq!(take_uot_datagram(&mut buf), Some(b"ab".to_vec()));
        assert_eq!(take_uot_datagram(&mut buf), None);
        buf.push(b'd');
        buf.push(b'e');
        assert_eq!(take_uot_datagram(&mut buf), Some(b"cde".to_vec()));
        assert!(buf.is_empty());
    }

    #[test]
    fn frame_split_keeps_partial_bytes() {
        let frame = encode_frame(AnyTlsCommand::Psh, 7, b"hi").expect("frame");
        let mut buf = frame[..3].to_vec();
        assert!(take_frame(&mut buf).is_none());
        buf.extend_from_slice(&frame[3..]);
        let parsed = take_frame(&mut buf).expect("frame parsed");
        assert_eq!(parsed.cmd, AnyTlsCommand::Psh);
        assert_eq!(parsed.stream_id, 7);
        assert_eq!(parsed.data, b"hi");
        assert!(buf.is_empty());
    }

    #[test]
    fn target_mapping_covers_all_atyp() {
        assert_eq!(
            anytls_target(&TargetAddr::Ip("127.0.0.1:53".parse().unwrap())),
            AnyTlsTarget::Ipv4([127, 0, 0, 1], 53)
        );
        assert_eq!(
            anytls_target(&TargetAddr::Domain {
                host: "example.com".into(),
                port: 443,
            }),
            AnyTlsTarget::Domain("example.com".into(), 443)
        );
    }
}
