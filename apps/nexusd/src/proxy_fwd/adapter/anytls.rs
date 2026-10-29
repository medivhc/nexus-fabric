//! AnyTLS 出站 adapter（spec §3.2）。
//!
//! 会话模型（Q8 冻结）：**每 TCP 流一个 session**——一条 TLS 连接 + 一次
//! `client_handshake` + 一个 stream，不做跨流复用。
//!
//! 握手：TCP connect → TLS（SNI、`TLS_HANDSHAKE_TIMEOUT`）→
//! `client_handshake(password, padding0_len=0, CLIENT_IDENT, padding_md5)` →
//! `client_open_stream(target)`。`PaddingSchemeUpdated` → fail-closed
//! （不重建、不降级）。
//!
//! 数据面：写 = `Psh` 帧；读 = 缓冲增量解帧（`decode_frame_bytes`）——
//! `Fin`→EOF、`Waste`→丢弃、其他 stream_id/控制帧→`UnexpectedFrame`。
//! 禁止使用 crate 的整体读帧辅助（其 `read_exact` 会在 100ms 中继读超时时
//! 丢弃半帧，spec §3.2 第 5 条）。
//!
//! UDP：`Unsupported { reason: NotWired }`（Q5=B；产品级 UoT 归 fixes-6）。

use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use nexus_outbound_anytls::{
    AnyTlsCommand, AnyTlsError, AnyTlsFrame, AnyTlsTarget, CLIENT_IDENT, DEFAULT_PADDING_SCHEME,
    MAX_FRAME_DATA_LEN, client_handshake, client_open_stream, decode_frame_bytes, encode_frame,
    padding_md5_hex,
};
use nexus_proxy_config::OutboundKind;

use super::framing::BufferedReader;
use super::tls::{self, Transport};
use super::{
    HandshakeFailure, OutboundDialer, OutboundError, PROTOCOL_HANDSHAKE_TIMEOUT, Protocol,
    TlsFailure, TunnelStream, UdpCapability, UdpUnsupportedReason,
};

/// AnyTLS 出站 dialer（每流一个 session）。
pub(super) struct AnytlsDialer {
    tag: String,
    server: SocketAddr,
    /// TLS SNI（`sni` 优先，缺省 locator host）。
    sni: String,
    password: String,
    skip_cert_verify: bool,
    client_config: OnceLock<Result<Arc<rustls::ClientConfig>, TlsFailure>>,
}

impl AnytlsDialer {
    pub(super) fn new(
        tag: String,
        server: SocketAddr,
        sni: String,
        password: String,
        skip_cert_verify: bool,
    ) -> Self {
        Self {
            tag,
            server,
            sni,
            password,
            skip_cert_verify,
            client_config: OnceLock::new(),
        }
    }

    fn tls_config(&self) -> Result<Arc<rustls::ClientConfig>, TlsFailure> {
        self.client_config
            .get_or_init(|| tls::build_client_config(self.skip_cert_verify, &[]).map(Arc::new))
            .clone()
    }
}

impl OutboundDialer for AnytlsDialer {
    fn kind(&self) -> OutboundKind {
        OutboundKind::Anytls
    }

    fn tag(&self) -> &str {
        &self.tag
    }

    fn dial_tcp(&self, target: SocketAddr) -> Result<Box<dyn TunnelStream>, OutboundError> {
        let config = self.tls_config().map_err(OutboundError::TlsHandshake)?;
        let mut transport = tls::connect_tls(self.server, &self.sni, config)?;

        // 协议握手在 10s 级别超时内完成，返回前清空（中继层自行重设）。
        transport
            .set_read_timeout(Some(PROTOCOL_HANDSHAKE_TIMEOUT))
            .map_err(handshake_io_error)?;
        transport
            .set_write_timeout(Some(PROTOCOL_HANDSHAKE_TIMEOUT))
            .map_err(handshake_io_error)?;

        let padding_md5 = padding_md5_hex(DEFAULT_PADDING_SCHEME);
        let mut handshake = client_handshake(
            &mut transport,
            &self.password,
            0,
            CLIENT_IDENT,
            &padding_md5,
        )
        .map_err(|error| map_anytls_error(error, target))?;
        let stream_id = client_open_stream(&mut transport, &mut handshake, &anytls_target(target))
            .map_err(|error| map_anytls_error(error, target))?;

        transport
            .set_read_timeout(None)
            .map_err(handshake_io_error)?;
        transport
            .set_write_timeout(None)
            .map_err(handshake_io_error)?;

        Ok(Box::new(AnytlsTunnelStream {
            reader: BufferedReader::new(transport),
            stream_id,
            pending: Vec::new(),
            finished: false,
        }))
    }

    fn udp_capability(&self) -> UdpCapability {
        // Q5=B：本 run 不接 AnyTLS UoT（产品级 UDP 归 fixes-6）。
        UdpCapability::Unsupported {
            reason: UdpUnsupportedReason::NotWired,
        }
    }
}

fn anytls_target(target: SocketAddr) -> AnyTlsTarget {
    match target.ip() {
        IpAddr::V4(ip) => AnyTlsTarget::Ipv4(ip.octets(), target.port()),
        IpAddr::V6(ip) => AnyTlsTarget::Ipv6(ip.octets(), target.port()),
    }
}

fn handshake_io_error(error: io::Error) -> OutboundError {
    OutboundError::Io { kind: error.kind() }
}

/// AnyTLS 隧道流：写 = Psh 帧，读 = 缓冲增量解帧。
struct AnytlsTunnelStream {
    reader: BufferedReader<Transport>,
    stream_id: u32,
    /// 单帧数据大于调用方缓冲区时的余量（中继 8192B，通常为空）。
    pending: Vec<u8>,
    /// 已收到本流 `Fin`（后续 `read` 返回 EOF）。
    finished: bool,
}

impl AnytlsTunnelStream {
    /// 从缓冲区解一帧；缓冲不足时继续读（超时原样返回，半帧保留）。
    fn next_frame(&mut self) -> io::Result<AnyTlsFrame> {
        loop {
            match decode_frame_bytes(self.reader.buffered()) {
                Ok((frame, consumed)) => {
                    self.reader.consume(consumed);
                    return Ok(frame);
                }
                Err(_) => {
                    // 帧头/帧体不完整：继续读；EOF 视为会话中断（不伪造 EOF 成功）。
                    if self.reader.fill()? == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "anytls session closed before Fin",
                        ));
                    }
                }
            }
        }
    }
}

impl Read for AnytlsTunnelStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.finished {
            return Ok(0);
        }
        if !self.pending.is_empty() {
            let read = self.pending.len().min(buf.len());
            buf[..read].copy_from_slice(&self.pending[..read]);
            self.pending.drain(..read);
            return Ok(read);
        }
        loop {
            let frame = self.next_frame()?;
            match frame.cmd {
                AnyTlsCommand::Waste => continue,
                AnyTlsCommand::Psh if frame.stream_id == self.stream_id => {
                    if frame.data.is_empty() {
                        continue;
                    }
                    let read = frame.data.len().min(buf.len());
                    buf[..read].copy_from_slice(&frame.data[..read]);
                    if read < frame.data.len() {
                        self.pending.extend_from_slice(&frame.data[read..]);
                    }
                    return Ok(read);
                }
                AnyTlsCommand::Fin if frame.stream_id == self.stream_id => {
                    self.finished = true;
                    return Ok(0);
                }
                other => {
                    // 其他 stream_id / 控制帧：不静默路由错流（spec §3.2）。
                    return Err(frame_error(other, frame.stream_id));
                }
            }
        }
    }
}

/// 帧解析失败（dial 之后）。
///
/// relay 读路径只接受 `io::Error`，故 §2.7 的 `UnexpectedFrame` 分类无法回传；
/// 返回 `InvalidData`，relay 以 RST 关闭流，绝不静默路由错流。
fn frame_error(command: AnyTlsCommand, stream_id: u32) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "anytls unexpected frame cmd={} stream_id={stream_id}",
            command.as_u8()
        ),
    )
}

impl Write for AnytlsTunnelStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let inner = self.reader.get_mut();
        for chunk in buf.chunks(MAX_FRAME_DATA_LEN) {
            let frame = encode_frame(AnyTlsCommand::Psh, self.stream_id, chunk)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "anytls frame encode"))?;
            inner.write_all(&frame)?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.reader.get_mut().flush()
    }
}

impl TunnelStream for AnytlsTunnelStream {
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        self.reader.get_mut().set_read_timeout(timeout)
    }

    fn set_write_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        self.reader.get_mut().set_write_timeout(timeout)
    }

    fn shutdown(&mut self) -> io::Result<()> {
        if self.finished {
            return Ok(());
        }
        self.finished = true;
        let inner = self.reader.get_mut();
        let write_result = encode_frame(AnyTlsCommand::Fin, self.stream_id, &[])
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "anytls frame encode"))
            .and_then(|frame| {
                inner.write_all(&frame)?;
                inner.flush()
            });
        let shutdown_result = inner.shutdown_write();
        write_result.and(shutdown_result)
    }
}

/// `AnyTlsError` → `OutboundError`（spec §2.7 冻结映射）。
fn map_anytls_error(error: AnyTlsError, target: SocketAddr) -> OutboundError {
    match error {
        AnyTlsError::AuthDenied => {
            OutboundError::ProtocolHandshake(HandshakeFailure::AuthRejected {
                protocol: Protocol::Anytls,
            })
        }
        AnyTlsError::InvalidFrame => {
            OutboundError::ProtocolHandshake(HandshakeFailure::InvalidFrame {
                protocol: Protocol::Anytls,
            })
        }
        AnyTlsError::InvalidSettings | AnyTlsError::InvalidPaddingScheme { .. } => {
            OutboundError::ProtocolHandshake(HandshakeFailure::ResponseInvalid {
                protocol: Protocol::Anytls,
            })
        }
        AnyTlsError::InvalidAddress => {
            OutboundError::Config(super::OutboundConfigError::UnsupportedTarget { target })
        }
        AnyTlsError::UnexpectedCommand { cmd, stream_id } => {
            OutboundError::ProtocolHandshake(HandshakeFailure::UnexpectedFrame {
                protocol: Protocol::Anytls,
                command: cmd,
                stream_id,
            })
        }
        AnyTlsError::StreamRejected { stream_id, reason } => {
            OutboundError::ProtocolHandshake(HandshakeFailure::StreamRejected {
                protocol: Protocol::Anytls,
                stream_id,
                reason,
            })
        }
        AnyTlsError::PaddingSchemeUpdated { .. } => {
            OutboundError::ProtocolHandshake(HandshakeFailure::PaddingSchemeUpdate {
                protocol: Protocol::Anytls,
            })
        }
        AnyTlsError::Tls => OutboundError::TlsHandshake(TlsFailure::Handshake),
        AnyTlsError::Io => OutboundError::Io {
            kind: io::ErrorKind::Other,
        },
    }
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;
    use std::time::Duration;

    use super::*;

    fn loopback_pair() -> (std::net::TcpStream, std::net::TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let client = std::net::TcpStream::connect(addr).expect("connect");
        let (server, _) = listener.accept().expect("accept");
        (client, server)
    }

    fn tunnel(client: std::net::TcpStream, stream_id: u32) -> AnytlsTunnelStream {
        client
            .set_read_timeout(Some(Duration::from_millis(100)))
            .expect("timeout");
        AnytlsTunnelStream {
            reader: BufferedReader::new(Transport::Plain(client)),
            stream_id,
            pending: Vec::new(),
            finished: false,
        }
    }

    /// 模拟中继读循环：超时继续重试，直到拿到数据（最多 2s）。
    fn read_until_data(stream: &mut AnytlsTunnelStream, buf: &mut [u8]) -> usize {
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            match stream.read(buf) {
                Ok(read) => return read,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    assert!(std::time::Instant::now() < deadline, "read deadline");
                }
                Err(error) => panic!("unexpected read error: {error:?}"),
            }
        }
    }

    /// A3 约束 2：半帧跨超时保留，恢复后按帧交付。
    #[test]
    fn partial_frame_survives_read_timeout() {
        let (client, mut server) = loopback_pair();
        let mut stream = tunnel(client, 7);
        let frame = encode_frame(AnyTlsCommand::Psh, 7, b"payload").expect("frame");
        let (head, tail) = frame.split_at(4);
        let head = head.to_vec();
        let tail = tail.to_vec();
        let writer = std::thread::spawn(move || {
            server.write_all(&head).expect("head");
            std::thread::sleep(Duration::from_millis(250));
            server.write_all(&tail).expect("tail");
        });

        let mut buf = [0u8; 32];
        let error = stream.read(&mut buf).expect_err("timeout expected");
        assert!(
            matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ),
            "{error:?}"
        );
        let read = read_until_data(&mut stream, &mut buf);
        assert_eq!(&buf[..read], b"payload");
        writer.join().expect("writer");
    }

    #[test]
    fn fin_returns_eof_and_waste_is_dropped() {
        let (client, mut server) = loopback_pair();
        let mut stream = tunnel(client, 3);
        let writer = std::thread::spawn(move || {
            for frame in [
                encode_frame(AnyTlsCommand::Waste, 0, b"junk").expect("waste"),
                encode_frame(AnyTlsCommand::Psh, 3, b"data").expect("psh"),
                encode_frame(AnyTlsCommand::Fin, 3, b"").expect("fin"),
            ] {
                server.write_all(&frame).expect("frame");
            }
        });
        let mut buf = [0u8; 16];
        let read = stream.read(&mut buf).expect("data");
        assert_eq!(&buf[..read], b"data");
        assert_eq!(stream.read(&mut buf).expect("eof"), 0);
        writer.join().expect("writer");
    }

    #[test]
    fn foreign_stream_id_is_unexpected_frame() {
        let (client, mut server) = loopback_pair();
        let mut stream = tunnel(client, 3);
        let writer = std::thread::spawn(move || {
            let frame = encode_frame(AnyTlsCommand::Psh, 9, b"other").expect("psh");
            server.write_all(&frame).expect("frame");
        });
        let mut buf = [0u8; 16];
        let error = stream.read(&mut buf).expect_err("unexpected frame");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        writer.join().expect("writer");
    }

    #[test]
    fn control_frame_is_unexpected() {
        let (client, mut server) = loopback_pair();
        let mut stream = tunnel(client, 3);
        let writer = std::thread::spawn(move || {
            let frame = encode_frame(AnyTlsCommand::HeartRequest, 0, b"").expect("heart");
            server.write_all(&frame).expect("frame");
        });
        let mut buf = [0u8; 16];
        let error = stream.read(&mut buf).expect_err("unexpected control");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        writer.join().expect("writer");
    }

    /// 会话关闭但没有 Fin：不伪造 EOF 成功。
    #[test]
    fn session_close_without_fin_is_error() {
        let (client, server) = loopback_pair();
        let mut stream = tunnel(client, 3);
        drop(server);
        let mut buf = [0u8; 16];
        let error = stream.read(&mut buf).expect_err("closed without fin");
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn psh_larger_than_read_buffer_is_delivered_across_reads() {
        let (client, mut server) = loopback_pair();
        let mut stream = tunnel(client, 4);
        let payload: Vec<u8> = (0..32u8).collect();
        let frame = encode_frame(AnyTlsCommand::Psh, 4, &payload).expect("frame");
        let writer = std::thread::spawn(move || {
            server.write_all(&frame).expect("frame");
        });
        let mut got = Vec::new();
        let mut buf = [0u8; 8];
        while got.len() < payload.len() {
            let read = stream.read(&mut buf).expect("read");
            assert!(read > 0);
            got.extend_from_slice(&buf[..read]);
        }
        assert_eq!(got, payload);
        writer.join().expect("writer");
    }

    #[test]
    fn write_emits_psh_frames() {
        let (client, mut server) = loopback_pair();
        let mut stream = tunnel(client, 5);
        stream.write_all(b"hello").expect("write");
        let mut header = [0u8; 7];
        server.read_exact(&mut header).expect("header");
        assert_eq!(header[0], AnyTlsCommand::Psh.as_u8());
        assert_eq!(
            u32::from_be_bytes([header[1], header[2], header[3], header[4]]),
            5
        );
        assert_eq!(u16::from_be_bytes([header[5], header[6]]), 5);
        let mut payload = [0u8; 5];
        server.read_exact(&mut payload).expect("payload");
        assert_eq!(&payload, b"hello");
    }
}
