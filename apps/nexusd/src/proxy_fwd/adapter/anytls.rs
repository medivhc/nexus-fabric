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
//! UDP（PRODUCT §11.18.1）：`AnytlsUot`。每条 UDP 代理流一个新 session（同样不复用），
//! 其上开一条 UoT v2 connect 模式 stream（crate `client_open_uot_stream`）；数据报按
//! u16 长度前缀成帧放入 `Psh`，读侧把本 stream 的 `Psh` 数据视为字节流再切数据报。

use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use nexus_outbound_anytls::{
    AnyTlsCommand, AnyTlsError, AnyTlsFrame, AnyTlsTarget, CLIENT_IDENT, ClientHandshake,
    DEFAULT_PADDING_SCHEME, MAX_FRAME_DATA_LEN, client_handshake, client_open_stream,
    client_open_uot_stream, decode_frame_bytes, encode_frame, padding_md5_hex,
};
use nexus_proxy_config::OutboundKind;

use super::framing::{BufferedReader, split_u16_datagrams};
use super::tls::{self, Transport};
use super::{
    HandshakeFailure, OutboundDialer, OutboundError, PROTOCOL_HANDSHAKE_TIMEOUT, Protocol,
    TlsFailure, TunnelStream, UdpCapability, UdpMode, UdpStream,
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

    /// 新 session：TLS + 认证 + Settings；`open` 在同一握手超时内开出 stream。
    /// 返回前清空超时（流层自行重设）。
    fn open_session(
        &self,
        target: SocketAddr,
        open: impl FnOnce(&mut Transport, &mut ClientHandshake) -> Result<u32, AnyTlsError>,
    ) -> Result<(Transport, u32), OutboundError> {
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
        let stream_id = open(&mut transport, &mut handshake)
            .map_err(|error| map_anytls_error(error, target))?;

        transport
            .set_read_timeout(None)
            .map_err(handshake_io_error)?;
        transport
            .set_write_timeout(None)
            .map_err(handshake_io_error)?;
        Ok((transport, stream_id))
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
        let (transport, stream_id) = self.open_session(target, |transport, handshake| {
            client_open_stream(transport, handshake, &anytls_target(target))
        })?;
        Ok(Box::new(AnytlsTunnelStream {
            reader: BufferedReader::new(transport),
            stream_id,
            pending: Vec::new(),
            finished: false,
        }))
    }

    fn udp_capability(&self) -> UdpCapability {
        UdpCapability::Supported(UdpMode::AnytlsUot {
            server: self.server,
        })
    }

    fn open_udp(&self, target: SocketAddr) -> Result<Box<dyn UdpStream>, OutboundError> {
        let (transport, stream_id) = self.open_session(target, |transport, handshake| {
            client_open_uot_stream(transport, handshake, &anytls_target(target))
        })?;
        Ok(Box::new(AnytlsUdpStream {
            reader: BufferedReader::new(transport),
            stream_id,
            uot: Vec::new(),
            finished: false,
        }))
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
            let frame = next_frame(&mut self.reader)?;
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

/// 从缓冲区解一帧；缓冲不足时继续读（超时原样返回，半帧保留）。EOF 视为会话中断。
fn next_frame(reader: &mut BufferedReader<Transport>) -> io::Result<AnyTlsFrame> {
    loop {
        match decode_frame_bytes(reader.buffered()) {
            Ok((frame, consumed)) => {
                reader.consume(consumed);
                return Ok(frame);
            }
            Err(_) => {
                if reader.fill()? == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "anytls session closed before Fin",
                    ));
                }
            }
        }
    }
}

/// AnyTLS UoT 代理流：本 stream 的 `Psh` 数据构成 UoT 字节流（数据报可跨帧）。
struct AnytlsUdpStream {
    reader: BufferedReader<Transport>,
    stream_id: u32,
    /// 尚未切出完整数据报的 UoT 字节。
    uot: Vec<u8>,
    /// 已发出或收到 `Fin`。
    finished: bool,
}

impl UdpStream for AnytlsUdpStream {
    fn established(&self) -> bool {
        // `open_udp` 返回前已收到无错误文本的 SynAck。
        true
    }

    fn send_datagram(&mut self, datagram: &[u8]) -> io::Result<()> {
        let len = u16::try_from(datagram.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "anytls uot datagram"))?;
        let mut framed = Vec::with_capacity(2 + datagram.len());
        framed.extend_from_slice(&len.to_be_bytes());
        framed.extend_from_slice(datagram);
        let transport = self.reader.get_mut();
        // UoT 是字节流：超过单帧上限的数据报拆成多个 `Psh`。
        for chunk in framed.chunks(MAX_FRAME_DATA_LEN) {
            let frame = encode_frame(AnyTlsCommand::Psh, self.stream_id, chunk)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "anytls frame encode"))?;
            transport.write_all(&frame)?;
        }
        transport.flush()
    }

    fn recv_datagrams(&mut self) -> io::Result<Option<Vec<Vec<u8>>>> {
        if self.finished {
            return Ok(None);
        }
        loop {
            let (datagrams, used) = split_u16_datagrams(&self.uot);
            if !datagrams.is_empty() {
                self.uot.drain(..used);
                return Ok(Some(datagrams));
            }
            let frame = next_frame(&mut self.reader)?;
            match frame.cmd {
                AnyTlsCommand::Waste => {}
                AnyTlsCommand::Psh if frame.stream_id == self.stream_id => {
                    self.uot.extend_from_slice(&frame.data);
                }
                AnyTlsCommand::Fin if frame.stream_id == self.stream_id => {
                    self.finished = true;
                    return Ok(None);
                }
                other => return Err(frame_error(other, frame.stream_id)),
            }
        }
    }

    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        self.reader.get_mut().set_read_timeout(timeout)
    }

    fn set_write_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        self.reader.get_mut().set_write_timeout(timeout)
    }

    fn shutdown(&mut self) -> io::Result<()> {
        if self.finished {
            return self.reader.get_mut().shutdown_write();
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

    // ---- UDP（PRODUCT §11.18.1；test review r3 的 T10 / T11 / T12） ----

    fn uot(client: std::net::TcpStream, stream_id: u32) -> AnytlsUdpStream {
        client
            .set_read_timeout(Some(Duration::from_millis(100)))
            .expect("timeout");
        AnytlsUdpStream {
            reader: BufferedReader::new(Transport::Plain(client)),
            stream_id,
            uot: Vec::new(),
            finished: false,
        }
    }

    fn recv_until(stream: &mut AnytlsUdpStream) -> io::Result<Option<Vec<Vec<u8>>>> {
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            match stream.recv_datagrams() {
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    assert!(std::time::Instant::now() < deadline, "recv deadline");
                }
                other => return other,
            }
        }
    }

    fn frame(cmd: AnyTlsCommand, stream_id: u32, data: &[u8]) -> Vec<u8> {
        encode_frame(cmd, stream_id, data).expect("frame")
    }

    #[test]
    fn uot_reader_takes_several_datagrams_per_psh_and_skips_waste() {
        let (client, mut server) = loopback_pair();
        let mut stream = uot(client, 1);
        server
            .write_all(
                &[
                    frame(AnyTlsCommand::Waste, 0, &[0xEE; 4]),
                    frame(AnyTlsCommand::Psh, 1, &[0, 1, b'a', 0, 2, b'b', b'c']),
                ]
                .concat(),
            )
            .expect("write");
        assert_eq!(
            recv_until(&mut stream).expect("recv"),
            Some(vec![b"a".to_vec(), b"bc".to_vec()])
        );
    }

    #[test]
    fn uot_reader_joins_a_datagram_split_across_psh_frames_then_fin_closes() {
        let (client, mut server) = loopback_pair();
        let mut stream = uot(client, 1);
        let writer = std::thread::spawn(move || {
            server
                .write_all(&frame(AnyTlsCommand::Psh, 1, &[0, 3, b'x']))
                .expect("first");
            std::thread::sleep(Duration::from_millis(150));
            server
                .write_all(
                    &[
                        frame(AnyTlsCommand::Psh, 1, b"yz"),
                        frame(AnyTlsCommand::Fin, 1, &[]),
                    ]
                    .concat(),
                )
                .expect("rest");
            server
        });
        assert_eq!(
            recv_until(&mut stream).expect("recv"),
            Some(vec![b"xyz".to_vec()])
        );
        assert_eq!(recv_until(&mut stream).expect("fin"), None);
        assert_eq!(recv_until(&mut stream).expect("after fin"), None);
        drop(writer.join().expect("writer"));
    }

    #[test]
    fn uot_reader_rejects_another_streams_data() {
        let (client, mut server) = loopback_pair();
        let mut stream = uot(client, 1);
        server
            .write_all(&frame(AnyTlsCommand::Psh, 2, &[0, 1, b'a']))
            .expect("write");
        let error = recv_until(&mut stream).expect_err("wrong stream");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    /// 65507 字节（最大 IPv4 UDP 载荷）在一帧内；65535 字节的数据报拆成两帧，对端按字节流
    /// 重组。
    #[test]
    fn uot_large_datagrams_round_trip_and_split_over_the_frame_limit() {
        let (client, mut server) = loopback_pair();
        let mut stream = uot(client, 1);
        let small: Vec<u8> = (0..65_507u32).map(|i| (i % 251) as u8).collect();
        let large: Vec<u8> = (0..65_535u32).map(|i| (i % 241) as u8).collect();
        let echo = std::thread::spawn(move || {
            let mut uot_bytes = Vec::new();
            let mut frames = 0;
            while uot_bytes.len() < (2 + 65_507) + (2 + 65_535) {
                let frame = nexus_outbound_anytls::read_frame(&mut server).expect("frame");
                assert_eq!((frame.cmd, frame.stream_id), (AnyTlsCommand::Psh, 1));
                uot_bytes.extend_from_slice(&frame.data);
                frames += 1;
            }
            for chunk in uot_bytes.chunks(MAX_FRAME_DATA_LEN) {
                server
                    .write_all(&frame(AnyTlsCommand::Psh, 1, chunk))
                    .expect("echo");
            }
            (frames, server)
        });
        stream.send_datagram(&small).expect("small");
        stream.send_datagram(&large).expect("large");
        let mut got = Vec::new();
        while got.len() < 2 {
            got.extend(recv_until(&mut stream).expect("recv").expect("open"));
        }
        assert_eq!(got, vec![small, large]);
        let (frames, _server) = echo.join().expect("echo");
        assert_eq!(frames, 3, "65507 B in one frame, 65535 B in two");
    }

    const UOT_PASSWORD: &str = "uot-test-password";

    /// 本地 AnyTLS UoT 节点：每条 TLS 会话计数；`reject` 时 SynAck 带错误文本。
    fn spawn_uot_node(
        reject: Option<&'static str>,
    ) -> (SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let identity = nexus_outbound_anytls::generate_loopback_identity().expect("identity");
        let config =
            Arc::new(nexus_outbound_anytls::server_config(&identity).expect("server config"));
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let sessions = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&sessions);
        std::thread::spawn(move || {
            for sock in listener.incoming().flatten() {
                let (config, counter) = (Arc::clone(&config), Arc::clone(&counter));
                std::thread::spawn(move || {
                    let conn = rustls::ServerConnection::new(config).expect("conn");
                    let mut tls = rustls::StreamOwned::new(conn, sock);
                    if nexus_outbound_anytls::server_handshake(
                        &mut tls,
                        UOT_PASSWORD,
                        DEFAULT_PADDING_SCHEME,
                    )
                    .is_err()
                    {
                        return;
                    }
                    counter.fetch_add(1, Ordering::SeqCst);
                    let mut pushes = 0;
                    while let Ok(frame) = nexus_outbound_anytls::read_frame(&mut tls) {
                        if frame.cmd != AnyTlsCommand::Psh {
                            continue;
                        }
                        pushes += 1;
                        let reply = match pushes {
                            1 => continue,
                            2 => {
                                let reason = reject.unwrap_or("").as_bytes();
                                frame_bytes(AnyTlsCommand::SynAck, frame.stream_id, reason)
                            }
                            _ => frame_bytes(AnyTlsCommand::Psh, frame.stream_id, &frame.data),
                        };
                        if tls.write_all(&reply).is_err() {
                            return;
                        }
                    }
                });
            }
        });
        (addr, sessions)
    }

    fn frame_bytes(cmd: AnyTlsCommand, stream_id: u32, data: &[u8]) -> Vec<u8> {
        encode_frame(cmd, stream_id, data).expect("frame")
    }

    fn uot_dialer(server: SocketAddr) -> AnytlsDialer {
        AnytlsDialer::new(
            "a".to_string(),
            server,
            "localhost".to_string(),
            UOT_PASSWORD.to_string(),
            true,
        )
    }

    #[test]
    fn each_uot_stream_gets_a_new_session_including_sequential_reopens() {
        use std::sync::atomic::Ordering;
        let (server, sessions) = spawn_uot_node(None);
        let dialer = uot_dialer(server);
        assert_eq!(
            dialer.udp_capability(),
            UdpCapability::Supported(UdpMode::AnytlsUot { server })
        );
        let target: SocketAddr = "192.0.2.1:53".parse().expect("target");
        for round in 1..=2 {
            let mut stream = dialer.open_udp(target).expect("open");
            stream.send_datagram(b"ping").expect("send");
            stream
                .set_read_timeout(Some(Duration::from_millis(100)))
                .expect("timeout");
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            let reply = loop {
                match stream.recv_datagrams() {
                    Ok(datagrams) => break datagrams,
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) =>
                    {
                        assert!(std::time::Instant::now() < deadline, "recv deadline");
                    }
                    Err(error) => panic!("recv: {error:?}"),
                }
            };
            assert_eq!(reply, Some(vec![b"ping".to_vec()]));
            stream.shutdown().expect("shutdown");
            assert_eq!(
                sessions.load(Ordering::SeqCst),
                round,
                "one session per stream"
            );
        }
    }

    #[test]
    fn a_rejecting_synack_fails_the_uot_open() {
        let (server, _) = spawn_uot_node(Some("udp not allowed"));
        let error = match uot_dialer(server).open_udp("192.0.2.1:53".parse().expect("target")) {
            Ok(_) => panic!("open must fail"),
            Err(error) => error,
        };
        assert_eq!(error.reason(), "stream_rejected");
    }
}
