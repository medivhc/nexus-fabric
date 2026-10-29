//! VLESS 出站 adapter（spec §3.1）。
//!
//! 握手（冻结）：`connect_timeout(DIAL_TIMEOUT)` → 可选 TLS →
//! `VlessConn::new` + `handshake(VlessRequest{.., command: Tcp})`；**dial 阶段不读响应**。
//!
//! 数据面：`VlessTunnelStream` 用 [`BufferedReader`] **增量**消费响应头
//! `[version(1) | addon_len(1) | addon]`，然后透传字节。禁止使用 crate 的
//! 整体读响应辅助（其 `read_exact` 会把 100ms 中继读超时当错误并丢弃已读字节，
//! spec §3.1 第 4 条）。
//!
//! UDP（PRODUCT §11.18.1）：`VlessOverTcp`。每条 UDP 代理流一条连接（传输同 TCP 拨号），
//! 请求 `command = UDP`、不带 flow（Vision 不用于 UDP）；响应头同样惰性增量消费，之后
//! 数据报按 u16 大端长度前缀成帧。

use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use nexus_outbound_vless::{
    VLESS_VERSION, VlessCommand, VlessConn, VlessError, VlessFlow, VlessRequest, VlessTarget,
    VlessUuid, encode_udp_datagram,
};
use nexus_proxy_config::OutboundKind;

use super::framing::{BufferedReader, split_u16_datagrams};
use super::tls::{self, Transport};
use super::{
    HandshakeFailure, OutboundDialer, OutboundError, Protocol, TlsFailure, TunnelStream,
    UdpCapability, UdpMode, UdpStream,
};

/// VLESS 出站 dialer（一个配置出站一个实例；可被多流并发调用）。
pub(super) struct VlessDialer {
    tag: String,
    server: SocketAddr,
    /// TLS SNI（`servername` 或 locator host）。
    sni: String,
    uuid: VlessUuid,
    flow: VlessFlow,
    /// 是否启用外层 TLS（`tls: true`）。
    use_tls: bool,
    skip_cert_verify: bool,
    /// 惰性构造一次 TLS 配置（避免每流重复加载系统信任根）。
    client_config: OnceLock<Result<Arc<rustls::ClientConfig>, TlsFailure>>,
}

impl VlessDialer {
    pub(super) fn new(
        tag: String,
        server: SocketAddr,
        sni: String,
        uuid: VlessUuid,
        flow: VlessFlow,
        use_tls: bool,
        skip_cert_verify: bool,
    ) -> Self {
        Self {
            tag,
            server,
            sni,
            uuid,
            flow,
            use_tls,
            skip_cert_verify,
            client_config: OnceLock::new(),
        }
    }

    fn tls_config(&self) -> Result<Arc<rustls::ClientConfig>, TlsFailure> {
        self.client_config
            .get_or_init(|| tls::build_client_config(self.skip_cert_verify, &[]).map(Arc::new))
            .clone()
    }

    /// 建传输（可选 TLS）并写请求头；dial 阶段不读响应。
    fn connect(
        &self,
        command: VlessCommand,
        flow: VlessFlow,
        target: SocketAddr,
    ) -> Result<Transport, OutboundError> {
        let transport = if self.use_tls {
            let config = self.tls_config().map_err(OutboundError::TlsHandshake)?;
            tls::connect_tls(self.server, &self.sni, config)?
        } else {
            tls::connect_plain(self.server)?
        };
        let request = VlessRequest {
            uuid: self.uuid,
            flow,
            command,
            port: target.port(),
            target: Some(vless_target(target)),
        };
        let mut conn = VlessConn::new(transport);
        conn.handshake(&request)
            .map_err(|error| map_vless_error(error, flow))?;
        Ok(conn.into_inner())
    }
}

impl OutboundDialer for VlessDialer {
    fn kind(&self) -> OutboundKind {
        OutboundKind::Vless
    }

    fn tag(&self) -> &str {
        &self.tag
    }

    fn dial_tcp(&self, target: SocketAddr) -> Result<Box<dyn TunnelStream>, OutboundError> {
        let transport = self.connect(VlessCommand::Tcp, self.flow, target)?;
        Ok(Box::new(VlessTunnelStream {
            reader: BufferedReader::new(transport),
            response_pending: true,
        }))
    }

    fn udp_capability(&self) -> UdpCapability {
        UdpCapability::Supported(UdpMode::VlessOverTcp {
            server: self.server,
        })
    }

    fn open_udp(&self, target: SocketAddr) -> Result<Box<dyn UdpStream>, OutboundError> {
        // Vision 只用于 TCP：UDP 请求恒不带 flow（PRODUCT §11.18.1）。
        let transport = self.connect(VlessCommand::Udp, VlessFlow::None, target)?;
        Ok(Box::new(VlessUdpStream {
            reader: BufferedReader::new(transport),
            response_pending: true,
        }))
    }
}

fn vless_target(target: SocketAddr) -> VlessTarget {
    match target.ip() {
        IpAddr::V4(ip) => VlessTarget::Ipv4(ip),
        IpAddr::V6(ip) => VlessTarget::Ipv6(ip),
    }
}

/// VLESS 隧道流：响应头惰性 + 增量解析，之后双向透传。
struct VlessTunnelStream {
    reader: BufferedReader<Transport>,
    /// 响应头是否尚未消费（首次 `read` 时增量解析）。
    response_pending: bool,
}

impl VlessTunnelStream {
    fn ensure_response_header(&mut self) -> io::Result<()> {
        if self.response_pending {
            consume_response_header(&mut self.reader)?;
            self.response_pending = false;
        }
        Ok(())
    }
}

/// 增量消费响应头 `[version | addon_len | addon]`（TCP / UDP 共用）。
///
/// 超时/WouldBlock 原样返回，已读字节保留在缓冲里（下次调用继续）。
fn consume_response_header(reader: &mut BufferedReader<Transport>) -> io::Result<()> {
    if !reader.fill_at_least(2)? {
        return Err(header_error("vless response header truncated"));
    }
    let version = reader.buffered()[0];
    if version != VLESS_VERSION {
        return Err(header_error("vless response version mismatch"));
    }
    let addon_len = reader.buffered()[1] as usize;
    if !reader.fill_at_least(2 + addon_len)? {
        return Err(header_error("vless response addon truncated"));
    }
    reader.consume(2 + addon_len);
    Ok(())
}

/// 响应头解析失败。
///
/// 响应头是 dial 之后惰性读取的，此时 relay 只接受 `io::Error`，§2.6.4 的
/// `ProtocolHandshake` 分类无法回传（spec §3.1 第 4 条与 §2.6.4 的固有张力）。
/// 返回 `InvalidData`，relay 以 RST 关闭流（不伪造 EOF/成功）。
fn header_error(detail: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, detail)
}

impl Read for VlessTunnelStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        self.ensure_response_header()?;
        if self.reader.buffered().is_empty() && self.reader.fill()? == 0 {
            return Ok(0);
        }
        let read = {
            let buffered = self.reader.buffered();
            let read = buffered.len().min(buf.len());
            buf[..read].copy_from_slice(&buffered[..read]);
            read
        };
        self.reader.consume(read);
        Ok(read)
    }
}

impl Write for VlessTunnelStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.reader.get_mut().write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.reader.get_mut().flush()
    }
}

impl TunnelStream for VlessTunnelStream {
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        self.reader.get_mut().set_read_timeout(timeout)
    }

    fn set_write_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        self.reader.get_mut().set_write_timeout(timeout)
    }

    fn shutdown(&mut self) -> io::Result<()> {
        self.reader.get_mut().shutdown_write()
    }
}

/// VLESS UDP 代理流：响应头惰性增量消费，之后按 u16 长度前缀收发数据报。
struct VlessUdpStream {
    reader: BufferedReader<Transport>,
    /// 响应头是否尚未消费（可能晚于已写出的数据报到达）。
    response_pending: bool,
}

impl UdpStream for VlessUdpStream {
    fn send_datagram(&mut self, datagram: &[u8]) -> io::Result<()> {
        let framed = encode_udp_datagram(datagram)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "vless udp datagram"))?;
        let transport = self.reader.get_mut();
        transport.write_all(&framed)?;
        transport.flush()
    }

    fn recv_datagrams(&mut self) -> io::Result<Option<Vec<Vec<u8>>>> {
        if self.response_pending {
            consume_response_header(&mut self.reader)?;
            self.response_pending = false;
        }
        loop {
            let (datagrams, used) = split_u16_datagrams(self.reader.buffered());
            if !datagrams.is_empty() {
                self.reader.consume(used);
                return Ok(Some(datagrams));
            }
            if self.reader.fill()? == 0 {
                if self.reader.buffered().is_empty() {
                    return Ok(None);
                }
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "vless udp datagram truncated",
                ));
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
        self.reader.get_mut().shutdown_write()
    }

    fn established(&self) -> bool {
        !self.response_pending
    }
}

/// `VlessError` → `OutboundError`（spec §2.7 冻结映射）。
fn map_vless_error(error: VlessError, flow: VlessFlow) -> OutboundError {
    match error {
        VlessError::InvalidUuid => OutboundError::Config(super::OutboundConfigError::InvalidUuid),
        VlessError::UnsupportedFlow => {
            OutboundError::Config(super::OutboundConfigError::UnsupportedFlow {
                flow: flow.as_str().to_string(),
            })
        }
        VlessError::VisionRequiresTls => {
            OutboundError::Config(super::OutboundConfigError::VisionRequiresTls)
        }
        VlessError::InvalidCommand { .. }
        | VlessError::InvalidAddressType { .. }
        | VlessError::MissingTarget
        | VlessError::InvalidDomain => {
            OutboundError::Config(super::OutboundConfigError::InvalidRequest {
                detail: "vless request target cannot be encoded",
            })
        }
        VlessError::TruncatedHeader => {
            OutboundError::ProtocolHandshake(HandshakeFailure::Truncated {
                protocol: Protocol::Vless,
            })
        }
        VlessError::InvalidVersion { version } => {
            OutboundError::ProtocolHandshake(HandshakeFailure::VersionMismatch {
                protocol: Protocol::Vless,
                got: version,
            })
        }
        VlessError::InvalidResponse => {
            OutboundError::ProtocolHandshake(HandshakeFailure::ResponseInvalid {
                protocol: Protocol::Vless,
            })
        }
        VlessError::VisionUuidMismatch => {
            OutboundError::ProtocolHandshake(HandshakeFailure::VisionUuidMismatch {
                protocol: Protocol::Vless,
            })
        }
        VlessError::InvalidVisionFrame
        | VlessError::VisionAlreadyEnded
        | VlessError::DatagramTooLarge { .. }
        | VlessError::TruncatedDatagram => {
            OutboundError::ProtocolHandshake(HandshakeFailure::InvalidFrame {
                protocol: Protocol::Vless,
            })
        }
        VlessError::Io => OutboundError::Io {
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

    fn tunnel(client: std::net::TcpStream) -> VlessTunnelStream {
        client
            .set_read_timeout(Some(Duration::from_millis(100)))
            .expect("timeout");
        VlessTunnelStream {
            reader: BufferedReader::new(Transport::Plain(client)),
            response_pending: true,
        }
    }

    /// 模拟中继读循环：超时继续重试，直到拿到数据（最多 2s）。
    fn read_until_data(stream: &mut VlessTunnelStream, buf: &mut [u8]) -> usize {
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

    /// A3 约束 1：响应头跨超时增量消费，不丢已读字节。
    #[test]
    fn response_header_survives_read_timeout_without_losing_bytes() {
        let (client, mut server) = loopback_pair();
        let mut stream = tunnel(client);
        let writer = std::thread::spawn(move || {
            server.write_all(&[VLESS_VERSION]).expect("version");
            std::thread::sleep(Duration::from_millis(250));
            server.write_all(&[0x00, b'h', b'i']).expect("rest");
        });

        let mut buf = [0u8; 16];
        let error = stream.read(&mut buf).expect_err("timeout expected");
        assert!(
            matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ),
            "{error:?}"
        );
        // 中继读循环会持续重试；半头保留，超时不是错误。
        let read = read_until_data(&mut stream, &mut buf);
        assert_eq!(&buf[..read], b"hi");
        writer.join().expect("writer");
    }

    #[test]
    fn response_header_skips_addon_bytes() {
        let (client, mut server) = loopback_pair();
        let mut stream = tunnel(client);
        let writer = std::thread::spawn(move || {
            server
                .write_all(&[VLESS_VERSION, 0x02, 0xAA, 0xBB, b'o', b'k'])
                .expect("header");
        });
        let mut buf = [0u8; 8];
        let read = stream.read(&mut buf).expect("read");
        assert_eq!(&buf[..read], b"ok");
        writer.join().expect("writer");
    }

    #[test]
    fn response_version_mismatch_is_invalid_data() {
        let (client, mut server) = loopback_pair();
        let mut stream = tunnel(client);
        let writer = std::thread::spawn(move || {
            server.write_all(&[0x01, 0x00]).expect("header");
        });
        let mut buf = [0u8; 8];
        let error = stream.read(&mut buf).expect_err("version mismatch");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        writer.join().expect("writer");
    }

    #[test]
    fn truncated_response_header_on_eof_is_reported() {
        let (client, server) = loopback_pair();
        let mut stream = tunnel(client);
        drop(server);
        let mut buf = [0u8; 8];
        let error = stream.read(&mut buf).expect_err("truncated");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    // ---- UDP（PRODUCT §11.18.1；test review r3 的 T8 / T9 / T12） ----

    fn udp_stream(client: std::net::TcpStream) -> VlessUdpStream {
        client
            .set_read_timeout(Some(Duration::from_millis(100)))
            .expect("timeout");
        VlessUdpStream {
            reader: BufferedReader::new(Transport::Plain(client)),
            response_pending: true,
        }
    }

    /// 模拟流 worker：超时继续，直到拿到数据报或流结束（最多 2s）。
    fn recv_until(stream: &mut VlessUdpStream) -> io::Result<Option<Vec<Vec<u8>>>> {
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

    #[test]
    fn udp_header_and_datagram_split_across_reads() {
        let (client, mut server) = loopback_pair();
        let mut stream = udp_stream(client);
        let writer = std::thread::spawn(move || {
            for chunk in [&[VLESS_VERSION][..], &[0x00, 0x00, 0x03, b'a'], b"bc"] {
                server.write_all(chunk).expect("chunk");
                std::thread::sleep(Duration::from_millis(150));
            }
            server
        });
        assert_eq!(
            recv_until(&mut stream).expect("recv"),
            Some(vec![b"abc".to_vec()])
        );
        drop(writer.join().expect("writer"));
        assert_eq!(recv_until(&mut stream).expect("eof"), None);
    }

    #[test]
    fn udp_header_addon_and_several_datagrams_in_one_read() {
        let (client, mut server) = loopback_pair();
        let mut stream = udp_stream(client);
        server
            .write_all(&[
                VLESS_VERSION,
                0x02,
                0xAA,
                0xBB,
                0,
                1,
                b'x',
                0,
                2,
                b'y',
                b'z',
                0,
                0,
            ])
            .expect("write");
        assert_eq!(
            recv_until(&mut stream).expect("recv"),
            Some(vec![b"x".to_vec(), b"yz".to_vec(), Vec::new()])
        );
    }

    #[test]
    fn udp_datagram_truncated_by_eof_is_an_error() {
        let (client, mut server) = loopback_pair();
        let mut stream = udp_stream(client);
        server
            .write_all(&[VLESS_VERSION, 0x00, 0x00, 0x05, b'a'])
            .expect("write");
        drop(server);
        let error = recv_until(&mut stream).expect_err("truncated");
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn udp_datagrams_written_before_the_response_header_arrives() {
        let (client, mut server) = loopback_pair();
        let mut stream = udp_stream(client);
        stream.send_datagram(b"hello").expect("send");
        let mut got = [0u8; 7];
        server.read_exact(&mut got).expect("read");
        assert_eq!(&got, &[0, 5, b'h', b'e', b'l', b'l', b'o']);
        server
            .write_all(&[VLESS_VERSION, 0x00, 0x00, 0x02, b'o', b'k'])
            .expect("reply");
        assert_eq!(
            recv_until(&mut stream).expect("recv"),
            Some(vec![b"ok".to_vec()])
        );
    }

    #[test]
    fn udp_largest_ipv4_datagram_round_trips() {
        let (client, mut server) = loopback_pair();
        let mut stream = udp_stream(client);
        let payload: Vec<u8> = (0..65_507u32).map(|i| (i % 251) as u8).collect();
        let echo = std::thread::spawn(move || {
            let mut framed = vec![0u8; 2 + 65_507];
            server.read_exact(&mut framed).expect("read");
            server.write_all(&[VLESS_VERSION, 0x00]).expect("header");
            server.write_all(&framed).expect("echo");
            server
        });
        stream.send_datagram(&payload).expect("send");
        assert_eq!(recv_until(&mut stream).expect("recv"), Some(vec![payload]));
        drop(echo.join().expect("echo"));
    }

    fn dialer(server: SocketAddr, flow: VlessFlow, use_tls: bool) -> VlessDialer {
        VlessDialer::new(
            "v".to_string(),
            server,
            "localhost".to_string(),
            VlessUuid::parse("11111111-2222-3333-4444-555555555555").expect("uuid"),
            flow,
            use_tls,
            true,
        )
    }

    fn expected_udp_request(target: SocketAddr) -> Vec<u8> {
        nexus_outbound_vless::encode_request(&VlessRequest {
            uuid: VlessUuid::parse("11111111-2222-3333-4444-555555555555").expect("uuid"),
            flow: VlessFlow::None,
            command: VlessCommand::Udp,
            port: target.port(),
            target: Some(vless_target(target)),
        })
        .expect("encode")
    }

    #[test]
    fn udp_request_bytes_are_exact() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let server = listener.local_addr().expect("addr");
        let target: SocketAddr = "192.0.2.1:53".parse().expect("target");
        let expected = expected_udp_request(target);
        let len = expected.len();
        let peer = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().expect("accept");
            let mut got = vec![0u8; len];
            sock.read_exact(&mut got).expect("request");
            got
        });
        assert_eq!(
            dialer(server, VlessFlow::None, false).udp_capability(),
            UdpCapability::Supported(UdpMode::VlessOverTcp { server })
        );
        let _stream = dialer(server, VlessFlow::None, false)
            .open_udp(target)
            .expect("open");
        assert_eq!(peer.join().expect("peer"), expected);
    }

    /// Vision 出站（`tls: true`）的 UDP：照样走 TLS，请求不带 flow，数据报可往返。
    #[test]
    fn vision_outbound_udp_runs_over_tls_without_flow() {
        let identity = nexus_outbound_trojan::generate_loopback_identity().expect("identity");
        let config =
            Arc::new(nexus_outbound_trojan::server_config(&identity).expect("server config"));
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let server = listener.local_addr().expect("addr");
        let target: SocketAddr = "192.0.2.1:53".parse().expect("target");
        let expected = expected_udp_request(target);
        let len = expected.len();
        let peer = std::thread::spawn(move || {
            let (sock, _) = listener.accept().expect("accept");
            let conn = rustls::ServerConnection::new(config).expect("conn");
            let mut tls = rustls::StreamOwned::new(conn, sock);
            let mut got = vec![0u8; len + 4];
            tls.read_exact(&mut got).expect("request + datagram");
            tls.write_all(&[VLESS_VERSION, 0x00, 0x00, 0x02, b'o', b'k'])
                .expect("reply");
            tls.flush().expect("flush");
            std::thread::sleep(Duration::from_millis(300));
            got
        });
        let mut stream = dialer(server, VlessFlow::XtlsRprxVision, true)
            .open_udp(target)
            .expect("open over TLS");
        stream.send_datagram(b"hi").expect("send");
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
        assert_eq!(reply, Some(vec![b"ok".to_vec()]));
        let got = peer.join().expect("peer");
        assert_eq!(&got[..len], expected.as_slice());
        assert_eq!(&got[len..], &[0, 2, b'h', b'i']);
    }
}
