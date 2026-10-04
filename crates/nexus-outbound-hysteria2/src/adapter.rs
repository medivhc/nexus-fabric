//! `OutboundAdapter` 实现（`kind = "hysteria2"`）。
//!
//! 领域中立接缝：只暴露出站标识与离线交接语义；真实建连由
//! [`Hysteria2Adapter::connect`]（阻塞：QUIC 握手 + H3 认证）完成，
//! 由 Composition Root 按需调用。

use nexus_connectivity::{ConnectivityError, OutboundAdapter, OutboundHandoff};

use super::client::Hysteria2Client;
use super::config::Hysteria2Target;
use super::Hysteria2Error;

/// Hysteria2 出站 adapter（`OutboundAdapter` 实现，`kind = "hysteria2"`）。
pub struct Hysteria2Adapter {
    tag: String,
    locator: String,
    target: Hysteria2Target,
}

impl Hysteria2Adapter {
    /// 构造 adapter。
    #[must_use]
    pub fn new(tag: impl Into<String>, target: Hysteria2Target) -> Self {
        let locator = target.locator();
        Self {
            tag: tag.into(),
            locator,
            target,
        }
    }

    /// 配置的目标（出站参数）。
    #[must_use]
    pub fn target(&self) -> &Hysteria2Target {
        &self.target
    }

    /// 配置的服务端 locator（`server:port`）。
    #[must_use]
    pub fn locator(&self) -> &str {
        &self.locator
    }

    /// 真实建连（阻塞）：QUIC 握手 + 最小 HTTP/3 认证，返回已认证客户端。
    ///
    /// # Errors
    ///
    /// 握手/认证失败 → [`Hysteria2Error`]。
    pub fn connect(&self) -> Result<Hysteria2Client, Hysteria2Error> {
        Hysteria2Client::connect(&self.target)
    }
}

impl OutboundAdapter for Hysteria2Adapter {
    fn outbound_kind(&self) -> &'static str {
        "hysteria2"
    }

    fn tag(&self) -> &str {
        &self.tag
    }

    fn handoff(&self, locator: &str) -> Result<OutboundHandoff, ConnectivityError> {
        Ok(OutboundHandoff {
            kind: self.outbound_kind().to_string(),
            tag: self.tag.clone(),
            locator: locator.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_server::TestServer;
    use crate::tls::CertVerify;
    use std::time::Duration;

    fn test_target(server: &TestServer) -> Hysteria2Target {
        let mut t = Hysteria2Target::new("127.0.0.1", server.addr.port(), "correct-password");
        t.sni = Some("localhost".to_string());
        t.verify = CertVerify::PinSha256(server.pin_sha256);
        t
    }

    #[test]
    fn adapter_kind_and_handoff() {
        let target = Hysteria2Target::new("example.com", 443, "pw");
        let adapter = Hysteria2Adapter::new("hy2-tag", target);
        assert_eq!(adapter.outbound_kind(), "hysteria2");
        assert_eq!(adapter.tag(), "hy2-tag");
        let h = adapter.handoff("example.com:443").unwrap();
        assert_eq!(h.kind, "hysteria2");
        assert_eq!(h.tag, "hy2-tag");
        assert_eq!(h.locator, "example.com:443");
    }

    #[test]
    fn loopback_connect_and_auth() {
        let server = TestServer::spawn("correct-password", true).unwrap();
        let adapter = Hysteria2Adapter::new("hy2", test_target(&server));
        let client = adapter.connect().unwrap();
        assert!(client.udp_enabled());
    }

    #[test]
    fn loopback_wrong_password_rejected() {
        let server = TestServer::spawn("correct-password", true).unwrap();
        let mut target = test_target(&server);
        target.password = "wrong-password".to_string();
        let adapter = Hysteria2Adapter::new("hy2", target);
        assert!(matches!(
            adapter.connect(),
            Err(Hysteria2Error::AuthFailed)
        ));
    }

    #[test]
    fn loopback_udp_disabled_by_server() {
        let server = TestServer::spawn("correct-password", false).unwrap();
        let adapter = Hysteria2Adapter::new("hy2", test_target(&server));
        let mut client = adapter.connect().unwrap();
        assert!(!client.udp_enabled());
        assert_eq!(
            client.send_udp(0, "8.8.8.8:53", b"ping"),
            Err(Hysteria2Error::UdpDisabled)
        );
    }

    #[test]
    fn loopback_tcp_echo() {
        let server = TestServer::spawn("correct-password", true).unwrap();
        let adapter = Hysteria2Adapter::new("hy2", test_target(&server));
        let mut client = adapter.connect().unwrap();
        // fast-open=true（默认）：open_tcp 不等 TCPResponse 即返回。
        let stream = client.open_tcp("example.com:80").unwrap();
        client.stream_write(stream, b"hello").unwrap();
        let mut buf = [0u8; 64];
        let n = client
            .stream_read(stream, &mut buf, Duration::from_secs(5))
            .unwrap();
        // 读侧剥离 TCPResponse 后拿到回显。
        assert_eq!(&buf[..n], b"hello");
        client.stream_write(stream, b"world").unwrap();
        let n = client
            .stream_read(stream, &mut buf, Duration::from_secs(5))
            .unwrap();
        assert_eq!(&buf[..n], b"world");
        client.stream_finish(stream);
    }

    #[test]
    fn loopback_tcp_stream_ids_step_by_4() {
        let server = TestServer::spawn("correct-password", true).unwrap();
        let adapter = Hysteria2Adapter::new("hy2", test_target(&server));
        let mut client = adapter.connect().unwrap();
        // stream 0 = 认证；代理 stream 从 4 起、步进 4（文档 §2.2(1)）。
        let s1 = client.open_tcp("a:1").unwrap();
        let s2 = client.open_tcp("b:2").unwrap();
        assert_eq!(s1.index(), 1); // id 4
        assert_eq!(s2.index(), 2); // id 8
        client.stream_finish(s1);
        client.stream_finish(s2);
    }

    #[test]
    fn loopback_udp_echo() {
        let server = TestServer::spawn("correct-password", true).unwrap();
        let adapter = Hysteria2Adapter::new("hy2", test_target(&server));
        let mut client = adapter.connect().unwrap();
        let session = client.alloc_udp_session();
        assert_eq!(session, 0);
        let session2 = client.alloc_udp_session();
        assert_eq!(session2, 1);
        client.send_udp(session, "8.8.8.8:53", b"dns-query").unwrap();
        let msg = client.recv_udp(Duration::from_secs(5)).unwrap();
        assert_eq!(msg.session_id, session);
        assert_eq!(msg.target, "8.8.8.8:53");
        assert_eq!(msg.payload, b"dns-query");
        assert_eq!(msg.frag_id, 0);
        assert_eq!(msg.frag_count, 1);
    }

    #[test]
    fn loopback_udp_too_large_rejected() {
        let server = TestServer::spawn("correct-password", true).unwrap();
        let adapter = Hysteria2Adapter::new("hy2", test_target(&server));
        let mut client = adapter.connect().unwrap();
        let big = vec![0u8; 5000];
        assert!(matches!(
            client.send_udp(0, "8.8.8.8:53", &big),
            Err(Hysteria2Error::DatagramTooLarge { .. })
        ));
    }
}
