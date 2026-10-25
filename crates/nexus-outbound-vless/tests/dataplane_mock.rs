//! VLESS 数据面装配集成测试。
//!
//! 用最小 mock server（TCP listener；TLS 变体加 rustls 自签证书）验证 client
//! 数据面流程与 apps/nexus 中 vless 出站 arm 的装配顺序一致：TCP 建连 → 可选
//! TLS 握手 → `VlessConn::handshake`（只写请求头：UUID + flow addon + TCP 命令 +
//! 目标地址）→ 消费响应头 → 双向中继。
//!
//! mock server 用 `decode_request` 校验请求头（UUID / flow / 命令 / 目标地址），
//! 回送 `encode_response` 的响应头后回显 payload。VLESS 允许客户端在请求头之后
//! 立即发送载荷（真实服务端会保留 leftover），因此 mock 保留「与请求头同批到达
//! 的字节」作为 payload 首段并逐字节校验：明文 client 真流水线（先发 payload 再读
//! 响应头，与 apps/nexus pump 的时序一致），TLS client 保持严格串行。
//! flow=xtls-rprx-vision 只验证握手 addon 编码（中继仍为普通中继；
//! Vision 传输层 splice 未实现，见 arm 注释）。

use nexus_outbound_vless::{
    VlessCommand, VlessConn, VlessFlow, VlessRequest, VlessResponse, VlessTarget, VlessUuid,
    decode_request, encode_request, encode_response, read_response,
};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::Duration;

const READ_TIMEOUT: Duration = Duration::from_secs(10);
const TEST_UUID: &str = "123e4567-e89b-12d3-a456-426614174000";
const PAYLOAD: &[u8] = b"ping-via-vless-tunnel";

/// mock VLESS server 连接处理：增量读请求头 → `decode_request` 校验 → 上报
/// `(command, port, target)` → 回送响应头 → 保留「与请求头同批到达的流水线字节」
/// 作为 payload 首段，不足部分才继续读 → 校验 payload 后回显。
fn mock_serve_conn<S: Read + Write>(
    mut s: S,
    expected_uuid: VlessUuid,
    expected_flow: VlessFlow,
    report_tx: &mpsc::Sender<(u8, u16, String, usize)>,
) {
    // 增量读到请求头完整（只用公开 API；不假设 TCP 分段）。
    let mut buf = Vec::new();
    let (req, consumed) = loop {
        let mut chunk = [0u8; 256];
        let n = s.read(&mut chunk).expect("mock read request");
        assert!(n > 0, "mock: client closed before request header complete");
        buf.extend_from_slice(&chunk[..n]);
        match decode_request(&buf) {
            Ok((req, consumed)) => break (req, consumed),
            Err(nexus_outbound_vless::VlessError::TruncatedHeader) => continue,
            Err(e) => panic!("mock: bad request header: {e}"),
        }
    };
    assert_eq!(req.uuid, expected_uuid, "mock: uuid mismatch");
    assert_eq!(req.flow, expected_flow, "mock: flow mismatch");
    assert_eq!(req.command, VlessCommand::Tcp, "mock: command");
    let target_label = match req.target.as_ref().expect("mock: target") {
        VlessTarget::Ipv4(ip) => format!("ipv4:{ip}"),
        VlessTarget::Ipv6(ip) => format!("ipv6:{ip}"),
        VlessTarget::Domain(d) => format!("domain:{d}"),
    };
    // 上报「与请求头同批到达的流水线字节数」，让 client 侧可以把
    // 「载荷真的流水线进来了」变成可断言的不变量，而不是时序侥幸。
    let pipelined = buf.len() - consumed;
    report_tx
        .send((req.command.as_u8(), req.port, target_label, pipelined))
        .expect("report");
    // 回送响应头（version 0 + 空 addon）。
    let resp = encode_response(&VlessResponse {
        version: 0,
        addon: Vec::new(),
    });
    s.write_all(&resp).expect("mock write response");
    s.flush().expect("mock flush");
    // 与请求头同批到达的字节是流水线 payload 的首段：必须保留并逐字节校验，
    // 不能像真实缺陷那样丢弃（VLESS 允许客户端在请求头后立即发载荷）。
    let mut payload = buf.split_off(consumed);
    if payload.len() < PAYLOAD.len() {
        let mut rest = vec![0u8; PAYLOAD.len() - payload.len()];
        s.read_exact(&mut rest).expect("mock read payload");
        payload.extend_from_slice(&rest);
    }
    assert_eq!(
        payload.as_slice(),
        PAYLOAD,
        "mock: pipelined payload after request header mismatch (got {} bytes)",
        payload.len()
    );
    s.write_all(&payload).expect("mock write echo");
    s.flush().expect("mock flush echo");
}

/// 起一个 mock server（明文 TCP），返回地址、上报通道与 JoinHandle。
#[allow(clippy::type_complexity)]
fn spawn_mock_plain(
    expected_uuid: VlessUuid,
    expected_flow: VlessFlow,
) -> (
    SocketAddr,
    mpsc::Receiver<(u8, u16, String, usize)>,
    thread::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let (tx, rx) = mpsc::channel();
    let h = thread::spawn(move || {
        let (sock, _) = listener.accept().expect("mock accept");
        sock.set_read_timeout(Some(READ_TIMEOUT)).expect("timeout");
        mock_serve_conn(sock, expected_uuid, expected_flow, &tx);
    });
    (addr, rx, h)
}

/// rcgen 自签证书（SAN=localhost），返回 `(cert_der, key_der_pkcs8)`。
fn test_identity() -> (Vec<u8>, Vec<u8>) {
    let key_pair = rcgen::KeyPair::generate().expect("rcgen key");
    let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("params");
    let cert = params.self_signed(&key_pair).expect("self-signed");
    (cert.der().to_vec(), key_pair.serialize_der())
}

fn ring_provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn server_config(cert_der: &[u8], key_der: &[u8]) -> Arc<rustls::ServerConfig> {
    let cert = rustls::pki_types::CertificateDer::from(cert_der.to_vec());
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(key_der.to_vec());
    let cfg = rustls::ServerConfig::builder_with_provider(ring_provider())
        .with_safe_default_protocol_versions()
        .expect("tls versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert], key.into())
        .expect("server cert");
    Arc::new(cfg)
}

/// 客户端 TLS 配置：把自签证书作为唯一信任根（公钥 pin，不依赖系统根）。
fn client_config_pinned(cert_der: &[u8]) -> Arc<rustls::ClientConfig> {
    let cert = rustls::pki_types::CertificateDer::from(cert_der.to_vec());
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).expect("add root");
    let cfg = rustls::ClientConfig::builder_with_provider(ring_provider())
        .with_safe_default_protocol_versions()
        .expect("tls versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    Arc::new(cfg)
}

/// 起一个 mock server（TLS），返回地址、上报通道与 JoinHandle。
#[allow(clippy::type_complexity)]
fn spawn_mock_tls(
    srv_cfg: Arc<rustls::ServerConfig>,
    expected_uuid: VlessUuid,
    expected_flow: VlessFlow,
) -> (
    SocketAddr,
    mpsc::Receiver<(u8, u16, String, usize)>,
    thread::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let (tx, rx) = mpsc::channel();
    let h = thread::spawn(move || {
        let (sock, _) = listener.accept().expect("mock accept");
        sock.set_read_timeout(Some(READ_TIMEOUT)).expect("timeout");
        let conn = rustls::ServerConnection::new(srv_cfg).expect("server conn");
        let tls = rustls::StreamOwned::new(conn, sock);
        mock_serve_conn(tls, expected_uuid, expected_flow, &tx);
    });
    (addr, rx, h)
}

/// client 数据面流程（与 apps/nexus vless arm 同顺序）：TCP → 请求头 →
/// **流水线发送 payload** → 响应头消费 → 读回显。返回回显字节。
///
/// 与产品 pump 一致：载荷不等响应头就写，服务端必须保留与请求头同批到达的字节。
/// 请求头与载荷合并成一次 `write_all`，让 coalesce 在 loopback 上成为常态
/// （而不是依赖两次 write 恰好在一次 read 里被合并）。
fn client_plain_relay(addr: SocketAddr, req: &VlessRequest) -> Vec<u8> {
    let sock = TcpStream::connect(addr).expect("client connect");
    sock.set_read_timeout(Some(READ_TIMEOUT)).expect("timeout");
    let mut sock = sock;
    let mut first_write = encode_request(req).expect("encode request");
    first_write.extend_from_slice(PAYLOAD);
    sock.write_all(&first_write).expect("write header+payload");
    sock.flush().expect("flush header+payload");
    let resp = read_response(&mut sock).expect("read response");
    assert_eq!(resp.version, 0);
    assert!(resp.addon.is_empty());
    let mut back = vec![0u8; PAYLOAD.len()];
    sock.read_exact(&mut back).expect("read echo");
    back
}

/// client 数据面流程（TLS 变体，与 arm 同顺序；证书 pin 验证）。
fn client_tls_relay(
    addr: SocketAddr,
    cli_cfg: Arc<rustls::ClientConfig>,
    req: &VlessRequest,
) -> Vec<u8> {
    let sock = TcpStream::connect(addr).expect("client connect");
    sock.set_read_timeout(Some(READ_TIMEOUT)).expect("timeout");
    let sni = rustls::pki_types::ServerName::try_from("localhost").expect("sni");
    let conn = rustls::ClientConnection::new(cli_cfg, sni).expect("client conn");
    let tls = rustls::StreamOwned::new(conn, sock);
    let mut vc = VlessConn::new(tls);
    vc.handshake(req).expect("handshake");
    vc.flush().expect("flush");
    let mut tls = vc.into_inner();
    let resp = read_response(&mut tls).expect("read response");
    assert_eq!(resp.version, 0);
    tls.write_all(PAYLOAD).expect("write payload");
    tls.flush().expect("flush payload");
    let mut back = vec![0u8; PAYLOAD.len()];
    tls.read_exact(&mut back).expect("read echo");
    back
}

#[test]
fn dataplane_plain_tcp_handshake_relay() {
    let uuid = VlessUuid::parse(TEST_UUID).expect("uuid");
    let (addr, rx, server) = spawn_mock_plain(uuid, VlessFlow::None);
    let req = VlessRequest {
        uuid,
        flow: VlessFlow::None,
        command: VlessCommand::Tcp,
        port: 8080,
        target: Some(VlessTarget::Ipv4(std::net::Ipv4Addr::new(127, 0, 0, 1))),
    };
    let back = client_plain_relay(addr, &req);
    assert_eq!(back, PAYLOAD, "payload roundtrip");
    drop(req);

    let (cmd, port, target, pipelined) = rx.recv_timeout(READ_TIMEOUT).expect("report");
    assert_eq!(cmd, 0x01, "command = TCP");
    assert_eq!(port, 8080);
    assert_eq!(target, "ipv4:127.0.0.1");
    // 明文 client 单次 write 发送「请求头 + 载荷」：mock 必须真的看到流水线字节，
    // 否则本次加固就退化成「不覆盖 coalesce 时序」。
    assert!(
        pipelined >= PAYLOAD.len(),
        "mock: expected pipelined payload bytes, got {pipelined}"
    );
    server.join().expect("mock server join");
}

#[test]
fn dataplane_tls_handshake_relay() {
    let (cert_der, key_der) = test_identity();
    let srv_cfg = server_config(&cert_der, &key_der);
    let cli_cfg = client_config_pinned(&cert_der);
    let uuid = VlessUuid::parse(TEST_UUID).expect("uuid");
    let (addr, rx, server) = spawn_mock_tls(srv_cfg, uuid, VlessFlow::None);
    let req = VlessRequest {
        uuid,
        flow: VlessFlow::None,
        command: VlessCommand::Tcp,
        port: 443,
        target: Some(VlessTarget::Domain("example.com".to_string())),
    };
    let back = client_tls_relay(addr, cli_cfg, &req);
    assert_eq!(back, PAYLOAD, "payload roundtrip");
    drop(req);

    // TLS client 保持严格串行：请求头之后等响应头，因此没有流水线字节。
    let (cmd, port, target, pipelined) = rx.recv_timeout(READ_TIMEOUT).expect("report");
    assert_eq!(cmd, 0x01, "command = TCP");
    assert_eq!(port, 443);
    assert_eq!(target, "domain:example.com");
    assert_eq!(pipelined, 0, "serial TLS client must not pipeline bytes");
    server.join().expect("mock server join");
}

#[test]
fn dataplane_vision_flow_handshake_addon() {
    // flow=xtls-rprx-vision 的握手 addon 编码（TLS 必需；中继仍为普通中继，
    // Vision 传输层 splice 未实现——见 apps/nexus vless arm 注释）。
    let (cert_der, key_der) = test_identity();
    let srv_cfg = server_config(&cert_der, &key_der);
    let cli_cfg = client_config_pinned(&cert_der);
    let uuid = VlessUuid::parse(TEST_UUID).expect("uuid");
    let (addr, rx, server) = spawn_mock_tls(srv_cfg, uuid, VlessFlow::XtlsRprxVision);
    let req = VlessRequest {
        uuid,
        flow: VlessFlow::XtlsRprxVision,
        command: VlessCommand::Tcp,
        port: 443,
        target: Some(VlessTarget::Ipv6(std::net::Ipv6Addr::LOCALHOST)),
    };
    let back = client_tls_relay(addr, cli_cfg, &req);
    assert_eq!(back, PAYLOAD, "payload roundtrip");
    drop(req);

    let (cmd, port, target, _pipelined) = rx.recv_timeout(READ_TIMEOUT).expect("report");
    assert_eq!(cmd, 0x01, "command = TCP");
    assert_eq!(port, 443);
    assert_eq!(target, "ipv6:::1");
    server.join().expect("mock server join");
}
