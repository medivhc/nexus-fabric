//! AnyTLS 数据面装配集成测试。
//!
//! 用最小 mock server（TCP listener + rustls TLS + `server_handshake`）验证
//! client 数据面流程与 apps/nexus 中 anytls 出站 arm 的装配顺序一致：
//! TCP 建连 → TLS 握手 → `client_handshake`（auth 一次写 + Settings → 等
//! ServerSettings）→ `client_open_stream`（SYN → 首个 PSH 带 SOCKS5 目标地址 →
//! 等 SYNACK）→ PSH 数据中继 → Fin 关闭。

use nexus_outbound_anytls::{
    AnyTlsCommand, AnyTlsTarget, CLIENT_IDENT, DEFAULT_PADDING_SCHEME, client_config,
    client_handshake, client_open_stream, encode_socks5_addr, generate_loopback_identity,
    padding_md5_hex, read_frame, server_config, server_handshake, write_frame,
};
use rustls::pki_types::ServerName;
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::Duration;

const TEST_PASSWORD: &str = "dataplane-mock-secret";
const READ_TIMEOUT: Duration = Duration::from_secs(10);

/// mock AnyTLS server：TLS accept → `server_handshake` → 循环处理 stream：
/// SYN → 读首个 PSH（目标地址，上报主线程）→ 回 SYNACK → 回显后续 PSH →
/// Fin 则回 Fin；client 关闭连接时结束。
fn spawn_mock_server(
    server_cfg: Arc<rustls::ServerConfig>,
    listener: TcpListener,
    addr_tx: mpsc::Sender<Vec<u8>>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let (sock, _) = listener.accept().expect("mock accept");
        sock.set_read_timeout(Some(READ_TIMEOUT)).expect("timeout");
        let server_conn = rustls::ServerConnection::new(server_cfg).expect("server conn");
        let mut tls = rustls::StreamOwned::new(server_conn, sock);
        server_handshake(&mut tls, TEST_PASSWORD, DEFAULT_PADDING_SCHEME)
            .expect("mock server handshake");
        // client 关闭连接时 read 出错 → while let 结束。
        while let Ok(frame) = read_frame(&mut tls) {
            match frame.cmd {
                AnyTlsCommand::Syn => {
                    let sid = frame.stream_id;
                    let addr_frame = read_frame(&mut tls).expect("mock read addr psh");
                    assert_eq!(addr_frame.cmd, AnyTlsCommand::Psh);
                    assert_eq!(addr_frame.stream_id, sid);
                    addr_tx.send(addr_frame.data).expect("addr report");
                    write_frame(&mut tls, AnyTlsCommand::SynAck, sid, &[]).expect("mock synack");
                }
                AnyTlsCommand::Psh => {
                    // 数据回显。
                    write_frame(&mut tls, AnyTlsCommand::Psh, frame.stream_id, &frame.data)
                        .expect("mock echo");
                }
                AnyTlsCommand::Fin => {
                    write_frame(&mut tls, AnyTlsCommand::Fin, frame.stream_id, &[])
                        .expect("mock fin");
                }
                // Waste/心跳等：mock 忽略。
                _ => {}
            }
        }
    })
}

/// client 数据面流程（与 apps/nexus anytls arm 同顺序）：开 stream →
/// PSH 中继。返回 stream_id。
fn client_open_and_relay(
    tls: &mut rustls::StreamOwned<rustls::ClientConnection, TcpStream>,
    hs: &mut nexus_outbound_anytls::ClientHandshake,
    target: &AnyTlsTarget,
    payload: &[u8],
) -> u32 {
    let stream_id = client_open_stream(tls, hs, target).expect("open stream");
    write_frame(tls, AnyTlsCommand::Psh, stream_id, payload).expect("psh send");
    let echo = read_frame(tls).expect("psh echo");
    assert_eq!(echo.cmd, AnyTlsCommand::Psh);
    assert_eq!(echo.stream_id, stream_id);
    assert_eq!(echo.data, payload);
    stream_id
}

#[test]
fn dataplane_handshake_relay_and_close() {
    let identity = generate_loopback_identity().expect("identity");
    let server_cfg = Arc::new(server_config(&identity).expect("server cfg"));
    let client_cfg = Arc::new(client_config(&identity).expect("client cfg"));

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let (addr_tx, addr_rx) = mpsc::channel();
    let server = spawn_mock_server(server_cfg, listener, addr_tx);

    // ---- client：TCP → TLS（与 arm 同顺序） ----
    let sock = TcpStream::connect(addr).expect("client connect");
    sock.set_read_timeout(Some(READ_TIMEOUT)).expect("timeout");
    let sni = ServerName::try_from("localhost").expect("sni");
    let client_conn = rustls::ClientConnection::new(client_cfg, sni).expect("client conn");
    let mut tls = rustls::StreamOwned::new(client_conn, sock);

    // ---- session 握手：auth 一次写 → Settings → 等 ServerSettings ----
    let md5 = padding_md5_hex(DEFAULT_PADDING_SCHEME);
    let mut hs = client_handshake(&mut tls, TEST_PASSWORD, 0, CLIENT_IDENT, &md5)
        .expect("client session handshake");
    assert_eq!(hs.next_stream_id, 1);

    // ---- stream 1：SYN → PSH(地址) → SYNACK → 数据中继 ----
    let target = AnyTlsTarget::Domain("example.com".to_string(), 80);
    let s1 = client_open_and_relay(&mut tls, &mut hs, &target, b"hello-anytls-dataplane");
    assert_eq!(s1, 1);
    // server 收到的首个 PSH 地址与客户端编码一致。
    let got_addr = addr_rx.recv_timeout(READ_TIMEOUT).expect("addr report");
    assert_eq!(got_addr, encode_socks5_addr(&target).expect("addr encode"));

    // ---- stream 2（同一 session 多路复用）：id 递增，中继独立 ----
    let target2 = AnyTlsTarget::Ipv4([93, 184, 216, 34], 443);
    let s2 = client_open_and_relay(&mut tls, &mut hs, &target2, b"second-stream-payload");
    assert_eq!(s2, 2);
    let got_addr2 = addr_rx.recv_timeout(READ_TIMEOUT).expect("addr report 2");
    assert_eq!(
        got_addr2,
        encode_socks5_addr(&target2).expect("addr encode")
    );

    // ---- Fin 关闭两条 stream ----
    for sid in [s1, s2] {
        write_frame(&mut tls, AnyTlsCommand::Fin, sid, &[]).expect("fin");
        let fin = read_frame(&mut tls).expect("fin ack");
        assert_eq!(fin.cmd, AnyTlsCommand::Fin);
        assert_eq!(fin.stream_id, sid);
    }
    drop(tls);
    server.join().expect("mock server join");
}
