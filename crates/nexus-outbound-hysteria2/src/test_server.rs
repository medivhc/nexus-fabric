//! 测试用最小 Hysteria2 server（**仅测试**，非产品代码）。
//!
//! 实现 client 测试所需的最小行为：
//!
//! 1. rcgen 自签证书（CN/SAN = localhost），QUIC 监听 127.0.0.1:0；
//! 2. 接受连接后：读单向控制流的空 SETTINGS（内容不严格校验）、读 stream 0
//!    的 HEADERS 认证请求、校验 `hysteria-auth`；
//! 3. 密码正确 → 回 `:status: 233` + `hysteria-udp` + `hysteria-cc-rx: 0`；
//!    错误 → 回 `:status: 403` 并关闭连接；
//! 4. 之后把 bidi stream 当 TCP 处理（读 `TCPRequest` → 回 `TCPResponse OK`
//!    → 回显），把 DATAGRAM 当 UDP 处理（解码 `UDPMessage` → 原样回显）。
//!    目标为 [`SINK_TARGET`] 的 stream 改作吸收端：读 8 字节大端长度 `L`，
//!    吸收 `L` 字节后回 8 字节大端实收字节数（上行吞吐测试用，无下行数据）。
//!    crate 内测试另有四个目标：`banner.test:1`（TCPResponse 与 `banner` 同批
//!    写出后 FIN）、`close.test:1`（TCPResponse + `last words` 后立即关闭连接）、
//!    `fin.test:1`（不回 TCPResponse 直接 FIN）、`reject.test:1`（拒绝，消息
//!    `denied`）。
//!
//! 不实现：完整 HTTP/3（无 QPACK 动态表、无 server SETTINGS）、拥塞协商的
//! 实际限速、分片重组（测试只发不分片的包）。

use std::net::SocketAddr;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use quinn_proto::{Connection, ConnectionHandle, Dir, StreamId};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

use super::Hysteria2Error;
use super::auth;
use super::driver::{self, Driver};
use super::frames::{TcpResponse, UdpMessage};
use super::qpack;
use super::tls;

/// 让测试 server 把 TCP stream 当吸收端的目标地址（见模块文档第 4 条）。
pub const SINK_TARGET: &str = "sink.test:1";

/// 测试 server 句柄。
pub struct TestServer {
    /// 监听地址（127.0.0.1:port）。
    pub addr: SocketAddr,
    /// 服务端证书 DER 的 SHA-256（client 用 `pin-sha256` 校验）。
    pub pin_sha256: [u8; 32],
    handle: Option<JoinHandle<()>>,
}

impl TestServer {
    /// 启动 server（后台线程）：`expected_password` 为期望的 `hysteria-auth`，
    /// `udp_enabled` 控制响应中的 `hysteria-udp`。
    ///
    /// # Errors
    ///
    /// 证书生成 / socket 绑定失败 → [`Hysteria2Error`]。
    pub fn spawn(expected_password: &str, udp_enabled: bool) -> Result<Self, Hysteria2Error> {
        let (cert_der, key_der) = tls::generate_test_identity()?;
        let pin_sha256 = tls::sha256_of(&cert_der);
        // quinn-proto 的 ServerConfig::with_single_cert（随机握手 token key，
        // 与 nexus-fabric 一致），再覆盖 crypto（带 ALPN h3 的 rustls 配置——
        // quinn-proto 要求服务端配置 ALPN，否则以 no_application_protocol
        // 拒绝客户端）与传输参数。
        let mut sc = quinn_proto::ServerConfig::with_single_cert(
            vec![CertificateDer::from(cert_der.clone())],
            PrivatePkcs8KeyDer::from(key_der.clone()).into(),
        )
        .map_err(|_| Hysteria2Error::Tls)?;
        sc.crypto = Arc::new(tls::build_quic_server_config(&cert_der, &key_der)?);
        sc.transport = Arc::new(driver::hysteria_transport_config());
        let server_config = Arc::new(sc);

        let driver = Driver::new(Some(server_config.clone()), None)?;
        let port = driver.local_addr()?.port();
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let expected = expected_password.to_string();

        let handle = thread::Builder::new()
            .name("hy2-test-server".to_string())
            .spawn(move || {
                run_server(driver, server_config, &expected, udp_enabled);
            })
            .map_err(|e| Hysteria2Error::Io(e.to_string()))?;
        Ok(Self {
            addr,
            pin_sha256,
            handle: Some(handle),
        })
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        // server 线程在连接关闭/超时后自行退出；这里 detach 而不 join，
        // 避免测试拆卸被阻塞（线程最多再存活数十秒，端口是按测试独立的）。
        let _ = self.handle.take();
    }
}

/// 读取一条对端发起的 stream（阻塞至 `deadline`）。
fn accept_bidi(
    driver: &mut Driver,
    handle: ConnectionHandle,
    conn: &mut Connection,
    deadline: Instant,
) -> Option<StreamId> {
    while Instant::now() < deadline {
        if let Some(id) = driver.accept_stream(handle, conn, Dir::Bi) {
            return Some(id);
        }
        if conn.is_closed() {
            return None;
        }
        driver.recv_one(handle, conn, Duration::from_millis(50));
    }
    None
}

/// 读取 stream 0 上的 HEADERS 认证请求，返回解码后的头列表。
fn read_auth_request(
    driver: &mut Driver,
    handle: ConnectionHandle,
    conn: &mut Connection,
    id: StreamId,
    deadline: Instant,
) -> Result<Vec<(String, String)>, Hysteria2Error> {
    let frame_type = driver.read_exact(handle, conn, id, 1, deadline)?;
    if frame_type[0] != auth::HEADERS_FRAME_TYPE {
        return Err(Hysteria2Error::InvalidFrame);
    }
    let body_len = driver.read_varint(handle, conn, id, deadline)?;
    let body_len = usize::try_from(body_len).map_err(|_| Hysteria2Error::InvalidFrame)?;
    let body = driver.read_exact(handle, conn, id, body_len, deadline)?;
    qpack::decode_field_section(&body)
}

/// 吸收端：读 8 字节长度，吸收该长度后回实收字节数，再等对端 FIN。
fn sink_stream(
    driver: &mut Driver,
    handle: ConnectionHandle,
    conn: &mut Connection,
    id: StreamId,
    buf: &mut [u8],
) {
    let step = || Instant::now() + Duration::from_secs(5);
    let Ok(len) = driver.read_exact(handle, conn, id, 8, step()) else {
        return;
    };
    let mut len_be = [0u8; 8];
    len_be.copy_from_slice(&len);
    let want = u64::from_be_bytes(len_be);
    let mut got = 0u64;
    while got < want {
        match driver.read_some(handle, conn, id, buf, step()) {
            Ok(0) | Err(_) => break,
            Ok(n) => got += n as u64,
        }
    }
    let _ = driver.write_all(handle, conn, id, &got.to_be_bytes(), step());
    while let Ok(n) = driver.read_some(handle, conn, id, buf, step()) {
        if n == 0 {
            break;
        }
    }
}

fn run_server(
    mut driver: Driver,
    server_config: Arc<quinn_proto::ServerConfig>,
    expected_password: &str,
    udp_enabled: bool,
) {
    let Some((handle, mut conn)) = driver.accept_one(&server_config, Duration::from_secs(30))
    else {
        return;
    };
    let start = Instant::now();
    let end = start + Duration::from_secs(60);

    // 等待握手完成。
    let hs_deadline = Instant::now() + Duration::from_secs(10);
    if !driver
        .drive_until(handle, &mut conn, hs_deadline, |c| !c.is_handshaking())
        .unwrap_or(false)
    {
        return;
    }

    // 读单向控制流的空 SETTINGS（最小 server 不严格校验内容）。
    let ctl_deadline = Instant::now() + Duration::from_secs(10);
    let mut saw_settings = false;
    while Instant::now() < ctl_deadline && !saw_settings {
        if let Some(id) = driver.accept_stream(handle, &mut conn, Dir::Uni) {
            let _ = driver.read_exact(handle, &mut conn, id, 3, ctl_deadline);
            saw_settings = true;
        } else {
            driver.recv_one(handle, &mut conn, Duration::from_millis(50));
        }
    }

    // 读 stream 0 的认证请求。
    let auth_deadline = Instant::now() + Duration::from_secs(10);
    let Some(auth_stream) = accept_bidi(&mut driver, handle, &mut conn, auth_deadline) else {
        return;
    };
    let headers =
        match read_auth_request(&mut driver, handle, &mut conn, auth_stream, auth_deadline) {
            Ok(h) => h,
            Err(_) => return,
        };
    let authed = headers
        .iter()
        .any(|(k, v)| k == "hysteria-auth" && v == expected_password);

    if authed {
        let resp = auth::build_auth_response("233", udp_enabled, "0");
        let _ = driver.write_all(handle, &mut conn, auth_stream, &resp, auth_deadline);
    } else {
        let resp = auth::build_auth_response("403", false, "0");
        let _ = driver.write_all(handle, &mut conn, auth_stream, &resp, auth_deadline);
        driver.finish_stream(handle, &mut conn, auth_stream);
        driver.close(handle, &mut conn, 0, b"auth failed");
        return;
    }
    driver.finish_stream(handle, &mut conn, auth_stream);

    // 主循环：TCP 代理 stream（回显）+ UDP DATAGRAM（回显）。
    let mut buf = [0u8; 8192];
    while Instant::now() < end && !conn.is_closed() {
        // 新的 TCP 代理 stream：读 TCPRequest → 回 TCPResponse OK → 回显。
        if let Some(id) = driver.accept_stream(handle, &mut conn, Dir::Bi) {
            let stream_deadline = Instant::now() + Duration::from_secs(10);
            let req_ok = (|| -> Result<String, Hysteria2Error> {
                let frame_id = driver.read_varint(handle, &mut conn, id, stream_deadline)?;
                if frame_id != super::frames::TCP_REQUEST_ID {
                    return Err(Hysteria2Error::InvalidFrame);
                }
                let addr_len = driver.read_varint(handle, &mut conn, id, stream_deadline)?;
                let addr_len =
                    usize::try_from(addr_len).map_err(|_| Hysteria2Error::InvalidFrame)?;
                let addr = driver.read_exact(handle, &mut conn, id, addr_len, stream_deadline)?;
                let target = String::from_utf8(addr).map_err(|_| Hysteria2Error::InvalidFrame)?;
                let pad_len = driver.read_varint(handle, &mut conn, id, stream_deadline)?;
                let pad_len = usize::try_from(pad_len).map_err(|_| Hysteria2Error::InvalidFrame)?;
                let _ = driver.read_exact(handle, &mut conn, id, pad_len, stream_deadline)?;
                Ok(target)
            })();
            match req_ok {
                Ok(target) if target == "banner.test:1" => {
                    let mut resp = TcpResponse::encode(true, "", &[]);
                    resp.extend_from_slice(b"banner");
                    let _ = driver.write_all(handle, &mut conn, id, &resp, stream_deadline);
                    driver.finish_stream(handle, &mut conn, id);
                }
                Ok(target) if target == "close.test:1" => {
                    let mut resp = TcpResponse::encode(true, "", &[]);
                    resp.extend_from_slice(b"last words");
                    let _ = driver.write_all(handle, &mut conn, id, &resp, stream_deadline);
                    driver.close(handle, &mut conn, 0, b"bye");
                    return;
                }
                Ok(target) if target == "fin.test:1" => {
                    driver.finish_stream(handle, &mut conn, id);
                }
                Ok(target) if target == "reject.test:1" => {
                    let resp = TcpResponse::encode(false, "denied", &[]);
                    let _ = driver.write_all(handle, &mut conn, id, &resp, stream_deadline);
                    driver.finish_stream(handle, &mut conn, id);
                }
                Ok(target) if target == SINK_TARGET => {
                    let resp = TcpResponse::encode(true, "", &[]);
                    let _ = driver.write_all(handle, &mut conn, id, &resp, stream_deadline);
                    sink_stream(&mut driver, handle, &mut conn, id, &mut buf);
                    driver.finish_stream(handle, &mut conn, id);
                }
                Ok(_target) => {
                    let resp = TcpResponse::encode(true, "", &[]);
                    let _ = driver.write_all(handle, &mut conn, id, &resp, stream_deadline);
                    // 回显直到对端 FIN。
                    loop {
                        match driver.read_some(
                            handle,
                            &mut conn,
                            id,
                            &mut buf,
                            Instant::now() + Duration::from_secs(5),
                        ) {
                            Ok(0) => break,
                            Ok(n) => {
                                let _ = driver.write_all(
                                    handle,
                                    &mut conn,
                                    id,
                                    &buf[..n],
                                    Instant::now() + Duration::from_secs(5),
                                );
                            }
                            Err(_) => break,
                        }
                    }
                    driver.finish_stream(handle, &mut conn, id);
                }
                Err(_) => {
                    let resp = TcpResponse::encode(false, "bad request", &[]);
                    let _ = driver.write_all(handle, &mut conn, id, &resp, stream_deadline);
                    driver.finish_stream(handle, &mut conn, id);
                }
            }
            continue;
        }
        // UDP 回显。
        if let Some(d) = driver.recv_datagram(handle, &mut conn, Duration::from_millis(20)) {
            if udp_enabled {
                if let Ok(msg) = UdpMessage::decode(&d) {
                    let echo = UdpMessage {
                        session_id: msg.session_id,
                        packet_id: msg.packet_id,
                        frag_id: 0,
                        frag_count: 1,
                        target: msg.target,
                        payload: msg.payload,
                    };
                    let _ = driver.send_datagram(handle, &mut conn, &echo.encode());
                }
            }
            continue;
        }
        driver.recv_one(handle, &mut conn, Duration::from_millis(20));
    }
    driver.close(handle, &mut conn, 0, b"server done");
}
