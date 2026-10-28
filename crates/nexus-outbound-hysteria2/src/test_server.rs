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
//!    → 按 [`EchoMode`] 回显或 sink 丢弃），把 DATAGRAM 当 UDP 处理
//!    （解码 `UDPMessage` → 原样回显）。[`EchoMode`] 仅测试使用。
//!    crate 内测试另有四个按目标地址选择的 TCP 行为：`banner.test:1`
//!    （TCPResponse 与 `banner` 同批写出后 FIN）、`close.test:1`（TCPResponse +
//!    `last words` 后立即关闭连接）、`fin.test:1`（不回 TCPResponse 直接 FIN）、
//!    `reject.test:1`（拒绝，消息 `denied`）、`hold.test:1`（读走上行并计入
//!    `received_bytes`、永不回 TCPResponse）、`late.test:1`（3 s 后才回 TCPResponse，之后回显）。
//!
//! 不实现：完整 HTTP/3（无 QPACK 动态表、无 server SETTINGS）、拥塞协商的
//! 实际限速、分片重组（测试只发不分片的包）。

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
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

/// TCP 代理 stream 的测试行为（**仅测试**，不进入产品路径）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EchoMode {
    /// 回显收到的载荷（既有行为）。
    Echo,
    /// 只读丢弃载荷（sink；用于上传-only 场景），不写回任何载荷。
    Sink,
}

/// 测试 server 句柄。
pub struct TestServer {
    /// 监听地址（127.0.0.1:port）。
    pub addr: SocketAddr,
    /// 服务端证书 DER 的 SHA-256（client 用 `pin-sha256` 校验）。
    pub pin_sha256: [u8; 32],
    /// TCP stream 收到的载荷字节数（测试诊断用）。
    received_bytes: Arc<AtomicU64>,
    handle: Option<JoinHandle<()>>,
}

impl TestServer {
    /// 启动 server（后台线程）：`expected_password` 为期望的 `hysteria-auth`，
    /// `udp_enabled` 控制响应中的 `hysteria-udp`。TCP stream 回显。
    ///
    /// # Errors
    ///
    /// 证书生成 / socket 绑定失败 → [`Hysteria2Error`]。
    pub fn spawn(expected_password: &str, udp_enabled: bool) -> Result<Self, Hysteria2Error> {
        Self::spawn_with_mode(expected_password, udp_enabled, EchoMode::Echo)
    }

    /// 启动 server 并指定 TCP stream 测试行为（**仅测试**）。
    ///
    /// # Errors
    ///
    /// 证书生成 / socket 绑定失败 → [`Hysteria2Error`]。
    pub fn spawn_with_mode(
        expected_password: &str,
        udp_enabled: bool,
        mode: EchoMode,
    ) -> Result<Self, Hysteria2Error> {
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
        let received_bytes = Arc::new(AtomicU64::new(0));
        let received_for_thread = Arc::clone(&received_bytes);

        let handle = thread::Builder::new()
            .name("hy2-test-server".to_string())
            .spawn(move || {
                run_server(
                    driver,
                    server_config,
                    &expected,
                    udp_enabled,
                    mode,
                    received_for_thread,
                );
            })
            .map_err(|e| Hysteria2Error::Io(e.to_string()))?;
        Ok(Self {
            addr,
            pin_sha256,
            received_bytes,
            handle: Some(handle),
        })
    }

    /// TCP stream 累计收到的载荷字节数（测试诊断用）。
    #[must_use]
    pub fn received_bytes(&self) -> u64 {
        self.received_bytes.load(Ordering::Relaxed)
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

fn run_server(
    mut driver: Driver,
    server_config: Arc<quinn_proto::ServerConfig>,
    expected_password: &str,
    udp_enabled: bool,
    mode: EchoMode,
    received_bytes: Arc<AtomicU64>,
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
                Ok(target) if target == "hold.test:1" => {
                    // 从不回 TCPResponse：持续读走上行直到对端 FIN/出错。
                    while let Ok(n) = driver.read_some(
                        handle,
                        &mut conn,
                        id,
                        &mut buf,
                        Instant::now() + Duration::from_secs(30),
                    ) {
                        if n == 0 {
                            break;
                        }
                        received_bytes.fetch_add(n as u64, Ordering::Relaxed);
                    }
                    driver.finish_stream(handle, &mut conn, id);
                }
                Ok(target) => {
                    if target == "late.test:1" {
                        // 晚 3 s 才回 TCPResponse（期间照常收包），之后按 mode 回显。
                        let late = Instant::now() + Duration::from_secs(3);
                        let _ = driver.drive_until(handle, &mut conn, late, |_| false);
                    }
                    let resp = TcpResponse::encode(true, "", &[]);
                    let _ = driver.write_all(
                        handle,
                        &mut conn,
                        id,
                        &resp,
                        Instant::now() + Duration::from_secs(10),
                    );
                    // Echo 回显 / Sink 只读丢弃，直到对端 FIN。
                    loop {
                        match driver.read_some(
                            handle,
                            &mut conn,
                            id,
                            &mut buf,
                            Instant::now() + Duration::from_secs(5),
                        ) {
                            Ok(0) => break,
                            Ok(n) => match mode {
                                EchoMode::Echo => {
                                    let _ = driver.write_all(
                                        handle,
                                        &mut conn,
                                        id,
                                        &buf[..n],
                                        Instant::now() + Duration::from_secs(5),
                                    );
                                }
                                EchoMode::Sink => {
                                    received_bytes.fetch_add(n as u64, Ordering::Relaxed);
                                }
                            },
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
        if let Some(d) = driver.recv_datagram(handle, &mut conn, Duration::ZERO) {
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
        driver.recv_one(handle, &mut conn, Duration::from_millis(2));
    }
    driver.close(handle, &mut conn, 0, b"server done");
}
