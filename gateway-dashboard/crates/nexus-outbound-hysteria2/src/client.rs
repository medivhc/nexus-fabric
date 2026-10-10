//! Hysteria2 客户端：QUIC 建连 → 最小 HTTP/3 认证 → TCP/UDP 代理。
//!
//! 流程（文档 §2.1/§2.2/§2.3）：
//!
//! 1. UDP socket 绑定通配地址，解析服务端地址；
//! 2. QUIC 握手（SNI、ALPN `h3`、禁用 greasing、DATAGRAM、窗口/超时参数见
//!    [`crate::driver`]）；证书校验三选一（[`crate::tls::CertVerify`]）；
//! 3. 建连后在单向流（id 2）发空 SETTINGS，在 stream 0 发 HEADERS 认证请求，
//!    校验响应 `:status == 233`；
//! 4. 认证成功后该连接即为代理连接：TCP 每条连接一条双向 stream（id 从 4
//!    步进 4），UDP 走 QUIC DATAGRAM。
//!
//! fast-open 语义（文档 §5 坑 #7）：`fast-open=true` 时请求帧发出后不等响应
//! 即返回可用；但**读侧始终先剥离 TCPResponse**（`response_pending` 保证）。

use std::collections::HashSet;
use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::time::{Duration, Instant};

use quinn_proto::{ClientConfig, Connection, ConnectionHandle, StreamId};

use super::Hysteria2Error;
use super::auth::{self, AuthResponse, CcRx};
use super::config::{DEFAULT_AUTHORITY, Hysteria2Target};
use super::driver::{self, Driver};
use super::frames::{MAX_UDP_PAYLOAD, TcpRequest, TcpResponse, UdpMessage};
use super::tls;

/// TCP stream 操作的默认超时。
const STREAM_TIMEOUT: Duration = Duration::from_secs(10);
/// TCPRequest 随机 padding 长度（文档未规定具体长度；取 16 字节）。
const TCP_REQUEST_PADDING_LEN: usize = 16;

/// 已认证的 Hysteria2 代理连接。
pub struct Hysteria2Client {
    driver: Driver,
    handle: ConnectionHandle,
    conn: Connection,
    target: Hysteria2Target,
    udp_enabled: bool,
    cc_rx: CcRx,
    next_udp_session: u32,
    next_packet_id: u16,
    /// 读侧尚未剥离 TCPResponse 的 stream（fast-open 下写侧已放行）。
    response_pending: HashSet<StreamId>,
}

impl Hysteria2Client {
    /// 建连并完成认证（阻塞至 `target.handshake_timeout`）。
    ///
    /// # Errors
    ///
    /// 配置非法 / 地址不可解析 / QUIC 握手失败 / 认证失败（`:status != 233`）/
    /// 超时 → [`Hysteria2Error`]。
    pub fn connect(target: &Hysteria2Target) -> Result<Self, Hysteria2Error> {
        target.validate()?;
        let remote = target
            .locator()
            .to_socket_addrs()
            .map_err(|e| Hysteria2Error::InvalidConfig(format!("resolve failed: {e}")))?
            .next()
            .ok_or_else(|| Hysteria2Error::InvalidConfig("no address resolved".to_string()))?;

        let mut driver = Driver::new(None, target.obfs_key())?;
        let quic_crypto = tls::build_quic_client_config(&target.verify)?;
        let mut cc = ClientConfig::new(Arc::new(quic_crypto));
        cc.transport_config(Arc::new(driver::hysteria_transport_config()));

        let sni = target.effective_sni();
        let now = Instant::now();
        let deadline = now + target.handshake_timeout;
        let (handle, mut conn) = driver
            .endpoint_mut()
            .connect(now, cc, remote, &sni)
            .map_err(|e| Hysteria2Error::Quic(format!("connect: {e:?}")))?;

        // QUIC 握手。
        let ok = driver.drive_until(handle, &mut conn, deadline, |c| !c.is_handshaking())?;
        if !ok {
            return Err(Hysteria2Error::Timeout);
        }

        // 空 SETTINGS（单向控制流，client 首个 uni stream id 为 2）。
        let uni = driver.open_uni(handle, &mut conn)?;
        debug_assert_eq!(uni.index(), 0, "first client uni stream must be id 2");
        driver.write_all(handle, &mut conn, uni, &auth::SETTINGS_FRAME, deadline)?;
        // H3 控制流保持打开（不 FIN）。

        // HEADERS 认证请求（stream 0）。
        let bidi0 = driver.open_bi(handle, &mut conn)?;
        debug_assert_eq!(bidi0.index(), 0, "first client bidi stream must be id 0");
        let request =
            auth::build_auth_request(&target.password, target.cc_rx_bps, DEFAULT_AUTHORITY);
        driver.write_all(handle, &mut conn, bidi0, &request, deadline)?;

        // 读响应 HEADERS 帧：1 字节类型 + varint 长度 + QPACK 块。
        let frame_type = driver.read_exact(handle, &mut conn, bidi0, 1, deadline)?;
        let body_len = driver.read_varint(handle, &mut conn, bidi0, deadline)?;
        let body_len = usize::try_from(body_len).map_err(|_| Hysteria2Error::InvalidFrame)?;
        let body = driver.read_exact(handle, &mut conn, bidi0, body_len, deadline)?;
        let mut frame = frame_type;
        super::varint::encode(body_len as u64, &mut frame);
        frame.extend_from_slice(&body);
        let resp: AuthResponse = auth::decode_auth_response(&frame)?;

        Ok(Self {
            driver,
            handle,
            conn,
            target: target.clone(),
            udp_enabled: resp.udp_enabled && target.udp,
            cc_rx: resp.cc_rx,
            next_udp_session: 0,
            next_packet_id: 0,
            response_pending: HashSet::new(),
        })
    }

    /// UDP 是否可用（配置开关与 server 协商的交集）。
    #[must_use]
    pub fn udp_enabled(&self) -> bool {
        self.udp_enabled
    }

    /// 服务端协商的 `Hysteria-CC-RX`。
    #[must_use]
    pub fn cc_rx(&self) -> &CcRx {
        &self.cc_rx
    }

    /// 打开一条 TCP 代理 stream（id 从 4 起、步进 4，由 QUIC 分配）。
    ///
    /// `fast-open=true` 时请求帧发出后即返回；否则等待 `TCPResponse` 的 OK。
    ///
    /// # Errors
    ///
    /// 服务端拒绝（`TCPResponse.status=1`）→ [`Hysteria2Error::TcpRejected`]；
    /// 超时/关闭 → [`Hysteria2Error`]。
    pub fn open_tcp(&mut self, target: &str) -> Result<StreamId, Hysteria2Error> {
        let deadline = Instant::now() + STREAM_TIMEOUT;
        let id = self.driver.open_bi(self.handle, &mut self.conn)?;
        let mut padding = [0u8; TCP_REQUEST_PADDING_LEN];
        {
            use ring::rand::{SecureRandom, SystemRandom};
            SystemRandom::new()
                .fill(&mut padding)
                .map_err(|_| Hysteria2Error::Tls)?;
        }
        let frame = TcpRequest::encode(target, &padding);
        self.driver
            .write_all(self.handle, &mut self.conn, id, &frame, deadline)?;
        if self.target.fast_open {
            // fast-open：写侧已放行；读侧仍需剥离 TCPResponse（见 stream_read）。
            self.response_pending.insert(id);
        } else {
            let resp = self.read_tcp_response(id, deadline)?;
            if !resp.ok {
                return Err(Hysteria2Error::TcpRejected(resp.message));
            }
        }
        Ok(id)
    }

    /// 从代理 stream 首部读取并剥离 `TCPResponse`。
    fn read_tcp_response(
        &mut self,
        id: StreamId,
        deadline: Instant,
    ) -> Result<TcpResponse, Hysteria2Error> {
        let status = self
            .driver
            .read_exact(self.handle, &mut self.conn, id, 1, deadline)?;
        let ok = match status[0] {
            super::frames::TCP_STATUS_OK => true,
            super::frames::TCP_STATUS_ERROR => false,
            _ => return Err(Hysteria2Error::InvalidFrame),
        };
        let msg_len = self
            .driver
            .read_varint(self.handle, &mut self.conn, id, deadline)?;
        let msg_len = usize::try_from(msg_len).map_err(|_| Hysteria2Error::InvalidFrame)?;
        let msg = self
            .driver
            .read_exact(self.handle, &mut self.conn, id, msg_len, deadline)?;
        let message = String::from_utf8(msg).map_err(|_| Hysteria2Error::InvalidFrame)?;
        let pad_len = self
            .driver
            .read_varint(self.handle, &mut self.conn, id, deadline)?;
        let pad_len = usize::try_from(pad_len).map_err(|_| Hysteria2Error::InvalidFrame)?;
        let _ = self
            .driver
            .read_exact(self.handle, &mut self.conn, id, pad_len, deadline)?;
        Ok(TcpResponse { ok, message })
    }

    /// 在代理 stream 上写数据。
    ///
    /// # Errors
    ///
    /// 超时/关闭 → [`Hysteria2Error`]。
    pub fn stream_write(&mut self, id: StreamId, data: &[u8]) -> Result<(), Hysteria2Error> {
        let deadline = Instant::now() + STREAM_TIMEOUT;
        self.driver
            .write_all(self.handle, &mut self.conn, id, data, deadline)
    }

    /// 从代理 stream 读数据（阻塞至有数据或 `timeout`）。
    ///
    /// fast-open 下首次调用会先剥离 `TCPResponse`；服务端拒绝则返回
    /// [`Hysteria2Error::TcpRejected`]。返回 `Ok(0)` 表示对端已关闭写端。
    ///
    /// # Errors
    ///
    /// 超时 → [`Hysteria2Error::Timeout`]；流被重置 → [`Hysteria2Error::StreamReset`]。
    pub fn stream_read(
        &mut self,
        id: StreamId,
        buf: &mut [u8],
        timeout: Duration,
    ) -> Result<usize, Hysteria2Error> {
        let deadline = Instant::now() + timeout;
        if self.response_pending.remove(&id) {
            let resp = self.read_tcp_response(id, deadline)?;
            if !resp.ok {
                return Err(Hysteria2Error::TcpRejected(resp.message));
            }
        }
        self.driver
            .read_some(self.handle, &mut self.conn, id, buf, deadline)
    }

    /// 关闭 stream 写端（FIN）。
    pub fn stream_finish(&mut self, id: StreamId) {
        self.driver.finish_stream(self.handle, &mut self.conn, id);
    }

    /// 分配一个新的 UDP session id（本地从 0 递增；无显式关闭，server 按不活跃
    /// 超时回收——文档 §2.3(4)）。
    #[must_use]
    pub fn alloc_udp_session(&mut self) -> u32 {
        let id = self.next_udp_session;
        self.next_udp_session = self.next_udp_session.wrapping_add(1);
        id
    }

    /// 发送一个 UDP 包（封装为 `UDPMessage`，经 QUIC DATAGRAM 发出）。
    ///
    /// 不分片（`frag_id=0, frag_count=1`）；超过上限的包直接丢弃并返回
    /// [`Hysteria2Error::DatagramTooLarge`]（文档 §2.3(3) 允许"分片或丢弃"，
    /// 本 crate 暂不实现分片）。
    ///
    /// # Errors
    ///
    /// UDP 未启用 → [`Hysteria2Error::UdpDisabled`]；包过大 → [`Hysteria2Error::DatagramTooLarge`]。
    pub fn send_udp(
        &mut self,
        session: u32,
        target: &str,
        payload: &[u8],
    ) -> Result<(), Hysteria2Error> {
        if !self.udp_enabled {
            return Err(Hysteria2Error::UdpDisabled);
        }
        if payload.len() > MAX_UDP_PAYLOAD {
            return Err(Hysteria2Error::DatagramTooLarge { len: payload.len() });
        }
        let packet_id = self.next_packet_id;
        self.next_packet_id = self.next_packet_id.wrapping_add(1);
        let msg = UdpMessage {
            session_id: session,
            packet_id,
            frag_id: 0,
            frag_count: 1,
            target: target.to_string(),
            payload: payload.to_vec(),
        };
        let bytes = msg.encode();
        if let Some(max) = self.driver.max_datagram_size(&mut self.conn) {
            if bytes.len() > max {
                return Err(Hysteria2Error::DatagramTooLarge { len: bytes.len() });
            }
        }
        self.driver
            .send_datagram(self.handle, &mut self.conn, &bytes)
    }

    /// 接收一个 UDP 包（阻塞至多 `timeout`），返回解码后的 [`UdpMessage`]。
    ///
    /// # Errors
    ///
    /// UDP 未启用 → [`Hysteria2Error::UdpDisabled`]；超时 → [`Hysteria2Error::Timeout`]；
    /// 帧非法 → [`Hysteria2Error::InvalidFrame`]。
    pub fn recv_udp(&mut self, timeout: Duration) -> Result<UdpMessage, Hysteria2Error> {
        if !self.udp_enabled {
            return Err(Hysteria2Error::UdpDisabled);
        }
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(d) =
                self.driver
                    .recv_datagram(self.handle, &mut self.conn, Duration::from_millis(50))
            {
                return UdpMessage::decode(&d);
            }
            if self.conn.is_closed() {
                return Err(Hysteria2Error::Closed);
            }
            if Instant::now() >= deadline {
                return Err(Hysteria2Error::Timeout);
            }
        }
    }

    /// 关闭连接。
    pub fn close(&mut self) {
        self.driver
            .close(self.handle, &mut self.conn, 0, b"client close");
    }
}

// WARN4: Drop 保证错误路径也发送 CONNECTION_CLOSE，避免服务端状态残留到 idle 超时。
// 显式 close() 后再 drop 会发第二次 CLOSE，quinn 侧幂等，无害。
impl Drop for Hysteria2Client {
    fn drop(&mut self) {
        self.close();
    }
}
