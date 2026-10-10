//! 最小 sans-IO QUIC 驱动（基于 quinn-proto 0.11，同步阻塞 API）。
//!
//! `quinn-proto` 的 `Endpoint` 本身不持有 socket（纯 sans-IO）：driver 负责
//! UDP 收发（`poll_transmit` → `send_to`，`recv_from` → `endpoint.handle`）、
//! 定时器（`poll_timeout` → `handle_timeout`）与端点事件路由。本模块提供
//! client 与测试用 server 共用的驱动原语。
//!
//! Salamander 混淆（如配置）发生在 **QUIC 包之下**：发出时对整个 UDP 载荷
//! 做 `salt + XOR`（[`crate::obfs`]），收到时先解混淆再喂给 endpoint。
//!
//! QUIC 参数（文档 §2.1(2)）：
//!
//! - ALPN `h3`（在 [`crate::tls`] 的 rustls 配置中设置）；
//! - 禁用 QUIC bit greasing（`EndpointConfig::grease_quic_bit(false)`；
//!   quinn-proto 直接支持该旋钮）；
//! - DATAGRAM 收发缓冲：文档"收发队列各 1024"指 1024 个包，quinn-proto 的
//!   buffer 以字节计，按典型 1350 字节/包折算；
//! - 流接收窗口 8MB、连接接收窗口 20MB、最大空闲超时 30s、
//!   最大并发双向/单向流各 1024；
//! - 保活：10s 无流量发 keep-alive（ack-eliciting）包。

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use quinn_proto::{
    Connection, ConnectionHandle, DatagramEvent, Dir, Endpoint, EndpointConfig, IdleTimeout,
    ReadError, SendDatagramError, ServerConfig, StreamId, TransportConfig, VarInt, WriteError,
};

use super::Hysteria2Error;
use super::obfs;
use super::varint;

/// 构造 Hysteria2 的 QUIC 传输参数（文档 §2.1(2)）。
#[must_use]
pub fn hysteria_transport_config() -> TransportConfig {
    let mut t = TransportConfig::default();
    t.max_concurrent_bidi_streams(VarInt::from_u32(1024));
    t.max_concurrent_uni_streams(VarInt::from_u32(1024));
    t.stream_receive_window(VarInt::from_u32(8 * 1024 * 1024));
    t.receive_window(VarInt::from_u32(20 * 1024 * 1024));
    if let Ok(timeout) = IdleTimeout::try_from(Duration::from_secs(30)) {
        t.max_idle_timeout(Some(timeout));
    }
    // DATAGRAM：文档"收发队列各 1024"指包数；quinn-proto 以字节计，
    // 按 1350 字节/包折算（约 1.38MB）。
    t.datagram_receive_buffer_size(Some(1024 * 1350));
    t.datagram_send_buffer_size(1024 * 1350);
    // 保活：10s 无流量则发 ack-eliciting 包（文档 §2.1(6)）。
    t.keep_alive_interval(Some(Duration::from_secs(10)));
    // 拥塞控制：用 quinn-proto 默认（Cubic）；Brutal CC 不在本 crate 实现
    // （MODULE.md Non-Responsibilities）。
    t
}

/// 构造端点配置：禁用 QUIC bit greasing（文档 §2.1(2)、§5 坑 #5）。
#[must_use]
pub fn hysteria_endpoint_config() -> EndpointConfig {
    let mut c = EndpointConfig::default();
    c.grease_quic_bit(false);
    c
}

/// 最小 QUIC 驱动：UDP socket + sans-IO endpoint + 收发缓冲。
pub struct Driver {
    socket: UdpSocket,
    endpoint: Endpoint,
    /// `poll_transmit` 输出暂存。
    tx_buf: Vec<u8>,
    /// `recv_from` 暂存。
    rx_buf: Vec<u8>,
    /// Salamander key（`None` = 不启用混淆）。
    obfs_key: Option<Vec<u8>>,
}

impl Driver {
    /// 创建驱动：绑定通配地址（优先双栈 `[::]:0`，失败回退 `0.0.0.0:0`）。
    ///
    /// # Errors
    ///
    /// socket 绑定失败 → [`Hysteria2Error::Io`]。
    pub fn new(
        server_config: Option<Arc<ServerConfig>>,
        obfs_key: Option<Vec<u8>>,
    ) -> Result<Self, Hysteria2Error> {
        // 双栈通配：优先 `[::]:0`（v4/v6），失败回退 `0.0.0.0:0`。
        // 注意：见 `normalize_remote` 的注释。
        let socket = UdpSocket::bind("[::]:0")
            .or_else(|_| UdpSocket::bind("0.0.0.0:0"))
            .map_err(|e| Hysteria2Error::Io(e.to_string()))?;
        Ok(Self {
            socket,
            endpoint: Endpoint::new(
                Arc::new(hysteria_endpoint_config()),
                server_config,
                false,
                None,
            ),
            // 注意：tx_buf 必须为空 Vec（poll_transmit 向 buf 尾部追加写包；
            // 预填充会导致写偏移错误甚至减法溢出）。
            tx_buf: Vec::new(),
            rx_buf: vec![0u8; 65535],
            obfs_key,
        })
    }

    /// 本地 UDP 地址。
    pub fn local_addr(&self) -> Result<SocketAddr, Hysteria2Error> {
        self.socket
            .local_addr()
            .map_err(|e| Hysteria2Error::Io(e.to_string()))
    }

    /// 可变借用底层 endpoint（建连/accept 用）。
    pub fn endpoint_mut(&mut self) -> &mut Endpoint {
        &mut self.endpoint
    }

    /// 发出一个 UDP 包（如配置 Salamander 则先整包混淆）。
    fn send_udp(&self, payload: &[u8], dest: SocketAddr) {
        if let Some(key) = &self.obfs_key {
            let mut salt = [0u8; obfs::SALT_LEN];
            {
                use ring::rand::{SecureRandom, SystemRandom};
                let _ = SystemRandom::new().fill(&mut salt);
            }
            let enc = obfs::obfuscate(key, payload, &salt);
            let _ = self.socket.send_to(&enc, dest);
        } else {
            let _ = self.socket.send_to(payload, dest);
        }
    }

    /// 把连接的待发包全部发出。
    fn flush_transmits(&mut self, conn: &mut Connection) {
        let now = Instant::now();
        while let Some(t) = conn.poll_transmit(now, 1, &mut self.tx_buf) {
            let pkt = self.tx_buf[..t.size].to_vec();
            self.tx_buf.clear();
            self.send_udp(&pkt, t.destination);
        }
    }

    /// 推进一个连接：定时器 → 端点事件 → 待发包 → 丢弃已消费的连接事件。
    ///
    /// 连接丢失在这里只表现为 `is_closed()`；调用方通过 [`Driver::drive_until`]
    /// 或 `is_closed()` 感知。
    pub fn pump(&mut self, handle: ConnectionHandle, conn: &mut Connection) {
        let now = Instant::now();
        if matches!(conn.poll_timeout(), Some(t) if t <= now) {
            conn.handle_timeout(now);
        }
        while let Some(ev) = conn.poll_endpoint_events() {
            if let Some(cev) = self.endpoint.handle_event(handle, ev) {
                conn.handle_event(cev);
            }
        }
        // 排空连接事件（本驱动的调用方直接轮询 stream/datagram 状态，
        // 不依赖事件队列；排空防止队列无界增长）。
        while conn.poll().is_some() {}
        self.flush_transmits(conn);
    }

    /// 收一个 UDP 包（阻塞至多 `timeout`），解混淆后喂给 endpoint。
    ///
    /// `Response` 立即回发；`ConnectionEvent` 在 handle 匹配时路由给 `conn`；
    /// `NewConnection` 在 client 驱动中忽略（server 路径用 [`Driver::accept_one`]）。
    /// 返回 `true` 表示收到并处理了一个包。
    pub fn recv_one(
        &mut self,
        handle: ConnectionHandle,
        conn: &mut Connection,
        timeout: Duration,
    ) -> bool {
        let timeout = timeout.max(Duration::from_millis(1));
        if self.socket.set_read_timeout(Some(timeout)).is_err() {
            return false;
        }
        let (n, remote) = match self.socket.recv_from(&mut self.rx_buf) {
            Ok((n, remote)) => (n, normalize_remote(remote)),
            Err(_) => return false,
        };
        let plain: Vec<u8> = match &self.obfs_key {
            Some(key) => match obfs::deobfuscate(key, &self.rx_buf[..n]) {
                Ok(p) => p,
                Err(_) => return false, // 非法包丢弃
            },
            None => self.rx_buf[..n].to_vec(),
        };
        let local_ip: Option<IpAddr> = self.socket.local_addr().ok().map(|a| a.ip());
        let data = BytesMut::from(&plain[..]);
        let ev = self.endpoint.handle(
            Instant::now(),
            remote,
            local_ip,
            None,
            data,
            &mut self.tx_buf,
        );
        match ev {
            None => false,
            Some(DatagramEvent::Response(t)) => {
                let pkt = self.tx_buf[..t.size].to_vec();
                self.tx_buf.clear();
                self.send_udp(&pkt, t.destination);
                true
            }
            Some(DatagramEvent::NewConnection(_)) => {
                // client 驱动无 server 配置：丢弃陌生握手。
                true
            }
            Some(DatagramEvent::ConnectionEvent(ch, cev)) => {
                if ch == handle {
                    conn.handle_event(cev);
                }
                true
            }
        }
    }

    /// 驱动直到 `cond(conn)` 成立（返回 `Ok(true)`）或 `deadline` 到达
    /// （返回 `Ok(false)`）。连接关闭 → [`Hysteria2Error::Closed`]。
    ///
    /// # Errors
    ///
    /// 连接关闭 → [`Hysteria2Error::Closed`]。
    pub fn drive_until<F>(
        &mut self,
        handle: ConnectionHandle,
        conn: &mut Connection,
        deadline: Instant,
        mut cond: F,
    ) -> Result<bool, Hysteria2Error>
    where
        F: FnMut(&Connection) -> bool,
    {
        loop {
            self.pump(handle, conn);
            if cond(conn) {
                return Ok(true);
            }
            if conn.is_closed() {
                return Err(Hysteria2Error::Closed);
            }
            let now = Instant::now();
            if now >= deadline {
                return Ok(false);
            }
            let wait = conn
                .poll_timeout()
                .map(|t| t.saturating_duration_since(now))
                .unwrap_or(Duration::from_millis(50))
                .min(deadline.saturating_duration_since(now))
                .min(Duration::from_millis(200));
            self.recv_one(handle, conn, wait);
        }
    }

    /// 打开一条双向 stream（client 发起；首个 id 为 0，之后 4、8…步进 4）。
    ///
    /// # Errors
    ///
    /// 流配额耗尽 → [`Hysteria2Error::Quic`]。
    pub fn open_bi(
        &mut self,
        handle: ConnectionHandle,
        conn: &mut Connection,
    ) -> Result<StreamId, Hysteria2Error> {
        self.pump(handle, conn);
        conn.streams()
            .open(Dir::Bi)
            .ok_or_else(|| Hysteria2Error::Quic("open_bi: no stream id available".to_string()))
    }

    /// 打开一条单向 stream（client 发起；首个 id 为 2）。
    ///
    /// # Errors
    ///
    /// 流配额耗尽 → [`Hysteria2Error::Quic`]。
    pub fn open_uni(
        &mut self,
        handle: ConnectionHandle,
        conn: &mut Connection,
    ) -> Result<StreamId, Hysteria2Error> {
        self.pump(handle, conn);
        conn.streams()
            .open(Dir::Uni)
            .ok_or_else(|| Hysteria2Error::Quic("open_uni: no stream id available".to_string()))
    }

    /// 非阻塞地接受一条对端发起的 stream（没有则返回 `None`）。
    pub fn accept_stream(
        &mut self,
        handle: ConnectionHandle,
        conn: &mut Connection,
        dir: Dir,
    ) -> Option<StreamId> {
        self.pump(handle, conn);
        conn.streams().accept(dir)
    }

    /// 在 stream 上写完 `data`（阻塞至 `deadline`，处理流控 `Blocked`）。
    ///
    /// # Errors
    ///
    /// 超时 → [`Hysteria2Error::Timeout`]；连接/流关闭 → [`Hysteria2Error::Closed`]。
    pub fn write_all(
        &mut self,
        handle: ConnectionHandle,
        conn: &mut Connection,
        id: StreamId,
        mut data: &[u8],
        deadline: Instant,
    ) -> Result<(), Hysteria2Error> {
        while !data.is_empty() {
            match conn.send_stream(id).write(data) {
                Ok(n) => data = &data[n..],
                Err(WriteError::Blocked) => {
                    self.pump(handle, conn);
                    if Instant::now() >= deadline {
                        return Err(Hysteria2Error::Timeout);
                    }
                    self.recv_one(handle, conn, Duration::from_millis(50));
                }
                Err(_) => return Err(Hysteria2Error::Closed),
            }
            self.pump(handle, conn);
            if conn.is_closed() {
                return Err(Hysteria2Error::Closed);
            }
            if !data.is_empty() && Instant::now() >= deadline {
                return Err(Hysteria2Error::Timeout);
            }
        }
        Ok(())
    }

    /// 从 stream 精确读 `len` 字节（阻塞至 `deadline`）。
    ///
    /// # Errors
    ///
    /// 对端提前结束流 → [`Hysteria2Error::InvalidFrame`]；超时 → [`Hysteria2Error::Timeout`]。
    pub fn read_exact(
        &mut self,
        handle: ConnectionHandle,
        conn: &mut Connection,
        id: StreamId,
        len: usize,
        deadline: Instant,
    ) -> Result<Vec<u8>, Hysteria2Error> {
        let mut out = Vec::with_capacity(len);
        let mut buf = [0u8; 8192];
        while out.len() < len {
            let want = (len - out.len()).min(buf.len());
            let n = self.read_some(handle, conn, id, &mut buf[..want], deadline)?;
            if n == 0 {
                // 对端提前 FIN：帧被截断。
                return Err(Hysteria2Error::InvalidFrame);
            }
            out.extend_from_slice(&buf[..n]);
        }
        Ok(out)
    }

    /// 从 stream 读一个 QUIC varint（阻塞至 `deadline`）。
    ///
    /// # Errors
    ///
    /// 截断/超时等 → [`Hysteria2Error`]。
    pub fn read_varint(
        &mut self,
        handle: ConnectionHandle,
        conn: &mut Connection,
        id: StreamId,
        deadline: Instant,
    ) -> Result<u64, Hysteria2Error> {
        let first = self.read_exact(handle, conn, id, 1, deadline)?;
        let total = match first[0] >> 6 {
            0 => 1,
            1 => 2,
            2 => 4,
            _ => 8,
        };
        let mut raw = first;
        if total > 1 {
            raw.extend_from_slice(&self.read_exact(handle, conn, id, total - 1, deadline)?);
        }
        // `raw` 由本函数按长度位构造，必为合法 varint。
        let (value, _) = varint::decode(&raw)?;
        Ok(value)
    }

    /// 从 stream 至多读 `buf.len()` 字节（阻塞至有数据或 `deadline`）。
    /// 返回 `Ok(0)` 表示对端已 FIN 且数据读完。
    ///
    /// # Errors
    ///
    /// 超时 → [`Hysteria2Error::Timeout`]；流被重置 → [`Hysteria2Error::StreamReset`]。
    pub fn read_some(
        &mut self,
        handle: ConnectionHandle,
        conn: &mut Connection,
        id: StreamId,
        buf: &mut [u8],
        deadline: Instant,
    ) -> Result<usize, Hysteria2Error> {
        assert!(!buf.is_empty(), "read_some needs a non-empty buffer");
        loop {
            let chunk_len = {
                let mut recv = conn.recv_stream(id);
                let mut chunks = recv.read(true).map_err(|_| Hysteria2Error::Closed)?;
                let max = buf.len().min(16384);
                let r = chunks.next(max);
                let _ = chunks.finalize();
                r
            };
            match chunk_len {
                Ok(Some(chunk)) => {
                    let n = chunk.bytes.len().min(buf.len());
                    buf[..n].copy_from_slice(&chunk.bytes[..n]);
                    self.pump(handle, conn);
                    return Ok(n);
                }
                Ok(None) => return Ok(0),
                Err(ReadError::Blocked) => {
                    self.pump(handle, conn);
                    if conn.is_closed() {
                        return Err(Hysteria2Error::Closed);
                    }
                    if Instant::now() >= deadline {
                        return Err(Hysteria2Error::Timeout);
                    }
                    self.recv_one(handle, conn, Duration::from_millis(50));
                }
                Err(ReadError::Reset(code)) => {
                    return Err(Hysteria2Error::StreamReset {
                        code: code.into_inner(),
                    });
                }
            }
        }
    }

    /// 关闭 stream 写端（FIN）。
    pub fn finish_stream(&mut self, handle: ConnectionHandle, conn: &mut Connection, id: StreamId) {
        let _ = conn.send_stream(id).finish();
        self.pump(handle, conn);
    }

    /// 发送一个 QUIC DATAGRAM（尽力而为；发送缓冲满则丢弃）。
    ///
    /// # Errors
    ///
    /// 对端不支持/本地禁用 DATAGRAM → [`Hysteria2Error::UdpDisabled`]；
    /// 超过当前路径上限 → [`Hysteria2Error::DatagramTooLarge`]。
    pub fn send_datagram(
        &mut self,
        handle: ConnectionHandle,
        conn: &mut Connection,
        data: &[u8],
    ) -> Result<(), Hysteria2Error> {
        let len = data.len();
        match conn.datagrams().send(Bytes::from(data.to_vec()), true) {
            Ok(()) => {}
            Err(SendDatagramError::Blocked(_)) => {
                // 缓冲满：pump 一次把待发包送出去再试一次；仍满则丢弃
                //（UDP 语义为尽力而为）。
                self.pump(handle, conn);
                match conn.datagrams().send(Bytes::from(data.to_vec()), true) {
                    Ok(()) | Err(SendDatagramError::Blocked(_)) => {}
                    Err(e) => return Err(map_datagram_error(e, len)),
                }
            }
            Err(e) => return Err(map_datagram_error(e, len)),
        }
        self.pump(handle, conn);
        Ok(())
    }

    /// 当前路径允许的最大 DATAGRAM 载荷（`None` = 未知/不支持）。
    pub fn max_datagram_size(&mut self, conn: &mut Connection) -> Option<usize> {
        conn.datagrams().max_size()
    }

    /// 接收一个 QUIC DATAGRAM（阻塞至多 `timeout`）。
    pub fn recv_datagram(
        &mut self,
        handle: ConnectionHandle,
        conn: &mut Connection,
        timeout: Duration,
    ) -> Option<Vec<u8>> {
        let deadline = Instant::now() + timeout;
        loop {
            self.pump(handle, conn);
            if let Some(d) = conn.datagrams().recv() {
                return Some(d.to_vec());
            }
            if conn.is_closed() || Instant::now() >= deadline {
                return None;
            }
            self.recv_one(handle, conn, Duration::from_millis(50));
        }
    }

    /// 关闭连接（发送 CONNECTION_CLOSE，尽力）。
    pub fn close(
        &mut self,
        handle: ConnectionHandle,
        conn: &mut Connection,
        code: u64,
        reason: &[u8],
    ) {
        let code = VarInt::from_u64(code.min((1 << 62) - 1)).unwrap_or(VarInt::MAX);
        conn.close(Instant::now(), code, Bytes::copy_from_slice(reason));
        self.pump(handle, conn);
    }

    /// 服务端：阻塞至多 `timeout` 接受一个新连接。
    ///
    /// `Response` 包（版本协商/重试）已直接回发；返回接受后的连接。
    pub fn accept_one(
        &mut self,
        server_config: &Arc<ServerConfig>,
        timeout: Duration,
    ) -> Option<(ConnectionHandle, Connection)> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            let remain = deadline.saturating_duration_since(Instant::now());
            if self
                .socket
                .set_read_timeout(Some(remain.max(Duration::from_millis(1))))
                .is_err()
            {
                return None;
            }
            let (n, remote) = match self.socket.recv_from(&mut self.rx_buf) {
                Ok((n, remote)) => (n, normalize_remote(remote)),
                Err(_) => continue,
            };
            let plain: Vec<u8> = match &self.obfs_key {
                Some(key) => match obfs::deobfuscate(key, &self.rx_buf[..n]) {
                    Ok(p) => p,
                    Err(_) => continue,
                },
                None => self.rx_buf[..n].to_vec(),
            };
            let local_ip: Option<IpAddr> = self.socket.local_addr().ok().map(|a| a.ip());
            let data = BytesMut::from(&plain[..]);
            let ev = self.endpoint.handle(
                Instant::now(),
                remote,
                local_ip,
                None,
                data,
                &mut self.tx_buf,
            );
            match ev {
                Some(DatagramEvent::Response(t)) => {
                    let pkt = self.tx_buf[..t.size].to_vec();
                    self.tx_buf.clear();
                    self.send_udp(&pkt, t.destination);
                }
                Some(DatagramEvent::NewConnection(incoming)) => {
                    match self.endpoint.accept(
                        incoming,
                        Instant::now(),
                        &mut self.tx_buf,
                        Some(server_config.clone()),
                    ) {
                        Ok((handle, mut conn)) => {
                            self.pump(handle, &mut conn);
                            return Some((handle, conn));
                        }
                        Err(e) => {
                            if let Some(t) = e.response {
                                let pkt = self.tx_buf[..t.size].to_vec();
                                self.tx_buf.clear();
                                self.send_udp(&pkt, t.destination);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        None
    }
}

/// 归一化收包源地址：双栈 socket 上收到的 IPv4 包源地址为
/// IPv4-mapped IPv6（`::ffff:a.b.c.d`），必须转回纯 IPv4 再交给 quinn-proto。
///
/// 背景：实测发现，若把 mapped 地址直接传给 `Endpoint::handle`，而建连时用的
/// 是未映射的 `127.0.0.1`，quinn-proto 的连接/路径处理会失配——握手包能加解密、
/// 事件能路由，但握手永远无法完成（双方持续重传 Initial）。归一化后握手正常。
fn normalize_remote(remote: SocketAddr) -> SocketAddr {
    match remote.ip() {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(IpAddr::V4(v4), remote.port()),
            None => remote,
        },
        IpAddr::V4(_) => remote,
    }
}

fn map_datagram_error(e: SendDatagramError, len: usize) -> Hysteria2Error {
    match e {
        SendDatagramError::UnsupportedByPeer | SendDatagramError::Disabled => {
            Hysteria2Error::UdpDisabled
        }
        SendDatagramError::TooLarge => Hysteria2Error::DatagramTooLarge { len },
        SendDatagramError::Blocked(_) => Hysteria2Error::DatagramTooLarge { len },
    }
}
