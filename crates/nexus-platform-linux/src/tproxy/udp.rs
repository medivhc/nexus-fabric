//! TPROXY UDP socket（spec §9.1 / §13.2 S2）。
//!
//! 单个接收 `SOCK_DGRAM` socket：`recvmsg` 解析 `IP_ORIGDSTADDR` ancillary 得到
//! 原始目的地。回包源地址必须恰为 `orig_dst`（IP 与端口，PRODUCT §11.18）：经
//! 按 `orig_dst` 复用的 `IP_TRANSPARENT` 回包 socket（bind `orig_dst` 后
//! `sendto`）发出，数量有界（LRU）。per-flow 状态由 core 的
//! `TransparentPipeline` 持有。

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use nexus_platform::{ReceivedDatagram, TransparentIngressError, TransparentUdpIngress};

use super::sockaddr::{find_orig_dst, from_sockaddr_in, parse_cmsgs, to_sockaddr_in};
use super::{IP_RECVORIGDSTADDR, IP_TRANSPARENT};

/// UDP socket 配置。
#[derive(Debug, Clone)]
pub struct TproxyUdpConfig {
    /// 监听地址。
    pub listen: SocketAddrV4,
    /// `SO_RCVBUF` 初始值（默认 1 MiB）。
    pub recv_buffer_bytes: usize,
    /// 必须为 false（本 run IPv4-only）。
    pub ipv6: bool,
    /// 同时保留的回包 socket 上限（每个 `orig_dst` 一个，LRU 淘汰；默认 256；
    /// 0 按 1 处理：回包总需要一个源地址为 `orig_dst` 的 socket）。
    pub max_reply_sockets: usize,
}

impl Default for TproxyUdpConfig {
    fn default() -> Self {
        Self {
            listen: SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 7895),
            recv_buffer_bytes: 1024 * 1024,
            ipv6: false,
            max_reply_sockets: 256,
        }
    }
}

/// UDP 透明 socket。
#[derive(Debug)]
pub struct TproxyUdpSocket {
    fd: RawFd,
    started: bool,
    closed: bool,
    max_reply_sockets: usize,
    /// 回包 socket，按 `orig_dst` 一个；末尾为最近使用（LRU 淘汰队首）。
    reply_sockets: Vec<(SocketAddrV4, OwnedFd)>,
}

impl TproxyUdpSocket {
    /// 创建 socket、设置 sockopt 并 bind。
    ///
    /// # Errors
    ///
    /// 权限不足 → `PermissionDenied`；内核不支持 → `CapabilityUnavailable`；
    /// bind 失败 → `BindFailed`。
    pub fn bind(config: &TproxyUdpConfig) -> Result<Self, TransparentIngressError> {
        if config.ipv6 {
            return Err(TransparentIngressError::UnsupportedFamily {
                family: libc::AF_INET6 as u16,
            });
        }
        // SAFETY: socket(2) has no pointer arguments; fd ownership is guarded
        // by `closed` and closed exactly once.
        let fd = unsafe {
            libc::socket(
                libc::AF_INET,
                libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                0,
            )
        };
        if fd < 0 {
            return Err(map_socket_errno("socket"));
        }
        let socket = Self {
            fd,
            started: false,
            closed: false,
            max_reply_sockets: config.max_reply_sockets.max(1),
            reply_sockets: Vec::new(),
        };
        socket.set_int_opt(IP_TRANSPARENT, 1, "IP_TRANSPARENT")?;
        socket.set_int_opt(IP_RECVORIGDSTADDR, 1, "IP_RECVORIGDSTADDR")?;
        let buffer = libc::c_int::try_from(config.recv_buffer_bytes).unwrap_or(libc::c_int::MAX);
        socket.set_int_opt(libc::SO_RCVBUF, buffer, "SO_RCVBUF")?;
        let addr = to_sockaddr_in(config.listen);
        // SAFETY: `addr` is a fully initialized sockaddr_in; fd is valid.
        let rc = unsafe {
            libc::bind(
                socket.fd,
                (&addr as *const libc::sockaddr_in).cast(),
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
            return Err(TransparentIngressError::BindFailed {
                addr: config.listen.to_string(),
                errno,
            });
        }
        Ok(socket)
    }

    /// 取（或建立）源地址为 `orig_dst` 的回包 socket，并记为最近使用。
    fn reply_socket(&mut self, orig_dst: SocketAddrV4) -> Result<RawFd, TransparentIngressError> {
        if let Some(pos) = self
            .reply_sockets
            .iter()
            .position(|(dst, _)| *dst == orig_dst)
        {
            let entry = self.reply_sockets.remove(pos);
            self.reply_sockets.push(entry);
        } else {
            let fd = open_reply_socket(orig_dst)?;
            if self.reply_sockets.len() >= self.max_reply_sockets {
                self.reply_sockets.remove(0);
            }
            self.reply_sockets.push((orig_dst, fd));
        }
        match self.reply_sockets.last() {
            Some((_, fd)) => Ok(fd.as_raw_fd()),
            None => Err(TransparentIngressError::Io {
                operation: "sendto",
                message: "reply socket missing".to_string(),
            }),
        }
    }

    #[cfg(test)]
    fn reply_socket_count(&self) -> usize {
        self.reply_sockets.len()
    }

    #[cfg(test)]
    fn has_reply_socket(&self, orig_dst: SocketAddrV4) -> bool {
        self.reply_sockets.iter().any(|(dst, _)| *dst == orig_dst)
    }

    fn set_int_opt(
        &self,
        opt: libc::c_int,
        value: libc::c_int,
        name: &'static str,
    ) -> Result<(), TransparentIngressError> {
        set_int_opt(self.fd, libc::IPPROTO_IP, opt, value, name)
    }
}

fn set_int_opt(
    fd: RawFd,
    level: libc::c_int,
    opt: libc::c_int,
    value: libc::c_int,
    name: &'static str,
) -> Result<(), TransparentIngressError> {
    // SAFETY: fd is valid; `value` outlives the call and its length matches
    // the int option expected by setsockopt(2).
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            opt,
            (&value as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return Err(match errno {
            libc::EPERM | libc::EACCES => TransparentIngressError::PermissionDenied {
                operation: "setsockopt",
                errno,
            },
            libc::ENOPROTOOPT | libc::EOPNOTSUPP => {
                TransparentIngressError::CapabilityUnavailable { capability: name }
            }
            _ => TransparentIngressError::SockOptFailed { opt: name, errno },
        });
    }
    Ok(())
}

/// 建立源地址为 `orig_dst` 的回包 socket：`IP_TRANSPARENT` 允许 bind 非本机地址
/// （不同 `orig_dst` IP 共用同一端口号本就不冲突）；`SO_REUSEADDR` 让它与同样设置
/// 了 `SO_REUSEADDR` 的本机通配 socket（如 dnsmasq 的 `0.0.0.0:53`）共存。本机已有
/// socket 独占该地址端口时 bind 失败（`BindFailed`），调用方丢弃回包而不是改用其它
/// 源端口（已知限制：此时发往该端口的透明 UDP 流收不到回包）。
fn open_reply_socket(orig_dst: SocketAddrV4) -> Result<OwnedFd, TransparentIngressError> {
    // SAFETY: socket(2) has no pointer arguments.
    let raw = unsafe {
        libc::socket(
            libc::AF_INET,
            libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if raw < 0 {
        return Err(map_socket_errno("socket"));
    }
    // SAFETY: `raw` is a fresh, valid fd that nothing else owns; OwnedFd
    // closes it exactly once on drop.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    set_int_opt(
        fd.as_raw_fd(),
        libc::SOL_SOCKET,
        libc::SO_REUSEADDR,
        1,
        "SO_REUSEADDR",
    )?;
    set_int_opt(
        fd.as_raw_fd(),
        libc::IPPROTO_IP,
        IP_TRANSPARENT,
        1,
        "IP_TRANSPARENT",
    )?;
    let addr = to_sockaddr_in(orig_dst);
    // SAFETY: `addr` is a fully initialized sockaddr_in; fd is valid.
    let rc = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            (&addr as *const libc::sockaddr_in).cast(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return Err(TransparentIngressError::BindFailed {
            addr: orig_dst.to_string(),
            errno,
        });
    }
    Ok(fd)
}

impl TransparentUdpIngress for TproxyUdpSocket {
    fn start(&mut self) -> Result<(), TransparentIngressError> {
        self.started = true;
        Ok(())
    }

    fn local_addr(&self) -> Result<SocketAddr, TransparentIngressError> {
        // SAFETY: sockaddr_in is plain-old-data; zeroing is a valid initial value.
        let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        // SAFETY: valid out-params sized for sockaddr_in.
        let rc = unsafe {
            libc::getsockname(
                self.fd,
                (&mut addr as *mut libc::sockaddr_in).cast(),
                &mut len,
            )
        };
        if rc != 0 {
            return Err(TransparentIngressError::Io {
                operation: "getsockname",
                message: io::Error::last_os_error().to_string(),
            });
        }
        // SAFETY: kernel filled `addr` as sockaddr_in.
        Ok(SocketAddr::V4(unsafe { from_sockaddr_in(&addr) }))
    }

    fn recv(
        &mut self,
        now_millis: u64,
    ) -> Result<Option<ReceivedDatagram>, TransparentIngressError> {
        if self.closed {
            return Err(TransparentIngressError::Io {
                operation: "recvmsg",
                message: "socket closed".to_string(),
            });
        }
        let mut payload = vec![0u8; 65_535];
        let mut control = [0u8; 256];
        // SAFETY: sockaddr_in/msghdr are plain-old-data; zeroing is a valid initial value.
        let mut peer: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        let mut iov = libc::iovec {
            iov_base: payload.as_mut_ptr().cast(),
            iov_len: payload.len(),
        };
        // SAFETY: msghdr is plain-old-data; all pointers are filled below.
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_name = (&mut peer as *mut libc::sockaddr_in).cast();
        msg.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = control.len();
        // SAFETY: `msg` points to live payload/control/peer buffers of the
        // stated lengths; recvmsg writes only within those bounds.
        let n = unsafe { libc::recvmsg(self.fd, &mut msg, 0) };
        if n < 0 {
            let err = io::Error::last_os_error();
            return match err.raw_os_error() {
                Some(libc::EAGAIN) => Ok(None),
                Some(libc::EPERM) | Some(libc::EACCES) => {
                    Err(TransparentIngressError::PermissionDenied {
                        operation: "recvmsg",
                        errno: err.raw_os_error().unwrap_or(0),
                    })
                }
                _ => Err(TransparentIngressError::Io {
                    operation: "recvmsg",
                    message: err.to_string(),
                }),
            };
        }
        if peer.sin_family as i32 != libc::AF_INET {
            return Err(TransparentIngressError::UnsupportedFamily {
                family: peer.sin_family as u16,
            });
        }
        // SAFETY: kernel filled `peer` as sockaddr_in.
        let peer = unsafe { from_sockaddr_in(&peer) };
        let control_len = msg.msg_controllen.min(control.len());
        let messages = parse_cmsgs(&control[..control_len])?;
        let orig_dst =
            find_orig_dst(&messages)?.ok_or_else(|| TransparentIngressError::OrigDstMissing {
                peer: peer.to_string(),
            })?;
        payload.truncate(usize::try_from(n).unwrap_or(0));
        Ok(Some(ReceivedDatagram {
            payload,
            peer,
            orig_dst,
            received_at_millis: now_millis,
        }))
    }

    fn send_from(
        &mut self,
        orig_dst: SocketAddrV4,
        peer: SocketAddrV4,
        payload: &[u8],
    ) -> Result<usize, TransparentIngressError> {
        if self.closed {
            return Err(TransparentIngressError::Io {
                operation: "sendto",
                message: "socket closed".to_string(),
            });
        }
        let fd = self.reply_socket(orig_dst)?;
        let dest = to_sockaddr_in(peer);
        // SAFETY: `payload` and `dest` are live for the call with the stated
        // lengths; sendto only reads them. `fd` stays open (owned by
        // `reply_sockets`) until this method returns.
        let n = unsafe {
            libc::sendto(
                fd,
                payload.as_ptr().cast(),
                payload.len(),
                0,
                (&dest as *const libc::sockaddr_in).cast(),
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        if n < 0 {
            return Err(TransparentIngressError::Io {
                operation: "sendto",
                message: io::Error::last_os_error().to_string(),
            });
        }
        Ok(usize::try_from(n).unwrap_or(0))
    }

    fn shutdown(&mut self) -> Result<(), TransparentIngressError> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        self.reply_sockets.clear();
        // SAFETY: fd is owned and closed exactly once (guarded by `closed`).
        let rc = unsafe { libc::close(self.fd) };
        if rc != 0 {
            return Err(TransparentIngressError::Io {
                operation: "close",
                message: io::Error::last_os_error().to_string(),
            });
        }
        Ok(())
    }
}

impl Drop for TproxyUdpSocket {
    fn drop(&mut self) {
        if !self.closed {
            self.closed = true;
            // SAFETY: fd is owned and not closed elsewhere (`closed` guard).
            unsafe { libc::close(self.fd) };
        }
    }
}

fn map_socket_errno(operation: &'static str) -> TransparentIngressError {
    let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
    match errno {
        libc::EPERM | libc::EACCES => {
            TransparentIngressError::PermissionDenied { operation, errno }
        }
        libc::EPROTONOSUPPORT | libc::ENOPROTOOPT => {
            TransparentIngressError::CapabilityUnavailable {
                capability: "AF_INET/SOCK_DGRAM",
            }
        }
        _ => TransparentIngressError::Io {
            operation,
            message: io::Error::last_os_error().to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn loopback(port: u16) -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)
    }

    #[test]
    fn tproxy_udp_bind_reports_permission_or_starts() {
        let config = TproxyUdpConfig {
            listen: loopback(0),
            ..TproxyUdpConfig::default()
        };
        match TproxyUdpSocket::bind(&config) {
            Ok(mut socket) => {
                socket.start().unwrap();
                assert!(socket.local_addr().is_ok());
                assert!(socket.recv(1).unwrap().is_none());
                socket.shutdown().unwrap();
            }
            Err(TransparentIngressError::PermissionDenied { operation, .. }) => {
                assert_eq!(operation, "setsockopt");
            }
            Err(TransparentIngressError::CapabilityUnavailable { .. }) => {}
            Err(other) => panic!("unexpected bind error: {other}"),
        }
    }

    #[test]
    fn tproxy_udp_rejects_ipv6_config() {
        let config = TproxyUdpConfig {
            listen: loopback(0),
            ipv6: true,
            ..TproxyUdpConfig::default()
        };
        let err = TproxyUdpSocket::bind(&config).unwrap_err();
        assert!(matches!(
            err,
            TransparentIngressError::UnsupportedFamily { .. }
        ));
    }

    #[test]
    fn tproxy_udp_shutdown_is_idempotent() {
        let config = TproxyUdpConfig {
            listen: loopback(0),
            ..TproxyUdpConfig::default()
        };
        if let Ok(mut socket) = TproxyUdpSocket::bind(&config) {
            socket.shutdown().unwrap();
            socket.shutdown().unwrap();
        }
    }

    /// Binds a TPROXY UDP socket, or `None` without the privilege to do so.
    /// A skip is printed; with `NEXUS_REQUIRE_PRIVILEGED_TESTS=1` it fails
    /// instead, so a privileged run cited as evidence cannot pass vacuously.
    fn privileged_socket(max_reply_sockets: usize) -> Option<TproxyUdpSocket> {
        let config = TproxyUdpConfig {
            listen: loopback(0),
            max_reply_sockets,
            ..TproxyUdpConfig::default()
        };
        match TproxyUdpSocket::bind(&config) {
            Ok(socket) => Some(socket),
            Err(
                err @ (TransparentIngressError::PermissionDenied { .. }
                | TransparentIngressError::CapabilityUnavailable { .. }),
            ) => {
                let test = std::thread::current().name().unwrap_or("?").to_string();
                assert!(
                    std::env::var("NEXUS_REQUIRE_PRIVILEGED_TESTS").as_deref() != Ok("1"),
                    "{test}: privileged test cannot run: {err}"
                );
                // Written to the stderr handle, not eprintln!, so libtest's
                // output capture does not hide the skip on a passing run.
                let _ = writeln!(
                    std::io::stderr(),
                    "SKIP {test}: needs CAP_NET_ADMIN ({err})"
                );
                None
            }
            Err(other) => panic!("unexpected bind error: {other}"),
        }
    }

    /// TEST-NET-2 address: never local, so binding it needs `IP_TRANSPARENT`,
    /// and nothing else on the machine holds it (no port-reuse race).
    fn non_local(last: u8, port: u16) -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, last), port)
    }

    /// Exclusive (no `SO_REUSEADDR`) transparent bind of `addr`: succeeds only
    /// while no reply socket holds it. Returns the errno on failure.
    fn exclusive_bind(addr: SocketAddrV4) -> Result<OwnedFd, i32> {
        // SAFETY: socket(2) has no pointer arguments.
        let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        assert!(raw >= 0, "socket: {}", io::Error::last_os_error());
        // SAFETY: `raw` is a fresh fd owned only here.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        set_int_opt(
            fd.as_raw_fd(),
            libc::IPPROTO_IP,
            IP_TRANSPARENT,
            1,
            "IP_TRANSPARENT",
        )
        .unwrap();
        let sa = to_sockaddr_in(addr);
        // SAFETY: `sa` is a fully initialized sockaddr_in; fd is valid.
        let rc = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&sa as *const libc::sockaddr_in).cast(),
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        if rc == 0 {
            Ok(fd)
        } else {
            Err(io::Error::last_os_error().raw_os_error().unwrap_or(0))
        }
    }

    /// `SO_COOKIE` of the cached reply socket for `orig_dst` (unique per socket).
    fn reply_cookie(socket: &TproxyUdpSocket, orig_dst: SocketAddrV4) -> Option<u64> {
        let (_, fd) = socket.reply_sockets.iter().find(|(d, _)| *d == orig_dst)?;
        let mut cookie: u64 = 0;
        let mut len = std::mem::size_of::<u64>() as libc::socklen_t;
        // SAFETY: valid fd; out-params sized for u64.
        let rc = unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_COOKIE,
                (&mut cookie as *mut u64).cast(),
                &mut len,
            )
        };
        (rc == 0).then_some(cookie)
    }

    fn client() -> (std::net::UdpSocket, SocketAddrV4) {
        let client = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let SocketAddr::V4(addr) = client.local_addr().unwrap() else {
            unreachable!("bound to an IPv4 address")
        };
        (client, addr)
    }

    fn recv_from_source(client: &std::net::UdpSocket) -> (Vec<u8>, SocketAddr) {
        let mut buf = [0u8; 64];
        let (n, from) = client.recv_from(&mut buf).unwrap();
        (buf[..n].to_vec(), from)
    }

    fn assert_no_datagram(client: &std::net::UdpSocket) {
        client
            .set_read_timeout(Some(std::time::Duration::from_millis(200)))
            .unwrap();
        let mut buf = [0u8; 16];
        assert!(
            client.recv_from(&mut buf).is_err(),
            "no reply may be sent from a different source"
        );
    }

    fn assert_bind_failed(result: Result<usize, TransparentIngressError>, orig_dst: SocketAddrV4) {
        match result {
            Err(TransparentIngressError::BindFailed { addr, errno }) => {
                assert_eq!(addr, orig_dst.to_string());
                assert_eq!(errno, libc::EADDRINUSE);
            }
            other => panic!("expected BindFailed for {orig_dst}, got {other:?}"),
        }
    }

    /// Bound to a non-local orig_dst, so this also needs `IP_TRANSPARENT`.
    #[test]
    fn tproxy_udp_reply_comes_from_orig_dst_ip_and_port() {
        let Some(mut socket) = privileged_socket(8) else {
            return;
        };
        let (client, peer) = client();
        let orig_dst = non_local(11, 53);
        for payload in [&b"first"[..], b"second"] {
            socket.send_from(orig_dst, peer, payload).unwrap();
            let (got, from) = recv_from_source(&client);
            assert_eq!(got, payload);
            assert_eq!(
                from,
                SocketAddr::V4(orig_dst),
                "reply source must be orig_dst"
            );
        }
        // Same IP, another port: a distinct orig_dst with its own reply socket.
        let other_port = non_local(11, 5353);
        socket.send_from(other_port, peer, b"third").unwrap();
        assert_eq!(recv_from_source(&client).1, SocketAddr::V4(other_port));
        assert_eq!(
            socket.reply_socket_count(),
            2,
            "one reply socket per orig_dst"
        );
    }

    #[test]
    fn tproxy_udp_reply_socket_is_reused_not_reopened() {
        let Some(mut socket) = privileged_socket(8) else {
            return;
        };
        let (client, peer) = client();
        let orig_dst = non_local(12, 9000);
        socket.send_from(orig_dst, peer, b"a").unwrap();
        recv_from_source(&client);
        let first = reply_cookie(&socket, orig_dst).expect("reply socket cached");
        socket.send_from(orig_dst, peer, b"b").unwrap();
        recv_from_source(&client);
        assert_eq!(
            reply_cookie(&socket, orig_dst),
            Some(first),
            "the same reply socket must be reused"
        );
    }

    #[test]
    fn tproxy_udp_reply_sockets_are_bounded_lru() {
        let Some(mut socket) = privileged_socket(2) else {
            return;
        };
        let (client, peer) = client();
        let dsts = [
            non_local(21, 9000),
            non_local(22, 9000),
            non_local(23, 9000),
        ];
        for dst in [dsts[0], dsts[1], dsts[0], dsts[2]] {
            socket.send_from(dst, peer, b"x").unwrap();
            assert_eq!(recv_from_source(&client).1, SocketAddr::V4(dst));
        }
        // dsts[1] was least recently used when dsts[2] needed a slot.
        assert_eq!(socket.reply_socket_count(), 2);
        assert!(socket.has_reply_socket(dsts[0]));
        assert!(!socket.has_reply_socket(dsts[1]));
        assert!(socket.has_reply_socket(dsts[2]));
    }

    #[test]
    fn tproxy_udp_evicted_reply_socket_is_closed_and_readmitted() {
        let Some(mut socket) = privileged_socket(1) else {
            return;
        };
        let (client, peer) = client();
        let (d0, d1) = (non_local(31, 9000), non_local(32, 9000));
        socket.send_from(d0, peer, b"a").unwrap();
        recv_from_source(&client);
        socket.send_from(d1, peer, b"b").unwrap();
        recv_from_source(&client);
        drop(exclusive_bind(d0).expect("evicted reply socket must be closed"));
        socket.send_from(d0, peer, b"c").unwrap();
        assert_eq!(recv_from_source(&client).1, SocketAddr::V4(d0));
    }

    #[test]
    fn tproxy_udp_zero_reply_socket_cap_counts_as_one() {
        let Some(mut socket) = privileged_socket(0) else {
            return;
        };
        let (client, peer) = client();
        for dst in [non_local(41, 9000), non_local(42, 9000)] {
            socket.send_from(dst, peer, b"z").unwrap();
            assert_eq!(recv_from_source(&client).1, SocketAddr::V4(dst));
            assert_eq!(socket.reply_socket_count(), 1);
        }
    }

    /// dnsmasq-style services bind `0.0.0.0:P` with `SO_REUSEADDR`; the reply
    /// socket sets it too, so both coexist.
    #[test]
    fn tproxy_udp_reply_coexists_with_reuseaddr_wildcard_socket() {
        let Some(mut socket) = privileged_socket(8) else {
            return;
        };
        let (client, peer) = client();
        let svc = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None).unwrap();
        svc.set_reuse_address(true).unwrap();
        svc.bind(&SocketAddr::from(([0, 0, 0, 0], 0)).into())
            .unwrap();
        let port = svc.local_addr().unwrap().as_socket_ipv4().unwrap().port();
        let orig_dst = loopback(port);
        socket.send_from(orig_dst, peer, b"x").unwrap();
        assert_eq!(recv_from_source(&client).1, SocketAddr::V4(orig_dst));
    }

    #[test]
    fn tproxy_udp_reply_fails_instead_of_using_another_source_port() {
        let Some(mut socket) = privileged_socket(8) else {
            return;
        };
        let (client, peer) = client();
        // A plain wildcard socket (no SO_REUSEADDR) owns this port exclusively.
        let owner = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let busy = loopback(owner.local_addr().unwrap().port());
        assert_bind_failed(socket.send_from(busy, peer, b"x"), busy);
        assert_no_datagram(&client);
        assert_eq!(socket.reply_socket_count(), 0);
    }

    #[test]
    fn tproxy_udp_failed_reply_bind_keeps_cached_socket() {
        let Some(mut socket) = privileged_socket(1) else {
            return;
        };
        let (client, peer) = client();
        let live = non_local(51, 4433);
        socket.send_from(live, peer, b"a").unwrap();
        recv_from_source(&client);
        let owner = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let busy = loopback(owner.local_addr().unwrap().port());
        assert_bind_failed(socket.send_from(busy, peer, b"x"), busy);
        assert!(
            socket.has_reply_socket(live),
            "a failed bind must not evict a live reply socket"
        );
    }

    #[test]
    fn tproxy_udp_reply_sockets_close_with_frontend() {
        let Some(mut socket) = privileged_socket(8) else {
            return;
        };
        let (client, peer) = client();
        let orig_dst = non_local(61, 9000);
        socket.send_from(orig_dst, peer, b"x").unwrap();
        recv_from_source(&client);
        assert_eq!(exclusive_bind(orig_dst).err(), Some(libc::EADDRINUSE));
        socket.shutdown().unwrap();
        drop(exclusive_bind(orig_dst).expect("reply socket must close on shutdown"));
        assert!(socket.send_from(orig_dst, peer, b"y").is_err());
        assert_no_datagram(&client);
    }
}
