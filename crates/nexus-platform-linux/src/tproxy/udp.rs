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
    /// 同时保留的回包 socket 上限（每个 `orig_dst` 一个，LRU 淘汰；默认 256）。
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

/// 建立源地址为 `orig_dst` 的回包 socket：`IP_TRANSPARENT` 允许 bind 非本机地址，
/// `SO_REUSEADDR` 允许多个 `orig_dst` 共享端口号；本机已有 socket 独占该地址时
/// bind 失败（`BindFailed`），调用方丢弃回包而不是改用其它源端口。
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
                operation: "sendmsg",
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
    fn privileged_socket(max_reply_sockets: usize) -> Option<TproxyUdpSocket> {
        let config = TproxyUdpConfig {
            listen: loopback(0),
            max_reply_sockets,
            ..TproxyUdpConfig::default()
        };
        match TproxyUdpSocket::bind(&config) {
            Ok(socket) => Some(socket),
            Err(
                TransparentIngressError::PermissionDenied { .. }
                | TransparentIngressError::CapabilityUnavailable { .. },
            ) => None,
            Err(other) => panic!("unexpected bind error: {other}"),
        }
    }

    fn free_loopback_port() -> SocketAddrV4 {
        let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        match probe.local_addr().unwrap() {
            SocketAddr::V4(addr) => addr,
            SocketAddr::V6(_) => unreachable!("bound to an IPv4 address"),
        }
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

    #[test]
    fn tproxy_udp_reply_comes_from_orig_dst_ip_and_port() {
        let Some(mut socket) = privileged_socket(8) else {
            return;
        };
        let (client, peer) = client();
        let orig_dst = free_loopback_port();
        for payload in [&b"first"[..], b"second"] {
            socket.send_from(orig_dst, peer, payload).unwrap();
            let mut buf = [0u8; 64];
            let (n, from) = client.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..n], payload);
            assert_eq!(
                from,
                SocketAddr::V4(orig_dst),
                "reply source must be orig_dst"
            );
        }
        assert_eq!(
            socket.reply_socket_count(),
            1,
            "one reply socket per orig_dst"
        );
    }

    #[test]
    fn tproxy_udp_reply_sockets_are_bounded_lru() {
        let Some(mut socket) = privileged_socket(2) else {
            return;
        };
        let (client, peer) = client();
        let dsts = [
            free_loopback_port(),
            free_loopback_port(),
            free_loopback_port(),
        ];
        let mut buf = [0u8; 16];
        for dst in [dsts[0], dsts[1], dsts[0], dsts[2]] {
            socket.send_from(dst, peer, b"x").unwrap();
            let (_, from) = client.recv_from(&mut buf).unwrap();
            assert_eq!(from, SocketAddr::V4(dst));
        }
        // dsts[1] was least recently used when dsts[2] needed a slot.
        assert_eq!(socket.reply_socket_count(), 2);
        assert!(socket.has_reply_socket(dsts[0]));
        assert!(!socket.has_reply_socket(dsts[1]));
        assert!(socket.has_reply_socket(dsts[2]));
    }

    #[test]
    fn tproxy_udp_reply_fails_instead_of_using_another_source_port() {
        let Some(mut socket) = privileged_socket(8) else {
            return;
        };
        let (client, peer) = client();
        // A plain socket (no SO_REUSEADDR) owns this address exclusively.
        let owner = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let SocketAddr::V4(busy) = owner.local_addr().unwrap() else {
            unreachable!("bound to an IPv4 address")
        };
        assert!(socket.send_from(busy, peer, b"x").is_err());
        client
            .set_read_timeout(Some(std::time::Duration::from_millis(200)))
            .unwrap();
        let mut buf = [0u8; 16];
        assert!(
            client.recv_from(&mut buf).is_err(),
            "no reply may be sent from a different source"
        );
        assert_eq!(socket.reply_socket_count(), 0);
    }
}
