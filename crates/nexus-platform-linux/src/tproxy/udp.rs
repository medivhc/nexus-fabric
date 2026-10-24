//! TPROXY UDP socket（spec §9.1 / §13.2 S2）。
//!
//! 单 `SOCK_DGRAM` socket：`recvmsg` 解析 `IP_ORIGDSTADDR` ancillary 得到原始
//! 目的地；回包用 `sendmsg` + `IP_PKTINFO`（`ipi_spec_dst = orig_dst`）保持
//! 源地址。per-flow 状态由 core 的 `TransparentPipeline` 持有，这里无状态。

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::RawFd;

use nexus_platform::{ReceivedDatagram, TransparentIngressError, TransparentUdpIngress};

use super::sockaddr::{find_orig_dst, from_sockaddr_in, parse_cmsgs, to_sockaddr_in};
use super::{IP_PKTINFO, IP_RECVORIGDSTADDR, IP_TRANSPARENT};

/// UDP socket 配置。
#[derive(Debug, Clone)]
pub struct TproxyUdpConfig {
    /// 监听地址。
    pub listen: SocketAddrV4,
    /// `SO_RCVBUF` 初始值（默认 1 MiB）。
    pub recv_buffer_bytes: usize,
    /// 必须为 false（本 run IPv4-only）。
    pub ipv6: bool,
}

impl Default for TproxyUdpConfig {
    fn default() -> Self {
        Self {
            listen: SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 7895),
            recv_buffer_bytes: 1024 * 1024,
            ipv6: false,
        }
    }
}

/// UDP 透明 socket。
#[derive(Debug)]
pub struct TproxyUdpSocket {
    fd: RawFd,
    started: bool,
    closed: bool,
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

    fn set_int_opt(
        &self,
        opt: libc::c_int,
        value: libc::c_int,
        name: &'static str,
    ) -> Result<(), TransparentIngressError> {
        // SAFETY: fd is valid; `value` outlives the call and its length matches
        // the int option expected by setsockopt(2).
        let rc = unsafe {
            libc::setsockopt(
                self.fd,
                libc::IPPROTO_IP,
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
}

impl TransparentUdpIngress for TproxyUdpSocket {
    fn start(&mut self) -> Result<(), TransparentIngressError> {
        self.started = true;
        Ok(())
    }

    fn local_addr(&self) -> Result<SocketAddr, TransparentIngressError> {
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
        let mut peer: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        let mut iov = libc::iovec {
            iov_base: payload.as_mut_ptr().cast(),
            iov_len: payload.len(),
        };
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
        let mut dest = to_sockaddr_in(peer);
        let control = build_pktinfo_control(orig_dst);
        let mut iov = libc::iovec {
            iov_base: payload.as_ptr().cast_mut().cast(),
            iov_len: payload.len(),
        };
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_name = (&mut dest as *mut libc::sockaddr_in).cast();
        msg.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_ptr().cast_mut().cast();
        msg.msg_controllen = control.len();
        // SAFETY: all pointers reference live buffers with the stated lengths;
        // sendmsg only reads them.
        let n = unsafe { libc::sendmsg(self.fd, &msg, 0) };
        if n < 0 {
            let err = io::Error::last_os_error();
            let errno = err.raw_os_error().unwrap_or(0);
            return Err(match errno {
                libc::EINVAL | libc::EPERM | libc::EACCES => {
                    TransparentIngressError::SockOptFailed {
                        opt: "IP_PKTINFO",
                        errno,
                    }
                }
                _ => TransparentIngressError::Io {
                    operation: "sendmsg",
                    message: err.to_string(),
                },
            });
        }
        Ok(usize::try_from(n).unwrap_or(0))
    }

    fn shutdown(&mut self) -> Result<(), TransparentIngressError> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
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

/// 构造 `IP_PKTINFO` 控制消息（`ipi_spec_dst = orig_dst.ip()`、ifindex=0）。
///
/// 纯函数便于单测校验布局，不需要真实发送。
pub(crate) fn build_pktinfo_control(orig_dst: SocketAddrV4) -> Vec<u8> {
    let header = std::mem::size_of::<usize>() + 2 * std::mem::size_of::<libc::c_int>();
    let data_len = std::mem::size_of::<libc::in_pktinfo>();
    let len = header + data_len;
    let align = std::mem::size_of::<usize>();
    let padded = (len + align - 1) & !(align - 1);
    let mut out = vec![0u8; padded];
    out[0..std::mem::size_of::<usize>()].copy_from_slice(&len.to_ne_bytes());
    out[std::mem::size_of::<usize>()..std::mem::size_of::<usize>() + 4]
        .copy_from_slice(&libc::IPPROTO_IP.to_ne_bytes());
    out[std::mem::size_of::<usize>() + 4..header].copy_from_slice(&IP_PKTINFO.to_ne_bytes());
    let info = libc::in_pktinfo {
        ipi_ifindex: 0,
        ipi_spec_dst: libc::in_addr {
            s_addr: u32::from_ne_bytes(orig_dst.ip().octets()),
        },
        ipi_addr: libc::in_addr { s_addr: 0 },
    };
    // SAFETY: `info` is a plain-old-data struct; copying its bytes into the
    // control buffer is valid and does not read padding-dependent fields.
    let bytes = unsafe {
        std::slice::from_raw_parts(
            (&info as *const libc::in_pktinfo).cast::<u8>(),
            std::mem::size_of::<libc::in_pktinfo>(),
        )
    };
    out[header..len].copy_from_slice(bytes);
    out
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
    fn tproxy_udp_pktinfo_control_sets_spec_dst() {
        let dst = SocketAddrV4::new(Ipv4Addr::new(10, 200, 2, 2), 53);
        let control = build_pktinfo_control(dst);
        let messages = parse_cmsgs(&control).unwrap();
        assert_eq!(messages.len(), 1);
        let msg = &messages[0];
        assert_eq!(msg.level, libc::IPPROTO_IP);
        assert_eq!(msg.ty, IP_PKTINFO);
        // in_pktinfo: ipi_ifindex (4 bytes) then ipi_spec_dst (4 bytes).
        assert_eq!(&msg.data[0..4], &0i32.to_ne_bytes());
        assert_eq!(&msg.data[4..8], &dst.ip().octets());
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
}
