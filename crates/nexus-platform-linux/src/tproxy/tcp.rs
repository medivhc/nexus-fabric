//! TPROXY TCP listener（spec §9.1 / §13.2 S1）。
//!
//! `IP_TRANSPARENT` 让 accept 后的 socket local address 等于原始目的地；
//! 这里把该契约显式暴露为 `AcceptedTcpStream.orig_dst`，绝不回退到
//! listener / peer 地址。

use std::io;
use std::net::{SocketAddr, SocketAddrV4, TcpStream};
use std::os::fd::{FromRawFd, RawFd};

use nexus_platform::{AcceptedTcpStream, TransparentIngressError, TransparentTcpIngress};

use super::IP_TRANSPARENT;
use super::sockaddr::{from_sockaddr_in, to_sockaddr_in};

/// TCP listener 配置。
#[derive(Debug, Clone)]
pub struct TproxyTcpConfig {
    /// 监听地址。
    pub listen: SocketAddrV4,
    /// `listen(2)` backlog（默认 1024）。
    pub backlog: u32,
    /// 必须为 false（本 run IPv4-only）。
    pub ipv6: bool,
}

impl Default for TproxyTcpConfig {
    fn default() -> Self {
        Self {
            listen: SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, 7895),
            backlog: 1024,
            ipv6: false,
        }
    }
}

/// TCP 透明 listener。
#[derive(Debug)]
pub struct TproxyTcpListener {
    fd: RawFd,
    listen: SocketAddrV4,
    started: bool,
    closed: bool,
}

impl TproxyTcpListener {
    /// 创建 socket、设置 `IP_TRANSPARENT`、bind 并 listen。
    ///
    /// # Errors
    ///
    /// 权限不足 → `PermissionDenied`；内核不支持 → `CapabilityUnavailable`；
    /// bind 失败 → `BindFailed`；其它 → `Io`。
    pub fn bind(config: &TproxyTcpConfig) -> Result<Self, TransparentIngressError> {
        if config.ipv6 {
            return Err(TransparentIngressError::UnsupportedFamily {
                family: libc::AF_INET6 as u16,
            });
        }
        // SAFETY: socket(2) has no pointer arguments; the returned fd is owned
        // by this struct and closed exactly once in `shutdown`/`Drop`.
        let fd = unsafe {
            libc::socket(
                libc::AF_INET,
                libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                0,
            )
        };
        if fd < 0 {
            return Err(map_socket_errno("socket"));
        }
        let listener = Self {
            fd,
            listen: config.listen,
            started: false,
            closed: false,
        };
        listener.set_int_opt(IP_TRANSPARENT, 1, "IP_TRANSPARENT")?;
        let addr = to_sockaddr_in(config.listen);
        // SAFETY: `addr` is a fully initialized sockaddr_in and the fd is a
        // valid AF_INET socket owned by `listener`.
        let rc = unsafe {
            libc::bind(
                listener.fd,
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
        // SAFETY: listener.fd is a valid bound stream socket.
        let rc = unsafe { libc::listen(listener.fd, clamp_backlog(config.backlog)) };
        if rc != 0 {
            return Err(TransparentIngressError::Io {
                operation: "listen",
                message: io::Error::last_os_error().to_string(),
            });
        }
        Ok(listener)
    }

    fn set_int_opt(
        &self,
        opt: libc::c_int,
        value: libc::c_int,
        name: &'static str,
    ) -> Result<(), TransparentIngressError> {
        // SAFETY: fd is valid; `value` outlives the call and the length matches
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

fn clamp_backlog(backlog: u32) -> libc::c_int {
    libc::c_int::try_from(backlog).unwrap_or(libc::c_int::MAX)
}

impl TransparentTcpIngress for TproxyTcpListener {
    fn start(&mut self) -> Result<(), TransparentIngressError> {
        self.started = true;
        Ok(())
    }

    fn local_addr(&self) -> Result<SocketAddr, TransparentIngressError> {
        // SAFETY: sockaddr_in is plain-old-data; zeroing is a valid initial value.
        let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        // SAFETY: `addr`/`len` are valid out-params sized for sockaddr_in.
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
        // SAFETY: kernel filled `addr` as sockaddr_in (AF_INET socket).
        Ok(SocketAddr::V4(unsafe { from_sockaddr_in(&addr) }))
    }

    fn accept(
        &mut self,
        now_millis: u64,
    ) -> Result<Option<AcceptedTcpStream>, TransparentIngressError> {
        if self.closed {
            return Err(TransparentIngressError::Io {
                operation: "accept",
                message: "listener closed".to_string(),
            });
        }
        // SAFETY: fd is a valid listening socket; accept4 writes only through
        // the returned fd, and NULL address pointers are allowed by the API.
        let accepted = unsafe {
            libc::accept4(
                self.fd,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            )
        };
        if accepted < 0 {
            let err = io::Error::last_os_error();
            return match err.raw_os_error() {
                Some(libc::EAGAIN) => Ok(None),
                Some(libc::EPERM) | Some(libc::EACCES) => {
                    Err(TransparentIngressError::PermissionDenied {
                        operation: "accept",
                        errno: err.raw_os_error().unwrap_or(0),
                    })
                }
                _ => Err(TransparentIngressError::Io {
                    operation: "accept",
                    message: err.to_string(),
                }),
            };
        }
        let peer = peer_addr(accepted)?;
        let orig_dst = local_addr_of(accepted)?;
        if orig_dst == self.listen {
            // SAFETY: `accepted` is a fresh fd owned here; close on the error
            // path before returning so it is not leaked.
            unsafe { libc::close(accepted) };
            return Err(TransparentIngressError::OrigDstMissing {
                peer: peer.to_string(),
            });
        }
        if orig_dst.port() == 0 {
            // SAFETY: `accepted` is a fresh fd owned here; close before return.
            unsafe { libc::close(accepted) };
            return Err(TransparentIngressError::OrigDstInvalid {
                raw: orig_dst.to_string(),
            });
        }
        // SAFETY: `accepted` is a valid, uniquely owned socket fd; ownership is
        // transferred to the TcpStream and never used through the raw fd again.
        let stream = unsafe { TcpStream::from_raw_fd(accepted) };
        Ok(Some(AcceptedTcpStream {
            stream,
            peer,
            orig_dst,
            accepted_at_millis: now_millis,
        }))
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

impl Drop for TproxyTcpListener {
    fn drop(&mut self) {
        if !self.closed {
            self.closed = true;
            // SAFETY: fd is owned and not closed elsewhere (`closed` guard).
            unsafe { libc::close(self.fd) };
        }
    }
}

fn peer_addr(fd: RawFd) -> Result<SocketAddrV4, TransparentIngressError> {
    // SAFETY: sockaddr_in is plain-old-data; zeroing is a valid initial value.
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    // SAFETY: valid out-params for getpeername on an accepted AF_INET socket.
    let rc =
        unsafe { libc::getpeername(fd, (&mut addr as *mut libc::sockaddr_in).cast(), &mut len) };
    if rc != 0 {
        return Err(TransparentIngressError::Io {
            operation: "getpeername",
            message: io::Error::last_os_error().to_string(),
        });
    }
    if addr.sin_family as i32 != libc::AF_INET {
        return Err(TransparentIngressError::UnsupportedFamily {
            family: addr.sin_family as u16,
        });
    }
    // SAFETY: kernel filled `addr` as sockaddr_in.
    Ok(unsafe { from_sockaddr_in(&addr) })
}

fn local_addr_of(fd: RawFd) -> Result<SocketAddrV4, TransparentIngressError> {
    // SAFETY: sockaddr_in is plain-old-data; zeroing is a valid initial value.
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    // SAFETY: valid out-params for getsockname on an accepted AF_INET socket.
    let rc =
        unsafe { libc::getsockname(fd, (&mut addr as *mut libc::sockaddr_in).cast(), &mut len) };
    if rc != 0 {
        return Err(TransparentIngressError::Io {
            operation: "getsockname",
            message: io::Error::last_os_error().to_string(),
        });
    }
    if addr.sin_family as i32 != libc::AF_INET {
        return Err(TransparentIngressError::UnsupportedFamily {
            family: addr.sin_family as u16,
        });
    }
    // SAFETY: kernel filled `addr` as sockaddr_in.
    Ok(unsafe { from_sockaddr_in(&addr) })
}

fn map_socket_errno(operation: &'static str) -> TransparentIngressError {
    let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
    match errno {
        libc::EPERM | libc::EACCES => {
            TransparentIngressError::PermissionDenied { operation, errno }
        }
        libc::EPROTONOSUPPORT | libc::ENOPROTOOPT => {
            TransparentIngressError::CapabilityUnavailable {
                capability: "AF_INET/SOCK_STREAM",
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
        SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, port)
    }

    #[test]
    fn tproxy_tcp_bind_reports_permission_or_starts() {
        let config = TproxyTcpConfig {
            listen: loopback(0),
            ..TproxyTcpConfig::default()
        };
        match TproxyTcpListener::bind(&config) {
            Ok(mut listener) => {
                listener.start().unwrap();
                assert!(listener.local_addr().is_ok());
                // 非阻塞 accept 在无连接时返回 None，不 panic。
                assert!(listener.accept(1).unwrap().is_none());
                listener.shutdown().unwrap();
            }
            Err(TransparentIngressError::PermissionDenied { operation, .. }) => {
                assert_eq!(operation, "setsockopt");
            }
            Err(TransparentIngressError::CapabilityUnavailable { .. }) => {}
            Err(other) => panic!("unexpected bind error: {other}"),
        }
    }

    #[test]
    fn tproxy_tcp_rejects_ipv6_config() {
        let config = TproxyTcpConfig {
            listen: loopback(0),
            ipv6: true,
            ..TproxyTcpConfig::default()
        };
        let err = TproxyTcpListener::bind(&config).unwrap_err();
        assert!(matches!(
            err,
            TransparentIngressError::UnsupportedFamily { .. }
        ));
    }

    #[test]
    fn tproxy_tcp_shutdown_is_idempotent() {
        let config = TproxyTcpConfig {
            listen: loopback(0),
            ..TproxyTcpConfig::default()
        };
        if let Ok(mut listener) = TproxyTcpListener::bind(&config) {
            listener.shutdown().unwrap();
            listener.shutdown().unwrap();
        }
    }
}
