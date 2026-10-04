//! SOCKS5 CONNECT handshake (RFC 1928), client side.
//!
//! 1. TCP-connect to the proxy server.
//! 2. Method negotiation: offer `00` (no auth), plus `02` (username/password)
//!    when credentials are configured.
//! 3. RFC 1929 username/password sub-negotiation if the server selects `02`.
//! 4. `CONNECT` to the target (IPv4 / IPv6).
//!
//! All I/O is blocking with explicit timeouts (`connect_timeout`,
//! `handshake_timeout`); a hanging proxy can never block the caller forever
//! (Recovery Semantics in MODULE.md).

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};

use crate::{ProxyError, Socks5ProxyConfig};

/// Perform the SOCKS5 handshake and return a connected `TcpStream`
/// positioned right after the server's CONNECT reply.
pub fn socks5_connect(
    config: &Socks5ProxyConfig,
    target: SocketAddr,
) -> Result<TcpStream, ProxyError> {
    let mut stream = TcpStream::connect_timeout(&config.server, config.connect_timeout)?;
    stream.set_read_timeout(Some(config.handshake_timeout))?;
    stream.set_write_timeout(Some(config.handshake_timeout))?;

    // --- Method negotiation ------------------------------------------------
    let methods: &[u8] = if config.auth.is_some() {
        &[0x00, 0x02]
    } else {
        &[0x00]
    };
    let mut greeting = vec![0x05, methods.len() as u8];
    greeting.extend_from_slice(methods);
    stream.write_all(&greeting)?;

    let mut choice = [0u8; 2];
    stream.read_exact(&mut choice)?;
    if choice[0] != 0x05 {
        return Err(ProxyError::BadReply("method choice: bad version"));
    }
    match choice[1] {
        0x00 => {}
        0x02 => {
            let auth = config.auth.as_ref().ok_or(ProxyError::BadReply(
                "server asked for auth we did not offer",
            ))?;
            let u = auth.username.as_bytes();
            let p = auth.password.as_bytes();
            if u.len() > 255 || p.len() > 255 {
                return Err(ProxyError::BadReply("credential too long"));
            }
            let mut req = vec![0x01, u.len() as u8];
            req.extend_from_slice(u);
            req.push(p.len() as u8);
            req.extend_from_slice(p);
            stream.write_all(&req)?;

            let mut resp = [0u8; 2];
            stream.read_exact(&mut resp)?;
            if resp[0] != 0x01 {
                return Err(ProxyError::BadReply("auth reply: bad version"));
            }
            if resp[1] != 0x00 {
                return Err(ProxyError::AuthFailed);
            }
        }
        0xff => return Err(ProxyError::NoAcceptableAuth),
        _ => return Err(ProxyError::BadReply("method choice: unknown method")),
    }

    // --- CONNECT ------------------------------------------------------------
    let mut req = vec![0x05, 0x01, 0x00];
    match target.ip() {
        std::net::IpAddr::V4(v4) => {
            req.push(0x01);
            req.extend_from_slice(&v4.octets());
        }
        std::net::IpAddr::V6(v6) => {
            req.push(0x04);
            req.extend_from_slice(&v6.octets());
        }
    }
    req.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&req)?;

    // Reply: VER REP RSV ATYP BND.ADDR BND.PORT — BND.ADDR is variable length.
    let mut head = [0u8; 4];
    stream.read_exact(&mut head)?;
    if head[0] != 0x05 {
        return Err(ProxyError::BadReply("connect reply: bad version"));
    }
    if head[1] != 0x00 {
        return Err(ProxyError::ConnectRejected(head[1]));
    }
    let bnd_len = match head[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut l = [0u8; 1];
            stream.read_exact(&mut l)?;
            l[0] as usize
        }
        _ => return Err(ProxyError::BadReply("connect reply: unknown ATYP")),
    };
    let mut bnd = vec![0u8; bnd_len + 2]; // addr + port
    stream.read_exact(&mut bnd)?;

    // Handshake done: clear timeouts; the transport sets its own later.
    stream.set_read_timeout(None)?;
    stream.set_write_timeout(None)?;
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    fn test_config(server: SocketAddr, auth: Option<Socks5Auth>) -> Socks5ProxyConfig {
        Socks5ProxyConfig {
            server,
            auth,
            connect_timeout: Duration::from_secs(5),
            handshake_timeout: Duration::from_secs(5),
        }
    }

    use crate::Socks5Auth;

    /// Scripted fake SOCKS5 server: runs `script` against one accepted
    /// connection, then exits. Returns the listening address.
    fn fake_server(script: impl FnOnce(TcpStream) + Send + 'static) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            script(stream);
        });
        addr
    }

    #[test]
    fn handshake_no_auth_ok() {
        let target: SocketAddr = "127.0.0.1:4433".parse().unwrap();
        let addr = fake_server(move |mut s| {
            // greeting: 05 01 00
            let mut g = [0u8; 3];
            s.read_exact(&mut g).unwrap();
            assert_eq!(g, [0x05, 0x01, 0x00]);
            // choose no-auth
            s.write_all(&[0x05, 0x00]).unwrap();
            // CONNECT 05 01 00 01 7f000001 1151
            let mut c = [0u8; 10];
            s.read_exact(&mut c).unwrap();
            assert_eq!(&c[..4], &[0x05, 0x01, 0x00, 0x01]);
            assert_eq!(&c[4..8], &[127, 0, 0, 1]);
            assert_eq!(u16::from_be_bytes([c[8], c[9]]), 4433);
            // reply success, BND.ADDR = 0.0.0.0:0
            s.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .unwrap();
        });
        let stream = socks5_connect(&test_config(addr, None), target).unwrap();
        assert!(stream.local_addr().is_ok());
    }

    #[test]
    fn handshake_userpass_ok() {
        let target: SocketAddr = "127.0.0.1:4433".parse().unwrap();
        let addr = fake_server(move |mut s| {
            // greeting offers 00 and 02
            let mut g = [0u8; 4];
            s.read_exact(&mut g).unwrap();
            assert_eq!(g, [0x05, 0x02, 0x00, 0x02]);
            // choose user/pass
            s.write_all(&[0x05, 0x02]).unwrap();
            // auth: 01 ulen user plen pass
            let mut ver = [0u8; 1];
            s.read_exact(&mut ver).unwrap();
            assert_eq!(ver[0], 0x01);
            let mut ulen = [0u8; 1];
            s.read_exact(&mut ulen).unwrap();
            let mut u = vec![0u8; ulen[0] as usize];
            s.read_exact(&mut u).unwrap();
            let mut plen = [0u8; 1];
            s.read_exact(&mut plen).unwrap();
            let mut p = vec![0u8; plen[0] as usize];
            s.read_exact(&mut p).unwrap();
            assert_eq!(u, b"user1");
            assert_eq!(p, b"s3cr3t");
            s.write_all(&[0x01, 0x00]).unwrap();
            // CONNECT
            let mut c = [0u8; 10];
            s.read_exact(&mut c).unwrap();
            assert_eq!(c[0], 0x05);
            s.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .unwrap();
        });
        let auth = Socks5Auth {
            username: "user1".into(),
            password: "s3cr3t".into(),
        };
        let stream = socks5_connect(&test_config(addr, Some(auth)), target).unwrap();
        assert!(stream.local_addr().is_ok());
    }

    #[test]
    fn handshake_no_acceptable_auth() {
        let target: SocketAddr = "127.0.0.1:4433".parse().unwrap();
        let addr = fake_server(move |mut s| {
            let mut g = [0u8; 3];
            s.read_exact(&mut g).unwrap();
            s.write_all(&[0x05, 0xff]).unwrap();
        });
        let err = socks5_connect(&test_config(addr, None), target).unwrap_err();
        assert!(matches!(err, ProxyError::NoAcceptableAuth));
    }

    #[test]
    fn handshake_auth_failed() {
        let target: SocketAddr = "127.0.0.1:4433".parse().unwrap();
        let addr = fake_server(move |mut s| {
            let mut g = [0u8; 4];
            s.read_exact(&mut g).unwrap();
            s.write_all(&[0x05, 0x02]).unwrap();
            let mut req = [0u8; 2];
            s.read_exact(&mut req).unwrap(); // 01 ulen (don't care)
                                             // reject
            s.write_all(&[0x01, 0x01]).unwrap();
        });
        let auth = Socks5Auth {
            username: "u".into(),
            password: "p".into(),
        };
        let err = socks5_connect(&test_config(addr, Some(auth)), target).unwrap_err();
        assert!(matches!(err, ProxyError::AuthFailed));
    }

    #[test]
    fn handshake_connect_rejected() {
        let target: SocketAddr = "127.0.0.1:4433".parse().unwrap();
        let addr = fake_server(move |mut s| {
            let mut g = [0u8; 3];
            s.read_exact(&mut g).unwrap();
            s.write_all(&[0x05, 0x00]).unwrap();
            let mut c = [0u8; 10];
            s.read_exact(&mut c).unwrap();
            // REP=0x05 connection refused
            s.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .unwrap();
        });
        let err = socks5_connect(&test_config(addr, None), target).unwrap_err();
        assert!(matches!(err, ProxyError::ConnectRejected(0x05)));
    }

    #[test]
    fn handshake_ipv6_target() {
        let target: SocketAddr = "[::1]:4433".parse().unwrap();
        let addr = fake_server(move |mut s| {
            let mut g = [0u8; 3];
            s.read_exact(&mut g).unwrap();
            s.write_all(&[0x05, 0x00]).unwrap();
            // CONNECT with ATYP=0x04 (16-byte IPv6)
            let mut c = [0u8; 22];
            s.read_exact(&mut c).unwrap();
            assert_eq!(&c[..4], &[0x05, 0x01, 0x00, 0x04]);
            assert_eq!(&c[4..20], &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
            // reply with IPv6 BND.ADDR
            let mut reply = vec![0x05, 0x00, 0x00, 0x04];
            reply.extend_from_slice(&[0u8; 16]);
            reply.extend_from_slice(&[0, 0]);
            s.write_all(&reply).unwrap();
        });
        socks5_connect(&test_config(addr, None), target).unwrap();
    }

    #[test]
    fn handshake_bad_version() {
        let target: SocketAddr = "127.0.0.1:4433".parse().unwrap();
        let addr = fake_server(move |mut s| {
            let mut g = [0u8; 3];
            s.read_exact(&mut g).unwrap();
            s.write_all(&[0x04, 0x00]).unwrap(); // wrong version
        });
        let err = socks5_connect(&test_config(addr, None), target).unwrap_err();
        assert!(matches!(err, ProxyError::BadReply(_)));
    }
}
