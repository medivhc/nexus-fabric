//! Length-prefixed framing over the SOCKS5-established TCP stream (X1).
//!
//! Wire format: `len: u16be || payload`, `len <= MAX_DATAGRAM` (1200,
//! fabric S5). [`ProxyTransport`] implements [`UdpTransport`] on top of
//! this framing; the QUIC driver is unaware it is not talking UDP.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Mutex,
};
use std::time::Duration;

use nexus_fabric::UdpTransport;

use crate::{socks5, ProxyError, Socks5ProxyConfig, FRAME_HEADER_LEN, MAX_DATAGRAM};

/// QUIC datagrams over a SOCKS5-established TCP stream (X1).
///
/// Point-to-point: bound to the single CONNECT `target` at construction;
/// [`UdpTransport::send_to`]'s `target` parameter is ignored (the TCP
/// connection *is* the target).
pub struct ProxyTransport {
    stream: Mutex<TcpStream>,
    target: SocketAddr,
    /// Read buffer for atomic `recv_from`: bytes read from the socket but not
    /// yet consumed as a complete frame. A `recv_from` that times out leaves
    /// this buffer untouched, so the next call resumes at a frame boundary.
    read_buf: Vec<u8>,
    handshake_ok: AtomicU64,
    handshake_err: AtomicU64,
    framed_bytes: AtomicU64,
}

impl ProxyTransport {
    /// Wrap an already SOCKS5-connected stream.
    pub fn new(stream: TcpStream, target: SocketAddr) -> Self {
        Self {
            stream: Mutex::new(stream),
            target,
            read_buf: Vec::new(),
            handshake_ok: AtomicU64::new(1),
            handshake_err: AtomicU64::new(0),
            framed_bytes: AtomicU64::new(0),
        }
    }

    /// One-step helper: SOCKS5 handshake then wrap (X4).
    pub fn connect(config: &Socks5ProxyConfig, target: SocketAddr) -> Result<Self, ProxyError> {
        match socks5::socks5_connect(config, target) {
            Ok(stream) => Ok(Self::new(stream, target)),
            Err(e) => Err(e),
        }
    }

    /// The CONNECT target — the real peer as seen by this transport.
    pub fn target(&self) -> SocketAddr {
        self.target
    }

    /// X6: `(handshake_ok, handshake_err, framed_bytes)`.
    ///
    /// - `handshake_ok` is 1 if the SOCKS5 handshake succeeded (object exists).
    /// - `handshake_err` counts post-handshake protocol/framing errors
    ///   (e.g. oversize frame, buffer overflow). A failed SOCKS5 handshake
    ///   prevents object creation, so it is reported via `Err`, not here.
    /// - `framed_bytes` counts payload bytes sent/recv'd (excludes headers).
    pub fn counters(&self) -> (u64, u64, u64) {
        (
            self.handshake_ok.load(Ordering::Relaxed),
            self.handshake_err.load(Ordering::Relaxed),
            self.framed_bytes.load(Ordering::Relaxed),
        )
    }

    fn record_err(&self) {
        self.handshake_err.fetch_add(1, Ordering::Relaxed);
    }
}

impl UdpTransport for ProxyTransport {
    fn recv_from(&mut self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        // Atomic framing: bytes are first accumulated in `read_buf`. A socket
        // timeout leaves `read_buf` untouched, so the next call resumes at a
        // frame boundary. Without this, a timeout between the 2-byte header
        // and the payload would desynchronize the stream.
        loop {
            // Try to parse a complete frame from the buffer.
            if self.read_buf.len() >= FRAME_HEADER_LEN {
                let len = u16::from_be_bytes([self.read_buf[0], self.read_buf[1]]) as usize;
                if len > MAX_DATAGRAM {
                    self.record_err();
                    return Err(ProxyError::FrameTooLarge(len).into());
                }
                if self.read_buf.len() >= FRAME_HEADER_LEN + len {
                    if len > buf.len() {
                        self.record_err();
                        // Drain the frame to keep the stream synchronized,
                        // then report the overflow.
                        self.read_buf.drain(..FRAME_HEADER_LEN + len);
                        return Err(ProxyError::FrameOverflow {
                            frame: len,
                            buf: buf.len(),
                        }
                        .into());
                    }
                    buf[..len]
                        .copy_from_slice(&self.read_buf[FRAME_HEADER_LEN..FRAME_HEADER_LEN + len]);
                    self.read_buf.drain(..FRAME_HEADER_LEN + len);
                    self.framed_bytes.fetch_add(len as u64, Ordering::Relaxed);
                    // The "source address" is the real peer (decapsulated), per UdpTransport.
                    return Ok((len, self.target));
                }
            }
            // Need more bytes: read from the socket (honors its read timeout).
            let mut stream = self
                .stream
                .lock()
                .map_err(|_| std::io::Error::other("proxy transport mutex poisoned"))?;
            let mut tmp = [0u8; 8192];
            match stream.read(&mut tmp) {
                Ok(0) => {
                    self.record_err();
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "proxy connection closed",
                    ));
                }
                Ok(n) => {
                    self.read_buf.extend_from_slice(&tmp[..n]);
                }
                Err(e) => {
                    // Timeout or other error: buffer untouched, caller retries.
                    return Err(e);
                }
            }
        }
    }

    fn send_to(&self, buf: &[u8], _target: SocketAddr) -> std::io::Result<usize> {
        if buf.len() > MAX_DATAGRAM {
            return Err(ProxyError::FrameTooLarge(buf.len()).into());
        }
        let mut stream = self
            .stream
            .lock()
            .map_err(|_| std::io::Error::other("proxy transport mutex poisoned"))?;
        // Two writes: header then payload. (A single writev would save a
        // syscall; not worth the complexity at P1.)
        stream.write_all(&(buf.len() as u16).to_be_bytes())?;
        stream.write_all(buf)?;
        self.framed_bytes
            .fetch_add(buf.len() as u64, Ordering::Relaxed);
        Ok(buf.len())
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        let stream = self
            .stream
            .lock()
            .map_err(|_| std::io::Error::other("proxy transport mutex poisoned"))?;
        stream.set_read_timeout(timeout)
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        let stream = self
            .stream
            .lock()
            .map_err(|_| std::io::Error::other("proxy transport mutex poisoned"))?;
        stream.local_addr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn loopback_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();
        (client, server)
    }

    fn target() -> SocketAddr {
        "127.0.0.1:9999".parse().unwrap()
    }

    #[test]
    fn frame_roundtrip() {
        let (client, mut server) = loopback_pair();
        let mut tx = ProxyTransport::new(client, target());

        // send_to frames: server reads 2-byte len + payload.
        let payload = b"hello-framed";
        let n = tx.send_to(payload, target()).unwrap();
        assert_eq!(n, payload.len());

        let mut hdr = [0u8; 2];
        server.read_exact(&mut hdr).unwrap();
        let len = u16::from_be_bytes(hdr) as usize;
        assert_eq!(len, payload.len());
        let mut got = vec![0u8; len];
        server.read_exact(&mut got).unwrap();
        assert_eq!(got, payload);

        // recv_from deframes: server writes a frame, transport returns payload.
        let reply = b"world-framed";
        server
            .write_all(&(reply.len() as u16).to_be_bytes())
            .unwrap();
        server.write_all(reply).unwrap();
        let mut buf = [0u8; 1500];
        let (m, src) = tx.recv_from(&mut buf).unwrap();
        assert_eq!(m, reply.len());
        assert_eq!(&buf[..m], reply);
        assert_eq!(src, target());

        // X6 counters moved.
        let (_, _, framed) = tx.counters();
        assert_eq!(framed, (payload.len() + reply.len()) as u64);
    }

    #[test]
    fn send_to_rejects_oversize() {
        let (client, _server) = loopback_pair();
        let tx = ProxyTransport::new(client, target());
        let big = vec![0u8; MAX_DATAGRAM + 1];
        let err = tx.send_to(&big, target()).unwrap_err();
        // X1: oversize send_to must be InvalidInput, never silently truncated.
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("too large"));
    }

    #[test]
    fn send_to_accepts_max_datagram() {
        let (client, mut server) = loopback_pair();
        let tx = ProxyTransport::new(client, target());
        let max = vec![0xABu8; MAX_DATAGRAM];
        let n = tx.send_to(&max, target()).unwrap();
        assert_eq!(n, MAX_DATAGRAM);
        let mut hdr = [0u8; 2];
        server.read_exact(&mut hdr).unwrap();
        assert_eq!(u16::from_be_bytes(hdr) as usize, MAX_DATAGRAM);
    }

    #[test]
    fn recv_from_rejects_oversize_frame() {
        let (client, mut server) = loopback_pair();
        let mut tx = ProxyTransport::new(client, target());
        // Malicious/buggy peer sends len > MAX_DATAGRAM.
        server
            .write_all(&((MAX_DATAGRAM + 1) as u16).to_be_bytes())
            .unwrap();
        let mut buf = [0u8; 2048];
        let err = tx.recv_from(&mut buf).unwrap_err();
        assert!(err.to_string().contains("too large"));
    }

    #[test]
    fn recv_from_rejects_frame_overflow() {
        let (client, mut server) = loopback_pair();
        let mut tx = ProxyTransport::new(client, target());
        server.write_all(&100u16.to_be_bytes()).unwrap();
        server.write_all(&[0u8; 100]).unwrap();
        // Caller buffer smaller than the frame.
        let mut small = [0u8; 10];
        let err = tx.recv_from(&mut small).unwrap_err();
        assert!(err.to_string().contains("exceeds buffer"));
    }

    #[test]
    fn local_addr_delegates() {
        let (client, _server) = loopback_pair();
        let expected = client.local_addr().unwrap();
        let tx = ProxyTransport::new(client, target());
        assert_eq!(tx.local_addr().unwrap(), expected);
    }

    #[test]
    fn target_ignored_in_send_to() {
        // X1: send_to's target param is ignored; the TCP connection is the target.
        let (client, mut server) = loopback_pair();
        let tx = ProxyTransport::new(client, target());
        let other: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        tx.send_to(b"ping", other).unwrap(); // must not error, must go to the TCP peer
        let mut hdr = [0u8; 2];
        server.read_exact(&mut hdr).unwrap();
        assert_eq!(u16::from_be_bytes(hdr), 4);
    }

    #[test]
    fn set_read_timeout_roundtrip() {
        let (client, _server) = loopback_pair();
        let tx = ProxyTransport::new(client, target());
        tx.set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        tx.set_read_timeout(None).unwrap();
    }

    #[test]
    fn transport_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<ProxyTransport>();
        assert_send::<Box<dyn UdpTransport>>();
    }
}
