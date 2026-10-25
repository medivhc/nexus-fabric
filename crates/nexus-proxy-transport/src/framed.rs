//! Length-prefixed framing over a proxy-established TCP stream (X1, T4).
//!
//! Wire format: `len: u16be || payload`, `len <= max_wire`.
//! [`FramedTransport`] is the shared framing core for the SOCKS5 (X1),
//! shadowsocks (T1) and trojan (T2) transports. [`ProxyTransport`] keeps its
//! frozen X-contract public API as a thin wrapper over [`FramedTransport`];
//! its behavior is unchanged since the X freeze.
//!
//! Atomicity (knowledge entry `2026-09-30-proxy-transport-atomic-recv`):
//! `recv_from` either returns one complete datagram or returns an error
//! (e.g. timeout) **without consuming any bytes** — `read_buf` is left
//! untouched on error so the next call resumes at a frame boundary.
//! `read_exact` straight on the socket is wrong here: a timeout between the
//! 2-byte header and the payload would permanently desynchronize the stream.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};
use std::time::Duration;

use nexus_fabric::UdpTransport;

use crate::{socks5, ProxyError, Socks5ProxyConfig, FRAME_HEADER_LEN, MAX_DATAGRAM};

/// X6/T6 counters, shareable via [`FramedTransport::counters_handle`].
///
/// The transport is moved into the QUIC driver (`connect_with_transport`),
/// so the E4 examples clone this handle *before* the move and read the
/// counters *after* the transfer. (P1-3 fix.)
#[derive(Clone, Default, Debug)]
pub struct Counters {
    handshake_ok: Arc<AtomicU64>,
    handshake_err: Arc<AtomicU64>,
    framed_bytes: Arc<AtomicU64>,
}

impl Counters {
    /// Snapshot as `(handshake_ok, handshake_err, framed_bytes)`.
    pub fn get(&self) -> (u64, u64, u64) {
        (
            self.handshake_ok.load(Ordering::Relaxed),
            self.handshake_err.load(Ordering::Relaxed),
            self.framed_bytes.load(Ordering::Relaxed),
        )
    }

    /// Mark handshake success (T6; T7 reuses for TLS trojan).
    pub(crate) fn set_handshake_ok(&self) {
        self.handshake_ok.store(1, Ordering::Relaxed);
    }
}

/// Shared length-prefix framing core (T4).
///
/// Point-to-point: bound to the single proxy `target` at construction.
/// `max_wire` is the largest accepted wire frame: `MAX_DATAGRAM` (1200) for
/// plaintext framing (SOCKS5/trojan), `MAX_SEALED_FRAME` (1266) for the
/// shadowsocks sealed frames. The *datagram* (plaintext) limit stays
/// `MAX_DATAGRAM` for every transport (X1).
pub struct FramedTransport {
    stream: Mutex<TcpStream>,
    target: SocketAddr,
    /// Read buffer for atomic `recv_from`: bytes read from the socket but not
    /// yet consumed as a complete frame. A `recv_from` that times out leaves
    /// this buffer untouched, so the next call resumes at a frame boundary.
    /// Bounded at `FRAME_HEADER_LEN + max_wire` (P1-4).
    read_buf: Vec<u8>,
    counters: Counters,
    max_wire: usize,
}

impl FramedTransport {
    /// Plaintext framing core (`max_wire = MAX_DATAGRAM`).
    pub fn new(stream: TcpStream, target: SocketAddr) -> Self {
        Self::with_max_wire(stream, target, MAX_DATAGRAM)
    }

    /// Framing core with a custom wire-frame bound (ss sealed frames).
    pub fn with_max_wire(stream: TcpStream, target: SocketAddr, max_wire: usize) -> Self {
        Self {
            stream: Mutex::new(stream),
            target,
            read_buf: Vec::new(),
            counters: Counters::default(),
            max_wire,
        }
    }

    /// The accepted wire-frame bound.
    pub fn max_wire(&self) -> usize {
        self.max_wire
    }

    /// The proxy target — the real peer as seen by this transport.
    pub fn target(&self) -> SocketAddr {
        self.target
    }

    /// `(handshake_ok, handshake_err, framed_bytes)` (X6/T6).
    pub fn counters(&self) -> (u64, u64, u64) {
        self.counters.get()
    }

    /// Cloneable handle to the counters. Use this when the transport is
    /// moved into the driver but counters must be read after I/O.
    pub fn counters_handle(&self) -> Counters {
        self.counters.clone()
    }

    /// Record a successful handshake (called by each transport's `connect`).
    pub(crate) fn set_handshake_ok(&self) {
        self.counters.handshake_ok.store(1, Ordering::Relaxed);
    }

    pub(crate) fn record_err(&self) {
        self.counters.handshake_err.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn add_framed_bytes(&self, n: u64) {
        self.counters.framed_bytes.fetch_add(n, Ordering::Relaxed);
    }

    /// Write one length-prefixed frame. Callers enforce the datagram limit
    /// first; the `max_wire` check here is a safety net.
    pub(crate) fn send_frame(&self, blob: &[u8]) -> std::io::Result<()> {
        if blob.len() > self.max_wire {
            self.record_err();
            return Err(ProxyError::FrameTooLarge(blob.len()).into());
        }
        let mut stream = self
            .stream
            .lock()
            .map_err(|_| std::io::Error::other("proxy transport mutex poisoned"))?;
        // Two writes: header then payload. (A single writev would save a
        // syscall; not worth the complexity at this phase.)
        stream.write_all(&(blob.len() as u16).to_be_bytes())?;
        stream.write_all(blob)?;
        Ok(())
    }

    /// Read one complete frame into `out`; returns the payload length.
    ///
    /// Atomic: on error (including timeout) `read_buf` is untouched.
    /// If the frame does not fit `out`, the frame is drained to keep the
    /// stream synchronized and `FrameOverflow` is returned.
    pub(crate) fn recv_frame(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        loop {
            // Try to parse a complete frame from the buffer.
            if self.read_buf.len() >= FRAME_HEADER_LEN {
                let len = u16::from_be_bytes([self.read_buf[0], self.read_buf[1]]) as usize;
                if len > self.max_wire {
                    self.record_err();
                    return Err(ProxyError::FrameTooLarge(len).into());
                }
                if self.read_buf.len() >= FRAME_HEADER_LEN + len {
                    if len > out.len() {
                        self.record_err();
                        // Drain the frame to keep the stream synchronized,
                        // then report the overflow.
                        self.read_buf.drain(..FRAME_HEADER_LEN + len);
                        return Err(ProxyError::FrameOverflow {
                            frame: len,
                            buf: out.len(),
                        }
                        .into());
                    }
                    out[..len]
                        .copy_from_slice(&self.read_buf[FRAME_HEADER_LEN..FRAME_HEADER_LEN + len]);
                    self.read_buf.drain(..FRAME_HEADER_LEN + len);
                    return Ok(len);
                }
            }
            // P1-4: bound the buffer. If we have more than a max-size frame
            // but still can't parse one, the peer is sending garbage.
            if self.read_buf.len() > FRAME_HEADER_LEN + self.max_wire {
                self.read_buf.clear();
                self.record_err();
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "proxy: read buffer exceeded max frame size",
                ));
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
                    // Note: bound check is at the top of the loop, after the
                    // parse attempt. A single read may bring multiple frames;
                    // we must try to parse before declaring the buffer full.
                }
                Err(e) => {
                    // Timeout or other error: buffer untouched, caller retries.
                    return Err(e);
                }
            }
        }
    }
}

impl UdpTransport for FramedTransport {
    fn recv_from(&mut self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        let n = self.recv_frame(buf)?;
        self.add_framed_bytes(n as u64);
        // The "source address" is the real peer (decapsulated), per UdpTransport.
        Ok((n, self.target))
    }

    fn send_to(&self, buf: &[u8], _target: SocketAddr) -> std::io::Result<usize> {
        // X1: oversize datagrams are rejected, never silently truncated.
        // The `target` parameter is ignored: the TCP connection *is* the target.
        if buf.len() > MAX_DATAGRAM {
            return Err(ProxyError::FrameTooLarge(buf.len()).into());
        }
        self.send_frame(buf)?;
        self.add_framed_bytes(buf.len() as u64);
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

/// QUIC datagrams over a SOCKS5-established TCP stream (X1).
///
/// Frozen X-contract public API: thin wrapper over [`FramedTransport`].
/// Behavior is unchanged since the X freeze; `new` still records
/// `handshake_ok = 1` (object exists ⇒ SOCKS5 handshake succeeded).
pub struct ProxyTransport {
    inner: FramedTransport,
}

impl ProxyTransport {
    /// Wrap an already SOCKS5-connected stream.
    pub fn new(stream: TcpStream, target: SocketAddr) -> Self {
        let inner = FramedTransport::new(stream, target);
        inner.set_handshake_ok();
        Self { inner }
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
        self.inner.target()
    }

    /// X6: `(handshake_ok, handshake_err, framed_bytes)`.
    ///
    /// - `handshake_ok` is 1 if the SOCKS5 handshake succeeded (object exists).
    /// - `handshake_err` counts post-handshake protocol/framing errors
    ///   (e.g. oversize frame, buffer overflow). A failed SOCKS5 handshake
    ///   prevents object creation, so it is reported via `Err`, not here.
    /// - `framed_bytes` counts payload bytes sent/recv'd (excludes headers).
    pub fn counters(&self) -> (u64, u64, u64) {
        self.inner.counters()
    }

    /// Cloneable handle to the X6 counters. Use this when the transport is
    /// moved into the driver but counters must be read after I/O.
    pub fn counters_handle(&self) -> Counters {
        self.inner.counters_handle()
    }
}

impl UdpTransport for ProxyTransport {
    fn recv_from(&mut self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        self.inner.recv_from(buf)
    }

    /// [`UdpTransport::send_to`]'s `target` parameter is ignored (the TCP
    /// connection *is* the target).
    fn send_to(&self, buf: &[u8], target: SocketAddr) -> std::io::Result<usize> {
        self.inner.send_to(buf, target)
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.inner.set_read_timeout(timeout)
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.inner.local_addr()
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
        assert_send::<FramedTransport>();
        assert_send::<Box<dyn UdpTransport>>();
    }

    #[test]
    fn new_marks_handshake_ok() {
        // X6: ProxyTransport::new records handshake_ok = 1 (frozen behavior).
        let (client, _server) = loopback_pair();
        let tx = ProxyTransport::new(client, target());
        assert_eq!(tx.counters().0, 1);
    }

    #[test]
    fn framed_transport_starts_handshake_zero() {
        // FramedTransport itself claims no handshake (B-side / pre-handshake use).
        let (client, _server) = loopback_pair();
        let tx = FramedTransport::new(client, target());
        assert_eq!(tx.counters().0, 0);
        assert_eq!(tx.max_wire(), MAX_DATAGRAM);
    }

    #[test]
    fn with_max_wire_accepts_larger_frames() {
        // T4: the ss path needs wire frames up to MAX_SEALED_FRAME.
        let (client, mut server) = loopback_pair();
        let mut tx = FramedTransport::with_max_wire(client, target(), crate::MAX_SEALED_FRAME);
        assert_eq!(tx.max_wire(), crate::MAX_SEALED_FRAME);
        let big = vec![0xCDu8; crate::MAX_SEALED_FRAME];
        server.write_all(&(big.len() as u16).to_be_bytes()).unwrap();
        server.write_all(&big).unwrap();
        let mut buf = vec![0u8; crate::MAX_SEALED_FRAME];
        let (n, _) = tx.recv_from(&mut buf).unwrap();
        assert_eq!(n, big.len());
        assert_eq!(&buf[..n], &big[..]);
    }

    #[test]
    fn with_max_wire_still_rejects_beyond() {
        let (client, mut server) = loopback_pair();
        let mut tx = FramedTransport::with_max_wire(client, target(), crate::MAX_SEALED_FRAME);
        server
            .write_all(&((crate::MAX_SEALED_FRAME + 1) as u16).to_be_bytes())
            .unwrap();
        let mut buf = vec![0u8; 2048];
        let err = tx.recv_from(&mut buf).unwrap_err();
        assert!(err.to_string().contains("too large"));
    }
}
