//! UDP transport abstraction (S9).
//!
//! The driver talks to the network through [`UdpTransport`] instead of
//! owning a `UdpSocket` directly. [`StdUdpTransport`] is the default
//! implementation (behavior identical to the previous direct-socket code);
//! out-of-tree transports (e.g. `nexus-turn::TurnSocket`) implement the
//! same trait so QUIC can run over a TURN relay.
//!
//! Deletion test (§12): if this trait were removed and the driver went back
//! to a concrete `UdpSocket`, the "QUIC over TURN relay" dimension would
//! collapse — every caller needing a relayed path would have to fork the
//! driver. The trait is the narrow seam that keeps `nexus-fabric` from
//! depending on `nexus-turn` (dependency inversion, S9).

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

/// Byte-level UDP transport used by the fabric driver.
///
/// Signatures mirror `std::net::UdpSocket` so [`StdUdpTransport`] is a
/// trivial delegation. `recv_from` takes `&mut self` (unlike `UdpSocket`'s
/// `&self`) because relayed transports may need to mutate decode state;
/// callers must treat the transport as exclusively borrowed during receive.
pub trait UdpTransport: Send {
    /// Receive one datagram. Returns `(bytes, source address)`.
    ///
    /// For relayed transports the source address is the *real* peer
    /// (decapsulated), not the relay server.
    fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)>;

    /// Send one datagram to `target`. Returns bytes written.
    fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize>;

    /// Set the read timeout used by `recv_from`.
    ///
    /// Same contract as `UdpSocket::set_read_timeout`, including the
    /// platform quirk that `Some(Duration::ZERO)` is rejected with
    /// `InvalidInput` (see driver `min_poll_timeout`).
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;

    /// Local address of this transport.
    ///
    /// For relayed transports this is the *allocated relay address*, not
    /// the underlying direct socket address.
    fn local_addr(&self) -> io::Result<SocketAddr>;
}

/// Default transport: direct delegation to `std::net::UdpSocket`.
#[derive(Debug)]
pub struct StdUdpTransport(pub UdpSocket);

impl StdUdpTransport {
    /// Bind a new UDP socket on `addr`.
    pub fn bind(addr: SocketAddr) -> io::Result<Self> {
        Ok(Self(UdpSocket::bind(addr)?))
    }
}

impl UdpTransport for StdUdpTransport {
    fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.0.recv_from(buf)
    }

    fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        self.0.send_to(buf, target)
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.0.set_read_timeout(timeout)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.local_addr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loopback(n: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], n))
    }

    /// S9: `StdUdpTransport` behaves exactly like a bare `UdpSocket`
    /// (send/recv roundtrip, local_addr, read timeout).
    #[test]
    fn std_transport_matches_socket_behavior() {
        let mut rx = StdUdpTransport::bind(loopback(0)).unwrap();
        let tx = StdUdpTransport::bind(loopback(0)).unwrap();
        let rx_addr = rx.local_addr().unwrap();

        // send_to returns full length, like UdpSocket.
        let n = tx.send_to(b"hello-s9", rx_addr).unwrap();
        assert_eq!(n, 8);

        // recv_from returns (len, real source).
        let mut buf = [0u8; 64];
        let (m, src) = rx.recv_from(&mut buf).unwrap();
        assert_eq!(m, 8);
        assert_eq!(&buf[..m], b"hello-s9");
        assert_eq!(src, tx.local_addr().unwrap());

        // set_read_timeout(None) then back to Some works.
        rx.set_read_timeout(None).unwrap();
        rx.set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
    }

    /// S9: zero timeout is rejected, mirroring the UdpSocket platform quirk
    /// the driver relies on (see driver `min_poll_timeout`).
    #[test]
    fn std_transport_rejects_zero_timeout() {
        let rx = StdUdpTransport::bind(loopback(0)).unwrap();
        let err = rx.set_read_timeout(Some(Duration::ZERO)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    /// S9: the trait is object-safe and `Send` (driver holds it boxed
    /// across the driver thread boundary).
    #[test]
    fn transport_is_object_safe_send() {
        fn assert_send<T: Send>() {}
        assert_send::<Box<dyn UdpTransport>>();
        let t: Box<dyn UdpTransport> = Box::new(StdUdpTransport::bind(loopback(0)).unwrap());
        let _ = t.local_addr().unwrap();
    }
}
