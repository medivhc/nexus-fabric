//! Projection layer: L3 tunnel (TUN <-> fabric datagrams).
//!
//! Captures IP packets from a TUN device, encapsulates them into fabric
//! datagrams (payload = raw IP packet, zero overhead per S2), and decapsulates
//! received datagrams back into the local TUN. P0: L3 tunnel only.
//!
//! Contract phase: honest stubs.

use std::io;

/// Abstraction over a TUN device. Implementations: `MockTun` (E4),
/// OS-specific (E5, `os::linux`).
pub trait TunDevice: Send {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize>;
    fn write(&mut self, packet: &[u8]) -> io::Result<usize>;
    fn name(&self) -> &str;
}

/// In-memory mock TUN for E4 (no privileges needed).
pub struct MockTun {
    inbound: std::collections::VecDeque<Vec<u8>>,
    name: String,
}

impl MockTun {
    pub fn new(name: &str) -> Self {
        Self {
            inbound: std::collections::VecDeque::new(),
            name: name.to_string(),
        }
    }

    /// Inject a packet as if read from the OS (test helper).
    pub fn inject(&mut self, packet: Vec<u8>) {
        self.inbound.push_back(packet);
    }
}

impl TunDevice for MockTun {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.inbound.pop_front() {
            Some(pkt) => {
                let n = pkt.len().min(buf.len());
                buf[..n].copy_from_slice(&pkt[..n]);
                Ok(n)
            }
            None => Err(io::Error::new(io::ErrorKind::WouldBlock, "no packet")),
        }
    }

    fn write(&mut self, packet: &[u8]) -> io::Result<usize> {
        self.inbound.push_back(packet.to_vec());
        Ok(packet.len())
    }

    fn name(&self) -> &str {
        &self.name
    }
}

impl Default for MockTun {
    fn default() -> Self {
        Self::new("mocktun0")
    }
}

/// Configuration for the projection.
#[derive(Debug, Clone)]
pub struct ProjectionConfig {
    /// Max fabric datagram payload. Packets larger than this are dropped (S5).
    pub mtu: usize,
}

impl Default for ProjectionConfig {
    fn default() -> Self {
        Self { mtu: 1400 }
    }
}

/// Packet counters (S8: honest, same code for mock and real devices).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TunStats {
    pub packets_in: u64,
    pub packets_out: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub dropped_oversize: u64,
}

/// Error type for projection operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectionError {
    NotImplemented,
    Oversize { len: usize, mtu: usize },
    Io(String),
}

impl std::fmt::Display for ProjectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProjectionError::NotImplemented => write!(f, "not implemented"),
            ProjectionError::Oversize { len, mtu } => {
                write!(f, "packet too large: {len} > mtu {mtu}")
            }
            ProjectionError::Io(e) => write!(f, "io error: {e}"),
        }
    }
}

impl std::error::Error for ProjectionError {}

/// L3 tunnel projection: TUN <-> fabric datagrams.
///
/// Contract phase: honest stub. Packet flow is not yet implemented.
pub struct Projection {
    _tun: Box<dyn TunDevice>,
    _config: ProjectionConfig,
}

impl Projection {
    pub fn new(tun: Box<dyn TunDevice>, config: ProjectionConfig) -> Self {
        Self {
            _tun: tun,
            _config: config,
        }
    }

    pub fn send_packet(&mut self, _packet: &[u8]) -> Result<(), ProjectionError> {
        Err(ProjectionError::NotImplemented)
    }

    pub fn recv_packet(&mut self) -> Option<Vec<u8>> {
        None
    }

    pub fn stats(&self) -> TunStats {
        TunStats::default()
    }

    pub fn close(self) {
        // Contract phase: no background threads yet.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_tun_loopback() {
        let mut tun = MockTun::new("test0");
        let pkt = vec![0x45, 0x00, 0x00, 0x14];
        tun.write(&pkt).unwrap();
        let mut buf = [0u8; 1500];
        let n = tun.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], &pkt[..]);
    }

    #[test]
    fn stub_returns_not_implemented() {
        let tun = Box::new(MockTun::default());
        let mut proj = Projection::new(tun, ProjectionConfig::default());
        assert_eq!(
            proj.send_packet(&[0x45]),
            Err(ProjectionError::NotImplemented)
        );
        assert_eq!(proj.recv_packet(), None);
    }
}
