//! Active quality measurement for NAT paths.
//!
//! - [`probe`]: probe wire format + sliding-window [`probe::LossProbe`].
//! - [`endpoint`]: per-connection [`endpoint::ProbeEndpoint`] (ping/pong/forward).
//! - [`monitor`]: [`monitor::QualityMonitor`] background supply loop feeding
//!   `PathManager::on_stats` and forwarding `PathEvent`s.
//!
//! Design note (why a separate crate, not `nexus-nat-wireup`):
//! `nexus-nat-wireup`'s MODULE.md forbids write access to `nexus-path`, and
//! `on_stats` is a write. `nexus-path` itself is transport-agnostic (no
//! `nexus-fabric` dependency) and must stay that way. The monitor is a
//! distinct long-running responsibility, so it gets its own crate.

pub mod endpoint;
pub mod monitor;
pub mod probe;

pub use endpoint::{DatagramTransport, EndpointError, ProbeEndpoint};
pub use monitor::{MeasuredPath, PathEventSink, ProbeRole, QualityMonitor};
pub use probe::{LossProbe, PROBE_LEN, PROBE_MAGIC, ProbeMsg, decode, encode_ping, encode_pong};

use std::sync::Arc;

/// Production transport: [`DatagramTransport`] over a fabric QUIC connection.
///
/// Pings/pongs ride as datagrams on the measured connection; RTT comes from
/// `FabricConn::stats().rtt_ms` (quinn smoothed RTT, zero new mechanism).
/// Loss is purely from the probe window — `stats().loss_rate` is not used
/// (it is never populated; see R3 rationale in MODULE.md).
impl DatagramTransport for Arc<nexus_fabric::FabricConn> {
    type Error = nexus_fabric::FabricError;

    fn send_dgram(&self, data: &[u8]) -> Result<(), Self::Error> {
        self.send_datagram(data)
    }

    fn recv_dgram(&self) -> Result<Vec<u8>, Self::Error> {
        self.recv_datagram()
    }

    fn rtt_ms(&self) -> Option<u64> {
        self.stats().rtt_ms
    }
}
