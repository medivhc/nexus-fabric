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

/// Driver-level transport: [`DatagramTransport`] over a shared connection
/// handle.
///
/// `PunchManager` hands out `Arc<ConnShared>`, not `FabricConn` (which also
/// anchors the driver thread). The probe logic is identical to the
/// `Arc<FabricConn>` impl above — same `Cmd::SendDatagram` path, same
/// `dgrams` queue, same `stats().rtt_ms`. This is what the production
/// composition root and the E4 use.
impl DatagramTransport for Arc<nexus_fabric::ConnShared> {
    type Error = nexus_fabric::FabricError;

    fn send_dgram(&self, data: &[u8]) -> Result<(), Self::Error> {
        if data.len() > 1200 {
            return Err(nexus_fabric::FabricError::Transport(
                "datagram too large (S5: 1200 byte cap)".into(),
            ));
        }
        let (tx, rx) = std::sync::mpsc::channel();
        self.tx
            .send(nexus_fabric::Cmd::SendDatagram {
                conn: self.id.0,
                data: data.to_vec(),
                reply: tx,
            })
            .map_err(|_| nexus_fabric::FabricError::Closed(0))?;
        rx.recv()
            .map_err(|_| nexus_fabric::FabricError::Closed(0))?
    }

    fn recv_dgram(&self) -> Result<Vec<u8>, Self::Error> {
        let mut q = self.dgrams.lock().unwrap();
        loop {
            if let Some(d) = q.pop_front() {
                return Ok(d);
            }
            if let Some(e) = self.state.lock().unwrap().closed.clone() {
                return Err(e);
            }
            q = self
                .dgram_cv
                .wait(q)
                .map_err(|_| nexus_fabric::FabricError::Transport("lock poisoned".into()))?;
        }
    }

    fn rtt_ms(&self) -> Option<u64> {
        self.stats.lock().unwrap().rtt_ms
    }
}
