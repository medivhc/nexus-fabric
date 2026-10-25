//! Per-connection probe endpoint: answers pings, tracks pongs.
//!
//! One `ProbeEndpoint` per measured connection runs a receive loop that
//! demultiplexes datagrams: probe pings are answered with pongs, probe pongs
//! feed the local [`LossProbe`](crate::probe::LossProbe), and non-probe
//! datagrams are forwarded (or dropped if no forwarder — documented at the
//! call site, never silently misclassified).
//!
//! [`DatagramTransport`] is the seam between the endpoint and the wire:
//! production uses `Arc<FabricConn>`; tests use an in-memory channel pair.
//! Deletion Test: removing it would fuse the endpoint to `FabricConn` and
//! make the ping/pong/forward logic untestable without a QUIC driver.

use crate::probe::{LossProbe, ProbeMsg, decode, encode_pong};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;

/// Blocking datagram transport (send + receive). Implemented by
/// `Arc<FabricConn>` in production.
pub trait DatagramTransport: Send + Sync + 'static {
    type Error: std::fmt::Debug;
    fn send_dgram(&self, data: &[u8]) -> Result<(), Self::Error>;
    /// Blocking receive. Returns `Err` on close; the endpoint then exits.
    fn recv_dgram(&self) -> Result<Vec<u8>, Self::Error>;
    /// Smoothed RTT in ms, if known (from `FabricConn::stats().rtt_ms`).
    fn rtt_ms(&self) -> Option<u64>;
}

/// Error type for the endpoint.
#[derive(Debug)]
pub enum EndpointError {
    Send(String),
}

impl std::fmt::Display for EndpointError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Send(e) => write!(f, "probe send failed: {e}"),
        }
    }
}

/// A measured connection: pings the peer, answers the peer's pings.
pub struct ProbeEndpoint<T: DatagramTransport> {
    transport: T,
    probe: Mutex<LossProbe>,
    forward: Option<mpsc::Sender<Vec<u8>>>,
}

impl<T: DatagramTransport> ProbeEndpoint<T> {
    /// Start the endpoint: spawns the receive loop. `forward` receives
    /// non-probe datagrams; if `None` they are dropped (caller documents
    /// that it owns the datagram queue for probe-only connections).
    pub fn start(transport: T, forward: Option<mpsc::Sender<Vec<u8>>>) -> Arc<Self> {
        let ep = Arc::new(Self {
            transport,
            probe: Mutex::new(LossProbe::new(10)),
            forward,
        });
        let ep_c = Arc::clone(&ep);
        thread::Builder::new()
            .name("nat-quality-responder".to_string())
            .spawn(move || ep_c.recv_loop())
            .expect("spawn probe responder");
        ep
    }

    /// Send one ping now with its own per-ping deadline. Records the nonce
    /// for loss accounting.
    pub fn ping(&self, now_ms: u64, deadline_ms: u64) -> Result<(), EndpointError> {
        let (_, frame) = self.probe.lock().unwrap().send_ping(now_ms, deadline_ms);
        self.transport
            .send_dgram(&frame)
            .map_err(|e| EndpointError::Send(format!("{e:?}")))
    }

    /// Expire pings whose own deadline elapsed; returns how many were newly
    /// marked lost.
    pub fn expire(&self, now_ms: u64) -> u32 {
        self.probe.lock().unwrap().expire(now_ms)
    }

    /// Consecutive hard misses (used by the monitor's death/suspect logic).
    pub fn consecutive_misses(&self) -> u32 {
        self.probe.lock().unwrap().consecutive_misses()
    }

    /// Zero the consecutive-miss counter (called on probe-role changes).
    pub fn reset_consecutive_misses(&self) {
        self.probe.lock().unwrap().reset_consecutive_misses();
    }

    /// Age of the oldest outstanding ping at `now_ms`, if any.
    pub fn oldest_outstanding_age_ms(&self, now_ms: u64) -> Option<u64> {
        self.probe.lock().unwrap().oldest_outstanding_age_ms(now_ms)
    }

    /// Current loss estimate (`None` = no completed sample yet).
    pub fn loss_rate(&self) -> Option<f64> {
        self.probe.lock().unwrap().loss_rate()
    }

    /// RTT from the transport, if known.
    pub fn rtt_ms(&self) -> Option<u64> {
        self.transport.rtt_ms()
    }

    fn recv_loop(&self) {
        loop {
            let dgram = match self.transport.recv_dgram() {
                Ok(d) => d,
                Err(_) => break, // closed
            };
            match decode(&dgram) {
                Some(ProbeMsg::Ping { nonce, sent_ms }) => {
                    let pong = encode_pong(nonce, sent_ms);
                    let _ = self.transport.send_dgram(&pong);
                }
                Some(ProbeMsg::Pong { nonce, .. }) => {
                    self.probe.lock().unwrap().on_pong(nonce);
                }
                None => {
                    if let Some(fw) = &self.forward {
                        let _ = fw.send(dgram);
                    }
                    // else: dropped by caller contract.
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// In-memory transport: `tx` delivers to the peer's `rx`.
    struct MockTransport {
        tx: mpsc::Sender<Vec<u8>>,
        rx: Mutex<mpsc::Receiver<Vec<u8>>>,
        rtt: Option<u64>,
    }

    impl MockTransport {
        fn pair(rtt: Option<u64>) -> (Self, Self) {
            let (a_tx, a_rx) = mpsc::channel();
            let (b_tx, b_rx) = mpsc::channel();
            (
                Self {
                    tx: a_tx,
                    rx: Mutex::new(b_rx),
                    rtt,
                },
                Self {
                    tx: b_tx,
                    rx: Mutex::new(a_rx),
                    rtt,
                },
            )
        }
    }

    impl DatagramTransport for MockTransport {
        type Error = String;
        fn send_dgram(&self, data: &[u8]) -> Result<(), String> {
            self.tx.send(data.to_vec()).map_err(|e| e.to_string())
        }
        fn recv_dgram(&self) -> Result<Vec<u8>, String> {
            self.rx.lock().unwrap().recv().map_err(|e| e.to_string())
        }
        fn rtt_ms(&self) -> Option<u64> {
            self.rtt
        }
    }

    fn poll_until<F: Fn() -> Option<f64>>(f: F, timeout: Duration) -> Option<f64> {
        let start = std::time::Instant::now();
        loop {
            if let Some(v) = f() {
                return Some(v);
            }
            if start.elapsed() > timeout {
                return None;
            }
            thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn endpoint_ping_pong_zero_loss() {
        let (ta, tb) = MockTransport::pair(Some(12));
        let ea = ProbeEndpoint::start(ta, None);
        let _eb = ProbeEndpoint::start(tb, None);
        ea.ping(0, 2000).unwrap();
        // pong arrives asynchronously; wait for the completed sample.
        let lr = poll_until(|| ea.loss_rate(), Duration::from_secs(2)).unwrap();
        assert_eq!(lr, 0.0);
        assert_eq!(ea.rtt_ms(), Some(12));
    }

    #[test]
    fn endpoint_no_pong_full_loss_after_expire() {
        // b's transport is kept alive but no responder is started on it:
        // pings sit unread, so they expire as lost.
        let (ta, _tb) = MockTransport::pair(None);
        let ea = ProbeEndpoint::start(ta, None);
        ea.ping(0, 2000).unwrap();
        ea.expire(10_000);
        assert_eq!(ea.loss_rate(), Some(1.0));
    }

    #[test]
    fn endpoint_forwards_non_probe_datagrams() {
        let (ta, tb) = MockTransport::pair(None);
        let (fw_tx, fw_rx) = mpsc::channel();
        let ea = ProbeEndpoint::start(ta, Some(fw_tx));
        let _eb = ProbeEndpoint::start(tb, None);
        // send an application datagram from b to a
        _eb.transport.send_dgram(b"hello app").unwrap();
        let got = fw_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(got, b"hello app");
        // and probes still work through the same queue
        ea.ping(0, 2000).unwrap();
        let lr = poll_until(|| ea.loss_rate(), Duration::from_secs(2)).unwrap();
        assert_eq!(lr, 0.0);
    }

    #[test]
    fn endpoint_reset_consecutive_misses_clears_counter() {
        let (ta, _tb) = MockTransport::pair(None);
        let ea = ProbeEndpoint::start(ta, None);
        ea.ping(0, 300).unwrap();
        assert_eq!(ea.oldest_outstanding_age_ms(100), Some(100));
        assert_eq!(ea.expire(300), 1);
        assert_eq!(ea.consecutive_misses(), 1);
        ea.reset_consecutive_misses();
        assert_eq!(ea.consecutive_misses(), 0);
        assert_eq!(ea.oldest_outstanding_age_ms(1000), None);
    }

    #[test]
    fn endpoint_drops_non_probe_when_no_forwarder() {
        let (ta, tb) = MockTransport::pair(None);
        let ea = ProbeEndpoint::start(ta, None);
        let _eb = ProbeEndpoint::start(tb, None);
        _eb.transport.send_dgram(b"app-data").unwrap();
        thread::sleep(Duration::from_millis(100));
        // no panic, no misclassification; probe path unaffected
        ea.ping(0, 2000).unwrap();
        let lr = poll_until(|| ea.loss_rate(), Duration::from_secs(2)).unwrap();
        assert_eq!(lr, 0.0);
    }
}
