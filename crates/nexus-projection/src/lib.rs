//! Projection layer: L3 tunnel (TUN <-> fabric datagrams).
//!
//! Captures IP packets from a TUN device, encapsulates them into fabric
//! datagrams (payload = raw IP packet, zero overhead per S2), and decapsulates
//! received datagrams back into the local TUN. P0: L3 tunnel only.
//!
//! P0 transport: internal `mpsc` queues simulate the fabric. `link_peer` wires
//! two projections together for E4. Future: replace with `FabricConn`
//! (`send_datagram` / `recv_datagram`) — see comments at `link_peer`.

use std::collections::VecDeque;
use std::io;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
    mpsc,
};
use std::thread;
use std::time::Duration;

/// Abstraction over a TUN device. Implementations: `MockTun` (E4),
/// OS-specific (E5, `os::linux`).
pub trait TunDevice: Send {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize>;
    fn write(&mut self, packet: &[u8]) -> io::Result<usize>;
    fn name(&self) -> &str;
}

/// In-memory mock TUN for E4 (no privileges needed).
///
/// Separate queues model real TUN directionality:
/// - `inject` / `read`: OS -> us (packets the "network stack" gives us)
/// - `write` / `take_written`: us -> OS (packets we deliver to the "stack")
pub struct MockTun {
    read_queue: VecDeque<Vec<u8>>,
    write_queue: VecDeque<Vec<u8>>,
    name: String,
}

impl MockTun {
    pub fn new(name: &str) -> Self {
        Self {
            read_queue: VecDeque::new(),
            write_queue: VecDeque::new(),
            name: name.to_string(),
        }
    }

    /// Inject a packet as if read from the OS (test helper).
    pub fn inject(&mut self, packet: Vec<u8>) {
        self.read_queue.push_back(packet);
    }

    /// Drain packets written to the (mock) OS. Test/E4 helper.
    pub fn take_written(&mut self) -> Vec<Vec<u8>> {
        self.write_queue.drain(..).collect()
    }
}

impl TunDevice for MockTun {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.read_queue.pop_front() {
            Some(pkt) => {
                let n = pkt.len().min(buf.len());
                buf[..n].copy_from_slice(&pkt[..n]);
                Ok(n)
            }
            None => Err(io::Error::new(io::ErrorKind::WouldBlock, "no packet")),
        }
    }

    fn write(&mut self, packet: &[u8]) -> io::Result<usize> {
        self.write_queue.push_back(packet.to_vec());
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
    Oversize { len: usize, mtu: usize },
    Io(String),
}

impl std::fmt::Display for ProjectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProjectionError::Oversize { len, mtu } => {
                write!(f, "packet too large: {len} > mtu {mtu}")
            }
            ProjectionError::Io(e) => write!(f, "io error: {e}"),
        }
    }
}

impl std::error::Error for ProjectionError {}

/// Lock helper that tolerates poisoning (a panicked thread must not
/// permanently break stats).
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Shared fabric sender. `link_peer` swaps the target; the uplink thread and
/// `send_packet` both go through here so linking is atomic.
type FabricSender = Arc<Mutex<mpsc::Sender<Vec<u8>>>>;

/// L3 tunnel projection: TUN <-> fabric datagrams.
///
/// Two background threads (owner: this struct, joined on `close`/`Drop`):
/// - uplink: TUN.read -> MTU check -> fabric (S2: payload = raw IP packet)
/// - downlink: fabric -> TUN.write
///
/// `send_packet` is the test/E4 injection path (same MTU check as the uplink
/// thread). `recv_packet` drains the fabric inbox directly and is only
/// available on thread-less instances (see `new_for_test`); with threads
/// running, the downlink thread owns the inbox and writes to the TUN.
pub struct Projection {
    config: ProjectionConfig,
    /// Current fabric destination. P0: peer's inbox (see `link_peer`).
    /// Future: `FabricConn::send_datagram`.
    to_net: FabricSender,
    /// Inbound from fabric. `None` once the downlink thread takes ownership.
    from_net: Option<mpsc::Receiver<Vec<u8>>>,
    /// Our inbox sender, handed to the peer via `link_peer`.
    inbox_tx: mpsc::Sender<Vec<u8>>,
    stats: Arc<Mutex<TunStats>>,
    path_switches: Arc<AtomicU64>,
    shutdown: Arc<AtomicBool>,
    uplink: Option<thread::JoinHandle<()>>,
    downlink: Option<thread::JoinHandle<()>>,
}

impl Projection {
    pub fn new(tun: Box<dyn TunDevice>, config: ProjectionConfig) -> Self {
        Self::new_inner(tun, config, true)
    }

    fn new_inner(tun: Box<dyn TunDevice>, config: ProjectionConfig, spawn_threads: bool) -> Self {
        let (inbox_tx, from_net) = mpsc::channel::<Vec<u8>>();
        // Unlinked: loop back to self. `link_peer` replaces the target.
        let to_net: FabricSender = Arc::new(Mutex::new(inbox_tx.clone()));
        let stats = Arc::new(Mutex::new(TunStats::default()));
        let path_switches = Arc::new(AtomicU64::new(0));
        let shutdown = Arc::new(AtomicBool::new(false));
        let tun = Arc::new(Mutex::new(tun));
        let mtu = config.mtu;

        let (uplink, downlink, from_net) = if spawn_threads {
            // Uplink: TUN -> fabric.
            let up = {
                let tun = Arc::clone(&tun);
                let to_net = Arc::clone(&to_net);
                let stats = Arc::clone(&stats);
                let shutdown = Arc::clone(&shutdown);
                thread::Builder::new()
                    .name("projection-uplink".into())
                    .spawn(move || {
                        let mut buf = vec![0u8; mtu.max(1500) + 64];
                        while !shutdown.load(Ordering::Relaxed) {
                            let n = {
                                let mut tun = lock(&tun);
                                match tun.read(&mut buf) {
                                    Ok(n) => n,
                                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                                        drop(tun);
                                        thread::sleep(Duration::from_millis(1));
                                        continue;
                                    }
                                    Err(_) => {
                                        drop(tun);
                                        thread::sleep(Duration::from_millis(10));
                                        continue;
                                    }
                                }
                            };
                            if n > mtu {
                                lock(&stats).dropped_oversize += 1;
                                continue;
                            }
                            // S2: zero overhead — payload is the raw IP packet.
                            let pkt = buf[..n].to_vec();
                            let sent = lock(&to_net).send(pkt).is_ok();
                            if sent {
                                let mut s = lock(&stats);
                                s.packets_out += 1;
                                s.bytes_out += n as u64;
                            }
                            // S3: best-effort. If the peer is gone, drop silently.
                        }
                    })
                    .expect("spawn projection uplink")
            };
            // Downlink: fabric -> TUN. Takes ownership of from_net.
            let down = {
                let tun = Arc::clone(&tun);
                let stats = Arc::clone(&stats);
                let shutdown = Arc::clone(&shutdown);
                thread::Builder::new()
                    .name("projection-downlink".into())
                    .spawn(move || {
                        while !shutdown.load(Ordering::Relaxed) {
                            match from_net.recv_timeout(Duration::from_millis(100)) {
                                Ok(pkt) => {
                                    let mut tun = lock(&tun);
                                    if tun.write(&pkt).is_ok() {
                                        let mut s = lock(&stats);
                                        s.packets_in += 1;
                                        s.bytes_in += pkt.len() as u64;
                                    }
                                }
                                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                                Err(mpsc::RecvTimeoutError::Disconnected) => break,
                            }
                        }
                    })
                    .expect("spawn projection downlink")
            };
            (Some(up), Some(down), None)
        } else {
            (None, None, Some(from_net))
        };

        Self {
            config,
            to_net,
            from_net,
            inbox_tx,
            stats,
            path_switches,
            shutdown,
            uplink,
            downlink,
        }
    }

    /// Test helper: create without background threads, so `send_packet` /
    /// `recv_packet` have exclusive access to the fabric channels.
    #[cfg(test)]
    fn new_for_test(tun: Box<dyn TunDevice>, config: ProjectionConfig) -> Self {
        Self::new_inner(tun, config, false)
    }

    /// P0 mock fabric wiring: direct our output to the peer's inbox.
    ///
    /// Future: replaced by binding to `FabricConn` — `to_net.send(pkt)`
    /// becomes `fabric.send_datagram(pkt)`, and the downlink thread calls
    /// `fabric.recv_datagram()` instead of reading `from_net`.
    pub fn link_peer(&mut self, peer_inbox: mpsc::Sender<Vec<u8>>) {
        *lock(&self.to_net) = peer_inbox;
    }

    /// Our inbox sender, for the peer to `link_peer` to.
    pub fn inbox_sender(&self) -> mpsc::Sender<Vec<u8>> {
        self.inbox_tx.clone()
    }

    /// Handle a path-switch event from `nexus-path`.
    ///
    /// P0: records the event. The mock fabric channel is unaffected, so packet
    /// flow continues uninterrupted (S3 best-effort).
    /// Future: trigger `FabricConn` rebind / path migration here.
    pub fn on_path_event(&mut self) {
        self.path_switches.fetch_add(1, Ordering::Relaxed);
    }

    /// Number of path-switch events handled.
    pub fn path_switch_count(&self) -> u64 {
        self.path_switches.load(Ordering::Relaxed)
    }

    /// Inject a packet to send (test/E4 path; production uses the TUN).
    ///
    /// S5: oversize packets are dropped, counted, and reported — never
    /// truncated or fragmented.
    pub fn send_packet(&mut self, packet: &[u8]) -> Result<(), ProjectionError> {
        if packet.len() > self.config.mtu {
            lock(&self.stats).dropped_oversize += 1;
            return Err(ProjectionError::Oversize {
                len: packet.len(),
                mtu: self.config.mtu,
            });
        }
        // S2: zero overhead — the datagram payload IS the raw IP packet.
        match lock(&self.to_net).send(packet.to_vec()) {
            Ok(()) => {
                let mut s = lock(&self.stats);
                s.packets_out += 1;
                s.bytes_out += packet.len() as u64;
                Ok(())
            }
            Err(_) => {
                // S3: best-effort; peer gone.
                Err(ProjectionError::Io("fabric send failed".into()))
            }
        }
    }

    /// Take a received packet (thread-less test instances only).
    pub fn recv_packet(&mut self) -> Option<Vec<u8>> {
        let rx = self.from_net.as_ref()?;
        match rx.try_recv() {
            Ok(pkt) => {
                let mut s = lock(&self.stats);
                s.packets_in += 1;
                s.bytes_in += pkt.len() as u64;
                Some(pkt)
            }
            Err(_) => None,
        }
    }

    pub fn stats(&self) -> TunStats {
        *lock(&self.stats)
    }

    /// Stop background threads and drop unsent packets (S7).
    pub fn close(mut self) {
        self.shutdown_threads();
    }

    fn shutdown_threads(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(h) = self.uplink.take() {
            let _ = h.join();
        }
        if let Some(h) = self.downlink.take() {
            let _ = h.join();
        }
    }
}

impl Drop for Projection {
    fn drop(&mut self) {
        self.shutdown_threads();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_tun_separate_queues() {
        let mut tun = MockTun::new("test0");
        // inject -> read path
        let pkt = vec![0x45, 0x00, 0x00, 0x14];
        tun.inject(pkt.clone());
        let mut buf = [0u8; 1500];
        let n = tun.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], &pkt[..]);
        // write -> take_written path (does NOT loop back to read)
        tun.write(&pkt).unwrap();
        assert!(tun.read(&mut buf).is_err());
        let written = tun.take_written();
        assert_eq!(written, vec![pkt]);
    }

    #[test]
    fn s1_packet_integrity_loopback() {
        let tun = Box::new(MockTun::default());
        let mut p = Projection::new_for_test(tun, ProjectionConfig::default());
        // Unlinked: to_net loops back to own from_net.
        let pkt: Vec<u8> = (0..100).map(|i| (i * 7 % 256) as u8).collect();
        p.send_packet(&pkt).unwrap();
        let got = p.recv_packet().expect("loopback packet");
        assert_eq!(got, pkt);
    }

    #[test]
    fn s5_oversize_dropped_and_counted() {
        let tun = Box::new(MockTun::default());
        let mut p = Projection::new_for_test(tun, ProjectionConfig { mtu: 100 });
        let big = vec![0u8; 101];
        let err = p.send_packet(&big).unwrap_err();
        assert_eq!(err, ProjectionError::Oversize { len: 101, mtu: 100 });
        assert_eq!(p.stats().dropped_oversize, 1);
        assert_eq!(p.stats().packets_out, 0);
        // Exactly at MTU is fine.
        let exact = vec![0u8; 100];
        p.send_packet(&exact).unwrap();
        assert_eq!(p.stats().packets_out, 1);
    }

    #[test]
    fn s2_zero_overhead_payload_is_raw_packet() {
        let tun = Box::new(MockTun::default());
        let mut p = Projection::new_for_test(tun, ProjectionConfig::default());
        // Minimal IPv4 header (20 bytes).
        let pkt = vec![
            0x45, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 0x7f, 0x00,
            0x00, 0x01, 0x7f, 0x00, 0x00, 0x01,
        ];
        p.send_packet(&pkt).unwrap();
        let got = p.recv_packet().unwrap();
        // No projection header: what comes out is exactly what went in.
        assert_eq!(got.len(), pkt.len());
        assert_eq!(got, pkt);
    }

    #[test]
    fn s8_stats_honest() {
        let tun = Box::new(MockTun::default());
        let mut p = Projection::new_for_test(tun, ProjectionConfig::default());
        assert_eq!(p.stats(), TunStats::default());
        p.send_packet(&[0x45; 20]).unwrap();
        p.send_packet(&[0x45; 40]).unwrap();
        let _ = p.recv_packet();
        let s = p.stats();
        assert_eq!(s.packets_out, 2);
        assert_eq!(s.bytes_out, 60);
        assert_eq!(s.packets_in, 1);
        assert_eq!(s.bytes_in, 20);
        assert_eq!(s.dropped_oversize, 0);
    }

    #[test]
    fn linked_pair_delivers() {
        let ta = Box::new(MockTun::default());
        let tb = Box::new(MockTun::default());
        let mut a = Projection::new_for_test(ta, ProjectionConfig::default());
        let mut b = Projection::new_for_test(tb, ProjectionConfig::default());
        let ai = a.inbox_sender();
        let bi = b.inbox_sender();
        a.link_peer(bi);
        b.link_peer(ai);
        let pkt = vec![0x45; 64];
        a.send_packet(&pkt).unwrap();
        let got = b.recv_packet().expect("peer delivery");
        assert_eq!(got, pkt);
        assert_eq!(a.stats().packets_out, 1);
        assert_eq!(b.stats().packets_in, 1);
    }

    #[test]
    fn on_path_event_counts() {
        let tun = Box::new(MockTun::default());
        let mut p = Projection::new_for_test(tun, ProjectionConfig::default());
        assert_eq!(p.path_switch_count(), 0);
        p.on_path_event();
        p.on_path_event();
        assert_eq!(p.path_switch_count(), 2);
    }

    #[test]
    fn close_joins_threads() {
        let tun = Box::new(MockTun::default());
        let p = Projection::new(tun, ProjectionConfig::default());
        // Threads started; close must join them without hanging.
        p.close();
    }
}
