//! Punch socket: QUIC handshakes from the shared punch driver.
//!
//! `send_punch(target, _)` spawns a background `Driver::connect` on the
//! punch driver's **same** UDP socket (zero new mechanism — the Initial
//! packets themselves are the punch). `await_direct` returns the first
//! successful handshake's address (first-wins across spray fan-out).

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use nexus_fabric::{ConnShared, Driver, FabricError, PeerId as FabricPeerId};
use nexus_nat_traversal::PunchSocket;

/// Poll `handles` until the first one finishes; return its address and join
/// result. Returns `None` when all handles are gone or `deadline` passes.
/// Generic over the join payload for testability.
pub fn first_finished<T: Send + 'static>(
    handles: &mut Vec<(SocketAddr, JoinHandle<T>)>,
    deadline: Instant,
) -> Option<(SocketAddr, thread::Result<T>)> {
    loop {
        let mut i = 0;
        while i < handles.len() {
            if handles[i].1.is_finished() {
                let (addr, h) = handles.remove(i);
                return Some((addr, h.join()));
            }
            i += 1;
        }
        if handles.is_empty() || Instant::now() >= deadline {
            return None;
        }
        thread::sleep(Duration::from_millis(20));
    }
}

type PunchAttempt = JoinHandle<Result<Arc<ConnShared>, FabricError>>;

/// `PunchSocket` backed by a shared punch [`Driver`].
pub struct DriverPunchSocket {
    driver: Arc<Driver>,
    peer: FabricPeerId,
    handshake_timeout: Duration,
    pending: Mutex<Vec<(SocketAddr, PunchAttempt)>>,
    winner: Mutex<Option<(SocketAddr, Arc<ConnShared>)>>,
    attempts: Mutex<u64>,
}

impl DriverPunchSocket {
    pub fn new(driver: Arc<Driver>, peer: FabricPeerId, handshake_timeout: Duration) -> Self {
        Self {
            driver,
            peer,
            handshake_timeout,
            pending: Mutex::new(Vec::new()),
            winner: Mutex::new(None),
            attempts: Mutex::new(0),
        }
    }

    /// Take the winning (handshake-completed) direct connection, if any.
    /// Used by the orchestrator for tie-break and registration.
    pub fn take_winner(&self) -> Option<(SocketAddr, Arc<ConnShared>)> {
        self.winner.lock().ok()?.take()
    }

    /// Number of `send_punch` calls so far (E4 asserts no spray storm).
    pub fn punch_attempts(&self) -> u64 {
        self.attempts.lock().map(|g| *g).unwrap_or(0)
    }
}

impl PunchSocket for DriverPunchSocket {
    fn send_punch(&self, target: SocketAddr, _payload: &[u8]) -> io::Result<()> {
        // The payload is intentionally ignored: the QUIC Initial emitted by
        // `Driver::connect` *is* the punch packet. The contract freezes the
        // "same socket + target address" semantics, which this satisfies.
        let driver = self.driver.clone();
        let peer = self.peer;
        let timeout = self.handshake_timeout;
        let handle = thread::spawn(move || driver.connect(peer, target, timeout));
        if let Ok(mut p) = self.pending.lock() {
            p.push((target, handle));
        }
        if let Ok(mut a) = self.attempts.lock() {
            *a = a.saturating_add(1);
        }
        Ok(())
    }

    fn await_direct(&self, timeout: Duration) -> io::Result<SocketAddr> {
        let deadline = Instant::now() + timeout;
        let mut pending = match self.pending.lock() {
            Ok(mut p) => std::mem::take(&mut *p),
            Err(_) => {
                return Err(io::Error::other("punch socket lock poisoned"));
            }
        };
        let mut last_err = String::new();
        while !pending.is_empty() && Instant::now() < deadline {
            match first_finished(&mut pending, deadline) {
                Some((addr, Ok(Ok(conn)))) => {
                    if let Ok(mut w) = self.winner.lock() {
                        *w = Some((addr, conn));
                    }
                    // Remaining attempts are detached; each self-terminates
                    // on its own handshake timeout (<= punch_timeout).
                    return Ok(addr);
                }
                Some((_, join_res)) => {
                    last_err = format!("{join_res:?}");
                }
                None => break,
            }
        }
        if pending.is_empty() {
            Err(io::Error::other(format!(
                "all punch attempts failed: {last_err}"
            )))
        } else {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "punch direct wait timeout",
            ))
        }
    }
}
