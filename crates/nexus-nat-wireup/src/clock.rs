//! Production clock for the portable punch core.
//!
//! `nexus-nat-traversal` never reads system time; the edge injects this
//! implementation (`now_ms` on a monotonic `Instant` base, `wall_ms` from
//! `SystemTime`).

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use nexus_nat_traversal::PunchClock;

#[derive(Debug)]
pub struct SystemPunchClock {
    start: Instant,
}

impl Default for SystemPunchClock {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemPunchClock {
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
        }
    }
}

impl PunchClock for SystemPunchClock {
    fn now_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }
    fn wall_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }
    fn sleep_until_ms(&self, deadline_ms: u64) {
        let now = self.now_ms();
        if deadline_ms > now {
            std::thread::sleep(Duration::from_millis(deadline_ms - now));
        }
    }
    fn sleep_ms(&self, ms: u64) {
        std::thread::sleep(Duration::from_millis(ms));
    }
}
