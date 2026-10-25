//! Probe wire format + sliding-window loss estimation (pure logic, no I/O).
//!
//! Wire format (wireup-layer internal, NOT part of frozen P2 signaling):
//! `[8B magic "NXQPROB!"][1B type 0x01=ping/0x02=pong][8B nonce BE][8B sent_ms BE]`
//! = 25 bytes, well under the 1200B datagram cap.

/// Magic prefix distinguishing probe datagrams from application datagrams.
pub const PROBE_MAGIC: &[u8; 8] = b"NXQPROB!";
/// Total probe frame length in bytes.
pub const PROBE_LEN: usize = 25;
const TYPE_PING: u8 = 0x01;
const TYPE_PONG: u8 = 0x02;

use std::collections::{HashMap, VecDeque};

/// A decoded probe datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeMsg {
    Ping { nonce: u64, sent_ms: u64 },
    Pong { nonce: u64, sent_ms: u64 },
}

/// Encode a ping frame. Returns `(nonce, frame)`.
pub fn encode_ping(nonce: u64, sent_ms: u64) -> (u64, [u8; PROBE_LEN]) {
    (nonce, encode(TYPE_PING, nonce, sent_ms))
}

/// Encode a pong frame for the given ping nonce.
pub fn encode_pong(nonce: u64, sent_ms: u64) -> [u8; PROBE_LEN] {
    encode(TYPE_PONG, nonce, sent_ms)
}

fn encode(ty: u8, nonce: u64, sent_ms: u64) -> [u8; PROBE_LEN] {
    let mut b = [0u8; PROBE_LEN];
    b[..8].copy_from_slice(PROBE_MAGIC);
    b[8] = ty;
    b[9..17].copy_from_slice(&nonce.to_be_bytes());
    b[17..25].copy_from_slice(&sent_ms.to_be_bytes());
    b
}

/// Decode a datagram. Returns `None` if it is not a probe frame
/// (application datagrams must be forwarded, never misclassified).
pub fn decode(data: &[u8]) -> Option<ProbeMsg> {
    if data.len() != PROBE_LEN {
        return None;
    }
    if &data[..8] != PROBE_MAGIC {
        return None;
    }
    let mut nb = [0u8; 8];
    let mut sb = [0u8; 8];
    nb.copy_from_slice(&data[9..17]);
    sb.copy_from_slice(&data[17..25]);
    let nonce = u64::from_be_bytes(nb);
    let sent_ms = u64::from_be_bytes(sb);
    match data[8] {
        TYPE_PING => Some(ProbeMsg::Ping { nonce, sent_ms }),
        TYPE_PONG => Some(ProbeMsg::Pong { nonce, sent_ms }),
        _ => None,
    }
}

/// Sliding-window loss estimator over probe ping/pong outcomes.
///
/// A ping is "completed" when its pong arrives (`on_pong`) or when it ages
/// past its own per-ping deadline (`expire`). `loss_rate()` is `None` until at
/// least one sample completes (PathManager S7: no measurement = not eligible).
///
/// The window is a *scoring* device (10 completed samples). Death is decided
/// elsewhere by `consecutive_misses`, which counts hard misses (per-ping
/// deadlines that elapsed without a pong) and resets on any pong, including a
/// late one that lands inside `2 x` that ping's deadline.
pub struct LossProbe {
    window: VecDeque<bool>, // true = pong received, false = lost; oldest front
    capacity: usize,
    outstanding: HashMap<u64, (u64, u64)>, // nonce -> (sent_ms, deadline_ms)
    recent_expired: HashMap<u64, (u64, u64)>, // nonce -> (expired_at_ms, deadline_ms)
    consecutive_misses: u32,
    next_nonce: u64,
}

impl LossProbe {
    pub fn new(capacity: usize) -> Self {
        Self {
            window: VecDeque::with_capacity(capacity.max(1)),
            capacity: capacity.max(1),
            outstanding: HashMap::new(),
            recent_expired: HashMap::new(),
            consecutive_misses: 0,
            next_nonce: 1,
        }
    }

    /// Record a ping sent at `now_ms` with its own `deadline_ms`.
    /// Returns `(nonce, frame)`.
    pub fn send_ping(&mut self, now_ms: u64, deadline_ms: u64) -> (u64, [u8; PROBE_LEN]) {
        self.prune_recent_expired(now_ms);
        let nonce = self.next_nonce;
        self.next_nonce = self.next_nonce.wrapping_add(1).max(1);
        self.outstanding.insert(nonce, (now_ms, deadline_ms));
        (nonce, encode_ping(nonce, now_ms).1)
    }

    /// Record a pong.
    ///
    /// Returns `true` iff the nonce matched an outstanding ping. A pong that
    /// matches `recent_expired` is late: it resets `consecutive_misses` but
    /// returns `false`, and the `false` already pushed into the scoring window
    /// is not recycled.
    pub fn on_pong(&mut self, nonce: u64) -> bool {
        if self.outstanding.remove(&nonce).is_some() {
            self.push(true);
            self.consecutive_misses = 0;
            true
        } else if self.recent_expired.remove(&nonce).is_some() {
            self.consecutive_misses = 0;
            false
        } else {
            false
        }
    }

    /// Expire outstanding pings whose own deadline has elapsed. Returns the
    /// number of pings newly marked lost.
    pub fn expire(&mut self, now_ms: u64) -> u32 {
        let expired: Vec<(u64, u64)> = self
            .outstanding
            .iter()
            .filter(|&(_, &(sent, deadline))| now_ms.saturating_sub(sent) >= deadline)
            .map(|(&n, &(_, deadline))| (n, deadline))
            .collect();
        let count = expired.len() as u32;
        for (n, deadline) in expired {
            self.outstanding.remove(&n);
            self.push(false);
            self.consecutive_misses = self.consecutive_misses.saturating_add(1);
            self.recent_expired.insert(n, (now_ms, deadline));
        }
        self.prune_recent_expired(now_ms);
        count
    }

    /// Loss rate over the window: `None` if no completed sample yet.
    pub fn loss_rate(&self) -> Option<f64> {
        if self.window.is_empty() {
            return None;
        }
        let lost = self.window.iter().filter(|&&b| !b).count();
        Some(lost as f64 / self.window.len() as f64)
    }

    /// Consecutive hard misses since the last pong (any pong, including a late
    /// one inside the grace window). Reset by `reset_consecutive_misses`.
    pub fn consecutive_misses(&self) -> u32 {
        self.consecutive_misses
    }

    /// Age of the oldest outstanding ping at `now_ms`, if any.
    pub fn oldest_outstanding_age_ms(&self, now_ms: u64) -> Option<u64> {
        self.outstanding
            .values()
            .map(|&(sent, _)| now_ms.saturating_sub(sent))
            .max()
    }

    /// Number of pings awaiting pong or expiry.
    pub fn outstanding(&self) -> usize {
        self.outstanding.len()
    }

    pub(crate) fn reset_consecutive_misses(&mut self) {
        self.consecutive_misses = 0;
    }

    /// Drop grace entries older than `2 x` their own deadline. The boundary is
    /// strict: an entry exactly `2 x deadline` old no longer matches.
    fn prune_recent_expired(&mut self, now_ms: u64) {
        self.recent_expired.retain(|_, &mut (at, deadline)| {
            now_ms.saturating_sub(at) < deadline.saturating_mul(2)
        });
    }

    fn push(&mut self, received: bool) {
        if self.window.len() >= self.capacity {
            self.window.pop_front();
        }
        self.window.push_back(received);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ping_pong_roundtrip() {
        let (nonce, frame) = encode_ping(42, 1000);
        assert_eq!(nonce, 42);
        assert_eq!(
            decode(&frame),
            Some(ProbeMsg::Ping {
                nonce: 42,
                sent_ms: 1000
            })
        );
        let pong = encode_pong(42, 1000);
        assert_eq!(
            decode(&pong),
            Some(ProbeMsg::Pong {
                nonce: 42,
                sent_ms: 1000
            })
        );
    }

    #[test]
    fn decode_rejects_non_probe() {
        assert_eq!(decode(&[]), None);
        assert_eq!(decode(&[0u8; 25]), None); // wrong magic
        assert_eq!(decode(b"short"), None);
        let (_, frame) = encode_ping(1, 2);
        assert_eq!(decode(&frame[..24]), None); // truncated
        let mut bad_type = frame;
        bad_type[8] = 0xFF;
        assert_eq!(decode(&bad_type), None);
        // application datagram that happens to be 25 bytes but wrong magic
        assert_eq!(decode(&[0xAAu8; 25]), None);
    }

    #[test]
    fn loss_probe_no_data_is_none() {
        let p = LossProbe::new(10);
        assert_eq!(p.loss_rate(), None);
        assert_eq!(p.outstanding(), 0);
    }

    #[test]
    fn loss_probe_all_pongs_zero_loss() {
        let mut p = LossProbe::new(10);
        for i in 0..5 {
            let (nonce, _) = p.send_ping(i * 1000, 2000);
            assert!(p.on_pong(nonce));
        }
        assert_eq!(p.loss_rate(), Some(0.0));
        assert_eq!(p.outstanding(), 0);
    }

    #[test]
    fn loss_probe_no_pongs_full_loss_after_expire() {
        let mut p = LossProbe::new(10);
        for i in 0..3 {
            let _ = p.send_ping(i * 1000, 2000);
        }
        assert_eq!(p.outstanding(), 3);
        p.expire(10_000);
        assert_eq!(p.loss_rate(), Some(1.0));
        assert_eq!(p.outstanding(), 0);
    }

    #[test]
    fn loss_probe_partial_loss() {
        let mut p = LossProbe::new(10);
        let (n0, _) = p.send_ping(0, 2000);
        let (n1, _) = p.send_ping(1000, 2000);
        let (n2, _) = p.send_ping(2000, 2000);
        let _ = p.send_ping(3000, 2000);
        assert!(p.on_pong(n0));
        assert!(p.on_pong(n1));
        assert!(p.on_pong(n2));
        p.expire(10_000); // the 4th ping lost
        let lr = p.loss_rate().unwrap();
        assert!((lr - 0.25).abs() < 1e-9, "got {lr}");
    }

    #[test]
    fn loss_probe_window_evicts_old() {
        let mut p = LossProbe::new(4);
        for i in 0..4 {
            let (n, _) = p.send_ping(i, 1000);
            p.on_pong(n);
        }
        assert_eq!(p.loss_rate(), Some(0.0));
        for i in 4..8 {
            let _ = p.send_ping(i * 1000, 2000);
        }
        p.expire(100_000);
        // window (cap 4) now holds only the 4 losses
        assert_eq!(p.loss_rate(), Some(1.0));
    }

    #[test]
    fn loss_probe_unknown_nonce_ignored() {
        let mut p = LossProbe::new(10);
        assert!(!p.on_pong(999));
        assert_eq!(p.loss_rate(), None);
    }

    #[test]
    fn loss_probe_inflight_not_counted() {
        let mut p = LossProbe::new(10);
        let _ = p.send_ping(0, 2000);
        p.expire(500); // sent at 0, now 500 < deadline 2000
        assert_eq!(p.outstanding(), 1);
        assert_eq!(p.loss_rate(), None); // no completed sample yet
    }

    #[test]
    fn loss_probe_nonce_wraps_safely() {
        let mut p = LossProbe::new(10);
        p.next_nonce = u64::MAX;
        let (n, _) = p.send_ping(0, 300);
        assert_eq!(n, u64::MAX);
        let (n2, _) = p.send_ping(0, 300);
        assert_ne!(n2, 0); // never zero (0 is not used as a valid nonce)
        assert!(p.on_pong(n));
    }

    #[test]
    fn consecutive_miss_death_at_thirteen_and_fourteen() {
        let mut p = LossProbe::new(10);
        for i in 0..13u64 {
            let _ = p.send_ping(i * 1000, 300);
            assert_eq!(p.expire(i * 1000 + 300), 1);
        }
        assert_eq!(p.consecutive_misses(), 13);
        let _ = p.send_ping(13_000, 300);
        assert_eq!(p.expire(13_300), 1);
        assert_eq!(p.consecutive_misses(), 14);
    }

    #[test]
    fn pong_resets_consecutive_misses() {
        let mut p = LossProbe::new(10);
        for i in 0..13u64 {
            let _ = p.send_ping(i * 1000, 300);
            p.expire(i * 1000 + 300);
        }
        assert_eq!(p.consecutive_misses(), 13);
        let (n, _) = p.send_ping(13_000, 300);
        assert!(p.on_pong(n));
        assert_eq!(p.consecutive_misses(), 0);

        // Late pong (nonce already expired) resets too, but returns false.
        for i in 0..13u64 {
            let _ = p.send_ping(20_000 + i * 1000, 300);
            p.expire(20_000 + i * 1000 + 300);
        }
        assert_eq!(p.consecutive_misses(), 13);
        let (late, _) = p.send_ping(33_000, 300);
        p.expire(33_300);
        assert_eq!(p.consecutive_misses(), 14);
        assert!(!p.on_pong(late));
        assert_eq!(p.consecutive_misses(), 0);
    }

    #[test]
    fn per_ping_deadline_is_honored() {
        let mut p = LossProbe::new(10);
        let (a, _) = p.send_ping(0, 300);
        let (b, _) = p.send_ping(100, 1000);
        assert_eq!(p.expire(300), 1, "only the 300ms ping is due");
        assert_eq!(p.outstanding(), 1);
        assert!(p.on_pong(b));
        assert_eq!(p.expire(1099), 0);
        assert_eq!(p.outstanding(), 0);
        assert_eq!(p.consecutive_misses(), 0);
        assert!(!p.on_pong(a));
    }

    #[test]
    fn late_pong_grace_expires() {
        let mut p = LossProbe::new(10);
        let (n, _) = p.send_ping(0, 300);
        assert_eq!(p.expire(300), 1);
        assert_eq!(p.consecutive_misses(), 1);
        // grace is strictly < 2 x deadline (600ms from expiry); at 901ms the
        // entry is pruned and the pong must not reset the counter.
        assert_eq!(p.expire(901), 0);
        assert!(!p.on_pong(n));
        assert_eq!(p.consecutive_misses(), 1);
    }
}
