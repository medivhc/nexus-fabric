//! Production peer sources for NAT relay triggering.
//!
//! The feed merges the three peer sources the node actually has — the static
//! `[[peers]]` table, discovery results (paired/LSA/mDNS through the single
//! [`DiscoveryHub`]) and the live N1 sessions — then keeps a per-peer relay
//! subscription and drives the relay trigger state machine.
//!
//! Design contract (spec §4.4):
//! - one owner, one calling thread: [`PeerSourceFeed`] is held **by value** by
//!   `NatSwitchRuntime` and `tick`/`shutdown` are only ever called from the NAT
//!   worker thread (the `&mut self` receiver plus non-`Arc` ownership makes a
//!   second caller impossible at compile time);
//! - no field locks: every mutable field below is worker-exclusive; only the
//!   published status snapshot is shared (its own `Mutex`) and is written once
//!   per tick, so readers never observe a torn combination;
//! - discovery returns `(PeerId, candidate addr)` only — the feed never dials a
//!   discovered address; triggers use the address book exclusively.

use std::time::Duration;

/// Which sources currently know a peer (spec §4.2).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PeerSources {
    /// Present in the static `[[peers]]` table.
    pub static_cfg: bool,
    /// Present in the paired discovery source.
    pub paired: bool,
    /// Present in the LSA source (inside the freshness window).
    pub lsa: bool,
    /// Present in the mDNS cache.
    pub mdns: bool,
    /// Present in the live N1 session table.
    pub n1: bool,
}

impl PeerSources {
    /// A peer with no source left must be unsubscribed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        !(self.static_cfg || self.paired || self.lsa || self.mdns || self.n1)
    }

    /// Source labels in the frozen order `paired,static,lsa,mdns,n1`
    /// (only true entries, comma separated).
    #[must_use]
    pub fn labels(&self) -> String {
        let mut out: Vec<&'static str> = Vec::new();
        if self.paired {
            out.push("paired");
        }
        if self.static_cfg {
            out.push("static");
        }
        if self.lsa {
            out.push("lsa");
        }
        if self.mdns {
            out.push("mdns");
        }
        if self.n1 {
            out.push("n1");
        }
        out.join(",")
    }
}

/// Strict discovery-id parse: exactly 64 chars, every char `0-9a-f`.
///
/// No trimming, no case folding, and none of the lenient parsers already in
/// the tree (`parse_hex32` accepts `A-F`; `N1PeerId::from_hex` accepts mixed
/// case). Static and N1 ids are `[u8; 32]` already and never take this path.
#[must_use]
pub fn parse_fabric_peer_hex(s: &str) -> Option<nexus_fabric::PeerId> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    let bytes = s.as_bytes();
    for (i, chunk) in bytes.chunks_exact(2).enumerate() {
        let hi = hex_val(chunk[0])?;
        let lo = hex_val(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(nexus_fabric::PeerId(out))
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

/// Trigger timings and limits (spec §4.4.3, frozen values).
#[derive(Debug, Clone)]
pub struct PeerSourceConfig {
    /// Tick interval (worker calls `tick` at most this often).
    pub feed_interval: Duration,
    /// Address-book reload interval.
    pub book_poll_interval: Duration,
    /// Consecutive failures before `Parked{MaxFailures}`.
    pub trigger_max_failures: u32,
    /// Backoff after the 1st/2nd/3rd failure.
    pub trigger_backoff: [Duration; 3],
    /// In-flight trigger deadline.
    pub trigger_inflight_timeout: Duration,
}

impl Default for PeerSourceConfig {
    fn default() -> Self {
        Self {
            feed_interval: Duration::from_millis(1000),
            book_poll_interval: Duration::from_millis(5000),
            trigger_max_failures: 3,
            trigger_backoff: [
                Duration::from_millis(1000),
                Duration::from_millis(2000),
                Duration::from_millis(4000),
            ],
            trigger_inflight_timeout: Duration::from_secs(30),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_follow_frozen_order() {
        let mut s = PeerSources::default();
        assert!(s.is_empty());
        assert_eq!(s.labels(), "");
        s.mdns = true;
        s.static_cfg = true;
        s.paired = true;
        s.lsa = true;
        s.n1 = true;
        assert!(!s.is_empty());
        assert_eq!(s.labels(), "paired,static,lsa,mdns,n1");
    }

    #[test]
    fn parse_rejects_non_canonical_ids() {
        let good = "ab".repeat(32);
        let peer = parse_fabric_peer_hex(&good).expect("canonical id");
        assert_eq!(peer.0, [0xabu8; 32]);

        // Wrong length.
        assert!(parse_fabric_peer_hex(&"ab".repeat(31)).is_none());
        assert!(parse_fabric_peer_hex(&"ab".repeat(33)).is_none());
        // Uppercase is not canonical (no case folding).
        assert!(parse_fabric_peer_hex(&"AB".repeat(32)).is_none());
        // Mixed case.
        let mut mixed = "ab".repeat(32);
        mixed.replace_range(0..1, "A");
        assert!(parse_fabric_peer_hex(&mixed).is_none());
        // Non-hex.
        assert!(parse_fabric_peer_hex(&"zz".repeat(32)).is_none());
        // Whitespace is not trimmed.
        assert!(parse_fabric_peer_hex(&format!(" {} ", good)).is_none());
    }

    #[test]
    fn config_defaults_are_frozen() {
        let cfg = PeerSourceConfig::default();
        assert_eq!(cfg.feed_interval, Duration::from_millis(1000));
        assert_eq!(cfg.book_poll_interval, Duration::from_millis(5000));
        assert_eq!(cfg.trigger_max_failures, 3);
        assert_eq!(
            cfg.trigger_backoff,
            [
                Duration::from_millis(1000),
                Duration::from_millis(2000),
                Duration::from_millis(4000)
            ]
        );
        assert_eq!(cfg.trigger_inflight_timeout, Duration::from_secs(30));
    }
}
