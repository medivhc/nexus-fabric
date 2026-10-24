//! B14 candidate gathering (fix round, 2026-10-25).
//!
//! Implements the plan-required `CandidateGatherer` (develop-plan B14) per
//! spec v1.1: the spec's `CandidateGatherer` API (§14.x: `new(stun,
//! local_bind)` / `gather(turn_mapped, turn_same_socket, samples)`) and the
//! §4.1 item 3 copy rule, with `GatherError` per §13.8.
//!
//! # The copy rule (AC-1)
//!
//! `srflx_turn` (TURN Allocate's XOR-MAPPED) is **diagnostic**: it is
//! recorded on `LocalCandidates` whenever a TURN mapping exists, but it
//! becomes authoritative `srflx` **only** when BOTH hold:
//!
//! 1. the TURN client's local UDP socket is the punch driver's socket
//!    (`turn_same_socket`, explicitly asserted by the composition root —
//!    spec §4.1 item 3: same-socket must never be assumed); and
//! 2. the NAT is non-Symmetric (cone: Full / Restricted / PortRestricted —
//!    the mapping is destination-independent, so the TURN-observed mapping
//!    is valid for direct punching).
//!
//! Otherwise `srflx_turn` stays diagnostic and never enters `ordered()`
//! (that rule lives in `candidate.rs` and is unchanged here).
//!
//! # Two spec-signature gaps, closed explicitly (fix-round notes)
//!
//! 1. The spec's `gather()` signature carries no NAT-type input, but the
//!    copy rule needs one. The composition root supplies the detected type
//!    via [`CandidateGatherer::set_nat_type`] before calling `gather()`.
//!    Default is `Unknown`, which is fail-closed: it never copies.
//! 2. `gather()` takes `samples: &mut Vec<PortSample>` but this round does
//!    not append or filter: sample collection stays with the caller's STUN
//!    path (filtering here would empty production samples, whose STUN
//!    transport is a separate socket — see below). The `&mut` is
//!    spec-structural; a future refresh step may append here.
//!
//! # Production scope note (pre-existing, not changed by this fix)
//!
//! The daemon worker's STUN prober still uses a separate `UdpStunTransport`
//! socket, not the punch driver's socket (the `DriverStunTransport` tap
//! exists and is unit-tested, but the worker does not use it). That means
//! production STUN-derived `srflx` is not same-socket evidence today, and
//! production `turn_same_socket` is `false` (the `TurnManager` owns its own
//! socket). The gatherer therefore yields diagnostic-only `srflx_turn` in
//! production today — which is the spec-correct outcome for those inputs,
//! not a gap: the copy path activates automatically if/when TURN shares
//! the punch socket, and it is proven by the quadrant tests below.

use std::net::SocketAddr;

use nexus_connectivity::nat::NatType;
use nexus_nat_traversal::{LocalCandidates, PortSample};

use crate::nat_stun::{StunError, StunProber};
use crate::nat_turn::TurnError;

/// Spec §13.8 gather errors.
///
/// - `Stun`: STUN probing failed — caller keeps previous candidates, WARN.
/// - `Turn`: TURN allocation/mapping failed — `srflx_turn=None`, the relay
///   path is unaffected. This variant is produced by the composition root
///   when TURN allocation fails (the worker maps `ensure_allocated` errors
///   to WARN + `turn_mapped=None`); `gather()` itself never constructs it,
///   because it receives the mapping as an `Option`.
/// - `NoCandidates`: host and srflx are both empty — caller must not signal
///   or punch (`StayedOnRelay{NoCandidates}`).
#[derive(Debug)]
pub enum GatherError {
    Stun(StunError),
    Turn(TurnError),
    NoCandidates,
}

impl std::fmt::Display for GatherError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GatherError::Stun(e) => write!(f, "STUN gather failed: {e}"),
            GatherError::Turn(e) => write!(f, "TURN gather failed: {e}"),
            GatherError::NoCandidates => write!(f, "no punchable candidates"),
        }
    }
}

impl std::error::Error for GatherError {}

/// Spec §14.x candidate gatherer.
///
/// Holds the composition root's STUN prober (spec-structural: `gather()`
/// is a pure composition step and issues no network I/O) and the punch
/// socket's local bind address (the host-candidate fallback).
pub struct CandidateGatherer {
    stun: StunProber,
    local_bind: SocketAddr,
    nat_type: NatType,
}

impl CandidateGatherer {
    /// Spec signature: `new(stun, local_bind)`.
    pub fn new(stun: StunProber, local_bind: SocketAddr) -> Self {
        Self {
            stun,
            local_bind,
            nat_type: NatType::Unknown,
        }
    }

    /// Additive (see module docs): supply the NAT type detected by the
    /// composition root (`StunProber::detect_nat_type`口径) before
    /// `gather()`. Default `Unknown` never copies (fail-closed).
    pub fn set_nat_type(&mut self, nat_type: NatType) {
        self.nat_type = nat_type;
    }

    /// The held STUN prober, for the composition root to run detection
    /// through the same instance (`probe_and_detect`).
    pub fn stun_prober(&mut self) -> &mut StunProber {
        &mut self.stun
    }

    /// Spec signature: `gather(turn_mapped, turn_same_socket, samples)`.
    ///
    /// Pure composition, no I/O:
    /// - `host`: `[local_bind]` unless the bind address is unspecified.
    /// - `srflx_turn`: `turn_mapped` whenever present (diagnostic).
    /// - `srflx`: `turn_mapped` **iff** `turn_same_socket` and the NAT
    ///   type is cone (Full / Restricted / PortRestricted). Otherwise
    ///   `None` — the caller overlays its STUN-derived `srflx` afterwards.
    /// - `srflx_stun`: `None` here; the caller fills it from its STUN path.
    /// - `nat_type`: the type supplied via `set_nat_type`.
    ///
    /// Returns `Err(NoCandidates)` iff the composed set has no host and no
    /// `srflx` (caller: keep previous candidates, WARN).
    pub fn gather(
        &mut self,
        turn_mapped: Option<SocketAddr>,
        turn_same_socket: bool,
        _samples: &mut Vec<PortSample>,
    ) -> Result<LocalCandidates, GatherError> {
        let host = if self.local_bind.ip().is_unspecified() {
            Vec::new()
        } else {
            vec![self.local_bind]
        };
        let is_cone = matches!(
            self.nat_type,
            NatType::FullCone | NatType::RestrictedCone | NatType::PortRestrictedCone
        );
        let srflx = if turn_same_socket && is_cone {
            turn_mapped
        } else {
            None
        };
        if host.is_empty() && srflx.is_none() {
            return Err(GatherError::NoCandidates);
        }
        Ok(LocalCandidates {
            host,
            srflx,
            srflx_stun: None,
            srflx_turn: turn_mapped,
            nat_type: self.nat_type,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nat_stun::StunTransport;
    use std::time::Duration;

    struct NullTransport {
        local: SocketAddr,
    }

    impl StunTransport for NullTransport {
        fn send_recv(
            &mut self,
            _request: &[u8],
            _server: SocketAddr,
            _timeout: Duration,
        ) -> Result<Vec<u8>, StunError> {
            Err(StunError::Timeout)
        }

        fn local_addr(&self) -> Result<SocketAddr, StunError> {
            Ok(self.local)
        }
    }

    fn gatherer(bind: &str) -> CandidateGatherer {
        let local: SocketAddr = bind.parse().unwrap();
        CandidateGatherer::new(StunProber::new(Box::new(NullTransport { local })), local)
    }

    fn mapped() -> SocketAddr {
        "203.0.113.7:45000".parse().unwrap()
    }

    fn sample() -> PortSample {
        PortSample {
            port: 45000,
            at_ms: 0,
            target: "198.51.100.1:3478".parse().unwrap(),
            observed_from: "192.0.2.5:54321".parse().unwrap(),
        }
    }

    #[test]
    fn copy_same_socket_cone_becomes_authoritative() {
        let mut g = gatherer("192.0.2.5:54321");
        g.set_nat_type(NatType::RestrictedCone);
        let mut samples = vec![sample()];
        let c = g.gather(Some(mapped()), true, &mut samples).unwrap();
        assert_eq!(c.srflx, Some(mapped()));
        assert_eq!(c.srflx_turn, Some(mapped()));
        assert_eq!(c.authoritative_srflx(), Some(mapped()));
        assert_eq!(c.ordered()[0].addr, mapped());
        // Samples pass through untouched this round (see module docs).
        assert_eq!(samples.len(), 1);
    }

    #[test]
    fn full_cone_and_port_restricted_cone_also_copy() {
        for nat in [NatType::FullCone, NatType::PortRestrictedCone] {
            let mut g = gatherer("192.0.2.5:54321");
            g.set_nat_type(nat);
            let mut samples = vec![];
            let c = g.gather(Some(mapped()), true, &mut samples).unwrap();
            assert_eq!(c.srflx, Some(mapped()), "nat={nat:?}");
        }
    }

    #[test]
    fn symmetric_never_copies_diagnostic_only() {
        let mut g = gatherer("192.0.2.5:54321");
        g.set_nat_type(NatType::Symmetric);
        let mut samples = vec![];
        let c = g.gather(Some(mapped()), true, &mut samples).unwrap();
        assert_eq!(c.srflx, None);
        assert_eq!(c.srflx_turn, Some(mapped()));
        assert!(!c.ordered().iter().any(|p| p.addr == mapped()));
    }

    #[test]
    fn separate_socket_never_copies_even_when_cone() {
        let mut g = gatherer("192.0.2.5:54321");
        g.set_nat_type(NatType::RestrictedCone);
        let mut samples = vec![];
        let c = g.gather(Some(mapped()), false, &mut samples).unwrap();
        assert_eq!(c.srflx, None);
        assert_eq!(c.srflx_turn, Some(mapped()));
        assert!(!c.ordered().iter().any(|p| p.addr == mapped()));
    }

    #[test]
    fn unknown_nat_type_is_fail_closed() {
        // set_nat_type never called: default Unknown must not copy.
        let mut g = gatherer("192.0.2.5:54321");
        let mut samples = vec![];
        let c = g.gather(Some(mapped()), true, &mut samples).unwrap();
        assert_eq!(c.srflx, None);
        assert_eq!(c.srflx_turn, Some(mapped()));
    }

    #[test]
    fn no_turn_mapping_is_not_an_error_when_host_exists() {
        let mut g = gatherer("192.0.2.5:54321");
        g.set_nat_type(NatType::RestrictedCone);
        let mut samples = vec![];
        let c = g.gather(None, true, &mut samples).unwrap();
        assert_eq!(c.srflx, None);
        assert_eq!(c.srflx_turn, None);
        assert_eq!(
            c.host,
            vec!["192.0.2.5:54321".parse::<SocketAddr>().unwrap()]
        );
    }

    #[test]
    fn unspecified_bind_with_no_copy_is_no_candidates() {
        let mut g = gatherer("0.0.0.0:54321");
        g.set_nat_type(NatType::RestrictedCone);
        let mut samples = vec![];
        // Not same-socket: no srflx, no host -> NoCandidates.
        let err = g.gather(Some(mapped()), false, &mut samples).unwrap_err();
        assert!(matches!(err, GatherError::NoCandidates));
        // Same-socket + cone would have copied, so this is not an error:
        let mut g2 = gatherer("0.0.0.0:54321");
        g2.set_nat_type(NatType::RestrictedCone);
        let mut samples2 = vec![];
        let c = g2.gather(Some(mapped()), true, &mut samples2).unwrap();
        assert_eq!(c.srflx, Some(mapped()));
        assert!(c.host.is_empty());
    }
}
