//! Responder: accept punch offers on relayed connections, answer on the
//! same stream, and punch back.
//!
//! The responder reuses the frozen `PunchSession` state machine via
//! [`PreAnsweredChannel`]: the offer was already answered on the accepted
//! stream, so the session's own offer is a nonce-capturing no-op and
//! `recv_answer` replays the prebuilt answer.

use std::io;
use std::sync::Mutex;
use std::time::Duration;

use nexus_connectivity::nat::NatType;
use nexus_nat_traversal::{PunchAnswer, PunchCandidate, PunchChannel, PunchOffer, SIGNAL_VERSION};

/// `PunchChannel` adapter for the responder path.
///
/// - `send_offer`: captures the session's nonce (no network I/O — the real
///   answer was already written on the accepted stream).
/// - `recv_answer`: returns the prebuilt answer with the captured nonce.
pub struct PreAnsweredChannel {
    candidates: Vec<PunchCandidate>,
    nat_type: NatType,
    nonce: Mutex<Option<u64>>,
}

impl PreAnsweredChannel {
    /// `candidates`/`nat_type` are the *initiator's* (from the accepted
    /// offer): the session punches toward them.
    pub fn new(candidates: Vec<PunchCandidate>, nat_type: NatType) -> Self {
        Self {
            candidates,
            nat_type,
            nonce: Mutex::new(None),
        }
    }
}

impl PunchChannel for PreAnsweredChannel {
    fn send_offer(&self, offer: &PunchOffer) -> io::Result<()> {
        *self
            .nonce
            .lock()
            .map_err(|_| io::Error::other("preanswered lock poisoned"))? = Some(offer.nonce);
        Ok(())
    }

    fn recv_answer(&self, _timeout: Duration) -> io::Result<PunchAnswer> {
        let nonce = self
            .nonce
            .lock()
            .map_err(|_| io::Error::other("preanswered lock poisoned"))?
            .ok_or_else(|| io::Error::other("send_offer not called"))?;
        Ok(PunchAnswer {
            version: SIGNAL_VERSION,
            nonce,
            candidates: self.candidates.clone(),
            nat_type: self.nat_type,
        })
    }
}
