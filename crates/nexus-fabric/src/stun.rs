//! Additive STUN transaction tap for NAT candidate gathering.
//!
//! A registered 12-byte transaction id + STUN magic cookie diverts the packet
//! to the sink instead of quinn-proto. Unregistered STUN packets stay on the
//! normal QUIC path (no hijacking). Pending transactions expire after 2000ms.

use std::net::SocketAddr;

/// STUN transaction id (12 bytes at offset 8 of a Binding message).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StunTransactionId(pub [u8; 12]);

#[derive(Debug, Clone)]
pub struct StunRequest {
    pub transaction_id: StunTransactionId,
    pub server: SocketAddr,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct StunResponse {
    pub transaction_id: StunTransactionId,
    pub from: SocketAddr,
    pub bytes: Vec<u8>,
}

pub trait StunSink: Send + Sync {
    fn on_stun_response(&self, response: StunResponse);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StunTapError {
    AlreadyInstalled,
    NotInstalled,
    DriverClosed,
    MalformedRequest,
}

pub(crate) const STUN_MAGIC_COOKIE: u32 = 0x2112_A442;

/// Parse a STUN message header: 20+ bytes, top two bits 00, magic cookie.
pub(crate) fn parse_transaction(b: &[u8]) -> Option<StunTransactionId> {
    if b.len() < 20 || b[0] & 0xC0 != 0 {
        return None;
    }
    let cookie = u32::from_be_bytes([b[4], b[5], b[6], b[7]]);
    if cookie != STUN_MAGIC_COOKIE {
        return None;
    }
    let mut txn = [0u8; 12];
    txn.copy_from_slice(&b[8..20]);
    Some(StunTransactionId(txn))
}
