//! Signal channel: `PunchChannel` over a bidirectional stream on the relayed
//! QUIC connection.
//!
//! Framing: `u8` stream type + `u32` big-endian length prefix + payload
//! (P2 codec bytes). Both ends agree on this framing; it is wireup-level,
//! not part of the frozen P2 contract.
//!
//! Stream types: `0x01` = punch signaling (offer/answer), `0x02` = direct-
//! connection nonce bind (challenge/response), `0x03` = workspace sync
//! (C2; the responder routes by this type to `serve_sync`). Other values are reserved;
//! the responder must NOT consume non-punch streams (see `PunchManager`
//! stream routing): unknown streams are stashed, never mis-decoded.

use std::collections::HashSet;
use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use nexus_fabric::{Cmd, ConnShared, FabricError, StreamShared};
use nexus_nat_traversal::{PunchAnswer, PunchChannel, PunchOffer, decode_answer, encode_offer};

/// Stream type: punch signaling (offer/answer) on the relayed connection.
pub const STREAM_TYPE_PUNCH: u8 = 0x01;
/// Stream type: nonce bind challenge/response on a direct connection.
pub const STREAM_TYPE_BIND: u8 = 0x02;
/// Stream type: workspace sync frames (C2; `serve_sync` on the passive side).
pub const STREAM_TYPE_WORKSPACE_SYNC: u8 = 0x03;

/// Max single frame (64KB — offers/answers are tiny; this is a sanity cap).
pub const MAX_FRAME: usize = 65536;

/// Length-prefix a payload with its stream type (pure, testable).
/// Wire: `u8 type | u32 BE length | payload`.
pub fn frame_msg(ty: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(ty);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Parse one frame from the front of `buf`.
/// Returns `Some((type, payload, consumed))`, or `None` if incomplete/invalid.
pub fn deframe(buf: &[u8]) -> Option<(u8, Vec<u8>, usize)> {
    if buf.len() < 5 {
        return None;
    }
    let ty = buf[0];
    let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
    if len == 0 || len > MAX_FRAME {
        return None;
    }
    if buf.len() < 5 + len {
        return None;
    }
    Some((ty, buf[5..5 + len].to_vec(), 5 + len))
}

fn fabric_err_to_io(e: FabricError) -> io::Error {
    match e {
        FabricError::Timeout => io::Error::new(io::ErrorKind::TimedOut, "fabric timeout"),
        FabricError::Closed(c) => io::Error::new(
            io::ErrorKind::NotConnected,
            format!("fabric connection closed ({c})"),
        ),
        other => io::Error::other(format!("fabric: {other:?}")),
    }
}

/// Read exactly `buf.len()` bytes from a `StreamShared` before `deadline`.
pub fn read_exact_deadline(
    stream: &Arc<StreamShared>,
    buf: &mut [u8],
    deadline: Instant,
) -> io::Result<()> {
    let mut filled = 0usize;
    let mut st = stream
        .state
        .lock()
        .map_err(|_| io::Error::other("stream lock poisoned"))?;
    loop {
        while filled < buf.len() && !st.recv_buf.is_empty() {
            buf[filled] = st.recv_buf.pop_front().expect("checked non-empty");
            filled += 1;
        }
        if filled == buf.len() {
            return Ok(());
        }
        if st.recv_eof {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "punch stream closed by peer",
            ));
        }
        if let Some(e) = st.error.clone() {
            return Err(fabric_err_to_io(e));
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "punch channel read timeout",
            ));
        }
        let (guard, wait) = stream
            .cv
            .wait_timeout(st, deadline - now)
            .map_err(|_| io::Error::other("stream lock poisoned"))?;
        st = guard;
        if wait.timed_out() && st.recv_buf.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "punch channel read timeout",
            ));
        }
    }
}

/// Write all bytes into the stream's send buffer and pump the driver
/// (mirrors `SendStream::write`, which has no public constructor here).
pub fn write_all_stream(stream: &Arc<StreamShared>, buf: &[u8]) -> io::Result<()> {
    let mut st = stream
        .state
        .lock()
        .map_err(|_| io::Error::other("stream lock poisoned"))?;
    if let Some(e) = st.error.clone() {
        return Err(fabric_err_to_io(e));
    }
    st.send_buf.extend(buf.iter().copied());
    let _ = stream.tx.send(Cmd::Pump {
        conn: stream.conn_id,
    });
    Ok(())
}

/// Read one typed message before `deadline`.
/// Returns `(stream type, payload)`.
pub fn read_msg(stream: &Arc<StreamShared>, deadline: Instant) -> io::Result<(u8, Vec<u8>)> {
    let mut hdr = [0u8; 5];
    read_exact_deadline(stream, &mut hdr, deadline)?;
    let ty = hdr[0];
    let len = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]) as usize;
    if len == 0 || len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("bad punch frame length {len}"),
        ));
    }
    let mut payload = vec![0u8; len];
    read_exact_deadline(stream, &mut payload, deadline)?;
    Ok((ty, payload))
}

/// Write one typed message.
pub fn write_msg(stream: &Arc<StreamShared>, ty: u8, payload: &[u8]) -> io::Result<()> {
    if payload.is_empty() || payload.len() > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "punch frame payload out of range",
        ));
    }
    write_all_stream(stream, &frame_msg(ty, payload))
}

/// Peek the stream type of the first frame WITHOUT consuming any bytes.
/// Used by the responder to route streams: punch streams are consumed,
/// everything else is stashed untouched. Waits until at least one byte
/// is available, EOF, error, or `deadline`.
pub fn peek_stream_type(stream: &Arc<StreamShared>, deadline: Instant) -> io::Result<u8> {
    let mut st = stream
        .state
        .lock()
        .map_err(|_| io::Error::other("stream lock poisoned"))?;
    loop {
        if let Some(&b) = st.recv_buf.front() {
            return Ok(b);
        }
        if st.recv_eof {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "stream closed before type byte",
            ));
        }
        if let Some(e) = st.error.clone() {
            return Err(fabric_err_to_io(e));
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "peek stream type timeout",
            ));
        }
        let (guard, wait) = stream
            .cv
            .wait_timeout(st, deadline - now)
            .map_err(|_| io::Error::other("stream lock poisoned"))?;
        st = guard;
        if wait.timed_out() && st.recv_buf.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "peek stream type timeout",
            ));
        }
    }
}

/// Encode a bind response payload: `u8 count | count * u64 BE` nonces.
/// The responder serves every signaling nonce it used with this peer; the
/// challenger accepts if ANY matches a nonce it saw on the relay.
pub fn encode_bind_response(nonces: &[u64]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 8 * nonces.len());
    out.push(nonces.len().min(255) as u8);
    for n in nonces.iter().take(255) {
        out.extend_from_slice(&n.to_be_bytes());
    }
    out
}

/// Decode a bind response payload into the responder's nonce list.
pub fn decode_bind_response(payload: &[u8]) -> io::Result<Vec<u64>> {
    if payload.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "empty bind response",
        ));
    }
    let count = payload[0] as usize;
    if payload.len() != 1 + 8 * count {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("bad bind response length {}", payload.len()),
        ));
    }
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let mut b = [0u8; 8];
        b.copy_from_slice(&payload[1 + 8 * i..1 + 8 * (i + 1)]);
        out.push(u64::from_be_bytes(b));
    }
    Ok(out)
}

/// Bind verification: true iff the responder proved knowledge of at least
/// one nonce from the relay signaling exchange with this peer.
/// Pure and multi-peer safe: each peer has its own expected set, so peer B's
/// nonce can never verify as peer A.
pub fn verify_bind(expected: &HashSet<u64>, response: &[u64]) -> bool {
    response.iter().any(|n| expected.contains(n))
}

/// Open a bidirectional stream on `conn` (shared helper for punch signaling
/// and bind challenges).
pub fn open_bi_stream(conn: &Arc<ConnShared>, timeout: Duration) -> io::Result<Arc<StreamShared>> {
    let (tx, rx) = std::sync::mpsc::channel();
    conn.tx
        .send(Cmd::OpenBi {
            conn: conn.id.0,
            reply: tx,
        })
        .map_err(|_| io::Error::new(io::ErrorKind::NotConnected, "driver gone"))?;
    rx.recv_timeout(timeout)
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "open_bi timeout"))?
        .map_err(fabric_err_to_io)
}

/// `PunchChannel` over a freshly opened bidirectional stream on the relayed
/// connection. The stream stays open for the offer/answer round trip.
/// All frames use `STREAM_TYPE_PUNCH`; the responder routes by this type.
pub struct FabricPunchChannel {
    stream: Arc<StreamShared>,
    /// Nonce of the last offer sent (for bind identity; read after `run()`).
    last_offer_nonce: std::sync::Mutex<Option<u64>>,
}

impl FabricPunchChannel {
    /// Open a bidirectional stream on `relay_conn` for punch signaling.
    pub fn open(relay_conn: &Arc<ConnShared>) -> io::Result<Self> {
        let stream = open_bi_stream(relay_conn, Duration::from_secs(5))?;
        Ok(Self {
            stream,
            last_offer_nonce: std::sync::Mutex::new(None),
        })
    }

    /// Wrap an already-accepted stream (responder side).
    pub fn wrap(stream: Arc<StreamShared>) -> Self {
        Self {
            stream,
            last_offer_nonce: std::sync::Mutex::new(None),
        }
    }

    /// Nonce of the offer most recently sent on this channel, if any.
    pub fn last_offer_nonce(&self) -> Option<u64> {
        self.last_offer_nonce.lock().ok().and_then(|g| *g)
    }
}

impl PunchChannel for FabricPunchChannel {
    fn send_offer(&self, offer: &PunchOffer) -> io::Result<()> {
        let payload = encode_offer(offer);
        if let Ok(mut g) = self.last_offer_nonce.lock() {
            *g = Some(offer.nonce);
        }
        write_msg(&self.stream, STREAM_TYPE_PUNCH, &payload)
    }

    fn recv_answer(&self, timeout: Duration) -> io::Result<PunchAnswer> {
        let deadline = Instant::now() + timeout;
        let (ty, payload) = read_msg(&self.stream, deadline)?;
        if ty != STREAM_TYPE_PUNCH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("expected punch frame, got type {ty:#04x}"),
            ));
        }
        decode_answer(&payload)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e:?}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Red: typed framing must round-trip (type + payload).
    #[test]
    fn frame_type_roundtrip() {
        let payload = b"punch-offer-bytes";
        let framed = frame_msg(STREAM_TYPE_PUNCH, payload);
        let (ty, out, consumed) = deframe(&framed).expect("complete frame must parse");
        assert_eq!(ty, STREAM_TYPE_PUNCH);
        assert_eq!(out, payload);
        assert_eq!(consumed, framed.len());
        // Non-punch type survives the round trip.
        let framed2 = frame_msg(0x7F, payload);
        let (ty2, out2, _) = deframe(&framed2).expect("must parse");
        assert_eq!(ty2, 0x7F);
        assert_eq!(out2, payload);
        // Truncated: no frame (even the 1-byte type header).
        assert!(deframe(&framed[..4]).is_none());
        assert!(deframe(&[]).is_none());
    }

    /// Red: wrong-type frames must be distinguishable from punch frames.
    #[test]
    fn frame_type_distinguishes_punch() {
        let punch = frame_msg(STREAM_TYPE_PUNCH, b"offer");
        let other = frame_msg(0x7F, b"transfer-data");
        let (ty_punch, _, _) = deframe(&punch).unwrap();
        let (ty_other, _, _) = deframe(&other).unwrap();
        assert_ne!(ty_punch, ty_other);
        assert_eq!(ty_punch, STREAM_TYPE_PUNCH);
    }

    /// Bind response codec round-trips the nonce list.
    #[test]
    fn bind_response_roundtrip() {
        let nonces = vec![0xdeadbeef_u64, 0x1234_u64];
        let payload = encode_bind_response(&nonces);
        let back = decode_bind_response(&payload).expect("must decode");
        assert_eq!(back, nonces);
        // Empty list is legal (peer had no nonce — verifies false).
        let empty = decode_bind_response(&encode_bind_response(&[])).unwrap();
        assert!(empty.is_empty());
        // Malformed.
        assert!(decode_bind_response(&[]).is_err());
        assert!(decode_bind_response(&[2, 1, 2, 3]).is_err());
    }

    /// Red (D4): bind verification must accept a matching nonce and reject
    /// a foreign one — per-peer sets, so peer B's nonce never verifies as A.
    #[test]
    fn bind_verify_per_peer() {
        use std::collections::HashSet;
        let expected_a: HashSet<u64> = [111u64].into_iter().collect();
        let expected_b: HashSet<u64> = [222u64].into_iter().collect();
        // Matching nonce verifies.
        assert!(verify_bind(&expected_a, &[111]));
        // Foreign nonce (B's) does NOT verify as A — the multi-peer
        // misidentification case the old heuristic allowed.
        assert!(!verify_bind(&expected_a, &[222]));
        assert!(verify_bind(&expected_b, &[222]));
        // Empty response never verifies.
        assert!(!verify_bind(&expected_a, &[]));
        // Unknown peer (empty expected set) never verifies.
        assert!(!verify_bind(&HashSet::new(), &[111]));
    }
}
