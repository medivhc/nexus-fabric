//! Signal channel: `PunchChannel` over a bidirectional stream on the relayed
//! QUIC connection.
//!
//! Framing: `u32` big-endian length prefix + payload (P2 codec bytes).
//! Both ends agree on this framing; it is wireup-level, not part of the
//! frozen P2 contract.

use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use nexus_fabric::{Cmd, ConnShared, FabricError, StreamShared};
use nexus_nat_traversal::{PunchAnswer, PunchChannel, PunchOffer, decode_answer, encode_offer};

/// Max single frame (64KB — offers/answers are tiny; this is a sanity cap).
pub const MAX_FRAME: usize = 65536;

/// Length-prefix a payload (pure, testable).
pub fn frame_msg(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Parse one frame from the front of `buf`.
/// Returns `Some((payload, consumed))`, or `None` if incomplete/invalid.
pub fn deframe(buf: &[u8]) -> Option<(Vec<u8>, usize)> {
    if buf.len() < 4 {
        return None;
    }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if len == 0 || len > MAX_FRAME {
        return None;
    }
    if buf.len() < 4 + len {
        return None;
    }
    Some((buf[4..4 + len].to_vec(), 4 + len))
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

/// Read one length-prefixed message before `deadline`.
pub fn read_msg(stream: &Arc<StreamShared>, deadline: Instant) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    read_exact_deadline(stream, &mut len_buf, deadline)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("bad punch frame length {len}"),
        ));
    }
    let mut payload = vec![0u8; len];
    read_exact_deadline(stream, &mut payload, deadline)?;
    Ok(payload)
}

/// Write one length-prefixed message.
pub fn write_msg(stream: &Arc<StreamShared>, payload: &[u8]) -> io::Result<()> {
    if payload.is_empty() || payload.len() > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "punch frame payload out of range",
        ));
    }
    write_all_stream(stream, &frame_msg(payload))
}

/// `PunchChannel` over a freshly opened bidirectional stream on the relayed
/// connection. The stream stays open for the offer/answer round trip.
pub struct FabricPunchChannel {
    stream: Arc<StreamShared>,
}

impl FabricPunchChannel {
    /// Open a bidirectional stream on `relay_conn` for punch signaling.
    pub fn open(relay_conn: &Arc<ConnShared>) -> io::Result<Self> {
        let (tx, rx) = std::sync::mpsc::channel();
        relay_conn
            .tx
            .send(Cmd::OpenBi {
                conn: relay_conn.id.0,
                reply: tx,
            })
            .map_err(|_| io::Error::new(io::ErrorKind::NotConnected, "driver gone"))?;
        let stream = rx
            .recv_timeout(Duration::from_secs(5))
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "open_bi timeout"))?
            .map_err(fabric_err_to_io)?;
        Ok(Self { stream })
    }

    /// Wrap an already-accepted stream (responder side).
    pub fn wrap(stream: Arc<StreamShared>) -> Self {
        Self { stream }
    }
}

impl PunchChannel for FabricPunchChannel {
    fn send_offer(&self, offer: &PunchOffer) -> io::Result<()> {
        let payload = encode_offer(offer);
        write_msg(&self.stream, &payload)
    }

    fn recv_answer(&self, timeout: Duration) -> io::Result<PunchAnswer> {
        let deadline = Instant::now() + timeout;
        let payload = read_msg(&self.stream, deadline)?;
        decode_answer(&payload)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e:?}")))
    }
}
