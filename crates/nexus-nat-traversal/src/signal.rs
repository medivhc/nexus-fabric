//! P2 信令编解码（v1.1）：手写二进制。
//!
//! v1 offer 线格式：
//! `version:u8 | nonce:u64 BE | nat_type:u8 | start_at_ms:u64 BE | n:u8 | candidates`
//! v1 answer 线格式：
//! `version:u8 | nonce:u64 BE | nat_type:u8 | n:u8 | candidates`
//! v2 在 v1 字段后追加 `has_prediction:u8`，为 1 时再 7 字节
//! `base_port:u16 BE | delta:i32 BE | samples:u8`。
//! 单个候选：`kind:u8 | family:u8(4|6) | ip(4B|16B) | port:u16 BE`

use std::fmt;
use std::net::{IpAddr, SocketAddr};

use nexus_domain::nat::NatType;

use crate::candidate::{CandidateKind, PunchCandidate};

/// 信令协议版本（v1.1 =2）。
pub const SIGNAL_VERSION: u8 = 2;
/// 单条信令最大候选数（冻结 =16）。
pub const MAX_CANDIDATES: usize = 16;

/// 预测提示（v2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PredictionHint {
    pub base_port: u16,
    pub delta: i32,
    pub samples: u8,
}

/// 打洞提议（发起方 → 响应方）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PunchOffer {
    pub version: u8,
    pub nonce: u64,
    pub candidates: Vec<PunchCandidate>,
    pub nat_type: NatType,
    pub start_at_ms: u64,
    pub prediction: Option<PredictionHint>,
}

/// 打洞应答（响应方 → 发起方；nonce 必须回显 offer 的）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PunchAnswer {
    pub version: u8,
    pub nonce: u64,
    pub candidates: Vec<PunchCandidate>,
    pub nat_type: NatType,
    pub prediction: Option<PredictionHint>,
}

/// 信令编解码错误。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalError {
    Version,
    TooMany,
    Truncated,
    BadNatType,
    BadKind,
    BadFamily,
    BadPrediction,
    TrailingBytes,
}

impl fmt::Display for SignalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            SignalError::Version => "unsupported signal version",
            SignalError::TooMany => "too many candidates",
            SignalError::Truncated => "truncated signal buffer",
            SignalError::BadNatType => "unknown nat_type encoding",
            SignalError::BadKind => "unknown candidate kind encoding",
            SignalError::BadFamily => "unknown address family",
            SignalError::BadPrediction => "invalid prediction hint",
            SignalError::TrailingBytes => "trailing bytes after signal",
        };
        f.write_str(s)
    }
}

impl std::error::Error for SignalError {}

pub fn encode_offer(o: &PunchOffer) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + o.candidates.len() * 20);
    out.push(SIGNAL_VERSION);
    out.extend_from_slice(&o.nonce.to_be_bytes());
    out.push(encode_nat_type(o.nat_type));
    out.extend_from_slice(&o.start_at_ms.to_be_bytes());
    encode_candidates(&o.candidates, &mut out);
    encode_prediction(o.prediction, &mut out);
    out
}

pub fn decode_offer(b: &[u8]) -> Result<PunchOffer, SignalError> {
    let mut r = Reader::new(b);
    let version = r.u8()?;
    if version != SIGNAL_VERSION {
        return Err(SignalError::Version);
    }
    let nonce = r.u64()?;
    let nat_type = decode_nat_type(r.u8()?)?;
    let start_at_ms = r.u64()?;
    let candidates = decode_candidates(&mut r)?;
    let prediction = decode_prediction(&mut r)?;
    r.end()?;
    Ok(PunchOffer {
        version,
        nonce,
        candidates,
        nat_type,
        start_at_ms,
        prediction,
    })
}

pub fn encode_answer(a: &PunchAnswer) -> Vec<u8> {
    let mut out = Vec::with_capacity(24 + a.candidates.len() * 20);
    out.push(SIGNAL_VERSION);
    out.extend_from_slice(&a.nonce.to_be_bytes());
    out.push(encode_nat_type(a.nat_type));
    encode_candidates(&a.candidates, &mut out);
    encode_prediction(a.prediction, &mut out);
    out
}

pub fn decode_answer(b: &[u8]) -> Result<PunchAnswer, SignalError> {
    let mut r = Reader::new(b);
    let version = r.u8()?;
    if version != SIGNAL_VERSION {
        return Err(SignalError::Version);
    }
    let nonce = r.u64()?;
    let nat_type = decode_nat_type(r.u8()?)?;
    let candidates = decode_candidates(&mut r)?;
    let prediction = decode_prediction(&mut r)?;
    r.end()?;
    Ok(PunchAnswer {
        version,
        nonce,
        candidates,
        nat_type,
        prediction,
    })
}

pub fn encode_offer_v1(o: &PunchOffer) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + o.candidates.len() * 20);
    out.push(1);
    out.extend_from_slice(&o.nonce.to_be_bytes());
    out.push(encode_nat_type(o.nat_type));
    out.extend_from_slice(&o.start_at_ms.to_be_bytes());
    encode_candidates(&o.candidates, &mut out);
    out
}

pub fn decode_offer_v1(b: &[u8]) -> Result<PunchOffer, SignalError> {
    let mut r = Reader::new(b);
    let version = r.u8()?;
    if version != 1 {
        return Err(SignalError::Version);
    }
    let nonce = r.u64()?;
    let nat_type = decode_nat_type(r.u8()?)?;
    let start_at_ms = r.u64()?;
    let candidates = decode_candidates(&mut r)?;
    r.end()?;
    Ok(PunchOffer {
        version,
        nonce,
        candidates,
        nat_type,
        start_at_ms,
        prediction: None,
    })
}

pub fn encode_answer_v1(a: &PunchAnswer) -> Vec<u8> {
    let mut out = Vec::with_capacity(24 + a.candidates.len() * 20);
    out.push(1);
    out.extend_from_slice(&a.nonce.to_be_bytes());
    out.push(encode_nat_type(a.nat_type));
    encode_candidates(&a.candidates, &mut out);
    out
}

pub fn decode_answer_v1(b: &[u8]) -> Result<PunchAnswer, SignalError> {
    let mut r = Reader::new(b);
    let version = r.u8()?;
    if version != 1 {
        return Err(SignalError::Version);
    }
    let nonce = r.u64()?;
    let nat_type = decode_nat_type(r.u8()?)?;
    let candidates = decode_candidates(&mut r)?;
    r.end()?;
    Ok(PunchAnswer {
        version,
        nonce,
        candidates,
        nat_type,
        prediction: None,
    })
}

// --- 内部 ---

fn encode_candidates(cands: &[PunchCandidate], out: &mut Vec<u8>) {
    // Contract v1.1: silently truncate to 16 on encode (decode rejects >16).
    // A debug_assert here would abort debug/test builds that intentionally
    // exercise the cap (G18), so truncation is the frozen observable behavior.
    let n = cands.len().min(MAX_CANDIDATES);
    out.push(n as u8);
    for c in cands.iter().take(n) {
        out.push(encode_kind(c.kind));
        encode_ip(&c.addr.ip(), out);
        out.extend_from_slice(&c.addr.port().to_be_bytes());
    }
}

fn decode_candidates(r: &mut Reader<'_>) -> Result<Vec<PunchCandidate>, SignalError> {
    let n = r.u8()?;
    if n as usize > MAX_CANDIDATES {
        return Err(SignalError::TooMany);
    }
    let mut out = Vec::with_capacity(n as usize);
    for _ in 0..n {
        let kind = decode_kind(r.u8()?)?;
        let ip = r.ip()?;
        let port = r.u16()?;
        out.push(PunchCandidate {
            addr: SocketAddr::new(ip, port),
            kind,
        });
    }
    Ok(out)
}

fn encode_prediction(p: Option<PredictionHint>, out: &mut Vec<u8>) {
    match p {
        None => out.push(0),
        Some(h) => {
            out.push(1);
            out.extend_from_slice(&h.base_port.to_be_bytes());
            out.extend_from_slice(&h.delta.to_be_bytes());
            out.push(h.samples);
        }
    }
}

fn decode_prediction(r: &mut Reader<'_>) -> Result<Option<PredictionHint>, SignalError> {
    match r.u8()? {
        0 => Ok(None),
        1 => {
            let base_port = r.u16()?;
            let delta = r.i32()?;
            let samples = r.u8()?;
            if samples < 3 {
                return Err(SignalError::BadPrediction);
            }
            Ok(Some(PredictionHint {
                base_port,
                delta,
                samples,
            }))
        }
        _ => Err(SignalError::BadPrediction),
    }
}

struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], SignalError> {
        let end = self.pos.checked_add(n).ok_or(SignalError::Truncated)?;
        if end > self.b.len() {
            return Err(SignalError::Truncated);
        }
        let s = &self.b[self.pos..end];
        self.pos = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, SignalError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, SignalError> {
        let s = self.take(2)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }
    fn i32(&mut self) -> Result<i32, SignalError> {
        let s = self.take(4)?;
        Ok(i32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn u64(&mut self) -> Result<u64, SignalError> {
        let s = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        Ok(u64::from_be_bytes(a))
    }
    fn ip(&mut self) -> Result<IpAddr, SignalError> {
        match self.u8()? {
            4 => {
                let s = self.take(4)?;
                let mut a = [0u8; 4];
                a.copy_from_slice(s);
                Ok(IpAddr::from(a))
            }
            6 => {
                let s = self.take(16)?;
                let mut a = [0u8; 16];
                a.copy_from_slice(s);
                Ok(IpAddr::from(a))
            }
            _ => Err(SignalError::BadFamily),
        }
    }
    fn end(&self) -> Result<(), SignalError> {
        if self.pos == self.b.len() {
            Ok(())
        } else {
            Err(SignalError::TrailingBytes)
        }
    }
}

fn encode_nat_type(t: NatType) -> u8 {
    match t {
        NatType::FullCone => 0,
        NatType::RestrictedCone => 1,
        NatType::PortRestrictedCone => 2,
        NatType::Symmetric => 3,
        NatType::Unknown => 4,
    }
}

fn decode_nat_type(b: u8) -> Result<NatType, SignalError> {
    match b {
        0 => Ok(NatType::FullCone),
        1 => Ok(NatType::RestrictedCone),
        2 => Ok(NatType::PortRestrictedCone),
        3 => Ok(NatType::Symmetric),
        4 => Ok(NatType::Unknown),
        _ => Err(SignalError::BadNatType),
    }
}

fn encode_kind(k: CandidateKind) -> u8 {
    match k {
        CandidateKind::Host => 0,
        CandidateKind::Srflx => 1,
        CandidateKind::Relay => 2,
    }
}

fn decode_kind(b: u8) -> Result<CandidateKind, SignalError> {
    match b {
        0 => Ok(CandidateKind::Host),
        1 => Ok(CandidateKind::Srflx),
        2 => Ok(CandidateKind::Relay),
        _ => Err(SignalError::BadKind),
    }
}

fn encode_ip(ip: &IpAddr, out: &mut Vec<u8>) {
    match ip {
        IpAddr::V4(v4) => {
            out.push(4);
            out.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            out.push(6);
            out.extend_from_slice(&v6.octets());
        }
    }
}
