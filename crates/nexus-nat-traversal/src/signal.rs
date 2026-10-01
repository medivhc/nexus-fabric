//! P2 信令编解码（冻结合同 §P2）：手写二进制。
//!
//! Offer 线格式：
//! `version:u8 | nonce:u64 BE | nat_type:u8 | start_at_ms:u64 BE | n:u8 | candidates`
//! Answer 线格式：
//! `version:u8 | nonce:u64 BE | nat_type:u8 | n:u8 | candidates`
//! 单个候选：`kind:u8 | family:u8(4|6) | ip(4B|16B) | port:u16 BE`

use std::fmt;
use std::net::{IpAddr, SocketAddr};

use nexus_connectivity::nat::NatType;

use crate::candidate::{CandidateKind, PunchCandidate};

/// 信令协议版本（冻结 =1）。
pub const SIGNAL_VERSION: u8 = 1;
/// 单条信令最大候选数（冻结 =16）。
pub const MAX_CANDIDATES: usize = 16;

/// 打洞提议（发起方 → 响应方）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PunchOffer {
    pub version: u8,
    pub nonce: u64,
    pub candidates: Vec<PunchCandidate>,
    pub nat_type: NatType,
    /// 发送方建议开打时间（unix ms）。
    pub start_at_ms: u64,
}

/// 打洞应答（响应方 → 发起方；nonce 必须回显 offer 的）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PunchAnswer {
    pub version: u8,
    pub nonce: u64,
    pub candidates: Vec<PunchCandidate>,
    pub nat_type: NatType,
}

/// 信令编解码错误。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalError {
    /// version != 1。
    Version,
    /// 候选数 > 16。
    TooMany,
    /// 输入过短。
    Truncated,
    /// 未知 nat_type 编码。
    BadNatType,
    /// 未知 candidate kind 编码。
    BadKind,
    /// family 不是 4/6。
    BadFamily,
    /// 解码后有多余字节。
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
            SignalError::TrailingBytes => "trailing bytes after signal",
        };
        f.write_str(s)
    }
}

impl std::error::Error for SignalError {}

pub fn encode_offer(o: &PunchOffer) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + o.candidates.len() * 20);
    out.push(o.version);
    out.extend_from_slice(&o.nonce.to_be_bytes());
    out.push(encode_nat_type(o.nat_type));
    out.extend_from_slice(&o.start_at_ms.to_be_bytes());
    encode_candidates(&o.candidates, &mut out);
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
    r.end()?;
    Ok(PunchOffer {
        version,
        nonce,
        candidates,
        nat_type,
        start_at_ms,
    })
}

pub fn encode_answer(a: &PunchAnswer) -> Vec<u8> {
    let mut out = Vec::with_capacity(24 + a.candidates.len() * 20);
    out.push(a.version);
    out.extend_from_slice(&a.nonce.to_be_bytes());
    out.push(encode_nat_type(a.nat_type));
    encode_candidates(&a.candidates, &mut out);
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
    r.end()?;
    Ok(PunchAnswer {
        version,
        nonce,
        candidates,
        nat_type,
    })
}

// --- 内部 ---

fn encode_candidates(cands: &[PunchCandidate], out: &mut Vec<u8>) {
    // u8 长度前缀：最多编码 255 个；合同的 16 上限由 decode 侧以 TooMany 拒绝。
    let n = cands.len().min(255);
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

/// 严格读取器：越界 → Truncated；尾部多余 → TrailingBytes。
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

// --- 内部 ---

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
