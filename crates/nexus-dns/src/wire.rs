//! DNS wire 格式编解码（纯函数）。
//!
//! 边界（冻结）：本模块**无 I/O、无时间、无全局状态**；真实 socket 在
//! `nexusd`。这里只负责把查询/响应字节与结构化类型互转，供上游引擎与
//! 数据面回包共用。
//!
//! 12 字节规则（spec §5.2 / §5.7 R2）：DNS 头不足 12 字节 → `Truncated`
//! （调用方丢弃、不回包）；≥12 字节后 QDCOUNT≠1 / opcode≠QUERY →
//! `BadHeader`（调用方可回 FORMERR）；question 段缺失 → `NoQuestion`；
//! QTYPE/QCLASS 截断 → `BadQuestion`；name 非法/压缩指针（查询侧）→
//! `BadName`。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::{DnsQuery, DnsType};

const HEADER_LEN: usize = 12;
const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const TYPE_OPT: u16 = 41;
const CLASS_IN: u16 = 1;
const FLAG_QR: u16 = 0x8000;
const FLAG_OPCODE_MASK: u16 = 0x7800;
const FLAG_TC: u16 = 0x0200;
const FLAG_RD: u16 = 0x0100;
const FLAG_RA: u16 = 0x0080;
const RCODE_MASK: u16 = 0x000f;
const MAX_NAME_LEN: usize = 253;
const MAX_POINTER_JUMPS: u8 = 16;

/// DNS RCODE（仅列本 run 需要的语义值；其余保留原始低 4 位）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsRcode {
    /// 0 — 正常。
    NoError,
    /// 1 — 报文格式错误。
    FormErr,
    /// 2 — 服务器失败。
    ServFail,
    /// 3 — 名字不存在。
    NxDomain,
    /// 4 — 未实现。
    NotImp,
    /// 5 — 拒绝。
    Refused,
    /// 其它取值（原样保留）。
    Other(u8),
}

impl DnsRcode {
    /// 取 wire 低 4 位。
    #[must_use]
    pub fn code(&self) -> u8 {
        match self {
            Self::NoError => 0,
            Self::FormErr => 1,
            Self::ServFail => 2,
            Self::NxDomain => 3,
            Self::NotImp => 4,
            Self::Refused => 5,
            Self::Other(v) => *v & 0x0f,
        }
    }

    /// 从 wire 低 4 位还原。
    #[must_use]
    pub fn from_code(code: u8) -> Self {
        match code & 0x0f {
            0 => Self::NoError,
            1 => Self::FormErr,
            2 => Self::ServFail,
            3 => Self::NxDomain,
            4 => Self::NotImp,
            5 => Self::Refused,
            other => Self::Other(other),
        }
    }
}

/// 解析后的查询（含 EDNS UDP size）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    /// 报文 ID。
    pub id: u16,
    /// 查询名（小写规范形式，不含结尾点）。
    pub name: String,
    /// QTYPE 原值（A=1 / AAAA=28 / 其它原样保留）。
    pub qtype: u16,
    /// RD 位。
    pub rd: bool,
    /// EDNS OPT 的 UDP payload size（无 OPT 为 `None`）。
    pub edns_udp_size: Option<u16>,
}

impl DnsQuestion {
    /// 把 QTYPE 映射为 `DnsType`；非 A/AAAA 返回 `None`（上游透传场景）。
    #[must_use]
    pub fn as_dns_type(&self) -> Option<DnsType> {
        match self.qtype {
            TYPE_A => Some(DnsType::A),
            TYPE_AAAA => Some(DnsType::Aaaa),
            _ => None,
        }
    }
}

/// 一条 wire 记录（`address` 仅 A/AAAA 有值）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireRecord {
    /// RR TYPE。
    pub rtype: u16,
    /// RR TTL（秒）。
    pub ttl_secs: u32,
    /// A/AAAA 的地址；其它类型为 `None`。
    pub address: Option<IpAddr>,
}

/// 解析后的上游响应。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamReply {
    /// 响应 RCODE。
    pub rcode: DnsRcode,
    /// TC 位（调用方应转 TCP 重试）。
    pub truncated: bool,
    /// answer 段记录。
    pub records: Vec<WireRecord>,
    /// answer 段最小 TTL（无记录为 0）。
    pub min_ttl_secs: u32,
    /// 原始报文（回包/审计用）。
    pub wire: Vec<u8>,
}

/// wire 层错误（spec §5.2 的 7 变体，无更多）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsWireError {
    /// 报文短于必需字段。
    Truncated,
    /// QDCOUNT≠1、opcode≠QUERY、或响应缺少 QR 位。
    BadHeader,
    /// 标签越界 / 查询中出现压缩指针 / 标签长度>63 / 名字过长。
    BadName,
    /// question 段完全缺失。
    NoQuestion,
    /// QTYPE/QCLASS 截断或 class 非 IN。
    BadQuestion,
    /// 响应 name/qtype 与请求不符。
    MismatchedQuestion,
    /// 内部 API 不接受该 RR TYPE / 地址族组合。
    UnsupportedType(u16),
}

impl std::fmt::Display for DnsWireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => write!(f, "dns wire message truncated"),
            Self::BadHeader => write!(f, "dns wire bad header"),
            Self::BadName => write!(f, "dns wire bad name"),
            Self::NoQuestion => write!(f, "dns wire has no question"),
            Self::BadQuestion => write!(f, "dns wire bad question"),
            Self::MismatchedQuestion => write!(f, "dns wire response question mismatch"),
            Self::UnsupportedType(t) => write!(f, "dns wire unsupported type {t}"),
        }
    }
}

impl std::error::Error for DnsWireError {}

// ---------- 头部 ----------

struct Header {
    id: u16,
    flags: u16,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
}

fn read_u16(packet: &[u8], off: usize) -> Result<u16, DnsWireError> {
    let bytes = packet.get(off..off + 2).ok_or(DnsWireError::Truncated)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_u32(packet: &[u8], off: usize) -> Result<u32, DnsWireError> {
    let bytes = packet.get(off..off + 4).ok_or(DnsWireError::Truncated)?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn parse_header(packet: &[u8]) -> Result<Header, DnsWireError> {
    if packet.len() < HEADER_LEN {
        return Err(DnsWireError::Truncated);
    }
    Ok(Header {
        id: read_u16(packet, 0)?,
        flags: read_u16(packet, 2)?,
        qdcount: read_u16(packet, 4)?,
        ancount: read_u16(packet, 6)?,
        nscount: read_u16(packet, 8)?,
        arcount: read_u16(packet, 10)?,
    })
}

// ---------- 名字 ----------

fn parse_name(
    packet: &[u8],
    off: &mut usize,
    allow_compression: bool,
) -> Result<String, DnsWireError> {
    let mut pos = *off;
    let mut name = String::new();
    let mut jumped = false;
    let mut jumps = 0u8;

    loop {
        let len_byte = *packet.get(pos).ok_or(DnsWireError::BadName)?;
        if len_byte & 0xc0 == 0xc0 {
            if !allow_compression {
                return Err(DnsWireError::BadName);
            }
            let low = *packet.get(pos + 1).ok_or(DnsWireError::BadName)?;
            let target = ((usize::from(len_byte & 0x3f)) << 8) | usize::from(low);
            if target >= packet.len() {
                return Err(DnsWireError::BadName);
            }
            jumps += 1;
            if jumps > MAX_POINTER_JUMPS {
                return Err(DnsWireError::BadName);
            }
            if !jumped {
                *off = pos + 2;
                jumped = true;
            }
            pos = target;
            continue;
        }
        if len_byte & 0xc0 != 0 {
            // 0x40/0x80：历史/保留标签类型，不接受。
            return Err(DnsWireError::BadName);
        }
        let label_len = usize::from(len_byte);
        if label_len == 0 {
            if !jumped {
                *off = pos + 1;
            }
            break;
        }
        if label_len > 63 {
            return Err(DnsWireError::BadName);
        }
        let end = pos + 1 + label_len;
        let label = packet.get(pos + 1..end).ok_or(DnsWireError::BadName)?;
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(&String::from_utf8_lossy(label));
        if name.len() > MAX_NAME_LEN {
            return Err(DnsWireError::BadName);
        }
        pos = end;
    }

    Ok(name.to_ascii_lowercase())
}

fn encode_name(name: &str) -> Result<Vec<u8>, DnsWireError> {
    let trimmed = name.strip_suffix('.').unwrap_or(name);
    if trimmed.is_empty() {
        return Err(DnsWireError::BadName);
    }
    let mut out = Vec::with_capacity(trimmed.len() + 2);
    for label in trimmed.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(DnsWireError::BadName);
        }
        out.push(u8::try_from(label.len()).map_err(|_| DnsWireError::BadName)?);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    if out.len() > 255 {
        return Err(DnsWireError::BadName);
    }
    Ok(out)
}

/// 跳过一条 RR，返回 `(rtype, class)`；用于定位 EDNS OPT。
fn skip_rr(packet: &[u8], off: &mut usize) -> Result<(u16, u16), DnsWireError> {
    let _name = parse_name(packet, off, true)?;
    let rtype = read_u16(packet, *off)?;
    let class = read_u16(packet, *off + 2)?;
    let _ttl = read_u32(packet, *off + 4)?;
    let rdlen = usize::from(read_u16(packet, *off + 8)?);
    let end = *off + 10 + rdlen;
    if end > packet.len() {
        return Err(DnsWireError::Truncated);
    }
    *off = end;
    Ok((rtype, class))
}

/// 尽力提取 EDNS OPT 的 UDP size；附加段不可解析时不报错（查询仍可用）。
fn find_edns(packet: &[u8], mut off: usize, header: &Header) -> Option<u16> {
    let skip = usize::from(header.ancount)
        .checked_add(usize::from(header.nscount))?
        .checked_add(usize::from(header.arcount))?;
    for _ in 0..skip {
        let (rtype, class) = skip_rr(packet, &mut off).ok()?;
        if rtype == TYPE_OPT {
            return Some(class);
        }
    }
    None
}

// ---------- 公开 API ----------

/// 解析客户端查询。
///
/// # Errors
///
/// 见 [`DnsWireError`]；12 字节规则与各类判定见模块文档。
pub fn parse_question(packet: &[u8]) -> Result<DnsQuestion, DnsWireError> {
    let header = parse_header(packet)?;
    if header.flags & FLAG_QR != 0 {
        return Err(DnsWireError::BadHeader);
    }
    if header.flags & FLAG_OPCODE_MASK != 0 {
        return Err(DnsWireError::BadHeader);
    }
    if header.qdcount != 1 {
        return Err(DnsWireError::BadHeader);
    }

    let mut off = HEADER_LEN;
    if off >= packet.len() {
        return Err(DnsWireError::NoQuestion);
    }
    let name = parse_name(packet, &mut off, false)?;
    if name.is_empty() {
        return Err(DnsWireError::BadName);
    }
    if off + 4 > packet.len() {
        return Err(DnsWireError::BadQuestion);
    }
    let qtype = read_u16(packet, off)?;
    let qclass = read_u16(packet, off + 2)?;
    if qclass != CLASS_IN {
        return Err(DnsWireError::BadQuestion);
    }
    off += 4;

    Ok(DnsQuestion {
        id: header.id,
        name,
        qtype,
        rd: header.flags & FLAG_RD != 0,
        edns_udp_size: find_edns(packet, off, &header),
    })
}

/// 构造一条上游查询。
///
/// 调用方保证 `q.name` 合法（来自 [`parse_question`] 或启动期校验）；非法名
/// 返回空 `Vec`，上游引擎应视为构造失败而不是发送空包。
#[must_use]
pub fn build_query(q: &DnsQuery, id: u16, edns_udp_size: Option<u16>) -> Vec<u8> {
    let Ok(name) = encode_name(&q.name) else {
        return Vec::new();
    };
    let qtype = match q.qtype {
        DnsType::A => TYPE_A,
        DnsType::Aaaa => TYPE_AAAA,
    };
    let arcount: u16 = if edns_udp_size.is_some() { 1 } else { 0 };
    let mut out = Vec::with_capacity(HEADER_LEN + name.len() + 4 + 11);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&FLAG_RD.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&arcount.to_be_bytes());
    out.extend_from_slice(&name);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    if let Some(size) = edns_udp_size {
        out.push(0); // OPT 根名
        out.extend_from_slice(&TYPE_OPT.to_be_bytes());
        out.extend_from_slice(&size.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes()); // extended rcode/flags = 0
        out.extend_from_slice(&0u16.to_be_bytes()); // rdlen = 0
    }
    out
}

/// 复制请求的 question 段（name + QTYPE + QCLASS），返回 `(bytes, 结束偏移)`。
fn question_section(query: &[u8]) -> Result<(Vec<u8>, usize), DnsWireError> {
    let mut off = HEADER_LEN;
    let _name = parse_name(query, &mut off, false)?;
    if off + 4 > query.len() {
        return Err(DnsWireError::BadQuestion);
    }
    off += 4;
    Ok((query[HEADER_LEN..off].to_vec(), off))
}

fn response_flags(request_flags: u16, rcode: DnsRcode) -> u16 {
    FLAG_QR | FLAG_RA | (request_flags & FLAG_RD) | u16::from(rcode.code())
}

/// 构造本地应答（A/AAAA 记录、NODATA 或带 rcode 的空应答）。
///
/// # Errors
///
/// 请求头/question 非法 → 对应 [`DnsWireError`]；记录 TYPE 与地址族不符 →
/// `UnsupportedType(rtype)`。
pub fn build_answer(
    query: &[u8],
    records: &[WireRecord],
    rcode: DnsRcode,
) -> Result<Vec<u8>, DnsWireError> {
    let header = parse_header(query)?;
    if header.qdcount != 1 {
        return Err(DnsWireError::BadHeader);
    }
    let (question, _end) = question_section(query)?;

    let mut out = Vec::with_capacity(HEADER_LEN + question.len() + records.len() * 16);
    out.extend_from_slice(&header.id.to_be_bytes());
    out.extend_from_slice(&response_flags(header.flags, rcode).to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(
        &u16::try_from(records.len())
            .map_err(|_| DnsWireError::BadHeader)?
            .to_be_bytes(),
    );
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&question);

    for record in records {
        let rdata = match (record.rtype, record.address) {
            (TYPE_A, Some(IpAddr::V4(v4))) => v4.octets().to_vec(),
            (TYPE_AAAA, Some(IpAddr::V6(v6))) => v6.octets().to_vec(),
            (TYPE_A | TYPE_AAAA, Some(_)) => {
                return Err(DnsWireError::UnsupportedType(record.rtype));
            }
            (_, Some(_)) => return Err(DnsWireError::UnsupportedType(record.rtype)),
            (_, None) => Vec::new(),
        };
        out.extend_from_slice(&[0xc0, 0x0c]); // 指向 question 的 name
        out.extend_from_slice(&record.rtype.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&record.ttl_secs.to_be_bytes());
        out.extend_from_slice(
            &u16::try_from(rdata.len())
                .map_err(|_| DnsWireError::UnsupportedType(record.rtype))?
                .to_be_bytes(),
        );
        out.extend_from_slice(&rdata);
    }

    Ok(out)
}

/// 构造错误应答（FORMERR/SERVFAIL/NXDOMAIN/REFUSED…）。
///
/// 首 12 字节不足 → `Truncated`（调用方丢弃，不回包）。question 可解析时回显，
/// 否则 QDCOUNT=0。
///
/// # Errors
///
/// 仅当报文不足 12 字节（无法取得 txid）时返回 `Truncated`。
pub fn build_error(query: &[u8], rcode: DnsRcode) -> Result<Vec<u8>, DnsWireError> {
    let header = parse_header(query)?;
    let (question, has_question) = if header.qdcount == 1 {
        match question_section(query) {
            Ok((bytes, _end)) => (bytes, true),
            Err(_) => (Vec::new(), false),
        }
    } else {
        (Vec::new(), false)
    };

    let mut out = Vec::with_capacity(HEADER_LEN + question.len());
    out.extend_from_slice(&header.id.to_be_bytes());
    out.extend_from_slice(&response_flags(header.flags, rcode).to_be_bytes());
    let qdcount: u16 = if has_question { 1 } else { 0 };
    out.extend_from_slice(&qdcount.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&question);
    Ok(out)
}

/// 改写报文 ID（用于并发上游响应的复用/校验）。
///
/// # Errors
///
/// 报文不足 12 字节 → `Truncated`。
pub fn patch_id(packet: &mut [u8], id: u16) -> Result<(), DnsWireError> {
    if packet.len() < HEADER_LEN {
        return Err(DnsWireError::Truncated);
    }
    packet[0..2].copy_from_slice(&id.to_be_bytes());
    Ok(())
}

/// 解析上游响应并与请求 question 校验。
///
/// TC=1 时只校验 header/question，直接返回 `truncated=true`（调用方转 TCP）。
///
/// # Errors
///
/// 见 [`DnsWireError`]；name/qtype/class 与 `expected` 不符 →
/// `MismatchedQuestion`。
pub fn parse_response(
    packet: &[u8],
    expected: &DnsQuestion,
) -> Result<UpstreamReply, DnsWireError> {
    let header = parse_header(packet)?;
    if header.flags & FLAG_QR == 0 {
        return Err(DnsWireError::BadHeader);
    }
    if header.flags & FLAG_OPCODE_MASK != 0 {
        return Err(DnsWireError::BadHeader);
    }
    if header.qdcount != 1 {
        return Err(DnsWireError::BadHeader);
    }

    let mut off = HEADER_LEN;
    let name = parse_name(packet, &mut off, true)?;
    if off + 4 > packet.len() {
        return Err(DnsWireError::BadQuestion);
    }
    let qtype = read_u16(packet, off)?;
    let qclass = read_u16(packet, off + 2)?;
    off += 4;
    if name != expected.name.to_ascii_lowercase() || qtype != expected.qtype || qclass != CLASS_IN {
        return Err(DnsWireError::MismatchedQuestion);
    }

    let rcode = DnsRcode::from_code((header.flags & RCODE_MASK) as u8);
    let truncated = header.flags & FLAG_TC != 0;
    if truncated {
        return Ok(UpstreamReply {
            rcode,
            truncated: true,
            records: Vec::new(),
            min_ttl_secs: 0,
            wire: packet.to_vec(),
        });
    }

    let mut records = Vec::with_capacity(usize::from(header.ancount));
    for _ in 0..header.ancount {
        let _owner = parse_name(packet, &mut off, true)?;
        let rtype = read_u16(packet, off)?;
        let _class = read_u16(packet, off + 2)?;
        let ttl = read_u32(packet, off + 4)?;
        let rdlen = usize::from(read_u16(packet, off + 8)?);
        let start = off + 10;
        let end = start + rdlen;
        let rdata = packet.get(start..end).ok_or(DnsWireError::Truncated)?;
        let address = match (rtype, rdlen) {
            (TYPE_A, 4) => Some(IpAddr::V4(Ipv4Addr::new(
                rdata[0], rdata[1], rdata[2], rdata[3],
            ))),
            (TYPE_AAAA, 16) => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(rdata);
                Some(IpAddr::V6(Ipv6Addr::from(octets)))
            }
            _ => None,
        };
        records.push(WireRecord {
            rtype,
            ttl_secs: ttl,
            address,
        });
        off = end;
    }

    let min_ttl_secs = records.iter().map(|r| r.ttl_secs).min().unwrap_or(0);
    Ok(UpstreamReply {
        rcode,
        truncated: false,
        records,
        min_ttl_secs,
        wire: packet.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: u16 = 0x1234;
    const V4: IpAddr = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
    const V6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1));

    fn query(name: &str, qtype: DnsType, edns: Option<u16>) -> Vec<u8> {
        build_query(
            &DnsQuery {
                name: name.to_string(),
                qtype,
            },
            ID,
            edns,
        )
    }

    fn expected(name: &str, qtype: DnsType) -> DnsQuestion {
        parse_question(&query(name, qtype, None)).expect("valid query")
    }

    fn record(rtype: u16, ttl: u32, address: Option<IpAddr>) -> WireRecord {
        WireRecord {
            rtype,
            ttl_secs: ttl,
            address,
        }
    }

    fn header_with(qdcount: u16) -> Vec<u8> {
        let mut packet = vec![0u8; HEADER_LEN];
        packet[0..2].copy_from_slice(&ID.to_be_bytes());
        packet[4..6].copy_from_slice(&qdcount.to_be_bytes());
        packet
    }

    #[test]
    fn build_and_parse_question_roundtrip() {
        let packet = query("Example.COM", DnsType::A, Some(1232));
        let parsed = parse_question(&packet).expect("parse");
        assert_eq!(parsed.id, ID);
        assert_eq!(parsed.name, "example.com");
        assert_eq!(parsed.qtype, TYPE_A);
        assert!(parsed.rd);
        assert_eq!(parsed.edns_udp_size, Some(1232));
        assert_eq!(parsed.as_dns_type(), Some(DnsType::A));
    }

    #[test]
    fn parse_question_without_edns() {
        let parsed = parse_question(&query("a.test", DnsType::Aaaa, None)).expect("parse");
        assert_eq!(parsed.edns_udp_size, None);
        assert_eq!(parsed.as_dns_type(), Some(DnsType::Aaaa));
    }

    #[test]
    fn parse_question_twelve_byte_rule() {
        assert_eq!(parse_question(&[0u8; 11]), Err(DnsWireError::Truncated));
    }

    #[test]
    fn parse_question_qdcount_must_be_one() {
        assert_eq!(
            parse_question(&header_with(0)),
            Err(DnsWireError::BadHeader)
        );
        assert_eq!(
            parse_question(&header_with(2)),
            Err(DnsWireError::BadHeader)
        );
    }

    #[test]
    fn parse_question_rejects_compression_pointer() {
        let mut packet = header_with(1);
        packet.extend_from_slice(&[0xc0, 0x0c]);
        assert_eq!(parse_question(&packet), Err(DnsWireError::BadName));
    }

    #[test]
    fn parse_question_rejects_name_running_past_end() {
        let mut packet = header_with(1);
        packet.extend_from_slice(&[5, b'a', b'b']);
        assert_eq!(parse_question(&packet), Err(DnsWireError::BadName));
    }

    #[test]
    fn parse_question_no_question_section() {
        assert_eq!(
            parse_question(&header_with(1)),
            Err(DnsWireError::NoQuestion)
        );
    }

    #[test]
    fn parse_question_bad_question_when_qtype_truncated() {
        let packet = query("example.com", DnsType::A, None);
        let truncated = &packet[..packet.len() - 4];
        assert_eq!(parse_question(truncated), Err(DnsWireError::BadQuestion));
    }

    #[test]
    fn parse_question_rejects_non_internet_class() {
        let mut packet = query("example.com", DnsType::A, None);
        let class_at = packet.len() - 2;
        packet[class_at..].copy_from_slice(&3u16.to_be_bytes());
        assert_eq!(parse_question(&packet), Err(DnsWireError::BadQuestion));
    }

    #[test]
    fn build_query_rejects_invalid_name_as_empty_packet() {
        assert!(query("", DnsType::A, None).is_empty());
        assert!(query("a..b", DnsType::A, None).is_empty());
    }

    #[test]
    fn build_answer_a_and_parse_response() {
        let request = query("example.com", DnsType::A, None);
        let answer = build_answer(&request, &[record(TYPE_A, 60, Some(V4))], DnsRcode::NoError)
            .expect("build");
        assert_eq!(answer[0..2], ID.to_be_bytes());
        assert_eq!(answer[4..6], 1u16.to_be_bytes());
        assert_eq!(answer[6..8], 1u16.to_be_bytes());

        let parsed = parse_response(&answer, &expected("example.com", DnsType::A)).expect("parse");
        assert_eq!(parsed.rcode, DnsRcode::NoError);
        assert!(!parsed.truncated);
        assert_eq!(parsed.records, vec![record(TYPE_A, 60, Some(V4))]);
        assert_eq!(parsed.min_ttl_secs, 60);
        assert_eq!(parsed.wire, answer);
    }

    #[test]
    fn build_answer_aaaa_and_min_ttl() {
        let request = query("six.example", DnsType::Aaaa, None);
        let answer = build_answer(
            &request,
            &[
                record(TYPE_AAAA, 60, Some(V6)),
                record(TYPE_A, 30, Some(V4)),
            ],
            DnsRcode::NoError,
        )
        .expect("build");
        let parsed =
            parse_response(&answer, &expected("six.example", DnsType::Aaaa)).expect("parse");
        assert_eq!(parsed.records.len(), 2);
        assert_eq!(parsed.records[0].address, Some(V6));
        assert_eq!(parsed.min_ttl_secs, 30);
    }

    #[test]
    fn build_answer_nodata_has_zero_ancount() {
        let request = query("proxy.example.com", DnsType::Aaaa, None);
        let answer = build_answer(&request, &[], DnsRcode::NoError).expect("build");
        assert_eq!(answer[6..8], 0u16.to_be_bytes());
        let parsed =
            parse_response(&answer, &expected("proxy.example.com", DnsType::Aaaa)).expect("parse");
        assert_eq!(parsed.rcode, DnsRcode::NoError);
        assert!(parsed.records.is_empty());
        assert_eq!(parsed.min_ttl_secs, 0);
    }

    #[test]
    fn build_answer_carries_rcode() {
        let request = query("nx.example.com", DnsType::A, None);
        let answer = build_answer(&request, &[], DnsRcode::NxDomain).expect("build");
        let parsed =
            parse_response(&answer, &expected("nx.example.com", DnsType::A)).expect("parse");
        assert_eq!(parsed.rcode, DnsRcode::NxDomain);
    }

    #[test]
    fn build_answer_rejects_family_mismatch() {
        let request = query("example.com", DnsType::A, None);
        let err =
            build_answer(&request, &[record(TYPE_A, 60, Some(V6))], DnsRcode::NoError).unwrap_err();
        assert_eq!(err, DnsWireError::UnsupportedType(TYPE_A));

        let err = build_answer(
            &request,
            &[record(TYPE_AAAA, 60, Some(V4))],
            DnsRcode::NoError,
        )
        .unwrap_err();
        assert_eq!(err, DnsWireError::UnsupportedType(TYPE_AAAA));
    }

    #[test]
    fn build_error_echoes_valid_question() {
        let request = query("example.com", DnsType::A, None);
        let error = build_error(&request, DnsRcode::ServFail).expect("build");
        assert_eq!(error[0..2], ID.to_be_bytes());
        assert_eq!(error[4..6], 1u16.to_be_bytes());
        let parsed = parse_response(&error, &expected("example.com", DnsType::A)).expect("parse");
        assert_eq!(parsed.rcode, DnsRcode::ServFail);
        assert!(parsed.records.is_empty());
    }

    #[test]
    fn build_error_omits_unparseable_question() {
        let mut packet = header_with(1);
        packet.extend_from_slice(&[0xc0, 0x0c]);
        let error = build_error(&packet, DnsRcode::FormErr).expect("build");
        assert_eq!(error[0..2], ID.to_be_bytes());
        assert_eq!(error[4..6], 0u16.to_be_bytes());
        assert_eq!(DnsRcode::from_code(error[3] & 0x0f), DnsRcode::FormErr);
    }

    #[test]
    fn build_error_requires_twelve_bytes() {
        assert_eq!(
            build_error(&[0u8; 11], DnsRcode::FormErr),
            Err(DnsWireError::Truncated)
        );
    }

    #[test]
    fn patch_id_rewrites_transaction_id() {
        let mut packet = query("example.com", DnsType::A, None);
        patch_id(&mut packet, 0xbeef).expect("patch");
        assert_eq!(parse_question(&packet).expect("parse").id, 0xbeef);
        assert_eq!(patch_id(&mut packet[..11], 1), Err(DnsWireError::Truncated));
    }

    #[test]
    fn parse_response_rejects_mismatched_question() {
        let request = query("example.com", DnsType::A, None);
        let answer = build_answer(&request, &[record(TYPE_A, 60, Some(V4))], DnsRcode::NoError)
            .expect("build");
        assert_eq!(
            parse_response(&answer, &expected("other.example", DnsType::A)),
            Err(DnsWireError::MismatchedQuestion)
        );
        assert_eq!(
            parse_response(&answer, &expected("example.com", DnsType::Aaaa)),
            Err(DnsWireError::MismatchedQuestion)
        );
    }

    #[test]
    fn parse_response_reports_truncation() {
        let request = query("example.com", DnsType::A, None);
        let mut answer = build_answer(&request, &[record(TYPE_A, 60, Some(V4))], DnsRcode::NoError)
            .expect("build");
        answer[2] |= 0x02; // TC
        let parsed = parse_response(&answer, &expected("example.com", DnsType::A)).expect("parse");
        assert!(parsed.truncated);
        assert!(parsed.records.is_empty());
    }

    #[test]
    fn parse_response_requires_qr_bit() {
        let request = query("example.com", DnsType::A, None);
        assert_eq!(
            parse_response(&request, &expected("example.com", DnsType::A)),
            Err(DnsWireError::BadHeader)
        );
    }

    #[test]
    fn parse_response_truncated_rdata_is_truncated() {
        let request = query("example.com", DnsType::A, None);
        let answer = build_answer(&request, &[record(TYPE_A, 60, Some(V4))], DnsRcode::NoError)
            .expect("build");
        let cut = &answer[..answer.len() - 2];
        assert_eq!(
            parse_response(cut, &expected("example.com", DnsType::A)),
            Err(DnsWireError::Truncated)
        );
    }

    #[test]
    fn parse_response_keeps_non_address_records() {
        let request = query("example.com", DnsType::A, None);
        let answer =
            build_answer(&request, &[record(65, 120, None)], DnsRcode::NoError).expect("build");
        let parsed = parse_response(&answer, &expected("example.com", DnsType::A)).expect("parse");
        assert_eq!(parsed.records[0].rtype, 65);
        assert_eq!(parsed.records[0].address, None);
        assert_eq!(parsed.min_ttl_secs, 120);
    }

    #[test]
    fn rcode_code_and_from_code_roundtrip() {
        for code in 0u8..=7 {
            assert_eq!(DnsRcode::from_code(code).code(), code);
        }
        assert_eq!(DnsRcode::from_code(9), DnsRcode::Other(9));
        assert_eq!(DnsRcode::NxDomain.code(), 3);
    }
}
