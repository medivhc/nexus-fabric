//! mDNS 发现源（DESIGN §8.2 D3）。
//!
//! 纯状态机 + DNS 子集编解码，**零 I/O、零第三方依赖**（`#![forbid(unsafe_code)]`
//! 由 lib.rs 全局生效）。Socket 装配（bind 5353 + SO_REUSEADDR + 加入组播组）
//! 与 pump 循环是组合根职责，本模块只提供：
//!
//! - [`MdnsDiscovery::encode_query`] / [`MdnsDiscovery::encode_announce`]
//!   （待发送的数据报载荷）；
//! - [`MdnsDiscovery::handle_datagram`]（喂入收到的数据报，返回应答载荷）；
//! - [`Discovery`](super::Discovery) trait 实现（读缓存）。
//!
//! **只做发现，不做认证**：mDNS 记录无认证；解析出的地址只是拨号候选，
//! 身份认证是会话层的事（DESIGN §8.1 ed25519）。
//!
//! 诚实边界（见 MODULE.md D3）：跨子网不工作；实例名冲突解决超出范围；
//! 只实现 Nexus 节点互发现所需的 DNS 子集（PTR/SRV/TXT/A + 查询），
//! 不追求与 Avahi/Bonjour 的完整互操作。

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use super::{Discovery, DiscoveryError, PeerId};

/// Nexus mDNS 服务名（DNS-SD）。
pub const MDNS_SERVICE: &str = "_nexus._udp.local";
/// mDNS 组播端点（RFC 6762）。
pub const MDNS_ADDR: &str = "224.0.0.251:5353";
/// 记录 TTL（秒，RFC 6762 §10 建议值）。
pub const MDNS_TTL_SECS: u32 = 120;

// ---------- DNS 常量（子集） ----------

const TYPE_A: u16 = 1;
const TYPE_PTR: u16 = 12;
const TYPE_TXT: u16 = 16;
const TYPE_SRV: u16 = 33;
const TYPE_ANY: u16 = 255;
const CLASS_IN: u16 = 1;
/// CLASS 高位 = cache-flush（RFC 6762 §10.2）。
const CLASS_FLUSH: u16 = 0x8000;
const FLAG_QR: u16 = 0x8000;
const FLAG_AA: u16 = 0x0400;
/// 解码压缩指针的最大跳转次数（防恶意循环）。
const MAX_NAME_JUMPS: u8 = 8;

// ---------- 编解码原语 ----------

fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn get_u16(buf: &[u8], pos: &mut usize) -> Option<u16> {
    let b: [u8; 2] = buf.get(*pos..*pos + 2)?.try_into().ok()?;
    *pos += 2;
    Some(u16::from_be_bytes(b))
}

fn get_u32(buf: &[u8], pos: &mut usize) -> Option<u32> {
    let b: [u8; 4] = buf.get(*pos..*pos + 4)?.try_into().ok()?;
    *pos += 4;
    Some(u32::from_be_bytes(b))
}

/// 编码域名（label 序列 + 0 终止；不使用压缩指针）。
fn encode_name(out: &mut Vec<u8>, name: &str) {
    for label in name.split('.') {
        let b = label.as_bytes();
        debug_assert!(b.len() < 64, "DNS label too long");
        out.push(b.len() as u8);
        out.extend_from_slice(b);
    }
    out.push(0);
}

/// 解码域名（处理 0xC0 压缩指针，有界跳转；label 限 63 字节）。
fn decode_name(buf: &[u8], pos: &mut usize) -> Option<String> {
    let mut out = String::new();
    let mut p = *pos;
    let mut jumps: u8 = 0;
    // 发生跳转后，从原流消费的字节数固定为指针本身（2 字节）。
    let mut consumed: Option<usize> = None;
    loop {
        let b = *buf.get(p)?;
        if b & 0xC0 == 0xC0 {
            let lo = *buf.get(p + 1)? as usize;
            let target = ((b as usize & 0x3F) << 8) | lo;
            if target >= buf.len() {
                return None;
            }
            if consumed.is_none() {
                consumed = Some(p + 2 - *pos);
            }
            p = target;
            jumps += 1;
            if jumps > MAX_NAME_JUMPS {
                return None;
            }
        } else if b == 0 {
            if consumed.is_none() {
                consumed = Some(p + 1 - *pos);
            }
            break;
        } else {
            let len = b as usize;
            if len > 63 {
                return None;
            }
            let bytes = buf.get(p + 1..p + 1 + len)?;
            let s = std::str::from_utf8(bytes).ok()?;
            if !out.is_empty() {
                out.push('.');
            }
            out.push_str(s);
            p += 1 + len;
        }
    }
    *pos += consumed.unwrap_or(p - *pos);
    Some(out)
}

// ---------- 包模型（子集） ----------

/// 解析出的资源记录（仅 Nexus 需要的四种；其余归为 Other 跳过）。
#[derive(Debug, Clone, PartialEq, Eq)]
enum RData {
    Ptr(String),
    Srv { port: u16, target: String },
    Txt(Vec<(String, String)>),
    A(Ipv4Addr),
    Other,
}

#[derive(Debug, Clone)]
struct Answer {
    name: String,
    ttl: u32,
    rdata: RData,
}

fn decode_rdata(rtype: u16, buf: &[u8]) -> Option<RData> {
    match rtype {
        TYPE_PTR => {
            let mut p = 0;
            decode_name(buf, &mut p).map(RData::Ptr)
        }
        TYPE_SRV => {
            let mut p = 0;
            let _priority = get_u16(buf, &mut p)?;
            let _weight = get_u16(buf, &mut p)?;
            let port = get_u16(buf, &mut p)?;
            let target = decode_name(buf, &mut p)?;
            Some(RData::Srv { port, target })
        }
        TYPE_TXT => {
            let mut kvs = Vec::new();
            let mut p = 0;
            while p < buf.len() {
                let len = *buf.get(p)? as usize;
                p += 1;
                let s = buf.get(p..p + len)?;
                p += len;
                let s = std::str::from_utf8(s).ok()?;
                // "k=v"；无 '=' 的条目保留空值。
                let (k, v) = match s.find('=') {
                    Some(i) => (s[..i].to_string(), s[i + 1..].to_string()),
                    None => (s.to_string(), String::new()),
                };
                kvs.push((k, v));
            }
            Some(RData::Txt(kvs))
        }
        TYPE_A => {
            if buf.len() != 4 {
                return None;
            }
            Some(RData::A(Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3])))
        }
        _ => Some(RData::Other),
    }
}

struct Packet {
    is_response: bool,
    questions: Vec<(String, u16)>,
    answers: Vec<Answer>,
}

fn decode_packet(data: &[u8]) -> Option<Packet> {
    if data.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([data[2], data[3]]);
    let qd = u16::from_be_bytes([data[4], data[5]]) as usize;
    let an = u16::from_be_bytes([data[6], data[7]]) as usize;
    let mut pos = 12;
    // capacity hint only, not truncation（知识条目 lsa-codec-alloc-001）。
    let mut questions = Vec::with_capacity(qd.min(16));
    for _ in 0..qd {
        let name = decode_name(data, &mut pos)?;
        let qtype = get_u16(data, &mut pos)?;
        let _qclass = get_u16(data, &mut pos)?;
        questions.push((name, qtype));
    }
    let mut answers = Vec::with_capacity(an.min(32));
    for _ in 0..an {
        let name = decode_name(data, &mut pos)?;
        let rtype = get_u16(data, &mut pos)?;
        let _class = get_u16(data, &mut pos)?;
        let ttl = get_u32(data, &mut pos)?;
        let rdlen = get_u16(data, &mut pos)? as usize;
        let end = pos.checked_add(rdlen)?;
        let rdata = decode_rdata(rtype, data.get(pos..end)?)?;
        pos = end;
        answers.push(Answer { name, ttl, rdata });
    }
    Some(Packet {
        is_response: flags & FLAG_QR != 0,
        questions,
        answers,
    })
}

// ---------- MdnsDiscovery ----------

/// 缓存的发现结果。
#[derive(Debug, Clone)]
struct CachedAddr {
    addr: SocketAddr,
    expires: Instant,
}

/// mDNS 发现源：纯状态机，零 I/O。
///
/// 时间由调用方注入（`now: Instant`），便于确定性测试；
/// `resolve` 返回缓存快照，过期条目依赖 [`Self::prune_expired`] /
/// [`Self::handle_datagram`] 清理（组合根义务）。
#[derive(Debug)]
pub struct MdnsDiscovery {
    peer_id: PeerId,
    instance: String,
    service_port: u16,
    announce_ip: Ipv4Addr,
    cache: HashMap<PeerId, CachedAddr>,
}

/// PeerId → DNS 安全的实例名片段（`[a-z0-9_-]`，其余转 `-`，限 32 字符）。
fn sanitize_instance(peer_id: &str) -> Option<String> {
    let mut s: String = peer_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else if c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();
    // 截断到 32 字符（按字符，非字节；已是 ASCII 安全）。
    if s.len() > 32 {
        s.truncate(32);
    }
    let s = s.trim_matches('-').to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

impl MdnsDiscovery {
    /// 创建 mDNS 发现源。
    ///
    /// - `service_port`：本节点 Nexus 服务端口（SRV 记录宣告）；
    /// - `announce_ip`：A 记录宣告的 IPv4 地址（由组合根注入；仅支持 IPv4，
    ///   传入 IPv6 返回 `Err`）。
    pub fn new(
        peer_id: PeerId,
        service_port: u16,
        announce_ip: IpAddr,
    ) -> Result<Self, DiscoveryError> {
        let announce_ip = match announce_ip {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(_) => {
                return Err(DiscoveryError::Transport(
                    "mdns: announce_ip must be IPv4 (AAAA not in D3 scope)".into(),
                ));
            }
        };
        let san = sanitize_instance(&peer_id.0).ok_or_else(|| {
            DiscoveryError::Transport("mdns: peer id has no DNS-safe characters".into())
        })?;
        Ok(Self {
            peer_id,
            instance: format!("nx-{san}.{MDNS_SERVICE}"),
            service_port,
            announce_ip,
            cache: HashMap::new(),
        })
    }

    /// 本节点实例名（测试/诊断用）。
    #[must_use]
    pub fn instance_name(&self) -> &str {
        &self.instance
    }

    /// 编码 PTR 查询（`_nexus._udp.local`）。
    #[must_use]
    pub fn encode_query(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        put_u16(&mut out, 0); // id = 0（mDNS）
        put_u16(&mut out, 0); // flags: query
        put_u16(&mut out, 1); // QDCOUNT
        put_u16(&mut out, 0); // ANCOUNT
        put_u16(&mut out, 0); // NSCOUNT
        put_u16(&mut out, 0); // ARCOUNT
        encode_name(&mut out, MDNS_SERVICE);
        put_u16(&mut out, TYPE_PTR);
        put_u16(&mut out, CLASS_IN);
        out
    }

    /// 编码本节点宣告（unsolicited 响应：PTR + SRV + TXT + A）。
    #[must_use]
    pub fn encode_announce(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        put_u16(&mut out, 0);
        put_u16(&mut out, FLAG_QR | FLAG_AA);
        put_u16(&mut out, 0); // QDCOUNT
        put_u16(&mut out, 4); // ANCOUNT
        put_u16(&mut out, 0);
        put_u16(&mut out, 0);
        let class = CLASS_IN | CLASS_FLUSH;

        // PTR: service -> instance
        encode_name(&mut out, MDNS_SERVICE);
        put_u16(&mut out, TYPE_PTR);
        put_u16(&mut out, class);
        put_u32(&mut out, MDNS_TTL_SECS);
        let mut rd = Vec::new();
        encode_name(&mut rd, &self.instance);
        put_u16(&mut out, rd.len() as u16);
        out.extend_from_slice(&rd);

        // SRV: instance -> port + target
        encode_name(&mut out, &self.instance);
        put_u16(&mut out, TYPE_SRV);
        put_u16(&mut out, class);
        put_u32(&mut out, MDNS_TTL_SECS);
        let mut rd = Vec::new();
        put_u16(&mut rd, 0); // priority
        put_u16(&mut rd, 0); // weight
        put_u16(&mut rd, self.service_port);
        encode_name(&mut rd, &self.instance);
        put_u16(&mut out, rd.len() as u16);
        out.extend_from_slice(&rd);

        // TXT: peer=<PeerId>
        encode_name(&mut out, &self.instance);
        put_u16(&mut out, TYPE_TXT);
        put_u16(&mut out, class);
        put_u32(&mut out, MDNS_TTL_SECS);
        let txt = format!("peer={}", self.peer_id.0);
        let tb = txt.as_bytes();
        let mut rd = Vec::with_capacity(tb.len() + 1);
        rd.push(tb.len() as u8);
        rd.extend_from_slice(tb);
        put_u16(&mut out, rd.len() as u16);
        out.extend_from_slice(&rd);

        // A: instance -> ipv4
        encode_name(&mut out, &self.instance);
        put_u16(&mut out, TYPE_A);
        put_u16(&mut out, class);
        put_u32(&mut out, MDNS_TTL_SECS);
        put_u16(&mut out, 4);
        out.extend_from_slice(&self.announce_ip.octets());

        out
    }

    /// 喂入收到的数据报，返回应答数据报载荷（为空表示无需应答）。
    ///
    /// 畸形包静默忽略（返回空）；`peer == self` 的自回环学习跳过。
    /// 每次调用附带一次过期清理。
    pub fn handle_datagram(&mut self, data: &[u8], now: Instant) -> Vec<Vec<u8>> {
        self.prune_expired(now);
        let pkt = match decode_packet(data) {
            Some(p) => p,
            None => return Vec::new(),
        };
        if !pkt.is_response {
            for (qname, qtype) in &pkt.questions {
                if qname.eq_ignore_ascii_case(MDNS_SERVICE)
                    && (*qtype == TYPE_PTR || *qtype == TYPE_ANY)
                {
                    return vec![self.encode_announce()];
                }
            }
            return Vec::new();
        }
        // 响应包：按实例聚合 SRV/TXT/A。
        let mut ports: HashMap<&str, (u16, u32)> = HashMap::new();
        let mut peers: HashMap<&str, (&str, u32)> = HashMap::new();
        let mut ips: HashMap<&str, (Ipv4Addr, u32)> = HashMap::new();
        for ans in &pkt.answers {
            match &ans.rdata {
                RData::Srv { port, .. } => {
                    ports.insert(ans.name.as_str(), (*port, ans.ttl));
                }
                RData::Txt(kvs) => {
                    for (k, v) in kvs {
                        if k == "peer" {
                            peers.insert(ans.name.as_str(), (v.as_str(), ans.ttl));
                        }
                    }
                }
                RData::A(ip) => {
                    ips.insert(ans.name.as_str(), (*ip, ans.ttl));
                }
                _ => {}
            }
        }
        for (instance, (peer_id, ttl_txt)) in &peers {
            if *peer_id == self.peer_id.0 {
                continue; // 自回环：忽略自己的组播。
            }
            if let (Some((port, ttl_srv)), Some((ip, ttl_a))) =
                (ports.get(instance), ips.get(instance))
            {
                let ttl = (*ttl_txt).min(*ttl_srv).min(*ttl_a).min(MDNS_TTL_SECS);
                self.cache.insert(
                    PeerId(peer_id.to_string()),
                    CachedAddr {
                        addr: SocketAddr::new(IpAddr::V4(*ip), *port),
                        expires: now + Duration::from_secs(ttl.max(1) as u64),
                    },
                );
            }
        }
        Vec::new()
    }

    /// 清理过期缓存条目（组合根周期性调用；`handle_datagram` 已附带调用）。
    pub fn prune_expired(&mut self, now: Instant) {
        self.cache.retain(|_, c| c.expires > now);
    }

    /// 当前缓存的 peer 数量（可观测/测试用）。
    #[must_use]
    pub fn cached_peer_count(&self) -> usize {
        self.cache.len()
    }
}

impl Discovery for MdnsDiscovery {
    /// 返回缓存快照；过期条目依赖 `prune_expired` 清理（组合根义务）。
    fn resolve(&self, peer: &PeerId) -> Vec<SocketAddr> {
        self.cache
            .get(peer)
            .map(|c| vec![c.addr])
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(id: &str) -> PeerId {
        PeerId(id.to_string())
    }

    fn mk(ip: &str, port: u16, id: &str) -> MdnsDiscovery {
        MdnsDiscovery::new(peer(id), port, ip.parse().unwrap()).unwrap()
    }

    #[test]
    fn query_announce_roundtrip() {
        let a = mk("127.0.0.1", 5001, "peer-a");
        let mut b = mk("127.0.0.1", 5002, "peer-b");
        let now = Instant::now();
        // B 收到 A 的查询 → 回应宣告。
        let resp = b.handle_datagram(&a.encode_query(), now);
        assert_eq!(resp.len(), 1);
        // A 从 B 的宣告中学习到 peer-b（响应包不产生新的应答）。
        let mut a2 = mk("127.0.0.1", 5001, "peer-a");
        let no_resp = a2.handle_datagram(&resp[0], now);
        assert!(no_resp.is_empty());
        let addrs = Discovery::resolve(&a2, &peer("peer-b"));
        assert_eq!(addrs, vec!["127.0.0.1:5002".parse().unwrap()]);
    }

    #[test]
    fn self_announce_ignored() {
        let mut a = mk("127.0.0.1", 5001, "peer-a");
        let now = Instant::now();
        let ann = a.encode_announce();
        a.handle_datagram(&ann, now);
        assert_eq!(a.cached_peer_count(), 0);
        assert!(Discovery::resolve(&a, &peer("peer-a")).is_empty());
    }

    #[test]
    fn malformed_datagram_ignored() {
        let mut a = mk("127.0.0.1", 5001, "peer-a");
        let now = Instant::now();
        assert!(a.handle_datagram(&[], now).is_empty());
        assert!(a.handle_datagram(&[0u8; 11], now).is_empty());
        assert!(a.handle_datagram(&[0xff; 64], now).is_empty());
        assert_eq!(a.cached_peer_count(), 0);
    }

    #[test]
    fn cache_expires_with_ttl() {
        let mut a = mk("127.0.0.1", 5001, "peer-a");
        let b = mk("127.0.0.1", 5002, "peer-b");
        let now = Instant::now();
        a.handle_datagram(&b.encode_announce(), now);
        assert_eq!(a.cached_peer_count(), 1);
        a.prune_expired(now + Duration::from_secs(MDNS_TTL_SECS as u64 + 1));
        assert_eq!(a.cached_peer_count(), 0);
        assert!(Discovery::resolve(&a, &peer("peer-b")).is_empty());
    }

    #[test]
    fn constructor_rejects_bad_input() {
        // IPv6 不在 D3 范围。
        assert!(MdnsDiscovery::new(peer("x"), 1, "::1".parse().unwrap()).is_err());
        // 全空实例名。
        assert!(MdnsDiscovery::new(peer("---"), 1, "127.0.0.1".parse().unwrap()).is_err());
    }

    #[test]
    fn instance_name_sanitized() {
        let m = mk("127.0.0.1", 5001, "Peer.A/01");
        assert!(m.instance_name().starts_with("nx-peer-a-01."));
        assert!(m.instance_name().ends_with(MDNS_SERVICE));
    }

    #[test]
    fn decode_name_handles_compression() {
        // 手工构造带压缩指针的包：问题名后接指向它的指针。
        let mut pkt = Vec::new();
        put_u16(&mut pkt, 0);
        put_u16(&mut pkt, FLAG_QR | FLAG_AA);
        put_u16(&mut pkt, 0);
        put_u16(&mut pkt, 1);
        put_u16(&mut pkt, 0);
        put_u16(&mut pkt, 0);
        let name_off = pkt.len();
        encode_name(&mut pkt, "nx-x._nexus._udp.local");
        put_u16(&mut pkt, TYPE_A);
        put_u16(&mut pkt, CLASS_IN);
        put_u32(&mut pkt, MDNS_TTL_SECS);
        put_u16(&mut pkt, 2 + 4); // RDLEN: 指针(2) + 4 字节
        pkt.push(0xC0 | ((name_off >> 8) as u8));
        pkt.push((name_off & 0xFF) as u8);
        pkt.extend_from_slice(&[1, 2, 3, 4]);
        let p = decode_packet(&pkt).expect("decode with compression");
        assert!(p.is_response);
        assert_eq!(p.answers.len(), 1);
        assert_eq!(p.answers[0].name, "nx-x._nexus._udp.local");
        assert!(matches!(p.answers[0].rdata, RData::A(_)));
    }

    #[test]
    fn query_for_other_service_gets_no_response() {
        let mut b = mk("127.0.0.1", 5002, "peer-b");
        let now = Instant::now();
        // 构造一个问别的服务的查询。
        let mut q = Vec::new();
        put_u16(&mut q, 0);
        put_u16(&mut q, 0);
        put_u16(&mut q, 1);
        put_u16(&mut q, 0);
        put_u16(&mut q, 0);
        put_u16(&mut q, 0);
        encode_name(&mut q, "_other._tcp.local");
        put_u16(&mut q, TYPE_PTR);
        put_u16(&mut q, CLASS_IN);
        assert!(b.handle_datagram(&q, now).is_empty());
    }
}
