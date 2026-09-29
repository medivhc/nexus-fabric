//! VirtualSubnet 广域协调核心 + 自动 IP 分配（P2.3+P2.4，PRODUCT §12.10）。
//!
//! Portable Core：零 I/O、零第三方依赖、可编译 WASI。显式 `now_secs` 注入
//! 保证确定性（不用 `Instant`）。
//!
//! 组成：
//! - `Coordinator`：注册 / 心跳 / 对端列表 / locator 解析（复用 PresenceRegistry
//!   的"通告/过期"语义，独立实现）。
//! - `VirtualIpAllocator`：CIDR 内顺序分配 / 幂等重领 / 显式保留冲突 /
//!   释放复用 / 耗尽。
//! - `CoordFrame`：协议帧编解码（u8 tag + u16 长度前缀字符串 + u64 BE，
//!   与 `nexus-discovery::DiscoveryFrame` 同风格）。
//! - `peer_id_from_public_key`：X25519 公钥 → 确定性 FNV-1a 64 哈希标识。

#![forbid(unsafe_code)]

use std::net::Ipv4Addr;

/// 稳定模块标识。
pub const NEXUS_COORD_MODULE: &str = "nexus-connectivity::coord";

/// 协调错误（全部结构化，无 panic 路径）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoordError {
    /// Peer 未注册。
    PeerUnknown(String),
    /// Peer Presence 已过期。
    PeerExpired(String),
    /// 指定虚拟 IP 已被其他 peer 占用。
    AddressInUse(String),
    /// 地址池耗尽。
    NoAddressAvailable,
    /// CIDR 非法。
    InvalidCidr(String),
    /// 帧编码/解码非法。
    InvalidFrame(String),
}

impl std::fmt::Display for CoordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CoordError::PeerUnknown(p) => write!(f, "PEER_UNKNOWN: {p}"),
            CoordError::PeerExpired(p) => write!(f, "PEER_EXPIRED: {p}"),
            CoordError::AddressInUse(ip) => write!(f, "ADDRESS_IN_USE: {ip}"),
            CoordError::NoAddressAvailable => write!(f, "NO_ADDRESS_AVAILABLE"),
            CoordError::InvalidCidr(s) => write!(f, "INVALID_CIDR: {s}"),
            CoordError::InvalidFrame(s) => write!(f, "INVALID_FRAME: {s}"),
        }
    }
}

impl std::error::Error for CoordError {}

/// 一条 Presence 记录（显式时间戳，确定性）。
#[derive(Debug, Clone, PartialEq, Eq)]
struct PresenceEntry {
    peer: String,
    locator: String,
    ttl_secs: u64,
    announced_at_secs: u64,
}

impl PresenceEntry {
    #[must_use]
    fn expired(&self, now_secs: u64) -> bool {
        now_secs.saturating_sub(self.announced_at_secs) >= self.ttl_secs
    }
}

/// 协调器：注册 / 心跳 / 对端列表 / locator 解析（显式 `now_secs` 驱动）。
#[derive(Debug, Clone, Default)]
pub struct Coordinator {
    presences: Vec<PresenceEntry>,
}

impl Coordinator {
    /// 创建空协调器。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 通告（或幂等刷新）peer 的 Presence。
    pub fn announce(
        &mut self,
        now_secs: u64,
        peer: &str,
        locator: &str,
        ttl_secs: u64,
    ) -> Result<(), CoordError> {
        if let Some(p) = self.presences.iter_mut().find(|p| p.peer == peer) {
            p.locator = locator.to_string();
            p.ttl_secs = ttl_secs;
            p.announced_at_secs = now_secs;
        } else {
            self.presences.push(PresenceEntry {
                peer: peer.to_string(),
                locator: locator.to_string(),
                ttl_secs,
                announced_at_secs: now_secs,
            });
        }
        Ok(())
    }

    /// 心跳：刷新 TTL（未知 peer → `PeerUnknown`）。
    pub fn heartbeat(
        &mut self,
        now_secs: u64,
        peer: &str,
        ttl_secs: u64,
    ) -> Result<(), CoordError> {
        let p = self
            .presences
            .iter_mut()
            .find(|p| p.peer == peer)
            .ok_or_else(|| CoordError::PeerUnknown(peer.to_string()))?;
        p.ttl_secs = ttl_secs;
        p.announced_at_secs = now_secs;
        Ok(())
    }

    /// 当前在线（未过期）peer 列表：(peer, locator)，注册顺序稳定。
    /// 返回 (peer, locator) 对（vip 由 `VirtualIpAllocator::peer_vip` 补充）。
    #[must_use]
    pub fn peer_list(&self, now_secs: u64) -> Vec<(String, String)> {
        self.presences
            .iter()
            .filter(|p| !p.expired(now_secs))
            .map(|p| (p.peer.clone(), p.locator.clone()))
            .collect()
    }

    /// 解析 peer 当前 locator；未知 → `PeerUnknown`，过期 → `PeerExpired`。
    pub fn resolve_locator(&self, now_secs: u64, peer: &str) -> Result<String, CoordError> {
        let Some(p) = self.presences.iter().find(|p| p.peer == peer) else {
            return Err(CoordError::PeerUnknown(peer.to_string()));
        };
        if p.expired(now_secs) {
            return Err(CoordError::PeerExpired(peer.to_string()));
        }
        Ok(p.locator.clone())
    }

    /// peer 是否已注册（不校验过期）。
    #[must_use]
    pub fn is_announced(&self, peer: &str) -> bool {
        self.presences.iter().any(|p| p.peer == peer)
    }
}

/// 一条虚拟 IP 租约：peer ↔ 地址。
#[derive(Debug, Clone, PartialEq, Eq)]
struct Lease {
    peer: String,
    virtual_ip: Ipv4Addr,
}

/// CIDR 校验结果：网络地址 + 主机位长度。
struct CidrInfo {
    network: Ipv4Addr,
    prefix_len: u8,
}

/// 解析 IPv4 CIDR（如 "10.99.0.0/24"）。
fn parse_cidr(cidr: &str) -> Result<CidrInfo, CoordError> {
    let (ip_part, prefix_part) = cidr
        .split_once('/')
        .ok_or_else(|| CoordError::InvalidCidr(cidr.to_string()))?;
    let network: Ipv4Addr = ip_part
        .parse()
        .map_err(|_| CoordError::InvalidCidr(cidr.to_string()))?;
    let prefix_len: u8 = prefix_part
        .parse()
        .map_err(|_| CoordError::InvalidCidr(cidr.to_string()))?;
    if !(2..=30).contains(&prefix_len) {
        return Err(CoordError::InvalidCidr(cidr.to_string()));
    }
    // 校验主机位全零（必须指向网络地址）。
    let host_mask = if prefix_len == 0 {
        u32::MAX
    } else {
        (1u32 << (32 - u32::from(prefix_len))) - 1
    };
    if u32::from(network) & host_mask != 0 {
        return Err(CoordError::InvalidCidr(cidr.to_string()));
    }
    Ok(CidrInfo {
        network,
        prefix_len,
    })
}

/// 虚拟 IP 分配器：CIDR 内顺序分配 / 幂等重领 / 显式保留冲突 / 释放复用 / 耗尽。
#[derive(Debug, Clone)]
pub struct VirtualIpAllocator {
    cidr: String,
    network: Ipv4Addr,
    prefix_len: u8,
    leases: Vec<Lease>,
    /// 已释放、可复用的地址（按释放顺序）。
    free_pool: Vec<Ipv4Addr>,
}

impl VirtualIpAllocator {
    /// 创建分配器；CIDR 非法 → `InvalidCidr`。
    pub fn new(cidr: &str) -> Result<Self, CoordError> {
        let info = parse_cidr(cidr)?;
        Ok(Self {
            cidr: cidr.to_string(),
            network: info.network,
            prefix_len: info.prefix_len,
            leases: Vec::new(),
            free_pool: Vec::new(),
        })
    }

    /// CIDR 字符串（用于错误信息与可观测）。
    #[must_use]
    pub fn cidr(&self) -> &str {
        &self.cidr
    }

    /// 顺序分配空闲 IP：`.1` 起跳，跳过网络/广播地址；同 peer 重复领号幂等
    /// 返回原号；耗尽 → `NoAddressAvailable`。
    pub fn allocate(&mut self, _now_secs: u64, peer: &str) -> Result<String, CoordError> {
        if let Some(lease) = self.leases.iter().find(|l| l.peer == peer) {
            return Ok(lease.virtual_ip.to_string());
        }
        // 优先复用已释放地址（FIFO）。
        if let Some(ip) = self.free_pool.first().copied() {
            self.free_pool.remove(0);
            self.leases.push(Lease {
                peer: peer.to_string(),
                virtual_ip: ip,
            });
            return Ok(ip.to_string());
        }
        let host_bits = 32 - u32::from(self.prefix_len);
        for offset in 1..(1u64 << host_bits) - 1 {
            let ip = self.network_ip_at_offset(offset);
            if self.leases.iter().any(|l| l.virtual_ip == ip) {
                continue;
            }
            self.leases.push(Lease {
                peer: peer.to_string(),
                virtual_ip: ip,
            });
            return Ok(ip.to_string());
        }
        Err(CoordError::NoAddressAvailable)
    }

    /// 显式保留指定 IP；被他人占用 → `AddressInUse`；同 peer 幂等。
    pub fn allocate_specific(
        &mut self,
        _now_secs: u64,
        peer: &str,
        virtual_ip: &str,
    ) -> Result<String, CoordError> {
        let ip: Ipv4Addr = virtual_ip
            .parse()
            .map_err(|_| CoordError::InvalidCidr(virtual_ip.to_string()))?;
        if let Some(lease) = self.leases.iter().find(|l| l.peer == peer) {
            if lease.virtual_ip == ip {
                return Ok(ip.to_string());
            }
            return Err(CoordError::AddressInUse(ip.to_string()));
        }
        if self.leases.iter().any(|l| l.virtual_ip == ip) {
            return Err(CoordError::AddressInUse(ip.to_string()));
        }
        self.leases.push(Lease {
            peer: peer.to_string(),
            virtual_ip: ip,
        });
        Ok(ip.to_string())
    }

    /// 释放 peer 的租约（地址回池复用）；未租给该 peer → `PeerUnknown`。
    pub fn release(&mut self, _now_secs: u64, peer: &str) -> Result<(), CoordError> {
        let idx = self
            .leases
            .iter()
            .position(|l| l.peer == peer)
            .ok_or_else(|| CoordError::PeerUnknown(peer.to_string()))?;
        let lease = self.leases.remove(idx);
        self.free_pool.push(lease.virtual_ip);
        Ok(())
    }

    /// 查询 peer 当前虚拟 IP。
    #[must_use]
    pub fn peer_vip(&self, peer: &str) -> Option<String> {
        self.leases
            .iter()
            .find(|l| l.peer == peer)
            .map(|l| l.virtual_ip.to_string())
    }

    /// 当前租约数。
    #[must_use]
    pub fn len(&self) -> usize {
        self.leases.len()
    }

    /// 是否无租约。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.leases.is_empty()
    }

    /// 网络地址 + offset（offset 从 1 起，跳过网络地址本身）。
    fn network_ip_at_offset(&self, offset: u64) -> Ipv4Addr {
        let base = u32::from(self.network);
        Ipv4Addr::from(base.wrapping_add(offset as u32))
    }
}

/// 协调协议帧（编解码见 `encode_frame` / `decode_frame`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoordFrame {
    /// 节点 -> 协调器：通告/刷新 Presence。
    Announce {
        peer: String,
        locator: String,
        ttl_secs: u64,
    },
    /// 节点 -> 协调器：心跳刷新。
    Heartbeat { peer: String, ttl_secs: u64 },
    /// 节点 -> 协调器：请求在线对端列表。
    PeerListReq,
    /// 协调器 -> 节点：在线对端列表（(peer, locator, virtual_ip) 三元组，注册顺序）。
    PeerListResp {
        peers: Vec<(String, String, String)>,
    },
    /// 节点 -> 协调器：领号。
    AllocateReq { peer: String },
    /// 协调器 -> 节点：领号成功。
    AllocateResp { peer: String, virtual_ip: String },
    /// 协调器 -> 节点：领号失败（冲突/耗尽）。
    AllocateNack { peer: String, reason: String },
    /// 节点 -> 协调器：释放。
    ReleaseReq { peer: String },
    /// 协调器 -> 节点：peer 未注册。
    UnknownPeer(String),
    /// 协调器 -> 节点：peer Presence 已过期。
    ExpiredPeer(String),
}

const FRAME_ANNOUNCE: u8 = 1;
const FRAME_HEARTBEAT: u8 = 2;
const FRAME_PEER_LIST_REQ: u8 = 3;
const FRAME_PEER_LIST_RESP: u8 = 4;
const FRAME_ALLOCATE_REQ: u8 = 5;
const FRAME_ALLOCATE_RESP: u8 = 6;
const FRAME_ALLOCATE_NACK: u8 = 7;
const FRAME_RELEASE_REQ: u8 = 8;
const FRAME_UNKNOWN_PEER: u8 = 9;
const FRAME_EXPIRED_PEER: u8 = 10;

/// 写入 u16 BE 长度前缀字符串。
fn put_str(out: &mut Vec<u8>, s: &str) -> Result<(), CoordError> {
    let len =
        u16::try_from(s.len()).map_err(|_| CoordError::InvalidFrame("string too long".into()))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(s.as_bytes());
    Ok(())
}

/// 读取 u16 BE 长度前缀字符串。
fn get_str(buf: &[u8], pos: &mut usize) -> Result<String, CoordError> {
    if *pos + 2 > buf.len() {
        return Err(CoordError::InvalidFrame("frame truncated".into()));
    }
    let len = u16::from_be_bytes([buf[*pos], buf[*pos + 1]]) as usize;
    *pos += 2;
    if *pos + len > buf.len() {
        return Err(CoordError::InvalidFrame("frame truncated".into()));
    }
    let s = std::str::from_utf8(&buf[*pos..*pos + len])
        .map_err(|_| CoordError::InvalidFrame("invalid utf8".into()))?;
    *pos += len;
    Ok(s.to_owned())
}

fn expect_frame_end(buf: &[u8], pos: usize) -> Result<(), CoordError> {
    if pos != buf.len() {
        return Err(CoordError::InvalidFrame("trailing bytes".into()));
    }
    Ok(())
}

fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn get_u64(buf: &[u8], pos: &mut usize) -> Result<u64, CoordError> {
    if *pos + 8 > buf.len() {
        return Err(CoordError::InvalidFrame("frame truncated".into()));
    }
    let v = u64::from_be_bytes(buf[*pos..*pos + 8].try_into().unwrap());
    *pos += 8;
    Ok(v)
}

/// 编码一帧；确定性、可移植、零依赖。
pub fn encode_frame(frame: &CoordFrame) -> Result<Vec<u8>, CoordError> {
    let mut out = Vec::new();
    match frame {
        CoordFrame::Announce {
            peer,
            locator,
            ttl_secs,
        } => {
            out.push(FRAME_ANNOUNCE);
            put_str(&mut out, peer)?;
            put_str(&mut out, locator)?;
            put_u64(&mut out, *ttl_secs);
        }
        CoordFrame::Heartbeat { peer, ttl_secs } => {
            out.push(FRAME_HEARTBEAT);
            put_str(&mut out, peer)?;
            put_u64(&mut out, *ttl_secs);
        }
        CoordFrame::PeerListReq => {
            out.push(FRAME_PEER_LIST_REQ);
        }
        CoordFrame::PeerListResp { peers } => {
            out.push(FRAME_PEER_LIST_RESP);
            let count = u16::try_from(peers.len())
                .map_err(|_| CoordError::InvalidFrame("too many peers".into()))?;
            out.extend_from_slice(&count.to_be_bytes());
            for (peer, locator, virtual_ip) in peers {
                put_str(&mut out, peer)?;
                put_str(&mut out, locator)?;
                put_str(&mut out, virtual_ip)?;
            }
        }
        CoordFrame::AllocateReq { peer } => {
            out.push(FRAME_ALLOCATE_REQ);
            put_str(&mut out, peer)?;
        }
        CoordFrame::AllocateResp { peer, virtual_ip } => {
            out.push(FRAME_ALLOCATE_RESP);
            put_str(&mut out, peer)?;
            put_str(&mut out, virtual_ip)?;
        }
        CoordFrame::AllocateNack { peer, reason } => {
            out.push(FRAME_ALLOCATE_NACK);
            put_str(&mut out, peer)?;
            put_str(&mut out, reason)?;
        }
        CoordFrame::ReleaseReq { peer } => {
            out.push(FRAME_RELEASE_REQ);
            put_str(&mut out, peer)?;
        }
        CoordFrame::UnknownPeer(peer) => {
            out.push(FRAME_UNKNOWN_PEER);
            put_str(&mut out, peer)?;
        }
        CoordFrame::ExpiredPeer(peer) => {
            out.push(FRAME_EXPIRED_PEER);
            put_str(&mut out, peer)?;
        }
    }
    Ok(out)
}

/// 解码一帧；空帧 / 未知 tag / 截断 / 非法编码 → `InvalidFrame`。
pub fn decode_frame(payload: &[u8]) -> Result<CoordFrame, CoordError> {
    let Some(&tag) = payload.first() else {
        return Err(CoordError::InvalidFrame("empty frame".into()));
    };
    let mut pos = 1;
    match tag {
        FRAME_ANNOUNCE => {
            let peer = get_str(payload, &mut pos)?;
            let locator = get_str(payload, &mut pos)?;
            let ttl_secs = get_u64(payload, &mut pos)?;
            expect_frame_end(payload, pos)?;
            Ok(CoordFrame::Announce {
                peer,
                locator,
                ttl_secs,
            })
        }
        FRAME_HEARTBEAT => {
            let peer = get_str(payload, &mut pos)?;
            let ttl_secs = get_u64(payload, &mut pos)?;
            expect_frame_end(payload, pos)?;
            Ok(CoordFrame::Heartbeat { peer, ttl_secs })
        }
        FRAME_PEER_LIST_REQ => {
            expect_frame_end(payload, pos)?;
            Ok(CoordFrame::PeerListReq)
        }
        FRAME_PEER_LIST_RESP => {
            if pos + 2 > payload.len() {
                return Err(CoordError::InvalidFrame("frame truncated".into()));
            }
            let count = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
            pos += 2;
            let mut peers = Vec::with_capacity(count);
            for _ in 0..count {
                let peer = get_str(payload, &mut pos)?;
                let locator = get_str(payload, &mut pos)?;
                let virtual_ip = get_str(payload, &mut pos)?;
                peers.push((peer, locator, virtual_ip));
            }
            expect_frame_end(payload, pos)?;
            Ok(CoordFrame::PeerListResp { peers })
        }
        FRAME_ALLOCATE_REQ => {
            let peer = get_str(payload, &mut pos)?;
            expect_frame_end(payload, pos)?;
            Ok(CoordFrame::AllocateReq { peer })
        }
        FRAME_ALLOCATE_RESP => {
            let peer = get_str(payload, &mut pos)?;
            let virtual_ip = get_str(payload, &mut pos)?;
            expect_frame_end(payload, pos)?;
            Ok(CoordFrame::AllocateResp { peer, virtual_ip })
        }
        FRAME_ALLOCATE_NACK => {
            let peer = get_str(payload, &mut pos)?;
            let reason = get_str(payload, &mut pos)?;
            expect_frame_end(payload, pos)?;
            Ok(CoordFrame::AllocateNack { peer, reason })
        }
        FRAME_RELEASE_REQ => {
            let peer = get_str(payload, &mut pos)?;
            expect_frame_end(payload, pos)?;
            Ok(CoordFrame::ReleaseReq { peer })
        }
        FRAME_UNKNOWN_PEER => {
            let peer = get_str(payload, &mut pos)?;
            expect_frame_end(payload, pos)?;
            Ok(CoordFrame::UnknownPeer(peer))
        }
        FRAME_EXPIRED_PEER => {
            let peer = get_str(payload, &mut pos)?;
            expect_frame_end(payload, pos)?;
            Ok(CoordFrame::ExpiredPeer(peer))
        }
        _ => Err(CoordError::InvalidFrame(format!(
            "unknown frame tag: {tag}"
        ))),
    }
}

/// X25519 公钥 → 确定性 peer 标识（FNV-1a 64，hex 16 字符）。
///
/// 用途：注册标识（Identity != Locator）；安全强度需求（防伪造）留 P3。
#[must_use]
pub fn peer_id_from_public_key(public_key: &[u8; 32]) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &b in public_key {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

/// 从 static 公钥确定性派生 VIP（P5 §12.43 去中心化组网）。
///
/// `h = fnv1a64(static_public ∥ nonce_be64)`，`vip = network + 1 + (h mod usable)`，
/// 其中 `usable = 2^host_bits - 2`（跳过网络地址与广播地址）。
/// 同一公钥 + CIDR + nonce → 同一 VIP；nonce 递增用于冲突重派。
/// IPv4 only（与 `CidrInfo` 一致；IPv6 为冻结边界）。
///
/// # Errors
///
/// CIDR 非法 → `CoordError::InvalidCidr`。
pub fn derive_vip(
    static_public: &[u8; 32],
    cidr: &str,
    nonce: u64,
) -> Result<Ipv4Addr, CoordError> {
    let info = parse_cidr(cidr)?;
    let host_bits = 32 - u32::from(info.prefix_len);
    // prefix_len ∈ 2..=30（parse_cidr 保证），usable ≥ 2。
    let usable = (1u64 << host_bits) - 2;
    let mut hash: u64 = 0xcbf29ce484222325;
    for &b in static_public.iter().chain(nonce.to_be_bytes().iter()) {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    let offset = (hash % usable) as u32 + 1; // 1..=usable，跳过网络地址
    let vip = u32::from(info.network).wrapping_add(offset);
    Ok(Ipv4Addr::from(vip))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allocator() -> VirtualIpAllocator {
        VirtualIpAllocator::new("10.99.0.0/24").unwrap()
    }

    #[test]
    fn allocator_sequential_idempotent_conflict_reuse_exhaust() {
        let mut a = allocator();
        let va = a.allocate(0, "peer-a").unwrap();
        assert_eq!(va, "10.99.0.1");
        let vb = a.allocate(0, "peer-b").unwrap();
        assert_eq!(vb, "10.99.0.2");
        // 幂等重领
        assert_eq!(a.allocate(0, "peer-a").unwrap(), "10.99.0.1");
        assert_eq!(a.len(), 2);
        // 显式保留冲突
        let err = a.allocate_specific(0, "peer-c", "10.99.0.2").unwrap_err();
        assert_eq!(err, CoordError::AddressInUse("10.99.0.2".into()));
        // 释放后复用
        a.release(0, "peer-b").unwrap();
        assert_eq!(a.allocate(0, "peer-c").unwrap(), "10.99.0.2");
        // 耗尽：/30 仅 2 个可用地址（.1、.2），占满后第 3 个 peer 无号
        let mut tiny = VirtualIpAllocator::new("10.0.0.0/30").unwrap();
        assert_eq!(tiny.allocate(0, "x").unwrap(), "10.0.0.1");
        assert_eq!(tiny.allocate(0, "y").unwrap(), "10.0.0.2");
        assert_eq!(
            tiny.allocate(0, "z").unwrap_err(),
            CoordError::NoAddressAvailable
        );
    }

    #[test]
    fn allocator_rejects_invalid_cidr() {
        assert!(VirtualIpAllocator::new("10.99.0.1/24").is_err());
        assert!(VirtualIpAllocator::new("10.99.0.0/1").is_err());
        assert!(VirtualIpAllocator::new("not-a-cidr").is_err());
    }

    #[test]
    fn coordinator_announce_list_expire_unknown() {
        let mut c = Coordinator::new();
        c.announce(0, "peer-a", "udp://1.1.1.1:1", 10).unwrap();
        c.announce(0, "peer-b", "udp://2.2.2.2:2", 100).unwrap();
        let list = c.peer_list(5);
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].0, "peer-a");
        // peer-a 在 t=10 过期（10-0 >= 10）
        assert_eq!(c.resolve_locator(9, "peer-a").unwrap(), "udp://1.1.1.1:1");
        assert_eq!(
            c.resolve_locator(10, "peer-a").unwrap_err(),
            CoordError::PeerExpired("peer-a".into())
        );
        let list = c.peer_list(10);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].0, "peer-b");
        // 未知 peer
        assert_eq!(
            c.resolve_locator(0, "peer-z").unwrap_err(),
            CoordError::PeerUnknown("peer-z".into())
        );
        assert!(c.heartbeat(0, "peer-z", 10).is_err());
        // heartbeat 刷新过期 peer
        c.heartbeat(10, "peer-a", 10).unwrap();
        assert_eq!(c.resolve_locator(15, "peer-a").unwrap(), "udp://1.1.1.1:1");
    }

    #[test]
    fn frame_roundtrip_all_variants() {
        let frames = vec![
            CoordFrame::Announce {
                peer: "peer-a".into(),
                locator: "udp://1.1.1.1:1".into(),
                ttl_secs: 60,
            },
            CoordFrame::Heartbeat {
                peer: "peer-a".into(),
                ttl_secs: 30,
            },
            CoordFrame::PeerListReq,
            CoordFrame::PeerListResp {
                peers: vec![
                    (
                        "peer-a".into(),
                        "udp://1.1.1.1:1".into(),
                        "10.99.0.1".into(),
                    ),
                    (
                        "peer-b".into(),
                        "udp://2.2.2.2:2".into(),
                        "10.99.0.2".into(),
                    ),
                ],
            },
            CoordFrame::AllocateReq {
                peer: "peer-a".into(),
            },
            CoordFrame::AllocateResp {
                peer: "peer-a".into(),
                virtual_ip: "10.99.0.1".into(),
            },
            CoordFrame::AllocateNack {
                peer: "peer-a".into(),
                reason: "ADDRESS_IN_USE".into(),
            },
            CoordFrame::ReleaseReq {
                peer: "peer-a".into(),
            },
            CoordFrame::UnknownPeer("peer-z".into()),
            CoordFrame::ExpiredPeer("peer-z".into()),
        ];
        for f in &frames {
            let enc = encode_frame(f).unwrap();
            assert_eq!(&decode_frame(&enc).unwrap(), f);
        }
        // 非法帧
        assert!(decode_frame(&[]).is_err());
        assert!(decode_frame(&[99]).is_err());
        assert!(decode_frame(&[FRAME_ANNOUNCE, 0, 5]).is_err());
    }

    #[test]
    fn peer_id_hash_is_deterministic_and_distinct() {
        let k1 = [7u8; 32];
        let k2 = [8u8; 32];
        let id1 = peer_id_from_public_key(&k1);
        assert_eq!(id1, peer_id_from_public_key(&k1));
        assert_ne!(id1, peer_id_from_public_key(&k2));
        assert_eq!(id1.len(), 16);
    }
}
