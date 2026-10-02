//! 流表：5 元组 key + 流状态机。

use std::collections::HashMap;
use std::time::Instant;

use nexus_domain::SessionId;

use crate::buffer::UdpBuffer;

/// IP 协议（流表 key 的一部分）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpProto {
    Tcp,
    Udp,
}

impl IpProto {
    /// 从 IPv4 协议号解析；其他协议返回 None（本层只处理 TCP/UDP）。
    #[must_use]
    pub fn from_ip_proto_number(n: u8) -> Option<Self> {
        match n {
            6 => Some(Self::Tcp),
            17 => Some(Self::Udp),
            _ => None,
        }
    }
}

/// 流 key = 完整 5 元组（D1：不按 destination 聚合）。
///
/// TUN 只产生上行包，方向固定，精确匹配 O(1) 无歧义。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src_ip: [u8; 4],
    pub src_port: u16,
    pub dst_ip: [u8; 4],
    pub dst_port: u16,
    pub proto: IpProto,
}

impl FlowKey {
    /// 从 IPv4 包字节解析 5 元组；非 TCP/UDP 或包太短返回 None。
    #[must_use]
    pub fn parse_ipv4(packet: &[u8]) -> Option<Self> {
        if packet.len() < 20 || packet[0] >> 4 != 4 {
            return None;
        }
        let ihl = usize::from(packet[0] & 0x0f) * 4;
        if packet.len() < ihl + 4 {
            return None;
        }
        let proto = IpProto::from_ip_proto_number(packet[9])?;
        let src_ip: [u8; 4] = packet[12..16].try_into().ok()?;
        let dst_ip: [u8; 4] = packet[16..20].try_into().ok()?;
        let (src_port, dst_port) = match proto {
            IpProto::Tcp | IpProto::Udp => {
                if packet.len() < ihl + 4 {
                    return None;
                }
                (
                    u16::from_be_bytes([packet[ihl], packet[ihl + 1]]),
                    u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]),
                )
            }
        };
        Some(Self {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            proto,
        })
    }
}

/// 流生命周期（PRODUCT.md#session 双轨中的 LifecyclePhase 投影）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowPhase {
    /// 首包链已跑，建连进行中。
    Allocating,
    /// 建连成功，可快路径转发。
    Active,
    /// 空闲超时/关闭中，不再接受新包。
    Draining,
    /// 已清理，等待从表移除。
    Disposed,
}

/// 流表项。
#[derive(Debug)]
pub struct FlowEntry {
    pub key: FlowKey,
    pub phase: FlowPhase,
    pub session_id: SessionId,
    pub created_at: Instant,
    pub last_seen: Instant,
    /// UDP 建连期的有界缓冲（Allocating 阶段）；TCP 复用 smoltcp buffer，本层不缓冲。
    pub udp_buffer: Option<UdpBuffer>,
    /// 该流触发的首包链次数（E4 `no_planner_in_hot_path` 的证明计数器）。
    pub chain_runs: u64,
}

impl FlowEntry {
    fn new(key: FlowKey, session_id: SessionId, udp: bool) -> Self {
        let now = Instant::now();
        Self {
            key,
            phase: FlowPhase::Allocating,
            session_id,
            created_at: now,
            last_seen: now,
            udp_buffer: udp.then(UdpBuffer::new),
            chain_runs: 1,
        }
    }
}

/// 包处理决策（dataplane 按此执行，不含业务逻辑）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowDecision {
    /// 新流：会话已创建（Allocating），首包链已跑。
    /// TCP：继续本地握手流程；UDP：本包已入缓冲。
    NewSession { session_id: SessionId },
    /// 已建流：按绑定 session 快路径转发。
    Forward { session_id: SessionId },
    /// 流不存在/已终结或首包链拒绝：丢弃。
    Drop { reason: &'static str },
    /// UDP 建连期：本包已入有界缓冲。
    Buffered { session_id: SessionId },
}

/// 5 元组流表。
#[derive(Debug, Default)]
pub struct FlowTable {
    inner: HashMap<FlowKey, FlowEntry>,
}

impl FlowTable {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn get(&self, key: &FlowKey) -> Option<&FlowEntry> {
        self.inner.get(key)
    }

    #[must_use]
    pub fn get_mut(&mut self, key: &FlowKey) -> Option<&mut FlowEntry> {
        self.inner.get_mut(key)
    }

    /// 插入新流（调用方保证 key 不存在）；返回表项可变引用。
    pub fn insert(&mut self, key: FlowKey, session_id: SessionId) -> &mut FlowEntry {
        let udp = key.proto == IpProto::Udp;
        self.inner
            .entry(key)
            .or_insert_with(|| FlowEntry::new(key, session_id, udp))
    }

    pub fn remove(&mut self, key: &FlowKey) -> Option<FlowEntry> {
        self.inner.remove(key)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// 空闲扫描：超过 `idle_timeout` 未见包的 Active/Allocating 流进 Draining。
    /// 返回进入 Draining 的 session id 列表。
    pub fn sweep_idle(&mut self, idle_timeout: std::time::Duration) -> Vec<SessionId> {
        let now = Instant::now();
        let mut drained = Vec::new();
        for entry in self.inner.values_mut() {
            if matches!(entry.phase, FlowPhase::Active | FlowPhase::Allocating)
                && now.duration_since(entry.last_seen) >= idle_timeout
            {
                entry.phase = FlowPhase::Draining;
                drained.push(entry.session_id.clone());
            }
        }
        drained
    }

    /// 移除所有 Disposed 项；返回移除数量。
    pub fn gc_disposed(&mut self) -> usize {
        let before = self.inner.len();
        self.inner
            .retain(|_, e| !matches!(e.phase, FlowPhase::Disposed));
        before - self.inner.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> FlowKey {
        FlowKey {
            src_ip: [192, 168, 1, 2],
            src_port: 54321,
            dst_ip: [93, 184, 216, 34],
            dst_port: 443,
            proto: IpProto::Tcp,
        }
    }

    #[test]
    fn parse_ipv4_tcp_extracts_five_tuple() {
        // 最小 IPv4/TCP 头。
        let mut pkt = vec![0x45u8, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0];
        pkt.extend_from_slice(&[192, 168, 1, 2]); // src
        pkt.extend_from_slice(&[93, 184, 216, 34]); // dst
        pkt.extend_from_slice(&[0xd4, 0x31, 0x01, 0xbb]); // sport 54321, dport 443
        pkt.extend_from_slice(&[0u8; 20]);
        let k = FlowKey::parse_ipv4(&pkt).expect("parse ok");
        assert_eq!(k, key());
    }

    #[test]
    fn parse_ipv4_rejects_non_tcp_udp() {
        let mut pkt = vec![0x45u8, 0, 0, 20, 0, 0, 0, 0, 64, 1, 0, 0]; // proto 1 = ICMP
        pkt.extend_from_slice(&[192, 168, 1, 2, 93, 184, 216, 34]);
        assert!(FlowKey::parse_ipv4(&pkt).is_none());
    }

    #[test]
    fn sweep_idle_moves_stale_to_draining() {
        let mut t = FlowTable::new();
        let k = key();
        t.insert(k, SessionId("s1".into()));
        // 人为把 last_seen 推到过去。
        t.get_mut(&k).unwrap().last_seen = Instant::now() - std::time::Duration::from_secs(3600);
        t.get_mut(&k).unwrap().phase = FlowPhase::Active;
        let drained = t.sweep_idle(std::time::Duration::from_secs(60));
        assert_eq!(drained.len(), 1);
        assert_eq!(t.get(&k).unwrap().phase, FlowPhase::Draining);
    }

    #[test]
    fn gc_disposed_removes_only_disposed() {
        let mut t = FlowTable::new();
        let k1 = key();
        let mut k2 = key();
        k2.dst_port = 80;
        t.insert(k1, SessionId("s1".into()));
        t.insert(k2, SessionId("s2".into()));
        t.get_mut(&k1).unwrap().phase = FlowPhase::Disposed;
        assert_eq!(t.gc_disposed(), 1);
        assert!(t.get(&k1).is_none());
        assert!(t.get(&k2).is_some());
    }
}
