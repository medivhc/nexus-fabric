//! 虚拟子网组网（Virtual Subnet Networking）
//!
//! 参考 EasyTier / WireGuard 组网模式：
//! - 节点在同一虚拟 CIDR 网段内，各有自己的虚拟 IP
//! - 每个 Peer 的物理 locator 静态配置（P0）
//! - 数据面：VPI 读 IP 包 → 封装 → 发给对端；对端收到 → 解封装 → 写回 VPI
//!
//! P0 边界：
//! - 点对点直连（不做网状自动路由）
//! - 静态配置 Peer（不做自动发现）
//! - 明文封装（加密后置）
//! - 内存模拟 VPI/Carrier（真实 TUN 是 E5）

use nexus_platform::{PacketCarrier, PlatformError, VirtualPacketInterface};
use std::collections::HashMap;

use crate::ConnectivityError;

/// 虚拟子网配置。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VirtualSubnetConfig {
    /// 子网 CIDR（如 "10.0.0.0/24"）。
    pub cidr: String,
    /// 本节点的虚拟 IP（如 "10.0.0.1"）。
    pub virtual_ip: String,
}

impl VirtualSubnetConfig {
    /// 创建虚拟子网配置。
    #[must_use]
    pub fn new(cidr: impl Into<String>, virtual_ip: impl Into<String>) -> Self {
        Self {
            cidr: cidr.into(),
            virtual_ip: virtual_ip.into(),
        }
    }

    /// 校验虚拟 IP 是否在子网范围内（P0 简化：字符串前缀匹配）。
    #[must_use]
    pub fn is_valid_virtual_ip(&self, ip: &str) -> bool {
        // P0 简化实现：提取 CIDR 的网络地址部分，检查 IP 是否前缀匹配
        let network_prefix = self
            .cidr
            .split('/')
            .next()
            .unwrap_or("")
            .rsplit_once('.')
            .map(|x| x.0)
            .unwrap_or("");
        ip.starts_with(network_prefix)
    }
}

/// 隧道 Peer 配置。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelPeer {
    /// 对端虚拟 IP。
    pub virtual_ip: String,
    /// 对端物理 locator。
    pub locator: String,
}

impl TunnelPeer {
    /// 创建隧道 Peer。
    #[must_use]
    pub fn new(virtual_ip: impl Into<String>, locator: impl Into<String>) -> Self {
        Self {
            virtual_ip: virtual_ip.into(),
            locator: locator.into(),
        }
    }
}

/// 隧道状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelState {
    /// 未连接。
    Disconnected,
    /// 握手进行中。
    Handshaking,
    /// 已连接。
    Connected,
    /// 连接失败。
    Failed,
}

/// 隧道统计数据。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TunnelStats {
    /// 上行字节数（本节点发给对端）。
    pub bytes_sent: u64,
    /// 下行字节数（本节点从对端接收）。
    pub bytes_received: u64,
    /// 丢包数。
    pub packets_dropped: u64,
}

/// 隧道帧头（P0 简化：纯文本标记）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelFrameHeader {
    /// 源虚拟 IP。
    pub src_virtual_ip: String,
    /// 目的虚拟 IP。
    pub dst_virtual_ip: String,
}

impl TunnelFrameHeader {
    /// 序列化帧头（P0 简化：`src->dst:` 前缀）。
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        format!("{}->{}:", self.src_virtual_ip, self.dst_virtual_ip).into_bytes()
    }

    /// 反序列化帧头（P0 简化：解析 `src->dst:` 前缀）。
    pub fn deserialize(data: &[u8]) -> Option<(Self, &[u8])> {
        let text = std::str::from_utf8(data).ok()?;
        let colon_pos = text.find(':')?;
        let header_part = &text[..colon_pos];
        let mut parts = header_part.split("->");
        let src = parts.next()?;
        let dst = parts.next()?;
        let header = Self {
            src_virtual_ip: src.to_string(),
            dst_virtual_ip: dst.to_string(),
        };
        let payload = &data[colon_pos + 1..];
        Some((header, payload))
    }
}

/// 虚拟子网隧道（数据面编排器）。
///
/// 注入 VPI 和 PacketCarrier，负责：
/// 1. 从 VPI 读 IP 包
/// 2. 根据目的虚拟 IP 查找对应 Peer 的物理 locator
/// 3. 封装隧道帧头
/// 4. 通过 PacketCarrier 发给对端
/// 5. 从 PacketCarrier 读帧
/// 6. 解封装提取原始 IP 包
/// 7. 写入 VPI
pub struct VirtualSubnetTunnel {
    /// 子网配置。
    config: VirtualSubnetConfig,
    /// Peer 表：虚拟 IP → (locator, state, stats)。
    peers: HashMap<String, (String, TunnelState, TunnelStats)>,
    /// VPI 接口。
    vpi: Box<dyn VirtualPacketInterface>,
    /// PacketCarrier。
    carrier: Box<dyn PacketCarrier>,
}

impl VirtualSubnetTunnel {
    /// 创建虚拟子网隧道。
    pub fn new(
        config: VirtualSubnetConfig,
        vpi: Box<dyn VirtualPacketInterface>,
        carrier: Box<dyn PacketCarrier>,
    ) -> Self {
        Self {
            config,
            peers: HashMap::new(),
            vpi,
            carrier,
        }
    }

    /// 注册 Peer。
    pub fn add_peer(&mut self, peer: TunnelPeer) -> Result<(), ConnectivityError> {
        if !self.config.is_valid_virtual_ip(&peer.virtual_ip) {
            return Err(ConnectivityError::Invalid {
                message: format!(
                    "virtual IP {} not in subnet {}",
                    peer.virtual_ip, self.config.cidr
                ),
            });
        }
        self.peers.insert(
            peer.virtual_ip,
            (
                peer.locator,
                TunnelState::Disconnected,
                TunnelStats::default(),
            ),
        );
        Ok(())
    }

    /// 设置 Peer 状态。
    pub fn set_peer_state(&mut self, virtual_ip: &str, state: TunnelState) {
        if let Some(entry) = self.peers.get_mut(virtual_ip) {
            entry.1 = state;
        }
    }

    /// 获取 Peer 状态。
    #[must_use]
    pub fn peer_state(&self, virtual_ip: &str) -> Option<TunnelState> {
        self.peers.get(virtual_ip).map(|(_, state, _)| *state)
    }

    /// 获取 Peer 统计。
    #[must_use]
    pub fn peer_stats(&self, virtual_ip: &str) -> Option<&TunnelStats> {
        self.peers.get(virtual_ip).map(|(_, _, stats)| stats)
    }

    /// 获取所有 Peer 列表。
    #[must_use]
    pub fn peers(&self) -> Vec<(&str, TunnelState)> {
        self.peers
            .iter()
            .map(|(ip, (_, state, _))| (ip.as_str(), *state))
            .collect()
    }

    /// 发送一个 IP 包到对端（封装 + carrier send）。
    pub fn send_ip_packet(
        &mut self,
        dst_virtual_ip: &str,
        packet: &[u8],
    ) -> Result<(), ConnectivityError> {
        let (locator, state, stats) =
            self.peers
                .get_mut(dst_virtual_ip)
                .ok_or_else(|| ConnectivityError::Invalid {
                    message: format!("peer {dst_virtual_ip} not found"),
                })?;

        if *state != TunnelState::Connected {
            return Err(ConnectivityError::Invalid {
                message: format!("peer {dst_virtual_ip} not connected"),
            });
        }

        // 封装隧道帧
        let header = TunnelFrameHeader {
            src_virtual_ip: self.config.virtual_ip.clone(),
            dst_virtual_ip: dst_virtual_ip.to_string(),
        };
        let mut frame = header.serialize();
        frame.extend_from_slice(packet);

        // 通过 carrier 发送
        self.carrier
            .send_to(locator, &frame)
            .map_err(|e| ConnectivityError::Io {
                operation: "send_to".to_string(),
                message: e.to_string(),
            })?;

        stats.bytes_sent += frame.len() as u64;
        Ok(())
    }

    /// 接收一个隧道帧，解封装后写入 VPI。
    pub fn recv_and_deliver(
        &mut self,
        buffer: &mut [u8],
    ) -> Result<Option<(String, usize)>, ConnectivityError> {
        let n = self
            .carrier
            .receive_into(buffer)
            .map_err(|e| ConnectivityError::Io {
                operation: "receive_into".to_string(),
                message: e.to_string(),
            })?;

        if n == 0 {
            return Ok(None);
        }

        let data = &buffer[..n];

        // 解封装
        let (header, payload) =
            TunnelFrameHeader::deserialize(data).ok_or_else(|| ConnectivityError::Invalid {
                message: "invalid tunnel frame header".to_string(),
            })?;

        // 更新发送方统计
        if let Some((_, _, stats)) = self.peers.get_mut(&header.src_virtual_ip) {
            stats.bytes_received += n as u64;
        }

        // 写入 VPI
        self.vpi.send(payload).map_err(|e| ConnectivityError::Io {
            operation: "vpi_send".to_string(),
            message: e.to_string(),
        })?;

        Ok(Some((header.src_virtual_ip, payload.len())))
    }

    /// 从 VPI 读一个 IP 包并路由到对应 Peer。
    pub fn read_vpi_and_route(
        &mut self,
        buffer: &mut [u8],
    ) -> Result<Option<usize>, ConnectivityError> {
        let n = self
            .vpi
            .receive(buffer)
            .map_err(|e| ConnectivityError::Io {
                operation: "vpi_receive".to_string(),
                message: e.to_string(),
            })?;

        if n == 0 {
            return Ok(None);
        }

        // P0 简化：从 IP 包提取目的 IP（第 16-19 字节是目的 IP）
        // 真实实现应该解析 IP 头，P0 简化为取前 24 字节内的目的 IP 字段
        let packet = &buffer[..n];
        let dst_ip = extract_dst_ip_from_ipv4(packet).unwrap_or_default();

        self.send_ip_packet(&dst_ip, packet)?;
        Ok(Some(n))
    }

    /// 获取子网配置。
    #[must_use]
    pub fn config(&self) -> &VirtualSubnetConfig {
        &self.config
    }
}

/// 从 IPv4 包提取目的 IP（P0 简化实现：取第 16-19 字节）。
fn extract_dst_ip_from_ipv4(packet: &[u8]) -> Option<String> {
    if packet.len() < 20 {
        return None;
    }
    // IPv4 头第 16-19 字节是目的 IP
    let dst = &packet[16..20];
    Some(format!("{}.{}.{}.{}", dst[0], dst[1], dst[2], dst[3]))
}

// ---------- 内存模拟实现（离线确定性 E4） ----------

use std::sync::Mutex;

/// 内存模拟 VPI（进程内内存 buffer）。
pub struct MemoryVpi {
    /// 接收缓冲区（对端写入，本节点读取）。
    recv_buf: Mutex<Vec<u8>>,
    /// 发送缓冲区（本节点写入，对端读取）。
    send_buf: Mutex<Vec<u8>>,
}

impl MemoryVpi {
    /// 创建内存 VPI。
    #[must_use]
    pub fn new() -> Self {
        Self {
            recv_buf: Mutex::new(Vec::new()),
            send_buf: Mutex::new(Vec::new()),
        }
    }

    /// 注入一个待接收的包（模拟对端发来）。
    pub fn inject_recv(&self, data: &[u8]) {
        let mut buf = self.recv_buf.lock().unwrap();
        buf.extend_from_slice(data);
    }

    /// 读取已发送的包（模拟本节点发出）。
    #[must_use]
    pub fn take_sent(&self) -> Vec<u8> {
        let mut buf = self.send_buf.lock().unwrap();
        std::mem::take(&mut *buf)
    }
}

impl Default for MemoryVpi {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtualPacketInterface for MemoryVpi {
    fn receive(&mut self, output: &mut [u8]) -> Result<usize, PlatformError> {
        let mut buf = self.recv_buf.lock().unwrap();
        let n = buf.len().min(output.len());
        if n > 0 {
            output[..n].copy_from_slice(&buf[..n]);
            buf.drain(..n);
        }
        Ok(n)
    }

    fn send(&mut self, packet: &[u8]) -> Result<(), PlatformError> {
        let mut buf = self.send_buf.lock().unwrap();
        buf.extend_from_slice(packet);
        Ok(())
    }
}

/// 内存模拟 PacketCarrier（进程内双向通道）。
pub struct MemoryCarrier {
    /// 发送缓冲区（本节点发送，对端接收）。
    send_buf: Mutex<Vec<u8>>,
    /// 接收缓冲区（对端发送，本节点接收）。
    recv_buf: Mutex<Vec<u8>>,
    /// 绑定的 locator。
    local_locator: Mutex<Option<String>>,
}

impl MemoryCarrier {
    /// 创建空的 MemoryCarrier。
    #[must_use]
    pub fn new() -> Self {
        Self {
            send_buf: Mutex::new(Vec::new()),
            recv_buf: Mutex::new(Vec::new()),
            local_locator: Mutex::new(None),
        }
    }

    /// 创建一对互连的 MemoryCarrier（P0 简化：手动连接 send->recv）。
    #[must_use]
    pub fn pair() -> (Self, Self) {
        let a = Self {
            send_buf: Mutex::new(Vec::new()),
            recv_buf: Mutex::new(Vec::new()),
            local_locator: Mutex::new(None),
        };
        let b = Self {
            send_buf: Mutex::new(Vec::new()),
            recv_buf: Mutex::new(Vec::new()),
            local_locator: Mutex::new(None),
        };
        (a, b)
    }

    /// 把另一个 carrier 的接收缓冲区连到本节点的发送缓冲区。
    pub fn connect_to(&self, other: &MemoryCarrier) {
        // 简化：把 self.send_buf 的内容复制到 other.recv_buf
        // 实际应该用 channel，但为了 E4 确定性，我们直接操作
        let send = self.send_buf.lock().unwrap();
        let mut recv = other.recv_buf.lock().unwrap();
        recv.extend_from_slice(&send);
    }

    /// 注入一个待接收的帧。
    pub fn inject_recv(&self, data: &[u8]) {
        let mut buf = self.recv_buf.lock().unwrap();
        buf.extend_from_slice(data);
    }
}

impl PacketCarrier for MemoryCarrier {
    fn bind(&mut self, local_locator: &str) -> Result<String, PlatformError> {
        *self.local_locator.lock().unwrap() = Some(local_locator.to_string());
        Ok(local_locator.to_string())
    }

    fn send_to(&mut self, _peer_locator: &str, frame: &[u8]) -> Result<(), PlatformError> {
        let mut buf = self.send_buf.lock().unwrap();
        buf.extend_from_slice(frame);
        Ok(())
    }

    fn receive_into(&mut self, output: &mut [u8]) -> Result<usize, PlatformError> {
        let mut buf = self.recv_buf.lock().unwrap();
        let n = buf.len().min(output.len());
        if n > 0 {
            output[..n].copy_from_slice(&buf[..n]);
            buf.drain(..n);
        }
        Ok(n)
    }

    fn local_locator(&self) -> Option<String> {
        self.local_locator.lock().unwrap().clone()
    }
}

impl Default for MemoryCarrier {
    fn default() -> Self {
        Self::new()
    }
}

// ---------- 测试 ----------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_header_serialize_deserialize() {
        let header = TunnelFrameHeader {
            src_virtual_ip: "10.0.0.1".to_string(),
            dst_virtual_ip: "10.0.0.2".to_string(),
        };
        let mut frame = header.serialize();
        frame.extend_from_slice(b"hello");

        let (parsed_header, payload) = TunnelFrameHeader::deserialize(&frame).unwrap();
        assert_eq!(parsed_header.src_virtual_ip, "10.0.0.1");
        assert_eq!(parsed_header.dst_virtual_ip, "10.0.0.2");
        assert_eq!(payload, b"hello");
    }

    #[test]
    fn test_subnet_config_validation() {
        let config = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.1");
        assert!(config.is_valid_virtual_ip("10.0.0.2"));
        assert!(config.is_valid_virtual_ip("10.0.0.100"));
        assert!(!config.is_valid_virtual_ip("192.168.1.1"));
    }

    #[test]
    fn test_memory_vpi_roundtrip() {
        let mut vpi = MemoryVpi::new();
        vpi.inject_recv(b"test packet");
        let mut buf = [0u8; 1024];
        let n = vpi.receive(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"test packet");
        vpi.send(b"reply packet").unwrap();
        assert_eq!(&vpi.take_sent(), b"reply packet");
    }

    #[test]
    fn test_virtual_subnet_tunnel_basic() {
        // 节点 A
        let config_a = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.1");
        let vpi_a = Box::new(MemoryVpi::new());
        let carrier_a = Box::new(MemoryCarrier::new());

        let mut tunnel_a = VirtualSubnetTunnel::new(config_a, vpi_a, carrier_a);

        // 节点 B 的 carrier
        let mut carrier_b = MemoryCarrier::new();
        carrier_b.bind("10.0.0.2:10000").unwrap();

        // 注册 Peer B
        tunnel_a
            .add_peer(TunnelPeer::new("10.0.0.2", "10.0.0.2:10000"))
            .unwrap();
        tunnel_a.set_peer_state("10.0.0.2", TunnelState::Connected);

        // 发送一个 IP 包（目的 IP 10.0.0.2）
        let mut ip_packet = vec![0u8; 20];
        ip_packet[16] = 10;
        ip_packet[17] = 0;
        ip_packet[18] = 0;
        ip_packet[19] = 2;
        ip_packet.extend_from_slice(b"hello");

        tunnel_a.send_ip_packet("10.0.0.2", &ip_packet).unwrap();

        // 检查统计
        let stats = tunnel_a.peer_stats("10.0.0.2").unwrap();
        assert!(stats.bytes_sent > 0);
    }

    #[test]
    fn test_send_to_unknown_peer_fails() {
        let config = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.1");
        let vpi = Box::new(MemoryVpi::new());
        let carrier = Box::new(MemoryCarrier::new());
        let mut tunnel = VirtualSubnetTunnel::new(config, vpi, carrier);

        let packet = vec![0u8; 20];
        let result = tunnel.send_ip_packet("10.0.0.99", &packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_send_to_disconnected_peer_fails() {
        let config = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.1");
        let vpi = Box::new(MemoryVpi::new());
        let carrier = Box::new(MemoryCarrier::new());
        let mut tunnel = VirtualSubnetTunnel::new(config, vpi, carrier);

        tunnel
            .add_peer(TunnelPeer::new("10.0.0.2", "peer:10000"))
            .unwrap();
        // 不设置 Connected 状态

        let packet = vec![0u8; 20];
        let result = tunnel.send_ip_packet("10.0.0.2", &packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_add_peer_outside_subnet_fails() {
        let config = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.1");
        let vpi = Box::new(MemoryVpi::new());
        let carrier = Box::new(MemoryCarrier::new());
        let mut tunnel = VirtualSubnetTunnel::new(config, vpi, carrier);

        let result = tunnel.add_peer(TunnelPeer::new("192.168.1.2", "peer:10000"));
        assert!(result.is_err());
    }
}
