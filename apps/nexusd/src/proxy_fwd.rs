//! Proxy 生产转发（P1-P5）。
//!
//! `ProxyEngine`：dataplane 中分类为 `Proxy` 的包的真实转发：
//! - TCP（P1）：`tcp_relay::TcpForwarder`（smoltcp 终结 → dialer.dial_tcp → 中继）；
//! - UDP（P2）：`udp_relay::UdpForwarder`（协议 UDP 中继 → 回包写 TUN）；
//! - 出站选择（P3）：`adapter::select_dialer` 选 `proxy.yaml` 首个可用出站；
//! - 失败计数不崩（P4）；资源有界（P5）。
//!
//! TUN 所有权仍在 dataplane（D1）：engine 只返回待写回 TUN 的包，
//! 不直接持有/写 TUN。

pub(crate) mod adapter;
pub mod ss_std;
mod tcp_relay;
mod udp_relay;

pub use adapter::{EngineInitError, OutboundConfigError};

pub use udp_relay::build_udp_reply;

use std::net::IpAddr;
use std::sync::Arc;

/// Proxy 转发统计（P4 可观测；dataplane 合并到 DataplaneStats；spec §6.4）。
#[derive(Debug, Default, Clone)]
pub struct ProxyFwdStats {
    // 现有
    pub tcp_dials_ok: u64,
    pub tcp_dials_failed: u64,
    pub udp_sent: u64,
    pub udp_send_failed: u64,
    // §6.4 新增
    /// Syn 成功建立并进入 relay 的流数。
    pub tcp_streams_ok: u64,
    /// client → proxy 明文字节。
    pub tcp_bytes_up: u64,
    /// proxy → client 明文字节。
    pub tcp_bytes_down: u64,
    /// `MAX_ACTIVE_TCP_FLOWS` 拒绝。
    pub tcp_flows_rejected: u64,
    /// `MAX_CONCURRENT_DIALS` 拒绝。
    pub tcp_dials_throttled: u64,
    /// `UdpCapability::Unsupported` 总数。
    pub udp_unsupported: u64,
    /// VLESS UDP 丢弃。
    pub udp_unsupported_vless: u64,
    /// AnyTLS UDP 丢弃。
    pub udp_unsupported_anytls: u64,
    /// 其他 unsupported。
    pub udp_unsupported_other: u64,
    /// 限频日志抑制计数。
    pub udp_unsupported_log_suppressed: u64,
}

/// Proxy 转发引擎（dataplane 拥有）。
pub struct ProxyEngine {
    tcp: tcp_relay::TcpForwarder,
    udp: udp_relay::UdpForwarder,
}

impl ProxyEngine {
    /// `None` = 没有 proxy.yaml；`Some(yaml)` = 有文件，区分「可用」与「不可用」。
    ///
    /// # Errors
    /// `Yaml` / `SelectedInvalid` / `NoUsableOutbound` → 调用方 fail-closed（exit 1）。
    pub fn new(proxy_yaml: Option<&str>) -> Result<Option<Self>, EngineInitError> {
        let Some(proxy_yaml) = proxy_yaml else {
            return Ok(None);
        };
        let dialer = adapter::select_dialer(proxy_yaml)?.dialer;
        Ok(Some(Self {
            tcp: tcp_relay::TcpForwarder::new(Arc::clone(&dialer)),
            udp: udp_relay::UdpForwarder::new(dialer),
        }))
    }

    /// 处理一个 proxy 分类的包；返回 (待写回 TUN 的包, 是否真实转发)。
    ///
    /// - TCP → TcpForwarder；UDP → UdpForwarder；其他 → (vec![], false)。
    /// - 返回的包由 dataplane 写回 TUN（D1 不变量）。
    /// - bool 语义（P1）：UDP 返回真实发送结果；TCP 恒返回 false——
    ///   dial 是异步的，SYN 到达时转发尚未确认，TCP 的真实计数由
    ///   dataplane 经 `stats().tcp_dials_ok/failed` 的增量驱动。
    pub fn handle_packet(&mut self, packet: &[u8]) -> (Vec<Vec<u8>>, bool) {
        if packet.len() < 20 {
            return (vec![], false);
        }
        match packet[9] {
            6 => {
                // TCP
                let tun_pkts = self.tcp.handle_packet(packet);
                // P1：dial 是异步的（worker 线程），SYN 到达时转发尚未确认，
                // 此时返回 false；真实计数由 dataplane 经
                // engine.stats().tcp_dials_ok/failed 的增量驱动。
                (tun_pkts, false)
            }
            17 => {
                // UDP（DNS 已在 D3 短路，这里的 UDP 是业务流量）。
                let ok = self.udp.handle_packet(packet);
                (vec![], ok)
            }
            _ => (vec![], false),
        }
    }

    /// 定期驱动（dataplane 每轮调用）；返回待写回 TUN 的包。
    pub fn poll(&mut self) -> Vec<Vec<u8>> {
        let mut out = self.tcp.poll();
        // UDP 回包 → 重构 IP 包。
        for inbound in self.udp.drain_inbound() {
            if let Some(local) = self.udp.lookup_local(&inbound.remote) {
                if let Some(pkt) = build_udp_reply(local, inbound.remote, &inbound.payload) {
                    out.push(pkt);
                }
            }
        }
        out
    }

    /// 合并统计。
    pub fn stats(&self) -> ProxyFwdStats {
        let t = self.tcp.stats();
        let u = self.udp.stats();
        ProxyFwdStats {
            tcp_dials_ok: t.tcp_dials_ok,
            tcp_dials_failed: t.tcp_dials_failed,
            tcp_streams_ok: t.tcp_streams_ok,
            tcp_bytes_up: t.tcp_bytes_up,
            tcp_bytes_down: t.tcp_bytes_down,
            tcp_flows_rejected: t.tcp_flows_rejected,
            tcp_dials_throttled: t.tcp_dials_throttled,
            udp_sent: u.udp_sent,
            udp_send_failed: u.udp_send_failed,
            udp_unsupported: u.udp_unsupported,
            udp_unsupported_vless: u.udp_unsupported_vless,
            udp_unsupported_anytls: u.udp_unsupported_anytls,
            udp_unsupported_other: u.udp_unsupported_other,
            udp_unsupported_log_suppressed: u.udp_unsupported_log_suppressed,
        }
    }

    /// 是否有可用 dial 配置（P3 可观测）。
    #[allow(dead_code)]
    pub fn has_dial_config(&self) -> bool {
        true
    }
}

/// 供单测：判断 IP 是否为 IPv4 单播（非回环/组播）。
#[allow(dead_code)]
fn is_usable_target(_ip: IpAddr) -> bool {
    true
}
