//! 通用 UDP 承载（`PacketCarrier` 的真实网络实现）。
//!
//! 语义（PRODUCT §12.17）：locator 格式 `udp://<host>:<port>`；`bind` 解析并
//! 绑定本地 UDP socket（非阻塞）；`send_to` 按对端 locator 发送一帧封装数据；
//! `receive_into` 收一帧，无数据返回 `Ok(0)`。纯逻辑（locator 解析、错误映射）
//! 与 socket 操作分离，可离线单测。

use std::net::UdpSocket;

use crate::{PacketCarrier, PlatformError};

/// UDP 承载（`udp://<host>:<port>` 语义）。
///
/// 非阻塞模式：`receive_into` 在无数据时返回 `Ok(0)`（对应契约
/// "无可用数据时返回 Ok(0)"）。
pub struct UdpCarrier {
    socket: Option<UdpSocket>,
    local_locator: Option<String>,
    /// 最近一次成功收帧的来源（`udp://<ip>:<port>`，NAT 会话回程用）。
    last_peer: Option<String>,
}

impl UdpCarrier {
    /// 创建未绑定的 UDP 承载（调用 `bind` 后可用）。
    #[must_use]
    pub fn new() -> Self {
        Self {
            socket: None,
            local_locator: None,
            last_peer: None,
        }
    }

    /// 解析 `udp://<host>:<port>` 为 `(host, port)`（纯函数，可单测）。
    ///
    /// 校验：前缀必须为 `udp://`、host 非空、port 在 `1..=65535`。
    pub fn parse_locator(locator: &str) -> Result<(String, u16), PlatformError> {
        let rest = locator
            .strip_prefix("udp://")
            .ok_or_else(|| PlatformError::Invalid {
                message: format!("locator not udp://: {locator}"),
            })?;
        let (host, port_str) = rest
            .rsplit_once(':')
            .ok_or_else(|| PlatformError::Invalid {
                message: format!("locator missing port: {locator}"),
            })?;
        if host.is_empty() {
            return Err(PlatformError::Invalid {
                message: format!("locator empty host: {locator}"),
            });
        }
        let port: u16 = port_str.parse().map_err(|_| PlatformError::Invalid {
            message: format!("locator invalid port: {locator}"),
        })?;
        if port == 0 {
            return Err(PlatformError::Invalid {
                message: format!("locator zero port: {locator}"),
            });
        }
        Ok((host.to_string(), port))
    }
}

impl Default for UdpCarrier {
    fn default() -> Self {
        Self::new()
    }
}

impl PacketCarrier for UdpCarrier {
    fn bind(&mut self, local_locator: &str) -> Result<String, PlatformError> {
        let (host, port) = Self::parse_locator(local_locator)?;
        let socket = UdpSocket::bind((host.as_str(), port)).map_err(|e| PlatformError::Io {
            operation: "udp bind".into(),
            message: e.to_string(),
        })?;
        socket
            .set_nonblocking(true)
            .map_err(|e| PlatformError::Io {
                operation: "udp set_nonblocking".into(),
                message: e.to_string(),
            })?;
        self.socket = Some(socket);
        self.local_locator = Some(local_locator.to_string());
        Ok(local_locator.to_string())
    }

    fn send_to(&mut self, peer_locator: &str, frame: &[u8]) -> Result<(), PlatformError> {
        let socket = self.socket.as_ref().ok_or_else(|| PlatformError::Invalid {
            message: "carrier not bound".into(),
        })?;
        let (host, port) = Self::parse_locator(peer_locator)?;
        socket
            .send_to(frame, (host.as_str(), port))
            .map_err(|e| PlatformError::Io {
                operation: "udp send_to".into(),
                message: e.to_string(),
            })?;
        Ok(())
    }

    fn receive_into(&mut self, output: &mut [u8]) -> Result<usize, PlatformError> {
        let socket = self.socket.as_ref().ok_or_else(|| PlatformError::Invalid {
            message: "carrier not bound".into(),
        })?;
        match socket.recv_from(output) {
            Ok((n, src)) => {
                self.last_peer = Some(format!("udp://{}:{}", src.ip(), src.port()));
                Ok(n)
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(0),
            Err(e) => Err(PlatformError::Io {
                operation: "udp recv_from".into(),
                message: e.to_string(),
            }),
        }
    }

    fn local_locator(&self) -> Option<String> {
        self.local_locator.clone()
    }

    fn last_peer_locator(&self) -> Option<String> {
        self.last_peer.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_locator_valid_and_invalid() {
        assert_eq!(
            UdpCarrier::parse_locator("udp://127.0.0.1:52001").unwrap(),
            ("127.0.0.1".to_string(), 52001)
        );
        assert!(UdpCarrier::parse_locator("tcp://127.0.0.1:1").is_err());
        assert!(UdpCarrier::parse_locator("udp://127.0.0.1").is_err());
        assert!(UdpCarrier::parse_locator("udp://:52001").is_err());
        assert!(UdpCarrier::parse_locator("udp://127.0.0.1:0").is_err());
        assert!(UdpCarrier::parse_locator("udp://127.0.0.1:65536").is_err());
    }

    #[test]
    fn last_peer_tracks_received_source() {
        // 双 socket 回环：A 发帧到 B，B 记录来源 locator。
        let mut a = UdpCarrier::new();
        a.bind("udp://127.0.0.1:55001").unwrap();
        let mut b = UdpCarrier::new();
        b.bind("udp://127.0.0.1:55002").unwrap();
        let a_loc = a.local_locator().unwrap();
        b.send_to(&a_loc, b"ping").unwrap();
        let mut buf = [0u8; 64];
        assert_eq!(a.receive_into(&mut buf).unwrap(), 4);
        let src = a.last_peer_locator().expect("source recorded");
        assert!(src.starts_with("udp://127.0.0.1:"));
        assert_ne!(src, a_loc);
        // 未收帧的 carrier：None（默认语义）。
        let c = UdpCarrier::new();
        assert_eq!(c.last_peer_locator(), None);
    }

    #[test]
    fn send_before_bind_rejected() {
        let mut c = UdpCarrier::new();
        assert!(matches!(
            c.send_to("udp://127.0.0.1:52001", &[1, 2, 3]),
            Err(PlatformError::Invalid { .. })
        ));
        assert!(matches!(
            c.receive_into(&mut [0u8; 64]),
            Err(PlatformError::Invalid { .. })
        ));
    }
}
