//! 中继通道（Relay Channel）：NAT 打洞失败时的回退数据面骨架。
//!
//! 本模块提供 **可移植、离线确定性** 的中继通道状态机：
//! - `RelayConfig`：中继服务器地址 + 对端 peer 标识（领域中立 DTO）；
//! - `RelayState`：`Disconnected -> Connecting -> Connected / Failed` 状态机；
//! - `RelayTransport` trait：真实中继建连/收发的接缝（由 Composition Root 以平台 I/O 实现，
//!   本层只做状态机编排与统计，零真实网络）；
//! - `RelayChannel`：持有配置、状态、统计与事件序列，驱动 `RelayTransport`；
//! - `MockRelayTransport`：离线回环替身，供单测与 E4 产品场景确定性驱动。
//!
//! 不变量：
//! - 未进入 `Connected` 不允许 `forward` / `receive`（门控，避免未建连即发流量）；
//! - `connect` 严格走状态机（`Disconnected -> Connecting -> Connected/Failed`）；
//! - 真实中继建连（DERP 类协议、加密、平台 socket）由 Composition Root / platform 完成，
//!   此处仅为可移植骨架，平台特定逻辑留 TODO。
//!
//! 详细契约见 `MODULE.md` 的「冻结契约（RelayChannel 中继通道 P0）」。

use crate::ConnectivityError;

// ---------- 配置 ----------

/// 中继通道配置（领域中立：中继服务器 locator + 对端 peer 标识）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayConfig {
    /// 中继服务器 locator（如 `relay.example.org:9999`）。
    pub relay_server: String,
    /// 目标对端 peer 标识（中继转发的目标 peer_id）。
    pub peer_id: String,
}

impl RelayConfig {
    /// 构造中继配置。
    #[must_use]
    pub fn new(relay_server: impl Into<String>, peer_id: impl Into<String>) -> Self {
        Self {
            relay_server: relay_server.into(),
            peer_id: peer_id.into(),
        }
    }

    /// 校验配置：`relay_server` 或 `peer_id` 为空则返回 `ConnectivityError::Invalid`。
    pub fn validate(&self) -> Result<(), ConnectivityError> {
        if self.relay_server.is_empty() {
            return Err(ConnectivityError::Invalid {
                message: "relay_server must not be empty".to_string(),
            });
        }
        if self.peer_id.is_empty() {
            return Err(ConnectivityError::Invalid {
                message: "peer_id must not be empty".to_string(),
            });
        }
        Ok(())
    }
}

// ---------- 状态机与统计 ----------

/// 中继通道状态（每通道一份，由 Owner / 编排层持有）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayState {
    /// 尚未建连 / 已关闭。
    Disconnected,
    /// 建连进行中。
    Connecting,
    /// 已连接（可收发）。
    Connected,
    /// 建连失败（结构化原因在事件 / 错误中保留）。
    Failed,
}

impl core::fmt::Display for RelayState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Disconnected => f.write_str("disconnected"),
            Self::Connecting => f.write_str("connecting"),
            Self::Connected => f.write_str("connected"),
            Self::Failed => f.write_str("failed"),
        }
    }
}

/// 中继通道流量统计（单调计数，重置由 Owner 重建通道完成）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RelayStats {
    /// 已发送字节数。
    pub bytes_sent: u64,
    /// 已接收字节数。
    pub bytes_received: u64,
    /// 已转发请求次数（每次 `forward` 计一次）。
    pub forward_requests: u64,
}

// ---------- 结构化事件 ----------

/// 中继通道结构化事件（Worker 只发事件，不直接改 Owner Outcome）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayEvent {
    /// 开始经中继建连。
    Connecting {
        /// 中继服务器 locator。
        relay_server: String,
        /// 对端 peer 标识。
        peer_id: String,
    },
    /// 中继建连成功。
    Connected {
        /// 中继服务器 locator。
        relay_server: String,
        /// 对端 peer 标识。
        peer_id: String,
    },
    /// 中继建连失败。
    ConnectFailed {
        /// 中继服务器 locator。
        relay_server: String,
        /// 对端 peer 标识。
        peer_id: String,
        /// 失败原因。
        reason: String,
    },
    /// 已向中继转发一段数据。
    DataForwarded {
        /// 对端 peer 标识。
        peer_id: String,
        /// 转发字节数。
        bytes: u64,
    },
    /// 已从中继收到一段数据。
    DataReceived {
        /// 对端 peer 标识。
        peer_id: String,
        /// 接收字节数。
        bytes: u64,
    },
    /// 通道已关闭。
    Closed {
        /// 对端 peer 标识。
        peer_id: String,
    },
}

// ---------- 传输接缝 ----------

/// 中继传输接缝：真实中继建连 / 转发 / 接收的平台实现由 Composition Root 注入。
///
/// 本 trait 是领域中立接缝（Deletion Test：真实 DERP 协议实现与离线 Mock 构成独立变化维度）；
/// `RelayChannel` 只做状态机门控与统计，不发起真实网络 I/O。
pub trait RelayTransport {
    /// 发起中继建连；`Ok(())` 成功，`Err(reason)` 保留失败原因。
    fn connect(&mut self, config: &RelayConfig) -> Result<(), String>;
    /// 向指定 `peer_id` 转发一段数据。
    fn forward(&mut self, peer_id: &str, data: &[u8]) -> Result<(), String>;
    /// 从中继接收至多 `output.len()` 字节到 `output`，返回实际接收字节数（无数据返回 `Ok(0)`）。
    fn receive(&mut self, peer_id: &str, output: &mut [u8]) -> Result<usize, String>;
}

// ---------- 通道 ----------

/// 中继通道：驱动 `RelayTransport`，维护状态机、统计与事件序列。
pub struct RelayChannel {
    config: RelayConfig,
    state: RelayState,
    stats: RelayStats,
    events: Vec<RelayEvent>,
    transport: Box<dyn RelayTransport>,
}

impl RelayChannel {
    /// 构造通道：初始 `Disconnected`，事件序列为空。
    #[must_use]
    pub fn new(config: RelayConfig, transport: Box<dyn RelayTransport>) -> Self {
        Self {
            config,
            state: RelayState::Disconnected,
            stats: RelayStats::default(),
            events: Vec::new(),
            transport,
        }
    }

    /// 经中继建连：`Disconnected -> Connecting -> Connected / Failed`。
    ///
    /// 先校验配置；校验失败直接返回 `Invalid`（不产生状态迁移、不发事件）。
    /// 成功返回 `Connected`；失败进入 `Failed` 并返回 `ConnectivityError::Io{operation:"relay_connect"}`。
    pub fn connect(&mut self) -> Result<RelayState, ConnectivityError> {
        self.config.validate()?;
        if self.state != RelayState::Disconnected {
            return Err(ConnectivityError::Invalid {
                message: format!(
                    "relay channel must be Disconnected to connect, current state: {}",
                    self.state
                ),
            });
        }

        self.state = RelayState::Connecting;
        self.events.push(RelayEvent::Connecting {
            relay_server: self.config.relay_server.clone(),
            peer_id: self.config.peer_id.clone(),
        });

        match self.transport.connect(&self.config) {
            Ok(()) => {
                self.state = RelayState::Connected;
                self.events.push(RelayEvent::Connected {
                    relay_server: self.config.relay_server.clone(),
                    peer_id: self.config.peer_id.clone(),
                });
                Ok(self.state)
            }
            Err(reason) => {
                self.state = RelayState::Failed;
                self.events.push(RelayEvent::ConnectFailed {
                    relay_server: self.config.relay_server.clone(),
                    peer_id: self.config.peer_id.clone(),
                    reason: reason.clone(),
                });
                Err(ConnectivityError::Io {
                    operation: "relay_connect".to_string(),
                    message: reason,
                })
            }
        }
    }

    /// 转发一段数据（仅 `Connected` 允许；否则 `Invalid("relay not connected")`）。
    ///
    /// 成功后累加 `bytes_sent` / `forward_requests` 并发 `DataForwarded` 事件。
    pub fn forward(&mut self, data: &[u8]) -> Result<(), ConnectivityError> {
        self.ensure_connected()?;
        self.transport
            .forward(&self.config.peer_id, data)
            .map_err(|message| ConnectivityError::Io {
                operation: "relay_forward".to_string(),
                message,
            })?;
        self.stats.bytes_sent += data.len() as u64;
        self.stats.forward_requests += 1;
        self.events.push(RelayEvent::DataForwarded {
            peer_id: self.config.peer_id.clone(),
            bytes: data.len() as u64,
        });
        Ok(())
    }

    /// 接收一段数据到 `output`（仅 `Connected` 允许）。
    ///
    /// 收到 `n > 0` 字节时累加 `bytes_received` 并发 `DataReceived` 事件；`Ok(0)` 不计数、不发事件。
    pub fn receive(&mut self, output: &mut [u8]) -> Result<usize, ConnectivityError> {
        self.ensure_connected()?;
        let n = self
            .transport
            .receive(&self.config.peer_id, output)
            .map_err(|message| ConnectivityError::Io {
                operation: "relay_receive".to_string(),
                message,
            })?;
        if n > 0 {
            self.stats.bytes_received += n as u64;
            self.events.push(RelayEvent::DataReceived {
                peer_id: self.config.peer_id.clone(),
                bytes: n as u64,
            });
        }
        Ok(n)
    }

    /// 关闭通道：若非 `Disconnected`，回到 `Disconnected` 并发一次 `Closed` 事件；
    /// 已经是 `Disconnected` 则为幂等 no-op（不重复发 `Closed` 事件）。
    pub fn close(&mut self) {
        if self.state == RelayState::Disconnected {
            return;
        }
        self.state = RelayState::Disconnected;
        self.events.push(RelayEvent::Closed {
            peer_id: self.config.peer_id.clone(),
        });
    }

    /// 当前状态。
    #[must_use]
    pub fn state(&self) -> RelayState {
        self.state
    }

    /// 流量统计只读视图。
    #[must_use]
    pub fn stats(&self) -> &RelayStats {
        &self.stats
    }

    /// 已产生事件只读视图（可重放 / explain）。
    #[must_use]
    pub fn events(&self) -> &[RelayEvent] {
        &self.events
    }

    /// 通道配置只读视图。
    #[must_use]
    pub fn config(&self) -> &RelayConfig {
        &self.config
    }

    /// 收发门控：仅 `Connected` 允许数据面操作。
    fn ensure_connected(&self) -> Result<(), ConnectivityError> {
        if self.state == RelayState::Connected {
            Ok(())
        } else {
            Err(ConnectivityError::Invalid {
                message: "relay not connected".to_string(),
            })
        }
    }
}

// ---------- 离线 Mock 传输 ----------

use std::sync::{Arc, Mutex};

/// Mock 传输的可变内部状态（共享以支持 `inject_echo(&self)`）。
#[derive(Default)]
struct MockRelayInner {
    /// 待接收字节流（`receive` 按 FIFO 读出）。
    inbound: Vec<u8>,
    /// 已转发字节记录（测试断言用）。
    sent: Vec<Vec<u8>>,
}

/// 离线 Mock 中继传输：确定性回环，供单测与 E4 产品场景使用（零真实网络）。
///
/// - `connect` 按构造时预置结果返回；
/// - `forward` 把数据追加到 `sent` 记录；
/// - `receive` 从 `inbound` 字节流拷贝到输出（`inject_echo` 注入的数据可被读回）。
pub struct MockRelayTransport {
    connect_result: Result<(), String>,
    inner: Arc<Mutex<MockRelayInner>>,
}

impl MockRelayTransport {
    /// 构造：预置 `connect` 结果（`Ok(())` 表示建连成功，`Err(reason)` 表示失败）。
    #[must_use]
    pub fn new(connect_result: Result<(), String>) -> Self {
        Self {
            connect_result,
            inner: Arc::new(Mutex::new(MockRelayInner::default())),
        }
    }

    /// 注入一段待接收数据（模拟中继回环）；后续 `receive` 会按字节流读出。
    pub fn inject_echo(&self, data: &[u8]) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.inbound.extend_from_slice(data);
        }
    }

    /// 已转发数据的只读快照（测试断言用）。
    #[must_use]
    pub fn sent(&self) -> Vec<Vec<u8>> {
        self.inner
            .lock()
            .map(|guard| guard.sent.clone())
            .unwrap_or_default()
    }
}

impl RelayTransport for MockRelayTransport {
    fn connect(&mut self, _config: &RelayConfig) -> Result<(), String> {
        self.connect_result.clone()
    }

    fn forward(&mut self, _peer_id: &str, data: &[u8]) -> Result<(), String> {
        let mut inner = self.inner.lock().map_err(|e| e.to_string())?;
        inner.sent.push(data.to_vec());
        Ok(())
    }

    fn receive(&mut self, _peer_id: &str, output: &mut [u8]) -> Result<usize, String> {
        let mut inner = self.inner.lock().map_err(|e| e.to_string())?;
        let n = inner.inbound.len().min(output.len());
        output[..n].copy_from_slice(&inner.inbound[..n]);
        inner.inbound.drain(..n);
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_mock() -> MockRelayTransport {
        MockRelayTransport::new(Ok(()))
    }

    #[test]
    fn empty_server_or_peer_fails_validation() {
        assert!(RelayConfig::new("", "peer-a").validate().is_err());
        assert!(RelayConfig::new("relay:9999", "").validate().is_err());
        assert!(RelayConfig::new("relay:9999", "peer-a").validate().is_ok());
    }

    #[test]
    fn connect_success_transitions_disconnected_to_connected_with_events() {
        let config = RelayConfig::new("relay.example.org:9999", "peer-b");
        let mut channel = RelayChannel::new(config, Box::new(ok_mock()));
        assert_eq!(channel.state(), RelayState::Disconnected);

        let state = channel.connect().expect("connect should succeed");
        assert_eq!(state, RelayState::Connected);
        assert_eq!(channel.state(), RelayState::Connected);

        let events = channel.events();
        assert_eq!(events.len(), 2);
        assert!(matches!(
            events[0],
            RelayEvent::Connecting { ref relay_server, ref peer_id }
                if relay_server == "relay.example.org:9999" && peer_id == "peer-b"
        ));
        assert!(matches!(events[1], RelayEvent::Connected { .. }));
    }

    #[test]
    fn connect_failure_moves_to_failed_and_records_reason() {
        let config = RelayConfig::new("relay.example.org:9999", "peer-b");
        let mut channel = RelayChannel::new(
            config,
            Box::new(MockRelayTransport::new(Err("relay down".into()))),
        );
        let err = channel.connect().expect_err("connect should fail");
        assert_eq!(channel.state(), RelayState::Failed);
        match err {
            ConnectivityError::Io { operation, message } => {
                assert_eq!(operation, "relay_connect");
                assert_eq!(message, "relay down");
            }
            other => panic!("expected Io, got {other:?}"),
        }
        let last = channel.events.last().expect("has event");
        assert!(matches!(
            last,
            RelayEvent::ConnectFailed { reason, .. } if reason == "relay down"
        ));
    }

    #[test]
    fn forward_and_receive_require_connected_and_count_stats() {
        let config = RelayConfig::new("relay.example.org:9999", "peer-b");
        let mock = MockRelayTransport::new(Ok(()));
        let mut channel = RelayChannel::new(config, Box::new(mock));

        // 未连接：forward / receive 都被门控拒绝。
        assert!(channel.forward(b"payload").is_err());
        let mut buf = [0u8; 16];
        assert!(channel.receive(&mut buf).is_err());

        channel.connect().expect("connect");
        channel.forward(b"payload").expect("forward");
        assert_eq!(channel.stats().bytes_sent, 7);
        assert_eq!(channel.stats().forward_requests, 1);
    }

    #[test]
    fn receive_echo_returns_injected_bytes_and_counts() {
        let config = RelayConfig::new("relay.example.org:9999", "peer-b");
        let mock = MockRelayTransport::new(Ok(()));
        mock.inject_echo(b"relay-payload-12345");
        let mut channel = RelayChannel::new(config, Box::new(mock));
        channel.connect().expect("connect");

        let mut buf = [0u8; 64];
        let n = channel.receive(&mut buf).expect("receive");
        assert_eq!(n, 19);
        assert_eq!(&buf[..n], b"relay-payload-12345");
        assert_eq!(channel.stats().bytes_received, 19);
        assert!(matches!(
            channel.events.last(),
            Some(RelayEvent::DataReceived { bytes: 19, .. })
        ));
    }

    #[test]
    fn close_returns_to_disconnected_and_emits_closed() {
        let config = RelayConfig::new("relay.example.org:9999", "peer-b");
        let mut channel = RelayChannel::new(config, Box::new(ok_mock()));
        channel.connect().expect("connect");
        assert_eq!(channel.state(), RelayState::Connected);

        channel.close();
        assert_eq!(channel.state(), RelayState::Disconnected);
        assert!(matches!(
            channel.events.last(),
            Some(RelayEvent::Closed { peer_id }) if peer_id == "peer-b"
        ));
    }

    #[test]
    fn second_connect_after_connected_is_rejected() {
        let config = RelayConfig::new("relay.example.org:9999", "peer-b");
        let mut channel = RelayChannel::new(config, Box::new(ok_mock()));
        channel.connect().expect("first connect");
        let err = channel.connect().expect_err("second connect must fail");
        match err {
            ConnectivityError::Invalid { message } => {
                assert!(message.contains("must be Disconnected to connect"));
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn receive_without_injected_data_returns_zero_without_event() {
        let config = RelayConfig::new("relay.example.org:9999", "peer-b");
        let transport = MockRelayTransport::new(Ok(()));
        let mut channel = RelayChannel::new(config, Box::new(transport));
        channel.connect().expect("connect");

        let before = channel.events().len();
        let mut buf = [0u8; 16];
        let n = channel.receive(&mut buf).expect("receive empty");
        assert_eq!(n, 0);
        assert_eq!(channel.stats().bytes_received, 0);
        // Ok(0) 不发 DataReceived 事件；末事件仍为 Connected。
        assert_eq!(channel.events().len(), before);
        assert!(matches!(
            channel.events.last(),
            Some(RelayEvent::Connected { .. })
        ));
    }

    #[test]
    fn close_is_idempotent_and_does_not_duplicate_closed_event() {
        let config = RelayConfig::new("relay.example.org:9999", "peer-b");
        let mut channel = RelayChannel::new(config, Box::new(ok_mock()));
        channel.connect().expect("connect");

        channel.close();
        assert_eq!(channel.state(), RelayState::Disconnected);
        let len_after_first_close = channel.events().len();
        assert!(matches!(
            channel.events.last(),
            Some(RelayEvent::Closed { peer_id }) if peer_id == "peer-b"
        ));

        channel.close();
        assert_eq!(channel.state(), RelayState::Disconnected);
        assert_eq!(channel.events().len(), len_after_first_close);
        assert_eq!(
            channel
                .events()
                .iter()
                .filter(|e| matches!(e, RelayEvent::Closed { .. }))
                .count(),
            1
        );
    }
}
