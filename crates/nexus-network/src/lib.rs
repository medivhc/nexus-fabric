//! nexus-network
//!
//! 实现 InternetAccess Network Domain Runtime，消费 Policy/Plan/Session/Delivery/DNS 结果执行网络会话。
//!
//! 详细边界见同目录 `MODULE.md`。

#![forbid(unsafe_code)]

/// N1 Universal Connectivity 装配（portable core，M1–M7）。
///
/// 契约见同目录 `MODULE.md` "N1 Universal Connectivity 装配契约"一节。
/// 本模块只经注入 trait 消费 fabric/path/discovery/platform 实现，
/// 不新增架构边（Deletion Test 见 MODULE.md）。
pub mod n1;

/// 网络会话阶段（冻结契约，scenarios/product/remote_internet_access_flow.toml）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkPhase {
    /// 正在建立网络会话（请求/响应往返尚未完成）。
    Connecting,
    /// 网络会话已建立且请求/响应往返成功（携带 HTTP 状态码）。
    Active,
    /// 网络会话已关闭。
    Closed,
}

impl std::fmt::Display for NetworkPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            NetworkPhase::Connecting => "Connecting",
            NetworkPhase::Active => "Active",
            NetworkPhase::Closed => "Closed",
        };
        f.write_str(s)
    }
}

/// 网络会话错误（冻结契约）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkError {
    /// 底层帧通道读写失败。
    Transport,
    /// 响应帧不携带有效 HTTP 状态码（未认证/被拒绝语义）。
    Unauthorized,
    /// 帧通道已关闭。
    Closed,
}

impl std::fmt::Display for NetworkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            NetworkError::Transport => "network transport failure",
            NetworkError::Unauthorized => "network session rejected",
            NetworkError::Closed => "network session closed",
        };
        f.write_str(s)
    }
}

impl std::error::Error for NetworkError {}

/// 注入的帧通道（冻结契约）：由 Composition Root 以 `nexus_transport::FrameStream`
/// 适配装配，避免 network -> transport 依赖边（MODULE.md Allowed Dependencies）。
pub trait NetworkTransport {
    /// 发送一帧请求；失败返回 `NetworkError::Transport`。
    fn send_frame(&mut self, payload: &[u8]) -> Result<(), NetworkError>;
    /// 接收一帧响应；通道关闭返回 `NetworkError::Closed`。
    fn recv_frame(&mut self) -> Result<Vec<u8>, NetworkError>;
}

/// InternetAccess 远程网络会话（PRODUCT §2/§6）：在已认证帧通道上发送请求帧、
/// 接收响应帧并提取 HTTP 状态码后进入 Active。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkSession {
    phase: NetworkPhase,
    response_status: Option<String>,
}

impl NetworkSession {
    /// 建立网络会话：发送 `request` 帧并接收响应帧；响应首行解析出 HTTP 状态码后
    /// 进入 `Active`，否则视为被拒绝（`NetworkError::Unauthorized`）。
    ///
    /// 冻结语义（MODULE.md）：网络会话必须显式建立后才 Active；调用方保证帧通道
    /// 已完成认证（W7：未认证帧不得进入业务处理）。
    pub fn establish(
        mut transport: Box<dyn NetworkTransport>,
        request: &[u8],
    ) -> Result<Self, NetworkError> {
        let mut session = Self {
            phase: NetworkPhase::Connecting,
            response_status: None,
        };
        transport.send_frame(request)?;
        let resp = transport.recv_frame()?;
        match extract_http_status(&resp) {
            Some(code) => {
                session.response_status = Some(code);
                session.phase = NetworkPhase::Active;
                Ok(session)
            }
            None => Err(NetworkError::Unauthorized),
        }
    }

    /// 当前网络会话阶段。
    #[must_use]
    pub fn phase(&self) -> NetworkPhase {
        self.phase
    }

    /// 成功往返携带的 HTTP 状态码（如 "200"）；未建立成功时为 None。
    #[must_use]
    pub fn response_status(&self) -> Option<&str> {
        self.response_status.as_deref()
    }
}

/// 从 HTTP 响应帧中提取状态码：首行（CRLF/LF 截断）按空白切分的第二个字段，
/// 且必须为 3 位 ASCII 数字。
fn extract_http_status(resp: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(resp);
    let first_line = text.split(['\r', '\n']).next()?;
    let mut parts = first_line.split_whitespace();
    let _version = parts.next()?;
    let status = parts.next()?;
    if status.len() == 3 && status.bytes().all(|b| b.is_ascii_digit()) {
        Some(status.to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockTransport {
        inbound: Vec<u8>,
    }

    impl NetworkTransport for MockTransport {
        fn send_frame(&mut self, _payload: &[u8]) -> Result<(), NetworkError> {
            Ok(())
        }

        fn recv_frame(&mut self) -> Result<Vec<u8>, NetworkError> {
            Ok(self.inbound.clone())
        }
    }

    #[test]
    fn establish_parses_http_status_and_activates() {
        let transport = MockTransport {
            inbound: b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec(),
        };
        let session = NetworkSession::establish(Box::new(transport), b"GET / HTTP/1.1\r\n\r\n")
            .expect("establish must succeed");
        assert_eq!(session.phase(), NetworkPhase::Active);
        assert_eq!(session.response_status(), Some("200"));
    }

    #[test]
    fn establish_rejects_non_http_response() {
        let transport = MockTransport {
            inbound: b"NOT-A-RESPONSE".to_vec(),
        };
        let session = NetworkSession::establish(Box::new(transport), b"GET / HTTP/1.1\r\n\r\n");
        assert_eq!(session, Err(NetworkError::Unauthorized));
    }

    #[test]
    fn extract_status_is_strict() {
        assert_eq!(
            extract_http_status(b"HTTP/1.1 404 Not Found\r\n"),
            Some("404".into())
        );
        assert_eq!(extract_http_status(b"HTTP/1.1 OK\r\n"), None);
        assert_eq!(extract_http_status(b"garbage"), None);
        assert_eq!(extract_http_status(b""), None);
    }
}
