//! Typed errors for the Nexus Web Gateway.

use std::io;

/// Errors produced by the web gateway.
#[derive(Debug)]
pub enum GatewayError {
    /// I/O error (TLS, TCP, UDP, file).
    Io(io::Error),
    /// Invalid configuration (missing field, bad address, ...).
    Config(String),
    /// TLS material generation / loading failed.
    Tls(String),
    /// WebSocket protocol error.
    WebSocket(String),
    /// WebRTC (str0m) error.
    Rtc(String),
    /// Mesh signaling error.
    Mesh(String),
    /// SSH bridge error.
    Ssh(String),
    /// Protocol violation from a browser peer.
    Protocol(String),
    /// Session not found / already gone.
    SessionNotFound(String),
    /// Limit reached (e.g. max concurrent terminals).
    Limit(String),
}

impl From<io::Error> for GatewayError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl std::fmt::Display for GatewayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io error: {e}"),
            Self::Config(s) => write!(f, "config error: {s}"),
            Self::Tls(s) => write!(f, "tls error: {s}"),
            Self::WebSocket(s) => write!(f, "websocket error: {s}"),
            Self::Rtc(s) => write!(f, "webrtc error: {s}"),
            Self::Mesh(s) => write!(f, "mesh error: {s}"),
            Self::Ssh(s) => write!(f, "ssh error: {s}"),
            Self::Protocol(s) => write!(f, "protocol error: {s}"),
            Self::SessionNotFound(s) => write!(f, "session not found: {s}"),
            Self::Limit(s) => write!(f, "limit reached: {s}"),
        }
    }
}

impl std::error::Error for GatewayError {}

impl From<tungstenite::Error> for GatewayError {
    fn from(e: tungstenite::Error) -> Self {
        Self::WebSocket(e.to_string())
    }
}

impl From<str0m::RtcError> for GatewayError {
    fn from(e: str0m::RtcError) -> Self {
        Self::Rtc(e.to_string())
    }
}
