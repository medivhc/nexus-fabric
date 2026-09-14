//! Portable ingress semantics. No OS-specific interception belongs here.

#![forbid(unsafe_code)]

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowContext {
    pub source: String,
    pub destination: String,
    pub protocol: String,
    pub domain: Option<String>,
    pub process: Option<String>,
    pub application: Option<String>,
    pub uid: Option<u32>,
}

pub trait IngressSink: Send + Sync {
    fn submit(&self, flow: FlowContext) -> Result<(), String>;
}
