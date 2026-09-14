//! Nexus stable domain core.

#![forbid(unsafe_code)]

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ResourceId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProviderId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionId(pub String);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Intent {
    pub profile: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Constraint {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub resource_id: ResourceId,
    pub provider_id: ProviderId,
    pub placement: String,
    pub path: Vec<String>,
    pub execution_strategy: String,
    pub domain_extension_type: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LifecyclePhase {
    Allocating,
    Active,
    Draining,
    Disposed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TerminalOutcome {
    Unfinished,
    Completed,
    Failed(String),
    Cancelled(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionStatus {
    pub phase: LifecyclePhase,
    pub outcome: TerminalOutcome,
}
