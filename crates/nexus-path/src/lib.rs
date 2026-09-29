//! Path layer: "which path should packets take to reach the peer?"
//!
//! Manages candidate paths (direct → mesh → TURN → proxy), probes them,
//! scores them, and switches the active path with hysteresis. P0: single
//! active path, no racing/prediction/multipath.
//!
//! Contract phase: all APIs are honest stubs returning "not implemented".

use std::net::SocketAddr;

/// Kind of candidate path, ordered by preference (cost ascending).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathKind {
    Direct,
    Mesh,
    Turn,
    Proxy,
}

/// A candidate path to a peer.
#[derive(Debug, Clone)]
pub struct CandidatePath {
    pub kind: PathKind,
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    /// Relative cost (relay bandwidth, cellular billing, etc.). Lower is better.
    pub cost: f64,
}

/// Observed statistics for a path (all optional; unknown = not yet measured).
#[derive(Debug, Clone, Default)]
pub struct PathStats {
    pub rtt_ms: Option<u64>,
    pub loss_rate: Option<f64>,
    pub throughput_bps: Option<u64>,
}

/// Configuration for path selection.
#[derive(Debug, Clone)]
pub struct PathConfig {
    /// New path must beat current by this margin (in score units) to switch.
    pub hysteresis_db: f64,
    /// New path must hold the lead for this long before switching.
    pub switch_hold_ms: u64,
    /// Interval between active probes on idle paths.
    pub probe_interval_ms: u64,
    /// EWMA smoothing factor for scores.
    pub ewma_alpha: f64,
    /// Consecutive missed probes before a path is declared failed.
    pub max_missed_probes: u32,
}

impl Default for PathConfig {
    fn default() -> Self {
        Self {
            hysteresis_db: 1.0,
            switch_hold_ms: 2000,
            probe_interval_ms: 5000,
            ewma_alpha: 0.3,
            max_missed_probes: 3,
        }
    }
}

/// Reason for a path switch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwitchReason {
    BetterScore,
    PathFailed,
    PathAdded,
}

/// Path lifecycle event.
#[derive(Debug, Clone)]
pub enum PathEvent {
    Switched {
        from: CandidatePath,
        to: CandidatePath,
        reason: SwitchReason,
    },
}

/// Error type for path operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathError {
    /// Operation requires the path manager to be implemented.
    NotImplemented,
    /// No candidate paths available.
    NoPath,
}

impl std::fmt::Display for PathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PathError::NotImplemented => write!(f, "not implemented"),
            PathError::NoPath => write!(f, "no path available"),
        }
    }
}

impl std::error::Error for PathError {}

/// Manages candidate paths and selects the active one.
///
/// Contract phase: honest stub. All methods return `NotImplemented` or `None`.
pub struct PathManager {
    _config: PathConfig,
}

impl PathManager {
    pub fn new(config: PathConfig) -> Self {
        Self { _config: config }
    }

    pub fn add_candidate(&mut self, _path: CandidatePath) -> Result<(), PathError> {
        Err(PathError::NotImplemented)
    }

    pub fn remove_candidate(&mut self, _remote: &SocketAddr) -> Result<(), PathError> {
        Err(PathError::NotImplemented)
    }

    pub fn current_path(&self) -> Option<CandidatePath> {
        None
    }

    pub fn on_stats(&mut self, _remote: &SocketAddr, _stats: PathStats) -> Result<(), PathError> {
        Err(PathError::NotImplemented)
    }

    pub fn poll_event(&self) -> Option<PathEvent> {
        None
    }

    /// Score for a path (higher is better). Unknown if no data.
    pub fn score(&self, _remote: &SocketAddr) -> Option<f64> {
        None
    }
}

impl Drop for PathManager {
    fn drop(&mut self) {
        // Contract phase: no background thread yet.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_returns_not_implemented() {
        let mut pm = PathManager::new(PathConfig::default());
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let path = CandidatePath {
            kind: PathKind::Direct,
            local_addr: addr,
            remote_addr: addr,
            cost: 0.0,
        };
        assert_eq!(pm.add_candidate(path), Err(PathError::NotImplemented));
        assert_eq!(pm.current_path(), None);
    }
}
