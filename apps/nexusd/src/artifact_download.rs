//! Compatibility facade for the shared Linux Artifact receiver.
//!
//! The CLI composition root owns receiving and no-replace publication; the
//! daemon keeps its existing public receiver path for downstream callers.
pub use nexus::artifact_download::ArtifactDownload;
