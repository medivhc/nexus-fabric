//! Filesystem projection contract (v9 §22, portable).
//!
//! A workspace projected as a filesystem: platform adapters (Linux FUSE,
//! Windows/macOS filesystem adapters, mobile File/Document providers) map
//! platform file semantics onto this trait. The adapters MUST NOT own
//! replica selection, path planning, cache policy, or commit semantics —
//! they only translate file operations into these calls.
//!
//! Deletion Test: if this trait is removed and `nexus-platform-linux`
//! depends directly on `nexus-workspace::WorkspaceAccess`, the v9 §4
//! invariant "platform adapters -X-> higher-level domain runtimes" breaks,
//! and every future platform adapter would need its own private coupling
//! to the workspace domain. This trait is the single portable contract
//! that keeps the dependency arrow pointing down.

use crate::PlatformError;

/// One directory entry in a projected workspace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectedDirEntry {
    /// Entry name (not a path; relative to the listed directory).
    pub name: String,
    pub is_dir: bool,
    /// File size in bytes; `None` for directories.
    pub size: Option<u64>,
}

/// Portable workspace-as-filesystem contract.
///
/// Implemented by workspace access channels (adapted in `nexus-workspace`);
/// consumed by platform projection adapters (`nexus-platform-*`).
/// Method semantics mirror `WorkspaceAccess`: writes stage, `commit`
/// persists staged changes as a new commit.
pub trait ProjectedWorkspace: Send {
    /// Read full file content.
    fn read_file(&self, path: &str) -> Result<Vec<u8>, PlatformError>;
    /// Stage a file write (not committed until [`ProjectedWorkspace::commit`]).
    fn write_file(&mut self, path: &str, content: &[u8]) -> Result<(), PlatformError>;
    /// List a directory's entries.
    fn list_dir(&self, path: &str) -> Result<Vec<ProjectedDirEntry>, PlatformError>;
    /// Delete a file or (empty) directory.
    fn delete(&mut self, path: &str) -> Result<(), PlatformError>;
    /// Commit staged changes; returns the new commit id.
    fn commit(&mut self) -> Result<String, PlatformError>;
    /// Current head commit id, if any.
    fn head(&self) -> Option<String>;
    /// Current durable state root object id, if the access channel tracks one.
    ///
    /// Default: `None` (channels without durable state). Added for daemon
    /// lifecycle (C1/D4): the composition root needs the latest state root
    /// after each commit to update its `state_root` anchor file for `open`
    /// on restart. This is observability metadata, not file semantics.
    fn state_root(&self) -> Option<String> {
        None
    }
}
