//! Adapter: `WorkspaceAccess` → `nexus_platform::ProjectedWorkspace`.
//!
//! This is the single place where workspace-domain file semantics are
//! translated into the portable projection contract consumed by platform
//! adapters (`nexus-platform-*`). The adapter owns no replica selection,
//! path planning, cache policy, or commit semantics — it only maps calls
//! and errors.

#![forbid(unsafe_code)]

use nexus_platform::{PlatformError, ProjectedDirEntry, ProjectedWorkspace};

use crate::{WorkspaceAccess, WorkspaceError};

fn map_err(op: &'static str, e: WorkspaceError) -> PlatformError {
    match e {
        WorkspaceError::NotFound { path } => PlatformError::NotFound { key: path },
        WorkspaceError::PathTraversal { path } => PlatformError::Invalid {
            message: format!("path traversal rejected: {path}"),
        },
        other => PlatformError::Io {
            operation: op.to_string(),
            message: format!("{other:?}"),
        },
    }
}

/// Adapts any `WorkspaceAccess + Send` channel to the portable
/// [`ProjectedWorkspace`] contract.
pub struct WorkspaceProjection<A: WorkspaceAccess + Send>(pub A);

impl<A: WorkspaceAccess + Send> WorkspaceProjection<A> {
    /// Wrap an access channel.
    pub fn new(access: A) -> Self {
        Self(access)
    }

    /// Unwrap back to the access channel.
    pub fn into_inner(self) -> A {
        self.0
    }
}

impl<A: WorkspaceAccess + Send> ProjectedWorkspace for WorkspaceProjection<A> {
    fn read_file(&self, path: &str) -> Result<Vec<u8>, PlatformError> {
        self.0.read_file(path).map_err(|e| map_err("read_file", e))
    }

    fn write_file(&mut self, path: &str, content: &[u8]) -> Result<(), PlatformError> {
        self.0
            .write_file(path, content)
            .map_err(|e| map_err("write_file", e))
    }

    fn list_dir(&self, path: &str) -> Result<Vec<ProjectedDirEntry>, PlatformError> {
        let entries = self.0.list_dir(path).map_err(|e| map_err("list_dir", e))?;
        Ok(entries
            .into_iter()
            .map(|d| {
                // DirEntry.path is workspace-root-relative; project the leaf name.
                let name = d.path.rsplit('/').next().unwrap_or(&d.path).to_string();
                ProjectedDirEntry {
                    name,
                    is_dir: d.is_dir,
                    size: d.size,
                }
            })
            .collect())
    }

    fn delete(&mut self, path: &str) -> Result<(), PlatformError> {
        self.0.delete(path).map_err(|e| map_err("delete", e))
    }

    fn commit(&mut self) -> Result<String, PlatformError> {
        self.0
            .commit()
            .map(|id| id.0)
            .map_err(|e| map_err("commit", e))
    }

    fn head(&self) -> Option<String> {
        self.0.head().map(|id| id.0.clone())
    }

    fn state_root(&self) -> Option<String> {
        self.0.state_root()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuthorId, NativeApiWorkspaceAccess, Workspace, WorkspaceId};
    use nexus_storage::InMemoryContentStore;

    fn setup() -> WorkspaceProjection<NativeApiWorkspaceAccess<InMemoryContentStore>> {
        let ws = Workspace::init(
            WorkspaceId("proj-test".into()),
            InMemoryContentStore::new(),
            AuthorId("test-author".into()),
        )
        .expect("init");
        WorkspaceProjection::new(NativeApiWorkspaceAccess::new(ws))
    }

    #[test]
    fn roundtrip_through_projection() {
        let mut p = setup();
        p.write_file("a.txt", b"hello").unwrap();
        assert_eq!(p.read_file("a.txt").unwrap(), b"hello");
        let entries = p.list_dir("").unwrap();
        assert!(entries.iter().any(|e| e.name == "a.txt" && !e.is_dir));
        let h0 = p.head();
        let h1 = p.commit().unwrap();
        assert_ne!(Some(h1.as_str()), h0.as_deref());
        assert_eq!(p.head().as_deref(), Some(h1.as_str()));
    }

    #[test]
    fn not_found_maps_to_platform_not_found() {
        let p = setup();
        let r = p.read_file("missing.txt");
        assert!(matches!(r, Err(PlatformError::NotFound { .. })));
    }

    #[test]
    fn delete_roundtrip() {
        let mut p = setup();
        p.write_file("d.txt", b"x").unwrap();
        p.delete("d.txt").unwrap();
        assert!(matches!(
            p.read_file("d.txt"),
            Err(PlatformError::NotFound { .. })
        ));
    }
}
