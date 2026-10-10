//! N3 content addresses are independent of legacy FNV locators. The composition
//! root supplies SHA-256 and durable publication; this crate stays portable.
use nexus_domain::task::{Sha256Digest, TaskError, TaskErrorCode, codec::DigestFn};

/// A verified v1 SHA-256 namespace. Implementations must verify every read and
/// publish only digest/length-matching bytes, never address them by legacy ID.
/// Deletion is deliberately absent: GC needs recovered domain roots.
pub trait StrongContentStore {
    fn get_verified(&self, digest: &Sha256Digest, size_bytes: u64) -> Result<Vec<u8>, TaskError>;
    fn put_verified(&mut self, digest: &Sha256Digest, bytes: &[u8]) -> Result<(), TaskError>;
}

/// Pure check shared by publishing, reading and materialization boundaries.
pub fn verify_content(
    digest: &Sha256Digest,
    size_bytes: u64,
    bytes: &[u8],
    hash: DigestFn,
) -> Result<(), TaskError> {
    if bytes.len() as u64 != size_bytes || &hash(bytes) != digest {
        return Err(TaskError::new(
            TaskErrorCode::InputIntegrityFailed,
            "SHA-256 or content length differs from frozen input",
            false,
        ));
    }
    Ok(())
}
