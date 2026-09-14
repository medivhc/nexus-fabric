//! Content-addressed local storage abstractions.

#![forbid(unsafe_code)]

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ObjectId(pub String);

pub trait ContentStore {
    fn contains(&self, id: &ObjectId) -> Result<bool, String>;
    fn get(&self, id: &ObjectId) -> Result<Option<Vec<u8>>, String>;
    fn put(&mut self, bytes: &[u8]) -> Result<ObjectId, String>;
}

pub trait ReachabilityGc {
    fn mark_roots(&mut self, roots: &[ObjectId]) -> Result<(), String>;
    fn sweep_older_than(&mut self, retention_seconds: u64) -> Result<u64, String>;
}
