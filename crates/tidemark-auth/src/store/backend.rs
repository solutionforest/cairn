//! Persistence abstraction for the credential store. tidemark-meta provides the redb impl.

use std::collections::BTreeMap;
use std::sync::RwLock;

/// Backend error (opaque message; must not contain secrets).
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct BackendError(pub String);

/// Key/value pairs returned by a prefix scan.
pub type KvPairs = Vec<(Vec<u8>, Vec<u8>)>;

/// One mutation in an atomic batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendOp {
    /// Insert or replace.
    Put(Vec<u8>, Vec<u8>),
    /// Remove (no-op if absent).
    Delete(Vec<u8>),
}

/// Ordered byte-key/value store. Keys are namespaced by a one-letter prefix and `/`
/// (`u/` users, `g/` groups, `r/` roles, `p/` managed policies, `k/` access keys,
/// `s/` STS sessions, `x/` singletons such as `x/root`). Values are opaque, schema-versioned
/// postcard records; secrets inside them are already AEAD-encrypted.
pub trait CredentialBackend: Send + Sync {
    /// Get a value.
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, BackendError>;
    /// Put a value.
    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), BackendError> {
        self.apply(vec![BackendOp::Put(key.to_vec(), value.to_vec())])
    }
    /// Delete a value; returns whether it existed.
    fn delete(&self, key: &[u8]) -> Result<bool, BackendError> {
        let existed = self.get(key)?.is_some();
        self.apply(vec![BackendOp::Delete(key.to_vec())])?;
        Ok(existed)
    }
    /// All entries whose key starts with `prefix`, in key order.
    fn list_prefix(&self, prefix: &[u8]) -> Result<KvPairs, BackendError>;
    /// Apply a batch atomically (one write transaction).
    fn apply(&self, ops: Vec<BackendOp>) -> Result<(), BackendError>;
}

/// In-memory backend for tests and ephemeral servers.
#[derive(Debug, Default)]
pub struct MemoryBackend {
    map: RwLock<BTreeMap<Vec<u8>, Vec<u8>>>,
}

impl MemoryBackend {
    /// Empty backend.
    pub fn new() -> Self {
        Self::default()
    }
    /// Number of stored entries.
    pub fn len(&self) -> usize {
        self.map.read().map(|m| m.len()).unwrap_or(0)
    }
    /// True if empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Raw dump (tests: check secrets are not stored in plaintext).
    pub fn dump(&self) -> KvPairs {
        self.map
            .read()
            .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default()
    }
}

fn poisoned<T>(_: T) -> BackendError {
    BackendError("memory backend lock poisoned".into())
}

impl CredentialBackend for MemoryBackend {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, BackendError> {
        Ok(self.map.read().map_err(poisoned)?.get(key).cloned())
    }

    fn list_prefix(&self, prefix: &[u8]) -> Result<KvPairs, BackendError> {
        let m = self.map.read().map_err(poisoned)?;
        Ok(m.range(prefix.to_vec()..)
            .take_while(|(k, _)| k.starts_with(prefix))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect())
    }

    fn apply(&self, ops: Vec<BackendOp>) -> Result<(), BackendError> {
        let mut m = self.map.write().map_err(poisoned)?;
        for op in ops {
            match op {
                BackendOp::Put(k, v) => {
                    m.insert(k, v);
                }
                BackendOp::Delete(k) => {
                    m.remove(&k);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_backend_basics() {
        let b = MemoryBackend::new();
        b.put(b"u/a", b"1").unwrap();
        b.put(b"u/b", b"2").unwrap();
        b.put(b"v/a", b"3").unwrap();
        assert_eq!(b.get(b"u/a").unwrap(), Some(b"1".to_vec()));
        assert_eq!(b.list_prefix(b"u/").unwrap().len(), 2);
        assert!(b.delete(b"u/a").unwrap());
        assert!(!b.delete(b"u/a").unwrap());
        b.apply(vec![
            BackendOp::Delete(b"u/b".to_vec()),
            BackendOp::Put(b"u/c".to_vec(), vec![]),
        ])
        .unwrap();
        assert_eq!(
            b.list_prefix(b"u/").unwrap(),
            vec![(b"u/c".to_vec(), vec![])]
        );
    }
}
