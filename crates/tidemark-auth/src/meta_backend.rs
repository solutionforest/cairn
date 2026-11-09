//! [`CredentialBackend`] over `tidemark-meta` (redb). Prefixes route to the IAM tables of DESIGN
//! §4.3: `u/ g/ r/` → `principals`, `k/ x/` → `access_keys`, `p/` → `policies`,
//! `s/` → `sessions`. Keys keep their prefix inside the table.

use crate::store::{BackendError, BackendOp, CredentialBackend, backend::KvPairs};
use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};
use tidemark_meta::{Flow, MetaError, MetaStore, Reader, RedbMetaStore, Table};

/// Credential persistence in the metadata database.
#[derive(Clone)]
pub struct MetaCredentialBackend {
    store: RedbMetaStore,
}

impl std::fmt::Debug for MetaCredentialBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MetaCredentialBackend")
    }
}

impl MetaCredentialBackend {
    /// Wrap an open metadata store.
    pub fn new(store: RedbMetaStore) -> Self {
        Self { store }
    }
}

/// Table for a backend key (by its one-letter prefix).
pub(crate) fn table_for(key: &[u8]) -> Table {
    match key.first() {
        Some(b'k' | b'x') => Table::AccessKeys,
        Some(b'p') => Table::Policies,
        Some(b's') => Table::Sessions,
        _ => Table::Principals,
    }
}

fn me(e: MetaError) -> BackendError {
    BackendError(e.to_string())
}

struct ThreadWaker(std::thread::Thread);

impl Wake for ThreadWaker {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }
}

/// Drive a future to completion on the current thread. Used for metadata writes from the
/// synchronous backend trait; the future only waits on the writer thread, never on tokio.
pub(crate) fn block_on<F: Future>(fut: F) -> F::Output {
    let waker = Waker::from(Arc::new(ThreadWaker(std::thread::current())));
    let mut cx = Context::from_waker(&waker);
    let mut fut = std::pin::pin!(fut);
    loop {
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(v) => return v,
            Poll::Pending => std::thread::park(),
        }
    }
}

impl CredentialBackend for MetaCredentialBackend {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, BackendError> {
        self.store
            .read()
            .and_then(|r| r.get(table_for(key), key))
            .map_err(me)
    }

    fn list_prefix(&self, prefix: &[u8]) -> Result<KvPairs, BackendError> {
        let r = self.store.read().map_err(me)?;
        let mut out = Vec::new();
        r.scan_prefix(table_for(prefix), prefix, &mut |k, v| {
            out.push((k.to_vec(), v.to_vec()));
            Ok(Flow::Continue)
        })
        .map_err(me)?;
        Ok(out)
    }

    fn apply(&self, ops: Vec<BackendOp>) -> Result<(), BackendError> {
        let fut = self.store.write(move |txn| -> Result<(), MetaError> {
            for op in &ops {
                match op {
                    BackendOp::Put(k, v) => txn.put(table_for(k), k, v)?,
                    BackendOp::Delete(k) => {
                        txn.del(table_for(k), k)?;
                    }
                }
            }
            Ok(())
        });
        block_on(fut).map_err(me)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::CredentialStore;
    use crate::{MasterKey, SecretString};

    #[tokio::test]
    async fn store_roundtrips_through_redb() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("meta.redb");
        let mk = MasterKey::new([3; 32]);
        {
            let meta = RedbMetaStore::open(&path).unwrap();
            let cs = CredentialStore::new(
                Arc::new(MetaCredentialBackend::new(meta.clone())),
                mk.clone(),
            );
            cs.ensure_root("ROOTKEY", &SecretString::new("rootsecret"))
                .await
                .unwrap();
            cs.create_user("alice").await.unwrap();
            cs.create_access_key("alice", Default::default())
                .await
                .unwrap();
            meta.shutdown();
        }
        let meta = RedbMetaStore::open(&path).unwrap();
        let backend = MetaCredentialBackend::new(meta.clone());
        assert_eq!(backend.list_prefix(b"u/").unwrap().len(), 1);
        assert_eq!(backend.list_prefix(b"k/").unwrap().len(), 2);
        let r = meta.read().unwrap();
        assert!(r.get(Table::Principals, b"u/alice").unwrap().is_some());
        assert!(r.get(Table::AccessKeys, b"x/root").unwrap().is_some());
        let cs = CredentialStore::new(Arc::new(backend), mk);
        let c = cs.lookup("ROOTKEY").await.unwrap().unwrap();
        assert!(c.principal.is_root);
        assert_eq!(c.secret_key.expose(), "rootsecret");
        meta.shutdown();
    }
}
