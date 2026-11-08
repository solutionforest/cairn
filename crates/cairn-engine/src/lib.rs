#![forbid(unsafe_code)]
#![warn(clippy::all)]
//! Cairn engine: orchestrates `cairn-meta` and `cairn-blob` into S3 semantics — buckets,
//! versioning (with shadow versioning on unversioned buckets), multipart, tagging, soft delete,
//! trash, PITR and GC (DESIGN §5, §7).

mod bucket;
mod commit;
mod multipart;
mod object;
mod recovery;
pub mod types;
mod util;

use cairn_blob::{DataKey, FsBlobStore};
use cairn_core::config::{LimitsConfig, RetentionConfig};
use cairn_core::{BucketName, S3Error, S3ErrorCode, S3Result};
use cairn_meta::{BucketRecord, BucketState, MetaStore, ReadExt, ReadTxn, RedbMetaStore};
use std::path::Path;
use std::sync::Arc;

pub use cairn_meta;
pub use types::*;

/// Engine settings derived from `cairn_core::Config`.
#[derive(Clone, Default)]
pub struct EngineConfig {
    /// Retention defaults.
    pub retention: RetentionConfig,
    /// Request limits.
    pub limits: LimitsConfig,
    /// Encrypt blobs at rest with this key.
    pub at_rest_key: Option<DataKey>,
    /// fsync blobs.
    pub fsync: bool,
}

struct Inner {
    meta: RedbMetaStore,
    blobs: FsBlobStore,
    cfg: EngineConfig,
}

/// The object store.
#[derive(Clone)]
pub struct CairnEngine {
    inner: Arc<Inner>,
}

impl CairnEngine {
    /// Open the engine on a data directory (`meta/cairn.redb`, `blobs/`, `tmp/`).
    pub fn open(data_dir: &Path, cfg: EngineConfig) -> S3Result<CairnEngine> {
        let meta = RedbMetaStore::open(&data_dir.join("meta").join("cairn.redb"))?;
        let blobs = FsBlobStore::open(data_dir, cfg.fsync)?;
        blobs.clean_tmp()?;
        Ok(CairnEngine { inner: Arc::new(Inner { meta, blobs, cfg }) })
    }

    /// Metadata store handle (shared with `cairn-auth`).
    pub fn meta(&self) -> &RedbMetaStore {
        &self.inner.meta
    }

    /// Blob store handle.
    pub fn blobs(&self) -> &FsBlobStore {
        &self.inner.blobs
    }

    /// Engine configuration.
    pub fn config(&self) -> &EngineConfig {
        &self.inner.cfg
    }

    /// Stop the metadata writer.
    pub fn shutdown(&self) {
        self.inner.meta.shutdown();
    }

    pub(crate) fn read(&self) -> S3Result<ReadTxn> {
        Ok(self.inner.meta.read()?)
    }

    /// Resolve an active bucket by name.
    pub fn bucket(&self, name: &str) -> S3Result<BucketRecord> {
        resolve_bucket(&self.read()?, name)
    }

    /// Readiness: metadata readable and data dir writable.
    pub fn ready(&self) -> bool {
        self.read().is_ok() && self.inner.blobs.clean_tmp().is_ok()
    }
}

pub(crate) fn no_such_bucket(name: &str) -> S3Error {
    S3Error::code(S3ErrorCode::NoSuchBucket).with_resource(name)
}

pub(crate) fn resolve_bucket<R: ReadExt + ?Sized>(r: &R, name: &str) -> S3Result<BucketRecord> {
    BucketName::try_from(name).map_err(|_| no_such_bucket(name))?;
    match r.bucket_by_name(name)? {
        Some(b) if b.state == BucketState::Active => Ok(b),
        _ => Err(no_such_bucket(name)),
    }
}
