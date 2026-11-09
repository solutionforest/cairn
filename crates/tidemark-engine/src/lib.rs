#![forbid(unsafe_code)]
#![warn(clippy::all)]
//! Tidemark engine: orchestrates `tidemark-meta` and `tidemark-blob` into S3 semantics — buckets,
//! versioning (with shadow versioning on unversioned buckets), multipart, tagging, soft delete,
//! trash, PITR and GC (DESIGN §5, §7).

/// Named crash point for the kill -9 tests in `crash_tests`; expands to nothing outside
/// `cfg(test)`.
macro_rules! failpoint {
    ($name:literal) => {
        #[cfg(test)]
        crate::crash_tests::failpoint($name);
    };
}

pub mod backup;
mod bucket;
mod commit;
#[cfg(test)]
mod crash_tests;
mod events;
pub mod fsck;
mod gc;
pub mod lifecycle;
mod list;
mod multipart;
mod object;
mod recovery;
pub mod replication;
pub mod scrub;
mod trash;
pub mod types;
pub mod usage;
mod util;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tidemark_blob::{DataKey, FsBlobStore};
use tidemark_core::config::{LimitsConfig, RetentionConfig};
use tidemark_core::{BucketName, S3Error, S3ErrorCode, S3Result};
use tidemark_meta::{BucketRecord, BucketState, MetaStore, ReadExt, ReadTxn, RedbMetaStore};

pub use events::{RequestCtx, current_ctx, tidemark_events, with_request_ctx};
pub use list::MAX_LIST_KEYS;
pub use recovery::{LATEST_SAMPLE, RecoveryReport};
pub use tidemark_meta;
pub use types::*;
pub use usage::BucketUsage;

/// Engine settings derived from `tidemark_core::Config`.
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

/// Runtime collaborators that are not plain configuration (see [`TidemarkEngine::open_with`]).
#[derive(Clone, Default)]
pub struct EngineExtras {
    /// Event outbox every committed mutation appends to (default: records nothing unless a
    /// bucket has a notification configuration).
    pub outbox: tidemark_events::Outbox,
    /// Region name stamped on events (default `us-east-1`).
    pub region: Option<String>,
    /// Free-space guard checked before new blob data is written.
    pub space: Option<tidemark_blob::space::SpaceGuard>,
}

struct Inner {
    meta: RedbMetaStore,
    blobs: FsBlobStore,
    cfg: EngineConfig,
    data_dir: PathBuf,
    unclean: bool,
    tmp_removed: usize,
    shut: AtomicBool,
    outbox: tidemark_events::Outbox,
    region: String,
    space: Option<tidemark_blob::space::SpaceGuard>,
}

/// Marker file present while an engine has the data directory open.
const RUNNING_MARKER: &str = "RUNNING";

/// The object store.
#[derive(Clone)]
pub struct TidemarkEngine {
    inner: Arc<Inner>,
}

impl TidemarkEngine {
    /// Open the engine on a data directory (`meta/tidemark.redb`, `blobs/`, `tmp/`).
    pub fn open(data_dir: &Path, cfg: EngineConfig) -> S3Result<TidemarkEngine> {
        TidemarkEngine::open_with(data_dir, cfg, EngineExtras::default())
    }

    /// [`TidemarkEngine::open`] with an event outbox, region and free-space guard.
    pub fn open_with(
        data_dir: &Path,
        cfg: EngineConfig,
        extras: EngineExtras,
    ) -> S3Result<TidemarkEngine> {
        let meta = RedbMetaStore::open(&data_dir.join("meta").join("tidemark.redb"))?;
        let blobs = FsBlobStore::open(data_dir, cfg.fsync)?;
        let tmp_removed = blobs.clean_tmp()?;
        let marker = data_dir.join("meta").join(RUNNING_MARKER);
        let unclean = marker.exists();
        std::fs::write(&marker, std::process::id().to_string())?;
        Ok(TidemarkEngine {
            inner: Arc::new(Inner {
                meta,
                blobs,
                cfg,
                data_dir: data_dir.to_path_buf(),
                unclean,
                tmp_removed,
                shut: AtomicBool::new(false),
                outbox: extras.outbox,
                region: extras.region.unwrap_or_else(|| "us-east-1".into()),
                space: extras.space,
            }),
        })
    }

    /// Metadata store handle (shared with `tidemark-auth`).
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

    /// Data directory root.
    pub fn data_dir(&self) -> &Path {
        &self.inner.data_dir
    }

    /// Stop the metadata writer after draining queued jobs and mark the shutdown clean.
    /// Idempotent; the database file is closed once every engine handle is dropped.
    pub fn shutdown(&self) {
        if self.inner.shut.swap(true, Ordering::SeqCst) {
            return;
        }
        self.inner.meta.shutdown();
        let _ = std::fs::remove_file(self.inner.data_dir.join("meta").join(RUNNING_MARKER));
    }

    /// Whether [`TidemarkEngine::shutdown`] has run.
    pub fn is_shut_down(&self) -> bool {
        self.inner.shut.load(Ordering::SeqCst)
    }

    pub(crate) fn read(&self) -> S3Result<ReadTxn> {
        Ok(self.inner.meta.read()?)
    }

    /// Resolve an active bucket by name.
    pub fn bucket(&self, name: &str) -> S3Result<BucketRecord> {
        resolve_bucket(&self.read()?, name)
    }

    /// A bucket by identity, active or trashed (time travel and PITR across a bucket delete
    /// address the bucket by id, never by a name that may since have been reused).
    pub fn bucket_by_id(&self, id: tidemark_core::BucketId) -> S3Result<BucketRecord> {
        self.read()?
            .bucket(id)?
            .ok_or_else(|| no_such_bucket(&id.to_string()))
    }

    /// Readiness: not shut down, metadata readable and `tmp/` writable.
    pub fn ready(&self) -> bool {
        if self.is_shut_down() || self.read().is_err() {
            return false;
        }
        let probe = self
            .inner
            .data_dir
            .join("tmp")
            .join(format!(".ready-{}", uuid::Uuid::new_v4()));
        let ok = std::fs::write(&probe, b"ok").is_ok();
        let _ = std::fs::remove_file(&probe);
        ok
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
