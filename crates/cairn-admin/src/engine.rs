//! The storage-side operations the admin API exposes, as a trait cairn-engine implements.
//! Timestamps are RFC 3339 strings so the wire format does not depend on internal types.

use crate::error::AdminError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Mutex;

/// Per-bucket retention settings (DESIGN §7).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionSettings {
    /// Days a soft-deleted version stays in the trash before GC (`None` = server default).
    pub trash_days: Option<u32>,
    /// Days superseded versions stay restorable for PITR (`None` = server default).
    pub history_days: Option<u32>,
}

/// Object Lock configuration summary.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectLockSummary {
    /// Object Lock enabled on the bucket.
    pub enabled: bool,
    /// Default retention mode (`GOVERNANCE` / `COMPLIANCE`).
    pub default_mode: Option<String>,
    /// Default retention in days.
    pub default_days: Option<u32>,
    /// Default retention in years.
    pub default_years: Option<u32>,
}

/// Admin view of a bucket.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BucketSummary {
    /// Bucket name.
    pub name: String,
    /// Internal bucket id (needed to restore a trashed bucket).
    pub id: String,
    /// Creation time.
    pub created_at: String,
    /// Owner principal id.
    pub owner: String,
    /// `Off` / `Enabled` / `Suspended`.
    pub versioning: String,
    /// Live objects.
    pub object_count: u64,
    /// Bytes of live objects.
    pub total_bytes: u64,
    /// Bytes held in trash and history.
    pub trash_bytes: u64,
    /// Quota in bytes (`None` = unlimited).
    pub quota_bytes: Option<u64>,
    /// Retention settings.
    pub retention: RetentionSettings,
    /// Object Lock summary.
    pub object_lock: ObjectLockSummary,
    /// True if the bucket itself is in the trash.
    pub trashed: bool,
}

/// Filters for listing the trash.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrashQuery {
    /// Only this bucket.
    pub bucket: Option<String>,
    /// Only keys with this prefix.
    pub prefix: Option<String>,
    /// Deleted at or after (RFC 3339).
    pub deleted_after: Option<String>,
    /// Deleted before (RFC 3339).
    pub deleted_before: Option<String>,
    /// Deleted by this principal id.
    pub by: Option<String>,
    /// Page size (default 1000).
    pub limit: Option<u32>,
    /// Continuation cursor from a previous page.
    pub cursor: Option<String>,
}

/// One soft-deleted version.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrashEntry {
    /// Bucket name.
    pub bucket: String,
    /// Object key.
    pub key: String,
    /// Version id.
    pub version_id: String,
    /// Size in bytes.
    pub size: u64,
    /// Deletion time.
    pub deleted_at: String,
    /// Who deleted it.
    pub deleted_by: String,
    /// `Api` / `Lifecycle` / `Admin`.
    pub reason: String,
    /// When GC may purge it.
    pub expires_at: String,
}

/// A page of trash entries.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrashPage {
    /// Entries.
    pub entries: Vec<TrashEntry>,
    /// Cursor for the next page.
    pub next_cursor: Option<String>,
}

/// Restore one soft-deleted object version.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreRequest {
    /// Bucket.
    pub bucket: String,
    /// Key.
    pub key: String,
    /// Version (default: newest deleted).
    pub version_id: Option<String>,
}

/// Outcome of a restore.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreResult {
    /// Bucket.
    pub bucket: String,
    /// Key.
    pub key: String,
    /// Restored version.
    pub version_id: String,
    /// True if the restored version is now the current one.
    pub became_current: bool,
}

/// Restore a trashed bucket.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreBucketRequest {
    /// Bucket id of the trashed bucket.
    pub bucket_id: String,
    /// Restore under a new name.
    pub as_name: Option<String>,
}

/// Irreversibly purge trash entries.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PurgeRequest {
    /// Bucket.
    pub bucket: String,
    /// Single key.
    pub key: Option<String>,
    /// Single version of `key`.
    pub version_id: Option<String>,
    /// All keys under a prefix.
    pub prefix: Option<String>,
    /// Only entries deleted before this time (RFC 3339).
    pub older_than: Option<String>,
    /// Must be true (the CLI's `--yes`).
    #[serde(default)]
    pub confirm: bool,
}

/// Outcome of a purge.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PurgeResult {
    /// Versions purged.
    pub purged: u64,
    /// Bytes released (before blob dedup).
    pub bytes: u64,
}

/// Point-in-time restore of a bucket or prefix.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PitrRequest {
    /// Source bucket.
    pub bucket: String,
    /// Limit to a prefix.
    pub prefix: Option<String>,
    /// Target time (RFC 3339).
    pub as_of: String,
    /// Write into another bucket instead of in place.
    pub target_bucket: Option<String>,
    /// Write under another prefix.
    pub target_prefix: Option<String>,
    /// Only report what would change.
    #[serde(default)]
    pub dry_run: bool,
}

/// One key's change in a PITR restore or diff.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PitrChange {
    /// Key.
    pub key: String,
    /// `restore` / `delete` / `create` / `modify` / `unchanged`.
    pub action: String,
    /// Version before.
    pub from_version: Option<String>,
    /// Version after.
    pub to_version: Option<String>,
}

/// Outcome of a PITR restore.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PitrResult {
    /// Keys changed.
    pub restored: u64,
    /// Keys already at the target state.
    pub unchanged: u64,
    /// Echo of the request flag.
    pub dry_run: bool,
    /// Per-key changes (may be truncated by the engine).
    pub changes: Vec<PitrChange>,
}

/// Difference between two points in time.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PitrDiffQuery {
    /// Bucket.
    pub bucket: String,
    /// Prefix.
    pub prefix: Option<String>,
    /// From (RFC 3339).
    pub from: String,
    /// To (RFC 3339, default now).
    pub to: Option<String>,
}

/// Server facts for `cairn admin info`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerInfo {
    /// Cairn version.
    pub version: String,
    /// Region name.
    pub region: String,
    /// Seconds since start.
    pub uptime_secs: u64,
    /// Number of buckets.
    pub buckets: u64,
    /// Live objects.
    pub objects: u64,
    /// Live bytes.
    pub bytes: u64,
    /// Metadata schema version.
    pub schema_version: u32,
}

/// Storage operations behind the admin API (implemented by cairn-engine).
#[async_trait::async_trait]
pub trait AdminEngine: Send + Sync {
    /// Server summary.
    async fn server_info(&self) -> Result<ServerInfo, AdminError>;
    /// All buckets (including trashed ones) with usage, quota, retention and lock summary.
    async fn list_buckets(&self) -> Result<Vec<BucketSummary>, AdminError>;
    /// One bucket.
    async fn get_bucket(&self, bucket: &str) -> Result<BucketSummary, AdminError>;
    /// Set or clear the bucket quota.
    async fn set_quota(&self, bucket: &str, quota_bytes: Option<u64>) -> Result<(), AdminError>;
    /// Set retention windows.
    async fn set_retention(&self, bucket: &str, r: RetentionSettings) -> Result<(), AdminError>;
    /// List soft-deleted versions.
    async fn list_trash(&self, q: TrashQuery) -> Result<TrashPage, AdminError>;
    /// Restore a soft-deleted version.
    async fn restore(&self, r: RestoreRequest) -> Result<RestoreResult, AdminError>;
    /// Restore a trashed bucket.
    async fn restore_bucket(&self, r: RestoreBucketRequest) -> Result<BucketSummary, AdminError>;
    /// Purge trash entries (refuses under Compliance lock).
    async fn purge(&self, r: PurgeRequest) -> Result<PurgeResult, AdminError>;
    /// Point-in-time restore.
    async fn pitr_restore(&self, r: PitrRequest) -> Result<PitrResult, AdminError>;
    /// Diff between two points in time.
    async fn pitr_diff(&self, q: PitrDiffQuery) -> Result<Vec<PitrChange>, AdminError>;
}

/// In-memory [`AdminEngine`] for tests and for running the admin API without storage.
#[derive(Debug, Default)]
pub struct MockAdminEngine {
    /// Buckets by name.
    pub buckets: Mutex<BTreeMap<String, BucketSummary>>,
    /// Trash entries.
    pub trash: Mutex<Vec<TrashEntry>>,
}

impl MockAdminEngine {
    /// Engine with the given buckets and trash.
    pub fn new(buckets: Vec<BucketSummary>, trash: Vec<TrashEntry>) -> Self {
        Self {
            buckets: Mutex::new(buckets.into_iter().map(|b| (b.name.clone(), b)).collect()),
            trash: Mutex::new(trash),
        }
    }
    fn b(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, BucketSummary>> {
        self.buckets.lock().unwrap_or_else(|e| e.into_inner())
    }
    fn t(&self) -> std::sync::MutexGuard<'_, Vec<TrashEntry>> {
        self.trash.lock().unwrap_or_else(|e| e.into_inner())
    }
}

fn no_bucket(b: &str) -> AdminError {
    AdminError::not_found(format!("bucket not found: {b}"))
}

#[async_trait::async_trait]
impl AdminEngine for MockAdminEngine {
    async fn server_info(&self) -> Result<ServerInfo, AdminError> {
        let b = self.b();
        Ok(ServerInfo {
            version: env!("CARGO_PKG_VERSION").into(),
            region: "us-east-1".into(),
            uptime_secs: 0,
            buckets: b.len() as u64,
            objects: b.values().map(|x| x.object_count).sum(),
            bytes: b.values().map(|x| x.total_bytes).sum(),
            schema_version: 1,
        })
    }
    async fn list_buckets(&self) -> Result<Vec<BucketSummary>, AdminError> {
        Ok(self.b().values().cloned().collect())
    }
    async fn get_bucket(&self, bucket: &str) -> Result<BucketSummary, AdminError> {
        self.b()
            .get(bucket)
            .cloned()
            .ok_or_else(|| no_bucket(bucket))
    }
    async fn set_quota(&self, bucket: &str, quota_bytes: Option<u64>) -> Result<(), AdminError> {
        let mut b = self.b();
        b.get_mut(bucket)
            .ok_or_else(|| no_bucket(bucket))?
            .quota_bytes = quota_bytes;
        Ok(())
    }
    async fn set_retention(&self, bucket: &str, r: RetentionSettings) -> Result<(), AdminError> {
        let mut b = self.b();
        b.get_mut(bucket)
            .ok_or_else(|| no_bucket(bucket))?
            .retention = r;
        Ok(())
    }
    async fn list_trash(&self, q: TrashQuery) -> Result<TrashPage, AdminError> {
        let entries = self
            .t()
            .iter()
            .filter(|e| q.bucket.as_ref().is_none_or(|b| &e.bucket == b))
            .filter(|e| {
                q.prefix
                    .as_ref()
                    .is_none_or(|p| e.key.starts_with(p.as_str()))
            })
            .filter(|e| q.by.as_ref().is_none_or(|p| &e.deleted_by == p))
            .take(q.limit.unwrap_or(1000) as usize)
            .cloned()
            .collect();
        Ok(TrashPage {
            entries,
            next_cursor: None,
        })
    }
    async fn restore(&self, r: RestoreRequest) -> Result<RestoreResult, AdminError> {
        let mut t = self.t();
        let pos = t
            .iter()
            .position(|e| {
                e.bucket == r.bucket
                    && e.key == r.key
                    && r.version_id.as_ref().is_none_or(|v| &e.version_id == v)
            })
            .ok_or_else(|| AdminError::not_found("no such trash entry"))?;
        let e = t.remove(pos);
        Ok(RestoreResult {
            bucket: e.bucket,
            key: e.key,
            version_id: e.version_id,
            became_current: true,
        })
    }
    async fn restore_bucket(&self, r: RestoreBucketRequest) -> Result<BucketSummary, AdminError> {
        let mut b = self.b();
        let name = b
            .values()
            .find(|x| x.id == r.bucket_id && x.trashed)
            .map(|x| x.name.clone())
            .ok_or_else(|| AdminError::not_found("no such trashed bucket"))?;
        let mut x = b.remove(&name).unwrap_or_default();
        x.trashed = false;
        if let Some(n) = r.as_name {
            x.name = n;
        }
        b.insert(x.name.clone(), x.clone());
        Ok(x)
    }
    async fn purge(&self, r: PurgeRequest) -> Result<PurgeResult, AdminError> {
        let mut t = self.t();
        let before = t.len();
        let mut bytes = 0;
        t.retain(|e| {
            let hit = e.bucket == r.bucket
                && r.key.as_ref().is_none_or(|k| &e.key == k)
                && r.version_id.as_ref().is_none_or(|v| &e.version_id == v)
                && r.prefix
                    .as_ref()
                    .is_none_or(|p| e.key.starts_with(p.as_str()));
            if hit {
                bytes += e.size;
            }
            !hit
        });
        Ok(PurgeResult {
            purged: (before - t.len()) as u64,
            bytes,
        })
    }
    async fn pitr_restore(&self, r: PitrRequest) -> Result<PitrResult, AdminError> {
        if !self.b().contains_key(&r.bucket) {
            return Err(no_bucket(&r.bucket));
        }
        Ok(PitrResult {
            restored: 0,
            unchanged: 0,
            dry_run: r.dry_run,
            changes: Vec::new(),
        })
    }
    async fn pitr_diff(&self, q: PitrDiffQuery) -> Result<Vec<PitrChange>, AdminError> {
        if !self.b().contains_key(&q.bucket) {
            return Err(no_bucket(&q.bucket));
        }
        Ok(Vec::new())
    }
}
