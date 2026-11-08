//! [`cairn_admin::AdminEngine`] over [`CairnEngine`]: buckets with usage/quota/retention, trash,
//! purge and point-in-time restore for the `/_cairn/v1` API.

use cairn_admin::AdminError;
use cairn_admin::engine::*;
use cairn_core::{BucketId, PrincipalId, S3Error, S3ErrorCode, Ts, VersionId};
use cairn_engine::cairn_meta::{
    BucketRecord, BucketState, DeleteReason, MetaStore, RetentionPolicy, VersionState, Versioning,
};
use cairn_engine::{CairnEngine, DiffKind, PitrTarget, usage};
use std::time::Instant;

const DAY: u64 = 86_400;
/// Most PITR changes returned in one response.
const MAX_CHANGES: usize = 1000;

/// The admin API's storage backend.
pub struct EngineAdmin {
    engine: CairnEngine,
    region: String,
    started: Instant,
}

impl EngineAdmin {
    /// Wrap an engine.
    pub fn new(engine: CairnEngine, region: String) -> EngineAdmin {
        EngineAdmin {
            engine,
            region,
            started: Instant::now(),
        }
    }

    fn summary(&self, b: &BucketRecord) -> Result<BucketSummary, AdminError> {
        let u = self.engine.usage_of(b).map_err(map)?;
        let days = |s: Option<u64>| s.map(|s| (s / DAY) as u32);
        Ok(BucketSummary {
            name: b.name.clone(),
            id: b.id.to_string(),
            created_at: b.created_at.to_rfc3339(),
            owner: b.owner.as_str().to_string(),
            versioning: match b.versioning {
                Versioning::Off => "Off",
                Versioning::Enabled => "Enabled",
                Versioning::Suspended => "Suspended",
            }
            .into(),
            object_count: u.objects,
            total_bytes: u.live_bytes(),
            trash_bytes: u.hidden_bytes,
            quota_bytes: usage::quota(b),
            retention: RetentionSettings {
                trash_days: days(b.retention.soft_delete_secs),
                history_days: days(b.retention.shadow_history_secs),
            },
            object_lock: ObjectLockSummary {
                enabled: b.object_lock_enabled,
                ..Default::default()
            },
            trashed: matches!(b.state, BucketState::Trashed { .. }),
        })
    }
}

fn admin_principal() -> PrincipalId {
    PrincipalId("cairn:admin".into())
}

/// Map engine errors onto the admin error envelope.
pub fn map(e: S3Error) -> AdminError {
    use S3ErrorCode::*;
    match e.code {
        NoSuchBucket | NoSuchKey | NoSuchVersion | NoSuchUpload => AdminError::not_found(e.message),
        InvalidArgument | InvalidRequest | InvalidBucketName | MalformedXML => {
            AdminError::invalid(e.message)
        }
        BucketAlreadyExists | BucketAlreadyOwnedByYou | InvalidBucketState => {
            AdminError::conflict(e.message)
        }
        AccessDenied => AdminError::denied(e.message),
        _ => AdminError::internal(e),
    }
}

fn parse_time(s: &str) -> Result<Ts, AdminError> {
    s.parse::<jiff::Timestamp>()
        .map(|t| Ts(t.as_nanosecond()))
        .map_err(|_| AdminError::invalid(format!("invalid RFC 3339 timestamp {s:?}")))
}

fn parse_vid(s: &str) -> Result<VersionId, AdminError> {
    s.parse()
        .map_err(|_| AdminError::invalid(format!("invalid version id {s:?}")))
}

fn change(c: &cairn_engine::PitrChange) -> PitrChange {
    PitrChange {
        key: c.key.clone(),
        action: match c.kind {
            DiffKind::Recreate => "restore",
            DiffKind::Revert => "modify",
            DiffKind::Remove => "delete",
        }
        .into(),
        from_version: c.now.map(|v| v.to_string()),
        to_version: c
            .new_version
            .clone()
            .or_else(|| c.then.map(|v| v.to_string())),
    }
}

impl EngineAdmin {
    fn trash_entries(&self, q: &TrashQuery) -> Result<Vec<TrashEntry>, AdminError> {
        let buckets: Vec<String> = match &q.bucket {
            Some(b) => vec![b.clone()],
            None => self
                .engine
                .list_buckets()
                .map_err(map)?
                .into_iter()
                .map(|b| b.name)
                .collect(),
        };
        let after = q.deleted_after.as_deref().map(parse_time).transpose()?;
        let before = q.deleted_before.as_deref().map(parse_time).transpose()?;
        let mut out = Vec::new();
        for b in buckets {
            let list = self
                .engine
                .trash_list(&b, q.prefix.as_deref().unwrap_or(""), 100_000)
                .map_err(map)?;
            for e in list {
                let (by, reason) = match &e.version.state {
                    VersionState::SoftDeleted { by, reason, .. } => (
                        by.as_str().to_string(),
                        match reason {
                            DeleteReason::Api => "Api",
                            DeleteReason::Lifecycle => "Lifecycle",
                            DeleteReason::Admin => "Admin",
                        },
                    ),
                    _ => (e.version.owner.as_str().to_string(), "Superseded"),
                };
                if after.is_some_and(|t| e.hidden_at < t)
                    || before.is_some_and(|t| e.hidden_at >= t)
                    || q.by.as_ref().is_some_and(|p| p != &by)
                {
                    continue;
                }
                out.push(TrashEntry {
                    bucket: e.bucket.clone(),
                    key: e.version.key.clone(),
                    version_id: e.version.version_id.to_string(),
                    size: e.version.body().map_or(0, |b| b.size),
                    deleted_at: e.hidden_at.to_rfc3339(),
                    deleted_by: by,
                    reason: reason.into(),
                    expires_at: e.expires_at.to_rfc3339(),
                });
            }
        }
        Ok(out)
    }
}

#[async_trait::async_trait]
impl AdminEngine for EngineAdmin {
    async fn server_info(&self) -> Result<ServerInfo, AdminError> {
        let buckets = self.engine.list_buckets().map_err(map)?;
        let (mut objects, mut bytes) = (0, 0);
        for b in &buckets {
            let u = self.engine.usage_of(b).map_err(map)?;
            objects += u.objects;
            bytes += u.live_bytes();
        }
        let r = self.engine.meta().read().map_err(|e| map(e.into()))?;
        let schema = cairn_meta::migrate::schema_version(&r)
            .ok()
            .flatten()
            .unwrap_or(cairn_meta::migrate::CURRENT_SCHEMA);
        Ok(ServerInfo {
            version: env!("CARGO_PKG_VERSION").into(),
            region: self.region.clone(),
            uptime_secs: self.started.elapsed().as_secs(),
            buckets: buckets.len() as u64,
            objects,
            bytes,
            schema_version: schema,
        })
    }

    async fn list_buckets(&self) -> Result<Vec<BucketSummary>, AdminError> {
        let mut v = self.engine.list_buckets().map_err(map)?;
        v.extend(self.engine.trashed_buckets().map_err(map)?);
        v.iter().map(|b| self.summary(b)).collect()
    }

    async fn get_bucket(&self, bucket: &str) -> Result<BucketSummary, AdminError> {
        let b = self.engine.bucket(bucket).map_err(map)?;
        self.summary(&b)
    }

    async fn set_quota(&self, bucket: &str, quota_bytes: Option<u64>) -> Result<(), AdminError> {
        self.engine
            .set_bucket_quota(bucket, quota_bytes)
            .await
            .map_err(map)
    }

    async fn set_retention(&self, bucket: &str, r: RetentionSettings) -> Result<(), AdminError> {
        let cur = self.engine.bucket(bucket).map_err(map)?.retention;
        let secs = |d: Option<u32>| d.map(|d| u64::from(d) * DAY);
        if r.trash_days == Some(0) || r.history_days == Some(0) {
            tracing::warn!(
                bucket,
                "retention set to 0 days: deletes become hard deletes"
            );
        }
        self.engine
            .set_bucket_retention(
                bucket,
                RetentionPolicy {
                    soft_delete_secs: secs(r.trash_days),
                    shadow_history_secs: secs(r.history_days),
                    min_versions_kept: cur.min_versions_kept,
                },
            )
            .await
            .map_err(map)
    }

    async fn list_trash(&self, q: TrashQuery) -> Result<TrashPage, AdminError> {
        let all = self.trash_entries(&q)?;
        let start: usize = match &q.cursor {
            Some(c) => c
                .parse()
                .map_err(|_| AdminError::invalid("invalid cursor"))?,
            None => 0,
        };
        let limit = q.limit.unwrap_or(1000).clamp(1, 10_000) as usize;
        let entries: Vec<_> = all.iter().skip(start).take(limit).cloned().collect();
        let next = start + entries.len();
        Ok(TrashPage {
            next_cursor: (next < all.len()).then(|| next.to_string()),
            entries,
        })
    }

    async fn restore(&self, r: RestoreRequest) -> Result<RestoreResult, AdminError> {
        let vid = r.version_id.as_deref().map(parse_vid).transpose()?;
        let res = self
            .engine
            .trash_restore(&r.bucket, &r.key, vid, &admin_principal())
            .await
            .map_err(map)?;
        Ok(RestoreResult {
            bucket: r.bucket,
            key: r.key,
            version_id: res
                .version_id
                .unwrap_or_else(|| res.version.version_id.to_string()),
            became_current: true,
        })
    }

    async fn restore_bucket(&self, r: RestoreBucketRequest) -> Result<BucketSummary, AdminError> {
        let id: BucketId = match (&r.bucket, r.bucket_id.is_empty()) {
            (Some(name), true) => {
                self.engine
                    .trashed_buckets()
                    .map_err(map)?
                    .into_iter()
                    .find(|b| &b.name == name)
                    .ok_or_else(|| AdminError::not_found(format!("no trashed bucket {name:?}")))?
                    .id
            }
            _ => r
                .bucket_id
                .parse()
                .map_err(|_| AdminError::invalid("invalid bucket id"))?,
        };
        let b = if r.all_versions {
            self.engine
                .restore_bucket_all(id, r.as_name, &admin_principal())
                .await
                .map_err(map)?
                .0
        } else {
            self.engine
                .restore_bucket(id, r.as_name)
                .await
                .map_err(map)?
        };
        self.summary(&b)
    }

    async fn purge(&self, r: PurgeRequest) -> Result<PurgeResult, AdminError> {
        if !r.confirm {
            return Err(AdminError::invalid("purge is irreversible; set confirm"));
        }
        let older = r.older_than.as_deref().map(parse_time).transpose()?;
        let entries = self.trash_entries(&TrashQuery {
            bucket: Some(r.bucket.clone()),
            prefix: r.key.clone().or(r.prefix.clone()),
            deleted_before: None,
            ..Default::default()
        })?;
        let mut out = PurgeResult::default();
        for e in entries {
            if r.key.as_ref().is_some_and(|k| k != &e.key)
                || r.version_id.as_ref().is_some_and(|v| v != &e.version_id)
            {
                continue;
            }
            if let Some(t) = older
                && parse_time(&e.deleted_at)? >= t
            {
                continue;
            }
            self.engine
                .trash_purge(&e.bucket, &e.key, parse_vid(&e.version_id)?)
                .await
                .map_err(map)?;
            out.purged += 1;
            out.bytes += e.size;
        }
        Ok(out)
    }

    async fn pitr_restore(&self, r: PitrRequest) -> Result<PitrResult, AdminError> {
        let at = parse_time(&r.as_of)?;
        let src = match &r.bucket_id {
            Some(id) => {
                let id = id
                    .parse::<BucketId>()
                    .map_err(|_| AdminError::invalid("invalid bucket id"))?;
                // Authorization was decided on `bucket`; the id must name that bucket.
                if self.engine.bucket_by_id(id).map_err(map)?.name != r.bucket {
                    return Err(AdminError::invalid("bucket_id does not belong to bucket"));
                }
                id
            }
            None => self.engine.bucket(&r.bucket).map_err(map)?.id,
        };
        let rep = self
            .engine
            .pitr_restore_id(
                src,
                r.prefix.as_deref().unwrap_or(""),
                at,
                PitrTarget {
                    bucket: r.target_bucket.clone(),
                    prefix: r.target_prefix.clone(),
                },
                r.dry_run,
                &admin_principal(),
            )
            .await
            .map_err(map)?;
        Ok(PitrResult {
            restored: rep.changes.len() as u64,
            unchanged: rep.unchanged,
            dry_run: r.dry_run,
            changes: rep.changes.iter().take(MAX_CHANGES).map(change).collect(),
        })
    }

    async fn pitr_diff(&self, q: PitrDiffQuery) -> Result<Vec<PitrChange>, AdminError> {
        if q.to.is_some() {
            return Err(AdminError::not_implemented(
                "pitr diff is computed against the current state; omit `to`",
            ));
        }
        let at = parse_time(&q.from)?;
        let d = self
            .engine
            .pitr_diff(&q.bucket, q.prefix.as_deref().unwrap_or(""), at)
            .map_err(map)?;
        Ok(d.iter()
            .take(MAX_CHANGES)
            .map(|e| {
                change(&cairn_engine::PitrChange {
                    key: e.key.clone(),
                    kind: e.kind,
                    then: e.then,
                    now: e.now,
                    new_version: None,
                })
            })
            .collect())
    }
}
