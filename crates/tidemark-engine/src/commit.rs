//! Synchronous helpers that run inside metadata write jobs.

use crate::{EngineConfig, no_such_bucket};
use std::time::Duration;
use tidemark_blob::FsBlobStore;
use tidemark_core::{BlobId, BucketId, PrincipalId, S3Error, S3ErrorCode, S3Result, Ts, VersionId};
use tidemark_meta::{
    BucketRecord, BucketState, Flow, ReadExt, Reader, Table, VersionKind, VersionRecord,
    VersionState, Versioning, WriteTxn, decode, keys,
};

use crate::types::WriteConditions;
use crate::util::check_write_conditions;

/// Active bucket by id, inside a txn.
pub(crate) fn active_bucket(txn: &WriteTxn, id: BucketId, name: &str) -> S3Result<BucketRecord> {
    match txn.bucket(id)? {
        Some(b) if b.state == BucketState::Active => Ok(b),
        _ => Err(no_such_bucket(name)),
    }
}

/// (soft_delete, shadow_history) windows for a bucket.
pub(crate) fn retention(b: &BucketRecord, cfg: &EngineConfig) -> (Duration, Duration) {
    (
        b.retention
            .soft_delete_secs
            .map_or(cfg.retention.soft_delete, Duration::from_secs),
        b.retention
            .shadow_history_secs
            .map_or(cfg.retention.shadow_history, Duration::from_secs),
    )
}

/// A timestamp strictly newer than any stored version of `key` (keeps per-key order monotonic
/// even if the wall clock steps backwards).
pub(crate) fn now_for_key(txn: &WriteTxn, b: BucketId, key: &str) -> S3Result<Ts> {
    let mut now = Ts::now();
    txn.scan_prefix(Table::Versions, &keys::versions_of(b, key), &mut |_, v| {
        let r: VersionRecord = decode(v)?;
        if r.created_at >= now {
            now = Ts(r.created_at.0 + 1);
        }
        if let Some(h) = r.state.hidden_since()
            && h >= now
        {
            now = Ts(h.0 + 1);
        }
        Ok(Flow::Stop)
    })?;
    Ok(now)
}

/// Increment a blob refcount; if it had no live references, require the file to still exist
/// (GC unlinks only from inside write jobs, so this check is race-free).
pub(crate) fn incref_checked(
    txn: &WriteTxn,
    blobs: &FsBlobStore,
    id: &BlobId,
    size: u64,
) -> S3Result<()> {
    let prev = txn.blob_incref(id, size)?;
    if prev.is_none_or(|r| r.refcount == 0) && !blobs.exists_sync(id) {
        return Err(S3Error::new(
            S3ErrorCode::InternalError,
            "blob was garbage collected concurrently; retry the request",
        ));
    }
    Ok(())
}

/// Move a version out of Live and into the trash index.
pub(crate) fn hide(
    txn: &WriteTxn,
    b: BucketId,
    mut v: VersionRecord,
    state: VersionState,
    expires: Ts,
) -> S3Result<()> {
    crate::usage::on_hide(txn, b, &v)?;
    v.state = state;
    txn.put_version(b, &v)?;
    txn.trash_add(expires, b, &v.key, &v.version_id)?;
    Ok(())
}

/// Soft-delete a version on behalf of `by`.
pub(crate) fn soft_delete(
    txn: &WriteTxn,
    b: &BucketRecord,
    cfg: &EngineConfig,
    v: VersionRecord,
    now: Ts,
    by: &PrincipalId,
) -> S3Result<()> {
    soft_delete_as(txn, b, cfg, v, now, by, tidemark_meta::DeleteReason::Api)
}

/// [`soft_delete`] with an explicit reason (lifecycle, admin).
pub(crate) fn soft_delete_as(
    txn: &WriteTxn,
    b: &BucketRecord,
    cfg: &EngineConfig,
    v: VersionRecord,
    now: Ts,
    by: &PrincipalId,
    reason: tidemark_meta::DeleteReason,
) -> S3Result<()> {
    let (soft, _) = retention(b, cfg);
    let state = VersionState::SoftDeleted {
        at: now,
        by: by.clone(),
        reason,
    };
    hide(txn, b.id, v, state, now.plus(soft))
}

/// Object Lock / legal hold guard for version-specific deletes.
pub(crate) fn check_lock(v: &VersionRecord, now: Ts) -> S3Result<()> {
    if v.legal_hold || v.lock.is_some_and(|l| l.retain_until > now) {
        return Err(S3Error::new(
            S3ErrorCode::AccessDenied,
            "Access Denied because object protected by object lock.",
        ));
    }
    Ok(())
}

/// Create a new Live version of `key` with the bucket's versioning semantics:
/// Enabled → old head stays Live; Off/Suspended → the Live `null` version becomes Superseded.
/// Every blob referenced by `kind` is increfed.
#[allow(clippy::too_many_arguments)]
pub(crate) fn commit_version(
    txn: &WriteTxn,
    blobs: &FsBlobStore,
    cfg: &EngineConfig,
    bucket_id: BucketId,
    bucket_name: &str,
    key: &str,
    kind: VersionKind,
    owner: &PrincipalId,
    conds: &WriteConditions,
) -> S3Result<(VersionRecord, BucketRecord)> {
    let bucket = active_bucket(txn, bucket_id, bucket_name)?;
    let head = txn
        .latest(bucket_id, key)?
        .filter(|v| !v.is_delete_marker());
    check_write_conditions(conds, head.as_ref())?;
    let now = now_for_key(txn, bucket_id, key)?;
    if let VersionKind::Object(body) = &kind {
        crate::usage::check_quota(txn, &bucket, body.size)?;
        for p in &body.parts {
            incref_checked(txn, blobs, &p.blob, p.size)?;
        }
    }
    let is_null = bucket.versioning != Versioning::Enabled;
    if is_null && let Some(old) = txn.null_version(bucket_id, key, false)? {
        let (_, shadow) = retention(&bucket, cfg);
        hide(
            txn,
            bucket_id,
            old,
            VersionState::Superseded { at: now },
            now.plus(shadow),
        )?;
    }
    let v = VersionRecord {
        key: key.to_string(),
        version_id: VersionId::new(now),
        created_at: now,
        is_null,
        kind,
        state: VersionState::Live,
        lock: None,
        legal_hold: false,
        owner: owner.clone(),
    };
    crate::usage::on_create(txn, bucket_id, &v)?;
    txn.put_version(bucket_id, &v)?;
    txn.refresh_latest(bucket_id, key)?;
    Ok((v, bucket))
}

/// Unlink a blob file from inside a write job (idempotent).
pub(crate) fn unlink_blob(blobs: &FsBlobStore, id: &BlobId) {
    for p in [blobs.plain_path(id), blobs.enc_path(id)] {
        let _ = std::fs::remove_file(p);
    }
}

/// Write a replica version with a caller-chosen id (Tidemark→Tidemark replication via
/// `x-tidemark-version-id`). Requires versioning `Enabled`; returns `None` when that version id is
/// already stored (idempotent re-delivery). Blobs referenced by `kind` are increfed.
#[allow(clippy::too_many_arguments)]
pub(crate) fn commit_replica(
    txn: &WriteTxn,
    blobs: &FsBlobStore,
    bucket_id: BucketId,
    bucket_name: &str,
    key: &str,
    kind: VersionKind,
    owner: &PrincipalId,
    vid: VersionId,
) -> S3Result<(Option<VersionRecord>, BucketRecord)> {
    let bucket = active_bucket(txn, bucket_id, bucket_name)?;
    if bucket.versioning != Versioning::Enabled {
        return Err(S3Error::new(
            S3ErrorCode::InvalidRequest,
            "replica bucket must have versioning enabled",
        ));
    }
    if txn.version(bucket_id, key, &vid)?.is_some() {
        return Ok((None, bucket));
    }
    if let VersionKind::Object(body) = &kind {
        crate::usage::check_quota(txn, &bucket, body.size)?;
        for p in &body.parts {
            incref_checked(txn, blobs, &p.blob, p.size)?;
        }
    }
    let v = VersionRecord {
        key: key.to_string(),
        version_id: vid,
        created_at: vid.created_at(),
        is_null: false,
        kind,
        state: VersionState::Live,
        lock: None,
        legal_hold: false,
        owner: owner.clone(),
    };
    crate::usage::on_create(txn, bucket_id, &v)?;
    txn.put_version(bucket_id, &v)?;
    txn.refresh_latest(bucket_id, key)?;
    Ok((Some(v), bucket))
}
