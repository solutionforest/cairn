//! Garbage collection (DESIGN §7.3): purge expired trash versions and trashed buckets, then unlink
//! blobs whose refcount has been zero for longer than the grace period.

use crate::TidemarkEngine;
use crate::commit::{retention, unlink_blob};
use crate::recovery::BATCH;
use crate::types::GcStats;
use std::ops::Bound;
use tidemark_core::{BlobId, BucketId, S3Result, Ts, VersionId};
use tidemark_meta::{
    BucketRecord, BucketState, Flow, MetaError, ReadExt, Reader, Table, VersionRecord, WriteTxn,
    keys,
};

/// Upper scan bound for index tables keyed by a leading timestamp: every entry `<= now`.
fn upto(now: Ts) -> Vec<u8> {
    keys::ts_bytes(Ts(now.0.saturating_add(1))).to_vec()
}

/// When a hidden version may be purged under the bucket's current retention.
fn purge_due(b: &BucketRecord, cfg: &crate::EngineConfig, v: &VersionRecord) -> Option<Ts> {
    let since = v.state.hidden_since()?;
    let (soft, shadow) = retention(b, cfg);
    Some(match v.state {
        tidemark_meta::VersionState::Superseded { .. } => since.plus(shadow),
        _ => since.plus(soft),
    })
}

/// Hard-delete one version row and release its blobs.
pub(crate) fn purge_version(
    txn: &WriteTxn,
    b: BucketId,
    v: &VersionRecord,
    now: Ts,
) -> Result<(), MetaError> {
    crate::usage::on_purge(txn, b, v)?;
    txn.del_version(b, &v.key, &v.version_id)?;
    for blob in v.blobs() {
        txn.blob_decref(&blob, now)?;
    }
    Ok(())
}

impl TidemarkEngine {
    /// One GC pass as of `now`. Safe to run concurrently with traffic: every step is a metadata
    /// write job, and blob files are unlinked only from inside those jobs.
    pub async fn gc_tick(&self, now: Ts) -> S3Result<GcStats> {
        let mut stats = GcStats::default();
        loop {
            let n = self.gc_trash_batch(now).await?;
            stats.versions_purged += n.0;
            if !n.1 {
                break;
            }
        }
        loop {
            let (purged, buckets, more) = self.gc_bucket_batch(now).await?;
            stats.versions_purged += purged;
            stats.buckets_purged += buckets;
            if !more {
                break;
            }
        }
        let grace = self.inner.cfg.retention.gc_grace;
        loop {
            let (deleted, more) = self.gc_blob_batch(now.minus(grace)).await?;
            stats.blobs_deleted += deleted;
            if !more {
                break;
            }
        }
        if stats != GcStats::default() {
            tracing::info!(?stats, "gc tick");
        }
        Ok(stats)
    }

    /// Process up to one batch of due `trash_idx` entries. Returns (purged, more work remains).
    async fn gc_trash_batch(&self, now: Ts) -> S3Result<(u64, bool)> {
        let mut due: Vec<Vec<u8>> = Vec::new();
        let end = upto(now);
        self.read()?.scan(
            Table::TrashIdx,
            Bound::Unbounded,
            Bound::Excluded(&end),
            &mut |k, _| {
                due.push(k.to_vec());
                Ok(if due.len() >= BATCH {
                    Flow::Stop
                } else {
                    Flow::Continue
                })
            },
        )?;
        if due.is_empty() {
            return Ok((0, false));
        }
        let more = due.len() >= BATCH;
        let inner = self.inner.clone();
        let purged = self
            .inner
            .meta
            .write(move |txn| -> Result<u64, MetaError> {
                let mut n = 0;
                for k in &due {
                    txn.del(Table::TrashIdx, k)?;
                    let Some((_, b, key, vid)) = keys::split_trash_key(k) else {
                        continue;
                    };
                    let Some(v) = txn.version(b, &key, &vid)? else {
                        continue;
                    };
                    let Some(bucket) = txn.bucket(b)? else {
                        purge_version(txn, b, &v, now)?;
                        n += 1;
                        continue;
                    };
                    let Some(at) = purge_due(&bucket, &inner.cfg, &v) else {
                        continue;
                    };
                    let locked = v.legal_hold || v.lock.is_some_and(|l| l.retain_until > now);
                    if at > now || locked {
                        let later = if locked && at <= now {
                            v.lock.map_or(now, |l| l.retain_until).max(Ts(now.0 + 1))
                        } else {
                            at
                        };
                        txn.trash_add(later, b, &key, &vid)?;
                        continue;
                    }
                    purge_version(txn, b, &v, now)?;
                    n += 1;
                }
                Ok(n)
            })
            .await?;
        Ok((purged, more))
    }

    /// Purge expired trashed buckets, one batch of version rows at a time.
    /// Returns (versions purged, buckets fully purged, more work remains).
    async fn gc_bucket_batch(&self, now: Ts) -> S3Result<(u64, u64, bool)> {
        let mut first: Option<Vec<u8>> = None;
        let end = upto(now);
        self.read()?.scan(
            Table::BucketTrashIdx,
            Bound::Unbounded,
            Bound::Excluded(&end),
            &mut |k, _| {
                first = Some(k.to_vec());
                Ok(Flow::Stop)
            },
        )?;
        let Some(idx_key) = first else {
            return Ok((0, 0, false));
        };
        self.inner
            .meta
            .write(move |txn| -> Result<(u64, u64, bool), MetaError> {
                let bid = match idx_key
                    .get(16..32)
                    .and_then(|b| <[u8; 16]>::try_from(b).ok())
                {
                    Some(b) => BucketId::from_bytes(b),
                    None => {
                        txn.del(Table::BucketTrashIdx, &idx_key)?;
                        return Ok((0, 0, true));
                    }
                };
                match txn.bucket(bid)? {
                    Some(b) if matches!(b.state, BucketState::Trashed { .. }) => {}
                    _ => {
                        txn.del(Table::BucketTrashIdx, &idx_key)?;
                        return Ok((0, 0, true));
                    }
                }
                let mut rows: Vec<(String, VersionId)> = Vec::new();
                txn.scan_prefix(Table::Versions, &bid.to_bytes(), &mut |k, _| {
                    if let Some((key, vid)) = keys::split_version_key(k) {
                        rows.push((key.to_string(), vid));
                    }
                    Ok(if rows.len() >= BATCH {
                        Flow::Stop
                    } else {
                        Flow::Continue
                    })
                })?;
                let mut n = 0;
                for (key, vid) in &rows {
                    if let Some(v) = txn.version(bid, key, vid)? {
                        purge_version(txn, bid, &v, now)?;
                        n += 1;
                    }
                }
                if !rows.is_empty() {
                    return Ok((n, 0, true));
                }
                let mut leftovers: Vec<(Table, Vec<u8>)> = Vec::new();
                for t in [Table::Latest, Table::BucketHistory] {
                    txn.scan_prefix(t, &bid.to_bytes(), &mut |k, _| {
                        leftovers.push((t, k.to_vec()));
                        Ok(Flow::Continue)
                    })?;
                }
                for (t, k) in &leftovers {
                    txn.del(*t, k)?;
                }
                crate::usage::forget(txn, bid)?;
                tidemark_events::notification::remove(txn, bid).map_err(|e| match e {
                    tidemark_events::EventsError::Meta(m) => m,
                    other => MetaError::Corrupt(other.to_string()),
                })?;
                txn.del(Table::BucketMeta, &bid.to_bytes())?;
                txn.del(Table::BucketTrashIdx, &idx_key)?;
                Ok((0, 1, true))
            })
            .await
            .map_err(Into::into)
    }

    /// Unlink one batch of blobs unreferenced since before `cutoff`.
    /// Returns (blobs deleted, more work remains).
    async fn gc_blob_batch(&self, cutoff: Ts) -> S3Result<(u64, bool)> {
        let mut due: Vec<(Vec<u8>, BlobId)> = Vec::new();
        let end = upto(cutoff);
        self.read()?.scan(
            Table::BlobGcIdx,
            Bound::Unbounded,
            Bound::Excluded(&end),
            &mut |k, _| {
                if let Some(id) = k
                    .get(16..48)
                    .and_then(|b| <[u8; 32]>::try_from(b).ok())
                    .map(BlobId)
                {
                    due.push((k.to_vec(), id));
                }
                Ok(if due.len() >= BATCH {
                    Flow::Stop
                } else {
                    Flow::Continue
                })
            },
        )?;
        if due.is_empty() {
            return Ok((0, false));
        }
        let more = due.len() >= BATCH;
        let blobs = self.inner.blobs.clone();
        let deleted = self
            .inner
            .meta
            .write(move |txn| -> Result<u64, MetaError> {
                let mut n = 0;
                for (k, id) in &due {
                    match txn.blob_ref(id)? {
                        Some(r) if r.refcount == 0 => {
                            unlink_blob(&blobs, id);
                            txn.blob_forget(id)?;
                            n += 1;
                        }
                        _ => {}
                    }
                    txn.del(Table::BlobGcIdx, k)?;
                }
                Ok(n)
            })
            .await?;
        Ok((deleted, more))
    }
}
