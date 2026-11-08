//! Startup recovery (DESIGN §9): tmp sweep, orphan multipart cleanup, `latest` consistency check
//! and, after an unclean shutdown, an orphan-blob sweep.

use crate::CairnEngine;
use crate::commit::unlink_blob;
use cairn_core::{BlobId, BucketId, S3Result, Ts};
use cairn_meta::{
    BucketState, Flow, MetaError, MultipartRecord, ReadExt, Reader, Table, VersionRecord, decode,
    keys,
};
use std::ops::Bound;
use std::path::Path;
use std::time::{Duration, SystemTime};

/// What startup recovery found and fixed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecoveryReport {
    /// The previous run did not shut down cleanly.
    pub unclean_shutdown: bool,
    /// Stale files removed from `tmp/`.
    pub tmp_removed: usize,
    /// Multipart uploads aborted because their bucket is gone or trashed.
    pub uploads_aborted: u64,
    /// `uploads` / `uploads_by_key` index rows repaired.
    pub upload_index_repaired: u64,
    /// `latest` rows checked against `versions`.
    pub latest_checked: u64,
    /// `latest` rows rewritten because they disagreed with `versions`.
    pub latest_repaired: u64,
    /// Blob files with no metadata reference that were unlinked.
    pub orphan_blobs_removed: u64,
}

/// Rows handled per metadata write job during recovery and GC.
pub(crate) const BATCH: usize = 256;

/// Default number of keys sampled by the `latest` consistency check.
pub const LATEST_SAMPLE: usize = 10_000;

impl CairnEngine {
    /// Run startup recovery. Call once after [`CairnEngine::open`] and before serving traffic.
    /// The orphan-blob sweep walks the whole blob tree, so it only runs after an unclean shutdown
    /// (or when `full` is set).
    pub async fn recover(&self, full: bool) -> S3Result<RecoveryReport> {
        let mut rep = RecoveryReport {
            unclean_shutdown: self.inner.unclean,
            tmp_removed: self.inner.tmp_removed,
            ..Default::default()
        };
        let (aborted, repaired) = self.cleanup_orphan_uploads().await?;
        rep.uploads_aborted = aborted;
        rep.upload_index_repaired = repaired;
        let (checked, fixed) = self.check_latest(LATEST_SAMPLE).await?;
        rep.latest_checked = checked;
        rep.latest_repaired = fixed;
        if full || rep.unclean_shutdown {
            rep.orphan_blobs_removed = self.sweep_orphan_blobs(Duration::ZERO).await?;
        }
        tracing::info!(?rep, "startup recovery finished");
        Ok(rep)
    }

    /// Abort uploads whose bucket is not Active and repair the `uploads_by_key` index.
    /// Returns (uploads aborted, index rows repaired).
    pub async fn cleanup_orphan_uploads(&self) -> S3Result<(u64, u64)> {
        let r = self.read()?;
        let mut orphans: Vec<MultipartRecord> = Vec::new();
        let mut missing_idx: Vec<MultipartRecord> = Vec::new();
        r.scan(
            Table::Uploads,
            Bound::Unbounded,
            Bound::Unbounded,
            &mut |_, v| {
                let u: MultipartRecord = decode(v)?;
                let active = matches!(
                    r.bucket(u.bucket)?.map(|b| b.state),
                    Some(BucketState::Active)
                );
                if !active {
                    orphans.push(u);
                } else if r
                    .get(
                        Table::UploadsByKey,
                        &keys::upload_by_key(u.bucket, &u.key, &u.upload_id),
                    )?
                    .is_none()
                {
                    missing_idx.push(u);
                }
                Ok(Flow::Continue)
            },
        )?;
        let mut dangling: Vec<Vec<u8>> = Vec::new();
        r.scan(
            Table::UploadsByKey,
            Bound::Unbounded,
            Bound::Unbounded,
            &mut |k, _| {
                let mut bid = [0u8; 16];
                if k.len() < 16 {
                    dangling.push(k.to_vec());
                    return Ok(Flow::Continue);
                }
                bid.copy_from_slice(&k[..16]);
                let ok = keys::split_upload_by_key(k).is_some_and(|(_, uid)| {
                    matches!(
                        r.get(
                            Table::Uploads,
                            &keys::upload_key(BucketId::from_bytes(bid), uid)
                        ),
                        Ok(Some(_))
                    )
                });
                if !ok {
                    dangling.push(k.to_vec());
                }
                Ok(Flow::Continue)
            },
        )?;
        drop(r);
        let aborted = orphans.len() as u64;
        let repaired = (missing_idx.len() + dangling.len()) as u64;
        for chunk in orphans.chunks(BATCH) {
            let chunk = chunk.to_vec();
            self.inner
                .meta
                .write(move |txn| -> Result<(), MetaError> {
                    let now = Ts::now();
                    for u in &chunk {
                        if txn.upload(u.bucket, &u.upload_id)?.is_none() {
                            continue;
                        }
                        for p in u.parts.values() {
                            txn.blob_decref(&p.blob, now)?;
                        }
                        txn.del_upload(u)?;
                    }
                    Ok(())
                })
                .await?;
        }
        if repaired > 0 {
            self.inner
                .meta
                .write(move |txn| -> Result<(), MetaError> {
                    for u in &missing_idx {
                        txn.put_upload(u)?;
                    }
                    for k in &dangling {
                        txn.del(Table::UploadsByKey, k)?;
                    }
                    Ok(())
                })
                .await?;
        }
        Ok((aborted, repaired))
    }

    /// Compare up to `sample` `latest` rows (and the keys of up to `sample` version rows) with the
    /// newest Live version from `versions`, rewriting any that disagree.
    /// Returns (keys checked, keys repaired).
    pub async fn check_latest(&self, sample: usize) -> S3Result<(u64, u64)> {
        let r = self.read()?;
        let mut suspects: Vec<(BucketId, String)> = Vec::new();
        let mut checked = 0u64;
        let mut n = 0usize;
        r.scan(
            Table::Latest,
            Bound::Unbounded,
            Bound::Unbounded,
            &mut |k, v| {
                if n >= sample {
                    return Ok(Flow::Stop);
                }
                n += 1;
                let (Some(bid), Some(key)) = (bucket_of(k), keys::split_latest_key(k)) else {
                    return Ok(Flow::Continue);
                };
                checked += 1;
                let cur: VersionRecord = decode(v)?;
                if r.newest_live(bid, key)?.as_ref() != Some(&cur) {
                    suspects.push((bid, key.to_string()));
                }
                Ok(Flow::Continue)
            },
        )?;
        let mut n = 0usize;
        r.scan(
            Table::Versions,
            Bound::Unbounded,
            Bound::Unbounded,
            &mut |k, _| {
                if n >= sample {
                    return Ok(Flow::Stop);
                }
                n += 1;
                let (Some(bid), Some((key, _))) = (bucket_of(k), keys::split_version_key(k)) else {
                    return Ok(Flow::Continue);
                };
                checked += 1;
                let want = r.newest_live(bid, key)?;
                if want != r.latest(bid, key)? {
                    suspects.push((bid, key.to_string()));
                }
                let next = keys::prefix_successor(&keys::versions_of(bid, key)).expect("successor");
                Ok(Flow::Seek(next))
            },
        )?;
        drop(r);
        suspects.sort();
        suspects.dedup();
        let repaired = suspects.len() as u64;
        for chunk in suspects.chunks(BATCH) {
            let chunk = chunk.to_vec();
            self.inner
                .meta
                .write(move |txn| -> Result<(), MetaError> {
                    for (b, k) in &chunk {
                        txn.refresh_latest(*b, k)?;
                    }
                    Ok(())
                })
                .await?;
        }
        if repaired > 0 {
            tracing::warn!(repaired, "repaired inconsistent `latest` rows");
        }
        Ok((checked, repaired))
    }

    /// Unlink blob files that no metadata row references (left behind by a crash between the
    /// blob rename and the metadata commit). Files modified within `min_age` are skipped so the
    /// sweep is safe while uploads are in flight. Returns the number removed.
    pub async fn sweep_orphan_blobs(&self, min_age: Duration) -> S3Result<u64> {
        let root = self.inner.data_dir.join("blobs");
        let ids = tokio::task::spawn_blocking(move || walk_blob_ids(&root, min_age))
            .await
            .map_err(cairn_core::S3Error::internal)??;
        let mut removed = 0u64;
        for chunk in ids.chunks(BATCH) {
            let chunk = chunk.to_vec();
            let blobs = self.inner.blobs.clone();
            removed += self
                .inner
                .meta
                .write(move |txn| -> Result<u64, MetaError> {
                    let mut n = 0;
                    for id in &chunk {
                        if txn.blob_ref(id)?.is_none() {
                            unlink_blob(&blobs, id);
                            n += 1;
                        }
                    }
                    Ok(n)
                })
                .await?;
        }
        if removed > 0 {
            tracing::warn!(removed, "removed orphan blob files");
        }
        Ok(removed)
    }
}

fn bucket_of(k: &[u8]) -> Option<BucketId> {
    let b: [u8; 16] = k.get(..16)?.try_into().ok()?;
    Some(BucketId::from_bytes(b))
}

/// Every blob id present under `blobs/ab/cd/`.
fn walk_blob_ids(root: &Path, min_age: Duration) -> std::io::Result<Vec<BlobId>> {
    let mut out = Vec::new();
    let now = SystemTime::now();
    for l1 in read_dir_or_empty(root)? {
        for l2 in read_dir_or_empty(&l1)? {
            for f in read_dir_or_empty(&l2)? {
                let Some(name) = f.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };
                let hex = name.strip_suffix(".enc").unwrap_or(name);
                let young = min_age > Duration::ZERO
                    && std::fs::metadata(&f)
                        .and_then(|m| m.modified())
                        .is_ok_and(|m| now.duration_since(m).unwrap_or_default() < min_age);
                if let (false, Ok(id)) = (young, hex.parse::<BlobId>()) {
                    out.push(id);
                }
            }
        }
    }
    out.sort_by_key(|a| a.0);
    out.dedup();
    Ok(out)
}

fn read_dir_or_empty(p: &Path) -> std::io::Result<Vec<std::path::PathBuf>> {
    match std::fs::read_dir(p) {
        Ok(rd) => rd.map(|e| e.map(|e| e.path())).collect(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}
