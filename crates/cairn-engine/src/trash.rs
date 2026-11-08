//! Trash (soft-deleted / superseded versions) and point-in-time queries (DESIGN §7.3–§7.4).

use crate::commit::{active_bucket, commit_version, retention};
use crate::gc::purge_version;
use crate::types::*;
use crate::{CairnEngine, resolve_bucket};
use cairn_core::{BucketId, PrincipalId, S3Error, S3ErrorCode, S3Result, Ts, VersionId};
use cairn_meta::{
    BucketRecord, BucketState, Flow, ReadExt, Reader, Table, VersionRecord, VersionState, decode,
    keys, pitr,
};

fn not_in_trash(key: &str) -> S3Error {
    S3Error::new(S3ErrorCode::NoSuchVersion, "no such version in the trash").with_resource(key)
}

impl CairnEngine {
    /// Hidden (soft-deleted or superseded) versions under `prefix`, in key order, newest first
    /// per key, at most `limit`.
    pub fn trash_list(
        &self,
        bucket: &str,
        prefix: &str,
        limit: usize,
    ) -> S3Result<Vec<TrashEntry>> {
        let r = self.read()?;
        let b = resolve_bucket(&r, bucket)?;
        let (soft, shadow) = retention(&b, &self.inner.cfg);
        let mut out = Vec::new();
        r.scan_prefix(
            Table::Versions,
            &keys::bucket_key(b.id, prefix),
            &mut |_, v| {
                let rec: VersionRecord = decode(v)?;
                if let Some(at) = rec.state.hidden_since() {
                    let window = match rec.state {
                        VersionState::Superseded { .. } => shadow,
                        _ => soft,
                    };
                    out.push(TrashEntry {
                        bucket: bucket.to_string(),
                        hidden_at: at,
                        expires_at: at.plus(window),
                        version: rec,
                    });
                }
                Ok(if out.len() >= limit {
                    Flow::Stop
                } else {
                    Flow::Continue
                })
            },
        )?;
        Ok(out)
    }

    /// Restore a hidden version by writing a new Live version that shares its blobs (history is
    /// never rewritten). `version = None` picks the newest hidden version of the key.
    pub async fn trash_restore(
        &self,
        bucket: &str,
        key: &str,
        version: Option<VersionId>,
        by: &PrincipalId,
    ) -> S3Result<PutObjectRes> {
        let b = self.bucket(bucket)?;
        let inner = self.inner.clone();
        let em = self.emitter(by);
        let (bn, k, by) = (bucket.to_string(), key.to_string(), by.clone());
        let (v, br) = self
            .inner
            .meta
            .write(move |txn| {
                active_bucket(txn, b.id, &bn)?;
                let src = match version {
                    Some(vid) => txn.version(b.id, &k, &vid)?,
                    None => txn
                        .versions_of(b.id, &k)?
                        .into_iter()
                        .find(|v| !v.is_live() && !v.is_delete_marker()),
                }
                .filter(|v| !v.is_live() && !v.is_delete_marker())
                .ok_or_else(|| not_in_trash(&k))?;
                let (v, br) = commit_version(
                    txn,
                    &inner.blobs,
                    &inner.cfg,
                    b.id,
                    &bn,
                    &k,
                    src.kind.clone(),
                    &by,
                    &WriteConditions::default(),
                )?;
                em.emit(
                    txn,
                    &br,
                    cairn_events::EventName::CairnTrashRestored,
                    &k,
                    Some(&v),
                    vec![(
                        "restored_from_version_id".into(),
                        src.version_id.to_string(),
                    )],
                )?;
                Ok::<_, S3Error>((v, br))
            })
            .await?;
        self.notify();
        let body = v.body().expect("restored object");
        Ok(PutObjectRes {
            etag: body.etag.clone(),
            version_id: crate::util::s3_version_id(&v, br.versioning),
            checksum: body.checksum.as_ref().map(|c| (c.algo, c.value.clone())),
            size: body.size,
            version: v,
        })
    }

    /// Undo a bucket delete in one step: bring the trashed bucket `id` back (under its old name
    /// or `as_name`) and replay every hidden version of every key, oldest first, so each key's
    /// newest version is current again and its whole history is visible. Versions share their
    /// blobs (no blob bytes are written). Returns the bucket and the number of versions replayed.
    pub async fn restore_bucket_all(
        &self,
        id: BucketId,
        as_name: Option<String>,
        by: &PrincipalId,
    ) -> S3Result<(cairn_meta::BucketRecord, u64)> {
        let b = self.restore_bucket(id, as_name).await?;
        let mut hidden: Vec<VersionRecord> = Vec::new();
        self.read()?
            .scan_prefix(Table::Versions, &b.id.to_bytes(), &mut |_, v| {
                let rec: VersionRecord = decode(v)?;
                if !rec.is_live() && !rec.is_delete_marker() {
                    hidden.push(rec);
                }
                Ok(Flow::Continue)
            })?;
        hidden.sort_by(|a, b| a.key.cmp(&b.key).then(a.created_at.cmp(&b.created_at)));
        let mut n = 0;
        for v in &hidden {
            self.trash_restore(&b.name, &v.key, Some(v.version_id), by)
                .await?;
            n += 1;
        }
        Ok((self.bucket_by_id(id)?, n))
    }

    /// Irreversibly purge one hidden version now (refused under an active Object Lock).
    pub async fn trash_purge(&self, bucket: &str, key: &str, version: VersionId) -> S3Result<()> {
        let b = self.bucket(bucket)?;
        let k = key.to_string();
        self.inner
            .meta
            .write(move |txn| {
                let v = txn
                    .version(b.id, &k, &version)?
                    .filter(|v| !v.is_live())
                    .ok_or_else(|| not_in_trash(&k))?;
                let now = Ts::now();
                crate::commit::check_lock(&v, now)?;
                purge_version(txn, b.id, &v, now)?;
                Ok::<_, S3Error>(())
            })
            .await
    }

    /// The version that was the S3-visible head of `key` at `at` (`None` if absent or a delete
    /// marker).
    pub fn pitr_head_at(&self, bucket: &str, key: &str, at: Ts) -> S3Result<Option<VersionRecord>> {
        let r = self.read()?;
        let b = resolve_bucket(&r, bucket)?;
        Ok(pitr::head_at(&r, b.id, key, at)?)
    }

    /// [`CairnEngine::pitr_head_at`] by bucket identity; reaches a trashed bucket.
    pub fn pitr_head_at_id(
        &self,
        bucket: BucketId,
        key: &str,
        at: Ts,
    ) -> S3Result<Option<VersionRecord>> {
        let r = self.read()?;
        let b = r
            .bucket(bucket)?
            .ok_or_else(|| crate::no_such_bucket(&bucket.to_string()))?;
        Ok(pitr::head_at(&r, b.id, key, at)?)
    }

    /// Differences between the current state of `prefix` and its state at `at`.
    pub fn pitr_diff(&self, bucket: &str, prefix: &str, at: Ts) -> S3Result<Vec<DiffEntry>> {
        let r = self.read()?;
        let b = resolve_bucket(&r, bucket)?;
        let mut out = Vec::new();
        pitr::keys_with_history(&r, b.id, prefix, |key| {
            let then = pitr::head_at(&r, b.id, key, at)?;
            let now = r.latest(b.id, key)?.filter(|v| !v.is_delete_marker());
            let kind = match (&then, &now) {
                (Some(_), None) => Some(DiffKind::Recreate),
                (None, Some(_)) => Some(DiffKind::Remove),
                (Some(t), Some(n)) if t.version_id != n.version_id && t.body() != n.body() => {
                    Some(DiffKind::Revert)
                }
                _ => None,
            };
            if let Some(kind) = kind {
                out.push(DiffEntry {
                    key: key.to_string(),
                    kind,
                    then: then.map(|v| v.version_id),
                    now: now.map(|v| v.version_id),
                });
            }
            Ok(true)
        })?;
        Ok(out)
    }

    /// Point-in-time restore (DESIGN §7.4): make `prefix` of `bucket` look as it did at `at` by
    /// writing new versions that share the old versions' blobs (and deleting keys created
    /// since). With a different target bucket or prefix, every key that existed at `at` is
    /// written there and nothing is deleted. Each key is one ordinary, reversible write that
    /// emits `cairn:PitrRestore` (deletes emit `s3:ObjectRemoved:*`).
    pub async fn pitr_restore(
        &self,
        bucket: &str,
        prefix: &str,
        at: Ts,
        target: PitrTarget,
        dry_run: bool,
        by: &PrincipalId,
    ) -> S3Result<PitrReport> {
        let src = self.bucket(bucket)?;
        self.pitr_restore_id(src.id, prefix, at, target, dry_run, by)
            .await
    }

    /// [`CairnEngine::pitr_restore`] from a bucket addressed by identity, which may be trashed.
    /// In place (no target bucket) a trashed source bucket is first brought back under its
    /// old name; a dry run plans that without doing it.
    pub async fn pitr_restore_id(
        &self,
        src_id: BucketId,
        prefix: &str,
        at: Ts,
        target: PitrTarget,
        dry_run: bool,
        by: &PrincipalId,
    ) -> S3Result<PitrReport> {
        let mut src = self.bucket_by_id(src_id)?;
        let bucket = src.name.clone();
        let dst_name = target.bucket.clone().unwrap_or_else(|| bucket.clone());
        if !matches!(src.state, BucketState::Active) && target.bucket.is_none() {
            if dry_run {
                return self.pitr_plan(&src, &src, prefix, at, &target, true);
            }
            src = self.restore_bucket(src.id, None).await?;
        }
        let dst = self.bucket(&dst_name)?;
        let mut report = self.pitr_plan(&src, &dst, prefix, at, &target, false)?;
        if dry_run {
            return Ok(report);
        }
        self.pitr_apply(&src, &dst, &dst_name, prefix, at, &target, by, &mut report)
            .await?;
        Ok(report)
    }

    /// The changes a PITR restore from `src` into `dst` would make. `trashed_in_place` treats
    /// `dst` as the (still trashed) source bucket coming back under its own name.
    #[allow(clippy::too_many_arguments)]
    fn pitr_plan(
        &self,
        src: &BucketRecord,
        dst: &BucketRecord,
        prefix: &str,
        at: Ts,
        target: &PitrTarget,
        trashed_in_place: bool,
    ) -> S3Result<PitrReport> {
        let in_place = trashed_in_place
            || (dst.id == src.id && target.prefix.as_deref().is_none_or(|p| p == prefix));
        let dest_key = |k: &str| match &target.prefix {
            Some(p) => format!("{p}{}", &k[prefix.len().min(k.len())..]),
            None => k.to_string(),
        };
        let mut report = PitrReport::default();
        {
            let r = self.read()?;
            pitr::keys_with_history(&r, src.id, prefix, |key| {
                let then = pitr::head_at(&r, src.id, key, at)?;
                let dk = dest_key(key);
                let now = r.latest(dst.id, &dk)?.filter(|v| !v.is_delete_marker());
                let kind = match (&then, &now) {
                    (Some(_), None) => Some(DiffKind::Recreate),
                    (None, Some(_)) if in_place => Some(DiffKind::Remove),
                    (Some(t), Some(n)) if t.version_id != n.version_id && t.body() != n.body() => {
                        Some(DiffKind::Revert)
                    }
                    _ => None,
                };
                match kind {
                    Some(kind) => report.changes.push(PitrChange {
                        key: dk,
                        kind,
                        then: then.map(|v| v.version_id),
                        now: now.map(|v| v.version_id),
                        new_version: None,
                    }),
                    None => report.unchanged += 1,
                }
                Ok(true)
            })?;
        }
        Ok(report)
    }

    #[allow(clippy::too_many_arguments)]
    async fn pitr_apply(
        &self,
        src: &BucketRecord,
        dst: &BucketRecord,
        dst_name: &str,
        prefix: &str,
        at: Ts,
        target: &PitrTarget,
        by: &PrincipalId,
        report: &mut PitrReport,
    ) -> S3Result<()> {
        let dest_key = |k: &str| match &target.prefix {
            Some(p) => format!("{p}{}", &k[prefix.len().min(k.len())..]),
            None => k.to_string(),
        };
        let dst_name = dst_name.to_string();
        let src_keys: Vec<Option<String>> = {
            let r = self.read()?;
            let mut out = Vec::new();
            pitr::keys_with_history(&r, src.id, prefix, |key| {
                out.push(Some(key.to_string()));
                Ok(true)
            })?;
            out
        };
        for c in &mut report.changes {
            match c.kind {
                DiffKind::Remove => {
                    let d = self.delete_object(&dst_name, &c.key, None, by).await?;
                    c.new_version = d.version_id;
                }
                DiffKind::Recreate | DiffKind::Revert => {
                    let vid = c.then.expect("then version");
                    let src_key = src_keys
                        .iter()
                        .flatten()
                        .find(|k| dest_key(k) == c.key)
                        .cloned()
                        .unwrap_or_else(|| c.key.clone());
                    let inner = self.inner.clone();
                    let em = self.emitter(by);
                    let (dn, dk, owner) = (dst_name.clone(), c.key.clone(), by.clone());
                    let (src_id, dst_id) = (src.id, dst.id);
                    let as_of = at.to_rfc3339();
                    let (v, b) = self
                        .inner
                        .meta
                        .write(move |txn| {
                            let old = txn
                                .version(src_id, &src_key, &vid)?
                                .ok_or_else(|| not_in_trash(&src_key))?;
                            let (v, b) = commit_version(
                                txn,
                                &inner.blobs,
                                &inner.cfg,
                                dst_id,
                                &dn,
                                &dk,
                                old.kind.clone(),
                                &owner,
                                &WriteConditions::default(),
                            )?;
                            em.emit(
                                txn,
                                &b,
                                cairn_events::EventName::CairnPitrRestore,
                                &dk,
                                Some(&v),
                                vec![
                                    ("as_of".into(), as_of.clone()),
                                    ("restored_from_version_id".into(), vid.to_string()),
                                ],
                            )?;
                            Ok::<_, S3Error>((v, b))
                        })
                        .await?;
                    self.notify();
                    c.new_version = crate::util::s3_version_id(&v, b.versioning);
                }
            }
        }
        Ok(())
    }
}
