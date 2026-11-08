//! Trash (soft-deleted / superseded versions) and point-in-time queries (DESIGN §7.3–§7.4).

use crate::commit::{active_bucket, commit_version, retention};
use crate::gc::purge_version;
use crate::types::*;
use crate::{CairnEngine, resolve_bucket};
use cairn_core::{PrincipalId, S3Error, S3ErrorCode, S3Result, Ts, VersionId};
use cairn_meta::{Flow, ReadExt, Reader, Table, VersionRecord, VersionState, decode, keys, pitr};

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
                commit_version(
                    txn,
                    &inner.blobs,
                    &inner.cfg,
                    b.id,
                    &bn,
                    &k,
                    src.kind.clone(),
                    &by,
                    &WriteConditions::default(),
                )
            })
            .await?;
        let body = v.body().expect("restored object");
        Ok(PutObjectRes {
            etag: body.etag.clone(),
            version_id: crate::util::s3_version_id(&v, br.versioning),
            checksum: body.checksum.as_ref().map(|c| (c.algo, c.value.clone())),
            size: body.size,
            version: v,
        })
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
}
